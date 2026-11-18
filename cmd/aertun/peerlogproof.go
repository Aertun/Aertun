// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/inbound"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/translog"
)

// `aertun inbound prove NAME --key F [--at TIME]` signs whether another
// deployment's audit log, as this one received it on a stream feed, is
// complete and unforked up to a time (internal/proof/peerlog.go).
//
// Everything is read again from what the feed kept: the records' leaves,
// every tree head the sender signed with a batch, and every head it signed
// that was not the log held. Each head's signatures are checked with the
// keys the feed holds, and each root is recomputed from the leaves, so a
// leaf lost or changed here since it was taken refutes as surely as a
// sender that signed two histories.

func inboundProve(root string, args []string) error {
	flags := flag.NewFlagSet("inbound prove", flag.ContinueOnError)
	atFlag := flags.String("at", "", "the time the log is claimed complete up to, RFC 3339 (default: now)")
	keyAt := flags.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := flags.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := flags.String("out", "", "where to write the proof (default: standard output)")
	name, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, rest = args[0], args[1:]
	}
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if name == "" || flags.NArg() != 0 || *keyAt == "" {
		return fmt.Errorf("inbound prove takes NAME and --key FILE: an unsigned statement that " +
			"another site's log is whole is a claim about a claim")
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: this one says, in
	// the organisation's name, that a site showed it one history and all of
	// it — or that it did not.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	now := time.Now().UTC()
	at := now
	if *atFlag != "" {
		t, err := time.Parse(time.RFC3339, *atFlag)
		if err != nil {
			return fmt.Errorf("--at is a time written as 2026-11-17T09:00:00Z")
		}
		if t.After(now) {
			return fmt.Errorf("--at is in the future: nothing can be said of records not yet written")
		}
		at = t.UTC()
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	feeds, err := loadFeeds(root)
	if err != nil {
		return err
	}
	f, ok := feeds[name]
	if !ok || f.Kind != inbound.AuditStream || f.Stream == nil {
		return fmt.Errorf("%q is not a stream feed (aertun inbound list)", name)
	}
	ev, materials, err := peerLogEvidence(root, f, at)
	if err != nil {
		return err
	}
	st, err := proof.ProvePeerLog(proof.PeerLogInput{Evidence: ev, Materials: materials,
		Program: version, Now: now})
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	if err := recordE(root, caller.auditRecord("peerlog.proved", "/proofs", audit.Success,
		map[string]string{"feed": name, "verdict": string(st.Predicate.Verdict),
			"held": fmt.Sprint(ev.Held), "forks": fmt.Sprint(ev.ForkCount)})); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}

// peerState is what a stream feed keeps of its sender, read and checked
// again: for a proof, and for the Feeds screen.
type peerState struct {
	Held        int
	Root        string
	Heads       []peerHead
	Agreeing    int
	Disagreeing []proof.PeerHead
	Forks       []peerFork
}

// readPeer reads the leaves, heads and forks a stream feed kept, rebuilds
// the log from the leaves, and holds every head to it and to the feed's
// keys.
func readPeer(root string, f inbound.Feed) (*peerState, error) {
	_, headEd, headML, err := f.Stream.Decode()
	if err != nil {
		return nil, err
	}
	context := f.Stream.HeadContext
	if context == "" {
		context = audit.HeadContext
	}
	verifier, err := audit.NewHeadVerifierIn(context, headEd, headML)
	if err != nil {
		return nil, err
	}
	leaves, err := readStreamLeaves(streamLeavesPath(root, f.Name))
	if err != nil {
		return nil, err
	}
	log := translog.New()
	for _, l := range leaves {
		b, err := hex.DecodeString(l)
		if err != nil {
			return nil, fmt.Errorf("a leaf kept for %s is not hex, so what is held cannot be rebuilt", f.Name)
		}
		log.Append(b)
	}
	st := &peerState{Held: log.Size()}
	if st.Held > 0 {
		st.Root = log.Head().Root
	}
	if st.Heads, err = readJSONLines[peerHead](streamHeadsPath(root, f.Name)); err != nil {
		return nil, err
	}
	kept, err := readJSONLines[peerFork](streamForksPath(root, f.Name))
	if err != nil {
		return nil, err
	}
	// A fork is the sender's word only with the sender's signatures on it:
	// one that no longer verifies is evidence of nothing, and is left out.
	for _, fk := range kept {
		if verifier.Verify(fk.Head) == nil && fk.Held != fk.Head.Root {
			st.Forks = append(st.Forks, fk)
		}
	}
	// The root the log held had at each head's size, in one pass.
	var sizes []int
	for _, h := range st.Heads {
		if h.Head.Size >= 1 && h.Head.Size <= st.Held {
			sizes = append(sizes, h.Head.Size)
		}
	}
	roots, err := log.RootsAt(sizes)
	if err != nil {
		return nil, err
	}
	next := 0
	for _, h := range st.Heads {
		bad := proof.PeerHead{Size: h.Head.Size, Root: h.Head.Root,
			Received: h.Received.UTC().Format(time.RFC3339Nano)}
		var held string
		if h.Head.Size >= 1 && h.Head.Size <= st.Held {
			held = roots[next]
			next++
		}
		switch {
		case verifier.Verify(h.Head) != nil:
			bad.Why, bad.Held = proof.PeerHeadSignature, held
		case h.Head.Size > st.Held || h.Head.Size < 1:
			bad.Why = proof.PeerHeadBeyond
		case held != h.Head.Root:
			bad.Why, bad.Held = proof.PeerHeadRoot, held
		default:
			st.Agreeing++
			continue
		}
		st.Disagreeing = append(st.Disagreeing, bad)
	}
	return st, nil
}

// peerLogEvidence is what the store shows about one stream feed's sender.
func peerLogEvidence(root string, f inbound.Feed, at time.Time) (proof.PeerLogEvidence, []proof.Material, error) {
	context := f.Stream.HeadContext
	if context == "" {
		context = audit.HeadContext
	}
	ev := proof.PeerLogEvidence{Peer: f.Name, At: at.UTC().Format(time.RFC3339Nano),
		FullBatch: proof.MaxStreamBatch,
		Keys: proof.PeerKeys{KeyID: f.Stream.HeadKeyID, Ed25519: f.Stream.HeadEd25519,
			MLDSA: f.Stream.HeadMLDSA, Context: context}}
	st, err := readPeer(root, f)
	if err != nil {
		return ev, nil, err
	}
	ev.Held, ev.Root = st.Held, st.Root
	ev.Heads, ev.Agreeing, ev.Disagree = len(st.Heads), st.Agreeing, len(st.Disagreeing)
	ev.Disagreeing = st.Disagreeing[:min(len(st.Disagreeing), proof.MaxFailures)]
	if n := len(st.Heads); n > 0 {
		last := st.Heads[n-1]
		head := last.Head
		ev.Last, ev.LastRecords = &head, last.Records
		ev.LastReceived = last.Received.UTC().Format(time.RFC3339Nano)
	}
	ev.ForkCount = len(st.Forks)
	for _, fk := range st.Forks[:min(len(st.Forks), proof.MaxPeerForks)] {
		ev.Forks = append(ev.Forks, proof.PeerFork{Received: fk.Received.UTC().Format(time.RFC3339Nano),
			Resent: fk.Resent, Held: fk.Held, Head: fk.Head})
	}
	// The forks this deployment's own log recorded when they arrived. One
	// kept as evidence can be deleted from the feed's files by whoever can
	// write the store; the entry that recorded it cannot be taken out of
	// the log without breaking it.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return ev, nil, err
	}
	if ok, problems := audit.Verify(events); !ok {
		return ev, nil, fmt.Errorf("the audit log does not verify at entry %d (%s), so what it "+
			"records of this feed cannot be relied on", problems[0].Seq, problems[0].Reason)
	}
	for _, e := range events {
		if e.Action != "inbound.fork" || e.Detail["feed"] != f.Name {
			continue
		}
		if when, err := time.Parse(time.RFC3339Nano, e.At); err == nil && !when.Before(f.Created) {
			ev.ForksRecorded++
		}
	}
	var materials []proof.Material
	for _, m := range []struct{ name, path string }{{"peer-leaves", streamLeavesPath(root, f.Name)},
		{"peer-heads", streamHeadsPath(root, f.Name)}, {"peer-forks", streamForksPath(root, f.Name)}} {
		if b, err := os.ReadFile(m.path); err == nil {
			materials = append(materials, proof.Material{Name: m.name, Digest: proof.SHA256(b)})
		}
	}
	if len(events) > 0 {
		materials = append(materials, proof.Material{Name: "audit-log",
			Digest: proof.Digest{"sha256": events[len(events)-1].Hash}, Entries: len(events)})
	}
	return ev, materials, nil
}
