// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/seal"
)

// `aertun proof sealed`: when did an alert exist? Signed as a sealed-alert
// proof (internal/proof) and kept where the proving ground shows it.
//
// The alert is one JSON object, as it was sealed (`aertun alert seal`), or
// a finding a detection run raised, named by its id and made again from the
// register. Its digest is looked for in every batch the verified audit log
// records sealing; the entry that committed the earliest is shown in a head
// of the log; and the earliest head sent to OpenTimestamps that covers the
// entry says what fixes the time, as internal/anchor reads its proof.

// maxAnchorFile bounds the files of sent heads and their proofs when they
// are read for a proof: a proof is a few hundred bytes, three per head.
const maxAnchorFile = 16 << 20

func proofSealed(root string, args []string) error {
	flags := flag.NewFlagSet("proof sealed", flag.ContinueOnError)
	alertAt := flags.String("alert", "", "the alert, as the JSON object that was sealed")
	findingID := flags.String("finding", "", "instead of --alert, a finding a detection run raised, "+
		"by id: the alert it was sealed as is made again from the register")
	keyAt := flags.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := flags.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := flags.String("out", "", "where to write the proof (default: standard output)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *keyAt == "" || (*alertAt == "") == (*findingID == "") {
		return fmt.Errorf("proof sealed takes --alert FILE, or --finding ID, and --key FILE: an " +
			"unsigned proof of when an alert existed is a claim about a claim")
	}

	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed statement
	// that an alert existed by a time, in this organisation's name, is one
	// somebody settles a dispute about who saw what first on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	var raw []byte
	what := *alertAt
	if *alertAt != "" {
		if raw, err = readBounded(*alertAt, seal.MaxAlertBytes); err != nil {
			return err
		}
	} else {
		reg, _, err := finding.Load(findingsPath(root))
		if err != nil {
			return err
		}
		f, ok := reg.Get(*findingID)
		if !ok {
			return fmt.Errorf("no finding %q is in the register (aertun finding list)", *findingID)
		}
		raw, what = findingAlert(f), "finding "+*findingID
	}
	digest, err := seal.Digest(raw)
	if err != nil {
		return fmt.Errorf("%s is not one alert: %w", what, err)
	}

	ev, materials, err := sealedEvidence(root, digest)
	if err != nil {
		return err
	}
	st, err := proof.ProveSealed(proof.SealedInput{Evidence: ev, Materials: materials,
		Program: version, Now: time.Now().UTC()})
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
	if err := recordE(root, caller.auditRecord("sealed.proved", "/proofs", audit.Success,
		map[string]string{"alert": digest[:16], "verdict": string(st.Predicate.Verdict),
			"entry": fmt.Sprint(ev.Entry), "anchor": ev.Anchor})); err != nil {
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

// sealedEvidence is what the store shows about one digest: the log, read
// whole and verified; the heads it sent to be anchored, placed in it; the
// batch that sealed the digest and the entry that committed it; and the
// head that covers that entry.
func sealedEvidence(root, digest string) (proof.SealedEvidence, []proof.Material, error) {
	ev := proof.SealedEvidence{Digest: digest}
	events, err := audit.Read(auditPath(root))
	var opening *fs.PathError
	if errors.As(err, &opening) {
		// The file would not open or read: a permission problem is not
		// evidence of tampering, and signing it as a refutation would say
		// it was (auditVerify says why).
		return ev, nil, err
	}
	ev.LogEntries = len(events)
	if err != nil {
		// A line that is not an entry: the log cannot be read whole, and
		// that is where it stops verifying.
		ev.LogEntries++
		ev.LogBreak = ev.LogEntries
		return ev, nil, nil
	}
	if ev.LogBreak = seal.Break(events); ev.LogBreak > 0 {
		return ev, nil, nil
	}
	var materials []proof.Material
	if len(events) > 0 {
		materials = append(materials, proof.Material{Name: "audit-log",
			Digest: proof.Digest{"sha256": events[len(events)-1].Hash}, Entries: len(events)})
	}
	t, err := seal.LogTree(events)
	if err != nil {
		return ev, nil, err
	}
	heads, anchors := &headFile{}, &anchorFile{}
	if err := loadBoundedJSON(headsPath(root), heads); err != nil {
		return ev, nil, err
	}
	if err := loadBoundedJSON(anchorPath(root), anchors); err != nil {
		return ev, nil, err
	}
	placed, rewritten := seal.Anchors(t, heads.Heads, anchors.Proofs)
	if ev.Rewritten = rewritten; rewritten > 0 {
		return ev, materials, nil
	}

	commits := seal.Commits(events)
	ev.Batches = len(commits)
	found, unkept := seal.Find(seal.Dir(root), commits, digest)
	ev.Unkept = unkept
	if found == nil {
		return ev, materials, nil
	}
	c := found.Commit
	at, err := time.Parse(time.RFC3339Nano, c.At)
	if err != nil {
		return ev, nil, fmt.Errorf("audit entry %d records no time this can read, so when it sealed "+
			"the alert cannot be said", c.Seq)
	}
	leaf, err := audit.LeafHash(events[c.Index])
	if err != nil {
		return ev, nil, err
	}
	ev.Entry, ev.Sealed = int(c.Seq), at.UTC().Format(time.RFC3339Nano)
	ev.BatchRoot, ev.BatchSize, ev.BatchIndex, ev.BatchPath = c.Root, c.Count, found.Index, found.Path
	ev.EntryLeaf = hex.EncodeToString(leaf)
	ev.Anchor, ev.HeadSize = proof.AnchorNone, len(events)
	if cover, ok := seal.Cover(placed, c.Index); ok {
		ev.Anchor, ev.HeadSize = cover.Anchor(), cover.Size
		switch {
		case cover.State == anchor.Anchored:
			ev.Height, ev.BlockHash = int(cover.Height), cover.Block.Hash
			ev.Mined, ev.Header = cover.Block.Mined.Format(time.RFC3339), cover.Block.Header
		case cover.Unconfirmed:
			ev.Height = int(cover.Height)
		}
		materials = append(materials, proof.Material{Name: "anchor-proof", Digest: proof.SHA256(cover.Body)})
	}
	head, err := t.HeadAt(ev.HeadSize)
	if err != nil {
		return ev, nil, err
	}
	ev.HeadRoot = head.Root
	if ev.HeadPath, err = t.InclusionProof(c.Index, ev.HeadSize); err != nil {
		return ev, nil, err
	}
	return ev, materials, nil
}

// describeSealed is the evidence line of a sealed-alert proof, for a person.
func describeSealed(v *proof.SealedEvidence) string {
	switch {
	case v.LogBreak > 0:
		return fmt.Sprintf("  evidence: the audit log stops verifying at entry %d of %d", v.LogBreak, v.LogEntries)
	case v.Rewritten > 0:
		return fmt.Sprintf("  evidence: the log's first %d entries were rewritten after their head was sent", v.Rewritten)
	case v.Entry == 0:
		return fmt.Sprintf("  evidence: in none of %d sealed batch(es) of a log of %d entries", v.Batches, v.LogEntries)
	case v.Anchor == proof.AnchorBitcoin:
		return fmt.Sprintf("  evidence: sealed in entry %d at %s, under the head of %d entries in Bitcoin "+
			"block %d (%s, mined %s)", v.Entry, v.Sealed, v.HeadSize, v.Height, v.BlockHash, v.Mined)
	}
	return fmt.Sprintf("  evidence: sealed in entry %d at %s; the head of %d entries is %s, so the time is "+
		"the log's own", v.Entry, v.Sealed, v.HeadSize, map[string]string{proof.AnchorPending: "pending in the calendars",
		proof.AnchorUnconfirmed: "stamped for a block nobody has checked", proof.AnchorNone: "not anchored"}[v.Anchor])
}

// loadBoundedJSON is loadJSON under a size limit: absent is empty.
func loadBoundedJSON(path string, into any) error {
	b, err := readBounded(path, maxAnchorFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}
