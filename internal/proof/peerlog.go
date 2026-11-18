// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/aertun/aertun/internal/audit"
)

// A peer-log proof: another deployment's audit log, as this one received
// it, is complete and unforked up to a time.
//
// # Why
//
// An organisation with several sites runs one deployment at each, and each
// keeps its own signed audit log. One of them — or an auditor's — receives
// the others' logs as a signed stream (internal/auditstream). What that
// buys is only worth having if it can be said plainly: that nothing was
// left out, and that the site has not shown this receiver one history and
// keeps another. Neither takes any trust in the site beyond the keys it
// published when the feed was added.
//
// # The claim
//
// Every record of the peer's audit log up to a time is held here in order,
// each tree head the peer signed as it sent them is the Merkle root of the
// records held, and the peer has signed no other history.
//
//   - refuted when a tree head the peer signed is not the records held — a
//     record was lost or changed here, or the head's signatures no longer
//     verify — or when the peer sent a head, signed with its own keys, of a
//     log that is not the one held: a fork, with the signed head carried in
//     the proof as the evidence, or recorded in this deployment's own audit
//     log when it arrived and since removed from the feed's files;
//   - proven when every head agrees, there is no fork, and the last batch
//     was received at or after the time asked about and was smaller than a
//     full batch, so it reached the end of the peer's log as it then was;
//   - inconclusive otherwise: nothing has arrived since before that time, the
//     last batch was full and more may be waiting, or no head has been kept.
//
// # What it cannot say
//
// That the peer wrote down everything that happened: a log holds what its
// own program recorded. And nothing about the time after the last batch. A
// peer with nothing to send is silent and so is one that has stopped
// sending, which is why the proof is inconclusive, never proven, for a time
// after the last batch arrived.

// PeerLogVerifier and its version name this verifier.
const (
	PeerLogVerifier        = "aertun/peer-log"
	PeerLogVerifierVersion = "1"
)

// PredicatePeerLog is the predicate of a peer-log proof.
const PredicatePeerLog = "https://aertun.github.io/proof/peer-log/v1"

// The bounds a peer-log proof's numbers are held to.
const (
	// MaxStreamBatch is the most records one batch of an audit stream
	// carries (auditstream.MaxBatch): a batch with fewer reached the end of
	// the sender's log as it then was.
	MaxStreamBatch = 500
	// MaxPeerForks bounds the conflicting heads a proof carries with their
	// signatures: one is enough to refute, and each is two signatures long.
	MaxPeerForks = 8
	// maxPeerLog bounds a log's size.
	maxPeerLog = 1 << 40
)

// Why a head the peer signed is not the records held.
const (
	// PeerHeadRoot is a head whose root is not the Merkle root of the first
	// so-many records held.
	PeerHeadRoot = "root"
	// PeerHeadBeyond is a head of more records than are held.
	PeerHeadBeyond = "beyond"
	// PeerHeadSignature is a head whose signatures do not verify with the
	// keys the feed holds.
	PeerHeadSignature = "signature"
)

var peerShape = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)

// PeerKeys are the keys a peer signs its tree heads with, as the feed holds
// them and as `aertun siem stream key --json` writes them, in base64: what
// makes a head in the proof the peer's own word, and what a reader holds
// against the keys the peer publishes.
type PeerKeys struct {
	// KeyID names the pair.
	KeyID string `json:"key_id"`
	// Ed25519 and MLDSA are the two public keys.
	Ed25519 string `json:"ed25519"`
	MLDSA   string `json:"mldsa"`
	// Context is the context the peer signs its heads in.
	Context string `json:"context"`
}

func (k PeerKeys) verifier() (*audit.HeadVerifier, error) {
	ed, err1 := base64.StdEncoding.DecodeString(k.Ed25519)
	ml, err2 := base64.StdEncoding.DecodeString(k.MLDSA)
	if err1 != nil || err2 != nil || len(ml) == 0 {
		return nil, fmt.Errorf("a peer's head keys are an Ed25519 and an ML-DSA public key in base64")
	}
	v, err := audit.NewHeadVerifierIn(k.Context, ed, ml)
	if err != nil {
		return nil, fmt.Errorf("a peer's head keys do not read: %w", err)
	}
	if v.KeyID() != k.KeyID {
		return nil, fmt.Errorf("a peer's head keys are named by their own key id")
	}
	return v, nil
}

// PeerHead is a tree head the peer signed that is not the records held.
type PeerHead struct {
	// Size is how many records the head covers, and Root the root it
	// signed.
	Size int    `json:"size"`
	Root string `json:"root"`
	// Held is the Merkle root this deployment computes over its first Size
	// records; empty when it holds fewer.
	Held string `json:"held,omitempty"`
	// Received is when the batch that carried the head was taken.
	Received string `json:"received"`
	// Why is root, beyond or signature.
	Why string `json:"why"`
}

// PeerFork is a tree head the peer signed and sent that is not the log
// held: the peer's own signatures on another history.
type PeerFork struct {
	// Received is when it arrived.
	Received string `json:"received"`
	// Resent is whether it covered records already held, so that Head and
	// Held are roots over exactly the same number of records; otherwise the
	// records it brought, added to those held, did not rebuild it.
	Resent bool `json:"resent,omitempty"`
	// Held is the root this deployment computed.
	Held string `json:"held"`
	// Head is the head as the peer signed it, both signatures with it.
	Head audit.SignedHead `json:"head"`
}

// PeerLogEvidence is what a peer-log proof rests on.
type PeerLogEvidence struct {
	// Peer is the feed the peer's log arrives on, by the name it has here.
	Peer string `json:"peer"`
	// Keys are the keys the peer signs its tree heads with.
	Keys PeerKeys `json:"keys"`
	// At is the time the log is claimed complete up to, RFC 3339.
	At string `json:"at"`
	// Held is how many of the peer's records are held, in order from its
	// first.
	Held int `json:"held"`
	// Root is the Merkle root this deployment computes over them; empty
	// when none is held.
	Root string `json:"root,omitempty"`
	// Heads is how many tree heads the peer signed were kept, one with each
	// batch taken.
	Heads int `json:"heads"`
	// Agreeing is how many of them still verify with Keys and are the
	// Merkle root of the first so-many records held.
	Agreeing int `json:"agreeing"`
	// Disagree is how many are not, and Disagreeing lists them, up to
	// MaxFailures.
	Disagree    int        `json:"disagree"`
	Disagreeing []PeerHead `json:"disagreeing,omitempty"`
	// Last is the last head kept, as the peer signed it.
	Last *audit.SignedHead `json:"last,omitempty"`
	// LastReceived is when the batch that carried it was taken, by this
	// deployment's clock, and LastRecords how many records that batch held.
	LastReceived string `json:"last_received,omitempty"`
	LastRecords  int    `json:"last_records,omitempty"`
	// FullBatch is the most records a batch carries: a last batch smaller
	// than this reached the end of the peer's log.
	FullBatch int `json:"full_batch"`
	// ForkCount is how many heads the peer signed and sent that are not the
	// log held, and Forks carries them, up to MaxPeerForks.
	ForkCount int        `json:"fork_count"`
	Forks     []PeerFork `json:"forks,omitempty"`
	// ForksRecorded is how many forks from this feed this deployment's own
	// audit log recorded as they arrived. More recorded than kept means
	// evidence of one was removed from the feed's files afterwards.
	ForksRecorded int `json:"forks_recorded"`
}

// PeerLogInput is what a peer-log proof is made from.
type PeerLogInput struct {
	Evidence  PeerLogEvidence
	Materials []Material
	Program   string
	Now       time.Time
}

// ProvePeerLog builds the unsigned statement.
func ProvePeerLog(in PeerLogInput) (*Statement, error) {
	ev := in.Evidence
	ev.Disagreeing = append([]PeerHead(nil), ev.Disagreeing...)
	ev.Forks = append([]PeerFork(nil), ev.Forks...)
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: Digest{"sha256": ev.subjectDigest()}}},
		PredicateType: PredicatePeerLog,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: PeerLogVerifier, Version: PeerLogVerifierVersion,
				Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(),
			PeerLog:   &ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *PeerLogEvidence) subject() string { return "peer-log/" + ev.Peer }

// subjectDigest names what the proof is about: the log held, by its root,
// or, with nothing held, the keys the peer would sign it with.
func (ev *PeerLogEvidence) subjectDigest() string {
	if ev.Root != "" {
		return ev.Root
	}
	sum := sha256.Sum256([]byte("peer-log/" + ev.Peer + "/" + ev.Keys.KeyID))
	return hex.EncodeToString(sum[:])
}

// lastAgrees reports whether the last head kept is the whole of what is
// held.
func (ev *PeerLogEvidence) lastAgrees() bool {
	return ev.Last != nil && ev.Last.Size == ev.Held && ev.Last.Root == ev.Root
}

func (ev *PeerLogEvidence) held() bool {
	return ev.Disagree == 0 && (ev.Heads == 0 || ev.lastAgrees())
}

// reachedEnd reports whether the last batch reached the end of the peer's
// log, at or after the time asked about.
func (ev *PeerLogEvidence) reachedEnd() bool {
	at, ok1 := parseInstant(ev.At)
	got, ok2 := parseInstant(ev.LastReceived)
	return ev.Heads > 0 && ok1 && ok2 && !got.IsZero() && !got.Before(at) && ev.LastRecords < ev.FullBatch
}

// forked reports whether the peer is known to have signed another history:
// by a head kept, or by this deployment's log having recorded one.
func (ev *PeerLogEvidence) forked() bool { return ev.ForkCount > 0 || ev.ForksRecorded > 0 }

func (ev *PeerLogEvidence) verdict() Verdict {
	switch {
	case !ev.held(), ev.forked():
		return Refuted
	case ev.reachedEnd():
		return Proven
	}
	return Inconclusive
}

func (ev *PeerLogEvidence) claim() string {
	return fmt.Sprintf("Every record of %s's audit log up to %s is held here in order, each tree "+
		"head it signed as it sent them is the Merkle root of the records held, and it has signed "+
		"no other history.", ev.Peer, ev.At)
}

func (ev *PeerLogEvidence) checks() []Check {
	held := Check{Name: "held", Passed: ev.held()}
	switch {
	case ev.Heads == 0:
		held.Detail = fmt.Sprintf("%d record(s) are held and no tree head the peer signed has been "+
			"kept with them, so nothing it signed can be held against them", ev.Held)
	case ev.Disagree > 0:
		held.Detail = fmt.Sprintf("%d of the %d tree head(s) the peer signed are not the records "+
			"held: a record was lost or changed here after it was taken, or a head no longer "+
			"verifies with the keys the feed holds", ev.Disagree, ev.Heads)
	case !ev.lastAgrees():
		held.Detail = fmt.Sprintf("the last tree head the peer signed covers %d record(s) with root "+
			"%s, and %d are held with root %s: what is held is not what it last signed for",
			ev.Last.Size, ev.Last.Root, ev.Held, ev.Root)
	default:
		held.Detail = fmt.Sprintf("%d record(s) are held, and each of the %d tree head(s) the peer "+
			"signed as it sent them, with keys %s, is the Merkle root of the first so-many of them; "+
			"the last covers all %d, with root %s", ev.Held, ev.Heads, ev.Keys.KeyID, ev.Held, ev.Root)
	}
	for _, h := range ev.Disagreeing {
		held.Failures = append(held.Failures, fmt.Sprintf("%s: the head of %d record(s) with root %s, "+
			"received %s", h.Why, h.Size, h.Root, h.Received))
	}

	unforked := Check{Name: "unforked", Passed: !ev.forked()}
	switch {
	case !ev.forked():
		unforked.Detail = "the peer has sent no tree head, signed with its keys, of a log that is " +
			"not the one held, and this deployment's audit log records none"
	case ev.ForkCount > 0:
		unforked.Detail = fmt.Sprintf("%d tree head(s) the peer signed with its own keys and sent "+
			"here are not the log held: it has signed more than one history. Up to %d are carried "+
			"in this proof with their signatures; this deployment's audit log recorded %d as they "+
			"arrived", ev.ForkCount, MaxPeerForks, ev.ForksRecorded)
	default:
		unforked.Detail = fmt.Sprintf("this deployment's audit log recorded %d tree head(s) from "+
			"the peer that were not the log held, and none is kept with the feed now: the evidence "+
			"was removed after it arrived, and the log's entries say what it was", ev.ForksRecorded)
	}
	for _, f := range ev.Forks {
		unforked.Failures = append(unforked.Failures, fmt.Sprintf("fork: %d record(s), signed root %s, "+
			"held root %s, received %s", f.Head.Size, f.Head.Root, f.Held, f.Received))
	}

	complete := Check{Name: "complete-to", Passed: true}
	switch {
	case ev.Heads == 0:
		complete.Detail = "no batch has been taken with its tree head, so nothing says how far " +
			"the peer's log is held"
	case ev.reachedEnd():
		complete.Detail = fmt.Sprintf("the last batch was received at %s, at or after %s, and "+
			"carried %d record(s), fewer than a full batch of %d: it reached the end of the peer's "+
			"log as it then was, so every record the peer had written by %s is among the %d held",
			ev.LastReceived, ev.At, ev.LastRecords, ev.FullBatch, ev.At, ev.Held)
	case ev.LastRecords >= ev.FullBatch:
		complete.Detail = fmt.Sprintf("the last batch, received at %s, carried a full %d record(s), "+
			"so more may have been waiting behind it: the next batch says", ev.LastReceived,
			ev.LastRecords)
	default:
		complete.Detail = fmt.Sprintf("the last batch was received at %s, before %s, and nothing has "+
			"arrived since. A peer with nothing to send is silent, and so is one that has stopped "+
			"sending, so whether its log is complete up to %s is not known", ev.LastReceived, ev.At,
			ev.At)
	}
	return []Check{held, unforked, complete}
}

// wellFormed refuses evidence whose shapes or numbers do not hold together,
// on either side of signing, and a head carried as the peer's word that its
// keys did not sign.
func (ev *PeerLogEvidence) wellFormed() error {
	if !peerShape.MatchString(ev.Peer) {
		return fmt.Errorf("a peer is named by the feed its log arrives on")
	}
	v, err := ev.Keys.verifier()
	if err != nil {
		return err
	}
	if at, ok := parseInstant(ev.At); !ok || at.IsZero() {
		return fmt.Errorf("a peer-log proof is about a time, written exactly")
	}
	if ev.Held < 0 || ev.Held > maxPeerLog || (ev.Held == 0) != (ev.Root == "") ||
		(ev.Root != "" && !hex64.MatchString(ev.Root)) {
		return fmt.Errorf("what is held is a number of records and, when there are any, their Merkle root")
	}
	if ev.FullBatch != MaxStreamBatch {
		return fmt.Errorf("a full batch is %d records", MaxStreamBatch)
	}
	if ev.Heads < 0 || ev.Agreeing < 0 || ev.Disagree < 0 || ev.Agreeing+ev.Disagree != ev.Heads ||
		len(ev.Disagreeing) != min(ev.Disagree, MaxFailures) {
		return fmt.Errorf("the tree heads kept are those that agree and those that do not, " +
			"the second listed up to a bound")
	}
	for _, h := range ev.Disagreeing {
		got, ok := parseInstant(h.Received)
		if h.Size < 1 || h.Size > maxPeerLog || !hex64.MatchString(h.Root) || !ok || got.IsZero() {
			return fmt.Errorf("a head that disagrees is a size, a root and when it was received")
		}
		switch h.Why {
		case PeerHeadRoot:
			if !hex64.MatchString(h.Held) || h.Held == h.Root || h.Size > ev.Held {
				return fmt.Errorf("a head with another root is held against the root computed here")
			}
		case PeerHeadBeyond:
			if h.Held != "" || h.Size <= ev.Held {
				return fmt.Errorf("a head beyond what is held covers more records than are held")
			}
		case PeerHeadSignature:
			if h.Held != "" && !hex64.MatchString(h.Held) {
				return fmt.Errorf("a head whose signatures fail names a root computed here, or none")
			}
		default:
			return fmt.Errorf("a head disagrees by its root, by reaching beyond what is held, or by its signature")
		}
	}
	if (ev.Heads == 0) != (ev.Last == nil) {
		return fmt.Errorf("the last head kept is carried when any was kept")
	}
	if ev.Last == nil {
		if ev.LastReceived != "" || ev.LastRecords != 0 {
			return fmt.Errorf("with no head kept, no last batch is named")
		}
	} else {
		got, ok := parseInstant(ev.LastReceived)
		if !ok || got.IsZero() || ev.LastRecords < 1 || ev.LastRecords > ev.FullBatch ||
			ev.Last.Size < 1 || ev.Last.Size > maxPeerLog || ev.LastRecords > ev.Last.Size ||
			!hex64.MatchString(ev.Last.Root) {
			return fmt.Errorf("the last batch is a time it was received, the records it carried and its head")
		}
		// The last head is the peer's word, or is listed as one whose
		// signatures no longer verify.
		if v.Verify(*ev.Last) != nil && !ev.lists(ev.Last.Size, ev.Last.Root, PeerHeadSignature) {
			return fmt.Errorf("the last head kept does not verify with the peer's keys, and is not listed as one that does not")
		}
	}
	if ev.ForksRecorded < 0 || ev.ForksRecorded > maxPeerLog {
		return fmt.Errorf("the forks the audit log recorded are counted")
	}
	if ev.ForkCount < 0 || len(ev.Forks) != min(ev.ForkCount, MaxPeerForks) {
		return fmt.Errorf("the forks carried are those counted, up to %d", MaxPeerForks)
	}
	for _, f := range ev.Forks {
		got, ok := parseInstant(f.Received)
		if !ok || got.IsZero() || f.Head.Size < 1 || f.Head.Size > maxPeerLog ||
			!hex64.MatchString(f.Head.Root) || !hex64.MatchString(f.Held) || f.Held == f.Head.Root {
			return fmt.Errorf("a fork is a head the peer signed and a different root computed here")
		}
		// A fork is evidence against the peer only as far as it is the
		// peer's own signature.
		if err := v.Verify(f.Head); err != nil {
			return fmt.Errorf("a fork is carried with signatures the peer's keys made: %w", err)
		}
	}
	return nil
}

// lists reports whether a head is among those listed as disagreeing for a
// reason.
func (ev *PeerLogEvidence) lists(size int, root, why string) bool {
	for _, h := range ev.Disagreeing {
		if h.Size == size && h.Root == root && h.Why == why {
			return true
		}
	}
	return false
}

// validate refuses evidence whose numbers do not hold together, do not
// support the verdict, or do not account for every word the statement says.
func (ev *PeerLogEvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
		return err
	}
	if len(s.Subject) != 1 || s.Subject[0].Digest["sha256"] != ev.subjectDigest() || len(s.Subject[0].Digest) != 1 {
		return fmt.Errorf("a peer-log proof is about one peer's log, by the root of what is held")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the evidence makes this %s, not %s", want, s.Predicate.Verdict)
	}
	got, _ := json.Marshal(s.Predicate.Checks)
	want, _ := json.Marshal(ev.checks())
	if string(got) != string(want) {
		return fmt.Errorf("the checks are not the ones its evidence makes")
	}
	return sameWords(s, ev.subject(), ev.claim(), ev.checks())
}
