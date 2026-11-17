// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/aertun/aertun/internal/translog"
)

// A sealed-alert proof: an alert existed no later than a time somebody
// other than its owner fixed (internal/seal).
//
// # Why
//
// "Our monitor saw it first" and "we raised this alert before the exploit"
// are claims nobody can check. An alert log is written by the party making
// the claim and can be edited afterwards, so a timestamp in it is that
// party's word. Aertun already keeps a hash-chained audit log with a Merkle
// tree over it and sends the tree's head to OpenTimestamps; an alert whose
// digest is committed in an entry of that log is fixed in time as firmly as
// the head that covers the entry.
//
// # The claim
//
// The alert whose canonical JSON has a given SHA-256 was sealed in an entry
// of the audit log, the log verifies from its first entry, and a Bitcoin
// timestamp attests a head of the log that includes that entry.
//
//   - refuted when the log does not verify — an entry that does not
//     re-hash, link or follow in sequence, or a head the log sent to be
//     anchored that its first entries no longer hash to — or when the digest
//     is in no batch the log records sealing, or its path to the batch's
//     root, or the entry's path to the head, does not verify;
//   - proven when it was sealed and a confirmed Bitcoin attestation
//     commits to a head that includes the entry: the alert existed no later
//     than the block that holds the commitment;
//   - inconclusive when it was sealed and nothing confirmed covers the
//     entry yet: the head that does was sent and is pending in the
//     calendars, or no head sent since covers it. The entry's time is then
//     the log's own word, and the proof says so.
//
// # What is attested, exactly
//
// OpenTimestamps attests one value: the Merkle root of the audit log's first
// N entries, the head `aertun auditlog anchor` sends. Not the chain as a
// whole and not an entry: a head, by its root and the size it covers. The
// proof names that root and size, the entry's leaf and path into it, and
// the block height the attestation names. internal/anchor walks the
// attestation's operations from the root to the Bitcoin attestation, which
// shows the attestation is about this root; whether that block holds the
// commitment needs block headers, which Aertun does not have, and is
// checked with `ots verify`. The block's time is the chain's: the proof
// names the height, and the time is read from the chain.
//
// # What it does not cover
//
// What the alert says, or that it is true: only that these exact bytes, up
// to the canonical form, existed by then. The alert itself is never carried
// — only its digest — because it may hold what a monitor saw, and a proof
// travels further than that should.

// SealedVerifier and its version name this verifier.
const (
	SealedVerifier        = "aertun/seal"
	SealedVerifierVersion = "1"
)

// PredicateSealed is the predicate of a sealed-alert proof.
const PredicateSealed = "https://aertun.github.io/proof/sealed/v1"

// What fixes a head in time.
const (
	// AnchorBitcoin is a confirmed attestation: the head's root reaches a
	// Bitcoin block.
	AnchorBitcoin = "bitcoin"
	// AnchorPending is a head a calendar holds and has not yet put in a
	// block. It is not an anchor.
	AnchorPending = "pending"
	// AnchorNone is no head sent to be anchored that covers the entry.
	AnchorNone = "none"
)

// The bounds a sealed-alert proof's numbers are held to.
const (
	// MaxSealedBatch bounds the digests one batch holds, and so the batch
	// a proof can name: sixteen levels of tree.
	MaxSealedBatch = 1 << 16
	// MaxBitcoinHeight bounds the block an attestation can name: centuries
	// beyond the chain's height now, and far short of a number that is not
	// a block at all.
	MaxBitcoinHeight = 10_000_000
	// maxSealedPath bounds an audit path, which is one hash per level of
	// its tree.
	maxSealedPath = 64
	// maxSealedLog bounds the log's counts.
	maxSealedLog = math.MaxInt32
)

// SealedEvidence is what a sealed-alert proof rests on.
type SealedEvidence struct {
	// Digest is the alert's identity: the SHA-256, in hex, of its JSON in
	// the canonical form of RFC 8785, and the subject's digest. The alert
	// itself is not carried.
	Digest string `json:"digest"`
	// LogEntries is how many entries the audit log held when it was read,
	// counting one that could not be read.
	LogEntries int `json:"log_entries"`
	// LogBreak is the first entry, counting from one, that did not re-hash,
	// did not link to the one before it, was out of sequence or could not be
	// read; zero when every entry verified.
	LogBreak int `json:"log_break,omitempty"`
	// Rewritten is the size of a head the log sent to be anchored that its
	// first entries no longer hash to — the log rewritten after the head
	// left the machine; zero when every such head still matches.
	Rewritten int `json:"rewritten,omitempty"`
	// Batches is how many batches the log records sealing: the batches the
	// digest was looked for in.
	Batches int `json:"batches"`
	// Unkept is how many of those batches have no readable record of their
	// digests here, so the digest could not be looked for in them.
	Unkept int `json:"unkept,omitempty"`
	// Entry is the audit entry that committed the earliest batch holding
	// the digest; zero when none did.
	Entry int `json:"entry,omitempty"`
	// Sealed is when that entry was written, as the log recorded it, RFC
	// 3339 to the nanosecond: the log's own clock, which an anchor bounds.
	Sealed string `json:"sealed,omitempty"`
	// BatchRoot is the RFC 6962 Merkle root over the batch's digests, as
	// the entry committed it.
	BatchRoot string `json:"batch_root,omitempty"`
	// BatchSize is how many digests the entry says the batch holds.
	BatchSize int `json:"batch_size,omitempty"`
	// BatchIndex is the digest's place in the batch, counting from zero.
	BatchIndex int `json:"batch_index,omitempty"`
	// BatchPath is the RFC 6962 audit path from the digest's leaf to the
	// batch root, nearest the leaf first.
	BatchPath []string `json:"batch_path,omitempty"`
	// EntryLeaf is the entry's leaf in the audit log's Merkle tree, which
	// internal/audit derives from the entry's content and its chain hashes.
	EntryLeaf string `json:"entry_leaf,omitempty"`
	// HeadSize is how many entries the head the entry is shown in covers:
	// the anchored head when one covers the entry, otherwise the log as
	// read.
	HeadSize int `json:"head_size,omitempty"`
	// HeadRoot is that head's Merkle root: for an anchored head, the value
	// the timestamp commits to.
	HeadRoot string `json:"head_root,omitempty"`
	// HeadPath is the RFC 6962 audit path from the entry's leaf, at index
	// Entry-1, to the head's root, nearest the leaf first.
	HeadPath []string `json:"head_path,omitempty"`
	// Anchor is what fixes that head in time: bitcoin for a confirmed
	// attestation, pending for a head a calendar holds and has not yet put
	// in a block, none when no head sent to be anchored covers the entry.
	Anchor string `json:"anchor,omitempty"`
	// Height is the Bitcoin block the attestation names, when Anchor is
	// bitcoin.
	Height int `json:"height,omitempty"`
}

// SealedInput is what a sealed-alert proof is made from: the evidence as
// the command found it, which is checked here before anything is signed.
type SealedInput struct {
	Evidence  SealedEvidence
	Materials []Material
	Program   string
	Now       time.Time
}

// ProveSealed builds the unsigned statement.
func ProveSealed(in SealedInput) (*Statement, error) {
	ev := in.Evidence
	ev.BatchPath = append([]string(nil), ev.BatchPath...)
	ev.HeadPath = append([]string(nil), ev.HeadPath...)
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: Digest{"sha256": ev.Digest}}},
		PredicateType: PredicateSealed,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: SealedVerifier, Version: SealedVerifierVersion,
				Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(),
			Sealed:    &ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *SealedEvidence) subject() string { return "alert/" + ev.Digest[:16] }

// logVerifies is the first check: the log is whole, and no head it sent
// out has been rewritten since.
func (ev *SealedEvidence) logVerifies() bool { return ev.LogBreak == 0 && ev.Rewritten == 0 }

// inBatch recomputes the batch's root from the digest and its path.
func (ev *SealedEvidence) inBatch() bool {
	return ev.Entry > 0 && included(ev.Digest, ev.BatchIndex, ev.BatchSize, ev.BatchPath, ev.BatchRoot)
}

// inLog recomputes the head's root from the entry's leaf and its path.
func (ev *SealedEvidence) inLog() bool {
	return ev.Entry > 0 && included(ev.EntryLeaf, ev.Entry-1, ev.HeadSize, ev.HeadPath, ev.HeadRoot)
}

// included runs translog's verifier — the one every inclusion proof in
// this program is checked with — over hex, so a proof's paths are checked
// whenever it is opened and not only when it was made.
func included(leaf string, index, size int, path []string, root string) bool {
	l, err1 := hex.DecodeString(leaf)
	r, err2 := hex.DecodeString(root)
	raw, err3 := translog.DecodeHashes(path)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	return translog.VerifyInclusion(translog.HashLeaf(l), index, size, raw, r) == nil
}

func validPath(path []string) bool {
	if len(path) > maxSealedPath {
		return false
	}
	for _, h := range path {
		if !hex64.MatchString(h) {
			return false
		}
	}
	return true
}

// wellFormed refuses evidence whose shapes or numbers do not hold together,
// on either side of signing. Every string is a hex digest, a time, or one
// of three words; every number is bounded by another.
func (ev *SealedEvidence) wellFormed() error {
	if !hex64.MatchString(ev.Digest) {
		return fmt.Errorf("an alert is named by the lower-case sha256 of its canonical JSON")
	}
	if ev.LogEntries < 0 || ev.LogEntries > maxSealedLog || ev.LogBreak < 0 || ev.LogBreak > ev.LogEntries ||
		ev.Rewritten < 0 || ev.Rewritten > maxSealedLog || (ev.LogBreak > 0 && ev.Rewritten > 0) ||
		ev.Batches < 0 || ev.Batches > ev.LogEntries || ev.Unkept < 0 || ev.Unkept > ev.Batches {
		return fmt.Errorf("the log's counts do not hold together: a break within the log, or a " +
			"rewritten head, not both, and no more batches than entries")
	}
	unreached := ev.Entry == 0 && ev.Sealed == "" && ev.BatchRoot == "" && ev.BatchSize == 0 &&
		ev.BatchIndex == 0 && len(ev.BatchPath) == 0 && ev.EntryLeaf == "" && ev.HeadSize == 0 &&
		ev.HeadRoot == "" && len(ev.HeadPath) == 0 && ev.Anchor == "" && ev.Height == 0
	if !ev.logVerifies() {
		if ev.Batches != 0 || ev.Unkept != 0 || !unreached {
			return fmt.Errorf("nothing is taken from a log that does not verify, and this names " +
				"batches, an entry or an anchor")
		}
		return nil
	}
	if ev.Entry == 0 {
		if !unreached {
			return fmt.Errorf("a digest found in no batch has no batch, entry or anchor")
		}
		return nil
	}
	sealed, err := time.Parse(time.RFC3339Nano, ev.Sealed)
	if ev.Entry < 1 || ev.Entry > ev.LogEntries || ev.Batches < 1 || err != nil || instant(sealed) != ev.Sealed {
		return fmt.Errorf("the entry that sealed it is one of the log's, with the time it was written")
	}
	if !hex64.MatchString(ev.BatchRoot) || ev.BatchSize < 1 || ev.BatchSize > MaxSealedBatch ||
		ev.BatchIndex < 0 || ev.BatchIndex >= ev.BatchSize || !validPath(ev.BatchPath) {
		return fmt.Errorf("a batch is a Merkle root over between 1 and %d digests, with the "+
			"digest's place in it and a path of hashes", MaxSealedBatch)
	}
	if !hex64.MatchString(ev.EntryLeaf) || ev.HeadSize < ev.Entry || ev.HeadSize > ev.LogEntries ||
		!hex64.MatchString(ev.HeadRoot) || !validPath(ev.HeadPath) {
		return fmt.Errorf("the entry is shown by its leaf and a path of hashes in a head of the " +
			"log that includes it")
	}
	switch ev.Anchor {
	case AnchorBitcoin:
		if ev.Height < 1 || ev.Height > MaxBitcoinHeight {
			return fmt.Errorf("a Bitcoin attestation names a block between 1 and %d", MaxBitcoinHeight)
		}
	case AnchorPending:
		if ev.Height != 0 {
			return fmt.Errorf("a pending head names no block")
		}
	case AnchorNone:
		if ev.Height != 0 || ev.HeadSize != ev.LogEntries {
			return fmt.Errorf("with nothing anchored, the entry is shown in the log as read, " +
				"and no block is named")
		}
	default:
		return fmt.Errorf("an anchor is bitcoin, pending or none")
	}
	return nil
}

func (ev *SealedEvidence) verdict() Verdict {
	switch {
	case !ev.logVerifies(), !ev.inBatch(), !ev.inLog():
		return Refuted
	case ev.Anchor == AnchorBitcoin:
		return Proven
	}
	return Inconclusive
}

func (ev *SealedEvidence) claim() string {
	return fmt.Sprintf("The alert whose RFC 8785 canonical JSON has SHA-256 %s was sealed in an "+
		"entry of the audit log, the log verifies from its first entry, and a Bitcoin timestamp "+
		"attests a head of the log that includes that entry: the alert existed no later than the "+
		"block that holds it.", ev.Digest)
}

// checks are the proof's checks, in the order they are run; each needs the
// one before it, so they stop at the first that fails.
func (ev *SealedEvidence) checks() []Check {
	log := Check{Name: "log-verifies", Passed: ev.logVerifies()}
	switch {
	case ev.LogBreak > 0:
		log.Detail = fmt.Sprintf("entry %d of %d does not re-hash, link to the one before it, "+
			"follow it in sequence or read at all, so nothing can be taken from the log",
			ev.LogBreak, ev.LogEntries)
	case ev.Rewritten > 0:
		log.Detail = fmt.Sprintf("the log's first %d entries no longer hash to the root it sent to "+
			"be anchored, so they were rewritten after that head left this machine", ev.Rewritten)
	default:
		log.Detail = fmt.Sprintf("%d entries re-hash and link from the first, and every head the "+
			"log sent to be anchored still matches its first entries", ev.LogEntries)
	}
	out := []Check{log}
	if !log.Passed {
		return out
	}

	sealed := Check{Name: "sealed", Passed: ev.inBatch()}
	switch {
	case ev.Entry == 0:
		sealed.Detail = fmt.Sprintf("the digest is in none of the %d batch(es) the log records sealing",
			ev.Batches)
		if ev.Unkept > 0 {
			sealed.Detail += fmt.Sprintf("; %d of them have no readable record of their digests here, "+
				"so it could not be looked for in those", ev.Unkept)
		}
	case !sealed.Passed:
		sealed.Detail = fmt.Sprintf("audit entry %d committed a batch of %d with Merkle root %s, and "+
			"the digests kept for it put this one at leaf %d by a path that does not reach that root, "+
			"so its inclusion cannot be shown", ev.Entry, ev.BatchSize, ev.BatchRoot, ev.BatchIndex)
	default:
		sealed.Detail = fmt.Sprintf("audit entry %d, written at %s, committed a batch of %d with "+
			"Merkle root %s; the digest is leaf %d, and its path of %d hash(es) reaches that root",
			ev.Entry, ev.Sealed, ev.BatchSize, ev.BatchRoot, ev.BatchIndex, len(ev.BatchPath))
	}
	out = append(out, sealed)
	if !sealed.Passed {
		return out
	}

	inLog := Check{Name: "in-log", Passed: ev.inLog()}
	if inLog.Passed {
		inLog.Detail = fmt.Sprintf("entry %d is leaf %d of the head of %d entries with Merkle root "+
			"%s, by a path of %d hash(es)", ev.Entry, ev.Entry-1, ev.HeadSize, ev.HeadRoot, len(ev.HeadPath))
	} else {
		inLog.Detail = fmt.Sprintf("entry %d's leaf does not reach the Merkle root %s of the head of "+
			"%d entries by the path given", ev.Entry, ev.HeadRoot, ev.HeadSize)
	}
	out = append(out, inLog)
	if !inLog.Passed {
		return out
	}

	anchored := Check{Name: "anchored", Passed: true}
	switch ev.Anchor {
	case AnchorBitcoin:
		anchored.Detail = fmt.Sprintf("an OpenTimestamps proof walks from that root to a Bitcoin "+
			"attestation at block %d, so the alert existed no later than block %d was mined; whether "+
			"the block holds the commitment needs block headers Aertun does not have, and is "+
			"checked with ots verify", ev.Height, ev.Height)
	case AnchorPending:
		anchored.Detail = fmt.Sprintf("that head was sent to OpenTimestamps calendars and no Bitcoin "+
			"attestation covers entry %d yet, so the time %s rests on the audit log alone; "+
			"aertun auditlog anchor upgrade collects the attestation once a calendar has one",
			ev.Entry, ev.Sealed)
	default:
		anchored.Detail = fmt.Sprintf("no head sent to be anchored covers entry %d, so the time %s "+
			"rests on the audit log alone; aertun auditlog anchor sends the head as it stands",
			ev.Entry, ev.Sealed)
	}
	return append(out, anchored)
}

// validate refuses evidence whose numbers do not hold together, do not
// support the verdict, or do not account for every word the statement
// says.
func (ev *SealedEvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
		return err
	}
	if len(s.Subject) != 1 || s.Subject[0].Digest["sha256"] != ev.Digest || len(s.Subject[0].Digest) != 1 {
		return fmt.Errorf("a sealed-alert proof is about one alert, by the digest its evidence names")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the evidence makes this %s, not %s", want, s.Predicate.Verdict)
	}
	for _, c := range s.Predicate.Checks {
		if len(c.Failures) > 0 {
			return fmt.Errorf("a sealed-alert proof says what failed in its checks' details, and lists nothing")
		}
	}
	return sameWords(s, ev.subject(), ev.claim(), ev.checks())
}
