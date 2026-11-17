// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/translog"
)

var sl0 = time.Date(2026, 11, 10, 12, 0, 0, 123456789, time.UTC)

func sha(s string) []byte { sum := sha256.Sum256([]byte(s)); return sum[:] }

// sealedFixture is a batch of five alerts and a log of ten entries, with
// real Merkle paths through both.
type sealedFixture struct {
	digests []string
	batch   *translog.Log
	leaves  []string
	log     *translog.Log
}

func newSealedFixture(t *testing.T) *sealedFixture {
	t.Helper()
	f := &sealedFixture{batch: translog.New(), log: translog.New()}
	for i := range 5 {
		d := sha(fmt.Sprint("alert ", i))
		f.digests = append(f.digests, hex.EncodeToString(d))
		f.batch.Append(d)
	}
	for i := range 10 {
		l := sha(fmt.Sprint("entry ", i))
		f.leaves = append(f.leaves, hex.EncodeToString(l))
		f.log.Append(l)
	}
	return f
}

// head shows entry 7 in the head of size entries.
func (f *sealedFixture) head(t *testing.T, ev *SealedEvidence, size int) {
	t.Helper()
	h, err := f.log.HeadAt(size)
	if err != nil {
		t.Fatal(err)
	}
	path, err := f.log.InclusionProof(ev.Entry-1, size)
	if err != nil {
		t.Fatal(err)
	}
	ev.HeadSize, ev.HeadRoot, ev.HeadPath = size, h.Root, path
}

// sealedInput is the third alert of five, sealed in entry 7 of a log of
// ten, under the head of nine entries in Bitcoin block 870000.
func sealedInput(t *testing.T) (SealedInput, *sealedFixture) {
	t.Helper()
	f := newSealedFixture(t)
	path, err := f.batch.InclusionProof(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	ev := SealedEvidence{Digest: f.digests[2], LogEntries: 10, Batches: 2, Entry: 7,
		Sealed: instant(sl0), BatchRoot: f.batch.Head().Root, BatchSize: 5, BatchIndex: 2,
		BatchPath: path, EntryLeaf: f.leaves[6], Anchor: AnchorBitcoin, Height: 870000}
	ev.BlockHash, ev.Mined, ev.Header = testBlock(sl0.Add(30 * time.Minute))
	f.head(t, &ev, 9)
	return SealedInput{Evidence: ev, Program: "test", Now: sl0.Add(time.Hour),
		Materials: []Material{{Name: "audit-log", Digest: SHA256([]byte("log")), Entries: 10}}}, f
}

// unreached clears everything past the log, as the command leaves it when
// it stops there.
func unreached(ev *SealedEvidence) {
	*ev = SealedEvidence{Digest: ev.Digest, LogEntries: ev.LogEntries, LogBreak: ev.LogBreak,
		Rewritten: ev.Rewritten, Batches: ev.Batches, Unkept: ev.Unkept}
}

// noBlock clears what is said of a block, as the command leaves it when no
// block was checked.
func noBlock(ev *SealedEvidence) { ev.BlockHash, ev.Mined, ev.Header = "", "", "" }

func TestASealedAlertsVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*SealedEvidence, *sealedFixture)
		want   Verdict
		checks int
	}{
		"its head is in a block": {func(*SealedEvidence, *sealedFixture) {}, Proven, 4},
		"its head is pending in the calendars": {func(ev *SealedEvidence, _ *sealedFixture) {
			ev.Anchor, ev.Height = AnchorPending, 0
			noBlock(ev)
		}, Inconclusive, 4},
		// A timestamp's attestation is a height and nothing more: with no
		// header checked for that block, it is not an anchor.
		"its head names a block nobody checked": {func(ev *SealedEvidence, _ *sealedFixture) {
			ev.Anchor = AnchorUnconfirmed
			noBlock(ev)
		}, Inconclusive, 4},
		"nothing anchored covers it": {func(ev *SealedEvidence, f *sealedFixture) {
			ev.Anchor, ev.Height = AnchorNone, 0
			noBlock(ev)
			f.head(t, ev, 10)
		}, Inconclusive, 4},
		"the log breaks": {func(ev *SealedEvidence, _ *sealedFixture) {
			ev.LogBreak, ev.Batches = 4, 0
			unreached(ev)
		}, Refuted, 1},
		"the log was rewritten after its head was sent": {func(ev *SealedEvidence, _ *sealedFixture) {
			ev.Rewritten, ev.Batches = 9, 0
			unreached(ev)
		}, Refuted, 1},
		"it is in no batch": {func(ev *SealedEvidence, _ *sealedFixture) {
			ev.Unkept = 1
			unreached(ev)
		}, Refuted, 2},
		"its path does not reach the root committed": {func(ev *SealedEvidence, f *sealedFixture) {
			ev.BatchRoot = f.digests[0]
		}, Refuted, 2},
		"the entry committed fewer than were kept": {func(ev *SealedEvidence, _ *sealedFixture) {
			ev.BatchSize = 3
		}, Refuted, 2},
		"the entry's path does not reach the head": {func(ev *SealedEvidence, f *sealedFixture) {
			ev.HeadPath = append([]string{f.leaves[0]}, ev.HeadPath[1:]...)
		}, Refuted, 3},
	}
	for name, c := range cases {
		in, f := sealedInput(t)
		c.change(&in.Evidence, f)
		st, err := ProveSealed(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want || len(st.Predicate.Checks) != c.checks {
			t.Errorf("%s: %s with %d checks, want %s with %d: %+v", name, st.Predicate.Verdict,
				len(st.Predicate.Checks), c.want, c.checks, st.Predicate.Checks)
		}
	}
}

// What is attested is said exactly: the block for a proof, and for the
// rest, that the time is the log's word alone.
func TestASealedProofSaysWhatFixesTheTime(t *testing.T) {
	in, f := sealedInput(t)
	st, err := ProveSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Subject[0].Name != "alert/"+in.Evidence.Digest[:16] || st.Subject[0].Digest["sha256"] != in.Evidence.Digest {
		t.Errorf("the subject: %+v", st.Subject)
	}
	if d := st.Predicate.Checks[3].Detail; !strings.Contains(d, "attestation at block 870000") ||
		!strings.Contains(d, in.Evidence.BlockHash+", mined 2026-11-10T12:30:00Z") ||
		!strings.Contains(d, "the work of a real block") {
		t.Errorf("the anchor: %s", d)
	}
	un, _ := sealedInput(t)
	un.Evidence.Anchor = AnchorUnconfirmed
	noBlock(&un.Evidence)
	ust, err := ProveSealed(un)
	if err != nil {
		t.Fatal(err)
	}
	if d := ust.Predicate.Checks[3].Detail; !strings.Contains(d, "naming Bitcoin block 870000") ||
		!strings.Contains(d, "rests on the audit log alone") || !strings.Contains(d, "anchor upgrade") {
		t.Errorf("an unconfirmed anchor: %s", d)
	}
	if d := st.Predicate.Checks[1].Detail; !strings.Contains(d, "audit entry 7, written at 2026-11-10T12:00:00.123456789Z") ||
		!strings.Contains(d, "batch of 5") {
		t.Errorf("the seal: %s", d)
	}
	in.Evidence.Anchor, in.Evidence.Height = AnchorNone, 0
	noBlock(&in.Evidence)
	f.head(t, &in.Evidence, 10)
	st, err = ProveSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Predicate.Checks[3].Detail; !strings.Contains(d, "rests on the audit log alone") ||
		!strings.Contains(d, "aertun auditlog anchor") {
		t.Errorf("an unanchored seal: %s", d)
	}
	in, _ = sealedInput(t)
	unreached(&in.Evidence)
	st, err = ProveSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Predicate.Checks[1].Detail; st.Predicate.Checks[1].Passed ||
		!strings.Contains(d, "in none of the 2 batch(es)") {
		t.Errorf("an alert in no batch: %+v", st.Predicate.Checks)
	}
}

// Evidence whose shapes or numbers do not hold together is refused before
// anything is signed.
func TestASealedProofThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*SealedEvidence){
		"a digest in capitals":         func(ev *SealedEvidence) { ev.Digest = strings.ToUpper(ev.Digest) },
		"a break beyond the log":       func(ev *SealedEvidence) { ev.LogBreak = 11; unreached(ev); ev.Batches = 0 },
		"a break and a rewrite":        func(ev *SealedEvidence) { ev.LogBreak, ev.Rewritten = 2, 3; unreached(ev); ev.Batches = 0 },
		"more batches than entries":    func(ev *SealedEvidence) { ev.Batches = 11 },
		"more unkept than batches":     func(ev *SealedEvidence) { ev.Unkept = 3 },
		"a break that names an entry":  func(ev *SealedEvidence) { ev.LogBreak, ev.Batches = 3, 0 },
		"no batch but a root":          func(ev *SealedEvidence) { ev.Entry = 0 },
		"an entry beyond the log":      func(ev *SealedEvidence) { ev.Entry = 11 },
		"a time not as it was written": func(ev *SealedEvidence) { ev.Sealed = "2026-11-10T17:45:00.123456789+05:45" },
		"a place past the batch":       func(ev *SealedEvidence) { ev.BatchIndex = 5 },
		"a batch over the cap":         func(ev *SealedEvidence) { ev.BatchSize = MaxSealedBatch + 1 },
		"a path in prose":              func(ev *SealedEvidence) { ev.BatchPath[0] = "the root, trust me" },
		"a path longer than a tree":    func(ev *SealedEvidence) { ev.HeadPath = make([]string, 65) },
		"a head without the entry":     func(ev *SealedEvidence) { ev.HeadSize = 6 },
		"a head beyond the log":        func(ev *SealedEvidence) { ev.HeadSize = 11 },
		"a leaf in prose":              func(ev *SealedEvidence) { ev.EntryLeaf = "entry 7" },
		"an anchor in prose":           func(ev *SealedEvidence) { ev.Anchor = "confirmed" },
		"a block of nothing":           func(ev *SealedEvidence) { ev.Height = 0 },
		"a block beyond any chain":     func(ev *SealedEvidence) { ev.Height = MaxBitcoinHeight + 1 },
		"a pending head with a block":  func(ev *SealedEvidence) { ev.Anchor = AnchorPending },
		"a pending head with a header": func(ev *SealedEvidence) { ev.Anchor, ev.Height = AnchorPending, 0 },
		"nothing anchored, a smaller head": func(ev *SealedEvidence) {
			ev.Anchor, ev.Height = AnchorNone, 0
			noBlock(ev)
		},
		"a block with no header": func(ev *SealedEvidence) { ev.Header = "" },
		"a hash that is not its header's": func(ev *SealedEvidence) {
			ev.BlockHash = strings.Repeat("0", 64)
		},
		"a time that is not its header's":    func(ev *SealedEvidence) { ev.Mined = "2026-11-10T11:00:00Z" },
		"an unconfirmed block with a header": func(ev *SealedEvidence) { ev.Anchor = AnchorUnconfirmed },
		"an unconfirmed block of nothing": func(ev *SealedEvidence) {
			ev.Anchor, ev.Height = AnchorUnconfirmed, 0
			noBlock(ev)
		},
	}
	for name, change := range cases {
		in, _ := sealedInput(t)
		change(&in.Evidence)
		if _, err := ProveSealed(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

// Every word is rebuilt from the evidence when the statement is opened, and
// every path is walked again, so an edited one is refused.
func TestASealedProofCarriesOnlyWhatItsEvidenceSays(t *testing.T) {
	in, f := sealedInput(t)
	st, err := ProveSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict":       func(s *Statement) { s.Predicate.Verdict = Inconclusive },
		"claim":         func(s *Statement) { s.Predicate.Claim += " Before anybody else." },
		"a detail":      func(s *Statement) { s.Predicate.Checks[3].Detail = "anchored, honestly" },
		"a failure":     func(s *Statement) { s.Predicate.Checks[0].Failures = []string{"nothing"} },
		"a check gone":  func(s *Statement) { s.Predicate.Checks = s.Predicate.Checks[:3] },
		"the subject":   func(s *Statement) { s.Subject[0].Name = "alert/0000000000000000" },
		"its digest":    func(s *Statement) { s.Subject[0].Digest["sha256"] = f.digests[0] },
		"another alert": func(s *Statement) { s.Predicate.Sealed.Digest = f.digests[3] },
		"the block moved": func(s *Statement) {
			s.Predicate.Sealed.Height = 800000
		},
		"made pending": func(s *Statement) {
			s.Predicate.Sealed.Anchor, s.Predicate.Sealed.Height = AnchorPending, 0
			noBlock(s.Predicate.Sealed)
		},
		"an unconfirmed block made confirmed": func(s *Statement) {
			s.Predicate.Sealed.Anchor = AnchorUnconfirmed
		},
		"the block made earlier": func(s *Statement) { s.Predicate.Sealed.Mined = "2026-11-09T12:30:00Z" },
		"another block's header": func(s *Statement) {
			_, _, s.Predicate.Sealed.Header = testBlock(sl0.Add(-30 * 24 * time.Hour))
		},
		"a hash in the path": func(s *Statement) { s.Predicate.Sealed.BatchPath[1] = f.digests[4] },
		"the entry moved":    func(s *Statement) { s.Predicate.Sealed.Entry = 8 },
		"a second kind of evidence": func(s *Statement) {
			s.Predicate.Revocation = &RevocationEvidence{}
		},
	}
	for name, change := range tamper {
		var copied Statement
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &copied)
		change(&copied)
		if copied.Validate() == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
	k := mustKey(t)
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(env, k.PublicKey())
	if err != nil || back.Predicate.Verdict != Proven || back.Predicate.Sealed.Height != 870000 ||
		back.Predicate.Sealed.HeadSize != 9 {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}
