// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/translog"
)

var pl0 = time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

// peerFixture is a peer's log of some records, the keys it signs heads
// with, and another log signed with the same keys: a second history.
type peerFixture struct {
	signer *audit.HeadSigner
	keys   PeerKeys
	log    *translog.Log
	other  *translog.Log
}

func newPeerFixture(t *testing.T, records int) *peerFixture {
	t.Helper()
	ed, ml, err := audit.GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewHeadSigner(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	edPub, mlPub := signer.Verifier().PublicKeys()
	f := &peerFixture{signer: signer, log: translog.New(), other: translog.New(),
		keys: PeerKeys{KeyID: signer.Verifier().KeyID(), Ed25519: base64.StdEncoding.EncodeToString(edPub),
			MLDSA: base64.StdEncoding.EncodeToString(mlPub), Context: audit.HeadContext}}
	for i := 0; i < records; i++ {
		f.log.Append([]byte(fmt.Sprintf("record %d", i)))
		f.other.Append([]byte(fmt.Sprintf("rewritten %d", i)))
	}
	return f
}

// signed is the head of a log's first n records, signed by the peer.
func (f *peerFixture) signed(t *testing.T, l *translog.Log, n int) audit.SignedHead {
	t.Helper()
	h, err := l.HeadAt(n)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := f.signer.Sign(audit.Head{Size: h.Size, Root: h.Root, At: pl0.Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	return sh
}

// peerInput is a peer's five records held under two heads it signed, the
// second received an hour before the time asked about... and one a minute
// after it: complete up to that time, and unforked.
func peerInput(t *testing.T, records int) (PeerLogInput, *peerFixture) {
	t.Helper()
	f := newPeerFixture(t, records)
	last := f.signed(t, f.log, records)
	ev := PeerLogEvidence{Peer: "site-berlin", Keys: f.keys, At: instant(pl0),
		Held: records, Root: f.log.Head().Root, Heads: 2, Agreeing: 2, Last: &last,
		LastReceived: instant(pl0.Add(time.Minute)), LastRecords: 2, FullBatch: MaxStreamBatch}
	return PeerLogInput{Evidence: ev, Program: "test", Now: pl0.Add(time.Hour),
		Materials: []Material{{Name: "peer-leaves", Digest: SHA256([]byte("leaves"))}}}, f
}

// fork is a head of the other history's first n records, held against the
// log's own root at that size.
func (f *peerFixture) fork(t *testing.T, n int) PeerFork {
	t.Helper()
	held, _ := f.log.HeadAt(n)
	return PeerFork{Received: instant(pl0.Add(-time.Hour)), Resent: true, Held: held.Root,
		Head: f.signed(t, f.other, n)}
}

func TestAPeerLogsVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*PeerLogEvidence, *peerFixture)
		want   Verdict
	}{
		"every head agrees and the last batch reached the end": {func(*PeerLogEvidence, *peerFixture) {}, Proven},
		"received exactly at the time asked about": {func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.LastReceived = ev.At
		}, Proven},
		"nothing has arrived since before the time": {func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.LastReceived = instant(pl0.Add(-time.Nanosecond))
		}, Inconclusive},
		"no head was kept": {func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.Heads, ev.Agreeing, ev.Last, ev.LastReceived, ev.LastRecords = 0, 0, nil, "", 0
		}, Inconclusive},
		"a head that is not the records held": {func(ev *PeerLogEvidence, f *peerFixture) {
			held, _ := f.log.HeadAt(3)
			other, _ := f.other.HeadAt(3)
			ev.Agreeing, ev.Disagree = 1, 1
			ev.Disagreeing = []PeerHead{{Size: 3, Root: other.Root, Held: held.Root,
				Received: instant(pl0.Add(-2 * time.Hour)), Why: PeerHeadRoot}}
		}, Refuted},
		"a head of more records than are held": {func(ev *PeerLogEvidence, f *peerFixture) {
			h, _ := f.log.HeadAt(4)
			ev.Held, ev.Root = 4, h.Root
			ev.Agreeing, ev.Disagree = 1, 1
			ev.Disagreeing = []PeerHead{{Size: 5, Root: ev.Last.Root, Received: ev.LastReceived, Why: PeerHeadBeyond}}
		}, Refuted},
		"a head whose signatures no longer verify": {func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.Last.Ed25519 = base64.StdEncoding.EncodeToString(make([]byte, 64))
			ev.Agreeing, ev.Disagree = 1, 1
			ev.Disagreeing = []PeerHead{{Size: ev.Last.Size, Root: ev.Last.Root, Held: ev.Root,
				Received: ev.LastReceived, Why: PeerHeadSignature}}
		}, Refuted},
		"more held than the last head covers": {func(ev *PeerLogEvidence, f *peerFixture) {
			last := f.signed(t, f.log, 4)
			ev.Last = &last
		}, Refuted},
		"a fork the peer signed": {func(ev *PeerLogEvidence, f *peerFixture) {
			ev.ForkCount, ev.ForksRecorded, ev.Forks = 1, 1, []PeerFork{f.fork(t, 3)}
		}, Refuted},
		// Kept with the feed, and not in this log: a log from before forks
		// were recorded, or one whose entry could not be written.
		"a fork kept that this log did not record": {func(ev *PeerLogEvidence, f *peerFixture) {
			ev.ForkCount, ev.Forks = 1, []PeerFork{f.fork(t, 3)}
		}, Refuted},
		"a fork this log recorded and nobody kept": {func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.ForksRecorded = 1
		}, Refuted},
	}
	for name, c := range cases {
		in, f := peerInput(t, 5)
		c.change(&in.Evidence, f)
		st, err := ProvePeerLog(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
	}

	// A last batch that was full says nothing about what waited behind it.
	in, _ := peerInput(t, MaxStreamBatch)
	in.Evidence.LastRecords = MaxStreamBatch
	st, err := ProvePeerLog(in)
	if err != nil || st.Predicate.Verdict != Inconclusive ||
		!strings.Contains(st.Predicate.Checks[2].Detail, "more may have been waiting") {
		t.Errorf("a full last batch: %v: %+v", err, st)
	}
}

// What is held, what forked and how far it reaches are each said exactly.
func TestAPeerLogProofSaysWhatItRestsOn(t *testing.T) {
	in, f := peerInput(t, 5)
	st, err := ProvePeerLog(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Subject[0].Name != "peer-log/site-berlin" || st.Subject[0].Digest["sha256"] != f.log.Head().Root {
		t.Errorf("the subject: %+v", st.Subject)
	}
	if !strings.Contains(st.Predicate.Claim, "site-berlin's audit log up to 2026-11-17T09:00:00Z") {
		t.Errorf("the claim: %s", st.Predicate.Claim)
	}
	if d := st.Predicate.Checks[0].Detail; !strings.Contains(d, "5 record(s) are held") ||
		!strings.Contains(d, "each of the 2 tree head(s)") || !strings.Contains(d, f.keys.KeyID) {
		t.Errorf("what is held: %s", d)
	}
	if d := st.Predicate.Checks[2].Detail; !strings.Contains(d, "received at 2026-11-17T09:01:00Z, at or after 2026-11-17T09:00:00Z") ||
		!strings.Contains(d, "fewer than a full batch of 500") {
		t.Errorf("how far it reaches: %s", d)
	}

	in.Evidence.LastReceived = instant(pl0.Add(-3 * time.Hour))
	st, _ = ProvePeerLog(in)
	if d := st.Predicate.Checks[2].Detail; !strings.Contains(d, "nothing has arrived since") ||
		!strings.Contains(d, "so is one that has stopped sending") {
		t.Errorf("a silent peer: %s", d)
	}

	in, f = peerInput(t, 5)
	fork := f.fork(t, 3)
	in.Evidence.ForkCount, in.Evidence.ForksRecorded, in.Evidence.Forks = 1, 1, []PeerFork{fork}
	st, err = ProvePeerLog(in)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("fork: 3 record(s), signed root %s, held root %s, received 2026-11-17T08:00:00Z",
		fork.Head.Root, fork.Held)
	if got := strings.Join(st.Predicate.Checks[1].Failures, "|"); got != want || st.Predicate.Checks[1].Passed {
		t.Errorf("the fork is named %q, want %q", got, want)
	}

	in, _ = peerInput(t, 5)
	in.Evidence.ForksRecorded = 2
	st, _ = ProvePeerLog(in)
	if d := st.Predicate.Checks[1].Detail; !strings.Contains(d, "recorded 2 tree head(s)") ||
		!strings.Contains(d, "evidence was removed") {
		t.Errorf("evidence removed: %s", d)
	}
}

func TestAPeerLogProofThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*PeerLogEvidence, *peerFixture){
		"a peer in prose":            func(ev *PeerLogEvidence, _ *peerFixture) { ev.Peer = "the Berlin site" },
		"keys named by another id":   func(ev *PeerLogEvidence, _ *peerFixture) { ev.Keys.KeyID = "aertun-head-0000" },
		"keys that are not keys":     func(ev *PeerLogEvidence, _ *peerFixture) { ev.Keys.Ed25519 = "not base64" },
		"no context":                 func(ev *PeerLogEvidence, _ *peerFixture) { ev.Keys.Context = "" },
		"a time not exact":           func(ev *PeerLogEvidence, _ *peerFixture) { ev.At = "17 November" },
		"records with no root":       func(ev *PeerLogEvidence, _ *peerFixture) { ev.Root = "" },
		"a root in prose":            func(ev *PeerLogEvidence, _ *peerFixture) { ev.Root = "the root" },
		"another size of full batch": func(ev *PeerLogEvidence, _ *peerFixture) { ev.FullBatch = 5000 },
		"heads that do not add up":   func(ev *PeerLogEvidence, _ *peerFixture) { ev.Agreeing = 1 },
		"a disagreement not listed":  func(ev *PeerLogEvidence, _ *peerFixture) { ev.Agreeing, ev.Disagree = 1, 1 },
		"heads kept and none carried": func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.Last, ev.LastReceived, ev.LastRecords = nil, "", 0
		},
		"a last batch of nothing": func(ev *PeerLogEvidence, _ *peerFixture) { ev.LastRecords = 0 },
		"a last batch larger than the log": func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.LastRecords = 6
		},
		"a last head another key signed": func(ev *PeerLogEvidence, _ *peerFixture) {
			stranger := newPeerFixture(t, 5)
			last := stranger.signed(t, stranger.log, 5)
			ev.Last = &last
		},
		"a last head with its root changed": func(ev *PeerLogEvidence, f *peerFixture) {
			h, _ := f.other.HeadAt(5)
			ev.Last.Root = h.Root
		},
		"a fork another key signed": func(ev *PeerLogEvidence, f *peerFixture) {
			stranger := newPeerFixture(t, 5)
			fk := stranger.fork(t, 3)
			ev.ForkCount, ev.Forks = 1, []PeerFork{fk}
		},
		"a fork that is the log held": func(ev *PeerLogEvidence, f *peerFixture) {
			fk := f.fork(t, 3)
			fk.Head = f.signed(t, f.log, 3)
			ev.ForkCount, ev.Forks = 1, []PeerFork{fk}
		},
		"forks counted and none carried": func(ev *PeerLogEvidence, _ *peerFixture) { ev.ForkCount = 2 },
		"a head beyond that is not beyond": func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.Agreeing, ev.Disagree = 1, 1
			ev.Disagreeing = []PeerHead{{Size: 3, Root: ev.Root, Received: ev.LastReceived, Why: PeerHeadBeyond}}
		},
		"a head with another root that is the same root": func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.Agreeing, ev.Disagree = 1, 1
			ev.Disagreeing = []PeerHead{{Size: 3, Root: ev.Root, Held: ev.Root, Received: ev.LastReceived,
				Why: PeerHeadRoot}}
		},
		"a disagreement for a reason not known": func(ev *PeerLogEvidence, _ *peerFixture) {
			ev.Agreeing, ev.Disagree = 1, 1
			ev.Disagreeing = []PeerHead{{Size: 3, Root: ev.Root, Received: ev.LastReceived, Why: "odd"}}
		},
	}
	for name, change := range cases {
		in, f := peerInput(t, 5)
		change(&in.Evidence, f)
		if _, err := ProvePeerLog(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

// Every word is rebuilt from the evidence when the statement is opened, and
// every head carried is checked against the peer's keys again.
func TestAPeerLogProofCarriesOnlyWhatItsEvidenceSays(t *testing.T) {
	in, f := peerInput(t, 5)
	in.Evidence.ForkCount, in.Evidence.ForksRecorded, in.Evidence.Forks = 1, 1, []PeerFork{f.fork(t, 3)}
	st, err := ProvePeerLog(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict":      func(s *Statement) { s.Predicate.Verdict = Proven },
		"claim":        func(s *Statement) { s.Predicate.Claim += " Every site is clean." },
		"a detail":     func(s *Statement) { s.Predicate.Checks[1].Detail = "no forks" },
		"a failure":    func(s *Statement) { s.Predicate.Checks[1].Failures = nil },
		"a check gone": func(s *Statement) { s.Predicate.Checks = s.Predicate.Checks[:2] },
		"the subject":  func(s *Statement) { s.Subject[0].Name = "peer-log/site-paris" },
		"another peer": func(s *Statement) { s.Predicate.PeerLog.Peer = "site-paris" },
		"the fork dropped": func(s *Statement) {
			s.Predicate.PeerLog.ForkCount, s.Predicate.PeerLog.ForksRecorded, s.Predicate.PeerLog.Forks = 0, 0, nil
		},
		"the fork's root changed": func(s *Statement) { s.Predicate.PeerLog.Forks[0].Head.Root = f.other.Head().Root },
		"the time moved":          func(s *Statement) { s.Predicate.PeerLog.At = instant(pl0.Add(-24 * time.Hour)) },
		"more held":               func(s *Statement) { s.Predicate.PeerLog.Held = 6 },
		"the last batch later": func(s *Statement) {
			s.Predicate.PeerLog.LastReceived = instant(pl0.Add(2 * time.Hour))
		},
		"other keys": func(s *Statement) {
			s.Predicate.PeerLog.Keys = newPeerFixture(t, 1).keys
		},
		"a second kind of evidence": func(s *Statement) { s.Predicate.Revocation = &RevocationEvidence{} },
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
	if err != nil || back.Predicate.Verdict != Refuted || back.Predicate.PeerLog.ForkCount != 1 ||
		back.Predicate.PeerLog.Last.Size != 5 {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}
