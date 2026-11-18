// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
)

var ck0 = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

func ckAt(d time.Duration) string { return instant(ck0.Add(d)) }

// clockInput is an awareness decision recorded and anchored, with GDPR's
// seventy-two hours met, proved four days later.
func clockInput() ClockInput {
	return ClockInput{Evidence: ClockEvidence{Incident: "inc-20261110-abc123", Trigger: "aware",
		Entry: 41, Decided: ckAt(0), Recorded: ckAt(-20 * time.Millisecond), Verified: true,
		Anchor: clockHead(60, "ab", 921004, ck0.Add(40*time.Minute), "alice.btc.calendar.opentimestamps.org"),
		Linked: 2, Lead: 5400,
		Duties: []ClockDuty{{Regime: "GDPR Article 33", Due: ckAt(72 * time.Hour),
			Done: ckAt(30 * time.Hour), Outcome: DutyMet}}},
		Lines: []byte("{}\n"), Program: "test", Now: ck0.Add(96 * time.Hour)}
}

// clockHead is a head anchored in a block mined in the test at a time.
func clockHead(size int, root string, block uint64, mined time.Time, calendar string) *ClockHead {
	h := &ClockHead{Size: size, Root: strings.Repeat(root, 32), Block: block, Calendar: calendar}
	h.Hash, h.Mined, h.Header = testBlock(mined)
	return h
}

func TestAClocksVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*ClockEvidence)
		want   Verdict
	}{
		"recorded, anchored and met": {func(*ClockEvidence) {}, Proven},
		"no anchor yet":              {func(ev *ClockEvidence) { ev.Anchor = nil }, Inconclusive},
		"an unverified person":       {func(ev *ClockEvidence) { ev.Verified = false }, Inconclusive},
		"a clock still running": {func(ev *ClockEvidence) {
			ev.Duties = append(ev.Duties, ClockDuty{Regime: "NIS2 final report", Outcome: DutyOpen})
		}, Inconclusive},
		"ruled out": {func(ev *ClockEvidence) {
			ev.Duties[0].Waived, ev.Duties[0].Outcome = true, DutyWaived
		}, Proven},
		"not in the log": {func(ev *ClockEvidence) {
			ev.Entry, ev.Decided, ev.Verified, ev.Anchor = 0, "", false, nil
		}, Refuted},
		"the clock moved earlier": {func(ev *ClockEvidence) { ev.Recorded = ckAt(-6 * time.Hour) }, Refuted},
		"the clock moved later":   {func(ev *ClockEvidence) { ev.Recorded = ckAt(time.Second) }, Refuted},
		"discharged late": {func(ev *ClockEvidence) {
			ev.Duties[0].Done, ev.Duties[0].Outcome = ckAt(80*time.Hour), DutyLate
		}, Refuted},
		"past due, not discharged": {func(ev *ClockEvidence) {
			ev.Duties[0].Done, ev.Duties[0].Outcome = "", DutyLate
		}, Refuted},
		"a discharge moved": {func(ev *ClockEvidence) {
			ev.Duties[0].Moved, ev.Duties[0].Recorded = true, ckAt(20*time.Hour)
		}, Refuted},
		"a discharge only in the incident": {func(ev *ClockEvidence) {
			ev.Duties[0].Done, ev.Duties[0].Outcome = "", DutyLate
			ev.Duties[0].Moved, ev.Duties[0].Recorded = true, ckAt(30*time.Hour)
		}, Refuted},
		"an anchored head the log no longer matches": {func(ev *ClockEvidence) {
			ev.Broken = []ClockHead{*clockHead(30, "cd", 920000, ck0.Add(-48*time.Hour),
				"bob.btc.calendar.opentimestamps.org")}
		}, Refuted},
		// An entry cannot be written after the block that anchors it: the
		// time in it is then not when it was written. Bitcoin lets a
		// block's own time run two hours off, and no further.
		"written after the block that anchors it": {func(ev *ClockEvidence) {
			ev.Anchor = clockHead(60, "ab", 921004, ck0.Add(-2*time.Hour-time.Second),
				"alice.btc.calendar.opentimestamps.org")
		}, Refuted},
		"within the two hours a block's time may run off": {func(ev *ClockEvidence) {
			ev.Anchor = clockHead(60, "ab", 921004, ck0.Add(-2*time.Hour),
				"alice.btc.calendar.opentimestamps.org")
		}, Proven},
	}
	for name, c := range cases {
		in := clockInput()
		in.Evidence.Duties = append([]ClockDuty{}, in.Evidence.Duties...)
		c.change(&in.Evidence)
		st, err := ProveClock(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
	}
}

// What failed is said in closed phrases, names from the table and times.
func TestAClockSaysWhatMovedAndWhatWasLate(t *testing.T) {
	in := clockInput()
	in.Evidence.Recorded = ckAt(-6 * time.Hour)
	in.Evidence.Duties[0].Done, in.Evidence.Duties[0].Outcome = ckAt(80*time.Hour), DutyLate
	st, err := ProveClock(in)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(st.Predicate.Checks[0].Failures, "|") + "|" +
		strings.Join(st.Predicate.Checks[3].Failures, "|")
	want := "moved: aware at 2026-11-10T03:00:00Z in the incident and 2026-11-10T09:00:00Z in the log|" +
		"late: GDPR Article 33 due 2026-11-13T09:00:00Z, discharged 2026-11-13T17:00:00Z"
	if got != want {
		t.Errorf("named %q, want %q", got, want)
	}
	if d := st.Predicate.Checks[1].Detail; !strings.Contains(d, "Bitcoin block 921004") {
		t.Errorf("the anchor is not said: %s", d)
	}
	if d := st.Predicate.Checks[2].Detail; !strings.Contains(d, "first seen 90 minutes before") {
		t.Errorf("the lead is not said: %s", d)
	}
}

func TestAClockThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*ClockEvidence){
		"an incident in prose":       func(ev *ClockEvidence) { ev.Incident = "the outage" },
		"a decision not in the list": func(ev *ClockEvidence) { ev.Trigger = "embarrassing" },
		"a regime not in the table":  func(ev *ClockEvidence) { ev.Duties[0].Regime = "Our policy" },
		"a regime another decision starts": func(ev *ClockEvidence) {
			ev.Duties[0].Regime = "SEC Item 1.05"
		},
		"an outcome the times do not make": func(ev *ClockEvidence) { ev.Duties[0].Outcome = DutyLate },
		"a regime twice":                   func(ev *ClockEvidence) { ev.Duties = append(ev.Duties, ev.Duties[0]) },
		"verified with no entry":           func(ev *ClockEvidence) { ev.Entry, ev.Decided, ev.Anchor = 0, "", nil },
		"an anchor before the entry":       func(ev *ClockEvidence) { ev.Anchor.Size = 40 },
		"a calendar as a URL": func(ev *ClockEvidence) {
			ev.Anchor.Calendar = "https://alice.btc.calendar.opentimestamps.org/"
		},
		"a root that is not hex": func(ev *ClockEvidence) { ev.Anchor.Root = "root" },
		"a block with no header": func(ev *ClockEvidence) { ev.Anchor.Header = "" },
		"a hash that is not its header's": func(ev *ClockEvidence) {
			ev.Anchor.Hash = strings.Repeat("0", 64)
		},
		"a time that is not its header's": func(ev *ClockEvidence) {
			ev.Anchor.Mined = "2026-11-10T08:00:00Z"
		},
		"a header with its nonce changed": func(ev *ClockEvidence) {
			// Half of all nonces meet the easy target, so one that does not
			// is looked for; the hash is the changed header's own.
			for n := 0; n < 64; n++ {
				hd, _ := anchor.ParseHeader(ev.Anchor.Header)
				hd[76] ^= byte(n + 1)
				if hd.Worked() != nil {
					ev.Anchor.Header, ev.Anchor.Hash = hd.Hex(), hd.Hash()
					return
				}
			}
		},
		"a time not exact":           func(ev *ClockEvidence) { ev.Decided = "2026-11-10T09:00:00.000Z" },
		"a lead with nothing linked": func(ev *ClockEvidence) { ev.Linked = 0 },
		"a move that agrees": func(ev *ClockEvidence) {
			ev.Duties[0].Moved, ev.Duties[0].Recorded = true, ev.Duties[0].Done
		},
	}
	for name, change := range cases {
		in := clockInput()
		a := *in.Evidence.Anchor
		in.Evidence.Anchor = &a
		in.Evidence.Duties = append([]ClockDuty{}, in.Evidence.Duties...)
		change(&in.Evidence)
		if _, err := ProveClock(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

func TestAClockCarriesOnlyWhatItsEvidenceSays(t *testing.T) {
	in := clockInput()
	in.Evidence.Duties[0].Done, in.Evidence.Duties[0].Outcome = ckAt(80*time.Hour), DutyLate
	st, err := ProveClock(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict": func(s *Statement) { s.Predicate.Verdict = Proven },
		"claim":   func(s *Statement) { s.Predicate.Claim += " We were on time." },
		"a failure dropped": func(s *Statement) {
			s.Predicate.Checks[3].Failures, s.Predicate.Checks[3].Passed = nil, true
			s.Predicate.Verdict = Proven
		},
		"a failure reworded": func(s *Statement) {
			s.Predicate.Checks[3].Failures[0] = "late: GDPR Article 33, but only slightly"
		},
		"the discharge made earlier": func(s *Statement) {
			s.Predicate.Clock.Duties[0].Done = ckAt(30 * time.Hour)
		},
		"the decision made later": func(s *Statement) { s.Predicate.Clock.Decided = ckAt(time.Hour) },
		"the block made earlier": func(s *Statement) {
			s.Predicate.Clock.Anchor.Mined = "2026-11-09T09:40:00Z"
		},
		"another block's hash": func(s *Statement) {
			s.Predicate.Clock.Anchor.Hash = strings.Repeat("0", 64)
		},
		"another block's header": func(s *Statement) {
			_, _, s.Predicate.Clock.Anchor.Header = testBlock(ck0.Add(-30 * 24 * time.Hour))
		},
		"the block's number": func(s *Statement) { s.Predicate.Clock.Anchor.Block = 800000 },
		"a second kind":      func(s *Statement) { s.Predicate.Revocation = &RevocationEvidence{} },
		"the subject":        func(s *Statement) { s.Subject[0].Name = "incident/inc-20261110-abc123/material" },
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
	// A duty never discharged is late or still running depending on when
	// the proof was made, so the moment of proving is part of what is held.
	open := clockInput()
	open.Evidence.Duties[0].Done, open.Evidence.Duties[0].Outcome = "", DutyLate
	late, err := ProveClock(open)
	if err != nil {
		t.Fatal(err)
	}
	late.Predicate.VerifiedAt = ck0.Add(10 * time.Hour).Format(time.RFC3339)
	if late.Validate() == nil {
		t.Error("a proof moved to before the deadline validated")
	}
	k := mustKey(t)
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	if back, err := Open(env, k.PublicKey()); err != nil || back.Predicate.Clock.Entry != 41 {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}
