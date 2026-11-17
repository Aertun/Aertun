// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

var md0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// mdrIn is a plan of forty emulations over thirty days, committed a minute
// after its window opened, every one run and notified ten minutes later,
// proved an hour after the test closed, against an SLA of thirty minutes and
// a tolerance of a tenth.
func mdrIn() MDRInput {
	in := MDRInput{Plan: "acme-q4", Provider: "acme", PlanSHA256: strings.Repeat("ab", 32),
		Committed: AuditEntry{Seq: 12, Hash: strings.Repeat("cd", 32),
			At: md0.Add(time.Minute + 5*time.Nanosecond).Format(time.RFC3339Nano)},
		WindowStart: md0, WindowEnd: md0.Add(30 * 24 * time.Hour), SLA: 30 * time.Minute,
		Tolerance: 0.1, Planned: 40, Program: "test",
		Now: md0.Add(31*24*time.Hour + 90*time.Minute)}
	for i := range 40 {
		ran := md0.Add(time.Duration(i)*17*time.Hour + 2*time.Hour)
		in.Runs = append(in.Runs, MDRRun{N: i + 1, Emulation: fmt.Sprintf("T1059.%03d-1", i),
			Ran: ran, Notified: ran.Add(10 * time.Minute)})
	}
	return in
}

// missEvery marks k runs, every fourth from the first, missed: never
// notified, or notified the given time after the run.
func missEvery(in *MDRInput, k int, after time.Duration) {
	for i := 0; i < k; i++ {
		r := &in.Runs[i*4%len(in.Runs)]
		if after == 0 {
			r.Notified = time.Time{}
		} else {
			r.Notified = r.Ran.Add(after)
		}
	}
}

func TestAnMDRProofsVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*MDRInput)
		want   Verdict
	}{
		"every run notified in time": {func(*MDRInput) {}, Proven},
		"late is missed":             {func(in *MDRInput) { missEvery(in, 10, 2*time.Hour) }, Refuted},
		"never is missed":            {func(in *MDRInput) { missEvery(in, 10, 0) }, Refuted},
		"one in forty does not show it under a tenth": {
			func(in *MDRInput) { missEvery(in, 1, 0) }, Inconclusive},
		"one in forty is under a fifth": {func(in *MDRInput) {
			missEvery(in, 1, 0)
			in.Tolerance = 0.2
		}, Proven},
		"fewer than thirty runs": {func(in *MDRInput) {
			in.Runs, in.Tolerance = in.Runs[:20], 0.5
		}, Inconclusive},
		"nothing run": {func(in *MDRInput) { in.Runs = nil }, Inconclusive},
		"a test still open decides nothing": {func(in *MDRInput) {
			missEvery(in, 10, 0)
			in.Now = md0.Add(31*24*time.Hour + 29*time.Minute)
		}, Inconclusive},
		"on the SLA to the second is in time": {
			func(in *MDRInput) { missEvery(in, 10, 30*time.Minute) }, Proven},
		"a nanosecond past the SLA is late": {
			func(in *MDRInput) { missEvery(in, 10, 30*time.Minute+time.Nanosecond) }, Refuted},
	}
	for name, c := range cases {
		in := mdrIn()
		c.change(&in)
		st, err := ProveMDR(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
	}
}

// A refutation names each missed item by number and emulation, and says how
// it was missed; a proven proof names none, so the list a customer tests
// with stays its own.
func TestAnMDRProofNamesWhatWasMissed(t *testing.T) {
	in := mdrIn()
	in.Runs[3].Notified = time.Time{}
	in.Runs[7].Notified = in.Runs[7].Ran.Add(time.Hour)
	in.Runs[11].Notified = time.Time{}
	in.Runs[15].Notified = time.Time{}
	in.Runs[19].Notified = time.Time{}
	in.Tolerance = 0.02
	st, err := ProveMDR(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "item 4 (T1059.003-1) not notified|item 8 (T1059.007-1) notified late|" +
		"item 12 (T1059.011-1) not notified|item 16 (T1059.015-1) not notified|" +
		"item 20 (T1059.019-1) not notified"
	if st.Predicate.Verdict != Refuted || strings.Join(st.Predicate.Checks[2].Failures, "|") != want {
		t.Errorf("%s named %q, want %q", st.Predicate.Verdict, st.Predicate.Checks[2].Failures, want)
	}
	ev := st.Predicate.MDR
	if ev.Within != 35 || ev.Late != 1 || ev.Never != 4 || ev.Missed.K != 5 || ev.Missed.N != 40 {
		t.Errorf("counted %+v", ev)
	}
	if !strings.Contains(st.Predicate.Claim, "plan acme-q4") ||
		!strings.Contains(st.Predicate.Claim, "committed at audit entry 12 before any was run") ||
		!strings.Contains(st.Predicate.Claim, "provider acme notified within 30 minutes on all but a share of at most 0.02") {
		t.Errorf("the claim: %s", st.Predicate.Claim)
	}
	b, _ := json.Marshal(st)
	in.Tolerance = 0.5
	st, err = ProveMDR(in)
	if err != nil {
		t.Fatal(err)
	}
	proven, _ := json.Marshal(st)
	if st.Predicate.Verdict != Proven || strings.Contains(string(proven), "T1059") {
		t.Errorf("a %s proof names the emulations tested", st.Predicate.Verdict)
	}
	if !strings.Contains(string(b), "T1059.003-1") {
		t.Error("the refutation does not name the emulation it missed")
	}
}

// The time to notify is the nearest-rank median and 90th percentile of the
// runs notified, late or in time, rounded up to the second.
func TestTheTimeToNotify(t *testing.T) {
	in := mdrIn()
	in.Runs = in.Runs[:10]
	for i := range in.Runs {
		in.Runs[i].Notified = in.Runs[i].Ran.Add(time.Duration(10-i)*time.Minute - 400*time.Millisecond)
	}
	in.Runs[0].Notified = time.Time{} // never: not in the times
	st, err := ProveMDR(in)
	if err != nil {
		t.Fatal(err)
	}
	ev := st.Predicate.MDR
	// Nine times, 1m … 9m each a fraction short and rounded up: the 5th and
	// the 9th of them, in order.
	if ev.Median != 300 || ev.P90 != 540 || ev.Within != 9 || ev.Never != 1 {
		t.Errorf("median %d, p90 %d, %+v", ev.Median, ev.P90, ev)
	}
	if d := st.Predicate.Checks[3].Detail; !strings.Contains(d, "median time from the run to the notification was 5m0s") ||
		!strings.Contains(d, "90th percentile 9m0s") {
		t.Errorf("the time to notify: %s", d)
	}
	in.Runs = in.Runs[:1]
	st, err = ProveMDR(in)
	if err != nil || !strings.Contains(st.Predicate.Checks[3].Detail, "nothing run was notified") {
		t.Errorf("%v: %+v", err, st)
	}
}

// Evidence that does not hold together is refused before anything is
// signed.
func TestAnMDRProofThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*MDRInput){
		"a plan named in prose":       func(in *MDRInput) { in.Plan = "Acme Q4" },
		"a provider in its own words": func(in *MDRInput) { in.Provider = "Acme Managed Detection" },
		"a digest that is not one":    func(in *MDRInput) { in.PlanSHA256 = "abc" },
		"no commitment":               func(in *MDRInput) { in.Committed.Seq = 0 },
		"a window under a day":        func(in *MDRInput) { in.WindowEnd = md0.Add(23 * time.Hour) },
		"a window over a year":        func(in *MDRInput) { in.WindowEnd = md0.Add(400 * 24 * time.Hour) },
		"committed before the window": func(in *MDRInput) {
			in.Committed.At = md0.Add(-time.Hour).Format(time.RFC3339Nano)
		},
		"an SLA under a minute":  func(in *MDRInput) { in.SLA = 30 * time.Second },
		"an SLA over a day":      func(in *MDRInput) { in.SLA = 25 * time.Hour },
		"an SLA in fractions":    func(in *MDRInput) { in.SLA = 30*time.Minute + 500*time.Millisecond },
		"no tolerance":           func(in *MDRInput) { in.Tolerance = 0 },
		"a tolerance of all":     func(in *MDRInput) { in.Tolerance = 1 },
		"an empty plan":          func(in *MDRInput) { in.Planned = 0 },
		"a plan too big to run":  func(in *MDRInput) { in.Planned = MaxMDRItems + 1 },
		"more runs than planned": func(in *MDRInput) { in.Planned = 10 },
		"a run the plan has not": func(in *MDRInput) { in.Runs[39].N = 41 },
		"a run counted twice":    func(in *MDRInput) { in.Runs[1].N = 1 },
		"a run before the commitment": func(in *MDRInput) {
			in.Runs[0].Ran, in.Runs[0].Notified = md0, md0.Add(time.Minute)
		},
		"a notification before the run": func(in *MDRInput) {
			in.Runs[2].Notified = in.Runs[2].Ran.Add(-time.Second)
		},
		"an emulation in prose": func(in *MDRInput) { in.Runs[5].Emulation = "run mimikatz" },
	}
	for name, change := range cases {
		in := mdrIn()
		in.Runs = append([]MDRRun{}, in.Runs...)
		change(&in)
		if _, err := ProveMDR(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

// Every word is rebuilt from the numbers when the statement is opened, so an
// edited one is refused.
func TestAnMDRProofCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	in := mdrIn()
	missEvery(&in, 10, 0)
	in.Runs[1].Notified = in.Runs[1].Ran.Add(time.Hour)
	st, err := ProveMDR(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != Refuted || len(st.Predicate.Checks[2].Failures) != 11 {
		t.Fatalf("%s %+v", st.Predicate.Verdict, st.Predicate.Checks[2])
	}
	tamper := map[string]func(*Statement){
		"verdict":   func(s *Statement) { s.Predicate.Verdict = Proven },
		"claim":     func(s *Statement) { s.Predicate.Claim += " The contract is renewed." },
		"tolerance": func(s *Statement) { s.Predicate.MDR.Tolerance = 0.9 },
		"the missed counted away": func(s *Statement) {
			s.Predicate.MDR.Missed = ExactBound(0, 40)
		},
		"a run made notified": func(s *Statement) {
			s.Predicate.MDR.Items[0].Notified, s.Predicate.MDR.Items[0].Seconds = true, 60
		},
		"the median":     func(s *Statement) { s.Predicate.MDR.Median = 1 },
		"a run dropped":  func(s *Statement) { s.Predicate.MDR.Items = s.Predicate.MDR.Items[1:] },
		"the run window": func(s *Statement) { s.Predicate.MDR.RunWithin = 7 * 24 * 3600 },
		"the window end": func(s *Statement) { s.Predicate.MDR.WindowEnd = md0.Add(29 * 24 * time.Hour).Format(time.RFC3339) },
		"a failure naming an item notified in time": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "item 3 (T1059.002-1) not notified"
		},
		"a failure naming an emulation in prose": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "item 1 (rm -rf /) not notified"
		},
		"a never called late": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "item 1 (T1059.000-1) notified late"
		},
		"a failure dropped": func(s *Statement) {
			s.Predicate.Checks[2].Failures = s.Predicate.Checks[2].Failures[1:]
		},
		"a failure on the wrong check": func(s *Statement) {
			s.Predicate.Checks[3].Failures = s.Predicate.Checks[2].Failures[:1]
		},
		"closed while it was open": func(s *Statement) {
			s.Predicate.VerifiedAt = md0.Add(31 * 24 * time.Hour).Format(time.RFC3339)
		},
		"the first run before the commitment": func(s *Statement) {
			s.Predicate.MDR.FirstRun = md0.Format(time.RFC3339Nano)
		},
		"the subject's digest": func(s *Statement) {
			s.Subject[0].Digest["sha256"] = strings.Repeat("ef", 32)
		},
		"the subject":               func(s *Statement) { s.Subject[0].Name = "mdr/acme-q3" },
		"a second kind of evidence": func(s *Statement) { s.Predicate.ClaimTest = &ClaimEvidence{} },
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
	if err != nil || back.Predicate.MDR.Never != 10 || back.Predicate.MDR.Late != 1 ||
		back.Predicate.Verdict != Refuted || back.Subject[0].Name != "mdr/acme-q4" {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}

// A missed item beyond the cap is counted, not named, and the statement
// still validates with every word rebuilt.
func TestMissedItemsBeyondTheCapAreCounted(t *testing.T) {
	in := mdrIn()
	in.Planned = 70
	for i := 40; i < 70; i++ {
		ran := md0.Add(time.Duration(i)*9*time.Hour + 3*time.Hour)
		in.Runs = append(in.Runs, MDRRun{N: i + 1, Emulation: "T1003.001-2", Ran: ran})
	}
	for i := range 27 {
		in.Runs[i].Notified = time.Time{}
	}
	st, err := ProveMDR(in)
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Predicate.Checks[2]; st.Predicate.Verdict != Refuted || len(c.Failures) != MaxFailures ||
		!strings.Contains(c.Detail, "7 more not listed") {
		t.Errorf("%s %+v", st.Predicate.Verdict, c)
	}
}
