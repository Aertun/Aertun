// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func breachInput() BreachScopeInput {
	return BreachScopeInput{Evidence: BreachScopeEvidence{Vendor: "acme-crm", Reference: "ACME-SA-2026-07",
		Since: "2026-08-08T00:00:00Z", Until: "2026-08-18T00:00:00Z", Margin: 30 * 24 * 3600,
		Told: ToldNotAffected, HeldBefore: true, HeldDuring: true, HeldAfter: true, Events: 90210,
		Indicators: []BreachIndicator{{Type: ObsIPv4, Value: "203.0.113.7"},
			{Type: ObsDomain, Value: "exfil.example"}}},
		Disclosure: []byte("{}"), Program: "test", Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
}

func TestABreachScopesVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*BreachScopeEvidence)
		want   Verdict
	}{
		"nothing seen, everything held": {func(*BreachScopeEvidence) {}, Proven},
		"seen before the window":        {func(ev *BreachScopeEvidence) { ev.Indicators[0].Before = 3 }, Refuted},
		"seen after the window":         {func(ev *BreachScopeEvidence) { ev.Indicators[1].After = 1 }, Refuted},
		"seen in it, told not affected": {func(ev *BreachScopeEvidence) { ev.Indicators[0].During = 12 }, Refuted},
		"seen in it, told affected": {func(ev *BreachScopeEvidence) {
			ev.Told, ev.Indicators[0].During = ToldAffected, 12
		}, Proven},
		"seen in it, nothing said": {func(ev *BreachScopeEvidence) {
			ev.Told, ev.Indicators[0].During = ToldUnstated, 12
		}, Proven},
		"the store does not hold the margin before": {func(ev *BreachScopeEvidence) { ev.HeldBefore = false }, Inconclusive},
		"the store does not hold the window":        {func(ev *BreachScopeEvidence) { ev.HeldDuring = false }, Inconclusive},
		"a sighting outweighs a gap": {func(ev *BreachScopeEvidence) {
			ev.HeldAfter, ev.Indicators[0].Before = false, 1
		}, Refuted},
	}
	for name, c := range cases {
		in := breachInput()
		in.Evidence.Indicators = append([]BreachIndicator{}, in.Evidence.Indicators...)
		c.change(&in.Evidence)
		st, err := ProveBreachScope(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s", name, st.Predicate.Verdict, c.want)
		}
	}
}

func TestABreachScopeNamesWhatWasSeenWhere(t *testing.T) {
	in := breachInput()
	in.Evidence.Indicators[0].Before, in.Evidence.Indicators[1].During = 3, 7
	st, err := ProveBreachScope(in)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(st.Predicate.Checks[0].Failures, "|") + "|" + strings.Join(st.Predicate.Checks[1].Failures, "|")
	want := "seen before the window: ipv4 203.0.113.7, in 3 event(s)|seen in the window: domain exfil.example, in 7 event(s)"
	if got != want {
		t.Errorf("named %q, want %q", got, want)
	}
	if !strings.Contains(st.Predicate.Claim, "nor inside it") {
		t.Errorf("the claim: %s", st.Predicate.Claim)
	}
}

func TestABreachScopeThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*BreachScopeEvidence){
		"a vendor in prose":        func(ev *BreachScopeEvidence) { ev.Vendor = "Acme CRM, Inc." },
		"a reference with a space": func(ev *BreachScopeEvidence) { ev.Reference = "the August notice" },
		"an indicator not canonical": func(ev *BreachScopeEvidence) {
			ev.Indicators[1].Value = "EXFIL.example"
		},
		"an indicator of no type":  func(ev *BreachScopeEvidence) { ev.Indicators[0].Type = "vibe" },
		"an indicator twice":       func(ev *BreachScopeEvidence) { ev.Indicators[1] = ev.Indicators[0] },
		"no indicators":            func(ev *BreachScopeEvidence) { ev.Indicators = nil },
		"a window backwards":       func(ev *BreachScopeEvidence) { ev.Since, ev.Until = ev.Until, ev.Since },
		"a margin over 90 days":    func(ev *BreachScopeEvidence) { ev.Margin = 91 * 24 * 3600 },
		"told something else":      func(ev *BreachScopeEvidence) { ev.Told = "probably-fine" },
		"a negative count":         func(ev *BreachScopeEvidence) { ev.Indicators[0].After = -1 },
		"a time not to the second": func(ev *BreachScopeEvidence) { ev.Since = "2026-08-08T00:00:00.5Z" },
	}
	for name, change := range cases {
		in := breachInput()
		in.Evidence.Indicators = append([]BreachIndicator{}, in.Evidence.Indicators...)
		change(&in.Evidence)
		if _, err := ProveBreachScope(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

func TestABreachScopeCarriesOnlyWhatItsEvidenceSays(t *testing.T) {
	in := breachInput()
	in.Evidence.Indicators[0].During = 4
	st, err := ProveBreachScope(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict":            func(s *Statement) { s.Predicate.Verdict = Proven },
		"told":               func(s *Statement) { s.Predicate.BreachScope.Told = ToldAffected },
		"a sighting removed": func(s *Statement) { s.Predicate.BreachScope.Indicators[0].During = 0 },
		"a failure reworded": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "seen in the window: ipv4 203.0.113.7, but harmless"
		},
		"the window widened": func(s *Statement) { s.Predicate.BreachScope.Until = "2026-09-18T00:00:00Z" },
		"a second kind":      func(s *Statement) { s.Predicate.Clock = &ClockEvidence{} },
		"the subject":        func(s *Statement) { s.Subject[0].Name = "disclosure/acme-crm/OTHER" },
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
	if back, err := Open(env, k.PublicKey()); err != nil || back.Predicate.Verdict != Refuted {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}
