// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var rv0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// revInput is an identity revoked at noon, watched for a day afterwards in
// hour-long stretches, seen acting before by one source that kept
// delivering throughout.
func revInput() RevocationInput {
	return RevocationInput{Kind: RevokedIdentity, Name: "okta:00u1", Identities: []string{"okta:00u1",
		"github:dana-ops"}, Revoked: rv0, Grace: 5 * time.Minute, Until: rv0.Add(24*time.Hour + 5*time.Minute),
		Lookback: 7 * 24 * time.Hour, Stretch: time.Hour, Stretches: 24,
		Sources: []RevocationSource{{Source: "okta/system-log", Before: 40}},
		Lines:   []byte("{}\n"), Program: "test", Now: rv0.Add(25 * time.Hour)}
}

func TestARevocationsVerdict(t *testing.T) {
	use := RevocationUse{Source: "okta/system-log", Identity: "okta:00u1", At: rv0.Add(3 * time.Hour)}
	cases := map[string]struct {
		change func(*RevocationInput)
		want   Verdict
	}{
		"nothing acted and the source listened": {func(*RevocationInput) {}, Proven},
		"a use after the grace": {func(in *RevocationInput) {
			in.Sources[0].Uses = 1
			in.Uses = []RevocationUse{use}
		}, Refuted},
		"attempts refused are not uses": {func(in *RevocationInput) {
			in.Sources[0].Refused = 3
		}, Proven},
		"the source went quiet": {func(in *RevocationInput) {
			in.Sources[0].Quiet = 2
		}, Inconclusive},
		"nothing had seen it act": {func(in *RevocationInput) {
			in.Sources[0].Before = 0
		}, Inconclusive},
		"its own account is not a witness": {func(in *RevocationInput) {
			in.Sources[0].Account = true
		}, Inconclusive},
		"its own account still refutes": {func(in *RevocationInput) {
			in.Sources = append(in.Sources, RevocationSource{Source: "otel/genai", Before: 9, Uses: 1, Account: true})
			in.Uses = []RevocationUse{{Source: "otel/genai", Identity: "github:dana-ops", At: rv0.Add(time.Hour)}}
		}, Refuted},
		"a period too short": {func(in *RevocationInput) {
			in.Until, in.Stretches = rv0.Add(50*time.Minute), 1
		}, Inconclusive},
		"one silent source of two": {func(in *RevocationInput) {
			in.Sources = append(in.Sources, RevocationSource{Source: "github/audit", Before: 2, Quiet: 1})
		}, Inconclusive},
		"a source that never saw it may be quiet": {func(in *RevocationInput) {
			in.Sources = append(in.Sources, RevocationSource{Source: "github/audit", Quiet: 24, Refused: 1})
		}, Proven},
	}
	for name, c := range cases {
		in := revInput()
		c.change(&in)
		st, err := ProveRevocation(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
	}
}

// An agent disabled here is proven by this program's own log alone: every
// act through it passes the gate that writes it, so its silence needs no
// stretches.
func TestTheGatesOwnLogIsCompleteForAnAgent(t *testing.T) {
	in := revInput()
	in.Kind, in.Name, in.RevokedEntry = RevokedAgent, "triage-bot", 812
	in.Identities = []string{"aertun:triage-bot", "otel:triage-bot"}
	in.Sources = []RevocationSource{{Source: "aertun/audit", Before: 30, Complete: true}}
	st, err := ProveRevocation(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != Proven || st.Subject[0].Name != "agent/triage-bot" ||
		!strings.Contains(st.Predicate.Checks[0].Detail, "audit entry 812") {
		t.Errorf("%s %s %+v", st.Predicate.Verdict, st.Subject[0].Name, st.Predicate.Checks)
	}
}

// What acted is named by source, by an identity it was matched on, and by
// time; the inconclusive reason is said in words.
func TestARevocationSaysWhatActedAndWhatWasWatching(t *testing.T) {
	in := revInput()
	in.Sources[0].Uses, in.Sources[0].Refused = 1, 2
	in.Uses = []RevocationUse{{Source: "okta/system-log", Identity: "okta:00u1", At: rv0.Add(3 * time.Hour)}}
	st, err := ProveRevocation(in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(st.Predicate.Checks[1].Failures, "|"),
		"use after revocation: okta/system-log as okta:00u1 at 2026-11-10T15:00:00Z"; got != want {
		t.Errorf("named %q, want %q", got, want)
	}
	if d := st.Predicate.Checks[1].Detail; !strings.Contains(d, "2 attempt(s) were refused") {
		t.Errorf("the refused attempts are not said: %s", d)
	}
	in = revInput()
	in.Sources[0].Quiet = 3
	st, err = ProveRevocation(in)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Predicate.Checks[2].Detail; !strings.Contains(d, "quiet in 3 of 24 stretch(es) of 1 hour") ||
		!strings.Contains(d, "went quiet") {
		t.Errorf("the quiet source is not said: %s", d)
	}
	if !strings.Contains(st.Predicate.Claim, "after okta:00u1 was revoked at 2026-11-10T12:00:00Z") ||
		!strings.Contains(st.Predicate.Claim, "in the 7 days before") {
		t.Errorf("the claim: %s", st.Predicate.Claim)
	}
}

// Evidence that does not hold together is refused before anything is
// signed.
func TestARevocationThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*RevocationInput){
		"an identity with a space":   func(in *RevocationInput) { in.Identities[1] = "github:dana ops" },
		"no issuer":                  func(in *RevocationInput) { in.Identities[1] = "dana-ops" },
		"the name is not first":      func(in *RevocationInput) { in.Name = "github:dana-ops" },
		"an identity twice":          func(in *RevocationInput) { in.Identities[1] = "okta:00u1" },
		"a grace over a day":         func(in *RevocationInput) { in.Grace = 25 * time.Hour },
		"a period over 31 days":      func(in *RevocationInput) { in.Until = rv0.Add(40 * 24 * time.Hour) },
		"stretches miscounted":       func(in *RevocationInput) { in.Stretches = 23 },
		"a stretch under a minute":   func(in *RevocationInput) { in.Stretch = time.Second },
		"a lookback under an hour":   func(in *RevocationInput) { in.Lookback = time.Minute },
		"a source named in prose":    func(in *RevocationInput) { in.Sources[0].Source = "Okta System Log" },
		"a source twice":             func(in *RevocationInput) { in.Sources = append(in.Sources, in.Sources[0]) },
		"more quiet than stretches":  func(in *RevocationInput) { in.Sources[0].Quiet = 25 },
		"a complete source is quiet": func(in *RevocationInput) { in.Sources[0].Complete, in.Sources[0].Quiet = true, 1 },
		"uses not the sources' sum": func(in *RevocationInput) {
			in.Uses = []RevocationUse{{Source: "okta/system-log", Identity: "okta:00u1", At: rv0.Add(time.Hour)}}
		},
		"an identity with an entry here": func(in *RevocationInput) { in.RevokedEntry = 4 },
		"an agent in prose":              func(in *RevocationInput) { in.Kind, in.Name = RevokedAgent, "Triage Bot" },
		"no lines":                       func(in *RevocationInput) { in.Lines = nil },
	}
	for name, change := range cases {
		in := revInput()
		in.Identities = append([]string{}, in.Identities...)
		in.Sources = append([]RevocationSource{}, in.Sources...)
		change(&in)
		if _, err := ProveRevocation(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

// Every word is rebuilt from the numbers when the statement is opened, so an
// edited one is refused.
func TestARevocationCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	in := revInput()
	in.Sources[0].Uses = 1
	in.Uses = []RevocationUse{{Source: "okta/system-log", Identity: "okta:00u1", At: rv0.Add(3 * time.Hour)}}
	st, err := ProveRevocation(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict": func(s *Statement) { s.Predicate.Verdict = Proven },
		"claim":   func(s *Statement) { s.Predicate.Claim += " The incident is closed." },
		"a use by an identity it was not matched on": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "use after revocation: okta/system-log as okta:00u2 at 2026-11-10T15:00:00Z"
		},
		"a use by a source that saw none": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "use after revocation: github/audit as okta:00u1 at 2026-11-10T15:00:00Z"
		},
		"a failure on the wrong check": func(s *Statement) {
			s.Predicate.Checks[2].Failures = s.Predicate.Checks[1].Failures
		},
		"a use dropped": func(s *Statement) {
			s.Predicate.Checks[1].Failures = nil
			s.Predicate.Checks[1].Passed = true
			s.Predicate.Verdict = Proven
		},
		"the source made quiet": func(s *Statement) { s.Predicate.Revocation.Sources[0].Quiet = 4 },
		"the uses counted away": func(s *Statement) {
			s.Predicate.Revocation.Uses, s.Predicate.Revocation.Sources[0].Uses = 0, 0
		},
		"the revocation moved": func(s *Statement) { s.Predicate.Revocation.Revoked = "2026-11-10T13:00:00Z" },
		"a second kind of evidence": func(s *Statement) {
			s.Predicate.Reconciliation = &ReconciliationEvidence{}
		},
		"the subject": func(s *Statement) { s.Subject[0].Name = "identity/okta:00u2" },
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
	if err != nil || back.Predicate.Revocation.Uses != 1 || back.Predicate.Verdict != Refuted {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}

// A use beyond the cap is counted, not named, and the statement still
// validates with every word rebuilt.
func TestUsesBeyondTheCapAreCounted(t *testing.T) {
	in := revInput()
	for i := range MaxFailures + 7 {
		in.Uses = append(in.Uses, RevocationUse{Source: "okta/system-log", Identity: "okta:00u1",
			At: rv0.Add(time.Hour + time.Duration(i)*time.Minute)})
	}
	in.Sources[0].Uses = len(in.Uses)
	st, err := ProveRevocation(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Predicate.Checks[1].Failures) != MaxFailures ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "7 more not listed") {
		t.Errorf("%+v", st.Predicate.Checks[1])
	}
}
