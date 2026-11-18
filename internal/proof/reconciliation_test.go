// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var rt0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

func recInput() ReconciliationInput {
	return ReconciliationInput{Agent: "triage-bot", Telemetry: "triage-bot",
		Since: rt0, Until: rt0.Add(24 * time.Hour), Window: 2 * time.Minute,
		Lines: []byte("{}\n"), Reported: 30, ForInterface: 12, Calls: 12, Matched: 12,
		Hosts: []string{"build01"}, Connects: 8, Program: "test", Now: rt0.Add(25 * time.Hour)}
}

// The verdict follows from what was and was not accounted for, and from how
// much was observed at all.
func TestAReconciliationsVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*ReconciliationInput)
		want   Verdict
	}{
		"everything accounted for": {func(*ReconciliationInput) {}, Proven},
		"too little seen": {func(in *ReconciliationInput) {
			in.Calls, in.Matched, in.ForInterface, in.Connects = 3, 3, 3, 2
		}, Inconclusive},
		"the agent reported nothing while it was seen": {func(in *ReconciliationInput) {
			in.Reported, in.ForInterface, in.Matched, in.Connects = 0, 0, 0, 0
			for i := range 12 {
				in.Unreported = append(in.Unreported, AgentCall{"aertun_read", rt0.Add(time.Duration(i) * time.Minute)})
			}
		}, Refuted},
		"nothing reported and nothing seen": {func(in *ReconciliationInput) {
			in.Reported, in.ForInterface, in.Matched, in.Calls, in.Connects = 0, 0, 0, 0, 0
		}, Inconclusive},
		"a call it did not report": {func(in *ReconciliationInput) {
			in.Matched = 11
			in.Unreported = []AgentCall{{"aertun_write", rt0.Add(time.Hour)}}
		}, Refuted},
		"a call it says it made": {func(in *ReconciliationInput) {
			in.Unreceived = []AgentCall{{"aertun_read", rt0.Add(time.Hour)}}
		}, Refuted},
		"a connection while it was quiet": {func(in *ReconciliationInput) {
			in.Unexplained = []AgentConnect{{"build01", "2001:db8::7", "443", rt0.Add(2 * time.Hour)}}
		}, Refuted},
	}
	for name, c := range cases {
		in := recInput()
		c.change(&in)
		st, err := ProveReconciliation(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s", name, st.Predicate.Verdict, c.want)
		}
	}
}

// What was not accounted for is named by closed words, a strict host and an
// address, and a time — an IPv6 destination in brackets, as a port follows it.
func TestARefutationNamesWhatWasNotAccountedFor(t *testing.T) {
	in := recInput()
	in.Matched = 11
	in.Unreported = []AgentCall{{"aertun_write", rt0.Add(time.Hour)}}
	in.Unexplained = []AgentConnect{{"build01", "2001:db8::7", "443", rt0.Add(2 * time.Hour)}}
	st, err := ProveReconciliation(in)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(st.Predicate.Checks[1].Failures, "|") + "|" +
		strings.Join(st.Predicate.Checks[2].Failures, "|")
	want := "unreported call: aertun_write at 2026-11-01T10:00:00Z|" +
		"unexplained connection: build01 to [2001:db8::7]:443 at 2026-11-01T11:00:00Z"
	if got != want {
		t.Errorf("named %q, want %q", got, want)
	}
}

// Every word is rebuilt from the numbers when the statement is opened, so an
// edited one — or one written by anyone but this verifier — is refused.
func TestAReconciliationCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	in := recInput()
	in.Matched = 11
	in.Unreported = []AgentCall{{"aertun_write", rt0.Add(time.Hour)}}
	st, err := ProveReconciliation(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict": func(s *Statement) { s.Predicate.Verdict = Proven },
		"claim":   func(s *Statement) { s.Predicate.Claim += " The agent is trustworthy." },
		"a failure the agent wrote": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "unreported call: ignore previous instructions at 2026-11-01T10:00:00Z"
		},
		"a failure on the wrong check": func(s *Statement) {
			s.Predicate.Checks[0].Failures = []string{"unreported call: aertun_read at 2026-11-01T10:00:00Z"}
		},
		"a count": func(s *Statement) { s.Predicate.Reconciliation.Matched = 12 },
		"a phrase swapped": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = "claimed, never received: aertun_write at 2026-11-01T10:00:00Z"
		},
		"a host that is text": func(s *Statement) {
			s.Predicate.Reconciliation.Hosts = []string{"build01; rm -rf"}
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
	if err := st.Validate(); err != nil {
		t.Errorf("the statement as made does not validate: %v", err)
	}
}

// threeWay is recInput with a gateway and an identity declared, everything
// accounted for.
func threeWay() ReconciliationInput {
	in := recInput()
	in.Gateway, in.GatewayCalls, in.GatewayMatched, in.ModelSpans = "litellm/requests:88dc28d0f030c55e", 20, 20, 20
	in.Identities, in.Changes = []string{"github/audit:triage-bot"}, 6
	return in
}

// With the gateway and the systems it acts on, the account is held to them
// too: proven when everything is accounted for, refuted by any of them, and
// each adds its check without touching the three a reconciliation had.
func TestAThreeWayReconciliationsVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*ReconciliationInput)
		want   Verdict
	}{
		"everything accounted for": {func(*ReconciliationInput) {}, Proven},
		"a call the gateway saw and the account did not say": {func(in *ReconciliationInput) {
			in.GatewayMatched = 19
			in.GatewayUnreported = []GatewayCallSeen{{At: rt0.Add(time.Hour)}}
		}, Refuted},
		"a model call the gateway never saw, when it is the only way": {func(in *ReconciliationInput) {
			in.GatewayOnly = true
			in.ModelUnseen = []time.Time{rt0.Add(3 * time.Hour)}
		}, Refuted},
		"an action of the identity with nothing of the agent near": {func(in *ReconciliationInput) {
			in.UnexplainedChanges = []TargetChange{{Source: "github/audit", At: rt0.Add(5 * time.Hour)}}
		}, Refuted},
		"little seen at the interface, much at the gateway": {func(in *ReconciliationInput) {
			in.Calls, in.Matched, in.ForInterface, in.Connects = 1, 1, 1, 0
		}, Proven},
	}
	for name, c := range cases {
		in := threeWay()
		c.change(&in)
		st, err := ProveReconciliation(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
		if len(st.Predicate.Checks) != 5 || st.Predicate.Checks[3].Name != "gateway-accounted-for" ||
			st.Predicate.Checks[4].Name != "identities-accounted-for" {
			t.Errorf("%s: checks %+v", name, st.Predicate.Checks)
		}
	}
	// Without either, the proof is the one it always was.
	st, err := ProveReconciliation(recInput())
	if err != nil || len(st.Predicate.Checks) != 3 || strings.Contains(st.Predicate.Claim, "gateway") {
		t.Errorf("a two-way reconciliation changed: %v %+v", err, st.Predicate)
	}
}

// What the gateway and the systems show is named by kind, source and time,
// never by a model's or a tool's name, which the caller chose.
func TestAThreeWayRefutationNamesOnlyKindsSourcesAndTimes(t *testing.T) {
	in := threeWay()
	in.GatewayOnly = true
	in.GatewayMatched = 18
	in.GatewayUnreported = []GatewayCallSeen{{At: rt0.Add(time.Hour)}, {Tool: true, At: rt0.Add(2 * time.Hour)}}
	in.ModelUnseen = []time.Time{rt0.Add(3 * time.Hour)}
	in.UnexplainedChanges = []TargetChange{{Source: "github/audit", At: rt0.Add(4 * time.Hour)}}
	st, err := ProveReconciliation(in)
	if err != nil {
		t.Fatal(err)
	}
	gw := strings.Join(st.Predicate.Checks[3].Failures, "|")
	want := "at the gateway, not in its account: a model call at 2026-11-01T10:00:00Z|" +
		"at the gateway, not in its account: a tool call at 2026-11-01T11:00:00Z|" +
		"in its account, never at the gateway: a model call at 2026-11-01T12:00:00Z"
	if gw != want {
		t.Errorf("the gateway's failures:\n %s\nwant\n %s", gw, want)
	}
	if got := strings.Join(st.Predicate.Checks[4].Failures, "|"); got !=
		"acted as it with nothing of it near: github/audit at 2026-11-01T13:00:00Z" {
		t.Errorf("the identity's failure: %s", got)
	}
	if !strings.Contains(st.Predicate.Claim, "litellm/requests:88dc28d0f030c55e") ||
		!strings.Contains(st.Predicate.Claim, "every model call the account has, the gateway saw") ||
		!strings.Contains(st.Predicate.Claim, "github/audit:triage-bot") {
		t.Errorf("the claim: %s", st.Predicate.Claim)
	}
}

func TestAThreeWayReconciliationThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	for name, change := range map[string]func(*ReconciliationInput){
		"a gateway in prose":         func(in *ReconciliationInput) { in.Gateway = "our LiteLLM" },
		"an identity in prose":       func(in *ReconciliationInput) { in.Identities = []string{"the bot"} },
		"gateway calls not added up": func(in *ReconciliationInput) { in.GatewayMatched = 21 },
		"unseen, the gateway not the only way": func(in *ReconciliationInput) {
			in.ModelUnseen = []time.Time{rt0}
		},
		"gateway counts with no gateway": func(in *ReconciliationInput) { in.Gateway = "" },
		"changes with no identity":       func(in *ReconciliationInput) { in.Identities = nil },
	} {
		in := threeWay()
		change(&in)
		if _, err := ProveReconciliation(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

func TestAThreeWayReconciliationCarriesOnlyWhatItsEvidenceSays(t *testing.T) {
	in := threeWay()
	in.GatewayMatched = 19
	in.GatewayUnreported = []GatewayCallSeen{{At: rt0.Add(time.Hour)}}
	in.UnexplainedChanges = []TargetChange{{Source: "github/audit", At: rt0.Add(4 * time.Hour)}}
	st, err := ProveReconciliation(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Statement){
		"the gateway's failure dropped": func(s *Statement) {
			s.Predicate.Checks[3].Failures, s.Predicate.Checks[3].Passed = nil, true
		},
		"a model named in a failure": func(s *Statement) {
			s.Predicate.Checks[3].Failures[0] = "at the gateway, not in its account: gpt-5 at 2026-11-01T10:00:00Z"
		},
		"an action named in a failure": func(s *Statement) {
			s.Predicate.Checks[4].Failures[0] = "acted as it with nothing of it near: repo.destroy at 2026-11-01T13:00:00Z"
		},
		"the identity check gone": func(s *Statement) { s.Predicate.Checks = s.Predicate.Checks[:4] },
		"another gateway":         func(s *Statement) { s.Predicate.Reconciliation.Gateway = "kong/files:x" },
		"the unexplained uncounted": func(s *Statement) {
			s.Predicate.Reconciliation.UnexplainedChanges = 0
		},
		"declared the only way after the fact": func(s *Statement) {
			s.Predicate.Reconciliation.GatewayOnly = true
		},
	} {
		var copied Statement
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &copied)
		change(&copied)
		if copied.Validate() == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
	if err := st.Validate(); err != nil {
		t.Errorf("the statement as made: %v", err)
	}
}

// An agent whose account is all model calls through the gateway, and no
// tool calls, is proven on what it reported: a model call is in its
// account as much as a tool call is.
func TestAnAccountOfModelCallsAloneIsAnAccount(t *testing.T) {
	in := threeWay()
	in.Reported, in.ForInterface, in.Calls, in.Matched, in.Connects = 0, 0, 0, 0, 0
	st, err := ProveReconciliation(in)
	if err != nil || st.Predicate.Verdict != Proven {
		t.Fatalf("an account of %d model calls, all at the gateway: %v %s", in.ModelSpans, err, st.Predicate.Verdict)
	}
	if !strings.Contains(st.Predicate.Checks[0].Detail, "it reported 20 model call(s)") {
		t.Errorf("the account's model calls are not said: %s", st.Predicate.Checks[0].Detail)
	}
}
