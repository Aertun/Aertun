// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

func at(m float64) time.Time { return t0.Add(time.Duration(m * float64(time.Minute))) }

func input() Input {
	return Input{Since: t0, Until: t0.Add(time.Hour), Window: 2 * time.Minute}
}

// An agent whose spans account for every call the agent interface answered,
// however its host prefixed the tool, reconciles clean.
func TestAnAgentThatReportsWhatItDidReconciles(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(5), "aertun_read"}, {at(20), "aertun_find"}, {at(30), "aertun_read"}}
	in.Spans = []Span{{at(4.9), "mcp__aertun__aertun_read"}, {at(19.5), "aertun.aertun_find"},
		{at(30.2), "aertun_read"}, {at(40), "shell"}}
	r := Reconcile(in)
	if r.Calls != 3 || r.Matched != 3 || len(r.Unreported) != 0 || len(r.Unreceived) != 0 ||
		r.Reported != 4 || r.ForInterface != 3 {
		t.Errorf("result %+v", r)
	}
}

// A call no span accounts for is unreported; a span for the agent interface
// no call matches is a call the agent says it made and the server never
// received. Each span answers for one call.
func TestWhatTheAccountsDisagreeOnIsNamed(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(5), "aertun_read"}, {at(5.5), "aertun_read"}, {at(50), "aertun_write"}}
	in.Spans = []Span{{at(5.2), "aertun_read"}, {at(25), "mcp__aertun__aertun_write"},
		{at(50), "aertun_read"}}
	r := Reconcile(in)
	if r.Matched != 1 || len(r.Unreported) != 2 {
		t.Fatalf("result %+v", r)
	}
	if r.Unreported[0].At != at(5.5) || r.Unreported[1].Tool != "aertun_write" {
		t.Errorf("unreported %+v", r.Unreported)
	}
	if len(r.Unreceived) != 2 || r.Unreceived[0].Tool != "aertun_write" || r.Unreceived[1].At != at(50) {
		t.Errorf("unreceived %+v", r.Unreceived)
	}
}

// A tool name is matched exactly, or after a separator hosts use: a tool
// that only contains the name is somebody else's.
func TestAToolIsTheInterfacesOnlyByItsName(t *testing.T) {
	for name, want := range map[string]string{
		"aertun_read": "aertun_read", "mcp__aertun__aertun_read": "aertun_read",
		"srv/aertun_write": "aertun_write", "not_aertun_read": "", "aertun_readme": "",
		"shell": "", "": "",
	} {
		if got := interfaceTool(name); got != want {
			t.Errorf("%q is %q, want %q", name, got, want)
		}
	}
}

// A connection from the agent's own machine is explained by the agent
// acting near it; one while it reported nothing is unexplained. A machine it
// shares is skipped, never attributed, and a destination that is not an
// address and a port is not counted.
func TestConnectionsAreHeldToWhenTheAgentWasActing(t *testing.T) {
	in := input()
	in.Hosts, in.Shared = []string{"build01"}, []string{"shared02"}
	in.Spans = []Span{{at(10), "shell"}}
	in.Connects = []Connect{
		{at(11), "build01", "203.0.113.9", "443"},
		{at(40), "build01", "198.51.100.7", "22"},
		{at(40), "shared02", "198.51.100.7", "22"},
		{at(41), "build01", "/run/socket", ""},
		{at(42), "elsewhere", "198.51.100.8", "22"},
	}
	r := Reconcile(in)
	if r.Connects != 2 || r.SharedSkipped != 1 || len(r.Unexplained) != 1 ||
		r.Unexplained[0].Addr != "198.51.100.7" {
		t.Errorf("result %+v", r)
	}
}

// The period bounds what is counted; a span just outside it can still
// account for a call at its edge.
func TestThePeriodBoundsWhatIsCounted(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(0.5), "aertun_read"}, {at(70), "aertun_read"}}
	in.Spans = []Span{{at(-1), "aertun_read"}, {at(-30), "aertun_read"}}
	r := Reconcile(in)
	if r.Calls != 1 || r.Matched != 1 || r.Reported != 0 || len(r.Unreceived) != 0 {
		t.Errorf("result %+v", r)
	}
}

// A call the server recorded under a name that is not one of its tools —
// a client may send any name, and is refused under it — is not a call to
// the interface, however it is spelt.
func TestOnlyTheServersOwnToolNamesAreCalls(t *testing.T) {
	in := input()
	in.Calls = []Call{{at(5), "x__aertun_read"}, {at(6), "aertun_read; drop"}, {at(7), "aertun_read"}}
	in.Spans = []Span{{at(7), "aertun_read"}}
	r := Reconcile(in)
	if r.Calls != 1 || r.Matched != 1 || len(r.Unreported) != 0 {
		t.Errorf("result %+v", r)
	}
}

// The gateway's calls on the agent's key are held against the account: a
// model call to a model span, a tool call to a span for the same tool, each
// span once, nearest first. What the gateway saw and the agent did not say
// is named; what the agent says it asked a model and the gateway never saw
// is named only when the gateway is its only way to one.
func TestTheGatewaysCallsAreHeldAgainstTheAccount(t *testing.T) {
	in := input()
	in.ModelSpans = []Span{{At: at(5)}, {At: at(10)}, {At: at(55)}}
	in.Spans = []Span{{at(20), "mcp__github__create_issue"}}
	in.Gateway = []GatewayCall{
		{At: at(5.1)}, {At: at(10.5)}, {At: at(30)}, // the third the agent never said
		{At: at(20.1), Tool: "github-create_issue"},
		{At: at(40), Tool: "github-delete_repo"}, // a tool call it never said
	}
	r := Reconcile(in)
	if r.GatewayCalls != 5 || r.GatewayMatched != 3 || len(r.GatewayUnreported) != 2 {
		t.Fatalf("result %+v", r)
	}
	if r.GatewayUnreported[0].At != at(30) || r.GatewayUnreported[0].Tool != "" ||
		r.GatewayUnreported[1].Tool != "github-delete_repo" {
		t.Errorf("unreported at the gateway %+v", r.GatewayUnreported)
	}
	if r.ModelSpans != 3 || len(r.ModelUnseen) != 0 {
		t.Errorf("with the gateway not the only way, a model call it did not see is nothing: %+v", r.ModelUnseen)
	}
	in.GatewayOnly = true
	r = Reconcile(in)
	if len(r.ModelUnseen) != 1 || r.ModelUnseen[0].At != at(55) {
		t.Errorf("the gateway the only way to a model, the call it never saw: %+v", r.ModelUnseen)
	}
	// A tool call is not matched to a model span, nor to a span for
	// another tool.
	in = input()
	in.ModelSpans = []Span{{At: at(5)}}
	in.Spans = []Span{{at(5), "mcp__github__list_issues"}}
	in.Gateway = []GatewayCall{{At: at(5), Tool: "github-create_issue"}}
	if r := Reconcile(in); len(r.GatewayUnreported) != 1 {
		t.Errorf("a tool call matched another tool's span or a model span: %+v", r)
	}
}

// What a target system records of the agent's identity is explained by
// anything the agent did near it — by its account, at the gateway, at the
// agent interface — and named when nothing was.
func TestATargetsActionsAreExplainedByWhatTheAgentDid(t *testing.T) {
	in := input()
	in.Spans = []Span{{at(5), "mcp__github__create_issue"}}
	in.Gateway = []GatewayCall{{At: at(20)}}
	in.Calls = []Call{{at(35), "aertun_write"}}
	in.Changes = []Change{
		{At: at(5.5), Source: "github/audit"}, {At: at(21), Source: "github/audit"},
		{At: at(36), Source: "okta/system"},
		{At: at(50), Source: "github/audit"}, // the identity used with nothing of the agent near
		{At: at(70), Source: "github/audit"}, // outside the period
	}
	r := Reconcile(in)
	if r.Changes != 4 || len(r.UnexplainedChanges) != 1 || r.UnexplainedChanges[0].At != at(50) ||
		r.UnexplainedChanges[0].Source != "github/audit" {
		t.Errorf("result %+v", r)
	}
}

func TestAGatewaysNameForAToolIsMatchedOnlyAfterASeparator(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"create_issue", "create_issue", true},
		{"mcp__github__create_issue", "github-create_issue", true},
		{"mcp__gitlab__create_issue", "github-create_issue", false},
		{"mcp__github__create_issue", "github-list_issues", false},
		{"mcp__github__create_issue", "create_issue", true},
		{"github-create_issue", "create_issue", true},
		{"github.create_issue", "create_issue", true},
		{"recreate_issue", "create_issue", false},
		{"", "create_issue", false},
	} {
		if got := sameTool(c.a, c.b); got != c.want {
			t.Errorf("sameTool(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
