// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// reconcileSite is a store with agent triage-bot registered and declared to
// run alone on build01, and watcher sharing build02 with it.
func reconcileSite(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	for _, a := range [][]string{
		{"add", "triage-bot", "--owner", "dana", "--allow", "aertun_read,aertun_find,aertun_write"},
		{"add", "watcher", "--owner", "dana", "--allow", "aertun_read,aertun_find,aertun_write"},
		{"maps", "triage-bot", "--host", "build01"},
		{"maps", "triage-bot", "--host", "build02"},
		{"maps", "watcher", "--host", "build02"},
	} {
		if err := cmdAgent(root, a); err != nil {
			t.Fatalf("agent %v: %v", a, err)
		}
	}
	return root
}

// appendAgentEvents appends what the event store would hold: the agent's own spans and
// connections from its machines.
func appendAgentEvents(t *testing.T, root string, evs ...telemetry.Event) {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	if _, err := sp.AppendBatch(evs); err != nil {
		t.Fatal(err)
	}
}

func span(at time.Time, tool string) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: otelSource, Class: telemetry.ClassAPIActivity,
		Actor: telemetry.ID{Issuer: "otel", Value: "triage-bot"},
		Raw:   map[string]string{"operation": "execute_tool", "tool": tool}}
}

func connect(at time.Time, host, addr string) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: auditdSource, Class: telemetry.ClassNetworkActivity,
		Device: telemetry.ID{Issuer: "auditd", Value: host},
		Raw:    map[string]string{"syscall": "connect", "addr": addr, "port": "443"}}
}

func reconcileProof(t *testing.T, root string, args ...string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "reconcile.json")
	base := []string{"reconcile", "triage-bot", "--since",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "--key", key, "--public-key", pub, "--out", at}
	err := cmdAgent(root, append(base, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// An agent whose telemetry accounts for every call the agent interface
// answered for it, and for the connections from the machine it runs on
// alone, reconciles proven; the proof is kept where the proving ground
// shows it.
func TestAnAgentThatAccountsForItselfReconciles(t *testing.T) {
	root := reconcileSite(t)
	now := time.Now().UTC()
	var evs []telemetry.Event
	for range 10 {
		auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings", nil)
		evs = append(evs, span(time.Now().UTC(), "mcp__aertun__aertun_read"))
	}
	// Another client's call is not this agent's.
	auditMCPCall(root, agentCalling("watcher"), "aertun_read", "list_findings", nil)
	evs = append(evs, connect(now, "build01", "203.0.113.9"),
		connect(now, "build02", "198.51.100.7")) // shared: not attributed
	appendAgentEvents(t, root, evs...)
	st, err := reconcileProof(t, root)
	ev := st.Predicate.Reconciliation
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Calls != 10 || ev.Matched != 10 ||
		ev.Connects != 1 || ev.SharedSkipped != 1 || ev.SharedHosts != 1 {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 1 || kept[0].Statement == nil || kept[0].Statement.Predicate.Reconciliation == nil {
		t.Errorf("the reconciliation was not kept: %+v", kept)
	}
}

// What the accounts disagree on refutes, by name: a call the agent did not
// report, a call it reports and the server never received, and a
// connection from its machine while it reported nothing.
func TestWhatAnAgentLeftOutRefutesItsAccount(t *testing.T) {
	root := reconcileSite(t)
	var evs []telemetry.Event
	for range 10 {
		auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings", nil)
		evs = append(evs, span(time.Now().UTC(), "aertun_read"))
	}
	auditMCPCall(root, agentCalling("triage-bot"), "aertun_write", "propose_finding_decision", nil)
	quiet := time.Now().UTC().Add(-40 * time.Minute)
	evs = append(evs, span(time.Now().UTC().Add(-20*time.Minute), "mcp__aertun__aertun_find"),
		connect(quiet, "build01", "2001:db8::7"))
	appendAgentEvents(t, root, evs...)
	st, err := reconcileProof(t, root)
	if err == nil || st.Predicate.Verdict != proof.Refuted {
		t.Fatalf("%v: %s", err, st.Predicate.Verdict)
	}
	named := strings.Join(st.Predicate.Checks[1].Failures, "|") + "|" +
		strings.Join(st.Predicate.Checks[2].Failures, "|")
	for _, want := range []string{"unreported call: aertun_write at ", "claimed, never received: aertun_find at ",
		"unexplained connection: build01 to [2001:db8::7]:443 at "} {
		if !strings.Contains(named, want) {
			t.Errorf("the refutation does not name %q: %s", want, named)
		}
	}
}

// An agent that reported nothing while it was seen acting has an account
// that covers nothing: refuted, every call named, and the proof says it
// cannot tell that from an agent never instrumented.
func TestAnAgentThatReportsNothingWhileActingIsRefuted(t *testing.T) {
	root := reconcileSite(t)
	for range 12 {
		auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings", nil)
	}
	st, err := reconcileProof(t, root)
	if err == nil || st.Predicate.Verdict != proof.Refuted || len(st.Predicate.Checks[1].Failures) != 12 ||
		!strings.Contains(st.Predicate.Checks[0].Detail, "never having been instrumented") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}
}

// An agent nobody saw, that reported nothing, has nothing to fail.
func TestAnAgentNobodySawIsInconclusive(t *testing.T) {
	root := reconcileSite(t)
	st, err := reconcileProof(t, root)
	if err == nil || st.Predicate.Verdict != proof.Inconclusive {
		t.Errorf("%v: %s", err, st.Predicate.Verdict)
	}
}

// Only a registered agent is reconciled: whose account it is is not a
// guess.
func TestOnlyARegisteredAgentIsReconciled(t *testing.T) {
	root := reconcileSite(t)
	key, _ := signingFiles(t)
	err := cmdAgent(root, []string{"reconcile", "stranger", "--since", "2026-11-01", "--key", key})
	if err == nil || !strings.Contains(err.Error(), "is registered") {
		t.Errorf("an unregistered agent: %v", err)
	}
}

// agentCalling is the caller the agent interface resolves for a registered
// agent's credential: issued to a principal that is not the agent's name,
// which is what a credential made as the help shows is.
func agentCalling(name string) *Caller {
	return &Caller{Name: "svc-" + name, Agent: name, Kind: audit.KindAI}
}

// The calls an agent really makes are the ones reconciled: a registered
// agent, under a credential minted for one run, calls the agent interface
// the way it does in use, and its reconciliation counts that call. The
// record names the agent by its registered name, which the gate checked,
// beside the principal its credential was issued to — reconciliation once
// looked for the agent in the client, where no credential this program
// issues ever put it, and so saw none of an agent's calls.
func TestTheCallsAnAgentMakesAreTheOnesReconciled(t *testing.T) {
	root := caveatSite(t)
	c := runCaller(t, root, mintRun(t, root, "nightly-1", []string{"aertun_read"}, "", 0, -1))
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"aertun_read","arguments":{"operation":"list_findings"}}}` + "\n"
	var out bytes.Buffer
	if err := serveStdio(root, buildMCP(root, c), c, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"result"`) {
		t.Fatalf("the agent's read was not answered: %s", out.String())
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var call *audit.Event
	for i, e := range events {
		if e.Action == "mcp.call" {
			call = &events[i]
		}
	}
	if call == nil || call.Detail["agent"] != "watcher" || call.Detail["run"] != "nightly-1" ||
		call.Detail["client"] == "" {
		t.Fatalf("the call was recorded as %+v", call)
	}
	// The reconciliation is an administrator's command, in a store that
	// asks who is calling.
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example", auth.RoleAdmin, "/",
		time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AERTUN_TOKEN", secret)
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "reconcile.json")
	// Refuted, and rightly: the agent reported nothing and was seen calling.
	err = cmdAgent(root, []string{"reconcile", "watcher", "--since",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "--key", key, "--public-key", pub, "--out", at})
	st := readStatement(t, at, pub)
	if ev := st.Predicate.Reconciliation; ev == nil || ev.Calls != 1 {
		t.Fatalf("%v: reconciliation counted %+v, want the one call the agent made", err, ev)
	}
	// Another agent's reconciliation does not count it.
	register(t, root, "other", "aertun_read")
	at2 := filepath.Join(t.TempDir(), "other.json")
	_ = cmdAgent(root, []string{"reconcile", "other", "--since",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "--key", key, "--public-key", pub, "--out", at2})
	if ev := readStatement(t, at2, pub).Predicate.Reconciliation; ev == nil || ev.Calls != 0 {
		t.Errorf("another agent was credited with the call: %+v", ev)
	}
}

// gatewayCall is a call a LiteLLM proxy logged on a key, as the
// litellm/requests mapping stores it; tool is empty for a model call.
func gatewayCall(at time.Time, key, tool string) telemetry.Event {
	raw := map[string]string{"call_type": "acompletion", "status": "success"}
	if tool != "" {
		raw["call_type"], raw["namespaced_tool_name"] = "call_mcp_tool", tool
	}
	return telemetry.Event{Time: at, Received: at, Source: "litellm/requests", Class: telemetry.ClassAPIActivity,
		Actor: telemetry.ID{Issuer: "litellm", Value: key}, Raw: raw}
}

func modelSpan(at time.Time) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: otelSource, Class: telemetry.ClassAPIActivity,
		Actor: telemetry.ID{Issuer: "otel", Value: "triage-bot"}, Raw: map[string]string{"operation": "chat"}}
}

// githubAction is something GitHub's audit log recorded of an actor.
func githubAction(at time.Time, actor, action string) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: "github/audit", Class: telemetry.ClassAPIActivity,
		Actor: telemetry.ID{Issuer: "github", Value: actor}, Message: action,
		Raw: map[string]string{"action": action}}
}

// Three ways: the agent's own account, the model gateway it calls through,
// and the system it acts on. Every call the gateway saw on its key, and
// everything GitHub recorded of its login, is accounted for — proven; then
// the key used for a call the agent never reported, and the login used for
// an action with nothing of the agent near, refute, named by kind, source
// and time and nothing the caller chose.
func TestAnAgentIsHeldToItsGatewayAndTheSystemsItActsOn(t *testing.T) {
	root := reconcileSite(t)
	key := "88dc28d0f030c55ed4ab77ed8faf098196cb1c05df778539800c9f1243fe6b4b"
	now := time.Now().UTC().Add(-30 * time.Minute)
	var evs []telemetry.Event
	for i := range 12 {
		at := now.Add(time.Duration(i) * 90 * time.Second)
		evs = append(evs, modelSpan(at), gatewayCall(at.Add(2*time.Second), key, ""))
	}
	at := now.Add(20 * time.Minute)
	evs = append(evs, span(at, "mcp__github__create_issue"),
		gatewayCall(at.Add(time.Second), key, "github-create_issue"),
		githubAction(at.Add(3*time.Second), "triage-bot", "issues.opened"),
		// Somebody else's login and somebody else's key are not the agent's.
		githubAction(now.Add(25*time.Minute), "dana", "repo.destroy"),
		gatewayCall(now.Add(25*time.Minute), "a-different-key", ""))
	appendAgentEvents(t, root, evs...)
	args := []string{"--gateway", "litellm/requests:" + key, "--gateway-only", "--identity", "github/audit:triage-bot"}
	st, err := reconcileProof(t, root, args...)
	ev := st.Predicate.Reconciliation
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.GatewayCalls != 13 || ev.GatewayMatched != 13 ||
		ev.ModelSpans != 12 || ev.Changes != 1 || ev.UnexplainedChanges != 0 || len(st.Predicate.Checks) != 5 {
		t.Fatalf("everything accounted for: %v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks)
	}

	// The key used for a call the agent never reported, a model call the
	// agent reported that never went through the gateway, and the login
	// used with nothing of the agent near.
	later := now.Add(28 * time.Minute)
	appendAgentEvents(t, root, gatewayCall(later, key, ""), modelSpan(later.Add(-10*time.Minute)),
		githubAction(now.Add(-10*time.Minute), "triage-bot", "repo.add_member"))
	st, err = reconcileProof(t, root, args...)
	ev = st.Predicate.Reconciliation
	if err == nil || st.Predicate.Verdict != proof.Refuted || ev.GatewayUnreported != 1 ||
		ev.ModelUnseen != 1 || ev.UnexplainedChanges != 1 {
		t.Fatalf("refuted three ways: %v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	failures := strings.Join(st.Predicate.Checks[3].Failures, "|") + "|" +
		strings.Join(st.Predicate.Checks[4].Failures, "|")
	for _, want := range []string{"at the gateway, not in its account: a model call at ",
		"in its account, never at the gateway: a model call at ", "acted as it with nothing of it near: github/audit at "} {
		if !strings.Contains(failures, want) {
			t.Errorf("not named: %q in %s", want, failures)
		}
	}
	for _, chosen := range []string{"repo.add_member", "acompletion", "create_issue"} {
		if strings.Contains(failures, chosen) {
			t.Errorf("a name the caller chose is in the proof: %q", chosen)
		}
	}

	for _, bad := range [][]string{{"--gateway", "LiteLLM"}, {"--gateway-only"}, {"--identity", "the bot"}} {
		if _, err := reconcileProofArgs(t, root, bad...); err == nil {
			t.Errorf("%v was taken", bad)
		}
	}
}

// reconcileProofArgs runs a reconciliation expected to be refused before
// anything is written.
func reconcileProofArgs(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	key, pub := signingFiles(t)
	base := []string{"reconcile", "triage-bot", "--since",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "--key", key, "--public-key", pub,
		"--out", filepath.Join(t.TempDir(), "r.json")}
	return "", cmdAgent(root, append(base, args...))
}
