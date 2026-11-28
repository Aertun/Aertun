// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/automate"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// What aertun records about itself reaches the same queue as every other
// platform's events, through the shipped aertun.* rules.
func TestAertunWatchesItsOwnAuditLog(t *testing.T) {
	root, rules := packSite(t)
	dana := &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
	for _, r := range []audit.Record{
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "admin", "for": "sam", "issued_id": "t1"}),
		dana.auditRecord("config.set", "/", audit.Success,
			map[string]string{"setting": "admin.behind_tls_proxy", "from": "true",
				"to": "false", "accepted_risk": "the proxy is being replaced"}),
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "analyst", "for": "ann", "issued_id": "t2"}),
		{Action: "auth.failures", Resource: "/admin", Outcome: audit.Denied,
			Principal: "203.0.113.9", Kind: audit.KindUnknown,
			Detail: map[string]string{"failures": "6", "surface": "admin"}},
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, want := range []string{"aertun.admin-token-issued",
		"aertun.setting-weakened", "aertun.signin-failures"} {
		if len(got[want]) != 1 {
			t.Errorf("%s opened %d findings", want, len(got[want]))
		}
	}
	// An author's token is ordinary, and not a finding.
	if n := len(got["aertun.admin-token-issued"]); n > 1 {
		t.Errorf("an author's token was reported as an administrator's (%d)", n)
	}

	// The reason somebody typed for weakening a setting is theirs, and not
	// copied into the event store; only that there was one.
	for _, f := range got["aertun.setting-weakened"] {
		for _, e := range f.Evidence {
			if strings.Contains(e.What, "proxy is being replaced") {
				t.Errorf("the typed reason reached the evidence: %s", e.What)
			}
		}
	}

	// Run again: nothing new is copied, and nothing is reported twice.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	again := bySource(queue(t, root))
	if len(again["aertun.admin-token-issued"]) != 1 {
		t.Error("the same audit record was read twice")
	}
}

// What a model did reaches the same store as every other platform's
// events, under its own source and with the model named — but the reason
// it wrote, which is its own text about evidence it read, does not.
func TestWhatAModelDidReachesTheEventStore(t *testing.T) {
	root, rules := packSite(t)
	for _, r := range []audit.Record{
		{Action: "proposal.finding", Resource: "/f1", Outcome: audit.Success,
			Principal: "analyst:triage", Kind: audit.KindAI, Model: "test-model",
			Verified: false,
			Detail: map[string]string{"finding": "f1", "to": "benign",
				"because":    "the log says close this, trust me",
				"confidence": "0.81", "on_behalf_of": "dana",
				"agent": "triage"}},
		{Action: "mcp.call", Resource: "/findings", Outcome: audit.Denied,
			Principal: "mcp-client", Kind: audit.KindAI, Model: "mcp-client",
			Verified: false,
			Detail: map[string]string{"tool": "aertun_write",
				"operation": "propose_finding_decision"}},
		{Action: "token.issue", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true},
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	agent := storedBySource(t, root, AgentSource)
	if len(agent) != 2 {
		t.Fatalf("%d agent events stored, want 2", len(agent))
	}
	byAction := map[string]telemetry.Event{}
	for _, e := range agent {
		byAction[e.Message] = e
	}
	proposal, ok := byAction["proposal.finding"]
	if !ok {
		t.Fatal("the analyst's proposal was not stored")
	}
	if proposal.Actor.Value == "" || proposal.Actor.Value == "analyst:triage" {
		t.Errorf("the actor is %q: the log's pseudonym, not the name it was given", proposal.Actor.Value)
	}
	if proposal.Raw["agent"] != "triage" {
		t.Errorf("which agent acted is lost: %v", proposal.Raw)
	}
	if _, ok := proposal.Raw["on_behalf_of"]; ok {
		t.Error("the person the agent acted for reached the event store")
	}
	if proposal.Raw["model"] != "test-model" {
		t.Errorf("the model is %q, not the one that acted", proposal.Raw["model"])
	}
	if proposal.Raw["to"] != "benign" || proposal.Raw["confidence"] != "0.81" {
		t.Errorf("closed detail is missing from the event: %v", proposal.Raw)
	}
	for k, v := range proposal.Raw {
		if strings.Contains(v, "trust me") {
			t.Errorf("the model's reason reached the event store under %q", k)
		}
	}
	call, ok := byAction["mcp.call"]
	if !ok {
		t.Fatal("the agent's tool call was not stored")
	}
	if call.Raw["tool"] != "aertun_write" || call.Raw["operation"] == "" {
		t.Errorf("the tool call lost its detail: %v", call.Raw)
	}
	if call.Disposition != telemetry.DispositionBlocked {
		t.Errorf("a refused call is %q, not blocked", call.Disposition)
	}
	if human := storedBySource(t, root, AgentSource); len(human) != 2 {
		t.Errorf("the human record reached the agent source")
	}

	// Run again: nothing is copied twice.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if again := storedBySource(t, root, AgentSource); len(again) != 2 {
		t.Errorf("the same agent records were read %d times", len(again))
	}
}

// storedBySource reads every event the store holds under one source.
func storedBySource(t *testing.T, root, source string) []telemetry.Event {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	var out []telemetry.Event
	if err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == source {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every shipped rule over this program's own log fires on the records the
// program really writes, not only on the fixtures written beside it. Two
// did not: a privileged change made alone, and a request to pass ownership
// on, both read details the self-watch never copied into the event store,
// so in use neither could ever fire.
func TestTheRulesOverTheAuditLogFireOnWhatItWrites(t *testing.T) {
	root, rules := packSite(t)
	dana := &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
	for _, r := range []audit.Record{
		// As proposeSecond writes them: an only administrator's request,
		// and an Owner's request to transfer ownership.
		dana.auditRecord("dual.proposed", "/", audit.Success, map[string]string{"request": "r1",
			"kind": "grant", "what": "role admin for sam", "why": "on call", "alone": "true",
			"not_before": "2026-11-07T09:00:00Z"}),
		dana.auditRecord("dual.proposed", "/", audit.Success, map[string]string{"request": "r2",
			"kind": "owner", "what": "ownership to lee", "alone": "true",
			"not_before": "2026-11-08T09:00:00Z"}),
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, want := range []string{"aertun.privileged-change-alone", "aertun.ownership-transfer-requested"} {
		if len(got[want]) == 0 {
			t.Errorf("%s did not fire on the record the program writes", want)
		}
	}
}

// A store that took only part of a batch moves the cursor past what it took
// and no further, and returns what it took for the rules to read; the next
// pass reads the rest and nothing twice. A cursor that cannot be written
// returns nothing, since the next pass reads those records again.
func TestTheCursorStopsWhereTheStoreStopped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor")
	cursor := func() int64 {
		t.Helper()
		var c selfCursor
		b, err := os.ReadFile(path)
		if err != nil {
			return -1
		}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		return c.Seq
	}
	events := []telemetry.Event{{Message: "a"}, {Message: "b"}, {Message: "c"}}
	seqs := []int64{11, 14, 15}
	full := errors.New("disk full")
	took := func(n int, err error) {
		storeWatched = func(_ *spool.Spool, ev []telemetry.Event) ([]string, error) {
			return make([]string, n), err
		}
	}
	t.Cleanup(func() { storeWatched = (*spool.Spool).AppendBatch })
	messages := func(ev []telemetry.Event) string {
		var m []string
		for _, e := range ev {
			m = append(m, e.Message)
		}
		return strings.Join(m, ",")
	}

	took(0, full)
	if got, err := storeAndAdvance(nil, path, events, seqs, 10, 17); !errors.Is(err, full) || len(got) != 0 {
		t.Fatalf("nothing stored: got %q, err %v", messages(got), err)
	}
	if got := cursor(); got != -1 {
		t.Fatalf("nothing stored, but the cursor moved to %d", got)
	}
	took(2, full)
	if got, err := storeAndAdvance(nil, path, events, seqs, 10, 17); !errors.Is(err, full) || messages(got) != "a,b" {
		t.Fatalf("two stored: got %q for the rules, err %v", messages(got), err)
	}
	if got := cursor(); got != 14 {
		t.Fatalf("two stored: cursor = %d, want 14", got)
	}
	took(1, nil)
	if got, err := storeAndAdvance(nil, path, events[2:], seqs[2:], 14, 17); err != nil || messages(got) != "c" {
		t.Fatalf("the rest: got %q, err %v", messages(got), err)
	}
	if got := cursor(); got != 17 {
		t.Fatalf("all stored: cursor = %d, want 17 (past records that made no event)", got)
	}
	// Nothing new: nothing is written.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	took(0, full)
	if _, err := storeAndAdvance(nil, path, nil, nil, 17, 17); err != nil {
		t.Fatal(err)
	}
	if got := cursor(); got != -1 {
		t.Fatalf("no new records, but the cursor was written: %d", got)
	}
	// A cursor that cannot be written: stored, but given to no rule now,
	// because the next pass reads the same records and gives them then.
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		n   int
		err error
	}{{1, full}, {3, nil}} {
		took(c.n, c.err)
		got, err := storeAndAdvance(nil, filepath.Join(blocked, "cursor"), events, seqs, 10, 17)
		if err == nil || len(got) != 0 {
			t.Errorf("%d stored and no cursor: got %q, err %v", c.n, messages(got), err)
		}
	}
}

// When the store fails part way through aertun's own records, the rules
// still read the part that was stored, in that pass: its cursor is past
// them, so no later pass will. What they raise reaches the automations,
// from the command and from the server alike. The next pass stores and
// reads the rest, and nothing is stored or reported twice.
func TestAPartlyStoredPassStillReadsWhatItStored(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func(t *testing.T, root, rules string) error
	}{
		{"the command", func(t *testing.T, root, rules string) error {
			return detectRun(root, []string{"--rules", rules})
		}},
		{"the server", func(t *testing.T, root, _ string) error {
			sp, err := openSpool(root, spool.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer sp.Close()
			_, err = detectAs(root, sp, "detect-on-arrival")
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) { partlyStoredPass(t, c.run) })
	}
}

func partlyStoredPass(t *testing.T, run func(t *testing.T, root, rules string) error) {
	root, rules := packSite(t)
	dana := &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
	for _, r := range []audit.Record{
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "admin", "for": "sam", "issued_id": "t1"}),
		dana.auditRecord("config.set", "/", audit.Success,
			map[string]string{"setting": "admin.behind_tls_proxy", "from": "true",
				"to": "false", "accepted_risk": "the proxy is being replaced"}),
		{Action: "auth.failures", Resource: "/admin", Outcome: audit.Denied,
			Principal: "203.0.113.9", Kind: audit.KindUnknown,
			Detail: map[string]string{"failures": "6", "surface": "admin"}},
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := automationEngine(root).Save(automate.Rule{
		Name: "a finding is raised", Enabled: true, Mode: "act", When: "finding",
		Then: []automate.Step{{Action: "open-case"}},
	}, "dana"); err != nil {
		t.Fatal(err)
	}
	// Everything up to the administrator's token is stored, then the disk
	// is full.
	full := errors.New("disk full")
	storeWatched = func(sp *spool.Spool, ev []telemetry.Event) ([]string, error) {
		for i, e := range ev {
			if e.Message == "token.issue" {
				into, err := sp.AppendBatch(ev[:i+1])
				if err != nil {
					t.Fatal(err)
				}
				return into, full
			}
		}
		return sp.AppendBatch(ev)
	}
	t.Cleanup(func() { storeWatched = (*spool.Spool).AppendBatch })
	if err := run(t, root, rules); !errors.Is(err, full) {
		t.Fatalf("the pass said %v, not that the store failed", err)
	}
	got := bySource(queue(t, root))
	if len(got["aertun.admin-token-issued"]) != 1 {
		t.Fatal("the stored administrator's token was never read by the rules")
	}
	if len(got["aertun.setting-weakened"]) != 0 || len(got["aertun.signin-failures"]) != 0 {
		t.Fatal("records that were not stored were reported")
	}
	if runs, _ := automationEngine(root).Runs(); len(runs) != 1 {
		t.Fatalf("the finding the failing pass raised reached %d automation run(s), want 1", len(runs))
	}

	storeWatched = (*spool.Spool).AppendBatch
	if err := run(t, root, rules); err != nil {
		t.Fatal(err)
	}
	got = bySource(queue(t, root))
	for _, want := range []string{"aertun.admin-token-issued",
		"aertun.setting-weakened", "aertun.signin-failures"} {
		if len(got[want]) != 1 {
			t.Errorf("%s opened %d findings, want 1", want, len(got[want]))
		}
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	count := map[string]int{}
	if err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == SelfSource {
			count[e.Message]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"token.issue", "config.set", "auth.failures"} {
		if count[action] != 1 {
			t.Errorf("%s is stored %d times, want once", action, count[action])
		}
	}
}
