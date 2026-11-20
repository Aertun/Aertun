// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/benign"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/telemetry"
)

var benignNow = time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

func benignRule(t *testing.T, js string) detect.Rule {
	t.Helper()
	var r detect.Rule
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// bulkRows fires on a query returning more than limit rows.
func bulkRows(t *testing.T, limit string) detect.Rule {
	return benignRule(t, `{"id":"otel.bulk-rows","title":"A query returned many rows","sources":["otel/genai"],
	 "severity":3,"when":{"all":[{"match":{"field":"raw.tool","op":"equals","values":["sql_query"]}},
	  {"match":{"field":"raw.rows","op":"above","values":["`+limit+`"]}}]}}`)
}

// notTheMigrator compares the actor with a literal: on a pseudonymised
// session it cannot be measured unless it was in the fidelity check.
func notTheMigrator(t *testing.T) detect.Rule {
	return benignRule(t, `{"id":"otel.sql-not-migrator","title":"SQL by anyone but the migrator","sources":["otel/genai"],
	 "severity":3,"when":{"all":[{"match":{"field":"raw.tool","op":"equals","values":["sql_query"]}},
	  {"not":{"match":{"field":"actor","op":"equals","values":["otel:migrator"]}}}]}}`)
}

func reference(rules ...detect.Rule) *Reference {
	return &Reference{Name: "test", Rules: rules, Digest: strings.Repeat("ab", 32),
		ruleQuiet: map[string]bool{}, corrIDs: map[string]bool{}}
}

// agentRun is one vouched-for workflow: an agent making n queries a second
// apart, each returning rows rows.
func agentRun(agent string, n int, rows string) []telemetry.Event {
	start := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	var out []telemetry.Event
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		out = append(out, telemetry.Event{Time: at, Received: at.Add(2 * time.Second), Source: "otel/genai",
			Class: telemetry.ClassAPIActivity, Disposition: telemetry.DispositionAllowed,
			Actor: telemetry.ID{Issuer: "otel", Value: agent},
			Raw: map[string]string{"operation": "execute_tool", "tool": "sql_query", "rows": rows,
				"status": "ok", "trace_id": "9f00aa11bb22cc33dd44ee55ff660077"}})
	}
	return out
}

// bundleOf captures each workflow against rules and seals the bundle.
func bundleOf(t *testing.T, rules []detect.Rule, sessions map[string][]telemetry.Event) *benign.Bundle {
	t.Helper()
	key := bytes.Repeat([]byte{9}, 32)
	m := benign.Manifest{Made: benignNow, Policy: benign.PolicyVersion, KeyID: benign.KeyID(key)}
	events := map[string][]telemetry.Event{}
	for name, evs := range sessions {
		ack := map[string]bool{}
		for _, r := range rules {
			ack[r.ID] = true
		}
		c, err := benign.NewCapture(benign.CaptureInput{Name: name, Class: "migration", Events: evs, Key: key,
			Rules: benign.RuleSet{Rules: rules}, Acknowledge: ack, Why: "the quarterly migration",
			By: "dana", Life: 30 * 24 * time.Hour, Now: benignNow.Add(-24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		c.Session.ApprovedBy = "p-" + strings.Repeat("b", 13)
		m.Sessions = append(m.Sessions, c.Session)
		m.Sets = append(m.Sets, benign.FidelitySet{ID: c.Session.Fidelity.Set, Rules: c.FidelityRules})
		events[name] = c.Events
	}
	seen := map[string]bool{}
	var sets []benign.FidelitySet
	for _, s := range m.Sets {
		if !seen[s.ID] {
			sets = append(sets, s)
			seen[s.ID] = true
		}
	}
	m.Sets = sets
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := benign.Seal(m, events, k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := benign.Open(body, k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func benignRun(t *testing.T, ref *Reference, b *benign.Bundle, mutate int) *Scorecard {
	t.Helper()
	card, err := Run(RunOptions{Seed: 7, Now: benignNow, Reference: ref, Baseline: b, Mutate: mutate,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Into: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// The estate's own sessions are replayed and a rule that fires on one is a
// false positive this estate would have seen, counted per session with
// Wilson bounds and named; the scorecard seals it.
func TestABenignSessionARuleFiresOnIsCountedAndNamed(t *testing.T) {
	rules := []detect.Rule{bulkRows(t, "1000")}
	b := bundleOf(t, rules, map[string][]telemetry.Event{
		"quarterly-migration": agentRun("migrator", 40, "5000"),
		"nightly-report":      agentRun("reporter", 10, "20"),
	})
	card := benignRun(t, reference(rules...), b, 0)
	r := card.Benign
	if r == nil || r.Fires.K != 1 || r.Fires.N != 2 || r.Bundle != b.Digest {
		t.Fatalf("%+v", r)
	}
	var fired *BenignSession
	for i := range r.Sessions {
		if r.Sessions[i].Name == "quarterly-migration" {
			fired = &r.Sessions[i]
		}
	}
	if fired == nil || fired.Outcome != BenignFires || strings.Join(fired.Fired, ",") != "otel.bulk-rows" {
		t.Errorf("%+v", r.Sessions)
	}
	if len(r.Rules) != 1 || r.Rules[0].Fires.K != 1 || r.Rules[0].Fires.N != 2 || r.Fires.High <= r.Fires.Low {
		t.Errorf("%+v", r.Rules)
	}
	if !strings.Contains(card.Summarize(), "1 of 2 session(s)") {
		t.Errorf("the screen does not say it: %s", card.Summarize())
	}
	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
}

// A rule that compares a pseudonymised field with a literal, and was not in
// the session's fidelity check, is named as unmeasurable — and its fires on
// the sanitised events, which are not what it would do on the raw ones, are
// not counted.
func TestARuleThatCannotBeMeasuredIsNeitherQuietNorFiring(t *testing.T) {
	b := bundleOf(t, []detect.Rule{bulkRows(t, "1000")}, map[string][]telemetry.Event{
		"quarterly-migration": agentRun("migrator", 40, "20"),
	})
	card := benignRun(t, reference(bulkRows(t, "1000"), notTheMigrator(t)), b, 0)
	r := card.Benign
	if r.Fires.K != 0 || r.Fires.N != 1 || len(r.Gaps) != 1 || r.Gaps[0].Rule != "otel.sql-not-migrator" ||
		!strings.Contains(r.Gaps[0].Why, "pseudonymised") {
		t.Fatalf("%+v", r)
	}
	// Measured only by the rule it cannot read: the session says nothing.
	card = benignRun(t, reference(notTheMigrator(t)), b, 0)
	if card.Benign.Unread != 1 || card.Benign.Fires.N != 0 || card.Benign.Sessions[0].Outcome != BenignUnread {
		t.Errorf("%+v", card.Benign)
	}
}

// A rule change that fires on a benign session fails the gate, pair by
// pair; an accepted pair passes with its reason; an expired acceptance is
// ignored and named; a rule narrowed back is a fix.
func TestABenignRegressionFailsTheGateUnlessAccepted(t *testing.T) {
	b := bundleOf(t, []detect.Rule{bulkRows(t, "10000")}, map[string][]telemetry.Event{
		"quarterly-migration": agentRun("migrator", 40, "5000"),
	})
	before := benignRun(t, reference(bulkRows(t, "10000")), b, 0)
	after := benignRun(t, reference(bulkRows(t, "1000")), b, 0)
	d, err := Diff("before.json", before, "after.json", after)
	if err != nil {
		t.Fatal(err)
	}
	if d.Benign == nil || d.Benign.Regressions != 1 || d.Gating() != 1 ||
		d.Benign.Pairs[0].Rule != "otel.bulk-rows" || d.Benign.Pairs[0].Kind != BenignRegression {
		t.Fatalf("%+v", d.Benign)
	}
	if !strings.Contains(d.Summarize(), "revoke the session") {
		t.Errorf("the way out is not named: %s", d.Summarize())
	}
	acc, err := ReadAcceptances([]byte(`[{"session":"quarterly-migration","rule":"otel.bulk-rows",
	  "reason":"the migration runs once a quarter and is watched","by":"dana","expires":"2027-01-31T00:00:00Z"},
	 {"session":"quarterly-migration","rule":"otel.other","reason":"old","by":"dana","expires":"2026-11-01T00:00:00Z"}]`), benignNow)
	if err != nil {
		t.Fatal(err)
	}
	d.Accept(acc, benignNow)
	if d.Benign.Regressions != 0 || d.Benign.Accepted != 1 || d.Gating() != 0 ||
		len(d.Benign.ExpiredAcceptances) != 1 || !strings.Contains(d.Benign.Pairs[0].Reason, "once a quarter") {
		t.Errorf("%+v", d.Benign)
	}
	back, err := Diff("after.json", after, "before.json", before)
	if err != nil {
		t.Fatal(err)
	}
	if back.Benign.Fixes != 1 || back.Gating() != 0 {
		t.Errorf("narrowed back: %+v", back.Benign)
	}
}

func TestAnAcceptanceFileIsReadStrictly(t *testing.T) {
	for body, want := range map[string]string{
		`[{"session":"m","rule":"r","reason":"x","by":"d","expires":"2027-01-01T00:00:00Z"}]`:            "ids",
		`[{"session":"mig","rule":"r","reason":"","by":"d","expires":"2027-01-01T00:00:00Z"}]`:           "reason",
		`[{"session":"mig","rule":"r","reason":"x","by":"d","expires":"2028-01-01T00:00:00Z"}]`:          "180 days",
		`[{"session":"mig","rule":"r","reason":"x","by":"d","expires":"2027-01-01T00:00:00Z","note":1}]`: "JSON array",
	} {
		if _, err := ReadAcceptances([]byte(body), benignNow); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", body, err, want)
		}
	}
}

// Expired sessions are left out and named; a bundle with none live is
// refused rather than measuring nothing.
func TestExpiredSessionsAreLeftOutAndNamed(t *testing.T) {
	rules := []detect.Rule{bulkRows(t, "1000")}
	b := bundleOf(t, rules, map[string][]telemetry.Event{"quarterly-migration": agentRun("migrator", 5, "20")})
	_, err := Run(RunOptions{Seed: 7, Now: benignNow.Add(60 * 24 * time.Hour), Reference: reference(rules...),
		Baseline: b, Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Into: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("%v", err)
	}
	card, err := Run(RunOptions{Seed: 7, Now: benignNow.Add(20 * 24 * time.Hour), Reference: reference(rules...),
		Baseline: b, Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Into: t.TempDir()})
	if err != nil || len(card.Benign.Expiring) != 1 {
		t.Errorf("%v %+v", err, card.Benign)
	}
}

// An allowlist written for one exact spelling of a benign command is quiet
// on the session and fires on its respellings: under --mutate the benign
// axis says so, which is the robustness a gate over real workflows needs.
func TestABenignSessionIsRespelledUnderMutation(t *testing.T) {
	allow := benignRule(t, `{"id":"otel.shell-not-the-backup","title":"A shell command that is not the backup",
	 "sources":["otel/genai"],"severity":3,"when":{"all":[{"match":{"field":"raw.tool","op":"equals","values":["shell"]}},
	  {"not":{"match":{"field":"raw.command","op":"equals","values":["pg_dump --table orders --file /var/backups/orders.sql"]}}}]}}`)
	start := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	var evs []telemetry.Event
	for i := 0; i < 3; i++ {
		at := start.Add(time.Duration(i) * time.Minute)
		evs = append(evs, telemetry.Event{Time: at, Received: at.Add(time.Second), Source: "otel/genai",
			Class: telemetry.ClassAPIActivity, Actor: telemetry.ID{Issuer: "otel", Value: "backup-agent"},
			Raw: map[string]string{"operation": "execute_tool", "tool": "shell", "shell": "bash",
				"command": "pg_dump --table orders --file /var/backups/orders.sql"}})
	}
	b := bundleOf(t, []detect.Rule{allow}, map[string][]telemetry.Event{"nightly-dump": evs})
	card := benignRun(t, reference(allow), b, 8)
	r := card.Benign
	if r.Fires.K != 0 || r.Fires.N != 1 {
		t.Fatalf("the exact spelling should be quiet: %+v", r)
	}
	if r.Mutated == nil || r.Mutated.N == 0 || r.Mutated.K == 0 || r.Sessions[0].Mutated == nil {
		t.Errorf("respellings of the allowed command did not fire the spelling-bound rule: %+v", r.Mutated)
	}
}
