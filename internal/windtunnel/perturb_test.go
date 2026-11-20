// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/correlate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/telemetry"
)

func TestThePerturbationsAreAClosedSet(t *testing.T) {
	got, err := ParsePerturb("burst, dup,burst")
	if err != nil || strings.Join(got, ",") != "dup,burst" {
		t.Errorf("%v %v", got, err)
	}
	if all, _ := ParsePerturb("all"); len(all) != len(PerturbKinds) {
		t.Errorf("all is %v", all)
	}
	if _, err := ParsePerturb("dup,chaos"); err == nil || !strings.Contains(err.Error(), "chaos") {
		t.Errorf("%v", err)
	}
	if _, err := Run(RunOptions{Perturb: []string{"chaos"}}); err == nil {
		t.Error("a run took a perturbation outside the set")
	}
}

func sessionOf(n int, gap time.Duration) []telemetry.Event {
	start := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	var out []telemetry.Event
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * gap)
		src := "otel/genai"
		if i%3 == 2 {
			src = "aws/cloudtrail"
		}
		out = append(out, telemetry.Event{Time: at, Received: at.Add(2 * time.Second), Source: src,
			Raw: map[string]string{"tool": "sql_query", "rows": "20"}})
	}
	return out
}

// Each fault does what the pipeline does, deterministically, and leaves the
// session it was handed untouched.
func TestEachPerturbationDoesWhatThePipelineDoes(t *testing.T) {
	in := sessionOf(12, time.Minute)
	reads := map[string]bool{"tool": true}
	dup, _ := perturb(PerturbDup, "s", 7, in, time.Second, reads)
	if len(dup) <= len(in) {
		t.Errorf("dup delivered %d of %d", len(dup), len(in))
	}
	again, _ := perturb(PerturbDup, "s", 7, in, time.Second, reads)
	if fmt.Sprint(again) != fmt.Sprint(dup) {
		t.Error("the same seed perturbed differently")
	}
	burst, _ := perturb(PerturbBurst, "s", 7, in, time.Second, reads)
	if span := burst[len(burst)-1].Time.Sub(burst[0].Time); span != 11*time.Minute/burstFactor {
		t.Errorf("burst spans %s", span)
	}
	if late := burst[5].Received.Sub(burst[5].Time); late != 2*time.Second {
		t.Errorf("burst changed an event's own lateness to %s", late)
	}
	skew, _ := perturb(PerturbSkew, "s", 7, in, time.Second, reads)
	if skew[0].Time.Sub(in[0].Time) != skewBy || !skew[2].Time.Equal(in[2].Time) {
		t.Error("skew did not move the busiest source alone")
	}
	drop, note := perturb(PerturbDropField, "s", 7, in, time.Second, reads)
	if _, has := drop[0].Raw["tool"]; has || drop[0].Raw["rows"] != "20" || note != "raw.tool removed" {
		t.Errorf("drop-field: %v %q", drop[0].Raw, note)
	}
	reorder, _ := perturb(PerturbReorder, "s", 7, in, 10*time.Second, reads)
	moved := 0
	for i := range in {
		if !reorder[i].Received.Equal(in[i].Received) {
			moved++
		}
	}
	if moved == 0 {
		t.Error("reorder delayed nothing")
	}
	if _, has := in[0].Raw["tool"]; !has || !in[0].Time.Equal(time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)) {
		t.Error("a perturbation changed the session it was handed")
	}
}

// A scenario the rules catch is missed when an upgrade takes away the field
// they match on; the report names the field and counts the break.
func TestADroppedFieldBreaksACatchAndIsCounted(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7, Now: benignNow, Perturb: []string{PerturbDup, PerturbDropField},
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Into: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := card.Perturbation
	if p == nil || len(p.Rows) != 2 {
		t.Fatalf("%+v", p)
	}
	var drop PerturbRow
	for _, r := range p.Rows {
		if r.Kind == PerturbDropField {
			drop = r
		}
	}
	if drop.Original != OutcomeCaughtAlert || drop.Outcome != OutcomeMissed || !strings.HasSuffix(drop.Note, " removed") {
		t.Errorf("%+v", drop)
	}
	if p.Breaks[1].Kind != PerturbDropField || p.Breaks[1].Rate.K != 1 || p.Breaks[1].Rate.N != 1 {
		t.Errorf("%+v", p.Breaks)
	}
	if !strings.Contains(card.Summarize(), "under perturbation") {
		t.Error("the screen does not say it")
	}
}

// A count-based correlation quiet on a real workflow fires when the same
// workflow runs four times faster: the threshold was chosen for the speed
// it ran at when somebody looked, and the report says so.
func TestABurstOfABenignWorkflowCrossesAThreshold(t *testing.T) {
	sql := benignRule(t, `{"id":"otel.any-sql","title":"Any query","sources":["otel/genai"],"severity":2,"quiet":true,
	 "when":{"match":{"field":"raw.tool","op":"equals","values":["sql_query"]}}}`)
	many := correlate.Rule{ID: "corr.many-queries", Title: "Many queries by one agent", Type: correlate.EventCount,
		Rules: []string{"otel.any-sql"}, GroupBy: []string{"actor"}, Timespan: 5 * time.Minute,
		Test: correlate.Test{Op: "gte", N: 8}}
	ref := reference(sql)
	ref.Corrs = []correlate.Rule{many}
	ref.ruleQuiet["otel.any-sql"] = true
	ref.corrIDs["corr.many-queries"] = true
	var evs []telemetry.Event
	start := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		at := start.Add(time.Duration(i) * time.Minute)
		evs = append(evs, telemetry.Event{Time: at, Received: at.Add(time.Second), Source: "otel/genai",
			Class: telemetry.ClassAPIActivity, Actor: telemetry.ID{Issuer: "otel", Value: "migrator"},
			Raw: map[string]string{"operation": "execute_tool", "tool": "sql_query"}})
	}
	b := bundleOf(t, []detect.Rule{sql}, map[string][]telemetry.Event{"quarterly-migration": evs})
	card, err := Run(RunOptions{Seed: 7, Now: benignNow, Reference: ref, Baseline: b,
		Perturb: []string{PerturbBurst}, Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Into: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if card.Benign.Fires.K != 0 {
		t.Fatalf("the workflow at its own pace should be quiet: %+v", card.Benign.Sessions)
	}
	pb := card.Perturbation.Benign
	if len(pb) != 1 || pb[0].Outcome != BenignFires || strings.Join(pb[0].Fired, ",") != "corr.many-queries" ||
		card.Perturbation.BenignFires[0].Rate.K != 1 {
		t.Errorf("%+v", pb)
	}
}
