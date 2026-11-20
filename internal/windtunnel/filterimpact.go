// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"path/filepath"
	"time"

	"github.com/aertun/aertun/internal/benign"
	"github.com/aertun/aertun/internal/telemetry"
)

// What a library's exceptions cost. Tuning is judged everywhere by the
// noise it removes and nowhere by the attacks it hides, so a filter added
// for last quarter's migration can quietly blind the rule it tuned. When a
// library's global filters tuned anything, the run replays the library a
// second time without them: a scenario the unfiltered rules caught and the
// filtered ones missed was hidden by the filters, and a benign session the
// unfiltered rules fired on and the filtered ones did not had its false
// positive removed. Each is attributed to every applied filter whose
// condition takes out one of that session's events, so the scorecard names
// the exception beside the attack it costs.
func filterImpact(card *Scorecard, theirs *theirSigma, selected []*Loaded, base []telemetry.Event,
	into string, seed int64, baseline *benign.Bundle, now time.Time) error {

	bare := theirs.bare
	dir := filepath.Join(into, "unfiltered")
	ambSp, err := WriteScratch(filepath.Join(dir, "ambient"), base)
	if err != nil {
		return err
	}
	amb, err := runPass(ambSp, bare, latenessHistogram(base).quantile(0.99))
	ambSp.Close()
	if err != nil {
		return err
	}
	anchor, err := DefaultAnchor(base)
	if err != nil {
		return err
	}
	filtered := map[string]string{}
	for _, r := range card.Rows {
		filtered[r.Scenario] = r.Outcome
	}
	impacts := card.TheirSigma.Filters
	for _, l := range selected {
		row, _, _, err := runOne(l, bare, base, dir, seed, amb, true, 0, nil)
		if err != nil {
			return err
		}
		if row.Outcome != OutcomeCaughtAlert || filtered[l.Scenario.ID] != OutcomeMissed {
			continue
		}
		placed, err := Place(l.Scenario, l.Scenario.Steps, base, seed, anchor)
		if err != nil {
			return err
		}
		for i, f := range theirs.filters {
			if len(f.Applied) > 0 && takesOut(f, placed.Events) {
				impacts[i].Hid = append(impacts[i].Hid, l.Scenario.ID)
			}
		}
	}
	if baseline == nil || card.Benign == nil {
		return nil
	}
	quiet := map[string]bool{}
	for _, s := range card.Benign.Sessions {
		quiet[s.Name] = s.Outcome == BenignQuiet
	}
	unfiltered, _, err := runBenign(baseline, bare, base, dir, amb, 0, nil, seed, now)
	if err != nil {
		return err
	}
	for _, s := range unfiltered.Sessions {
		if s.Outcome != BenignFires || !quiet[s.Name] {
			continue
		}
		events := shiftTo(baseline.Events[s.Name], anchor)
		for i, f := range theirs.filters {
			if len(f.Applied) > 0 && takesOut(f, events) {
				impacts[i].Removed = append(impacts[i].Removed, s.Name)
			}
		}
	}
	return nil
}
