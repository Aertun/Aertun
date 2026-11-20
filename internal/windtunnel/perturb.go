// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// Perturbations: the faults real pipelines put into telemetry, applied to
// each scenario's session and each benign session, and the run scored
// again under each.
//
// Detections are written against clean streams and run against messy ones.
// At-least-once delivery duplicates events; a collector's queue delays some
// and reorders them; a source's clock runs minutes ahead; a workflow runs
// faster than it did when the threshold was chosen; an upgrade renames a
// field. Each breaks something different — a count, a correlation window, an
// ordering, a threshold, a predicate — and none of it is in a fixture. So
// each is a perturbation, deterministic from the run's seed and the
// session's identity, and the report says, per kind, how often an attack
// the rules caught is missed under it, and how often a benign session the
// rules were quiet on fires.

// The perturbation kinds, a closed set.
const (
	PerturbDup       = "dup"
	PerturbReorder   = "reorder"
	PerturbSkew      = "skew"
	PerturbBurst     = "burst"
	PerturbDropField = "drop-field"
)

// PerturbKinds are the kinds in the order they are reported.
var PerturbKinds = []string{PerturbDup, PerturbReorder, PerturbSkew, PerturbBurst, PerturbDropField}

// The parameters, fixed so two runs are comparable: a quarter of events
// delivered twice, a second apart; extra arrival delay up to twice the
// stream's own 99th-percentile lateness; one source five minutes ahead; the
// session four times faster.
const (
	dupEvery    = 4
	skewBy      = 5 * time.Minute
	burstFactor = 4
)

const perturbCaveat = "perturbations are fixed faults applied to each session as the " +
	"pipeline would — duplicated, delayed and reordered, a source's clock ahead, the work " +
	"compressed in time, a field the rules read removed — so a change under one is a finding " +
	"about how the rules meet messy data, not about the attack or the workflow"

// ParsePerturb reads --perturb: a comma-separated list from PerturbKinds, or
// all.
func ParsePerturb(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	if s == "all" {
		return append([]string{}, PerturbKinds...), nil
	}
	known := map[string]bool{}
	for _, k := range PerturbKinds {
		known[k] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if !known[k] {
			return nil, fmt.Errorf("%q is not a perturbation; the set is %s, or all", k,
				strings.Join(PerturbKinds, ", "))
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return kindIndex(out[i]) < kindIndex(out[j]) })
	return out, nil
}

func kindIndex(k string) int {
	for i, x := range PerturbKinds {
		if x == k {
			return i
		}
	}
	return len(PerturbKinds)
}

// readFields are the raw fields an instrument's rules read.
func readFields(ref *Reference) map[string]bool {
	out := map[string]bool{}
	for _, r := range ref.Rules {
		for _, f := range r.Fields() {
			if k, ok := strings.CutPrefix(f, "raw."); ok {
				out[k] = true
			}
		}
	}
	return out
}

// perturb applies one kind to a session. It answers the perturbed events and
// a note when the kind had nothing to act on.
func perturb(kind, id string, seed int64, events []telemetry.Event, lateness time.Duration,
	reads map[string]bool) ([]telemetry.Event, string) {

	r := newMutRand(id+"|"+kind, int(seed&0x7fffffff), 0)
	copyEvent := func(e telemetry.Event) telemetry.Event {
		if e.Raw != nil {
			raw := make(map[string]string, len(e.Raw))
			for k, v := range e.Raw {
				raw[k] = v
			}
			e.Raw = raw
		}
		return e
	}
	out := make([]telemetry.Event, 0, len(events)+len(events)/dupEvery+1)
	switch kind {
	case PerturbDup:
		dupped := false
		for i, e := range events {
			out = append(out, copyEvent(e))
			if r.intn(dupEvery) == 0 || (!dupped && i == len(events)-1) {
				d := copyEvent(e)
				d.Received = d.Received.Add(time.Second)
				out = append(out, d)
				dupped = true
			}
		}
	case PerturbReorder:
		budget := 2 * lateness
		if budget < 2*time.Second {
			budget = 2 * time.Second
		}
		for _, e := range events {
			c := copyEvent(e)
			c.Received = c.Received.Add(time.Duration(r.intn(int(budget/time.Millisecond))) * time.Millisecond)
			out = append(out, c)
		}
	case PerturbSkew:
		counts := map[string]int{}
		for _, e := range events {
			counts[e.Source]++
		}
		src := ""
		for _, s := range sortedKeys(counts) {
			if counts[s] > counts[src] {
				src = s
			}
		}
		for _, e := range events {
			c := copyEvent(e)
			if c.Source == src {
				c.Time = c.Time.Add(skewBy)
			}
			out = append(out, c)
		}
	case PerturbBurst:
		if len(events) == 0 {
			return nil, ""
		}
		t0 := events[0].Time
		for _, e := range events {
			if e.Time.Before(t0) {
				t0 = e.Time
			}
		}
		for _, e := range events {
			c := copyEvent(e)
			late := c.Received.Sub(c.Time)
			c.Time = t0.Add(c.Time.Sub(t0) / burstFactor)
			c.Received = c.Time.Add(late)
			out = append(out, c)
		}
	case PerturbDropField:
		// The field the rules read that the most of the session's events
		// carry: what an upgrade renaming one field takes from the rules.
		counts := map[string]int{}
		for _, e := range events {
			for k := range e.Raw {
				if reads[k] {
					counts[k]++
				}
			}
		}
		drop := ""
		for _, k := range sortedKeys(counts) {
			if counts[k] > counts[drop] {
				drop = k
			}
		}
		if drop == "" {
			return events, "carries no raw field the rules read"
		}
		for _, e := range events {
			c := copyEvent(e)
			delete(c.Raw, drop)
			out = append(out, c)
		}
		return out, "raw." + drop + " removed"
	}
	return out, ""
}

// PerturbRow is one scenario under one perturbation.
type PerturbRow struct {
	Scenario string `json:"scenario"`
	Kind     string `json:"kind"`
	Original string `json:"original_outcome"`
	Outcome  string `json:"outcome"`
	Note     string `json:"note,omitempty"`
}

// PerturbBenign is one benign session under one perturbation.
type PerturbBenign struct {
	Session  string   `json:"session"`
	Kind     string   `json:"kind"`
	Original string   `json:"original_outcome"`
	Outcome  string   `json:"outcome"`
	Fired    []string `json:"fired,omitempty"`
	Note     string   `json:"note,omitempty"`
}

// PerturbRate is one kind's rate.
type PerturbRate struct {
	Kind string     `json:"kind"`
	Rate *RateBound `json:"rate"`
}

// PerturbReport is the run under perturbation.
type PerturbReport struct {
	Kinds  []string        `json:"kinds"`
	Rows   []PerturbRow    `json:"rows"`
	Benign []PerturbBenign `json:"benign,omitempty"`
	// Miss is, per kind, the scenarios missed of those that landed caught
	// or missed under it; Breaks those the rules caught unperturbed and
	// missed under it.
	Miss   []PerturbRate `json:"miss"`
	Breaks []PerturbRate `json:"breaks"`
	// BenignFires is, per kind, the benign sessions that fired of those
	// measured.
	BenignFires []PerturbRate `json:"benign_fires,omitempty"`
	Caveat      string        `json:"caveat"`
}

func (p *PerturbReport) tally() {
	sort.Slice(p.Rows, func(i, j int) bool {
		if p.Rows[i].Scenario != p.Rows[j].Scenario {
			return p.Rows[i].Scenario < p.Rows[j].Scenario
		}
		return kindIndex(p.Rows[i].Kind) < kindIndex(p.Rows[j].Kind)
	})
	sort.Slice(p.Benign, func(i, j int) bool {
		if p.Benign[i].Session != p.Benign[j].Session {
			return p.Benign[i].Session < p.Benign[j].Session
		}
		return kindIndex(p.Benign[i].Kind) < kindIndex(p.Benign[j].Kind)
	})
	for _, k := range p.Kinds {
		var mk, mn, bk, bn, fk, fn int
		for _, r := range p.Rows {
			if r.Kind != k {
				continue
			}
			if r.Outcome == OutcomeMissed || r.Outcome == OutcomeCaughtAlert {
				mn++
				if r.Outcome == OutcomeMissed {
					mk++
				}
			}
			if r.Original == OutcomeCaughtAlert {
				bn++
				if r.Outcome == OutcomeMissed {
					bk++
				}
			}
		}
		for _, b := range p.Benign {
			if b.Kind != k || b.Outcome == BenignUnread {
				continue
			}
			fn++
			if b.Outcome == BenignFires {
				fk++
			}
		}
		p.Miss = append(p.Miss, PerturbRate{Kind: k, Rate: bound(mk, mn)})
		p.Breaks = append(p.Breaks, PerturbRate{Kind: k, Rate: bound(bk, bn)})
		if len(p.Benign) > 0 {
			p.BenignFires = append(p.BenignFires, PerturbRate{Kind: k, Rate: bound(fk, fn)})
		}
	}
}

// perturbScenario replays a placed session under each kind and scores it as
// the session itself was scored.
func perturbScenario(l *Loaded, ref *Reference, base []telemetry.Event, into string,
	placed *Placed, ambient *passResult, their bool, original string, kinds []string,
	seed int64) ([]PerturbRow, error) {

	sc := l.Scenario
	lateness := latenessHistogram(base).quantile(0.99)
	reads := readFields(ref)
	var rows []PerturbRow
	for _, k := range kinds {
		events, note := perturb(k, sc.ID, seed, placed.Events, lateness, reads)
		res, err := replaySession(base, events, ref,
			filepath.Join(into, "perturbed", sanitize(sc.ID)+"--"+k))
		if err != nil {
			return nil, fmt.Errorf("%s under %s: %w", sc.ID, k, err)
		}
		vp := &Placed{Events: events, Anchor: placed.Anchor, Delays: placed.Delays}
		rows = append(rows, PerturbRow{Scenario: sc.ID, Kind: k, Original: original,
			Outcome: sessionOutcome(sc, ref, res, ambient, vp, their), Note: note})
	}
	return rows, nil
}

func summarizePerturb(p *PerturbReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nunder perturbation (%s):\n", strings.Join(p.Kinds, ", "))
	for i, k := range p.Kinds {
		m, br := p.Miss[i].Rate, p.Breaks[i].Rate
		fmt.Fprintf(&b, "  %-10s missed %d of %d; caught before and missed under it: %d of %d", k, m.K, m.N, br.K, br.N)
		if len(p.BenignFires) > i {
			f := p.BenignFires[i].Rate
			fmt.Fprintf(&b, "; benign sessions firing %d of %d", f.K, f.N)
		}
		b.WriteString("\n")
	}
	for _, r := range p.Rows {
		if r.Outcome != r.Original {
			fmt.Fprintf(&b, "    %-38s %-10s %s → %s", r.Scenario, r.Kind, r.Original, r.Outcome)
			if r.Note != "" {
				fmt.Fprintf(&b, " (%s)", r.Note)
			}
			b.WriteString("\n")
		}
	}
	for _, s := range p.Benign {
		if s.Outcome != s.Original {
			fmt.Fprintf(&b, "    %-38s %-10s benign %s → %s %s\n", s.Session, s.Kind, s.Original, s.Outcome,
				strings.Join(s.Fired, ", "))
		}
	}
	b.WriteString(hang("  ", p.Caveat))
	return b.String()
}
