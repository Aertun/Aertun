// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package benign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/correlate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/telemetry"
)

// RuleSet is the rules a capture is checked against and a bundle measured
// with: detections and the correlations over them.
type RuleSet struct {
	Rules []detect.Rule
	Corrs []correlate.Rule
}

// RuleDigest names one rule by the SHA-256 of its canonical JSON, so a rule
// edited after the check is not mistaken for the one that was checked.
func RuleDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	c, err := jcs.Canonicalize(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// Digests are every rule's and correlation's digest, sorted.
func (rs RuleSet) Digests() ([]string, error) {
	out := make([]string, 0, len(rs.Rules)+len(rs.Corrs))
	for _, r := range rs.Rules {
		d, err := RuleDigest(r)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	for _, c := range rs.Corrs {
		d, err := RuleDigest(c)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// SetDigest names a set of rule digests.
func SetDigest(digests []string) string {
	sum := sha256.Sum256([]byte(strings.Join(digests, "\n")))
	return hex.EncodeToString(sum[:])
}

// Outcome is what a rule set did over a list of events: each detection's
// matches by event, each correlation's hit count, and the alert-tier rules
// that fired at all.
type Outcome struct {
	Matches map[string][]int
	Hits    map[string]int
	Fired   []string
}

// Evaluate runs a rule set over events in arrival order, as the replay
// would: detections event by event, correlations windowed on the events'
// own time and closed when the recording ends.
func Evaluate(rs RuleSet, events []telemetry.Event) (*Outcome, error) {
	progs := make([]*detect.Program, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		p, err := r.Compile()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.ID, err)
		}
		progs = append(progs, p)
	}
	engines := make([]*correlate.Engine, 0, len(rs.Corrs))
	for _, c := range rs.Corrs {
		e, err := correlate.New(c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		engines = append(engines, e)
	}
	order := make([]int, len(events))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return events[order[a]].Received.Before(events[order[b]].Received)
	})
	out := &Outcome{Matches: map[string][]int{}, Hits: map[string]int{}}
	fired := map[string]bool{}
	var wm time.Time
	for _, i := range order {
		e := events[i]
		if e.Received.After(wm) {
			wm = e.Received
		}
		f := e.Fields()
		for _, p := range progs {
			if !p.MatchesFields(e.Source, f) {
				continue
			}
			out.Matches[p.ID] = append(out.Matches[p.ID], i)
			if !p.Quiet {
				fired[p.ID] = true
			}
			for _, eng := range engines {
				if eng.Watches(p.ID) {
					if err := eng.Observe(correlate.Seen{Rule: p.ID, Event: e}, wm); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	for _, eng := range engines {
		if n := len(eng.Flush()); n > 0 {
			out.Hits[eng.Rule().ID] = n
			fired[eng.Rule().ID] = true
		}
	}
	for id := range fired {
		out.Fired = append(out.Fired, id)
	}
	sort.Strings(out.Fired)
	for id := range out.Matches {
		sort.Ints(out.Matches[id])
	}
	return out, nil
}

// Mismatch is a rule whose outcome sanitising changed: on which event, and
// which of the fields it reads differ there. Event is -1 for a correlation,
// whose hits are counted rather than placed.
type Mismatch struct {
	Rule   string
	Event  int
	Fields []string
}

// Compare holds the sanitised outcome to the raw one, rule by rule and event
// by event, and names every difference with the fields that explain it.
func Compare(rs RuleSet, raw, clean []telemetry.Event, a, b *Outcome) []Mismatch {
	var out []Mismatch
	reads := map[string][]string{}
	for _, r := range rs.Rules {
		reads[r.ID] = r.Fields()
	}
	ids := map[string]bool{}
	for id := range a.Matches {
		ids[id] = true
	}
	for id := range b.Matches {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		x, y := toSet(a.Matches[id]), toSet(b.Matches[id])
		for _, i := range union(x, y) {
			if x[i] == y[i] {
				continue
			}
			rf, cf := raw[i].Fields(), clean[i].Fields()
			var diff []string
			for _, f := range reads[id] {
				if rf[f] != cf[f] {
					diff = append(diff, f)
				}
			}
			out = append(out, Mismatch{Rule: id, Event: i, Fields: diff})
		}
	}
	for _, c := range rs.Corrs {
		if a.Hits[c.ID] != b.Hits[c.ID] {
			out = append(out, Mismatch{Rule: c.ID, Event: -1})
		}
	}
	return out
}

func toSet(xs []int) map[int]bool {
	m := make(map[int]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func union(a, b map[int]bool) []int {
	var out []int
	for k := range a {
		out = append(out, k)
	}
	for k := range b {
		if !a[k] {
			out = append(out, k)
		}
	}
	sort.Ints(out)
	return out
}

// literalFields are the fields a predicate compares against a value it
// names: every comparison but presence. A consistent pseudonym keeps
// presence and every equality between events; it keeps no literal.
func literalFields(p detect.Predicate, into map[string]bool) {
	if p.Match != nil && p.Match.Op != detect.Exists {
		into[p.Match.Field] = true
	}
	for _, sub := range p.All {
		literalFields(sub, into)
	}
	for _, sub := range p.Any {
		literalFields(sub, into)
	}
	if p.Not != nil {
		literalFields(*p.Not, into)
	}
}

// aliases are the names a rule may read an identifier by: the pair, its
// issuer, its value. A transformed value transforms the pair.
func aliased(set []string) map[string]bool {
	m := map[string]bool{}
	for _, f := range set {
		m[f] = true
		if base, ok := strings.CutSuffix(f, ".value"); ok {
			m[base] = true
		}
	}
	return m
}

// Unmeasurable says why a rule cannot be measured on a session, or nothing
// when it can.
//
// A rule that reads none of the session's sources can be measured: it
// cannot fire there, raw or sanitised. Otherwise it cannot be measured when
// it reads a field the session dropped, or compares a field the session
// transformed with a literal — unless this exact rule, by digest, was in the
// session's fidelity check, which showed its outcome unchanged.
func Unmeasurable(r detect.Rule, digest string, s Session, checked map[string]bool) string {
	reads := false
	for _, src := range r.Sources {
		for _, have := range s.Sources {
			if strings.EqualFold(strings.TrimSpace(src), have) {
				reads = true
			}
		}
	}
	if !reads {
		return ""
	}
	dropped := aliased(s.Dropped)
	var gone []string
	for _, f := range r.Fields() {
		if dropped[f] {
			gone = append(gone, f)
		}
	}
	if len(gone) > 0 {
		return "reads " + strings.Join(gone, ", ") + ", which the session does not carry"
	}
	if checked[digest] {
		return ""
	}
	transformed := aliased(s.Transformed)
	lit := map[string]bool{}
	literalFields(r.When, lit)
	var changed []string
	for f := range lit {
		if transformed[f] {
			changed = append(changed, f)
		}
	}
	sort.Strings(changed)
	if len(changed) > 0 {
		return "compares " + strings.Join(changed, ", ") + " with a value, and the session " +
			"pseudonymised it; this rule was not in its fidelity check"
	}
	return ""
}
