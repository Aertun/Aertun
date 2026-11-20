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

	"github.com/aertun/aertun/internal/benign"
	"github.com/aertun/aertun/internal/telemetry"
)

// The benign axis: the estate's own weird-but-benign sessions
// (internal/benign), replayed one at a time into the base stream, and every
// alert above ambient that a measurable rule raises on one is a false
// positive this estate would have seen.
//
// # What a session comes to
//
// Quiet, or fires — naming each measurable rule — or unread, when no rule
// that reads its sources can be measured on it, so it says nothing about
// these rules either way. A rule is unmeasurable on a session when it reads
// a field the session dropped, or compares a field the session pseudonymised
// with a literal and was not in the session's fidelity check: what such a
// rule does on the sanitised events is not what it would do on the raw
// ones, so its fires there are not counted and its silence is not either.
//
// # The rates
//
// Per session, not per event — the unit a team vouches for and an analyst
// experiences — with 95% Wilson bounds: overall, per rule over the sessions
// it can be measured on, and per class. A bundle is the sessions somebody
// chose to vouch for, not a random sample of the estate, and the caveat says
// so on every document.

// The outcomes a benign session comes to.
const (
	BenignQuiet  = "quiet"
	BenignFires  = "fires"
	BenignUnread = "unread"
)

// BenignSoon is how far ahead the report names sessions about to expire, so
// a renewal is asked for before a gate starts failing for want of one.
const BenignSoon = 14 * 24 * time.Hour

const benignCaveat = "the benign sessions are the ones this estate's people vouched for and " +
	"a second administrator approved — chosen, not sampled — so the rates say how often these " +
	"rules fire on these workflows, not on everything the estate does; a rule that cannot be " +
	"measured on a sanitised session is named and left out rather than counted as quiet"

// BenignSession is what one session came to.
type BenignSession struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Digest  string `json:"digest"`
	Outcome string `json:"outcome"`
	// Fired are the measurable rules that raised an alert above ambient.
	Fired []string `json:"fired,omitempty"`
	// Unmeasurable are the rules that read its sources and cannot be
	// measured on it.
	Unmeasurable []string `json:"unmeasurable,omitempty"`
	// Mutated is its variants that fired, of those made, when mutation was
	// asked for and its events carry anything to respell.
	Mutated *RateBound `json:"mutated,omitempty"`
}

// BenignRule is one rule over the sessions it can be measured on.
type BenignRule struct {
	Rule  string     `json:"rule"`
	Fires *RateBound `json:"fires"`
}

// BenignClass is one class of session.
type BenignClass struct {
	Class string     `json:"class"`
	Fires *RateBound `json:"fires"`
}

// BenignGap is a rule that cannot be measured on some sessions, and why.
type BenignGap struct {
	Rule     string `json:"rule"`
	Sessions int    `json:"sessions"`
	Why      string `json:"why"`
}

// BenignReport is the benign axis of a run.
type BenignReport struct {
	// Bundle names the bundle by its digest, Signer by the key that signed
	// it, Policy the sanitising rules it was made under.
	Bundle string `json:"bundle"`
	Signer string `json:"signer"`
	Policy string `json:"policy"`
	// Sessions are the live sessions, by name.
	Sessions []BenignSession `json:"sessions"`
	// Fires is the sessions that raised a false positive, of those any
	// measurable rule reads.
	Fires *RateBound `json:"fires"`
	// Unread counts the sessions no measurable rule reads.
	Unread  int           `json:"unread"`
	Rules   []BenignRule  `json:"rules,omitempty"`
	Classes []BenignClass `json:"classes,omitempty"`
	Gaps    []BenignGap   `json:"gaps,omitempty"`
	// Mutated is every session's variants together, when mutation ran.
	Mutated *RateBound `json:"mutated,omitempty"`
	// Expired names the sessions past their expiry, left out; Expiring
	// those within BenignSoon of it.
	Expired  []string `json:"expired,omitempty"`
	Expiring []string `json:"expiring,omitempty"`
	Caveat   string   `json:"caveat"`
}

// shiftTo moves a session so its first event happens at anchor, keeping
// every gap between events and every event's own arrival delay: the
// burstiness and the lateness are the session's, and are what is tested.
func shiftTo(events []telemetry.Event, anchor time.Time) []telemetry.Event {
	if len(events) == 0 {
		return nil
	}
	first := events[0].Time
	for _, e := range events {
		if e.Time.Before(first) {
			first = e.Time
		}
	}
	d := anchor.Sub(first)
	out := make([]telemetry.Event, len(events))
	for i, e := range events {
		e.Time, e.Received = e.Time.Add(d), e.Received.Add(d)
		out[i] = e
	}
	return out
}

// fires are the rules and correlations a replay raised above ambient.
func fires(p, ambient *passResult) map[string]bool {
	out := map[string]bool{}
	for id, n := range p.loud {
		if n > ambient.loud[id] {
			out[id] = true
		}
	}
	for id, hits := range p.hits {
		if len(hits) > len(ambient.hits[id]) {
			out[id] = true
		}
	}
	return out
}

// runBenign replays every live session of a bundle and reports the benign
// axis.
func runBenign(b *benign.Bundle, ref *Reference, base []telemetry.Event, into string,
	ambient *passResult, mutate int, perturbs []string, seed int64, now time.Time) (*BenignReport, []PerturbBenign, error) {

	anchor, err := DefaultAnchor(base)
	if err != nil {
		return nil, nil, err
	}
	digests := make(map[string]string, len(ref.Rules))
	for _, r := range ref.Rules {
		d, derr := benign.RuleDigest(r)
		if derr != nil {
			return nil, nil, derr
		}
		digests[r.ID] = d
	}
	live, expired := b.Live(now)
	if len(live) == 0 {
		return nil, nil, fmt.Errorf("every session in the bundle has expired; a baseline nobody " +
			"vouches for any longer measures nothing — renew them, or capture the workflows again")
	}
	rep := &BenignReport{Bundle: b.Digest, Signer: b.Signer, Policy: b.Manifest.Policy, Caveat: benignCaveat}
	for _, s := range expired {
		rep.Expired = append(rep.Expired, s.Name)
	}
	type tally struct{ k, n int }
	var perturbed []PerturbBenign
	lateness := latenessHistogram(base).quantile(0.99)
	reads := readFields(ref)
	perRule, perClass := map[string]*tally{}, map[string]*tally{}
	gapWhy, gapCount := map[string]string{}, map[string]int{}
	var mk, mn, k, n int
	for _, s := range live {
		if s.Expires.Sub(now) <= BenignSoon {
			rep.Expiring = append(rep.Expiring, s.Name)
		}
		checked := b.Checked(s)
		measurable, unmeasurable := map[string]bool{}, map[string]bool{}
		for _, r := range ref.Rules {
			if !benign.Reads(r, s) {
				continue
			}
			if why := benign.Unmeasurable(r, digests[r.ID], s, checked); why != "" {
				unmeasurable[r.ID] = true
				gapCount[r.ID]++
				if gapWhy[r.ID] == "" {
					gapWhy[r.ID] = why
				}
				continue
			}
			measurable[r.ID] = true
		}
		dropped := map[string]bool{}
		for _, f := range s.Dropped {
			dropped[f] = true
		}
		for _, c := range ref.Corrs {
			reads, blind := false, false
			for _, id := range c.Rules {
				reads = reads || measurable[id] || unmeasurable[id]
				blind = blind || unmeasurable[id]
			}
			for _, f := range append(append([]string{}, c.GroupBy...), c.Field) {
				blind = blind || (f != "" && dropped[f])
			}
			switch {
			case !reads:
			case blind:
				unmeasurable[c.ID] = true
				gapCount[c.ID]++
				if gapWhy[c.ID] == "" {
					gapWhy[c.ID] = "watches a rule that cannot be measured on the session, or groups by a field it does not carry"
				}
			default:
				measurable[c.ID] = true
			}
		}
		row := BenignSession{Name: s.Name, Class: s.Class, Digest: s.Digest, Unmeasurable: keys(unmeasurable)}
		if len(measurable) == 0 {
			row.Outcome = BenignUnread
			rep.Unread++
			rep.Sessions = append(rep.Sessions, row)
			continue
		}
		events := shiftTo(b.Events[s.Name], anchor)
		res, err := replaySession(base, events, ref, filepath.Join(into, "benign--"+sanitize(s.Name)))
		if err != nil {
			return nil, nil, fmt.Errorf("benign session %s: %w", s.Name, err)
		}
		fired := map[string]bool{}
		for id := range fires(res, ambient) {
			if measurable[id] {
				fired[id] = true
			}
		}
		row.Fired = keys(fired)
		row.Outcome = BenignQuiet
		if len(fired) > 0 {
			row.Outcome = BenignFires
			k++
		}
		n++
		if perClass[s.Class] == nil {
			perClass[s.Class] = &tally{}
		}
		perClass[s.Class].n++
		if len(fired) > 0 {
			perClass[s.Class].k++
		}
		for id := range measurable {
			if perRule[id] == nil {
				perRule[id] = &tally{}
			}
			perRule[id].n++
			if fired[id] {
				perRule[id].k++
			}
		}
		if mutate > 0 {
			variants, _ := mutateSession(s.Name, events, mutate)
			vk := 0
			for i, v := range variants {
				vres, verr := replaySession(base, v, ref,
					filepath.Join(into, fmt.Sprintf("benign--%s--m%d", sanitize(s.Name), i+1)))
				if verr != nil {
					return nil, nil, verr
				}
				for id := range fires(vres, ambient) {
					if measurable[id] {
						vk++
						break
					}
				}
			}
			if len(variants) > 0 {
				row.Mutated = bound(vk, len(variants))
				mk += vk
				mn += len(variants)
			}
		}
		for _, kind := range perturbs {
			pev, note := perturb(kind, s.Name, seed, events, lateness, reads)
			pres, perr := replaySession(base, pev, ref,
				filepath.Join(into, "perturbed", "benign--"+sanitize(s.Name)+"--"+kind))
			if perr != nil {
				return nil, nil, perr
			}
			pf := map[string]bool{}
			for id := range fires(pres, ambient) {
				if measurable[id] {
					pf[id] = true
				}
			}
			out := BenignQuiet
			if len(pf) > 0 {
				out = BenignFires
			}
			perturbed = append(perturbed, PerturbBenign{Session: s.Name, Kind: kind,
				Original: row.Outcome, Outcome: out, Fired: keys(pf), Note: note})
		}
		rep.Sessions = append(rep.Sessions, row)
	}
	rep.Fires = bound(k, n)
	if mn > 0 {
		rep.Mutated = bound(mk, mn)
	}
	for _, id := range sortedKeys(perRule) {
		t := perRule[id]
		rep.Rules = append(rep.Rules, BenignRule{Rule: id, Fires: bound(t.k, t.n)})
	}
	for _, c := range sortedKeys(perClass) {
		t := perClass[c]
		rep.Classes = append(rep.Classes, BenignClass{Class: c, Fires: bound(t.k, t.n)})
	}
	for _, id := range sortedKeys(gapCount) {
		rep.Gaps = append(rep.Gaps, BenignGap{Rule: id, Sessions: gapCount[id], Why: gapWhy[id]})
	}
	sort.Slice(rep.Sessions, func(i, j int) bool { return rep.Sessions[i].Name < rep.Sessions[j].Name })
	return rep, perturbed, nil
}

func keys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// summarizeBenign is the benign axis in words, for the scorecard's screen.
func summarizeBenign(r *BenignReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nbenign baseline (bundle %s…, %d session(s)):\n", r.Bundle[:12], len(r.Sessions))
	f := r.Fires
	fmt.Fprintf(&b, "  false positives on this estate's workflows: %d of %d session(s), %.1f%% (95%% Wilson %.1f%% to %.1f%%)\n",
		f.K, f.N, 100*f.Rate, 100*f.Low, 100*f.High)
	for _, s := range r.Sessions {
		switch s.Outcome {
		case BenignFires:
			fmt.Fprintf(&b, "    FIRES  %-28s %-12s %s\n", s.Name, s.Class, strings.Join(s.Fired, ", "))
		case BenignUnread:
			fmt.Fprintf(&b, "    unread %-28s %-12s no measurable rule reads it\n", s.Name, s.Class)
		}
	}
	for _, c := range r.Classes {
		fmt.Fprintf(&b, "  %-12s %d of %d\n", c.Class, c.Fires.K, c.Fires.N)
	}
	if r.Mutated != nil {
		fmt.Fprintf(&b, "  under mutation: %d of %d variant(s) fired (95%% Wilson %.1f%% to %.1f%%)\n",
			r.Mutated.K, r.Mutated.N, 100*r.Mutated.Low, 100*r.Mutated.High)
	}
	for _, g := range r.Gaps {
		fmt.Fprintf(&b, "  not measurable: %s on %d session(s): %s\n", g.Rule, g.Sessions, g.Why)
	}
	if len(r.Expired) > 0 {
		fmt.Fprintf(&b, "  expired, left out: %s\n", strings.Join(r.Expired, ", "))
	}
	if len(r.Expiring) > 0 {
		fmt.Fprintf(&b, "  expiring within 14 days: %s\n", strings.Join(r.Expiring, ", "))
	}
	return b.String()
}
