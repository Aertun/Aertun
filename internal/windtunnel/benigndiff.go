// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The benign axis of a diff. A rule change that catches an attack and fires
// on the estate's own backup job may still be the right change — but it is
// a decision, not a side effect. So every (session, rule) pair that fires in
// the later run and did not in the earlier one is a benign regression, and
// the gate fails on it unless somebody accepted that exact pair, with a
// reason and an expiry, in a file reviewed with the rule change. The way out
// the report names is either to narrow the rule, or — when the rule was
// right and the session was never benign — to revoke the session.
//
// Sessions are compared by content digest, so two bundles that share a
// session compare on it whatever they named it, and a session in only one
// run is named rather than read as a transition.

// The kinds a benign transition comes to.
const (
	BenignRegression = "benign-regression"
	BenignFix        = "benign-fix"
	BenignAccepted   = "benign-accepted"
)

// MaxAcceptances bounds an acceptance file, and AcceptanceLife how far ahead
// one may expire: an accepted trade-off is a decision to revisit, not a
// standing exception.
const (
	MaxAcceptances = 1000
	AcceptanceLife = 180 * 24 * time.Hour
)

// Acceptance is one accepted benign regression: this rule may fire on this
// session, because of this, until then.
type Acceptance struct {
	Session string    `json:"session"`
	Rule    string    `json:"rule"`
	Reason  string    `json:"reason"`
	By      string    `json:"by"`
	Expires time.Time `json:"expires"`
}

var (
	acceptSession = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	acceptRule    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

// ReadAcceptances reads an acceptance file: a JSON array, strict, bounded,
// each entry naming a session and a rule by their exact shapes, a reason,
// who accepted it, and an expiry no further than AcceptanceLife from now.
func ReadAcceptances(body []byte, now time.Time) ([]Acceptance, error) {
	var out []Acceptance
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("an acceptance file is a JSON array of {session, rule, reason, by, expires}: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("an acceptance file holds one array")
	}
	if len(out) > MaxAcceptances {
		return nil, fmt.Errorf("an acceptance file holds at most %d entries", MaxAcceptances)
	}
	for i, a := range out {
		switch {
		case !acceptSession.MatchString(a.Session) || !acceptRule.MatchString(a.Rule):
			return nil, fmt.Errorf("acceptance %d names a session and a rule by their ids", i+1)
		case strings.TrimSpace(a.Reason) == "" || len(a.Reason) > 500:
			return nil, fmt.Errorf("acceptance %d gives a reason, in at most 500 characters", i+1)
		case strings.TrimSpace(a.By) == "" || len(a.By) > 128:
			return nil, fmt.Errorf("acceptance %d says who accepted it", i+1)
		case a.Expires.IsZero() || a.Expires.Sub(now) > AcceptanceLife:
			return nil, fmt.Errorf("acceptance %d expires, and no more than %d days from now: an "+
				"accepted false positive is a decision to revisit", i+1, int(AcceptanceLife.Hours()/24))
		}
	}
	return out, nil
}

// BenignDiff is one (session, rule) pair that moved.
type BenignDiff struct {
	Session string `json:"session"`
	Class   string `json:"class"`
	Rule    string `json:"rule"`
	Kind    string `json:"kind"`
	// Reason is the acceptance's, for an accepted regression.
	Reason string `json:"reason,omitempty"`
}

// BenignDiffReport is the benign axis of a diff.
type BenignDiffReport struct {
	From *RateBound `json:"from"`
	To   *RateBound `json:"to"`
	// Compared is how many sessions both runs measured.
	Compared int          `json:"compared"`
	Pairs    []BenignDiff `json:"pairs,omitempty"`
	// OnlyFrom and OnlyTo name the sessions only one run carried.
	OnlyFrom []string `json:"only_earlier,omitempty"`
	OnlyTo   []string `json:"only_later,omitempty"`
	// ExpiredAcceptances name acceptances past their expiry, ignored.
	ExpiredAcceptances []string `json:"expired_acceptances,omitempty"`
	Regressions        int      `json:"regressions"`
	Fixes              int      `json:"fixes"`
	Accepted           int      `json:"accepted"`
	// BundleChanged says the two runs replayed different bundles: the pairs
	// are over the sessions they share.
	BundleChanged bool `json:"bundle_changed"`
}

func diffBenign(from, to *BenignReport) *BenignDiffReport {
	rep := &BenignDiffReport{From: from.Fires, To: to.Fires, BundleChanged: from.Bundle != to.Bundle}
	old := map[string]BenignSession{}
	for _, s := range from.Sessions {
		old[s.Digest] = s
	}
	now := map[string]bool{}
	for _, n := range to.Sessions {
		now[n.Digest] = true
		o, ok := old[n.Digest]
		if !ok {
			rep.OnlyTo = append(rep.OnlyTo, n.Name)
			continue
		}
		if o.Outcome == BenignUnread || n.Outcome == BenignUnread {
			continue
		}
		rep.Compared++
		was, is := set(o.Fired), set(n.Fired)
		for _, r := range n.Fired {
			if !was[r] {
				rep.Pairs = append(rep.Pairs, BenignDiff{Session: n.Name, Class: n.Class, Rule: r, Kind: BenignRegression})
				rep.Regressions++
			}
		}
		unmeasured := set(n.Unmeasurable)
		for _, r := range o.Fired {
			// A rule that stopped firing because it can no longer be
			// measured on the session is not a fix; it is a blind spot.
			if !is[r] && !unmeasured[r] {
				rep.Pairs = append(rep.Pairs, BenignDiff{Session: n.Name, Class: n.Class, Rule: r, Kind: BenignFix})
				rep.Fixes++
			}
		}
	}
	for _, o := range from.Sessions {
		if !now[o.Digest] {
			rep.OnlyFrom = append(rep.OnlyFrom, o.Name)
		}
	}
	sort.Slice(rep.Pairs, func(i, j int) bool {
		if rep.Pairs[i].Session != rep.Pairs[j].Session {
			return rep.Pairs[i].Session < rep.Pairs[j].Session
		}
		return rep.Pairs[i].Rule < rep.Pairs[j].Rule
	})
	sort.Strings(rep.OnlyFrom)
	sort.Strings(rep.OnlyTo)
	return rep
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Accept turns each benign regression a live acceptance names into an
// accepted one, and names the acceptances that have expired.
func (d *DiffReport) Accept(acc []Acceptance, now time.Time) {
	if d.Benign == nil {
		return
	}
	live := map[string]Acceptance{}
	for _, a := range acc {
		if !now.Before(a.Expires) {
			d.Benign.ExpiredAcceptances = append(d.Benign.ExpiredAcceptances,
				a.Session+" / "+a.Rule+" (expired "+a.Expires.UTC().Format("2006-01-02")+")")
			continue
		}
		live[a.Session+"\x00"+a.Rule] = a
	}
	for i, p := range d.Benign.Pairs {
		if p.Kind != BenignRegression {
			continue
		}
		if a, ok := live[p.Session+"\x00"+p.Rule]; ok {
			d.Benign.Pairs[i].Kind = BenignAccepted
			d.Benign.Pairs[i].Reason = a.Reason + " (" + a.By + ", until " + a.Expires.UTC().Format("2006-01-02") + ")"
			d.Benign.Regressions--
			d.Benign.Accepted++
		}
	}
	sort.Strings(d.Benign.ExpiredAcceptances)
}

func summarizeBenignDiff(b *BenignDiffReport) string {
	var s strings.Builder
	fmt.Fprintf(&s, "  benign baseline: %d of %d session(s) fired → %d of %d; compared on %d shared session(s)\n",
		b.From.K, b.From.N, b.To.K, b.To.N, b.Compared)
	if b.BundleChanged {
		s.WriteString("    the two runs replayed different bundles; the pairs below are over the sessions both carried\n")
	}
	for _, p := range b.Pairs {
		switch p.Kind {
		case BenignAccepted:
			fmt.Fprintf(&s, "    %-28s %-12s %s accepted: %s\n", p.Session, p.Class, p.Rule, p.Reason)
		default:
			fmt.Fprintf(&s, "    %-28s %-12s %s (%s)\n", p.Session, p.Class, p.Rule, p.Kind)
		}
	}
	if len(b.OnlyFrom) > 0 {
		fmt.Fprintf(&s, "    only in the earlier run: %s\n", strings.Join(b.OnlyFrom, ", "))
	}
	if len(b.OnlyTo) > 0 {
		fmt.Fprintf(&s, "    only in the later run: %s\n", strings.Join(b.OnlyTo, ", "))
	}
	for _, e := range b.ExpiredAcceptances {
		fmt.Fprintf(&s, "    acceptance ignored, expired: %s\n", e)
	}
	if b.Regressions > 0 {
		s.WriteString(hang("    ", "each benign regression is a rule that now fires on a workflow "+
			"this estate vouched for: narrow the rule, or accept the pair with a reason and an "+
			"expiry (windtunnel diff --accept FILE), or — if the rule was right and the session "+
			"was never benign — revoke the session (aertun benign revoke NAME)"))
	}
	return s.String()
}
