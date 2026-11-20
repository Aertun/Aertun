// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/detect"
)

// Skip is a rule that did not come across, and why.
type Skip struct {
	Title string `json:"title"`
	What  string `json:"what"`
	Why   string `json:"why"`
	// Ours says the gap is in this implementation rather than in the rule.
	// Two different lists for two different people: one is work for
	// whoever maintains this, the other is work for whoever wrote the rule.
	Ours bool `json:"ours"`
}

// Report is what happened to a library of rules.
type Report struct {
	Rules []detect.Rule `json:"-"`
	// Bare are the same rules before any global filter was added: what the
	// library would detect with its exceptions taken away, so a caller can
	// show what each exception costs.
	Bare []detect.Rule `json:"-"`
	// Filters are the library's global filters and what became of each.
	Filters []FilterReport `json:"filters,omitempty"`
	Skipped []Skip         `json:"skipped,omitempty"`
	// Loud names rules that claim high or critical and say their false
	// positives are unknown.
	Loud []string `json:"loud,omitempty"`
	Read int      `json:"read"`
}

// Unproven is how many imported rules nothing has shown can fire.
//
// All of them, always, and that is the point rather than a bug. Sigma has
// no place to record an event a rule is asserted to match, so a library of
// three thousand community rules arrives as three thousand rules that have
// never been demonstrated to do anything. internal/detect refuses to load
// one, quoting the finding that between 13 and 18 percent of deployed rules
// in this industry never fire under any input.
//
// This is the most useful thing an import can tell somebody, and no product
// that offers Sigma import says it.
func (r Report) Unproven() int {
	n := 0
	for _, c := range r.Rules {
		if len(c.Fixtures) == 0 {
			n++
		}
	}
	return n
}

// Ours is the skips caused by gaps in this implementation.
func (r Report) Ours() []Skip {
	var out []Skip
	for _, s := range r.Skipped {
		if s.Ours {
			out = append(out, s)
		}
	}
	return out
}

// Theirs is the skips caused by the rules themselves.
func (r Report) Theirs() []Skip {
	var out []Skip
	for _, s := range r.Skipped {
		if !s.Ours {
			out = append(out, s)
		}
	}
	return out
}

// Why summarises an import in a sentence.
func (r Report) Why() string {
	var says []string
	says = append(says, fmt.Sprintf("%d of %d compiled", len(r.Rules),
		r.Read))
	if n := len(r.Ours()); n > 0 {
		says = append(says, fmt.Sprintf("%d use something not implemented "+
			"here", n))
	}
	if n := len(r.Theirs()); n > 0 {
		says = append(says, fmt.Sprintf("%d are malformed", n))
	}
	if n := r.Unproven(); n > 0 {
		says = append(says, fmt.Sprintf("%d have no fixture and so cannot "+
			"be loaded until somebody writes one", n))
	}
	if n := len(r.Loud); n > 0 {
		says = append(says, fmt.Sprintf("%d claim high or critical with "+
			"unknown false positives", n))
	}
	return strings.Join(says, ", ")
}

// Import reads a library of Sigma rules and compiles what it can.
//
// Never partial within a rule: a rule either comes across whole or is
// listed as skipped with the construct named. Partial across a library is
// the whole point — a team importing three thousand rules needs the ones
// that worked and an accurate account of the ones that did not.
func Import(files map[string][]byte, pipe Pipeline) Report {
	var rep Report
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var logsources, titles, filterFiles []string
	var filters []Filter
	for _, name := range names {
		rules, fs, err := ReadAll(files[name])
		if err != nil {
			rep.Read++
			rep.Skipped = append(rep.Skipped, Skip{
				Title: name, What: "could not be read", Why: err.Error(),
			})
			continue
		}
		for _, f := range fs {
			filters = append(filters, f)
			filterFiles = append(filterFiles, name)
		}
		for _, r := range rules {
			rep.Read++
			c, err := r.CompileWith(pipe)
			if err != nil {
				var u *Unsupported
				rep.Skipped = append(rep.Skipped, Skip{
					Title: title(name, r), What: what(err),
					Why: err.Error(), Ours: errors.As(err, &u),
				})
				continue
			}
			if r.Loud() {
				rep.Loud = append(rep.Loud, title(name, r))
			}
			rep.Rules = append(rep.Rules, c)
			logsources = append(logsources, r.LogSource.Name())
			titles = append(titles, r.Title)
		}
	}
	rep.Bare = append([]detect.Rule(nil), rep.Rules...)
	if len(filters) > 0 {
		now := pipe.Now
		if now.IsZero() {
			now = time.Now()
		}
		rep.Filters = applyFilters(rep.Rules, logsources, titles, filters, filterFiles, pipe, now.UTC())
	}
	return rep
}

func title(file string, r Rule) string {
	if strings.TrimSpace(r.Title) != "" {
		return r.Title
	}
	return file
}

func what(err error) string {
	var u *Unsupported
	if errors.As(err, &u) {
		return u.What
	}
	return "did not compile"
}

// Gaps counts the constructs this implementation does not handle, most
// common first.
//
// The list somebody maintaining this works down, and the honest answer to
// "how much of Sigma do you support" — which is a percentage of a
// particular library rather than a property of the format.
func (r Report) Gaps() []string {
	by := map[string]int{}
	for _, s := range r.Ours() {
		by[s.What]++
	}
	type pair struct {
		what string
		n    int
	}
	var ps []pair
	for w, n := range by {
		ps = append(ps, pair{w, n})
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].n != ps[j].n {
			return ps[i].n > ps[j].n
		}
		return ps[i].what < ps[j].what
	})
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s (%d)", p.what, p.n))
	}
	return out
}
