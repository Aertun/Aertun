// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/detect"
)

// Sigma global filters (specification v2.1.0): one document of tuning
// applied to the rules it names, so that a benign thing which trips many
// rules is excluded once rather than in every rule.
//
// A filter is an exception, and exceptions are where detections quietly go
// blind: one added for last quarter's migration still suppresses this
// quarter's attack. The specification gives a filter no expiry, no owner and
// no approval. So this reader accepts four more keys, all optional, that
// any other Sigma tool ignores — expires, owner, ticket and approved_by —
// and refuses to apply a filter whose expiry has passed, saying so. A
// filter with no expiry is applied and counted as one that never expires,
// so the report names every exception nobody will revisit.
//
// It applies the way the specification says: the filter's condition is
// added to each named rule as "and not", only where the filter's log source
// is exactly the rule's. "rules: any" applies to every rule with that log
// source, and is reported as the broad exception it is.

// Filter is a Sigma global filter as written.
type Filter struct {
	Title       string    `json:"title"`
	ID          string    `json:"id,omitempty"`
	Description string    `json:"description,omitempty"`
	Date        string    `json:"date,omitempty"`
	Modified    string    `json:"modified,omitempty"`
	LogSource   LogSource `json:"logsource"`
	// Rules are the ids or titles of the rules it tunes; Any says every
	// rule with its log source.
	Rules []string `json:"rules,omitempty"`
	Any   bool     `json:"any,omitempty"`
	// Selections and Condition are the filter's detection, as a rule's.
	Selections map[string]any `json:"-"`
	Condition  string         `json:"condition"`
	// The lifecycle this reader adds: when the exception stops applying,
	// who answers for it, the change that explains it, and who agreed.
	Expires    time.Time `json:"expires,omitzero"`
	Owner      string    `json:"owner,omitempty"`
	Ticket     string    `json:"ticket,omitempty"`
	ApprovedBy string    `json:"approved_by,omitempty"`
}

// isFilter reports whether a document is a global filter rather than a rule.
func isFilter(d Doc) bool {
	_, has := d["filter"]
	_, rule := d["detection"]
	return has && !rule
}

func filterFromDoc(d Doc) (Filter, error) {
	f := Filter{Title: str(d["title"]), ID: str(d["id"]), Description: str(d["description"]),
		Date: str(d["date"]), Modified: str(d["modified"]), Owner: str(d["owner"]),
		Ticket: str(d["ticket"]), ApprovedBy: str(d["approved_by"])}
	if strings.TrimSpace(f.Title) == "" {
		return f, fmt.Errorf("a filter needs a title")
	}
	ls, ok := d["logsource"].(map[string]any)
	if !ok {
		return f, fmt.Errorf("%s: a filter needs a log source, which it must share exactly "+
			"with the rules it tunes", f.Title)
	}
	f.LogSource = LogSource{Category: str(ls["category"]), Product: str(ls["product"]),
		Service: str(ls["service"]), Definition: str(ls["definition"])}
	if e := str(d["expires"]); e != "" {
		t, err := time.Parse("2006-01-02", e)
		if err != nil {
			if t, err = time.Parse(time.RFC3339, e); err != nil {
				return f, fmt.Errorf("%s: expires is a date (2006-01-02) or an RFC 3339 time", f.Title)
			}
		}
		f.Expires = t.UTC()
	}
	body, ok := d["filter"].(map[string]any)
	if !ok {
		return f, fmt.Errorf("%s: the filter block is a mapping of rules, selections and a condition", f.Title)
	}
	f.Selections = map[string]any{}
	for k, v := range body {
		switch k {
		case "rules":
			if s, isStr := v.(string); isStr && strings.EqualFold(strings.TrimSpace(s), "any") {
				f.Any = true
				continue
			}
			f.Rules = strs(v)
		case "condition":
			f.Condition = str(v)
		default:
			f.Selections[k] = v
		}
	}
	if !f.Any && len(f.Rules) == 0 {
		return f, fmt.Errorf("%s: a filter names the rules it tunes (or says any)", f.Title)
	}
	if strings.TrimSpace(f.Condition) == "" || len(f.Selections) == 0 {
		return f, fmt.Errorf("%s: a filter has a selection and a condition", f.Title)
	}
	return f, nil
}

// ReadAll parses a Sigma file into its rules and its global filters.
func ReadAll(in []byte) ([]Rule, []Filter, error) {
	docs, err := Parse(in)
	if err != nil {
		return nil, nil, err
	}
	var rules []Rule
	var filters []Filter
	for i, d := range docs {
		if isFilter(d) {
			f, err := filterFromDoc(d)
			if err != nil {
				return nil, nil, fmt.Errorf("document %d: %w", i+1, err)
			}
			filters = append(filters, f)
			continue
		}
		r, err := fromDoc(d)
		if err != nil {
			return nil, nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		rules = append(rules, r)
	}
	return rules, filters, nil
}

// Predicate is the filter's condition, compiled as a rule's would be.
func (f Filter) Predicate(pipe Pipeline) (detect.Predicate, error) {
	sels := map[string]detect.Predicate{}
	names := make([]string, 0, len(f.Selections))
	for name, body := range f.Selections {
		p, err := selection(pipe, f.Title, name, body)
		if err != nil {
			return detect.Predicate{}, err
		}
		sels[name] = p
		names = append(names, name)
	}
	sort.Strings(names)
	return condition(f.Title, f.Condition, sels, names)
}

// FilterReport is what became of one filter.
type FilterReport struct {
	Title string `json:"title"`
	ID    string `json:"id,omitempty"`
	File  string `json:"file"`
	// Applied are the rules it was added to; Unmatched the ones it named
	// that no imported rule with its log source answers to.
	Applied   []string `json:"applied,omitempty"`
	Unmatched []string `json:"unmatched,omitempty"`
	// Any says it tuned every rule with its log source.
	Any bool `json:"any,omitempty"`
	// Expired says it was not applied because its expiry has passed;
	// NoExpiry that it never expires.
	Expired    bool   `json:"expired,omitempty"`
	NoExpiry   bool   `json:"no_expiry,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Ticket     string `json:"ticket,omitempty"`
	ApprovedBy string `json:"approved_by,omitempty"`
	// Refused says why it could not be compiled, when it could not.
	Refused string `json:"refused,omitempty"`
	// Source and Predicate are the compiled filter, for a caller that
	// tests which events it takes out; set only when it was applied.
	Source    string           `json:"-"`
	Predicate detect.Predicate `json:"-"`
}

// applyFilters adds each live filter to the rules it names, as "and not",
// where the log sources match exactly; the rules are changed in place.
func applyFilters(rules []detect.Rule, logsources []string, titles []string, filters []Filter,
	files []string, pipe Pipeline, now time.Time) []FilterReport {

	var out []FilterReport
	for i, f := range filters {
		rep := FilterReport{Title: f.Title, ID: f.ID, File: files[i], Any: f.Any, Owner: f.Owner,
			Ticket: f.Ticket, ApprovedBy: f.ApprovedBy, NoExpiry: f.Expires.IsZero()}
		if !f.Expires.IsZero() {
			rep.Expires = f.Expires.Format(time.RFC3339)
		}
		if !f.Expires.IsZero() && !now.Before(f.Expires) {
			rep.Expired = true
			out = append(out, rep)
			continue
		}
		pred, err := f.Predicate(pipe)
		if err != nil {
			rep.Refused = err.Error()
			out = append(out, rep)
			continue
		}
		wanted := map[string]bool{}
		for _, r := range f.Rules {
			wanted[strings.ToLower(strings.TrimSpace(r))] = true
		}
		found := map[string]bool{}
		for j := range rules {
			if logsources[j] != f.LogSource.Name() {
				continue
			}
			id, title := strings.ToLower(rules[j].ID), strings.ToLower(titles[j])
			if !f.Any && !wanted[id] && !wanted[title] {
				continue
			}
			found[id], found[title] = true, true
			not := pred
			rules[j].When = detect.Predicate{All: []detect.Predicate{rules[j].When, {Not: &not}}}
			rep.Applied = append(rep.Applied, rules[j].ID)
		}
		for _, r := range f.Rules {
			if !found[strings.ToLower(strings.TrimSpace(r))] {
				rep.Unmatched = append(rep.Unmatched, r)
			}
		}
		sort.Strings(rep.Applied)
		if len(rep.Applied) > 0 {
			rep.Source, rep.Predicate = f.LogSource.Name(), pred
		}
		out = append(out, rep)
	}
	return out
}
