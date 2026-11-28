// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
)

// WilsonMethod and WilsonConfidence are the interval every scorecard
// rate carries: internal/stats.Wilson at z for 95%.
const (
	WilsonMethod     = "wilson"
	WilsonConfidence = 0.95
)

// ScorecardRates are the rates a scorecard states with their counts and their
// interval: the aggregate miss rate, and every rate object (k, n, rate,
// wilson_low, wilson_high) anywhere in it, each named by its path. Counts
// a scorecard gives without an interval are left out rather than given
// one it did not state. card is the scorecard's JSON, already verified;
// digest is its SHA-256, by which each row names it; alias pseudonymises
// what a path would otherwise name, a benign session.
func ScorecardRates(card []byte, digest string, alias func(kind, v string) string) ([]OutcomeRow, error) {
	dec := json.NewDecoder(bytes.NewReader(card))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("the scorecard is not JSON: %w", err)
	}
	rows := []OutcomeRow{}
	var walk func(path string, v any) error
	walk = func(path string, v any) error {
		switch v := v.(type) {
		case map[string]any:
			if row, ok, err := rateAt(path, v); err != nil {
				return err
			} else if ok {
				row.Scorecard = digest
				rows = append(rows, row)
				return nil
			}
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				if err := walk(join(path, k), v[k]); err != nil {
					return err
				}
			}
		case []any:
			for i, item := range v {
				if err := walk(path+"["+label(item, i, alias)+"]", item); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("", doc); err != nil {
		return nil, err
	}
	return rows, nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// label names an element of a list by what it is about when it says so,
// and by its place otherwise. Scenarios, rules, faults, families,
// techniques and classes are named as the scorecard names them; a benign
// session, which is named by whoever captured it, by a pseudonym.
func label(item any, i int, alias func(kind, v string) string) string {
	if m, ok := item.(map[string]any); ok {
		for _, k := range []string{"id", "scenario", "rule", "fault", "family", "technique", "session", "name", "class"} {
			if s, ok := m[k].(string); ok && s != "" {
				if k == "session" || k == "name" {
					return alias("session", s)
				}
				return s
			}
		}
	}
	return strconv.Itoa(i)
}

// rateAt reads a rate object, or the aggregate's miss rate, at path.
func rateAt(path string, m map[string]any) (OutcomeRow, bool, error) {
	shape := func(k, n, rate, low, high string) (OutcomeRow, bool, error) {
		for _, f := range []string{k, n, rate, low, high} {
			if _, ok := m[f].(json.Number); !ok {
				return OutcomeRow{}, false, nil
			}
		}
		row := OutcomeRow{Measure: path, Method: WilsonMethod, Confidence: WilsonConfidence}
		var err error
		ints := []struct {
			f string
			p *int
		}{{k, &row.K}, {n, &row.N}}
		for _, x := range ints {
			v, perr := m[x.f].(json.Number).Int64()
			if perr != nil || v < 0 {
				return OutcomeRow{}, false, fmt.Errorf("%s: %s is not a count", path, x.f)
			}
			*x.p = int(v)
		}
		floats := []struct {
			f string
			p *float64
		}{{rate, &row.Rate}, {low, &row.Low}, {high, &row.High}}
		for _, x := range floats {
			if *x.p, err = m[x.f].(json.Number).Float64(); err != nil {
				return OutcomeRow{}, false, fmt.Errorf("%s: %s is not a number", path, x.f)
			}
		}
		// The interval is computed in floating point, and at 0 of n or n of n
		// its bound can land a rounding error to the wrong side of the rate.
		const eps = 1e-9
		if row.K > row.N || row.Low > row.Rate+eps || row.Rate > row.High+eps {
			return OutcomeRow{}, false, fmt.Errorf("%s: %d of %d with an interval of %g to %g "+
				"around %g does not hold together", path, row.K, row.N, row.Low, row.High, row.Rate)
		}
		return row, true, nil
	}
	if row, ok, err := shape("k", "n", "rate", "wilson_low", "wilson_high"); ok || err != nil {
		return row, ok, err
	}
	row, ok, err := shape("missed", "must_alert_scenarios", "miss_rate",
		"miss_rate_wilson_low", "miss_rate_wilson_high")
	if ok {
		row.Measure = join(path, "miss_rate")
	}
	return row, ok, err
}
