// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package quality

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

var day0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// usual is a day's ordinary traffic from one source: n events arriving a
// minute late, each carrying an actor and raw.user.
func usual(a *Accumulator, date time.Time, n int, mutate func(*telemetry.Event, int)) {
	for i := range n {
		at := date.Add(time.Duration(i) * time.Minute)
		e := telemetry.Event{Source: "okta/system-log", Time: at, Received: at.Add(time.Minute),
			Class: telemetry.ClassAuthentication, Actor: telemetry.ID{Issuer: "okta", Value: fmt.Sprint("u", i)},
			Raw: map[string]string{"user": fmt.Sprint("u", i), "ip": "203.0.113.9"}}
		if mutate != nil {
			mutate(&e, i)
		}
		a.Add(e)
	}
}

func judgeLast(t *testing.T, a *Accumulator, days int) Verdict {
	t.Helper()
	hist, err := History("okta/system-log", a.Days(), DateOf(day0), DateOf(day0.AddDate(0, 0, days-1)))
	if err != nil {
		t.Fatal(err)
	}
	return Judge(hist[len(hist)-1], hist[:len(hist)-1])
}

func reasons(v Verdict) string {
	var out []string
	for _, r := range v.Reasons {
		out = append(out, r.Code)
	}
	return strings.Join(out, ",")
}

func TestOrdinaryDayIsOK(t *testing.T) {
	a := NewAccumulator()
	for d := range 10 {
		usual(a, day0.AddDate(0, 0, d), 100, nil)
	}
	if v := judgeLast(t, a, 10); v.Status != OK || v.Usual != 100 {
		t.Errorf("%+v", v)
	}
}

func TestLearning(t *testing.T) {
	a := NewAccumulator()
	usual(a, day0, 100, nil)
	usual(a, day0.AddDate(0, 0, 1), 3, nil)
	if v := judgeLast(t, a, 2); v.Status != Learning {
		t.Errorf("%+v", v)
	}
}

// TestDegradations: each way a day goes wrong, alone, is named.
func TestDegradations(t *testing.T) {
	cases := map[string]struct {
		n      int
		mutate func(*telemetry.Event, int)
		want   string
		status string
	}{
		"silent":      {0, nil, "silent", Degraded},
		"volume drop": {30, nil, "volume-drop", Degraded},
		"spike":       {900, nil, "volume-spike", Notice},
		"field lost": {100, func(e *telemetry.Event, i int) {
			delete(e.Raw, "user")
		}, "field-lost", Degraded},
		"late": {100, func(e *telemetry.Event, i int) {
			e.Received = e.Time.Add(3 * time.Hour)
		}, "late", Degraded},
		"clock ahead": {100, func(e *telemetry.Event, i int) {
			if i%10 == 0 {
				e.Time = e.Received.Add(time.Hour)
			}
		}, "clock-ahead", Degraded},
		"duplicates": {100, func(e *telemetry.Event, i int) {
			if i%5 == 0 && i > 0 {
				e.Time, e.Actor.Value, e.Raw = e.Time.Add(-time.Minute), fmt.Sprint("u", i-1), map[string]string{"user": fmt.Sprint("u", i-1), "ip": "203.0.113.9"}
			}
		}, "duplicates", Degraded},
		"backfill": {100, func(e *telemetry.Event, i int) {
			if i%4 == 0 {
				e.Time = e.Received.Add(-10 * 24 * time.Hour)
			}
		}, "backfill", Notice},
	}
	for name, c := range cases {
		a := NewAccumulator()
		for d := range 9 {
			usual(a, day0.AddDate(0, 0, d), 100, nil)
		}
		usual(a, day0.AddDate(0, 0, 9), c.n, c.mutate)
		v := judgeLast(t, a, 10)
		if v.Status != c.status || !strings.Contains(reasons(v), c.want) {
			t.Errorf("%s: %s %s %+v", name, v.Status, reasons(v), v.Reasons)
		}
	}
}

// TestQuietByHabit: a source silent on the same weekday last week is
// quiet by habit, a notice.
func TestQuietByHabit(t *testing.T) {
	a := NewAccumulator()
	for d := range 14 {
		if d == 6 {
			continue // a week ago, nothing
		}
		if d < 13 {
			usual(a, day0.AddDate(0, 0, d), 100, nil)
		}
	}
	v := judgeLast(t, a, 14)
	if v.Status != Notice || reasons(v) != "silent" {
		t.Errorf("%+v", v)
	}
}

func TestQuantileAndDuplicatesBound(t *testing.T) {
	a := NewAccumulator()
	usual(a, day0, 100, nil)
	d := a.Days()[0]
	if q := d.Quantile(0.95); q != 64*time.Second {
		t.Errorf("a minute late lands in the 64-second bucket, got %s", q)
	}
	if d.Duplicates != 0 || d.Fields["raw.user"] != 100 || d.Fields["actor"] != 100 {
		t.Errorf("%+v", d)
	}
}

// TestWitness: an ordinary day is a witness; a sampled one is a notice and
// not a witness; a degraded one or a learning one is not a witness.
func TestWitness(t *testing.T) {
	a := NewAccumulator()
	for d := range 9 {
		usual(a, day0.AddDate(0, 0, d), 100, nil)
	}
	if v := judgeLast(t, a, 9); !v.Witness {
		t.Errorf("an ordinary day: %+v", v)
	}
	usual(a, day0.AddDate(0, 0, 9), 100, func(e *telemetry.Event, i int) {
		e.Raw["sampling_threshold"] = "8"
	})
	if v := judgeLast(t, a, 10); v.Witness || v.Status != Notice || reasons(v) != "sampled" {
		t.Errorf("a sampled day: %+v", v)
	}
	b := NewAccumulator()
	usual(b, day0, 100, func(e *telemetry.Event, i int) { e.Raw["sampling_threshold"] = "0" })
	if d := b.Days()[0]; d.Sampled != 0 {
		t.Errorf("a threshold of zero keeps every span, and is not sampling: %d", d.Sampled)
	}
	if v := judgeLast(t, b, 1); v.Witness || v.Status != Learning {
		t.Errorf("a learning day: %+v", v)
	}
}
