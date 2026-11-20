// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"math"
	"strings"
	"sync"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	c := r.Counter("aertun_calls_total", "Calls answered,\nby outcome.", "outcome")
	c.Inc("ok")
	c.Add(2, "ok")
	c.Inc(`a"b\c`)
	r.Gauge("aertun_ready", "Whether it is ready.", func() []Sample { return One(1) })
	r.Gauge("aertun_odd", "Odd values.", func() []Sample {
		return []Sample{{Labels: []Label{{"k", "x"}}, Value: math.Inf(1)}, {Labels: []Label{{"k", "a"}}, Value: 0.5}}
	})
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP aertun_calls_total Calls answered,\nby outcome.
# TYPE aertun_calls_total counter
aertun_calls_total{outcome="a\"b\\c"} 1
aertun_calls_total{outcome="ok"} 3
# HELP aertun_odd Odd values.
# TYPE aertun_odd gauge
aertun_odd{k="a"} 0.5
aertun_odd{k="x"} +Inf
# HELP aertun_ready Whether it is ready.
# TYPE aertun_ready gauge
aertun_ready 1
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestConcurrentCounting(t *testing.T) {
	r := New()
	c := r.Counter("n_total", "n", "k")
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range 1000 {
				c.Inc([]string{"a", "b"}[i%2])
			}
			var b strings.Builder
			r.WriteTo(&b)
		}(i)
	}
	wg.Wait()
	var b strings.Builder
	r.WriteTo(&b)
	if !strings.Contains(b.String(), `n_total{k="a"} 25000`) || !strings.Contains(b.String(), `n_total{k="b"} 25000`) {
		t.Errorf("%s", b.String())
	}
}

func TestRefusals(t *testing.T) {
	for name, f := range map[string]func(){
		"bad name":    func() { New().Counter("1x", "h") },
		"bad label":   func() { New().Counter("x", "h", "a-b") },
		"twice":       func() { r := New(); r.Counter("x", "h"); r.Gauge("x", "h", nil) },
		"arity":       func() { New().Counter("x", "h", "a").Inc() },
		"empty label": func() { New().Counter("x", "h", "") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic", name)
				}
			}()
			f()
		}()
	}
}
