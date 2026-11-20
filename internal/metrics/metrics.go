// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package metrics is the program's own telemetry, in the Prometheus text
// exposition format (version 0.0.4), written by hand.
//
// Counters are kept as they happen; gauges are read when scraped, from the
// thing they describe, so a gauge is never a copy that drifted. Every
// label value comes from a closed set the caller fixes, never from a
// request: a label taken from input is a way to grow the scrape without
// bound, and to write into somebody's dashboard.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds metrics by name.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]*metric
}

type metric struct {
	name, help, kind string
	// counters by their rendered label set, the map guarded by mu
	mu     sync.Mutex
	values map[string]*atomic.Uint64
	// gauge is read at scrape time and returns values by label set
	gauge func() []Sample
}

// Sample is one gauge value and its labels.
type Sample struct {
	Labels []Label
	Value  float64
}

// Label is one label pair.
type Label struct{ Name, Value string }

// New returns an empty registry.
func New() *Registry { return &Registry{metrics: map[string]*metric{}} }

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func (r *Registry) add(m *metric) {
	if !validName(m.name) {
		panic("metrics: invalid name " + m.name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.metrics[m.name]; dup {
		panic("metrics: registered twice: " + m.name)
	}
	r.metrics[m.name] = m
}

// Counter is a monotonically increasing count, by label values.
type Counter struct {
	m      *metric
	labels []string
}

// Counter registers a counter with the label names given.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	for _, l := range labels {
		if !validName(l) {
			panic("metrics: invalid label " + l)
		}
	}
	m := &metric{name: name, help: help, kind: "counter", values: map[string]*atomic.Uint64{}}
	r.add(m)
	return &Counter{m: m, labels: labels}
}

// Add adds n under the label values, given in the order the labels were.
func (c *Counter) Add(n uint64, values ...string) {
	if len(values) != len(c.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values", c.m.name, len(c.labels)))
	}
	pairs := make([]Label, len(values))
	for i, v := range values {
		pairs[i] = Label{c.labels[i], v}
	}
	key := render(pairs)
	c.m.mu.Lock()
	v, ok := c.m.values[key]
	if !ok {
		v = &atomic.Uint64{}
		c.m.values[key] = v
	}
	c.m.mu.Unlock()
	v.Add(n)
}

// Inc adds one.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Gauge registers a gauge read by f at scrape time.
func (r *Registry) Gauge(name, help string, f func() []Sample) {
	r.add(&metric{name: name, help: help, kind: "gauge", gauge: f})
}

// One is a gauge with one unlabelled value.
func One(v float64) []Sample { return []Sample{{Value: v}} }

func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func render(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = l.Name + `="` + escape(l.Value) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func value(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// WriteTo writes every metric, sorted by name and then by label set, so
// two scrapes of the same state are the same bytes.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	sort.Strings(names)
	type line struct{ labels, value string }
	type block struct {
		m     *metric
		lines []line
	}
	var blocks []block
	for _, n := range names {
		m := r.metrics[n]
		b := block{m: m}
		if m.gauge == nil {
			m.mu.Lock()
			for k, v := range m.values {
				b.lines = append(b.lines, line{k, strconv.FormatUint(v.Load(), 10)})
			}
			m.mu.Unlock()
		}
		blocks = append(blocks, b)
	}
	r.mu.Unlock()
	// Gauges are read outside the lock: reading one may take time, and a
	// counter must not wait for it.
	for i := range blocks {
		if blocks[i].m.gauge == nil {
			continue
		}
		for _, s := range blocks[i].m.gauge() {
			blocks[i].lines = append(blocks[i].lines, line{render(s.Labels), value(s.Value)})
		}
	}
	var b strings.Builder
	for _, bl := range blocks {
		sort.Slice(bl.lines, func(i, j int) bool { return bl.lines[i].labels < bl.lines[j].labels })
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", bl.m.name,
			strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(bl.m.help), bl.m.name, bl.m.kind)
		for _, l := range bl.lines {
			fmt.Fprintf(&b, "%s%s %s\n", bl.m.name, l.labels, l.value)
		}
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// ContentType is the exposition format's media type.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"
