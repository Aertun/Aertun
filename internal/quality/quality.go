// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package quality keeps a ledger of how each source's data arrives, a day
// at a time, and judges each day against the source's own recent past.
//
// # Why a ledger
//
// A detection that matched nothing, and a proof that something stopped,
// both rest on silence, and silence means something only from a source that
// was delivering whole, on time and in its usual shape. A connector whose
// parser drops a field converts cleanly and matches nothing forever; an
// agent whose clock runs ahead files events where no window looks; a
// source that falls to a tenth of its volume looks, to everything
// downstream, like a quiet week. None of these is an error at ingest.
//
// # What a day records
//
// Days are by arrival (the spool's own partition, in UTC), so a finished
// day never changes: whatever arrives later belongs to a later day. For
// each source and day:
//   - events, and duplicates (the same event, apart from when it arrived);
//   - lateness, as a log2 histogram of arrival minus event time;
//   - events stamped ahead of their arrival, and events arriving a week or
//     more after they happened;
//   - how many events carried each field a rule may read.
//
// # How a day is judged
//
// Against the same source's previous days, never against a global norm: a
// daily export and a streaming agent have nothing in common. With fewer
// than three earlier days to compare, a day is "learning". A day is
// degraded when it is silent or under half the usual volume (unless it was
// as quiet on the same weekday a week before), when a field
// nearly every earlier event carried is missing from most of today's, when
// it is four times later than usual and an hour or more, when more than one
// event in a hundred is stamped ahead of its arrival, or when more than one
// in twenty is a duplicate, or when the mapping turned away more than one
// record in twenty. A spike in volume, or a backfill of old events,
// is a notice: it says something changed, and takes nothing away from what
// the source's silence means.
//
// A day is a witness when its silence can count as evidence that nothing
// happened: judged (not learning), not degraded, and with no event from a
// sampler that drops spans by design (OpenTelemetry's consistent
// probability sampling writes its threshold into the tracestate). A
// sampled source is a notice every day, never a finding, and never a
// witness.
package quality

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// Thresholds, fixed so a judgement can be explained and repeated.
const (
	MinBaselineDays = 3
	// MinVolume is the usual daily volume below which volume is not judged:
	// a source that sends five events a day has no meaningful "half".
	MinVolume = 20
	DropRatio = 0.5
	// SpikeRatio and MinSpike: four times the usual, and at least 100.
	SpikeRatio = 4.0
	MinSpike   = 100
	// A field is usual at 90% of earlier events and lost under 50% today.
	UsualField = 0.9
	LostField  = 0.5
	// Late: the 95th percentile four times the usual, and at least an hour.
	LateFactor = 2 // log2 buckets: two buckets is four times
	MinLate    = time.Hour
	AheadSkew  = 5 * time.Minute
	AheadRatio = 0.01
	Stale      = 7 * 24 * time.Hour
	StaleRatio = 0.1
	DupRatio   = 0.05
	// MaxDistinct bounds the events a day remembers to find duplicates;
	// past it, duplicates are not counted and the day says so.
	MaxDistinct = 2_000_000
	// MaxFields bounds the raw fields tracked per source and day.
	MaxFields = 200
	// LateBuckets is the histogram's width: the last bucket holds delays of
	// 2^32 seconds (136 years) and more, and its bound still fits a Duration.
	LateBuckets = 34
)

// Day is one source's arrivals on one UTC day.
type Day struct {
	Source string `json:"source"`
	Date   string `json:"date"`
	Events int    `json:"events"`
	// Duplicates is how many events repeated one already seen that day;
	// DupUnmeasured says the day was too large to count them.
	Duplicates    int  `json:"duplicates"`
	DupUnmeasured bool `json:"dup_unmeasured,omitempty"`
	Ahead         int  `json:"ahead"`
	Stale         int  `json:"stale"`
	// Sampled counts events from a sampler that drops some by design (a
	// non-zero OpenTelemetry sampling threshold).
	Sampled int `json:"sampled,omitempty"`
	// Refused counts the records the source's mapping turned away that
	// day (internal/deadletter): set when the day is judged, never kept.
	Refused int `json:"refused,omitempty"`
	// Late is a histogram of arrival minus event time, for events less
	// than a week late: bucket n holds delays under 2^n seconds and at
	// least 2^(n-1). Older arrivals are Stale.
	Late [LateBuckets]int `json:"late"`
	// Fields counts the events that carried each field.
	Fields map[string]int `json:"fields"`
}

// Accumulator builds days from events.
type Accumulator struct {
	days map[string]*Day
	seen map[string]map[uint64]struct{}
}

// NewAccumulator is an empty one.
func NewAccumulator() *Accumulator {
	return &Accumulator{days: map[string]*Day{}, seen: map[string]map[uint64]struct{}{}}
}

// DateOf is the UTC day an arrival falls on.
func DateOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

// fingerprint is the event without its arrival: two deliveries of one
// event fingerprint alike.
func fingerprint(e telemetry.Event) uint64 {
	e.Received = time.Time{}
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return binary.BigEndian.Uint64(sum[:8])
}

func bucket(d time.Duration) int {
	n := 0
	for secs := int64(d / time.Second); secs > 0; secs >>= 1 {
		n++
	}
	return min(n, LateBuckets-1)
}

// Add counts one event on the day it arrived.
func (a *Accumulator) Add(e telemetry.Event) {
	date := DateOf(e.Received)
	key := e.Source + "\x00" + date
	d, ok := a.days[key]
	if !ok {
		d = &Day{Source: e.Source, Date: date, Fields: map[string]int{}}
		a.days[key] = d
		a.seen[key] = map[uint64]struct{}{}
	}
	d.Events++
	if seen := a.seen[key]; !d.DupUnmeasured {
		fp := fingerprint(e)
		if _, dup := seen[fp]; dup {
			d.Duplicates++
		} else if len(seen) >= MaxDistinct {
			d.DupUnmeasured, d.Duplicates = true, 0
			a.seen[key] = nil
		} else {
			seen[fp] = struct{}{}
		}
	}
	delay := e.Received.Sub(e.Time)
	switch {
	case e.Time.After(e.Received.Add(AheadSkew)):
		d.Ahead++
	case delay >= Stale:
		// A backfill: counted on its own, and kept out of the lateness a
		// live feed is judged by.
		d.Stale++
	case delay >= 0:
		d.Late[bucket(delay)]++
	default:
		d.Late[0]++
	}
	if th := e.Raw["sampling_threshold"]; strings.TrimLeft(th, "0") != "" {
		d.Sampled++
	}
	for _, f := range fieldsOf(e) {
		if _, tracked := d.Fields[f]; tracked || len(d.Fields) < MaxFields {
			d.Fields[f]++
		}
	}
}

// fieldsOf names the fields an event carries that a rule may read.
func fieldsOf(e telemetry.Event) []string {
	var out []string
	for name, set := range map[string]bool{"actor": e.Actor.Value != "", "target": e.Target.Value != "",
		"device": e.Device.Value != "", "observables": len(e.Observables) > 0, "message": e.Message != ""} {
		if set {
			out = append(out, name)
		}
	}
	for k, v := range e.Raw {
		if v != "" {
			out = append(out, "raw."+k)
		}
	}
	return out
}

// Days returns what was counted, by source and then date.
func (a *Accumulator) Days() []Day {
	out := make([]Day, 0, len(a.days))
	for _, d := range a.days {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Date < out[j].Date
	})
	return out
}

// Quantile is the upper bound of the bucket holding the q-th fraction of
// a day's on-time events (0 when there were none).
func (d Day) Quantile(q float64) time.Duration {
	total := 0
	for _, n := range d.Late {
		total += n
	}
	if total == 0 {
		return 0
	}
	want := int(q*float64(total) + 0.5)
	run := 0
	for i, n := range d.Late {
		run += n
		if run >= want && n > 0 {
			return time.Duration(int64(1)<<i) * time.Second
		}
	}
	return time.Duration(int64(1)<<(LateBuckets-1)) * time.Second
}

func (d Day) lateBucket(q float64) int {
	b := 0
	for v := d.Quantile(q); v > time.Second; v /= 2 {
		b++
	}
	return b
}

// Status of a judged day.
const (
	OK       = "ok"
	Learning = "learning"
	Notice   = "notice"
	Degraded = "degraded"
)

// Reason is one finding about a day.
type Reason struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	// Degrades says the finding takes away from what the source's silence
	// means; a notice does not.
	Degrades bool `json:"degrades"`
}

// Verdict is a day judged.
type Verdict struct {
	Source  string   `json:"source"`
	Date    string   `json:"date"`
	Status  string   `json:"status"`
	Events  int      `json:"events"`
	Usual   int      `json:"usual"`
	Reasons []Reason `json:"reasons,omitempty"`
	// Witness says the source's silence that day can count as evidence
	// that nothing happened: judged, not degraded, and not sampled.
	Witness bool `json:"witness"`
}

func median(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[len(s)/2]
}

// Judge judges day against the earlier days given, which are the same
// source's, oldest first. Days with no arrivals are passed as zero days.
func Judge(day Day, earlier []Day) Verdict {
	v := Verdict{Source: day.Source, Date: day.Date, Events: day.Events, Status: OK}
	var vols []int
	baseEvents := 0
	fields := map[string]int{}
	var lates []int
	for _, d := range earlier {
		vols = append(vols, d.Events)
		baseEvents += d.Events
		for f, n := range d.Fields {
			fields[f] += n
		}
		if d.Events > 0 {
			lates = append(lates, d.lateBucket(0.95))
		}
	}
	v.Usual = median(vols)
	if len(earlier) < MinBaselineDays || baseEvents == 0 {
		v.Status = Learning
		return v
	}
	add := func(code string, degrades bool, format string, args ...any) {
		v.Reasons = append(v.Reasons, Reason{Code: code, Detail: fmt.Sprintf(format, args...), Degrades: degrades})
	}
	// A source quiet on the same weekday last week (a business system at
	// the weekend) is quiet by habit: a notice, not a degradation.
	habit := false
	if len(earlier) >= 7 {
		habit = float64(earlier[len(earlier)-7].Events) < DropRatio*float64(v.Usual)
	}
	switch {
	case day.Events == 0 && v.Usual >= MinVolume:
		add("silent", !habit, "no events, where %d a day is usual%s", v.Usual, habitNote(habit))
	case v.Usual >= MinVolume && float64(day.Events) < DropRatio*float64(v.Usual):
		add("volume-drop", !habit, "%d events, under half the usual %d%s", day.Events, v.Usual, habitNote(habit))
	case day.Events >= MinSpike && float64(day.Events) > SpikeRatio*float64(max(v.Usual, 1)):
		add("volume-spike", false, "%d events, over four times the usual %d", day.Events, v.Usual)
	}
	if day.Events >= MinVolume {
		var lost []string
		for f, n := range fields {
			if float64(n) >= UsualField*float64(baseEvents) && float64(day.Fields[f]) < LostField*float64(day.Events) {
				lost = append(lost, f)
			}
		}
		sort.Strings(lost)
		if len(lost) > 0 {
			add("field-lost", true, "carried by nearly every earlier event and by under half today: %s",
				strings.Join(lost, ", "))
		}
	}
	if day.Refused > 0 && float64(day.Refused) > DupRatio*float64(day.Events+day.Refused) {
		add("refused", true, "the mapping turned away %d of %d records (aertun telemetry dead-letter)",
			day.Refused, day.Events+day.Refused)
	}
	if day.Events > 0 && len(lates) > 0 {
		p95 := day.Quantile(0.95)
		if day.lateBucket(0.95) >= median(lates)+LateFactor && p95 >= MinLate {
			add("late", true, "the 95th percentile arrives %s after the event, four or more times the usual", p95)
		}
	}
	if day.Events > 0 {
		if float64(day.Ahead) > AheadRatio*float64(day.Events) {
			add("clock-ahead", true, "%d of %d events stamped more than %s after they arrived", day.Ahead, day.Events, AheadSkew)
		}
		if !day.DupUnmeasured && float64(day.Duplicates) > DupRatio*float64(day.Events) {
			add("duplicates", true, "%d of %d events delivered more than once", day.Duplicates, day.Events)
		}
		if float64(day.Stale) > StaleRatio*float64(day.Events) {
			add("backfill", false, "%d of %d events arrived a week or more after they happened", day.Stale, day.Events)
		}
		if day.Sampled > 0 {
			add("sampled", false, "%d of %d events come from a sampler that drops some by design, so its "+
				"silence is not evidence that nothing happened", day.Sampled, day.Events)
		}
	}
	for _, r := range v.Reasons {
		if r.Degrades {
			v.Status = Degraded
			break
		}
		v.Status = Notice
	}
	v.Witness = v.Status != Degraded && day.Sampled == 0
	return v
}

func habitNote(habit bool) string {
	if habit {
		return "; it was as quiet on the same day last week"
	}
	return ""
}

// History lines up one source's days from first to last date, inclusive,
// putting a zero day where nothing arrived.
func History(source string, have []Day, first, last string) ([]Day, error) {
	from, err := time.Parse("2006-01-02", first)
	if err != nil {
		return nil, err
	}
	to, err := time.Parse("2006-01-02", last)
	if err != nil {
		return nil, err
	}
	by := map[string]Day{}
	for _, d := range have {
		if d.Source == source {
			by[d.Date] = d
		}
	}
	var out []Day
	for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
		date := DateOf(t)
		d, ok := by[date]
		if !ok {
			d = Day{Source: source, Date: date, Fields: map[string]int{}}
		}
		out = append(out, d)
	}
	return out, nil
}
