// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mdr

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

// The audit log holds the commitment, written before any item is shown,
// and every run and notification, written as it is recorded. The plan file
// says what was drawn; the log says it was drawn first and run after.

const (
	// RanAction records that an item was run.
	RanAction = "mdr.ran"
	// NotifiedAction records the provider's notification about an item.
	NotifiedAction = "mdr.notified"
	// JoinHorizon is how long after a run a provider's alert in the event
	// store may be joined to it. It is the longest SLA a test can hold a
	// provider to, so anything later is late whatever the SLA; a later
	// notification can still be recorded by hand.
	JoinHorizon = proof.MaxMDRSLA
)

// Entry is an audit entry, by where it is in the chain.
type Entry struct {
	Seq  int64
	Hash string
	At   time.Time
}

func entryOf(e audit.Event) (Entry, bool) {
	at, err := time.Parse(time.RFC3339Nano, e.At)
	return Entry{Seq: e.Seq, Hash: e.Hash, At: at}, err == nil
}

// RanDetail is what a run's record says: the item and when it was run.
func RanDetail(plan string, n int, at time.Time) map[string]string {
	return map[string]string{"plan": plan, "item": strconv.Itoa(n),
		"at": at.UTC().Format(time.RFC3339Nano)}
}

// NotifiedDetail is what a notification's record says: the item, when the
// provider's notification came, the ticket or alert id it came as, and the
// source it was joined from when it was read from the event store.
func NotifiedDetail(plan string, n int, at time.Time, ref, source string) map[string]string {
	d := map[string]string{"plan": plan, "item": strconv.Itoa(n),
		"at": at.UTC().Format(time.RFC3339Nano), "ref": ref}
	if source != "" {
		d["source"] = source
	}
	return d
}

// Result is what the log records about a plan, checked.
type Result struct {
	// Commit is the entry that committed the plan.
	Commit Entry
	// Ran is when each item recorded as run was run, by item number.
	Ran map[int]time.Time
	// Notified is when the provider's notification about each item came.
	Notified map[int]time.Time
	// Refs are the ticket and alert ids already recorded, by the item each
	// was recorded for, so one alert is never counted for two items.
	Refs map[string]int
}

// commitments are the entries that committed a plan of this name.
func commitments(events []audit.Event, name string) []audit.Event {
	var out []audit.Event
	for _, e := range events {
		if e.Action == PlannedAction && e.Detail["plan"] == name {
			out = append(out, e)
		}
	}
	return out
}

// Committed reports whether the log already commits a plan of this name: a
// name, once committed, is never drawn again, so the log cannot hold two
// plans either of which a proof could be made on.
func Committed(events []audit.Event, name string) bool {
	return len(commitments(events, name)) > 0
}

// Verify checks that the log commits this plan, exactly once and before
// anything was run, and that every run and notification recorded for it is
// one a test can count, and reads them. It refuses, rather than counts
// around, anything that would make the test mean something else: a broken
// chain, a plan that is not the one committed, a record by somebody whose
// identity was not proved or by something that is not a person, a run
// before the commitment, before its item fell due or more than
// proof.MDRRunWithin after, an item run or notified twice, a notification
// for an item not yet run or before its run.
func Verify(p *Plan, events []audit.Event) (*Result, error) {
	if ok, problems := audit.Verify(events); !ok {
		return nil, fmt.Errorf("the audit log does not verify at entry %d (%s); nothing it "+
			"holds can be relied on", problems[0].Seq, problems[0].Reason)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	commits := commitments(events, p.Name)
	if len(commits) != 1 {
		return nil, fmt.Errorf("plan %s is committed %d times in the audit log, and a test "+
			"counts only against the one commitment made before it began", p.Name, len(commits))
	}
	c, want := commits[0], p.CommitDetail()
	for k, v := range want {
		if c.Detail[k] != v {
			return nil, fmt.Errorf("plan %s is not the plan the audit log committed: its %s differs",
				p.Name, k)
		}
	}
	commit, ok := entryOf(c)
	if !ok {
		return nil, fmt.Errorf("the commitment of plan %s has no time it can be read at", p.Name)
	}
	r := &Result{Commit: commit, Ran: map[int]time.Time{}, Notified: map[int]time.Time{},
		Refs: map[string]int{}}
	ranAt := map[int]int64{}
	for _, e := range events {
		if (e.Action != RanAction && e.Action != NotifiedAction) || e.Detail["plan"] != p.Name {
			continue
		}
		n, err := strconv.Atoi(e.Detail["item"])
		it, has := p.Item(n)
		at, terr := time.Parse(time.RFC3339Nano, e.Detail["at"])
		written, wok := entryOf(e)
		switch {
		case err != nil || !has:
			return nil, fmt.Errorf("the entry at %d records an item plan %s does not have", e.Seq, p.Name)
		case e.Seq <= c.Seq:
			return nil, fmt.Errorf("item %d of plan %s was recorded before the plan was committed",
				n, p.Name)
		case !e.Verified || e.Kind != audit.KindHuman:
			return nil, fmt.Errorf("item %d of plan %s was recorded by somebody whose identity was "+
				"not proved, or by something that is not a person", n, p.Name)
		case terr != nil || !wok || at.After(written.At):
			return nil, fmt.Errorf("the entry at %d records a time that is unreadable, or later "+
				"than the record itself", e.Seq)
		}
		if e.Action == RanAction {
			if _, twice := r.Ran[n]; twice {
				return nil, fmt.Errorf("item %d of plan %s is recorded as run more than once", n, p.Name)
			}
			if err := RunCounts(it, at, commit.At); err != nil {
				return nil, err
			}
			r.Ran[n], ranAt[n] = at, e.Seq
			continue
		}
		ref, source := e.Detail["ref"], e.Detail["source"]
		ran, wasRun := r.Ran[n]
		switch {
		case !wasRun || ranAt[n] >= e.Seq:
			return nil, fmt.Errorf("item %d of plan %s has a notification recorded before its run", n, p.Name)
		case at.Before(ran):
			return nil, fmt.Errorf("item %d of plan %s is recorded as notified before it was run", n, p.Name)
		case !telemetry.ValidAlertID(ref) || (source != "" && !proof.ValidSource(source)):
			return nil, fmt.Errorf("the notification of item %d of plan %s names a ticket or a "+
				"source not in its shape", n, p.Name)
		}
		if _, twice := r.Notified[n]; twice {
			return nil, fmt.Errorf("item %d of plan %s is recorded as notified more than once", n, p.Name)
		}
		if other, used := r.Refs[ref]; used {
			return nil, fmt.Errorf("items %d and %d of plan %s are recorded as notified by one "+
				"ticket, and one notification is about one emulation", other, n, p.Name)
		}
		r.Notified[n], r.Refs[ref] = at, n
	}
	return r, nil
}

// RunCounts is nil when an item run at at, on a plan committed at
// committed, is one the test counts, and says why not otherwise.
func RunCounts(it Item, at, committed time.Time) error {
	switch {
	case at.Before(committed):
		return fmt.Errorf("item %d is recorded as run before its plan was committed, and a test "+
			"counts only runs after its commitment", it.N)
	case at.Before(it.At):
		return fmt.Errorf("item %d was not yet due at that time: a run before its time is a time "+
			"somebody chose, not the plan's", it.N)
	case !at.Before(it.At.Add(proof.MDRRunWithin)):
		return fmt.Errorf("item %d's time to run had passed by then: it is counted only when run "+
			"within %s of falling due", it.N, proof.MDRRunWithin)
	}
	return nil
}

// Progress is where a test stands at now, for whoever runs it.
type Progress struct {
	// Due are the items that have fallen due and are not recorded as run,
	// whose time to run has not passed, in the order they fell due.
	Due []Item
	// Run, Lapsed and Waiting count the items recorded as run, those whose
	// time to run passed with no run recorded, and those not yet due.
	Run, Lapsed, Waiting int
}

// Progress says what is due. It never says when an item not yet due falls
// due: that is the secret the test rests on.
func (p *Plan) Progress(r *Result, now time.Time) Progress {
	var out Progress
	for _, it := range p.Items {
		_, ran := r.Ran[it.N]
		switch {
		case ran:
			out.Run++
		case now.Before(it.At):
			out.Waiting++
		case !now.Before(it.At.Add(proof.MDRRunWithin)):
			out.Lapsed++
		default:
			out.Due = append(out.Due, it)
		}
	}
	return out
}

// Alert is one of the provider's alerts as the event store holds it.
type Alert struct {
	// Ref is the alert's id in the provider's system.
	Ref string
	// Host is the device it names, issuer:value; empty when it names none.
	Host string
	// Raised is when the provider says it raised it, and Received when this
	// program took delivery of it. Received is the notification's time: the
	// provider cannot set it, so a provider cannot backdate one.
	Raised, Received time.Time
}

// Match is a notification joined from the event store.
type Match struct {
	N   int
	Ref string
	At  time.Time
}

// JoinReport is why the items a join did not match were not matched.
type JoinReport struct {
	// NoHost are items run and not notified whose plan names no host: a
	// provider's alert near the time of a run could be about anything on
	// the estate, so time alone would be a guess, and they wait for a
	// record by hand.
	NoHost int
	// Ambiguous are items another item on the same host was run within
	// JoinHorizon of: an alert on that host could be about either.
	Ambiguous int
	// Unmatched are items no alert naming their host arrived for within
	// JoinHorizon after the run.
	Unmatched int
	// Taken are items whose earliest matching alert is already recorded as
	// the notification of another item.
	Taken int
}

// Join matches the provider's alerts to the items run and not yet notified,
// on evidence alone: an item is matched only when its plan names the host,
// the alert names exactly that device, the provider raised it and this
// program received it no earlier than the run and received it within
// JoinHorizon after, and no other item ran on that host near enough for
// the alert to be about it instead. The earliest such alert is the
// notification.
func Join(p *Plan, r *Result, alerts []Alert) ([]Match, JoinReport) {
	var rep JoinReport
	var out []Match
	sorted := append([]Alert{}, alerts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Received.Before(sorted[j].Received) })
	for _, it := range p.Items {
		ran, wasRun := r.Ran[it.N]
		if _, done := r.Notified[it.N]; !wasRun || done {
			continue
		}
		if it.Host == "" {
			rep.NoHost++
			continue
		}
		ambiguous := false
		for _, other := range p.Items {
			at, ok := r.Ran[other.N]
			if other.N != it.N && ok && other.Host == it.Host && absDuration(at.Sub(ran)) < JoinHorizon {
				ambiguous = true
				break
			}
		}
		if ambiguous {
			rep.Ambiguous++
			continue
		}
		var found *Alert
		for i := range sorted {
			a := &sorted[i]
			if a.Host == it.Host && !a.Raised.Before(ran) && !a.Received.Before(ran) &&
				a.Received.Before(ran.Add(JoinHorizon)) {
				found = a
				break
			}
		}
		switch {
		case found == nil:
			rep.Unmatched++
		case r.Refs[found.Ref] != 0:
			rep.Taken++
		default:
			out = append(out, Match{N: it.N, Ref: found.Ref, At: found.Received})
		}
	}
	return out, rep
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
