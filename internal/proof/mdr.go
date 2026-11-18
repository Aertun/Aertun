// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// An MDR proof: a managed detection provider's, or an AI SOC's, claim to
// notify within a time, tested blind on the customer's own estate
// (internal/mdr).
//
// # Why
//
// "We detect and notify within 30 minutes" is what such a service sells,
// and the independent tests of it are few, run on somebody else's network,
// and announced. Here the customer draws a plan: emulations from its own
// list, each at a random time in a window, and commits the plan's digest to
// the signed audit log before any is run. The plan itself stays in the
// store, so neither the provider nor anybody reading what this program
// publishes can learn when the next one comes, and the digest means the
// plan cannot be changed afterwards to leave out a bad day. Each run, and
// each notification the provider sent about it, is recorded by a verified
// person.
//
// # The claim
//
// Of the emulations run from the plan, the provider notified within the SLA
// on all but a share of at most the tolerance. The missed share — notified
// late, or not at all, of those run — is read with the exact one-sided
// bounds, as the other rates here are:
//
//   - refuted when the lower bound is over the tolerance, naming each missed
//     item by number and emulation;
//   - proven when the upper bound is at or under it, on at least MinSample
//     runs, every one of them recorded after the commitment;
//   - inconclusive otherwise, and always while the test is open: until the
//     last item's time to run and its SLA after that have passed, nothing is
//     decided, so a test cannot be stopped on a good day.
//
// The proof names the emulations only of the items it says were missed: the
// list a customer tests with is worth keeping from the provider, which could
// otherwise write detections for exactly those, and the hosts never appear
// at all.

// MDRVerifier and its version name this verifier.
const (
	MDRVerifier        = "aertun/mdr"
	MDRVerifierVersion = "1"
)

// PredicateMDR is the predicate of an MDR proof.
const PredicateMDR = "https://aertun.github.io/proof/mdr/v1"

// The bounds an MDR proof's numbers are held to.
const (
	// MDRRunWithin is how long after its scheduled time an item may still be
	// run. Later than that, the time is one somebody chose rather than the
	// plan's, and the run is not counted.
	MDRRunWithin = 24 * time.Hour
	// MinMDRWindow and MaxMDRWindow bound the window a plan is drawn in.
	MinMDRWindow = 24 * time.Hour
	MaxMDRWindow = 366 * 24 * time.Hour
	// MinMDRSLA and MaxMDRSLA bound the time to notify a provider is held to.
	MinMDRSLA = time.Minute
	MaxMDRSLA = 24 * time.Hour
	// MaxMDRItems bounds a plan: every item is run by somebody.
	MaxMDRItems = 1000
)

var (
	mdrPlanShape   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	emulationShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	missedFailure  = regexp.MustCompile(`^item ([1-9][0-9]{0,3}) \(([^)]*)\) (notified late|not notified)$`)
)

// ValidMDRPlan reports whether s can name a plan.
func ValidMDRPlan(s string) bool { return mdrPlanShape.MatchString(s) }

// ValidEmulation reports whether s has the shape of an emulation's id: an
// identifier in a test library, such as an Atomic Red Team test's T1059.001-1,
// never a description, so nothing but letters, digits and . _ : -.
func ValidEmulation(s string) bool { return emulationShape.MatchString(s) }

// MDRItem is one item of the plan that was run, and how the provider
// answered it.
type MDRItem struct {
	// N is the item's number in the plan.
	N int `json:"n"`
	// Notified is whether a notification from the provider about it was
	// recorded.
	Notified bool `json:"notified"`
	// Seconds is how long after the run the notification came, rounded up
	// to the whole second; zero when none came.
	Seconds int `json:"seconds"`
}

// MDREvidence is what an MDR proof rests on.
type MDREvidence struct {
	// Plan is the plan's name, as the operator gave it.
	Plan string `json:"plan"`
	// Provider is the provider under test, by a short name the operator
	// chose: never the provider's own wording.
	Provider string `json:"provider"`
	// PlanSHA256 is the digest of the plan as it was committed, which is
	// also the subject's digest.
	PlanSHA256 string `json:"plan_sha256"`
	// Committed is the audit entry that committed the plan's digest, before
	// any item was run.
	Committed AuditEntry `json:"committed"`
	// WindowStart and WindowEnd bound the times the items were drawn at,
	// RFC 3339; the end is not included.
	WindowStart string `json:"window_start"`
	WindowEnd   string `json:"window_end"`
	// RunWithin is how long after its scheduled time an item could still be
	// run and counted.
	RunWithin int `json:"run_within_seconds"`
	// SLA is the time to notify the provider is held to, in seconds.
	SLA int `json:"sla_seconds"`
	// Closed is whether the test had closed when the proof was made: the
	// window's end, the time to run its last item, and the SLA after that,
	// all passed.
	Closed bool `json:"closed"`
	// Tolerance is the missed share the provider is held to, declared when
	// the proof was made.
	Tolerance float64 `json:"tolerance"`
	// Planned is how many items the plan holds.
	Planned int `json:"planned"`
	// Run is how many of them were recorded as run.
	Run int `json:"run"`
	// FirstRun is when the first of them was run, RFC 3339 as recorded;
	// empty when none was.
	FirstRun string `json:"first_run,omitempty"`
	// Within is how many runs the provider notified within the SLA.
	Within int `json:"within_sla"`
	// Late is how many it notified after the SLA.
	Late int `json:"late"`
	// Never is how many it did not notify at all.
	Never int `json:"not_notified"`
	// Missed is the late and the never, of the runs, with the exact
	// one-sided bounds on the share.
	Missed Bound `json:"missed"`
	// Median is the time to notify, in seconds, of the runs notified late or
	// in time: the nearest-rank 50th percentile, zero when none was.
	Median int `json:"median_seconds"`
	// P90 is the nearest-rank 90th percentile of the same, zero when none
	// was.
	P90 int `json:"p90_seconds"`
	// Items are the runs, by item number, and how the provider answered
	// each: what every count above is recounted from.
	Items []MDRItem `json:"items"`
	// MinRun is the fewest runs a proven verdict may rest on.
	MinRun int `json:"min_run"`
}

// MDRRun is one item that was run, as an MDR proof is made from it.
type MDRRun struct {
	N         int
	Emulation string
	Ran       time.Time
	// Notified is when the provider's notification came, zero when none
	// did.
	Notified time.Time
}

// MDRInput is what an MDR proof is made from.
type MDRInput struct {
	Plan, Provider, PlanSHA256 string
	Committed                  AuditEntry
	WindowStart, WindowEnd     time.Time
	SLA                        time.Duration
	Tolerance                  float64
	Planned                    int
	Runs                       []MDRRun
	Materials                  []Material
	Program                    string
	Now                        time.Time
}

// ceilSeconds is a duration in whole seconds, rounded up: a notification a
// fraction of a second past the SLA is past it.
func ceilSeconds(d time.Duration) int {
	s := d / time.Second
	if d%time.Second > 0 {
		s++
	}
	return int(s)
}

// nearestRank is the p-th percentile of sorted values, by nearest rank: the
// smallest value at least p% of them are at or under. Whole numbers only, so
// a reader recomputes it exactly.
func nearestRank(sorted []int, p int) int {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[(p*len(sorted)+99)/100-1]
}

func missedFailureOf(n int, emulation string, late bool) string {
	if late {
		return "item " + strconv.Itoa(n) + " (" + emulation + ") notified late"
	}
	return "item " + strconv.Itoa(n) + " (" + emulation + ") not notified"
}

// ProveMDR builds the unsigned statement.
func ProveMDR(in MDRInput) (*Statement, error) {
	if in.SLA%time.Second != 0 {
		return nil, fmt.Errorf("the SLA is a whole number of seconds")
	}
	runs := append([]MDRRun{}, in.Runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].N < runs[j].N })
	now := in.Now.UTC().Truncate(time.Second)
	ev := &MDREvidence{Plan: in.Plan, Provider: in.Provider, PlanSHA256: in.PlanSHA256,
		Committed: in.Committed, WindowStart: day(in.WindowStart), WindowEnd: day(in.WindowEnd),
		RunWithin: int(MDRRunWithin / time.Second), SLA: int(in.SLA / time.Second),
		Tolerance: in.Tolerance, Planned: in.Planned, Run: len(runs), Items: []MDRItem{},
		MinRun: MinSample}
	var first time.Time
	for _, r := range runs {
		if !ValidEmulation(r.Emulation) {
			return nil, fmt.Errorf("item %d's emulation is not an id in its shape", r.N)
		}
		it := MDRItem{N: r.N}
		if !r.Notified.IsZero() {
			if r.Notified.Before(r.Ran) {
				return nil, fmt.Errorf("item %d was notified before it was run", r.N)
			}
			it.Notified, it.Seconds = true, ceilSeconds(r.Notified.Sub(r.Ran))
		}
		ev.Items = append(ev.Items, it)
		if first.IsZero() || r.Ran.Before(first) {
			first = r.Ran
		}
	}
	if !first.IsZero() {
		ev.FirstRun = instant(first)
	}
	ev.count()
	ev.Closed = !now.Before(ev.closes())
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	var failures []string
	if ev.verdict() == Refuted {
		for i, r := range runs {
			if it := ev.Items[i]; !it.Notified || it.Seconds > ev.SLA {
				failures = append(failures, missedFailureOf(r.N, r.Emulation, it.Notified))
			}
		}
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: Digest{"sha256": ev.PlanSHA256}}},
		PredicateType: PredicateMDR,
		Predicate: Predicate{
			Claim:     ev.claim(),
			Verdict:   ev.verdict(),
			Verifier:  VerifierID{ID: MDRVerifier, Version: MDRVerifierVersion, Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(failures),
			MDR:       ev, VerifiedAt: now.Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

// count fills in every number the items decide.
func (ev *MDREvidence) count() {
	ev.Within, ev.Late, ev.Never = ev.tally()
	ev.Missed = ExactBound(ev.Late+ev.Never, len(ev.Items))
	ev.Median, ev.P90 = ev.percentiles()
}

func (ev *MDREvidence) tally() (within, late, never int) {
	for _, it := range ev.Items {
		switch {
		case !it.Notified:
			never++
		case it.Seconds > ev.SLA:
			late++
		default:
			within++
		}
	}
	return within, late, never
}

func (ev *MDREvidence) percentiles() (median, p90 int) {
	var times []int
	for _, it := range ev.Items {
		if it.Notified {
			times = append(times, it.Seconds)
		}
	}
	sort.Ints(times)
	return nearestRank(times, 50), nearestRank(times, 90)
}

func (ev *MDREvidence) subject() string { return "mdr/" + ev.Plan }

func (ev *MDREvidence) window() (start, end time.Time) {
	start, _ = time.Parse(time.RFC3339, ev.WindowStart)
	end, _ = time.Parse(time.RFC3339, ev.WindowEnd)
	return start, end
}

func (ev *MDREvidence) sla() time.Duration { return time.Duration(ev.SLA) * time.Second }

// closes is when the test closes: the last item could be scheduled just
// before the window's end, run up to RunWithin after that, and notified up
// to the SLA after its run.
func (ev *MDREvidence) closes() time.Time {
	_, end := ev.window()
	return end.Add(time.Duration(ev.RunWithin)*time.Second + ev.sla())
}

// wellFormed refuses evidence whose shapes or numbers do not hold together,
// on either side of signing.
func (ev *MDREvidence) wellFormed() error {
	if !ValidMDRPlan(ev.Plan) || !ValidVerdictSource(ev.Provider) || !hex64.MatchString(ev.PlanSHA256) ||
		!ev.Committed.valid() {
		return fmt.Errorf("an MDR proof names its plan, by name and digest, the provider, " +
			"and the audit entry that committed the plan")
	}
	start, err1 := time.Parse(time.RFC3339, ev.WindowStart)
	end, err2 := time.Parse(time.RFC3339, ev.WindowEnd)
	committed, _ := time.Parse(time.RFC3339Nano, ev.Committed.At)
	if err1 != nil || err2 != nil || day(start) != ev.WindowStart || day(end) != ev.WindowEnd ||
		end.Sub(start) < MinMDRWindow || end.Sub(start) > MaxMDRWindow ||
		committed.Before(start) || !committed.Before(end) {
		return fmt.Errorf("a plan's window is between a day and %d days long, and its commitment "+
			"falls inside it", int(MaxMDRWindow.Hours()/24))
	}
	if ev.RunWithin != int(MDRRunWithin/time.Second) || ev.MinRun != MinSample {
		return fmt.Errorf("the evidence's time to run and minimum are not this version's")
	}
	if ev.sla() < MinMDRSLA || ev.sla() > MaxMDRSLA || !validTolerance(ev.Tolerance) {
		return fmt.Errorf("the SLA is between a minute and a day, and the tolerance a rate " +
			"between 0 and 1, more than none")
	}
	if ev.Planned < 1 || ev.Planned > MaxMDRItems || ev.Run != len(ev.Items) || ev.Run > ev.Planned {
		return fmt.Errorf("a plan holds between 1 and %d items, and the runs are some of them",
			MaxMDRItems)
	}
	last := 0
	for _, it := range ev.Items {
		if it.N <= last || it.N > ev.Planned || it.Seconds < 0 || (!it.Notified && it.Seconds != 0) ||
			time.Duration(it.Seconds)*time.Second > MaxMDRWindow {
			return fmt.Errorf("the runs are listed once each, in order, by a number the plan has, " +
				"each with a time to notify only when it was notified")
		}
		last = it.N
	}
	if ev.Run == 0 && ev.FirstRun != "" {
		return fmt.Errorf("nothing was run, so there is no first run")
	}
	if ev.Run > 0 {
		first, err := time.Parse(time.RFC3339Nano, ev.FirstRun)
		if err != nil || instant(first) != ev.FirstRun || first.Before(committed) {
			return fmt.Errorf("the first run came after the plan was committed, or the plan " +
				"proves nothing")
		}
	}
	within, late, never := ev.tally()
	median, p90 := ev.percentiles()
	if within != ev.Within || late != ev.Late || never != ev.Never || median != ev.Median || p90 != ev.P90 {
		return fmt.Errorf("the counts and times are not the ones the runs make")
	}
	if !ev.Missed.valid() || ev.Missed.K != late+never || ev.Missed.N != ev.Run {
		return fmt.Errorf("the missed share is not the late and the never, of the runs, with " +
			"its exact bounds")
	}
	return nil
}

func (ev *MDREvidence) verdict() Verdict {
	switch {
	case !ev.Closed:
		return Inconclusive
	case ev.Missed.Lower > ev.Tolerance:
		return Refuted
	case ev.Run >= MinSample && ev.Missed.Upper <= ev.Tolerance:
		return Proven
	}
	return Inconclusive
}

func (ev *MDREvidence) tolerance() string { return num(ev.Tolerance) }

func (ev *MDREvidence) claim() string {
	return fmt.Sprintf("Of the emulations run from plan %s, scheduled at random between %s and %s "+
		"and committed at audit entry %d before any was run, provider %s notified within %s on all "+
		"but a share of at most %s.", ev.Plan, ev.WindowStart, ev.WindowEnd, ev.Committed.Seq,
		ev.Provider, span(ev.sla()), ev.tolerance())
}

// checks are the proof's checks, from the evidence and the names of the
// items missed.
func (ev *MDREvidence) checks(failures []string) []Check {
	committed := Check{Name: "committed-first", Passed: true,
		Detail: fmt.Sprintf("plan %s, %d emulation(s) each drawn at random from the operator's list "+
			"for a random time between %s and %s, was committed at audit entry %d as a digest alone, "+
			"so nothing this program publishes could tell %s when any would come; a run counts from "+
			"its scheduled time to %s after it", ev.Plan, ev.Planned, ev.WindowStart, ev.WindowEnd,
			ev.Committed.Seq, ev.Provider, span(time.Duration(ev.RunWithin)*time.Second))}
	if ev.Run > 0 {
		committed.Detail += fmt.Sprintf("; the first run, at %s, came after the commitment", ev.FirstRun)
	} else {
		committed.Detail += "; nothing has been run"
	}

	closes := instant(ev.closes())
	window := Check{Name: "window-closed", Passed: true,
		Detail: fmt.Sprintf("with %s to run the last item and an SLA of %s after that, the test "+
			"closed at %s, before this ran", span(time.Duration(ev.RunWithin)*time.Second), span(ev.sla()),
			closes)}
	if !ev.Closed {
		window.Detail = fmt.Sprintf("with %s to run the last item and an SLA of %s after that, the "+
			"test closes at %s and is still open, so nothing is decided: a test that could be "+
			"stopped on a good day would not be blind", span(time.Duration(ev.RunWithin)*time.Second),
			span(ev.sla()), closes)
	}

	missed := Check{Name: "missed", Passed: ev.verdict() != Refuted,
		Detail: fmt.Sprintf("of %d planned, %d run: %d notified within %s, %d late and %d not at all; "+
			"the missed share is between %.4f and %.4f (exact, one-sided, 95%% each), against a "+
			"tolerance of %s", ev.Planned, ev.Run, ev.Within, span(ev.sla()), ev.Late, ev.Never,
			ev.Missed.Lower, ev.Missed.Upper, ev.tolerance())}
	if ev.Run < MinSample && ev.verdict() != Refuted {
		missed.Detail += fmt.Sprintf("; fewer than the %d runs a proven verdict needs", MinSample)
	}
	shown, more := capped(failures)
	missed.Failures = shown
	if more > 0 {
		missed.Detail += fmt.Sprintf("; %d more not listed", more)
	}

	timing := Check{Name: "time-to-notify", Passed: true,
		Detail: "nothing run was notified, so there is no time to notify to report"}
	if n := ev.Within + ev.Late; n > 0 {
		timing.Detail = fmt.Sprintf("of the %d notified, the median time from the run to the "+
			"notification was %s and the 90th percentile %s (nearest rank, rounded up to the second)",
			n, time.Duration(ev.Median)*time.Second, time.Duration(ev.P90)*time.Second)
	}
	return []Check{committed, window, missed, timing}
}

// validate refuses evidence whose numbers do not add up, do not support the
// verdict, or do not account for every word the statement says.
func (ev *MDREvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
		return err
	}
	verified, err := time.Parse(time.RFC3339, s.Predicate.VerifiedAt)
	if err != nil || ev.Closed != !verified.Before(ev.closes()) {
		return fmt.Errorf("the test is said to be %s, and it was not when the proof was made",
			map[bool]string{true: "closed", false: "open"}[ev.Closed])
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the counts make this %s, not %s", want, s.Predicate.Verdict)
	}
	if len(s.Predicate.Checks) != 4 {
		return fmt.Errorf("an MDR proof has four checks")
	}
	if len(s.Subject) != 1 || s.Subject[0].Digest["sha256"] != ev.PlanSHA256 {
		return fmt.Errorf("the subject is not the plan the evidence names")
	}
	// The items missed, in order, as a refutation names them: each failure
	// must be the next of them, by number and by how it was missed.
	var missed []MDRItem
	if ev.verdict() == Refuted {
		for _, it := range ev.Items {
			if !it.Notified || it.Seconds > ev.SLA {
				missed = append(missed, it)
			}
		}
	}
	var listed []string
	for i, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			m := missedFailure.FindStringSubmatch(f)
			k := len(listed)
			if i != 2 || m == nil || !ValidEmulation(m[2]) || k >= len(missed) ||
				m[1] != strconv.Itoa(missed[k].N) || (m[3] == "notified late") != missed[k].Notified {
				return fmt.Errorf("a failure in an MDR proof names the next item missed, by its " +
					"number, its emulation and how it was missed, and nothing else")
			}
			listed = append(listed, f)
		}
	}
	if len(listed) != min(len(missed), MaxFailures) {
		return fmt.Errorf("the items listed as missed are not the ones counted")
	}
	pad := append(listed, make([]string, len(missed)-len(listed))...)
	return sameWords(s, ev.subject(), ev.claim(), ev.checks(pad))
}
