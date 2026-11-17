// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/incident"
)

// A clock proof: when an incident's clock started, and whether what it
// started was done in time.
//
// # Why
//
// Every reporting deadline runs from a decision — GDPR's seventy-two hours
// from awareness, DORA's four from classifying an incident major, the SEC's
// four business days from determining it material — and the first thing a
// regulator asks is when that decision was made. The honest answer is in a
// record somebody could have edited afterwards. This program records each
// decision in its signed, hash-chained audit log as it is made, and can
// anchor the log's head in Bitcoin, which nobody involved can alter. A clock
// proof holds the incident's own record against that log.
//
// # The claim
//
// An incident's decision — aware, major, material, personal, health,
// mitigated — was recorded at a time by a verified person in an entry of the
// audit log, the incident's record agrees with it, the entry is under a log
// head anchored in Bitcoin, and every obligation the decision started was
// discharged by its deadline.
//
//   - refuted when the log has no entry for the decision, the incident's
//     record of it or of a discharge disagrees with the log — a clock moved
//     afterwards — an anchored head no longer matches the log, the entry
//     says it was written after the block that anchors it was mined, or an
//     obligation was discharged late or is past due;
//   - proven when none of that, the decision was made by a verified
//     person, a Bitcoin anchor whose block was checked covers its entry,
//     and every obligation it started is discharged or ruled out;
//   - inconclusive otherwise: nothing anchors the entry yet, so its time
//     rests on this program's own log; the person was not verified; or an
//     obligation's clock is still running.
//
// An anchor counts only with its block: the header two explorers returned
// for the height the timestamp names, whose merkle root is the value the
// timestamp reaches and whose work is that of a real block (internal/anchor).
// The proof carries the header, so the work is checked again whenever the
// proof is, and names the block's hash, so a reader can look it up.
//
// The deadlines are the published headline ones the incident package
// carries, and it says that is not legal advice; the proof is arithmetic on
// clocks people started.

// ClockVerifier and its version name this verifier.
const (
	ClockVerifier        = "aertun/clock"
	ClockVerifierVersion = "1"
)

// PredicateClock is the predicate of a clock proof.
const PredicateClock = "https://aertun.github.io/proof/clock/v1"

// ClockSkew is how long before its audit entry the incident's own record of
// a decision may say it was made: the record is written, then the entry
// appended, and the two clocks are read a moment apart. A record later than
// its entry, or earlier by more than this, was moved.
const ClockSkew = time.Minute

// The outcomes of an obligation.
const (
	DutyMet    = "met"
	DutyLate   = "late"
	DutyOpen   = "open"
	DutyWaived = "waived"
)

var calendarShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ClockDuty is one obligation the decision started.
type ClockDuty struct {
	// Regime is the obligation, by the name the incident package's table
	// gives it.
	Regime string `json:"regime"`
	// Due is its deadline, RFC 3339; empty for one expected without undue
	// delay, or whose clock has not started.
	Due string `json:"due,omitempty"`
	// Done is when the audit log recorded it discharged or ruled out.
	Done string `json:"done,omitempty"`
	// Waived says it was ruled out rather than discharged.
	Waived bool `json:"waived,omitempty"`
	// Moved says the incident's own record of the discharge disagrees with
	// the audit log's, or is not in the log at all.
	Moved bool `json:"moved,omitempty"`
	// Recorded is the incident's own time for the discharge, when it
	// disagrees with the log's.
	Recorded string `json:"recorded,omitempty"`
	// Outcome is met, late, open or waived, as of when the proof was made.
	Outcome string `json:"outcome"`
}

// ClockHead is a log head anchored in Bitcoin.
type ClockHead struct {
	// Size is how many entries the head covers.
	Size int `json:"size"`
	// Root is its Merkle root.
	Root string `json:"root"`
	// Block is the Bitcoin block the attestation is in.
	Block uint64 `json:"block"`
	// Hash is that block's hash: what a reader looks up at that height, in
	// any node or explorer, to see the block is in the chain.
	Hash string `json:"block_hash"`
	// Mined is the time the block's header carries, RFC 3339. Bitcoin lets a
	// block's own time run up to two hours off.
	Mined string `json:"mined"`
	// Header is the block's header, eighty bytes in hex. Its hash is Hash
	// and its time is Mined; the work it shows is checked again whenever
	// the proof is; and its merkle root is the value the OpenTimestamps
	// proof reaches from Root, which the command checked before signing.
	Header string `json:"header"`
	// Calendar is the host of the OpenTimestamps calendar that made it.
	Calendar string `json:"calendar"`
}

// BlockTimeSlack is how far a block's own time may run from the time it was
// mined: Bitcoin accepts one up to two hours ahead.
const BlockTimeSlack = 2 * time.Hour

// checkBlock holds a head's block to its header: the hash and the time are
// the header's, and work was done for it that a block is believed at.
func (h ClockHead) checkBlock() error {
	hd, err := anchor.ParseHeader(h.Header)
	if err != nil || hd.Hash() != h.Hash || hd.Time().Format(time.RFC3339) != h.Mined {
		return fmt.Errorf("an anchored head's block hash and time are its header's")
	}
	if err := hd.Worked(); err != nil {
		return fmt.Errorf("an anchored head's block is not one to believe: %w", err)
	}
	return nil
}

// ClockEvidence is what a clock proof rests on.
type ClockEvidence struct {
	// Incident is the incident's identifier.
	Incident string `json:"incident"`
	// Trigger is the decision: aware, major, material, personal, health or
	// mitigated.
	Trigger string `json:"trigger"`
	// Entry is the audit entry that recorded the decision; zero when the
	// log has none.
	Entry int `json:"entry"`
	// Decided is when the log recorded it, RFC 3339 to the nanosecond.
	Decided string `json:"decided,omitempty"`
	// Recorded is when the incident's own record says it was made.
	Recorded string `json:"recorded"`
	// Verified says the person who made it proved who they were.
	Verified bool `json:"verified"`
	// Anchor is the earliest head covering the entry with a confirmed
	// Bitcoin attestation that still matches the log.
	Anchor *ClockHead `json:"anchor,omitempty"`
	// Broken are anchored heads that no longer match the log.
	Broken []ClockHead `json:"broken,omitempty"`
	// Linked is how many findings were linked to the incident when the
	// decision was made.
	Linked int `json:"linked"`
	// Lead is how long before the decision the earliest of them was first
	// seen, in seconds.
	Lead int `json:"lead_seconds"`
	// Duties are the obligations the decision started.
	Duties []ClockDuty `json:"duties"`
}

// ClockInput is what a clock proof is made from.
type ClockInput struct {
	Evidence ClockEvidence
	// Lines are the entries and records read, one JSON object per line.
	Lines     []byte
	Materials []Material
	Program   string
	Now       time.Time
}

// ProveClock builds the unsigned statement.
func ProveClock(in ClockInput) (*Statement, error) {
	ev := in.Evidence
	ev.Duties = append([]ClockDuty{}, ev.Duties...)
	ev.Broken = append([]ClockHead(nil), ev.Broken...)
	now := in.Now.UTC().Truncate(time.Second)
	if err := ev.wellFormed(now); err != nil {
		return nil, err
	}
	if len(in.Lines) == 0 {
		return nil, fmt.Errorf("nothing was read, so there is nothing to sign")
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: SHA256(in.Lines)}},
		PredicateType: PredicateClock,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: ClockVerifier, Version: ClockVerifierVersion,
				Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(), Clock: &ev, VerifiedAt: now.Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *ClockEvidence) subject() string { return "incident/" + ev.Incident + "/" + ev.Trigger }

// DutyOutcome is what became of an obligation, as of now: ruled out, done by
// its deadline (or done, when it has none), done late or past due, or
// still running.
func DutyOutcome(due, done time.Time, waived bool, now time.Time) string {
	switch {
	case waived:
		return DutyWaived
	case !done.IsZero() && (due.IsZero() || !done.After(due)):
		return DutyMet
	case !done.IsZero(), !due.IsZero() && now.After(due):
		return DutyLate
	}
	return DutyOpen
}

func parseInstant(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil && instant(t) == s
}

// moved reports whether the incident's record of the decision disagrees
// with the log's.
func (ev *ClockEvidence) moved() bool {
	decided, _ := parseInstant(ev.Decided)
	recorded, _ := parseInstant(ev.Recorded)
	return ev.Entry > 0 && (recorded.After(decided) || decided.Sub(recorded) > ClockSkew)
}

func (ev *ClockEvidence) wellFormed(now time.Time) error {
	if !incident.ValidID(ev.Incident) {
		return fmt.Errorf("a clock proof names an incident by its identifier")
	}
	known := false
	for _, t := range incident.Triggers {
		known = known || string(t) == ev.Trigger
	}
	if !known {
		return fmt.Errorf("%q is not a decision that starts a clock", ev.Trigger)
	}
	decided, ok1 := parseInstant(ev.Decided)
	recorded, ok2 := parseInstant(ev.Recorded)
	if !ok1 || !ok2 || recorded.IsZero() || ev.Entry < 0 || (ev.Entry == 0) != decided.IsZero() ||
		(ev.Entry == 0 && ev.Verified) || ev.Linked < 0 || ev.Lead < 0 || (ev.Linked == 0 && ev.Lead != 0) {
		return fmt.Errorf("a clock proof's decision, entry and times do not hold together")
	}
	heads := ev.Broken
	if ev.Anchor != nil {
		heads = append([]ClockHead{*ev.Anchor}, heads...)
		if ev.Entry == 0 || ev.Anchor.Size < ev.Entry {
			return fmt.Errorf("an anchor covers the decision's entry or is not named")
		}
	}
	if len(ev.Broken) > MaxFailures {
		return fmt.Errorf("a clock proof lists at most %d broken heads", MaxFailures)
	}
	for _, h := range heads {
		if h.Size <= 0 || !hex64.MatchString(h.Root) || h.Block == 0 || !calendarShape.MatchString(h.Calendar) {
			return fmt.Errorf("an anchored head is a size, a root, a block and a calendar's host")
		}
		if err := h.checkBlock(); err != nil {
			return err
		}
	}
	regimes := map[string]incident.Obligation{}
	for _, o := range incident.Obligations {
		regimes[o.Regime] = o
	}
	seen := map[string]bool{}
	for _, d := range ev.Duties {
		o, ok := regimes[d.Regime]
		due, ok1 := parseInstant(d.Due)
		done, ok2 := parseInstant(d.Done)
		rec, ok3 := parseInstant(d.Recorded)
		if !ok || seen[d.Regime] || string(o.Needs) != ev.Trigger || !ok1 || !ok2 || !ok3 ||
			(d.Waived && done.IsZero()) || d.Moved != (d.Recorded != "") ||
			(d.Moved && !done.IsZero() && !rec.After(done) && done.Sub(rec) <= ClockSkew) ||
			d.Outcome != DutyOutcome(due, done, d.Waived, now) {
			return fmt.Errorf("obligation %q does not hold together", d.Regime)
		}
		seen[d.Regime] = true
	}
	return nil
}

// postdated reports whether the decision's entry says it was written after
// the block that anchors it was mined, which cannot be: the time in the
// entry is then not when it was written.
func (ev *ClockEvidence) postdated() bool {
	if ev.Anchor == nil || ev.Entry == 0 {
		return false
	}
	decided, ok1 := parseInstant(ev.Decided)
	mined, ok2 := parseInstant(ev.Anchor.Mined)
	return ok1 && ok2 && decided.After(mined.Add(BlockTimeSlack))
}

func (ev *ClockEvidence) verdict() Verdict {
	if ev.Entry == 0 || ev.moved() || len(ev.Broken) > 0 || ev.postdated() {
		return Refuted
	}
	open := false
	for _, d := range ev.Duties {
		if d.Moved || d.Outcome == DutyLate {
			return Refuted
		}
		open = open || d.Outcome == DutyOpen
	}
	if !ev.Verified || ev.Anchor == nil || open {
		return Inconclusive
	}
	return Proven
}

func (ev *ClockEvidence) claim() string {
	return fmt.Sprintf("Incident %s's %s decision was recorded by a verified person in an entry "+
		"of this program's audit log, the incident's own record agrees with it, the entry is "+
		"under a log head anchored in Bitcoin, and every obligation the decision started was "+
		"discharged by its deadline.", ev.Incident, ev.Trigger)
}

func (ev *ClockEvidence) checks() []Check {
	recorded := Check{Name: "recorded", Passed: ev.Entry > 0 && !ev.moved()}
	switch {
	case ev.Entry == 0:
		recorded.Detail = fmt.Sprintf("the incident records %s at %s, and the audit log has no "+
			"entry for it", ev.Trigger, ev.Recorded)
		recorded.Failures = []string{"no entry: " + ev.Trigger}
	default:
		who := "a verified person"
		if !ev.Verified {
			who = "a person who did not prove who they were, so whose decision it was rests on the session alone"
		}
		recorded.Detail = fmt.Sprintf("audit entry %d recorded %s at %s, by %s; the incident "+
			"records it at %s", ev.Entry, ev.Trigger, ev.Decided, who, ev.Recorded)
		if ev.moved() {
			recorded.Failures = []string{"moved: " + ev.Trigger + " at " + ev.Recorded +
				" in the incident and " + ev.Decided + " in the log"}
		}
	}

	anchored := Check{Name: "anchored", Passed: len(ev.Broken) == 0 && !ev.postdated()}
	switch {
	case ev.postdated():
		anchored.Detail = fmt.Sprintf("entry %d says it was written at %s, and the log head of %d "+
			"entries that holds it is in Bitcoin block %d (%s), mined at %s: an entry cannot be "+
			"written after the block that anchors it, so the time in it is not when it was written",
			ev.Entry, ev.Decided, ev.Anchor.Size, ev.Anchor.Block, ev.Anchor.Hash, ev.Anchor.Mined)
		anchored.Failures = []string{"written after its block: " + ev.Decided + " in the log, and block " +
			strconv.FormatUint(ev.Anchor.Block, 10) + " mined at " + ev.Anchor.Mined}
	case ev.Anchor != nil:
		anchored.Detail = fmt.Sprintf("entry %d is under the log head of %d entries anchored in "+
			"Bitcoin block %d (%s, mined %s) by %s; the block's header holds the commitment and "+
			"shows the work of a real block, so the entry existed no later than that block",
			ev.Entry, ev.Anchor.Size, ev.Anchor.Block, ev.Anchor.Hash, ev.Anchor.Mined, ev.Anchor.Calendar)
	case ev.Entry > 0:
		anchored.Detail = fmt.Sprintf("no anchor whose block was checked covers entry %d yet, so "+
			"its time rests on this program's own log (aertun auditlog anchor, then anchor upgrade)",
			ev.Entry)
	default:
		anchored.Detail = "there is no entry to anchor"
	}
	for _, h := range ev.Broken {
		anchored.Failures = append(anchored.Failures, fmt.Sprintf("does not match the log: the "+
			"head of %d entries anchored in block %d", h.Size, h.Block))
	}
	if len(ev.Broken) > 0 {
		anchored.Detail += fmt.Sprintf("; %d anchored head(s) no longer match the log, which "+
			"was rewritten after they were anchored", len(ev.Broken))
	}

	known := Check{Name: "known-then", Passed: true,
		Detail: fmt.Sprintf("%d finding(s) were linked to the incident when the decision was made", ev.Linked)}
	if ev.Linked > 0 {
		known.Detail += fmt.Sprintf("; the earliest was first seen %s before it",
			span(time.Duration(ev.Lead)*time.Second))
	}

	deadlines := Check{Name: "deadlines", Passed: true}
	counts := map[string]int{}
	for _, d := range ev.Duties {
		counts[d.Outcome]++
		switch {
		case d.Moved && d.Done == "":
			deadlines.Passed = false
			deadlines.Failures = append(deadlines.Failures, "moved: "+d.Regime+" done at "+
				d.Recorded+" in the incident and not in the log")
		case d.Moved:
			deadlines.Passed = false
			deadlines.Failures = append(deadlines.Failures, "moved: "+d.Regime+" done at "+
				d.Recorded+" in the incident and "+d.Done+" in the log")
		case d.Outcome == DutyLate && d.Done != "":
			deadlines.Passed = false
			deadlines.Failures = append(deadlines.Failures, "late: "+d.Regime+" due "+d.Due+
				", discharged "+d.Done)
		case d.Outcome == DutyLate:
			deadlines.Passed = false
			deadlines.Failures = append(deadlines.Failures, "late: "+d.Regime+" due "+d.Due+
				", not discharged")
		}
	}
	deadlines.Detail = fmt.Sprintf("%d obligation(s) started by %s in this incident's regimes: "+
		"%d met, %d ruled out, %d late, %d still running", len(ev.Duties), ev.Trigger,
		counts[DutyMet], counts[DutyWaived], counts[DutyLate], counts[DutyOpen])
	return []Check{recorded, anchored, known, deadlines}
}

// validate rebuilds every word, failures included — they come from the
// evidence alone — and refuses a statement that says anything else.
func (ev *ClockEvidence) validate(s *Statement) error {
	now, err := time.Parse(time.RFC3339, s.Predicate.VerifiedAt)
	if err != nil {
		return err
	}
	if err := ev.wellFormed(now); err != nil {
		return err
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the evidence makes this %s, not %s", want, s.Predicate.Verdict)
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != ev.subject() {
		return fmt.Errorf("the subject is not %s", ev.subject())
	}
	if s.Predicate.Claim != ev.claim() {
		return fmt.Errorf("the claim is not the sentence its evidence makes")
	}
	a, _ := json.Marshal(s.Predicate.Checks)
	b, _ := json.Marshal(ev.checks())
	if string(a) != string(b) {
		return fmt.Errorf("the checks are not the ones its evidence makes")
	}
	return nil
}
