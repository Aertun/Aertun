// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package benign keeps an estate's weird-but-benign sessions: real activity
// a person has vouched for, captured from the event store, sanitised, and
// sealed into a bundle the wind tunnel replays to measure how often a rule
// fires on what this organisation really does.
//
// # Why
//
// A rule tuned on synthetic data fires on the real estate: the migration
// that touches every table, the agent that makes forty tool calls a second,
// the maintenance script nobody would write by hand. Either the rule is then
// switched off, which is a blind spot, or the analysts drown, which is a
// slower one. The wind tunnel's benign twins are written beside the attacks
// and cannot know any of this. Only the estate's own sessions can.
//
// # What a benign session is not
//
// It is not an exception. Nothing here suppresses an alert in production:
// a bundle is replayed in a scratch store, and what it decides is whether a
// rule change passes its gate. But a session vouched for as benign can block
// a rule that would catch it, so it is held like an exception would be: a
// second person approves it, it names a reason, it expires, it can be
// revoked, and at capture it is run against the rules and the intelligence
// already held, so known-bad activity is refused rather than vouched for.
//
// # Sanitising, and what it can and cannot preserve
//
// A bundle travels — to a CI runner, a vendor, a research partner — and the
// key its pseudonyms are made with does not. Identifiers become keyed
// pseudonyms that keep their shape (an address stays in its special-purpose
// class, an email stays an email, a domain keeps its hierarchy), secrets and
// personal data inside free text are masked, and fields no rule reads are
// dropped. Consistent pseudonyms preserve every equality — a group-by, a
// distinct count, the same actor twice — and preserve no literal: a rule
// comparing a pseudonymised field with a value can no longer match. So a
// capture is checked for fidelity, rule by rule, raw against sanitised, and
// a bundle records which fields it transformed, so a rule it was not checked
// against is reported as unmeasurable rather than as quiet.
package benign

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Limits on what one session and one bundle may hold.
const (
	// MaxSessionEvents bounds one session: a workflow, not a day.
	MaxSessionEvents = 50000
	// MaxSessionSpan bounds the time one session covers.
	MaxSessionSpan = 24 * time.Hour
	// MaxSessions bounds one bundle.
	MaxSessions = 2000
	// MaxBundleBytes bounds a bundle file.
	MaxBundleBytes = 256 << 20
	// DefaultLife is how long a session is vouched for unless the capture
	// says otherwise, and MaxLife the longest it may be.
	DefaultLife = 90 * 24 * time.Hour
	MaxLife     = 365 * 24 * time.Hour
	// Recapture is how old a capture may be before renewing it is refused
	// and it must be captured again: the estate a year ago is not this one.
	Recapture = 365 * 24 * time.Hour
	// MaxTicket bounds a ticket reference.
	MaxTicket = 64
)

// Classes is the closed vocabulary a session is filed under, so reports
// group like with like and a class is never somebody's sentence.
var Classes = []string{"migration", "backup", "deploy", "maintenance", "agent-run",
	"batch", "admin", "test", "other"}

// KnownClass reports whether c is one of Classes.
func KnownClass(c string) bool {
	for _, k := range Classes {
		if k == c {
			return true
		}
	}
	return false
}

// The states a session is in, in the store.
const (
	Pending  = "pending"
	Approved = "approved"
	Revoked  = "revoked"
)

var (
	nameShape   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	ticketShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,63}$`)
	digestShape = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pseudoShape = regexp.MustCompile(`^p-[a-z0-9]{8,32}$`)
)

// ValidName reports whether s can name a session.
func ValidName(s string) bool { return nameShape.MatchString(s) }

// ValidTicket reports whether s can reference a change ticket.
func ValidTicket(s string) bool { return ticketShape.MatchString(s) }

// Fidelity is what the capture's raw-against-sanitised check showed.
type Fidelity struct {
	// Set names the rule set the check ran: an entry in the bundle's table
	// of fidelity sets, by the digest of its sorted rule digests.
	Set string `json:"set"`
	// Rules is how many rules and correlations it ran.
	Rules int `json:"rules"`
	// Reduced says the operator accepted outcomes that differed, and Lost
	// names the rules whose outcome sanitising changed.
	Reduced bool     `json:"reduced,omitempty"`
	Lost    []string `json:"lost,omitempty"`
}

// Session is one vouched-for workflow: what it holds, who vouched for it,
// and for how long.
type Session struct {
	// Name is the session's name, unique in the store.
	Name string `json:"name"`
	// Class is what kind of workflow it is, from Classes.
	Class string `json:"class"`
	// Digest is the SHA-256 of the canonical sanitised events: the
	// session's content address.
	Digest string `json:"digest"`
	// Events is how many events it holds.
	Events int `json:"events"`
	// Sources are the sources its events came from, sorted.
	Sources []string `json:"sources"`
	// Since and Until are its first and last event's times.
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	// Captured is when it was captured, and Expires when it stops counting.
	Captured time.Time `json:"captured"`
	Expires  time.Time `json:"expires"`
	// VouchedBy and ApprovedBy are the two people, as pseudonyms.
	VouchedBy  string `json:"vouched_by"`
	ApprovedBy string `json:"approved_by,omitempty"`
	// Alone says the store's only administrator approved their own capture
	// after the waiting period: said, so nobody reads one person as two.
	Alone bool `json:"alone,omitempty"`
	// WhySHA256 is the digest of the reason given; the reason itself stays
	// in the audit log.
	WhySHA256 string `json:"why_sha256"`
	// Ticket references the change that explains it, when there is one.
	Ticket string `json:"ticket,omitempty"`
	// Fields are the fields the sanitised events carry, sorted: what a rule
	// can be measured on.
	Fields []string `json:"fields"`
	// Transformed are the fields at least one of whose values sanitising
	// changed: a rule comparing one of them with a literal is measurable
	// only if this session's fidelity check ran it.
	Transformed []string `json:"transformed,omitempty"`
	// Dropped are the fields the raw events carried that sanitising
	// removed, because no rule read them at capture: a rule reading one of
	// them cannot be measured on this session.
	Dropped []string `json:"dropped,omitempty"`
	// Raw are the fields the operator asked to keep unsanitised.
	Raw []string `json:"raw,omitempty"`
	// Fidelity is the raw-against-sanitised check.
	Fidelity Fidelity `json:"fidelity"`
	// Acknowledged are the rules that fired on it at capture and that the
	// operator acknowledged by name.
	Acknowledged []string `json:"acknowledged,omitempty"`
	// Renewals is how many times it has been vouched for again.
	Renewals int `json:"renewals,omitempty"`
}

// Expired reports whether the session no longer counts at t.
func (s Session) Expired(t time.Time) bool { return !t.Before(s.Expires) }

// Check refuses a session whose shapes or numbers do not hold together.
func (s Session) Check() error {
	if !ValidName(s.Name) || !KnownClass(s.Class) || !digestShape.MatchString(s.Digest) {
		return fmt.Errorf("a session has a name, a class from the list, and a digest")
	}
	if s.Events <= 0 || s.Events > MaxSessionEvents || len(s.Sources) == 0 {
		return fmt.Errorf("session %s holds between 1 and %d events from at least one source",
			s.Name, MaxSessionEvents)
	}
	if s.Until.Before(s.Since) || s.Until.Sub(s.Since) > MaxSessionSpan {
		return fmt.Errorf("session %s spans at most %s", s.Name, MaxSessionSpan)
	}
	if !s.Captured.Before(s.Expires) || s.Expires.Sub(s.Captured) > MaxLife+Recapture {
		return fmt.Errorf("session %s expires after its capture and within the limits", s.Name)
	}
	if !pseudoShape.MatchString(s.VouchedBy) || (s.ApprovedBy != "" && !pseudoShape.MatchString(s.ApprovedBy)) ||
		(s.ApprovedBy != "" && (s.ApprovedBy == s.VouchedBy) != s.Alone) || (s.Alone && s.ApprovedBy == "") {
		return fmt.Errorf("session %s is approved by a second person, or by its only "+
			"administrator alone and marked so", s.Name)
	}
	if !digestShape.MatchString(s.WhySHA256) || (s.Ticket != "" && !ValidTicket(s.Ticket)) {
		return fmt.Errorf("session %s names a reason by its digest, and a ticket by its id", s.Name)
	}
	for _, list := range [][]string{s.Sources, s.Fields, s.Transformed, s.Dropped, s.Raw, s.Acknowledged, s.Fidelity.Lost} {
		if !sort.StringsAreSorted(list) {
			return fmt.Errorf("session %s lists its sources and fields sorted", s.Name)
		}
		for i := 1; i < len(list); i++ {
			if list[i] == list[i-1] {
				return fmt.Errorf("session %s lists a source or field twice", s.Name)
			}
		}
	}
	if s.Fidelity.Rules < 0 || (s.Fidelity.Reduced != (len(s.Fidelity.Lost) > 0)) ||
		(s.Fidelity.Set != "" && !digestShape.MatchString(s.Fidelity.Set)) {
		return fmt.Errorf("session %s's fidelity check does not hold together", s.Name)
	}
	if s.Renewals < 0 {
		return fmt.Errorf("session %s counts its renewals", s.Name)
	}
	return nil
}
