// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// A revocation proof: after something was revoked — an agent disabled with
// the kill switch, or an identity an operator revoked in another system —
// did the access actually stop (internal/revoke)?
//
// # Why
//
// Revoking is the step every incident ends with and nothing checks. A token
// is revoked in one console while a copy keeps working somewhere else; an
// agent's credentials here are cancelled while it carries on with others;
// a vendor says every session was ended. When OAuth tokens were stolen
// from a SaaS integration in 2025, the advice was to treat every connected
// token as compromised, because nobody could show which were still in use.
// This program collects the systems those tokens and identities act in,
// so it can look.
//
// # The claim
//
// Between the end of a grace period after the revocation and the end of the
// period, no source this program collects saw the revoked identity act, and
// every source that had seen it act in the lookback before the revocation
// was delivering events throughout.
//
//   - refuted when anything acted as it after the grace, and the proof
//     names each use by source, identity and time. An attempt the source
//     says it refused or failed is counted beside, not against it: it shows
//     the revocation holding while somebody still holds the credential;
//   - proven when nothing did, at least one source had seen it act before,
//     and every such source delivered at least one event in every stretch
//     of the period — so silence in it means nothing happened, not that it
//     stopped listening. This program's own signed audit log is complete
//     by construction for what an agent does through it: every call passes
//     the gate that writes it, so its silence needs no stretches;
//   - inconclusive otherwise: nothing had seen the identity act, so nothing
//     could show it stopped; a source went quiet for a stretch; or the
//     period after the grace is shorter than MinRevocationPeriod.
//
// # What it does not cover
//
// Systems this program does not collect, and identities nobody declared: an
// agent's identity in another system is joined only on the issuer and value
// the operator declares for it, never guessed, because a guess puts one
// principal's actions on another's record. An agent's own telemetry may
// refute a revocation — it is the agent saying it still acts — but never
// supports one, because an agent that stops reporting has not shown it
// stopped acting.

// RevocationVerifier and its version name this verifier.
const (
	RevocationVerifier        = "aertun/revoke"
	RevocationVerifierVersion = "1"
)

// PredicateRevocation is the predicate of a revocation proof.
const PredicateRevocation = "https://aertun.github.io/proof/revocation/v1"

// MinRevocationPeriod is the shortest period after the grace a proven
// verdict may cover: a revocation shown to hold for a minute has not been
// shown to hold.
const MinRevocationPeriod = time.Hour

// The bounds a revocation proof's numbers are held to.
const (
	MaxRevocationGrace    = 24 * time.Hour
	MaxRevocationLookback = 30 * 24 * time.Hour
	MaxRevocationPeriod   = 31 * 24 * time.Hour
	MinRevocationStretch  = time.Minute
	MaxRevocationStretch  = 24 * time.Hour
	// MaxRevocationSources bounds the sources one proof lists.
	MaxRevocationSources = 64
	// MaxRevocationIdentities bounds the identities one proof matches on.
	MaxRevocationIdentities = 16
)

// The kinds of revocation.
const (
	RevokedAgent    = "agent"
	RevokedIdentity = "identity"
)

var (
	issuerShape    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	valueShape     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$`)
	connectorShape = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,63}$`)
)

// ValidIdentity reports whether an identity can be carried in a revocation
// proof: an issuer and a value, issuer:value, each in a strict shape. The
// value is an identifier — a user id, a login, an application id — not a
// display name, so a space is not in it.
func ValidIdentity(s string) bool {
	issuer, value, ok := strings.Cut(s, ":")
	return ok && issuerShape.MatchString(issuer) && valueShape.MatchString(value)
}

// ValidSource reports whether a source's name can be carried in a proof.
func ValidSource(s string) bool { return connectorShape.MatchString(s) }

// RevocationSource is what one source showed.
type RevocationSource struct {
	Source string `json:"source"`
	// Before is how many times it saw the identity act in the lookback.
	Before int `json:"seen_before"`
	// Uses is how many times it saw the identity act after the grace, and
	// Refused how many attempts it says it refused or failed.
	Uses    int `json:"uses"`
	Refused int `json:"refused"`
	// Quiet is how many stretches of the period it delivered nothing in.
	Quiet int `json:"quiet_stretches"`
	// Complete marks this program's own audit log: every act it records
	// passes the gate that writes it, so its silence is evidence.
	Complete bool `json:"complete,omitempty"`
	// Account marks the subject's own account of itself — an agent's
	// telemetry — which may refute and never supports.
	Account bool `json:"own_account,omitempty"`
}

// watched reports whether a source's silence after the grace could count:
// it saw the identity act before, and it is not the subject's own account.
// covers adds that it was listening throughout.
func (s RevocationSource) watched() bool { return s.Before > 0 && !s.Account }
func (s RevocationSource) covers() bool  { return s.watched() && (s.Complete || s.Quiet == 0) }

// RevocationEvidence is what a revocation proof rests on.
type RevocationEvidence struct {
	Kind string `json:"kind"`
	// Name is the revoked agent, or the identity revoked.
	Name string `json:"name"`
	// Identities are every issuer:value it was matched on.
	Identities []string `json:"identities"`
	Revoked    string   `json:"revoked"`
	// RevokedEntry is the audit entry that recorded the revocation, when
	// this program made it.
	RevokedEntry int    `json:"revoked_entry,omitempty"`
	Grace        int    `json:"grace_seconds"`
	Until        string `json:"until"`
	Lookback     int    `json:"lookback_seconds"`
	Stretch      int    `json:"stretch_seconds"`
	// Stretches is how many stretches the period was divided into.
	Stretches int                `json:"stretches"`
	Sources   []RevocationSource `json:"sources"`
	Uses      int                `json:"uses"`
	Refused   int                `json:"refused"`
	MinPeriod int                `json:"min_period_seconds"`
}

// RevocationUse is one act after the grace, named by source, identity and
// time.
type RevocationUse struct {
	Source, Identity string
	At               time.Time
}

// RevocationInput is what a revocation proof is made from.
type RevocationInput struct {
	Kind, Name   string
	Identities   []string
	Revoked      time.Time
	RevokedEntry int
	Grace        time.Duration
	Until        time.Time
	Lookback     time.Duration
	Stretch      time.Duration
	Stretches    int
	Sources      []RevocationSource
	Uses         []RevocationUse
	// Lines are the observations read, one JSON object per line: what the
	// subject's digest is over.
	Lines     []byte
	Materials []Material
	Program   string
	Now       time.Time
}

// Stretches is how many stretches a period divides into: whole stretches,
// the remainder joined to the last, and one when the period is shorter
// than a stretch.
func Stretches(period, stretch time.Duration) int {
	if stretch <= 0 || period <= 0 {
		return 0
	}
	return max(1, int(period/stretch))
}

func useFailure(u RevocationUse) string {
	return "use after revocation: " + u.Source + " as " + u.Identity + " at " +
		u.At.UTC().Format(time.RFC3339Nano)
}

func validUseFailure(s string, identities []string, sources map[string]int) bool {
	rest, ok := strings.CutPrefix(s, "use after revocation: ")
	if !ok {
		return false
	}
	src, rest, ok := strings.Cut(rest, " as ")
	if !ok || sources[src] == 0 {
		return false
	}
	id, when, ok := strings.Cut(rest, " at ")
	if !ok || !containsString(identities, id) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, when)
	return err == nil
}

// ProveRevocation builds the unsigned statement.
func ProveRevocation(in RevocationInput) (*Statement, error) {
	ev := &RevocationEvidence{Kind: in.Kind, Name: in.Name,
		Identities: append([]string{}, in.Identities...), Revoked: instant(in.Revoked),
		RevokedEntry: in.RevokedEntry, Grace: int(in.Grace / time.Second), Until: instant(in.Until),
		Lookback: int(in.Lookback / time.Second), Stretch: int(in.Stretch / time.Second),
		Stretches: in.Stretches, Sources: append([]RevocationSource{}, in.Sources...),
		Uses: len(in.Uses), MinPeriod: int(MinRevocationPeriod / time.Second)}
	for _, s := range in.Sources {
		ev.Refused += s.Refused
	}
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	if len(in.Lines) == 0 {
		return nil, fmt.Errorf("nothing was read, so there is nothing to sign")
	}
	var uses []string
	for _, u := range in.Uses {
		uses = append(uses, useFailure(u))
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: SHA256(in.Lines)}},
		PredicateType: PredicateRevocation,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: RevocationVerifier, Version: RevocationVerifierVersion,
				Program: in.Program},
			Materials:  append([]Material{}, in.Materials...),
			Checks:     ev.checks(uses),
			Revocation: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *RevocationEvidence) subject() string { return ev.Kind + "/" + ev.Name }

// instant is a time as exactly as it was recorded: a revocation's moment is
// the audit entry's, to the nanosecond, and rounding it would move uses
// across it.
func instant(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (ev *RevocationEvidence) times() (revoked, until time.Time) {
	revoked, _ = time.Parse(time.RFC3339Nano, ev.Revoked)
	until, _ = time.Parse(time.RFC3339Nano, ev.Until)
	return revoked, until
}

// period is how long the proof watched, after the grace.
func (ev *RevocationEvidence) period() time.Duration {
	revoked, until := ev.times()
	return until.Sub(revoked.Add(time.Duration(ev.Grace) * time.Second))
}

// wellFormed refuses evidence whose shapes or numbers do not hold together,
// on either side of signing.
func (ev *RevocationEvidence) wellFormed() error {
	switch ev.Kind {
	case RevokedAgent:
		if !agentShape.MatchString(ev.Name) {
			return fmt.Errorf("a revoked agent is named as the registry names it")
		}
	case RevokedIdentity:
		if !ValidIdentity(ev.Name) || len(ev.Identities) == 0 || ev.Identities[0] != ev.Name {
			return fmt.Errorf("a revoked identity is named issuer:value, first among those matched")
		}
		if ev.RevokedEntry != 0 {
			return fmt.Errorf("an identity revoked elsewhere has no entry in this program's log")
		}
	default:
		return fmt.Errorf("a revocation is of an agent or an identity")
	}
	if len(ev.Identities) == 0 || len(ev.Identities) > MaxRevocationIdentities {
		return fmt.Errorf("a revocation is matched on between 1 and %d identities", MaxRevocationIdentities)
	}
	seen := map[string]bool{}
	for _, id := range ev.Identities {
		if !ValidIdentity(id) || seen[id] {
			return fmt.Errorf("each identity is issuer:value, once")
		}
		seen[id] = true
	}
	revoked, err1 := time.Parse(time.RFC3339Nano, ev.Revoked)
	until, err2 := time.Parse(time.RFC3339Nano, ev.Until)
	grace := time.Duration(ev.Grace) * time.Second
	stretch := time.Duration(ev.Stretch) * time.Second
	lookback := time.Duration(ev.Lookback) * time.Second
	if err1 != nil || err2 != nil || instant(revoked) != ev.Revoked || instant(until) != ev.Until || ev.Grace < 0 || grace > MaxRevocationGrace ||
		!revoked.Add(grace).Before(until) || until.Sub(revoked.Add(grace)) > MaxRevocationPeriod ||
		stretch < MinRevocationStretch || stretch > MaxRevocationStretch ||
		lookback < time.Hour || lookback > MaxRevocationLookback || ev.RevokedEntry < 0 {
		return fmt.Errorf("a revocation names when it happened, a grace of at most %s, a period "+
			"after it of at most %d days, a stretch between a minute and a day, and a lookback "+
			"between an hour and %d days", MaxRevocationGrace, int(MaxRevocationPeriod.Hours()/24),
			int(MaxRevocationLookback.Hours()/24))
	}
	if ev.Stretches != Stretches(ev.period(), stretch) {
		return fmt.Errorf("the period does not divide into the stretches the proof says")
	}
	if ev.MinPeriod != int(MinRevocationPeriod/time.Second) {
		return fmt.Errorf("the evidence's minimum period is not this version's")
	}
	if len(ev.Sources) > MaxRevocationSources {
		return fmt.Errorf("a revocation lists at most %d sources", MaxRevocationSources)
	}
	names := map[string]bool{}
	uses, refused := 0, 0
	for _, s := range ev.Sources {
		if !ValidSource(s.Source) || names[s.Source] {
			return fmt.Errorf("each source is named once, in a source's shape")
		}
		names[s.Source] = true
		if s.Before < 0 || s.Uses < 0 || s.Refused < 0 || s.Quiet < 0 || s.Quiet > ev.Stretches ||
			(s.Complete && (s.Account || s.Quiet != 0)) {
			return fmt.Errorf("source %s's counts do not hold together", s.Source)
		}
		uses += s.Uses
		refused += s.Refused
	}
	if uses != ev.Uses || refused != ev.Refused {
		return fmt.Errorf("the uses and refusals are not the sum of the sources'")
	}
	return nil
}

func (ev *RevocationEvidence) verdict() Verdict {
	if ev.Uses > 0 {
		return Refuted
	}
	if ev.period() < MinRevocationPeriod {
		return Inconclusive
	}
	watched := 0
	for _, s := range ev.Sources {
		if !s.watched() {
			continue
		}
		watched++
		if !s.covers() {
			return Inconclusive
		}
	}
	if watched == 0 {
		return Inconclusive
	}
	return Proven
}

func (ev *RevocationEvidence) what() string {
	if ev.Kind == RevokedAgent {
		return "agent " + ev.Name
	}
	return ev.Name
}

func (ev *RevocationEvidence) claim() string {
	revoked, _ := ev.times()
	from := revoked.Add(time.Duration(ev.Grace) * time.Second)
	return fmt.Sprintf("Between %s and %s, after %s was revoked at %s, no source this program "+
		"collects saw it act as %s, and every source that had seen it act in the %s before "+
		"was delivering events throughout.", instant(from), ev.Until, ev.what(), ev.Revoked,
		strings.Join(ev.Identities, ", "), span(time.Duration(ev.Lookback)*time.Second))
}

// span says a duration in the largest whole unit it is.
func span(d time.Duration) string {
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d%(24*time.Hour) == 0:
		return plural(int(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return plural(int(d/time.Minute), "minute")
	}
	return plural(int(d/time.Second), "second")
}

// checks are the proof's checks, from the evidence and the names of the
// uses after the grace.
func (ev *RevocationEvidence) checks(uses []string) []Check {
	revoked := Check{Name: "revoked", Passed: true}
	if ev.RevokedEntry > 0 {
		revoked.Detail = fmt.Sprintf("%s was disabled at %s, audit entry %d; every credential "+
			"bound to it was revoked with it", ev.what(), ev.Revoked, ev.RevokedEntry)
	} else {
		revoked.Detail = fmt.Sprintf("%s was revoked at %s, as the operator declared", ev.what(), ev.Revoked)
	}
	if ev.Grace > 0 {
		revoked.Detail += fmt.Sprintf("; what happened in the %s after it is not counted, for "+
			"revocations to reach every system and clocks to differ",
			span(time.Duration(ev.Grace)*time.Second))
	}

	noUse := Check{Name: "no-use-after", Passed: ev.Uses == 0,
		Detail: fmt.Sprintf("%d use(s) after the grace", ev.Uses)}
	if ev.Refused > 0 {
		noUse.Detail += fmt.Sprintf("; %d attempt(s) were refused or failed, which shows the "+
			"revocation holding and the credential still being tried", ev.Refused)
	}
	shown, more := capped(uses)
	noUse.Failures = shown
	if more > 0 {
		noUse.Detail += fmt.Sprintf("; %d more not listed", more)
	}

	watch := Check{Name: "sources-watching", Passed: true}
	var parts []string
	watched := 0
	for _, s := range ev.Sources {
		switch {
		case s.Account:
			parts = append(parts, fmt.Sprintf("%s is its own account, which can refute and not support", s.Source))
		case !s.watched():
			parts = append(parts, fmt.Sprintf("%s had not seen it act before", s.Source))
		case s.Complete:
			watched++
			parts = append(parts, fmt.Sprintf("%s saw it act %d time(s) before and records every "+
				"act through this program", s.Source, s.Before))
		default:
			watched++
			parts = append(parts, fmt.Sprintf("%s saw it act %d time(s) before and was quiet in "+
				"%d of %d stretch(es) of %s", s.Source, s.Before, s.Quiet, ev.Stretches,
				span(time.Duration(ev.Stretch)*time.Second)))
		}
	}
	watch.Detail = fmt.Sprintf("%d source(s) had seen it act in the %s before", watched,
		span(time.Duration(ev.Lookback)*time.Second))
	if len(parts) > 0 {
		watch.Detail += ": " + strings.Join(parts, "; ")
	}
	if ev.verdict() == Inconclusive {
		switch {
		case ev.period() < MinRevocationPeriod:
			watch.Detail += fmt.Sprintf("; the period after the grace is shorter than the %s a "+
				"proven verdict needs", span(MinRevocationPeriod))
		case watched == 0:
			watch.Detail += "; nothing had seen it act, so nothing could show it stopped"
		default:
			watch.Detail += "; a source that had seen it act went quiet, so its silence then " +
				"shows nothing"
		}
	}
	return []Check{revoked, noUse, watch}
}

// validate refuses evidence whose numbers do not add up, do not support the
// verdict, or do not account for every word the statement says.
func (ev *RevocationEvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
		return err
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the counts make this %s, not %s", want, s.Predicate.Verdict)
	}
	if len(s.Predicate.Checks) != 3 {
		return fmt.Errorf("a revocation proof has three checks")
	}
	uses := map[string]int{}
	for _, src := range ev.Sources {
		uses[src.Source] = src.Uses
	}
	var listed []string
	for i, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			if i != 1 || !validUseFailure(f, ev.Identities, uses) {
				return fmt.Errorf("a failure in a revocation proof names a use after the grace, " +
					"by a source that saw one and an identity it was matched on, and nothing else")
			}
			listed = append(listed, f)
		}
	}
	if len(listed) != min(ev.Uses, MaxFailures) {
		return fmt.Errorf("the uses listed are not the ones counted")
	}
	pad := append(listed, make([]string, ev.Uses-len(listed))...)
	return sameWords(s, ev.subject(), ev.claim(), ev.checks(pad))
}
