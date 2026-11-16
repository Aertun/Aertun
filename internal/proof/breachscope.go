// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// A breach-scope proof: a vendor's disclosure of its own breach — the
// window the attacker was active in, the indicators it left, and what the
// vendor told this organisation about being affected — held against this
// organisation's own events.
//
// # Why
//
// When a supplier is breached, its customers learn the scope by being told.
// The first scope is often revised: a window widened, more tenants added,
// "no customer data" walked back. Meanwhile each customer holds logs that
// could have said so on the first day, and nobody reads them against the
// disclosure. This program collects those logs and already checks claims
// against them (internal/evidence); a disclosure is a set of claims.
//
// # The claim
//
// No indicator the vendor named was seen in this organisation's events
// outside the window it gave, and — when it said this organisation was not
// affected — none was seen inside it either.
//
//   - refuted when an indicator was seen before or after the window, or
//     inside it when the vendor said this organisation was not affected,
//     each named with how many events carried it;
//   - proven when nothing contradicts the disclosure and the store holds
//     the whole of each period — the margin before the window, the window,
//     and the margin after it — so not finding an indicator means it was
//     not there;
//   - inconclusive otherwise, saying which period the store does not hold.
//
// The indicators and the reference are the vendor's words, strictly parsed:
// an indicator is carried only in its canonical form, and the proving
// ground labels them as written outside.

// BreachScopeVerifier and its version name this verifier.
const (
	BreachScopeVerifier        = "aertun/breach-scope"
	BreachScopeVerifierVersion = "1"
)

// PredicateBreachScope is the predicate of a breach-scope proof.
const PredicateBreachScope = "https://aertun.github.io/proof/breach-scope/v1"

// What a vendor told this organisation about being affected.
const (
	ToldAffected    = "affected"
	ToldNotAffected = "not-affected"
	ToldUnstated    = "unstated"
)

// MaxIndicators bounds the indicators one disclosure names.
const MaxIndicators = 500

// MaxBreachMargin bounds the margin either side of the window.
const MaxBreachMargin = 90 * 24 * time.Hour

var referenceShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// ValidReference reports whether s can name a disclosure: an advisory or
// notice identifier, not a title.
func ValidReference(s string) bool { return referenceShape.MatchString(s) }

// BreachIndicator is one indicator the vendor named, and where it was seen.
type BreachIndicator struct {
	// Type is the kind of observable: an address, a domain, a digest, an
	// email address.
	Type string `json:"type"`
	// Value is the indicator in its canonical form.
	Value string `json:"value"`
	// Before, During and After are how many events carried it in the margin
	// before the window, in the window, and in the margin after it.
	Before int `json:"before"`
	During int `json:"during"`
	After  int `json:"after"`
}

// BreachScopeEvidence is what a breach-scope proof rests on.
type BreachScopeEvidence struct {
	// Vendor is the vendor, by the short name the operator gave it.
	Vendor string `json:"vendor"`
	// Reference is the disclosure's identifier: an advisory or notice id.
	Reference string `json:"reference"`
	// Since and Until are the window the vendor said the attacker was
	// active in, RFC 3339; Until is not included.
	Since string `json:"since"`
	Until string `json:"until"`
	// Margin is how far before and after the window was searched, in
	// seconds.
	Margin int `json:"margin_seconds"`
	// Told is what the vendor told this organisation: affected,
	// not-affected or unstated.
	Told string `json:"told"`
	// Indicators are each indicator and how many events carried it.
	Indicators []BreachIndicator `json:"indicators"`
	// HeldBefore, HeldDuring and HeldAfter say whether the store holds the
	// whole of the margin before, the window, and the margin after: where
	// it does not, not finding an indicator shows nothing.
	HeldBefore bool `json:"held_before"`
	HeldDuring bool `json:"held_during"`
	HeldAfter  bool `json:"held_after"`
	// Events is how many events in the three periods were read.
	Events int `json:"events"`
}

// BreachScopeInput is what a breach-scope proof is made from.
type BreachScopeInput struct {
	Evidence BreachScopeEvidence
	// Disclosure is the disclosure as handed in: what the subject's digest
	// is over.
	Disclosure []byte
	Materials  []Material
	Program    string
	Now        time.Time
}

// ProveBreachScope builds the unsigned statement.
func ProveBreachScope(in BreachScopeInput) (*Statement, error) {
	ev := in.Evidence
	ev.Indicators = append([]BreachIndicator{}, ev.Indicators...)
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	if len(in.Disclosure) == 0 {
		return nil, fmt.Errorf("there is no disclosure to sign about")
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: SHA256(in.Disclosure)}},
		PredicateType: PredicateBreachScope,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: BreachScopeVerifier, Version: BreachScopeVerifierVersion,
				Program: in.Program},
			Materials:   append([]Material{}, in.Materials...),
			Checks:      ev.checks(),
			BreachScope: &ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *BreachScopeEvidence) subject() string {
	return "disclosure/" + ev.Vendor + "/" + ev.Reference
}

func (ev *BreachScopeEvidence) wellFormed() error {
	if !sourceShape.MatchString(ev.Vendor) || !ValidReference(ev.Reference) {
		return fmt.Errorf("a disclosure names its vendor by a short name and itself by an identifier")
	}
	since, err1 := time.Parse(time.RFC3339, ev.Since)
	until, err2 := time.Parse(time.RFC3339, ev.Until)
	margin := time.Duration(ev.Margin) * time.Second
	if err1 != nil || err2 != nil || day(since) != ev.Since || day(until) != ev.Until ||
		!since.Before(until) || ev.Margin <= 0 || margin > MaxBreachMargin {
		return fmt.Errorf("a disclosure gives a window, and the search a margin of at most %d days",
			int(MaxBreachMargin.Hours()/24))
	}
	switch ev.Told {
	case ToldAffected, ToldNotAffected, ToldUnstated:
	default:
		return fmt.Errorf("what the vendor told is affected, not-affected or unstated")
	}
	if len(ev.Indicators) == 0 || len(ev.Indicators) > MaxIndicators {
		return fmt.Errorf("a disclosure names between 1 and %d indicators", MaxIndicators)
	}
	seen := map[string]bool{}
	for _, in := range ev.Indicators {
		v, ok := CanonicalObservable(in.Type, in.Value)
		if !ok || v != in.Value || seen[in.Type+" "+in.Value] || in.Before < 0 || in.During < 0 ||
			in.After < 0 {
			return fmt.Errorf("each indicator is named once, in its canonical form, with counts")
		}
		seen[in.Type+" "+in.Value] = true
	}
	if ev.Events < 0 {
		return fmt.Errorf("the events read are counted")
	}
	return nil
}

func (ev *BreachScopeEvidence) outside() (n int) {
	for _, in := range ev.Indicators {
		if in.Before+in.After > 0 {
			n++
		}
	}
	return n
}

func (ev *BreachScopeEvidence) inside() (n int) {
	for _, in := range ev.Indicators {
		if in.During > 0 {
			n++
		}
	}
	return n
}

func (ev *BreachScopeEvidence) verdict() Verdict {
	if ev.outside() > 0 || (ev.Told == ToldNotAffected && ev.inside() > 0) {
		return Refuted
	}
	if ev.HeldBefore && ev.HeldDuring && ev.HeldAfter {
		return Proven
	}
	return Inconclusive
}

func (ev *BreachScopeEvidence) claim() string {
	s := fmt.Sprintf("No indicator in %s's disclosure %s was seen in this organisation's "+
		"events outside the window it gave, %s to %s", ev.Vendor, ev.Reference, ev.Since, ev.Until)
	if ev.Told == ToldNotAffected {
		s += ", nor inside it, as the vendor said this organisation was not affected"
	}
	return s + "."
}

func (ev *BreachScopeEvidence) checks() []Check {
	margin := span(time.Duration(ev.Margin) * time.Second)
	window := Check{Name: "window", Passed: ev.outside() == 0,
		Detail: fmt.Sprintf("%d indicator(s) searched for in the %s before the window and the %s "+
			"after it; %d seen outside it", len(ev.Indicators), margin, margin, ev.outside())}
	told := Check{Name: "told", Passed: !(ev.Told == ToldNotAffected && ev.inside() > 0)}
	for _, in := range ev.Indicators {
		if in.Before > 0 {
			window.Failures = append(window.Failures, fmt.Sprintf("seen before the window: %s %s, "+
				"in %d event(s)", in.Type, in.Value, in.Before))
		}
		if in.After > 0 {
			window.Failures = append(window.Failures, fmt.Sprintf("seen after the window: %s %s, "+
				"in %d event(s)", in.Type, in.Value, in.After))
		}
		if in.During > 0 && ev.Told == ToldNotAffected {
			told.Failures = append(told.Failures, fmt.Sprintf("seen in the window: %s %s, in %d "+
				"event(s)", in.Type, in.Value, in.During))
		}
	}
	shown, more := capped(window.Failures)
	window.Failures = shown
	if more > 0 {
		window.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	switch ev.Told {
	case ToldNotAffected:
		told.Detail = fmt.Sprintf("the vendor said this organisation was not affected; %d "+
			"indicator(s) were seen in the window", ev.inside())
	case ToldAffected:
		told.Detail = fmt.Sprintf("the vendor said this organisation was affected; %d "+
			"indicator(s) were seen in the window", ev.inside())
	default:
		told.Detail = fmt.Sprintf("the vendor did not say whether this organisation was affected; "+
			"%d indicator(s) were seen in the window", ev.inside())
	}
	shown, more = capped(told.Failures)
	told.Failures = shown
	if more > 0 {
		told.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	var missing []string
	for _, p := range []struct {
		held bool
		name string
	}{{ev.HeldBefore, "the margin before"}, {ev.HeldDuring, "the window"}, {ev.HeldAfter, "the margin after"}} {
		if !p.held {
			missing = append(missing, p.name)
		}
	}
	held := Check{Name: "held", Passed: true,
		Detail: fmt.Sprintf("%d event(s) read", ev.Events)}
	if len(missing) == 0 {
		held.Detail += "; the store holds the whole of the window and both margins, so an " +
			"indicator not found was not there"
	} else {
		held.Detail += "; the store does not hold all of " + strings.Join(missing, ", ") +
			" — it has not all passed, or was not all collected — so not finding an " +
			"indicator there shows nothing"
	}
	return []Check{window, told, held}
}

// validate rebuilds every word, failures included — they come from the
// evidence alone — and refuses a statement that says anything else.
func (ev *BreachScopeEvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
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
