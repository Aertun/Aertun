// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package benign

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/telemetry"
)

// Keep is the field set a rule set reads: every field a detection
// compares, the fields a correlation groups or counts by, and the
// structural fields every event keeps. Sanitising keeps these and drops the
// rest.
func (rs RuleSet) Keep() map[string]bool {
	keep := map[string]bool{}
	for _, f := range Structural {
		keep[f] = true
	}
	for _, r := range rs.Rules {
		for _, f := range r.Fields() {
			keep[f] = true
		}
	}
	for _, c := range rs.Corrs {
		for _, f := range c.GroupBy {
			keep[f] = true
		}
		if c.Field != "" {
			keep[c.Field] = true
		}
	}
	return keep
}

// CaptureInput is one capture: the raw events a selection found, and what
// the person vouching for them says.
type CaptureInput struct {
	Name, Class string
	Events      []telemetry.Event
	Key         []byte
	Rules       RuleSet
	// RawFields are fields to keep unsanitised, by the operator's recorded
	// request; KeepAll keeps every field, not only those the rules read.
	RawFields map[string]bool
	KeepAll   bool
	// Acknowledge names each alert-tier rule that fires on the raw events
	// and that the person has looked at: one firing and not named refuses
	// the capture.
	Acknowledge map[string]bool
	// AcceptLoss accepts rule outcomes sanitising changed; the session is
	// then marked reduced and names them.
	AcceptLoss  bool
	Why, Ticket string
	By          string
	Life        time.Duration
	Now         time.Time
}

// Capture is the sanitised session, its events, and what the checks found.
type Capture struct {
	Session Session
	Events  []telemetry.Event
	// FidelityRules are the rule digests the check ran: the bundle's
	// fidelity set for this session.
	FidelityRules []string
	// Fired are the alert-tier rules that fired on the raw events.
	Fired []string
}

// Digest is the content address of a list of events: the SHA-256 of their
// canonical JSON.
func Digest(events []telemetry.Event) (string, error) {
	b, err := json.Marshal(events)
	if err != nil {
		return "", err
	}
	c, err := jcs.Canonicalize(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// WhyDigest is the digest a reason is named by in a bundle.
func WhyDigest(why string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(why)))
	return hex.EncodeToString(sum[:])
}

// NewCapture sanitises one selection into a session, refusing it when an
// alert-tier rule fires on it unacknowledged, or when sanitising changed an
// outcome and the loss was not accepted.
func NewCapture(in CaptureInput) (*Capture, error) {
	switch {
	case !ValidName(in.Name):
		return nil, fmt.Errorf("a session's name is lower-case letters, digits and hyphens, 2 to 63 long")
	case !KnownClass(in.Class):
		return nil, fmt.Errorf("the class is one of %s", strings.Join(Classes, ", "))
	case strings.TrimSpace(in.Why) == "":
		return nil, fmt.Errorf("vouching for a session as benign needs a reason: it can block a " +
			"rule that would catch what it holds")
	case in.Ticket != "" && !ValidTicket(in.Ticket):
		return nil, fmt.Errorf("a ticket is an identifier (letters, digits, . _ : / # -), not a sentence")
	case strings.TrimSpace(in.By) == "":
		return nil, fmt.Errorf("somebody vouches for a session")
	}
	life := in.Life
	if life == 0 {
		life = DefaultLife
	}
	if life < time.Hour || life > MaxLife {
		return nil, fmt.Errorf("a session is vouched for between an hour and %d days", int(MaxLife.Hours()/24))
	}
	if len(in.Events) == 0 {
		return nil, fmt.Errorf("the selection found no events")
	}
	if len(in.Events) > MaxSessionEvents {
		return nil, fmt.Errorf("the selection found %d events; a session holds at most %d — a "+
			"workflow, not a day — so narrow it", len(in.Events), MaxSessionEvents)
	}
	since, until := in.Events[0].Time, in.Events[0].Time
	for _, e := range in.Events {
		if e.Time.Before(since) {
			since = e.Time
		}
		if e.Time.After(until) {
			until = e.Time
		}
	}
	if until.Sub(since) > MaxSessionSpan {
		return nil, fmt.Errorf("the selection spans %s; a session spans at most %s", until.Sub(since).Round(time.Second), MaxSessionSpan)
	}

	rawOut, err := Evaluate(in.Rules, in.Events)
	if err != nil {
		return nil, err
	}
	var unacked []string
	for _, id := range rawOut.Fired {
		if !in.Acknowledge[id] {
			unacked = append(unacked, id)
		}
	}
	if len(unacked) > 0 {
		return nil, fmt.Errorf("%d rule(s) fire on this selection as it is: %s. A session that "+
			"raises alerts is not vouched for unseen — look at each, then name it with "+
			"--acknowledge RULE if it is benign here", len(unacked), strings.Join(unacked, ", "))
	}

	keep := in.Rules.Keep()
	if in.KeepAll {
		keep = nil
	}
	san, err := NewSanitiser(in.Key, keep, in.RawFields)
	if err != nil {
		return nil, err
	}
	clean := make([]telemetry.Event, len(in.Events))
	transformed, dropped, sources := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, e := range in.Events {
		var ch, dr []string
		clean[i], ch, dr = san.Event(e)
		for _, f := range ch {
			transformed[f] = true
		}
		for _, f := range dr {
			dropped[f] = true
		}
		sources[e.Source] = true
	}
	cleanOut, err := Evaluate(in.Rules, clean)
	if err != nil {
		return nil, err
	}
	mismatches := Compare(in.Rules, in.Events, clean, rawOut, cleanOut)
	lost := map[string]bool{}
	var why []string
	for _, m := range mismatches {
		if !lost[m.Rule] {
			why = append(why, fmt.Sprintf("%s (fields %s)", m.Rule, strings.Join(m.Fields, ", ")))
		}
		lost[m.Rule] = true
	}
	if len(lost) > 0 && !in.AcceptLoss {
		return nil, fmt.Errorf("sanitising changed what %d rule(s) do on this session: %s. Keep "+
			"the field as it is with --raw FIELD (recorded on the session), or accept the "+
			"loss with --accept-fidelity-loss and the session is marked reduced",
			len(lost), strings.Join(why, "; "))
	}
	digest, err := Digest(clean)
	if err != nil {
		return nil, err
	}
	ruleDigests, err := in.Rules.Digests()
	if err != nil {
		return nil, err
	}
	s := Session{Name: in.Name, Class: in.Class, Digest: digest, Events: len(clean),
		Sources: sortedKeys(sources), Since: since.UTC(), Until: until.UTC(),
		Captured: in.Now.UTC(), Expires: in.Now.UTC().Add(life),
		VouchedBy: san.Person(in.By), WhySHA256: WhyDigest(in.Why), Ticket: in.Ticket,
		Fields: FieldsOf(clean), Transformed: sortedKeys(transformed), Dropped: sortedKeys(dropped),
		Raw:      sortedKeys(in.RawFields),
		Fidelity: Fidelity{Set: SetDigest(ruleDigests), Rules: len(ruleDigests), Reduced: len(lost) > 0, Lost: sortedKeys(lost)},
	}
	for _, id := range rawOut.Fired {
		s.Acknowledged = append(s.Acknowledged, id)
	}
	if err := s.Check(); err != nil {
		return nil, err
	}
	return &Capture{Session: s, Events: clean, FidelityRules: ruleDigests, Fired: rawOut.Fired}, nil
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
