// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package revoke watches what happens after something was revoked: whether
// anything still acted as it, and whether the sources that would have seen
// it were listening.
//
// # What is watched, and how
//
// The caller declares the identities to watch, each as an issuer and a
// value (internal/telemetry's ID, the pair the connectors write), and feeds
// every event it reads, in any order. An event is the identity acting when
// its actor is one of them, exactly; nothing looser, because a guess puts
// one principal's actions on another's record.
//
//   - Before the revocation, within the lookback, an act counts toward the
//     source having seen the identity: that source is one whose silence
//     afterwards could mean something.
//   - In the grace after the revocation, nothing is counted.
//   - After the grace, an act is a use, unless the source says it refused
//     or failed it, which is an attempt: the revocation held and somebody
//     still holds the credential.
//
// Separately, every event from every source after the grace marks the
// stretch it fell in as heard, so a source that went silent — down,
// disconnected, its token expired — is told apart from one that was
// listening and saw nothing.
package revoke

import (
	"sort"
	"time"

	"github.com/aertun/aertun/internal/proof"
)

// Window is the period watched and how it is divided.
type Window struct {
	Revoked  time.Time
	Grace    time.Duration
	Until    time.Time
	Lookback time.Duration
	Stretch  time.Duration
}

// From is where counting uses starts: the end of the grace.
func (w Window) From() time.Time { return w.Revoked.Add(w.Grace) }

// Stretches is how many stretches the period after the grace divides into.
func (w Window) Stretches() int { return proof.Stretches(w.Until.Sub(w.From()), w.Stretch) }

// stretch is which stretch a time after the grace falls in: whole stretches,
// with the remainder joined to the last.
func (w Window) stretch(at time.Time) int {
	n := w.Stretches()
	i := int(at.Sub(w.From()) / w.Stretch)
	return min(i, n-1)
}

type source struct {
	before, uses, refused int
	heard                 []bool
	complete, account     bool
}

// Watch accumulates what one revocation's sources showed.
type Watch struct {
	w       Window
	ids     map[string]bool
	sources map[string]*source
	uses    []proof.RevocationUse
}

// New starts a watch for the identities, each issuer:value.
func New(w Window, identities []string) *Watch {
	ids := map[string]bool{}
	for _, id := range identities {
		ids[id] = true
	}
	return &Watch{w: w, ids: ids, sources: map[string]*source{}}
}

func (wa *Watch) source(name string) *source {
	s, ok := wa.sources[name]
	if !ok {
		s = &source{heard: make([]bool, wa.w.Stretches())}
		wa.sources[name] = s
	}
	return s
}

// Complete marks a source whose silence is evidence without stretches:
// this program's own audit log, which every act through it passes.
func (wa *Watch) Complete(name string) { wa.source(name).complete = true }

// Account marks a source that is the subject's own account of itself, which
// may refute a revocation and never supports one.
func (wa *Watch) Account(name string) { wa.source(name).account = true }

// Event is one event read: its source, its actor as issuer:value (empty when
// it names none), when it happened, and whether the source says it was
// refused or failed.
func (wa *Watch) Event(name, actor string, at time.Time, refused bool) {
	from := wa.w.From()
	after := !at.Before(from) && at.Before(wa.w.Until)
	acted := actor != "" && wa.ids[actor]
	if !after && !acted {
		return
	}
	s := wa.source(name)
	if after {
		s.heard[wa.w.stretch(at)] = true
	}
	switch {
	case !acted:
	case after && refused:
		s.refused++
	case after:
		s.uses++
		wa.uses = append(wa.uses, proof.RevocationUse{Source: name, Identity: actor, At: at})
	case at.Before(wa.w.Revoked) && !at.Before(wa.w.Revoked.Add(-wa.w.Lookback)):
		s.before++
	}
}

// Result is what the sources showed: those that saw the identity at all,
// and the complete ones, by name; and every use, in time order. A source
// that only delivered other events after the grace is not listed — it had
// nothing to say about this identity either way — and neither is the
// subject's own account when it said nothing.
func (wa *Watch) Result() ([]proof.RevocationSource, []proof.RevocationUse) {
	var out []proof.RevocationSource
	for name, s := range wa.sources {
		if s.before+s.uses+s.refused == 0 && !s.complete {
			continue
		}
		quiet := 0
		if !s.complete {
			for _, h := range s.heard {
				if !h {
					quiet++
				}
			}
		}
		out = append(out, proof.RevocationSource{Source: name, Before: s.before, Uses: s.uses,
			Refused: s.refused, Quiet: quiet, Complete: s.complete, Account: s.account})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	uses := append([]proof.RevocationUse{}, wa.uses...)
	sort.SliceStable(uses, func(i, j int) bool { return uses[i].At.Before(uses[j].At) })
	return out, uses
}
