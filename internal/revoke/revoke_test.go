// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package revoke

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func window() Window {
	return Window{Revoked: t0, Grace: 5 * time.Minute, Until: t0.Add(4*time.Hour + 5*time.Minute),
		Lookback: 24 * time.Hour, Stretch: time.Hour}
}

// Before, in the grace and after: an act counts toward the source having
// seen the identity, is ignored, or is a use — or an attempt, when the
// source refused it. Only the declared pair matches.
func TestWhereAnActFallsDecidesWhatItIs(t *testing.T) {
	wa := New(window(), []string{"okta:00u1"})
	wa.Event("okta/system-log", "okta:00u1", t0.Add(-2*time.Hour), false)  // before
	wa.Event("okta/system-log", "okta:00u1", t0.Add(-48*time.Hour), false) // beyond the lookback
	wa.Event("okta/system-log", "okta:00u1", t0.Add(2*time.Minute), false) // in the grace
	wa.Event("okta/system-log", "okta:00u1", t0.Add(90*time.Minute), true) // refused
	wa.Event("okta/system-log", "okta:00u1", t0.Add(3*time.Hour), false)   // a use
	wa.Event("okta/system-log", "entra:00u1", t0.Add(3*time.Hour), false)  // another issuer's id
	wa.Event("okta/system-log", "", t0.Add(10*time.Minute), false)         // heard, nobody
	wa.Event("okta/system-log", "okta:00u9", t0.Add(4*time.Hour), false)   // heard, somebody else
	wa.Event("github/audit", "github:someone", t0.Add(time.Hour), false)   // never saw it: not listed
	sources, uses := wa.Result()
	if len(sources) != 1 {
		t.Fatalf("%+v", sources)
	}
	s := sources[0]
	if s.Source != "okta/system-log" || s.Before != 1 || s.Uses != 1 || s.Refused != 1 || s.Quiet != 0 {
		t.Errorf("%+v", s)
	}
	if len(uses) != 1 || !uses[0].At.Equal(t0.Add(3*time.Hour)) || uses[0].Identity != "okta:00u1" {
		t.Errorf("%+v", uses)
	}
}

// A stretch with no event from a source is quiet; the remainder of the
// period joins the last stretch, so an event in it hears the last stretch.
func TestASilentStretchIsCounted(t *testing.T) {
	wa := New(window(), []string{"okta:00u1"})
	wa.Event("okta/system-log", "okta:00u1", t0.Add(-time.Hour), false)
	wa.Event("okta/system-log", "", t0.Add(10*time.Minute), false)            // stretch 0
	wa.Event("okta/system-log", "", t0.Add(4*time.Hour+4*time.Minute), false) // stretch 3, the remainder
	sources, _ := wa.Result()
	if len(sources) != 1 || sources[0].Quiet != 2 {
		t.Errorf("%+v", sources)
	}
	if n := window().Stretches(); n != 4 {
		t.Errorf("%d stretches", n)
	}
}

// The gate's own log needs no stretches, and the subject's own account is
// listed only when it said something.
func TestCompleteAndOwnAccountSources(t *testing.T) {
	wa := New(window(), []string{"aertun:triage-bot", "otel:triage-bot"})
	wa.Complete("aertun/audit")
	wa.Account("otel/genai")
	wa.Event("aertun/audit", "aertun:triage-bot", t0.Add(-time.Hour), false)
	sources, _ := wa.Result()
	if len(sources) != 1 || !sources[0].Complete || sources[0].Quiet != 0 || sources[0].Before != 1 {
		t.Errorf("%+v", sources)
	}
	wa.Event("otel/genai", "otel:triage-bot", t0.Add(time.Hour), false)
	sources, uses := wa.Result()
	if len(sources) != 2 || !sources[1].Account || sources[1].Uses != 1 || len(uses) != 1 {
		t.Errorf("%+v %+v", sources, uses)
	}
}
