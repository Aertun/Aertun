// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/mcp"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
)

func revocationProof(t *testing.T, root string, args ...string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "revocation.json")
	err := cmdProof(root, append([]string{"revocation", "--key", key, "--public-key", pub,
		"--out", at}, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// oktaAct is the identity provider's record of somebody acting; heard is any
// other event it delivered, which shows it was listening.
func oktaAct(at time.Time, who string, d telemetry.Disposition) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: "okta/system-log",
		Class: telemetry.ClassAuthentication, Disposition: d,
		Actor: telemetry.ID{Issuer: "okta", Value: who}}
}

func heard(from, to time.Time, every time.Duration) []telemetry.Event {
	var evs []telemetry.Event
	for at := from; at.Before(to); at = at.Add(every) {
		evs = append(evs, oktaAct(at, "00u-somebody-else", telemetry.DispositionAllowed))
	}
	return evs
}

// An identity revoked in another system, seen acting there before and not
// after, by a source that kept delivering throughout: proven, and kept.
func TestAnIdentityThatStoppedIsProvenRevoked(t *testing.T) {
	root := reconcileSite(t)
	now := time.Now().UTC().Truncate(time.Second)
	revoked := now.Add(-3 * time.Hour)
	evs := append(heard(revoked, now, 20*time.Minute),
		oktaAct(revoked.Add(-26*time.Hour), "00u1", telemetry.DispositionAllowed),
		oktaAct(revoked.Add(-time.Hour), "00u1", telemetry.DispositionAllowed),
		// Somebody still has the credential, and the provider refuses it.
		oktaAct(revoked.Add(time.Hour), "00u1", telemetry.DispositionBlocked))
	appendAgentEvents(t, root, evs...)
	st, err := revocationProof(t, root, "--identity", "okta:00u1", "--at", revoked.Format(time.RFC3339))
	ev := st.Predicate.Revocation
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Uses != 0 || ev.Refused != 1 ||
		len(ev.Sources) != 1 || ev.Sources[0].Before != 2 || ev.Sources[0].Quiet != 0 ||
		st.Subject[0].Name != "identity/okta:00u1" {
		t.Fatalf("%v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks)
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 1 || kept[0].Statement == nil || kept[0].Statement.Predicate.Revocation == nil {
		t.Errorf("the proof was not kept: %+v", kept)
	}
}

// One use after the grace refutes, by name, from whichever identity the
// revoked principal acted as.
func TestAUseAfterTheGraceRefutesTheRevocation(t *testing.T) {
	root := reconcileSite(t)
	now := time.Now().UTC().Truncate(time.Second)
	revoked := now.Add(-3 * time.Hour)
	use := revoked.Add(2 * time.Hour)
	evs := append(heard(revoked, now, 20*time.Minute),
		oktaAct(revoked.Add(-time.Hour), "00u1", telemetry.DispositionAllowed),
		oktaAct(revoked.Add(2*time.Minute), "00u1", telemetry.DispositionAllowed), // in the grace
		telemetry.Event{Time: use, Received: use, Source: "github/audit", Class: telemetry.ClassAPIActivity,
			Actor: telemetry.ID{Issuer: "github", Value: "dana-ops"}})
	appendAgentEvents(t, root, evs...)
	st, err := revocationProof(t, root, "--identity", "okta:00u1", "--identity", "github:dana-ops",
		"--at", revoked.Format(time.RFC3339))
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.Revocation.Uses != 1 {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Revocation)
	}
	want := "use after revocation: github/audit as github:dana-ops at " + use.Format(time.RFC3339Nano)
	if f := st.Predicate.Checks[1].Failures; len(f) != 1 || f[0] != want {
		t.Errorf("named %q, want %q", f, want)
	}
}

// A source that saw the identity before and then went silent cannot show
// that nothing happened while it was silent.
func TestASourceThatWentSilentLeavesItInconclusive(t *testing.T) {
	root := reconcileSite(t)
	now := time.Now().UTC().Truncate(time.Second)
	revoked := now.Add(-5 * time.Hour)
	evs := append(heard(revoked, revoked.Add(2*time.Hour), 20*time.Minute),
		oktaAct(revoked.Add(-time.Hour), "00u1", telemetry.DispositionAllowed))
	appendAgentEvents(t, root, evs...)
	st, err := revocationProof(t, root, "--identity", "okta:00u1", "--at", revoked.Format(time.RFC3339))
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Revocation.Sources[0].Quiet == 0 ||
		!strings.Contains(st.Predicate.Checks[2].Detail, "went quiet") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}
}

// An agent disabled with the kill switch: a call the agent interface still
// answered for it afterwards refutes, from this program's own log; a call
// it refused is an attempt, not a use; and the agent's own telemetry saying
// it carried on refutes too.
func TestAKilledAgentThatStillActsIsRefuted(t *testing.T) {
	root := reconcileSite(t)
	for range 3 {
		auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings", nil)
	}
	if err := cmdAgent(root, []string{"disable", "triage-bot", "--why", "drill"}); err != nil {
		t.Fatal(err)
	}
	auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings",
		&mcp.Error{Code: mcp.CodeRefused, Message: "disabled"})
	st, err := revocationProof(t, root, "--agent", "triage-bot", "--grace", "0s")
	ev := st.Predicate.Revocation
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || ev.Refused != 1 || ev.Uses != 0 ||
		ev.RevokedEntry == 0 || st.Subject[0].Name != "agent/triage-bot" {
		t.Fatalf("a refused call: %v: %s %+v", err, st.Predicate.Verdict, ev)
	}

	auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings", nil)
	appendAgentEvents(t, root, span(time.Now().UTC(), "shell"))
	st, err = revocationProof(t, root, "--agent", "triage-bot", "--grace", "0s")
	ev = st.Predicate.Revocation
	named := strings.Join(st.Predicate.Checks[1].Failures, "|")
	if err == nil || st.Predicate.Verdict != proof.Refuted || ev.Uses != 2 ||
		!strings.Contains(named, "aertun/audit as aertun:triage-bot at ") ||
		!strings.Contains(named, "otel/genai as otel:triage-bot at ") {
		t.Fatalf("calls answered after the kill: %v: %s %+v %s", err, st.Predicate.Verdict, ev, named)
	}
}

// What a revocation proof starts from has to have happened, and has to
// still hold.
func TestARevocationProofStartsFromARevocation(t *testing.T) {
	root := reconcileSite(t)
	key, _ := signingFiles(t)
	run := func(args ...string) error {
		return cmdProof(root, append([]string{"revocation", "--key", key}, args...))
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--agent", "triage-bot"}, "no kill switch entry"},
		{[]string{"--agent", "stranger"}, "is registered"},
		{[]string{"--identity", "okta:00u1"}, "needs --at"},
		{[]string{"--identity", "aertun:triage-bot", "--at", "2026-11-01"}, "--agent"},
		{[]string{"--identity", "Dana Ops", "--at", "2026-11-01"}, "ISSUER:VALUE"},
		{[]string{"--identity", "okta:00u1", "--at", "2026-11-01", "--grace", "48h"}, "--grace"},
		{[]string{}, "takes --agent"},
	}
	for _, c := range cases {
		if err := run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	if err := cmdAgent(root, []string{"disable", "triage-bot", "--why", "drill"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAgent(root, []string{"enable", "triage-bot", "--why", "drill over"}); err != nil {
		t.Fatal(err)
	}
	if err := run("--agent", "triage-bot", "--grace", "0s"); err == nil ||
		!strings.Contains(err.Error(), "enabled again") {
		t.Errorf("an agent enabled again: %v", err)
	}
}

// A use seen by a source a proof cannot name stops the proof rather than
// being left out of it.
func TestAUseASourceCannotNameStopsTheProof(t *testing.T) {
	root := reconcileSite(t)
	now := time.Now().UTC().Truncate(time.Second)
	revoked := now.Add(-3 * time.Hour)
	odd := oktaAct(revoked.Add(time.Hour), "00u1", telemetry.DispositionAllowed)
	odd.Source = "Okta Imported"
	appendAgentEvents(t, root, odd)
	key, _ := signingFiles(t)
	err := cmdProof(root, []string{"revocation", "--key", key, "--identity", "okta:00u1",
		"--at", revoked.Format(time.RFC3339)})
	if err == nil || !strings.Contains(err.Error(), "cannot name it") {
		t.Errorf("%v", err)
	}
}
