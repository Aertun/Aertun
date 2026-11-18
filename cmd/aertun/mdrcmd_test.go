// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/mdr"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
)

// asPerson makes who the caller, through a token of their own that names
// them as a person.
func asPerson(t *testing.T, root, who, name string) {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.Issue(name, who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", secret)
}

// mdrSite is a fresh store and an operator's list of forty Atomic Red Team
// tests, each on a host of its own, with lee, a person, as the caller.
func mdrSite(t *testing.T) (root, list string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AERTUN_TOKEN", "")
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("# id host\n")
	for i := range 40 {
		fmt.Fprintf(&b, "T1059.%03d-1 crowdstrike:dev-%02d\n", i, i)
	}
	list = filepath.Join(t.TempDir(), "emulations.txt")
	if err := os.WriteFile(list, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	asPerson(t, root, "lee", "cli")
	t.Cleanup(func() { mdrNow = time.Now })
	return root, list
}

// drawPlan draws a plan whose window opened a few minutes short of a day
// ago, so nearly every item has fallen due and may still be run, and reads
// it back.
func drawPlan(t *testing.T, root, name, list string, count int) *mdr.Plan {
	t.Helper()
	real := time.Now()
	mdrNow = func() time.Time { return real.Add(-23*time.Hour - 50*time.Minute) }
	defer func() { mdrNow = time.Now }()
	if err := cmdMDR(root, []string{"plan", name, "--provider", "acme", "--emulations", list,
		"--count", fmt.Sprint(count), "--over", "1d"}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	p, err := loadPlan(root, name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// runDue records every item that has fallen due as run now, and returns
// when, by item.
func runDue(t *testing.T, root string, p *mdr.Plan) map[int]time.Time {
	t.Helper()
	ran := map[int]time.Time{}
	for _, it := range p.Items {
		if it.At.After(time.Now()) {
			continue
		}
		at := time.Now().UTC()
		if err := cmdMDR(root, []string{"ran", p.Name, "--item", fmt.Sprint(it.N), "--at",
			at.Format(time.RFC3339Nano)}); err != nil {
			t.Fatalf("ran %d: %v", it.N, err)
		}
		ran[it.N] = at
	}
	return ran
}

func mdrProof(t *testing.T, root, name string, args ...string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "mdr.json")
	err := cmdMDR(root, append([]string{"prove", name, "--key", key, "--public-key", pub, "--out", at}, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// A whole test: the plan committed as a digest alone, every due item run,
// all but five notified; inconclusive while open, and once closed proven or
// refuted against the tolerance, naming what was missed, and kept.
func TestAProviderIsTestedBlindEndToEnd(t *testing.T) {
	root, list := mdrSite(t)
	p := drawPlan(t, root, "acme-q4", list, 40)

	// What the log was told is the digest, which is the plan file's own,
	// and nothing about which emulation, where or when.
	body, err := os.ReadFile(mdrPath(root, "acme-q4"))
	if err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	var committed *audit.Event
	for i, e := range events {
		if e.Action == mdr.PlannedAction {
			committed = &events[i]
		}
	}
	if committed == nil || committed.Detail["sha256"] != proof.SHA256(body)["sha256"] ||
		committed.Detail["items"] != "40" || committed.Detail["provider"] != "acme" {
		t.Fatalf("the commitment: %+v", committed)
	}
	if err := cmdMDR(root, []string{"next", "acme-q4"}); err != nil {
		t.Fatalf("next: %v", err)
	}

	ran := runDue(t, root, p)
	if len(ran) < proof.MinSample {
		t.Fatalf("only %d of 40 items fell due", len(ran))
	}
	var missed []int
	for _, it := range p.Items {
		if _, ok := ran[it.N]; !ok {
			continue
		}
		if len(missed) < 5 {
			missed = append(missed, it.N)
			continue
		}
		if err := cmdMDR(root, []string{"notified", "acme-q4", "--item", fmt.Sprint(it.N), "--at",
			time.Now().UTC().Format(time.RFC3339Nano), "--ref", fmt.Sprintf("ldt:%d", it.N)}); err != nil {
			t.Fatalf("notified %d: %v", it.N, err)
		}
	}
	// Recorded once each.
	if err := cmdMDR(root, []string{"ran", "acme-q4", "--item", fmt.Sprint(missed[0]), "--at",
		time.Now().UTC().Format(time.RFC3339Nano)}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("an item was run twice: %v", err)
	}

	// The log carries item numbers and times, never an emulation or a host.
	events, _ = audit.Read(auditPath(root))
	for _, e := range events {
		if !strings.HasPrefix(e.Action, "mdr.") {
			continue
		}
		for k, v := range e.Detail {
			if strings.Contains(v, "T1059") || strings.Contains(v, "dev-") {
				t.Errorf("entry %d (%s) gives away the plan in %s: %s", e.Seq, e.Action, k, v)
			}
		}
	}

	st, err := mdrProof(t, root, "acme-q4", "--sla", "30m", "--tolerance", "0.5")
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.MDR.Closed ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "still open") {
		t.Errorf("an open test: %v %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}

	real := time.Now()
	mdrNow = func() time.Time { return real.Add(26 * time.Hour) }
	st, err = mdrProof(t, root, "acme-q4", "--sla", "30m", "--tolerance", "0.5")
	ev := st.Predicate.MDR
	if err != nil || st.Predicate.Verdict != proof.Proven || !ev.Closed || ev.Run != len(ran) ||
		ev.Never != 5 || ev.Within != len(ran)-5 || ev.Planned != 40 ||
		st.Subject[0].Name != "mdr/acme-q4" || st.Subject[0].Digest["sha256"] != proof.SHA256(body)["sha256"] ||
		ev.Committed.Seq != committed.Seq {
		t.Fatalf("closed, against 0.5: %v %s %+v", err, st.Predicate.Verdict, ev)
	}
	st, err = mdrProof(t, root, "acme-q4", "--sla", "30m", "--tolerance", "0.02")
	if err == nil || st.Predicate.Verdict != proof.Refuted {
		t.Fatalf("closed, against 0.02: %v %s", err, st.Predicate.Verdict)
	}
	var want []string
	for _, n := range missed {
		it, _ := p.Item(n)
		want = append(want, fmt.Sprintf("item %d (%s) not notified", n, it.Emulation))
	}
	if got := strings.Join(st.Predicate.Checks[2].Failures, "|"); got != strings.Join(want, "|") {
		t.Errorf("named %q, want %q", got, strings.Join(want, "|"))
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 2 {
		t.Errorf("%d proofs kept, want the two made after the test closed", len(kept))
	}
}

// What a test cannot count is refused when it is recorded, with what to do
// instead.
func TestAnMDRRecordIsRefusedWhenATestCouldNotCountIt(t *testing.T) {
	root, list := mdrSite(t)
	p := drawPlan(t, root, "acme-q4", list, 40)
	var due mdr.Item
	for _, it := range p.Items {
		if !it.At.After(time.Now()) {
			due = it
			break
		}
	}
	now := func() string { return time.Now().UTC().Format(time.RFC3339Nano) }
	item := fmt.Sprint(due.N)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"plan", "acme-q4", "--provider", "acme", "--emulations", list, "--count", "5"}, "already drawn"},
		{[]string{"plan", "acme-q5", "--provider", "Acme Inc", "--emulations", list, "--count", "5"}, "short name"},
		{[]string{"plan", "acme-q5", "--provider", "acme", "--emulations", list, "--count", "5", "--over", "2h"}, "--over"},
		{[]string{"plan", "../acme", "--provider", "acme", "--emulations", list, "--count", "5"}, "plan's name"},
		{[]string{"ran", "acme-q4", "--item", "41", "--at", now()}, "no item 41"},
		{[]string{"ran", "acme-q4", "--item", item, "--at", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, "future"},
		{[]string{"ran", "acme-q4", "--item", item, "--at", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}, "before its plan was committed"},
		{[]string{"ran", "acme-q4", "--item", item, "--at", "yesterday"}, "RFC 3339"},
		{[]string{"notified", "acme-q4", "--item", item, "--at", now(), "--ref", "ldt:1"}, "not recorded as run"},
		{[]string{"notified", "acme-q4", "--item", item, "--at", now(), "--ref", "ldt:1", "--source", "crowdstrike/detections"}, "or NAME --source"},
		{[]string{"prove", "acme-q4", "--sla", "30m", "--key", "k"}, "--tolerance"},
		{[]string{"prove", "acme-q4", "--sla", "48h", "--tolerance", "0.1", "--key", "k"}, "--sla"},
	}
	for _, c := range cases {
		if err := cmdMDR(root, c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	if err := cmdMDR(root, []string{"ran", "acme-q4", "--item", item, "--at", now()}); err != nil {
		t.Fatal(err)
	}
	if err := cmdMDR(root, []string{"notified", "acme-q4", "--item", item, "--at", now(),
		"--ref", "the analyst rang us"}); err == nil || !strings.Contains(err.Error(), "--ref") {
		t.Errorf("a ticket in prose: %v", err)
	}

	// A run is a person's word, and only a person whose identity was proved
	// may give it.
	t.Setenv("AERTUN_TOKEN", "")
	if err := cmdMDR(root, []string{"notified", "acme-q4", "--item", item, "--at", now(),
		"--ref", "ldt:1"}); err == nil || !strings.Contains(err.Error(), "identity is proved") {
		t.Errorf("nobody's notification: %v", err)
	}
	asPerson(t, root, "ci", "ci-pipeline")
	if err := cmdMDR(root, []string{"notified", "acme-q4", "--item", item, "--at", now(),
		"--ref", "ldt:1"}); err == nil || !strings.Contains(err.Error(), "service's") {
		t.Errorf("a service's notification: %v", err)
	}
}

func alertOn(host, ref, source string, at time.Time) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: source, Class: telemetry.ClassDetection,
		Activity: 1, Device: telemetry.ID{Issuer: "crowdstrike", Value: host},
		Raw: map[string]string{telemetry.AlertField: ref}}
}

// The provider's alerts are joined from the event store on the host the
// plan names, from the source the operator names, and only there; a plan
// that names no host joins nothing.
func TestNotificationsAreJoinedFromTheEventStoreOnTheHost(t *testing.T) {
	root, list := mdrSite(t)
	p := drawPlan(t, root, "acme-q4", list, 6)
	ran := runDue(t, root, p)
	hosts := map[string]int{}
	for n := range ran {
		it, _ := p.Item(n)
		hosts[it.Host]++
	}
	var evs []telemetry.Event
	joinable := 0
	for n, at := range ran {
		it, _ := p.Item(n)
		host := strings.TrimPrefix(it.Host, "crowdstrike:")
		// Another product saw it first; the provider's alert is the one
		// that counts.
		evs = append(evs, alertOn(host, fmt.Sprintf("other:%d", n), "sentinelone/threats", at.Add(time.Millisecond)),
			alertOn(host, fmt.Sprintf("ldt:%d", n), "crowdstrike/detections", at.Add(2*time.Millisecond)))
		if hosts[it.Host] == 1 {
			joinable++
		}
	}
	evs = append(evs, alertOn("dev-99", "ldt:elsewhere", "crowdstrike/detections", time.Now().UTC()))
	appendAgentEvents(t, root, evs...)
	if err := cmdMDR(root, []string{"notified", "acme-q4", "--source", "crowdstrike/detections"}); err != nil {
		t.Fatal(err)
	}
	_, r, events, err := mdrState(root, "acme-q4")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Notified) != joinable || joinable == 0 {
		t.Fatalf("%d joined of %d run, want %d", len(r.Notified), len(ran), joinable)
	}
	for ref, n := range r.Refs {
		if ref != fmt.Sprintf("ldt:%d", n) {
			t.Errorf("item %d was joined to %s", n, ref)
		}
	}
	for _, e := range events {
		if e.Action == mdr.NotifiedAction && e.Detail["source"] != "crowdstrike/detections" {
			t.Errorf("a joined notification does not say where it came from: %v", e.Detail)
		}
	}

	// A list with no hosts: an alert near the time of a run could be about
	// anything, so nothing is joined.
	bare := filepath.Join(t.TempDir(), "bare.txt")
	if err := os.WriteFile(bare, []byte("T1003.001-2\nT1547.001-3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := drawPlan(t, root, "acme-bare", bare, 3)
	ranBare := runDue(t, root, q)
	evs = nil
	for n, at := range ranBare {
		evs = append(evs, alertOn("dev-00", fmt.Sprintf("ldt:bare-%d", n), "crowdstrike/detections", at.Add(time.Millisecond)))
	}
	appendAgentEvents(t, root, evs...)
	if err := cmdMDR(root, []string{"notified", "acme-bare", "--source", "crowdstrike/detections"}); err != nil {
		t.Fatal(err)
	}
	if _, r, _, err := mdrState(root, "acme-bare"); err != nil || len(r.Notified) != 0 {
		t.Errorf("a plan with no hosts joined %v: %v", r, err)
	}
}
