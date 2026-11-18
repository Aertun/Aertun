// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/proof"
)

const refereeCommit = "46bee3dea75ef53a8eae49f3b7487e6341de6074"

// refereeSource is a checkout of a small package at refereeCommit.
func refereeSource(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{
		".git/HEAD":            "ref: refs/heads/main\n",
		".git/refs/heads/main": refereeCommit + "\n",
		"package.json":         `{"name":"tiny-parse","version":"2.1.0"}`,
		"lib/header.js":        "'use strict'\n\nexport function parseHeader(s) {\n  return /^(a+)+$/.test(s)\n}\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func reportFile(t *testing.T, function, score, severity string) string {
	t.Helper()
	body := `{"format":"aertun/vuln-report/v1","title":"ReDoS in parseHeader","package":"pkg:npm/tiny-parse@2.1.0",` +
		`"commit":"` + refereeCommit + `","affected":{"introduced":"2.0.0","fixed":"2.1.1"},` +
		`"locations":[{"file":"lib/header.js","function":"` + function + `","line":4}],"cwe":"CWE-1333",` +
		`"cvss":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","score":` + score + `,"severity":"` + severity + `"}}`
	at := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(at, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return at
}

func refereeRun(t *testing.T, root, report, source string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	out := filepath.Join(t.TempDir(), "referee.json")
	err := cmdVuln(root, []string{"referee", report, "--source", source, "--key", key, "--public-key", pub, "--out", out})
	if _, serr := os.Stat(out); serr != nil {
		return nil, err
	}
	return readStatement(t, out, pub), err
}

func TestARefereedReportWhoseClaimsHoldIsProven(t *testing.T) {
	root := reconcileSite(t)
	st, err := refereeRun(t, root, reportFile(t, "parseHeader", "7.5", "high"), refereeSource(t))
	if err != nil {
		t.Fatalf("a report that holds: %v", err)
	}
	ev := st.Predicate.Referee
	if ev.Head != refereeCommit || ev.Declared != "2.1.0" || ev.Range != proof.RangeInside ||
		ev.Locations[0].Found != proof.PlaceDefined || ev.Locations[0].Language != "javascript" {
		t.Fatalf("%+v", ev)
	}
	if !auditHas(t, root, "vuln.report.refereed", map[string]string{"verdict": "proven"}) {
		t.Error("the referee's run is not in the audit log")
	}
}

// The kind of report maintainers now receive by the hundred: a function the
// file does not have, a severity its own vector does not give.
func TestASlopReportIsRefuted(t *testing.T) {
	root := reconcileSite(t)
	st, err := refereeRun(t, root, reportFile(t, "parseHeaderUnsafe", "9.8", "critical"), refereeSource(t))
	if err == nil || !strings.Contains(err.Error(), "refuted") {
		t.Fatalf("slop passed: %v", err)
	}
	failed := map[string]bool{}
	for _, c := range st.Predicate.Checks {
		if !c.Passed {
			failed[c.Name] = true
		}
	}
	if !failed["locations"] || !failed["severity"] || len(failed) != 2 {
		t.Fatalf("failed %v", failed)
	}
}

// Committed first, the report's priority is its audit entry; a second report
// of the same flaw, worded otherwise, is refuted as a duplicate of it.
func TestACommittedReportHasPriorityOverALaterOneOfTheSameFlaw(t *testing.T) {
	root := reconcileSite(t)
	source := refereeSource(t)
	first := reportFile(t, "parseHeader", "7.5", "high")
	if err := cmdVuln(root, []string{"commit", first}); err != nil {
		t.Fatal(err)
	}
	if err := cmdVuln(root, []string{"commit", first}); err == nil || !strings.Contains(err.Error(), "committed already") {
		t.Errorf("committed twice: %v", err)
	}
	body, _ := os.ReadFile(first)
	second := filepath.Join(t.TempDir(), "second.json")
	if err := os.WriteFile(second, []byte(strings.Replace(string(body), `"title":"ReDoS in parseHeader"`,
		`"title":"Catastrophic backtracking"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdVuln(root, []string{"commit", second}); err != nil {
		t.Fatal(err)
	}
	st, err := refereeRun(t, root, first, source)
	if err != nil {
		t.Fatalf("the first report: %v", err)
	}
	if c := st.Predicate.Referee.Committed; c == nil || len(st.Predicate.Referee.Duplicates) != 0 {
		t.Fatalf("first: committed %+v, duplicates %+v", c, st.Predicate.Referee.Duplicates)
	}
	st, err = refereeRun(t, root, second, source)
	if err == nil {
		t.Fatal("the later report of the same flaw was not refuted")
	}
	ev := st.Predicate.Referee
	if len(ev.Duplicates) != 1 || ev.Committed == nil || ev.Duplicates[0].Seq >= ev.Committed.Seq {
		t.Fatalf("second: committed %+v, duplicates %+v", ev.Committed, ev.Duplicates)
	}
}

func TestTheRefereeRefusesWhatItCannotUse(t *testing.T) {
	root := reconcileSite(t)
	key, _ := signingFiles(t)
	report := reportFile(t, "parseHeader", "7.5", "high")
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no source":          {[]string{"referee", report, "--key", key}, "--source DIR"},
		"no key":             {[]string{"referee", report, "--source", t.TempDir()}, "--key FILE"},
		"a source not a dir": {[]string{"referee", report, "--source", report, "--key", key}, "a directory"},
		"commit with a flag": {[]string{"commit", "--now"}, "one report FILE"},
	} {
		if err := cmdVuln(root, c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	notReport := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(notReport, []byte(`{"format":"aertun/vuln-report/v1","exploit":"yes"}`), 0o600)
	if err := cmdVuln(root, []string{"commit", notReport}); err == nil {
		t.Error("a file that is no report was committed")
	}
}

func TestTheRefereeTakesTune(t *testing.T) {
	windtunnelOutput(t)
	root := reconcileSite(t)
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "analyst"})
	asOnly(t, root, "sam")
	key, _ := signingFiles(t)
	err := cmdVuln(root, []string{"referee", reportFile(t, "parseHeader", "7.5", "high"), "--source",
		refereeSource(t), "--key", key})
	if err == nil || strings.Contains(err.Error(), "proven") {
		t.Fatalf("an analyst signed a referee proof: %v", err)
	}
}

// Refereed again, a report is not a duplicate of itself.
func TestARefereedReportIsNotItsOwnDuplicate(t *testing.T) {
	root := reconcileSite(t)
	source := refereeSource(t)
	report := reportFile(t, "parseHeader", "7.5", "high")
	for i := range 2 {
		if _, err := refereeRun(t, root, report, source); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
}
