// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/research"
)

// A research dataset holds what the store recorded — events, findings,
// detection passes, the audit log, receipts and their reconciliation, a
// benign session, a signed scorecard's rates and this machine's timings —
// names nobody it came from, and verifies only as it was signed.
func TestAResearchDatasetNamesNobodyAndVerifies(t *testing.T) {
	root, parties := receiptSite(t)
	agent := parties[0]
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	logKey := filepath.Join(t.TempDir(), "log.json")
	var files []string
	for i, p := range parties {
		f := emitReceipt(t, p, "read_file", `{"path":"/srv/a"}`, t0.Add(time.Duration(i)*20*time.Millisecond), "--seq", "0")
		files = append(files, registerReceipt(t, root, parties, f, logKey))
	}
	only := emitReceipt(t, agent, "send_email", `{"to":"boss@example.com"}`, t0.Add(time.Minute), "--seq", "1")
	files = append(files, registerReceipt(t, root, parties, only, logKey))
	reconKey, reconPub := signingFiles(t)
	k, _ := pack.LoadKey(reconKey)
	if err := pack.WritePublicKey(reconPub, k.PublicKey()); err != nil {
		t.Fatal(err)
	}
	reconAt := filepath.Join(t.TempDir(), "reconciliation.cose")
	recon := append([]string{"reconcile"}, files...)
	recon = append(recon, "--key", reconKey, "--issuer", "https://aertun.test",
		"--from", t0.Add(-time.Minute).Format(time.RFC3339), "--to", t0.Add(time.Hour).Format(time.RFC3339),
		"--log-key", logKey, "--out", reconAt)
	for _, p := range parties {
		recon = append(recon, "--expect", p.issuer+"="+p.vantage)
	}
	if err := cmdReceipt("", append(recon, trustAll(parties)...)); err == nil {
		t.Fatal("the call only the agent reported was reconciled as agreed")
	}
	if err := cmdReceipt(root, append([]string{"register", reconAt, "--log-key", logKey,
		"--out", reconAt + ".transparent", "--issuer-key", "https://aertun.test=" + reconPub},
		trustAll(parties)...)); err != nil {
		t.Fatal(err)
	}

	rules := benignRules(t)
	since, until := backupNight(t, root)
	if err := captureBenign(root, rules, since, until, "--acknowledge", "aws.bulk-read", "--raw", "raw.userName"); err != nil {
		t.Fatal(err)
	}
	dana := &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
	if err := recordE(root, dana.auditRecord("token.issue", "/", audit.Success,
		map[string]string{"role": "admin", "for": "sam-the-auditor", "issued_id": "t1"})); err != nil {
		t.Fatal(err)
	}
	// The shipped pack's rules about aertun itself raise a finding on it.
	if err := cmdDetect(root, []string{"pack", "install"}); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", filepath.Join(root, "detections")}); err != nil {
		t.Fatal(err)
	}

	key, pub := signingFiles(t)
	out := filepath.Join(t.TempDir(), "dataset")
	card, cardKey := "../../scorecards/scorecard-2026-11-04.json", "../../scorecards/public-key.json"
	export := func(extra ...string) error {
		return cmdResearch(root, append([]string{"export", "--key", key, "--public-key", pub, "--out", out,
			"--since", "2d", "--iterations", "3"}, extra...))
	}
	if err := export("--scorecard", card); err == nil {
		t.Error("a scorecard was read without a key to verify it")
	}
	forged := filepath.Join(t.TempDir(), "forged.json")
	body, _ := os.ReadFile(card)
	os.WriteFile(forged, []byte(strings.Replace(string(body), `"missed": 0`, `"missed": 1`, 1)), 0o600)
	if err := export("--scorecard", forged, "--scorecard-key", cardKey); err == nil {
		t.Error("a changed scorecard went into the dataset")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused export left a directory")
	}
	if err := export("--scorecard", card, "--scorecard-key", cardKey); err != nil {
		t.Fatal(err)
	}
	if err := cmdResearch(root, []string{"verify", out, "--public-key", pub}); err != nil {
		t.Fatal(err)
	}
	pk, err := pack.LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sheet, err := research.Verify(out, pk)
	if err != nil {
		t.Fatal(err)
	}

	rows := map[string]int{}
	for _, tb := range sheet.Tables {
		rows[tb.Name] = tb.Rows
	}
	for name, least := range map[string]int{"events": 30, "findings": 1, "detections": 1, "audit": 1,
		"receipts": 4, "reconciliations": 1, "benign": 1, "outcomes": 1, "measurements": 5} {
		if rows[name] < least {
			t.Errorf("%s holds %d rows, want at least %d", name, rows[name], least)
		}
	}
	sum := sha256.Sum256(body)
	if len(sheet.Inputs) != 1 || sheet.Inputs[0].SHA256 != hex.EncodeToString(sum[:]) ||
		sheet.Inputs[0].Kind != "scorecard" {
		t.Errorf("inputs %+v", sheet.Inputs)
	}
	// One identity, one pseudonym: the finding the administrator's token
	// raised is about the actor of the event that raised it.
	actors := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(out, "events.jsonl"))), "\n") {
		var row research.EventRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		actors[row.Actor] = true
	}
	matched := false
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(out, "findings.jsonl"))), "\n") {
		var row research.FindingRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Rule == "aertun.admin-token-issued" {
			matched = actors[row.Entity] && row.Entity != ""
		}
	}
	if !matched {
		t.Error("the finding's entity is not the pseudonym of the event's actor it was raised on")
	}
	recs, _ := os.ReadFile(filepath.Join(out, "reconciliations.jsonl"))
	if !strings.Contains(string(recs), `"verdict":"disagree"`) || !strings.Contains(string(recs), `"gaps":1`) {
		t.Errorf("the reconciliation's counts: %s", recs)
	}

	// Nothing that names a person, a machine, a place or a call. Each of
	// these holds a character a pseudonym never does, so none can turn up
	// by chance.
	for _, e := range mustReadDir(t, out) {
		b, _ := os.ReadFile(filepath.Join(out, e))
		for _, name := range []string{"svc-backup", "10.20.0.5", "acme-prod-db", "/home/dana", `"dana"`,
			"sam-the-auditor", "nightly-backup", "CHG-1042", "agent-7", "agent.test", "gateway.test",
			"boss@example.com", "/srv/a", "read_file", "send_email", "aertun.test"} {
			if strings.Contains(string(b), name) {
				t.Errorf("%s names %s", e, name)
			}
		}
	}

	entries, _ := audit.Read(auditPath(root))
	if last := entries[len(entries)-1]; last.Action != "research.exported" || last.Detail["tables"] != "11" {
		t.Errorf("the export was recorded as %s %v", last.Action, last.Detail)
	}

	// An analyst may verify a dataset, and may not make one, once the store
	// has a policy that says who is which.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if err := p.Grant(auth.Binding{Principal: "watcher", Role: auth.RoleAnalyst, Resource: "/"}); err != nil {
			return err
		}
		return p.Grant(auth.Binding{Principal: "dana@acme.example", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	viewer, _, _ := ts.Issue("someone", "watcher", auth.RoleAnalyst, "/", time.Hour, auth.RoleAdmin)
	saveTokens(root, ts)
	t.Setenv("AERTUN_TOKEN", viewer)
	other := filepath.Join(t.TempDir(), "other")
	if err := cmdResearch(root, []string{"export", "--key", key, "--out", other}); err == nil {
		t.Error("an analyst took the store's data out")
	}
	if err := cmdResearch(root, []string{"verify", out, "--public-key", pub}); err != nil {
		t.Errorf("an analyst could not verify a dataset: %v", err)
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// What a refused command's words or an indicator's digest would name goes
// into a dataset as a pseudonym; the program's own vocabulary as it is.
func TestTheResearchTablesKeepVocabularyAndHideWords(t *testing.T) {
	alias := func(kind, v string) string { return "p-" + kind }
	for in, want := range map[string]string{"detect.run": "detect.run", "token.issue": "token.issue",
		"triage /home/dana/acme-incident.jsonl": "p-action", "Login": "p-action"} {
		if got := researchAction(in, alias); got != want {
			t.Errorf("action %q became %q, want %q", in, got, want)
		}
	}
	for _, c := range []struct {
		kind         finding.Kind
		source, want string
	}{{finding.FromDetection, "aertun.admin-token-issued", "aertun.admin-token-issued"},
		{finding.FromDetection, "intel/9f86d081", "p-rule"},
		{finding.FromVendor, "crowdstrike", "p-rule"},
		{finding.FromVulnerability, "CVE-2026-1001", "p-rule"}} {
		if got := researchRule(c.kind, c.source, alias); got != c.want {
			t.Errorf("rule %s %q became %q, want %q", c.kind, c.source, got, c.want)
		}
	}
	for _, c := range []struct {
		dir, path string
		in        bool
	}{{"/a/b", "/a/b/k.json", true}, {"/a/b", "/a/b/c/k.json", true}, {"/a/b", "/a/bk.json", false},
		{"/a/b", "/a/k.json", false}, {"/a/b", "/a/b", true}, {"/a/b", "/a/..b/k", false}} {
		if got, _ := within(c.dir, c.path); got != c.in {
			t.Errorf("within(%s, %s) = %v", c.dir, c.path, got)
		}
	}
}

// Asked two ways where the window starts, or to put its key inside the
// dataset, an export refuses; one that fails after writing takes itself
// back out.
func TestAResearchExportRefusesAndCleansUp(t *testing.T) {
	root, _ := receiptSite(t)
	key, _ := signingFiles(t)
	out := filepath.Join(t.TempDir(), "dataset")
	if err := cmdResearch(root, []string{"export", "--key", key, "--out", out, "--since", "2d",
		"--from", "2026-11-01T00:00:00Z"}); err == nil {
		t.Error("--since and --from were both taken")
	}
	if err := cmdResearch(root, []string{"export", "--key", key, "--out", out,
		"--public-key", filepath.Join(out, "pub.json")}); err == nil {
		t.Error("the public key was written inside the dataset")
	}
	if err := cmdResearch(root, []string{"export", "--key", key, "--out", out, "--iterations", "1",
		"--public-key", filepath.Join(t.TempDir(), "missing", "dir", "pub.json")}); err == nil {
		t.Fatal("a public key that could not be written was not an error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a failed export left its dataset behind: %v", err)
	}
	entries, _ := audit.Read(auditPath(root))
	for _, e := range entries {
		if e.Action == "research.exported" {
			t.Error("a failed export was recorded as made")
		}
	}
}
