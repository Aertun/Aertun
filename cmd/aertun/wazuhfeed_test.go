// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/seal"
)

// wazuhAlertLines are alerts a Wazuh 4.14.10 manager raised, captured.
func wazuhAlertLines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "source", "testdata", "wazuh-alerts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// A Wazuh manager's integrator posts each alert, signed, to a feed added with
// --seal: the alert is stored through the wazuh/alerts mapping, and its
// digest is committed to the audit log in the feed's name, the same digest
// `aertun alert seal` gives the alert as Wazuh wrote it.
func TestASealingFeedStoresAndSealsEachWazuhAlert(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	_, shown, err := makeFeed(root, "webhook", "wazuh", map[string]string{"mapping": "wazuh/alerts",
		"seal": "yes"}, "boss")
	if err != nil {
		t.Fatal(err)
	}
	secret := shownSecret(t, shown, "signing secret: ")
	inb := newInboundServer(root)
	lines := wazuhAlertLines(t)
	for i, line := range lines {
		r := httptest.NewRequest(http.MethodPost, "/feeds/wazuh", strings.NewReader(line))
		r.Header = standardHeaders(secret, "wazuh-"+string(rune('a'+i)), time.Now().Unix(), line)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		inb.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("alert %d was answered %d: %s", i, w.Code, w.Body)
		}
	}
	inb.process()
	if n := storedFrom(t, root, "wazuh/alerts"); n != len(lines) {
		t.Fatalf("stored %d of %d alerts", n, len(lines))
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	commits := seal.Commits(events)
	if len(commits) != len(lines) {
		t.Fatalf("%d sealing entries for %d deliveries", len(commits), len(lines))
	}
	for _, e := range events {
		if e.Action == seal.ActionSealed && (e.Kind != audit.KindService || !e.Verified || e.Detail["feed"] != "wazuh") {
			t.Fatalf("a sealing entry not in the feed's name: %+v", e)
		}
	}
	// Each alert, as Wazuh wrote it, is found where the feed sealed it.
	for _, line := range lines {
		d, err := seal.Digest([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		found, _ := seal.Find(seal.Dir(root), commits, d)
		if found == nil || !found.Reaches {
			t.Fatalf("the alert %s… is not found sealed: %+v", line[:60], found)
		}
	}
	// A feed added without --seal seals nothing.
	if _, _, err := makeFeed(root, "webhook", "plain", map[string]string{"mapping": "wazuh/alerts"}, "boss"); err != nil {
		t.Fatal(err)
	}
	feeds, _ := loadFeeds(root)
	if feeds["plain"].Seal || !feeds["wazuh"].Seal {
		t.Fatalf("seal flags %v %v", feeds["plain"].Seal, feeds["wazuh"].Seal)
	}
}

// The integration's script, run as Wazuh's integrator runs it, delivers an
// alert to a sealing feed over TLS: stored, sealed, and taken once however
// often it is sent; a wrong secret, plain http and an unknown certificate
// are each refused before anything is stored.
func TestTheWazuhScriptDeliversAnAlertAsIntegratorRunsIt(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	_, shown, err := makeFeed(root, "webhook", "wazuh", map[string]string{"mapping": "wazuh/alerts",
		"seal": "yes"}, "boss")
	if err != nil {
		t.Fatal(err)
	}
	secret := shownSecret(t, shown, "signing secret: ")
	inb := newInboundServer(root)
	srv := httptest.NewTLSServer(inb)
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	options := filepath.Join(dir, "aertun.options")
	if err := os.WriteFile(options, []byte(`{"ca_file":"`+ca+`","timeout":5,"retries":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	alert := filepath.Join(dir, "1794994957.710989.alert")
	line := wazuhAlertLines(t)[10]
	if err := os.WriteFile(alert, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join("..", "..", "integrations", "wazuh", "custom-aertun.py")
	run := func(args ...string) int {
		cmd := exec.Command(python, append([]string{script}, args...)...)
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			_ = out
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}
	url := srv.URL + "/feeds/wazuh"
	if code := run(alert, secret, url, options); code != 0 {
		t.Fatalf("the script exited %d", code)
	}
	if code := run(alert, secret, url, options); code != 0 {
		t.Fatalf("the same alert again exited %d", code)
	}
	if code := run(alert, "whsec_"+strings.Repeat("A", 44), url, options); code != 1 {
		t.Errorf("a wrong secret exited %d", code)
	}
	if code := run(alert, secret, strings.Replace(url, "https://", "http://", 1), options); code != 2 {
		t.Errorf("plain http exited %d", code)
	}
	if code := run(alert, secret, url); code != 1 {
		t.Errorf("an untrusted certificate exited %d", code)
	}
	inb.process()
	if n := storedFrom(t, root, "wazuh/alerts"); n != 1 {
		t.Fatalf("stored %d events", n)
	}
	events, _ := audit.Read(auditPath(root))
	commits := seal.Commits(events)
	d, _ := seal.Digest([]byte(line))
	if found, _ := seal.Find(seal.Dir(root), commits, d); len(commits) != 1 || found == nil || !found.Reaches {
		t.Fatalf("%d sealing entries; the alert found: %+v", len(commits), found)
	}
	if st := inb.snapshot()["wazuh"]; st.Refused != 1 {
		t.Errorf("refusals %+v", st)
	}
}
