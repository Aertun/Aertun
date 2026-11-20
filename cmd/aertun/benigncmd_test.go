// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/benign"
	"github.com/aertun/aertun/internal/indicator"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/telemetry"
)

// benignRules is a rules directory: a rule that fires on every bulk read,
// and one that is quiet only for the backup account.
func benignRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bulk.json": `{"id":"aws.bulk-read","title":"Bulk object reads","sources":["aws/cloudtrail"],"severity":3,
		 "when":{"match":{"field":"raw.eventName","op":"equals","values":["GetObject"]}}}`,
		"notbackup.json": `{"id":"aws.not-the-backup-account","title":"A read not by the backup account","sources":["aws/cloudtrail"],"severity":3,
		 "when":{"all":[{"match":{"field":"raw.eventName","op":"equals","values":["GetObject"]}},
		  {"not":{"match":{"field":"raw.userName","op":"equals","values":["svc-backup"]}}}]}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// backupNight is last night's backup, as CloudTrail delivered it.
func backupNight(t *testing.T, root string) (since, until time.Time) {
	t.Helper()
	start := time.Now().UTC().Add(-20 * time.Hour).Truncate(time.Minute)
	var evs []telemetry.Event
	for i := 0; i < 30; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		evs = append(evs, telemetry.Event{Time: at, Received: at.Add(3 * time.Second), Source: "aws/cloudtrail",
			Class: telemetry.ClassAPIActivity, Actor: telemetry.ID{Issuer: "aws", Value: "svc-backup"},
			Observables: []telemetry.Observable{{Kind: telemetry.ObservableIP, Value: "10.20.0.5", Name: "sourceIPAddress"}},
			Raw: map[string]string{"eventName": "GetObject", "userName": "svc-backup",
				"requestParameters": "bucket=acme-prod-db key=/home/dana/dump.sql"}})
	}
	appendAgentEvents(t, root, evs...)
	return start.Add(-time.Minute), start.Add(time.Hour)
}

func captureBenign(root, rules string, since, until time.Time, extra ...string) error {
	return cmdBenign(root, append([]string{"capture", "nightly-backup", "--class", "backup",
		"--source", "aws/cloudtrail", "--since", since.Format(time.RFC3339), "--until",
		until.Format(time.RFC3339), "--why", "the 02:00 backup reads every object", "--ticket", "CHG-1042",
		"--rules", rules}, extra...))
}

// A session goes from the store to a signed bundle: refused while a rule
// fires on it unseen and while sanitising would change a rule's outcome,
// pending until a second administrator approves it, then bundled, and the
// bundle verifies offline and carries nothing it should not.
func TestABenignSessionGoesFromTheStoreToASignedBundle(t *testing.T) {
	root := reconcileSite(t)
	rules := benignRules(t)
	since, until := backupNight(t, root)
	if err := captureBenign(root, rules, since, until); err == nil || !strings.Contains(err.Error(), "aws.bulk-read") {
		t.Fatalf("an unacknowledged fire: %v", err)
	}
	if err := captureBenign(root, rules, since, until, "--acknowledge", "aws.bulk-read"); err == nil ||
		!strings.Contains(err.Error(), "raw.userName") {
		t.Fatalf("a fidelity loss: %v", err)
	}
	if err := captureBenign(root, rules, since, until, "--acknowledge", "aws.bulk-read", "--raw", "raw.userName"); err != nil {
		t.Fatal(err)
	}
	rec, err := loadBenign(root, "nightly-backup")
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != benign.Pending || rec.Request == "" || rec.Session.Events != 30 {
		t.Fatalf("%+v", rec.Session)
	}
	key, pub := signingFiles(t)
	out := filepath.Join(t.TempDir(), "bundle.json")
	if err := cmdBenign(root, []string{"bundle", "--key", key, "--out", out}); err == nil ||
		!strings.Contains(err.Error(), "no session is approved") {
		t.Fatalf("a pending session was bundled: %v", err)
	}
	r, err := dualStore(root).Get(rec.Request)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyDual(root, r, "lee"); err != nil {
		t.Fatal(err)
	}
	if rec, _ = loadBenign(root, "nightly-backup"); rec.State != benign.Approved || rec.Session.ApprovedBy == "" ||
		rec.Session.Alone {
		t.Fatalf("approved: %+v", rec.Session)
	}
	if err := cmdBenign(root, []string{"bundle", "--key", key, "--public-key", pub, "--out", out}); err != nil {
		t.Fatal(err)
	}
	if err := cmdBenign(root, []string{"verify", out, "--public-key", pub}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(out)
	// The address is pseudonymised and the request parameters, which no
	// rule reads, are not carried at all.
	for _, gone := range []string{"/home/dana", "acme-prod-db", "10.20.0.5"} {
		if strings.Contains(string(body), gone) {
			t.Errorf("%q reached the bundle", gone)
		}
	}
	if !strings.Contains(string(body), `"userName":"svc-backup"`) {
		t.Error("a field kept raw on request was not kept")
	}
	k, _ := pack.LoadPublicKey(pub)
	b, err := benign.Read(out, k)
	if err != nil || len(b.Manifest.Sessions) != 1 || b.Manifest.Sessions[0].Ticket != "CHG-1042" {
		t.Fatalf("%v %+v", err, b)
	}

	// Revoked, it is never bundled again.
	if err := cmdBenign(root, []string{"revoke", "nightly-backup", "--why", "it was the attacker's staging run"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdBenign(root, []string{"bundle", "--key", key, "--out", out}); err == nil {
		t.Error("a revoked session was bundled")
	}
	if err := applyDual(root, r, "lee"); err == nil {
		t.Error("a revoked session was approved again")
	}
}

// What the intelligence store already says is bad is never vouched for.
func TestAKnownIndicatorRefusesTheCapture(t *testing.T) {
	root := reconcileSite(t)
	rules := benignRules(t)
	since, until := backupNight(t, root)
	// One of the night's reads came from an address the intelligence store
	// holds as the attacker's.
	at := since.Add(2 * time.Minute)
	appendAgentEvents(t, root, telemetry.Event{Time: at, Received: at, Source: "aws/cloudtrail",
		Class: telemetry.ClassAPIActivity, Actor: telemetry.ID{Issuer: "aws", Value: "svc-backup"},
		Observables: []telemetry.Observable{{Kind: telemetry.ObservableIP, Value: "185.220.101.4", Name: "sourceIPAddress"}},
		Raw:         map[string]string{"eventName": "GetObject", "userName": "svc-backup"}})
	ind, err := indicator.New(indicator.IP, "185.220.101.4", "test", "exfiltration host seen in the breach",
		time.Time{}, time.Time{}, time.Now().UTC().Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := saveIndicators(root, indicator.NewSet([]indicator.Indicator{ind})); err != nil {
		t.Fatal(err)
	}
	err = captureBenign(root, rules, since, until, "--acknowledge", "aws.bulk-read", "--raw", "raw.userName")
	if err == nil || !strings.Contains(err.Error(), "indicator") {
		t.Errorf("%v", err)
	}
}

func TestACaptureIsSelectedExactly(t *testing.T) {
	root := reconcileSite(t)
	rules := benignRules(t)
	since, _ := backupNight(t, root)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"capture", "nightly-backup", "--class", "backup", "--source", "aws/cloudtrail",
			"--since", since.Format(time.RFC3339), "--until", since.Add(48 * time.Hour).Format(time.RFC3339),
			"--why", "x", "--rules", rules}, "at most 24h"},
		{[]string{"capture", "nightly-backup", "--class", "backup", "--source", "aws/cloudtrail",
			"--since", since.Format(time.RFC3339), "--until", since.Add(time.Hour).Format(time.RFC3339),
			"--rules", rules}, "--why"},
		{[]string{"capture", "Nightly Backup", "--class", "backup", "--source", "aws/cloudtrail",
			"--since", since.Format(time.RFC3339), "--until", since.Add(time.Hour).Format(time.RFC3339),
			"--why", "x", "--rules", rules}, "name"},
		{[]string{"capture", "nightly-backup", "--class", "fine", "--source", "aws/cloudtrail",
			"--since", since.Format(time.RFC3339), "--until", since.Add(time.Hour).Format(time.RFC3339),
			"--why", "x", "--rules", rules, "--acknowledge", "aws.bulk-read", "--raw", "raw.userName"}, "class"},
		{[]string{"capture", "nightly-backup", "--class", "backup", "--source", "aws/cloudtrail",
			"--since", since.Format(time.RFC3339), "--until", since.Add(time.Hour).Format(time.RFC3339),
			"--why", "x", "--rules", rules, "--where", "eventName=GetObject"}, "raw.KEY=VALUE"},
	} {
		if err := cmdBenign(root, c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args[1], err, c.want)
		}
	}
}
