// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/quality"
	"github.com/aertun/aertun/internal/telemetry"
)

// TestTheLedgerFindsAFieldLostAndTheRuleReadsIt: three weeks of a source's
// ordinary traffic, then a day on which its parser stopped filling a field.
// The ledger names it; the daily job records it once; the shipped rule
// fires on the record.
func TestTheLedgerFindsAFieldLostAndTheRuleReadsIt(t *testing.T) {
	root := reconcileSite(t)
	today := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	t.Cleanup(func() { qualityNow = time.Now })
	qualityNow = func() time.Time { return today }
	var evs []telemetry.Event
	for d := 21; d >= 1; d-- {
		day := today.Truncate(24*time.Hour).AddDate(0, 0, -d)
		for i := range 48 {
			at := day.Add(time.Duration(i) * 30 * time.Minute)
			raw := map[string]string{"user": fmt.Sprint("u", i%7), "ip": "198.51.100.20"}
			if d == 1 {
				delete(raw, "user")
			}
			evs = append(evs, telemetry.Event{Time: at, Received: at.Add(30 * time.Second), Source: "okta/system-log",
				Class: telemetry.ClassAuthentication, Actor: telemetry.ID{Issuer: "okta", Value: "00u1"}, Raw: raw})
		}
	}
	appendAgentEvents(t, root, evs...)

	var buf bytes.Buffer
	w = &out.Writer{Mode: out.JSON, Out: &buf, Err: &bytes.Buffer{}}
	t.Cleanup(func() { w = out.New(false) })
	if err := cmdTelemetry(root, []string{"quality"}); err != nil {
		t.Fatal(err)
	}
	var got struct{ Verdicts []quality.Verdict }
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	if len(got.Verdicts) != 1 || got.Verdicts[0].Status != quality.Degraded || got.Verdicts[0].Date != "2026-11-20" ||
		len(got.Verdicts[0].Reasons) != 1 || got.Verdicts[0].Reasons[0].Code != "field-lost" {
		t.Fatalf("%+v", got.Verdicts)
	}
	// Finished days are kept, and today is not.
	if _, err := os.Stat(filepath.Join(qualityDir(root), "days", "2026-11-20.json")); err != nil {
		t.Error("a finished day was not kept")
	}
	if _, err := os.Stat(filepath.Join(qualityDir(root), "days", "2026-11-21.json")); err == nil {
		t.Error("today was kept before it was over")
	}
	w = out.New(false)

	for range 2 {
		if _, err := recordDegraded(root, today); err != nil {
			t.Fatal(err)
		}
	}
	events, _ := audit.Read(auditPath(root))
	recorded := 0
	for _, e := range events {
		if e.Action == "source.degraded" {
			recorded++
		}
	}
	if recorded != 1 {
		t.Fatalf("the degraded day was recorded %d times", recorded)
	}

	rules := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "detect", "pack", "aertun.source-quality-degraded.json"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(rules, "aertun.source-quality-degraded.json"), b, 0o600)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	fired := 0
	for _, f := range queue(t, root) {
		if f.Source == "aertun.source-quality-degraded" {
			fired++
		}
	}
	if fired != 1 {
		t.Errorf("the rule fired %d times on the recorded day", fired)
	}
}

// TestARefusedRecordIsReadAgainOnceTheMappingIsFixed: the source renamed a
// field; the record its mapping could no longer read is kept as a dead
// letter, not lost; once the mapping reads the new name, replaying stores
// it.
func TestARefusedRecordIsReadAgainOnceTheMappingIsFixed(t *testing.T) {
	root := collectSite(t, &fakeTool{answer: func(*http.Request) (int, string, http.Header) { return 200, "[]", nil }})
	dir := t.TempDir()
	mapping := `{"issuer":"billing","tool":"Billing","stream":"admin","class":6003,"activity":1,
	 "time":"at","layout":"2006-01-02T15:04:05Z07:00","actor":"%s","target":"invoice","message":"action",
	 "require":["at","%s","action"],"keep":["action"],"lateness":60000000000}`
	good := put(t, filepath.Join(dir, "good.jsonl"),
		`{"at":"2026-11-20T10:00:00Z","user":"dana","action":"refund","invoice":"INV-7"}`+"\n")
	if err := cmdSource(root, []string{"add", put(t, filepath.Join(dir, "m.json"), fmt.Sprintf(mapping, "user", "user")),
		"--sample", good}); err != nil {
		t.Fatal(err)
	}
	renamed := put(t, filepath.Join(dir, "new.jsonl"),
		`{"at":"2026-11-20T10:00:00Z","user":"dana","action":"refund","invoice":"INV-7"}`+"\n"+
			`{"at":"2026-11-20T10:05:00Z","username":"sam","action":"refund","invoice":"INV-8","token":"ghp_`+strings.Repeat("a", 36)+`"}`+"\n")
	if err := cmdCollect(root, []string{"file", "billing/admin", renamed}); err != nil {
		t.Fatal(err)
	}
	sum, err := deadLetters(root).Summary("billing/admin")
	if err != nil || sum.Held != 1 || len(sum.Missing) != 1 || sum.Missing[0].Path != "user" {
		t.Fatalf("%v %+v", err, sum)
	}
	// The mapping is fixed to read the new name, and the dead letter
	// replayed.
	files, _ := filepath.Glob(filepath.Join(sourcesDir(root), "*.json"))
	if len(files) != 1 {
		t.Fatalf("%d installed mappings", len(files))
	}
	if err := os.WriteFile(files[0], []byte(fmt.Sprintf(mapping, "username", "username")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdTelemetry(root, []string{"dead-letter", "replay", "billing/admin"}); err != nil {
		t.Fatal(err)
	}
	stored := 0
	for _, e := range storedEvents(t, root) {
		if e.Source == "billing/admin" && e.Actor.Value == "sam" && e.Raw["dead_letter_at"] != "" {
			stored++
		}
	}
	if stored != 1 {
		t.Errorf("the replayed record was stored %d times", stored)
	}
	if sum, _ = deadLetters(root).Summary("billing/admin"); sum.Held != 0 || sum.Refused[quality.DateOf(time.Now())] != 1 {
		t.Errorf("after the replay: %+v", sum)
	}
}
