// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
)

func oktaSystem(at time.Time, raw map[string]string) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: "okta/system", Class: telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed, Actor: telemetry.ID{Issuer: "okta", Value: "00u9"},
		Message: raw["eventType"], Raw: raw}
}

// coverageRules copies two of the reference pack's rules into a directory of
// their own, with a corpus beside them.
func coverageRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, id := range []string{"okta.mfa-reset", "okta.admin-privilege-granted"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "detect", "pack", id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, id+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	var lines []string
	for _, l := range []detect.Labelled{
		{Name: "atomic T1556 reset", Techniques: []string{"T1556"},
			Event: oktaSystem(at, map[string]string{"eventType": "user.mfa.factor.reset_all"})},
		{Name: "atomic T1098.003 grant", Techniques: []string{"T1098.003"},
			Event: oktaSystem(at, map[string]string{"eventType": "user.account.privilege.grant"})},
		{Name: "self-service enrolment",
			Event: oktaSystem(at, map[string]string{"eventType": "user.mfa.factor.activate"})},
	} {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	if err := os.WriteFile(filepath.Join(dir, "corpus.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestProofCoverageSignsEachTechniqueAndDrawsALayer(t *testing.T) {
	root := reconcileSite(t)
	rules := coverageRules(t)
	key, pub := signingFiles(t)
	out := filepath.Join(t.TempDir(), "coverage.json")
	layerAt := filepath.Join(t.TempDir(), "layer.json")
	if err := cmdProof(root, []string{"coverage", "--rules", rules, "--key", key, "--public-key", pub,
		"--out", out, "--navigator", layerAt}); err != nil {
		t.Fatalf("a proven coverage proof failed the command: %v", err)
	}
	st := readStatement(t, out, pub)
	if st.Predicate.Coverage == nil || st.Predicate.Verdict != "proven" || len(st.Predicate.Coverage.Techniques) != 2 {
		t.Fatalf("statement %+v", st.Predicate)
	}
	if err := proofVerify([]string{"--key", pub, out}); err != nil {
		t.Errorf("the CI gate refused a proven coverage proof: %v", err)
	}
	b, err := os.ReadFile(layerAt)
	if err != nil {
		t.Fatal(err)
	}
	var layer struct {
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Comment     string `json:"comment"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(b, &layer); err != nil || layer.Domain != "enterprise-attack" || len(layer.Techniques) != 2 {
		t.Fatalf("layer %s: %v", b, err)
	}
	if fi, _ := os.Stat(layerAt); fi.Mode().Perm() != 0o600 {
		t.Errorf("the layer is %v", fi.Mode().Perm())
	}

	// Kept, it lists as a coverage proof.
	if err := cmdProof(root, []string{"keep", out, "--public-key", pub}); err != nil {
		t.Fatalf("keeping it: %v", err)
	}
	if err := cmdProof(root, []string{"list", "--kind", "coverage"}); err != nil {
		t.Errorf("listing coverage proofs: %v", err)
	}
}

func TestProofCoverageJudgesDecayAgainstTheStore(t *testing.T) {
	root := reconcileSite(t)
	rules := coverageRules(t)
	key, pub := signingFiles(t)
	// Lately the source sends event_type, not eventType.
	now := time.Now().UTC()
	appendAgentEvents(t, root, oktaSystem(now.Add(-time.Hour), map[string]string{"event_type": "user.session.start"}))
	out := filepath.Join(t.TempDir(), "coverage.json")
	err := cmdProof(root, []string{"coverage", "--rules", rules, "--key", key, "--public-key", pub,
		"--out", out, "--telemetry", "7d"})
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("decay did not withhold the proof: %v", err)
	}
	st := readStatement(t, out, pub)
	ev := st.Predicate.Coverage
	if ev.Telemetry == nil || ev.Telemetry.Events != 1 || ev.DarkCount != 2 || ev.Dark[0].Missing[0] != "raw.eventType" {
		t.Fatalf("telemetry %+v, dark %+v", ev.Telemetry, ev.Dark)
	}
	if len(st.Predicate.Materials) != 2 {
		t.Fatalf("materials %+v", st.Predicate.Materials)
	}
	// Signed from the store, it is kept there and written to its log.
	if !auditHas(t, root, "coverage.proved", map[string]string{"verdict": "inconclusive", "dark": "2"}) {
		t.Error("the audit log does not record the proof")
	}
	if kept, err := proofstore.List(root); err != nil || len(kept) != 1 {
		t.Errorf("kept %d proof(s): %v", len(kept), err)
	}
}

func TestProofCoverageRefusesWhatItCannotUse(t *testing.T) {
	root := reconcileSite(t)
	rules := coverageRules(t)
	key, _ := signingFiles(t)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no key":           {[]string{"coverage", "--rules", rules}, "--key FILE"},
		"a stray argument": {[]string{"coverage", "--rules", rules, "--key", key, "extra"}, "flags only"},
		"a window too long": {[]string{"coverage", "--rules", rules, "--key", key, "--telemetry", "365d"},
			"between 1h and 90d"},
		"a window that is not one": {[]string{"coverage", "--rules", rules, "--key", key, "--telemetry", "soon"},
			"length of time"},
		"a technique made up": {[]string{"coverage", "--rules", rules, "--key", key, "--technique", "creds"},
			"not an ATT&CK"},
		"no corpus": {[]string{"coverage", "--rules", rules, "--key", key, "--corpus",
			filepath.Join(rules, "none.jsonl")}, "no such file"},
	} {
		if err := cmdProof(root, c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A store nothing was collected into is not one whose sources went
	// quiet.
	empty := t.TempDir()
	if err := cmdProof(empty, []string{"coverage", "--rules", rules, "--key", key, "--telemetry", "7d"}); err == nil ||
		!strings.Contains(err.Error(), "nothing has been collected") {
		t.Errorf("an empty store: %v", err)
	}
	if _, err := os.Stat(spoolDir(empty)); !os.IsNotExist(err) {
		t.Error("asking about decay created an event store")
	}
}

// Reading the store and signing what it showed takes tune; checking files
// the caller named does not.
func TestProofCoverageReadsTheStoreOnlyForWhoMayTune(t *testing.T) {
	windtunnelOutput(t)
	root := reconcileSite(t)
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "viewer"})
	asOnly(t, root, "sam")
	appendAgentEvents(t, root, oktaSystem(time.Now().UTC().Add(-time.Hour), map[string]string{"eventType": "x"}))
	rules := coverageRules(t)
	key, _ := signingFiles(t)
	out := filepath.Join(t.TempDir(), "c.json")
	if err := cmdProof(root, []string{"coverage", "--rules", rules, "--key", key, "--out", out,
		"--telemetry", "7d"}); err == nil || strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("a viewer read the store for a signed proof: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("a refused proof was written")
	}
	if err := cmdProof(root, []string{"coverage", "--rules", rules, "--key", key, "--out", out}); err != nil {
		t.Errorf("a viewer checking files they named: %v", err)
	}
}

// A busy source is read up to a bound, and the proof says it was.
func TestProofCoverageReadsABusySourceUpToItsBound(t *testing.T) {
	root := reconcileSite(t)
	was := coveragePerSourceCap
	coveragePerSourceCap = 2
	t.Cleanup(func() { coveragePerSourceCap = was })
	now := time.Now().UTC()
	var evs []telemetry.Event
	for i := range 3 {
		evs = append(evs, oktaSystem(now.Add(-time.Duration(i+1)*time.Minute), map[string]string{"eventType": "x"}))
	}
	appendAgentEvents(t, root, evs...)
	got, err := recentFields(root, now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Events != 2 || got.Capped != 1 || got.PerSourceCap != 2 || !got.Fields["okta/system"]["raw.eventType"] {
		t.Fatalf("read %+v", got)
	}
}
