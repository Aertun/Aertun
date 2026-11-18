// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/telemetry"
)

// A proven proof kept here, or handed over as a file with its key, becomes
// a verification result a policy engine reads; a refuted one does not.
func TestAProvenProofBecomesAVerificationResult(t *testing.T) {
	root := reconcileSite(t)
	var evs []telemetry.Event
	for range 10 {
		auditMCPCall(root, agentCalling("triage-bot"), "aertun_read", "list_findings", nil)
		evs = append(evs, span(time.Now().UTC(), "mcp__aertun__aertun_read"))
	}
	appendAgentEvents(t, root, evs...)
	key, pub := signingFiles(t)
	proofAt := filepath.Join(t.TempDir(), "reconcile.json")
	if err := cmdAgent(root, []string{"reconcile", "triage-bot", "--since",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "--key", key, "--public-key", pub,
		"--out", proofAt}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 1 || kept[0].Statement.Predicate.Verdict != proof.Proven {
		t.Fatalf("kept %+v", kept)
	}

	svrKey, svrPub := signingFiles(t)
	check := func(at string) *proof.SVRStatement {
		t.Helper()
		env, err := proof.ReadEnvelope(at)
		if err != nil {
			t.Fatal(err)
		}
		k, err := pack.LoadPublicKey(svrPub)
		if err != nil {
			t.Fatal(err)
		}
		s, err := proof.OpenSVR(env, k)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	byID := filepath.Join(t.TempDir(), "svr.json")
	if err := cmdProof(root, []string{"svr", kept[0].ID, "--key", svrKey, "--public-key", svrPub, "--out", byID}); err != nil {
		t.Fatalf("proof svr by id: %v", err)
	}
	s := check(byID)
	if s.Predicate.Properties[0] != "AERTUN_RECONCILIATION_PROVEN" || s.Subject[0].Name != "agent/triage-bot" ||
		s.Predicate.Verifier.Policies[0].Annotations["aertun.proof.sha256"] != kept[0].Digest {
		t.Errorf("by id: %+v", s)
	}
	byFile := filepath.Join(t.TempDir(), "svr2.json")
	if err := cmdProof(root, []string{"svr", proofAt, "--proof-key", pub, "--key", svrKey, "--out", byFile}); err != nil {
		t.Fatalf("proof svr by file: %v", err)
	}
	if s2 := check(byFile); s2.Predicate.Verifier.Policies[0].Annotations["aertun.proof.sha256"] != kept[0].Digest {
		t.Errorf("the same proof by file names another digest: %+v", s2.Predicate.Verifier)
	}
	// A proof file against a key that did not sign it, and a file with no
	// key, say nothing.
	if err := cmdProof(root, []string{"svr", proofAt, "--proof-key", otherPubFile(t), "--key", svrKey,
		"--out", filepath.Join(t.TempDir(), "x.json")}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a proof against another key: %v", err)
	}
	if err := cmdProof(root, []string{"svr", proofAt, "--key", svrKey}); err == nil {
		t.Error("a proof file with no key to check it was summed up")
	}

	// Refuted: an unreported call.
	auditMCPCall(root, agentCalling("triage-bot"), "aertun_write", "decide_finding", nil)
	_ = cmdAgent(root, []string{"reconcile", "triage-bot", "--since",
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), "--key", key, "--out",
		filepath.Join(t.TempDir(), "r2.json")})
	kept, _ = proofstore.List(root)
	var refuted string
	for _, e := range kept {
		if e.Statement != nil && e.Statement.Predicate.Verdict == proof.Refuted {
			refuted = e.ID
		}
	}
	if refuted == "" {
		t.Fatal("no refuted proof was kept")
	}
	if err := cmdProof(root, []string{"svr", refuted, "--key", svrKey, "--out", filepath.Join(t.TempDir(), "y.json")}); err == nil ||
		!strings.Contains(err.Error(), "only a proven proof") {
		t.Errorf("a refuted proof: %v", err)
	}
}
