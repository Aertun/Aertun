// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func statementDigest(t *testing.T, st *Statement) string {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// A proven proof sums up as a verification result about the same artifact,
// with one property a policy can ask for, the verifier and policy named by
// the proof's own predicate, and the proof itself findable from it.
func TestAProvenProofHasAVerificationResult(t *testing.T) {
	st := prove(t, goodCorpus(t))
	digest := statementDigest(t, st)
	svr, err := SVRFor(st, digest, "a1b2c3d4")
	if err != nil {
		t.Fatal(err)
	}
	if svr.Type != "https://in-toto.io/Statement/v1" || svr.PredicateType != "https://in-toto.io/attestation/svr/v0.2" {
		t.Errorf("not an in-toto SVR: %s %s", svr.Type, svr.PredicateType)
	}
	if len(svr.Subject) != 1 || svr.Subject[0].Digest["sha256"] != st.Subject[0].Digest["sha256"] {
		t.Errorf("the result is not about the artifact the proof is: %+v", svr.Subject)
	}
	p := svr.Predicate
	if strings.Join(p.Properties, ",") != "AERTUN_DETECTION_PROVEN" {
		t.Errorf("properties %v", p.Properties)
	}
	if p.Verifier.ID != "https://aertun.github.io/proof/detection/v1#verifier-"+st.Predicate.Verifier.Version ||
		len(p.Verifier.Policies) != 1 || p.Verifier.Policies[0].URI != PredicateDetection {
		t.Errorf("verifier %+v", p.Verifier)
	}
	if a := p.Verifier.Policies[0].Annotations; a["aertun.proof.sha256"] != digest || a["aertun.proof.key"] != "a1b2c3d4" {
		t.Errorf("the proof cannot be found from the result: %+v", a)
	}
	if p.TimeCreated != st.Predicate.VerifiedAt {
		t.Errorf("verified at %s, the result says %s", st.Predicate.VerifiedAt, p.TimeCreated)
	}
	// The spec's own field names, and nothing else.
	b, _ := json.Marshal(svr)
	for _, field := range []string{`"_type"`, `"subject"`, `"predicateType"`, `"verifier"`, `"policies"`,
		`"timeCreated"`, `"properties"`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("%s is missing: %s", field, b)
		}
	}
	for kind, want := range map[string]string{
		PredicateNotAffected: "AERTUN_NOT_AFFECTED_PROVEN", PredicatePeerLog: "AERTUN_PEER_LOG_PROVEN",
		PredicateChainPosture: "AERTUN_CHAIN_POSTURE_PROVEN",
	} {
		if got, err := SVRProperty(kind); err != nil || got != want {
			t.Errorf("%s: %s %v", kind, got, err)
		}
	}
	if _, err := SVRProperty("https://example.com/proof/detection/v1"); err == nil {
		t.Error("another program's predicate was given an Aertun property")
	}
}

// Only a proven proof: a result lists what passed, and nothing passed in a
// refuted or inconclusive one.
func TestOnlyAProvenProofHasAVerificationResult(t *testing.T) {
	for name, st := range map[string]*Statement{
		"inconclusive": prove(t, nil),
	} {
		if _, err := SVRFor(st, statementDigest(t, st), "k"); err == nil || !strings.Contains(err.Error(), "only a proven proof") {
			t.Errorf("%s: %v", name, err)
		}
	}
	st := prove(t, goodCorpus(t))
	if _, err := SVRFor(st, "not a digest", "k"); err == nil {
		t.Error("a result naming no proof")
	}
	edited := *st
	edited.Predicate.Verdict = Refuted
	if _, err := SVRFor(&edited, statementDigest(t, st), "k"); err == nil {
		t.Error("a statement whose verdict was edited was summed up")
	}
}

// Signed so that any DSSE verifier with the public key checks it, and in a
// domain of its own so it is never read as a proof, nor a proof as it.
func TestAVerificationResultIsPlainDSSEAndNeverAProof(t *testing.T) {
	k := mustKey(t)
	st := prove(t, goodCorpus(t))
	svr, err := SVRFor(st, statementDigest(t, st), "k")
	if err != nil {
		t.Fatal(err)
	}
	env, err := SealSVR(svr, k)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	pub, _ := base64.StdEncoding.DecodeString(k.PublicKey().Ed25519)
	if !ed25519.Verify(ed25519.PublicKey(pub), pae(PayloadType, payload), sig) {
		t.Error("the Ed25519 signature does not verify as plain DSSE")
	}
	back, err := OpenSVR(env, k.PublicKey())
	if err != nil || back.Predicate.Properties[0] != "AERTUN_DETECTION_PROVEN" {
		t.Fatalf("the result does not round-trip: %v", err)
	}
	if _, err := Open(env, k.PublicKey()); err == nil {
		t.Error("a verification result opened as a proof")
	}
	proofEnv, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSVR(proofEnv, k.PublicKey()); err == nil {
		t.Error("a proof opened as a verification result")
	}
	// Edited after signing: refused.
	var s SVRStatement
	_ = json.Unmarshal(payload, &s)
	s.Predicate.Properties = []string{"AERTUN_EVERYTHING_PROVEN"}
	b, _ := json.Marshal(s)
	env.Payload = base64.StdEncoding.EncodeToString(b)
	if _, err := OpenSVR(env, k.PublicKey()); err == nil {
		t.Error("a result with its properties edited opened")
	}
}
