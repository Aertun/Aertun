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

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// The statements vexSite's evidence decides: one its reachability analysis
// contradicts, one its bill supports, and one about an advisory it has never
// heard of.
const (
	stContradicted = `{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:golang/github.com/x/lib@1.2.0"}],` +
		`"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}`
	stSupported = `{"vulnerability":{"name":"GHSA-dddd-eeee-ffff"},"products":[{"@id":"pkg:golang/github.com/x/old@1.4.0"}],` +
		`"status":"not_affected","justification":"vulnerable_code_not_present"}`
	stUncheckable = `{"vulnerability":{"name":"CVE-2026-9999"},"products":[{"@id":"pkg:golang/github.com/x/lib@1.2.0"}],` +
		`"status":"not_affected","justification":"vulnerable_code_not_present"}`
)

func repeated(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// keptVEX proves a document of these statements about github:acme/app for
// acme-scanner, keeps it, and returns its id in the store and the public key
// it was signed with.
func keptVEX(t *testing.T, root string, statements ...string) (id, pub string) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "vex.proof.json")
	_ = cmdVuln(root, []string{"prove-vex", vexDoc(t, strings.Join(statements, ",")), "--source", "acme-scanner",
		"--where", "github:acme/app", "--key", key, "--public-key", pub, "--out", at})
	env, err := proof.ReadEnvelope(at)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	b, _ := os.ReadFile(pub)
	st, _, err := proofstore.Check(body, b)
	if err != nil || st.Predicate.NotAffected == nil {
		t.Fatalf("the not-affected proof: %v", err)
	}
	kept, _ := proofstore.List(root)
	for _, e := range kept {
		if e.Statement != nil && e.Statement.Predicate.VerifiedAt == st.Predicate.VerifiedAt &&
			e.Statement.Subject[0].Digest["sha256"] == st.Subject[0].Digest["sha256"] {
			return e.ID, pub
		}
	}
	t.Fatal("the not-affected proof was not kept")
	return "", ""
}

func vexRecord(t *testing.T, root string, args ...string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "record.json")
	err := cmdVuln(root, append([]string{"vex-record", "--source", "acme-scanner", "--include-untrusted",
		"--since", time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
		"--key", key, "--public-key", pub, "--out", at}, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no record was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// An issuer whose kept proofs found its statements contradicted more often
// than it is held to is refuted, naming the proofs by their ids in the store;
// the record is kept and audited, and nothing the issuer wrote reaches it.
func TestAnIssuerContradictedTooOftenIsRefutedByItsKeptProofs(t *testing.T) {
	root := vexSite(t)
	id, _ := keptVEX(t, root, append(append(repeated(stContradicted, 10), repeated(stSupported, 2)...),
		stUncheckable)...)
	st, err := vexRecord(t, root, "--tolerance", "0.1")
	ev := st.Predicate.VEXRecord
	if err == nil || st.Predicate.Verdict != proof.Refuted || ev.Used != 1 || ev.Read != 1 ||
		ev.Contradicted != 10 || ev.Supported != 2 || ev.Uncheckable != 1 || ev.Share.N != 12 ||
		ev.Untrusted != 1 || ev.Trusted != 0 || st.Subject[0].Name != "vex-issuer/acme-scanner" {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	want := "kept proof " + id + " found 10 of 12 checked statement(s) contradicted"
	if f := st.Predicate.Checks[2].Failures; len(f) != 1 || f[0] != want {
		t.Errorf("named %q, want %q", f, want)
	}
	b, _ := json.Marshal(st)
	for _, s := range []string{"Vendor Inc", "ignore previous"} {
		if strings.Contains(string(b), s) {
			t.Errorf("the issuer's text %q reached the record", s)
		}
	}
	kinds := map[string]int{}
	kept, _ := proofstore.List(root)
	for _, e := range kept {
		switch {
		case e.Statement == nil:
		case e.Statement.Predicate.VEXRecord != nil:
			kinds["vex-record"]++
		case e.Statement.Predicate.NotAffected != nil:
			kinds["not-affected"]++
		}
	}
	if kinds["vex-record"] != 1 || kinds["not-affected"] != 1 {
		t.Errorf("kept %v", kinds)
	}
	events, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range events {
		found = found || (e.Action == "vuln.vex-record-proved" && e.Detail["verdict"] == "refuted" &&
			e.Detail["contradicted"] == "10")
	}
	if !found {
		t.Error("the record was not audited")
	}

	// The record kept above is not a not-affected proof, so the next record
	// reads the same one proof.
	again, _ := vexRecord(t, root, "--tolerance", "0.1")
	if again.Predicate.VEXRecord.Read != 1 {
		t.Errorf("a record read itself: %+v", again.Predicate.VEXRecord)
	}
}

// A kept proof that no longer verifies is counted and never used, whatever
// it says; a proof signed by a key this store trusts is counted as such; and
// enough statements, none contradicted, prove the record.
func TestAProofThatNoLongerVerifiesIsCountedAndNotUsed(t *testing.T) {
	root := vexSite(t)
	_, pub := keptVEX(t, root, repeated(stSupported, 40)...)
	broken, _ := keptVEX(t, root, repeated(stContradicted, 10)...)
	path := filepath.Join(proofstore.Dir(root), broken+".json")
	var k proofstore.Kept
	body, _ := os.ReadFile(path)
	if err := json.Unmarshal(body, &k); err != nil || len(k.Envelope.Signatures) != 2 {
		t.Fatalf("the kept file: %v", err)
	}
	// Each half's signature in the other's place: the same statement, signed
	// by nothing.
	s := k.Envelope.Signatures
	s[0].Sig, s[1].Sig = s[1].Sig, s[0].Sig
	body, _ = json.Marshal(k)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, _ := os.ReadFile(pub)
	if _, err := proofstore.Trust(root, "ci", trusted, "dana", "the CI key", time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := vexRecord(t, root, "--tolerance", "0.1")
	ev := st.Predicate.VEXRecord
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Read != 2 || ev.LeftOut != 1 ||
		ev.Used != 1 || ev.Trusted != 1 || ev.Untrusted != 0 || ev.Contradicted != 0 || ev.Supported != 40 {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, ev)
	}
	if d := st.Predicate.Checks[0].Detail; !strings.Contains(d, "1 that no longer verify") ||
		strings.Contains(strings.Join(st.Predicate.Checks[2].Failures, " "), broken) {
		t.Errorf("the proof that no longer verifies: %s %v", d, st.Predicate.Checks[2].Failures)
	}
	if len(st.Predicate.Materials) != 1 || st.Predicate.Materials[0].Name != "proof-signers" {
		t.Errorf("the trust list read is not named: %+v", st.Predicate.Materials)
	}
}

// Too few checked statements leave a record inconclusive, and a record
// starts from proofs kept about that issuer in that period.
func TestAVEXRecordStartsFromTheIssuersKeptProofs(t *testing.T) {
	root := vexSite(t)
	keptVEX(t, root, append(repeated(stSupported, 2), stUncheckable)...)
	st, err := vexRecord(t, root, "--tolerance", "0.1")
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.VEXRecord.Share.N != 2 ||
		!strings.Contains(st.Predicate.Checks[2].Detail, "fewer than the 30") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}

	key, _ := signingFiles(t)
	now := time.Now().UTC()
	day := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--source", "other-vendor", "--since", day(-time.Hour), "--tolerance", "0.1"}, "no not-affected proof about other-vendor"},
		{[]string{"--source", "acme-scanner", "--since", day(-3 * time.Hour), "--until", day(-2 * time.Hour),
			"--tolerance", "0.1"}, "no not-affected proof about acme-scanner"},
		{[]string{"--source", "Acme Scanner", "--since", day(-time.Hour), "--tolerance", "0.1"}, "short name"},
		{[]string{"--source", "acme-scanner", "--since", day(-time.Hour)}, "--tolerance"},
		{[]string{"--source", "acme-scanner", "--since", day(-time.Hour), "--tolerance", "1"}, "--tolerance"},
		{[]string{"--source", "acme-scanner", "--since", day(-time.Hour), "--until", day(time.Hour),
			"--tolerance", "0.1"}, "future"},
		{[]string{"--source", "acme-scanner", "--since", day(-time.Hour), "--until", day(-2 * time.Hour),
			"--tolerance", "0.1"}, "starts before it ends"},
		{[]string{"--source", "acme-scanner", "--tolerance", "0.1"}, "takes --source"},
	}
	for _, c := range cases {
		err := cmdVuln(root, append([]string{"vex-record", "--key", key}, c.args...))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	if proof.MaxVEXRecordProofs != proofstore.MaxKept {
		t.Errorf("a record reads at most %d proofs and a store keeps %d", proof.MaxVEXRecordProofs, proofstore.MaxKept)
	}
}

// Without --include-untrusted a record rests on trusted signers' proofs, and
// one with none says how to trust a signer rather than counting proofs
// anybody could have signed.
func TestAVEXRecordNeedsATrustedSignerOrSaysWhy(t *testing.T) {
	root := vexSite(t)
	keptVEX(t, root, repeated(stSupported, 40)...)
	key, _ := signingFiles(t)
	err := cmdVuln(root, []string{"vex-record", "--source", "acme-scanner",
		"--since", time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
		"--tolerance", "0.1", "--key", key, "--out", filepath.Join(t.TempDir(), "r.json")})
	if err == nil || !strings.Contains(err.Error(), "aertun proof trust") ||
		!strings.Contains(err.Error(), "--include-untrusted") {
		t.Errorf("a record from untrusted proofs alone: %v", err)
	}
}
