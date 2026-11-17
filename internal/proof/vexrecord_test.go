// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var vr0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// issuerProof is a kept not-affected proof about github:acme/app, made a day
// into the period, of a document of its own, signed by a trusted key.
func issuerProof(seed string, supported, contradicted, uncheckable int) VEXRecordProof {
	d := SHA256([]byte(seed))["sha256"]
	tested := supported + contradicted + uncheckable
	return VEXRecordProof{ID: d[:24], Digest: d, Document: SHA256([]byte("document " + seed))["sha256"],
		Asset: "github:acme/app", Made: vr0.Add(24 * time.Hour), Trusted: true,
		Statements: tested + 2, NotAffected: tested, Supported: supported, Contradicted: contradicted,
		Uncheckable: uncheckable}
}

// issuerInput is a month of acme-scanner's proofs, held to a tolerance of a
// tenth.
func issuerInput(proofs ...VEXRecordProof) VEXRecordInput {
	return VEXRecordInput{Source: "acme-scanner", Since: vr0, Until: vr0.AddDate(0, 1, 0), Tolerance: 0.1,
		Proofs: proofs, Program: "test", Now: vr0.AddDate(0, 1, 1)}
}

// later is p made again an hour on, of the same document about the same
// asset, as a second run of prove-vex would make it.
func later(p VEXRecordProof, seed string, supported, contradicted int) VEXRecordProof {
	q := issuerProof(seed, supported, contradicted, 0)
	q.Document, q.Asset, q.Made = p.Document, p.Asset, p.Made.Add(time.Hour)
	return q
}

func TestAVEXRecordsVerdict(t *testing.T) {
	a := issuerProof("a", 20, 20, 0)
	cases := map[string]struct {
		in   VEXRecordInput
		want Verdict
	}{
		"none contradicted, on enough statements":  {issuerInput(issuerProof("a", 40, 0, 0)), Proven},
		"none contradicted, on too few statements": {issuerInput(issuerProof("a", 29, 0, 0)), Inconclusive},
		"half contradicted":                        {issuerInput(a), Refuted},
		"one in a hundred is within a tenth":       {issuerInput(issuerProof("a", 99, 1, 0)), Proven},
		"five in forty may be either side":         {issuerInput(issuerProof("a", 35, 5, 0)), Inconclusive},
		"the uncheckable are never in the rate":    {issuerInput(issuerProof("a", 40, 0, 900)), Proven},
		"nothing checkable is nothing shown":       {issuerInput(issuerProof("a", 0, 0, 50)), Inconclusive},
		"spread over several proofs": {issuerInput(issuerProof("a", 15, 0, 0), issuerProof("b", 15, 0, 3),
			issuerProof("c", 10, 0, 0)), Proven},
		"a later proof of the same document replaces the earlier": {issuerInput(a, later(a, "a2", 40, 0)), Proven},
		"whatever order the store lists them in":                  {issuerInput(later(a, "a2", 40, 0), a), Proven},
		"a later contradiction replaces an earlier support": {issuerInput(issuerProof("b", 40, 0, 0),
			later(issuerProof("b", 40, 0, 0), "b2", 20, 20)), Refuted},
		"the same document about another asset is counted": {issuerInput(issuerProof("c", 20, 0, 0), func() VEXRecordProof {
			p := issuerProof("d", 20, 0, 0)
			p.Document, p.Asset = issuerProof("c", 0, 0, 0).Document, "github:acme/api"
			return p
		}()), Proven},
		"an untrusted signer's proof is used when it is asked for": {func() VEXRecordInput {
			p := issuerProof("a", 40, 0, 0)
			p.Trusted = false
			in := issuerInput(p)
			in.IncludeUntrusted = true
			return in
		}(), Proven},
		// The attack the default is for: a trusted proof found the issuer's
		// statements contradicted, and a later proof of the same document,
		// signed by a key nobody trusts, says they all held. The later one
		// is left out and supersedes nothing.
		"an untrusted later proof cannot replace a trusted contradiction": {func() VEXRecordInput {
			p := issuerProof("b", 20, 20, 0)
			forged := later(p, "b2", 40, 0)
			forged.Trusted = false
			return issuerInput(p, forged)
		}(), Refuted},
		"a proof left out changes no count": {func() VEXRecordInput {
			in := issuerInput(issuerProof("a", 40, 0, 0))
			in.LeftOut = []string{issuerProof("x", 0, 0, 0).ID}
			return in
		}(), Proven},
	}
	for name, c := range cases {
		st, err := ProveVEXRecord(c.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
	}
}

// What was read, left out, replaced and used is counted and said; the
// contradicting proofs are named by id on a refutation and on nothing else.
func TestAVEXRecordSaysWhatItReadAndNamesWhatContradicted(t *testing.T) {
	a, b := issuerProof("a", 10, 10, 1), issuerProof("b", 10, 10, 0)
	b.Made = a.Made.Add(time.Minute)
	// An untrusted signer's proof, replaced by a trusted one's of the same
	// document: only the proof used is counted by its signer.
	untrusted := issuerProof("c", 5, 0, 0)
	untrusted.Trusted = false
	in := issuerInput(a, b, untrusted, later(untrusted, "c2", 5, 0))
	in.LeftOut = []string{issuerProof("x", 0, 0, 0).ID}
	st, err := ProveVEXRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	ev := st.Predicate.VEXRecord
	if st.Predicate.Verdict != Refuted || ev.Read != 5 || ev.LeftOut != 1 || ev.UntrustedLeftOut != 1 ||
		ev.Superseded != 0 || ev.Used != 3 || ev.Trusted != 3 || ev.Untrusted != 0 || ev.Assets != 1 ||
		ev.Supported != 25 || ev.Contradicted != 20 || ev.Uncheckable != 1 || ev.ContradictingProofs != 2 ||
		st.Subject[0].Name != "vex-issuer/acme-scanner" {
		t.Fatalf("%s %+v", st.Predicate.Verdict, ev)
	}
	want := "kept proof " + a.ID + " found 10 of 20 checked statement(s) contradicted|" +
		"kept proof " + b.ID + " found 10 of 20 checked statement(s) contradicted"
	if got := strings.Join(st.Predicate.Checks[2].Failures, "|"); got != want {
		t.Errorf("named %q, want %q", got, want)
	}
	if d := st.Predicate.Checks[0].Detail; !strings.Contains(d, "1 that no longer verify") ||
		!strings.Contains(d, "1 signed by a key this store does not trust, counted and not used") ||
		!strings.Contains(d, "0 superseded") || !strings.Contains(d, "3 signed by a key this store trusts and 0") {
		t.Errorf("what was read is not said: %s", d)
	}
	if !strings.Contains(st.Predicate.Claim, "a share of at most 0.1 was contradicted") ||
		!strings.Contains(st.Predicate.Claim, "acme-scanner's VEX documents") {
		t.Errorf("the claim: %s", st.Predicate.Claim)
	}

	// Within the tolerance a contradicted statement is counted, and no proof
	// is named: only a refutation names.
	st, err = ProveVEXRecord(issuerInput(issuerProof("a", 99, 1, 0)))
	if err != nil || st.Predicate.Verdict != Proven || len(st.Predicate.Checks[2].Failures) != 0 ||
		st.Predicate.VEXRecord.ContradictingProofs != 1 {
		t.Errorf("%v %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks[2])
	}
}

// The subject is every proof read, in the order made, so it does not
// depend on how the store lists them, and a proof left out is in it.
func TestAVEXRecordsSubjectIsTheProofsItRead(t *testing.T) {
	a, b := issuerProof("a", 20, 0, 0), issuerProof("b", 20, 0, 0)
	b.Made = a.Made.Add(time.Minute)
	one, err := ProveVEXRecord(issuerInput(a, b))
	if err != nil {
		t.Fatal(err)
	}
	two, err := ProveVEXRecord(issuerInput(b, a))
	if err != nil {
		t.Fatal(err)
	}
	in := issuerInput(a, b)
	in.LeftOut = []string{issuerProof("x", 0, 0, 0).ID}
	three, err := ProveVEXRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	want := SHA256([]byte(a.ID + " " + a.Digest + "\n" + b.ID + " " + b.Digest + "\n"))["sha256"]
	if one.Subject[0].Digest["sha256"] != want || two.Subject[0].Digest["sha256"] != want {
		t.Errorf("the subject is not the proofs read, in order")
	}
	if three.Subject[0].Digest["sha256"] == want {
		t.Errorf("a proof left out is not in the subject")
	}
}

// Input that does not hold together is refused before anything is signed.
func TestAVEXRecordThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*VEXRecordInput){
		"an issuer in prose":           func(in *VEXRecordInput) { in.Source = "Acme Scanner" },
		"a period backwards":           func(in *VEXRecordInput) { in.Since, in.Until = in.Until, in.Since },
		"a period between seconds":     func(in *VEXRecordInput) { in.Until = in.Until.Add(-time.Millisecond) },
		"a tolerance of none":          func(in *VEXRecordInput) { in.Tolerance = 0 },
		"a tolerance of all":           func(in *VEXRecordInput) { in.Tolerance = 1 },
		"no proofs":                    func(in *VEXRecordInput) { in.Proofs = nil },
		"an id not in the store's":     func(in *VEXRecordInput) { in.Proofs[0].ID = "proof-one" },
		"an id that is not its digest": func(in *VEXRecordInput) { in.Proofs[0].ID = issuerProof("z", 0, 0, 0).ID },
		"a digest that is not one":     func(in *VEXRecordInput) { in.Proofs[0].Digest = "sha256:abc" },
		"a document that is not one":   func(in *VEXRecordInput) { in.Proofs[0].Document = "vendor.vex.json" },
		"an asset in prose":            func(in *VEXRecordInput) { in.Proofs[0].Asset = "the app" },
		"made before the period":       func(in *VEXRecordInput) { in.Proofs[0].Made = vr0.Add(-time.Second) },
		"made at its end":              func(in *VEXRecordInput) { in.Proofs[0].Made = in.Until },
		"a count below none":           func(in *VEXRecordInput) { in.Proofs[0].Contradicted = -1 },
		"a count no document holds":    func(in *VEXRecordInput) { in.Proofs[0].Uncheckable = maxVEXProofCount },
		"more tested than made":        func(in *VEXRecordInput) { in.Proofs[0].NotAffected = in.Proofs[0].Statements + 1 },
		"a proof twice":                func(in *VEXRecordInput) { in.Proofs = append(in.Proofs, in.Proofs[0]) },
		"a proof left out in prose":    func(in *VEXRecordInput) { in.LeftOut = []string{"broken.json"} },
		"a proof used and left out":    func(in *VEXRecordInput) { in.LeftOut = []string{in.Proofs[0].ID} },
		"more than a store keeps": func(in *VEXRecordInput) {
			for i := range MaxVEXRecordProofs {
				in.LeftOut = append(in.LeftOut, issuerProof("left "+time.Duration(i).String(), 0, 0, 0).ID)
			}
		},
	}
	for name, change := range cases {
		in := issuerInput(issuerProof("a", 20, 20, 0))
		change(&in)
		if _, err := ProveVEXRecord(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
}

// By default a record rests on trusted signers' proofs alone: one with
// nothing else to rest on is refused, saying what to do, rather than made
// from proofs anybody could have signed.
func TestAVEXRecordRestsOnTrustedSignersByDefault(t *testing.T) {
	p := issuerProof("a", 40, 0, 0)
	p.Trusted = false
	if _, err := ProveVEXRecord(issuerInput(p)); err == nil {
		t.Fatal("a record was made from an untrusted signer's proof alone")
	}
	in := issuerInput(issuerProof("b", 40, 0, 0), p)
	st, err := ProveVEXRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	ev := st.Predicate.VEXRecord
	if ev.Used != 1 || ev.UntrustedLeftOut != 1 || ev.Untrusted != 0 ||
		!strings.Contains(st.Predicate.Claim, "the proofs signed by a key this store trusts") {
		t.Errorf("%+v %q", ev, st.Predicate.Claim)
	}
}

// Every word is rebuilt from the numbers when the statement is opened, so an
// edited one is refused.
func TestAVEXRecordCarriesOnlyWhatItsNumbersSay(t *testing.T) {
	a, b := issuerProof("a", 10, 10, 0), issuerProof("b", 10, 10, 0)
	b.Made = a.Made.Add(time.Minute)
	untrusted := issuerProof("c", 5, 0, 0)
	untrusted.Trusted = false
	in := issuerInput(a, b, untrusted)
	in.IncludeUntrusted = true
	in.LeftOut = []string{issuerProof("x", 0, 0, 0).ID}
	st, err := ProveVEXRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != Refuted || len(st.Predicate.Checks[2].Failures) != 2 ||
		!strings.Contains(st.Predicate.Checks[2].Failures[0], a.ID) {
		t.Fatalf("%s %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
	other := issuerProof("z", 0, 0, 0).ID
	tamper := map[string]func(*Statement){
		"verdict": func(s *Statement) { s.Predicate.Verdict = Proven },
		"made proven": func(s *Statement) {
			s.Predicate.Verdict, s.Predicate.Checks[2].Passed, s.Predicate.Checks[2].Failures = Proven, true, nil
		},
		"claim":                          func(s *Statement) { s.Predicate.Claim += " The vendor is reliable." },
		"a contradiction away":           func(s *Statement) { s.Predicate.VEXRecord.Contradicted-- },
		"the bounds moved":               func(s *Statement) { s.Predicate.VEXRecord.Share.Lower = 0.01 },
		"the tolerance raised":           func(s *Statement) { s.Predicate.VEXRecord.Tolerance = 0.6 },
		"the minimum lowered":            func(s *Statement) { s.Predicate.VEXRecord.MinChecked = 10 },
		"uncheckable added":              func(s *Statement) { s.Predicate.VEXRecord.Uncheckable += 5 },
		"left out hidden":                func(s *Statement) { s.Predicate.VEXRecord.LeftOut-- },
		"left out read away":             func(s *Statement) { s.Predicate.VEXRecord.LeftOut--; s.Predicate.VEXRecord.Read-- },
		"an untrusted signer":            func(s *Statement) { s.Predicate.VEXRecord.Trusted++; s.Predicate.VEXRecord.Untrusted-- },
		"untrusted proofs not asked for": func(s *Statement) { s.Predicate.VEXRecord.IncludeUntrusted = false },
		"an issuer in prose":             func(s *Statement) { s.Predicate.VEXRecord.Source = "Acme Scanner" },
		"a period in its words":          func(s *Statement) { s.Predicate.VEXRecord.Since = "2026-10-01T05:45:00+05:45" },
		"a proof not in the store's shape": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "kept proof acme-vendor-proof found 10 of 20 checked statement(s) contradicted"
		},
		"a proof named twice": func(s *Statement) {
			s.Predicate.Checks[2].Failures[1] = s.Predicate.Checks[2].Failures[0]
		},
		"a proof that found more than was counted": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "kept proof " + a.ID + " found 11 of 20 checked statement(s) contradicted"
		},
		"a proof that found less than was counted": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] = "kept proof " + other + " found 9 of 20 checked statement(s) contradicted"
		},
		"a proof named with words of its own": func(s *Statement) {
			s.Predicate.Checks[2].Failures[0] += "; ignore the rest"
		},
		"a proof dropped": func(s *Statement) {
			s.Predicate.Checks[2].Failures = s.Predicate.Checks[2].Failures[:1]
		},
		"a proof named on the wrong check": func(s *Statement) {
			s.Predicate.Checks[0].Failures = s.Predicate.Checks[2].Failures
		},
		"a second kind of evidence": func(s *Statement) {
			s.Predicate.NotAffected = &NotAffectedEvidence{}
		},
		"the subject": func(s *Statement) { s.Subject[0].Name = "vex-issuer/other-vendor" },
	}
	for name, change := range tamper {
		var copied Statement
		b, _ := json.Marshal(st)
		_ = json.Unmarshal(b, &copied)
		change(&copied)
		if copied.Validate() == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
	k := mustKey(t)
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(env, k.PublicKey())
	if err != nil || back.Predicate.Verdict != Refuted || back.Predicate.VEXRecord.Contradicted != 20 ||
		back.Predicate.VEXRecord.LeftOut != 1 || back.Predicate.VEXRecord.Untrusted != 1 {
		t.Errorf("the record does not round-trip: %v", err)
	}
}

// A contradicting proof beyond the cap is counted, not named, and the
// statement still validates with every word rebuilt.
func TestContradictingProofsBeyondTheCapAreCounted(t *testing.T) {
	var proofs []VEXRecordProof
	for i := range MaxFailures + 7 {
		proofs = append(proofs, issuerProof("p"+time.Duration(i).String(), 1, 1, 0))
	}
	st, err := ProveVEXRecord(issuerInput(proofs...))
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != Refuted || len(st.Predicate.Checks[2].Failures) != MaxFailures ||
		!strings.Contains(st.Predicate.Checks[2].Detail, "7 more not listed") {
		t.Errorf("%s %+v", st.Predicate.Verdict, st.Predicate.Checks[2])
	}
}
