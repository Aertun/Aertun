// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package httpsig_test

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/httpsig"
)

func at() time.Time { return time.Unix(1787000000, 0) }

func edPair(t *testing.T, seed byte) (ed25519.PrivateKey, httpsig.PublicKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, httpsig.PublicKey{
		ID: "k-ed", Alg: httpsig.Ed25519,
		Ed: priv.Public().(ed25519.PublicKey),
	}
}

func req() *http.Request {
	return httptest.NewRequest("POST", "http://example.test/inbox", nil)
}

var cover = []string{"@method", "@authority", "@path"}

// The round trip: what this package signs, it verifies, and says what was
// covered.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	priv, pub := edPair(t, 3)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	got, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatalf("a signature this package made did not verify: %v", err)
	}
	if got == nil {
		t.Fatal("no signature was reported")
	}
	if got.KeyID != pub.ID {
		t.Errorf("key id is %q", got.KeyID)
	}
	for _, want := range cover {
		if !got.Covers(want) {
			t.Errorf("%s is not reported as covered", want)
		}
	}
}

// An unsigned request is not an error. A browser signs nothing.
func TestAnUnsignedRequestIsNotAFailure(t *testing.T) {
	got, err := httpsig.Verify(req(), nil, 0, at())
	if err != nil || got != nil {
		t.Fatalf("an unsigned request gave (%v, %v)", got, err)
	}
}

// The algorithm claim cannot be rewritten, because it is inside what was
// signed.
//
// This test first asserted the weaker thing — that a rewritten claim would be
// ignored and the signature would still verify — and it failed, which was the
// test being wrong rather than the code. The @signature-params line is the raw
// Signature-Input value and it is part of the base, so changing any of it,
// including alg, changes the base and the signature stops matching.
//
// That is a better property than ignoring the claim: it cannot be tampered
// with at all, rather than being tampered with harmlessly.
func TestTheAlgorithmClaimIsItselfSigned(t *testing.T) {
	edPriv, edPub := edPair(t, 5)
	r := req()
	if err := httpsig.Sign(r, edPub.ID, httpsig.Ed25519, edPriv, cover, at()); err != nil {
		t.Fatal(err)
	}

	// It verifies as sent.
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{edPub}, 0, at()); err != nil {
		t.Fatalf("the signature did not verify as made: %v", err)
	}

	// And not once the claim is edited.
	r.Header.Set("Signature-Input", strings.Replace(
		r.Header.Get("Signature-Input"), `alg="ed25519"`, `alg="rsa-v1_5-sha256"`, 1))
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{edPub}, 0, at()); err == nil {
		t.Fatal("the algorithm claim was rewritten and the signature still " +
			"verified, so it is not covered by the signature")
	}

	// The same holds for the key id, which is the other field an attacker
	// would want to move.
	r2 := req()
	if err := httpsig.Sign(r2, edPub.ID, httpsig.Ed25519, edPriv, cover, at()); err != nil {
		t.Fatal(err)
	}
	swapped := httpsig.PublicKey{ID: "someone-else", Alg: edPub.Alg, Ed: edPub.Ed}
	r2.Header.Set("Signature-Input", strings.Replace(
		r2.Header.Get("Signature-Input"), `keyid="k-ed"`, `keyid="someone-else"`, 1))
	if _, err := httpsig.Verify(r2, []httpsig.PublicKey{swapped}, 0, at()); err == nil {
		t.Fatal("the key id was rewritten to another configured key and the " +
			"signature still verified")
	}
}

// One algorithm, and a key says which. A key declaring any other, or
// declaring Ed25519 and carrying no key, verifies nothing; and nothing is
// signed with another.
func TestOnlyEd25519IsSignedOrVerified(t *testing.T) {
	priv, pub := edPair(t, 9)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]httpsig.PublicKey{
		"a key declaring RSA":              {ID: pub.ID, Alg: "rsa-v1_5-sha256", Ed: pub.Ed},
		"a key declaring nothing":          {ID: pub.ID, Ed: pub.Ed},
		"an Ed25519 key with no key in it": {ID: pub.ID, Alg: httpsig.Ed25519},
	} {
		if _, err := httpsig.Verify(r, []httpsig.PublicKey{key}, 0, at()); err == nil {
			t.Errorf("%s verified a signature", name)
		}
	}
	if err := httpsig.Sign(req(), pub.ID, "rsa-v1_5-sha256", priv, cover, at()); err == nil {
		t.Error("a signature was made with an algorithm that is not Ed25519")
	}
}

// The draft that came before the standard carried everything in one
// Signature header, with no Signature-Input. Nothing that sends here writes
// it, and it is refused rather than read: a second format on a door that
// takes signed batches is a second thing to get wrong.
func TestTheDraftBeforeTheStandardIsRefused(t *testing.T) {
	_, pub := edPair(t, 13)
	r := req()
	r.Header.Set("Date", at().UTC().Format(http.TimeFormat))
	r.Header.Set("Signature", `keyId="`+pub.ID+`",algorithm="hs2019",`+
		`headers="(request-target) host date",signature="AAAA"`)
	got, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err == nil || got != nil || !strings.Contains(err.Error(), "one half of a signature") {
		t.Fatalf("a draft signature gave (%v, %v)", got, err)
	}
}

// A round trip passes even when verification always says yes: signing and
// verifying agree perfectly if the verifier agrees with everything. Only a
// tampered request separates the two.
func TestATamperedRequestIsRefused(t *testing.T) {
	priv, pub := edPair(t, 11)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	// It verifies as made, so a failure below is the tampering and not a
	// broken fixture.
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err != nil {
		t.Fatalf("the signature did not verify as made: %v", err)
	}
	r.URL.Path = "/somewhere-else"
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a request altered after signing verified")
	}
}

// A component that cannot be rebuilt is refused, never skipped. Verifying over
// less than was signed and calling it valid is a forgery the verifier performs
// on itself.
func TestAnUnknownCoveredComponentIsRefusedNotSkipped(t *testing.T) {
	priv, pub := edPair(t, 13)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Signature-Input", strings.Replace(
		r.Header.Get("Signature-Input"), `"@path"`, `"@path" "@invented"`, 1))

	_, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err == nil {
		t.Fatal("a signature covering an unrebuildable component verified")
	}
	if !strings.Contains(err.Error(), "@invented") {
		t.Errorf("the error does not name the component: %v", err)
	}
}

// Covers is what lets a caller require that something in particular was
// signed. A signature over "@method" alone is valid and proves almost nothing.
func TestCoversReportsWhatWasActuallySigned(t *testing.T) {
	priv, pub := edPair(t, 17)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv,
		[]string{"@method"}, at()); err != nil {
		t.Fatal(err)
	}
	got, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Covers("@method") {
		t.Error("@method was signed and is not reported as covered")
	}
	if got.Covers("@path") {
		t.Error("@path was not signed and is reported as covered, so a caller " +
			"requiring it would be satisfied by a signature that omitted it")
	}
}

func TestAnOldSignatureIsRefused(t *testing.T) {
	priv, pub := edPair(t, 19)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover,
		at().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a ten-minute-old signature verified")
	}
}

func TestHalfASignatureIsRefused(t *testing.T) {
	priv, pub := edPair(t, 23)
	for _, drop := range []string{"Signature", "Signature-Input"} {
		r := req()
		if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
			t.Fatal(err)
		}
		r.Header.Del(drop)
		if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
			t.Errorf("a request with no %s verified", drop)
		}
	}
}

func TestAnotherKeyIsRefused(t *testing.T) {
	priv, pub := edPair(t, 29)
	_, other := edPair(t, 31)
	other.ID = pub.ID // same name, different key

	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{other}, 0, at()); err == nil {
		t.Fatal("a signature verified against a different key of the same name")
	}
}

func TestSigningNothingIsRefused(t *testing.T) {
	priv, pub := edPair(t, 37)
	if err := httpsig.Sign(req(), pub.ID, httpsig.Ed25519, priv, nil, at()); err == nil {
		t.Fatal("a signature covering no components was produced")
	}
}

// A signature that covers nothing is refused by the parser.
//
// An empty component list parses cleanly and produces a base of the parameters
// alone, so the signature authenticates possession of a key against any request
// at all. Every caller would have to remember to check; one that forgot would
// report "valid" for a proof about nothing, which is the forgery this package's
// own documentation says it must never perform on itself.
func TestASignatureOverNothingIsRefused(t *testing.T) {
	priv, pub := edPair(t, 7)
	r := req()
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	// The same signature bytes, re-labelled as covering nothing.
	r.Header.Set("Signature-Input",
		`sig1=();created=1787000000;keyid="`+pub.ID+`"`)

	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a signature covering no components verified")
	}
}
