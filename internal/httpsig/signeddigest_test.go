// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package httpsig_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/httpsig"
)

var coverBody = append(append([]string{}, cover...), "content-digest")

// A body is vouched for only by a digest the signature covered. A sender
// signs the request line alone; somebody on the way replaces the body and
// writes a Content-Digest for it. The header matches the new body, and
// nobody signed it.
func TestOnlyADigestThatWasSignedVouchesForTheBody(t *testing.T) {
	priv, pub := edPair(t, 9)
	sent := []byte(`{"from":1,"to":3}`)

	r := req()
	httpsig.SetContentDigest(r, sent)
	if err := httpsig.Sign(r, pub.ID, httpsig.Ed25519, priv, coverBody, at()); err != nil {
		t.Fatal(err)
	}
	signed, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.CheckSignedDigest(r, sent, signed); err != nil {
		t.Fatalf("the body as sent was refused: %v", err)
	}
	// The body swapped under the signed digest.
	swapped := []byte(`{"from":1,"to":9}`)
	if err := httpsig.CheckSignedDigest(r, swapped, signed); err == nil {
		t.Fatal("a body that is not the one the signed digest names was accepted")
	}
	// The digest rewritten for the new body: the signature no longer
	// verifies, because the header it covered changed.
	other := sha256.Sum256(swapped)
	r.Header.Set(httpsig.ContentDigest, "sha-256=:"+base64.StdEncoding.EncodeToString(other[:])+":")
	if _, err := httpsig.Verify(r, []httpsig.PublicKey{pub}, 0, at()); err == nil {
		t.Fatal("a signature verified over a Content-Digest rewritten after signing")
	}

	// A signature over a digest header the request then lacks proves
	// nothing.
	r.Header.Del(httpsig.ContentDigest)
	if err := httpsig.CheckSignedDigest(r, sent, signed); err == nil || !strings.Contains(err.Error(), "has none") {
		t.Errorf("a signed digest header that is gone: %v", err)
	}

	// A signature that covered no digest says nothing about the body,
	// whatever Content-Digest the request carries.
	r2 := req()
	httpsig.SetContentDigest(r2, swapped)
	if err := httpsig.Sign(r2, pub.ID, httpsig.Ed25519, priv, cover, at()); err != nil {
		t.Fatal(err)
	}
	s2, err := httpsig.Verify(r2, []httpsig.PublicKey{pub}, 0, at())
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.CheckContentDigest(r2, swapped); err != nil {
		t.Fatalf("the unsigned digest should match the body it was written for: %v", err)
	}
	if err := httpsig.CheckSignedDigest(r2, swapped, s2); err == nil || !strings.Contains(err.Error(), "does not cover a body digest") {
		t.Errorf("a signature over no digest vouched for a body: %v", err)
	}
	if err := httpsig.CheckSignedDigest(r2, swapped, nil); err == nil {
		t.Error("no signature at all vouched for a body")
	}

	// The older Digest header is neither written nor read.
	r3 := req()
	httpsig.SetContentDigest(r3, sent)
	if r3.Header.Get("Digest") != "" {
		t.Error("the pre-standard Digest header is still written")
	}
	r3.Header.Del(httpsig.ContentDigest)
	sum := sha256.Sum256(sent)
	r3.Header.Set("Digest", "SHA-256="+base64.StdEncoding.EncodeToString(sum[:]))
	if err := httpsig.CheckContentDigest(r3, sent); err == nil {
		t.Error("a body was vouched for by the pre-standard Digest header")
	}
}
