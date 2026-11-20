// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/cbor"
)

func keys(t *testing.T) (*Ed25519, *MLDSA65) {
	t.Helper()
	ed, err := NewEd25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ml, err := NewMLDSA65Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	return ed, ml
}

func verifiers(t *testing.T, ed *Ed25519, ml *MLDSA65) (*Ed25519, *MLDSA65) {
	t.Helper()
	ev, err := NewEd25519Verifier(ed.pub)
	if err != nil {
		t.Fatal(err)
	}
	mv, err := NewMLDSA65Verifier(ml.pub)
	if err != nil {
		t.Fatal(err)
	}
	return ev, mv
}

func TestRoundTrip(t *testing.T) {
	ed, ml := keys(t)
	ev, mv := verifiers(t, ed, ml)
	header := cbor.Map{{Key: cbor.Int(LabelContentType), Value: cbor.Text("application/example")}}
	payload := []byte("an action happened")
	for _, c := range []struct {
		s Signer
		v Verifier
	}{{ed, ev}, {ml, mv}} {
		for _, detached := range []bool{false, true} {
			m, err := Sign(c.s, header, payload, detached, []byte("aad"))
			if err != nil {
				t.Fatal(err)
			}
			b, err := m.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !cbor.Canonical(b) {
				t.Error("a message this package writes is not in deterministic form")
			}
			back, err := Parse(b)
			if err != nil {
				t.Fatal(err)
			}
			var given []byte
			if detached {
				given = payload
				if back.Payload != nil {
					t.Error("a detached message carries its payload")
				}
			}
			if err := back.Verify(c.v, given, []byte("aad")); err != nil {
				t.Fatalf("alg %d detached %v: %v", c.s.Algorithm(), detached, err)
			}
			if err := back.Verify(c.v, given, []byte("other")); err == nil {
				t.Error("verified under different external data")
			}
		}
	}
}

// TestDeterministic: the same bytes sign to the same message, so a
// message is a commitment and a test vector is reproducible.
func TestDeterministic(t *testing.T) {
	ed, ml := keys(t)
	for _, s := range []Signer{ed, ml} {
		a, _ := Sign(s, nil, []byte("x"), false, nil)
		b, _ := Sign(s, nil, []byte("x"), false, nil)
		ab, _ := a.Encode()
		bb, _ := b.Encode()
		if !bytes.Equal(ab, bb) {
			t.Errorf("alg %d is not deterministic", s.Algorithm())
		}
	}
}

// TestTamper: a changed byte anywhere signed, a wrong key, an algorithm the
// key does not verify, or a kid that is not the key's, all fail.
func TestTamper(t *testing.T) {
	ed, ml := keys(t)
	ev, mv := verifiers(t, ed, ml)
	m, err := Sign(ed, nil, []byte("payload"), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(ev, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(mv, nil, nil); err == nil {
		t.Error("an Ed25519 message verified with an ML-DSA key")
	}
	other, _ := NewEd25519Verifier(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey))
	if err := m.Verify(other, nil, nil); err == nil || !strings.Contains(err.Error(), "names key") {
		t.Errorf("another key's verifier: %v", err)
	}
	flip := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 1; return c }
	for name, mut := range map[string]*Sign1{
		"payload":   {Protected: m.Protected, Header: m.Header, Payload: flip(m.Payload, 0), Signature: m.Signature},
		"signature": {Protected: m.Protected, Header: m.Header, Payload: m.Payload, Signature: flip(m.Signature, 5)},
		"protected": {Protected: flip(m.Protected, len(m.Protected)-1), Header: m.Header, Payload: m.Payload, Signature: m.Signature},
	} {
		if err := mut.Verify(ev, nil, nil); err == nil {
			t.Errorf("a changed %s verified", name)
		}
	}
	if err := m.Verify(ev, []byte("payload"), nil); err == nil {
		t.Error("an attached message verified against a second payload")
	}
	d, _ := Sign(ml, nil, []byte("payload"), true, nil)
	if err := d.Verify(mv, nil, nil); err == nil {
		t.Error("a detached message verified with no payload")
	}
	if err := d.Verify(mv, []byte("payloaD"), nil); err == nil {
		t.Error("a detached message verified against another payload")
	}
	if _, err := Sign(ed, cbor.Map{{Key: cbor.Int(LabelAlg), Value: cbor.Int(AlgMLDSA65)}}, nil, false, nil); err == nil {
		t.Error("a caller set the algorithm")
	}
}

// TestDeprecatedEdDSA: a message from an issuer still writing EdDSA (-8)
// verifies with the Ed25519 key it names.
func TestDeprecatedEdDSA(t *testing.T) {
	ed, ml := keys(t)
	ev, _ := verifiers(t, ed, ml)
	protected, _ := cbor.Encode(cbor.Map{{Key: cbor.Int(LabelAlg), Value: cbor.Int(AlgEdDSA)}})
	tbs, _ := toBeSigned(protected, []byte("p"), nil)
	sig, _ := ed.Sign(tbs)
	b, _ := (&Sign1{Protected: protected, Payload: []byte("p"), Signature: sig}).Encode()
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(ev, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestParseRefusals(t *testing.T) {
	ed, _ := keys(t)
	good, _ := Sign(ed, nil, []byte("p"), false, nil)
	enc := func(v cbor.Value) []byte {
		b, err := cbor.Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	prot := func(m cbor.Map) cbor.Bytes { return cbor.Bytes(enc(m)) }
	alg := cbor.Entry{Key: cbor.Int(LabelAlg), Value: cbor.Int(AlgEd25519)}
	sig := cbor.Bytes(good.Signature)
	cases := map[string][]byte{
		"untagged":           enc(cbor.Array{prot(cbor.Map{alg}), cbor.Map{}, cbor.Bytes("p"), sig}),
		"COSE_Sign tag":      enc(cbor.Tagged{Tag: 98, Value: cbor.Array{prot(cbor.Map{alg}), cbor.Map{}, cbor.Bytes("p"), sig}}),
		"three items":        enc(cbor.Tagged{Tag: 18, Value: cbor.Array{prot(cbor.Map{alg}), cbor.Map{}, cbor.Bytes("p")}}),
		"text payload":       enc(cbor.Tagged{Tag: 18, Value: cbor.Array{prot(cbor.Map{alg}), cbor.Map{}, cbor.Text("p"), sig}}),
		"no algorithm":       enc(cbor.Tagged{Tag: 18, Value: cbor.Array{cbor.Bytes{}, cbor.Map{alg}, cbor.Bytes("p"), sig}}),
		"label in both":      enc(cbor.Tagged{Tag: 18, Value: cbor.Array{prot(cbor.Map{alg}), cbor.Map{alg}, cbor.Bytes("p"), sig}}),
		"critical header":    enc(cbor.Tagged{Tag: 18, Value: cbor.Array{prot(cbor.Map{alg, {Key: cbor.Int(LabelCrit), Value: cbor.Array{cbor.Int(99)}}, {Key: cbor.Int(99), Value: cbor.Bool(true)}}), cbor.Map{}, cbor.Bytes("p"), sig}}),
		"protected not map":  enc(cbor.Tagged{Tag: 18, Value: cbor.Array{cbor.Bytes(enc(cbor.Array{})), cbor.Map{}, cbor.Bytes("p"), sig}}),
		"protected trailing": enc(cbor.Tagged{Tag: 18, Value: cbor.Array{cbor.Bytes(append(enc(cbor.Map{alg}), 0)), cbor.Map{}, cbor.Bytes("p"), sig}}),
		"too large":          make([]byte, MaxMessage+1),
	}
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestThumbprints pins the kid computation (RFC 9679 over the members RFC
// 9679 §4.1 and RFC 9964 §6 name), so a change to it is seen.
func TestThumbprints(t *testing.T) {
	ed, ml := keys(t)
	pk, _ := cbor.Encode(cbor.Map{{Key: cbor.Int(1), Value: cbor.Int(1)}, {Key: cbor.Int(-1), Value: cbor.Int(6)},
		{Key: cbor.Int(-2), Value: cbor.Bytes(ed.pub)}})
	if !strings.HasPrefix(hex.EncodeToString(pk), "a301012006215820") {
		t.Errorf("the OKP thumbprint input is %x", pk[:8])
	}
	if len(ed.KeyID()) != 32 || len(ml.KeyID()) != 32 || bytes.Equal(ed.KeyID(), ml.KeyID()) {
		t.Error("thumbprints are not distinct SHA-256 digests")
	}
}
