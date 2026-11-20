// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package scitt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/cbor"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/translog"
)

type pair struct {
	s cose.Signer
	v cose.Verifier
}

func keyPairs(t *testing.T, seed byte) (ed, ml pair) {
	t.Helper()
	es, err := cose.NewEd25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := cose.NewEd25519Verifier(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey))
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := cose.NewMLDSA65Signer(priv)
	mv, _ := cose.NewMLDSA65Verifier(priv.PublicKey())
	return pair{es, ev}, pair{ms, mv}
}

var when = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func statement(t *testing.T, s cose.Signer, sub string) []byte {
	t.Helper()
	b, err := Sign(s, Statement{Issuer: "https://gateway.example", Subject: sub, IssuedAt: when,
		ContentType: "application/example+cbor", Payload: []byte("payload " + sub)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStatement(t *testing.T) {
	ed, ml := keyPairs(t, 1)
	for _, p := range []pair{ed, ml} {
		b := statement(t, p.s, "action-1")
		s, err := Read(b)
		if err != nil {
			t.Fatal(err)
		}
		if s.Issuer != "https://gateway.example" || s.Subject != "action-1" || !s.IssuedAt.Equal(when) ||
			s.ContentType != "application/example+cbor" || len(s.Receipts) != 0 {
			t.Errorf("read back %+v", s)
		}
		if err := s.Verify(p.v); err != nil {
			t.Fatal(err)
		}
		entry, _ := s.Entry()
		if !bytes.Equal(entry, b) {
			t.Error("a statement with no receipts is not its own entry")
		}
	}
	if _, err := Sign(ed.s, Statement{Issuer: "", Subject: "x", ContentType: "a/b"}); err == nil {
		t.Error("a statement with no issuer was signed")
	}
	if _, err := Sign(ed.s, Statement{Issuer: "i", Subject: strings.Repeat("x", MaxClaim+1), ContentType: "a/b"}); err == nil {
		t.Error("an oversized subject was signed")
	}
}

// TestReceipts: every entry of logs of every size up to 17 gets a receipt
// in both algorithms that verifies against its own entry and no other.
func TestReceipts(t *testing.T) {
	ed, ml := keyPairs(t, 1)
	led, lml := keyPairs(t, 7)
	log := translog.New()
	var entries [][]byte
	for i := 0; i < 17; i++ {
		e := statement(t, []cose.Signer{ed.s, ml.s}[i%2], fmt.Sprint("action-", i))
		entries = append(entries, e)
		log.Append(e)
	}
	for size := 1; size <= len(entries); size++ {
		for index := 0; index < size; index++ {
			for _, p := range []pair{led, lml} {
				r, err := IssueReceipt(p.s, "https://log.example", "action", log, entries[index], index, size, when)
				if err != nil {
					t.Fatalf("size %d index %d: %v", size, index, err)
				}
				in, err := VerifyReceipt(r, entries[index], p.v)
				if err != nil {
					t.Fatalf("size %d index %d: %v", size, index, err)
				}
				if in.Size != uint64(size) || in.Index != uint64(index) || in.Issuer != "https://log.example" {
					t.Errorf("inclusion %+v", in)
				}
				other := entries[(index+1)%len(entries)]
				if _, err := VerifyReceipt(r, other, p.v); err == nil {
					t.Errorf("size %d index %d: a receipt verified for another entry", size, index)
				}
			}
		}
	}
	if _, err := IssueReceipt(led.s, "l", "s", log, entries[3], 4, 10, when); err == nil {
		t.Error("a receipt was issued for an entry the log does not hold at that index")
	}
}

func TestTransparent(t *testing.T) {
	ed, _ := keyPairs(t, 1)
	led, lml := keyPairs(t, 7)
	b := statement(t, ed.s, "a")
	log := translog.New()
	log.Append(b)
	r1, _ := IssueReceipt(led.s, "https://log.example", "a", log, b, 0, 1, when)
	r2, _ := IssueReceipt(lml.s, "https://log.example", "a", log, b, 0, 1, when)
	tr, err := Attach(b, r1)
	if err != nil {
		t.Fatal(err)
	}
	tr, err = Attach(tr, r2)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Read(tr)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Receipts) != 2 {
		t.Fatalf("%d receipts", len(s.Receipts))
	}
	entry, _ := s.Entry()
	if !bytes.Equal(entry, b) {
		t.Fatal("attaching receipts changed the entry")
	}
	if err := s.Verify(ed.v); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(s.Receipts[0], entry, led.v); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(s.Receipts[1], entry, lml.v); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReceipt(s.Receipts[1], entry, led.v); err == nil {
		t.Error("an ML-DSA receipt verified with an Ed25519 key")
	}
}

// TestReceiptRefusals: each malformed receipt is refused for its own reason.
func TestReceiptRefusals(t *testing.T) {
	ed, _ := keyPairs(t, 1)
	led, _ := keyPairs(t, 7)
	log := translog.New()
	var entries [][]byte
	for i := 0; i < 5; i++ {
		e := statement(t, ed.s, fmt.Sprint(i))
		entries = append(entries, e)
		log.Append(e)
	}
	good, err := IssueReceipt(led.s, "https://log.example", "s", log, entries[2], 2, 5, when)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := cose.Parse(good)
	_, _, path, _ := ReadReceipt(good)
	proof := func(size, index uint64, path [][]byte) cbor.Map {
		items := cbor.Array{}
		for _, h := range path {
			items = append(items, cbor.Bytes(h))
		}
		p, _ := cbor.Encode(cbor.Array{cbor.Uint(size), cbor.Uint(index), items})
		return cbor.Map{{Key: cbor.Int(LabelVDP), Value: cbor.Map{{Key: cbor.Int(ProofInclusion), Value: cbor.Array{cbor.Bytes(p)}}}}}
	}
	with := func(un cbor.Map) []byte {
		c := *m
		c.Unprotected = un
		b, _ := c.Encode()
		return b
	}
	short := path[:len(path)-1]
	long := append(append([][]byte(nil), path...), path[0])
	cases := map[string][]byte{
		"index at size": with(proof(5, 5, path)),
		"index moved":   with(proof(5, 3, path)),
		"size reshaped": with(proof(3, 2, path)),
		"path short":    with(proof(5, 2, short)),
		"path long":     with(proof(5, 2, long)),
		"no proofs":     with(cbor.Map{}),
	}
	for name, b := range cases {
		if _, err := VerifyReceipt(b, entries[2], led.v); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	truncated := append(append([][]byte(nil), path[:len(path)-1]...), path[len(path)-1][:31])
	if _, err := VerifyReceipt(with(proof(5, 2, truncated)), entries[2], led.v); err == nil || !strings.Contains(err.Error(), "not 32 bytes") {
		t.Errorf("a path hash of 31 bytes: %v", err)
	}
	// RFC 9942 signs the root, not the size: a size whose walk has the same
	// shape verifies, and leads to the root of the tree that was signed.
	restated, err := VerifyReceipt(with(proof(8, 2, path)), entries[2], led.v)
	if err != nil {
		t.Fatalf("a restated size whose walk has the same shape: %v", err)
	}
	head, _ := log.HeadAt(5)
	if fmt.Sprintf("%x", restated.Root) != head.Root || restated.Size != 8 {
		t.Errorf("restated size leads to %x (size %d), want the size-5 root %s", restated.Root, restated.Size, head.Root)
	}
	attached := *m
	attached.Payload = []byte("root")
	ab, _ := attached.Encode()
	if _, err := VerifyReceipt(ab, entries[2], led.v); err == nil || !strings.Contains(err.Error(), "detaches") {
		t.Errorf("a receipt carrying its root: %v", err)
	}
	// A receipt with no vds, signed properly, is still not a receipt.
	noVDS, _ := cose.Sign(led.s, cbor.Map{{Key: cbor.Int(cose.LabelCWTClaims), Value: claims("i", "s", when)}}, []byte{}, true, nil)
	noVDS.Unprotected = proof(5, 2, path)
	nb, _ := noVDS.Encode()
	if _, err := VerifyReceipt(nb, entries[2], led.v); err == nil || !strings.Contains(err.Error(), "vds") {
		t.Errorf("a receipt with no vds: %v", err)
	}
}

func TestReadRefusals(t *testing.T) {
	ed, _ := keyPairs(t, 1)
	sign := func(h cbor.Map) []byte {
		m, err := cose.Sign(ed.s, h, []byte("p"), false, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.Encode()
		return b
	}
	cases := map[string][]byte{
		"no claims":      sign(cbor.Map{}),
		"no subject":     sign(cbor.Map{{Key: cbor.Int(15), Value: cbor.Map{{Key: cbor.Int(1), Value: cbor.Text("i")}}}}),
		"issuer number":  sign(cbor.Map{{Key: cbor.Int(15), Value: cbor.Map{{Key: cbor.Int(1), Value: cbor.Int(1)}, {Key: cbor.Int(2), Value: cbor.Text("s")}}}}),
		"empty subject":  sign(cbor.Map{{Key: cbor.Int(15), Value: cbor.Map{{Key: cbor.Int(1), Value: cbor.Text("i")}, {Key: cbor.Int(2), Value: cbor.Text("")}}}}),
		"claims not map": sign(cbor.Map{{Key: cbor.Int(15), Value: cbor.Text("i")}}),
	}
	for name, b := range cases {
		if _, err := Read(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	b := statement(t, ed.s, "s")
	m, _ := cose.Parse(b)
	m.Unprotected = cbor.Map{{Key: cbor.Int(LabelReceipts), Value: cbor.Array{cbor.Text("not bytes")}}}
	bad, _ := m.Encode()
	if _, err := Read(bad); err == nil {
		t.Error("a receipt that is not a byte string was accepted")
	}
}
