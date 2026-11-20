// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package scitt writes and reads SCITT signed statements (RFC 9943) and the
// COSE receipts (RFC 9942) a transparency log issues for them.
//
// # Shapes
//
// A signed statement is a tagged COSE_Sign1 whose protected header carries
// the algorithm, the key's thumbprint as kid, the content type, and CWT
// claims (RFC 9597) naming the issuer, the subject and when it was issued.
// Its unprotected header is empty until it is registered; registering
// appends it to a Merkle log, and the log answers with a receipt: a tagged
// COSE_Sign1 over the log's root at some size, with the root detached and
// the inclusion proof that leads to it from the statement in the
// unprotected header (verifiable data structure 1, RFC 9162 SHA-256). A
// statement carrying receipts under label 394 is a transparent statement.
//
// # What is in the log
//
// The entry is the statement as signed, with its unprotected header empty
// (RFC 9943 §6.3), so receipts attached afterwards change nothing a receipt
// proves. A receipt is checked by computing the root the proof leads to
// from that entry and verifying the log's signature over it; a receipt
// whose leaf index is not below its tree size is refused, as RFC 9942 §5.2
// requires.
package scitt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/cbor"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/translog"
)

// Header labels from RFC 9942 and RFC 9943.
const (
	LabelReceipts = 394
	LabelVDS      = 395
	LabelVDP      = 396
	// VDSRFC9162 is the RFC 9162 SHA-256 binary Merkle tree.
	VDSRFC9162 = 1
	// ProofInclusion is the inclusion-proof key inside the vdp map.
	ProofInclusion = -1
)

// CWT claim keys (RFC 8392).
const (
	claimIss = 1
	claimSub = 2
	claimIat = 6
)

// MaxClaim bounds the issuer and subject, as RFC 9943 bounds an issuer URI.
const MaxClaim = 8192

// MaxReceipts bounds how many receipts one statement may carry.
const MaxReceipts = 16

// MaxPath bounds an inclusion path: 64 hashes is a tree of 2^64 entries.
const MaxPath = 64

// Statement is what an issuer says, before it is signed.
type Statement struct {
	Issuer      string
	Subject     string
	IssuedAt    time.Time
	ContentType string
	Payload     []byte
}

// Sign makes a signed statement with the payload attached.
func Sign(s cose.Signer, st Statement) ([]byte, error) {
	if err := CheckClaim("issuer", st.Issuer); err != nil {
		return nil, err
	}
	if err := CheckClaim("subject", st.Subject); err != nil {
		return nil, err
	}
	if st.ContentType == "" || !utf8.ValidString(st.ContentType) {
		return nil, errors.New("a statement names its content type")
	}
	header := cbor.Map{
		{Key: cbor.Int(cose.LabelContentType), Value: cbor.Text(st.ContentType)},
		{Key: cbor.Int(cose.LabelCWTClaims), Value: claims(st.Issuer, st.Subject, st.IssuedAt)},
	}
	m, err := cose.Sign(s, header, st.Payload, false, nil)
	if err != nil {
		return nil, err
	}
	return m.Encode()
}

func claims(iss, sub string, at time.Time) cbor.Map {
	c := cbor.Map{{Key: cbor.Int(claimIss), Value: cbor.Text(iss)}, {Key: cbor.Int(claimSub), Value: cbor.Text(sub)}}
	if !at.IsZero() {
		c = append(c, cbor.Entry{Key: cbor.Int(claimIat), Value: cbor.Int(at.Unix())})
	}
	return c
}

// CheckClaim checks an issuer or subject: 1 to MaxClaim bytes of text.
func CheckClaim(name, v string) error {
	if v == "" || len(v) > MaxClaim || !utf8.ValidString(v) {
		return fmt.Errorf("the %s is 1 to %d bytes of text", name, MaxClaim)
	}
	return nil
}

// Signed is a signed statement read back.
type Signed struct {
	Message     *cose.Sign1
	Issuer      string
	Subject     string
	IssuedAt    time.Time
	ContentType string
	// Receipts are the receipts attached under label 394, unverified.
	Receipts [][]byte
}

// Read parses a signed or transparent statement and checks the headers
// RFC 9943 §6 requires; it does not check the signature.
func Read(b []byte) (*Signed, error) {
	m, err := cose.Parse(b)
	if err != nil {
		return nil, err
	}
	iss, sub, at, err := readClaims(m.Header)
	if err != nil {
		return nil, err
	}
	s := &Signed{Message: m, Issuer: iss, Subject: sub, IssuedAt: at}
	if m.KeyID() == nil {
		_, x5t := m.Header.Get(cbor.Int(cose.LabelX5T))
		_, x5c := m.Header.Get(cbor.Int(cose.LabelX5Chain))
		if !x5t && !x5c {
			return nil, errors.New("a signed statement names its key: kid, or x5t or x5chain, in the protected header")
		}
	}
	if ct, ok := m.Header.Get(cbor.Int(cose.LabelContentType)); ok {
		switch v := ct.(type) {
		case cbor.Text:
			s.ContentType = string(v)
		case cbor.Uint:
			s.ContentType = fmt.Sprintf("coap/%d", v)
		default:
			return nil, errors.New("the content type is text or a CoAP number")
		}
	}
	if r, ok := m.Unprotected.Get(cbor.Int(LabelReceipts)); ok {
		list, ok := r.(cbor.Array)
		if !ok || len(list) == 0 || len(list) > MaxReceipts {
			return nil, fmt.Errorf("receipts are an array of 1 to %d byte strings", MaxReceipts)
		}
		for _, item := range list {
			rb, ok := item.(cbor.Bytes)
			if !ok {
				return nil, errors.New("a receipt is carried as a byte string")
			}
			s.Receipts = append(s.Receipts, rb)
		}
	}
	return s, nil
}

func readClaims(h cbor.Map) (iss, sub string, at time.Time, err error) {
	v, ok := h.Get(cbor.Int(cose.LabelCWTClaims))
	if !ok {
		return "", "", at, errors.New("the protected header carries no CWT claims (label 15)")
	}
	c, ok := v.(cbor.Map)
	if !ok {
		return "", "", at, errors.New("the CWT claims are not a map")
	}
	text := func(key int64, name string, required bool) (string, error) {
		v, ok := c.Get(cbor.Int(key))
		if !ok {
			if required {
				return "", fmt.Errorf("the CWT claims name no %s", name)
			}
			return "", nil
		}
		t, ok := v.(cbor.Text)
		if !ok {
			return "", fmt.Errorf("the %s claim is not text", name)
		}
		return string(t), CheckClaim(name, string(t))
	}
	if iss, err = text(claimIss, "issuer", true); err != nil {
		return
	}
	if sub, err = text(claimSub, "subject", true); err != nil {
		return
	}
	if v, ok := c.Get(cbor.Int(claimIat)); ok {
		n, ok := cbor.AsInt(v)
		if !ok {
			return "", "", at, errors.New("the issued-at claim is not an integer")
		}
		at = time.Unix(n, 0).UTC()
	}
	return iss, sub, at, nil
}

// Entry is the statement as a log holds it: as signed, with an empty
// unprotected header.
func (s *Signed) Entry() ([]byte, error) {
	bare := *s.Message
	bare.Unprotected = cbor.Map{}
	return bare.Encode()
}

// Verify checks the statement's signature.
func (s *Signed) Verify(v cose.Verifier) error { return s.Message.Verify(v, nil, nil) }

// Attach adds receipts to a statement, making it transparent.
func Attach(statement []byte, receipts ...[]byte) ([]byte, error) {
	s, err := Read(statement)
	if err != nil {
		return nil, err
	}
	all := append(append([][]byte(nil), s.Receipts...), receipts...)
	if len(all) > MaxReceipts {
		return nil, fmt.Errorf("a statement carries at most %d receipts", MaxReceipts)
	}
	list := make(cbor.Array, len(all))
	for i, r := range all {
		list[i] = cbor.Bytes(r)
	}
	m := *s.Message
	m.Unprotected = cbor.Map{{Key: cbor.Int(LabelReceipts), Value: list}}
	return m.Encode()
}

// -- receipts -----------------------------------------------------------------

// Inclusion is what a verified receipt establishes: that the entry is in
// the tree whose root, Root, the log signed.
//
// Size and Index are as the proof states them, and RFC 9942 signs neither:
// the signature is over the root alone. The root commits to the tree's true
// size, but a proof's size can be restated as any other size whose
// inclusion walk has the same shape (index 2 at size 5 walks as it does at
// sizes 6 to 8) and still lead to the same root. So a caller that relies on
// the size, to order entries or to count them, compares Root with a head
// the log signed at that size; inclusion itself needs nothing more.
type Inclusion struct {
	Issuer    string
	Subject   string
	IssuedAt  time.Time
	Algorithm int64
	Size      uint64
	Index     uint64
	Root      []byte
}

// IssueReceipt signs a receipt for the entry at index in the log at size,
// after checking that the entry given is the one the log holds there.
func IssueReceipt(s cose.Signer, issuer, subject string, log *translog.Log, entry []byte,
	index, size int, at time.Time) ([]byte, error) {

	head, err := log.HeadAt(size)
	if err != nil {
		return nil, err
	}
	root, err := translog.DecodeHashes([]string{head.Root})
	if err != nil {
		return nil, err
	}
	hexPath, err := log.InclusionProof(index, size)
	if err != nil {
		return nil, err
	}
	path, err := translog.DecodeHashes(hexPath)
	if err != nil {
		return nil, err
	}
	if err := translog.VerifyInclusion(translog.HashLeaf(entry), index, size, path, root[0]); err != nil {
		return nil, fmt.Errorf("the log does not hold this entry at %d: %w", index, err)
	}
	items := make(cbor.Array, len(path))
	for i, h := range path {
		items[i] = cbor.Bytes(h)
	}
	proof, err := cbor.Encode(cbor.Array{cbor.Uint(size), cbor.Uint(index), items})
	if err != nil {
		return nil, err
	}
	header := cbor.Map{
		{Key: cbor.Int(LabelVDS), Value: cbor.Int(VDSRFC9162)},
		{Key: cbor.Int(cose.LabelCWTClaims), Value: claims(issuer, subject, at)},
	}
	m, err := cose.Sign(s, header, root[0], true, nil)
	if err != nil {
		return nil, err
	}
	m.Unprotected = cbor.Map{{Key: cbor.Int(LabelVDP), Value: cbor.Map{
		{Key: cbor.Int(ProofInclusion), Value: cbor.Array{cbor.Bytes(proof)}}}}}
	return m.Encode()
}

// ReadReceipt parses a receipt without verifying it, for a caller that
// needs its issuer and key to choose a verifier.
func ReadReceipt(b []byte) (*cose.Sign1, Inclusion, [][]byte, error) {
	var in Inclusion
	m, err := cose.Parse(b)
	if err != nil {
		return nil, in, nil, fmt.Errorf("the receipt: %w", err)
	}
	if in.Algorithm, err = m.Algorithm(); err != nil {
		return nil, in, nil, err
	}
	vds, ok := m.Header.Get(cbor.Int(LabelVDS))
	if n, isInt := cbor.AsInt(vds); !ok || !isInt || n != VDSRFC9162 {
		return nil, in, nil, errors.New("the receipt is not for an RFC 9162 SHA-256 Merkle tree (vds 1)")
	}
	if in.Issuer, in.Subject, in.IssuedAt, err = readClaims(m.Header); err != nil {
		return nil, in, nil, fmt.Errorf("the receipt: %w", err)
	}
	if m.Payload != nil {
		return nil, in, nil, errors.New("the receipt carries its root; RFC 9942 detaches it, to be computed from the proof")
	}
	vdp, ok := m.Unprotected.Get(cbor.Int(LabelVDP))
	proofs, isMap := vdp.(cbor.Map)
	if !ok || !isMap {
		return nil, in, nil, errors.New("the receipt carries no verifiable proofs (label 396)")
	}
	incl, ok := proofs.Get(cbor.Int(ProofInclusion))
	list, isArr := incl.(cbor.Array)
	if !ok || !isArr || len(list) != 1 {
		return nil, in, nil, errors.New("the receipt carries exactly one inclusion proof here")
	}
	raw, ok := list[0].(cbor.Bytes)
	if !ok {
		return nil, in, nil, errors.New("an inclusion proof is carried as a byte string")
	}
	pv, err := cbor.Decode(raw)
	if err != nil {
		return nil, in, nil, fmt.Errorf("the inclusion proof: %w", err)
	}
	parts, ok := pv.(cbor.Array)
	if !ok || len(parts) != 3 {
		return nil, in, nil, errors.New("an inclusion proof is [tree size, leaf index, path]")
	}
	size, ok1 := parts[0].(cbor.Uint)
	index, ok2 := parts[1].(cbor.Uint)
	hashes, ok3 := parts[2].(cbor.Array)
	if !ok1 || !ok2 || !ok3 {
		return nil, in, nil, errors.New("an inclusion proof is [tree size, leaf index, path]")
	}
	if index >= size {
		return nil, in, nil, fmt.Errorf("the leaf index %d is not below the tree size %d", index, size)
	}
	if len(hashes) > MaxPath {
		return nil, in, nil, fmt.Errorf("an inclusion path is at most %d hashes", MaxPath)
	}
	path := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, ok := h.(cbor.Bytes)
		if !ok || len(b) != sha256.Size {
			return nil, in, nil, fmt.Errorf("path hash %d is not %d bytes", i, sha256.Size)
		}
		path[i] = b
	}
	in.Size, in.Index = uint64(size), uint64(index)
	return m, in, path, nil
}

// VerifyReceipt checks a receipt for an entry with the log's key.
func VerifyReceipt(receipt, entry []byte, v cose.Verifier) (Inclusion, error) {
	m, in, path, err := ReadReceipt(receipt)
	if err != nil {
		return in, err
	}
	if in.Size > uint64(math.MaxInt) {
		return in, errors.New("the tree size is past what is read here")
	}
	root, err := translog.RootFromInclusion(translog.HashLeaf(entry), int(in.Index), int(in.Size), path)
	if err != nil {
		return in, fmt.Errorf("the inclusion proof does not lead from this entry: %w", err)
	}
	if err := m.Verify(v, root, nil); err != nil {
		return in, fmt.Errorf("the receipt: %w", err)
	}
	in.Root = root
	return in, nil
}
