// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package cose signs and verifies COSE_Sign1 messages (RFC 9052) with the
// two algorithms this program holds keys for: Ed25519 (RFC 9864, -19) and
// ML-DSA-65 (RFC 9964, -49).
//
// # One algorithm per message
//
// A COSE_Sign1 carries one signature. This program's other documents carry
// two, one per algorithm, so a break in either leaves the other standing.
// The evidence protocol keeps that property without leaving the standard:
// a statement is signed with one algorithm, and the log that registers it
// issues a receipt in each (RFC 9943 lets a statement carry any number of
// receipts). A verifier that wants both requires both receipts; one that
// knows only Ed25519 still verifies the statement.
//
// # What is checked
//
// The algorithm must be in the protected header and must be the
// verifier's; a key identifier, when present, must be the verifier's; no
// label may appear in both headers; and a critical header this program does
// not process is refused, as RFC 9052 §3.1 requires. Signatures are checked
// over the protected header exactly as received, never over a re-encoding.
package cose

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/aertun/aertun/internal/cbor"
)

// Algorithm identifiers from the IANA COSE Algorithms registry.
const (
	// AlgEd25519 is EdDSA on Ed25519 (RFC 9864), what this program signs with.
	AlgEd25519 int64 = -19
	// AlgEdDSA is the polymorphic EdDSA identifier RFC 9864 deprecates;
	// read, with an Ed25519 key, for issuers that still write it, never
	// written.
	AlgEdDSA int64 = -8
	// AlgMLDSA65 is ML-DSA-65 (FIPS 204, RFC 9964), signed with the empty
	// context RFC 9964 §5 requires.
	AlgMLDSA65 int64 = -49
)

// Header labels from the IANA COSE Header Parameters registry.
const (
	LabelAlg         = 1
	LabelCrit        = 2
	LabelContentType = 3
	LabelKID         = 4
	LabelCWTClaims   = 15
	LabelX5Chain     = 33
	LabelX5T         = 34
)

// TagSign1 is the CBOR tag of a COSE_Sign1.
const TagSign1 = 18

// MaxMessage bounds a message read here. A statement with an ML-DSA
// signature and a few receipts is some tens of kilobytes; a megabyte is
// room for anything legitimate and a limit on anything else.
const MaxMessage = 1 << 20

// Signer makes signatures for one algorithm and key.
type Signer interface {
	Algorithm() int64
	// KeyID is what goes in the kid header: the key's thumbprint.
	KeyID() []byte
	Sign(toBeSigned []byte) ([]byte, error)
}

// Verifier checks signatures for one key.
type Verifier interface {
	// Accepts says whether a message's alg header is one this key verifies.
	Accepts(alg int64) bool
	KeyID() []byte
	Verify(toBeSigned, signature []byte) error
}

// -- keys ---------------------------------------------------------------------

// Ed25519 is an Ed25519 key, public or private.
type Ed25519 struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewEd25519Signer wraps a private key.
func NewEd25519Signer(priv ed25519.PrivateKey) (*Ed25519, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("an Ed25519 private key is 64 bytes")
	}
	return &Ed25519{pub: priv.Public().(ed25519.PublicKey), priv: priv}, nil
}

// NewEd25519Verifier wraps a public key.
func NewEd25519Verifier(pub ed25519.PublicKey) (*Ed25519, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("an Ed25519 public key is 32 bytes")
	}
	return &Ed25519{pub: pub}, nil
}

// Algorithm is Ed25519's fully specified identifier.
func (k *Ed25519) Algorithm() int64 { return AlgEd25519 }

// Accepts Ed25519, and the deprecated EdDSA that names it with this key.
func (k *Ed25519) Accepts(alg int64) bool { return alg == AlgEd25519 || alg == AlgEdDSA }

// KeyID is the RFC 9679 thumbprint of the OKP key: kty 1, crv 6, x.
func (k *Ed25519) KeyID() []byte {
	return thumbprint(cbor.Map{{Key: cbor.Int(1), Value: cbor.Int(1)},
		{Key: cbor.Int(-1), Value: cbor.Int(6)}, {Key: cbor.Int(-2), Value: cbor.Bytes(k.pub)}})
}

// Sign signs with the private key.
func (k *Ed25519) Sign(msg []byte) ([]byte, error) {
	if k.priv == nil {
		return nil, errors.New("this Ed25519 key is public only")
	}
	return ed25519.Sign(k.priv, msg), nil
}

// Verify checks a signature.
func (k *Ed25519) Verify(msg, sig []byte) error {
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.pub, msg, sig) {
		return errors.New("the Ed25519 signature does not verify")
	}
	return nil
}

// MLDSA65 is an ML-DSA-65 key, public or private.
type MLDSA65 struct {
	pub  *mldsa.PublicKey
	priv *mldsa.PrivateKey
}

// NewMLDSA65Signer wraps a private key.
func NewMLDSA65Signer(priv *mldsa.PrivateKey) (*MLDSA65, error) {
	if priv == nil {
		return nil, errors.New("no ML-DSA-65 key")
	}
	return &MLDSA65{pub: priv.PublicKey(), priv: priv}, nil
}

// NewMLDSA65Verifier wraps a public key.
func NewMLDSA65Verifier(pub *mldsa.PublicKey) (*MLDSA65, error) {
	if pub == nil {
		return nil, errors.New("no ML-DSA-65 key")
	}
	return &MLDSA65{pub: pub}, nil
}

// Algorithm is ML-DSA-65.
func (k *MLDSA65) Algorithm() int64 { return AlgMLDSA65 }

// Accepts ML-DSA-65 only.
func (k *MLDSA65) Accepts(alg int64) bool { return alg == AlgMLDSA65 }

// KeyID is the RFC 9679 thumbprint of the AKP key, with the members RFC
// 9964 §6 names: kty 7, alg, pub.
func (k *MLDSA65) KeyID() []byte {
	return thumbprint(cbor.Map{{Key: cbor.Int(1), Value: cbor.Int(7)},
		{Key: cbor.Int(3), Value: cbor.Int(AlgMLDSA65)}, {Key: cbor.Int(-1), Value: cbor.Bytes(k.pub.Bytes())}})
}

// Sign signs deterministically with the empty context (RFC 9964 §5), so
// the same bytes sign to the same signature.
func (k *MLDSA65) Sign(msg []byte) ([]byte, error) {
	if k.priv == nil {
		return nil, errors.New("this ML-DSA-65 key is public only")
	}
	return k.priv.SignDeterministic(msg, &mldsa.Options{})
}

// Verify checks a signature with the empty context.
func (k *MLDSA65) Verify(msg, sig []byte) error {
	if err := mldsa.Verify(k.pub, msg, sig, &mldsa.Options{}); err != nil {
		return fmt.Errorf("the ML-DSA-65 signature does not verify: %w", err)
	}
	return nil
}

func thumbprint(key cbor.Map) []byte {
	b, err := cbor.Encode(key)
	if err != nil {
		// The maps above are fixed shapes of integers and bytes.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

// -- messages -----------------------------------------------------------------

// Sign1 is a COSE_Sign1 message.
type Sign1 struct {
	// Protected is the protected header exactly as signed; Header is it
	// decoded.
	Protected []byte
	Header    cbor.Map
	// Unprotected is the unprotected header, outside the signature.
	Unprotected cbor.Map
	// Payload is nil when the payload is detached.
	Payload   []byte
	Signature []byte
}

// Sign makes a COSE_Sign1 over a payload. The header must not set alg or
// kid; they are the signer's, and are added. A detached message carries no
// payload, and is verified against one supplied separately.
func Sign(s Signer, header cbor.Map, payload []byte, detached bool, external []byte) (*Sign1, error) {
	for _, l := range []int64{LabelAlg, LabelKID} {
		if _, ok := header.Get(cbor.Int(l)); ok {
			return nil, fmt.Errorf("header label %d is the signer's to set", l)
		}
	}
	if payload == nil {
		payload = []byte{}
	}
	h := append(cbor.Map{{Key: cbor.Int(LabelAlg), Value: cbor.Int(s.Algorithm())},
		{Key: cbor.Int(LabelKID), Value: cbor.Bytes(s.KeyID())}}, header...)
	protected, err := cbor.Encode(h)
	if err != nil {
		return nil, err
	}
	tbs, err := toBeSigned(protected, payload, external)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(tbs)
	if err != nil {
		return nil, err
	}
	decoded, err := cbor.Decode(protected)
	if err != nil {
		return nil, err
	}
	m := &Sign1{Protected: protected, Header: decoded.(cbor.Map), Unprotected: cbor.Map{}, Signature: sig}
	if !detached {
		m.Payload = payload
	}
	return m, nil
}

// toBeSigned is the Sig_structure of RFC 9052 §4.4.
func toBeSigned(protected, payload, external []byte) ([]byte, error) {
	if external == nil {
		external = []byte{}
	}
	return cbor.Encode(cbor.Array{cbor.Text("Signature1"), cbor.Bytes(protected),
		cbor.Bytes(external), cbor.Bytes(payload)})
}

// Encode writes the message as a tagged COSE_Sign1.
func (m *Sign1) Encode() ([]byte, error) {
	var payload cbor.Value = cbor.Null{}
	if m.Payload != nil {
		payload = cbor.Bytes(m.Payload)
	}
	un := m.Unprotected
	if un == nil {
		un = cbor.Map{}
	}
	return cbor.Encode(cbor.Tagged{Tag: TagSign1, Value: cbor.Array{cbor.Bytes(m.Protected), un,
		payload, cbor.Bytes(m.Signature)}})
}

// Parse reads a tagged COSE_Sign1, checking its shape and its headers but
// not its signature.
func Parse(b []byte) (*Sign1, error) {
	if len(b) > MaxMessage {
		return nil, fmt.Errorf("a COSE message here is at most %d bytes, and this is %d", MaxMessage, len(b))
	}
	v, err := cbor.Decode(b)
	if err != nil {
		return nil, fmt.Errorf("not CBOR: %w", err)
	}
	t, ok := v.(cbor.Tagged)
	if !ok || t.Tag != TagSign1 {
		return nil, errors.New("not a tagged COSE_Sign1")
	}
	a, ok := t.Value.(cbor.Array)
	if !ok || len(a) != 4 {
		return nil, errors.New("a COSE_Sign1 is an array of four")
	}
	protected, ok1 := a[0].(cbor.Bytes)
	un, ok2 := a[1].(cbor.Map)
	sig, ok3 := a[3].(cbor.Bytes)
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("a COSE_Sign1 is a protected header in bytes, an unprotected map, a payload and a signature in bytes")
	}
	m := &Sign1{Protected: protected, Unprotected: un, Signature: sig, Header: cbor.Map{}}
	switch p := a[2].(type) {
	case cbor.Bytes:
		m.Payload = p
	case cbor.Null:
	default:
		return nil, errors.New("a COSE_Sign1 payload is bytes or nil")
	}
	// RFC 9052 §3: an empty protected header is the empty string, not a map.
	if len(protected) > 0 {
		h, err := cbor.Decode(protected)
		if err != nil {
			return nil, fmt.Errorf("the protected header: %w", err)
		}
		if m.Header, ok = h.(cbor.Map); !ok {
			return nil, errors.New("the protected header is not a map")
		}
	}
	if err := m.checkHeaders(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Sign1) checkHeaders() error {
	seen := map[string]bool{}
	for _, en := range m.Header {
		k, _ := cbor.Encode(en.Key)
		seen[string(k)] = true
	}
	for _, en := range m.Unprotected {
		k, _ := cbor.Encode(en.Key)
		if seen[string(k)] {
			return errors.New("a header label is in both the protected and unprotected headers")
		}
	}
	if _, ok := m.Unprotected.Get(cbor.Int(LabelCrit)); ok {
		return errors.New("crit must be protected")
	}
	if c, ok := m.Header.Get(cbor.Int(LabelCrit)); ok {
		// Nothing this program processes is critical, so any label named
		// critical is one it would otherwise ignore: refused.
		return fmt.Errorf("the message marks %v critical, which is not processed here", c)
	}
	if _, err := m.Algorithm(); err != nil {
		return err
	}
	return nil
}

// Algorithm is the alg in the protected header.
func (m *Sign1) Algorithm() (int64, error) {
	v, ok := m.Header.Get(cbor.Int(LabelAlg))
	if !ok {
		return 0, errors.New("the protected header names no algorithm")
	}
	alg, ok := cbor.AsInt(v)
	if !ok {
		return 0, errors.New("the algorithm is not an integer")
	}
	return alg, nil
}

// KeyID is the kid in the protected header, nil when there is none.
func (m *Sign1) KeyID() []byte {
	if v, ok := m.Header.Get(cbor.Int(LabelKID)); ok {
		if b, ok := v.(cbor.Bytes); ok {
			return b
		}
	}
	return nil
}

// Verify checks the signature with a key. A detached message is checked
// against the payload given; an attached one must be given none.
func (m *Sign1) Verify(v Verifier, detached, external []byte) error {
	alg, err := m.Algorithm()
	if err != nil {
		return err
	}
	if !v.Accepts(alg) {
		return fmt.Errorf("the message is signed with algorithm %d, which this key does not verify", alg)
	}
	if kid := m.KeyID(); kid != nil && !bytes.Equal(kid, v.KeyID()) {
		return fmt.Errorf("the message names key %x, and the key here is %x", kid, v.KeyID())
	}
	payload := m.Payload
	switch {
	case m.Payload == nil && detached == nil:
		return errors.New("the payload is detached and none was given")
	case m.Payload != nil && detached != nil:
		return errors.New("the payload is attached, and a second one was given")
	case m.Payload == nil:
		payload = detached
	}
	tbs, err := toBeSigned(m.Protected, payload, external)
	if err != nil {
		return err
	}
	return v.Verify(tbs, m.Signature)
}
