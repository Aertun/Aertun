// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/pack"
)

// A Simple Verification Result beside a proof.
//
// A policy engine that admits an artifact on in-toto attestations — Kyverno,
// sigstore's policy-controller, an in-toto verifier, a CI gate — reads the
// in-toto Simple Verification Result (svr/v0.2): this verifier checked these
// artifacts, at this time, under this policy, and these properties passed.
// It cannot read an Aertun proof's predicate, and does not need to. So a
// proven proof can be summed up as one, about the same artifacts, signed
// with the same kind of key: whoever gates on it asks for one property —
// AERTUN_DETECTION_PROVEN, AERTUN_NOT_AFFECTED_PROVEN — and the proof itself
// stays where it is for whoever wants the evidence.
//
// Only a proven proof has one. A result lists the properties that passed,
// and a refuted or inconclusive proof passed nothing; an SVR with no
// properties would read, to a policy that only asks whether an attestation
// exists, as one that passed.

// PredicateSVR is the in-toto Simple Verification Result, version 0.2
// (github.com/in-toto/attestation, spec/predicates/svr.md).
const PredicateSVR = "https://in-toto.io/attestation/svr/v0.2"

// SVRContext is the domain an SVR's ML-DSA signature is made in: not a
// proof's, so neither can be taken for the other. The Ed25519 signature is
// DSSE's own, over its pre-authentication encoding, which any DSSE verifier
// holding the public key checks.
const SVRContext = "aertun/svr/v1"

// SVRStatement is an in-toto Statement whose predicate is a Simple
// Verification Result.
type SVRStatement struct {
	Type          string       `json:"_type"`
	Subject       []Subject    `json:"subject"`
	PredicateType string       `json:"predicateType"`
	Predicate     SVRPredicate `json:"predicate"`
}

// SVRPredicate is the result: who verified, under what, when, and what
// passed.
type SVRPredicate struct {
	Verifier    SVRVerifier `json:"verifier"`
	TimeCreated string      `json:"timeCreated"`
	Properties  []string    `json:"properties"`
}

// SVRVerifier names the verifier and the policies it verified under.
type SVRVerifier struct {
	ID       string               `json:"id"`
	Policies []ResourceDescriptor `json:"policies"`
}

// ResourceDescriptor is in-toto's reference to a resource, with the fields
// an SVR here uses.
type ResourceDescriptor struct {
	Name        string            `json:"name,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Digest      Digest            `json:"digest,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

var predicateKind = regexp.MustCompile(`^https://aertun\.github\.io/proof/([a-z][a-z-]*)/v([0-9]+)$`)

// SVRProperty is the property an SVR says passed for a proof of a kind:
// AERTUN_, the kind in capitals, and _PROVEN.
func SVRProperty(predicateType string) (string, error) {
	m := predicateKind.FindStringSubmatch(predicateType)
	if m == nil {
		return "", fmt.Errorf("%q is not an Aertun proof's predicate", predicateType)
	}
	return "AERTUN_" + strings.ToUpper(strings.ReplaceAll(m[1], "-", "_")) + "_PROVEN", nil
}

// SVRFor sums a proven proof up as a Simple Verification Result about the
// same artifacts. digest is the proof's statement digest, as the store names
// it, and keyID the fingerprint of the key that signed it: both are on the
// policy it names, so whoever reads the result can find the proof and whose
// it is.
func SVRFor(st *Statement, digest, keyID string) (*SVRStatement, error) {
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("the proof does not hold together: %w", err)
	}
	if st.Predicate.Verdict != Proven {
		return nil, fmt.Errorf("the proof is %s, and a verification result lists what passed: "+
			"only a proven proof has one", st.Predicate.Verdict)
	}
	property, err := SVRProperty(st.PredicateType)
	if err != nil {
		return nil, err
	}
	if !hex64.MatchString(digest) {
		return nil, fmt.Errorf("a proof is named by the sha256 of its statement")
	}
	verified, err := time.Parse(time.RFC3339, st.Predicate.VerifiedAt)
	if err != nil {
		return nil, fmt.Errorf("the proof says no time it was verified at")
	}
	return &SVRStatement{
		Type: StatementType, Subject: append([]Subject(nil), st.Subject...),
		PredicateType: PredicateSVR,
		Predicate: SVRPredicate{
			Verifier: SVRVerifier{
				ID: st.PredicateType + "#verifier-" + st.Predicate.Verifier.Version,
				Policies: []ResourceDescriptor{{
					Name: "aertun-" + strings.TrimSuffix(strings.TrimPrefix(property, "AERTUN_"), "_PROVEN"),
					URI:  st.PredicateType,
					Annotations: map[string]string{
						"aertun.verifier":     st.Predicate.Verifier.ID,
						"aertun.program":      st.Predicate.Verifier.Program,
						"aertun.proof.sha256": digest,
						"aertun.proof.key":    keyID,
					},
				}},
			},
			TimeCreated: verified.UTC().Format(time.RFC3339),
			Properties:  []string{property},
		},
	}, nil
}

// SealSVR signs a verification result in a DSSE envelope.
func SealSVR(s *SVRStatement, k *pack.Key) (*Envelope, error) {
	if s.PredicateType != PredicateSVR || len(s.Subject) == 0 || len(s.Predicate.Properties) == 0 {
		return nil, fmt.Errorf("refusing to sign: a verification result names what it is about and what passed")
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	edSig, mlSig, err := k.DualSign(pae(PayloadType, payload), SVRContext)
	if err != nil {
		return nil, err
	}
	id, err := KeyID(k.PublicKey())
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{
			{KeyID: id + suffixEd, Sig: base64.StdEncoding.EncodeToString(edSig)},
			{KeyID: id + suffixML, Sig: base64.StdEncoding.EncodeToString(mlSig)},
		},
	}, nil
}

// OpenSVR checks both signatures and returns the result.
func OpenSVR(env *Envelope, pub pack.KeyPublic) (*SVRStatement, error) {
	if env.PayloadType != PayloadType {
		return nil, fmt.Errorf("the envelope carries %q, and a result is %s", env.PayloadType, PayloadType)
	}
	id, err := KeyID(pub)
	if err != nil {
		return nil, err
	}
	var edB64, mlB64 string
	for _, s := range env.Signatures {
		switch s.KeyID {
		case id + suffixEd:
			edB64 = s.Sig
		case id + suffixML:
			mlB64 = s.Sig
		}
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("the payload is not base64: %w", err)
	}
	if err := pack.DualVerifyBase64(pae(env.PayloadType, payload), SVRContext, edB64, mlB64, pub); err != nil {
		return nil, err
	}
	var s SVRStatement
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("the signed result is not one this version reads: %w", err)
	}
	if s.PredicateType != PredicateSVR {
		return nil, fmt.Errorf("the signed statement is a %s, not a verification result", s.PredicateType)
	}
	return &s, nil
}
