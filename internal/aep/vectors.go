// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package aep

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/scitt"
)

// Test vectors: the protocol's conformance suite, in a form any
// implementation can read. Each vector is one JSON document that says
// what to check and whether it must pass. A digest vector gives the
// inputs of an action digest and the digest; a statement vector gives a
// statement in hex, the public keys of the parties it may come from, the
// log's keys when its receipts must be checked, the arguments when they
// must be held to the receipt, and for a reconciliation the receipts it
// reconciled. A conforming verifier accepts every vector marked valid and
// refuses every other; Reason says, for a person, what an invalid one
// gets wrong.

// Key is a public key in a vector: its COSE algorithm and its raw bytes
// in hex (32 for Ed25519, 1952 for ML-DSA-65).
type Key struct {
	Alg    int64  `json:"alg"`
	Public string `json:"public"`
}

// Vector is one conformance case.
type Vector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Kind is "digest" or "statement".
	Kind string `json:"kind"`

	// A digest vector: an action's inputs and its digests.
	Target     string `json:"target,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Args       string `json:"args,omitempty"`
	ArgsDigest string `json:"args_digest,omitempty"`
	Digest     string `json:"digest,omitempty"`

	// A statement vector.
	Statement  string         `json:"statement,omitempty"`
	IssuerKeys map[string]Key `json:"issuer_keys,omitempty"`
	LogKeys    []Key          `json:"log_keys,omitempty"`
	Inputs     []string       `json:"inputs,omitempty"`

	// Verdict is what a reconciliation vector's statement concludes, which
	// a verifier recomputes.
	Verdict string `json:"verdict,omitempty"`

	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}

// Verifier makes a COSE verifier from a vector's key.
func (k Key) Verifier() (cose.Verifier, error) {
	raw, err := hex.DecodeString(k.Public)
	if err != nil {
		return nil, fmt.Errorf("a key is not hex: %w", err)
	}
	switch k.Alg {
	case cose.AlgEd25519:
		return cose.NewEd25519Verifier(ed25519.PublicKey(raw))
	case cose.AlgMLDSA65:
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
		if err != nil {
			return nil, err
		}
		return cose.NewMLDSA65Verifier(pub)
	}
	return nil, fmt.Errorf("algorithm %d is not one this profile signs with", k.Alg)
}

// trusted reads a statement and verifies it with its issuer's key.
func trusted(b []byte, keys map[string]Key) (*scitt.Signed, error) {
	s, err := scitt.Read(b)
	if err != nil {
		return nil, err
	}
	k, ok := keys[s.Issuer]
	if !ok {
		return nil, fmt.Errorf("no key is given for %s", s.Issuer)
	}
	v, err := k.Verifier()
	if err != nil {
		return nil, err
	}
	if err := s.Verify(v); err != nil {
		return nil, err
	}
	return s, nil
}

// CheckVector checks one vector the way a verifier must, returning nil
// when everything it states holds. Whether that was expected is Valid's.
func CheckVector(v Vector) error {
	switch v.Kind {
	case "digest":
		args, err := ArgsDigest([]byte(v.Args))
		if err != nil {
			return err
		}
		if hex.EncodeToString(args[:]) != v.ArgsDigest {
			return errors.New("the arguments digest differs")
		}
		d, err := Action{Target: v.Target, Tool: v.Tool, Args: args}.Digest()
		if err != nil {
			return err
		}
		if hex.EncodeToString(d[:]) != v.Digest {
			return errors.New("the action digest differs")
		}
		return nil
	case "statement":
	default:
		return fmt.Errorf("kind %q is not one this reads", v.Kind)
	}
	b, err := hex.DecodeString(v.Statement)
	if err != nil {
		return fmt.Errorf("the statement is not hex: %w", err)
	}
	s, err := trusted(b, v.IssuerKeys)
	if err != nil {
		return err
	}
	if len(v.LogKeys) > 0 {
		var logs []cose.Verifier
		for _, k := range v.LogKeys {
			lv, err := k.Verifier()
			if err != nil {
				return err
			}
			logs = append(logs, lv)
		}
		if _, err := scitt.VerifyReceipts(s, logs...); err != nil {
			return err
		}
	}
	switch s.ContentType {
	case ContentAction:
		_, r, err := ReadReceipt(b)
		if err != nil {
			return err
		}
		if v.Args != "" {
			d, err := ArgsDigest([]byte(v.Args))
			if err != nil {
				return err
			}
			if d != r.Args {
				return errors.New("the receipt is not about these arguments")
			}
		}
		return nil
	case ContentReconciliation:
		var inputs []Input
		for i, h := range v.Inputs {
			ib, err := hex.DecodeString(h)
			if err != nil {
				return fmt.Errorf("input %d is not hex: %w", i, err)
			}
			is, err := trusted(ib, v.IssuerKeys)
			if err != nil {
				return fmt.Errorf("input %d: %w", i, err)
			}
			_, r, err := ReadReceipt(ib)
			if err != nil {
				return fmt.Errorf("input %d: %w", i, err)
			}
			entry, err := is.Entry()
			if err != nil {
				return err
			}
			inputs = append(inputs, Input{Issuer: is.Issuer, Entry: entry, Receipt: r})
		}
		res, err := CheckReconciliation(b, inputs)
		if err != nil {
			return err
		}
		if v.Verdict != "" && res.Verdict != v.Verdict {
			return fmt.Errorf("the reconciliation concludes %s, and the vector says %s", res.Verdict, v.Verdict)
		}
		return nil
	}
	return fmt.Errorf("the statement is %q, which this profile does not define", s.ContentType)
}
