// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// `aertun proof svr ID|FILE --key F` sums a proven proof up as an in-toto
// Simple Verification Result (internal/proof/svr.go), for a policy engine
// that admits artifacts on attestations and reads that predicate and no
// other. The proof is a kept one, by its id, or a file with the public key
// it was signed with; either way it is verified before anything is said
// about it, and only a proven one has a result.
func proofSVR(root string, args []string) error {
	fs := flag.NewFlagSet("proof svr", flag.ContinueOnError)
	proofKey := fs.String("proof-key", "", "with a proof FILE: the public key it was signed with")
	keyAt := fs.String("key", "", "the dual signing key file the result is signed with (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a policy engine checks the result with")
	outAt := fs.String("out", "", "where to write the result (default: standard output)")
	var what string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		what, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if what == "" || fs.NArg() != 0 || *keyAt == "" {
		return fmt.Errorf("proof svr takes a kept proof's ID, or a proof FILE with --proof-key, and --key FILE")
	}
	caller := resolveCaller(root, flagToken)
	// Tune, as signing a proof does: a result says, in the organisation's
	// name, that an artifact passed, and a policy engine admits it on that.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	var st *proof.Statement
	var digest, keyID string
	if proofstore.ValidID(what) && *proofKey == "" {
		e, err := proofstore.Get(root, what)
		if err != nil {
			return err
		}
		if e.Statement == nil {
			return fmt.Errorf("proof %s no longer verifies (%s), so nothing is said about it", what, e.Broken)
		}
		st, digest, keyID = e.Statement, e.Digest, e.KeyID
	} else {
		if *proofKey == "" {
			return fmt.Errorf("%s is not a kept proof's id; a proof file is checked with --proof-key, the public key it was signed with", what)
		}
		env, err := proof.ReadEnvelope(what)
		if err != nil {
			return err
		}
		pub, err := pack.LoadPublicKey(*proofKey)
		if err != nil {
			return err
		}
		if st, err = proof.Open(env, pub); err != nil {
			return fmt.Errorf("the proof does not verify against that key: %w", err)
		}
		if keyID, err = proof.KeyID(pub); err != nil {
			return err
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			return err
		}
		digest = proof.SHA256(payload)["sha256"]
	}
	svr, err := proof.SVRFor(st, digest, keyID)
	if err != nil {
		return err
	}
	env, err := proof.SealSVR(svr, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if err := recordE(root, caller.auditRecord("svr.issued", "/proofs", audit.Success,
		map[string]string{"proof": digest[:24], "property": svr.Predicate.Properties[0]})); err != nil {
		return err
	}
	if *outAt == "" {
		_, err := os.Stdout.Write(doc)
		return err
	}
	if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
		return err
	}
	w.Human("%s for %s, about %d artifact(s), signed\n", svr.Predicate.Properties[0], digest[:24], len(svr.Subject))
	return nil
}
