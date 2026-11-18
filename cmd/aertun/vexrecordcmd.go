// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// `aertun vuln vex-record --source NAME --since DATE --tolerance R`: one VEX
// issuer's track record, from the not-affected proofs this store keeps about
// it (`aertun vuln prove-vex`), signed as a VEX record (internal/proof). Each
// kept proof is checked again as it is read; one that no longer verifies is
// counted and never used. The record reads proofs and nothing else, so what
// it can say is what those proofs said, and no document an issuer wrote is
// read again here.

func vulnVEXRecord(root string, args []string) error {
	fs := flag.NewFlagSet("vuln vex-record", flag.ContinueOnError)
	source := fs.String("source", "", "the issuer, by the short name its not-affected proofs were made under")
	sinceAt := fs.String("since", "", "the period's start: a date or an RFC 3339 time")
	untilAt := fs.String("until", "", "the period's end, not included (default: now)")
	tolerance := fs.Float64("tolerance", 0, "the share of checked statements the issuer may have "+
		"had contradicted, between 0 and 1, declared before the record is made (required)")
	includeUntrusted := fs.Bool("include-untrusted", false, "also count kept proofs signed by "+
		"keys this store does not trust, and say so in the record; without it they are counted and left out")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *sinceAt == "" || *keyAt == "" {
		return fmt.Errorf("vuln vex-record takes --source NAME --since DATE --tolerance R --key FILE: " +
			"an unsigned track record is a claim about a claim")
	}
	if !proof.ValidVerdictSource(*source) {
		return fmt.Errorf("%q is not the short name a not-affected proof is made under: lower-case "+
			"letters, digits and dashes, as given to vuln prove-vex --source", *source)
	}
	if !(*tolerance > 0 && *tolerance < 1) {
		return fmt.Errorf("--tolerance is the share of checked statements the issuer is held to, " +
			"between 0 and 1 and more than none, and it has no default: it is the claim, so it is " +
			"chosen before the numbers are seen")
	}
	now := time.Now().UTC()
	since, err := parseDay(*sinceAt)
	if err != nil {
		return err
	}
	// A proof says when it was made to the second, so the period is whole
	// seconds too, and what the record says it covers is exactly what it
	// read. By default it runs to the end of this second, so a proof made a
	// moment ago is in it.
	until := now.Truncate(time.Second).Add(time.Second)
	if *untilAt != "" {
		t, err := parseDay(*untilAt)
		if err != nil {
			return err
		}
		if t.After(now) {
			return fmt.Errorf("--until is in the future, and a record is of proofs already made")
		}
		until = t.Truncate(time.Second)
	}
	since = since.Truncate(time.Second)
	if !since.Before(until) {
		return fmt.Errorf("the period starts before it ends: --since is earlier than --until")
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed track
	// record of an issuer, in this organisation's name, is one somebody may
	// decide to stop or go on trusting a vendor on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	// The trust list as it was read, named among the materials, since which
	// proofs count as signed by a trusted key turns on it.
	var materials []proof.Material
	signers, err := proof.ReadBounded(proofstore.SignersPath(root), 1<<20)
	switch {
	case err == nil:
		materials = append(materials, proof.Material{Name: "proof-signers", Digest: proof.SHA256(signers)})
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	// Every kept proof, each verified again as it is read.
	kept, err := proofstore.List(root)
	if err != nil {
		return err
	}
	in := proof.VEXRecordInput{Source: *source, Since: since, Until: until, Tolerance: *tolerance,
		IncludeUntrusted: *includeUntrusted, Materials: materials, Program: version, Now: now}
	for _, e := range kept {
		if e.Broken != "" || e.Statement == nil {
			// Whom a proof that no longer verifies was about cannot be
			// believed, so every one is counted, and none is used.
			in.LeftOut = append(in.LeftOut, e.ID)
			continue
		}
		na := e.Statement.Predicate.NotAffected
		if na == nil || na.Source != *source {
			continue
		}
		made, err := time.Parse(time.RFC3339, e.Statement.Predicate.VerifiedAt)
		if err != nil || made.Before(since) || !made.Before(until) {
			continue
		}
		in.Proofs = append(in.Proofs, proof.VEXRecordProof{ID: e.ID, Digest: e.Digest,
			Document: e.Statement.Subject[0].Digest["sha256"], Asset: na.Asset, Made: made,
			Trusted: e.Signer != "", Statements: na.Statements, NotAffected: na.NotAffected,
			Supported: na.Supported, Contradicted: na.Contradicted, Uncheckable: na.Uncheckable})
	}
	if len(in.Proofs) == 0 {
		return fmt.Errorf("no not-affected proof about %s made between %s and %s is kept here: "+
			"aertun vuln prove-vex makes them, and aertun proof list --kind not-affected lists "+
			"those kept", *source, since.Format(time.RFC3339), until.Format(time.RFC3339))
	}
	trusted := 0
	for _, p := range in.Proofs {
		if p.Trusted {
			trusted++
		}
	}
	if trusted == 0 && !in.IncludeUntrusted {
		return fmt.Errorf("%d not-affected proof(s) about %s are kept, and a key this store trusts "+
			"signed none of them, so a record would rest on proofs anybody could have signed. "+
			"aertun proof trust NAME --key PUBLIC-KEY --why \"…\" trusts the key that signed them "+
			"(it takes two administrators), or --include-untrusted counts them and says so",
			len(in.Proofs), *source)
	}
	st, err := proof.ProveVEXRecord(in)
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
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
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.VEXRecord
	if err := recordE(root, caller.auditRecord("vuln.vex-record-proved", "/vuln", audit.Success,
		map[string]string{"source": ev.Source, "verdict": string(st.Predicate.Verdict),
			"tolerance": fmt.Sprint(ev.Tolerance), "used": fmt.Sprint(ev.Used),
			"left_out": fmt.Sprint(ev.LeftOut), "checked": fmt.Sprint(ev.Share.N),
			"contradicted": fmt.Sprint(ev.Contradicted), "since": ev.Since, "until": ev.Until})); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}
