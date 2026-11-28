// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/spool"
)

// `aertun proof coverage` holds each technique the rules claim to the corpus
// entries labelled with it and those labelled benign (internal/proof/
// coverage.go), and signs what came of it. With --telemetry it also reads
// what each source sent lately from the store, and says which techniques'
// instances, and which rules, would no longer be caught with only those
// fields. With --navigator it draws the result as an ATT&CK Navigator layer.

// coveragePerSourceCap is how many events of one source decay is judged on:
// enough to see every field a busy source sends, and a bound on the read. A
// variable so a test can reach it without writing a hundred thousand events.
var coveragePerSourceCap = 100_000

// The longest and shortest telemetry windows decay is judged against.
const (
	minCoverageWindow = time.Hour
	maxCoverageWindow = 90 * 24 * time.Hour
)

func proofCoverage(root string, args []string) error {
	fs := flag.NewFlagSet("proof coverage", flag.ContinueOnError)
	dir := fs.String("rules", "", "where the rules live (default: the store's detections, or ./detections)")
	corpusAt := fs.String("corpus", "", "the labelled corpus (default: corpus.jsonl beside the rules)")
	var techniques multiFlag
	fs.Var(&techniques, "technique", "a technique to prove, repeatable (default: every one the rules claim)")
	minPositives := fs.Int("min-positives", 1, "how many labelled instances a technique needs to be proven")
	minBenign := fs.Int("min-benign", 1, "how many benign entries from its rules' sources a technique needs to be proven")
	recent := fs.String("telemetry", "", "judge decay against the fields each source sent this long back, read from the store (e.g. 7d)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	navAt := fs.String("navigator", "", "where to write an ATT&CK Navigator layer of the result")
	by := fs.String("by", "", "who submitted the rules: a person or an agent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("proof coverage takes flags only; %q is not one", fs.Arg(0))
	}
	if *keyAt == "" {
		return fmt.Errorf("proof coverage needs --key FILE: an unsigned verdict is a claim about a claim")
	}
	var window time.Duration
	caller := resolveCaller(root, flagToken)
	if *recent != "" {
		d, err := parseCoverageWindow(*recent)
		if err != nil {
			return err
		}
		window = d
		// Reading the store and signing what it showed in the
		// organisation's name: tune, as the other proofs signed from the
		// store ask for, before anything is read.
		if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
			return err
		}
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	files, err := ruleFilesIn(rulesDir(root, *dir))
	if err != nil {
		return err
	}
	in := proof.CoverageInput{Techniques: techniques, MinPositives: *minPositives, MinBenign: *minBenign,
		Author: proof.Author{By: *by}, Program: version, Now: time.Now()}
	for _, f := range files {
		in.Rules = append(in.Rules, proof.CoverageRule{Rule: f.Rule, File: f.Body})
	}
	path := corpusPath(root, *dir, *corpusAt)
	corpus, err := proof.ReadBounded(path, MaxProofCorpus)
	if err != nil {
		return err
	}
	entries, err := detect.ParseCorpus(bytes.NewReader(corpus))
	if err != nil {
		return fmt.Errorf("%s %w", path, err)
	}
	in.CorpusName, in.Corpus, in.Entries = filepath.Base(path), corpus, entries
	if window > 0 {
		if in.Telemetry, err = recentFields(root, in.Now.Add(-window), in.Now); err != nil {
			return err
		}
	}
	st, err := proof.ProveCoverage(in)
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
	if window > 0 {
		// Signed from the store, so kept in it and written to its log, as
		// the other proofs signed from the store are.
		if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
			keepMade(root, env, pubDoc, caller.Name)
		}
		if err := recordE(root, caller.auditRecord("coverage.proved", "/proofs", audit.Success,
			map[string]string{"verdict": string(st.Predicate.Verdict),
				"techniques": fmt.Sprint(len(st.Predicate.Coverage.Techniques)),
				"dark":       fmt.Sprint(st.Predicate.Coverage.DarkCount)})); err != nil {
			return err
		}
	}
	if *navAt != "" {
		digest, err := envelopeDigest(env)
		if err != nil {
			return err
		}
		layer, left, err := proof.CoverageLayer(st, digest)
		if err != nil {
			return err
		}
		if err := atomicfile.Write(*navAt, layer, 0o600); err != nil {
			return err
		}
		if left > 0 {
			w.Human("the layer leaves out %d technique(s) that are not ATT&CK Enterprise ids\n", left)
		}
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		// 0o600 like every operator-named document: the corpus it names is
		// named after what happened to somebody.
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n", describe(st))
		}
	}
	return notProven(st)
}

// envelopeDigest is a proof's statement digest, as the store names it: the
// sha256 of the signed payload.
func envelopeDigest(env *proof.Envelope) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", fmt.Errorf("the envelope's payload is not base64")
	}
	return proof.SHA256(payload)["sha256"], nil
}

// parseSpan reads a length of time given to the flag named: a whole number
// of days (30d), or anything time.ParseDuration reads. Bounds are the
// caller's.
func parseSpan(flagName, example, s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("%s %s is not a number of days", flagName, s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s is a length of time, like %s", flagName, example)
	}
	return d, nil
}

// parseCoverageWindow reads the telemetry window: whole days as 7d, or a Go
// duration.
func parseCoverageWindow(s string) (time.Duration, error) {
	d, err := parseSpan("--telemetry", "7d or 72h", s)
	if err != nil {
		return 0, err
	}
	if d < minCoverageWindow || d > maxCoverageWindow || d%time.Second != 0 {
		return 0, fmt.Errorf("--telemetry is between 1h and 90d")
	}
	return d, nil
}

// recentFields reads the field names each source sent between two times,
// from the store, up to coveragePerSourceCap events a source.
func recentFields(root string, since, until time.Time) (*proof.CoverageFields, error) {
	// Not created when absent: a store nobody has collected into is not one
	// whose sources all went quiet, and saying so would be a false decay.
	if _, err := os.Stat(spoolDir(root)); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("--telemetry reads the event store, and nothing has been collected into it")
		}
		return nil, err
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return nil, err
	}
	defer sp.Close()
	out := &proof.CoverageFields{Since: since.UTC().Truncate(time.Second), Until: until.UTC().Truncate(time.Second),
		Fields: map[string]map[string]bool{}, PerSourceCap: coveragePerSourceCap}
	read := map[string]int{}
	capped := map[string]bool{}
	err = sp.Scan(out.Since, out.Until, func(r *spool.Row) error {
		src := strings.ToLower(strings.TrimSpace(r.Source()))
		if read[src] >= coveragePerSourceCap {
			capped[src] = true
			return nil
		}
		e, err := r.Event()
		if err != nil {
			return err
		}
		read[src]++
		out.Events++
		names := out.Fields[src]
		if names == nil {
			names = map[string]bool{}
			out.Fields[src] = names
		}
		for f := range e.Fields() {
			names[f] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Capped = len(capped)
	return out, nil
}

// describeCoverage is each technique's verdict, one to a line, with the
// counts behind it.
func describeCoverage(v *proof.CoverageEvidence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  evidence: %d rule(s), %d corpus entr(ies), %d labelled as techniques, %d benign\n",
		len(v.Rules), v.Entries, v.Labelled, v.Benign)
	for _, t := range v.Techniques {
		fmt.Fprintf(&b, "    %-12s %-12s %d of %d caught, %d only quietly, %d missed; %d of %d benign fired on; %d rule(s)",
			t.Technique, t.Verdict, t.Caught, t.Positives, t.QuietOnly, t.Missed, t.FalseFires, t.Benign, len(t.Rules))
		if v.Telemetry != nil && t.Decayed > 0 {
			fmt.Fprintf(&b, "; %d would no longer be caught", t.Decayed)
		}
		b.WriteByte('\n')
	}
	for _, u := range v.Unclaimed {
		fmt.Fprintf(&b, "    %-12s %-12s %d labelled instance(s), %d caught by a rule claiming something else\n",
			u.Technique, "unclaimed", u.Positives, u.CaughtByOther)
	}
	for _, d := range v.Dark {
		if d.Silent {
			fmt.Fprintf(&b, "    dark: %s, none of the sources it reads sent anything\n", d.Rule)
		} else {
			fmt.Fprintf(&b, "    dark: %s, its sources no longer send %s\n", d.Rule, strings.Join(d.Missing, ", "))
		}
	}
	return b.String()
}
