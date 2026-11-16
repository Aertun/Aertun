// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// A VEX record: one issuer's not_affected statements scored over time, from
// the not-affected proofs this store keeps about it (notaffected.go).
//
// # Why
//
// A not-affected proof says whether one document about one asset held. An
// issuer — a vendor, a scanner, an AI triage tool — writes many, and what
// somebody deciding whether to go on taking its word needs is how often its
// statements turn out to be wrong. Nobody keeps that score, and this program
// already holds the checks it is made of.
//
// # The claim
//
// Of the not_affected statements in the issuer's documents that this program
// held to the evidence in a period, and that the evidence could test, a share
// of at most the tolerance was contradicted. The operator declares the
// tolerance before the record is made, and the verdict reads the exact
// one-sided bounds against it, as a verdicts proof does:
//
//   - refuted when the lower bound is over the tolerance, naming every kept
//     proof that found a statement contradicted by its id in the store;
//   - proven when the upper bound is at or under it, on at least MinSample
//     checked statements;
//   - inconclusive between.
//
// A checked statement is one statement about one package that a not-affected
// proof found supported or contradicted. One it found uncheckable is counted
// beside the rate and never in it: a statement nothing could test is neither
// right nor wrong, and putting it on either side would let an issuer's record
// turn on what this program happens not to know.
//
// # What it reads
//
// Every kept proof, each checked again as it is read (internal/proofstore).
// A not-affected proof about the issuer made in the period, by the time its
// own verifier says it ran, is used. One that no longer verifies is counted
// and left out, never used; and since what a proof that does not verify says
// it is about cannot be believed, every such proof in the store is counted,
// whoever it was about. Whether a key this store trusts signed each proof
// used is counted as well: a signature says which key signed, never whose,
// and the reader of a record decides how far an untrusted signer's proofs go.
//
// The same document about the same asset proved more than once is counted
// once, from the latest proof of it, which held it to the most evidence.
// Counting every proof of it would count the same statements again, and
// narrow the bounds on nothing new.
//
// # What it does not cover
//
// Reversals: a statement supported in one proof and contradicted in a later
// one. A not-affected proof names the statements it found contradicted and
// only counts the rest, so which statements it supported cannot be told, and
// finding a reversal would mean inventing which statement was which. For the
// same reason a statement an issuer repeats in a later document is counted
// again in each.

// VEXRecordVerifier and its version name this verifier.
const (
	VEXRecordVerifier        = "aertun/vex-record"
	VEXRecordVerifierVersion = "1"
)

// PredicateVEXRecord is the predicate of a VEX record.
const PredicateVEXRecord = "https://aertun.github.io/proof/vex-record/v1"

// MaxVEXRecordProofs bounds the kept proofs one record reads: the most a
// store keeps (internal/proofstore's MaxKept).
const MaxVEXRecordProofs = 2000

// maxVEXProofCount bounds each count one not-affected proof carries into a
// record. No document this program reads comes near it (internal/vexcheck
// reads at most 16 MiB and 50,000 statements), so a proof over it was not
// made from one, and the bound keeps the sums over every proof a store holds
// within an int.
const maxVEXProofCount = 1 << 20

// maxVEXRecordCount bounds each count a record carries: every proof a store
// holds, each at its own bound.
const maxVEXRecordCount = MaxVEXRecordProofs * maxVEXProofCount

var (
	keptIDShape   = regexp.MustCompile(`^[0-9a-f]{24}$`)
	recordFailure = regexp.MustCompile(`^kept proof ([0-9a-f]{24}) found ([1-9][0-9]{0,12}) of ([1-9][0-9]{0,12}) checked statement\(s\) contradicted$`)
)

// VEXRecordEvidence is what a VEX record rests on: the proofs it read, the
// statements they came to, and the contradicted share with its bounds.
type VEXRecordEvidence struct {
	// Source is the operator's short name for the issuer, as the
	// not-affected proofs read name it.
	Source string `json:"source"`
	// Since is the start of the period the proofs were made in, by the time
	// each says its verifier ran, RFC 3339 in UTC.
	Since string `json:"since"`
	// Until is the end of the period, not included.
	Until string `json:"until"`
	// Tolerance is the contradicted share the issuer is held to, declared
	// before the record was made.
	Tolerance float64 `json:"tolerance"`
	// Read is every kept proof the record read: the not-affected proofs
	// about the issuer made in the period, and every kept proof that no
	// longer verifies. It is LeftOut, Superseded and Used together.
	Read int `json:"read"`
	// LeftOut is the kept proofs that no longer verify, counted and never
	// used. Every one in the store is counted, because what a proof that
	// does not verify says it is about cannot be believed.
	LeftOut int `json:"left_out"`
	// Superseded is the proofs of a document about an asset that a later
	// proof of the same document about the same asset replaced, so no
	// statement is counted twice.
	Superseded int `json:"superseded"`
	// Used is the proofs the counts below are taken from.
	Used int `json:"used"`
	// Trusted is how many of the proofs used were signed by a key this store
	// trusts (internal/proofstore's signers).
	Trusted int `json:"signed_by_trusted"`
	// Untrusted is how many of the proofs used were signed by a key this
	// store does not trust: anybody can make a key that signs a proof.
	Untrusted int `json:"signed_by_untrusted"`
	// Assets is how many assets the proofs used held documents against.
	Assets int `json:"assets"`
	// Statements is every statement the documents made, whatever its status.
	Statements int `json:"statements"`
	// NotAffected is the not_affected statements among them, each of which
	// was tested.
	NotAffected int `json:"not_affected"`
	// Supported is the tested statements the evidence supported, one for
	// each package a statement is about.
	Supported int `json:"supported"`
	// Contradicted is the tested statements the evidence contradicted, one
	// for each package a statement is about.
	Contradicted int `json:"contradicted"`
	// Uncheckable is the tested statements nothing here could decide, one
	// for each package a statement is about: counted, and never in the rate.
	Uncheckable int `json:"uncheckable"`
	// ContradictingProofs is how many of the proofs used found at least one
	// statement contradicted: the proofs a refutation names.
	ContradictingProofs int `json:"contradicting_proofs"`
	// Share is the contradicted statements of the checked ones, supported or
	// contradicted, with its exact one-sided bounds: the rate the verdict
	// reads. Uncheckable statements are never in it.
	Share Bound `json:"contradicted_share"`
	// MinChecked is the fewest checked statements a proven verdict may rest
	// on.
	MinChecked int `json:"min_checked"`
}

// VEXRecordProof is one kept not-affected proof, as a record reads it.
type VEXRecordProof struct {
	// ID is the proof's id in the store, and Digest the sha256 of the
	// statement as signed, which the id is the start of.
	ID, Digest string
	// Document is the sha256 of the VEX document the proof checked, its
	// subject's digest; Asset the asset it was checked against.
	Document, Asset string
	// Made is when the proof's verifier ran, as the proof says.
	Made time.Time
	// Trusted says a key this store trusts signed it.
	Trusted bool
	// The proof's counts, as its evidence carries them.
	Statements, NotAffected, Supported, Contradicted, Uncheckable int
}

// VEXRecordInput is what a VEX record is made from.
type VEXRecordInput struct {
	Source       string
	Since, Until time.Time
	Tolerance    float64
	// Proofs are the not-affected proofs about Source made in the period
	// that verified when they were read, in any order.
	Proofs []VEXRecordProof
	// LeftOut are the ids of the kept proofs that no longer verify.
	LeftOut   []string
	Materials []Material
	Program   string
	Now       time.Time
}

func recordFailureOf(id string, contradicted, checked int) string {
	return "kept proof " + id + " found " + strconv.Itoa(contradicted) + " of " +
		strconv.Itoa(checked) + " checked statement(s) contradicted"
}

// parseRecordFailure reads a failure back into the proof it names and its
// counts, refusing anything not in that one shape.
func parseRecordFailure(s string) (id string, contradicted, checked int, ok bool) {
	m := recordFailure.FindStringSubmatch(s)
	if m == nil {
		return "", 0, 0, false
	}
	k, err1 := strconv.Atoi(m[2])
	n, err2 := strconv.Atoi(m[3])
	if err1 != nil || err2 != nil || k > n {
		return "", 0, 0, false
	}
	return m[1], k, n, true
}

// ProveVEXRecord builds the unsigned statement.
func ProveVEXRecord(in VEXRecordInput) (*Statement, error) {
	if !ValidVerdictSource(in.Source) || !in.Since.Before(in.Until) {
		return nil, fmt.Errorf("a VEX record names an issuer, by the short name its not-affected " +
			"proofs were made under, and a period that starts before it ends")
	}
	// A proof says when it was made to the second, and the period is written
	// to the second, so a period between seconds would read proofs its own
	// words leave out.
	if !in.Since.Equal(in.Since.Truncate(time.Second)) || !in.Until.Equal(in.Until.Truncate(time.Second)) {
		return nil, fmt.Errorf("a VEX record's period starts and ends on a whole second, as a " +
			"proof says when it was made")
	}
	if !validTolerance(in.Tolerance) {
		return nil, fmt.Errorf("the tolerance is a rate between 0 and 1, more than none: "+
			"no sample can show a rate of exactly zero, and %v is not one", in.Tolerance)
	}
	if len(in.Proofs) == 0 {
		return nil, fmt.Errorf("no not-affected proof about %s was made in the period, so there "+
			"is no record to sign", in.Source)
	}
	if len(in.Proofs)+len(in.LeftOut) > MaxVEXRecordProofs {
		return nil, fmt.Errorf("a VEX record reads at most %d kept proofs", MaxVEXRecordProofs)
	}
	proofs := append([]VEXRecordProof{}, in.Proofs...)
	seen := map[string]bool{}
	for _, p := range proofs {
		if !keptIDShape.MatchString(p.ID) || !hex64.MatchString(p.Digest) || p.Digest[:24] != p.ID ||
			!hex64.MatchString(p.Document) || !assetShape.MatchString(p.Asset) || seen[p.ID] {
			return nil, fmt.Errorf("each proof read is named once, by its id in the store and the " +
				"digest of the statement it signed, with the document and the asset it checked")
		}
		seen[p.ID] = true
		if p.Made.Before(in.Since) || !p.Made.Before(in.Until) {
			return nil, fmt.Errorf("proof %s was not made in the period", p.ID)
		}
		for _, n := range []int{p.Statements, p.NotAffected, p.Supported, p.Contradicted, p.Uncheckable} {
			if n >= maxVEXProofCount {
				return nil, fmt.Errorf("proof %s counts more than any document this program reads "+
					"could hold, so it was not made from one", p.ID)
			}
		}
		if p.NotAffected > p.Statements || min(p.Statements, p.NotAffected, p.Supported,
			p.Contradicted, p.Uncheckable) < 0 {
			return nil, fmt.Errorf("proof %s's counts do not hold together", p.ID)
		}
	}
	left := append([]string{}, in.LeftOut...)
	sort.Strings(left)
	for _, id := range left {
		if !keptIDShape.MatchString(id) || seen[id] {
			return nil, fmt.Errorf("each proof left out is named once, by its id in the store")
		}
		seen[id] = true
	}
	// In the order they were made, by the time each says, so the subject's
	// digest is the same however the store happens to list them.
	sort.Slice(proofs, func(i, j int) bool {
		if !proofs[i].Made.Equal(proofs[j].Made) {
			return proofs[i].Made.Before(proofs[j].Made)
		}
		return proofs[i].ID < proofs[j].ID
	})
	latest := map[[2]string]int{}
	for i, p := range proofs {
		latest[[2]string{p.Document, p.Asset}] = i
	}
	ev := &VEXRecordEvidence{Source: in.Source, Since: day(in.Since), Until: day(in.Until),
		Tolerance: in.Tolerance, Read: len(proofs) + len(left), LeftOut: len(left), MinChecked: MinSample}
	assets := map[string]bool{}
	var failures []string
	// The subject is every proof read, in order: each verified one by its id
	// and the digest of what was signed, and each left out by its id alone,
	// since its bytes are not the ones anybody signed.
	var read bytes.Buffer
	for i, p := range proofs {
		read.WriteString(p.ID + " " + p.Digest + "\n")
		if latest[[2]string{p.Document, p.Asset}] != i {
			ev.Superseded++
			continue
		}
		ev.Used++
		if p.Trusted {
			ev.Trusted++
		} else {
			ev.Untrusted++
		}
		assets[p.Asset] = true
		ev.Statements += p.Statements
		ev.NotAffected += p.NotAffected
		ev.Supported += p.Supported
		ev.Contradicted += p.Contradicted
		ev.Uncheckable += p.Uncheckable
		if p.Contradicted > 0 {
			ev.ContradictingProofs++
			failures = append(failures, recordFailureOf(p.ID, p.Contradicted, p.Supported+p.Contradicted))
		}
	}
	for _, id := range left {
		read.WriteString(id + " unverified\n")
	}
	ev.Assets = len(assets)
	ev.Share = ExactBound(ev.Contradicted, ev.Supported+ev.Contradicted)
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	if ev.verdict() != Refuted {
		failures = nil
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: SHA256(read.Bytes())}},
		PredicateType: PredicateVEXRecord,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: VEXRecordVerifier, Version: VEXRecordVerifierVersion,
				Program: in.Program},
			Materials: append([]Material{}, in.Materials...),
			Checks:    ev.checks(failures),
			VEXRecord: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *VEXRecordEvidence) subject() string { return "vex-issuer/" + ev.Source }

func (ev *VEXRecordEvidence) tolerance() string {
	return strconv.FormatFloat(ev.Tolerance, 'g', -1, 64)
}

// canonicalPeriod is a period written as this package writes one: RFC 3339
// in UTC to the second, starting before it ends.
func canonicalPeriod(since, until string) bool {
	a, err1 := time.Parse(time.RFC3339, since)
	b, err2 := time.Parse(time.RFC3339, until)
	return err1 == nil && err2 == nil && day(a) == since && day(b) == until && a.Before(b)
}

// wellFormed refuses evidence whose shapes or numbers do not hold together,
// on either side of signing.
func (ev *VEXRecordEvidence) wellFormed() error {
	if !ValidVerdictSource(ev.Source) || !canonicalPeriod(ev.Since, ev.Until) || !validTolerance(ev.Tolerance) {
		return fmt.Errorf("a VEX record names an issuer, a period in UTC that starts before it " +
			"ends, and a tolerance more than none and less than all")
	}
	for _, n := range []int{ev.Read, ev.LeftOut, ev.Superseded, ev.Used, ev.Trusted, ev.Untrusted,
		ev.Assets, ev.Statements, ev.NotAffected, ev.Supported, ev.Contradicted, ev.Uncheckable,
		ev.ContradictingProofs} {
		if n < 0 || n > maxVEXRecordCount {
			return fmt.Errorf("a VEX record's counts are whole numbers within what a store could hold")
		}
	}
	if ev.Read > MaxVEXRecordProofs || ev.Used < 1 || ev.Read != ev.LeftOut+ev.Superseded+ev.Used ||
		ev.Trusted+ev.Untrusted != ev.Used || ev.Assets < 1 || ev.Assets > ev.Used {
		return fmt.Errorf("the proofs read, left out, superseded and used do not add up, or the " +
			"record rests on none")
	}
	if ev.NotAffected > ev.Statements || ev.ContradictingProofs > ev.Used ||
		ev.ContradictingProofs > ev.Contradicted || (ev.ContradictingProofs == 0) != (ev.Contradicted == 0) {
		return fmt.Errorf("the statements' counts do not add up")
	}
	if ev.Share.K != ev.Contradicted || ev.Share.N != ev.Supported+ev.Contradicted || !ev.Share.valid() {
		return fmt.Errorf("the contradicted share is not the contradicted of the checked, or its " +
			"bounds do not follow from them")
	}
	if ev.MinChecked != MinSample {
		return fmt.Errorf("the evidence's minimum is not this version's")
	}
	return nil
}

func (ev *VEXRecordEvidence) verdict() Verdict {
	b := ev.Share
	switch {
	case b.Lower > ev.Tolerance:
		return Refuted
	case b.N >= MinSample && b.Upper <= ev.Tolerance:
		return Proven
	}
	return Inconclusive
}

func (ev *VEXRecordEvidence) claim() string {
	return fmt.Sprintf("Of the not_affected statements in %s's VEX documents that this program "+
		"held to each asset's bill of materials, advisories and reachability analysis between %s "+
		"and %s, and that the evidence could test, a share of at most %s was contradicted, "+
		"counting a statement once for each package it is about.", ev.Source, ev.Since, ev.Until,
		ev.tolerance())
}

// checks are the record's checks, from the evidence and, when it is refuted,
// the names of the proofs that found a statement contradicted: the last
// lists at most MaxFailures and counts the rest.
func (ev *VEXRecordEvidence) checks(failures []string) []Check {
	read := fmt.Sprintf("%d kept proof(s) read: %d not-affected proof(s) about %s made in the "+
		"period, each verified as it was read, and %d that no longer verify, counted and not "+
		"used, whoever they were about, since what one says it is about cannot be believed",
		ev.Read, ev.Read-ev.LeftOut, ev.Source, ev.LeftOut)
	read += fmt.Sprintf("; %d superseded by a later proof of the same document about the same "+
		"asset, so no statement is counted twice", ev.Superseded)
	read += fmt.Sprintf("; %d used, about %d asset(s): %d signed by a key this store trusts and "+
		"%d by a key it does not", ev.Used, ev.Assets, ev.Trusted, ev.Untrusted)
	statements := fmt.Sprintf("%d statement(s) in the documents, %d of them not_affected and "+
		"tested, came to %d supported, %d contradicted and %d uncheckable, one for each package "+
		"a statement is about; the uncheckable are counted and never in the rate, and a "+
		"statement repeated in a later document is counted again, since a not-affected proof "+
		"does not name the statements it supported", ev.Statements, ev.NotAffected, ev.Supported,
		ev.Contradicted, ev.Uncheckable)
	b := ev.Share
	share := Check{Name: "contradicted-share", Passed: ev.verdict() != Refuted,
		Detail: fmt.Sprintf("%d of %d checked statement(s) were contradicted, found by %d "+
			"proof(s); the share is between %.4f and %.4f (exact, one-sided, 95%% each), against "+
			"a tolerance of %s", b.K, b.N, ev.ContradictingProofs, b.Lower, b.Upper, ev.tolerance())}
	if b.N < MinSample {
		share.Detail += fmt.Sprintf("; fewer than the %d checked statements a proven verdict needs", MinSample)
	}
	shown, more := capped(failures)
	share.Failures = shown
	if more > 0 {
		share.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	return []Check{{Name: "proofs-read", Passed: true, Detail: read},
		{Name: "statements", Passed: true, Detail: statements}, share}
}

// validate refuses evidence whose numbers do not add up, do not support the
// verdict, or do not account for every word the statement says.
func (ev *VEXRecordEvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
		return err
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("%d contradicted of %d checked against a tolerance of %s is %s, not %s",
			ev.Share.K, ev.Share.N, ev.tolerance(), want, s.Predicate.Verdict)
	}
	if len(s.Predicate.Checks) != 3 {
		return fmt.Errorf("a VEX record has three checks")
	}
	var failures []string
	named := map[string]bool{}
	contradicted, checked := 0, 0
	for i, c := range s.Predicate.Checks {
		for _, f := range c.Failures {
			id, k, n, ok := parseRecordFailure(f)
			if i != 2 || !ok || named[id] {
				return fmt.Errorf("a failure in a VEX record names a kept proof by its id, once, with " +
					"how many of its checked statements it found contradicted, and nothing else")
			}
			named[id] = true
			contradicted += k
			checked += n
			failures = append(failures, f)
		}
	}
	listed := 0
	if ev.verdict() == Refuted {
		listed = min(ev.ContradictingProofs, MaxFailures)
	}
	// What the proofs named found can be no more than was counted, and when
	// every contradicting proof is named it is exactly what was counted.
	if len(failures) != listed || contradicted > ev.Contradicted || checked > ev.Share.N ||
		(listed > 0 && listed == ev.ContradictingProofs && contradicted != ev.Contradicted) {
		return fmt.Errorf("the proofs named are not the contradicting proofs a refutation names")
	}
	if listed > 0 {
		failures = append(failures, make([]string, ev.ContradictingProofs-len(failures))...)
	}
	return sameWords(s, ev.subject(), ev.claim(), ev.checks(failures))
}
