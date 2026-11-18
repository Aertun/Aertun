// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/vuln"
)

// A continuity proof: no package in a bill lost, from the release before
// it, what that release had.
//
// # Why
//
// The packages that have done the most damage lately were not new ones. A
// maintainer's account was taken over, and the next release of a package
// millions already trusted came out of it: axios 1.14.1, in March 2026,
// published with a long-lived token where every release before it had come
// from the project's own workflow through trusted publishing with signed
// provenance, and carrying a new dependency whose install script fetched the
// payload. Nothing in the release itself was unusual for a package; what
// was unusual was the difference from the one before. A bill of materials
// names the release, and the registry still says how the release before it
// was made. So each package is held to its predecessor.
//
// # The claim
//
// None of the npm, PyPI and Go packages in the bill lost, from the release
// before it, its provenance, its trusted publishing, the repository,
// workflow or tagged source it was built from, its publishing account's
// identity, or its having no install scripts; and its registry has neither
// withdrawn nor yanked it, nor served provenance about another artifact as
// its own.
//
//   - refuted when one did, naming the package and what it lost;
//   - proven when every package was read and none did;
//   - inconclusive when a package could not be read: its registry did not
//     answer, does not know it, or its version does not order.
//
// A package's first release has nothing before it and holds. Components of
// other ecosystems, or naming no version, are counted and not in the claim.
//
// # What it cannot say
//
// That a release is safe: only that it was made the way the one before it
// was. The registry's word is taken for who published a release and
// whether its attestation was signed; npm and PyPI check the signatures
// when it is published, and this proof checks that the attestation is about
// the artifact by its digest. A release whose predecessor was made the same
// bad way holds. A publisher's name or email, a repository and a workflow
// are carried as sha256 digests, never as text: they are whoever published
// the package's choice, and a proof repeats nobody's words.

// ContinuityVerifier and its version name this verifier.
const (
	ContinuityVerifier        = "aertun/continuity"
	ContinuityVerifierVersion = "1"
)

// PredicateContinuity is the predicate of a continuity proof.
const PredicateContinuity = "https://aertun.github.io/proof/continuity/v1"

// SubjectContinuity names what a continuity proof is about: the bill.
const SubjectContinuity = "bill"

// MaxContinuityPackages bounds the packages one proof reads.
const MaxContinuityPackages = 5000

// The outcomes a package has.
const (
	ContinuityHeld      = "held"
	ContinuityRegressed = "regressed"
	ContinuityFirst     = "first"
	ContinuityUnread    = "unread"
)

// Why a package could not be read.
const (
	UnreadRegistry     = "registry"      // its registry did not answer as one does
	UnreadNoPackage    = "no-package"    // its registry has no package by that name
	UnreadAbsent       = "absent"        // the Go proxy does not list the version
	UnreadVersionOrder = "version-order" // its version does not order, so nothing is before it
	UnreadProvenance   = "provenance"    // its provenance, or its predecessor's, did not read
)

// What a release can lose. Standing is about the release alone; the rest
// are against the release before it.
const (
	LostWithdrawn       = "withdrawn"
	LostYanked          = "yanked"
	LostMismatch        = "provenance-mismatch"
	LostProvenance      = "provenance-lost"
	LostTrusted         = "trusted-publishing-lost"
	LostRepository      = "repository-changed"
	LostWorkflow        = "workflow-changed"
	LostTag             = "untagged"
	LostOrigin          = "origin-lost"
	LostAccount         = "account-email-changed"
	LostScriptsAdded    = "install-script-added"
	LostScriptsChanged  = "install-script-changed"
	refTag, refBranch   = "tag", "branch"
	refOther            = "other"
	continuityEcosystem = `(npm|pypi|golang)`
)

var (
	standingLosses = map[string]bool{LostWithdrawn: true, LostYanked: true, LostMismatch: true}
	purlShape      = regexp.MustCompile(`^pkg:` + continuityEcosystem + `/[A-Za-z0-9._~%/!+-]{1,300}@[A-Za-z0-9._+~-]{1,128}$`)
	versionShape   = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,128}$`)
	commitShape    = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	unreadWords    = map[string]bool{UnreadRegistry: true, UnreadNoPackage: true, UnreadAbsent: true,
		UnreadVersionOrder: true, UnreadProvenance: true}
)

// ContinuityRelease is one release as its registry described it, with
// everything somebody else chose carried as a digest.
type ContinuityRelease struct {
	Version string `json:"version"`
	// Published is when the registry says it was published, RFC 3339.
	Published string `json:"published,omitempty"`
	// Listed is whether the registry serves it; Yanked, whether its
	// publisher asked that nobody install it.
	Listed bool `json:"listed"`
	Yanked bool `json:"yanked,omitempty"`
	// Provenance is whether an attestation about this artifact, by its
	// digest, was found; Mismatch, whether one about another was.
	Provenance bool `json:"provenance"`
	Mismatch   bool `json:"provenance_mismatch,omitempty"`
	// Attestation is the sha256 of the provenance statement read.
	Attestation string `json:"attestation,omitempty"`
	// Trusted is whether it was published through trusted publishing.
	Trusted bool `json:"trusted_publishing,omitempty"`
	// Publisher, Account, Repository and Workflow are sha256 digests of
	// who published it, the account (npm), and the repository and workflow
	// it was built from.
	Publisher  string `json:"publisher,omitempty"`
	Account    string `json:"account,omitempty"`
	Repository string `json:"repository,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	// Ref is the kind of ref it was built from — tag, branch or other —
	// and Commit the commit, when its provenance or origin says.
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
	// Scripts is the sha256 of what it runs on install; empty when nothing.
	Scripts string `json:"install_scripts,omitempty"`
}

// ContinuityPackage is one package of the bill and how it fared.
type ContinuityPackage struct {
	Purl    string `json:"purl"`
	Outcome string `json:"outcome"`
	// Unread says why a package could not be read.
	Unread string `json:"unread,omitempty"`
	// Now is the release the bill names, and Before the one before it.
	Now    *ContinuityRelease `json:"now,omitempty"`
	Before *ContinuityRelease `json:"before,omitempty"`
	// Lost is what it lost, in order.
	Lost []string `json:"lost,omitempty"`
}

// ContinuityEvidence is what a continuity proof rests on.
type ContinuityEvidence struct {
	// Packages are the bill's npm, PyPI and Go packages, once each, in
	// order of their package URL.
	Packages []ContinuityPackage `json:"packages"`
	// Outside counts the components of other ecosystems, or naming no
	// version: not in the claim.
	Outside int `json:"outside"`
	// PublicRegistries is whether every registry read was the public one.
	PublicRegistries bool `json:"public_registries"`
	Held             int  `json:"held"`
	Regressed        int  `json:"regressed"`
	First            int  `json:"first"`
	Unread           int  `json:"unread"`
}

// ContinuityInput is what a continuity proof is made from.
type ContinuityInput struct {
	Bill     []byte
	Evidence ContinuityEvidence
	Author   Author
	Program  string
	Now      time.Time
}

func ecosystemOf(purl string) string {
	rest := strings.TrimPrefix(purl, "pkg:")
	eco, _, _ := strings.Cut(rest, "/")
	return eco
}

// ContinuityLosses is what a release lost, from its predecessor where it
// has one, in order: the one rule, used to make a proof and to check one.
func ContinuityLosses(ecosystem string, now, before *ContinuityRelease) []string {
	var lost []string
	if now == nil {
		return nil
	}
	if !now.Listed {
		lost = append(lost, LostWithdrawn)
	}
	if now.Yanked {
		lost = append(lost, LostYanked)
	}
	if now.Mismatch {
		lost = append(lost, LostMismatch)
	}
	if before != nil && now.Listed {
		if before.Provenance && !now.Provenance && !now.Mismatch {
			lost = append(lost, LostProvenance)
		}
		if before.Trusted && !now.Trusted {
			lost = append(lost, LostTrusted)
		}
		if before.Repository != "" && now.Repository != "" && before.Repository != now.Repository {
			lost = append(lost, LostRepository)
		}
		if before.Workflow != "" && now.Workflow != "" && before.Workflow != now.Workflow &&
			before.Repository == now.Repository {
			lost = append(lost, LostWorkflow)
		}
		if before.Ref == refTag && now.Ref != "" && now.Ref != refTag {
			lost = append(lost, LostTag)
		}
		if ecosystem == "golang" && before.Repository != "" && now.Repository == "" {
			lost = append(lost, LostOrigin)
		}
		if !before.Trusted && !now.Trusted && before.Account != "" && before.Account == now.Account &&
			before.Publisher != now.Publisher {
			lost = append(lost, LostAccount)
		}
		if before.Scripts == "" && now.Scripts != "" {
			lost = append(lost, LostScriptsAdded)
		}
		if before.Scripts != "" && now.Scripts != "" && before.Scripts != now.Scripts {
			lost = append(lost, LostScriptsChanged)
		}
	}
	sort.Strings(lost)
	return lost
}

// ContinuityOutcome is a package's outcome from what it lost and whether it
// was read.
func ContinuityOutcome(p ContinuityPackage) string {
	switch {
	case len(p.Lost) > 0:
		return ContinuityRegressed
	case p.Unread != "":
		return ContinuityUnread
	case p.Before == nil:
		return ContinuityFirst
	}
	return ContinuityHeld
}

// ProveContinuity builds the unsigned statement.
func ProveContinuity(in ContinuityInput) (*Statement, error) {
	if len(in.Bill) == 0 {
		return nil, fmt.Errorf("a continuity proof is about a bill of materials")
	}
	ev := in.Evidence
	ev.Packages = append([]ContinuityPackage(nil), ev.Packages...)
	sort.Slice(ev.Packages, func(i, j int) bool { return ev.Packages[i].Purl < ev.Packages[j].Purl })
	ev.Held, ev.Regressed, ev.First, ev.Unread = 0, 0, 0, 0
	for i := range ev.Packages {
		p := &ev.Packages[i]
		p.Lost = ContinuityLosses(ecosystemOf(p.Purl), p.Now, p.Before)
		p.Outcome = ContinuityOutcome(*p)
		ev.count(p.Outcome)
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectContinuity, Digest: SHA256(in.Bill)}},
		PredicateType: PredicateContinuity,
		Predicate: Predicate{
			Author: in.Author, Claim: ev.claim(), Verdict: ev.verdict(),
			Verifier: VerifierID{ID: ContinuityVerifier, Version: ContinuityVerifierVersion,
				Program: in.Program},
			Materials: []Material{}, Checks: ev.checks(), Continuity: &ev,
			VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *ContinuityEvidence) count(outcome string) {
	switch outcome {
	case ContinuityHeld:
		ev.Held++
	case ContinuityRegressed:
		ev.Regressed++
	case ContinuityFirst:
		ev.First++
	case ContinuityUnread:
		ev.Unread++
	}
}

func (ev *ContinuityEvidence) verdict() Verdict {
	switch {
	case ev.Regressed > 0:
		return Refuted
	case ev.Unread > 0 || len(ev.Packages) == 0:
		return Inconclusive
	}
	return Proven
}

func (ev *ContinuityEvidence) claim() string {
	return fmt.Sprintf("None of the %d npm, PyPI and Go package(s) in the bill lost, from the release before "+
		"it, its provenance, its trusted publishing, the repository, workflow or tagged source it was built "+
		"from, its publishing account's identity, or its having no install scripts; and its registry has "+
		"neither withdrawn nor yanked it, nor served provenance about another artifact as its own.",
		len(ev.Packages))
}

func (ev *ContinuityEvidence) checks() []Check {
	var standing, compared []string
	withdrawn, yanked, mismatched := 0, 0, 0
	for _, p := range ev.Packages {
		var s, c []string
		for _, l := range p.Lost {
			if standingLosses[l] {
				s = append(s, l)
			} else {
				c = append(c, l)
			}
			switch l {
			case LostWithdrawn:
				withdrawn++
			case LostYanked:
				yanked++
			case LostMismatch:
				mismatched++
			}
		}
		if len(s) > 0 {
			standing = append(standing, p.Purl+": "+strings.Join(s, ", "))
		}
		if len(c) > 0 {
			compared = append(compared, fmt.Sprintf("%s, after %s: %s", p.Purl, p.Before.Version, strings.Join(c, ", ")))
		}
	}
	standingCheck := Check{Name: "standing", Passed: len(standing) == 0,
		Detail: fmt.Sprintf("of %d package(s), %d release(s) were withdrawn by their registry, %d yanked by "+
			"their publisher, and %d served with provenance about another artifact", len(ev.Packages),
			withdrawn, yanked, mismatched)}
	var more int
	standingCheck.Failures, more = capped(standing)
	if more > 0 {
		standingCheck.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	continuity := Check{Name: "continuity", Passed: len(compared) == 0,
		Detail: fmt.Sprintf("%d release(s) held what the release before them had, %d were first releases "+
			"with nothing before them, and %d lost something from it", ev.Held, ev.First, len(compared))}
	continuity.Failures, more = capped(compared)
	if more > 0 {
		continuity.Detail += fmt.Sprintf("; %d more not listed", more)
	}
	registries := "the public registries"
	if !ev.PublicRegistries {
		registries = "registries the operator named"
	}
	read := Check{Name: "read", Passed: true,
		Detail: fmt.Sprintf("%d of %d package(s) were read from %s and %d could not be; %d component(s) are "+
			"of other ecosystems or name no version, and are not in the claim", len(ev.Packages)-ev.Unread,
			len(ev.Packages), registries, ev.Unread, ev.Outside)}
	return []Check{standingCheck, continuity, read}
}

// wellFormed holds one release's fields to their shapes and to what its
// ecosystem can say.
func (r *ContinuityRelease) wellFormed(ecosystem string) error {
	if !versionShape.MatchString(r.Version) {
		return fmt.Errorf("a release is named by its version")
	}
	if r.Published != "" {
		if _, err := time.Parse(time.RFC3339, r.Published); err != nil {
			return fmt.Errorf("a release's publication is a time, RFC 3339")
		}
	}
	for _, d := range []string{r.Attestation, r.Publisher, r.Account, r.Repository, r.Workflow, r.Scripts} {
		if d != "" && !hex64.MatchString(d) {
			return fmt.Errorf("what somebody else chose is carried as a sha256 digest")
		}
	}
	if r.Commit != "" && !commitShape.MatchString(r.Commit) {
		return fmt.Errorf("a commit is a git hash")
	}
	if r.Ref != "" && r.Ref != refTag && r.Ref != refBranch && r.Ref != refOther {
		return fmt.Errorf("a ref is a tag, a branch or other")
	}
	if r.Provenance && (r.Mismatch || r.Attestation == "") {
		return fmt.Errorf("provenance found is an attestation about the artifact, by digest")
	}
	if !r.Provenance && r.Attestation != "" {
		return fmt.Errorf("an attestation is carried only when it was provenance about the artifact")
	}
	if !r.Listed && (r.Provenance || r.Trusted || r.Publisher != "" || r.Repository != "" || r.Scripts != "" ||
		r.Yanked || r.Mismatch) {
		return fmt.Errorf("a release the registry no longer serves says nothing more about itself")
	}
	switch ecosystem {
	case "golang":
		if r.Provenance || r.Mismatch || r.Trusted || r.Publisher != "" || r.Account != "" || r.Workflow != "" ||
			r.Scripts != "" || r.Yanked {
			return fmt.Errorf("a Go module has an origin and nothing else")
		}
	case "pypi":
		if r.Account != "" || r.Scripts != "" || r.Ref != "" || r.Commit != "" ||
			(r.Provenance != r.Trusted) {
			return fmt.Errorf("a PyPI release has an attestation from a trusted publisher, or none")
		}
	}
	return nil
}

// validate refuses evidence whose shapes or numbers do not hold together,
// do not support the verdict, or do not account for every word.
func (ev *ContinuityEvidence) validate(s *Statement) error {
	if len(ev.Packages) > MaxContinuityPackages || ev.Outside < 0 || ev.Outside > 1<<40 {
		return fmt.Errorf("a continuity proof reads at most %d packages", MaxContinuityPackages)
	}
	var held, regressed, first, unread int
	for i, p := range ev.Packages {
		if !purlShape.MatchString(p.Purl) || (i > 0 && ev.Packages[i-1].Purl >= p.Purl) {
			return fmt.Errorf("the packages are package URLs of npm, PyPI or Go, in order, once each")
		}
		eco := ecosystemOf(p.Purl)
		version := p.Purl[strings.LastIndex(p.Purl, "@")+1:]
		if p.Unread != "" && !unreadWords[p.Unread] {
			return fmt.Errorf("%s: a package is unread for a reason of a known kind", p.Purl)
		}
		if p.Now != nil {
			if p.Now.Version != version {
				return fmt.Errorf("%s: the release read is the one the bill names", p.Purl)
			}
			if err := p.Now.wellFormed(eco); err != nil {
				return fmt.Errorf("%s: %w", p.Purl, err)
			}
		} else if p.Unread == "" || p.Before != nil {
			return fmt.Errorf("%s: a package read has the release the bill names", p.Purl)
		}
		if b := p.Before; b != nil {
			if err := b.wellFormed(eco); err != nil {
				return fmt.Errorf("%s, before: %w", p.Purl, err)
			}
			if c, ok := vuln.Compare(b.Version, version); !ok || c >= 0 || !b.Listed {
				return fmt.Errorf("%s: the release before it orders before it and is served", p.Purl)
			}
		}
		lost := ContinuityLosses(eco, p.Now, p.Before)
		if strings.Join(lost, ",") != strings.Join(p.Lost, ",") {
			return fmt.Errorf("%s: what it lost is not what its releases say", p.Purl)
		}
		if p.Outcome != ContinuityOutcome(p) {
			return fmt.Errorf("%s: its outcome is not the one its releases make", p.Purl)
		}
		switch p.Outcome {
		case ContinuityHeld:
			held++
		case ContinuityRegressed:
			regressed++
		case ContinuityFirst:
			first++
		case ContinuityUnread:
			unread++
		}
	}
	if held != ev.Held || regressed != ev.Regressed || first != ev.First || unread != ev.Unread {
		return fmt.Errorf("the counts are not the packages'")
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != SubjectContinuity || len(s.Subject[0].Digest) != 1 {
		return fmt.Errorf("a continuity proof is about one bill, by its digest")
	}
	if len(s.Predicate.Materials) != 0 {
		return fmt.Errorf("a continuity proof reads the bill and its registries, and names no other material")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the evidence makes this %s, not %s", want, s.Predicate.Verdict)
	}
	if s.Predicate.Claim != ev.claim() {
		return fmt.Errorf("the claim is not the sentence its evidence makes")
	}
	got, _ := json.Marshal(s.Predicate.Checks)
	want, _ := json.Marshal(ev.checks())
	if string(got) != string(want) {
		return fmt.Errorf("the checks are not the ones its evidence makes")
	}
	return nil
}
