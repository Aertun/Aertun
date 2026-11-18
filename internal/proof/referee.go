// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/sca"
	"github.com/aertun/aertun/internal/vuln"
)

// A referee proof: a vulnerability report's static claims, held to the
// source it is about.
//
// # Why
//
// Finding a vulnerability is now cheap and checking one is not. In 2026 one
// model produced over twenty thousand candidate findings in a month; curl
// ended its bug bounty over reports that cited functions it does not have;
// HackerOne's Internet Bug Bounty and Google's open-source programme stopped
// taking submissions. Every maintainer is now triaging reports by hand that
// a program could have refused in a second: a file from another project, a
// function that is not there, a version outside the range the report itself
// gives, a severity its own CVSS vector does not give, the fourth copy of a
// flaw already reported.
//
// # The claim
//
// The report cites places that exist in the source at the commit it names;
// names the version that source declares, inside the range it gives; gives
// a CVSS score its vector recomputes to and the severity of that score; and
// is the first report of its flaw here. With an asset named, the asset's
// own code references the vulnerable symbol.
//
//   - refuted when a cited file is not there, or a cited function is not
//     defined in it, or a line is past its end; when the source declares
//     another version, or the version is outside the range or the range is
//     inverted; when the vector scores otherwise or the score is not of the
//     severity given; or when an earlier report of the same flaw was
//     committed or refereed here;
//   - proven when every claim was checked and held;
//   - inconclusive when one could not be checked: the source is not a
//     checkout at the commit named, a version does not order, a file is in a
//     language whose definitions are not read here, the vector is not a CVSS
//     3 base vector, or the asset's own code does not name the symbol (a
//     dependency may).
//
// # Priority
//
// `aertun vuln commit REPORT` writes the report's digest and its flaw's
// fingerprint to the audit log, revealing nothing of what it says: the
// moment the organisation knew. A referee proof names that entry, so the
// report's priority over a later one of the same flaw, and the start of any
// reporting clock it set running — the Cyber Resilience Act's among them —
// rest on the signed log rather than on anybody's inbox.
//
// # What it cannot say
//
// That the flaw is real. A report can cite real code and be wrong about it;
// running its proof of concept needs a sandbox and is out of scope. Every
// path, name and word the report chose is in the proof as a digest or not
// at all.

// RefereeVerifier and its version name this verifier.
const (
	RefereeVerifier        = "aertun/referee"
	RefereeVerifierVersion = "1"
)

// PredicateReferee is the predicate of a referee proof.
const PredicateReferee = "https://aertun.github.io/proof/referee/v1"

// SubjectReferee names what a referee proof is about.
const SubjectReferee = "vulnerability-report"

// What a cited place was found to be (internal/referee).
const (
	PlaceDefined    = "defined"
	PlaceMentioned  = "mentioned"
	PlaceNotDefined = "not-defined"
	PlaceNoFile     = "no-file"
	PlacePastEnd    = "past-end"
)

// Where the release falls against the range the report gives.
const (
	RangeInside    = "inside"
	RangeOutside   = "outside"
	RangeInverted  = "inverted"
	RangeUnordered = "unordered"
)

// MaxRefereeLocations bounds the places one report cites.
const MaxRefereeLocations = 64

var (
	refereePurl     = regexp.MustCompile(`^pkg:(npm|pypi|golang|github|cargo|maven|gem|nuget|composer)/[A-Za-z0-9._~%/!+-]{1,300}@[A-Za-z0-9._+~-]{1,128}$`)
	cvss3Base       = regexp.MustCompile(`^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$`)
	refereeCWE      = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	refereeLanguage = map[string]bool{"go": true, "javascript": true, "python": true, "c": true, "rust": true,
		"java": true, "ruby": true, "php": true, "unknown": true}
	refereePlaces = map[string]bool{PlaceDefined: true, PlaceMentioned: true, PlaceNotDefined: true,
		PlaceNoFile: true, PlacePastEnd: true}
	reachWords = map[string]bool{"referenced": true, "not-referenced": true, "unanalysed": true, "no-source": true}
)

// RefereeLocation is one place the report cites, and what was found there.
type RefereeLocation struct {
	// File and Function are the sha256 digests of the path and the name the
	// report gave.
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line,omitempty"`
	// Language is what the file's definitions were read as.
	Language string `json:"language"`
	Found    string `json:"found"`
}

// RefereeEarlier is an earlier report of the same flaw, by the audit entry
// that committed or refereed it.
type RefereeEarlier struct {
	Report string `json:"report"`
	Seq    int64  `json:"seq"`
	At     string `json:"at"`
}

// RefereeEvidence is what a referee proof rests on.
type RefereeEvidence struct {
	// Package is the release the report is about, by package URL, and
	// Commit the commit it was written against.
	Package string `json:"package"`
	Commit  string `json:"commit"`
	// Head is the commit the source read was at, when it was a checkout.
	Head string `json:"head,omitempty"`
	// Declared is the version the source says it is, when it says.
	Declared string `json:"declared,omitempty"`
	// Introduced and Fixed are the range the report gives, and Range where
	// the release falls against it.
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Range      string `json:"range"`
	// Locations are the places cited, in the report's order.
	Locations []RefereeLocation `json:"locations"`
	CWE       string            `json:"cwe,omitempty"`
	// Vector is the CVSS vector, when it is a CVSS 3 base vector; Score and
	// Severity are what the report gives.
	Vector   string  `json:"vector,omitempty"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	// PoC is the digest of the proof of concept, which was not run.
	PoC string `json:"poc_sha256,omitempty"`
	// Fingerprint is what two reports of one flaw share (internal/referee).
	Fingerprint string `json:"fingerprint"`
	// Committed is the audit entry that committed this report, when one did.
	Committed *AuditEntry `json:"committed,omitempty"`
	// Duplicates are earlier reports of the same flaw, up to MaxFailures.
	Duplicates []RefereeEarlier `json:"duplicates,omitempty"`
	// Reach is what an asset's own code was found to do with the symbol,
	// when an asset was named (internal/reach).
	Reach string `json:"reach,omitempty"`
}

// RefereeInput is what a referee proof is made from.
type RefereeInput struct {
	Report   []byte
	Evidence RefereeEvidence
	Author   Author
	Program  string
	Now      time.Time
}

// RangeOf is where version falls against introduced and fixed.
func RangeOf(version, introduced, fixed string) string {
	if introduced != "" && fixed != "" {
		c, ok := vuln.Compare(introduced, fixed)
		if !ok {
			return RangeUnordered
		}
		if c >= 0 {
			return RangeInverted
		}
	}
	if introduced != "" {
		c, ok := vuln.Compare(version, introduced)
		if !ok {
			return RangeUnordered
		}
		if c < 0 {
			return RangeOutside
		}
	}
	if fixed != "" {
		c, ok := vuln.Compare(version, fixed)
		if !ok {
			return RangeUnordered
		}
		if c >= 0 {
			return RangeOutside
		}
	}
	return RangeInside
}

// SeverityOf is the CVSS severity of a score.
func SeverityOf(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score < 4:
		return "low"
	case score < 7:
		return "medium"
	case score < 9:
		return "high"
	}
	return "critical"
}

func (ev *RefereeEvidence) version() string { return ev.Package[strings.LastIndex(ev.Package, "@")+1:] }

func (ev *RefereeEvidence) atCommit() bool { return ev.Head == ev.Commit }

func (ev *RefereeEvidence) recomputed() (float64, bool) {
	if ev.Vector == "" {
		return 0, false
	}
	return sca.BaseScore(ev.Vector)
}

// ProveReferee builds the unsigned statement.
func ProveReferee(in RefereeInput) (*Statement, error) {
	if len(in.Report) == 0 {
		return nil, fmt.Errorf("a referee proof is about a report")
	}
	ev := in.Evidence
	ev.Locations = append([]RefereeLocation(nil), ev.Locations...)
	ev.Duplicates = append([]RefereeEarlier(nil), ev.Duplicates...)
	if len(ev.Duplicates) > MaxFailures {
		ev.Duplicates = ev.Duplicates[:MaxFailures]
	}
	if !cvss3Base.MatchString(ev.Vector) {
		ev.Vector = ""
	}
	ev.Range = RangeOf(ev.version(), ev.Introduced, ev.Fixed)
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectReferee, Digest: SHA256(in.Report)}},
		PredicateType: PredicateReferee,
		Predicate: Predicate{
			Author: in.Author, Claim: ev.claim(), Verdict: ev.verdict(),
			Verifier: VerifierID{ID: RefereeVerifier, Version: RefereeVerifierVersion,
				Program: in.Program},
			Materials: []Material{}, Checks: ev.checks(), Referee: &ev,
			VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *RefereeEvidence) claim() string {
	asset := ""
	if ev.Reach != "" {
		asset = " The asset named references the vulnerable symbol in its own code."
	}
	return fmt.Sprintf("The report about %s at commit %s cites places that exist there, names the version "+
		"that source declares and one inside the range it gives, gives a CVSS score its vector recomputes "+
		"to and the severity of that score, and is the first report of its flaw here.%s", ev.Package,
		ev.Commit, asset)
}

func (ev *RefereeEvidence) verdict() Verdict {
	for _, c := range ev.checks() {
		if !c.Passed {
			return Refuted
		}
	}
	if !ev.atCommit() || ev.Range == RangeUnordered || ev.Vector == "" || (ev.Reach != "" && ev.Reach != "referenced") {
		return Inconclusive
	}
	for _, l := range ev.Locations {
		if l.Found == PlaceMentioned {
			return Inconclusive
		}
	}
	return Proven
}

func (ev *RefereeEvidence) checks() []Check {
	v := ev.version()
	at := Check{Name: "at-commit", Passed: true}
	switch {
	case !ev.atCommit() && ev.Head == "":
		at.Detail = fmt.Sprintf("the source read is not a git checkout whose head could be read, so nothing "+
			"in it can be said to be at commit %s", ev.Commit)
	case !ev.atCommit():
		at.Detail = fmt.Sprintf("the source read is at commit %s, not the %s the report names, so nothing in "+
			"it can be held against the report", ev.Head, ev.Commit)
	case ev.Declared == "":
		at.Detail = fmt.Sprintf("the source is at commit %s, and declares no version of its own to hold "+
			"%s against", ev.Commit, v)
	case ev.Declared != v:
		at.Passed = false
		at.Detail = fmt.Sprintf("the source at commit %s declares version %s, and the report names %s",
			ev.Commit, ev.Declared, v)
	default:
		at.Detail = fmt.Sprintf("the source is at commit %s and declares version %s, the one the report names",
			ev.Commit, v)
	}

	rng := Check{Name: "range", Passed: ev.Range != RangeOutside && ev.Range != RangeInverted}
	bounds := fmt.Sprintf("from %s to before %s", orAny(ev.Introduced, "the first release"), orAny(ev.Fixed, "any fix"))
	switch ev.Range {
	case RangeInside:
		rng.Detail = fmt.Sprintf("%s is inside the range the report gives, %s", v, bounds)
	case RangeOutside:
		rng.Detail = fmt.Sprintf("%s is outside the range the report gives, %s", v, bounds)
	case RangeInverted:
		rng.Detail = fmt.Sprintf("the range the report gives is inverted: it is introduced at %s and fixed "+
			"at %s, which does not come after it", ev.Introduced, ev.Fixed)
	default:
		rng.Detail = fmt.Sprintf("%s and the range the report gives, %s, do not order, so where it falls is "+
			"not known", v, bounds)
	}

	places := Check{Name: "locations", Passed: true}
	counts := map[string]int{}
	var failed []string
	for i, l := range ev.Locations {
		counts[l.Found]++
		if l.Found == PlaceNoFile || l.Found == PlaceNotDefined || l.Found == PlacePastEnd {
			failed = append(failed, fmt.Sprintf("location %d: %s (%s)", i+1, l.Found, l.Language))
		}
	}
	bad := len(failed)
	if ev.atCommit() {
		places.Passed = bad == 0
		places.Failures, _ = capped(failed)
	}
	places.Detail = fmt.Sprintf("of %d place(s) cited, %d are defined where cited, %d are named in a file "+
		"whose language's definitions are not read here, %d name no file there, %d name a function the file "+
		"does not define, and %d a line past the file's end", len(ev.Locations), counts[PlaceDefined],
		counts[PlaceMentioned], counts[PlaceNoFile], counts[PlaceNotDefined], counts[PlacePastEnd])
	if !ev.atCommit() && bad > 0 {
		places.Detail += ", which is not held against a report the source is not at the commit of"
	}

	severity := Check{Name: "severity", Passed: SeverityOf(ev.Score) == ev.Severity}
	got, scored := ev.recomputed()
	switch {
	case !severity.Passed:
		severity.Detail = fmt.Sprintf("the report gives a score of %.1f and calls it %s, and a score of %.1f "+
			"is %s", ev.Score, ev.Severity, ev.Score, SeverityOf(ev.Score))
	case !scored:
		severity.Detail = fmt.Sprintf("the report gives %.1f, %s, with no CVSS 3 base vector to recompute it "+
			"from", ev.Score, ev.Severity)
	case math.Abs(got-ev.Score) > 0.05:
		severity.Passed = false
		severity.Detail = fmt.Sprintf("the vector %s scores %.1f (%s), and the report gives %.1f (%s)",
			ev.Vector, got, SeverityOf(got), ev.Score, ev.Severity)
	default:
		severity.Detail = fmt.Sprintf("the vector %s scores %.1f, %s, as the report gives", ev.Vector, got,
			ev.Severity)
	}

	unique := Check{Name: "unique", Passed: len(ev.Duplicates) == 0}
	if unique.Passed {
		unique.Detail = "no earlier report of the same flaw — the same package, weakness and places — was " +
			"committed or refereed here"
	} else {
		unique.Detail = fmt.Sprintf("%d earlier report(s) of the same flaw were committed or refereed here",
			len(ev.Duplicates))
		for _, d := range ev.Duplicates {
			unique.Failures = append(unique.Failures, fmt.Sprintf("report %s, at audit entry %d, %s",
				d.Report[:16], d.Seq, d.At))
		}
	}

	priority := Check{Name: "priority", Passed: true,
		Detail: "the report was not committed to the audit log before this, so this proof is the first record of it"}
	if c := ev.Committed; c != nil {
		priority.Detail = fmt.Sprintf("the report's digest was committed to the audit log at entry %d, %s: "+
			"its priority, and the moment it was known here", c.Seq, c.At)
	}
	checks := []Check{at, rng, places, severity, unique, priority}
	if ev.Reach != "" {
		reach := Check{Name: "reach", Passed: true}
		switch ev.Reach {
		case "referenced":
			reach.Detail = "the asset's own code names the vulnerable symbol"
		case "not-referenced":
			reach.Detail = "the asset's own code never names the vulnerable symbol; a dependency of it may"
		case "unanalysed":
			reach.Detail = "the report names no importable symbol to look for in the asset"
		default:
			reach.Detail = "the asset's source could not be read"
		}
		checks = append(checks, reach)
	}
	return checks
}

func orAny(s, otherwise string) string {
	if s == "" {
		return otherwise
	}
	return s
}

// validate refuses evidence whose shapes do not hold, whose derived words
// are not the ones it makes, or whose verdict it does not support.
func (ev *RefereeEvidence) validate(s *Statement) error {
	if !refereePurl.MatchString(ev.Package) || !commitShape.MatchString(ev.Commit) ||
		(ev.Head != "" && !commitShape.MatchString(ev.Head)) {
		return fmt.Errorf("a referee proof names a release by package URL and a commit in full")
	}
	for _, v := range []string{ev.Declared, ev.Introduced, ev.Fixed} {
		if v != "" && !versionShape.MatchString(v) {
			return fmt.Errorf("a version is a version")
		}
	}
	if ev.Range != RangeOf(ev.version(), ev.Introduced, ev.Fixed) {
		return fmt.Errorf("where the release falls is not what its versions say")
	}
	if len(ev.Locations) == 0 || len(ev.Locations) > MaxRefereeLocations {
		return fmt.Errorf("a report cites between 1 and %d places", MaxRefereeLocations)
	}
	for _, l := range ev.Locations {
		if !hex64.MatchString(l.File) || !hex64.MatchString(l.Function) || l.Line < 0 ||
			!refereeLanguage[l.Language] || !refereePlaces[l.Found] {
			return fmt.Errorf("a place is a digest of its path and its name, a language and what was found")
		}
		// A name is only mentioned in a language whose definitions are not
		// read, and only defined in one whose are.
		if (l.Found == PlaceMentioned) != (l.Language == "unknown" && l.Found != PlaceNoFile &&
			l.Found != PlaceNotDefined && l.Found != PlacePastEnd) {
			return fmt.Errorf("a place found by name alone is in a language whose definitions are not read")
		}
	}
	if ev.CWE != "" && !refereeCWE.MatchString(ev.CWE) {
		return fmt.Errorf("a weakness is named CWE-N")
	}
	if ev.Vector != "" && !cvss3Base.MatchString(ev.Vector) {
		return fmt.Errorf("a vector is carried only when it is a CVSS 3 base vector")
	}
	if ev.Score < 0 || ev.Score > 10 || math.IsNaN(ev.Score) || !severityWords[ev.Severity] {
		return fmt.Errorf("a score is between 0 and 10, and a severity is none, low, medium, high or critical")
	}
	if (ev.PoC != "" && !hex64.MatchString(ev.PoC)) || !hex64.MatchString(ev.Fingerprint) {
		return fmt.Errorf("a proof of concept and a fingerprint are digests")
	}
	if c := ev.Committed; c != nil && !c.valid() {
		return fmt.Errorf("a commitment is an audit entry")
	}
	if len(ev.Duplicates) > MaxFailures {
		return fmt.Errorf("the earlier reports are listed up to %d", MaxFailures)
	}
	for _, d := range ev.Duplicates {
		at, err := time.Parse(time.RFC3339Nano, d.At)
		if !hex64.MatchString(d.Report) || d.Seq < 1 || err != nil {
			return fmt.Errorf("an earlier report is a digest and the audit entry that recorded it")
		}
		if c := ev.Committed; c != nil {
			committed, _ := time.Parse(time.RFC3339Nano, c.At)
			if d.Seq >= c.Seq || at.After(committed) {
				return fmt.Errorf("an earlier report was recorded before this one was committed")
			}
		}
	}
	if ev.Reach != "" && !reachWords[ev.Reach] {
		return fmt.Errorf("what an asset does with a symbol is referenced, not-referenced, unanalysed or no-source")
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != SubjectReferee || len(s.Subject[0].Digest) != 1 {
		return fmt.Errorf("a referee proof is about one report, by its digest")
	}
	if len(s.Predicate.Materials) != 0 {
		return fmt.Errorf("a referee proof names no material beside the report")
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

var severityWords = map[string]bool{"none": true, "low": true, "medium": true, "high": true, "critical": true}
