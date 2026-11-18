// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package referee reads a vulnerability report — usually one a model wrote —
// and the source it is about, and says which of its static claims hold: the
// files and functions it cites exist at the commit it names, the version it
// names is the one the source declares and inside the range it gives, and
// its CVSS vector scores what it says. internal/proof signs what came of it.
//
// It never runs a proof of concept. That needs a sandbox, and a report's
// static claims are where most of what maintainers now receive falls down:
// a function that is not there, a file from another project, a severity
// the vector does not give.
package referee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Format is the report format this reads.
const Format = "aertun/vuln-report/v1"

// The bounds a report is held to.
const (
	MaxReport    = 1 << 20
	MaxLocations = 64
)

// Report is a vulnerability report.
type Report struct {
	Format string `json:"format"`
	// Title and Summary are for people; nothing here reads them.
	Title   string `json:"title,omitempty"`
	Summary string `json:"summary,omitempty"`
	// Package is the package URL of the release the report is about.
	Package string `json:"package"`
	// Commit is the source commit the report was written against.
	Commit string `json:"commit"`
	// Affected is the range of versions the report says are affected.
	Affected struct {
		Introduced string `json:"introduced,omitempty"`
		Fixed      string `json:"fixed,omitempty"`
	} `json:"affected"`
	// Locations are the places in the source the report says the flaw is.
	Locations []Location `json:"locations"`
	// Symbols are the importable symbols the flaw is in (Go: a package path
	// and functions), for asking whether an asset reaches them.
	Symbols []Symbol `json:"symbols,omitempty"`
	CWE     string   `json:"cwe,omitempty"`
	CVSS    struct {
		Vector   string  `json:"vector"`
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
	} `json:"cvss"`
	// PoCSHA256 is the digest of a proof of concept, which is never run.
	PoCSHA256 string `json:"poc_sha256,omitempty"`
}

// Location is a file and the function in it.
type Location struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line,omitempty"`
}

// Symbol is a package path and the functions in it.
type Symbol struct {
	Path  string   `json:"path"`
	Names []string `json:"names,omitempty"`
}

var (
	purlShape     = regexp.MustCompile(`^pkg:(npm|pypi|golang|github|cargo|maven|gem|nuget|composer)/[A-Za-z0-9._~%/!+-]{1,300}@[A-Za-z0-9._+~-]{1,128}$`)
	commitShape   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	versionShape  = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,128}$`)
	functionShape = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*((\.|::)[A-Za-z_$][A-Za-z0-9_$]*){0,4}$`)
	cweShape      = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	hexShape      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	symbolPath    = regexp.MustCompile(`^[A-Za-z0-9._~/-]{1,300}$`)
	identShape    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
	severities    = map[string]bool{"none": true, "low": true, "medium": true, "high": true, "critical": true}
)

// Parse reads a report strictly: a field this version does not know is an
// error, so a report cannot say something nobody checked.
func Parse(b []byte) (*Report, error) {
	if len(b) > MaxReport {
		return nil, fmt.Errorf("a report is at most %d bytes", MaxReport)
	}
	var r Report
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("this is not a report this version reads: %w", err)
	}
	if r.Format != Format {
		return nil, fmt.Errorf("a report says format %q", Format)
	}
	if !purlShape.MatchString(r.Package) {
		return nil, fmt.Errorf("a report names the release it is about by package URL, with its version")
	}
	if !commitShape.MatchString(r.Commit) {
		return nil, fmt.Errorf("a report names the commit it was written against, in full")
	}
	for _, v := range []string{r.Affected.Introduced, r.Affected.Fixed} {
		if v != "" && !versionShape.MatchString(v) {
			return nil, fmt.Errorf("an affected range is versions")
		}
	}
	if len(r.Locations) == 0 || len(r.Locations) > MaxLocations {
		return nil, fmt.Errorf("a report cites between 1 and %d places in the source", MaxLocations)
	}
	for i, l := range r.Locations {
		if _, ok := CleanPath(l.File); !ok {
			return nil, fmt.Errorf("location %d: a file is a relative path inside the source", i+1)
		}
		if !functionShape.MatchString(l.Function) {
			return nil, fmt.Errorf("location %d: a function is an identifier, qualified at most four times", i+1)
		}
		if l.Line < 0 || l.Line > 10_000_000 {
			return nil, fmt.Errorf("location %d: a line is a positive number", i+1)
		}
	}
	for i, s := range r.Symbols {
		if !symbolPath.MatchString(s.Path) {
			return nil, fmt.Errorf("symbol %d: a symbol's package is an import path", i+1)
		}
		for _, n := range s.Names {
			if !identShape.MatchString(n) {
				return nil, fmt.Errorf("symbol %d: a symbol is a function or Type.Method", i+1)
			}
		}
	}
	if r.CWE != "" && !cweShape.MatchString(r.CWE) {
		return nil, fmt.Errorf("a weakness is named CWE-N")
	}
	if !severities[r.CVSS.Severity] || r.CVSS.Score < 0 || r.CVSS.Score > 10 || len(r.CVSS.Vector) > 200 {
		return nil, fmt.Errorf("a report gives a CVSS vector, its score and its severity: none, low, medium, high or critical")
	}
	if r.PoCSHA256 != "" && !hexShape.MatchString(r.PoCSHA256) {
		return nil, fmt.Errorf("a proof of concept is named by its sha256")
	}
	return &r, nil
}

// CleanPath is a cited file as a path inside the source, or false when it
// would leave it.
func CleanPath(p string) (string, bool) {
	if p == "" || len(p) > 1024 || strings.ContainsAny(p, "\\\x00") || strings.HasPrefix(p, "/") {
		return "", false
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || c != p {
		return "", false
	}
	return c, true
}

// Ecosystem, Name and Version are the package URL's parts.
func (r *Report) Ecosystem() string {
	t, _, _ := strings.Cut(strings.TrimPrefix(r.Package, "pkg:"), "/")
	return t
}

// Name is the package's name, unescaped.
func (r *Report) Name() string {
	rest := strings.TrimPrefix(r.Package, "pkg:")
	_, rest, _ = strings.Cut(rest, "/")
	rest = rest[:strings.LastIndex(rest, "@")]
	if u, err := url.PathUnescape(rest); err == nil {
		return u
	}
	return rest
}

// Version is the release's version.
func (r *Report) Version() string { return r.Package[strings.LastIndex(r.Package, "@")+1:] }

// Fingerprint is what two reports of the same flaw share: the package, not
// its version; the weakness; and the places cited, without their lines,
// which two finders of one flaw rarely agree on.
func (r *Report) Fingerprint() string {
	places := make([]string, 0, len(r.Locations))
	for _, l := range r.Locations {
		places = append(places, l.File+"#"+l.Function)
	}
	sort.Strings(places)
	b, _ := json.Marshal(map[string]any{"package": r.Ecosystem() + "/" + r.Name(), "cwe": r.CWE,
		"locations": places})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Digest is sha256 in hex.
func Digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
