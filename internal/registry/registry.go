// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package registry reads what a package registry says about a release: who
// published it and how, what it was built from, and what it runs on
// install — for npm, PyPI and the Go module proxy.
//
// It reads, and it does not judge: internal/proof holds two releases
// against each other. What it reads is the registry's own word. npm and
// PyPI check the Sigstore signatures on an attestation when it is
// published; this package does not check them again. It does check that the
// attestation is about the release it was fetched for — its subject is the
// artifact by digest — because an attestation for something else is not
// provenance for this.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/vuln"
)

// The ecosystems read, by their package-URL type.
const (
	NPM  = "npm"
	PyPI = "pypi"
	Go   = "golang"
)

// Ref kinds: what a release was built from, when its provenance says.
const (
	RefTag    = "tag"
	RefBranch = "branch"
	RefOther  = "other"
)

// Release is one release, as its registry describes it.
type Release struct {
	Version string
	// Published is when the registry says it was published; zero when it
	// does not say.
	Published time.Time
	// Listed is whether the registry serves it now. npm keeps the time of a
	// release it has removed — unpublished by its author or taken down for
	// malware — and serves nothing else of it.
	Listed bool
	// Yanked is whether its publisher asked that nobody install it (PyPI).
	Yanked bool

	// Provenance is whether a provenance attestation about this artifact
	// was found; Mismatch, whether one was found about something else.
	Provenance bool
	Mismatch   bool
	// Attestation is the sha256 of the provenance statement read.
	Attestation string
	// Trusted is whether it was published through trusted publishing: a
	// short-lived identity from a CI system, not a long-lived token.
	Trusted bool
	// Publisher is who the registry says published it, and Account the
	// account (npm), both as the registry spells them.
	Publisher string
	Account   string
	// Repository, Workflow, Ref and Commit are what its provenance, or the
	// Go proxy's record of its origin, says it was built from.
	Repository string
	Workflow   string
	Ref        string
	Commit     string
	// Scripts is what it runs on install (npm's preinstall, install and
	// postinstall), one "name=command" to a line; empty when nothing.
	Scripts string

	// detailed records that the second request, for provenance, was made.
	detailed bool
	// claimed is the registry's saying it has provenance, which Detail
	// reads before anything counts it; integrity is the artifact's digest
	// an attestation must be about (npm's sha512); files are a release's
	// files and their sha256 (PyPI).
	claimed   bool
	integrity string
	files     map[string]string
	// attested are the files the PyPI simple index shows with provenance;
	// nil when it was not read.
	attested map[string]bool
}

// RefKind is the kind of ref a release was built from, or "" when nothing
// says.
func (r *Release) RefKind() string {
	switch {
	case r.Ref == "":
		return ""
	case strings.HasPrefix(r.Ref, "refs/tags/"):
		return RefTag
	case strings.HasPrefix(r.Ref, "refs/heads/"):
		return RefBranch
	}
	return RefOther
}

// Getter fetches a URL, returning the body and the status. It is the one
// door to the network, so a test can serve the registry's answers from
// files.
type Getter func(ctx context.Context, url string) ([]byte, int, error)

// ErrNoPackage is a registry that has never heard of the package.
var ErrNoPackage = errors.New("the registry has no package by that name")

// Registry is one ecosystem's registry.
type Registry interface {
	// Releases is every version the registry knows of the package, removed
	// ones included where it keeps them, with what one request says.
	Releases(ctx context.Context, name string) (map[string]*Release, error)
	// Detail adds what another request says: the release's provenance.
	Detail(ctx context.Context, name string, r *Release) error
}

// Bases are where each registry is read from.
type Bases struct {
	NPM, PyPI, GoProxy string
}

// Public are the public registries.
var Public = Bases{NPM: "https://registry.npmjs.org", PyPI: "https://pypi.org",
	GoProxy: "https://proxy.golang.org"}

// For returns the registry of an ecosystem.
func For(ecosystem string, b Bases, get Getter) (Registry, bool) {
	switch ecosystem {
	case NPM:
		return &npm{base: strings.TrimRight(b.NPM, "/"), get: get}, true
	case PyPI:
		return &pypi{base: strings.TrimRight(b.PyPI, "/"), get: get}, true
	case Go:
		return &goproxy{base: strings.TrimRight(b.GoProxy, "/"), get: get}, true
	}
	return nil, false
}

// Predecessor is the release before version: the greatest one the registry
// still serves that orders before it and, where the registry says when each
// was published, was published before it — a maintenance release of an old
// line, published since, is not what came before — leaving out pre-releases
// unless version is one. A removed release says nothing of how it was made,
// so the one before it stands in. Versions that do not order (vuln.Compare) are left
// out; ok is false when version itself does not.
func Predecessor(all map[string]*Release, version string) (prev *Release, ok bool) {
	if _, comparable := vuln.Compare(version, version); !comparable {
		return nil, false
	}
	pre := strings.Contains(strings.TrimPrefix(version, "v"), "-")
	var at time.Time
	if r := all[version]; r != nil {
		at = r.Published
	}
	candidates := make([]string, 0, len(all))
	for v, r := range all {
		if !r.Listed || (!pre && strings.Contains(strings.TrimPrefix(v, "v"), "-")) {
			continue
		}
		if !at.IsZero() && !r.Published.IsZero() && !r.Published.Before(at) {
			continue
		}
		if c, ok := vuln.Compare(v, version); ok && c < 0 {
			candidates = append(candidates, v)
		}
	}
	if len(candidates) == 0 {
		return nil, true
	}
	sort.Slice(candidates, func(i, j int) bool {
		c, _ := vuln.Compare(candidates[i], candidates[j])
		if c == 0 {
			return candidates[i] < candidates[j]
		}
		return c < 0
	})
	return all[candidates[len(candidates)-1]], true
}

// Find is the release a bill names. PyPI writes a version in more than one
// spelling — 1.0.0-rc1, 1.0.0rc1, 1.0.0.RC1 are one release (PEP 440) — so
// for PyPI a version is also looked for as PEP 440 normalises it; anywhere
// else the version is the registry's own string.
func Find(ecosystem string, all map[string]*Release, version string) (*Release, bool) {
	if r, ok := all[version]; ok {
		return r, true
	}
	if ecosystem != PyPI {
		return nil, false
	}
	want := pep440(version)
	for v, r := range all {
		if pep440(v) == want {
			return r, true
		}
	}
	return nil, false
}

var (
	pepPre  = regexp.MustCompile(`[-_.]?(alpha|beta|preview|pre|rc|c|a|b)[-_.]?([0-9]*)$`)
	pepPost = regexp.MustCompile(`[-_.]?(post|rev|r)[-_.]?([0-9]*)$`)
	pepDev  = regexp.MustCompile(`[-_.]?dev[-_.]?([0-9]*)$`)
)

// pep440 is a version in PEP 440's normal form, as far as the spellings
// people write go: lower case, no leading v, and a pre-, post- or
// development release written the one way.
func pep440(v string) string {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	dev := ""
	if m := pepDev.FindStringSubmatch(v); m != nil {
		dev = ".dev" + orZero(m[1])
		v = v[:len(v)-len(m[0])]
	}
	post := ""
	if m := pepPost.FindStringSubmatch(v); m != nil {
		post = ".post" + orZero(m[2])
		v = v[:len(v)-len(m[0])]
	}
	pre := ""
	if m := pepPre.FindStringSubmatch(v); m != nil {
		tag := map[string]string{"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "rc": "rc",
			"pre": "rc", "preview": "rc"}[m[1]]
		pre = tag + orZero(m[2])
		v = v[:len(v)-len(m[0])]
	}
	return v + pre + post + dev
}

func orZero(n string) string {
	v, _ := strconv.Atoi(n)
	return strconv.Itoa(v)
}

// Detailed fetches a release's detail once.
func Detailed(ctx context.Context, reg Registry, name string, r *Release) error {
	if r == nil || r.detailed || !r.Listed {
		return nil
	}
	r.detailed = true
	return reg.Detail(ctx, name, r)
}

// Digest is a text's sha256, in hex: how a name somebody else chose is
// carried where it should not be repeated.
func Digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fetch gets a URL and requires a 200, telling a missing package apart.
func fetch(ctx context.Context, get Getter, raw string) ([]byte, error) {
	body, status, err := get(ctx, raw)
	switch {
	case err != nil:
		return nil, err
	case status == 404:
		return nil, ErrNoPackage
	case status != 200:
		return nil, fmt.Errorf("the registry answered %d", status)
	}
	return body, nil
}

// pathEscape escapes a name for one path segment.
func pathEscape(s string) string { return url.PathEscape(s) }
