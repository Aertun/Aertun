// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/fetch"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/registry"
	"github.com/aertun/aertun/internal/sca"
)

// `aertun vuln continuity BILL --key F` holds each npm, PyPI and Go package
// in a bill of materials to the release before it, as its registry
// describes both (internal/proof/continuity.go), and signs what came of it.
// It exits non-zero unless the proof is proven, so it is the gate in front
// of an install: a release made differently from the one before it — no
// provenance where there was, a token where there was trusted publishing,
// an install script where there was none — stops the build until somebody
// has looked.

// MaxBill bounds a bill of materials read for a continuity proof.
const MaxBill = 64 << 20

// continuityWorkers is how many packages are read at once: enough to keep a
// bill of a thousand quick, few enough to be a polite client.
const continuityWorkers = 8

// registryGetter is the door to the network continuity uses; a test serves
// the registries' answers from files through it.
var registryGetter registry.Getter = func(ctx context.Context, raw string) ([]byte, int, error) {
	c := fetch.For("registry")
	// A popular package's document lists every release it ever had.
	c.Limits = fetch.Limits{MaxBytes: 96 << 20, Timeout: time.Minute}
	// Do, not Get: a 404 is an answer — the registry has no such package —
	// and a redirect is not followed anywhere.
	r, err := c.Do(ctx, "GET", raw, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, 0, err
	}
	if r.Truncated {
		return nil, r.Status, fmt.Errorf("the registry's answer is larger than this reads")
	}
	return r.Body, r.Status, nil
}

func vulnContinuity(root string, args []string) error {
	var bill string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		bill, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("vuln continuity", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	npmAt := fs.String("npm", registry.Public.NPM, "the npm registry, or a mirror of it")
	pypiAt := fs.String("pypi", registry.Public.PyPI, "PyPI, or a mirror of it")
	goAt := fs.String("goproxy", registry.Public.GoProxy, "the Go module proxy, or a mirror of it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if bill == "" || fs.NArg() != 0 || *keyAt == "" {
		return fmt.Errorf("vuln continuity takes a bill of materials FILE and --key FILE")
	}
	bases := registry.Bases{NPM: *npmAt, PyPI: *pypiAt, GoProxy: *goAt}
	for _, b := range []string{bases.NPM, bases.PyPI, bases.GoProxy} {
		if _, err := fetch.ValidateURL(b); err != nil {
			return fmt.Errorf("a registry is reached over https at a public address: %w", err)
		}
	}
	caller := resolveCaller(root, flagToken)
	// Tune, as every proof signed in the organisation's name asks for.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	body, err := proof.ReadBounded(bill, MaxBill)
	if err != nil {
		return err
	}
	bom, err := sca.ReadBOM(body)
	if err != nil {
		return fmt.Errorf("%s: %w", bill, err)
	}
	wanted, outside := billPackages(bom)
	if len(wanted) > proof.MaxContinuityPackages {
		return fmt.Errorf("the bill names %d packages, and a continuity proof reads at most %d",
			len(wanted), proof.MaxContinuityPackages)
	}
	packages, why := inspectAll(context.Background(), bases, wanted)
	ev := proof.ContinuityEvidence{Outside: outside, PublicRegistries: bases == registry.Public,
		Packages: packages}
	// Why a package could not be read is the registry's words, so it is
	// told to whoever ran this and kept out of the proof.
	for i, reason := range why {
		if reason != "" {
			w.Human("%s was not read: %s\n", wanted[i].purl, reason)
		}
	}
	st, err := proof.ProveContinuity(proof.ContinuityInput{Bill: body, Evidence: ev, Program: version,
		Author: proof.Author{By: caller.Name}, Now: time.Now()})
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
	c := st.Predicate.Continuity
	if err := recordE(root, caller.auditRecord("continuity.proved", "/proofs", audit.Success,
		map[string]string{"verdict": string(st.Predicate.Verdict), "packages": fmt.Sprint(len(c.Packages)),
			"regressed": fmt.Sprint(c.Regressed), "unread": fmt.Sprint(c.Unread)})); err != nil {
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

// billPackage is one package the bill names, in an ecosystem read here.
type billPackage struct {
	ecosystem, name, version, purl string
}

var billVersion = regexp.MustCompile(`^[A-Za-z0-9._+~-]{1,128}$`)

// billPackages is the bill's npm, PyPI and Go packages, once each, and how
// many components are something else.
func billPackages(b sca.BOM) ([]billPackage, int) {
	seen := map[string]bool{}
	var out []billPackage
	outside := 0
	parts := b.Flat()
	root, hasRoot := b.Root()
	for _, p := range parts {
		if hasRoot && p.BOMRef != "" && p.BOMRef == root.BOMRef {
			continue
		}
		typ, name, version, ok := purlParts(p.PURL)
		if !ok {
			outside++
			continue
		}
		bp := billPackage{ecosystem: typ, name: name, version: version}
		bp.purl = canonicalPurl(bp)
		if seen[bp.purl] {
			continue
		}
		seen[bp.purl] = true
		out = append(out, bp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].purl < out[j].purl })
	return out, outside
}

// purlParts reads a package URL of an ecosystem read here into its type,
// name and version.
func purlParts(p string) (typ, name, version string, ok bool) {
	p = strings.TrimSpace(p)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	at := strings.LastIndex(p, "@")
	if !strings.HasPrefix(p, "pkg:") || at < 0 {
		return "", "", "", false
	}
	version, _ = url.PathUnescape(p[at+1:])
	t, _, _ := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	typ = strings.ToLower(t)
	if typ != registry.NPM && typ != registry.PyPI && typ != registry.Go {
		return "", "", "", false
	}
	_, name, found := sca.ParsePURL(p)
	if !found || !billVersion.MatchString(version) {
		return "", "", "", false
	}
	if typ == registry.PyPI {
		name = strings.ToLower(name)
	}
	return typ, name, version, true
}

// canonicalPurl writes a package's URL the one way: each name segment
// escaped, a scope's @ as %40.
func canonicalPurl(p billPackage) string {
	segs := strings.Split(p.name, "/")
	for i, s := range segs {
		segs[i] = strings.ReplaceAll(url.PathEscape(s), "@", "%40")
	}
	return "pkg:" + p.ecosystem + "/" + strings.Join(segs, "/") + "@" + p.version
}

// inspectAll reads every package's registry, a few at a time, with why
// each that could not be read was not.
func inspectAll(ctx context.Context, bases registry.Bases, wanted []billPackage) ([]proof.ContinuityPackage, []string) {
	out := make([]proof.ContinuityPackage, len(wanted))
	why := make([]string, len(wanted))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range continuityWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i], why[i] = inspect(ctx, bases, wanted[i])
			}
		}()
	}
	for i := range wanted {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out, why
}

// inspect reads one package: the release the bill names and the one before
// it, each with its provenance.
func inspect(ctx context.Context, bases registry.Bases, bp billPackage) (proof.ContinuityPackage, string) {
	p := proof.ContinuityPackage{Purl: bp.purl}
	reg, _ := registry.For(bp.ecosystem, bases, registryGetter)
	all, err := reg.Releases(ctx, bp.name)
	switch {
	case errors.Is(err, registry.ErrNoPackage):
		p.Unread = proof.UnreadNoPackage
		return p, err.Error()
	case err != nil:
		p.Unread = proof.UnreadRegistry
		return p, err.Error()
	}
	now := all[bp.version]
	if now == nil {
		if bp.ecosystem == registry.Go {
			p.Unread = proof.UnreadAbsent
			return p, "the module proxy does not list " + bp.version
		}
		// The package is there and this release is not: removed, and its
		// registry no longer says when.
		now = &registry.Release{Version: bp.version}
	}
	before, ordered := registry.Predecessor(all, bp.version)
	if err := registry.Detailed(ctx, reg, bp.name, now); err != nil {
		p.Now, p.Unread = summarise(&registry.Release{Version: now.Version, Published: now.Published,
			Listed: now.Listed, Yanked: now.Yanked}), proof.UnreadProvenance
		return p, err.Error()
	}
	p.Now = summarise(now)
	if !ordered {
		p.Unread = proof.UnreadVersionOrder
		return p, "its version does not order, so no release is before it"
	}
	if before != nil {
		if err := registry.Detailed(ctx, reg, bp.name, before); err != nil {
			p.Unread = proof.UnreadProvenance
			return p, err.Error()
		}
		p.Before = summarise(before)
	}
	return p, ""
}

var gitHash = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// summarise is a release as a proof carries it: what somebody else chose,
// as a digest.
func summarise(r *registry.Release) *proof.ContinuityRelease {
	out := &proof.ContinuityRelease{Version: r.Version, Listed: r.Listed, Yanked: r.Yanked && r.Listed}
	if !r.Published.IsZero() {
		out.Published = r.Published.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	if !r.Listed {
		return out
	}
	out.Provenance, out.Mismatch, out.Trusted = r.Provenance, r.Mismatch && !r.Provenance, r.Trusted
	if r.Provenance {
		out.Attestation = r.Attestation
	}
	out.Publisher = registry.Digest(r.Publisher)
	out.Account = registry.Digest(r.Account)
	out.Repository = registry.Digest(normaliseRepository(r.Repository))
	out.Workflow = registry.Digest(r.Workflow)
	out.Ref = r.RefKind()
	if gitHash.MatchString(r.Commit) {
		out.Commit = r.Commit
	}
	out.Scripts = registry.Digest(r.Scripts)
	return out
}

// normaliseRepository is a repository's address the one way, so the same
// repository written twice is not a change.
func normaliseRepository(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	return s
}

// describeContinuity is each package that did not hold, one to a line.
func describeContinuity(v *proof.ContinuityEvidence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  evidence: %d package(s): %d held, %d first release(s), %d regressed, %d unread; "+
		"%d other component(s)\n", len(v.Packages), v.Held, v.First, v.Regressed, v.Unread, v.Outside)
	for _, p := range v.Packages {
		switch p.Outcome {
		case proof.ContinuityRegressed:
			from := ""
			if p.Before != nil {
				from = " (after " + p.Before.Version + ")"
			}
			fmt.Fprintf(&b, "    %s%s: %s\n", p.Purl, from, strings.Join(p.Lost, ", "))
		case proof.ContinuityUnread:
			fmt.Fprintf(&b, "    %s: not read (%s)\n", p.Purl, p.Unread)
		}
	}
	return b.String()
}
