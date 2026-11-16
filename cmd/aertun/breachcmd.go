// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/evidence"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// `aertun vendor check-breach FILE`: a vendor's disclosure of its own
// breach, held against this organisation's events and signed as a
// breach-scope proof (internal/proof).
//
// The disclosure is written down by whoever received it, in a small strict
// format: the vendor, the notice's identifier, the window the vendor says
// the attacker was active in, what the vendor said about this organisation
// being affected, and the indicators it published. Each indicator is
// searched for, the way an investigation's citations are run again
// (internal/evidence), in a margin before the window, in it, and in a margin
// after it.

// BreachFormat names the disclosure format and its version.
const BreachFormat = "aertun/breach-disclosure/v1"

// MaxDisclosure bounds a disclosure file.
const MaxDisclosure = 1 << 20

// breachNow is when a breach-scope proof is made: the margin after a window
// is searched only up to it.
var breachNow = time.Now

type breachDisclosure struct {
	Format    string `json:"format"`
	Vendor    string `json:"vendor"`
	Reference string `json:"reference"`
	// Title is for a person to read, and never read here.
	Title      string `json:"title,omitempty"`
	Since      string `json:"since"`
	Until      string `json:"until"`
	Told       string `json:"told"`
	Indicators []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"indicators"`
}

const breachUsage = `usage: aertun vendor check-breach FILE --key FILE [--margin 30d] [--public-key F] [--out F]

FILE is the disclosure as received, written down in this form:

  {"format": "aertun/breach-disclosure/v1",
   "vendor": "acme-crm", "reference": "ACME-SA-2026-07",
   "title": "for people to read; never read here",
   "since": "2026-08-08T00:00:00Z", "until": "2026-08-18T00:00:00Z",
   "told": "not-affected",
   "indicators": [{"type": "ipv4", "value": "203.0.113.7"},
                  {"type": "domain", "value": "exfil.example"}]}

told is what the vendor told this organisation: affected, not-affected or unstated.`

func vendorCheckBreach(root string, args []string) error {
	fs := flag.NewFlagSet("vendor check-breach", flag.ContinueOnError)
	margin := fs.Duration("margin", 30*24*time.Hour, "how far before and after the window to "+
		"search: at most 2160h (90 days)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || fs.NArg() != 0 || *keyAt == "" {
		return fmt.Errorf("%s", breachUsage)
	}
	if *margin < time.Hour || *margin > proof.MaxBreachMargin {
		return fmt.Errorf("--margin is between 1h and 2160h")
	}
	body, err := proof.ReadBounded(pos[0], MaxDisclosure)
	if err != nil {
		return err
	}
	var d breachDisclosure
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.More() {
		return fmt.Errorf("the disclosure is not one JSON object in %s's form (aertun vendor "+
			"check-breach -h shows it)", BreachFormat)
	}
	if d.Format != BreachFormat {
		return fmt.Errorf("the disclosure says format %q; this reads %s", d.Format, BreachFormat)
	}
	since, err1 := time.Parse(time.RFC3339, d.Since)
	until, err2 := time.Parse(time.RFC3339, d.Until)
	if err1 != nil || err2 != nil || !since.Before(until) {
		return fmt.Errorf("the disclosure's since and until are RFC 3339 times, since first")
	}
	since, until = since.UTC().Truncate(time.Second), until.UTC().Truncate(time.Second)
	now := breachNow().UTC().Truncate(time.Second)
	if !until.Before(now) {
		return fmt.Errorf("the window has not ended: what has not happened yet cannot be checked")
	}
	ev := proof.BreachScopeEvidence{Vendor: d.Vendor, Reference: d.Reference,
		Since: since.Format(time.RFC3339), Until: until.Format(time.RFC3339),
		Margin: int(*margin / time.Second), Told: d.Told}
	if !proof.ValidVerdictSource(d.Vendor) || !proof.ValidReference(d.Reference) {
		return fmt.Errorf("the vendor is a short name (lower-case letters, digits, hyphens) and " +
			"the reference an identifier (letters, digits, . _ : -), not a title")
	}
	if len(d.Indicators) == 0 || len(d.Indicators) > proof.MaxIndicators {
		return fmt.Errorf("a disclosure names between 1 and %d indicators", proof.MaxIndicators)
	}
	var claims []evidence.Claim
	seen := map[string]bool{}
	for n, in := range d.Indicators {
		v, ok := proof.CanonicalObservable(in.Type, in.Value)
		if !ok {
			// By its place, never by what it says: the value is the vendor's.
			return fmt.Errorf("indicator %d is not an observable of a type this reads: %s",
				n+1, strings.Join(proof.ObservableTypes(), ", "))
		}
		if seen[in.Type+" "+v] {
			continue
		}
		seen[in.Type+" "+v] = true
		claims = append(claims, evidence.Claim{ID: fmt.Sprintf("i%d", len(claims)+1),
			Kind: proof.CiteSeen, ObsType: in.Type, Obs: v})
		ev.Indicators = append(ev.Indicators, proof.BreachIndicator{Type: in.Type, Value: v})
	}

	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed statement
	// that a supplier's disclosure does or does not hold is one somebody
	// takes to that supplier.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}

	// The three periods, each searched by the events' own time.
	afterEnd := until.Add(*margin)
	if afterEnd.After(now) {
		afterEnd = now
	}
	periods := []struct {
		from, to time.Time
		count    func(*proof.BreachIndicator, int)
		held     *bool
	}{
		{since.Add(-*margin), since, func(b *proof.BreachIndicator, n int) { b.Before = n }, &ev.HeldBefore},
		{since, until, func(b *proof.BreachIndicator, n int) { b.During = n }, &ev.HeldDuring},
		{until, afterEnd, func(b *proof.BreachIndicator, n int) { b.After = n }, &ev.HeldAfter},
	}
	var cov evidence.Coverage
	var sp *spool.Spool
	if _, err := os.Stat(spoolDir(root)); err == nil {
		if sp, err = openSpool(root, spool.Options{}); err != nil {
			return err
		}
		defer sp.Close()
		for _, seg := range sp.Segments() {
			if cov.From.IsZero() || seg.First.Before(cov.From) {
				cov.From = seg.First
			}
			if seg.Last.After(cov.Until) {
				cov.Until = seg.Last
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, p := range periods {
		*p.held = !cov.From.IsZero() && !cov.From.After(p.from) && !cov.Until.Before(p.to)
		if sp == nil || !p.from.Before(p.to) {
			continue
		}
		rep := evidence.Report{Source: d.Vendor, Form: "json", Since: p.from, Until: p.to, Claims: claims}
		results, events, err := evidence.Check(rep, cov, func(fn func(telemetry.Event) error) error {
			return sp.During(p.from, p.to, fn)
		})
		if err != nil {
			return err
		}
		ev.Events += events
		for i, r := range results {
			p.count(&ev.Indicators[i], r.Observed)
		}
	}

	in := proof.BreachScopeInput{Evidence: ev, Disclosure: body, Program: version, Now: now}
	st, err := proof.ProveBreachScope(in)
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
	if err := recordE(root, caller.auditRecord("vendor.breach-checked", "/vendors/"+d.Vendor,
		audit.Success, map[string]string{"reference": d.Reference,
			"verdict": string(st.Predicate.Verdict), "indicators": fmt.Sprint(len(ev.Indicators))})); err != nil {
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
