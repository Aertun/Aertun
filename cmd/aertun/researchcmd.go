// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

// `aertun research`: the dataset a paper's figures are drawn from
// (internal/research). Export writes what this store recorded and what
// this machine measured, de-identified, with a datasheet, under one dual
// signature; verify holds a dataset to it.

import (
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/benign"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/research"
	"github.com/aertun/aertun/internal/scitt"
	"github.com/aertun/aertun/internal/telemetry"
	"github.com/aertun/aertun/internal/windtunnel"
)

const researchUsage = `usage:
  aertun research export --key F --out DIR [--since 30d | --from T --to T] [--scorecard F --scorecard-key F]... [--iterations N] [--public-key F]
  aertun research verify DIR --public-key F`

// researchMaxWindow bounds the window one export covers, and
// researchMaxIterations the timings it takes.
const (
	researchMaxWindow     = 400 * 24 * time.Hour
	researchMaxIterations = 10000
)

func cmdResearch(root string, args []string) error {
	if len(args) == 0 {
		return errors.New(researchUsage)
	}
	switch args[0] {
	case "export":
		return researchExport(root, args[1:])
	case "verify":
		return researchVerify(args[1:])
	}
	return fmt.Errorf("research %s is not a command\n%s", args[0], researchUsage)
}

func researchExport(root string, args []string) error {
	fs := flag.NewFlagSet("research export", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file the dataset is signed with (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "where to write the public key a reader verifies the dataset with")
	outDir := fs.String("out", "", "the directory to write the dataset into; it must not exist or be empty")
	since := fs.String("since", "30d", "the window: this long before now")
	fromAt := fs.String("from", "", "the window's start, RFC 3339, instead of --since")
	toAt := fs.String("to", "", "the window's end, RFC 3339 (default now)")
	scoreKey := fs.String("scorecard-key", "", "the public key every --scorecard is verified against")
	iterations := fs.Int("iterations", 200, "timed repetitions of each measurement")
	var cards []string
	fs.Func("scorecard", "a signed wind tunnel scorecard whose rates go in the outcomes table (repeat)",
		func(s string) error { cards = append(cards, s); return nil })
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyAt == "" || *outDir == "" || fs.NArg() != 0 {
		return errors.New("research export needs --key FILE --out DIR\n" + researchUsage)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if given["since"] && given["from"] {
		return errors.New("--since and --from both say where the window starts; give one")
	}
	if *pubAt != "" {
		if inside, err := within(*outDir, *pubAt); err != nil {
			return err
		} else if inside {
			return errors.New("--public-key is inside --out: a dataset holds only what its signature names, " +
				"and the key a reader checks it with comes to them another way")
		}
	}
	if *iterations < 1 || *iterations > researchMaxIterations {
		return fmt.Errorf("--iterations is 1 to %d", researchMaxIterations)
	}
	if len(cards) > 0 && *scoreKey == "" {
		return errors.New("--scorecard needs --scorecard-key: a rate goes in the dataset only " +
			"from a scorecard verified against a key the exporter was handed")
	}
	now := time.Now().UTC()
	to := now
	if *toAt != "" {
		t, err := time.Parse(time.RFC3339Nano, *toAt)
		if err != nil {
			return fmt.Errorf("--to: %w", err)
		}
		to = t.UTC()
	}
	var from time.Time
	if *fromAt != "" {
		t, err := time.Parse(time.RFC3339Nano, *fromAt)
		if err != nil {
			return fmt.Errorf("--from: %w", err)
		}
		from = t.UTC()
	} else {
		d, err := parseSpan("--since", "30d or 72h", *since)
		if err != nil {
			return err
		}
		from = to.Add(-d)
	}
	if !from.Before(to) || to.Sub(from) > researchMaxWindow {
		return fmt.Errorf("the window runs forward and is at most %d days", int(researchMaxWindow.Hours()/24))
	}

	caller := resolveCaller(root, flagToken)
	// Grant, as a backup asks: the dataset draws on the event store, the
	// findings, the audit log, the receipt log and the benign register at
	// once, and takes what it draws out of the store.
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}

	// A key for this export alone, thrown away with it: pseudonyms are
	// consistent within the dataset and match nothing outside it.
	pkey := make([]byte, 32)
	if _, err := rand.Read(pkey); err != nil {
		return err
	}
	san, err := benign.NewSanitiser(pkey, nil, nil)
	if err != nil {
		return err
	}
	alias := func(kind, v string) string {
		if v == "" {
			return ""
		}
		return san.Opaque(kind, v)
	}

	x := research.New(research.Datasheet{
		Made: now, Program: version, Go: runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH, CPUs: runtime.NumCPU(),
		FIPS140: fips140.Enabled(), From: from, To: to,
		Pseudonyms: research.Pseudonyms{
			Method: "HMAC-SHA-256 under a random key made for this export and discarded with " +
				"it. One value of one kind has one pseudonym throughout the dataset, and none " +
				"matches anything outside it. A person the store itself records in two forms " +
				"(the audit log's principal, a benign session's approver) has two",
			KeyID: benign.KeyID(pkey)},
		NotCollected: []string{
			"what events said, where on the network they came from, finding titles, evidence " +
				"text, audit resources and details, and receipts' targets, tools and arguments: " +
				"left out so that the dataset names nobody",
			"when a rule fired for a given finding: a finding records the time of its " +
				"evidence, and the detections table records when each pass ran",
			"an anchor's Bitcoin transaction: OpenTimestamps records the block height and " +
				"header, not a transaction",
			"the build a scorecard was made with: a scorecard records its corpus, pack and " +
				"scenario digests and its seed, and the build that made this dataset is the " +
				"datasheet's program and go",
			"nothing is held back about detection rules: their ids are kept as the deployment " +
				"wrote them, and a rule named after a person or a customer would carry that name",
		},
	})

	if err := researchEvents(root, x, from, to, alias); err != nil {
		return err
	}
	if err := researchFindings(root, x, from, to, now, alias); err != nil {
		return err
	}
	if err := researchAudit(root, x, from, to, alias); err != nil {
		return err
	}
	if err := researchAnchors(root, x, from, to); err != nil {
		return err
	}
	if err := researchReceipts(root, x, from, to, alias); err != nil {
		return err
	}
	if err := researchBenign(root, x, alias); err != nil {
		return err
	}
	if err := researchOutcomes(x, cards, *scoreKey, alias); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp("", "aertun-research-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	measured, err := research.Measure(scratch, *iterations)
	if err != nil {
		return err
	}
	if err := x.Add(research.Measurements, measured); err != nil {
		return err
	}

	_, statErr := os.Stat(*outDir)
	made := errors.Is(statErr, os.ErrNotExist)
	if _, err := x.Write(*outDir, k); err != nil {
		return err
	}
	// From here a failure takes the dataset back out: one that was never
	// recorded, or that does not verify, is not one to leave lying about.
	sheet, sum, err := researchFinish(root, caller, *outDir, *pubAt, k, from, to)
	if err != nil {
		researchRemove(*outDir, made)
		return err
	}
	tables := map[string]int{}
	for _, t := range sheet.Tables {
		tables[t.Name] = t.Rows
	}
	if w.JSON(map[string]any{"out": *outDir, "export": sum, "tables": tables,
		"from": sheet.From, "to": sheet.To}) {
		return nil
	}
	w.Human("%swrote a research dataset to %s%s\n  %s\n  %sexport.json %s…; read the columns in %s%s\n",
		bold, *outDir, reset, sheet.Summary(), dim, sum[:16],
		research.DatasheetFile, reset)
	return nil
}

// researchFinish reads a dataset just written back as a reader would,
// writes the public key, and records the export, returning the datasheet
// and the envelope's SHA-256.
func researchFinish(root string, caller *Caller, dir, pubAt string, k *pack.Key,
	from, to time.Time) (*research.Datasheet, string, error) {
	sheet, err := research.Verify(dir, k.PublicKey())
	if err != nil {
		return nil, "", fmt.Errorf("the dataset just written does not verify: %w", err)
	}
	env, err := os.ReadFile(filepath.Join(dir, research.EnvelopeFile))
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(env)
	digest := hex.EncodeToString(sum[:])
	if pubAt != "" {
		if err := pack.WritePublicKey(pubAt, k.PublicKey()); err != nil {
			return nil, "", err
		}
	}
	rows := 0
	for _, t := range sheet.Tables {
		rows += t.Rows
	}
	if err := recordE(root, caller.auditRecord("research.exported", "/", audit.Success,
		map[string]string{"tables": strconv.Itoa(len(sheet.Tables)), "rows": strconv.Itoa(rows),
			"export": digest, "from": research.Stamp(from), "to": research.Stamp(to)})); err != nil {
		return nil, "", err
	}
	return sheet, digest, nil
}

// researchRemove takes a dataset back out of dir: the files it wrote, and
// the directory itself when the export made it.
func researchRemove(dir string, made bool) {
	if made {
		os.RemoveAll(dir)
		return
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		os.Remove(filepath.Join(dir, e.Name()))
	}
}

// within reports whether path is in dir or under it.
func within(dir, path string) (bool, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(d, p)
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// actionWord is an audit action as a table may carry it: the action's own
// name, which is the program's vocabulary. A refused command is recorded
// with the words it was given, which can carry a path, and becomes a
// pseudonym.
var actionWord = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$`)

func researchAction(action string, alias func(string, string) string) string {
	if actionWord.MatchString(action) {
		return action
	}
	return alias("action", action)
}

// researchRule is a finding's source as the findings table carries it:
// a detection rule's id as written, and anything else — an indicator's
// digest, a vendor's alert, a check — as a pseudonym, since it can name
// what the deployment touched.
func researchRule(kind finding.Kind, source string, alias func(string, string) string) string {
	if kind == finding.FromDetection && actionWord.MatchString(source) {
		return source
	}
	return alias("rule", source)
}

func researchEvents(root string, x *research.Export, from, to time.Time, alias func(string, string) string) error {
	rows := []research.EventRow{}
	if _, err := os.Stat(spoolDir(root)); err == nil {
		sp, err := openSpoolReadOnly(root)
		if err != nil {
			return err
		}
		defer sp.Close()
		if err := sp.Range(from, to, func(e telemetry.Event) error {
			if len(rows) == research.MaxRows {
				return fmt.Errorf("the window holds more than %d events, over what a dataset may; "+
					"narrow it with --since or --from and --to", research.MaxRows)
			}
			actor := ""
			if e.Actor.Value != "" {
				actor = alias("identity", e.Actor.Issuer+"\x00"+e.Actor.Value)
			}
			rows = append(rows, research.EventRow{Source: e.Source, Class: uint32(e.Class),
				Activity: e.Activity, Disposition: uint8(e.Disposition), Severity: uint8(e.Severity),
				Time: research.Stamp(e.Time), Received: research.Stamp(e.Received),
				LatenessMS: e.Lateness().Milliseconds(), Actor: actor})
			return nil
		}); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return x.Add(research.Events, rows)
}

func researchFindings(root string, x *research.Export, from, to, now time.Time,
	alias func(string, string) string) error {
	rows := []research.FindingRow{}
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		return err
	}
	for _, f := range reg.All(now) {
		if f.Last.Before(from) || !f.First.Before(to) {
			continue
		}
		entity := ""
		if f.Entity.Value != "" {
			entity = alias("identity", f.Entity.Issuer+"\x00"+f.Entity.Value)
		}
		rows = append(rows, research.FindingRow{Finding: alias("finding", f.ID), Kind: string(f.Kind),
			Rule: researchRule(f.Kind, f.Source, alias), Severity: uint8(f.Severity), State: string(f.State), Trial: f.Trial,
			First: research.Stamp(f.First), Last: research.Stamp(f.Last), Seen: f.Seen,
			Evidence: len(f.Evidence), Entity: entity})
	}
	return x.Add(research.Findings, rows)
}

func researchAudit(root string, x *research.Export, from, to time.Time, alias func(string, string) string) error {
	entries, err := audit.Read(auditPath(root))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	rows, runs := []research.AuditRow{}, []research.DetectionRow{}
	for _, e := range entries {
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil {
			return fmt.Errorf("audit entry %d has no time this reads: %w", e.Seq, err)
		}
		if at.Before(from) || !at.Before(to) {
			continue
		}
		rows = append(rows, research.AuditRow{At: research.Stamp(at), Action: researchAction(e.Action, alias),
			Outcome: string(e.Outcome), Kind: string(e.Kind), Verified: e.Verified,
			Principal: alias("principal", e.Principal)})
		if e.Action == "detect.run" {
			n := func(k string) int { v, _ := strconv.Atoi(e.Detail[k]); return v }
			runs = append(runs, research.DetectionRow{At: research.Stamp(at), By: string(e.Kind),
				Outcome: string(e.Outcome), Rules: n("rules"), Events: n("events"), Matches: n("matches"),
				Opened: n("opened"), Suppressed: n("suppressed"), Off: n("off"),
				Correlated: n("correlated"), IndicatorHits: n("indicator_hits")})
		}
	}
	if err := x.Add(research.Detections, runs); err != nil {
		return err
	}
	if err := x.Add(research.Audit, rows); err != nil {
		return err
	}
	heads := &headFile{}
	if err := loadJSON(headsPath(root), heads); err != nil {
		return err
	}
	headRows := []research.HeadRow{}
	for _, h := range heads.Heads {
		at, err := time.Parse(time.RFC3339Nano, h.At)
		if err != nil {
			return fmt.Errorf("a saved head has no time this reads: %w", err)
		}
		if at.Before(from) || !at.Before(to) {
			continue
		}
		headRows = append(headRows, research.HeadRow{Size: h.Size, At: research.Stamp(at)})
	}
	return x.Add(research.Heads, headRows)
}

func researchAnchors(root string, x *research.Export, from, to time.Time) error {
	f := &anchorFile{}
	if err := loadJSON(anchorPath(root), f); err != nil {
		return err
	}
	rows := []research.AnchorRow{}
	for _, p := range f.Proofs {
		sub, err := time.Parse(time.RFC3339Nano, p.SubmittedAt)
		if err != nil {
			return fmt.Errorf("an anchor has no submission time this reads: %w", err)
		}
		if sub.Before(from) || !sub.Before(to) {
			continue
		}
		row := research.AnchorRow{Calendar: p.Calendar, State: string(p.State),
			Height: p.Height, SubmittedAt: research.Stamp(sub)}
		if p.State == anchor.Anchored && p.UpgradedAt != "" {
			up, err := time.Parse(time.RFC3339Nano, p.UpgradedAt)
			if err != nil {
				return fmt.Errorf("an anchor has no upgrade time this reads: %w", err)
			}
			row.UpgradedAt, row.ConfirmSecs = research.Stamp(up), up.Sub(sub).Seconds()
		}
		rows = append(rows, row)
	}
	return x.Add(research.Anchors, rows)
}

func researchReceipts(root string, x *research.Export, from, to time.Time, alias func(string, string) string) error {
	receipts, recs := []research.ReceiptRow{}, []research.ReconciliationRow{}
	dir := filepath.Join(root, "receipts")
	// Only a whole log: opening one that is missing a part would make it.
	if receiptlog.Readable(dir) {
		l, err := receiptlog.Open(dir, "")
		if err != nil {
			return err
		}
		if err := l.Each(func(i int, entry []byte) error {
			s, err := scitt.Read(entry)
			if err != nil {
				return fmt.Errorf("receipt log entry %d: %w", i, err)
			}
			alg, err := s.Message.Algorithm()
			if err != nil {
				return fmt.Errorf("receipt log entry %d: %w", i, err)
			}
			switch s.ContentType {
			case aep.ContentAction:
				_, r, err := aep.ReadReceipt(entry)
				if err != nil {
					return fmt.Errorf("receipt log entry %d: %w", i, err)
				}
				if r.At.Before(from) || !r.At.Before(to) {
					return nil
				}
				row := research.ReceiptRow{Alg: cose.AlgName(alg), Bytes: len(entry),
					Issuer: alias("issuer", s.Issuer), Vantage: r.Vantage, At: research.Stamp(r.At),
					Outcome: r.Outcome, HasSeq: r.HasSeq}
				receipts = append(receipts, row)
			case aep.ContentReconciliation:
				if s.IssuedAt.Before(from) || !s.IssuedAt.Before(to) {
					return nil
				}
				t, err := aep.ReadTally(entry)
				if err != nil {
					return fmt.Errorf("receipt log entry %d: %w", i, err)
				}
				recs = append(recs, research.ReconciliationRow{Alg: cose.AlgName(alg),
					Bytes: len(entry), Issuer: alias("issuer", s.Issuer), IssuedAt: research.Stamp(s.IssuedAt),
					From: research.Stamp(t.From), To: research.Stamp(t.To), Expected: len(t.Expect),
					Verdict: t.Verdict, Receipts: t.Receipts, Actions: t.Actions, Complete: t.Complete,
					Gaps: t.Gaps, SeqGaps: t.SeqGaps, ActorSplits: t.ActorSplits})
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if err := x.Add(research.Receipts, receipts); err != nil {
		return err
	}
	return x.Add(research.Reconciliations, recs)
}

func researchBenign(root string, x *research.Export, alias func(string, string) string) error {
	rows := []research.BenignRow{}
	all, err := listBenign(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(all) > 0 {
		// Read only when there are sessions, which made the key: reading
		// it otherwise would make one.
		key, err := benignKey(root)
		if err != nil {
			return err
		}
		id := alias("benign-key", benign.KeyID(key))
		for _, r := range all {
			s := r.Session
			rows = append(rows, research.BenignRow{Session: alias("session", s.Name), Class: s.Class,
				State: r.State, Events: s.Events, Captured: research.Stamp(s.Captured),
				Expires: research.Stamp(s.Expires), Renewals: s.Renewals, Alone: s.Alone,
				VouchedBy: alias("principal", s.VouchedBy), ApprovedBy: alias("principal", s.ApprovedBy),
				Fields: len(s.Fields), Dropped: len(s.Dropped), Raw: len(s.Raw),
				Reduced: s.Fidelity.Reduced, KeyID: id})
		}
	}
	return x.Add(research.Benign, rows)
}

func researchOutcomes(x *research.Export, cards []string, keyAt string, alias func(string, string) string) error {
	rows := []research.OutcomeRow{}
	if len(cards) > 0 {
		pub, err := pack.LoadPublicKey(keyAt)
		if err != nil {
			return err
		}
		signer, err := windtunnel.ScorecardKeyID(pub)
		if err != nil {
			return err
		}
		for i, path := range cards {
			_, body, err := readSignedScorecard(path, pub)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			sum := sha256.Sum256(body)
			digest := hex.EncodeToString(sum[:])
			rates, err := research.ScorecardRates(body, digest, alias)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			rows = append(rows, rates...)
			// By its place, not its file name, which is whatever somebody
			// called it.
			x.Input(research.Input{Kind: "scorecard", Name: fmt.Sprintf("scorecard-%d", i+1),
				SHA256: digest, Signer: signer})
		}
	} else {
		x.NotCollected("rates from the wind tunnel: no --scorecard was given, so the outcomes table is empty")
	}
	return x.Add(research.Outcomes, rows)
}

func researchVerify(args []string) error {
	fs := flag.NewFlagSet("research verify", flag.ContinueOnError)
	pubAt := fs.String("public-key", "", "the public key the exporter published")
	// The directory first, as the usage writes it, and the flags after.
	var dir string
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		dir, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dir == "" && fs.NArg() == 1 {
		dir = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return errors.New(researchUsage)
	}
	if dir == "" || *pubAt == "" {
		return errors.New("research verify takes DIR --public-key FILE: a dataset is checked against " +
			"a key the reader was handed, never one it carries\n" + researchUsage)
	}
	pub, err := pack.LoadPublicKey(*pubAt)
	if err != nil {
		return err
	}
	sheet, err := research.Verify(dir, pub)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"verified": true, "datasheet": sheet}) {
		return nil
	}
	w.Human("verified: both signatures hold and every table is the one signed\n  %s\n", sheet.Summary())
	return nil
}
