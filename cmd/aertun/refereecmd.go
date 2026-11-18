// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/reach"
	"github.com/aertun/aertun/internal/referee"
)

// The vulnerability-report referee (internal/proof/referee.go).
//
// `aertun vuln commit REPORT` is the moment a report arrived: its digest
// and its flaw's fingerprint go into the audit log, and nothing else of it.
// `aertun vuln referee REPORT --source DIR --key F` holds the report's
// static claims to a checkout of the source it is about and signs what came
// of it, naming that commitment, so priority over a later report of the same
// flaw and the start of any reporting clock rest on the signed log.

// The audit actions the referee writes and reads.
const (
	reportCommitted = "vuln.report.committed"
	reportRefereed  = "vuln.report.refereed"
)

func readReport(file string) ([]byte, *referee.Report, error) {
	body, err := proof.ReadBounded(file, referee.MaxReport)
	if err != nil {
		return nil, nil, err
	}
	r, err := referee.Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	return body, r, nil
}

// reportLog is the audit log, verified, for finding what was committed and
// refereed: a log that does not verify cannot say what came first.
func reportLog(root string) ([]audit.Event, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	if ok, problems := audit.Verify(events); !ok {
		return nil, fmt.Errorf("the audit log does not verify at entry %d (%s), so what it says came first "+
			"cannot be relied on", problems[0].Seq, problems[0].Reason)
	}
	return events, nil
}

func vulnCommit(root string, args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("vuln commit takes one report FILE")
	}
	caller := resolveCaller(root, flagToken)
	body, r, err := readReport(args[0])
	if err != nil {
		return err
	}
	digest := proof.SHA256(body)["sha256"]
	events, err := reportLog(root)
	if err != nil {
		return err
	}
	for _, e := range events {
		if e.Action == reportCommitted && e.Outcome == audit.Success && e.Detail["sha256"] == digest {
			return fmt.Errorf("this report was committed already, at audit entry %d (%s)", e.Seq, e.At)
		}
	}
	fingerprint := r.Fingerprint()
	if err := recordE(root, caller.auditRecord(reportCommitted, "/vuln/reports", audit.Success,
		map[string]string{"sha256": digest, "fingerprint": fingerprint})); err != nil {
		return err
	}
	if w.JSON(map[string]any{"sha256": digest, "fingerprint": fingerprint}) {
		return nil
	}
	w.Human("report %s committed to the audit log by its digest alone; its flaw's fingerprint is %s\n",
		digest[:16], fingerprint[:16])
	return nil
}

func vulnReferee(root string, args []string) error {
	var file string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("vuln referee", flag.ContinueOnError)
	source := fs.String("source", "", "a checkout of the source the report is about, at the commit it names")
	asset := fs.String("asset", "", "the Go source of an asset, to ask whether it references the vulnerable symbol")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if file == "" || fs.NArg() != 0 || *source == "" || *keyAt == "" {
		return fmt.Errorf("vuln referee takes a report FILE, --source DIR and --key FILE")
	}
	if fi, err := os.Stat(*source); err != nil || !fi.IsDir() {
		return fmt.Errorf("--source is a directory: the source the report is about")
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
	body, r, err := readReport(file)
	if err != nil {
		return err
	}
	events, err := reportLog(root)
	if err != nil {
		return err
	}
	ev, err := refereeEvidence(body, r, *source, *asset, events)
	if err != nil {
		return err
	}
	st, err := proof.ProveReferee(proof.RefereeInput{Report: body, Evidence: ev, Program: version,
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
	if err := recordE(root, caller.auditRecord(reportRefereed, "/vuln/reports", audit.Success,
		map[string]string{"sha256": proof.SHA256(body)["sha256"], "fingerprint": ev.Fingerprint,
			"verdict": string(st.Predicate.Verdict)})); err != nil {
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

// refereeEvidence holds a report to its source and to what the audit log
// recorded before it.
func refereeEvidence(body []byte, r *referee.Report, source, asset string, events []audit.Event) (proof.RefereeEvidence, error) {
	digest := proof.SHA256(body)["sha256"]
	ev := proof.RefereeEvidence{Package: r.Package, Commit: r.Commit, Head: referee.Head(source),
		Declared: referee.Declared(source, r.Ecosystem(), r.Name()), Introduced: r.Affected.Introduced,
		Fixed: r.Affected.Fixed, CWE: r.CWE, Vector: r.CVSS.Vector, Score: r.CVSS.Score,
		Severity: r.CVSS.Severity, PoC: r.PoCSHA256, Fingerprint: r.Fingerprint()}
	for _, l := range r.Locations {
		language, found, err := referee.Locate(source, l)
		if err != nil {
			return ev, err
		}
		ev.Locations = append(ev.Locations, proof.RefereeLocation{File: referee.Digest(l.File),
			Function: referee.Digest(l.Function), Line: l.Line, Language: language, Found: found})
	}
	// This report's own commitment, the first of it, and every earlier
	// record of another report of the same flaw.
	for _, e := range events {
		if e.Action == reportCommitted && e.Outcome == audit.Success && e.Detail["sha256"] == digest {
			ev.Committed = &proof.AuditEntry{Seq: e.Seq, Hash: e.Hash, At: e.At}
			break
		}
	}
	for _, e := range events {
		if ev.Committed != nil && e.Seq >= ev.Committed.Seq {
			break
		}
		if (e.Action != reportCommitted && e.Action != reportRefereed) || e.Outcome != audit.Success ||
			e.Detail["fingerprint"] != ev.Fingerprint || e.Detail["sha256"] == digest {
			continue
		}
		ev.Duplicates = append(ev.Duplicates, proof.RefereeEarlier{Report: e.Detail["sha256"], Seq: e.Seq, At: e.At})
	}
	if asset != "" {
		var imports []reach.Affected
		for _, s := range r.Symbols {
			imports = append(imports, reach.Affected{Path: s.Path, Symbols: s.Names})
		}
		res, err := reach.Assess("report", r.Name(), imports, reach.Source{Dir: asset})
		if err != nil {
			return ev, err
		}
		ev.Reach = string(res.Verdict)
	}
	return ev, nil
}

// describeReferee is what failed or was left open, in a few lines.
func describeReferee(v *proof.RefereeEvidence) string {
	committed := "not committed before"
	if v.Committed != nil {
		committed = fmt.Sprintf("committed at audit entry %d", v.Committed.Seq)
	}
	return fmt.Sprintf("  evidence: %s at %s; %d place(s) cited; range %s; fingerprint %s; %s; %d earlier report(s) "+
		"of the flaw\n", v.Package, v.Commit[:12], len(v.Locations), v.Range, v.Fingerprint[:16], committed,
		len(v.Duplicates))
}
