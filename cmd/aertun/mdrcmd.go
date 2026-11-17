// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/mdr"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// A managed detection provider, or an AI SOC, tested blind on this estate
// (internal/mdr), and signed as an MDR proof (internal/proof).
//
// `mdr plan` draws the schedule — emulations from the operator's list, at
// random times in a window — keeps it in the store, and commits only its
// digest, with the provider, the count and the window, to the audit log.
// `mdr next` shows the person running the emulations what has fallen due,
// and nothing about what has not. `mdr ran` and `mdr notified` record, as a
// verified person, that an emulation was run and that the provider's
// notification about it came; `mdr notified --source` joins notifications
// from the provider's alerts in the event store where the plan names the
// host. `mdr prove` signs the result, and decides nothing until the test
// has closed.
//
// None of it is on the console or the agent interface: the schedule is the
// one thing the provider must not learn, and a provider under test is often
// given a seat on both.

// mdrNow is the clock the commands run on: whether a test has closed is the
// whole question, and a test cannot wait two days for it.
var mdrNow = time.Now

func mdrDir(root string) string { return filepath.Join(root, "mdr") }

func mdrPath(root, name string) string { return filepath.Join(mdrDir(root), name+".json") }

// maxPlanFile bounds a plan file: a thousand items of an id, a host and a
// time each.
const maxPlanFile = 1 << 20

// maxEmulationsFile bounds the operator's list.
const maxEmulationsFile = 1 << 20

// maxJoinAlerts bounds how many of the provider's alerts one join holds.
const maxJoinAlerts = 1 << 20

// loadPlan reads a plan strictly. The file is written as exactly the bytes
// the commitment's digest is over, so its sha256 is the digest the audit
// log holds and a proof's subject names; one in any other form has been
// edited, and is refused before anything else is compared.
func loadPlan(root, name string) (*mdr.Plan, error) {
	if !mdr.ValidName(name) {
		return nil, fmt.Errorf("a plan's name is 2 to 48 of a-z, 0-9 and -, starting with a letter")
	}
	body, err := proof.ReadBounded(mdrPath(root, name), maxPlanFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no plan is called %s; aertun mdr plan %s draws one", name, name)
	}
	if err != nil {
		return nil, err
	}
	var p mdr.Plan
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("plan %s does not read as one: %w", name, err)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	if p.Name != name || proof.SHA256(body)["sha256"] != p.Digest() {
		return nil, fmt.Errorf("plan %s is not in the form it was drawn in, so it has been edited", name)
	}
	return &p, nil
}

func cmdMDR(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("mdr needs plan, next, ran, notified or prove")
	}
	switch args[0] {
	case "plan":
		return mdrPlan(root, args[1:])
	case "next":
		return mdrNext(root, args[1:])
	case "ran":
		return mdrRan(root, args[1:])
	case "notified":
		return mdrNotified(root, args[1:])
	case "prove":
		return mdrProve(root, args[1:])
	default:
		return fmt.Errorf("unknown mdr command %q; try plan, next, ran, notified or prove", args[0])
	}
}

// nameFirst takes a leading positional name off the arguments.
func nameFirst(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// parseOver reads a window's length: whole days as 30d, or a Go duration.
func parseOver(s string) (time.Duration, error) {
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("--over %s is not a number of days", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("--over is a length of time, like 30d or 72h")
		}
		d = parsed
	}
	if d < proof.MinMDRWindow || d > proof.MaxMDRWindow || d%time.Second != 0 {
		return 0, fmt.Errorf("--over is between 1d and %dd, in whole seconds",
			int(proof.MaxMDRWindow.Hours()/24))
	}
	return d, nil
}

// requirePerson refuses a record of a run or a notification by anybody but
// a person whose identity was proved: the proof counts each record as that
// person's word, and a word nobody can be held to is not evidence.
func requirePerson(c *Caller, what string) error {
	if c.Kind == audit.KindAI {
		return fmt.Errorf("%s is recorded by a person: a model writing the evidence a provider, "+
			"perhaps an AI like it, is measured on is not a blind test", what)
	}
	if !c.Verified || c.Kind != audit.KindHuman {
		why := c.Why
		if why == "" {
			why = "the token presented is a service's, not a person's"
		}
		return fmt.Errorf("%s is recorded by a person whose identity is proved, and %s; present "+
			"your own token with --token, %s or AERTUN_TOKEN", what, why, tokenFile())
	}
	return nil
}

// mdrState reads a plan and its verified record.
func mdrState(root, name string) (*mdr.Plan, *mdr.Result, []audit.Event, error) {
	p, err := loadPlan(root, name)
	if err != nil {
		return nil, nil, nil, err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, nil, nil, err
	}
	r, err := mdr.Verify(p, events)
	if err != nil {
		return nil, nil, nil, err
	}
	return p, r, events, nil
}

func mdrPlan(root string, args []string) error {
	fs := flag.NewFlagSet("mdr plan", flag.ContinueOnError)
	provider := fs.String("provider", "", "the provider under test, by a short name you choose")
	emulationsAt := fs.String("emulations", "", "the list to draw from: one emulation id per line, "+
		"such as an Atomic Red Team test's T1059.001-1, optionally followed by the host to run it on "+
		"as the connectors write the device, issuer:value")
	count := fs.Int("count", 0, "how many emulations to draw")
	overAt := fs.String("over", "30d", "how long the window the times are drawn in runs from now: "+
		"between 1d and 366d")
	name, args := nameFirst(args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" || fs.NArg() != 0 || *provider == "" || *emulationsAt == "" || *count <= 0 {
		return fmt.Errorf("mdr plan takes NAME --provider P --emulations FILE --count N [--over 30d]")
	}
	if !mdr.ValidName(name) {
		return fmt.Errorf("a plan's name is 2 to 48 of a-z, 0-9 and -, starting with a letter")
	}
	over, err := parseOver(*overAt)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Tune: a plan decides what a provider will be measured on, as a blind
	// sample does.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a plan is drawn by a person: a model choosing when a provider is " +
			"tested could choose the nights it does well")
	}
	body, err := proof.ReadBounded(*emulationsAt, maxEmulationsFile)
	if err != nil {
		return err
	}
	list, err := mdr.ReadEmulations(body)
	if err != nil {
		return fmt.Errorf("%s: %w", *emulationsAt, err)
	}
	if _, err := os.Stat(mdrPath(root, name)); err == nil {
		return fmt.Errorf("a plan called %s is already drawn; a plan is never drawn again under "+
			"its name, because a second draw is how a bad schedule would be replaced", name)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return fmt.Errorf("the audit log does not verify, so nothing can be committed to it: "+
			"entry %d: %s", p.Seq, p.Reason)
	}
	if mdr.Committed(events, name) {
		return fmt.Errorf("the audit log already commits a plan called %s; draw this one under "+
			"another name, and the log keeps both", name)
	}
	p, err := mdr.Draw(name, *provider, list, *count, mdrNow(), over, rand.Reader)
	if err != nil {
		return err
	}
	doc, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(mdrDir(root), 0o700); err != nil {
		return err
	}
	// The file first and the commitment second: a commitment to a file that
	// was never written could never be checked, and a file nobody committed
	// is one no proof will accept.
	if err := atomicfile.Write(mdrPath(root, name), doc, 0o600); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord(mdr.PlannedAction, "/mdr/"+name, audit.Success,
		p.CommitDetail())); err != nil {
		return err
	}
	if w.JSON(map[string]any{"plan": name, "sha256": p.Digest(), "provider": p.Provider,
		"items": len(p.Items), "since": p.Since, "until": p.Until}) {
		return nil
	}
	w.Human("plan %s: %d emulation(s) for %s between %s and %s, committed to the audit log as a "+
		"digest alone. The schedule stays in the store and is shown only as each item falls due: "+
		"aertun mdr next %s\n", name, len(p.Items), p.Provider, p.Since.Format(time.RFC3339),
		p.Until.Format(time.RFC3339), name)
	return nil
}

func mdrNext(root string, args []string) error {
	name, args := nameFirst(args)
	fs := flag.NewFlagSet("mdr next", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" || fs.NArg() != 0 {
		return fmt.Errorf("mdr next takes NAME")
	}
	caller := resolveCaller(root, flagToken)
	// Tune, as drawing the plan takes: what has fallen due is part of the
	// schedule, and only those who could have drawn it may read it. Reading
	// it writes no record, because an entry each time somebody looked would
	// tell whoever reads the log when something was due.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("the schedule is shown to a person: an agent shown it could pass it to " +
			"the provider it is meant to be kept from")
	}
	p, r, _, err := mdrState(root, name)
	if err != nil {
		return err
	}
	prog := p.Progress(r, mdrNow().UTC())
	if w.JSON(map[string]any{"plan": p.Name, "due": prog.Due, "run": prog.Run,
		"lapsed": prog.Lapsed, "not_yet_due": prog.Waiting}) {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "plan %s: %d run, %d due, %d lapsed, %d not yet due\n", p.Name, prog.Run,
		len(prog.Due), prog.Lapsed, prog.Waiting)
	for _, it := range prog.Due {
		where := ""
		if it.Host != "" {
			where = " on " + it.Host
		}
		fmt.Fprintf(&b, "  %sitem %d%s  %s%s, due since %s; it counts if run before %s\n", bold, it.N,
			reset, it.Emulation, where, it.At.Format(time.RFC3339),
			it.At.Add(proof.MDRRunWithin).Format(time.RFC3339))
	}
	if len(prog.Due) > 0 {
		fmt.Fprintf(&b, "record each once its notification window has passed, so the record does "+
			"not tell the provider which alert is the test: aertun mdr ran %s --item N --at TIME\n", p.Name)
	}
	w.Human("%s", b.String())
	return nil
}

func mdrRan(root string, args []string) error {
	name, args := nameFirst(args)
	fs := flag.NewFlagSet("mdr ran", flag.ContinueOnError)
	item := fs.Int("item", 0, "the item's number, as aertun mdr next shows it")
	atAt := fs.String("at", "", "when it was run, as an RFC 3339 time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" || fs.NArg() != 0 || *item <= 0 || *atAt == "" {
		return fmt.Errorf("mdr ran takes NAME --item N --at TIME")
	}
	at, err := time.Parse(time.RFC3339, *atAt)
	if err != nil {
		return fmt.Errorf("--at is an RFC 3339 time, such as 2026-11-16T14:05:00Z")
	}
	caller := resolveCaller(root, flagToken)
	// Triage: recording what was run is reporting what happened, an
	// analyst's work like judging a blind item; whoever records it is named
	// in the log, and only a verified person may.
	if err := authorise(root, caller, auth.ActTriage, auth.AreaSecurity); err != nil {
		return err
	}
	if err := requirePerson(caller, "a run"); err != nil {
		return err
	}
	p, r, _, err := mdrState(root, name)
	if err != nil {
		return err
	}
	it, ok := p.Item(*item)
	if !ok {
		return fmt.Errorf("plan %s has no item %d", p.Name, *item)
	}
	if at.After(mdrNow()) {
		return fmt.Errorf("--at is in the future; a run is recorded once it has happened")
	}
	if _, done := r.Ran[it.N]; done {
		return fmt.Errorf("item %d is already recorded as run, and a test counts each item once", it.N)
	}
	if err := mdr.RunCounts(it, at, r.Commit.At); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord(mdr.RanAction, "/mdr/"+p.Name, audit.Success,
		mdr.RanDetail(p.Name, it.N, at))); err != nil {
		return err
	}
	if w.JSON(map[string]any{"plan": p.Name, "item": it.N, "ran": at.UTC()}) {
		return nil
	}
	w.Human("item %d recorded as run at %s; when the provider's notification about it comes: "+
		"aertun mdr notified %s --item %d --at TIME --ref TICKET\n", it.N,
		at.UTC().Format(time.RFC3339), p.Name, it.N)
	return nil
}

func mdrNotified(root string, args []string) error {
	name, args := nameFirst(args)
	fs := flag.NewFlagSet("mdr notified", flag.ContinueOnError)
	item := fs.Int("item", 0, "the item's number")
	atAt := fs.String("at", "", "when the provider's notification came, as an RFC 3339 time")
	ref := fs.String("ref", "", "the ticket or alert id the provider's notification came as")
	source := fs.String("source", "", "instead of one by hand, join the provider's alerts from "+
		"this source in the event store, on the hosts the plan names")
	if err := fs.Parse(args); err != nil {
		return err
	}
	byHand := *item != 0 || *atAt != "" || *ref != ""
	if name == "" || fs.NArg() != 0 || byHand == (*source != "") {
		return fmt.Errorf("mdr notified takes NAME --item N --at TIME --ref TICKET, or NAME --source S")
	}
	caller := resolveCaller(root, flagToken)
	// Triage, and a verified person, as for a run: a notification recorded
	// is the evidence the provider is credited with.
	if err := authorise(root, caller, auth.ActTriage, auth.AreaSecurity); err != nil {
		return err
	}
	if err := requirePerson(caller, "a notification"); err != nil {
		return err
	}
	p, r, _, err := mdrState(root, name)
	if err != nil {
		return err
	}
	if *source != "" {
		return mdrJoin(root, caller, p, r, *source)
	}
	if *item <= 0 || *atAt == "" || *ref == "" {
		return fmt.Errorf("a notification by hand takes --item N, --at TIME and --ref TICKET")
	}
	at, err := time.Parse(time.RFC3339, *atAt)
	if err != nil {
		return fmt.Errorf("--at is an RFC 3339 time, such as 2026-11-16T14:21:00Z")
	}
	if !telemetry.ValidAlertID(*ref) {
		return fmt.Errorf("--ref is the provider's ticket or alert id: letters, digits and . _ : -, " +
			"at most 128, never a sentence")
	}
	ran, wasRun := r.Ran[*item]
	switch {
	case !wasRun:
		return fmt.Errorf("item %d is not recorded as run; record the run first: aertun mdr ran %s "+
			"--item %d --at TIME", *item, p.Name, *item)
	case at.After(mdrNow()):
		return fmt.Errorf("--at is in the future; a notification is recorded once it has come")
	case at.Before(ran):
		return fmt.Errorf("--at is before item %d was run, so the notification is not about it", *item)
	}
	if _, done := r.Notified[*item]; done {
		return fmt.Errorf("item %d already has its notification recorded; the first one is the one "+
			"that counts", *item)
	}
	if other, used := r.Refs[*ref]; used {
		return fmt.Errorf("%s is already recorded as the notification of item %d", *ref, other)
	}
	if err := recordE(root, caller.auditRecord(mdr.NotifiedAction, "/mdr/"+p.Name, audit.Success,
		mdr.NotifiedDetail(p.Name, *item, at, *ref, ""))); err != nil {
		return err
	}
	if w.JSON(map[string]any{"plan": p.Name, "item": *item, "notified": at.UTC(),
		"after_seconds": int(at.Sub(ran).Seconds())}) {
		return nil
	}
	w.Human("item %d recorded as notified at %s, %s after it was run\n", *item,
		at.UTC().Format(time.RFC3339), at.Sub(ran).Round(time.Second))
	return nil
}

// mdrJoin records the notifications the provider's alerts in the event
// store show, where the join can be made on evidence (mdr.Join), and says
// which items it could not join and why.
func mdrJoin(root string, caller *Caller, p *mdr.Plan, r *mdr.Result, source string) error {
	if !proof.ValidSource(source) {
		return fmt.Errorf("--source is a source as the event store names it, such as " +
			"crowdstrike/detections")
	}
	var from, to time.Time
	for n, ran := range r.Ran {
		it, _ := p.Item(n)
		if _, done := r.Notified[n]; done || it.Host == "" {
			continue
		}
		if from.IsZero() || ran.Before(from) {
			from = ran
		}
		if end := ran.Add(mdr.JoinHorizon); end.After(to) {
			to = end
		}
	}
	var alerts []mdr.Alert
	unnamed := 0
	if !from.IsZero() {
		if _, err := os.Stat(spoolDir(root)); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("there is no event store here, so there is nothing to join; record "+
				"notifications by hand: aertun mdr notified %s --item N --at TIME --ref TICKET", p.Name)
		} else if err != nil {
			return err
		}
		if now := mdrNow().Add(time.Second); to.After(now) {
			to = now
		}
		sp, err := openSpool(root, spool.Options{})
		if err != nil {
			return err
		}
		defer sp.Close()
		err = sp.Range(from, to, func(e telemetry.Event) error {
			if e.Source != source || e.Class.Category() != telemetry.CategoryFindings {
				return nil
			}
			ref := e.Raw[telemetry.AlertField]
			if !telemetry.ValidAlertID(ref) {
				unnamed++
				return nil
			}
			if len(alerts) >= maxJoinAlerts {
				return fmt.Errorf("more than %d alerts from %s arrived in the period; record "+
					"notifications by hand", maxJoinAlerts, source)
			}
			host := ""
			if e.Device.Issuer != "" && e.Device.Value != "" {
				host = e.Device.Issuer + ":" + e.Device.Value
			}
			alerts = append(alerts, mdr.Alert{Ref: ref, Host: host, Raised: e.Time, Received: e.Received})
			return nil
		})
		if err != nil {
			return err
		}
	}
	matches, rep := mdr.Join(p, r, alerts)
	sort.Slice(matches, func(i, j int) bool { return matches[i].N < matches[j].N })
	for _, m := range matches {
		if err := recordE(root, caller.auditRecord(mdr.NotifiedAction, "/mdr/"+p.Name, audit.Success,
			mdr.NotifiedDetail(p.Name, m.N, m.At, m.Ref, source))); err != nil {
			return err
		}
	}
	if w.JSON(map[string]any{"plan": p.Name, "source": source, "joined": len(matches),
		"no_host": rep.NoHost, "ambiguous": rep.Ambiguous, "unmatched": rep.Unmatched,
		"taken": rep.Taken, "alerts_without_id": unnamed}) {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d notification(s) joined from %s, each an alert naming the host the plan "+
		"ran the emulation on, received within a day after the run\n", len(matches), source)
	if rep.NoHost > 0 {
		fmt.Fprintf(&b, "%d item(s) run name no host in the plan, and an alert matched on time alone "+
			"would be a guess: record their notifications by hand\n", rep.NoHost)
	}
	if rep.Ambiguous > 0 {
		fmt.Fprintf(&b, "%d item(s) ran within a day of another on the same host, so an alert there "+
			"could be about either: record them by hand\n", rep.Ambiguous)
	}
	if rep.Unmatched > 0 {
		fmt.Fprintf(&b, "%d item(s) have no alert from %s naming their host yet\n", rep.Unmatched, source)
	}
	if rep.Taken > 0 {
		fmt.Fprintf(&b, "%d item(s) would take an alert already recorded for another item, and "+
			"were left\n", rep.Taken)
	}
	if unnamed > 0 {
		fmt.Fprintf(&b, "%d alert(s) from %s carry no alert id in its shape, and a notification "+
			"is recorded by its id\n", unnamed, source)
	}
	if rep.NoHost+rep.Ambiguous+rep.Unmatched+rep.Taken > 0 {
		fmt.Fprintf(&b, "by hand: aertun mdr notified %s --item N --at TIME --ref TICKET\n", p.Name)
	}
	w.Human("%s", b.String())
	return nil
}

func mdrProve(root string, args []string) error {
	name, args := nameFirst(args)
	fs := flag.NewFlagSet("mdr prove", flag.ContinueOnError)
	sla := fs.Duration("sla", 0, "the time to notify the provider is held to, between 1m and 24h "+
		"(required)")
	tolerance := fs.Float64("tolerance", 0, "the share of runs the provider may miss — notify late or "+
		"not at all — between 0 and 1 (required)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if name == "" || fs.NArg() != 0 || *keyAt == "" {
		return fmt.Errorf("mdr prove takes NAME --sla 30m --tolerance R --key FILE")
	}
	if *sla < proof.MinMDRSLA || *sla > proof.MaxMDRSLA || *sla%time.Second != 0 {
		return fmt.Errorf("--sla is the time to notify the provider claims, between 1m and 24h, " +
			"and has no default: it is the claim")
	}
	if !(*tolerance > 0 && *tolerance < 1) {
		return fmt.Errorf("--tolerance is the share of runs the provider may miss, between 0 and 1, " +
			"and has no default: it is the claim")
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed statement
	// of how a provider performed, in this organisation's name, is one a
	// contract is renewed or ended on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	p, r, events, err := mdrState(root, name)
	if err != nil {
		return err
	}
	runs := make([]proof.MDRRun, 0, len(r.Ran))
	for n, ran := range r.Ran {
		it, _ := p.Item(n)
		runs = append(runs, proof.MDRRun{N: n, Emulation: it.Emulation, Ran: ran, Notified: r.Notified[n]})
	}
	now := mdrNow().UTC()
	head := events[len(events)-1]
	st, err := proof.ProveMDR(proof.MDRInput{Plan: p.Name, Provider: p.Provider, PlanSHA256: p.Digest(),
		Committed: proof.AuditEntry{Seq: r.Commit.Seq, Hash: r.Commit.Hash,
			At: r.Commit.At.UTC().Format(time.RFC3339Nano)},
		WindowStart: p.Since, WindowEnd: p.Until, SLA: *sla, Tolerance: *tolerance,
		Planned: len(p.Items), Runs: runs,
		Materials: []proof.Material{{Name: "audit-log", Digest: proof.Digest{"sha256": head.Hash},
			Entries: len(events)}},
		Program: version, Now: now})
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
	ev := st.Predicate.MDR
	// Kept only once the test has closed: a proof made while it is open
	// says nothing is decided, and keeping one a day would fill the proving
	// ground with the same nothing.
	if ev.Closed {
		if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
			keepMade(root, env, pubDoc, caller.Name)
		}
	}
	if err := recordE(root, caller.auditRecord("mdr.proved", "/mdr/"+p.Name, audit.Success,
		map[string]string{"plan": p.Name, "verdict": string(st.Predicate.Verdict),
			"sla": sla.String(), "tolerance": strconv.FormatFloat(*tolerance, 'g', -1, 64),
			"missed": fmt.Sprintf("%d/%d", ev.Missed.K, ev.Missed.N),
			"closed": strconv.FormatBool(ev.Closed)})); err != nil {
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
