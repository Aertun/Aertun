// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/incident"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// `aertun incident prove ID --trigger aware`: when an incident's clock
// started, held against the signed audit log and its Bitcoin anchors, and
// whether every obligation it started was done in time — signed as a clock
// proof (internal/proof) and kept where the proving ground shows it.
//
// The audit log is the authority on when: the incident's own file is
// written by this program too, but it is a file, and a clock moved in it
// afterwards is exactly what a regulator would ask about. So the decision's
// time and every discharge's are taken from the log, verified first, and
// the incident's record is held against them.

// clockNow is when a clock proof is made, which decides whether an
// obligation not yet discharged is late or still running; a variable so a
// test can stand four days later.
var clockNow = time.Now

func incidentProve(root string, args []string) error {
	fs := flag.NewFlagSet("incident prove", flag.ContinueOnError)
	triggerAt := fs.String("trigger", "", "the decision: "+triggerList())
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || fs.NArg() != 0 || *triggerAt == "" || *keyAt == "" {
		return fmt.Errorf("incident prove takes ID --trigger DECISION --key FILE: an unsigned " +
			"account of when a clock started is the account a regulator already doubts")
	}
	id, trig := pos[0], incident.Trigger(*triggerAt)
	if !incident.ValidID(id) {
		return fmt.Errorf("%q is not an incident's identifier (aertun incident list)", id)
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed statement
	// of when this organisation knew is one a regulator is handed.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	inc, err := loadIncident(root, id)
	if err != nil {
		return err
	}
	moment, ok := inc.Started(trig)
	if !ok {
		return fmt.Errorf("incident %s has no %q decision recorded, so no clock to prove "+
			"(decisions are %s)", id, trig, triggerList())
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return fmt.Errorf("the audit log does not verify, so nothing can be taken from it: "+
			"entry %d: %s", p.Seq, p.Reason)
	}
	now := clockNow().UTC().Truncate(time.Second)

	var lines bytes.Buffer
	line := func(v any) {
		b, _ := json.Marshal(v)
		lines.Write(b)
		lines.WriteByte('\n')
	}
	ev := proof.ClockEvidence{Incident: id, Trigger: string(trig),
		Recorded: moment.At.UTC().Format(time.RFC3339Nano)}
	line(map[string]any{"incident": id, "trigger": trig, "recorded": moment.At})

	// The decision's entry, the discharges', and what was linked before it,
	// all from the verified log.
	resource := "/incidents/" + id
	type done struct {
		at     time.Time
		waived bool
	}
	discharged := map[string]done{}
	linked := map[string]bool{}
	decidedAt := -1
	for i, e := range events {
		if e.Resource != resource || e.Outcome != audit.Success {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, e.At)
		if perr != nil {
			continue
		}
		switch e.Action {
		case "incident.decide":
			if e.Detail["trigger"] == string(trig) && ev.Entry == 0 {
				ev.Entry, ev.Decided, ev.Verified = int(e.Seq), at.UTC().Format(time.RFC3339Nano), e.Verified
				decidedAt = i
				line(map[string]any{"entry": e.Seq, "hash": e.Hash, "decided": at})
			}
		case "incident.discharge", "incident.waive":
			if _, seen := discharged[e.Detail["regime"]]; !seen {
				discharged[e.Detail["regime"]] = done{at.UTC(), e.Action == "incident.waive"}
				line(map[string]any{"entry": e.Seq, "regime": e.Detail["regime"], "at": at})
			}
		case "incident.link":
			if decidedAt < 0 {
				linked[e.Detail["finding"]] = true
			}
		case "incident.unlink":
			if decidedAt < 0 {
				delete(linked, e.Detail["finding"])
			}
		}
	}

	// The obligations, timed from the log's moments rather than the file's.
	timed := *inc
	timed.Moments = map[incident.Trigger]incident.Moment{}
	for t, m := range inc.Moments {
		timed.Moments[t] = m
	}
	if ev.Entry > 0 {
		m := timed.Moments[trig]
		m.At, _ = time.Parse(time.RFC3339Nano, ev.Decided)
		timed.Moments[trig] = m
	}
	timed.Discharged = map[string]incident.Moment{}
	for regime, d := range discharged {
		m := incident.Moment{At: d.at, Why: "recorded"}
		if d.waived {
			m.Why = "not applicable: recorded"
		}
		timed.Discharged[regime] = m
	}
	for _, d := range timed.Duties(now) {
		if d.Needs != trig {
			continue
		}
		cd := proof.ClockDuty{Regime: d.Regime}
		var due, at time.Time
		if d.Started && !d.Due.IsZero() {
			due = d.Due
			cd.Due = due.UTC().Format(time.RFC3339Nano)
		}
		if l, ok := discharged[d.Regime]; ok {
			at, cd.Waived = l.at, l.waived
			cd.Done = at.Format(time.RFC3339Nano)
		}
		if m, ok := inc.Discharged[d.Regime]; ok {
			rec := m.At.UTC()
			if at.IsZero() || rec.After(at) || at.Sub(rec) > proof.ClockSkew {
				cd.Moved, cd.Recorded = true, rec.Format(time.RFC3339Nano)
			}
		}
		cd.Outcome = proof.DutyOutcome(due, at, cd.Waived, now)
		ev.Duties = append(ev.Duties, cd)
	}

	// What was known: the findings linked when the decision was made, and
	// how long before it the earliest was first seen.
	if decidedAt >= 0 && len(linked) > 0 {
		decided, _ := time.Parse(time.RFC3339Nano, ev.Decided)
		q, err := loadQueue(root, now)
		if err != nil {
			return err
		}
		ev.Linked = len(linked)
		var earliest time.Time
		for _, f := range q {
			if linked[f.ID] && !f.First.IsZero() && (earliest.IsZero() || f.First.Before(earliest)) {
				earliest = f.First
			}
		}
		if !earliest.IsZero() && earliest.Before(decided) {
			ev.Lead = int(decided.Sub(earliest) / time.Second)
		}
		line(map[string]any{"linked": ev.Linked, "earliest": earliest})
	}

	// The anchors: every head with a confirmed Bitcoin attestation, held to
	// the log as it is now.
	if ev.Entry > 0 {
		var unchecked int
		ev.Anchor, ev.Broken, unchecked, err = clockAnchors(root, events, ev.Entry)
		if err != nil {
			return err
		}
		if ev.Anchor != nil {
			line(map[string]any{"anchor": ev.Anchor})
		} else if unchecked > 0 {
			w.Human("  %s%d timestamp(s) name a Bitcoin block whose header has not been checked, "+
				"so none counts yet: aertun auditlog anchor upgrade fetches and checks it%s\n",
				dim, unchecked, reset)
		}
	}

	in := proof.ClockInput{Evidence: ev, Lines: lines.Bytes(), Program: version, Now: now}
	if len(events) > 0 {
		head := events[len(events)-1]
		in.Materials = append(in.Materials, proof.Material{Name: "audit-log",
			Digest: proof.Digest{"sha256": head.Hash}, Entries: len(events)})
	}
	if p, err := incidentPath(root, id); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			in.Materials = append(in.Materials, proof.Material{Name: "incident", Digest: proof.SHA256(b)})
		}
	}
	if b, err := os.ReadFile(anchorPath(root)); err == nil {
		in.Materials = append(in.Materials, proof.Material{Name: "anchors", Digest: proof.SHA256(b)})
	}
	st, err := proof.ProveClock(in)
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
	if err := recordE(root, caller.auditRecord("incident.proved", resource, audit.Success,
		map[string]string{"trigger": string(trig), "verdict": string(st.Predicate.Verdict),
			"entry": fmt.Sprint(st.Predicate.Clock.Entry)})); err != nil {
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

func triggerList() string {
	var out []string
	for _, t := range incident.Triggers {
		out = append(out, string(t))
	}
	return strings.Join(out, ", ")
}

// clockAnchors is the earliest anchor covering an entry whose block was
// checked, every such anchor whose head no longer matches the log, and how
// many timestamps name a block nobody has checked yet.
//
// Each timestamp is confirmed again from its own bytes and the header kept
// with it (anchor.Confirm) rather than from the state stored beside it: a
// Bitcoin attestation is a height and nothing more, and one written into the
// file by hand reaches no block. Each head is recomputed from the log: a
// head that matches is one the log still commits to; one that does not —
// or is longer than the log now is — was anchored before the log was
// rewritten, which is the thing an anchor exists to show.
func clockAnchors(root string, events []audit.Event, entry int) (*proof.ClockHead, []proof.ClockHead, int, error) {
	heads := &headFile{}
	if err := loadJSON(headsPath(root), heads); err != nil {
		return nil, nil, 0, err
	}
	anchors := &anchorFile{}
	if err := loadJSON(anchorPath(root), anchors); err != nil {
		return nil, nil, 0, err
	}
	roots := map[string]audit.Head{}
	for _, h := range heads.Heads {
		roots[h.Root] = h
	}
	var best *proof.ClockHead
	var broken []proof.ClockHead
	unchecked := 0
	seen := map[string]bool{}
	for _, p := range anchors.Proofs {
		head, ok := roots[p.Digest]
		if !ok || len(p.Body) == 0 {
			continue
		}
		blk, cerr := anchor.Confirm(p)
		if errors.Is(cerr, anchor.ErrUnchecked) {
			unchecked++
		}
		if cerr != nil || blk.Height == 0 {
			continue
		}
		height := blk.Height
		u, uerr := url.Parse(p.Calendar)
		if uerr != nil || u.Hostname() == "" {
			continue
		}
		ch := proof.ClockHead{Size: head.Size, Root: head.Root, Block: height, Hash: blk.Hash,
			Mined: blk.Mined.Format(time.RFC3339), Header: blk.Header,
			Calendar: strings.ToLower(u.Hostname())}
		key := fmt.Sprintf("%d/%s/%d", ch.Size, ch.Root, ch.Block)
		if seen[key] {
			continue
		}
		seen[key] = true
		matches := false
		if head.Size > 0 && head.Size <= len(events) {
			now, err := audit.TreeHead(events[:head.Size], time.Now())
			if err != nil {
				return nil, nil, 0, err
			}
			matches = now.Root == head.Root
		}
		switch {
		case !matches:
			if len(broken) < proof.MaxFailures {
				broken = append(broken, ch)
			}
		case head.Size >= entry && (best == nil || ch.Block < best.Block ||
			(ch.Block == best.Block && ch.Size < best.Size)):
			c := ch
			best = &c
		}
	}
	return best, broken, unchecked, nil
}
