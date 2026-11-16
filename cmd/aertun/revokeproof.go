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
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/revoke"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// `aertun proof revocation`: after something was revoked, did the access
// stop? Signed as a revocation proof (internal/proof) and kept where the
// proving ground shows it.
//
// Two kinds of revocation. An agent disabled with the kill switch (--agent):
// the moment is the audit entry the switch wrote, and what acted as it is
// read from this program's own verified audit log — every call it answered
// for the agent and every token the agent exchanged — from the agent's own
// telemetry, and from the event store under any identity the operator
// declares the agent acts as elsewhere. Or an identity revoked in another
// system (--identity, with --at): a user, a token's client, an application,
// read from the event store under exactly the issuer and value the
// connectors write.

// revocationLate is how long after the period an event may arrive and
// still be read: sources deliver late, and a use that happened in the
// period and arrived an hour after it is still a use.
const revocationLate = 24 * time.Hour

func proofRevocation(root string, args []string) error {
	fs := flag.NewFlagSet("proof revocation", flag.ContinueOnError)
	agentName := fs.String("agent", "", "a registered agent disabled with the kill switch")
	var identities []string
	fs.Func("identity", "an identity to watch, ISSUER:VALUE as the connectors write it "+
		"(repeat for several; with --agent, what the agent acts as in other systems)",
		func(s string) error { identities = append(identities, s); return nil })
	atAt := fs.String("at", "", "when it was revoked, as an RFC 3339 time (default for an "+
		"agent: when the kill switch disabled it)")
	untilAt := fs.String("until", "", "the end of the period, not included (default: now)")
	grace := fs.Duration("grace", 5*time.Minute, "how long after the revocation is not counted, "+
		"for revocations to reach every system: at most 24h")
	lookback := fs.Duration("lookback", 7*24*time.Hour, "how far before the revocation to look "+
		"for sources that saw it act: between 1h and 720h")
	stretch := fs.Duration("stretch", time.Hour, "a source must deliver an event in every "+
		"stretch this long to count as listening: between 1m and 24h")
	telemetryID := fs.String("telemetry", "", "with --agent, the identity its GenAI spans name "+
		"it by (default: its registered name)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keyAt == "" || (*agentName == "" && len(identities) == 0) {
		return fmt.Errorf("proof revocation takes --agent NAME, or --identity ISSUER:VALUE --at " +
			"TIME, and --key FILE: an unsigned revocation proof is a claim about a claim")
	}
	for _, id := range identities {
		if !proof.ValidIdentity(id) {
			return fmt.Errorf("%q is not ISSUER:VALUE: the issuer a connector writes (okta, "+
				"github, aws) and the identifier, not a display name", id)
		}
		if strings.HasPrefix(id, "aertun:") {
			return fmt.Errorf("this program's own agents are named with --agent, whose log " +
				"is read directly; --identity is for other systems")
		}
	}
	if *grace < 0 || *grace > proof.MaxRevocationGrace ||
		*lookback < time.Hour || *lookback > proof.MaxRevocationLookback ||
		*stretch < proof.MinRevocationStretch || *stretch > proof.MaxRevocationStretch {
		return fmt.Errorf("--grace is at most 24h, --lookback between 1h and 720h, and " +
			"--stretch between 1m and 24h")
	}
	now := time.Now().UTC()
	until := now
	if *untilAt != "" {
		t, err := parseDay(*untilAt)
		if err != nil {
			return err
		}
		until = t
	}
	if until.After(now) {
		return fmt.Errorf("--until is not in the future")
	}

	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed from the store: a signed statement
	// that a revocation held, in this organisation's name, is one somebody
	// closes an incident on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
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

	in := proof.RevocationInput{Kind: proof.RevokedIdentity, Program: version, Now: now}
	var watched []string
	if *agentName != "" {
		name := *agentName
		if _, ok, err := agentStore(root).Get(name); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("no agent %q is registered (aertun agent list)", name)
		}
		var at time.Time
		if *atAt != "" {
			if at, err = parseDay(*atAt); err != nil {
				return err
			}
		}
		entry, revokedAt, err := agentDisabled(events, name, at)
		if err != nil {
			return err
		}
		if back, ok := agentEnabledAfter(events, name, revokedAt); ok && back.Before(until) {
			return fmt.Errorf("%s was enabled again at %s, and what it did after that is not a "+
				"use of a revoked agent: end the period before then (--until)", name,
				back.Format(time.RFC3339))
		}
		tele := *telemetryID
		if tele == "" {
			tele = name
		}
		if !proof.ValidIdentity("otel:" + tele) {
			return fmt.Errorf("--telemetry %q is not an identifier its spans could carry", tele)
		}
		watched = append([]string{"aertun:" + name}, identities...)
		watched = append(watched, "otel:"+tele)
		in.Kind, in.Name, in.Revoked, in.RevokedEntry = proof.RevokedAgent, name, revokedAt, entry
	} else {
		if *atAt == "" {
			return fmt.Errorf("an identity revoked in another system needs --at: when it was " +
				"revoked there, which this program did not see happen")
		}
		at, err := parseDay(*atAt)
		if err != nil {
			return err
		}
		watched = identities
		in.Name, in.Revoked = identities[0], at
	}
	if len(dedupe(watched)) != len(watched) || len(watched) > proof.MaxRevocationIdentities {
		return fmt.Errorf("each identity is watched once, and at most %d", proof.MaxRevocationIdentities)
	}
	win := revoke.Window{Revoked: in.Revoked, Grace: *grace, Until: until, Lookback: *lookback,
		Stretch: *stretch}
	if !win.From().Before(until) || until.Sub(win.From()) > proof.MaxRevocationPeriod {
		return fmt.Errorf("the period after the grace starts before it ends and is at most %d days",
			int(proof.MaxRevocationPeriod.Hours()/24))
	}
	in.Identities, in.Grace, in.Until, in.Lookback, in.Stretch = watched, *grace, until, *lookback, *stretch
	in.Stretches = win.Stretches()

	var lines bytes.Buffer
	line := func(v any) {
		b, _ := json.Marshal(v)
		lines.Write(b)
		lines.WriteByte('\n')
	}
	line(map[string]any{"kind": in.Kind, "name": in.Name, "revoked": in.Revoked,
		"entry": in.RevokedEntry, "identities": watched})
	wa := revoke.New(win, watched)
	// The agents' own telemetry is their word about themselves.
	wa.Account(otelSource)
	if in.Kind == proof.RevokedAgent {
		// This program's own log, verified above: every call the agent
		// interface answered for the agent and every token it exchanged
		// passed the gate that wrote it.
		wa.Complete(SelfSource)
		for _, e := range events {
			acted := (e.Action == "mcp.call" && e.Detail["agent"] == in.Name) ||
				(e.Principal == in.Name && e.Kind == audit.KindAI)
			if !acted {
				continue
			}
			at, perr := time.Parse(time.RFC3339Nano, e.At)
			if perr != nil {
				continue
			}
			refused := e.Outcome != audit.Success
			wa.Event(SelfSource, "aertun:"+in.Name, at, refused)
			if !at.Before(in.Revoked.Add(-*lookback)) && at.Before(until) {
				line(map[string]any{"source": SelfSource, "seq": e.Seq, "at": at, "refused": refused})
			}
		}
	}
	if _, err := os.Stat(spoolDir(root)); err == nil {
		sp, err := openSpool(root, spool.Options{})
		if err != nil {
			return err
		}
		defer sp.Close()
		ids := map[string]bool{}
		for _, id := range watched {
			ids[id] = true
		}
		readTo := until.Add(revocationLate)
		if readTo.After(now) {
			readTo = now.Add(time.Second)
		}
		err = sp.Range(in.Revoked.Add(-*lookback), readTo, func(e telemetry.Event) error {
			// The store's copies of this program's own log are read from
			// the log itself, verified, and not counted twice.
			if e.Source == SelfSource || e.Source == AgentSource {
				return nil
			}
			actor := ""
			if e.Actor.Issuer != "" {
				actor = e.Actor.Issuer + ":" + e.Actor.Value
			}
			if !proof.ValidSource(e.Source) {
				// A source a proof cannot name. Its other events change
				// nothing; one naming a watched identity would be a use or
				// a witness left out, so it stops the proof instead.
				if ids[actor] {
					return fmt.Errorf("source %q saw %s, and a proof cannot name it: rename the "+
						"feed (lower-case letters, digits, . _ / -)", e.Source, actor)
				}
				return nil
			}
			refused := e.Disposition == telemetry.DispositionBlocked ||
				e.Disposition == telemetry.DispositionFailed
			wa.Event(e.Source, actor, e.Time, refused)
			if ids[actor] {
				line(map[string]any{"source": e.Source, "actor": actor, "at": e.Time, "refused": refused})
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	in.Sources, in.Uses = wa.Result()
	if len(in.Sources) > proof.MaxRevocationSources {
		return fmt.Errorf("%d sources saw these identities; a proof lists at most %d — watch "+
			"fewer identities", len(in.Sources), proof.MaxRevocationSources)
	}
	for _, s := range in.Sources {
		line(map[string]any{"source": s.Source, "quiet": s.Quiet, "of": in.Stretches})
	}
	in.Lines = lines.Bytes()
	if len(events) > 0 {
		head := events[len(events)-1]
		in.Materials = append(in.Materials, proof.Material{Name: "audit-log",
			Digest: proof.Digest{"sha256": head.Hash}, Entries: len(events)})
	}
	if in.Kind == proof.RevokedAgent {
		if b, err := os.ReadFile(agentsPath(root)); err == nil {
			in.Materials = append(in.Materials, proof.Material{Name: "agent-register", Digest: proof.SHA256(b)})
		}
	}

	st, err := proof.ProveRevocation(in)
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
	ev := st.Predicate.Revocation
	if err := recordE(root, caller.auditRecord("revocation.proved", "/proofs", audit.Success,
		map[string]string{"kind": ev.Kind, "name": ev.Name, "verdict": string(st.Predicate.Verdict),
			"uses": fmt.Sprint(ev.Uses), "refused": fmt.Sprint(ev.Refused),
			"revoked": ev.Revoked, "until": ev.Until})); err != nil {
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

// agentDisabled is the kill switch's entry for an agent: the last one at or
// before at, or the last of all when at is zero.
func agentDisabled(events []audit.Event, name string, at time.Time) (int, time.Time, error) {
	seq, when := 0, time.Time{}
	for _, e := range events {
		if e.Action != "agent.disable" || e.Resource != "/agents/"+name || e.Outcome != audit.Success {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil || (!at.IsZero() && t.After(at)) {
			continue
		}
		seq, when = int(e.Seq), t
	}
	if seq == 0 {
		return 0, time.Time{}, fmt.Errorf("the audit log has no kill switch entry for %s%s: a "+
			"revocation proof starts from the revocation (aertun agent disable %s)", name,
			map[bool]string{true: "", false: " at or before --at"}[at.IsZero()], name)
	}
	return seq, when, nil
}

// agentEnabledAfter is when an agent was next enabled after a time.
func agentEnabledAfter(events []audit.Event, name string, after time.Time) (time.Time, bool) {
	for _, e := range events {
		if e.Action != "agent.enable" || e.Resource != "/agents/"+name || e.Outcome != audit.Success {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, e.At); err == nil && t.After(after) {
			return t, true
		}
	}
	return time.Time{}, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
