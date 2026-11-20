// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/benign"
	"github.com/aertun/aertun/internal/dual"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// `aertun benign`: the estate's weird-but-benign sessions (internal/benign).
//
// capture selects events from the store, runs the active rules and the
// intelligence over them, sanitises them and asks a second administrator to
// approve the session; list and show read the register; revoke ends one;
// renew asks again for a longer life; bundle seals the approved, unexpired
// sessions into one signed file the wind tunnel replays (`windtunnel run
// --baseline`); verify checks a bundle offline.
//
// The register lives under the store's benign directory: the pseudonym key,
// which never leaves it, and one file per session holding only the
// sanitised events. The raw events stay in the event store they came from.

func benignDir(root string) string      { return filepath.Join(root, "benign") }
func benignKeyPath(root string) string  { return filepath.Join(benignDir(root), "key") }
func benignSessions(root string) string { return filepath.Join(benignDir(root), "sessions") }

// benignRecord is one session in the register.
type benignRecord struct {
	Session benign.Session `json:"session"`
	State   string         `json:"state"`
	// Request is the two-person request that approves it.
	Request string `json:"request,omitempty"`
	// FidelityRules are the rule digests its fidelity check ran.
	FidelityRules []string          `json:"fidelity_rules"`
	Events        []telemetry.Event `json:"events"`
	// RevokedAt and RevokedBy say when and by whom it was revoked.
	RevokedAt time.Time `json:"revoked_at,omitzero"`
	RevokedBy string    `json:"revoked_by,omitempty"`
}

// benignKey is the store's pseudonym key, made on first use. Whoever holds
// it can test a guess against a pseudonym, so it is the owner's alone.
func benignKey(root string) ([]byte, error) {
	b, err := os.ReadFile(benignKeyPath(root))
	if err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s is not a 32-byte key", benignKeyPath(root))
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(benignDir(root), 0o700); err != nil {
		return nil, err
	}
	return key, atomicfile.Write(benignKeyPath(root), key, 0o600)
}

func benignPath(root, name string) (string, error) {
	if !benign.ValidName(name) {
		return "", fmt.Errorf("%q is not a session's name (lower-case letters, digits, hyphens)", name)
	}
	return filepath.Join(benignSessions(root), name+".json"), nil
}

func loadBenign(root, name string) (*benignRecord, error) {
	p, err := benignPath(root, name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no session called %s (aertun benign list)", name)
	}
	if err != nil {
		return nil, err
	}
	var r benignRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &r, nil
}

func saveBenign(root string, r *benignRecord) error {
	p, err := benignPath(root, r.Session.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(benignSessions(root), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return atomicfile.Write(p, b, 0o600)
}

func listBenign(root string) ([]*benignRecord, error) {
	entries, err := os.ReadDir(benignSessions(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*benignRecord
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !benign.ValidName(name) || !e.Type().IsRegular() {
			continue
		}
		r, err := loadBenign(root, name)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Session.Name < out[j].Session.Name })
	return out, nil
}

func cmdBenign(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "capture":
		return benignCapture(root, args[1:])
	case "list":
		return benignList(root)
	case "show":
		return benignShow(root, args[1:])
	case "revoke":
		return benignRevoke(root, args[1:])
	case "renew":
		return benignRenew(root, args[1:])
	case "bundle":
		return benignBundle(root, args[1:])
	case "verify":
		return benignVerify(args[1:])
	default:
		return fmt.Errorf("unknown benign command %q; try capture, list, show, revoke, renew, "+
			"bundle or verify", args[0])
	}
}

// benignRuleSet is the active rule set: the store's detections and the
// correlations beside them, or the directory named.
func benignRuleSet(root, dir string) (benign.RuleSet, error) {
	d := rulesDir(root, dir)
	rules, err := rulesIn(d)
	if err != nil {
		return benign.RuleSet{}, fmt.Errorf("the rules a session is checked against: %w", err)
	}
	corrs, err := correlationsIn(d)
	if err != nil {
		return benign.RuleSet{}, err
	}
	return benign.RuleSet{Rules: rules, Corrs: corrs}, nil
}

func benignCapture(root string, args []string) error {
	fs := flag.NewFlagSet("benign capture", flag.ContinueOnError)
	class := fs.String("class", "", "what kind of workflow it is: "+strings.Join(benign.Classes, ", "))
	sinceAt := fs.String("since", "", "the window's start: an RFC 3339 time")
	untilAt := fs.String("until", "", "the window's end, not included: at most 24 hours after --since")
	actorAt := fs.String("actor", "", "only events by this actor, ISSUER:VALUE")
	deviceAt := fs.String("device", "", "only events from this device, ISSUER:VALUE")
	why := fs.String("why", "", "why this is benign: kept in the audit log, its digest on the session")
	ticket := fs.String("ticket", "", "the change ticket that explains it, by its id")
	life := fs.Duration("expires", benign.DefaultLife, "how long it counts: between 1h and 8760h")
	rulesAt := fs.String("rules", "", "the rules to check it against (default: the store's detections)")
	keepAll := fs.Bool("keep-all-fields", false, "keep every field, not only those the rules read")
	acceptLoss := fs.Bool("accept-fidelity-loss", false, "accept rule outcomes sanitising changed; "+
		"the session is marked reduced and names them")
	var sources, wheres, acks, raws []string
	fs.Func("source", "a source to select (repeat for several)", func(s string) error { sources = append(sources, s); return nil })
	fs.Func("where", "only events whose raw field equals a value, raw.KEY=VALUE (repeat)", func(s string) error { wheres = append(wheres, s); return nil })
	fs.Func("acknowledge", "a rule that fires on it, or a finding about one of its entities, "+
		"that you have looked at and still call benign (repeat)", func(s string) error { acks = append(acks, s); return nil })
	fs.Func("raw", "a field to keep unsanitised, recorded on the session (repeat)", func(s string) error { raws = append(raws, s); return nil })
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || fs.NArg() != 0 || *class == "" || len(sources) == 0 || *sinceAt == "" ||
		*untilAt == "" || strings.TrimSpace(*why) == "" {
		return fmt.Errorf("benign capture takes NAME --class C --source S --since T --until T " +
			"--why \"…\": a session is selected exactly, and vouched for with a reason")
	}
	name := pos[0]
	since, err := time.Parse(time.RFC3339, *sinceAt)
	if err != nil {
		return fmt.Errorf("--since is an RFC 3339 time")
	}
	until, err := time.Parse(time.RFC3339, *untilAt)
	if err != nil {
		return fmt.Errorf("--until is an RFC 3339 time")
	}
	if !since.Before(until) || until.Sub(since) > benign.MaxSessionSpan {
		return fmt.Errorf("the window starts before it ends and spans at most %s", benign.MaxSessionSpan)
	}
	where := map[string]string{}
	for _, w := range wheres {
		k, v, ok := strings.Cut(w, "=")
		key, isRaw := strings.CutPrefix(k, "raw.")
		if !ok || !isRaw || key == "" {
			return fmt.Errorf("--where is raw.KEY=VALUE")
		}
		where[key] = v
	}
	caller := resolveCaller(root, flagToken)
	// Tune: a benign session can block a rule change, which is the weight
	// of tuning the detections themselves.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	if p, _ := benignPath(root, name); p != "" {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("a session called %s exists; revoke it or choose another name", name)
		}
	}

	// The selection, by the events' own time, from the store.
	want := map[string]bool{}
	for _, s := range sources {
		want[s] = true
	}
	var events []telemetry.Event
	if _, err := os.Stat(spoolDir(root)); err == nil {
		sp, err := openSpool(root, spool.Options{})
		if err != nil {
			return err
		}
		defer sp.Close()
		err = sp.During(since, until, func(e telemetry.Event) error {
			if !want[e.Source] || (*actorAt != "" && e.Actor.String() != *actorAt) ||
				(*deviceAt != "" && e.Device.String() != *deviceAt) {
				return nil
			}
			for k, v := range where {
				if e.Raw[k] != v {
					return nil
				}
			}
			if len(events) > benign.MaxSessionEvents {
				return errTooMany
			}
			events = append(events, e)
			return nil
		})
		if errors.Is(err, errTooMany) {
			return fmt.Errorf("the selection holds more than %d events: a session is a workflow, "+
				"not a day; narrow it with --actor, --device or --where", benign.MaxSessionEvents)
		}
		if err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Received.Before(events[j].Received) })

	ack := map[string]bool{}
	for _, a := range acks {
		ack[a] = true
	}
	// What is already known to be bad is never vouched for: an indicator
	// held here refuses the capture outright, and a finding about one of
	// its entities still being worked must be acknowledged by its id.
	ind, err := loadIndicators(root)
	if err != nil {
		return err
	}
	matched := 0
	for _, e := range events {
		matched += len(ind.Match(e))
	}
	if matched > 0 {
		return fmt.Errorf("%d indicator match(es) held in the intelligence store are in this "+
			"selection, so it is not vouched for as benign; look at it as the finding it is", matched)
	}
	entities := map[string]bool{}
	for _, e := range events {
		for _, id := range []telemetry.ID{e.Actor, e.Target, e.Device} {
			if !id.Zero() {
				entities[id.String()] = true
			}
		}
	}
	q, err := loadQueue(root, time.Now().UTC())
	if err != nil {
		return err
	}
	var open []string
	for _, f := range q {
		if !f.State.Closed() && !f.Entity.Zero() && entities[f.Entity.String()] && !ack[f.ID] {
			open = append(open, f.ID)
		}
	}
	if len(open) > 0 {
		return fmt.Errorf("finding(s) %s about an entity in this selection are still being "+
			"worked; a session vouched for now could block the rule that raised them. Close "+
			"them, or name each with --acknowledge ID", strings.Join(open, ", "))
	}

	rs, err := benignRuleSet(root, *rulesAt)
	if err != nil {
		return err
	}
	key, err := benignKey(root)
	if err != nil {
		return err
	}
	rawFields := map[string]bool{}
	for _, f := range raws {
		rawFields[f] = true
	}
	c, err := benign.NewCapture(benign.CaptureInput{Name: name, Class: *class, Events: events, Key: key,
		Rules: rs, RawFields: rawFields, KeepAll: *keepAll, Acknowledge: ack, AcceptLoss: *acceptLoss,
		Why: *why, Ticket: *ticket, By: caller.Name, Life: *life, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	req, err := proposeBenign(root, caller, dual.BenignChange{Name: name, Action: "approve"}, *why)
	if err != nil {
		return err
	}
	rec := &benignRecord{Session: c.Session, State: benign.Pending, Request: req,
		FidelityRules: c.FidelityRules, Events: c.Events}
	if err := saveBenign(root, rec); err != nil {
		return err
	}
	s := c.Session
	if err := recordE(root, caller.auditRecord("benign.captured", "/benign/"+name, audit.Success,
		map[string]string{"name": name, "class": s.Class, "events": fmt.Sprint(s.Events),
			"sources": strings.Join(s.Sources, ","), "request": req, "why": strings.TrimSpace(*why),
			"acknowledged": strings.Join(s.Acknowledged, ","), "reduced": fmt.Sprint(s.Fidelity.Reduced),
			"expires": s.Expires.Format(time.RFC3339)})); err != nil {
		return err
	}
	if w.JSON(map[string]any{"session": s, "state": rec.State, "request": req}) {
		return nil
	}
	w.Human("%s%s%s captured: %d event(s) from %s, %s, expires %s\n", bold, name, reset, s.Events,
		strings.Join(s.Sources, ", "), s.Class, s.Expires.Format("2006-01-02"))
	w.Human("  kept %d field(s), dropped %d, pseudonymised %d; fidelity checked against %d rule(s)\n",
		len(s.Fields), len(s.Dropped), len(s.Transformed), s.Fidelity.Rules)
	if s.Fidelity.Reduced {
		w.Human("  %sreduced: sanitising changed what %s do%s\n", yellow, strings.Join(s.Fidelity.Lost, ", "), reset)
	}
	w.Human("  %swaiting for a second administrator: aertun pending approve %s%s\n", dim, req, reset)
	return nil
}

var errTooMany = errors.New("too many events")

// proposeBenign asks a second administrator to agree to a session, or to
// its renewal.
func proposeBenign(root string, c *Caller, ch dual.BenignChange, why string) (string, error) {
	what := "vouch for benign session " + ch.Name
	if ch.Action == "renew" {
		what = "renew benign session " + ch.Name + " until " + ch.Expires.Format("2006-01-02")
	}
	alone := onlyAdministrator(root, c.Name)
	r, err := dualStore(root).Propose(dual.Benign, what, ch, why, c.Name, alone, time.Now())
	if err != nil {
		return "", err
	}
	if err := recordE(root, c.auditRecord("dual.proposed", "/", audit.Success,
		map[string]string{"request": r.ID, "kind": dual.Benign, "what": what, "why": why,
			"alone": fmt.Sprint(alone)})); err != nil {
		return "", err
	}
	return r.ID, nil
}

// applyBenign is a Benign request approved: the session counts, or counts
// for longer, and the approver is named on it by pseudonym.
func applyBenign(root string, r dual.Request, by string) error {
	var ch dual.BenignChange
	if err := json.Unmarshal(r.Payload, &ch); err != nil {
		return err
	}
	rec, err := loadBenign(root, ch.Name)
	if err != nil {
		return err
	}
	if rec.State == benign.Revoked {
		return fmt.Errorf("session %s was revoked, and a revoked session is not approved again; "+
			"capture it anew", ch.Name)
	}
	key, err := benignKey(root)
	if err != nil {
		return err
	}
	san, err := benign.NewSanitiser(key, nil, nil)
	if err != nil {
		return err
	}
	rec.Session.ApprovedBy = san.Person(by)
	rec.Session.Alone = rec.Session.ApprovedBy == rec.Session.VouchedBy
	switch ch.Action {
	case "approve":
		rec.State = benign.Approved
	case "renew":
		rec.Session.Expires = ch.Expires.UTC()
		rec.Session.Renewals++
		rec.State = benign.Approved
	default:
		return fmt.Errorf("a benign request approves or renews, not %q", ch.Action)
	}
	if err := rec.Session.Check(); err != nil {
		return err
	}
	return saveBenign(root, rec)
}

func benignList(root string) error {
	all, err := listBenign(root)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if w.JSON(map[string]any{"sessions": all}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("  no session has been vouched for as benign\n")
		w.Human("  %saertun benign capture NAME --class C --source S --since T --until T --why \"…\"%s\n", dim, reset)
		return nil
	}
	for _, r := range all {
		s := r.Session
		state := r.State
		if state == benign.Approved && s.Expired(now) {
			state = "expired"
		}
		colour := green
		switch state {
		case benign.Pending:
			colour = yellow
		case benign.Revoked, "expired":
			colour = red
		}
		w.Human("%s%-9s%s %s%s%s  %s, %d event(s), expires %s\n", colour, state, reset, bold, s.Name,
			reset, s.Class, s.Events, s.Expires.Format("2006-01-02"))
	}
	return nil
}

func benignShow(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: aertun benign show NAME")
	}
	r, err := loadBenign(root, args[0])
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"session": r.Session, "state": r.State, "request": r.Request}) {
		return nil
	}
	s := r.Session
	w.Human("%s%s%s  %s, %s\n", bold, s.Name, reset, s.Class, r.State)
	w.Human("  %d event(s) from %s, %s to %s\n", s.Events, strings.Join(s.Sources, ", "),
		s.Since.Format(time.RFC3339), s.Until.Format(time.RFC3339))
	w.Human("  captured %s, expires %s, renewed %d time(s)\n", s.Captured.Format("2006-01-02"),
		s.Expires.Format("2006-01-02"), s.Renewals)
	w.Human("  fields kept: %s\n", strings.Join(s.Fields, ", "))
	if len(s.Dropped) > 0 {
		w.Human("  dropped: %s\n", strings.Join(s.Dropped, ", "))
	}
	if len(s.Transformed) > 0 {
		w.Human("  pseudonymised: %s\n", strings.Join(s.Transformed, ", "))
	}
	if len(s.Raw) > 0 {
		w.Human("  %skept raw on request: %s%s\n", yellow, strings.Join(s.Raw, ", "), reset)
	}
	if len(s.Acknowledged) > 0 {
		w.Human("  fired at capture, acknowledged: %s\n", strings.Join(s.Acknowledged, ", "))
	}
	w.Human("  fidelity: %d rule(s) checked", s.Fidelity.Rules)
	if s.Fidelity.Reduced {
		w.Human(", %sreduced: %s%s", yellow, strings.Join(s.Fidelity.Lost, ", "), reset)
	}
	w.Human("\n")
	return nil
}

func benignRevoke(root string, args []string) error {
	fs := flag.NewFlagSet("benign revoke", flag.ContinueOnError)
	why := fs.String("why", "", "why it is no longer benign")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || strings.TrimSpace(*why) == "" {
		return fmt.Errorf("benign revoke takes NAME --why \"…\"")
	}
	caller := resolveCaller(root, flagToken)
	// Revoking only narrows what a gate accepts, so it is a responder's
	// act and needs nobody else: a session found to be an attack is
	// withdrawn by whoever finds it, at once.
	if err := authorise(root, caller, auth.ActRespond, auth.AreaSecurity); err != nil {
		return err
	}
	r, err := loadBenign(root, pos[0])
	if err != nil {
		return err
	}
	if r.State == benign.Revoked {
		return fmt.Errorf("%s is already revoked", pos[0])
	}
	key, err := benignKey(root)
	if err != nil {
		return err
	}
	san, err := benign.NewSanitiser(key, nil, nil)
	if err != nil {
		return err
	}
	r.State, r.RevokedAt, r.RevokedBy = benign.Revoked, time.Now().UTC(), san.Person(caller.Name)
	if err := saveBenign(root, r); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("benign.revoked", "/benign/"+pos[0], audit.Success,
		map[string]string{"name": pos[0], "why": strings.TrimSpace(*why)})); err != nil {
		return err
	}
	w.Human("%s revoked: no bundle made from now on carries it; a bundle already handed out "+
		"still does, until it is made again\n", pos[0])
	return nil
}

func benignRenew(root string, args []string) error {
	fs := flag.NewFlagSet("benign renew", flag.ContinueOnError)
	why := fs.String("why", "", "why it is still benign")
	life := fs.Duration("expires", benign.DefaultLife, "how long from now it counts: at most 8760h")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || strings.TrimSpace(*why) == "" {
		return fmt.Errorf("benign renew takes NAME --expires DURATION --why \"…\"")
	}
	if *life < time.Hour || *life > benign.MaxLife {
		return fmt.Errorf("--expires is between 1h and 8760h")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	r, err := loadBenign(root, pos[0])
	if err != nil {
		return err
	}
	if r.State != benign.Approved {
		return fmt.Errorf("%s is %s; only an approved session is renewed", pos[0], r.State)
	}
	now := time.Now().UTC()
	if now.Sub(r.Session.Captured) > benign.Recapture {
		return fmt.Errorf("%s was captured %s ago; the estate a year ago is not this one, so it "+
			"is captured again rather than renewed", pos[0], now.Sub(r.Session.Captured).Round(24*time.Hour))
	}
	req, err := proposeBenign(root, caller, dual.BenignChange{Name: pos[0], Action: "renew",
		Expires: now.Add(*life)}, *why)
	if err != nil {
		return err
	}
	w.Human("renewal of %s asked for; a second administrator approves it: aertun pending approve %s\n", pos[0], req)
	return nil
}

func benignBundle(root string, args []string) error {
	fs := flag.NewFlagSet("benign bundle", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file the bundle is signed with")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the bundle")
	var only []string
	fs.Func("session", "only this session (repeat; default: every approved, unexpired one)",
		func(s string) error { only = append(only, s); return nil })
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyAt == "" || *outAt == "" || fs.NArg() != 0 {
		return fmt.Errorf("benign bundle takes --key FILE --out FILE")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	all, err := listBenign(root)
	if err != nil {
		return err
	}
	pick := map[string]bool{}
	for _, n := range only {
		pick[n] = true
	}
	now := time.Now().UTC()
	key, err := benignKey(root)
	if err != nil {
		return err
	}
	m := benign.Manifest{Made: now, Program: version, Policy: benign.PolicyVersion, KeyID: benign.KeyID(key)}
	events := map[string][]telemetry.Event{}
	sets := map[string][]string{}
	var skipped []string
	for _, r := range all {
		if len(pick) > 0 && !pick[r.Session.Name] {
			continue
		}
		if r.State != benign.Approved || r.Session.Expired(now) {
			skipped = append(skipped, r.Session.Name+" ("+r.State+")")
			continue
		}
		m.Sessions = append(m.Sessions, r.Session)
		events[r.Session.Name] = r.Events
		sets[r.Session.Fidelity.Set] = r.FidelityRules
	}
	for n := range pick {
		if _, ok := events[n]; !ok {
			return fmt.Errorf("session %s is not approved and unexpired, so it is not bundled", n)
		}
	}
	if len(m.Sessions) == 0 {
		return fmt.Errorf("no session is approved and unexpired: nothing to bundle")
	}
	for id, rules := range sets {
		m.Sets = append(m.Sets, benign.FidelitySet{ID: id, Rules: rules})
	}
	doc, err := benign.Seal(m, events, k)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
		return err
	}
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	b, err := benign.Open(doc, k.PublicKey())
	if err != nil {
		return fmt.Errorf("the bundle just written does not open: %w", err)
	}
	if err := recordE(root, caller.auditRecord("benign.bundled", "/benign", audit.Success,
		map[string]string{"sessions": fmt.Sprint(len(m.Sessions)), "bundle": b.Digest})); err != nil {
		return err
	}
	if w.JSON(map[string]any{"bundle": b.Digest, "sessions": len(m.Sessions), "skipped": skipped}) {
		return nil
	}
	w.Human("bundled %d session(s) into %s (bundle %s…)\n", len(m.Sessions), *outAt, b.Digest[:16])
	if len(skipped) > 0 {
		w.Human("  %snot bundled: %s%s\n", dim, strings.Join(skipped, ", "), reset)
	}
	return nil
}

func benignVerify(args []string) error {
	fs := flag.NewFlagSet("benign verify", flag.ContinueOnError)
	pubAt := fs.String("public-key", "", "the public key file the bundle's signer published")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *pubAt == "" {
		return fmt.Errorf("benign verify takes FILE --public-key FILE")
	}
	pub, err := pack.LoadPublicKey(*pubAt)
	if err != nil {
		return err
	}
	b, err := benign.Read(pos[0], pub)
	if err != nil {
		return err
	}
	live, expired := b.Live(time.Now().UTC())
	if w.JSON(map[string]any{"bundle": b.Digest, "live": len(live), "expired": len(expired),
		"manifest": b.Manifest}) {
		return nil
	}
	w.Human("both signatures hold; every session's events are the ones its digest names\n")
	w.Human("  %d session(s) count now, %d expired; sanitised by %s\n", len(live), len(expired), b.Manifest.Policy)
	return nil
}
