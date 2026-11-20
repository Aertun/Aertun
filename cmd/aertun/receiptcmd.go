// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/scitt"
)

// `aertun receipt`: the Aertun Evidence Protocol (internal/aep) from the
// command line. A party that saw an agent's action emits a signed receipt
// for it; this deployment registers receipts in its transparency log, which
// answers with a receipt of its own in each algorithm; anyone verifies them
// offline; and a reconciliation over several parties' receipts says, in a
// receipt of its own, whether they agree and where they do not.

const receiptUsage = `usage:
  aertun receipt emit --key F --issuer URI --vantage agent|gateway|target|sandbox --target URI --tool NAME [--args F|-] [--at TIME] [--actor A] [--grant G] [--outcome ok|error|refused] [--seq N] [--alg ed25519|ml-dsa-65] [--public-key F] --out F
  aertun receipt register FILE --issuer-key ISSUER=F... [--log-name URI] [--log-key F] --out F
  aertun receipt verify FILE --issuer-key ISSUER=F... [--log-key F] [--args F] [RECEIPT...]
  aertun receipt reconcile FILE... --key F --issuer URI --from TIME --to TIME --expect ISSUER=VANTAGE... --issuer-key ISSUER=F... [--log-key F] [--tolerance 1s] [--alg ed25519|ml-dsa-65] --out F`

// receiptNow is when statements are signed and registered.
var receiptNow = time.Now

func cmdReceipt(root string, args []string) error {
	if len(args) == 0 {
		return errors.New(receiptUsage)
	}
	switch args[0] {
	case "emit":
		return receiptEmit(args[1:])
	case "register":
		return receiptRegister(root, args[1:])
	case "verify":
		return receiptVerify(args[1:])
	case "reconcile":
		return receiptReconcile(args[1:])
	}
	return fmt.Errorf("unknown receipt command %q\n%s", args[0], receiptUsage)
}

// signerFor is one half of a dual key, as the statement's one algorithm.
func signerFor(k *pack.Key, alg string) (cose.Signer, error) {
	ed, ml, err := receiptlog.Signers(k)
	if err != nil {
		return nil, err
	}
	switch alg {
	case "ed25519":
		return ed, nil
	case "ml-dsa-65":
		return ml, nil
	}
	return nil, fmt.Errorf("--alg is ed25519 or ml-dsa-65, not %q", alg)
}

// readArgs reads a call's arguments from a file, or from standard input
// for "-".
func readArgs(path string) ([]byte, error) {
	if path != "-" {
		return readBounded(path, aep.MaxArgs)
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, aep.MaxArgs+1))
	if err != nil {
		return nil, err
	}
	if len(b) > aep.MaxArgs {
		return nil, fmt.Errorf("the arguments are past %d bytes", aep.MaxArgs)
	}
	return b, nil
}

func writeStatement(path string, b []byte) error {
	if path == "" {
		return errors.New("--out names where the statement goes: it is CBOR, not text for a terminal")
	}
	return atomicfile.Write(path, b, 0o600)
}

func receiptEmit(args []string) error {
	fs := flag.NewFlagSet("receipt emit", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	issuer := fs.String("issuer", "", "who is saying this: the party's own identifier, a URI")
	vantage := fs.String("vantage", "", "where the action was seen from: agent, gateway, target or sandbox")
	target := fs.String("target", "", "the resource the call was for, as its RFC 8707 resource indicator")
	tool := fs.String("tool", "", "the tool or operation called")
	argsAt := fs.String("args", "", "the call's JSON arguments (a file, or - for standard input); none is {}")
	at := fs.String("at", "", "when the action was seen, RFC 3339 (default: now)")
	actor := fs.String("actor", "", "who was seen to act")
	grant := fs.String("grant", "", "the authority seen exercised: a token or delegation identifier")
	outcome := fs.String("outcome", "", "how it ended: ok, error or refused")
	seq := fs.String("seq", "", "this party's own sequence number for the receipt")
	alg := fs.String("alg", "ed25519", "the algorithm: ed25519 or ml-dsa-65")
	pubAt := fs.String("public-key", "", "where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the receipt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyAt == "" || *issuer == "" || *vantage == "" || *target == "" || *tool == "" {
		return errors.New("receipt emit needs --key, --issuer, --vantage, --target and --tool\n" + receiptUsage)
	}
	r := aep.Receipt{Action: aep.Action{Target: *target, Tool: *tool}, Vantage: *vantage,
		Actor: *actor, Grant: *grant, Outcome: *outcome, At: receiptNow()}
	if *at != "" {
		t, err := time.Parse(time.RFC3339Nano, *at)
		if err != nil {
			return fmt.Errorf("--at is an RFC 3339 time: %w", err)
		}
		r.At = t
	}
	if *seq != "" {
		n, err := strconv.ParseUint(*seq, 10, 64)
		if err != nil {
			return fmt.Errorf("--seq is a whole number: %w", err)
		}
		r.Seq, r.HasSeq = n, true
	}
	var body []byte
	if *argsAt != "" {
		var err error
		if body, err = readArgs(*argsAt); err != nil {
			return err
		}
	}
	d, err := aep.ArgsDigest(body)
	if err != nil {
		return err
	}
	r.Args = d
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	s, err := signerFor(k, *alg)
	if err != nil {
		return err
	}
	b, err := aep.Emit(s, *issuer, r, receiptNow())
	if err != nil {
		return err
	}
	if err := writeStatement(*outAt, b); err != nil {
		return err
	}
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	_, back, err := aep.ReadReceipt(b)
	if err != nil {
		return err
	}
	if !w.JSON(receiptSummary(*issuer, back)) {
		w.Human("receipt for %s %s seen by %s at %s\naction %x\n", back.Tool, back.Target, back.Vantage,
			back.At.Format(time.RFC3339Nano), back.Digest)
	}
	return nil
}

func receiptSummary(issuer string, r aep.Receipt) map[string]any {
	out := map[string]any{"kind": "action", "issuer": issuer, "action": hex.EncodeToString(r.Digest[:]),
		"target": r.Target, "tool": r.Tool, "args": hex.EncodeToString(r.Args[:]), "vantage": r.Vantage,
		"at": r.At.Format(time.RFC3339Nano)}
	for k, v := range map[string]string{"actor": r.Actor, "grant": r.Grant, "outcome": r.Outcome} {
		if v != "" {
			out[k] = v
		}
	}
	if r.HasSeq {
		out["seq"] = r.Seq
	}
	return out
}

// issuerKeys reads --issuer-key ISSUER=FILE values: the parties trusted to
// speak for themselves, each with its published dual key.
func issuerKeys(vals []string) (map[string]pack.KeyPublic, error) {
	out := map[string]pack.KeyPublic{}
	for _, v := range vals {
		iss, path, ok := strings.Cut(v, "=")
		if !ok || iss == "" || path == "" {
			return nil, fmt.Errorf("--issuer-key is ISSUER=FILE, not %q", v)
		}
		if _, dup := out[iss]; dup {
			return nil, fmt.Errorf("%s has two keys", iss)
		}
		pub, err := pack.LoadPublicKey(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", iss, err)
		}
		out[iss] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("--issuer-key ISSUER=FILE names whose statements are trusted, and with which key")
	}
	return out, nil
}

// checkStatement verifies a statement with the half of its issuer's key
// the statement names, refusing an issuer not trusted.
func checkStatement(s *scitt.Signed, keys map[string]pack.KeyPublic) error {
	pub, ok := keys[s.Issuer]
	if !ok {
		return fmt.Errorf("the statement is from %s, whose key was not given", s.Issuer)
	}
	ed, ml, err := receiptlog.Verifiers(pub)
	if err != nil {
		return err
	}
	alg, err := s.Message.Algorithm()
	if err != nil {
		return err
	}
	var v cose.Verifier = ed
	if ml.Accepts(alg) {
		v = ml
	}
	if err := s.Verify(v); err != nil {
		return fmt.Errorf("%s: %w", s.Issuer, err)
	}
	return nil
}

func receiptRegister(root string, args []string) error {
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet("receipt register", flag.ContinueOnError)
	var trusted multiFlag
	fs.Var(&trusted, "issuer-key", "ISSUER=FILE: a party whose statements this log admits, and its published key")
	logName := fs.String("log-name", "", "the log's name in its receipts, a URI; needed the first time only")
	logKeyAt := fs.String("log-key", "", "where to write the log's public key, which verifiers of its receipts need")
	outAt := fs.String("out", "", "where to write the statement with the log's receipts attached")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if len(pos) != 1 || fs.NArg() != 0 {
		return errors.New("receipt register takes one statement\n" + receiptUsage)
	}
	keys, err := issuerKeys(trusted)
	if err != nil {
		return err
	}
	statement, err := readBounded(pos[0], cose.MaxMessage)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Tune, like a proof signed from the store: the log's receipts are
	// signed in this deployment's name.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	l, err := receiptlog.Open(filepath.Join(root, "receipts"), *logName)
	if err != nil {
		return err
	}
	tr, err := l.Register(statement, func(s *scitt.Signed) error { return checkStatement(s, keys) }, receiptNow())
	if err != nil {
		return err
	}
	s, err := scitt.Read(tr)
	if err != nil {
		return err
	}
	in, err := receiptlog.VerifyReceipts(s, l.PublicKey())
	if err != nil {
		return err
	}
	if err := writeStatement(*outAt, tr); err != nil {
		return err
	}
	if *logKeyAt != "" {
		if err := pack.WritePublicKey(*logKeyAt, l.PublicKey()); err != nil {
			return err
		}
	}
	if err := recordE(root, caller.auditRecord("receipt.registered", "/receipts/"+strconv.FormatUint(in[0].Index, 10),
		audit.Success, map[string]string{"issuer": s.Issuer, "subject": s.Subject,
			"size": strconv.FormatUint(in[0].Size, 10)})); err != nil {
		return err
	}
	if !w.JSON(map[string]any{"log": l.Issuer(), "index": in[0].Index, "size": in[0].Size,
		"root": hex.EncodeToString(in[0].Root), "issuer": s.Issuer, "subject": s.Subject}) {
		w.Human("registered in %s at %d of %d, with a receipt in each algorithm\n", l.Issuer(), in[0].Index, in[0].Size)
	}
	return nil
}

// readTrusted reads a statement, checks its signature with its issuer's
// key, and with a log key also requires the log's two receipts.
func readTrusted(path string, keys map[string]pack.KeyPublic, logKey *pack.KeyPublic) (*scitt.Signed, []byte, []scitt.Inclusion, error) {
	b, err := readBounded(path, cose.MaxMessage)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := scitt.Read(b)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := checkStatement(s, keys); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	var in []scitt.Inclusion
	if logKey != nil {
		if in, err = receiptlog.VerifyReceipts(s, *logKey); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return s, b, in, nil
}

func loadLogKey(path string) (*pack.KeyPublic, error) {
	if path == "" {
		return nil, nil
	}
	pub, err := pack.LoadPublicKey(path)
	if err != nil {
		return nil, err
	}
	return &pub, nil
}

func receiptVerify(args []string) error {
	pos, rest := leadingArgs(args, len(args))
	fs := flag.NewFlagSet("receipt verify", flag.ContinueOnError)
	var trusted multiFlag
	fs.Var(&trusted, "issuer-key", "ISSUER=FILE: a party trusted to speak for itself, and its published key")
	logKeyAt := fs.String("log-key", "", "the log's public key: then both of its receipts are required")
	argsAt := fs.String("args", "", "the call's JSON arguments, to check the receipt is about them")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	files := append(pos, fs.Args()...)
	if len(files) == 0 {
		return errors.New("receipt verify takes a statement, and for a reconciliation the receipts it reconciled\n" + receiptUsage)
	}
	keys, err := issuerKeys(trusted)
	if err != nil {
		return err
	}
	logKey, err := loadLogKey(*logKeyAt)
	if err != nil {
		return err
	}
	s, b, in, err := readTrusted(files[0], keys, logKey)
	if err != nil {
		return err
	}
	summary := map[string]any{}
	switch s.ContentType {
	case aep.ContentAction:
		if len(files) != 1 {
			return errors.New("an action receipt is verified on its own")
		}
		_, r, err := aep.ReadReceipt(b)
		if err != nil {
			return err
		}
		if *argsAt != "" {
			body, err := readArgs(*argsAt)
			if err != nil {
				return err
			}
			d, err := aep.ArgsDigest(body)
			if err != nil {
				return err
			}
			if d != r.Args {
				return errors.New("the receipt is not about these arguments")
			}
		}
		summary = receiptSummary(s.Issuer, r)
	case aep.ContentReconciliation:
		if *argsAt != "" {
			return errors.New("--args is for an action receipt")
		}
		inputs, err := reconcileInputs(files[1:], keys, logKey)
		if err != nil {
			return err
		}
		res, err := aep.CheckReconciliation(b, inputs)
		if err != nil {
			return err
		}
		summary = reconcileSummary(s.Issuer, res)
	default:
		return fmt.Errorf("the statement is %q, which is not one this verifies", s.ContentType)
	}
	if len(in) > 0 {
		summary["log"] = in[0].Issuer
		summary["index"] = in[0].Index
		summary["size"] = in[0].Size
		summary["root"] = hex.EncodeToString(in[0].Root)
	}
	if !w.JSON(summary) {
		w.Human("verified: %s from %s", summary["kind"], s.Issuer)
		if len(in) > 0 {
			w.Human(", in %s at %d of %d (Ed25519 and ML-DSA-65 receipts)", in[0].Issuer, in[0].Index, in[0].Size)
		}
		w.Human("\n")
	}
	return nil
}

// reconcileInputs reads action receipts, each checked against its issuer.
func reconcileInputs(paths []string, keys map[string]pack.KeyPublic, logKey *pack.KeyPublic) ([]aep.Input, error) {
	var out []aep.Input
	for _, p := range paths {
		s, b, _, err := readTrusted(p, keys, logKey)
		if err != nil {
			return nil, err
		}
		_, r, err := aep.ReadReceipt(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		entry, err := s.Entry()
		if err != nil {
			return nil, err
		}
		out = append(out, aep.Input{Issuer: s.Issuer, Entry: entry, Receipt: r})
	}
	return out, nil
}

func reconcileSummary(issuer string, r aep.Result) map[string]any {
	gaps := []map[string]any{}
	for _, g := range r.Gaps {
		gaps = append(gaps, map[string]any{"action": hex.EncodeToString(g.Action[:]), "tool": g.Tool,
			"at": g.At.Format(time.RFC3339Nano), "seen_by": g.SeenBy, "missing": g.Missing})
	}
	seq := []map[string]any{}
	for _, g := range r.SeqGaps {
		seq = append(seq, map[string]any{"issuer": g.Issuer, "missing": g.Missing, "repeated": g.Repeated})
	}
	actors := []map[string]any{}
	for _, a := range r.Actors {
		actors = append(actors, map[string]any{"action": hex.EncodeToString(a.Action[:]),
			"at": a.At.Format(time.RFC3339Nano), "actors": a.Actors})
	}
	return map[string]any{"kind": "reconciliation", "issuer": issuer, "verdict": r.Verdict,
		"from": r.From.Format(time.RFC3339Nano), "to": r.To.Format(time.RFC3339Nano),
		"tolerance": r.Tolerance.String(), "receipts": r.Receipts, "actions": r.Actions, "complete": r.Complete,
		"gaps": gaps, "gaps_total": r.GapsTotal, "seq_gaps": seq, "actor_splits": actors,
		"actor_splits_total": r.ActorsTotal, "inputs": hex.EncodeToString(r.Inputs[:])}
}

func receiptReconcile(args []string) error {
	fs := flag.NewFlagSet("receipt reconcile", flag.ContinueOnError)
	keyAt := fs.String("key", "", "the dual signing key file the reconciliation is signed with")
	issuer := fs.String("issuer", "", "who is reconciling: this party's identifier, a URI")
	from := fs.String("from", "", "the window's start, RFC 3339")
	to := fs.String("to", "", "the window's end, RFC 3339")
	tolerance := fs.Duration("tolerance", time.Second, "how far apart two parties' times for one action may be, at most 1m")
	var expect, trusted multiFlag
	fs.Var(&expect, "expect", "ISSUER=VANTAGE: a party every action should have been seen by")
	fs.Var(&trusted, "issuer-key", "ISSUER=FILE: each expected party's published key")
	logKeyAt := fs.String("log-key", "", "a log's public key: then every receipt must carry both of its receipts")
	alg := fs.String("alg", "ed25519", "the algorithm: ed25519 or ml-dsa-65")
	outAt := fs.String("out", "", "where to write the reconciliation receipt")
	pos, rest := leadingArgs(args, len(args))
	if err := fs.Parse(rest); err != nil {
		return err
	}
	files := append(pos, fs.Args()...)
	if *keyAt == "" || *issuer == "" || *from == "" || *to == "" || len(expect) == 0 {
		return errors.New("receipt reconcile needs --key, --issuer, --from, --to and --expect\n" + receiptUsage)
	}
	win := aep.Window{Tolerance: *tolerance}
	var err error
	if win.From, err = time.Parse(time.RFC3339Nano, *from); err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	if win.To, err = time.Parse(time.RFC3339Nano, *to); err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	for _, e := range expect {
		iss, v, ok := strings.Cut(e, "=")
		if !ok {
			return fmt.Errorf("--expect is ISSUER=VANTAGE, not %q", e)
		}
		win.Expect = append(win.Expect, aep.Expect{Issuer: iss, Vantage: v})
	}
	keys, err := issuerKeys(trusted)
	if err != nil {
		return err
	}
	logKey, err := loadLogKey(*logKeyAt)
	if err != nil {
		return err
	}
	inputs, err := reconcileInputs(files, keys, logKey)
	if err != nil {
		return err
	}
	res, err := aep.Reconcile(inputs, win)
	if err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	s, err := signerFor(k, *alg)
	if err != nil {
		return err
	}
	b, err := aep.IssueReconciliation(s, *issuer, res, receiptNow())
	if err != nil {
		return err
	}
	if err := writeStatement(*outAt, b); err != nil {
		return err
	}
	if !w.JSON(reconcileSummary(*issuer, res)) {
		w.Human("%s: %d actions from %d receipts, %d seen by every party, %d not\n", res.Verdict,
			res.Actions, res.Receipts, res.Complete, res.GapsTotal)
		for _, g := range res.Gaps {
			w.Human("  %s %s seen by %s, not by %s\n", g.At.Format(time.RFC3339Nano), g.Tool,
				strings.Join(g.SeenBy, ", "), strings.Join(g.Missing, ", "))
		}
		for _, g := range res.SeqGaps {
			w.Human("  %s: sequence numbers missing %v, used twice %v\n", g.Issuer, g.Missing, g.Repeated)
		}
		for _, a := range res.Actors {
			w.Human("  %s: the parties name different actors %v\n", a.At.Format(time.RFC3339Nano), a.Actors)
		}
	}
	if res.Verdict != aep.Agree {
		return fmt.Errorf("the verdict is %s, and only agree passes", res.Verdict)
	}
	return nil
}
