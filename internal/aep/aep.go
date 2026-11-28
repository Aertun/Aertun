// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package aep is the Aertun Evidence Protocol, version 1: a profile of
// SCITT (RFC 9943) in which every party that sees an AI agent's action says
// so in a signed statement, and a reconciliation of those statements says,
// in another, whether they agree and where they do not.
//
// # The action digest
//
// The agent that calls a tool, the gateway that forwards the call and the
// server that carries it out each see the same three things: the resource
// the call was for (the RFC 8707 resource indicator an MCP client already
// names), the tool or operation, and the arguments. The action digest is
// SHA-256 over those three in deterministic CBOR, with the arguments as the
// SHA-256 of their RFC 8785 canonical JSON, so every party computes it
// alike from what it saw and receipts from different parties can be put
// side by side. Who acted, under what grant and when are not in it: they
// are what each party reports, and what the reconciliation compares.
//
// # Receipts
//
// An action receipt is a signed statement whose issuer is the party, whose
// subject is "aep:action:" and the digest in hex, and whose payload is a
// CBOR map with text keys: the digest and its inputs, the vantage point
// (agent, gateway, target or sandbox), when it was seen, and optionally the
// actor, the grant, the outcome and the party's own sequence number. A
// reader recomputes the digest from the inputs and refuses a receipt whose
// digest or subject does not match, and refuses keys it does not know: a
// change of meaning is a new version, never a new key read by some
// readers and not others.
//
// # Reconciliation
//
// Given the receipts of a window and the parties expected to have seen
// every action, the reconciliation groups receipts into actions (the same
// digest, one receipt per party, within a tolerance of the first) and
// names every action some expected party did not report, every gap in a
// party's sequence numbers, every number a party used twice, and every
// action the parties disagree about the actor of. A party that reported
// nothing at all is still expected, which is the point: silence is a gap,
// not an absence of evidence. The result is deterministic in its inputs, so
// anyone holding the same receipts recomputes the same reconciliation
// receipt, byte for byte.
package aep

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aertun/aertun/internal/cbor"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/scitt"
)

// Content types of the two statements.
const (
	ContentAction         = "application/vnd.aertun.aep.action+cbor"
	ContentReconciliation = "application/vnd.aertun.aep.reconciliation+cbor"
)

// Version is the profile version every payload carries.
const Version = 1

// digestDomain separates the action digest from every other SHA-256 over
// CBOR, and names its version.
const digestDomain = "AEP-Action-v1"

// Vantages are the points an action is seen from.
var Vantages = []string{"agent", "gateway", "target", "sandbox"}

// Outcomes are what a party saw become of an action.
var Outcomes = []string{"ok", "error", "refused"}

// MaxName bounds a target, tool, actor or grant.
const MaxName = 2048

// MaxArgs bounds the arguments read to digest them.
const MaxArgs = 1 << 20

// MaxListed bounds each list a reconciliation names; the totals are kept.
const MaxListed = 200

// Action is what every party to a call sees alike.
type Action struct {
	// Target is the resource the call was for: an RFC 8707 resource
	// indicator, such as an MCP server's URL.
	Target string
	// Tool is the tool or operation called.
	Tool string
	// Args is ArgsDigest of the call's arguments.
	Args [32]byte
}

// ArgsDigest is SHA-256 over the RFC 8785 form of a call's JSON arguments.
// No arguments are the empty object, as MCP treats them.
func ArgsDigest(js []byte) ([32]byte, error) {
	if len(js) > MaxArgs {
		return [32]byte{}, fmt.Errorf("arguments are at most %d bytes", MaxArgs)
	}
	if len(bytes.TrimSpace(js)) == 0 {
		js = []byte("{}")
	}
	c, err := jcs.Canonicalize(js)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the arguments: %w", err)
	}
	return sha256.Sum256(c), nil
}

// Digest is the action digest.
func (a Action) Digest() ([32]byte, error) {
	if err := name("target", a.Target, true); err != nil {
		return [32]byte{}, err
	}
	if err := name("tool", a.Tool, true); err != nil {
		return [32]byte{}, err
	}
	b, err := cbor.Encode(cbor.Array{cbor.Text(digestDomain), cbor.Text(a.Target), cbor.Text(a.Tool), cbor.Bytes(a.Args[:])})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func name(what, v string, required bool) error {
	if v == "" && !required {
		return nil
	}
	if v == "" || len(v) > MaxName || !utf8.ValidString(v) || strings.ContainsFunc(v, isControl) {
		return fmt.Errorf("the %s is 1 to %d bytes of text with no control characters", what, MaxName)
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// Subject is the statement subject for an action digest.
func Subject(digest [32]byte) string { return "aep:action:" + hex.EncodeToString(digest[:]) }

// Receipt is one party's account of one action.
type Receipt struct {
	Action
	// Digest is the action digest, computed when the receipt is made or read.
	Digest  [32]byte
	Vantage string
	// At is when the party saw the action.
	At time.Time
	// Actor and Grant are who the party saw act and under what authority,
	// when it saw them.
	Actor string
	Grant string
	// Outcome is ok, error or refused; empty when the party did not see
	// how it ended.
	Outcome string
	// Seq is the party's own sequence number for its receipts, when it
	// keeps one; HasSeq says it does.
	Seq    uint64
	HasSeq bool
}

// Check reports whether r is a receipt Emit would sign, without signing
// it: for a party that must refuse an action it could not receipt before
// the action happens, not after.
func (r Receipt) Check() error { return r.check() }

func (r *Receipt) check() error {
	d, err := r.Action.Digest()
	if err != nil {
		return err
	}
	r.Digest = d
	if !slices.Contains(Vantages, r.Vantage) {
		return fmt.Errorf("the vantage is one of %s", strings.Join(Vantages, ", "))
	}
	if r.Outcome != "" && !slices.Contains(Outcomes, r.Outcome) {
		return fmt.Errorf("the outcome is one of %s", strings.Join(Outcomes, ", "))
	}
	if r.At.IsZero() {
		return errors.New("a receipt says when the action was seen")
	}
	if err := name("actor", r.Actor, false); err != nil {
		return err
	}
	return name("grant", r.Grant, false)
}

func instant(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseInstant(what, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !strings.HasSuffix(s, "Z") || instant(t) != s {
		return time.Time{}, fmt.Errorf("%s is an RFC 3339 time in UTC, written as %s", what, instant(time.Unix(0, 0)))
	}
	return t.UTC(), nil
}

// Emit signs a receipt as a SCITT statement from the issuer.
func Emit(s cose.Signer, issuer string, r Receipt, now time.Time) ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	p := cbor.Map{
		{Key: cbor.Text("v"), Value: cbor.Uint(Version)},
		{Key: cbor.Text("action"), Value: cbor.Bytes(r.Digest[:])},
		{Key: cbor.Text("target"), Value: cbor.Text(r.Target)},
		{Key: cbor.Text("tool"), Value: cbor.Text(r.Tool)},
		{Key: cbor.Text("args"), Value: cbor.Bytes(r.Args[:])},
		{Key: cbor.Text("vantage"), Value: cbor.Text(r.Vantage)},
		{Key: cbor.Text("at"), Value: cbor.Text(instant(r.At))},
	}
	for _, kv := range [][2]string{{"actor", r.Actor}, {"grant", r.Grant}, {"outcome", r.Outcome}} {
		if kv[1] != "" {
			p = append(p, cbor.Entry{Key: cbor.Text(kv[0]), Value: cbor.Text(kv[1])})
		}
	}
	if r.HasSeq {
		p = append(p, cbor.Entry{Key: cbor.Text("seq"), Value: cbor.Uint(r.Seq)})
	}
	payload, err := cbor.Encode(p)
	if err != nil {
		return nil, err
	}
	return scitt.Sign(s, scitt.Statement{Issuer: issuer, Subject: Subject(r.Digest), IssuedAt: now,
		ContentType: ContentAction, Payload: payload})
}

// fields reads a payload map with text keys, refusing a key it is not
// given and one of the required keys missing.
func fields(payload []byte, known, required []string) (map[string]cbor.Value, error) {
	if payload == nil {
		return nil, errors.New("the payload is detached; an AEP statement carries its own")
	}
	v, err := cbor.Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("the payload: %w", err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, errors.New("the payload is not a map")
	}
	out := map[string]cbor.Value{}
	for _, en := range m {
		k, ok := en.Key.(cbor.Text)
		if !ok || !slices.Contains(known, string(k)) {
			return nil, fmt.Errorf("the payload has a key %v this version does not define", en.Key)
		}
		out[string(k)] = en.Value
	}
	for _, k := range required {
		if _, ok := out[k]; !ok {
			return nil, fmt.Errorf("the payload has no %q", k)
		}
	}
	if n, ok := cbor.AsInt(out["v"]); !ok || n != Version {
		return nil, fmt.Errorf("the payload is not version %d", Version)
	}
	return out, nil
}

func text(f map[string]cbor.Value, k string) (string, error) {
	v, ok := f[k]
	if !ok {
		return "", nil
	}
	t, ok := v.(cbor.Text)
	if !ok {
		return "", fmt.Errorf("%q is not text", k)
	}
	return string(t), nil
}

func digest32(f map[string]cbor.Value, k string) ([32]byte, error) {
	b, ok := f[k].(cbor.Bytes)
	if !ok || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("%q is not 32 bytes", k)
	}
	return [32]byte(b), nil
}

// ReadReceipt reads an action receipt, checking its shape and that its
// digest and subject are its inputs'; it does not check the signature.
func ReadReceipt(b []byte) (*scitt.Signed, Receipt, error) {
	var r Receipt
	s, err := scitt.Read(b)
	if err != nil {
		return nil, r, err
	}
	if s.ContentType != ContentAction {
		return nil, r, fmt.Errorf("the statement is %q, not an action receipt", s.ContentType)
	}
	f, err := fields(s.Message.Payload, []string{"v", "action", "target", "tool", "args", "vantage", "at",
		"actor", "grant", "outcome", "seq"}, []string{"v", "action", "target", "tool", "args", "vantage", "at"})
	if err != nil {
		return nil, r, err
	}
	stated, err := digest32(f, "action")
	if err != nil {
		return nil, r, err
	}
	if r.Args, err = digest32(f, "args"); err != nil {
		return nil, r, err
	}
	var at string
	for k, dst := range map[string]*string{"target": &r.Target, "tool": &r.Tool, "vantage": &r.Vantage,
		"at": &at, "actor": &r.Actor, "grant": &r.Grant, "outcome": &r.Outcome} {
		if *dst, err = text(f, k); err != nil {
			return nil, r, err
		}
	}
	if r.At, err = parseInstant("at", at); err != nil {
		return nil, r, err
	}
	if v, ok := f["seq"]; ok {
		n, ok := v.(cbor.Uint)
		if !ok {
			return nil, r, errors.New(`"seq" is not an unsigned integer`)
		}
		r.Seq, r.HasSeq = uint64(n), true
	}
	if err := r.check(); err != nil {
		return nil, r, err
	}
	if r.Digest != stated {
		return nil, r, errors.New("the receipt's action digest is not the digest of its own target, tool and arguments")
	}
	if s.Subject != Subject(r.Digest) {
		return nil, r, errors.New("the statement's subject is not its action digest")
	}
	return s, r, nil
}
