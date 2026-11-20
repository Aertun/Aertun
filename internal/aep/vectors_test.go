// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package aep

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/cbor"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/scitt"
	"github.com/aertun/aertun/internal/translog"
)

// update rewrites the published vectors from the generator below. Without
// it, the generator must reproduce them byte for byte: both algorithms
// sign deterministically, so a vector that changes is a protocol that
// changed, and that is a decision, not a side effect.
var update = flag.Bool("update", false, "rewrite spec/aep/v1/vectors")

const vectorDir = "../../spec/aep/v1/vectors"

type vkey struct {
	s   cose.Signer
	key Key
}

func edKey(t *testing.T, seed byte) vkey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	s, err := cose.NewEd25519Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	return vkey{s, Key{Alg: cose.AlgEd25519, Public: hex.EncodeToString(priv.Public().(ed25519.PublicKey))}}
}

func mlKey(t *testing.T, seed byte) vkey {
	t.Helper()
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := cose.NewMLDSA65Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	return vkey{s, Key{Alg: cose.AlgMLDSA65, Public: hex.EncodeToString(priv.PublicKey().Bytes())}}
}

const (
	vAgent   = "https://agent.example"
	vGateway = "https://gateway.example"
	vTarget  = "https://mcp.example/mcp"
	vLog     = "https://log.example"
	vAuditor = "https://auditor.example"
)

var v0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// generate builds every vector from fixed keys and times.
func generate(t *testing.T) []Vector {
	t.Helper()
	agent, gateway, target := edKey(t, 0x11), mlKey(t, 0x22), edKey(t, 0x33)
	logEd, logML, auditor := edKey(t, 0x44), mlKey(t, 0x55), edKey(t, 0x66)
	keys := map[string]Key{vAgent: agent.key, vGateway: gateway.key, vTarget: target.key, vAuditor: auditor.key}
	logKeys := []Key{logEd.key, logML.key}
	const transfer = `{"amount":100,"to":"acct-7"}`
	h := func(b []byte) string { return hex.EncodeToString(b) }

	emitOne := func(k vkey, issuer, vantage, tool, args string, at time.Time, seq uint64) []byte {
		d, err := ArgsDigest([]byte(args))
		if err != nil {
			t.Fatal(err)
		}
		b, err := Emit(k.s, issuer, Receipt{Action: Action{Target: vTarget, Tool: tool, Args: d}, Vantage: vantage,
			At: at, Actor: "agent-7", Grant: "grant-1", Outcome: "ok", Seq: seq, HasSeq: true}, at)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	agentR := emitOne(agent, vAgent, "agent", "transfer_funds", transfer, v0, 0)
	gatewayR := emitOne(gateway, vGateway, "gateway", "transfer_funds", transfer, v0.Add(20*time.Millisecond), 0)
	targetR := emitOne(target, vTarget, "target", "transfer_funds", transfer, v0.Add(45*time.Millisecond), 0)
	onlyAgent := emitOne(agent, vAgent, "agent", "send_email", `{"to":"boss@example.com"}`, v0.Add(time.Minute), 1)

	log := translog.New()
	for _, e := range [][]byte{agentR, gatewayR, targetR} {
		log.Append(e)
	}
	receipt := func(k vkey, entry []byte, index int) []byte {
		r, err := scitt.IssueReceipt(k.s, vLog, "receipt", log, entry, index, 3, v0.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	attach := func(st []byte, rs ...[]byte) []byte {
		b, err := scitt.Attach(st, rs...)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	transparent := attach(targetR, receipt(logEd, targetR, 2), receipt(logML, targetR, 2))

	win := Window{From: v0.Add(-time.Minute), To: v0.Add(time.Hour), Tolerance: time.Second,
		Expect: []Expect{{vAgent, "agent"}, {vGateway, "gateway"}, {vTarget, "target"}}}
	reconcile := func(stmts ...[]byte) Result {
		var in []Input
		for _, b := range stmts {
			s, r, err := ReadReceipt(b)
			if err != nil {
				t.Fatal(err)
			}
			entry, _ := s.Entry()
			in = append(in, Input{Issuer: s.Issuer, Entry: entry, Receipt: r})
		}
		res, err := Reconcile(in, win)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	issue := func(res Result) []byte {
		b, err := IssueReconciliation(auditor.s, vAuditor, res, v0.Add(2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	agree := issue(reconcile(agentR, gatewayR, transparent))
	disagreeRes := reconcile(agentR, gatewayR, transparent, onlyAgent)
	disagree := issue(disagreeRes)
	lie := disagreeRes
	lie.Verdict, lie.Gaps, lie.GapsTotal, lie.Complete = Agree, nil, 0, lie.Actions
	lieB := issue(lie)

	// Statements that are wrong in one way each, signed properly.
	signPayload := func(k vkey, issuer, sub string, p cbor.Map, header cbor.Map) []byte {
		payload, err := cbor.Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		if header == nil {
			b, err := scitt.Sign(k.s, scitt.Statement{Issuer: issuer, Subject: sub, IssuedAt: v0,
				ContentType: ContentAction, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		m, err := cose.Sign(k.s, header, payload, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.Encode()
		return b
	}
	_, base, _ := ReadReceipt(agentR)
	payload := func(extra ...cbor.Entry) cbor.Map {
		m := cbor.Map{{Key: cbor.Text("v"), Value: cbor.Uint(1)},
			{Key: cbor.Text("action"), Value: cbor.Bytes(base.Digest[:])},
			{Key: cbor.Text("target"), Value: cbor.Text(base.Target)},
			{Key: cbor.Text("tool"), Value: cbor.Text(base.Tool)},
			{Key: cbor.Text("args"), Value: cbor.Bytes(base.Args[:])},
			{Key: cbor.Text("vantage"), Value: cbor.Text("agent")},
			{Key: cbor.Text("at"), Value: cbor.Text("2026-11-20T12:00:00Z")}}
		return append(m, extra...)
	}
	otherTool := payload()
	otherTool[3].Value = cbor.Text("read_balance")
	digestMismatch := signPayload(agent, vAgent, Subject(base.Digest), otherTool, nil)
	unknownKey := signPayload(agent, vAgent, Subject(base.Digest), payload(cbor.Entry{Key: cbor.Text("note"), Value: cbor.Text("x")}), nil)
	crit := signPayload(agent, vAgent, "", payload(), cbor.Map{
		{Key: cbor.Int(cose.LabelCrit), Value: cbor.Array{cbor.Int(-70000)}},
		{Key: cbor.Int(-70000), Value: cbor.Bool(true)},
		{Key: cbor.Int(cose.LabelContentType), Value: cbor.Text(ContentAction)},
		{Key: cbor.Int(cose.LabelCWTClaims), Value: cbor.Map{{Key: cbor.Int(1), Value: cbor.Text(vAgent)},
			{Key: cbor.Int(2), Value: cbor.Text(Subject(base.Digest))}}}})
	badSig := bytes.Clone(agentR)
	badSig[len(badSig)-1] ^= 1
	edOnly := attach(targetR, receipt(logEd, targetR, 2))
	wrongEntry := attach(targetR, receipt(logEd, gatewayR, 1), receipt(logML, gatewayR, 1))

	ad, _ := ArgsDigest([]byte(transfer))
	dd, _ := Action{Target: vTarget, Tool: "transfer_funds", Args: ad}.Digest()
	st := func(name, desc string, b []byte, valid bool, reason string) Vector {
		return Vector{Name: name, Description: desc, Kind: "statement", Statement: h(b), IssuerKeys: keys,
			Valid: valid, Reason: reason}
	}
	withLog := func(v Vector) Vector { v.LogKeys = logKeys; return v }
	withArgs := func(v Vector, a string) Vector { v.Args = a; return v }
	recon := func(v Vector, verdict string, in ...[]byte) Vector {
		v.Verdict = verdict
		for _, b := range in {
			v.Inputs = append(v.Inputs, h(b))
		}
		return v
	}
	return []Vector{
		{Name: "digest", Description: "The action digest of a call: SHA-256 over the deterministic CBOR array " +
			`["AEP-Action-v1", target, tool, SHA-256(RFC 8785 JSON of the arguments)]. The arguments are given ` +
			"with whitespace and member order a canonicaliser removes.", Kind: "digest", Target: vTarget,
			Tool: "transfer_funds", Args: ` { "to" : "acct-7", "amount" : 1.00E2 } `, ArgsDigest: h(ad[:]),
			Digest: h(dd[:]), Valid: true},
		withArgs(st("receipt-agent-ed25519", "The agent's receipt for the call, signed with Ed25519 (-19), "+
			"checked against the call's arguments.", agentR, true, ""), transfer),
		st("receipt-gateway-mldsa65", "The gateway's receipt for the same call, signed with ML-DSA-65 (-49).",
			gatewayR, true, ""),
		withLog(st("receipt-target-transparent", "The target's receipt with the log's two RFC 9942 receipts, "+
			"Ed25519 and ML-DSA-65, for entry 2 of a tree of 3; both are required.", transparent, true, "")),
		recon(st("reconciliation-agree", "A reconciliation over the three receipts: one action, seen by "+
			"every party.", agree, true, ""), Agree, agentR, gatewayR, transparent),
		recon(st("reconciliation-disagree", "A reconciliation over the three receipts and an action only "+
			"the agent reported: the statement is valid, and its verdict is disagree.", disagree, true, ""),
			Disagree, agentR, gatewayR, transparent, onlyAgent),
		st("bad-signature", "The agent's receipt with the last byte of its signature changed.", badSig,
			false, "the signature does not verify"),
		st("digest-mismatch", "A receipt whose stated action digest is not the digest of its own target, "+
			"tool and arguments, signed properly.", digestMismatch, false, "the digest is not its inputs'"),
		st("unknown-payload-key", "A receipt with a payload key version 1 does not define.", unknownKey,
			false, "a key this version does not define"),
		st("critical-header", "A receipt whose protected header marks an unknown label critical.", crit,
			false, "a critical header is not processed"),
		withArgs(st("other-arguments", "The agent's receipt, held to arguments it is not about.", agentR,
			false, "the arguments differ"), `{"amount":100,"to":"acct-8"}`),
		withLog(st("one-log-receipt", "The target's receipt with only the log's Ed25519 receipt.", edOnly,
			false, "a receipt in each of the log's algorithms is required")),
		withLog(st("receipt-for-another-entry", "The target's receipt carrying the log's receipts for the "+
			"gateway's entry.", wrongEntry, false, "the root its proof leads to from this entry is not the one the log signed")),
		recon(st("reconciliation-false-agreement", "A reconciliation stating agreement over receipts that "+
			"disagree, signed properly.", lieB, false, "recomputing it gives another result"), Agree,
			agentR, gatewayR, transparent, onlyAgent),
		{Name: "unknown-issuer", Description: "The gateway's receipt, with only the agent's key given.",
			Kind: "statement", Statement: h(gatewayR), IssuerKeys: map[string]Key{vAgent: agent.key},
			Valid: false, Reason: "the issuer's key is not given"},
	}
}

// refusedFor is what this verifier says about each invalid vector.
var refusedFor = map[string]string{
	"bad-signature":                  "signature does not verify",
	"digest-mismatch":                "not the digest of its own target",
	"unknown-payload-key":            "this version does not define",
	"critical-header":                "critical",
	"other-arguments":                "not about these arguments",
	"one-log-receipt":                "one is required in each",
	"receipt-for-another-entry":      "signature does not verify",
	"reconciliation-false-agreement": "reconcile to something other",
	"unknown-issuer":                 "no key is given",
}

func TestVectors(t *testing.T) {
	vectors := generate(t)
	if *update {
		if err := os.MkdirAll(vectorDir, 0o755); err != nil {
			t.Fatal(err)
		}
		old, _ := filepath.Glob(filepath.Join(vectorDir, "*.json"))
		for _, f := range old {
			os.Remove(f)
		}
	}
	for i, v := range vectors {
		err := CheckVector(v)
		if v.Valid && err != nil {
			t.Errorf("%s is valid and was refused: %v", v.Name, err)
		}
		if !v.Valid && err == nil {
			t.Errorf("%s is invalid and was accepted", v.Name)
		}
		// Each invalid vector is refused for its own reason, not by accident.
		if want, ok := refusedFor[v.Name]; ok && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: refused with %v, not for %q", v.Name, err, want)
		} else if !ok && !v.Valid {
			t.Errorf("%s: no reason pinned in refusedFor", v.Name)
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		path := filepath.Join(vectorDir, fmt.Sprintf("%02d-%s.json", i+1, v.Name))
		if *update {
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (go test ./internal/aep -run TestVectors -update writes them)", err)
		}
		if !bytes.Equal(got, b) {
			t.Errorf("%s: the published vector is not what the protocol now produces", path)
		}
	}
	files, _ := filepath.Glob(filepath.Join(vectorDir, "*.json"))
	if len(files) != len(vectors) {
		t.Errorf("%d vector files and %d vectors", len(files), len(vectors))
	}
}
