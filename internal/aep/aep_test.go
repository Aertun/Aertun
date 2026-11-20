// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package aep

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/cbor"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/scitt"
)

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func signer(t *testing.T, seed byte) *cose.Ed25519 {
	t.Helper()
	s, err := cose.NewEd25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func args(t *testing.T, js string) [32]byte {
	t.Helper()
	d, err := ArgsDigest([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestArgsDigest(t *testing.T) {
	a := args(t, `{"b":1,"a":[1,2.50,"x"]}`)
	b := args(t, " { \"a\" : [1, 2.5, \"\\u0078\"], \"b\": 1 } ")
	if a != b {
		t.Error("two writings of the same arguments digest differently")
	}
	if args(t, "") != args(t, "{}") {
		t.Error("no arguments are not the empty object")
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":`, `[1,]`, "\"\\ud800\""} {
		if _, err := ArgsDigest([]byte(bad)); err == nil {
			t.Errorf("%s digested", bad)
		}
	}
}

// TestDigestVector pins the action digest, so a change to how it is
// computed is a failing test and not a quiet new protocol.
func TestDigestVector(t *testing.T) {
	a := Action{Target: "https://mcp.example/", Tool: "transfer_funds", Args: args(t, `{"amount":100,"to":"acct-7"}`)}
	d, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// Recomputed independently: SHA-256 over 84 6d"AEP-Action-v1" 74"https://mcp.example/"
	// 6e"transfer_funds" 5820 SHA-256({"amount":100,"to":"acct-7"}).
	const want = "2ccbd601ae06c347e830e1dfadf2dfed9dfdddc4f8ff47945af22fee7c0f82ab"
	if got := hex.EncodeToString(d[:]); got != want {
		t.Errorf("action digest %s, pinned %s", got, want)
	}
	for _, bad := range []Action{{Tool: "t"}, {Target: "x"}, {Target: "x\n", Tool: "t"}, {Target: strings.Repeat("x", MaxName+1), Tool: "t"}} {
		if _, err := bad.Digest(); err == nil {
			t.Errorf("%+v digested", bad)
		}
	}
}

func receipt(t *testing.T, vantage, tool, js string, at time.Time) Receipt {
	t.Helper()
	return Receipt{Action: Action{Target: "https://mcp.example/", Tool: tool, Args: args(t, js)},
		Vantage: vantage, At: at, Actor: "agent-7", Outcome: "ok"}
}

func TestReceiptRoundTrip(t *testing.T) {
	s := signer(t, 1)
	r := receipt(t, "gateway", "read_file", `{"path":"/etc/hosts"}`, t0.Add(1500*time.Microsecond))
	r.Grant, r.Seq, r.HasSeq = "tok-123", 42, true
	b, err := Emit(s, "https://gateway.example", r, t0)
	if err != nil {
		t.Fatal(err)
	}
	st, got, err := ReadReceipt(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Verify(s); err != nil {
		t.Fatal(err)
	}
	r.Digest = got.Digest
	if got != r {
		t.Errorf("read back %+v\nwant %+v", got, r)
	}
	if st.Subject != Subject(got.Digest) || st.Issuer != "https://gateway.example" {
		t.Errorf("statement %s %s", st.Issuer, st.Subject)
	}
	for _, bad := range []Receipt{
		{Action: r.Action, Vantage: "observer", At: t0},
		{Action: r.Action, Vantage: "agent"},
		{Action: r.Action, Vantage: "agent", At: t0, Outcome: "maybe"},
		{Action: r.Action, Vantage: "agent", At: t0, Actor: "a\x00b"},
	} {
		if _, err := Emit(s, "i", bad, t0); err == nil {
			t.Errorf("%+v emitted", bad)
		}
	}
}

// TestReceiptTamper: a payload whose digest, subject, keys or times are
// not what the reader requires is refused, even when properly signed.
func TestReceiptTamper(t *testing.T) {
	s := signer(t, 1)
	r := receipt(t, "agent", "read_file", `{}`, t0)
	r.Digest, _ = r.Action.Digest()
	base := func() cbor.Map {
		return cbor.Map{
			{Key: cbor.Text("v"), Value: cbor.Uint(1)},
			{Key: cbor.Text("action"), Value: cbor.Bytes(r.Digest[:])},
			{Key: cbor.Text("target"), Value: cbor.Text(r.Target)},
			{Key: cbor.Text("tool"), Value: cbor.Text(r.Tool)},
			{Key: cbor.Text("args"), Value: cbor.Bytes(r.Args[:])},
			{Key: cbor.Text("vantage"), Value: cbor.Text("agent")},
			{Key: cbor.Text("at"), Value: cbor.Text(instant(t0))},
		}
	}
	set := func(m cbor.Map, k string, v cbor.Value) cbor.Map {
		for i := range m {
			if m[i].Key == cbor.Text(k) {
				m[i].Value = v
				return m
			}
		}
		return append(m, cbor.Entry{Key: cbor.Text(k), Value: v})
	}
	drop := func(m cbor.Map, k string) cbor.Map {
		out := cbor.Map{}
		for _, e := range m {
			if e.Key != cbor.Text(k) {
				out = append(out, e)
			}
		}
		return out
	}
	sign := func(p cbor.Map, sub string) []byte {
		payload, err := cbor.Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		b, err := scitt.Sign(s, scitt.Statement{Issuer: "i", Subject: sub, ContentType: ContentAction, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := Subject(r.Digest)
	if _, _, err := ReadReceipt(sign(base(), good)); err != nil {
		t.Fatalf("the base receipt: %v", err)
	}
	cases := map[string][]byte{
		"tool changed":    sign(set(base(), "tool", cbor.Text("delete_file")), good),
		"subject":         sign(base(), "aep:action:00"),
		"unknown key":     sign(set(base(), "note", cbor.Text("x")), good),
		"no at":           sign(drop(base(), "at"), good),
		"version 2":       sign(set(base(), "v", cbor.Uint(2)), good),
		"offset time":     sign(set(base(), "at", cbor.Text("2026-11-20T13:00:00+01:00")), good),
		"padded time":     sign(set(base(), "at", cbor.Text("2026-11-20T12:00:00.000Z")), good),
		"negative seq":    sign(set(base(), "seq", cbor.Int(-1)), good),
		"short digest":    sign(set(base(), "action", cbor.Bytes(r.Digest[:31])), good),
		"vantage unknown": sign(set(base(), "vantage", cbor.Text("observer")), good),
	}
	for name, b := range cases {
		if _, _, err := ReadReceipt(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	other, _ := scitt.Sign(s, scitt.Statement{Issuer: "i", Subject: good, ContentType: ContentReconciliation, Payload: []byte{0xa0}})
	if _, _, err := ReadReceipt(other); err == nil {
		t.Error("a reconciliation was read as an action receipt")
	}
}

const (
	agentIss  = "https://agent.example"
	gwIss     = "https://gateway.example"
	targetIss = "https://target.example"
)

var three = []Expect{{agentIss, "agent"}, {gwIss, "gateway"}, {targetIss, "target"}}

type world struct {
	t   *testing.T
	in  []Input
	seq map[string]uint64
}

func (w *world) see(iss, vantage, tool, js string, at time.Time, actor string) {
	w.t.Helper()
	r := receipt(w.t, vantage, tool, js, at)
	r.Actor = actor
	if w.seq == nil {
		w.seq = map[string]uint64{}
	}
	r.Seq, r.HasSeq = w.seq[iss], true
	w.seq[iss]++
	b, err := Emit(signer(w.t, byte(len(iss))), iss, r, at)
	if err != nil {
		w.t.Fatal(err)
	}
	_, back, err := ReadReceipt(b)
	if err != nil {
		w.t.Fatal(err)
	}
	w.in = append(w.in, Input{Issuer: iss, Entry: b, Receipt: back})
}

// all is one action seen by all three parties, a little apart.
func (w *world) all(tool, js string, at time.Time) {
	w.see(agentIss, "agent", tool, js, at, "agent-7")
	w.see(gwIss, "gateway", tool, js, at.Add(20*time.Millisecond), "agent-7")
	w.see(targetIss, "target", tool, js, at.Add(45*time.Millisecond), "agent-7")
}

func window() Window {
	return Window{From: t0, To: t0.Add(time.Hour), Tolerance: time.Second, Expect: three}
}

func TestReconcileAgree(t *testing.T) {
	w := &world{t: t}
	w.all("read_file", `{"path":"a"}`, t0.Add(time.Minute))
	// The same call twice, a moment apart: two actions, each complete.
	w.all("read_file", `{"path":"a"}`, t0.Add(time.Minute+300*time.Millisecond))
	w.all("send_email", `{"to":"x"}`, t0.Add(2*time.Minute))
	res, err := Reconcile(w.in, window())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Agree || res.Actions != 3 || res.Complete != 3 || res.Receipts != 9 {
		t.Errorf("%+v", res)
	}
}

func TestReconcileGaps(t *testing.T) {
	w := &world{t: t}
	w.all("read_file", `{"path":"a"}`, t0.Add(time.Minute))
	// The agent did something it reported, and the gateway and the target
	// saw nothing: a call that never went where it says.
	w.see(agentIss, "agent", "send_email", `{"to":"boss"}`, t0.Add(2*time.Minute), "agent-7")
	// The target saw something the agent never reported.
	w.see(gwIss, "gateway", "send_email", `{"to":"attacker"}`, t0.Add(3*time.Minute), "agent-7")
	w.see(targetIss, "target", "send_email", `{"to":"attacker"}`, t0.Add(3*time.Minute+10*time.Millisecond), "agent-7")
	res, err := Reconcile(w.in, window())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Disagree || res.Actions != 3 || res.Complete != 1 || res.GapsTotal != 2 {
		t.Fatalf("%+v", res)
	}
	if g := res.Gaps[0]; g.Tool != "send_email" || strings.Join(g.Missing, ",") != gwIss+","+targetIss {
		t.Errorf("first gap %+v", g)
	}
	if g := res.Gaps[1]; strings.Join(g.Missing, ",") != agentIss || len(g.SeenBy) != 2 {
		t.Errorf("second gap %+v", g)
	}
}

// TestReconcileSilentParty: a party that reported nothing is still
// expected, and every action is a gap naming it.
func TestReconcileSilentParty(t *testing.T) {
	w := &world{t: t}
	for i := range 4 {
		w.see(agentIss, "agent", "t", "{}", t0.Add(time.Duration(i)*time.Minute), "")
		w.see(gwIss, "gateway", "t", "{}", t0.Add(time.Duration(i)*time.Minute), "")
	}
	res, err := Reconcile(w.in, window())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Disagree || res.GapsTotal != 4 {
		t.Fatalf("%+v", res)
	}
	for _, g := range res.Gaps {
		if strings.Join(g.Missing, ",") != targetIss {
			t.Errorf("gap %+v", g)
		}
	}
}

func TestReconcileTolerance(t *testing.T) {
	w := &world{t: t}
	w.see(agentIss, "agent", "t", "{}", t0.Add(time.Minute), "")
	w.see(gwIss, "gateway", "t", "{}", t0.Add(time.Minute+time.Second), "")
	w.see(targetIss, "target", "t", "{}", t0.Add(time.Minute+time.Second+time.Millisecond), "")
	res, _ := Reconcile(w.in, window())
	if res.Actions != 2 || res.Complete != 0 {
		t.Errorf("a sighting past the tolerance joined the action: %+v", res)
	}
	// A sighting exactly the tolerance after the first joins it.
	if strings.Join(res.Gaps[0].Missing, ",") != targetIss || strings.Join(res.Gaps[1].SeenBy, ",") != targetIss {
		t.Errorf("the tolerance is not inclusive: %+v", res.Gaps)
	}
	win := window()
	win.Tolerance = 2 * time.Second
	res, _ = Reconcile(w.in, win)
	if res.Actions != 1 || res.Complete != 1 {
		t.Errorf("sightings within the tolerance were not joined: %+v", res)
	}
}

// TestReconcileEdges: an action is counted in the window its first
// sighting falls in, and matched across the edge.
func TestReconcileEdges(t *testing.T) {
	w := &world{t: t}
	w.all("a", "{}", t0.Add(-500*time.Millisecond))
	w.all("b", "{}", t0.Add(time.Hour-10*time.Millisecond))
	w.all("c", "{}", t0.Add(-time.Hour))
	res, err := Reconcile(w.in, window())
	if err != nil {
		t.Fatal(err)
	}
	if res.Actions != 1 || res.Complete != 1 || res.Verdict != Agree {
		t.Errorf("%+v", res)
	}
	before := Window{From: t0.Add(-time.Hour), To: t0, Tolerance: time.Second, Expect: three}
	res, _ = Reconcile(w.in, before)
	if res.Actions != 2 || res.Complete != 2 {
		t.Errorf("the earlier window: %+v", res)
	}
}

func TestReconcileSeqAndActors(t *testing.T) {
	w := &world{t: t}
	w.all("a", "{}", t0.Add(time.Minute))
	w.seq[gwIss] += 3 // the gateway's receipts 1 to 3 are not here
	w.all("b", "{}", t0.Add(2*time.Minute))
	w.seq[targetIss]-- // the target uses one number twice
	w.see(agentIss, "agent", "c", "{}", t0.Add(3*time.Minute), "agent-7")
	w.see(gwIss, "gateway", "c", "{}", t0.Add(3*time.Minute), "agent-7")
	w.see(targetIss, "target", "c", "{}", t0.Add(3*time.Minute), "agent-9")
	res, err := Reconcile(w.in, window())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Disagree || res.GapsTotal != 0 || len(res.SeqGaps) != 2 || res.ActorsTotal != 1 {
		t.Fatalf("%+v", res)
	}
	gw, tg := res.SeqGaps[0], res.SeqGaps[1]
	if gw.Issuer != gwIss || len(gw.Missing) != 1 || gw.Missing[0] != [2]uint64{1, 3} {
		t.Errorf("gateway %+v", gw)
	}
	if tg.Issuer != targetIss || len(tg.Repeated) != 1 || tg.Repeated[0] != 1 {
		t.Errorf("target %+v", tg)
	}
	if a := res.Actors[0]; a.Actors[targetIss] != "agent-9" || a.Actors[agentIss] != "agent-7" {
		t.Errorf("actors %+v", a)
	}
}

func TestReconcileRefusals(t *testing.T) {
	w := &world{t: t}
	w.see("https://stranger.example", "agent", "t", "{}", t0.Add(time.Minute), "")
	if _, err := Reconcile(w.in, window()); err == nil {
		t.Error("a receipt from a party not expected was reconciled")
	}
	w = &world{t: t}
	w.see(gwIss, "target", "t", "{}", t0.Add(time.Minute), "")
	if _, err := Reconcile(w.in, window()); err == nil {
		t.Error("a party reporting from a vantage it is not expected at was reconciled")
	}
	for _, bad := range []Window{
		{From: t0, To: t0, Tolerance: time.Second, Expect: three},
		{From: t0, To: t0.Add(MaxWindow + 1), Expect: three},
		{From: t0, To: t0.Add(time.Hour), Tolerance: 2 * MaxTolerance, Expect: three},
		{From: t0, To: t0.Add(time.Hour), Expect: three[:1]},
		{From: t0, To: t0.Add(time.Hour), Expect: []Expect{three[0], three[0]}},
		{From: t0, To: t0.Add(time.Hour), Expect: []Expect{three[0], {gwIss, "observer"}}},
	} {
		if _, err := Reconcile(nil, bad); err == nil {
			t.Errorf("window %+v was accepted", bad)
		}
	}
	res, err := Reconcile(nil, window())
	if err != nil || res.Verdict != Inconclusive {
		t.Errorf("no receipts: %v %+v", err, res)
	}
}

// TestReconciliationReceipt: the receipt is deterministic in its inputs,
// whatever order they come in, and is checked by doing it again.
func TestReconciliationReceipt(t *testing.T) {
	w := &world{t: t}
	w.all("a", `{"x":1}`, t0.Add(time.Minute))
	w.see(agentIss, "agent", "b", "{}", t0.Add(2*time.Minute), "agent-7")
	w.all("a", `{"x":1}`, t0.Add(3*time.Minute))
	s := signer(t, 9)
	res, err := Reconcile(w.in, window())
	if err != nil {
		t.Fatal(err)
	}
	b, err := IssueReconciliation(s, "https://aertun.example", res, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	shuffled := append([]Input(nil), w.in...)
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	shuffled = append(shuffled, shuffled[0]) // and one handed in twice
	again, err := CheckReconciliation(b, shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if again.Verdict != Disagree || again.GapsTotal != 1 {
		t.Errorf("%+v", again)
	}
	st, win, inputs, verdict, err := ReadReconciliation(b)
	if err != nil || verdict != Disagree || inputs != res.Inputs || !win.From.Equal(t0) || len(win.Expect) != 3 {
		t.Fatalf("%v %s %+v", err, verdict, win)
	}
	if err := st.Verify(s); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckReconciliation(b, w.in[1:]); err == nil || !strings.Contains(err.Error(), "not the receipts") {
		t.Errorf("one receipt short: %v", err)
	}
	// A reconciliation that states agreement over receipts that disagree.
	lie := res
	lie.Verdict, lie.Gaps, lie.GapsTotal, lie.Complete = Agree, nil, 0, res.Actions
	lb, _ := IssueReconciliation(s, "https://aertun.example", lie, t0)
	if _, err := CheckReconciliation(lb, w.in); err == nil || !strings.Contains(err.Error(), "other than it states") {
		t.Errorf("a false agreement: %v", err)
	}
}

// TestReconcileFlood: many receipts for one action are matched in time
// close to linear, and still each to its own action.
func TestReconcileFlood(t *testing.T) {
	r := receipt(t, "agent", "t", "{}", t0)
	r.Digest, _ = r.Action.Digest()
	var in []Input
	for i := range 20000 {
		for _, e := range three {
			x := r
			x.Vantage, x.At = e.Vantage, t0.Add(time.Duration(i)*2*time.Second)
			in = append(in, Input{Issuer: e.Issuer, Entry: []byte(fmt.Sprint(e.Issuer, i)), Receipt: x})
		}
	}
	start := time.Now()
	res, err := Reconcile(in, Window{From: t0, To: t0.Add(24 * time.Hour), Tolerance: time.Second, Expect: three})
	if err != nil {
		t.Fatal(err)
	}
	if res.Actions != 20000 || res.Complete != 20000 {
		t.Errorf("%d actions, %d complete", res.Actions, res.Complete)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("60000 receipts took %s", d)
	}
}
