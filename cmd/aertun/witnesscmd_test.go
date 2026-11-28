// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/extmcp"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/receiptlog"
)

const testGatewaySecret = "the-gateway-secret-0123456789abcdef"

// witnessSite is a store with a receipt log, three parties, the agent
// registered, and the gateway's witness answering over cleartext HTTP/2.
func witnessSite(t *testing.T) (root, logKey string, parties []party, wt *agwWitness, c *extmcp.Client, at time.Time) {
	t.Helper()
	root, parties = receiptSite(t)
	register(t, root, "agent-7", "aertun_read")
	at = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	logKey = filepath.Join(t.TempDir(), "log.json")
	if err := cmdReceipt(root, []string{"init", "--log-name", "https://receipts.test", "--log-key", logKey}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "receipts")
	l, err := receiptlog.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	gw := parties[1]
	k, err := pack.LoadKey(gw.key)
	if err != nil {
		t.Fatal(err)
	}
	signer, _, err := receiptlog.Signers(k)
	if err != nil {
		t.Fatal(err)
	}
	wt = newAgwWitness(root, dir, l, signer, gw.issuer, []byte(testGatewaySecret),
		map[string]string{"fs": "https://mcp.test/"}, false, time.Minute)
	wt.now = func() time.Time { return at }
	t.Cleanup(wt.close)
	srv := httptest.NewUnstartedServer(extmcp.Handler(wt))
	srv.Config.Protocols = extmcp.Server("", wt).Protocols
	srv.Start()
	t.Cleanup(srv.Close)
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	hc := &http.Client{Transport: &http.Transport{Protocols: &protos}, Timeout: 30 * time.Second}
	return root, logKey, parties, wt, extmcp.NewClient(srv.Listener.Addr().String(), hc), at
}

// gateway is the metadata agentgateway is configured to send.
func gateway(actor string, extra ...string) map[string]any {
	m := map[string]any{"actor": actor, "aertun_secret": testGatewaySecret}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return m
}

// call passes one tools/call through the witness as agentgateway would,
// and its response, unless result is empty.
func call(t *testing.T, c *extmcp.Client, actor, tool, args, result string) *extmcp.RequestResult {
	t.Helper()
	ctx := context.Background()
	res, err := c.CheckRequest(ctx, &extmcp.Request{ServiceNames: []string{"fs"}, Method: "tools/call",
		Metadata: gateway(actor), Params: []byte(`{"name":"` + tool + `","arguments":` + args + `}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deny == nil && result != "" {
		if _, err := c.CheckResponse(ctx, &extmcp.Response{ServiceNames: []string{"fs"}, Method: "tools/call",
			Metadata: gateway(actor, "aertun_call", res.Metadata["aertun_call"]), Result: []byte(result)}); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

// gatewayReceipts are the gateway's receipts in the log, oldest first,
// once the witness has written what it holds.
func gatewayReceipts(t *testing.T, wt *agwWitness, root, issuer string) []aep.Receipt {
	t.Helper()
	wt.flush()
	l, err := receiptlog.Open(filepath.Join(root, "receipts"), "")
	if err != nil {
		t.Fatal(err)
	}
	var out []aep.Receipt
	if err := l.Each(func(_ int, entry []byte) error {
		s, r, err := aep.ReadReceipt(entry)
		if err == nil && s.Issuer == issuer {
			out = append(out, r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// The gateway, made a witness: a call every party reports reconciles; a
// call the agent never reported is caught, because the gateway and the
// server both saw it.
func TestTheGatewayWitnessesWhatTheAgentLeftOut(t *testing.T) {
	root, logKey, parties, wt, c, at := witnessSite(t)
	agent, gw, target := parties[0], parties[1], parties[2]

	// The call all three see.
	registerReceipt(t, root, parties, emitReceipt(t, agent, "read_file", `{"path":"/srv/a"}`, at, "--seq", "0"), logKey)
	registerReceipt(t, root, parties, emitReceipt(t, target, "read_file", `{"path":"/srv/a"}`, at, "--seq", "0"), logKey)
	if res := call(t, c, "agent-7", "read_file", ` { "path" : "/srv/a" } `, `{"content":[]}`); res.Deny != nil {
		t.Fatalf("the call was refused: %s", res.Deny.Reason)
	}
	// One the agent leaves out of its own account.
	later := at.Add(time.Minute)
	registerReceipt(t, root, parties, emitReceipt(t, target, "send_email", `{"to":"boss@example.com"}`, later, "--seq", "1"), logKey)
	got := gatewayReceipts(t, wt, root, gw.issuer)
	if len(got) != 1 || got[0].Vantage != "gateway" || got[0].Outcome != "ok" || got[0].Actor != "agent-7" ||
		got[0].Target != "https://mcp.test/" || !got[0].HasSeq || got[0].Seq != 0 {
		t.Fatalf("the gateway's receipt: %+v", got)
	}

	exportDir := t.TempDir()
	reconcile := func(to time.Time) error {
		wt.flush()
		os.RemoveAll(exportDir)
		if err := cmdReceipt(root, []string{"export", "--out", exportDir, "--log-key", logKey}); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(exportDir)
		var files []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".cose") {
				files = append(files, filepath.Join(exportDir, e.Name()))
			}
		}
		sort.Strings(files)
		key, _ := signingFiles(t)
		args := append([]string{"reconcile"}, files...)
		args = append(args, "--key", key, "--issuer", "https://aertun.test",
			"--from", at.Add(-time.Minute).Format(time.RFC3339), "--to", to.Format(time.RFC3339),
			"--log-key", logKey, "--out", filepath.Join(t.TempDir(), "r.cose"),
			"--expect", agent.issuer+"=agent", "--expect", gw.issuer+"=gateway", "--expect", target.issuer+"=target")
		return cmdReceipt("", append(args, trustAll(parties)...))
	}
	if err := reconcile(at.Add(30 * time.Second)); err != nil {
		t.Fatalf("the call every party reported did not reconcile: %v", err)
	}

	// The gateway sees the second call; the agent says nothing of it.
	wt.now = func() time.Time { return later }
	if res := call(t, c, "agent-7", "send_email", `{"to":"boss@example.com"}`, `{"content":[]}`); res.Deny != nil {
		t.Fatal(res.Deny.Reason)
	}
	err := reconcile(later.Add(30 * time.Second))
	if err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("a call the agent left out reconciled: %v", err)
	}
}

// The kill switch at the gateway: a disabled agent, a caller the registry
// does not hold, and a caller the gateway did not name are refused before
// the call reaches the server, and each refusal is receipted.
func TestTheGatewayRefusesWhatTheKillSwitchRefuses(t *testing.T) {
	root, _, parties, wt, c, _ := witnessSite(t)
	gw := parties[1]
	if err := cmdAgent(root, []string{"disable", "agent-7", "--why", "it mailed the board"}); err != nil {
		t.Fatal(err)
	}
	for actor, want := range map[string]string{"agent-7": "disabled (it mailed the board)",
		"stranger": "no agent \"stranger\" is registered", "": "did not say who is calling"} {
		res := call(t, c, actor, "read_file", `{}`, `{"content":[]}`)
		if res.Deny == nil || res.Deny.Code != extmcp.PermissionDenied || !strings.Contains(res.Deny.Reason, want) {
			t.Errorf("%q: %+v", actor, res.Deny)
		}
	}
	got := gatewayReceipts(t, wt, root, gw.issuer)
	if len(got) != 3 {
		t.Fatalf("%d receipts for three refusals", len(got))
	}
	for _, r := range got {
		if r.Outcome != "refused" {
			t.Errorf("a refusal was receipted as %q", r.Outcome)
		}
	}
	// Letting unregistered callers through lets them through, and never a
	// disabled agent, and never a caller nobody named.
	wt.allowUnregistered = true
	if res := call(t, c, "stranger", "read_file", `{}`, `{"content":[]}`); res.Deny != nil {
		t.Errorf("an unregistered caller was refused: %s", res.Deny.Reason)
	}
	for _, actor := range []string{"agent-7", ""} {
		if res := call(t, c, actor, "read_file", `{}`, `{"content":[]}`); res.Deny == nil {
			t.Errorf("%q was let through", actor)
		}
	}
	wt.flush()
	if s := wt.stats(); s.refused != 5 || s.receipted != 1 || s.failed != 0 {
		t.Errorf("counted %+v", s)
	}
}

// Only the gateway is answered: a call without its secret is refused and
// receipts nothing, and a response without it is ignored. A refused agent
// retrying in a loop is refused every time and receipted within its rate;
// calls waiting for responses are bounded; a call that could not be
// receipted is refused before it reaches the server.
func TestTheWitnessAnswersOnlyItsGatewayAndWithinBounds(t *testing.T) {
	root, _, parties, wt, c, at := witnessSite(t)
	gw := parties[1]
	ctx := context.Background()
	forged := map[string]any{"actor": "agent-7", "aertun_secret": "a guess"}
	res, err := c.CheckRequest(ctx, &extmcp.Request{ServiceNames: []string{"fs"}, Method: "tools/call",
		Metadata: forged, Params: []byte(`{"name":"read_file","arguments":{}}`)})
	if err != nil || res.Deny == nil || res.Deny.Code != extmcp.PermissionDenied {
		t.Fatalf("a call without the gateway's secret: %+v %v", res, err)
	}
	pass := call(t, c, "agent-7", "read_file", `{}`, "")
	forged["aertun_call"] = pass.Metadata["aertun_call"]
	if _, err := c.CheckResponse(ctx, &extmcp.Response{ServiceNames: []string{"fs"}, Method: "tools/call",
		Metadata: forged, Result: []byte(`{"content":[]}`)}); err != nil {
		t.Fatal(err)
	}
	if n := len(gatewayReceipts(t, wt, root, gw.issuer)); n != 0 {
		t.Fatalf("%d receipts from calls without the gateway's secret", n)
	}
	if s := wt.stats(); s.strangers != 1 {
		t.Errorf("counted %d strangers", s.strangers)
	}

	// A refused caller retrying: every call refused, the first few
	// receipted, the rest counted.
	wt.refusalBurst = 3
	for range 5 {
		if res := call(t, c, "stranger", "read_file", `{}`, ""); res.Deny == nil {
			t.Fatal("a stranger was let through")
		}
	}
	wt.flush()
	if s := wt.stats(); s.refused != 3 || s.quiet != 2 {
		t.Errorf("five refusals counted %+v", s)
	}
	// A minute later the caller's rate is its own again.
	wt.now = func() time.Time { return at.Add(2 * time.Minute) }
	call(t, c, "stranger", "read_file", `{}`, "")
	wt.flush()
	if s := wt.stats(); s.refused != 4 {
		t.Errorf("after a minute, %d refusals receipted", s.refused)
	}

	// Calls waiting: one already (pass, above); bounded at two.
	wt.maxPending = 2
	if res := call(t, c, "agent-7", "read_file", `{}`, ""); res.Deny != nil {
		t.Fatal(res.Deny.Reason)
	}
	if res := call(t, c, "agent-7", "read_file", `{}`, ""); res.Deny == nil || res.Deny.Code != extmcp.ResourceExhaust {
		t.Errorf("a call past the bound: %+v", res.Deny)
	}

	// What cannot be receipted is refused first, and takes no number.
	before := len(gatewayReceipts(t, wt, root, gw.issuer))
	for name, params := range map[string]string{
		"a tool named with a control character": `{"name":"read\u0007file","arguments":{}}`,
		"arguments over the digest's bound":     `{"name":"w","arguments":{"x":"` + strings.Repeat("a", aep.MaxArgs) + `"}}`,
	} {
		res, err := c.CheckRequest(ctx, &extmcp.Request{ServiceNames: []string{"fs"}, Method: "tools/call",
			Metadata: gateway("agent-7"), Params: []byte(params)})
		if err != nil || res.Deny == nil || res.Deny.Code != extmcp.Invalid {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	wt.maxPending = witnessMaxPending
	next := call(t, c, "agent-7", "read_file", `{}`, `{"content":[]}`)
	if next.Deny != nil {
		t.Fatal(next.Deny.Reason)
	}
	got := gatewayReceipts(t, wt, root, gw.issuer)
	if len(got) != before+1 || got[len(got)-1].Seq != got[len(got)-2].Seq+1 {
		t.Errorf("a refused-as-invalid call took a number: %+v", got[len(got)-2:])
	}
}

// A call whose response never comes is receipted once its deadline passes,
// with no outcome, since the witness cannot tell an upstream error from a
// call still running; its late response adds nothing. Other methods pass
// unreceipted, and a call that names no tool is refused as invalid.
func TestTheGatewayWitnessReceiptsWhatNeverAnswers(t *testing.T) {
	root, _, parties, wt, c, at := witnessSite(t)
	gw := parties[1]
	res := call(t, c, "agent-7", "read_file", `{"path":"/srv/a"}`, "")
	if res.Deny != nil || res.Metadata["aertun_call"] == "" {
		t.Fatalf("%+v", res)
	}
	wt.sweep(false)
	if n := len(gatewayReceipts(t, wt, root, gw.issuer)); n != 0 {
		t.Fatalf("%d receipts before the deadline", n)
	}
	wt.now = func() time.Time { return at.Add(2 * time.Minute) }
	wt.sweep(false)
	got := gatewayReceipts(t, wt, root, gw.issuer)
	if len(got) != 1 || got[0].Outcome != "" || !got[0].At.Equal(at) {
		t.Fatalf("the unanswered call: %+v", got)
	}
	if _, err := c.CheckResponse(context.Background(), &extmcp.Response{ServiceNames: []string{"fs"},
		Method: "tools/call", Metadata: gateway("agent-7", "aertun_call", res.Metadata["aertun_call"]),
		Result: []byte(`{"content":[]}`)}); err != nil {
		t.Fatal(err)
	}
	if n := len(gatewayReceipts(t, wt, root, gw.issuer)); n != 1 {
		t.Errorf("a late response made %d receipts", n)
	}
	// An error result is receipted as one.
	if res := call(t, c, "agent-7", "read_file", `{}`, `{"content":[],"isError":true}`); res.Deny != nil {
		t.Fatal(res.Deny.Reason)
	}
	if got := gatewayReceipts(t, wt, root, gw.issuer); got[len(got)-1].Outcome != "error" {
		t.Errorf("an error result was receipted as %q", got[len(got)-1].Outcome)
	}
	before := len(gatewayReceipts(t, wt, root, gw.issuer))
	if res, err := c.CheckRequest(context.Background(), &extmcp.Request{Method: "tools/list",
		Metadata: gateway("agent-7")}); err != nil || res.Deny != nil {
		t.Errorf("tools/list: %+v %v", res, err)
	}
	if res, err := c.CheckRequest(context.Background(), &extmcp.Request{Method: "tools/call",
		Metadata: gateway("agent-7"), Params: []byte(`{"arguments":{}}`)}); err != nil ||
		res.Deny == nil || res.Deny.Code != extmcp.Invalid {
		t.Errorf("a call naming no tool: %+v %v", res, err)
	}
	if n := len(gatewayReceipts(t, wt, root, gw.issuer)); n != before {
		t.Errorf("%d receipts for a listing and an invalid call", n-before)
	}
	// Stopping receipts what is still waiting.
	call(t, c, "agent-7", "read_file", `{}`, "")
	wt.sweep(true)
	if n := len(gatewayReceipts(t, wt, root, gw.issuer)); n != before+1 {
		t.Errorf("stopping left a call unreceipted (%d)", n-before)
	}
}

// The listener stays on this host unless the operator says otherwise; there
// is no witness without a receipt log; the gateway's secret is made 0600
// when absent, and refused when readable by others or too short.
func TestTheWitnessListensOnLoopbackAndKeepsItsSecret(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:9001": true, "[::1]:9001": true, "localhost:9001": true,
		"0.0.0.0:9001": false, ":9001": false, "10.0.0.5:9001": false} {
		if got, err := loopback(addr); err != nil || got != want {
			t.Errorf("loopback(%s) = %v %v", addr, got, err)
		}
	}
	root, parties := receiptSite(t)
	secret := filepath.Join(t.TempDir(), "gateway.secret")
	base := []string{"agentgateway", "--issuer", parties[1].issuer, "--key", parties[1].key, "--secret-file", secret}
	if err := cmdWitness(root, append(base, "--listen", "0.0.0.0:0")); err == nil || !strings.Contains(err.Error(), "--listen-any") {
		t.Errorf("a listener beyond this host: %v", err)
	}
	if err := cmdWitness(root, append(base, "--listen", "127.0.0.1:0")); err == nil || !strings.Contains(err.Error(), "receipt log") {
		t.Errorf("no receipt log: %v", err)
	}
	if err := cmdWitness(root, []string{"agentgateway", "--issuer", parties[1].issuer, "--key", parties[1].key}); err == nil {
		t.Error("a witness with no secret was started")
	}

	s, made, err := witnessSecret(secret)
	if err != nil || !made || len(s) < 32 {
		t.Fatalf("making the secret: %q %v %v", s, made, err)
	}
	if info, _ := os.Stat(secret); info.Mode().Perm() != 0o600 {
		t.Errorf("the secret was made %04o", info.Mode().Perm())
	}
	again, made, err := witnessSecret(secret)
	if err != nil || made || string(again) != string(s) {
		t.Errorf("reading it back: %v %v", made, err)
	}
	os.Chmod(secret, 0o644)
	if _, _, err := witnessSecret(secret); err == nil {
		t.Error("a secret readable by others was taken")
	}
	short := filepath.Join(t.TempDir(), "short")
	os.WriteFile(short, []byte("abc\n"), 0o600)
	if _, _, err := witnessSecret(short); err == nil {
		t.Error("a three-character secret was taken")
	}
}
