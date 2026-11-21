// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/scitt"
)

type party struct {
	issuer, vantage, key, pub string
}

func receiptSite(t *testing.T) (root string, parties []party) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"https://agent.test", "agent"}, {"https://gateway.test", "gateway"},
		{"https://target.test", "target"}} {
		key, pub := signingFiles(t)
		k, err := pack.LoadKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := pack.WritePublicKey(pub, k.PublicKey()); err != nil {
			t.Fatal(err)
		}
		parties = append(parties, party{p[0], p[1], key, pub})
	}
	return root, parties
}

func emitReceipt(t *testing.T, p party, tool, args string, at time.Time, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	argsAt := filepath.Join(dir, "args.json")
	os.WriteFile(argsAt, []byte(args), 0o600)
	outAt := filepath.Join(dir, "receipt.cose")
	if err := cmdReceipt("", append([]string{"emit", "--key", p.key, "--issuer", p.issuer, "--vantage", p.vantage,
		"--target", "https://mcp.test/", "--tool", tool, "--args", argsAt, "--at", at.Format(time.RFC3339Nano),
		"--actor", "agent-7", "--public-key", p.pub, "--out", outAt}, extra...)); err != nil {
		t.Fatal(err)
	}
	return outAt
}

func trustAll(parties []party) []string {
	var out []string
	for _, p := range parties {
		out = append(out, "--issuer-key", p.issuer+"="+p.pub)
	}
	return out
}

func registerReceipt(t *testing.T, root string, parties []party, file, logKey string) string {
	t.Helper()
	outAt := file + ".transparent"
	args := append([]string{"register", file, "--log-name", "https://receipts.test", "--log-key", logKey, "--out", outAt},
		trustAll(parties)...)
	if err := cmdReceipt(root, args); err != nil {
		t.Fatal(err)
	}
	return outAt
}

// TestReceiptsEndToEnd: three parties see an agent's calls; one call only
// the agent reports. Every receipt is registered, verifies offline with
// both of the log's receipts, and the reconciliation names the call the
// gateway and the target never saw, and is checked by doing it again.
func TestReceiptsEndToEnd(t *testing.T) {
	root, parties := receiptSite(t)
	agent, gw := parties[0], parties[1]
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	logKey := filepath.Join(t.TempDir(), "log.json")
	var files []string
	for i, p := range parties {
		f := emitReceipt(t, p, "read_file", `{"path":"/srv/a"}`, t0.Add(time.Duration(i)*20*time.Millisecond), "--seq", "0")
		files = append(files, registerReceipt(t, root, parties, f, logKey))
	}
	only := emitReceipt(t, agent, "send_email", `{"to":"boss@example.com"}`, t0.Add(time.Minute), "--seq", "1")
	files = append(files, registerReceipt(t, root, parties, only, logKey))

	verify := append([]string{"verify", files[1], "--log-key", logKey, "--args", ""}, trustAll(parties)...)
	argsAt := filepath.Join(t.TempDir(), "args.json")
	os.WriteFile(argsAt, []byte(` { "path" : "/srv/a" } `), 0o600)
	verify[5] = argsAt
	if err := cmdReceipt("", verify); err != nil {
		t.Fatalf("verify: %v", err)
	}
	os.WriteFile(argsAt, []byte(`{"path":"/srv/b"}`), 0o600)
	if err := cmdReceipt("", verify); err == nil || !strings.Contains(err.Error(), "not about these arguments") {
		t.Errorf("other arguments: %v", err)
	}
	// Only the gateway's key is trusted: the agent's receipt is refused.
	if err := cmdReceipt("", []string{"verify", files[0], "--issuer-key", gw.issuer + "=" + gw.pub}); err == nil {
		t.Error("a receipt verified from an issuer whose key was not given")
	}
	// The agent's name with the gateway's key: refused.
	if err := cmdReceipt("", []string{"verify", files[0], "--issuer-key", agent.issuer + "=" + gw.pub}); err == nil {
		t.Error("a receipt verified with another party's key")
	}
	// Without the log's receipts, a log key makes verification fail.
	if err := cmdReceipt("", append([]string{"verify", only, "--log-key", logKey}, trustAll(parties)...)); err == nil {
		t.Error("an unregistered receipt verified as registered")
	}

	reconAt := filepath.Join(t.TempDir(), "reconciliation.cose")
	key, _ := signingFiles(t)
	recon := append([]string{"reconcile"}, files...)
	recon = append(recon, "--key", key, "--issuer", "https://aertun.test", "--from", t0.Add(-time.Minute).Format(time.RFC3339),
		"--to", t0.Add(time.Hour).Format(time.RFC3339), "--log-key", logKey, "--out", reconAt)
	for _, p := range parties {
		recon = append(recon, "--expect", p.issuer+"="+p.vantage)
	}
	recon = append(recon, trustAll(parties)...)
	err := cmdReceipt("", recon)
	if err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("reconcile: %v", err)
	}
	b, rerr := os.ReadFile(reconAt)
	if rerr != nil {
		t.Fatal(rerr)
	}
	_, win, _, verdict, rerr := aep.ReadReconciliation(b)
	if rerr != nil || verdict != aep.Disagree || len(win.Expect) != 3 {
		t.Fatalf("%v %s %+v", rerr, verdict, win)
	}

	// The reconciliation verifies by doing it again over the same receipts,
	// with the reconciler's key trusted beside the parties'.
	reconPub := filepath.Join(t.TempDir(), "reconciler.json")
	k, _ := pack.LoadKey(key)
	if err := pack.WritePublicKey(reconPub, k.PublicKey()); err != nil {
		t.Fatal(err)
	}
	check := append([]string{"verify", reconAt}, files...)
	check = append(check, "--issuer-key", "https://aertun.test="+reconPub)
	check = append(check, trustAll(parties)...)
	if err := cmdReceipt("", check); err != nil {
		t.Fatalf("checking the reconciliation: %v", err)
	}
	short := append([]string{"verify", reconAt}, files[1:]...)
	short = append(short, "--issuer-key", "https://aertun.test="+reconPub)
	short = append(short, trustAll(parties)...)
	if err := cmdReceipt("", short); err == nil || !strings.Contains(err.Error(), "not the receipts") {
		t.Errorf("checked against fewer receipts: %v", err)
	}
}

// TestRegisterRefuses: a statement whose signature does not verify, or
// from a party not trusted, never enters the log.
func TestRegisterRefuses(t *testing.T) {
	root, parties := receiptSite(t)
	f := emitReceipt(t, parties[0], "read_file", `{}`, time.Now().UTC())
	b, _ := os.ReadFile(f)
	b[len(b)-3] ^= 1
	bad := filepath.Join(t.TempDir(), "bad.cose")
	os.WriteFile(bad, b, 0o600)
	logKey := filepath.Join(t.TempDir(), "log.json")
	args := append([]string{"register", bad, "--log-name", "https://receipts.test", "--out", bad + ".t"}, trustAll(parties)...)
	if err := cmdReceipt(root, args); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Errorf("a broken signature: %v", err)
	}
	args = []string{"register", f, "--log-name", "https://receipts.test", "--log-key", logKey, "--out", f + ".t",
		"--issuer-key", parties[1].issuer + "=" + parties[1].pub}
	if err := cmdReceipt(root, args); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Errorf("an issuer not trusted: %v", err)
	}
	ok := registerReceipt(t, root, parties, f, logKey)
	tb, _ := os.ReadFile(ok)
	s, err := scitt.Read(tb)
	if err != nil || len(s.Receipts) != 2 {
		t.Fatalf("%v, %d receipts", err, len(s.Receipts))
	}
	if err := cmdReceipt(root, []string{"emit", "--key", parties[0].key}); err == nil {
		t.Error("an emit with nothing to say was accepted")
	}
}

// TestTheAgentInterfaceReceiptsItsCalls: with a receipt log set up, a call
// an agent makes over stdio is appended as a receipt from the target's
// vantage, exported with the log's two receipts on demand, verified with
// the log's key, and reconciled against the agent's own receipt for the
// same call: they agree.
func TestTheAgentInterfaceReceiptsItsCalls(t *testing.T) {
	root := caveatSite(t)
	if err := cmdConfig(root, []string{"set", "admin.base_url", "https://aertun.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiptlog.Open(filepath.Join(root, "receipts"), "https://receipts.test"); err != nil {
		t.Fatal(err)
	}
	c := runCaller(t, root, mintRun(t, root, "nightly-1", []string{"aertun_read"}, "", 0, -1))
	at := time.Now().UTC()
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"aertun_read","arguments":{"operation":"list_findings"}}}` + "\n"
	var out bytes.Buffer
	if err := serveStdio(root, buildMCP(root, c), c, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	// Export signs in the deployment's name: an administrator does it.
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin, auth.Scope{})
	if err != nil || saveTokens(root, ts) != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", secret)
	dir := t.TempDir()
	logKey := filepath.Join(dir, "log.json")
	exported := filepath.Join(dir, "out")
	if err := cmdReceipt(root, []string{"export", "--out", exported, "--issuer", "https://aertun.test/mcp",
		"--log-key", logKey}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(exported, "*.cose"))
	if len(files) != 1 {
		t.Fatalf("%d receipts exported", len(files))
	}
	b, _ := os.ReadFile(files[0])
	_, r, rerr := aep.ReadReceipt(b)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if r.Vantage != "target" || r.Tool != "aertun_read" || r.Target != "https://aertun.test/mcp" ||
		r.Actor != c.Agent || r.Grant != "nightly-1" || r.Outcome != "ok" {
		t.Errorf("the interface's receipt: %+v (agent %q)", r, c.Agent)
	}
	iface := "https://aertun.test/mcp=" + logKey
	if err := cmdReceipt("", []string{"verify", files[0], "--issuer-key", iface, "--log-key", logKey}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The agent's own account of the same call, from its own key.
	_, parties := receiptSite(t)
	agent := parties[0]
	argsAt := filepath.Join(dir, "args.json")
	os.WriteFile(argsAt, []byte(`{"operation": "list_findings"}`), 0o600)
	mine := filepath.Join(dir, "agent.cose")
	if err := cmdReceipt("", []string{"emit", "--key", agent.key, "--issuer", agent.issuer, "--vantage", "agent",
		"--target", "https://aertun.test/mcp", "--tool", "aertun_read", "--args", argsAt,
		"--at", at.Format(time.RFC3339Nano), "--out", mine}); err != nil {
		t.Fatal(err)
	}
	key, _ := signingFiles(t)
	err = cmdReceipt("", []string{"reconcile", mine, files[0], "--key", key, "--issuer", "https://auditor.test",
		"--from", at.Add(-time.Minute).Format(time.RFC3339), "--to", at.Add(time.Minute).Format(time.RFC3339),
		"--tolerance", "10s", "--expect", agent.issuer + "=agent", "--expect", "https://aertun.test/mcp=target",
		"--issuer-key", agent.issuer + "=" + agent.pub, "--issuer-key", iface, "--out", filepath.Join(dir, "r.cose")})
	if err != nil {
		t.Fatalf("the agent and the interface do not agree: %v", err)
	}
}

// TestTheHTTPInterfaceReceiptsItsCalls: over HTTP the receipt names the
// resource the metadata names, the address the operator chose.
func TestTheHTTPInterfaceReceiptsItsCalls(t *testing.T) {
	base, root, _, analyst, _ := agentSite(t)
	l, err := receiptlog.Open(filepath.Join(root, "receipts"), "https://receipts.test")
	if err != nil {
		t.Fatal(err)
	}
	code, _, resp := agentCall{token: analyst, body: `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
		`"params":{"name":"aertun_read","arguments":{"operation":"list_findings"}}}`}.do(t, base)
	if code != 200 || resp.Error != nil {
		t.Fatalf("%d %+v", code, resp.Error)
	}
	var got []aep.Receipt
	if err := l.Each(func(_ int, e []byte) error {
		s, r, err := aep.ReadReceipt(e)
		if err != nil {
			return err
		}
		if s.Issuer != base+"/mcp" {
			t.Errorf("issued as %s", s.Issuer)
		}
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Target != base+"/mcp" || got[0].Tool != "aertun_read" || got[0].Outcome != "ok" {
		t.Errorf("%+v", got)
	}
}

// TestReceiptInit: a log is set up once under a name, its key written for
// verifiers; a second init under another name is refused.
func TestReceiptInit(t *testing.T) {
	root, _ := receiptSite(t)
	key := filepath.Join(t.TempDir(), "log.json")
	if err := cmdReceipt(root, []string{"init", "--log-name", "https://receipts.test", "--log-key", key}); err != nil {
		t.Fatal(err)
	}
	if !receiptlog.Exists(filepath.Join(root, "receipts")) {
		t.Fatal("no log was set up")
	}
	if _, err := pack.LoadPublicKey(key); err != nil {
		t.Errorf("the log's key: %v", err)
	}
	if err := cmdReceipt(root, []string{"init", "--log-name", "https://receipts.test"}); err != nil {
		t.Errorf("init again under the same name: %v", err)
	}
	if err := cmdReceipt(root, []string{"init", "--log-name", "https://other.test"}); err == nil {
		t.Error("a log was renamed")
	}
}
