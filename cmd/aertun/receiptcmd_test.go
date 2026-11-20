// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/pack"
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
