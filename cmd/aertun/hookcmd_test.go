// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/receiptlog"
)

func runHook(t *testing.T, root, event string, args ...string) error {
	t.Helper()
	old := hookStdin
	hookStdin = strings.NewReader(event)
	defer func() { hookStdin = old }()
	return cmdHook(root, append([]string{"claude-code"}, args...))
}

func hookSite(t *testing.T) (root, key, pub string) {
	t.Helper()
	root = caveatSite(t)
	if _, err := receiptlog.Open(filepath.Join(root, "receipts"), "https://receipts.test"); err != nil {
		t.Fatal(err)
	}
	key, pub = signingFiles(t)
	k, err := pack.LoadKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := pack.WritePublicKey(pub, k.PublicKey()); err != nil {
		t.Fatal(err)
	}
	return root, key, pub
}

const pre = `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"toolu_1"}`

// TestTheHookObeysTheKillSwitch: an active agent's calls go ahead; a
// disabled one's, an unregistered one's, and any when the registry cannot
// be read, are refused with the exit status Claude Code honours.
func TestTheHookObeysTheKillSwitch(t *testing.T) {
	root, _, _ := hookSite(t)
	if err := runHook(t, root, pre, "--agent", "watcher"); err != nil {
		t.Fatalf("an active agent was refused: %v", err)
	}
	var deny errHookDeny
	if err := runHook(t, root, pre, "--agent", "stranger"); !errors.As(err, &deny) || !strings.Contains(err.Error(), "no agent") {
		t.Errorf("an unregistered agent: %v", err)
	}
	if err := agentStore(root).Disable("watcher", "it read a poisoned issue", "dana@acme.example", time.Now()); err != nil {
		t.Fatal(err)
	}
	err := runHook(t, root, pre, "--agent", "watcher")
	if !errors.As(err, &deny) || !strings.Contains(err.Error(), "it read a poisoned issue") {
		t.Errorf("a disabled agent: %v", err)
	}
	os.WriteFile(agentsPath(root), []byte("{not json"), 0o600)
	if err := runHook(t, root, pre, "--agent", "watcher"); !errors.As(err, &deny) || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("an unreadable registry: %v", err)
	}
	if err := runHook(t, root, `{"hook_event_name":"Stop"}`, "--agent", "watcher"); err != nil {
		t.Errorf("an event the hook has nothing to say about: %v", err)
	}
}

// TestTheHookReceiptsEveryCall: each call after it ran is a signed receipt
// in the agent's own sequence, with the outcome its event says, including
// calls made in parallel.
func TestTheHookReceiptsEveryCall(t *testing.T) {
	root, key, _ := hookSite(t)
	args := []string{"--agent", "watcher", "--key", key, "--issuer", "https://dev.test/claude-code", "--target", "claude-code://dev"}
	post := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"stdout":"a"}}`
	fail := `{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_input":{"command":"rm x"},"tool_response":"no such file"}`
	if err := runHook(t, root, post, args...); err != nil {
		t.Fatal(err)
	}
	if err := runHook(t, root, fail, args...); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := hookEvent{Tool: "Read", Input: []byte(fmt.Sprintf(`{"file_path":"/f%d"}`, i))}
			if err := hookReceipt(root, "watcher", key, "https://dev.test/claude-code", "claude-code://dev", nil, ev, "ok", time.Now()); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	l, _ := receiptlog.Open(filepath.Join(root, "receipts"), "")
	seqs := map[uint64]bool{}
	var outcomes []string
	l.Each(func(_ int, e []byte) error {
		_, r, err := aep.ReadReceipt(e)
		if err != nil {
			return err
		}
		seqs[r.Seq] = true
		if r.Tool == "Bash" {
			outcomes = append(outcomes, r.Outcome)
		}
		if r.Vantage != "agent" || r.Actor != "watcher" || r.Target != "claude-code://dev" {
			t.Errorf("%+v", r)
		}
		return nil
	})
	if len(seqs) != 14 || !seqs[0] || !seqs[13] || strings.Join(outcomes, ",") != "ok,error" {
		t.Errorf("sequence %v, outcomes %v", seqs, outcomes)
	}
	os.RemoveAll(filepath.Join(root, "receipts"))
	if err := runHook(t, root, post, args...); err == nil || !strings.Contains(err.Error(), "receipt init") {
		t.Errorf("no receipt log: %v", err)
	}
}

// TestTheAgentAndTheServerAgree: Claude Code calls this deployment's own
// agent interface. The hook receipts the call from the agent's side, the
// interface from the server's, and the two reconcile.
func TestTheAgentAndTheServerAgree(t *testing.T) {
	root, key, pub := hookSite(t)
	if err := cmdConfig(root, []string{"set", "admin.base_url", "https://aertun.test"}); err != nil {
		t.Fatal(err)
	}
	c := runCaller(t, root, mintRun(t, root, "nightly-1", []string{"aertun_read"}, "", 0, -1))
	at := time.Now().UTC()
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"aertun_read","arguments":{"operation":"list_findings"}}}` + "\n"
	var outBuf bytes.Buffer
	if err := serveStdio(root, buildMCP(root, c), c, strings.NewReader(call), &outBuf); err != nil {
		t.Fatal(err)
	}
	post := `{"hook_event_name":"PostToolUse","tool_name":"mcp__aertun__aertun_read","tool_input":{"operation":"list_findings"},"tool_response":{}}`
	if err := runHook(t, root, post, "--agent", "watcher", "--key", key, "--issuer", "https://dev.test/claude-code",
		"--mcp", "aertun=https://aertun.test/mcp"); err != nil {
		t.Fatal(err)
	}

	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil || saveTokens(root, ts) != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", secret)
	dir := t.TempDir()
	logKey := filepath.Join(dir, "log.json")
	if err := cmdReceipt(root, []string{"export", "--out", dir, "--log-key", logKey}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.cose"))
	if len(files) != 2 {
		t.Fatalf("%d receipts exported", len(files))
	}
	auditor, _ := signingFiles(t)
	args := append([]string{"reconcile"}, files...)
	args = append(args, "--key", auditor, "--issuer", "https://auditor.test",
		"--from", at.Add(-time.Minute).Format(time.RFC3339), "--to", at.Add(time.Minute).Format(time.RFC3339),
		"--tolerance", "10s", "--expect", "https://dev.test/claude-code=agent", "--expect", "https://aertun.test/mcp=target",
		"--issuer-key", "https://dev.test/claude-code="+pub, "--issuer-key", "https://aertun.test/mcp="+logKey,
		"--log-key", logKey, "--out", filepath.Join(dir, "r.cose"))
	if err := cmdReceipt("", args); err != nil {
		t.Fatalf("the agent's account and the server's do not agree: %v", err)
	}
}
