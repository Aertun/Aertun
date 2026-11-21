// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/scitt"
)

// `aertun hook claude-code`: a coding agent under this deployment's kill
// switch, with a signed receipt for everything it does.
//
// Claude Code runs the command on PreToolUse, PostToolUse and
// PostToolUseFailure, with the event as JSON on standard input.
//
//   - Before a tool runs, the agent must be registered here and active.
//     Disabled (`aertun agent disable`), unregistered, or a registry that
//     cannot be read: the call is refused, exit 2 with the reason on
//     standard error, which is how a hook says no. Every other exit lets
//     the call go ahead, so this command refuses by exit 2 and nothing
//     else.
//   - After it ran, an AEP action receipt from the agent's vantage is
//     signed with the agent's key and appended to the receipt log,
//     numbered in the agent's own sequence, with the outcome the event
//     says. An MCP tool (mcp__SERVER__TOOL) is receipted under the server's
//     resource and the server's own name for the tool when --mcp maps the
//     server, so the receipt lines up with the one the server makes; a
//     built-in tool is receipted under --target.
//
// The settings, in ~/.claude/settings.json or a project's
// .claude/settings.json:
//
//	{"hooks": {
//	  "PreToolUse":         [{"matcher": "*", "hooks": [{"type": "command", "command": "aertun hook claude-code --agent NAME --key F --issuer URI"}]}],
//	  "PostToolUse":        [{"matcher": "*", "hooks": [{"type": "command", "command": "...the same..."}]}],
//	  "PostToolUseFailure": [{"matcher": "*", "hooks": [{"type": "command", "command": "...the same..."}]}]}}

// MaxHookInput bounds the event read from standard input; a tool's input
// and response can be large, and are digested, never kept.
const MaxHookInput = 16 << 20

// hookStdin is where the event is read from.
var hookStdin io.Reader = os.Stdin

// errHookDeny is a refusal Claude Code must see as one: exit 2.
type errHookDeny struct{ reason string }

func (e errHookDeny) Error() string { return e.reason }

type hookEvent struct {
	Event string          `json:"hook_event_name"`
	Tool  string          `json:"tool_name"`
	Input json.RawMessage `json:"tool_input"`
}

const hookUsage = `usage: aertun hook claude-code --agent NAME --key F --issuer URI [--target URI] [--mcp SERVER=URL]...`

func cmdHook(root string, args []string) error {
	if len(args) == 0 || args[0] != "claude-code" {
		return errors.New(hookUsage)
	}
	fs := flag.NewFlagSet("hook claude-code", flag.ContinueOnError)
	agent := fs.String("agent", "", "the agent as registered here (aertun agent add)")
	keyAt := fs.String("key", "", "the agent's dual signing key file")
	issuer := fs.String("issuer", "", "who the receipts are from: the agent's identifier, a URI")
	host, _ := os.Hostname()
	target := fs.String("target", "claude-code://"+host, "the resource built-in tools act on")
	var mcp multiFlag
	fs.Var(&mcp, "mcp", "SERVER=URL: an MCP server's name in this agent's settings, and its resource")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *agent == "" || fs.NArg() != 0 {
		return errors.New(hookUsage)
	}
	body, err := io.ReadAll(io.LimitReader(hookStdin, MaxHookInput+1))
	if err != nil {
		return err
	}
	if len(body) > MaxHookInput {
		return fmt.Errorf("the hook's event is past %d bytes", MaxHookInput)
	}
	var ev hookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return fmt.Errorf("the hook's event is not JSON: %w", err)
	}
	switch ev.Event {
	case "PreToolUse":
		return hookGate(root, *agent)
	case "PostToolUse", "PostToolUseFailure":
		if *keyAt == "" || *issuer == "" {
			return errors.New("receipts need --key and --issuer\n" + hookUsage)
		}
		servers := map[string]string{}
		for _, m := range mcp {
			name, url, ok := strings.Cut(m, "=")
			if !ok || name == "" || url == "" {
				return fmt.Errorf("--mcp is SERVER=URL, not %q", m)
			}
			servers[name] = url
		}
		outcome := "ok"
		if ev.Event == "PostToolUseFailure" {
			outcome = "error"
		}
		return hookReceipt(root, *agent, *keyAt, *issuer, *target, servers, ev, outcome, time.Now())
	}
	return nil // an event this hook has nothing to say about
}

// hookGate refuses a registered agent's call unless it is active: the
// same kill switch the agent interface obeys.
func hookGate(root, name string) error {
	a, found, err := agentStore(root).Get(name)
	switch {
	case err != nil:
		return errHookDeny{fmt.Sprintf("aertun: the agent registry could not be read, so nothing %s does is "+
			"authorised: %v", name, err)}
	case !found:
		return errHookDeny{fmt.Sprintf("aertun: no agent %q is registered here, so it may not act "+
			"(aertun agent add %s --owner WHO)", name, name)}
	case a.Status != agentreg.Active:
		why := a.DisabledWhy
		if why == "" {
			why = "no reason was given"
		}
		return errHookDeny{fmt.Sprintf("aertun: agent %q is disabled (%s), so every tool call is refused "+
			"until somebody enables it", name, why)}
	}
	return nil
}

// toolTarget is the resource and tool name a call is receipted under.
func toolTarget(tool, builtin string, servers map[string]string) (string, string) {
	rest, ok := strings.CutPrefix(tool, "mcp__")
	if !ok {
		return builtin, tool
	}
	server, name, ok := strings.Cut(rest, "__")
	if !ok || name == "" {
		return builtin, tool
	}
	if url, mapped := servers[server]; mapped {
		return url, name
	}
	return builtin, tool
}

func hookReceipt(root, agent, keyAt, issuer, builtin string, servers map[string]string, ev hookEvent,
	outcome string, now time.Time) error {

	dir := filepath.Join(root, "receipts")
	if !receiptlog.Exists(dir) {
		return errors.New("there is no receipt log here: aertun receipt init --log-name URI sets one up")
	}
	if ev.Tool == "" {
		return errors.New("the hook's event names no tool")
	}
	args, err := aep.ArgsDigest(ev.Input)
	if err != nil {
		return err
	}
	k, err := loadSigningKey(keyAt)
	if err != nil {
		return err
	}
	signer, _, err := receiptlog.Signers(k)
	if err != nil {
		return err
	}
	resource, tool := toolTarget(ev.Tool, builtin, servers)
	seq, err := nextSeq(dir, issuer)
	if err != nil {
		return err
	}
	r := aep.Receipt{Action: aep.Action{Target: resource, Tool: tool, Args: args}, Vantage: "agent", At: now,
		Actor: agent, Outcome: outcome, Seq: seq, HasSeq: true}
	b, err := aep.Emit(signer, issuer, r, now)
	if err != nil {
		return err
	}
	l, err := receiptlog.Open(dir, "")
	if err != nil {
		return err
	}
	_, err = l.Append(b, func(*scitt.Signed) error { return nil })
	return err
}

// nextSeq hands out an issuer's next sequence number. Hooks for parallel
// tool calls run at once, so the counter is taken under a lock; a number
// taken and never used shows as a gap, which is what a gap is for.
func nextSeq(dir, issuer string) (uint64, error) {
	sum := sha256.Sum256([]byte(issuer))
	path := filepath.Join(dir, "seq", hex.EncodeToString(sum[:8])+".json")
	var n uint64
	err := atomicfile.Update(path, func(c *struct {
		Issuer string `json:"issuer"`
		Next   uint64 `json:"next"`
	}) error {
		if c.Issuer != "" && c.Issuer != issuer {
			return fmt.Errorf("the sequence file %s belongs to %s", path, c.Issuer)
		}
		c.Issuer, n = issuer, c.Next
		c.Next++
		return nil
	})
	return n, err
}
