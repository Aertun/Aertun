// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/mcp"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/scitt"
)

// The agent interface's own receipts: once a receipt log is set up (the
// first `aertun receipt register --log-name`), every tools/call this
// deployment answers is appended to it as an action receipt from the
// target's vantage, issued as the interface's resource and signed with the
// log's key. An agent's own receipts and its gateway's then reconcile
// against what the server it called says it was asked, with no change to
// the agent. Receipts for the log's entries come on demand (`aertun receipt
// export`), so a call costs one signature and one append.

// receiptLogs keeps each store's log open across calls, so the interface
// reads only what was appended since its last call.
var receiptLogs sync.Map

func openReceiptLog(root string) (*receiptlog.Log, error) {
	if l, ok := receiptLogs.Load(root); ok {
		return l.(*receiptlog.Log), nil
	}
	dir := filepath.Join(root, "receipts")
	if !receiptlog.Exists(dir) {
		return nil, nil
	}
	l, err := receiptlog.Open(dir, "")
	if err != nil {
		return nil, err
	}
	actual, _ := receiptLogs.LoadOrStore(root, l)
	return actual.(*receiptlog.Log), nil
}

// stdioResources is the resource each store's stdio interface answers as:
// the configured public address, when there is one. A process on a pipe
// has no address of its own, and a receipt naming one the agent does not
// would match nothing.
var stdioResources sync.Map

func stdioResource(root string) string {
	if r, ok := stdioResources.Load(root); ok {
		return r.(string)
	}
	resource := ""
	if cfg, err := loadConfig(root); err == nil {
		if base := cfg.Raw("admin.base_url"); base != "" {
			resource = strings.TrimRight(base, "/") + "/mcp"
		}
	}
	stdioResources.Store(root, resource)
	return resource
}

// receiptMCPCall appends the receipt for one tools/call, whichever
// transport carried it. Reported rather than returned, as the audit record
// is: the call has happened and the caller has its answer.
func receiptMCPCall(root, resource string, c *Caller, params json.RawMessage, rerr *mcp.Error) {
	if resource == "" {
		return
	}
	if err := appendCallReceipt(root, resource, c, params, rerr, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "%sthe receipt for an agent interface call was not kept: %v%s\n", red, err, reset)
	}
}

func appendCallReceipt(root, resource string, c *Caller, params json.RawMessage, rerr *mcp.Error, now time.Time) error {
	l, err := openReceiptLog(root)
	if err != nil || l == nil {
		return err
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		// Refused before it named a tool, so not a call to one.
		return nil
	}
	args, err := aep.ArgsDigest(p.Arguments)
	if err != nil {
		return err
	}
	outcome := "ok"
	if rerr != nil {
		outcome = "error"
		if rerr.Code == mcp.CodeRefused {
			outcome = "refused"
		}
	}
	actor := c.Name
	if c.Agent != "" {
		actor = c.Agent
	}
	r := aep.Receipt{Action: aep.Action{Target: resource, Tool: p.Name, Args: args}, Vantage: "target",
		At: now, Actor: actor, Grant: c.Run, Outcome: outcome}
	b, err := aep.Emit(l.Signer(), resource, r, now)
	if err != nil {
		return err
	}
	_, err = l.Append(b, func(*scitt.Signed) error { return nil })
	return err
}
