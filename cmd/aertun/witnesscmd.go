// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

// `aertun witness agentgateway`: this deployment as the policy server that
// agentgateway's mcpGuardrails calls for every tools/call (internal/extmcp).
// Aertun does not become a gateway; the gateway it already runs becomes a
// witness. For each call it signs, in the gateway's name, a receipt that
// the gateway saw it, from the gateway's vantage, with the outcome the
// response showed, and appends it where every other party's receipts are
// held against it. It also applies the kill switch at the gateway: a
// disabled agent's call is refused before it reaches the server, and the
// refusal is receipted too.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/extmcp"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/scitt"
)

const witnessUsage = `usage:
  aertun witness agentgateway --issuer URI --key F --secret-file F [--listen 127.0.0.1:9001] [--backend NAME=URI]... [--allow-unregistered] [--deadline 10m] [--listen-any]`

// The metadata keys the gateway is configured to send: who is calling, the
// secret that says it is the gateway, and the call's own token, handed out
// on the request and read back on the response.
const (
	witnessActorKey  = "actor"
	witnessSecretKey = "aertun_secret"
	witnessCallKey   = "aertun_call"
)

// Bounds on what one gateway, or whatever reaches the port, can make the
// witness hold or write.
const (
	witnessMaxPending   = 10000
	witnessRefusalBurst = 30 // refusal receipts per caller per minute
	witnessQueue        = 1024
)

func cmdWitness(root string, args []string) error {
	if len(args) == 0 || args[0] != "agentgateway" {
		return errors.New(witnessUsage)
	}
	return witnessAgentgateway(root, args[1:])
}

func witnessAgentgateway(root string, args []string) error {
	fs := flag.NewFlagSet("witness agentgateway", flag.ContinueOnError)
	issuer := fs.String("issuer", "", "the gateway's issuer URI, as its receipts name it")
	keyAt := fs.String("key", "", "the dual signing key the gateway's receipts are signed with (aertun content keygen makes one)")
	secretAt := fs.String("secret-file", "", "the secret the gateway sends to say it is the gateway; made here, 0600, if absent")
	listen := fs.String("listen", "127.0.0.1:9001", "where agentgateway's remote processor connects, over cleartext HTTP/2")
	listenAny := fs.Bool("listen-any", false, "listen beyond this host, knowing the calls arrive in clear text")
	allowUnregistered := fs.Bool("allow-unregistered", false, "receipt a named caller the agent registry does not hold instead of refusing it")
	deadline := fs.Duration("deadline", 10*time.Minute, "how long a call may wait for its response before it is receipted with no outcome")
	backends := map[string]string{}
	fs.Func("backend", "NAME=URI: the target a backend's calls are receipted under, as the server's own receipts name it (repeat)",
		func(s string) error {
			name, uri, ok := strings.Cut(s, "=")
			if !ok || name == "" || uri == "" {
				return errors.New("--backend is NAME=URI")
			}
			backends[name] = uri
			return nil
		})
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuer == "" || *keyAt == "" || *secretAt == "" || fs.NArg() != 0 {
		return errors.New("witness agentgateway needs --issuer URI --key FILE --secret-file FILE\n" + witnessUsage)
	}
	if err := scitt.CheckClaim("issuer", *issuer); err != nil {
		return err
	}
	if *deadline < time.Second || *deadline > 24*time.Hour {
		return errors.New("--deadline is between 1s and 24h")
	}
	if !*listenAny {
		if loop, err := loopback(*listen); err != nil {
			return err
		} else if !loop {
			return fmt.Errorf("%s is reachable beyond this host, and agentgateway's calls arrive in clear "+
				"text: keep it on loopback, or in the gateway's pod, or say --listen-any", *listen)
		}
	}
	caller := resolveCaller(root, flagToken)
	// Tune, as registering a receipt is: each is signed in a party's name
	// and appended to this deployment's log.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	dir := filepath.Join(root, "receipts")
	if !receiptlog.Exists(dir) {
		return errors.New("there is no receipt log here: aertun receipt init --log-name URI sets one up")
	}
	secret, made, err := witnessSecret(*secretAt)
	if err != nil {
		return err
	}
	l, err := receiptlog.Open(dir, "")
	if err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	signer, _, err := receiptlog.Signers(k)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	wt := newAgwWitness(root, dir, l, signer, *issuer, secret, backends, *allowUnregistered, *deadline)
	if err := recordE(root, caller.auditRecord("witness.started", "/receipts", audit.Success,
		map[string]string{"gateway": "agentgateway", "issuer": *issuer, "listen": ln.Addr().String()})); err != nil {
		ln.Close()
		return err
	}
	if made {
		w.Human("  %smade the gateway's secret in %s (0600)%s\n", dim, *secretAt, reset)
	}
	w.Human("%switnessing agentgateway on %s%s, as %s\n%s", bold, ln.Addr(), reset, *issuer,
		agwConfig(ln.Addr().String(), *secretAt))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = wt.serve(ctx, ln)
	stats := wt.stats()
	if rerr := recordE(root, caller.auditRecord("witness.stopped", "/receipts", audit.Success,
		map[string]string{"gateway": "agentgateway", "issuer": *issuer, "receipted": fmt.Sprint(stats.receipted),
			"refused": fmt.Sprint(stats.refused), "unanswered": fmt.Sprint(stats.unanswered),
			"failed": fmt.Sprint(stats.failed), "unreceipted_refusals": fmt.Sprint(stats.quiet),
			"strangers": fmt.Sprint(stats.strangers)})); rerr != nil && err == nil {
		err = rerr
	}
	w.Human("stopped: %d receipted, %d refused (%d more past the rate, unreceipted), %d with no response "+
		"in time, %d could not be written, %d calls without the gateway's secret\n",
		stats.receipted, stats.refused, stats.quiet, stats.unanswered, stats.failed, stats.strangers)
	return err
}

// witnessSecret reads the gateway's secret from path, or makes one there
// when there is none. It is never printed: the operator copies it into the
// gateway's configuration from the file.
func witnessSecret(path string) (secret []byte, made bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		var raw [32]byte
		rand.Read(raw[:])
		s := hex.EncodeToString(raw[:])
		if err := atomicfile.Write(path, []byte(s+"\n"), 0o600); err != nil {
			return nil, false, err
		}
		return []byte(s), true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info, err := os.Stat(path); err != nil {
		return nil, false, err
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf("%s is readable by others (mode %04o); the gateway's secret must be 0600",
			path, info.Mode().Perm())
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 32 {
		return nil, false, fmt.Errorf("%s holds fewer than 32 characters, which is not a secret", path)
	}
	return []byte(s), false, nil
}

// agwConfig is the processor an operator adds to agentgateway's route.
func agwConfig(addr, secretAt string) string {
	return fmt.Sprintf(`
  add to the route's policies in agentgateway, as the LAST processor: one
  after it could still refuse or rewrite a call this has receipted.

    mcpGuardrails:
      processors:
      - kind: remote
        host: %s
        failureMode: failClosed
        methods:
          tools/call: full
        metadata:
          %s: jwt.sub   # who is calling, from the gateway's own authentication
          %s: '"<the contents of %s>"'
          %s: mcpGuardrails.%s

`, addr, witnessActorKey, witnessSecretKey, secretAt, witnessCallKey, witnessCallKey)
}

// loopback reports whether addr listens on this host alone.
func loopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("--listen %s: %w", addr, err)
	}
	if host == "localhost" {
		return true, nil
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback(), nil
}

// agwWitness is the policy agentgateway calls.
type agwWitness struct {
	root, dir, issuer string
	secret            []byte
	log               *receiptlog.Log
	signer            cose.Signer
	backends          map[string]string
	allowUnregistered bool
	deadline          time.Duration
	maxPending        int
	refusalBurst      int
	now               func() time.Time

	mu       sync.Mutex
	pending  map[string]agwCall
	refusals map[string][]time.Time
	stopping bool
	count    agwStats

	// One writer, in order: the gateway is answered at once, and the
	// receipts are numbered in the order they were made.
	queue   chan agwIssue
	written sync.WaitGroup
	writer  sync.WaitGroup
}

// agwCall is a call the gateway passed, waiting for its response.
type agwCall struct {
	receipt aep.Receipt
	since   time.Time
}

// agwIssue is one receipt to write, and the count it goes to.
type agwIssue struct {
	receipt aep.Receipt
	at      time.Time
	tally   *int
}

type agwStats struct{ receipted, refused, unanswered, failed, quiet, strangers int }

func newAgwWitness(root, dir string, l *receiptlog.Log, signer cose.Signer, issuer string, secret []byte,
	backends map[string]string, allowUnregistered bool, deadline time.Duration) *agwWitness {
	wt := &agwWitness{root: root, dir: dir, log: l, signer: signer, issuer: issuer, secret: secret,
		backends: backends, allowUnregistered: allowUnregistered, deadline: deadline,
		maxPending: witnessMaxPending, refusalBurst: witnessRefusalBurst, now: time.Now,
		pending: map[string]agwCall{}, refusals: map[string][]time.Time{},
		queue: make(chan agwIssue, witnessQueue)}
	wt.writer.Add(1)
	go wt.write()
	return wt
}

func (wt *agwWitness) stats() agwStats {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	return wt.count
}

// issue hands one receipt to the writer.
func (wt *agwWitness) issue(r aep.Receipt, at time.Time, tally *int) {
	wt.written.Add(1)
	wt.queue <- agwIssue{receipt: r, at: at, tally: tally}
}

// write is the writer: it numbers, signs and appends each receipt, and
// counts it, or counts and reports that it could not be written. A witness
// that stays silent about its own failure is not one.
func (wt *agwWitness) write() {
	defer wt.writer.Done()
	for job := range wt.queue {
		err := issueReceipt(wt.dir, wt.log, wt.signer, wt.issuer, job.receipt, job.at)
		wt.mu.Lock()
		if err != nil {
			wt.count.failed++
			fmt.Fprintf(os.Stderr, "aertun witness: the receipt for %q on %q could not be written: %v\n",
				job.receipt.Tool, job.receipt.Target, err)
		} else {
			*job.tally++
		}
		wt.mu.Unlock()
		wt.written.Done()
	}
}

// flush waits until every receipt handed to the writer is written.
func (wt *agwWitness) flush() { wt.written.Wait() }

// close stops the writer once what it holds is written.
func (wt *agwWitness) close() {
	close(wt.queue)
	wt.writer.Wait()
}

// fromGateway reports whether the call carries the gateway's secret.
func (wt *agwWitness) fromGateway(meta map[string]any) bool {
	got, _ := meta[witnessSecretKey].(string)
	return subtle.ConstantTimeCompare([]byte(got), wt.secret) == 1
}

// target is the resource a call's receipt names: the backend's mapped
// URI, or a name that says plainly it is agentgateway's backend.
func (wt *agwWitness) target(names []string) string {
	if len(names) != 1 {
		return "urn:agentgateway:backends:" + strings.Join(names, ",")
	}
	if uri, ok := wt.backends[names[0]]; ok {
		return uri
	}
	return "urn:agentgateway:backend:" + names[0]
}

// refusal is the kill switch at the gateway. A caller the gateway did not
// name is refused whatever the flags say: a receipt with no actor holds
// nobody to anything.
func (wt *agwWitness) refusal(actor string) string {
	if actor == "" {
		return "aertun: the gateway did not say who is calling, so the call is refused " +
			"(map an identity into the processor's metadata as " + witnessActorKey + ")"
	}
	return agentRefusal(wt.root, actor, wt.allowUnregistered)
}

// refuse answers a call with a denial and, within the caller's rate,
// receipts the refusal: a refused agent retrying in a loop must not fill
// the log every party writes to.
func (wt *agwWitness) refuse(r aep.Receipt, code extmcp.Code, why string) *extmcp.RequestResult {
	now := wt.now()
	wt.mu.Lock()
	recent := wt.refusals[r.Actor][:0]
	for _, t := range wt.refusals[r.Actor] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	receipt := len(recent) < wt.refusalBurst
	if receipt {
		recent = append(recent, now)
	} else {
		wt.count.quiet++
	}
	if len(recent) == 0 {
		delete(wt.refusals, r.Actor)
	} else {
		wt.refusals[r.Actor] = recent
	}
	wt.mu.Unlock()
	if receipt {
		r.Outcome = "refused"
		wt.issue(r, now, &wt.count.refused)
	}
	return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: code, Reason: why}}
}

func (wt *agwWitness) CheckRequest(_ context.Context, req *extmcp.Request) (*extmcp.RequestResult, error) {
	if !wt.fromGateway(req.Metadata) {
		wt.mu.Lock()
		wt.count.strangers++
		wt.mu.Unlock()
		return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: extmcp.PermissionDenied,
			Reason: "aertun: this witness answers its own gateway, which sends its secret"}}, nil
	}
	if req.Method != "tools/call" {
		return &extmcp.RequestResult{}, nil
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: extmcp.Invalid,
			Reason: "aertun: the call names no tool"}}, nil
	}
	if len(p.Arguments) > aep.MaxArgs {
		return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: extmcp.Invalid,
			Reason: fmt.Sprintf("aertun: the arguments are over %d bytes, more than a receipt here digests, "+
				"so the call cannot be witnessed and is refused", aep.MaxArgs)}}, nil
	}
	args, err := aep.ArgsDigest(p.Arguments)
	if err != nil {
		return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: extmcp.Invalid, Reason: "aertun: " + err.Error()}}, nil
	}
	actor, _ := req.Metadata[witnessActorKey].(string)
	now := wt.now()
	r := aep.Receipt{Action: aep.Action{Target: wt.target(req.ServiceNames), Tool: p.Name, Args: args},
		Vantage: "gateway", At: now, Actor: actor}
	// What cannot be receipted is refused before it reaches the server,
	// not discovered after: a call the gateway passed is one it witnessed.
	if err := r.Check(); err != nil {
		return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: extmcp.Invalid,
			Reason: "aertun: the call cannot be witnessed: " + err.Error()}}, nil
	}
	if why := wt.refusal(actor); why != "" {
		return wt.refuse(r, extmcp.PermissionDenied, why), nil
	}
	var id [16]byte
	rand.Read(id[:])
	call := hex.EncodeToString(id[:])
	wt.mu.Lock()
	full, stopping := len(wt.pending) >= wt.maxPending, wt.stopping
	if !full && !stopping {
		wt.pending[call] = agwCall{receipt: r, since: now}
	}
	wt.mu.Unlock()
	if stopping {
		return &extmcp.RequestResult{Deny: &extmcp.Denial{Code: extmcp.ResourceExhaust,
			Reason: "aertun: the witness is stopping"}}, nil
	}
	if full {
		return wt.refuse(r, extmcp.ResourceExhaust,
			fmt.Sprintf("aertun: %d calls are waiting for their responses, as many as the witness holds", wt.maxPending)), nil
	}
	return &extmcp.RequestResult{Metadata: map[string]string{witnessCallKey: call}}, nil
}

func (wt *agwWitness) CheckResponse(_ context.Context, resp *extmcp.Response) (*extmcp.ResponseResult, error) {
	if resp.Method != "tools/call" || !wt.fromGateway(resp.Metadata) {
		return &extmcp.ResponseResult{}, nil
	}
	call, _ := resp.Metadata[witnessCallKey].(string)
	wt.mu.Lock()
	c, ok := wt.pending[call]
	delete(wt.pending, call)
	wt.mu.Unlock()
	if !ok {
		// Not a call this witness passed, or one already receipted when
		// its deadline ran out: the response goes on, and says nothing new.
		return &extmcp.ResponseResult{}, nil
	}
	var result struct {
		IsError bool `json:"isError"`
	}
	json.Unmarshal(resp.Result, &result)
	c.receipt.Outcome = "ok"
	if result.IsError {
		c.receipt.Outcome = "error"
	}
	// The call has run, and its response is never refused here: that would
	// hide the result without undoing anything. The receipt is written
	// after the answer, by the writer.
	wt.issue(c.receipt, wt.now(), &wt.count.receipted)
	return &extmcp.ResponseResult{}, nil
}

// sweep receipts every call whose response has not come by the deadline,
// or every call when all is true, with no outcome: an upstream error skips
// the response, and so does a call still running, and the witness cannot
// tell which.
func (wt *agwWitness) sweep(all bool) {
	now := wt.now()
	var due []agwCall
	wt.mu.Lock()
	for id, c := range wt.pending {
		if all || now.Sub(c.since) >= wt.deadline {
			due = append(due, c)
			delete(wt.pending, id)
		}
	}
	wt.mu.Unlock()
	for _, c := range due {
		wt.issue(c.receipt, now, &wt.count.unanswered)
	}
}

// serve answers agentgateway on ln until ctx ends, sweeping as it goes.
// Stopping, it takes no new call, receipts what is still waiting, and
// writes every receipt it holds before it returns.
func (wt *agwWitness) serve(ctx context.Context, ln net.Listener) error {
	srv := extmcp.Server("", wt)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	tick := time.NewTicker(min(wt.deadline/4, 30*time.Second))
	defer tick.Stop()
	var err error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err = <-done:
			break loop
		case <-tick.C:
			wt.sweep(false)
		}
	}
	wt.mu.Lock()
	wt.stopping = true
	wt.mu.Unlock()
	shut, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if serr := srv.Shutdown(shut); serr != nil {
		srv.Close()
	}
	wt.sweep(true)
	wt.close()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
