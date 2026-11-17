// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

const (
	pSafe     = "0x1111111111111111111111111111111111111111"
	pTimelock = "0x2222222222222222222222222222222222222222"
	pProxy    = "0x3333333333333333333333333333333333333333"
	pImpl     = "0x4444444444444444444444444444444444444444"
	pHash     = "0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	// pCredential is in the endpoint's path and query, as a hosted
	// provider's credential is, and must appear nowhere it is written.
	pCredential = "c0ffee-project-credential"
)

const pPosture = `{
  "name": "example-protocol",
  "chain_id": 1,
  "safes": [{"address": "` + pSafe + `", "min_threshold": 5, "min_owners": 9}],
  "timelocks": [{"address": "` + pTimelock + `", "min_delay_seconds": 172800}],
  "proxies": [{"address": "` + pProxy + `", "admin": "` + pTimelock + `", "implementation": "` + pImpl + `"}]
}`

// rpcNode is a JSON-RPC endpoint for chain 1 at one finalized block, which
// answers each call from answers by contract and selector or slot; a value
// beginning "!" is a JSON-RPC error.
func rpcNode(t *testing.T, answers map[string]string) *httptest.Server {
	t.Helper()
	word := func(n int) string { return fmt.Sprintf("%064x", n) }
	addr := func(a string) string { return strings.Repeat("0", 24) + a[2:] }
	owners := "0x" + word(32) + word(9)
	for i := range 9 {
		owners += addr(fmt.Sprintf("0x%040x", 0xa0+i))
	}
	held := map[string]string{
		pSafe + "0xe75235b8":     "0x" + word(5),
		pSafe + "0xa0e67e2b":     owners,
		pTimelock + "0xf27a0c92": "0x" + word(172800),
		pProxy + "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "0x" + addr(pTimelock),
		pProxy + "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "0x" + addr(pImpl),
	}
	for k, v := range answers {
		held[k] = v
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		key := ""
		switch req.Method {
		case "eth_chainId":
			reply["result"] = "0x1"
		case "eth_getBlockByNumber":
			reply["result"] = map[string]string{"number": "0x1406f40", "hash": pHash}
		case "eth_call":
			var call struct{ To, Data string }
			_ = json.Unmarshal(req.Params[0], &call)
			key = call.To + call.Data
		case "eth_getStorageAt":
			var contract, slot string
			_ = json.Unmarshal(req.Params[0], &contract)
			_ = json.Unmarshal(req.Params[1], &slot)
			key = contract + slot
		}
		if key != "" {
			v := held[key]
			if strings.HasPrefix(v, "!") {
				reply["error"] = map[string]any{"code": -32000, "message": "execution reverted at " + r.URL.String()}
			} else {
				reply["result"] = v
			}
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// chainPostureProof runs the command against a node and returns what it
// signed, with the proof's file.
func chainPostureProof(t *testing.T, root string, srv *httptest.Server, extra ...string) (*proof.Statement, string, error) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "posture.json")
	if err := os.WriteFile(file, []byte(pPosture), 0o600); err != nil {
		t.Fatal(err)
	}
	key, pub := signingFiles(t)
	at := filepath.Join(dir, "posture.proof.json")
	err := cmdChain(root, append([]string{"posture", file,
		"--rpc", srv.URL + "/v3/" + pCredential + "?key=" + pCredential, "--reach", "127.0.0.1/32",
		"--key", key, "--public-key", pub, "--out", at}, extra...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), at, err
}

// A posture whose every setting holds at the finalized block is proven over
// the posture file's canonical digest, kept, and recorded — and the
// endpoint's credential is in none of them.
func TestAPostureThatHoldsIsProvenAndKept(t *testing.T) {
	root := reconcileSite(t)
	srv := rpcNode(t, nil)
	st, at, err := chainPostureProof(t, root, srv)
	ev := st.Predicate.ChainPosture
	if err != nil || st.Predicate.Verdict != proof.Proven || ev == nil || ev.Held != 5 ||
		ev.Block != 21000000 || ev.BlockHash != pHash || !ev.Finalized {
		t.Fatalf("%v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks)
	}
	canonical, _ := jcs.Canonicalize([]byte(pPosture))
	if st.Subject[0].Name != "chain/1/example-protocol" ||
		st.Subject[0].Digest["sha256"] != proof.SHA256(canonical)["sha256"] {
		t.Errorf("the subject is not the canonical posture file: %+v", st.Subject)
	}
	if len(st.Predicate.Materials) != 1 || st.Predicate.Materials[0].Name != "chain-state" ||
		st.Predicate.Materials[0].Entries != 7 {
		t.Errorf("the materials: %+v", st.Predicate.Materials)
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 1 || kept[0].Statement == nil || kept[0].Statement.Predicate.ChainPosture == nil {
		t.Errorf("the proof was not kept: %+v", kept)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var recorded *audit.Event
	for i := range events {
		if events[i].Action == "chain.posture-proved" {
			recorded = &events[i]
		}
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	if recorded == nil || recorded.Detail["endpoint"] != host || recorded.Detail["verdict"] != "proven" ||
		recorded.Detail["block_hash"] != pHash {
		t.Errorf("the record: %+v", recorded)
	}
	for _, f := range []string{at, auditPath(root)} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), pCredential) {
			t.Errorf("%s carries the endpoint's credential", f)
		}
	}
}

// A threshold lowered, a delay emptied and an admin moved each refute the
// posture, named by contract, setting, declared and found.
func TestARegressedSettingRefutesThePosture(t *testing.T) {
	root := reconcileSite(t)
	srv := rpcNode(t, map[string]string{
		pSafe + "0xe75235b8":     "0x" + fmt.Sprintf("%064x", 2),
		pTimelock + "0xf27a0c92": "0x" + fmt.Sprintf("%064x", 0),
		pProxy + "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "0x" +
			strings.Repeat("0", 24) + strings.Repeat("5", 40),
	})
	st, _, err := chainPostureProof(t, root, srv, "--block", "21000000")
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.ChainPosture.Regressed != 3 ||
		st.Predicate.ChainPosture.Finalized {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.ChainPosture)
	}
	want := pSafe + " safe-threshold: declared at least 5, found 2|" +
		pTimelock + " timelock-delay: declared at least 172800, found 0|" +
		pProxy + " proxy-admin: declared " + pTimelock + ", found 0x" + strings.Repeat("5", 40)
	if got := strings.Join(st.Predicate.Checks[1].Failures, "|"); got != want {
		t.Errorf("named %q, want %q", got, want)
	}
}

// A contract that does not answer as its kind does leaves the posture
// inconclusive, saying which setting and why; what the endpoint said in its
// error is not repeated.
func TestAnUnreadSettingLeavesThePostureInconclusive(t *testing.T) {
	root := reconcileSite(t)
	srv := rpcNode(t, map[string]string{pTimelock + "0xf27a0c92": "!revert"})
	st, at, err := chainPostureProof(t, root, srv)
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.ChainPosture.Unread != 1 ||
		!strings.Contains(st.Predicate.Checks[2].Detail, pTimelock+" timelock-delay (rpc-error)") {
		t.Fatalf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}
	b, _ := os.ReadFile(at)
	if strings.Contains(string(b), "reverted") || strings.Contains(string(b), pCredential) {
		t.Error("the endpoint's own words reached the proof")
	}
}

// What a posture proof starts from has to be readable: the arguments, the
// endpoint, and a chain that is the one declared. None of the refusals
// repeats the endpoint's URL, and none writes a proof.
func TestAChainPostureProofStartsFromWhatItCanRead(t *testing.T) {
	root := reconcileSite(t)
	srv := rpcNode(t, nil)
	key, _ := signingFiles(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "posture.json")
	if err := os.WriteFile(file, []byte(pPosture), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other-chain.json")
	if err := os.WriteFile(other, []byte(strings.Replace(pPosture, `"chain_id": 1`, `"chain_id": 10`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	rpc := srv.URL + "/v3/" + pCredential
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"posture", "--rpc", rpc, "--key", key}, "takes FILE --rpc URL --key FILE"},
		{[]string{"posture", file, "--key", key}, "takes FILE --rpc URL --key FILE"},
		{[]string{"posture", file, "--rpc", rpc, "--key", key, "--reach", "127.0.0.1/32", "--block", "latest"}, "--block"},
		{[]string{"posture", file, "--rpc", rpc, "--key", key, "--reach", "169.254.169.254/32"}, "cannot be reached"},
		{[]string{"posture", file, "--rpc", rpc, "--key", key}, "loopback"},
		{[]string{"posture", file, "--rpc", "http://rpc.example.org/v3/" + pCredential, "--key", key}, "plain http"},
		{[]string{"posture", other, "--rpc", rpc, "--key", key, "--reach", "127.0.0.1/32"}, "serves chain 1, and the posture declares chain 10"},
		{[]string{"lineage"}, "try posture"},
		{nil, "chain needs posture"},
	}
	for _, c := range cases {
		err := cmdChain(root, c.args)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), pCredential) {
			t.Errorf("%v: the refusal repeats the endpoint's URL: %v", c.args, err)
		}
	}
	if kept, _ := proofstore.List(root); len(kept) != 0 {
		t.Errorf("a refusal kept a proof: %+v", kept)
	}
}
