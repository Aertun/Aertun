// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aertun/aertun/internal/fetch"
	"github.com/aertun/aertun/internal/proof"
)

const (
	tSafe     = "0x1111111111111111111111111111111111111111"
	tTimelock = "0x2222222222222222222222222222222222222222"
	tProxy    = "0x3333333333333333333333333333333333333333"
	tImpl     = "0x4444444444444444444444444444444444444444"
	tHash     = "0x" + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

// thisMachine is the reach a test server on loopback needs: declared, as an
// operator would declare a node run beside this program.
var thisMachine = fetch.Within([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128")})

func uintWord(n uint64) string { return fmt.Sprintf("%064x", n) }

func addrWord(a string) string { return strings.Repeat("0", 24) + a[2:] }

// ownersData is getOwners()'s answer for these owners.
func ownersData(owners ...string) string {
	s := "0x" + uintWord(32) + uintWord(uint64(len(owners)))
	for _, o := range owners {
		s += addrWord(o)
	}
	return s
}

func owners(n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("0x%040x", 0xa0+i))
	}
	return out
}

// node is a JSON-RPC endpoint holding one chain at one block: answers to
// calls by contract and selector, and storage by contract and slot. An
// answer beginning "!" is a JSON-RPC error with that code.
type node struct {
	mu        sync.Mutex
	chainID   string
	block     string // the finalized block's number, or "" for none
	hash      string
	calls     map[string]string
	storage   map[string]string
	byNumber  bool // every read named the block by its hash, until this is set
	methods   []string
	raw       string // when set, every answer is this, whatever was asked
	rawStatus int
}

func healthyNode() *node {
	return &node{chainID: "0x1", block: "0x1406f40", hash: tHash,
		calls: map[string]string{
			tSafe + selectorGetThreshold:    "0x" + uintWord(5),
			tSafe + selectorGetOwners:       ownersData(owners(9)...),
			tTimelock + selectorGetMinDelay: "0x" + uintWord(172800),
		},
		storage: map[string]string{
			tProxy + slotAdmin:          "0x" + addrWord(tTimelock),
			tProxy + slotImplementation: "0x" + addrWord(tImpl),
		}}
}

func (n *node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.raw != "" {
		w.WriteHeader(max(n.rawStatus, 200))
		_, _ = w.Write([]byte(n.raw))
		return
	}
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil || req.Params == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	n.methods = append(n.methods, req.Method)
	answer := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}
	fail := func(code int) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": code, "message": "execution reverted: see " + r.URL.Path}})
	}
	str := func(i int) string {
		var s string
		if i < len(req.Params) {
			_ = json.Unmarshal(req.Params[i], &s)
		}
		return s
	}
	atHash := func(i int) bool {
		var at map[string]string
		if i >= len(req.Params) || json.Unmarshal(req.Params[i], &at) != nil || at["blockHash"] != n.hash {
			n.byNumber = true
			return false
		}
		return true
	}
	respond := func(v string) {
		var code int
		if _, err := fmt.Sscanf(v, "!%d", &code); err == nil {
			fail(code)
			return
		}
		answer(v)
	}
	switch req.Method {
	case "eth_chainId":
		answer(n.chainID)
	case "eth_getBlockByNumber":
		tag := str(0)
		if n.block == "" || (tag != "finalized" && tag != n.block) {
			answer(nil)
			return
		}
		answer(map[string]any{"number": n.block, "hash": n.hash, "miner": "0x00", "transactions": []string{}})
	case "eth_call":
		var call struct{ To, Data string }
		_ = json.Unmarshal(req.Params[0], &call)
		if !atHash(1) {
			fail(-32602)
			return
		}
		v, ok := n.calls[call.To+call.Data]
		if !ok {
			v = "0x"
		}
		respond(v)
	case "eth_getStorageAt":
		if !atHash(2) {
			fail(-32602)
			return
		}
		v, ok := n.storage[str(0)+str(1)]
		if !ok {
			v = "0x" + uintWord(0)
		}
		respond(v)
	default:
		fail(-32601)
	}
}

func posture(t *testing.T, body string) *Posture {
	t.Helper()
	p, _, err := ParsePosture([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const wholePosture = `{"name": "example-protocol", "chain_id": 1,
  "safes": [{"address": "` + tSafe + `", "min_threshold": 5, "min_owners": 9}],
  "timelocks": [{"address": "` + tTimelock + `", "min_delay_seconds": 172800}],
  "proxies": [{"address": "` + tProxy + `", "admin": "` + tTimelock + `", "implementation": "` + tImpl + `"}]}`

func serve(t *testing.T, n *node) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	c, err := Dial(srv.URL+"/v3/s3cr3t-project-credential?apikey=s3cr3t", thisMachine)
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func read(t *testing.T, c *Client, p *Posture, block int64) *Reading {
	t.Helper()
	r, err := Read(context.Background(), c, p, block)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func found(r *Reading) string {
	var parts []string
	for _, s := range r.Settings {
		v := s.Found
		if v == "" {
			v = "(" + s.Reason + ")"
		}
		parts = append(parts, s.Setting+"="+v)
	}
	return strings.Join(parts, " ")
}

// Every setting a posture declares is read, at the finalized block, and
// every read names that block by its hash.
func TestAPostureIsReadAtOneBlockByItsHash(t *testing.T) {
	n := healthyNode()
	c, _ := serve(t, n)
	r := read(t, c, posture(t, wholePosture), -1)
	want := "safe-threshold=5 safe-owners=9 timelock-delay=172800 proxy-admin=" + tTimelock +
		" proxy-implementation=" + tImpl
	if got := found(r); got != want {
		t.Errorf("read %s, want %s", got, want)
	}
	if r.ChainID != 1 || r.Block != 0x1406f40 || r.BlockHash != tHash || !r.Finalized {
		t.Errorf("the block: %+v", r)
	}
	if n.byNumber {
		t.Error("a read named the block by something other than its hash")
	}
	if lines := strings.Count(string(r.Lines), "\n"); r.Calls != 7 || lines != r.Calls ||
		len(n.methods) != r.Calls {
		t.Errorf("%d calls, %d lines, %d answered", r.Calls, lines, len(n.methods))
	}
	if r.Settings[0].Declared != "5" || r.Settings[3].Declared != tTimelock {
		t.Errorf("the declarations: %+v", r.Settings)
	}

	// A block named is read at, by its own hash, and not called finalized.
	r = read(t, c, posture(t, wholePosture), 0x1406f40)
	if r.Finalized || r.Block != 0x1406f40 {
		t.Errorf("the named block: %+v", r)
	}
}

// What a contract answers decides what is found; what is not its kind's
// answer is unread, with the reason.
func TestWhatAContractAnswersDecidesTheReading(t *testing.T) {
	big := "0x" + strings.Repeat("0", 48) + "0020000000000000"
	cases := map[string]struct {
		change func(*node)
		want   string
	}{
		"a lowered threshold is found as it is": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = "0x" + uintWord(2)
		}, "safe-threshold=2"},
		"no code at the Safe": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = "0x"
		}, "safe-threshold=(empty)"},
		"a revert": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = "!3"
		}, "safe-threshold=(rpc-error)"},
		"a threshold a byte too long": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = "0x00" + uintWord(5)
		}, "safe-threshold=(malformed)"},
		"a threshold past what a proof carries": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = big
		}, "safe-threshold=(out-of-range)"},
		"a threshold of none": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = "0x" + uintWord(0)
		}, "safe-threshold=(malformed)"},
		"a threshold above the owners": {func(n *node) {
			n.calls[tSafe+selectorGetThreshold] = "0x" + uintWord(10)
		}, "safe-threshold=(malformed) safe-owners=9"},
		"an owner twice": {func(n *node) {
			n.calls[tSafe+selectorGetOwners] = ownersData(append(owners(8), owners(1)...)...)
		}, "safe-owners=(malformed)"},
		"the zero address as an owner": {func(n *node) {
			n.calls[tSafe+selectorGetOwners] = ownersData(append(owners(8), proof.ZeroAddress)...)
		}, "safe-owners=(malformed)"},
		"no owners": {func(n *node) {
			n.calls[tSafe+selectorGetOwners] = ownersData()
		}, "safe-owners=(malformed)"},
		"owners at the wrong offset": {func(n *node) {
			n.calls[tSafe+selectorGetOwners] = "0x" + uintWord(64) + ownersData(owners(9)...)[66:]
		}, "safe-owners=(malformed)"},
		"owners with something after": {func(n *node) {
			n.calls[tSafe+selectorGetOwners] = ownersData(owners(9)...) + uintWord(1)
		}, "safe-owners=(malformed)"},
		"more owners than a proof carries": {func(n *node) {
			n.calls[tSafe+selectorGetOwners] = ownersData(owners(proof.MaxSafeOwners + 1)...)
		}, "safe-owners=(out-of-range)"},
		"an owner word with high bits": {func(n *node) {
			o := ownersData(owners(9)...)
			n.calls[tSafe+selectorGetOwners] = o[:130] + "ff" + o[132:]
		}, "safe-owners=(malformed)"},
		"an answer that is not hexadecimal": {func(n *node) {
			n.calls[tTimelock+selectorGetMinDelay] = "two days"
		}, "timelock-delay=(rpc-error)"},
		"a delay of nothing is found as nothing": {func(n *node) {
			n.calls[tTimelock+selectorGetMinDelay] = "0x" + uintWord(0)
		}, "timelock-delay=0"},
		"a delay past what a proof carries": {func(n *node) {
			n.calls[tTimelock+selectorGetMinDelay] = "0x" + strings.Repeat("f", 64)
		}, "timelock-delay=(out-of-range)"},
		"an empty implementation slot": {func(n *node) {
			delete(n.storage, tProxy+slotImplementation)
		}, "proxy-admin=(not-a-proxy) proxy-implementation=(not-a-proxy)"},
		"an admin slot that holds no address": {func(n *node) {
			n.storage[tProxy+slotAdmin] = "0x" + strings.Repeat("1", 64)
		}, "proxy-admin=(malformed)"},
		"a storage word cut short": {func(n *node) {
			n.storage[tProxy+slotAdmin] = "0x1"
		}, "proxy-admin=(rpc-error)"},
		"an admin renounced is found as the zero address": {func(n *node) {
			delete(n.storage, tProxy+slotAdmin)
		}, "proxy-admin=" + proof.ZeroAddress},
	}
	for name, cs := range cases {
		n := healthyNode()
		cs.change(n)
		c, _ := serve(t, n)
		r := read(t, c, posture(t, wholePosture), -1)
		if got := found(r); !strings.Contains(got, cs.want) {
			t.Errorf("%s: read %s, want %s", name, got, cs.want)
		}
	}
}

// The chain and the block are what a proof is about, so not knowing either
// is an error, not an unread setting; and the endpoint's own words never
// reach the message.
func TestTheChainAndTheBlockMustBeKnown(t *testing.T) {
	cases := map[string]struct {
		change func(*node)
		block  int64
		want   string
	}{
		"another chain": {func(n *node) { n.chainID = "0xa" }, -1,
			"serves chain 10, and the posture declares chain 1"},
		"no chain id": {func(n *node) { n.chainID = "mainnet" }, -1, "not a chain id"},
		"no finalized block": {func(n *node) { n.block = "" }, -1,
			"knows no finalized block; name a block"},
		"a block not there yet": {func(*node) {}, 0x1406f41, "has no block 21000001 yet"},
		"a hash in prose":       {func(n *node) { n.hash = "the latest" }, -1, "without a hash"},
		"not JSON-RPC": {func(n *node) { n.raw = "<html>busy</html>" }, -1,
			"not JSON-RPC 2.0"},
		"another request's answer": {func(n *node) {
			n.raw = `{"jsonrpc":"2.0","id":99,"result":"0x1"}`
		}, -1, "another request"},
		"an HTTP error": {func(n *node) { n.raw, n.rawStatus = "{}", http.StatusTooManyRequests }, -1,
			"HTTP 429"},
		"an answer too large": {func(n *node) {
			n.raw = `{"jsonrpc":"2.0","id":1,"result":"0x` + strings.Repeat("0", MaxResponse) + `"}`
		}, -1, "larger than"},
	}
	for name, cs := range cases {
		n := healthyNode()
		cs.change(n)
		c, srv := serve(t, n)
		_, err := Read(context.Background(), c, posture(t, wholePosture), cs.block)
		if err == nil || !strings.Contains(err.Error(), cs.want) {
			t.Errorf("%s: %v, want %q", name, err, cs.want)
			continue
		}
		host := strings.TrimPrefix(srv.URL, "http://")
		if strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), host) {
			t.Errorf("%s: the message names more or less than the host: %v", name, err)
		}
	}
	// A setting's call failing is not an error: the setting is unread.
	n := healthyNode()
	n.calls[tTimelock+selectorGetMinDelay] = "!-32000"
	c, _ := serve(t, n)
	if r := read(t, c, posture(t, wholePosture), -1); !strings.Contains(found(r), "timelock-delay=(rpc-error)") {
		t.Errorf("a failed call: %s", found(r))
	}
}

// The endpoint's URL may carry a credential, so no message repeats any part
// of it but the host: not when the connection fails, not when the endpoint
// redirects to it, and not when the URL is refused.
func TestNoMessageRepeatsTheEndpointsURL(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	addr := gone.URL
	gone.Close()
	c, err := Dial(addr+"/v3/s3cr3t-project-credential", thisMachine)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Read(context.Background(), c, posture(t, wholePosture), -1)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), c.Host()) {
		t.Errorf("a refused connection: %v", err)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example"+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c, err = Dial(redirect.URL+"/v3/s3cr3t-project-credential?key=s3cr3t", thisMachine)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Read(context.Background(), c, posture(t, wholePosture), -1)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("a redirect: %v", err)
	}

	for raw, want := range map[string]string{
		"http://rpc.example.org/v3/s3cr3t":          "plain http",
		"https://user:s3cr3t@rpc.example.org/v3":    "user and password",
		"ftp://rpc.example.org/v3/s3cr3t":           `"ftp"`,
		"rpc.example.org/v3/s3cr3t":                 "not a URL with a host",
		"https://rpc.example.org:bad/v3/s3cr3t":     "not a URL with a host",
		"http://[::1]:8545/v3/s3cr3t#frag":          "",
		"http://localhost:8545/v3/s3cr3t?k=s3cr3t":  "",
		"https://rpc.example.org/v3/s3cr3t?k=s3cr3": "",
	} {
		_, err := Dial(raw, thisMachine)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s was refused: %v", raw, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: %v, want %q", raw, err, want)
		case err != nil && strings.Contains(err.Error(), "s3cr3t"):
			t.Errorf("%s: the refusal repeats the URL: %v", raw, err)
		}
	}
}

// A node on this machine or the organisation's network is reached only when
// its range is declared: by default an endpoint is somewhere on the public
// internet, and loopback is not.
func TestALoopbackNodeIsReachedOnlyWhenDeclared(t *testing.T) {
	srv := httptest.NewServer(healthyNode())
	defer srv.Close()
	c, err := Dial(srv.URL+"/s3cr3t", fetch.Public)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Read(context.Background(), c, posture(t, wholePosture), -1)
	if err == nil || !strings.Contains(err.Error(), "loopback") || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("an undeclared loopback node: %v", err)
	}
	u, _ := url.Parse(srv.URL)
	if c.Host() != u.Host {
		t.Errorf("the host is %q, want %q", c.Host(), u.Host)
	}
}

// A posture file is read strictly, and its digest is over its canonical
// form, so the same declaration written two ways is one subject.
func TestAPostureFileIsReadStrictly(t *testing.T) {
	p, canonical, err := ParsePosture([]byte(wholePosture))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.settings()) != 5 {
		t.Errorf("%d settings", len(p.settings()))
	}
	reordered := `{"proxies":[{"implementation":"` + tImpl + `","admin":"` + tTimelock +
		`","address":"` + tProxy + `"}],"timelocks":[{"min_delay_seconds":172800,"address":"` +
		tTimelock + `"}],"chain_id":1,"safes":[{"min_owners":9,"min_threshold":5,"address":"` + tSafe +
		`"}],"name":"example-protocol"}`
	_, again, err := ParsePosture([]byte(reordered))
	if err != nil || string(again) != string(canonical) {
		t.Errorf("the same posture written another way: %v\n%s\n%s", err, canonical, again)
	}
	mixed, _, err := ParsePosture([]byte(strings.Replace(wholePosture, tSafe, "0xAbCdEf"+tSafe[8:], 1)))
	if err != nil || mixed.Safes[0].Address != "0xabcdef"+tSafe[8:] {
		t.Errorf("a mixed-case address is lower-cased: %v %+v", err, mixed)
	}

	refused := map[string]string{
		"a field not known": `{"name":"p","chain_id":1,"timelocks":[{"address":"` + tTimelock +
			`","min_delay_seconds":60,"guardian":"` + tSafe + `"}]}`,
		"a member twice": `{"name":"p","name":"q","chain_id":1,"timelocks":[{"address":"` + tTimelock +
			`","min_delay_seconds":60}]}`,
		"two documents": `{"name":"p","chain_id":1,"timelocks":[{"address":"` + tTimelock +
			`","min_delay_seconds":60}]} {}`,
		"a fraction":                 strings.Replace(wholePosture, `"min_threshold": 5`, `"min_threshold": 5.5`, 1),
		"a threshold above owners":   strings.Replace(wholePosture, `"min_threshold": 5`, `"min_threshold": 10`, 1),
		"a threshold of none":        strings.Replace(wholePosture, `"min_threshold": 5`, `"min_threshold": 0`, 1),
		"owners past the bound":      strings.Replace(wholePosture, `"min_owners": 9`, `"min_owners": 257`, 1),
		"a delay of none":            strings.Replace(wholePosture, `172800`, `0`, 1),
		"a delay past ten years":     strings.Replace(wholePosture, `172800`, `315360001`, 1),
		"an address too short":       strings.Replace(wholePosture, tSafe, tSafe[:41], 1),
		"an address in words":        strings.Replace(wholePosture, `"admin": "`+tTimelock, `"admin": "the timelock`, 1),
		"an empty implementation":    strings.Replace(wholePosture, tImpl, proof.ZeroAddress, 1),
		"a contract at zero":         strings.Replace(wholePosture, tSafe, proof.ZeroAddress, 1),
		"a name in prose":            strings.Replace(wholePosture, `"example-protocol"`, `"Example Protocol"`, 1),
		"no chain":                   strings.Replace(wholePosture, `"chain_id": 1`, `"chain_id": 0`, 1),
		"a chain past 2^53":          strings.Replace(wholePosture, `"chain_id": 1`, `"chain_id": 9007199254740992`, 1),
		"nothing declared":           `{"name":"p","chain_id":1}`,
		"not UTF-8":                  "{\"name\":\"p\xff\",\"chain_id\":1}",
		"a Safe twice":               strings.Replace(wholePosture, `"safes": [`, `"safes": [{"address": "`+tSafe+`", "min_threshold": 1, "min_owners": 1},`, 1),
		"an address with no 0x":      strings.Replace(wholePosture, `"address": "`+tSafe, `"address": "`+tSafe[2:]+`00`, 1),
		"a settings list too long":   tooManySettings(),
		"a document larger than 64K": `{"name":"` + strings.Repeat("p", MaxPostureFile) + `"}`,
	}
	for name, body := range refused {
		if _, _, err := ParsePosture([]byte(body)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func tooManySettings() string {
	var ts []string
	for i := range proof.MaxPostureSettings + 1 {
		ts = append(ts, fmt.Sprintf(`{"address":"0x%040x","min_delay_seconds":60}`, 0x100+i))
	}
	return `{"name":"p","chain_id":1,"timelocks":[` + strings.Join(ts, ",") + `]}`
}
