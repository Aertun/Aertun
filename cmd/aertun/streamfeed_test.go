// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auditstream"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/httpsig"
	"github.com/aertun/aertun/internal/inbound"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The batches here are made the way another Aertun deployment makes them:
// its own audit log, its own head signer and stream key, and
// auditstream.Sender building each batch, signed as the sender signs it for
// the address it was given. Nothing is captured from anywhere, so a change
// on either side that stops Aertun reading what Aertun sends fails this.

// streamOrigin is the address the sender was given: the receiver's
// admin.base_url, which is what the sender signs.
const streamOrigin = "http://127.0.0.1:9911"

// sendingSite is the sending deployment.
type sendingSite struct {
	key    ed25519.PrivateKey
	heads  *audit.HeadSigner
	events []audit.Event
	keys   string // the published keys file
}

// newSendingSite writes an audit log of n records — an administrator
// granted alone among them — and publishes its keys as `aertun siem stream
// key --json` does. headContext, when set, is what the published keys say
// the heads are signed in.
func newSendingSite(t *testing.T, n int, headContext string) *sendingSite {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.New(audit.Options{Path: path, Source: "site-b"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		rec := audit.Record{Action: "finding.triaged", Resource: fmt.Sprintf("/findings/f%d", i),
			Outcome: audit.Success, Principal: "dana@b.example", Kind: audit.KindHuman, Verified: true}
		switch {
		case i == n-1:
			rec = audit.Record{Action: "dual.proposed", Resource: "/", Outcome: audit.Success,
				Principal: "dana@b.example", Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"alone": "true", "kind": "grant", "role": "admin"}}
		case i == n-2 && n > 3:
			rec = audit.Record{Action: "dual.proposed", Resource: "/", Outcome: audit.Success,
				Principal: "dana@b.example", Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"kind": "owner", "to": "lee@b.example"}}
		case i == n-3 && n > 3:
			rec = audit.Record{Action: "config.set", Resource: "/", Outcome: audit.Success,
				Principal: "dana@b.example", Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"setting": "admin.behind_tls_proxy", "to": "false",
					"accepted_risk": "the proxy terminates TLS on the same host"}}
		}
		if _, err := l.Append(rec); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	seed := func() []byte {
		b := make([]byte, audit.SeedSize)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	heads, err := audit.NewHeadSigner(seed(), seed())
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	ed, ml := heads.Verifier().PublicKeys()
	k, _ := json.Marshal(inbound.StreamKeys{KeyID: auditstream.KeyID(pub), Alg: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub), HeadKeyID: heads.Verifier().KeyID(),
		HeadEd25519: base64.StdEncoding.EncodeToString(ed), HeadMLDSA: base64.StdEncoding.EncodeToString(ml),
		HeadContext: headContext})
	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keys, k, 0o600); err != nil {
		t.Fatal(err)
	}
	return &sendingSite{key: key, heads: heads, events: events, keys: keys}
}

// delivery is the batch after `sent` holding records up to `upto`, as a
// proxy hands it on: signed for the sender's address, arriving in origin
// form at an internal host over plain HTTP. change, when set, alters the
// body after it was signed.
func (s *sendingSite) delivery(t *testing.T, feed string, sent, upto int64, change func(string) string) (*http.Request, time.Time) {
	t.Helper()
	at := time.Now().UTC().Truncate(time.Second)
	sender := &auditstream.Sender{Key: s.key, Heads: s.heads}
	var events []audit.Event
	for _, e := range s.events {
		if e.Seq <= upto {
			events = append(events, e)
		}
	}
	b, err := sender.Batch(events, sent, at)
	if err != nil || b == nil {
		t.Fatalf("no batch after %d: %v", sent, err)
	}
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	signed := httptest.NewRequest(http.MethodPost, streamOrigin+"/feeds/"+feed, bytes.NewReader(body))
	signed.Header.Set("Content-Type", "application/json")
	httpsig.SetContentDigest(signed, body)
	if err := httpsig.Sign(signed, auditstream.KeyID(s.key.Public().(ed25519.PublicKey)), httpsig.Ed25519,
		s.key, auditstream.Covered, at); err != nil {
		t.Fatal(err)
	}
	sent2 := string(body)
	if change != nil {
		sent2 = change(sent2)
	}
	r := httptest.NewRequest(http.MethodPost, "/feeds/"+feed, strings.NewReader(sent2))
	r.Host = "aertun.internal:8080"
	for k, v := range signed.Header {
		r.Header[k] = v
	}
	return r, at.Add(2 * time.Second)
}

func (s *sendingSite) deliver(t *testing.T, inb *inboundServer, feed string, sent, upto int64, change func(string) string) (int, int64) {
	t.Helper()
	r, at := s.delivery(t, feed, sent, upto, change)
	inb.now = func() time.Time { return at }
	w := httptest.NewRecorder()
	inb.ServeHTTP(w, r)
	var ans struct {
		Holds *int64 `json:"holds"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ans)
	if ans.Holds == nil {
		return w.Code, -1
	}
	return w.Code, *ans.Holds
}

// streamStore is a receiving store whose admin.base_url is the address the
// sender was given.
func streamStore(t *testing.T) string {
	t.Helper()
	root := connectStore(t)
	if err := cmdConfig(root, []string{"set", "admin.base_url", streamOrigin}); err != nil {
		t.Fatal(err)
	}
	return root
}

// Another deployment's audit log is taken batch by batch, only in order and
// only as it was signed, kept across a restart, and stored with each actor
// named by the feed.
func TestAnotherDeploymentsAuditStreamIsTakenInOrder(t *testing.T) {
	root := streamStore(t)
	site := newSendingSite(t, 46, "")
	f, shown, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss")
	if err != nil {
		t.Fatal(err)
	}
	if f.Stream == nil || !strings.Contains(strings.Join(shown, "\n"), "siem.stream.url") {
		t.Fatalf("the feed did not pin the keys or say how to point the sender at it: %+v %v", f, shown)
	}
	inb := newInboundServer(root)

	// Out of order: the receiver holds nothing, and says so.
	if code, holds := site.deliver(t, inb, "site-b", 43, 46, nil); code != http.StatusConflict || holds != 0 {
		t.Fatalf("a batch that skips records 1 to 43 answered %d, holding %d", code, holds)
	}
	if code, holds := site.deliver(t, inb, "site-b", 0, 43, nil); code != http.StatusOK || holds != 43 {
		t.Fatalf("the first batch answered %d, holding %d", code, holds)
	}
	if n := storedFrom(t, root, inbound.StreamSource); n != 43 {
		t.Fatalf("%d events stored from 43 records", n)
	}
	// One record changed on the way: the body no longer has the digest it
	// was signed with.
	tampered := func(s string) string { return strings.Replace(s, `\"status\":\"success\"`, `\"status\":\"denied\"`, 1) }
	if code, _ := site.deliver(t, inb, "site-b", 43, 46, tampered); code != http.StatusUnauthorized {
		t.Fatalf("a changed batch answered %d", code)
	}
	if code, holds := site.deliver(t, inb, "site-b", 43, 46, nil); code != http.StatusOK || holds != 46 {
		t.Fatalf("the second batch answered %d, holding %d", code, holds)
	}
	// Sent again, as a sender that lost the answer would: refused with
	// where the receiver is, so the sender moves on.
	if code, holds := site.deliver(t, inb, "site-b", 0, 43, nil); code != http.StatusConflict || holds != 46 {
		t.Fatalf("a batch already held answered %d, holding %d", code, holds)
	}
	// A restart remembers the chain.
	again := newInboundServer(root)
	if code, holds := site.deliver(t, again, "site-b", 43, 46, nil); code != http.StatusConflict || holds != 46 {
		t.Fatalf("after a restart the second batch answered %d, holding %d", code, holds)
	}

	// What was stored: every record, its action as the sender wrote it, its
	// actor under the feed's name, and the details a rule may read.
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Release()
	var stored []telemetry.Event
	_ = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == inbound.StreamSource {
			stored = append(stored, e)
		}
		return nil
	})
	if len(stored) != 46 {
		t.Fatalf("%d events stored from 46 records", len(stored))
	}
	var alone *telemetry.Event
	for i, e := range stored {
		if e.Actor.Issuer != "site-b" {
			t.Fatalf("an actor is named under %q, not the feed", e.Actor.Issuer)
		}
		if e.Raw["action"] == "dual.proposed" && e.Raw["alone"] == "true" {
			alone = &stored[i]
		}
		if strings.Contains(e.Raw["accepted_risk"], "proxy") {
			t.Fatalf("the reason somebody typed arrived in the event store: %+v", e.Raw)
		}
	}
	if alone == nil || alone.Raw["alone"] != "true" || alone.Raw["request_kind"] != "grant" || alone.Raw["role"] != "admin" {
		t.Fatalf("the privileged change made alone did not arrive as the sender wrote it: %+v", alone)
	}

	// The rules that watch this deployment's own log watch the other's too:
	// the change the other's only administrator made alone is found, and
	// nothing that did not happen there is.
	files, err := detect.Pack()
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]bool{}
	reads := 0
	for _, pf := range files {
		var r detect.Rule
		if err := json.Unmarshal(pf.Body, &r); err != nil || !slices.Contains(r.Sources, inbound.StreamSource) {
			continue
		}
		reads++
		for _, e := range stored {
			if r.Matches(e) {
				fired[r.ID] = true
			}
		}
	}
	for _, want := range []string{"aertun.privileged-change-alone",
		"aertun.ownership-transfer-requested", "aertun.setting-weakened"} {
		if !fired[want] {
			t.Errorf("%s did not fire on the peer's record of it (fired: %v)", want, fired)
		}
	}
	// Every rule over this program's own log reads a peer's log too.
	for _, pf := range files {
		var r detect.Rule
		if json.Unmarshal(pf.Body, &r) == nil && slices.Contains(r.Sources, "aertun/audit") &&
			!slices.Contains(r.Sources, inbound.StreamSource) {
			t.Errorf("%s reads this deployment's log and not a peer's", r.ID)
		}
	}
	for _, quiet := range []string{"aertun.break-glass", "aertun.audit-log-moved", "aertun.admin-token-issued"} {
		if fired[quiet] {
			t.Errorf("%s fired on a stream with nothing of the kind in it", quiet)
		}
	}
}

// The heads are checked in the context the published keys name: a sender
// that signs in this program's context is refused by a feed told to expect
// another, so a signature made for one program is never taken as another's.
func TestTheHeadsAreCheckedInTheContextTheKeysName(t *testing.T) {
	root := streamStore(t)
	site := newSendingSite(t, 5, "other/audit-head/v1")
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss"); err != nil {
		t.Fatal(err)
	}
	if code, _ := site.deliver(t, newInboundServer(root), "site-b", 0, 5, nil); code == http.StatusOK {
		t.Fatal("heads signed in this program's context were taken as another program's")
	}
}

// Without the configured origin, the address a proxy hands on is not the
// one the sender signed, and the batch is refused rather than taken
// unchecked.
func TestTheSignedAddressIsTheOneTheSenderWasGiven(t *testing.T) {
	root := connectStore(t)
	site := newSendingSite(t, 5, "")
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss"); err != nil {
		t.Fatal(err)
	}
	if code, _ := site.deliver(t, newInboundServer(root), "site-b", 0, 5, nil); code != http.StatusUnauthorized {
		t.Fatalf("a batch checked against an address it was not signed for answered %d", code)
	}
}

// A write that stopped part way through a leaf leaves the feed at the last
// whole one, and says so, rather than refusing everything after it.
func TestATornWriteOfTheChainIsCutBackToWhatWasWhole(t *testing.T) {
	root := streamStore(t)
	site := newSendingSite(t, 46, "")
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss"); err != nil {
		t.Fatal(err)
	}
	if code, holds := site.deliver(t, newInboundServer(root), "site-b", 0, 43, nil); code != http.StatusOK || holds != 43 {
		t.Fatalf("the first batch answered %d, holding %d", code, holds)
	}
	path := streamLeavesPath(root, "site-b")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	// Forty leaves whole and the forty-first half written.
	torn := strings.Join(lines[:40], "") + lines[40][:20]
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	inb := newInboundServer(root)
	if code, holds := site.deliver(t, inb, "site-b", 43, 46, nil); code != http.StatusConflict || holds != 40 {
		t.Fatalf("after a torn write the feed answered %d, holding %d; it holds forty whole leaves", code, holds)
	}
	after, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(after), "\n") || strings.Count(string(after), "\n") != 40 {
		t.Fatalf("the half-written leaf was left in the file:\n%q", string(after)[len(after)-30:])
	}
}

// A feed of this kind needs the keys, and the keys must be keys.
func TestAStreamFeedNeedsItsPublishedKeys(t *testing.T) {
	root := connectStore(t)
	if _, _, err := makeFeed(root, "stream", "site-b", nil, "boss"); err == nil ||
		!strings.Contains(err.Error(), "--keys") {
		t.Fatalf("a feed with no keys: %v", err)
	}
	bad := t.TempDir() + "/keys.json"
	_ = os.WriteFile(bad, []byte(`{"key_id":"x","alg":"ed25519","public_key":"AAAA"}`), 0o600)
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": bad}, "boss"); err == nil {
		t.Fatal("a key that is not an Ed25519 key was pinned")
	}
}
