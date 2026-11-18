// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auditstream"
	"github.com/aertun/aertun/internal/proof"
)

// peerLogProof proves a stream feed's sender's log, as an operator would.
func peerLogProof(t *testing.T, root, feed string, args ...string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "peer-log.json")
	err := cmdInbound(root, append([]string{"prove", feed, "--key", key, "--public-key", pub, "--out", at}, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// ageHeads rewrites when each kept head was received, as if the batches had
// arrived that long ago.
func ageHeads(t *testing.T, root, feed string, by time.Duration) {
	t.Helper()
	heads, err := readJSONLines[peerHead](streamHeadsPath(root, feed))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, h := range heads {
		h.Received = h.Received.Add(-by)
		line, _ := json.Marshal(h)
		b.Write(append(line, '\n'))
	}
	if err := os.WriteFile(streamHeadsPath(root, feed), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Another site's log, received on a stream feed, is proved complete and
// unforked up to a time; not proved for a time after its last batch; and
// refuted once the site signs a second history — even after the evidence
// kept with the feed is deleted, because this deployment's own log recorded
// it as it arrived.
func TestAPeersLogIsProvedWholeAndUnforkedOrShownNotToBe(t *testing.T) {
	root := streamStore(t)
	site := newSendingSite(t, 46, "")
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss"); err != nil {
		t.Fatal(err)
	}
	inb := newInboundServer(root)

	// Nothing taken yet: nothing it signed can be held against anything.
	st, err := peerLogProof(t, root, "site-b")
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.PeerLog.Heads != 0 {
		t.Fatalf("before anything arrived: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.PeerLog)
	}

	before := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	for _, b := range [][2]int64{{0, 43}, {43, 46}} {
		if code, holds := site.deliver(t, inb, "site-b", b[0], b[1], nil); code != http.StatusOK || holds != b[1] {
			t.Fatalf("batch %v answered %d, holding %d", b, code, holds)
		}
	}
	st, err = peerLogProof(t, root, "site-b", "--at", before.Format(time.RFC3339))
	ev := st.Predicate.PeerLog
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Held != 46 || ev.Heads != 2 ||
		ev.Agreeing != 2 || ev.LastRecords != 3 || ev.Last.Size != 46 || ev.ForkCount != 0 {
		t.Fatalf("two batches, the last reaching the end: %v: %s %+v %+v", err, st.Predicate.Verdict,
			ev, st.Predicate.Checks)
	}
	materials := map[string]bool{}
	for _, m := range st.Predicate.Materials {
		materials[m.Name] = true
	}
	if !materials["peer-leaves"] || !materials["peer-heads"] || !materials["audit-log"] {
		t.Errorf("materials: %+v", st.Predicate.Materials)
	}

	// The batches arrived two hours ago, and nothing since: whether the log
	// is complete up to an hour ago is not known.
	ageHeads(t, root, "site-b", 2*time.Hour)
	st, err = peerLogProof(t, root, "site-b", "--at", time.Now().UTC().Add(-time.Hour).Format(time.RFC3339))
	if err == nil || st.Predicate.Verdict != proof.Inconclusive ||
		!strings.Contains(st.Predicate.Checks[2].Detail, "nothing has arrived since") {
		t.Fatalf("a silent peer: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks[2])
	}

	// A leaf lost here after it was taken: the heads the site signed are no
	// longer the records held.
	leaves := streamLeavesPath(root, "site-b")
	held, _ := os.ReadFile(leaves)
	lines := strings.SplitAfter(string(held), "\n")
	changed := strings.Join(append(append([]string{}, lines[:5]...), lines[6:]...), "")
	if err := os.WriteFile(leaves, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = peerLogProof(t, root, "site-b", "--at", before.Format(time.RFC3339))
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.PeerLog.Disagree != 2 ||
		st.Predicate.PeerLog.Held != 45 {
		t.Fatalf("a leaf lost here: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.PeerLog)
	}
	if err := os.WriteFile(leaves, held, 0o600); err != nil {
		t.Fatal(err)
	}

	// The site signs another history of its first ten records, with the
	// same keys, and sends it: a fork, answered 409, kept, recorded, and
	// nothing taken.
	other := newSendingSite(t, 10, "")
	other.key, other.heads = site.key, site.heads
	if code, holds := other.deliver(t, inb, "site-b", 0, 10, nil); code != http.StatusConflict || holds != 46 {
		t.Fatalf("a second history answered %d, holding %d", code, holds)
	}
	if code, _ := other.deliver(t, inb, "site-b", 0, 10, nil); code != http.StatusConflict {
		t.Fatalf("the same fork again answered %d", code)
	}
	events, _ := audit.Read(auditPath(root))
	recorded := 0
	for _, e := range events {
		if e.Action == "inbound.fork" && e.Detail["feed"] == "site-b" && e.Detail["records"] == "10" {
			recorded++
		}
	}
	if recorded != 1 {
		t.Errorf("the fork was recorded %d times; once, however often it is sent", recorded)
	}
	st, err = peerLogProof(t, root, "site-b", "--at", before.Format(time.RFC3339))
	ev = st.Predicate.PeerLog
	if err == nil || st.Predicate.Verdict != proof.Refuted || ev.ForkCount != 1 || ev.ForksRecorded != 1 ||
		ev.Held != 46 || ev.Forks[0].Head.Size != 10 || !ev.Forks[0].Resent ||
		!strings.HasPrefix(strings.Join(st.Predicate.Checks[1].Failures, ""), "fork: 10 record(s), signed root ") {
		t.Fatalf("a fork: %v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks[1])
	}

	// The evidence deleted from the feed's files: still refuted, by the
	// entry the log wrote when it arrived.
	if err := os.Remove(streamForksPath(root, "site-b")); err != nil {
		t.Fatal(err)
	}
	st, err = peerLogProof(t, root, "site-b", "--at", before.Format(time.RFC3339))
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.PeerLog.ForkCount != 0 ||
		st.Predicate.PeerLog.ForksRecorded != 1 ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "evidence was removed") {
		t.Fatalf("a fork whose evidence was deleted: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks[1])
	}

	// And the log goes on from what is held.
	if code, holds := site.deliver(t, inb, "site-b", 43, 46, nil); code != http.StatusConflict || holds != 46 {
		t.Fatalf("after the fork: %d, holding %d", code, holds)
	}

	// The entry the fork wrote is what the shipped rule reads.
	rules := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "detect", "pack", "aertun.peer-log-forked.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "aertun.peer-log-forked.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	// Once on the fork this deployment caught, and once on the fork the
	// site's own log says it caught in a third's stream.
	sources := map[string]int{}
	for _, f := range queue(t, root) {
		if f.Source != "aertun.peer-log-forked" {
			continue
		}
		for _, e := range f.Evidence {
			sources[e.Source]++
		}
	}
	if sources["aertun/audit"] != 1 || sources["stream/audit"] != 1 {
		t.Errorf("aertun.peer-log-forked fired on %v; once on this log's fork, once on the peer's", sources)
	}
}

// A head somebody else signed for records already held is not the site's
// word, so it is no evidence against the site: only a resend, kept nowhere.
func TestAHeadAnotherKeySignedIsNoFork(t *testing.T) {
	root := streamStore(t)
	site := newSendingSite(t, 12, "")
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss"); err != nil {
		t.Fatal(err)
	}
	inb := newInboundServer(root)
	if code, _ := site.deliver(t, inb, "site-b", 0, 12, nil); code != http.StatusOK {
		t.Fatalf("the batch answered %d", code)
	}
	stranger := newSendingSite(t, 5, "")
	stranger.key = site.key
	if code, _ := stranger.deliver(t, inb, "site-b", 0, 5, nil); code != http.StatusConflict {
		t.Fatalf("a head another key signed answered %d", code)
	}
	if _, err := os.Stat(streamForksPath(root, "site-b")); !os.IsNotExist(err) {
		t.Errorf("a head another key signed was kept as a fork: %v", err)
	}
	events, _ := audit.Read(auditPath(root))
	for _, e := range events {
		if e.Action == "inbound.fork" {
			t.Errorf("a head another key signed was recorded as a fork: %+v", e.Detail)
		}
	}
}

// What a proof calls a full batch is what a sender sends at most: a smaller
// one reached the end of the sender's log.
func TestAFullBatchIsWhatASenderSends(t *testing.T) {
	if proof.MaxStreamBatch != auditstream.MaxBatch {
		t.Fatalf("a peer-log proof counts a full batch as %d records and a sender sends %d",
			proof.MaxStreamBatch, auditstream.MaxBatch)
	}
}

// The Feeds screen and `inbound status` say where each peer's chain stands
// and whether it forked, from the end of what the feed kept.
func TestAPeersChainHeadIsShown(t *testing.T) {
	root := streamStore(t)
	site := newSendingSite(t, 7, "")
	if _, _, err := makeFeed(root, "stream", "site-b", map[string]string{"keys": site.keys}, "boss"); err != nil {
		t.Fatal(err)
	}
	inb := newInboundServer(root)
	hooks := feedsHooks(root, inb)
	views, err := hooks.List()
	if err != nil || len(views) != 1 || views[0].Peer != nil {
		t.Fatalf("before anything arrived: %v %+v", err, views)
	}
	if code, _ := site.deliver(t, inb, "site-b", 0, 7, nil); code != http.StatusOK {
		t.Fatalf("the batch answered %d", code)
	}
	views, _ = hooks.List()
	if p := views[0].Peer; p == nil || p.Records != 7 || p.Root == "" || p.Received == "" || p.Forks != 0 {
		t.Fatalf("after a batch: %+v", views[0].Peer)
	}
	other := newSendingSite(t, 3, "")
	other.key, other.heads = site.key, site.heads
	if code, _ := other.deliver(t, inb, "site-b", 0, 3, nil); code != http.StatusConflict {
		t.Fatalf("a fork answered %d", code)
	}
	views, _ = hooks.List()
	if p := views[0].Peer; p == nil || p.Forks != 1 || p.Records != 7 {
		t.Fatalf("after a fork: %+v", p)
	}
	head, forks, err := peerChainHead(root, "site-b")
	if err != nil || head == nil || head.Head.Size != 7 || head.Records != 7 || forks != 1 {
		t.Errorf("the chain head read for status: %+v %d %v", head, forks, err)
	}
}
