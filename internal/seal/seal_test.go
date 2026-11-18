// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/translog"
)

// The same alert written another way is the same alert; anything that is
// not one JSON object is not an alert.
func TestAnAlertIsItsCanonicalForm(t *testing.T) {
	a, err := Digest([]byte(`{"rule":"r1","at":"2026-11-10T12:00:00Z","score":4.50}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Digest([]byte(" {\n \"score\" : 4.5, \"at\":\"2026-11-10T12:00:00Z\", \"rule\" : \"r1\" }\n"))
	if err != nil || a != b {
		t.Errorf("one alert, two digests: %s %s %v", a, b, err)
	}
	for _, bad := range []string{`[1,2]`, `"an alert"`, `{"a":1}{"b":2}`, `{"a":1,"a":2}`, `{"a":`, ``} {
		if _, err := Digest([]byte(bad)); err == nil {
			t.Errorf("%q was taken for an alert", bad)
		}
	}
}

// A batch is one alert per line; a line that is not one refuses the batch
// by its number, and a repeated alert is sealed once.
func TestABatchIsReadLineByLine(t *testing.T) {
	digests, read, err := Read(strings.NewReader("{\"id\":1}\n\n  {\"id\":2}\n{ \"id\" : 1 }\n"))
	if err != nil || len(digests) != 2 || read != 3 {
		t.Fatalf("%d digests of %d lines: %v", len(digests), read, err)
	}
	cases := []struct{ in, want string }{
		{"{\"id\":1}\n{\"id\":2}\n[3]\n", "line 3"},
		{"{\"id\":1}\n" + `{"x":"` + strings.Repeat("a", MaxAlertBytes) + `"}`, "line 2 is longer than an alert"},
		{"\n\n", "no alerts"},
	}
	for _, c := range cases {
		if _, _, err := Read(strings.NewReader(c.in)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%.40q: %v, want %q", c.in, err, c.want)
		}
	}
}

func digestOf(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func digestsOf(prefix string, n int) []string {
	var out []string
	for i := range n {
		out = append(out, digestOf(fmt.Sprint(prefix, i)))
	}
	return out
}

func commitOf(b *Batch, seq int64) audit.Event {
	return audit.Event{Seq: seq, At: "2026-11-10T12:00:00Z", Action: ActionSealed,
		Outcome: audit.Success, Detail: Detail(b)}
}

// Every digest in a batch is shown under the root its entry committed, by
// a path translog's verifier accepts.
func TestEveryDigestIsShownUnderItsBatchsRoot(t *testing.T) {
	dir := t.TempDir()
	digests := digestsOf("alert ", 7)
	b, err := NewBatch(digests)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, b); err != nil {
		t.Fatal(err)
	}
	commits := Commits([]audit.Event{commitOf(b, 1)})
	root, _ := hex.DecodeString(b.Root)
	for i, d := range digests {
		f, unkept := Find(dir, commits, d)
		if f == nil || !f.Reaches || f.Index != i || unkept != 0 {
			t.Fatalf("digest %d: %+v", i, f)
		}
		raw, _ := hex.DecodeString(d)
		path, _ := translog.DecodeHashes(f.Path)
		if err := translog.VerifyInclusion(translog.HashLeaf(raw), i, len(digests), path, root); err != nil {
			t.Errorf("digest %d: %v", i, err)
		}
	}
	if f, _ := Find(dir, commits, digestOf("never sealed")); f != nil {
		t.Errorf("an alert nobody sealed was found: %+v", f)
	}
	if _, err := NewBatch(append(digests, digests[0])); err == nil {
		t.Error("a batch holding one alert twice was made")
	}
}

// Only a sealing entry that succeeded, carrying a root and a count in
// their shapes, commits a batch.
func TestOnlyASealingEntryCommits(t *testing.T) {
	b, _ := NewBatch(digestsOf("a", 3))
	good := commitOf(b, 1)
	run := good
	run.Action = ActionDetect
	failed := good
	failed.Outcome = audit.Failure
	other := good
	other.Action = "proof.kept"
	padded := commitOf(b, 5)
	padded.Detail = map[string]string{DetailRoot: b.Root, DetailCount: "03"}
	none := commitOf(b, 6)
	none.Detail = map[string]string{DetailRoot: b.Root, DetailCount: "0"}
	short := commitOf(b, 7)
	short.Detail = map[string]string{DetailRoot: b.Root[:63], DetailCount: "3"}
	got := Commits([]audit.Event{good, run, failed, other, padded, none, short})
	if len(got) != 2 || got[0].Index != 0 || got[1].Index != 1 || got[0].Count != 3 {
		t.Errorf("%+v", got)
	}
}

// The earliest batch whose kept digests are the ones its entry committed
// is the one shown; an altered one is shown failing only when nothing
// better exists; a missing one is counted.
func TestTheEarliestBatchThatReachesItsRootIsShown(t *testing.T) {
	dir := t.TempDir()
	target := digestOf("the alert")
	first, _ := NewBatch(append(digestsOf("x", 3), target))
	second, _ := NewBatch([]string{digestOf("y"), target})
	gone, _ := NewBatch(digestsOf("z", 2))
	for _, b := range []*Batch{first, second} {
		if _, err := Save(dir, b); err != nil {
			t.Fatal(err)
		}
	}
	commits := Commits([]audit.Event{commitOf(gone, 1), commitOf(first, 2), commitOf(second, 3)})
	f, unkept := Find(dir, commits, target)
	if f == nil || f.Commit.Seq != 2 || !f.Reaches || unkept != 1 {
		t.Fatalf("%+v unkept %d", f, unkept)
	}

	// The first batch's file altered: another digest swapped for a stranger.
	altered := *first
	altered.Digests = append([]string{digestOf("stranger")}, first.Digests[1:]...)
	if _, err := Save(dir, &Batch{Root: first.Root, Digests: altered.Digests}); err != nil {
		t.Fatal(err)
	}
	if f, _ := Find(dir, commits, target); f == nil || f.Commit.Seq != 3 || !f.Reaches {
		t.Errorf("an altered batch was preferred to an intact one: %+v", f)
	}
	if err := Remove(dir, second.Root); err != nil {
		t.Fatal(err)
	}
	f, unkept = Find(dir, commits, target)
	if f == nil || f.Commit.Seq != 2 || f.Reaches || unkept != 2 {
		t.Errorf("with only an altered batch, it is shown not reaching: %+v unkept %d", f, unkept)
	}

	// A digest added past the count its entry committed is not in that
	// batch.
	padded, _ := NewBatch(digestsOf("p", 2))
	if _, err := Save(dir, &Batch{Root: padded.Root, Digests: append(padded.Digests, target)}); err != nil {
		t.Fatal(err)
	}
	if f, _ := Find(dir, Commits([]audit.Event{commitOf(padded, 9)}), target); f != nil {
		t.Errorf("a digest past the committed count was found: %+v", f)
	}
}

// A root names a file only in its own shape.
func TestARootThatIsNotOneNamesNoFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir, "../../etc/passwd"); err == nil {
		t.Error("a path was read as a batch")
	}
	if _, err := Save(dir, &Batch{Root: "../x", Digests: digestsOf("a", 1)}); err == nil {
		t.Error("a batch was saved under a path")
	}
	b, _ := NewBatch(digestsOf("a", 2))
	path := filepath.Join(dir, b.Root+".json")
	if err := os.WriteFile(path, []byte(`{"root":"x","digests":["not a digest"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, b.Root); err == nil {
		t.Error("a batch holding something that is not a digest was read")
	}
}

// writeLog keeps n entries with the real audit log and reads them back.
func writeLog(t *testing.T, n int) []audit.Event {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.New(audit.Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(audit.Record{Action: "test.act", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Detail: map[string]string{"n": fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// The log verifies from entry 1 in sequence, or says the first entry where
// it stops.
func TestALogBreaksWhereItStopsVerifying(t *testing.T) {
	events := writeLog(t, 5)
	if b := Break(events); b != 0 {
		t.Fatalf("an intact log breaks at %d", b)
	}
	edited := append([]audit.Event{}, events...)
	edited[2].Detail = map[string]string{"n": "edited"}
	if b := Break(edited); b != 3 {
		t.Errorf("an edited entry 3 breaks at %d", b)
	}
	if b := Break(append(append([]audit.Event{}, events[:1]...), events[2:]...)); b != 2 {
		t.Errorf("a removed entry 2 breaks at %d", b)
	}
	if b := Break(events[1:]); b != 1 {
		t.Errorf("a log that does not begin at entry 1 breaks at %d", b)
	}
}

// OpenTimestamps proofs, built as a calendar writes them: an operation,
// then an attestation.
var (
	bitcoinMagic = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	pendingMagic = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
)

func varint(n uint64) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			c |= 0x80
		}
		out = append(out, c)
		if n == 0 {
			return out
		}
	}
}

func attested(magic, payload []byte) []byte {
	b := append([]byte{0x08, 0x00}, magic...)
	return append(append(b, varint(uint64(len(payload)))...), payload...)
}

func inBlock(height uint64) []byte { return attested(bitcoinMagic, varint(height)) }

// checkedInBlock is a head's proof with the header of the block that holds
// it, mined in the test: what `auditlog anchor upgrade` keeps once explorers
// have returned the block's header.
func checkedInBlock(t *testing.T, root string, height uint64, mined time.Time) anchor.Proof {
	t.Helper()
	digest, err := hex.DecodeString(root)
	if err != nil {
		t.Fatal(err)
	}
	reached := sha256.Sum256(digest)
	p := anchor.Proof{Digest: root, Body: inBlock(height), State: anchor.Anchored, Height: height,
		Header: anchor.MineForTesting(reached[:], mined).Hex(), HeaderHeight: height}
	if _, err := anchor.Confirm(p); err != nil {
		t.Fatalf("the test's own anchor is not confirmed: %v", err)
	}
	return p
}

func pendingAt(uri string) []byte {
	return attested(pendingMagic, append(varint(uint64(len(uri))), uri...))
}

// A head is placed in the log by the size it was recorded at, and only
// when the log's first entries still hash to it; its state is read from its
// proof, never from what was stored beside it.
func TestHeadsArePlacedAndTheirStateIsReadFromTheirProofs(t *testing.T) {
	events := writeLog(t, 6)
	tree, err := LogTree(events)
	if err != nil {
		t.Fatal(err)
	}
	h4, _ := tree.HeadAt(4)
	h6, _ := tree.HeadAt(6)
	if again, _ := audit.TreeHead(events[:4], time.Now()); again.Root != h4.Root {
		t.Fatalf("the tree here and the log's own disagree: %s %s", again.Root, h4.Root)
	}
	heads := []audit.Head{{Size: 4, Root: h4.Root}, {Size: 6, Root: h6.Root}}
	mined := time.Date(2026, 11, 10, 12, 30, 0, 0, time.UTC)
	other := checkedInBlock(t, digestOf("another log"), 870030, mined)
	proofs := []anchor.Proof{
		checkedInBlock(t, h4.Root, 870010, mined),
		// Stored as anchored, and its proof is only a calendar's promise.
		{Digest: h6.Root, Body: pendingAt("https://alice.btc.calendar.opentimestamps.org"), State: anchor.Anchored, Height: 1},
		// A root no recorded head names cannot be placed.
		{Digest: digestOf("unrecorded"), Body: inBlock(870000)},
		// Not a block anybody mined.
		{Digest: h6.Root, Body: inBlock(0)},
		// "In block 870020", written into the file by hand: a height and
		// nothing more, with no header that holds it.
		{Digest: h6.Root, Body: inBlock(870020), State: anchor.Anchored, Height: 870020},
		// And the same beside a header that is another commitment's.
		{Digest: h6.Root, Body: inBlock(870030), State: anchor.Anchored, Height: 870030,
			Header: other.Header, HeaderHeight: 870030},
	}
	placed, rewritten := Anchors(tree, heads, proofs)
	if rewritten != 0 || len(placed) != 4 || placed[0].State != anchor.Anchored || placed[0].Height != 870010 ||
		placed[0].Block.Hash == "" || !placed[0].Block.Mined.Equal(mined) || placed[0].Anchor() != "bitcoin" ||
		placed[1].State != anchor.Pending || placed[1].Anchor() != "pending" {
		t.Fatalf("%d rewritten, placed %+v", rewritten, placed)
	}
	for _, p := range placed[2:] {
		if p.State == anchor.Anchored || !p.Unconfirmed || p.Anchor() != "unconfirmed" || p.Block.Hash != "" {
			t.Errorf("an attestation no checked header holds was placed as %+v", p)
		}
	}
	if placed[2].Height != 870020 || placed[3].Height != 870030 {
		t.Errorf("the blocks the unconfirmed attestations name: %d %d", placed[2].Height, placed[3].Height)
	}
	if c, ok := Cover(placed, 3); !ok || c.Size != 4 || c.Anchor() != "bitcoin" {
		t.Errorf("entry 4 is covered by the head of 4 in a block: %+v", c)
	}
	if c, ok := Cover(placed, 4); !ok || c.Size != 6 || c.State == anchor.Anchored {
		t.Errorf("entry 5 is covered by a head of 6 no block holds: %+v", c)
	}
	// A header mined in a test is a block only in a test: with the work a
	// block is believed at as a deployment has it, the same proof is no
	// anchor.
	restoreWork()
	real, _ := Anchors(tree, heads, proofs[:1])
	restoreWork = anchor.EasyWorkForTesting()
	if len(real) != 1 || real[0].State == anchor.Anchored || !real[0].Unconfirmed {
		t.Errorf("a header nobody worked for was believed: %+v", real)
	}
	if _, ok := Cover(placed[:1], 4); ok {
		t.Error("a head of 4 covered entry 5")
	}

	// The log rewritten after a head was sent: its first entries no longer
	// hash to the root the calendars hold, or the log is shorter than it.
	_, rewritten = Anchors(tree, []audit.Head{{Size: 3, Root: h4.Root}, {Size: 4, Root: h4.Root}},
		proofs[:1])
	if rewritten != 3 {
		t.Errorf("a head the log no longer matches: rewritten %d", rewritten)
	}
	_, rewritten = Anchors(tree, []audit.Head{{Size: 9, Root: h4.Root}}, proofs[:1])
	if rewritten != 9 {
		t.Errorf("a head larger than the log: rewritten %d", rewritten)
	}
}

// The tightest bound covers: a block before a promise, the lower block,
// then the smaller head.
func TestTheEarliestAnchoredHeadCovers(t *testing.T) {
	placed := []Placed{
		{Size: 3, State: anchor.Pending},
		{Size: 5, State: anchor.Anchored, Height: 900},
		{Size: 8, State: anchor.Anchored, Height: 800},
		{Size: 9, State: anchor.Anchored, Height: 800},
	}
	if c, ok := Cover(placed, 2); !ok || c.Size != 8 {
		t.Errorf("covered by %+v", c)
	}
	if c, ok := Cover(placed[:1], 2); !ok || c.Size != 3 {
		t.Errorf("only a pending head: %+v", c)
	}
	if _, ok := Cover(placed, 9); ok {
		t.Error("an entry past every head was covered")
	}
}

// A head placed in a test is anchored in a block mined in the test, which
// internal/anchor believes only while a test has lowered the work a block
// is believed at.
var restoreWork func()

func TestMain(m *testing.M) {
	restoreWork = anchor.EasyWorkForTesting()
	code := m.Run()
	restoreWork()
	os.Exit(code)
}
