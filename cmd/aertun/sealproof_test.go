// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
	"github.com/aertun/aertun/internal/seal"
	"github.com/aertun/aertun/internal/telemetry"
)

// sealSite is a new store.
func sealSite(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFile(t *testing.T, name string, lines ...string) string {
	t.Helper()
	at := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(at, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return at
}

// threeAlerts are a web3 monitor's alerts, as it exported them.
var threeAlerts = []string{
	`{"monitor":"chainwatch","alert":"A-1","contract":"0xabc","signal":"flash-loan","at":"2026-11-10T11:58:00Z"}`,
	`{"monitor":"chainwatch","alert":"A-2","contract":"0xabc","signal":"price-oracle-skew","at":"2026-11-10T11:59:30Z"}`,
	`{"monitor":"chainwatch","alert":"A-3","contract":"0xdef","signal":"admin-key-change","at":"2026-11-10T12:01:00Z"}`,
}

// secondAlert is A-2 as somebody holding it later writes it: other member
// order, other whitespace. The canonical form makes it the same alert.
const secondAlert = `{ "signal": "price-oracle-skew", "at": "2026-11-10T11:59:30Z",
  "contract": "0xabc", "alert": "A-2", "monitor": "chainwatch" }`

func sealedProof(t *testing.T, root string, args ...string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "sealed.json")
	err := cmdProof(root, append([]string{"sealed", "--key", key, "--public-key", pub, "--out", at}, args...))
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// anchorSealHead records the log's head as it stands as sent to OpenTimestamps,
// as `aertun auditlog anchor` does, with what a calendar handed back.
func anchorSealHead(t *testing.T, root string, body []byte, stored anchor.State) audit.Head {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	head, err := audit.TreeHead(events, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recordSent(t, root, head, body, stored)
	return head
}

func recordSent(t *testing.T, root string, head audit.Head, body []byte, stored anchor.State) {
	t.Helper()
	hf, af := &headFile{}, &anchorFile{}
	if err := loadJSON(headsPath(root), hf); err != nil {
		t.Fatal(err)
	}
	if err := loadJSON(anchorPath(root), af); err != nil {
		t.Fatal(err)
	}
	hf.Heads = append(hf.Heads, head)
	af.Proofs = append(af.Proofs, anchor.Proof{Digest: head.Root, Calendar: "https://alice.btc.calendar.opentimestamps.org",
		Body: body, State: stored, SubmittedAt: time.Now().UTC().Format(time.RFC3339)})
	if err := saveJSON(headsPath(root), hf); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(anchorPath(root), af); err != nil {
		t.Fatal(err)
	}
}

// inBlock is a calendar's proof once the commitment is in a block: one
// operation and a Bitcoin attestation, in the OpenTimestamps format.
func inBlock(height uint64) []byte {
	var h []byte
	for n := height; ; {
		c := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			c |= 0x80
		}
		h = append(h, c)
		if n == 0 {
			break
		}
	}
	b := append([]byte{0x08, 0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}, byte(len(h)))
	return append(b, h...)
}

// pendingProof is a real calendar's answer to a fresh submission, which
// commits to nothing yet (internal/anchor's fixture).
func pendingProof(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "anchor", "testdata", "calendar-response.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An alert sealed and then written another way: inconclusive while
// nothing is anchored, inconclusive while its head is pending in the
// calendars, proven once a Bitcoin attestation covers it — and kept.
func TestASealedAlertIsProvenOnceItsHeadIsInABlock(t *testing.T) {
	root := sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	alert := writeFile(t, "a2.json", secondAlert)

	st, err := sealedProof(t, root, "--alert", alert)
	ev := st.Predicate.Sealed
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || ev.Anchor != proof.AnchorNone ||
		ev.Entry == 0 || ev.BatchSize != 3 || ev.BatchIndex != 1 || ev.HeadSize != ev.LogEntries ||
		!strings.Contains(st.Predicate.Checks[3].Detail, "rests on the audit log alone") {
		t.Fatalf("unanchored: %v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks)
	}
	sealedIn := ev.Entry

	pending := anchorSealHead(t, root, pendingProof(t), anchor.Pending)
	st, err = sealedProof(t, root, "--alert", alert)
	ev = st.Predicate.Sealed
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || ev.Anchor != proof.AnchorPending ||
		ev.HeadSize != pending.Size || ev.HeadRoot != pending.Root || ev.Entry != sealedIn {
		t.Fatalf("pending: %v: %s %+v", err, st.Predicate.Verdict, ev)
	}

	// A later head, in a block, covers the entry too: the confirmed one is
	// what fixes the time, though the pending one is earlier.
	confirmed := anchorSealHead(t, root, inBlock(870123), anchor.Anchored)
	st, err = sealedProof(t, root, "--alert", alert)
	ev = st.Predicate.Sealed
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Anchor != proof.AnchorBitcoin ||
		ev.Height != 870123 || ev.HeadSize != confirmed.Size || ev.HeadRoot != confirmed.Root ||
		ev.Entry != sealedIn || !strings.HasPrefix(st.Subject[0].Name, "alert/") {
		t.Fatalf("anchored: %v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks)
	}
	materials := map[string]bool{}
	for _, m := range st.Predicate.Materials {
		materials[m.Name] = true
	}
	if !materials["audit-log"] || !materials["anchor-proof"] {
		t.Errorf("materials: %+v", st.Predicate.Materials)
	}
	kept, _ := proofstore.List(root)
	if len(kept) != 3 || kept[0].Statement == nil || kept[0].Statement.Predicate.Sealed == nil {
		t.Errorf("the proofs were not kept: %d", len(kept))
	}
}

// What anchors.json says of a proof's state is not believed: a proof
// stored as anchored whose operations reach only a calendar's promise is
// pending.
func TestAStoredStateIsNotTheAttestation(t *testing.T) {
	root := sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	anchorSealHead(t, root, pendingProof(t), anchor.Anchored)
	st, err := sealedProof(t, root, "--alert", writeFile(t, "a1.json", threeAlerts[0]))
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Sealed.Anchor != proof.AnchorPending {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Sealed)
	}
}

// An alert nobody sealed is refuted, and says in how many batches it was
// looked for.
func TestAnAlertNobodySealedIsRefuted(t *testing.T) {
	root := sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts[:2]...)}); err != nil {
		t.Fatal(err)
	}
	anchorSealHead(t, root, inBlock(870000), anchor.Anchored)
	st, err := sealedProof(t, root, "--alert", writeFile(t, "a3.json", threeAlerts[2]))
	if err == nil || st.Predicate.Verdict != proof.Refuted || len(st.Predicate.Checks) != 2 ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "in none of the 1 batch(es)") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}
}

// A batch file altered after the seal, or an audit log edited, refutes:
// the digests no longer hash to the root the entry committed, or the log
// stops verifying.
func TestAnEditedBatchOrLogRefutes(t *testing.T) {
	root := sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	c := seal.Commits(events)
	if len(c) != 1 {
		t.Fatalf("%d sealing entries", len(c))
	}
	b, err := seal.Load(seal.Dir(root), c[0].Root)
	if err != nil {
		t.Fatal(err)
	}
	b.Digests[0] = strings.Repeat("0", 64)
	if _, err := seal.Save(seal.Dir(root), b); err != nil {
		t.Fatal(err)
	}
	st, err := sealedProof(t, root, "--alert", writeFile(t, "a2.json", secondAlert))
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.Checks[1].Passed ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "cannot be shown") {
		t.Errorf("an altered batch: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}

	root = sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var first audit.Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	first.Resource = "/somewhere-else"
	edited, _ := json.Marshal(first)
	lines[0] = string(edited)
	if err := os.WriteFile(auditPath(root), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = sealedProof(t, root, "--alert", writeFile(t, "a2.json", secondAlert))
	if err == nil || st.Predicate.Verdict != proof.Refuted || len(st.Predicate.Checks) != 1 ||
		st.Predicate.Sealed.LogBreak != 1 {
		t.Errorf("an edited log: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Sealed)
	}
}

// A head sent to be anchored that the log's first entries no longer hash to
// is the log rewritten after the head left: refuted, whatever was sealed.
func TestALogRewrittenAfterItsHeadWasSentRefutes(t *testing.T) {
	root := sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	recordSent(t, root, audit.Head{Size: 2, Root: strings.Repeat("ab", 32)}, inBlock(870000), anchor.Anchored)
	st, err := sealedProof(t, root, "--alert", writeFile(t, "a1.json", threeAlerts[0]))
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.Sealed.Rewritten != 2 ||
		!strings.Contains(st.Predicate.Checks[0].Detail, "rewritten") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks)
	}
}

// A detection run seals what it raises in its own entry, and a finding is
// proved by its id: the alert it was sealed as is made again from the
// register.
func TestADetectionRunSealsTheFindingsItRaises(t *testing.T) {
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	failed := telemetry.DispositionFailed
	root, rules := siemSite(t, []labelled{
		{"spray", true, signIn("okta/system", "admin-dana", failed, "", t0)},
		{"second admin", true, signIn("okta/system", "admin-ops", failed, "", t0.Add(time.Minute))},
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	var run audit.Event
	for _, e := range events {
		if e.Action == "detect.run" {
			run = e
		}
	}
	if run.Detail[seal.DetailCount] != "2" || run.Detail[seal.DetailCount] != run.Detail["opened"] {
		t.Fatalf("the run's entry: %+v", run.Detail)
	}
	q := queue(t, root)
	if len(q) != 2 {
		t.Fatalf("%d findings", len(q))
	}
	st, err := sealedProof(t, root, "--finding", q[0].ID)
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Sealed.Entry != int(run.Seq) {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Sealed)
	}

	// A second run that raises nothing seals nothing.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	events, _ = audit.Read(auditPath(root))
	if c := seal.Commits(events); len(c) != 1 {
		t.Errorf("%d sealing entries after a run that raised nothing", len(c))
	}
	key, _ := signingFiles(t)
	if err := cmdProof(root, []string{"sealed", "--key", key, "--finding", "0000000000000000"}); err == nil ||
		!strings.Contains(err.Error(), "aertun finding list") {
		t.Errorf("an unknown finding: %v", err)
	}
}

// What is not a batch is refused before anything is written, and so is a
// proof asked for without what it needs.
func TestSealingRefusesWhatIsNotABatch(t *testing.T) {
	root := sealSite(t)
	key, _ := signingFiles(t)
	alert := writeFile(t, "a.json", threeAlerts[0])
	cases := []struct {
		run  func() error
		want string
	}{
		{func() error { return cmdAlert(root, nil) }, "alert needs seal"},
		{func() error { return cmdAlert(root, []string{"unseal"}) }, "try seal"},
		{func() error { return cmdAlert(root, []string{"seal"}) }, "one FILE"},
		{func() error { return cmdAlert(root, []string{"seal", writeFile(t, "e.jsonl", "")}) }, "no alerts"},
		{func() error {
			return cmdAlert(root, []string{"seal", writeFile(t, "x.jsonl", threeAlerts[0], "[1]")})
		}, "line 2"},
		{func() error { return cmdAlert(root, []string{"seal", "--list", "x"}) }, "nothing else"},
		{func() error { return cmdProof(root, []string{"sealed", "--alert", alert}) }, "--key FILE"},
		{func() error {
			return cmdProof(root, []string{"sealed", "--key", key, "--alert", alert, "--finding", "f"})
		}, "or --finding"},
		{func() error {
			return cmdProof(root, []string{"sealed", "--key", key, "--alert", writeFile(t, "two.json", threeAlerts[:2]...)})
		}, "is not one alert"},
	}
	for i, c := range cases {
		if err := c.run(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("case %d: %v, want %q", i, err, c.want)
		}
	}
	events, _ := audit.Read(auditPath(root))
	if c := seal.Commits(events); len(c) != 0 {
		t.Errorf("a refused batch was sealed: %+v", c)
	}
	if entries, _ := os.ReadDir(seal.Dir(root)); len(entries) != 0 {
		t.Errorf("a refused batch was kept: %d file(s)", len(entries))
	}
}

// The batches are listed with the entry that sealed each, and one whose
// digests are not kept here says so.
func TestTheSealedBatchesAreListed(t *testing.T) {
	root := sealSite(t)
	if got := capture(t, func() error { return cmdAlert(root, []string{"seal", "--list"}) }); !strings.Contains(got, "nothing has been sealed") {
		t.Errorf("an empty listing: %s", got)
	}
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	c := seal.Commits(events)
	got := capture(t, func() error { return cmdAlert(root, []string{"seal", "--list"}) })
	if len(c) != 1 || !strings.Contains(got, "3 alert(s)") || !strings.Contains(got, c[0].Root[:16]) ||
		strings.Contains(got, "not kept") {
		t.Errorf("%s", got)
	}
	if err := seal.Remove(seal.Dir(root), c[0].Root); err != nil {
		t.Fatal(err)
	}
	if got := capture(t, func() error { return cmdAlert(root, []string{"seal", "--list"}) }); !strings.Contains(got, "not kept here") {
		t.Errorf("a batch whose digests are gone: %s", got)
	}
}
