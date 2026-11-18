// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/incident"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// commander is the person working the incident, signed in with a passkey.
var commander = &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}

// clockSite is a store with one incident under GDPR, its awareness decided
// by a verified person.
func clockSite(t *testing.T) (root, id string) {
	t.Helper()
	root = reconcileSite(t)
	i, err := declareIncident(root, commander, "customer records exposed",
		"sev2", []string{"eu"}, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	clockDo(t, root, i.ID, incident.Action{Do: "decide", Trigger: incident.Aware,
		Text: "the bucket was public and logs show reads"})
	return root, i.ID
}

func clockDo(t *testing.T, root, id string, a incident.Action) {
	t.Helper()
	if _, err := actOnIncident(root, id, commander, a, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func clockProof(t *testing.T, root, id string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	at := filepath.Join(t.TempDir(), "clock.json")
	err := cmdIncident(root, []string{"prove", id, "--trigger", "aware", "--key", key,
		"--public-key", pub, "--out", at})
	if _, serr := os.Stat(at); serr != nil {
		t.Fatalf("no proof was written: %v", err)
	}
	return readStatement(t, at, pub), err
}

// anchorHead commits the log as it stands and files a Bitcoin attestation
// for its root with the header of the block that holds it, as `auditlog
// anchor` and `anchor upgrade` would once a calendar answered and explorers
// returned the block: the attestation sits directly on the root, and the
// block is mined now.
func anchorHead(t *testing.T, root string, block uint64) audit.Head {
	t.Helper()
	return anchorHeadMined(t, root, block, time.Now())
}

// anchorHeadMined is anchorHead with the time the block's header carries.
func anchorHeadMined(t *testing.T, root string, block uint64, mined time.Time) audit.Head {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	head, err := audit.TreeHead(events, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f := &headFile{}
	_ = loadJSON(headsPath(root), f)
	f.Heads = append(f.Heads, head)
	if err := saveJSON(headsPath(root), f); err != nil {
		t.Fatal(err)
	}
	body := []byte{0x00, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	var h []byte
	for n := block; ; {
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
	body = append(append(body, byte(len(h))), h...)
	digest, _ := hex.DecodeString(head.Root)
	if state, height, _, err := anchor.Classify(digest, body); err != nil || state != anchor.Anchored ||
		height != block {
		t.Fatalf("the test's attestation does not classify: %s %d %v", state, height, err)
	}
	af := &anchorFile{}
	_ = loadJSON(anchorPath(root), af)
	af.Proofs = append(af.Proofs, inCheckedBlock(t, anchor.Proof{Digest: head.Root,
		Calendar: "https://alice.btc.calendar.opentimestamps.org", Body: body,
		State: anchor.Anchored, Height: block}, mined))
	if err := saveJSON(anchorPath(root), af); err != nil {
		t.Fatal(err)
	}
	return head
}

// A decision in the log, the incident agreeing, anchored, and its one
// obligation met: proven, and kept. Before the anchor it is inconclusive,
// because its time rests on this program's own log.
func TestAClockRecordedAnchoredAndMetIsProven(t *testing.T) {
	root, id := clockSite(t)
	st, err := clockProof(t, root, id)
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Clock.Entry == 0 ||
		st.Predicate.Clock.Duties[0].Outcome != proof.DutyOpen {
		t.Fatalf("before anything: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Clock)
	}
	clockDo(t, root, id, incident.Action{Do: "discharge", Regime: "GDPR Article 33",
		Text: "notified the supervisory authority, reference 2026-118"})
	anchorHead(t, root, 921004)
	st, err = clockProof(t, root, id)
	ev := st.Predicate.Clock
	if err != nil || st.Predicate.Verdict != proof.Proven || ev.Anchor == nil || ev.Anchor.Block != 921004 ||
		ev.Anchor.Calendar != "alice.btc.calendar.opentimestamps.org" || len(ev.Duties) != 1 ||
		ev.Duties[0].Outcome != proof.DutyMet {
		t.Fatalf("%v: %s %+v %+v", err, st.Predicate.Verdict, ev, st.Predicate.Checks)
	}
	kept, _ := proofstore.List(root)
	found := false
	for _, k := range kept {
		found = found || (k.Statement != nil && k.Statement.Predicate.Clock != nil &&
			k.Statement.Predicate.Verdict == proof.Proven)
	}
	if !found {
		t.Error("the proof was not kept")
	}
}

// A clock moved in the incident's file afterwards is refuted against the
// log, and so is a log rewritten after its head was anchored.
func TestAMovedClockAndARewrittenLogAreRefuted(t *testing.T) {
	root, id := clockSite(t)
	inc, err := loadIncident(root, id)
	if err != nil {
		t.Fatal(err)
	}
	m := inc.Moments["aware"]
	m.At = m.At.Add(-36 * time.Hour)
	inc.Moments["aware"] = m
	if err := saveIncident(root, inc); err != nil {
		t.Fatal(err)
	}
	st, err := clockProof(t, root, id)
	if err == nil || st.Predicate.Verdict != proof.Refuted ||
		!strings.HasPrefix(strings.Join(st.Predicate.Checks[0].Failures, ""), "moved: aware at ") {
		t.Fatalf("a moved clock: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks[0])
	}

	// A head anchored and then no longer what the log commits to — the log
	// rewritten behind it, or the head's record edited — is refuted, and
	// is not the anchor the decision rests on.
	root, id = clockSite(t)
	anchorHead(t, root, 921004)
	// The head really was anchored at this root; the log's first entries no
	// longer hash to it at the size it was sent at.
	f := &headFile{}
	_ = loadJSON(headsPath(root), f)
	f.Heads[0].Size--
	_ = saveJSON(headsPath(root), f)
	st, err = clockProof(t, root, id)
	if err == nil || st.Predicate.Verdict != proof.Refuted || len(st.Predicate.Clock.Broken) != 1 ||
		st.Predicate.Clock.Anchor != nil ||
		!strings.HasPrefix(strings.Join(st.Predicate.Checks[1].Failures, ""), "does not match the log: ") {
		t.Errorf("a head the log no longer matches: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Clock)
	}
}

// An obligation past its deadline and not discharged refutes, named: the
// same incident, proved four days after its awareness was decided.
func TestAnObligationPastDueRefutes(t *testing.T) {
	root, id := clockSite(t)
	later := time.Now().Add(96 * time.Hour)
	clockNow = func() time.Time { return later }
	t.Cleanup(func() { clockNow = time.Now })
	st, err := clockProof(t, root, id)
	if err == nil || st.Predicate.Verdict != proof.Refuted ||
		!strings.Contains(strings.Join(st.Predicate.Checks[3].Failures, ""), "late: GDPR Article 33 due ") ||
		!strings.HasSuffix(strings.Join(st.Predicate.Checks[3].Failures, ""), ", not discharged") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks[3])
	}
}

// What a clock proof starts from has to exist.
func TestAClockProofNeedsADecision(t *testing.T) {
	root, id := clockSite(t)
	key, _ := signingFiles(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"prove", id, "--trigger", "material", "--key", key}, "no \"material\" decision"},
		{[]string{"prove", "inc-1", "--trigger", "aware", "--key", key}, "not an incident"},
		{[]string{"prove", id, "--key", key}, "takes ID --trigger"},
	} {
		if err := cmdIncident(root, c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
}
