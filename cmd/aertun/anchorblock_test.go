// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/incident"
	"github.com/aertun/aertun/internal/proof"
)

// A head anchored in a test is in a block mined in the test, which
// internal/anchor believes only while a test has lowered the work a block
// is believed at.
var restoreWork func()

func TestMain(m *testing.M) {
	restoreWork = anchor.EasyWorkForTesting()
	code := m.Run()
	restoreWork()
	os.Exit(code)
}

// inCheckedBlock gives a proof the header of the block its Bitcoin
// attestation names, mined in the test at a time: what `auditlog anchor
// upgrade` keeps once explorers have returned it. A proof that reaches no
// Bitcoin attestation is returned as it is.
func inCheckedBlock(t *testing.T, p anchor.Proof, mined time.Time) anchor.Proof {
	t.Helper()
	digest, err := hex.DecodeString(p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	atts, err := anchor.Walk(digest, p.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range atts {
		if a.Kind != "bitcoin" {
			continue
		}
		p.Header, p.HeaderHeight = anchor.MineForTesting(a.Commitment, mined).Hex(), a.Height
		p.HeaderFrom, p.HeaderChecked = []string{"blockstream.info", "mempool.emzy.de"}, mined.Format(time.RFC3339)
		if _, err := anchor.Confirm(p); err != nil {
			t.Fatalf("the test's own anchor is not confirmed: %v", err)
		}
		return p
	}
	return p
}

// uncheck takes the header away from every proof kept, leaving what
// somebody who wrote "attested in block N" into anchors.json by hand would
// leave: a height and nothing more.
func uncheck(t *testing.T, root string) {
	t.Helper()
	af := &anchorFile{}
	if err := loadJSON(anchorPath(root), af); err != nil {
		t.Fatal(err)
	}
	for i := range af.Proofs {
		af.Proofs[i].Header, af.Proofs[i].HeaderHeight = "", 0
		af.Proofs[i].HeaderFrom, af.Proofs[i].HeaderChecked = nil, ""
	}
	if err := saveJSON(anchorPath(root), af); err != nil {
		t.Fatal(err)
	}
}

// The backdating an anchor has to withstand: "attested in block 921004"
// written into the store by somebody who can write it. With no header
// checked for that block it anchors nothing, in either proof; and a header
// nobody worked for is no header.
func TestAnAttestationWithNoCheckedBlockAnchorsNothing(t *testing.T) {
	root, id := clockSite(t)
	clockDo(t, root, id, incident.Action{Do: "discharge", Regime: "GDPR Article 33",
		Text: "notified the supervisory authority, reference 2026-118"})
	anchorHead(t, root, 921004)
	st, err := clockProof(t, root, id)
	if err != nil || st.Predicate.Verdict != proof.Proven {
		t.Fatalf("with its block checked: %v: %s", err, st.Predicate.Verdict)
	}
	anchored := *st.Predicate.Clock.Anchor
	if anchored.Hash == "" || anchored.Header == "" || anchored.Mined == "" {
		t.Errorf("the proof does not carry its block: %+v", anchored)
	}

	// The same store as a deployment would read it: a header mined in a
	// test is not a block.
	restoreWork()
	st, err = clockProof(t, root, id)
	restoreWork = anchor.EasyWorkForTesting()
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Clock.Anchor != nil {
		t.Errorf("a header nobody worked for anchored a decision: %v: %s", err, st.Predicate.Verdict)
	}

	uncheck(t, root)
	st, err = clockProof(t, root, id)
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || st.Predicate.Clock.Anchor != nil ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "no anchor whose block was checked") {
		t.Errorf("a height and nothing more anchored a decision: %v: %s %+v", err, st.Predicate.Verdict,
			st.Predicate.Checks[1])
	}

	// A sealed alert, the same way.
	root = sealSite(t)
	if err := cmdAlert(root, []string{"seal", writeFile(t, "alerts.jsonl", threeAlerts...)}); err != nil {
		t.Fatal(err)
	}
	alert := writeFile(t, "a1.json", threeAlerts[0])
	anchorSealHead(t, root, inBlock(870123), anchor.Anchored)
	st, err = sealedProof(t, root, "--alert", alert)
	if err != nil || st.Predicate.Verdict != proof.Proven || st.Predicate.Sealed.BlockHash == "" ||
		st.Predicate.Sealed.Header == "" {
		t.Fatalf("with its block checked: %v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Sealed)
	}
	uncheck(t, root)
	st, err = sealedProof(t, root, "--alert", alert)
	ev := st.Predicate.Sealed
	if err == nil || st.Predicate.Verdict != proof.Inconclusive || ev.Anchor != proof.AnchorUnconfirmed ||
		ev.Height != 870123 || ev.BlockHash != "" || ev.Header != "" ||
		!strings.Contains(st.Predicate.Checks[3].Detail, "no header checked for that block holds it") {
		t.Errorf("a height and nothing more anchored an alert: %v: %s %+v", err, st.Predicate.Verdict, ev)
	}
}

// A decision whose entry says it was written after the block that anchors
// it was mined is refuted: the time in the entry is not when it was written.
func TestADecisionDatedAfterItsBlockIsRefuted(t *testing.T) {
	root, id := clockSite(t)
	clockDo(t, root, id, incident.Action{Do: "discharge", Regime: "GDPR Article 33",
		Text: "notified the supervisory authority, reference 2026-118"})
	anchorHeadMined(t, root, 921004, time.Now().Add(-3*time.Hour))
	st, err := clockProof(t, root, id)
	if err == nil || st.Predicate.Verdict != proof.Refuted || st.Predicate.Checks[1].Passed ||
		!strings.HasPrefix(strings.Join(st.Predicate.Checks[1].Failures, ""), "written after its block: ") {
		t.Errorf("%v: %s %+v", err, st.Predicate.Verdict, st.Predicate.Checks[1])
	}
}
