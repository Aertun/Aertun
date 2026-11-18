// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
)

// A proof made in a test is anchored in a block mined in the test, which
// internal/anchor believes only while a test has lowered the work a block
// is believed at. realWork puts the floor back for one test.
var restoreWork func()

func TestMain(m *testing.M) {
	restoreWork = anchor.EasyWorkForTesting()
	code := m.Run()
	restoreWork()
	os.Exit(code)
}

// realWork runs f with the work a block is believed at as a deployment has
// it.
func realWork(f func()) {
	restoreWork()
	defer func() { restoreWork = anchor.EasyWorkForTesting() }()
	f()
}

// testBlock is a block mined in the test at a time: its hash, the time its
// header carries and the header.
func testBlock(at time.Time) (hash, mined, header string) {
	h := anchor.MineForTesting(bytes.Repeat([]byte{0x5a}, 32), at)
	return h.Hash(), h.Time().Format(time.RFC3339), h.Hex()
}

// realBlock is block 966959 as the chain has it, read from the anchor
// package's test data: a header with a real block's work.
var realBlock = func() struct{ Hash, Mined, Header string } {
	b, err := os.ReadFile("../anchor/testdata/anchored.json")
	if err != nil {
		panic(err)
	}
	i := bytes.Index(b, []byte(`"header": "`))
	hex := string(b[i+11 : i+11+160])
	h, err := anchor.ParseHeader(hex)
	if err != nil {
		panic(err)
	}
	return struct{ Hash, Mined, Header string }{h.Hash(), h.Time().Format(time.RFC3339), h.Hex()}
}()

// A header mined in a test is believed only in a test: with the floor as a
// deployment has it, a proof resting on one is refused on both sides of
// signing, and one resting on a real block's header is not.
func TestAProofRestsOnlyOnABlockWithRealWork(t *testing.T) {
	clock := clockInput()
	sealed, _ := sealedInput(t)
	cst, err := ProveClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	sst, err := ProveSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	realWork(func() {
		if _, err := ProveClock(clock); err == nil || !strings.Contains(err.Error(), "not one to believe") {
			t.Errorf("a clock proof was made on a header nobody worked for: %v", err)
		}
		if _, err := ProveSealed(sealed); err == nil || !strings.Contains(err.Error(), "not one to believe") {
			t.Errorf("a sealed proof was made on a header nobody worked for: %v", err)
		}
		if cst.Validate() == nil || sst.Validate() == nil {
			t.Error("a statement resting on a header nobody worked for validated")
		}

		// The same proofs on block 966959's own header, the decision and
		// the seal dated before it was mined.
		mined, _ := time.Parse(time.RFC3339, realBlock.Mined)
		real := clockInput()
		a := *real.Evidence.Anchor
		a.Block, a.Hash, a.Mined, a.Header = 966959, realBlock.Hash, realBlock.Mined, realBlock.Header
		real.Evidence.Anchor = &a
		shift := mined.Add(-10 * time.Minute).Sub(ck0)
		move := func(s string) string {
			if s == "" {
				return s
			}
			at, _ := time.Parse(time.RFC3339Nano, s)
			return instant(at.Add(shift))
		}
		real.Evidence.Decided, real.Evidence.Recorded = move(real.Evidence.Decided), move(real.Evidence.Recorded)
		real.Evidence.Duties = append([]ClockDuty{}, real.Evidence.Duties...)
		real.Evidence.Duties[0].Due, real.Evidence.Duties[0].Done = move(real.Evidence.Duties[0].Due),
			move(real.Evidence.Duties[0].Done)
		real.Now = real.Now.Add(shift)
		st, err := ProveClock(real)
		if err != nil || st.Predicate.Verdict != Proven || st.Validate() != nil {
			t.Errorf("a clock proof on a real block: %v", err)
		}
		rs, _ := sealedInput(t)
		rs.Evidence.Height, rs.Evidence.BlockHash = 966959, realBlock.Hash
		rs.Evidence.Mined, rs.Evidence.Header = realBlock.Mined, realBlock.Header
		st, err = ProveSealed(rs)
		if err != nil || st.Predicate.Verdict != Proven || st.Validate() != nil {
			t.Errorf("a sealed proof on a real block: %v", err)
		}
	})
}
