// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// A test cannot mine a block, and a proof made in a test still has to be
// anchored in one. So a test may lower the work a header is believed at to
// the easiest there is, and mine a header for its own commitment in a few
// tries. Both refuse to run outside a test binary: testing.Testing is false
// in everything `go build` makes, so nothing a deployment runs can lower the
// floor, whatever calls these.

// easyBits is the compact form of the easiest target Bitcoin's own
// regression-test network uses: half of all hashes meet it.
const easyBits = 0x207fffff

// EasyWorkForTesting lowers the least work a header is believed at to the
// easiest there is, and returns what puts it back. It panics outside a test.
func EasyWorkForTesting() (restore func()) {
	if !testing.Testing() {
		panic("anchor: the work a block is believed at can be lowered only in a test")
	}
	was := workFloor
	workFloor = new(big.Int).Set(compactTarget(easyBits))
	return func() { workFloor = was }
}

// MineForTesting makes a header whose merkle root is root and whose time is
// at, with work enough for EasyWorkForTesting's floor and no other. It
// panics outside a test.
func MineForTesting(root []byte, at time.Time) Header {
	if !testing.Testing() {
		panic("anchor: a header can be made only in a test")
	}
	var h Header
	binary.LittleEndian.PutUint32(h[0:4], 0x20000000)
	copy(h[36:68], root)
	binary.LittleEndian.PutUint32(h[68:72], uint32(at.Unix()))
	binary.LittleEndian.PutUint32(h[72:76], easyBits)
	for nonce := uint32(0); ; nonce++ {
		binary.LittleEndian.PutUint32(h[76:80], nonce)
		if h.checkWork(compactTarget(easyBits)) == nil {
			return h
		}
	}
}
