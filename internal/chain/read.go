// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/aertun/aertun/internal/proof"
)

// The calls a posture is read with. A selector is the first four bytes of
// the Keccak-256 of the function's signature, and an EIP-1967 slot is the
// Keccak-256 of its label less one. They are written out rather than
// computed because the standard library has SHA-3 and not Keccak-256,
// which differs from it in a padding byte; each was checked with OpenSSL
// 3.2 or later, which has it:
//
//	printf '%s' 'getThreshold()' | openssl dgst -keccak-256
const (
	// selectorGetThreshold is getThreshold(): a Safe's threshold, uint256.
	selectorGetThreshold = "0xe75235b8"
	// selectorGetOwners is getOwners(): a Safe's owners, address[].
	selectorGetOwners = "0xa0e67e2b"
	// selectorGetMinDelay is getMinDelay(): an OpenZeppelin
	// TimelockController's minimum delay in seconds, uint256.
	selectorGetMinDelay = "0xf27a0c92"
	// slotAdmin is bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1),
	// where an EIP-1967 proxy keeps the address that may upgrade it.
	slotAdmin = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
	// slotImplementation is
	// bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1),
	// where it keeps the address of the code it runs.
	slotImplementation = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)

var (
	quantityShape = regexp.MustCompile(`^0x[0-9a-fA-F]{1,16}$`)
	dataShape     = regexp.MustCompile(`^0x(?:[0-9a-fA-F]{2})*$`)
	wordShape     = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	hashShape     = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
)

// Reading is what was read for a posture at one block.
type Reading struct {
	// ChainID is the chain the endpoint said it serves, and the posture
	// declares.
	ChainID int64
	// Block and BlockHash are the block every setting was read at.
	Block     int64
	BlockHash string
	// Finalized says the block was the endpoint's latest finalized one.
	Finalized bool
	// Settings are every declared setting with what was read for it.
	Settings []proof.PostureReading
	// Lines are every call made and what came of it, one JSON object per
	// line: what the proof's chain-state material is a digest of.
	Lines []byte
	// Calls is how many calls were made.
	Calls int
}

// Read reads every setting a posture declares, at block, or at the
// endpoint's latest finalized block when block is negative.
//
// The chain and the block are read first, and either failing is an error:
// a proof needs to say which state it read, and a posture for one chain
// read from an endpoint for another is a mistake, not a finding. After
// that nothing is an error. A setting that cannot be read is unread, with
// the reason, and the proof says so.
func Read(ctx context.Context, c *Client, p *Posture, block int64) (*Reading, error) {
	r := &Reading{}
	var lines bytes.Buffer
	line := func(method string, params []any, result any, reason string) {
		r.Calls++
		entry := map[string]any{"method": method, "params": params}
		if reason != "" {
			entry["unread"] = reason
		} else {
			entry["result"] = result
		}
		b, _ := json.Marshal(entry)
		lines.Write(b)
		lines.WriteByte('\n')
	}

	raw, err := c.call(ctx, "eth_chainId")
	if err != nil {
		return nil, fmt.Errorf("%w, so which chain it serves is not known", err)
	}
	chainID, ok := quantity(raw)
	if !ok {
		return nil, fmt.Errorf("the RPC endpoint at %s answered eth_chainId with something that "+
			"is not a chain id", c.host)
	}
	line("eth_chainId", []any{}, chainID, "")
	if chainID != p.ChainID {
		return nil, fmt.Errorf("the RPC endpoint at %s serves chain %d, and the posture declares "+
			"chain %d: read it from an endpoint for chain %d", c.host, chainID, p.ChainID, p.ChainID)
	}
	r.ChainID = chainID

	tag := "finalized"
	if block >= 0 {
		tag = "0x" + strconv.FormatInt(block, 16)
	}
	raw, err = c.call(ctx, "eth_getBlockByNumber", tag, false)
	if err != nil {
		if block < 0 {
			return nil, fmt.Errorf("%w; it may know no finalized block, so name a block to read at", err)
		}
		return nil, err
	}
	var b struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if string(raw) == "null" {
		if block < 0 {
			return nil, fmt.Errorf("the RPC endpoint at %s knows no finalized block; name a block "+
				"to read at", c.host)
		}
		return nil, fmt.Errorf("the RPC endpoint at %s has no block %d yet", c.host, block)
	}
	if err := json.Unmarshal(raw, &b); err != nil || !hashShape.MatchString(b.Hash) {
		return nil, fmt.Errorf("the RPC endpoint at %s answered for the block without a hash a "+
			"proof can name it by", c.host)
	}
	height, ok := quantityText(b.Number)
	if !ok || (block >= 0 && height != block) {
		return nil, fmt.Errorf("the RPC endpoint at %s answered for another block than the one asked", c.host)
	}
	r.Block, r.BlockHash, r.Finalized = height, strings.ToLower(b.Hash), block < 0
	line("eth_getBlockByNumber", []any{tag, false}, map[string]any{"number": r.Block, "hash": r.BlockHash}, "")

	// Every read from here names the block by its hash, not its number, so
	// a block replaced at that height while this runs cannot be read from.
	at := map[string]string{"blockHash": r.BlockHash}
	callData := func(to, selector string) ([]byte, string) {
		params := []any{map[string]string{"to": to, "data": selector}, at}
		raw, err := c.call(ctx, "eth_call", params...)
		if err != nil {
			line("eth_call", params, nil, proof.UnreadRPCError)
			return nil, proof.UnreadRPCError
		}
		data, ok := hexData(raw)
		if !ok {
			line("eth_call", params, nil, proof.UnreadRPCError)
			return nil, proof.UnreadRPCError
		}
		line("eth_call", params, "0x"+hex.EncodeToString(data), "")
		return data, ""
	}
	storage := func(contract, slot string) ([]byte, string) {
		params := []any{contract, slot, at}
		raw, err := c.call(ctx, "eth_getStorageAt", params...)
		if err != nil {
			line("eth_getStorageAt", params, nil, proof.UnreadRPCError)
			return nil, proof.UnreadRPCError
		}
		var s string
		if json.Unmarshal(raw, &s) != nil || !wordShape.MatchString(s) {
			line("eth_getStorageAt", params, nil, proof.UnreadRPCError)
			return nil, proof.UnreadRPCError
		}
		word, _ := hex.DecodeString(s[2:])
		line("eth_getStorageAt", params, "0x"+hex.EncodeToString(word), "")
		return word, ""
	}
	reading := func(s setting, found, reason string) {
		r.Settings = append(r.Settings, proof.PostureReading{Address: s.address, Setting: s.name,
			Declared: s.declared, Found: found, Reason: reason})
	}

	declared := p.settings()
	for i := 0; i < len(declared); i++ {
		s := declared[i]
		switch s.name {
		case proof.SettingSafeThreshold:
			// A Safe's two settings are read together, because each is
			// checked against the other: a threshold of none, or above the
			// owners, is not a Safe's answer.
			threshold, tReason := uintAnswer(callData(s.address, selectorGetThreshold))
			owners, oReason := ownersAnswer(callData(s.address, selectorGetOwners))
			if tReason == "" && threshold > proof.MaxSafeOwners {
				tReason = proof.UnreadOutOfRange
			}
			if tReason == "" && (threshold < 1 || (oReason == "" && threshold > owners)) {
				tReason = proof.UnreadMalformed
			}
			reading(s, number(threshold, tReason), tReason)
			i++
			reading(declared[i], number(owners, oReason), oReason)
		case proof.SettingTimelockDelay:
			delay, reason := uintAnswer(callData(s.address, selectorGetMinDelay))
			reading(s, number(delay, reason), reason)
		case proof.SettingProxyAdmin:
			// The implementation slot is read whether or not one is
			// declared: an empty one says the contract is not an EIP-1967
			// proxy, and then its admin slot means nothing either.
			admin, aReason := addressAnswer(storage(s.address, slotAdmin))
			impl, iReason := addressAnswer(storage(s.address, slotImplementation))
			if iReason == "" && impl == proof.ZeroAddress {
				iReason, impl = proof.UnreadNotAProxy, ""
				aReason, admin = proof.UnreadNotAProxy, ""
			}
			reading(s, admin, aReason)
			if i+1 < len(declared) && declared[i+1].name == proof.SettingProxyImplementation &&
				declared[i+1].address == s.address {
				i++
				reading(declared[i], impl, iReason)
			}
		}
	}
	r.Lines = lines.Bytes()
	return r, nil
}

// number is a number read as a proof writes it, or nothing when it was not
// read.
func number(n int64, reason string) string {
	if reason != "" {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

// quantity reads a JSON-RPC quantity — a JSON string of 0x and hexadecimal
// digits — that a proof can carry.
func quantity(raw json.RawMessage) (int64, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0, false
	}
	return quantityText(s)
}

// quantityText is quantity for a value already read as a string.
func quantityText(s string) (int64, bool) {
	if !quantityShape.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s[2:], 16, 64)
	if err != nil || n > proof.MaxChainNumber {
		return 0, false
	}
	return int64(n), true
}

// hexData reads a JSON-RPC data string.
func hexData(raw json.RawMessage) ([]byte, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil || !dataShape.MatchString(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil
}

// uintAnswer decodes an ABI-encoded uint256 that a proof can carry.
func uintAnswer(b []byte, reason string) (int64, string) {
	switch {
	case reason != "":
		return 0, reason
	case len(b) == 0:
		return 0, proof.UnreadEmpty
	case len(b) != 32:
		return 0, proof.UnreadMalformed
	}
	return word(b)
}

// word is a 32-byte word as a number a proof can carry.
func word(w []byte) (int64, string) {
	if !allZero(w[:24]) {
		return 0, proof.UnreadOutOfRange
	}
	n := binary.BigEndian.Uint64(w[24:])
	if n > proof.MaxChainNumber {
		return 0, proof.UnreadOutOfRange
	}
	return int64(n), ""
}

// addressWord is a 32-byte word as an address: twelve zero bytes and
// twenty that are the address.
func addressWord(w []byte) (string, bool) {
	if len(w) != 32 || !allZero(w[:12]) {
		return "", false
	}
	return "0x" + hex.EncodeToString(w[12:]), true
}

// addressAnswer decodes a storage slot holding an address.
func addressAnswer(w []byte, reason string) (string, string) {
	if reason != "" {
		return "", reason
	}
	a, ok := addressWord(w)
	if !ok {
		return "", proof.UnreadMalformed
	}
	return a, ""
}

// ownersAnswer decodes getOwners()'s address[] and counts it: an offset of
// one word, a length, and that many address words, with nothing after, no
// owner twice and none the zero address.
func ownersAnswer(b []byte, reason string) (int64, string) {
	if reason != "" {
		return 0, reason
	}
	if len(b) == 0 {
		return 0, proof.UnreadEmpty
	}
	if len(b) < 64 || len(b)%32 != 0 {
		return 0, proof.UnreadMalformed
	}
	if offset, r := word(b[:32]); r != "" || offset != 32 {
		return 0, proof.UnreadMalformed
	}
	n, r := word(b[32:64])
	if r != "" || n > proof.MaxSafeOwners {
		return 0, proof.UnreadOutOfRange
	}
	if int64(len(b)) != 64+32*n || n == 0 {
		return 0, proof.UnreadMalformed
	}
	seen := map[string]bool{}
	for i := int64(0); i < n; i++ {
		a, ok := addressWord(b[64+32*i : 96+32*i])
		if !ok || a == proof.ZeroAddress || seen[a] {
			return 0, proof.UnreadMalformed
		}
		seen[a] = true
	}
	return n, ""
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
