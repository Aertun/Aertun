// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// # The block an attestation names, checked
//
// A Bitcoin attestation in an OpenTimestamps proof is a block height and
// nothing else. Walking the proof shows the digest reaches a value — the
// merkle root the attestation says is in that block — but not that any
// block holds it: anybody who can write the file a proof is kept in can
// append "attested in block 800000" to a digest and the walk will reach it.
// For a proof that says when something existed, that is a backdating, and
// the people best placed to make it are the ones a proof of time is meant
// to hold to account.
//
// So a Bitcoin attestation counts only with its block's header beside it,
// checked three ways:
//
//   - The header's merkle root is the value the walk reached. Only the block
//     that really includes the calendar's transaction has it.
//   - The header's hash meets the target its own bits declare, and that
//     target is no easier than MinWorkDifficulty's: making a header that passes costs the
//     work of mining a block at a difficulty Bitcoin has been above since
//     mid-2023, around a hundred thousand dollars of hash power, and it
//     would still not be in the chain.
//   - When it was fetched, at least two independent explorers returned the
//     same header for that height, none returned another, and its hash is
//     the one each named for it.
//
// The first two are checked offline, every time a proof is made, from the
// eighty bytes kept with the attestation. The third cannot be checked again
// offline, which is why a proof names the block's hash: whoever reads it can
// look up that one hash at that height in any node or explorer they trust.

// HeaderSize is the length of a Bitcoin block header.
const HeaderSize = 80

// MinWorkDifficulty is the least difficulty a header must have been mined at
// for its block to be believed: 50 trillion, which Bitcoin has been above
// since mid-2023 and is a third of what it was in November 2026. A block anchored by
// this program is far above it; a header made to pass it costs the work of
// mining one.
const MinWorkDifficulty = 50_000_000_000_000

// workFloor is the highest target a header's hash may meet: difficulty-one's
// target divided by MinWorkDifficulty. Unexported, so nothing outside this
// package can move it; EasyWorkForTesting does, and only inside a test.
var workFloor = new(big.Int).Div(compactTarget(0x1d00ffff), big.NewInt(MinWorkDifficulty))

// Header is a Bitcoin block header, as the chain serialises it.
type Header [HeaderSize]byte

var hexHeader = regexp.MustCompile(`^[0-9a-f]{160}$`)

// ParseHeader reads a header from the hex an explorer returns.
func ParseHeader(s string) (Header, error) {
	var h Header
	s = strings.TrimSpace(s)
	if !hexHeader.MatchString(s) {
		return h, fmt.Errorf("a block header is %d bytes of lowercase hex", HeaderSize)
	}
	b, _ := hex.DecodeString(s)
	copy(h[:], b)
	return h, nil
}

// Hex is the header as an explorer gives it.
func (h Header) Hex() string { return hex.EncodeToString(h[:]) }

// Hash is the block's hash, as explorers and nodes display it: the double
// SHA-256 of the header, byte-reversed.
func (h Header) Hash() string {
	first := sha256.Sum256(h[:])
	second := sha256.Sum256(first[:])
	return hex.EncodeToString(reversed(second[:]))
}

// MerkleRoot is the root of the block's transactions, in the order the
// header holds it, which is the order an OpenTimestamps walk reaches it in.
func (h Header) MerkleRoot() []byte { return append([]byte(nil), h[36:68]...) }

// Time is when the block's miner says it was mined. Bitcoin accepts a time
// up to two hours ahead of the network's, and one as far behind as the
// median of the eleven blocks before it.
func (h Header) Time() time.Time {
	return time.Unix(int64(binary.LittleEndian.Uint32(h[68:72])), 0).UTC()
}

// Bits is the target the header declares its hash meets, compactly.
func (h Header) Bits() uint32 { return binary.LittleEndian.Uint32(h[72:76]) }

// Worked reports whether work was done for the header that a block is
// believed at: its hash meets the target its own bits declare, and that
// target is no easier than MinWorkDifficulty's.
func (h Header) Worked() error { return h.checkWork(workFloor) }

func (h Header) checkWork(floor *big.Int) error {
	target := compactTarget(h.Bits())
	if target.Sign() <= 0 {
		return fmt.Errorf("the header's bits %#08x declare no target", h.Bits())
	}
	if target.Cmp(floor) > 0 {
		return fmt.Errorf("the header's bits %#08x declare a target easier than difficulty %d, "+
			"which no block this program could have been anchored in was mined at", h.Bits(),
			int64(MinWorkDifficulty))
	}
	hash, _ := hex.DecodeString(h.Hash())
	if new(big.Int).SetBytes(hash).Cmp(target) > 0 {
		return fmt.Errorf("the header's hash does not meet the target its bits declare, so no " +
			"work was done for it")
	}
	return nil
}

// compactTarget expands Bitcoin's compact encoding of a target. A negative
// or overflowing one is zero, which no hash meets.
func compactTarget(bits uint32) *big.Int {
	exponent := int(bits >> 24)
	mantissa := int64(bits & 0x007fffff)
	if bits&0x00800000 != 0 || mantissa == 0 || exponent > 34 {
		return new(big.Int)
	}
	t := big.NewInt(mantissa)
	if exponent <= 3 {
		return t.Rsh(t, uint(8*(3-exponent)))
	}
	return t.Lsh(t, uint(8*(exponent-3)))
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// CheckBitcoin reports whether a Bitcoin attestation is in the block whose
// header is h: the value the walk reached is the header's merkle root, and
// the header was worked for at a difficulty of at least MinWorkDifficulty.
func CheckBitcoin(a Attestation, h Header) error {
	return checkBitcoin(a, h, workFloor)
}

func checkBitcoin(a Attestation, h Header, floor *big.Int) error {
	if a.Kind != "bitcoin" {
		return fmt.Errorf("the attestation is not a Bitcoin one")
	}
	if len(a.Commitment) != sha256.Size || !bytes.Equal(a.Commitment, h.MerkleRoot()) {
		return fmt.Errorf("the proof reaches %x, and block %s's merkle root is %x: the block does "+
			"not hold this commitment", a.Commitment, h.Hash(), h.MerkleRoot())
	}
	return h.checkWork(floor)
}

// Block is the Bitcoin block a proof is anchored in, checked.
type Block struct {
	// Height is the block's height, as the attestation names it and as the
	// explorers confirmed it.
	Height uint64
	// Hash is the block's hash: what a reader looks up to check it.
	Hash string
	// Mined is the time the header carries.
	Mined time.Time
	// Header is the header, in hex.
	Header string
}

// ErrUnchecked is a Bitcoin attestation with no header checked for it yet:
// what `aertun auditlog anchor upgrade` fetches.
var ErrUnchecked = errors.New("its block's header has not been checked")

// Confirm is the block a proof is anchored in: the Bitcoin attestation its
// operations reach from its digest, held against the header kept with it.
// It is the only way a proof counts as anchored for anything this program
// signs; the state stored beside it is never read.
func Confirm(p Proof) (Block, error) { return confirm(p, workFloor) }

func confirm(p Proof, floor *big.Int) (Block, error) {
	digest, err := hex.DecodeString(p.Digest)
	if err != nil {
		return Block{}, fmt.Errorf("the stored digest is not hex")
	}
	atts, err := Walk(digest, p.Body)
	if err != nil {
		return Block{}, err
	}
	var bitcoin []Attestation
	for _, a := range atts {
		if a.Kind == "bitcoin" {
			bitcoin = append(bitcoin, a)
		}
	}
	if len(bitcoin) == 0 {
		return Block{}, fmt.Errorf("the proof reaches no Bitcoin attestation")
	}
	if p.Header == "" {
		return Block{}, ErrUnchecked
	}
	h, err := ParseHeader(p.Header)
	if err != nil {
		return Block{}, fmt.Errorf("the header kept with it does not read: %w", err)
	}
	var last error
	for _, a := range bitcoin {
		if a.Height != p.HeaderHeight {
			last = fmt.Errorf("the header kept with it is of block %d, and the attestation names "+
				"block %d", p.HeaderHeight, a.Height)
			continue
		}
		if err := checkBitcoin(a, h, floor); err != nil {
			last = err
			continue
		}
		return Block{Height: a.Height, Hash: h.Hash(), Mined: h.Time(), Header: h.Hex()}, nil
	}
	return Block{}, last
}

// -- fetching a header -------------------------------------------------------

// Explorers are the public Esplora explorers a header is fetched from:
// three operators, each serving the same API. A header is taken when two of
// them return it and none returns another, so one being unreachable from a
// network does not stop a check, and one alone cannot make a header up.
var Explorers = []string{
	"https://blockstream.info/api",
	"https://mempool.space/api",
	"https://mempool.emzy.de/api",
}

// Getter fetches a URL. Submitter is one.
type Getter interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FetchHeader asks each explorer for the header of the block at height, and
// returns it with the hosts that returned it, when at least two did and none
// returned another. An explorer that answers with a header whose hash is not
// the one it named for that height is not counted, and one that disagrees
// with another stops the fetch: which of them is lying is not a question to
// settle by vote.
func FetchHeader(ctx context.Context, g Getter, explorers []string, height uint64) (Header, []string, error) {
	if len(explorers) == 0 {
		explorers = Explorers
	}
	type answer struct {
		host string
		h    Header
	}
	var got []answer
	var failed []string
	for _, base := range explorers {
		u, err := url.Parse(base)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			failed = append(failed, fmt.Sprintf("%s is not an https URL", base))
			continue
		}
		host := strings.ToLower(u.Hostname())
		base = strings.TrimSuffix(base, "/")
		hb, err := g.Get(ctx, base+"/block-height/"+strconv.FormatUint(height, 10))
		hash := strings.TrimSpace(string(hb))
		if err != nil || !hexHash.MatchString(hash) {
			failed = append(failed, fmt.Sprintf("%s did not name a block at height %d", host, height))
			continue
		}
		body, err := g.Get(ctx, base+"/block/"+hash+"/header")
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s did not return block %s's header", host, hash))
			continue
		}
		h, err := ParseHeader(string(body))
		if err != nil || h.Hash() != hash {
			failed = append(failed, fmt.Sprintf("%s returned a header that is not block %s's", host, hash))
			continue
		}
		got = append(got, answer{host, h})
	}
	for _, a := range got[min(1, len(got)):] {
		if a.h != got[0].h {
			return Header{}, nil, fmt.Errorf("%s and %s return different headers for block %d, so "+
				"neither is taken", got[0].host, a.host, height)
		}
	}
	if len(got) < 2 {
		return Header{}, nil, fmt.Errorf("a header is taken only when two explorers return it, and "+
			"%d did (%s)", len(got), strings.Join(failed, "; "))
	}
	hosts := make([]string, 0, len(got))
	for _, a := range got {
		hosts = append(hosts, a.host)
	}
	sort.Strings(hosts)
	return got[0].h, hosts, nil
}

// CheckHeader fetches the header of the block a proof's Bitcoin attestation
// names and, when it holds the commitment, keeps it in the proof. A proof
// already checked is returned as it is.
func CheckHeader(ctx context.Context, g Getter, p Proof, explorers []string, now time.Time) (Proof, Block, error) {
	if b, err := Confirm(p); err == nil {
		return p, b, nil
	}
	digest, err := hex.DecodeString(p.Digest)
	if err != nil {
		return p, Block{}, fmt.Errorf("the stored digest is not hex")
	}
	atts, err := Walk(digest, p.Body)
	if err != nil {
		return p, Block{}, err
	}
	var last error = fmt.Errorf("the proof reaches no Bitcoin attestation")
	for _, a := range atts {
		if a.Kind != "bitcoin" {
			continue
		}
		h, hosts, err := FetchHeader(ctx, g, explorers, a.Height)
		if err != nil {
			last = err
			continue
		}
		if err := CheckBitcoin(a, h); err != nil {
			last = fmt.Errorf("block %d: %w", a.Height, err)
			continue
		}
		out := p
		out.Header, out.HeaderHeight, out.HeaderFrom = h.Hex(), a.Height, hosts
		out.HeaderChecked = now.UTC().Format(time.RFC3339)
		b, err := Confirm(out)
		return out, b, err
	}
	return p, Block{}, last
}
