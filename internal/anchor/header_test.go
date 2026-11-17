// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The first block of the chain: every number of it is published, and it was
// mined at the easiest difficulty there is.
const genesisHeader = "0100000000000000000000000000000000000000000000000000000000000000" +
	"000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa" +
	"4b1e5e4a29ab5f49ffff001d1dac2b7c"

func TestAHeaderIsReadAsTheChainWritesIt(t *testing.T) {
	h, err := ParseHeader(genesisHeader)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.Hash(), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"; got != want {
		t.Errorf("hash %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(h.MerkleRoot()),
		"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"; got != want {
		t.Errorf("merkle root %s, want %s", got, want)
	}
	if got, want := h.Time().Format(time.RFC3339), "2009-01-03T18:15:05Z"; got != want {
		t.Errorf("time %s, want %s", got, want)
	}
	if h.Bits() != 0x1d00ffff {
		t.Errorf("bits %#x", h.Bits())
	}
	if h.Hex() != genesisHeader {
		t.Error("the header does not round-trip")
	}
	// Its work is real at the difficulty it declares, and that difficulty
	// is nowhere near one a block is believed at.
	if err := h.checkWork(compactTarget(0x1d00ffff)); err != nil {
		t.Errorf("the genesis block's own work: %v", err)
	}
	if err := h.Worked(); err == nil || !strings.Contains(err.Error(), "easier") {
		t.Errorf("a difficulty-one header passed the floor: %v", err)
	}
	// One bit of the nonce, and the work is gone.
	bad := h
	bad[79] ^= 1
	if err := bad.checkWork(compactTarget(0x1d00ffff)); err == nil {
		t.Error("a header with its nonce changed still met its target")
	}
	for _, s := range []string{"", genesisHeader[:158], genesisHeader + "00", strings.ToUpper(genesisHeader),
		"zz" + genesisHeader[2:]} {
		if _, err := ParseHeader(s); err == nil {
			t.Errorf("%q read as a header", s)
		}
	}
}

func TestACompactTargetExpandsAsBitcoinDoes(t *testing.T) {
	for bits, want := range map[uint32]string{
		0x1d00ffff: "ffff0000000000000000000000000000000000000000000000000000",
		0x1b0404cb: "404cb000000000000000000000000000000000000000000000000",
		0x03123456: "123456",
		0x02123456: "1234",
		0x01123456: "12",
		// Negative, empty and overflowing ones are no target at all.
		0x04923456: "0",
		0x1d000000: "0",
		0xff00ffff: "0",
	} {
		if got := compactTarget(bits).Text(16); got != want {
			t.Errorf("%#08x expands to %s, want %s", bits, got, want)
		}
	}
	// The floor is difficulty one's target over the least difficulty.
	if workFloor.Sign() <= 0 || workFloor.Cmp(compactTarget(0x1d00ffff)) >= 0 {
		t.Error("the floor is not below difficulty one's target")
	}
}

// realAnchors are two calendars' proofs for one digest, upgraded on 17
// November 2026 and checked against the headers two explorers returned:
// blocks 966959 and 967150.
func realAnchors(t *testing.T) []Proof {
	t.Helper()
	b, err := os.ReadFile("testdata/anchored.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Proofs []Proof `json:"proofs"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Proofs) != 2 {
		t.Fatalf("testdata/anchored.json: %v", err)
	}
	return f.Proofs
}

func TestARealAnchorIsConfirmedAgainstItsBlock(t *testing.T) {
	ps := realAnchors(t)
	for i, want := range []Block{
		{Height: 966959, Hash: "000000000000000000003b5807ddd161ca867345646e5c3e21d06014d845fe3f",
			Mined: time.Date(2026, 9, 14, 11, 47, 45, 0, time.UTC)},
		{Height: 967150, Hash: "00000000000000000001998f987d447c78e4ca82e379843e18d5c79699f21f27",
			Mined: time.Date(2026, 9, 15, 16, 12, 52, 0, time.UTC)},
	} {
		got, err := Confirm(ps[i])
		if err != nil {
			t.Fatalf("%s: %v", ps[i].Calendar, err)
		}
		if got.Height != want.Height || got.Hash != want.Hash || !got.Mined.Equal(want.Mined) ||
			got.Header != ps[i].Header {
			t.Errorf("%s confirmed as %+v, want %+v", ps[i].Calendar, got, want)
		}
	}
}

// What somebody who can write the file a proof is kept in can do to make it
// say an earlier block, and why none of it counts.
func TestAnAnchorThatIsNotInItsBlockIsNotConfirmed(t *testing.T) {
	ps := realAnchors(t)
	real, other := ps[0], ps[1]
	digest, _ := hex.DecodeString(real.Digest)

	// "attested in block 800000", appended straight to the digest: the walk
	// reaches it, and it is a height and nothing more.
	forged := append([]byte{opAttestation}, magicBitcoin...)
	forged = append(forged, 0x03, 0x80, 0xea, 0x30) // a 3-byte payload: varint 800000
	if state, height, _, err := Classify(digest, forged); err != nil || state != Anchored || height != 800000 {
		t.Fatalf("the forged proof should classify as anchored by its own word: %v %v %v", state, height, err)
	}

	cases := map[string]struct {
		p    Proof
		want string
	}{
		"a forged attestation with no header": {
			Proof{Digest: real.Digest, Body: forged}, "has not been checked"},
		"a forged attestation beside a real block's header": {
			Proof{Digest: real.Digest, Body: forged, Header: real.Header, HeaderHeight: 800000},
			"does not hold this commitment"},
		"a real proof beside another real block's header": {
			Proof{Digest: real.Digest, Body: real.Body, Header: other.Header, HeaderHeight: real.HeaderHeight},
			"does not hold this commitment"},
		"a real proof whose header is said to be of another height": {
			Proof{Digest: real.Digest, Body: real.Body, Header: real.Header, HeaderHeight: real.HeaderHeight - 1},
			"names block"},
		"a real proof with its header gone": {
			Proof{Digest: real.Digest, Body: real.Body, HeaderHeight: real.HeaderHeight},
			"has not been checked"},
		"a real proof with a header that does not read": {
			Proof{Digest: real.Digest, Body: real.Body, Header: real.Header[:158], HeaderHeight: real.HeaderHeight},
			"does not read"},
		"another digest under a real proof": {
			Proof{Digest: strings.Repeat("ab", 32), Body: real.Body, Header: real.Header,
				HeaderHeight: real.HeaderHeight}, "does not hold this commitment"},
		"a pending proof": {
			Proof{Digest: real.Digest, Body: trimBitcoin(t, digest, real.Body), Header: real.Header,
				HeaderHeight: real.HeaderHeight}, ""},
	}
	for name, c := range cases {
		b, err := Confirm(c.p)
		if err == nil {
			t.Errorf("%s: confirmed in block %d", name, b.Height)
			continue
		}
		if c.want != "" && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: refused with %q, want it to say %q", name, err, c.want)
		}
	}
	if _, err := Confirm(Proof{Digest: real.Digest, Body: forged}); !errors.Is(err, ErrUnchecked) {
		t.Errorf("a Bitcoin attestation with no header is %v, want ErrUnchecked", err)
	}

	// A header whose work is real but too easy to believe is refused by the
	// floor, and accepted only when the floor is lowered to it: the floor is
	// what stands between a mined-to-order header and a proof.
	easy, _ := ParseHeader(genesisHeader)
	att := Attestation{Kind: "bitcoin", Commitment: easy.MerkleRoot(), Height: 0}
	if err := CheckBitcoin(att, easy); err == nil {
		t.Error("a difficulty-one header was believed")
	}
	if err := checkBitcoin(att, easy, compactTarget(0x1d00ffff)); err != nil {
		t.Errorf("with the floor lowered to it: %v", err)
	}
	att.Kind = "pending"
	if err := checkBitcoin(att, easy, compactTarget(0x1d00ffff)); err == nil {
		t.Error("a pending attestation was held to be in a block")
	}
}

// trimBitcoin cuts a proof back to something that reaches no Bitcoin
// attestation: the digest with a pending one on it.
func trimBitcoin(t *testing.T, digest, body []byte) []byte {
	t.Helper()
	uri := "https://alice.btc.calendar.opentimestamps.org"
	out := append([]byte{opAttestation}, magicPending...)
	out = append(out, byte(len(uri)+1), byte(len(uri)))
	out = append(out, uri...)
	if state, _, _, err := Classify(digest, out); err != nil || state != Pending {
		t.Fatalf("the pending proof does not read as pending: %v %v", state, err)
	}
	return out
}

// fakeExplorers answers as explorers would, by host.
type fakeExplorers struct {
	// hash and header are what each host says for the height; a missing host
	// does not answer.
	hash, header map[string]string
	asked        []string
}

func (f *fakeExplorers) Get(_ context.Context, url string) ([]byte, error) {
	f.asked = append(f.asked, url)
	host := strings.SplitN(strings.TrimPrefix(url, "https://"), "/", 2)[0]
	switch {
	case strings.Contains(url, "/block-height/"):
		if h, ok := f.hash[host]; ok {
			return []byte(h + "\n"), nil
		}
	case strings.HasSuffix(url, "/header"):
		if h, ok := f.header[host]; ok {
			return []byte(h), nil
		}
	}
	return nil, fmt.Errorf("%s: 404", host)
}

func TestAHeaderIsTakenOnlyWhenTwoExplorersAgree(t *testing.T) {
	ps := realAnchors(t)
	a, _ := ParseHeader(ps[0].Header)
	b, _ := ParseHeader(ps[1].Header)
	three := []string{"https://one.example/api", "https://two.example/api/", "https://three.example/api"}
	says := func(m map[string]Header) *fakeExplorers {
		f := &fakeExplorers{hash: map[string]string{}, header: map[string]string{}}
		for host, h := range m {
			f.hash[host], f.header[host] = h.Hash(), h.Hex()
		}
		return f
	}

	got, hosts, err := FetchHeader(context.Background(),
		says(map[string]Header{"one.example": a, "two.example": a, "three.example": a}), three, 966959)
	if err != nil || got != a || strings.Join(hosts, ",") != "one.example,three.example,two.example" {
		t.Fatalf("three agreeing: %v %v", hosts, err)
	}
	// One of three unreachable: two still agree.
	got, hosts, err = FetchHeader(context.Background(),
		says(map[string]Header{"one.example": a, "three.example": a}), three, 966959)
	if err != nil || got != a || strings.Join(hosts, ",") != "one.example,three.example" {
		t.Fatalf("two of three: %v %v", hosts, err)
	}
	// One alone is nobody's word but its own.
	if _, _, err := FetchHeader(context.Background(), says(map[string]Header{"two.example": a}), three,
		966959); err == nil || !strings.Contains(err.Error(), "only when two explorers") {
		t.Errorf("one explorer alone: %v", err)
	}
	// Two that disagree settle nothing, whatever a third says.
	if _, _, err := FetchHeader(context.Background(),
		says(map[string]Header{"one.example": a, "two.example": b, "three.example": a}), three,
		966959); err == nil || !strings.Contains(err.Error(), "different headers") {
		t.Errorf("explorers that disagree: %v", err)
	}
	// An explorer whose header is not the block it named is not counted.
	lying := says(map[string]Header{"one.example": a, "two.example": a})
	lying.header["two.example"] = b.Hex()
	if _, _, err := FetchHeader(context.Background(), lying, three[:2], 966959); err == nil ||
		!strings.Contains(err.Error(), "is not block") {
		t.Errorf("a header that is not the named block's: %v", err)
	}
	// Only https, and at least the default three when none is named.
	plain := says(map[string]Header{"one.example": a, "two.example": a})
	if _, _, err := FetchHeader(context.Background(), plain,
		[]string{"http://one.example/api", "https://two.example/api"}, 966959); err == nil {
		t.Error("an explorer over plain http was asked")
	}
	for _, u := range plain.asked {
		if strings.HasPrefix(u, "http://") {
			t.Errorf("%s was fetched", u)
		}
	}
	if len(Explorers) < 3 {
		t.Error("fewer than three explorers by default: one unreachable would stop every check")
	}
}

func TestCheckingAHeaderKeepsItOnlyWhenItHoldsTheCommitment(t *testing.T) {
	ps := realAnchors(t)
	real, other := ps[0], ps[1]
	a, _ := ParseHeader(real.Header)
	b, _ := ParseHeader(other.Header)
	two := []string{"https://one.example/api", "https://two.example/api"}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	bare := real
	bare.Header, bare.HeaderHeight, bare.HeaderFrom, bare.HeaderChecked = "", 0, nil, ""

	right := &fakeExplorers{hash: map[string]string{"one.example": a.Hash(), "two.example": a.Hash()},
		header: map[string]string{"one.example": a.Hex(), "two.example": a.Hex()}}
	out, blk, err := CheckHeader(context.Background(), right, bare, two, now)
	if err != nil {
		t.Fatal(err)
	}
	if blk.Height != 966959 || out.Header != real.Header || out.HeaderHeight != 966959 ||
		strings.Join(out.HeaderFrom, ",") != "one.example,two.example" ||
		out.HeaderChecked != "2026-11-17T12:00:00Z" {
		t.Errorf("checked as %+v, kept %+v", blk, out)
	}
	if !strings.HasSuffix(right.asked[0], "/block-height/966959") {
		t.Errorf("the height asked for is not the attestation's: %s", right.asked[0])
	}
	// Checked already: nothing is fetched.
	right.asked = nil
	if _, _, err := CheckHeader(context.Background(), right, out, two, now); err != nil || len(right.asked) != 0 {
		t.Errorf("a proof already checked was fetched again: %v %v", right.asked, err)
	}

	// Explorers that agree on a block that does not hold the commitment —
	// the calendar's word was wrong, or the chain reorganised: nothing is
	// kept.
	wrong := &fakeExplorers{hash: map[string]string{"one.example": b.Hash(), "two.example": b.Hash()},
		header: map[string]string{"one.example": b.Hex(), "two.example": b.Hex()}}
	out, _, err = CheckHeader(context.Background(), wrong, bare, two, now)
	if err == nil || !strings.Contains(err.Error(), "does not hold this commitment") || out.Header != "" {
		t.Errorf("a block without the commitment: %v, header kept %q", err, out.Header)
	}
}

// A test may lower the floor and mine for its own commitment; a built
// program may not, whatever calls the hook.
func TestTheFloorCanBeLoweredOnlyInATest(t *testing.T) {
	ps := realAnchors(t)
	digest, _ := hex.DecodeString(ps[0].Digest)
	forged := append([]byte{opAttestation}, magicBitcoin...)
	forged = append(forged, 0x03, 0x80, 0xea, 0x30)
	mined := MineForTesting(digest, time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC))
	p := Proof{Digest: ps[0].Digest, Body: forged, Header: mined.Hex(), HeaderHeight: 800000}

	if _, err := Confirm(p); err == nil || !strings.Contains(err.Error(), "easier") {
		t.Fatalf("a header mined in a test was believed at the real floor: %v", err)
	}
	restore := EasyWorkForTesting()
	b, err := Confirm(p)
	if err != nil || b.Height != 800000 || !b.Mined.Equal(time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("with the floor lowered for the test: %+v %v", b, err)
	}
	restore()
	if _, err := Confirm(p); err == nil {
		t.Error("the floor was not put back")
	}
	if _, err := Confirm(ps[0]); err != nil {
		t.Errorf("a real anchor after the floor was put back: %v", err)
	}

	if testing.Short() {
		return
	}
	// The same call from a program `go build` makes: an overlay stands a
	// main package beside this one without writing into the tree.
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]string{
		"EasyWorkForTesting": "anchor.EasyWorkForTesting()",
		"MineForTesting":     "anchor.MineForTesting(make([]byte, 32), time.Now())",
	} {
		src := filepath.Join(dir, name+".go")
		body := "package main\n\nimport (\n\t\"time\"\n\n\t\"github.com/aertun/aertun/internal/anchor\"\n)\n\n" +
			"var _ = time.Now\n\nfunc main() { " + call + " }\n"
		if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{
			filepath.Join(wd, "hookcheck", "main.go"): src}})
		of := filepath.Join(dir, name+".json")
		if err := os.WriteFile(of, overlay, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("go", "run", "-overlay", of, "./hookcheck").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "only in a test") {
			t.Errorf("%s ran in a built program: %v\n%s", name, err, out)
		}
	}
}
