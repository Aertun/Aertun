// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package cbor

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAppendixA holds the encoder to RFC 8949 Appendix A, both ways.
func TestAppendixA(t *testing.T) {
	cases := []struct {
		v   Value
		hex string
	}{
		{Uint(0), "00"},
		{Uint(23), "17"},
		{Uint(24), "1818"},
		{Uint(100), "1864"},
		{Uint(1000), "1903e8"},
		{Uint(1000000), "1a000f4240"},
		{Uint(1000000000000), "1b000000e8d4a51000"},
		{Uint(math.MaxUint64), "1bffffffffffffffff"},
		{Int(-1), "20"},
		{Int(-10), "29"},
		{Int(-100), "3863"},
		{Int(-1000), "3903e7"},
		{Int(math.MinInt64), "3b7fffffffffffffff"},
		{Bytes{}, "40"},
		{Bytes{1, 2, 3, 4}, "4401020304"},
		{Text(""), "60"},
		{Text("a"), "6161"},
		{Text("IETF"), "6449455446"},
		{Text("ü"), "62c3bc"},
		{Text("水"), "63e6b0b4"},
		{Bool(false), "f4"},
		{Bool(true), "f5"},
		{Null{}, "f6"},
		{Tagged{Tag: 1, Value: Uint(1363896240)}, "c11a514b67b0"},
		{Tagged{Tag: 32, Value: Text("http://www.example.com")}, "d82076687474703a2f2f7777772e6578616d706c652e636f6d"},
		{Array{}, "80"},
		{Array{Uint(1), Uint(2), Uint(3)}, "83010203"},
		{Array{Uint(1), Array{Uint(2), Uint(3)}, Array{Uint(4), Uint(5)}}, "8301820203820405"},
		{Map{}, "a0"},
		{Map{{Uint(1), Uint(2)}, {Uint(3), Uint(4)}}, "a201020304"},
		{Map{{Text("a"), Uint(1)}, {Text("b"), Array{Uint(2), Uint(3)}}}, "a26161016162820203"},
	}
	for _, c := range cases {
		got, err := Encode(c.v)
		if err != nil {
			t.Fatalf("%#v: %v", c.v, err)
		}
		if hex.EncodeToString(got) != c.hex {
			t.Errorf("%#v encodes as %x, want %s", c.v, got, c.hex)
		}
		back, err := Decode(got)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		again, _ := Encode(back)
		if !bytes.Equal(again, got) {
			t.Errorf("%s does not survive decoding: %x", c.hex, again)
		}
		if !Canonical(got) {
			t.Errorf("%s is not reported canonical", c.hex)
		}
	}
}

// TestMapOrder: keys are written in the bytewise order of their encodings
// (RFC 8949 §4.2.1) whatever order the map was built in, which puts
// positive integers before negative ones before text, and shorter text
// before longer.
func TestMapOrder(t *testing.T) {
	m := Map{
		{Text("aa"), Uint(0)}, {Int(-1), Uint(0)}, {Text("b"), Uint(0)},
		{Uint(10), Uint(0)}, {Int(100), Uint(0)}, {Uint(1), Uint(0)},
	}
	got, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	want := "a6" + "0100" + "0a00" + "186400" + "2000" + "616200" + "62616100"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x, want %s", got, want)
	}
}

func TestGet(t *testing.T) {
	m := Map{{Int(1), Text("one")}, {Int(-8), Text("eddsa")}, {Text("k"), Bool(true)}}
	if v, ok := m.Get(Uint(1)); !ok || v != Text("one") {
		t.Errorf("Uint(1) does not find the key written as Int(1): %v %v", v, ok)
	}
	if v, ok := m.Get(Int(-8)); !ok || v != Text("eddsa") {
		t.Errorf("Int(-8): %v %v", v, ok)
	}
	if _, ok := m.Get(Int(2)); ok {
		t.Error("an absent key is found")
	}
	if n, ok := AsInt(Uint(math.MaxUint64)); ok {
		t.Errorf("AsInt accepted a value outside int64: %d", n)
	}
}

// TestRefusals: every way the decoder refuses, each named.
func TestRefusals(t *testing.T) {
	cases := map[string]string{
		"indefinite array":        "9f01ff",
		"indefinite bytes":        "5f4101ff",
		"half float":              "f93c00",
		"double float":            "fb3ff199999999999a",
		"undefined":               "f7",
		"simple 16":               "f0",
		"duplicate key":           "a201020103",
		"duplicate key, long arg": "a20102180103",
		"array map key":           "a18001",
		"bytes map key":           "a1410102",
		"invalid utf-8":           "62c328",
		"truncated string":        "6461",
		"truncated argument":      "1903",
		"trailing byte":           "0000",
		"empty":                   "",
		"array count too large":   "9b00000000ffffffff",
		"map count too large":     "bb00000000ffffffff",
		"negative too small":      "3bffffffffffffffff",
		"reserved argument":       "1c",
	}
	for name, h := range cases {
		if _, err := Decode(mustHex(t, h)); err == nil {
			t.Errorf("%s (%s) was accepted", name, h)
		}
	}
	at := strings.Repeat("81", MaxDepth-1) + "80"
	if b, err := Decode(mustHex(t, at)); err != nil {
		t.Errorf("%d nested arrays were refused: %v", MaxDepth, err)
	} else if _, err := Encode(b); err != nil {
		t.Errorf("%d nested arrays decode but do not encode: %v", MaxDepth, err)
	}
	if _, err := Decode(mustHex(t, "81"+at)); err == nil {
		t.Errorf("%d nested arrays were accepted", MaxDepth+1)
	}
}

// TestLenientButReported: an argument written longer than needed, or keys
// out of order, decode (other encoders are not all deterministic) and are
// reported as not canonical.
func TestLenientButReported(t *testing.T) {
	for _, h := range []string{"1800", "a202000100", "5800"} {
		b := mustHex(t, h)
		if _, err := Decode(b); err != nil {
			t.Errorf("%s: %v", h, err)
		}
		if Canonical(b) {
			t.Errorf("%s is reported canonical", h)
		}
	}
}

func TestEncodeRefusals(t *testing.T) {
	bad := []Value{
		nil,
		Text("\xff"),
		Array{nil},
		Map{{Bytes{1}, Uint(1)}},
		Map{{Uint(1), Uint(1)}, {Int(1), Uint(2)}},
		Map{{Uint(1), nil}},
		Tagged{Tag: 1},
	}
	for _, v := range bad {
		if _, err := Encode(v); err == nil {
			t.Errorf("%#v encoded", v)
		}
	}
	var deep Value = Uint(0)
	for i := 0; i <= MaxDepth; i++ {
		deep = Array{deep}
	}
	if _, err := Encode(deep); err == nil {
		t.Error("a value nested past MaxDepth encoded")
	}
}

// FuzzDecode: whatever decodes re-encodes, and the re-encoding decodes to
// the same bytes again; nothing panics.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"a201020304", "d28443a10126a0f640", "9f01ff", "3b7fffffffffffffff"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Decode(b)
		if err != nil {
			return
		}
		out, err := Encode(v)
		if err != nil {
			t.Fatalf("decoded but does not encode: %v", err)
		}
		v2, err := Decode(out)
		if err != nil {
			t.Fatalf("re-encoding does not decode: %v", err)
		}
		out2, _ := Encode(v2)
		if !bytes.Equal(out, out2) {
			t.Fatalf("not stable: %x then %x", out, out2)
		}
	})
}
