// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package cbor is the subset of CBOR (RFC 8949) that COSE and SCITT use,
// written out so the format the evidence protocol rests on carries no
// dependency.
//
// # Deterministic, because the bytes are signed
//
// A COSE signature is over encoded bytes, and an action digest is a hash of
// encoded bytes that several parties must compute alike. So the encoder
// follows the core deterministic rules of RFC 8949 §4.2.1: every argument in
// its shortest form, definite lengths only, and map keys sorted by the
// bytewise order of their encodings. There is no float: nothing this program
// signs is one, and a float is a value whose bytes depend on rounding.
//
// # Strict, because the bytes come from other people's software
//
// The decoder refuses indefinite lengths, floats, undefined, duplicate map
// keys, map keys other than integers and text, invalid UTF-8, trailing bytes,
// and nesting past a fixed depth; and no length is believed beyond the bytes
// that remain. It does accept an argument written longer than it needed to
// be and keys out of order, since other encoders are not all deterministic
// and a signature is checked over the bytes as received, never over a
// re-encoding; Canonical says whether given bytes are in the deterministic
// form, for the places that require it.
package cbor

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// Value is anything this package encodes. A closed set: an int8 or a
// json.Number handed to a generic encoder would be written in whatever way
// seemed reasonable at the time, and these bytes are signed.
type Value interface{ encode(*encoder) error }

type (
	// Uint is a non-negative integer, major type 0.
	Uint uint64
	// Int is a signed integer: major type 0 when non-negative, 1 when not.
	Int int64
	// Bytes is a byte string, major type 2.
	Bytes []byte
	// Text is a UTF-8 string, major type 3.
	Text string
	// Array is a list, major type 4.
	Array []Value
	// Map is a map, major type 5, with integer or text keys. Written in
	// deterministic order whatever order it is built in.
	Map []Entry
	// Bool is true or false, major type 7.
	Bool bool
	// Null is null, major type 7 value 22.
	Null struct{}
	// Tagged is a value under a semantic tag, major type 6.
	Tagged struct {
		Tag   uint64
		Value Value
	}
)

// Entry is one key and value of a Map.
type Entry struct {
	Key   Value
	Value Value
}

// MaxDepth bounds nesting. COSE structures are a few levels deep; anything
// much deeper is a way to spend a stack, not a message.
const MaxDepth = 16

// Encode writes a value in deterministic form.
func Encode(v Value) ([]byte, error) {
	if v == nil {
		return nil, errors.New("there is no encoding of nothing")
	}
	e := &encoder{}
	if err := v.encode(e); err != nil {
		return nil, err
	}
	return e.out, nil
}

type encoder struct {
	out   []byte
	depth int
}

// head writes a major type and its argument in the shortest form.
func (e *encoder) head(major byte, arg uint64) {
	m := major << 5
	switch {
	case arg < 24:
		e.out = append(e.out, m|byte(arg))
	case arg <= math.MaxUint8:
		e.out = append(e.out, m|24, byte(arg))
	case arg <= math.MaxUint16:
		e.out = append(e.out, m|25, byte(arg>>8), byte(arg))
	case arg <= math.MaxUint32:
		e.out = append(e.out, m|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		e.out = append(e.out, m|27, byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

func (e *encoder) nested(f func() error) error {
	if e.depth++; e.depth > MaxDepth {
		return fmt.Errorf("this value nests deeper than %d", MaxDepth)
	}
	err := f()
	e.depth--
	return err
}

func (v Uint) encode(e *encoder) error { e.head(0, uint64(v)); return nil }

func (v Int) encode(e *encoder) error {
	if v >= 0 {
		e.head(0, uint64(v))
	} else {
		// Major type 1 carries -1-n, so -1 is argument 0.
		e.head(1, uint64(-1-v))
	}
	return nil
}

func (v Bytes) encode(e *encoder) error {
	e.head(2, uint64(len(v)))
	e.out = append(e.out, v...)
	return nil
}

func (v Text) encode(e *encoder) error {
	if !utf8.ValidString(string(v)) {
		return errors.New("a text string is not valid UTF-8")
	}
	e.head(3, uint64(len(v)))
	e.out = append(e.out, v...)
	return nil
}

func (v Array) encode(e *encoder) error {
	return e.nested(func() error {
		e.head(4, uint64(len(v)))
		for _, item := range v {
			if item == nil {
				return errors.New("an array holds nothing where a value belongs")
			}
			if err := item.encode(e); err != nil {
				return err
			}
		}
		return nil
	})
}

func (v Map) encode(e *encoder) error {
	return e.nested(func() error {
		type pair struct{ key, value []byte }
		pairs := make([]pair, 0, len(v))
		for _, en := range v {
			if !isKey(en.Key) {
				return fmt.Errorf("a map key is %T; keys here are integers or text", en.Key)
			}
			if en.Value == nil {
				return errors.New("a map key holds nothing where a value belongs")
			}
			k := &encoder{depth: e.depth}
			if err := en.Key.encode(k); err != nil {
				return err
			}
			val := &encoder{depth: e.depth}
			if err := en.Value.encode(val); err != nil {
				return err
			}
			pairs = append(pairs, pair{k.out, val.out})
		}
		sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].key, pairs[j].key) < 0 })
		for i := 1; i < len(pairs); i++ {
			if bytes.Equal(pairs[i-1].key, pairs[i].key) {
				return errors.New("a map holds the same key twice")
			}
		}
		e.head(5, uint64(len(pairs)))
		for _, p := range pairs {
			e.out = append(e.out, p.key...)
			e.out = append(e.out, p.value...)
		}
		return nil
	})
}

func (v Bool) encode(e *encoder) error {
	if v {
		e.out = append(e.out, 0xf5)
	} else {
		e.out = append(e.out, 0xf4)
	}
	return nil
}

func (Null) encode(e *encoder) error { e.out = append(e.out, 0xf6); return nil }

func (v Tagged) encode(e *encoder) error {
	if v.Value == nil {
		return errors.New("a tag wraps nothing")
	}
	return e.nested(func() error {
		e.head(6, v.Tag)
		return v.Value.encode(e)
	})
}

func isKey(v Value) bool {
	switch v.(type) {
	case Uint, Int, Text:
		return true
	}
	return false
}

// Get returns the value under a key, comparing keys by their encoding, so
// Int(1) and Uint(1) are the same key as they are on the wire.
func (m Map) Get(key Value) (Value, bool) {
	want, err := Encode(key)
	if err != nil {
		return nil, false
	}
	for _, en := range m {
		if got, err := Encode(en.Key); err == nil && bytes.Equal(got, want) {
			return en.Value, true
		}
	}
	return nil, false
}

// AsInt reads an integer of either major type as an int64, refusing one
// outside its range.
func AsInt(v Value) (int64, bool) {
	switch n := v.(type) {
	case Int:
		return int64(n), true
	case Uint:
		if uint64(n) <= math.MaxInt64 {
			return int64(n), true
		}
	}
	return 0, false
}

// -- reading ------------------------------------------------------------------

// Decode reads exactly one value; bytes after it are an error, because a
// signed structure is one structure and what follows it is something this
// program did not understand.
func Decode(b []byte) (Value, error) {
	d := &decoder{in: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.at != len(b) {
		return nil, fmt.Errorf("%d bytes follow the value", len(b)-d.at)
	}
	return v, nil
}

// Canonical reports whether b is one value in deterministic form: what
// Encode would write for what Decode reads.
func Canonical(b []byte) bool {
	v, err := Decode(b)
	if err != nil {
		return false
	}
	out, err := Encode(v)
	return err == nil && bytes.Equal(out, b)
}

type decoder struct {
	in []byte
	at int
}

// value reads one item; depth is the number of arrays, maps and tags
// around it, counted as the encoder counts them.
func (d *decoder) value(depth int) (Value, error) {
	if d.at >= len(d.in) {
		return nil, errors.New("the value ends before it is complete")
	}
	b := d.in[d.at]
	major, minor := b>>5, b&0x1f
	d.at++
	if major == 7 {
		switch minor {
		case 20:
			return Bool(false), nil
		case 21:
			return Bool(true), nil
		case 22:
			return Null{}, nil
		case 25, 26, 27:
			return nil, errors.New("a float is not read here: nothing signed here is one")
		}
		return nil, fmt.Errorf("simple value %d is not read here", minor)
	}
	arg, err := d.argument(minor)
	if err != nil {
		return nil, err
	}
	remaining := uint64(len(d.in) - d.at)
	if major >= 4 && depth+1 > MaxDepth {
		return nil, fmt.Errorf("this value nests deeper than %d", MaxDepth)
	}
	switch major {
	case 0:
		return Uint(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, errors.New("a negative integer is below the range read here")
		}
		return Int(-1 - int64(arg)), nil
	case 2, 3:
		if arg > remaining {
			return nil, fmt.Errorf("a string claims %d bytes and %d remain", arg, remaining)
		}
		raw := d.in[d.at : d.at+int(arg)]
		d.at += int(arg)
		if major == 2 {
			return Bytes(bytes.Clone(raw)), nil
		}
		if !utf8.Valid(raw) {
			return nil, errors.New("a text string is not valid UTF-8")
		}
		return Text(raw), nil
	case 4:
		// Every item takes at least a byte, so a count beyond the bytes
		// left is a lie, refused before anything is allocated for it.
		if arg > remaining {
			return nil, fmt.Errorf("an array claims %d items and %d bytes remain", arg, remaining)
		}
		out := make(Array, 0, arg)
		for i := uint64(0); i < arg; i++ {
			item, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, nil
	case 5:
		if arg > remaining/2 {
			return nil, fmt.Errorf("a map claims %d entries and %d bytes remain", arg, remaining)
		}
		out := make(Map, 0, arg)
		seen := map[string]bool{}
		for i := uint64(0); i < arg; i++ {
			start := d.at
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if !isKey(k) {
				return nil, fmt.Errorf("a map key is %T; keys here are integers or text", k)
			}
			// Keyed by the key's bytes as written; a key written twice in
			// two lengths is caught by re-encoding it.
			canon, err := Encode(k)
			if err != nil {
				return nil, err
			}
			if seen[string(canon)] {
				return nil, fmt.Errorf("a map holds the key %x twice", d.in[start:d.at])
			}
			seen[string(canon)] = true
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, Entry{Key: k, Value: v})
		}
		return out, nil
	case 6:
		inner, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		return Tagged{Tag: arg, Value: inner}, nil
	}
	return nil, fmt.Errorf("major type %d is not read here", major)
}

func (d *decoder) argument(minor byte) (uint64, error) {
	switch {
	case minor < 24:
		return uint64(minor), nil
	case minor <= 27:
		n := 1 << (minor - 24)
		if n > len(d.in)-d.at {
			return 0, errors.New("an argument runs past the end")
		}
		var out uint64
		for _, c := range d.in[d.at : d.at+n] {
			out = out<<8 | uint64(c)
		}
		d.at += n
		return out, nil
	}
	return 0, fmt.Errorf("argument form %d is not read here: indefinite lengths are refused, "+
		"since a signed structure has a length", minor)
}
