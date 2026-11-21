// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// OTLP/HTTP protobuf: the encoding most SDKs send by default.
//
// The Python, Java and JavaScript exporters send protobuf unless told
// otherwise, and some cannot be told: LiteLLM maps its "http/json" setting
// onto the protobuf exporter. So this reads the protobuf encoding of
// ExportTraceServiceRequest too, into the same structure the JSON mapping
// fills, and everything after that — what is a GenAI span, what is content,
// what is kept — is the one path both take.
//
// Not a protobuf runtime: a reader for the fixed set of messages a traces
// export is (opentelemetry-proto, trace/v1, common/v1, resource/v1), by
// field number, over the protobuf wire format. Strict where the format
// allows nothing else — a varint longer than ten bytes, a length past the
// end of the body, a group, a field number of zero, a trace id of the wrong
// length — and lenient exactly where the format requires it: a field this
// does not read is skipped by its wire type, which is how a newer sender's
// fields reach an older reader without breaking it.

// Wire types.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireStart   = 3 // a group: refused
	wireEnd     = 4 // a group: refused
	wireFixed32 = 5
)

// maxNesting bounds how deep a value may nest. The trace schema nests to a
// fixed depth; an AnyValue may hold arrays of arrays, which this does not
// read, but whose bytes it still skips without recursing.
const maxNesting = 16

var errTruncated = errors.New("the protobuf body ends in the middle of a field")

// MaxMessages bounds the messages one export may hold — resource spans,
// scope spans, spans, events and attributes together. Two bytes make an
// empty message, and a struct costs a hundred, so a body read without a
// bound is one a few megabytes of zeroes turn into gigabytes. A real batch
// is a few hundred spans of a few dozen attributes each.
const MaxMessages = 200_000

// budget counts the messages a decode has made.
type budget struct{ left int }

func (b *budget) take() error {
	if b.left <= 0 {
		return fmt.Errorf("the protobuf body holds more than %d messages, more than any one export does", MaxMessages)
	}
	b.left--
	return nil
}

// pbReader walks one message's bytes.
type pbReader struct {
	b []byte
}

func (r *pbReader) varint() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if len(r.b) == 0 {
			return 0, errTruncated
		}
		c := r.b[0]
		r.b = r.b[1:]
		if i == 9 && c > 1 {
			return 0, errors.New("a varint in the protobuf body overflows 64 bits")
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, nil
		}
	}
	return 0, errors.New("a varint in the protobuf body is longer than ten bytes")
}

// field reads the next field's number and wire type.
func (r *pbReader) field() (int, int, error) {
	k, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	num, wt := k>>3, int(k&7)
	if num == 0 || num > math.MaxInt32>>3 {
		return 0, 0, fmt.Errorf("a protobuf field number of %d is not one", num)
	}
	return int(num), wt, nil
}

func (r *pbReader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.b)) {
		return nil, errTruncated
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, nil
}

func (r *pbReader) fixed64() (uint64, error) {
	if len(r.b) < 8 {
		return 0, errTruncated
	}
	v := binary.LittleEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v, nil
}

// skip passes over a field this does not read.
func (r *pbReader) skip(wt int) error {
	switch wt {
	case wireVarint:
		_, err := r.varint()
		return err
	case wireFixed64:
		_, err := r.fixed64()
		return err
	case wireBytes:
		_, err := r.bytes()
		return err
	case wireFixed32:
		if len(r.b) < 4 {
			return errTruncated
		}
		r.b = r.b[4:]
		return nil
	case wireStart, wireEnd:
		return errors.New("the protobuf body holds a group, which no OTLP message has")
	}
	return fmt.Errorf("the protobuf body holds wire type %d, which is not one", wt)
}

// each calls fn for every field of a message, and fails on the first error.
func each(b []byte, fn func(num, wt int, r *pbReader) error) error {
	r := &pbReader{b: b}
	for len(r.b) > 0 {
		num, wt, err := r.field()
		if err != nil {
			return err
		}
		if err := fn(num, wt, r); err != nil {
			return err
		}
	}
	return nil
}

// sub reads a length-delimited field and hands its bytes to parse.
func sub(wt int, r *pbReader, parse func([]byte) error) error {
	if wt != wireBytes {
		return errors.New("a protobuf message field is not length-delimited")
	}
	b, err := r.bytes()
	if err != nil {
		return err
	}
	return parse(b)
}

func str(wt int, r *pbReader) (string, error) {
	if wt != wireBytes {
		return "", errors.New("a protobuf string field is not length-delimited")
	}
	b, err := r.bytes()
	return string(b), err
}

func nanos(wt int, r *pbReader) (json.Number, error) {
	if wt != wireFixed64 {
		return "", errors.New("a protobuf time field is not fixed64")
	}
	v, err := r.fixed64()
	return json.Number(strconv.FormatUint(v, 10)), err
}

// id reads a trace or span id as the hex the JSON mapping carries, and
// refuses one of the wrong length: an id that is not 16 or 8 bytes names
// nothing, and a join on it would join on nothing.
func id(wt int, r *pbReader, size int) (string, error) {
	if wt != wireBytes {
		return "", errors.New("a protobuf id field is not length-delimited")
	}
	b, err := r.bytes()
	if err != nil {
		return "", err
	}
	if len(b) != 0 && len(b) != size {
		return "", fmt.Errorf("an id of %d bytes where the protocol has %d", len(b), size)
	}
	return hex.EncodeToString(b), nil
}

// decodeProtobuf reads an ExportTraceServiceRequest.
func decodeProtobuf(body []byte) (exportRequest, error) {
	var req exportRequest
	d := &budget{left: MaxMessages}
	err := each(body, func(num, wt int, r *pbReader) error {
		if num != 1 {
			return r.skip(wt)
		}
		return sub(wt, r, func(b []byte) error {
			rs, err := d.pbResourceSpans(b)
			req.ResourceSpans = append(req.ResourceSpans, rs)
			return err
		})
	})
	return req, err
}

func (d *budget) pbResourceSpans(b []byte) (resourceSpans, error) {
	if err := d.take(); err != nil {
		return resourceSpans{}, err
	}
	var rs resourceSpans
	err := each(b, func(num, wt int, r *pbReader) error {
		switch num {
		case 1:
			return sub(wt, r, func(b []byte) error {
				res := &resource{}
				rs.Resource = res
				return each(b, func(num, wt int, r *pbReader) error {
					if num != 1 {
						return r.skip(wt)
					}
					return sub(wt, r, func(b []byte) error {
						a, err := d.pbKeyValue(b)
						res.Attributes = append(res.Attributes, a)
						return err
					})
				})
			})
		case 2, 1000:
			// 1000 is instrumentation_library_spans, the name before 1.0.
			return sub(wt, r, func(b []byte) error {
				ss, err := d.pbScopeSpans(b)
				if num == 2 {
					rs.ScopeSpans = append(rs.ScopeSpans, ss)
				} else {
					rs.LegacySpans = append(rs.LegacySpans, ss)
				}
				return err
			})
		}
		return r.skip(wt)
	})
	return rs, err
}

func (d *budget) pbScopeSpans(b []byte) (scopeSpans, error) {
	if err := d.take(); err != nil {
		return scopeSpans{}, err
	}
	var ss scopeSpans
	err := each(b, func(num, wt int, r *pbReader) error {
		if num != 2 {
			return r.skip(wt)
		}
		return sub(wt, r, func(b []byte) error {
			sp, err := d.pbSpan(b)
			ss.Spans = append(ss.Spans, sp)
			return err
		})
	})
	return ss, err
}

func (d *budget) pbSpan(b []byte) (span, error) {
	if err := d.take(); err != nil {
		return span{}, err
	}
	var sp span
	err := each(b, func(num, wt int, r *pbReader) error {
		var err error
		switch num {
		case 1:
			sp.TraceID, err = id(wt, r, 16)
		case 2:
			sp.SpanID, err = id(wt, r, 8)
		case 3:
			sp.TraceState, err = str(wt, r)
		case 5:
			sp.Name, err = str(wt, r)
		case 7:
			sp.StartTimeUnixNano, err = nanos(wt, r)
		case 8:
			sp.EndTimeUnixNano, err = nanos(wt, r)
		case 9:
			err = sub(wt, r, func(b []byte) error {
				a, err := d.pbKeyValue(b)
				sp.Attributes = append(sp.Attributes, a)
				return err
			})
		case 11:
			err = sub(wt, r, func(b []byte) error {
				ev, err := d.pbEvent(b)
				sp.Events = append(sp.Events, ev)
				return err
			})
		case 15:
			err = sub(wt, r, func(b []byte) error {
				st, err := d.pbStatus(b)
				sp.Status = st
				return err
			})
		default:
			err = r.skip(wt)
		}
		return err
	})
	return sp, err
}

func (d *budget) pbEvent(b []byte) (spanEvent, error) {
	if err := d.take(); err != nil {
		return spanEvent{}, err
	}
	var ev spanEvent
	err := each(b, func(num, wt int, r *pbReader) error {
		switch num {
		case 2:
			var err error
			ev.Name, err = str(wt, r)
			return err
		case 3:
			return sub(wt, r, func(b []byte) error {
				a, err := d.pbKeyValue(b)
				ev.Attributes = append(ev.Attributes, a)
				return err
			})
		}
		return r.skip(wt)
	})
	return ev, err
}

// pbStatus reads a Status. Its code is the enum's number, which the JSON
// mapping's reader takes as written.
func (d *budget) pbStatus(b []byte) (*spanStatus, error) {
	if err := d.take(); err != nil {
		return nil, err
	}
	st := &spanStatus{Code: json.RawMessage("0")}
	err := each(b, func(num, wt int, r *pbReader) error {
		switch num {
		case 2:
			var err error
			st.Message, err = str(wt, r)
			return err
		case 3:
			if wt != wireVarint {
				return errors.New("a status code is not a varint")
			}
			c, err := r.varint()
			if err != nil {
				return err
			}
			if c > 2 {
				return fmt.Errorf("a span status code of %d is not one the protocol has", c)
			}
			st.Code = json.RawMessage(strconv.FormatUint(c, 10))
			return nil
		}
		return r.skip(wt)
	})
	return st, err
}

func (d *budget) pbKeyValue(b []byte) (attribute, error) {
	if err := d.take(); err != nil {
		return attribute{}, err
	}
	var a attribute
	err := each(b, func(num, wt int, r *pbReader) error {
		switch num {
		case 1:
			var err error
			a.Key, err = str(wt, r)
			return err
		case 2:
			return sub(wt, r, func(b []byte) error {
				v, err := d.pbAnyValue(b)
				a.Value = v
				return err
			})
		}
		return r.skip(wt)
	})
	return a, err
}

// pbAnyValue reads the scalar kinds the JSON mapping models. An array, a
// key-value list or bytes is skipped, as the JSON mapping leaves them: the
// only GenAI attributes that carry them are message content, which is never
// read here.
func (d *budget) pbAnyValue(b []byte) (*attrValue, error) {
	if err := d.take(); err != nil {
		return nil, err
	}
	v := &attrValue{}
	err := each(b, func(num, wt int, r *pbReader) error {
		switch num {
		case 1:
			s, err := str(wt, r)
			v.StringValue = &s
			return err
		case 2:
			if wt != wireVarint {
				return errors.New("a bool value is not a varint")
			}
			n, err := r.varint()
			t := n != 0
			v.BoolValue = &t
			return err
		case 3:
			if wt != wireVarint {
				return errors.New("an int value is not a varint")
			}
			n, err := r.varint()
			v.IntValue = json.Number(strconv.FormatInt(int64(n), 10))
			return err
		case 4:
			if wt != wireFixed64 {
				return errors.New("a double value is not fixed64")
			}
			n, err := r.fixed64()
			f := math.Float64frombits(n)
			if math.IsNaN(f) || math.IsInf(f, 0) {
				// JSON has no NaN or infinity, and json.Number would carry
				// one into a comparison as text nothing else writes.
				return nil
			}
			v.DoubleValue = json.Number(strconv.FormatFloat(f, 'g', -1, 64))
			return err
		}
		return r.skip(wt)
	})
	return v, err
}

// -- answering in protobuf --------------------------------------------------

// The answers, in the encoding the request came in, as the specification
// requires: an ExportTraceServiceResponse, whose partial_success (field 1)
// holds rejected_spans (1, int64) and error_message (2, string), and a
// google.rpc.Status for a failure, code (1, int32) and message (2, string).

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendTag(b []byte, num, wt int) []byte { return appendVarint(b, uint64(num)<<3|uint64(wt)) }

func appendString(b []byte, num int, s string) []byte {
	if s == "" {
		return b
	}
	b = appendTag(b, num, wireBytes)
	b = appendVarint(b, uint64(len(s)))
	return append(b, s...)
}

// protobufResponse is an ExportTraceServiceResponse.
func protobufResponse(rejected int64, message string) []byte {
	if rejected == 0 && message == "" {
		return []byte{}
	}
	var partial []byte
	if rejected != 0 {
		partial = appendTag(partial, 1, wireVarint)
		partial = appendVarint(partial, uint64(rejected))
	}
	partial = appendString(partial, 2, message)
	out := appendTag(nil, 1, wireBytes)
	out = appendVarint(out, uint64(len(partial)))
	return append(out, partial...)
}

// protobufStatus is a google.rpc.Status.
func protobufStatus(code int, message string) []byte {
	var out []byte
	if code != 0 {
		out = appendTag(out, 1, wireVarint)
		out = appendVarint(out, uint64(int64(code)))
	}
	return appendString(out, 2, message)
}
