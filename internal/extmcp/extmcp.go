// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package extmcp is agentgateway's ExtMCP protocol as Aertun answers it:
// the external policy server agentgateway's mcpGuardrails calls for an MCP
// method, modelled on Envoy's ext_authz but at the JSON-RPC layer. These
// are the messages of ext_mcp.proto (package agentgateway.dev.ext_mcp, as
// at agentgateway v1.7.0), encoded and decoded here by hand, and gRPC's
// unary calls over cleartext HTTP/2, with the standard library alone.
//
// Only what the protocol carries is read. A field this version does not
// know is skipped, as protobuf requires, so a newer gateway's addition is
// not a failure; a malformed message, a group, a nesting past MaxDepth or
// a message past MaxMessage is.
package extmcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
)

const (
	// Service is the gRPC service the paths are under.
	Service = "agentgateway.dev.ext_mcp.ExtMcp"
	// MaxMessage bounds a request-phase message, gRPC's own default
	// receive limit, and MaxResponse a response-phase one, which carries a
	// tool's whole result. A response past it is passed unread: refusing it
	// would hide the result of a call that has already run.
	MaxMessage  = 4 << 20
	MaxResponse = 64 << 20
	// MaxDepth bounds how deeply a Struct may nest.
	MaxDepth = 32
)

// Request is McpRequest: a call agentgateway is about to forward.
type Request struct {
	// ServiceNames are the backends the call targets: one for tools/call.
	ServiceNames []string
	// Method is the JSON-RPC method, such as tools/call.
	Method string
	// Metadata is the context gateway configuration evaluates in CEL.
	Metadata map[string]any
	// Params are the JSON-RPC params as raw JSON, nil when absent.
	Params []byte
	// Headers are the incoming HTTP headers agentgateway allowed through.
	Headers []Header
}

// Response is McpResponse: what the upstream answered. Upstream errors
// skip this call.
type Response struct {
	ServiceNames []string
	Method       string
	Metadata     map[string]any
	// Result is the JSON-RPC result as raw JSON.
	Result []byte
}

// Header is McpHeader: one value of one header.
type Header struct {
	Key   string
	Value []byte
}

// Code is AuthorizationError.Code.
type Code int32

const (
	Unknown          Code = 0
	PermissionDenied Code = 1
	ResourceExhaust  Code = 2
	Invalid          Code = 3
)

// Denial is AuthorizationError: a call refused, with its reason. On
// tools/call agentgateway answers it as a tool result with isError set.
type Denial struct {
	Code   Code
	Reason string
}

// RequestResult is McpRequestResult, limited to what Aertun answers: pass,
// with metadata the gateway keeps for the call (agentgateway v1.7.0
// exposes it to CEL as mcpGuardrails.<key>, so a processor's metadata
// expressions can hand it back on the response), or a denial.
type RequestResult struct {
	Deny     *Denial
	Metadata map[string]string
}

// ResponseResult is McpResponseResult: pass or a denial.
type ResponseResult struct {
	Deny *Denial
}

// Wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
)

var errTruncated = errors.New("the message ends inside a field")

// reader walks one message's fields.
type reader struct {
	b []byte
}

func (r *reader) varint() (uint64, error) {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		return 0, errors.New("a varint is malformed or truncated")
	}
	r.b = r.b[n:]
	return v, nil
}

// next reads a field's number and wire type; done at the end.
func (r *reader) next() (field int, wire int, done bool, err error) {
	if len(r.b) == 0 {
		return 0, 0, true, nil
	}
	tag, err := r.varint()
	if err != nil {
		return 0, 0, false, err
	}
	field, wire = int(tag>>3), int(tag&7)
	if field < 1 || tag>>3 > math.MaxInt32 {
		return 0, 0, false, fmt.Errorf("field number %d is not one protobuf allows", tag>>3)
	}
	return field, wire, false, nil
}

func (r *reader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.b)) {
		return nil, errTruncated
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v, nil
}

func (r *reader) fixed64() (uint64, error) {
	if len(r.b) < 8 {
		return 0, errTruncated
	}
	v := binary.LittleEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v, nil
}

// skip passes over a field this version does not read.
func (r *reader) skip(wire int) error {
	switch wire {
	case wireVarint:
		_, err := r.varint()
		return err
	case wireI64:
		_, err := r.fixed64()
		return err
	case wireLen:
		_, err := r.bytes()
		return err
	case wireI32:
		if len(r.b) < 4 {
			return errTruncated
		}
		r.b = r.b[4:]
		return nil
	}
	return fmt.Errorf("wire type %d (a group, or nothing) is not read", wire)
}

// want reads a length-delimited field, refusing any other wire type.
func (r *reader) want(field, wire int) ([]byte, error) {
	if wire != wireLen {
		return nil, fmt.Errorf("field %d has wire type %d, not a length-delimited value", field, wire)
	}
	return r.bytes()
}

// DecodeRequest reads McpRequest.
func DecodeRequest(b []byte) (*Request, error) {
	if len(b) > MaxMessage {
		return nil, fmt.Errorf("the message is over %d bytes", MaxMessage)
	}
	req := &Request{}
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return req, err
		}
		switch field {
		case 1, 2, 3, 4, 5:
			v, err := r.want(field, wire)
			if err != nil {
				return nil, err
			}
			switch field {
			case 1:
				req.ServiceNames = append(req.ServiceNames, string(v))
			case 2:
				req.Method = string(v)
			case 3:
				if req.Metadata, err = decodeStruct(v, 0); err != nil {
					return nil, fmt.Errorf("metadata_context: %w", err)
				}
			case 4:
				req.Params = append([]byte{}, v...)
			case 5:
				h, err := decodeHeader(v)
				if err != nil {
					return nil, err
				}
				req.Headers = append(req.Headers, h)
			}
		default:
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
}

// DecodeResponse reads McpResponse.
func DecodeResponse(b []byte) (*Response, error) {
	if len(b) > MaxResponse {
		return nil, fmt.Errorf("the message is over %d bytes", MaxResponse)
	}
	resp := &Response{}
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return resp, err
		}
		switch field {
		case 1, 2, 3, 4:
			v, err := r.want(field, wire)
			if err != nil {
				return nil, err
			}
			switch field {
			case 1:
				resp.ServiceNames = append(resp.ServiceNames, string(v))
			case 2:
				resp.Method = string(v)
			case 3:
				if resp.Metadata, err = decodeStruct(v, 0); err != nil {
					return nil, fmt.Errorf("metadata_context: %w", err)
				}
			case 4:
				resp.Result = append([]byte{}, v...)
			}
		default:
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
}

func decodeHeader(b []byte) (Header, error) {
	var h Header
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return h, err
		}
		switch field {
		case 1, 2:
			v, err := r.want(field, wire)
			if err != nil {
				return h, err
			}
			if field == 1 {
				h.Key = string(v)
			} else {
				h.Value = append([]byte{}, v...)
			}
		default:
			if err := r.skip(wire); err != nil {
				return h, err
			}
		}
	}
}

// decodeStruct reads google.protobuf.Struct into JSON's values: nil,
// float64, string, bool, map[string]any and []any.
func decodeStruct(b []byte, depth int) (map[string]any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("a Struct nests deeper than %d", MaxDepth)
	}
	out := map[string]any{}
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return out, err
		}
		if field != 1 {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		entry, err := r.want(field, wire)
		if err != nil {
			return nil, err
		}
		key, val, err := decodeEntry(entry, depth)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
}

// decodeEntry reads one map<string, Value> entry.
func decodeEntry(b []byte, depth int) (string, any, error) {
	var key string
	var val any
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return key, val, err
		}
		switch field {
		case 1:
			v, err := r.want(field, wire)
			if err != nil {
				return "", nil, err
			}
			key = string(v)
		case 2:
			v, err := r.want(field, wire)
			if err != nil {
				return "", nil, err
			}
			if val, err = decodeValue(v, depth+1); err != nil {
				return "", nil, err
			}
		default:
			if err := r.skip(wire); err != nil {
				return "", nil, err
			}
		}
	}
}

// decodeValue reads google.protobuf.Value.
func decodeValue(b []byte, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("a Value nests deeper than %d", MaxDepth)
	}
	var val any
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return val, err
		}
		switch {
		case field == 1 && wire == wireVarint: // null_value
			if _, err := r.varint(); err != nil {
				return nil, err
			}
			val = nil
		case field == 2 && wire == wireI64: // number_value
			bits, err := r.fixed64()
			if err != nil {
				return nil, err
			}
			val = math.Float64frombits(bits)
		case field == 3 && wire == wireLen: // string_value
			v, err := r.bytes()
			if err != nil {
				return nil, err
			}
			val = string(v)
		case field == 4 && wire == wireVarint: // bool_value
			v, err := r.varint()
			if err != nil {
				return nil, err
			}
			val = v != 0
		case field == 5 && wire == wireLen: // struct_value
			v, err := r.bytes()
			if err != nil {
				return nil, err
			}
			if val, err = decodeStruct(v, depth+1); err != nil {
				return nil, err
			}
		case field == 6 && wire == wireLen: // list_value
			v, err := r.bytes()
			if err != nil {
				return nil, err
			}
			if val, err = decodeList(v, depth+1); err != nil {
				return nil, err
			}
		case field >= 1 && field <= 6:
			return nil, fmt.Errorf("Value field %d has wire type %d", field, wire)
		default:
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
}

func decodeList(b []byte, depth int) ([]any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("a list nests deeper than %d", MaxDepth)
	}
	out := []any{}
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return out, err
		}
		if field != 1 {
			if err := r.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		v, err := r.want(field, wire)
		if err != nil {
			return nil, err
		}
		item, err := decodeValue(v, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
}

// writer builds one message.
type writer struct {
	b []byte
}

func (w *writer) tag(field, wire int) { w.b = binary.AppendUvarint(w.b, uint64(field)<<3|uint64(wire)) }

func (w *writer) bytes(field int, v []byte) {
	w.tag(field, wireLen)
	w.b = binary.AppendUvarint(w.b, uint64(len(v)))
	w.b = append(w.b, v...)
}

func (w *writer) varint(field int, v uint64) {
	w.tag(field, wireVarint)
	w.b = binary.AppendUvarint(w.b, v)
}

func denial(d *Denial) []byte {
	var w writer
	if d.Code != Unknown {
		w.varint(1, uint64(d.Code))
	}
	if d.Reason != "" {
		w.bytes(2, []byte(d.Reason))
	}
	return w.b
}

// Encode writes McpRequestResult.
func (rr *RequestResult) Encode() []byte {
	var w writer
	if rr.Deny != nil {
		w.bytes(3, denial(rr.Deny))
		return w.b
	}
	w.bytes(1, nil) // pass: the empty message, present
	if len(rr.Metadata) > 0 {
		meta := make(map[string]any, len(rr.Metadata))
		for k, v := range rr.Metadata {
			meta[k] = v
		}
		s, _ := structOf(meta, 0) // strings only: nothing to refuse
		w.bytes(5, s)
	}
	return w.b
}

// Encode writes McpResponseResult.
func (rr *ResponseResult) Encode() []byte {
	var w writer
	if rr.Deny != nil {
		w.bytes(3, denial(rr.Deny))
		return w.b
	}
	w.bytes(1, nil)
	return w.b
}

// The other direction of each message: what agentgateway sends, written,
// and what Aertun answers, read. Tests speak to the server through them as
// agentgateway would, and so does Client.

// valueOf encodes one JSON value as google.protobuf.Value.
func valueOf(v any, depth int) ([]byte, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("a value nests deeper than %d", MaxDepth)
	}
	var w writer
	switch v := v.(type) {
	case nil:
		w.varint(1, 0)
	case float64:
		w.tag(2, wireI64)
		w.b = binary.LittleEndian.AppendUint64(w.b, math.Float64bits(v))
	case string:
		w.bytes(3, []byte(v))
	case bool:
		b := uint64(0)
		if v {
			b = 1
		}
		w.varint(4, b)
	case map[string]any:
		s, err := structOf(v, depth+1)
		if err != nil {
			return nil, err
		}
		w.bytes(5, s)
	case []any:
		var list writer
		for _, item := range v {
			b, err := valueOf(item, depth+1)
			if err != nil {
				return nil, err
			}
			list.bytes(1, b)
		}
		w.bytes(6, list.b)
	default:
		return nil, fmt.Errorf("a %T is not a JSON value", v)
	}
	return w.b, nil
}

// structOf encodes google.protobuf.Struct, keys in order.
func structOf(m map[string]any, depth int) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var s writer
	for _, k := range keys {
		val, err := valueOf(m[k], depth+1)
		if err != nil {
			return nil, err
		}
		var entry writer
		entry.bytes(1, []byte(k))
		entry.bytes(2, val)
		s.bytes(1, entry.b)
	}
	return s.b, nil
}

// Encode writes McpRequest.
func (req *Request) Encode() ([]byte, error) {
	var w writer
	for _, n := range req.ServiceNames {
		w.bytes(1, []byte(n))
	}
	if req.Method != "" {
		w.bytes(2, []byte(req.Method))
	}
	if req.Metadata != nil {
		s, err := structOf(req.Metadata, 0)
		if err != nil {
			return nil, err
		}
		w.bytes(3, s)
	}
	if req.Params != nil {
		w.bytes(4, req.Params)
	}
	for _, h := range req.Headers {
		var hw writer
		hw.bytes(1, []byte(h.Key))
		hw.bytes(2, h.Value)
		w.bytes(5, hw.b)
	}
	return w.b, nil
}

// Encode writes McpResponse.
func (resp *Response) Encode() ([]byte, error) {
	var w writer
	for _, n := range resp.ServiceNames {
		w.bytes(1, []byte(n))
	}
	if resp.Method != "" {
		w.bytes(2, []byte(resp.Method))
	}
	if resp.Metadata != nil {
		s, err := structOf(resp.Metadata, 0)
		if err != nil {
			return nil, err
		}
		w.bytes(3, s)
	}
	w.bytes(4, resp.Result)
	return w.b, nil
}

// decodeDenial reads AuthorizationError.
func decodeDenial(b []byte) (*Denial, error) {
	d := &Denial{}
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil || done {
			return d, err
		}
		switch {
		case field == 1 && wire == wireVarint:
			v, err := r.varint()
			if err != nil {
				return nil, err
			}
			d.Code = Code(int32(v))
		case field == 2 && wire == wireLen:
			v, err := r.bytes()
			if err != nil {
				return nil, err
			}
			d.Reason = string(v)
		default:
			if err := r.skip(wire); err != nil {
				return nil, err
			}
		}
	}
}

// result reads the oneof both result messages share: pass (1), mutated
// (2) or an error (3), and, for a request's result, metadata (5).
func result(b []byte) (deny *Denial, mutated bool, meta map[string]any, err error) {
	set := false
	r := &reader{b: b}
	for {
		field, wire, done, err := r.next()
		if err != nil {
			return nil, false, nil, err
		}
		if done {
			if !set {
				return nil, false, nil, errors.New("the result is neither pass, mutated nor an error")
			}
			return deny, mutated, meta, nil
		}
		switch field {
		case 1, 2, 3:
			v, err := r.want(field, wire)
			if err != nil {
				return nil, false, nil, err
			}
			set, mutated, deny = true, field == 2, nil
			if field == 3 {
				if deny, err = decodeDenial(v); err != nil {
					return nil, false, nil, err
				}
			}
		case 5:
			v, err := r.want(field, wire)
			if err != nil {
				return nil, false, nil, err
			}
			if meta, err = decodeStruct(v, 0); err != nil {
				return nil, false, nil, err
			}
		default:
			if err := r.skip(wire); err != nil {
				return nil, false, nil, err
			}
		}
	}
}

// DecodeRequestResult reads McpRequestResult. A mutation is refused:
// Aertun never rewrites a call, and a result that does is not its answer.
func DecodeRequestResult(b []byte) (*RequestResult, error) {
	deny, mutated, meta, err := result(b)
	if err != nil {
		return nil, err
	}
	if mutated {
		return nil, errors.New("the result mutates the call")
	}
	rr := &RequestResult{Deny: deny}
	for k, v := range meta {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("metadata %q is not a string", k)
		}
		if rr.Metadata == nil {
			rr.Metadata = map[string]string{}
		}
		rr.Metadata[k] = s
	}
	return rr, nil
}

// DecodeResponseResult reads McpResponseResult.
func DecodeResponseResult(b []byte) (*ResponseResult, error) {
	deny, mutated, _, err := result(b)
	if err != nil {
		return nil, err
	}
	if mutated {
		return nil, errors.New("the result mutates the response")
	}
	return &ResponseResult{Deny: deny}, nil
}
