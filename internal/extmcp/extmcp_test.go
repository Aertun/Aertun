// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package extmcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Bytes worked out by hand from the protobuf encoding rules, so that the
// encoder and the decoder are each held to the specification and not
// only to each other.
func TestTheWireIsTheSpecifications(t *testing.T) {
	// service_names "fs" (field 1), method "tools/call" (2), metadata
	// {"a": "b"} (3), params {} (4), header x: y (5).
	want := unhex(t, "0a 02 6673"+
		" 12 0a 746f6f6c732f63616c6c"+
		" 1a 0a 0a08 0a0161 1203 1a0162"+
		" 22 02 7b7d"+
		" 2a 06 0a0178 120179")
	req := &Request{ServiceNames: []string{"fs"}, Method: "tools/call",
		Metadata: map[string]any{"a": "b"}, Params: []byte("{}"),
		Headers: []Header{{Key: "x", Value: []byte("y")}}}
	got, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encoded %x\n   want %x", got, want)
	}
	back, err := DecodeRequest(want)
	if err != nil || !reflect.DeepEqual(back, req) {
		t.Errorf("decoded %+v %v", back, err)
	}

	// A denial: field 3 holding code 1 and reason "no".
	deny := (&RequestResult{Deny: &Denial{Code: PermissionDenied, Reason: "no"}}).Encode()
	if !bytes.Equal(deny, unhex(t, "1a 06 0801 12026e6f")) {
		t.Errorf("a denial encoded as %x", deny)
	}
	// A pass (field 1, empty) with metadata {"k": "v"} (field 5).
	pass := (&RequestResult{Metadata: map[string]string{"k": "v"}}).Encode()
	if !bytes.Equal(pass, unhex(t, "0a00 2a 0a 0a08 0a016b 1203 1a0176")) {
		t.Errorf("a pass encoded as %x", pass)
	}
	// A number, 2.5, is a fixed64 in field 2 of Value.
	v, err := valueOf(2.5, 0)
	if err != nil || !bytes.Equal(v, unhex(t, "11 0000000000000440")) {
		t.Errorf("2.5 encoded as %x %v", v, err)
	}
	if (&ResponseResult{}).Encode()[0] != 0x0a {
		t.Error("a response's pass is not field 1")
	}
}

// Every kind of value survives the trip, and a field this version does not
// know is passed over.
func TestValuesRoundTripAndUnknownFieldsArePassedOver(t *testing.T) {
	meta := map[string]any{"s": "x", "n": -1.5, "t": true, "f": false, "z": nil,
		"m": map[string]any{"deep": []any{"a", 2.0, map[string]any{}}}, "l": []any{}}
	resp := &Response{ServiceNames: []string{"a", "b"}, Method: "tools/list", Metadata: meta,
		Result: []byte(`{"tools":[]}`)}
	b, err := resp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// A newer gateway's fields: a varint as field 9, bytes as field 10, a
	// fixed32 as field 11 and a fixed64 as field 12.
	b = append(b, unhex(t, "4801 5203616263 5d01020304 610102030405060708")...)
	back, err := DecodeResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, resp) {
		t.Errorf("decoded %+v\n   want %+v", back, resp)
	}
}

// What is not a message is refused, never read past its end, and never
// nested past MaxDepth.
func TestMalformedMessagesAreRefused(t *testing.T) {
	deep := []byte{}
	for range MaxDepth + 2 {
		// Each level: a Struct entry whose value is a struct_value.
		entry := append([]byte{0x0a, 0x01, 'k', 0x12, byte(len(deep) + 2), 0x2a, byte(len(deep))}, deep...)
		deep = append([]byte{0x0a, byte(len(entry))}, entry...)
		if len(deep) > 120 {
			break
		}
	}
	for name, b := range map[string][]byte{
		"a group":                         unhex(t, "33"),
		"a length past the end":           unhex(t, "1205746f"),
		"a varint that never ends":        unhex(t, "08ffffffffffffffffffff"),
		"field number zero":               unhex(t, "0001"),
		"method as a varint":              unhex(t, "1001"),
		"a string Value sent as a varint": unhex(t, "1a 09 0a07 0a0161 12021801"),
	} {
		if _, err := DecodeRequest(b); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	if _, err := decodeStruct(deep, MaxDepth-1); err == nil {
		t.Error("a Struct nested past MaxDepth was read")
	}
	// Each reader holds the line itself, not only the one that calls it.
	if _, err := decodeStruct(nil, MaxDepth+1); err == nil {
		t.Error("decodeStruct read past MaxDepth")
	}
	if _, err := decodeList(nil, MaxDepth+1); err == nil {
		t.Error("decodeList read past MaxDepth")
	}
	if _, err := decodeValue(nil, MaxDepth+1); err == nil {
		t.Error("decodeValue read past MaxDepth")
	}
	if _, err := DecodeRequest(make([]byte, MaxMessage+1)); err == nil {
		t.Error("a message over MaxMessage was read")
	}
	if _, err := DecodeRequestResult(unhex(t, "1200")); err == nil {
		t.Error("a mutation was taken as an answer")
	}
	if _, err := DecodeRequestResult(nil); err == nil {
		t.Error("an empty result was taken as an answer")
	}
}

type policy struct {
	deny bool
	fail bool
	seen []string
}

func (p *policy) CheckRequest(_ context.Context, r *Request) (*RequestResult, error) {
	if p.fail {
		return nil, errors.New("the policy broke")
	}
	p.seen = append(p.seen, "req:"+r.Method+":"+string(r.Params))
	if p.deny {
		return &RequestResult{Deny: &Denial{Code: PermissionDenied, Reason: "the agent is disabled"}}, nil
	}
	return &RequestResult{Metadata: map[string]string{"aertun_call": "c1"}}, nil
}

func (p *policy) CheckResponse(_ context.Context, r *Response) (*ResponseResult, error) {
	p.seen = append(p.seen, "resp:"+r.Metadata["aertun_call"].(string)+":"+string(r.Result))
	return &ResponseResult{}, nil
}

func h2cServer(t *testing.T, p Policy) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(Handler(p))
	srv.Config.Protocols = Server("", p).Protocols
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// Over cleartext HTTP/2, as agentgateway calls it: both phases answered,
// a denial carried, a broken policy reported as a gRPC error, and what is
// not a gRPC call refused.
func TestTheServiceAnswersAsAgentgatewayCallsIt(t *testing.T) {
	p := &policy{}
	srv := h2cServer(t, p)
	c := NewClient(srv.Listener.Addr().String(), H2CClient())
	ctx := context.Background()
	res, err := c.CheckRequest(ctx, &Request{ServiceNames: []string{"fs"}, Method: "tools/call",
		Params: []byte(`{"name":"read","arguments":{}}`)})
	if err != nil || res.Deny != nil || res.Metadata["aertun_call"] != "c1" {
		t.Fatalf("request phase: %+v %v", res, err)
	}
	if _, err := c.CheckResponse(ctx, &Response{ServiceNames: []string{"fs"}, Method: "tools/call",
		Metadata: map[string]any{"aertun_call": "c1"}, Result: []byte(`{"content":[]}`)}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.seen, "|") != `req:tools/call:{"name":"read","arguments":{}}|resp:c1:{"content":[]}` {
		t.Errorf("the policy saw %v", p.seen)
	}
	p.deny = true
	if res, err := c.CheckRequest(ctx, &Request{Method: "tools/call"}); err != nil || res.Deny == nil ||
		res.Deny.Code != PermissionDenied || res.Deny.Reason != "the agent is disabled" {
		t.Errorf("a denial came back as %+v %v", res, err)
	}
	p.fail = true
	if _, err := c.CheckRequest(ctx, &Request{Method: "tools/call"}); err == nil ||
		!strings.Contains(err.Error(), "status 13") || !strings.Contains(err.Error(), "the policy broke") {
		t.Errorf("a broken policy: %v", err)
	}

	raw := func(path string, body []byte, header map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, c.Base+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/grpc")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body) // the trailers come after the body
		resp.Body.Close()
		return resp
	}
	statusOf := func(resp *http.Response) string {
		if s := resp.Header.Get("Grpc-Status"); s != "" {
			return s
		}
		return resp.Trailer.Get("Grpc-Status")
	}
	big := func(n uint32) []byte {
		b := []byte{0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], n)
		return b
	}
	msg, _ := (&Request{Method: "tools/call"}).Encode()
	for name, c := range map[string]struct {
		path   string
		body   []byte
		header map[string]string
		code   string
	}{
		"an unknown method":   {"/" + Service + "/Check", frame(msg), nil, "12"},
		"another service":     {"/grpc.health.v1.Health/Check", frame(msg), nil, "12"},
		"compression":         {"/" + Service + "/CheckRequest", frame(msg), map[string]string{"Grpc-Encoding": "gzip"}, "12"},
		"a compressed frame":  {"/" + Service + "/CheckRequest", append([]byte{1}, frame(msg)[1:]...), nil, "3"},
		"two messages":        {"/" + Service + "/CheckRequest", append(frame(msg), frame(msg)...), nil, "3"},
		"a short frame":       {"/" + Service + "/CheckRequest", []byte{0, 0, 0}, nil, "3"},
		"a length that lies":  {"/" + Service + "/CheckRequest", append([]byte{0, 0, 0, 0, 9}, msg...), nil, "3"},
		"not an McpRequest":   {"/" + Service + "/CheckRequest", frame([]byte{0x33}), nil, "3"},
		"an oversized length": {"/" + Service + "/CheckRequest", []byte{0, 0xff, 0xff, 0xff, 0xff}, nil, "3"},
		// A call too large to witness is refused; the result of one that
		// ran, too large to read, is passed unread rather than hidden.
		"a request over MaxMessage":   {"/" + Service + "/CheckRequest", big(MaxMessage + 1), nil, "3"},
		"a response over MaxResponse": {"/" + Service + "/CheckResponse", big(MaxResponse + 1), nil, "0"},
	} {
		if got := statusOf(raw(c.path, c.body, c.header)); got != c.code {
			t.Errorf("%s: grpc-status %q, want %s", name, got, c.code)
		}
	}
	// HTTP/1.1 is not gRPC: the server speaks cleartext HTTP/2 alone, and
	// a connection that opens with anything else is closed.
	if resp, err := http.Post(c.Base+"/"+Service+"/CheckRequest", "application/grpc",
		bytes.NewReader(frame(msg))); err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("an HTTP/1.1 call was answered as gRPC")
		}
	}
	if got := percentEncode("100% ok\n"); got != "100%25 ok%0A" {
		t.Errorf("percent-encoded as %q", got)
	}
}

// No input makes a decoder panic, and what one decodes encodes back to
// what it decodes again.
func FuzzDecode(f *testing.F) {
	seed, _ := (&Request{ServiceNames: []string{"fs"}, Method: "tools/call",
		Metadata: map[string]any{"a": []any{1.0, "b", nil}}, Params: []byte("{}")}).Encode()
	f.Add(seed)
	f.Add([]byte{0x33})
	f.Fuzz(func(t *testing.T, b []byte) {
		if req, err := DecodeRequest(b); err == nil {
			again, err := req.Encode()
			if err != nil {
				t.Fatalf("a decoded request does not encode: %v", err)
			}
			if _, err := DecodeRequest(again); err != nil {
				t.Fatalf("a re-encoded request does not decode: %v", err)
			}
		}
		DecodeResponse(b)
		DecodeRequestResult(b)
		DecodeResponseResult(b)
	})
}

// H2CClient is a client that speaks cleartext HTTP/2, as agentgateway's
// remote processor does.
func H2CClient() *http.Client {
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: &protos}, Timeout: 30 * time.Second}
}
