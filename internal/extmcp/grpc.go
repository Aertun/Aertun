// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package extmcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// gRPC status codes this server answers with.
const (
	statusOK            = 0
	statusInvalid       = 3
	statusUnimplemented = 12
	statusInternal      = 13
)

// Policy answers ExtMCP's two calls.
type Policy interface {
	CheckRequest(ctx context.Context, req *Request) (*RequestResult, error)
	CheckResponse(ctx context.Context, resp *Response) (*ResponseResult, error)
}

// Handler serves a Policy as gRPC: a unary call on each of the service's
// two paths, its body one length-prefixed, uncompressed message.
func Handler(p Policy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.ProtoMajor != 2 ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			http.Error(w, "this is a gRPC service: POST over HTTP/2, content-type application/grpc",
				http.StatusUnsupportedMediaType)
			return
		}
		method, ok := strings.CutPrefix(r.URL.Path, "/"+Service+"/")
		if !ok || (method != "CheckRequest" && method != "CheckResponse") {
			status(w, statusUnimplemented, "no such method: "+r.URL.Path)
			return
		}
		if enc := r.Header.Get("Grpc-Encoding"); enc != "" && enc != "identity" {
			status(w, statusUnimplemented, "messages are not compressed here")
			return
		}
		limit := MaxMessage
		if method == "CheckResponse" {
			limit = MaxResponse
		}
		msg, err := readFrame(r.Body, limit)
		if errors.Is(err, errTooLarge) && method == "CheckResponse" {
			// The call has run; its result is too large to read, and
			// refusing it would only hide it from the caller.
			reply(w, (&ResponseResult{}).Encode())
			return
		}
		if err != nil {
			status(w, statusInvalid, err.Error())
			return
		}
		var out []byte
		switch method {
		case "CheckRequest":
			req, err := DecodeRequest(msg)
			if err != nil {
				status(w, statusInvalid, "McpRequest: "+err.Error())
				return
			}
			res, err := p.CheckRequest(r.Context(), req)
			if err != nil {
				status(w, statusInternal, err.Error())
				return
			}
			out = res.Encode()
		case "CheckResponse":
			resp, err := DecodeResponse(msg)
			if err != nil {
				status(w, statusInvalid, "McpResponse: "+err.Error())
				return
			}
			res, err := p.CheckResponse(r.Context(), resp)
			if err != nil {
				status(w, statusInternal, err.Error())
				return
			}
			out = res.Encode()
		}
		reply(w, out)
	})
}

// reply answers a call with one message and an OK status in the trailers.
func reply(w http.ResponseWriter, msg []byte) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", strconv.Itoa(statusOK))
	w.WriteHeader(http.StatusOK)
	w.Write(frame(msg))
}

// Server is an http.Server for a Policy that speaks cleartext HTTP/2 and
// nothing else, as agentgateway's remote processor connects.
func Server(addr string, p Policy) *http.Server {
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	return &http.Server{Addr: addr, Handler: Handler(p), Protocols: &protos,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute}
}

var errTooLarge = errors.New("the message is larger than this server reads")

// readFrame reads a body that is exactly one uncompressed message of at
// most limit bytes; one that says it is larger is not read at all.
func readFrame(body io.Reader, limit int) ([]byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(body, head[:]); err != nil {
		return nil, errors.New("the body is not a gRPC message")
	}
	if head[0] != 0 {
		return nil, errors.New("the message is compressed, and messages are not compressed here")
	}
	n := binary.BigEndian.Uint32(head[1:5])
	if uint64(n) > uint64(limit) {
		return nil, fmt.Errorf("%w: %d bytes, over %d", errTooLarge, n, limit)
	}
	b, err := io.ReadAll(io.LimitReader(body, int64(n)+1))
	if err != nil {
		return nil, err
	}
	if uint32(len(b)) != n {
		return nil, errors.New("the body is not exactly one message")
	}
	return b, nil
}

func frame(msg []byte) []byte {
	out := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	return append(out, msg...)
}

// status answers a call with a gRPC status and no message: the
// trailers-only form, every status in the headers.
func status(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", strconv.Itoa(code))
	w.Header().Set("Grpc-Message", percentEncode(msg))
	w.WriteHeader(http.StatusOK)
}

// percentEncode is gRPC's encoding of a status message: every byte that is
// not printable ASCII, and the percent sign, as %XX.
func percentEncode(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// Client calls an ExtMCP server as agentgateway does.
type Client struct {
	// Base is the server's URL, http://host:port.
	Base string
	HTTP *http.Client
}

// NewClient is a client for the server at addr (host:port) through hc,
// which must speak cleartext HTTP/2. The caller makes hc: this package
// dials nothing of its own, and nothing in the program calls an ExtMCP
// server; the tests do, as agentgateway would.
func NewClient(addr string, hc *http.Client) *Client {
	return &Client{Base: "http://" + addr, HTTP: hc}
}

func (c *Client) call(ctx context.Context, method string, msg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/"+Service+"/"+method,
		bytes.NewReader(frame(msg)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+5+1))
	if err != nil {
		return nil, err
	}
	code := resp.Header.Get("Grpc-Status")
	if code == "" {
		code = resp.Trailer.Get("Grpc-Status")
	}
	if code != strconv.Itoa(statusOK) {
		msg := resp.Header.Get("Grpc-Message")
		if msg == "" {
			msg = resp.Trailer.Get("Grpc-Message")
		}
		return nil, fmt.Errorf("gRPC status %s: %s", code, msg)
	}
	return readFrame(bytes.NewReader(body), MaxResponse)
}

// CheckRequest sends a request-phase call.
func (c *Client) CheckRequest(ctx context.Context, req *Request) (*RequestResult, error) {
	msg, err := req.Encode()
	if err != nil {
		return nil, err
	}
	out, err := c.call(ctx, "CheckRequest", msg)
	if err != nil {
		return nil, err
	}
	return DecodeRequestResult(out)
}

// CheckResponse sends a response-phase call.
func (c *Client) CheckResponse(ctx context.Context, resp *Response) (*ResponseResult, error) {
	msg, err := resp.Encode()
	if err != nil {
		return nil, err
	}
	out, err := c.call(ctx, "CheckResponse", msg)
	if err != nil {
		return nil, err
	}
	return DecodeResponseResult(out)
}
