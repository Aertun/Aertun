// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/fetch"
)

// The bounds one call is held to.
const (
	// RequestTimeout bounds one call, connection and answer together.
	RequestTimeout = 15 * time.Second
	// ReadTimeout bounds every call a posture makes, together: an endpoint
	// that answers slowly leaves the rest of the settings unread rather
	// than holding the command open.
	ReadTimeout = 2 * time.Minute
	// MaxResponse bounds one answer. The largest is a Safe's owners, which
	// at MaxSafeOwners is under twenty kilobytes of hexadecimal.
	MaxResponse = 256 << 10
)

// Client calls one JSON-RPC endpoint.
type Client struct {
	// url is where every call goes. It is never put into a message,
	// because a hosted provider's carries the credential in its path or
	// query.
	url string
	// host is what every message names instead.
	host string
	// hidden are the parts of the URL no message may repeat, longest
	// first, for an error that echoes them.
	hidden []string
	http   *http.Client
	next   int
}

// Dial checks an endpoint's URL and makes a client for it whose every
// connection is held to reach, to the deployment's network mode under the
// purpose "chain", and to no redirect.
func Dial(raw string, reach fetch.Reach) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	// The parser's own error quotes the URL, so it is not passed on.
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("the RPC endpoint is not a URL with a host, like " +
			"https://rpc.example.org/v1")
	}
	host := u.Host
	if u.User != nil {
		return nil, fmt.Errorf("the RPC endpoint at %s has a user and password in its URL, which "+
			"parsers disagree about the host of; use the provider's URL with the credential in "+
			"its path or query", host)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Plain HTTP only where no network lies between: a node run on this
		// machine. Anywhere else whoever is on the path chooses the
		// settings a proof says it read.
		if !loopback(u.Hostname()) {
			return nil, fmt.Errorf("the RPC endpoint at %s is plain http; use https, which "+
				"every hosted provider serves, or a node on this machine", host)
		}
	default:
		return nil, fmt.Errorf("the RPC endpoint at %s is %q; it is https", host, u.Scheme)
	}
	u.Fragment, u.RawFragment = "", ""
	c := &Client{url: u.String(), host: host,
		http: fetch.Speaking("chain", reach, RequestTimeout)}
	for _, s := range []string{u.String(), u.RequestURI(), u.EscapedPath(), u.Path, u.RawQuery} {
		if len(s) > 1 {
			c.hidden = append(c.hidden, s)
		}
	}
	sort.Slice(c.hidden, func(i, j int) bool { return len(c.hidden[i]) > len(c.hidden[j]) })
	return c, nil
}

// Host is the endpoint's host, which is all of it a message or a record
// names.
func (c *Client) Host() string { return c.host }

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// callError is a call the endpoint did not answer with a result. Code is
// the JSON-RPC error code when it answered with an error, and zero when it
// did not answer properly at all. Its text names the host, never the URL,
// and never repeats what the endpoint said: an error message is the
// endpoint's to write.
type callError struct {
	method string
	host   string
	code   int64
	why    string
}

func (e *callError) Error() string {
	if e.code != 0 {
		return fmt.Sprintf("the RPC endpoint at %s answered %s with error %d", e.host, e.method, e.code)
	}
	return fmt.Sprintf("the RPC endpoint at %s did not answer %s: %s", e.host, e.method, e.why)
}

// scrubbed is a transport error's text without any part of the URL in it.
func (c *Client) scrubbed(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		// The wrapper's text is "Post \"<url>\": …"; only what follows it
		// is the reason.
		err = ue.Err
	}
	msg := err.Error()
	for _, h := range c.hidden {
		msg = strings.ReplaceAll(msg, h, "…")
	}
	return msg
}

// call makes one JSON-RPC call and returns its result.
func (c *Client) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	c.next++
	id := c.next
	if params == nil {
		// JSON-RPC 2.0 has params be a list or an object, and some
		// endpoints refuse null for it.
		params = []any{}
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	fail := func(why string) error { return &callError{method: method, host: c.host, why: why} }
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fail(c.scrubbed(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aertun/1 (+chain)")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fail(c.scrubbed(err))
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return nil, fail(c.scrubbed(err))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fail(fmt.Sprintf("it answered HTTP %d", resp.StatusCode))
	}
	if len(answer) > MaxResponse {
		return nil, fail(fmt.Sprintf("its answer is larger than %d bytes", MaxResponse))
	}
	var r struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code int64 `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(answer, &r); err != nil || r.JSONRPC != "2.0" {
		return nil, fail("its answer is not JSON-RPC 2.0")
	}
	if string(r.ID) != strconv.Itoa(id) {
		return nil, fail("it answered another request than the one asked")
	}
	if r.Error != nil {
		code := r.Error.Code
		if code == 0 {
			// Zero is not a JSON-RPC code, and here it means "no code".
			return nil, fail("it answered with an error that has no code")
		}
		return nil, &callError{method: method, host: c.host, code: code}
	}
	if len(r.Result) == 0 {
		return nil, fail("its answer has no result")
	}
	return r.Result, nil
}
