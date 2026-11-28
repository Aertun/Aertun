// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/source"
	"github.com/aertun/aertun/internal/telemetry"
)

// Handler answers POST /v1/traces.
//
// It is mounted beside the console and outside its session middleware, the
// way the MCP endpoint is, because it authenticates the same way everything
// a push does: a static token from the store's sealed credentials, proved
// before the body is read. An installation that has made no token refuses
// every push, which is the correct behaviour for a write primitive — an
// open telemetry endpoint is a way to put events in the store, and nobody
// should be able to do that by accident.
type Handler struct {
	// Token returns the credential pushes must carry. Empty or erroring
	// refuses everything.
	Token func() (string, error)
	// Mapping returns the source GenAI spans map through, by name, so the
	// deployment's own mapping file wins over the built-in.
	Mapping func() (source.Source, error)
	// Store appends events and says how many it stored, in order: all of
	// them, or, with an error, those stored before it. Answering 200 only
	// after the write is what makes a 200 mean kept.
	Store func([]telemetry.Event) (int, error)
	// Now is the clock; a test sets it.
	Now func() time.Time
	// Limit is how many pushes a minute one source may make. Zero means
	// the feeds' figure.
	Limit int
	// MaxBody caps a request body, compressed or not. Zero means the
	// default below.
	MaxBody int64

	mu     sync.Mutex
	status Status
	// seen holds stored span ids for keepWindow, and swept when it was
	// last swept, so a batch of many spans does not sweep the map once
	// per span.
	seen   map[string]time.Time
	swept  time.Time
	window rateWindow
}

// defaultBody is 16 MiB, decoded. An OTLP batch carries whole spans with
// their content attributes, so it is larger than a webhook's cap; it is
// still a ceiling, because a reader with no ceiling is a way to fill a disk
// from outside.
const defaultBody = 16 << 20

// feedRate is the feeds' own figure, reused rather than invented: far above
// anything a collector sends and far below what fills a disk.
const feedRate = 3000

type rateWindow struct {
	start time.Time
	n     int
}

// The google.rpc.Status codes the protocol's failure bodies carry.
const (
	codeInvalid         = 3  // INVALID_ARGUMENT
	codeExhausted       = 8  // RESOURCE_EXHAUSTED
	codeUnimplemented   = 12 // UNIMPLEMENTED
	codeUnavailable     = 14 // UNAVAILABLE
	codeUnauthenticated = 16 // UNAUTHENTICATED
)

// exportResponse is ExportTraceServiceResponse, the only success shape the
// protocol defines. A full success is the empty partial success.
type exportResponse struct {
	PartialSuccess partialSuccess `json:"partialSuccess"`
}

type partialSuccess struct {
	RejectedSpans int64  `json:"rejectedSpans,omitempty"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
}

// rpcStatus is the failure body the OTLP/HTTP specification uses.
type rpcStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Handler) limit() int {
	if h.Limit > 0 {
		return h.Limit
	}
	return feedRate
}

func (h *Handler) cap() int64 {
	if h.MaxBody > 0 {
		return h.MaxBody
	}
	return defaultBody
}

// Status is a copy of the counters, for whoever wires a screen to this
// later.
func (h *Handler) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

// refused counts a push that did not prove itself. On the status rather
// than the audit log, for the reason the feeds made that trade: whoever is
// failing to authenticate is choosing how fast a one-per-push log grows.
func (h *Handler) refused(why string) {
	h.mu.Lock()
	h.status.Refused++
	h.status.LastRefuse = h.now()
	h.status.Why = why
	h.mu.Unlock()
}

func (h *Handler) allow() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if h.window.start.IsZero() || now.Sub(h.window.start) >= time.Minute {
		h.window = rateWindow{start: now}
	}
	h.window.n++
	return h.window.n <= h.limit()
}

// spanIDs is the ids among a run of events' ids, leaving out spans that
// had none.
func spanIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

// seenBefore reports whether a span id was delivered already, without
// remembering it. Remembering happens once the store has taken the batch
// (remember, below), so a store failure does not swallow the exporter's
// retry: the retry is compared against what was stored, not what was
// accepted and then lost. The cost is a window in which two concurrent
// deliveries of one span both store; against losing events on a retry, that
// is the right side of the trade, and the spool is append-only either way.
func (h *Handler) seenBefore(id string, at time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if at.Sub(h.swept) > time.Minute {
		h.sweep(at)
		h.swept = at
	}
	_, dup := h.seen[id]
	return dup
}

// maxSeen bounds the span ids held for de-duplication. A day of spans at
// the push limit is unbounded in principle — a push carries as many spans
// as fit its body — so the map has a ceiling as well as a horizon.
const maxSeen = 1 << 20

// remember holds span ids as stored.
//
// Past maxSeen, what is past the horizon is swept, and if that is not
// enough the map starts again. Forgetting costs at most a retried span
// stored twice in an append-only spool, the same cost seenBefore already
// accepts for concurrent deliveries; holding without limit costs the
// process.
func (h *Handler) remember(ids []string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil || len(h.seen)+len(ids) > maxSeen {
		h.sweep(at)
		if h.seen == nil || len(h.seen)+len(ids) > maxSeen {
			h.seen = map[string]time.Time{}
		}
	}
	for _, id := range ids {
		h.seen[id] = at
	}
}

// sweep drops ids past the horizon, so the map is bounded by a day of
// spans rather than by the process's life.
func (h *Handler) sweep(at time.Time) {
	if len(h.seen) == 0 {
		return
	}
	for k, when := range h.seen {
		if at.Sub(when) > keepWindow {
			delete(h.seen, k)
		}
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		h.fail(w, r, http.StatusMethodNotAllowed, codeUnimplemented,
			"the OTLP traces endpoint takes POST only")
		return
	}
	// Authenticate before counting: the window is shared, and a window
	// charged for pushes that never proved themselves is one anybody on
	// the network can fill, locking out the exporters it exists to serve.
	// The check reads one header and compares two digests; no body has
	// been read yet.
	if !h.authenticate(w, r) {
		return
	}
	if !h.allow() {
		w.Header().Set("Retry-After", "60")
		h.fail(w, r, http.StatusTooManyRequests, codeExhausted,
			"too many pushes; retry after the window")
		return
	}
	if ct := contentType(r); ct != "application/json" && !isProtobuf(r) {
		h.fail(w, r, http.StatusUnsupportedMediaType, codeInvalid,
			"this endpoint reads OTLP/HTTP, as JSON (application/json) or "+
				"protobuf (application/x-protobuf), and nothing else")
		return
	}
	body, code, msg := h.read(r)
	if code != 0 {
		h.fail(w, r, code, codeInvalid, msg)
		return
	}
	var req exportRequest
	var err error
	if isProtobuf(r) {
		req, err = decodeProtobuf(body)
		if err == nil && len(req.ResourceSpans) == 0 && len(body) > 0 {
			err = errors.New("the protobuf body holds no resource spans, so it is not a traces export")
		}
	} else {
		req, err = parse(body)
	}
	if err != nil {
		// Nothing of a request that did not parse is stored: half of a
		// malformed batch is a shape nobody sent.
		h.refused(err.Error())
		h.fail(w, r, http.StatusBadRequest, codeInvalid, err.Error())
		return
	}
	h.deliver(w, r, req)
}

// authenticate proves the push, in constant time against a digest, before
// the body is read. An endpoint with no credential made yet refuses
// everything rather than accepting everything, and says so on its status
// the way a feed does.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) bool {
	want, err := h.Token()
	if err != nil || strings.TrimSpace(want) == "" {
		h.refused("the endpoint has no push credential to check against " +
			"(aertun connect secret " + SecretName + ")")
		h.fail(w, r, http.StatusServiceUnavailable, codeUnavailable,
			"this endpoint has no push credential to check against")
		return false
	}
	presented := strings.TrimSpace(r.Header.Get("Authorization"))
	if v, ok := strings.CutPrefix(presented, "Bearer "); ok {
		presented = strings.TrimSpace(v)
	}
	// Both sides through SHA-256 first: constant time on equal-length
	// digests, and no dependency on how the secret was stored.
	got := sha256.Sum256([]byte(presented))
	need := sha256.Sum256([]byte(want))
	if subtle.ConstantTimeCompare(got[:], need[:]) != 1 {
		h.refused("the Authorization header does not hold this endpoint's " +
			"credential")
		h.fail(w, r, http.StatusUnauthorized, codeUnauthenticated,
			"the push did not carry this endpoint's authorization")
		return false
	}
	return true
}

// read takes the body, decoding the one compression the specification
// demands of receivers and refusing the rest by name.
func (h *Handler) read(r *http.Request) ([]byte, int, string) {
	ceiling := h.cap()
	raw := io.LimitReader(r.Body, ceiling+1)
	var in io.Reader = raw
	switch strings.ToLower(strings.TrimSpace(
		r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return nil, http.StatusBadRequest,
				"the body says it is gzip and does not open as gzip"
		}
		defer gz.Close()
		in = gz
	default:
		return nil, http.StatusUnsupportedMediaType,
			"this endpoint reads identity and gzip bodies only"
	}
	body, err := io.ReadAll(io.LimitReader(in, ceiling+1))
	if err != nil {
		return nil, http.StatusBadRequest, "the body did not arrive whole"
	}
	if int64(len(body)) > ceiling {
		return nil, http.StatusRequestEntityTooLarge,
			"the body is larger than this endpoint reads"
	}
	return body, 0, ""
}

// deliver maps, stores and answers. One lock around the counting is enough:
// the store itself serialises writers the way every writer to it does.
func (h *Handler) deliver(w http.ResponseWriter, r *http.Request, req exportRequest) {
	now := h.now()
	mapping, err := h.Mapping()
	if err != nil {
		h.fail(w, r, http.StatusServiceUnavailable, codeUnavailable,
			"the GenAI mapping cannot be loaded right now")
		return
	}
	h.mu.Lock()
	h.status.Deliveries++
	h.status.LastAt = now
	h.mu.Unlock()

	var events []telemetry.Event
	var ids []string
	var rejected int64
	worst := ""
	rej := func(path string) {
		rejected++
		if path != "" {
			worst = path
		}
	}
	// Idempotency is per span: a repeated span id, inside one request or
	// across two, is the exporter's retry, not new behaviour.
	batch := map[string]bool{}
	req.each(func(rs *resourceSpans, sp *span) {
		h.mu.Lock()
		h.status.Spans++
		h.mu.Unlock()
		rec, is := record(rs, sp)
		if !is {
			h.mu.Lock()
			h.status.Ignored++
			h.mu.Unlock()
			return
		}
		h.mu.Lock()
		h.status.GenAI++
		h.mu.Unlock()
		id := sp.TraceID + ":" + sp.SpanID
		if sp.SpanID != "" && (batch[id] || h.seenBefore(id, now)) {
			batch[id] = true
			h.mu.Lock()
			h.status.Duplicates++
			h.mu.Unlock()
			return
		}
		e, missed := mapping.Map(rec)
		if len(missed) > 0 {
			rej(missed[0].Path)
			return
		}
		e.Received = now
		if err := e.Validate(); err != nil {
			rej("(not a usable event)")
			return
		}
		events = append(events, e)
		// One id per event, empty for a span that has none, so what the
		// store took can be named exactly.
		if sp.SpanID != "" {
			batch[id] = true
			ids = append(ids, id)
		} else {
			ids = append(ids, "")
		}
	})
	if len(events) > 0 {
		n, err := h.Store(events)
		n = min(max(n, 0), len(events))
		if err != nil {
			h.mu.Lock()
			h.status.Error = err.Error()
			h.status.Stored += n
			h.mu.Unlock()
			// What was stored before the failure is remembered, so the
			// exporter's retry stores only the rest; everything after it
			// must be free to arrive.
			h.remember(spanIDs(ids[:n]), now)
			h.fail(w, r, http.StatusServiceUnavailable, codeUnavailable,
				"the event store did not take the batch; send it again")
			return
		}
		h.remember(spanIDs(ids), now)
	}
	h.mu.Lock()
	h.status.Stored += len(events)
	h.status.Rejected += int(rejected)
	h.status.Error = ""
	h.mu.Unlock()

	// The honest answer: a full success is an empty partial success, and
	// nothing else is invented into the shape. Non-GenAI spans are not
	// rejections — they are on the status, not in the protocol's mouth.
	if isProtobuf(r) {
		w.Header().Set("Content-Type", protobufType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(protobufResponse(rejected, rejectionMessage(rejected, worst)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(exportResponse{PartialSuccess: partialSuccess{
		RejectedSpans: rejected,
		ErrorMessage:  rejectionMessage(rejected, worst),
	}})
}

func rejectionMessage(rejected int64, worst string) string {
	if rejected == 0 {
		return ""
	}
	if worst == "" {
		return "span(s) carrying GenAI attributes could not be turned " +
			"into events"
	}
	// A field a rejection failed on, named the way the mapping names it: a
	// collector operator reading this can go and look at exactly one
	// attribute.
	return "span(s) are missing " + worst + ", which every GenAI event " +
		"needs; nothing without it was stored"
}

// fail answers with a google.rpc.Status, in the encoding the request came
// in: protobuf to a protobuf sender, JSON to everybody else.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status, code int, msg string) {
	if isProtobuf(r) {
		w.Header().Set("Content-Type", protobufType)
		w.WriteHeader(status)
		_, _ = w.Write(protobufStatus(code, msg))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(rpcStatus{Code: code, Message: msg})
}

// protobufType is the media type of OTLP/HTTP protobuf.
const protobufType = "application/x-protobuf"

// contentType is a request's media type, without its parameters.
func contentType(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
}

// isProtobuf reports whether a request is OTLP/HTTP protobuf.
func isProtobuf(r *http.Request) bool {
	ct := contentType(r)
	return ct == protobufType || ct == "application/protobuf"
}
