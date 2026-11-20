// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/metrics"
	"github.com/aertun/aertun/internal/receiptlog"
)

// The server's own telemetry at /metrics, in the Prometheus text format,
// beside the /healthz and /readyz the console already answers.
//
// It answers a bearer token and nothing else: `aertun token issue
// prometheus --principal prometheus --role viewer`, then the scrape's
// authorization. The token is read from the request alone, never from the
// files the command line falls back to, so an anonymous request is
// refused rather than answered as whoever runs the server. A token bound
// to a key, or to another resource, is refused, and so is an agent's:
// agents reach this program through the agent interface and nowhere else.
//
// Nothing here names a person, an agent, a tool or a source: counts by
// closed words only, so the scrape is safe to keep in a monitoring system
// whose readers are not the store's.

// ownMetrics are the counters kept as things happen, for the process's life.
var ownMetrics = metrics.New()

var (
	httpResponses = ownMetrics.Counter("aertun_http_responses_total",
		"HTTP responses the server gave, by status class.", "class")
	mcpCalls = ownMetrics.Counter("aertun_mcp_calls_total",
		"Tool calls the agent interface answered, by outcome.", "outcome")
	callReceipts = ownMetrics.Counter("aertun_mcp_call_receipts_total",
		"Receipts the agent interface appended for the calls it answered, by result.", "result")
	upkeepRuns = ownMetrics.Counter("aertun_upkeep_runs_total",
		"Scheduled job runs, by job and result.", "job", "result")
)

// upkeepLast is when each scheduled job last succeeded.
var upkeepLast sync.Map

var startedAt = time.Now()

// noteUpkeep counts one run of a scheduled job.
func noteUpkeep(job string, err error) {
	if err != nil {
		upkeepRuns.Inc(job, "error")
		return
	}
	upkeepRuns.Inc(job, "ok")
	upkeepLast.Store(job, time.Now())
}

// statusWriter remembers the status a handler wrote.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the writer underneath, which
// is how the console's live pages flush.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// countResponses counts every response by its status class.
func countResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		code := sw.status
		if code == 0 {
			code = http.StatusOK
		}
		class := "other"
		if code >= 100 && code < 600 {
			class = string(rune('0'+code/100)) + "xx"
		}
		httpResponses.Inc(class)
	})
}

// mountMetrics puts /metrics on the server, with the gauges read when it
// is scraped.
func mountMetrics(mux *http.ServeMux, root string, cfg *config.Config, addr string, ready func() error) {
	gauges := metrics.New()
	gauges.Gauge("aertun_build_info", "The running build.", func() []metrics.Sample {
		return []metrics.Sample{{Labels: []metrics.Label{{Name: "version", Value: version},
			{Name: "go_version", Value: runtime.Version()}}, Value: 1}}
	})
	gauges.Gauge("aertun_start_time_seconds", "When this process started, in Unix seconds.",
		func() []metrics.Sample { return metrics.One(float64(startedAt.Unix())) })
	gauges.Gauge("aertun_ready", "1 when the console can do its work, as /readyz answers.",
		func() []metrics.Sample { return metrics.One(boolValue(ready == nil || ready() == nil)) })
	gauges.Gauge("aertun_audit_log_writable", "1 when the last write to the audit log succeeded.",
		func() []metrics.Sample {
			_, failed := auditFaults.Load(auditKey(root))
			return metrics.One(boolValue(!failed))
		})
	gauges.Gauge("aertun_receipt_log_entries", "Entries in the receipt log, when one is set up.",
		func() []metrics.Sample {
			if !receiptlog.Exists(filepath.Join(root, "receipts")) {
				return nil
			}
			l, err := openReceiptLog(root)
			if err != nil || l == nil {
				return nil
			}
			n, err := l.Size()
			if err != nil {
				return nil
			}
			return metrics.One(float64(n))
		})
	gauges.Gauge("aertun_upkeep_last_success_seconds", "When each scheduled job last succeeded, in Unix seconds.",
		func() []metrics.Sample {
			var out []metrics.Sample
			upkeepLast.Range(func(k, v any) bool {
				out = append(out, metrics.Sample{Labels: []metrics.Label{{Name: "job", Value: k.(string)}},
					Value: float64(v.(time.Time).Unix())})
				return true
			})
			return out
		})
	gauges.Gauge("go_goroutines", "Goroutines that currently exist.",
		func() []metrics.Sample { return metrics.One(float64(runtime.NumGoroutine())) })
	gauges.Gauge("go_memstats_heap_alloc_bytes", "Heap bytes allocated and still in use.",
		func() []metrics.Sample {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return metrics.One(float64(m.HeapAlloc))
		})

	resource := publicOrigin(cfg, addr) + "/metrics"
	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		if err := metricsCaller(root, r, resource); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aertun-metrics"`)
			code := http.StatusUnauthorized
			if errors.Is(err, errForbiddenScrape) {
				code = http.StatusForbidden
			}
			http.Error(w, http.StatusText(code), code)
			return
		}
		w.Header().Set("Content-Type", metrics.ContentType)
		_, _ = ownMetrics.WriteTo(w)
		_, _ = gauges.WriteTo(w)
	}))
}

var errForbiddenScrape = errors.New("this credential may not read the metrics")

// metricsCaller checks the scrape's bearer token: a plain token for this
// resource, held by somebody who may view, and not an agent.
func metricsCaller(root string, r *http.Request, resource string) error {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return errors.New("no bearer token")
	}
	toks, err := loadTokens(root)
	if err != nil {
		return err
	}
	tok, err := toks.AuthenticateFor(strings.TrimSpace(token), resource, time.Now())
	if err != nil {
		// Including a key-bound token presented without its proof.
		return err
	}
	c := callerFromToken(tok)
	if c.Agent != "" {
		return errForbiddenScrape
	}
	if err := authorise(root, c, auth.ActView, auth.AreaSecurity); err != nil {
		return errForbiddenScrape
	}
	return nil
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
