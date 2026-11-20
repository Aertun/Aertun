// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
)

// TestMetricsAnswerABearerTokenOnly: /metrics answers a viewer's token
// presented with the request, and refuses no token, a bad one, an agent's,
// and — the case a command-line resolver would get wrong — a request that
// presents nothing while the server's own environment holds a token.
func TestMetricsAnswerABearerTokenOnly(t *testing.T) {
	root := caveatSite(t)
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	viewer, _, err := ts.Issue("prometheus", "dana@acme.example", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	agent, _, err := ts.Issue("agent:watcher", "watcher", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", viewer)

	mux := http.NewServeMux()
	cfg := mustConfig(root)
	mountMetrics(mux, root, cfg, "127.0.0.1:8080", func() error { return nil })
	srv := httptest.NewServer(countResponses(mux))
	defer srv.Close()

	get := func(method, token string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+"/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	for name, c := range map[string]struct {
		method, token string
		want          int
	}{
		"nothing, with AERTUN_TOKEN set on the server": {"GET", "", 401},
		"a bad token":    {"GET", "aet_" + strings.Repeat("x", 52), 401},
		"an agent token": {"GET", agent, 403},
		"a POST":         {"POST", viewer, 405},
	} {
		if code, _ := get(c.method, c.token); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	code, body := get("GET", viewer)
	if code != 200 {
		t.Fatalf("a viewer's token: %d %s", code, body)
	}
	for _, want := range []string{"# TYPE aertun_build_info gauge", "aertun_ready 1", "aertun_audit_log_writable 1",
		`aertun_http_responses_total{class="4xx"} `, "go_goroutines "} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape has no %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "dana") || strings.Contains(body, "watcher") {
		t.Error("the scrape names a person or an agent")
	}
}
