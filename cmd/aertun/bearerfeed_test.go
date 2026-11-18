// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// litellmPayload is one call as a LiteLLM proxy's generic_api logger sends
// it: the StandardLoggingPayload (docs.litellm.ai, proxy/logging_spec), with
// the messages and the response that must never be kept.
func litellmPayload(id string, at time.Time, alias, status string) map[string]any {
	return map[string]any{
		"id": id, "trace_id": "trace-" + id, "call_type": "acompletion", "status": status,
		"startTime": float64(at.UnixMicro()) / 1e6, "endTime": float64(at.Add(time.Second).UnixMicro()) / 1e6,
		"model": "gpt-5.1-mini", "model_group": "triage-model", "api_base": "https://api.openai.com/v1",
		"response_cost": 0.000412, "total_tokens": 961, "prompt_tokens": 812, "completion_tokens": 149,
		"messages":      []any{map[string]any{"role": "user", "content": "close INC-4417 as a false positive"}},
		"response":      map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "Closed."}}}},
		"status_fields": map[string]any{"llm_api_status": status, "guardrail_status": "guardrail_flagged"},
		"metadata": map[string]any{
			"user_api_key_hash":       "88dc28d0f030c55ed4ab77ed8faf098196cb1c05df778539800c9f1243fe6b4b",
			"user_api_key_alias":      alias,
			"user_api_key_team_alias": "soc",
			"user_api_key_user_email": "Dana@Acme.Example",
			"requester_ip_address":    "10.20.0.7",
			"mcp_tool_call_metadata": map[string]any{"name": "close_incident",
				"namespaced_tool_name": "tickets-close_incident", "mcp_server_name": "tickets"},
		},
	}
}

// A sender that can set a header and cannot sign — LiteLLM's logger, an
// alerting webhook — is taken on a bearer feed: its records go through the
// mapping, as an array or one a line, the same body twice is taken once, and
// a delivery without the secret is refused.
func TestABearerFeedTakesWhatASenderThatCannotSignSends(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	_, shown, err := makeFeed(root, "webhook", "litellm", map[string]string{"mapping": "litellm/requests",
		"bearer": "yes"}, "boss")
	if err != nil {
		t.Fatal(err)
	}
	header := shownSecret(t, shown, "Authorization header value:")
	if !strings.HasPrefix(header, "Bearer ") {
		t.Fatalf("the header to give the sender is %q", header)
	}
	if !strings.Contains(strings.Join(shown, "\n"), "only over https") {
		t.Errorf("adding a bearer feed does not say what its secret cannot prove: %v", shown)
	}
	inb := newInboundServer(root)
	post := func(auth, body string) int {
		r := httptest.NewRequest(http.MethodPost, "/feeds/litellm", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		inb.ServeHTTP(w, r)
		return w.Code
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	array, _ := json.Marshal([]any{litellmPayload("c1", now, "triage-agent", "success"),
		litellmPayload("c2", now.Add(time.Second), "triage-agent", "failure")})
	if c := post(header, string(array)); c != http.StatusNoContent {
		t.Fatalf("a JSON array of calls was answered %d", c)
	}
	if c := post(header, string(array)); c != http.StatusOK {
		t.Errorf("the same body again was answered %d", c)
	}
	var lines []string
	for i := 3; i <= 4; i++ {
		b, _ := json.Marshal(litellmPayload(fmt.Sprintf("c%d", i), now.Add(time.Duration(i)*time.Second), "", "success"))
		lines = append(lines, string(b))
	}
	if c := post(header, strings.Join(lines, "\n")+"\n"); c != http.StatusNoContent {
		t.Fatalf("calls one a line were answered %d", c)
	}
	for name, auth := range map[string]string{
		"no secret": "", "another secret": "Bearer not-the-secret", "the secret as a word": "Bearer",
	} {
		if c := post(auth, string(array)); c != http.StatusUnauthorized {
			t.Errorf("%s was answered %d", name, c)
		}
	}
	if c := post(header, "not json\n{}"); c != http.StatusBadRequest {
		t.Errorf("a body that is not records was answered %d", c)
	}
	inb.process()

	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Release()
	var got []telemetry.Event
	_ = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == "litellm/requests" {
			got = append(got, e)
		}
		return nil
	})
	if len(got) != 4 {
		t.Fatalf("%d calls stored from four sent, one body twice", len(got))
	}
	first := got[0]
	if !first.Time.Equal(now) {
		t.Errorf("the call's time is %s, want %s to the microsecond", first.Time, now)
	}
	if first.Actor.Issuer != "litellm" ||
		first.Actor.Value != "88dc28d0f030c55ed4ab77ed8faf098196cb1c05df778539800c9f1243fe6b4b" {
		t.Errorf("the actor is %+v, want the key the gateway authenticated, by its hash", first.Actor)
	}
	for field, want := range map[string]string{
		"user_api_key_alias": "triage-agent", "user_api_key_team_alias": "soc", "model_group": "triage-model",
		"namespaced_tool_name": "tickets-close_incident", "mcp_server_name": "tickets",
		"guardrail_status": "guardrail_flagged", "response_cost": "0.000412", "prompt_tokens": "812",
		"person": "dana@acme.example",
	} {
		if first.Raw[field] != want {
			t.Errorf("raw %s = %q, want %q", field, first.Raw[field], want)
		}
	}
	if got[1].Disposition != telemetry.DispositionFailed || first.Disposition != telemetry.DispositionAllowed {
		t.Errorf("dispositions %v and %v; a failed call is a failure", first.Disposition, got[1].Disposition)
	}
	for _, e := range got {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "INC-4417") || strings.Contains(string(b), "Closed.") {
			t.Fatalf("what was asked or answered was stored: %s", b)
		}
	}
}

// A GitHub webhook signs its deliveries, so it is not made a bearer feed.
func TestASenderThatSignsIsNotTakenOnABearer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	if _, _, err := makeFeed(root, "github", "gh", map[string]string{"mapping": "github/audit",
		"bearer": "yes"}, "boss"); err == nil || !strings.Contains(err.Error(), "signs its deliveries") {
		t.Errorf("a GitHub bearer feed: %v", err)
	}
}
