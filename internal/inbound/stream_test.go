// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package inbound

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// A record becomes the event the rules read: the action, its outcome, the
// kind of actor and the details a rule needs, and not the free text.
func TestAStreamRecordIsWhatTheRulesRead(t *testing.T) {
	lines := []string{
		`{"class_uid":6003,"activity_id":3,"activity_name":"dual.approved","time":1792921835099,"status":"success",` +
			`"api":{"operation":"dual.approved"},"actor":{"user":{"name":"p_1a2b","type":"User"}},"resources":[{"uid":"/"}],` +
			`"unmapped":{"seq":44,"hash":"ab","detail_alone":"true","detail_kind":"grant","detail_what":"make lee admin on /"}}`,
		`{"class_uid":3002,"activity_id":1,"activity_name":"auth.failures","time":1792921835100,"status":"denied",` +
			`"actor":{"user":{"name":"p_9","type":"Service"}},"resources":[{"uid":"/"}],"unmapped":{"detail_failures":"6"}}`,
		`{"class_uid":6003,"activity_id":2,"activity_name":"mcp.call","time":1792921835101,"status":"failure",` +
			`"api":{"operation":"publish"},"actor":{"user":{"name":"app:agent_1","type":"AI"},"app_name":"agent_1"},` +
			`"resources":[{"uid":"/mcp"}],"unmapped":{"detail_tool":"aertun_read"}}`,
	}
	at := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	evs, err := StreamEvents(strings.Join(lines, "\n")+"\n", "site-b", at)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("%d events", len(evs))
	}
	alone := evs[0]
	if alone.Source != StreamSource || alone.Class != telemetry.ClassAPIActivity ||
		alone.Disposition != telemetry.DispositionAllowed || alone.Actor.Issuer != "site-b" ||
		alone.Actor.Value != "p_1a2b" || !alone.Received.Equal(at) {
		t.Errorf("%+v", alone)
	}
	if alone.Raw["action"] != "dual.approved" || alone.Raw["alone"] != "true" ||
		alone.Raw["request_kind"] != "grant" || alone.Raw["kind"] != "human" || alone.Raw["seq"] != "44" {
		t.Errorf("raw %v", alone.Raw)
	}
	if _, ok := alone.Raw["what"]; ok {
		t.Error("free text somebody wrote was copied into what the rules read")
	}
	if f := evs[1]; f.Class != telemetry.ClassAuthentication || f.Disposition != telemetry.DispositionBlocked ||
		f.Raw["kind"] != "service" || f.Raw["failures"] != "6" {
		t.Errorf("%+v", f)
	}
	if m := evs[2]; m.Disposition != telemetry.DispositionFailed || m.Raw["kind"] != "ai" ||
		m.Raw["operation"] != "publish" || m.Raw["model"] != "agent_1" || m.Raw["tool"] != "aertun_read" {
		t.Errorf("%+v", m)
	}
	// A verified batch with a line that is not a record is the sender's bug
	// and is said, not skipped.
	if _, err := StreamEvents(lines[0]+"\nnot json\n", "site-b", at); err == nil {
		t.Error("a line that is not a record was skipped quietly")
	}
}

func TestStreamKeysAreCheckedWhenPinned(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	head, _, _ := ed25519.GenerateKey(rand.Reader)
	good := StreamKeys{KeyID: "aertun-stream-0123", Alg: "ed25519",
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		HeadEd25519: base64.StdEncoding.EncodeToString(head),
		HeadMLDSA:   base64.StdEncoding.EncodeToString([]byte("an ML-DSA key is checked when the verifier is built"))}
	b, _ := json.Marshal(good)
	if _, err := ParseStreamKeys(b); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*StreamKeys){
		"another algorithm": func(k *StreamKeys) { k.Alg = "hmac-sha256" },
		"no key id":         func(k *StreamKeys) { k.KeyID = "" },
		"a key id to break a header with": func(k *StreamKeys) {
			k.KeyID = `x";alg="none`
		},
		"a short key":                      func(k *StreamKeys) { k.PublicKey = "AAAA" },
		"no head key":                      func(k *StreamKeys) { k.HeadEd25519 = "" },
		"no ML-DSA head key":               func(k *StreamKeys) { k.HeadMLDSA = "" },
		"a head context to break out with": func(k *StreamKeys) { k.HeadContext = "a\nb" },
	} {
		k := good
		change(&k)
		b, _ := json.Marshal(k)
		if _, err := ParseStreamKeys(b); err == nil {
			t.Errorf("%s was pinned", name)
		}
	}
}
