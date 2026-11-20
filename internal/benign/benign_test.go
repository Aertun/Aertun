// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package benign

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/correlate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/telemetry"
)

var testKey = bytes.Repeat([]byte{7}, 32)

func sanitiser(t *testing.T) *Sanitiser {
	t.Helper()
	s, err := NewSanitiser(testKey, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func commonPrefix(a, b netip.Addr) int {
	x, y := a.AsSlice(), b.AsSlice()
	for i := range x {
		for bit := 0; bit < 8; bit++ {
			m := byte(0x80 >> bit)
			if x[i]&m != y[i]&m {
				return i*8 + bit
			}
		}
	}
	return len(x) * 8
}

// An address keeps its special-purpose range and its shared prefixes with
// other addresses, and becomes the same pseudonym every time.
func TestAnAddressKeepsItsClassAndItsPrefixes(t *testing.T) {
	s := sanitiser(t)
	for _, c := range []struct {
		a, within string
	}{{"10.1.2.3", "10.0.0.0/8"}, {"192.168.7.9", "192.168.0.0/16"}, {"127.0.0.1", "127.0.0.0/8"},
		{"fe80::1", "fe80::/10"}, {"2001:db8::7", "2001:db8::/32"}, {"fd00::5", "fc00::/7"},
		{"2a00:1450::1", "2000::/3"}} {
		in := netip.MustParseAddr(c.a)
		out := s.IP(in)
		if !netip.MustParsePrefix(c.within).Contains(out) || out == in {
			t.Errorf("%s became %s, outside %s or unchanged", c.a, out, c.within)
		}
		if again := s.IP(in); again != out {
			t.Errorf("%s became %s and then %s", c.a, out, again)
		}
	}
	a, b := netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("8.8.8.8")
	pa, pb := s.IP(a), s.IP(b)
	if commonPrefix(pa, pb) != commonPrefix(a, b) {
		t.Errorf("8.8.4.4 and 8.8.8.8 share %d bits; their pseudonyms %s and %s share %d",
			commonPrefix(a, b), pa, pb, commonPrefix(pa, pb))
	}
	if _, special := specialOf(pa); special {
		t.Errorf("a public address became %s, in a special range", pa)
	}
	other, _ := NewSanitiser(bytes.Repeat([]byte{8}, 32), nil, nil)
	if other.IP(a) == pa {
		t.Error("two keys made the same pseudonym")
	}
}

func TestIdentifiersKeepTheirShape(t *testing.T) {
	s := sanitiser(t)
	e := s.Email("Dana.Ops@corp.example.com")
	if !strings.HasPrefix(e, "p-") || !strings.HasSuffix(e, ".com") || strings.Contains(e, "dana") ||
		strings.Count(e, "@") != 1 {
		t.Errorf("an email became %q", e)
	}
	if s.Email("dana.ops@corp.example.com") != e {
		t.Error("the same address in another case became another pseudonym")
	}
	x, y := s.Domain("build.corp.example.com"), s.Domain("mail.corp.example.com")
	if x == y || x[strings.Index(x, "."):] != y[strings.Index(y, "."):] {
		t.Errorf("siblings %q and %q lost their shared parent", x, y)
	}
	if b := s.Domain("acme-backups.s3.amazonaws.com"); !strings.HasSuffix(b, ".s3.amazonaws.com") ||
		strings.Contains(b, "acme") {
		t.Errorf("a bucket on a public provider became %q", b)
	}
	if p := s.Path("/home/dana/projects/run.sh"); strings.Contains(p, "dana") ||
		!strings.HasSuffix(p, "/projects/run.sh") || !strings.HasPrefix(p, "/home/u") {
		t.Errorf("a home path became %q", p)
	}
	if p := s.Path(`C:\Users\Dana\AppData\x.ps1`); strings.Contains(p, "Dana") {
		t.Errorf("a Windows profile path became %q", p)
	}
}

// Free text keeps its command and loses its credentials and personal data,
// the same placeholder for the same value everywhere.
func TestFreeTextLosesWhatItMustNotCarry(t *testing.T) {
	s := sanitiser(t)
	cmd := "psql postgres://app:Sup3rS3cretPassw0rd@db/prod -c 'select 1' --notify dana@corp.example.com " +
		"AKIAIOSFODNN7EXAMPLE /home/dana/.pgpass"
	out := s.Text(cmd)
	for _, gone := range []string{"Sup3rS3cret", "dana@", "AKIAIOSFODNN7EXAMPLE", "/home/dana/"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q survived: %s", gone, out)
		}
	}
	for _, kept := range []string{"psql", "-c 'select 1'", "--notify", ".pgpass"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q was lost: %s", kept, out)
		}
	}
	if s.Text(cmd) != out {
		t.Error("the same text sanitised twice came out differently")
	}
	if !strings.Contains(out, s.Email("dana@corp.example.com")) {
		t.Errorf("an email in text is not the pseudonym it has in a field: %s", out)
	}
}

func rule(t *testing.T, js string) detect.Rule {
	t.Helper()
	var r detect.Rule
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

var t0 = time.Date(2026, 11, 10, 2, 0, 0, 0, time.UTC)

func backupRun(n int) []telemetry.Event {
	var out []telemetry.Event
	for i := 0; i < n; i++ {
		at := t0.Add(time.Duration(i) * time.Second)
		out = append(out, telemetry.Event{Time: at, Received: at.Add(2 * time.Second),
			Source: "aws/cloudtrail", Class: telemetry.ClassAPIActivity,
			Actor: telemetry.ID{Issuer: "aws", Value: "svc-backup"},
			Raw: map[string]string{"eventName": "GetObject", "userName": "svc-backup",
				"sourceIPAddress": "10.20.0.5", "requestParameters": "bucket=acme-prod-db"}})
	}
	return out
}

func rules(t *testing.T) RuleSet {
	return RuleSet{Rules: []detect.Rule{
		rule(t, `{"id":"aws.bulk-read","title":"Bulk object reads","sources":["aws/cloudtrail"],"severity":3,
		 "when":{"match":{"field":"raw.eventName","op":"equals","values":["GetObject"]}}}`),
		rule(t, `{"id":"aws.not-the-backup-account","title":"A read not by the backup account","sources":["aws/cloudtrail"],"severity":3,
		 "when":{"all":[{"match":{"field":"raw.eventName","op":"equals","values":["GetObject"]}},
		  {"not":{"match":{"field":"raw.userName","op":"equals","values":["svc-backup"]}}}]}}`),
	}}
}

// A capture refuses what fires unseen, refuses what sanitising changed
// unless the loss is accepted or the field kept, and records both.
func TestACaptureIsRefusedUntilItsFiresAndLossesAreFaced(t *testing.T) {
	in := CaptureInput{Name: "nightly-backup", Class: "backup", Events: backupRun(20), Key: testKey,
		Rules: rules(t), Why: "the 02:00 backup reads every object", Ticket: "CHG-1042", By: "dana",
		Now: t0.Add(time.Hour)}
	_, err := NewCapture(in)
	if err == nil || !strings.Contains(err.Error(), "aws.bulk-read") {
		t.Fatalf("an unacknowledged fire: %v", err)
	}
	in.Acknowledge = map[string]bool{"aws.bulk-read": true}
	_, err = NewCapture(in)
	if err == nil || !strings.Contains(err.Error(), "aws.not-the-backup-account") ||
		!strings.Contains(err.Error(), "raw.userName") {
		t.Fatalf("sanitising changed a rule's outcome and was not refused: %v", err)
	}
	in.RawFields = map[string]bool{"raw.userName": true}
	c, err := NewCapture(in)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Session
	if s.Fidelity.Reduced || s.Raw[0] != "raw.userName" || s.Acknowledged[0] != "aws.bulk-read" ||
		s.Expires != t0.Add(time.Hour+DefaultLife) || s.Events != 20 {
		t.Errorf("%+v", s)
	}
	if a := c.Events[0].Actor; a.Issuer != "aws" || !strings.HasPrefix(a.Value, "p-") {
		t.Errorf("the actor was not pseudonymised under its issuer: %+v", a)
	}
	if c.Events[0].Raw["userName"] != "svc-backup" {
		t.Error("a field kept raw on request was changed")
	}
	in.RawFields, in.AcceptLoss = nil, true
	c, err = NewCapture(in)
	if err != nil || !c.Session.Fidelity.Reduced || c.Session.Fidelity.Lost[0] != "aws.not-the-backup-account" {
		t.Errorf("an accepted loss: %v %+v", err, c.Session.Fidelity)
	}
}

// Only what the rules read is kept; what was dropped and what was changed
// are recorded by the names rules read them by.
func TestACaptureKeepsWhatTheRulesReadAndSaysWhatItChanged(t *testing.T) {
	in := CaptureInput{Name: "nightly-backup", Class: "backup", Events: backupRun(3), Key: testKey,
		Rules: rules(t), Why: "backup", By: "dana", Now: t0.Add(time.Hour),
		Acknowledge: map[string]bool{"aws.bulk-read": true}, RawFields: map[string]bool{"raw.userName": true}}
	c, err := NewCapture(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := c.Events[0].Raw["requestParameters"]; kept {
		t.Error("a field no rule reads was kept")
	}
	if strings.Join(c.Session.Dropped, ",") != "raw.requestParameters,raw.sourceIPAddress" {
		t.Errorf("dropped %v", c.Session.Dropped)
	}
	if strings.Join(c.Session.Transformed, ",") != "actor.value" {
		t.Errorf("transformed %v", c.Session.Transformed)
	}
}

// A rule reading a dropped field, or comparing a transformed one with a
// value, is unmeasurable unless this rule, by digest, was checked; a rule
// over other sources is measurable, because it cannot fire there at all.
func TestWhatARuleCanBeMeasuredOn(t *testing.T) {
	s := Session{Sources: []string{"aws/cloudtrail"}, Dropped: []string{"raw.sourceIPAddress"},
		Transformed: []string{"actor.value", "raw.userName"}}
	cases := map[string]struct {
		js, want string
		checked  bool
	}{
		"other sources":            {`{"id":"x","sources":["okta/system-log"],"when":{"match":{"field":"raw.sourceIPAddress","op":"exists"}}}`, "", false},
		"a dropped field":          {`{"id":"x","sources":["aws/cloudtrail"],"when":{"match":{"field":"raw.sourceIPAddress","op":"inside","values":["10.0.0.0/8"]}}}`, "does not carry", false},
		"a literal on a pseudonym": {`{"id":"x","sources":["aws/cloudtrail"],"when":{"match":{"field":"actor","op":"equals","values":["aws:svc-backup"]}}}`, "pseudonymised", false},
		"the same, checked":        {`{"id":"x","sources":["aws/cloudtrail"],"when":{"match":{"field":"actor","op":"equals","values":["aws:svc-backup"]}}}`, "", true},
		"presence of a pseudonym":  {`{"id":"x","sources":["aws/cloudtrail"],"when":{"match":{"field":"raw.userName","op":"exists"}}}`, "", false},
		"a field kept as it was":   {`{"id":"x","sources":["aws/cloudtrail"],"when":{"match":{"field":"raw.eventName","op":"equals","values":["GetObject"]}}}`, "", false},
	}
	for name, c := range cases {
		r := rule(t, c.js)
		d, _ := RuleDigest(r)
		got := Unmeasurable(r, d, s, map[string]bool{d: c.checked})
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func sealed(t *testing.T) ([]byte, *pack.Key, Manifest, map[string][]telemetry.Event) {
	t.Helper()
	in := CaptureInput{Name: "nightly-backup", Class: "backup", Events: backupRun(5), Key: testKey,
		Rules: rules(t), Why: "backup", By: "dana", Now: t0.Add(time.Hour),
		Acknowledge: map[string]bool{"aws.bulk-read": true}, RawFields: map[string]bool{"raw.userName": true}}
	c, err := NewCapture(in)
	if err != nil {
		t.Fatal(err)
	}
	c.Session.ApprovedBy = "p-" + strings.Repeat("a", 13)
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{Made: t0.Add(2 * time.Hour), Program: "test", Policy: PolicyVersion, KeyID: KeyID(testKey),
		Sessions: []Session{c.Session}, Sets: []FidelitySet{{ID: c.Session.Fidelity.Set, Rules: c.FidelityRules}}}
	ev := map[string][]telemetry.Event{c.Session.Name: c.Events}
	b, err := Seal(m, ev, k)
	if err != nil {
		t.Fatal(err)
	}
	return b, k, m, ev
}

func TestABundleOpensOnlyAsItWasSealed(t *testing.T) {
	body, k, _, _ := sealed(t)
	b, err := Open(body, k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Manifest.Sessions) != 1 || len(b.Events["nightly-backup"]) != 5 || len(b.Digest) != 64 {
		t.Fatalf("%+v", b.Manifest)
	}
	live, expired := b.Live(t0.Add(DefaultLife + 2*time.Hour))
	if len(live) != 0 || len(expired) != 1 {
		t.Error("a session past its expiry still counts")
	}
	if len(b.Checked(b.Manifest.Sessions[0])) != 2 {
		t.Error("the fidelity set was not carried")
	}

	edit := func(f func(map[string]any)) []byte {
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		f(doc)
		out, _ := json.Marshal(doc)
		return out
	}
	events := func(doc map[string]any) []any {
		return doc["events"].(map[string]any)["nightly-backup"].([]any)
	}
	tamper := map[string][]byte{
		"an event edited": edit(func(d map[string]any) {
			events(d)[0].(map[string]any)["raw"].(map[string]any)["eventName"] = "DeleteObject"
		}),
		"an event dropped": edit(func(d map[string]any) {
			d["events"].(map[string]any)["nightly-backup"] = events(d)[1:]
		}),
		"a session added": edit(func(d map[string]any) {
			d["events"].(map[string]any)["another"] = events(d)
		}),
		"a field nobody knows": edit(func(d map[string]any) { d["note"] = "trust me" }),
		"the payload swapped": edit(func(d map[string]any) {
			d["envelope"].(map[string]any)["payload"] = "e30="
		}),
	}
	for name, b := range tamper {
		if _, err := Open(b, k.PublicKey()); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	other, _ := pack.GenerateKey()
	if _, err := Open(body, other.PublicKey()); err == nil {
		t.Error("another key's bundle opened")
	}
}

func TestASealRefusesWhatDoesNotHoldTogether(t *testing.T) {
	_, k, m, ev := sealed(t)
	cases := map[string]func(*Manifest, map[string][]telemetry.Event){
		"vouched and approved by one person": func(m *Manifest, _ map[string][]telemetry.Event) {
			m.Sessions[0].ApprovedBy = m.Sessions[0].VouchedBy
		},
		"a class not in the list": func(m *Manifest, _ map[string][]telemetry.Event) { m.Sessions[0].Class = "fine" },
		"a missing fidelity set":  func(m *Manifest, _ map[string][]telemetry.Event) { m.Sets = nil },
		"an older policy":         func(m *Manifest, _ map[string][]telemetry.Event) { m.Policy = "v0" },
		"events not its digest": func(_ *Manifest, e map[string][]telemetry.Event) {
			e["nightly-backup"] = e["nightly-backup"][:4]
		},
	}
	for name, change := range cases {
		mm := m
		mm.Sessions = append([]Session{}, m.Sessions...)
		e := map[string][]telemetry.Event{"nightly-backup": append([]telemetry.Event{}, ev["nightly-backup"]...)}
		change(&mm, e)
		if _, err := Seal(mm, e, k); err == nil {
			t.Errorf("%s: sealed", name)
		}
	}
}

// A correlation over pseudonymised group-by fields keeps its outcome,
// because a consistent pseudonym keeps every equality.
func TestACorrelationSurvivesPseudonyms(t *testing.T) {
	rs := rules(t)
	rs.Corrs = []correlate.Rule{{ID: "aws.many-reads", Title: "many reads by one actor", Type: correlate.EventCount,
		Rules: []string{"aws.bulk-read"}, GroupBy: []string{"actor"}, Timespan: time.Minute,
		Test: correlate.Test{Op: "gte", N: 10}}}
	in := CaptureInput{Name: "nightly-backup", Class: "backup", Events: backupRun(20), Key: testKey,
		Rules: rs, Why: "backup", By: "dana", Now: t0.Add(time.Hour), RawFields: map[string]bool{"raw.userName": true},
		Acknowledge: map[string]bool{"aws.bulk-read": true, "aws.many-reads": true}}
	c, err := NewCapture(in)
	if err != nil {
		t.Fatalf("the correlation's outcome changed under pseudonyms: %v", err)
	}
	if strings.Join(c.Fired, ",") != "aws.bulk-read,aws.many-reads" {
		t.Errorf("fired %v", c.Fired)
	}
}
