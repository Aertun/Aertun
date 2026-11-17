// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mdr

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/proof"
)

// stream is a reader of bytes a seed decides, so a test can draw the same
// plan twice.
type stream struct {
	seed  byte
	block uint64
	buf   []byte
}

func (s *stream) Read(p []byte) (int, error) {
	for len(s.buf) < len(p) {
		var b [9]byte
		b[0] = s.seed
		binary.BigEndian.PutUint64(b[1:], s.block)
		sum := sha256.Sum256(b[:])
		s.buf = append(s.buf, sum[:]...)
		s.block++
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

var t0 = time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)

const list = `# Atomic Red Team tests, and where each runs
T1059.001-1 crowdstrike:dev-a
T1059.001-1 crowdstrike:dev-b
T1003.001-2

T1547.001-3 crowdstrike:dev-a
`

func TestTheOperatorsListIsReadStrictly(t *testing.T) {
	got, err := ReadEmulations([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	want := []Emulation{{"T1059.001-1", "crowdstrike:dev-a"}, {"T1059.001-1", "crowdstrike:dev-b"},
		{"T1003.001-2", ""}, {"T1547.001-3", "crowdstrike:dev-a"}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	for name, body := range map[string]string{
		"a description":          "T1059.001-1 run powershell on the box\n",
		"an id with a slash":     "T1059/001\n",
		"a host with no issuer":  "T1059.001-1 dev-a\n",
		"a host with a space":    "T1059.001-1 crowdstrike:dev a\n",
		"the same pair twice":    "T1003.001-2\nT1003.001-2\n",
		"nothing":                "# only a comment\n\n",
		"a line past the buffer": strings.Repeat("A", 5000) + "\n",
	} {
		if _, err := ReadEmulations([]byte(body)); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

// A plan is drawn from the reader it is given: the same bytes draw the same
// plan, other bytes another; every item falls due inside the window, at a
// whole second, in order, and is an emulation from the list on its host.
func TestAPlanIsDrawnAtRandomInItsWindow(t *testing.T) {
	emulations, _ := ReadEmulations([]byte(list))
	draw := func(r *stream) *Plan {
		p, err := Draw("acme-q4", "acme", emulations, 200, t0.Add(400*time.Millisecond), 30*24*time.Hour, r)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b, c := draw(&stream{seed: 1}), draw(&stream{seed: 1}), draw(&stream{seed: 2})
	if a.Digest() != b.Digest() || a.Digest() == c.Digest() || a.Nonce == c.Nonce {
		t.Error("the plan is not what its randomness decides")
	}
	if !a.Since.Equal(t0) || !a.Until.Equal(t0.Add(30*24*time.Hour)) || len(a.Items) != 200 {
		t.Fatalf("%s to %s, %d items", a.Since, a.Until, len(a.Items))
	}
	listed := map[Emulation]bool{}
	for _, e := range emulations {
		listed[e] = true
	}
	drawn := map[Emulation]int{}
	days := map[int]bool{}
	for i, it := range a.Items {
		if it.N != i+1 || it.At.Before(a.Since) || !it.At.Before(a.Until) ||
			!it.At.Equal(it.At.Truncate(time.Second)) || (i > 0 && it.At.Before(a.Items[i-1].At)) {
			t.Fatalf("item %+v", it)
		}
		e := Emulation{it.Emulation, it.Host}
		if !listed[e] {
			t.Fatalf("item %d is not from the list: %+v", it.N, e)
		}
		drawn[e]++
		days[int(it.At.Sub(a.Since)/(24*time.Hour))] = true
	}
	// Two hundred draws from four: each drawn, none overwhelmingly; spread
	// across the month rather than bunched in a corner of it.
	for e, n := range drawn {
		if n < 20 || n > 80 {
			t.Errorf("%+v drawn %d times of 200", e, n)
		}
	}
	if len(drawn) != 4 || len(days) < 25 {
		t.Errorf("%d emulations drawn, on %d days of 30", len(drawn), len(days))
	}
	if err := a.Check(); err != nil {
		t.Error(err)
	}
	for name, change := range map[string]func(*Plan){
		"an item moved past the window": func(p *Plan) { p.Items[199].At = p.Until },
		"items out of order":            func(p *Plan) { p.Items[0].At = p.Items[199].At },
		"items renumbered":              func(p *Plan) { p.Items[3].N = 9 },
		"an emulation in prose":         func(p *Plan) { p.Items[5].Emulation = "run mimikatz" },
		"a host in prose":               func(p *Plan) { p.Items[5].Host = "the CFO's laptop" },
		"a nonce cut short":             func(p *Plan) { p.Nonce = p.Nonce[:16] },
		"a window of an hour":           func(p *Plan) { p.Until = p.Since.Add(time.Hour) },
		"a time not on the second":      func(p *Plan) { p.Items[0].At = p.Items[0].At.Add(time.Millisecond) },
	} {
		p := draw(&stream{seed: 1})
		change(p)
		if p.Check() == nil {
			t.Errorf("%s: checked", name)
		}
	}
	for name, err := range map[string]error{
		"no items": func() error {
			_, err := Draw("acme-q4", "acme", emulations, 0, t0, 30*24*time.Hour, rand.Reader)
			return err
		}(),
		"too many": func() error {
			_, err := Draw("acme-q4", "acme", emulations, 1001, t0, 30*24*time.Hour, rand.Reader)
			return err
		}(),
		"an empty list": func() error { _, err := Draw("acme-q4", "acme", nil, 5, t0, 30*24*time.Hour, rand.Reader); return err }(),
		"a short window": func() error {
			_, err := Draw("acme-q4", "acme", emulations, 5, t0, 23*time.Hour, rand.Reader)
			return err
		}(),
		"a provider in prose": func() error {
			_, err := Draw("acme-q4", "Acme MDR", emulations, 5, t0, 30*24*time.Hour, rand.Reader)
			return err
		}(),
		"a name with a slash": func() error {
			_, err := Draw("../acme", "acme", emulations, 5, t0, 30*24*time.Hour, rand.Reader)
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("%s: drawn", name)
		}
	}
}

// What the log is told is the digest and what anybody may know — the
// provider, how many, the window — and nothing that says which emulation,
// where, or when.
func TestThePlanIsCommittedAsADigestAlone(t *testing.T) {
	emulations, _ := ReadEmulations([]byte(list))
	p, err := Draw("acme-q4", "acme", emulations, 12, t0, 30*24*time.Hour, &stream{seed: 3})
	if err != nil {
		t.Fatal(err)
	}
	d := p.CommitDetail()
	b, _ := json.Marshal(p)
	if len(d) != 6 || d["plan"] != "acme-q4" || d["provider"] != "acme" || d["items"] != "12" ||
		d["since"] != "2026-11-01T09:30:00Z" || d["until"] != "2026-12-01T09:30:00Z" ||
		d["sha256"] != p.Digest() || proof.SHA256(b)["sha256"] != p.Digest() {
		t.Fatalf("%v", d)
	}
	for k, v := range d {
		for _, secret := range []string{"T1059", "T1003", "T1547", "dev-a", "dev-b", p.Nonce,
			p.Items[0].At.Format(time.RFC3339)} {
			if strings.Contains(v, secret) {
				t.Errorf("the commitment's %s gives away %s", k, secret)
			}
		}
		if audit.ForbiddenKey(k) != "" {
			t.Errorf("the log refuses the key %s", k)
		}
	}
}

// A draw rejects a value past the largest multiple of n below 2^64, so no
// remainder is likelier than another.
func TestADrawRejectsTheRemainder(t *testing.T) {
	r := bytes.NewReader(append(bytes.Repeat([]byte{0xff}, 8), 0, 0, 0, 0, 0, 0, 0, 5))
	if v, err := randInt(r, 3); err != nil || v != 2 {
		t.Errorf("%d, %v: the top value was not rejected", v, err)
	}
	r = bytes.NewReader(bytes.Repeat([]byte{0xff}, 8))
	if v, err := randInt(r, 4); err != nil || v != 3 {
		t.Errorf("%d, %v: nothing needs rejecting when n divides 2^64", v, err)
	}
}

// test is a log with a plan committed in it, now: items 1 to 3 fell due in
// the last two hours, item 4 is not due for ten.
type test struct {
	t   *testing.T
	log *audit.Log
	at  string
	p   *Plan
	now time.Time
}

func newTest(t *testing.T) *test {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.New(audit.Options{Path: path, Key: []byte("0123456789abcdef0123456789abcdef"),
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := &Plan{Name: "acme-q4", Nonce: strings.Repeat("9f", 32), Provider: "acme",
		Since: now.Add(-2 * time.Hour), Until: now.Add(46 * time.Hour), Items: []Item{
			{N: 1, Emulation: "T1059.001-1", Host: "crowdstrike:dev-a", At: now.Add(-90 * time.Minute)},
			{N: 2, Emulation: "T1003.001-2", At: now.Add(-time.Hour)},
			{N: 3, Emulation: "T1547.001-3", Host: "crowdstrike:dev-b", At: now.Add(-30 * time.Minute)},
			{N: 4, Emulation: "T1059.001-1", Host: "crowdstrike:dev-a", At: now.Add(10 * time.Hour)},
		}}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	tt := &test{t: t, log: l, at: path, p: p, now: now}
	tt.append(PlannedAction, "lee", true, audit.KindHuman, p.CommitDetail())
	return tt
}

func (tt *test) append(action, who string, verified bool, kind audit.Kind, d map[string]string) {
	tt.t.Helper()
	model := ""
	if kind == audit.KindAI {
		model = "mcp-client"
	}
	if _, err := tt.log.Append(audit.Record{Action: action, Resource: "/mdr/acme-q4",
		Outcome: audit.Success, Principal: who, Kind: kind, Model: model, Verified: verified,
		Detail: d}); err != nil {
		tt.t.Fatal(err)
	}
}

func (tt *test) ran(n int) { tt.ranAt(n, time.Now()) }
func (tt *test) ranAt(n int, at time.Time) {
	tt.append(RanAction, "lee", true, audit.KindHuman, RanDetail("acme-q4", n, at))
}
func (tt *test) notified(n int, ref string) {
	tt.append(NotifiedAction, "lee", true, audit.KindHuman, NotifiedDetail("acme-q4", n, time.Now(), ref, ""))
}

func (tt *test) verify() (*Result, error) {
	events, err := audit.Read(tt.at)
	if err != nil {
		tt.t.Fatal(err)
	}
	return Verify(tt.p, events)
}

func TestTheRecordIsReadBack(t *testing.T) {
	tt := newTest(t)
	r, err := tt.verify()
	if err != nil {
		t.Fatal(err)
	}
	prog := tt.p.Progress(r, time.Now())
	if len(prog.Due) != 3 || prog.Waiting != 1 || prog.Run != 0 || prog.Lapsed != 0 {
		t.Errorf("before any run: %+v", prog)
	}
	tt.ran(1)
	tt.ran(3)
	tt.notified(1, "ldt:1")
	r, err = tt.verify()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Ran) != 2 || len(r.Notified) != 1 || r.Refs["ldt:1"] != 1 || r.Commit.Seq != 1 {
		t.Errorf("%+v", r)
	}
	prog = tt.p.Progress(r, time.Now())
	if len(prog.Due) != 1 || prog.Due[0].N != 2 || prog.Run != 2 || prog.Waiting != 1 {
		t.Errorf("after two runs: %+v", prog)
	}
	// Thirty hours on: item 2's time to run passed with no run; item 4 has
	// fallen due.
	prog = tt.p.Progress(r, tt.now.Add(30*time.Hour))
	if prog.Lapsed != 1 || len(prog.Due) != 1 || prog.Due[0].N != 4 || prog.Waiting != 0 {
		t.Errorf("thirty hours on: %+v", prog)
	}
}

// What a test cannot count is refused, not counted around.
func TestARecordATestCannotCountIsRefused(t *testing.T) {
	cases := map[string]struct {
		do   func(*test)
		want string
	}{
		"a person whose identity was not proved": {func(tt *test) {
			tt.append(RanAction, "lee", false, audit.KindHuman, RanDetail("acme-q4", 1, time.Now()))
		}, "not proved"},
		"a model": {func(tt *test) {
			tt.append(RanAction, "agent:bot", true, audit.KindAI, RanDetail("acme-q4", 1, time.Now()))
		}, "not a person"},
		"a run twice": {func(tt *test) { tt.ran(1); tt.ran(1) }, "more than once"},
		"an item the plan has not": {func(tt *test) {
			tt.append(RanAction, "lee", true, audit.KindHuman, RanDetail("acme-q4", 9, time.Now()))
		}, "does not have"},
		"a run before it fell due": {func(tt *test) { tt.ran(4) }, "not yet due"},
		"a run before the commitment": {func(tt *test) {
			tt.ranAt(1, tt.now.Add(-80*time.Minute))
		}, "before its plan was committed"},
		"a run said to be later than its record": {func(tt *test) {
			tt.ranAt(1, time.Now().Add(time.Hour))
		}, "later than the record"},
		"a notification before its run is recorded": {func(tt *test) { tt.notified(1, "ldt:1") },
			"before its run"},
		"a notification before the run": {func(tt *test) {
			tt.ran(1)
			tt.append(NotifiedAction, "lee", true, audit.KindHuman,
				NotifiedDetail("acme-q4", 1, tt.now.Add(-time.Hour), "ldt:1", ""))
		}, "before it was run"},
		"one ticket for two items": {func(tt *test) {
			tt.ran(1)
			tt.ran(3)
			tt.notified(1, "ldt:1")
			tt.notified(3, "ldt:1")
		}, "one ticket"},
		"a notification twice": {func(tt *test) {
			tt.ran(1)
			tt.notified(1, "ldt:1")
			tt.notified(1, "ldt:2")
		}, "notified more than once"},
		"a ticket in prose": {func(tt *test) {
			tt.ran(1)
			tt.notified(1, "the analyst emailed us")
		}, "not in its shape"},
		"the plan committed twice": {func(tt *test) {
			tt.append(PlannedAction, "lee", true, audit.KindHuman, tt.p.CommitDetail())
		}, "committed 2 times"},
		"the plan changed since": {func(tt *test) { tt.p.Items[1].Emulation = "T1003.001-1" },
			"not the plan the audit log committed"},
	}
	for name, c := range cases {
		tt := newTest(t)
		c.do(tt)
		if _, err := tt.verify(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// A run counts from its item's time to a day after it, and never before
// the commitment.
func TestWhenARunCounts(t *testing.T) {
	it := Item{N: 3, At: t0}
	committed := t0.Add(-time.Hour)
	for at, ok := range map[time.Time]bool{
		t0: true, t0.Add(23*time.Hour + 59*time.Minute): true,
		t0.Add(-time.Second): false, t0.Add(24 * time.Hour): false,
	} {
		if err := RunCounts(it, at, committed); (err == nil) != ok {
			t.Errorf("run at %s: %v", at, err)
		}
	}
	if err := RunCounts(it, t0, t0.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "committed") {
		t.Errorf("a run before the commitment: %v", err)
	}
}

// A notification is joined from the event store only on evidence: the host
// the plan names, an alert raised and received after the run and within a
// day of it, and no other run on that host near enough to share it.
func TestANotificationIsJoinedOnlyOnEvidence(t *testing.T) {
	p := &Plan{Name: "acme-q4", Items: []Item{
		{N: 1, Emulation: "T1", Host: "crowdstrike:dev-a"},
		{N: 2, Emulation: "T2"},
		{N: 3, Emulation: "T3", Host: "crowdstrike:dev-a"},
		{N: 4, Emulation: "T4", Host: "crowdstrike:dev-b"},
		{N: 5, Emulation: "T5", Host: "crowdstrike:dev-c"},
		{N: 6, Emulation: "T6", Host: "crowdstrike:dev-d"},
		{N: 7, Emulation: "T7", Host: "crowdstrike:dev-e"},
		{N: 8, Emulation: "T8", Host: "crowdstrike:dev-f"},
	}}
	ran := func(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }
	r := &Result{Ran: map[int]time.Time{1: ran(0), 2: ran(1), 3: ran(5), 4: ran(2), 5: ran(3),
		6: ran(4), 7: ran(6)}, Notified: map[int]time.Time{7: ran(7)}, Refs: map[string]int{"ldt:7": 7, "ldt:taken": 8}}
	alerts := []Alert{
		// dev-a: about item 1 or item 3, which ran five hours apart.
		{Ref: "ldt:a", Host: "crowdstrike:dev-a", Raised: ran(6), Received: ran(6)},
		// dev-b: the earliest after the run is the notification; one the
		// provider dated before the run, and one before it, are not.
		{Ref: "ldt:b-late", Host: "crowdstrike:dev-b", Raised: ran(4), Received: ran(4)},
		{Ref: "ldt:b", Host: "crowdstrike:dev-b", Raised: ran(2).Add(20 * time.Minute), Received: ran(2).Add(21 * time.Minute)},
		{Ref: "ldt:b-backdated", Host: "crowdstrike:dev-b", Raised: ran(2).Add(-time.Minute), Received: ran(2).Add(time.Minute)},
		{Ref: "ldt:b-before", Host: "crowdstrike:dev-b", Raised: ran(1), Received: ran(1)},
		// dev-c: only after a day has passed.
		{Ref: "ldt:c", Host: "crowdstrike:dev-c", Raised: ran(27), Received: ran(27)},
		// dev-d: the alert is already another item's.
		{Ref: "ldt:taken", Host: "crowdstrike:dev-d", Raised: ran(4).Add(time.Minute), Received: ran(4).Add(time.Minute)},
		// Item 2 names no host; an alert at its time on any device is not it.
		{Ref: "ldt:x", Host: "crowdstrike:dev-z", Raised: ran(1).Add(time.Minute), Received: ran(1).Add(time.Minute)},
		{Ref: "ldt:y", Raised: ran(1).Add(time.Minute), Received: ran(1).Add(time.Minute)},
	}
	matches, rep := Join(p, r, alerts)
	if len(matches) != 1 || matches[0].N != 4 || matches[0].Ref != "ldt:b" ||
		!matches[0].At.Equal(ran(2).Add(21*time.Minute)) {
		t.Errorf("joined %+v", matches)
	}
	if rep.NoHost != 1 || rep.Ambiguous != 2 || rep.Unmatched != 1 || rep.Taken != 1 {
		t.Errorf("%+v", rep)
	}
}
