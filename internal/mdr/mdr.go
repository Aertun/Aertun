// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package mdr tests a managed detection provider, or an AI SOC, blind: on
// emulations run at times drawn at random and committed before any was run,
// on the customer's own estate.
//
// # Why
//
// Such a service sells a time: "we detect and notify within 30 minutes".
// The independent tests of that claim are few, run on somebody else's
// network, and known about in advance, which is the one condition under
// which any service performs at its best. What a customer wants to know is
// how the service does on an ordinary night, on its own machines.
//
// # What makes the test blind
//
// A plan is drawn before anything is run: each item an emulation from the
// operator's own list — an Atomic Red Team test's id, say — and, where the
// list says so, the host to run it on, at a time drawn uniformly at random
// in the window. The randomness is crypto/rand's, and a random nonce is in
// the plan so its digest cannot be found by trying every schedule. The plan
// is kept in the store and only its digest, with the provider, the count
// and the window, goes into the signed, hash-chained audit log, so nothing
// this program publishes tells the provider when the next emulation comes,
// and nobody can change the plan afterwards to leave out a bad day.
//
// Items are shown to whoever runs them only once they are due. A run is
// counted from its scheduled time to a day after it: earlier is not the
// plan, and later is a time somebody chose. Each run, and the provider's
// notification about it, is recorded by a verified person in the audit
// log; a notification can also be joined from the provider's alerts in the
// event store, but only on the host the plan names, never on time alone.
//
// The audit log may leave the store — streamed to a SIEM, handed to an
// assessor — and the provider may be able to read it there. So the records
// carry item numbers and times, never emulations or hosts, and a run is
// best recorded once its notification window has passed: a record written
// while the provider is still deciding tells it which alert is the test.
package mdr

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/proof"
)

// MaxEmulations bounds an operator's list: it is read whole.
const MaxEmulations = 10000

var nonceShape = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidName reports whether s can name a plan.
func ValidName(s string) bool { return proof.ValidMDRPlan(s) }

// ValidHost reports whether s can name the host an emulation runs on: the
// device as the connectors write it, issuer:value, which is the only form a
// provider's alert can be joined on exactly.
func ValidHost(s string) bool { return proof.ValidIdentity(s) }

// Emulation is one line of the operator's list.
type Emulation struct {
	ID string
	// Host is where it is run, when the list says.
	Host string
}

// ReadEmulations reads the operator's list: one emulation per line, its id
// and optionally the host it is run on, separated by spaces. A blank line
// and a line starting with # are skipped. Anything else — a line with more
// in it, an id or a host not in its shape, the same pair twice — is refused
// rather than skipped, because a list read differently from how it was
// written draws from something other than what the operator meant.
func ReadEmulations(b []byte) ([]Emulation, error) {
	var out []Emulation
	seen := map[Emulation]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		e := Emulation{ID: fields[0]}
		if len(fields) == 2 {
			e.Host = fields[1]
		}
		switch {
		case len(fields) > 2:
			return nil, fmt.Errorf("line %d has more than an emulation and a host", line)
		case !proof.ValidEmulation(e.ID):
			return nil, fmt.Errorf("line %d: an emulation is an id, such as T1059.001-1: letters, "+
				"digits and . _ : -, at most 64", line)
		case e.Host != "" && !ValidHost(e.Host):
			return nil, fmt.Errorf("line %d: a host is the device as the connectors write it, "+
				"issuer:value, such as crowdstrike:4f2a9c", line)
		case seen[e]:
			return nil, fmt.Errorf("line %d lists an emulation, on its host, a second time; "+
				"each is listed once, so each is as likely to be drawn", line)
		}
		seen[e] = true
		out = append(out, e)
		if len(out) > MaxEmulations {
			return nil, fmt.Errorf("the list holds more than %d emulations", MaxEmulations)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d cannot be read: %w", line+1, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the list names no emulation")
	}
	return out, nil
}

// Item is one emulation of a plan, numbered in the order the items fall due.
type Item struct {
	N         int    `json:"n"`
	Emulation string `json:"emulation"`
	Host      string `json:"host,omitempty"`
	// At is when it falls due.
	At time.Time `json:"at"`
}

// Plan is a drawn test.
type Plan struct {
	Name string `json:"name"`
	// Nonce is 32 random bytes, in hex. Without it a plan of one item from a
	// short list could be found from its digest by trying every second of
	// the window.
	Nonce    string `json:"nonce"`
	Provider string `json:"provider"`
	// Since and Until bound when the items fall due; Until is not included.
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
	Items []Item    `json:"items"`
}

// random is a whole number in [0, n) from r, uniformly.
func random(r io.Reader, n int64) (int64, error) {
	v, err := randInt(r, n)
	if err != nil {
		return 0, fmt.Errorf("no randomness for the plan: %w", err)
	}
	return v, nil
}

// Draw makes a plan of count items from the list, each at a time drawn
// uniformly from the whole seconds of [since, since+over), each emulation
// drawn uniformly from the list. r is crypto/rand.Reader everywhere but a
// test.
func Draw(name, provider string, list []Emulation, count int, since time.Time,
	over time.Duration, r io.Reader) (*Plan, error) {

	since = since.UTC().Truncate(time.Second)
	p := &Plan{Name: name, Provider: provider, Since: since, Until: since.Add(over)}
	if err := p.checkTerms(); err != nil {
		return nil, err
	}
	if count < 1 || count > proof.MaxMDRItems {
		return nil, fmt.Errorf("a plan holds between 1 and %d emulations", proof.MaxMDRItems)
	}
	if len(list) == 0 || len(list) > MaxEmulations {
		return nil, fmt.Errorf("a plan is drawn from a list of between 1 and %d emulations", MaxEmulations)
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("no randomness for the nonce: %w", err)
	}
	p.Nonce = hex.EncodeToString(nonce)
	seconds := int64(over / time.Second)
	for range count {
		pick, err := random(r, int64(len(list)))
		if err != nil {
			return nil, err
		}
		offset, err := random(r, seconds)
		if err != nil {
			return nil, err
		}
		e := list[pick]
		p.Items = append(p.Items, Item{Emulation: e.ID, Host: e.Host,
			At: since.Add(time.Duration(offset) * time.Second)})
	}
	sort.SliceStable(p.Items, func(i, j int) bool { return p.Items[i].At.Before(p.Items[j].At) })
	for i := range p.Items {
		p.Items[i].N = i + 1
	}
	return p, p.Check()
}

func wholeUTC(t time.Time) bool {
	return t.Location() == time.UTC && t.Equal(t.Truncate(time.Second))
}

// checkTerms refuses a name, a provider or a window a plan cannot have.
func (p *Plan) checkTerms() error {
	if !ValidName(p.Name) {
		return fmt.Errorf("a plan's name is 2 to 48 of a-z, 0-9 and -, starting with a letter")
	}
	if !proof.ValidVerdictSource(p.Provider) {
		return fmt.Errorf("the provider is named by a short name you choose: 2 to 32 of a-z, " +
			"0-9 and -, starting with a letter")
	}
	span := p.Until.Sub(p.Since)
	if !wholeUTC(p.Since) || !wholeUTC(p.Until) || span < proof.MinMDRWindow || span > proof.MaxMDRWindow {
		return fmt.Errorf("a plan's window is between a day and %d days, in whole seconds",
			int(proof.MaxMDRWindow.Hours()/24))
	}
	return nil
}

// Check refuses a plan that is not one Draw could have made, so an edited
// plan file is caught before its digest is even compared with the log's.
func (p *Plan) Check() error {
	if err := p.checkTerms(); err != nil {
		return err
	}
	if !nonceShape.MatchString(p.Nonce) {
		return fmt.Errorf("plan %s's nonce is not 32 bytes of hex", p.Name)
	}
	if len(p.Items) < 1 || len(p.Items) > proof.MaxMDRItems {
		return fmt.Errorf("a plan holds between 1 and %d emulations", proof.MaxMDRItems)
	}
	for i, it := range p.Items {
		switch {
		case it.N != i+1:
			return fmt.Errorf("plan %s's items are not numbered in order", p.Name)
		case !proof.ValidEmulation(it.Emulation) || (it.Host != "" && !ValidHost(it.Host)):
			return fmt.Errorf("plan %s's item %d does not name an emulation, or a host, in its shape",
				p.Name, it.N)
		case !wholeUTC(it.At) || it.At.Before(p.Since) || !it.At.Before(p.Until):
			return fmt.Errorf("plan %s's item %d does not fall due inside its window", p.Name, it.N)
		case i > 0 && it.At.Before(p.Items[i-1].At):
			return fmt.Errorf("plan %s's items are not in the order they fall due", p.Name)
		}
	}
	return nil
}

// Digest is the sha256 of the plan as committed: what the audit log records
// and what a proof's subject is.
func (p *Plan) Digest() string {
	b, err := json.Marshal(p)
	if err != nil {
		// Marshalling this plain struct cannot fail; a digest of nothing
		// would match nothing, which is the safe answer if it ever did.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Item returns the n-th item.
func (p *Plan) Item(n int) (Item, bool) {
	if n < 1 || n > len(p.Items) {
		return Item{}, false
	}
	return p.Items[n-1], true
}

// Closes is when a test on the plan closes, for a provider held to sla: the
// last item may fall due just before the window's end, be run up to
// proof.MDRRunWithin after that, and be notified up to sla after its run.
func (p *Plan) Closes(sla time.Duration) time.Time {
	return p.Until.Add(proof.MDRRunWithin + sla)
}

// PlannedAction is the audit action a plan is committed under.
const PlannedAction = "mdr.planned"

// CommitDetail is what the commitment records: the digest, which is the
// commitment, and what a reader of the log may know — the provider, how
// many and when — and nothing that says which emulation, where, or when
// any one of them falls due.
func (p *Plan) CommitDetail() map[string]string {
	return map[string]string{"plan": p.Name, "sha256": p.Digest(), "provider": p.Provider,
		"items": strconv.Itoa(len(p.Items)), "since": p.Since.Format(time.RFC3339),
		"until": p.Until.Format(time.RFC3339)}
}

// randInt is a whole number in [0, n), uniformly, from the bytes r gives:
// eight at a time, rejecting a draw past the largest multiple of n below
// 2^64, so no remainder is likelier than another. Written out rather than
// taken from crypto/rand.Int so the reader it is given is the one it reads,
// which is what lets a test draw the same plan twice.
func randInt(r io.Reader, n int64) (int64, error) {
	if n <= 0 {
		return 0, fmt.Errorf("nothing to draw from")
	}
	un := uint64(n)
	rem := (math.MaxUint64%un + 1) % un // 2^64 mod n
	buf := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		if v := binary.BigEndian.Uint64(buf); v <= math.MaxUint64-rem {
			return int64(v % un), nil
		}
	}
}
