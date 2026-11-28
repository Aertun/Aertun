// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package benign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/telemetry"
)

// A bundle is one file: an in-toto Statement whose subjects are the sessions
// by their content digests, in a DSSE envelope signed with both halves of a
// dual key in this package's own context, beside the sanitised events
// themselves. A verifier recomputes every session's digest from its events,
// so an edited event, a dropped one or a session swapped for another is
// refused, and the envelope says who vouched for the set.

const (
	// Format names the bundle file.
	Format = "aertun/benign-bundle/v1"
	// PredicateType is the Statement's predicate.
	PredicateType = "https://aertun.github.io/benign-bundle/v1"
	// Context is the domain the ML-DSA half signs in and the signer's key
	// id is taken in, so a bundle's signature is never a proof's.
	Context = "aertun/benign-bundle/v1"
)

// FidelitySet is one rule set a capture was checked against, by its rules'
// digests; sessions name it by ID, the digest of the sorted list.
type FidelitySet struct {
	ID    string   `json:"id"`
	Rules []string `json:"rules"`
}

// Manifest is what a bundle says about its sessions.
type Manifest struct {
	// Made is when the bundle was made, and Program the build that made it.
	Made    time.Time `json:"made"`
	Program string    `json:"program,omitempty"`
	// Policy is the sanitising rules' version, and KeyID names the
	// pseudonym key: two bundles' pseudonyms are comparable only under one
	// key.
	Policy string `json:"policy"`
	KeyID  string `json:"key_id"`
	// Sessions are the sessions, by name.
	Sessions []Session `json:"sessions"`
	// Sets are the fidelity checks' rule sets.
	Sets []FidelitySet `json:"fidelity_sets"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Manifest  `json:"predicate"`
}

type file struct {
	Format   string                       `json:"format"`
	Envelope proof.Envelope               `json:"envelope"`
	Events   map[string][]telemetry.Event `json:"events"`
}

// Bundle is an opened, verified bundle.
type Bundle struct {
	Manifest Manifest
	// Events are each session's sanitised events, by name.
	Events map[string][]telemetry.Event
	// Digest names the bundle: the SHA-256 of its signed payload.
	Digest string
	// Signer is the key id that signed it, in Context.
	Signer string
}

// Checked is the set of rule digests a session's fidelity check ran.
func (b *Bundle) Checked(s Session) map[string]bool {
	out := map[string]bool{}
	for _, set := range b.Manifest.Sets {
		if set.ID == s.Fidelity.Set {
			for _, d := range set.Rules {
				out[d] = true
			}
		}
	}
	return out
}

// Live are the sessions that count at t, by name, and those that do not.
func (b *Bundle) Live(t time.Time) (live, expired []Session) {
	for _, s := range b.Manifest.Sessions {
		if s.Expired(t) {
			expired = append(expired, s)
		} else {
			live = append(live, s)
		}
	}
	return live, expired
}

var keyIDShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// check holds a manifest's sessions, sets and events together.
func (m Manifest) check(events map[string][]telemetry.Event) error {
	if m.Policy != PolicyVersion {
		return fmt.Errorf("the bundle was sanitised by %q; this version reads %s", m.Policy, PolicyVersion)
	}
	if !keyIDShape.MatchString(m.KeyID) {
		return fmt.Errorf("the bundle names its pseudonym key by an id")
	}
	if len(m.Sessions) == 0 || len(m.Sessions) > MaxSessions {
		return fmt.Errorf("a bundle holds between 1 and %d sessions", MaxSessions)
	}
	sets := map[string]bool{}
	for _, set := range m.Sets {
		if !sort.StringsAreSorted(set.Rules) || set.ID != SetDigest(set.Rules) || sets[set.ID] {
			return fmt.Errorf("a fidelity set is named by the digest of its sorted rules, once")
		}
		for _, d := range set.Rules {
			if !digestShape.MatchString(d) {
				return fmt.Errorf("a fidelity set lists rules by their digests")
			}
		}
		sets[set.ID] = true
	}
	names := map[string]bool{}
	for _, s := range m.Sessions {
		if err := s.Check(); err != nil {
			return err
		}
		if names[s.Name] {
			return fmt.Errorf("session %s is in the bundle twice", s.Name)
		}
		names[s.Name] = true
		if s.Fidelity.Set != "" && !sets[s.Fidelity.Set] {
			return fmt.Errorf("session %s names a fidelity set the bundle does not carry", s.Name)
		}
		evs, ok := events[s.Name]
		if !ok || len(evs) != s.Events {
			return fmt.Errorf("session %s says it holds %d events and the bundle carries %d", s.Name, s.Events, len(evs))
		}
		d, err := Digest(evs)
		if err != nil {
			return err
		}
		if d != s.Digest {
			return fmt.Errorf("session %s's events are not the ones its digest names", s.Name)
		}
		srcs := map[string]bool{}
		for _, e := range evs {
			srcs[e.Source] = true
		}
		if got := sortedKeys(srcs); fmt.Sprint(got) != fmt.Sprint(s.Sources) {
			return fmt.Errorf("session %s's sources are not the ones its events come from", s.Name)
		}
	}
	if len(events) != len(m.Sessions) {
		return fmt.Errorf("the bundle carries events for a session it does not name")
	}
	return nil
}

func subjects(m Manifest) []subject {
	out := make([]subject, len(m.Sessions))
	for i, s := range m.Sessions {
		out[i] = subject{Name: "benign/" + s.Name, Digest: map[string]string{"sha256": s.Digest}}
	}
	return out
}

// Seal checks a manifest against its events and signs it with both halves
// of k. Sessions are written in name order.
func Seal(m Manifest, events map[string][]telemetry.Event, k *pack.Key) ([]byte, error) {
	sort.Slice(m.Sessions, func(i, j int) bool { return m.Sessions[i].Name < m.Sessions[j].Name })
	sort.Slice(m.Sets, func(i, j int) bool { return m.Sets[i].ID < m.Sets[j].ID })
	m.Made = m.Made.UTC()
	if err := m.check(events); err != nil {
		return nil, fmt.Errorf("refusing to seal: %w", err)
	}
	payload, err := json.Marshal(statement{Type: proof.StatementType, Subject: subjects(m),
		PredicateType: PredicateType, Predicate: m})
	if err != nil {
		return nil, err
	}
	env, err := proof.SealIn(payload, Context, k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(file{Format: Format, Events: events, Envelope: *env})
}

// Read reads a bundle file under MaxBundleBytes and opens it.
func Read(path string, pub pack.KeyPublic) (*Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, MaxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBundleBytes {
		return nil, fmt.Errorf("%s is larger than the %d bytes a bundle may be", path, MaxBundleBytes)
	}
	return Open(body, pub)
}

// Open verifies a bundle's two signatures against pub, decodes its
// statement strictly, and holds every session's events to its digest.
// Expired sessions are opened like the rest; which count is the reader's
// question, asked with Live.
func Open(body []byte, pub pack.KeyPublic) (*Bundle, error) {
	var f file
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("this is not a benign bundle: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("the bundle carries more than one document")
	}
	if f.Format != Format {
		return nil, fmt.Errorf("the file says it is %q; a bundle is %s", f.Format, Format)
	}
	payload, err := proof.OpenIn(&f.Envelope, Context, pub)
	if err != nil {
		return nil, err
	}
	id, err := pack.KeyIDIn(Context, pub)
	if err != nil {
		return nil, err
	}
	var st statement
	sdec := json.NewDecoder(bytes.NewReader(payload))
	sdec.DisallowUnknownFields()
	if err := sdec.Decode(&st); err != nil {
		return nil, fmt.Errorf("the signed statement is not one this version reads: %w", err)
	}
	if st.Type != proof.StatementType || st.PredicateType != PredicateType {
		return nil, fmt.Errorf("the signed statement is not a benign bundle")
	}
	if err := st.Predicate.check(f.Events); err != nil {
		return nil, err
	}
	want := subjects(st.Predicate)
	if len(want) != len(st.Subject) {
		return nil, fmt.Errorf("the statement's subjects are not its sessions")
	}
	for i := range want {
		if want[i].Name != st.Subject[i].Name || want[i].Digest["sha256"] != st.Subject[i].Digest["sha256"] ||
			len(st.Subject[i].Digest) != 1 {
			return nil, fmt.Errorf("the statement's subjects are not its sessions")
		}
	}
	sum := sha256.Sum256(payload)
	return &Bundle{Manifest: st.Predicate, Events: f.Events, Digest: hex.EncodeToString(sum[:]),
		Signer: id}, nil
}
