// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package deadletter keeps the records a source's mapping refused, so a
// mapping that broke can be fixed and what it missed read again.
//
// # Why whole records
//
// A mapping usually stops matching because the source changed shape: a
// field renamed, moved or emptied. Keeping only the fields the old mapping
// read would keep exactly the part that no longer helps, and the fixed
// mapping, reading the new name, would find nothing. So a record is kept
// as it arrived, with three things done to it first: any value the secret
// detector recognises is masked, a record over MaxRecord is not kept (it
// is counted), and the store is bounded per source by count and by age.
// A connector's records reach here already cut to the fields its manifest
// declares; a pushed feed's are what the sender sent.
//
// # What is counted
//
// Every refusal is counted by source and day, including the ones not kept,
// and the counts outlive the records, so the source-quality ledger can say
// how much of a day's arrivals a mapping turned away long after the
// records themselves are gone.
package deadletter

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/secret"
)

// Bounds.
const (
	MaxRecord    = 64 << 10
	MaxPerSource = 1000
	MaxAge       = 14 * 24 * time.Hour
	// CountDays is how long the daily counts are kept.
	CountDays = 120
)

// Entry is one refused record.
type Entry struct {
	At      time.Time       `json:"at"`
	Source  string          `json:"source"`
	Missing []string        `json:"missing"`
	Record  json.RawMessage `json:"record"`
}

// Store is the dead letters under one directory.
type Store struct{ Dir string }

type counts struct {
	Source string `json:"source"`
	// Refused counts refusals by UTC day; Kept the records kept; Dropped
	// those not kept or later trimmed.
	Refused map[string]int `json:"refused"`
	Dropped int            `json:"dropped"`
}

func (s Store) base(source string) string {
	sum := sha256.Sum256([]byte(source))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:8]))
}

// mask replaces what the secret detector recognises in every string.
func mask(v any) any {
	switch x := v.(type) {
	case string:
		spans := secret.Spans(x)
		if len(spans) == 0 {
			return x
		}
		var b bytes.Buffer
		at := 0
		for _, sp := range spans {
			b.WriteString(x[at:sp[0]])
			b.WriteString("[secret]")
			at = sp[1]
		}
		b.WriteString(x[at:])
		return b.String()
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = mask(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = mask(e)
		}
		return out
	}
	return v
}

// Refused is one record a mapping turned away, and why.
type Refused struct {
	Record  any
	Missing []string
}

// Add keeps refused records for a source, counts them, and trims the
// source's store to its bounds.
func (s Store) Add(source string, refused []Refused, now time.Time) error {
	if len(refused) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	base := s.base(source)
	unlock, err := atomicfile.Lock(base + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	c, err := s.loadCounts(source)
	if err != nil {
		return err
	}
	entries, err := s.read(base + ".jsonl")
	if err != nil {
		return err
	}
	day := now.UTC().Format("2006-01-02")
	for _, r := range refused {
		c.Refused[day]++
		body, err := json.Marshal(mask(r.Record))
		if err != nil || len(body) > MaxRecord {
			c.Dropped++
			continue
		}
		entries = append(entries, Entry{At: now.UTC(), Source: source, Missing: r.Missing, Record: body})
	}
	// Bounded by age, then by count, oldest first.
	cut := 0
	for cut < len(entries) && now.Sub(entries[cut].At) > MaxAge {
		cut++
	}
	if over := len(entries) - cut - MaxPerSource; over > 0 {
		cut += over
	}
	c.Dropped += cut
	entries = entries[cut:]
	for d := range c.Refused {
		if t, err := time.Parse("2006-01-02", d); err != nil || now.Sub(t) > CountDays*24*time.Hour {
			delete(c.Refused, d)
		}
	}
	if err := s.write(base+".jsonl", entries); err != nil {
		return err
	}
	return s.saveCounts(source, c)
}

func (s Store) loadCounts(source string) (counts, error) {
	c := counts{Source: source, Refused: map[string]int{}}
	b, err := os.ReadFile(s.base(source) + ".json")
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("the dead-letter counts for %s: %w", source, err)
	}
	if c.Source != source {
		return c, fmt.Errorf("the dead-letter counts at %s belong to %s", s.base(source), c.Source)
	}
	if c.Refused == nil {
		c.Refused = map[string]int{}
	}
	return c, nil
}

func (s Store) saveCounts(source string, c counts) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.base(source)+".json", b, 0o600)
}

func (s Store) read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxRecord*2)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func (s Store) write(path string, entries []Entry) error {
	var b bytes.Buffer
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return atomicfile.Write(path, b.Bytes(), 0o600)
}

// Summary is one source's dead letters.
type Summary struct {
	Source  string         `json:"source"`
	Held    int            `json:"held"`
	Dropped int            `json:"dropped"`
	Refused map[string]int `json:"refused"`
	// Missing counts the paths the held records lacked, commonest first.
	Missing []PathCount `json:"missing"`
	Oldest  time.Time   `json:"oldest,omitzero"`
}

// PathCount is a path and how many held records lacked it.
type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// Sources lists every source with dead letters or counts.
func (s Store) Sources() ([]Summary, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Summary
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c counts
		if err := json.Unmarshal(b, &c); err != nil || c.Source == "" {
			return nil, fmt.Errorf("%s is not dead-letter counts", f)
		}
		sum, err := s.Summary(c.Source)
		if err != nil {
			return nil, err
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

// Summary describes one source's dead letters.
func (s Store) Summary(source string) (Summary, error) {
	c, err := s.loadCounts(source)
	if err != nil {
		return Summary{}, err
	}
	entries, err := s.read(s.base(source) + ".jsonl")
	if err != nil {
		return Summary{}, err
	}
	out := Summary{Source: source, Held: len(entries), Dropped: c.Dropped, Refused: c.Refused}
	paths := map[string]int{}
	for i, e := range entries {
		if i == 0 {
			out.Oldest = e.At
		}
		for _, p := range e.Missing {
			paths[p]++
		}
	}
	for p, n := range paths {
		out.Missing = append(out.Missing, PathCount{p, n})
	}
	sort.Slice(out.Missing, func(i, j int) bool {
		if out.Missing[i].Count != out.Missing[j].Count {
			return out.Missing[i].Count > out.Missing[j].Count
		}
		return out.Missing[i].Path < out.Missing[j].Path
	})
	return out, nil
}

// Replay offers every held record of a source to try, which says whether
// it has now been taken; the ones taken are removed and the rest kept.
func (s Store) Replay(source string, try func(Entry) (bool, error)) (taken, left int, err error) {
	base := s.base(source)
	unlock, err := atomicfile.Lock(base + ".lock")
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	entries, err := s.read(base + ".jsonl")
	if err != nil {
		return 0, 0, err
	}
	var keep []Entry
	for i, e := range entries {
		ok, err := try(e)
		if err != nil {
			// Stop where it failed: what was taken is removed, the rest kept.
			keep = append(keep, entries[i:]...)
			if werr := s.write(base+".jsonl", keep); werr != nil {
				return taken, len(keep), werr
			}
			return taken, len(keep), err
		}
		if ok {
			taken++
		} else {
			keep = append(keep, e)
		}
	}
	return taken, len(keep), s.write(base+".jsonl", keep)
}

// Purge removes a source's held records; its counts stay.
func (s Store) Purge(source string) (int, error) {
	base := s.base(source)
	unlock, err := atomicfile.Lock(base + ".lock")
	if err != nil {
		return 0, err
	}
	defer unlock()
	entries, err := s.read(base + ".jsonl")
	if err != nil {
		return 0, err
	}
	return len(entries), s.write(base+".jsonl", nil)
}
