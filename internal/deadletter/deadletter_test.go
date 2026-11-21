// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package deadletter

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func rec(i int) Refused {
	return Refused{Record: map[string]any{"uuid": fmt.Sprint("e", i), "actor": map[string]any{"uuid": "00u1"}},
		Missing: []string{"actor.id"}}
}

func TestAddSummaryReplay(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	var batch []Refused
	for i := range 5 {
		batch = append(batch, rec(i))
	}
	if err := s.Add("okta/system", batch, t0); err != nil {
		t.Fatal(err)
	}
	sum, err := s.Summary("okta/system")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Held != 5 || sum.Refused["2026-11-20"] != 5 || len(sum.Missing) != 1 || sum.Missing[0].Count != 5 {
		t.Errorf("%+v", sum)
	}
	all, _ := s.Sources()
	if len(all) != 1 || all[0].Source != "okta/system" {
		t.Errorf("%+v", all)
	}
	// The fixed mapping takes the even ones.
	taken, left, err := s.Replay("okta/system", func(e Entry) (bool, error) {
		return strings.Contains(string(e.Record), `"e0"`) || strings.Contains(string(e.Record), `"e2"`) ||
			strings.Contains(string(e.Record), `"e4"`), nil
	})
	if err != nil || taken != 3 || left != 2 {
		t.Fatalf("%v %d %d", err, taken, left)
	}
	// A failure part way keeps what was not yet tried.
	n := 0
	taken, left, err = s.Replay("okta/system", func(e Entry) (bool, error) {
		if n++; n == 2 {
			return false, errors.New("the store refused")
		}
		return true, nil
	})
	if err == nil || taken != 1 || left != 1 {
		t.Errorf("%v %d %d", err, taken, left)
	}
	if sum, _ = s.Summary("okta/system"); sum.Held != 1 || sum.Refused["2026-11-20"] != 5 {
		t.Errorf("the counts outlive the records: %+v", sum)
	}
	if n, err := s.Purge("okta/system"); err != nil || n != 1 {
		t.Errorf("purge: %v %d", err, n)
	}
}

func TestBounds(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	var batch []Refused
	for i := range MaxPerSource + 10 {
		batch = append(batch, rec(i))
	}
	big := Refused{Record: map[string]any{"blob": strings.Repeat("x", MaxRecord)}}
	batch = append(batch, big)
	if err := s.Add("src", batch, t0); err != nil {
		t.Fatal(err)
	}
	sum, _ := s.Summary("src")
	if sum.Held != MaxPerSource || sum.Dropped != 11 || sum.Refused["2026-11-20"] != MaxPerSource+11 {
		t.Errorf("held %d dropped %d refused %d", sum.Held, sum.Dropped, sum.Refused["2026-11-20"])
	}
	// Two weeks on, the old ones age out and the counts remain.
	if err := s.Add("src", []Refused{rec(0)}, t0.Add(MaxAge+time.Hour)); err != nil {
		t.Fatal(err)
	}
	sum, _ = s.Summary("src")
	if sum.Held != 1 || sum.Refused["2026-11-20"] != MaxPerSource+11 {
		t.Errorf("after aging: held %d, counts %v", sum.Held, sum.Refused)
	}
}

func TestSecretsAreMaskedAndFilesPrivate(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	if err := s.Add("aws/cloudtrail", []Refused{{Record: map[string]any{"note": "key " + key + " used"}}}, t0); err != nil {
		t.Fatal(err)
	}
	var held string
	s.Replay("aws/cloudtrail", func(e Entry) (bool, error) { held = string(e.Record); return false, nil })
	if strings.Contains(held, key) || !strings.Contains(held, "[secret]") {
		t.Errorf("held: %s", held)
	}
	entries, _ := os.ReadDir(s.Dir)
	for _, e := range entries {
		if info, _ := e.Info(); info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is %v", e.Name(), info.Mode().Perm())
		}
	}
}
