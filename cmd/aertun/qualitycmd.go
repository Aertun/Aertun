// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/quality"
	"github.com/aertun/aertun/internal/telemetry"
	"github.com/aertun/aertun/internal/upkeep"
)

// `aertun telemetry quality`: the source-quality ledger (internal/quality),
// read from the event store, and the job that turns a newly degraded day
// into an audit record, which the rule aertun.source-quality-degraded reads.
//
// A finished day is by arrival, so it never changes, and is kept once
// measured (quality/days/DATE.json): the store is read only for days not
// yet measured, and today, which is never judged because it is not over.

// MaxQualityDays bounds how far back the ledger looks.
const MaxQualityDays = 120

func qualityDir(root string) string { return filepath.Join(root, "quality") }

// qualityNow is the clock the ledger judges by.
var qualityNow = time.Now

// qualityDays returns the measured days from first to last (inclusive),
// reading the store only for days not kept yet.
func qualityDays(root string, first, last time.Time) ([]quality.Day, error) {
	dir := filepath.Join(qualityDir(root), "days")
	var out []quality.Day
	var missing []time.Time
	for t := first; !t.After(last); t = t.AddDate(0, 0, 1) {
		kept := filepath.Join(dir, quality.DateOf(t)+".json")
		if _, err := os.Stat(kept); err != nil {
			missing = append(missing, t)
			continue
		}
		var days []quality.Day
		if err := loadJSON(kept, &days); err != nil {
			return nil, err
		}
		out = append(out, days...)
	}
	if len(missing) == 0 {
		return out, nil
	}
	sp, err := openSpoolReadOnly(root)
	if err != nil {
		return nil, err
	}
	acc := quality.NewAccumulator()
	from, to := missing[0], missing[len(missing)-1].AddDate(0, 0, 1)
	want := map[string]bool{}
	for _, t := range missing {
		want[quality.DateOf(t)] = true
	}
	if err := sp.Range(from, to, func(e telemetry.Event) error {
		if want[quality.DateOf(e.Received)] {
			acc.Add(e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	byDate := map[string][]quality.Day{}
	for _, d := range acc.Days() {
		byDate[d.Date] = append(byDate[d.Date], d)
	}
	today := quality.DateOf(qualityNow())
	for _, t := range missing {
		date := quality.DateOf(t)
		days := byDate[date]
		if days == nil {
			days = []quality.Day{}
		}
		out = append(out, days...)
		if date < today {
			// Finished, so kept: it can never change.
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, err
			}
			if err := saveJSON(filepath.Join(dir, date+".json"), days); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// judgeQuality judges each source's finished days from first to last
// against the baseline days before each.
func judgeQuality(root string, first, last time.Time, baseline int, only string) ([]quality.Verdict, error) {
	days, err := qualityDays(root, first.AddDate(0, 0, -baseline), last)
	if err != nil {
		return nil, err
	}
	sources := map[string]bool{}
	for _, d := range days {
		sources[d.Source] = true
	}
	var names []string
	for s := range sources {
		if only == "" || s == only {
			names = append(names, s)
		}
	}
	sort.Strings(names)
	var out []quality.Verdict
	for _, s := range names {
		hist, err := quality.History(s, days, quality.DateOf(first.AddDate(0, 0, -baseline)), quality.DateOf(last))
		if err != nil {
			return nil, err
		}
		// Earlier days start where the source first sent anything: a new
		// source is learning, never silent before it existed.
		firstSeen := len(hist)
		for i, d := range hist {
			if d.Events > 0 {
				firstSeen = i
				break
			}
		}
		for i := baseline; i < len(hist); i++ {
			if i < firstSeen {
				continue
			}
			out = append(out, quality.Judge(hist[i], hist[max(i-baseline, firstSeen):i]))
		}
	}
	return out, nil
}

func telemetryQuality(root string, args []string) error {
	fs := flag.NewFlagSet("telemetry quality", flag.ContinueOnError)
	days := fs.Int("days", 7, "how many finished days to judge, ending yesterday")
	baseline := fs.Int("baseline", 14, "how many earlier days each day is judged against")
	source := fs.String("source", "", "one source, every day shown")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *days < 1 || *baseline < quality.MinBaselineDays || *days+*baseline > MaxQualityDays {
		return fmt.Errorf("--days is at least 1, --baseline at least %d, and together at most %d",
			quality.MinBaselineDays, MaxQualityDays)
	}
	yesterday := qualityNow().UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	verdicts, err := judgeQuality(root, yesterday.AddDate(0, 0, -(*days-1)), yesterday, *baseline, *source)
	if err != nil {
		return err
	}
	if *source != "" && len(verdicts) == 0 {
		return fmt.Errorf("nothing from %s in the last %d days", *source, *days+*baseline)
	}
	shown := verdicts
	if *source == "" {
		// The latest day of each source.
		last := map[string]quality.Verdict{}
		for _, v := range verdicts {
			last[v.Source] = v
		}
		shown = nil
		for _, v := range last {
			shown = append(shown, v)
		}
		sort.Slice(shown, func(i, j int) bool { return shown[i].Source < shown[j].Source })
	}
	if w.JSON(map[string]any{"verdicts": shown}) {
		return nil
	}
	if len(shown) == 0 {
		w.Human("nothing has arrived in the last %d days\n", *days+*baseline)
		return nil
	}
	for _, v := range shown {
		label := v.Source
		if *source != "" {
			label = v.Date
		}
		w.Human("%-10s %-32s %6d events (usual %d)\n", v.Status, label, v.Events, v.Usual)
		for _, r := range v.Reasons {
			w.Human("             %s: %s\n", r.Code, r.Detail)
		}
	}
	return nil
}

// qualityJob judges yesterday once a day and records each newly degraded
// source-day in the audit log, where the rule
// aertun.source-quality-degraded finds it.
func qualityJob(root string) upkeep.Job {
	return upkeep.Job{Name: "quality", Do: func(now time.Time) (int, error) {
		return recordDegraded(root, now)
	}}
}

type qualityFlags struct {
	// Recorded is every source-day already put in the audit log.
	Recorded map[string]bool `json:"recorded"`
}

func recordDegraded(root string, now time.Time) (int, error) {
	if _, err := os.Stat(spoolDir(root)); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	yesterday := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -1)
	verdicts, err := judgeQuality(root, yesterday, yesterday, 14, "")
	if err != nil {
		return 0, err
	}
	path := filepath.Join(qualityDir(root), "recorded.json")
	n := 0
	err = atomicfile.Update(path, func(f *qualityFlags) error {
		if f.Recorded == nil {
			f.Recorded = map[string]bool{}
		}
		for _, v := range verdicts {
			key := v.Source + "|" + v.Date
			if v.Status != quality.Degraded || f.Recorded[key] {
				continue
			}
			var codes, details []string
			for _, r := range v.Reasons {
				if r.Degrades {
					codes = append(codes, r.Code)
					details = append(details, r.Detail)
				}
			}
			if err := recordE(root, audit.Record{Action: "source.degraded", Resource: "/sources/" + v.Source,
				Outcome: audit.Failure, Principal: "aertun", Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"source": v.Source, "date": v.Date, "reasons": strings.Join(codes, ","),
					"detail": strings.Join(details, "; "), "events": fmt.Sprint(v.Events), "usual": fmt.Sprint(v.Usual)}}); err != nil {
				return err
			}
			f.Recorded[key] = true
			n++
		}
		return nil
	})
	return n, err
}
