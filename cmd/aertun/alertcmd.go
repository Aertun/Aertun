// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/seal"
)

// `aertun alert seal`: alerts from any monitor committed to the audit log by
// their digests, so that "this alert existed before then" is a claim
// `aertun proof sealed` can check (internal/seal). One audit entry per batch
// carries the batch's Merkle root and size; the digests are kept beside the
// store by that root, and the alerts themselves are not kept at all.
//
// A detection run seals the findings it raises the same way, in its own
// entry (sealFindings), as the alert findingAlert makes of each.

func cmdAlert(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("alert needs seal: `aertun alert seal FILE` commits alerts, one JSON " +
			"object per line, and `aertun alert seal --list` lists what was sealed")
	}
	switch args[0] {
	case "seal":
		return alertSeal(root, args[1:])
	default:
		return fmt.Errorf("unknown alert command %q; try seal", args[0])
	}
}

func alertSeal(root string, args []string) error {
	fs := flag.NewFlagSet("alert seal", flag.ContinueOnError)
	list := fs.Bool("list", false, "list the batches the audit log records sealing, instead of sealing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		if fs.NArg() != 0 {
			return fmt.Errorf("alert seal --list takes nothing else: it lists every batch")
		}
		return alertList(root)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("alert seal takes one FILE of alerts, one JSON object per line, or - " +
			"to read them from standard input")
	}
	var in io.Reader = os.Stdin
	if at := fs.Arg(0); at != "-" {
		f, err := os.Open(at)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	digests, read, err := seal.Read(in)
	if err != nil {
		return err
	}
	b, err := seal.NewBatch(digests)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	dir := seal.Dir(root)
	existed, err := seal.Save(dir, b)
	if err != nil {
		return err
	}
	// The entry is the seal: a batch kept without one commits nothing, so
	// it is taken back when the entry is refused — unless it was kept
	// before, for an entry already written.
	if err := recordE(root, caller.auditRecord(seal.ActionSealed, "/alerts", audit.Success,
		seal.Detail(b))); err != nil {
		if !existed {
			_ = seal.Remove(dir, b.Root)
		}
		return err
	}
	if w.JSON(map[string]any{"root": b.Root, "sealed": len(b.Digests), "read": read}) {
		return nil
	}
	w.Human("%ssealed %d alert(s)%s in one audit entry, under Merkle root %s\n",
		bold, len(b.Digests), reset, b.Root)
	if read > len(b.Digests) {
		w.Human("  %s%d line(s) repeated an alert already in the batch%s\n", dim, read-len(b.Digests), reset)
	}
	w.Human("  %sthe entry's time is the log's own word until a head that covers it is anchored:%s\n",
		dim, reset)
	w.Human("    %saertun auditlog anchor%s\n", dim, reset)
	w.Human("  %sthen, for any one of them: aertun proof sealed --alert FILE --key F%s\n", dim, reset)
	return nil
}

// alertList lists the batches the audit log records sealing, and whether
// the digests for each are kept here. A listing, not a proof: it does not
// verify the log, which `proof sealed` does.
func alertList(root string) error {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	type row struct {
		Entry  int64  `json:"entry"`
		At     string `json:"at"`
		By     string `json:"by"`
		Root   string `json:"root"`
		Alerts int    `json:"alerts"`
		Kept   bool   `json:"kept"`
	}
	rows := []row{}
	for _, c := range seal.Commits(events) {
		kept := false
		if b, err := seal.Load(seal.Dir(root), c.Root); err == nil && len(b.Digests) == c.Count {
			again, err := seal.NewBatch(b.Digests)
			kept = err == nil && again.Root == c.Root
		}
		rows = append(rows, row{Entry: c.Seq, At: c.At, By: events[c.Index].Action, Root: c.Root,
			Alerts: c.Count, Kept: kept})
	}
	if w.JSON(map[string]any{"batches": rows}) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("nothing has been sealed\n")
		w.Human("  %saertun alert seal FILE — alerts from any monitor, one JSON object per line%s\n", dim, reset)
		return nil
	}
	for _, r := range rows {
		note := ""
		if !r.Kept {
			note = yellow + "  its digests are not kept here, so none of them can be proved" + reset
		}
		w.Human("  entry %-7d %s  %-12s %6d alert(s)  %s…%s\n", r.Entry, r.At, r.By, r.Alerts, r.Root[:16], note)
	}
	w.Human("\n  %sa listing, not a proof: aertun proof sealed checks one alert against the verified\n"+
		"  log and the heads anchored since%s\n", dim, reset)
	return nil
}

// findingAlert is the alert a finding is sealed as when a detection run
// raises it: what names it and when it was first seen, and nothing a person
// changes while working it — not its state, owner, severity or evidence —
// so the same bytes are made again from the register for as long as the
// finding is kept (proof sealed --finding).
func findingAlert(f finding.Finding) []byte {
	b, _ := json.Marshal(struct {
		Finding string `json:"aertun_finding"`
		Kind    string `json:"kind"`
		Source  string `json:"source"`
		Entity  string `json:"entity"`
		First   string `json:"first"`
	}{f.ID, string(f.Kind), f.Source, f.Entity.Issuer + ":" + f.Entity.Value,
		f.First.UTC().Format(time.RFC3339Nano)})
	return b
}

// sealFindings seals the findings a detection run raised and returns what
// the run's own audit entry carries to commit them. The run's entry is the
// one place every pass already writes, so sealing costs a digest per new
// finding and one file, and adds no entry — an entry of its own would wake
// the self-watch that reruns the detections on what the log gained
// (selfLogGrew). Nothing is returned when nothing was raised, or when the
// batch could not be kept: said, and never fatal, because a seal is not a
// reason to lose a detection run. A pass raising more than a batch holds
// seals the first batch's worth; the run's entry then says how many it
// sealed beside how many it opened.
func sealFindings(root string, raised []finding.Finding) map[string]string {
	var digests []string
	seen := map[string]bool{}
	for _, f := range raised {
		if len(digests) == seal.MaxBatch {
			break
		}
		d, err := seal.Digest(findingAlert(f))
		if err != nil || seen[d] {
			continue
		}
		seen[d] = true
		digests = append(digests, d)
	}
	if len(digests) == 0 {
		return nil
	}
	b, err := seal.NewBatch(digests)
	if err == nil {
		_, err = seal.Save(seal.Dir(root), b)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sthe findings this run raised were not sealed: %v%s\n", yellow, err, reset)
		return nil
	}
	return seal.Detail(b)
}
