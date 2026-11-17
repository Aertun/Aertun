// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/fetch"
)

// The audit log head, committed to Bitcoin through OpenTimestamps
// calendars: `aertun auditlog anchor` submits, `anchor upgrade` collects
// the block attestations once they exist, and `anchor status` lists them.

func anchorPath(root string) string { return filepath.Join(root, "anchors.json") }

type anchorFile struct {
	Proofs []anchor.Proof `json:"proofs"`
}

func anchorUpgrade(root string, args []string) error {
	fs := flag.NewFlagSet("anchor upgrade", flag.ContinueOnError)
	var explorers multiFlag
	fs.Var(&explorers, "explorer", "an Esplora API to fetch block headers from, such as "+
		"https://blockstream.info/api or a node of your own; given twice or more, these "+
		"replace the three public explorers (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: aertun auditlog anchor upgrade [--explorer URL ...]")
	}
	if len(explorers) == 1 {
		return fmt.Errorf("a header is taken only when two explorers return it, so --explorer " +
			"is given at least twice or not at all")
	}
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
		return err
	}
	if len(file.Proofs) == 0 {
		return fmt.Errorf("nothing has been submitted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sub := httpSubmitter{fetch.For("anchor")}

	var upgraded, waiting, checked int
	for i := range file.Proofs {
		if !file.Proofs[i].Anchored() {
			out, err := anchor.Upgrade(ctx, sub, file.Proofs[i], time.Now())
			if errors.Is(err, anchor.ErrNotYet) {
				waiting++
				continue
			}
			if err != nil {
				w.Human("  %s%s: %v%s\n", yellow, file.Proofs[i].Calendar, err, reset)
				continue
			}
			file.Proofs[i] = out
			if !out.Anchored() {
				continue
			}
			upgraded++
		}
		// A Bitcoin attestation is a height and nothing more: it counts once
		// that block's header, from two explorers, is shown to hold it.
		if _, err := anchor.Confirm(file.Proofs[i]); err == nil {
			continue
		}
		out, b, err := anchor.CheckHeader(ctx, sub, file.Proofs[i], explorers, time.Now())
		if err != nil {
			w.Human("  %s%s: block %d: %v%s\n", yellow, file.Proofs[i].Calendar,
				file.Proofs[i].Height, err, reset)
			continue
		}
		checked++
		file.Proofs[i] = out
		w.Human("  %sanchored%s  %s  block %d, %s, mined %s; header from %s\n", green, reset,
			out.Calendar, b.Height, b.Hash, b.Mined.Format(time.RFC3339),
			strings.Join(out.HeaderFrom, " and "))
	}
	if err := saveJSON(anchorPath(root), file); err != nil {
		return err
	}
	if upgraded == 0 && checked == 0 && waiting > 0 {
		w.Human("  %s%d proof(s) still waiting for a block; commitments take "+
			"hours%s\n", dim, waiting, reset)
	}
	return anchorStatus(root)
}

// httpSubmitter routes calendar traffic through the SSRF-hardened fetcher.
//
// Calendar URLs are configuration, and a pending attestation inside a proof
// names a URL this program later fetches — so one of these addresses arrives
// from a file somebody else produced. That is exactly the case the fetcher's
// connect-time check exists for.
type httpSubmitter struct{ c *fetch.Client }

func anchorStatus(root string) error {
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
		return err
	}
	if w.JSON(file) {
		return nil
	}
	if len(file.Proofs) == 0 {
		w.Human("nothing has been anchored\n")
		w.Human("  %saertun auditlog anchor — commit the log head%s\n", dim, reset)
		w.Human("  %sone hash over the whole log. Nothing about a record or a\n"+
			"  person goes to a public ledger, because a ledger cannot forget.%s\n",
			dim, reset)
		return nil
	}

	for _, p := range file.Proofs {
		state := yellow + string(p.State) + reset
		b, cerr := anchor.Confirm(p)
		switch {
		case cerr == nil:
			state = green + "anchored" + reset
		case p.Anchored():
			state = yellow + "unchecked" + reset
		}
		w.Human("  %-10s %-46s %s\n", state, p.Calendar, short(p.Digest))
		switch {
		case cerr == nil:
			w.Human("             %sBitcoin block %d, %s, mined %s%s\n", dim, b.Height, b.Hash,
				b.Mined.Format(time.RFC3339), reset)
			w.Human("             %sheader from %s, checked %s%s\n", dim,
				strings.Join(p.HeaderFrom, " and "), p.HeaderChecked, reset)
		case p.Anchored():
			w.Human("             %sattests Bitcoin block %d; %v (aertun auditlog anchor upgrade)%s\n",
				dim, p.Height, cerr, reset)
		default:
			w.Human("             %swaiting %s%s\n", dim,
				anchor.Age(p, time.Now()).Round(time.Minute), reset)
		}
	}
	w.Human("\n  %sa block counts once its header, from two explorers, holds the commitment and\n"+
		"  its work is real; look up its hash at its height in any node to check it again,\n"+
		"  or run ots verify on the proof%s\n", dim, reset)
	return nil
}

func (h httpSubmitter) Post(ctx context.Context, url string, body []byte) ([]byte, error) {
	res, err := h.c.Post(ctx, url, body, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func (h httpSubmitter) Get(ctx context.Context, url string) ([]byte, error) {
	res, err := h.c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}
