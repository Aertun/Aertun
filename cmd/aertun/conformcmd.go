// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/aep"
	"github.com/aertun/aertun/spec/aep/v1/vectors"
)

// `aertun conform`: the evidence protocol's test vectors (spec/aep/v1),
// run against this program's verifier or any other. A verifier conforms
// when it accepts every vector marked valid and refuses every other.
//
// Another implementation is run as a command given one vector file per
// run, with no shell between: it must exit 0 exactly when it accepts.

const conformUsage = `usage: aertun conform [--vectors DIR] [--verifier "CMD ARG..."] [--timeout 30s]`

// MaxVector bounds a vector file.
const MaxVector = 1 << 20

func cmdConform(args []string) error {
	fset := flag.NewFlagSet("conform", flag.ContinueOnError)
	dir := fset.String("vectors", "", "a directory of vectors (default: the version 1 vectors built in)")
	verifier := fset.String("verifier", "", "a verifier to run on each vector file, split on spaces, never through a shell")
	timeout := fset.Duration("timeout", 30*time.Second, "how long one run of the verifier may take")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() != 0 {
		return errors.New(conformUsage)
	}
	var files fs.FS = vectors.FS
	if *dir != "" {
		files = os.DirFS(*dir)
	}
	names, err := fs.Glob(files, "*.json")
	if err != nil {
		return err
	}
	sort.Strings(names)
	if len(names) == 0 {
		return errors.New("no vectors (*.json) to run")
	}
	var cmd []string
	if *verifier != "" {
		cmd = strings.Fields(*verifier)
	}
	scratch := ""
	if cmd != nil && *dir == "" {
		// A command reads files, and the built-in vectors are not files.
		if scratch, err = os.MkdirTemp("", "aertun-conform-"); err != nil {
			return err
		}
		defer os.RemoveAll(scratch)
	}
	type row struct {
		Name     string `json:"name"`
		Valid    bool   `json:"valid"`
		Accepted bool   `json:"accepted"`
		Pass     bool   `json:"pass"`
		Detail   string `json:"detail,omitempty"`
	}
	var rows []row
	failed := 0
	for _, name := range names {
		body, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		if len(body) > MaxVector {
			return fmt.Errorf("%s is past %d bytes", name, MaxVector)
		}
		var v aep.Vector
		if err := json.Unmarshal(body, &v); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		var accepted bool
		var detail string
		if cmd == nil {
			err := aep.CheckVector(v)
			accepted = err == nil
			if err != nil {
				detail = err.Error()
			}
		} else {
			path := filepath.Join(*dir, name)
			if scratch != "" {
				path = filepath.Join(scratch, name)
				if err := os.WriteFile(path, body, 0o600); err != nil {
					return err
				}
			}
			accepted, detail = runVerifier(cmd, path, *timeout)
		}
		r := row{Name: name, Valid: v.Valid, Accepted: accepted, Pass: accepted == v.Valid, Detail: detail}
		if !r.Pass {
			failed++
		}
		rows = append(rows, r)
	}
	if !w.JSON(map[string]any{"vectors": rows, "failed": failed}) {
		for _, r := range rows {
			mark := "pass"
			if !r.Pass {
				mark = "FAIL"
			}
			want := "accept"
			if !r.Valid {
				want = "refuse"
			}
			w.Human("%s  %-44s should %s", mark, r.Name, want)
			if !r.Pass && r.Detail != "" {
				w.Human(": %s", r.Detail)
			}
			w.Human("\n")
		}
		w.Human("%d of %d vectors as the protocol requires\n", len(rows)-failed, len(rows))
	}
	if failed > 0 {
		return fmt.Errorf("%d vectors were not decided as the protocol requires", failed)
	}
	return nil
}

// runVerifier runs another implementation on one vector: exit 0 accepts.
func runVerifier(cmd []string, path string, timeout time.Duration) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], append(cmd[1:], path)...)
	out, err := c.CombinedOutput()
	if ctx.Err() != nil {
		return false, "the verifier ran past " + timeout.String()
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return false, err.Error()
	}
	detail := strings.TrimSpace(string(out))
	if len(detail) > 300 {
		detail = detail[:300] + "…"
	}
	return err == nil, detail
}
