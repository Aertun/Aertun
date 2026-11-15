// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The program is Aertun, and no other program's name is anywhere in it.
//
// The code began inside another product and has been renamed twice since,
// and a name left behind — in a message, a cookie, a test host, a signed
// fixture, a comment — is a sentence that tells somebody the wrong program.
// So every file the repository tracks is read, fixtures included, and none
// may name a product this one was, or one it was written beside.
//
// The names are written as fragments, so this file does not name them
// itself.
func TestNoOtherProgramIsNamedAnywhere(t *testing.T) {
	forbidden := map[string]*regexp.Regexp{
		"the product this code began in": regexp.MustCompile(`(?i)u` + `ilzo`),
		"a name this program retired":    regexp.MustCompile(`(?i)a` + `igil|e` + `roprove`),
		"another product's test host":    regexp.MustCompile(`(?i)\bc` + `ms\.example\b|dot` + `cms`),
	}
	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files: %v", err)
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	if len(files) < 500 {
		t.Fatalf("only %d tracked files; this test is reading the wrong tree", len(files))
	}
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			// Tracked and deleted in the working tree: nothing to read.
			continue
		}
		if bytes.IndexByte(b, 0) >= 0 {
			continue // a picture, a font: not text anybody reads
		}
		for n, line := range strings.Split(string(b), "\n") {
			for what, re := range forbidden {
				if re.MatchString(line) {
					t.Errorf("%s:%d names %s: %.120s", path, n+1, what, strings.TrimSpace(line))
				}
			}
		}
	}
}
