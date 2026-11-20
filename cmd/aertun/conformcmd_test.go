// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/out"
)

// TestConform: this program's verifier decides every built-in vector as
// the protocol requires; a verifier that accepts everything, or refuses
// everything, is told it does not conform.
func TestConform(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	if err := cmdConform(nil); err != nil {
		t.Fatalf("this program's own verifier: %v", err)
	}
	for _, c := range []string{"true", "false"} {
		path, err := exec.LookPath(c)
		if err != nil {
			t.Skipf("no %s here", c)
		}
		err = cmdConform([]string{"--verifier", path})
		if err == nil || !strings.Contains(err.Error(), "not decided as the protocol requires") {
			t.Errorf("a verifier that is %s about everything conformed: %v", c, err)
		}
	}
	if err := cmdConform([]string{"--vectors", t.TempDir()}); err == nil {
		t.Error("an empty directory of vectors passed")
	}
}
