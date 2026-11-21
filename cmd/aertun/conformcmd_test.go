// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
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

// TestThePythonVerifierConforms: the standard-library Python verifier in
// verifiers/python decides every vector as the protocol requires, and its
// own tests pass: a second implementation, sharing no code with this one.
func TestThePythonVerifierConforms(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	if w == nil {
		w = out.New(false)
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "verifiers", "python"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdConform([]string{"--verifier", python + " -I " + filepath.Join(dir, "aertun_verify.py")}); err != nil {
		t.Fatalf("the Python verifier does not conform: %v", err)
	}
	cmd := exec.Command(python, "-I", filepath.Join(dir, "test_aertun_verify.py"))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("its own tests: %v\n%s", err, b)
	}
}
