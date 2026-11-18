// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package repocheck holds the checks that read the whole repository rather
// than one package: that every package is reached by something, that every
// audit record's details are declared, that the documents say what the code
// does, that no other program is named anywhere, and that the signed
// scorecards verify. It has no code of its own, only tests.
package repocheck

import (
	"os"
	"testing"
)

// TestMain runs every check from the repository's root, which is where the
// paths they read are written from.
func TestMain(m *testing.M) {
	if err := os.Chdir("../.."); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
