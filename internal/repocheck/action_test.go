// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"regexp"
	"strings"
	"testing"
)

// The GitHub Action runs only a binary it has checked, fetches the names
// the release publishes, and never writes an input into a script: inputs
// reach the shell as environment variables, so an argument with a quote or
// a $( in it is an argument and not a command.
func TestTheActionChecksWhatItRunsAndQuotesWhatItIsGiven(t *testing.T) {
	action := read(t, "action.yml")
	release := read(t, ".github/workflows/release.yml")

	// Every ${{ }} the action has is in an env: or a default, never in a
	// run: script.
	inRun := false
	for n, line := range strings.Split(action, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "run: |"):
			inRun = true
		case inRun && !strings.HasPrefix(line, "        ") && trimmed != "":
			inRun = false
		}
		if inRun && strings.Contains(line, "${{") {
			t.Errorf("action.yml:%d writes an expression into a script: %s", n+1, trimmed)
		}
	}
	for _, step := range []string{"SHA256SUMS", "gh attestation verify", `"$got" != "$want"`,
		"--proto '=https'", `aertun "${args[@]}"`} {
		if !strings.Contains(action, step) {
			t.Errorf("the action does not %s", step)
		}
	}
	// The assets it asks for are the ones the release builds.
	for _, platform := range []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64",
		"windows-amd64", "windows-arm64"} {
		if !strings.Contains(release, "aertun-"+platform) {
			t.Errorf("the release builds no aertun-%s, and the action may ask for it", platform)
		}
	}
	// Its default version is the chart's: one release number in both.
	chart := read(t, "deploy/helm/aertun/Chart.yaml")
	app := regexp.MustCompile(`(?m)^appVersion: "([^"]+)"$`).FindStringSubmatch(chart)
	def := regexp.MustCompile(`(?m)^    default: "([0-9.]+)"$`).FindStringSubmatch(action)
	if app == nil || def == nil || app[1] != def[1] {
		t.Errorf("the action runs %v by default and the chart is %v", def, app)
	}
}
