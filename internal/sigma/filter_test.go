// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/telemetry"
)

const compressRule = `title: Data Compressed - rar.exe
id: 6f3e2987-db24-4c78-a860-b4f4095a7095
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rar.exe'
    condition: selection
level: medium
`

const otherSource = `title: Something on Linux
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/rar'
    condition: selection
level: medium
`

// The specification's own example, with this reader's lifecycle keys.
func filterDoc(extra string) string {
	return `title: Filter Administrator account
description: The valid administrator account start with adm_
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 6f3e2987-db24-4c78-a860-b4f4095a7095
        - df0841c0-9846-4e9f-ad8a-7df91571771b
    selection:
        User|startswith: 'adm_'
    condition: selection
` + extra
}

func matches(t *testing.T, r detect.Rule, raw map[string]string) bool {
	t.Helper()
	p, err := r.Compile()
	if err != nil {
		t.Fatal(err)
	}
	e := telemetry.Event{Source: r.Sources[0], Raw: raw}
	return p.MatchesFields(e.Source, e.Fields())
}

var filterNow = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// A filter is added to the rules it names, as "and not", where the log
// source is the same; the rule without it is kept for comparison; a named
// rule nothing answers to is reported.
func TestAFilterTunesTheRulesItNames(t *testing.T) {
	rep := Import(map[string][]byte{"compress.yml": []byte(compressRule), "linux.yml": []byte(otherSource),
		"mf_admins.yml": []byte(filterDoc("expires: 2027-01-31\nowner: dana\nticket: CHG-77\n"))},
		Pipeline{Now: filterNow})
	if len(rep.Rules) != 2 || len(rep.Filters) != 1 || len(rep.Skipped) != 0 {
		t.Fatalf("%+v", rep)
	}
	f := rep.Filters[0]
	if strings.Join(f.Applied, ",") != "6f3e2987-db24-4c78-a860-b4f4095a7095" || f.Expired || f.NoExpiry ||
		strings.Join(f.Unmatched, ",") != "df0841c0-9846-4e9f-ad8a-7df91571771b" || f.Owner != "dana" {
		t.Errorf("%+v", f)
	}
	var filtered, bare detect.Rule
	for i, r := range rep.Rules {
		if strings.HasPrefix(r.ID, "6f3e") {
			filtered, bare = r, rep.Bare[i]
		}
	}
	admin := map[string]string{"Image": `C:\tools\rar.exe`, "User": "adm_dana"}
	user := map[string]string{"Image": `C:\tools\rar.exe`, "User": "sam"}
	if matches(t, filtered, admin) || !matches(t, filtered, user) {
		t.Error("the filter did not take out the administrator, or took out everybody")
	}
	if !matches(t, bare, admin) {
		t.Error("the rule kept without its filters is filtered")
	}
}

// An expired filter is not applied, and says so; one that never expires
// is applied and counted as such; "rules: any" tunes every rule with its
// log source and no other.
func TestAFilterPastItsExpiryIsNotApplied(t *testing.T) {
	rep := Import(map[string][]byte{"compress.yml": []byte(compressRule),
		"mf_admins.yml": []byte(filterDoc("expires: 2026-10-01\n"))}, Pipeline{Now: filterNow})
	if !rep.Filters[0].Expired || len(rep.Filters[0].Applied) != 0 {
		t.Fatalf("%+v", rep.Filters[0])
	}
	if !matches(t, rep.Rules[0], map[string]string{"Image": `C:\rar.exe`, "User": "adm_dana"}) {
		t.Error("an expired filter still tuned the rule")
	}
	anyDoc := strings.Replace(filterDoc(""), "    rules:\n        - 6f3e2987-db24-4c78-a860-b4f4095a7095\n        - df0841c0-9846-4e9f-ad8a-7df91571771b\n", "    rules: any\n", 1)
	rep = Import(map[string][]byte{"compress.yml": []byte(compressRule), "linux.yml": []byte(otherSource),
		"mf_any.yml": []byte(anyDoc)}, Pipeline{Now: filterNow})
	f := rep.Filters[0]
	if !f.Any || !f.NoExpiry || len(f.Applied) != 1 || f.Applied[0] != "6f3e2987-db24-4c78-a860-b4f4095a7095" {
		t.Errorf("%+v", f)
	}
}

func TestAFilterIsReadStrictly(t *testing.T) {
	for doc, want := range map[string]string{
		strings.Replace(filterDoc(""), "logsource:\n    category: process_creation\n    product: windows\n", "", 1): "log source",
		strings.Replace(filterDoc(""), "    condition: selection\n", "", 1):                                         "condition",
		filterDoc("expires: next quarter\n"):                                                                        "expires",
	} {
		if _, _, err := ReadAll([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v, want %q", err, want)
		}
	}
	// A rules-only reader passes over a filter instead of calling it a
	// malformed rule.
	if rules, err := Read([]byte(filterDoc(""))); err != nil || len(rules) != 0 {
		t.Errorf("%v %v", rules, err)
	}
}
