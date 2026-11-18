// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package repocheck

import (
	"encoding/json"
	"encoding/xml"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The Wazuh integration kit (integrations/wazuh) is checked here as code is:
// its rules parse and stay in their range, every rule is exercised by a case
// whose log is a real sample, the audit actions they match are ones this
// program still writes, the loop guard holds, the README follows Wazuh's
// template with its provenance, and the scripts compile.

type wazuhRule struct {
	ID       string `xml:"id,attr"`
	Level    string `xml:"level,attr"`
	IfSID    string `xml:"if_sid"`
	IfMatch  string `xml:"if_matched_sid"`
	Action   string `xml:"action"`
	Desc     string `xml:"description"`
	Frequent string `xml:"frequency,attr"`
}

func wazuhRules(t *testing.T) []wazuhRule {
	t.Helper()
	var g struct {
		Rules []wazuhRule `xml:"rule"`
	}
	if err := xml.Unmarshal([]byte(read(t, "integrations/wazuh/ruleset/rules/aertun_rules.xml")), &g); err != nil {
		t.Fatalf("aertun_rules.xml does not parse: %v", err)
	}
	if len(g.Rules) < 10 {
		t.Fatalf("only %d rules read", len(g.Rules))
	}
	return g.Rules
}

func TestTheWazuhRulesStayInTheirRangeAndHangFromTheirParent(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range wazuhRules(t) {
		n, err := strconv.Atoi(r.ID)
		if err != nil || n < 998000 || n > 998099 {
			t.Errorf("rule %q is outside 998000-998099", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("rule %s is defined twice", r.ID)
		}
		seen[r.ID] = true
		if r.ID != "998000" && r.IfSID != "998000" && r.IfMatch == "" {
			t.Errorf("rule %s does not hang from 998000: it would match other JSON logs", r.ID)
		}
		if strings.TrimSpace(r.Desc) == "" {
			t.Errorf("rule %s has no description", r.ID)
		}
	}
}

// The sealing rule raises nothing: an alert on a seal would be sent back to
// Aertun and sealed again, without end.
func TestTheWazuhSealingRuleCannotFeedBack(t *testing.T) {
	for _, r := range wazuhRules(t) {
		if strings.Contains(r.Action, `alert\.sealed`) && r.Level != "0" {
			t.Fatalf("rule %s raises an alert at level %s on a seal; every sealed alert would come back", r.ID, r.Level)
		}
	}
	if !strings.Contains(read(t, "integrations/wazuh/README.md"), "<level>3</level>") {
		t.Error("the README's integration block no longer names the level the loop guard is set against")
	}
}

// Every exact action a rule matches is one this program still writes, so a
// rename here fails a test rather than a customer's alerting.
func TestTheWazuhRulesMatchActionsThisProgramWrites(t *testing.T) {
	exact := regexp.MustCompile(`^\^([a-z_.\\]+)\$$`)
	alternation := regexp.MustCompile(`^\^([a-z_]+)\\\.\(([a-z_|]+)\)\$$`)
	out, err := exec.Command("git", "grep", "-h", "-o", "-E", `"[a-z_]+(\.[a-z_]+)+"`, "--", "*.go").Output()
	if err != nil {
		t.Skipf("git grep: %v", err)
	}
	written := map[string]bool{}
	for _, s := range strings.Fields(string(out)) {
		written[strings.Trim(s, `"`)] = true
	}
	for _, r := range wazuhRules(t) {
		var actions []string
		if m := exact.FindStringSubmatch(r.Action); m != nil {
			actions = []string{strings.ReplaceAll(m[1], `\`, "")}
		} else if m := alternation.FindStringSubmatch(r.Action); m != nil {
			for _, tail := range strings.Split(m[2], "|") {
				actions = append(actions, m[1]+"."+tail)
			}
		}
		for _, a := range actions {
			if !written[a] {
				t.Errorf("rule %s matches action %q, which nothing in this program writes", r.ID, a)
			}
		}
	}
}

func TestEveryWazuhRuleHasACaseOnARealSample(t *testing.T) {
	samples := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(read(t, "integrations/wazuh/sample_logs.txt")), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("a sample is not JSON: %v", err)
		}
		for _, k := range []string{"seq", "hash", "action", "outcome", "principal"} {
			if _, ok := e[k]; !ok {
				t.Fatalf("a sample has no %q: it is not an audit entry", k)
			}
		}
		samples[line] = true
	}
	expected := map[string]bool{}
	for _, line := range strings.Split(read(t, "integrations/wazuh/aertun.ini"), "\n") {
		if v, ok := strings.CutPrefix(line, "rule = "); ok {
			expected[v] = true
		}
		if strings.HasPrefix(line, "log ") {
			_, log, _ := strings.Cut(line, " pass = ")
			if !samples[log] {
				t.Errorf("a case's log is not in sample_logs.txt: %.80s", log)
			}
		}
	}
	for _, r := range wazuhRules(t) {
		if !expected[r.ID] {
			t.Errorf("rule %s has no case in aertun.ini", r.ID)
		}
	}
}

func TestTheWazuhReadmeFollowsTheirTemplate(t *testing.T) {
	readme := read(t, "integrations/wazuh/README.md")
	for _, heading := range []string{"# Aertun-Wazuh Integration", "### Introduction", "### Prerequisites",
		"### Installation and Configuration", "#### Using the Integration Files", "### Integration Steps",
		"### Integration Testing", "### Sources", "## Provenance and Maintenance",
		"**Original source:**", "**Adapted by:**", "**Tested versions:**", "**Maintainer:**",
		"**Support boundary:**"} {
		if !strings.Contains(readme, heading) {
			t.Errorf("the README has no %q", heading)
		}
	}
}

func TestTheWazuhScriptsCompile(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	for _, f := range []string{"integrations/wazuh/custom-aertun.py", "integrations/wazuh/check_rules.py"} {
		// Compiled to nowhere: the check is the parse, and no cache is
		// written into the tree.
		code := "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')"
		if out, err := exec.Command(python, "-c", code, f).CombinedOutput(); err != nil {
			t.Errorf("%s does not compile: %v\n%s", f, err, out)
		}
	}
}
