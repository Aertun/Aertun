// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"strings"
	"testing"
)

const refCommit = "46bee3dea75ef53a8eae49f3b7487e6341de6074"

func heldReport() RefereeEvidence {
	return RefereeEvidence{Package: "pkg:npm/tiny-parse@2.1.0", Commit: refCommit, Head: refCommit,
		Declared: "2.1.0", Introduced: "2.0.0", Fixed: "2.1.1", CWE: "CWE-1333",
		Locations: []RefereeLocation{{File: dig("lib/header.js"), Function: dig("parseHeader"), Line: 3,
			Language: "javascript", Found: PlaceDefined}},
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", Score: 7.5, Severity: "high",
		Fingerprint: dig("flaw")}
}

func refereeOf(t *testing.T, ev RefereeEvidence) *Statement {
	t.Helper()
	st, err := ProveReferee(RefereeInput{Report: []byte("report"), Evidence: ev, Program: "test", Now: tnow})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRangeAndSeverityAreComputedNotTaken(t *testing.T) {
	for _, c := range []struct{ v, in, fix, want string }{
		{"2.1.0", "2.0.0", "2.1.1", RangeInside}, {"2.1.1", "2.0.0", "2.1.1", RangeOutside},
		{"1.9.0", "2.0.0", "", RangeOutside}, {"9.0.0", "", "", RangeInside},
		{"2.1.0", "2.2.0", "2.1.0", RangeInverted}, {"2.1.0", "2.0.0", "2.1.x", RangeUnordered},
	} {
		if got := RangeOf(c.v, c.in, c.fix); got != c.want {
			t.Errorf("%s in [%s, %s): %s, want %s", c.v, c.in, c.fix, got, c.want)
		}
	}
	for score, want := range map[float64]string{0: "none", 3.9: "low", 4: "medium", 6.9: "medium", 7: "high",
		8.9: "high", 9: "critical", 10: "critical"} {
		if SeverityOf(score) != want {
			t.Errorf("%.1f is %s", score, SeverityOf(score))
		}
	}
}

func TestAReportWhoseClaimsHoldIsProven(t *testing.T) {
	st := refereeOf(t, heldReport())
	if st.Predicate.Verdict != Proven {
		t.Fatalf("%s: %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
	b, _ := jsonOf(st)
	for _, word := range []string{"lib/header.js", "parseHeader"} {
		if strings.Contains(b, word) {
			t.Errorf("the proof carries the report's %q", word)
		}
	}
}

func TestEachWayAReportFallsDown(t *testing.T) {
	for name, c := range map[string]struct {
		edit  func(*RefereeEvidence)
		check string
		want  Verdict
	}{
		"a function that is not there": {func(ev *RefereeEvidence) { ev.Locations[0].Found = PlaceNotDefined }, "locations", Refuted},
		"a file from another project":  {func(ev *RefereeEvidence) { ev.Locations[0].Found = PlaceNoFile }, "locations", Refuted},
		"a line past the end":          {func(ev *RefereeEvidence) { ev.Locations[0].Found = PlacePastEnd }, "locations", Refuted},
		"another version declared":     {func(ev *RefereeEvidence) { ev.Declared = "2.0.9" }, "at-commit", Refuted},
		"outside its own range":        {func(ev *RefereeEvidence) { ev.Fixed = "2.1.0" }, "range", Refuted},
		"an inverted range":            {func(ev *RefereeEvidence) { ev.Introduced, ev.Fixed = "3.0.0", "2.2.0" }, "range", Refuted},
		"a score its vector does not give": {func(ev *RefereeEvidence) { ev.Score, ev.Severity = 9.8, "critical" },
			"severity", Refuted},
		"a severity its score is not": {func(ev *RefereeEvidence) { ev.Severity = "critical" }, "severity", Refuted},
		"a duplicate": {func(ev *RefereeEvidence) {
			ev.Duplicates = []RefereeEarlier{{Report: dig("first"), Seq: 4, At: "2026-11-01T09:00:00Z"}}
		}, "unique", Refuted},
		// Not held against the report: the checkout is not at its commit.
		"a checkout elsewhere": {func(ev *RefereeEvidence) {
			ev.Head = "0000000000000000000000000000000000000000"
			ev.Locations[0].Found = PlaceNoFile
			ev.Declared = "1.0.0"
		}, "locations", Inconclusive},
		"no checkout at all":           {func(ev *RefereeEvidence) { ev.Head = "" }, "at-commit", Inconclusive},
		"a CVSS 4 vector":              {func(ev *RefereeEvidence) { ev.Vector = "CVSS:4.0/AV:N/AC:L" }, "severity", Inconclusive},
		"a language not read":          {func(ev *RefereeEvidence) { ev.Locations[0].Language, ev.Locations[0].Found = "unknown", PlaceMentioned }, "locations", Inconclusive},
		"an asset that never names it": {func(ev *RefereeEvidence) { ev.Reach = "not-referenced" }, "reach", Inconclusive},
		"an asset that names it":       {func(ev *RefereeEvidence) { ev.Reach = "referenced" }, "reach", Proven},
	} {
		ev := heldReport()
		c.edit(&ev)
		st := refereeOf(t, ev)
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s", name, st.Predicate.Verdict, c.want)
		}
		for _, chk := range st.Predicate.Checks {
			if chk.Name == c.check && (chk.Passed == (c.want == Refuted)) {
				t.Errorf("%s: check %s passed %v", name, chk.Name, chk.Passed)
			}
		}
	}
}

func TestACommittedReportNamesItsEntryAndOnlyEarlierDuplicates(t *testing.T) {
	ev := heldReport()
	ev.Committed = &AuditEntry{Seq: 9, Hash: dig("entry"), At: "2026-11-02T10:00:00Z"}
	st := refereeOf(t, ev)
	if !strings.Contains(st.Predicate.Checks[5].Detail, "entry 9") {
		t.Fatalf("priority: %+v", st.Predicate.Checks[5])
	}
	ev.Duplicates = []RefereeEarlier{{Report: dig("later"), Seq: 12, At: "2026-11-03T10:00:00Z"}}
	if _, err := ProveReferee(RefereeInput{Report: []byte("r"), Evidence: ev, Now: tnow}); err == nil {
		t.Error("a report recorded after this one was committed is called an earlier one")
	}
}

func TestAnEditedRefereeProofIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*RefereeEvidence, *Statement){
		"a place found":        func(ev *RefereeEvidence, _ *Statement) { ev.Locations[0].Found = PlaceNoFile },
		"a path as text":       func(ev *RefereeEvidence, _ *Statement) { ev.Locations[0].File = "lib/header.js" },
		"a word made up":       func(ev *RefereeEvidence, _ *Statement) { ev.Locations[0].Found = "close-enough" },
		"defined, unread":      func(ev *RefereeEvidence, _ *Statement) { ev.Locations[0].Language = "unknown" },
		"mentioned, read":      func(ev *RefereeEvidence, _ *Statement) { ev.Locations[0].Found = PlaceMentioned },
		"the range word":       func(ev *RefereeEvidence, _ *Statement) { ev.Range = RangeOutside },
		"the score":            func(ev *RefereeEvidence, _ *Statement) { ev.Score = 9.8 },
		"a vector of no shape": func(ev *RefereeEvidence, _ *Statement) { ev.Vector = "CVSS:3.1/AV:N" },
		"the head":             func(ev *RefereeEvidence, _ *Statement) { ev.Head = "main" },
		"a duplicate hidden":   func(ev *RefereeEvidence, _ *Statement) { ev.Fingerprint = "x" },
		"the reach word":       func(ev *RefereeEvidence, _ *Statement) { ev.Reach = "probably" },
		"the purl":             func(ev *RefereeEvidence, _ *Statement) { ev.Package = "tiny-parse 2.1.0" },
		"the claim":            func(_ *RefereeEvidence, s *Statement) { s.Predicate.Claim += " It is critical." },
		"the verdict":          func(_ *RefereeEvidence, s *Statement) { s.Predicate.Verdict = Inconclusive },
		"a check":              func(_ *RefereeEvidence, s *Statement) { s.Predicate.Checks[0].Detail = "fine" },
		"the subject":          func(_ *RefereeEvidence, s *Statement) { s.Subject[0].Name = "report.json" },
		"a material": func(_ *RefereeEvidence, s *Statement) {
			s.Predicate.Materials = []Material{{Name: "poc", Digest: SHA256(nil)}}
		},
	} {
		st := refereeOf(t, heldReport())
		edit(st.Predicate.Referee, st)
		if err := st.Validate(); err == nil {
			t.Errorf("%s: the edited proof validates", name)
		}
	}
}

// A forger who edits the evidence and rebuilds the claim, the checks and the
// verdict from it meets the evidence's own shapes.
func TestARefereeForgeryThatRebuildsItsWordsIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*RefereeEvidence){
		"the range word":       func(ev *RefereeEvidence) { ev.Range = RangeOutside },
		"a vector of no shape": func(ev *RefereeEvidence) { ev.Vector = "CVSS:3.1/AV:N" },
		"a purl with prose": func(ev *RefereeEvidence) {
			ev.Package = "tiny-parse, which is critical@2.1.0"
		},
		"a short commit": func(ev *RefereeEvidence) { ev.Commit = "46bee3d" },
		"a head by name": func(ev *RefereeEvidence) { ev.Head = "main" },
		"a reach word":   func(ev *RefereeEvidence) { ev.Reach = "probably" },
	} {
		st := refereeOf(t, heldReport())
		ev := st.Predicate.Referee
		edit(ev)
		st.Predicate.Claim, st.Predicate.Checks, st.Predicate.Verdict = ev.claim(), ev.checks(), ev.verdict()
		if err := st.Validate(); err == nil {
			t.Errorf("%s: the rebuilt forgery validates", name)
		}
	}
}
