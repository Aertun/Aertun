// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/telemetry"
)

// The rules are the reference pack's own, so a technique is proven or
// refuted against rules that ship rather than ones shaped for the test.
func packRule(t *testing.T, id string) CoverageRule {
	t.Helper()
	b, err := os.ReadFile("../detect/pack/" + id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var r detect.Rule
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return CoverageRule{Rule: r, File: b}
}

// reTagged is a pack rule claiming other techniques, as a file of its own.
func reTagged(t *testing.T, id string, techniques ...string) CoverageRule {
	t.Helper()
	cr := packRule(t, id)
	cr.Rule.Technique = techniques
	b, err := json.Marshal(cr.Rule)
	if err != nil {
		t.Fatal(err)
	}
	cr.File = b
	return cr
}

func failedSignin() telemetry.Event {
	var e telemetry.Event
	body := `{"source":"okta/system","time":"2026-10-01T09:00:00Z","received":"2026-10-01T09:00:03Z",` +
		`"class":3002,"disposition":4,"actor":{"issuer":"okta","value":"00u9"},"message":"user.session.start",` +
		`"raw":{"eventType":"user.session.start","person":"lee@acme.com"}}`
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		panic(err)
	}
	return e
}

func attack(name, eventType string, techniques ...string) detect.Labelled {
	return detect.Labelled{Name: name, Event: oktaEvent(eventType), Techniques: techniques}
}

func benign(name, eventType string) detect.Labelled {
	return detect.Labelled{Name: name, Event: oktaEvent(eventType)}
}

func coverageOf(t *testing.T, rules []CoverageRule, entries []detect.Labelled, edit func(*CoverageInput)) *Statement {
	t.Helper()
	st, err := tryCoverage(t, rules, entries, edit)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func tryCoverage(t *testing.T, rules []CoverageRule, entries []detect.Labelled, edit func(*CoverageInput)) (*Statement, error) {
	t.Helper()
	corpus := corpusOf(t, entries...)
	parsed, err := detect.ParseCorpus(strings.NewReader(string(corpus)))
	if err != nil {
		t.Fatal(err)
	}
	in := CoverageInput{Rules: rules, CorpusName: "corpus.jsonl", Corpus: corpus, Entries: parsed,
		MinPositives: 1, MinBenign: 1, Program: "test", Now: tnow}
	if edit != nil {
		edit(&in)
	}
	return ProveCoverage(in)
}

func row(t *testing.T, st *Statement, technique string) TechniqueCoverage {
	t.Helper()
	for _, r := range st.Predicate.Coverage.Techniques {
		if r.Technique == technique {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", technique, st.Predicate.Coverage.Techniques)
	return TechniqueCoverage{}
}

func checkNamed(st *Statement, name string) Check {
	for _, c := range st.Predicate.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

func twoRules(t *testing.T) []CoverageRule {
	return []CoverageRule{packRule(t, "okta.mfa-reset"), packRule(t, "okta.admin-privilege-granted")}
}

func goodEntries() []detect.Labelled {
	return []detect.Labelled{
		attack("atomic T1556 reset", "user.mfa.factor.reset_all", "T1556"),
		// A sub-technique is an instance of its parent.
		attack("atomic T1098.003 grant", "user.account.privilege.grant", "T1098.003"),
		benign("self-service enrolment", "user.mfa.factor.activate"),
	}
}

func TestATechniqueCaughtOnEveryLabelledInstanceIsProven(t *testing.T) {
	st := coverageOf(t, twoRules(t), goodEntries(), nil)
	if st.Predicate.Verdict != Proven {
		t.Fatalf("verdict %s; checks %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
	for _, tech := range []string{"T1098", "T1556"} {
		r := row(t, st, tech)
		if r.Verdict != Proven || r.Positives != 1 || r.Caught != 1 || r.Benign != 1 || r.FalseFires != 0 {
			t.Errorf("%s: %+v", tech, r)
		}
		if r.RecallLow <= 0 || r.RecallLow >= 1 {
			t.Errorf("%s: one of one caught bounds recall at %v", tech, r.RecallLow)
		}
	}
	if st.Subject[0].Name != SubjectCoverage || len(st.Predicate.Coverage.Rules) != 2 {
		t.Errorf("subject %+v, rules %+v", st.Subject, st.Predicate.Coverage.Rules)
	}
	k := mustKey(t)
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(env, k.PublicKey())
	if err != nil {
		t.Fatalf("a coverage proof does not round-trip: %v", err)
	}
	if back.Predicate.Coverage == nil || back.Predicate.Verdict != Proven {
		t.Fatalf("opened %+v", back.Predicate)
	}
	if !strings.Contains(st.Predicate.Claim, "2 technique(s) the rules claim") {
		t.Errorf("claim: %s", st.Predicate.Claim)
	}
}

func TestAnInstanceNoClaimingRuleCatchesRefutesItsTechnique(t *testing.T) {
	entries := append(goodEntries(), attack("atomic T1556 update", "user.mfa.factor.update", "T1556"))
	st := coverageOf(t, twoRules(t), entries, nil)
	r := row(t, st, "T1556")
	if r.Verdict != Refuted || r.Missed != 1 || len(r.MissedEntries) != 1 || r.MissedEntries[0] != 4 {
		t.Fatalf("T1556: %+v", r)
	}
	if st.Predicate.Verdict != Refuted || checkNamed(st, "caught").Passed {
		t.Fatalf("one technique refuted refutes the proof: %s", st.Predicate.Verdict)
	}
	if got := checkNamed(st, "caught").Failures; len(got) != 1 || !strings.Contains(got[0], "T1556") ||
		!strings.Contains(got[0], "entries 4") {
		t.Errorf("failures %v", got)
	}
	if row(t, st, "T1098").Verdict != Proven {
		t.Error("another technique's miss moved this one")
	}
}

// Caught by a rule claiming something else is still missed for the
// technique: the claim is the rule's tag, and the tag is what is held.
func TestCaughtOnlyByARuleClaimingSomethingElseIsMissed(t *testing.T) {
	entries := append(goodEntries(), attack("grant labelled T1556", "user.account.privilege.grant", "T1556"))
	st := coverageOf(t, twoRules(t), entries, nil)
	if r := row(t, st, "T1556"); r.Verdict != Refuted || r.Missed != 1 {
		t.Fatalf("T1556: %+v", r)
	}
}

func TestARuleFiringOnABenignEntryRefutesItsTechnique(t *testing.T) {
	entries := append(goodEntries(), benign("a helpdesk reset, ruled benign", "user.mfa.factor.reset_all"))
	st := coverageOf(t, twoRules(t), entries, nil)
	r := row(t, st, "T1556")
	if r.Verdict != Refuted || r.FalseFires != 1 || r.FalseEntries[0] != 4 || r.Benign != 2 {
		t.Fatalf("T1556: %+v", r)
	}
	if checkNamed(st, "quiet-on-benign").Passed || st.Predicate.Verdict != Refuted {
		t.Fatal("a false fire passed")
	}
}

// An attack is not a false positive for a rule that catches it while
// claiming something else, and it is not benign.
func TestAnAttackLabelledOtherwiseIsNotBenign(t *testing.T) {
	entries := append(goodEntries(), attack("reset during a T1098 run", "user.mfa.factor.reset_all", "T1098"))
	st := coverageOf(t, twoRules(t), entries, nil)
	if r := row(t, st, "T1556"); r.FalseFires != 0 || r.Benign != 1 {
		t.Fatalf("T1556: %+v", r)
	}
}

func TestAnInstanceSeenOnlyByAQuietRuleIsInconclusive(t *testing.T) {
	rules := append(twoRules(t), packRule(t, "okta.signin-failed"))
	entries := append(goodEntries(), detect.Labelled{Name: "atomic T1110 spray", Event: failedSignin(),
		Techniques: []string{"T1110.003"}})
	st := coverageOf(t, rules, entries, nil)
	r := row(t, st, "T1110")
	if r.Verdict != Inconclusive || r.QuietOnly != 1 || r.Caught != 0 || r.Missed != 0 {
		t.Fatalf("T1110: %+v", r)
	}
	if st.Predicate.Verdict != Inconclusive {
		t.Fatalf("verdict %s", st.Predicate.Verdict)
	}
}

func TestThinEvidenceIsInconclusive(t *testing.T) {
	// No labelled instance at all.
	rules := append(twoRules(t), packRule(t, "okta.api-token-created"))
	st := coverageOf(t, rules, goodEntries(), nil)
	if r := row(t, st, "T1528"); r.Verdict != Inconclusive || r.Positives != 0 {
		t.Fatalf("T1528: %+v", r)
	}
	// Fewer instances than asked for.
	st = coverageOf(t, twoRules(t), goodEntries(), func(in *CoverageInput) { in.MinPositives = 2 })
	if st.Predicate.Verdict != Inconclusive || row(t, st, "T1556").Verdict != Inconclusive {
		t.Fatalf("one instance against a floor of two: %s", st.Predicate.Verdict)
	}
	// No benign entry from a source the rules read.
	st = coverageOf(t, twoRules(t), goodEntries()[:2], nil)
	if st.Predicate.Verdict != Inconclusive {
		t.Fatalf("no benign entry: %s", st.Predicate.Verdict)
	}
}

// A sub-technique is part of its parent; the parent is not part of it.
func TestASubTechniqueIsAnInstanceOfItsParentAndNotTheReverse(t *testing.T) {
	rules := []CoverageRule{packRule(t, "okta.mfa-reset"),
		reTagged(t, "okta.admin-privilege-granted", "T1098.003")}
	entries := []detect.Labelled{
		attack("grant labelled only as the parent", "user.account.privilege.grant", "T1098"),
		attack("atomic T1556 reset", "user.mfa.factor.reset_all", "T1556"),
		benign("self-service enrolment", "user.mfa.factor.activate"),
	}
	st := coverageOf(t, rules, entries, nil)
	if r := row(t, st, "T1098.003"); r.Positives != 0 || r.Verdict != Inconclusive {
		t.Fatalf("T1098.003 counted its parent's instance: %+v", r)
	}
	un := st.Predicate.Coverage.Unclaimed
	if len(un) != 1 || un[0].Technique != "T1098" || un[0].Positives != 1 || un[0].CaughtByOther != 1 {
		t.Fatalf("unclaimed %+v", un)
	}
	// Asked about the parent, the rule claiming the sub-technique is held
	// to it.
	st = coverageOf(t, rules, entries, func(in *CoverageInput) { in.Techniques = []string{"T1098"} })
	if r := row(t, st, "T1098"); r.Verdict != Proven || len(r.Rules) != 1 || r.Rules[0] != "okta.admin-privilege-granted" {
		t.Fatalf("T1098 asked: %+v", r)
	}
	if len(st.Predicate.Coverage.Unclaimed) != 0 || len(st.Predicate.Coverage.Techniques) != 1 {
		t.Fatalf("asked about one technique, it covered %+v", st.Predicate.Coverage)
	}
}

func TestANamedTechniqueNoRuleClaimsIsRefutedByItsInstances(t *testing.T) {
	entries := append(goodEntries(), attack("atomic T1003", "user.session.start", "T1003.001"))
	st := coverageOf(t, twoRules(t), entries, func(in *CoverageInput) { in.Techniques = []string{"T1003", "T1556"} })
	r := row(t, st, "T1003")
	if r.Verdict != Refuted || len(r.Rules) != 0 || r.Missed != 1 {
		t.Fatalf("T1003: %+v", r)
	}
	if f := checkNamed(st, "caught").Failures; len(f) != 1 || !strings.Contains(f[0], "no rule claims it") {
		t.Fatalf("failures %v", f)
	}
	// With no instance, it is not known either way.
	st = coverageOf(t, twoRules(t), goodEntries(), func(in *CoverageInput) { in.Techniques = []string{"T1003"} })
	if st.Predicate.Verdict != Inconclusive {
		t.Fatalf("verdict %s", st.Predicate.Verdict)
	}
}

func TestDecayWithholdsProofAndNamesTheDarkRule(t *testing.T) {
	window := func(fields map[string]map[string]bool) func(*CoverageInput) {
		return func(in *CoverageInput) {
			in.Telemetry = &CoverageFields{Since: tnow.Add(-7 * 24 * time.Hour), Until: tnow, Fields: fields,
				Events: 120, PerSourceCap: 100000}
		}
	}
	// Everything still sent: proven, and nothing dark.
	sent := map[string]bool{}
	for f := range oktaEvent("x").Fields() {
		sent[f] = true
	}
	st := coverageOf(t, twoRules(t), goodEntries(), window(map[string]map[string]bool{"okta/system": sent}))
	if st.Predicate.Verdict != Proven || st.Predicate.Coverage.DarkCount != 0 {
		t.Fatalf("nothing changed: %s, dark %d", st.Predicate.Verdict, st.Predicate.Coverage.DarkCount)
	}
	if c := checkNamed(st, "still-fires"); !c.Passed || !strings.Contains(c.Detail, "120 event(s)") {
		t.Fatalf("still-fires: %+v", c)
	}
	if len(st.Predicate.Materials) != 2 || st.Predicate.Materials[1].Name != "telemetry-fields" {
		t.Fatalf("materials %+v", st.Predicate.Materials)
	}

	// The source stopped sending raw.eventType.
	renamed := map[string]bool{}
	for f := range sent {
		if f != "raw.eventType" {
			renamed[f] = true
		}
	}
	renamed["raw.event_type"] = true
	st = coverageOf(t, twoRules(t), goodEntries(), window(map[string]map[string]bool{"okta/system": renamed}))
	r := row(t, st, "T1556")
	if r.Verdict != Inconclusive || r.Decayed != 1 || r.DecayedEntries[0] != 1 {
		t.Fatalf("T1556 after the rename: %+v", r)
	}
	if st.Predicate.Verdict != Inconclusive {
		t.Fatalf("decay refuted or proved: %s", st.Predicate.Verdict)
	}
	ev := st.Predicate.Coverage
	if ev.DarkCount != 2 || ev.Dark[0].Rule != "okta.admin-privilege-granted" || ev.Dark[0].Silent ||
		len(ev.Dark[0].Missing) != 1 || ev.Dark[0].Missing[0] != "raw.eventType" {
		t.Fatalf("dark %+v", ev.Dark)
	}

	// The source sent nothing at all.
	st = coverageOf(t, twoRules(t), goodEntries(), window(map[string]map[string]bool{}))
	ev = st.Predicate.Coverage
	if ev.DarkCount != 2 || !ev.Dark[0].Silent || ev.Telemetry.Silent != 1 || ev.Telemetry.Sources != 0 {
		t.Fatalf("silent: %+v %+v", ev.Dark, ev.Telemetry)
	}
}

func TestACoverageProofIsRefusedWithoutWhatItNeeds(t *testing.T) {
	for name, edit := range map[string]func(*CoverageInput){
		"no corpus":           func(in *CoverageInput) { in.Entries, in.Corpus, in.CorpusName = nil, nil, "" },
		"no floor":            func(in *CoverageInput) { in.MinPositives = 0 },
		"no benign floor":     func(in *CoverageInput) { in.MinBenign = 0 },
		"no rules":            func(in *CoverageInput) { in.Rules = nil },
		"a technique made up": func(in *CoverageInput) { in.Techniques = []string{"credential dumping"} },
		"two rules one name":  func(in *CoverageInput) { in.Rules = append(in.Rules, in.Rules[0]) },
		"a rule id with spaces": func(in *CoverageInput) {
			in.Rules = append([]CoverageRule{}, in.Rules...)
			in.Rules[0].Rule.ID = "Okta MFA reset"
		},
		"a material named like the field listing": func(in *CoverageInput) { in.CorpusName = "telemetry-fields" },
	} {
		if _, err := tryCoverage(t, twoRules(t), goodEntries(), edit); err == nil {
			t.Errorf("%s: a proof was made", name)
		}
	}
	// Rules that claim nothing, asked about nothing.
	if _, err := tryCoverage(t, []CoverageRule{reTagged(t, "okta.mfa-reset")}, goodEntries(), nil); err == nil ||
		!strings.Contains(err.Error(), "claim no technique") {
		t.Errorf("rules claiming nothing: %v", err)
	}
	// A tag of no known shape is counted and left out of every row.
	st := coverageOf(t, []CoverageRule{reTagged(t, "okta.mfa-reset", "T1556", "credential-access")},
		goodEntries(), nil)
	if st.Predicate.Coverage.Unrecognised != 1 || len(st.Predicate.Coverage.Techniques) != 1 {
		t.Fatalf("unrecognised %d, rows %d", st.Predicate.Coverage.Unrecognised, len(st.Predicate.Coverage.Techniques))
	}
}

func at(ev *CoverageEvidence, technique string) *TechniqueCoverage {
	for i := range ev.Techniques {
		if ev.Techniques[i].Technique == technique {
			return &ev.Techniques[i]
		}
	}
	panic("no row for " + technique)
}

// Every number and word in a signed coverage proof is held to the rest: a
// statement edited after it was made is refused, whichever part was edited.
func TestAnEditedCoverageProofIsRefused(t *testing.T) {
	fresh := func() *Statement {
		rules := append(twoRules(t), packRule(t, "okta.signin-failed"))
		entries := append(goodEntries(), attack("atomic T1556 update", "user.mfa.factor.update", "T1556"))
		return coverageOf(t, rules, entries, func(in *CoverageInput) {
			in.Telemetry = &CoverageFields{Since: tnow.Add(-time.Hour), Until: tnow,
				Fields: map[string]map[string]bool{}, Events: 0, PerSourceCap: 10}
		})
	}
	if err := fresh().Validate(); err != nil {
		t.Fatalf("the unedited proof: %v", err)
	}
	edits := map[string]func(*CoverageEvidence, *Statement){
		"a row's verdict": func(ev *CoverageEvidence, _ *Statement) { at(ev, "T1556").Verdict = Proven },
		"a count":         func(ev *CoverageEvidence, _ *Statement) { at(ev, "T1098").Caught++ },
		"a miss hidden":   func(ev *CoverageEvidence, _ *Statement) { r := at(ev, "T1556"); r.Missed, r.Caught = 0, r.Caught+1 },
		"a missed entry":  func(ev *CoverageEvidence, _ *Statement) { at(ev, "T1556").MissedEntries[0] = 99 },
		"the bound":       func(ev *CoverageEvidence, _ *Statement) { at(ev, "T1098").RecallLow = 0.99 },
		"a claiming rule": func(ev *CoverageEvidence, _ *Statement) { at(ev, "T1098").Rules = []string{"okta.mfa-reset"} },
		"a rule's digest": func(ev *CoverageEvidence, _ *Statement) { ev.Rules[0].SHA256 = strings.Repeat("0", 64) },
		"a rule's tags":   func(ev *CoverageEvidence, _ *Statement) { ev.Rules[0].Techniques = []string{"T1003"} },
		"a row dropped":   func(ev *CoverageEvidence, _ *Statement) { ev.Techniques = ev.Techniques[1:] },
		// Appended, a row the rules do not claim must be refused, not read
		// past the end of what they do.
		"a row added": func(ev *CoverageEvidence, _ *Statement) {
			ev.Techniques = append(ev.Techniques, TechniqueCoverage{Technique: "T9999", Rules: []string{},
				Verdict: Inconclusive})
		},
		// Inconclusive to proven leaves the whole refuted: only the row's
		// own verdict is held to its counts.
		"a row's verdict, the whole unchanged": func(ev *CoverageEvidence, _ *Statement) {
			at(ev, "T1110").Verdict = Proven
		},
		"asked, afterwards": func(ev *CoverageEvidence, _ *Statement) { ev.Asked = true },
		"the floor":         func(ev *CoverageEvidence, _ *Statement) { ev.MinPositives = 5 },
		"decay without a window": func(ev *CoverageEvidence, _ *Statement) {
			ev.Telemetry = nil
		},
		"a dark rule removed": func(ev *CoverageEvidence, _ *Statement) { ev.Dark = ev.Dark[1:] },
		"a dark rule made up": func(ev *CoverageEvidence, _ *Statement) { ev.Dark[0].Rule = "aaa.not-read" },
		"an unclaimed technique under a row": func(ev *CoverageEvidence, _ *Statement) {
			ev.Unclaimed = append(ev.Unclaimed, UnclaimedTechnique{Technique: "T1556.006", Positives: 1})
		},
		"the window's digest": func(ev *CoverageEvidence, _ *Statement) { ev.Telemetry.Fields = strings.Repeat("a", 64) },
		"the claim":           func(_ *CoverageEvidence, s *Statement) { s.Predicate.Claim += " Also T1003." },
		"a check's words":     func(_ *CoverageEvidence, s *Statement) { s.Predicate.Checks[2].Detail = "plenty" },
		"a failure's words": func(_ *CoverageEvidence, s *Statement) {
			s.Predicate.Checks[0].Failures[0] = "T1556: fine"
		},
		"the subject":   func(_ *CoverageEvidence, s *Statement) { s.Subject[0].Digest["sha256"] = strings.Repeat("1", 64) },
		"the materials": func(_ *CoverageEvidence, s *Statement) { s.Predicate.Materials = s.Predicate.Materials[:1] },
		"the verdict":   func(_ *CoverageEvidence, s *Statement) { s.Predicate.Verdict = Inconclusive },
	}
	for name, edit := range edits {
		st := fresh()
		edit(st.Predicate.Coverage, st)
		if err := st.Validate(); err == nil {
			t.Errorf("%s: the edited proof validates", name)
		}
	}
}

// Edits only the evidence's own invariants catch: nothing else in the
// statement says them.
func TestAnEditedCoverageProofIsRefusedWhereOnlyItsCountsSayIt(t *testing.T) {
	// Decay claimed of a proof that read no telemetry.
	st := coverageOf(t, twoRules(t), append(goodEntries(),
		attack("atomic T1556 update", "user.mfa.factor.update", "T1556")), nil)
	r := at(st.Predicate.Coverage, "T1556")
	r.Decayed, r.DecayedEntries = 1, []int{1}
	if err := st.Validate(); err == nil {
		t.Error("decay without telemetry validates")
	}
	// Another technique listed beside the ones named.
	st = coverageOf(t, twoRules(t), goodEntries(), func(in *CoverageInput) { in.Techniques = []string{"T1556"} })
	st.Predicate.Coverage.Unclaimed = []UnclaimedTechnique{{Technique: "T1003", Positives: 1}}
	if err := st.Validate(); err == nil {
		t.Error("a named-technique proof lists one it was not asked about")
	}
	// A row's counts that do not add up, and lists that are not their counts.
	ev := &CoverageEvidence{Entries: 10, Labelled: 5, Benign: 5}
	for name, row := range map[string]TechniqueCoverage{
		"instances unaccounted for":    {Rules: []string{"r"}, Positives: 2, Caught: 1},
		"more instances than labelled": {Rules: []string{"r"}, Positives: 6, Caught: 6},
		"a miss not listed":            {Rules: []string{"r"}, Positives: 1, Missed: 1},
		"a false fire not listed":      {Rules: []string{"r"}, Benign: 1, FalseFires: 1},
		"more false than benign":       {Rules: []string{"r"}, Benign: 1, FalseFires: 2, FalseEntries: []int{1, 2}},
		"an entry past the corpus":     {Rules: []string{"r"}, Positives: 1, Missed: 1, MissedEntries: []int{11}},
		"caught with no rule":          {Positives: 1, Caught: 1},
	} {
		if err := row.wellFormed(ev); err == nil {
			t.Errorf("%s: %+v is well formed", name, row)
		}
	}
}

// A dark rule names only the fields it reads that were not sent.
func TestADarkRuleNamesOnlyTheFieldsNoLongerSent(t *testing.T) {
	cr := packRule(t, "okta.mfa-reset")
	cr.Rule.When = detect.Predicate{All: []detect.Predicate{cr.Rule.When,
		{Match: &detect.Match{Field: "actor.issuer", Op: detect.Equals, Values: []string{"okta"}}}}}
	b, err := json.Marshal(cr.Rule)
	if err != nil {
		t.Fatal(err)
	}
	cr.File = b
	sent := map[string]bool{}
	for f := range oktaEvent("x").Fields() {
		if f != "raw.eventType" {
			sent[f] = true
		}
	}
	st := coverageOf(t, []CoverageRule{cr}, goodEntries(), func(in *CoverageInput) {
		in.Telemetry = &CoverageFields{Since: tnow.Add(-time.Hour), Until: tnow, PerSourceCap: 10,
			Fields: map[string]map[string]bool{"okta/system": sent}}
	})
	dark := st.Predicate.Coverage.Dark
	if len(dark) != 1 || len(dark[0].Missing) != 1 || dark[0].Missing[0] != "raw.eventType" {
		t.Fatalf("dark %+v", dark)
	}
}

func TestALayerShowsEachVerdictInWordsAndScoresNothing(t *testing.T) {
	rules := []CoverageRule{packRule(t, "okta.mfa-reset"), reTagged(t, "okta.admin-privilege-granted", "T1098", "AML.T0051")}
	entries := append(goodEntries(), attack("atomic T1003", "user.session.start", "T1003.001"))
	st := coverageOf(t, rules, entries, nil)
	digest := strings.Repeat("ab", 32)
	doc, left, err := CoverageLayer(st, digest)
	if err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Errorf("left out %d; the ATLAS id is not on the ATT&CK matrix", left)
	}
	var layer map[string]any
	if err := json.Unmarshal(doc, &layer); err != nil {
		t.Fatal(err)
	}
	if layer["domain"] != "enterprise-attack" || layer["versions"].(map[string]any)["layer"] != "4.5" {
		t.Fatalf("layer header %v %v", layer["domain"], layer["versions"])
	}
	if strings.Contains(string(doc), `"score"`) || strings.Contains(string(doc), "%\"") {
		t.Error("a layer scores a technique")
	}
	if !strings.Contains(layer["description"].(string), digest) {
		t.Error("the layer does not name its proof")
	}
	techniques := layer["techniques"].([]any)
	words := map[string]string{}
	for _, raw := range techniques {
		tech := raw.(map[string]any)
		words[tech["techniqueID"].(string)] = strings.SplitN(tech["comment"].(string), ":", 2)[0]
	}
	want := map[string]string{"T1556": "proven", "T1098": "proven", "T1003.001": "unclaimed"}
	for id, word := range want {
		if words[id] != word {
			t.Errorf("%s says %q, want %q", id, words[id], word)
		}
	}
	if len(words) != len(want) {
		t.Errorf("layer techniques %v", words)
	}
	if _, _, err := CoverageLayer(st, "not-a-digest"); err == nil {
		t.Error("a layer named a proof by something other than its digest")
	}
	other := prove(t, goodCorpus(t))
	if _, _, err := CoverageLayer(other, digest); err == nil {
		t.Error("a layer was drawn from a detection proof")
	}
}
