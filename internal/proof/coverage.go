// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/stats"
)

// A coverage proof: for each technique a set of rules claims, the events
// labelled as that technique are caught by a rule claiming it, and nothing
// labelled benign sets one off.
//
// # Why
//
// A rule's ATT&CK tag is its author's word. A coverage grid built from the
// tags — the grid every SIEM and every breach-and-attack product renders —
// says which techniques somebody meant to cover, and MITRE's own Center for
// Threat-Informed Defense says a technique marked covered "doesn't reveal
// whether detections can reliably identify all variations of that technique
// or if adversaries could easily evade them". So the tag is held to evidence
// its author did not write: events labelled with the technique by whatever
// produced them — an Atomic Red Team test run on a lab host, a red team's
// plan — and events labelled benign.
//
// # The claim, per technique
//
//   - refuted when an event labelled as an instance of it is caught by no
//     rule claiming it, or a rule claiming it that raises an alert fires on
//     an event labelled benign from a source it reads;
//   - proven when every labelled instance is caught by a rule claiming it
//     that raises an alert, on at least as many instances and benign events
//     as the proof asks for, and — when the store's recent telemetry was
//     read — every instance caught is still caught with only the fields its
//     source has sent lately;
//   - inconclusive otherwise: too few labelled instances or benign events,
//     an instance seen only by a rule that raises nothing on its own (a
//     correlation may count it; the proof cannot say), or an instance that
//     would not be caught with only the fields its source has sent lately.
//
// A sub-technique is an instance of its parent: an event labelled T1098.004
// is an instance of T1098, and a rule claiming T1098.004 claims part of
// T1098. The reverse does not hold, so an event labelled T1098 is no
// instance of T1098.004, and a rule claiming T1098 is not held to it.
//
// The proof as a whole is refuted when any technique is, proven when every
// one is, and inconclusive otherwise. There is no percentage anywhere in it.
//
// # Decay
//
// A rule written against a source's fields stops firing, without an error,
// when the source stops sending one of them: a vendor renames a field, a
// connector's mapping changes, an agent is upgraded. With the store's recent
// telemetry, each instance a rule caught is asked again with only the fields
// its source sent in that window, and each rule's own examples likewise. An
// instance no longer caught keeps its technique from being proven, and a
// rule that catches none of its own examples is listed as dark.
//
// # What it cannot say
//
// That a technique is detected in every form it takes: only that the forms
// in the corpus are. That a field still present carries the same values: a
// source can keep a field and change what it says. And absence over a window
// is not proof a source cannot send a field — a rare event's fields are rare
// — which is why decay makes a technique inconclusive and never refuted.

// CoverageVerifier and its version name this verifier.
const (
	CoverageVerifier        = "aertun/coverage"
	CoverageVerifierVersion = "1"
)

// PredicateCoverage is the predicate of a coverage proof.
const PredicateCoverage = "https://aertun.github.io/proof/coverage/v1"

// The bounds a coverage proof is held to.
const (
	// MaxCoverageRules bounds the rules one proof reads.
	MaxCoverageRules = 10000
	// MaxCoverageTechniques bounds its techniques: ATT&CK has under a
	// thousand techniques and sub-techniques, ATLAS and OWASP a few dozen.
	MaxCoverageTechniques = 2000
	// MaxCoverageEntries bounds the corpus entries a technique lists by
	// number for each way it can fail; the rest are counted.
	MaxCoverageEntries = 10
	// MaxDarkFields bounds the fields a dark rule lists as no longer sent.
	MaxDarkFields = 16
	// maxCoverageCount bounds every count.
	maxCoverageCount = 1 << 40
)

// SubjectCoverage names what a coverage proof is about: the rules it read.
const SubjectCoverage = "detection-rules"

var (
	coverageRuleShape  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	coverageFieldShape = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,127}$`)
)

// CoverageRule is one rule as it was read: what it is, and its exact bytes,
// whose digest is what the proof says it read.
type CoverageRule struct {
	Rule detect.Rule
	File []byte
}

// CoverageFields are the field names each source's events carried over a
// window of the store, keyed by source in lower case.
type CoverageFields struct {
	Since, Until time.Time
	Fields       map[string]map[string]bool
	// Events is how many events were read, and Capped how many sources had
	// more than PerSourceCap, of which the first PerSourceCap were read.
	Events, Capped, PerSourceCap int
}

// CoverageInput is what a coverage proof is made from.
type CoverageInput struct {
	Rules []CoverageRule
	// CorpusName and Corpus are the labelled corpus's name and exact bytes;
	// Entries is it parsed.
	CorpusName string
	Corpus     []byte
	Entries    []detect.Labelled
	// Techniques are the techniques asked about; empty asks about every one
	// the rules claim.
	Techniques []string
	// MinPositives and MinBenign are how many labelled instances, and how
	// many benign events from the sources its rules read, a technique needs
	// to be proven.
	MinPositives, MinBenign int
	// Telemetry, when set, is what the store's sources sent lately.
	Telemetry *CoverageFields
	Author    Author
	Program   string
	Now       time.Time
}

// CoverageRuleFile is a rule the proof read: its id, the digest of its file,
// whether it raises nothing on its own, and the techniques it claims that
// have a known shape.
type CoverageRuleFile struct {
	ID         string   `json:"id"`
	SHA256     string   `json:"sha256"`
	Quiet      bool     `json:"quiet,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
}

// CoverageWindow is the stretch of the store's telemetry decay was judged
// against.
type CoverageWindow struct {
	Since string `json:"since"`
	Until string `json:"until"`
	// Sources is how many sources the rules claiming these techniques read
	// sent at least one event in the window, and Silent how many sent none.
	Sources int `json:"sources"`
	Silent  int `json:"silent"`
	// Events is how many events were read; Capped is how many sources sent
	// more than PerSourceCap, of which the first PerSourceCap were read.
	Events       int `json:"events"`
	Capped       int `json:"capped"`
	PerSourceCap int `json:"per_source_cap"`
	// Fields is the sha256 of the field names each source sent, as listed
	// in the material of the same name.
	Fields string `json:"fields"`
}

// TechniqueCoverage is one technique's verdict and the counts behind it.
type TechniqueCoverage struct {
	Technique string `json:"technique"`
	// Rules are the rules claiming it or one of its sub-techniques.
	Rules []string `json:"rules"`
	// Positives are the corpus entries labelled as an instance of it.
	// Caught were caught by a rule claiming it that raises an alert,
	// QuietOnly only by ones that raise nothing on their own, and Missed by
	// none, listed by their place in the corpus (1 is the first entry).
	Positives     int   `json:"positives"`
	Caught        int   `json:"caught"`
	QuietOnly     int   `json:"quiet_only"`
	Missed        int   `json:"missed"`
	MissedEntries []int `json:"missed_entries,omitempty"`
	// Benign are the entries labelled benign from a source its rules read,
	// and FalseFires those a rule claiming it that raises an alert fired on.
	Benign       int   `json:"benign"`
	FalseFires   int   `json:"false_fires"`
	FalseEntries []int `json:"false_entries,omitempty"`
	// RecallLow is the exact one-sided 95% lower bound on the share of its
	// instances caught (Clopper–Pearson): how much Caught of Positives says.
	RecallLow float64 `json:"recall_low"`
	// Decayed are the instances caught that no rule claiming it catches
	// with only the fields their source sent lately; with telemetry only.
	Decayed        int     `json:"decayed,omitempty"`
	DecayedEntries []int   `json:"decayed_entries,omitempty"`
	Verdict        Verdict `json:"verdict"`
}

// UnclaimedTechnique is a technique the corpus labels that no rule claims.
type UnclaimedTechnique struct {
	Technique string `json:"technique"`
	Positives int    `json:"positives"`
	// CaughtByOther is how many of them a rule raising an alert caught
	// anyway, while claiming something else.
	CaughtByOther int `json:"caught_by_other"`
}

// DarkRule is a rule claiming one of the techniques that catches none of its
// own examples — the fixtures it must match, and the instances it caught —
// with only the fields its sources sent lately.
type DarkRule struct {
	Rule string `json:"rule"`
	// Silent is set when none of the sources it reads sent anything.
	Silent bool `json:"silent,omitempty"`
	// Missing are fields it reads that none of its sources sent.
	Missing []string `json:"missing,omitempty"`
}

// CoverageEvidence is what a coverage proof rests on.
type CoverageEvidence struct {
	// Rules are every rule read, by id; the subject's digest is over them.
	Rules []CoverageRuleFile `json:"rules"`
	// Entries is the corpus's size; Labelled how many are labelled with a
	// technique, and Benign how many as nothing happening.
	Entries  int `json:"entries"`
	Labelled int `json:"labelled"`
	Benign   int `json:"benign"`
	// MinPositives and MinBenign are what a technique needs to be proven.
	MinPositives int `json:"min_positives"`
	MinBenign    int `json:"min_benign"`
	// Asked is set when the techniques were named rather than every one the
	// rules claim.
	Asked bool `json:"asked,omitempty"`
	// Unrecognised is how many distinct tags the rules carry that are not a
	// technique id of a known shape, and so are in no row.
	Unrecognised int                  `json:"unrecognised"`
	Telemetry    *CoverageWindow      `json:"telemetry,omitempty"`
	Techniques   []TechniqueCoverage  `json:"techniques"`
	Unclaimed    []UnclaimedTechnique `json:"unclaimed,omitempty"`
	// DarkCount is how many rules are dark, and Dark lists them, up to
	// MaxFailures.
	DarkCount int        `json:"dark_count,omitempty"`
	Dark      []DarkRule `json:"dark,omitempty"`
}

// within reports whether a label is an instance of a technique: the
// technique itself, or one of its sub-techniques.
func within(label, technique string) bool {
	return label == technique || strings.HasPrefix(label, technique+".")
}

func sourceKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ProveCoverage runs the corpus past every rule claiming each technique and
// builds the unsigned statement.
func ProveCoverage(in CoverageInput) (*Statement, error) {
	if in.CorpusName == "" || len(in.Corpus) == 0 || len(in.Entries) == 0 {
		return nil, fmt.Errorf("a coverage proof needs a labelled corpus: it is what the rules' claims are held to")
	}
	if in.MinPositives < 1 || in.MinPositives > 1_000_000 || in.MinBenign < 1 || in.MinBenign > 1_000_000 {
		return nil, fmt.Errorf("a technique is proven on at least one labelled instance and one benign event")
	}
	if len(in.Rules) == 0 || len(in.Rules) > MaxCoverageRules {
		return nil, fmt.Errorf("a coverage proof reads between 1 and %d rules", MaxCoverageRules)
	}
	for i, l := range in.Entries {
		if err := l.Validate(); err != nil {
			return nil, fmt.Errorf("corpus entry %d: %w", i+1, err)
		}
	}
	ev := &CoverageEvidence{Entries: len(in.Entries), MinPositives: in.MinPositives,
		MinBenign: in.MinBenign, Asked: len(in.Techniques) > 0}
	for _, l := range in.Entries {
		switch {
		case len(l.Techniques) > 0:
			ev.Labelled++
		case l.Benign():
			ev.Benign++
		}
	}

	rules := append([]CoverageRule(nil), in.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Rule.ID < rules[j].Rule.ID })
	progs := make([]*detect.Program, len(rules))
	unrecognised := map[string]bool{}
	for i, cr := range rules {
		r := cr.Rule
		if !coverageRuleShape.MatchString(r.ID) {
			return nil, fmt.Errorf("a rule in a coverage proof is named by an id of lower-case letters, digits, dots and dashes; %q is not one", r.ID)
		}
		if i > 0 && rules[i-1].Rule.ID == r.ID {
			return nil, fmt.Errorf("two rules are called %s", r.ID)
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("%s is not a usable rule: %w", r.ID, err)
		}
		p, err := r.Compile()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.ID, err)
		}
		progs[i] = p
		file := CoverageRuleFile{ID: r.ID, SHA256: SHA256(cr.File)["sha256"], Quiet: r.Quiet}
		seen := map[string]bool{}
		for _, t := range r.Technique {
			t = strings.TrimSpace(t)
			switch {
			case !detect.TechniqueShape.MatchString(t):
				unrecognised[t] = true
			case !seen[t]:
				seen[t] = true
				file.Techniques = append(file.Techniques, t)
			}
		}
		sort.Strings(file.Techniques)
		ev.Rules = append(ev.Rules, file)
	}
	ev.Unrecognised = len(unrecognised)

	asked, err := askedTechniques(in.Techniques)
	if err != nil {
		return nil, err
	}
	rows := asked
	if !ev.Asked {
		rows = ev.claimed()
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("the rules claim no technique of a known shape; name one with --technique")
	}
	if len(rows) > MaxCoverageTechniques {
		return nil, fmt.Errorf("a coverage proof covers at most %d techniques", MaxCoverageTechniques)
	}

	// Each entry's fields, built once, and each rule's answer on it, asked
	// once.
	fields := make([]map[string]string, len(in.Entries))
	for i, l := range in.Entries {
		fields[i] = l.Event.Fields()
	}
	type key struct{ rule, entry int }
	fired := map[key]bool{}
	fires := func(ri, ei int) bool {
		k := key{ri, ei}
		if v, ok := fired[k]; ok {
			return v
		}
		v := progs[ri].MatchesFields(in.Entries[ei].Event.Source, fields[ei])
		fired[k] = v
		return v
	}
	var now map[string]map[string]bool
	if in.Telemetry != nil {
		now = in.Telemetry.Fields
	}
	// trimmed is an entry's fields cut to those its source sent lately.
	trimmed := func(source string, f map[string]string) map[string]string {
		sent := now[sourceKey(source)]
		out := make(map[string]string, len(f))
		for k, v := range f {
			if sent[k] {
				out[k] = v
			}
		}
		return out
	}

	claimers := map[int]bool{}
	for _, t := range rows {
		row := TechniqueCoverage{Technique: t, Rules: []string{}}
		var loud, quiet []int
		for ri, rf := range ev.Rules {
			if rf.claims(t) {
				row.Rules = append(row.Rules, rf.ID)
				claimers[ri] = true
				if rf.Quiet {
					quiet = append(quiet, ri)
				} else {
					loud = append(loud, ri)
				}
			}
		}
		for ei, l := range in.Entries {
			switch {
			case instanceOf(l, t):
				row.Positives++
				switch {
				case anyFires(loud, func(ri int) bool { return fires(ri, ei) }):
					row.Caught++
					if in.Telemetry != nil {
						f := trimmed(l.Event.Source, fields[ei])
						if !anyFires(loud, func(ri int) bool { return progs[ri].MatchesFields(l.Event.Source, f) }) {
							row.Decayed++
							row.DecayedEntries = listEntry(row.DecayedEntries, ei)
						}
					}
				case anyFires(quiet, func(ri int) bool { return fires(ri, ei) }):
					row.QuietOnly++
				default:
					row.Missed++
					row.MissedEntries = listEntry(row.MissedEntries, ei)
				}
			case l.Benign() && readBy(rules, append(append([]int{}, loud...), quiet...), l.Event.Source):
				row.Benign++
				if anyFires(loud, func(ri int) bool { return fires(ri, ei) }) {
					row.FalseFires++
					row.FalseEntries = listEntry(row.FalseEntries, ei)
				}
			}
		}
		row.RecallLow = recallLow(row.Caught, row.Positives)
		row.Verdict = row.verdict(ev)
		ev.Techniques = append(ev.Techniques, row)
	}

	if !ev.Asked {
		ev.Unclaimed = unclaimed(in.Entries, rows, func(ei int) bool {
			for ri, rf := range ev.Rules {
				if !rf.Quiet && fires(ri, ei) {
					return true
				}
			}
			return false
		})
	}

	materials := []Material{{Name: in.CorpusName, Digest: SHA256(in.Corpus), Entries: len(in.Entries)}}
	if in.Telemetry != nil {
		window, listing, dark := decay(in.Telemetry, rules, progs, claimers, in.Entries, fields, ev, trimmed, fires)
		ev.Telemetry = window
		ev.DarkCount = len(dark)
		ev.Dark, _ = cappedDark(dark)
		materials = append(materials, Material{Name: "telemetry-fields", Digest: SHA256(listing),
			Entries: in.Telemetry.Events})
	}

	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectCoverage, Digest: Digest{"sha256": ev.subjectDigest()}}},
		PredicateType: PredicateCoverage,
		Predicate: Predicate{
			Author:  in.Author,
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: CoverageVerifier, Version: CoverageVerifierVersion,
				Program: in.Program},
			Materials: materials, Checks: ev.checks(), Coverage: ev,
			VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

// askedTechniques is the techniques named, checked, once each and sorted.
func askedTechniques(named []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, t := range named {
		t = strings.TrimSpace(t)
		if !detect.TechniqueShape.MatchString(t) {
			return nil, fmt.Errorf("%q is not an ATT&CK, ATLAS or OWASP id (T1098, T1098.004, AML.T0051, ASI01, LLM10)", t)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, nil
}

// claimed is every technique the rules claim, once each and sorted.
func (ev *CoverageEvidence) claimed() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range ev.Rules {
		for _, t := range r.Techniques {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// claims reports whether a rule claims a technique or one of its
// sub-techniques.
func (r CoverageRuleFile) claims(t string) bool {
	for _, c := range r.Techniques {
		if within(c, t) {
			return true
		}
	}
	return false
}

// instanceOf reports whether an entry is labelled as an instance of a
// technique.
func instanceOf(l detect.Labelled, t string) bool {
	for _, label := range l.Techniques {
		if within(label, t) {
			return true
		}
	}
	return false
}

func anyFires(rules []int, fires func(int) bool) bool {
	for _, ri := range rules {
		if fires(ri) {
			return true
		}
	}
	return false
}

func readBy(rules []CoverageRule, which []int, source string) bool {
	for _, ri := range which {
		for _, s := range rules[ri].Rule.Sources {
			if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(source)) {
				return true
			}
		}
	}
	return false
}

// listEntry adds an entry, by its place in the corpus, to a list kept to
// MaxCoverageEntries.
func listEntry(list []int, ei int) []int {
	if len(list) < MaxCoverageEntries {
		list = append(list, ei+1)
	}
	return list
}

// recallLow is the exact one-sided 95% lower bound on k of n.
func recallLow(k, n int) float64 {
	if n == 0 {
		return 0
	}
	return 1 - stats.ClopperPearsonUpper(n-k, n, 0.95)
}

func (t TechniqueCoverage) verdict(ev *CoverageEvidence) Verdict {
	switch {
	case t.Missed > 0 || t.FalseFires > 0:
		return Refuted
	case t.Positives >= ev.MinPositives && t.Benign >= ev.MinBenign && t.QuietOnly == 0 && t.Decayed == 0:
		return Proven
	}
	return Inconclusive
}

// unclaimed are the techniques the corpus labels that no row counts an
// instance of.
func unclaimed(entries []detect.Labelled, rows []string, caught func(int) bool) []UnclaimedTechnique {
	byLabel := map[string]*UnclaimedTechnique{}
	for ei, l := range entries {
		for _, label := range l.Techniques {
			covered := false
			for _, t := range rows {
				covered = covered || within(label, t)
			}
			if covered {
				continue
			}
			u := byLabel[label]
			if u == nil {
				u = &UnclaimedTechnique{Technique: label}
				byLabel[label] = u
			}
			u.Positives++
			if caught(ei) {
				u.CaughtByOther++
			}
		}
	}
	out := make([]UnclaimedTechnique, 0, len(byLabel))
	for _, u := range byLabel {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Technique < out[j].Technique })
	if len(out) > MaxCoverageTechniques {
		out = out[:MaxCoverageTechniques]
	}
	return out
}

// decay judges the rules claiming the techniques against what their sources
// sent lately: the window, the field listing it was judged on, and the rules
// that catch none of their own examples that way.
func decay(tel *CoverageFields, rules []CoverageRule, progs []*detect.Program, claimers map[int]bool,
	entries []detect.Labelled, fields []map[string]string, ev *CoverageEvidence,
	trimmed func(string, map[string]string) map[string]string, fires func(int, int) bool) (*CoverageWindow, []byte, []DarkRule) {
	listing := fieldListing(tel.Fields)
	sum := sha256.Sum256(listing)
	window := &CoverageWindow{Since: tel.Since.UTC().Format(time.RFC3339), Until: tel.Until.UTC().Format(time.RFC3339),
		Events: tel.Events, Capped: tel.Capped, PerSourceCap: tel.PerSourceCap, Fields: hex.EncodeToString(sum[:])}
	read := map[string]bool{}
	for ri := range claimers {
		for _, s := range rules[ri].Rule.Sources {
			read[sourceKey(s)] = true
		}
	}
	for s := range read {
		if len(tel.Fields[s]) > 0 {
			window.Sources++
		} else {
			window.Silent++
		}
	}

	var dark []DarkRule
	for ri := range rules {
		if !claimers[ri] {
			continue
		}
		r := rules[ri].Rule
		examples, still := 0, false
		ask := func(source string, f map[string]string) {
			examples++
			still = still || progs[ri].MatchesFields(source, trimmed(source, f))
		}
		for _, fx := range r.Fixtures {
			if fx.Match && progs[ri].Matches(fx.Event) {
				ask(fx.Event.Source, fx.Event.Fields())
			}
		}
		for ei, l := range entries {
			if len(l.Techniques) > 0 && fires(ri, ei) {
				ask(l.Event.Source, fields[ei])
			}
		}
		if examples == 0 || still {
			continue
		}
		d := DarkRule{Rule: r.ID, Silent: true}
		sent := map[string]bool{}
		for _, s := range r.Sources {
			for f := range tel.Fields[sourceKey(s)] {
				sent[f] = true
				d.Silent = false
			}
		}
		if !d.Silent {
			for _, f := range r.Fields() {
				if !sent[f] && coverageFieldShape.MatchString(f) && len(d.Missing) < MaxDarkFields {
					d.Missing = append(d.Missing, f)
				}
			}
		}
		dark = append(dark, d)
	}
	sort.Slice(dark, func(i, j int) bool { return dark[i].Rule < dark[j].Rule })
	return window, listing, dark
}

// fieldListing is the field names each source sent, one source to a line,
// sorted: what the telemetry-fields material's digest is over.
func fieldListing(by map[string]map[string]bool) []byte {
	sources := make([]string, 0, len(by))
	for s := range by {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	var b strings.Builder
	for _, s := range sources {
		names := make([]string, 0, len(by[s]))
		for f := range by[s] {
			names = append(names, f)
		}
		sort.Strings(names)
		line, _ := json.Marshal(map[string]any{"source": s, "fields": names})
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func cappedDark(d []DarkRule) ([]DarkRule, int) {
	if len(d) <= MaxFailures {
		return d, 0
	}
	return d[:MaxFailures], len(d) - MaxFailures
}

// subjectDigest is over the rules read: each id and the digest of its file,
// one to a line, in order.
func (ev *CoverageEvidence) subjectDigest() string {
	var b strings.Builder
	for _, r := range ev.Rules {
		b.WriteString(r.ID + " " + r.SHA256 + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func (ev *CoverageEvidence) count(v Verdict) int {
	n := 0
	for _, t := range ev.Techniques {
		if t.Verdict == v {
			n++
		}
	}
	return n
}

func (ev *CoverageEvidence) verdict() Verdict {
	switch {
	case ev.count(Refuted) > 0:
		return Refuted
	case ev.count(Proven) == len(ev.Techniques):
		return Proven
	}
	return Inconclusive
}

func (ev *CoverageEvidence) claim() string {
	which := "the rules claim"
	if ev.Asked {
		which = "named"
	}
	decay := ""
	if w := ev.Telemetry; w != nil {
		decay = fmt.Sprintf(", and every instance caught is still caught with only the fields its source sent "+
			"between %s and %s", w.Since, w.Until)
	}
	return fmt.Sprintf("For each of the %d technique(s) %s, every corpus entry labelled as an instance of it "+
		"is caught by a rule claiming it that raises an alert, and no such rule fires on an entry labelled "+
		"benign from a source it reads, on at least %d labelled instance(s) and %d benign entr(ies) for "+
		"each%s.", len(ev.Techniques), which, ev.MinPositives, ev.MinBenign, decay)
}

func entryList(list []int, of int) string {
	words := make([]string, len(list))
	for i, e := range list {
		words[i] = fmt.Sprint(e)
	}
	s := strings.Join(words, ", ")
	if of > len(list) {
		s += fmt.Sprintf(" and %d more", of-len(list))
	}
	return s
}

func (ev *CoverageEvidence) checks() []Check {
	var positives, caught, quietOnly, missed, falseFires, enough, none, decayed, decaying int
	var missedRows, falseRows []string
	for _, t := range ev.Techniques {
		positives += t.Positives
		caught += t.Caught
		quietOnly += t.QuietOnly
		missed += t.Missed
		falseFires += t.FalseFires
		decayed += t.Decayed
		if t.Decayed > 0 {
			decaying++
		}
		if t.Positives == 0 {
			none++
		}
		if t.Positives >= ev.MinPositives && t.Benign >= ev.MinBenign {
			enough++
		}
		if t.Missed > 0 {
			if len(t.Rules) == 0 {
				missedRows = append(missedRows, fmt.Sprintf("%s: no rule claims it, and %d labelled instance(s) "+
					"of it are in the corpus (entries %s)", t.Technique, t.Missed, entryList(t.MissedEntries, t.Missed)))
			} else {
				missedRows = append(missedRows, fmt.Sprintf("%s: %d of %d labelled instance(s) caught by none "+
					"of the %d rule(s) claiming it (entries %s)", t.Technique, t.Missed, t.Positives, len(t.Rules),
					entryList(t.MissedEntries, t.Missed)))
			}
		}
		if t.FalseFires > 0 {
			falseRows = append(falseRows, fmt.Sprintf("%s: a rule claiming it fired on %d of %d benign "+
				"entr(ies) from the sources it reads (entries %s)", t.Technique, t.FalseFires, t.Benign,
				entryList(t.FalseEntries, t.FalseFires)))
		}
	}
	caughtCheck := Check{Name: "caught", Passed: missed == 0,
		Detail: fmt.Sprintf("of %d labelled instance(s) counted across %d technique(s), %d were caught by a "+
			"rule claiming the technique that raises an alert, %d only by rules that raise nothing on their "+
			"own, and %d by none", positives, len(ev.Techniques), caught, quietOnly, missed)}
	var more int
	caughtCheck.Failures, more = capped(missedRows)
	if more > 0 {
		caughtCheck.Detail += fmt.Sprintf("; %d more technique(s) not listed", more)
	}
	quietCheck := Check{Name: "quiet-on-benign", Passed: falseFires == 0,
		Detail: fmt.Sprintf("rules raising an alert fired %d time(s) on entries labelled benign from the "+
			"sources they read, counted once for each technique they claim; the corpus labels %d of its %d "+
			"entries benign", falseFires, ev.Benign, ev.Entries)}
	quietCheck.Failures, more = capped(falseRows)
	if more > 0 {
		quietCheck.Detail += fmt.Sprintf("; %d more technique(s) not listed", more)
	}
	evidence := Check{Name: "evidence", Passed: true,
		Detail: fmt.Sprintf("%d of %d technique(s) have at least %d labelled instance(s) and %d benign "+
			"entr(ies) from the sources their rules read; %d have no labelled instance; the corpus labels "+
			"%d of its %d entries as instances of a technique", enough, len(ev.Techniques), ev.MinPositives,
			ev.MinBenign, none, ev.Labelled, ev.Entries)}
	checks := []Check{caughtCheck, quietCheck, evidence}
	if w := ev.Telemetry; w != nil {
		silent := ""
		if w.Silent > 0 {
			silent = fmt.Sprintf(", and %d more sent nothing", w.Silent)
		}
		checks = append(checks, Check{Name: "still-fires", Passed: true,
			Detail: fmt.Sprintf("between %s and %s, %d event(s) were read from the %d source(s) the rules "+
				"claiming these techniques read that sent any%s; %d instance(s) caught, in %d technique(s), "+
				"would not be caught with only the fields their source sent, and %d rule(s) catch none of "+
				"their own examples that way", w.Since, w.Until, w.Events, w.Sources, silent, decayed,
				decaying, ev.DarkCount)})
	}
	return checks
}

// validate refuses evidence whose shapes or numbers do not hold together,
// do not support the verdict, or do not account for every word the
// statement says.
func (ev *CoverageEvidence) validate(s *Statement) error {
	if ev.Entries < 1 || ev.Entries > maxCoverageCount || ev.Labelled < 0 || ev.Benign < 0 ||
		ev.Labelled+ev.Benign > ev.Entries {
		return fmt.Errorf("a coverage proof's corpus is its entries, some labelled as techniques and some benign")
	}
	if ev.MinPositives < 1 || ev.MinBenign < 1 || ev.MinPositives > 1_000_000 || ev.MinBenign > 1_000_000 {
		return fmt.Errorf("a technique is proven on at least one labelled instance and one benign event")
	}
	if len(ev.Rules) < 1 || len(ev.Rules) > MaxCoverageRules || ev.Unrecognised < 0 || ev.Unrecognised > maxCoverageCount {
		return fmt.Errorf("a coverage proof reads between 1 and %d rules", MaxCoverageRules)
	}
	for i, r := range ev.Rules {
		if !coverageRuleShape.MatchString(r.ID) || !hex64.MatchString(r.SHA256) || (i > 0 && ev.Rules[i-1].ID >= r.ID) {
			return fmt.Errorf("the rules read are each an id and a digest, in order, once each")
		}
		for j, t := range r.Techniques {
			if !detect.TechniqueShape.MatchString(t) || (j > 0 && r.Techniques[j-1] >= t) {
				return fmt.Errorf("a rule's techniques are ids of a known shape, in order, once each")
			}
		}
	}
	if len(ev.Techniques) < 1 || len(ev.Techniques) > MaxCoverageTechniques {
		return fmt.Errorf("a coverage proof covers between 1 and %d techniques", MaxCoverageTechniques)
	}
	if !ev.Asked {
		want := ev.claimed()
		if len(want) != len(ev.Techniques) {
			return fmt.Errorf("without techniques named, a coverage proof covers every one the rules claim")
		}
		for i, t := range ev.Techniques {
			if t.Technique != want[i] {
				return fmt.Errorf("without techniques named, a coverage proof covers every one the rules claim")
			}
		}
	}
	for i, t := range ev.Techniques {
		if !detect.TechniqueShape.MatchString(t.Technique) || (i > 0 && ev.Techniques[i-1].Technique >= t.Technique) {
			return fmt.Errorf("the techniques are ids of a known shape, in order, once each")
		}
		var rules []string
		for _, r := range ev.Rules {
			if r.claims(t.Technique) {
				rules = append(rules, r.ID)
			}
		}
		if strings.Join(rules, " ") != strings.Join(t.Rules, " ") || t.Rules == nil {
			return fmt.Errorf("%s's rules are the ones that claim it", t.Technique)
		}
		if err := t.wellFormed(ev); err != nil {
			return fmt.Errorf("%s: %w", t.Technique, err)
		}
		if t.RecallLow != recallLow(t.Caught, t.Positives) {
			return fmt.Errorf("%s's bound is not the one its counts give", t.Technique)
		}
		if t.Verdict != t.verdict(ev) {
			return fmt.Errorf("%s's counts make it %s, not %s", t.Technique, t.verdict(ev), t.Verdict)
		}
	}
	if ev.Asked && len(ev.Unclaimed) > 0 {
		return fmt.Errorf("with techniques named, a coverage proof lists no others")
	}
	for i, u := range ev.Unclaimed {
		if !detect.TechniqueShape.MatchString(u.Technique) || (i > 0 && ev.Unclaimed[i-1].Technique >= u.Technique) ||
			u.Positives < 1 || u.Positives > ev.Labelled || u.CaughtByOther < 0 || u.CaughtByOther > u.Positives {
			return fmt.Errorf("an unclaimed technique is an id the corpus labels, with how many and how many were caught")
		}
		for _, t := range ev.Techniques {
			if within(u.Technique, t.Technique) {
				return fmt.Errorf("%s is counted under %s, so it is not unclaimed", u.Technique, t.Technique)
			}
		}
	}
	if err := ev.validateWindow(); err != nil {
		return err
	}
	if len(s.Subject) != 1 || s.Subject[0].Name != SubjectCoverage || len(s.Subject[0].Digest) != 1 ||
		s.Subject[0].Digest["sha256"] != ev.subjectDigest() {
		return fmt.Errorf("a coverage proof is about the rules it read, by the digest of their listing")
	}
	if !coverageMaterials(s.Predicate.Materials, ev) {
		return fmt.Errorf("a coverage proof's materials are its corpus and, with telemetry, the fields its sources sent")
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the evidence makes this %s, not %s", want, s.Predicate.Verdict)
	}
	if s.Predicate.Claim != ev.claim() {
		return fmt.Errorf("the claim is not the sentence its evidence makes")
	}
	got, _ := json.Marshal(s.Predicate.Checks)
	want, _ := json.Marshal(ev.checks())
	if string(got) != string(want) {
		return fmt.Errorf("the checks are not the ones its evidence makes")
	}
	return nil
}

// wellFormed holds one technique's counts and lists together.
func (t TechniqueCoverage) wellFormed(ev *CoverageEvidence) error {
	for _, n := range []int{t.Positives, t.Caught, t.QuietOnly, t.Missed, t.Benign, t.FalseFires, t.Decayed} {
		if n < 0 || n > ev.Entries {
			return fmt.Errorf("a count is of corpus entries")
		}
	}
	if t.Caught+t.QuietOnly+t.Missed != t.Positives || t.Positives > ev.Labelled {
		return fmt.Errorf("its labelled instances are caught, caught only quietly, or missed")
	}
	if t.Benign > ev.Benign || t.FalseFires > t.Benign {
		return fmt.Errorf("its false fires are among the benign entries its rules read")
	}
	if len(t.Rules) == 0 && (t.Caught > 0 || t.QuietOnly > 0 || t.Benign > 0) {
		return fmt.Errorf("with no rule claiming it, nothing catches it and nothing is read for it")
	}
	if ev.Telemetry == nil && (t.Decayed != 0 || len(t.DecayedEntries) != 0) {
		return fmt.Errorf("decay is judged only against telemetry")
	}
	if t.Decayed > t.Caught {
		return fmt.Errorf("what decayed is among what was caught")
	}
	for _, l := range []struct {
		list []int
		of   int
	}{{t.MissedEntries, t.Missed}, {t.FalseEntries, t.FalseFires}, {t.DecayedEntries, t.Decayed}} {
		if len(l.list) != min(l.of, MaxCoverageEntries) {
			return fmt.Errorf("its entries are listed up to %d", MaxCoverageEntries)
		}
		for i, e := range l.list {
			if e < 1 || e > ev.Entries || (i > 0 && l.list[i-1] >= e) {
				return fmt.Errorf("an entry is named by its place in the corpus, in order, once")
			}
		}
	}
	return nil
}

func (ev *CoverageEvidence) validateWindow() error {
	w := ev.Telemetry
	if w == nil {
		if ev.DarkCount != 0 || len(ev.Dark) != 0 {
			return fmt.Errorf("a dark rule is judged only against telemetry")
		}
		return nil
	}
	since, err1 := time.Parse(time.RFC3339, w.Since)
	until, err2 := time.Parse(time.RFC3339, w.Until)
	if err1 != nil || err2 != nil || !since.Before(until) || since.UTC().Format(time.RFC3339) != w.Since ||
		until.UTC().Format(time.RFC3339) != w.Until {
		return fmt.Errorf("the telemetry is a window from one time to a later one")
	}
	if w.Sources < 0 || w.Silent < 0 || w.Sources+w.Silent > maxCoverageCount || w.Events < 0 ||
		w.Events > maxCoverageCount || w.Capped < 0 || w.Capped > w.Sources+w.Silent+maxCoverageCount ||
		w.PerSourceCap < 1 || !hex64.MatchString(w.Fields) {
		return fmt.Errorf("the telemetry window's counts are of sources and events, and its fields a digest")
	}
	if ev.DarkCount < len(ev.Dark) || len(ev.Dark) != min(ev.DarkCount, MaxFailures) || ev.DarkCount > len(ev.Rules) {
		return fmt.Errorf("the dark rules are those counted, listed up to %d", MaxFailures)
	}
	for i, d := range ev.Dark {
		if !coverageRuleShape.MatchString(d.Rule) || (i > 0 && ev.Dark[i-1].Rule >= d.Rule) ||
			(d.Silent && len(d.Missing) > 0) || len(d.Missing) > MaxDarkFields {
			return fmt.Errorf("a dark rule is a rule's id, and the fields it reads that were not sent")
		}
		known := false
		for _, r := range ev.Rules {
			known = known || r.ID == d.Rule
		}
		if !known {
			return fmt.Errorf("a dark rule is one of the rules read")
		}
		for _, f := range d.Missing {
			if !coverageFieldShape.MatchString(f) {
				return fmt.Errorf("a field a dark rule reads is named as a field")
			}
		}
	}
	return nil
}

// coverageMaterials reports whether the materials are the corpus and, with
// telemetry, the field listing — nothing the evidence does not account for.
func coverageMaterials(ms []Material, ev *CoverageEvidence) bool {
	want := 1
	if ev.Telemetry != nil {
		want = 2
	}
	if len(ms) != want || ms[0].Entries != ev.Entries || ms[0].Name == "telemetry-fields" {
		return false
	}
	if ev.Telemetry != nil {
		m := ms[1]
		return m.Name == "telemetry-fields" && m.Digest["sha256"] == ev.Telemetry.Fields && len(m.Digest) == 1 &&
			m.Entries == ev.Telemetry.Events
	}
	return true
}
