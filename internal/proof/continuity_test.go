// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"strings"
	"testing"
)

func dig(s string) string { return SHA256([]byte(s))["sha256"] }

// workflowRelease is a release made the way axios 1.14.0 was: trusted
// publishing from the project's workflow, with provenance, from a tag.
func workflowRelease(v string) *ContinuityRelease {
	return &ContinuityRelease{Version: v, Published: "2026-03-27T19:01:40Z", Listed: true, Provenance: true,
		Attestation: dig("statement " + v), Trusted: true, Publisher: dig("GitHub Actions"),
		Account: dig("GitHub Actions"), Repository: dig("https://github.com/axios/axios"),
		Workflow: dig(".github/workflows/publish.yml"), Ref: "tag",
		Commit: "46bee3dea75ef53a8eae49f3b7487e6341de6074"}
}

// tokenRelease is a release made the way axios 1.14.1 was: a person's
// account and a token, no provenance.
func tokenRelease(v, email string) *ContinuityRelease {
	return &ContinuityRelease{Version: v, Published: "2026-03-31T00:21:58Z", Listed: true,
		Publisher: dig("maintainer <" + email + ">"), Account: dig("maintainer")}
}

func continuityOf(t *testing.T, pkgs ...ContinuityPackage) *Statement {
	t.Helper()
	st, err := ProveContinuity(ContinuityInput{Bill: []byte(`{"bomFormat":"CycloneDX"}`), Program: "test", Now: tnow,
		Evidence: ContinuityEvidence{Packages: pkgs, Outside: 2, PublicRegistries: true}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestEachLossIsNamed(t *testing.T) {
	scripted := func(r *ContinuityRelease, s string) *ContinuityRelease { r.Scripts = dig(s); return r }
	for name, c := range map[string]struct {
		eco         string
		now, before *ContinuityRelease
		want        string
	}{
		"axios 1.14.1": {"npm", tokenRelease("1.14.1", "account-takeover@proton.example"), workflowRelease("1.14.0"),
			"provenance-lost,trusted-publishing-lost"},
		"axios 0.30.4": {"npm", tokenRelease("0.30.4", "account-takeover@proton.example"),
			tokenRelease("0.30.3", "maintainer@example.com"), "account-email-changed"},
		"another maintainer publishing": {"npm", &ContinuityRelease{Version: "2.0.1", Listed: true,
			Publisher: dig("lee <lee@example.com>"), Account: dig("lee")}, tokenRelease("2.0.0", "maintainer@example.com"), ""},
		"plain-crypto-js 4.2.1": {"npm", scripted(tokenRelease("4.2.1", "x@example.com"), "postinstall=node setup.js"),
			tokenRelease("4.2.0", "x@example.com"), "install-script-added"},
		"a changed script": {"npm", scripted(tokenRelease("1.0.1", "x@example.com"), "postinstall=node b.js"),
			scripted(tokenRelease("1.0.0", "x@example.com"), "postinstall=node a.js"), "install-script-changed"},
		"another repository": {"npm", func() *ContinuityRelease {
			r := workflowRelease("1.14.2")
			r.Repository = dig("https://github.com/someone-else/axios")
			return r
		}(), workflowRelease("1.14.0"), "repository-changed"},
		"another workflow": {"npm", func() *ContinuityRelease {
			r := workflowRelease("1.14.2")
			r.Workflow = dig(".github/workflows/other.yml")
			return r
		}(), workflowRelease("1.14.0"), "workflow-changed"},
		"from a branch": {"npm", func() *ContinuityRelease { r := workflowRelease("1.14.2"); r.Ref = "branch"; return r }(),
			workflowRelease("1.14.0"), "untagged"},
		"taken down": {"npm", &ContinuityRelease{Version: "1.14.1", Published: "2026-03-31T00:21:58Z"},
			workflowRelease("1.14.0"), "withdrawn"},
		"yanked": {"pypi", &ContinuityRelease{Version: "2.0.1", Listed: true, Yanked: true}, nil, "yanked"},
		"another artifact's provenance": {"npm", func() *ContinuityRelease {
			r := tokenRelease("1.14.2", "maintainer@example.com")
			r.Mismatch = true
			return r
		}(), tokenRelease("1.14.1", "maintainer@example.com"), "provenance-mismatch"},
		"a Go module's origin lost": {"golang", &ContinuityRelease{Version: "v1.9.4", Listed: true},
			&ContinuityRelease{Version: "v1.9.3", Listed: true, Repository: dig("https://github.com/sirupsen/logrus"), Ref: "tag"},
			"origin-lost"},
		"made the same way": {"npm", workflowRelease("1.14.2"), workflowRelease("1.14.0"), ""},
		// Gaining something is not losing anything.
		"to trusted publishing": {"npm", workflowRelease("1.13.5"), tokenRelease("1.13.2", "maintainer@example.com"), ""},
	} {
		got := strings.Join(ContinuityLosses(c.eco, c.now, c.before), ",")
		if got != c.want {
			t.Errorf("%s: lost %q, want %q", name, got, c.want)
		}
	}
}

func TestAPackageThatLostSomethingRefutesTheBill(t *testing.T) {
	st := continuityOf(t,
		ContinuityPackage{Purl: "pkg:npm/axios@1.14.1", Now: tokenRelease("1.14.1", "a@proton.example"),
			Before: workflowRelease("1.14.0")},
		ContinuityPackage{Purl: "pkg:npm/left-pad@1.3.0", Now: tokenRelease("1.3.0", "m@example.com"),
			Before: tokenRelease("1.2.0", "m@example.com")},
		ContinuityPackage{Purl: "pkg:npm/brand-new@1.0.0", Now: tokenRelease("1.0.0", "m@example.com")},
	)
	ev := st.Predicate.Continuity
	if st.Predicate.Verdict != Refuted || ev.Regressed != 1 || ev.Held != 1 || ev.First != 1 {
		t.Fatalf("verdict %s, %+v", st.Predicate.Verdict, ev)
	}
	c := st.Predicate.Checks[1]
	if c.Name != "continuity" || c.Passed || len(c.Failures) != 1 ||
		c.Failures[0] != "pkg:npm/axios@1.14.1, after 1.14.0: provenance-lost, trusted-publishing-lost" {
		t.Fatalf("continuity check %+v", c)
	}
	if !st.Predicate.Checks[0].Passed {
		t.Error("nothing was withdrawn")
	}
	if !strings.Contains(st.Predicate.Checks[2].Detail, "2 component(s)") {
		t.Errorf("read: %s", st.Predicate.Checks[2].Detail)
	}
	// Nothing anybody chose is in it as text.
	for _, word := range []string{"maintainer", "proton", "GitHub Actions", "axios/axios", "publish.yml"} {
		b, _ := jsonOf(st)
		if strings.Contains(b, word) {
			t.Errorf("the proof carries %q", word)
		}
	}
}

func TestAnUnreadPackageLeavesTheBillInconclusive(t *testing.T) {
	st := continuityOf(t,
		ContinuityPackage{Purl: "pkg:npm/left-pad@1.3.0", Now: tokenRelease("1.3.0", "m@example.com"),
			Before: tokenRelease("1.2.0", "m@example.com")},
		ContinuityPackage{Purl: "pkg:npm/internal-only@1.0.0", Unread: UnreadNoPackage},
	)
	if st.Predicate.Verdict != Inconclusive || st.Predicate.Continuity.Unread != 1 {
		t.Fatalf("verdict %s", st.Predicate.Verdict)
	}
	// A withdrawn release refutes whatever else could not be read.
	st = continuityOf(t, ContinuityPackage{Purl: "pkg:npm/axios@1.14.1", Unread: UnreadProvenance,
		Now: &ContinuityRelease{Version: "1.14.1"}})
	if st.Predicate.Verdict != Refuted || st.Predicate.Continuity.Packages[0].Outcome != ContinuityRegressed {
		t.Fatalf("withdrawn and unread: %s", st.Predicate.Verdict)
	}
	// Everything read and held is proven; an empty bill is not.
	st = continuityOf(t, ContinuityPackage{Purl: "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
		Now:    &ContinuityRelease{Version: "v1.9.3", Listed: true, Repository: dig("r"), Ref: "tag"},
		Before: &ContinuityRelease{Version: "v1.9.2", Listed: true, Repository: dig("r"), Ref: "tag"}})
	if st.Predicate.Verdict != Proven {
		t.Fatalf("held: %s", st.Predicate.Verdict)
	}
	if st = continuityOf(t); st.Predicate.Verdict != Inconclusive {
		t.Fatalf("an empty bill: %s", st.Predicate.Verdict)
	}
}

func TestAnEditedContinuityProofIsRefused(t *testing.T) {
	fresh := func() *Statement {
		return continuityOf(t,
			ContinuityPackage{Purl: "pkg:npm/axios@1.14.1", Now: tokenRelease("1.14.1", "a@proton.example"),
				Before: workflowRelease("1.14.0")},
			ContinuityPackage{Purl: "pkg:npm/left-pad@1.3.0", Now: tokenRelease("1.3.0", "m@example.com"),
				Before: tokenRelease("1.2.0", "m@example.com")},
			ContinuityPackage{Purl: "pkg:pypi/urllib3@2.5.0", Now: &ContinuityRelease{Version: "2.5.0", Listed: true,
				Provenance: true, Trusted: true, Attestation: dig("s")}},
			ContinuityPackage{Purl: "pkg:npm/internal-only@1.0.0", Unread: UnreadRegistry},
		)
	}
	if err := fresh().Validate(); err != nil {
		t.Fatalf("unedited: %v", err)
	}
	for name, edit := range map[string]func(*ContinuityEvidence, *Statement){
		"a loss hidden":   func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Lost = nil },
		"a loss made up":  func(ev *ContinuityEvidence, _ *Statement) { pkgAt(ev, "left-pad").Lost = []string{LostTag} },
		"an outcome":      func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Outcome = ContinuityHeld },
		"the provenance":  func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Now.Provenance = true },
		"a count":         func(ev *ContinuityEvidence, _ *Statement) { ev.Held++ },
		"a name as text":  func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Now.Publisher = "maintainer" },
		"a ref word":      func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Before.Ref = "refs/tags/v1" },
		"a commit":        func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Before.Commit = "HEAD" },
		"another version": func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Now.Version = "1.14.0" },
		"a later before":  func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Before.Version = "1.15.0" },
		"an unread word":  func(ev *ContinuityEvidence, _ *Statement) { pkgAt(ev, "internal-only").Unread = "busy" },
		"out of order": func(ev *ContinuityEvidence, _ *Statement) {
			ev.Packages[0], ev.Packages[1] = ev.Packages[1], ev.Packages[0]
		},
		"a purl that is not one": func(ev *ContinuityEvidence, _ *Statement) {
			ev.Packages[0].Purl = "pkg:npm/axios@1.14.1 (see https://evil.example)"
		},
		"another ecosystem": func(ev *ContinuityEvidence, _ *Statement) { ev.Packages[0].Purl = "pkg:maven/axios@1.14.1" },
		"a PyPI script": func(ev *ContinuityEvidence, _ *Statement) {
			pkgAt(ev, "urllib3").Now.Scripts = dig("x")
		},
		"a removed release with a publisher": func(ev *ContinuityEvidence, _ *Statement) {
			pkgAt(ev, "left-pad").Now.Listed = false
		},
		"an unread package with a predecessor": func(ev *ContinuityEvidence, _ *Statement) {
			pkgAt(ev, "internal-only").Before = workflowRelease("0.9.0")
		},
		"the claim":   func(_ *ContinuityEvidence, s *Statement) { s.Predicate.Claim = "All is well." },
		"a failure":   func(_ *ContinuityEvidence, s *Statement) { s.Predicate.Checks[1].Failures[0] = "fine" },
		"the verdict": func(_ *ContinuityEvidence, s *Statement) { s.Predicate.Verdict = Inconclusive },
		"a material": func(_ *ContinuityEvidence, s *Statement) {
			s.Predicate.Materials = []Material{{Name: "x", Digest: SHA256(nil)}}
		},
		"the registry": func(ev *ContinuityEvidence, _ *Statement) { ev.PublicRegistries = false },
	} {
		st := fresh()
		edit(st.Predicate.Continuity, st)
		if err := st.Validate(); err == nil {
			t.Errorf("%s: the edited proof validates", name)
		}
	}
}

func jsonOf(st *Statement) (string, error) {
	b, err := json.Marshal(st)
	return string(b), err
}

func pkgAt(ev *ContinuityEvidence, name string) *ContinuityPackage {
	for i := range ev.Packages {
		if strings.Contains(ev.Packages[i].Purl, "/"+name+"@") {
			return &ev.Packages[i]
		}
	}
	panic("no package " + name)
}

// A forger who edits the evidence and then rebuilds every word the evidence
// makes — what each package lost, its outcome, the counts, the checks, the
// claim and the verdict — is left with only the evidence's own shapes to
// get past.
func TestAContinuityForgeryThatRebuildsItsWordsIsRefused(t *testing.T) {
	fresh := func() *Statement {
		return continuityOf(t,
			ContinuityPackage{Purl: "pkg:npm/axios@1.14.1", Now: tokenRelease("1.14.1", "a@proton.example"),
				Before: workflowRelease("1.14.0")},
			ContinuityPackage{Purl: "pkg:npm/left-pad@1.3.0", Now: tokenRelease("1.3.0", "m@example.com"),
				Before: tokenRelease("1.2.0", "m@example.com")},
			ContinuityPackage{Purl: "pkg:pypi/urllib3@2.5.0", Now: &ContinuityRelease{Version: "2.5.0", Listed: true,
				Provenance: true, Trusted: true, Attestation: dig("s")}},
		)
	}
	rebuild := func(ev *ContinuityEvidence, s *Statement, derive bool) {
		if derive {
			ev.Held, ev.Regressed, ev.First, ev.Unread = 0, 0, 0, 0
			for i := range ev.Packages {
				p := &ev.Packages[i]
				p.Lost = ContinuityLosses(ecosystemOf(p.Purl), p.Now, p.Before)
				p.Outcome = ContinuityOutcome(*p)
				ev.count(p.Outcome)
			}
		}
		s.Predicate.Claim, s.Predicate.Checks, s.Predicate.Verdict = ev.claim(), ev.checks(), ev.verdict()
	}
	for name, c := range map[string]struct {
		edit   func(*ContinuityEvidence)
		derive bool
	}{
		"an outcome that is not its losses'": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "axios").Outcome = ContinuityUnread
			ev.Regressed, ev.Unread = 0, 1
		}, false},
		"a count that no check repeats": {func(ev *ContinuityEvidence) { ev.Regressed = 2 }, false},
		"a held release called a first one": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "left-pad").Outcome = ContinuityFirst
			ev.Held, ev.First = ev.Held-1, ev.First+1
		}, false},
		"a removed release that says who published it": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "left-pad").Now.Listed = false
		}, true},
		"provenance with no attestation": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "urllib3").Now.Attestation = ""
		}, true},
		"an attestation with no provenance": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "left-pad").Now.Attestation = dig("x")
		}, true},
		"provenance and a mismatch at once": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "urllib3").Now.Mismatch = true
		}, true},
		"PyPI provenance from no trusted publisher": {func(ev *ContinuityEvidence) {
			pkgAt(ev, "urllib3").Now.Trusted = false
		}, true},
	} {
		st := fresh()
		c.edit(st.Predicate.Continuity)
		rebuild(st.Predicate.Continuity, st, c.derive)
		if err := st.Validate(); err == nil {
			t.Errorf("%s: the rebuilt forgery validates", name)
		}
	}
	st := fresh()
	st.Subject[0].Name = "rules"
	if err := st.Validate(); err == nil {
		t.Error("a continuity proof about something other than a bill validates")
	}
}
