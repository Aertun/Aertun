// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// The registries' answers are internal/registry's fixtures: captured, except
// the axios document of the morning of 31 March 2026, shaped as public
// reports describe it, and the dependency it pulled in.
func serveRegistries(t *testing.T, axios string) {
	t.Helper()
	routes := map[string]string{
		"https://registry.npmjs.org/axios":                                                   "npm-axios-" + axios + ".json",
		"https://registry.npmjs.org/-/npm/v1/attestations/axios@1.14.0":                      "npm-axios-attestations-1.14.0.json",
		"https://registry.npmjs.org/plain-crypto-js":                                         "npm-plain-crypto-js.json",
		"https://pypi.org/pypi/urllib3/json":                                                 "pypi-urllib3.json",
		"https://pypi.org/integrity/urllib3/2.5.0/urllib3-2.5.0-py3-none-any.whl/provenance": "pypi-urllib3-2.5.0-whl.json",
		"https://pypi.org/integrity/urllib3/2.4.0/urllib3-2.4.0-py3-none-any.whl/provenance": "pypi-urllib3-2.4.0-whl.json",
		"https://proxy.golang.org/github.com/sirupsen/logrus/@v/list":                        "go-logrus-list.txt",
		"https://proxy.golang.org/github.com/sirupsen/logrus/@v/v1.9.3.info":                 "go-logrus-v1.9.3.json",
		"https://proxy.golang.org/github.com/sirupsen/logrus/@v/v1.9.2.info":                 "go-logrus-v1.9.2.json",
	}
	was := registryGetter
	registryGetter = func(_ context.Context, url string) ([]byte, int, error) {
		file, ok := routes[url]
		if !ok {
			return []byte(`{"error":"Not found"}`), 404, nil
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "registry", "testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		return b, 200, nil
	}
	t.Cleanup(func() { registryGetter = was })
}

func billOf(t *testing.T, purls ...string) string {
	t.Helper()
	var parts []string
	for i, p := range purls {
		parts = append(parts, `{"type":"library","bom-ref":"c`+string(rune('a'+i))+`","name":"x","purl":"`+p+`"}`)
	}
	body := `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application",` +
		`"bom-ref":"app","name":"shop"}},"components":[` + strings.Join(parts, ",") + `]}`
	at := filepath.Join(t.TempDir(), "bom.json")
	if err := os.WriteFile(at, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return at
}

func continuityRun(t *testing.T, root, bill string) (*proof.Statement, error) {
	t.Helper()
	key, pub := signingFiles(t)
	out := filepath.Join(t.TempDir(), "continuity.json")
	err := cmdVuln(root, []string{"continuity", bill, "--key", key, "--public-key", pub, "--out", out})
	if _, serr := os.Stat(out); serr != nil {
		return nil, err
	}
	return readStatement(t, out, pub), err
}

// The axios releases of 31 March 2026, as the registry served them that
// morning: the gate refuses the install, and names what each lost.
func TestContinuityRefusesTheAxiosReleasesAsTheyWerePublished(t *testing.T) {
	root := reconcileSite(t)
	serveRegistries(t, "2026-03-31")
	bill := billOf(t, "pkg:npm/axios@1.14.1", "pkg:npm/axios@0.30.4", "pkg:npm/plain-crypto-js@4.2.1",
		"pkg:pypi/urllib3@2.5.0", "pkg:golang/github.com/sirupsen/logrus@v1.9.3",
		"pkg:maven/org.example/lib@1.0", "pkg:npm/axios@1.14.1")
	st, err := continuityRun(t, root, bill)
	if err == nil || !strings.Contains(err.Error(), "refuted") {
		t.Fatalf("the gate let it through: %v", err)
	}
	ev := st.Predicate.Continuity
	lost := map[string]string{}
	outcome := map[string]string{}
	for _, p := range ev.Packages {
		lost[p.Purl] = strings.Join(p.Lost, ",")
		outcome[p.Purl] = p.Outcome
	}
	for purl, want := range map[string]string{
		"pkg:npm/axios@1.14.1":                         "provenance-lost,trusted-publishing-lost",
		"pkg:npm/axios@0.30.4":                         "account-email-changed",
		"pkg:npm/plain-crypto-js@4.2.1":                "install-script-added",
		"pkg:pypi/urllib3@2.5.0":                       "",
		"pkg:golang/github.com/sirupsen/logrus@v1.9.3": "",
	} {
		if lost[purl] != want {
			t.Errorf("%s lost %q, want %q", purl, lost[purl], want)
		}
	}
	if outcome["pkg:pypi/urllib3@2.5.0"] != "held" || outcome["pkg:golang/github.com/sirupsen/logrus@v1.9.3"] != "held" {
		t.Errorf("outcomes %v", outcome)
	}
	if len(ev.Packages) != 5 || ev.Outside != 1 || !ev.PublicRegistries {
		t.Errorf("packages %d, outside %d, public %v", len(ev.Packages), ev.Outside, ev.PublicRegistries)
	}
	if !auditHas(t, root, "continuity.proved", map[string]string{"verdict": "refuted", "regressed": "3"}) {
		t.Error("the audit log does not record it")
	}
	if kept, err := proofstore.List(root); err != nil || len(kept) != 1 {
		t.Errorf("kept %d: %v", len(kept), err)
	}
}

// The same bill today: npm has taken both releases down, and keeps when
// they were published.
func TestContinuityRefusesAReleaseItsRegistryTookDown(t *testing.T) {
	root := reconcileSite(t)
	serveRegistries(t, "today")
	st, err := continuityRun(t, root, billOf(t, "pkg:npm/axios@1.14.1"))
	if err == nil {
		t.Fatal("a withdrawn release passed")
	}
	p := st.Predicate.Continuity.Packages[0]
	if strings.Join(p.Lost, ",") != "withdrawn" || p.Now == nil || p.Now.Listed || p.Now.Published == "" {
		t.Fatalf("%+v %+v", p, p.Now)
	}
}

func TestContinuityProvesABillMadeTheWayItsPredecessorsWere(t *testing.T) {
	root := reconcileSite(t)
	serveRegistries(t, "today")
	st, err := continuityRun(t, root, billOf(t, "pkg:pypi/urllib3@2.5.0",
		"pkg:golang/github.com/sirupsen/logrus@v1.9.3", "pkg:npm/axios@1.14.0"))
	if err != nil {
		t.Fatalf("a bill that held: %v", err)
	}
	if st.Predicate.Verdict != proof.Proven || st.Predicate.Continuity.Held != 3 {
		t.Fatalf("%s %+v", st.Predicate.Verdict, st.Predicate.Continuity)
	}
}

func TestContinuityIsInconclusiveOnWhatItCannotRead(t *testing.T) {
	root := reconcileSite(t)
	serveRegistries(t, "today")
	st, err := continuityRun(t, root, billOf(t, "pkg:npm/our-internal-lib@1.0.0", "pkg:npm/axios@1.14.0"))
	if err == nil || !strings.Contains(err.Error(), "inconclusive") {
		t.Fatalf("%v", err)
	}
	if p := st.Predicate.Continuity.Packages[1]; p.Unread != proof.UnreadNoPackage {
		t.Fatalf("%+v", p)
	}
}

func TestContinuityRefusesWhatItCannotUse(t *testing.T) {
	root := reconcileSite(t)
	key, _ := signingFiles(t)
	bill := billOf(t, "pkg:npm/axios@1.14.0")
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no bill": {[]string{"continuity", "--key", key}, "bill of materials FILE"},
		"no key":  {[]string{"continuity", bill}, "--key FILE"},
		"a registry over http": {[]string{"continuity", bill, "--key", key, "--npm", "http://registry.example"},
			"https"},
		"a registry inside": {[]string{"continuity", bill, "--key", key, "--pypi", "https://127.0.0.1"},
			"refusing"},
	} {
		if err := cmdVuln(root, c.args); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	notBill := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(notBill, []byte(`{"hello":1}`), 0o600)
	if err := cmdVuln(root, []string{"continuity", notBill, "--key", key}); err == nil {
		t.Error("a file that is no bill was read as one")
	}
}

// Signing what the registries said in the organisation's name takes tune.
func TestContinuityTakesTune(t *testing.T) {
	windtunnelOutput(t)
	root := reconcileSite(t)
	serveRegistries(t, "today")
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "analyst"})
	asOnly(t, root, "sam")
	key, _ := signingFiles(t)
	if err := cmdVuln(root, []string{"continuity", billOf(t, "pkg:npm/axios@1.14.0"), "--key", key}); err == nil ||
		strings.Contains(err.Error(), "proven") {
		t.Fatalf("an analyst signed a continuity proof: %v", err)
	}
}

func TestABillsPackagesAreReadOnceEachInOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/%40scope/pkg@1.0.0":                   "pkg:npm/%40scope/pkg@1.0.0",
		"pkg:npm/@scope/pkg@1.0.0":                     "pkg:npm/%40scope/pkg@1.0.0",
		"pkg:pypi/URLLib3@2.5.0":                       "pkg:pypi/urllib3@2.5.0",
		"pkg:golang/github.com/BurntSushi/toml@v1.4.0": "pkg:golang/github.com/BurntSushi/toml@v1.4.0",
		"pkg:npm/axios@1.14.0?repository_url=x":        "pkg:npm/axios@1.14.0",
	} {
		typ, name, v, ok := purlParts(in)
		if !ok {
			t.Errorf("%s did not read", in)
			continue
		}
		if got := canonicalPurl(billPackage{ecosystem: typ, name: name, version: v}); got != want {
			t.Errorf("%s is written %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"pkg:maven/a/b@1", "pkg:npm/axios", "npm/axios@1", "pkg:npm/axios@1 2"} {
		if _, _, _, ok := purlParts(bad); ok {
			t.Errorf("%s read as a package of an ecosystem read here", bad)
		}
	}
}
