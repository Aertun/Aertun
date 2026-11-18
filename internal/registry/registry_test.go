// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures are the registries' own answers, captured, except where a
// name says otherwise: npm-axios-2026-03-31.json is the axios document
// shaped as public reports describe it on the morning the two compromised
// releases were live, with every maintainer's identity replaced; and
// npm-plain-crypto-js.json is the dependency they pulled in, likewise.

// Serve answers each URL from a file, and anything else with a 404.
func Serve(t *testing.T, routes map[string]string) Getter {
	t.Helper()
	return func(_ context.Context, url string) ([]byte, int, error) {
		file, ok := routes[url]
		if !ok {
			return []byte(`{"error":"Not found"}`), 404, nil
		}
		if strings.HasPrefix(file, "{") {
			return []byte(file), 200, nil
		}
		b, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		return b, 200, nil
	}
}

// Routes are the fixtures, at the public registries' addresses.
func Routes(axios string) map[string]string {
	return map[string]string{
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
}

func read(t *testing.T, eco, name string, routes map[string]string) (Registry, map[string]*Release) {
	t.Helper()
	reg, ok := For(eco, Public, Serve(t, routes))
	if !ok {
		t.Fatalf("no registry for %s", eco)
	}
	all, err := reg.Releases(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return reg, all
}

func TestAnNPMReleaseIsReadWithItsProvenance(t *testing.T) {
	reg, all := read(t, NPM, "axios", Routes("2026-03-31"))
	good := all["1.14.0"]
	if err := Detailed(context.Background(), reg, "axios", good); err != nil {
		t.Fatal(err)
	}
	if !good.Listed || !good.Provenance || good.Mismatch || !good.Trusted || len(good.Attestation) != 64 {
		t.Fatalf("1.14.0: %+v", good)
	}
	if good.Repository != "https://github.com/axios/axios" || good.Workflow != ".github/workflows/publish.yml" ||
		good.RefKind() != RefTag || good.Commit != "46bee3dea75ef53a8eae49f3b7487e6341de6074" {
		t.Fatalf("1.14.0 built from %q %q %q %q", good.Repository, good.Workflow, good.Ref, good.Commit)
	}
	bad := all["1.14.1"]
	if err := Detailed(context.Background(), reg, "axios", bad); err != nil {
		t.Fatal(err)
	}
	if bad.Provenance || bad.Trusted || bad.Account != "maintainer" || bad.Scripts != "" {
		t.Fatalf("1.14.1: %+v", bad)
	}
	for v, want := range map[string]string{"1.14.1": "1.14.0", "0.30.4": "0.30.3", "1.14.0": "0.30.3"} {
		got, ok := Predecessor(all, v)
		if !ok || got == nil || got.Version != want {
			t.Errorf("before %s: %v", v, got)
		}
	}
}

// A release the registry has taken down keeps its time and nothing else,
// and is never the release another is held to.
func TestARemovedNPMReleaseIsKnownAndNeverAPredecessor(t *testing.T) {
	_, all := read(t, NPM, "axios", Routes("today"))
	gone := all["1.14.1"]
	if gone == nil || gone.Listed || gone.Published.IsZero() {
		t.Fatalf("1.14.1 today: %+v", gone)
	}
	if got, _ := Predecessor(all, "1.14.2"); got == nil || got.Version != "1.14.0" {
		t.Errorf("before 1.14.2: %v", got)
	}
	if all["1.14.2"] != nil {
		t.Error("a release nobody published is known")
	}
}

func TestAnInstallScriptIsRead(t *testing.T) {
	_, all := read(t, NPM, "plain-crypto-js", Routes("today"))
	if all["4.2.0"].Scripts != "" || all["4.2.1"].Scripts != "postinstall=node setup.js" {
		t.Fatalf("scripts %q / %q", all["4.2.0"].Scripts, all["4.2.1"].Scripts)
	}
}

// An attestation about another artifact is not provenance for this one.
func TestAnAttestationAboutAnotherArtifactIsAMismatch(t *testing.T) {
	routes := Routes("2026-03-31")
	b, err := os.ReadFile(filepath.Join("testdata", "npm-axios-2026-03-31.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	v := doc["versions"].(map[string]any)["1.14.1"].(map[string]any)
	v["dist"].(map[string]any)["attestations"] = map[string]any{
		"provenance": map[string]any{"predicateType": "https://slsa.dev/provenance/v1"}}
	forged, _ := json.Marshal(doc)
	routes["https://registry.npmjs.org/axios"] = string(forged)
	routes["https://registry.npmjs.org/-/npm/v1/attestations/axios@1.14.1"] = "npm-axios-attestations-1.14.0.json"
	reg, all := read(t, NPM, "axios", routes)
	r := all["1.14.1"]
	if err := Detailed(context.Background(), reg, "axios", r); err != nil {
		t.Fatal(err)
	}
	if r.Provenance || !r.Mismatch || r.Attestation != "" {
		t.Fatalf("1.14.0's attestation served for 1.14.1: %+v", r)
	}
	// Said to have provenance, and none to be read: not counted as any.
	delete(routes, "https://registry.npmjs.org/-/npm/v1/attestations/axios@1.14.1")
	reg, all = read(t, NPM, "axios", routes)
	if err := Detailed(context.Background(), reg, "axios", all["1.14.1"]); err == nil {
		t.Error("provenance said and not served was read as none")
	}
}

func TestAPyPIReleaseIsReadWithItsTrustedPublisher(t *testing.T) {
	reg, all := read(t, PyPI, "urllib3", Routes("today"))
	for _, v := range []string{"2.4.0", "2.5.0"} {
		r := all[v]
		if err := Detailed(context.Background(), reg, "urllib3", r); err != nil {
			t.Fatal(err)
		}
		if !r.Provenance || !r.Trusted || r.Repository != "github:urllib3/urllib3" || r.Workflow != "publish.yml" ||
			r.Published.IsZero() || r.Yanked {
			t.Fatalf("%s: %+v", v, r)
		}
	}
	if got, _ := Predecessor(all, "2.5.0"); got == nil || got.Version != "2.4.0" {
		t.Errorf("before 2.5.0: %v", got)
	}
	// Named as people write it, it is read as PyPI spells it.
	if pypiName("URLLib3") != "urllib3" || pypiName("Foo__Bar.baz") != "foo-bar-baz" {
		t.Error("PEP 503 normalisation")
	}
}

func TestAGoModuleIsReadWithItsOrigin(t *testing.T) {
	reg, all := read(t, Go, "github.com/sirupsen/logrus", Routes("today"))
	r := all["v1.9.3"]
	if err := Detailed(context.Background(), reg, "github.com/sirupsen/logrus", r); err != nil {
		t.Fatal(err)
	}
	if r.Repository != "https://github.com/sirupsen/logrus" || r.RefKind() != RefTag ||
		r.Commit != "d40e25cd45ed9c6b2b66e6b97573a0413e4c23bd" || r.Provenance {
		t.Fatalf("v1.9.3: %+v", r)
	}
	if got, _ := Predecessor(all, "v1.9.3"); got == nil || got.Version != "v1.9.2" {
		t.Errorf("before v1.9.3: %v", got)
	}
	if goEscape("github.com/BurntSushi/toml") != "github.com/!burnt!sushi/toml" {
		t.Error("the proxy's case escaping")
	}
}

func TestAPackageNobodyHasIsToldApart(t *testing.T) {
	reg, _ := For(NPM, Public, Serve(t, nil))
	if _, err := reg.Releases(context.Background(), "no-such-package"); err != ErrNoPackage {
		t.Fatalf("a missing package: %v", err)
	}
	broken := func(context.Context, string) ([]byte, int, error) { return nil, 503, nil }
	reg, _ = For(NPM, Public, broken)
	if _, err := reg.Releases(context.Background(), "axios"); err == nil || err == ErrNoPackage {
		t.Fatalf("a registry that did not answer: %v", err)
	}
	if npmDocName("@scope/pkg") != "@scope%2Fpkg" {
		t.Errorf("scoped name %q", npmDocName("@scope/pkg"))
	}
}

// A version that does not order has no predecessor, and says so.
func TestAVersionThatDoesNotOrderHasNoPredecessor(t *testing.T) {
	all := map[string]*Release{"1.0.0": {Version: "1.0.0", Listed: true}, "2.0.0-rc1": {Version: "2.0.0-rc1", Listed: true}}
	if _, ok := Predecessor(all, "v0.0.0-20230101000000-abcdef123456"); ok {
		t.Error("a pseudo-version was ordered")
	}
	if got, ok := Predecessor(all, "2.0.0"); !ok || got.Version != "1.0.0" {
		t.Errorf("a release is held to a release, not a pre-release: %v", got)
	}
	if got, ok := Predecessor(all, "1.0.0"); !ok || got != nil {
		t.Errorf("a first release: %v", got)
	}
}

// A PyPI attestation about another file is not provenance for this one.
func TestAPyPIAttestationAboutAnotherFileIsAMismatch(t *testing.T) {
	routes := Routes("today")
	routes["https://pypi.org/integrity/urllib3/2.4.0/urllib3-2.4.0-py3-none-any.whl/provenance"] =
		"pypi-urllib3-2.5.0-whl.json"
	reg, all := read(t, PyPI, "urllib3", routes)
	r := all["2.4.0"]
	if err := Detailed(context.Background(), reg, "urllib3", r); err != nil {
		t.Fatal(err)
	}
	if r.Provenance || !r.Mismatch || r.Trusted {
		t.Fatalf("2.5.0's attestation served for 2.4.0: %+v", r)
	}
}

// A release of an old line published since is not what came before.
func TestAPredecessorWasPublishedBefore(t *testing.T) {
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	all := map[string]*Release{
		"22.15.0": {Version: "22.15.0", Listed: true, Published: at("2025-05-01T00:00:00Z")},
		"22.20.5": {Version: "22.20.5", Listed: true, Published: at("2026-10-01T00:00:00Z")},
		"24.0.0":  {Version: "24.0.0", Listed: true, Published: at("2025-06-10T00:00:00Z")},
	}
	if got, ok := Predecessor(all, "24.0.0"); !ok || got == nil || got.Version != "22.15.0" {
		t.Fatalf("before 24.0.0: %v", got)
	}
	// With no times, the order of versions alone.
	for _, r := range all {
		r.Published = time.Time{}
	}
	if got, _ := Predecessor(all, "24.0.0"); got == nil || got.Version != "22.20.5" {
		t.Fatalf("before 24.0.0 without times: %v", got)
	}
}
