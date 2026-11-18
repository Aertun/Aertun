// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package referee

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commit = "46bee3dea75ef53a8eae49f3b7487e6341de6074"

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func goodReport() string {
	return `{"format":"aertun/vuln-report/v1","title":"ignored","package":"pkg:npm/tiny-parse@2.1.0",` +
		`"commit":"` + commit + `","affected":{"introduced":"2.0.0","fixed":"2.1.1"},` +
		`"locations":[{"file":"lib/header.js","function":"parseHeader","line":3}],"cwe":"CWE-1333",` +
		`"cvss":{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","score":7.5,"severity":"high"}}`
}

func TestAReportIsReadStrictly(t *testing.T) {
	r, err := Parse([]byte(goodReport()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Ecosystem() != "npm" || r.Name() != "tiny-parse" || r.Version() != "2.1.0" {
		t.Fatalf("%s %s %s", r.Ecosystem(), r.Name(), r.Version())
	}
	for name, edit := range map[string][2]string{
		"an unknown field":       {`"title":"ignored"`, `"title":"ignored","exploited":true`},
		"another format":         {`aertun/vuln-report/v1`, `aertun/vuln-report/v9`},
		"no version":             {`tiny-parse@2.1.0`, `tiny-parse`},
		"a short commit":         {commit, commit[:12]},
		"a path out":             {`lib/header.js`, `../../etc/passwd`},
		"an absolute path":       {`lib/header.js`, `/etc/passwd`},
		"a path not clean":       {`lib/header.js`, `lib/./header.js`},
		"a function with spaces": {`parseHeader`, `parse Header(); rm -rf`},
		"a severity made up":     {`"severity":"high"`, `"severity":"severe"`},
		"a score past ten":       {`"score":7.5`, `"score":11`},
		"a weakness made up":     {`CWE-1333`, `ReDoS`},
	} {
		if _, err := Parse([]byte(strings.Replace(goodReport(), edit[0], edit[1], 1))); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := Parse([]byte(strings.Replace(goodReport(), `"locations":[{"file":"lib/header.js","function":"parseHeader","line":3}]`, `"locations":[]`, 1))); err == nil {
		t.Error("a report citing nothing was read")
	}
}

// Two reports of one flaw share a fingerprint whatever lines they cite and
// in whatever order; another version of the package is the same flaw.
func TestAFingerprintIsTheFlawNotTheWording(t *testing.T) {
	a, _ := Parse([]byte(goodReport()))
	b, _ := Parse([]byte(strings.NewReplacer(`"line":3`, `"line":40`, `"title":"ignored"`, `"title":"Another title"`,
		`tiny-parse@2.1.0`, `tiny-parse@2.0.5`).Replace(goodReport())))
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("the same flaw has two fingerprints")
	}
	c, _ := Parse([]byte(strings.Replace(goodReport(), `CWE-1333`, `CWE-787`, 1)))
	d, _ := Parse([]byte(strings.Replace(goodReport(), `parseHeader`, `parseBody`, 1)))
	if a.Fingerprint() == c.Fingerprint() || a.Fingerprint() == d.Fingerprint() {
		t.Error("two flaws share a fingerprint")
	}
}

func TestADefinitionIsFoundInEachLanguage(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"a.go":    "package a\n\nfunc (h *Header) Parse(b []byte) error {\n\treturn nil\n}\nfunc plain[T any](x T) {}\n",
		"b.js":    "export function parseHeader(s) {}\nconst parseBody = async (s) => s\nclass P { static split(x) { return x } }\n",
		"c.py":    "class Reader:\n    async def read_header(self):\n        pass\n",
		"d.c":     "static int\nparse_header(const char *s, size_t n)\n{\n\treturn 0;\n}\nint other(void);\n",
		"e.rs":    "pub fn decode<T>(x: T) {}\n",
		"f.java":  "public class X {\n  public static int parse(String s) throws IOException {\n    return 0;\n  }\n}\n",
		"g.rb":    "def self.load(x)\nend\n",
		"h.php":   "function &render($x) {}\n",
		"i.ex":    "defmodule M do\n  def handle(x), do: x\nend\n",
		"link.js": "",
		"README":  "nothing here\n",
	})
	for loc, want := range map[Location]string{
		{File: "a.go", Function: "Header.Parse"}:       Defined,
		{File: "a.go", Function: "plain"}:              Defined,
		{File: "a.go", Function: "Missing"}:            NotDefined,
		{File: "a.go", Function: "Body.Parse"}:         NotDefined,
		{File: "b.js", Function: "parseHeader"}:        Defined,
		{File: "b.js", Function: "parseBody"}:          Defined,
		{File: "b.js", Function: "P.split"}:            Defined,
		{File: "c.py", Function: "Reader.read_header"}: Defined,
		{File: "d.c", Function: "parse_header"}:        Defined,
		{File: "d.c", Function: "other"}:               NotDefined,
		{File: "e.rs", Function: "decode"}:             Defined,
		{File: "f.java", Function: "X.parse"}:          Defined,
		{File: "g.rb", Function: "load"}:               Defined,
		{File: "h.php", Function: "render"}:            Defined,
		{File: "i.ex", Function: "handle"}:             Mentioned,
		{File: "i.ex", Function: "absent"}:             NotDefined,
		{File: "nope.go", Function: "Parse"}:           NoFile,
		{File: "a.go", Function: "plain", Line: 7}:     PastEnd,
		{File: "a.go", Function: "plain", Line: 6}:     Defined,
	} {
		_, got, err := Locate(root, loc)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s in %s: %s, want %s", loc.Function, loc.File, got, want)
		}
	}
}

// A cited path cannot leave the source through a link inside it.
func TestACitedPathStaysInsideTheSource(t *testing.T) {
	outside := t.TempDir()
	write(t, outside, map[string]string{"secret.go": "package s\nfunc Steal() {}\n"})
	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "vendor")); err != nil {
		t.Skip(err)
	}
	if _, got, _ := Locate(root, Location{File: "vendor/secret.go", Function: "Steal"}); got != NoFile {
		t.Errorf("a link out of the source was followed: %s", got)
	}
	for _, p := range []string{"../x", "/etc/passwd", "a/../../x", "a\\b", ""} {
		if _, ok := CleanPath(p); ok {
			t.Errorf("%q is a path inside the source", p)
		}
	}
}

func TestTheHeadOfACheckoutIsRead(t *testing.T) {
	root := t.TempDir()
	if Head(root) != "" {
		t.Error("a directory that is no checkout has a head")
	}
	write(t, root, map[string]string{".git/HEAD": "ref: refs/heads/main\n", ".git/refs/heads/main": commit + "\n"})
	if Head(root) != commit {
		t.Errorf("a branch: %q", Head(root))
	}
	packed := t.TempDir()
	write(t, packed, map[string]string{".git/HEAD": "ref: refs/heads/release\n",
		".git/packed-refs": "# pack-refs with: peeled fully-peeled sorted\n" + commit + " refs/heads/release\n"})
	if Head(packed) != commit {
		t.Errorf("a packed ref: %q", Head(packed))
	}
	detached := t.TempDir()
	write(t, detached, map[string]string{".git/HEAD": commit + "\n"})
	if Head(detached) != commit {
		t.Errorf("a detached head: %q", Head(detached))
	}
	worktree := t.TempDir()
	write(t, worktree, map[string]string{".git": "gitdir: " + filepath.Join(root, ".git") + "\n"})
	if Head(worktree) != commit {
		t.Errorf("a worktree: %q", Head(worktree))
	}
	odd := t.TempDir()
	write(t, odd, map[string]string{".git/HEAD": "ref: ../planted\n", "planted": commit + "\n"})
	if Head(odd) != "" {
		t.Error("a ref outside refs/ was followed")
	}
	climbing := t.TempDir()
	write(t, climbing, map[string]string{".git/HEAD": "ref: refs/../../planted\n", "planted": commit + "\n"})
	if Head(climbing) != "" {
		t.Error("a ref climbing out of refs/ was followed")
	}
}

func TestTheVersionASourceDeclaresIsRead(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"package.json": `{"name":"tiny-parse","version":"2.1.0"}`,
		"pyproject.toml": "[build-system]\nrequires = [\"hatchling\"]\n\n[project]\nname = \"Tiny_Parse\"\nversion = \"2.1.0\"\n\n[tool.x]\nversion = \"9\"\n"})
	if Declared(root, "npm", "tiny-parse") != "2.1.0" || Declared(root, "npm", "other") != "" {
		t.Error("npm")
	}
	if Declared(root, "pypi", "tiny-parse") != "2.1.0" || Declared(root, "golang", "x") != "" {
		t.Error("PyPI")
	}
}
