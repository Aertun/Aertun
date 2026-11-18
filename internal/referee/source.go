// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package referee

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// What a cited place was found to be.
const (
	Defined    = "defined"     // the function is defined in the file
	Mentioned  = "mentioned"   // named in a file of a language read here only by name
	NotDefined = "not-defined" // the file is there and the function is not
	NoFile     = "no-file"     // the source has no such file
	PastEnd    = "past-end"    // the function is there and the line cited is past the end of the file
)

// The languages a definition is recognised in.
const (
	LangGo, LangJS, LangPython, LangC, LangRust = "go", "javascript", "python", "c", "rust"
	LangJava, LangRuby, LangPHP, LangUnknown    = "java", "ruby", "php", "unknown"
)

// MaxSourceFile bounds a cited file read.
const MaxSourceFile = 16 << 20

var languages = map[string]string{
	".go": LangGo, ".js": LangJS, ".mjs": LangJS, ".cjs": LangJS, ".jsx": LangJS, ".ts": LangJS,
	".tsx": LangJS, ".mts": LangJS, ".cts": LangJS, ".py": LangPython, ".c": LangC, ".h": LangC,
	".cc": LangC, ".cpp": LangC, ".cxx": LangC, ".hpp": LangC, ".hh": LangC, ".rs": LangRust,
	".java": LangJava, ".kt": LangJava, ".cs": LangJava, ".scala": LangJava, ".rb": LangRuby,
	".php": LangPHP,
}

// definitions are, per language, what a definition of NAME looks like on
// the line it starts. They err towards finding one: a definition missed is
// a report wrongly refuted, and one found in a comment costs only a check
// that should have failed.
var definitions = map[string][]string{
	LangGo:     {`^\s*func\s+(\([^)]*\)\s*)?NAME\s*[\[(]`},
	LangJS:     {`\bfunction\s*\*?\s*NAME\s*\(`, `(?:^|[^A-Za-z0-9_$])NAME\s*[:=]\s*(async\s+)?(function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)`, `^\s*((static|async|get|set|public|private|protected|readonly|override)\s+)*\*?NAME\s*(<[^>]*>)?\s*\(`, `[{;]\s*((static|async|get|set)\s+)*\*?NAME\s*\([^)]*\)\s*\{`},
	LangPython: {`^\s*(async\s+)?def\s+NAME\s*\(`},
	LangC:      {`^[A-Za-z_][\w\s\*&:<>,]*[\s\*&:]NAME\s*\([^;]*$`, `^NAME\s*\(`},
	LangRust:   {`\bfn\s+NAME\s*[<(]`},
	LangJava:   {`(?:^|[^A-Za-z0-9_$])(fun\s+)?NAME\s*(<[^>]*>)?\s*\([^;]*$`},
	LangRuby:   {`^\s*def\s+(self\.)?NAME(?:[^A-Za-z0-9_$?!]|$)`},
	LangPHP:    {`\bfunction\s+&?NAME\s*\(`},
}

// identifier is a pattern for a name standing on its own: not the middle of a
// longer one. Spelled out rather than \b, which does not stand between a
// space and a name starting with $.
func identifier(name string) string {
	return `(?:^|[^A-Za-z0-9_$])` + regexp.QuoteMeta(name) + `(?:[^A-Za-z0-9_$]|$)`
}

// Locate finds a cited place in a source tree.
func Locate(root string, l Location) (language, found string, err error) {
	rel, ok := CleanPath(l.File)
	if !ok {
		return LangUnknown, NoFile, nil
	}
	language = languages[strings.ToLower(filepath.Ext(rel))]
	if language == "" {
		language = LangUnknown
	}
	body, ok, err := readInside(root, rel)
	if err != nil {
		return language, "", err
	}
	if !ok {
		return language, NoFile, nil
	}
	name := l.Function
	qualifier := ""
	for _, sep := range []string{"::", "."} {
		if i := strings.LastIndex(name, sep); i >= 0 {
			qualifier, name = name[:i], name[i+len(sep):]
			break
		}
	}
	if qualifier != "" {
		last := qualifier
		for _, sep := range []string{"::", "."} {
			if i := strings.LastIndex(last, sep); i >= 0 {
				last = last[i+len(sep):]
			}
		}
		if !regexp.MustCompile(identifier(last)).Match(body) {
			return language, NotDefined, nil
		}
	}
	lines := bytes.Count(body, []byte("\n"))
	if len(body) > 0 && body[len(body)-1] != '\n' {
		lines++
	}
	found = NotDefined
	if language == LangUnknown {
		if regexp.MustCompile(identifier(name)).Match(body) {
			found = Mentioned
		}
	} else {
		var res []*regexp.Regexp
		for _, d := range definitions[language] {
			res = append(res, regexp.MustCompile(strings.ReplaceAll(d, "NAME", regexp.QuoteMeta(name))))
		}
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 0, 64<<10), MaxSourceFile)
		for sc.Scan() && found == NotDefined {
			for _, re := range res {
				if re.Match(sc.Bytes()) {
					found = Defined
					break
				}
			}
		}
	}
	if found != NotDefined && l.Line > lines {
		found = PastEnd
	}
	return language, found, nil
}

// readInside reads a file under root, refusing one whose real path leaves
// it: a cited path is the report's, and a symbolic link in the source is
// not a way out of it.
func readInside(root, rel string) ([]byte, bool, error) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, false, fmt.Errorf("the source %s cannot be read: %w", root, err)
	}
	p, err := filepath.EvalSymlinks(filepath.Join(realRoot, filepath.FromSlash(rel)))
	if err != nil {
		return nil, false, nil
	}
	if p != realRoot && !strings.HasPrefix(p, realRoot+string(filepath.Separator)) {
		return nil, false, nil
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false, nil
	}
	if fi.Size() > MaxSourceFile {
		return nil, false, fmt.Errorf("a cited file is larger than %d bytes", MaxSourceFile)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// Head is the commit a git checkout is at, or "" when root is not one or
// its head cannot be read.
func Head(root string) string {
	gitDir := filepath.Join(root, ".git")
	if fi, err := os.Stat(gitDir); err == nil && !fi.IsDir() {
		// A worktree or submodule: .git is a file naming the directory.
		b, err := os.ReadFile(gitDir)
		if err != nil {
			return ""
		}
		d, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir: ")
		if !ok {
			return ""
		}
		if !filepath.IsAbs(d) {
			d = filepath.Join(root, d)
		}
		gitDir = d
	}
	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	h := strings.TrimSpace(string(head))
	ref, symbolic := strings.CutPrefix(h, "ref: ")
	if !symbolic {
		if commitShape.MatchString(h) {
			return h
		}
		return ""
	}
	if !strings.HasPrefix(ref, "refs/") || strings.Contains(ref, "..") {
		return ""
	}
	for _, dir := range []string{gitDir, commonDir(gitDir)} {
		if b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(ref))); err == nil {
			if c := strings.TrimSpace(string(b)); commitShape.MatchString(c) {
				return c
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "packed-refs")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if c, name, ok := strings.Cut(strings.TrimSpace(line), " "); ok && name == ref && commitShape.MatchString(c) {
					return c
				}
			}
		}
	}
	return ""
}

// commonDir is a worktree's shared git directory.
func commonDir(gitDir string) string {
	b, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return gitDir
	}
	d := strings.TrimSpace(string(b))
	if !filepath.IsAbs(d) {
		d = filepath.Join(gitDir, d)
	}
	return d
}

var pyprojectVersion = regexp.MustCompile(`(?m)^\s*version\s*=\s*["']([^"']+)["']`)
var pyprojectName = regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([^"']+)["']`)

// Declared is the version the source says it is, for a package of this
// name, or "" when it does not say: npm's package.json, and a PyPI
// project's pyproject.toml when it names a static version.
func Declared(root, ecosystem, name string) string {
	switch ecosystem {
	case "npm":
		b, ok, _ := readInside(root, "package.json")
		if !ok {
			return ""
		}
		var pkg struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &pkg) != nil || pkg.Name != name || !versionShape.MatchString(pkg.Version) {
			return ""
		}
		return pkg.Version
	case "pypi":
		b, ok, _ := readInside(root, "pyproject.toml")
		if !ok {
			return ""
		}
		project := string(b)
		if i := strings.Index(project, "[project]"); i >= 0 {
			project = project[i:]
			if j := strings.Index(project[1:], "\n["); j >= 0 {
				project = project[:j+1]
			}
		} else {
			return ""
		}
		n := pyprojectName.FindStringSubmatch(project)
		v := pyprojectVersion.FindStringSubmatch(project)
		if n == nil || v == nil || normalise(n[1]) != normalise(name) || !versionShape.MatchString(v[1]) {
			return ""
		}
		return v[1]
	}
	return ""
}

var pyRun = regexp.MustCompile(`[-_.]+`)

func normalise(s string) string { return pyRun.ReplaceAllString(strings.ToLower(s), "-") }
