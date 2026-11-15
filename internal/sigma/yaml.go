// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A YAML reader for the subset Sigma uses.
//
// Not a YAML implementation. YAML is an enormous specification with
// anchors, aliases, merge keys, tags, directives, multiple scalar styles
// and a type-inference table that has caused real incidents — the Norway
// problem, where the country code NO parses as the boolean false, is the
// famous one but not the worst.
//
// Sigma uses a small, regular corner of it: block mappings, block
// sequences (indented under their key or level with it), plain and quoted
// scalars, a plain scalar carried on to the next lines, block scalars for
// prose, comments, and documents separated by ---. That corner is what this
// reads, and everything outside it is an error naming the line rather than
// a silent misreading. A parser that
// accepts more than it understands is the problem, not the solution: the
// failure mode of a lenient YAML reader is a rule that loads and means
// something other than what its author wrote.
//
// Everything is a string. No type inference at all, which removes the whole
// class of bug above: "no" is the string "no", 010 is the string "010", and
// the Sigma compiler converts where a number or a boolean is actually
// wanted, in a place where it knows which it expects.

// Doc is one parsed YAML document: a mapping at the top level, which is
// what every Sigma rule is.
type Doc map[string]any

// line is one significant line of input.
type line struct {
	n      int
	indent int
	text   string
	// raw is the line as it was written, for the body of a block scalar,
	// where a # is text and not a comment.
	raw string
}

// Parse reads a stream of YAML documents.
func Parse(in []byte) ([]Doc, error) {
	lines, err := significant(string(in))
	if err != nil {
		return nil, err
	}
	var docs []Doc
	start := 0
	for i := 0; i <= len(lines); i++ {
		// A separator is at the margin: three dashes indented are a line of
		// somebody's prose.
		if i < len(lines) && (lines[i].text != "---" || lines[i].indent != 0) {
			continue
		}
		if i > start {
			d, err := block(lines[start:i], lines[start].indent)
			if err != nil {
				return nil, err
			}
			m, ok := d.(map[string]any)
			if !ok {
				return nil, fmt.Errorf(
					"line %d: a document here is a mapping of keys, and "+
						"this one is not", lines[start].n)
			}
			docs = append(docs, Doc(m))
		}
		start = i + 1
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("there is nothing in this file")
	}
	return docs, nil
}

// significant drops blank lines and comments, and records indentation.
func significant(in string) ([]line, error) {
	var out []line
	for i, raw := range strings.Split(in, "\n") {
		n := i + 1
		if tabbed(raw) {
			return nil, fmt.Errorf(
				"line %d: indented with a tab. YAML forbids it, and a file "+
					"that mixes tabs and spaces reads differently in "+
					"different editors — which is the kind of difference "+
					"that changes what a detection matches", n)
		}
		text := strip(raw)
		if strings.TrimSpace(text) == "" {
			continue
		}
		out = append(out, line{n: n, indent: leading(text),
			text: strings.TrimRight(strings.TrimLeft(text, " "), " "),
			raw:  strings.TrimRight(raw, " \r")})
	}
	return out, nil
}

// tabbed reports whether a line's indentation contains a tab.
func tabbed(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
		case '\t':
			return true
		default:
			return false
		}
	}
	return false
}

func leading(s string) int {
	for i, r := range s {
		if r != ' ' {
			return i
		}
	}
	return len(s)
}

// strip removes a trailing comment. A # starts one at the start of a line or
// after a space, unless it is inside a quoted scalar — and a scalar is
// quoted only when a quote mark is the first thing in it. A quote mark
// further into plain text is text: a regular expression that names one
// does not thereby swallow the comment written after it, which is how a
// comment once became part of the pattern a rule matched.
func strip(s string) string {
	var quote byte // the mark a scalar was opened with, or 0
	start := true  // whatever comes next that is not a space begins a scalar
	flow := 0      // how many [ the line is inside
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			switch {
			case quote == '"' && c == '\\':
				i++
			case c == quote && quote == '\'' && i+1 < len(s) && s[i+1] == '\'':
				i++ // two single quotes are one, inside single quotes
			case c == quote:
				quote = 0
			}
			continue
		}
		switch {
		case c == ' ':
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return s[:i]
		case start && (c == '\'' || c == '"'):
			quote, start = c, false
		case start && c == '[':
			flow++
		case start && c == '-' && (i+1 == len(s) || s[i+1] == ' '):
			// A list item's dash: what follows it begins a scalar.
		case c == ':' && (i+1 == len(s) || s[i+1] == ' '):
			start = true
		case flow > 0 && c == ',':
			start = true
		case flow > 0 && c == ']':
			flow--
			start = false
		default:
			start = false
		}
	}
	return s
}

// block parses a run of lines at one indentation into a map or a sequence.
func block(ls []line, indent int) (any, error) {
	if len(ls) == 0 {
		return nil, nil
	}
	if item(ls[0].text) {
		return sequence(ls, indent)
	}
	// Plain text, on the lines under its key rather than beside it: one
	// value, as a condition written over several lines is.
	if plain(ls[0].text, ls[1:]) {
		parts := make([]string, 0, len(ls))
		for _, l := range ls {
			parts = append(parts, l.text)
		}
		return strings.Join(parts, " "), nil
	}
	return mapping(ls, indent)
}

func mapping(ls []line, indent int) (any, error) {
	out := map[string]any{}
	for i := 0; i < len(ls); {
		l := ls[i]
		if l.indent != indent {
			return nil, fmt.Errorf(
				"line %d: indented %d space(s) where %d was expected. This "+
					"reader will not guess: a mapping whose keys are at "+
					"different depths means two different things and looks "+
					"like one", l.n, l.indent, indent)
		}
		key, rest, ok := split(l.text)
		if !ok {
			return nil, fmt.Errorf(
				"line %d: %q is not \"key: value\". This reader takes the "+
					"part of YAML that Sigma uses and nothing else",
				l.n, l.text)
		}
		j := i + 1
		for j < len(ls) && ls[j].indent > indent {
			j++
		}
		// A list may sit level with the key it belongs to rather than under
		// it: both are YAML, and half the rules in the public Sigma
		// repository are written this way. It runs until the next line at
		// this depth that is not an item, which is the next key.
		if rest == "" && j == i+1 && j < len(ls) && item(ls[j].text) {
			for j < len(ls) && (ls[j].indent > indent || item(ls[j].text)) {
				j++
			}
			v, err := sequence(ls[i+1:j], indent)
			if err != nil {
				return nil, err
			}
			out[key] = v
			i = j
			continue
		}
		switch {
		case rest != "" && j > i+1 && (rest[0] == '|' || rest[0] == '>'):
			// A block scalar: prose, which is what Sigma writes with it —
			// a description, a logsource's definition. The lines under the
			// key are the value as they were written, comment signs and
			// all; a literal keeps its line breaks and a folded one reads
			// as one line. Blank lines inside are not kept: nothing here
			// reads a description for its paragraphs.
			sep := "\n"
			if rest[0] == '>' {
				sep = " "
			}
			if strings.Trim(rest[1:], "+-0123456789 ") != "" {
				return nil, fmt.Errorf(
					"line %d: %q is not a block scalar's header", l.n, rest)
			}
			body := make([]string, 0, j-i-1)
			for _, b := range ls[i+1 : j] {
				body = append(body, strings.TrimSpace(b.raw))
			}
			out[key] = strings.Join(body, sep)
		case rest != "" && j > i+1:
			// A plain scalar carried on to the lines under it: one value,
			// its lines joined by a space, as YAML reads it. Only plain
			// text continues — a quoted or bracketed value ends where it
			// closes, and a line that is itself a key or a list item is a
			// nested block under a key that already has a value, which
			// means two different things and is refused.
			if !plain(rest, ls[i+1:j]) {
				return nil, fmt.Errorf(
					"line %d: %q has a value and a nested block under it",
					l.n, key)
			}
			parts := []string{rest}
			for _, c := range ls[i+1 : j] {
				parts = append(parts, c.text)
			}
			out[key] = strings.Join(parts, " ")
		case rest != "":
			v, err := scalar(l.n, rest)
			if err != nil {
				return nil, err
			}
			out[key] = v
		case j > i+1:
			v, err := block(ls[i+1:j], ls[i+1].indent)
			if err != nil {
				return nil, err
			}
			out[key] = v
		default:
			// A key with nothing under it. Kept as an empty string rather
			// than as null, because everything here is a string and a
			// missing value is a thing the compiler should notice.
			out[key] = ""
		}
		i = j
	}
	return out, nil
}

// plain reports whether first, and the lines under it, are one plain scalar
// written over several lines: first opens no quote, bracket, anchor or
// block scalar, it is not itself "key: value", and no line under it is a
// key or a list item.
func plain(first string, under []line) bool {
	if first == "" || item(first) || strings.ContainsRune("'\"[{&*|>", rune(first[0])) {
		return false
	}
	if _, _, isKey := split(first); isKey {
		return false
	}
	for _, c := range under {
		if _, _, isKey := split(c.text); isKey || item(c.text) {
			return false
		}
	}
	return true
}

// item reports whether a line is a list item.
func item(text string) bool {
	return strings.HasPrefix(text, "- ") || text == "-"
}

func sequence(ls []line, indent int) (any, error) {
	var out []any
	for i := 0; i < len(ls); {
		l := ls[i]
		if l.indent != indent {
			return nil, fmt.Errorf("line %d: this list item is indented %d "+
				"space(s) where %d was expected", l.n, l.indent, indent)
		}
		if !item(l.text) {
			return nil, fmt.Errorf(
				"line %d: a list and a mapping at the same depth", l.n)
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		j := i + 1
		for j < len(ls) && ls[j].indent > indent {
			j++
		}
		switch {
		case rest != "" && j > i+1 && plain(rest, ls[i+1:j]):
			// An item of plain text carried on to the lines under it.
			parts := []string{rest}
			for _, c := range ls[i+1 : j] {
				parts = append(parts, c.text)
			}
			out = append(out, strings.Join(parts, " "))
		case rest != "" && j > i+1:
			// "- key: value" with more keys under it: a mapping whose
			// first key sits on the dash line, at the column it is
			// written in — which is where the keys under it are, however
			// deep what hangs off them goes.
			inner := append([]line{{n: l.n,
				indent: l.indent + len(l.text) - len(rest), text: rest,
				raw: l.raw}}, ls[i+1:j]...)
			v, err := block(inner, inner[0].indent)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case rest != "":
			if k, r, ok := split(rest); ok && r != "" {
				v, err := scalar(l.n, r)
				if err != nil {
					return nil, err
				}
				out = append(out, map[string]any{k: v})
				break
			}
			v, err := scalar(l.n, rest)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		case j > i+1:
			v, err := block(ls[i+1:j], ls[i+1].indent)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		default:
			out = append(out, "")
		}
		i = j
	}
	return out, nil
}

// split separates "key: value". A key is quoted only when a quote mark
// opens it, and then it ends where that mark closes; a plain key ends at
// the first colon that a space or the end of the line follows, so a colon
// inside a plain scalar — a URL — is not one.
func split(s string) (key, rest string, ok bool) {
	if s == "" {
		return "", "", false
	}
	i := 0
	if q := s[0]; q == '\'' || q == '"' {
		for i = 1; i < len(s) && s[i] != q; i++ {
			switch {
			case q == '"' && s[i] == '\\':
				i++
			}
		}
		for q == '\'' && i+1 < len(s) && s[i+1] == '\'' {
			// Two single quotes are one inside single quotes: keep going.
			for i += 2; i < len(s) && s[i] != q; i++ {
			}
		}
		if i >= len(s) {
			return "", "", false
		}
		end := i + 1
		for i = end; i < len(s) && s[i] == ' '; i++ {
		}
		if i >= len(s) || s[i] != ':' || (i+1 < len(s) && s[i+1] != ' ') {
			return "", "", false
		}
		return unquoteKey(s[:end]), strings.TrimSpace(s[i+1:]), true
	}
	for ; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			return unquoteKey(strings.TrimSpace(s[:i])),
				strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func unquoteKey(k string) string {
	if v, err := scalar(0, k); err == nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return k
}

// scalar reads one value, including a simple flow sequence.
func scalar(n int, s string) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		var out []any
		for _, part := range splitFlow(inner) {
			v, err := scalar(n, part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case strings.HasPrefix(s, "{"):
		return nil, fmt.Errorf(
			"line %d: flow mappings are not read here. Sigma writes its "+
				"detections as blocks, and a reader that accepted both "+
				"would be two readers", n)
	case strings.HasPrefix(s, "|") || strings.HasPrefix(s, ">"):
		// A block scalar's header with nothing under it: an empty one. One
		// with a body is read where its key is (mapping).
		return "", nil
	case strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) > 1:
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	case strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") && len(s) > 1:
		return unescape(s[1 : len(s)-1]), nil
	case strings.HasPrefix(s, "&") || strings.HasPrefix(s, "*"):
		return nil, fmt.Errorf(
			"line %d: anchors and aliases are not read here. They are the "+
				"part of YAML that makes a file mean something other than "+
				"what it looks like", n)
	}
	return s, nil
}

func splitFlow(s string) []string {
	var out []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '[':
			if !inSingle && !inDouble {
				depth++
			}
		case ']':
			if !inSingle && !inDouble {
				depth--
			}
		case ',':
			if depth == 0 && !inSingle && !inDouble {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// unescape reads a double-quoted scalar's escapes: the ones YAML defines
// that a rule has a use for, among them a character named by its code
// point, which is how a rule about look-alike letters names the letter. An
// escape it does not know is left as it was written.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		digits := map[byte]int{'x': 2, 'u': 4, 'U': 8}[s[i]]
		if digits > 0 && i+digits < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+1+digits], 16, 32); err == nil &&
				utf8.ValidRune(rune(n)) {
				b.WriteRune(rune(n))
				i += digits
				continue
			}
		}
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0':
			b.WriteByte(0)
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\', '"', '/', ' ':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
