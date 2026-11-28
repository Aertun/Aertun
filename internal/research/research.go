// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package research writes the dataset a paper's figures are drawn from:
// tables of what this deployment recorded and what it measured,
// de-identified, with a datasheet that says what every column means, all
// under one signature, so that every figure traces back to a signed file.
//
// A dataset is a directory: one JSON Lines file per table, the datasheet
// as JSON for a person to read, and export.json, a DSSE envelope whose
// in-toto statement names every table by its SHA-256 and carries the
// datasheet as its predicate. Verify holds a directory to all of it and
// refuses anything the signature does not cover.
package research

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

const (
	// Format names the envelope file and the datasheet.
	Format = "aertun/research-export/v1"
	// PredicateType is the statement's predicate: the datasheet.
	PredicateType = "https://aertun.github.io/research-export/v1"
	// Context is the domain the dataset is signed in, so that its
	// signature is never a proof's or a bundle's.
	Context = "aertun/research-export/v1"

	// EnvelopeFile and DatasheetFile are the two files beside the tables.
	EnvelopeFile  = "export.json"
	DatasheetFile = "datasheet.json"

	// MaxEnvelope and MaxTable bound what Verify reads, and MaxRows a
	// table: Add refuses past either, so nothing is written that Verify
	// would refuse to read.
	MaxEnvelope = 16 << 20
	MaxTable    = 1 << 30
	MaxRows     = 2_000_000
)

// Column is one column of a table, as the datasheet describes it.
type Column struct {
	Name string `json:"name"`
	// Type is string, integer, number, boolean, or time: RFC 3339 in UTC,
	// empty when not known.
	Type    string `json:"type"`
	Unit    string `json:"unit,omitempty"`
	Meaning string `json:"meaning"`
}

// Table is one table of the dataset as the datasheet records it.
type Table struct {
	Name        string   `json:"name"`
	File        string   `json:"file"`
	Description string   `json:"description"`
	Source      string   `json:"source"`
	Columns     []Column `json:"columns"`
	Rows        int      `json:"rows"`
	SHA256      string   `json:"sha256"`
}

// Input is a signed document the dataset drew on, checked before it was
// read: what it was, its digest as read, and the key it verified against.
type Input struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Signer string `json:"signer"`
}

// Pseudonyms says how names were replaced: the method, and the key by its
// fingerprint, never the key.
type Pseudonyms struct {
	Method string `json:"method"`
	KeyID  string `json:"key_id"`
}

// Datasheet is the data dictionary and the run's manifest: the build and
// platform that made the dataset, the window it covers, how it was
// de-identified, what it drew on, every table with every column, and what
// a reader might expect that was not collected, and why.
type Datasheet struct {
	Format       string     `json:"format"`
	Made         time.Time  `json:"made"`
	Program      string     `json:"program"`
	Go           string     `json:"go"`
	Platform     string     `json:"platform"`
	CPUs         int        `json:"cpus"`
	FIPS140      bool       `json:"fips140"`
	From         time.Time  `json:"from"`
	To           time.Time  `json:"to"`
	Pseudonyms   Pseudonyms `json:"pseudonyms"`
	Inputs       []Input    `json:"inputs"`
	Tables       []Table    `json:"tables"`
	NotCollected []string   `json:"not_collected"`
}

// Def defines a table: what it holds, where its rows came from, and a
// column for every field of its row type, in order, so the datasheet and
// the data cannot say different things.
type Def struct {
	Name        string
	Description string
	Source      string
	Columns     []Column
}

var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// Export is a dataset being assembled.
type Export struct {
	sheet Datasheet
	files map[string][]byte
}

// New starts a dataset. The sheet's tables are filled by Add; anything
// else in it is the caller's.
func New(sheet Datasheet) *Export {
	sheet.Format = Format
	sheet.Made, sheet.From, sheet.To = sheet.Made.UTC(), sheet.From.UTC(), sheet.To.UTC()
	sheet.Tables = nil
	if sheet.Inputs == nil {
		sheet.Inputs = []Input{}
	}
	if sheet.NotCollected == nil {
		sheet.NotCollected = []string{}
	}
	return &Export{sheet: sheet, files: map[string][]byte{}}
}

// Input records a signed document the dataset drew on, checked before it
// was read.
func (x *Export) Input(in Input) { x.sheet.Inputs = append(x.sheet.Inputs, in) }

// NotCollected says what a reader might expect that the dataset does not
// hold, and why.
func (x *Export) NotCollected(why string) { x.sheet.NotCollected = append(x.sheet.NotCollected, why) }

// Add writes rows, a slice of one struct type, as table d. Every field of
// the struct is a column d describes, in the same order, and nothing else.
func (x *Export) Add(d Def, rows any) error {
	if !tableName.MatchString(d.Name) {
		return fmt.Errorf("%q is not a table name", d.Name)
	}
	file := d.Name + ".jsonl"
	if _, dup := x.files[file]; dup {
		return fmt.Errorf("table %s is added twice", d.Name)
	}
	v := reflect.ValueOf(rows)
	if v.Kind() != reflect.Slice || v.Type().Elem().Kind() != reflect.Struct {
		return fmt.Errorf("table %s: rows are a slice of one struct type", d.Name)
	}
	fields := jsonFields(v.Type().Elem())
	var named []string
	for _, c := range d.Columns {
		if c.Meaning == "" || !slices.Contains([]string{"string", "integer", "number", "boolean", "time"}, c.Type) {
			return fmt.Errorf("table %s: column %s has no meaning or no known type", d.Name, c.Name)
		}
		named = append(named, c.Name)
	}
	if !slices.Equal(fields, named) {
		return fmt.Errorf("table %s: the rows have columns %v and the datasheet describes %v",
			d.Name, fields, named)
	}
	if v.Len() > MaxRows {
		return fmt.Errorf("table %s would hold %d rows, over the %d a dataset may; narrow the window",
			d.Name, v.Len(), MaxRows)
	}
	var buf bytes.Buffer
	for i := range v.Len() {
		line, err := json.Marshal(v.Index(i).Interface())
		if err != nil {
			return fmt.Errorf("table %s, row %d: %w", d.Name, i+1, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
		if buf.Len() > MaxTable {
			return fmt.Errorf("table %s is over the %d bytes a dataset may hold; narrow the window", d.Name, MaxTable)
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	x.files[file] = buf.Bytes()
	x.sheet.Tables = append(x.sheet.Tables, Table{Name: d.Name, File: file,
		Description: d.Description, Source: d.Source, Columns: d.Columns,
		Rows: v.Len(), SHA256: hex.EncodeToString(sum[:])})
	return nil
}

// jsonFields are a struct's JSON names in field order. A field without a
// tag, with omitempty, or left out is refused by Add's comparison, since
// a column that can vanish from a row is not one a reader can rely on.
func jsonFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		out = append(out, tag)
	}
	return out
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Datasheet `json:"predicate"`
}

type envelopeFile struct {
	Format   string         `json:"format"`
	Envelope proof.Envelope `json:"envelope"`
}

func subjectsOf(tables []Table) []subject {
	out := make([]subject, len(tables))
	for i, t := range tables {
		out[i] = subject{Name: t.File, Digest: map[string]string{"sha256": t.SHA256}}
	}
	return out
}

// Write signs the dataset with both halves of k and writes it into dir,
// which must not exist or be empty: a dataset is the files it names and
// nothing else. Files are written owner-only; sharing one is a choice made
// after reading the datasheet.
func (x *Export) Write(dir string, k *pack.Key) (*Datasheet, error) {
	if len(x.sheet.Tables) == 0 {
		return nil, errors.New("a dataset with no tables says nothing")
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s already holds files; a dataset is written into an empty directory", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	payload, err := json.Marshal(statement{Type: proof.StatementType, Subject: subjectsOf(x.sheet.Tables),
		PredicateType: PredicateType, Predicate: x.sheet})
	if err != nil {
		return nil, err
	}
	env, err := proof.SealIn(payload, Context, k)
	if err != nil {
		return nil, err
	}
	envBody, err := json.MarshalIndent(envelopeFile{Format: Format, Envelope: *env}, "", "  ")
	if err != nil {
		return nil, err
	}
	sheetBody, err := readableSheet(x.sheet)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for name, body := range x.files {
		if err := atomicfile.Write(filepath.Join(dir, name), body, 0o600); err != nil {
			return nil, err
		}
	}
	if err := atomicfile.Write(filepath.Join(dir, DatasheetFile), sheetBody, 0o600); err != nil {
		return nil, err
	}
	// The envelope last: a directory without it is visibly unfinished.
	if err := atomicfile.Write(filepath.Join(dir, EnvelopeFile), append(envBody, '\n'), 0o600); err != nil {
		return nil, err
	}
	sheet := x.sheet
	return &sheet, nil
}

// Verify checks a dataset in dir against a trusted key: both signatures,
// every table's digest, row count and columns, and that the datasheet
// beside it is the one signed. A file in dir that the signature does not
// name is refused, since a reader could not tell it from one it does.
func Verify(dir string, pub pack.KeyPublic) (*Datasheet, error) {
	body, err := readBounded(filepath.Join(dir, EnvelopeFile), MaxEnvelope)
	if err != nil {
		return nil, err
	}
	var f envelopeFile
	if err := strictDecode(body, &f); err != nil {
		return nil, fmt.Errorf("%s is not a research export: %w", EnvelopeFile, err)
	}
	if f.Format != Format {
		return nil, fmt.Errorf("%s says it is %q; this reads %s", EnvelopeFile, f.Format, Format)
	}
	payload, err := proof.OpenIn(&f.Envelope, Context, pub)
	if err != nil {
		return nil, err
	}
	var st statement
	if err := strictDecode(payload, &st); err != nil {
		return nil, fmt.Errorf("the signed statement is not one this version reads: %w", err)
	}
	if st.Type != proof.StatementType || st.PredicateType != PredicateType || st.Predicate.Format != Format {
		return nil, errors.New("the signed statement is not a research export")
	}
	sheet := st.Predicate
	if !reflect.DeepEqual(st.Subject, subjectsOf(sheet.Tables)) {
		return nil, errors.New("the statement's subjects are not its tables")
	}
	want := map[string]bool{EnvelopeFile: true, DatasheetFile: true}
	for _, t := range sheet.Tables {
		if !tableName.MatchString(t.Name) || t.File != t.Name+".jsonl" || want[t.File] {
			return nil, fmt.Errorf("the datasheet names a table file %q this reads nowhere", t.File)
		}
		want[t.File] = true
		if err := checkTable(dir, t); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !want[e.Name()] {
			return nil, fmt.Errorf("%s is in the dataset and no signature covers it", e.Name())
		}
	}
	// Byte for byte: a decoder takes a key written twice, or in another
	// case, and a person reading the file would see the forgery while a
	// comparison of meanings passed it.
	shown, err := readBounded(filepath.Join(dir, DatasheetFile), MaxEnvelope)
	if err != nil {
		return nil, err
	}
	signed, err := readableSheet(sheet)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(shown, signed) {
		return nil, fmt.Errorf("%s is not the datasheet that was signed", DatasheetFile)
	}
	return &sheet, nil
}

// readableSheet is the datasheet as datasheet.json holds it.
func readableSheet(s Datasheet) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// checkTable holds one table file to its digest, its row count, and its
// columns: each line one JSON object with exactly the columns described.
func checkTable(dir string, t Table) error {
	body, err := readBounded(filepath.Join(dir, t.File), MaxTable)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != t.SHA256 {
		return fmt.Errorf("%s is not the table that was signed", t.File)
	}
	var cols []string
	for _, c := range t.Columns {
		cols = append(cols, c.Name)
	}
	slices.Sort(cols)
	rows := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		rows++
		var row map[string]json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			return fmt.Errorf("%s, row %d: %w", t.File, rows, err)
		}
		var got []string
		for k := range row {
			got = append(got, k)
		}
		slices.Sort(got)
		if !slices.Equal(got, cols) {
			return fmt.Errorf("%s, row %d has columns %v and the datasheet describes %v",
				t.File, rows, got, cols)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %w", t.File, err)
	}
	if rows != t.Rows {
		return fmt.Errorf("%s holds %d rows and the datasheet says %d", t.File, rows, t.Rows)
	}
	return nil
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one document")
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d bytes it may be", filepath.Base(path), limit)
	}
	return b, nil
}

// Stamp is a time as a table writes it: RFC 3339 in UTC, to the
// nanosecond, and empty when not known.
func Stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// Summary is a one-line description of a verified dataset, for a command
// to print.
func (d *Datasheet) Summary() string {
	var names []string
	rows := 0
	for _, t := range d.Tables {
		names = append(names, fmt.Sprintf("%s (%d)", t.Name, t.Rows))
		rows += t.Rows
	}
	return fmt.Sprintf("%d table(s), %d row(s), %s to %s: %s", len(d.Tables), rows,
		Stamp(d.From), Stamp(d.To), strings.Join(names, ", "))
}
