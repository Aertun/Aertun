// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/stats"
)

func sample(t *testing.T) *Export {
	t.Helper()
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	x := New(Datasheet{Made: at, Program: "test", Go: "go", Platform: "linux/amd64", CPUs: 1,
		From: at.Add(-time.Hour), To: at, Pseudonyms: Pseudonyms{Method: "m", KeyID: "k"}})
	if err := x.Add(Heads, []HeadRow{{Size: 3, At: Stamp(at)}, {Size: 4, At: Stamp(at)}}); err != nil {
		t.Fatal(err)
	}
	if err := x.Add(Audit, []AuditRow{}); err != nil {
		t.Fatal(err)
	}
	return x
}

// A dataset verifies against its key and nothing else, and every way of
// changing it after it was signed is refused.
func TestADatasetIsItsSignatureAndNothingElse(t *testing.T) {
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ds")
	if _, err := sample(t).Write(dir, k); err != nil {
		t.Fatal(err)
	}
	sheet, err := Verify(dir, k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(sheet.Tables) != 2 || sheet.Tables[0].Rows != 2 || sheet.Tables[1].Rows != 0 {
		t.Fatalf("tables %+v", sheet.Tables)
	}
	if _, err := sample(t).Write(dir, k); err == nil {
		t.Error("a dataset was written over another")
	}

	other, _ := pack.GenerateKey()
	if _, err := Verify(dir, other.PublicKey()); err == nil {
		t.Error("another key verified the dataset")
	}
	change := func(name string, f func(string) string) func(t *testing.T) {
		return func(t *testing.T) {
			copyDir := filepath.Join(t.TempDir(), "ds")
			if err := os.CopyFS(copyDir, os.DirFS(dir)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(copyDir, name)
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(f(string(b))), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(copyDir, k.PublicKey()); err == nil {
				t.Errorf("%s changed and the dataset still verified", name)
			}
		}
	}
	t.Run("a table", change("heads.jsonl", func(s string) string { return strings.Replace(s, `"size":3`, `"size":5`, 1) }))
	t.Run("a row dropped", change("heads.jsonl", func(s string) string { return s[strings.Index(s, "\n")+1:] }))
	t.Run("the datasheet beside it", change(DatasheetFile, func(s string) string {
		return strings.Replace(s, `"program": "test"`, `"program": "other"`, 1)
	}))
	t.Run("a file nobody signed", change("extra.jsonl", func(string) string { return "{}\n" }))
	t.Run("a table removed", func(t *testing.T) {
		copyDir := filepath.Join(t.TempDir(), "ds")
		if err := os.CopyFS(copyDir, os.DirFS(dir)); err != nil {
			t.Fatal(err)
		}
		os.Remove(filepath.Join(copyDir, "audit.jsonl"))
		if _, err := Verify(copyDir, k.PublicKey()); err == nil {
			t.Error("a dataset missing a table verified")
		}
	})
}

// A row type and its definition must agree, column for column, and a
// column that can vanish from a row is refused.
func TestTheDatasheetAndTheRowsCannotDisagree(t *testing.T) {
	x := sample(t)
	type short struct {
		Size int `json:"size"`
	}
	if err := x.Add(Def{Name: "heads2", Columns: Heads.Columns}, []short{}); err == nil {
		t.Error("rows missing a described column were taken")
	}
	type vanishing struct {
		Size int    `json:"size"`
		At   string `json:"at,omitempty"`
	}
	if err := x.Add(Def{Name: "heads3", Columns: Heads.Columns}, []vanishing{}); err == nil {
		t.Error("a column that can vanish was taken")
	}
	if err := x.Add(Def{Name: "heads4", Columns: []Column{{"size", "integer", "", ""},
		{"at", "time", "", "a"}}}, []HeadRow{}); err == nil {
		t.Error("a column with no meaning was taken")
	}
	if err := x.Add(Heads, []HeadRow{}); err == nil {
		t.Error("one table was added twice")
	}
	// Every table this package defines matches its row type.
	for _, c := range []struct {
		d    Def
		rows any
	}{{Events, []EventRow{}}, {Findings, []FindingRow{}}, {Detections, []DetectionRow{}},
		{Audit, []AuditRow{}}, {Heads, []HeadRow{}}, {Anchors, []AnchorRow{}},
		{Receipts, []ReceiptRow{}}, {Reconciliations, []ReconciliationRow{}},
		{Benign, []BenignRow{}}, {Outcomes, []OutcomeRow{}}, {Measurements, []MeasurementRow{}}} {
		if err := New(Datasheet{}).Add(c.d, c.rows); err != nil {
			t.Errorf("%s: %v", c.d.Name, err)
		}
	}
}

// The committed scorecard's aggregate becomes one row with the counts and
// interval it states; a newer card's rate objects each become a row named
// by where they are.
func TestEveryRateAScorecardStatesIsARow(t *testing.T) {
	card, err := os.ReadFile("../../scorecards/scorecard-2026-11-04.json")
	if err != nil {
		t.Fatal(err)
	}
	alias := func(kind, v string) string { return "p-" + kind }
	rows, err := ScorecardRates(card, "d1", alias)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Measure != "aggregate.miss_rate" || rows[0].K != 0 || rows[0].N != 4 ||
		rows[0].High < 0.48 || rows[0].Scorecard != "d1" || rows[0].Method != WilsonMethod {
		t.Fatalf("rows %+v", rows)
	}
	nested := []byte(`{"mutation":{"evasion":{"k":2,"n":10,"rate":0.2,"wilson_low":0.05,"wilson_high":0.5}},
		"perturb":[{"fault":"dup","rate":{"k":0,"n":4,"rate":0,"wilson_low":0,"wilson_high":0.49}},
		           {"rate":{"k":1,"n":4,"rate":0.25,"wilson_low":0.04,"wilson_high":0.7}}]}`)
	rows, err = ScorecardRates(nested, "d2", alias)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.Measure)
	}
	if strings.Join(got, ",") != "mutation.evasion,perturb[dup].rate,perturb[1].rate" {
		t.Fatalf("measures %v", got)
	}
	if _, err := ScorecardRates([]byte(`{"x":{"k":5,"n":4,"rate":1,"wilson_low":0,"wilson_high":1}}`), "d", alias); err == nil {
		t.Error("five of four was taken")
	}
	// A benign session is named by whoever captured it, so its path names
	// it by a pseudonym.
	rows, err = ScorecardRates([]byte(`{"benign":{"sessions":[{"name":"nightly-backup","class":"backup",
		"fires":{"k":0,"n":3,"rate":0,"wilson_low":0,"wilson_high":0.56}}]}}`), "d3", alias)
	if err != nil || len(rows) != 1 || rows[0].Measure != "benign.sessions[p-session].fires" {
		t.Fatalf("a session's rate: %+v %v", rows, err)
	}
	// Every count from 0 to n of every n up to 400, with the interval the
	// wind tunnel computes, holds together, rounding and all.
	for n := 1; n <= 400; n++ {
		for _, k := range []int{0, n / 2, n} {
			lo, hi := stats.Wilson(k, n)
			card := fmt.Sprintf(`{"r":{"k":%d,"n":%d,"rate":%v,"wilson_low":%v,"wilson_high":%v}}`,
				k, n, float64(k)/float64(n), lo, hi)
			if _, err := ScorecardRates([]byte(card), "d", alias); err != nil {
				t.Fatalf("%d of %d: %v", k, n, err)
			}
		}
	}
}

// The timings are taken, and the sizes are each algorithm's own.
func TestTheMeasurementsAreTaken(t *testing.T) {
	rows, err := Measure(t.TempDir(), 3)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]int{"sign ed25519": {64, 32}, "verify ed25519": {64, 32},
		"sign ml-dsa-65": {3309, 1952}, "verify ml-dsa-65": {3309, 1952}, "audit-append ": {0, 0}}
	if len(rows) != len(want) {
		t.Fatalf("%d rows", len(rows))
	}
	for _, r := range rows {
		w, ok := want[r.Measure+" "+r.Alg]
		if !ok || r.SignatureBytes != w[0] || r.PublicKeyBytes != w[1] || r.Iterations != 3 ||
			r.MedianUS <= 0 || r.P95US < r.MedianUS || r.MessageBytes <= 0 {
			t.Errorf("row %+v", r)
		}
	}
}

// A dataset signed as it should not have been — a row count, or a row's
// columns, that the datasheet does not describe — is still refused: the
// signature says who made it, not that it holds together.
func TestASignedDatasetThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(x *Export){
		"a row count": func(x *Export) { x.sheet.Tables[0].Rows = 3 },
		"a row's columns": func(x *Export) {
			body := []byte(strings.Replace(string(x.files["heads.jsonl"]), `"size":3`, `"size":3,"who":"dana"`, 1))
			x.files["heads.jsonl"] = body
			sum := sha256.Sum256(body)
			x.sheet.Tables[0].SHA256 = hex.EncodeToString(sum[:])
		},
	} {
		x := sample(t)
		spoil(x)
		dir := filepath.Join(t.TempDir(), "ds")
		if _, err := x.Write(dir, k); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(dir, k.PublicKey()); err == nil {
			t.Errorf("%s the datasheet does not describe was signed and verified", name)
		}
	}
}

// The statement's subjects, which a generic in-toto verifier reads, must be
// the tables the datasheet describes, digest for digest.
func TestTheSubjectsAreTheTables(t *testing.T) {
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ds")
	x := sample(t)
	if _, err := x.Write(dir, k); err != nil {
		t.Fatal(err)
	}
	subjects := subjectsOf(x.sheet.Tables)
	subjects[0].Digest["sha256"] = strings.Repeat("0", 64)
	payload, _ := json.Marshal(statement{Type: proof.StatementType, Subject: subjects,
		PredicateType: PredicateType, Predicate: x.sheet})
	env, err := proof.SealIn(payload, Context, k)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(envelopeFile{Format: Format, Envelope: *env})
	if err := os.WriteFile(filepath.Join(dir, EnvelopeFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, k.PublicKey()); err == nil || !strings.Contains(err.Error(), "subjects") {
		t.Errorf("subjects that are not the tables: %v", err)
	}
}

// A datasheet beside the dataset that decodes to the signed one but is not
// its bytes — a key written twice, the forged one first — is refused: a
// person reading the file would read the forgery.
func TestTheReadableDatasheetIsTheSignedOneByteForByte(t *testing.T) {
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ds")
	if _, err := sample(t).Write(dir, k); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, DatasheetFile)
	b, _ := os.ReadFile(path)
	forged := strings.Replace(string(b), "{\n", "{\n  \"program\": \"forged\",\n", 1)
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, k.PublicKey()); err == nil {
		t.Error("a datasheet carrying a forged key ahead of the signed one verified")
	}
}
