// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const pass = "correct horse battery staple"

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// make writes a backup of a few files, one large enough to span chunks.
func makeBackup(t *testing.T) ([]byte, []byte) {
	t.Helper()
	big := make([]byte, 3*chunkSize+123)
	rand.Read(big)
	var out bytes.Buffer
	w, err := NewWriter(&out, pass, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Dir("spool", 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"config.json": []byte(`{"a":1}`), "spool/0001": big, "empty": {}} {
		if err := w.File(name, 0o600, int64(len(body)), bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close("aertun test", map[string]int{"audit_size": 7}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), big
}

func TestRoundTrip(t *testing.T) {
	b, big := makeBackup(t)
	if bytes.Contains(b, []byte(`{"a":1}`)) || bytes.Contains(b, big[:64]) {
		t.Fatal("the backup holds plaintext")
	}
	dir := filepath.Join(t.TempDir(), "restored")
	m, err := Restore(bytes.NewReader(b), pass, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 || !strings.Contains(string(m.Store), `"audit_size":7`) || m.Program != "aertun test" {
		t.Errorf("%+v", m)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "spool", "0001"))
	if !bytes.Equal(got, big) {
		t.Error("the large file did not come back whole")
	}
	if info, _ := os.Stat(filepath.Join(dir, "config.json")); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	if _, err := Restore(bytes.NewReader(b), pass, dir); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a restore over a store: %v", err)
	}
	// Refused over a store, it leaves the store as it was.
	if got, _ := os.ReadFile(filepath.Join(dir, "spool", "0001")); !bytes.Equal(got, big) {
		t.Error("a refused restore touched the directory it was refused for")
	}
	// A restore that fails part way leaves its new directory empty.
	other := filepath.Join(t.TempDir(), "fresh")
	if _, err := Restore(bytes.NewReader(b[:len(b)-30]), pass, other); err == nil {
		t.Fatal("a cut-short backup was restored")
	}
	if entries, _ := os.ReadDir(other); len(entries) != 0 {
		t.Errorf("a failed restore left %d entries behind", len(entries))
	}
}

func TestRefusals(t *testing.T) {
	b, _ := makeBackup(t)
	restore := func(data []byte, p string) error {
		_, err := Restore(bytes.NewReader(data), p, filepath.Join(t.TempDir(), "r"))
		return err
	}
	if err := restore(b, pass+"!"); err == nil {
		t.Error("the wrong passphrase opened it")
	}
	if _, err := NewWriter(&bytes.Buffer{}, "too short", now); err == nil {
		t.Error("a short passphrase was accepted")
	}
	// Cut off anywhere after the header: never a clean restore.
	start := bytes.IndexByte(b[len(Magic):], '\n') + len(Magic) + 1
	for _, cut := range []int{start + 2, start + 4 + chunkSize/2, start + 4 + chunkSize + 16, len(b) - 1, len(b) - 20} {
		if err := restore(b[:cut], pass); err == nil {
			t.Errorf("cut at %d of %d was restored", cut, len(b))
		}
	}
	if err := restore(append(bytes.Clone(b), 0), pass); err == nil {
		t.Error("trailing data was accepted")
	}
	// The header is bound to every chunk: a lowered work factor fails.
	tampered := bytes.Replace(b, []byte(`"iterations":600000`), []byte(`"iterations":700000`), 1)
	if err := restore(tampered, pass); err == nil {
		t.Error("a changed header was accepted")
	}
	// Two chunks swapped.
	first := start
	swapped := bytes.Clone(b)
	l1 := 4 + int(uint32(b[first])<<24|uint32(b[first+1])<<16|uint32(b[first+2])<<8|uint32(b[first+3]))
	second := first + l1
	l2 := 4 + int(uint32(b[second])<<24|uint32(b[second+1])<<16|uint32(b[second+2])<<8|uint32(b[second+3]))
	if l1 == l2 {
		copy(swapped[first:], b[second:second+l2])
		copy(swapped[first+l2:], b[first:first+l1])
		if err := restore(swapped, pass); err == nil {
			t.Error("two chunks swapped were accepted")
		}
	}
	if err := restore([]byte("not a backup"), pass); err == nil {
		t.Error("garbage was accepted")
	}
}

// hostile builds an encrypted archive with whatever entries it is given,
// past the checks the writer makes, as an attacker's would be.
func hostile(t *testing.T, entries []*tar.Header, bodies [][]byte, manifest string) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewWriter(&out, pass, now)
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range entries {
		if err := w.tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if bodies[i] != nil {
			w.tw.Write(bodies[i])
		}
	}
	w.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: manifestTar, Mode: 0o600, Size: int64(len(manifest))})
	w.tw.Write([]byte(manifest))
	w.tw.Close()
	w.s.seal(true)
	return out.Bytes()
}

func TestHostileArchives(t *testing.T) {
	reg := func(name string, body string) (*tar.Header, []byte) {
		return &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(body))}, []byte(body)
	}
	empty := `{"format":1,"files":[]}`
	cases := map[string]func() []byte{
		"parent escape": func() []byte { h, b := reg("../escaped", "x"); return hostile(t, []*tar.Header{h}, [][]byte{b}, empty) },
		"absolute":      func() []byte { h, b := reg("/tmp/abs", "x"); return hostile(t, []*tar.Header{h}, [][]byte{b}, empty) },
		"symlink": func() []byte {
			return hostile(t, []*tar.Header{{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "/etc/passwd"}}, [][]byte{nil}, empty)
		},
		"device": func() []byte {
			return hostile(t, []*tar.Header{{Typeflag: tar.TypeChar, Name: "dev"}}, [][]byte{nil}, empty)
		},
		"unlisted file": func() []byte { h, b := reg("extra", "x"); return hostile(t, []*tar.Header{h}, [][]byte{b}, empty) },
		"wrong hash": func() []byte {
			h, b := reg("f", "x")
			return hostile(t, []*tar.Header{h}, [][]byte{b},
				`{"format":1,"files":[{"path":"f","size":1,"mode":384,"sha256":"00"}]}`)
		},
		"no manifest": func() []byte {
			var out bytes.Buffer
			w, _ := NewWriter(&out, pass, now)
			w.tw.Close()
			w.s.seal(true)
			return out.Bytes()
		},
	}
	parent := t.TempDir()
	for name, build := range cases {
		dir := filepath.Join(parent, strings.ReplaceAll(name, " ", "-"), "store")
		_, err := Restore(bytes.NewReader(build()), pass, dir)
		if err == nil {
			t.Errorf("%s was restored", name)
		}
	}
	if _, err := os.Stat(filepath.Join(parent, "parent-escape", "escaped")); err == nil {
		t.Error("a file was written outside the restore")
	}
}
