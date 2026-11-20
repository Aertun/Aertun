// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package receiptlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/scitt"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

const logName = "https://receipts.example"

func issuerKey(t *testing.T) *pack.Key {
	t.Helper()
	k, err := pack.NewKey(bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func statement(t *testing.T, k *pack.Key, sub string) []byte {
	t.Helper()
	ed, _, err := Signers(k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := scitt.Sign(ed, scitt.Statement{Issuer: "https://gateway.example", Subject: sub, IssuedAt: now,
		ContentType: "application/example", Payload: []byte(sub)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func admitAll(*scitt.Signed) error { return nil }

func TestRegisterAndVerify(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, logName)
	if err != nil {
		t.Fatal(err)
	}
	k := issuerKey(t)
	var transparent [][]byte
	for i := range 5 {
		tr, err := l.Register(statement(t, k, fmt.Sprint("s", i)), admitAll, now)
		if err != nil {
			t.Fatal(err)
		}
		transparent = append(transparent, tr)
	}
	for i, tr := range transparent {
		s, err := scitt.Read(tr)
		if err != nil {
			t.Fatal(err)
		}
		in, err := VerifyReceipts(s, l.PublicKey())
		if err != nil {
			t.Fatalf("statement %d: %v", i, err)
		}
		if len(in) != 2 || in[0].Index != uint64(i) || in[0].Size != uint64(i+1) || in[0].Issuer != logName {
			t.Errorf("statement %d: %+v", i, in)
		}
	}
	// The same statement again is not a second entry.
	again, err := l.Register(statement(t, k, "s2"), admitAll, now)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := scitt.Read(again)
	in, err := VerifyReceipts(s, l.PublicKey())
	if err != nil || in[0].Index != 2 || in[0].Size != 5 {
		t.Errorf("re-registered: %v %+v", err, in)
	}
	if n, _ := l.Size(); n != 5 {
		t.Errorf("size %d", n)
	}
	// Reopened, it is the same log with the same key and name.
	l2, err := Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if l2.Issuer() != logName || l2.PublicKey() != l.PublicKey() {
		t.Error("a reopened log is not the same log")
	}
	if _, err := Open(dir, "https://other.example"); err == nil {
		t.Error("a log opened under another name")
	}
	if _, err := Open(t.TempDir(), ""); err == nil {
		t.Error("a new log opened with no name")
	}
}

func TestAdmit(t *testing.T) {
	l, _ := Open(t.TempDir(), logName)
	no := errors.New("unknown issuer")
	if _, err := l.Register(statement(t, issuerKey(t), "s"), func(*scitt.Signed) error { return no }, now); !errors.Is(err, no) {
		t.Errorf("a refused statement: %v", err)
	}
	if _, err := l.Register(statement(t, issuerKey(t), "s"), nil, now); err == nil {
		t.Error("a statement registered with no policy")
	}
	if n, _ := l.Size(); n != 0 {
		t.Errorf("a refused statement is in the log: size %d", n)
	}
}

// TestBothRequired: a transparent statement with only one of the log's
// receipts, or with another log's, does not verify.
func TestBothRequired(t *testing.T) {
	l, _ := Open(t.TempDir(), logName)
	other, _ := Open(t.TempDir(), "https://other.example")
	st := statement(t, issuerKey(t), "s")
	tr, err := l.Register(st, admitAll, now)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := scitt.Read(tr)
	for name, keep := range map[string][]int{"Ed25519 only": {0}, "ML-DSA only": {1}} {
		var rs [][]byte
		for _, i := range keep {
			rs = append(rs, s.Receipts[i])
		}
		one, err := scitt.Attach(st, rs...)
		if err != nil {
			t.Fatal(err)
		}
		half, _ := scitt.Read(one)
		if _, err := VerifyReceipts(half, l.PublicKey()); err == nil || !strings.Contains(err.Error(), "both are required") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyReceipts(s, other.PublicKey()); err == nil {
		t.Error("one log's receipts verified with another's key")
	}
	// Another log's receipts alongside are passed over, not fatal.
	tr2, _ := other.Register(st, admitAll, now)
	s2, _ := scitt.Read(tr2)
	both, _ := scitt.Attach(tr, s2.Receipts...)
	sb, _ := scitt.Read(both)
	if in, err := VerifyReceipts(sb, l.PublicKey()); err != nil || len(in) != 2 {
		t.Errorf("with another log's receipts too: %v %d", err, len(in))
	}
}

// TestCrashTail: a record cut short is dropped on the next open, and the
// log carries on; a record that claims an impossible length is refused.
func TestCrashTail(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir, logName)
	k := issuerKey(t)
	l.Register(statement(t, k, "a"), admitAll, now)
	path := filepath.Join(dir, entriesFile)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.Write(binary.BigEndian.AppendUint32(nil, 500))
	f.Write([]byte("only part of it"))
	f.Close()
	tr, err := l.Register(statement(t, k, "b"), admitAll, now)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := scitt.Read(tr)
	in, err := VerifyReceipts(s, l.PublicKey())
	if err != nil || in[0].Index != 1 || in[0].Size != 2 {
		t.Errorf("after a cut-short record: %v %+v", err, in)
	}
	f, _ = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	f.Write(binary.BigEndian.AppendUint32(nil, 0))
	f.Close()
	if _, err := l.Size(); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("a zero-length record: %v", err)
	}
}

// TestConcurrent: two openers registering at once append one after the
// other, and every statement ends up with its own index.
func TestConcurrent(t *testing.T) {
	dir := t.TempDir()
	a, _ := Open(dir, logName)
	b, _ := Open(dir, "")
	k := issuerKey(t)
	var wg sync.WaitGroup
	seen := make([]uint64, 20)
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := a
			if i%2 == 1 {
				l = b
			}
			tr, err := l.Register(statement(t, k, fmt.Sprint("c", i)), admitAll, now)
			if err != nil {
				errs <- err
				return
			}
			s, _ := scitt.Read(tr)
			in, err := VerifyReceipts(s, a.PublicKey())
			if err != nil {
				errs <- err
				return
			}
			seen[i] = in[0].Index
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	indexes := map[uint64]bool{}
	for _, ix := range seen {
		indexes[ix] = true
	}
	if n, _ := a.Size(); n != 20 || len(indexes) != 20 {
		t.Errorf("size %d, %d distinct indexes", n, len(indexes))
	}
}

func TestKeyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	dir := t.TempDir()
	if _, err := Open(dir, logName); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, keyFile), 0o644)
	if _, err := Open(dir, ""); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("a readable key: %v", err)
	}
}

// TestAppendThenReceipts: appending signs nothing; receipts come when
// asked, for the log as it stands then, and an opener sees what another
// appended. A log that shrinks under an opener is refused.
func TestAppendThenReceipts(t *testing.T) {
	dir := t.TempDir()
	a, _ := Open(dir, logName)
	b, _ := Open(dir, "")
	k := issuerKey(t)
	i0, err := a.Append(statement(t, k, "x0"), admitAll)
	if err != nil {
		t.Fatal(err)
	}
	i1, err := b.Append(statement(t, k, "x1"), admitAll)
	if err != nil || i0 != 0 || i1 != 1 {
		t.Fatalf("%v %d %d", err, i0, i1)
	}
	tr, err := a.Receipts(1, now)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := scitt.Read(tr)
	in, err := VerifyReceipts(s, a.PublicKey())
	if err != nil || in[0].Index != 1 || in[0].Size != 2 || s.Subject != "x1" {
		t.Errorf("%v %+v %s", err, in, s.Subject)
	}
	if _, err := a.Receipts(2, now); err == nil {
		t.Error("a receipt for an entry the log does not hold")
	}
	var subjects []string
	if err := b.Each(func(i int, e []byte) error {
		st, err := scitt.Read(e)
		if err != nil {
			return err
		}
		subjects = append(subjects, fmt.Sprint(i, st.Subject))
		return nil
	}); err != nil || strings.Join(subjects, ",") != "0x0,1x1" {
		t.Errorf("each: %v %v", err, subjects)
	}
	path := filepath.Join(dir, entriesFile)
	info, _ := os.Stat(path)
	os.Truncate(path, info.Size()-10)
	if _, err := a.Size(); err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Errorf("a log that shrank: %v", err)
	}
}
