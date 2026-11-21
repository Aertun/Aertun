// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/receiptlog"
	"github.com/aertun/aertun/internal/scitt"
)

const drillPass = "a passphrase of some length, kept elsewhere"

// drillStore is a store with access control, agents, a receipt log, a
// signed head and a root anchored in Bitcoin, and an administrator's token
// presented.
func drillStore(t *testing.T) string {
	t.Helper()
	root := caveatSite(t)
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin, auth.Scope{})
	if err != nil || saveTokens(root, ts) != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", secret)
	t.Setenv("AERTUN_BACKUP_PASSPHRASE", drillPass)

	l, err := receiptlog.Open(filepath.Join(root, "receipts"), "https://receipts.test")
	if err != nil {
		t.Fatal(err)
	}
	ed, _, err := receiptlog.Signers(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		st, err := scitt.Sign(ed, scitt.Statement{Issuer: "https://x.test", Subject: string(rune('a' + i)),
			ContentType: "application/example", Payload: []byte{byte(i)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(st, func(*scitt.Signed) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdAuditLog(root, []string{"head", "--save"}); err != nil {
		t.Fatal(err)
	}
	anchorRoot(t, root, "")
	return root
}

func mustKey(t *testing.T) *pack.Key {
	t.Helper()
	key, _ := signingFiles(t)
	k, err := loadSigningKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// anchorRoot records an anchored proof for the log's current root, or for
// the root given.
func anchorRoot(t *testing.T, root, digest string) {
	t.Helper()
	if digest == "" {
		events, err := audit.Read(auditPath(root))
		if err != nil {
			t.Fatal(err)
		}
		head, err := audit.TreeHead(events, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		digest = head.Root
	}
	f := anchorFile{Proofs: []anchor.Proof{{Digest: digest, Calendar: "https://calendar.test",
		State: anchor.Anchored, Height: 900000, SubmittedAt: time.Now().UTC().Format(time.RFC3339)}}}
	if err := saveJSON(anchorPath(root), f); err != nil {
		t.Fatal(err)
	}
}

func backupOf(t *testing.T, root string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "store.aertun-backup")
	if err := cmdBackup(root, []string{"--out", out}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRestoreDrill: a store backed up and restored into a new directory is
// the same store, file for file, apart from what the server appended after
// the copy was measured; its audit log is held to the head at backup, the
// head it signed and the root it anchored; and it works.
func TestRestoreDrill(t *testing.T) {
	root := drillStore(t)
	file := backupOf(t, root)
	body, _ := os.ReadFile(file)
	if bytes.Contains(body, []byte("dana@acme.example")) || bytes.Contains(body, []byte("receipts.test")) {
		t.Fatal("the backup holds plaintext")
	}
	to := filepath.Join(t.TempDir(), "restored")
	if err := cmdRestore([]string{file, "--to", to}); err != nil {
		t.Fatal(err)
	}
	compared := 0
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, ".lock") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		want, _ := os.ReadFile(path)
		got, rerr := os.ReadFile(filepath.Join(to, rel))
		switch rel {
		case "audit.jsonl":
			// The backup's own record came after the copy was measured.
			if rerr != nil || !bytes.HasPrefix(want, got) || len(got) == 0 {
				t.Errorf("the restored audit log is not a prefix of the store's")
			}
		case "tokens.json":
			// Using a token records when it was used.
			if rerr != nil {
				t.Errorf("tokens.json was not restored")
			}
		default:
			if rerr != nil || !bytes.Equal(want, got) {
				t.Errorf("%s did not come back as it was", rel)
			}
		}
		compared++
		return nil
	})
	if compared < 10 {
		t.Fatalf("only %d files compared", compared)
	}
	// The restored store answers the same token, and its logs verify.
	if c := resolveCaller(to, os.Getenv("AERTUN_TOKEN")); !c.Verified || c.Name != "dana@acme.example" {
		t.Errorf("the restored store does not know its administrator: %+v", c)
	}
	l, err := receiptlog.Open(filepath.Join(to, "receipts"), "")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := l.Size(); n != 3 {
		t.Errorf("the restored receipt log has %d entries", n)
	}
	if err := cmdRestore([]string{file, "--to", to}); err == nil {
		t.Error("a restore went over a store")
	}
}

// TestRestoreRefusesALogItsAnchorsDisown: a store whose anchored root is
// not a root of its own log restores, and is refused as not the log it
// claims to be, with the directory left for inspection.
func TestRestoreRefusesALogItsAnchorsDisown(t *testing.T) {
	root := drillStore(t)
	anchorRoot(t, root, hex.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	file := backupOf(t, root)
	to := filepath.Join(t.TempDir(), "restored")
	err := cmdRestore([]string{file, "--to", to})
	if err == nil || !strings.Contains(err.Error(), "not a root of this log") || !strings.Contains(err.Error(), "must not be put in service") {
		t.Fatalf("%v", err)
	}
}

// TestBackupRefusals: no passphrase, a short one, a readable passphrase
// file, a backup inside the store, and somebody who is not an
// administrator.
func TestBackupRefusals(t *testing.T) {
	root := drillStore(t)
	out := filepath.Join(t.TempDir(), "b")
	t.Setenv("AERTUN_BACKUP_PASSPHRASE", "")
	if err := cmdBackup(root, []string{"--out", out}); err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Errorf("no passphrase: %v", err)
	}
	t.Setenv("AERTUN_BACKUP_PASSPHRASE", "short")
	if err := cmdBackup(root, []string{"--out", out}); err == nil {
		t.Error("a short passphrase was accepted")
	}
	pf := filepath.Join(t.TempDir(), "pass")
	os.WriteFile(pf, []byte(drillPass+"\n"), 0o644)
	if err := cmdBackup(root, []string{"--out", out, "--passphrase-file", pf}); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("a readable passphrase file: %v", err)
	}
	t.Setenv("AERTUN_BACKUP_PASSPHRASE", drillPass)
	if err := cmdBackup(root, []string{"--out", filepath.Join(root, "inside")}); err == nil {
		t.Error("a backup was written inside the store")
	}
	ts, _ := loadTokens(root)
	viewer, _, _ := ts.Issue("someone", "watcher", auth.RoleAnalyst, "/", time.Hour, auth.RoleAdmin)
	saveTokens(root, ts)
	t.Setenv("AERTUN_TOKEN", viewer)
	if err := cmdBackup(root, []string{"--out", out}); err == nil {
		t.Error("an analyst took a backup of every secret")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a refused backup left a file")
	}
}

// TestRestoreMovesAnAuditLogKeptElsewhere: an audit log the store keeps in
// another directory travels in the backup and is restored beside the store.
func TestRestoreMovesAnAuditLogKeptElsewhere(t *testing.T) {
	root := drillStore(t)
	other := t.TempDir()
	for _, f := range []string{"audit.jsonl", "audit.key"} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue
		}
		os.WriteFile(filepath.Join(other, f), b, 0o600)
		os.Remove(filepath.Join(root, f))
	}
	if err := setAuditDir(root, other); err != nil {
		t.Fatal(err)
	}
	file := backupOf(t, root)
	to := filepath.Join(t.TempDir(), "restored")
	if err := cmdRestore([]string{file, "--to", to}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(to, "audit.jsonl")); err != nil {
		t.Error("the audit log was not restored beside the store")
	}
	if _, err := os.Stat(filepath.Join(to, "auditlog.dir")); err == nil {
		t.Error("the restored store still points at the old audit directory")
	}
}

// TestRestoreHoldsTheLogToTheHeadAtBackup: a restored log whose root at the
// recorded size is not the root recorded is refused.
func TestRestoreHoldsTheLogToTheHeadAtBackup(t *testing.T) {
	root := drillStore(t)
	file := backupOf(t, root)
	to := filepath.Join(t.TempDir(), "restored")
	if err := cmdRestore([]string{file, "--to", to}); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(to))
	st := backupStore{AuditSize: len(events), AuditRoot: hex.EncodeToString(bytes.Repeat([]byte{9}, 32))}
	if _, err := settleRestore(to, st); err == nil || !strings.Contains(err.Error(), "recorded at backup") {
		t.Errorf("a log not matching the head at backup: %v", err)
	}
	st.AuditSize = len(events) + 1
	if _, err := settleRestore(to, st); err == nil || !strings.Contains(err.Error(), "had") {
		t.Errorf("a log shorter than at backup: %v", err)
	}
}
