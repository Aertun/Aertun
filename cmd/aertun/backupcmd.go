// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/backup"
	"github.com/aertun/aertun/internal/receiptlog"
)

// `aertun backup` and `aertun restore`: the whole store in one encrypted
// file (internal/backup), and back, checked.
//
// # A consistent copy without stopping the server
//
// Most files here are replaced whole (internal/atomicfile), so a file
// opened is a file complete. The two that grow in place — the audit log
// and the receipt log — are measured under their own locks before
// anything is copied, and copied to exactly that length: each is a prefix
// that was whole, and its Merkle head at that length is recorded in the
// manifest. Writes go on meanwhile, and land after the prefix.
//
// # A restore that proves itself
//
// A restore goes into a new directory, never over a store. It then
// rebuilds the audit log's chain and Merkle tree and holds them to the
// head recorded at backup, to every head the log signed, and to every
// root it anchored in Bitcoin: a restored log that is not the log those
// commitments were made to is refused, not quietly put in service.

const backupUsage = `usage:
  aertun backup --out FILE [--passphrase-file F]
  aertun restore FILE --to DIR [--passphrase-file F]
The passphrase is read from --passphrase-file, or AERTUN_BACKUP_PASSPHRASE; at least 15 characters.`

// backupStore is what a backup records about the store it was taken from.
type backupStore struct {
	AuditSize      int    `json:"audit_size"`
	AuditRoot      string `json:"audit_root"`
	AuditElsewhere string `json:"audit_elsewhere,omitempty"`
	ReceiptEntries int    `json:"receipt_entries"`
}

// auditPrefix is where an audit log kept outside the store is put inside
// a backup.
const auditPrefix = "auditlog"

func backupPassphrase(path string) (string, error) {
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("%s is readable by others (mode %04o); a passphrase file must be 0600",
				path, info.Mode().Perm())
		}
		b, err := readBounded(path, 4<<10)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if p := os.Getenv("AERTUN_BACKUP_PASSPHRASE"); p != "" {
		return p, nil
	}
	return "", errors.New("no passphrase: give --passphrase-file F, or set AERTUN_BACKUP_PASSPHRASE")
}

func cmdBackup(root string, args []string) error {
	fset := flag.NewFlagSet("backup", flag.ContinueOnError)
	outAt := fset.String("out", "", "the backup file to write")
	passAt := fset.String("passphrase-file", "", "a 0600 file holding the passphrase")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if *outAt == "" || fset.NArg() != 0 {
		return errors.New(backupUsage)
	}
	pass, err := backupPassphrase(*passAt)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Every secret the store holds is in a backup: an administrator's act.
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	absOut, err := filepath.Abs(*outAt)
	if err != nil {
		return err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if strings.HasPrefix(absOut, absRoot+string(filepath.Separator)) {
		return errors.New("the backup would be written inside the store it copies; put it somewhere else")
	}
	st, limits, err := measureStore(root)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(absOut), ".aertun-backup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	bw, err := backup.NewWriter(tmp, pass, time.Now())
	if err != nil {
		tmp.Close()
		return err
	}
	files := 0
	add := func(base, prefix string) error {
		return filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(base, path)
			if err != nil || rel == "." {
				return err
			}
			name := filepath.ToSlash(rel)
			if prefix != "" {
				name = prefix + "/" + name
			}
			switch {
			case d.Type()&fs.ModeSymlink != 0:
				return fmt.Errorf("%s is a symbolic link; a store holds none, and a backup will not follow one", path)
			case d.IsDir():
				info, err := d.Info()
				if err != nil {
					return err
				}
				return bw.Dir(name, info.Mode())
			case !d.Type().IsRegular():
				return fmt.Errorf("%s is not a regular file", path)
			case strings.HasSuffix(name, ".lock"):
				return nil // a lock belongs to the process holding it
			}
			if same, _ := filepath.Abs(path); same == absOut {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				return err
			}
			size := info.Size()
			if abs, err := filepath.Abs(path); err == nil {
				if n, ok := limits[abs]; ok {
					size = n
				}
			}
			files++
			return bw.File(name, info.Mode(), size, f)
		})
	}
	if err := add(root, ""); err != nil {
		tmp.Close()
		return err
	}
	if st.AuditElsewhere != "" {
		if err := add(st.AuditElsewhere, auditPrefix); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := bw.Close("aertun "+version, st); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), absOut); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("store.backed-up", "/", audit.Success,
		map[string]string{"files": fmt.Sprint(files), "audit_size": fmt.Sprint(st.AuditSize)})); err != nil {
		return err
	}
	if !w.JSON(map[string]any{"out": absOut, "files": files, "audit_size": st.AuditSize,
		"audit_root": st.AuditRoot, "receipt_entries": st.ReceiptEntries}) {
		w.Human("%d files written to %s, encrypted; the audit log at %d entries, root %s\n",
			files, absOut, st.AuditSize, short(st.AuditRoot))
		w.Human("  %skeep the passphrase apart from the file: without it the backup cannot be read%s\n", dim, reset)
	}
	return nil
}

// measureStore takes, under each log's lock, the length the copy will
// stop at and what the log commits to there.
func measureStore(root string) (backupStore, map[string]int64, error) {
	var st backupStore
	limits := map[string]int64{}
	dir := auditDir(root)
	if abs, _ := filepath.Abs(dir); abs != "" {
		if r, _ := filepath.Abs(root); r != abs {
			st.AuditElsewhere = abs
		}
	}
	logPath := auditPath(root)
	if _, err := os.Stat(logPath); err == nil {
		unlock, err := atomicfile.Lock(logPath + ".lock")
		if err != nil {
			return st, nil, err
		}
		info, err := os.Stat(logPath)
		var events []audit.Event
		if err == nil {
			events, err = audit.Read(logPath)
		}
		unlock()
		if err != nil {
			return st, nil, err
		}
		head, err := audit.TreeHead(events, time.Now())
		if err != nil {
			return st, nil, err
		}
		st.AuditSize, st.AuditRoot = head.Size, head.Root
		abs, err := filepath.Abs(logPath)
		if err != nil {
			return st, nil, err
		}
		limits[abs] = info.Size()
	}
	rdir := filepath.Join(root, "receipts")
	if receiptlog.Exists(rdir) {
		l, err := receiptlog.Open(rdir, "")
		if err != nil {
			return st, nil, err
		}
		n, size, err := l.Measure()
		if err != nil {
			return st, nil, err
		}
		st.ReceiptEntries = n
		abs, err := filepath.Abs(filepath.Join(rdir, "entries"))
		if err != nil {
			return st, nil, err
		}
		limits[abs] = size
	}
	return st, limits, nil
}

func cmdRestore(args []string) error {
	pos, rest := leadingArgs(args, 1)
	fset := flag.NewFlagSet("restore", flag.ContinueOnError)
	to := fset.String("to", "", "a new, empty directory to restore the store into")
	passAt := fset.String("passphrase-file", "", "a 0600 file holding the passphrase")
	if err := fset.Parse(rest); err != nil {
		return err
	}
	if len(pos) != 1 || *to == "" || fset.NArg() != 0 {
		return errors.New(backupUsage)
	}
	pass, err := backupPassphrase(*passAt)
	if err != nil {
		return err
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	defer f.Close()
	m, err := backup.Restore(f, pass, *to)
	if err != nil {
		return err
	}
	var st backupStore
	if err := json.Unmarshal(m.Store, &st); err != nil {
		return fmt.Errorf("the backup does not say what store it was: %w", err)
	}
	report, err := settleRestore(*to, st)
	if err != nil {
		return fmt.Errorf("restored into %s, and it does not check out: %w; the directory is left for "+
			"inspection and must not be put in service", *to, err)
	}
	report["files"] = len(m.Files)
	report["taken"] = m.Taken.Format(time.RFC3339)
	report["program"] = m.Program
	if !w.JSON(report) {
		w.Human("restored %d files into %s, from a backup taken %s by %s\n", len(m.Files), *to,
			m.Taken.Format(time.RFC3339), m.Program)
		w.Human("  the audit log: %v entries, chain and tree whole, the head at backup matches\n", report["audit_entries"])
		w.Human("  signed heads checked: %v; anchored roots matched: %v\n", report["heads_checked"], report["anchors_matched"])
		if v, ok := report["receipt_entries"]; ok {
			w.Human("  the receipt log: %v entries\n", v)
		}
		if note, ok := report["note"]; ok {
			w.Human("  %s%v%s\n", dim, note, reset)
		}
	}
	return nil
}

// settleRestore puts an audit log that lived outside the store beside the
// rest, then holds what was restored to what the backup recorded.
func settleRestore(dir string, st backupStore) (map[string]any, error) {
	report := map[string]any{}
	moved := filepath.Join(dir, auditPrefix)
	if st.AuditElsewhere != "" {
		entries, err := os.ReadDir(moved)
		if err != nil {
			return nil, fmt.Errorf("the backup says the audit log lived at %s, and holds no copy of it", st.AuditElsewhere)
		}
		for _, e := range entries {
			target := filepath.Join(dir, e.Name())
			if _, err := os.Stat(target); err == nil {
				return nil, fmt.Errorf("%s is both in the store and beside the audit log", e.Name())
			}
			if err := os.Rename(filepath.Join(moved, e.Name()), target); err != nil {
				return nil, err
			}
		}
		if err := os.Remove(moved); err != nil {
			return nil, err
		}
		if err := os.Remove(filepath.Join(dir, "auditlog.dir")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		report["note"] = fmt.Sprintf("the audit log lived at %s and is restored beside the store; "+
			"aertun auditlog dir moves it again", st.AuditElsewhere)
	}
	if logDirOverride != "" {
		return nil, errors.New("a restore is checked against the store's own log, not one named elsewhere")
	}
	logPath := auditPath(dir)
	events, err := audit.Read(logPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if ok, problems := audit.Verify(events); !ok {
		return nil, fmt.Errorf("the audit log does not verify: %v", problems[0])
	}
	if len(events) < st.AuditSize {
		return nil, fmt.Errorf("the audit log has %d entries and had %d at backup", len(events), st.AuditSize)
	}
	report["audit_entries"] = len(events)

	// Every size a commitment names, then every root at those sizes, in
	// one pass over the log.
	var heads headFile
	if err := loadJSON(headsPath(dir), &heads); err != nil {
		return nil, err
	}
	var anchors anchorFile
	if err := loadJSON(anchorPath(dir), &anchors); err != nil {
		return nil, err
	}
	sizes := []int{}
	for n := 1; n <= len(events); n++ {
		sizes = append(sizes, n)
	}
	roots, err := audit.Roots(events, sizes)
	if err != nil {
		return nil, err
	}
	rootAt := func(n int) string {
		if n < 1 || n > len(roots) {
			return ""
		}
		return roots[n-1]
	}
	if st.AuditSize > 0 && rootAt(st.AuditSize) != st.AuditRoot {
		return nil, fmt.Errorf("the audit log's root at %d entries is not the one recorded at backup", st.AuditSize)
	}
	checked := 0
	for _, h := range heads.Heads {
		if h.Size > len(events) {
			return nil, fmt.Errorf("a signed head names %d entries and the log has %d", h.Size, len(events))
		}
		if h.Size > 0 && rootAt(h.Size) != h.Root {
			return nil, fmt.Errorf("the log does not match the head it signed at %d entries", h.Size)
		}
		checked++
	}
	report["heads_checked"] = checked
	all := map[string]bool{}
	for _, r := range roots {
		all[r] = true
	}
	matched := 0
	for _, p := range anchors.Proofs {
		if !p.Anchored() {
			continue
		}
		if !all[p.Digest] {
			return nil, fmt.Errorf("a root anchored in Bitcoin (block %d) is not a root of this log", p.Height)
		}
		matched++
	}
	report["anchors_matched"] = matched

	rdir := filepath.Join(dir, "receipts")
	if receiptlog.Exists(rdir) {
		l, err := receiptlog.Open(rdir, "")
		if err != nil {
			return nil, err
		}
		n, err := l.Size()
		if err != nil {
			return nil, err
		}
		if n < st.ReceiptEntries {
			return nil, fmt.Errorf("the receipt log has %d entries and had %d at backup", n, st.ReceiptEntries)
		}
		report["receipt_entries"] = n
	}
	return report, nil
}
