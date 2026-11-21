// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package receiptlog is the transparency log signed statements are
// registered in: an append-only file of entries, the Merkle tree over them
// (RFC 9162 hashing, internal/translog), and a dual key that signs a
// receipt in each of its algorithms for every entry.
//
// # Two receipts, both required
//
// Every other document this program signs carries an Ed25519 and an
// ML-DSA-65 signature, so a break in either algorithm leaves the other
// standing. A COSE receipt carries one signature, so the log issues two for
// each entry, and VerifyReceipts requires one in each from the log's key.
// An Ed25519 statement registered here is then protected after Ed25519
// falls: a forgery made later has no ML-DSA receipt from the log.
//
// # On disk
//
// Each entry is a four-byte big-endian length and the statement's bytes,
// written and synced before any receipt for it is signed. So a record cut
// short by a crash is one no receipt was ever issued for, and is dropped
// the next time the log is read; nothing else in the file is ever
// rewritten, and a file found shorter than what was read from it is
// refused. Every operation holds an exclusive lock across processes, so a
// command and a server append one after the other.
//
// # Appending is cheap; receipts are on demand
//
// A server that appends a statement for every call it answers cannot
// reread the log each time. So an opened log keeps its tree and reads only
// what other processes appended since; Append signs nothing; and Receipts
// proves an entry's inclusion in the log as it stands when asked, as SCITT
// allows a receipt to be fetched after registration.
package receiptlog

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/scitt"
	"github.com/aertun/aertun/internal/translog"
)

const (
	entriesFile = "entries"
	keyFile     = "key"
	issuerFile  = "issuer"
	lockFile    = "lock"
)

// MaxLog bounds the entries file.
const MaxLog = 1 << 30

// Log is a receipt log in a directory.
type Log struct {
	dir    string
	issuer string
	key    *pack.Key
	ed     *cose.Ed25519
	ml     *cose.MLDSA65

	// What has been read of the entries file: the tree over it, each
	// entry's offset, and each entry's index by its digest. Kept, so each
	// operation reads only what other processes appended since.
	mu      sync.Mutex
	tree    *translog.Log
	offsets []int64
	leaves  map[[32]byte]int
	read    int64
}

// Open opens the log in dir, creating it, its key and its name on first
// use. issuer names the log in its receipts; once set it is the log's
// name, and a different one is refused rather than quietly used.
func Open(dir, issuer string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := atomicfile.Lock(filepath.Join(dir, lockFile))
	if err != nil {
		return nil, err
	}
	defer unlock()
	name, err := os.ReadFile(filepath.Join(dir, issuerFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		if issuer == "" {
			return nil, errors.New("a new receipt log needs a name: the issuer its receipts carry")
		}
		if err := scitt.CheckClaim("issuer", issuer); err != nil {
			return nil, err
		}
		if err := atomicfile.Write(filepath.Join(dir, issuerFile), []byte(issuer+"\n"), 0o600); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		stored := strings.TrimSpace(string(name))
		if issuer != "" && issuer != stored {
			return nil, fmt.Errorf("this receipt log is named %s, not %s", stored, issuer)
		}
		issuer = stored
	}
	kp := filepath.Join(dir, keyFile)
	if _, err := os.Stat(kp); errors.Is(err, os.ErrNotExist) {
		k, err := pack.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := pack.SaveKey(kp, k, 0o600); err != nil {
			return nil, err
		}
	}
	if info, err := os.Stat(kp); err != nil {
		return nil, err
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %04o); the log's key must be 0600", kp, info.Mode().Perm())
	}
	k, err := pack.LoadKey(kp)
	if err != nil {
		return nil, err
	}
	ed, ml, err := Signers(k)
	if err != nil {
		return nil, err
	}
	return &Log{dir: dir, issuer: issuer, key: k, ed: ed, ml: ml, tree: translog.New(),
		leaves: map[[32]byte]int{}}, nil
}

// Exists reports whether a receipt log has been set up in dir.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, issuerFile))
	return err == nil
}

// Signers are a dual key's halves as COSE signers.
func Signers(k *pack.Key) (*cose.Ed25519, *cose.MLDSA65, error) {
	edPriv, mlPriv, err := k.Halves()
	if err != nil {
		return nil, nil, err
	}
	ed, err := cose.NewEd25519Signer(edPriv)
	if err != nil {
		return nil, nil, err
	}
	ml, err := cose.NewMLDSA65Signer(mlPriv)
	if err != nil {
		return nil, nil, err
	}
	return ed, ml, nil
}

// Verifiers are a published dual key's halves as COSE verifiers.
func Verifiers(pub pack.KeyPublic) (*cose.Ed25519, *cose.MLDSA65, error) {
	edPub, mlPub, err := pub.Halves()
	if err != nil {
		return nil, nil, err
	}
	ed, err := cose.NewEd25519Verifier(edPub)
	if err != nil {
		return nil, nil, err
	}
	ml, err := cose.NewMLDSA65Verifier(mlPub)
	if err != nil {
		return nil, nil, err
	}
	return ed, ml, nil
}

// Signer is the log's Ed25519 half, for statements this deployment makes
// about what it saw itself; verifiers check them with the log's key.
func (l *Log) Signer() cose.Signer { return l.ed }

// Issuer is the log's name.
func (l *Log) Issuer() string { return l.issuer }

// PublicKey is what a verifier of the log's receipts needs.
func (l *Log) PublicKey() pack.KeyPublic { return l.key.PublicKey() }

// locked runs f holding the lock across processes and this log's own,
// after reading whatever other processes appended since it last looked.
func (l *Log) locked(f func(*os.File) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := atomicfile.Lock(filepath.Join(l.dir, lockFile))
	if err != nil {
		return err
	}
	defer unlock()
	file, err := os.OpenFile(filepath.Join(l.dir, entriesFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := l.catchUp(file); err != nil {
		return err
	}
	return f(file)
}

// catchUp reads the records past what this log has read, adding each to
// the tree, and drops a last record a crash cut short: one is written and
// synced whole before any receipt for it is signed, so a partial one was
// never receipted. The caller holds the lock, so no append is under way.
func (l *Log) catchUp(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()
	switch {
	case size < l.read:
		return fmt.Errorf("the receipt log is %d bytes and %d were read from it: it was rewritten, "+
			"which an append-only log never is", size, l.read)
	case size > MaxLog:
		return fmt.Errorf("the receipt log is past %d bytes", MaxLog)
	case size == l.read:
		return nil
	}
	body := make([]byte, size-l.read)
	if _, err := f.ReadAt(body, l.read); err != nil {
		return err
	}
	at := 0
	for len(body)-at >= 4 {
		n := int(binary.BigEndian.Uint32(body[at:]))
		if n == 0 || n > cose.MaxMessage {
			return fmt.Errorf("the receipt log's record at byte %d claims %d bytes; the file is damaged",
				l.read+int64(at), n)
		}
		if len(body)-at-4 < n {
			break
		}
		e := body[at+4 : at+4+n]
		l.offsets = append(l.offsets, l.read+int64(at))
		l.leaves[sha256.Sum256(e)] = l.tree.Append(e)
		at += 4 + n
	}
	l.read += int64(at)
	if l.read < size {
		if err := f.Truncate(l.read); err != nil {
			return fmt.Errorf("cannot drop the record a crash cut short: %w", err)
		}
	}
	return nil
}

// entryAt reads the entry at index. The caller holds the lock.
func (l *Log) entryAt(f *os.File, index int) ([]byte, error) {
	var n [4]byte
	if _, err := f.ReadAt(n[:], l.offsets[index]); err != nil {
		return nil, err
	}
	e := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := f.ReadAt(e, l.offsets[index]+4); err != nil {
		return nil, err
	}
	return e, nil
}

// Size is how many entries the log holds.
func (l *Log) Size() (int, error) {
	var n int
	err := l.locked(func(*os.File) error { n = l.tree.Size(); return nil })
	return n, err
}

// Measure is how many entries the log holds and the length of the file
// that holds them, read under the lock: a copy of that many bytes is the
// log as it stood, whatever is appended while it is made.
func (l *Log) Measure() (int, int64, error) {
	var n int
	var size int64
	err := l.locked(func(*os.File) error { n, size = l.tree.Size(), l.read; return nil })
	return n, size, err
}

// Append adds a statement admit accepts, and returns its index. A
// statement already in the log is not added again; its index is returned.
func (l *Log) Append(statement []byte, admit func(*scitt.Signed) error) (int, error) {
	s, err := scitt.Read(statement)
	if err != nil {
		return 0, err
	}
	if admit == nil {
		return 0, errors.New("a statement is registered only under a policy that admits it")
	}
	if err := admit(s); err != nil {
		return 0, fmt.Errorf("not admitted: %w", err)
	}
	entry, err := s.Entry()
	if err != nil {
		return 0, err
	}
	index := -1
	err = l.locked(func(f *os.File) error {
		if i, ok := l.leaves[sha256.Sum256(entry)]; ok {
			index = i
			return nil
		}
		rec := binary.BigEndian.AppendUint32(nil, uint32(len(entry)))
		rec = append(rec, entry...)
		if _, err := f.WriteAt(rec, l.read); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		l.offsets = append(l.offsets, l.read)
		index = l.tree.Append(entry)
		l.leaves[sha256.Sum256(entry)] = index
		l.read += int64(len(rec))
		return nil
	})
	return index, err
}

// Receipts returns the entry at index as a transparent statement, with a
// receipt in each algorithm for the log as it stands.
func (l *Log) Receipts(index int, now time.Time) ([]byte, error) {
	var out []byte
	err := l.locked(func(f *os.File) error {
		if index < 0 || index >= l.tree.Size() {
			return fmt.Errorf("the log has no entry %d", index)
		}
		entry, err := l.entryAt(f, index)
		if err != nil {
			return err
		}
		s, err := scitt.Read(entry)
		if err != nil {
			return fmt.Errorf("entry %d: %w", index, err)
		}
		var receipts [][]byte
		for _, signer := range []cose.Signer{l.ed, l.ml} {
			r, err := scitt.IssueReceipt(signer, l.issuer, s.Subject, l.tree, entry, index, l.tree.Size(), now)
			if err != nil {
				return err
			}
			receipts = append(receipts, r)
		}
		out, err = scitt.Attach(entry, receipts...)
		return err
	})
	return out, err
}

// Register appends a statement admit accepts and returns it transparent.
func (l *Log) Register(statement []byte, admit func(*scitt.Signed) error, now time.Time) ([]byte, error) {
	index, err := l.Append(statement, admit)
	if err != nil {
		return nil, err
	}
	return l.Receipts(index, now)
}

// Each calls f with every entry's index and bytes, in order, while holding
// the lock; f must not call back into the log.
func (l *Log) Each(f func(index int, entry []byte) error) error {
	return l.locked(func(file *os.File) error {
		for i := range l.offsets {
			e, err := l.entryAt(file, i)
			if err != nil {
				return err
			}
			if err := f(i, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// VerifyReceipts checks a transparent statement's receipts against a log's
// published key and requires one verified in each algorithm, for the same
// entry in the same tree. It returns the inclusions they establish.
func VerifyReceipts(s *scitt.Signed, logKey pack.KeyPublic) ([]scitt.Inclusion, error) {
	ed, ml, err := Verifiers(logKey)
	if err != nil {
		return nil, err
	}
	return scitt.VerifyReceipts(s, ed, ml)
}
