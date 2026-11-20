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
// the next time the log is opened; nothing else in the file is ever
// rewritten. Registration holds an exclusive lock across processes, so a
// command and a server registering at once append one after the other.
package receiptlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// MaxLog bounds the entries file read into memory to rebuild the tree.
const MaxLog = 1 << 30

// Log is a receipt log in a directory.
type Log struct {
	dir    string
	issuer string
	key    *pack.Key
	ed     *cose.Ed25519
	ml     *cose.MLDSA65
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
	return &Log{dir: dir, issuer: issuer, key: k, ed: ed, ml: ml}, nil
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

// Issuer is the log's name.
func (l *Log) Issuer() string { return l.issuer }

// PublicKey is what a verifier of the log's receipts needs.
func (l *Log) PublicKey() pack.KeyPublic { return l.key.PublicKey() }

// load reads every entry and rebuilds the tree, dropping a last record a
// crash cut short. The caller holds the lock.
func (l *Log) load() (*translog.Log, [][]byte, error) {
	path := filepath.Join(l.dir, entriesFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, MaxLog+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > MaxLog {
		return nil, nil, fmt.Errorf("the receipt log is past %d bytes, which this reads whole", MaxLog)
	}
	tree := translog.New()
	var entries [][]byte
	at := 0
	for at < len(body) {
		if len(body)-at < 4 {
			break
		}
		n := int(binary.BigEndian.Uint32(body[at:]))
		if n == 0 || n > cose.MaxMessage {
			return nil, nil, fmt.Errorf("the receipt log's record at byte %d claims %d bytes; the file is damaged", at, n)
		}
		if len(body)-at-4 < n {
			break
		}
		e := body[at+4 : at+4+n]
		tree.Append(e)
		entries = append(entries, e)
		at += 4 + n
	}
	if at < len(body) {
		// Written but never synced whole, so never receipted.
		if err := f.Truncate(int64(at)); err != nil {
			return nil, nil, fmt.Errorf("cannot drop the record a crash cut short: %w", err)
		}
	}
	return tree, entries, nil
}

// Size is how many entries the log holds.
func (l *Log) Size() (int, error) {
	unlock, err := atomicfile.Lock(filepath.Join(l.dir, lockFile))
	if err != nil {
		return 0, err
	}
	defer unlock()
	tree, _, err := l.load()
	if err != nil {
		return 0, err
	}
	return tree.Size(), nil
}

// Register appends a statement admit accepts and returns it transparent,
// carrying a receipt in each algorithm. A statement already in the log is
// not appended again: it gets fresh receipts for where it already is.
func (l *Log) Register(statement []byte, admit func(*scitt.Signed) error, now time.Time) ([]byte, error) {
	s, err := scitt.Read(statement)
	if err != nil {
		return nil, err
	}
	if admit == nil {
		return nil, errors.New("a statement is registered only under a policy that admits it")
	}
	if err := admit(s); err != nil {
		return nil, fmt.Errorf("not admitted: %w", err)
	}
	entry, err := s.Entry()
	if err != nil {
		return nil, err
	}
	unlock, err := atomicfile.Lock(filepath.Join(l.dir, lockFile))
	if err != nil {
		return nil, err
	}
	defer unlock()
	tree, entries, err := l.load()
	if err != nil {
		return nil, err
	}
	index := -1
	for i, e := range entries {
		if bytes.Equal(e, entry) {
			index = i
			break
		}
	}
	if index < 0 {
		if err := l.append(entry); err != nil {
			return nil, err
		}
		index = tree.Append(entry)
	}
	size := tree.Size()
	var receipts [][]byte
	for _, signer := range []cose.Signer{l.ed, l.ml} {
		r, err := scitt.IssueReceipt(signer, l.issuer, s.Subject, tree, entry, index, size, now)
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, r)
	}
	return scitt.Attach(entry, receipts...)
}

func (l *Log) append(entry []byte) error {
	f, err := os.OpenFile(filepath.Join(l.dir, entriesFile), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	rec := binary.BigEndian.AppendUint32(nil, uint32(len(entry)))
	rec = append(rec, entry...)
	if _, err := f.Write(rec); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// VerifyReceipts checks a transparent statement's receipts against a log's
// published key and requires one verified in each algorithm, for the same
// entry in the same tree. It returns the inclusions they establish.
func VerifyReceipts(s *scitt.Signed, logKey pack.KeyPublic) ([]scitt.Inclusion, error) {
	ed, ml, err := Verifiers(logKey)
	if err != nil {
		return nil, err
	}
	entry, err := s.Entry()
	if err != nil {
		return nil, err
	}
	edAt, mlAt := -1, -1
	var out []scitt.Inclusion
	for i, r := range s.Receipts {
		m, in, _, err := scitt.ReadReceipt(r)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i+1, err)
		}
		var v cose.Verifier
		at := &mlAt
		switch {
		case ed.Accepts(in.Algorithm):
			v, at = ed, &edAt
		case ml.Accepts(in.Algorithm):
			v = ml
		default:
			continue // another log's, in an algorithm this key has no half for
		}
		if kid := m.KeyID(); kid != nil && !bytes.Equal(kid, v.KeyID()) {
			continue // another log's, in the same algorithm
		}
		got, err := scitt.VerifyReceipt(r, entry, v)
		if err != nil {
			return nil, fmt.Errorf("receipt %d: %w", i+1, err)
		}
		out = append(out, got)
		*at = len(out) - 1
	}
	switch {
	case edAt < 0 && mlAt < 0:
		return nil, errors.New("no receipt from this log")
	case edAt < 0:
		return nil, errors.New("no Ed25519 receipt from this log: both are required, one per algorithm")
	case mlAt < 0:
		return nil, errors.New("no ML-DSA-65 receipt from this log: both are required, one per algorithm")
	}
	edIn, mlIn := out[edAt], out[mlAt]
	if !bytes.Equal(edIn.Root, mlIn.Root) || edIn.Issuer != mlIn.Issuer {
		return nil, errors.New("the log's two receipts are for different trees")
	}
	return out, nil
}
