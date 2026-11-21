// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package backup writes and reads an encrypted archive of a store.
//
// # Everything is encrypted
//
// A store holds keys and secrets in many files: signing seeds, the audit
// log's pseudonymisation key, the keyring, token hashes, a SCIM token. A
// backup that encrypted only the files on a list would be one new file away
// from leaking. So the whole archive is encrypted, and the question of which
// files are secret is never asked.
//
// # The format
//
// A magic line, a JSON header (format version, KDF parameters, salt, chunk
// size), then the archive in chunks. The key is PBKDF2-HMAC-SHA-256 over a
// passphrase (NIST SP 800-132), with a random salt per backup and 600,000
// iterations. Each chunk is AES-256-GCM with a nonce that counts chunks, and
// additional data that binds the header and marks the last chunk: chunks
// cannot be reordered, dropped, or cut off at the end without the last
// one failing to open (the STREAM construction of Hoang, Reyhanitabar,
// Rogaway and Vizár).
//
// Inside is a tar archive of regular files and directories, then a
// manifest of every file's size and SHA-256, and what the caller recorded
// about the store when it was taken.
//
// # Reading one back
//
// Every name must be local (filepath.IsLocal): no absolute path, no "..",
// so an archive cannot write outside the directory it is restored into.
// Links, devices and anything but files and directories are refused. Each
// file is hashed as it is written and held to the manifest, which must
// list exactly the files the archive held.
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Magic begins every backup.
const Magic = "AERTUN-BACKUP\n"

// Version is the format version this writes.
const Version = 1

// Iterations is the PBKDF2 work factor this writes; a reader accepts any
// from MinIterations up.
const (
	Iterations    = 600_000
	MinIterations = 600_000
	MaxIterations = 10_000_000
)

// MinPassphrase is the shortest passphrase accepted: NIST SP 800-63B's
// floor for a memorised secret used alone.
const MinPassphrase = 15

const (
	chunkSize   = 64 << 10
	manifestTar = ".aertun-backup-manifest.json"
	maxHeader   = 4 << 10
	// MaxFile bounds one file read back.
	MaxFile = 16 << 30
)

type header struct {
	Format     int    `json:"format"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Cipher     string `json:"cipher"`
	Chunk      int    `json:"chunk"`
}

// Manifest describes what a backup holds.
type Manifest struct {
	Format  int       `json:"format"`
	Program string    `json:"program"`
	Taken   time.Time `json:"taken"`
	Files   []File    `json:"files"`
	// Store is what the caller recorded about the store, for the restore
	// to hold the result to.
	Store json.RawMessage `json:"store,omitempty"`
}

// File is one file in a backup.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

func key(passphrase string, salt []byte, iterations int) ([]byte, error) {
	if len([]rune(passphrase)) < MinPassphrase {
		return nil, fmt.Errorf("a backup passphrase is at least %d characters", MinPassphrase)
	}
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32)
}

// -- writing ------------------------------------------------------------------

// sealer encrypts what is written to it in chunks.
type sealer struct {
	w     io.Writer
	aead  cipher.AEAD
	ad    []byte
	buf   []byte
	count uint64
}

func (s *sealer) nonce() []byte {
	n := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], s.count)
	return n
}

func (s *sealer) seal(last bool) error {
	ad := append(bytes.Clone(s.ad), 0)
	if last {
		ad[len(ad)-1] = 1
	}
	ct := s.aead.Seal(nil, s.nonce(), s.buf, ad)
	s.count++
	s.buf = s.buf[:0]
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(ct)))
	if _, err := s.w.Write(n[:]); err != nil {
		return err
	}
	_, err := s.w.Write(ct)
	return err
}

func (s *sealer) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		take := min(chunkSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:take]...)
		p, written = p[take:], written+take
		if len(s.buf) == chunkSize {
			if err := s.seal(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Writer writes one backup.
type Writer struct {
	s      *sealer
	tw     *tar.Writer
	files  []File
	seen   map[string]bool
	taken  time.Time
	closed bool
}

// NewWriter begins a backup to w under a passphrase.
func NewWriter(w io.Writer, passphrase string, now time.Time) (*Writer, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	k, err := key(passphrase, salt, Iterations)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	h, err := json.Marshal(header{Format: Version, KDF: "PBKDF2-HMAC-SHA256", Iterations: Iterations,
		Salt: hex.EncodeToString(salt), Cipher: "AES-256-GCM", Chunk: chunkSize})
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, Magic); err != nil {
		return nil, err
	}
	if _, err := w.Write(append(h, '\n')); err != nil {
		return nil, err
	}
	s := &sealer{w: w, aead: aead, ad: append([]byte(Magic), h...)}
	return &Writer{s: s, tw: tar.NewWriter(s), seen: map[string]bool{}, taken: now.UTC()}, nil
}

func checkName(name string) error {
	if name == "" || !filepath.IsLocal(filepath.FromSlash(name)) || strings.Contains(name, `\`) ||
		path.Clean(name) != name || name == manifestTar {
		return fmt.Errorf("%q is not a path a backup holds", name)
	}
	return nil
}

// Dir records a directory.
func (b *Writer) Dir(name string, mode os.FileMode) error {
	if err := checkName(name); err != nil {
		return err
	}
	return b.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: int64(mode.Perm()),
		ModTime: b.taken})
}

// File records one file of exactly size bytes read from r.
func (b *Writer) File(name string, mode os.FileMode, size int64, r io.Reader) error {
	if err := checkName(name); err != nil {
		return err
	}
	if b.seen[name] {
		return fmt.Errorf("%s is in the backup twice", name)
	}
	b.seen[name] = true
	if err := b.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: int64(mode.Perm()),
		Size: size, ModTime: b.taken}); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(b.tw, io.TeeReader(io.LimitReader(r, size), h))
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("%s ended at %d bytes, %d were expected: it changed while it was read", name, n, size)
	}
	b.files = append(b.files, File{Path: name, Size: size, Mode: uint32(mode.Perm()), SHA256: hex.EncodeToString(h.Sum(nil))})
	return nil
}

// Close writes the manifest, with what the caller records about the
// store, and the last chunk.
func (b *Writer) Close(program string, store any) error {
	if b.closed {
		return errors.New("the backup is closed")
	}
	b.closed = true
	m := Manifest{Format: Version, Program: program, Taken: b.taken, Files: b.files}
	if store != nil {
		raw, err := json.Marshal(store)
		if err != nil {
			return err
		}
		m.Store = raw
	}
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := b.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: manifestTar, Mode: 0o600,
		Size: int64(len(body)), ModTime: b.taken}); err != nil {
		return err
	}
	if _, err := b.tw.Write(body); err != nil {
		return err
	}
	if err := b.tw.Close(); err != nil {
		return err
	}
	return b.s.seal(true)
}

// -- reading ------------------------------------------------------------------

// opener decrypts chunks, refusing anything after the last.
type opener struct {
	r     *bufio.Reader
	aead  cipher.AEAD
	ad    []byte
	buf   []byte
	count uint64
	done  bool
}

func (o *opener) Read(p []byte) (int, error) {
	for len(o.buf) == 0 {
		if o.done {
			return 0, io.EOF
		}
		var n [4]byte
		if _, err := io.ReadFull(o.r, n[:]); err != nil {
			return 0, errors.New("the backup ends before its last chunk: it was cut short")
		}
		size := binary.BigEndian.Uint32(n[:])
		if int(size) > chunkSize+o.aead.Overhead() {
			return 0, errors.New("a chunk is larger than the format allows")
		}
		ct := make([]byte, size)
		if _, err := io.ReadFull(o.r, ct); err != nil {
			return 0, errors.New("the backup ends inside a chunk: it was cut short")
		}
		nonce := make([]byte, o.aead.NonceSize())
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], o.count)
		o.count++
		for _, last := range []byte{0, 1} {
			pt, err := o.aead.Open(nil, nonce, ct, append(bytes.Clone(o.ad), last))
			if err == nil {
				o.buf, o.done = pt, last == 1
				break
			}
			if last == 1 {
				return 0, errors.New("a chunk does not open: the passphrase is wrong, or the backup was changed")
			}
		}
		if o.done {
			if _, err := o.r.ReadByte(); err != io.EOF {
				return 0, errors.New("there is data after the backup's last chunk")
			}
		}
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

// Restore reads a backup from r into dir, which must not exist or be
// empty, and returns its manifest once every file is held to it. A restore
// that fails leaves dir as it found it: what it wrote is removed, since
// half a store is worse than none.
func Restore(r io.Reader, passphrase, dir string) (m *Manifest, err error) {
	// Checked first, and only then is anything ever removed: a directory
	// refused for holding something is left exactly as it is.
	if err := emptyDir(dir); err != nil {
		return nil, err
	}
	m, err = restore(r, passphrase, dir)
	if err != nil {
		if entries, rerr := os.ReadDir(dir); rerr == nil {
			for _, e := range entries {
				os.RemoveAll(filepath.Join(dir, e.Name()))
			}
		}
	}
	return m, err
}

func restore(r io.Reader, passphrase, dir string) (*Manifest, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != Magic {
		return nil, errors.New("this is not an Aertun backup")
	}
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxHeader {
		return nil, errors.New("the backup's header is unreadable")
	}
	hdr := bytes.TrimSuffix(line, []byte("\n"))
	var h header
	dec := json.NewDecoder(bytes.NewReader(hdr))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("the backup's header: %w", err)
	}
	if h.Format != Version || h.KDF != "PBKDF2-HMAC-SHA256" || h.Cipher != "AES-256-GCM" || h.Chunk != chunkSize {
		return nil, fmt.Errorf("this backup is format %d with %s and %s, which this release does not read",
			h.Format, h.KDF, h.Cipher)
	}
	if h.Iterations < MinIterations || h.Iterations > MaxIterations {
		return nil, fmt.Errorf("the backup's work factor %d is outside %d to %d", h.Iterations, MinIterations, MaxIterations)
	}
	salt, err := hex.DecodeString(h.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("the backup's salt is unreadable")
	}
	k, err := key(passphrase, salt, h.Iterations)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	op := &opener{r: br, aead: aead, ad: append([]byte(Magic), hdr...)}
	tr := tar.NewReader(op)
	got := map[string]File{}
	var manifest *Manifest
	for {
		th, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if manifest != nil {
			return nil, errors.New("the archive goes on after its manifest")
		}
		if th.Name == manifestTar && th.Typeflag == tar.TypeReg {
			if th.Size > 64<<20 {
				return nil, errors.New("the manifest is too large")
			}
			body, err := io.ReadAll(io.LimitReader(tr, th.Size))
			if err != nil {
				return nil, err
			}
			manifest = &Manifest{}
			if err := json.Unmarshal(body, manifest); err != nil {
				return nil, fmt.Errorf("the manifest: %w", err)
			}
			continue
		}
		name := strings.TrimSuffix(th.Name, "/")
		if err := checkName(name); err != nil {
			return nil, err
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		mode := os.FileMode(th.Mode).Perm() &^ 0o022
		switch th.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, mode|0o700); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			if th.Size < 0 || th.Size > MaxFile {
				return nil, fmt.Errorf("%s claims %d bytes", name, th.Size)
			}
			if _, dup := got[name]; dup {
				return nil, fmt.Errorf("%s is in the backup twice", name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return nil, err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode|0o600)
			if err != nil {
				return nil, err
			}
			hash := sha256.New()
			n, err := io.Copy(f, io.TeeReader(io.LimitReader(tr, th.Size), hash))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return nil, err
			}
			got[name] = File{Path: name, Size: n, Mode: uint32(mode), SHA256: hex.EncodeToString(hash.Sum(nil))}
		default:
			return nil, fmt.Errorf("%s is not a file or a directory, and a backup holds nothing else", name)
		}
	}
	// The tar reader may stop before the stream does; the stream is read
	// to its end, which the opener reports only after the authenticated
	// last chunk, so one cut off is never missed.
	if _, err := io.Copy(io.Discard, op); err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, errors.New("the archive has no manifest")
	}
	if manifest.Format != Version {
		return nil, fmt.Errorf("the manifest is format %d", manifest.Format)
	}
	if len(manifest.Files) != len(got) {
		return nil, fmt.Errorf("the manifest lists %d files and the archive held %d", len(manifest.Files), len(got))
	}
	for _, f := range manifest.Files {
		g, ok := got[f.Path]
		if !ok {
			return nil, fmt.Errorf("the manifest lists %s, which the archive did not hold", f.Path)
		}
		if g.Size != f.Size || g.SHA256 != f.SHA256 {
			return nil, fmt.Errorf("%s is not the file the manifest describes", f.Path)
		}
	}
	return manifest, nil
}

// emptyDir makes dir, or accepts it when it exists and is empty: a restore
// never writes over anything.
func emptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return err
	case len(entries) > 0:
		return fmt.Errorf("%s is not empty: a restore goes into a new directory, never over a store", dir)
	}
	return nil
}
