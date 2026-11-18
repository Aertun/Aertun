// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package seal commits alerts to the audit log by their digests, so that
// whoever raised an alert can later show it existed before a time somebody
// else fixed (internal/proof, sealed.go).
//
// # What is committed
//
// An alert's identity is the SHA-256 of its JSON in the canonical form of
// RFC 8785, so the same alert written with its members in another order, or
// with other whitespace, is the same alert. A batch of digests is committed
// by one audit entry carrying the RFC 6962 Merkle root over them and how
// many there are; the digests are kept beside the store, by that root, so a
// digest's path to the root can be shown later. The alerts themselves are
// not kept: what a monitor saw may be somebody's personal data, and the
// commitment does not need it.
//
// # Why one entry per batch
//
// An entry per alert would put an MDR's day of alerts into the audit log
// line by line, and the log is the record of who did what here. One entry
// carries a root and a count — two short values — whatever the batch holds,
// and the Merkle path makes each alert in it as provable as an entry of its
// own.
//
// # What fixes the time
//
// The entry's time is the log's own clock. What fixes it for somebody else
// is a head of the log sent to OpenTimestamps (`aertun auditlog anchor`):
// Anchors reads what internal/anchor says of each head that was sent, and
// Cover finds the earliest that includes a given entry.
package seal

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
	"regexp"
	"strconv"

	"github.com/aertun/aertun/internal/anchor"
	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/translog"
)

const (
	// MaxAlertBytes bounds one alert. A monitor's alert with its evidence
	// attached is a few kilobytes; a quarter of a megabyte on one line is
	// not an alert.
	MaxAlertBytes = 256 << 10
	// MaxBatch bounds the distinct alerts one batch seals: the batch a
	// proof can name.
	MaxBatch = proof.MaxSealedBatch
	// MaxInput bounds everything one batch is read from.
	MaxInput = 64 << 20
	// maxBatchFile bounds a kept batch when it is read back: every digest,
	// quoted and separated, with room for the rest of the document.
	maxBatchFile = MaxBatch*70 + 4096
)

// The entries that seal a batch, and the detail they carry. A detection run
// seals the findings it raised in its own entry (cmd/aertun, detectrun.go),
// so its action is one of the two.
const (
	ActionSealed = "alert.sealed"
	ActionDetect = "detect.run"
	// DetailRoot and DetailCount are the batch's root and size in a sealing
	// entry: short values, under keys the audit log accepts.
	DetailRoot  = "sealed_root"
	DetailCount = "sealed"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Digest is an alert's identity: the SHA-256, in hex, of its RFC 8785
// canonical form. An alert is one JSON object.
func Digest(alert []byte) (string, error) {
	canon, err := jcs.Canonicalize(alert)
	if err != nil {
		return "", err
	}
	if len(canon) == 0 || canon[0] != '{' {
		return "", fmt.Errorf("an alert is one JSON object")
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// Read reads alerts, one JSON object per line, and returns their digests,
// each once, in the order first read, with how many lines held an alert.
// Blank lines are skipped; anything else that is not one object refuses the
// whole batch, by line number, because a batch with a line quietly left out
// is a batch whose owner believes something was sealed that was not.
func Read(r io.Reader) ([]string, int, error) {
	lr := &io.LimitedReader{R: r, N: MaxInput + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 0, 64<<10), MaxAlertBytes)
	seen := map[string]bool{}
	var out []string
	read, line := 0, 0
	for sc.Scan() {
		line++
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		d, err := Digest(text)
		if err != nil {
			return nil, 0, fmt.Errorf("line %d is not one JSON alert: %w", line, err)
		}
		read++
		if seen[d] {
			continue
		}
		if len(out) == MaxBatch {
			return nil, 0, fmt.Errorf("more than %d distinct alerts: seal them in batches of at "+
				"most that many", MaxBatch)
		}
		seen[d] = true
		out = append(out, d)
	}
	if err := sc.Err(); errors.Is(err, bufio.ErrTooLong) {
		return nil, 0, fmt.Errorf("line %d is longer than an alert may be (%d bytes)", line+1, MaxAlertBytes)
	} else if err != nil {
		return nil, 0, err
	}
	if lr.N <= 0 {
		return nil, 0, fmt.Errorf("the alerts are more than %d bytes: seal them in smaller batches", MaxInput)
	}
	if len(out) == 0 {
		return nil, 0, fmt.Errorf("no alerts were read: a batch is one JSON object per line")
	}
	return out, read, nil
}

// Batch is digests sealed together, kept so a digest's place under the root
// its entry committed can be shown later.
type Batch struct {
	// Root is the RFC 6962 Merkle root over the digests, in order. Written
	// for whoever reads the file; it is computed again from the digests
	// whenever it matters, never read from here.
	Root    string   `json:"root"`
	Digests []string `json:"digests"`
}

// NewBatch is a batch over distinct digests, with its root.
func NewBatch(digests []string) (*Batch, error) {
	if len(digests) == 0 || len(digests) > MaxBatch {
		return nil, fmt.Errorf("a batch seals between 1 and %d alerts", MaxBatch)
	}
	seen := map[string]bool{}
	for _, d := range digests {
		if !hex64.MatchString(d) || seen[d] {
			return nil, fmt.Errorf("a batch holds each alert's sha256 once")
		}
		seen[d] = true
	}
	t, err := tree(digests)
	if err != nil {
		return nil, err
	}
	return &Batch{Root: t.Head().Root, Digests: append([]string(nil), digests...)}, nil
}

// tree is the Merkle tree over a batch's digests, each digest's 32 bytes a
// leaf.
func tree(digests []string) (*translog.Log, error) {
	t := translog.New()
	for _, d := range digests {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("%q is not a sha256", d)
		}
		t.Append(raw)
	}
	return t, nil
}

// Detail is what a sealing entry carries to commit a batch.
func Detail(b *Batch) map[string]string {
	return map[string]string{DetailRoot: b.Root, DetailCount: strconv.Itoa(len(b.Digests))}
}

// Dir is where a store keeps its batches.
func Dir(root string) string { return filepath.Join(root, "sealed") }

func batchPath(dir, root string) (string, error) {
	// The root names the file, so it is held to its shape before it is part
	// of a path: a root from an audit entry is somebody's input as far as
	// the filesystem is concerned.
	if !hex64.MatchString(root) {
		return "", fmt.Errorf("%q is not a batch's root", root)
	}
	return filepath.Join(dir, root+".json"), nil
}

// Save keeps a batch by its root, and says whether a batch was already kept
// under that root: the same digests in the same order are the same batch,
// and a caller undoing a seal must not remove one somebody sealed before.
func Save(dir string, b *Batch) (existed bool, err error) {
	path, err := batchPath(dir, b.Root)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	_, serr := os.Stat(path)
	body, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return serr == nil, atomicfile.Write(path, append(body, '\n'), 0o600)
}

// Remove takes back a batch whose entry was never written.
func Remove(dir, root string) error {
	path, err := batchPath(dir, root)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// Load reads the digests kept for a root, bounded and in their shape. It
// does not check them against the root: whoever asks compares them with
// what the entry committed, so an altered batch is shown failing rather
// than refused unseen.
func Load(dir, root string) (*Batch, error) {
	path, err := batchPath(dir, root)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxBatchFile+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBatchFile {
		return nil, fmt.Errorf("%s is larger than a batch can be", path)
	}
	var b Batch
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(b.Digests) == 0 || len(b.Digests) > MaxBatch {
		return nil, fmt.Errorf("%s holds no batch", path)
	}
	for _, d := range b.Digests {
		if !hex64.MatchString(d) {
			return nil, fmt.Errorf("%s holds something that is not a sha256", path)
		}
	}
	return &b, nil
}

// Commit is an audit entry that sealed a batch.
type Commit struct {
	// Index is the entry's place in the log, counting from zero.
	Index int
	Seq   int64
	At    string
	Root  string
	Count int
}

// Commits are the entries in a log that sealed a batch, in log order: an
// alert.sealed entry, or a detection run that sealed what it raised, that
// succeeded and carries a root and a count in their shapes. Anything else
// carrying the same keys is not a seal.
func Commits(events []audit.Event) []Commit {
	var out []Commit
	for i, e := range events {
		if (e.Action != ActionSealed && e.Action != ActionDetect) || e.Outcome != audit.Success {
			continue
		}
		root, count := e.Detail[DetailRoot], e.Detail[DetailCount]
		n, err := strconv.Atoi(count)
		if !hex64.MatchString(root) || err != nil || strconv.Itoa(n) != count || n < 1 || n > MaxBatch {
			continue
		}
		out = append(out, Commit{Index: i, Seq: e.Seq, At: e.At, Root: root, Count: n})
	}
	return out
}

// Found is where a digest was sealed.
type Found struct {
	Commit Commit
	// Index is the digest's place in the batch kept for the commit, and Path
	// its audit path there.
	Index int
	Path  []string
	// Reaches says the kept batch is the one the entry committed: its
	// digests, as many as the entry says, hash to the entry's root.
	Reaches bool
}

// Find looks for a digest in every batch a log sealed, earliest entry
// first. It returns the earliest batch whose kept digests are the ones its
// entry committed; failing that, the earliest that holds the digest at all,
// whose path a proof then shows not reaching the root; and how many of the
// commits have no readable batch here.
func Find(dir string, commits []Commit, digest string) (*Found, int) {
	var first *Found
	unkept := 0
	type kept struct {
		b    *Batch
		t    *translog.Log
		root string
	}
	cache := map[string]*kept{}
	for _, c := range commits {
		k, ok := cache[c.Root]
		if !ok {
			k = &kept{}
			if b, err := Load(dir, c.Root); err == nil {
				if t, err := tree(b.Digests); err == nil {
					k = &kept{b: b, t: t, root: t.Head().Root}
				}
			}
			cache[c.Root] = k
		}
		if k.b == nil {
			unkept++
			continue
		}
		index := -1
		for i, d := range k.b.Digests {
			if d == digest {
				index = i
				break
			}
		}
		// A digest kept past the count the entry committed is not in the
		// batch that entry committed, whatever the file beside it says.
		if index < 0 || index >= c.Count {
			continue
		}
		path, err := k.t.InclusionProof(index, k.t.Size())
		if err != nil {
			continue
		}
		f := &Found{Commit: c, Index: index, Path: path,
			Reaches: k.root == c.Root && len(k.b.Digests) == c.Count}
		if f.Reaches {
			return f, unkept
		}
		if first == nil {
			first = f
		}
	}
	return first, unkept
}

// Break is the first entry, counting from one, at which a log does not
// verify: one out of sequence — a log begins at entry 1 and counts up by
// one, so an entry's sequence is its place — or one audit.Verify finds
// altered, inserted after or removed from; zero when the whole log
// verifies.
func Break(events []audit.Event) int {
	for i, e := range events {
		if e.Seq != int64(i+1) {
			return i + 1
		}
	}
	if ok, problems := audit.Verify(events); !ok {
		return int(problems[0].Seq)
	}
	return 0
}

// LogTree is the audit log's Merkle tree, built once, from which every head
// and path here is read. Its leaves are audit.LeafHash's, so its roots are
// the ones `aertun auditlog head` and `auditlog anchor` publish.
func LogTree(events []audit.Event) (*translog.Log, error) {
	t := translog.New()
	for _, e := range events {
		leaf, err := audit.LeafHash(e)
		if err != nil {
			return nil, err
		}
		t.Append(leaf)
	}
	return t, nil
}

// Placed is a head of the log sent to OpenTimestamps, placed in the log as
// it stands, with what its proof attests.
type Placed struct {
	Size int
	Root string
	// State is Anchored only for a head whose Bitcoin block was checked
	// (anchor.Confirm); a head whose timestamp names a block nobody has
	// checked, or whose header does not hold it, is Pending with Unconfirmed
	// set, and is no anchor.
	State       anchor.State
	Unconfirmed bool
	// Height is the block the timestamp names; Block is that block as it
	// was checked, when it was.
	Height uint64
	Block  anchor.Block
	// Body is the OpenTimestamps proof, for its digest as a material.
	Body []byte
}

// Anchor is the word a proof uses for the head's state.
func (p Placed) Anchor() string {
	switch {
	case p.State == anchor.Anchored:
		return proof.AnchorBitcoin
	case p.Unconfirmed:
		return proof.AnchorUnconfirmed
	}
	return proof.AnchorPending
}

// Anchors places every head sent to OpenTimestamps in the log, and returns
// the smallest head the log no longer matches, or zero.
//
// What a proof attests is internal/anchor's to say, and it is asked again
// here: a proof's state is derived from its operations walked from its
// digest (anchor.Classify), never read from the state it was stored with,
// and a Bitcoin attestation counts only when the header kept with it holds
// the value the walk reaches and shows a real block's work
// (anchor.Confirm). An attestation is a height and nothing more; one
// written into the file by hand reaches no block.
// A digest is placed only through a head the log recorded at a size
// (log-heads.json, written when the head was sent), and only when the log's
// first entries of that size hash to it now. A digest no recorded head names
// cannot be placed and is left out; one whose head the log no longer matches
// is the log rewritten after the head left the machine, which is what
// anchoring exists to show.
func Anchors(t *translog.Log, heads []audit.Head, proofs []anchor.Proof) ([]Placed, int) {
	sizes := map[string][]int{}
	for _, h := range heads {
		if hex64.MatchString(h.Root) && h.Size > 0 {
			sizes[h.Root] = append(sizes[h.Root], h.Size)
		}
	}
	roots := map[int]string{}
	rootAt := func(size int) string {
		if r, ok := roots[size]; ok {
			return r
		}
		h, err := t.HeadAt(size)
		if err != nil {
			return ""
		}
		roots[size] = h.Root
		return h.Root
	}
	var placed []Placed
	rewritten := 0
	for _, p := range proofs {
		if !hex64.MatchString(p.Digest) {
			continue
		}
		digest, _ := hex.DecodeString(p.Digest)
		state, height, _, err := anchor.Classify(digest, p.Body)
		if err != nil || (state != anchor.Anchored && state != anchor.Pending) ||
			(state == anchor.Anchored && (height == 0 || height > proof.MaxBitcoinHeight)) {
			continue
		}
		for _, size := range sizes[p.Digest] {
			if size > t.Size() || rootAt(size) != p.Digest {
				if rewritten == 0 || size < rewritten {
					rewritten = size
				}
				continue
			}
			pl := Placed{Size: size, Root: p.Digest, State: state, Height: height, Body: p.Body}
			if state == anchor.Anchored {
				if blk, cerr := anchor.Confirm(p); cerr == nil {
					pl.Block = blk
				} else {
					pl.State, pl.Unconfirmed = anchor.Pending, true
				}
			}
			placed = append(placed, pl)
		}
	}
	return placed, rewritten
}

// Cover is the earliest head that includes the entry at index: one whose
// block was checked before any that is not, the lowest block among those,
// and the smallest head among equals — the tightest bound there is.
func Cover(placed []Placed, index int) (Placed, bool) {
	better := func(a, b Placed) bool {
		if (a.State == anchor.Anchored) != (b.State == anchor.Anchored) {
			return a.State == anchor.Anchored
		}
		if a.State == anchor.Anchored && a.Height != b.Height {
			return a.Height < b.Height
		}
		return a.Size < b.Size
	}
	var best Placed
	found := false
	for _, p := range placed {
		if p.Size > index && (!found || better(p, best)) {
			best, found = p, true
		}
	}
	return best, found
}
