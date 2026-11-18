// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auditstream"
	"github.com/aertun/aertun/internal/httpsig"
	"github.com/aertun/aertun/internal/inbound"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// A signed audit stream, received.
//
// A feed of kind stream is the receiving end of a sender's siem.stream.url:
// another Aertun deployment, or any program that sends the same format.
// The sender pushes; nothing here reaches into it. A batch is taken only
// when it is signed by the stream key the feed pinned, follows the last
// record held exactly, and its leaves rebuild a tree head signed by the
// head keys the feed pinned. Then the records go into the event store as
// stream/audit, and the answer tells the sender how far it has got: 200
// with what is held, or 409 with what is held when a batch does not follow,
// so the sender starts again from there.
//
// The leaves taken are kept beside the feed, one per line, so the chain
// survives a restart: a receiver that forgot them would take a batch that
// skipped records, which is exactly what the stream exists to make
// impossible.

// streamFeedHelp is what `aertun inbound help` says about this kind.
const streamFeedHelp = `
  Another deployment's audit log, as it is written
    aertun siem stream key --json > site-b-keys.json        (on the sender)
    aertun inbound add stream site-b --keys site-b-keys.json
    aertun config set siem.stream.url https://YOUR-ADMIN/feeds/site-b   (on the sender)
    Each batch is taken only when it is signed by the stream key, follows
    the last record held exactly, and rebuilds the signed tree head. The
    records are stored as stream/audit, the actors named by the feed.
    Another program sending the same format signs its tree heads in a
    context of its own; when its keys file does not say which, name it:
    aertun inbound add stream app --keys app-keys.json --head-context app/audit-head/v1
    aertun inbound prove site-b --key release.key    whole and unforked, signed
`

// streamFeedLabel is what the Feeds screen calls the kind.
const streamFeedLabel = "Signed audit stream"

// streamRotateHelp is the answer to rotating one: its keys are the sender's.
const streamRotateHelp = "an audit stream's keys are the sender's: rotate them there, then " +
	"`aertun inbound remove NAME` and add the feed again with the sender's new `aertun siem stream key --json`"

// streamFeedUsage is its line in the usage.
const streamFeedUsage = "add stream NAME --keys FILE [--head-context C] | "

// streamBodyLimit is the largest batch taken: five hundred records of OCSF
// with their envelope and leaves come to about a megabyte and a half.
const streamBodyLimit = 8 << 20

func streamLeavesPath(root, name string) string {
	return filepath.Join(inboundDir(root), name+".leaves")
}

func streamHeadsPath(root, name string) string {
	return filepath.Join(inboundDir(root), name+".heads")
}

func streamForksPath(root, name string) string {
	return filepath.Join(inboundDir(root), name+".forks")
}

// maxStreamForks bounds the conflicting heads kept for one feed: one is
// enough to refute, and whoever holds the sender's keys would otherwise
// choose how large the file grows.
const maxStreamForks = 64

// peerHead is a tree head a sender signed, kept with the batch it came in:
// what `aertun inbound prove` holds the records against, and what the Feeds
// screen shows as the peer's chain head.
type peerHead struct {
	// Received is when the batch was taken, by this deployment's clock.
	Received time.Time `json:"received"`
	// Records is how many records the batch carried. Fewer than a full
	// batch means it reached the end of the sender's log as it then was.
	Records int              `json:"records"`
	Head    audit.SignedHead `json:"head"`
}

// peerFork is a tree head a sender signed that is not the log held here.
type peerFork struct {
	Received time.Time `json:"received"`
	// Resent is whether it covered records already held (see
	// auditstream.ErrFork).
	Resent bool `json:"resent,omitempty"`
	// Held is the root this deployment computed over the same number of
	// records.
	Held string           `json:"held"`
	Head audit.SignedHead `json:"head"`
}

// readJSONLines reads a file of one JSON value a line into out, leaving out
// a last line that was not finished, as readStreamLeaves does.
func readJSONLines[T any](path string) ([]T, error) {
	b, err := readBounded(path, 64<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []T
	for _, l := range bytes.Split(b[:bytes.LastIndexByte(b, '\n')+1], []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(l, &v); err != nil {
			return nil, fmt.Errorf("%s holds a line that does not read: %w", filepath.Base(path), err)
		}
		out = append(out, v)
	}
	return out, nil
}

// appendJSONLine adds one value to a file of JSON lines, synced.
func appendJSONLine(path string, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := fh.Write(append(line, '\n'))
	serr := fh.Sync()
	cerr := fh.Close()
	return errors.Join(werr, serr, cerr)
}

// peerChainHead is the last tree head a stream feed's sender signed and
// this deployment took, and how many heads it signed that were not the log
// held: what the Feeds screen and `inbound status` say of a peer. Read from
// the end of the heads file, so a page view never rebuilds the log; the
// proof (`aertun inbound prove`) is what checks every head against it.
func peerChainHead(root, name string) (*peerHead, int, error) {
	b, err := readBounded(streamHeadsPath(root, name), 64<<20)
	var last *peerHead
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, 0, err
	default:
		whole := b[:bytes.LastIndexByte(b, '\n')+1]
		lines := bytes.Split(bytes.TrimRight(whole, "\n"), []byte("\n"))
		if n := len(lines); n > 0 && len(bytes.TrimSpace(lines[n-1])) > 0 {
			var h peerHead
			if err := json.Unmarshal(lines[n-1], &h); err != nil {
				return nil, 0, fmt.Errorf("the last head kept for %s does not read: %w", name, err)
			}
			last = &h
		}
	}
	forks, err := readJSONLines[peerFork](streamForksPath(root, name))
	if err != nil {
		return nil, 0, err
	}
	return last, len(forks), nil
}

// keepFork keeps a conflicting head once, and reports whether it was new.
func keepFork(root, name string, fork peerFork) (bool, error) {
	path := streamForksPath(root, name)
	kept, err := readJSONLines[peerFork](path)
	if err != nil {
		return false, err
	}
	for _, k := range kept {
		if k.Head.Size == fork.Head.Size && k.Head.Root == fork.Head.Root {
			return false, nil
		}
	}
	if len(kept) >= maxStreamForks {
		return false, nil
	}
	return true, appendJSONLine(path, fork)
}

// heldStream is one feed's receiver, and the lock that keeps its batches in
// order.
type heldStream struct {
	mu   sync.Mutex
	keys string
	rc   *auditstream.Receiver
}

// streamKeysDigest names a set of keys, so a receiver built for old keys is
// not used once the feed has new ones.
func streamKeysDigest(f inbound.Feed) string {
	// The feed's creation too: one removed and added again under its name
	// starts from nothing, and must not inherit the chain held for the old.
	b, _ := json.Marshal(struct {
		K *inbound.StreamKeys
		C string
	}{f.Stream, f.Created.String()})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// stream returns the feed's receiver, building it and restoring the leaves
// already taken when there is none, or when its keys changed.
func (s *inboundServer) stream(f inbound.Feed) (*heldStream, error) {
	if f.Stream == nil {
		return nil, errors.New("the feed holds no stream keys")
	}
	s.mu.Lock()
	if s.streams == nil {
		s.streams = map[string]*heldStream{}
	}
	h := s.streams[f.Name]
	if h == nil {
		h = &heldStream{}
		s.streams[f.Name] = h
	}
	s.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	digest := streamKeysDigest(f)
	if h.rc != nil && h.keys == digest {
		return h, nil
	}
	rc, err := streamReceiver(s.root, f)
	if err != nil {
		return nil, err
	}
	h.rc, h.keys = rc, digest
	return h, nil
}

func streamReceiver(root string, f inbound.Feed) (*auditstream.Receiver, error) {
	pub, headEd, headML, err := f.Stream.Decode()
	if err != nil {
		return nil, err
	}
	context := f.Stream.HeadContext
	if context == "" {
		context = audit.HeadContext
	}
	heads, err := audit.NewHeadVerifierIn(context, headEd, headML)
	if err != nil {
		return nil, err
	}
	rc := &auditstream.Receiver{
		Keys:  []httpsig.PublicKey{{ID: f.Stream.KeyID, Alg: httpsig.Ed25519, Ed: pub}},
		Heads: heads,
		// The address the sender was given, which is the one it signs.
		Origin: strings.TrimSuffix(mustConfig(root).Raw("admin.base_url"), "/"),
	}
	leaves, err := readStreamLeaves(streamLeavesPath(root, f.Name))
	if err != nil {
		return nil, err
	}
	if err := rc.Restore(leaves); err != nil {
		return nil, err
	}
	return rc, nil
}

// readStreamLeaves reads the leaves held, one a line.
//
// A last line with no newline is a write that did not finish: the disk
// filled, or the process stopped, part way through a batch. It is cut off,
// in the file as well, rather than read as a leaf. Read, it would fail every
// restore and the feed would refuse everything from then on; left in the
// file, the next batch's first leaf would be appended to it. The leaves
// before it were written whole and are what was held, so the sender, told
// so, sends again from there.
func readStreamLeaves(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if cut := bytes.LastIndexByte(b, '\n') + 1; cut != len(b) {
		if err := os.Truncate(path, int64(cut)); err != nil {
			return nil, err
		}
		b = b[:cut]
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// appendStreamLeaves keeps what a batch added, synced before the sender is
// told it was taken.
func appendStreamLeaves(path string, leaves []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := fh.WriteString(strings.Join(leaves, "\n") + "\n")
	serr := fh.Sync()
	cerr := fh.Close()
	return errors.Join(werr, serr, cerr)
}

// storeStream writes a batch's events to the store before its sender is told
// they were taken. Other feeds queue what arrives while the store is busy;
// a stream may not, because the leaves kept next say these records are held,
// and a queue lost with the process would make that untrue with nothing to
// show it. A failure part way leaves some stored, and the sender, told
// nothing was taken, sends them again: twice, never not at all.
func (s *inboundServer) storeStream(f inbound.Feed, events []telemetry.Event, at time.Time) error {
	stored := 0
	err := withSpool(s.root, func(sp *spool.Spool) error {
		for _, e := range events {
			if _, err := sp.Append(e); err != nil {
				return err
			}
			stored++
		}
		return nil
	})
	s.mu.Lock()
	st := s.statusOf(f.Name)
	st.Deliveries++
	st.LastAt = at
	st.Records += len(events)
	st.Stored += stored
	if err != nil {
		st.Error = err.Error()
	} else {
		st.Error = ""
	}
	if stored > 0 {
		s.fresh = true
	}
	s.dirty = true
	s.mu.Unlock()
	s.poke()
	return err
}

func streamAnswer(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// auditStream takes one batch.
func (s *inboundServer) auditStream(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	h, err := s.stream(f)
	if err != nil {
		s.refused(f.Name, err.Error())
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "this feed cannot check what it is sent"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rc == nil {
		// A batch before this one was taken and then could not be kept, so
		// what is held is what is on disk.
		if h.rc, err = streamReceiver(s.root, f); err != nil {
			s.refused(f.Name, err.Error())
			streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "this feed cannot check what it is sent"})
			return
		}
	}
	now := s.now().UTC()
	b, err := h.rc.Accept(r, body, now)
	var gap *auditstream.ErrGap
	var fork *auditstream.ErrFork
	switch {
	case errors.As(err, &gap):
		streamAnswer(w, http.StatusConflict, map[string]any{"holds": gap.Holds, "error": gap.Error()})
		return
	case errors.As(err, &fork):
		// The sender's own signatures on a history that is not the one
		// held. Kept as evidence, once, and written to this deployment's
		// own log, where a rule reads it; nothing is taken from the batch.
		fresh, kerr := keepFork(s.root, f.Name, peerFork{Received: now, Resent: fork.Resent,
			Held: fork.Held, Head: fork.Head})
		// The sender is who signed it, proved by its keys: the entry is in
		// its name, as the feed's, like everything else a feed delivers.
		if kerr == nil && fresh {
			if err := recordE(s.root, audit.Record{Action: "inbound.fork", Resource: "/feeds/" + f.Name,
				Outcome: audit.Failure, Principal: "feed:" + f.Name, Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"feed": f.Name, "records": strconv.Itoa(fork.Head.Size),
					"signed_root": fork.Head.Root, "held_root": fork.Held,
					"resent": strconv.FormatBool(fork.Resent)}}); err != nil {
				s.mu.Lock()
				s.statusOf(f.Name).Error = err.Error()
				s.dirty = true
				s.mu.Unlock()
			}
		}
		s.refused(f.Name, fork.Error())
		streamAnswer(w, http.StatusConflict, map[string]any{"holds": h.rc.Holds(),
			"error": "the tree head is not the log held here"})
		return
	case err != nil:
		s.refused(f.Name, err.Error())
		streamAnswer(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// From here the receiver holds the batch in memory. Anything that stops
	// it being kept drops that, so the next batch is checked against what
	// is on disk and the sender, told nothing was taken, sends it again.
	events, err := inbound.StreamEvents(b.OCSF, f.Name, now)
	if err != nil {
		h.rc = nil
		s.refused(f.Name, err.Error())
		streamAnswer(w, http.StatusBadRequest, map[string]any{"error": "the records are not readable"})
		return
	}
	if err := s.storeStream(f, events, now); err != nil {
		h.rc = nil
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "what was sent could not be stored"})
		return
	}
	if err := appendStreamLeaves(streamLeavesPath(s.root, f.Name), b.Leaves); err != nil {
		h.rc = nil
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "what was sent could not be kept"})
		return
	}
	// The head it signed, kept after the leaves it covers: a head with no
	// leaves under it would be one nothing here could be held against.
	if err := appendJSONLine(streamHeadsPath(s.root, f.Name), peerHead{Received: now,
		Records: len(b.Leaves), Head: b.Head}); err != nil {
		h.rc = nil
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "what was sent could not be kept"})
		return
	}
	streamAnswer(w, http.StatusOK, map[string]any{"holds": b.To})
}

// streamFeed fills in a new feed of this kind from the keys file.
func streamFeed(root string, f *inbound.Feed, opts map[string]string) ([]string, error) {
	if opts["keys"] == "" {
		return nil, errors.New("this feed checks the sender's batches against its published keys: " +
			"--keys FILE, where FILE is what `aertun siem stream key --json` writes on the sender")
	}
	b, err := os.ReadFile(opts["keys"])
	if err != nil {
		return nil, err
	}
	k, err := inbound.ParseStreamKeys(b)
	if err != nil {
		return nil, err
	}
	// The context the sender signs its tree heads in, when its keys file
	// does not say: another program's own, which a head signed in it
	// verifies in and no other. Named by whoever adds the feed, never
	// guessed from what arrives — a receiver that tried contexts until one
	// worked would be one that accepted a signature made for another use.
	if c := opts["head-context"]; c != "" {
		if k.HeadContext != "" && k.HeadContext != c {
			return nil, fmt.Errorf("the keys say the sender signs its tree heads in %q, and "+
				"--head-context names %q", k.HeadContext, c)
		}
		k.HeadContext = c
		if _, _, _, err := k.Decode(); err != nil {
			return nil, err
		}
	}
	// A head key's id is a fingerprint over its public keys and the context
	// it signs in, so the id the sender published says whether the context
	// here is the sender's: checked now, rather than found in every batch
	// refused from now on.
	if k.HeadKeyID != "" {
		_, headEd, headML, err := k.Decode()
		if err != nil {
			return nil, err
		}
		context := k.HeadContext
		if context == "" {
			context = audit.HeadContext
		}
		v, err := audit.NewHeadVerifierIn(context, headEd, headML)
		if err != nil {
			return nil, err
		}
		if v.KeyID() != k.HeadKeyID {
			return nil, fmt.Errorf("the sender names its head key %s, and in the context %s these "+
				"public keys are %s: it signs its tree heads in another context. Name it with "+
				"--head-context (the sender's documentation says which; a program's own is often "+
				"NAME/audit-head/v1)", k.HeadKeyID, context, v.KeyID())
		}
	}
	f.Kind, f.Stream = inbound.AuditStream, k
	return []string{
		"batches are checked against " + k.KeyID + ", tree heads against " + k.HeadKeyID,
		"on the sender, set siem.stream.url to " + feedURL(root, f.Name) +
			" (on another Aertun: aertun config set siem.stream.url " + feedURL(root, f.Name) + ")",
	}, nil
}
