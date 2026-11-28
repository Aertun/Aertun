// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package aep

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/aertun/aertun/internal/cbor"
	"github.com/aertun/aertun/internal/cose"
	"github.com/aertun/aertun/internal/scitt"
)

// Verdicts of a reconciliation.
const (
	Agree        = "agree"
	Disagree     = "disagree"
	Inconclusive = "inconclusive"
)

// MaxTolerance bounds how far apart two parties' times for one action may
// be. Past a minute, two calls are as likely to be two actions as one.
const MaxTolerance = time.Minute

// MaxWindow bounds one reconciliation's window.
const MaxWindow = 31 * 24 * time.Hour

// Expect is a party every action in the window should have been seen by.
type Expect struct {
	Issuer  string
	Vantage string
}

// Input is one verified receipt: its issuer, the statement as registered,
// and what it says.
type Input struct {
	Issuer  string
	Entry   []byte
	Receipt Receipt
}

// Window is what a reconciliation covers.
type Window struct {
	From, To  time.Time
	Tolerance time.Duration
	Expect    []Expect
}

// Gap is an action some expected party did not report.
type Gap struct {
	Action  [32]byte
	Tool    string
	At      time.Time
	SeenBy  []string
	Missing []string
}

// SeqGap is what is wrong with one party's sequence numbers in the window:
// the ranges missing between the lowest and highest it used, and the
// numbers it used for more than one receipt.
type SeqGap struct {
	Issuer   string
	Missing  [][2]uint64
	Repeated []uint64
}

// ActorSplit is an action the parties name different actors for.
type ActorSplit struct {
	Action [32]byte
	At     time.Time
	// Actors maps each party that named one to the actor it named.
	Actors map[string]string
}

// Result is a reconciliation.
type Result struct {
	Window
	// Inputs is SHA-256 over the sorted SHA-256 digests of the receipts
	// considered, so a holder of the receipts can see these were the ones.
	Inputs   [32]byte
	Receipts int
	Actions  int
	Complete int
	Gaps     []Gap
	// GapsTotal and the other totals count past MaxListed.
	GapsTotal   int
	SeqGaps     []SeqGap
	Actors      []ActorSplit
	ActorsTotal int
	Verdict     string
}

func (w Window) check() error {
	if w.From.IsZero() || !w.To.After(w.From) || w.To.Sub(w.From) > MaxWindow {
		return fmt.Errorf("a window has a start before its end, at most %s apart", MaxWindow)
	}
	if w.Tolerance < 0 || w.Tolerance > MaxTolerance {
		return fmt.Errorf("the tolerance is between 0 and %s", MaxTolerance)
	}
	if len(w.Expect) < 2 {
		return errors.New("a reconciliation compares at least two parties")
	}
	seen := map[string]bool{}
	for _, e := range w.Expect {
		if err := scitt.CheckClaim("issuer", e.Issuer); err != nil {
			return err
		}
		if !slices.Contains(Vantages, e.Vantage) {
			return fmt.Errorf("%s: the vantage is one of %v", e.Issuer, Vantages)
		}
		if seen[e.Issuer] {
			return fmt.Errorf("%s is expected twice", e.Issuer)
		}
		seen[e.Issuer] = true
	}
	return nil
}

type cluster struct {
	digest [32]byte
	tool   string
	first  time.Time
	by     map[string]Receipt
}

// Reconcile groups the receipts of a window into actions and names what
// does not agree. Receipts from parties not expected are refused, since a
// reconciliation that quietly dropped them would be about other receipts
// than the ones it was given.
func Reconcile(inputs []Input, w Window) (Result, error) {
	if err := w.check(); err != nil {
		return Result{}, err
	}
	w.Expect = slices.Clone(w.Expect)
	sort.Slice(w.Expect, func(i, j int) bool { return w.Expect[i].Issuer < w.Expect[j].Issuer })
	vantage := map[string]string{}
	for _, e := range w.Expect {
		vantage[e.Issuer] = e.Vantage
	}
	res := Result{Window: w}

	// The receipts considered: those within the window widened by the
	// tolerance at both ends, so an action at an edge can be matched,
	// each counted once.
	type occ struct {
		in  Input
		sum [32]byte
	}
	var occs []occ
	seen := map[[32]byte]bool{}
	for _, in := range inputs {
		want, ok := vantage[in.Issuer]
		if !ok {
			return Result{}, fmt.Errorf("a receipt from %s, which is not one of the parties expected", in.Issuer)
		}
		if in.Receipt.Vantage != want {
			return Result{}, fmt.Errorf("%s is expected as the %s and reports as the %s", in.Issuer, want, in.Receipt.Vantage)
		}
		at := in.Receipt.At
		if at.Before(w.From.Add(-w.Tolerance)) || !at.Before(w.To.Add(w.Tolerance)) {
			continue
		}
		sum := sha256.Sum256(in.Entry)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		occs = append(occs, occ{in, sum})
	}
	sort.Slice(occs, func(i, j int) bool {
		a, b := occs[i], occs[j]
		if !a.in.Receipt.At.Equal(b.in.Receipt.At) {
			return a.in.Receipt.At.Before(b.in.Receipt.At)
		}
		if a.in.Issuer != b.in.Issuer {
			return a.in.Issuer < b.in.Issuer
		}
		return bytes.Compare(a.sum[:], b.sum[:]) < 0
	})
	sums := make([][32]byte, len(occs))
	for i, o := range occs {
		sums[i] = o.sum
	}
	slices.SortFunc(sums, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	h := sha256.New()
	for _, s := range sums {
		h.Write(s[:])
	}
	copy(res.Inputs[:], h.Sum(nil))
	res.Receipts = len(occs)

	// Each receipt joins the earliest open action with its digest that it
	// has not already reported and that began within the tolerance;
	// otherwise it begins one.
	var clusters []*cluster
	open := map[[32]byte][]*cluster{}
	for _, o := range occs {
		r := o.in.Receipt
		// Clusters begin in time order and receipts arrive in it, so those
		// begun more than the tolerance ago can take nothing more: dropped
		// from the front, which keeps a flood of one action linear.
		live := open[r.Digest]
		for len(live) > 0 && r.At.Sub(live[0].first) > w.Tolerance {
			live = live[1:]
		}
		open[r.Digest] = live
		var into *cluster
		for _, c := range live {
			if _, has := c.by[o.in.Issuer]; !has && r.At.Sub(c.first) <= w.Tolerance {
				into = c
				break
			}
		}
		if into == nil {
			into = &cluster{digest: r.Digest, tool: r.Tool, first: r.At, by: map[string]Receipt{}}
			clusters = append(clusters, into)
			open[r.Digest] = append(open[r.Digest], into)
		}
		into.by[o.in.Issuer] = r
	}

	for _, c := range clusters {
		// Counted in the window its first sighting falls in, so adjacent
		// windows with the same tolerance count each action once.
		if c.first.Before(w.From) || !c.first.Before(w.To) {
			continue
		}
		res.Actions++
		var by, missing []string
		actors := map[string]string{}
		for _, e := range w.Expect {
			r, ok := c.by[e.Issuer]
			if !ok {
				missing = append(missing, e.Issuer)
				continue
			}
			by = append(by, e.Issuer)
			if r.Actor != "" {
				actors[e.Issuer] = r.Actor
			}
		}
		if len(missing) == 0 {
			res.Complete++
		} else {
			res.GapsTotal++
			if len(res.Gaps) < MaxListed {
				res.Gaps = append(res.Gaps, Gap{Action: c.digest, Tool: c.tool, At: c.first, SeenBy: by, Missing: missing})
			}
		}
		distinct := map[string]bool{}
		for _, a := range actors {
			distinct[a] = true
		}
		if len(distinct) > 1 {
			res.ActorsTotal++
			if len(res.Actors) < MaxListed {
				res.Actors = append(res.Actors, ActorSplit{Action: c.digest, At: c.first, Actors: actors})
			}
		}
	}
	considered := make([]Input, len(occs))
	for i, o := range occs {
		considered[i] = o.in
	}
	res.SeqGaps = seqGaps(considered, w)

	switch {
	case res.Receipts == 0:
		res.Verdict = Inconclusive
	case res.GapsTotal > 0 || res.ActorsTotal > 0 || len(res.SeqGaps) > 0:
		res.Verdict = Disagree
	default:
		res.Verdict = Agree
	}
	return res, nil
}

// seqGaps checks each party's sequence numbers within the window: a
// number missing between its lowest and highest is a receipt withheld or
// lost, and a number used twice is two receipts claiming one place.
func seqGaps(in []Input, w Window) []SeqGap {
	per := map[string][]uint64{}
	for _, i := range in {
		r := i.Receipt
		if r.HasSeq && !r.At.Before(w.From) && r.At.Before(w.To) {
			per[i.Issuer] = append(per[i.Issuer], r.Seq)
		}
	}
	var out []SeqGap
	for _, e := range w.Expect {
		seqs := per[e.Issuer]
		if len(seqs) == 0 {
			continue
		}
		slices.Sort(seqs)
		g := SeqGap{Issuer: e.Issuer}
		for i := 1; i < len(seqs); i++ {
			switch {
			case seqs[i] == seqs[i-1]:
				if len(g.Repeated) < MaxListed && (len(g.Repeated) == 0 || g.Repeated[len(g.Repeated)-1] != seqs[i]) {
					g.Repeated = append(g.Repeated, seqs[i])
				}
			case seqs[i] > seqs[i-1]+1:
				if len(g.Missing) < MaxListed {
					g.Missing = append(g.Missing, [2]uint64{seqs[i-1] + 1, seqs[i] - 1})
				}
			}
		}
		if len(g.Missing) > 0 || len(g.Repeated) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// -- the reconciliation receipt -----------------------------------------------

func texts(ss []string) cbor.Array {
	out := make(cbor.Array, len(ss))
	for i, s := range ss {
		out[i] = cbor.Text(s)
	}
	return out
}

func (r Result) payload() cbor.Map {
	expect := cbor.Array{}
	for _, e := range r.Expect {
		expect = append(expect, cbor.Map{{Key: cbor.Text("issuer"), Value: cbor.Text(e.Issuer)},
			{Key: cbor.Text("vantage"), Value: cbor.Text(e.Vantage)}})
	}
	gaps := cbor.Array{}
	for _, g := range r.Gaps {
		gaps = append(gaps, cbor.Map{{Key: cbor.Text("action"), Value: cbor.Bytes(g.Action[:])},
			{Key: cbor.Text("tool"), Value: cbor.Text(g.Tool)}, {Key: cbor.Text("at"), Value: cbor.Text(instant(g.At))},
			{Key: cbor.Text("seen_by"), Value: texts(g.SeenBy)}, {Key: cbor.Text("missing"), Value: texts(g.Missing)}})
	}
	seq := cbor.Array{}
	for _, g := range r.SeqGaps {
		missing, repeated := cbor.Array{}, cbor.Array{}
		for _, m := range g.Missing {
			missing = append(missing, cbor.Array{cbor.Uint(m[0]), cbor.Uint(m[1])})
		}
		for _, n := range g.Repeated {
			repeated = append(repeated, cbor.Uint(n))
		}
		seq = append(seq, cbor.Map{{Key: cbor.Text("issuer"), Value: cbor.Text(g.Issuer)},
			{Key: cbor.Text("missing"), Value: missing}, {Key: cbor.Text("repeated"), Value: repeated}})
	}
	actors := cbor.Array{}
	for _, a := range r.Actors {
		named := cbor.Map{}
		for iss, actor := range a.Actors {
			named = append(named, cbor.Entry{Key: cbor.Text(iss), Value: cbor.Text(actor)})
		}
		actors = append(actors, cbor.Map{{Key: cbor.Text("action"), Value: cbor.Bytes(a.Action[:])},
			{Key: cbor.Text("at"), Value: cbor.Text(instant(a.At))}, {Key: cbor.Text("actors"), Value: named}})
	}
	return cbor.Map{
		{Key: cbor.Text("v"), Value: cbor.Uint(Version)},
		{Key: cbor.Text("from"), Value: cbor.Text(instant(r.From))},
		{Key: cbor.Text("to"), Value: cbor.Text(instant(r.To))},
		{Key: cbor.Text("tolerance_ms"), Value: cbor.Uint(uint64(r.Tolerance / time.Millisecond))},
		{Key: cbor.Text("expect"), Value: expect},
		{Key: cbor.Text("inputs"), Value: cbor.Bytes(r.Inputs[:])},
		{Key: cbor.Text("receipts"), Value: cbor.Uint(uint64(r.Receipts))},
		{Key: cbor.Text("actions"), Value: cbor.Uint(uint64(r.Actions))},
		{Key: cbor.Text("complete"), Value: cbor.Uint(uint64(r.Complete))},
		{Key: cbor.Text("gaps"), Value: gaps},
		{Key: cbor.Text("gaps_total"), Value: cbor.Uint(uint64(r.GapsTotal))},
		{Key: cbor.Text("seq_gaps"), Value: seq},
		{Key: cbor.Text("actor_splits"), Value: actors},
		{Key: cbor.Text("actor_splits_total"), Value: cbor.Uint(uint64(r.ActorsTotal))},
		{Key: cbor.Text("verdict"), Value: cbor.Text(r.Verdict)},
	}
}

// ReconciliationSubject names a reconciliation by its inputs.
func ReconciliationSubject(inputs [32]byte) string {
	return fmt.Sprintf("aep:reconciliation:%x", inputs)
}

// Payload is the reconciliation receipt's payload.
func (r Result) Payload() ([]byte, error) {
	if r.Tolerance%time.Millisecond != 0 {
		return nil, errors.New("the tolerance is a whole number of milliseconds")
	}
	return cbor.Encode(r.payload())
}

// IssueReconciliation signs a reconciliation as a SCITT statement.
func IssueReconciliation(s cose.Signer, issuer string, r Result, now time.Time) ([]byte, error) {
	payload, err := r.Payload()
	if err != nil {
		return nil, err
	}
	return scitt.Sign(s, scitt.Statement{Issuer: issuer, Subject: ReconciliationSubject(r.Inputs),
		IssuedAt: now, ContentType: ContentReconciliation, Payload: payload})
}

// ReadReconciliation reads a reconciliation receipt's statement and the
// verdict, window and inputs digest it states; it does not check the
// signature. CheckReconciliation is how its findings are checked.
func ReadReconciliation(b []byte) (*scitt.Signed, Window, [32]byte, string, error) {
	var w Window
	s, err := scitt.Read(b)
	if err != nil {
		return nil, w, [32]byte{}, "", err
	}
	if s.ContentType != ContentReconciliation {
		return nil, w, [32]byte{}, "", fmt.Errorf("the statement is %q, not a reconciliation receipt", s.ContentType)
	}
	f, err := fields(s.Message.Payload, reconciliationKeys, reconciliationKeys)
	if err != nil {
		return nil, w, [32]byte{}, "", err
	}
	inputs, err := digest32(f, "inputs")
	if err != nil {
		return nil, w, [32]byte{}, "", err
	}
	if s.Subject != ReconciliationSubject(inputs) {
		return nil, w, [32]byte{}, "", errors.New("the statement's subject is not its inputs digest")
	}
	from, _ := text(f, "from")
	to, _ := text(f, "to")
	if w.From, err = parseInstant("from", from); err != nil {
		return nil, w, [32]byte{}, "", err
	}
	if w.To, err = parseInstant("to", to); err != nil {
		return nil, w, [32]byte{}, "", err
	}
	tol, ok := f["tolerance_ms"].(cbor.Uint)
	if !ok || time.Duration(tol) > MaxTolerance/time.Millisecond {
		return nil, w, [32]byte{}, "", errors.New(`"tolerance_ms" is not a tolerance read here`)
	}
	w.Tolerance = time.Duration(tol) * time.Millisecond
	list, ok := f["expect"].(cbor.Array)
	if !ok {
		return nil, w, [32]byte{}, "", errors.New(`"expect" is not a list`)
	}
	for _, item := range list {
		m, ok := item.(cbor.Map)
		if !ok || len(m) != 2 {
			return nil, w, [32]byte{}, "", errors.New("an expected party is an issuer and a vantage")
		}
		iss, _ := m.Get(cbor.Text("issuer"))
		van, _ := m.Get(cbor.Text("vantage"))
		it, ok1 := iss.(cbor.Text)
		vt, ok2 := van.(cbor.Text)
		if !ok1 || !ok2 {
			return nil, w, [32]byte{}, "", errors.New("an expected party is an issuer and a vantage")
		}
		w.Expect = append(w.Expect, Expect{Issuer: string(it), Vantage: string(vt)})
	}
	if err := w.check(); err != nil {
		return nil, w, [32]byte{}, "", err
	}
	verdict, _ := text(f, "verdict")
	if !slices.Contains([]string{Agree, Disagree, Inconclusive}, verdict) {
		return nil, w, [32]byte{}, "", errors.New("the verdict is agree, disagree or inconclusive")
	}
	return s, w, inputs, verdict, nil
}

// reconciliationKeys are a reconciliation payload's fields, every one
// required.
var reconciliationKeys = []string{"v", "from", "to", "tolerance_ms", "expect", "inputs", "receipts",
	"actions", "complete", "gaps", "gaps_total", "seq_gaps", "actor_splits", "actor_splits_total", "verdict"}

// Tally is what a reconciliation receipt counts: the receipts and actions
// it read, the actions every expected party reported, and the
// disagreements of each kind, past the lists' cap.
type Tally struct {
	Window
	Verdict                     string
	Receipts, Actions, Complete int
	Gaps, SeqGaps, ActorSplits  int
}

// ReadTally reads a reconciliation receipt's counts as ReadReconciliation
// reads its verdict, without checking the signature: what it reported.
func ReadTally(b []byte) (Tally, error) {
	s, w, _, verdict, err := ReadReconciliation(b)
	if err != nil {
		return Tally{}, err
	}
	f, err := fields(s.Message.Payload, reconciliationKeys, reconciliationKeys)
	if err != nil {
		return Tally{}, err
	}
	t := Tally{Window: w, Verdict: verdict}
	for _, c := range []struct {
		key string
		n   *int
	}{{"receipts", &t.Receipts}, {"actions", &t.Actions}, {"complete", &t.Complete},
		{"gaps_total", &t.Gaps}, {"actor_splits_total", &t.ActorSplits}} {
		u, ok := f[c.key].(cbor.Uint)
		if !ok || u > math.MaxInt32 {
			return Tally{}, fmt.Errorf("%q is not a count", c.key)
		}
		*c.n = int(u)
	}
	seq, ok := f["seq_gaps"].(cbor.Array)
	if !ok {
		return Tally{}, errors.New(`"seq_gaps" is not a list`)
	}
	t.SeqGaps = len(seq)
	return t, nil
}

// CheckReconciliation recomputes a reconciliation receipt from receipts
// and requires its payload byte for byte: a reconciliation is checked by
// doing it again, not by trusting who signed it.
func CheckReconciliation(statement []byte, inputs []Input) (Result, error) {
	s, w, stated, _, err := ReadReconciliation(statement)
	if err != nil {
		return Result{}, err
	}
	again, err := Reconcile(inputs, w)
	if err != nil {
		return Result{}, err
	}
	payload, err := again.Payload()
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(payload, s.Message.Payload) {
		if again.Inputs != stated {
			return again, errors.New("these are not the receipts it reconciled: the inputs digest differs")
		}
		return again, errors.New("the same receipts reconcile to something other than it states")
	}
	return again, nil
}
