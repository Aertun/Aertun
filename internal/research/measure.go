// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/aertun/aertun/internal/audit"
)

// MeasureMessage is the size of what the signing timings sign: a kilobyte,
// the order of a receipt's payload.
const MeasureMessage = 1024

// warmup runs are made and not timed before each measure.
const warmup = 10

// Measure times, iterations times each after a warm-up: Ed25519 and
// ML-DSA-65 signing and verifying a MeasureMessage-byte message, and an
// append to a hash-chained audit log in scratch, a directory it may
// write in and that it leaves its log in. The keys are made for the
// measurement and thrown away.
func Measure(scratch string, iterations int) ([]MeasurementRow, error) {
	if iterations < 1 {
		return nil, errors.New("a measurement needs at least one iteration")
	}
	msg := make([]byte, MeasureMessage)
	rand.Read(msg)

	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var edSig []byte
	edSign := time1(iterations, func() error { edSig = ed25519.Sign(edKey, msg); return nil })
	edVerify := time1(iterations, func() error {
		if !ed25519.Verify(edPub, msg, edSig) {
			return errors.New("an Ed25519 signature made here did not verify")
		}
		return nil
	})

	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	mlPub := mlKey.PublicKey()
	opts := &mldsa.Options{Context: Context}
	var mlSig []byte
	mlSign := time1(iterations, func() (err error) { mlSig, err = mlKey.SignDeterministic(msg, opts); return err })
	mlVerify := time1(iterations, func() error { return mldsa.Verify(mlPub, msg, mlSig, opts) })

	log, err := audit.New(audit.Options{Path: filepath.Join(scratch, "measure-audit.jsonl"),
		Source: "research-measure"})
	if err != nil {
		return nil, err
	}
	var entry []byte
	appendOne := time1(iterations, func() error {
		ev, err := log.Append(audit.Record{Action: "research.measure", Resource: "/",
			Outcome: audit.Success, Principal: "measure", Kind: audit.KindService, Verified: true})
		if err != nil {
			return err
		}
		entry, err = json.Marshal(ev)
		return err
	})

	rows := []MeasurementRow{}
	for _, m := range []struct {
		measure, alg  string
		msg, sig, pub int
		t             timing
	}{
		{"sign", "ed25519", len(msg), ed25519.SignatureSize, ed25519.PublicKeySize, edSign},
		{"verify", "ed25519", len(msg), ed25519.SignatureSize, ed25519.PublicKeySize, edVerify},
		{"sign", "ml-dsa-65", len(msg), len(mlSig), len(mlPub.Bytes()), mlSign},
		{"verify", "ml-dsa-65", len(msg), len(mlSig), len(mlPub.Bytes()), mlVerify},
		{"audit-append", "", len(entry), 0, 0, appendOne},
	} {
		if m.t.err != nil {
			return nil, fmt.Errorf("measuring %s %s: %w", m.measure, m.alg, m.t.err)
		}
		rows = append(rows, MeasurementRow{Measure: m.measure, Alg: m.alg, MessageBytes: m.msg,
			SignatureBytes: m.sig, PublicKeyBytes: m.pub, Iterations: iterations,
			MedianUS: m.t.median, P95US: m.t.p95})
	}
	return rows, nil
}

type timing struct {
	median, p95 float64
	err         error
}

// time1 runs f warmup times untimed, then n times timed, and gives the
// median and the 95th percentile in microseconds; the first error stops it.
func time1(n int, f func() error) timing {
	for range warmup {
		if err := f(); err != nil {
			return timing{err: err}
		}
	}
	d := make([]time.Duration, n)
	for i := range d {
		start := time.Now()
		if err := f(); err != nil {
			return timing{err: err}
		}
		d[i] = time.Since(start)
	}
	slices.Sort(d)
	at := func(q float64) float64 {
		i := int(q*float64(n)+0.999999) - 1
		return float64(d[max(0, min(i, n-1))].Nanoseconds()) / 1e3
	}
	return timing{median: at(0.5), p95: at(0.95)}
}
