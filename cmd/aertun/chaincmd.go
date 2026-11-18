// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/chain"
	"github.com/aertun/aertun/internal/fetch"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// `aertun chain posture FILE --rpc URL`: what a protocol declares about the
// settings that guard it on an EVM chain — a Safe's threshold and owners, a
// timelock's delay, a proxy's admin and implementation — read from the
// chain at one block (internal/chain) and signed as a chain-posture proof
// (internal/proof), kept where the proving ground shows it.
//
// The endpoint is the operator's to name and is used for nothing else: its
// URL is never written into the proof, the audit record or a message,
// because a hosted provider's carries the credential in it. Its host is
// named instead.

func cmdChain(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("chain needs posture")
	}
	switch args[0] {
	case "posture":
		return chainPosture(root, args[1:])
	default:
		return fmt.Errorf("unknown chain command %q; try posture", args[0])
	}
}

var blockNumber = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

func chainPosture(root string, args []string) error {
	fs := flag.NewFlagSet("chain posture", flag.ContinueOnError)
	rpcAt := fs.String("rpc", "", "the chain's JSON-RPC endpoint: https, or http to a node on this "+
		"machine; it is never written down, since a provider's URL carries its credential")
	blockAt := fs.String("block", "", "the block to read at, by number (default: the endpoint's "+
		"latest finalized block)")
	reachAt := fs.String("reach", "", "private ranges a node run inside the organisation is in, "+
		"comma-separated (10.20.0.0/16, or 127.0.0.1/32 for one on this machine)")
	keyAt := fs.String("key", "", "the dual signing key file (aertun content keygen makes one)")
	pubAt := fs.String("public-key", "", "with --key, where to write the public key a verifier needs")
	outAt := fs.String("out", "", "where to write the proof (default: standard output)")
	var file string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if file == "" || fs.NArg() != 0 || *rpcAt == "" || *keyAt == "" {
		return fmt.Errorf("chain posture takes FILE --rpc URL --key FILE: the posture file, the " +
			"chain's endpoint, and the key the proof is signed with")
	}
	block := int64(-1)
	if *blockAt != "" {
		n, err := strconv.ParseInt(*blockAt, 10, 64)
		if !blockNumber.MatchString(*blockAt) || err != nil || n > proof.MaxChainNumber {
			return fmt.Errorf("--block is a block's number in decimal, like 21000000")
		}
		block = n
	}
	reach := fetch.Public
	if *reachAt != "" {
		var ranges []string
		for _, r := range strings.Split(*reachAt, ",") {
			if r = strings.TrimSpace(r); r != "" {
				ranges = append(ranges, r)
			}
		}
		prefixes, err := parseReach(ranges)
		if err != nil {
			return err
		}
		reach = fetch.Within(prefixes)
	}

	caller := resolveCaller(root, flagToken)
	// Tune, like the other proofs signed in the organisation's name: a
	// signed statement that a protocol's guards hold is one somebody moves
	// money, or approves a listing, on.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	k, err := loadSigningKey(*keyAt)
	if err != nil {
		return err
	}
	body, err := proof.ReadBounded(file, chain.MaxPostureFile)
	if err != nil {
		return err
	}
	p, canonical, err := chain.ParsePosture(body)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	c, err := chain.Dial(*rpcAt, reach)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), chain.ReadTimeout)
	defer cancel()
	r, err := chain.Read(ctx, c, p, block)
	if err != nil {
		return err
	}

	st, err := proof.ProveChainPosture(proof.ChainPostureInput{Name: p.Name, ChainID: r.ChainID,
		Block: r.Block, BlockHash: r.BlockHash, Finalized: r.Finalized, Readings: r.Settings,
		Posture: canonical, Materials: []proof.Material{{Name: "chain-state",
			Digest: proof.SHA256(r.Lines), Entries: r.Calls}},
		Program: version, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	env, err := proof.Seal(st, k)
	if err != nil {
		return err
	}
	doc, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	doc = append(doc, '\n')
	if *pubAt != "" {
		if err := pack.WritePublicKey(*pubAt, k.PublicKey()); err != nil {
			return err
		}
	}
	if pubDoc, err := json.Marshal(k.PublicKey()); err == nil {
		keepMade(root, env, pubDoc, caller.Name)
	}
	ev := st.Predicate.ChainPosture
	if err := recordE(root, caller.auditRecord("chain.posture-proved", "/proofs", audit.Success,
		map[string]string{"name": ev.Name, "chain": strconv.FormatInt(ev.ChainID, 10),
			"block": strconv.FormatInt(ev.Block, 10), "block_hash": ev.BlockHash,
			"endpoint": c.Host(), "verdict": string(st.Predicate.Verdict),
			"held": strconv.Itoa(ev.Held), "regressed": strconv.Itoa(ev.Regressed),
			"unread": strconv.Itoa(ev.Unread)})); err != nil {
		return err
	}
	if *outAt == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else {
		if err := atomicfile.Write(*outAt, doc, 0o600); err != nil {
			return err
		}
		if !w.JSON(summary(st)) {
			w.Human("%s\n  read from %s\n", describe(st), c.Host())
		}
	}
	return notProven(st)
}
