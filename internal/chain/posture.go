// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package chain reads the settings that guard a protocol on an EVM chain —
// a Safe multisig's threshold and owners, an OpenZeppelin
// TimelockController's minimum delay, an EIP-1967 proxy's admin and
// implementation — over JSON-RPC at one block, for a chain-posture proof
// (internal/proof).
//
// # What a posture file is
//
// What a protocol says about itself, in a form a program can hold it to:
//
//	{
//	  "name": "example-protocol",
//	  "chain_id": 1,
//	  "safes": [{"address": "0x…", "min_threshold": 5, "min_owners": 9}],
//	  "timelocks": [{"address": "0x…", "min_delay_seconds": 172800}],
//	  "proxies": [{"address": "0x…", "admin": "0x…", "implementation": "0x…"}]
//	}
//
// The implementation is optional; everything else a contract is declared
// with is not. The file is read strictly: no field this version does not
// know, no member twice, no number that is not a whole one inside its
// bounds, and no address that is not 0x and forty hexadecimal digits. An
// address is lower-cased as it is read. Its EIP-55 mixed-case checksum is
// not checked, because that needs Keccak-256 and the standard library has
// SHA-3 only; a mistyped address reads a contract that is not there, and
// that setting is unread rather than held.
//
// The proof's subject is the file's RFC 8785 canonical form, so anybody
// with the file and any canonicaliser recomputes the digest it signs.
//
// # What is read, and from where
//
// Every call goes to the one endpoint the operator names, through the
// program's declared network purpose (internal/egress), over HTTPS — plain
// HTTP only to this machine, where no network lies between — with no
// redirect followed and every answer read under a size limit. The endpoint
// may carry a credential in its path or query, as hosted providers' do, so
// its URL is never written into a message: only its host is named.
//
// Every read names the block by its hash (EIP-1898), so every setting comes
// from the same state even while the chain moves on.
package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/aertun/aertun/internal/jcs"
	"github.com/aertun/aertun/internal/proof"
)

// MaxPostureFile bounds a posture file, which a hundred and twenty-eight
// settings fit in many times over.
const MaxPostureFile = 64 << 10

// Posture is what a protocol declares about its settings on one chain.
type Posture struct {
	// Name is the protocol's, in the shape a proof can carry.
	Name string `json:"name"`
	// ChainID is the chain the settings are on.
	ChainID int64 `json:"chain_id"`
	// Safes are the Safe multisigs it declares.
	Safes []Safe `json:"safes,omitempty"`
	// Timelocks are the TimelockControllers it declares.
	Timelocks []Timelock `json:"timelocks,omitempty"`
	// Proxies are the EIP-1967 proxies it declares.
	Proxies []Proxy `json:"proxies,omitempty"`
}

// Safe is a Safe multisig and the least it declares of it.
type Safe struct {
	Address      string `json:"address"`
	MinThreshold int64  `json:"min_threshold"`
	MinOwners    int64  `json:"min_owners"`
}

// Timelock is a TimelockController and the least delay it declares.
type Timelock struct {
	Address         string `json:"address"`
	MinDelaySeconds int64  `json:"min_delay_seconds"`
}

// Proxy is an EIP-1967 proxy and who it declares may upgrade it, and to
// what when it says.
type Proxy struct {
	Address        string `json:"address"`
	Admin          string `json:"admin"`
	Implementation string `json:"implementation,omitempty"`
}

var anyCaseAddress = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// address reads a declared address, lower-cased, or says what it should be.
func address(what, s string) (string, error) {
	if !anyCaseAddress.MatchString(s) {
		return "", fmt.Errorf("%s is %q, and an address is 0x and forty hexadecimal digits", what, s)
	}
	return strings.ToLower(s), nil
}

// ParsePosture reads a posture file strictly, and returns it with its RFC
// 8785 canonical form: the bytes the proof's subject digest is over.
func ParsePosture(body []byte) (*Posture, []byte, error) {
	if len(body) > MaxPostureFile {
		return nil, nil, fmt.Errorf("the posture file is larger than %d bytes", MaxPostureFile)
	}
	// Canonicalised first, because the canonicaliser refuses what
	// encoding/json lets through without a word: a member given twice, of
	// which it would keep the last, and text that is not UTF-8.
	canonical, err := jcs.Canonicalize(body)
	if err != nil {
		return nil, nil, fmt.Errorf("the posture file is not one JSON document: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	var p Posture
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("the posture file does not read as one: %w; it has name, "+
			"chain_id, safes, timelocks and proxies, and nothing else", err)
	}
	if !proof.ValidPostureName(p.Name) {
		return nil, nil, fmt.Errorf("the posture's name is %q; name it in lower-case letters, "+
			"digits, '.', '_' and '-', at most 64, as a proof can carry it", p.Name)
	}
	if p.ChainID < 1 || p.ChainID > proof.MaxChainNumber {
		return nil, nil, fmt.Errorf("chain_id is %d; it is the chain's id, a whole number from 1 "+
			"(1 is Ethereum's mainnet)", p.ChainID)
	}
	if len(p.Safes)+len(p.Timelocks)+len(p.Proxies) == 0 {
		return nil, nil, fmt.Errorf("the posture declares no Safe, timelock or proxy, so there " +
			"is nothing to read")
	}
	seen := map[string]bool{}
	once := func(kind, a string) error {
		if seen[kind+a] {
			return fmt.Errorf("%s %s is declared twice; declare each once", kind, a)
		}
		seen[kind+a] = true
		return nil
	}
	for i := range p.Safes {
		s := &p.Safes[i]
		if s.Address, err = address("a Safe's address", s.Address); err != nil {
			return nil, nil, err
		}
		if err := once("the Safe", s.Address); err != nil {
			return nil, nil, err
		}
		if s.MinThreshold < 1 || s.MinOwners < s.MinThreshold || s.MinOwners > proof.MaxSafeOwners {
			return nil, nil, fmt.Errorf("the Safe %s declares %d of %d; a threshold is at least 1 "+
				"and never more than the owners, who are at most %d", s.Address, s.MinThreshold,
				s.MinOwners, proof.MaxSafeOwners)
		}
	}
	for i := range p.Timelocks {
		t := &p.Timelocks[i]
		if t.Address, err = address("a timelock's address", t.Address); err != nil {
			return nil, nil, err
		}
		if err := once("the timelock", t.Address); err != nil {
			return nil, nil, err
		}
		if t.MinDelaySeconds < 1 || t.MinDelaySeconds > proof.MaxPostureDelay {
			return nil, nil, fmt.Errorf("the timelock %s declares a delay of %d seconds; it is "+
				"between 1 and %d (ten years)", t.Address, t.MinDelaySeconds, proof.MaxPostureDelay)
		}
	}
	for i := range p.Proxies {
		x := &p.Proxies[i]
		if x.Address, err = address("a proxy's address", x.Address); err != nil {
			return nil, nil, err
		}
		if err := once("the proxy", x.Address); err != nil {
			return nil, nil, err
		}
		// The zero address is a declaration an admin may have: renounced,
		// so nobody can upgrade. An implementation may not: a proxy with
		// none is not one.
		if x.Admin, err = address("the admin of "+x.Address, x.Admin); err != nil {
			return nil, nil, err
		}
		if x.Implementation != "" {
			if x.Implementation, err = address("the implementation of "+x.Address, x.Implementation); err != nil {
				return nil, nil, err
			}
			if x.Implementation == proof.ZeroAddress {
				return nil, nil, fmt.Errorf("the proxy %s declares no implementation by naming the "+
					"zero address; leave implementation out instead", x.Address)
			}
		}
	}
	for a := range seen {
		if strings.HasSuffix(a, proof.ZeroAddress) {
			return nil, nil, fmt.Errorf("no contract is at the zero address, so none can be declared there")
		}
	}
	if n := len(p.settings()); n > proof.MaxPostureSettings {
		return nil, nil, fmt.Errorf("the posture declares %d settings; a proof carries at most %d, "+
			"so split it into postures of a part of the protocol each", n, proof.MaxPostureSettings)
	}
	return &p, canonical, nil
}

// setting is one declared setting, before it is read.
type setting struct {
	address, name, declared string
}

// settings are what the posture declares, in its order: a Safe's threshold
// then its owners, a timelock's delay, a proxy's admin then its
// implementation.
func (p *Posture) settings() []setting {
	var out []setting
	for _, s := range p.Safes {
		out = append(out, setting{s.Address, proof.SettingSafeThreshold, strconv.FormatInt(s.MinThreshold, 10)},
			setting{s.Address, proof.SettingSafeOwners, strconv.FormatInt(s.MinOwners, 10)})
	}
	for _, t := range p.Timelocks {
		out = append(out, setting{t.Address, proof.SettingTimelockDelay, strconv.FormatInt(t.MinDelaySeconds, 10)})
	}
	for _, x := range p.Proxies {
		out = append(out, setting{x.Address, proof.SettingProxyAdmin, x.Admin})
		if x.Implementation != "" {
			out = append(out, setting{x.Address, proof.SettingProxyImplementation, x.Implementation})
		}
	}
	return out
}
