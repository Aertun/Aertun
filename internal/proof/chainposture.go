// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// A chain-posture proof: the settings a protocol says guard it on an EVM
// chain — how many of a multisig's owners must sign, how long a timelock
// makes every change wait, who may upgrade a proxy and to what — read from
// the chain at one block and held to what the protocol declared
// (internal/chain).
//
// # Why
//
// The largest crypto thefts of 2025 and 2026 were operational, and the weak
// settings behind them were public before them: one protocol moved its
// admin multisig to two of five, with no timelock, days before it lost
// $285M; another ran a verifier one signature could satisfy. A protocol
// states its posture — five of nine, a 48-hour delay — in its documents,
// and the chain says what it is, block by block, to anybody who asks.
// Nobody asks continuously. This asks, at one block, and signs the answer.
//
// # The claim
//
// At block B (hash H) on chain C, every setting the posture file declares
// holds: each Safe multisig's threshold and number of owners is at least
// the least declared; each OpenZeppelin TimelockController's minimum delay
// is at least the least declared; each EIP-1967 proxy's admin slot holds
// the address declared, and its implementation slot does too when one is
// declared.
//
//   - refuted when a setting was read and does not hold, and the proof
//     names each: the contract, the setting, what was declared and what was
//     found, in numbers and addresses only. One setting shown weaker than
//     declared refutes the claim whatever the others did;
//   - proven when every setting declared was read and holds;
//   - inconclusive otherwise: a setting could not be read, because the
//     endpoint failed or the contract did not answer as the kind declared
//     answers, and the proof says which and why.
//
// # What it does not cover
//
// What the posture file does not declare. A Safe's modules and guard can
// move what it holds without its owners' signatures; who holds a
// timelock's proposer, executor and admin roles decides whether its delay
// can be stepped around; a proxy's admin is often a ProxyAdmin contract
// whose own owner is the real authority. Each is a further read this
// version does not make, so a proven posture is proof of what was declared
// and nothing beside it. Every read is answered by the endpoint the
// operator names, against one block's hash; anybody can make the same reads
// at the same hash against another endpoint, and must get the same values.

// ChainPostureVerifier and its version name this verifier.
const (
	ChainPostureVerifier        = "aertun/chain-posture"
	ChainPostureVerifierVersion = "1"
)

// PredicateChainPosture is the predicate of a chain-posture proof.
const PredicateChainPosture = "https://aertun.github.io/proof/chain-posture/v1"

// The settings a posture declares. The first three are numbers, of which
// the posture declares the least; the last two are addresses a slot must
// hold.
const (
	SettingSafeThreshold       = "safe-threshold"
	SettingSafeOwners          = "safe-owners"
	SettingTimelockDelay       = "timelock-delay"
	SettingProxyAdmin          = "proxy-admin"
	SettingProxyImplementation = "proxy-implementation"
)

// What came of one setting.
const (
	PostureHeld      = "held"
	PostureRegressed = "regressed"
	PostureUnread    = "unread"
)

// Why a setting could not be read. A closed set, so nothing the endpoint
// or the contract wrote reaches the proof as words.
const (
	// UnreadRPCError is a call the endpoint failed or answered with an
	// error; a revert is one.
	UnreadRPCError = "rpc-error"
	// UnreadEmpty is a call answered with nothing: no code at the address,
	// or no such function and no fallback that reverts.
	UnreadEmpty = "empty"
	// UnreadMalformed is an answer that is not the shape the declared kind
	// of contract gives: a word too long, an address word with high bits
	// set, a Safe with no owners or a threshold above them.
	UnreadMalformed = "malformed"
	// UnreadOutOfRange is a number larger than a proof carries.
	UnreadOutOfRange = "out-of-range"
	// UnreadNotAProxy is a proxy whose implementation slot is empty: it is
	// not an EIP-1967 proxy, whatever its admin slot holds.
	UnreadNotAProxy = "not-a-proxy"
)

// The bounds a chain-posture proof's numbers are held to.
const (
	// MaxChainNumber is the largest chain id, block number or setting a
	// proof carries: 2^53 - 1, the largest integer every JSON reader reads
	// exactly.
	MaxChainNumber = 1<<53 - 1
	// MaxPostureSettings bounds the settings one posture declares.
	MaxPostureSettings = 128
	// MaxSafeOwners bounds a Safe's owners, declared or read.
	MaxSafeOwners = 256
	// MaxPostureDelay bounds a declared delay, in seconds: ten years, past
	// which a number is a typing mistake rather than a delay.
	MaxPostureDelay = 3650 * 24 * 60 * 60
)

var (
	addressShape     = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	blockHashShape   = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	postureNameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	decimalShape     = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)
)

// ZeroAddress is the address no contract is at.
const ZeroAddress = "0x0000000000000000000000000000000000000000"

// ValidAddress reports whether s is an address as a proof carries it: 0x
// and forty lower-case hexadecimal digits.
func ValidAddress(s string) bool { return addressShape.MatchString(s) }

// ValidBlockHash reports whether s is a block hash as a proof carries it.
func ValidBlockHash(s string) bool { return blockHashShape.MatchString(s) }

// ValidPostureName reports whether s can name a posture in a proof.
func ValidPostureName(s string) bool { return postureNameShape.MatchString(s) }

// numberSetting reports whether a setting is a number, and the bounds a
// declared one is held to.
func numberSetting(setting string) (bool, int64) {
	switch setting {
	case SettingSafeThreshold, SettingSafeOwners:
		return true, MaxSafeOwners
	case SettingTimelockDelay:
		return true, MaxPostureDelay
	}
	return false, 0
}

func knownSetting(setting string) bool {
	switch setting {
	case SettingSafeThreshold, SettingSafeOwners, SettingTimelockDelay,
		SettingProxyAdmin, SettingProxyImplementation:
		return true
	}
	return false
}

func proxySetting(setting string) bool {
	return setting == SettingProxyAdmin || setting == SettingProxyImplementation
}

// postureDecimal reads a number as a proof writes it, and reports whether
// it is one.
func postureDecimal(s string) (int64, bool) {
	if !decimalShape.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n <= MaxChainNumber
}

// PostureSetting is one setting a posture file declares, and what was read
// for it.
type PostureSetting struct {
	// Address is the contract the setting is on: 0x and forty lower-case
	// hexadecimal digits.
	Address string `json:"address"`
	// Setting is which setting it is: safe-threshold, safe-owners,
	// timelock-delay (in seconds), proxy-admin or proxy-implementation.
	Setting string `json:"setting"`
	// Declared is what the posture file declares: for a number setting the
	// least it may be, in decimal; for an address setting the address the
	// slot must hold.
	Declared string `json:"declared"`
	// Found is what was read at the block, in the same form as Declared,
	// and empty when the setting could not be read.
	Found string `json:"found,omitempty"`
	// Outcome is held, regressed or unread, and follows from the fields
	// above: a number holds when it is at least what was declared, an
	// address when it is the one declared.
	Outcome string `json:"outcome"`
	// Reason is why an unread setting could not be read: rpc-error, empty,
	// malformed, out-of-range or not-a-proxy. Empty when it was read.
	Reason string `json:"reason,omitempty"`
}

// outcome is what the declared and found values make of a setting.
func (s PostureSetting) outcome() string {
	if s.Found == "" {
		return PostureUnread
	}
	if number, _ := numberSetting(s.Setting); number {
		want, _ := postureDecimal(s.Declared)
		got, _ := postureDecimal(s.Found)
		if got >= want {
			return PostureHeld
		}
		return PostureRegressed
	}
	if s.Found == s.Declared {
		return PostureHeld
	}
	return PostureRegressed
}

// ChainPostureEvidence is what a chain-posture proof rests on.
type ChainPostureEvidence struct {
	// Name is the protocol's name as the posture file gives it: lower-case
	// letters, digits, '.', '_' and '-', at most 64.
	Name string `json:"name"`
	// ChainID is the chain the posture file declares, and the one the
	// endpoint said it serves.
	ChainID int64 `json:"chain_id"`
	// Block is the number of the block every setting was read at.
	Block int64 `json:"block"`
	// BlockHash is that block's hash. Every read named the block by it
	// (EIP-1898), so every setting was read from the same state.
	BlockHash string `json:"block_hash"`
	// Finalized says the block was the endpoint's latest finalized one,
	// read at because the operator named no block.
	Finalized bool `json:"finalized,omitempty"`
	// Settings are every setting the posture file declares, in its order,
	// with what was read for each.
	Settings []PostureSetting `json:"settings"`
	// Held is how many settings were read and hold.
	Held int `json:"held"`
	// Regressed is how many settings were read and do not hold.
	Regressed int `json:"regressed"`
	// Unread is how many settings could not be read.
	Unread int `json:"unread"`
}

// PostureReading is one declared setting and what was read for it: Found
// in the setting's form, or the Reason it could not be read.
type PostureReading struct {
	Address, Setting, Declared, Found, Reason string
}

// ChainPostureInput is what a chain-posture proof is made from.
type ChainPostureInput struct {
	Name      string
	ChainID   int64
	Block     int64
	BlockHash string
	Finalized bool
	Readings  []PostureReading
	// Posture is the posture file in its RFC 8785 canonical form: what the
	// subject's digest is over.
	Posture   []byte
	Materials []Material
	Program   string
	Now       time.Time
}

// ProveChainPosture builds the unsigned statement.
func ProveChainPosture(in ChainPostureInput) (*Statement, error) {
	ev := &ChainPostureEvidence{Name: in.Name, ChainID: in.ChainID, Block: in.Block,
		BlockHash: in.BlockHash, Finalized: in.Finalized}
	for _, r := range in.Readings {
		s := PostureSetting{Address: r.Address, Setting: r.Setting, Declared: r.Declared,
			Found: r.Found, Reason: r.Reason}
		s.Outcome = s.outcome()
		ev.Settings = append(ev.Settings, s)
		switch s.Outcome {
		case PostureHeld:
			ev.Held++
		case PostureRegressed:
			ev.Regressed++
		default:
			ev.Unread++
		}
	}
	if err := ev.wellFormed(); err != nil {
		return nil, err
	}
	if len(in.Posture) == 0 {
		return nil, fmt.Errorf("no posture file was read, so there is nothing to sign")
	}
	st := &Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: ev.subject(), Digest: SHA256(in.Posture)}},
		PredicateType: PredicateChainPosture,
		Predicate: Predicate{
			Claim:   ev.claim(),
			Verdict: ev.verdict(),
			Verifier: VerifierID{ID: ChainPostureVerifier, Version: ChainPostureVerifierVersion,
				Program: in.Program},
			Materials:    append([]Material{}, in.Materials...),
			Checks:       ev.checks(),
			ChainPosture: ev, VerifiedAt: in.Now.UTC().Format(time.RFC3339),
		},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (ev *ChainPostureEvidence) subject() string {
	return fmt.Sprintf("chain/%d/%s", ev.ChainID, ev.Name)
}

// wellFormed refuses evidence whose shapes or numbers do not hold together,
// on either side of signing.
func (ev *ChainPostureEvidence) wellFormed() error {
	if !ValidPostureName(ev.Name) {
		return fmt.Errorf("a posture is named in lower-case letters, digits, '.', '_' and '-', " +
			"at most 64 of them")
	}
	if ev.ChainID < 1 || ev.ChainID > MaxChainNumber || ev.Block < 0 || ev.Block > MaxChainNumber ||
		!ValidBlockHash(ev.BlockHash) {
		return fmt.Errorf("a posture names its chain, and the block it was read at by number and " +
			"by a hash of 64 lower-case hexadecimal digits")
	}
	if len(ev.Settings) == 0 || len(ev.Settings) > MaxPostureSettings {
		return fmt.Errorf("a posture declares between 1 and %d settings", MaxPostureSettings)
	}
	at := map[string]PostureSetting{}
	held, regressed, unread := 0, 0, 0
	for _, s := range ev.Settings {
		key := s.Address + " " + s.Setting
		if !ValidAddress(s.Address) || s.Address == ZeroAddress || !knownSetting(s.Setting) {
			return fmt.Errorf("each setting is one this version reads, on a contract named by its address")
		}
		if _, twice := at[key]; twice {
			return fmt.Errorf("%s is declared twice for %s", s.Setting, s.Address)
		}
		at[key] = s
		if err := s.wellFormed(); err != nil {
			return err
		}
		switch s.Outcome {
		case PostureHeld:
			held++
		case PostureRegressed:
			regressed++
		default:
			unread++
		}
	}
	if held != ev.Held || regressed != ev.Regressed || unread != ev.Unread {
		return fmt.Errorf("the held, regressed and unread counts are not the settings'")
	}
	// A contract is declared whole: a Safe by its threshold and its owners,
	// a proxy by its admin before its implementation. The two halves of
	// one have to agree with each other as well as with the chain.
	for _, s := range at {
		switch s.Setting {
		case SettingSafeThreshold, SettingSafeOwners:
			threshold, okT := at[s.Address+" "+SettingSafeThreshold]
			owners, okO := at[s.Address+" "+SettingSafeOwners]
			if !okT || !okO {
				return fmt.Errorf("a Safe is declared by its threshold and its owners together")
			}
			dt, _ := postureDecimal(threshold.Declared)
			do, _ := postureDecimal(owners.Declared)
			if dt > do {
				return fmt.Errorf("a Safe's threshold is never more than its owners, and %s "+
					"declares it so", s.Address)
			}
			if threshold.Found != "" && owners.Found != "" {
				ft, _ := postureDecimal(threshold.Found)
				fo, _ := postureDecimal(owners.Found)
				if ft > fo {
					return fmt.Errorf("%s was read with a threshold above its owners, which is "+
						"not a Safe's answer", s.Address)
				}
			}
		case SettingProxyImplementation:
			admin, ok := at[s.Address+" "+SettingProxyAdmin]
			if !ok {
				return fmt.Errorf("a proxy's implementation is declared with its admin")
			}
			if (admin.Reason == UnreadNotAProxy) != (s.Reason == UnreadNotAProxy) {
				return fmt.Errorf("%s is a proxy for one of its settings and not the other", s.Address)
			}
		}
	}
	return nil
}

// wellFormed holds one setting to the shapes its kind allows.
func (s PostureSetting) wellFormed() error {
	number, most := numberSetting(s.Setting)
	if number {
		want, ok := postureDecimal(s.Declared)
		if !ok || want < 1 || want > most {
			return fmt.Errorf("%s on %s declares %q, and it is a whole number between 1 and %d",
				s.Setting, s.Address, s.Declared, most)
		}
		if s.Found != "" {
			got, ok := postureDecimal(s.Found)
			if !ok || (s.Setting != SettingTimelockDelay && (got < 1 || got > MaxSafeOwners)) {
				return fmt.Errorf("%s on %s was found as %q, which is not a reading it can have",
					s.Setting, s.Address, s.Found)
			}
		}
	} else {
		if !ValidAddress(s.Declared) || (s.Setting == SettingProxyImplementation && s.Declared == ZeroAddress) {
			return fmt.Errorf("%s on %s declares %q, and it is an address", s.Setting, s.Address, s.Declared)
		}
		if s.Found != "" && (!ValidAddress(s.Found) ||
			(s.Setting == SettingProxyImplementation && s.Found == ZeroAddress)) {
			return fmt.Errorf("%s on %s was found as %q, which is not a reading it can have",
				s.Setting, s.Address, s.Found)
		}
	}
	switch {
	case s.Found != "" && s.Reason != "":
		return fmt.Errorf("%s on %s was read, and still gives a reason it was not", s.Setting, s.Address)
	case s.Found == "" && !knownReason(s.Reason, s.Setting):
		return fmt.Errorf("%s on %s was not read, and the reason is not one a %s setting can have",
			s.Setting, s.Address, map[bool]string{true: "number", false: "address"}[number])
	}
	if s.Outcome != s.outcome() {
		return fmt.Errorf("%s on %s is said to have %s, and what was declared and found make it %s",
			s.Setting, s.Address, s.Outcome, s.outcome())
	}
	return nil
}

// knownReason reports whether a reason is one a setting can be unread for:
// only a number can be out of range, and only a proxy's setting can be on a
// contract that is not one.
func knownReason(reason, setting string) bool {
	number, _ := numberSetting(setting)
	switch reason {
	case UnreadRPCError, UnreadEmpty, UnreadMalformed:
		return true
	case UnreadOutOfRange:
		return number
	case UnreadNotAProxy:
		return proxySetting(setting)
	}
	return false
}

func (ev *ChainPostureEvidence) verdict() Verdict {
	switch {
	case ev.Regressed > 0:
		return Refuted
	case ev.Unread > 0:
		return Inconclusive
	}
	return Proven
}

// contracts is how many contracts the settings are on.
func (ev *ChainPostureEvidence) contracts() int {
	seen := map[string]bool{}
	for _, s := range ev.Settings {
		seen[s.Address] = true
	}
	return len(seen)
}

func (ev *ChainPostureEvidence) claim() string {
	return fmt.Sprintf("At block %d (hash %s) on chain %d, every setting the posture file "+
		"declares holds: %d setting(s) on %d contract(s).", ev.Block, ev.BlockHash, ev.ChainID,
		len(ev.Settings), ev.contracts())
}

// postureRegression names one setting that does not hold, in numbers and
// addresses only.
func postureRegression(s PostureSetting) string {
	if number, _ := numberSetting(s.Setting); number {
		return fmt.Sprintf("%s %s: declared at least %s, found %s", s.Address, s.Setting, s.Declared, s.Found)
	}
	return fmt.Sprintf("%s %s: declared %s, found %s", s.Address, s.Setting, s.Declared, s.Found)
}

// checks are the proof's checks, every word from the evidence.
func (ev *ChainPostureEvidence) checks() []Check {
	block := Check{Name: "block", Passed: true,
		Detail: fmt.Sprintf("chain %d, block %d, hash %s: every read named the block by its hash, "+
			"so every setting was read from the same state", ev.ChainID, ev.Block, ev.BlockHash)}
	if ev.Finalized {
		block.Detail += "; it was the endpoint's latest finalized block, which the chain does not " +
			"take back"
	} else {
		block.Detail += "; it was the block the operator named"
	}

	hold := Check{Name: "settings-hold", Passed: ev.Regressed == 0,
		Detail: fmt.Sprintf("%d of %d setting(s) read hold; %d regressed", ev.Held,
			ev.Held+ev.Regressed, ev.Regressed)}
	var regressions, unread []string
	for _, s := range ev.Settings {
		switch s.Outcome {
		case PostureRegressed:
			regressions = append(regressions, postureRegression(s))
		case PostureUnread:
			unread = append(unread, fmt.Sprintf("%s %s (%s)", s.Address, s.Setting, s.Reason))
		}
	}
	shown, more := capped(regressions)
	hold.Failures = shown
	if more > 0 {
		hold.Detail += fmt.Sprintf("; %d more not listed", more)
	}

	read := Check{Name: "settings-read", Passed: true}
	if ev.Unread == 0 {
		read.Detail = fmt.Sprintf("every one of the %d declared setting(s) was read", len(ev.Settings))
	} else {
		named, more := capped(unread)
		read.Detail = fmt.Sprintf("%d of %d declared setting(s) could not be read, so they are not "+
			"shown to hold: %s", ev.Unread, len(ev.Settings), strings.Join(named, "; "))
		if more > 0 {
			read.Detail += fmt.Sprintf("; %d more not listed", more)
		}
	}
	return []Check{block, hold, read}
}

// validate refuses evidence whose numbers do not add up, do not support the
// verdict, or do not account for every word the statement says. Every
// regression is in the evidence, so the names listed are rebuilt and
// compared exactly, not only counted.
func (ev *ChainPostureEvidence) validate(s *Statement) error {
	if err := ev.wellFormed(); err != nil {
		return err
	}
	if want := ev.verdict(); s.Predicate.Verdict != want {
		return fmt.Errorf("the settings make this %s, not %s", want, s.Predicate.Verdict)
	}
	if len(s.Predicate.Checks) != 3 {
		return fmt.Errorf("a chain-posture proof has three checks")
	}
	want := ev.checks()
	for i, c := range s.Predicate.Checks {
		if !slices.Equal(c.Failures, want[i].Failures) {
			return fmt.Errorf("the regressions listed are not the ones the settings show")
		}
	}
	return sameWords(s, ev.subject(), ev.claim(), want)
}
