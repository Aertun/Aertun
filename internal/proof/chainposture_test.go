// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	cpSafe     = "0x1111111111111111111111111111111111111111"
	cpTimelock = "0x2222222222222222222222222222222222222222"
	cpProxy    = "0x3333333333333333333333333333333333333333"
	cpImpl     = "0x4444444444444444444444444444444444444444"
	cpOther    = "0x5555555555555555555555555555555555555555"
	cpHash     = "0x" + "ab" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
)

// cpInput is a five-of-nine Safe behind a 48-hour timelock that administers
// one proxy, every setting read and holding, at a finalized block.
func cpInput() ChainPostureInput {
	return ChainPostureInput{Name: "example-protocol", ChainID: 1, Block: 21000000, BlockHash: cpHash,
		Finalized: true, Readings: []PostureReading{
			{Address: cpSafe, Setting: SettingSafeThreshold, Declared: "5", Found: "5"},
			{Address: cpSafe, Setting: SettingSafeOwners, Declared: "9", Found: "9"},
			{Address: cpTimelock, Setting: SettingTimelockDelay, Declared: "172800", Found: "172800"},
			{Address: cpProxy, Setting: SettingProxyAdmin, Declared: cpTimelock, Found: cpTimelock},
			{Address: cpProxy, Setting: SettingProxyImplementation, Declared: cpImpl, Found: cpImpl},
		},
		Posture: []byte(`{"chain_id":1,"name":"example-protocol"}`), Program: "test",
		Now: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
}

func TestAChainPosturesVerdict(t *testing.T) {
	cases := map[string]struct {
		change func(*ChainPostureInput)
		want   Verdict
	}{
		"every setting holds":            {func(*ChainPostureInput) {}, Proven},
		"more than declared still holds": {func(in *ChainPostureInput) { in.Readings[0].Found = "7" }, Proven},
		"a threshold lowered": {func(in *ChainPostureInput) {
			in.Readings[0].Found = "2"
		}, Refuted},
		"owners fewer than declared": {func(in *ChainPostureInput) {
			in.Readings[0].Found, in.Readings[1].Found = "2", "5"
		}, Refuted},
		"a delay of nothing": {func(in *ChainPostureInput) { in.Readings[2].Found = "0" }, Refuted},
		"the admin moved": {func(in *ChainPostureInput) {
			in.Readings[3].Found = cpOther
		}, Refuted},
		"the implementation replaced": {func(in *ChainPostureInput) {
			in.Readings[4].Found = cpOther
		}, Refuted},
		"one setting unread": {func(in *ChainPostureInput) {
			in.Readings[2].Found, in.Readings[2].Reason = "", UnreadRPCError
		}, Inconclusive},
		"not a proxy": {func(in *ChainPostureInput) {
			in.Readings[3].Found, in.Readings[3].Reason = "", UnreadNotAProxy
			in.Readings[4].Found, in.Readings[4].Reason = "", UnreadNotAProxy
		}, Inconclusive},
		"a regression outranks an unread setting": {func(in *ChainPostureInput) {
			in.Readings[0].Found = "1"
			in.Readings[2].Found, in.Readings[2].Reason = "", UnreadEmpty
		}, Refuted},
		"an admin renounced, as declared": {func(in *ChainPostureInput) {
			in.Readings[3].Declared, in.Readings[3].Found = ZeroAddress, ZeroAddress
		}, Proven},
	}
	for name, c := range cases {
		in := cpInput()
		in.Readings = append([]PostureReading{}, in.Readings...)
		c.change(&in)
		st, err := ProveChainPosture(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Predicate.Verdict != c.want {
			t.Errorf("%s: %s, want %s: %+v", name, st.Predicate.Verdict, c.want, st.Predicate.Checks)
		}
	}
}

// What regressed is named by contract, setting, declared and found; what
// could not be read is named with why; and the claim says the block.
func TestAChainPostureNamesEachRegressionAndEachUnreadSetting(t *testing.T) {
	in := cpInput()
	in.Readings[0].Found = "2"
	in.Readings[3].Found = cpOther
	in.Readings[2].Found, in.Readings[2].Reason = "", UnreadMalformed
	st, err := ProveChainPosture(in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(st.Predicate.Checks[1].Failures, "|"),
		cpSafe+" safe-threshold: declared at least 5, found 2|"+
			cpProxy+" proxy-admin: declared "+cpTimelock+", found "+cpOther; got != want {
		t.Errorf("named %q, want %q", got, want)
	}
	if d := st.Predicate.Checks[2].Detail; !strings.Contains(d, cpTimelock+" timelock-delay (malformed)") {
		t.Errorf("the unread setting is not named: %s", d)
	}
	if c := st.Predicate.Claim; !strings.Contains(c, "At block 21000000 (hash "+cpHash+") on chain 1") ||
		!strings.Contains(c, "5 setting(s) on 3 contract(s)") {
		t.Errorf("the claim: %s", c)
	}
	if st.Subject[0].Name != "chain/1/example-protocol" || st.Subject[0].Digest["sha256"] == "" {
		t.Errorf("the subject: %+v", st.Subject)
	}
	ev := st.Predicate.ChainPosture
	if ev.Held != 2 || ev.Regressed != 2 || ev.Unread != 1 {
		t.Errorf("counts: %+v", ev)
	}
}

// Evidence that does not hold together is refused before anything is
// signed.
func TestAChainPostureThatDoesNotHoldTogetherIsRefused(t *testing.T) {
	cases := map[string]func(*ChainPostureInput){
		"a name in prose":           func(in *ChainPostureInput) { in.Name = "Example Protocol" },
		"no chain":                  func(in *ChainPostureInput) { in.ChainID = 0 },
		"a chain past 2^53":         func(in *ChainPostureInput) { in.ChainID = MaxChainNumber + 1 },
		"a block hash too short":    func(in *ChainPostureInput) { in.BlockHash = "0xabcd" },
		"a block hash in capitals":  func(in *ChainPostureInput) { in.BlockHash = strings.ToUpper(cpHash) },
		"no settings":               func(in *ChainPostureInput) { in.Readings = nil },
		"an address in capitals":    func(in *ChainPostureInput) { in.Readings[2].Address = strings.ToUpper(cpTimelock) },
		"an address with no 0x":     func(in *ChainPostureInput) { in.Readings[2].Address = cpTimelock[2:] + "00" },
		"the zero contract":         func(in *ChainPostureInput) { in.Readings[2].Address = ZeroAddress },
		"a setting not known":       func(in *ChainPostureInput) { in.Readings[2].Setting = "timelock-guard" },
		"a setting twice":           func(in *ChainPostureInput) { in.Readings = append(in.Readings, in.Readings[2]) },
		"a declared zero":           func(in *ChainPostureInput) { in.Readings[2].Declared = "0" },
		"a declared leading zero":   func(in *ChainPostureInput) { in.Readings[2].Declared = "0172800" },
		"a delay over ten years":    func(in *ChainPostureInput) { in.Readings[2].Declared = "315360001" },
		"a found number in words":   func(in *ChainPostureInput) { in.Readings[2].Found = "two days" },
		"a found address in prose":  func(in *ChainPostureInput) { in.Readings[3].Found = "the timelock" },
		"a found threshold of zero": func(in *ChainPostureInput) { in.Readings[0].Found = "0" },
		"more owners than read": func(in *ChainPostureInput) {
			in.Readings[1].Declared, in.Readings[1].Found = "9", fmt.Sprint(MaxSafeOwners+1)
		},
		"a threshold read above the owners": func(in *ChainPostureInput) { in.Readings[0].Found = "10" },
		"a threshold declared above the owners": func(in *ChainPostureInput) {
			in.Readings[0].Declared = "10"
		},
		"a Safe declared by half": func(in *ChainPostureInput) { in.Readings = in.Readings[1:] },
		"an implementation without its admin": func(in *ChainPostureInput) {
			in.Readings = append(in.Readings[:3], in.Readings[4])
		},
		"a proxy for one setting and not the other": func(in *ChainPostureInput) {
			in.Readings[3].Found, in.Readings[3].Reason = "", UnreadNotAProxy
		},
		"an empty implementation declared": func(in *ChainPostureInput) {
			in.Readings[4].Declared = ZeroAddress
		},
		"read and a reason beside": func(in *ChainPostureInput) { in.Readings[2].Reason = UnreadRPCError },
		"unread with no reason":    func(in *ChainPostureInput) { in.Readings[2].Found = "" },
		"unread for a reason in prose": func(in *ChainPostureInput) {
			in.Readings[2].Found, in.Readings[2].Reason = "", "the node said no"
		},
		"a delay that is not a proxy": func(in *ChainPostureInput) {
			in.Readings[2].Found, in.Readings[2].Reason = "", UnreadNotAProxy
		},
		"an address out of range": func(in *ChainPostureInput) {
			in.Readings[3].Found, in.Readings[3].Reason = "", UnreadOutOfRange
		},
		"no posture file": func(in *ChainPostureInput) { in.Posture = nil },
	}
	for name, change := range cases {
		in := cpInput()
		in.Readings = append([]PostureReading{}, in.Readings...)
		change(&in)
		if _, err := ProveChainPosture(in); err == nil {
			t.Errorf("%s: proved", name)
		}
	}
	in := cpInput()
	for i := range MaxPostureSettings {
		in.Readings = append(in.Readings, PostureReading{Address: fmt.Sprintf("0x%040x", 0x100+i),
			Setting: SettingTimelockDelay, Declared: "60", Found: "60"})
	}
	if _, err := ProveChainPosture(in); err == nil {
		t.Errorf("%d settings proved", len(in.Readings))
	}
}

// Every word is rebuilt from the settings when the statement is opened, so
// an edited one is refused.
func TestAChainPostureCarriesOnlyWhatItsSettingsSay(t *testing.T) {
	in := cpInput()
	in.Readings[0].Found = "2"
	in.Readings[2].Found, in.Readings[2].Reason = "", UnreadRPCError
	st, err := ProveChainPosture(in)
	if err != nil {
		t.Fatal(err)
	}
	tamper := map[string]func(*Statement){
		"verdict": func(s *Statement) { s.Predicate.Verdict = Inconclusive },
		"claim":   func(s *Statement) { s.Predicate.Claim += " The protocol is safe." },
		"a regression renamed": func(s *Statement) {
			s.Predicate.Checks[1].Failures[0] = cpSafe + " safe-threshold: declared at least 5, found 4"
		},
		"a regression dropped": func(s *Statement) {
			s.Predicate.Checks[1].Failures = nil
			s.Predicate.Checks[1].Passed = true
			s.Predicate.Verdict = Inconclusive
		},
		"a regression on the wrong check": func(s *Statement) {
			s.Predicate.Checks[2].Failures = s.Predicate.Checks[1].Failures
		},
		"the found value raised": func(s *Statement) {
			s.Predicate.ChainPosture.Settings[0].Found = "5"
		},
		"the found value raised and the outcome with it": func(s *Statement) {
			ev := s.Predicate.ChainPosture
			ev.Settings[0].Found, ev.Settings[0].Outcome = "5", PostureHeld
			ev.Held, ev.Regressed = ev.Held+1, 0
		},
		"the declared value lowered": func(s *Statement) {
			s.Predicate.ChainPosture.Settings[0].Declared = "2"
		},
		"the unread made read": func(s *Statement) {
			ev := s.Predicate.ChainPosture
			ev.Settings[2].Found, ev.Settings[2].Reason, ev.Settings[2].Outcome = "172800", "", PostureHeld
		},
		"the block moved":      func(s *Statement) { s.Predicate.ChainPosture.Block++ },
		"the chain changed":    func(s *Statement) { s.Predicate.ChainPosture.ChainID = 10 },
		"finalized claimed":    func(s *Statement) { s.Predicate.ChainPosture.Finalized = false },
		"the subject":          func(s *Statement) { s.Subject[0].Name = "chain/1/another-protocol" },
		"a check's detail":     func(s *Statement) { s.Predicate.Checks[2].Detail = "every setting was read" },
		"a fourth check":       func(s *Statement) { s.Predicate.Checks = append(s.Predicate.Checks, Check{Name: "x", Passed: true}) },
		"a second kind":        func(s *Statement) { s.Predicate.Revocation = &RevocationEvidence{} },
		"another predicate":    func(s *Statement) { s.PredicateType = PredicateRevocation },
		"the counts away":      func(s *Statement) { s.Predicate.ChainPosture.Unread = 0 },
		"an unread reason":     func(s *Statement) { s.Predicate.ChainPosture.Settings[2].Reason = UnreadEmpty },
		"a setting's contract": func(s *Statement) { s.Predicate.ChainPosture.Settings[4].Address = cpOther },
	}
	for name, change := range tamper {
		var copied Statement
		b, _ := json.Marshal(st)
		if err := json.Unmarshal(b, &copied); err != nil {
			t.Fatal(err)
		}
		change(&copied)
		if copied.Validate() == nil {
			t.Errorf("%s: an edited statement validated", name)
		}
	}
	k := mustKey(t)
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Open(env, k.PublicKey())
	if err != nil || back.Predicate.Verdict != Refuted || back.Predicate.ChainPosture.Regressed != 1 ||
		back.Predicate.ChainPosture.Settings[2].Reason != UnreadRPCError {
		t.Errorf("the proof does not round-trip: %v", err)
	}
}

// A regression beyond the cap is counted, not named, and the statement still
// validates with every word rebuilt; so does an unread setting beyond it.
func TestRegressionsBeyondTheCapAreCounted(t *testing.T) {
	in := cpInput()
	for i := range MaxFailures + 7 {
		in.Readings = append(in.Readings, PostureReading{Address: fmt.Sprintf("0x%040x", 0x100+i),
			Setting: SettingTimelockDelay, Declared: "172800", Found: "3600"})
	}
	for i := range MaxFailures + 3 {
		in.Readings = append(in.Readings, PostureReading{Address: fmt.Sprintf("0x%040x", 0x1000+i),
			Setting: SettingTimelockDelay, Declared: "172800", Reason: UnreadEmpty})
	}
	st, err := ProveChainPosture(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Predicate.Checks[1].Failures) != MaxFailures ||
		!strings.Contains(st.Predicate.Checks[1].Detail, "7 more not listed") ||
		!strings.Contains(st.Predicate.Checks[2].Detail, "3 more not listed") {
		t.Errorf("%+v", st.Predicate.Checks)
	}
	if err := st.Validate(); err != nil {
		t.Error(err)
	}
}
