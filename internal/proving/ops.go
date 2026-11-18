// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package proving declares the proving ground's operations: what has been
// proven, refuted and left inconclusive in a store, read and added to the same
// way on the command line, in the console and by agents (internal/ops).
package proving

import (
	"errors"
	"strings"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/ops"
	"github.com/aertun/aertun/internal/proof"
	"github.com/aertun/aertun/internal/proofstore"
)

// Kept proofs: what has been proven, refuted and left inconclusive here,
// whose key signed each, and whether each still verifies. A proof's words
// are labelled by where they came from. A calibration certificate's and a
// verdicts proof's claim and checks are rebuilt from their numbers and
// closed sets whenever they are opened (internal/proof), so they are this
// program's. A detection proof names the rule it checked — a file name and a
// title chosen by whoever submitted the rule, which may be the model under
// test — so its subject, claim, check details and materials are labelled as
// written outside, as anything that could be either is. An evidence proof's
// words are rebuilt from closed sets too, but they carry the ids and
// observables the investigation's author cited, strictly parsed and still
// the author's choice, so they are labelled as written outside as well. So
// are a chain-posture proof's: its words are rebuilt from numbers and closed
// sets, but its subject carries the name the posture file gives and its
// settings the addresses the file declares, which are the claimant's.
// the author's choice, so they are labelled as written outside as well. A
// sealed-alert proof's words are rebuilt from digests and numbers alone —
// the alert itself is never in it — so they are this program's.
// the author's choice, so they are labelled as written outside as well. An
// MDR proof's words are rebuilt from its numbers, and the emulation ids a
// refutation names come from the operator's own list, strictly parsed and
// never the provider's, so they are this program's. A coverage proof's
// words are rebuilt from its numbers and from technique ids of a fixed
// shape, so they are this program's; the rule ids its evidence lists are
// the rules' authors' choice, strictly shaped, and labelled as written
// outside.

// proofKinds names each predicate by the word every face shows.
var proofKinds = map[string]string{
	proof.PredicateDetection:      "detection",
	proof.PredicateCalibration:    "calibration",
	proof.PredicateVerdicts:       "verdicts",
	proof.PredicateReconciliation: "reconciliation",
	proof.PredicateAdjudication:   "adjudication",
	proof.PredicateClaim:          "claim",
	proof.PredicateNotAffected:    "not-affected",
	proof.PredicateTriage:         "triage",
	proof.PredicateEvidence:       "evidence",
	proof.PredicateRevocation:     "revocation",
	proof.PredicateClock:          "clock",
	proof.PredicateBreachScope:    "breach-scope",
	proof.PredicateVEXRecord:      "vex-record",
	proof.PredicateChainPosture:   "chain-posture",
	proof.PredicateSealed:         "sealed",
	proof.PredicateMDR:            "mdr",
	proof.PredicatePeerLog:        "peer-log",
	proof.PredicateCoverage:       "coverage",
}

// kindWords are the kinds a listing can be narrowed to.
var kindWords = []string{"detection", "triage", "calibration", "verdicts", "reconciliation", "adjudication", "claim",
	"not-affected", "evidence", "revocation", "clock", "breach-scope", "vex-record", "chain-posture", "sealed", "mdr",
	"peer-log", "coverage"}

func proofKind(st *proof.Statement) string {
	if k, ok := proofKinds[st.PredicateType]; ok {
		return k
	}
	return "unknown"
}

// wordsFrom is how a proof's words are labelled: its own for the kinds whose
// words are rebuilt from numbers, outside for the rest.
func wordsFrom(st *proof.Statement) func(string) *ops.Answer {
	if st.Predicate.Calibration != nil || st.Predicate.Verdicts != nil ||
		st.Predicate.Reconciliation != nil || st.Predicate.Adjudication != nil ||
		st.Predicate.ClaimTest != nil || st.Predicate.NotAffected != nil || st.Predicate.Triage != nil ||
		st.Predicate.Revocation != nil || st.Predicate.Clock != nil || st.Predicate.VEXRecord != nil ||
		st.Predicate.Sealed != nil || st.Predicate.MDR != nil || st.Predicate.PeerLog != nil ||
		st.Predicate.Coverage != nil {
		return ops.OursText
	}
	return ops.Outside
}

func entryRow(e proofstore.Entry) *ops.Answer {
	row := ops.Object().With("id", ops.Ours(e.ID)).With("kept_at", ops.Ours(e.KeptAt)).
		With("kept_by", ops.Ours(e.KeptBy)).With("origin", ops.Ours(e.Origin)).With("key_id", ops.Ours(e.KeyID)).
		With("signer", ops.Ours(e.Signer)).With("trusted", ops.Ours(e.Signer != ""))
	if e.Broken != "" {
		return row.With("broken", ops.Ours(e.Broken))
	}
	st := e.Statement
	words := wordsFrom(st)
	row.With("kind", ops.Ours(proofKind(st))).With("verdict", ops.Ours(string(st.Predicate.Verdict))).
		With("subject", words(st.Subject[0].Name)).With("claim", words(st.Predicate.Claim)).
		With("verified_at", ops.Ours(st.Predicate.VerifiedAt))
	if c := st.Predicate.Calibration; c != nil {
		row.With("expires", ops.Ours(c.Expires))
	}
	return row
}

// Source is where the operations read kept proofs from: the store, or a
// recorded case (the context twin), so a replay is answered by the same
// operations over what was kept when it was recorded.
type Source interface {
	List() ([]proofstore.Entry, error)
	Get(id string) (proofstore.Entry, error)
	// Trusted is the trusted signers' names by key fingerprint.
	Trusted() (map[string]string, error)
}

// Store is the kept proofs of the store at its root, read and checked again
// on every call.
type Store string

// List is every kept proof.
func (s Store) List() ([]proofstore.Entry, error) { return proofstore.List(string(s)) }

// Get is one kept proof.
func (s Store) Get(id string) (proofstore.Entry, error) { return proofstore.Get(string(s), id) }

// Trusted is the store's trusted signers.
func (s Store) Trusted() (map[string]string, error) {
	signers, err := proofstore.Signers(string(s))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(signers))
	for _, g := range signers {
		out[g.KeyID] = g.Name
	}
	return out, nil
}

// Recorded is kept proofs as they were read once: what a recorded case holds.
type Recorded []proofstore.Entry

// List is every recorded proof.
func (r Recorded) List() ([]proofstore.Entry, error) {
	return append([]proofstore.Entry(nil), r...), nil
}

// Trusted is the signers the recorded proofs were labelled with when they
// were recorded: trust as it stood then, which is what a replay answers.
func (r Recorded) Trusted() (map[string]string, error) {
	out := map[string]string{}
	for _, e := range r {
		if e.Signer != "" {
			out[e.KeyID] = e.Signer
		}
	}
	return out, nil
}

// Get is one recorded proof.
func (r Recorded) Get(id string) (proofstore.Entry, error) {
	for _, e := range r {
		if e.ID == id {
			return e, nil
		}
	}
	return proofstore.Entry{}, errors.New("no proof is kept with that id")
}

func listProofs(src Source) func(ops.Call) (*ops.Answer, error) {
	return func(c ops.Call) (*ops.Answer, error) {
		kind := c.Args.Text("kind")
		if kind != "" && !containsWord(kindWords, kind) {
			return nil, &ops.Refusal{Reason: "kind is one of " + strings.Join(kindWords, ", ")}
		}
		limit := c.Args.Number("limit", 50)
		if limit < 1 || limit > 500 {
			return nil, &ops.Refusal{Reason: "limit is between 1 and 500"}
		}
		all, err := src.List()
		if err != nil {
			return nil, err
		}
		rows := ops.List()
		shown, broken := 0, 0
		counts := map[string]int{}
		for _, e := range all {
			if e.Broken != "" {
				broken++
			} else {
				counts[proofKind(e.Statement)+" "+string(e.Statement.Predicate.Verdict)]++
			}
			if kind != "" && (e.Statement == nil || proofKind(e.Statement) != kind) {
				continue
			}
			if shown < limit {
				rows.Add(entryRow(e))
				shown++
			}
		}
		return ops.Object().With("proofs", rows).With("kept", ops.Ours(len(all))).
			With("broken", ops.Ours(broken)).With("by_kind_and_verdict", ops.ByKey(counts, func(n int) *ops.Answer {
			return ops.Ours(n)
		})), nil
	}
}

func containsWord(set []string, w string) bool {
	for _, s := range set {
		if s == w {
			return true
		}
	}
	return false
}

func readProof(src Source) func(ops.Call) (*ops.Answer, error) {
	return func(c ops.Call) (*ops.Answer, error) {
		id := c.Args.Text("id")
		if !proofstore.ValidID(id) {
			return nil, &ops.Refusal{Reason: "a proof's id is 24 hexadecimal characters"}
		}
		e, err := src.Get(id)
		if err != nil {
			return nil, &ops.Refusal{Reason: err.Error()}
		}
		row := entryRow(e)
		if e.Broken != "" {
			return row, nil
		}
		st := e.Statement
		p := st.Predicate
		words := wordsFrom(st)
		row.With("verifier", ops.Object().With("id", ops.Ours(p.Verifier.ID)).
			With("version", ops.Ours(p.Verifier.Version)).With("program", ops.Ours(p.Verifier.Program)))
		row.With("checks", ops.ListOf(p.Checks, func(ch proof.Check) *ops.Answer {
			return ops.Object().With("name", ops.Ours(ch.Name)).With("passed", ops.Ours(ch.Passed)).
				With("detail", words(ch.Detail)).With("failures", ops.ListOf(ch.Failures, words))
		}))
		row.With("materials", ops.ListOf(p.Materials, func(m proof.Material) *ops.Answer {
			return ops.Object().With("name", words(m.Name)).With("sha256", ops.Ours(m.Digest["sha256"])).
				With("entries", ops.Ours(m.Entries))
		}))
		switch {
		case p.Detection != nil:
			d := p.Detection
			row.With("evidence", ops.Object().With("rule", ops.Outside(d.Rule)).
				With("positives", ops.Ours(d.Positives)).With("caught", ops.Ours(d.Caught)).
				With("negatives", ops.Ours(d.Negatives)).With("quiet", ops.Ours(d.Quiet)).
				With("recall_wilson_low", ops.Ours(d.RecallLow)).
				With("specificity_wilson_low", ops.Ours(d.SpecificityLow)).
				With("fixtures", ops.Ours(d.Fixtures)))
		case p.Triage != nil:
			tr := p.Triage
			row.With("evidence", ops.Object().With("model", ops.Ours(tr.Model)).
				With("corpus", ops.Ours(tr.Corpus)).With("runs", ops.Ours(tr.Runs)).
				With("cases", ops.Ours(tr.Cases)).With("tolerance", ops.Ours(tr.Tolerance)).
				With("false_closures", boundAnswer(tr.FalseClosures)).
				With("closure_reliability", rateAnswer(tr.ClosureReliability)).
				With("pass_k", rateAnswer(tr.PassK)).With("hijacks", rateAnswer(tr.Hijacks)).
				With("abstentions", rateAnswer(tr.Abstentions)))
		case p.Calibration != nil:
			k := p.Calibration
			row.With("evidence", ops.Object().With("model", ops.Ours(k.Model)).
				With("family", ops.Ours(k.Family)).With("channel", ops.Ours(k.Channel)).
				With("threshold", ops.Ours(k.Threshold)).With("epsilon", ops.Ours(k.Epsilon)).
				With("delta", ops.Ours(k.Delta)).With("cases", ops.Ours(k.Cases)).
				With("closures", ops.Ours(k.Closures)).With("false_closures", ops.Ours(k.FalseClosures)).
				With("false_closure_upper", ops.Ours(k.Upper)).With("expires", ops.Ours(k.Expires)).
				With("template_sha256", ops.Ours(k.Template)))
		case p.NotAffected != nil:
			v := p.NotAffected
			reasons := ops.List()
			for _, r := range v.Reasons {
				reasons.Add(ops.Object().With("reason", ops.Ours(r.Reason)).With("count", ops.Ours(r.Count)))
			}
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("asset", ops.Ours(v.Asset)).With("statements", ops.Ours(v.Statements)).
				With("not_affected", ops.Ours(v.NotAffected)).With("supported", ops.Ours(v.Supported)).
				With("contradicted", ops.Ours(v.Contradicted)).With("uncheckable", ops.Ours(v.Uncheckable)).
				With("reasons", reasons))
		case p.Citations != nil:
			v := p.Citations
			outcomes := ops.ListOf(v.Outcomes, func(o proof.CitationOutcome) *ops.Answer {
				row := ops.Object().With("id", ops.Outside(o.ID)).With("kind", ops.Ours(o.Kind)).
					With("outcome", ops.Ours(o.Outcome)).With("reason", ops.Ours(o.Reason)).
					With("observed", ops.Ours(o.Observed)).With("extracted", ops.Ours(o.Extracted))
				if o.Kind == proof.CiteCount {
					return row.With("compare", ops.Ours(o.Compare)).With("stated", ops.Ours(o.Stated))
				}
				return row.With("cited_type", ops.Ours(o.CitedType)).With("cited", ops.Outside(o.Cited))
			})
			row.With("evidence", ops.Object().With("source", ops.Outside(v.Source)).
				With("form", ops.Ours(v.Form)).With("since", ops.Ours(v.Since)).With("until", ops.Ours(v.Until)).
				With("held_from", ops.Ours(v.HeldFrom)).With("held_until", ops.Ours(v.HeldUntil)).
				With("covered", ops.Ours(v.Covered)).With("events_read", ops.Ours(v.EventsRead)).
				With("claims", ops.Ours(v.Claims)).With("extracted", ops.Ours(v.Extracted)).
				With("supported", ops.Ours(v.Supported)).With("contradicted", ops.Ours(v.Contradicted)).
				With("uncheckable", ops.Ours(v.Uncheckable)).With("outcomes", outcomes))
		case p.ClaimTest != nil:
			v := p.ClaimTest
			row.With("evidence", ops.Object().With("card", ops.Ours(v.Name)).
				With("source", ops.Ours(v.Source)).With("metric", ops.Ours(v.Metric)).
				With("direction", ops.Ours(v.Direction)).With("threshold", ops.Ours(v.Threshold)).
				With("confidence", ops.Ours(v.Confidence)).With("window_closed", ops.Ours(v.Closed)).
				With("count", ops.Object().With("k", ops.Ours(v.K)).With("n", ops.Ours(v.N)).
					With("lower", ops.Ours(v.Low)).With("upper", ops.Ours(v.High))))
		case p.Adjudication != nil:
			v := p.Adjudication
			bound := func(b proof.Bound) *ops.Answer {
				return ops.Object().With("k", ops.Ours(b.K)).With("n", ops.Ours(b.N)).
					With("lower", ops.Ours(b.Lower)).With("upper", ops.Ours(b.Upper))
			}
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("sample", ops.Ours(v.Sample)).With("committed_at_entry", ops.Ours(int(v.Committed.Seq))).
				With("tolerance", ops.Ours(v.Tolerance)).
				With("ai_false_closures", bound(v.AI)).With("human_false_closures", bound(v.Human)).
				With("population_ai", ops.Ours(v.PopulationAI)).
				With("population_human", ops.Ours(v.PopulationHuman)).
				With("reviewers", ops.Ours(v.Reviewers)).With("earlier_draws", ops.Ours(v.EarlierDraws)))
		case p.Reconciliation != nil:
			v := p.Reconciliation
			row.With("evidence", ops.Object().With("agent", ops.Ours(v.Agent)).
				With("telemetry_agent", ops.Ours(v.Telemetry)).
				With("since", ops.Ours(v.Since)).With("until", ops.Ours(v.Until)).
				With("window_seconds", ops.Ours(v.Window)).
				With("reported", ops.Ours(v.Reported)).With("calls", ops.Ours(v.Calls)).
				With("matched", ops.Ours(v.Matched)).With("unreported", ops.Ours(v.Unreported)).
				With("unreceived", ops.Ours(v.Unreceived)).With("connections", ops.Ours(v.Connects)).
				With("unexplained", ops.Ours(v.Unexplained)).
				With("shared_skipped", ops.Ours(v.SharedSkipped)).
				With("gateway", ops.Ours(v.Gateway)).With("gateway_only", ops.Ours(v.GatewayOnly)).
				With("gateway_calls", ops.Ours(v.GatewayCalls)).
				With("gateway_unreported", ops.Ours(v.GatewayUnreported)).
				With("model_spans", ops.Ours(v.ModelSpans)).With("model_unseen", ops.Ours(v.ModelUnseen)).
				With("identities", ops.ListOf(v.Identities, func(s string) *ops.Answer { return ops.Ours(s) })).
				With("actions", ops.Ours(v.Changes)).
				With("unexplained_actions", ops.Ours(v.UnexplainedChanges)))
		case p.Revocation != nil:
			v := p.Revocation
			sources := ops.ListOf(v.Sources, func(s proof.RevocationSource) *ops.Answer {
				return ops.Object().With("source", ops.Ours(s.Source)).
					With("seen_before", ops.Ours(s.Before)).With("uses", ops.Ours(s.Uses)).
					With("refused", ops.Ours(s.Refused)).With("quiet_stretches", ops.Ours(s.Quiet)).
					With("complete", ops.Ours(s.Complete)).With("own_account", ops.Ours(s.Account))
			})
			identities := ops.ListOf(v.Identities, func(s string) *ops.Answer { return ops.Ours(s) })
			row.With("evidence", ops.Object().With("kind", ops.Ours(v.Kind)).
				With("name", ops.Ours(v.Name)).With("identities", identities).
				With("revoked", ops.Ours(v.Revoked)).With("revoked_entry", ops.Ours(v.RevokedEntry)).
				With("grace_seconds", ops.Ours(v.Grace)).With("until", ops.Ours(v.Until)).
				With("lookback_seconds", ops.Ours(v.Lookback)).With("stretch_seconds", ops.Ours(v.Stretch)).
				With("stretches", ops.Ours(v.Stretches)).With("uses", ops.Ours(v.Uses)).
				With("refused", ops.Ours(v.Refused)).With("sources", sources))
		case p.BreachScope != nil:
			v := p.BreachScope
			indicators := ops.ListOf(v.Indicators, func(b proof.BreachIndicator) *ops.Answer {
				return ops.Object().With("type", ops.Ours(b.Type)).With("value", ops.Outside(b.Value)).
					With("before", ops.Ours(b.Before)).With("during", ops.Ours(b.During)).
					With("after", ops.Ours(b.After))
			})
			row.With("evidence", ops.Object().With("vendor", ops.Ours(v.Vendor)).
				With("reference", ops.Outside(v.Reference)).With("since", ops.Ours(v.Since)).
				With("until", ops.Ours(v.Until)).With("margin_seconds", ops.Ours(v.Margin)).
				With("told", ops.Ours(v.Told)).With("held_before", ops.Ours(v.HeldBefore)).
				With("held_during", ops.Ours(v.HeldDuring)).With("held_after", ops.Ours(v.HeldAfter)).
				With("events", ops.Ours(v.Events)).With("indicators", indicators))
		case p.Clock != nil:
			v := p.Clock
			duties := ops.ListOf(v.Duties, func(d proof.ClockDuty) *ops.Answer {
				return ops.Object().With("regime", ops.Ours(d.Regime)).With("due", ops.Ours(d.Due)).
					With("done", ops.Ours(d.Done)).With("waived", ops.Ours(d.Waived)).
					With("moved", ops.Ours(d.Moved)).With("outcome", ops.Ours(d.Outcome))
			})
			evidence := ops.Object().With("incident", ops.Ours(v.Incident)).
				With("trigger", ops.Ours(v.Trigger)).With("entry", ops.Ours(v.Entry)).
				With("decided", ops.Ours(v.Decided)).With("recorded", ops.Ours(v.Recorded)).
				With("verified", ops.Ours(v.Verified)).With("linked", ops.Ours(v.Linked)).
				With("lead_seconds", ops.Ours(v.Lead)).With("broken_anchors", ops.Ours(len(v.Broken))).
				With("duties", duties)
			if a := v.Anchor; a != nil {
				evidence.With("anchor", ops.Object().With("size", ops.Ours(a.Size)).
					With("block", ops.Ours(int(a.Block))).With("block_hash", ops.Ours(a.Hash)).
					With("mined", ops.Ours(a.Mined)).With("calendar", ops.Ours(a.Calendar)))
			}
			row.With("evidence", evidence)
		case p.VEXRecord != nil:
			v := p.VEXRecord
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("since", ops.Ours(v.Since)).With("until", ops.Ours(v.Until)).
				With("tolerance", ops.Ours(v.Tolerance)).With("read", ops.Ours(v.Read)).
				With("left_out", ops.Ours(v.LeftOut)).With("superseded", ops.Ours(v.Superseded)).
				With("used", ops.Ours(v.Used)).With("signed_by_trusted", ops.Ours(v.Trusted)).
				With("signed_by_untrusted", ops.Ours(v.Untrusted)).With("assets", ops.Ours(v.Assets)).
				With("statements", ops.Ours(v.Statements)).With("not_affected", ops.Ours(v.NotAffected)).
				With("supported", ops.Ours(v.Supported)).With("contradicted", ops.Ours(v.Contradicted)).
				With("uncheckable", ops.Ours(v.Uncheckable)).
				With("contradicting_proofs", ops.Ours(v.ContradictingProofs)).
				With("contradicted_share", boundAnswer(v.Share)))
		case p.ChainPosture != nil:
			v := p.ChainPosture
			settings := ops.ListOf(v.Settings, func(s proof.PostureSetting) *ops.Answer {
				return ops.Object().With("address", ops.Outside(s.Address)).
					With("setting", ops.Ours(s.Setting)).With("declared", ops.Outside(s.Declared)).
					With("found", ops.Outside(s.Found)).With("outcome", ops.Ours(s.Outcome)).
					With("reason", ops.Ours(s.Reason))
			})
			row.With("evidence", ops.Object().With("name", ops.Outside(v.Name)).
				With("chain_id", ops.Ours(v.ChainID)).With("block", ops.Ours(v.Block)).
				With("block_hash", ops.Ours(v.BlockHash)).With("finalized", ops.Ours(v.Finalized)).
				With("held", ops.Ours(v.Held)).With("regressed", ops.Ours(v.Regressed)).
				With("unread", ops.Ours(v.Unread)).With("settings", settings))
		case p.Sealed != nil:
			v := p.Sealed
			hashes := func(h string) *ops.Answer { return ops.Ours(h) }
			row.With("evidence", ops.Object().With("digest", ops.Ours(v.Digest)).
				With("log_entries", ops.Ours(v.LogEntries)).With("log_break", ops.Ours(v.LogBreak)).
				With("rewritten", ops.Ours(v.Rewritten)).With("batches", ops.Ours(v.Batches)).
				With("unkept", ops.Ours(v.Unkept)).With("entry", ops.Ours(v.Entry)).
				With("sealed", ops.Ours(v.Sealed)).With("batch_root", ops.Ours(v.BatchRoot)).
				With("batch_size", ops.Ours(v.BatchSize)).With("batch_index", ops.Ours(v.BatchIndex)).
				With("batch_path", ops.ListOf(v.BatchPath, hashes)).
				With("entry_leaf", ops.Ours(v.EntryLeaf)).With("head_size", ops.Ours(v.HeadSize)).
				With("head_root", ops.Ours(v.HeadRoot)).With("head_path", ops.ListOf(v.HeadPath, hashes)).
				With("anchor", ops.Ours(v.Anchor)).With("height", ops.Ours(v.Height)).
				With("block_hash", ops.Ours(v.BlockHash)).With("mined", ops.Ours(v.Mined)))
		case p.MDR != nil:
			v := p.MDR
			row.With("evidence", ops.Object().With("plan", ops.Ours(v.Plan)).
				With("provider", ops.Ours(v.Provider)).
				With("committed_at_entry", ops.Ours(int(v.Committed.Seq))).
				With("window_start", ops.Ours(v.WindowStart)).With("window_end", ops.Ours(v.WindowEnd)).
				With("window_closed", ops.Ours(v.Closed)).With("sla_seconds", ops.Ours(v.SLA)).
				With("tolerance", ops.Ours(v.Tolerance)).With("planned", ops.Ours(v.Planned)).
				With("run", ops.Ours(v.Run)).With("within_sla", ops.Ours(v.Within)).
				With("late", ops.Ours(v.Late)).With("not_notified", ops.Ours(v.Never)).
				With("missed", ops.Object().With("k", ops.Ours(v.Missed.K)).With("n", ops.Ours(v.Missed.N)).
					With("lower", ops.Ours(v.Missed.Lower)).With("upper", ops.Ours(v.Missed.Upper))).
				With("median_seconds", ops.Ours(v.Median)).With("p90_seconds", ops.Ours(v.P90)))
		case p.PeerLog != nil:
			v := p.PeerLog
			evidence := ops.Object().With("peer", ops.Ours(v.Peer)).With("head_key", ops.Ours(v.Keys.KeyID)).
				With("at", ops.Ours(v.At)).With("held", ops.Ours(v.Held)).With("root", ops.Ours(v.Root)).
				With("heads", ops.Ours(v.Heads)).With("agreeing", ops.Ours(v.Agreeing)).
				With("disagree", ops.Ours(v.Disagree)).With("forks", ops.Ours(v.ForkCount)).
				With("last_received", ops.Ours(v.LastReceived)).With("last_records", ops.Ours(v.LastRecords)).
				With("full_batch", ops.Ours(v.FullBatch))
			if v.Last != nil {
				evidence.With("last_head", ops.Object().With("size", ops.Ours(v.Last.Size)).
					With("root", ops.Ours(v.Last.Root)))
			}
			row.With("evidence", evidence)
		case p.Coverage != nil:
			v := p.Coverage
			techniques := ops.ListOf(v.Techniques, func(t proof.TechniqueCoverage) *ops.Answer {
				return ops.Object().With("technique", ops.Ours(t.Technique)).
					With("verdict", ops.Ours(string(t.Verdict))).
					With("rules", ops.ListOf(t.Rules, ops.Outside)).
					With("positives", ops.Ours(t.Positives)).With("caught", ops.Ours(t.Caught)).
					With("quiet_only", ops.Ours(t.QuietOnly)).With("missed", ops.Ours(t.Missed)).
					With("benign", ops.Ours(t.Benign)).With("false_fires", ops.Ours(t.FalseFires)).
					With("recall_low", ops.Ours(t.RecallLow)).With("decayed", ops.Ours(t.Decayed))
			})
			unclaimed := ops.ListOf(v.Unclaimed, func(u proof.UnclaimedTechnique) *ops.Answer {
				return ops.Object().With("technique", ops.Ours(u.Technique)).
					With("positives", ops.Ours(u.Positives)).With("caught_by_other", ops.Ours(u.CaughtByOther))
			})
			dark := ops.ListOf(v.Dark, func(d proof.DarkRule) *ops.Answer {
				return ops.Object().With("rule", ops.Outside(d.Rule)).With("silent", ops.Ours(d.Silent)).
					With("missing", ops.ListOf(d.Missing, ops.Outside))
			})
			evidence := ops.Object().With("rules", ops.Ours(len(v.Rules))).
				With("entries", ops.Ours(v.Entries)).With("labelled", ops.Ours(v.Labelled)).
				With("benign", ops.Ours(v.Benign)).With("min_positives", ops.Ours(v.MinPositives)).
				With("min_benign", ops.Ours(v.MinBenign)).With("asked", ops.Ours(v.Asked)).
				With("unrecognised", ops.Ours(v.Unrecognised)).With("techniques", techniques).
				With("unclaimed", unclaimed).With("dark_count", ops.Ours(v.DarkCount)).With("dark", dark)
			if w := v.Telemetry; w != nil {
				evidence.With("telemetry", ops.Object().With("since", ops.Ours(w.Since)).
					With("until", ops.Ours(w.Until)).With("sources", ops.Ours(w.Sources)).
					With("silent", ops.Ours(w.Silent)).With("events", ops.Ours(w.Events)).
					With("capped", ops.Ours(w.Capped)).With("fields", ops.Ours(w.Fields)))
			}
			row.With("evidence", evidence)
		case p.Verdicts != nil:
			v := p.Verdicts
			count := func(k, n int) *ops.Answer { return ops.Object().With("k", ops.Ours(k)).With("n", ops.Ours(n)) }
			row.With("evidence", ops.Object().With("source", ops.Ours(v.Source)).
				With("labels", ops.Ours(v.Labels)).With("since", ops.Ours(v.Since)).With("until", ops.Ours(v.Until)).
				With("tolerance", ops.Ours(v.Tolerance)).
				With("false_closures", count(v.FalseClosures.K, v.FalseClosures.N).
					With("lower", ops.Ours(v.FalseClosures.Lower)).With("upper", ops.Ours(v.FalseClosures.Upper))).
				With("review_coverage", count(v.ReviewCoverage.K, v.ReviewCoverage.N)).
				With("delivered_before_disposition", count(v.DeliveredFirst.K, v.DeliveredFirst.N)).
				With("agreement", count(v.Agreement.K, v.Agreement.N)).
				With("escalations_closed", count(v.EscalationsClosed.K, v.EscalationsClosed.N)).
				With("abstentions", count(v.Abstentions.K, v.Abstentions.N)).
				With("consistency", count(v.Consistency.K, v.Consistency.N)))
		}
		return row, nil
	}
}

func keepProof(root string) func(ops.Call) (*ops.Answer, error) {
	return func(c ops.Call) (*ops.Answer, error) {
		id, st, err := proofstore.Keep(root, []byte(c.Args.Text("envelope")),
			[]byte(c.Args.Text("public_key")), c.Caller.Name(), proofstore.OriginHandedIn, c.Now)
		already := errors.Is(err, proofstore.ErrAlreadyKept)
		if err != nil && !already {
			return nil, &ops.Refusal{Reason: err.Error()}
		}
		return ops.Object().With("id", ops.Ours(id)).With("kind", ops.Ours(proofKind(st))).
			With("verdict", ops.Ours(string(st.Predicate.Verdict))).With("already_kept", ops.Ours(already)), nil
	}
}

// Ops is the proving ground's registry for the store at root: the reads, and
// keeping a proof.
func Ops(root string) *ops.Registry {
	r := ops.NewRegistry()
	addReads(r, Store(root))
	r.Add(keepOp(root))
	return r
}

// verifyOp checks a proof made anywhere against the public key that
// signed it, keeping nothing: what an agent in a pipeline, or a person
// handed a proof, asks before relying on it. The answer says whether the
// key is one this store trusts (internal/proofstore's signers), because a
// signature only says which key signed, never whose.
func verifyOp(src Source) ops.Op {
	return ops.Op{Name: "verify_proof",
		Summary: "check a signed proof against its public key, and whether this store trusts that key",
		Detail: "Keeps nothing. A proof that does not verify is refused, and one that does " +
			"is answered with its verdict, its claim and the signer this store trusts it as, if any.",
		Needs: auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read,
		Args: []ops.Arg{
			{Name: "envelope", Kind: ops.Document, Required: true, Positional: true, Max: proof.MaxEnvelope,
				About: "the signed proof (a DSSE envelope)"},
			{Name: "public_key", Kind: ops.Document, Required: true, Max: 64 << 10,
				About: "the public key that signed it"},
		},
		Keywords: []string{"verify", "proof", "signature", "trusted", "signer"},
		Run: func(c ops.Call) (*ops.Answer, error) {
			st, kid, err := proofstore.Check([]byte(c.Args.Text("envelope")), []byte(c.Args.Text("public_key")))
			if err != nil {
				return nil, &ops.Refusal{Reason: err.Error()}
			}
			trusted, err := src.Trusted()
			if err != nil {
				return nil, err
			}
			signer := trusted[kid]
			words := wordsFrom(st)
			return ops.Object().With("verdict", ops.Ours(string(st.Predicate.Verdict))).
				With("kind", ops.Ours(proofKind(st))).With("subject", words(st.Subject[0].Name)).
				With("claim", words(st.Predicate.Claim)).With("verified_at", ops.Ours(st.Predicate.VerifiedAt)).
				With("key_id", ops.Ours(kid)).With("signer", ops.Ours(signer)).
				With("trusted", ops.Ours(signer != "")), nil
		}}
}

// ReadOps is the proving ground's reads over src alone: what a recorded case
// can answer, with nothing to change.
func ReadOps(src Source) *ops.Registry {
	r := ops.NewRegistry()
	addReads(r, src)
	return r
}

func addReads(r *ops.Registry, src Source) {
	r.Add(ops.Op{Name: "list_proofs", CLI: "proof list",
		Summary: "the proofs kept here: what was proven, refuted or left inconclusive",
		Detail: "Newest first. Each says whose key signed it and whether it still " +
			"verifies; one that no longer does is listed as broken, never as what it now says.",
		Needs: auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read,
		Args: []ops.Arg{
			{Name: "kind", Kind: ops.Text, About: "only this kind: " + strings.Join(kindWords, ", ")},
			{Name: "limit", Kind: ops.Number, About: "how many to show, at most 500 (default 50)"},
		},
		Keywords: []string{"proof", "proofs", "verdict", "certificate", "calibration", "scorecard", "proven", "refuted"},
		Run:      listProofs(src)})
	r.Add(ops.Op{Name: "read_proof", CLI: "proof show",
		Summary: "one kept proof: its claim, checks, evidence and materials",
		Needs:   auth.ActView, Area: auth.AreaSecurity, Effect: ops.Read,
		Args: []ops.Arg{{Name: "id", Kind: ops.Text, Required: true, Positional: true,
			About: "the proof's id, as list_proofs gives it"}},
		Keywords: []string{"proof", "evidence", "checks", "claim"},
		Run:      readProof(src)})
	r.Add(verifyOp(src))
}

func keepOp(root string) ops.Op {
	return ops.Op{Name: "keep_proof", CLI: "proof keep",
		Summary: "keep a proof made elsewhere, after checking it against its public key",
		Needs:   auth.ActTriage, Area: auth.AreaSecurity, Effect: ops.Change, Audit: "proof.kept",
		Args: []ops.Arg{
			{Name: "envelope", Kind: ops.Document, Required: true, Positional: true, Max: proof.MaxEnvelope,
				About: "the signed proof (a DSSE envelope)"},
			{Name: "public_key", Kind: ops.Document, Required: true, Max: 64 << 10,
				About: "the public key that signed it"},
		},
		Run: keepProof(root)}
}

// boundAnswer is an exact bound with the counts it rests on.
func boundAnswer(b proof.Bound) *ops.Answer {
	return ops.Object().With("k", ops.Ours(b.K)).With("n", ops.Ours(b.N)).
		With("lower", ops.Ours(b.Lower)).With("upper", ops.Ours(b.Upper))
}

// rateAnswer is a rate with the counts it rests on.
func rateAnswer(r proof.Rate) *ops.Answer {
	return ops.Object().With("k", ops.Ours(r.K)).With("n", ops.Ours(r.N)).
		With("low", ops.Ours(r.Low)).With("high", ops.Ours(r.High))
}
