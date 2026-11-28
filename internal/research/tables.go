// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

// The tables, each a row type and the definition the datasheet carries.
// A row has no omitempty field and no field the definition does not
// describe: Add refuses both.

// EventRow is one event in the window, by its times and kind alone.
type EventRow struct {
	Source      string `json:"source"`
	Class       uint32 `json:"class"`
	Activity    uint8  `json:"activity"`
	Disposition uint8  `json:"disposition"`
	Severity    uint8  `json:"severity"`
	Time        string `json:"time"`
	Received    string `json:"received"`
	LatenessMS  int64  `json:"lateness_ms"`
	Actor       string `json:"actor"`
}

// Events defines the events table.
var Events = Def{
	Name: "events",
	Description: "Every event the store received in the window: when it happened, when it " +
		"arrived, and what kind of event it was. What it said, where it came from on the " +
		"network and whom it was about are left out; the actor is a pseudonym.",
	Source: "the event store (spool), by arrival time",
	Columns: []Column{
		{"source", "string", "", "the platform or feed the event came from, as this deployment names it"},
		{"class", "integer", "", "OCSF class_uid"},
		{"activity", "integer", "", "OCSF activity_id within the class"},
		{"disposition", "integer", "", "OCSF disposition_id: what was done about it"},
		{"severity", "integer", "", "OCSF severity_id"},
		{"time", "time", "", "when the source says the event happened"},
		{"received", "time", "", "when this deployment stored it"},
		{"lateness_ms", "integer", "ms", "received minus time; negative when the source's clock runs ahead"},
		{"actor", "string", "", "pseudonym of who acted, empty when the event names nobody"},
	},
}

// FindingRow is one finding in the register.
type FindingRow struct {
	Finding  string `json:"finding"`
	Kind     string `json:"kind"`
	Rule     string `json:"rule"`
	Severity uint8  `json:"severity"`
	State    string `json:"state"`
	Trial    bool   `json:"trial"`
	First    string `json:"first"`
	Last     string `json:"last"`
	Seen     int    `json:"seen"`
	Evidence int    `json:"evidence"`
	Entity   string `json:"entity"`
}

// Findings defines the findings table.
var Findings = Def{
	Name: "findings",
	Description: "Every finding in the register whose evidence reaches into the window, with " +
		"its rule, severity, state and the times of its first and last evidence. Titles, " +
		"evidence text and decisions' reasons are left out.",
	Source: "the finding register (findings.json)",
	Columns: []Column{
		{"finding", "string", "", "pseudonym of the finding's id, the same for one finding across tables"},
		{"kind", "string", "", "what raised it: detection, vulnerability, control, vendor or code"},
		{"rule", "string", "", "the detection rule that raised it, by its id as the deployment wrote it; a pseudonym for anything else (an indicator's digest, a vendor's or a check's name), which could name what was touched"},
		{"severity", "integer", "", "OCSF severity_id"},
		{"state", "string", "", "open, triaged, accepted, fixed, stale, false-positive or benign, as decided when the export was made"},
		{"trial", "boolean", "", "raised by a rule on trial, kept from the automations"},
		{"first", "time", "", "the event time of its first evidence"},
		{"last", "time", "", "the event time of its latest evidence"},
		{"seen", "integer", "", "how many times it was raised"},
		{"evidence", "integer", "", "how many pieces of evidence it keeps"},
		{"entity", "string", "", "pseudonym of whom or what it is about"},
	},
}

// DetectionRow is one detection pass.
type DetectionRow struct {
	At            string `json:"at"`
	By            string `json:"by"`
	Outcome       string `json:"outcome"`
	Rules         int    `json:"rules"`
	Events        int    `json:"events"`
	Matches       int    `json:"matches"`
	Opened        int    `json:"opened"`
	Suppressed    int    `json:"suppressed"`
	Off           int    `json:"off"`
	Correlated    int    `json:"correlated"`
	IndicatorHits int    `json:"indicator_hits"`
}

// Detections defines the detection passes table.
var Detections = Def{
	Name: "detections",
	Description: "Every detection pass in the window, from the audit log: when the rules ran, " +
		"over how many new events, and what they matched and raised. A finding records the " +
		"time of its evidence, not of the pass that raised it; this is when passes ran.",
	Source: "the audit log's detect.run entries",
	Columns: []Column{
		{"at", "time", "", "when the pass was recorded"},
		{"by", "string", "", "the kind of principal that ran it: human, service or ai"},
		{"outcome", "string", "", "success, or failure when part of the pass's input could not be stored"},
		{"rules", "integer", "", "rules run"},
		{"events", "integer", "", "new events read"},
		{"matches", "integer", "", "rule matches"},
		{"opened", "integer", "", "findings it opened"},
		{"suppressed", "integer", "", "matches hidden by suppressions"},
		{"off", "integer", "", "rules switched off"},
		{"correlated", "integer", "", "correlation windows that met their condition"},
		{"indicator_hits", "integer", "", "events that carried a held indicator"},
	},
}

// AuditRow is one audit log entry.
type AuditRow struct {
	At        string `json:"at"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
	Kind      string `json:"kind"`
	Verified  bool   `json:"verified"`
	Principal string `json:"principal"`
}

// Audit defines the audit log table.
var Audit = Def{
	Name: "audit",
	Description: "Every audit log entry in the window, by its action and outcome. Resources " +
		"and details are left out, and the principal is pseudonymised again under this " +
		"export's key. Who holds the deployment's own log can still match rows to it by time.",
	Source: "the audit log (audit.jsonl)",
	Columns: []Column{
		{"at", "time", "", "when it was recorded"},
		{"action", "string", "", "what was done, by the audit log's own name for the action; a pseudonym for a refused command's words, which can carry a path"},
		{"outcome", "string", "", "success, failure or denied"},
		{"kind", "string", "", "the principal's kind: human, service, ai or unknown"},
		{"verified", "boolean", "", "whether the principal was authenticated"},
		{"principal", "string", "", "pseudonym of who did it"},
	},
}

// HeadRow is one saved audit log head.
type HeadRow struct {
	Size int    `json:"size"`
	At   string `json:"at"`
}

// Heads defines the audit log heads table.
var Heads = Def{
	Name:        "heads",
	Description: "Every saved head of the audit log in the window: how large the log was, and when. The root is left out: it is published, and would name the deployment.",
	Source:      "log-heads.json",
	Columns: []Column{
		{"size", "integer", "entries", "how many entries the log had"},
		{"at", "time", "", "when the head was taken, by this deployment's clock"},
	},
}

// AnchorRow is one anchor of a head in Bitcoin, through OpenTimestamps.
type AnchorRow struct {
	Calendar    string  `json:"calendar"`
	State       string  `json:"state"`
	Height      uint64  `json:"height"`
	SubmittedAt string  `json:"submitted_at"`
	UpgradedAt  string  `json:"upgraded_at"`
	ConfirmSecs float64 `json:"confirm_secs"`
}

// Anchors defines the anchors table.
var Anchors = Def{
	Name: "anchors",
	Description: "Every anchor of an audit log head through OpenTimestamps submitted in the " +
		"window. The time to confirm is measured to the poll that saw the attestation, not " +
		"to the block, and overstates the latency by up to the polling interval. The anchored " +
		"digest is left out: it is the published head, and would name the deployment.",
	Source: "anchors.json",
	Columns: []Column{
		{"calendar", "string", "", "the public OpenTimestamps calendar it was submitted to"},
		{"state", "string", "", "pending, anchored in a block, or unknown"},
		{"height", "integer", "", "the Bitcoin block height, 0 while pending"},
		{"submitted_at", "time", "", "when it was submitted"},
		{"upgraded_at", "time", "", "when a poll found it confirmed"},
		{"confirm_secs", "number", "s", "upgraded_at minus submitted_at, 0 while pending"},
	},
}

// ReceiptRow is one action receipt in the transparency log.
type ReceiptRow struct {
	Alg     string `json:"alg"`
	Bytes   int    `json:"bytes"`
	Issuer  string `json:"issuer"`
	Vantage string `json:"vantage"`
	At      string `json:"at"`
	Outcome string `json:"outcome"`
	HasSeq  bool   `json:"has_seq"`
}

// Receipts defines the action receipts table.
var Receipts = Def{
	Name: "receipts",
	Description: "Every action receipt in this deployment's transparency log whose action, by " +
		"the issuer's own clock, falls in the window: its algorithm and size, who issued it " +
		"from which vantage, and the outcome it reports. The action's target, tool and " +
		"arguments, and the issuer's sequence numbers, are left out.",
	Source: "the receipt log (receipts/entries)",
	Columns: []Column{
		{"alg", "string", "", "the statement's signature algorithm: Ed25519, EdDSA or ML-DSA-65"},
		{"bytes", "integer", "bytes", "the signed statement's size as registered"},
		{"issuer", "string", "", "pseudonym of the issuer"},
		{"vantage", "string", "", "where the issuer saw the action: agent, gateway, target or sandbox"},
		{"at", "time", "", "when the issuer says the action happened"},
		{"outcome", "string", "", "the outcome the receipt reports"},
		{"has_seq", "boolean", "", "whether the issuer numbered its receipts"},
	},
}

// ReconciliationRow is one reconciliation receipt in the transparency log.
type ReconciliationRow struct {
	Alg         string `json:"alg"`
	Bytes       int    `json:"bytes"`
	Issuer      string `json:"issuer"`
	IssuedAt    string `json:"issued_at"`
	From        string `json:"from"`
	To          string `json:"to"`
	Expected    int    `json:"expected"`
	Verdict     string `json:"verdict"`
	Receipts    int    `json:"receipts"`
	Actions     int    `json:"actions"`
	Complete    int    `json:"complete"`
	Gaps        int    `json:"gaps"`
	SeqGaps     int    `json:"seq_gaps"`
	ActorSplits int    `json:"actor_splits"`
}

// Reconciliations defines the reconciliations table.
var Reconciliations = Def{
	Name: "reconciliations",
	Description: "Every reconciliation receipt in the log issued in the window: its verdict and the " +
		"disagreements it counted by kind. The counts are as the receipt states them; a " +
		"receipt is checked by recomputing it from its inputs, which `aertun receipt verify` does.",
	Source: "the receipt log (receipts/entries)",
	Columns: []Column{
		{"alg", "string", "", "the statement's signature algorithm: Ed25519, EdDSA or ML-DSA-65"},
		{"bytes", "integer", "bytes", "the signed statement's size"},
		{"issuer", "string", "", "pseudonym of the reconciler"},
		{"issued_at", "time", "", "when it was issued"},
		{"from", "time", "", "the start of the window it reconciled"},
		{"to", "time", "", "the end of that window"},
		{"expected", "integer", "", "how many parties were expected to report each action"},
		{"verdict", "string", "", "agree, disagree or inconclusive"},
		{"receipts", "integer", "", "receipts read"},
		{"actions", "integer", "", "distinct actions"},
		{"complete", "integer", "", "actions every expected party reported"},
		{"gaps", "integer", "", "actions an expected party never reported"},
		{"seq_gaps", "integer", "", "issuers with missing or repeated sequence numbers"},
		{"actor_splits", "integer", "", "actions the parties named different actors for"},
	},
}

// BenignRow is one benign session's provenance.
type BenignRow struct {
	Session    string `json:"session"`
	Class      string `json:"class"`
	State      string `json:"state"`
	Events     int    `json:"events"`
	Captured   string `json:"captured"`
	Expires    string `json:"expires"`
	Renewals   int    `json:"renewals"`
	Alone      bool   `json:"alone"`
	VouchedBy  string `json:"vouched_by"`
	ApprovedBy string `json:"approved_by"`
	Fields     int    `json:"fields"`
	Dropped    int    `json:"dropped"`
	Raw        int    `json:"raw"`
	Reduced    bool   `json:"reduced"`
	KeyID      string `json:"key_id"`
}

// Benign defines the benign sessions table.
var Benign = Def{
	Name: "benign",
	Description: "Every benign session captured here: who vouched for and approved it, when " +
		"it expires, how it was sanitised, and which sessions share a pseudonym key. A " +
		"session's approvers are already pseudonyms in the store, so the same person can " +
		"have one pseudonym here and another in the audit table.",
	Source: "benign/sessions",
	Columns: []Column{
		{"session", "string", "", "pseudonym of the session's name"},
		{"class", "string", "", "what kind of benign activity it is"},
		{"state", "string", "", "pending, approved or revoked"},
		{"events", "integer", "", "events in the session"},
		{"captured", "time", "", "when it was captured"},
		{"expires", "time", "", "when its approval expires"},
		{"renewals", "integer", "", "times its approval was renewed"},
		{"alone", "boolean", "", "approved by one administrator where no second exists, and recorded so"},
		{"vouched_by", "string", "", "pseudonym of who vouched for it"},
		{"approved_by", "string", "", "pseudonym of who approved it"},
		{"fields", "integer", "", "fields kept for the rules"},
		{"dropped", "integer", "", "fields dropped by sanitising"},
		{"raw", "integer", "", "fields kept unsanitised at an operator's recorded request"},
		{"reduced", "boolean", "", "sanitising changed what a rule does, and this was accepted"},
		{"key_id", "string", "", "pseudonym of the fingerprint of the key the session was pseudonymised under: equal for sessions under one key, matching no bundle the deployment shares"},
	},
}

// OutcomeRow is one measured rate from a signed wind tunnel scorecard.
type OutcomeRow struct {
	Scorecard  string  `json:"scorecard"`
	Measure    string  `json:"measure"`
	K          int     `json:"k"`
	N          int     `json:"n"`
	Rate       float64 `json:"rate"`
	Method     string  `json:"method"`
	Confidence float64 `json:"confidence"`
	Low        float64 `json:"low"`
	High       float64 `json:"high"`
}

// Outcomes defines the outcomes table.
var Outcomes = Def{
	Name: "outcomes",
	Description: "Every rate a signed wind tunnel scorecard reports, with the counts behind " +
		"it and its interval: misses, evasion under mutation, misses under each pipeline " +
		"fault, and false positives on benign sessions.",
	Source: "wind tunnel scorecards given to the export, each verified against its key",
	Columns: []Column{
		{"scorecard", "string", "", "the SHA-256 of the scorecard file, as listed among the inputs"},
		{"measure", "string", "", "where in the scorecard the rate is, as a path"},
		{"k", "integer", "", "the count: misses, evasions or firings"},
		{"n", "integer", "", "the trials it is out of"},
		{"rate", "number", "", "k over n"},
		{"method", "string", "", "the interval's method"},
		{"confidence", "number", "", "the interval's confidence level"},
		{"low", "number", "", "the interval's lower bound"},
		{"high", "number", "", "the interval's upper bound"},
	},
}

// MeasurementRow is one timing measured when the export was made.
type MeasurementRow struct {
	Measure        string  `json:"measure"`
	Alg            string  `json:"alg"`
	MessageBytes   int     `json:"message_bytes"`
	SignatureBytes int     `json:"signature_bytes"`
	PublicKeyBytes int     `json:"public_key_bytes"`
	Iterations     int     `json:"iterations"`
	MedianUS       float64 `json:"median_us"`
	P95US          float64 `json:"p95_us"`
}

// Measurements defines the measurements table.
var Measurements = Def{
	Name: "measurements",
	Description: "Timings measured on the machine that made the export, when it made it: " +
		"signing and verifying in each algorithm, and appending to a hash-chained audit " +
		"log with its fsync, in a scratch directory. They describe that machine; the " +
		"datasheet names its platform.",
	Source: "measured at export time",
	Columns: []Column{
		{"measure", "string", "", "sign, verify or audit-append"},
		{"alg", "string", "", "the algorithm, empty for audit-append"},
		{"message_bytes", "integer", "bytes", "the size of what was signed or appended"},
		{"signature_bytes", "integer", "bytes", "the signature's size, 0 for audit-append"},
		{"public_key_bytes", "integer", "bytes", "the public key's size, 0 for audit-append"},
		{"iterations", "integer", "", "timed repetitions, after a warm-up"},
		{"median_us", "number", "µs", "the median time"},
		{"p95_us", "number", "µs", "the 95th percentile time"},
	},
}
