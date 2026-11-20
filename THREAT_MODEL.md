# Threat model

This file says what Aertun defends, against whom, and what it does not
defend. The properties a report can show to be false are listed in
[SECURITY.md](SECURITY.md); this is the reasoning behind them.

## What is protected

1. **The evidence and the verdicts.** This covers:
   - the audit log;
   - the event store;
   - signed proofs;
   - evidence-protocol receipts and the receipt log;
   - the conclusions drawn from all of them.

   The worst outcome is a signed statement that verifies while saying
   something its evidence does not support.
2. **Who may do what.** The policy, the tokens and the sessions. The worst
   outcome is an action taken by someone, or something, not allowed to
   take it.
3. **Secrets.** Signing seeds, connector credentials, and personal data in
   events.

## Who it is defended against

- **An AI agent steered by what it reads.** This is any agent connected
  over MCP, and Aertun's own analyst model. Every frontier model can be
  steered by text placed in its input. So an agent is assumed to do
  whatever the last attacker-written text told it, within what its
  credential allows.
- **An agent that misreports itself.** This may be through compromise,
  through a bug, or by design. Its own telemetry is its word, and it is
  never the only evidence for a conclusion about it.
- **A person with a valid account acting beyond it.** That includes an
  administrator acting alone where two people are required.
- **An attacker on the network** between Aertun and the platforms it
  reads from, between a party and the receipt log, or between Aertun and a
  verifier.
- **A forger after the fact.** This is someone who obtains a signing key
  later, or who breaks Ed25519 or ML-DSA-65 later, and wants to forge
  evidence about the past.
- **A party to reconciliation that lies.** The agent, its gateway, the
  target server, or a vendor reporting on itself.

## How

- **No conclusion rests on one party's account.**
  - Agent reconciliation sets the agent's spans against the interface's
    record and the gateway's log.
  - A revocation proof counts only the sources shown to have kept
    listening.
  - An evidence-protocol reconciliation expects every named party. A party
    that reported nothing is a gap, not an absence of evidence.
  - A reconciliation is checked by doing it again, not by trusting who
    signed it.
- **An agent reads and proposes.** The agent interface has no operation
  that decides, approves, grants, signs, or reaches another platform. Each
  call is recorded under the agent's registered name, and, once a receipt
  log exists, receipted from the server's side.
- **Untrusted text stays data.** The analyst's plan is fixed in code
  before anything is read. Counts are kept apart from quoted text, the
  answer is one word from a closed set, and a closing answer is asked again
  without the attacker's text.
- **Two algorithms, both required.** Everything signed carries Ed25519 and
  ML-DSA-65:
  - A proof carries both signatures.
  - A receipt log issues one receipt in each algorithm.
  - Audit-log heads are signed with both and anchored in Bitcoin through
    OpenTimestamps.

  A forger who breaks one algorithm still lacks the other. A forger who
  steals a key after an anchor cannot move evidence to before it.
- **Append-only, verifiably.** The audit log is a hash chain with a Merkle
  tree over it, and can be written by a separate account. The receipt log
  never rewrites a record, and refuses a file that shrank under it. Merkle
  proofs show one entry without showing the rest.
- **Strict readers of signed formats.**
  - The CBOR and COSE readers refuse duplicate keys, indefinite lengths,
    unknown critical headers, trailing bytes, and nesting past a fixed
    depth.
  - The JSON canonicaliser refuses duplicate members and lone surrogates.
  - Inputs are read with size bounds.
  - Signatures are checked over the bytes as received.
- **No dependencies.** Aertun is the Go standard library only, so a
  compromised upstream package cannot reach it. Releases carry SLSA build
  provenance.

## What it does not defend

- **A compromised host running Aertun.** Root on that machine can read
  signing seeds and write whatever it likes. The defences are separation
  and detection after the fact, not prevention:
  - the separate log account;
  - anchors;
  - receipts already held by other parties.
- **Parties that collude.** If the agent, its gateway and the target all
  lie consistently, reconciliation agrees. Completeness is only as strong
  as the independence of the parties named.
- **What the action digest reveals.** The arguments are hidden only as well
  as they are hard to guess. Share receipts with those entitled to an
  action's arguments.
- **Confidentiality of the receipt log.** Entries carry tool names, actors
  and timing. The log is for parties to an action and their auditors, not
  for publication.
- **Correctness of the model.** The design limits what a wrong or steered
  model can do. It does not make the model right.
- **Denial of service** by very large or very many requests, beyond the
  size bounds that keep a single input from exhausting memory.
- **The tree size in an RFC 9942 receipt.** It is not signed. Inclusion
  rests on the signed root, and a reader that relies on the size compares
  it with a signed head.
