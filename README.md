<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/aertun-wordmark-dark.svg">
    <img src="docs/brand/aertun-wordmark-light.svg" alt="Aertun" width="300">
  </picture>
</h1>

<p align="center"><strong>The proving ground for AI security work.</strong></p>

<p align="center">
  Aertun checks what AI defenders produce — detection rules, triage verdicts,
  investigations, "not affected" statements — against evidence the AI did not
  write, and signs the result in open formats anybody can verify.
  Self-hosted, one binary, no dependencies.
</p>

<p align="center">
  <a href="https://github.com/aertun/aertun/actions/workflows/ci.yml"><img src="https://github.com/aertun/aertun/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="licence: Apache-2.0"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="dependencies: 0"></a>
  <a href="https://aertun.github.io/"><img src="https://img.shields.io/badge/manual-aertun.github.io-informational" alt="manual"></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#why">Why</a> ·
  <a href="#what-it-proves">What it proves</a> ·
  <a href="#the-wind-tunnel">Wind tunnel</a> ·
  <a href="#the-evidence-a-security-operations-core">The evidence</a> ·
  <a href="#who-may-do-what">Who may do what</a> ·
  <a href="#measured">Measured</a> ·
  <a href="#install">Install</a> ·
  <a href="https://aertun.github.io/">Manual</a> ·
  <a href="https://aertun.github.io/#tour">Video tour</a>
</p>

<p align="center">
  <img src="docs/screens/proofs.webp" alt="The Proofs screen: the kept proofs counted by verdict, then each with its claim, its kind, who kept it and whether its signing key is trusted here" width="900">
</p>

---

One static binary written in Go, using the standard library only, with no
third-party dependencies. The few third-party assets it carries (a typeface,
icons, public data sets) are credited in [NOTICE](NOTICE).

## Quickstart

Download the binary for your platform from the
[latest release](https://github.com/aertun/aertun/releases/latest), check it,
and run it — there is nothing else to install:

```bash
curl -LO https://github.com/aertun/aertun/releases/download/v0.1.0/aertun-linux-amd64
curl -LO https://github.com/aertun/aertun/releases/download/v0.1.0/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS && chmod +x aertun-linux-amd64

./aertun-linux-amd64 init --owner you@example.com   # a store, its Owner, and the link that adds your passkey
./aertun-linux-amd64 serve                          # the console, on http://localhost:8080
```

Other platforms, the container image and building from source are under
[Install](#install).

Open the link `init` printed and add a passkey, and you are signed in as the
store's Owner. There is no default password and no default account, and
everybody signs in with two factors.

The first screen is **Today**: what is waiting for you to decide, then what is
wrong in the parts of the estate you work in. **Get started** walks the four
things that make it useful: bring events in, decide what counts as wrong, know
the estate, and decide who else may do what.

## Why

Finding weaknesses, attacking and triaging have all been automated. Deciding
which of those outputs to believe has not. Anthropic, on vulnerabilities its
models found: "Now it's limited by how quickly we can verify, disclose, and
patch the large numbers of vulnerabilities found by AI"
([Project Glasswing, May 2026](https://www.anthropic.com/research/glasswing-initial-update)).
The accuracy of AI security-operations products is mostly reported by whoever
sells them, and where one is measured in the open the result is sobering: a
vendor's own benchmark, replaying real telemetry to 32 models, has none
clearing its bar of more than 50% recall on every ATT&CK tactic
([Simbian](https://simbian.ai/research/cyber-defense-benchmark)).

Aertun is the check that does not trust the author. It holds a piece of AI
security work to evidence its author could not have written, says **proven**,
**refuted** or **inconclusive**, and signs that — whichever it is.

## What it proves

A proof is a claim about security work, checked by a program, and signed
whatever the verdict: **proven**; **refuted**, naming what failed; or
**inconclusive** — nothing failed, but nothing could have. It is an
[in-toto](https://in-toto.io/) statement in a
[DSSE](https://github.com/secure-systems-lab/dsse) envelope, signed with
Ed25519 and ML-DSA-65.

| Proof | The claim | Held against | Command |
|---|---|---|---|
| **Detection** | a rule — usually one a model drafted — fires on what it should and on nothing else | its own fixtures and a labelled corpus its author did not write | `aertun proof detection` |
| **Analyst** | your AI analyst rarely closes a real finding, and text planted in a log cannot steer it | the labelled corpus that ships (48 cases), each asked several times, with instructions planted where a log's text goes | `aertun proof analyst` |
| **Calibration** | above this confidence, the analyst's closing suggestions are wrong at most this often | the findings verified people have ruled | `aertun analyst calibrate` |
| **Vendor verdicts** | another product's AI closed few alerts that people found real | the decisions verified people made here, on verdicts given before them | `aertun verdict prove` |
| **Blind adjudication** | the same, without the bias of only re-examining what looked wrong | a random sample committed to the audit log before anybody saw it, judged without knowing who closed what | `aertun adjudicate prove` |
| **Claim card** | a vendor's claim, tested as it was made | the metric, threshold and period registered before the data arrived | `aertun claim test` |
| **Reconciliation** | an agent did what it says it did | the calls its interface answered, read from the signed log, the connections its machine made, and, when declared, a model gateway's record of its key (LiteLLM) and what the systems it acts on recorded of its identity (GitHub, Okta, CloudTrail) | `aertun agent reconcile` |
| **Not affected** | a VEX document's `not_affected` statements hold | the asset's bill of materials, advisories and reachability analysis | `aertun vuln prove-vex` |
| **Cited evidence** | every claim in an AI's investigation report is true | the event store, with each citation run again | `aertun proof evidence` |
| **Revocation** | after an agent was killed, or an identity revoked in another system, nothing acted as it | this program's signed log, the agent's own telemetry, and every collected source that had seen it act — each shown to have kept delivering events | `aertun proof revocation` |
| **Clock** | an incident's awareness, major or material decision was made when its record says, and every reporting deadline it started was met | the signed audit log, the log's Bitcoin anchors — each held to its block's header — and the deadlines of the regimes the incident is under | `aertun incident prove` |
| **Breach scope** | a supplier's disclosure of its own breach holds: no indicator outside the window it gave, and none inside it when it said you were not affected | your own event store, searched in the window and a margin either side, with whether the store holds each period whole | `aertun vendor check-breach` |
| **VEX record** | over a period, an issuer's `not_affected` statements were contradicted at most this often | the not-affected proofs kept here about that issuer and signed by a key this store trusts, each verified again as it is read; uncheckable statements counted and never in the rate | `aertun vuln vex-record` |
| **Chain posture** | a protocol's multisig thresholds, timelock delays and proxy admins are what it declares | the chain itself, read over JSON-RPC at one block named by its hash | `aertun chain posture` |
| **Sealed alert** | this alert existed by then — a monitor saw it first | the audit log, verified, holding the alert's digest in a batch it sealed (`aertun alert seal`), under a log head anchored in Bitcoin through OpenTimestamps, in a block whose header was checked | `aertun proof sealed` |
| **MDR** | a managed detection provider, or an AI SOC, notifies within its SLA on all but this share of attacks | emulations run on your estate at random times from a plan whose digest the audit log committed before any ran, each run and notification recorded by a verified person or joined from the provider's alerts | `aertun mdr prove` |
| **Continuity** | no package in a bill lost, from the release before it, its provenance, trusted publishing, source, publisher or install-script-free state, and none was withdrawn or yanked | npm, PyPI and the Go module proxy, read for the release the bill names and the one before it; each attestation held to the artifact by digest | `aertun vuln continuity` |
| **Coverage** | each ATT&CK technique the rules claim is caught wherever it appears, without firing on benign events, and still with the fields the sources send today | corpus entries labelled with the technique by what produced them (an Atomic Red Team run, a red team's plan), entries labelled benign, and the field names each source sent lately; exported as an ATT&CK Navigator layer, with no score | `aertun proof coverage` |
| **Peer log** | another site's audit log is complete up to a time, and the site has not signed a second history | the site's records as its signed stream delivered them, every tree head it signed with its own keys, and this deployment's log of any head that contradicted them | `aertun inbound prove` |

In CI, the action runs any of these and fails the job unless the proof is
proven:

```yaml
- uses: Aertun/Aertun@v0.2.0
  with:
    args: |
      proof
      verify
      draft.proof.json
      --key
      release.pub.json
```

On Kubernetes, `deploy/kubernetes/aertun.yaml` or the Helm chart in
`deploy/helm/aertun` (see `deploy/README.md`).

A proven proof is also a verification result a policy engine reads:
`aertun proof svr ID --key F` writes the in-toto Simple Verification Result
for it, with one property to gate on, such as `AERTUN_DETECTION_PROVEN`.

A detection rule as a model drafted it, held to five labelled events it did
not write:

```console
$ aertun proof detection --rule mfa-reset.draft.json --corpus mfa-corpus.jsonl --key content/release.key --out draft.proof.json
REFUTED: mfa-reset.draft.json
  Rule "okta.mfa-reset" fires on every corpus entry labelled as its own and on nothing else it reads.
  pass  valid    it names its sources, its condition is well formed, and its fixtures are usable events
  pass  fixtures 2 of 2 hold
  FAIL  corpus   caught 2 of 2 labelled as this rule; quiet on 1 of 3 other entries from sources it reads
        - fired on: a new starter enrolled their first factor
        - fired on: a person replaced a lost phone themselves
  evidence: recall ≥ 0.34 over 2, specificity ≥ 0.06 over 3 (95% Wilson lower bounds)
the verdict is refuted, and only proven passes
```

The rule's own fixtures agreed with it; the corpus did not. Every command in
the table exits non-zero unless the verdict is proven, which makes each one a
gate for a pipeline, and the numbers are bounds rather than rates — exact
Clopper–Pearson or Wilson — so a proof over two examples reads as the weak
thing it is.

**What a proof will not do.** Nothing the author wrote reaches a proof except
identifiers and numbers that passed a strict parser: a rule's name, a
vendor's reasoning, a report's prose are never copied in, so a proof cannot
carry somebody's instructions to whoever reads it. A proof that rests on a
rate needs a minimum of evidence before it says proven — thirty answers,
closures or sampled items. Every proof states what it did not cover beside
what it did, and none decides anything: no proof closes a finding.

<p align="center">
  <img src="docs/screens/proof-triage.webp" alt="A refuted analyst proof: its claim, its three checks with the one that failed, and the evidence in numbers" width="900">
</p>

**Checking one without this program.** Both signatures are over DSSE's
pre-authentication encoding of the payload. The Ed25519 one is plain DSSE, so
in-toto and Sigstore tooling reads it; the ML-DSA-65 one is FIPS 204 with the
context string `aertun/proof/v1`.
[scripts/verifyproof/verify.py](scripts/verifyproof/verify.py) checks both
with the Python `cryptography` package and the `openssl` command and shares no
code with Aertun. `aertun proof verify --key KEY --subject FILE PROOF` also
checks that the proof is about the file in your hand.

**Whose proof it is.** A signature says which key signed, never whose. A proof
counts as this organisation's only when its key is one the store trusts
(`aertun proof signers`), added by one administrator and approved by another.
Kept proofs are verified again every time they are read, so one edited
afterwards shows as no longer verifying.

**The same on every face.** The proving ground is the console's first section,
the `aertun proof`, `claim`, `adjudicate` and `verdict` commands, and the
agent interface's `list_proofs`, `read_proof`, `verify_proof` and
`list_claims` — one set of operations declared once, each asking whether the
caller may. Every value an operation answers says whether somebody outside
Aertun could have written it; the console tags those "written outside".

<p align="center">
  <img src="docs/screens/review.webp" alt="Blind adjudication: one sampled closure shown with its evidence and nothing that says who closed it" width="900">
</p>

## The wind tunnel

`aertun windtunnel run --sigma DIR` replays scripted malicious-agent
sessions — an injection through an issue, an MCP server's rug-pull, a
read-then-exfiltrate chain, a slopsquatted install, a runaway cost loop, a
blind window in the recorder — through a recorded telemetry stream in a
scratch store, and measures whether your own Sigma rules caught them. Each
scenario is data, never code, and ships with a benign twin that must raise
nothing. The scorecard names what ran before how it went (scenario digests,
the stream's digest, your rules' digest and what the importer refused), and
reports the miss rate first, as k of n with Wilson bounds. `windtunnel diff`
is the gate between two runs.

`--mutate N` replays N respellings of each session as well: the URLs,
tool-call paths and shell command lines an attacker types, rewritten by
equivalences their consumer applies (RFC 9110 URL normalisation, POSIX
pathname resolution, POSIX shell quoting) — never letter case alone, and
never a field the attacker does not spell.

Run without `--sigma`, it scores Aertun's own rule pack instead. The six
scenarios that ship were written beside those rules, so that result is
self-graded — a regression test of the pack, not an independent
measurement — and every screen and document that shows it says so. The
scorecard's digest covers its RFC 8785 canonical form; it is signed only in
CI, and `aertun windtunnel verify` checks a signed card offline.

## The evidence: a security-operations core

A proof is only as good as the evidence it is held to, so Aertun keeps that
evidence itself.

| | |
|---|---|
| **Collect** | Ten connectors that read other tools with sealed credentials, twenty log sources mapped to one event shape, scheduled collection, files, and feeds other systems push to: an identity provider's security events (SSF, CAEP, RISC), Okta event hooks, signed webhooks, GenAI agent telemetry over OTLP, and another deployment's signed audit stream. Every event is kept, append-only, before anything reads it. |
| **Detect** | Rules written here or imported as Sigma, each with fixtures that must match and must not, and MITRE ATT&CK technique IDs. A new rule runs in a trial ring that records what it would raise until its record earns it the queue. Correlations across rules and platforms, suppressions that end, and indicators imported from STIX 2.1 bundles or plain lists. |
| **Decide** | One queue of findings, ranked by risk, with every decision kept and replayable. An AI analyst writes a first pass as a suggestion a person agrees with or not; it has no way to record a decision itself. Hunting stacks any field of the stored events by rarity. |
| **Respond** | Cases and incidents with the notification clocks each law starts (GDPR, NIS2, DORA, the Cyber Resilience Act, SEC, CIRCIA, HIPAA), playbooks, and actions on other platforms asked for by one person and approved by another. Automations that watch, ask, or act, within limits. |
| **Expose** | Vulnerabilities ranked with CISA KEV and EPSS, decided with SSVC and published as OpenVEX; dependency scanning from CycloneDX and SPDX 2.x (JSON) bills of materials against OSV; code-scanning results from SARIF; workforce, device and vendor risk; access reviews. |

<p align="center">
  <img src="docs/screens/findings.webp" alt="The findings queue, ranked by risk, each with why it ranks where it does" width="900">
</p>

## AI that cannot be talked into anything

A security tool that puts a language model in front of log data hands the
model text written by attackers. Aertun is built so that the worst an AI can
do is be wrong in a suggestion:

- **The analyst's plan is fixed in code before anything untrusted is read.**
  Nothing a log line says can add a step (`aertun analyst plan` prints it).
- **Counts and quoted text are kept apart.** The model is given numbers and
  closed words the program worked out, and, separately and marked as such,
  the text somebody else wrote.
- **The answer is one word from a closed set, with a confidence.** Below the
  threshold it is not shown. The reason a person reads is assembled from the
  counts, never from what the model wrote.
- **A closing answer is asked again without the attacker's text**, and
  withheld from the person if it changes.
- **The threshold can be measured rather than declared** (`aertun analyst
  calibrate`), and the analyst itself proven (`aertun proof analyst`) on the
  model actually configured.
- **A privacy guard sits in front of every model call.** Personal data and
  credentials are masked before the prompt leaves and restored in the answer.
- **It works with any OpenAI-compatible endpoint**, hosted or local
  (`AERTUN_MODEL_URL`, `AERTUN_MODEL_KEY`, `AERTUN_MODEL`), and with none: the
  model is an aid, never a dependency.

AI agents reach Aertun through its **MCP server**: twelve operations behind
three tools, which an agent loads only as it searches for them
(`aertun mcp --list`). Eleven read — findings, proofs, claim cards, incident
clocks, detection statistics, the vulnerability plan, the estate in numbers —
and one proposes a decision on a finding for a person to make. Agents cannot
change who may do what, approve anything, sign or keep a proof, or reach
another platform. Every call is recorded under the agent's registered name,
and what agents did reaches the same detection engine as every other
platform's events.

Each agent is registered before it acts (`aertun agent add`), may be given a
token bound to one run, and has one kill switch, on the console and the
command line, that disables it and revokes its credentials in the same act.

<p align="center">
  <img src="docs/screens/registry.webp" alt="The agent registry: each registered agent, what it may call, who owns it, and its kill switch" width="900">
</p>

To put the same investigation to an agent twice, `aertun twin record` writes
what those operations would answer now to one file under its digest, and
`aertun mcp --twin FILE` answers from that file alone. `aertun forge export`
writes what the analyst saw, what it answered and how a person ruled as signed
episodes — counts and closed words only, never the text it read.

## Who may do what

A store starts with one person, its **Owner** (`aertun init --owner NAME`).
Everybody else is invited: `aertun auth invite NAME ROLE` grants a role and
prints the one-time link that adds their passkey.

| Role | May |
|---|---|
| `viewer` | read findings, cases, the vulnerability queue, the proofs and the dashboards |
| `analyst` | triage findings, open cases and add notes to them, hunt through events, judge adjudication samples |
| `responder` | run cases, ask for an action on another platform, approve somebody else's action, accept a risk, stop an agent |
| `admin` | manage people, connectors and their credentials, proof signers and settings |

Each role includes the ones above it. Beside them are jobs, for a different
kind of work rather than more of it: an `engineer` tunes detections and
automation rules, a `vuln-manager` decides vulnerabilities, and an `auditor`
reads the queue and the audit log for a set time, after which the grant ends
by itself. A grant can be limited to the security area, can end, and a deny
always wins. That is the whole model — `aertun auth roles` prints it — and
there are deliberately no custom roles, because assembling permissions is how
a role surface stops being reviewable.

What stops one person, or one stolen session, acting alone is not a setting:

- The **Owner** always administers the whole store. Nobody can revoke, deny
  or expire that. Ownership moves only when the Owner asks for a transfer and
  confirms it a day later.
- Making somebody an administrator, issuing an administrator's token,
  trusting a proof signer, weakening a setting and moving the audit log each
  take a second administrator. **An only administrator is slowed, not
  blocked**: their request needs a written reason, waits an hour (a day to
  move the audit log), is raised by Aertun's detections over its own log, and
  may then be approved by them only with a passkey sign-in made in the last
  five minutes.
- **Agents propose; people decide.** An agent's authority is the intersection
  of its registry entry, the grants of the person it acts for, and its
  token's own limits.
- Everybody signs in with a passkey that verifies it is them, or through
  single sign-on (OpenID Connect or SAML 2.0) that says it used two factors.
  Failed sign-ins lock out the places they come from, not the person.
  Sessions end after an hour unused, and after fifteen minutes for
  administrators.

<p align="center">
  <img src="docs/screens/people-pending.webp" alt="The People screen with a privileged change waiting: a request to trust a signing key, its reason, and when its only administrator may approve it" width="900">
</p>

## Its own record

Every change is written to an append-only audit log: a hash chain, a Merkle
tree over it, tree heads signed with Ed25519 and ML-DSA-65, and the head
committed to Bitcoin through OpenTimestamps (`aertun auditlog anchor`). The
log writer can run as its own account (`aertun logd`), so the console cannot
rewrite what it recorded. `aertun auditlog prove SEQ` gives the handful of
hashes that prove one entry is in the log without showing any other, and
`aertun compliance evidence CONTROL` packs the entries behind an SP 800-53
control with their proofs, for somebody to verify offline.

The log can also be sent to another SIEM as it is written: batches of OCSF,
each following the last, carrying a signed tree head and an HTTP message
signature (RFC 9421).

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="Four ways in over one set of declared operations; the security-operations core that is the evidence; the proving ground with each kind of proof; and what all of it rests on" width="900">
</p>

Everything is reachable from the console, from the command line
(`aertun help`), and from AI agents over MCP. A test fails when a command has
no screen and no written reason, or no agent operation and no written reason.

## Measured

Every figure here comes from the build being released, by a method in the
repository, so it can be produced again. Nothing is compared with a number
somebody else reported about their own product.

**Against outside references**

| | |
|---|---|
| **Sigma, read** | Every one of the 4,544 `.yml` files in [SigmaHQ](https://github.com/SigmaHQ/sigma) (commit `54967d6`, 13 November 2026) reads to the same values as PyYAML's reader with type inference off. |
| **Sigma, compiled** | 3,076 of the 3,164 core rules (97.2%), 455 of 474 emerging-threat rules (96.0%) and 140 of 141 threat-hunting rules (99.3%). Each rule refused is refused by name for a construct not implemented: a bare keyword search over the whole event (94), and the `fieldref` (6), `i` (5), `expand` (2) and `wide` (1) modifiers. |
| **Proof signatures** | A proof's Ed25519 signature verifies with Python's `cryptography` package and its ML-DSA-65 signature with OpenSSL 3.6.2, through [verify.py](scripts/verifyproof/verify.py), which shares no code with Aertun; one changed character is refused by both. |
| **Supply chain** | No third-party module in `go.mod`; `govulncheck` reports no reachable vulnerability on Go 1.27.4. |

**Live, end to end** — in Docker, on the release image, driving a real
Chrome with a WebAuthn virtual authenticator:

| | |
|---|---|
| **Command line** | 71 steps, each with its exit code and output checked: every proof above made, verified and kept, an agent's run reconciled, an incident's clocks, invitations, the audit log proved. |
| **Console** | 50 flow checks — enrolment, passkey sign-in, trusting a signer as an only administrator, blind review, the kill switch, the agent consent page, whose Allow the consent register and the audit log then recorded — and 62 pages crawled: all answered, no console errors, and no issue on an audit of labels, accessible names, headings, landmarks, duplicate ids, alternative text, tab order and WCAG 2.2 AA text contrast, in light and dark, with no sideways scroll at phone width. |
| **HTTP and MCP** | 30 checks: sign-in and two factors, cross-site requests, rate limiting, security headers, cookies, OAuth metadata with PKCE, the agent interface's authorisation, refusals and proof verification. |
| **OpenID Connect** | 13 checks against Keycloak 26 over HTTPS: sign-in with PKCE; one factor is asked for a passkey; an address outside the domain, a forged callback, a provider at a private address without `--reach`, and a certificate from an unknown authority are each refused. |
| **SAML 2.0** | 7 checks against Keycloak 26: a signed assertion signs in, one factor is asked for a passkey, an address outside the domain is refused. |
| **Test suite** | Ninety-seven packages with tests, run on every push; several walk the source and fail when a command has no screen and no written reason, or declares no privilege. |

**Speed** — four CPUs of an Intel Core i5-1235U laptop under WSL2, Go
1.27.4: the median of three runs of `go test -bench . -count 3` over
`internal/spool`, `internal/audit` and `internal/detect`, and the Sigma
import timed three times through the binary. Every write is durable —
fsynced — when it returns.

| What | Measured | Against |
|---|---|---|
| Storing an event (`spool add`) | 15.4 µs | 5.35 ms appended one at a time |
| Storing 1,000 events in one append | 22.2 ms | 5.04 s one by one |
| Writing an audit record, many writers | 58 µs | 1.73 ms from one writer |
| Four fields of 400,000 stored events | 51 ms, from the columns | 1.29 s decoding every event |
| An equality search over 400,000 events | 3.6 ms, through the postings | 1.25 s scanning every event |
| A hunt the segment blooms can prune | 147 ms | 1.26 s unpruned |
| A time window inside a segment | 84 ms, through the index | 276 ms read from its start |
| A hunt nothing can prune, eight segments | 1.27 s, segments read in parallel | 1.63 s one after another |
| A window across six segments | 1.86 s in parallel | 1.70 s one after another: no gain on this machine |
| 20 rules over 10,000 events | 431 ms | |
| Importing SigmaHQ's 3,164 core rules | 0.13 s | 0.8 s the first time, the files read from disk |

## Integrations

**Connectors** (read through each tool's API, credentials sealed in Aertun's
vault): Okta, Microsoft Entra ID, GitHub, EVM smart contracts through a
Blockscout explorer, KnowBe4, ManageEngine Endpoint Central, ManageEngine MDM
Plus, Vanta, and the OpenAI and Anthropic organisation audit logs.

**Log sources** mapped to one event shape: AWS CloudTrail, Microsoft Entra ID,
Microsoft Azure, Google Workspace, Google Cloud, Okta, Duo, CrowdStrike Falcon,
Jamf Pro, GitHub, Kubernetes, Cloudflare, Salesforce, Slack, Snowflake, Linux
auditd, EVM chains, the OpenAI and Anthropic audit logs, and GenAI agent
telemetry over OTLP (agent, tool and model calls, with prompts read for size
and never stored).

**Another vendor's AI verdicts** arrive as a file: JSON lines or CSV with the
columns `alert`, `verdict`, `at` and optionally `confidence`, `disposition`,
`disposition_at`, `source`. A file carrying any other column, such as the
product's reasoning, is refused whole.

**Standards**: in-toto, DSSE, OCSF, Sigma, MITRE ATT&CK, STIX 2.1,
SSF/CAEP/RISC, OpenTelemetry (OTLP), CycloneDX, SPDX, OSV, OpenVEX, SSVC,
CISA KEV, EPSS, SARIF, MCP, OAuth 2.1 with PKCE and DPoP, OpenID Connect,
SAML 2.0, SCIM 2.0 and WebAuthn passkeys.

## Install

**Download a release.** Each release has one static binary for each of Linux,
macOS and Windows on amd64 and arm64, a `SHA256SUMS` file, and a build
provenance attestation for every binary. Pick the file for your platform —
`aertun-linux-amd64`, `aertun-linux-arm64`, `aertun-darwin-arm64`,
`aertun-darwin-amd64`, `aertun-windows-amd64.exe` or
`aertun-windows-arm64.exe` — then check it before you run it:

```bash
VERSION=0.1.0 FILE=aertun-linux-amd64
curl -LO "https://github.com/aertun/aertun/releases/download/v$VERSION/$FILE"
curl -LO "https://github.com/aertun/aertun/releases/download/v$VERSION/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS            # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
gh attestation verify "$FILE" --repo aertun/aertun   # built by this repository's release workflow, from the tag
sudo install -m 0755 "$FILE" /usr/local/bin/aertun
```

On Windows, compare `Get-FileHash aertun-windows-amd64.exe` in PowerShell with
the line for it in `SHA256SUMS`. The checksum proves the file is the one
listed; the attestation proves which workflow, commit and tag built it.

**Run the container.** `ghcr.io/aertun/aertun` is the binary alone on
`gcr.io/distroless/static-debian12:nonroot`, with no shell, tagged with the
version without its `v` (`0.1.0`, `0.1`, `latest`) for amd64 and arm64:

```bash
docker run --rm -v aertun:/srv ghcr.io/aertun/aertun:0.1.0 --root /srv/store init --owner you@example.com
docker run -p 8080:8080 -v aertun:/srv ghcr.io/aertun/aertun:0.1.0
```

The image is attested like the binaries, by the release workflow from the
tag:

```bash
gh attestation verify oci://ghcr.io/aertun/aertun:0.1.0 --repo aertun/aertun
```

**Build from source.** Go 1.27 or later and nothing else — `go.mod` has no
dependencies to fetch:

```bash
git clone https://github.com/aertun/aertun && cd aertun
go build -o aertun ./cmd/aertun        # or: make && sudo make install
```

Behind a reverse proxy, set `admin.behind_tls_proxy` and `admin.base_url`;
[deploy/](deploy/) has a systemd unit and a Caddy configuration, and
[INSTALL](INSTALL) has the rest.

## Licence

Apache-2.0. Copyright 2026 Rashik Adhikari. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md).
