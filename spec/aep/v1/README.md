# The Aertun Evidence Protocol, version 1

Status: draft for implementation. The test vectors in [`vectors/`](vectors)
are normative: where this text and a vector disagree, the vector is right,
and the text is corrected.

## 1. What it is for

An AI agent's action is usually seen by more than one party: the agent
that decided on it, the gateway it went through, the server that carried
it out, and sometimes a sandbox. Each party's log is its own account.
The protocol lets each party sign what it saw, in a form the others can
line up with theirs. A reconciliation of those statements then says,
in a statement of its own, whether they agree and where they do not:
- an action some party never reported;
- a party's sequence numbers that skip or repeat;
- an action whose actor the parties name differently.

The protocol is a profile of SCITT (RFC 9943). Every statement is a SCITT
signed statement, so any SCITT transparency service can register it, and
any COSE library can check its signature. The profile adds three things:
1. a digest every party computes alike;
2. payloads with a fixed meaning;
3. a reconciliation anyone can recompute.

## 2. Conventions

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and
RFC 8174.

CBOR is encoded deterministically, following RFC 8949 §4.2.1:
- shortest-form arguments;
- definite lengths;
- map keys sorted by the bytes of their encodings.

A verifier MUST refuse indefinite lengths, duplicate map keys, and text
that is not UTF-8. Signatures are checked over the bytes received, never
over a re-encoding.

An *instant* is an RFC 3339 time in UTC, written with `Z` and with any
fraction of a second in its shortest form, for example
`2026-11-20T12:00:00.045Z`. A verifier MUST refuse any other writing of
the same instant, so each instant has exactly one encoding.

## 3. The action digest

The action digest is SHA-256 over the deterministic CBOR array
`["AEP-Action-v1", target, tool, args]`.

- `target` is the resource the call was for: the RFC 8707 resource
  indicator, such as an MCP server's URL.
- `tool` is the tool or operation called.
- `args` is SHA-256 over the RFC 8785 canonical form of the call's JSON
  arguments. If there are no arguments, the canonical form is that of `{}`.

`target` and `tool` are 1 to 2048 bytes of UTF-8, with no control
characters.

Who acted, under what grant, and when are deliberately not part of the
digest. Those are what the parties may disagree about, and comparing
them is the reconciliation's job.

Vector 01 gives the inputs and both digests.

## 4. Statements

### 4.1 Common to both kinds

A statement is a tagged COSE_Sign1 (RFC 9052). Its protected header
carries:

| Label | Name | Value |
|---|---|---|
| 1 | alg | -19 (Ed25519, RFC 9864) or -49 (ML-DSA-65, RFC 9964) |
| 4 | kid | the RFC 9679 COSE Key Thumbprint of the signing key, SHA-256 |
| 3 | content_type | one of the two media types below |
| 15 | CWT claims | {1: issuer, 2: subject, 6: issued-at in seconds} |

The members that go into the kid thumbprint are fixed by the key type:
- Ed25519, an OKP key: kty 1, crv 6 and x.
- ML-DSA-65, an AKP key: kty 7, alg -49 and pub (RFC 9964 §6).

When signing:
- ML-DSA-65 is signed with the empty context string, as RFC 9964 §5
  requires.
- Issuers SHOULD NOT use the deprecated polymorphic EdDSA identifier (-8).
  Verifiers MAY accept it with an Ed25519 key.

When verifying:
- A verifier MUST refuse a message whose `crit` header names any label.
  Version 1 defines none.
- A verifier MUST refuse a label that appears in both the protected and
  the unprotected header.

The payload is attached. It is a CBOR map with text keys, given in
[`aep.cddl`](aep.cddl). Every payload carries `"v": 1`. A verifier MUST
refuse a payload with any key this version does not define. Any change
of meaning is a new version, never a new optional key.

### 4.2 Action receipt

The content type is `application/vnd.aertun.aep.action+cbor`. The CWT
claims are:
- the issuer is the party;
- the subject is `aep:action:` followed by the action digest in lowercase
  hex.

A verifier MUST:
- recompute the digest from the payload's `target`, `tool` and `args`;
- refuse the receipt if that digest differs from `action`, or if the
  subject differs from what the digest gives.

`vantage` is where the action was seen from: one of `agent`, `gateway`,
`target` or `sandbox`. `at` is when this party saw the action. The
optional fields are:
- `actor`: who the party saw act;
- `grant`: the authority it saw exercised, as a token or delegation
  identifier;
- `outcome`: `ok`, `error` or `refused`;
- `seq`: the party's own counter, if it keeps one.

Vectors 02–04 are valid receipts. Vectors 07–11 and 15 are receipts a
verifier must refuse.

### 4.3 Reconciliation receipt

The content type is `application/vnd.aertun.aep.reconciliation+cbor`.
The CWT claims are:
- the issuer is the reconciler;
- the subject is `aep:reconciliation:` followed by the inputs digest in
  hex.

A reconciliation is checked by doing it again. A verifier given the
receipts it reconciled MUST:
1. verify each receipt;
2. recompute the reconciliation under §5;
3. accept only when the recomputed payload is byte-for-byte the stated
   one.

The verifier does not trust the reconciler's signature for the result.
The signature only says who claimed it.

Vectors 05 and 06 must be accepted. Vector 14, a false agreement that is
properly signed, must be refused.

## 5. Reconciliation

The inputs are:
- a window [`from`, `to`), at most 31 days long;
- a tolerance of 0 to 60 seconds, a whole number of milliseconds;
- two or more expected parties, each an issuer at one vantage point;
- verified action receipts.

The steps are:

1. **Refuse foreign receipts.** A receipt from an issuer not expected, or
   reporting from another vantage point, is refused. Quietly dropping it
   would make the result about other receipts than the ones given.
2. **Select the receipts.** Consider receipts whose `at` is within the
   window widened by the tolerance at both ends. Drop any receipt whose
   registered bytes repeat another's, comparing bytes with the unprotected
   header emptied.
3. **Compute `inputs`.** It is SHA-256 over the concatenation, in sorted
   order, of the SHA-256 of each receipt considered.
4. **Group receipts into actions.** Order the receipts by `at`, then by
   issuer, then by their SHA-256. Each receipt joins the earliest open
   action that meets all three conditions:
   - it has the same digest;
   - this receipt's issuer is not yet in it;
   - it began no more than the tolerance before this receipt.

   If no action qualifies, the receipt begins a new one. The tolerance is
   inclusive.
5. **Count the actions.** An action is counted when its first receipt
   falls within [`from`, `to`). So adjacent windows with the same
   tolerance count each action exactly once. An action missing any
   expected party is a gap, which names who saw the action and who did
   not. A party that reported nothing at all is still expected: its
   silence is a gap.
6. **Find actor splits.** An action whose parties name two or more
   different actors is an actor split.
7. **Check sequence numbers.** Use each party's `seq` values within the
   window. Report:
   - every range missing between its lowest and highest;
   - every number used more than once.
8. **Decide the verdict.**
   - `inconclusive` if no receipt was considered;
   - otherwise `disagree` if there is any gap, split or sequence finding;
   - otherwise `agree`.

Lists hold at most 200 entries. The totals count every finding.

## 6. Registration and the two receipts

A statement is registered in a transparency log as SCITT describes. The
log entry is the statement with its unprotected header emptied. The log
answers with RFC 9942 inclusion receipts:
- verifiable data structure 1 (RFC 9162 SHA-256);
- the root at the stated tree size, carried detached;
- the inclusion proof `[tree_size, leaf_index, path]` under label 396,
  key -1;
- CWT claims naming the log.

Receipts are attached under label 394.

A log implementing this profile issues one receipt for each of its
algorithms, Ed25519 and ML-DSA-65. A verifier holding the log's two keys
MUST require one verified receipt from each, for the same root, before
treating the statement as registered (vectors 04, 12 and 13). This is
what keeps an Ed25519 statement protected after Ed25519 is broken: a
later forgery has no ML-DSA receipt from the log.

RFC 9942 signs the root and not the tree size. A verifier that relies on
the size, to order or count entries, compares the root with a head the
log signed.

## 7. Conformance

An implementation conforms as a **verifier** when it accepts every vector
marked `"valid": true` and refuses every other. Each vector is
self-contained: it carries the statement, the keys, and the receipts or
arguments needed.

`aertun conform VECTORS --verifier CMD` runs any verifier over the
vectors. The verifier is given one vector file per run and must exit 0
exactly when it accepts the vector.

Two verifiers conform today: the Go one in this repository (`aertun
conform` with no `--verifier`), and [the Python one](../../../verifiers/python),
standard library only, which shares no code with it.

An implementation conforms as a **producer** when its statements pass a
conforming verifier, and its action digests match vector 01's
construction.

## 8. Security considerations

- **What a receipt proves.** A receipt says what one party claims it
  saw, and nothing more. Its value comes from reconciliation against
  parties that do not share a failure. The stronger guarantees, such as
  showing that silence means nothing happened, need parties whose logs an
  attacker controlling the agent cannot also write.
- **What the digest leaks.** The digest hides the arguments only as well
  as they are hard to guess. A receipt for `{"approve": true}` reveals
  the value to anyone who tries both. Parties that need confidentiality
  share receipts only with those entitled to the action's arguments.
- **The parties' own identifiers.** The issuer, actor and grant are each
  party's own names. A disagreement over the actor is evidence, either
  of a token being passed between agents, or of naming that differs and
  needs mapping first.
- **Time.** Parties' clocks differ. The tolerance absorbs the difference,
  and a tolerance wider than the interval between repeated identical
  calls merges them.
- **Where the [threat model](../../../THREAT_MODEL.md) applies.** It
  covers the implementation in this repository.

## 9. Versioning

Every receipt ever issued under version 1 stays verifiable by every later
verifier. A change of meaning is a new version, with a new media type,
never an edit to this one. See [STABILITY.md](../../../STABILITY.md).
