# Stability

Aertun is before 1.0. This file says what that means for each thing other
people build on, and what never changes even before 1.0.

## Never changes: what has been signed

Anything Aertun has signed stays verifiable by every later release:

- **Proof predicates.** Each proof kind is published at a versioned
  address, for example `https://aertun.github.io/proof/reconciliation/v1/`.
  - A proof made under `v1` verifies, with the meaning `v1` gave it, in
    every later release.
  - A change of meaning is a new address (`v2`) beside the old one, never
    an edit to it.
  - The words a proof's claims are written in are part of what is
    signed. They are changed only for a kind that has never been released.
- **Evidence protocol statements.** Receipts and reconciliations under
  [AEP version 1](spec/aep/v1/README.md) stay verifiable as version 1.
  A change of meaning is a new version with a new media type. The
  [test vectors](spec/aep/v1/vectors) are fixed: the test suite requires
  the generator to reproduce them byte for byte, so a vector can change
  only by a deliberate commit that says why.
- **Signatures.** Every document this program signs carries two
  signatures, Ed25519 and ML-DSA-65, or, for the evidence protocol, a log
  receipt in each. Both are required, and neither will be dropped.
- **The audit log.** The chain and the Merkle tree over it keep their
  hashing. A log written by any release verifies with `aertun auditlog
  verify` in every later one.

## Kept with notice: what you configure and call

These may change before 1.0. When they do, the change is announced in
[NEWS](NEWS) in the release that makes it, together with what to do.
- **Commands and flags.** Where possible, a removed flag is refused with
  a message naming its replacement, for one release, before it goes.
- **Configuration keys** (`aertun config list` names them all). A key is
  renamed or removed only with a NEWS entry. Setting a name that is no
  longer a key is refused, never silently accepted.
- **The agent interface's operations** (`aertun mcp --list`). Operations
  are added freely. One that is removed or renamed is announced in NEWS.
- **Detection content.** Packs are signed and versioned, and a pack is
  installed only if its metadata version moves forward.

## No promise yet

- **The store's on-disk layout under `--root`.** Keep backups. Running a
  store under an older release than the one that last wrote it is not
  supported.
- **Go packages under `internal/`.** By Go's rules they cannot be
  imported from outside this module. A library for verifiers is planned,
  and will carry its own promise.
- **Screens in the console.**

## At 1.0

Commands, flags, configuration keys and the agent interface's operations
will then follow semantic versioning: no incompatible change before 2.0.
