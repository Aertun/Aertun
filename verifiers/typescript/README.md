# aertun_verify (TypeScript)

A verifier for the [Aertun Evidence Protocol, version 1](../../spec/aep/v1/README.md)
in one TypeScript file for Node.js 24 or later. There is nothing to install
and nothing to build: Node runs the file as it is, and `node:crypto` supplies
SHA-256, Ed25519 and ML-DSA-65.

The rest is written here from the specification, and shares no code with
the Go or the Python implementation:
- CBOR;
- COSE_Sign1 (RFC 9052);
- RFC 9162 inclusion proofs;
- RFC 8785 canonical JSON, refusing members named twice;
- the action digest and receipts;
- reconciliation, recomputed in full.

```bash
node aertun_verify.ts VECTOR.json        # exit 0 when the vector verifies
aertun conform --verifier "node verifiers/typescript/aertun_verify.ts"
node --test verifiers/typescript/test_aertun_verify.ts
```

It decides every one of the protocol's test vectors as the protocol
requires. Its tests check:
- Ed25519 against RFC 8032;
- ML-DSA-65 against signatures made by Go's `crypto/mldsa`, with each part
  tampered;
- canonical JSON against RFC 8785;
- that a false reconciliation is refused by recomputing it;
- that random bit flips in statements are all refused.

The Go test suite runs both on every change, with Node 24 in CI.

To verify a statement from a program, import the module and call
`checkVector`, or use `Statement`, `Key` and `readReceipt` directly. It
verifies; it does not sign.
