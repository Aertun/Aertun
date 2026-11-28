# aertun_verify (TypeScript)

A verifier for the [Aertun Evidence Protocol, version 1](https://github.com/Aertun/Aertun/blob/main/spec/aep/v1/README.md)
in one TypeScript file for Node.js 24.7 or later. It depends on nothing:
`node:crypto` supplies SHA-256, Ed25519 and ML-DSA-65.

```bash
npm install aertun-verify
npx aertun-verify VECTOR.json        # exit 0 when the vector verifies
```

Or run the file straight from the repository. Node runs it as it is, with
nothing installed and nothing built:

```bash
node verifiers/typescript/aertun_verify.ts VECTOR.json
aertun conform --verifier "node verifiers/typescript/aertun_verify.ts"
node --test verifiers/typescript/test_aertun_verify.ts
```

The rest is written here from the specification, and shares no code with
the Go or the Python implementation:
- CBOR;
- COSE_Sign1 (RFC 9052);
- RFC 9162 inclusion proofs;
- RFC 8785 canonical JSON, refusing members named twice;
- the action digest and receipts;
- reconciliation, recomputed in full.

It decides every one of the protocol's test vectors as the protocol
requires. Its tests check:
- Ed25519 against RFC 8032;
- ML-DSA-65 against signatures made by Go's `crypto/mldsa`, with each part
  tampered;
- canonical JSON against RFC 8785;
- that a false reconciliation is refused by recomputing it;
- that random bit flips in statements are all refused.

The Go test suite runs it on every change, with Node 24 in CI.

To verify a statement from a program, import the module and call
`checkVector`, or use `Statement`, `Key` and `readReceipt` directly:

```ts
import { Statement, Key, ALG_ED25519, readReceipt } from "aertun-verify";
const statement = new Statement(rawBytes);
statement.message.verify(new Key(ALG_ED25519, ed25519PublicKey));
const [, receipt] = readReceipt(rawBytes);
```

It verifies; it does not sign.

The package on npm is this file compiled by the TypeScript compiler, which
type-checks it under `strict` and writes the declarations. The compiler is
pinned in `package-lock.json`, and none of it is in the package. The release
workflow builds the package from the release's tag and stages it with
provenance; a maintainer approves it before it is public.
`verifiers/pack.sh` builds it and checks the installed package against every
vector before anything is published.
