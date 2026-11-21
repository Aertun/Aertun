# aertun_verify (Python)

A verifier for the [Aertun Evidence Protocol, version 1](../../spec/aep/v1/README.md),
in one file of Python's standard library: nothing to install.

It shares no code with the Go implementation. It has its own:
- CBOR reader and writer;
- COSE_Sign1 (RFC 9052);
- Ed25519 (RFC 8032);
- ML-DSA-65 (FIPS 204), using SHAKE from `hashlib`;
- RFC 9162 inclusion proofs;
- RFC 8785 canonical JSON.

On top of those it checks the protocol's action digest and receipts, and
recomputes reconciliations, written from the specification.

```bash
python3 aertun_verify.py VECTOR.json        # exit 0 when the vector verifies
aertun conform --verifier "python3 verifiers/python/aertun_verify.py"
python3 verifiers/python/test_aertun_verify.py
```

It decides every one of the protocol's test vectors as the protocol
requires. Its tests check the following, among other cases:
- Ed25519 against RFC 8032;
- ML-DSA-65 against signatures made by Go's `crypto/mldsa`, with the
  challenge, the response and the hint each tampered;
- canonical JSON against RFC 8785;
- statements with random bit flips, which must all be refused.

The Go test suite runs both on every change, wherever `python3` is
installed.

To verify a statement from a program, import it:

```python
import aertun_verify as av
statement = av.Statement(raw_bytes)
statement.message.verify(av.Key(-19, ed25519_public_key))
_, receipt = av.read_receipt(raw_bytes)
```

It verifies; it does not sign.
