# aertun_verify (Python)

A verifier for the [Aertun Evidence Protocol, version 1](https://github.com/Aertun/Aertun/blob/main/spec/aep/v1/README.md),
in one file of Python's standard library. It depends on nothing.

```bash
pip install aertun-verify
aertun-verify VECTOR.json        # exit 0 when the vector verifies
```

Or use the file straight from the repository, with nothing installed:

```bash
python3 verifiers/python/aertun_verify.py VECTOR.json
aertun conform --verifier "python3 verifiers/python/aertun_verify.py"
python3 verifiers/python/test_aertun_verify.py
```

It shares no code with the Go implementation. It has its own:
- CBOR reader and writer;
- COSE_Sign1 (RFC 9052);
- Ed25519 (RFC 8032);
- ML-DSA-65 (FIPS 204), using SHAKE from `hashlib`;
- RFC 9162 inclusion proofs;
- RFC 8785 canonical JSON.

On top of those it checks the protocol's action digest and receipts, and
recomputes reconciliations, written from the specification.

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

The package on PyPI is built and published by the release workflow from
the release's tag, with an attestation of where it was built. Building it
uses PyPA's `build` and `setuptools`, pinned by hash in
`build-requirements.txt`; none of that is in the package.
`verifiers/pack.sh` builds it and checks the installed package against every
vector before anything is published.
