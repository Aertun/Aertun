#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: Apache-2.0
"""Check an Aertun proof with nothing of Aertun's.

    python3 scripts/verifyproof/verify.py PROOF.json PUBLIC-KEY.json

A proof is an in-toto Statement in a DSSE envelope carrying two signatures
over the same bytes, the DSSE pre-authentication encoding of its payload:

    Ed25519        as DSSE defines it, so in-toto and Sigstore tooling reads
                   this half without knowing anything else about the proof
    ML-DSA-65      FIPS 204, pure, with the context string aertun/proof/v1

This script builds that encoding by hand, checks the first signature with
the Python `cryptography` package and the second with the `openssl` command
(3.5 or later, which is when it learned ML-DSA), and prints the claim and
the verdict. It shares no code with the program that made the proof, which
is the point: "anybody can check one without this program" is a claim, and
this is it being checked.

It checks the signatures and nothing else. Whether the key is one you
trust, and whether the subject's digest is the file in your hand, are
yours to decide: `aertun proof verify --subject FILE` does the second.

Exit status: 0 when both signatures hold, 1 when either does not, 2 when
the files cannot be read as a proof and its key.
"""

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

CONTEXT = "aertun/proof/v1"
# id-ml-dsa-65, 2.16.840.1.101.3.4.3.18, as a DER object identifier.
ML_DSA_65 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])


def der(tag: int, content: bytes) -> bytes:
    """One DER element: a tag, a definite length, the content."""
    n = len(content)
    if n < 128:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.split("\n\n")[1].strip(), file=sys.stderr)
        return 2
    try:
        envelope = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        key = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        payload = base64.b64decode(envelope["payload"], validate=True)
        kind = envelope["payloadType"].encode()
        signatures = {s["keyid"].rsplit(":", 1)[1]: base64.b64decode(s["sig"], validate=True)
                      for s in envelope["signatures"]}
        ed_key = base64.b64decode(key["ed25519"], validate=True)
        ml_key = base64.b64decode(key["mldsa_65"], validate=True)
        ed_sig, ml_sig = signatures["ed25519"], signatures["mldsa65"]
    except (OSError, ValueError, KeyError, TypeError) as err:
        print(f"not a proof and its public key: {err!r}", file=sys.stderr)
        return 2

    # DSSE's pre-authentication encoding: what both signatures are over.
    signed = b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)
    held = True

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("the Ed25519 check needs the Python `cryptography` package", file=sys.stderr)
        return 2
    try:
        Ed25519PublicKey.from_public_bytes(ed_key).verify(ed_sig, signed)
        print("Ed25519     holds  (python cryptography)")
    except (InvalidSignature, ValueError):
        print("Ed25519     DOES NOT HOLD")
        held = False

    with tempfile.TemporaryDirectory() as tmp:
        at = Path(tmp)
        (at / "key.der").write_bytes(der(0x30, der(0x30, ML_DSA_65) + der(0x03, b"\x00" + ml_key)))
        (at / "signed").write_bytes(signed)
        (at / "sig").write_bytes(ml_sig)
        try:
            ran = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                 "-inkey", str(at / "key.der"), "-rawin", "-in", str(at / "signed"),
                 "-sigfile", str(at / "sig"), "-pkeyopt", "context-string:" + CONTEXT],
                capture_output=True, text=True, check=False)
        except OSError as err:
            print(f"the ML-DSA-65 check needs the openssl command: {err}", file=sys.stderr)
            return 2
    if ran.returncode == 0:
        print("ML-DSA-65   holds  (openssl, context " + CONTEXT + ")")
    else:
        print("ML-DSA-65   DOES NOT HOLD")
        held = False

    if not held:
        return 1
    try:
        statement = json.loads(payload)
        predicate = statement["predicate"]
        print()
        print(predicate["verdict"].upper() + ": " + statement["subject"][0]["name"])
        print("  " + predicate["claim"])
        for check in predicate.get("checks", []):
            print("  %-5s %s" % ("pass" if check.get("passed") else "FAIL", check.get("name", "")))
    except (ValueError, KeyError, IndexError, TypeError):
        print("the signatures hold over a payload that is not a proof statement", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
