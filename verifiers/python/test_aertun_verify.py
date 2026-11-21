#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: Apache-2.0
"""Tests for aertun_verify: each primitive held to a published vector or to
the Go implementation's own output, and every way a statement can be
changed refused."""

import json
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import aertun_verify as av  # noqa: E402

VECTORS = os.path.join(HERE, "..", "..", "spec", "aep", "v1", "vectors")


def vector(name):
    with open(os.path.join(VECTORS, name)) as f:
        return json.load(f)


class Ed25519(unittest.TestCase):
    # RFC 8032 section 7.1, TEST 1 and TEST 2.
    def test_rfc8032(self):
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(av.ed25519_verify(pub, b"", sig))
        self.assertFalse(av.ed25519_verify(pub, b"x", sig))
        pub2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig2 = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                             "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        self.assertTrue(av.ed25519_verify(pub2, b"\x72", sig2))
        bad = bytearray(sig2)
        bad[63] ^= 0x10  # S beyond the group order or simply wrong
        self.assertFalse(av.ed25519_verify(pub2, b"\x72", bytes(bad)))


class MLDSA65(unittest.TestCase):
    def setUp(self):
        v = vector("03-receipt-gateway-mldsa65.json")
        self.key = av.Key(v["issuer_keys"]["https://gateway.example"]["alg"],
                          bytes.fromhex(v["issuer_keys"]["https://gateway.example"]["public"]))
        m = av.Sign1(bytes.fromhex(v["statement"]))
        self.tbs = av.cbor_encode(["Signature1", m.protected, b"", m.payload])
        self.sig = m.signature

    def test_go_signature_verifies(self):
        self.assertTrue(av.mldsa65_verify(self.key.public, self.tbs, self.sig))

    def test_every_part_is_checked(self):
        for at, what in ((0, "challenge"), (47, "challenge"), (48, "response"), (1500, "response"),
                         (3247, "response"), (3250, "hint"), (3308, "hint")):
            bad = bytearray(self.sig)
            bad[at] ^= 0x01
            self.assertFalse(av.mldsa65_verify(self.key.public, self.tbs, bytes(bad)), what + " %d" % at)
        self.assertFalse(av.mldsa65_verify(self.key.public, self.tbs + b"x", self.sig))
        self.assertFalse(av.mldsa65_verify(self.key.public, self.tbs, self.sig, ctx=b"other"))
        other = bytearray(self.key.public)
        other[100] ^= 0x01
        self.assertFalse(av.mldsa65_verify(bytes(other), self.tbs, self.sig))
        self.assertFalse(av.mldsa65_verify(self.key.public, self.tbs, self.sig[:-1]))


class CBOR(unittest.TestCase):
    def test_round_trip_and_order(self):
        self.assertEqual(av.cbor_encode({"aa": 0, -1: 0, "b": 0, 10: 0, 1: 0}).hex(),
                         "a5" "0100" "0a00" "2000" "616200" "62616100")

    def test_refusals(self):
        for h in ("9f01ff", "a201020103", "f93c00", "f7", "0000", "62c328", "1c"):
            with self.assertRaises((av.CBORError, UnicodeDecodeError)):
                av.cbor_decode(bytes.fromhex(h))


class JCS(unittest.TestCase):
    def test_numbers(self):
        # RFC 8785 appendix B and ECMAScript's Number::toString.
        for x, want in ((0.0, "0"), (-0.0, "0"), (1e30, "1e+30"), (4.5, "4.5"), (0.000001, "0.000001"),
                        (1e-7, "1e-7"), (333333333.33333329, "333333333.3333333"), (100.0, "100"),
                        (1e21, "1e+21"), (123e18, "123000000000000000000"), (-5e-324, "-5e-324")):
            self.assertEqual(av._jcs_number(x), want, repr(x))

    def test_canonical_form(self):
        self.assertEqual(av.args_digest(' { "b" : 1, "a" : [1, 2.50, "\\u0078"] } '),
                         av.args_digest('{"a":[1,2.5,"x"],"b":1}'))
        for bad in ('{"a":1,"a":2}', '{"a":', '"\\ud800"', "NaN"):
            with self.assertRaises(ValueError):
                av.args_digest(bad)


class Vectors(unittest.TestCase):
    def test_all(self):
        for name in sorted(os.listdir(VECTORS)):
            if not name.endswith(".json"):
                continue
            v = vector(name)
            try:
                av.check_vector(v)
                accepted = True
            except (av.Invalid, av.CBORError, ValueError, KeyError, TypeError, UnicodeDecodeError):
                accepted = False
            self.assertEqual(accepted, v["valid"], name)

    def test_any_change_is_refused(self):
        rng = random.Random(7)
        for name in sorted(os.listdir(VECTORS)):
            if not name.endswith(".json"):
                continue
            v = vector(name)
            if not v["valid"] or v["kind"] != "statement":
                continue
            raw = bytearray(bytes.fromhex(v["statement"]))
            positions = sorted(rng.sample(range(len(raw)), min(len(raw), 40)))
            for at in positions:
                bad = bytearray(raw)
                bad[at] ^= 1 << rng.randrange(8)
                changed = dict(v, statement=bytes(bad).hex())
                with self.assertRaises((av.Invalid, av.CBORError, ValueError, KeyError, TypeError,
                                        UnicodeDecodeError), msg="%s byte %d" % (name, at)):
                    av.check_vector(changed)


class Instants(unittest.TestCase):
    def test_one_writing(self):
        ns = av.parse_instant("2026-11-20T12:00:00.045Z")
        self.assertEqual(av.format_instant(ns), "2026-11-20T12:00:00.045Z")
        for bad in ("2026-11-20T12:00:00.000Z", "2026-11-20T13:00:00+01:00", "2026-02-30T00:00:00Z"):
            with self.assertRaises(av.Invalid):
                av.parse_instant(bad)


if __name__ == "__main__":
    unittest.main()
