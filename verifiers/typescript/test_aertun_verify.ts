// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0
//
// Tests for aertun_verify.ts: each primitive held to a published vector or
// to the Go implementation's own output, and every way a statement can be
// changed refused.
//
//   node --test test_aertun_verify.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as av from "./aertun_verify.ts";

const VECTORS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "spec", "aep", "v1", "vectors");
const vector = (name: string) => JSON.parse(readFileSync(join(VECTORS, name), "utf-8")) as av.Vector;
const h = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

test("Ed25519 against RFC 8032 section 7.1", () => {
  const k1 = new av.Key(av.ALG_ED25519, h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
  const s1 = h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
  assert.equal(k1.verify(new Uint8Array(0), s1), true);
  assert.equal(k1.verify(Uint8Array.of(0x78), s1), false);
  const k2 = new av.Key(av.ALG_ED25519, h("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"));
  const s2 = h("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
  assert.equal(k2.verify(Uint8Array.of(0x72), s2), true);
  const bad = s2.slice();
  bad[63] ^= 0x10;
  assert.equal(k2.verify(Uint8Array.of(0x72), bad), false);
});

test("ML-DSA-65: Go's signature verifies, and every part of it is checked", () => {
  const v = vector("03-receipt-gateway-mldsa65.json");
  const kv = v.issuer_keys!["https://gateway.example"];
  const key = new av.Key(kv.alg, h(kv.public));
  const msg = new av.Sign1(h(v.statement!));
  const tbs = av.cborEncode(["Signature1", msg.protected_, new Uint8Array(0), msg.payload]);
  assert.equal(key.verify(tbs, msg.signature), true);
  for (const at of [0, 47, 48, 1500, 3247, 3250, 3308]) {
    const bad = msg.signature.slice();
    bad[at] ^= 1;
    assert.equal(key.verify(tbs, bad), false, `byte ${at}`);
  }
  assert.equal(key.verify(av.cborEncode(["Signature1", msg.protected_, new Uint8Array(0), Uint8Array.of(1)]), msg.signature), false);
  assert.equal(key.verify(tbs, msg.signature.slice(0, -1)), false);
  const other = key.pub.slice();
  other[100] ^= 1;
  assert.equal(new av.Key(av.ALG_MLDSA65, other).verify(tbs, msg.signature), false);
});

test("CBOR: deterministic order, and the refusals", () => {
  const enc = av.cborEncode(av.m([["aa", 0], [-1, 0], ["b", 0], [10, 0], [1, 0]]));
  assert.equal(Buffer.from(enc).toString("hex"), "a5" + "0100" + "0a00" + "2000" + "616200" + "62616100");
  for (const bad of ["9f01ff", "a201020103", "f93c00", "f7", "0000", "62c328", "1c", "1b0020000000000000"])
    assert.throws(() => av.cborDecode(h(bad)), av.Invalid, bad);
});

test("RFC 8785: numbers, members in order, and what is refused", () => {
  const cases: [number, string][] = [[0, "0"], [-0, "0"], [1e30, "1e+30"], [4.5, "4.5"], [0.000001, "0.000001"],
    [1e-7, "1e-7"], [333333333.33333329, "333333333.3333333"], [100, "100"], [1e21, "1e+21"], [-5e-324, "-5e-324"]];
  for (const [x, want] of cases) assert.equal(av.jcs(x), want, String(x));
  assert.deepEqual(av.argsDigest(' { "b" : 1, "a" : [1, 2.50, "\\u0078"] } '), av.argsDigest('{"a":[1,2.5,"x"],"b":1}'));
  for (const bad of ['{"a":1,"a":2}', '{"a":', '"\\ud800"', "NaN", '{"a":1} x'])
    assert.throws(() => av.argsDigest(bad), undefined, bad);
});

test("instants have one writing", () => {
  assert.equal(av.formatInstant(av.parseInstant("2026-11-20T12:00:00.045Z")), "2026-11-20T12:00:00.045Z");
  for (const bad of ["2026-11-20T12:00:00.000Z", "2026-11-20T13:00:00+01:00", "2026-02-30T00:00:00Z"])
    assert.throws(() => av.parseInstant(bad), av.Invalid, bad);
});

const files = readdirSync(VECTORS).filter((f) => f.endsWith(".json")).sort();

test("every vector is decided as the protocol requires", () => {
  for (const f of files) {
    const v = vector(f);
    let accepted = true;
    try {
      av.checkVector(v);
    } catch {
      accepted = false;
    }
    assert.equal(accepted, v.valid, f);
  }
});

test("a false reconciliation is refused by recomputing it, not only by its verdict", () => {
  const v = vector("14-reconciliation-false-agreement.json");
  delete v.verdict;
  assert.throws(() => av.checkVector(v), /recomputing/);
});

test("any bit flipped in a valid statement is refused", () => {
  // A fixed sequence, so a failure names a byte that fails again.
  let seed = 7;
  const next = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31);
  for (const f of files) {
    const v = vector(f);
    if (!v.valid || v.kind !== "statement") continue;
    const raw = h(v.statement!);
    for (let n = 0; n < 40; n++) {
      const at = next() % raw.length;
      const bad = raw.slice();
      bad[at] ^= 1 << (next() % 8);
      assert.throws(() => av.checkVector({ ...v, statement: Buffer.from(bad).toString("hex") }), undefined, `${f} byte ${at}`);
    }
  }
});
