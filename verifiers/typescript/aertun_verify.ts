#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0
//
// A verifier for the Aertun Evidence Protocol, version 1, in TypeScript on
// Node.js 24 or later, with nothing installed: node:crypto supplies SHA-256,
// Ed25519 and ML-DSA-65, and the rest is written here from spec/aep/v1 —
// CBOR, COSE_Sign1 (RFC 9052), RFC 9162 inclusion proofs, RFC 8785
// canonical JSON, the action digest, receipts and reconciliation. It shares
// no code with the Go or the Python implementation.
//
//   node aertun_verify.ts VECTOR.json     exit 0 if the vector verifies
//
// so `aertun conform --verifier "node aertun_verify.ts"` runs the protocol's
// test vectors against it. Only erasable TypeScript syntax is used, so Node
// runs the file as it is.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

export class Invalid extends Error {}

// -- CBOR (RFC 8949): a strict reader and a deterministic writer -------------

export class Tag {
  tag: number;
  value: unknown;
  constructor(tag: number, value: unknown) {
    this.tag = tag;
    this.value = value;
  }
}

const MAX_DEPTH = 16;
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function cborDecode(b: Uint8Array): unknown {
  const [v, at] = item(b, 0, 0);
  if (at !== b.length) throw new Invalid("bytes follow the value");
  return v;
}

function arg(b: Uint8Array, at: number, minor: number): [number, number] {
  if (minor < 24) return [minor, at];
  if (minor > 27) throw new Invalid("indefinite or reserved length");
  const n = 1 << (minor - 24);
  if (at + n > b.length) throw new Invalid("argument runs past the end");
  let v = 0n;
  for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[at + i]);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Invalid("an integer past what is read here");
  return [Number(v), at + n];
}

function item(b: Uint8Array, at: number, depth: number): [unknown, number] {
  if (at >= b.length) throw new Invalid("value ends early");
  const major = b[at] >> 5, minor = b[at] & 0x1f;
  at++;
  if (major === 7) {
    if (minor === 20) return [false, at];
    if (minor === 21) return [true, at];
    if (minor === 22) return [null, at];
    throw new Invalid("float, undefined or simple value");
  }
  const [n, next] = arg(b, at, minor);
  at = next;
  if (major >= 4 && depth + 1 > MAX_DEPTH) throw new Invalid("nested too deep");
  switch (major) {
    case 0:
      return [n, at];
    case 1:
      return [-1 - n, at];
    case 2:
    case 3: {
      if (n > b.length - at) throw new Invalid("string runs past the end");
      const raw = b.slice(at, at + n);
      if (major === 2) return [raw, at + n];
      try {
        return [textDecoder.decode(raw), at + n];
      } catch {
        throw new Invalid("text that is not UTF-8");
      }
    }
    case 4: {
      if (n > b.length - at) throw new Invalid("array count beyond the bytes");
      const out: unknown[] = [];
      for (let i = 0; i < n; i++) {
        const [v, a] = item(b, at, depth + 1);
        out.push(v);
        at = a;
      }
      return [out, at];
    }
    case 5: {
      if (n > Math.floor((b.length - at) / 2)) throw new Invalid("map count beyond the bytes");
      const out = new Map<number | string, unknown>();
      for (let i = 0; i < n; i++) {
        const [k, a] = item(b, at, depth + 1);
        if (typeof k !== "number" && typeof k !== "string") throw new Invalid("map key is not an integer or text");
        if (out.has(k)) throw new Invalid("duplicate map key");
        const [v, a2] = item(b, a, depth + 1);
        out.set(k, v);
        at = a2;
      }
      return [out, at];
    }
    default: {
      const [v, a] = item(b, at, depth + 1);
      return [new Tag(n, v), a];
    }
  }
}

function head(major: number, n: number): Uint8Array {
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | n);
  for (const [code, size] of [[24, 1], [25, 2], [26, 4], [27, 8]]) {
    if (BigInt(n) < 1n << BigInt(8 * size)) {
      const out = new Uint8Array(1 + size);
      out[0] = m | code;
      let v = BigInt(n);
      for (let i = size; i >= 1; i--) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
      }
      return out;
    }
  }
  throw new Invalid("integer too large");
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  return compare(a, b) === 0;
}

export function cborEncode(v: unknown): Uint8Array {
  if (v === true) return Uint8Array.of(0xf5);
  if (v === false) return Uint8Array.of(0xf4);
  if (v === null) return Uint8Array.of(0xf6);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Invalid("only integers are written");
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (v instanceof Uint8Array) return concat([head(2, v.length), v]);
  if (typeof v === "string") {
    const e = new TextEncoder().encode(v);
    return concat([head(3, e.length), e]);
  }
  if (Array.isArray(v)) return concat([head(4, v.length), ...v.map(cborEncode)]);
  if (v instanceof Map) {
    const items = [...v.entries()].map(([k, x]) => [cborEncode(k), cborEncode(x)]);
    items.sort((a, b) => compare(a[0], b[0]));
    return concat([head(5, items.length), ...items.flat()]);
  }
  if (v instanceof Tag) return concat([head(6, v.tag), cborEncode(v.value)]);
  throw new Invalid("no encoding for this value");
}

// m builds a CBOR map from pairs, keeping insertion out of the encoding.
export function m(pairs: [number | string, unknown][]): Map<number | string, unknown> {
  return new Map(pairs);
}

// -- hashing and keys ---------------------------------------------------------

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export const ALG_ED25519 = -19, ALG_EDDSA = -8, ALG_MLDSA65 = -49;
const MLDSA65_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
  0x03, 0x82, 0x07, 0xa1, 0x00,
]);

export class Key {
  alg: number;
  pub: Uint8Array;
  constructor(alg: number, pub: Uint8Array) {
    if (alg !== ALG_ED25519 && alg !== ALG_MLDSA65) throw new Invalid(`algorithm ${alg} is not one this profile signs with`);
    if ((alg === ALG_ED25519 && pub.length !== 32) || (alg === ALG_MLDSA65 && pub.length !== 1952))
      throw new Invalid("a public key of the wrong length");
    this.alg = alg;
    this.pub = pub;
  }

  accepts(alg: number): boolean {
    return this.alg === ALG_ED25519 ? alg === ALG_ED25519 || alg === ALG_EDDSA : alg === ALG_MLDSA65;
  }

  kid(): Uint8Array {
    return this.alg === ALG_ED25519
      ? sha256(cborEncode(m([[1, 1], [-1, 6], [-2, this.pub]])))
      : sha256(cborEncode(m([[1, 7], [3, ALG_MLDSA65], [-1, this.pub]])));
  }

  verify(msg: Uint8Array, sig: Uint8Array): boolean {
    try {
      const key = this.alg === ALG_ED25519
        ? createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(this.pub).toString("base64url") }, format: "jwk" })
        : createPublicKey({ key: Buffer.from(concat([MLDSA65_SPKI_PREFIX, this.pub])), format: "der", type: "spki" });
      return cryptoVerify(null, msg, key, sig);
    } catch {
      return false;
    }
  }
}

// -- COSE_Sign1 ---------------------------------------------------------------

function isInt(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v);
}

export class Sign1 {
  protected_: Uint8Array;
  header: Map<number | string, unknown>;
  unprotected: Map<number | string, unknown>;
  payload: Uint8Array | null;
  signature: Uint8Array;

  constructor(raw: Uint8Array) {
    if (raw.length > 1 << 20) throw new Invalid("a message here is at most 1 MiB");
    const v = cborDecode(raw);
    if (!(v instanceof Tag) || v.tag !== 18 || !Array.isArray(v.value) || v.value.length !== 4)
      throw new Invalid("not a tagged COSE_Sign1");
    const [p, u, payload, sig] = v.value;
    if (!(p instanceof Uint8Array) || !(u instanceof Map) || !(sig instanceof Uint8Array))
      throw new Invalid("a COSE_Sign1 has the wrong shape");
    if (payload !== null && !(payload instanceof Uint8Array)) throw new Invalid("the payload is bytes or nil");
    const header = p.length ? cborDecode(p) : new Map();
    if (!(header instanceof Map)) throw new Invalid("the protected header is not a map");
    for (const k of header.keys()) if (u.has(k)) throw new Invalid("a label is in both headers");
    if (header.has(2) || u.has(2)) throw new Invalid("a critical header is not processed here");
    if (!isInt(header.get(1))) throw new Invalid("the protected header names no algorithm");
    this.protected_ = p;
    this.header = header;
    this.unprotected = u;
    this.payload = payload as Uint8Array | null;
    this.signature = sig;
  }

  verify(key: Key, detached: Uint8Array | null = null): void {
    const alg = this.header.get(1) as number;
    if (!key.accepts(alg)) throw new Invalid(`signed with algorithm ${alg}, which this key does not verify`);
    const kid = this.header.get(4);
    if (kid !== undefined && (!(kid instanceof Uint8Array) || !equal(kid, key.kid()))) throw new Invalid("the message names another key");
    if ((this.payload === null) === (detached === null)) throw new Invalid("a payload must be attached or given, not both or neither");
    const payload = this.payload ?? (detached as Uint8Array);
    const tbs = cborEncode(["Signature1", this.protected_, new Uint8Array(0), payload]);
    if (!key.verify(tbs, this.signature)) throw new Invalid("the signature does not verify");
  }

  entry(): Uint8Array {
    return cborEncode(new Tag(18, [this.protected_, new Map(), this.payload, this.signature]));
  }
}

// -- SCITT statements and RFC 9942 receipts -----------------------------------

function claim(c: Map<number | string, unknown>, k: number | string, name: string): string {
  const v = c.get(k);
  if (typeof v !== "string" || Buffer.byteLength(v) < 1 || Buffer.byteLength(v) > 8192)
    throw new Invalid(`the ${name} claim is 1 to 8192 bytes of text`);
  return v;
}

export class Statement {
  message: Sign1;
  issuer: string;
  subject: string;
  contentType: string | null;
  receipts: Uint8Array[];

  constructor(raw: Uint8Array) {
    this.message = new Sign1(raw);
    const c = this.message.header.get(15);
    if (!(c instanceof Map)) throw new Invalid("no CWT claims in the protected header");
    this.issuer = claim(c, 1, "issuer");
    this.subject = claim(c, 2, "subject");
    if (![4, 33, 34].some((l) => this.message.header.has(l))) throw new Invalid("the statement names no key");
    const ct = this.message.header.get(3);
    this.contentType = typeof ct === "string" ? ct : null;
    this.receipts = [];
    if (this.message.unprotected.has(394)) {
      const rs = this.message.unprotected.get(394);
      if (!Array.isArray(rs) || rs.length < 1 || rs.length > 16 || !rs.every((r) => r instanceof Uint8Array))
        throw new Invalid("receipts are 1 to 16 byte strings");
      this.receipts = rs as Uint8Array[];
    }
  }
}

function rootFromInclusion(leaf: Uint8Array, index: number, size: number, path: Uint8Array[]): Uint8Array {
  let fn = index, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) throw new Invalid("the proof is longer than the tree is deep");
    if (fn % 2 === 1 || fn === sn) {
      r = sha256(Uint8Array.of(1), p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = sha256(Uint8Array.of(1), r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Invalid("the proof is too short for its tree");
  return r;
}

export function verifyReceipt(raw: Uint8Array, entry: Uint8Array, key: Key): [string, Uint8Array] {
  const r = new Sign1(raw);
  if (r.header.get(395) !== 1) throw new Invalid("the receipt is not for an RFC 9162 tree");
  const c = r.header.get(15);
  if (!(c instanceof Map)) throw new Invalid("the receipt has no CWT claims");
  const issuer = claim(c, 1, "issuer");
  const proofs = r.unprotected.get(396);
  const incl = proofs instanceof Map ? proofs.get(-1) : undefined;
  if (!Array.isArray(incl) || incl.length !== 1 || !(incl[0] instanceof Uint8Array)) throw new Invalid("the receipt carries one inclusion proof");
  const p = cborDecode(incl[0]);
  if (!Array.isArray(p) || p.length !== 3) throw new Invalid("an inclusion proof is [size, index, path]");
  const [size, index, path] = p;
  if (!isInt(size) || !isInt(index) || size < 0 || index < 0 || index >= size) throw new Invalid("the leaf index is not below the tree size");
  if (!Array.isArray(path) || path.length > 64 || !path.every((h) => h instanceof Uint8Array && h.length === 32))
    throw new Invalid("the path is up to 64 hashes of 32 bytes");
  const root = rootFromInclusion(sha256(Uint8Array.of(0), entry), index, size, path as Uint8Array[]);
  r.verify(key, root);
  return [issuer, root];
}

export function verifyLogReceipts(st: Statement, keys: Key[]): void {
  const entry = st.message.entry();
  const found = new Map<number, [string, Uint8Array]>();
  for (const raw of st.receipts) {
    const r = new Sign1(raw);
    for (let i = 0; i < keys.length; i++) {
      if (found.has(i) || !keys[i].accepts(r.header.get(1) as number)) continue;
      const kid = r.header.get(4);
      if (kid instanceof Uint8Array && !equal(kid, keys[i].kid())) continue;
      found.set(i, verifyReceipt(raw, entry, keys[i]));
      break;
    }
  }
  if (found.size !== keys.length) throw new Invalid("a receipt in each of the log's algorithms is required");
  const first = found.get(0) as [string, Uint8Array];
  for (const [iss, root] of found.values())
    if (iss !== first[0] || !equal(root, first[1])) throw new Invalid("the log's receipts are for different trees");
}

// -- RFC 8785 canonical JSON ----------------------------------------------------

// parseJSON is JSON.parse that refuses what RFC 8785 refuses: a member named
// twice and a lone surrogate. JSON.parse keeps the last of two members and
// says nothing, so the text is walked here first.
export function parseJSON(text: string): unknown {
  let at = 0;
  const ws = () => {
    while (at < text.length && " \t\n\r".includes(text[at])) at++;
  };
  const str = (): string => {
    const start = at;
    at++;
    while (at < text.length && text[at] !== '"') at += text[at] === "\\" ? 2 : 1;
    if (at >= text.length) throw new Invalid("an unterminated string");
    at++;
    const s = JSON.parse(text.slice(start, at)) as string;
    if (!s.isWellFormed()) throw new Invalid("a lone surrogate");
    return s;
  };
  const value = (): void => {
    ws();
    const c = text[at];
    if (c === "{") {
      at++;
      const names = new Set<string>();
      ws();
      if (text[at] === "}") {
        at++;
        return;
      }
      for (;;) {
        ws();
        if (text[at] !== '"') throw new Invalid("a member name is a string");
        const k = str();
        if (names.has(k)) throw new Invalid("a member named twice");
        names.add(k);
        ws();
        if (text[at++] !== ":") throw new Invalid("a member without a value");
        value();
        ws();
        const d = text[at++];
        if (d === "}") return;
        if (d !== ",") throw new Invalid("a malformed object");
      }
    }
    if (c === "[") {
      at++;
      ws();
      if (text[at] === "]") {
        at++;
        return;
      }
      for (;;) {
        value();
        ws();
        const d = text[at++];
        if (d === "]") return;
        if (d !== ",") throw new Invalid("a malformed array");
      }
    }
    if (c === '"') {
      str();
      return;
    }
    const mt = /^(-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(at));
    if (!mt) throw new Invalid("not JSON");
    at += mt[0].length;
  };
  value();
  ws();
  if (at !== text.length) throw new Invalid("text after the value");
  const v = JSON.parse(text);
  return v;
}

export function jcs(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Invalid("not a finite number");
    return JSON.stringify(v); // ECMAScript's Number::toString is RFC 8785's
  }
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const o = v as Record<string, unknown>;
  // Default sort compares UTF-16 code units, as RFC 8785 requires.
  return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + jcs(o[k])).join(",") + "}";
}

export function argsDigest(text: string): Uint8Array {
  if (!text.trim()) text = "{}";
  return sha256(new TextEncoder().encode(jcs(parseJSON(text))));
}

// -- the protocol ----------------------------------------------------------------

export const ACTION = "application/vnd.aertun.aep.action+cbor";
export const RECONCILIATION = "application/vnd.aertun.aep.reconciliation+cbor";
const VANTAGES = ["agent", "gateway", "target", "sandbox"];
const OUTCOMES = ["ok", "error", "refused"];
const INSTANT = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$/;

// parseInstant is an instant as nanoseconds, refusing any writing but the one.
export function parseInstant(s: unknown): bigint {
  const mt = typeof s === "string" ? INSTANT.exec(s) : null;
  if (!mt) throw new Invalid("an instant is RFC 3339 in UTC");
  const frac = mt[7] ?? "";
  if (frac.endsWith("0")) throw new Invalid("an instant's fraction has no trailing zeros");
  const [y, mo, d, h, mi, se] = mt.slice(1, 7).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, se);
  const back = new Date(ms);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d || h > 23 || mi > 59 || se > 59)
    throw new Invalid("an instant that is not a time");
  return BigInt(ms) * 1_000_000n + BigInt(frac.padEnd(9, "0") || "0");
}

export function formatInstant(ns: bigint): string {
  const secs = ns / 1_000_000_000n, frac = ns % 1_000_000_000n;
  let s = new Date(Number(secs) * 1000).toISOString().slice(0, 19);
  if (frac) s += "." + frac.toString().padStart(9, "0").replace(/0+$/, "");
  return s + "Z";
}

function name(v: unknown, what: string, required: boolean): string {
  if ((v === undefined || v === "") && !required) return "";
  if (typeof v !== "string" || Buffer.byteLength(v) < 1 || Buffer.byteLength(v) > 2048 || /[\x00-\x1f\x7f]/.test(v))
    throw new Invalid(`the ${what} is 1 to 2048 bytes of text, no control characters`);
  return v;
}

export function actionDigest(target: unknown, tool: unknown, args: Uint8Array): Uint8Array {
  return sha256(cborEncode(["AEP-Action-v1", name(target, "target", true), name(tool, "tool", true), args]));
}

function fields(payload: Uint8Array | null, known: string[], required: string[]): Map<number | string, unknown> {
  if (payload === null) throw new Invalid("the payload is detached");
  const f = cborDecode(payload);
  if (!(f instanceof Map)) throw new Invalid("the payload is not a map");
  for (const k of f.keys()) if (typeof k !== "string" || !known.includes(k)) throw new Invalid("a payload key this version does not define");
  if (required.some((k) => !f.has(k)) || f.get("v") !== 1) throw new Invalid("a required key is missing, or the version is not 1");
  return f;
}

function digest32(f: Map<number | string, unknown>, k: string): Uint8Array {
  const v = f.get(k);
  if (!(v instanceof Uint8Array) || v.length !== 32) throw new Invalid(`"${k}" is not 32 bytes`);
  return v;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

export type Receipt = {
  digest: Uint8Array; target: string; tool: string; args: Uint8Array; vantage: string;
  at: bigint; actor: string; grant: string; outcome: string; seq: number | null;
};

export function readReceipt(raw: Uint8Array): [Statement, Receipt] {
  const st = new Statement(raw);
  if (st.contentType !== ACTION) throw new Invalid("not an action receipt");
  const f = fields(st.message.payload, ["v", "action", "target", "tool", "args", "vantage", "at", "actor", "grant", "outcome", "seq"],
    ["v", "action", "target", "tool", "args", "vantage", "at"]);
  for (const k of ["vantage", "actor", "grant", "outcome", "at"])
    if (f.has(k) && typeof f.get(k) !== "string") throw new Invalid(`"${k}" is not text`);
  const seq = f.get("seq");
  if (seq !== undefined && (!isInt(seq) || seq < 0)) throw new Invalid('"seq" is not an unsigned integer');
  const args = digest32(f, "args");
  const r: Receipt = {
    args, target: f.get("target") as string, tool: f.get("tool") as string, vantage: f.get("vantage") as string,
    at: parseInstant(f.get("at")), actor: name(f.get("actor"), "actor", false), grant: name(f.get("grant"), "grant", false),
    outcome: (f.get("outcome") as string) ?? "", seq: seq === undefined ? null : (seq as number),
    digest: actionDigest(f.get("target"), f.get("tool"), args),
  };
  if (!VANTAGES.includes(r.vantage) || (r.outcome && !OUTCOMES.includes(r.outcome))) throw new Invalid("an unknown vantage or outcome");
  if (!equal(r.digest, digest32(f, "action"))) throw new Invalid("the action digest is not the digest of its own inputs");
  if (st.subject !== "aep:action:" + hex(r.digest)) throw new Invalid("the subject is not the action digest");
  return [st, r];
}

export type Input = [string, Uint8Array, Receipt];

// reconcile is spec/aep/v1 section 5, returning the payload it states.
export function reconcile(inputs: Input[], from: bigint, to: bigint, tol: bigint, expectIn: [string, string][]): Map<number | string, unknown> {
  const expect = [...expectIn].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const vantage = new Map(expect);
  type Occ = { at: bigint; issuer: string; sum: Uint8Array; r: Receipt };
  const occs: Occ[] = [];
  const seen = new Set<string>();
  for (const [issuer, entry, r] of inputs) {
    if (vantage.get(issuer) !== r.vantage) throw new Invalid("a receipt from a party not expected, or at another vantage");
    if (r.at < from - tol || !(r.at < to + tol)) continue;
    const sum = sha256(entry);
    if (seen.has(hex(sum))) continue;
    seen.add(hex(sum));
    occs.push({ at: r.at, issuer, sum, r });
  }
  occs.sort((a, b) => (a.at !== b.at ? (a.at < b.at ? -1 : 1) : a.issuer !== b.issuer ? (a.issuer < b.issuer ? -1 : 1) : compare(a.sum, b.sum)));
  const inputsDigest = sha256(...occs.map((o) => o.sum).sort(compare));
  type Cluster = { digest: Uint8Array; tool: string; first: bigint; by: Map<string, Receipt> };
  const clusters: Cluster[] = [];
  const open = new Map<string, Cluster[]>();
  for (const o of occs) {
    const key = hex(o.r.digest);
    let live = open.get(key) ?? [];
    while (live.length && o.at - live[0].first > tol) live = live.slice(1);
    open.set(key, live);
    let into = live.find((c) => !c.by.has(o.issuer) && o.at - c.first <= tol);
    if (!into) {
      into = { digest: o.r.digest, tool: o.r.tool, first: o.at, by: new Map() };
      clusters.push(into);
      live.push(into);
    }
    into.by.set(o.issuer, o.r);
  }
  let actions = 0, complete = 0, gapsTotal = 0, splitsTotal = 0;
  const gaps: unknown[] = [], splits: unknown[] = [];
  for (const c of clusters) {
    if (c.first < from || c.first >= to) continue;
    actions++;
    const by = expect.filter(([i]) => c.by.has(i)).map(([i]) => i);
    const missing = expect.filter(([i]) => !c.by.has(i)).map(([i]) => i);
    const actors = new Map<string, string>();
    for (const i of by) {
      const a = (c.by.get(i) as Receipt).actor;
      if (a) actors.set(i, a);
    }
    if (!missing.length) complete++;
    else {
      gapsTotal++;
      if (gaps.length < 200) gaps.push(m([["action", c.digest], ["tool", c.tool], ["at", formatInstant(c.first)], ["seen_by", by], ["missing", missing]]));
    }
    if (new Set(actors.values()).size > 1) {
      splitsTotal++;
      if (splits.length < 200) splits.push(m([["action", c.digest], ["at", formatInstant(c.first)], ["actors", actors]]));
    }
  }
  const seqGaps: unknown[] = [];
  for (const [issuer] of expect) {
    const seqs = occs.filter((o) => o.issuer === issuer && o.r.seq !== null && from <= o.at && o.at < to)
      .map((o) => o.r.seq as number).sort((a, b) => a - b);
    const missingR: number[][] = [], repeated: number[] = [];
    for (let i = 1; i < seqs.length; i++) {
      const a = seqs[i - 1], b = seqs[i];
      if (a === b) {
        if (repeated.length < 200 && (!repeated.length || repeated[repeated.length - 1] !== b)) repeated.push(b);
      } else if (b > a + 1 && missingR.length < 200) missingR.push([a + 1, b - 1]);
    }
    if (missingR.length || repeated.length) seqGaps.push(m([["issuer", issuer], ["missing", missingR], ["repeated", repeated]]));
  }
  const verdict = !occs.length ? "inconclusive" : gapsTotal || splitsTotal || seqGaps.length ? "disagree" : "agree";
  return m([["v", 1], ["from", formatInstant(from)], ["to", formatInstant(to)], ["tolerance_ms", Number(tol / 1_000_000n)],
    ["expect", expect.map(([i, v]) => m([["issuer", i], ["vantage", v]]))], ["inputs", inputsDigest], ["receipts", occs.length],
    ["actions", actions], ["complete", complete], ["gaps", gaps], ["gaps_total", gapsTotal], ["seq_gaps", seqGaps],
    ["actor_splits", splits], ["actor_splits_total", splitsTotal], ["verdict", verdict]]);
}

export function checkReconciliation(raw: Uint8Array, inputs: Input[]): string {
  const st = new Statement(raw);
  if (st.contentType !== RECONCILIATION) throw new Invalid("not a reconciliation");
  const keys = ["v", "from", "to", "tolerance_ms", "expect", "inputs", "receipts", "actions", "complete", "gaps", "gaps_total",
    "seq_gaps", "actor_splits", "actor_splits_total", "verdict"];
  const f = fields(st.message.payload, keys, keys);
  if (st.subject !== "aep:reconciliation:" + hex(digest32(f, "inputs"))) throw new Invalid("the subject is not the inputs digest");
  const tolMs = f.get("tolerance_ms");
  if (!isInt(tolMs) || tolMs < 0 || tolMs > 60000) throw new Invalid("the tolerance is 0 to 60000 ms");
  const expect: [string, string][] = [];
  const ex = f.get("expect");
  for (const e of Array.isArray(ex) ? ex : []) {
    if (!(e instanceof Map) || e.size !== 2 || !VANTAGES.includes(e.get("vantage") as string)) throw new Invalid("an expected party is an issuer and a vantage");
    expect.push([claim(e, "issuer", "issuer"), e.get("vantage") as string]);
  }
  const from = parseInstant(f.get("from")), to = parseInstant(f.get("to"));
  if (expect.length < 2 || new Set(expect.map(([i]) => i)).size !== expect.length || !(from < to) || to - from > 31n * 86400n * 1_000_000_000n)
    throw new Invalid("a window of two or more parties, at most 31 days");
  const again = reconcile(inputs, from, to, BigInt(tolMs) * 1_000_000n, expect);
  if (!equal(cborEncode(again), st.message.payload as Uint8Array)) throw new Invalid("recomputing the reconciliation gives another result");
  return again.get("verdict") as string;
}

// -- vectors -------------------------------------------------------------------

type VectorKey = { alg: number; public: string };
export type Vector = {
  kind: string; valid: boolean; target?: string; tool?: string; args?: string; args_digest?: string; digest?: string;
  statement?: string; issuer_keys?: Record<string, VectorKey>; log_keys?: VectorKey[]; inputs?: string[]; verdict?: string;
};

const fromHex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));

function trusted(raw: Uint8Array, keys: Map<string, Key>): Statement {
  const st = new Statement(raw);
  const k = keys.get(st.issuer);
  if (!k) throw new Invalid("no key is given for " + st.issuer);
  st.message.verify(k);
  return st;
}

// checkVector throws when the vector does not verify.
export function checkVector(v: Vector): void {
  if (v.kind === "digest") {
    const a = argsDigest(v.args ?? "");
    if (hex(a) !== v.args_digest || hex(actionDigest(v.target, v.tool, a)) !== v.digest) throw new Invalid("a digest differs");
    return;
  }
  if (v.kind !== "statement") throw new Invalid("an unknown kind");
  const keys = new Map(Object.entries(v.issuer_keys ?? {}).map(([i, k]) => [i, new Key(k.alg, fromHex(k.public))] as [string, Key]));
  const raw = fromHex(v.statement ?? "");
  const st = trusted(raw, keys);
  if (v.log_keys?.length) verifyLogReceipts(st, v.log_keys.map((k) => new Key(k.alg, fromHex(k.public))));
  if (st.contentType === ACTION) {
    const [, r] = readReceipt(raw);
    if (v.args && !equal(argsDigest(v.args), r.args)) throw new Invalid("the receipt is not about these arguments");
    return;
  }
  if (st.contentType === RECONCILIATION) {
    const inputs: Input[] = (v.inputs ?? []).map((h) => {
      const ib = fromHex(h);
      const ist = trusted(ib, keys);
      return [ist.issuer, ist.message.entry(), readReceipt(ib)[1]];
    });
    const verdict = checkReconciliation(raw, inputs);
    if (v.verdict && verdict !== v.verdict) throw new Invalid("the reconciliation concludes otherwise");
    return;
  }
  throw new Invalid("a content type this profile does not define");
}

if (import.meta.main) {
  if (process.argv.length !== 3) {
    console.error(`usage: ${basename(process.argv[1])} VECTOR.json`);
    process.exit(2);
  }
  try {
    checkVector(JSON.parse(readFileSync(process.argv[2], "utf-8")) as Vector);
    console.log("verified");
  } catch (e) {
    console.log("refused: " + (e instanceof Error ? e.message : String(e)));
    process.exit(1);
  }
}
