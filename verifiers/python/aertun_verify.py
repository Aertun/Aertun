#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rashik Adhikari
# SPDX-License-Identifier: Apache-2.0
"""A verifier for the Aertun Evidence Protocol, version 1, in Python's
standard library alone.

It shares no code with the Go implementation: its own CBOR reader and
writer, COSE_Sign1 (RFC 9052), Ed25519 (RFC 8032), ML-DSA-65 (FIPS 204, with
SHAKE from hashlib), RFC 9162 inclusion proofs, RFC 8785 canonical JSON, and
the protocol's action digest, receipts and reconciliation, written from the
specification in spec/aep/v1.

    aertun_verify.py VECTOR.json     exit 0 if the vector verifies, 1 if not

so `aertun conform --verifier "python3 aertun_verify.py"` runs the protocol's
test vectors against it. Import it to verify statements in a program.
"""

import hashlib
import json
import os
import re
import sys
from decimal import Decimal

# -- CBOR (RFC 8949): a strict reader and a deterministic writer -------------

MAX_DEPTH = 16


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


class CBORError(ValueError):
    pass


def cbor_decode(b):
    v, at = _item(b, 0, 0)
    if at != len(b):
        raise CBORError("bytes follow the value")
    return v


def _arg(b, at, minor):
    if minor < 24:
        return minor, at
    if minor > 27:
        raise CBORError("indefinite or reserved length")
    n = 1 << (minor - 24)
    if at + n > len(b):
        raise CBORError("argument runs past the end")
    return int.from_bytes(b[at:at + n], "big"), at + n


def _item(b, at, depth):
    if at >= len(b):
        raise CBORError("value ends early")
    major, minor = b[at] >> 5, b[at] & 0x1F
    at += 1
    if major == 7:
        if minor == 20:
            return False, at
        if minor == 21:
            return True, at
        if minor == 22:
            return None, at
        raise CBORError("float, undefined or simple value")
    arg, at = _arg(b, at, minor)
    if major in (4, 5, 6) and depth + 1 > MAX_DEPTH:
        raise CBORError("nested too deep")
    if major == 0:
        return arg, at
    if major == 1:
        return -1 - arg, at
    if major in (2, 3):
        if arg > len(b) - at:
            raise CBORError("string runs past the end")
        raw = bytes(b[at:at + arg])
        if major == 3:
            return raw.decode("utf-8"), at + arg  # raises on invalid UTF-8
        return raw, at + arg
    if major == 4:
        if arg > len(b) - at:
            raise CBORError("array count beyond the bytes")
        out = []
        for _ in range(arg):
            v, at = _item(b, at, depth + 1)
            out.append(v)
        return out, at
    if major == 5:
        if arg > (len(b) - at) // 2:
            raise CBORError("map count beyond the bytes")
        out = {}
        for _ in range(arg):
            k, at = _item(b, at, depth + 1)
            if isinstance(k, bool) or not isinstance(k, (int, str)):
                raise CBORError("map key is not an integer or text")
            if k in out:
                raise CBORError("duplicate map key")
            v, at = _item(b, at, depth + 1)
            out[k] = v
        return out, at
    v, at = _item(b, at, depth + 1)
    return Tag(arg, v), at


def _head(major, n):
    m = major << 5
    if n < 24:
        return bytes([m | n])
    for code, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([m | code]) + n.to_bytes(size, "big")
    raise CBORError("integer too large")


def cbor_encode(v):
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        e = v.encode("utf-8")
        return _head(3, len(e)) + e
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor_encode(k), cbor_encode(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head(6, v.tag) + cbor_encode(v.value)
    raise CBORError("no encoding for %r" % type(v))


# -- Ed25519 (RFC 8032), verification only ------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _ed_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _ed_mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_encode(p):
    x, y, z, _ = p
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_BY = 4 * pow(5, _P - 2, _P) % _P
_B = _ed_decode(_BY.to_bytes(32, "little"))


def ed25519_verify(pub, msg, sig):
    if len(sig) != 64:
        return False
    A, R = _ed_decode(pub), _ed_decode(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    neg_a = ((_P - A[0]) % _P, A[1], A[2], (_P - A[3]) % _P)
    return _ed_encode(_ed_add(_ed_mul(s, _B), _ed_mul(k, neg_a))) == sig[:32]


# -- ML-DSA-65 (FIPS 204), verification only ----------------------------------

_Q, _N, _DROP = 8380417, 256, 13
_K, _LL, _TAU, _LAMBDA = 6, 5, 49, 192
_GAMMA1, _GAMMA2, _OMEGA = 1 << 19, (8380417 - 1) // 32, 55
_BETA = _TAU * 4


def _brv8(k):
    return int("{:08b}".format(k)[::-1], 2)


_ZETAS = [pow(1753, _brv8(k), _Q) for k in range(256)]


def _ntt(w):
    w = list(w)
    m, ln = 0, 128
    while ln >= 1:
        start = 0
        while start < 256:
            m += 1
            z = _ZETAS[m]
            for j in range(start, start + ln):
                t = z * w[j + ln] % _Q
                w[j + ln] = (w[j] - t) % _Q
                w[j] = (w[j] + t) % _Q
            start += 2 * ln
        ln //= 2
    return w


def _intt(w):
    w = list(w)
    m, ln = 256, 1
    while ln < 256:
        start = 0
        while start < 256:
            m -= 1
            z = -_ZETAS[m]
            for j in range(start, start + ln):
                t = w[j]
                w[j] = (t + w[j + ln]) % _Q
                w[j + ln] = z * (t - w[j + ln]) % _Q
            start += 2 * ln
        ln *= 2
    return [8347681 * x % _Q for x in w]


def _unpack(b, bits, count):
    v, mask = int.from_bytes(b, "little"), (1 << bits) - 1
    return [(v >> (bits * i)) & mask for i in range(count)]


def _pack(coeffs, bits):
    v = 0
    for i, c in enumerate(coeffs):
        v |= c << (bits * i)
    return v.to_bytes(bits * len(coeffs) // 8, "little")


def _shake(f, data, n):
    return f(data).digest(n)


def _rej_ntt_poly(seed):
    out, n = [], 840
    while True:
        stream = hashlib.shake_128(seed).digest(n)
        out, i = [], 0
        while len(out) < 256 and i + 3 <= len(stream):
            z = stream[i] | stream[i + 1] << 8 | (stream[i + 2] & 0x7F) << 16
            if z < _Q:
                out.append(z)
            i += 3
        if len(out) == 256:
            return out
        n *= 2


def _sample_in_ball(seed):
    n = 272
    while True:
        stream = hashlib.shake_256(seed).digest(n)
        signs, pos = int.from_bytes(stream[:8], "little"), 8
        c, ok = [0] * 256, True
        for i in range(256 - _TAU, 256):
            while True:
                if pos >= len(stream):
                    ok = False
                    break
                j = stream[pos]
                pos += 1
                if j <= i:
                    break
            if not ok:
                break
            c[i], c[j] = c[j], (-1 if signs & 1 else 1) % _Q
            signs >>= 1
        if ok:
            return c
        n *= 2


def _decompose(r):
    r = r % _Q
    r0 = r % (2 * _GAMMA2)
    if r0 > _GAMMA2:
        r0 -= 2 * _GAMMA2
    if r - r0 == _Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * _GAMMA2), r0


def _use_hint(h, r):
    m = (_Q - 1) // (2 * _GAMMA2)
    r1, r0 = _decompose(r)
    if h:
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m
    return r1


def mldsa65_verify(pk, msg, sig, ctx=b""):
    if len(pk) != 1952 or len(sig) != 3309 or len(ctx) > 255:
        return False
    rho, t1 = pk[:32], [_unpack(pk[32 + 320 * i:32 + 320 * (i + 1)], 10, 256) for i in range(_K)]
    ctilde = sig[:_LAMBDA // 4]
    zbytes = sig[_LAMBDA // 4:_LAMBDA // 4 + 640 * _LL]
    z = [[_GAMMA1 - x for x in _unpack(zbytes[640 * i:640 * (i + 1)], 20, 256)] for i in range(_LL)]
    y = sig[_LAMBDA // 4 + 640 * _LL:]
    h, index = [[0] * 256 for _ in range(_K)], 0
    for i in range(_K):
        if y[_OMEGA + i] < index or y[_OMEGA + i] > _OMEGA:
            return False
        first = index
        while index < y[_OMEGA + i]:
            if index > first and y[index - 1] >= y[index]:
                return False
            h[i][y[index]] = 1
            index += 1
    if any(y[i] for i in range(index, _OMEGA)):
        return False
    if max(abs(c) for poly in z for c in poly) >= _GAMMA1 - _BETA:
        return False
    tr = hashlib.shake_256(pk).digest(64)
    mu = hashlib.shake_256(tr + bytes([0, len(ctx)]) + ctx + msg).digest(64)
    c_hat = _ntt(_sample_in_ball(ctilde))
    z_hat = [_ntt([x % _Q for x in poly]) for poly in z]
    w1 = []
    for i in range(_K):
        acc = [0] * 256
        for j in range(_LL):
            a = _rej_ntt_poly(rho + bytes([j, i]))
            acc = [(acc[n] + a[n] * z_hat[j][n]) % _Q for n in range(256)]
        t_hat = _ntt([x << _DROP for x in t1[i]])
        approx = _intt([(acc[n] - c_hat[n] * t_hat[n]) % _Q for n in range(256)])
        w1.append([_use_hint(h[i][n], approx[n]) for n in range(256)])
    encoded = b"".join(_pack(poly, 4) for poly in w1)
    return hashlib.shake_256(mu + encoded).digest(_LAMBDA // 4) == ctilde


# -- keys, COSE_Sign1 (RFC 9052) and RFC 9679 thumbprints ---------------------

ALG_ED25519, ALG_EDDSA, ALG_MLDSA65 = -19, -8, -49


class Key:
    def __init__(self, alg, public):
        if alg not in (ALG_ED25519, ALG_MLDSA65):
            raise ValueError("algorithm %d is not one this profile signs with" % alg)
        self.alg, self.public = alg, public

    def accepts(self, alg):
        return alg in ((ALG_ED25519, ALG_EDDSA) if self.alg == ALG_ED25519 else (ALG_MLDSA65,))

    def kid(self):
        if self.alg == ALG_ED25519:
            return hashlib.sha256(cbor_encode({1: 1, -1: 6, -2: self.public})).digest()
        return hashlib.sha256(cbor_encode({1: 7, 3: ALG_MLDSA65, -1: self.public})).digest()

    def verify(self, msg, sig):
        if self.alg == ALG_ED25519:
            return ed25519_verify(self.public, msg, sig)
        return mldsa65_verify(self.public, msg, sig)


class Invalid(Exception):
    pass


class Sign1:
    """A tagged COSE_Sign1, its headers checked, its signature not yet."""

    def __init__(self, raw):
        if len(raw) > 1 << 20:
            raise Invalid("a message here is at most 1 MiB")
        try:
            v = cbor_decode(raw)
        except (CBORError, UnicodeDecodeError) as e:
            raise Invalid("not CBOR: %s" % e)
        if not isinstance(v, Tag) or v.tag != 18 or not isinstance(v.value, list) or len(v.value) != 4:
            raise Invalid("not a tagged COSE_Sign1")
        protected, unprotected, payload, signature = v.value
        if not isinstance(protected, bytes) or not isinstance(unprotected, dict) or not isinstance(signature, bytes):
            raise Invalid("a COSE_Sign1 has the wrong shape")
        if payload is not None and not isinstance(payload, bytes):
            raise Invalid("the payload is bytes or nil")
        try:
            header = cbor_decode(protected) if protected else {}
        except (CBORError, UnicodeDecodeError) as e:
            raise Invalid("the protected header: %s" % e)
        if not isinstance(header, dict):
            raise Invalid("the protected header is not a map")
        if set(header) & set(unprotected):
            raise Invalid("a label is in both headers")
        if 2 in header or 2 in unprotected:
            raise Invalid("a critical header is not processed here")
        if not isinstance(header.get(1), int) or isinstance(header.get(1), bool):
            raise Invalid("the protected header names no algorithm")
        self.protected, self.header, self.unprotected = protected, header, unprotected
        self.payload, self.signature = payload, signature

    def verify(self, key, detached=None):
        if not key.accepts(self.header[1]):
            raise Invalid("signed with algorithm %d, which this key does not verify" % self.header[1])
        kid = self.header.get(4)
        if kid is not None and kid != key.kid():
            raise Invalid("the message names another key")
        if (self.payload is None) == (detached is None):
            raise Invalid("a payload must be attached or given, not both or neither")
        payload = self.payload if self.payload is not None else detached
        tbs = cbor_encode(["Signature1", self.protected, b"", payload])
        if not key.verify(tbs, self.signature):
            raise Invalid("the signature does not verify")

    def entry(self):
        return cbor_encode(Tag(18, [self.protected, {}, self.payload, self.signature]))


# -- SCITT statements and RFC 9942 receipts -----------------------------------


def _claim(c, k, name):
    v = c.get(k)
    if not isinstance(v, str) or not 1 <= len(v.encode()) <= 8192:
        raise Invalid("the %s claim is 1 to 8192 bytes of text" % name)
    return v


class Statement:
    def __init__(self, raw):
        self.message = m = Sign1(raw)
        c = m.header.get(15)
        if not isinstance(c, dict):
            raise Invalid("no CWT claims in the protected header")
        self.issuer, self.subject = _claim(c, 1, "issuer"), _claim(c, 2, "subject")
        if 4 not in m.header and 33 not in m.header and 34 not in m.header:
            raise Invalid("the statement names no key")
        ct = m.header.get(3)
        self.content_type = ct if isinstance(ct, str) else None
        self.receipts = []
        if 394 in m.unprotected:
            rs = m.unprotected[394]
            if not isinstance(rs, list) or not 1 <= len(rs) <= 16 or not all(isinstance(r, bytes) for r in rs):
                raise Invalid("receipts are 1 to 16 byte strings")
            self.receipts = rs


def _root_from_inclusion(leaf, index, size, path):
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            raise Invalid("the proof is longer than the tree is deep")
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn, sn = fn >> 1, sn >> 1
    if sn:
        raise Invalid("the proof is too short for its tree")
    return r


def verify_receipt(raw, entry, key):
    m = Sign1(raw)
    if m.header.get(395) != 1:
        raise Invalid("the receipt is not for an RFC 9162 tree")
    c = m.header.get(15)
    if not isinstance(c, dict):
        raise Invalid("the receipt has no CWT claims")
    issuer = _claim(c, 1, "issuer")
    proofs = m.unprotected.get(396, {})
    incl = proofs.get(-1) if isinstance(proofs, dict) else None
    if not isinstance(incl, list) or len(incl) != 1 or not isinstance(incl[0], bytes):
        raise Invalid("the receipt carries one inclusion proof")
    p = cbor_decode(incl[0])
    if not isinstance(p, list) or len(p) != 3:
        raise Invalid("an inclusion proof is [size, index, path]")
    size, index, path = p
    if not all(isinstance(x, int) and x >= 0 for x in (size, index)) or index >= size:
        raise Invalid("the leaf index is not below the tree size")
    if not isinstance(path, list) or len(path) > 64 or not all(isinstance(h, bytes) and len(h) == 32 for h in path):
        raise Invalid("the path is up to 64 hashes of 32 bytes")
    root = _root_from_inclusion(hashlib.sha256(b"\x00" + entry).digest(), index, size, path)
    m.verify(key, detached=root)
    return issuer, root


def verify_log_receipts(statement, keys):
    entry, found = statement.message.entry(), {}
    for raw in statement.receipts:
        m = Sign1(raw)
        for i, k in enumerate(keys):
            if i in found or not k.accepts(m.header[1]):
                continue
            if m.header.get(4) is not None and m.header[4] != k.kid():
                continue
            found[i] = verify_receipt(raw, entry, k)
            break
    if len(found) != len(keys):
        raise Invalid("a receipt in each of the log's algorithms is required")
    if len({found[i] for i in found}) != 1:
        raise Invalid("the log's receipts are for different trees")


# -- RFC 8785 canonical JSON ---------------------------------------------------


def _jcs_number(x):
    if isinstance(x, bool) or x != x or x in (float("inf"), float("-inf")):
        raise ValueError("not a finite number")
    x = float(x)
    if x == 0:
        return "0"
    sign, x = ("-", -x) if x < 0 else ("", x)
    d = Decimal(repr(x)).normalize()
    digits = "".join(str(t) for t in d.as_tuple().digits)
    k, n = len(digits), d.adjusted() + 1
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * -n + digits
    else:
        e = n - 1
        s = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + s


def _jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF:
            raise ValueError("a lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _jcs_number(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v[k]) for k in keys) + "}"


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("a member named twice")
        out[k] = v
    return out


def args_digest(text):
    if not text.strip():
        text = "{}"
    v = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    return hashlib.sha256(_jcs(v).encode("utf-8")).digest()


# -- the protocol ---------------------------------------------------------------

ACTION = "application/vnd.aertun.aep.action+cbor"
RECONCILIATION = "application/vnd.aertun.aep.reconciliation+cbor"
VANTAGES = ("agent", "gateway", "target", "sandbox")
OUTCOMES = ("ok", "error", "refused")
_INSTANT = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$")


def parse_instant(s):
    """An instant as integer nanoseconds, refusing any writing but the one."""
    import calendar
    m = _INSTANT.match(s) if isinstance(s, str) else None
    if not m:
        raise Invalid("an instant is RFC 3339 in UTC")
    frac = m.group(7) or ""
    if frac.endswith("0"):
        raise Invalid("an instant's fraction has no trailing zeros")
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h < 24 and mi < 60 and se < 60):
        raise Invalid("an instant that is not a time")
    secs = calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0))
    return secs * 10**9 + int(frac.ljust(9, "0") or 0)


def format_instant(ns):
    import time
    secs, frac = divmod(ns, 10**9)
    s = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs))
    if frac:
        s += "." + ("%09d" % frac).rstrip("0")
    return s + "Z"


def _name(v, what, required):
    if v is None and not required:
        return ""
    if not isinstance(v, str) or not 1 <= len(v.encode()) <= 2048 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        raise Invalid("the %s is 1 to 2048 bytes of text, no control characters" % what)
    return v


def action_digest(target, tool, args):
    _name(target, "target", True)
    _name(tool, "tool", True)
    return hashlib.sha256(cbor_encode(["AEP-Action-v1", target, tool, args])).digest()


def _fields(payload, known, required):
    if payload is None:
        raise Invalid("the payload is detached")
    f = cbor_decode(payload)
    if not isinstance(f, dict) or any(not isinstance(k, str) or k not in known for k in f):
        raise Invalid("a payload key this version does not define")
    if any(k not in f for k in required) or f.get("v") != 1 or isinstance(f.get("v"), bool):
        raise Invalid("a required key is missing, or the version is not 1")
    return f


def _digest32(f, k):
    v = f.get(k)
    if not isinstance(v, bytes) or len(v) != 32:
        raise Invalid('"%s" is not 32 bytes' % k)
    return v


def read_receipt(raw):
    st = Statement(raw)
    if st.content_type != ACTION:
        raise Invalid("not an action receipt")
    f = _fields(st.message.payload,
                ("v", "action", "target", "tool", "args", "vantage", "at", "actor", "grant", "outcome", "seq"),
                ("v", "action", "target", "tool", "args", "vantage", "at"))
    r = {"args": _digest32(f, "args"), "target": f["target"], "tool": f["tool"]}
    for k in ("vantage", "actor", "grant", "outcome", "at"):
        if k in f and not isinstance(f[k], str):
            raise Invalid('"%s" is not text' % k)
    r["vantage"], r["at"] = f["vantage"], parse_instant(f["at"])
    r["actor"], r["grant"], r["outcome"] = f.get("actor", ""), f.get("grant", ""), f.get("outcome", "")
    _name(r["actor"] or None, "actor", False)
    _name(r["grant"] or None, "grant", False)
    if r["vantage"] not in VANTAGES or (r["outcome"] and r["outcome"] not in OUTCOMES):
        raise Invalid("an unknown vantage or outcome")
    if "seq" in f and (not isinstance(f["seq"], int) or isinstance(f["seq"], bool) or f["seq"] < 0):
        raise Invalid('"seq" is not an unsigned integer')
    r["seq"] = f.get("seq")
    r["digest"] = action_digest(r["target"], r["tool"], r["args"])
    if r["digest"] != _digest32(f, "action"):
        raise Invalid("the action digest is not the digest of its own inputs")
    if st.subject != "aep:action:" + r["digest"].hex():
        raise Invalid("the subject is not the action digest")
    return st, r


def reconcile(inputs, frm, to, tol, expect):
    """The reconciliation of spec/aep/v1 section 5, as its payload."""
    expect = sorted(expect)
    vantage = dict(expect)
    occs, seen = [], set()
    for issuer, entry, r in inputs:
        if issuer not in vantage or vantage[issuer] != r["vantage"]:
            raise Invalid("a receipt from a party not expected, or at another vantage")
        if r["at"] < frm - tol or not r["at"] < to + tol:
            continue
        s = hashlib.sha256(entry).digest()
        if s in seen:
            continue
        seen.add(s)
        occs.append((r["at"], issuer, s, r))
    occs.sort(key=lambda o: (o[0], o[1], o[2]))
    inputs_digest = hashlib.sha256(b"".join(sorted(o[2] for o in occs))).digest()
    clusters, open_ = [], {}
    for at, issuer, _, r in occs:
        live = open_.setdefault(r["digest"], [])
        while live and at - live[0]["first"] > tol:
            live.pop(0)
        into = next((c for c in live if issuer not in c["by"] and at - c["first"] <= tol), None)
        if into is None:
            into = {"digest": r["digest"], "tool": r["tool"], "first": at, "by": {}}
            clusters.append(into)
            live.append(into)
        into["by"][issuer] = r
    actions = complete = gaps_total = splits_total = 0
    gaps, splits = [], []
    for c in clusters:
        if c["first"] < frm or c["first"] >= to:
            continue
        actions += 1
        by = [i for i, _ in expect if i in c["by"]]
        missing = [i for i, _ in expect if i not in c["by"]]
        actors = {i: c["by"][i]["actor"] for i in by if c["by"][i]["actor"]}
        if not missing:
            complete += 1
        else:
            gaps_total += 1
            if len(gaps) < 200:
                gaps.append({"action": c["digest"], "tool": c["tool"], "at": format_instant(c["first"]),
                             "seen_by": by, "missing": missing})
        if len(set(actors.values())) > 1:
            splits_total += 1
            if len(splits) < 200:
                splits.append({"action": c["digest"], "at": format_instant(c["first"]), "actors": actors})
    seq_gaps = []
    for issuer, _ in expect:
        seqs = sorted(o[3]["seq"] for o in occs if o[1] == issuer and o[3]["seq"] is not None
                      and frm <= o[0] < to)
        missing_r, repeated = [], []
        for a, b in zip(seqs, seqs[1:]):
            if a == b:
                if len(repeated) < 200 and (not repeated or repeated[-1] != b):
                    repeated.append(b)
            elif b > a + 1 and len(missing_r) < 200:
                missing_r.append([a + 1, b - 1])
        if missing_r or repeated:
            seq_gaps.append({"issuer": issuer, "missing": missing_r, "repeated": repeated})
    if not occs:
        verdict = "inconclusive"
    elif gaps_total or splits_total or seq_gaps:
        verdict = "disagree"
    else:
        verdict = "agree"
    return {"v": 1, "from": format_instant(frm), "to": format_instant(to), "tolerance_ms": tol // 10**6,
            "expect": [{"issuer": i, "vantage": v} for i, v in expect], "inputs": inputs_digest,
            "receipts": len(occs), "actions": actions, "complete": complete, "gaps": gaps,
            "gaps_total": gaps_total, "seq_gaps": seq_gaps, "actor_splits": splits,
            "actor_splits_total": splits_total, "verdict": verdict}


def check_reconciliation(raw, inputs):
    st = Statement(raw)
    if st.content_type != RECONCILIATION:
        raise Invalid("not a reconciliation")
    keys = ("v", "from", "to", "tolerance_ms", "expect", "inputs", "receipts", "actions", "complete", "gaps",
            "gaps_total", "seq_gaps", "actor_splits", "actor_splits_total", "verdict")
    f = _fields(st.message.payload, keys, keys)
    if st.subject != "aep:reconciliation:" + _digest32(f, "inputs").hex():
        raise Invalid("the subject is not the inputs digest")
    tol = f["tolerance_ms"]
    if not isinstance(tol, int) or isinstance(tol, bool) or not 0 <= tol <= 60000:
        raise Invalid("the tolerance is 0 to 60000 ms")
    expect = []
    for e in f["expect"] if isinstance(f["expect"], list) else []:
        if not isinstance(e, dict) or set(e) != {"issuer", "vantage"} or e["vantage"] not in VANTAGES:
            raise Invalid("an expected party is an issuer and a vantage")
        expect.append((_claim(e, "issuer", "issuer"), e["vantage"]))
    frm, to = parse_instant(f["from"]), parse_instant(f["to"])
    if len(expect) < 2 or len({i for i, _ in expect}) != len(expect) or not frm < to or to - frm > 31 * 86400 * 10**9:
        raise Invalid("a window of two or more parties, at most 31 days")
    again = reconcile(inputs, frm, to, tol * 10**6, expect)
    if cbor_encode(again) != st.message.payload:
        raise Invalid("recomputing the reconciliation gives another result")
    return again


# -- vectors ---------------------------------------------------------------------


def _trusted(raw, keys):
    st = Statement(raw)
    k = keys.get(st.issuer)
    if k is None:
        raise Invalid("no key is given for " + st.issuer)
    st.message.verify(k)
    return st


def check_vector(v):
    """Raises Invalid (or ValueError) when the vector does not verify."""
    if v["kind"] == "digest":
        a = args_digest(v["args"])
        if a.hex() != v["args_digest"] or action_digest(v["target"], v["tool"], a).hex() != v["digest"]:
            raise Invalid("a digest differs")
        return
    if v["kind"] != "statement":
        raise Invalid("an unknown kind")
    keys = {iss: Key(k["alg"], bytes.fromhex(k["public"])) for iss, k in v.get("issuer_keys", {}).items()}
    raw = bytes.fromhex(v["statement"])
    st = _trusted(raw, keys)
    if v.get("log_keys"):
        verify_log_receipts(st, [Key(k["alg"], bytes.fromhex(k["public"])) for k in v["log_keys"]])
    if st.content_type == ACTION:
        _, r = read_receipt(raw)
        if v.get("args") and args_digest(v["args"]) != r["args"]:
            raise Invalid("the receipt is not about these arguments")
        return
    if st.content_type == RECONCILIATION:
        inputs = []
        for h in v.get("inputs", []):
            ib = bytes.fromhex(h)
            ist = _trusted(ib, keys)
            _, r = read_receipt(ib)
            inputs.append((ist.issuer, ist.message.entry(), r))
        res = check_reconciliation(raw, inputs)
        if v.get("verdict") and res["verdict"] != v["verdict"]:
            raise Invalid("the reconciliation concludes otherwise")
        return
    raise Invalid("a content type this profile does not define")


def main(argv=None):
    # None when installed: the aertun-verify command calls main() bare.
    argv = sys.argv if argv is None else argv
    if len(argv) != 2:
        print("usage: %s VECTOR.json" % os.path.basename(argv[0]), file=sys.stderr)
        return 2
    with open(argv[1], "rb") as f:
        vector = json.load(f)
    try:
        check_vector(vector)
    except (Invalid, CBORError, ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
        print("refused: %s" % e)
        return 1
    print("verified")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
