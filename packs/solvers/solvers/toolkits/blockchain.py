#!/usr/bin/env python3
"""Toolkit blockchain: READ-ONLY, artifact-only analysis of EVM and Bitcoin material (Day-31 finale
coverage; the 25-day retrospective listed blockchain as an absent category). Offline. Nothing is
executed: no contract is deployed or called, no RPC or network request is made, no chain is read, and
nothing is ever signed. Bytes in, facts out.

  EVM transaction     raw tx (legacy, EIP-155, EIP-2930, EIP-1559, EIP-4844, EIP-7702; strict canonical RLP):
                      nonce, gas limit, gas price / max fee / tip, to, value, chain id, calldata, the
                      4-byte selector, the tx hash and the SENDER (ecrecover of the signing hash,
                      pure-Python secp256k1, the recovered key re-verified against the signature);
                      an EIP-7702 tx also gives each authorization's delegate address and AUTHORITY
  selectors / ABI     selector = keccak256(signature)[:4]; a provided ABI json names the function and
                      decodes calldata and event logs (static types, bytes, string, T[], T[k], and since
                      B-243 tuples, nested tuples, tuple[] and arrays of dynamic types, which must be the
                      exact canonical encoding); a small common-selector table is a CANDIDATE only
                      (4-byte collisions exist), never proof
  EVM bytecode        disassembly, the solc `PUSH4 sel [DUPn] EQ PUSHn dest JUMPI` dispatch table,
                      the constructor/runtime split (the solc CODECOPY/RETURN tail), the solc
                      metadata version, PUSH-literal strings
  addresses / keys    EIP-55 checksum, address from a provided public key, from a provided private
                      key (only when the challenge supplies it; the key itself is NEVER emitted),
                      ecrecover of a provided (hash or EIP-191 message, signature)
  encodings           base58check (BTC P2PKH/P2SH, WIF recognised but never decoded out), bech32 and
                      bech32m segwit addresses (own BIP173/BIP350 implementation, test-vectored)
  Bitcoin raw tx      legacy and segwit: version, inputs, outputs, scriptPubKey types and addresses,
                      txid, wtxid, locktime, size, weight

Libraries: eth-utils, web3, eth-abi, rlp, coincurve and bech32 are NOT in the venv, so RLP, ABI, bech32,
base58check and secp256k1 are small own implementations, each checked against published vectors in
tests/test_day26_blockchain.py. Keccak-256 needs pycryptodome (`Crypto` or `Cryptodome`); without it every
keccak-dependent feature declines (None), nothing is half-done.

HARD RULES (AGENTS.md "Uncertain answers", the bright line):
  - Every answer is labels.pick(blockchain.<field>/<shape>, options): a fact the bytes prove, offered in
    its renderings (checksummed address first, wei before ether when the question says wei, ...); the
    runners probe it on the untimed base and the ledger makes it plain only after the judge accepted the
    rendering. A fact that rests on a heuristic (a dispatch pattern, a split pattern, the common-selector
    table, the mainnet rendering of an address) carries that in its SHAPE.
  - A malformed, truncated, non-canonical, ambiguous or absent input is None, never a partial guess. A
    question that names two fields, or two candidate artifacts, is None (the exactly-one router).
  - A private key, WIF, seed phrase, xprv or flag is ALWAYS None, never in any answer string (a final
    guard drops any answer that contains a secret the artifacts carry), never used outward.
"""
import argparse
import hashlib
import hmac
import json
import math
import re
import struct
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "blockchain"
MAX_FILE = 4 * 1024 * 1024
MAX_INSNS = 400000
MAX_WALLET_JSON = 4 * 1024 * 1024
MAX_DERIVATION_DEPTH = 255
MAX_DERIVATION_PATHS = 256
MAX_KEYSTORE_CIPHERTEXT = 4 * 1024 * 1024

# ---------------------------------------------------------------------------- keccak-256 (pycryptodome only)

_keccak_mod = None
for _name in ("Crypto.Hash.keccak", "Cryptodome.Hash.keccak"):
    try:
        _keccak_mod = __import__(_name, fromlist=["new"])
        break
    except Exception:  # noqa: BLE001
        continue


def _bytes_or_none(value):
    """Normalize binary inputs without coercing integers or text to evidence."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def keccak(data: bytes):
    """Keccak-256 (the Ethereum one, NOT SHA3-256), or None when no library provides it."""
    data = _bytes_or_none(data)
    if _keccak_mod is None or data is None:
        return None
    return _keccak_mod.new(digest_bits=256, data=data).digest()


def sha256d(b: bytes) -> bytes:
    b = _bytes_or_none(b)
    if b is None:
        return None
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b: bytes) -> bytes:
    b = _bytes_or_none(b)
    if b is None:
        return None
    try:
        return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
    except Exception:  # noqa: BLE001 - OpenSSL 3 may lack ripemd160
        return _ripemd160(hashlib.sha256(b).digest())


# ---------------------------------------------------------------------------- RIPEMD-160 (fallback only)

def _ripemd160(data: bytes) -> bytes:
    rl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    kl = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]
    M = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & M

    def f(j, x, y, z):
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & M & z)
        if j < 48:
            return (x | (~y & M)) ^ z
        if j < 64:
            return (x & z) | (y & (~z & M))
        return x ^ (y | (~z & M))

    msg = bytearray(data) + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\0"
    msg += struct.pack("<Q", len(data) * 8)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        a, b, c, d, e = h
        a2, b2, c2, d2, e2 = h
        for j in range(80):
            t = (rol((a + f(j, b, c, d) + x[rl[j]] + kl[j // 16]) & M, sl[j]) + e) & M
            a, e, d, c, b = e, d, rol(c, 10), b, t
            t = (rol((a2 + f(79 - j, b2, c2, d2) + x[rr[j]] + kr[j // 16]) & M, sr[j]) + e2) & M
            a2, e2, d2, c2, b2 = e2, d2, rol(c2, 10), b2, t
        t = (h[1] + c + d2) & M
        h = [t, (h[2] + d + e2) & M, (h[3] + e + a2) & M, (h[4] + a + b2) & M, (h[0] + b + c2) & M]
    return struct.pack("<5I", *h)


# ---------------------------------------------------------------------------- secp256k1 (pure Python, public data only)

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv(a, m):
    return pow(a, -1, m)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _P == 0:
            return None
        lam = 3 * p[0] * p[0] * _inv(2 * p[1], _P) % _P
    else:
        lam = (q[1] - p[1]) * _inv(q[0] - p[0], _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return (x, (lam * (p[0] - x) - p[1]) % _P)


def _mul(k, p):
    r = None
    k %= _N
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _on_curve(pt):
    return pt is not None and 0 <= pt[0] < _P and 0 <= pt[1] < _P and (pt[1] * pt[1] - pt[0] ** 3 - 7) % _P == 0


def _lift_x(x, odd):
    if not 0 <= x < _P:
        return None
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        return None
    return (x, y if (y & 1) == odd else _P - y)


def _verify(z, r, s, pub):
    if not (1 <= r < _N and 1 <= s < _N and _on_curve(pub)):
        return False
    w = _inv(s, _N)
    pt = _add(_mul(z * w % _N, _G), _mul(r * w % _N, pub))
    return pt is not None and pt[0] % _N == r


def ecrecover_pub(h32: bytes, r: int, s: int, recid: int):
    """The public key (x, y) that signed the 32-byte hash, or None; re-verified against the signature."""
    if not isinstance(h32, (bytes, bytearray, memoryview)) or any(type(v) is not int for v in (r, s, recid)):
        return None
    try:
        if (h32.nbytes if isinstance(h32, memoryview) else len(h32)) != 32:
            return None
        h32 = bytes(h32)
    except (TypeError, ValueError):
        return None
    if recid not in (0, 1) or not (1 <= r < _N and 1 <= s < _N):
        return None
    R = _lift_x(r, recid & 1)
    if R is None:
        return None
    z = int.from_bytes(h32, "big")
    rinv = _inv(r, _N)
    q = _mul(rinv, _add(_mul(s, R), _mul(-z, _G)))
    if q is None or not _verify(z, r, s, q):
        return None
    return q


def pub_to_address(pt):
    if (not isinstance(pt, (tuple, list)) or len(pt) != 2
            or any(type(v) is not int for v in pt) or not _on_curve(pt)):
        return None
    k = keccak(pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big"))
    return None if k is None else k[12:]


def parse_pubkey(b: bytes):
    """A secp256k1 public key from 64 (x||y), 65 (04||x||y) or 33 (02/03||x) bytes, ON the curve, else None."""
    b = _bytes_or_none(b)
    if b is None:
        return None
    if len(b) == 65 and b[0] == 4:
        b = b[1:]
    if len(b) == 64:
        pt = (int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big"))
        return pt if _on_curve(pt) else None
    if len(b) == 33 and b[0] in (2, 3):
        return _lift_x(int.from_bytes(b[1:], "big"), b[0] & 1)
    return None


# ---------------------------------------------------------------------------- RLP (strict canonical)

class _Bad(ValueError):
    pass


def _rlp_item(d, i, depth=0):
    if depth > 6 or i >= len(d):
        raise _Bad("rlp")
    b = d[i]
    if b < 0x80:
        return d[i:i + 1], i + 1
    if b <= 0xB7:
        n = b - 0x80
        end = i + 1 + n
        if end > len(d) or (n == 1 and d[i + 1] < 0x80):
            raise _Bad("rlp")
        return d[i + 1:end], end
    if b <= 0xBF:
        ln = b - 0xB7
        if i + 1 + ln > len(d) or d[i + 1] == 0:
            raise _Bad("rlp")
        n = int.from_bytes(d[i + 1:i + 1 + ln], "big")
        if n <= 55:
            raise _Bad("rlp")
        end = i + 1 + ln + n
        if end > len(d):
            raise _Bad("rlp")
        return d[i + 1 + ln:end], end
    if b <= 0xF7:
        n, start = b - 0xC0, i + 1
    else:
        ln = b - 0xF7
        if i + 1 + ln > len(d) or d[i + 1] == 0:
            raise _Bad("rlp")
        n = int.from_bytes(d[i + 1:i + 1 + ln], "big")
        if n <= 55:
            raise _Bad("rlp")
        start = i + 1 + ln
    end = start + n
    if end > len(d):
        raise _Bad("rlp")
    items, j = [], start
    while j < end:
        it, j = _rlp_item(d, j, depth + 1)
        items.append(it)
    if j != end:
        raise _Bad("rlp")
    return items, end


def rlp_decode(d: bytes):
    """One RLP item that consumes the whole buffer (canonical forms only), else None."""
    d = _bytes_or_none(d)
    if d is None:
        return None
    try:
        it, j = _rlp_item(d, 0)
    except (_Bad, IndexError):
        return None
    return it if j == len(d) else None


def rlp_encode(x) -> bytes:
    if isinstance(x, int):
        if x < 0:
            return None
        x = x.to_bytes((x.bit_length() + 7) // 8, "big") if x else b""
    if isinstance(x, (bytes, bytearray)):
        x = bytes(x)
        if len(x) == 1 and x[0] < 0x80:
            return x
        return _rlp_len(len(x), 0x80) + x
    try:
        items = [rlp_encode(e) for e in x]
        if any(item is None for item in items):
            return None
        body = b"".join(items)
    except (TypeError, RecursionError):
        return None
    return _rlp_len(len(body), 0xC0) + body


def _rlp_len(n, off):
    if n <= 55:
        return bytes([off + n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(nb)]) + nb


# ---------------------------------------------------------------------------- addresses (EIP-55) and encodings

def eip55(addr20: bytes):
    addr20 = _bytes_or_none(addr20)
    if addr20 is None or len(addr20) != 20:
        return None
    k = keccak(addr20.hex().encode())
    if k is None:
        return None
    h = k.hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 and c.isalpha() else c for i, c in enumerate(addr20.hex()))


_ADDR_RE = re.compile(r"(?<![0-9A-Za-z])0x([0-9a-fA-F]{40})(?![0-9A-Za-z])")


def classify_eth_address(text: str):
    """{'bytes', 'checksum': 'valid'|'invalid'|'none'} for an 0x + 40 hex string, else None.
    'none' is all-lowercase or all-uppercase hex: it carries no checksum to validate."""
    if not isinstance(text, str):
        return None
    m = re.fullmatch(r"0x([0-9a-fA-F]{40})", text.strip())
    if not m:
        return None
    s = m.group(1)
    raw = bytes.fromhex(s)
    ck = eip55(raw)
    if ck is None:
        return None
    if s == s.lower() or s == s.upper():
        return {"bytes": raw, "checksum": "none", "checksummed": ck}
    return {"bytes": raw, "checksum": "valid" if ck[2:] == s else "invalid", "checksummed": ck}


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str):
    if not isinstance(s, str) or not s or any(c not in _B58 for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(b: bytes) -> str:
    b = _bytes_or_none(b)
    if b is None:
        return None
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58check_decode(s: str):
    """(version_byte, payload) of a base58check string with a valid double-SHA256 checksum, else None."""
    if not isinstance(s, str):
        return None
    raw = b58decode(s.strip())
    if raw is None or len(raw) < 5 or sha256d(raw[:-4])[:4] != raw[-4:]:
        return None
    return raw[0], raw[1:-4]


def b58check_encode(version: int, payload: bytes) -> str:
    payload = _bytes_or_none(payload)
    if type(version) is not int or not 0 <= version <= 255 or payload is None:
        return None
    raw = bytes([version]) + payload
    return b58encode(raw + sha256d(raw)[:4])


_CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32, _BECH32M = 1, 0x2BC830A3


def _polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(s: str):
    """(hrp, data5, spec) with spec 'bech32'|'bech32m' for a string whose checksum verifies, else None."""
    if not isinstance(s, str) or not s or len(s) > 90 or any(ord(c) < 33 or ord(c) > 126 for c in s) or (s.lower() != s and s.upper() != s):
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or any(c not in _CS for c in s[pos + 1:]):
        return None
    hrp, data = s[:pos], [_CS.find(c) for c in s[pos + 1:]]
    const = _polymod(_hrp_expand(hrp) + data)
    if const == _BECH32:
        return hrp, data[:-6], "bech32"
    if const == _BECH32M:
        return hrp, data[:-6], "bech32m"
    return None


def bech32_encode(hrp, data5, spec):
    if (not isinstance(hrp, str) or not hrp or any(not 33 <= ord(c) <= 126 for c in hrp)
            or spec not in ("bech32", "bech32m")):
        return None
    try:
        data5 = list(data5)
    except TypeError:
        return None
    if len(hrp) + len(data5) + 7 > 90 or any(type(v) is not int or not 0 <= v < 32 for v in data5):
        return None
    const = _BECH32M if spec == "bech32m" else _BECH32
    pm = _polymod(_hrp_expand(hrp) + list(data5) + [0] * 6) ^ const
    return hrp + "1" + "".join(_CS[d] for d in list(data5) + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def _convertbits(data, frm, to, pad):
    acc, bits, out, maxv = 0, 0, [], (1 << to) - 1
    for v in data:
        if v < 0 or v >> frm:
            return None
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        return None
    return out


def segwit_decode(s: str):
    """{'hrp','version','program'(bytes),'spec'} for a valid BIP173/350 segwit address, else None."""
    d = bech32_decode(s)
    if d is None or not d[1]:
        return None
    hrp, data, spec = d
    ver = data[0]
    prog = _convertbits(data[1:], 5, 8, False)
    if ver > 16 or prog is None or not 2 <= len(prog) <= 40:
        return None
    if ver == 0 and (spec != "bech32" or len(prog) not in (20, 32)):
        return None
    if ver != 0 and spec != "bech32m":
        return None
    return {"hrp": hrp, "version": ver, "program": bytes(prog), "spec": spec}


def segwit_encode(hrp, version, program: bytes):
    program = _bytes_or_none(program)
    if (type(version) is not int or not 0 <= version <= 16 or program is None
            or not 2 <= len(program) <= 40 or (version == 0 and len(program) not in (20, 32))):
        return None
    return bech32_encode(hrp, [version] + _convertbits(list(program), 8, 5, True), "bech32" if version == 0 else "bech32m")


_B58_VERSIONS = {0x00: ("p2pkh", "mainnet"), 0x05: ("p2sh", "mainnet"), 0x6F: ("p2pkh", "testnet"),
                 0xC4: ("p2sh", "testnet")}


def classify_btc_address(text: str):
    """What a Bitcoin address string is, from the bytes: {'kind','network','payload'(bytes),'encoding'} or
    {'kind': 'wif'...} (recognised only, the payload is withheld) or None. A string that merely fails a
    checksum is not classified here."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    d = b58check_decode(t)
    if d is not None:
        v, pl = d
        if v in _B58_VERSIONS and len(pl) == 20:
            k, net = _B58_VERSIONS[v]
            return {"kind": k, "network": net, "payload": pl, "encoding": "base58check", "version_byte": v}
        if v in (0x80, 0xEF) and len(pl) in (32, 33):
            return {"kind": "wif", "network": "mainnet" if v == 0x80 else "testnet", "payload": None,
                    "encoding": "base58check", "version_byte": v}
        return None
    sw = segwit_decode(t)
    if sw is not None and sw["hrp"] in ("bc", "tb", "bcrt"):
        net = {"bc": "mainnet", "tb": "testnet", "bcrt": "regtest"}[sw["hrp"]]
        kind = {(0, 20): "p2wpkh", (0, 32): "p2wsh", (1, 32): "p2tr"}.get((sw["version"], len(sw["program"])), "segwit_other")
        return {"kind": kind, "network": net, "payload": sw["program"], "encoding": sw["spec"], "hrp": sw["hrp"],
                "witness_version": sw["version"]}
    return None


# ---------------------------------------------------------------------------- opcodes, disassembly, dispatch

_OPS = {0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD",
        0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
        0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE",
        0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN",
        0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY",
        0x38: "CODESIZE", 0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
        0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH", 0x41: "COINBASE",
        0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID",
        0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE", 0x50: "POP", 0x51: "MLOAD",
        0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC",
        0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST", 0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
        0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL", 0xF5: "CREATE2",
        0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT"}
for _i in range(32):
    _OPS[0x60 + _i] = f"PUSH{_i + 1}"
for _i in range(16):
    _OPS[0x80 + _i] = f"DUP{_i + 1}"
    _OPS[0x90 + _i] = f"SWAP{_i + 1}"
for _i in range(5):
    _OPS[0xA0 + _i] = f"LOG{_i}"


def disassemble(code: bytes, limit=MAX_INSNS):
    """[(pc, opcode, name, pushdata|None)]; a PUSH cut off by the end of the code keeps the bytes that exist."""
    code = _bytes_or_none(code)
    if code is None or type(limit) is not int or limit < 0:
        return []
    out, i, n = [], 0, len(code)
    while i < n and len(out) < limit:
        op = code[i]
        name = _OPS.get(op, f"UNKNOWN_0x{op:02x}")
        if 0x60 <= op <= 0x7F:
            k = op - 0x5F
            out.append((i, op, name, bytes(code[i + 1:i + 1 + k])))
            i += 1 + k
        else:
            out.append((i, op, name, None))
            i += 1
    return out


def solc_metadata(code: bytes):
    """(payload_length_incl_2_len_bytes, {'solc': 'x.y.z'|None}) when the code ends with a well-formed CBOR
    metadata tail (a map whose keys are short text), else None. Only structure is trusted: 2-byte length at the
    very end, the map header byte, and a bounded CBOR walk that consumes exactly the declared bytes."""
    code = _bytes_or_none(code)
    if code is None or len(code) < 4:
        return None
    L = int.from_bytes(code[-2:], "big")
    if not 8 <= L <= len(code) - 2 or L > 200:
        return None
    tail = code[-2 - L:-2]
    if not (0xA1 <= tail[0] <= 0xB7):
        return None
    cnt, i, info = tail[0] - 0xA0, 1, {}
    try:
        for _ in range(cnt):
            kl = tail[i]
            if not 0x60 <= kl <= 0x77:
                return None
            key = tail[i + 1:i + 1 + kl - 0x60].decode("ascii")
            i += 1 + kl - 0x60
            vh = tail[i]
            major, ln = vh >> 5, vh & 31
            if major == 2 and ln < 24:           # byte string
                val = tail[i + 1:i + 1 + ln]
                i += 1 + ln
            elif major == 2 and ln == 24:        # e.g. the 34-byte IPFS multihash
                ln = tail[i + 1]
                if ln < 24:
                    return None
                val = tail[i + 2:i + 2 + ln]
                i += 2 + ln
            elif major == 7 and ln in (20, 21):  # false/true
                val, i = (ln == 21), i + 1
            else:
                return None
            if len(tail) < i:
                return None
            info[key] = val
        if i != len(tail):
            return None
    except (IndexError, UnicodeDecodeError):
        return None
    ver = info.get("solc")
    if isinstance(ver, (bytes, bytearray)):
        ver = ".".join(str(b) for b in ver) if len(ver) == 3 else None
    else:
        ver = None
    return L + 2, {"solc": ver, "keys": sorted(info)}


_ZERO = (0x5F, 0x3D)       # PUSH0, RETURNDATASIZE as a zero


def split_creation(code: bytes):
    """(runtime_offset, runtime_length) of a solc-style creation code: the first (in the opening 600
    instructions) `PUSHn len; DUP1; PUSHn off; <zero>; CODECOPY; <zero>; RETURN` whose region lies inside the code,
    exactly one such site, else None. The site is a pattern, so the fact is offered under a pattern shape."""
    ins = disassemble(code, limit=600)
    hits = set()
    for i in range(len(ins) - 6):
        a, b, c, d, e, f, g = ins[i:i + 7]
        if not (0x60 <= a[1] <= 0x7F and b[1] == 0x80 and 0x60 <= c[1] <= 0x7F and e[1] == 0x39 and g[1] == 0xF3):
            continue
        z1 = d[1] in _ZERO or (d[1] == 0x60 and d[3] == b"\0")
        z2 = f[1] in _ZERO or (f[1] == 0x60 and f[3] == b"\0")
        if not (z1 and z2) or len(a[3]) != a[1] - 0x5F or len(c[3]) != c[1] - 0x5F:
            continue
        ln, off = int.from_bytes(a[3], "big"), int.from_bytes(c[3], "big")
        if ln > 0 and 0 < off and off + ln <= len(code):
            hits.add((off, ln))
    return next(iter(hits)) if len(hits) == 1 else None


def dispatch_table(runtime: bytes):
    """[(selector_hex, dest_pc)] from `PUSH4 sel [DUPn] EQ PUSHn dest JUMPI` sites, in code order, no repeats."""
    ins = disassemble(runtime)
    out, seen = [], set()
    for i, (pc, op, name, data) in enumerate(ins):
        if op != 0x63 or len(data) != 4:
            continue
        j = i + 1
        if j < len(ins) and 0x80 <= ins[j][1] <= 0x8F:
            j += 1
        if j + 2 < len(ins) and ins[j][1] == 0x14 and 0x60 <= ins[j + 1][1] <= 0x7F and ins[j + 2][1] == 0x57:
            sel = data.hex()
            if sel not in seen:
                seen.add(sel)
                out.append((sel, int.from_bytes(ins[j + 1][3], "big")))
    return out


def push_strings(code: bytes, minlen=5):
    """Printable-ASCII literals loaded by PUSHn (n >= minlen), trailing NUL padding stripped, in code order."""
    if type(minlen) is not int or minlen < 0:
        return []
    out = []
    for pc, op, name, data in disassemble(code):
        if data is None or len(data) < minlen or len(data) in (4, 20):      # 4: selectors, 20: addresses
            continue
        s = data.rstrip(b"\0")
        if len(s) >= minlen and all(0x20 <= c < 0x7F for c in s):
            out.append(s.decode("ascii"))
    return out


def bytecode_report(code: bytes):
    """The facts of a piece of EVM code (creation or runtime), or None when it is not code the readers trust."""
    code = _bytes_or_none(code)
    if not code or len(code) > MAX_FILE:
        return None
    meta = solc_metadata(code)
    split = split_creation(code)
    runtime = code
    if split:
        runtime = code[split[0]:split[0] + split[1]]
    rmeta = solc_metadata(runtime)
    body = runtime[:-rmeta[0]] if rmeta else runtime
    ins = disassemble(body)
    table = dispatch_table(body)
    return {"creation": split is not None, "runtime_offset": split[0] if split else None,
            "runtime_length": split[1] if split else None, "total_length": len(code),
            "solc": (rmeta or meta or (0, {}))[1].get("solc") if (rmeta or meta) else None,
            "metadata": bool(rmeta or meta), "selectors": [s for s, _ in table], "dispatch": table,
            "n_instructions": len(ins), "strings": push_strings(body), "starts_solc_prologue": code[:5] in
            (b"\x60\x80\x60\x40\x52", b"\x60\x60\x60\x40\x52")}


# ---------------------------------------------------------------------------- ABI

_UINT = re.compile(r"uint(\d{1,3})")
_INT = re.compile(r"int(\d{1,3})")
_BYTESN = re.compile(r"bytes(\d{1,2})")


def _ok_type(t: str) -> bool:
    m = re.fullmatch(r"(.+?)((?:\[\d*\])*)", t)
    base = m.group(1) if m else t
    if base in ("address", "bool", "string", "bytes"):
        return True
    for rx, lim in ((_UINT, 256), (_INT, 256), (_BYTESN, 32)):
        mm = rx.fullmatch(base)
        if mm:
            n = int(mm.group(1))
            return (1 <= n <= 32) if rx is _BYTESN else (8 <= n <= lim and n % 8 == 0)
    return False


def _canon_type(p):
    t = str(p.get("type", ""))
    if t.startswith("tuple"):
        comps = p.get("components")
        if not isinstance(comps, list) or not comps or not re.fullmatch(r"(?:\[(?:[1-9][0-9]{0,5})?\])*", t[5:]):
            raise _Bad("tuple")
        return "(" + ",".join(_canon_type(c) for c in comps) + ")" + t[5:]
    if not _ok_type(t):
        raise _Bad("type")
    return t


def signature_of(entry):
    try:
        ins = entry.get("inputs") or []
        return f"{entry['name']}({','.join(_canon_type(p) for p in ins)})"
    except (_Bad, KeyError, TypeError, AttributeError):
        return None


def selector_of_signature(sig: str):
    """keccak256(sig)[:4] for a CANONICAL signature `name(type,...)` (uint/int must be spelled uint256/int256,
    a struct argument as its tuple `(type,...)`), else None."""
    if not isinstance(sig, str):
        return None
    m = re.fullmatch(r"([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)", sig.strip(), re.S)
    if not m:
        return None
    if m.group(2):
        # the argument list parses as one tuple type and re-renders to exactly what was written (B-243:
        # tuple arguments such as `f((uint256,address)[])` are canonical too)
        node = parse_abi_type("(" + m.group(2) + ")")
        if node is None or abi_type_str(node) != "(" + m.group(2) + ")":
            return None
    k = keccak(sig.strip().encode())
    return None if k is None else k[:4]


def parse_abi(obj):
    """{'functions': [...], 'events': [...]} from an ABI list (or {'abi': [...]}), each entry with its
    signature, or None when it is not an ABI."""
    if isinstance(obj, dict) and isinstance(obj.get("abi"), list):
        obj = obj["abi"]
    if not isinstance(obj, list) or not obj or not all(isinstance(e, dict) for e in obj):
        return None
    fns, evs = [], []
    for e in obj:
        t = e.get("type", "function")
        if t not in ("function", "event", "constructor", "fallback", "receive", "error"):
            return None
        if t in ("function", "event", "error") and not isinstance(e.get("name"), str):
            return None
        if t in ("function", "event"):
            sig = signature_of(e)
            if sig is None:
                continue
            k = keccak(sig.encode())
            if k is None:
                return None
            rec = dict(e, signature=sig, sel=k[:4].hex(), topic=k.hex())
            (fns if t == "function" else evs).append(rec)
    if not fns and not evs:
        return None
    return {"functions": fns, "events": evs}


def _dynamic(t):
    if t in ("bytes", "string") or t.endswith("[]"):
        return True
    m = re.fullmatch(r"(.+)\[\d+\]", t)
    return bool(m) and _dynamic(m.group(1))


def _static_words(t):
    m = re.fullmatch(r"(.+)\[(\d+)\]", t)
    return int(m.group(2)) * _static_words(m.group(1)) if m else 1


def _word_value(t, w):
    if t == "address":
        return "0x" + w[12:].hex() if not any(w[:12]) else _raise()
    if t == "bool":
        v = int.from_bytes(w, "big")
        return (v == 1) if v in (0, 1) else _raise()
    m = _UINT.fullmatch(t)
    if m:
        n = int(m.group(1))
        v = int.from_bytes(w, "big")
        return v if v < 1 << n else _raise()
    m = _INT.fullmatch(t)
    if m:
        n = int(m.group(1))
        v = int.from_bytes(w, "big", signed=True)
        return v if -(1 << (n - 1)) <= v < 1 << (n - 1) else _raise()
    m = _BYTESN.fullmatch(t)
    if m:
        n = int(m.group(1))
        return bytes(w[:n]) if not any(w[n:]) else _raise()
    return _raise()


def _raise():
    raise _Bad("abi")


def _decode_static(t, data, pos):
    m = re.fullmatch(r"(.+)\[(\d+)\]", t)
    if m:
        w = _static_words(m.group(1))
        return [_decode_static(m.group(1), data, pos + 32 * w * i) for i in range(int(m.group(2)))]
    if pos + 32 > len(data):
        _raise()
    return _word_value(t, data[pos:pos + 32])


def _decode_one(t, data, head, base, tail_min=0, spans=None):
    if not _dynamic(t):
        return _decode_static(t, data, head)
    off = int.from_bytes(data[head:head + 32], "big") if head + 32 <= len(data) else _raise()
    p = base + off
    if off % 32 or p < tail_min or p + 32 > len(data):
        _raise()
    n = int.from_bytes(data[p:p + 32], "big")
    if t in ("bytes", "string"):
        end = p + 32 + ((n + 31) // 32) * 32
        if n > len(data) or end > len(data) or any(data[p + 32 + n:end]):
            _raise()
        if spans is not None:
            spans.append((p, end))
        raw = bytes(data[p + 32:p + 32 + n])
        if t == "string":
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                _raise()
        return raw
    if t.endswith("[]"):
        et = t[:-2]
        if _dynamic(et) or n > 4096 or p + 32 + n * 32 * _static_words(et) > len(data):
            _raise()
        w = _static_words(et)
        if spans is not None:
            spans.append((p, p + 32 + n * 32 * w))
        return [_decode_static(et, data, p + 32 + 32 * w * i) for i in range(n)]
    _raise()


# ---- general ABI types (B-243): tuples, nested tuples, tuple[] / tuple[k], arrays of dynamic types.
# A canonical type string is parsed into a small tree:
#   ("base", "uint256") | ("tuple", (child, ...)) | ("array", child, k or None)
# Decoding is bounded (type depth, component count, element count, a total value budget) and STRICT:
# the decoded value is re-encoded canonically and must reproduce the input byte for byte, so padding,
# pointer placement, overlap, gaps and trailing garbage are all checked by one rule.

MAX_ABI_TYPE_LEN = 4096
MAX_ABI_DEPTH = 16
MAX_ABI_COMPONENTS = 256
MAX_ABI_FIXED_ARRAY = 4096
MAX_ABI_VALUES = 200_000


def parse_abi_type(t: str):
    """The type tree of one canonical ABI type string, else None (unknown base type, an empty tuple,
    a non-canonical spelling such as `uint` or a space, or a type past the depth/size bounds)."""
    if not isinstance(t, str) or not t or len(t) > MAX_ABI_TYPE_LEN:
        return None
    try:
        node, i = _ptype(t, 0, 0)
    except _Bad:
        return None
    return node if i == len(t) else None


def _ptype(t, i, depth):
    if depth > MAX_ABI_DEPTH:
        raise _Bad("abi type depth")
    if i < len(t) and t[i] == "(":
        kids, i = [], i + 1
        while True:
            kid, i = _ptype(t, i, depth + 1)
            kids.append(kid)
            if len(kids) > MAX_ABI_COMPONENTS:
                raise _Bad("abi tuple size")
            if i < len(t) and t[i] == ",":
                i += 1
                continue
            if i < len(t) and t[i] == ")":
                i += 1
                break
            raise _Bad("abi tuple")
        node = ("tuple", tuple(kids))
    else:
        m = re.compile(r"[a-z]+[0-9]*").match(t, i)
        if not m or not _ok_type(m.group(0)):
            raise _Bad("abi base type")
        node, i = ("base", m.group(0)), m.end()
    nesting = depth
    while i < len(t) and t[i] == "[":
        m = re.compile(r"\[(0|[1-9][0-9]{0,5})?\]").match(t, i)
        if not m:
            raise _Bad("abi array")
        k = None if m.group(1) is None else int(m.group(1))
        if k is not None and not 1 <= k <= MAX_ABI_FIXED_ARRAY:
            raise _Bad("abi fixed array size")
        nesting += 1
        if nesting > MAX_ABI_DEPTH:
            raise _Bad("abi type depth")
        node, i = ("array", node, k), m.end()
    return node, i


def abi_type_str(node) -> str:
    """The canonical string of a type tree (the inverse of parse_abi_type)."""
    if node[0] == "base":
        return node[1]
    if node[0] == "tuple":
        return "(" + ",".join(abi_type_str(c) for c in node[1]) + ")"
    return abi_type_str(node[1]) + ("[]" if node[2] is None else f"[{node[2]}]")


def _tdyn(node) -> bool:
    if node[0] == "base":
        return node[1] in ("bytes", "string")
    if node[0] == "tuple":
        return any(_tdyn(c) for c in node[1])
    return node[2] is None or _tdyn(node[1])


def _thead(node) -> int:
    """Bytes the value occupies in its enclosing head: 32 for a dynamic value (its offset word)."""
    if _tdyn(node):
        return 32
    if node[0] == "base":
        return 32
    if node[0] == "tuple":
        return sum(_thead(c) for c in node[1])
    return node[2] * _thead(node[1])


def _word_at(data, pos):
    if pos < 0 or pos + 32 > len(data):
        _raise()
    return data[pos:pos + 32]


def _gdec(node, data, pos, budget):
    """The value of `node` whose encoding starts at `pos` (a dynamic value's tail, a static value in place)."""
    budget[0] -= 1
    if budget[0] < 0:
        raise _Bad("abi value budget")
    if node[0] == "base":
        if node[1] in ("bytes", "string"):
            n = int.from_bytes(_word_at(data, pos), "big")
            if n > len(data) - pos - 32:
                _raise()
            # charge the copy by the word: aliased pointers to one long tail cannot multiply the work
            budget[0] -= n // 32
            if budget[0] < 0:
                raise _Bad("abi value budget")
            raw = bytes(data[pos + 32:pos + 32 + n])
            if node[1] == "string":
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    _raise()
            return raw
        return _word_value(node[1], _word_at(data, pos))
    if node[0] == "tuple":
        return tuple(_gseq(node[1], data, pos, budget))
    child, k = node[1], node[2]
    if k is None:
        k = int.from_bytes(_word_at(data, pos), "big")
        pos += 32
    # every element needs at least one head word: a length the data cannot hold is refused before looping
    if k * _thead(child) > len(data) - pos:
        _raise()
    return _gseq([child] * k, data, pos, budget)


def _gseq(nodes, data, base, budget):
    out, head = [], base
    for node in nodes:
        if _tdyn(node):
            off = int.from_bytes(_word_at(data, head), "big")
            if off > len(data):
                _raise()
            out.append(_gdec(node, data, base + off, budget))
            head += 32
        else:
            out.append(_gdec(node, data, head, budget))
            head += _thead(node)
    return out


def _genc_word(t, v) -> bytes:
    if t == "address":
        return bytes(12) + bytes.fromhex(v[2:])
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if _BYTESN.fullmatch(t):
        return bytes(v) + bytes(32 - len(v))
    if _INT.fullmatch(t) and not _UINT.fullmatch(t):
        return (v % (1 << 256)).to_bytes(32, "big")
    return v.to_bytes(32, "big")


def _genc(node, v) -> bytes:
    if node[0] == "base":
        if node[1] in ("bytes", "string"):
            raw = v.encode("utf-8") if node[1] == "string" else bytes(v)
            return len(raw).to_bytes(32, "big") + raw + bytes((-len(raw)) % 32)
        return _genc_word(node[1], v)
    if node[0] == "tuple":
        return _genc_seq(node[1], list(v))
    if node[2] is None:
        return len(v).to_bytes(32, "big") + _genc_seq([node[1]] * len(v), list(v))
    return _genc_seq([node[1]] * node[2], list(v))


def _genc_seq(nodes, vals) -> bytes:
    heads, tails = [], []
    hlen = sum(_thead(n) for n in nodes)
    tail_len = 0
    for node, v in zip(nodes, vals):
        if _tdyn(node):
            heads.append((hlen + tail_len).to_bytes(32, "big"))
            enc = _genc(node, v)
            tails.append(enc)
            tail_len += len(enc)
        else:
            heads.append(_genc(node, v))
    return b"".join(heads) + b"".join(tails)


def abi_encode(types, values) -> bytes | None:
    """Canonical ABI encoding of `values` as `types` (the head/tail layout of the Solidity spec), or None.
    Used to prove a decode canonical; values are those abi_decode returns (address as a 0x string)."""
    if not isinstance(types, (list, tuple)) or not isinstance(values, (list, tuple)) or len(types) != len(values):
        return None
    nodes = [parse_abi_type(t) for t in types]
    if any(n is None for n in nodes):
        return None
    try:
        return _genc_seq(nodes, list(values))
    except (AttributeError, TypeError, ValueError, OverflowError, IndexError):
        return None


def _legacy_supported(node) -> bool:
    """The pre-B-243 decoder's types: base types and arrays of static non-tuple elements."""
    if node[0] == "base":
        return True
    if node[0] == "tuple":
        return False
    return not _tdyn(node[1]) and _legacy_supported(node[1])


def _abi_decode_general(nodes, data):
    try:
        budget = [MAX_ABI_VALUES]
        if sum(_thead(n) for n in nodes) > len(data):
            return None
        vals = _gseq(nodes, data, 0, budget)
        if _genc_seq(nodes, vals) != bytes(data):
            return None                    # non-canonical: padding, pointers, overlap, gaps or trailing bytes
        return vals
    except (_Bad, IndexError, ValueError, RecursionError, OverflowError, TypeError, AttributeError):
        return None


def abi_decode(types, data: bytes):
    """Decode ABI-encoded `data` as `types`; None for unknown types, or any out-of-bounds,
    non-zero-padded or out-of-range word. Dynamic tails must follow the head without overlap or gaps;
    the complete padded encoding must consume the input, with no trailing garbage. Tuples (B-243),
    nested tuples, tuple arrays and arrays of dynamic elements decode through the general decoder, which
    requires the exact canonical encoding; a tuple decodes to a Python tuple, an array to a list."""
    data = _bytes_or_none(data)
    if not isinstance(types, (list, tuple)) or data is None:
        return None
    if any(not isinstance(t, str) for t in types):
        return None
    nodes = [parse_abi_type(t) for t in types]
    if any(n is None for n in nodes):
        return None
    if not all(_legacy_supported(n) for n in nodes):
        return _abi_decode_general(nodes, data)
    try:
        if any(not isinstance(t, str) or not _ok_type(t) for t in types):
            return None
        head = sum(32 if _dynamic(t) else 32 * _static_words(t) for t in types)
        if len(data) < head:
            return None
        out, pos, spans = [], 0, []
        for t in types:
            out.append(_decode_one(t, data, pos, 0, head, spans))
            pos += 32 if _dynamic(t) else 32 * _static_words(t)
        end = head
        for start, stop in sorted(spans):
            if start != end:
                return None
            end = stop
        if end != len(data):
            return None
        return out
    except (_Bad, IndexError, ValueError, RecursionError):
        return None


def decode_calldata(abi, data: bytes):
    """(function entry, [(name, type, value)]) when the 4-byte selector matches EXACTLY ONE function of the
    provided ABI and the arguments decode cleanly, else None."""
    data = _bytes_or_none(data)
    if data is None or len(data) < 4 or not isinstance(abi, dict):
        return None
    functions = abi.get("functions")
    if not isinstance(functions, list) or any(not isinstance(f, dict) for f in functions):
        return None
    hits = [f for f in functions if f.get("sel") == data[:4].hex()]
    if len(hits) != 1:
        return None
    f = hits[0]
    ins = f.get("inputs") or []
    if not isinstance(ins, list) or any(not isinstance(p, dict) for p in ins):
        return None
    try:
        types = [_canon_type(p) for p in ins]
    except _Bad:
        return None
    vals = abi_decode(types, data[4:])
    if vals is None:
        return None
    return f, [(p.get("name") or f"arg{i}", types[i], vals[i]) for i, p in enumerate(ins)]


_COMMON_SIGS = [
    "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)",
    "balanceOf(address)", "allowance(address,address)", "totalSupply()", "name()", "symbol()", "decimals()",
    "mint(address,uint256)", "burn(uint256)", "burnFrom(address,uint256)", "ownerOf(uint256)",
    "safeTransferFrom(address,address,uint256)", "safeTransferFrom(address,address,uint256,bytes)",
    "setApprovalForAll(address,bool)", "getApproved(uint256)", "isApprovedForAll(address,address)",
    "tokenURI(uint256)", "owner()", "transferOwnership(address)", "renounceOwnership()", "withdraw()",
    "withdraw(uint256)", "deposit()", "deposit(uint256)", "claim()", "flag()", "getFlag()", "pause()", "unpause()",
    "initialize()", "upgradeTo(address)", "upgradeToAndCall(address,bytes)", "multicall(bytes[])",
    "execute(address,uint256,bytes)", "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "supportsInterface(bytes4)", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", "kill()",
    "setOwner(address)", "register(string)", "vote(uint256)", "buy()", "sell(uint256)", "isSolved()", "solve()"]


def common_selector_table():
    t = {}
    for s in _COMMON_SIGS:
        sel = selector_of_signature(s)
        if sel is not None:
            t.setdefault(sel.hex(), []).append(s)
    return t


# ---------------------------------------------------------------------------- EVM transactions

def _uint(b):
    if b[:1] == b"\0":
        raise _Bad("noncanonical int")
    return int.from_bytes(b, "big")


def _need_bytes(items):
    if not all(isinstance(x, bytes) for x in items):
        raise _Bad("shape")


TX_TYPE_NAMES = {0: "legacy", 1: "eip2930", 2: "eip1559", 3: "eip4844", 4: "eip7702"}


def decode_evm_tx(raw: bytes):
    """A transaction dict, or None. Strict: the whole buffer is one canonical RLP structure of the exact field
    count of its type, integers without leading zeros, `to` empty or 20 bytes, signature in range. `from` is the
    ecrecover of the signing hash (None when the signature is absent or does not recover)."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        return None
    try:
        if not 0 < (raw.nbytes if isinstance(raw, memoryview) else len(raw)) <= MAX_FILE or keccak(b"") is None:
            return None
        raw = bytes(raw)
        t = raw[0]
        if t >= 0xC0:
            typ, body = 0, rlp_decode(raw)
        elif t in (1, 2, 3, 4):
            typ, body = t, rlp_decode(raw[1:])
        else:
            return None
        if not isinstance(body, list):
            return None
        tx = {"type": typ, "hash": keccak(raw).hex(), "signed": True, "from": None, "chain_id": None}
        if typ == 0:
            if len(body) == 6:
                f, sig = body, None
                tx["signed"] = False
            elif len(body) == 9:
                f, sig = body[:6], body[6:]
            else:
                return None
            _need_bytes(body)
            nonce, gp, gas, to, val, data = f
            tx.update(nonce=_uint(nonce), gas_price=_uint(gp), gas_limit=_uint(gas), value=_uint(val), data=data)
            payload = list(f)
            if sig is not None:
                v, r, s = sig
                if r == b"" and s == b"":          # EIP-155 unsigned form: v is the chain id
                    tx["signed"] = False
                    tx["chain_id"] = _uint(v)
                    sig = None
                else:
                    vi = _uint(v)
                    if vi in (27, 28):
                        recid, chain = vi - 27, None
                    elif vi >= 35:
                        chain, recid = (vi - 35) // 2, (vi - 35) % 2
                    else:
                        return None
                    tx["chain_id"] = chain
                    if chain is not None:
                        payload = list(f) + [chain, b"", b""]
                    sighash = keccak(rlp_encode(payload))
                    sig = (sighash, _uint(r), _uint(s), recid)
        else:
            n_fields = {1: 11, 2: 12, 3: 14, 4: 13}[typ]
            if len(body) != n_fields:
                return None
            if typ == 1:
                cid, nonce, gp, gas, to, val, data, acl, y, r, s = body
                _need_bytes([cid, nonce, gp, gas, to, val, data, y, r, s])
                tx.update(gas_price=_uint(gp))
                signed_part = body[:8]
            elif typ == 2:
                cid, nonce, tip, mf, gas, to, val, data, acl, y, r, s = body
                _need_bytes([cid, nonce, tip, mf, gas, to, val, data, y, r, s])
                tx.update(max_priority_fee=_uint(tip), max_fee=_uint(mf))
                signed_part = body[:9]
            elif typ == 3:
                cid, nonce, tip, mf, gas, to, val, data, acl, mbf, bh, y, r, s = body
                _need_bytes([cid, nonce, tip, mf, gas, to, val, data, mbf, y, r, s])
                tx.update(max_priority_fee=_uint(tip), max_fee=_uint(mf), max_fee_per_blob_gas=_uint(mbf),
                          blob_versioned_hashes=len(bh) if isinstance(bh, list) else None)
                signed_part = body[:11]
            else:
                # EIP-7702 set-code transaction: a 1559 body plus a non-empty authorization list; it can
                # never create a contract, so `to` is exactly 20 bytes
                cid, nonce, tip, mf, gas, to, val, data, acl, auths, y, r, s = body
                _need_bytes([cid, nonce, tip, mf, gas, to, val, data, y, r, s])
                if len(to) != 20:
                    return None
                tx.update(max_priority_fee=_uint(tip), max_fee=_uint(mf), authorizations=_authorizations(auths))
                signed_part = body[:10]
            if not isinstance(acl, list):
                return None
            tx.update(chain_id=_uint(cid), nonce=_uint(nonce), gas_limit=_uint(gas), value=_uint(val), data=data,
                      access_list_len=len(acl))
            yi = _uint(y)
            if yi not in (0, 1):
                return None
            sig = (keccak(bytes([typ]) + rlp_encode(signed_part)), _uint(r), _uint(s), yi)
        if len(to) not in (0, 20):
            return None
        tx["to"] = to.hex() if to else None
        tx["creation"] = not to
        tx["selector"] = data_sel(tx["data"])
        if sig is not None and isinstance(sig, tuple):
            if not (1 <= sig[1] < _N and 1 <= sig[2] < _N):
                return None
            pt = ecrecover_pub(sig[0], sig[1], sig[2], sig[3])
            if pt is not None:
                a = pub_to_address(pt)
                tx["from"] = a.hex() if a else None
            tx["signing_hash"] = sig[0].hex()
        elif sig is None:
            tx["signed"] = False
        return tx
    except (_Bad, KeyError, ValueError, IndexError, TypeError):
        return None


def _authorizations(auths):
    """EIP-7702 authorization tuples [chain_id, address, nonce, y_parity, r, s] -> dicts with the recovered
    AUTHORITY (the account that delegates), or None for a signature the EIP rejects (y not 0/1, r or s out
    of range, s in the upper half). The list must be non-empty: an empty one makes the transaction invalid."""
    if not isinstance(auths, list) or not auths or len(auths) > 4096:
        raise _Bad("authorization list")
    out = []
    for a in auths:
        if not isinstance(a, list) or len(a) != 6:
            raise _Bad("authorization tuple")
        _need_bytes(a)
        cid, addr, nonce, y, r, s = a
        if len(addr) != 20:
            raise _Bad("authorization address")
        rec = {"chain_id": _uint(cid), "address": addr.hex(), "nonce": _uint(nonce), "authority": None}
        yi, ri, si = _uint(y), _uint(r), _uint(s)
        if yi in (0, 1) and 1 <= ri < _N and 1 <= si <= _N // 2:
            h = keccak(b"\x05" + rlp_encode([cid, addr, nonce]))
            pt = ecrecover_pub(h, ri, si, yi) if h is not None else None
            who = pub_to_address(pt) if pt is not None else None
            rec["authority"] = who.hex() if who else None
        out.append(rec)
    return out


def data_sel(data: bytes):
    data = _bytes_or_none(data)
    if data is None:
        return None
    return data[:4].hex() if len(data) >= 4 else None


# ---------------------------------------------------------------------------- Bitcoin raw transactions

def _varint(b, i):
    if i >= len(b):
        raise _Bad("varint")
    v = b[i]
    if v < 0xFD:
        return v, i + 1
    n = {0xFD: 2, 0xFE: 4, 0xFF: 8}[v]
    if i + 1 + n > len(b):
        raise _Bad("varint")
    x = int.from_bytes(b[i + 1:i + 1 + n], "little")
    if x < {2: 0xFD, 4: 0x10000, 8: 0x100000000}[n]:
        raise _Bad("varint not minimal")
    return x, i + 1 + n


def script_type(spk: bytes):
    spk = _bytes_or_none(spk)
    if spk is None:
        return "nonstandard", None
    n = len(spk)
    if n == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "p2pkh", spk[3:23]
    if n == 23 and spk[:2] == b"\xa9\x14" and spk[22] == 0x87:
        return "p2sh", spk[2:22]
    if n == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh", spk[2:]
    if n == 34 and spk[:2] == b"\x00\x20":
        return "p2wsh", spk[2:]
    if n == 34 and spk[:2] == b"\x51\x20":
        return "p2tr", spk[2:]
    if n in (35, 67) and spk[0] == n - 2 and spk[-1] == 0xAC and parse_pubkey(spk[1:-1]) is not None:
        return "p2pk", spk[1:-1]
    if n >= 1 and spk[0] == 0x6A:
        return "op_return", _op_return_data(spk)
    return "nonstandard", None


def _op_return_data(spk):
    body, out, i = spk[1:], [], 0
    while i < len(body):
        op = body[i]
        i += 1
        if 1 <= op <= 75:
            ln = op
        elif op == 0x4C and i < len(body):
            ln, i = body[i], i + 1
        else:
            return None
        if i + ln > len(body):
            return None
        out.append(body[i:i + ln])
        i += ln
    return b"".join(out)


def address_of(kind, payload, hrp="bc"):
    """Mainnet address of a standard scriptPubKey (the network is not in the bytes: this is the mainnet rendering)."""
    payload = _bytes_or_none(payload)
    if payload is None:
        return None
    if kind == "p2pkh":
        return b58check_encode(0x00, payload)
    if kind == "p2sh":
        return b58check_encode(0x05, payload)
    if kind in ("p2wpkh", "p2wsh"):
        return segwit_encode(hrp, 0, payload)
    if kind == "p2tr":
        return segwit_encode(hrp, 1, payload)
    if kind == "p2pk":
        return b58check_encode(0x00, hash160(payload))
    return None


def decode_btc_tx(raw: bytes):
    """A Bitcoin transaction dict (legacy or BIP144 segwit), the whole buffer consumed, or None."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        return None
    try:
        if not 10 <= (raw.nbytes if isinstance(raw, memoryview) else len(raw)) <= MAX_FILE:
            return None
        b = bytes(raw)
        ver = struct.unpack("<i", b[:4])[0]
        i, segwit = 4, False
        if b[4] == 0 and b[5] == 1:
            segwit, i = True, 6
        nin, i = _varint(b, i)
        if nin == 0 or nin > 20000:
            return None
        ins = []
        for _ in range(nin):
            if i + 36 > len(b):
                return None
            prev, vout = b[i:i + 32][::-1].hex(), struct.unpack("<I", b[i + 32:i + 36])[0]
            i += 36
            sl, i = _varint(b, i)
            if i + sl + 4 > len(b):
                return None
            ss, i = b[i:i + sl], i + sl
            seq, i = struct.unpack("<I", b[i:i + 4])[0], i + 4
            ins.append({"prev_txid": prev, "vout": vout, "script_sig_len": len(ss), "sequence": seq,
                        "coinbase": prev == "00" * 32 and vout == 0xFFFFFFFF})
        nout, i = _varint(b, i)
        if nout == 0 or nout > 20000:
            return None
        outs = []
        for _ in range(nout):
            if i + 8 > len(b):
                return None
            val, i = struct.unpack("<q", b[i:i + 8])[0], i + 8
            if val < 0:
                return None
            sl, i = _varint(b, i)
            if i + sl > len(b):
                return None
            spk, i = b[i:i + sl], i + sl
            kind, pl = script_type(spk)
            outs.append({"value": val, "type": kind, "script_len": len(spk),
                         "address": address_of(kind, pl) if kind not in ("op_return", "nonstandard") else None,
                         "data": pl if kind == "op_return" else None, "hash": pl.hex() if kind not in
                         ("op_return", "nonstandard") and pl else None})
        wit_start = i
        if segwit:
            for _ in range(nin):
                n, i = _varint(b, i)
                if n > 5000:
                    return None
                for _ in range(n):
                    sl, i = _varint(b, i)
                    if i + sl > len(b):
                        return None
                    i += sl
        if i + 4 != len(b):
            return None
        lock = struct.unpack("<I", b[i:i + 4])[0]
        base = b[:4] + b[6 if segwit else 4:wit_start] + b[len(b) - 4:]
        txid = sha256d(base)[::-1].hex()
        wtxid = sha256d(b)[::-1].hex()
        weight = len(base) * 3 + len(b)
        return {"version": ver, "segwit": segwit, "inputs": ins, "outputs": outs, "locktime": lock, "txid": txid,
                "wtxid": wtxid, "size": len(b), "weight": weight, "vsize": -(-weight // 4),
                "total_out": sum(o["value"] for o in outs)}
    except (_Bad, IndexError, struct.error, KeyError, TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------- artifacts: what each file is

_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F\s]+")


def _hex_bytes(text: str):
    t = text.strip()
    if not t or not _HEX_RE.fullmatch(t):
        return None
    t = re.sub(r"\s+", "", t)
    t = t[2:] if t[:2] in ("0x", "0X") else t
    if len(t) % 2 or not t:
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def _json_hex_fields(obj, depth=0):
    """Yield (key, hex-bytes) for JSON string fields that hold hex, a few levels deep (tx / bytecode wrappers)."""
    if depth > 4:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                bs = _hex_bytes(v) if len(v) >= 4 else None
                if bs is not None:
                    yield str(k).lower(), bs
            else:
                yield from _json_hex_fields(v, depth + 1)


_TX_KEYS = {"rawtransaction", "raw", "rawtx", "raw_tx", "signedtransaction", "tx", "transaction", "hex", "signedtx"}
_CODE_KEYS = {"bytecode", "object", "deployedbytecode", "runtimebytecode", "code", "runtime", "creationbytecode", "input",
              "initcode", "deployed_bytecode"}


def _is_code(bs):
    if bs[:5] in (b"\x60\x80\x60\x40\x52", b"\x60\x60\x60\x40\x52"):
        return True
    return len(bs) >= 12 and len(dispatch_table(bs)) >= 2


def read_artifacts(files):
    """[{'name','kind','obj'}] for every file the readers recognise as exactly one kind. A file that parses as
    two kinds is dropped (ambiguous)."""
    arts = []
    try:
        items = triage.unique_files(files or {})
    except Exception:  # noqa: BLE001
        return []
    for name, data in items:
        if len(data) > MAX_FILE or not data:
            continue
        found = []
        try:
            found = _kinds_of(data)
        except Exception:  # noqa: BLE001 - a reader that raises names no kind
            found = []
        if len(found) == 1:
            arts.append({"name": name, **found[0]})
    return arts


def _kinds_of(data: bytes):
    out = []
    text = None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    cands = []                 # (origin, bytes)
    jobj = None
    if text is not None:
        st = text.strip()
        if st[:1] in "[{":
            try:
                jobj = json.loads(st)
            except ValueError:
                jobj = None
        if jobj is None:
            bs = _hex_bytes(st)
            if bs is not None:
                cands.append(("hex", bs))
            ea = classify_eth_address(st)
            if ea:
                out.append({"kind": "eth_address", "obj": ea})
            ba = classify_btc_address(st) if re.fullmatch(r"[0-9A-Za-z]{14,90}", st) else None
            if ba:
                out.append({"kind": "btc_address", "obj": ba})
            if not ea and not ba and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", st) and (b := b58decode(st)) and len(b) == 32:
                out.append({"kind": "b58_32", "obj": {"bytes": b}})
    else:
        cands.append(("raw", data))
    if jobj is not None:
        abi = parse_abi(jobj)
        if abi:
            out.append({"kind": "abi", "obj": abi})
        for k, bs in _json_hex_fields(jobj):
            if k in _TX_KEYS:
                cands.append(("json", bs))
            if k in _CODE_KEYS:
                cands.append(("json", bs))
        sg = _sig_from_json(jobj)
        if sg:
            out.append({"kind": "sig", "obj": sg})
        lg = _logs_from_json(jobj)
        if lg:
            out.append({"kind": "logs", "obj": lg})
    for origin, bs in cands:
        tx = decode_evm_tx(bs)
        if tx:
            out.append({"kind": "evm_tx", "obj": tx})
            continue
        btx = decode_btc_tx(bs)
        if btx:
            out.append({"kind": "btc_tx", "obj": btx})
            continue
        if _is_code(bs):
            out.append({"kind": "bytecode", "obj": {"code": bs}})
            continue
        if len(bs) in (33, 64, 65) and parse_pubkey(bs) is not None:
            out.append({"kind": "pubkey", "obj": parse_pubkey(bs)})
            continue
        if len(bs) == 32 and origin == "hex":
            out.append({"kind": "key32", "obj": {"bytes": bs}})
            continue
        if origin == "hex" and len(bs) >= 36 and (len(bs) - 4) % 32 == 0:
            out.append({"kind": "calldata", "obj": {"data": bs}})
    # a bare 32-byte hex file that is also not code is only ever a key or a hash; keep a single kind
    uniq = []
    seen = set()
    for o in out:
        sig = (o["kind"], repr(o["obj"])[:200])
        if sig not in seen:
            seen.add(sig)
            uniq.append(o)
    return uniq


def _sig_from_json(j):
    if not isinstance(j, dict):
        return None
    sig = None
    for k in ("signature", "sig"):
        if isinstance(j.get(k), str):
            sig = _hex_bytes(j[k])
    if sig is None or len(sig) != 65:
        return None
    h = None
    for k in ("messagehash", "hash", "digest", "message_hash", "msghash"):
        for kk, v in j.items():
            if str(kk).lower() == k and isinstance(v, str):
                h = _hex_bytes(v)
    msg = j.get("message") if isinstance(j.get("message"), str) else None
    claimed = None
    for kk, v in j.items():
        if str(kk).lower() in ("address", "signer", "expected", "signed_by") and isinstance(v, str):
            claimed = classify_eth_address(v)
    if (h is None or len(h) != 32) and msg is None:
        return None
    return {"sig": sig, "hash": h if h is not None and len(h) == 32 else None, "message": msg,
            "claimed": claimed["bytes"] if claimed else None}


def _logs_from_json(j):
    logs = []
    if isinstance(j, dict) and isinstance(j.get("logs"), list):
        logs = j["logs"]
    elif isinstance(j, dict) and "topics" in j:
        logs = [j]
    elif isinstance(j, list) and j and all(isinstance(x, dict) and "topics" in x for x in j):
        logs = j
    out = []
    for lg in logs:
        if not isinstance(lg, dict) or not isinstance(lg.get("topics"), list) or not isinstance(lg.get("data", "0x"), str):
            return None
        tops = []
        for t in lg["topics"]:
            tb = _hex_bytes(t) if isinstance(t, str) else None
            if tb is None or len(tb) != 32:
                return None
            tops.append(tb)
        data = _hex_bytes(lg.get("data") or "0x") if (lg.get("data") not in (None, "", "0x")) else b""
        if data is None:
            return None
        addr = classify_eth_address(lg["address"]) if isinstance(lg.get("address"), str) else None
        out.append({"topics": tops, "data": data, "address": addr["bytes"] if addr else None})
    return out or None


def recover_signature(sig):
    """The signer address bytes for a sig artifact, plus the scheme that proved it, or (None, None).
    Given a hash: recovered under the signature as is. Given only a message: the scheme (EIP-191 personal_sign vs
    raw keccak of the message) must be PROVEN by the artifact's claimed address matching exactly one."""
    if not isinstance(sig, dict):
        return None, None
    raw = sig.get("sig")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 65:
        return None, None
    r, s, v = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
    recid = v - 27 if v in (27, 28) else (v if v in (0, 1) else None)
    if recid is None:
        return None, None

    def rec(h):
        pt = ecrecover_pub(h, r, s, recid)
        return pub_to_address(pt) if pt else None

    if sig.get("hash") is not None:
        a = rec(sig["hash"])
        return (a, "hash") if a else (None, None)
    message, claimed = sig.get("message"), sig.get("claimed")
    if not isinstance(message, str) or len(message) > MAX_FILE or not isinstance(claimed, (bytes, bytearray)) or len(claimed) != 20:
        return None, None
    try:
        msg = message.encode("utf-8")
    except UnicodeError:
        return None, None
    if len(msg) > MAX_FILE:
        return None, None
    k1 = keccak(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)
    k2 = keccak(msg)
    if k1 is None:
        return None, None
    a1, a2 = rec(k1), rec(k2)
    ok1, ok2 = a1 == claimed, a2 == claimed
    if ok1 and not ok2:
        return a1, "eip191"
    if ok2 and not ok1:
        return a2, "keccak"
    return None, None


# ---------------------------------------------------------------------------- the question router

_TOKEN_NORM = re.compile(r"[_\-]+")


def _qtext(q):
    if not isinstance(q, dict):
        return ""
    f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    parts = [q.get("question"), q.get("prompt"), q.get("description"), q.get("answer_id") or q.get("id") or q.get("qid"),
             f.get("syntax")]
    return _TOKEN_NORM.sub(" ", " ".join(str(x or "") for x in parts)).lower()


def _qraw(q):
    if not isinstance(q, dict):
        return ""
    return " ".join(str(q.get(k) or "") for k in ("question", "prompt", "description"))


_SECRET = r"private key|privkey|secret key|seed phrase|mnemonic|recovery phrase|\bwif\b|\bxprv\b|keystore"
_F = {
    "secret": _SECRET,
    "flag": r"\bflag\b|ctf\{|password|passphrase",
    "tx_hash": r"(transaction|tx) hash|\btxid\b|\btx id\b|hash of (the|this) (transaction|tx)|transaction id",
    "wtxid": r"\bwtxid\b|witness (transaction )?id|witness hash",
    "tx_from": r"\bsender\b|\bsigner\b|signed by|from address|\bfrom field\b|from account|who (sent|signed)|"
               r"originat(or|ing)|which address (sent|signed|produced)|recover(ed)? (the )?(address|signer)|ecrecover",
    "tx_to": r"recipient|\bto address\b|\bto field\b|destination address|sent to|receiv(er|ing) address|"
             r"which address (receive|is the (transaction|tx) (sent|addressed))|target address|callee",
    "tx_value": r"\bwei\b|\bvalue\b|how much (eth|ether)|(eth|ether) (was )?(sent|transferred)|amount of (eth|ether)",
    "tx_nonce": r"\bnonce\b",
    "tx_gas_limit": r"gas ?limit|gas_limit|gas allowance",
    "tx_gas_price": r"gas ?price|gasprice",
    "tx_max_fee": r"max(imum)? fee( per gas)?|maxfeepergas",
    "tx_tip": r"priority fee|max(imum)? priority|\btip\b|maxpriorityfeepergas",
    "tx_chain_id": r"chain ?id|chainid|which (network|chain)\b",
    "tx_type": r"(transaction|tx) type|eip-?(1559|2930|4844|155|7702)\b|type of (the |this )?(transaction|tx)|\btx_type\b",
    "tx_auth_address": r"delegat(e|es|ed|ion) (to|target|address|contract)|delegat(ion|ed) (code )?address|"
                    r"authori[sz]ation (target|address)|address (the )?(eoa|account|authority) delegates to",
    "tx_auth_authority": r"\bauthority\b|authori[sz]ing (account|address|eoa)|(signer|signed) (of )?the authori[sz]ation|"
                      r"who (signed|authori[sz]ed) the authori[sz]ation|which (account|eoa|address) (is )?delegat(ed|es|ing)\b",
    "tx_n_auth": r"(how many|number of|count of)\b.{0,20}authori[sz]ations?",
    "tx_creation": r"contract creation|creates? a contract|deploy(s|ing|ment)? (transaction|tx|a contract)",
    "selector": r"selector|first 4 bytes|first four bytes|method ?id|function id|4.?byte",
    "fn_name": r"function name|which function|method name|called function|function (is |was )?(called|invoked|executed)|"
               r"function being (called|invoked)|name of the function",
    "fn_sig": r"function signature|signature of the function|full signature|canonical signature",
    "topic0": r"topic ?0|event (signature )?hash|event topic|topic hash|keccak.*event",
    "event_name": r"event name|which event|name of the event|event (was )?(emitted|fired|logged)",
    "arg_n": r"\b(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th) (argument|parameter|arg|param|input)\b",
    "n_selectors": r"(how many|number of|count of|count)\b.{0,40}(function|selector|method)s?",
    "list_selectors": r"(list|all|every|each|set of)\b.{0,30}(selector|function id|method id)s?|dispatch(er)? table",
    "rt_offset": r"(runtime|deployed|contract) (code )?(starts?|offset|begins?)|offset of the (runtime|deployed)|"
                 r"(runtime|deployed).{0,25}offset",
    "rt_length": r"(runtime|deployed).{0,25}(length|size)|length of the (runtime|deployed)",
    "solc": r"\bsolc\b|compiler version|solidity version|compiled with",
    "n_insns": r"(how many|number of|count of)\b.{0,15}(opcode|instruction)s?",
    "literal": r"revert (message|reason|string)|error (message|string)|string literal|hardcoded string|embedded string|"
               r"string (stored|pushed|embedded|in the (byte)?code)",
    "checksum_valid": r"(\bvalid\b|invalid|\bcorrect\b|verif|passes|pass\b|checks out).{0,40}checksum|"
                      r"checksum.{0,40}(\bvalid\b|invalid|\bcorrect\b|verif|passes|pass\b|checks out)",
    "checksum_form": r"checksum|eip-?55|mixed.?case|proper (case|capital)|correct(ly)? (case|capital)",
    "addr_from_pub": r"(public key|pubkey).{0,60}address|address.{0,60}(public key|pubkey)",
    "addr_from_priv": r"(private key|privkey|secret key).{0,80}address|address.{0,80}(private key|privkey|secret key)",
    "addr_type": r"(type|kind|format|script)\b.{0,25}address|what (type|kind) of address|\bp2pkh\b|\bp2sh\b|\bp2wpkh\b|\bp2wsh\b|"
                 r"\bp2tr\b|taproot|segwit|bech32|address (type|format|kind)",
    "addr_net": r"which (bitcoin )?network|mainnet|testnet|\bhrp\b|human.readable",
    "addr_hash": r"hash ?160|pubkey ?hash|public key hash|witness program|script hash|payload",
    "addr_wver": r"witness version|segwit version",
    "addr_vbyte": r"version byte|prefix byte|address prefix",
    "sig_valid": r"(is|verify|valid|does).{0,30}signature.{0,30}(valid|match|verif|belong)|signature (valid|verif)",
    "btc_version": r"\bversion\b",
    "btc_nin": r"(how many|number of|count of)\b.{0,15}inputs?|input count",
    "btc_nout": r"(how many|number of|count of)\b.{0,15}outputs?|output count",
    "btc_locktime": r"lock ?time|nlocktime",
    "btc_segwit": r"\bsegwit\b|witness data",
    "btc_total": r"total (output|value|amount)|sum of (the )?outputs?|total sent|total spent",
    "btc_size": r"\b(size|vsize|weight)\b",
    "btc_out_val": r"\bvout\b|(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th) (\w+ )?(output|txout)|output index|output #?\d|\bout\[",
    "btc_op_return": r"op[_ ]?return|null data|embedded (data|message)",
}
_FRX = {k: re.compile(v) for k, v in _F.items()}


_ARGWORD = re.compile(r"\b(argument|parameter|param|arg)s?\b|\b(in|of) the event\b|\bevent (field|parameter|value)\b")


# A leading enumerator ("Q3:", "Question 2.", "1)", "2.", "(a)", "[4]") is not the question's opening.
_ENUMERATOR = re.compile(r"^\s*(?:(?:q(?:uestion)?|part|task)\s*#?\d+[a-z]?\s*[:.)\]]?|\(?\d+[a-z]?[).\]:]|\(?[a-h]\)"
                         r"|\[\d+\])\s+")


def _question_form(t):
    """(yes/no form, wh form) from the question's own opening: 'is/does/...' or 'yes or no' asks for a
    boolean, 'what/which/give/...' asks for a value. Both or neither is ambiguous. A leading enumerator
    ('Q3:', '1)') is skipped first."""
    t0 = _ENUMERATOR.sub("", t.strip(), count=1)
    yn = bool(re.match(r"(is|does|do|are|can|has|was|verify|check|validate|determine whether|true or false|yes or no)\b", t0)
              or re.search(r"yes or no|true or false|yes/no|true/false", t0))
    wh = bool(re.match(r"(what|which|give|provide|convert|compute|derive|write|submit|enter|return)\b", t0))
    return yn, wh


_SEGWIT_WORD = re.compile(r"\b(native )?segwit\b|\bbech32m?\b|witness data")


def route(q):
    """The set of fields a question names (text and answer id)."""
    t = _qtext(q)
    got = {k for k, rx in _FRX.items() if rx.search(t)}
    if "addr_wver" in got and not _question_form(t)[0]:
        # "what is the segwit/witness version": the version field, not the address type or a segwit yes/no
        got -= {"addr_type", "btc_segwit"}
    if {"addr_type", "btc_segwit"} <= got:
        # "segwit" names both the address type and the segwit yes/no (B-243). A yes/no opening ("is this
        # transaction segwit?", "does the address use segwit?") is the yes/no field; a what/which question
        # that names the address type without the segwit word ("what kind of address is this: legacy or
        # segwit?") is the type; anything else stays ambiguous.
        yn, wh = _question_form(t)
        if yn and not wh:
            got.discard("addr_type")
        elif wh and not yn and _FRX["addr_type"].search(_SEGWIT_WORD.sub(" ", t)):
            got.discard("btc_segwit")
    if "tx_auth_authority" in got:
        got.discard("tx_from")             # "who signed the authorization" is the authority, not the tx sender
    if "tx_auth_address" in got:
        got.discard("tx_to")
    if got & {"checksum_valid", "checksum_form"}:
        # yes/no or the checksummed form: only the question's own opening says which; else neither
        yn, wh = _question_form(t)
        got -= {"checksum_valid", "checksum_form"}
        if yn and not wh:
            got.add("checksum_valid")
        elif wh and not yn:
            got.add("checksum_form")
        else:
            got.add("ambiguous_checksum")
    if _ARGWORD.search(t):
        got -= {"tx_to", "tx_value", "tx_from", "tx_nonce", "tx_gas_limit", "tx_gas_price", "tx_chain_id", "tx_max_fee",
                "tx_tip", "tx_type", "n_selectors", "btc_version", "tx_auth_address", "tx_auth_authority", "tx_n_auth"}
        got.add("arg_n")
    if got & {"n_selectors", "list_selectors"}:
        got.discard("selector")
    if "btc_out_val" in got:
        got -= {"tx_value", "btc_nout", "btc_nin"}
    if "addr_from_priv" in got or "addr_from_pub" in got:
        got.discard("checksum_form")
        got.discard("secret")
        got.discard("addr_type")
    if "tx_hash" in got:
        got -= {"tx_value", "tx_type"}
    if "wtxid" in got:
        got.discard("tx_hash")
    for broad in ("btc_version",):
        # "version" is a field only when nothing about solc / witness / compiler is also said
        if broad in got and got & {"solc", "addr_wver", "addr_vbyte", "tx_type"}:
            got.discard(broad)
    if "fn_name" in got or "fn_sig" in got:
        got.discard("selector") if not re.search(r"selector|method ?id|function id|4.?byte", t) else None
    if "tx_value" in got and got & {"arg_n"}:
        got.discard("tx_value")
    return got


def _qaddrs(q):
    return sorted({m.group(0) for m in _ADDR_RE.finditer(_qraw(q))})


def _one(items):
    return items[0] if len(items) == 1 else None


def _of(arts, *kinds):
    return [a for a in arts if a["kind"] in kinds]


# ---------------------------------------------------------------------------- answers

def _pick(field, shape, options):
    opts, seen = [], set()
    for name, value in options:
        if value is None:
            continue
        value = str(value)
        if (name, value) not in seen:
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    key = re.sub(r"[^a-z0-9_+./-]", "_", f"{KEY}.{field}/{shape}".lower())
    try:
        return labels.pick(key, opts)
    except ValueError:
        return None


def _addr_opts(raw20: bytes):
    ck = eip55(raw20)
    return [("checksummed", ck), ("lowercase", "0x" + raw20.hex()), ("no_prefix", raw20.hex()),
            ("lowercase_no_prefix", raw20.hex())] if ck else []


def _int_opts(n, t):
    units = []
    if re.search(r"\bwei\b", t):
        units = [("wei", str(n)), ("hex", hex(n)), ("ether", _units(n, 18))]
    elif re.search(r"\bgwei\b", t):
        units = [("gwei", _units(n, 9)), ("wei", str(n)), ("hex", hex(n))]
    elif re.search(r"\beth(er)?\b", t):
        units = [("ether", _units(n, 18)), ("wei", str(n)), ("hex", hex(n))]
    else:
        units = [("decimal", str(n)), ("hex", hex(n)), ("hex_0x_padded", "0x" + format(n, "064x"))]
    return units


def _units(n, dec):
    ip, fp = divmod(n, 10 ** dec)
    return str(ip) if not fp else f"{ip}.{str(fp).rjust(dec, '0').rstrip('0')}"


def _btc_amount_opts(n, t):
    if re.search(r"\b(btc|bitcoin)\b", t) and not re.search(r"\bsat(oshi)?s?\b", t):
        return [("btc", _units(n, 8)), ("satoshi", str(n))]
    return [("satoshi", str(n)), ("btc", _units(n, 8))]


def _hexopts(b: bytes, prefix=True):
    return [("hex_0x", "0x" + b.hex()), ("hex", b.hex())] if prefix else [("hex", b.hex()), ("hex_0x", "0x" + b.hex())]


def _ord_index(t):
    """(index, base) of an output named in the question. 'vout N' / 'output index N' is a zero-based index;
    'first/second/... output' is one-based; a bare 'output N' is ambiguous, so None."""
    m = re.search(r"\b(?:vout|output index|index)\s*[:#=]?\s*(\d+)\b", t)
    if m:
        return int(m.group(1))
    words = {"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5, "1st": 1, "2nd": 2, "3rd": 3, "4th": 4, "5th": 5}
    m = re.search(r"\b(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th) (?:\w+ )?(?:output|vout|txout)\b", t)
    if m:
        return words[m.group(1)] - 1
    return None


def _answer_evm_tx(fld, tx, t, shape):
    if fld == "tx_hash":
        return _pick("tx_hash", shape, _hexopts(bytes.fromhex(tx["hash"])))
    if fld == "tx_from":
        if not tx.get("from"):
            return None
        return _pick("tx_from", shape, _addr_opts(bytes.fromhex(tx["from"])))
    if fld == "tx_to":
        if tx["to"] is None:
            return None
        return _pick("tx_to", shape, _addr_opts(bytes.fromhex(tx["to"])))
    if fld == "tx_value":
        return _pick("tx_value", shape, _int_opts(tx["value"], t))
    if fld == "tx_nonce":
        return _pick("tx_nonce", shape, [("decimal", tx["nonce"]), ("hex", hex(tx["nonce"]))])
    if fld == "tx_gas_limit":
        return _pick("tx_gas_limit", shape, [("decimal", tx["gas_limit"]), ("hex", hex(tx["gas_limit"]))])
    if fld == "tx_gas_price":
        if "gas_price" in tx:
            return _pick("tx_gas_price", shape, _int_opts(tx["gas_price"], t if "gwei" in t or "wei" in t else t + " gwei"))
        return None
    if fld == "tx_max_fee":
        return _pick("tx_max_fee", shape, _int_opts(tx["max_fee"], t if "gwei" in t or "wei" in t else t + " gwei")) \
            if "max_fee" in tx else None
    if fld == "tx_tip":
        return _pick("tx_tip", shape, _int_opts(tx["max_priority_fee"], t if "gwei" in t or "wei" in t else t + " gwei")) \
            if "max_priority_fee" in tx else None
    if fld == "tx_chain_id":
        return _pick("tx_chain_id", shape, [("decimal", tx["chain_id"]), ("hex", hex(tx["chain_id"]))]) \
            if tx["chain_id"] is not None else None
    if fld == "tx_type":
        names = TX_TYPE_NAMES
        return _pick("tx_type", shape, [("number", tx["type"]), ("hex", "0x%02x" % tx["type"]), ("name", names[tx["type"]])])
    if fld in ("tx_auth_address", "tx_auth_authority", "tx_n_auth"):
        auths = tx.get("authorizations")
        if not auths:
            return None                    # only an EIP-7702 transaction carries authorizations
        if fld == "tx_n_auth":
            return _pick("n_authorizations", shape, [("decimal", len(auths))])
        if len(auths) != 1:
            return None                    # several authorizations: the question must not guess which one
        a = auths[0]
        if fld == "tx_auth_address":
            return _pick("authorization_address", shape, _addr_opts(bytes.fromhex(a["address"])))
        if a["authority"] is None:
            return None
        return _pick("authorization_authority", shape, _addr_opts(bytes.fromhex(a["authority"])))
    if fld == "tx_creation":
        return _pick("tx_creation", shape, [("yes_no", "yes" if tx["creation"] else "no"),
                                            ("true_false", "true" if tx["creation"] else "false")])
    if fld == "selector":
        if tx["selector"] is None:
            return None
        return _pick("selector", shape, _hexopts(bytes.fromhex(tx["selector"])))
    return None


def _answer_selector_family(fld, q, t, sel_hex, abi, calldata, shape):
    """selector / fn_name / fn_sig / topic0 / arg decode for a known 4-byte selector (+ optional ABI + calldata)."""
    table = common_selector_table()
    fn = None
    if abi is not None and sel_hex is not None:
        hits = [f for f in abi["functions"] if f["sel"] == sel_hex]
        fn = hits[0] if len(hits) == 1 else None
    if fld == "selector":
        return _pick("selector", shape, _hexopts(bytes.fromhex(sel_hex))) if sel_hex else None
    if fld in ("fn_name", "fn_sig"):
        if fn is not None:
            if fld == "fn_name":
                return _pick("fn_name", shape + "+abi", [("name", fn["name"]), ("signature", fn["signature"])])
            return _pick("fn_sig", shape + "+abi", [("signature", fn["signature"])])
        if sel_hex in table and abi is None:
            c = table[sel_hex]
            if len(c) == 1:
                nm = c[0].split("(")[0]
                return _pick(fld, shape + "+common_table", [("name", nm)] if fld == "fn_name" else [("signature", c[0])])
        return None
    return None


def _struct_fields(params, fn_args, depth=0):
    """(name, type, value) of every NAMED component inside the tuple (struct) arguments, nested structs
    included (B-243), so a question may name a struct field ("the amount of the order"). Arrays of
    structs are not expanded: which element is meant is not named."""
    out = []
    if depth > MAX_ABI_DEPTH or not isinstance(params, list):
        return out
    if len(params) != len(fn_args):
        # an event drops its hashed indexed arguments: pair the rest by name
        by_name = {p.get("name"): p for p in params if isinstance(p, dict) and p.get("name")}
        params = [by_name.get(name) for name, _, _ in fn_args]
    for p, (name, typ, val) in zip(params, fn_args):
        comps = p.get("components") if isinstance(p, dict) else None
        if not isinstance(comps, list) or not isinstance(val, tuple) or len(comps) != len(val):
            continue
        try:
            kids = [(c.get("name") or "", _canon_type(c), v) for c, v in zip(comps, val)]
        except (_Bad, AttributeError):
            continue
        out.extend(k for k in kids if k[0])
        out.extend(_struct_fields(comps, kids, depth + 1))
    return out


def _answer_args(q, t, fn_args, shape, params=None):
    """The value of one decoded argument, named by the question exactly once (by its ABI name, by ordinal,
    or by the name of a field inside a struct argument)."""
    ords = {"first": 0, "second": 1, "third": 2, "fourth": 3, "fifth": 4, "1st": 0, "2nd": 1, "3rd": 2, "4th": 3, "5th": 4}
    m = re.search(r"\b(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th) (argument|parameter|arg|param|input)\b", t)
    cands = list(fn_args) + _struct_fields(params, fn_args)
    idx = []
    if m:
        idx.append(ords[m.group(1)])
    for i, (name, typ, val) in enumerate(cands):
        if name and not name.startswith("arg") and re.search(r"(?<![a-z0-9])" + re.escape(name.lower().lstrip("_")) + r"(?![a-z0-9])", t):
            idx.append(i)
    idx = sorted(set(idx))
    if len(idx) != 1 or idx[0] >= len(cands):
        return None
    name, typ, val = cands[idx[0]]
    return _pick(f"arg_{re.sub(r'[^a-z0-9]', '', name.lower()) or idx[0]}", shape, _render(typ, val, t))


def _render(typ, val, t):
    if typ == "address":
        return _addr_opts(bytes.fromhex(val[2:]))
    if typ.startswith(("uint", "int")) and isinstance(val, int):
        return _int_opts(val, t)
    if typ == "bool":
        return [("true_false", "true" if val else "false"), ("yes_no", "yes" if val else "no")]
    if isinstance(val, bytes):
        return _hexopts(val)
    if isinstance(val, str):
        return [("raw", val)]
    return []


def _answer_bytecode(fld, q, t, rep):
    shape = "dispatch" if fld in ("n_selectors", "list_selectors") else "code"
    if fld == "n_selectors":
        return _pick("n_selectors", "solc_eq_pattern", [("decimal", len(rep["selectors"]))]) if rep["selectors"] else None
    if fld == "list_selectors":
        s = rep["selectors"]
        if not s:
            return None
        return _pick("selectors", "solc_eq_pattern", [("comma_0x", ",".join("0x" + x for x in s)), ("comma", ",".join(s)),
                                                      ("comma_space_0x", ", ".join("0x" + x for x in s)),
                                                      ("newline_0x", "\n".join("0x" + x for x in s)),
                                                      ("sorted_comma_0x", ",".join("0x" + x for x in sorted(s)))])
    if fld == "rt_offset":
        return _pick("runtime_offset", "creation_codecopy_pattern", [("decimal", rep["runtime_offset"]),
                                                                      ("hex", hex(rep["runtime_offset"]))]) \
            if rep["creation"] else None
    if fld == "rt_length":
        return _pick("runtime_length", "creation_codecopy_pattern", [("decimal", rep["runtime_length"]),
                                                                      ("hex", hex(rep["runtime_length"]))]) \
            if rep["creation"] else None
    if fld == "solc":
        return _pick("solc_version", "metadata_cbor", [("dotted", rep["solc"]), ("v_prefixed", "v" + rep["solc"])]) \
            if rep["solc"] else None
    if fld == "n_insns":
        return _pick("n_instructions", "linear_sweep", [("decimal", rep["n_instructions"])])
    if fld == "literal":
        s = rep["strings"]
        return _pick("literal", "push_ascii", [("raw", s[0])]) if len(s) == 1 else None
    return None


def _answer_address(fld, q, t, arts):
    # text addresses in the question count, files first
    eth = _of(arts, "eth_address")
    qa = _qaddrs(q)
    cls = None
    if len(eth) == 1 and not qa:
        cls = eth[0]["obj"]
    elif not eth and len(qa) == 1:
        cls = classify_eth_address(qa[0])
    elif len(eth) == 1 and len(qa) == 1 and classify_eth_address(qa[0]) and \
            classify_eth_address(qa[0])["bytes"] == eth[0]["obj"]["bytes"]:
        cls = eth[0]["obj"]
    if cls is None:
        return None
    if fld == "checksum_valid":
        if cls["checksum"] == "none":
            return None            # no checksum to validate: lower/upper-case hex says nothing
        ok = cls["checksum"] == "valid"
        return _pick("checksum_valid", "eip55_" + cls["checksum"], [("yes_no", "yes" if ok else "no"),
                                                                    ("valid_invalid", "valid" if ok else "invalid"),
                                                                    ("true_false", "true" if ok else "false")])
    if fld == "checksum_form":
        # An address whose mixed case is WRONG still names one 20-byte address: its checksummed form is a fact,
        # offered under its own shape so a judged name for a valid input is not assumed for a corrupted one.
        return _pick("checksummed_address", "from_" + {"valid": "valid_checksum", "invalid": "wrong_case",
                                                       "none": "single_case"}[cls["checksum"]],
                     [("checksummed", cls["checksummed"])])
    return None


def _answer_btc_address(fld, q, t, arts):
    cands = [a["obj"] for a in _of(arts, "btc_address")]
    if not cands:
        toks = re.findall(r"(?<![0-9A-Za-z])(?:bc1|tb1|BC1|TB1|[13mn2])[0-9A-Za-z]{13,89}(?![0-9A-Za-z])", _qraw(q))
        cl = [classify_btc_address(x) for x in toks]
        cands = [c for c in cl if c]
        if len(cands) != 1 or len([x for x in toks if classify_btc_address(x)]) != 1:
            return None
    if len(cands) != 1:
        return None
    a = cands[0]
    if a["kind"] == "wif":
        return None
    shape = a["encoding"] + "_" + a["kind"]
    if fld == "addr_type":
        names = {"p2pkh": ["p2pkh", "P2PKH", "pay-to-pubkey-hash", "legacy"], "p2sh": ["p2sh", "P2SH", "pay-to-script-hash"],
                 "p2wpkh": ["p2wpkh", "P2WPKH", "bech32", "segwit", "native_segwit"], "p2wsh": ["p2wsh", "P2WSH", "bech32"],
                 "p2tr": ["p2tr", "P2TR", "taproot", "bech32m"], "segwit_other": ["segwit"]}[a["kind"]]
        return _pick("address_type", a["encoding"], [(f"n{i}_{n.lower()}", n) for i, n in enumerate(names)])
    if fld == "addr_net":
        if a["encoding"] == "base58check":
            if a["network"] == "testnet" and a["version_byte"] in (0x6F, 0xC4):
                return _pick("network", shape, [("testnet", "testnet"), ("bitcoin_testnet", "bitcoin testnet")])
            return _pick("network", shape, [("mainnet", "mainnet"), ("bitcoin_mainnet", "bitcoin mainnet"), ("bitcoin", "bitcoin")])
        hrp = a["hrp"]
        return _pick("hrp", shape, [("hrp", hrp)]) if re.search(r"\bhrp\b|human.readable", t) else \
            _pick("network", shape, [(a["network"], a["network"]), ("btc_" + a["network"], "bitcoin " + a["network"])])
    if fld == "addr_hash" and a["payload"] is not None:
        return _pick("payload", shape, _hexopts(a["payload"], prefix=False))
    if fld == "addr_wver" and "witness_version" in a:
        return _pick("witness_version", shape, [("decimal", a["witness_version"])])
    if fld == "addr_vbyte" and "version_byte" in a:
        return _pick("version_byte", shape, [("hex_0x", "0x%02x" % a["version_byte"]), ("decimal", a["version_byte"]),
                                              ("hex", "%02x" % a["version_byte"])])
    return None


def _answer_btc_tx(fld, q, t, tx):
    shape = "segwit" if tx["segwit"] else "legacy"
    if fld == "tx_hash":
        return _pick("txid", shape, [("hex", tx["txid"]), ("hex_0x", "0x" + tx["txid"])])
    if fld == "wtxid":
        return _pick("wtxid", shape, [("hex", tx["wtxid"])])
    if fld == "btc_version":
        return _pick("version", shape, [("decimal", tx["version"])])
    if fld == "btc_nin":
        return _pick("n_inputs", shape, [("decimal", len(tx["inputs"]))])
    if fld == "btc_nout":
        return _pick("n_outputs", shape, [("decimal", len(tx["outputs"]))])
    if fld == "btc_locktime":
        return _pick("locktime", shape, [("decimal", tx["locktime"]), ("hex", hex(tx["locktime"]))])
    if fld == "btc_segwit":
        return _pick("is_segwit", shape, _segwit_opts(tx["segwit"], t))
    if fld == "btc_total":
        return _pick("total_output", shape, _btc_amount_opts(tx["total_out"], t))
    if fld == "btc_size":
        if re.search(r"\bvsize\b|virtual", t):
            return _pick("vsize", shape, [("decimal", tx["vsize"])])
        if re.search(r"\bweight\b", t):
            return _pick("weight", shape, [("decimal", tx["weight"])])
        if re.search(r"\bsize\b", t) and not re.search(r"\bvsize\b|weight", t):
            return _pick("size", shape, [("bytes", tx["size"])])
        return None
    if fld == "btc_op_return":
        d = [o["data"] for o in tx["outputs"] if o["type"] == "op_return" and o["data"] is not None]
        if len(d) != 1:
            return None
        opts = [("hex", d[0].hex())]
        try:
            s = d[0].decode("utf-8")
            if s.isprintable():
                opts.insert(0, ("utf8", s))
        except UnicodeDecodeError:
            pass
        return _pick("op_return", shape, opts)
    if fld == "btc_out_val":
        idx = _ord_index(t)
        if idx is None or not 0 <= idx < len(tx["outputs"]):
            return None
        o = tx["outputs"][idx]
        if re.search(r"script type|scriptpubkey type|type of (the )?(script|output)", t):
            return _pick("out_script_type", shape, [("name", o["type"]), ("upper", o["type"].upper())])
        if re.search(r"address", t):
            return _pick("out_address", shape + "+mainnet_rendering", [("address", o["address"])]) if o["address"] else None
        if re.search(r"value|amount|satoshi|\bsats?\b|btc|how much", t):
            return _pick("out_value", shape, _btc_amount_opts(o["value"], t))
        return None
    return None


_SEGWIT_CHOICE = re.compile(r"\b(segwit|witness) or (legacy|non.?segwit|non.?witness)\b|"
                            r"\b(legacy|non.?segwit|non.?witness) or (native )?(segwit|witness)\b")


def _segwit_opts(is_segwit: bool, t: str):
    """'is it segwit or legacy?' names its own two answers; any other yes/no takes yes/no or true/false."""
    if _SEGWIT_CHOICE.search(t):
        return [("choice", "segwit" if is_segwit else "legacy")]
    return [("yes_no", "yes" if is_segwit else "no"), ("true_false", "true" if is_segwit else "false")]


def _answer_address_segwit(q, t, arts):
    """Segwit yes/no for the one Bitcoin address of the challenge (B-243). A P2SH address may wrap a segwit
    script (P2SH-P2WPKH) or not, which the address cannot show, so it is None; a WIF is never an address."""
    cands = [a["obj"] for a in _of(arts, "btc_address")]
    if not cands:
        toks = re.findall(r"(?<![0-9A-Za-z])(?:bc1|tb1|BC1|TB1|[13mn2])[0-9A-Za-z]{13,89}(?![0-9A-Za-z])", _qraw(q))
        cands = [c for c in (classify_btc_address(x) for x in toks) if c]
    if len(cands) != 1:
        return None
    a = cands[0]
    if a["kind"] in ("wif", "p2sh"):
        return None
    yes = a["encoding"] != "base58check"
    return _pick("address_is_segwit", a["encoding"] + "_" + a["kind"], _segwit_opts(yes, t))


def _solve_one(q, arts, ctx):
    t = _qtext(q)
    fields = route(q)
    if "flag" in fields or ("secret" in fields and not (fields & {"addr_from_priv", "addr_from_pub"})):
        return None
    fields -= {"secret", "flag"}
    # Disambiguate the broad value/output router words against the artifacts present.
    evtx, btx = _of(arts, "evm_tx"), _of(arts, "btc_tx")
    if len(fields) > 1:
        # a tx_value mention beside a more specific tx field is the word "value" in passing only when the
        # specific field is a hash / selector / name; otherwise it is ambiguous
        pass
    if len(fields) != 1:
        return None
    fld = next(iter(fields))

    if fld in ("addr_from_pub", "addr_from_priv"):
        return _address_derivation(fld, q, t, arts)
    if fld in ("checksum_valid", "checksum_form"):
        return _answer_address(fld, q, t, arts)
    if fld in ("addr_type", "addr_net", "addr_hash", "addr_wver", "addr_vbyte") and not (evtx or btx):
        return _answer_btc_address(fld, q, t, arts)
    if fld == "sig_valid":
        return None
    if fld in ("tx_from",) and not evtx:
        sg = _of(arts, "sig")
        if len(sg) == 1:
            a, scheme = recover_signature(sg[0]["obj"])
            return _pick("signer", scheme, _addr_opts(a)) if a else None
        return None
    if fld == "tx_from" and evtx and _of(arts, "sig"):
        return None
    if fld == "btc_segwit" and not btx and not evtx:
        return _answer_address_segwit(q, t, arts)
    if fld.startswith("btc_") or (fld in ("tx_hash", "wtxid") and btx and not evtx):
        tx = _one(btx)
        if tx is None or evtx:
            return None
        return _answer_btc_tx(fld, q, t, tx["obj"])
    if fld in ("selector", "fn_name", "fn_sig", "topic0", "event_name", "arg_n") or fld.startswith("tx_"):
        return _evm_family(fld, q, t, arts, evtx, btx)
    if fld in ("n_selectors", "list_selectors", "rt_offset", "rt_length", "solc", "n_insns", "literal"):
        bc = _of(arts, "bytecode")
        if len(bc) != 1:
            return None
        rep = bytecode_report(bc[0]["obj"]["code"])
        return _answer_bytecode(fld, q, t, rep) if rep else None
    return None


def _address_derivation(fld, q, t, arts):
    if fld == "addr_from_pub":
        pk = _of(arts, "pubkey")
        if len(pk) != 1:
            return None
        a = pub_to_address(pk[0]["obj"])
        return _pick("address_from_pubkey", "secp256k1_keccak", _addr_opts(a)) if a else None
    # a private key is never emitted: only the address derived from the one 32-byte key the challenge supplies
    ks = _of(arts, "key32")
    if len(ks) != 1:
        return None
    d = int.from_bytes(ks[0]["obj"]["bytes"], "big")
    if not 1 <= d < _N:
        return None
    pt = _mul(d, _G)
    a = pub_to_address(pt) if pt else None
    return _pick("address_from_provided_key", "secp256k1_keccak", _addr_opts(a)) if a else None


_SIG_TEXT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\((?:[A-Za-z0-9_,\[\]()]*)\)")


def _sigs_in(text):
    """Function/event signatures typed in a question, tuple arguments included (`f((uint256,address)[])`).
    A match that swallowed a closing parenthesis of the surrounding prose is trimmed until balanced."""
    out = []
    for m in _SIG_TEXT.finditer(text or ""):
        sig = m.group(0)
        while sig.count(")") > sig.count("(") and sig.endswith(")"):
            sig = sig[:-1]
        if sig.count("(") == sig.count(")"):
            out.append(sig)
    return out


def _evm_family(fld, q, t, arts, evtx, btx):
    abis = _of(arts, "abi")
    abi = abis[0]["obj"] if len(abis) == 1 else None
    if len(abis) > 1:
        # several ABIs: only usable if they agree on every selector name (merge exactly)
        return None
    # a bare blob of 4+32k bytes is calldata only when a provided ABI function owns its selector
    cd = [a for a in _of(arts, "calldata") if abi is not None and any(f["sel"] == a["obj"]["data"][:4].hex() for f in abi["functions"])]
    logs = _of(arts, "logs")
    tx = _one(evtx) if not btx else None
    shape = "evm_tx"
    # signature typed into the question: selector of that canonical signature
    if fld == "selector":
        sg = _sigs_in(_qraw(q))
        sels = {s: selector_of_signature(s) for s in sg}
        sels = {s: v for s, v in sels.items() if v}
        if len(sels) == 1 and not evtx and not cd:
            return _pick("selector", "of_signature", _hexopts(next(iter(sels.values()))))
        if abi and not evtx and not cd:
            names = [f for f in abi["functions"] if re.search(r"(?<![a-z0-9_])" + re.escape(f["name"].lower()) + r"(?![a-z0-9_])", t)]
            if len(names) == 1 and len([f for f in abi["functions"] if f["name"] == names[0]["name"]]) == 1:
                return _pick("selector", "of_abi_function", _hexopts(bytes.fromhex(names[0]["sel"])))
    if fld == "topic0" and abi:
        evn = [e for e in abi["events"] if re.search(r"(?<![a-z0-9_])" + re.escape(e["name"].lower()) + r"(?![a-z0-9_])", t)]
        if len(evn) == 1 and len([e for e in abi["events"] if e["name"] == evn[0]["name"]]) == 1:
            return _pick("topic0", "of_abi_event", _hexopts(bytes.fromhex(evn[0]["topic"]), prefix=True))
        sg = _sigs_in(_qraw(q))
        if len(sg) == 1 and keccak(sg[0].encode()):
            return _pick("topic0", "of_signature", _hexopts(keccak(sg[0].encode())))
    if fld == "topic0" and not abi:
        sg = _sigs_in(_qraw(q))
        if len(sg) == 1 and selector_of_signature(sg[0]) and keccak(sg[0].encode()):
            return _pick("topic0", "of_signature", _hexopts(keccak(sg[0].encode())))
    if fld in ("event_name", "arg_n") and logs:
        if len(logs) != 1 or len(logs[0]["obj"]) != 1 or abi is None:
            return None
        lg = logs[0]["obj"][0]
        evs = [e for e in abi["events"] if lg["topics"] and e["topic"] == lg["topics"][0].hex()]
        if len(evs) != 1 or evs[0].get("anonymous"):
            return None
        if fld == "event_name":
            return _pick("event_name", "abi_topic0", [("name", evs[0]["name"]), ("signature", evs[0]["signature"])])
        dec = _decode_event(evs[0], lg)
        return _answer_args(q, t, dec, "event", evs[0].get("inputs")) if dec else None
    # sources of a selector / calldata: a tx's data, a calldata file
    data = None
    if tx is not None and not cd:
        data = tx["obj"]["data"]
    elif tx is None and len(cd) == 1:
        data = cd[0]["obj"]["data"]
    elif tx is not None and cd:
        return None
    if fld.startswith("tx_") or (fld == "tx_hash"):
        if tx is None:
            return None
        return _answer_evm_tx(fld, tx["obj"], t, _txshape(tx["obj"]))
    if fld == "selector":
        if data is None:
            return None
        return _answer_selector_family("selector", q, t, data_sel(data), abi, None, "calldata")
    if fld in ("fn_name", "fn_sig"):
        if data is None or len(data) < 4:
            return None
        return _answer_selector_family(fld, q, t, data_sel(data), abi, data, "calldata")
    if fld == "arg_n":
        if data is None or abi is None:
            return None
        dc = decode_calldata(abi, data)
        return _answer_args(q, t, dc[1], "calldata", dc[0].get("inputs")) if dc else None
    return None


def _txshape(tx):
    return TX_TYPE_NAMES[tx["type"]] + ("" if tx["signed"] else "_unsigned")


def _decode_event(ev, lg):
    ins = ev.get("inputs") or []
    try:
        types = [_canon_type(p) for p in ins]
    except _Bad:
        return None
    nodes = [parse_abi_type(t) for t in types]
    if any(n is None for n in nodes):
        return None
    idx = [p for p in ins if p.get("indexed")]
    if len(lg["topics"]) != 1 + len(idx):
        return None
    vals, ti = {}, 1
    ndyn_types = []
    for i, p in enumerate(ins):
        if p.get("indexed"):
            if nodes[i][0] != "base" or _tdyn(nodes[i]):
                vals[i] = None             # an indexed string/bytes/array/tuple is only the hash of its encoding
            else:
                try:
                    vals[i] = _word_value(types[i], lg["topics"][ti])
                except _Bad:
                    return None
            ti += 1
        else:
            ndyn_types.append(i)
    if ndyn_types:
        dec = abi_decode([types[i] for i in ndyn_types], lg["data"])
        if dec is None:
            return None
        for i, v in zip(ndyn_types, dec):
            vals[i] = v
    elif lg["data"]:
        return None
    return [(p.get("name") or f"arg{i}", types[i], vals[i]) for i, p in enumerate(ins) if vals.get(i) is not None]


def _secrets(arts):
    """Hex/byte strings of secrets the artifacts carry, which no answer may contain."""
    out = set()
    for a in arts:
        if a["kind"] == "key32":
            out.add(a["obj"]["bytes"].hex())
        if a["kind"] == "btc_address" and a["obj"]["kind"] == "wif":
            out.add("wif")
    return out


def solve_set(questions, files, ctx) -> dict:
    out = {}
    if questions is not None and not isinstance(questions, (list, tuple)):
        return out
    try:
        arts = read_artifacts(files)
    except Exception:  # noqa: BLE001
        arts = []
    secrets = _secrets(arts)
    for q in questions or []:
        if not isinstance(q, dict):
            continue
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        try:
            ans = _solve_one(q, arts, ctx)
        except Exception:  # noqa: BLE001 - a value that cannot be read is no answer
            ans = None
        if isinstance(ans, str) and any(s in ans.lower() for s in secrets if s != "wif"):
            ans = None
        out[qid] = ans
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


# ---------------------------------------------------------------------------- wallet derivation (offline, caller-supplied secrets)

def bip39_seed(mnemonic: str, passphrase: str = "", wordlist=None):
    """BIP39 mnemonic -> 64-byte seed, optionally checksum-validating a supplied 2048-word list.

    BIP39 key stretching itself does not require a word list; when one is supplied this function
    additionally proves every word and the entropy checksum. Challenge data is never executed.
    """
    if not isinstance(mnemonic, str) or not isinstance(passphrase, str):
        return None
    phrase = unicodedata.normalize("NFKD", " ".join(mnemonic.strip().split()))
    words = phrase.split(" ") if phrase else []
    try:
        phrase_bytes = phrase.encode("utf-8")
        salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8")
    except UnicodeError:
        return None
    if len(words) not in (12, 15, 18, 21, 24) or len(phrase_bytes) > 4096:
        return None
    if wordlist is not None:
        try:
            catalog = list(wordlist)
        except (TypeError, MemoryError):
            return None
        if len(catalog) != 2048 or any(not isinstance(w, str) for w in catalog) or len(set(catalog)) != 2048:
            return None
        indices = {unicodedata.normalize("NFKD", word): index for index, word in enumerate(catalog)}
        if len(indices) != 2048:
            return None
        if any(word not in indices for word in words):
            return None
        bits = "".join(f"{indices[word]:011b}" for word in words)
        entropy_bits = len(bits) * 32 // 33
        entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, "big")
        checksum = bits[entropy_bits:]
        expected = f"{hashlib.sha256(entropy).digest()[0]:08b}"[:len(checksum)]
        if checksum != expected:
            return None
    return hashlib.pbkdf2_hmac("sha512", phrase_bytes, salt, 2048, 64)


def _compressed_pub(private: int) -> bytes:
    point = _mul(private, _G)
    if point is None:
        raise ValueError("invalid private scalar")
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def _fingerprint(private: int) -> bytes:
    return hash160(_compressed_pub(private))[:4]


def bip32_master(seed: bytes):
    if not isinstance(seed, bytes) or not 16 <= len(seed) <= 64:
        return None
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    private = int.from_bytes(digest[:32], "big")
    if not 1 <= private < _N:
        return None
    return {"private": private, "chain_code": digest[32:], "depth": 0, "index": 0,
            "parent_fingerprint": b"\0\0\0\0"}


def bip32_child(node: dict, index: int):
    if not isinstance(node, dict) or type(index) is not int:
        return None
    try:
        private, chain = int(node["private"]), bytes(node["chain_code"])
        depth = int(node.get("depth", 0))
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= private < _N or len(chain) != 32 or not 0 <= index < 1 << 32 or not 0 <= depth < MAX_DERIVATION_DEPTH:
        return None
    data = (b"\0" + private.to_bytes(32, "big")) if index & 0x80000000 else _compressed_pub(private)
    digest = hmac.new(chain, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (private + tweak) % _N
    if tweak >= _N or child == 0:
        return None
    return {"private": child, "chain_code": digest[32:], "depth": depth + 1, "index": index,
            "parent_fingerprint": _fingerprint(private)}


def parse_bip32_path(path: str):
    if not isinstance(path, str) or len(path) > 4096:
        return None
    pieces = path.strip().split("/")
    if not pieces or pieces[0] not in ("m", "M") or len(pieces) - 1 > MAX_DERIVATION_DEPTH:
        return None
    out = []
    for piece in pieces[1:]:
        hardened = piece.endswith(("'", "h", "H"))
        number = piece[:-1] if hardened else piece
        if not number.isascii() or not number.isdigit() or (len(number) > 1 and number.startswith("0")):
            return None
        value = int(number)
        if value >= 1 << 31:
            return None
        out.append(value | (0x80000000 if hardened else 0))
    return out


def bip32_derive(seed_or_node, path: str):
    indices = parse_bip32_path(path)
    if isinstance(seed_or_node, bytes):
        node = bip32_master(seed_or_node)
    elif isinstance(seed_or_node, dict):
        node = dict(seed_or_node)
    else:
        return None
    if indices is None or node is None:
        return None
    for index in indices:
        node = bip32_child(node, index)
        if node is None:
            return None
    return node


def bip32_extended(node: dict, *, private: bool = True, testnet: bool = False):
    if not isinstance(node, dict):
        return None
    try:
        key = int(node["private"])
        chain = bytes(node["chain_code"])
        depth, index = int(node["depth"]), int(node["index"])
        parent = bytes(node["parent_fingerprint"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= key < _N or len(chain) != 32 or len(parent) != 4 or not 0 <= depth <= 255 or not 0 <= index < 1 << 32:
        return None
    version = (0x04358394 if private else 0x043587CF) if testnet else (0x0488ADE4 if private else 0x0488B21E)
    material = b"\0" + key.to_bytes(32, "big") if private else _compressed_pub(key)
    raw = (version.to_bytes(4, "big") + bytes([depth]) + parent + index.to_bytes(4, "big")
           + chain + material)
    return b58encode(raw + sha256d(raw)[:4])


def private_to_eth_address(private: int):
    if not isinstance(private, int) or isinstance(private, bool) or not 1 <= private < _N:
        return None
    point = _mul(private, _G)
    raw = pub_to_address(point)
    return None if raw is None else eip55(raw)


def wif_encode(private: int, *, compressed: bool = True, testnet: bool = False):
    if not isinstance(private, int) or isinstance(private, bool) or not 1 <= private < _N:
        return None
    payload = private.to_bytes(32, "big") + (b"\x01" if compressed else b"")
    return b58check_encode(0xEF if testnet else 0x80, payload)


def wif_decode(value: str):
    decoded = b58check_decode(value) if isinstance(value, str) else None
    if decoded is None:
        return None
    version, payload = decoded
    if version not in (0x80, 0xEF) or len(payload) not in (32, 33) or (len(payload) == 33 and payload[-1] != 1):
        return None
    private = int.from_bytes(payload[:32], "big")
    if not 1 <= private < _N:
        return None
    return {"private": private, "compressed": len(payload) == 33,
            "network": "testnet" if version == 0xEF else "mainnet"}


def brainwallet(phrase: str, *, compressed: bool = True, testnet: bool = False):
    if not isinstance(phrase, str) or not phrase:
        return None
    try:
        phrase_bytes = phrase.encode("utf-8")
    except UnicodeError:
        return None
    if len(phrase_bytes) > 4096:
        return None
    private = int.from_bytes(hashlib.sha256(phrase_bytes).digest(), "big")
    if private == 0 or private >= _N:
        return None
    pub = _compressed_pub(private) if compressed else b"\x04" + _mul(private, _G)[0].to_bytes(32, "big") \
        + _mul(private, _G)[1].to_bytes(32, "big")
    btc = b58check_encode(0x6F if testnet else 0x00, hash160(pub))
    return {"private": private, "wif": wif_encode(private, compressed=compressed, testnet=testnet),
            "bitcoin": btc, "ethereum": private_to_eth_address(private)}


def derive_wallet(mnemonic: str, *, passphrase: str = "", paths=None, wordlist=None, testnet=False):
    seed = bip39_seed(mnemonic, passphrase, wordlist)
    if seed is None:
        return None
    paths = paths or ["m/44'/60'/0'/0/0"]
    if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= MAX_DERIVATION_PATHS:
        return None
    derived = []
    for path in paths:
        node = bip32_derive(seed, path)
        if node is None:
            return None
        private = node["private"]
        public = _compressed_pub(private)
        derived.append({"path": path, "private": private.to_bytes(32, "big"), "public": public,
                        "ethereum": private_to_eth_address(private),
                        "bitcoin_p2pkh": b58check_encode(0x6F if testnet else 0x00, hash160(public)),
                        "wif": wif_encode(private, compressed=True, testnet=testnet),
                        "xprv": bip32_extended(node, private=True, testnet=testnet),
                        "xpub": bip32_extended(node, private=False, testnet=testnet)})
    master = bip32_master(seed)
    return {"seed": seed, "master_xprv": bip32_extended(master, private=True, testnet=testnet),
            "master_xpub": bip32_extended(master, private=False, testnet=testnet), "derived": derived}


def decrypt_keystore_v3(document: dict, password: str | bytes):
    """Decrypt and MAC-verify an Ethereum Web3 Secret Storage v3 document, or return None."""
    if not isinstance(document, dict) or document.get("version") != 3:
        return None
    crypto = document.get("crypto", document.get("Crypto"))
    if not isinstance(crypto, dict):
        return None
    try:
        ciphertext = bytes.fromhex(crypto["ciphertext"])
        cipherparams = crypto["cipherparams"]
        iv = bytes.fromhex(cipherparams["iv"])
        kdf, params = str(crypto["kdf"]).lower(), crypto["kdfparams"]
        salt = bytes.fromhex(params["salt"])
        dklen = int(params["dklen"])
        expected_mac = bytes.fromhex(crypto["mac"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not isinstance(password, (str, bytes)) or len(ciphertext) > MAX_KEYSTORE_CIPHERTEXT \
            or len(iv) != 16 or not 32 <= dklen <= 64 or len(salt) > 1024:
        return None
    try:
        password = password.encode("utf-8") if isinstance(password, str) else password
        if kdf == "scrypt":
            n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
            if n < 2 or n > 1 << 20 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
                return None
            # scrypt's V array needs 128*r*n bytes; OpenSSL also wants B/X/T working buffers, so the
            # old fixed 256 MiB cap REJECTED the standard Geth/Web3 default (n=262144, r=8 ≈ 256 MiB)
            # even with the right password. Size maxmem to the real requirement plus slack, and decline
            # (rather than allocate) any param set that would exceed 1 GiB — bounding DoS from untrusted
            # params while covering every real-world keystore.
            needed = 128 * r * n
            if needed > (1 << 30):
                return None
            derived = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen,
                                     maxmem=needed + (64 << 20))
        elif kdf == "pbkdf2":
            iterations = int(params["c"])
            if not 1 <= iterations <= 2_000_000 or str(params.get("prf", "")).lower() != "hmac-sha256":
                return None
            derived = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)
        else:
            return None
    except (KeyError, TypeError, ValueError, OverflowError, MemoryError):
        return None
    actual_mac = keccak(derived[16:32] + ciphertext)
    if actual_mac is None or not hmac.compare_digest(actual_mac, expected_mac):
        return None
    if str(crypto.get("cipher", "")).lower() != "aes-128-ctr":
        return None
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(derived[:16], AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
        private_bytes = cipher.decrypt(ciphertext)
    except Exception:  # optional crypto backend or malformed parameters
        return None
    private = int.from_bytes(private_bytes, "big")
    if len(private_bytes) != 32 or not 1 <= private < _N:
        return None
    address = private_to_eth_address(private)
    stated = document.get("address")
    if isinstance(stated, str) and address is not None and stated.lower().removeprefix("0x") != address.lower().removeprefix("0x"):
        return None
    return {"private": private_bytes, "ethereum": address, "verified_mac": True,
            "kdf": kdf, "cipher": "aes-128-ctr"}


def _storage_key(value, kind):
    if kind == "address":
        if isinstance(value, str):
            value = value.removeprefix("0x")
            if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
                return None
            return bytes.fromhex(value).rjust(32, b"\0")
    if kind in ("uint", "uint256", "int", "int256"):
        try:
            number = int(value, 0) if isinstance(value, str) else int(value)
            return number.to_bytes(32, "big", signed=kind.startswith("int"))
        except (TypeError, ValueError, OverflowError):
            return None
    if kind == "bytes32":
        try:
            raw = bytes.fromhex(value.removeprefix("0x")) if isinstance(value, str) else bytes(value)
        except (TypeError, ValueError):
            return None
        return raw if len(raw) == 32 else None
    if kind in ("string", "bytes"):
        try:
            return value.encode("utf-8") if kind == "string" and isinstance(value, str) else (
                bytes(value) if kind == "bytes" and isinstance(value, (bytes, bytearray)) else None)
        except UnicodeError:
            return None
    return None


def storage_slot(key, slot: int, *, key_type="uint256"):
    """Solidity mapping element slot ``keccak256(h(key) || uint256(slot))``."""
    if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < 1 << 256:
        return None
    encoded = _storage_key(key, key_type)
    if encoded is None:
        return None
    return keccak(encoded + slot.to_bytes(32, "big"))


def nested_storage_slot(keys, slot: int):
    """Apply mapping slots left-to-right from ``[(value,type), ...]`` for nested mappings."""
    if not isinstance(keys, (list, tuple)) or not 1 <= len(keys) <= 64:
        return None
    current = slot
    for entry in keys:
        if isinstance(entry, dict):
            value, kind = entry.get("value"), entry.get("type", "uint256")
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            value, kind = entry
        else:
            return None
        digest = storage_slot(value, current, key_type=kind)
        if digest is None:
            return None
        current = int.from_bytes(digest, "big")
    return current.to_bytes(32, "big")


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(
    r"ethereum|\bevm\b|solidity|smart ?contract|bytecode|opcode|\bselector\b|\bwei\b|\bgwei\b|\bether\b|erc-?20|erc-?721|"
    r"\babi\b|\brlp\b|eip-?55|checksum(med)? address|bitcoin|\bbtc\b|satoshi|segwit|bech32|base58|scriptpubkey|"
    r"blockchain|chain ?id|ecrecover|keccak|\bnonce\b|calldata|\bgas\b|\bsolc\b|op_?return|\btxid\b|taproot|"
    r"transaction hash|contract address|etherscan|web3|metamask|\bwallet\b", re.I)


def signals(questions, files) -> float:
    """0..1: a blockchain artifact parses cleanly in the bytes (a canonical RLP transaction, an ABI, EVM bytecode
    with a solc prologue or dispatch table, a Bitcoin transaction or address, a public key on the curve) AND the
    questions use blockchain vocabulary. No parse, no signal: a 64-byte blob with a generic question is 0.0.
    A private-key-shaped 32-byte file alone is not a blockchain artifact."""
    if questions is not None and not isinstance(questions, (list, tuple)):
        return 0.0
    try:
        arts = [a for a in read_artifacts(files) if a["kind"] not in ("key32", "b58_32", "calldata")]
    except Exception:  # noqa: BLE001
        return 0.0
    qs_addr = any(_qaddrs(q) for q in questions or [])
    if not arts and not qs_addr:
        return 0.0
    hits = set()
    for q in questions or []:
        hits |= {m.group().lower() for m in _WORDS.finditer(_qtext(q))}
    strong = {"evm_tx", "btc_tx", "abi", "bytecode", "logs", "pubkey", "sig"}
    base = 0.45 if any(a["kind"] in strong for a in arts) else 0.3
    score = base + min(0.5, 0.15 * len(hits))
    if not arts:
        score = min(score, 0.45)
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- CLI (offline triage)

def _summary(a):
    k, o = a["kind"], a["obj"]
    if k == "evm_tx":
        return (f"evm tx type {o['type']} chain={o['chain_id']} nonce={o['nonce']} to={o['to']} value={o['value']} "
                f"from={o['from']} selector={o['selector']} hash={o['hash']}")
    if k == "btc_tx":
        return f"bitcoin tx {o['txid']} in={len(o['inputs'])} out={len(o['outputs'])} segwit={o['segwit']}"
    if k == "bytecode":
        r = bytecode_report(o["code"]) or {}
        return f"evm bytecode creation={r.get('creation')} selectors={r.get('selectors')} solc={r.get('solc')}"
    if k == "abi":
        return f"abi: {len(o['functions'])} functions, {len(o['events'])} events"
    if k == "eth_address":
        return f"ethereum address, checksum={o['checksum']}, EIP-55 form {o['checksummed']}"
    if k == "btc_address":
        return f"bitcoin address {o['kind']} {o['network']} ({o['encoding']})"
    if k == "key32":
        return "32-byte hex (a private key or a hash): value withheld"
    return k


class _WalletParser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover - normalized by _wallet_cli
        raise ValueError(message)


def _wallet_json(path):
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_WALLET_JSON + 1)
    if len(raw) > MAX_WALLET_JSON:
        raise ValueError("wallet JSON exceeds 4 MiB cap")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("wallet JSON root must be an object")
    return value


def _wallet_cli(argv):
    parser = _WalletParser(prog="blockchain.py")
    parser.add_argument("operation", choices=("wallet", "keystore", "slot", "wif", "brainwallet"))
    parser.add_argument("input", help="bounded JSON specification")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        data = _wallet_json(args.input)
        if args.operation == "wallet":
            result = derive_wallet(data["mnemonic"], passphrase=data.get("passphrase", ""),
                                   paths=data.get("paths"), wordlist=data.get("wordlist"),
                                   testnet=bool(data.get("testnet", False)))
        elif args.operation == "keystore":
            result = decrypt_keystore_v3(data["keystore"], data["password"])
        elif args.operation == "slot":
            if "keys" in data:
                result = nested_storage_slot(data["keys"], int(data["slot"]))
            else:
                result = storage_slot(data["key"], int(data["slot"]), key_type=data.get("key_type", "uint256"))
        elif args.operation == "wif":
            if "value" in data:
                result = wif_decode(data["value"])
            else:
                private = int(str(data["private"]), 0) if isinstance(data["private"], str) else int(data["private"])
                result = {"wif": wif_encode(private, compressed=bool(data.get("compressed", True)),
                                             testnet=bool(data.get("testnet", False)))}
        else:
            result = brainwallet(data["phrase"], compressed=bool(data.get("compressed", True)),
                                 testnet=bool(data.get("testnet", False)))
        if result is None:
            output = {"candidate": None, "verified": False}
        else:
            output = {"candidate": result, "verified": True, "sensitive": args.operation in
                      ("wallet", "keystore", "wif", "brainwallet")}

        def render(value):
            if isinstance(value, bytes):
                return value.hex()
            raise TypeError

        print(json.dumps(output, sort_keys=True, default=render))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (KeyError, OSError, TypeError, ValueError, OverflowError, UnicodeError,
            RecursionError, MemoryError, json.JSONDecodeError) as exc:
        print(f"blockchain: {exc}", file=sys.stderr)
        return 2


def main(argv) -> int:
    if not isinstance(argv, (list, tuple)) or any(not isinstance(a, str) for a in argv):
        return 2
    if argv and argv[0] in ("wallet", "keystore", "slot", "wif", "brainwallet"):
        return _wallet_cli(argv)
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: blockchain.py <file>...   (offline, read-only; a private key, seed or flag is never printed)",
              file=sys.stderr)
        return 2
    if keccak(b"") is None:
        print("NOTE no keccak library (pycryptodome): keccak-dependent features decline", file=sys.stderr)
    for p in paths:
        try:
            with Path(p).open("rb") as handle:
                data = handle.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise ValueError(f"input exceeds the {MAX_FILE}-byte artifact cap")
        except (OSError, ValueError) as e:
            print(f"blockchain.py: {p}: {e}", file=sys.stderr)
            continue
        arts = read_artifacts({p: data})
        if not arts:
            print(f"- {p}: no EVM or Bitcoin artifact recognised ({len(data)} bytes)")
        for a in arts:
            print(f"# {p}  [{a['kind']}]  {_summary(a)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
