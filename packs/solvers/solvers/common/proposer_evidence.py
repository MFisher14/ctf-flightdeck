"""Evidence packs and local candidates for a candidate PROPOSER (tests/adapt_bench, contender A).

Generic only: nothing here knows a day, a lane solver's reader or a judged answer. It reads the delivery the
way a first look by hand would (sizes and hashes, magic, headers through pefile / pyelftools / a few struct
reads, printable strings, string literals, and a bounded search over common text and byte codecs), and turns
what it finds into:

  member_evidence(name, data, deadline)  -> {"facts": {...}, "text": str, "decoded": [...], "records": {...}}
  local_candidates(q, evs, ...)          -> [(hypothesis_name, value), ...]  ranked, for one question

Everything it returns is a CANDIDATE: the proposer hands it on only as labels.candidates (unsure), never plain.
Artifacts are untrusted data: parsed, never run.
"""
import base64
import binascii
import bz2
import codecs
import hashlib
import io
import json
import lzma
import re
import string
import struct
import time
import zipfile
import zlib

PRINTABLE = set(bytes(string.printable, "ascii"))
WORDISH = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ")

# ---------------------------------------------------------------------------------------------- scoring


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for c in b if c in PRINTABLE) / len(b)


_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{8,}")


def trim_junk(b: bytes) -> bytes:
    """The span from the first to the last run of 8+ printable bytes (a header or padding around a decoded
    payload is cut off), or the input when there is no such run."""
    runs = list(_RUN.finditer(b[:65536]))
    if not runs:
        return b
    return b[runs[0].start():runs[-1].end()]


def text_score(b: bytes) -> float:
    """0..1: how much a byte string looks like readable text (printable, letters and spaces, few symbols);
    scored on the span trim_junk keeps when that span is most of it."""
    if len(b) < 4:
        return 0.0
    t = trim_junk(b)
    if len(t) >= max(8, 0.6 * len(b)):
        b = t
    p = printable_ratio(b)
    if p < 0.95:
        return p * 0.75
    w = sum(1 for c in b if c in WORDISH) / len(b)
    return 0.8 + 0.2 * w * p


def is_text(b: bytes) -> bool:
    if not b:
        return False
    try:
        s = b[:65536].decode("utf-8")
    except UnicodeDecodeError:
        return False
    bad = sum(1 for ch in s if ord(ch) < 32 and ch not in "\r\n\t")
    return bad <= max(2, len(s) // 200)


# ---------------------------------------------------------------------------------------------- codecs
B64 = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
B64U = re.compile(rb"^[A-Za-z0-9_\-=\s]+$")
HEXC = re.compile(rb"^[0-9a-fA-F]+$")
B32 = re.compile(rb"^[A-Z2-7=\s]+$")


def _b64(b):
    s = re.sub(rb"\s+", b"", b)
    if len(s) < 8 or not B64.match(s):
        return None
    s = s.rstrip(b"=")
    s += b"=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return None


def _b64u(b):
    s = re.sub(rb"\s+", b"", b)
    if len(s) < 8 or not B64U.match(s) or not (b"-" in s or b"_" in s):
        return None
    s = s.rstrip(b"=")
    s += b"=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except (binascii.Error, ValueError):
        return None


def _hex(b):
    best = None
    for src in (b, re.sub(rb"^[A-Za-z]{1,12}[-:_]", b"", b.strip())):
        s = re.sub(rb"(0x|\\x|[^0-9a-fA-F])", b"", src)
        if len(s) < 8 or not HEXC.match(s):
            continue
        # only when the hex digits are most of the input (separators allowed)
        if len(s) < 0.6 * len(re.sub(rb"\s+", b"", src)):
            continue
        if len(s) % 2:
            s = s[:-1]
        r = bytes.fromhex(s.decode())
        if best is None or text_score(r) > text_score(best):
            best = r
    return best


def _b32(b):
    s = re.sub(rb"\s+", b"", b).upper()
    if len(s) < 8 or not B32.match(s):
        return None
    s = s.rstrip(b"=")
    s += b"=" * (-len(s) % 8)
    try:
        return base64.b32decode(s)
    except (binascii.Error, ValueError):
        return None


def _b85(b):
    s = re.sub(rb"\s+", b"", b)
    if len(s) < 10 or re.fullmatch(rb"[A-Za-z0-9+/=_\-]+", s):
        return None   # nothing outside the base64 alphabet: base85 would read noise
    for f in (base64.b85decode, base64.a85decode):
        try:
            return f(s)
        except (ValueError, binascii.Error):
            continue
    return None


def _rot13(b):
    try:
        return codecs.encode(b.decode("latin-1"), "rot13").encode("latin-1")
    except Exception:
        return None


def _reverse(b):
    return b[::-1]


def _atbash(b):
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = 90 - (c - 65)
        elif 97 <= c <= 122:
            out[i] = 122 - (c - 97)
    return bytes(out)


def _decomp(b):
    for f in (lambda x: zlib.decompress(x), lambda x: zlib.decompress(x, -15), lambda x: zlib.decompress(x, 31),
              bz2.decompress, lzma.decompress):
        try:
            r = f(b)
            if r:
                return r
        except Exception:
            continue
    return None


def _url(b):
    if b"%" not in b:
        return None
    try:
        from urllib.parse import unquote_to_bytes
        r = unquote_to_bytes(b)
        return r if r != b else None
    except Exception:
        return None


def _decimal(b):
    nums = re.findall(rb"\d+", b)
    if len(nums) < 4 or len(b"".join(nums)) < 0.5 * len(re.sub(rb"\s+", b"", b)):
        return None
    vals = [int(n) for n in nums]
    if all(v < 256 for v in vals):
        return bytes(vals)
    return None


def _octal(b):
    nums = re.findall(rb"\\?([0-7]{3})", b)
    if len(nums) < 4:
        return None
    vals = [int(n, 8) for n in nums]
    return bytes(v for v in vals if v < 256) if all(v < 256 for v in vals) else None


def _alpha16(b):
    """A text of 16 letters standing for nibbles (a..p = 0..f), in either case."""
    s = re.sub(rb"\s+", b"", b).lower()
    if len(s) < 8 or len(s) % 2 or not re.fullmatch(rb"[a-p]+", s):
        return None
    return bytes(((s[i] - 97) << 4) | (s[i + 1] - 97) for i in range(0, len(s), 2))


def _two_symbol(b):
    """A text made of two symbols (01, ab, .-, AB...) in groups: map to bits, drop a column that never varies
    across groups, and pack to bytes. Tries both symbol orders."""
    s = re.sub(rb"\s+", b" ", b.strip())
    syms = sorted(set(s) - {32})
    if len(syms) != 2 or len(s) < 16:
        return None
    groups = s.split(b" ") if b" " in s else [s]
    outs = []
    for zero, one in ((syms[0], syms[1]), (syms[1], syms[0])):
        bits = [[1 if c == one else 0 for c in g] for g in groups if g]
        widths = {len(g) for g in bits}
        if len(widths) == 1 and len(bits) > 1:
            w = widths.pop()
            keep = [i for i in range(w) if len({g[i] for g in bits}) > 1]
            flat = [g[i] for g in bits for i in keep]
            # 5-bit groups as letters (Bacon, 26-letter) as well
            if w == 5:
                outs.append(bytes(65 + min(25, int("".join(map(str, g)), 2)) for g in bits))
        else:
            flat = [x for g in bits for x in g]
        if len(flat) >= 8:
            n = len(flat) // 8 * 8
            outs.append(bytes(int("".join(map(str, flat[i:i + 8])), 2) for i in range(0, n, 8)))
            if len(flat) % 7 == 0:
                outs.append(bytes(int("".join(map(str, flat[i:i + 7])), 2) for i in range(0, len(flat), 7)))
    best = max(outs, key=text_score, default=None)
    return best


_ALPHABET = re.compile(rb"[A-Za-z0-9+/=_\-.,:%\s]+")


def _readable(b: bytes) -> bool:
    """No key search is needed: already plain text (words of a message, a URL, a config), or text in an
    encoding alphabet (base64, hex, digits) that a parse codec reads instead."""
    return _wordy(b[:4000]) or bool(_ALPHABET.fullmatch(b[:4000]))


def _better(r: bytes, b: bytes) -> bool:
    """A key search's result is kept when it reads as text and reads better than its input."""
    if text_score(r) < 0.8:
        return False
    return text_score(b) < 0.8 or _wordy_score(r) > _wordy_score(b) + 0.1


def _rotbits(b):
    """Every byte rotated by the same number of bits (1..7), the rotation that reads best."""
    if len(b) < 8 or _readable(b):
        return None
    a = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
    best, bs = None, float("-inf")
    for r in range(1, 8):
        x = ((a << r) | (a >> (8 - r))) & 0xFF
        sc = float(_W[x[:512]].sum())
        if sc > bs:
            best, bs = x, sc
    out = bytes(best.astype(np.uint8))
    return out if _better(out, b) else None


def _delta(b):
    """Delta coding: each byte is the difference from the one before (decoded by a running sum), or the
    running sum of the plain bytes (decoded by differences)."""
    if len(b) < 8 or _readable(b):
        return None
    a = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
    outs = [bytes((np.cumsum(a) & 0xFF).astype(np.uint8)),
            bytes((np.diff(a, prepend=0) & 0xFF).astype(np.uint8))]
    out = max(outs, key=text_score)
    return out if _better(out, b) else None


def _xor_chain(b):
    """Each byte XORed with the byte before it (CBC-like, an IV for the first): plain[i] = c[i] ^ c[i-1], or
    the forward form plain[i] = c[i] ^ plain[i-1]; the IV is the one that reads best."""
    if len(b) < 8 or _readable(b):
        return None
    a = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
    back = a ^ np.concatenate(([0], a[:-1]))
    fwd = np.bitwise_xor.accumulate(a)
    outs = []
    for x in (back, fwd):
        x = x.copy()
        first = int(np.argmax(_W[(int(a[0]) ^ np.arange(256))]))   # the IV that makes byte 0 most likely
        x0 = int(a[0]) ^ first
        if x is fwd:
            x = fwd ^ first   # a forward chain with an IV shifts every byte by the IV
        x[0] = x0
        outs.append(bytes((x & 0xFF).astype(np.uint8)))
    out = max(outs, key=text_score)
    return out if _better(out, b) else None


def _gray(b):
    """Each byte Gray-coded (decoded by prefix XOR of its bits)."""
    if len(b) < 8 or _readable(b):
        return None
    out = bytearray()
    for g in b:
        x = g
        s = g >> 1
        while s:
            x ^= s
            s >>= 1
        out.append(x)
    out = bytes(out)
    return out if _better(out, b) else None


def _unicode_hidden(b):
    """Text hidden in invisible code points: Unicode tag characters (U+E0020..E007E stand for ASCII), or a
    two-symbol run of zero-width / format characters read as bits."""
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    tags = [ord(c) - 0xE0000 for c in s if 0xE0000 <= ord(c) <= 0xE007F]
    if len(tags) >= 4:
        return bytes(t for t in tags if 0 < t < 128)
    import unicodedata
    hid = [c for c in s if unicodedata.category(c) == "Cf" or c in "​‌‍⁠﻿᠎"]
    syms = sorted(set(hid))
    if len(hid) < 16 or len(syms) != 2:
        return None
    outs = []
    for one in syms:
        bits = "".join("1" if c == one else "0" for c in hid)
        n = len(bits) // 8 * 8
        outs.append(bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8)))
    return max(outs, key=text_score)


def _caesar_best(b):
    if not re.fullmatch(rb"[A-Za-z0-9 \-_.,:;!?'\"\n\r]+", b[:2000]) or len(b) < 8:
        return None
    from collections import Counter
    letters = [c | 32 for c in b if 65 <= (c & ~32) <= 90]
    if len(letters) < 8:
        return None
    # shift that maps the commonest letter to 'e'
    common = Counter(letters).most_common(1)[0][0]
    k = (common - ord("e")) % 26
    if k == 0:
        return None
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = 65 + (c - 65 - k) % 26
        elif 97 <= c <= 122:
            out[i] = 97 + (c - 97 - k) % 26
    return bytes(out)


import numpy as np  # noqa: E402

def _unigram() -> "np.ndarray":
    """Log-probabilities of a byte in text, code or JSON: English letter frequencies, spaces, digits and the
    punctuation of code; anything unprintable is very unlikely. Picks the key that makes a blob readable."""
    p = np.full(256, 1e-7)
    for c in range(32, 127):
        p[c] = 0.0015
    eng = "etaoinshrdlcumwfgypbvkjxqz"
    freqs = [12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8, 2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.5,
             1.0, 0.8, 0.15, 0.15, 0.1, 0.07]
    for ch, f in zip(eng, freqs):
        p[ord(ch)] = f / 100 * 0.55
        p[ord(ch.upper())] = f / 100 * 0.06
    p[ord(" ")] = 0.12
    for ch in "0123456789":
        p[ord(ch)] = 0.008
    for ch in "\"{}:,./-_=\\'()[];":
        p[ord(ch)] = 0.006
    p[ord("\n")] = 0.01
    p[ord("\r")] = 0.002
    p[ord("\t")] = 0.002
    return np.log(p / p.sum()).astype(np.float32)


_W = _unigram()
_K = np.arange(256, dtype=np.int64)[:, None]


def _brute(kind):
    """Best single key k for out[i] = f(in[i], i, k): xor, add, rolling xor up/down; numpy over all 256 k."""
    def f(b):
        if len(b) < 8 or _readable(b):
            return None
        a = np.frombuffer(b[:384], dtype=np.uint8).astype(np.int64)[None, :]
        i = np.arange(a.shape[1], dtype=np.int64)[None, :]
        if kind == "xor1":
            m = a ^ _K
        elif kind == "add":
            m = (a + _K) & 0xFF
        elif kind == "xor_rolling":
            m = a ^ ((_K + i) & 0xFF)
        else:
            m = a ^ ((_K - i) & 0xFF)
        sc = _W[m & 0xFF].sum(axis=1)
        k = int(sc.argmax())
        full = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
        ii = np.arange(len(full), dtype=np.int64)
        if kind == "xor1":
            r = full ^ k
        elif kind == "add":
            r = (full + k) & 0xFF
        elif kind == "xor_rolling":
            r = full ^ ((k + ii) & 0xFF)
        else:
            r = full ^ ((k - ii) & 0xFF)
        r = bytes((r & 0xFF).astype(np.uint8))
        return r if _better(r, b) else None
    return f


def _affine(kind):
    """out[i] = in[i] ^ ((k + s*i) mod 256) (or minus): a rolling key with any step s, k and s searched."""
    def f(b):
        if len(b) < 16 or _readable(b):
            return None
        a = np.frombuffer(b[:128], dtype=np.uint8).astype(np.int64)[None, :]
        i = np.arange(a.shape[1], dtype=np.int64)[None, :]
        a = a[:, :64]
        i = i[:, :64]
        S = np.arange(2, 256, dtype=np.int64)[:, None, None]
        if kind == "xor":
            m = a[None] ^ ((_K[None] + S * i[None]) & 0xFF)
        else:
            m = (a[None] - _K[None] - S * i[None]) & 0xFF
        sc = _W[m].sum(axis=2)                       # (s, k)
        si, k = np.unravel_index(int(sc.argmax()), sc.shape)
        s, k = int(si) + 2, int(k)
        full = np.frombuffer(b, dtype=np.uint8).astype(np.int64)
        ii = np.arange(len(full), dtype=np.int64)
        r = full ^ ((k + s * ii) & 0xFF) if kind == "xor" else (full - k - s * ii) & 0xFF
        r = bytes((r & 0xFF).astype(np.uint8))
        return r if _better(r, b) else None
    return f


def _xor_rep(b):
    """Repeating-key XOR with an unknown key of 2..16 bytes, each column's byte chosen for readable text."""
    if len(b) < 24 or _readable(b):
        return None
    full = np.frombuffer(b[:4096], dtype=np.uint8).astype(np.int64)
    best, bs = None, 0.0
    for kl in range(2, 17):
        if len(full) < kl * 4:
            break
        key = []
        for j in range(kl):
            col = full[j::kl][None, :200]
            key.append(int(_W[col ^ _K].sum(axis=1).argmax()))
        kk = np.array(key, dtype=np.int64)
        r = bytes((full ^ kk[np.arange(len(full)) % kl]).astype(np.uint8))
        sc = text_score(r)
        if sc > bs + 0.02:
            best, bs = r, sc
    if best is None or not _better(best, b):
        return None
    if len(b) > 4096:
        return None
    return best


def _nibswap(b):
    return bytes(((c << 4) | (c >> 4)) & 0xFF for c in b)


def _rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _keyed(keys):
    """XOR and RC4 with keys the evidence itself offers (short literals and strings near the data)."""
    def f(b):
        if len(b) < 8 or _readable(b):
            return None
        best, bs = None, 0.0
        for k in keys:
            for r in (bytes(c ^ k[i % len(k)] for i, c in enumerate(b)), _rc4(k, b[:4096])):
                sc = text_score(r)
                if sc > bs:
                    best, bs = r, sc
        return best if best is not None and _better(best, b) else None
    return f


# parse codecs: succeed only on input of their alphabet; every result is followed further
FORMAT = [("base64", _b64), ("base64url", _b64u), ("hex", _hex), ("base32", _b32), ("base85", _b85),
          ("decompress", _decomp), ("url", _url), ("decimal", _decimal), ("octal", _octal), ("bits", _two_symbol),
          ("alpha16", _alpha16), ("unicode_hidden", _unicode_hidden)]
# brute codecs: pick the key that reads best; kept only when the result reads as text
BRUTE = [("xor1", _brute("xor1")), ("add", _brute("add")), ("xor_rolling", _brute("xor_rolling")),
         ("xor_rolling_down", _brute("xor_rolling_down")), ("xor_rep", _xor_rep), ("xor_affine", _affine("xor")),
         ("sub_affine", _affine("sub")), ("rotbits", _rotbits), ("delta", _delta), ("gray", _gray), ("xor_chain", _xor_chain)]
# weak codecs: turn any input into other input; followed as an intermediate step, kept only when better text
WEAK = [("rot13", _rot13), ("reverse", _reverse), ("atbash", _atbash), ("caesar", _caesar_best), ("nibswap", _nibswap)]
CODECS = FORMAT + BRUTE + WEAK
WEAK_NAMES = {n for n, _ in WEAK}
BRUTE_NAMES = {n for n, _ in BRUTE} | {"keyed"}


def decode_search(data: bytes, deadline: float, depth: int = 4, beam: int = 8, limit: int = 40, keys=()) -> list:
    """Bounded best-first search over the codecs. Returns [(chain, bytes, score)] of readable results, best first."""
    seen = {hashlib.sha256(data).digest()}
    frontier = [((), data, text_score(data))]
    found = []
    codecs_ = list(CODECS) + ([("keyed", _keyed([bytes(k) for k in keys[:14] if k]))] if keys else [])
    for _ in range(depth):
        strong, weak = [], []
        for chain, b, sc in frontier:
            if time.time() > deadline:
                break
            for name, f in codecs_:
                if chain and chain[-1] == name and name in WEAK_NAMES:
                    continue
                if name in WEAK_NAMES and chain and chain[-1] in WEAK_NAMES:
                    continue   # two weak steps in a row lead nowhere new
                if name in ("xor_affine", "sub_affine") and chain:
                    continue   # the costly key searches run on the raw blobs only
                if name in BRUTE_NAMES and (len(chain) >= 2 or (chain and chain[-1] in BRUTE_NAMES)):
                    continue
                if name == "xor_rep" and (len(chain) >= 1 and chain[-1] not in ("base64", "hex", "base64url")):
                    continue   # the costliest search: on raw blobs and right after a base64/hex parse only
                try:
                    r = f(b)
                except Exception:
                    r = None
                if not r or len(r) < 4:
                    continue
                h = hashlib.sha256(r).digest()
                if h in seen:
                    continue
                seen.add(h)
                rs = text_score(r)
                item = (chain + (name,), r, rs)
                if name in WEAK_NAMES:
                    weak.append(item)
                    if rs >= 0.8 and _wordy_score(r) > _wordy_score(b) + 0.05:
                        found.append(item)
                    continue
                strong.append(item)
                if rs >= 0.8:
                    found.append(item)
        strong.sort(key=lambda x: -x[2])
        weak.sort(key=lambda x: -x[2])
        frontier = strong[:beam] + weak[:8]
        if not frontier:
            break
    found.sort(key=lambda x: (-_wordy_score(x[1]), -x[2], len(x[0])))
    return found[:limit]


COMMON = re.compile(rb"\b(the|and|submit|answer|slug|flag|key|is|to|of|http|https|url|campaign|config|"
                    rb"value|final|line|decode|message|id)\b", re.I)


def _wordy(b: bytes) -> bool:
    return len(COMMON.findall(b[:4000])) >= 2


def _wordy_score(b: bytes) -> float:
    return min(1.0, len(COMMON.findall(b[:4000])) / 6.0) + text_score(b)


# ---------------------------------------------------------------------------------------------- strings
STR_LIT = re.compile(r"\"((?:[^\"\\\n]|\\.){4,})\"|'((?:[^'\\\n]|\\.){4,})'")


def string_literals(text: str) -> list:
    return [a or b for a, b in STR_LIT.findall(text)]


def ascii_strings(data: bytes, n: int = 5, cap: int = 4000) -> list:
    out = [m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % n, data[:8_000_000])]
    out += [m.group().decode("utf-16le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % n, data[:8_000_000])]
    return out[:cap]


_LIT = r"(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")"
_PS_F = re.compile(r"(" + _LIT + r")\s*-f\s*(" + _LIT + r"(?:\s*,\s*" + _LIT + r")*)", re.I)
_DOT_FORMAT = re.compile(r"(" + _LIT + r")\s*\.\s*format\s*\(\s*(" + _LIT + r"(?:\s*,\s*" + _LIT + r")*)\s*\)")
_STR_FORMAT = re.compile(r"(?:String|string)\s*\.\s*Format\s*\(\s*(" + _LIT + r")\s*,\s*(" + _LIT + r"(?:\s*,\s*" + _LIT + r")*)\s*\)")


def format_expansions(text: str) -> list:
    """Format strings filled from literal arguments: PowerShell `'{1}{0}' -f 'a','b'`, Python
    `'{}{}'.format('a','b')`, .NET `String.Format("{0}", "a")`."""
    out = []
    for rx in (_PS_F, _DOT_FORMAT, _STR_FORMAT):
        for m in rx.finditer(text[:200_000]):
            fmt = m.group(1)[1:-1]
            args = [a[1:-1] for a in re.findall(_LIT, m.group(2))]
            auto = iter(range(len(args)))

            def sub(mm):
                k = mm.group(1)
                i = int(k) if k else next(auto, 0)
                return args[i] if i < len(args) else mm.group(0)
            try:
                out.append(re.sub(r"\{(\d*)\}", sub, fmt))
            except Exception:
                continue
    return [o for o in out if len(o) >= 8]


def literal_blobs(text: str) -> list:
    """Encoded-looking material in source text: long literals, runs of consecutive literals joined, and long
    unquoted runs of base64/hex alphabet."""
    lits = string_literals(text)
    blobs = [x for x in lits if len(x) >= 12]
    # consecutive literals of one array or concatenation: join in file order (fragments). Two literals belong
    # together when only separators (, + & . .. _ line continuations, whitespace) stand between them.
    joined, run, prev_end = [], [], None
    for m in STR_LIT.finditer(text):
        if run and not (prev_end is not None and re.fullmatch(r"[\s,+&._\\]{0,40}", text[prev_end:m.start()])):
            if len(run) > 1:
                joined.append("".join(run))
            run = []
        run.append(m.group(1) or m.group(2))
        prev_end = m.end()
    if len(run) > 1:
        joined.append("".join(run))
    blobs += [j for j in joined if len(j) >= 16]
    blobs += format_expansions(text)
    blobs += re.findall(r"[A-Za-z0-9+/=._\-]{40,}", text)
    seen, out = set(), []
    for b in sorted(blobs, key=len, reverse=True):
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out[:30]


# ---------------------------------------------------------------------------------------------- records
KV = re.compile(r"(?<![\w.])([A-Za-z_][\w.\-]{0,40})\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^|;&\n\r,\"'{}]+(?:,[^|;&\n\r=\"'{}]+(?=[|;&\n\r]|$))*)")


def records_of(text: str) -> dict:
    """key -> [values] from key=value / key: value pairs and JSON objects in a decoded text."""
    rec = {}
    t = text.strip()
    if t[:1] in "{[":
        try:
            _flatten(json.loads(t), "", rec)
        except ValueError:
            pass
    for k, v in KV.findall(text):
        v = v.strip().strip("\"'").strip()
        if v and len(v) <= 300:
            rec.setdefault(k.lower(), [])
            if v not in rec[k.lower()]:
                rec[k.lower()].append(v)
    return rec


def _flatten(o, prefix, rec):
    if isinstance(o, dict):
        for k, v in o.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), rec)
        if prefix:
            rec.setdefault(prefix.lower(), []).append(json.dumps(o, separators=(",", ":")))
    elif isinstance(o, list):
        rec.setdefault(prefix.lower(), []).append(json.dumps(o, separators=(",", ":")))
        if all(isinstance(x, str) for x in o):
            rec.setdefault(prefix.lower(), []).append(",".join(o))
    else:
        rec.setdefault(prefix.lower(), []).append(o if isinstance(o, str) else json.dumps(o))


# ---------------------------------------------------------------------------------------------- formats


def _hexw(v, w):
    return f"0x{v:0{w}x}"


def pe_facts(data: bytes) -> dict:
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=False)
    except Exception:
        return {}
    f = {}
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    f["pe.machine"] = _hexw(fh.Machine, 4)
    f["pe.number_of_sections"] = fh.NumberOfSections
    f["pe.timedatestamp"] = fh.TimeDateStamp
    f["pe.characteristics"] = _hexw(fh.Characteristics, 4)
    f["pe.optional_magic"] = _hexw(oh.Magic, 4)
    for k in ("AddressOfEntryPoint", "ImageBase", "SectionAlignment", "FileAlignment", "SizeOfImage",
              "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "MajorLinkerVersion",
              "MinorLinkerVersion", "MajorOperatingSystemVersion", "MajorSubsystemVersion", "SizeOfCode"):
        v = getattr(oh, k, None)
        if v is not None:
            f[f"pe.{k}"] = v
            f[f"pe.{k}.hex"] = _hexw(v, 8)
    f["pe.sections"] = [s.Name.rstrip(b"\0").decode("latin-1") for s in pe.sections]
    for s in pe.sections[:12]:
        n = s.Name.rstrip(b"\0").decode("latin-1")
        f[f"pe.section[{n}]"] = {"va": _hexw(s.VirtualAddress, 8), "vsize": s.Misc_VirtualSize,
                                  "raw_ptr": s.PointerToRawData, "raw_size": s.SizeOfRawData,
                                  "entropy": round(s.get_entropy(), 3), "flags": _hexw(s.Characteristics, 8)}
    try:
        f["pe.imports"] = {e.dll.decode("latin-1"): [i.name.decode("latin-1") for i in e.imports if i.name][:20]
                           for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:12]}
    except Exception:
        pass
    try:
        f["pe.exports"] = [e.name.decode("latin-1") for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name][:30]
    except Exception:
        pass
    try:
        end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
        if end < len(data):
            f["pe.overlay_offset"] = end
            f["pe.overlay_size"] = len(data) - end
            f["pe.overlay_head_hex"] = data[end:end + 32].hex()
    except ValueError:
        pass
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for e in fi:
                for st in getattr(e, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        f[f"pe.version.{k.decode('latin-1')}"] = v.decode("latin-1", "replace")
    except Exception:
        pass
    try:
        for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            e = getattr(d, "entry", None)
            if e is not None and hasattr(e, "PdbFileName"):
                f["pe.pdb"] = e.PdbFileName.rstrip(b"\0").decode("latin-1")
    except Exception:
        pass
    try:
        res = []
        for t in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None).entries:
            tn = str(t.name) if t.name else pefile.RESOURCE_TYPE.get(t.struct.Id, t.struct.Id)
            for n in getattr(t, "directory", None).entries if hasattr(t, "directory") else []:
                nn = str(n.name) if n.name else n.struct.Id
                for l in n.directory.entries if hasattr(n, "directory") else []:
                    ds = l.data.struct
                    res.append({"type": tn, "name": nn, "lang": l.struct.Id, "rva": ds.OffsetToData, "size": ds.Size})
        if res:
            f["pe.resources"] = res[:20]
    except Exception:
        pass
    try:
        clr = oh.DATA_DIRECTORY[14]
        if clr.VirtualAddress:
            f["pe.clr_header_rva"] = _hexw(clr.VirtualAddress, 8)
    except Exception:
        pass
    return f


def elf_facts(data: bytes) -> dict:
    try:
        from elftools.elf.elffile import ELFFile
        e = ELFFile(io.BytesIO(data))
    except Exception:
        return {}
    f = {}
    h = e.header
    f["elf.class"] = h["e_ident"]["EI_CLASS"]
    f["elf.data"] = h["e_ident"]["EI_DATA"]
    f["elf.osabi"] = h["e_ident"]["EI_OSABI"]
    f["elf.type"] = h["e_type"]
    f["elf.machine"] = h["e_machine"]
    try:
        f["elf.machine_num"] = struct.unpack_from("<H" if e.little_endian else ">H", data, 18)[0]
    except struct.error:
        pass
    f["elf.entry"] = _hexw(h["e_entry"], 8)
    f["elf.arch"] = e.get_machine_arch()
    secs = []
    try:
        for s in e.iter_sections():
            secs.append(s.name)
        f["elf.sections"] = secs[:60]
    except Exception:
        pass
    try:
        syms = []
        for name in (".symtab", ".dynsym"):
            s = e.get_section_by_name(name)
            if s is not None:
                syms += [x.name for x in s.iter_symbols() if x.name][:400]
        f["elf.has_symtab"] = e.get_section_by_name(".symtab") is not None
        f["elf.symbols_sample"] = [x for x in syms if not x.startswith("_GLOBAL")][:120]
    except Exception:
        pass
    try:
        segs = [s["p_type"] for s in e.iter_segments()]
        f["elf.segments"] = segs[:20]
        for s in e.iter_segments():
            if s["p_type"] == "PT_INTERP":
                f["elf.interp"] = s.get_interp_name()
    except Exception:
        pass
    try:
        d = e.get_section_by_name(".comment")
        if d is not None:
            f["elf.comment"] = d.data().replace(b"\0", b" ").decode("latin-1").strip()
    except Exception:
        pass
    try:
        end = max(h["e_shoff"] + h["e_shnum"] * h["e_shentsize"],
                  max((s["sh_offset"] + s["sh_size"] for s in e.iter_sections() if s["sh_type"] != "SHT_NOBITS"),
                      default=0))
        if end < len(data):
            f["elf.overlay_offset"] = end
            f["elf.overlay_size"] = len(data) - end
            f["elf.overlay_head_hex"] = data[end:end + 32].hex()
    except Exception:
        pass
    return f


def macho_facts(data: bytes) -> dict:
    if len(data) < 28:
        return {}
    m = data[:4]
    f = {}
    if m in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        en = "<"
    elif m in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        en = ">"
    elif m in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        en = ">" if m == b"\xca\xfe\xba\xbe" else "<"
        n = struct.unpack_from(en + "I", data, 4)[0]
        if n > 30:
            return {}
        arches = []
        for i in range(n):
            if 8 + 20 * (i + 1) > len(data):
                break
            ct, cs, off, size, align = struct.unpack_from(en + "5I", data, 8 + 20 * i)
            arches.append({"cputype": _hexw(ct, 8), "cpusubtype": _hexw(cs, 8), "offset": off, "size": size,
                           "align": align})
        f["macho.fat_magic"] = m.hex()
        f["macho.fat_arches"] = arches
        f["macho.cpu_types"] = [a["cputype"] for a in arches]
        return f
    else:
        return {}
    magic, ct, cs, ft, ncmds, sizeofcmds, flags = struct.unpack_from(en + "7I", data, 0)
    f.update({"macho.magic": _hexw(magic, 8), "macho.cputype": _hexw(ct, 8), "macho.cputype_dec": ct,
              "macho.cpusubtype": _hexw(cs, 8), "macho.filetype": ft, "macho.ncmds": ncmds,
              "macho.sizeofcmds": sizeofcmds, "macho.flags": _hexw(flags, 8)})
    off = 32 if m in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 28
    cmds = []
    for _ in range(min(ncmds, 64)):
        if off + 8 > len(data):
            break
        c, sz = struct.unpack_from(en + "2I", data, off)
        cmds.append({"cmd": _hexw(c, 8), "size": sz, "at": off})
        if sz < 8:
            break
        off += sz
    f["macho.load_commands"] = cmds
    return f


def zip_facts(data: bytes) -> dict:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return {}
    f = {"zip.members": [], "zip.comment": z.comment.decode("latin-1")}
    for i in z.infolist()[:60]:
        f["zip.members"].append({"name": i.filename, "method": i.compress_type, "size": i.file_size,
                                 "csize": i.compress_size, "crc": _hexw(i.CRC, 8), "date": list(i.date_time),
                                 "flags": i.flag_bits, "extra_len": len(i.extra), "comment": i.comment.decode("latin-1")})
    for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml", "word/_rels/document.xml.rels",
                 "xl/_rels/workbook.xml.rels", "ppt/_rels/presentation.xml.rels", "[Content_Types].xml",
                 "AndroidManifest.xml", "META-INF/MANIFEST.MF"):
        try:
            raw = z.read(name)
        except Exception:
            continue
        if name.endswith(".xml") or name.endswith(".rels") or name.endswith(".MF"):
            f[f"zip.{name}"] = raw[:1500].decode("utf-8", "replace")
    return f


def riff_facts(data: bytes) -> dict:
    if data[:4] not in (b"RIFF", b"RIFX") or len(data) < 12:
        return {}
    f = {"riff.form": data[8:12].decode("latin-1"), "riff.size": struct.unpack_from("<I", data, 4)[0]}
    off, chunks = 12, []
    while off + 8 <= len(data) and len(chunks) < 40:
        cid, sz = data[off:off + 4], struct.unpack_from("<I", data, off + 4)[0]
        chunks.append({"id": cid.decode("latin-1"), "size": sz, "at": off})
        if cid == b"fmt " and sz >= 16:
            fmt = struct.unpack_from("<HHIIHH", data, off + 8)
            f["riff.fmt"] = dict(zip(("format_tag", "channels", "sample_rate", "byte_rate", "block_align",
                                      "bits_per_sample"), fmt))
        if cid == b"LIST":
            f.setdefault("riff.list", []).append(data[off + 8:off + 8 + min(sz, 400)].decode("latin-1", "replace"))
        off += 8 + sz + (sz & 1)
    f["riff.chunks"] = chunks
    return f


def jpeg_facts(data: bytes) -> dict:
    if data[:2] != b"\xff\xd8":
        return {}
    off, marks = 2, []
    while off + 4 <= len(data) and len(marks) < 40:
        if data[off] != 0xFF:
            break
        mk = data[off + 1]
        if mk == 0xD9 or mk == 0xDA:
            marks.append({"marker": f"0xff{mk:02x}", "at": off})
            break
        sz = struct.unpack_from(">H", data, off + 2)[0]
        marks.append({"marker": f"0xff{mk:02x}", "size": sz, "at": off,
                      "head": data[off + 4:off + 4 + 24].decode("latin-1", "replace")})
        if mk in (0xC0, 0xC1, 0xC2) and sz >= 8:
            p, h, w = struct.unpack_from(">BHH", data, off + 4)
            marks[-1].update({"precision": p, "height": h, "width": w})
        off += 2 + sz
    return {"jpeg.markers": marks}


def png_facts(data: bytes) -> dict:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return {}
    off, chunks, f = 8, [], {}
    while off + 8 <= len(data) and len(chunks) < 40:
        sz = struct.unpack_from(">I", data, off)[0]
        cid = data[off + 4:off + 8].decode("latin-1")
        chunks.append({"id": cid, "size": sz, "at": off})
        body = data[off + 8:off + 8 + sz]
        if cid == "IHDR" and sz >= 13:
            w, h, bd, ct, cm, fm, im = struct.unpack_from(">IIBBBBB", body)
            f["png.ihdr"] = {"width": w, "height": h, "bit_depth": bd, "color_type": ct, "interlace": im}
        if cid in ("tEXt", "iTXt", "zTXt"):
            f.setdefault("png.text", []).append(body[:300].decode("latin-1", "replace"))
        off += 12 + sz
    f["png.chunks"] = chunks
    return f


def pdf_facts(data: bytes) -> dict:
    if not data.startswith(b"%PDF"):
        return {}
    f = {"pdf.version": data[5:8].decode("latin-1")}
    info = re.findall(rb"/(Title|Author|Creator|Producer|Subject|Keywords|CreationDate|ModDate)\s*\(([^)]{0,200})\)", data)
    for k, v in info[:20]:
        f[f"pdf.{k.decode()}"] = v.decode("latin-1")
    f["pdf.objects"] = len(re.findall(rb"\d+ \d+ obj", data))
    return f


def lnk_facts(data: bytes) -> dict:
    if data[:4] != b"\x4c\x00\x00\x00" or len(data) < 76:
        return {}
    flags, attrs = struct.unpack_from("<II", data, 20)
    return {"lnk.flags": _hexw(flags, 8), "lnk.file_attributes": _hexw(attrs, 8),
            "lnk.file_size": struct.unpack_from("<I", data, 52)[0],
            "lnk.show_command": struct.unpack_from("<I", data, 60)[0]}


def magic_markers(data: bytes) -> dict:
    """Four-byte uppercase-ASCII tags (overlay/config magics such as ABCD12) with every offset, when rare."""
    out = {}
    for m in re.finditer(rb"(?<![A-Za-z0-9])([A-Z]{2,4}[0-9]{1,4}|[A-Z]{4})(?![a-z])", data[:16_000_000]):
        t = m.group(1)
        if len(t) != 4:
            continue
        out.setdefault(t.decode(), []).append(m.start())
    return {k: v[:8] + ([v[-1]] if len(v) > 8 else []) for k, v in out.items() if len(v) <= 6}


def header_words(data: bytes, n: int = 64) -> dict:
    head = data[:n]
    return {"hex": head.hex(" "),
            "u16le": [struct.unpack_from("<H", head, i)[0] for i in range(0, len(head) - 1, 2)][:16],
            "u32le_hex": [_hexw(struct.unpack_from("<I", head, i)[0], 8) for i in range(0, len(head) - 3, 4)][:16],
            "u32be_hex": [_hexw(struct.unpack_from(">I", head, i)[0], 8) for i in range(0, len(head) - 3, 4)][:8]}


ARCH_SPELLINGS = {
    "x64": ["x86-64", "x86_64", "amd64", "x64"], "x86": ["x86", "i386", "i686", "x86-32"],
    "aarch64": ["aarch64", "arm64", "arm64-v8a"], "arm": ["arm", "arm32", "armv7"], "mips": ["mips"],
    "riscv": ["riscv64", "riscv"], "ppc64": ["ppc64", "powerpc64"],
}
PE_MACHINE = {0x14c: "x86", 0x8664: "x64", 0xaa64: "aarch64", 0x1c0: "arm", 0x1c4: "arm"}
MACHO_CPU = {7: "x86", 0x01000007: "x64", 12: "arm", 0x0100000c: "aarch64"}


def _names(f: dict, data: bytes):
    fmt, arch = None, None
    if data[:4] == b"\x7fELF":
        fmt = ["elf", "ELF"]
        arch = {"x64": "x64", "x86": "x86", "AArch64": "aarch64", "ARM": "arm", "MIPS": "mips",
                "RISC-V": "riscv"}.get(f.get("elf.arch"), None)
        bits = 64 if f.get("elf.class") == "ELFCLASS64" else 32
        fmt += [f"elf{bits}", f"ELF{bits}"]
    elif data[:2] == b"MZ":
        fmt = ["pe", "PE", "pe32+" if f.get("pe.optional_magic") == "0x020b" else "pe32"]
        if f.get("pe.clr_header_rva"):
            fmt = ["pe+cli", "dotnet", ".net", "pe_cli"] + fmt
        try:
            arch = PE_MACHINE.get(int(f.get("pe.machine", "0"), 16))
        except ValueError:
            arch = None
    elif "macho.cputype_dec" in f or "macho.fat_arches" in f:
        fmt = ["macho", "mach-o", "Mach-O"]
        arch = MACHO_CPU.get(f.get("macho.cputype_dec"))
    elif data[:2] == b"PK":
        fmt = ["zip", "jar", "apk"]
    elif data[:4] == b"dex\n":
        fmt = ["dex"]
    elif data[:4] == b"\xca\xfe\xba\xbe":
        fmt = ["class", "java_class"]
    elif data[:4] == b"\x00asm":
        fmt = ["wasm"]
    if fmt:
        f["format_names"] = fmt
    if arch:
        f["arch_names"] = ARCH_SPELLINGS.get(arch, [arch])


def format_facts(data: bytes) -> dict:
    f = {}
    for fn in (pe_facts if data[:2] == b"MZ" else None, elf_facts if data[:4] == b"\x7fELF" else None,
               macho_facts, zip_facts if data[:2] == b"PK" else None, riff_facts, jpeg_facts, png_facts, pdf_facts,
               lnk_facts):
        if fn is None:
            continue
        try:
            f.update(fn(data))
        except Exception:
            continue
    try:
        _names(f, data)
    except Exception:
        pass
    return f


# ---------------------------------------------------------------------------------------------- member


def member_evidence(name: str, data: bytes, deadline: float, text_cap: int = 6000, tags=()) -> dict:
    """`tags`: 4-character magic tags the questions name (searched first among the markers)."""
    ev = {"name": name, "facts": {}, "text": "", "decoded": [], "records": {}, "strings": []}
    f = ev["facts"]
    f["size"] = len(data)
    f["sha256"] = hashlib.sha256(data).hexdigest()
    f["md5"] = hashlib.md5(data).hexdigest()
    f["sha1"] = hashlib.sha1(data).hexdigest()
    f["crc32"] = _hexw(zlib.crc32(data) & 0xFFFFFFFF, 8)
    textual = is_text(data)
    keys, pre = [], []
    if textual:
        text = data.decode("utf-8", "replace")
        ev["text"] = text if len(text) <= text_cap else text[:text_cap * 2 // 3] + "\n...[cut]...\n" + text[-text_cap // 3:]
        blobs = [text.encode()] + [b.encode("latin-1", "ignore") for b in literal_blobs(text)]
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if lines and len(lines) <= 400:
            blobs += [ln.strip().encode("latin-1", "ignore") for ln in lines[-3:]]
        keys = [k.encode("latin-1", "ignore") for k in dict.fromkeys(string_literals(text))
                if 3 <= len(k) <= 32 and not re.search(r"\s", k)][:12]
    else:
        f.update(format_facts(data))
        f["head"] = header_words(data)
        mk = magic_markers(data)
        for t in tags:   # a tag the question names is looked for wherever it stands
            offs = [m.start() for m in re.finditer(re.escape(t.encode("latin-1", "ignore")), data[:16_000_000])]
            if offs:
                mk[t] = offs[:8] + ([offs[-1]] if len(offs) > 8 else [])
        if mk:
            f["markers"] = mk
        strs = ascii_strings(data)
        ev["strings"] = _rank_strings(strs)
        blobs = []
        if len(data) <= 4096:
            blobs.append(data)
        # the bytes after each rare 4-byte tag (a config or overlay magic), at a few header lengths: tags the
        # question names first, then the ones nearest the end of the file (overlays sit at the end)
        order = sorted((mk or {}).items(), key=lambda kv: (kv[0] not in set(tags), -kv[1][-1]))
        named = [kv for kv in order if kv[0] in set(tags)]
        for tag, offs in (named[:2] or order[:3]):
            o = offs[-1]
            blobs.insert(0, data[o + 4:o + 4 + 4096])
            # the header after the tag, read every common way, so a question's stated layout can be followed
            hdr = data[o:o + 48]
            f.setdefault("tag_headers", {})[tag] = {
                "offset_of_last": o, "offsets": offs, "size_after": len(data) - o,
                "bytes_hex": hdr.hex(" "),
                "u8": {f"+{i}": hdr[i] for i in range(4, min(12, len(hdr)))},
                "u16le": {f"+{i}": struct.unpack_from("<H", hdr, i)[0] for i in range(4, min(16, len(hdr) - 1), 2)},
                "u32le": {f"+{i}": [struct.unpack_from("<I", hdr, i)[0], _hexw(struct.unpack_from("<I", hdr, i)[0], 8)]
                          for i in range(4, min(44, len(hdr) - 3), 4)},
            }
            # a stream cipher needs its exact start: RC4 / repeating XOR under a key stored in the header
            for a in (4, 6, 8, 12, 16):
                for n in (4, 8, 16):
                    key = data[o + a:o + a + n]
                    if len(key) < n or len(set(key)) < 3:
                        continue
                    for start in sorted({a + n, 16, 20, 24, 32}):
                        body = data[o + start:o + start + 4096]
                        for via, fn in (("rc4_header_key", lambda k, x: _rc4(k, x)),
                                        ("xor_header_key", lambda k, x: bytes(c ^ k[i % len(k)] for i, c in enumerate(x)))):
                            if text_score(fn(key, body[:96])) >= 0.85:
                                r = fn(key, body)
                                if text_score(r) >= 0.8:
                                    pre.append((via, trim_junk(r)))
        tail = data[-4096:]
        # keys: header bytes right after the first tag (a key stored in the overlay header), then printable
        # runs near the end of the file
        if order:
            o = order[0][1][-1]
            keys = [data[o + a:o + a + n] for a in (4, 8, 12, 16) for n in (8, 16) if len(data) >= o + a + n]
        keys += [s.encode("latin-1") for s in dict.fromkeys(m.group().decode("latin-1")
                 for m in re.finditer(rb"[\x21-\x7e]{4,24}", tail))][:6]
        blobs += [s.encode("latin-1", "ignore") for s in strs
                  if len(s) >= 20 and re.fullmatch(r"[A-Za-z0-9+/=_\-.:%\\ ]+", s)][:12]
    dec, seen = [], set()

    def keep(via, r):
        r = trim_junk(r)
        s = r.decode("utf-8", "replace") if is_text(r) else r.decode("latin-1")
        s = s.strip()
        if len(s) >= 4 and s not in seen:
            seen.add(s)
            dec.append({"via": via, "text": s[:2000]})

    for via, r in pre:
        keep(via, r)
    blobs = blobs[:40]
    for i, b in enumerate(blobs):
        now = time.time()
        if now > deadline:
            break
        per = max(0.05, min(1.5, (deadline - now) / max(1, len(blobs) - i)))
        for chain, r, sc in decode_search(b, min(deadline, now + per), keys=keys):
            keep("+".join(chain), r)
    dec.sort(key=lambda d: -_wordy_score(d["text"].encode("utf-8", "replace")))
    ev["decoded"] = dec[:24]
    rec = {}
    for src in [ev["text"]] + [d["text"] for d in dec] + (ev["strings"] if not textual else []):
        for k, vs in records_of(src).items():
            for v in vs:
                rec.setdefault(k, [])
                if v not in rec[k]:
                    rec[k].append(v)
    ev["records"] = {k: v[:6] for k, v in list(rec.items())[:200]}
    return ev


def _rank_strings(strs: list) -> list:
    keep, seen = [], set()
    for s in strs:
        t = s.strip()
        if len(t) < 5 or t in seen:
            continue
        seen.add(t)
        # skip compiler/runtime noise: long runs of one char, pure symbols
        if len(set(t)) < 4:
            continue
        keep.append(t)
    interesting = [s for s in keep if re.search(r"https?://|\\\\|[A-Za-z]:\\|\.[a-z]{2,4}\b|[=:]|[A-Z]{2,}[-_]\d", s)]
    rest = [s for s in keep if s not in set(interesting)]
    return (interesting[:80] + rest[:80])


# ---------------------------------------------------------------------------------------------- questions
STOP = {"what", "is", "the", "exact", "value", "for", "field", "in", "delivered", "evidence", "set", "of", "a",
        "an", "and", "to", "recover", "identify", "determine", "submit", "which", "this", "its", "by", "with",
        "from", "only", "that", "does", "it", "on", "as", "are", "be", "or", "analysis", "embedded", "indicator",
        "sample", "reconstructed", "modeled", "synthetic", "inert", "using", "use", "all", "members", "member"}


def q_terms(q: dict) -> list:
    """The distinctive words of a question: its id tail and its text, minus filler."""
    qid = re.sub(r"^set\d+\.", "", q.get("qid") or q.get("id") or "")
    words = re.split(r"[^a-z0-9]+", (qid + " " + (q.get("question") or "")).lower())
    out = []
    for w in words:
        if len(w) >= 3 and w not in STOP and not re.fullmatch(r"d\d\d|\d+", w) and w not in out:
            out.append(w)
    return out


def qid_tail_terms(q: dict, member: str = "") -> list:
    """The words of the id that are not the member's name: the property being asked."""
    qid = re.sub(r"^set\d+\.", "", q.get("qid") or q.get("id") or "").lower()
    mwords = set(re.split(r"[^a-z0-9]+", (member or "").lower()))
    parts = [p for p in re.split(r"[^a-z0-9]+", qid) if p and p not in mwords and not re.fullmatch(r"d?\d+", p)]
    return [p for p in parts if p not in STOP]


SYNTAX_RX = [
    (re.compile(r"64 lowercase hex", re.I), re.compile(r"\b[0-9a-f]{64}\b")),
    (re.compile(r"40 lowercase hex", re.I), re.compile(r"\b[0-9a-f]{40}\b")),
    (re.compile(r"32 lowercase hex", re.I), re.compile(r"\b[0-9a-f]{32}\b")),
    (re.compile(r"three lowercase words separated by hyphens", re.I), re.compile(r"\b[a-z]+-[a-z]+-[a-z]+-\d{2}\b")),
    (re.compile(r"ANS-", re.I), re.compile(r"\bANS-[0-9A-F]{8,32}\b")),
    (re.compile(r"T####", re.I), re.compile(r"\bT\d{4}(?:\.\d{3})?\b")),
]


IOC_RX = [
    (("url", "uri", "endpoint"), re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>|`\\]+")),
    (("domain", "host", "hostname", "fqdn"), re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?\.)+(?:invalid|test|example|com|net|org|io|local|onion|xyz|ru|cn|info|biz)\b", re.I)),
    (("ip", "address", "ipv4"), re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")),
    (("mutex",), re.compile(r"\b(?:Global|Local|Session)\\[^\s\"'<>|`]+")),
    (("path", "file", "filename", "output", "note", "dropped"), re.compile(r"(?:[A-Za-z]:\\|%\w+%\\|/tmp/|/var/|/etc/|/home/|/usr/|\\\\)[^\s\"'<>|`]*")),
    (("file", "filename", "note", "extension", "name"), re.compile(r"\b[\w\-]+\.(?:exe|dll|txt|bin|dat|ps1|js|vbs|bat|cmd|zip|lnk|hta|html?|log|tmp|stage|key|enc|locked|crypt|sys|json|xml|py|sh|php)\b", re.I)),
    (("extension",), re.compile(r"(?<![\w\\/])\.[A-Za-z0-9][\w\-]{1,24}")),
    (("registry", "key", "run"), re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+|HKU|HKCR)\\[^\s\"'<>|`]+")),
    (("email", "sender", "recipient"), re.compile(r"\b[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+\b")),
    (("wallet",), re.compile(r"\bwallet[_\-][0-9a-zA-Z]+\b|\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|\b0x[0-9a-fA-F]{40}\b")),
    (("campaign",), re.compile(r"\b[A-Z][A-Z0-9_]{1,30}-[0-9a-fA-F]{3,16}\b")),
    (("agent", "useragent"), re.compile(r"\bMozilla/[^\"'|\n]+|\b[A-Za-z]+/\d+\.\d+(?: \([^)]*\))?")),
    (("guid", "uuid", "mvid", "clsid"), re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
]


def syntax_regexes(q: dict) -> list:
    syn = json.dumps(q.get("answer_format") or {}) + " " + (q.get("question") or "")
    out = [rx for test, rx in SYNTAX_RX if test.search(syn)]
    m = re.search(r"\b([A-Z]{2,5})-[0-9A-Fa-f#X]{4,}", syn)
    if m and not any("ANS" in rx.pattern for rx in out):
        out.append(re.compile(r"\b" + m.group(1) + r"-[0-9A-Fa-f]{4,32}\b"))
    return out


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def format_value(v, q: dict) -> list:
    """The value as the answer format asks for it, plus near forms (ordered tokens, json)."""
    af = q.get("answer_format") or {}
    kind = af.get("kind")
    out = []
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        out.append(str(v))
    else:
        s = str(v).strip()
        out.append(s)
        if kind == "ordered_tokens" or ">" in (q.get("question") or "") and "separat" in (q.get("question") or ""):
            for sep in (",", ";", " ", "|", "->"):
                if sep in s:
                    out.insert(0, ">".join(t.strip() for t in s.split(sep) if t.strip()))
                    break
        if kind == "integer":
            m = re.fullmatch(r"0x([0-9a-fA-F]+)", s)
            if m:
                out.insert(0, str(int(m.group(1), 16)))
    return [x for x in out if x]


def local_candidates(q: dict, evs: list, rejected=(), shipped=None) -> list:
    """Evidence-ranked candidates for one question from the packs of the members it names (no model)."""
    af = q.get("answer_format") or {}
    kind = af.get("kind")
    terms = q_terms(q)
    member = q.get("member") or ""
    tail = qid_tail_terms(q, member)
    cands = []

    def add(name, v):
        for x in format_value(v, q):
            cands.append((name, x))

    # 1. key=value records whose key matches the asked property
    scored = []
    for ev in evs:
        for k, vs in ev["records"].items():
            kn = set(re.split(r"[^a-z0-9]+", k))
            score = 0.0
            if tail and _norm("".join(tail)) == _norm(k):
                score += 5
            score += 2 * len(kn & set(tail)) + len(kn & set(terms))
            if score > 0:
                for i, v in enumerate(vs):
                    scored.append((score - 0.1 * i, f"record_{_slug(k)}", v))
    scored.sort(key=lambda x: -x[0])
    for _, n, v in scored[:12]:
        add(n, v)
    # 2. pattern matches in decoded text (last line first: "final line" questions)
    rxs = syntax_regexes(q)
    for rx in rxs:
        for ev in evs:
            texts = [d["text"] for d in ev["decoded"]] + [ev["text"]] + ev["strings"]
            hits = []
            for t in texts:
                for ln in reversed([x for x in t.splitlines() if x.strip()]):
                    hits += rx.findall(ln)
            for h in hits[:6]:
                add(f"pattern_{_slug(rx.pattern)[:20]}", h)
    # 2b. indicators by shape when the question names their kind (URL, domain, mutex, path, ...)
    for words, rx in IOC_RX:
        if not (set(words) & (set(terms) | set(tail))):
            continue
        hits = []
        for ev in evs:
            for t in [d["text"] for d in ev["decoded"]] + [ev["text"]] + ev["strings"]:
                for h in rx.findall(t):
                    h = h.strip(".,;)\"'")
                    if "\\\\" in h or "\\/" in h:
                        try:
                            hits.append(json.loads('"' + h + '"'))
                        except ValueError:
                            pass
                    hits.append(h)
        uniq = list(dict.fromkeys(hits))
        # a hit cut short by a partial decode is a prefix of a fuller one: keep the fuller
        uniq = [h for h in uniq if not any(o != h and o.startswith(h) for o in uniq)]
        for h in uniq[:6]:
            add(f"shape_{words[0]}", h)
    # 3. hashes and sizes the question names
    ql = (q.get("question") or "").lower() + " " + (q.get("qid") or "").lower()
    for algo in ("sha256", "sha1", "md5", "crc32"):
        if algo in ql.replace("-", ""):
            for ev in evs:
                # of what was decoded (a payload's checksum), then a stored header field, then the member
                for d in ev["decoded"][:2]:
                    raw = d["text"].encode("utf-8", "replace")
                    v = (_hexw(zlib.crc32(raw) & 0xFFFFFFFF, 8) if algo == "crc32"
                         else hashlib.new(algo, raw).hexdigest())
                    add(f"{algo}_of_decoded", v)
                if algo == "crc32":
                    for tag, h in (ev["facts"].get("tag_headers") or {}).items():
                        for off, (_, hx) in list(h["u32le"].items())[:5]:
                            add(f"crc32_field_{tag.lower()}_{off[1:]}", hx)
                add(f"{algo}_of_member", ev["facts"][algo])
    if kind == "integer":
        for ev in evs:
            for tag, h in (ev["facts"].get("tag_headers") or {}).items():
                if tag.lower() in ql:
                    if "offset" in ql:
                        add(f"tag_offset_last_{tag.lower()}", h["offset_of_last"])
                        add(f"tag_offset_first_{tag.lower()}", h["offsets"][0])
                    if re.search(r"size|length", ql):
                        add(f"size_from_tag_{tag.lower()}", h["size_after"])
    if kind == "integer" and re.search(r"\bsize|length|bytes\b", ql):
        for ev in evs:
            add("member_size", ev["facts"]["size"])
    # 4. format facts whose name matches the asked property
    fscored = []
    for ev in evs:
        for k, v in _flat_facts(ev["facts"]):
            if k in ("format_names", "arch_names") or (isinstance(v, (list, dict)) and kind != "json"):
                continue
            kn = set(re.split(r"[^a-z0-9]+", k.lower()))
            sc = 2 * len(kn & set(tail)) + len(kn & set(terms))
            if sc >= 2:
                fscored.append((sc, f"fact_{_slug(k)}", v))
    fscored.sort(key=lambda x: -x[0])
    for _, n, v in fscored[:8]:
        add(n, v if not isinstance(v, (list, dict)) else json.dumps(v, separators=(",", ":")))
    # 4b. container format and architecture under their common spellings
    for ev in evs:
        fx = ev["facts"]
        if {"format", "container", "type"} & set(tail):
            for v in fx.get("format_names", []):
                add("format_name", v)
        if {"architecture", "arch", "machine", "cpu"} & set(tail):
            for v in fx.get("arch_names", []):
                add("arch_name", v)
    # 4c. strings and symbols that contain a distinctive word of the asked property (shortest first)
    words = [w for w in tail if len(w) >= 4 and w not in ("symbol", "value", "name", "string", "field")]
    if words and kind in ("exact_text", "pattern", None):
        pool = []
        for ev in evs:
            pool += list(ev["facts"].get("elf.symbols_sample") or []) + list(ev["strings"])
        scored_s = []
        for s in dict.fromkeys(pool):
            if len(s) > 200:
                continue
            n = sum(1 for w in words if w in s.lower())
            if n:
                scored_s.append((-n, len(s), s))
        for _, _, s in sorted(scored_s)[:4]:
            add("contains_term", s)
    # 5. enum: accepted values that appear in the evidence first, then the rest
    if kind == "enum" and af.get("accepted_values"):
        vals = list(af["accepted_values"])
        blob = " ".join(json.dumps(ev["records"]) + " " + " ".join(d["text"] for d in ev["decoded"]) + ev["text"]
                        for ev in evs).lower()
        vals.sort(key=lambda v: -blob.count(str(v).lower()))
        for v in vals:
            if not cands or str(v) not in {c[1] for c in cands}:
                cands.append((f"enum_{_slug(str(v))}", str(v)))
    return dedupe(cands, q, rejected)


def _flat_facts(f, prefix=""):
    for k, v in f.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict) and k not in ("head",):
            yield from _flat_facts(v, key + ".")
        else:
            yield key, v


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")[:40] or "x"


def same(a: str, b: str, norm: str) -> bool:
    if norm == "trim":
        return a.strip() == b.strip()
    if norm == "case_insensitive":
        return a.casefold() == b.casefold()
    return a == b


def dedupe(cands: list, q: dict, rejected=()) -> list:
    norm = q.get("normalization") or "exact"
    out = []
    for n, v in cands:
        if not isinstance(v, str):
            v = json.dumps(v, separators=(",", ":"))
        if not v.strip() or len(v) > 2000:
            continue
        if any(same(v, r, norm) for r in rejected if isinstance(r, str)):
            continue
        if any(same(v, w, norm) for _, w in out):
            continue
        out.append((n, v))
    return out
