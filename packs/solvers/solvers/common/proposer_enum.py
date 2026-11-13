#!/usr/bin/env python3
"""Deterministic candidate enumerator (the adapt bench's contender B): no model, no network.

For every id a shipped solver left None or unsure, propose up to 12 evidence-ranked candidate values:

    propose(questions, files, ctx, deadline) -> {qid: [(hypothesis_name, value), ...]}

The interface is tests/adapt_bench/README.md's. In production the output is NEVER plain: `as_candidates()`
wraps it as `labels.candidates(key, options)` (unsure, row 346), which tools/verify.py probes on the untimed
base and the runners probe only on an attempt with no deadline. It runs only for ids still None/unsure,
under its own deadline, so it never slows a lane whose solver answers.

How it works, for each open question:
  1. Spec: the asked noun (from the question text and the id's own field words), the target member, the
     answer format (enum values, integer, hex, JSON array, digest, slug, ...), stated places (a magic named
     in the question, "member N", "+offset", "u32le").
  2. Experts enumerate candidate facts from the bytes, each with an evidence score:
       decode   every member's text decoded recursively (string literals joined, PowerShell -f pieces,
                hex/base64/base32/rot13/reversed/zlib/deflate/gzip/repeating-XOR with a key the text names,
                single-byte XOR) into a pool of texts;
       kv       key=value / key: value / JSON pairs in those texts, matched to the asked noun;
       shapes   values of the asked noun's shape (url, domain, mutex, path, filename, user agent, wallet,
                extension, campaign id, GUID, ATT&CK id, slug, ANS- code, ...);
       enum     every accepted value of an enum, ranked by evidence in the texts;
       attack   ATT&CK candidates from the decoded behaviour words and the script language;
       binfacts header facts of PE / ELF / Mach-O / Java class / WASM / RIFF / MP4 / JPEG / e-mail / OOXML
                / LNK, flattened to name -> value and matched to the asked property;
       symbols  symbol tables (ELF, PE COFF, Mach-O) matched to the asked noun, with section prefixes;
       overlay  a magic the question names: its offsets, sizes and header fields, and the payload behind it
                decoded by a family of byte transforms whose parameters come from the header;
       digest   hashes of named or numbered members, and orderings by digest;
       classical  for a slug: a battery of classical decoders (Atbash, Caesar, Vigenere/Beaufort keys
                recovered from a crib, Bacon, Morse, binary/octal/decimal, base-N, XOR, ...).
  3. Every candidate is rendered in the forms the answer format allows (decimal, 0x with the field's
     padding, lower/upper, compact JSON in order), checked against the format, de-duplicated under the
     judge's normalization, ranked by score and cut to 12. The morning's own unsure options (ctx["shipped"])
     come first unless stronger evidence outranks them; values the judge rejected (ctx["rejected"]) never.
"""
import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import struct
import sys
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

MAX = 12
MARGIN = 0.25          # seconds kept back from the deadline
MAX_MEMBER = 8 << 20   # bytes of one member the text decoders read
MAX_DECODES = 400      # decoded texts per member

# ---------------------------------------------------------------------------------------------------------
# small helpers

STOP = set("""a an the of in on for to is are was what which who whose how exact exactly value values field
analysis delivered evidence set sample specimen recover recovered identify classify determine submit inspect
embedded indicator only this that its it by from with and or as be using use into per each any one primary
inert modeled synthetic named given file member members zip central directory order artifact text""".split())


def toks(s):
    """Lowercase word tokens of a name or a sentence: snake, kebab, camel and dotted names split."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(s or ""))
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return ok / len(b)


def as_text(b: bytes) -> str:
    if b.count(b"\x00") > len(b) // 4 and len(b) >= 4:
        try:
            t = b.decode("utf-16-le")
            if printable_ratio(t.encode("utf-8", "ignore")) > 0.8:
                return t
        except UnicodeDecodeError:
            pass
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


def strings_of(b: bytes, n=4, cap=20000):
    """ASCII and UTF-16LE strings of at least n characters, in file order (offset, text)."""
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % n, b):
        out.append((m.start(), m.group().decode("latin-1")))
        if len(out) >= cap:
            break
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % n, b):
        out.append((m.start(), m.group().decode("utf-16-le", "ignore")))
        if len(out) >= 2 * cap:
            break
    out.sort()
    return out


def norm_eq(a, b, normalization):
    if normalization == "trim":
        return a.strip() == b.strip()
    if normalization == "case_insensitive":
        return a.casefold() == b.casefold()
    return a == b


def jdump(v):
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------------------------------------
# the question


class Spec:
    """What one question asks, read from its text, its format and its id."""

    def __init__(self, q, ctx):
        self.q = q
        self.qid = q.get("qid") or ""
        self.text = q.get("question") or q.get("text") or q.get("prompt") or ""
        fmt = q.get("answer_format") or {}
        self.kind = (fmt.get("kind") or "").lower()
        self.syntax = fmt.get("syntax") or ""
        self.accepted = [str(v) for v in fmt.get("accepted_values") or []]
        self.normalization = q.get("normalization") or "exact"
        self.member = q.get("member")
        self.set_text = ctx.get("_set_text") or ""
        rx = re.search(r"(?<![\w])/([^/\s][^/]{1,80})/(?![\w])", q.get("question") or q.get("text") or "")
        self.regex = None
        if rx:
            try:
                self.regex = re.compile(rx.group(1))
            except re.error:
                self.regex = None
        self.lane = ctx.get("lane") or ""
        low = (self.text + " " + self.syntax).lower()
        self.low = low
        self.field = self._field()
        self.field_toks = [t for t in toks(self.field) if t not in ("analysis", "d") and not re.fullmatch(r"d\d\d", t)]
        asked = self.text
        if len(asked) > 240:
            # a long stated procedure: the asked noun is in its last sentence
            asked = re.split(r"(?<=[.;])\s+", asked.strip())[-1]
        self.asked = asked
        qt = [t for t in toks(asked) if t not in STOP and not re.fullmatch(r"d\d\d|\d+", t)]
        self.noun_toks = list(dict.fromkeys(self.field_toks + qt))
        self.day_prefix = None
        m = re.search(r"\b(d\d\d)--", self.text) or re.match(r"(d\d\d)_", self.qid)
        if m:
            self.day_prefix = m.group(1)
        self.form = self._form()

    def _field(self):
        """The id's own field words: script `<member stem>-<field>`, binary `dNN_analysis_<field>`,
        metadata `<file stem>-<ns>-<property>`."""
        qid = re.sub(r"^set\d+\.", "", self.qid)
        m = re.match(r"d\d\d_(?:analysis|artifact)_(.+)$", qid)
        if m:
            return m.group(1)
        if self.member:
            stem = Path(self.member).stem
            if qid.startswith(stem + "-"):
                return qid[len(stem) + 1:]
        m = re.search(r"\b([a-z0-9]+)\.([a-z0-9_]+)\s+for\s", self.text)
        if m:
            return f"{m.group(1)}_{m.group(2)}"
        return qid

    def _form(self):
        k, s = self.kind, self.syntax.lower()
        if self.accepted:
            return "enum"
        if "ans-" in s:
            return "ans"
        if "three lowercase words" in s:
            return "slug"
        if k == "mitre_attack_id" or "att&ck" in s:
            return "attack"
        if "0x prefix" in s or "0x plus" in s:
            return "hex0x"
        if "64 lowercase hex" in s or ("sha-256" in self.asked.lower() and "hex" in s and k == "pattern"):
            return "sha256"
        if "guid" in s:
            return "guid"
        if "major.minor" in s:
            return "dotted"
        if k == "integer" or ("integer" in s and "none" not in s):
            return "int"
        if "integer" in s and "none" in s:
            return "int_or_none"
        if k == "json" or "json array" in s:
            return "json"
        if k == "ordered_tokens" or "joined by >" in s:
            return "tokens"
        return "text"

    def fits(self, v: str) -> bool:
        f = self.form
        if not isinstance(v, str) or not v.strip() or len(v) > 4000:
            return False
        if f == "enum":
            return any(norm_eq(v, a, "case_insensitive" if self.normalization == "case_insensitive" else "exact")
                       for a in self.accepted)
        if f == "ans":
            return bool(re.fullmatch(r"ANS-[0-9A-F]{16}", v))
        if f == "slug":
            return bool(re.fullmatch(r"[a-z]+-[a-z]+-[a-z]+-\d{2}", v))
        if f == "attack":
            return bool(re.fullmatch(r"T\d{4}(\.\d{3})?|none", v))
        if f == "sha256":
            return bool(re.fullmatch(r"[0-9a-f]{64}", v))
        if f == "guid":   # braces too: the judge took an MSI's braced GUID under an 8-4-4-4-12 syntax (family a)
            return bool(re.fullmatch(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?", v))
        if f == "hex0x":
            return bool(re.fullmatch(r"0x[0-9a-f]+", v))
        if f == "dotted":   # major.minor, and major.minor.patch where the syntax says so (family a)
            return bool(re.fullmatch(r"\d+\.\d+" + (r"(?:\.\d+){0,2}" if "patch" in self.syntax.lower() else ""), v))
        if f == "int":
            return bool(re.fullmatch(r"-?\d+", v))
        if f == "int_or_none":
            return bool(re.fullmatch(r"\d+|none", v))
        if f == "json":
            try:
                return isinstance(json.loads(v), list) and v == jdump(json.loads(v))
            except ValueError:
                return False
        if f == "tokens":
            return " " not in v.strip() and len(v) < 400
        return "\n" not in v.strip() and len(v) < 600

    def render(self, v):
        """Every form of a fact this question's format allows, best first."""
        f = self.form
        out = []
        if isinstance(v, bool):
            v = "true" if v else "false"
        if isinstance(v, (list, tuple)):
            items = list(v)
            if f == "json":
                out.append(jdump([str(x) if not isinstance(x, (int, float)) else x for x in items]))
                out.append(jdump([str(x) for x in items]))
            elif f == "tokens":
                out.append(">".join(str(x) for x in items))
            else:
                out.append(",".join(str(x) for x in items))
                out.append(jdump([str(x) for x in items]))
            return out
        if isinstance(v, int):
            if f in ("hex0x",):
                width = self.hex_width()
                if width:
                    out.append("0x%0*x" % (width, v))
                out.append("0x%x" % v)
                for w in (4, 8, 2, 16):
                    out.append("0x%0*x" % (w, v))
            out.append(str(v))
            return out
        s = str(v)
        if f == "tokens" and "," in s and ">" not in s:
            out.append(">".join(x.strip() for x in s.split(",")))
        if f == "json" and not s.startswith("["):
            parts = [x.strip() for x in re.split(r"[,;|]", s) if x.strip()]
            out.append(jdump(parts))
        if f == "sha256":
            out.append(s.lower())
        if f == "hex0x" and re.fullmatch(r"(0x)?[0-9a-fA-F]+", s):
            h = s.lower()[2:] if s.lower().startswith("0x") else s.lower()
            out.append("0x" + h)
            try:
                return out + self.render(int(h, 16))
            except ValueError:
                pass
        if f == "attack":
            out.append(s.upper() if s.lower() != "none" else "none")
        if f == "ans":
            out.append(s.upper())
        out.append(s)
        if f == "enum":
            for a in self.accepted:
                if a.lower() == s.lower():
                    out.insert(0, a)
        return out

    def hex_width(self):
        m = re.search(r"exactly (\w+) (?:lowercase |uppercase )?hex", self.low)
        words = {"two": 2, "four": 4, "six": 6, "eight": 8, "sixteen": 16}
        if m and (m.group(1) in words or m.group(1).isdigit()):
            return words.get(m.group(1)) or int(m.group(1))
        t = (self.field + " " + self.text).lower()
        if re.search(r"u16|machine|16[- ]?bit", t):
            return 4
        if re.search(r"u32|rva|address|32[- ]?bit|cpu_type|cputype", t):
            return 8
        if re.search(r"u64|64[- ]?bit", t):
            return 16
        if re.search(r"u8\b|byte", t):
            return 2
        return 0


# ---------------------------------------------------------------------------------------------------------
# the candidate pool


class Pool:
    def __init__(self, spec, rejected):
        self.spec = spec
        self.rejected = [str(r) for r in rejected or []]
        self.items = {}   # normalized value -> [score, name, value, order, provenance]
        self.n = 0
        self.where = ""   # integration fix (d): the member an expert is reading, the head of each provenance

    def _key(self, v):
        if self.spec.normalization == "case_insensitive" or self.spec.form in ("enum",):
            return v.casefold()
        if self.spec.normalization == "trim":
            return v.strip()
        return v

    def add(self, name, value, score, prov=None, _respell=True):
        """`prov` is the source chain of the candidate, e.g. `member a.ps1 > b64 > xor 0x5a > kv mutex=`; by default
        the member being read (self.where) and the expert's name split at its colons."""
        if value is None:
            return
        if prov is None:
            prov = " > ".join(x for x in [self.where] + str(name).split(":") if x)
        fitted = False
        for i, v in enumerate(self.spec.render(value)):
            if not isinstance(v, str) or not self.spec.fits(v):
                continue
            fitted = True
            if any(norm_eq(v, r, self.spec.normalization) for r in self.rejected):
                continue
            k = self._key(v)
            sc = score - 0.5 * i
            cur = self.items.get(k)
            nm = re.sub(r"[^a-z0-9_.:+~-]+", "_", str(name).lower())[:80] or "candidate"
            if i:
                nm = f"{nm}~f{i}"
            if cur is None:
                self.n += 1
                self.items[k] = [sc, nm, v, self.n, prov[:240]]
            elif sc > cur[0]:
                cur[0], cur[1], cur[4] = sc, nm, prov[:240]
            else:
                cur[0] += 0.01   # a second path to the same value is a little more evidence
        if not fitted and _respell and isinstance(value, str) and len(value) <= 400:
            # family (a): a fact the asked form does not take as it stands ("4096 bytes" for an integer, "Yes" for
            # true/false, "v1.2" for digits only), respelled into that form, a little under its own evidence
            fam = families()
            if fam:
                for how, v2 in fam.respell(self.spec, value):
                    self.add(f"{name}~respell:{how}", v2, score - 1.0, _respell=False)

    def ranked(self):
        if self.spec.regex is not None:
            for r in self.items.values():
                r[0] += 12.0 if self.spec.regex.search(r[2]) else -6.0
        vals = [r[2] for r in self.items.values()]
        if self.spec.form in ("text", "tokens", "json") and len(vals) < 400:
            # a value that is a strict prefix of another candidate is most likely a fragment of it
            by_src = defaultdict(list)
            for r in self.items.values():
                by_src[r[1].split(":")[0]].append(r[2])
            for r in self.items.values():
                v, src = r[2], r[1].split(":")[0]
                if src in ("kv", "shape", "overlay", "record") and len(v) >= 2 and any(
                        len(o) > len(v) and o.startswith(v) for o in by_src[src]):
                    r[0] -= 4.0
        rows = sorted(self.items.values(), key=lambda r: (-r[0], r[3]))
        out, names = [], set()
        for sc, nm, v, _, prov in rows[:MAX]:
            base, k = nm, 2
            while nm in names:
                nm = f"{base}#{k}"
                k += 1
            names.add(nm)
            out.append((nm, v, round(sc, 2), prov))
        return out


# ---------------------------------------------------------------------------------------------------------
# decoding: every text a member holds, decoded recursively

KEYISH_RE = re.compile(r"(?:^|[|;&\n,{ ])\"?[a-z][a-z0-9_]{1,30}\"?\s*[=:]")
B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s.:,_-]?){8,}")
LIT_RE = re.compile(r"'((?:[^'\\\n]|\\.){2,})'|\"((?:[^\"\\\n]|\\.){2,})\"|`([^`]{2,})`")


def _b64(s: str):
    s2 = re.sub(r"\s+", "", s)
    if len(s2) < 8:
        return None
    for alt in (None, b"-_"):
        t = s2 + "=" * (-len(s2) % 4)
        try:
            return base64.b64decode(t, altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def _hex(s: str):
    h = re.sub(r"\\x|0x|%|&#x|u00", "", re.sub(r"^[A-Z]{2,8}-", "", s.strip()))
    h = re.sub(r"[^0-9a-fA-F]", "", h)
    if len(h) < 8 or len(h) % 2:
        return None
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def _inflate(b: bytes):
    out = []
    for wbits in (-15, 15, 31):
        try:
            out.append(zlib.decompress(b, wbits))
        except zlib.error:
            pass
    for f in (bz2.decompress, lzma.decompress):
        try:
            out.append(f(b))
        except Exception:
            pass
    return out


_NONPRINT = bytes(c for c in range(256) if not (32 <= c < 127 or c in (9, 10, 13)))
_NONLETTER = bytes(c for c in range(256) if not (97 <= c <= 122 or 65 <= c <= 90))
_NONSEP = bytes(c for c in range(256) if c not in b"=|:,;_ /.-")
_NONWEIRD = bytes(c for c in range(256) if c not in b"^\\]`[{}~#$*!\"'<>")


def _textiness(b: bytes) -> float:
    """Printable, with letters and the separators a stated record uses (C-speed counts)."""
    if not b:
        return 0.0
    n = len(b)
    pr = len(b.translate(None, _NONPRINT)) / n
    if pr < 0.97:
        return pr
    letters = len(b.translate(None, _NONLETTER)) / n
    sep = len(b.translate(None, _NONSEP)) / n
    weird = len(b.translate(None, _NONWEIRD)) / n
    return pr + 0.5 * letters + 0.3 * min(sep, 0.2) - 1.5 * weird


BYTE_OPS = ([(f"xor{k:02x}", bytes(c ^ k for c in range(256))) for k in range(1, 256)]
            + [(f"add{k:02x}", bytes((c + k) & 0xff for c in range(256))) for k in range(1, 256)]
            + [(f"rotl{r}", bytes(((c << r) | (c >> (8 - r))) & 0xff for c in range(256))) for r in range(1, 8)])


def _bad_masks():
    """Per byte value c, one bit per BYTE_OPS table (in its order): set where that table maps c to a non-printable
    byte. Built from the non-printable set by bit permutations (XOR k permutes bit positions, add k rotates them),
    a millisecond, not a loop over every table and byte."""
    full = (1 << 256) - 1
    npm = sum(1 << p for p in range(256) if not (32 <= p < 127 or p in (9, 10, 13)))
    low = [sum(1 << x for x in range(256) if not (x >> j) & 1) for j in range(8)]
    k255 = (1 << 255) - 1
    out = []
    for c in range(256):
        m = npm
        for j in range(8):
            if (c >> j) & 1:
                sh = 1 << j
                m = ((m & low[j]) << sh) | ((m >> sh) & low[j])
        a = ((npm >> c) | (npm << (256 - c))) & full if c else npm
        rot = 0
        for r in range(1, 8):
            v = ((c << r) | (c >> (8 - r))) & 0xff
            if not (32 <= v < 127 or v in (9, 10, 13)):
                rot |= 1 << (r - 1)
        out.append(((m >> 1) & k255) | (((a >> 1) & k255) << 255) | (rot << 510))
    return out


_BAD_MASK = _bad_masks()
_ADD_BITS = ((1 << 255) - 1) << 255
_XOR_ROT_BITS = ((1 << 255) - 1) | (((1 << 7) - 1) << 510)


def _single_xor(b: bytes, floor=1.0):
    """Single-byte transforms (XOR k, add k, rotate) that turn the bytes into text, best two."""
    if len(b) < 6 or len(b) > 1 << 20:
        return []
    best = []
    sample, head = b[:256], b[:32]
    # cheap screen: XOR or a rotation of 7-bit text leaves one bit the same in every byte; adding a constant
    # to printable text keeps the bytes inside a window of 95 values (mod 256)
    andv, orv = 0xff, 0
    for c in head:
        andv &= c
        orv |= c
    constant_bit = (andv | (~orv & 0xff)) != 0
    vals = sorted(set(head))
    gaps = [(vals[(i + 1) % len(vals)] - vals[i]) % 256 for i in range(len(vals))] if vals else [256]
    narrow = 256 - max(gaps) <= 100 if len(vals) > 1 else True
    if not constant_bit and not narrow:
        return []
    # the screen "at most one head byte turns non-printable" for every table at once: a bit per table, set where
    # the table maps a byte to a non-printable one; `twos` collects the tables hit twice (the same tables, in the
    # same order, as translating the head through each of them)
    ones = twos = 0
    for c in head:
        m = _BAD_MASK[c]
        twos |= ones & m
        ones |= m
    keep = ((_XOR_ROT_BITS if constant_bit else 0) | (_ADD_BITS if narrow else 0)) & ~twos
    while keep:
        low = keep & -keep
        keep ^= low
        nm, table = BYTE_OPS[low.bit_length() - 1]
        t = _textiness(sample.translate(table))
        if t > floor:
            best.append((t, nm, table))
    best.sort(key=lambda r: -r[0])
    return [(nm, b.translate(table)) for _, nm, table in best[:2]]


def _chain_decodes(b: bytes, floor=1.2):
    """Feedback transforms: XOR or subtract the previous stored byte (CBC-like, any seed), XOR the previous
    decoded byte, and a running sum. The best ones that turn the bytes into text."""
    if len(b) < 8 or len(b) > 1 << 16:
        return []
    out = []
    head = b[:48]
    # stored-byte feedback: the seed changes only the first byte
    for nm, f in (("xor_prev", lambda c, p: c ^ p), ("sub_prev", lambda c, p: (c - p) & 0xff)):
        t = _textiness(bytes(f(b[i], b[i - 1]) for i in range(1, min(len(b), 64))))
        if t <= floor:
            continue
        body = bytes(f(b[i], b[i - 1]) for i in range(1, len(b)))
        t = _textiness(body[:256])
        if t > floor:
            firsts = [k for k in range(256) if 97 <= f(b[0], k) <= 122 or 65 <= f(b[0], k) <= 90]
            seed = firsts[0] if firsts else 0
            out.append((t, f"{nm}_seed", bytes([f(b[0], seed)]) + body))
    # decoded-byte feedback: try every seed on the head first
    best = None
    # x[i] = c[i] ^ x[i-1]: x[i] = c[i] ^ c[i-1] ^ ... ^ c[0] ^ seed, so the seed XORs every byte of a prefix-XOR
    pre, acc = bytearray(), 0
    for c in head:
        acc ^= c
        pre.append(acc)
    for k, x in _single_xor(bytes(pre), floor) if len(pre) >= 6 else []:
        t = _textiness(x)
        k = int(k[3:], 16) if k.startswith("xor") else None
        if k is not None and t > floor and (best is None or t > best[0]):
            best = (t, k)
    if _textiness(bytes(pre)) > floor:
        best = best or (_textiness(bytes(pre)), 0)
    if best:
        p, x = best[1], bytearray()
        for c in b:
            p = c ^ p
            x.append(p)
        out.append((best[0], f"xor_decoded_prev{best[1]:02x}", bytes(x)))
    acc, x = 0, bytearray()
    for c in b:
        acc = (acc + c) & 0xff
        x.append(acc)
    t = _textiness(bytes(x[:256]))
    if t > floor:
        out.append((t, "running_sum", bytes(x)))
    out.sort(key=lambda r: -r[0])
    return [(nm, x) for _, nm, x in out[:2]]


def _rep_xor(b: bytes, key: bytes):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(b))


def ps_format(text: str):
    """PowerShell '{1}{0}' -f 'a','b' pieces put together."""
    out = []
    for m in re.finditer(r"""\(?\s*["']((?:\{\d+\})+)["']\s*-f\s*((?:\s*["'][^"']*["']\s*,?)+)""", text):
        order = [int(x) for x in re.findall(r"\{(\d+)\}", m.group(1))]
        pieces = re.findall(r"""["']([^"']*)["']""", m.group(2))
        try:
            out.append("".join(pieces[i] for i in order))
        except IndexError:
            continue
    return out


def literal_groups(text: str):
    """String literals, and the literals of one statement or bracket joined in order."""
    lits, groups = [], []
    cur, last_end = [], 0
    for m in LIT_RE.finditer(text):
        s = m.group(1) or m.group(2) or m.group(3) or ""
        lits.append(s)
        gap = text[last_end:m.start()]
        if cur and (";" in gap or "\n\n" in gap or len(gap) > 40 or re.search(r"[=(]\s*$", gap) and "\n" in gap):
            groups.append("".join(cur))
            cur = []
        cur.append(s)
        last_end = m.end()
    if cur:
        groups.append("".join(cur))
    return lits, [g for g in groups if len(g) >= 16]


def rot13(s):
    return codecs.encode(s, "rot13")


class Decoded:
    """The pool of texts one member holds: its own text and everything decoded from it, with depth."""

    def __init__(self, data: bytes, deadline: float):
        self.texts = []    # (depth, how, text)
        self.seen = set()
        self.deadline = deadline
        self.keys = []
        self.tries = 0
        self.unkeyed = 0
        if data[:4] in (b"\x7fELF", b"MZ\x90\x00") or data[:2] == b"MZ" or data[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"dex\n", b"\x00asm"):
            text = "\n".join(s for _, s in strings_of(data[:MAX_MEMBER], 5))
        else:
            text = as_text(data[:MAX_MEMBER])
        self.keys = self._keys(text)
        self._add(0, "raw", text)

    def _keys(self, text):
        keys = []
        for m in re.finditer(r"(?i)(?:key|secret|pass(?:word)?|xor)\w*\s*[:=]\s*(?:\[[\w.]+\]::\w+\.GetBytes\()?\s*['\"]([^'\"]{2,64})['\"]", text):
            keys.append(m.group(1).encode())
        for m in re.finditer(r"GetBytes\(\s*['\"]([^'\"]{2,64})['\"]", text):
            keys.append(m.group(1).encode())
        # short byte arrays a decoder names: [128,2,77] / (0x80, 0x02) / "80,02,4d" beside a key word
        for m in re.finditer(r"(?i)(?:key|xor|mask|secret)\w*[^\n\[\(\"']{0,40}[\[\(\"']\s*((?:(?:0x)?[0-9a-f]{1,3}\s*,\s*){1,31}(?:0x)?[0-9a-f]{1,3})\s*[\]\)\"']", text[:200000]):
            parts = [x.strip() for x in m.group(1).split(",")]
            for base_ in ((16,) if any(re.search(r"[a-f]|0x", x, re.I) for x in parts) else (10, 16)):
                try:
                    vals = [int(x, 16) if base_ == 16 else int(x) for x in parts]
                except ValueError:
                    continue
                if all(v < 256 for v in vals):
                    keys.append(bytes(vals))
        for m in re.finditer(r"\|repeating[_a-z]*\|([0-9a-f]{2}(?:,[0-9a-f]{2}){1,31})", text):
            keys.append(bytes(int(x, 16) for x in m.group(1).split(",")))
        return list(dict.fromkeys(keys))[:8]

    def _add(self, depth, how, text):
        if not text or len(self.texts) >= MAX_DECODES:
            return
        h = hash(text)
        if h in self.seen:
            return
        self.seen.add(h)
        if depth >= 1 and len(text) >= 12:
            fwd = len(KEYISH_RE.findall(text[:20000]))
            rev = len(KEYISH_RE.findall(text[:20000][::-1]))
            if rev >= 2 and rev > fwd:
                text, how = text[::-1], how + ">reversed"
                self.seen.add(hash(text))
        self.texts.append((depth, how, text))
        vals = json_values_text(text)
        if vals and hash(vals) not in self.seen:
            self.seen.add(hash(vals))
            self.texts.append((depth, how + ">json_values", vals))
        if depth >= 4 or time.time() > self.deadline:
            return
        self._walk(depth, how, text)

    def _try_bytes(self, depth, how, b):
        if not b or len(b) < 4:
            return
        self.tries += 1
        if self.tries > 600 or time.time() > self.deadline:
            return
        if printable_ratio(b) > 0.9:
            self._add(depth + 1, how, as_text(b))
            if depth < 3 and len(b) >= 12:
                base = _textiness(b[:256])
                for k, x in _single_xor(b, base + 0.12) + _chain_decodes(b, base + 0.12):
                    self._add(depth + 1, how + f">{k}", as_text(x))
            return
        for x in _inflate(b):
            if printable_ratio(x) > 0.85:
                self._add(depth + 1, how + ">inflate", as_text(x))
        for key in self.keys:
            x = _rep_xor(b, key)
            if printable_ratio(x) > 0.9:
                self._add(depth + 1, how + ">xor_key", as_text(x))
        found = _single_xor(b) + _chain_decodes(b)
        for k, x in found:
            self._add(depth + 1, how + f">{k}", as_text(x))
        if not found and depth <= 1 and 24 <= len(b) <= 4096 and self.unkeyed < 12:
            self.unkeyed += 1
            rep = repeating_xor_unkeyed(b)
            if rep and _textiness(rep.encode("latin-1")[:256]) > 1.2:
                self._add(depth + 1, how + ">xor_rep_unkeyed", rep)
        if depth < 3:
            for k, x in _single_xor(b[::-1]):
                self._add(depth + 1, how + f">rev>{k}", as_text(x))
        if b.count(b"\x00") > len(b) // 3:
            try:
                t = b.decode("utf-16-le")
                if printable_ratio(t.encode("ascii", "ignore")) > 0.9:
                    self._add(depth + 1, how + ">utf16", t)
            except UnicodeDecodeError:
                pass

    def _walk(self, depth, how, text):
        cands = []
        lits, groups = literal_groups(text[:400000])
        cands += [("joined", g) for g in groups]
        cands += [("fmt", s) for s in ps_format(text[:400000])]
        cands += [("lit", s) for s in lits if len(s) >= 16]
        cands += [("run", m.group()) for m in B64_RE.finditer(text[:400000]) if len(m.group()) >= 24][:200]
        cands += [("hexrun", m.group()) for m in HEX_RE.finditer(text[:400000])][:200]
        # character-code arrays: [char]72,[char]117 / String.fromCharCode(72,117) / 72,117,110
        for m in re.finditer(r"(?:\d{1,3}\s*[,.]\s*){6,}\d{1,3}", text[:400000]):
            try:
                b = bytes(int(x) for x in re.findall(r"\d+", m.group()))
                cands.append(("charcodes", b.decode("latin-1")))
            except ValueError:
                pass
        done = set()
        for kind, s in cands:
            if time.time() > self.deadline or len(self.texts) >= MAX_DECODES:
                return
            if s in done or len(s) < 8:
                continue
            done.add(s)
            if kind == "charcodes":
                b = s.encode("latin-1")
                self._try_bytes(depth, how + ">charcodes", b)
                self._try_bytes(depth, how + ">charcodes>rev", b[::-1])
                continue
            stripped = s.strip()
            hx = _hex(stripped) if re.fullmatch(r"(?:[A-Z]{2,8}-)?(?:%[0-9a-fA-F]{2})+|(?:\\*(?:x|u00)[0-9a-fA-F]{2})+|(?:0x[0-9a-fA-F]{2}[,\s]*)+|(?:[A-Z]{2,8}-)?[0-9a-fA-F\s.:,_-]+", stripped) else None
            if hx:
                self._try_bytes(depth, how + f">{kind}:hex", hx)
            for label, src in (("b64", stripped), ("rev_b64", stripped[::-1]), ("rot13_b64", rot13(stripped))):
                if not re.fullmatch(r"[A-Za-z0-9+/_\-=\s]+", src):
                    continue
                b = _b64(src)
                if b:
                    self._try_bytes(depth, how + f">{kind}:{label}", b)
            if kind in ("joined", "fmt") and printable_ratio(stripped.encode("utf-8", "ignore")) > 0.95 and depth < 2:
                self._add(depth + 1, how + f">{kind}", stripped)

    def all_text(self):
        return "\n".join(t for _, _, t in self.texts)


# ---------------------------------------------------------------------------------------------------------
# facts from decoded text: key/value pairs and shaped values

KV_RE = re.compile(r"(?<![\w$])([A-Za-z_][A-Za-z0-9_.\-]{0,40})\s*(?:=|:)\s*(\"[^\"\n]{0,300}\"|'[^'\n]{0,300}'|[^|;&,\n\"'{}\[\]]{1,300})")


def flatten_json(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten_json(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        if all(not isinstance(x, (dict, list)) for x in obj):
            yield prefix, obj
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                yield from flatten_json(v, f"{prefix}[{i}]")
            else:
                yield f"{prefix}[{i}]", v
    else:
        yield prefix, obj


def json_values_text(text: str):
    """The string values of the JSON a text holds, one per line, unescaped."""
    t = text.strip()
    if not (t[:1] in "{[" or "{\"" in t[:2000]):
        return None
    vals = []
    for blob in ([t] if t[:1] in "{[" else []) + re.findall(r"\{[^{}]{4,4000}\}", text[:200000])[:50]:
        try:
            obj = json.loads(blob)
        except ValueError:
            continue
        for k, v in flatten_json(obj):
            if isinstance(v, str):
                vals.append(v)
            elif isinstance(v, list):
                vals += [str(x) for x in v if isinstance(x, str)]
    return "\n".join(dict.fromkeys(vals)) if vals else None


def kv_pairs(text: str):
    """(key, value) pairs a text states: JSON objects, then key=value / key: value runs."""
    out = []
    t = text.strip()
    for blob in ([t] if t[:1] in "{[" else []) + re.findall(r"\{[^{}]{4,4000}\}", text[:200000])[:50]:
        try:
            obj = json.loads(blob)
        except ValueError:
            continue
        out += [(k, v) for k, v in flatten_json(obj) if k]
    if "|" in text or "=" in text or ":" in text:
        for seg in re.split(r"[|\n;&]", text[:200000]):
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_.\-]{0,40})\s*[=:]\s*(.+?)\s*$", seg)
            if m and len(m.group(2)) <= 300:
                v = m.group(2).strip().strip("'\"")
                if v:
                    out.append((m.group(1), v))
    return out[:3000]


SHAPES = {
    "url": (r"\b(?:https?|ftp|wss?)://[^\s'\"<>|`)\]}]+", ["url", "uri", "link", "endpoint", "c2", "server", "stage", "download"]),
    "domain": (r"\b(?:[a-z0-9][a-z0-9_-]{0,62}\.)+(?:invalid|test|example|com|net|org|io|local|lan|internal|xyz|ru|cn|info|biz|top)\b", ["domain", "host", "hostname", "fqdn", "c2"]),
    "ip": (r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", ["ip", "address", "addr", "host", "c2"]),
    "mutex": (r"(?:Global|Local|Session)\\\\?[^\s'\"<>|,;]+", ["mutex", "mutant", "lock"]),
    "registry": (r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+|HKCR|HKU)\\[^\s'\"<>|]+", ["registry", "reg", "key", "run", "persistence"]),
    "winpath": (r"\b[A-Za-z]:\\[^\s'\"<>|*?]+", ["path", "file", "target", "drop", "location", "directory"]),
    "unixpath": (r"(?<![\w/])/(?:tmp|var|etc|usr|home|opt|dev|bin|Library|Users|private|run)/[^\s'\"<>|`;,)]+", ["path", "file", "drop", "location", "directory"]),
    "filename": (r"(?<![\w/\\.-])[\w-]{2,}(?:\.[\w-]+)*\.(?:exe|dll|dat|bin|txt|ps1|bat|cmd|vbs|js|zip|tmp|log|db|json|xml|cfg|ini|so|sh|py|lnk|scr|hta|jar|apk|png|jpg|doc|docx|pdf|msi|key|enc|locked|stage)\b", ["file", "filename", "name", "note", "drop", "payload", "dropped"]),
    "useragent": (r"(?<![A-Za-z0-9_])(?:Mozilla/\d\.\d[^'\"\n|;]*|[A-Za-z][\w.-]*/\d+(?:\.\d+)+(?:\s+[\w./()-]+)*)", ["agent", "ua", "useragent", "user"]),
    "wallet": (r"\b(?:wallet_[0-9a-zA-Z]+|bc1[0-9a-z]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b", ["wallet", "address", "btc", "monero", "eth", "crypto"]),
    "extension": (r"(?<![\w])\.[A-Za-z0-9]{2,12}(?:-[A-Za-z0-9]{2,16})?\b", ["extension", "ext", "suffix"]),
    "email": (r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", ["email", "mail", "sender", "recipient", "address"]),
    "guid": (r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", ["guid", "uuid", "clsid", "mvid", "id"]),
    "campaign": (r"\b[A-Z][A-Z0-9_]{1,30}-[0-9A-Fa-f]{3,16}\b", ["campaign", "id", "identifier", "tag", "build", "operation"]),
    "attack": (r"\bT\d{4}(?:\.\d{3})?\b", ["attack", "technique", "mitre"]),
    "sha256": (r"\b[0-9a-fA-F]{64}\b", ["sha256", "hash", "digest"]),
    "md5": (r"\b[0-9a-fA-F]{32}\b", ["md5", "hash", "digest"]),
    "pipe": (r"\\\\\.\\pipe\\[^\s'\"]+", ["pipe"]),
    "task": (r"(?i)\\?Microsoft\\Windows\\[^\s'\"]+", ["task", "scheduled"]),
}


def shape_hits(text, name):
    rx = re.compile(SHAPES[name][0])
    return [m.group().rstrip(".,") for m in rx.finditer(text[:2000000])]


# ---------------------------------------------------------------------------------------------------------
# the environment of one propose() call: caches over the set's files


class Env:
    def __init__(self, files, ctx, deadline):
        self.files = files
        self.ctx = ctx
        self.deadline = deadline
        self._dec = {}
        self._facts = {}
        self._syms = {}

    def member_bytes(self, name):
        if not name:
            return None
        if name in self.files:
            return self.files[name]
        for k, v in self.files.items():
            if k.endswith(" -> " + name) or k.endswith("/" + name) or Path(k).name == name:
                return v
        return None

    def plain_members(self):
        """Every distinct member (the short name, not the `archive -> member` duplicate)."""
        out = {}
        for k, v in self.files.items():
            short = k.split(" -> ")[-1]
            out.setdefault(short, v)
        return out

    def decoded(self, name, data=None):
        if name not in self._dec:
            data = data if data is not None else (self.member_bytes(name) or b"")
            self._dec[name] = Decoded(data, min(self.deadline - MARGIN, time.time() + 3.0))
        return self._dec[name]

    def time_left(self):
        return self.deadline - time.time() - MARGIN


# ---------------------------------------------------------------------------------------------------------
# experts


SYN = {
    "steps": {"behavior", "behaviour", "graph", "steps", "ordered", "actions"},
    "obfuscation": {"encoding", "obfuscation", "encoded", "encoder"},
    "attack": {"att", "ck", "technique", "mitre", "attack"},
    "campaign": {"campaign", "identifier", "id"},
    "host": {"host", "container", "source", "envelope"},
    "adapter": {"adapter", "language", "modeled"},
    "role": {"role"},
    "count": {"count", "number", "how", "many"},
    "language": {"language", "next", "script"},
    "path": {"path", "file", "location"},
    "url": {"url", "uri", "link"},
}


def key_score(key, spec):
    """How well a stated key names the asked noun: shared tokens, the id's field words weighted most."""
    kt = set(toks(key))
    if not kt:
        return 0.0
    ft = set(spec.field_toks)
    nt = set(spec.noun_toks)
    s = 0.0
    s += 6.0 * len(kt & ft)
    s += 2.0 * len(kt & nt)
    for k in kt:
        syn = SYN.get(k)
        if syn and (syn & (ft | nt)):
            s += 2.5
    if ft and kt == ft:
        s += 6.0
    if "_".join(toks(key)) == "_".join(spec.field_toks):
        s += 8.0
    # a plural or singular of a field word (`markers` for `marker_codes`) is the same noun (family a)
    stem = lambda w: w[:-1] if len(w) > 3 and w.endswith("s") and not w.endswith("ss") else w  # noqa: E731
    loose = {stem(k) for k in kt - ft - nt} & {stem(f) for f in ft}
    s += 4.0 * len(loose)
    s -= 0.5 * len(kt - ft - nt)
    return s


def wanted_shapes(spec):
    """Shapes whose words the asked noun uses, best first."""
    words = set(spec.field_toks) | set(spec.noun_toks)
    joined = " ".join(spec.field_toks + spec.noun_toks)
    out = []
    for name, (_, kws) in SHAPES.items():
        hit = sum(1 for k in kws if k in words)
        if name == "useragent" and ("user agent" in spec.low or "user-agent" in spec.low):
            hit += 3
        if name == "extension" and "extension" in joined:
            hit += 3
        if name == "filename" and re.search(r"file ?name|filename|note", spec.low):
            hit += 2
        if name == "url" and re.search(r"\burl\b", spec.low):
            hit += 3
        if hit:
            out.append((hit, name))
    out.sort(reverse=True)
    return [n for _, n in out]


def quality(how, text):
    """A complete decoded record (JSON, several key=value pairs, or the values of one) outranks a fragment."""
    if how.endswith("json_values"):
        return 2.5
    t = text.strip()
    if t[:1] in "{[":
        try:
            json.loads(t)
            return 2.0
        except ValueError:
            pass
    if len(KEYISH_RE.findall(t[:20000])) >= 3:
        return 2.0
    if how.split(">")[-1].startswith(("lit", "run")) or ">lit:" in how or ">run:" in how:
        return -1.0
    return 0.0


def complete_candidate_text(how, text):
    """Whether a decoded text is whole enough to source arbitrary candidates.

    ``run`` and ``lit`` decodes are deliberately speculative: a long encoded
    string can contain an aligned substring that happens to decode as a short
    ``key=value`` fragment.  Day 30 produced ``tion_profile=b64_f``,
    ``tage|file_path=/tm`` and similar fragments from that path.  They are
    evidence of neither a complete key nor a complete value and cost probes on
    a regular attempt.

    Keep complete records (JSON or at least three key/value fields), ordinary
    non-speculative texts, and one-field records only when the entire decoded
    text is a reasonably substantial key/value statement.  This only removes
    proposer candidates; it cannot create or change a plain solver answer.
    """
    if quality(how, text) >= 0:
        return True
    t = text.strip()
    if len(t) < 24:
        return False
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]{0,40}\s*[=:]\s*[^\r\n|;&,{}\[\]]{1,300}", t):
        return False
    return len(kv_pairs(t)) == 1


def expert_text(spec, env, pool, members):
    """kv pairs and shaped values from the decoded texts of the target members."""
    shapes = wanted_shapes(spec)
    first = re.search(r"\bfirst\b", spec.low)
    for mi, name in enumerate(members[:6]):
        if env.time_left() <= 0:
            return
        dec = env.decoded(name)
        mpen = 0.5 * mi
        kvs = []
        for depth, how, text in dec.texts:
            if not complete_candidate_text(how, text):
                continue
            for k, v in kv_pairs(text):
                kvs.append((depth, k, v, how))
        for depth, k, v, how in kvs:
            ks = key_score(k, spec)
            if ks <= 0:
                continue
            sc = 20 + ks + 0.5 * depth - mpen
            prov = f"member {name} > {how} > kv {k}="
            if isinstance(v, (list, tuple)):
                pool.add(f"kv:{k}", list(v), sc, prov)
                continue
            pool.add(f"kv:{k}", v if isinstance(v, str) else jdump(v) if not isinstance(v, (int, float)) else v, sc, prov)
            if isinstance(v, str) and "," in v and spec.form in ("tokens", "json"):
                pool.add(f"kv:{k}:split", [x.strip() for x in v.split(",")], sc, prov + " split ,")
        for si, sh in enumerate(shapes):
            seen = Counter()
            order = []
            hows = {}
            for depth, how, text in dec.texts:
                if not complete_candidate_text(how, text):
                    continue
                q = quality(how, text)
                for h in shape_hits(text, sh):
                    if h not in seen:
                        order.append((depth + q, h))
                        hows[h] = how
                    seen[h] += 1
            for oi, (depth, h) in enumerate(order[:40]):
                sc = 14 - 2 * si + 0.8 * min(depth, 4) + 0.3 * min(seen[h], 5) - mpen - (0.4 * oi if first else 0.05 * oi)
                pool.add(f"shape:{sh}", h, sc, f"member {name} > {hows.get(h, 'raw')} > shape {sh}")
                if sh == "url":
                    m = re.match(r"\w+://([^/:]+)", h)
                    if m and "domain" in spec.noun_toks + spec.field_toks:
                        pool.add("shape:url_host", m.group(1), sc + 1)


def expert_enum(spec, env, pool, members):
    if not spec.accepted:
        return
    text = ""
    kv_vals = Counter()
    boolean = {a.lower() for a in spec.accepted} == {"true", "false"}
    for name in ([] if boolean else members[:3]):
        if printable_ratio((env.member_bytes(name) or b"")[:2048]) < 0.85 and len(members) > 1:
            continue
        dec = env.decoded(name)
        text += dec.all_text()[:400000].lower()
        for depth, how, t in dec.texts:
            for k, v in kv_pairs(t):
                if isinstance(v, str):
                    ks = key_score(k, spec)
                    kv_vals[v.strip().lower()] += 1 + max(ks, 0)
    n = len(spec.accepted)
    focus = {}
    if re.search(r"\bstatement\b", spec.text) and members:
        focus = focus_scores(spec, env.decoded(members[0]).texts[0][2])
    # a value one of the members' parsed facts states (the format, the class, a flag) is strong evidence
    fact_vals = Counter()
    for name in members[:4]:
        for k, v in facts_of(env, name).items():
            if k.startswith("file."):
                continue
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, (str, int)) and not isinstance(x, bool):
                    fact_vals[str(x).lower()] += 1
    for i, a in enumerate(spec.accepted):
        sc = 10 - 3.0 * i / max(n, 1) + 3.0 * focus.get(a, 0)
        al = a.lower()
        if fact_vals.get(al) and not boolean:
            sc += 6
        if kv_vals.get(al):
            sc += 8 + min(kv_vals[al], 10)
        if al in ("true", "false"):
            sc += bool_evidence(spec, env, members, al)
        else:
            hits = len(re.findall(r"(?<![a-z0-9])" + re.escape(al) + r"(?![a-z0-9])", text)) if text else 0
            sc += min(hits, 5) * 0.6
            parts = [p for p in re.split(r"[_\W]+", al) if len(p) > 2]
            if parts and text:
                sc += 0.3 * sum(1 for p in parts if p in text)
        pool.add(f"enum:{a}", a, sc)


VALUE_ALIASES = {   # what a value word looks like in a statement (batch / shell / PowerShell / JS)
    "percent": [r"(?<!%)%[A-Za-z_]\w*%(?!%)"], "delayed": [r"![A-Za-z_]\w*!"],
    "double": [r"%%[A-Za-z_]\w*%%"], "call": [r"(?i)\bcall\b"], "indirect": [r"(?i)\bfor\b[^\n]*%%~?\w"],
    "for": [r"(?i)\bfor\b"], "once": [r"(?i)\bfor\b[^\n]*\(\s*\S+\s*\)\s*do\b"], "if": [r"(?i)\bif\b"],
    "errorlevel": [r"(?i)errorlevel|\|\||&&"], "goto": [r"(?i)\bgoto\b"], "dispatch": [r"(?i)\bgoto\b"],
    "subroutine": [r"(?i)\bcall\s+:"], "guard": [], "direct": [],
}
ASSIGN_RE = re.compile(r"(?im)^\s*(?:set\s+(?:/a\s+)?\"?|\$|(?:var|let|const|local|readonly)\s+)?([A-Za-z_][\w]*)\s*=")


def focus_context(text):
    """The statement that puts the most earlier-assigned variables together, and the lines that wrap it."""
    lines = text.replace("\r", "").split("\n")
    assigned = set()
    best, bi = 0, None
    for i, ln in enumerate(lines):
        refs = set(re.findall(r"[%!]+([A-Za-z_]\w*)(?=[%!:])|\$\{?([A-Za-z_]\w*)", ln))
        names = {a or b for a, b in refs} & assigned
        if len(names) >= 2 and len(names) > best:
            best, bi = len(names), i
        for m in ASSIGN_RE.finditer(ln):
            assigned.add(m.group(1))
    if bi is None:
        return None
    ctx = [lines[bi]]
    for j in range(bi - 1, max(-1, bi - 4), -1):
        ln = lines[j].strip()
        if not ln or re.match(r"(?i)(rem\b|::|ver\b|echo\b|set\s+\"?neutral)", ln):
            continue
        if ln.startswith(":"):
            label = ln[1:].split()[0]
            for k, other in enumerate(lines):
                if k == j or re.search(r"--inspect|--plan", other):
                    continue
                if re.search(r"(?i)\b(goto|call)\s+:?" + re.escape(label) + r"\b", other):
                    gap = [x for x in lines[k + 1:j] if x.strip() and not re.match(r"(?i)\s*(rem\b|::|ver\b|echo\b)", x.strip())]
                    if re.search(r"(?i)\bgoto\b", other) and k < j and len(gap) <= 1:
                        continue   # a goto to the next line is separator noise
                    ctx.append(other)
            continue
        if re.search(r"(?i)\bgoto\b", ln):
            continue
        ctx.append(ln)
        break
    return ctx


def focus_scores(spec, text):
    ctx = focus_context(text)
    if not ctx:
        return {}
    focus, wrap = ctx[0], " \n ".join(ctx[1:])
    lines = text.splitlines()
    out = {}
    for a in spec.accepted:
        sc, parts = 0.0, toks(a)
        for p in parts:
            for rx in VALUE_ALIASES.get(p, [r"(?i)\b" + re.escape(p) + r"\b"]):
                # a word that shows on many lines (the host envelope's `if`) says less than a rare one
                spec_w = 1.0 + 2.0 / (1 + sum(1 for ln in lines if re.search(rx, ln)))
                if re.search(rx, focus):
                    sc += 3.0 * spec_w
                if wrap and re.search(rx, wrap):
                    sc += 2.0 * spec_w
        if parts and all(not VALUE_ALIASES.get(p) and p in VALUE_ALIASES for p in parts):
            sc += 0.5   # 'direct': the default when nothing wraps the statement
        out[a] = sc / max(1, len(parts)) ** 0.5
    return out


def bool_evidence(spec, env, members, al):
    """'has X' / 'is X': X's words in the members' bytes make true more likely."""
    words = [t for t in spec.field_toks if t not in ("has", "is", "contains", "uses", "present")]
    if not words:
        return 0.0
    found = 0
    for name in members[:6]:
        data = env.member_bytes(name) or b""
        low = data[:MAX_MEMBER].lower()
        for w in words:
            if len(w) >= 4 and w.encode() in low:
                found += 1
        if "rust" in words and re.search(rb"_ZN\w+17h[0-9a-f]{16}E|_R[NC]v", data[:MAX_MEMBER]):
            found += 2
    return (2.0 if found else -1.0) if al == "true" else (-1.0 if found else 1.5)


ATTACK_SUB = {".ps1": "T1059.001", ".psm1": "T1059.001", ".bat": "T1059.003", ".cmd": "T1059.003",
              ".vbs": "T1059.005", ".vbe": "T1059.005", ".py": "T1059.006", ".pyc": "T1059.006",
              ".js": "T1059.007", ".jse": "T1059.007", ".ts": "T1059.007", ".mjs": "T1059.007", ".gs": "T1059.007",
              ".sh": "T1059.004", ".bash": "T1059.004", ".zsh": "T1059.004", ".applescript": "T1059.002",
              ".scpt": "T1059.002", ".au3": "T1059.010", ".lua": "T1059.011", ".hta": "T1059.005",
              ".wsf": "T1059.005", ".sct": "T1059.005", ".php": "T1059", ".rb": "T1059", ".pl": "T1059",
              ".mof": "T1059", ".aspx": "T1059", ".cs": "T1059"}
ATTACK_WORDS = [
    ("download", "T1105", r"download|acquire_remote|fetch|webclient|invoke-webrequest|curl|wget|urlretrieve|http_get|remote_fetch|stager"),
    ("decode", "T1140", r"decode_embedded|deobfusc|frombase64|unpack|decrypt_embedded|dropper"),
    ("upload", "T1041", r"upload|exfil|outbound|transmit_remote|uploader"),
    ("schedule", "T1053", r"cron|schtasks|scheduled|crontab|build_schedule|register_descriptor"),
    ("cron", "T1053.003", r"cron|crontab"),
    ("schtasks", "T1053.005", r"schtasks|scheduled.?task"),
    ("runkey", "T1547.001", r"currentversion\\\\?run|run.?key|startup"),
    ("service", "T1543", r"systemd|launchdaemon|create_service"),
    ("encrypt", "T1486", r"encrypt|ransom|write_recovery_note|transform_copy|transform_content"),
    ("interpreter", "T1059", r"launch|dispatch|handoff|relay|staged|spawn"),
    ("obfuscated", "T1027", r"obfusc|packed"),
    ("webproto", "T1071.001", r"beacon|http_client"),
    ("benign", "none", r"benign|harmless|return_configuration|verdict=clean|verdict=benign"),
]
# MITRE technique names a rubric may use, to their IDs (public ATT&CK names; a phrase may name several)
ATTACK_NAMES = [
    (r"benign|\bnone\b", ["none"]),
    (r"ingress", ["T1105"]),
    (r"deobfuscat|decod", ["T1140"]),
    (r"exfiltrat", ["T1041"]),
    (r"scheduled[- ]task|schedul", ["T1053", "T1053.005", "T1053.003"]),
    (r"cron", ["T1053.003"]),
    (r"encrypt\w* ?(?:file|for)?\s*impact|impact", ["T1486"]),
    (r"command and scripting interpreter", ["LANG", "T1059"]),
    (r"obfuscated", ["T1027"]),
    (r"registry run|run keys?", ["T1547.001"]),
    (r"autostart|logon", ["T1547"]),
    (r"system service|create or modify system process", ["T1543"]),
    (r"application layer|web protocol", ["T1071.001"]),
    (r"system information discovery", ["T1082"]),
    (r"archive", ["T1560"]),
    (r"local system", ["T1005"]),
    (r"masquerad", ["T1036"]),
]


def attack_ids_of(phrase):
    out = []
    low = phrase.lower()
    for rx, ids in ATTACK_NAMES:
        if re.search(rx, low):
            out += [i for i in ids if i not in out]
    return out


def rubric_clauses(text):
    """[(trigger step tokens, ids, terminal?, sequence?)] from 'A is B' / 'A followed by B is C' / 'terminal A or B makes ... C'."""
    out = []
    body = text.split(":", 1)[1] if ":" in text[:200] else text
    for clause in re.split(r";|\.\s|,\s(?=(?:and\s+)?[a-z]+_[a-z_]+ (?:is|or|followed)\b)", body):
        clause = re.sub(r"^(?:and|otherwise)\s+", "", clause.strip())
        m = re.match(r"(?:otherwise\s+)?(?:a\s+)?(terminal\s+)?(.+?)\s+(?:is|are|makes)\s+(.+)$", clause)
        if not m:
            continue
        trig = re.findall(r"\b[a-z]+_[a-z_]+\b", m.group(2))
        if not trig:
            continue
        phrase = re.split(r"\beven when\b|\bunless\b|\bexcept\b", m.group(3))[0]
        ids = attack_ids_of(re.sub(r"\b[a-z]+_[a-z_]+\b", " ", phrase))
        if not ids:
            continue
        seq = None
        if "followed by" in m.group(2):
            left, right = m.group(2).split("followed by", 1)
            seq = (re.findall(r"\b[a-z]+_[a-z_]+\b", left), re.findall(r"\b[a-z]+_[a-z_]+\b", right))
        out.append((trig, ids, bool(m.group(1)), seq))
    return out


def graph_steps(spec, env, members):
    for name in members[:2]:
        for depth, how, t in env.decoded(name).texts:
            for k, v in kv_pairs(t):
                if toks(k) and toks(k)[-1] in ("steps", "graph", "behavior", "behaviour") and isinstance(v, str) and "_" in v:
                    return [x.strip() for x in re.split(r"[,>]", v) if x.strip()]
    return []


def expert_attack(spec, env, pool, members):
    if spec.form != "attack" and "att&ck" not in spec.low:
        return
    ck = ("attack_text", tuple(members[:2]))
    if ck not in env._facts:   # the members' text and its word counts, read once per member set (a Mastery asks many)
        text = ""
        for name in members[:2]:
            text += env.decoded(name).all_text()[:300000].lower()
        env._facts[ck] = (text, [len(re.findall(rx, text)) for _, _, rx in ATTACK_WORDS])
    text, counts = env._facts[ck]
    ext = Path(spec.member or "").suffix.lower()
    lang_sub = ATTACK_SUB.get(ext)
    words = {}
    for (nm, code, rx), n in zip(ATTACK_WORDS, counts):
        words[code] = n          # counted once (the rubric below reads the same counts)
        pool.add(f"attack_words:{nm}", code, 4 + min(n, 8) * 0.5)
    if lang_sub:
        pool.add("attack:language_sub", lang_sub, 8)
    pool.add("attack:command_interpreter", "T1059", 7.5)
    if "none" in spec.low:
        pool.add("attack:benign_none", "none", 7)
    for code in re.findall(r"\bt\d{4}(?:\.\d{3})?\b", text):
        pool.add("attack:stated", code.upper(), 30)
    steps = graph_steps(spec, env, members)
    clauses = rubric_clauses(spec.text)
    if not steps or not clauses:
        return
    n = len(clauses)
    for ci, (trig, ids, terminal, seq) in enumerate(clauses):
        if terminal:
            hit = steps[-1] in trig
        elif seq:
            lp = [steps.index(t) for t in seq[0] if t in steps]
            rp = [steps.index(t) for t in seq[1] if t in steps]
            hit = bool(lp and rp and min(lp) < max(rp))
        else:
            hit = any(t in steps for t in trig)
        if not hit:
            continue
        sc = 40 - 2.0 * ci + (6 if terminal else 0) + (2 if seq else 0)
        for k, i in enumerate(ids):
            if i == "LANG":
                if lang_sub:
                    pool.add(f"rubric:{ci}:language_sub", lang_sub, sc + 3)
                continue
            pool.add(f"rubric:{ci}:{k}", i, sc - 0.6 * k + 0.8 * min(words.get(i, 0), 3))


# ---------------------------------------------------------------------------------------------------------
# binary facts


def macho_facts(b):
    f = {}
    magic = b[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca") and len(b) > 8:
        n = struct.unpack(">I", b[4:8])[0]
        if 0 < n < 30:
            cpus, subs = [], []
            for i in range(n):
                off = 8 + 20 * i
                ct, st, o, sz, al = struct.unpack(">IIIII", b[off:off + 20])
                cpus.append(ct)
                subs.append(st)
            f["macho.fat.nfat_arch"] = n
            f["macho.cpu_type_set"] = ["0x%08x" % c for c in cpus]
            f["macho.cpu_types"] = cpus
            f["macho.cpu_subtypes"] = subs
            f["macho.cpu_type_set_sorted"] = ["0x%08x" % c for c in sorted(set(cpus))]
            return f
    for m, end in ((b"\xcf\xfa\xed\xfe", "<"), (b"\xce\xfa\xed\xfe", "<"), (b"\xfe\xed\xfa\xcf", ">"), (b"\xfe\xed\xfa\xce", ">")):
        if magic == m:
            ct, st, ft, ncmds, sizeofcmds, flags = struct.unpack(end + "iiIIII", b[4:28])
            f.update({"macho.cpu_type": ct & 0xffffffff, "macho.cpu_subtype": st & 0xffffffff, "macho.filetype": ft,
                      "macho.ncmds": ncmds, "macho.sizeofcmds": sizeofcmds, "macho.flags": flags,
                      "macho.cpu_type_set": ["0x%08x" % (ct & 0xffffffff)]})
    return f


def pe_facts(b):
    f = {}
    if b[:2] != b"MZ":
        return f
    try:
        import pefile
        pe = pefile.PE(data=b, fast_load=True)
    except Exception:
        return f
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    for k in ("Machine", "NumberOfSections", "TimeDateStamp", "PointerToSymbolTable", "NumberOfSymbols",
              "SizeOfOptionalHeader", "Characteristics"):
        f[f"pe.coff_{k}"] = getattr(fh, k, None)
    for k in dir(oh):
        if k[:1].isupper() and not k.startswith("DATA"):
            v = getattr(oh, k, None)
            if isinstance(v, int):
                f[f"pe.optional_{k}"] = v
    f["pe.address_of_entry_point_rva"] = oh.AddressOfEntryPoint
    f["pe.linker_version_dotted"] = f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}"
    f["pe.os_version_dotted"] = f"{oh.MajorOperatingSystemVersion}.{oh.MinorOperatingSystemVersion}"
    f["pe.subsystem_version_dotted"] = f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}"
    f["pe.image_version_dotted"] = f"{oh.MajorImageVersion}.{oh.MinorImageVersion}"
    f["pe.magic"] = oh.Magic
    f["pe.section_names"] = [s.Name.rstrip(b"\x00").decode("latin-1") for s in pe.sections]
    for s in pe.sections:
        n = s.Name.rstrip(b"\x00").decode("latin-1")
        f[f"pe.section{n}.virtual_size"] = s.Misc_VirtualSize
        f[f"pe.section{n}.raw_size"] = s.SizeOfRawData
        f[f"pe.section{n}.characteristics"] = s.Characteristics
    try:
        pe.parse_data_directories()
    except Exception:
        pass
    imps = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    if imps:
        dlls = [i.dll.decode("latin-1") for i in imps]
        f["pe.import_dll_names"] = dlls
        f["pe.first_import_descriptor_dll_name"] = dlls[0]
        f["pe.import_functions_first_dll"] = [x.name.decode("latin-1") for x in imps[0].imports if x.name]
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp:
        try:
            f["pe.export_names"] = [s.name.decode("latin-1") for s in exp.symbols if s.name]
            f["pe.export_dll_name"] = exp.name.decode("latin-1") if exp.name else None
        except Exception:
            pass
    for fi in getattr(pe, "FileInfo", []) or []:
        for e in fi:
            for st in getattr(e, "StringTable", []) or []:
                for k, v in st.entries.items():
                    f["pe.version_" + k.decode("latin-1")] = v.decode("latin-1", "ignore")
    if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
        ff = pe.VS_FIXEDFILEINFO[0]
        f["pe.fixed_file_version"] = "%d.%d.%d.%d" % (ff.FileVersionMS >> 16, ff.FileVersionMS & 0xffff, ff.FileVersionLS >> 16, ff.FileVersionLS & 0xffff)
        f["pe.fixed_product_version"] = "%d.%d.%d.%d" % (ff.ProductVersionMS >> 16, ff.ProductVersionMS & 0xffff, ff.ProductVersionLS >> 16, ff.ProductVersionLS & 0xffff)
    dbg = getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []
    for d in dbg:
        e = getattr(d, "entry", None)
        if e is not None and hasattr(e, "PdbFileName"):
            f["pe.debug_pdb_path"] = e.PdbFileName.rstrip(b"\x00").decode("latin-1")
            if hasattr(e, "Signature_String"):
                f["pe.debug_pdb_guid"] = e.Signature_String
            f["pe.debug_pdb_age"] = getattr(e, "Age", None)
    f.update(dotnet_facts(b))
    return f


def dotnet_facts(b):
    f = {}
    try:
        import dnfile
        dn = dnfile.dnPE(data=b)
    except Exception:
        return f
    try:
        net = dn.net
        if net is None:
            return f
        md = net.metadata
        f["dotnet.runtime_version"] = md.struct.Version.rstrip(b"\x00").decode("latin-1") if hasattr(md.struct, "Version") else None
        mod = net.mdtables.Module.rows[0] if net.mdtables.Module else None
        if mod is not None:
            mv = mod.Mvid
            g = getattr(mv, "value", mv)
            if isinstance(g, (bytes, bytearray)) and len(g) == 16:
                import uuid
                f["dotnet.mvid_guid"] = str(uuid.UUID(bytes_le=bytes(g)))
            else:
                f["dotnet.mvid_guid"] = str(g)
            f["dotnet.module_name"] = str(mod.Name)
        asm = net.mdtables.Assembly.rows[0] if net.mdtables.Assembly else None
        if asm is not None:
            f["dotnet.assembly_name"] = str(asm.Name)
            f["dotnet.assembly_version"] = f"{asm.MajorVersion}.{asm.MinorVersion}.{asm.BuildNumber}.{asm.RevisionNumber}"
            f["dotnet.assembly_culture"] = str(asm.Culture) if asm.Culture else "none"
        if net.mdtables.TypeDef:
            f["dotnet.type_names"] = [str(r.TypeName) for r in net.mdtables.TypeDef.rows]
            f["dotnet.type_namespaces"] = sorted({str(r.TypeNamespace) for r in net.mdtables.TypeDef.rows if str(r.TypeNamespace)})
        if net.mdtables.MethodDef:
            f["dotnet.method_names"] = [str(r.Name) for r in net.mdtables.MethodDef.rows]
        if net.mdtables.AssemblyRef:
            f["dotnet.assembly_refs"] = [str(r.Name) for r in net.mdtables.AssemblyRef.rows]
        f["dotnet.flags"] = int(net.struct.Flags) if hasattr(net.struct, "Flags") else None
    except Exception:
        pass
    return f


def elf_facts(b):
    f = {}
    if b[:4] != b"\x7fELF":
        return f
    try:
        from elftools.elf.elffile import ELFFile
        e = ELFFile(io.BytesIO(b))
    except Exception:
        return f
    h = e.header
    f["elf.class"] = e.elfclass
    f["elf.endianness"] = "little" if e.little_endian else "big"
    from elftools.elf.descriptions import describe_e_machine
    mach = h["e_machine"]
    try:
        from elftools.elf.enums import ENUM_E_MACHINE
        f["elf.e_machine"] = ENUM_E_MACHINE.get(mach, mach) if isinstance(mach, str) else mach
    except Exception:
        f["elf.e_machine"] = mach
    f["elf.e_machine_name"] = mach
    for k in ("e_type", "e_entry", "e_phoff", "e_shoff", "e_flags", "e_ehsize", "e_phentsize", "e_phnum",
              "e_shentsize", "e_shnum", "e_shstrndx", "e_version"):
        v = h[k]
        f[f"elf.{k}"] = v
    f["elf.e_ident_osabi"] = h["e_ident"]["EI_OSABI"]
    f["elf.section_names"] = [s.name for s in e.iter_sections()]
    try:
        f["elf.segment_types"] = [s["p_type"] for s in e.iter_segments()]
    except Exception:
        pass
    for s in e.iter_sections():
        if s.name == ".interp":
            f["elf.interpreter"] = s.data().rstrip(b"\x00").decode("latin-1")
        if s.name == ".comment":
            f["elf.comment"] = [x.decode("latin-1") for x in s.data().split(b"\x00") if x]
        if s["sh_type"] == "SHT_NOTE" and "build" in s.name:
            try:
                for n in s.iter_notes():
                    if n["n_type"] == "NT_GNU_BUILD_ID":
                        f["elf.build_id"] = n["n_desc"]
            except Exception:
                pass
    try:
        dyn = e.get_section_by_name(".dynamic")
        if dyn is not None:
            f["elf.needed"] = [t.needed for t in dyn.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
            sn = [t.soname for t in dyn.iter_tags() if t.entry.d_tag == "DT_SONAME"]
            if sn:
                f["elf.soname"] = sn[0]
    except Exception:
        pass
    f["elf.stripped"] = "false" if e.get_section_by_name(".symtab") is not None else "true"
    return f


def class_facts(b):
    """A Java class file: version, access flags, names, fields and methods in order."""
    f = {}
    if b[:4] != b"\xca\xfe\xba\xbe" or len(b) < 10:
        return f
    try:
        minor, major, cpn = struct.unpack(">HHH", b[4:10])
        if major < 45 or major > 80:
            return f
        pos, cp, i = 10, [None] * cpn, 1
        while i < cpn:
            tag = b[pos]
            if tag == 1:
                ln = struct.unpack(">H", b[pos + 1:pos + 3])[0]
                cp[i] = ("utf8", b[pos + 3:pos + 3 + ln].decode("utf-8", "replace"))
                pos += 3 + ln
            elif tag in (3, 4):
                cp[i] = ("int", struct.unpack(">i", b[pos + 1:pos + 5])[0])
                pos += 5
            elif tag in (5, 6):
                cp[i] = ("long", struct.unpack(">q", b[pos + 1:pos + 9])[0])
                pos += 9
                i += 1
            elif tag in (7, 8, 16, 19, 20):
                cp[i] = ("ref", struct.unpack(">H", b[pos + 1:pos + 3])[0], tag)
                pos += 3
            elif tag in (9, 10, 11, 12, 17, 18):
                cp[i] = ("ref2", struct.unpack(">HH", b[pos + 1:pos + 5]), tag)
                pos += 5
            elif tag == 15:
                pos += 4
            else:
                return f
            i += 1

        def utf(ix):
            e = cp[ix] if 0 < ix < cpn else None
            return e[1] if e and e[0] == "utf8" else None

        def cls(ix):
            e = cp[ix] if 0 < ix < cpn else None
            return utf(e[1]) if e and e[0] == "ref" else None

        acc, this, sup, ni = struct.unpack(">HHHH", b[pos:pos + 8])
        pos += 8
        ifaces = [cls(struct.unpack(">H", b[pos + 2 * k:pos + 2 * k + 2])[0]) for k in range(ni)]
        pos += 2 * ni

        def members(pos):
            n = struct.unpack(">H", b[pos:pos + 2])[0]
            pos += 2
            out = []
            for _ in range(n):
                a, nm, ds, ac = struct.unpack(">HHHH", b[pos:pos + 8])
                pos += 8
                for _ in range(ac):
                    ln = struct.unpack(">I", b[pos + 2:pos + 6])[0]
                    pos += 6 + ln
                out.append((a, utf(nm), utf(ds)))
            return out, pos

        fields, pos = members(pos)
        methods, pos = members(pos)
        f.update({"class.minor_version": minor, "class.major_version": major, "class.access_flags": acc,
                  "class.this_class": cls(this), "class.super_class": cls(sup), "class.interfaces": ifaces,
                  "class.fields": [n for _, n, _ in fields], "class.field_descriptors": [d for _, _, d in fields],
                  "class.methods": [n for _, n, _ in methods], "class.method_descriptors": [d for _, _, d in methods],
                  "class.method_access_flags": [a for a, _, _ in methods],
                  "class.constant_strings": [cp[e[1]][1] for e in cp if e and e[0] == "ref" and e[2] == 8 and cp[e[1]]]})
        for a, n, d in methods:
            f[f"class.method.{n}.access_flags"] = a
        for a, n, d in fields:
            f[f"class.field.{n}.access_flags"] = a
    except Exception:
        return f
    return f


def wasm_facts(b):
    f = {}
    if b[:4] != b"\x00asm":
        return f
    f["wasm.version"] = struct.unpack("<I", b[4:8])[0]
    names = {0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory", 6: "global", 7: "export",
             8: "start", 9: "element", 10: "code", 11: "data", 12: "datacount"}
    pos, secs, customs, exports = 8, [], [], []

    def uleb(p):
        r, s = 0, 0
        while True:
            c = b[p]
            p += 1
            r |= (c & 0x7f) << s
            s += 7
            if c < 0x80:
                return r, p
    try:
        while pos < len(b):
            sid = b[pos]
            ln, p = uleb(pos + 1)
            secs.append(names.get(sid, str(sid)))
            if sid == 0:
                nl, q = uleb(p)
                customs.append(b[q:q + nl].decode("utf-8", "replace"))
            if sid == 7:
                cnt, q = uleb(p)
                for _ in range(cnt):
                    nl, q = uleb(q)
                    exports.append(b[q:q + nl].decode("utf-8", "replace"))
                    q += nl + 1
                    _, q = uleb(q)
            pos = p + ln
    except Exception:
        pass
    f["wasm.sections"] = secs
    f["wasm.custom_sections"] = customs
    f["wasm.exports"] = exports
    return f


def riff_facts(b):
    f = {}
    if b[:4] != b"RIFF" or len(b) < 12:
        return f
    f["riff.form_type"] = b[8:12].decode("latin-1")
    f["riff.size"] = struct.unpack("<I", b[4:8])[0]
    pos, ids = 12, []
    while pos + 8 <= len(b):
        cid = b[pos:pos + 4].decode("latin-1")
        sz = struct.unpack("<I", b[pos + 4:pos + 8])[0]
        ids.append(cid)
        f[f"riff.{cid.strip()}_chunk_size"] = sz
        if cid == "fmt ":
            tag, ch, rate, bps, align, bits = struct.unpack("<HHIIHH", b[pos + 8:pos + 24])
            f.update({"riff.fmt_audio_format": tag, "riff.fmt_channels": ch, "riff.fmt_sample_rate_hz": rate,
                      "riff.fmt_byte_rate": bps, "riff.fmt_block_align_bytes": align, "riff.fmt_bits_per_sample": bits})
            if tag == 1:
                f["media.audio_codec_name"] = ("pcm_u8" if bits == 8 else f"pcm_s{bits}le")
            elif tag == 3:
                f["media.audio_codec_name"] = f"pcm_f{bits}le"
            elif tag == 6:
                f["media.audio_codec_name"] = "pcm_alaw"
            elif tag == 7:
                f["media.audio_codec_name"] = "pcm_mulaw"
            if rate and bps:
                pass
        if cid == "data":
            f["riff.data_chunk_size_bytes"] = sz
            if f.get("riff.fmt_byte_rate"):
                f["media.duration_seconds"] = round(sz / f["riff.fmt_byte_rate"], 3)
        pos += 8 + sz + (sz & 1)
    f["riff.chunk_ids_in_order"] = ids
    return f


def mp4_facts(b):
    f = {}
    if b[4:8] != b"ftyp":
        return f
    f["mp4.major_brand"] = b[8:12].decode("latin-1")
    dims, handlers, codecs_ = [], [], []

    def walk(p, end, depth):
        while p + 8 <= end and depth < 8:
            sz, typ = struct.unpack(">I4s", b[p:p + 8])
            hdr = 8
            if sz == 1:
                sz = struct.unpack(">Q", b[p + 8:p + 16])[0]
                hdr = 16
            if sz < 8 or p + sz > end:
                return
            t = typ.decode("latin-1")
            if t in ("moov", "trak", "mdia", "minf", "stbl", "udta", "edts"):
                walk(p + hdr, p + sz, depth + 1)
            elif t == "tkhd":
                v = b[p + 8]
                o = p + 8 + (88 if v == 1 else 76)
                w, h = struct.unpack(">II", b[o:o + 8])
                if w or h:
                    dims.append((w >> 16, h >> 16))
            elif t == "hdlr":
                handlers.append(b[p + 16:p + 20].decode("latin-1"))
            elif t == "stsd":
                codecs_.append(b[p + 20:p + 24].decode("latin-1"))
            elif t == "mvhd":
                v = b[p + 8]
                if v == 0:
                    ts, dur = struct.unpack(">II", b[p + 20:p + 28])
                    f["mp4.timescale"], f["mp4.duration"] = ts, dur
                    if ts:
                        f["media.duration_seconds"] = round(dur / ts, 3)
            p += sz
    try:
        walk(0, len(b), 0)
    except Exception:
        pass
    if dims:
        f["media.video_dimensions"] = "%dx%d" % dims[0]
        f["media.video_width"], f["media.video_height"] = dims[0]
    f["mp4.handlers"] = handlers
    f["mp4.sample_entries"] = codecs_
    if codecs_:
        f["media.video_codec_fourcc"] = codecs_[0]
    return f


def jpeg_facts(b):
    f = {}
    if b[:2] != b"\xff\xd8":
        return f
    pos, markers = 2, ["0xffd8"]
    while pos + 4 <= len(b) and b[pos] == 0xff:
        m = b[pos + 1]
        markers.append("0xff%02x" % m)
        if m == 0xda:
            break
        ln = struct.unpack(">H", b[pos + 2:pos + 4])[0]
        if m in (0xc0, 0xc1, 0xc2):
            p, h, w = struct.unpack(">BHH", b[pos + 4:pos + 9])
            f["jpeg.width"], f["jpeg.height"], f["jpeg.precision"] = w, h, p
            f["media.dimensions"] = f"{w}x{h}"
        pos += 2 + ln
    f["jpeg.marker_codes_before_sos"] = markers
    f["jpeg.marker_codes_upper"] = [m.upper().replace("0X", "0x") for m in markers]
    f["jpeg.marker_names"] = markers
    return f


def eml_facts(b):
    f = {}
    if not re.match(rb"(?i)(received|from|return-path|message-id|mime-version|date|subject|to|delivered-to|x-[\w-]+):", b[:200]):
        return f
    import email
    from email import policy
    try:
        msg = email.message_from_bytes(b, policy=policy.compat32)
    except Exception:
        return f
    for k, v in msg.items():
        f[f"email.{k.lower()}"] = str(v)
        f[f"email.{k.lower()}_header_text"] = str(v)
    try:
        from email.header import decode_header, make_header
        if msg.get("Subject"):
            f["email.subject_decoded"] = str(make_header(decode_header(msg["Subject"])))
    except Exception:
        pass
    parts = []
    for p in msg.walk():
        parts.append(p.get_content_type())
        fn = p.get_filename()
        if fn:
            f.setdefault("email.attachment_filenames", []).append(fn)
    f["email.part_content_types"] = parts
    return f


def zip_facts(b):
    f = {}
    if b[:2] != b"PK":
        return f
    import zipfile
    try:
        z = zipfile.ZipFile(io.BytesIO(b))
    except Exception:
        return f
    names = z.namelist()
    f["zip.member_names"] = names
    f["zip.member_count"] = len(names)
    for n in names:
        if n.endswith(".rels") or n in ("docProps/core.xml", "docProps/app.xml", "[Content_Types].xml"):
            try:
                x = z.read(n).decode("utf-8", "replace")
            except Exception:
                continue
            if n == "docProps/core.xml" or n == "docProps/app.xml":
                for m in re.finditer(r"<(?:\w+:)?(\w+)[^>]*>([^<]{1,500})</", x):
                    tag = m.group(1)
                    ns = "core" if "core" in n else "app"
                    f[f"ooxml.{ns}_{tag}"] = m.group(2)
                    f[f"ooxml.{ns}_{tag}_text"] = m.group(2)
            if n.endswith(".rels"):
                ext = re.findall(r"<Relationship\b[^>]*>", x)
                for r in ext:
                    if 'TargetMode="External"' in r:
                        t = re.search(r'Target="([^"]*)"', r)
                        if t:
                            f.setdefault("ooxml.external_relationship_targets", []).append(t.group(1).replace("&amp;", "&"))
                    ty = re.search(r'Type="([^"]*)"', r)
                    if ty:
                        f.setdefault("ooxml.relationship_types", []).append(ty.group(1).rsplit("/", 1)[-1])
    if "ooxml.external_relationship_targets" in f:
        f["ooxml.external_relationship_targets_sorted"] = sorted(f["ooxml.external_relationship_targets"])
    return f


def lnk_facts(b):
    f = {}
    if b[:4] != b"\x4c\x00\x00\x00":
        return f
    try:
        flags = struct.unpack("<I", b[20:24])[0]
        f["lnk.link_flags"] = flags
        f["lnk.file_attributes"] = struct.unpack("<I", b[24:28])[0]
        f["lnk.file_size"] = struct.unpack("<I", b[52:56])[0]
        f["lnk.show_command"] = struct.unpack("<I", b[60:64])[0]
        pos = 76
        if flags & 1:
            n = struct.unpack("<H", b[pos:pos + 2])[0]
            pos += 2 + n
        if flags & 2:
            ln = struct.unpack("<I", b[pos:pos + 4])[0]
            li = b[pos:pos + ln]
            hs, lflags, vid, lbp, cnr, cps = struct.unpack("<IIIIII", li[4:28])
            if lflags & 1 and lbp:
                base = li[lbp:li.index(b"\x00", lbp)].decode("latin-1")
                suffix = li[cps:li.index(b"\x00", cps)].decode("latin-1") if cps else ""
                f["lnk.local_base_path"] = base
                f["lnk.target_path_windows"] = base + suffix
            pos += ln
        names = ["name", "relative_path", "working_dir", "arguments", "icon_location"]
        unicode = bool(flags & 0x80)
        for bit, nm in zip((4, 8, 16, 32, 64), names):
            if flags & bit:
                n = struct.unpack("<H", b[pos:pos + 2])[0]
                if unicode:
                    s = b[pos + 2:pos + 2 + 2 * n].decode("utf-16-le", "replace")
                    pos += 2 + 2 * n
                else:
                    s = b[pos + 2:pos + 2 + n].decode("latin-1")
                    pos += 2 + n
                f[f"lnk.{nm}"] = s
    except Exception:
        pass
    return f


def gif_png_facts(b):
    f = {}
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        w, h = struct.unpack(">II", b[16:24])
        f.update({"png.width": w, "png.height": h, "media.dimensions": f"{w}x{h}", "png.bit_depth": b[24], "png.color_type": b[25]})
        pos, chunks, texts = 8, [], []
        while pos + 8 <= len(b):
            ln, t = struct.unpack(">I4s", b[pos:pos + 8])
            chunks.append(t.decode("latin-1"))
            if t in (b"tEXt", b"iTXt", b"zTXt"):
                texts.append(b[pos + 8:pos + 8 + ln].split(b"\x00")[0].decode("latin-1"))
            pos += 12 + ln
        f["png.chunk_types_in_order"] = chunks
        f["png.text_keywords"] = texts
    return f


ARCH_NAMES = {   # machine -> architecture spellings, best first
    "EM_X86_64": ["x86-64", "x86_64", "amd64", "x64"], "EM_386": ["x86", "i386", "i686"],
    "EM_AARCH64": ["aarch64", "arm64"], "EM_ARM": ["arm", "armv7"], "EM_RISCV": ["riscv64", "riscv"],
    "EM_MIPS": ["mips"], "EM_PPC64": ["ppc64", "powerpc64"], "EM_PPC": ["ppc", "powerpc"], "EM_S390": ["s390x"],
    0x8664: ["x86-64", "x86_64", "amd64", "x64"], 0x14c: ["x86", "i386"], 0xaa64: ["arm64", "aarch64"],
    0x1c4: ["arm", "armnt"], 0x5064: ["riscv64"],
    0x01000007: ["x86-64", "x86_64"], 7: ["x86", "i386"], 0x0100000c: ["arm64", "aarch64"], 12: ["arm"],
}


def kind_facts(b):
    """The container format and the architecture, in the spellings a question may ask for."""
    f = {}
    fmt, arch = None, None
    if b[:4] == b"\x7fELF":
        fmt = ["elf", "elf64" if b[4] == 2 else "elf32"]
        try:
            from elftools.elf.elffile import ELFFile
            arch = ARCH_NAMES.get(ELFFile(io.BytesIO(b)).header["e_machine"])
        except Exception:
            pass
    elif b[:2] == b"MZ":
        fmt = ["pe", "pe32+" if b"PE\x00\x00" in b[:1024] and b"\x0b\x02" in b[:1024] else "pe32"]
        try:
            import pefile
            pe = pefile.PE(data=b, fast_load=True)
            arch = ARCH_NAMES.get(pe.FILE_HEADER.Machine)
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress:
                fmt.insert(1, "pe_cli")
        except Exception:
            pass
    elif b[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        fmt = ["macho", "mach-o", "mach_o"]
        arch = ARCH_NAMES.get(struct.unpack("<I", b[4:8])[0])
    elif b[:4] == b"\xca\xfe\xba\xbe" and len(b) > 8 and struct.unpack(">I", b[4:8])[0] < 30:
        fmt = ["macho_fat", "fat", "universal"]
    elif b[:4] == b"\xca\xfe\xba\xbe":
        fmt, arch = ["class", "java_class", "jvm"], ["jvm"]
    elif b[:4] == b"\x00asm":
        fmt, arch = ["wasm", "webassembly"], ["wasm32", "wasm"]
    elif b[:4] == b"dex\n":
        fmt, arch = ["dex"], ["dalvik"]
    elif b[:2] == b"PK":
        fmt = ["zip", "jar"]
    for i, x in enumerate(fmt or []):
        f["kind.format" + ("" if not i else "_alt%d" % i)] = x
    for i, x in enumerate(arch or []):
        f["kind.architecture" + ("" if not i else "_alt%d" % i)] = x
    return f


def snake(s):
    return "_".join(toks(s))


def exif_facts(b):
    """EXIF / TIFF tags (exifread) and the image header (PIL) of a JPEG, TIFF, PNG, GIF, BMP or WebP."""
    f = {}
    if not (b[:2] == b"\xff\xd8" or b[:4] in (b"II*\x00", b"MM\x00*") or b[:8] == b"\x89PNG\r\n\x1a\n"
            or b[:3] == b"GIF" or b[:2] == b"BM" or (b[:4] == b"RIFF" and b[8:12] == b"WEBP")):
        return f
    try:
        import exifread
        tags = exifread.process_file(io.BytesIO(b), details=False)
        for k, v in tags.items():
            grp, _, name = k.partition(" ")
            f[f"exif.{snake(name or grp)}"] = str(v)
            f[f"exif.{snake(grp)}_{snake(name)}"] = str(v)
    except Exception:
        pass
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(b))
        f["image.format"] = im.format
        f["image.mode"] = im.mode
        f["image.width"], f["image.height"] = im.size
        f["image.dimensions"] = "%dx%d" % im.size
        for k, v in (im.info or {}).items():
            if isinstance(v, (str, int, float)):
                f[f"image.info_{snake(str(k))}"] = v
            elif isinstance(v, tuple) and all(isinstance(x, (int, float)) for x in v):
                f[f"image.info_{snake(str(k))}"] = list(v)
        if b[:3] == b"GIF":
            f["gif.version"] = b[3:6].decode("latin-1")
            f["gif.frame_count"] = getattr(im, "n_frames", 1)
    except Exception:
        pass
    return f


def pdf_facts(b):
    f = {}
    if b[:5] != b"%PDF-":
        return f
    f["pdf.version"] = b[5:8].decode("latin-1")
    try:
        import pypdf
        r = pypdf.PdfReader(io.BytesIO(b))
        f["pdf.page_count"] = len(r.pages)
        f["pdf.encrypted"] = "true" if r.is_encrypted else "false"
        for k, v in (r.metadata or {}).items():
            f[f"pdf.info_{snake(str(k).lstrip('/'))}"] = str(v)
        try:
            box = r.pages[0].mediabox
            f["pdf.page_size"] = "%gx%g" % (float(box.width), float(box.height))
        except Exception:
            pass
    except Exception:
        pass
    return f


def ole_facts(b):
    f = {}
    if b[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return f
    try:
        import olefile
        o = olefile.OleFileIO(io.BytesIO(b))
        f["ole.streams"] = ["/".join(x) for x in o.listdir()]
        m = o.get_metadata()
        for attr in m.SUMMARY_ATTRIBS + m.DOCSUM_ATTRIBS:
            v = getattr(m, attr, None)
            if v not in (None, b"", ""):
                f[f"ole.{snake(attr)}"] = v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v)
    except Exception:
        pass
    return f


def misc_facts(b):
    """gzip, plist, SQLite and tar headers."""
    f = {}
    if b[:2] == b"\x1f\x8b" and len(b) >= 10:
        flg = b[3]
        f.update({"gzip.method": b[2], "gzip.flags": flg, "gzip.mtime": struct.unpack("<I", b[4:8])[0],
                  "gzip.os": b[9]})
        if flg & 8:
            end = b.find(b"\x00", 10 + (2 + struct.unpack("<H", b[10:12])[0] if flg & 4 else 0))
            start = 10 + (2 + struct.unpack("<H", b[10:12])[0] if flg & 4 else 0)
            f["gzip.original_filename"] = b[start:end].decode("latin-1")
    if b[:6] == b"bplist" or (b[:5] == b"<?xml" and b"<plist" in b[:400]):
        try:
            import plistlib
            obj = plistlib.loads(b)
            for k, v in flatten_json(obj if isinstance(obj, (dict, list)) else {"value": obj}):
                if isinstance(v, (str, int, float, bool)):
                    f[f"plist.{k}"] = v if not isinstance(v, bool) else ("true" if v else "false")
        except Exception:
            pass
    if b[:16] == b"SQLite format 3\x00":
        f["sqlite.page_size"] = struct.unpack(">H", b[16:18])[0]
        f["sqlite.page_count"] = struct.unpack(">I", b[28:32])[0]
        f["sqlite.text_encoding"] = struct.unpack(">I", b[56:60])[0]
        f["sqlite.user_version"] = struct.unpack(">I", b[60:64])[0]
        f["sqlite.application_id"] = struct.unpack(">I", b[68:72])[0]
        f["sqlite.tables"] = re.findall(rb"CREATE TABLE \"?(\w+)", b[:1 << 20]) and [
            x.decode() for x in re.findall(rb"CREATE TABLE \"?(\w+)", b[:1 << 20])]
    if len(b) > 262 and b[257:262] == b"ustar":
        import tarfile
        try:
            t = tarfile.open(fileobj=io.BytesIO(b))
            f["tar.member_names"] = t.getnames()
            f["tar.member_count"] = len(f["tar.member_names"])
        except Exception:
            pass
    return f


def macho_more_facts(b):
    """Load commands, segments, UUID of a thin Mach-O (lief)."""
    f = {}
    if b[:4] not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return f
    try:
        import lief
        fat = lief.MachO.parse(list(b))
        m = fat.at(0)
        f["macho.load_commands"] = [str(c.command).split(".")[-1] for c in m.commands]
        f["macho.segment_names"] = [sg.name for sg in m.segments]
        f["macho.section_names"] = [sc.name for sc in m.sections]
        f["macho.libraries"] = [lb.name for lb in m.libraries]
        if m.has_uuid:
            import uuid
            f["macho.uuid"] = str(uuid.UUID(bytes=bytes(m.uuid.uuid))).upper()
        if m.has_entrypoint:
            f["macho.entrypoint"] = m.entrypoint
    except Exception:
        pass
    return f


def derived_facts(f):
    """Counts, first and last items, sorted and joined forms of every list fact; lower/upper of short strings."""
    out = {}
    for k, v in list(f.items()):
        if isinstance(v, list) and v and all(isinstance(x, (str, int)) for x in v):
            out[f"{k}_count"] = len(v)
            out[f"{k}_first"] = v[0]
            out[f"{k}_last"] = v[-1]
            out[f"{k}_unique_count"] = len(set(v))
            try:
                out[f"{k}_sorted"] = sorted(v)
            except TypeError:
                pass
            if all(isinstance(x, str) for x in v):
                out[f"{k}_joined"] = ",".join(v)
    return out


FACT_READERS = (kind_facts, pe_facts, elf_facts, macho_facts, macho_more_facts, class_facts, wasm_facts, riff_facts,
                mp4_facts, jpeg_facts, exif_facts, eml_facts, lnk_facts, gif_png_facts, zip_facts, pdf_facts, ole_facts,
                misc_facts)


def facts_of(env, name):
    if name in env._facts:
        return env._facts[name]
    b = env.member_bytes(name) or b""
    f = {}
    for r in FACT_READERS:
        if env.time_left() <= 0:
            break
        try:
            got = r(b)
        except Exception:
            got = {}
        f.update({k: v for k, v in got.items() if v is not None})
    f.update({k: v for k, v in derived_facts(f).items() if k not in f})
    f["file.size_bytes"] = len(b)
    f["file.sha256"] = hashlib.sha256(b).hexdigest()
    f["file.md5"] = hashlib.md5(b).hexdigest()
    f["file.sha1"] = hashlib.sha1(b).hexdigest()
    f["file.crc32"] = "0x%08x" % (zlib.crc32(b) & 0xffffffff)
    env._facts[name] = f
    return f


def fact_score(key, spec):
    kt = set(toks(key.replace(".", "_")))
    ft = [t for t in spec.field_toks if t not in ("hex", "text", "u16", "u32", "u64", "dotted", "in", "order", "bytes", "hz", "rva")]
    ftset = set(ft)
    nt = set(spec.noun_toks)
    if not kt:
        return 0
    s = 4.0 * len(kt & ftset) + 1.0 * len(kt & nt)
    if ft and ftset <= kt:
        s += 6
    head = ft[-1] if ft else None
    if head and head not in ("name", "names", "value", "id"):
        s += 5 if head in kt else -4
    s -= 0.7 * len(kt - ftset - nt)
    # the namespace of a metadata property ("pe.", "elf.") must agree
    ns = spec.field.split("_")[0] if "." not in spec.field else spec.field.split(".")[0]
    if ns and key.split(".")[0] == ns:
        s += 2
    return s


HASH_WORDS = {"sha256", "sha1", "md5", "crc32", "size", "length", "bytes", "digest", "hash"}


def expert_facts(spec, env, pool, members):
    want_file = bool(HASH_WORDS & set(spec.noun_toks + spec.field_toks))
    for mi, name in enumerate(members[:8]):
        if env.time_left() <= 0:
            return
        pool.where = f"member {name}"
        facts = facts_of(env, name)
        scored = sorted(((fact_score(k, spec), k, v) for k, v in facts.items()
                         if want_file or not k.startswith("file.")), key=lambda r: -r[0])
        for sc, k, v in scored[:30]:
            if sc <= 0:
                break
            # a whole-file digest or size is asked by name ("full-file SHA-256"), rarely by a field's word alone
            whole = k.startswith("file.") and not re.search(r"full[- ]file|whole[- ]file|file size|of the (?:file|member)", spec.low)
            pool.add(f"fact:{k}", v, 12 + sc - 0.5 * mi - (6 if whole else 0))


# ---------------------------------------------------------------------------------------------------------
# symbols


def elf_symbols(b):
    out = []
    if b[:4] != b"\x7fELF":
        return out
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        e = ELFFile(io.BytesIO(b))
        for s in e.iter_sections():
            if isinstance(s, SymbolTableSection):
                for sym in s.iter_symbols():
                    if sym.name:
                        out.append((s.name, sym.name, sym["st_info"]["type"], sym["st_value"], sym["st_size"]))
    except Exception:
        pass
    return out


def pe_coff_symbols(b):
    out = []
    if b[:2] != b"MZ":
        return out
    try:
        import pefile
        pe = pefile.PE(data=b, fast_load=True)
        ptr, n = pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols
        if not ptr or not n:
            return out
        strtab = ptr + 18 * n
        i = 0
        while i < n:
            ent = b[ptr + 18 * i:ptr + 18 * i + 18]
            if len(ent) < 18:
                break
            if ent[:4] == b"\x00\x00\x00\x00":
                off = struct.unpack("<I", ent[4:8])[0]
                end = b.index(b"\x00", strtab + off)
                name = b[strtab + off:end].decode("latin-1")
            else:
                name = ent[:8].rstrip(b"\x00").decode("latin-1")
            val, sec, typ, cls, naux = struct.unpack("<IhHBB", ent[8:18])
            out.append(("coff", name, typ, val, sec))
            i += 1 + naux
    except Exception:
        pass
    return out


def symbols_of(env, name):
    if name not in env._syms:
        b = env.member_bytes(name) or b""
        env._syms[name] = elf_symbols(b) + pe_coff_symbols(b)
    return env._syms[name]


def expert_symbols(spec, env, pool, members):
    if not re.search(r"symbol|function|export|import|mangled|typeinfo|vtable", spec.low + " " + spec.field):
        return
    words = [t for t in spec.field_toks if t not in ("symbol", "name", "mangled", "analysis")]
    for mi, name in enumerate(members[:8]):
        pool.where = f"member {name}"
        syms = symbols_of(env, name)
        for si, (sec, nm, typ, val, size) in enumerate(syms):
            low = nm.lower()
            hit = sum(1 for w in words if w in low)
            if "typeinfo" in spec.field_toks and re.match(r"(\.\w+\$)?_ZTI", nm):
                hit += 2
            if "mangled" in spec.field_toks and re.search(r"_Z|\?\?", nm):
                hit += 1
            if not hit:
                continue
            sc = 14 + 3 * hit - 0.01 * si - 0.5 * mi
            pool.add(f"symbol:{sec}", nm, sc)
            bare = re.sub(r"^\.\w+\$", "", nm)
            if bare != nm:
                pool.add("symbol:bare", bare, sc - 0.5)


# ---------------------------------------------------------------------------------------------------------
# stated layouts: members by prefix and number, magic offsets, overlay payload transforms


def members_for(spec, env):
    """The members a question is about: the named member, else `dNN--` members in archive order (with what a
    prefixed archive holds), else every member; those whose names share the field's words first."""
    if spec.member and env.member_bytes(spec.member) is not None:
        return [spec.member]
    ck = ("members", spec.day_prefix, tuple(spec.field_toks), spec.text if not spec.day_prefix else "")
    if ck in env._facts:
        return env._facts[ck]
    plain = env.plain_members()
    top, nested = {}, {}
    if spec.day_prefix:
        pre = spec.day_prefix + "--"
        for k in env.files:
            parts = k.split(" -> ")
            last = parts[-1].rsplit("/", 1)[-1]
            if last.startswith(pre):
                top.setdefault(parts[-1], None)
            elif len(parts) >= 2 and parts[-2].rsplit("/", 1)[-1].startswith(pre) and not k.endswith("/"):
                nested.setdefault(k, None)
    ms = list(top) + list(nested)[:400]
    if not ms:
        ms = [k for k in plain if k in spec.text]
    if not ms:
        deliv = env.ctx.get("delivery_name")
        ms = [k for k in plain if k != deliv] or list(plain)
    words = [t for t in spec.field_toks if len(t) > 2]

    def rank(k):
        nm = k.lower()
        return (-sum(1 for w in words if w in nm), "$" in k)
    out = sorted(ms, key=rank)
    env._facts[ck] = out
    return out


MAGIC_CTX = r"(?:ascii|magic|overlay|record|resource|header|chunk|container|blob|section|marker)"


def magic_words_in(text, ranked=False):
    seen = {}
    for i, m in enumerate(re.finditer(r"\b([A-Z][A-Z0-9]{3})\b", text)):
        w = m.group(1)
        if w in ("ZIP", "ASCII", "CRC32", "UTF8", "JSON", "SHA2", "NULL", "PE32", "TRUE") or w.startswith(("SHA", "ELF", "UTF", "MD5")):
            continue
        near = text[max(0, m.start() - 24):m.end() + 24].lower()
        pri = (2 if re.search(r"overlay|magic", near) else 0) + (1 if re.search(r"\d", w) else 0)
        if pri or re.search(MAGIC_CTX, near):
            seen[w] = max(seen.get(w, 0), pri)
    out = list(seen)
    if ranked:
        out.sort(key=lambda w: -seen[w])
    return out


def magic_words(spec):
    out = magic_words_in(spec.text)
    if not out and re.search(r"\bmagic|overlay\b", spec.low):
        out = magic_words_in(spec.set_text, ranked=True)[:2]   # "the located overlay magic" of a sibling question
    return out


def member_index(spec):
    m = re.search(r"member (\d+)", spec.text)
    return int(m.group(1)) if m else None


def expert_layout(spec, env, pool, members):
    """Offsets of a named magic, the member size after it, fields at stated offsets, and member digests."""
    mags = magic_words(spec)
    idx = member_index(spec)
    if idx and 1 <= idx <= len(members):
        b = env.member_bytes(members[idx - 1]) or b""
        for algo in ("sha256", "sha1", "md5"):
            if algo in spec.low.replace("-", ""):
                pool.add(f"digest:{algo}:member{idx}", hashlib.new(algo, b).hexdigest(), 30)
    if spec.form == "sha256":
        for i, m in enumerate(members[:10]):
            pool.add(f"digest:sha256:m{i + 1}", hashlib.sha256(env.member_bytes(m) or b"").hexdigest(), 12 - i)
    if not mags:
        return
    for mi, name in enumerate(members[:10]):
        pool.where = f"member {name}"
        b = env.member_bytes(name) or b""
        for mag in mags:
            offs = [m.start() for m in re.finditer(re.escape(mag.encode()), b)]
            if not offs:
                continue
            last, first = offs[-1], offs[0]
            if spec.form in ("int", "int_or_none") or spec.form == "hex0x":
                final = "final" in spec.low or "last" in spec.low or "located" in spec.low
                o1, o2 = (last, first) if final else (first, last)
                ft = set(spec.field_toks)
                asked = spec.asked.lower()
                if "size" in ft or "length" in asked or "minus" in asked:
                    sc = 24 + (4 if "minus" in asked else 0) + (1 if "size" in ft else 0)
                    pool.add(f"layout:{mag}:tail_size", len(b) - o1, sc - mi)
                    pool.add(f"layout:{mag}:tail_size_alt", len(b) - o2, sc - 9 - mi)
                if "offset" in ft or "offset" in asked:
                    sc = 25 - (4 if "minus" in asked else 0) + (1 if "offset" in ft else 0)
                    pool.add(f"layout:{mag}:offset", o1, sc - mi)
                    pool.add(f"layout:{mag}:offset_alt", o2, sc - 9 - mi)
                # stated little-endian fields after the magic: "+N" / "bytes a..b" / "u16"/"u32"
                for m in re.finditer(r"(?:\+|bytes? |offset )" + NUM + r"(?:\.\." + NUM + r")?", spec.text):
                    a = num(m.group(1))
                    hi = num(m.group(2)) if m.group(2) else None
                    width = (hi - a + 1) if hi is not None else None
                    for w in ([width] if width in (1, 2, 4, 8) else [4, 2, 1]):
                        p = o1 + a
                        if p + w <= len(b):
                            v = int.from_bytes(b[p:p + w], "little")
                            pool.add(f"layout:{mag}:le{w}@{a}", v, 13 - mi)
                for w in (4, 2):
                    for a in range(4, 24, 2):
                        if o1 + a + w <= len(b):
                            v = int.from_bytes(b[o1 + a:o1 + a + w], "little")
                            if 0 < v < len(b):
                                pool.add(f"layout:{mag}:scan_le{w}@{a}", v, 6 - 0.1 * a - mi)
            else:
                expert_overlay_payload(spec, env, pool, b, last, mag, mi)
    expert_records(spec, env, pool, members, mags)


# --- stated records: a header the question lays out (or the lane's usual one), found raw or behind a transform


NUM = r"(0x[0-9a-fA-F]+|\d+)"


def num(x):
    return int(x, 0) if x.lower().startswith("0x") else int(x)


def stated_layout(text):
    """The record layout 'byte N is the X' / 'bytes a..b are the Y' / 'payload begins at byte N', and apart from
    it the outer container's 'X at +N' fields: ({role: (offset, width)}, payload start, {outer role: ...}).
    Offsets may be decimal or 0x-hex; widths come from a range, or from u16/uint32/little-endian 64-bit words."""
    lay, payload, outer = {}, None, {}
    for m in re.finditer(r"\bbytes? " + NUM + r"(?:\s*(?:\.\.|-|to|through)\s*" + NUM + r")? (?:(?:is|are|hold|holds|contain|contains) )?"
                         r"(?:the |an? )?((?:little|big)-endian )?([\w -]{2,60}?)(?=[,;.]|\band\b)", text):
        a = num(m.group(1))
        w = num(m.group(2)) - a + 1 if m.group(2) else 1
        if 0 < w <= 64:
            lay[m.group(4).strip().lower()] = (a, w)
    width_rx = r"(?:(?:u|uint|int)(8|16|32|64)(?:le|be|_le|_be)? |(?:little|big)-endian (?:u|uint|int)?(8|16|32|64)(?:-bit)? )?"
    for m in re.finditer(r"([\w -]{2,40}?) " + width_rx + r"(?:is )?(?:at|@) (?:offset |byte )?\+?" + NUM, text):
        name = m.group(1).strip().lower().split(",")[-1].strip()
        name = re.sub(r"^(?:and|read|the|a|an)\s+", "", name)
        bits = m.group(2) or m.group(3)
        w = int(bits) // 8 if bits else (32 if "sha-256" in name or "sha256" in name else 1)
        outer[name] = (num(m.group(4)), w)
    m = re.search(r"payload (?:begins|starts|is) at (?:byte |offset |\+)?" + NUM, text)
    if m:
        payload = num(m.group(1))
    return lay, payload, outer


def role(lay, *words):
    for name, (a, w) in lay.items():
        if all(x in name for x in words):
            return a, w
    return None


DEFAULT_RECORD = ({"version": (4, 1), "xor key": (5, 1), "little-endian payload length": (6, 2),
                   "little-endian crc32 of the decoded payload": (8, 4)}, 12)


def parse_record(buf, off, lay, payload_at):
    """One record at `off`: its header fields, its payload decoded with its own key, and whether its CRC holds."""
    hdr = buf[off:off + max([a + w for a, w in lay.values()] + [payload_at or 12])]
    fields = {name: int.from_bytes(hdr[a:a + w], "little") for name, (a, w) in lay.items() if a + w <= len(hdr)}
    k = role(lay, "key")
    ln = role(lay, "length") or role(lay, "len")
    crc = role(lay, "crc")
    start = off + (payload_at if payload_at is not None else 12)
    n = int.from_bytes(buf[off + ln[0]:off + ln[0] + ln[1]], "little") if ln else min(4096, len(buf) - start)
    body = buf[start:start + n]
    key = buf[off + k[0]] if k and off + k[0] < len(buf) else 0
    dec = bytes(c ^ key for c in body) if k and k[1] == 1 else body
    ok = None
    if crc:
        want = int.from_bytes(buf[off + crc[0]:off + crc[0] + 4], "little")
        ok = (zlib.crc32(dec) & 0xffffffff) == want or (zlib.crc32(body) & 0xffffffff) == want
    return {"offset": off, "fields": fields, "payload": dec, "crc_ok": ok, "header": hdr, "size": start - off + len(body)}


def xrx_tables(keys):
    """(name, table) for c -> rot(c ^ a, r) ^ b with a, b among the stated key bytes."""
    ks = [0] + [k for k in dict.fromkeys(keys) if k]
    out = []
    for a in ks:
        for b in ks:
            for r in range(0, 8):
                for d in (("ror", lambda x, r: ((x >> r) | (x << (8 - r))) & 0xff), ("rol", lambda x, r: ((x << r) | (x >> (8 - r))) & 0xff)):
                    if r == 0 and d[0] == "rol":
                        continue
                    t = bytes(d[1](c ^ a, r) ^ b for c in range(256))
                    out.append((f"xor{a:02x}_{d[0]}{r}_xor{b:02x}", t))
    return out


def expert_records(spec, env, pool, members, mags):
    if not mags or env.time_left() <= 0:
        return
    inner_lay, inner_at, lay = stated_layout(spec.text)
    if not role(inner_lay, "crc") and not role(inner_lay, "length"):
        if len(mags) == 1 and (role(lay, "length") or role(lay, "key")):
            inner_lay = dict(lay)   # one container stated with 'X at offset N': it is the record
        else:
            inner_lay, inner_at = DEFAULT_RECORD
    final_sentence = re.split(r"(?<=[.;])\s+", spec.text.strip())[-1]
    want_bytes = [(num(a), num(b) if b else None) for a, b in re.findall(r"bytes? " + NUM + r"(?:\.\." + NUM + r")?", final_sentence)]
    outer = mags[0]
    inner = [m for m in mags[1:]] or mags
    for mi, name in enumerate(members[:10]):
        if env.time_left() <= 0:
            return
        ck = ("records", name, outer, tuple(inner), repr(sorted(lay.items())), repr(sorted(inner_lay.items())), inner_at)
        if ck not in env._facts:
            env._facts[ck] = find_records(env.member_bytes(name) or b"", outer, inner, lay, inner_lay, inner_at, len(mags) > 1)
        for how, m_start, rec in env._facts[ck]:
            sc = 20 + (12 if rec["crc_ok"] else (-6 if rec["crc_ok"] is False else 0)) - mi + (3 if how != "raw" else 0)
            mag = rec["magic"]
            tag = f"record:{mag}:{how.split(':')[-1]}"
            if spec.form in ("int", "hex0x", "int_or_none"):
                # the record is what is asked only when the asked sentence names it (or names its bytes)
                about = bool(want_bytes) or mag.lower() in final_sentence.lower() or "record" in final_sentence.lower() \
                    or ("field" in final_sentence.lower() and mag == outer)
                if not about:
                    sc -= 14
                for a, z in want_bytes:
                    w = (z - a + 1) if z is not None else 1
                    v = int.from_bytes(rec["header"][a:a + w], "little")
                    pool.add(f"{tag}:bytes{a}", v, sc + 6)
                fin = set(toks(final_sentence)) - STOP
                for fname, v in rec["fields"].items():
                    boost = 8.0 * len(set(toks(fname)) & fin & {"crc32", "crc", "version", "key", "length", "size", "count", "flags", "seed"})
                    pool.add(f"{tag}:{'_'.join(toks(fname))[:30]}", v, sc - 4 + boost)
                pool.add(f"{tag}:offset", m_start, sc - 8)
                if rec.get("size"):
                    pool.add(f"{tag}:record_size", rec["size"], sc - 3 + (6 if "size" in spec.field_toks else 0))
                    pool.add(f"{tag}:payload_size", len(rec["payload"]), sc - 5 + (3 if "size" in spec.field_toks else 0))
            txt = rec["payload"].decode("utf-8", "replace")
            for k, v in kv_pairs(txt):
                ks = key_score(k, spec)
                if ks > 0:
                    pool.add(f"{tag}:kv:{k}", v if isinstance(v, (str, int)) else jdump(v), sc + ks)
            for si, sh in enumerate(wanted_shapes(spec)[:3]):
                for h in shape_hits(txt, sh)[:3]:
                    pool.add(f"{tag}:{sh}", h, sc - 2 - 2 * si)


_XRX = {}


def find_records(b, outer, inner, lay, inner_lay, inner_at, layered):
    """[(how, offset, record)]: inner records found raw, or behind the outer magic's stated transform."""
    bufs = [("raw", b)]
    offs = [m.start() for m in re.finditer(re.escape(outer.encode()), b)]
    key_bytes = [lay[n] for n in lay if re.fullmatch(r"k\d|key\w*|\w* key", n)]
    if offs and layered:
        o = offs[-1]
        region = b[o:o + (1 << 16)]
        kb = [region[a] for a, w in key_bytes if w == 1 and a < len(region)]
        starts = [a for a, w in lay.values() if w > 1 and a >= 8] + [44, 12, 16, 24]
        pl = role(lay, "packed bytes") or role(lay, "bytes")
        if pl:
            starts.insert(0, pl[0])
        plen = role(lay, "length")
        kk = tuple(kb or region[4:8])
        if kk not in _XRX:
            _XRX[kk] = xrx_tables(list(kk))
        for st in list(dict.fromkeys(starts))[:4]:
            body = region[st:]
            if plen and plen[1] in (2, 4):
                n = int.from_bytes(region[plen[0]:plen[0] + plen[1]], "little")
                if 0 < n <= len(body):
                    body = body[:n]
            head = body[:64]
            for nm, t in _XRX[kk]:
                x = head.translate(t)
                if any(m.encode() in x for m in inner):
                    bufs.append((f"{outer}+{st}:{nm}", body.translate(t)))
            if len(bufs) > 6:
                break
    out = []
    for how, buf in bufs:
        for mag in inner:
            for m in list(re.finditer(re.escape(mag.encode()), buf))[-4:]:
                rec = parse_record(buf, m.start(), inner_lay, inner_at)
                rec["magic"] = mag
                out.append((how, m.start(), rec))
    return out


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)


def payload_transforms(hdr):
    """(name, function) for a family of byte transforms whose parameters are the header bytes after the magic."""
    out = []
    for k in sorted(set(hdr[4:12])):
        out += [
            (f"xor_k{k:02x}", lambda b, k=k: bytes(c ^ k for c in b)),
            (f"sub_k{k:02x}", lambda b, k=k: bytes((c - k) & 0xff for c in b)),
            (f"add_k{k:02x}", lambda b, k=k: bytes((c + k) & 0xff for c in b)),
            (f"xor_swap_k{k:02x}", lambda b, k=k: bytes((((c ^ k) & 0xf) << 4) | ((c ^ k) >> 4) for c in b)),
            (f"swap_xor_k{k:02x}", lambda b, k=k: bytes(((((c & 0xf) << 4) | (c >> 4)) ^ k) for c in b)),
            (f"xor_rev_k{k:02x}", lambda b, k=k: bytes(c ^ k for c in b)[::-1]),
        ]
        for step in (1, 3, 5, 7, 11, 13, 17, 31):
            out.append((f"rollxor_k{k:02x}_s{step}", lambda b, k=k, s=step: bytes(c ^ ((k + s * i) & 0xff) for i, c in enumerate(b))))
            out.append((f"rollsub_k{k:02x}_s{step}", lambda b, k=k, s=step: bytes((c - k - s * i) & 0xff for i, c in enumerate(b))))
    out += [("plain", lambda b: b), ("rev", lambda b: b[::-1])]
    return out


def overlay_texts(spec, b, off):
    """[(start, how, text)]: the bytes after a magic, decoded by every transform that gives text."""
    region = b[off:off + 4096]
    hdr = region[:48]
    starts = sorted(set([8, 12, 16, 24, 44, 48] + [a for a in (int(x) for x in re.findall(r"\+(\d+)", spec.text)) if a < 128]))
    out = []
    fams = payload_transforms(hdr)
    for st in starts:
        body = region[st:st + 2048]
        for how, f in fams:
            dec = f(body[::-1][:24][::-1]) if how.startswith(("rev", "xor_rev")) else f(body[:24])
            if printable_ratio(dec) < 0.75:
                continue
            out.append((st, how, f(body).decode("latin-1")))
        for m in re.finditer(r"bytes (\d+)\.\.(\d+) are an? \d+-byte RC4 key", spec.text):
            a, z = int(m.group(1)), int(m.group(2))
            dec = rc4(region[a:z + 1], body)
            if printable_ratio(dec[:24]) >= 0.75:
                out.append((st, "rc4_stated", dec.decode("latin-1")))
    return out


def expert_overlay_payload(spec, env, pool, b, off, mag, mi):
    """Decode the bytes after the final magic by every transform and pull out the asked noun's shape."""
    shapes = wanted_shapes(spec) or ["campaign", "url", "domain", "mutex"]
    ck = ("overlay", id(b), off, tuple(re.findall(r"\+(\d+)", spec.text)), tuple(re.findall(r"bytes (\d+)\.\.(\d+) are an? \d+-byte RC4", spec.text)))
    if ck not in env._facts:
        env._facts[ck] = overlay_texts(spec, b, off)
    seen = set()
    for st, how, txt in env._facts[ck]:
        for k, v in kv_pairs(txt):
            ks = key_score(k, spec)
            if ks > 0 and isinstance(v, str):
                pool.add(f"overlay:{mag}:{how}:kv", v.strip(), 22 + ks - mi)
        for si, sh in enumerate(shapes):
            for h in shape_hits(txt, sh)[:4]:
                if (how, h) in seen:
                    continue
                seen.add((how, h))
                pool.add(f"overlay:{mag}:{how}:{sh}", h, 18 - 2 * si - mi + (2 if st in (8, 12, 24, 44) else 0))


# ---------------------------------------------------------------------------------------------------------
# digests and orderings named in a question


def expert_digest_order(spec, env, pool):
    m = re.search(r"Files:\s*(\[[^\]]*\])", spec.text)
    if not m:
        return
    try:
        names = json.loads(m.group(1))
    except ValueError:
        return
    for algo in ("sha256", "sha1", "md5"):
        if algo.replace("sha", "sha-") not in spec.low and algo not in spec.low:
            continue
        dig = {}
        for n in names:
            b = env.member_bytes(n)
            if b is None:
                return
            dig[n] = hashlib.new(algo, b).hexdigest()
        asc = sorted(names, key=lambda n: dig[n])
        desc = asc[::-1]
        first = ("descending" not in spec.low)
        pool.add(f"order:{algo}:asc", asc, 30 if first else 20)
        pool.add(f"order:{algo}:desc", desc, 20 if first else 30)


# ---------------------------------------------------------------------------------------------------------
# slugs (warmups) and codes (mobile): classical decoders over the delivery

SLUG_RE = re.compile(r"\b([a-z]{2,12})-([a-z]{2,12})-([a-z]{2,12})-(\d{2})\b")
ANS_RE = re.compile(r"ANS-[0-9A-Fa-f]{16}")


def caesar(s, k):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + k) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + k) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def atbash(s):
    return "".join(chr(219 - ord(c)) if "a" <= c <= "z" else chr(155 - ord(c)) if "A" <= c <= "Z" else c for c in s)


def digits_map(s, f):
    return re.sub(r"\d", lambda m: str(f(int(m.group()))), s)


BACON = {}
for _i, _c in enumerate("ABCDEFGHIKLMNOPQRSTUWXYZ"):
    BACON[format(_i, "05b")] = _c
BACON26 = {format(i, "05b"): chr(65 + i) for i in range(26)}
MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h", "..": "i",
         ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
         "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y", "--..": "z",
         "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
         "--...": "7", "---..": "8", "----.": "9", "-....-": "-", ".-.-.-": ".", "---...": ":", "--..--": ",",
         "-.-.--": "!"}
CRIBS = ["submit", "answer", "slug", "decode", "message", "the", "game", "master", "nice", "work", "flag", "final"]
QWERTY = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?"
DVORAK = "`1234567890[]',.pyfgcrl/=\\aoeuidhtns-;qjkxbmwvz~!@#$%^&*(){}\"<>PYFGCRL?+|AOEUIDHTNS_:QJKXBMWVZ"


COMMON_BIGRAMS = set("th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve "
                     "co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct "
                     "us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow "
                     "pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex "
                     "ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl "
                     "du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak "
                     "pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu "
                     "nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo lf nv je nk kn gs dy hy ze ks "
                     "xt bs ik dd cy rp sk xi oe oy ws lv dl rf eu dg wr xa yi nm eb rb tm xc eh tc gy ja hn yp za gg "
                     "ym sw bj lm cs ii ix xe oh lk dv lp ax ox uf dm iu sf bt ka yt ek pm ya gt wl rh yl hs ah yc yn "
                     "rw hm lw hl ae zi az lc py aj iq nj bb nh uo kl lb tz gm sn vy".split())


_WORDS = None


def words():
    """A sorted English word list (the system dictionary when there is one), for word coverage and prefixes."""
    global _WORDS
    if _WORDS is None:
        ws = set()
        for path in ("/usr/share/dict/words", "/usr/dict/words"):
            try:
                with open(path, encoding="latin-1") as fh:
                    ws = {w.strip().lower() for w in fh if 3 <= len(w.strip()) <= 14 and w.strip().isalpha()}
                break
            except OSError:
                continue
        _WORDS = sorted(ws)
    return _WORDS


def is_word(w):
    import bisect
    ws = words()
    i = bisect.bisect_left(ws, w)
    return i < len(ws) and ws[i] == w


def is_prefix(w):
    import bisect
    ws = words()
    i = bisect.bisect_left(ws, w)
    return i < len(ws) and ws[i].startswith(w)


def word_cover(s):
    """Share of letters in runs that are dictionary words (the last run may be a word's prefix)."""
    runs = re.findall(r"[a-z]+", s.lower())
    if not runs or not words():
        return 0.0
    tot = sum(len(r) for r in runs)
    ok = 0
    for i, r in enumerate(runs):
        if len(r) <= 2 or is_word(r) or (i == len(runs) - 1 and is_prefix(r)):
            ok += len(r)
    return ok / max(tot, 1)


def english_score(s):
    """How much a decoding reads like English text: common bigrams, letters and spaces, a crib or two."""
    low = s.lower()
    if not low:
        return 0.0
    n = len(low)
    letters = sum(1 for c in low if "a" <= c <= "z")
    spaces = low.count(" ")
    big = sum(1 for i in range(n - 1) if low[i:i + 2] in COMMON_BIGRAMS)
    weird = sum(1 for c in low if not (c.isalnum() or c in " -:.,!'?\n"))
    weird += 0.7 * len(re.findall(r"[a-z][A-Z]", s))
    cr = sum(1 for w in ("submit", "answer", "slug", "decode", "message", "nice", "work", "master", "game", "final",
                         "warmup", "blob", "the") if w in low)
    distinct = len({c for c in low if "a" <= c <= "z"})
    flat = 4.0 if letters >= 10 and distinct <= 4 else 0.0   # a two- or three-letter alphabet is a code, not text
    return 10.0 * big / max(1, n - 1) + 2.0 * letters / n + 1.5 * min(spaces / n, 0.2) - 4.0 * weird / n + 0.6 * cr - flat


def bits_to_bytes(bits):
    bits = re.sub(r"[^01]", "", bits)
    out = []
    for w in (8, 7):
        if len(bits) % w == 0 or w == 8:
            b = bytes(int(bits[i:i + w], 2) for i in range(0, len(bits) - w + 1, w))
            out.append((f"bin{w}", b))
    return out


def vig_crib_keys(ct, cribs=("submit", "answer", "nice", "the", "decode", "master", "message")):
    """Vigenere/Beaufort keys a crib implies at each position; the repeating ones are kept."""
    letters = [c for c in ct.lower() if c.isalpha()]
    L = "".join(letters)
    found = Counter()
    for crib in cribs:
        for pos in range(0, max(0, len(L) - len(crib)) + 1):
            seg = L[pos:pos + len(crib)]
            if len(seg) < len(crib):
                break
            for mode in ("vig", "beau", "varbeau"):
                if mode == "vig":
                    ks = [(ord(c) - ord(p)) % 26 for c, p in zip(seg, crib)]
                elif mode == "beau":
                    ks = [(ord(c) + ord(p) - 2 * 97) % 26 for c, p in zip(seg, crib)]
                else:
                    ks = [(ord(p) - ord(c)) % 26 for c, p in zip(seg, crib)]
                for period in range(1, 9):
                    if period >= len(crib):
                        break
                    ok = all(ks[i] == ks[i + period] for i in range(len(ks) - period))
                    if ok:
                        key = [None] * period
                        for i, k in enumerate(ks[:period]):
                            key[(pos + i) % period] = k
                        found[(mode, tuple(key))] += 1
                        break
    return [k for k, _ in found.most_common(40)]


def vig_apply(ct, mode, key):
    out, i = [], 0
    for c in ct:
        if c.isalpha():
            base = 97 if c.islower() else 65
            x, k = ord(c.lower()) - 97, key[i % len(key)]
            if mode == "vig":
                p = (x - k) % 26
            elif mode == "beau":
                p = (k - x) % 26
            else:
                p = (x + k) % 26
            out.append(chr(p + base))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def porta_apply(ct, key):
    out, i = [], 0
    for c in ct:
        if c.isalpha():
            k = (ord(key[i % len(key)]) - 97) // 2
            x = ord(c.lower()) - 97
            if x < 13:
                p = (x + k) % 13 + 13
            else:
                p = (x - 13 - k) % 13
            out.append(chr(p + (97 if c.islower() else 65)))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def classical_texts(raw: bytes, deadline):
    """(how, text) for a battery of classical and base-N decodings of a blob, two levels deep."""
    text = as_text(raw).strip()
    out = [("raw", text)]
    seen = {text}

    def add(how, t):
        if t and t not in seen and len(out) < 1500:
            seen.add(t)
            out.append((how, t))

    def level(how0, t):
        s = t.strip()
        add(how0 + ">rev", s[::-1])
        add(how0 + ">atbash", atbash(s))
        for k in range(1, 26):
            add(how0 + f">rot{k}", caesar(s, k))
        b = _b64(s) if re.fullmatch(r"[A-Za-z0-9+/=_\-\s]+", s) else None
        if b and printable_ratio(b) > 0.8:
            add(how0 + ">b64", as_text(b))
        for x in _inflate(b or b""):
            add(how0 + ">b64>inflate", as_text(x))
        if re.fullmatch(r"[A-Z2-7=\s]+", s):
            try:
                add(how0 + ">b32", base64.b32decode(re.sub(r"\s", "", s) + "=" * (-len(re.sub(r"\s", "", s)) % 8)).decode("latin-1"))
            except Exception:
                pass
        if re.fullmatch(r"[0-9a-fA-F\s]+", s):
            h = _hex(s)
            if h:
                add(how0 + ">hex", as_text(h))
                for k, x in _single_xor(h):
                    add(how0 + f">hex>{k}", as_text(x))
                for key in (b"huntress", b"HUNTRESS", b"Huntress", b"key", b"ctf"):
                    x = _rep_xor(h, key)
                    if printable_ratio(x) > 0.95:
                        add(how0 + f">hex>xor_{key.decode()}", as_text(x))
                rep = repeating_xor_unkeyed(h)
                if rep:
                    add(how0 + ">hex>xor_rep", rep)
                nib = h.hex()
                if len(nib) % 2 == 0:
                    half = len(nib) // 2
                    try:
                        inter = "".join(a + b2 for a, b2 in zip(nib[:half], nib[half:]))
                        add(how0 + ">hex>nibinter", as_text(bytes.fromhex(inter)))
                    except ValueError:
                        pass
        if re.fullmatch(r"[01\s]+", s) and len(re.sub(r"\s", "", s)) >= 16:
            for nm, b2 in bits_to_bytes(s):
                add(how0 + f">{nm}", as_text(b2))
                gray = gray_decode_bits(re.sub(r"\s", "", s))
                if gray:
                    add(how0 + ">gray", gray)
        if re.fullmatch(r"[0-7\s]+", s) and " " in s:
            try:
                add(how0 + ">oct", bytes(int(x, 8) for x in s.split()).decode("latin-1"))
            except ValueError:
                pass
        if re.fullmatch(r"[\d\s,]+", s):
            nums = [int(x) for x in re.findall(r"\d+", s)]
            if nums and max(nums) < 256:
                add(how0 + ">dec", bytes(nums).decode("latin-1"))
                acc, outb = 0, []
                for n in nums:
                    acc = (acc + n) & 0xff
                    outb.append(acc)
                add(how0 + ">delta", bytes(outb).decode("latin-1"))
        if re.fullmatch(r"[.\-/\s|]+", s) and "." in s:
            words = re.split(r"\s*/\s*|\s{2,}|\|", s)
            add(how0 + ">morse", " ".join("".join(MORSE.get(c, "?") for c in w.split()) for w in words))
        if re.fullmatch(r"[a-p\s]+", s) and len(re.sub(r"\s", "", s)) % 2 == 0 and len(s) >= 8:
            g = re.sub(r"\s", "", s)
            add(how0 + ">nibble_letters", as_text(bytes((ord(g[i]) - 97) * 16 + ord(g[i + 1]) - 97 for i in range(0, len(g), 2))))
        if "%" in s and re.search(r"%[0-9A-Fa-f]{2}", s):
            from urllib.parse import unquote
            add(how0 + ">url", unquote(s))
        if "&#" in s or "&amp;" in s:
            import html
            add(how0 + ">html", html.unescape(s))
        if "\\u" in s or "\\x" in s:
            try:
                add(how0 + ">unicode_escape", s.encode("latin-1", "ignore").decode("unicode_escape"))
            except Exception:
                pass
        add(how0 + ">rot47", "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s))
        if re.fullmatch(r"[abAB\s]+", s):
            g = re.sub(r"\s", "", s).lower()
            for table, nm in ((BACON, "bacon24"), (BACON26, "bacon26")):
                add(how0 + f">{nm}", "".join(table.get(g[i:i + 5].replace("a", "0").replace("b", "1"), "?")
                                             for i in range(0, len(g) - 4, 5)).lower())
        # zero-width and tag characters
        zw = [c for c in s if c in "\u200b\u200c\u200d\u2060\ufeff"]
        if len(zw) >= 8:
            bits = "".join("0" if c == "\u200b" else "1" for c in zw if c in "\u200b\u200c")
            for nm, b2 in bits_to_bytes(bits):
                add(how0 + ">zw_" + nm, as_text(b2))
        tags = [c for c in s if 0xE0000 <= ord(c) <= 0xE007F]
        if tags:
            add(how0 + ">unicode_tags", "".join(chr(ord(c) - 0xE0000) for c in tags))
        if any(c in s for c in "',.pyfgcrl;"):
            tr = str.maketrans(DVORAK, QWERTY)
            add(how0 + ">dvorak", s.translate(tr))
            tr2 = str.maketrans(QWERTY, DVORAK)
            add(how0 + ">dvorak_inv", s.translate(tr2))
        if re.search(r"ub[aeiou]", s.lower()):
            add(how0 + ">ubbi", re.sub(r"(?i)ub([aeiou])", r"\1", s))
        if "." in s and re.fullmatch(r"[A-Za-z0-9+/=.\s]+", s):
            blocks = s.split(".")
            joined = "".join(x[::-1] for x in blocks)
            b3 = _b64(joined)
            if b3:
                add(how0 + ">blockrev_b64", as_text(b3))
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", s) and len(s) >= 8:
            for blk in (4, 8):
                joined = "".join(s[i:i + blk][::-1] for i in range(0, len(s), blk))
                b4 = _b64(joined)
                if b4 and printable_ratio(b4) > 0.85:
                    add(how0 + f">blockrev{blk}_b64", as_text(b4))
            for r in (1, 2, 3, 4, 5, 6, 7):
                bb = _b64(s)
                if bb:
                    x = bytes(((c >> r) | (c << (8 - r))) & 0xff for c in bb)
                    if printable_ratio(x) > 0.9:
                        add(how0 + f">b64>rotr{r}", as_text(x))
        for mode, key in vig_crib_keys(s):
            add(how0 + f">{mode}_" + "".join(chr(97 + k) for k in key), vig_apply(s, mode, key))
        for key in ("huntress", "signal", "key", "secret", "cipher"):
            add(how0 + f">porta_{key}", porta_apply(s, key))
            for mode in ("vig", "beau", "varbeau"):
                add(how0 + f">{mode}_{key}", vig_apply(s, mode, [ord(c) - 97 for c in key]))
    level("", text)
    for i, mixed in enumerate(linewise(text, deadline)):
        add(">linewise" + (f"_alt{i}" if i else ""), mixed)
    if time.time() < deadline:
        base = list(out[1:])
        restricted = [r for r in base if not re.search(r">(?:rot\d+|rot47|atbash|rev|beau\w*|vig\w*|varbeau\w*|porta\w*|dvorak\w*)$", r[0])
                      and re.fullmatch(r"[A-Za-z0-9+/=\s]+|[0-9a-fA-F\s]+|[a-p\s]+|[01\s]+|[\d\s,]+", r[1].strip() or "-")
                      and len(r[1]) >= 8]
        base.sort(key=lambda r: -english_score(r[1]))
        for how, t in list(dict.fromkeys(base[:10] + restricted[:10])):
            if time.time() > deadline:
                break
            level(how, t)
    return out


def single_decodes(s, depth=0):
    """Every decoder on one short piece: one step, and a second step behind a decoder whose output is itself
    an encoding (Morse or Bacon giving hex digits or nibble letters, base64 giving hex, ...)."""
    out = one_step(s)
    if depth == 0:
        for nm, c in list(out):
            if nm in ("as_is", "rev", "atbash", "rot47") or nm.startswith("rot"):
                continue
            t = c.strip()
            if len(t) >= 2 and re.fullmatch(r"[0-9a-fA-F ]+|[a-p]+|[A-Za-z0-9+/=]+|[01 ]+|[\d ]+", t):
                out += [(f"{nm}>{n2}", c2) for n2, c2 in one_step(t) if n2 not in ("as_is",) and not n2.startswith("rot")]
    return out


def one_step(s):
    out = [("as_is", s), ("rev", s[::-1]), ("atbash", atbash(s))]
    out += [(f"rot{k}", caesar(s, k)) for k in range(1, 26)]
    out.append(("rot47", "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)))
    t = s.strip()
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", t):
        b = _b64(t)
        if b and printable_ratio(b) > 0.9:
            out.append(("b64", as_text(b)))
    if re.fullmatch(r"[A-Z2-7=]+", t):
        try:
            out.append(("b32", base64.b32decode(t + "=" * (-len(t) % 8)).decode("latin-1")))
        except Exception:
            pass
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0:
        out.append(("hex", bytes.fromhex(t).decode("latin-1")))
    if re.fullmatch(r"[01 ]+", t):
        for nm, b in bits_to_bytes(t):
            out.append((nm, as_text(b)))
    if re.fullmatch(r"[\d ]+", t):
        nums = t.split()
        for base_ in (10, 8):
            try:
                v = [int(x, base_) for x in nums]
                if all(x < 256 for x in v):
                    out.append((f"base{base_}", bytes(v).decode("latin-1")))
            except ValueError:
                pass
    if re.fullmatch(r"[.\- /|]+", t) and "." in t + "-":
        ws = re.split(r"\s*/\s*|\s{2,}|\|", t)
        out.append(("morse", " ".join("".join(MORSE.get(c, "?") for c in w.split()) for w in ws).replace(" ", "")))
        out.append(("morse_spaced", " ".join("".join(MORSE.get(c, "?") for c in w.split()) for w in ws)))
    if re.fullmatch(r"[abAB ]+", t) and len(t.replace(" ", "")) % 5 == 0:
        g = t.replace(" ", "").lower()
        for table, nm in ((BACON26, "bacon26"), (BACON, "bacon24")):
            out.append((nm, "".join(table.get(g[i:i + 5].replace("a", "0").replace("b", "1"), "?") for i in range(0, len(g), 5)).lower()))
    if re.fullmatch(r"[a-p]+", t) and len(t) % 2 == 0:
        out.append(("nibble_letters", as_text(bytes((ord(t[i]) - 97) * 16 + ord(t[i + 1]) - 97 for i in range(0, len(t), 2)))))
    if "%" in t:
        from urllib.parse import unquote
        out.append(("url", unquote(t)))
    if "&#" in t:
        import html
        out.append(("html", html.unescape(t)))
    if "\\u" in t or "\\x" in t:
        try:
            out.append(("unicode_escape", t.strip('"').encode("latin-1", "ignore").decode("unicode_escape")))
        except Exception:
            pass
    return out


PRIOR = {"as_is": 0.4, "rot13": 0.6, "b64": 1.2, "b32": 1.2, "hex": 1.2, "bin8": 1.2, "bin7": 0.8, "base10": 1.2,
         "base8": 1.0, "url": 1.2, "html": 1.2, "unicode_escape": 1.2, "rev": 0.5, "atbash": 0.5, "rot47": 0.5}


def linewise(text, deadline):
    """A blob whose lines each use their own codec (`NN<TAB>piece`): every line decoded by its best reading in
    the context of the lines before it; returns the best joined text and variants with a late line's runner-up."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) < 3:
        return []
    picks = []
    prev = ""
    for ln in lines:
        if time.time() > deadline:
            return []
        body = re.sub(r"^\s*\d{1,3}[\t:.)]\s?", "", ln)
        cands = single_decodes(body)
        tail = prev[-24:]
        tail = tail[re.search(r"[^A-Za-z]", tail).start():] if re.search(r"[^A-Za-z]", tail) else tail
        scored = sorted(((english_score(prev[-24:] + c) + PRIOR.get(nm, 0.0) + 0.3 * english_score(c)
                          + 4.0 * word_cover(tail + c), c) for nm, c in cands), key=lambda r: -r[0])
        uniq = []
        for sc, c in scored:
            if c not in uniq:
                uniq.append(c)
            if len(uniq) == 6:
                break
        picks.append(uniq)
        prev += uniq[0]
    best = "".join(p[0] for p in picks)
    out = [best]
    for i in range(max(0, len(picks) - 6), len(picks)):
        for alt in picks[i][1:6]:
            out.append("".join(p[0] if j != i else alt for j, p in enumerate(picks)))
    return out


XOR_TABLES = [bytes(c ^ k for c in range(256)) for k in range(256)]
_NOTLOWER_SP = bytes(c for c in range(256) if not (97 <= c <= 122 or c == 32))


def repeating_xor_unkeyed(b: bytes, max_len=16):
    """Repeating-key XOR with no key given: each key byte chosen by its column's text score (C-speed)."""
    b = b[:4096]
    best = None
    for klen in range(1, min(max_len, len(b) // 3) + 1):
        # screen: XOR of 7-bit text keeps bit 7 constant within each key column
        if any(len({c >> 7 for c in b[j::klen]}) > 1 for j in range(klen)):
            continue
        key = []
        for j in range(klen):
            col = b[j::klen]
            bk, bs = 0, -1.0
            for k in range(256):
                x = col.translate(XOR_TABLES[k])
                sc = len(x.translate(None, _NOTLOWER_SP)) + 0.5 * len(x.translate(None, _NONPRINT))
                if sc > bs:
                    bk, bs = k, sc
            key.append(bk)
        x = _rep_xor(b, bytes(key))
        pr = printable_ratio(x)
        sc = pr + english_score(x.decode("latin-1")[:400]) * 0.01 - 0.002 * klen
        if pr > 0.95 and (best is None or sc > best[0] + 0.02):
            best = (sc, x.decode("latin-1"))
    return best[1] if best else None


def gray_decode_bits(bits):
    if len(bits) % 8:
        return None
    out = []
    for i in range(0, len(bits), 8):
        g = int(bits[i:i + 8], 2)
        n = g
        s = g >> 1
        while s:
            n ^= s
            s >>= 1
        out.append(n)
    b = bytes(out)
    return as_text(b) if printable_ratio(b) > 0.9 else None


def expert_slug(spec, env, pool):
    if spec.form != "slug":
        return
    raw = env.ctx.get("delivery") or next(iter(env.files.values()), b"")
    texts = classical_texts(raw, min(env.deadline - MARGIN, time.time() + 4.0))
    scored = []
    for how, t in texts:
        hits = SLUG_RE.findall(t)
        if not hits:
            continue
        lines = [ln for ln in t.splitlines() if ln.strip()]
        last = lines[-1] if lines else t
        es = english_score(t[:400])
        for h in hits:
            slug = "-".join(h)
            in_last = slug in last
            words_ok = 3.0 * sum(1 for w in h[:3] if is_word(w)) + sum(english_score(w) for w in h[:3]) / 3
            scored.append((5 + 2 * min(es, 8) + words_ok + (3 if in_last else 0) - 0.05 * how.count(">"), how, slug))
    scored.sort(key=lambda r: -r[0])
    for sc, how, slug in scored[:40]:
        pool.add(f"classical:{how.strip('>').split('>')[0] or 'raw'}", slug, 10 + sc)
        # the number under the same digit maps the letter cipher may have used
        w = slug.rsplit("-", 1)
        n = w[1]
        for nm, f in (("digits_complement9", lambda d: 9 - d), ("digits_rot5", lambda d: (d + 5) % 10)):
            pool.add(f"classical:{nm}", w[0] + "-" + digits_map(n, f), 5 + sc * 0.5)


HEXU = "0123456789ABCDEF"


def param_decodes(data, params):
    """A puzzle's data string under generic transforms whose parameters are the puzzle's own numbers/strings."""
    out = []
    ints = sorted({v for v in params if isinstance(v, int) and 0 < v < 256} | {1, 2, 3})
    strs = [v for v in params if isinstance(v, str) and 0 < len(v) <= 64]
    t = data.strip()
    if re.fullmatch(r"\d{6,40}", t):
        v = int(t)
        out.append(("int_hex", "%016X" % v if v < 1 << 64 else "%X" % v))
    for st in ints:
        for sign in (1, -1):
            out.append((f"posshift{sign * st}", "".join(chr(33 + (ord(c) - 33 - sign * st * i) % 94) if 33 <= ord(c) <= 126 else c
                                                    for i, c in enumerate(t))))
            out.append((f"shift{sign * st}", "".join(chr(33 + (ord(c) - 33 - sign * st) % 94) if 33 <= ord(c) <= 126 else c for c in t)))
    for rails in ints:
        if 2 <= rails <= 8:
            out.append((f"railfence{rails}", rail_decode(t, rails)))
    half = (len(t) + 1) // 2
    out.append(("interleave", "".join(a + b for a, b in zip(t[:half], t[half:])) + (t[half - 1] if len(t) % 2 and False else "")))
    b = _b64(t) if re.fullmatch(r"[A-Za-z0-9+/=_-]+", t) else None
    raw = b if b else None
    for key in strs + [str(v) for v in ints]:
        kb = key.encode()
        hk = None
        if re.fullmatch(r"[0-9a-fA-F]+", key) and len(key) % 2 == 0:
            hk = bytes.fromhex(key)
        for k in [x for x in (kb, hk) if x]:
            if raw:
                prev, chain = list(k), []
                for i, c in enumerate(raw):
                    x = c ^ (prev[i] if i < len(prev) else raw[i - len(k)] if i >= len(k) else 0)
                    chain.append(x)
                out.append(("xor_chain", bytes(chain).decode("latin-1")))
                pv, ch2 = k[-1], []
                for c in raw:
                    ch2.append(c ^ pv)
                    pv = c
                out.append(("xor_chain1", bytes(ch2).decode("latin-1")))
                out.append(("xor_key", _rep_xor(raw, k).decode("latin-1")))
        if all(c.upper() in HEXU for c in key) and key:
            for mode in (1, -1):
                res = []
                j = 0
                for c in t:
                    if c.upper() in HEXU:
                        res.append(HEXU[(HEXU.index(c.upper()) - mode * HEXU.index(key[j % len(key)].upper())) % 16])
                        j += 1
                    else:
                        res.append(c)
                out.append((f"vig16_{mode}", "".join(res)))
    return out


def rail_decode(ct, rails):
    n = len(ct)
    pattern = []
    r, step = 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    counts = [pattern.count(i) for i in range(rails)]
    rows, pos = [], 0
    for c in counts:
        rows.append(list(ct[pos:pos + c]))
        pos += c
    return "".join(rows[r].pop(0) for r in pattern)


def ans_values(text, prefix="ANS-"):
    out = [m.group().upper() for m in ANS_RE.finditer(text)]
    for m in re.finditer(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16}(?![0-9A-Fa-f])", text):
        out.append(prefix + m.group().upper())
    return out


def expert_ans(spec, env, pool):
    if spec.form != "ans":
        return
    plain = env.plain_members()
    for name, b in list(plain.items())[:400]:
        if env.time_left() <= 0:
            return
        for m in ANS_RE.finditer(as_text(b[:MAX_MEMBER])):
            pool.add("ans:literal", m.group().upper(), 20)
        if len(b) > 1 << 20:
            continue
        if name.endswith(".json") or (b[:1] in (b"{", b"[") and printable_ratio(b[:512]) > 0.95):
            try:
                obj = json.loads(b.decode("utf-8", "replace"))
            except ValueError:
                obj = None
            if obj is not None:
                flat = list(flatten_json(obj))
                params = [v for k, v in flat if isinstance(v, (int, str)) and not (isinstance(v, str) and len(v) > 64)]
                prefix = next((v for k, v in flat if isinstance(v, str) and re.fullmatch(r"[A-Z]{2,5}-", v)), "ANS-")
                for k, v in flat:
                    if not isinstance(v, str) or len(v) < 8:
                        continue
                    for how, t in param_decodes(v, params) + [(f"{nm}", c) for nm, c in single_decodes(v)]:
                        for a in ans_values(t, prefix):
                            pool.add(f"ans_puzzle:{k}:{how}"[:60], a, 16 if a in t else 13)
            continue
        if not re.search(r"\.(txt|xml|properties|cfg|dat|bin)$", name) and b[:4] != b"dex\n":
            continue
        for _, st in strings_of(b, 8)[:1500]:
            if env.time_left() <= 0:
                return
            for how, t in one_step(st):
                for m in ANS_RE.finditer(t):
                    pool.add(f"ans:{how}", m.group().upper(), 12)


# ---------------------------------------------------------------------------------------------------------
# the driver


_FAMILIES = []


def families():
    """solvers/common/proposer_families.py (the families build), loaded by path beside this file and bound to THIS
    module, so a bench-loaded copy shares its caches; None when `CTF_PROPOSER_FAMILIES=off` or it does not load."""
    if ctf_env.get("CTF_PROPOSER_FAMILIES", "").lower() == "off":
        return None
    if not _FAMILIES:
        mod = None
        try:
            import importlib.util
            path = Path(__file__).resolve().parent / "proposer_families.py"
            spec = importlib.util.spec_from_file_location(f"proposer_families_{abs(hash(__name__))}", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            this = sys.modules.get(__name__)
            if this is None or getattr(this, "propose_one", None) is not propose_one:
                import types
                this = types.SimpleNamespace(**globals())   # loaded by path, not registered: its globals
            mod.E = this
        except Exception as e:
            print(f"proposer_enum: proposer_families.py did not load: {type(e).__name__}: {e}", file=sys.stderr)
            mod = None
        _FAMILIES.append(mod)
    return _FAMILIES[0]


def propose_one(q, env, ctx):
    spec = Spec(q, ctx)
    pool = Pool(spec, (ctx.get("rejected") or {}).get(spec.qid))
    shipped = (ctx.get("shipped") or {}).get(spec.qid) or {}
    for i, o in enumerate(shipped.get("options") or []):
        if isinstance(o, (list, tuple)) and len(o) == 2:
            pool.add(f"shipped:{o[0]}", o[1], 26 - 1.0 * i)
    members = members_for(spec, env)
    fam = families()
    if fam:
        fam.before(spec, env, pool, members, ctx)
    for ex in (expert_enum, expert_attack, expert_text, expert_facts, expert_symbols, expert_layout):
        if env.time_left() <= 0:
            break
        pool.where = f"members {','.join(members[:3])}{'...' if len(members) > 3 else ''} > {ex.__name__[7:]}"
        try:
            ex(spec, env, pool, members)
        except Exception as e:   # one expert's failure costs only its candidates
            print(f"proposer_enum: {ex.__name__} on {spec.qid}: {type(e).__name__}: {e}", file=sys.stderr)
    for ex in (expert_digest_order, expert_slug, expert_ans):
        if env.time_left() <= 0:
            break
        pool.where = ex.__name__[7:]
        try:
            ex(spec, env, pool)
        except Exception as e:
            print(f"proposer_enum: {ex.__name__} on {spec.qid}: {type(e).__name__}: {e}", file=sys.stderr)
    if spec.form == "int_or_none" or "literal none" in spec.low or "use the literal none" in spec.syntax.lower():
        pool.add("absent_none", "none", 5)
    if fam:
        fam.after(spec, env, pool, members, ctx)
    out = pool.ranked()
    sink = ctx.get("_score_sink")
    if isinstance(sink, dict):   # the two-tier proposer reads how strong the best evidence was
        sink[spec.qid] = max((r[0] for r in pool.items.values()), default=None)
    if ctf_env.get("CTF_PROPOSER_ENUM_DEBUG"):
        for sc, nm, v, _, _ in sorted(pool.items.values(), key=lambda r: -r[0])[:16]:
            print(f"   {sc:7.2f} {nm} => {v[:100]}", file=sys.stderr)
    return out


def propose(questions, files, ctx, deadline):
    """{qid: [(hypothesis_name, value), ...]} for ctx["open"], ranked best first, at most 12 each."""
    return {qid: [(c[0], c[1]) for c in cands] for qid, cands in propose_full(questions, files, ctx, deadline).items()}


def propose_full(questions, files, ctx, deadline):
    """{qid: [(hypothesis_name, value, score, provenance), ...]}: propose() with each candidate's evidence score and
    its source chain (`member a.ps1 > b64 > xor 0x5a > kv mutex=`), for tools/propose.py's proposals.json."""
    want = set(ctx.get("open") or [])
    ctx = dict(ctx)
    ctx["_set_text"] = " ".join((q.get("question") or q.get("text") or "") for q in questions)[:200000]
    env = Env(files, ctx, deadline)
    out = {}
    todo = [q for q in questions if q.get("qid") in want]
    for i, q in enumerate(todo):
        if time.time() > deadline - MARGIN:
            break
        # every open question gets a fair share of what is left, so a slow one cannot starve the rest
        share = (deadline - MARGIN - time.time()) / max(1, len(todo) - i)
        env.deadline = min(deadline, time.time() + max(share * 2.0, 0.3) + MARGIN)
        try:
            cands = propose_one(q, env, ctx)
        except Exception as e:
            print(f"proposer_enum: {q.get('qid')}: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if cands:
            out[q["qid"]] = cands[:MAX]
    return out


def as_candidates(lane_prefix, qid, cands):
    """The production form: an unsure `labels.candidates` value (row 346), never plain."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import labels
    field = re.sub(r"[^a-z0-9_]+", "_", re.sub(r"-\d{3}-", "-", re.sub(r"^set\d+\.", "", qid)).lower())[:60]
    return labels.candidates(f"{lane_prefix}.{field}/proposer_enum", [tuple(c[:2]) for c in cands])


LANE_PREFIX = {"script-analysis": "script", "binary-reverse-engineering": "binary", "warmups": "warmups",
               "mobile-android": "mobile", "metadata-forensics": "metadata"}


def main(argv=None) -> int:
    """Offline: the candidates for the open ids of a saved attempt folder (no Game Master request).

      .venv/bin/python -I solvers/common/proposer_enum.py ATTEMPT_DIR [--ids ID,ID] [--budget S] [--lane LANE]

    Open ids are the ones `gaps.json` lists as missing, bad or unsure (else every id). Prints one JSON object
    {answer_id: [[hypothesis, value], ...]}, for an agent to read or to pass to labels.candidates in a
    day_patch.py. Nothing here is ever a plain answer."""
    import argparse
    import contextlib as _cl
    ap = argparse.ArgumentParser(description="candidates for the open ids of a saved attempt folder (offline)")
    ap.add_argument("attempt_dir")
    ap.add_argument("--ids")
    ap.add_argument("--budget", type=float, default=20.0)
    ap.add_argument("--lane", default="")
    a = ap.parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / "tools"))
    import run as runner
    with _cl.redirect_stdout(sys.stderr):
        attempt, blobs, _ = runner.load_offline("", a.attempt_dir)
        sets = runner.split_sets(attempt, blobs)
    want = set(a.ids.split(",")) if a.ids else None
    if want is None:
        gp = Path(a.attempt_dir) / "gaps.json"
        if gp.is_file():
            try:
                g = json.loads(gp.read_text())
                want = set(g.get("missing") or []) | set(g.get("bad") or []) | {
                    i for k in (g.get("open") or {}).values() if isinstance(k, dict) for i in (k.get("ids") or [])}
            except (ValueError, AttributeError, TypeError):
                want = None
    lane = a.lane or next((ln for ln in LANE_PREFIX if ln in str(Path(a.attempt_dir).resolve())), "")
    out = {}
    for n, qs, files, ctx in sets:
        open_q = [q for q in qs if not want or q["answer_id"] in want]
        if not open_q:
            continue
        ctx = dict(ctx, lane=lane, open=[q["qid"] for q in open_q], shipped={}, rejected={}, budget_s=a.budget)
        got = propose(qs, files, ctx, time.time() + a.budget)
        for q in open_q:
            if got.get(q["qid"]):
                out[q["answer_id"]] = [list(x) for x in got[q["qid"]]]
    print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
