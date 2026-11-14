#!/usr/bin/env python3
"""Toolkit `ransom_keystream` (B-135): undo a toy ransomware's PRNG keystream by searching seed forms.

The shape it closes (CSCTF 9073, rebuilt synthetically in the tests): files `*.enc` XORed with a PRNG
keystream whose seed mixes the encryption time and the encryptor's PID, e.g. ((time ^ pid) * 0x9e3779b1)
mod 2^32 into xorshift32, one 4-byte keystream word per 4-byte block, the PRNG state shared across the
files in alphasort order. The time is in the ciphertexts' mtimes, the PID in a log line.

What it searches, tier by tier, stopping after the first tier that gives a flag:

  times   0 exact: ciphertext mtimes from the sweep's ext-listing.json (ctf/recover/extfs.py), zip
            members' UTC extra timestamps, and `times=`; each +/- `window` seconds (default 2)
          1 logs: timestamps in log/text files (a minute stamp covers its 60 seconds), epoch numbers,
            zip members' DOS times, read as UTC
          2 the same log times shifted by every whole hour from -12 to +14 (a local-time log)
  pids    `name[1234]`, `pid=1234`, `PID 1234` in the same files, and `pids=`
  forms   time, pid, time^pid, time+pid, time^(pid<<16), and for each multiplier K: time*K, (time^pid)*K,
          (time+pid)*K, (time*K)^pid, time^(pid*K), all mod 2^32. K: a table of common mixing constants
          plus every `imul r32, r32, imm32` constant in an ELF of the handout (the sweep's carves from
          free blocks included) and every hex constant in B-011's pseudocode (recon/decompile/)
  PRNGs   glibc srand/rand, xorshift32 and xorshift64 (13/17/5, 13/7/17, plus shift triples read from
          the same ELFs and pseudocode), msvcrt rand, MT19937 init_genrand, Python random.Random(seed);
          each as one low byte per output or as a whole little-endian output word per block
  layout  each file alone from the seed, and one stream across the files in alphasort (basename, then
          path), mtime and listing order; a file takes ceil(len / unit) outputs

A candidate is checked on the first 16 bytes of every ciphertext at once (numpy over a batch of seeds),
gated by what the original name says the plaintext is: text (all printable), a format with a magic, or
unknown (printable, or a known magic). Survivors are decrypted in full; a decryption is plausible when
every file whose type is known reads as that type. The event's flag format (ctf.flagfmt) is then searched
in the plaintexts. Decrypted files land in recon/ransom_keystream/.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  search(ciphers, times, pids, ff, ...) -> Search             the same over in-memory inputs
  hints_from_elf(data) / hints_from_text(text) -> Hints       multipliers and shift triples

  .venv/bin/python solvers/toolkits/ransom_keystream.py DIR [--event SLUG] [--time T]... [--pid P]...
        [--generators g1,g2] [--cpu-seconds S]

Options (`--opt key=value` through `python -m ctf run`): times, pids (comma lists), window, generators,
cpu_seconds (CPU-time budget, default 120), max_seeds (per tier, default 4,000,000), crib (plaintext
every candidate's first file must start with).

Status: a flag in a plausible decryption -> `solved` (one distinct flag) or `candidate` (several);
a plausible decryption with no flag -> `unsure`; nothing -> `none`, or `unsure` when the CPU budget or
the seed cap stopped the search. No seed candidate at all -> `blocked`, naming what to give. Never
executes the encryptor: its constants are read from bytes. Submits nothing.
"""
from __future__ import annotations

import argparse
import calendar
import datetime as dt
import hashlib
import json
import os
import random
import re
import struct
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:            # pragma: no cover - run as a script outside the repo root
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

ENGINE = "toolkits.ransom_keystream"
M32 = 0xFFFFFFFF
SUFFIXES = (".enc", ".encrypted", ".locked", ".crypt", ".crypted", ".crypto", ".ransom", ".lck")
LISTING = "ext-listing.json"          # ctf/recover/extfs.LISTING
PREFIX = 16                           # bytes of every ciphertext checked per candidate
BATCH = 1 << 15
MAX_FILE = 64 << 20
MAX_TEXT = 4 << 20
MAX_TEXT_TOTAL = 64 << 20
MAX_LOG_STAMPS = 256                  # read per file
LOG_STAMPS = 64                       # distinct stamps searched in tier 1
TZ_STAMPS = 8                         # of those, the ones also searched at every whole-hour offset
DEFAULT_CPU = 120.0
DEFAULT_MAX_SEEDS = 4_000_000
TZ_HOURS = tuple(h for h in range(-12, 15) if h)

# Common 32-bit mixing multipliers: golden ratio (Knuth, both spellings), murmur3 fmix, murmur2,
# FNV-1 32 prime, ANSI C/glibc LCG, Marsaglia, MT19937 init, xxhash prime 2 and 3.
MULTIPLIERS = (0x9E3779B1, 0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x5BD1E995, 0x01000193, 0x41C64E6D, 69069,
               0x6C078965, 0x27D4EB2F, 0x165667B1)
TEXT_EXT = {".txt", ".cfg", ".conf", ".ini", ".json", ".xml", ".yaml", ".yml", ".csv", ".log", ".md", ".html",
            ".htm", ".py", ".sh", ".js", ".toml", ".env", ".sql", ".c", ".h", ".properties", ".pem", ".service"}
MAGIC = {".png": b"\x89PNG\r\n\x1a\n", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff", ".gif": b"GIF8",
         ".pdf": b"%PDF-", ".zip": b"PK\x03\x04", ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04",
         ".pptx": b"PK\x03\x04", ".jar": b"PK\x03\x04", ".gz": b"\x1f\x8b", ".sqlite": b"SQLite format 3\x00",
         ".db": b"SQLite format 3\x00", ".bmp": b"BM", ".7z": b"7z\xbc\xaf\x27\x1c", ".elf": b"\x7fELF"}
KNOWN_MAGICS = tuple(sorted({m for m in MAGIC.values() if len(m) >= 4}, key=len, reverse=True))  # >= 32 bits


class NoNumpy(RuntimeError):
    pass


def _np():
    try:
        import numpy
    except ImportError as e:            # pragma: no cover - numpy is pinned in requirements.in
        raise NoNumpy("numpy is not installed: uv pip install numpy into the venv") from e
    return numpy


# ----------------------------------------------------------------------------- inputs
@dataclass
class Cipher:
    name: str                         # basename, ransom suffix included
    path: str                         # where it was read, relative to the challenge folder
    data: bytes
    mtime: int | None = None          # from a filesystem listing or a zip's UTC extra field
    order: int = 0                    # position in the listing (directory order), else discovery order

    @property
    def original(self) -> str:
        n = self.name
        for s in SUFFIXES:
            if n.lower().endswith(s):
                return n[: -len(s)]
        return n

    @property
    def expect(self) -> str | bytes:
        ext = os.path.splitext(self.original.lower())[1]
        if ext in TEXT_EXT:
            return "text"
        return MAGIC.get(ext, "unknown")


@dataclass(frozen=True)
class TimeCand:
    t: int
    source: str                       # what gave it: "mtime a.cfg.enc", "log var/log/x.log:3 +0h", ...


@dataclass
class Hints:
    multipliers: set = field(default_factory=set)
    triples32: set = field(default_factory=set)
    triples64: set = field(default_factory=set)
    sources: list = field(default_factory=list)

    def merge(self, other: "Hints") -> None:
        self.multipliers |= other.multipliers
        self.triples32 |= other.triples32
        self.triples64 |= other.triples64
        self.sources += other.sources


def _good_multiplier(v: int) -> bool:
    return v >= 0x10000 and v & 1 and 8 <= bin(v).count("1") <= 24


_IMUL = re.compile(rb"\x69([\xc0-\xff])(.{4})", re.S)
_SHIFT = re.compile(rb"\xc1([\xe0-\xef])(.)", re.S)


def _triples(seq: list[tuple[str, int]]) -> tuple[set, set]:
    t32, t64 = set(), set()
    for i in range(len(seq) - 2):
        (d1, a), (d2, b), (d3, c) = seq[i:i + 3]
        if d1 == d3 != d2 and d1 == "L":
            if max(a, b, c) < 32 and min(a, b, c) > 0:
                t32.add((a, b, c))
            if max(a, b, c) < 64 and min(a, b, c) > 0:
                t64.add((a, b, c))
    return t32, t64


def hints_from_elf(data: bytes, label: str = "") -> Hints:
    """Multipliers (x86 `imul r32, r/m32, imm32` with a register operand) and xorshift triples (three
    consecutive `shl/shr r, imm8` within 48 bytes, left-right-left) from an ELF's bytes. Static only."""
    h = Hints()
    if data[:4] != b"\x7fELF":
        return h
    for m in _IMUL.finditer(data):
        v = struct.unpack("<I", m.group(2))[0]
        if _good_multiplier(v):
            h.multipliers.add(v)
    shifts, last = [], None
    for m in _SHIFT.finditer(data):
        if last is not None and m.start() - last > 48:
            t32, t64 = _triples(shifts)
            h.triples32 |= t32
            h.triples64 |= t64
            shifts = []
        shifts.append(("L" if m.group(1)[0] < 0xE8 else "R", m.group(2)[0]))
        last = m.start()
    t32, t64 = _triples(shifts)
    h.triples32 |= t32
    h.triples64 |= t64
    if h.multipliers or h.triples32:
        h.sources.append(label or "elf")
    return h


_HEX = re.compile(r"0x([0-9a-fA-F]{5,8})\b")
_MULDEC = re.compile(r"\*\s*(\d{6,10})\b")
_CSHIFT = re.compile(r"(<<|>>)\s*(?:0x)?(\d{1,2})\b")


def hints_from_text(text: str, label: str = "") -> Hints:
    """The same from decompiled pseudocode or a disassembly listing: hex constants and `* 123456789`
    multipliers, and `<< a`, `>> b`, `<< c` runs."""
    h = Hints()
    for m in _HEX.finditer(text):
        v = int(m.group(1), 16)
        if _good_multiplier(v):
            h.multipliers.add(v)
    for m in _MULDEC.finditer(text):
        v = int(m.group(1))
        if v <= M32 and _good_multiplier(v):
            h.multipliers.add(v)
    seq = [("L" if m.group(1) == "<<" else "R", int(m.group(2))) for m in _CSHIFT.finditer(text)]
    t32, t64 = _triples(seq)
    h.triples32 |= t32
    h.triples64 |= t64
    if h.multipliers or h.triples32:
        h.sources.append(label or "text")
    return h


_PID_RES = (re.compile(r"\b[A-Za-z_][\w.\-/]*\[(\d{2,7})\]"),
            re.compile(r"\bpid\s*[=:#]?\s*(\d{2,7})\b", re.I))
_STAMP = re.compile(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:[.,]\d+)?"
                    r"\s*(Z|UTC|[+-]\d{2}:?\d{2})?")
_EPOCH = re.compile(r"(?<!\d)(1[5-9]\d{8})(?!\d)")


def pids_from_text(text: str) -> list[int]:
    out = []
    for rx in _PID_RES:
        for m in rx.finditer(text):
            v = int(m.group(1))
            if v > 1 and v not in out:
                out.append(v)
    return out


_KEYWORDS = re.compile(r"encrypt|crypt|ransom|lock|sweep|wip|start", re.I)


def stamps_from_text(text: str, label: str) -> list[tuple[int, int, bool, str, bool]]:
    """[(epoch of the stamp read as UTC, seconds it covers, has an explicit zone, source, on a line that
    names a PID or an encryption word)]."""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        pri = bool(pids_from_text(line) or _KEYWORDS.search(line))
        for m in _STAMP.finditer(line):
            y, mo, d, hh, mm, ss, zone = m.groups()
            try:
                base = calendar.timegm((int(y), int(mo), int(d), int(hh), int(mm), int(ss or 0)))
            except (ValueError, OverflowError):
                continue
            if not 1 <= int(mo) <= 12 or not 1 <= int(d) <= 31 or int(hh) > 23 or int(mm) > 59:
                continue
            explicit = zone is not None
            if zone and zone not in ("Z", "UTC"):
                sign = 1 if zone[0] == "+" else -1
                digits = zone[1:].replace(":", "")
                base -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
            out.append((base, 1 if ss else 60, explicit, f"{label}:{lineno}", pri))
        for m in _EPOCH.finditer(line):
            out.append((int(m.group(1)), 1, True, f"{label}:{lineno} epoch", pri))
    return out


# ----------------------------------------------------------------------------- generators
@dataclass(frozen=True)
class Gen:
    prng: str                          # glibc | xorshift32 | xorshift64 | msvcrt | mt19937 | python
    unit: str                          # byte (low byte of each output) | word (the output, little-endian)
    params: tuple = ()                 # xorshift shift triple

    @property
    def name(self) -> str:
        p = "/".join(map(str, self.params))
        return f"{self.prng}{'(' + p + ')' if p else ''}-{self.unit}"

    @property
    def width(self) -> int:
        """Keystream bytes one output gives."""
        if self.unit == "byte":
            return 1
        return {"xorshift64": 8, "python": 1}.get(self.prng, 4)


def default_gens(h: Hints | None = None) -> list[Gen]:
    t32 = [(13, 17, 5)] + sorted((h.triples32 if h else set()) - {(13, 17, 5)})
    t64 = [(13, 7, 17)] + sorted((h.triples64 if h else set()) - {(13, 7, 17)})
    gens = []
    for t in t32:
        gens += [Gen("xorshift32", "word", t), Gen("xorshift32", "byte", t)]
    gens += [Gen("glibc", "byte"), Gen("glibc", "word"), Gen("msvcrt", "byte")]
    for t in t64:
        gens += [Gen("xorshift64", "word", t), Gen("xorshift64", "byte", t)]
    gens += [Gen("mt19937", "word"), Gen("mt19937", "byte"), Gen("python", "byte")]
    return gens


def _outputs_batch(np, g: Gen, seeds, n: int):
    """(N, n) uint64: the first n outputs of generator g for each seed."""
    N = len(seeds)
    out = np.zeros((N, n), dtype=np.uint64)
    s = seeds.astype(np.uint64) & np.uint64(M32)
    if g.prng == "xorshift32":
        a, b, c = (np.uint64(v) for v in g.params)
        x = s.copy()
        for i in range(n):
            x ^= (x << a) & np.uint64(M32)
            x ^= x >> b
            x ^= (x << c) & np.uint64(M32)
            out[:, i] = x
    elif g.prng == "xorshift64":
        a, b, c = (np.uint64(v) for v in g.params)
        x = s.copy()
        for i in range(n):
            x ^= x << a
            x ^= x >> b
            x ^= x << c
            out[:, i] = x
    elif g.prng == "msvcrt":
        x = s.copy()
        for i in range(n):
            x = (x * np.uint64(214013) + np.uint64(2531011)) & np.uint64(M32)
            out[:, i] = (x >> np.uint64(16)) & np.uint64(0x7FFF)
    elif g.prng == "glibc":
        seed = np.where(s == 0, np.uint64(1), s)
        word = seed.astype(np.int64)
        word = np.where(word >= 1 << 31, word - (1 << 32), word)
        r = [seed.astype(np.int64)]
        for _ in range(30):
            hi = np.where(word < 0, -((-word) // 127773), word // 127773)
            lo = word - hi * 127773
            word = 16807 * lo - 2836 * hi
            word = np.where(word < 0, word + 2147483647, word)
            r.append(word & M32)
        r += r[:3]
        ring = r[:]                          # r[0..33]
        for i in range(34, 344 + n):
            v = (ring[-31] + ring[-3]) & M32                # r[i] = r[i-31] + r[i-3]
            ring.append(v)
            if len(ring) > 40:
                del ring[0]
            if i >= 344:
                out[:, i - 344] = (v >> 1).astype(np.uint64)
    elif g.prng == "mt19937":
        need = set(range(n + 1)) | set(range(397, 397 + n))
        cols = {}
        prev = s.copy()
        cols[0] = prev
        for i in range(1, 397 + n):
            prev = (np.uint64(1812433253) * (prev ^ (prev >> np.uint64(30))) + np.uint64(i)) & np.uint64(M32)
            if i in need:
                cols[i] = prev
        for k in range(n):
            y = (cols[k] & np.uint64(0x80000000)) | (cols[k + 1] & np.uint64(0x7FFFFFFF))
            v = cols[k + 397] ^ (y >> np.uint64(1)) ^ ((y & np.uint64(1)) * np.uint64(0x9908B0DF))
            v ^= v >> np.uint64(11)
            v ^= (v << np.uint64(7)) & np.uint64(0x9D2C5680)
            v ^= (v << np.uint64(15)) & np.uint64(0xEFC60000)
            v ^= v >> np.uint64(18)
            out[:, k] = v
    else:
        raise ValueError(f"no batch model for {g.prng}")
    return out


def keystream_batch(np, g: Gen, seeds, nbytes: int):
    """(N, nbytes) uint8 keystream prefixes."""
    if g.prng == "python":
        rows = [random.Random(int(sd)).randbytes(nbytes) for sd in seeds]
        return np.frombuffer(b"".join(rows), dtype=np.uint8).reshape(len(seeds), nbytes)
    units = -(-nbytes // g.width)
    outs = _outputs_batch(np, g, seeds, units)
    if g.unit == "byte":
        return (outs & np.uint64(0xFF)).astype(np.uint8)[:, :nbytes]
    w = g.width
    le = outs.astype("<u8").view(np.uint8).reshape(len(seeds), units, 8)[:, :, :w]
    return le.reshape(len(seeds), units * w)[:, :nbytes]


class Stream:
    """One seed's keystream, read file by file: a file takes ceil(len / width) outputs."""

    def __init__(self, g: Gen, seed: int):
        self.g, self.seed = g, seed & M32
        if g.prng == "python":
            self.rng = random.Random(self.seed)
        elif g.prng == "mt19937":
            self.rng = _MT(self.seed)
        elif g.prng == "glibc":
            self.r = _glibc_state(self.seed)
        else:
            self.x = self.seed

    def _next(self) -> int:
        p = self.g.prng
        if p == "xorshift32":
            a, b, c = self.g.params
            x = self.x
            x ^= (x << a) & M32
            x ^= x >> b
            x ^= (x << c) & M32
            self.x = x
            return x
        if p == "xorshift64":
            a, b, c = self.g.params
            x = self.x
            x ^= (x << a) & 0xFFFFFFFFFFFFFFFF
            x ^= x >> b
            x ^= (x << c) & 0xFFFFFFFFFFFFFFFF
            self.x = x
            return x
        if p == "msvcrt":
            self.x = (self.x * 214013 + 2531011) & M32
            return (self.x >> 16) & 0x7FFF
        if p == "glibc":
            r = self.r
            v = (r[-31] + r[-3]) & M32
            r.append(v)
            del r[0]
            return v >> 1
        if p == "mt19937":
            return self.rng.next()
        raise ValueError(p)

    def take(self, nbytes: int) -> bytes:
        if self.g.prng == "python":
            return self.rng.randbytes(nbytes)
        w = self.g.width
        units = -(-nbytes // w)
        if self.g.unit == "byte":
            return bytes(self._next() & 0xFF for _ in range(units))[:nbytes]
        return b"".join(self._next().to_bytes(8, "little")[:w] for _ in range(units))[:nbytes]


def _glibc_state(seed: int) -> list[int]:
    """The 34-word ring after srand(seed) with the 310 discarded outputs drawn (see modern_crypto)."""
    r = _mc().glibc_srand_state(seed)
    for i in range(34, 344):
        r.append((r[-31] + r[-3]) & M32)
    return r[-34:]


class _MT:
    def __init__(self, seed: int):
        mt = [seed & M32]
        for i in range(1, 624):
            mt.append((1812433253 * (mt[-1] ^ (mt[-1] >> 30)) + i) & M32)
        self.mt, self.i = mt, 624

    def next(self) -> int:
        if self.i >= 624:
            mt = self.mt
            for k in range(624):
                y = (mt[k] & 0x80000000) | (mt[(k + 1) % 624] & 0x7FFFFFFF)
                mt[k] = mt[(k + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
            self.i = 0
        y = self.mt[self.i]
        self.i += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        return y ^ (y >> 18)


_MC = None


def _mc():
    global _MC
    if _MC is None:
        import importlib.util
        path = Path(__file__).resolve().parents[1] / "common" / "modern_crypto.py"
        spec = importlib.util.spec_from_file_location("b135_modern_crypto", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MC = mod
    return _MC


# ----------------------------------------------------------------------------- seed forms
def forms(multipliers) -> list[tuple[str, bool, object]]:
    """[(name, uses_pid, f(T, p) -> seeds)] over numpy uint64 arrays T and an int p, mod 2^32."""
    out = [("time", False, lambda T, p: T),
           ("pid", True, lambda T, p: T * 0 + p),
           ("time^pid", True, lambda T, p: T ^ p),
           ("time+pid", True, lambda T, p: T + p),
           ("time^(pid<<16)", True, lambda T, p: T ^ (p << 16))]
    for k in multipliers:
        out += [(f"time*{k:#x}", False, lambda T, p, k=k: T * k),
                (f"(time^pid)*{k:#x}", True, lambda T, p, k=k: (T ^ p) * k),
                (f"(time+pid)*{k:#x}", True, lambda T, p, k=k: (T + p) * k),
                (f"(time*{k:#x})^pid", True, lambda T, p, k=k: (T * k) ^ p),
                (f"time^(pid*{k:#x})", True, lambda T, p, k=k: T ^ ((p * k) & M32))]
    return out


@dataclass(frozen=True)
class Prov:
    form: str
    t: int | None
    pid: int | None
    source: str


class Provenance:
    """Which form, time and PID first gave each seed of a table, worked out only when asked."""

    def __init__(self, np, chunks: list, origin):
        self.chunks = chunks                     # [(start, form, pid, times or None)]
        self.starts = np.array([c[0] for c in chunks], dtype=np.int64)
        self.origin = origin                     # unique seed index -> index in the concatenation
        self.np = np

    def __getitem__(self, i: int) -> Prov:
        at = int(self.origin[i])
        k = int(self.np.searchsorted(self.starts, at, side="right")) - 1
        start, form, pid, times = self.chunks[k]
        if times is None:
            return Prov(form, None, pid, "pids")
        c = times[at - start]
        return Prov(form, c.t, pid, c.source)


def seed_table(np, times: list[TimeCand], pids: list[int], multipliers, *, pid_only: bool = True):
    """(unique seeds as uint64 array in discovery order, Provenance: the first form that gave each)."""
    T = np.array([c.t & M32 for c in times], dtype=np.uint64)
    parts, chunks, n = [], [], 0
    for name, uses_pid, f in forms(multipliers):
        if name == "pid":
            if pid_only:
                for p in pids:
                    parts.append(np.array([p & M32], dtype=np.uint64))
                    chunks.append((n, "pid", p, None))
                    n += 1
            continue
        if not len(T):
            continue
        for p in (pids if uses_pid else [None]):
            v = f(T, np.uint64(p if p is not None else 0)) & np.uint64(M32)
            parts.append(v.astype(np.uint64))
            chunks.append((n, name, p, times))
            n += len(v)
    if not parts:
        return np.zeros(0, dtype=np.uint64), Provenance(np, [(0, "", None, None)], np.zeros(0, dtype=np.int64))
    allv = np.concatenate(parts)
    uniq, idx = np.unique(allv, return_index=True)
    order = np.argsort(idx)                  # keep discovery order: exact forms first
    return uniq[order], Provenance(np, chunks, idx[order])


# ----------------------------------------------------------------------------- plausibility
_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\n\r"


def _printable_table(np):
    t = np.zeros(256, dtype=bool)
    t[list(_PRINTABLE)] = True
    return t


def _gate(np, table, plain, expect):
    """Vectorised first-bytes check for a batch: (N,) bool."""
    if expect == "text":
        return table[plain].all(axis=1)
    if isinstance(expect, bytes):
        m = np.frombuffer(expect[: plain.shape[1]], dtype=np.uint8)
        return (plain[:, : len(m)] == m).all(axis=1)
    ok = table[plain].sum(axis=1) >= plain.shape[1] - 1
    for magic in KNOWN_MAGICS:
        m = np.frombuffer(magic[: plain.shape[1]], dtype=np.uint8)
        ok |= (plain[:, : len(m)] == m).all(axis=1)
    return ok


def plausible(data: bytes, expect) -> bool | None:
    """True / False when the expected type says; None for an unknown type that reads as neither."""
    if not data:
        return True
    if expect == "text":
        return sum(b in _PRINTABLE for b in data) / len(data) >= 0.95
    if isinstance(expect, bytes):
        if not data.startswith(expect):
            return False
        return True if len(expect) >= 4 else None          # a 2-byte magic is too weak to vouch alone
    if any(data.startswith(m) for m in KNOWN_MAGICS):
        return True
    if sum(b in _PRINTABLE for b in data) / len(data) >= 0.95:
        return True
    return None


# ----------------------------------------------------------------------------- the search
@dataclass
class Decryption:
    seed: int
    prov: Prov
    gen: Gen
    layout: str                        # "single" or "shared:<order>"
    files: list                        # [(Cipher, plaintext bytes, plausible True/None)]
    flags: list

    def describe(self) -> str:
        p = self.prov
        bits = [f"seed={self.seed:#010x}", f"form={p.form}"]
        if p.t is not None:
            bits.append(f"time={p.t} ({dt.datetime.fromtimestamp(p.t, dt.timezone.utc):%Y-%m-%d %H:%M:%SZ})")
        if p.pid is not None:
            bits.append(f"pid={p.pid}")
        bits += [f"time from {p.source}", f"prng={self.gen.name}", f"layout={self.layout}",
                 "files=" + ",".join(c.name for c, _, _ in self.files)]
        return " ".join(bits)


@dataclass
class Search:
    found: list = field(default_factory=list)       # [Decryption], plausible ones, best first
    tiers: list = field(default_factory=list)       # [(tier name, seeds, gens)]
    truncated: str = ""
    notes: list = field(default_factory=list)
    tried: int = 0                                  # seed x generator pairs checked


def orders(ciphers: list[Cipher]) -> list[tuple[str, list[int]]]:
    idx = list(range(len(ciphers)))
    cand = [("alphasort", sorted(idx, key=lambda i: (ciphers[i].name.encode(), ciphers[i].path))),
            ("path", sorted(idx, key=lambda i: ciphers[i].path.encode())),
            ("mtime", sorted(idx, key=lambda i: (ciphers[i].mtime or 0, ciphers[i].name.encode()))),
            ("listing", sorted(idx, key=lambda i: ciphers[i].order))]
    out, seen = [], set()
    for name, o in cand:
        if tuple(o) not in seen:
            seen.add(tuple(o))
            out.append((name, o))
    return out


def _verify(ciphers, g: Gen, seed: int, prov: Prov, first: int, ff, crib: bytes | None) -> list[Decryption]:
    out = []
    plain = bytes(a ^ b for a, b in zip(ciphers[first].data, Stream(g, seed).take(len(ciphers[first].data))))
    ok = plausible(plain, ciphers[first].expect)
    flags = ff.find_flags(plain)
    if (ok or flags) and ok is not False and (crib is None or plain.startswith(crib)):
        out.append(Decryption(seed, prov, g, "single", [(ciphers[first], plain, ok)], flags))
    if len(ciphers) > 1:
        for oname, o in orders(ciphers):
            if o[0] != first:
                continue
            st = Stream(g, seed)
            files, bad = [], False
            for i in o:
                c = ciphers[i]
                pt = bytes(a ^ b for a, b in zip(c.data, st.take(len(c.data))))
                okc = plausible(pt, c.expect)
                if okc is False:
                    bad = True
                    break
                files.append((c, pt, okc))
            if not bad:
                flags = []
                for _, pt, _ in files:
                    flags += [f for f in ff.find_flags(pt) if f not in flags]
                if not flags and not any(okc for _, _, okc in files):
                    continue
                out.append(Decryption(seed, prov, g, f"shared:{oname}", files, flags))
    return out


def search(ciphers: list[Cipher], tiers: list[tuple[str, list[TimeCand]]], pids: list[int], ff, *,
           gens: list[Gen] | None = None, multipliers=MULTIPLIERS, cpu_seconds: float = DEFAULT_CPU,
           max_seeds: int = DEFAULT_MAX_SEEDS, crib: bytes | None = None, clock=time.process_time) -> Search:
    """Run the tiers in order; stop after the first tier with a decryption that holds a flag."""
    np = _np()
    res = Search()
    if not ciphers:
        res.notes.append("no ciphertext")
        return res
    gens = gens or default_gens()
    table = _printable_table(np)
    start = clock()
    heads = [np.frombuffer(c.data[:PREFIX], dtype=np.uint8) for c in ciphers]
    width = max(len(h) for h in heads)
    seen_pairs, spent = set(), False
    for n_tier, (tier_name, times) in enumerate(tiers):
        if n_tier and not times:
            continue
        seeds, provs = seed_table(np, times, pids, multipliers, pid_only=n_tier == 0)
        if len(seeds) > max_seeds:
            res.notes.append(f"tier {tier_name}: {len(seeds)} seeds over the cap of {max_seeds}; the first "
                             f"{max_seeds} searched")
            res.truncated = res.truncated or f"seed cap {max_seeds} in tier {tier_name}"
            seeds = seeds[:max_seeds]
        res.tiers.append((tier_name, len(seeds), len(gens)))
        if not len(seeds):
            continue
        for g in gens:
            for lo in range(0, len(seeds), BATCH):
                if clock() - start > cpu_seconds:
                    res.truncated = f"CPU budget of {cpu_seconds:g} s spent in tier {tier_name} at {g.name}"
                    spent = True
                    break
                batch = seeds[lo:lo + BATCH]
                ks = keystream_batch(np, g, batch, width)
                res.tried += len(batch)
                for j, (c, head) in enumerate(zip(ciphers, heads)):
                    plain = ks[:, : len(head)] ^ head
                    mask = _gate(np, table, plain, c.expect)
                    if crib:
                        m = np.frombuffer(crib[: len(head)], dtype=np.uint8)
                        mask &= (plain[:, : len(m)] == m).all(axis=1)
                    hits = np.nonzero(mask)[0]
                    if len(hits) > 64:
                        res.notes.append(f"{c.name}: {len(hits)} seeds of one batch pass its {PREFIX}-byte gate "
                                         f"under {g.name}; only the first 64 were decrypted (pass crib=)")
                    for k in hits[:64]:
                        sd = int(batch[k])
                        if (g, sd, j) in seen_pairs:
                            continue
                        seen_pairs.add((g, sd, j))
                        res.found += _verify(ciphers, g, sd, provs[lo + int(k)], j, ff, crib)
            if spent:
                break
        if any(d.flags for d in res.found) or spent:
            break
    res.found.sort(key=lambda d: (not d.flags, -sum(1 for _, _, ok in d.files if ok), -len(d.files)))
    return res


# ----------------------------------------------------------------------------- gathering
_SKIP = {"recon", ".git", ".ctf"}


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames
                             if not (here == root and d in _SKIP) and d not in (".git", ".ctf")
                             and not (here / d).is_symlink())
        for n in sorted(filenames):
            f = here / n
            if not f.is_symlink() and f.is_file():
                yield f


def _is_cipher_name(name: str) -> bool:
    return name.lower().endswith(SUFFIXES)


def _zip_times(data: bytes, label: str) -> tuple[list[TimeCand], list[TimeCand], dict]:
    """Exact (UTC extra field) and DOS-time candidates of a zip's ransom-suffixed members; also
    {member name: exact mtime}."""
    import io
    exact, local, by = [], [], {}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError):
        return exact, local, by
    for info in z.infolist()[:4096]:
        if not _is_cipher_name(info.filename):
            continue
        ex, pos = info.extra, 0
        while pos + 4 <= len(ex):
            hid, size = struct.unpack_from("<HH", ex, pos)
            if hid == 0x5455 and size >= 5 and ex[pos + 4] & 1:
                t = struct.unpack_from("<I", ex, pos + 5)[0]
                exact.append(TimeCand(t, f"zip UT mtime {label}:{info.filename}"))
                by[os.path.basename(info.filename)] = t
            pos += 4 + size
        try:
            t = calendar.timegm(info.date_time + (0, 0, 0))
        except (ValueError, OverflowError):
            continue
        local.append(TimeCand(t, f"zip DOS time {label}:{info.filename}"))
    return exact, local, by


@dataclass
class Gathered:
    ciphers: list = field(default_factory=list)
    exact: list = field(default_factory=list)       # [TimeCand]
    logged: list = field(default_factory=list)      # [(epoch, span, explicit zone, source)]
    pids: list = field(default_factory=list)
    hints: Hints = field(default_factory=Hints)
    notes: list = field(default_factory=list)


def gather(challenge_dir: Path) -> Gathered:
    """Ciphertexts, time and PID candidates and binary hints under a challenge folder: files/, the sweep's
    scratch copy unpacked/ (ext files, listings and carves) and recon/decompile/ pseudocode."""
    out = Gathered()
    mt_by_path: dict[Path, tuple[int, int]] = {}
    zip_by_name: dict[str, int] = {}
    files = list(_walk(challenge_dir))
    for f in files:
        if f.name == LISTING:
            try:
                doc = json.loads(f.read_bytes()[:MAX_TEXT])
            except (OSError, ValueError):
                out.notes.append(f"{f.relative_to(challenge_dir)}: not JSON")
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("files", []), list):
                out.notes.append(f"{f.relative_to(challenge_dir)}: not an ext listing (want a JSON object whose "
                                 f"'files' is a list); its mtimes are not used")
                continue
            for n, row in enumerate(doc.get("files", [])):
                if isinstance(row, dict) and isinstance(row.get("mtime"), int) and isinstance(row.get("path"), str):
                    mt_by_path[(f.parent / "ext" / row["path"]).resolve()] = (row["mtime"], n)
    seen_sha: dict[str, Cipher] = {}
    text_total = 0
    for f in files:
        rel = f.relative_to(challenge_dir).as_posix()
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if _is_cipher_name(f.name):
            if size > MAX_FILE:
                out.notes.append(f"{rel}: {size} bytes, over {MAX_FILE}: not read")
                continue
            data = f.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            got = mt_by_path.get(f.resolve())
            c = seen_sha.get(sha)
            if c is None:
                c = Cipher(f.name, rel, data, order=len(seen_sha) + 10_000)
                seen_sha[sha] = c
                out.ciphers.append(c)
            if got and c.mtime is None:
                c.mtime, c.order, c.path = got[0], got[1], rel
            continue
        head = b""
        try:
            with open(f, "rb") as fh:
                head = fh.read(8)
        except OSError:
            continue
        if head[:4] == b"PK\x03\x04" and size <= 256 << 20:
            ex, local, by = _zip_times(f.read_bytes(), rel)
            out.exact += ex
            out.logged += [(c.t, 2, False, c.source, True) for c in local]
            zip_by_name.update(by)
            continue
        if head[:4] == b"\x7fELF" and size <= MAX_FILE:
            out.hints.merge(hints_from_elf(f.read_bytes(), rel))
            continue
        if f.name in (LISTING, ".sweep.json", ".sweep-owner"):
            continue
        if size > MAX_TEXT or text_total + size > MAX_TEXT_TOTAL:
            continue
        data = f.read_bytes()
        if b"\x00" in data[:4096] or not data:
            continue
        text_total += size
        text = data.decode("utf-8", "replace")
        out.pids += [p for p in pids_from_text(text) if p not in out.pids]
        out.logged += stamps_from_text(text, rel)[:MAX_LOG_STAMPS]
    # pseudocode from B-011 (recon/ is skipped by the walk above)
    dec = challenge_dir / "recon" / "decompile"
    if dec.is_dir():
        for f in _walk(dec):
            if f.suffix == ".c" and f.stat().st_size <= MAX_TEXT:
                out.hints.merge(hints_from_text(f.read_text("utf-8", "replace"),
                                                f.relative_to(challenge_dir).as_posix()))
    for c in out.ciphers:
        if c.mtime is None and c.name in zip_by_name:
            c.mtime = zip_by_name[c.name]
        if c.mtime is not None:
            out.exact.append(TimeCand(c.mtime, f"mtime {c.path}"))
    return out


def _spread(cands: list[TimeCand], window: int) -> list[TimeCand]:
    out, seen = [], set()
    for d in sorted(range(-window, window + 1), key=abs):
        for c in cands:
            t = c.t + d
            if t not in seen:
                seen.add(t)
                out.append(TimeCand(t, c.source + (f" {d:+d}s" if d else "")))
    return out


def build_tiers(g: Gathered, times: list[int], window: int) -> list[tuple[str, list[TimeCand]]]:
    """exact (given times and mtimes +/- window), logs (stamps as UTC over the span they cover), logs-tz
    (the TZ_STAMPS best stamps with no zone, at every whole-hour offset). Stamps on a line that names a
    PID or an encryption word come first; at most LOG_STAMPS distinct ones are used."""
    exact = _spread([TimeCand(t, "times=") for t in times] + g.exact, window)
    logs, shifted, seen = [], [], set()
    stamps = sorted(g.logged, key=lambda s: not s[4])            # stable: file order within a priority
    picked = []
    for s in stamps:
        if (s[0], s[1]) not in seen:
            seen.add((s[0], s[1]))
            picked.append(s)
    for n, (base, span, explicit, src, _pri) in enumerate(picked[:LOG_STAMPS]):
        rng = range(0, span) if span > 1 else range(-window, window + 1)
        for d in rng:
            logs.append(TimeCand(base + d, src))
        if not explicit and n < TZ_STAMPS:
            for h in TZ_HOURS:
                for d in rng:
                    shifted.append(TimeCand(base + d - h * 3600, f"{src} read as UTC{h:+d}"))
    return [("exact", exact), ("logs", _dedupe(logs, exact)), ("logs-tz", _dedupe(shifted, exact + logs))]


def _dedupe(cands: list[TimeCand], before: list[TimeCand]) -> list[TimeCand]:
    seen = {c.t for c in before}
    out = []
    for c in cands:
        if c.t not in seen:
            seen.add(c.t)
            out.append(c)
    return out


# ----------------------------------------------------------------------------- the engine
def _ints(value) -> list[int]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [int(v, 0) if isinstance(v, str) else int(v) for v in value]
    return [int(v, 0) for v in str(value).replace(";", ",").split(",") if v.strip()]


def _safe(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "file"
    return s[:120]


def solve(challenge_dir, profile, **opts):
    from ctf.result import Cost, Evidence, SolverResult

    started = time.process_time()
    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    window = int(opts.get("window", 2))
    times = _ints(opts.get("times"))
    try:
        _np()
    except NoNumpy as e:
        return SolverResult(status="blocked", engine=ENGINE, notes=str(e))
    g = gather(challenge_dir)
    pids = _ints(opts.get("pids")) + [p for p in g.pids if p not in _ints(opts.get("pids"))]
    if not g.ciphers:
        return SolverResult(status="none", engine=ENGINE,
                            notes=f"no ciphertext file (names ending {', '.join(SUFFIXES)}) under {challenge_dir}"
                                  + ("; " + "; ".join(g.notes) if g.notes else ""))
    tiers = build_tiers(g, times, window)
    if not any(t for _, t in tiers) and not pids:
        return SolverResult(status="blocked", engine=ENGINE, notes=(
            f"{len(g.ciphers)} ciphertext(s) but no seed-time or PID candidate: no mtime in an "
            f"{LISTING} (run `ctf sweep` on the disk image first), no timestamp or PID in a log; "
            f"give times=<epoch,...> and/or pids=<n,...>"))
    mults = list(MULTIPLIERS) + sorted(g.hints.multipliers - set(MULTIPLIERS))
    gens = default_gens(g.hints)
    want = opts.get("generators")
    if want:
        names = {w.strip() for w in str(want).split(",") if w.strip()}
        gens = [x for x in gens if x.name in names or f"{x.prng}-{x.unit}" in names or x.prng in names]
        if not gens:
            return SolverResult(status="blocked", engine=ENGINE,
                                notes=f"generators={want!r} names no known generator "
                                      f"({', '.join(sorted({x.name for x in default_gens(g.hints)}))})")
    crib = opts.get("crib")
    crib_b = crib.encode() if isinstance(crib, str) and crib else None
    res = search(g.ciphers, tiers, pids, ff, gens=gens, multipliers=mults,
                 cpu_seconds=float(opts.get("cpu_seconds", DEFAULT_CPU)),
                 max_seeds=int(opts.get("max_seeds", DEFAULT_MAX_SEEDS)), crib=crib_b)
    notes = list(g.notes) + res.notes
    space = "; ".join(f"{n}: {s} seeds x {k} generators" for n, s, k in res.tiers)
    hint_note = (f"hints from {', '.join(g.hints.sources[:5])}: multipliers "
                 f"{', '.join(hex(m) for m in sorted(g.hints.multipliers)[:8])}"
                 f"{', xorshift ' + ', '.join(map(str, sorted(g.hints.triples32)[:4])) if g.hints.triples32 else ''}"
                 if g.hints.sources else "no constant read from a binary or pseudocode")
    cost = Cost(seconds=round(time.process_time() - started, 3))
    if not res.found:
        status = "unsure" if res.truncated else "none"
        why = f"stopped: {res.truncated}; " if res.truncated else ""
        return SolverResult(status=status, engine=ENGINE, cost=cost, notes=(
            f"{why}no plausible decryption of {len(g.ciphers)} ciphertext(s) over {space}; pids "
            f"{pids or 'none found'}; {hint_note}" + ("; " + "; ".join(notes[:6]) if notes else "")))
    best = res.found[0]
    out_dir = challenge_dir / "recon" / "ransom_keystream"
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence, taken = [], {"seed.json"}
    for c, pt, _ok in best.files:
        name = _safe(c.original)
        if name in taken:              # same basename in another folder (or "seed.json"): prefix its path's hash
            name = f"{hashlib.sha256(c.path.encode()).hexdigest()[:8]}-{name}"
        taken.add(name)
        target = out_dir / name
        target.write_bytes(pt)
        evidence.append(Evidence("decode", f"{c.path} decrypted: {best.describe()}",
                                 path=target.relative_to(challenge_dir).as_posix()))
    (out_dir / "seed.json").write_text(json.dumps({
        "seed": best.seed, "form": best.prov.form, "time": best.prov.t, "pid": best.prov.pid,
        "time_source": best.prov.source, "prng": best.gen.name, "layout": best.layout,
        "files": [c.path for c, _, _ in best.files]}, indent=1) + "\n")
    flags = []
    for d in res.found:
        for f in d.flags:
            if f not in flags:
                flags.append(f)
    summary = f"{best.describe()}; searched {space}; {hint_note}"
    if flags:
        status = "solved" if len(flags) == 1 else "candidate"
        return SolverResult(status=status, flags=flags, evidence=evidence, engine=ENGINE, cost=cost,
                            notes=summary)
    return SolverResult(status="unsure", evidence=evidence, engine=ENGINE, cost=cost,
                        notes=f"plausible decryption, no flag in the event's format: read "
                              f"{out_dir.relative_to(challenge_dir)}/; {summary}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ransom_keystream.py", description=__doc__.split("\n")[0])
    ap.add_argument("challenge_dir")
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--time", action="append", default=[], help="a seed time (epoch seconds)")
    ap.add_argument("--pid", action="append", default=[], help="a candidate PID")
    ap.add_argument("--window", type=int, default=2)
    ap.add_argument("--generators", default="")
    ap.add_argument("--cpu-seconds", type=float, default=DEFAULT_CPU)
    ap.add_argument("--crib", default="")
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    r = solve(a.challenge_dir, profile, times=",".join(a.time), pids=",".join(a.pid), window=a.window,
              generators=a.generators, cpu_seconds=a.cpu_seconds, crib=a.crib)
    print(r.to_json(indent=1))
    return 0 if r.status != "blocked" else 2


if __name__ == "__main__":
    raise SystemExit(main())
