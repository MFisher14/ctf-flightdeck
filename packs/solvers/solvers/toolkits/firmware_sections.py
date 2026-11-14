#!/usr/bin/env python3
"""Firmware section-table walker (B-069): the table, then the readers the tree already has.

A vendor firmware bundle is a header, a table of sections (name, offset, size, checksum) and the
sections. The header differs per vendor; what does not differ is that a record names a byte range
of the same file and its CRC. So the table is found by that property, not by a magic:

  find_tables(data)   every run of fixed-size records in the first 64 KiB whose (offset, size) words
                      name a range inside the file and whose checksum word equals the CRC-32 of that
                      range (IEEE, or the same without the final inversion; either byte order; the
                      three fields anywhere within 60 bytes of each other). One confirmed record is
                      a 2**-32 coincidence; the record stride comes from two confirmed neighbours.
                      A record on the stride whose range is in bounds but whose CRC does NOT match
                      is listed with crc_ok False, so the per-entry CRC is a result, not a filter.

Each section then goes to the existing readers; nothing is re-implemented here:

  U-Boot env          firmware_walk.env_copies() over the whole image (an env need not sit on a
                      section boundary): both copies of a redundant env, each behind its own CRC,
                      and firmware_walk.pick_live_env() takes the live one by the flags counter.
  zlib FDICT          a section whose Adler-32 is the DICTID of a preset-dictionary zlib stream in
                      the image is that stream's dictionary: those sections are passed to
                      carving.carve_all(zlib_dictionaries=...), which confirms the stream to its
                      Adler-32 and end. gzip, bzip2, xz and plain zlib streams come from the same call.
  cpio                carve_stego_fs.cpio() on every section and inflated payload that is one.
  other containers    firmware_walk's SquashFS / JFFS2 / UBI / DTB readers on every section.

Flags (ctf.flagfmt) are read from the sections, the inflated payloads, the archive members and the
CRC-valid env values. Last, one lead that stays unsure: a hex or base64 token found in the extracted
files is XORed (repeating key) with every value of every CRC-valid env copy (as text, as a
MAC / hex string). Nothing says the token and the variable belong together, so a result counts
only when the WHOLE decoded token is one value in the event flag format; a stale copy's key yields
garbage and is dropped by that check. Such a flag is reported `candidate`, never `solved`.

Result: `solved` one flag read verbatim from the extracted content; `candidate` several flags, or a
flag only the keyed XOR produced; `unsure` a table or an env was read but no flag (the report is
for the next reader); `none` no file holds a section table or an env. Written to
<challenge>/recon/firmware_sections/<file>/: report.json, the inflated payloads, the members.

Limits, all named in the result notes when they bite: absolute section offsets only (no
table-relative offsets, no start/end pairs), the table within the first 64 KiB, a section over
8 MiB is not scanned for streams, a dictionary over 32 KiB is refused by carve_all.

  .venv/bin/python solvers/toolkits/firmware_sections.py firmware.bin [--event SLUG] [--out DIR]
  python -m ctf run toolkits.firmware_sections <challenge_dir>
"""
from __future__ import annotations

import argparse
import base64
import binascii
import bz2
import json
import lzma
import os
import re
import struct
import sys
import time
import zlib
from pathlib import Path

try:
    from ctf import flagfmt
except ImportError:                                   # run as a script from outside the repo root
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import carve_stego_fs as csf     # noqa: E402
import carving                   # noqa: E402
import firmware_walk as fw       # noqa: E402

ENGINE = "toolkits.firmware_sections"
DEFAULT_SECONDS = 40.0

MAX_FILE = 256 << 20                  # a file larger than this is not read
MIN_IMAGE = 64                        # a file smaller than this is not a firmware image
HEAD_WINDOW = 64 * 1024               # the table starts within this many bytes of the file start
FIELD_SPAN = 60                       # offset, size and checksum of a record lie this close together
MAX_PAIRS = 200_000                   # (offset, size) word pairs whose CRC is tried
CRC_FLOOR = 64 << 20                  # bytes the table search may checksum (or 4x the file, if more)
MIN_SHAPE = 8                         # shortest word{...} listed while the event's flag prefix is unknown
MAX_SECTIONS = 256
CARVE_MAX = 8 << 20                   # carve_all costs about a CPU second on 8 MiB: larger is skipped
CARVE_TOTAL = 32 << 20
MAX_DICT = 32768                      # carving.carve_all refuses a longer dictionary
MAX_DICTS = 64
MAX_INFLATE = 64 << 20
MAX_MEMBERS = 5000
MAX_TOKENS = 128
MAX_KEYS = 256
TOKEN_SCAN = 1 << 20                  # bytes of one extracted file searched for tokens
MAX_WRITE_FILES = 256
MAX_WRITE_BYTES = 16 << 20
STREAM_KINDS = ("zlib", "gzip", "bzip2", "xz")
SKIP_DIRS = {"recon", ".git"}
SKIP_FILES = {".sweep.json", ".sweep-owner", ".lock", "challenge.json", "notes.md", "triage.md"}

_DELTAS = tuple(d for d in range(-FIELD_SPAN, FIELD_SPAN + 1, 4) if d)
_NAME = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-/")
ALGOS = ("crc32", "crc32-jamcrc")     # IEEE CRC-32, and the same register without the final inversion


class _Spent(Exception):
    """A search cap was reached; the message names it."""


# ---- the section table ------------------------------------------------------------------------------

def _words(data: bytes, w: int, endian: str) -> list:
    """The u32 at every byte offset of data[:w] (index = offset)."""
    vals = [0] * max(0, w - 3)
    for phase in range(4):
        count = (w - phase) // 4
        if count > 0:
            vals[phase::4] = struct.unpack_from(f"{endian}{count}I", data, phase)
    return vals


def _checksum(algo: str, crc: int) -> int:
    return crc if algo == "crc32" else crc ^ 0xFFFFFFFF


def find_tables(data: bytes, *, window: int = HEAD_WINDOW, crc_budget: int = None, notes: list = None) -> list:
    """Every CRC-confirmed section table in the head of `data` (module docstring), best first.

    A table is {offset, stride, endian, checksum, fields: {offset, size, crc} (byte positions inside
    the record's field block), names, entries}; an entry is {index, name, record_offset, offset, size,
    crc_stored, crc_computed, crc_ok}. `stride` is None for a single confirmed record (no neighbour to
    measure it from, so no names and no unconfirmed entries). A cap that ended the search is named in
    `notes`: the tables found until then are still returned."""
    notes = notes if notes is not None else []
    n = len(data)
    if n < 16:
        return []
    w = min(n, window)
    budget = max(CRC_FLOOR, 4 * n) if crc_budget is None else crc_budget
    mv = memoryview(data)
    memo, spent = {}, 0

    def crc_of(off, size):
        nonlocal spent
        got = memo.get((off, size))
        if got is None:
            if spent + size > budget:
                raise _Spent(f"the checksum budget of {budget} bytes")
            spent += size
            got = memo[(off, size)] = zlib.crc32(mv[off:off + size]) & 0xFFFFFFFF
        return got

    groups, pairs = {}, 0             # (endian, size delta, crc delta, algo) -> {offset-field position: record}
    try:
        for endian in "<>":
            vals = _words(data, w, endian)
            where = {}
            for p, v in enumerate(vals):
                if v:
                    where.setdefault(v, []).append(p)
            plausible = [p for p, v in enumerate(vals) if 0 < v <= n]
            pset = set(plausible)
            for pa in plausible:
                off = vals[pa]
                for d in _DELTAS:
                    pb = pa + d
                    if pb not in pset or off + vals[pb] > n:
                        continue
                    pairs += 1
                    if pairs > MAX_PAIRS:
                        raise _Spent(f"{MAX_PAIRS} candidate (offset, size) pairs")
                    crc = crc_of(off, vals[pb])
                    for algo in ALGOS:
                        want = _checksum(algo, crc)
                        for pc in where.get(want, ()):
                            dc = pc - pa
                            if dc % 4 == 0 and abs(dc) <= FIELD_SPAN and pc != pa and pc != pb:
                                groups.setdefault((endian, d, dc, algo), {})[pa] = (off, vals[pb], want)
    except _Spent as e:
        notes.append(f"section-table search stopped at {e}: a table further in was not looked for")

    found = []
    for (endian, d_size, d_crc, algo), recs in groups.items():
        lo, hi = min(0, d_size, d_crc), max(0, d_size, d_crc) + 4
        left = dict(recs)
        while left:
            pas = sorted(left)
            steps = [b - a for a, b in zip(pas, pas[1:]) if b - a >= hi - lo]
            stride = min(steps) if steps else None
            if stride is None:
                chosen = pas[:1]
            else:
                anchor = next(a for a, b in zip(pas, pas[1:]) if b - a == stride)
                chosen = [p for p in pas if (p - anchor) % stride == 0]
            valid = {p: left.pop(p) for p in chosen}
            found.append(_table(data, endian, d_size, d_crc, algo, stride, valid, crc_of, notes))
    found.sort(key=lambda t: (-sum(e["crc_ok"] for e in t["entries"]), -len(t["entries"]), t["offset"],
                              t["endian"], t["checksum"], sorted(t["fields"].items())))
    out, seen = [], set()
    for t in found:
        ranges = {(e["offset"], e["size"]) for e in t["entries"] if e["crc_ok"]}
        if ranges <= seen:
            continue                                  # the same sections through a duplicated field
        seen |= ranges
        out.append(t)
    return out


def _table(data, endian, d_size, d_crc, algo, stride, valid, crc_of, notes):
    """One table from its confirmed records, plus the unconfirmed records on the same stride."""
    n = len(data)
    lo, hi = min(0, d_size, d_crc), max(0, d_size, d_crc) + 4
    fmt = endian + "I"
    rows = {p: (off, size, stored, True) for p, (off, size, stored) in valid.items()}
    if stride:
        t_lo, t_hi = min(valid) + lo, max(valid) + hi
        spans = sorted((off, off + size) for off, size, _ in valid.values())
        after = all(s >= t_hi for s, _ in spans)
        # The records are wider than their three fields by the name: in front of them, or behind.
        name_d = _names(data, sorted(valid), stride, (0, d_size, d_crc))[2]
        r_lo = t_lo if name_d is None or name_d > lo else min(valid) + name_d
        r_hi = t_hi if name_d is None or name_d < hi else max(valid) + lo + stride

        def unconfirmed(p):
            """A record on the stride that names a range a section can have, or None."""
            if p + lo < 0 or p + hi > n:
                return None
            off = struct.unpack_from(fmt, data, p)[0]
            size = struct.unpack_from(fmt, data, p + d_size)[0]
            stored = struct.unpack_from(fmt, data, p + d_crc)[0]
            if not (0 < off and 0 < size and off + size <= n):
                return None
            if off < r_hi and off + size > r_lo:
                return None                           # it would overlap the table itself
            if after and off < t_hi:
                return None                           # header words, not a record: sections follow the table
            if any(off < e and off + size > s for s, e in spans):
                return None                           # it would overlap a confirmed section
            return off, size, stored, False

        p = min(valid) + stride
        while p < max(valid):
            if p not in rows:
                row = unconfirmed(p)
                if row:
                    rows[p] = row
            p += stride
        for step, p in ((stride, max(valid) + stride), (-stride, min(valid) - stride)):
            while len(rows) < MAX_SECTIONS:
                row = unconfirmed(p)
                if not row:
                    break
                rows[p] = row
                p += step
    order = sorted(rows)
    names, names_note, _ = _names(data, order, stride, (0, d_size, d_crc))
    entries = []
    for i, p in enumerate(order):
        off, size, stored, ok = rows[p]
        try:
            computed = _checksum(algo, crc_of(off, size))
        except _Spent as e:
            computed = None
            notes.append(f"record at {p + lo:#x}: checksum not computed ({e} was spent)")
        entries.append({"index": i, "name": names[i] or f"section{i}", "record_offset": p + lo, "offset": off,
                        "size": size, "crc_stored": stored, "crc_computed": computed, "crc_ok": ok})
    return {"offset": order[0] + lo, "stride": stride, "endian": "little" if endian == "<" else "big",
            "checksum": algo, "fields": {"offset": -lo, "size": d_size - lo, "crc": d_crc - lo},
            "names": names_note, "entries": entries}


def _names(data, order, stride, slots):
    """(names, note, position) of the name field of each record: the position, relative to the offset
    field, where EVERY record starts a printable name. Field words and their repeats one stride away are never read as text,
    and the file magic at offset 0 is not a section name. Of several positions that fit, the one
    with distinct names, then the one where most names are padded out to the next field (a clean
    fixed-width field, which header text in front of the first record is not), then the earliest."""
    if not stride or not order:
        return [None] * len(order), "no record stride: sections are numbered", None
    n = len(data)
    lo, hi = min(slots), max(slots) + 4

    def field(d):
        return any((d - s) % stride < 4 for s in slots)

    def name_at(q, d):
        """(name, padded to the next field) at file offset q, or None."""
        if q <= 0 or q + 1 >= n or field(d) or field(d + 1):
            return None
        if data[q] not in _NAME or data[q + 1] not in _NAME:
            return None
        if data[q - 1] in _NAME and not field(d - 1):
            return None                               # the middle of a word, not its start
        end = q
        while end < n and end - q < 64 and data[end] in _NAME and not field(d + end - q):
            end += 1
        pad = end
        while pad < n and pad - q < stride and data[pad] in (0x00, 0x20, 0xFF) and not field(d + pad - q):
            pad += 1
        return data[q:end].decode("ascii"), pad >= n or field(d + pad - q)

    fits = []
    for d in range(hi - stride, lo + stride):
        got = [name_at(p + d, d) for p in order]
        if all(got):
            names = [g[0] for g in got]
            fits.append(((len(set(names)) != len(names), -sum(g[1] for g in got), d), names))
    if not fits:
        return [None] * len(order), "no name field found: sections are numbered", None
    fits.sort()
    (dupes, clean, d), names = fits[0]
    note = f"name field {d:+d} bytes from the offset field"
    if len(fits) > 1 and fits[1][0][:2] == (dupes, clean):
        note += f"; the position {fits[1][0][2]:+d} reads as names equally well: the earlier one is taken"
    return names, note, d


# ---- streams, dictionaries, archives ----------------------------------------------------------------

def _fdict_header(b: bytes) -> bool:
    """RFC 1950: CM 8, window <= 32 KiB, header a multiple of 31, FDICT set."""
    return len(b) >= 2 and b[0] & 0x0F == 8 and b[0] >> 4 <= 7 and b[1] & 0x20 and ((b[0] << 8) | b[1]) % 31 == 0


def fdict_streams(data: bytes, dictid: int) -> list:
    """Offsets of every zlib preset-dictionary header in `data` that names `dictid`."""
    needle, out, at = dictid.to_bytes(4, "big"), [], data.find(dictid.to_bytes(4, "big"), 2)
    while at >= 0 and len(out) < 64:
        if _fdict_header(data[at - 2:at]):
            out.append(at - 2)
        at = data.find(needle, at + 1)
    return out


def _inflate(kind: str, blob: bytes, zdict: bytes = None):
    """The payload of one carved stream, or None past MAX_INFLATE / on a stream the stdlib refuses."""
    try:
        if kind == "zlib":
            out = (zlib.decompressobj(zdict=zdict) if zdict else zlib.decompressobj()).decompress(blob, MAX_INFLATE + 1)
        elif kind == "gzip":
            out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob, MAX_INFLATE + 1)
        elif kind == "bzip2":
            out = bz2.BZ2Decompressor().decompress(blob, MAX_INFLATE + 1)
        elif kind == "xz":
            out = lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(blob, MAX_INFLATE + 1)
        else:
            return None
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None
    return out if len(out) <= MAX_INFLATE else None


# ---- the keyed-XOR lead -----------------------------------------------------------------------------

_HEX_TOKEN = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,512}(?![0-9A-Fa-f])")
_B64_TOKEN = re.compile(rb"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){4,256}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
                        rb"(?![A-Za-z0-9+/=])")
_LABEL = re.compile(rb"([A-Za-z_][A-Za-z0-9_.\-]{0,47})[ \t]*[=:][ \t]*[\"']?$")
_SECRET_WORD = re.compile(r"token|secret|key|pass|flag|auth|admin|recover|cred|license|serial", re.I)
_HEX_GROUPS = re.compile(r"[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2})+")
_HEX_RUN = re.compile(r"(?:0[xX])?((?:[0-9A-Fa-f]{2})+)")


def tokens_in(where: str, blob: bytes) -> list:
    """Hex and base64 runs of 8+ bytes in one extracted file: {where, label, encoding, text, raw}."""
    out, head = [], blob[:TOKEN_SCAN]
    for encoding, rx in (("hex", _HEX_TOKEN), ("base64", _B64_TOKEN)):
        for m in rx.finditer(head):
            text = m.group(0)
            if encoding == "base64" and _HEX_TOKEN.fullmatch(text):
                continue
            try:
                raw = bytes.fromhex(text.decode()) if encoding == "hex" else base64.b64decode(text, validate=True)
            except (ValueError, binascii.Error):
                continue
            label = _LABEL.search(head[max(0, m.start() - 64):m.start()])
            out.append({"where": where, "label": label.group(1).decode() if label else None,
                        "encoding": encoding, "text": text.decode(), "raw": raw})
    return out


def keys_of(value: str) -> list:
    """The byte strings one env value can be as an XOR key: (form, bytes)."""
    out = []
    v = value.strip()
    if _HEX_GROUPS.fullmatch(v):
        out.append(("hex groups", bytes.fromhex(re.sub(r"[:\-]", "", v))))
    else:
        m = _HEX_RUN.fullmatch(v)
        if m and len(m.group(1)) >= 4:
            out.append(("hex", bytes.fromhex(m.group(1))))
    if len(v) >= 2:
        out.append(("text", v.encode("latin-1", "replace")))
    return out


def xor_repeat(token: bytes, key: bytes) -> bytes:
    stream = (key * (len(token) // len(key) + 1))[:len(token)]
    return (int.from_bytes(token, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(token), "big")


def reportable(ff, text: str) -> bool:
    """A flag-shaped value may be listed: printable ASCII only (flagfmt.is_flag accepts a control or
    non-ASCII character inside the braces), and MIN_SHAPE+ characters while the event prefix is unknown."""
    return bool(text) and all(0x20 <= ord(ch) < 0x7F for ch in text) and (ff.known or len(text) >= MIN_SHAPE)


def keyed_xor_sweep(tokens: list, copies: list, live, ff) -> dict:
    """Every token XOR every key; a hit is a decoded token that is, whole, one flag in the format.
    Returns {tokens, keys, tried, hits: [{flag, token, copy, live, var, form}], note}."""
    cut = ""
    ranked = sorted(range(len(tokens)), key=lambda i: (not _SECRET_WORD.search(tokens[i]["label"] or ""),
                                                       tokens[i]["encoding"] != "hex", i))
    if len(ranked) > MAX_TOKENS:
        cut = f"{len(ranked)} tokens found, the first {MAX_TOKENS} tried (named secrets and hex first)"
        ranked = ranked[:MAX_TOKENS]
    keys, seen = [], set()
    order = ([live] if live is not None else []) + [i for i in range(len(copies)) if i != live]
    for ci in order:
        c = copies[ci]
        if not c.get("crc_valid"):
            continue                                  # no value is read behind a bad CRC
        for var, value in c["vars"].items():
            for form, raw in keys_of(value):
                if raw and (ci, raw) not in seen and len(keys) < MAX_KEYS:
                    seen.add((ci, raw))
                    keys.append((ci, var, form, raw))
    out = {"tokens": len(ranked), "keys": len(keys), "tried": 0, "hits": [], "note": cut}
    if ff is None:
        out["note"] = (cut + "; " if cut else "") + "no flag format: a keyed-XOR result cannot be confirmed, none tried"
        return out
    for ti in ranked:
        tok = tokens[ti]
        for ci, var, form, raw in keys:
            out["tried"] += 1
            text = xor_repeat(tok["raw"], raw).decode("latin-1").rstrip("\x00\r\n ")
            if reportable(ff, text) and ff.is_flag(text):
                out["hits"].append({"flag": text, "token": tok["where"], "label": tok["label"], "copy": ci,
                                    "live": ci == live, "var": var, "form": form})
    return out


# ---- one image --------------------------------------------------------------------------------------

def _magic(data: bytes):
    head = data[:4]
    return head.decode("ascii") if len(head) == 4 and all(c in _NAME for c in head) else None


def walk_image(name: str, data: bytes, ff=None, *, clock=time.monotonic, deadline: float = None):
    """(report, blobs) for one file, or (None, []) when it holds neither a CRC-confirmed section table
    nor a CRC-valid U-Boot env. `report` is JSON-safe; `blobs` is [(label, bytes)] of the inflated payloads and members.
    A phase that starts after `deadline` (on `clock`) is not run and is named in report["notes"]."""
    notes = []
    tables = find_tables(data, notes=notes)
    copies = fw.env_copies(data, notes=notes)
    if not tables and not any(c["crc_valid"] for c in copies):
        return None, []                               # strings that look like an env prove nothing
    live, why = fw.pick_live_env(copies)
    rep = {"file": name, "size": len(data), "magic": _magic(data), "tables": tables,
           "env": {"copies": copies, "live": live, "live_reason": why}, "streams": [], "containers": [],
           "members": [], "flags": [], "xor": None, "notes": notes}
    blobs = []

    def late(phase):
        if deadline is not None and clock() >= deadline:
            notes.append(f"time budget spent before {phase}: not run")
            return True
        return False

    sections, seen = [], set()
    for t in tables:
        for e in t["entries"]:
            if (e["offset"], e["size"]) not in seen:
                seen.add((e["offset"], e["size"]))
                sections.append(e)
    for c in copies:
        at = c["data_offset"]
        c["section"] = next((e["name"] for e in sections if e["offset"] <= at < e["offset"] + e["size"]), None)

    # Dictionaries: a section whose Adler-32 a preset-dictionary stream names.
    dicts, payloads = {}, []                           # dictid -> section; (label, bytes)
    adlers = [zlib.adler32(data[e["offset"]:e["offset"] + e["size"]]) & 0xFFFFFFFF for e in sections]
    if not late("the dictionary search"):
        for e, dictid in zip(sections, adlers):
            refs = fdict_streams(data, dictid)
            if not refs:
                continue
            e["dictionary_for"] = refs
            if e["size"] > MAX_DICT:
                notes.append(f"section {e['name']} ({e['size']} bytes) is the preset dictionary of the zlib stream at "
                             f"{refs[0]:#x}, but carve_all takes dictionaries up to {MAX_DICT} bytes: stream not inflated")
            elif len(dicts) >= MAX_DICTS:
                notes.append(f"section {e['name']} is a dictionary, but {MAX_DICTS} are already in use: not passed")
            else:
                dicts[dictid] = e

    carved_total = 0
    for e in sections:
        if late(f"the stream carve of section {e['name']}"):
            break
        sec = data[e["offset"]:e["offset"] + e["size"]]
        if _fdict_header(sec[:2]) and len(sec) >= 6:
            dictid = int.from_bytes(sec[2:6], "big")
            if dictid not in adlers:
                notes.append(f"section {e['name']} starts with a zlib preset-dictionary header (DICTID {dictid:#010x}) "
                             "and no section has that Adler-32: the dictionary is not in the table")
        if len(sec) > CARVE_MAX or carved_total + len(sec) > CARVE_TOTAL:
            notes.append(f"section {e['name']} ({len(sec)} bytes) not scanned for compressed streams: over the "
                         f"{CARVE_MAX} byte section cap or the {CARVE_TOTAL} byte total")
            continue
        carved_total += len(sec)
        zdicts = tuple(data[d["offset"]:d["offset"] + d["size"]] for d in dicts.values())
        for obj in carving.carve_all(sec, kinds=STREAM_KINDS, zlib_dictionaries=zdicts):
            dictid = int.from_bytes(obj.data[2:6], "big") if obj.kind == "zlib" and obj.data[1] & 0x20 else None
            src = dicts.get(dictid) if dictid is not None else None
            zdict = data[src["offset"]:src["offset"] + src["size"]] if src else None
            payload = _inflate(obj.kind, obj.data, zdict)
            stream = {"section": e["name"], "offset": e["offset"] + obj.offset, "end": e["offset"] + obj.end,
                      "kind": obj.kind, "dictid": dictid, "dictionary": src["name"] if src else None,
                      "inflated": None if payload is None else len(payload)}
            rep["streams"].append(stream)
            if payload is None:
                notes.append(f"stream at {stream['offset']:#x} ({obj.kind}) inflates past {MAX_INFLATE} bytes: not kept")
            else:
                payloads.append((f"{e['name']}@{stream['offset']:#x}.{obj.kind}", payload))

    # Containers: cpio through carve_stego_fs, the firmware filesystems through firmware_walk.
    regions = [(e["name"], data[e["offset"]:e["offset"] + e["size"]]) for e in sections] + payloads
    blobs.extend(payloads)
    if not late("the archive and filesystem readers"):
        for label, blob in regions:
            kind, files = None, []
            if csf.is_cpio(blob):
                kind = "cpio"
                files = [(m["path"], m["size"], m["dir"], m["data"]) for m in csf.cpio(blob) or []]
            else:
                img = fw._detect_and_walk(label, blob)
                if img is not None and img["kind"] != "uboot_env":
                    kind = img["kind"]
                    files = [(m["path"], m["size"], m["type"] == "dir", m.get("content")) for m in img.get("entries", [])]
            if kind is None:
                continue
            rep["containers"].append({"in": label, "kind": kind, "members": len(files)})
            for path, size, is_dir, content in files:
                if len(rep["members"]) >= MAX_MEMBERS:
                    notes.append(f"{label}: more than {MAX_MEMBERS} members, the rest not listed")
                    break
                rep["members"].append({"in": label, "path": path, "size": size, "dir": bool(is_dir),
                                       "read": content is not None})
                if content is not None and not is_dir:
                    blobs.append((f"{label}/{path}", bytes(content)))

    # Flags read verbatim, then the keyed-XOR lead.
    if ff is None:
        notes.append("no flag format given: the extracted content was not searched for flags")
    elif not late("the flag search"):
        found = {}
        if not ff.known:
            notes.append(f"the event flag prefix is not known yet: any printable word{{...}} of {MIN_SHAPE}+ "
                         "characters is listed as a flag")
        for label, blob in regions + blobs[len(payloads):]:
            for f in ff.find_flags(blob):
                if reportable(ff, f):
                    found.setdefault(f, label)
        for i, c in enumerate(copies):
            for var, value in c["vars"].items():
                for f in ff.find_flags(value):
                    if not reportable(ff, f):
                        continue
                    found.setdefault(f, f"env copy {i} @{c['offset']:#x} variable {var}")
        rep["flags"] = [{"flag": f, "where": where} for f, where in found.items()]
    if not late("the keyed-XOR sweep"):
        tokens, had = [], set()
        opened = {c["in"] for c in rep["containers"]}       # an archive is read through its members only
        sources = blobs[len(payloads):] + [p for p in payloads if p[0] not in opened]
        sources += [(f"env copy {i} variable {var}", value.encode("latin-1", "replace"))
                    for i, c in enumerate(copies) for var, value in c["vars"].items()]
        for label, blob in sources:
            for tok in tokens_in(label, blob):
                if tok["raw"] not in had:
                    had.add(tok["raw"])
                    tokens.append(tok)
        sweep = keyed_xor_sweep(tokens, copies, live, ff)
        sweep["token_list"] = [{k: t[k] for k in ("where", "label", "encoding", "text")} for t in tokens[:MAX_TOKENS]]
        rep["xor"] = sweep
    return rep, blobs


# ---- the engine -------------------------------------------------------------------------------------

def _read(path: Path) -> bytes:
    return path.read_bytes()


def iter_challenge_files(challenge_dir: Path, notes: list = None):
    """(relative name, bytes), one file at a time, read only when the caller asks for the next one: the
    sweep's scratch copy (`unpacked/`) when there is one, else `files/`, else the folder; recon output
    and links left out, a file over MAX_FILE named in `notes`. The folder is checked on the call."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    return _iter_files(challenge_dir, notes)


def _iter_files(challenge_dir: Path, notes):
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if n in SKIP_FILES or p.is_symlink() or not p.is_file():
                continue
            if p.stat().st_size > MAX_FILE:
                if notes is not None:
                    notes.append(f"{p.relative_to(challenge_dir)}: over {MAX_FILE} bytes, not read")
                continue
            yield str(p.relative_to(challenge_dir)), _read(p)


def challenge_files(challenge_dir: Path, notes: list = None) -> dict:
    """{relative name: bytes} of iter_challenge_files, all in memory (solve() streams them instead)."""
    return dict(iter_challenge_files(challenge_dir, notes))


def examine(files, ff, *, seconds: float = DEFAULT_SECONDS, clock=time.monotonic) -> dict:
    """Walk every file of `files`, a {name: bytes} or an iterable of (name, bytes) taken one at a time,
    so a lazy iterable (iter_challenge_files) holds one file in memory at a time.
    {"images": [report], "blobs": {file: [(label, bytes)]}, "skipped": n, "notes": []}."""
    deadline = clock() + seconds
    out = {"images": [], "blobs": {}, "skipped": 0, "notes": []}
    for name, data in (files.items() if isinstance(files, dict) else files):
        if len(data) < MIN_IMAGE:
            out["skipped"] += 1
            continue
        if clock() >= deadline:
            out["notes"].append(f"time budget of {seconds:g}s spent: {name} and the files after it not walked")
            break
        rep, blobs = walk_image(name, data, ff, clock=clock, deadline=deadline)
        del data                                      # the walk keeps only what it extracted
        if rep is None:
            out["skipped"] += 1
            continue
        out["images"].append(rep)
        out["blobs"][name] = blobs
    return out


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")[:120] or "unnamed"


def write_outputs(walked: dict, out_dir: Path) -> list:
    """report.json and the extracted bytes under out_dir/<file>/. Member names come from the image:
    every one is flattened to [A-Za-z0-9._-] behind a counter, so none can leave the folder."""
    written = []
    for rep in walked["images"]:
        base = Path(out_dir) / _safe(rep["file"])
        (base / "extracted").mkdir(parents=True, exist_ok=True)
        count = 0
        for i, (label, blob) in enumerate(walked["blobs"].get(rep["file"], [])):
            if count >= MAX_WRITE_FILES or len(blob) > MAX_WRITE_BYTES:
                rep["notes"].append(f"{label} ({len(blob)} bytes) not written: over the "
                                    f"{MAX_WRITE_FILES} file or {MAX_WRITE_BYTES} byte write cap")
                continue
            path = base / "extracted" / f"{i:04d}_{_safe(label)}"
            path.write_bytes(blob)
            written.append(path)
            count += 1
        report = base / "report.json"
        report.write_text(json.dumps(rep, indent=1, sort_keys=True) + "\n")
        written.append(report)
    return written


def summary(rep: dict) -> list:
    """The walk of one image as text lines (the result notes and the command output)."""
    lines = [f"{rep['file']}: {rep['size']} bytes" + (f", magic {rep['magic']}" if rep["magic"] else "")]
    for t in rep["tables"]:
        bad = [e["name"] for e in t["entries"] if not e["crc_ok"]]
        lines.append(f"  section table @{t['offset']:#x}: {len(t['entries'])} records, stride {t['stride']}, "
                     f"{t['endian']}-endian, {t['checksum']}" + (f"; CRC MISMATCH: {', '.join(bad)}" if bad else ""))
        for e in t["entries"]:
            lines.append(f"    {e['name']:<16} @{e['offset']:#x} +{e['size']:#x} crc {e['crc_stored']:08x} "
                         + ("ok" if e["crc_ok"] else "MISMATCH")
                         + (f"  [zlib dictionary of the stream at {e['dictionary_for'][0]:#x}]"
                            if e.get("dictionary_for") else ""))
    env = rep["env"]
    for i, c in enumerate(env["copies"]):
        where = f"@{c['offset']:#x}" if c["offset"] is not None else f"near {c['data_offset']:#x}"
        lines.append(f"  env copy {i} {where}" + (f" in section {c['section']}" if c.get("section") else "")
                     + (f": crc ok, flags {c['flags']}, {len(c['names'])} variables" if c["crc_valid"]
                        else f": CRC MISMATCH, values not read ({', '.join(c['names'][:6])})")
                     + (f"  LIVE ({env['live_reason']})" if i == env["live"] else ""))
    for s in rep["streams"]:
        lines.append(f"  {s['kind']} stream @{s['offset']:#x} in {s['section']}"
                     + (f", dictionary = section {s['dictionary']} (DICTID {s['dictid']:#010x})" if s["dictionary"] else "")
                     + f" -> {s['inflated']} bytes")
    for c in rep["containers"]:
        lines.append(f"  {c['kind']} in {c['in']}: {c['members']} members")
    x = rep["xor"]
    if x:
        lines.append(f"  keyed XOR (unsure lead): {x['tokens']} tokens x {x['keys']} env keys, {len(x['hits'])} in the "
                     "flag format" + (f" ({x['note']})" if x["note"] else ""))
        for h in x["hits"]:
            lines.append(f"    {h['flag']}  = {h['token']} XOR env copy {h['copy']} "
                         f"({'live' if h['live'] else 'NOT the live copy'}) variable {h['var']} as {h['form']}")
    lines.extend(f"  note: {n}" for n in rep["notes"])
    return lines


def result_of(walked: dict, *, seconds: float = 0.0, written=(), root: Path = None, challenge_id=None):
    """The SolverResult of an examine() (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    literal, derived, evidence, notes = {}, {}, [], list(walked["notes"])
    for rep in walked["images"]:
        for f in rep["flags"]:
            literal.setdefault(f["flag"], (rep["file"], f["where"]))
        for h in (rep["xor"] or {}).get("hits", []):
            derived.setdefault(h["flag"], (rep["file"], h))
        notes.extend(summary(rep))
    derived = {f: v for f, v in derived.items() if f not in literal}
    for f, (file, where) in literal.items():
        evidence.append(Evidence("carve", f"read verbatim in {where}", path=file))
    for f, (file, h) in derived.items():
        evidence.append(Evidence("decode", f"keyed XOR, confirmed only by the flag format: token in {h['token']} XOR "
                                 f"env variable {h['var']} ({h['form']}) of copy {h['copy']} "
                                 f"({'the live copy' if h['live'] else 'NOT the live copy'})", path=file))
    for p in written:
        if Path(p).name == "report.json":
            evidence.append(Evidence("carve", "walk report", path=rel(p)))
    flags = list(literal) + list(derived)
    common = dict(engine=ENGINE, challenge_id=challenge_id, cost=Cost(seconds=round(seconds, 3)),
                  flags=flags, evidence=evidence)
    if len(flags) == 1 and literal:
        return SolverResult(status="solved", notes="\n".join(notes), **common)
    if flags:
        why = ("several flags: decoys are possible" if len(flags) > 1 else
               "one flag, from the keyed-XOR lead only: nothing but the flag format ties the token to the env key")
        return SolverResult(status="candidate", notes="\n".join([why] + notes), **common)
    if walked["images"]:
        return SolverResult(status="unsure", notes="\n".join(
            ["section table / U-Boot env read, no flag in the event format: read the report"] + notes), **common)
    return SolverResult(status="none", notes="\n".join(
        [f"no section table and no U-Boot env in {walked['skipped']} file(s)"] + notes), **common)


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: out (folder for the report and extracted files; default
    <challenge>/recon/firmware_sections), seconds (time budget, default 40)."""
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    notes = []
    files = iter_challenge_files(challenge_dir, notes)
    walked = examine(files, flagfmt.for_profile(profile), seconds=float(opts.get("seconds", DEFAULT_SECONDS)))
    walked["notes"] = notes + walked["notes"]
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "firmware_sections"
    written = write_outputs(walked, out_dir) if walked["images"] else []
    return result_of(walked, seconds=time.monotonic() - t0, written=written, root=challenge_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="firmware_sections.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--out", type=Path, help="folder for report.json and the extracted files (default: none written)")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    a = ap.parse_args(argv)
    from ctf import event
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"firmware_sections.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    profile = event.load(a.event) if a.event else event.current()
    t0 = time.monotonic()
    walked = examine({str(p): p.read_bytes() for p in a.files}, flagfmt.for_profile(profile), seconds=a.seconds)
    written = write_outputs(walked, a.out) if a.out and walked["images"] else []
    res = result_of(walked, seconds=time.monotonic() - t0, written=written)
    for rep in walked["images"]:
        print("\n".join(summary(rep)))
    for p in written:
        print(f"written: {p}")
    print(res.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
