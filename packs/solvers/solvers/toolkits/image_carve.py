#!/usr/bin/env python3
"""Toolkit `image_carve` (B-030): the image carve family, no model.

Three jobs that were separate hand jobs at the 2026 events, behind one engine:

  aCropalypse   a PNG with data after IEND that is the tail of an older, larger image's IDAT stream
                (the file was overwritten without being truncated), so the tail must end with an
                IEND chunk of its own; or a PNG whose IDAT chunks hold, after their zlib stream
                ends, such a deflate tail (the after-IDAT shape). The trailing IDAT chunks are
                unwrapped, raw inflate restarts
                at the earliest byte or bit offset that inflates to the end of the stream, a zeroed
                32 KiB preset dictionary standing in for the lost
                window, and the scanlines are cut from the end at the width the IHDR, the caller or
                the scanline filter bytes give. Each rebuild is written as a PNG and, with
                tesseract on PATH, read by OCR for the event's flag (the OCR gate).
  fragments     a raw dump (chip-off flash, disk image) holding a PNG whose blocks are out of order.
                From each PNG header the dump is cut into blocks (512 to 4096 bytes), the runs of
                blocks that are neither erased (one byte value) nor text are the candidate
                fragments, and a depth-first search appends them after the header fragment (which
                keeps every chunk that verifies in place), pruned by chunk types and CRCs and a zlib
                prefix check, until IEND with every CRC right and the IDAT stream inflating to
                exactly the size the IHDR implies. The whole PNG is written and OCR-gated like a
                recovery.
  lsb routing   every PNG and BMP goes to carve_stego.lsb_scan whatever the challenge category; its
                payloads (judge_blob now also takes a 4-byte length before a gzip, zip or tar) are
                unpacked (gzip, zip, tar, three levels) and decoded (base64, base32, hex, through
                embedded_decode) and searched for the event's flag. carve_stego.scan's structural
                readings (data after IEND, an appended archive's members, text chunks) are searched
                the same way.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  examine(files, ff, ...) -> Report                          the same over {name: bytes}
  acropalypse(data, widths=(), deadline=None) -> [Recovery]
  reassemble_png(blob, block_sizes=..., deadline=None) -> [Reassembly]
  image_payloads(name, data, ff, deadline=None) -> [Hit]
  ocr_text(png, deadline=None) -> str                         tesseract (ToolMissing when absent)
  ocr_gate(images, ff, prefixes, deadline, skipped)            OCR best reading first, stop at a flag

  .venv/bin/python solvers/toolkits/image_carve.py FILE... [--event SLUG] [--width N]... [--out DIR]
        [--ocr auto|on|off] [--seconds S]

Status: a flag read from bytes (an LSB payload, an archive member, a decoded string) is `solved` when
it is the only one, `candidate` when there are several; a flag read by OCR is never more than
`candidate` (0/O and 1/l are the usual misreads). A rebuilt image or a payload with no flag in it is
`unsure`, with the files written and named. Nothing is executed; tesseract is the only program run.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

import carve_stego as cs        # noqa: E402
import embedded_decode as ed    # noqa: E402

ENGINE = "toolkits.image_carve"
PNG_SIG = cs.PNG_SIG
IEND_TAIL = b"IEND\xaeB`\x82"
WINDOW = bytes(32768)                 # the lost deflate window, as zeros
TRAIL_SLACK = 24                      # bytes allowed after the final deflate block (Adler-32, CRC, IEND)
MAX_RAW = 128 << 20                   # inflated bytes accepted from one stream
MAX_DUMP = 256 << 20                  # bytes of one file searched for a fragmented PNG
MAX_FILE = 256 << 20                  # files larger than this are not read
MAX_WIDTH = 16384
MIN_ROWS = 2                          # scanlines a recovery needs
SCAN_ROWS = 8                         # scanlines the filter-byte width scan needs
BLOCK_SIZES = (512, 1024, 2048, 4096)
ENTROPY_MIN = 1.0                     # bits/byte below which a block is erased or padding, never PNG data
PRINTABLE_MAX = 0.9                   # share of printable bytes from which a block is text, never PNG data
MAX_RUNS = 40                         # candidate fragments one search considers (nearest the header)
MAX_NODES = 20000                     # search nodes one header and block size may take
MAX_HEADERS = 16
MAX_CANDIDATES = 6                    # width readings rebuilt per recovery
DEFAULT_SECONDS = 25.0
OCR_SCALE = 3
OCR_PSMS = (6, 11)
COMMON_WIDTHS = (720, 750, 768, 800, 828, 1024, 1080, 1125, 1170, 1179, 1242, 1280, 1284, 1290, 1366, 1440,
                 1536, 1600, 1920, 2048, 2160, 2560, 2880, 3840)
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_CTYPE = {1: 0, 2: 4, 3: 2, 4: 6}
_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))


class ToolMissing(RuntimeError):
    """A program or module this reading needs is not installed; the message names it."""


class _OutOfBudget(Exception):
    pass


OutOfBudget = _OutOfBudget      # the public name: what a caller outside this module catches (ocr_text)


# ---- PNG pieces ------------------------------------------------------------------------------------

def _chunk(typ: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF)


def build_png(width: int, height: int, color_type: int, filtered: bytes, palette: bytes | None = None) -> bytes:
    """A PNG of already-filtered scanlines (each row: filter byte + samples), bit depth 8."""
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    out = PNG_SIG + _chunk(b"IHDR", ihdr)
    if color_type == 3 and palette:
        out += _chunk(b"PLTE", palette)
    return out + _chunk(b"IDAT", zlib.compress(filtered, 6)) + _chunk(b"IEND", b"")


def raw_size(width: int, height: int, depth: int, color_type: int, interlace: int) -> int | None:
    """Inflated bytes of a PNG's image data (filter bytes included), or None for a bad header."""
    ch = _CHANNELS.get(color_type)
    if not ch or depth not in (1, 2, 4, 8, 16) or not width or not height:
        return None
    bits = ch * depth
    if not interlace:
        return height * (1 + (width * bits + 7) // 8)
    total = 0
    for x0, y0, dx, dy in _ADAM7:
        pw, ph = (width - x0 + dx - 1) // dx, (height - y0 + dy - 1) // dy
        if pw > 0 and ph > 0:
            total += ph * (1 + (pw * bits + 7) // 8)
    return total


def _chunk_at(buf, s: int):
    """(type, body, end) of a whole chunk with a right CRC at s, or None."""
    if s < 0 or s + 12 > len(buf):
        return None
    ln = struct.unpack_from(">I", buf, s)[0]
    typ = bytes(buf[s + 4:s + 8])
    if ln > 0x7FFFFFFF or s + 12 + ln > len(buf) or not all(65 <= c <= 90 or 97 <= c <= 122 for c in typ):
        return None
    body = bytes(buf[s + 8:s + 8 + ln])
    if zlib.crc32(typ + body) & 0xFFFFFFFF != struct.unpack_from(">I", buf, s + 8 + ln)[0]:
        return None
    return typ, body, s + 12 + ln


def intact_at(blob: bytes, off: int) -> bool:
    """True when the PNG at off walks in place, every CRC right, to an IEND."""
    i = off + 8
    while True:
        got = _chunk_at(blob, i)
        if not got:
            return False
        if got[0] == b"IEND":
            return True
        i = got[2]


# ---- aCropalypse -----------------------------------------------------------------------------------

@dataclass
class Recovery:
    width: int
    height: int
    channels: int
    color_type: int
    png: bytes
    start_bit: int          # where inflate restarted, in bits into the unwrapped deflate tail
    tail_offset: int        # file offset where the tail (after IEND, or after the zlib stream) begins
    inflated: int           # bytes the restarted inflate produced
    how: str                # which source gave the width
    tail: str = "after IEND"    # AFTER_IEND or AFTER_IDAT: where the older image's tail was found
    file: str = ""
    source: str = "acropalypse"
    ocr: str | None = None
    ocr_flags: list = field(default_factory=list)


def tail_stream(tail: bytes) -> tuple[bytes, int, bool]:
    """(deflate bytes, whole IDAT chunks found, ends with IEND) of the data after IEND: the rest of
    the overwritten IDAT chunk (its CRC dropped) and the bodies of the whole IDAT chunks after it, up
    to IEND. With no whole chunk in it the tail is returned as it is, with (0, False)."""
    first = None
    for typ in (b"IDAT", b"IEND"):
        i = tail.find(typ)
        while i != -1:
            if _chunk_at(tail, i - 4):
                first = i - 4 if first is None else min(first, i - 4)
                break
            i = tail.find(typ, i + 1)
    if first is None:
        return tail, 0, False
    head = tail[:max(0, first - 4)]
    bodies, n, i, ended = [head], 0, first, False
    while True:
        got = _chunk_at(tail, i)
        if not got or got[0] == b"IEND":
            ended = bool(got)
            break
        if got[0] == b"IDAT":
            bodies.append(got[1])
            n += 1
        i = got[2]
    return b"".join(bodies), n, ended


def _shift(stream: bytes, k: int) -> bytes:
    """The stream read from its k-th bit (deflate packs bits from each byte's least significant end)."""
    if not k:
        return stream
    return (int.from_bytes(stream, "little") >> k).to_bytes(len(stream), "little")


def _inflate_tail(buf, off: int, max_out: int, slack: int = TRAIL_SLACK):
    """Raw inflate of buf[off:] with the zero window; the output when it ends within `slack` bytes
    of the end of buf, else None."""
    d = zlib.decompressobj(-15, zdict=WINDOW)
    view = memoryview(buf)
    out, total, pos, size = [], 0, off, 1024
    try:
        while pos < len(buf):
            piece = view[pos:pos + size]
            got = d.decompress(piece, max_out - total + 1)
            total += len(got)
            out.append(got)
            if total > max_out or d.unconsumed_tail:
                return None
            if d.eof:
                return b"".join(out) if len(d.unused_data) + (len(buf) - pos - len(piece)) <= slack else None
            pos += len(piece)
            size = min(size * 4, 1 << 20)
    except zlib.error:
        return None
    return None


def restart(stream: bytes, deadline=None, max_out: int = MAX_RAW, min_out: int = 64, slack: int = TRAIL_SLACK):
    """(bit offset, inflated bytes) of the earliest offset in stream from which raw inflate, with a
    zeroed window, runs to the end of the stream (`slack` bytes after the final block allowed). Byte
    offsets first (a zlib flush leaves the next block byte-aligned), then the seven bit shifts, each
    only before the best start found so far.
    None when no offset works; _OutOfBudget past the deadline."""
    best = None
    for k in range(8):
        s = _shift(stream, k)
        for off in range(0, max(0, len(s) - 2)):
            bit = off * 8 + k
            if best is not None and bit >= best[0]:
                break
            if deadline is not None and not off & 127 and time.monotonic() > deadline:
                raise _OutOfBudget(f"restart search stopped at bit {bit}")
            got = _inflate_tail(s, off, max_out, slack + (1 if k else 0))   # a shifted end can spill a byte
            if got is not None and len(got) >= min_out:
                best = (bit, got)
                break
    return best


_BAD_START = bytes(0 if v <= 4 else 1 for v in range(256))     # a row start that is no filter byte -> 1


def filter_fit(raw: bytes, stride: int) -> tuple[int, int]:
    """(rows, clean rows) when raw is cut into rows of `stride` bytes from its end: clean rows are the
    rows at the bottom, one after another, whose first byte is a filter byte (0..4). A restart can
    put a little garbage at the top, never at the bottom, so the clean rows are counted from there."""
    rows = len(raw) // stride if stride > 0 else 0
    if rows <= 0:
        return 0, 0
    marks = raw[len(raw) - rows * stride::stride].translate(_BAD_START)
    return rows, len(marks) - len(marks.rstrip(b"\x00"))


def _margin(raw: bytes, stride: int, clean: int) -> float:
    """1 minus how often the bytes just after the clean rows' starts are 0..4 as well: near 0 when
    everything is 0..4 (a flat area, or a wrong stride through one), near 1 for the true stride."""
    base = len(raw) - clean * stride
    near = []
    for k in range(1, min(stride, 9)):
        seg = raw[base + k::stride]
        if seg:
            near.append(1.0 - len(seg.translate(None, b"\x00\x01\x02\x03\x04")) / len(seg))
    return 1.0 - (sum(near) / len(near) if near else 1.0)


def fits(raw: bytes, stride: int, least: int = MIN_ROWS) -> bool:
    """The rows of this stride start with a filter byte from the bottom up: at least `least` rows and
    at least a quarter of all of them."""
    rows, clean = filter_fit(raw, stride)
    return clean >= least and clean * 4 >= rows


def scan_stride(raw: bytes, deadline=None) -> int | None:
    """The smallest row length at which the bottom rows (SCAN_ROWS at least, a quarter of all) start
    with a filter byte and the bytes beside those starts mostly do not: the stride of the image the
    inflated tail belongs to."""
    top = min(len(raw) // SCAN_ROWS, MAX_WIDTH * 8 + 1)
    for stride in range(3, top + 1):
        if deadline is not None and not stride & 1023 and time.monotonic() > deadline:
            raise _OutOfBudget(f"width scan stopped at stride {stride}")
        rows, clean = filter_fit(raw, stride)
        if clean >= SCAN_ROWS and clean * 4 >= rows and _margin(raw, stride, clean) >= 0.25:
            return stride
    return None


def width_candidates(raw: bytes, given=(), hints=(), channels=(4, 3), deadline=None, skipped=None) -> list:
    """[(width, channels, how)] that fit the inflated tail, best first, at most MAX_CANDIDATES:
    1. each width the caller gave whose rows all start with a filter byte;
    2. the row length the filter-byte scan finds (scan_stride), read with each channel count in
       `channels` order (the cropped image's own first): one stride is several (width, channels);
    3. only when the scan finds nothing (a flat image whose bytes are mostly 0..4 everywhere): the
       hinted widths (`hints`, [(width, why)], the IHDR's first) that fit, smallest row first.
    A hinted width that only fits because its row is a multiple of the true one is never taken
    while the scan has an answer."""
    out, seen = [], set()
    named = {}
    for w, how in hints:
        named.setdefault(w, how)

    def add(w, ch, how):
        if 1 <= w <= MAX_WIDTH and (w, ch) not in seen and len(out) < MAX_CANDIDATES:
            seen.add((w, ch))
            out.append((w, ch, how))

    for w in given:
        for ch in channels:
            if fits(raw, w * ch + 1):
                add(w, ch, "width given")
    try:
        s0 = scan_stride(raw, deadline)
    except _OutOfBudget as e:
        s0 = None
        if skipped is not None:
            skipped.append(f"acropalypse: {e}")
    if s0:
        for ch in channels:
            if (s0 - 1) % ch == 0:
                w = (s0 - 1) // ch
                add(w, ch, f"width from the scanline filter bytes ({named[w]})" if w in named
                    else "width from the scanline filter bytes")
        return out
    fitting = []
    for k, (w, how) in enumerate(hints):
        for j, ch in enumerate(channels):
            if fits(raw, w * ch + 1):
                # the IHDR's width in the cropped image's own channel order first, then the common
                # widths shortest row first
                fitting.append((k > 0, 0 if k else j, w * ch + 1, j, w, ch, how))
    for *_rank, w, ch, how in sorted(fitting):
        add(w, ch, how + " (no filter-byte scan answer)")
    return out


AFTER_IEND = "after IEND"
AFTER_IDAT = "after the zlib stream in IDAT"


def idat_tail(data: bytes):
    """(file offset, bytes) of what the PNG's IDAT chunks hold after their zlib stream ends (the
    "after-IDAT" shape: the chunk kept an older, longer image's deflate tail), or None. The offset is
    where those bytes begin in the file, inside the IDAT chunk that holds the stream's end."""
    chunks = [c for c in cs.png_chunks(data) if c["type"] == "IDAT" and not c["after_iend"]]
    idat = b"".join(c["data"] for c in chunks)
    if not idat or len(idat) > MAX_RAW:
        return None
    d = zlib.decompressobj()
    try:
        d.decompress(idat, MAX_RAW)
    except zlib.error:
        return None
    if not d.eof or d.unconsumed_tail or not d.unused_data.strip(b"\x00"):
        return None
    at, pos = len(idat) - len(d.unused_data), 0
    for c in chunks:
        if at < pos + c["length"]:
            return c["offset"] + 8 + (at - pos), d.unused_data
        pos += c["length"]
    return None


def _tails(data: bytes, end: int) -> list:
    """[(where, file offset, deflate bytes)] that may be an older image's IDAT tail: the data after
    IEND when it ends with an IEND chunk of its own (its IDAT chunks unwrapped), and the bytes after
    the zlib stream inside IDAT. Each is at least 32 bytes and not all zeros."""
    out = []
    tail = data[end:] if end else b""
    if len(tail) >= 32 and tail.strip(b"\x00"):
        stream, _n, ended = tail_stream(tail)
        if ended:                                   # an older image's tail ends with its own IEND
            out.append((AFTER_IEND, end, stream))
    got = idat_tail(data)
    if got and len(got[1]) >= 32:
        out.append((AFTER_IDAT, got[0], got[1]))
    return out


def acropalypse(data: bytes, widths=(), deadline=None, skipped: list | None = None) -> list:
    """Every rebuild of the older image whose IDAT tail follows this PNG's IEND or its zlib stream
    inside IDAT, best reading first (the after-IEND tail's readings, then the after-IDAT ones); []
    when the file is no PNG, it carries no such tail, or no restart inflates to the tail's end."""
    if not data.startswith(PNG_SIG) or len(data) < 33:
        return []
    kind, end = cs.primary(data)
    if kind != "png":
        return []
    w0, _h0, depth, ctype = struct.unpack(">IIBB", data[16:26])
    chans = [_CHANNELS.get(ctype, 4)] + [c for c in (4, 3, 1, 2) if c != _CHANNELS.get(ctype, 4)]
    hints = [(w0, "the IHDR width")] + [(w, "a common screen width") for w in COMMON_WIDTHS if w != w0]
    palette = next((c["data"] for c in cs.png_chunks(data) if c["type"] == "PLTE"), None)
    out = []
    for where, offset, stream in _tails(data, end):
        try:
            got = restart(stream, deadline)
        except _OutOfBudget as e:
            if skipped is not None:
                skipped.append(f"acropalypse ({where}): {e}")
            continue
        if not got:
            continue
        bit, raw = got
        if depth == 16:
            if skipped is not None:
                skipped.append(f"acropalypse ({where}): 16-bit images are not rebuilt")
            continue
        for w, ch, how in width_candidates(raw, [int(w) for w in widths], hints, chans, deadline, skipped):
            stride = w * ch + 1
            rows = len(raw) // stride
            ct = 3 if ch == 1 and ctype == 3 else _CTYPE[ch]
            png = build_png(w, rows, ct, raw[len(raw) - rows * stride:], palette if ct == 3 else None)
            out.append(Recovery(w, rows, ch, ct, png, bit, offset, len(raw), how, tail=where))
    return out


# ---- fragmented PNG --------------------------------------------------------------------------------

@dataclass
class Reassembly:
    offset: int                     # where the PNG header is in the dump
    block_size: int
    pieces: list                    # [(start, end)] dump byte ranges, in the order they were joined
    png: bytes
    width: int
    height: int
    nodes: int
    file: str = ""
    source: str = "fragments"
    ocr: str | None = None
    ocr_flags: list = field(default_factory=list)

    @property
    def contiguous(self) -> bool:
        return all(a[1] == b[0] for a, b in zip(self.pieces, self.pieces[1:]))


def block_stats(blob: bytes, base: int, bs: int) -> list:
    """[(entropy in bits per byte, share of printable ASCII and whitespace)] of every bs-byte block
    from base (the last one may be short)."""
    import numpy as np
    printable = np.zeros(256, dtype=np.float64)
    printable[[9, 10, 13, *range(32, 127)]] = 1.0
    arr = np.frombuffer(blob, dtype=np.uint8)[base:]
    out = []
    step = max(1, (4 << 20) // bs) * bs              # about 4 MiB at a time
    for at in range(0, len(arr), step):
        part = arr[at:at + step]
        n = (len(part) + bs - 1) // bs
        idx = np.arange(len(part), dtype=np.int64) // bs
        counts = np.bincount(idx * 256 + part.astype(np.int64), minlength=n * 256).reshape(n, 256).astype(np.float64)
        sizes = counts.sum(axis=1, keepdims=True)
        p = counts / sizes
        with np.errstate(divide="ignore", invalid="ignore"):
            ent = -np.where(p > 0, p * np.log2(np.where(p > 0, p, 1.0)), 0.0).sum(axis=1)
        out += [(float(e), float(t)) for e, t in zip(ent, p @ printable)]
    return out


def may_hold_png(entropy: float, printable: float) -> bool:
    """A block that can be part of a PNG: not (nearly) one byte value over and over (erased or padded
    flash) and not text. Compressed image data is not always high-entropy (a flat area deflates to a
    few repeated codes), so entropy alone would split true fragments."""
    return entropy >= ENTROPY_MIN and printable < PRINTABLE_MAX


def _walk(buf: bytes, expected: int):
    """Parse the joined bytes from the signature: ('fail'|'need'|'done', where it stopped, the IDAT
    bytes so far, the bytes still needed to finish the open chunk and reach the smallest IEND)."""
    i, idat = 8, []
    while True:
        if i + 8 > len(buf):
            return "need", i, b"".join(idat), i + 12 - len(buf)
        ln = struct.unpack_from(">I", buf, i)[0]
        typ = buf[i + 4:i + 8]
        if ln > 0x7FFFFFFF or not all(65 <= c <= 90 or 97 <= c <= 122 for c in typ):
            return "fail", i, b"", 0
        if i == 8 and (typ != b"IHDR" or ln != 13):
            return "fail", i, b"", 0
        if i + 12 + ln > len(buf):
            part = buf[i + 8:] if typ == b"IDAT" else b""
            return "need", i, b"".join(idat) + part, i + 12 + ln - len(buf) + (0 if typ == b"IEND" else 12)
        body = buf[i + 8:i + 8 + ln]
        if zlib.crc32(typ + body) & 0xFFFFFFFF != struct.unpack_from(">I", buf, i + 8 + ln)[0]:
            return "fail", i, b"", 0
        if typ == b"IDAT":
            idat.append(body)
        i += 12 + ln
        if typ == b"IEND":
            return "done", i, b"".join(idat), 0


def _prefix_ok(idat: bytes, expected: int) -> bool:
    """The IDAT bytes joined so far are a plausible start of a stream of `expected` inflated bytes."""
    if not idat:
        return True
    d = zlib.decompressobj()
    try:
        out = d.decompress(idat, expected + 1)
    except zlib.error:
        return False
    if len(out) > expected:
        return False
    return not d.eof or len(out) == expected


def _whole(idat: bytes, expected: int) -> bool:
    d = zlib.decompressobj()
    try:
        out = d.decompress(idat, expected + 1)
    except zlib.error:
        return False
    return d.eof and len(out) == expected


def _reassemble_at(blob: bytes, h: int, bs: int, deadline, max_nodes: int, skipped: list):
    if len(blob) - h < 33 or blob[h + 12:h + 16] != b"IHDR":
        return None
    w, hh, depth, ctype, _c, _f, interlace = struct.unpack(">IIBBBBB", blob[h + 16:h + 29])
    expected = raw_size(w, hh, depth, ctype, interlace)
    if not expected or expected > MAX_RAW:
        return None
    base = h % bs
    cand = [may_hold_png(e, t) for e, t in block_stats(blob, base, bs)]
    for m in re.finditer(re.escape(IEND_TAIL), blob):
        for b in range(max(0, (m.start() - 4 - base) // bs), min(len(cand), (m.end() - 1 - base) // bs + 1)):
            cand[b] = True
    hb = (h - base) // bs
    # the header fragment holds at least every chunk that verifies in place (a text chunk there is
    # low-entropy but proven), up to where the first chunk that does not verify begins
    proven, i = h + 8, h + 8
    while True:
        got = _chunk_at(blob, i)
        if not got:
            break
        proven = i = got[2]
    for b in range(hb, min(len(cand), (proven - 1 - base) // bs + 1)):
        cand[b] = True
    runs, i = [], 0
    while i < len(cand):
        if not cand[i]:
            i += 1
            continue
        j = i + 1
        while j < len(cand) and cand[j] and j != hb:
            j += 1
        runs.append((base + i * bs, min(len(blob), base + j * bs)))
        i = j
    head = next(r for r in runs if r[0] == base + hb * bs)
    others = [r for r in runs if r != head]
    if len(others) > MAX_RUNS:
        skipped.append(f"fragments: {len(others)} candidate runs at block size {bs}; the {MAX_RUNS} nearest the header "
                       "are searched")
        others = sorted(sorted(others, key=lambda r: abs(r[0] - h))[:MAX_RUNS])
    first = (h, head[1])
    nodes = 0

    def dfs(buf: bytes, order: list, unused: tuple):
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            raise _OutOfBudget(f"fragments: search budget of {max_nodes} nodes spent at block size {bs}")
        if deadline is not None and time.monotonic() > deadline:
            raise _OutOfBudget(f"fragments: out of time at block size {bs}")
        state, end, idat, _need = _walk(buf, expected)
        if state == "fail":
            return None
        if state == "done":
            return (buf[:end], order) if _whole(idat, expected) else None
        if not _prefix_ok(idat, expected):
            return None
        # in dump order: runs are maximal, so none starts where the piece before it ends, and a
        # "physically next first" key would never pick anything out
        for r in unused:
            got = dfs(buf + blob[r[0]:r[1]], order + [r], tuple(x for x in unused if x != r))
            if got:
                return got
        return None

    try:
        got = dfs(blob[first[0]:first[1]], [first], tuple(others))
    except _OutOfBudget as e:
        skipped.append(str(e))
        return None
    if not got:
        return None
    png, order = got
    # the last piece ends where IEND does
    total, pieces = 0, []
    for s, e in order:
        take = min(e - s, len(png) - total)
        pieces.append((s, s + take))
        total += take
    return Reassembly(h, bs, pieces, png, w, hh, nodes)


def reassemble_png(blob: bytes, block_sizes=BLOCK_SIZES, deadline=None, max_nodes: int = MAX_NODES,
                   skipped: list | None = None) -> list:
    """Every PNG in blob that does not walk whole in place but can be joined from its blocks:
    [Reassembly], one per header. `skipped` gets a note for each search a budget cut short."""
    skipped = skipped if skipped is not None else []
    if len(blob) > MAX_DUMP:
        skipped.append(f"fragments: only the first {MAX_DUMP} bytes are searched")
        blob = blob[:MAX_DUMP]
    out, start = [], 0
    headers = []
    while len(headers) < MAX_HEADERS:
        h = blob.find(PNG_SIG, start)
        if h < 0:
            break
        headers.append(h)
        start = h + 1
    for h in headers:
        if intact_at(blob, h):
            continue
        for bs in block_sizes:
            got = _reassemble_at(blob, h, bs, deadline, max_nodes, skipped)
            if got:
                out.append(got)
                break
    return out


# ---- payloads: unpack, decode, search --------------------------------------------------------------

@dataclass
class Hit:
    file: str
    channel: str            # lsb | trailing | member | png_text | ...
    method: str
    flags: list
    preview: str
    data: bytes | None = None
    kind: str | None = None


def unpack(data: bytes, depth: int = 0, label: str = "") -> list:
    """[(label, bytes)]: data itself, then what gzip, zip and tar layers inside it hold (three deep)."""
    out = [(label, data)]
    if depth >= 3 or not data:
        return out
    if data[:3] == b"\x1f\x8b\x08":
        try:
            d = zlib.decompressobj(31)
            inner = d.decompress(data, MAX_RAW)
            if d.eof:
                out += unpack(inner, depth + 1, label + "/gunzip")
        except zlib.error:
            pass
    elif data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist()[:256]:
                    if not info.is_dir() and info.file_size <= MAX_RAW:
                        try:
                            out += unpack(z.read(info), depth + 1, f"{label}/{info.filename}")
                        except (RuntimeError, zipfile.BadZipFile, zlib.error, NotImplementedError):
                            out.append((f"{label}/{info.filename} (encrypted or unreadable)", b""))
        except zipfile.BadZipFile:
            pass
    elif len(data) >= 512 and data[257:262] == b"ustar":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as t:
                for m in t.getmembers()[:256]:
                    if m.isfile() and m.size <= MAX_RAW:
                        f = t.extractfile(m)
                        if f is not None:
                            out += unpack(f.read(), depth + 1, f"{label}/{m.name}")
        except tarfile.TarError:
            pass
    return out


def flags_in(data, ff) -> list:
    """The event flags in data, as it is and decoded (base64, base32, hex runs inside it)."""
    found = list(ff.find_flags(data))
    for b in ed.find_blobs(data, min_printable=0.0, flag_re=ff.bregex, max_results=200):
        if b["flag"]:
            found += [f for f in ff.find_flags(b["decoded"])]
    return list(dict.fromkeys(found))


def _preview(data: bytes, n: int = 120) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in data[:n])


def image_payloads(name: str, data: bytes, ff, deadline=None, skipped: list | None = None) -> list:
    """[Hit] of a PNG or BMP: carve_stego's structural readings (data after the end, appended
    archives and their members, text and unknown chunks) and every lsb_scan payload, unpacked and
    searched for the event's flag."""
    skipped = skipped if skipped is not None else []
    hits = []
    for f in cs.scan(name, data, deep=False, deadline=deadline, skipped=skipped):
        blob = f.get("data") if isinstance(f.get("data"), (bytes, bytearray)) else None
        text = f.get("text")
        flags = []
        for _lbl, part in unpack(bytes(blob)) if blob else []:
            flags += flags_in(part, ff)
        if text:
            flags += flags_in(text, ff)
        flags = list(dict.fromkeys(flags))
        if flags:
            hits.append(Hit(name, f["channel"], f["method"], flags, _preview(blob or text.encode("utf-8", "replace")),
                            bytes(blob) if blob else None, f.get("kind")))
    kind = cs.sniff(data)
    px = cs.png_pixels(data) if kind == "png" else cs.bmp_pixels(data) if kind == "bmp" else None
    if px and px["width"] * px["height"] <= cs.MAX_PIXELS:
        for hit in cs.lsb_scan(px, deadline=deadline, skipped=skipped):
            payload = hit["data"] if hit["what"] == "file" else hit["text"].encode("latin-1", "replace")
            flags = []
            for _lbl, part in unpack(payload):
                flags += flags_in(part, ff)
            members = [lbl for lbl, _p in unpack(payload) if lbl]
            what = hit["kind"] or "text"
            method = hit["method"] + (f" ({what}: {', '.join(members[:6])})" if members else f" ({what})")
            hits.append(Hit(name, "lsb", method, list(dict.fromkeys(flags)), _preview(payload), payload, hit["kind"]))
    return hits


# ---- OCR -------------------------------------------------------------------------------------------

def ocr_text(png: bytes, scale: int = OCR_SCALE, timeout: float = 60.0, deadline=None) -> str:
    """tesseract's text of a picture (upscaled `scale` times), page modes OCR_PSMS joined. ToolMissing
    when tesseract is not on PATH or Pillow is not importable. Each page mode gets `timeout` seconds,
    and never more than is left before `deadline` (time.monotonic()); OutOfBudget when no time is
    left or tesseract runs past it."""
    exe = shutil.which("tesseract")
    if not exe:
        raise ToolMissing("tesseract is not on PATH")
    try:
        from PIL import Image
    except ImportError as e:
        raise ToolMissing("Pillow is not importable (py:PIL)") from e
    im = Image.open(io.BytesIO(png))
    im.load()
    if im.mode not in ("L", "RGB"):
        im = im.convert("RGB")
    if scale > 1:
        im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
    texts = []
    with tempfile.TemporaryDirectory(prefix="image_carve_ocr_") as td:
        path = Path(td) / "in.png"
        im.save(path)
        for psm in OCR_PSMS:
            limit = timeout if deadline is None else min(timeout, deadline - time.monotonic())
            if limit <= 0:
                raise _OutOfBudget(f"no time left for tesseract --psm {psm}")
            try:
                r = subprocess.run([exe, str(path), "stdout", "--psm", str(psm)], capture_output=True, timeout=limit,
                                   stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired as e:
                raise _OutOfBudget(f"tesseract --psm {psm} stopped after {limit:.1f} s") from e
            if r.returncode != 0:
                raise RuntimeError(f"tesseract exited {r.returncode}: {r.stderr.decode('utf-8', 'replace')[:200]}")
            texts.append(r.stdout.decode("utf-8", "replace"))
    return "\n".join(texts)


def _spacings(body: str):
    """An OCR'd flag body with its spaces read as underscores (the usual slip), as read, and dropped."""
    out = [body.replace(" ", "_"), body, body.replace(" ", "")] if " " in body else [body]
    return list(dict.fromkeys(out))


def ocr_flags(text: str, ff, prefixes=()) -> list:
    """Flags in OCR text, each kept only when it is one flag in the event format: what the format
    finds as read, and for each stated prefix (on a word start) the form whose opening brace was read
    as ( [ i l | 1 and closing one as ) ]. A body with spaces is offered with them read as
    underscores first, then as read, then dropped. 0/O and 1/l inside are left as read."""
    raw = []
    for f in ff.find_flags(text):
        i = f.index("{")
        raw.append((f[:i], f[i + 1:-1]))
    for pre in prefixes:
        rx = r"(?<![A-Za-z0-9_])" + re.escape(pre) + r"\s*[\{\(\[il|1]([^\n\{\}\(\)\[\]]{1,200})[\}\)\]]"
        raw += [(pre, m.group(1).strip()) for m in re.finditer(rx, text)]
    found = []
    for pre, body in raw:
        found += [g for g in (f"{pre}{{{b}}}" for b in _spacings(body)) if ff.is_flag(g)]
    return list(dict.fromkeys(found))


def ocr_gate(images: list, ff, prefixes=(), deadline=None, skipped: list | None = None, read=None) -> None:
    """Read the rebuilt images by OCR, filling each one's .ocr and .ocr_flags. The readings of one
    image source (a file's aCropalypse rebuilds, one reassembled header) are tried best first and the
    first that reads a flag ends that source's OCR: a wrong width or channel count of the same bytes
    reads slowly, if at all. Past the deadline an image is left unread and named in `skipped`; the
    deadline is passed to `read`, so one reading cannot run far past it either (a reading it cuts
    short is named too). `read(png, deadline=)` is the OCR call (default ocr_text); ToolMissing from
    it propagates."""
    read = read or ocr_text
    done = set()
    for im in images:
        key = (im.source, im.file, getattr(im, "offset", None))
        if key in done:
            continue
        if deadline is not None and time.monotonic() > deadline:
            if skipped is not None:
                skipped.append(f"OCR gate: out of time before {im.file} ({im.source} {im.width}x{im.height})")
            continue
        try:
            im.ocr = read(im.png, deadline=deadline)
        except _OutOfBudget as e:
            if skipped is not None:
                skipped.append(f"OCR gate: out of time in {im.file} ({im.source} {im.width}x{im.height}): {e}")
            continue
        im.ocr_flags = ocr_flags(im.ocr, ff, prefixes)
        if im.ocr_flags:
            done.add(key)


# ---- one delivery ----------------------------------------------------------------------------------

@dataclass
class Report:
    hits: list = field(default_factory=list)            # [Hit]
    recoveries: list = field(default_factory=list)      # [Recovery]
    reassemblies: list = field(default_factory=list)    # [Reassembly]
    written: list = field(default_factory=list)         # [Path]
    skipped: list = field(default_factory=list)
    ocr: str = "not needed"                             # what happened to the OCR gate


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "file"


def examine(files: dict, ff, *, widths=(), ocr: str = "auto", out_dir: Path | None = None, deadline=None,
            prefixes=()) -> Report:
    """Run the three jobs over {name: bytes}; write rebuilt images and payloads under out_dir."""
    if ocr not in ("auto", "on", "off"):
        raise ValueError("ocr must be auto, on or off")
    rep = Report()
    seen = set()
    for name in sorted(files):
        data = files[name]
        digest = hashlib.sha256(data).digest()
        if digest in seen:
            continue
        seen.add(digest)
        kind = cs.sniff(data)
        if kind in ("png", "bmp"):
            rep.hits += image_payloads(name, data, ff, deadline, rep.skipped)
        if kind == "png":
            for r in acropalypse(data, widths, deadline, rep.skipped):
                r.file = name
                rep.recoveries.append(r)
        if PNG_SIG in data[:MAX_DUMP] and not (kind == "png" and intact_at(data, 0)):
            for r in reassemble_png(data, deadline=deadline, skipped=rep.skipped):
                r.file = name
                rep.reassemblies.append(r)
    images = rep.recoveries + rep.reassemblies
    if images and ocr != "off":
        try:
            ocr_gate(images, ff, prefixes, deadline, rep.skipped)
            rep.ocr = "run"
        except ToolMissing as e:
            if ocr == "on":
                raise
            rep.ocr = f"not run: {e}"
            rep.skipped.append(f"OCR gate not run: {e}; the rebuilt images are written for a human or model read")
    elif images:
        rep.ocr = "off"
    if out_dir is not None and (images or any(h.data for h in rep.hits if h.channel == "lsb")):
        out_dir.mkdir(parents=True, exist_ok=True)
        for k, im in enumerate(images):
            tag = (f"acropalypse-{im.width}x{im.height}-{im.channels}ch" if im.source == "acropalypse"
                   else f"fragments-{im.offset:#x}-{im.block_size}")
            p = out_dir / f"{_safe(im.file)}.{tag}.{k}.png"
            p.write_bytes(im.png)
            rep.written.append(p)
        for k, h in enumerate(x for x in rep.hits if x.channel == "lsb" and x.data):
            p = out_dir / f"{_safe(h.file)}.lsb.{k}.{cs.EXT.get(h.kind or 'text', 'bin')}"
            p.write_bytes(h.data)
            rep.written.append(p)
    return rep


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    proven, evidence = {}, []
    for h in rep.hits:
        for f in h.flags:
            proven.setdefault(f, h)
    for f, h in proven.items():
        evidence.append(Evidence("carve" if h.channel != "lsb" else "decode", f"{h.channel}: {h.method}", path=h.file))
    ocr_only = {}
    for im in rep.recoveries + rep.reassemblies:
        for f in im.ocr_flags:
            if f not in proven:
                ocr_only.setdefault(f, im)
    for f, im in ocr_only.items():
        what = (f"aCropalypse rebuild {im.width}x{im.height} ({im.how}), OCR" if im.source == "acropalypse"
                else f"fragmented PNG joined from {len(im.pieces)} pieces at block size {im.block_size}, OCR")
        evidence.append(Evidence("ocr", what, path=im.file))
    for p in rep.written:
        evidence.append(Evidence("carve", "written", path=rel(p)))
    notes = []
    for im in rep.recoveries:
        notes.append(f"aCropalypse: {im.file}: {im.width}x{im.height} {im.channels}ch ({im.how}), inflate restarted at "
                     f"bit {im.start_bit} of the tail {im.tail} at offset {im.tail_offset:#x}")
    for im in rep.reassemblies:
        notes.append(f"fragments: {im.file}: PNG at {im.offset:#x} {im.width}x{im.height} joined from "
                     f"{', '.join(f'{s:#x}-{e:#x}' for s, e in im.pieces)} (block size {im.block_size})")
    for h in rep.hits:
        if h.channel == "lsb" and not h.flags:
            notes.append(f"lsb payload with no flag: {h.file}: {h.method}: {h.preview[:80]}")
    if rep.ocr not in ("not needed", "run"):
        notes.append(f"OCR {rep.ocr}")
    notes += rep.skipped
    flags = list(proven) + list(ocr_only)
    if len(proven) == 1 and not ocr_only:
        status = "solved"
    elif flags:
        status = "candidate"
    elif rep.recoveries or rep.reassemblies or any(h.channel == "lsb" for h in rep.hits):
        status = "unsure"
    else:
        status = "none"
    return SolverResult(status=status, flags=flags, evidence=evidence, cost=Cost(seconds=round(seconds, 3)),
                        engine=ENGINE, challenge_id=challenge_id, notes="; ".join(notes))


# ---- the engine contract ---------------------------------------------------------------------------

SKIP_DIRS = {"recon", ".git"}
SKIP_FILES = {".sweep.json", ".sweep-owner", ".lock", "challenge.json", "notes.md", "triage.md"}


def challenge_files(challenge_dir: Path) -> dict:
    """{relative name: bytes} of a challenge's files: the sweep's scratch copy (`unpacked/`, originals
    and members) when there is one, else `files/`, else the folder itself; recon output, links and
    files over MAX_FILE left out."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if n in SKIP_FILES or p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_FILE:
                continue
            out[str(p.relative_to(challenge_dir))] = p.read_bytes()
    return out


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: widths (list of ints), ocr (auto|on|off), out (folder for rebuilt images
    and payloads; default <challenge>/recon/image_carve), seconds (budget, default 25)."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    ff = flagfmt.for_profile(profile)
    widths = opts.get("widths") or ()
    if isinstance(widths, (int, str)):
        widths = [widths]
    widths = [int(w) for w in widths]
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "image_carve"
    deadline = t0 + float(opts.get("seconds", DEFAULT_SECONDS))
    files = challenge_files(challenge_dir)
    try:
        rep = examine(files, ff, widths=widths, ocr=str(opts.get("ocr", "auto")), out_dir=out_dir, deadline=deadline,
                      prefixes=tuple(profile.flag.prefixes))
    except ToolMissing as e:
        return SolverResult(status="blocked", engine=ENGINE, notes=f"OCR was asked for (ocr=on) but {e}")
    return result_of(rep, seconds=time.monotonic() - t0, root=challenge_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="image_carve.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--width", type=int, action="append", default=[], help="a width to try for an aCropalypse rebuild")
    ap.add_argument("--out", type=Path, help="folder for rebuilt images and payloads (default: none written)")
    ap.add_argument("--ocr", choices=("auto", "on", "off"), default="auto")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"image_carve.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    files = {str(p): p.read_bytes() for p in a.files}
    try:
        rep = examine(files, flagfmt.for_profile(profile), widths=a.width, ocr=a.ocr, out_dir=a.out,
                      deadline=t0 + a.seconds, prefixes=tuple(profile.flag.prefixes))
    except ToolMissing as e:
        print(f"image_carve.py: --ocr on, but {e}", file=sys.stderr)
        return 2
    res = result_of(rep, seconds=time.monotonic() - t0)
    for h in rep.hits:
        print(f"[{h.channel}] {h.file}: {h.method}: flags={h.flags} {h.preview[:60]!r}")
    for im in rep.recoveries + rep.reassemblies:
        print(f"[{im.source}] {im.file}: {im.width}x{im.height} OCR flags={im.ocr_flags}")
    for p in rep.written:
        print(f"written: {p}")
    print(res.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
