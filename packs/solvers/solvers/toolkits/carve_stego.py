#!/usr/bin/env python3
"""Toolkit `carve_stego`: carving, structural steganography, QR and barcodes, small disk and dump
containers. Offline: no Game Master request, no token.

  .venv/bin/python solvers/toolkits/carve_stego.py <file>... [--json] [--extract DIR] [--quick]

prints a triage of each file: what it is, where its own structure ends, what follows, what is
carved out of it, its chunks, comments and hidden channels, the codes it shows, the file system
it holds. --extract writes every carved or recovered member under DIR.

1. Readers an agent can call by hand (bytes in, plain values out; nothing is executed or written):

  primary(data)                 (kind, end) of the structure the file starts with
  trailing(data)                the bytes after that end (after IEND, EOI, %%EOF, the zip's EOCD, ...)
  carve(data)                   validated embedded files: zip (by its EOCD), 7z, rar, gzip, zlib,
                                png, jpeg, gif, pdf, elf, pe, riff; each {offset, end, kind, data, inside}
  polyglot(data)                the formats one file is at once
  png_chunks / png_text / png_pixels / png_fix_dimensions
  jpeg_segments, gif_blocks, bmp_pixels, gif_pixels, webp_pixels, wav_info
  lsb_extract(px, ...), lsb_scan(px)      LSB planes in the usual orders, kept only when they parse
  lsb_deep_scan(px, ...)                  snake/column, keyed pixel shuffle, cross-plane/channel
                                          arithmetic and adjacent-pixel parity, auto-judged
  wav_lsb(data), dtmf(data)               sample LSBs; DTMF digits by Goertzel
  zero_width(text), whitespace_bits(text) zero-width, Unicode tag, variation-selector and
                                trailing-whitespace channels (agent_trace reads the same ones)
  decode_codes(image bytes)     QR, Aztec, DataMatrix, PDF417, MaxiCode and 1D codes (zxing-cpp
                                through Pillow; pyzbar when zxing-cpp is missing)
  text_grid(text) / decode_grid(text)     a code drawn in text: block characters, 0/1 rows, ANSI
  decode_nested(data)           a code whose payload is another code (base64, data URI, text grid)
  carve_stego_fs: iso9660, fat (deleted entries), ext2, cpio, uimage, recycle_i, minidump, elf_core
  scan(name, data)              every finding of one file; scan_files(files) for a delivery
  carved_files(files)           the carved and recovered members as '<file> -> <member>' entries,
                                to hand back to solvers/common/triage.py and toolkits/evidence_core.py

2. signals(questions, files) -> 0..1: how much a delivery and its questions look like this category.

3. solve_set(questions, files, ctx): the runner contract, never guessing (AGENTS.md "Uncertain
answers"). It answers only a question whose own words name one of these channels (hidden,
embedded, appended, carved, chunk, comment, LSB, QR, barcode, DTMF, zero-width, deleted, recycle,
disk image, dump); any other question is None, so every base of Days 1 to 8 is None. An answer is
  - plain: a hash, size or count of the ONE extracted item the words name; a payload that the
    question's own pattern accepts and that is the only such value in every channel; the one
    payload of a channel the question names (the QR's text, the DTMF digits, the comment);
  - labels.pick('carve_stego.<field>/<shape>', ...): an established fact whose spelling or form is
    not judged (a type name, a timestamp form, an offset as decimal or hex, a payload no pattern
    confirms);
  - None: two candidates, no candidate, or anything else.
A question about a decoded `message` (the Warmups form) over an image or a recording is offered
unsure under 'warmups.message/carve_stego.<channel>'.

Never here: a password that is not in solvers/common/archive_passwords.py, OCR, SSTV, spectrogram
reading, Volatility. Those are agent work through tools/sandbox.py, off the clock. Pillow, numpy
and zxing-cpp are imported only when a picture or a recording is actually decoded; everything else
is the standard library.
"""
import base64
import binascii
from array import array
import hashlib
import io
import json
import math
import random
import re
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
for _p in (str(COMMON), str(HERE)):
    if _p not in sys.path:
        sys.path.append(_p)

import carve_stego_fs as fs     # noqa: E402

KEY = "carve_stego"
ARROW = " -> "
SENTINEL = "??"
MAX_SCAN = 16 * 1024 * 1024         # bytes of one file searched for embedded files
MAX_INFLATE = 64 * 1024 * 1024
MAX_PIXELS = 16 * 1000 * 1000
STDLIB_PNG = 600_000                # raw bytes up to which a PNG is unfiltered in plain Python
LSB_BYTES = 1 << 16                 # bytes read from each LSB plane
MAX_PERMUTED_PIXELS = 2_000_000     # keyed shuffle: at most 8 MiB for array('I')
BUDGET = 1.0                        # seconds solve_set spends reading one set's files
BUDGET_UNTIMED = 20.0               # the same when the attempt has no deadline (an untimed base)
NEST = 6                            # depth of a code inside a code


def _tri():
    import triage
    return triage


def pick(field: str, shape: str, options, lane: str = KEY):
    """labels.pick for '<lane>.<field>/<shape>'. solvers/common/labels.py knows five lane prefixes;
    until `carve_stego` is one of them the unsure string is written here in the same wire form,
    with no ledger behind it (nothing is remembered and tools/verify.py cannot probe the key)."""
    opts, seen = [], set()
    for item in options or []:
        name, value = item if isinstance(item, (tuple, list)) and len(item) == 2 else (str(item), item)
        if name and value is not None and name not in seen:
            seen.add(name)
            opts.append((str(name), value))
    if not opts:
        return None
    key = f"{lane}.{field}/{shape}".lower()
    try:
        import labels
        return labels.pick(key, opts)
    except (ValueError, ImportError):
        pass
    return SENTINEL + json.dumps({"k": key, "o": [[n, v] for n, v in opts[:12]]}, separators=(",", ":"))


# ---- what the bytes start with, and where that ends ------------------------------------------------

PNG_SIG = b"\x89PNG\r\n\x1a\n"
EXT = {"zip": "zip", "png": "png", "jpeg": "jpg", "gif": "gif", "pdf": "pdf", "gzip": "gz", "zlib": "bin", "7z": "7z",
       "rar": "rar", "elf": "elf", "pe": "exe", "wav": "wav", "webp": "webp", "avi": "avi", "riff": "riff", "bmp": "bmp",
       "text": "txt", "tar": "tar"}


def sniff(data: bytes) -> str:
    """A short kind by magic: png, jpeg, gif, bmp, pdf, zip, gzip, 7z, rar, elf, pe, wav, webp, avi,
    tiff, iso9660, ext, fat12/16/32, cpio, uimage, minidump, text, data."""
    h = data[:16]
    if h.startswith(PNG_SIG):
        return "png"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h.startswith(b"%PDF-"):
        return "pdf"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if h.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h[:4] == b"RIFF" and len(data) >= 12:
        return {b"WAVE": "wav", b"WEBP": "webp", b"AVI ": "avi"}.get(data[8:12], "riff")
    if h[:4] == b"MDMP":
        return "minidump"
    if h[:4] == b"\x27\x05\x19\x56":
        return "uimage"
    if h[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if h[:2] == b"MZ" and _pe_end(data, 0):
        return "pe"
    if h[:2] == b"BM" and _bmp_end(data, 0):
        return "bmp"
    k = fs.kind_of(data)
    if k:
        return k
    return "text" if _is_text(data[:4096]) else "data"


def _is_text(sample: bytes) -> bool:
    if not sample:
        return False
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = sample[:-3].decode("utf-8")
        except UnicodeDecodeError:
            return False
    return sum(1 for c in text if c.isprintable() or c in "\r\n\t\x1b" or 0x200b <= ord(c) <= 0x2064
               or 0xfe00 <= ord(c) <= 0xfeff or ord(c) >= 0xe0000) >= 0.9 * max(1, len(text))


def as_text(data: bytes):
    """The bytes as text (UTF-8, UTF-16 with a BOM), or None."""
    try:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return data.decode("utf-16")
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _png_end(data, off):
    i, n = off + 8, 0
    while i + 12 <= len(data) and n < 100000:
        ln = struct.unpack_from(">I", data, i)[0]
        typ = data[i + 4:i + 8]
        if ln > 0x7FFFFFFF or not all(65 <= c <= 90 or 97 <= c <= 122 for c in typ):
            return None
        if n == 0 and typ not in (b"IHDR", b"CgBI"):       # CgBI: Apple's iOS-optimised PNG
            return None
        i += 12 + ln
        n += 1
        if typ == b"IEND":
            return i if i <= len(data) else None
    return None


def _jpeg_end(data, off):
    i, n, sof, sos = off + 2, len(data), False, False
    while i + 2 <= n:
        if data[i] != 0xFF:
            return None
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            return i + 2 if sof and sos else None
        if m in (0x01,) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if i + 4 > n:
            return None
        ln = struct.unpack_from(">H", data, i + 2)[0]
        if ln < 2:
            return None
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            sof = True
        i += 2 + ln
        if m == 0xDA:                               # entropy-coded data up to the next real marker
            sos = True
            while True:
                j = data.find(b"\xff", i)
                if j < 0 or j + 1 >= n:
                    return None
                nxt = data[j + 1]
                if nxt == 0 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    i = j + 1 if nxt == 0xFF else j + 2
                    continue
                i = j
                break
    return None


def _gif_end(data, off):
    try:
        if len(data) < off + 13:
            return None
        flags = data[off + 10]
        i = off + 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
        frames = 0
        while i < len(data):
            b = data[i]
            if b == 0x3B:
                return i + 1 if frames else None
            if b == 0x21:
                i += 2
            elif b == 0x2C:
                lf = data[i + 9]
                i += 10 + (3 * (2 << (lf & 7)) if lf & 0x80 else 0) + 1
                frames += 1
            else:
                return None
            while True:                             # sub-blocks
                ln = data[i]
                i += 1 + ln
                if ln == 0:
                    break
    except IndexError:
        return None
    return None


def _pdf_end(data, off):
    j = data.rfind(b"%%EOF")
    if j < off:
        return None
    j += 5
    while j < len(data) and data[j:j + 1] in (b"\r", b"\n"):
        j += 1
    return j


def _inflate_at(data, off, wbits):
    """(end, output) of one whole deflate stream at off, fed a piece at a time so that a false start
    costs a few kilobytes; None when it breaks, does not end, or grows past MAX_INFLATE."""
    d = zlib.decompressobj(wbits)
    out, total, pos, size = [], 0, off, 4096
    try:
        while True:
            piece = data[pos:pos + size]
            if not piece:
                return None
            got = d.decompress(piece, MAX_INFLATE - total + 1)
            total += len(got)
            out.append(got)
            if total > MAX_INFLATE or d.unconsumed_tail:
                return None
            if d.eof:
                return pos + len(piece) - len(d.unused_data), b"".join(out)
            pos += len(piece)
            size = min(size * 4, 1 << 20)
    except zlib.error:
        return None


def _gzip_end(data, off, want_out=False):
    got = _inflate_at(data, off, 31)
    if not got:
        return None
    return got if want_out else got[0]


def _zlib_at(data, off):
    """(end, inflated) of a whole zlib stream at off (Adler-32 checked), or None."""
    if off + 2 > len(data) or data[off] & 0x0F != 8 or data[off] >> 4 > 7 or (data[off] << 8 | data[off + 1]) % 31:
        return None
    return _inflate_at(data, off, 15)


def _7z_end(data, off):
    if len(data) < off + 32:
        return None
    crc, nxt, size = struct.unpack_from("<IQQ", data, off + 8)
    if zlib.crc32(data[off + 12:off + 32]) & 0xFFFFFFFF != crc:
        return None
    end = off + 32 + nxt + size
    return end if end <= len(data) else None


def _elf_end(data, off):
    try:
        if data[off + 4] not in (1, 2) or data[off + 5] not in (1, 2) or data[off + 6] != 1:
            return None
        e = "<" if data[off + 5] == 1 else ">"
        if data[off + 4] == 2:
            phoff, shoff = struct.unpack_from(e + "QQ", data, off + 32)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, off + 54)
        else:
            phoff, shoff = struct.unpack_from(e + "II", data, off + 28)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, off + 42)
        if struct.unpack_from(e + "H", data, off + 16)[0] > 4 and struct.unpack_from(e + "H", data, off + 16)[0] < 0xFE00:
            return None
        end = shoff + shentsize * shnum if shoff else 0
        for k in range(min(phnum, 128)):
            p = off + phoff + k * phentsize
            if data[off + 4] == 2:
                poff, _, _, filesz = struct.unpack_from(e + "QQQQ", data, p + 8)
            else:
                poff, _, _, filesz = struct.unpack_from(e + "IIII", data, p + 4)
            end = max(end, poff + filesz)
        return off + end if 52 <= end <= len(data) - off else None
    except (struct.error, IndexError):
        return None


def _pe_end(data, off):
    try:
        lfa = struct.unpack_from("<I", data, off + 0x3C)[0]
        p = off + lfa
        if lfa > 0x1000 or data[p:p + 4] != b"PE\x00\x00":
            return None
        nsec, opt = struct.unpack_from("<H", data, p + 6)[0], struct.unpack_from("<H", data, p + 20)[0]
        end = lfa + 24 + opt + nsec * 40
        for k in range(min(nsec, 96)):
            rsize, rptr = struct.unpack_from("<II", data, p + 24 + opt + k * 40 + 16)
            if rptr:
                end = max(end, rptr + rsize)
        magic = struct.unpack_from("<H", data, p + 24)[0]
        dirs = p + 24 + (96 if magic == 0x10B else 112)
        if opt >= (dirs - p - 24) + 5 * 8:           # the certificate table is addressed by file offset
            coff, csize = struct.unpack_from("<II", data, dirs + 4 * 8)
            if coff and coff + csize <= len(data) - off:
                end = max(end, coff + csize)
        return off + end if end <= len(data) - off else None
    except (struct.error, IndexError):
        return None


def _riff_end(data, off):
    if len(data) < off + 12 or data[off + 8:off + 12] not in (b"WAVE", b"WEBP", b"AVI "):
        return None
    end = off + 8 + struct.unpack_from("<I", data, off + 4)[0]
    end += end & 1 and end < len(data)
    return end if off + 12 < end <= len(data) else None


def _bmp_end(data, off):
    if len(data) < off + 26:
        return None
    size, r, pix, hdr = struct.unpack_from("<IIII", data, off + 2)
    if r or hdr not in (12, 40, 52, 56, 108, 124) or not 14 + hdr <= pix <= size or size > len(data) - off:
        return None
    return off + size


def zips(data: bytes) -> list:
    """Every zip archive in the bytes, found by its end-of-central-directory record:
    [{offset, end, names, comment, data}]. A zip may start anywhere (appended, prefixed)."""
    out, i = [], 0
    scan = data[:MAX_SCAN * 4]
    while len(out) < 64:
        e = scan.find(b"PK\x05\x06", i)
        if e < 0 or e + 22 > len(scan):
            break
        i = e + 4
        _, _, _, total, cd_size, cd_off, clen = struct.unpack_from("<HHHHIIH", scan, e + 4)
        end = e + 22 + clen
        start = e - cd_size - cd_off
        if start < 0 or end > len(scan) or cd_size > e:
            continue
        if total and scan[e - cd_size:e - cd_size + 4] != b"PK\x01\x02":
            continue
        if total and scan[start:start + 4] not in (b"PK\x03\x04", b"PK\x07\x08"):
            # the offsets may count from the start of the host file (zip -A style)
            if scan[cd_off:cd_off + 4] == b"PK\x01\x02" and cd_off + cd_size == e:
                first = scan.find(b"PK\x03\x04")
                start = first if 0 <= first < cd_off else -1
                blob = scan[:end] if start >= 0 else None
            else:
                continue
        else:
            blob = scan[start:end]
        if start < 0 or blob is None:
            continue
        try:
            names = zipfile.ZipFile(io.BytesIO(blob)).namelist()
        except (zipfile.BadZipFile, ValueError, OSError, struct.error):
            continue
        out.append({"offset": start, "end": end, "names": names, "data": scan[start:end], "whole": blob,
                    "comment": scan[e + 22:end]})
        i = end
    return out


def primary(data: bytes):
    """(kind, end): the structure the file starts with and the offset where it ends. (kind, None)
    when the format has no end this reader can prove; ("data"|"text", 0) for no known structure."""
    kind = sniff(data)
    end = None
    if kind == "png":
        end = _png_end(data, 0)
    elif kind == "jpeg":
        end = _jpeg_end(data, 0)
    elif kind == "gif":
        end = _gif_end(data, 0)
    elif kind == "pdf":
        end = _pdf_end(data, 0)
    elif kind == "zip":
        z = [x for x in zips(data) if x["offset"] == 0]
        end = z[-1]["end"] if z else None
    elif kind == "gzip":
        end = _gzip_end(data, 0)
    elif kind == "7z":
        end = _7z_end(data, 0)
    elif kind == "elf":
        end = _elf_end(data, 0)
    elif kind == "pe":
        end = _pe_end(data, 0)
    elif kind in ("wav", "webp", "avi"):
        end = _riff_end(data, 0)
    elif kind == "bmp":
        end = _bmp_end(data, 0)
    elif kind in ("text", "data"):
        end = 0
    return kind, end


def trailing(data: bytes):
    """(offset, bytes) after the end of the file's own structure, or None when nothing follows
    (NUL and whitespace padding is nothing) or the end cannot be proven."""
    kind, end = primary(data)
    if not end or kind in ("text", "data") or end >= len(data):
        return None
    tail = data[end:]
    if not tail.strip(b"\x00\r\n\t "):
        return None
    return end, tail


_SIZERS = (
    (PNG_SIG, "png", _png_end), (b"\xff\xd8\xff", "jpeg", _jpeg_end), (b"GIF89a", "gif", _gif_end),
    (b"GIF87a", "gif", _gif_end), (b"%PDF-", "pdf", _pdf_end), (b"\x1f\x8b\x08", "gzip", _gzip_end),
    (b"7z\xbc\xaf\x27\x1c", "7z", _7z_end), (b"\x7fELF", "elf", _elf_end), (b"MZ", "pe", _pe_end),
    (b"RIFF", "riff", _riff_end),
)
_NATURAL = {"png": {"zlib"}, "jpeg": {"jpeg"}, "pdf": {"zlib", "jpeg", "gzip"}, "elf": set(), "pe": set(),
            "wav": set(), "webp": set(), "avi": {"jpeg"}, "bmp": set(), "gif": set(), "tiff": {"jpeg", "zlib"}}
_OPAQUE = {"zip", "gzip", "7z", "rar"}             # nothing is carved out of a packed host's own span


def carve(data: bytes, min_zlib: int = 32) -> list:
    """Embedded files, each proven by its own structure: [{offset, end, kind, data, inside, names}].
    `inside` is True for a hit within the host's own span (a zip in a WAV's data chunk) and False
    for one after it or in a file with no structure of its own. A hit inside an earlier hit is that
    one's business (carve it again). The file itself (offset 0) is not listed. A rar is listed
    unvalidated (`validated` False) to the end of the file."""
    kind, end = primary(data)
    host_end = end if end else (len(data) if kind in _OPAQUE else 0)
    if kind in ("text", "data"):
        host_end = 0
    natural = _NATURAL.get(kind, set())
    hits = []
    for z in zips(data):
        if z["offset"] > 0:
            hits.append({"offset": z["offset"], "end": z["end"], "kind": "zip", "data": z["data"], "names": z["names"],
                         "validated": True})
    scan = data[:MAX_SCAN]
    for magic, k, sizer in _SIZERS:
        i = scan.find(magic, 1)
        tries = 0
        while i > 0 and tries < 4000:
            tries += 1
            e = sizer(data, i)
            if e and e > i + len(magic) + 4:
                kk = k if k != "riff" else {b"WAVE": "wav", b"WEBP": "webp", b"AVI ": "avi"}.get(data[i + 8:i + 12], "riff")
                hits.append({"offset": i, "end": e, "kind": kk, "data": data[i:e], "validated": True})
            i = scan.find(magic, i + 1)
    i = scan.find(b"Rar!\x1a\x07", 1)
    if i > 0:
        hits.append({"offset": i, "end": len(data), "kind": "rar", "data": data[i:], "validated": False})
    if "zlib" not in natural:
        tries = 0
        for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", scan):
            if m.start() == 0 or tries >= 3000:
                continue
            tries += 1
            got = _zlib_at(data, m.start())
            if got and len(got[1]) >= min_zlib:
                hits.append({"offset": m.start(), "end": got[0], "kind": "zlib", "data": data[m.start():got[0]],
                             "inflated": got[1], "validated": True})
    hits.sort(key=lambda h: (h["offset"], -h["end"]))
    out, covered = [], 0
    for h in hits:
        inside = h["offset"] < host_end
        if inside and (kind in _OPAQUE or h["kind"] in natural):
            continue
        if h["offset"] < covered:
            continue
        h["inside"] = inside
        out.append(h)
        covered = h["end"]
    return out


def polyglot(data: bytes) -> list:
    """The formats the file is at once (two or more), or []. A zip counts when its archive ends the
    file wherever it starts; a PDF when its header sits in the first 1024 bytes."""
    kind, _ = primary(data)
    kinds = [kind] if kind not in ("text", "data") else []
    for z in zips(data):
        if z["end"] >= len(data.rstrip(b"\x00\r\n")) and "zip" not in kinds:
            kinds.append("zip")
    j = data[:1024].find(b"%PDF-")
    if j > 0 and b"%%EOF" in data and "pdf" not in kinds:
        kinds.append("pdf")
    if kind != "jpeg" and data[:2] == b"\xff\xd8" and "jpeg" not in kinds:
        kinds.append("jpeg")
    low = data[:2048].lower()
    if kinds and kind not in ("text",) and (b"<script" in low or b"<html" in low):
        kinds.append("html")
    return kinds if len(kinds) >= 2 else []


# ---- PNG --------------------------------------------------------------------------------------------

PNG_STANDARD = {"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "tEXt", "zTXt", "iTXt",
                "bKGD", "hIST", "pHYs", "sPLT", "tIME", "eXIf", "acTL", "fcTL", "fdAT", "cICP", "mDCV", "cLLI", "oFFs",
                "pCAL", "sCAL", "sTER", "gIFg", "gIFx", "vpAg", "caNv", "iDOT", "orNT"}


def png_chunks(data: bytes) -> list:
    """[{type, offset, length, crc_ok, standard, data, after_iend}] of a PNG, in file order; chunks
    that still parse after IEND are listed with after_iend True."""
    if not data.startswith(PNG_SIG):
        return []
    out, i, ended = [], 8, False
    while i + 12 <= len(data) and len(out) < 100000:
        ln = struct.unpack_from(">I", data, i)[0]
        typ = data[i + 4:i + 8]
        if i + 12 + ln > len(data) or not all(65 <= c <= 90 or 97 <= c <= 122 for c in typ):
            break
        body = data[i + 8:i + 8 + ln]
        crc = struct.unpack_from(">I", data, i + 8 + ln)[0]
        name = typ.decode("ascii")
        out.append({"type": name, "offset": i, "length": ln, "crc_ok": zlib.crc32(typ + body) & 0xFFFFFFFF == crc,
                    "standard": name in PNG_STANDARD, "data": body, "after_iend": ended})
        ended = ended or name == "IEND"
        i += 12 + ln
    return out


def png_text(data: bytes) -> list:
    """[(chunk type, keyword, text)] of tEXt, zTXt and iTXt chunks."""
    out = []
    for c in png_chunks(data):
        b = c["data"]
        try:
            if c["type"] == "tEXt":
                k, _, v = b.partition(b"\x00")
                out.append(("tEXt", k.decode("latin-1"), v.decode("latin-1")))
            elif c["type"] == "zTXt":
                k, _, v = b.partition(b"\x00")
                out.append(("zTXt", k.decode("latin-1"), zlib.decompressobj().decompress(v[1:], 1 << 20).decode("latin-1")))
            elif c["type"] == "iTXt":
                k, _, rest = b.partition(b"\x00")
                flag = rest[0]
                _lang, _, rest2 = rest[2:].partition(b"\x00")
                _tk, _, v = rest2.partition(b"\x00")
                v = zlib.decompressobj().decompress(v, 1 << 20) if flag else v
                out.append(("iTXt", k.decode("latin-1"), v.decode("utf-8", "replace")))
        except (zlib.error, IndexError):
            continue
    return out


def png_fix_dimensions(data: bytes, limit: int = 8192):
    """(width, height) that make a damaged IHDR's CRC right, or None: the IHDR whose stored CRC does
    not match is tried with every height, then every width, then both up to 2048."""
    if not data.startswith(PNG_SIG) or data[12:16] != b"IHDR":
        return None
    body, crc = bytearray(data[12:29]), struct.unpack_from(">I", data, 29)[0]
    if zlib.crc32(bytes(body)) & 0xFFFFFFFF == crc:
        return None
    w0, h0 = struct.unpack_from(">II", body, 4)
    for h in range(1, limit + 1):
        struct.pack_into(">I", body, 8, h)
        if zlib.crc32(bytes(body)) & 0xFFFFFFFF == crc:
            return w0, h
    struct.pack_into(">I", body, 8, h0)
    for w in range(1, limit + 1):
        struct.pack_into(">I", body, 4, w)
        if zlib.crc32(bytes(body)) & 0xFFFFFFFF == crc:
            return w, h0
    tail = bytes(body[12:])
    for w in range(1, 2049):
        head = zlib.crc32(b"IHDR" + struct.pack(">I", w))
        for h in range(1, 2049):
            if zlib.crc32(struct.pack(">I", h) + tail, head) & 0xFFFFFFFF == crc:
                return w, h
    return None


_PNG_CH = {0: ("L", 1), 2: ("RGB", 3), 3: ("P", 1), 4: ("LA", 2), 6: ("RGBA", 4)}


def _png_stdlib(data: bytes):
    chunks = png_chunks(data)
    if not chunks or chunks[0]["type"] != "IHDR" or chunks[0]["length"] != 13:
        return None
    w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", chunks[0]["data"])
    if ctype not in _PNG_CH or interlace or depth not in (1, 2, 4, 8, 16) or not w or not h or w * h > MAX_PIXELS:
        return None
    mode, ch = _PNG_CH[ctype]
    stride = (w * ch * depth + 7) // 8
    try:
        raw = zlib.decompressobj().decompress(b"".join(c["data"] for c in chunks if c["type"] == "IDAT" and not c["after_iend"]),
                                              (stride + 1) * h)
    except zlib.error:
        return None
    if len(raw) < (stride + 1) * h:
        return None
    bpp = max(1, ch * depth // 8)
    out = bytearray()
    prev = bytes(stride)
    for y in range(h):
        base = y * (stride + 1)
        ft = raw[base]
        line = bytearray(raw[base + 1:base + 1 + stride])
        if ft == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 255
        elif ft == 2:
            line = bytearray((a + b) & 255 for a, b in zip(line, prev))
        elif ft == 3:
            for i in range(stride):
                line[i] = (line[i] + (((line[i - bpp] if i >= bpp else 0) + prev[i]) >> 1)) & 255
        elif ft == 4:
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        elif ft != 0:
            return None
        out += line
        prev = bytes(line)
    samples = bytes(out)
    if depth < 8:                                   # one byte per sample
        mask, per = (1 << depth) - 1, 8 // depth
        rows = []
        for y in range(h):
            row = samples[y * stride:(y + 1) * stride]
            vals = bytearray()
            for byte in row:
                for k in range(per):
                    vals.append((byte >> (8 - depth * (k + 1))) & mask)
            rows.append(bytes(vals[:w * ch]))
        samples = b"".join(rows)
    elif depth == 16:                               # the low byte carries the LSB
        samples = samples[1::2]
    palette = next((c["data"] for c in chunks if c["type"] == "PLTE"), None)
    return {"width": w, "height": h, "mode": mode, "channels": ch, "depth": depth, "data": samples, "palette": palette,
            "by": "stdlib"}


def _pillow(data: bytes):
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS * 4
        im = Image.open(io.BytesIO(data))
        im.load()
        return im
    except Exception:
        return None


def png_pixels(data: bytes, by: str = "auto"):
    """A PNG's samples: {width, height, mode (L, LA, RGB, RGBA, P), channels, depth, data (one byte
    per sample, row by row), palette}. Plain Python (inflate and unfilter) for a small image, Pillow
    for a large or interlaced one when it is installed; by='stdlib' or 'pillow' forces one."""
    if not data.startswith(PNG_SIG) or len(data) < 33:
        return None
    w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", data[16:29])
    raw = w * h * _PNG_CH.get(ctype, ("", 4))[1] * max(1, depth // 8)
    if by == "stdlib" or (by == "auto" and not interlace and raw <= STDLIB_PNG):
        px = _png_stdlib(data)
        if px or by == "stdlib":
            return px
    im = _pillow(data)
    if im is None:
        return _png_stdlib(data) if by == "auto" and raw <= 16 * STDLIB_PNG else None
    if im.width * im.height > MAX_PIXELS:
        return None
    if im.mode not in ("L", "LA", "RGB", "RGBA", "P"):
        im = im.convert("RGBA" if "A" in im.mode else "RGB" if im.mode not in ("1", "I;16", "I") else "L")
    return {"width": im.width, "height": im.height, "mode": im.mode, "channels": len(im.getbands()), "depth": depth,
            "data": im.tobytes(), "palette": None, "by": "pillow"}


def png_idat_extra(data: bytes, chunks: list = None) -> list:
    """[(where, bytes)] of what a PNG's image data carries beyond the picture: bytes 'after the zlib
    stream' inside the IDAT chunks, and inflated bytes 'after the last scanline' (the stream holds
    more than height rows; not checked for an interlaced image). [] when the stream does not inflate."""
    if not data.startswith(PNG_SIG) or len(data) < 33:
        return []
    chunks = chunks if chunks is not None else png_chunks(data)
    idat = b"".join(c["data"] for c in chunks if c["type"] == "IDAT" and not c.get("after_iend"))
    if not idat or len(idat) > MAX_INFLATE:
        return []
    out = []
    try:
        d = zlib.decompressobj()
        raw = d.decompress(idat, MAX_INFLATE)
        if d.unconsumed_tail:
            return []                               # more than the limit: nothing is said about its end
        if d.eof and d.unused_data.strip(b"\x00"):
            out.append(("after the zlib stream", d.unused_data))
    except zlib.error:
        return []
    w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", data[16:29])
    ch = _PNG_CH.get(ctype, ("", 0))[1]
    if not interlace and ch and depth in (1, 2, 4, 8, 16) and w and h:
        want = h * (1 + (w * ch * depth + 7) // 8)
        if len(raw) > want and raw[want:].strip(b"\x00"):
            out.append(("after the last scanline", raw[want:]))
    return out


def bmp_pixels(data: bytes):
    """An uncompressed 8/24/32-bit BMP's samples in STORED order (bottom-up rows as they are in the
    file, B G R): {width, height, mode 'BGR'|'BGRA'|'P', channels, data, bottom_up, stride, raw};
    `raw` is the pixel array as stored, each row with its padding to four bytes."""
    if data[:2] != b"BM" or len(data) < 54:
        return None
    pix, hdr, w, h, _planes, bits, comp = struct.unpack_from("<IIiiHHI", data, 10)
    if hdr < 40 or comp not in (0, 3) or bits not in (8, 24, 32) or w <= 0 or not h or w * abs(h) > MAX_PIXELS:
        return None
    ch = bits // 8
    stride = (w * ch + 3) & ~3
    rows = [data[pix + y * stride:pix + y * stride + w * ch] for y in range(abs(h))]
    if any(len(r) != w * ch for r in rows):
        return None
    return {"width": w, "height": abs(h), "mode": {1: "P", 3: "BGR", 4: "BGRA"}[ch], "channels": ch, "depth": 8,
            "data": b"".join(rows), "palette": None, "bottom_up": h > 0, "by": "stdlib", "stride": stride,
            "raw": data[pix:pix + stride * abs(h)]}


def gif_pixels(data: bytes):
    """A GIF's FIRST frame as palette indices, the same {width, height, mode, channels, depth, data
    (one byte per sample, row by row), palette} shape as png_pixels. mode is 'P', so `data` is the
    index of each pixel into the colour table, one byte per pixel: the LSB of a palette INDEX is what
    a palette-LSB tool writes (what zsteg calls `b1,p` / `b1,index`), not the LSB of a resolved RGB
    channel, so the indices are the samples. Only frame 0 (Pillow opens there); an animation's later
    frames are not read. Needs Pillow; None when it is missing, the image does not decode, Pillow
    hands back something that is not a one-byte-per-sample palette image, or it is too large."""
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return None
    im = _pillow(data)
    if im is None:
        return None
    if im.width * im.height > MAX_PIXELS:
        return None
    if im.mode != "P" or len(im.getbands()) != 1:
        # a GIF Pillow resolves to RGB/RGBA (unusual) is not the palette-index channel this reader is
        # for; leave it to the RGB readers rather than read a channel it did not mean.
        return None
    body = im.tobytes()
    if len(body) != im.width * im.height:
        return None
    pal = None
    try:
        p = im.getpalette()
        pal = bytes(p) if p else None
    except Exception:
        pal = None
    return {"width": im.width, "height": im.height, "mode": "P", "channels": 1, "depth": 8,
            "data": body, "palette": pal, "by": "pillow"}


def webp_pixels(data: bytes):
    """A WebP's samples as RGB or RGBA (one byte per sample, row by row), the same shape as
    png_pixels. A LOSSLESS WebP keeps the exact bytes a tool wrote, so its LSB planes read back; a
    LOSSY WebP is re-quantised by the codec, so its low bits are not the ones a tool wrote and a
    reading of them validates only by chance -- which the CRC/checksum self-proof in stego_containers
    and lsb_scan rejects (it is never claimed PLAIN) -- and otherwise is None. Needs Pillow with its
    WebP codec; None when either is missing, the image does not decode, or it is too large. Only the
    first frame of an animation (Pillow opens there)."""
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return None
    im = _pillow(data)
    if im is None:
        return None
    if im.width * im.height > MAX_PIXELS:
        return None
    if im.mode not in ("L", "LA", "RGB", "RGBA"):
        im = im.convert("RGBA" if "A" in im.mode else "RGB")
    body = im.tobytes()
    if len(body) != im.width * im.height * len(im.getbands()):
        return None
    return {"width": im.width, "height": im.height, "mode": im.mode, "channels": len(im.getbands()),
            "depth": 8, "data": body, "palette": None, "by": "pillow"}


# ---- LSB planes -------------------------------------------------------------------------------------

_BIT = [bytes(48 + ((v >> b) & 1) for v in range(256)) for b in range(8)]
_REV = bytes(int(f"{v:08b}"[::-1], 2) for v in range(256))


def _bits_to_bytes(bits: bytes, msb_first: bool = True) -> bytes:
    n = len(bits) // 8 * 8
    if not n:
        return b""
    out = int(bits[:n], 2).to_bytes(n // 8, "big")
    return out if msb_first else out.translate(_REV)


def _pixel_order(width: int, height: int, order: str = "xy"):
    """Yield row-major pixel indices in a named deterministic traversal.

    ``column`` is the explicit spelling of the historical ``yx`` order.  Snake forms reverse every
    other row/column, matching the common image-editor and challenge embedders.  The generator has
    no allocation proportional to the image.
    """
    if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
        raise ValueError("invalid or over-cap pixel dimensions")
    order = {"row": "xy", "column": "yx", "col": "yx", "serpentine": "snake",
             "column-serpentine": "column_snake"}.get(order, order)
    if order == "xy":
        yield from range(width * height)
    elif order == "yx":
        for x in range(width):
            for y in range(height):
                yield y * width + x
    elif order == "snake":
        for y in range(height):
            xs = range(width) if y % 2 == 0 else range(width - 1, -1, -1)
            for x in xs:
                yield y * width + x
    elif order == "column_snake":
        for x in range(width):
            ys = range(height) if x % 2 == 0 else range(height - 1, -1, -1)
            for y in ys:
                yield y * width + x
    else:
        raise ValueError("order must be xy, yx/column, snake, or column_snake")


_ORDER_ALIASES = {"row": "xy", "column": "yx", "col": "yx", "serpentine": "snake",
                  "column-serpentine": "column_snake"}
_BIT01 = [bytes((v >> b) & 1 for v in range(256)) for b in range(8)]   # a sample -> its bit k as 0/1
_ASCII01 = bytes([48, 49]) + bytes(254)                              # 0/1 -> '0'/'1'
_ASCII10 = bytes([49, 48]) + bytes(254)                              # 0/1 -> '1'/'0' (inverted)


def _xor01(a: bytes, b: bytes) -> bytes:
    """Element-wise XOR of two equal-length 0/1 byte strings, as one big-integer XOR."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _selected_samples(px: dict, channel_indices: list, order: str, limit: int) -> bytes:
    """At most ``limit`` selected channel samples in traversal order: pixel by pixel in ``order``
    (see :func:`_pixel_order`), each pixel's channels in the order of ``channel_indices``.

    Built from whole-row and whole-column slices of each channel plane rather than pixel by pixel
    (R-15: the per-pixel loop cost lsb_deep_scan 2-3 s CPU on a 500x500 picture, and solve_set's
    one-second budget ran out before the older readings were done)."""
    c, w, h, data = px["channels"], px["width"], px["height"], px["data"]
    if len(data) < w * h * c or limit < 0:
        raise ValueError("truncated pixel sample array")
    if w <= 0 or h <= 0 or w * h > MAX_PIXELS:
        raise ValueError("invalid or over-cap pixel dimensions")
    order = _ORDER_ALIASES.get(order, order)
    if order not in ("xy", "yx", "snake", "column_snake"):
        raise ValueError("order must be xy, yx/column, snake, or column_snake")
    n = len(channel_indices)
    if not n or not limit:
        return b""
    per = -(-limit // n)                    # samples needed from each channel plane
    planes = []
    for i in channel_indices:
        p = data[i::c][:w * h]
        if order == "xy":
            planes.append(p[:per])
        elif order == "snake":
            rows = min(h, -(-per // w))
            planes.append(b"".join(p[y * w:(y + 1) * w][::-1 if y % 2 else 1] for y in range(rows)))
        else:
            cols = min(w, -(-per // h))
            planes.append(b"".join(p[x::w][::-1 if order == "column_snake" and x % 2 else 1] for x in range(cols)))
    if n == 1:
        return bytes(planes[0][:limit])
    m = min(len(p) for p in planes)
    out = bytearray(m * n)
    for k, p in enumerate(planes):
        out[k::n] = p[:m]
    return bytes(out[:limit])


def lsb_extract(px: dict, channels: str = None, bit: int = 0, order: str = "xy", msb_first: bool = True,
                max_bytes: int = LSB_BYTES) -> bytes:
    """The bytes hidden in one bit of the chosen channels. channels: letters of px['mode'] in the
    order they are read ('RGB', 'BGR', 'R', 'A', ...; default: every channel but alpha). Orders:
    ``xy`` row-major, ``yx``/``column`` column-major, ``snake`` alternating rows, and
    ``column_snake`` alternating columns. msb_first: the first bit read is a byte's highest."""
    mode, c, w, h, data = px["mode"], px["channels"], px["width"], px["height"], px["data"]
    if not isinstance(max_bytes, int) or max_bytes < 0 or max_bytes > LSB_BYTES:
        raise ValueError(f"max_bytes must be 0..{LSB_BYTES}")
    channels = channels or mode.replace("A", "") or mode
    try:
        idx = [mode.index(ch) for ch in channels]
    except ValueError as exc:
        raise ValueError("a selected channel is absent from the pixel mode") from exc
    if not idx:
        return b""
    need = max_bytes * 8
    normalized_order = {"column": "yx", "col": "yx", "row": "xy", "serpentine": "snake",
                        "column-serpentine": "column_snake"}.get(order, order)
    if normalized_order == "xy":
        if idx == list(range(c)):
            sel = data[:need]
        else:
            per = need // len(idx) + 1
            sel = bytearray(min(per, w * h) * len(idx))
            for k, i in enumerate(idx):
                sel[k::len(idx)] = data[i::c][:min(per, w * h)]
            sel = bytes(sel)
    elif normalized_order == "yx":
        planes = []
        for i in idx:
            p = data[i::c]
            cols = max(1, min(w, need // max(1, h * len(idx)) + 1))
            planes.append(b"".join(p[x::w] for x in range(cols)))
        if len(planes) == 1:
            sel = planes[0]
        else:
            sel = bytearray(len(planes[0]) * len(planes))
            for k, p in enumerate(planes):
                sel[k::len(planes)] = p
            sel = bytes(sel)
    elif normalized_order in ("snake", "column_snake"):
        per_sample = 1 if isinstance(bit, int) else len(bit)
        sel = _selected_samples(px, idx, normalized_order, (need + per_sample - 1) // per_sample)
    else:
        raise ValueError("order must be xy, yx/column, snake, or column_snake")
    if isinstance(bit, int):
        return _bits_to_bytes(sel[:need].translate(_BIT[bit]), msb_first)
    # several bits a sample, in the order given ((1, 0): bit 1 then bit 0 of each sample)
    s = sel[:need // len(bit) + 1]
    out = bytearray(len(s) * len(bit))
    for k, b in enumerate(bit):
        out[k::len(bit)] = s.translate(_BIT[b])
    return _bits_to_bytes(bytes(out[:need]), msb_first)


def pixel_permutation(count: int, *, passphrase: str | bytes = None, seed: int = None) -> array:
    """A deterministic Fisher-Yates pixel permutation for an explicit key.

    Exactly one of ``passphrase`` or ``seed`` is required.  No key guessing occurs.  Passphrases are
    reduced with SHA-256 so the permutation is reproducible across Python processes.  ``array('I')``
    keeps allocation at four bytes per pixel and the hard cap bounds it to eight MiB.
    """
    if not isinstance(count, int) or not 1 <= count <= MAX_PERMUTED_PIXELS:
        raise ValueError(f"pixel count must be 1..{MAX_PERMUTED_PIXELS}")
    if (passphrase is None) == (seed is None):
        raise ValueError("give exactly one passphrase or integer seed")
    if passphrase is not None:
        if isinstance(passphrase, str):
            key = passphrase.encode("utf-8")
        elif isinstance(passphrase, bytes):
            key = passphrase
        else:
            raise ValueError("passphrase must be text or bytes")
        if not key or len(key) > 4096:
            raise ValueError("passphrase must contain 1..4096 bytes")
        seed_value = int.from_bytes(hashlib.sha256(b"carve-stego-pixel-order\x00" + key).digest(), "big")
    else:
        if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed < (1 << 256):
            raise ValueError("seed must be a non-negative integer below 2^256")
        seed_value = seed
    order = array("I", range(count))
    rng = random.Random(seed_value)
    for i in range(count - 1, 0, -1):
        j = rng.randrange(i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def permuted_lsb_extract(px: dict, channels: str = None, bit: int = 0, *, passphrase: str | bytes = None,
                         seed: int = None, msb_first: bool = True, max_bytes: int = LSB_BYTES) -> bytes:
    """Read a bit plane after a caller-supplied passphrase/seed pixel shuffle."""
    mode, c, w, h, data = px["mode"], px["channels"], px["width"], px["height"], px["data"]
    if w * h > MAX_PERMUTED_PIXELS or len(data) < w * h * c:
        raise ValueError("keyed carrier is truncated or above the permutation cap")
    if not isinstance(bit, int) or not 0 <= bit <= 7:
        raise ValueError("bit must be 0..7")
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= LSB_BYTES:
        raise ValueError(f"max_bytes must be 0..{LSB_BYTES}")
    channels = channels or mode.replace("A", "") or mode
    try:
        selected = [mode.index(ch) for ch in channels]
    except ValueError as exc:
        raise ValueError("a selected channel is absent from the pixel mode") from exc
    needed = max_bytes * 8
    bits = bytearray()
    for pixel in pixel_permutation(w * h, passphrase=passphrase, seed=seed):
        base = pixel * c
        for channel in selected:
            bits.append(48 + ((data[base + channel] >> bit) & 1))
            if len(bits) >= needed:
                return _bits_to_bytes(bytes(bits), msb_first)
    return _bits_to_bytes(bytes(bits), msb_first)


def cross_plane_xor_extract(px: dict, channel: str, planes=(0, 1), *, order: str = "xy",
                            msb_first: bool = True, max_bytes: int = LSB_BYTES) -> bytes:
    """XOR two or more bit planes of one channel into a hidden bit stream."""
    if not isinstance(planes, (tuple, list)) or not 2 <= len(planes) <= 8 \
            or len(set(planes)) != len(planes) or any(not isinstance(b, int) or not 0 <= b <= 7 for b in planes):
        raise ValueError("planes must be 2..8 distinct bit indices in 0..7")
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= LSB_BYTES:
        raise ValueError(f"max_bytes must be 0..{LSB_BYTES}")
    mode = px["mode"]
    if len(channel) != 1 or channel not in mode:
        raise ValueError("channel is absent from the pixel mode")
    samples = _selected_samples(px, [mode.index(channel)], order, max_bytes * 8)
    table = bytes(48 + (sum((v >> plane) & 1 for plane in planes) & 1) for v in range(256))
    return _bits_to_bytes(samples.translate(table), msb_first)


def channel_arithmetic_extract(px: dict, left: str, right: str, operation: str = "xor", *, bit: int = 0,
                               order: str = "xy", msb_first: bool = True,
                               max_bytes: int = LSB_BYTES) -> bytes:
    """Read a bit plane after a StegSolve-style two-channel arithmetic operation.

    Operations are ``xor``, modulo-256 ``add``/``sub``, and absolute difference ``absdiff``.
    """
    mode = px["mode"]
    if left not in mode or right not in mode or len(left) != 1 or len(right) != 1 or left == right:
        raise ValueError("left/right must name two distinct present channels")
    if operation not in {"xor", "add", "sub", "absdiff"}:
        raise ValueError("operation must be xor, add, sub, or absdiff")
    if not isinstance(bit, int) or not 0 <= bit <= 7 or not 0 <= max_bytes <= LSB_BYTES:
        raise ValueError("invalid bit or max_bytes")
    li, ri, needed = mode.index(left), mode.index(right), max_bytes * 8
    pairs = _selected_samples(px, [li, ri], order, needed * 2)
    a, b = pairs[0::2], pairs[1::2]
    if operation == "xor" or bit == 0:
        # bit k of a^b is bit k of a xor bit k of b; and at bit 0 a+b, a-b and |a-b| all have the
        # parity of a^b, so the four operations are one reading there (one big-integer XOR)
        return _bits_to_bytes(_xor01(a.translate(_BIT01[bit]), b.translate(_BIT01[bit])).translate(_ASCII01), msb_first)
    op = {"add": lambda x, y: (x + y) & 255, "sub": lambda x, y: (x - y) & 255, "absdiff": lambda x, y: abs(x - y)}[operation]
    return _bits_to_bytes(bytes(48 + ((op(x, y) >> bit) & 1) for x, y in zip(a, b)), msb_first)


def adjacent_pixel_parity_extract(px: dict, channel: str, *, order: str = "xy", overlap: bool = False,
                                  invert: bool = False, msb_first: bool = True,
                                  max_bytes: int = LSB_BYTES) -> bytes:
    """Read pair-parity bits from adjacent pixels of one channel.

    Each bit is parity of the pair sum (equivalently the XOR of their low bits).  Non-overlapping
    pairs are the default; ``overlap=True`` uses (p0,p1), (p1,p2), ... .
    """
    mode = px["mode"]
    if len(channel) != 1 or channel not in mode or not 0 <= max_bytes <= LSB_BYTES:
        raise ValueError("invalid channel or max_bytes")
    samples = _selected_samples(px, [mode.index(channel)], order,
                                min(px["width"] * px["height"], max_bytes * 16 + 1))
    step = 1 if overlap else 2
    first = samples[0:max(0, len(samples) - 1):step][:max_bytes * 8]
    second = samples[1::step][:len(first)]
    hidden = _xor01(first.translate(_BIT01[0]), second.translate(_BIT01[0]))
    return _bits_to_bytes(hidden.translate(_ASCII10 if invert else _ASCII01), msb_first)


_INNER_TEXT = re.compile(rb"[\x20-\x7e]{20,}")


def _inner_text(blob: bytes, window: int = 2048):
    """(offset, text) of a sentence that starts inside the first `window` bytes of a reading but not
    at its start: 20 printable characters or more, at least two spaces (or a name{...} form), four
    in five of them letters, digits or spaces, and no character making up a third of it. None for
    anything else: over 2 KiB of a noise plane a run like that comes up about once in 10^7 readings."""
    for m in _INNER_TEXT.finditer(blob[:window + 256]):
        t = m.group()
        if m.start() == 0 or m.start() >= window:
            continue
        plainish = sum(1 for c in t if chr(c).isalnum() or c == 32)
        if plainish * 5 < len(t) * 4 or max(t.count(c) for c in set(t)) * 3 > len(t):
            continue
        if t.count(b" ") >= 2 or flagfmt.BYTES.search(t):
            return m.start(), t.decode("ascii").strip()
    return None


def _lead_text(blob: bytes):
    n = 0
    while n < len(blob) and n < 4096 and (32 <= blob[n] < 127 or blob[n] in (9, 10, 13)):
        n += 1
    if not (n >= 12 or (n >= 8 and n < len(blob) and blob[n] == 0)):
        return None
    head = blob[:n]
    # a flat or dithered area reads as one or two characters over and over: that is no message
    if len(set(head)) < (6 if n >= 16 else 5) or max(head.count(c) for c in set(head)) > 0.4 * n:
        return None
    return head.decode("ascii")


def _tar_size(body: bytes):
    """The length of a POSIX tar archive at the start of body (its members' headers walked, each
    header checksum right, up to the two zero blocks or the last member), or None."""
    if len(body) < 512 or body[257:262] != b"ustar":
        return None
    i = 0
    while i + 512 <= len(body):
        hdr = body[i:i + 512]
        if not hdr.strip(b"\x00"):
            return i + 512 if i else None
        try:
            stored = int(hdr[148:156].split(b"\x00")[0].strip() or b"-1", 8)
            size = int(hdr[124:136].split(b"\x00")[0].strip() or b"0", 8)
        except ValueError:
            return None
        if stored != sum(hdr[:148]) + 8 * 32 + sum(hdr[156:]):
            return None
        i += 512 + (size + 511) // 512 * 512
    return min(i, len(body)) if i else None


def _prefixed_file(body: bytes):
    """(kind, bytes) when body starts with a file this toolkit proves by its structure (the sizers,
    a zip by its EOCD, a tar by its header checksums), else None."""
    for magic, kind, sizer in _SIZERS:
        if body.startswith(magic):
            e = sizer(body, 0)
            if e:
                return kind, body[:e]
    if body[:4] == b"PK\x03\x04":
        z = [x for x in zips(body) if x["offset"] == 0]
        if z:
            return "zip", z[0]["data"]
    e = _tar_size(body)
    if e:
        return "tar", body[:e]
    return None


def judge_blob(blob: bytes):
    """What a blob read from a hidden channel is, when it is something: ('file', kind, bytes) for a
    file proven by its structure, at the start or within the n bytes after a 4-byte big- or
    little-endian length n (B-030: length + gzip, zip, tar, png, ...), ('text', None, text) for a NUL-ended or
    long printable start or a length-prefixed text; None for noise."""
    got = _prefixed_file(blob)
    if got:
        return "file", got[0], got[1]
    for fmt in (">I", "<I"):
        if len(blob) >= 16:
            n = struct.unpack_from(fmt, blob, 0)[0]
            if 12 <= n <= len(blob) - 4:
                got = _prefixed_file(blob[4:4 + n])
                if got:
                    return "file", got[0], got[1]
    for fmt in (">I", "<I"):
        if len(blob) >= 8:
            n = struct.unpack_from(fmt, blob, 0)[0]
            if 4 <= n <= len(blob) - 4 and all(32 <= b < 127 or b in (9, 10, 13) for b in blob[4:4 + n]) \
                    and len(set(blob[4:4 + n])) >= 3:
                return "text", None, blob[4:4 + n].decode("ascii")
    t = _lead_text(blob)
    if t:
        return "text", None, t
    return None


def lsb_deep_scan(px: dict, *, passphrases=(), seeds=(), deadline=None, skipped: list = None,
                  seen: set = None, include_unkeyed: bool = True) -> list:
    """Auto-judged nonstandard spatial readings.

    This complements :func:`lsb_scan` with snake traversals, cross-plane XOR, inter-channel
    arithmetic, adjacent-pixel parity, and explicitly keyed pixel permutations.  A reading is
    returned only when :func:`judge_blob` proves a complete file/structured text, or the same strict
    internal-text rule used by ``lsb_scan`` fires.  No passphrase generation or wordlist is present.
    """
    if not isinstance(px, dict) or px.get("width", 0) * px.get("height", 0) > MAX_PIXELS:
        return []
    passphrases, seeds = tuple(passphrases or ()), tuple(seeds or ())
    if len(passphrases) > 16 or len(seeds) > 16:
        raise ValueError("at most 16 explicitly supplied passphrases/seeds are accepted")
    out, seen = [], seen if seen is not None else set()
    mode = px.get("mode", "")
    color = mode.replace("A", "") or mode
    channel_sets = [color]
    if len(color) == 3:
        channel_sets += [color[::-1], *color]
    if "A" in mode:
        channel_sets += [mode, "A"]
    channel_sets = list(dict.fromkeys(channel_sets))

    def late(label="deep lsb"):
        if deadline is not None and time.monotonic() > deadline:
            if skipped is not None and f"{label}: out of time" not in skipped:
                skipped.append(f"{label}: out of time")
            return True
        return False

    def keep(method, blob):
        got, suffix = judge_blob(blob), ""
        if not got:
            inner = _inner_text(blob)
            if not inner:
                return
            got, suffix = ("text", None, inner[1]), f" from byte {inner[0]}"
        what, kind, payload = got
        key = payload
        if key in seen:
            return
        seen.add(key)
        out.append({"method": method + suffix, "what": what, "kind": kind,
                    "text": payload if what == "text" else None,
                    "data": payload if what == "file" else payload.encode()})

    if include_unkeyed:
        for order in ("snake", "column_snake"):
            for channels in channel_sets:
                for msb in (True, False):
                    if late():
                        return out
                    keep(f"bit0 {channels} {order} {'msb' if msb else 'lsb'}-first",
                         lsb_extract(px, channels, 0, order, msb))
        # Cross-plane XOR is meaningful channel by channel; test the low three plane pairs rather
        # than sweeping all 28 pairs (which would be a noisy, expensive search).
        for channel in dict.fromkeys(color):
            for planes in ((0, 1), (0, 2), (1, 2)):
                for msb in (True, False):
                    if late():
                        return out
                    keep(f"planes {planes[0]} xor {planes[1]} of {channel} xy "
                         f"{'msb' if msb else 'lsb'}-first",
                         cross_plane_xor_extract(px, channel, planes, msb_first=msb))
        if len(color) >= 2:
            pairs = [(color[i], color[j]) for i in range(len(color)) for j in range(i + 1, len(color))]
            for left, right in pairs:
                for operation in ("xor", "add", "sub", "absdiff"):
                    for msb in (True, False):
                        if late():
                            return out
                        keep(f"{left} {operation} {right} bit0 xy {'msb' if msb else 'lsb'}-first",
                             channel_arithmetic_extract(px, left, right, operation, msb_first=msb))
        for channel in dict.fromkeys(color):
            for order in ("xy", "snake"):
                for overlap in (False, True):
                    for msb in (True, False):
                        if late():
                            return out
                        keep(f"adjacent parity {channel} {order} {'overlap' if overlap else 'pairs'} "
                             f"{'msb' if msb else 'lsb'}-first",
                             adjacent_pixel_parity_extract(px, channel, order=order, overlap=overlap,
                                                           msb_first=msb))

    if passphrases or seeds:
        if px.get("width", 0) * px.get("height", 0) > MAX_PERMUTED_PIXELS:
            if skipped is not None:
                skipped.append("keyed lsb: image exceeds the permutation pixel cap")
            return out
        for channels in channel_sets:
            for passphrase in passphrases:
                for msb in (True, False):
                    if late("keyed lsb"):
                        return out
                    keep(f"bit0 {channels} sha256-passphrase permutation "
                         f"{'msb' if msb else 'lsb'}-first",
                         permuted_lsb_extract(px, channels, passphrase=passphrase, msb_first=msb))
            for seed in seeds:
                for msb in (True, False):
                    if late("keyed lsb"):
                        return out
                    keep(f"bit0 {channels} integer-seed {seed} permutation "
                         f"{'msb' if msb else 'lsb'}-first",
                         permuted_lsb_extract(px, channels, seed=seed, msb_first=msb))
    return out


def lsb_scan(px: dict, bits=(0, 1), deadline=None, skipped: list = None) -> list:
    """Every LSB reading of the usual orders that parses: [{method, what ('file'|'text'), kind,
    text, data}], one entry per distinct payload (the first method that gives it)."""
    mode = px["mode"]
    color = mode.replace("A", "")
    sets = [color]
    if len(color) == 3:
        sets += [color[::-1], color[0], color[1], color[2]]
    if "A" in mode:
        sets += [mode, "A"]
    out, seen = [], set()
    for bit in bits:
        for order in ("xy", "yx"):
            for chans in sets:
                if deadline and time.monotonic() > deadline:
                    if skipped is not None:
                        skipped.append("lsb: out of time")
                    return out
                for msb in (True, False):
                    blob = lsb_extract(px, chans, bit, order, msb)
                    got, at = judge_blob(blob), ""
                    if not got:
                        inner = _inner_text(blob)
                        if not inner:
                            continue
                        got, at = ("text", None, inner[1]), f" from byte {inner[0]}"
                    what, kind, payload = got
                    if payload in seen:
                        continue
                    seen.add(payload)
                    out.append({"method": f"bit{bit} {chans} {order} {'msb' if msb else 'lsb'}-first{at}", "what": what,
                                "kind": kind, "text": payload if what == "text" else None,
                                "data": payload if what == "file" else payload.encode()})
    # two bits a sample (zsteg's b2): the two lowest bits of each sample, either one first, rows only
    for pair in ((1, 0), (0, 1)):
        for chans in sets:
            if deadline and time.monotonic() > deadline:
                if skipped is not None:
                    skipped.append("lsb: out of time")
                return out
            for msb in (True, False):
                blob = lsb_extract(px, chans, pair, "xy", msb)
                got, at = judge_blob(blob), ""
                if not got:
                    inner = _inner_text(blob)
                    if not inner:
                        continue
                    got, at = ("text", None, inner[1]), f" from byte {inner[0]}"
                what, kind, payload = got
                if payload in seen:
                    continue
                seen.add(payload)
                out.append({"method": f"bits{pair[0]}{pair[1]} {chans} xy {'msb' if msb else 'lsb'}-first{at}", "what": what,
                            "kind": kind, "text": payload if what == "text" else None,
                            "data": payload if what == "file" else payload.encode()})
    raw = px.get("raw")
    if raw:
        # a BMP's pixel array as it is stored. A hex editor writes over it byte by byte, and a tool that hides
        # bits in "the bytes after the header" uses the row padding too: neither is a reading of the samples.
        tries = [("the pixel bytes as stored", raw)]
        if px.get("stride") and px["stride"] != px["width"] * px["channels"]:
            flat = {"mode": "P", "channels": 1, "width": px["stride"], "height": px["height"], "data": raw}
            tries += [(f"bit{bit} stored bytes with row padding {'msb' if msb else 'lsb'}-first", lsb_extract(flat, "P", bit, "xy", msb))
                      for bit in bits for msb in (True, False)]
        for method, blob in tries:
            got = judge_blob(blob)
            if not got or got[2] in seen or any(isinstance(s, str) and isinstance(got[2], str) and s.startswith(got[2]) for s in seen):
                continue
            what, kind, payload = got
            # the padded reading goes on where the sample reading stopped at a row's end: it replaces that piece
            out[:] = [o for o in out if not (o["what"] == "text" and what == "text" and payload.startswith(o["text"]))]
            seen.add(payload)
            out.append({"method": method, "what": what, "kind": kind, "text": payload if what == "text" else None,
                        "data": payload if what == "file" else payload.encode()})
    if not out and not px.get("raw"):
        # Day-26: channel orders and scan directions the sweep above omits, judged by validate_container only
        # (a stored length+CRC or a checksum-verified file); runs only when nothing parsed, so it moves no answer
        try:
            import f5_stego
            for payload, methods in f5_stego.lsb_extra_px(px, deadline).items():
                is_text = all(32 <= b < 127 or b in (9, 10, 13) for b in payload)
                out.append({"method": methods[0], "what": "text" if is_text else "file", "kind": None if is_text else sniff(payload),
                            "text": payload.decode("ascii") if is_text else None, "data": payload})
        except Exception:
            pass
    return out


# Flag-form `name{...}`, the toolkit's own standard (see _inner_text): a word, a brace, four or more
# printable ASCII characters that are no brace or whitespace, a brace. ASCII only, so .decode never raises.
_PLANE_FLAG = flagfmt.BYTES
HIGH_PLANES = (2, 3, 4, 5, 6, 7)                    # bits above lsb_scan's (0, 1); 7 is the MSB


def _plane_flag(blob: bytes):
    """A `name{...}` flag form that is BYTE-PROVEN to be a stored payload, not a chance match in the
    cover's own high-plane bytes: it begins in the first 64 bytes of the reading (where a payload
    embedded from the top of the plane lands) and is anchored to the start of the stream or to a NUL
    delimiter. Over 500 random covers this fired 0 times, where an un-anchored search fired on 1."""
    for m in _PLANE_FLAG.finditer(blob[:128]):
        if m.start() <= 64 and (m.start() == 0 or blob[m.start() - 1] == 0):
            return m.group().decode("ascii")
    return None


def _plane_judge(blob: bytes):
    """What a higher bit plane carries, only when the bytes prove it: a file (its magic and a sizer
    that validates its length), a length-prefixed printable text of twelve bytes or more, a
    NUL-terminated printable run, or a start-anchored `name{...}` flag form. None otherwise.

    A high bit plane holds the cover image's own structure, not the near-random data of the low planes,
    so judge_blob's loose lead-text rule (a bare printable run) is NOT used here: on a gradient or a
    smooth region such a run is not proof of a hidden message. Only a self-delimiting or start-anchored
    payload counts, which is the never-wrong choice: when in doubt, None."""
    for magic, kind, sizer in _SIZERS:
        if blob.startswith(magic):
            e = sizer(blob, 0)
            if e:
                return "file", kind, blob[:e]
    if blob[:4] == b"PK\x03\x04":
        z = [x for x in zips(blob) if x["offset"] == 0]
        if z:
            return "file", "zip", z[0]["data"]
    for fmt in (">I", "<I"):
        if len(blob) >= 16:
            n = struct.unpack_from(fmt, blob, 0)[0]
            if 12 <= n <= len(blob) - 4 and all(32 <= b < 127 or b in (9, 10, 13) for b in blob[4:4 + n]) \
                    and len(set(blob[4:4 + n])) >= 6:
                return "text", None, blob[4:4 + n].decode("ascii")
    run = _lead_text(blob)
    if run and len(run) >= 8 and len(run) < len(blob) and blob[len(run)] == 0:
        return "text", None, run                    # a NUL-terminated printable run (a stored C string)
    flag = _plane_flag(blob)
    if flag:
        return "text", None, flag
    return None


def plane_scan(px: dict, planes=HIGH_PLANES, deadline=None, skipped: list = None, seen: set = None) -> list:
    """The higher bit planes read the way lsb_scan reads bits 0 and 1: for each bit, the usual channel
    sets (each colour channel, every channel but alpha, the alpha), both the row and the column order,
    and both bit orders. A reading is kept only when _plane_judge proves it (a file, a length prefix, a
    flag form or a NUL-terminated run), so a plane that only shows the cover image yields nothing. One
    entry per distinct byte-proven payload; `seen` carries the payloads lsb_scan already reported."""
    mode = px["mode"]
    color = mode.replace("A", "")
    sets = [color]
    if len(color) == 3:
        sets += [color[::-1], color[0], color[1], color[2]]
    if "A" in mode:
        sets += [mode, "A"]
    out, seen = [], seen if seen is not None else set()
    for bit in planes:
        for order in ("xy", "yx"):
            for chans in sets:
                if deadline and time.monotonic() > deadline:
                    if skipped is not None:
                        skipped.append("planes: out of time")
                    return out
                for msb in (True, False):
                    got = _plane_judge(lsb_extract(px, chans, bit, order, msb))
                    if not got:
                        continue
                    what, kind, payload = got
                    if payload in seen:
                        continue
                    seen.add(payload)
                    out.append({"method": f"bit{bit} {chans} {order} {'msb' if msb else 'lsb'}-first", "what": what,
                                "kind": kind, "text": payload if what == "text" else None,
                                "data": payload if what == "file" else payload.encode()})
    return out


# ---- JPEG, GIF --------------------------------------------------------------------------------------

_JPEG_NAMES = {0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT", 0xDD: "DRI", 0xFE: "COM", 0xC0: "SOF0",
               0xC1: "SOF1", 0xC2: "SOF2"}


def jpeg_segments(data: bytes) -> list:
    """[{marker, name, offset, length, ident, text}] up to EOI. COM segments carry `text`; APPn
    segments their identifier (JFIF, Exif, ICC_PROFILE, http://ns.adobe.com/xap/1.0/, ...)."""
    if data[:2] != b"\xff\xd8":
        return []
    out, i, n = [{"marker": 0xD8, "name": "SOI", "offset": 0, "length": 0}], 2, len(data)
    while i + 2 <= n and len(out) < 10000:
        if data[i] != 0xFF:
            break
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            out.append({"marker": m, "name": "EOI", "offset": i, "length": 0})
            break
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        if i + 4 > n:
            break
        ln = struct.unpack_from(">H", data, i + 2)[0]
        body = data[i + 4:i + 2 + ln]
        seg = {"marker": m, "name": _JPEG_NAMES.get(m, f"APP{m - 0xE0}" if 0xE0 <= m <= 0xEF else f"0x{m:02X}"),
               "offset": i, "length": ln}
        if m == 0xFE:
            seg["text"] = body.decode("utf-8", "replace").rstrip("\x00")
            seg["data"] = body
        elif 0xE0 <= m <= 0xEF:
            seg["ident"] = body.split(b"\x00")[0][:40].decode("latin-1")
        elif 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC) and len(body) >= 5:
            seg["height"], seg["width"] = struct.unpack_from(">HH", body, 1)
        out.append(seg)
        i += 2 + ln
        if m == 0xDA:
            while True:
                j = data.find(b"\xff", i)
                if j < 0 or j + 1 >= n:
                    return out
                nxt = data[j + 1]
                if nxt == 0 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    i = j + 1 if nxt == 0xFF else j + 2
                    continue
                i = j
                break
    return out


def gif_blocks(data: bytes) -> dict:
    """{"frames": n, "comments": [text], "apps": [identifier]} of a GIF."""
    out = {"frames": 0, "comments": [], "apps": []}
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        return out
    try:
        flags = data[10]
        i = 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
        while i < len(data):
            b = data[i]
            if b == 0x3B:
                break
            label = None
            if b == 0x21:
                label = data[i + 1]
                i += 2
            elif b == 0x2C:
                lf = data[i + 9]
                i += 10 + (3 * (2 << (lf & 7)) if lf & 0x80 else 0) + 1
                out["frames"] += 1
            else:
                break
            parts = []
            while True:
                ln = data[i]
                parts.append(data[i + 1:i + 1 + ln])
                i += 1 + ln
                if ln == 0:
                    break
            if label == 0xFE:
                out["comments"].append(b"".join(parts).decode("utf-8", "replace"))
            elif label == 0xFF and parts:
                out["apps"].append(parts[0].decode("latin-1"))
    except IndexError:
        pass
    return out


# ---- WAV: chunks, sample LSBs, DTMF -----------------------------------------------------------------

WAV_STANDARD = {"fmt ", "data", "fact", "LIST", "cue ", "smpl", "bext", "PEAK", "JUNK", "junk", "id3 ", "ID3 ", "FLLR", "chan",
                "iXML", "PAD ", "afsp", "acid", "inst", "strc", "cart", "DISP", "plst", "ltxt", "labl", "note", "JUNQ", "ds64",
                "_PMX", "axml", "levl", "LGWV", "minf", "elm1", "regn", "umid", "wavl", "slnt"}


def wav_info(data: bytes):
    """{chunks: [{id, offset, size}], format, channels, rate, bits, data_offset, data_size, info:
    {LIST/INFO key: text}} of a RIFF/WAVE file; None when it is not one."""
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    out = {"chunks": [], "format": None, "channels": None, "rate": None, "bits": None, "data_offset": None,
           "data_size": 0, "info": {}}
    i = 12
    while i + 8 <= len(data) and len(out["chunks"]) < 1000:
        cid, size = data[i:i + 4], struct.unpack_from("<I", data, i + 4)[0]
        body = data[i + 8:i + 8 + size]
        out["chunks"].append({"id": cid.decode("latin-1"), "offset": i, "size": size})
        if cid == b"fmt " and len(body) >= 16:
            out["format"], out["channels"], out["rate"], _, _, out["bits"] = struct.unpack_from("<HHIIHH", body, 0)
        elif cid == b"data" and out["data_offset"] is None:
            out["data_offset"], out["data_size"] = i + 8, len(body)
        elif cid == b"LIST" and body[:4] == b"INFO":
            j = 4
            while j + 8 <= len(body):
                k, n = body[j:j + 4], struct.unpack_from("<I", body, j + 4)[0]
                out["info"][k.decode("latin-1")] = body[j + 8:j + 8 + n].split(b"\x00")[0].decode("utf-8", "replace")
                j += 8 + n + (n & 1)
        i += 8 + size + (size & 1)
    return out


def wav_samples(data: bytes, info: dict = None):
    """(rate, [mono samples as floats in -1..1]) of a PCM WAV (8, 16, 24 or 32 bit), or None."""
    info = info or wav_info(data)
    if not info or info["data_offset"] is None or info["format"] not in (1, 0xFFFE) or info["bits"] not in (8, 16, 24, 32):
        return None
    width, ch = info["bits"] // 8, info["channels"] or 1
    raw = data[info["data_offset"]:info["data_offset"] + info["data_size"]]
    n = len(raw) // (width * ch)
    if width == 1:
        vals = [(b - 128) / 128.0 for b in raw[:n * ch]]
    elif width == 2:
        vals = [v / 32768.0 for v in struct.unpack_from(f"<{n * ch}h", raw, 0)]
    elif width == 4:
        vals = [v / 2147483648.0 for v in struct.unpack_from(f"<{n * ch}i", raw, 0)]
    else:
        vals = [int.from_bytes(raw[k:k + 3], "little", signed=True) / 8388608.0 for k in range(0, n * ch * 3, 3)]
    if ch > 1:
        vals = [sum(vals[k:k + ch]) / ch for k in range(0, n * ch, ch)]
    return info["rate"], vals


def wav_lsb(data: bytes, info: dict = None) -> list:
    """Sample-LSB readings of a PCM WAV that parse (see judge_blob): [{method, what, kind, text, data}]."""
    info = info or wav_info(data)
    if not info or info["data_offset"] is None or not info["bits"] or info["bits"] % 8:
        return []
    width = info["bits"] // 8
    raw = data[info["data_offset"]:info["data_offset"] + min(info["data_size"], LSB_BYTES * 8 * width)]
    low = raw[0::width]
    out, seen = [], set()
    for bit in (0, 1):
        for msb in (True, False):
            got = judge_blob(_bits_to_bytes(low.translate(_BIT[bit]), msb))
            if got and got[2] not in seen:
                seen.add(got[2])
                out.append({"method": f"sample bit{bit} {'msb' if msb else 'lsb'}-first", "what": got[0], "kind": got[1],
                            "text": got[2] if got[0] == "text" else None,
                            "data": got[2] if got[0] == "file" else got[2].encode()})
    return out


_DTMF_LOW, _DTMF_HIGH = (697, 770, 852, 941), (1209, 1336, 1477, 1633)
_DTMF_KEYS = ("123A", "456B", "789C", "*0#D")


def _goertzel(frame, coeff):
    s1 = s2 = 0.0
    for x in frame:
        s1, s2 = x + coeff * s1 - s2, s1
    return s1 * s1 + s2 * s2 - coeff * s1 * s2


def dtmf(data: bytes, max_seconds: float = 120.0, use_numpy: bool = True, shift: float = 0.0, facts: dict = None):
    """The DTMF keys of a PCM WAV, in order, as one string ('' when there are none; None when the
    file is not readable PCM). Goertzel power at the eight DTMF frequencies over 20 ms windows: a
    key is one low and one high tone that together hold most of a window's energy, for two windows
    or more, and keys are separated by a window that is not that key."""
    got = wav_samples(data)
    if not got:
        return None
    rate, x = got
    if not rate or rate < 3400:
        return None
    step = max(1, rate // 8000)
    if step > 1:                                    # plain averaging is filter enough below 1.7 kHz
        x = [sum(x[k:k + step]) / step for k in range(0, len(x) - step + 1, step)]
        rate = rate / step
    if facts is not None:
        facts["cut"] = len(x) > int(max_seconds * rate)
    x = x[:int(max_seconds * rate)]
    n = int(rate * 0.02)
    x = x[int(n * shift):] if shift else x      # the same windows, begun a part of a window later
    if len(x) < n * 2:
        return ""
    freqs = _DTMF_LOW + _DTMF_HIGH
    windows = []
    np = None
    if use_numpy:
        try:
            import numpy as np
        except ImportError:
            np = None
    count = len(x) // n
    if np is not None:
        a = np.asarray(x[:count * n], dtype=np.float64).reshape(count, n)
        t = np.arange(n) / rate
        basis = np.exp(-2j * np.pi * np.outer(t, np.asarray(freqs, dtype=np.float64)))
        power = np.abs(a @ basis) ** 2
        energy = (a * a).sum(axis=1)
        rows = [(float(energy[k]), [float(v) for v in power[k]]) for k in range(count)]
    else:
        coeffs = [2.0 * math.cos(2.0 * math.pi * f / rate) for f in freqs]
        rows = []
        for k in range(count):
            frame = x[k * n:(k + 1) * n]
            energy = sum(v * v for v in frame)
            rows.append((energy, [_goertzel(frame, c) for c in coeffs] if energy > 1e-9 else [0.0] * 8))
    peak = max((e for e, _ in rows), default=0.0)
    for energy, p in rows:
        key = None
        if energy > max(1e-9, peak * 0.02):
            norm = [2.0 * v / (n * energy) for v in p]          # 0.5 each for a clean two-tone window
            lo = max(range(4), key=lambda i: norm[i])
            hi = max(range(4), key=lambda i: norm[4 + i])
            lo2 = max(norm[i] for i in range(4) if i != lo)
            hi2 = max(norm[4 + i] for i in range(4) if i != hi)
            if norm[lo] > 0.15 and norm[4 + hi] > 0.15 and norm[lo] + norm[4 + hi] > 0.6 \
                    and norm[lo] > 4 * lo2 and norm[4 + hi] > 4 * hi2:
                key = _DTMF_KEYS[lo][hi]
        windows.append(key)
    out, run, prev = [], 0, None
    for key in windows + [None]:
        if key == prev:
            run += 1
            continue
        if prev is not None and run >= 2:
            out.append(prev)
        prev, run = key, 1
    return "".join(out)


def dtmf_read(data: bytes, max_seconds: float = 120.0):
    """(keys, sure) of a PCM WAV; (None, False) when it is not readable. `sure` is False when the
    recording is longer than was read, or when the keys change with where the 20 ms windows begin
    (tones or gaps near one window long: a key may be missed, or a repeated key read once)."""
    facts = {}
    keys = dtmf(data, max_seconds, facts=facts)
    if keys is None:
        return None, False
    sure = not facts.get("cut") and all(dtmf(data, max_seconds, shift=s) == keys for s in (0.25, 0.5, 0.75))
    return keys, bool(sure and keys and _bursts(data) == len(keys))


def _bursts(data: bytes):
    """How many separate bursts of sound a PCM WAV holds, by its energy over 5 ms steps: a burst is
    10 ms or more above a tenth of the loud level, ended by a step below it. None when unreadable."""
    got = wav_samples(data)
    if not got or not got[0]:
        return None
    rate, x = got
    n = max(1, int(rate * 0.005))
    try:
        import numpy as np
        a = np.asarray(x[:len(x) // n * n], dtype=np.float64).reshape(-1, n)
        e = [float(v) for v in (a * a).sum(axis=1)]
    except ImportError:
        e = [sum(v * v for v in x[k:k + n]) for k in range(0, len(x) - n + 1, n)]
    if not e:
        return 0
    loud = sorted(e)[int(len(e) * 0.98)] if len(e) >= 50 else max(e)
    loud = max(loud, max(e) * 0.25)
    if loud <= 0:
        return 0
    count = run = 0
    for v in e + [0.0]:
        if v > 0.1 * loud:
            run += 1
        else:
            count += run >= 2
            run = 0
    return count


# ---- text channels: zero-width, tags, variation selectors, trailing whitespace ----------------------

ZERO_WIDTH = {"\u200b": "ZWSP", "\u200c": "ZWNJ", "\u200d": "ZWJ", "\u2060": "WJ", "\ufeff": "BOM", "\u180e": "MVS",
              "\u200e": "LRM", "\u200f": "RLM", "\u2062": "INVT", "\u2063": "INVS", "\u2064": "INVP"}


def _printable(text: str, least: int = 4) -> bool:
    return len(text) >= least and all(c.isprintable() or c in "\r\n\t" for c in text) and len(set(text)) >= 3


def _bin_text(bits: str, width: int = 8):
    n = len(bits) // width * width
    if n < width * 4:
        return None
    try:
        raw = bytes(int(bits[i:i + width], 2) for i in range(0, n, width))
    except ValueError:
        return None
    raw = raw.rstrip(b"\x00")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _printable(text) else None


def zero_width(text: str) -> list:
    """[(method, hidden text)] carried by invisible characters:
      tags                Unicode tag characters U+E0020..U+E007E, each an ASCII character
      variation-selectors VS1..VS256 (U+FE00.., U+E0100..), each a byte
      zw-binary ...       two zero-width characters as 0 and 1 (both ways), 8 bits a character
      zw-separated ...    two as 0 and 1 and a third between characters
    Only readings that are printable text are returned."""
    out = []
    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if _printable(tags):
        out.append(("tags", tags))
    vs = bytes(ord(c) - 0xFE00 if 0xFE00 <= ord(c) <= 0xFE0F else ord(c) - 0xE0100 + 16
               for c in text if 0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF)
    if len(vs) >= 4:
        try:
            t = vs.decode("utf-8")
            if _printable(t):
                out.append(("variation-selectors", t))
        except UnicodeDecodeError:
            pass
    body = text[1:] if text[:1] == "\ufeff" else text       # a leading BOM is not a channel
    zw = [c for c in body if c in ZERO_WIDTH]
    kinds = sorted(set(zw), key=zw.index)
    if len(kinds) == 2:
        for zero, one in ((kinds[0], kinds[1]), (kinds[1], kinds[0])):
            bits = "".join("0" if c == zero else "1" for c in zw)
            for width in (8, 7):
                t = _bin_text(bits, width)
                if t:
                    out.append((f"zw-binary {ZERO_WIDTH[zero]}=0 {ZERO_WIDTH[one]}=1 {width}-bit", t))
                    break
    elif len(kinds) == 3:
        import itertools
        for zero, one, sep in itertools.permutations(kinds):
            groups = "".join("0" if c == zero else "1" if c == one else " " for c in zw).split()
            try:
                t = "".join(chr(int(g, 2)) for g in groups if g)
            except ValueError:
                continue
            if len(groups) >= 4 and all(len(g) <= 21 for g in groups) and _printable(t) and all(ord(c) < 0x3000 for c in t) \
                    and sum(c.isascii() for c in t) >= 0.8 * len(t):
                out.append((f"zw-separated {ZERO_WIDTH[zero]}=0 {ZERO_WIDTH[one]}=1 {ZERO_WIDTH[sep]}=space", t))
    seen, uniq = set(), []
    for m, t in out:
        if t not in seen:
            seen.add(t)
            uniq.append((m, t))
    return uniq


def whitespace_bits(text: str) -> list:
    """[(method, hidden text)] in the spaces and tabs at the ends of lines, read as bits (space and
    tab as 0 and 1, both ways; 8 bits a character, across lines or one character a line)."""
    tails = [re.search(r"[ \t]*$", line.rstrip("\r")).group() for line in text.split("\n")]
    joined = "".join(tails)
    if len(joined) < 32 or " " not in joined or "\t" not in joined:
        return []
    out = []
    for zero, one in ((" ", "\t"), ("\t", " ")):
        t = _bin_text("".join("0" if c == zero else "1" for c in joined))
        if t:
            out.append((f"line-end whitespace {'space' if zero == ' ' else 'tab'}=0", t))
    return out


# ---- QR and barcodes --------------------------------------------------------------------------------

def _zxing():
    try:
        import zxingcpp
        return zxingcpp
    except ImportError:
        return None


def _fmt_name(fmt) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(getattr(fmt, "name", fmt)).lower()).strip("_")


MATRIX_FORMATS = {"qr_code", "qr_code_model_1", "qr_code_model_2", "micro_qr_code", "rmqr_code", "aztec", "aztec_code",
                  "aztec_rune", "data_matrix", "pdf417", "compact_pdf417", "micropdf417", "maxicode", "qrcode"}
_NEVER = {"dxfilmedge", "dx_film_edge"}             # read out of any striped edge


def _read(image, matrix_only: bool = False) -> list:
    """Codes in one image object (a PIL image, or a 2-D memoryview of gray bytes for zxing-cpp).
    matrix_only keeps the two-dimensional symbologies, whose error correction makes a reading out
    of noise all but impossible; a 1D reader finds short 'codes' in any noisy bit plane."""
    zx = _zxing()
    out = []
    if zx is not None:
        try:
            kw = {"formats": zx.BarcodeFormat.AllMatrix} if matrix_only and hasattr(zx.BarcodeFormat, "AllMatrix") else {}
            if hasattr(zx, "TextMode") and hasattr(zx.TextMode, "Plain"):
                # the default (HRI) spells a control character as '<LF>' or '<ESC>' and a GS1 code with
                # brackets: a payload with a line break in it would be answered wrong. Plain is the payload.
                kw["text_mode"] = zx.TextMode.Plain
            for r in zx.read_barcodes(image, **kw):
                name = _fmt_name(r.format)
                if getattr(r, "valid", True) and name not in _NEVER and (not matrix_only or name in MATRIX_FORMATS):
                    out.append({"format": name, "text": r.text, "bytes": bytes(r.bytes)})
        except Exception:
            pass
        return out
    try:
        from pyzbar import pyzbar
        for r in pyzbar.decode(image):
            raw = bytes(r.data)
            name = _fmt_name(r.type)
            if not matrix_only or name in MATRIX_FORMATS:
                out.append({"format": name, "text": raw.decode("utf-8", "replace"), "bytes": raw})
    except Exception:
        pass
    return out


def decode_codes(data: bytes, planes: bool = True, max_frames: int = 32, deadline=None, skipped: list = None) -> list:
    """The codes an image shows: [{format, text, bytes, how}]. Tried in turn, stopping at the first
    reading that finds any: the picture as it is; small pictures enlarged with a white border (a
    code drawn one pixel a module, no quiet zone); every frame of an animation; and, with `planes`,
    bit 0 of each channel drawn black and white (a code hidden in a bit plane). Needs Pillow."""
    im = _pillow(data)
    if im is None:
        return []
    try:
        from PIL import Image, ImageOps
    except ImportError:
        return []
    out, seen = [], set()

    def late():
        """Past the deadline: the readings left (a large picture costs half a second each) are noted, not made."""
        if deadline is not None and time.monotonic() > deadline:
            if skipped is not None:
                skipped.append("codes: out of time")
            return True
        return False

    def add(found, how):
        for r in found:
            if (r["format"], r["bytes"]) not in seen:
                seen.add((r["format"], r["bytes"]))
                out.append({**r, "how": how})

    frames = min(getattr(im, "n_frames", 1) or 1, max_frames)
    for k in range(frames):
        if k and late():
            break
        try:
            if frames > 1:
                im.seek(k)
            frame = im.convert("RGBA" if "A" in im.mode or im.mode == "P" and "transparency" in im.info else "RGB")
        except Exception:
            break
        if frame.width * frame.height > MAX_PIXELS:
            break
        how = f"frame {k}" if frames > 1 else "image"
        flat = frame.convert("RGB") if frame.mode == "RGBA" else frame
        if frame.mode == "RGBA":
            bg = Image.new("RGB", frame.size, (255, 255, 255))
            bg.paste(frame, mask=frame.getchannel("A"))
            flat = bg
        found = _read(flat)
        if not found and max(frame.size) <= 600 and not late():
            scale = max(2, min(10, 900 // max(frame.size)))
            big = ImageOps.expand(flat.convert("L"), border=max(4, min(frame.size) // 8), fill=255)
            big = big.resize((big.width * scale, big.height * scale), Image.NEAREST)
            found = _read(big)
            how += " enlarged"
        add(found, how)
        if not found and planes and k == 0 and im.format in ("PNG", "BMP", "GIF", "TIFF", "WEBP"):
            scale = max(1, min(8, 900 // max(frame.size)))
            border = max(4, min(frame.size) // 8)
            for band in frame.getbands():
                # every bit plane of the channel, 0 (the lsb) through 7 (the msb), each rendered black
                # and white and read as a matrix code; error correction makes a reading out of noise
                # all but impossible, so a code that decodes is self-checking (never-wrong).
                for b in range(8):
                    if late():
                        break
                    plane = frame.getchannel(band).point(lambda v, _b=b: 255 * ((v >> _b) & 1))
                    ex = plane.getextrema()
                    if ex[0] == ex[1]:
                        continue                    # a uniform plane shows nothing
                    big = ImageOps.expand(plane, border=border, fill=255)
                    big = big.resize((big.width * scale, big.height * scale), Image.NEAREST) if scale > 1 else big
                    add(_read(big, matrix_only=True), f"bit{b} of {band}")
                    if not out:
                        add(_read(ImageOps.invert(big), matrix_only=True), f"bit{b} of {band} inverted")
    return out


_SGR = re.compile(r"\x1b\[([0-9;]*)m")
_DARK = set("█#X@*1■▓▉▇")


def _ansi_cells(line: str, state: list):
    """One line's cells as 1 (dark background), 0 (light) or None (default), following the SGR
    background colours; `state` carries the colour over lines."""
    cells, i = [], 0
    for m in list(_SGR.finditer(line)) + [None]:
        end = m.start() if m else len(line)
        cells += [state[0]] * len(line[i:end])
        if m is None:
            break
        i = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c.isdigit()] or [0]
        k = 0
        while k < len(codes):
            c = codes[k]
            if c in (0, 49):
                state[0] = None
            elif c == 7:
                state[0] = 0 if state[0] else 1
            elif c in (40, 100):
                state[0] = 1
            elif 41 <= c <= 47 or 101 <= c <= 107:
                state[0] = 0 if c in (47, 107, 43, 103, 46, 106) else 1
            elif c == 48 and k + 2 < len(codes) and codes[k + 1] == 5:
                n = codes[k + 2]
                state[0] = 0 if n in (7, 15) or n >= 244 or (16 <= n <= 231 and ((n - 16) // 36 + (n - 16) // 6 % 6 + (n - 16) % 6) >= 9) else 1
                k += 2
            elif c == 48 and k + 4 < len(codes) and codes[k + 1] == 2:
                state[0] = 0 if sum(codes[k + 2:k + 5]) >= 384 else 1
                k += 4
            elif c == 38 and k + 1 < len(codes):
                k += 2 if codes[k + 1] == 5 else 4
            k += 1
    return cells


def text_grid(text: str):
    """A code drawn in text, as a matrix of 0/1 rows (1 is dark), or None. Reads ANSI background
    colours, half-block characters (two rows a line), and any drawing of at most two symbols
    (█ and space, ## and two spaces, 0 and 1, # and .), with or without separators. A uniform
    border is cut off and modules drawn several characters wide or high are reduced to one."""
    text = text.replace("\r", "")
    lines = [ln for ln in text.split("\n")]
    rows = []
    bare = set("".join(_SGR.sub("", ln).replace(" ", " ") for ln in lines))
    if "\x1b[" in text and bare & set("▀▄") and bare <= set("▀▄█ "):
        # half blocks under one colour pair a line (qrencode -t ANSIUTF8, as in Huntress 2025 "QRception"): the
        # characters are the drawing; which of the two colours is dark is settled by reading it both ways
        text = _SGR.sub("", text)
        lines = text.split("\n")
    if "\x1b[" in text and re.search(r"\x1b\[[0-9;]*(?:4[0-9]|10[0-7])[;m]", text):
        state = [None]
        for ln in lines:
            cells = _ansi_cells(ln, state)
            if cells:
                rows.append([0 if c is None else c for c in cells])
    else:
        lines = [_SGR.sub("", ln).replace("\u00a0", " ") for ln in lines]
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if not lines:
            return None
        chars = set("".join(lines))
        if chars & set("▀▄") and chars <= set("▀▄█ "):
            for ln in lines:
                rows.append([1 if c in "█▀" else 0 for c in ln])
                rows.append([1 if c in "█▄" else 0 for c in ln])
        else:
            if chars <= set("01 ,;|\t") and {"0", "1"} <= chars:
                lines = [re.sub(r"[ ,;|\t]", "", ln) for ln in lines]
                chars = {"0", "1"}
            if len(chars) > 2 and len(chars - {" "}) == 2:
                # two symbols separated by spaces ("# . # #")
                squeezed = [ln[::2] for ln in lines]
                if all(set(ln[1::2]) <= {" "} for ln in lines):
                    lines, chars = squeezed, set("".join(squeezed))
            if not 1 <= len(chars) <= 2:
                return None
            dark = next((c for c in chars if c in _DARK), None) or next((c for c in chars if c != " "), None)
            if len(chars) == 2 and " " not in chars and dark is None:
                dark = sorted(chars)[-1]
            rows = [[1 if c == dark else 0 for c in ln] for ln in lines]
    if not rows:
        return None
    width = max(len(r) for r in rows)
    rows = [r + [0] * (width - len(r)) for r in rows]
    # cut a uniform border, whatever its value
    while len(rows) > 1 and len(set(rows[0])) == 1:
        rows.pop(0)
    while len(rows) > 1 and len(set(rows[-1])) == 1:
        rows.pop()
    while rows and len(rows[0]) > 1 and len({r[0] for r in rows}) == 1:
        rows = [r[1:] for r in rows]
    while rows and len(rows[0]) > 1 and len({r[-1] for r in rows}) == 1:
        rows = [r[:-1] for r in rows]
    for s in (4, 3, 2):                             # modules drawn s characters wide
        if len(rows[0]) % s == 0 and all(len(set(r[i:i + s])) == 1 for r in rows for i in range(0, len(r), s)):
            rows = [r[::s] for r in rows]
            break
    for s in (4, 3, 2):                             # ... or s lines high
        if len(rows) % s == 0 and all(rows[i + k] == rows[i] for i in range(0, len(rows), s) for k in range(1, s)):
            rows = rows[::s]
            break
    if len(rows) < 8 or len(rows[0]) < 8 or len(rows) > 400 or len(rows[0]) > 400:
        return None
    return rows


def render_grid(rows, scale: int = 6, border: int = 4, invert: bool = False):
    """(width, height, gray bytes) of a matrix drawn `scale` pixels a module inside a light border."""
    w, h = len(rows[0]) + 2 * border, len(rows) + 2 * border
    on, off = (255, 0) if invert else (0, 255)        # inverted: the drawing's 1 is the light colour
    blank = b"\xff" * (w * scale)
    out = [blank] * (border * scale)
    for r in rows:
        line = b"\xff" * (border * scale) + b"".join(bytes([on if v else off]) * scale for v in r) + b"\xff" * (border * scale)
        out += [line] * scale
    out += [blank] * (border * scale)
    return w * scale, h * scale, b"".join(out)


def decode_grid(text: str) -> list:
    """The codes of a text drawing (text_grid), read both dark-on-light and light-on-dark."""
    rows = text_grid(text)
    if rows is None or _zxing() is None:
        return []
    for invert in (False, True):
        w, h, gray = render_grid(rows, invert=invert)
        found = _read(memoryview(gray).cast("B", shape=[h, w]), matrix_only=len(rows) > 4)
        if found:
            return [{**r, "how": "text grid" + (" inverted" if invert else "")} for r in found]
    return []


_IMG_MAGIC = (PNG_SIG, b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM", b"RIFF", b"II*\x00", b"MM\x00*")


def _as_image(payload):
    """Image bytes a payload stands for (itself, a data: URI, base64 or hex of an image), or None."""
    if isinstance(payload, (bytes, bytearray)):
        if bytes(payload[:8]).startswith(_IMG_MAGIC):
            return bytes(payload)
        try:
            payload = bytes(payload).decode("utf-8")
        except UnicodeDecodeError:
            return None
    s = payload.strip()
    m = re.match(r"data:image/[\w.+-]+;base64,(.+)$", s, re.S)
    if m:
        s = m.group(1)
    compact = re.sub(r"\s+", "", s)
    if len(compact) >= 40 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        try:
            raw = base64.b64decode(compact.replace("-", "+").replace("_", "/") + "=" * (-len(compact) % 4))
            if raw.startswith(_IMG_MAGIC):
                return raw
        except (binascii.Error, ValueError):
            pass
    if len(compact) >= 40 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        raw = bytes.fromhex(compact)
        if raw.startswith(_IMG_MAGIC):
            return raw
    return None


def decode_nested(data, depth: int = NEST, deadline=None, skipped: list = None) -> list:
    """Codes followed through codes: [{format, text, bytes, how, chain}] of the innermost payloads.
    A payload that is itself an image (raw, data: URI, base64, hex) or a text drawing of a code is
    decoded again, at most `depth` levels down; `chain` lists the formats from the outside in."""
    def step(payload, left, chain):
        img = _as_image(payload)
        found = decode_codes(img, deadline=deadline, skipped=skipped) if img is not None else []
        if not found and not isinstance(payload, (bytes, bytearray)):
            found = decode_grid(payload)
        if not found and isinstance(payload, (bytes, bytearray)) and img is None:
            t = as_text(bytes(payload))
            found = decode_grid(t) if t else []
        leaves = []
        for r in found:
            inner = step(r["text"] if r["text"] else r["bytes"], left - 1, chain + [r["format"]]) if left > 1 else []
            if not inner and r["bytes"] and _as_image(r["bytes"]) is not None and left > 1:
                inner = step(r["bytes"], left - 1, chain + [r["format"]])
            leaves += inner or [{**r, "chain": chain + [r["format"]]}]
        return leaves
    return step(data, depth, [])


# ---- findings ---------------------------------------------------------------------------------------

IMAGE_KINDS = {"png", "jpeg", "gif", "bmp", "webp", "tiff"}
BLOB_CHANNELS = {"trailing", "carved", "deleted", "lsb", "wav_lsb", "png_chunk"}


def _finding(channel, file, method, text=None, data=None, offset=None, kind=None, name=None, validated=True, depth=0,
             **more) -> dict:
    return {"channel": channel, "file": file, "method": method, "text": text, "data": data, "offset": offset,
            "kind": kind, "name": name, "validated": validated, "depth": depth, **more}


def _text_of(blob: bytes, limit: int = 1 << 16):
    """A blob as text when all of it is printable text (at most `limit` bytes), else None."""
    if not blob or len(blob) > limit:
        return None
    t = as_text(blob)
    if t is None:
        return None
    t = t.strip("\x00")
    return t if t.strip() and all(c.isprintable() or c in "\r\n\t" for c in t) else None


def _zip_members(blob: bytes) -> list:
    """[(name, bytes)] of a zip's members, encrypted ones under the known archive passwords only."""
    out = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except (zipfile.BadZipFile, ValueError, OSError):
        return out
    opener = None
    for info in zf.infolist()[:500]:
        if info.is_dir() or info.file_size > MAX_INFLATE:
            continue
        body = None
        try:
            if info.flag_bits & 1:
                import archive_passwords as pw
                opener = opener or pw.Opener(blob, zf)
                body = opener.read(info)
            else:
                body = zf.read(info)
        except Exception:
            body = None
        if body is not None:
            out.append((info.filename, body))
    return out


def scan(name: str, data: bytes, deep: bool = True, deadline=None, depth: int = 0, root: str = None,
         skipped: list = None) -> list:
    """Every finding of one file: a list of {channel, file, method, text, data, offset, kind, name,
    validated, depth}. Channels: trailing, carved, member (a file inside a carved or trailing
    archive), png_chunk (non-standard), png_text, comment (JPEG COM, GIF comment, zip comment),
    wav_chunk, lsb, wav_lsb, dtmf, code (QR and barcodes), zero_width, whitespace, fs, deleted,
    recycle, dump, uimage, polyglot, png_crc. `deep` adds the slower readings (pixels, samples,
    codes). A carved file is scanned again (two levels). `skipped`, when given, gets one note for
    every reading the deadline or a size limit left out: with a note in it the findings are not all
    there are, and "the one hidden item" is not proven."""
    root = root or name
    out = []
    skipped = skipped if skipped is not None else []

    def late():
        if deadline is not None and time.monotonic() > deadline:
            skipped.append(f"{name}: out of time")
            return True
        return False

    if len(data) > MAX_SCAN:
        skipped.append(f"{name}: only the first {MAX_SCAN} bytes are searched for embedded files")

    def add(channel, method, **kw):
        out.append(_finding(channel, root, method, depth=depth, **kw))

    def sub(label, blob, why):
        """A blob that was hidden: its members if it is an archive, then its own findings."""
        if depth >= 2 or late():
            return
        if blob[:4] == b"PK\x03\x04":
            for mname, body in _zip_members(blob):
                out.append(_finding("member", root, f"{why} zip member", text=_text_of(body), data=body, name=mname,
                                    kind=sniff(body), depth=depth + 1, parent=label))
                out.extend(scan(f"{label}{ARROW}{mname}", body, deep, deadline, depth + 1, root, skipped))
        elif blob[:3] == b"\x1f\x8b\x08":
            got = _gzip_end(blob, 0, want_out=True)
            if got:
                out.append(_finding("member", root, f"{why} gzip content", text=_text_of(got[1]), data=got[1],
                                    name=label, kind=sniff(got[1]), depth=depth + 1, parent=label))
                out.extend(scan(label + ".out", got[1], deep, deadline, depth + 1, root, skipped))
        else:
            out.extend(scan(label, blob, deep, deadline, depth + 1, root, skipped))

    kind, end = primary(data)
    # -- what follows the structure, and what is embedded
    tail_at = None
    if end and kind not in ("text", "data") and end < len(data) and data[end:].strip(b"\x00\r\n\t "):
        tail_at = end
    carved = carve(data) if len(data) > 8 else []
    whole_tail = next((c for c in carved if tail_at is not None and c["offset"] == tail_at
                       and c["end"] >= len(data.rstrip(b"\x00\r\n\t "))), None)
    if tail_at is not None:
        tail = data[tail_at:]
        if whole_tail:
            add("trailing", f"after the {kind} end", data=whole_tail["data"], offset=tail_at, kind=whole_tail["kind"],
                carved=True, names=whole_tail.get("names"))
            sub(f"{name}@{tail_at:#x}.{EXT.get(whole_tail['kind'], 'bin')}", whole_tail.get("inflated") or whole_tail["data"],
                "trailing")
        else:
            add("trailing", f"after the {kind} end", data=tail, offset=tail_at, text=_text_of(tail),
                kind="text" if _text_of(tail) else None)
    for c in carved:
        if c is whole_tail:
            continue
        add("carved", f"{c['kind']} at {c['offset']:#x}" + (" inside the " + kind if c["inside"] else ""),
            data=c.get("inflated") if c["kind"] == "zlib" else c["data"], offset=c["offset"], kind=c["kind"],
            validated=c["validated"], inside=c["inside"], names=c.get("names"),
            text=_text_of(c["inflated"]) if c["kind"] == "zlib" else None)
        if c["validated"]:
            sub(f"{name}@{c['offset']:#x}.{EXT.get(c['kind'], 'bin')}", c.get("inflated") or c["data"], "carved")
    pg = polyglot(data)
    if pg:
        add("polyglot", "+".join(pg), text="+".join(pg), kinds=pg)

    # -- the format's own side channels
    if kind == "png":
        chunks = png_chunks(data)
        for c in chunks:
            if not c["standard"]:
                add("png_chunk", f"chunk {c['type']} at {c['offset']:#x}", data=c["data"], offset=c["offset"],
                    name=c["type"], text=_text_of(c["data"]), kind=sniff(c["data"]) if len(c["data"]) > 8 else None)
            if not c["crc_ok"]:
                add("png_crc", f"chunk {c['type']} at {c['offset']:#x} has a wrong CRC", name=c["type"], offset=c["offset"],
                    fix=png_fix_dimensions(data) if c["type"] == "IHDR" and depth == 0 and len(data) < (1 << 22) else None)
        for typ, key, value in png_text(data):
            add("png_text", f"{typ} {key}", text=value, name=key, data=value.encode("utf-8", "replace"))
        for where, extra in png_idat_extra(data, chunks):
            add("png_chunk", f"IDAT: {len(extra)} bytes {where}", data=extra, name="IDAT", text=_text_of(extra),
                kind=sniff(extra) if len(extra) > 8 else None)
    elif kind == "jpeg":
        for s in jpeg_segments(data):
            if s["name"] == "COM":
                add("comment", f"JPEG COM at {s['offset']:#x}", text=s["text"], data=s.get("data"), offset=s["offset"])
    elif kind == "gif":
        blocks = gif_blocks(data)
        if blocks["frames"] > 32:
            skipped.append(f"{name}: only the first 32 frames are read for codes")
        for t in blocks["comments"]:
            add("comment", "GIF comment", text=t, data=t.encode("utf-8", "replace"))
    elif kind == "zip" and depth == 0:
        for z in zips(data):
            if z["comment"].strip(b"\x00"):
                add("comment", "zip comment", text=z["comment"].decode("utf-8", "replace"), data=z["comment"])
    elif kind == "wav":
        info = wav_info(data)
        for c in info["chunks"]:
            if c["id"] not in WAV_STANDARD:
                body = data[c["offset"] + 8:c["offset"] + 8 + c["size"]]
                add("wav_chunk", f"chunk {c['id']!r} at {c['offset']:#x}", data=body, offset=c["offset"], name=c["id"],
                    text=_text_of(body))
        for k, v in info["info"].items():
            add("wav_chunk", f"LIST/INFO {k}", text=v, name=k, data=v.encode("utf-8", "replace"))
    elif kind == "uimage":
        u = fs.uimage(data)
        if u:
            add("uimage", f"uImage {u['name']!r} {u['os']}/{u['arch']} {u['type']} {u['compression']}", name=u["name"],
                data=u["data"], info={k: v for k, v in u.items() if k != "data"})
            sub(f"{name}{ARROW}payload", u["data"], "uimage")
    elif kind == "minidump":
        d = fs.minidump(data)
        if d:
            add("dump", f"minidump: {len(d['streams'])} streams, {len(d['modules'])} modules, {len(d['threads'])} threads, "
                f"{len(d['memory'])} memory ranges", info=d, kind="minidump")
    elif kind == "elf":
        d = fs.elf_core(data) if depth == 0 else None
        if d:
            add("dump", f"ELF core of {d['process']!r}: {len(d['notes'])} notes, {len(d['files'])} mapped files", info=d,
                kind="elf_core")
    r = fs.recycle_i(data) if 28 <= len(data) <= 70000 else None
    if r:
        add("recycle", f"$I version {r['version']}", text=r["path"], name=r["path"], info=r)

    # -- file systems
    if kind in ("iso9660", "ext", "cpio", "fat12", "fat16", "fat32"):
        info = {}
        k, entries = fs.walk(data, info)
        if len(entries or []) >= fs.MAX_ENTRIES:
            skipped.append(f"{name}: more than {fs.MAX_ENTRIES} entries")
        for e in entries or []:
            add("deleted" if e["deleted"] else "fs", f"{kind} {'deleted ' if e['deleted'] else ''}{'dir' if e['dir'] else 'file'}",
                name=e["path"], data=e["data"], text=_text_of(e["data"]) if e["data"] else None, is_dir=e["dir"],
                size=e["size"], short=e.get("short"), mtime=e.get("mtime"), fs=kind, fsinfo=info, stale=bool(e.get("stale")),
                kind=sniff(e["data"]) if e["data"] else None)
            if e["data"] and not e["dir"] and len(e["data"]) > 8 and depth < 1 and not late():
                out.extend(scan(f"{name}{ARROW}{e['path']}", e["data"], deep, deadline, depth + 1, root, skipped))
    elif kind == "data" and len(data) >= 1024 and data[510:512] == b"\x55\xaa" and data[3:11] in (b"NTFS    ", b"EXFAT   "):
        vol = data[3:11].decode().strip().lower()
        add("fs", f"{vol} volume: NOT READ by this toolkit; list it with `tools/sandbox.py run --in <file> 7z l {{in}}` and extract "
                  f"with `tools/sandbox.py run --keep --in <file> 7z x -o{{out}} {{in}}`", name=vol, is_dir=True, fs=vol, kind=vol,
            validated=False, partition=True)
        skipped.append(f"{name}: {vol} is not read here")
    elif kind == "data" and depth < 1 and len(data) >= 1024 and data[510:512] == b"\x55\xaa":
        table = fs.partitions(data)
        for p in (table or {}).get("parts", [])[:16]:
            part = data[p["start"]:p["start"] + p["size"]]
            inner = fs.kind_of(part)
            add("fs", f"{table['scheme']} partition {p['index']}: type {p['type_name']}, {p['size']} bytes at {p['start']:#x}, "
                      f"{'file system ' + inner if inner else 'no file system this toolkit reads'}",
                name=f"partition{p['index']}", offset=p["start"], size=p["size"], is_dir=True, fs=table["scheme"], kind=inner,
                partition=True)
            if not inner and p["type"] not in (0x05, 0x0F, 0x82) and part.strip(b"\x00"):
                # data this toolkit cannot walk: "the files of the disk" is not proven without it
                skipped.append(f"{name}: partition {p['index']} ({p['type_name']}) holds data that is not read here")
            if inner and not late():
                # the partition is walked as a disk of its own: its entries are findings of '<image> -> partitionN'
                out.extend(scan(f"{name}{ARROW}partition{p['index']}", part, deep, deadline, depth + 1, root, skipped))

    # -- text channels
    if kind == "text":
        if len(data) > 1 << 20:
            skipped.append(f"{name}: only the first MiB of text is read")
        t = as_text(data[:1 << 20])
        if t:
            for method, hidden in zero_width(t):
                add("zero_width", method, text=hidden, data=hidden.encode("utf-8", "replace"))
            for method, hidden in whitespace_bits(t):
                add("whitespace", method, text=hidden, data=hidden.encode("utf-8", "replace"))
            if deep and not late() and len(t) < 400000 and (set(t) & set("█▀▄\x1b") or re.search(r"^[01#.X ]{8,}$", t, re.M)):
                for r_ in decode_nested(t, deadline=deadline, skipped=skipped):
                    add("code", f"{r_['format']} ({r_['how']})", text=r_["text"], data=r_["bytes"], kind=r_["format"],
                        chain=r_["chain"])

    # -- the slower readings
    if deep and not late():
        if kind in ("png", "bmp", "gif", "webp"):
            px = {"png": png_pixels, "bmp": bmp_pixels, "gif": gif_pixels, "webp": webp_pixels}[kind](data)
            if px and px["width"] * px["height"] <= MAX_PIXELS:
                seen = set()
                lsb_hits = lsb_scan(px, deadline=deadline, skipped=skipped)
                for hit in lsb_hits:
                    seen.add(hit["data"] if hit["what"] == "file" else hit["text"])
                deep_lsb_hits = lsb_deep_scan(px, deadline=deadline, skipped=skipped, seen=seen)
                # the higher planes (2..7, the MSB among them), read strictly: a byte-proven payload only
                for hit in list(lsb_hits) + deep_lsb_hits + plane_scan(px, deadline=deadline, skipped=skipped, seen=seen):
                    add("lsb", hit["method"], text=hit["text"], data=hit["data"], kind=hit["kind"] or "text")
                    if hit["what"] == "file":
                        sub(f"{name}{ARROW}lsb.{EXT.get(hit['kind'], 'bin')}", hit["data"], "lsb")
        if kind == "wav":
            for hit in wav_lsb(data):
                add("wav_lsb", hit["method"], text=hit["text"], data=hit["data"], kind=hit["kind"] or "text")
            keys, sure = dtmf_read(data) if not late() else (None, False)
            if keys:
                add("dtmf", "Goertzel" if sure else "Goertzel (cut short, or unstable: tones or gaps near one window)",
                    text=keys, data=keys.encode(), validated=sure)
        if kind in IMAGE_KINDS and not late():
            for r_ in decode_nested(data, deadline=deadline, skipped=skipped):
                add("code", f"{r_['format']} ({r_['how']})", text=r_["text"], data=r_["bytes"], kind=r_["format"],
                    chain=r_["chain"])
    return out


def unique_files(files: dict) -> list:
    """[(name, bytes)] once per file (tools/run.py files a member under two names)."""
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        out.append((key, bytes(data)))
    return sorted(out, key=lambda kv: kv[0])


def scan_files(files: dict, deep: bool = True, deadline=None, skipped: list = None) -> list:
    """scan() over a delivery's files; a finding's `file` is the member name (after the last arrow)."""
    out = []
    for name, data in unique_files(files):
        out.extend(scan(name.split(ARROW)[-1], data, deep, deadline, skipped=skipped))
    return out


def carved_files(files: dict, deep: bool = True) -> dict:
    """The carved and recovered members of a delivery as {'<file> -> <member>': bytes}: what follows
    a file's end, embedded files, archive members of those, non-standard PNG chunks, LSB files,
    deleted and live file-system entries. Add them to `files` and hand the lot back to
    solvers/common/triage.py or solvers/toolkits/evidence_core.py."""
    out = {}
    for f in scan_files(files, deep):
        if not f["data"] or f["channel"] not in ("trailing", "carved", "member", "png_chunk", "lsb", "wav_lsb", "fs",
                                                 "deleted", "uimage"):
            continue
        if f["channel"] in ("fs", "deleted", "member"):
            member = ("deleted/" if f["channel"] == "deleted" else "") + str(f["name"])
        elif f["channel"] == "png_chunk":
            member = f"chunk-{f['name']}@{f['offset']:#x}.bin"
        elif f["channel"] in ("lsb", "wav_lsb"):
            member = f"{f['channel']}-{len(out)}.{EXT.get(f['kind'], 'bin')}"
        elif f["channel"] == "uimage":
            member = "uimage-payload.bin"
        else:
            member = f"{f['channel']}@{f['offset']:#x}.{EXT.get(f['kind'], 'bin')}"
        parent = f.get("parent") or f["file"]
        key = f"{parent}{ARROW}{member}"
        n = 1
        while key in out and out[key] != f["data"]:
            n += 1
            key = f"{parent}{ARROW}{member}#{n}"
        out[key] = f["data"]
    return out


# ---- the question ----------------------------------------------------------------------------------

_CH = (
    ("code", r"\bqr\b|qr[- ]?codes?\b|\bbar ?codes?\b|\baztec\b|data ?matrix|pdf ?417|maxicode|\bscan(?:ning|ned)? the\b"),
    ("dtmf", r"\bdtmf\b|touch[- ]?tones?\b|\bdial(?:ed|led|ing)?\b|keypad tones?"),
    ("lsb", r"\blsb\b|least[- ]significant|bit[- ]?planes?\b|\bstegan?o\w*|\bpixels? (?:data|values)\b"),
    ("trailing", r"\bappend\w*|\btrailing (?:data|bytes)|\bafter the (?:end|iend|eoi|image|%%eof)|\bpast the end\b|\boverlay\b|"
                 r"\bend of the (?:image|file|picture|png|jpe?g)\b"),
    ("carved", r"\bembedded (?:file|archive|zip|image|picture|document|executable|binary|object)s?\b|\bcarv\w+|\bhidden (?:file|archive|zip|image|payload|document)\b|\bpolyglot\b|\bsmuggl\w+|"
               r"\binside the (?:image|picture|audio|recording|photo|png|jpe?g|wav)\b"),
    ("chunk", r"\bchunks?\b"),
    ("comment", r"\bcomments?\b"),
    ("text", r"zero[- ]?width|\binvisible\b|unicode tags?\b|tag characters?|variation selectors?|trailing (?:whitespace|spaces)|"
             r"\bwhitespace\b|tabs? and spaces?"),
    ("deleted", r"\bdeleted\b|\bundelet\w+|\bunallocated\b|\brecover(?:ed|able)? file"),
    ("recycle", r"recycle bin|\$i\w*\b|\$recycle"),
    ("fs", r"\bdisk image\b|\bfile ?system\b|\bfloppy\b|\biso(?:9660| image)?\b|\bfat(?:12|16|32)?\b|\bext[234]\b|\bcpio\b|"
           r"\binitramfs\b|\binitrd\b|\bu-?image\b|\bfirmware image\b|\bvolume label\b"),
    ("dump", r"\bminidump\b|\bcore dump\b|\bcrash dump\b|\bcore file\b|\b\.dmp\b"),
    ("hidden", r"\bhidden\b|\bsecret\b|\bconceal\w*|\bcovert\b|\bstego\w*"),
)
_CH_RX = [(name, re.compile(rx, re.I)) for name, rx in _CH]
_CHANNELS_OF = {
    "code": {"code"}, "dtmf": {"dtmf"}, "lsb": {"lsb", "wav_lsb"}, "trailing": {"trailing"},
    "carved": {"carved", "trailing", "member", "lsb", "wav_lsb", "png_chunk"}, "chunk": {"png_chunk", "png_text", "wav_chunk"},
    "comment": {"comment", "png_text", "wav_chunk"}, "text": {"zero_width", "whitespace"},
    "deleted": {"deleted", "recycle"}, "recycle": {"recycle"}, "fs": {"fs", "deleted", "uimage"}, "dump": {"dump"},
}
_PAYLOAD_CHANNELS = {"code", "dtmf", "lsb", "wav_lsb", "trailing", "carved", "member", "png_chunk", "png_text", "comment",
                     "wav_chunk", "zero_width", "whitespace", "deleted"}
_MEDIA_CHANNELS = {"code", "dtmf", "lsb", "wav_lsb", "png_text", "comment", "png_chunk", "trailing", "member", "zero_width"}
_ALGO = {"sha256": r"sha-?256", "sha1": r"sha-?1\b", "md5": r"\bmd5\b", "sha512": r"sha-?512"}
_TYPE_NAMES = {
    "zip": ["zip", "zip_archive", "pkzip"], "png": ["png", "png_image"], "jpeg": ["jpeg", "jpg", "jpeg_image"],
    "gif": ["gif", "gif_image"], "pdf": ["pdf", "pdf_document"], "gzip": ["gzip", "gz", "gzip_archive"],
    "7z": ["7z", "7zip", "seven_zip"], "rar": ["rar", "rar_archive"], "elf": ["elf", "elf_executable"],
    "pe": ["pe", "exe", "pe_executable"], "wav": ["wav", "wave", "riff_wave"], "zlib": ["zlib", "zlib_stream"],
    "text": ["text", "plain_text", "txt"], "bmp": ["bmp", "bitmap"], "webp": ["webp"],
    "fat12": ["fat12", "fat_12", "fat"], "fat16": ["fat16", "fat_16", "fat"], "fat32": ["fat32", "fat_32", "fat"],
    "ext2": ["ext2", "ext"], "ext3": ["ext3", "ext"], "ext4": ["ext4", "ext"], "iso9660": ["iso9660", "iso_9660", "iso"],
    "cpio": ["cpio", "cpio_archive"], "qr_code": ["qr_code", "qr", "qrcode"], "qrcode": ["qr_code", "qr", "qrcode"],
    "aztec": ["aztec", "aztec_code"], "data_matrix": ["data_matrix", "datamatrix"], "datamatrix": ["data_matrix", "datamatrix"],
    "pdf417": ["pdf417", "pdf_417"], "code128": ["code128", "code_128"], "code39": ["code39", "code_39"],
    "ean13": ["ean13", "ean_13"], "minidump": ["minidump", "mdmp", "windows_minidump"], "elf_core": ["elf_core", "core_dump", "core"],
}


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _pattern(q):
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    return rx if isinstance(rx, str) and rx.strip() else None


def _fits(q, value) -> bool:
    rx = _pattern(q)
    if rx is None:
        return True
    try:
        return re.fullmatch(rx, str(value)) is not None
    except re.error:
        return False


def _options(q) -> list:
    try:
        return _tri().enum_options(q)
    except Exception:
        return []


def channels_asked(q) -> set:
    """The channel words of a question ('code', 'dtmf', 'lsb', 'trailing', 'carved', 'chunk',
    'comment', 'text', 'deleted', 'recycle', 'fs', 'dump', 'hidden'), from its text and its id."""
    aid = str(q.get("answer_id") or q.get("qid") or q.get("id") or "")
    words = " ".join(str(x or "") for x in (q.get("question"), _fmt(q).get("syntax"), re.sub(r"[-_.]+", " ", aid)))
    return {name for name, rx in _CH_RX if rx.search(words)}


def _pattern_hits(rx: str, text: str) -> list:
    """The values in a payload the question's pattern accepts: the whole text, a whole line, or a
    piece found by the pattern without its anchors."""
    out = []
    try:
        whole = text.strip()
        if re.fullmatch(rx, whole):
            return [whole]
        for line in whole.splitlines():
            if re.fullmatch(rx, line.strip()):
                out.append(line.strip())
        if out:
            return out
        loose = rx.strip()
        loose = loose[1:] if loose.startswith("^") else loose
        loose = loose[:-1] if loose.endswith("$") and not loose.endswith("\\$") else loose
        for m in re.finditer(loose, whole):
            # a piece counts only when it stands alone: 'assword123' out of 'Password123' is no value
            before, after = whole[:m.start()][-1:], whole[m.end():][:1]
            if m.group() and re.fullmatch(rx, m.group()) and (not before or before.isspace() or before in "\"'`([<=:") \
                    and (not after or after.isspace() or after in "\"'`)]>.,;!?"):
                out.append(m.group())
    except re.error:
        return []
    return out


def _uniq(values) -> list:
    out = []
    for v in values:
        if v not in out:
            out.append(v)
    return out


class _State:
    """One set's findings, read once and only when a question asks for them."""

    def __init__(self, files, deadline):
        self.files, self.deadline, self._found, self.skipped = files, deadline, None, []

    def findings(self) -> list:
        if self._found is None:
            self._found = scan_files(self.files, True, self.deadline, self.skipped)
        return self._found

    def names(self) -> list:
        return _uniq(Path(n.split(ARROW)[-1]).name for n, _ in unique_files(self.files))


def _scope(q, st: _State, found: list) -> list:
    """The findings of the file a question names (its member, or a file name in its text); all of
    them when it names none."""
    text = str(q.get("question") or "")
    named = [n for n in st.names() if len(n) > 2 and re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", text)]
    member = q.get("member")
    if member:
        named.append(Path(str(member)).name)
    if not named:
        return found
    hit = [f for f in found if Path(str(f["file"])).name in named]
    return hit if hit else ([] if member else found)


def _stamp_options(stamp: str) -> list:
    """Spellings of one UTC or local time read as 'YYYY-MM-DDTHH:MM:SS[Z]'."""
    base = stamp.rstrip("Z")
    opts = [("iso_z", base + "Z"), ("iso", base), ("iso_space", base.replace("T", " ")), ("iso_offset", base + "+00:00")]
    return opts if stamp.endswith("Z") else opts[1:3] + [opts[0]]


# Words that make "the hash of <name>" a question about something other than that file's bytes as stored.
_ENTRY_QUALIFIED = re.compile(
    r"\b(?:not|deleted|removed|erased|hidden|inside|within|embedded|appended|slack|previous|earlier|older|original|decoded|decrypted|"
    r"decompressed|extracted|carved|recovered|first|last|line|other|another|except|without|after|before|modified|password|contents? of the)\b"
    r"|n't\b", re.I)


# "the SHA-256 of the disk image", "the MD5 of the whole archive": the container itself is asked (the triage
# answers a delivery's own hash), unless the next words turn it into the hidden item ("the image appended to ...").
_CONTAINER = (r"(?:the|this)\s+(?:whole\s+|entire\s+|full\s+|original\s+|delivered\s+|given\s+)?"
              r"(?:disk image|disk|image|file ?system|archive|floppy|iso|volume|partition|delivery|artifact|evidence|picture|photo|recording|"
              r"dump|capture|container|cover(?: file| image)?|carrier)\b"
              r"(?!\s+(?:hidden|embedded|appended|deleted|carved|concealed|recovered|stored\s+(?:after|inside|in)|inside|within|after|"
              r"(?:that|which)\s+(?:is|was|has been)\s+(?:hidden|embedded|appended|deleted|carved|concealed|recovered))\b)")
_HASH_OF_CONTAINER = re.compile(r"\b(?:hash|digest|checksum|sum|sha-?\d+|md5)\s+(?:hash\s+|digest\s+|checksum\s+|value\s+)?(?:of|for)\s+" + _CONTAINER, re.I)
_SIZE_OF_CONTAINER = re.compile(r"\b(?:size|length)(?:\s+in\s+bytes)?\s+(?:of|for)\s+" + _CONTAINER
                                + r"|\bhow\s+(?:many\s+bytes\s+(?:long\s+)?|big\s+|large\s+|long\s+)(?:is|are|does|has)\s+" + _CONTAINER, re.I)
# A question about what is NOT the hidden item, or about the hidden items together with the rest.
_NEGATED = re.compile(r"\bnot\b(?! part of\b)|n't\b|\bexcept\b|\bexcluding\b|\bother than\b|\bneither\b|\bnever\b", re.I)
_TOGETHER = re.compile(r"\binclud\w+|\bas well as\b|\bin total\b|\baltogether\b|\bcounting\b|\bboth\b|\band (?:the )?(?:live|existing|remaining|deleted)\b", re.I)


def answer(q, st: _State):
    """One question's answer: plain, an unsure pick, or None (see the module text)."""
    f = _fmt(q)
    kind = str(f.get("kind") or "")
    if kind in ("mitre_attack_id", "ordered_tokens", "json"):
        return None
    text = " ".join(str(q.get("question") or "").split())
    syntax = str(f.get("syntax") or "")
    low = (text + " " + syntax).lower()
    aid = str(q.get("answer_id") or q.get("qid") or "")
    asked = channels_asked(q)
    try:
        theirs = set(_tri().lane_signals([q], {}))
    except Exception:
        theirs = set()
    if theirs - {"warmups"}:
        return None             # the form of a known lane (Determine <property> for <file>, ANS-, dNN_, -role): its solver's
    warm = False
    if not asked or theirs:
        # the Warmups form over a picture or a recording: "decode ... message", no channel word
        if not (re.sub(r"^set\d+\.", "", aid) == "message" or re.search(r"\bdecod\w+\b", low)):
            return None
        if not any(sniff(d) in IMAGE_KINDS | {"wav"} for _, d in unique_files(st.files)):
            return None
        warm = True
    # a partition (or an unread volume) is a marker for the reader of the map: it is no directory, no file
    # and no file system of its own, so no count, name or kind is taken from it
    if _NEGATED.search(text):
        return None             # what is NOT hidden, deleted or appended is another fact than the one item found
    found = [x for x in _scope(q, st, st.findings()) if not x.get("partition")]
    if st.skipped:
        return None             # a reading was left out (time, a size limit): "the one item" is not proven
    if warm:
        chans = set(_MEDIA_CHANNELS)
    else:
        chans = set()
        for a in asked - {"hidden"}:
            chans |= _CHANNELS_OF[a]
        if not chans:
            chans = set(_PAYLOAD_CHANNELS)
    sel = [x for x in found if x["channel"] in chans]
    upper = re.search(r"\bupper-?case\b", low) is not None
    rx = _pattern(q)

    def plain(value):
        value = str(value)
        return value if _fits(q, value) else None

    def blobs():
        """The top-level hidden items the words name, once each by content."""
        want = (chans & BLOB_CHANNELS) or BLOB_CHANNELS
        seen, out = set(), []
        if "deleted" in want and any(x["channel"] == "deleted" and not x.get("is_dir") and x.get("size")
                                     and (x["data"] is None or x.get("stale")) for x in sel):
            return []
        for x in sel:
            if x["channel"] in want and x["data"] and x["depth"] == 0 and x["validated"] and not x.get("is_dir") \
                    and (x["channel"] not in ("lsb", "wav_lsb", "png_chunk") or x["kind"] not in (None, "text")
                         or asked & {"lsb", "chunk"}):
                if x["data"] not in seen:
                    seen.add(x["data"])
                    out.append(x)
        return out

    def tail_forms(x) -> list:
        """[(name, bytes)] of one hidden item: itself, and, for bytes after a file's end that are no
        file by their own structure, also without the NULs and line ends around them."""
        raw = x["data"]
        bare = raw.strip(b"\x00\r\n\t ")
        if x["channel"] == "trailing" and not x.get("carved") and bare and bare != raw:
            return [("as_is", raw), ("stripped", bare)]
        return [("as_is", raw)]

    def of_a_file(head: str) -> bool:
        """True when the phrase names a delivered file itself ("the SHA-256 of cover.png")."""
        return any(len(n) > 2 and re.search(head + r"\s+(?:hash|digest|checksum|value|sum)?\s*(?:of|for)\s+(?:the\s+)?"
                                            r"(?:file\s+)?[`'\"]?" + re.escape(n) + r"(?![\w-])", text, re.I) for n in st.names())

    def named_entry(head: str):
        """The one live file of a file system or archive inside the delivery that the question asks
        the hash OF, by its path or name ("the SHA-256 of passwords.txt"), or None: no such phrase,
        a name that fits entries with different bytes, a deleted entry of the same name, an entry
        not read whole, or a question about something else that only mentions the file (the image
        that holds it, what is hidden inside it, its deleted version, one line of it)."""
        if _ENTRY_QUALIFIED.search(text):
            return None
        hits, names = {}, set()
        for x in found:
            if x["channel"] not in ("fs", "member") or x.get("is_dir") or x.get("data") is None or not x.get("name") \
                    or not x.get("validated") or (x.get("size") is not None and x["size"] != len(x["data"])):
                continue
            path = str(x["name"])
            for n in {path, path.rsplit("/", 1)[-1]}:
                if len(n) > 2 and re.search(head + r"\s+(?:hash|digest|checksum|value|sum)?\s*(?:of|for)\s+(?:the\s+)?(?:file\s+)?[`'\"]?"
                                            + re.escape(n) + r"(?![\w/\\-]|\.\w)", text, re.I):
                    hits[x["data"]] = x
                    names.add(path.rsplit("/", 1)[-1].lower())
        if len(hits) != 1:
            return None
        if any(x["channel"] == "deleted" and str(x.get("name") or "").rsplit("/", 1)[-1].lower() in names for x in found):
            return None             # a deleted file of that name too: which of the two is asked is not told
        return next(iter(hits.values()))

    # -- a hash of the one hidden item
    algos = [a for a, r in _ALGO.items() if re.search(r, text, re.I)]
    if algos:
        if of_a_file(r"\b" + _ALGO[algos[0]].replace(r"\b", "")):
            return None
        entry = named_entry(r"\b" + _ALGO[algos[0]].replace(r"\b", ""))
        if entry is not None and len(algos) == 1 and not re.search(r"\b0x\b|\bbase64\b|\bcolon|\bseparat", low):
            v = hashlib.new(algos[0], entry["data"]).hexdigest()        # a file the image holds whole, named in the question
            return plain(v.upper() if upper else v)
        if _HASH_OF_CONTAINER.search(text):
            return None             # the hash of the image itself: never the hidden item's
        if any(x["channel"] in ("fs", "member") and not x.get("is_dir") and x.get("name") and len(str(x["name"]).rsplit("/", 1)[-1]) > 2
               and re.search(r"(?<![\w.-])" + re.escape(str(x["name"]).rsplit("/", 1)[-1]) + r"(?![\w-])", text, re.I) for x in found):
            return None             # a live file is named and its own hash is not what is asked: not read further
        items = blobs()
        if len(algos) != 1 or len(items) != 1 or re.search(r"\b0x\b|\bbase64\b|\bcolon|\bseparat", low):
            return None
        forms = [(n, hashlib.new(algos[0], d).hexdigest()) for n, d in tail_forms(items[0])]
        forms = [(n, v.upper() if upper else v) for n, v in forms if _fits(q, v.upper() if upper else v)]
        return plain(forms[0][1]) if len(forms) == 1 else pick("hash", "trailing.loose", forms)

    # -- the size of the one hidden item
    if re.search(r"\b(?:size|length)\b.*\bbytes\b|\bhow many bytes\b|\bbytes long\b|\bnumber of bytes\b", low):
        if of_a_file(r"\b(?:size|length)(?:\s+in\s+bytes)?") or any(
                re.search(r"\bhow many bytes\s+(?:long\s+)?(?:is|are|does)\s+(?:the\s+)?(?:file\s+)?[`'\"]?" + re.escape(n), text, re.I)
                for n in st.names() if len(n) > 2):
            return None
        if _SIZE_OF_CONTAINER.search(text):
            return None             # the size of the image itself: never the hidden item's
        items = blobs()
        if len(items) != 1:
            return None
        forms = [(n, str(len(d))) for n, d in tail_forms(items[0]) if _fits(q, len(d))]
        return forms[0][1] if len(forms) == 1 else pick("size", "trailing.loose", forms)

    # -- how many
    if re.search(r"\bhow many\b|\bnumber of\b|\bcount of\b|\bcount the\b", low):
        return _count(q, st, found, sel, asked, low, text, plain)

    # -- the offset of the one hidden item
    if re.search(r"\boffset\b|\bat what (?:byte|position)\b|\bwhere does\b", low):
        items = [x for x in sel if x["channel"] in ("trailing", "carved", "png_chunk") and x["offset"] is not None and x["depth"] == 0]
        offs = _uniq(x["offset"] for x in items)
        if len(offs) != 1:
            return None
        dec, hx = str(offs[0]), f"0x{offs[0]:x}"
        if re.search(r"\bhex", low) or "0x" in low:
            opts = [(n, v) for n, v in (("hex_0x", hx), ("hex_plain", f"{offs[0]:x}"), ("hex_0x_upper", f"0x{offs[0]:X}"))
                    if _fits(q, v)]
            forms = _uniq(v for _, v in opts)
            return forms[0] if rx and len(forms) == 1 else pick("offset", "hex", opts)
        if kind == "integer" or re.search(r"\bdecimal\b", low):
            return plain(dec)
        return pick("offset", "decimal", [("decimal", dec), ("hex_0x", hx)])

    # -- when
    if re.search(r"\bwhen\b|\btimestamp\b|\b(?:date|time)\b", low) and asked & {"deleted", "recycle", "fs", "dump"}:
        stamps = _uniq(x["info"]["deleted"] for x in sel if x["channel"] == "recycle")
        shape = "recycle.deleted"
        if not stamps:
            stamps = _uniq(x.get("mtime") for x in sel if x["channel"] == "deleted" and not x.get("is_dir") and x.get("mtime"))
            shape = "deleted.mtime"
        if len(stamps) != 1:
            return None
        opts = [(n, v) for n, v in _stamp_options(stamps[0]) if _fits(q, v)]
        return opts[0][1] if rx and len(opts) == 1 else pick("time", shape, opts)

    # -- what kind
    if re.search(r"\b(?:what|which) (?:type|kind|format|file ?system|symbology)\b|\b(?:file )?type of\b|\bformat of\b|"
                 r"\bkind of (?:file|archive|code)\b", low) or kind == "enum" and not re.search(r"\bname\b", low):
        facts = []
        if asked & {"code"}:
            facts = _uniq(x["kind"] for x in sel if x["channel"] == "code")
        elif asked & {"fs"} and not asked & {"deleted", "carved", "trailing"}:
            facts = _uniq((x.get("fsinfo") or {}).get("version") or x.get("fs") for x in sel if x["channel"] in ("fs", "deleted"))
        elif asked & {"dump"}:
            facts = _uniq(x["kind"] for x in sel if x["channel"] == "dump")
        else:
            facts = _uniq(x["kind"] for x in blobs() if x["kind"])
        if len(facts) != 1:
            return None
        names = _TYPE_NAMES.get(facts[0], [facts[0]])
        listed = _options(q)
        if listed:
            hits = [o for o in listed if o.strip().lower() in names]
            return hits[0] if len(hits) == 1 and _fits(q, hits[0]) else None
        return pick("type", facts[0], [n for n in names if _fits(q, n)])

    # -- a name
    if re.search(r"\b(?:file ?)?name\b|\bwhich file\b|\bwhat file\b|\boriginal (?:path|location)\b|\bpath\b|\bwhich chunk\b|"
                 r"\bchunk type\b|\bvolume label\b|\bprocess\b|\bexecutable\b", low):
        return _name(q, sel, asked, low, plain)

    # -- the payload itself
    return _payload(q, sel, asked, chans, warm, rx, plain, aid)


def _count(q, st, found, sel, asked, low, text, plain):
    if "chunk" in asked:
        pngs = [d for _, d in unique_files(st.files) if d.startswith(PNG_SIG)]
        named = [d for n, d in unique_files(st.files) if d.startswith(PNG_SIG)
                 and re.search(r"(?<![\w.-])" + re.escape(Path(n.split(ARROW)[-1]).name) + r"(?![\w-])", text)]
        pngs = named or pngs
        if len(pngs) != 1:
            return None
        chunks = png_chunks(pngs[0])
        m = re.search(r"\b([A-Za-z]{4}) chunks?\b", text)
        if m and m.group(1) in {c["type"] for c in chunks} | PNG_STANDARD:
            return plain(sum(1 for c in chunks if c["type"] == m.group(1)))
        if re.search(r"non-?standard|custom|private|unknown|unexpected|extra", low):
            n = sum(1 for c in chunks if not c["standard"])
            return pick("count", "png.nonstandard_chunks", [("not_in_the_png_registry", str(n))]) if _fits(q, n) else None
        if re.search(r"\bhow many chunks\b|\bnumber of chunks\b", low) and not re.search(r"\b(?:that|which|with|whose)\b", low):
            return plain(len(chunks))
        return None
    if "dump" in asked:
        d = [x["info"] for x in sel if x["channel"] == "dump"]
        if len(d) != 1:
            return None
        for word, key in (("module", "modules"), ("thread", "threads"), ("stream", "streams"), ("memory", "memory"),
                          ("region", "memory"), ("note", "notes"), ("mapped file", "files")):
            if re.search(r"\b" + word, low) and key in d[0]:
                return plain(len(d[0][key]))
        return None
    if asked & {"deleted", "fs"}:
        live = [x for x in sel if x["channel"] == "fs"]
        gone = [x for x in sel if x["channel"] == "deleted"]
        if not live and not gone:
            return None
        if re.search(r"\bdirector(?:y|ies)\b|\bfolders?\b", low):
            pool = gone if "deleted" in asked else live
            return plain(sum(1 for x in pool if x.get("is_dir"))) if not re.search(r"\bfiles?\b", low) else None
        if "deleted" in asked and _TOGETHER.search(low):
            return None             # deleted files together with the live ones: which sum is meant is not told
        if "deleted" in asked:
            files_, dirs_ = [x for x in gone if not x.get("is_dir")], [x for x in gone if x.get("is_dir")]
            stale = [x for x in files_ if x.get("stale")]
            if stale:               # a name left behind whose inode is in use: renamed, or a deleted file all the same
                return pick("count", "deleted.stale_names", [(n, v) for n, v in (
                    ("freed_inodes", str(len(files_) - len(stale))), ("with_stale_names", str(len(files_)))) if _fits(q, v)])
            if not dirs_:
                return plain(len(files_))
            return pick("count", "deleted.entries", [("files", str(len(files_))), ("files_and_directories", str(len(gone)))])
        files_ = [x for x in live if not x.get("is_dir")]
        top = [x for x in files_ if "/" not in str(x["name"])]
        if not gone and len(top) == len(files_):
            return plain(len(files_))
        opts = [("live", str(len(files_)))]
        if gone:
            opts.append(("live_and_deleted", str(len(files_) + sum(1 for x in gone if not x.get("is_dir")))))
        if len(top) != len(files_):
            opts.append(("top_level", str(len(top))))
        return pick("count", "fs.files", [(n, v) for n, v in opts if _fits(q, v)])
    if "code" in asked:
        return None
    if asked & {"carved", "trailing"}:
        top = [x for x in sel if x["channel"] in ("carved", "trailing") and x["depth"] == 0 and x["validated"] and x["kind"]]
        members = [x for x in sel if x["channel"] == "member" and x["depth"] == 1]
        if not top:
            return None
        opts = [("carved_items", str(len(top)))]
        if members and len(members) != len(top):
            opts.append(("archive_members", str(len(members))))
        return pick("count", "carved", [(n, v) for n, v in opts if _fits(q, v)])
    return None


def _name(q, sel, asked, low, plain):
    if "recycle" in asked or ("deleted" in asked and any(x["channel"] == "recycle" for x in sel)
                              and not any(x["channel"] == "deleted" for x in sel)):
        paths = _uniq(x["name"] for x in sel if x["channel"] == "recycle")
        if len(paths) != 1:
            return None
        base = re.split(r"[\\/]", paths[0])[-1]
        if re.search(r"\bpath\b|\blocation\b", low):
            return plain(paths[0])
        return pick("name", "recycle.original", [(n, v) for n, v in (("file_name", base), ("full_path", paths[0])) if _fits(q, v)])
    if "deleted" in asked:
        gone = [x for x in sel if x["channel"] == "deleted" and not x.get("is_dir")]
        if len(gone) != 1:
            return None
        x = gone[0]
        if x.get("stale"):          # its inode is in use: the file may only have been renamed
            return pick("name", "deleted.stale", [("name", x["name"].split("/")[-1])] if _fits(q, x["name"].split("/")[-1]) else [])
        path, base, short = x["name"], x["name"].split("/")[-1], x.get("short")
        opts = [("name", base)]
        if path != base:
            opts.append(("path", path))
        if short and short != base:
            opts.append(("short_name", short))
        if x.get("fs", "").startswith("fat") and short == base:
            # no long name survived: the first character of a deleted 8.3 name is gone for good
            return pick("name", "deleted.fat_short", [("underscore", base), ("question_mark", "?" + base[1:]),
                                                      ("without_first", base[1:])])
        opts = [(n, v) for n, v in opts if _fits(q, v)]
        return opts[0][1] if len(opts) == 1 else pick("name", "deleted", opts)
    if "chunk" in asked:
        if not re.search(r"non-?standard|custom|private|unknown|extra|unusual|unexpected|suspicious|hidden|odd|rogue|not part of", low):
            return None
        names = _uniq(x["name"] for x in sel if x["channel"] == "png_chunk")
        return plain(names[0]) if len(names) == 1 else None
    if "dump" in asked:
        d = [x["info"] for x in sel if x["channel"] == "dump"]
        if len(d) != 1:
            return None
        if d[0].get("process"):
            return plain(d[0]["process"])
        mods = d[0].get("modules") or []
        if mods and mods[0].get("name"):
            full = mods[0]["name"]
            return pick("name", "minidump.first_module", [("file_name", re.split(r"[\\/]", full)[-1]), ("full_path", full)])
        return None
    if "fs" in asked and re.search(r"\bvolume label\b|\blabel\b", low):
        infos = [x.get("fsinfo") or {} for x in sel if x["channel"] in ("fs", "deleted")]
        # FAT keeps the label twice; the root directory's entry is the one tools change
        labels_ = _uniq(v for i in infos for v in (i.get("dir_label"), i.get("label")) if v and v != "NO NAME")
        if len(labels_) == 2 and len({id(i) for i in infos}) == 1:
            return pick("name", "fat.label", [(n, v) for n, v in (("root_directory", labels_[0]), ("boot_sector", labels_[1]))
                                              if _fits(q, v)])
        return plain(labels_[0]) if len(labels_) == 1 else None
    if asked & {"carved", "trailing"}:
        members = _uniq(x["name"] for x in sel if x["channel"] == "member" and x["depth"] == 1)
        if len(members) != 1:
            return None
        base = members[0].split("/")[-1]
        return plain(base) if base == members[0] else pick("name", "member", [("file_name", base), ("path", members[0])])
    return None


_CONTENT = re.compile(r"\b(?:say|says|said|spell\w*|reads?|messages?|text|flag|payload|contents?|secret|password|passphrase|digits?|"
                      r"keys?|phone number|string|value|comment|decod\w+|recover\w*|extract\w*|scan\w*|hidden|url|link|"
                      r"dial\w*|contain\w*|hold\w*|carr(?:y|ies|ied)|stored|written|embedded|appended|encod\w+)\b", re.I)
_MEASURE = re.compile(r"\bhow (?:many|much|long|large|big|wide|tall)\b|\bnumber of\b|(?<!zero-)(?<!zero )\bwidth\b|"
                      r"\b(?:count|size|length|height|dimensions?|"
                      r"resolution|offset|crc|checksum|hash|entropy|ratio|percent\w*|version|duration|sample rate|bit depth|"
                      r"colou?r type|frames?|channels|when|date|time(?:stamp)?)\b", re.I)


def _payload(q, sel, asked, chans, warm, rx, plain, aid):
    words = " ".join(str(x or "") for x in (q.get("question"), _fmt(q).get("syntax")))
    if not warm and (not _CONTENT.search(words) or _MEASURE.search(words)):
        return None
    live = {"fs"} if rx and "fs" in asked else set()        # a live file's text counts only under the question's pattern
    texts = [(x, x["text"]) for x in sel if x["text"] and x["channel"] in _PAYLOAD_CHANNELS | live and x["validated"]]
    if rx:
        hits = []
        for x, t in texts:
            for v in _pattern_hits(rx, t):
                hits.append((x, v))
        values = _uniq(v for _, v in hits)
        if len(values) == 1:
            return values[0]
        return None
    if not texts:
        return None
    # one payload only: the same text reached twice (a trailing zip and its member) is one
    best = {}
    for x, t in texts:
        best.setdefault(t.strip(), x)
    # a container and what was read out of it are one item: drop a text that only wraps another
    values = [v for v in best if v]
    if len(values) != 1:
        return None
    value, x = values[0], best[values[0]]
    lines = [ln.strip() for ln in value.splitlines() if ln.strip()]
    channel = x["channel"]
    if warm:
        opts = [("last_line", lines[-1]), ("whole", value)] if lines else []
        return pick("message", f"{KEY}.{channel}", opts, lane="warmups")
    named = asked - {"hidden", "carved"}
    direct = bool(named) and channel in set().union(*(_CHANNELS_OF[a] for a in named))
    if direct and channel == "dtmf" and not value.isdigit():
        return pick("payload", "dtmf", [(n, v) for n, v in (("keys", value), ("digits_only", re.sub(r"\D", "", value))) if v and _fits(q, v)])
    if channel == "png_text" and direct:
        key = str(x.get("name") or "").lower()
        # 'Software: matplotlib' is no comment: the keyword must be one, or be named by the question
        direct = key in ("comment", "comments", "description") or (len(key) > 2 and re.search(r"\b" + re.escape(key) + r"\b", words.lower()) is not None)
    if direct and len(lines) == 1 and channel in ("code", "dtmf", "comment", "png_text", "zero_width", "whitespace"):
        return plain(value)
    opts = [("text", value)]
    if len(lines) > 1:
        opts += [("last_line", lines[-1]), ("first_line", lines[0])]
    if flagfmt.TEXT.fullmatch(value):
        opts.append(("inside_braces", value.split("{", 1)[1][:-1]))
    return pick("payload", channel, [(n, v) for n, v in opts if _fits(q, v)])


def solve_set(questions, files, ctx) -> dict:
    """The runner contract. A question that names none of this toolkit's channels costs nothing and
    is None; the files are read once, on the first question that does, within BUDGET seconds."""
    attempt = (ctx or {}).get("attempt")
    untimed = isinstance(attempt, dict) and bool(attempt) and not attempt.get("deadline")
    st = _State(files, time.monotonic() + float((ctx or {}).get("carve_stego_budget") or (BUDGET_UNTIMED if untimed else BUDGET)))
    out = {}
    partial = ctx.get("partial") if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict) else None
    for q in questions:
        qid = q.get("qid") or q.get("id")
        try:
            out[qid] = answer(q, st)
        except Exception:           # a fact that cannot be read is no answer
            out[qid] = None
        if partial is not None and out[qid] is not None:
            partial[qid] = out[qid]
    return out


# ---- signals ----------------------------------------------------------------------------------------

# What a file name's extension promises, for the names a picture or a recording is disguised under.
_EXT_KIND = {"png": "png", "jpg": "jpeg", "jpeg": "jpeg", "jpe": "jpeg", "gif": "gif", "bmp": "bmp", "webp": "webp", "tif": "tiff",
             "tiff": "tiff", "wav": "wav", "mp3": "mp3", "mp4": "mp4", "ogg": "ogg", "flac": "flac", "m4a": "mp4", "avi": "avi",
             "pdf": "pdf", "txt": "text", "doc": "ole", "docx": "zip", "zip": "zip", "exe": "pe", "dll": "pe", "bin": None, "dat": None}
_EXT_KIND = {k: v for k, v in _EXT_KIND.items() if v}


def signals(questions, files) -> float:
    """0..1: how strongly the questions and the delivery look like carving or steganography. Cheap:
    the questions' words and each file's structure (its end, its chunks, its magic), a picture or
    recording named as another type (0.3), and the codes of at most four pictures of 2 MB or less
    inside one second (a picture that is a QR code or a barcode: 0.5). Halved, and at most 0.2,
    when a known lane's marks are there."""
    score = 0.0
    strong = weak = 0
    for q in questions or []:
        asked = channels_asked(q)
        strong += bool(asked - {"hidden", "comment", "chunk", "fs"})
        weak += bool(asked & {"hidden", "comment", "chunk", "fs"}) and not (asked - {"hidden", "comment", "chunk", "fs"})
    n = max(1, len(questions or []))
    if strong:
        score += 0.45 + 0.3 * min(1.0, strong / n)
    elif weak:
        score += 0.15 + 0.15 * min(1.0, weak / n)
    evidence = 0.0
    media = coded = 0
    t_codes = time.monotonic() + 1.0
    for name, data in unique_files(files or {})[:200]:
        kind = sniff(data)
        if kind in IMAGE_KINDS or kind == "wav":
            media += 1
            ext = Path(name.split(ARROW)[-1]).suffix.lower().lstrip(".")
            if ext and ext in _EXT_KIND and _EXT_KIND[ext] != kind:
                evidence = max(evidence, 0.3)       # a picture or a recording under another type's name
            if kind in IMAGE_KINDS and coded < 4 and len(data) <= (2 << 20) and time.monotonic() < t_codes:
                coded += 1                          # a picture that IS a code is this toolkit's, whatever is asked
                try:
                    if decode_codes(data, planes=False, max_frames=1, deadline=t_codes):
                        evidence = max(evidence, 0.5)
                except Exception:
                    pass
            _, end = primary(data)
            if end and end < len(data) and data[end:].strip(b"\x00\r\n\t "):
                evidence = max(evidence, 0.3)
            if kind == "png" and any(not c["standard"] or not c["crc_ok"] for c in png_chunks(data)[:2000]):
                evidence = max(evidence, 0.3)
        elif kind in ("iso9660", "ext", "cpio", "fat12", "fat16", "fat32", "uimage", "minidump"):
            evidence = max(evidence, 0.3)
        elif kind == "data" and len(data) >= 1024 and data[510:512] == b"\x55\xaa" and (
                data[3:11] in (b"NTFS    ", b"EXFAT   ") or fs.partitions(data)):
            evidence = max(evidence, 0.3)           # a partitioned disk, or a volume this toolkit names but does not read
        elif kind == "text" and len(data) < (1 << 20):
            t = as_text(data) or ""
            if any(c in ZERO_WIDTH for c in t[1:]) or any(0xE0020 <= ord(c) <= 0xE007E for c in t):
                evidence = max(evidence, 0.3)
            elif set(t) & set("█▀▄") and text_grid(t):
                evidence = max(evidence, 0.3)
    if media and not evidence:
        evidence = 0.1
    score += evidence
    try:
        if _tri().lane_signals(questions or [], files or {}):
            score = min(score * 0.5, 0.2)       # a known lane's own marks: its solver's business first
    except Exception:
        pass
    return round(max(0.0, min(1.0, score)), 3)


# ---- the command ------------------------------------------------------------------------------------

def read_paths(paths) -> dict:
    files = {}
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for c in sorted(p.rglob("*")):
                if c.is_file():
                    files[str(c.relative_to(p))] = c.read_bytes()
        else:
            files[p.name] = p.read_bytes()
    return files


def _clip(v, n=100) -> str:
    s = v if isinstance(v, str) else repr(v)
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= n else s[:n - 3] + "..."


def report(files: dict, deep: bool = True, lsb_passphrases=(), lsb_seeds=()) -> list:
    """Per file: {name, size, kind, end, sha256, chunks, segments, wav, findings}."""
    out = []
    for name, data in unique_files(files):
        kind, end = primary(data)
        row = {"name": name, "size": len(data), "kind": kind, "end": end, "sha256": hashlib.sha256(data).hexdigest()}
        if kind == "png":
            row["chunks"] = [{k: c[k] for k in ("type", "offset", "length", "crc_ok", "standard", "after_iend")} for c in png_chunks(data)]
            if len(data) >= 29:
                row["ihdr"] = dict(zip(("width", "height", "depth", "color_type"), struct.unpack(">IIBB", data[16:26])))
        elif kind == "jpeg":
            row["segments"] = [{k: v for k, v in s.items() if k != "data"} for s in jpeg_segments(data)]
        elif kind == "gif":
            row["gif"] = gif_blocks(data)
        elif kind == "wav":
            row["wav"] = wav_info(data)
        row["findings"] = scan(name.split(ARROW)[-1], data, deep)
        # Keyed permutations are opt-in: only exact keys explicitly provided by the player are tried.
        if deep and (lsb_passphrases or lsb_seeds) and kind in ("png", "bmp", "gif", "webp"):
            px = {"png": png_pixels, "bmp": bmp_pixels, "gif": gif_pixels, "webp": webp_pixels}[kind](data)
            if px:
                seen = {f.get("text") if f.get("text") is not None else f.get("data")
                        for f in row["findings"] if f.get("channel") == "lsb"}
                for hit in lsb_deep_scan(px, passphrases=lsb_passphrases, seeds=lsb_seeds,
                                         seen=seen, include_unkeyed=False):
                    row["findings"].append(_finding(
                        "lsb", name.split(ARROW)[-1], hit["method"], text=hit["text"], data=hit["data"],
                        kind=hit["kind"] or "text"))
        out.append(row)
    return out


def print_report(rows: list):
    for r in rows:
        end = "" if r["end"] in (None, 0) else f", own structure ends at {r['end']:#x}" + (" (the end of the file)" if r["end"] >= r["size"] else "")
        print(f"== {r['name']}: {r['kind']}, {r['size']} bytes{end}")
        print(f"   sha256 {r['sha256']}")
        if "ihdr" in r:
            print(f"   IHDR {r['ihdr']['width']}x{r['ihdr']['height']} depth {r['ihdr']['depth']} colour type {r['ihdr']['color_type']}")
        if "chunks" in r:
            from collections import Counter
            counts = Counter(c["type"] for c in r["chunks"])
            print("   chunks: " + " ".join(f"{t}x{n}" if n > 1 else t for t, n in counts.items()))
        if "segments" in r:
            print("   segments: " + " ".join(s["name"] + (f"[{s['ident']}]" if s.get("ident") else "") for s in r["segments"][:40]))
        if r.get("wav"):
            w = r["wav"]
            print(f"   wav: format {w['format']} {w['channels']} ch {w['rate']} Hz {w['bits']} bit, data {w['data_size']} bytes; "
                  "chunks " + " ".join(c["id"].strip() for c in w["chunks"]))
        if r.get("gif"):
            print(f"   gif: {r['gif']['frames']} frames, {len(r['gif']['comments'])} comments")
        if not r["findings"]:
            print("   no finding")
        for f in r["findings"]:
            bits = [f"[{f['channel']}]", f["method"]]
            if f.get("name") and f["channel"] not in ("png_chunk",):
                bits.append(f"name={_clip(f['name'], 60)}")
            if f.get("kind"):
                bits.append(f"kind={f['kind']}")
            if f.get("data") is not None:
                bits.append(f"{len(f['data'])} bytes sha256={hashlib.sha256(f['data']).hexdigest()[:16]}")
            if not f["validated"]:
                bits.append("NOT VALIDATED")
            if f.get("fix"):
                bits.append(f"IHDR CRC fits {f['fix'][0]}x{f['fix'][1]}")
            print("   " + "  " * f["depth"] + " ".join(bits))
            if f.get("text"):
                print("   " + "  " * f["depth"] + "    text: " + _clip(f["text"], 160))


def main(argv) -> int:
    usage = ("usage: carve_stego.py <file>... [--json] [--extract DIR] [--quick] "
             "[--lsb-passphrase TEXT] [--lsb-seed INT]")
    work = list(argv)
    extract, passphrases, seeds = None, [], []

    def take_values(flag):
        values = []
        while flag in work:
            i = work.index(flag)
            if i + 1 >= len(work):
                raise ValueError(f"{flag} requires a value")
            values.append(work[i + 1])
            del work[i:i + 2]
        prefix = flag + "="
        for item in list(work):
            if item.startswith(prefix):
                values.append(item[len(prefix):])
                work.remove(item)
        return values

    try:
        extracts = take_values("--extract")
        if len(extracts) > 1:
            raise ValueError("--extract may be given once")
        extract = Path(extracts[0]) if extracts else None
        passphrases = take_values("--lsb-passphrase")
        if len(passphrases) > 16:
            raise ValueError("at most 16 explicitly supplied passphrases are accepted")
        seed_values = take_values("--lsb-seed")
        if len(seed_values) > 16:
            raise ValueError("at most 16 explicitly supplied seeds are accepted")
        for value in seed_values:
            try:
                seed = int(value, 0)
            except ValueError as exc:
                raise ValueError(f"invalid --lsb-seed {value!r}") from exc
            if not 0 <= seed < (1 << 256):
                raise ValueError("--lsb-seed must be in 0..2^256-1")
            seeds.append(seed)
        args = [a for a in work if not a.startswith("--")]
        if not args:
            raise ValueError(usage)
        missing = [a for a in args if not Path(a).exists()]
        if missing:
            raise ValueError(f"no such file: {', '.join(missing)}")
        files = read_paths(args)
        deep = "--quick" not in argv
        rows = report(files, deep, passphrases, seeds)
    except (ValueError, OSError, MemoryError) as exc:
        print(f"carve_stego.py: {exc}", file=sys.stderr)
        return 2
    if "--json" in argv:
        def clean(o):
            if isinstance(o, (bytes, bytearray)):
                return {"bytes": len(o), "sha256": hashlib.sha256(o).hexdigest(), "head_hex": bytes(o[:32]).hex()}
            if isinstance(o, dict):
                return {str(k): clean(v) for k, v in o.items()}
            if isinstance(o, (list, tuple)):
                return [clean(v) for v in o]
            return o
        print(json.dumps(clean(rows), indent=1, ensure_ascii=False))
    else:
        print_report(rows)
        print(f"CARVE_STEGO files={len(rows)} findings={sum(len(r['findings']) for r in rows)} "
              f"signals={signals([], files)}")
    if extract is not None:
        extract.mkdir(parents=True, exist_ok=True)
        n = 0
        for key, body in carved_files(files, deep).items():
            safe = re.sub(r"[^A-Za-z0-9._@#-]+", "_", key.replace(ARROW, "__"))[:180]
            (extract / safe).write_bytes(body)
            n += 1
        print(f"EXTRACTED {n} members to {extract}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
