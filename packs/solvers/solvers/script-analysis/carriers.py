#!/usr/bin/env python3
"""Binary carriers of a script, read as the containers they are (round 2 of the Day 9 preparation, 2026-10-08).

Usage:
  .venv/bin/python solvers/script-analysis/carriers.py <file> [...]     what each file holds, and makes no request

Until now a carrier that is no text file (a .chm, a .one, a .lnk, a compiled AutoIt or AutoHotkey script) was
read as the runs of printable characters it holds (analyze.strings_view). A run ends wherever the bytes around
it end it, so whatever was read that way has no proven last value (generic.read: loose_lines), and a script
that the container stores compressed or encoded is not in the strings at all. Here each container is read by
its own tables, and what it holds is handed on as the file it is:

  chm     ITSF / ITSP / PMGL: the directory, the files of section 0 as stored, and the files of the
          MSCompressed section through its LZXC control data and reset table (lzx_decode below: verbatim,
          aligned-offset and uncompressed blocks, frames of 32 KB, a reset every interval)
  one     a OneNote section: every FileDataStoreObject between its header and footer GUIDs (an embedded
          .hta, .vbs, .bat, .wsf, .js is stored so, whole)
  lnk     a shell link: the strings of its StringData (name, relative path, working directory, command-line
          arguments, icon location), each by its counted length, and the environment-variable target
  au3     a compiled AutoIt script (.a3x, or the script resource of an AutoIt executable): the EA05 / EA06
          container decrypted and inflated and its tokens written out as source text, by the autoit-ripper
          package (plain Python; nothing of the specimen is run). Its JB01 form holds an AutoHotkey script
  ahk     a compiled AutoHotkey executable: the RCDATA resource `>AUTOHOTKEY SCRIPT<` (the script as text)
  scpt    a compiled AppleScript (FasdUAS): its strings, UTF-16BE ones too (no container table is read, so
          this one stays a strings view: loose)

inner(name, data) returns (kind, [(inner name, bytes)], notes, loose) or None for a file that is none of
these. analyze.container_view hands a specimen to the general path as its inner file only when exactly one
plan is read from what the container holds; anything else is read as before.

Everything is bounded: an input over CARRIER_MAX is not read, at most INNER_MAX bytes are produced, and the
LZX and AutoIt decoders stop at a deadline (BUDGET seconds) and give nothing. A reader that fails gives
nothing; no answer is ever made here.
"""
import struct
import sys
import time
from pathlib import Path

CARRIER_MAX = 32 << 20       # bytes of a carrier that is read at all
INNER_MAX = 8 << 20          # bytes of inner files produced from one carrier
LZX_MAX = 1 << 20            # bytes of a compressed section that are decoded (0.3 s a megabyte, measured on
                             # literal-only frames, the slowest kind): a larger section is not read at all
BUDGET = 1.5                 # seconds one carrier may take (a clock can reach this; the sizes bind first)


class Incomplete(ValueError):
    """A container of which not everything could be read. Review of round 2 (2026-10-08): analyze.container_view
    calls a plan THE plan of a container only when it is the one plan in all the container holds, so a reader
    that leaves a file out (too large, too many, a section that does not decode, a size past the end) gives
    nothing, and the file is read as before."""
ENTRIES_MAX = 4096
TEXT_NAMES = (".htm", ".html", ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".bat", ".cmd", ".txt",
              ".hhc", ".hhk", ".xml", ".css", ".php", ".py", ".sh", ".au3", ".ahk", ".lua", ".rb", ".pl", ".json")


class Timeout(Exception):
    pass


# ---------------------------------------------------------------------------- LZX (as CHM uses it)

LZX_FRAME = 32768
_EXTRA = [0, 0, 0, 0] + [b for n in range(1, 17) for b in (n, n)] + [17] * 256
_BASE = [0]
for _b in _EXTRA[:-1]:
    _BASE.append(_BASE[-1] + (1 << _b))
_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50, 22: 66, 23: 98, 24: 162, 25: 290}


class _Bits:
    """LZX's bit reader: 16-bit little-endian words, most significant bit first."""

    def __init__(self, data: bytes):
        self.data, self.at, self.buf, self.n = data, 0, 0, 0

    def need(self, n):
        while self.n < n:
            word = int.from_bytes(self.data[self.at:self.at + 2].ljust(2, b"\0"), "little")
            if self.at > len(self.data) + 4:
                raise ValueError("LZX: read past the end")
            self.at += 2
            self.buf = (self.buf << 16) | word
            self.n += 16

    def read(self, n):
        if n == 0:
            return 0
        self.need(n)
        self.n -= n
        v = (self.buf >> self.n) & ((1 << n) - 1)
        self.buf &= (1 << self.n) - 1
        return v

    def peek16(self):
        self.need(16)
        return (self.buf >> (self.n - 16)) & 0xFFFF

    def drop(self, n):
        self.n -= n
        self.buf &= (1 << self.n) - 1

    def align(self):
        """To the next 16-bit word (nothing when already on one)."""
        self.drop(self.n & 15)

    def align_uncompressed(self):
        """Before an uncompressed block: 1 to 16 bits of padding. Returns the byte offset that follows."""
        if self.n & 15 == 0 and self.n == 0:
            self.need(16)
        self.buf, self.n = 0, 0
        return self.at


def _table(lengths):
    """(table, bits): a lookup of `bits` leading bits -> (symbol, length) for a canonical code, None when the
    lengths give no code."""
    top = max(lengths) if lengths else 0
    if top == 0:
        return None, 0
    table = [None] * (1 << top)
    code = 0
    for n in range(1, top + 1):
        for sym, ln in enumerate(lengths):
            if ln != n:
                continue
            lo = code << (top - n)
            hi = lo + (1 << (top - n))
            if hi > len(table):
                raise ValueError("LZX: an over-subscribed code")
            table[lo:hi] = [(sym, n)] * (hi - lo)
            code += 1
        code <<= 1
    return table, top


def _sym(bits, table, top):
    entry = table[bits.peek16() >> (16 - top)]
    if entry is None:
        raise ValueError("LZX: a code that is not in the tree")
    bits.drop(entry[1])
    return entry[0]


def _lengths(bits, lens, first, last):
    pre = [bits.read(4) for _ in range(20)]
    table, top = _table(pre)
    if table is None:
        raise ValueError("LZX: an empty pretree")
    x = first
    while x < last:
        z = _sym(bits, table, top)
        if z == 17:
            run = min(bits.read(4) + 4, last - x)
            lens[x:x + run] = [0] * run
            x += run
        elif z == 18:
            run = min(bits.read(5) + 20, last - x)
            lens[x:x + run] = [0] * run
            x += run
        elif z == 19:
            run = min(bits.read(1) + 4, last - x)
            z = (lens[x] - _sym(bits, table, top)) % 17
            lens[x:x + run] = [z] * run
            x += run
        else:
            lens[x] = (lens[x] - z) % 17
            x += 1


def lzx_decode(data: bytes, window_bits: int, reset_frames: int, length: int, deadline=None) -> bytes:
    """`length` bytes of an LZX stream as a CHM stores it (see the module text). ValueError for a stream
    that does not decode, Timeout past the deadline."""
    slots = _SLOTS.get(window_bits)
    if slots is None or length < 0 or length > INNER_MAX:
        raise ValueError("LZX: a window or a length this reader does not take")
    main_n = 256 + slots * 8
    out = bytearray()
    bits = _Bits(data)
    r0 = r1 = r2 = 1
    main_len, len_len = [0] * main_n, [0] * 249
    main = lent = aligned = None
    main_top = len_top = al_top = 0
    block_type, block_left, block_len, header = 0, 0, 0, False
    frame = 0
    while len(out) < length:
        if deadline is not None and time.perf_counter() > deadline:
            raise Timeout("LZX")
        if reset_frames and frame % reset_frames == 0:
            r0 = r1 = r2 = 1
            main_len, len_len = [0] * main_n, [0] * 249
            block_left, block_type, header = 0, 0, False
        if not header:
            if bits.read(1):
                bits.read(16)
                bits.read(16)           # the size of an x86 call translation: not applied (text is not touched by it)
            header = True
        frame_end = min(length, len(out) + LZX_FRAME)
        while len(out) < frame_end:
            if block_left == 0:
                if block_type == 3 and block_len & 1:
                    bits.at += 1
                block_type = bits.read(3)
                block_len = block_left = (bits.read(16) << 8) | bits.read(8)
                if block_type == 2:
                    aligned, al_top = _table([bits.read(3) for _ in range(8)])
                if block_type in (1, 2):
                    _lengths(bits, main_len, 0, 256)
                    _lengths(bits, main_len, 256, main_n)
                    main, main_top = _table(main_len)
                    _lengths(bits, len_len, 0, 249)
                    lent, len_top = _table(len_len)
                    if main is None:
                        raise ValueError("LZX: an empty main tree")
                elif block_type == 3:
                    at = bits.align_uncompressed()
                    r0, r1, r2 = struct.unpack_from("<III", data, at)
                    bits.at = at + 12
                else:
                    raise ValueError("LZX: a block type that is none")
            run = min(block_left, frame_end - len(out))
            block_left -= run
            if block_type == 3:
                chunk = data[bits.at:bits.at + run]
                if len(chunk) != run:
                    raise ValueError("LZX: an uncompressed block past the end")
                out += chunk
                bits.at += run
                continue
            stop = len(out) + run
            while len(out) < stop:
                sym = _sym(bits, main, main_top)
                if sym < 256:
                    out.append(sym)
                    continue
                sym -= 256
                n = sym & 7
                if n == 7:
                    if lent is None:
                        raise ValueError("LZX: a length from an empty tree")
                    n += _sym(bits, lent, len_top)
                n += 2
                slot = sym >> 3
                if slot == 0:
                    off = r0
                elif slot == 1:
                    off, r1 = r1, r0
                    r0 = off
                elif slot == 2:
                    off, r2 = r2, r0
                    r0 = off
                else:
                    extra = _EXTRA[slot]
                    if block_type == 2 and extra >= 3:
                        off = _BASE[slot] - 2 + (bits.read(extra - 3) << 3)
                        if aligned is None:
                            raise ValueError("LZX: an aligned offset from an empty tree")
                        off += _sym(bits, aligned, al_top)
                    else:
                        off = _BASE[slot] - 2 + bits.read(extra)
                    if off <= 0:
                        off = 1
                    r2, r1, r0 = r1, r0, off
                start = len(out) - off
                if start < 0:
                    raise ValueError("LZX: a match before the start")
                if off >= n:
                    out += out[start:start + n]
                else:
                    for i in range(n):
                        out.append(out[start + i])
            over = len(out) - stop
            if over:
                if over > block_left:
                    raise ValueError("LZX: a match past its block")
                block_left -= over
        if len(out) > frame_end and len(out) < length:
            raise ValueError("LZX: a match past its frame")
        bits.align()
        frame += 1
    return bytes(out[:length])


# ---------------------------------------------------------------------------- CHM

def _encint(data, at):
    v = 0
    for _ in range(10):
        b = data[at]
        at += 1
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, at
    raise ValueError("CHM: an ENCINT that does not end")


def chm_directory(data: bytes) -> tuple:
    """(entries, content offset): [(name, section, offset, length)] of an ITSF file's directory."""
    if data[:4] != b"ITSF" or len(data) < 0x60:
        raise ValueError("not ITSF")
    version, head_len = struct.unpack_from("<II", data, 4)
    dir_off, dir_len = struct.unpack_from("<QQ", data, 0x48)
    content = struct.unpack_from("<Q", data, 0x58)[0] if version >= 3 and head_len >= 0x60 else dir_off + dir_len
    if data[dir_off:dir_off + 4] != b"ITSP":
        raise ValueError("CHM: no ITSP directory")
    itsp_len, _, chunk = struct.unpack_from("<III", data, dir_off + 8)
    count = struct.unpack_from("<I", data, dir_off + 0x2C)[0]
    if not 0x40 <= chunk <= 1 << 20:
        raise ValueError("CHM: a chunk size this reader does not take")
    entries, files = [], 0
    for i in range(min(count, 1 << 16)):
        at = dir_off + itsp_len + i * chunk
        if at + chunk > len(data):
            raise Incomplete("CHM: a directory chunk past the end")
        if data[at:at + 4] != b"PMGL":
            continue                                # an index chunk (PMGI) lists no file
        free = struct.unpack_from("<I", data, at + 4)[0]
        end, p = at + chunk - free, at + 0x14
        while p < end:
            n, p = _encint(data, p)
            if n == 0 or p + n > end:
                break
            name = data[p:p + n].decode("utf-8", "replace")
            p += n
            section, p = _encint(data, p)
            offset, p = _encint(data, p)
            length, p = _encint(data, p)
            if name.startswith("::"):
                entries.append((name, section, offset, length))     # the storage's own streams: always kept
            elif files < ENTRIES_MAX:
                files += 1
                entries.append((name, section, offset, length))
            else:
                raise Incomplete(f"CHM: more than {ENTRIES_MAX} files")
    if count > 1 << 16:
        raise Incomplete("CHM: more directory chunks than are read")
    return entries, content


def chm_files(data: bytes, deadline=None) -> list:
    """[(name, bytes)] of the files a CHM holds (its `::` system streams and `/#` tables left out)."""
    entries, content = chm_directory(data)
    by_name = {name: (section, offset, length) for name, section, offset, length in entries}

    def stored(name):
        if name not in by_name or by_name[name][0] != 0:
            return None
        _, offset, length = by_name[name]
        return data[content + offset:content + offset + length]

    section1 = None
    wanted = [(n, s, o, ln) for n, s, o, ln in entries
              if n.startswith("/") and not n.startswith(("/#", "/$")) and not n.endswith("/") and ln]
    if any(s == 1 for _, s, _, _ in wanted):
        control = stored("::DataSpace/Storage/MSCompressed/ControlData")
        stream = stored("::DataSpace/Storage/MSCompressed/Content")
        table = stored("::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/"
                       "InstanceData/ResetTable")
        if control and stream is not None and len(control) >= 0x18 and control[4:8] == b"LZXC":
            ver, reset, window = struct.unpack_from("<III", control, 8)
            if ver == 2:
                reset, window = reset * LZX_FRAME, window * LZX_FRAME
            bits = window.bit_length() - 1
            total = max((o + ln for _, s, o, ln in wanted if s == 1), default=0)
            if table and len(table) >= 0x28:
                total = min(max(total, 0), struct.unpack_from("<Q", table, 0x10)[0])
            if total > LZX_MAX:
                raise Incomplete(f"CHM: a compressed section of {total} bytes, more than is decoded")
            if 1 << bits == window and 0 < total and len(stream) <= CARRIER_MAX:
                section1 = lzx_decode(stream, bits, max(1, reset // LZX_FRAME) if reset else 0, total, deadline)
    out, size = [], 0
    for name, section, offset, length in wanted:
        if section == 0:
            blob = data[content + offset:content + offset + length]
        elif section == 1 and section1 is not None:
            blob = section1[offset:offset + length]
        else:
            raise Incomplete(f"CHM: {name[:40]!r} is in a section that was not read")
        if len(blob) != length:
            raise Incomplete(f"CHM: {name[:40]!r} ends past its section")
        size += length
        if size > INNER_MAX:
            raise Incomplete("CHM: more bytes than are read")
        out.append((name.lstrip("/"), blob))
    return out


# ---------------------------------------------------------------------------- OneNote

ONE_HEAD = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")          # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
ONETOC_HEAD = bytes.fromhex("a12fff43d9ef764c9ee210ea5722765f")
FDSO_HEAD = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")         # {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
FDSO_FOOT = bytes.fromhex("22a7fb71790f0b4abb13899256426b24")         # {71FBA722-0F79-4A0B-BB13-899256426B24}


def onenote_files(data: bytes) -> list:
    """[(name, bytes)] of the files embedded in a OneNote section: each FileDataStoreObject whose length
    field leads to its footer GUID. The store keeps no file name beside the bytes, so each is named by what
    its first bytes are (sniffed_name)."""
    out, at, size = [], 0, 0
    while True:
        at = data.find(FDSO_HEAD, at)
        if at < 0:
            break
        if len(out) >= ENTRIES_MAX:
            raise Incomplete(f"OneNote: more than {ENTRIES_MAX} embedded files")
        try:
            length = struct.unpack_from("<Q", data, at + 16)[0]
        except struct.error:
            break
        start = at + 36
        end = start + length
        pad = (8 - (36 + length) % 8) % 8        # the object, header and all, ends on an 8-byte boundary
        if length and end + pad + 16 <= len(data) and data[end + pad:end + pad + 16] == FDSO_FOOT:
            size += length
            if size > INNER_MAX:
                raise Incomplete("OneNote: more embedded bytes than are read")
            out.append((sniffed_name(data[start:end], len(out)), data[start:end]))
            at = end
        else:
            at += 16
    return out


def sniffed_name(blob: bytes, n: int) -> str:
    """A name for an embedded file that has none: `embedded-<n>.<ext>` by its first bytes."""
    head = blob[:512].lstrip(b"\xef\xbb\xbf\xff\xfe \t\r\n").replace(b"\0", b"").lower()
    ext = "bin"
    if blob[:2] == b"MZ":
        ext = "exe"
    elif blob[:4] == b"PK\x03\x04":
        ext = "zip"
    elif blob[:8] == b"\x89PNG\r\n\x1a\n":
        ext = "png"
    elif blob[:3] == b"\xff\xd8\xff":
        ext = "jpg"
    elif blob[:4] == b"L\0\0\0":
        ext = "lnk"
    elif head.startswith((b"<job", b"<package", b"<?xml")) and b"<job" in blob[:4096].replace(b"\0", b"").lower():
        ext = "wsf"
    elif b"<hta:application" in blob[:8192].replace(b"\0", b"").lower():
        ext = "hta"
    elif head.startswith((b"<html", b"<!doctype html", b"<script", b"<head")):
        ext = "hta" if b"<hta:" in blob.replace(b"\0", b"").lower() else "html"
    elif head.startswith((b"@echo", b"rem ", b"::", b"setlocal")):
        ext = "bat"
    elif head.startswith(b"<?php"):
        ext = "php"
    elif head.startswith(b"#!"):
        ext = "sh"
    elif b"\0" not in blob[:4096] or blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        ext = "txt"
    return f"embedded-{n}.{ext}"


# ---------------------------------------------------------------------------- shell link

LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
_LNK_STRINGS = ((0x04, "name"), (0x08, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"),
                (0x40, "icon_location"))


def lnk_strings(data: bytes) -> list:
    """[(what, text)] of a shell link's StringData, each by its counted length, and the environment-variable
    target of its extra data. ValueError for a file that is no shell link."""
    if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C or data[4:20] != LNK_CLSID:
        raise ValueError("not a shell link")
    flags = struct.unpack_from("<I", data, 0x14)[0]
    at = 0x4C
    if flags & 0x01:
        at += 2 + struct.unpack_from("<H", data, at)[0]
    if flags & 0x02:
        at += struct.unpack_from("<I", data, at)[0]
    wide, out = bool(flags & 0x80), []
    for bit, what in _LNK_STRINGS:
        if not flags & bit:
            continue
        count = struct.unpack_from("<H", data, at)[0]
        at += 2
        raw = data[at:at + count * (2 if wide else 1)]
        if len(raw) != count * (2 if wide else 1):
            raise ValueError("a shell link string past the end")
        at += len(raw)
        out.append((what, raw.decode("utf-16-le" if wide else "cp1252", "replace")))
    while at + 8 <= len(data):
        size, sig = struct.unpack_from("<II", data, at)
        if size < 4:
            break
        if sig == 0xA0000001 and size >= 0x314:                    # EnvironmentVariableDataBlock
            wide_target = data[at + 8 + 260:at + 8 + 260 + 520].decode("utf-16-le", "replace").split("\0", 1)[0]
            ansi_target = data[at + 8:at + 8 + 260].split(b"\0", 1)[0].decode("cp1252", "replace")
            if wide_target or ansi_target:
                out.append(("env_target", wide_target or ansi_target))
        at += size
    return out


# ---------------------------------------------------------------------------- AutoIt, AutoHotkey

AU3_MAGIC = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d")
AU3_SCRIPT_MAX = 1 << 18     # bytes of one stored script that are decrypted (the keystream is plain Python:
                             # 0.1 s per 100 KB of an EA06 script, measured 2026-10-08)
AU3_OUT_MAX = 1 << 19        # bytes one stored script may inflate to (the package's inflater is plain Python too)


AU3_NAME_MAX = 4096          # characters of a stored file's type or name


def _au3_string(stream, decryptor, keys) -> str:
    """A counted, encrypted string of the container (the package's read_string, with a bound on the count:
    the count is the file's own word, and the keystream is paid for every byte of it)."""
    n = stream.u32() ^ keys[0]
    if n > AU3_NAME_MAX:
        raise Incomplete("AutoIt: a name longer than any name is")
    raw = decryptor.decrypt(stream.get_bytes(n << 1 if decryptor.au3_Unicode else n), n + keys[1])
    try:
        return raw.decode("utf-16" if decryptor.au3_Unicode else "utf-8")
    except UnicodeDecodeError:
        raise Incomplete("AutoIt: a name that is no text") from None


_AU3_LENGTHS = ((3, 2, 3), (6, 3, 7), (13, 5, 31), (44, 8, 255), (299, 8, 255))


def au3_inflate(blob: bytes, limit: int = None, deadline=None) -> bytes:
    """An EA05/EA06 compressed script inflated (the package's decompress_default, rewritten with bounds: the
    package's own trusts the size word of the blob up to 10 MB, copies the whole output at an offset of 0 and
    cannot be stopped). Incomplete for a stream that is not one or says more than `limit`, Timeout past the
    deadline."""
    limit = AU3_OUT_MAX if limit is None else limit
    magic, size = blob[:4], int.from_bytes(blob[4:8], "big")
    if magic not in (b"EA05", b"EA06") or len(blob) < 8:
        raise Incomplete("AutoIt: a compressed script of a kind this reader does not inflate")
    if size > limit:
        raise Incomplete(f"AutoIt: a script that inflates to {size} bytes, more than is read on a clock")
    literal = "1" if magic == b"EA06" else "0"
    body = blob[8:]
    bits = bin(int.from_bytes(body, "big"))[2:].zfill(len(body) * 8) if body else ""
    at, end, out, turn = 0, len(bits), bytearray(), 0

    def take(n):
        nonlocal at
        if at + n > end:
            raise Incomplete("AutoIt: a compressed script that ends before its size is reached")
        at += n
        return int(bits[at - n:at], 2)

    while len(out) < size:
        turn += 1
        if deadline is not None and not turn & 4095 and time.perf_counter() > deadline:
            raise Timeout("AutoIt")
        if at >= end:
            raise Incomplete("AutoIt: a compressed script that ends before its size is reached")
        at += 1
        if bits[at - 1] == literal:
            out.append(take(8))
            continue
        offset = take(15)
        for length, n, more in _AU3_LENGTHS:
            add = take(n)
            if add != more:
                break
        else:
            while True:
                length += more
                add = take(n)
                if add != more:
                    break
        length += add
        if offset == 0 or offset > len(out) or len(out) + length > limit:
            raise Incomplete("AutoIt: a match that no compressor writes")
        piece = bytes(out[len(out) - offset:len(out) - offset + length])
        if length > offset:
            piece = (piece * (length // offset + 1))[:length]
        out += piece
    return bytes(out)


def au3_source(tokens: bytes, deadline=None) -> str:
    """A tokenized AutoIt script written out as source: the package's deassemble_script with its opcode
    table, and an end. The package's own loop runs until the line count of the stream is reached, and a
    stream that ends before that reads as keyword 0 for ever."""
    from autoit_ripper.opcodes import OPCODES, TokenStream
    stream = TokenStream(tokens)
    lines = stream.u32()
    if len(tokens) < 4 or lines > len(tokens):
        raise Incomplete("AutoIt: a token stream with more lines than bytes")
    out, items, line = [], [], 0
    while line < lines:
        if stream._offset >= len(tokens):
            raise Incomplete("AutoIt: a token stream that ends before its lines do")
        op = stream.u8()
        if op in OPCODES:
            try:
                items.append(OPCODES[op](stream))
            except Incomplete:
                raise
            except Exception as e:  # noqa: BLE001 - the package raises plain Exception, IndexError, KeyError
                raise Incomplete(f"AutoIt: a token that does not read ({type(e).__name__})") from None
        elif op == 0x7F:
            line += 1
            out.append("\t" * max(stream.indent, 0) + " ".join(items) + "\r\n")
            items, stream.indent = [], stream.next_indent
            if deadline is not None and not line & 255 and time.perf_counter() > deadline:
                raise Timeout("AutoIt")
        else:
            raise Incomplete(f"AutoIt: an opcode this reader does not know ({op:#x})")
        if stream._offset > len(tokens):
            raise Incomplete("AutoIt: a token that ends past the stream")
    return "".join(out)


def _au3_parse(stream, decryptor, checksum, deadline):
    """The files of an EA05/EA06 stream, by autoit-ripper's tables and keystreams, with this module's bounds
    (review of round 2): every count and size of the file is checked before it is paid for, the inflater and
    the token reader are the bounded ones above, and a stored file that is not read makes the container
    Incomplete (it could hold a second script)."""
    from autoit_ripper.utils import crc_data
    out = []
    while True:
        if deadline is not None and time.perf_counter() > deadline:
            raise Timeout("AutoIt")
        if decryptor.decrypt(stream.get_bytes(4), decryptor.au3_ResType) != b"FILE":
            break
        if len(out) >= 64:
            raise Incomplete("AutoIt: more than 64 stored files")
        kind = _au3_string(stream, decryptor, decryptor.au3_ResSubType)
        name = _au3_string(stream, decryptor, decryptor.au3_ResName)
        if not kind:
            raise Incomplete("AutoIt: a stored file without a type")
        if kind == ">>>AUTOIT NO CMDEXECUTE<<<":
            stream.skip_bytes(num=1)
            stream.skip_bytes(num=(stream.u32() ^ decryptor.au3_ResSize) + 0x18)
            continue
        packed = stream.u8()
        stored = stream.u32() ^ decryptor.au3_ResSize
        size = stream.u32() ^ decryptor.au3_ResSize
        crc = stream.u32() ^ decryptor.au3_ResCrcCompressed
        stream.skip_bytes(num=16)
        if stored > AU3_SCRIPT_MAX or size > AU3_OUT_MAX:
            raise Incomplete(f"AutoIt: a stored file of {stored} bytes ({size} inflated), more than is read on a clock")
        raw = stream.get_bytes(stored)
        if len(raw) != stored:
            raise Incomplete("AutoIt: a stored file that ends past the container")
        blob = decryptor.decrypt(raw, checksum + decryptor.au3_ResContent)
        if crc != crc_data(blob):
            raise Incomplete("AutoIt: a stored file whose checksum does not hold")
        if packed == 1:
            blob = au3_inflate(bytes(blob), AU3_OUT_MAX, deadline)
            if len(blob) != size:
                raise Incomplete("AutoIt: a stored file that inflates to another size than its header says")
        elif packed != 0:
            raise Incomplete("AutoIt: a stored file packed in a way this reader does not know")
        if kind == ">>>AUTOIT SCRIPT<<<":
            out.append(("script.au3", au3_source(bytes(blob), deadline).encode("utf-8")))
        elif kind == ">AUTOIT UNICODE SCRIPT<":
            out.append(("script.au3", bytes(blob).decode("utf-16", "replace").encode("utf-8")))
        elif kind == ">AUTOIT SCRIPT<":
            out.append(("script.au3", bytes(blob)))
        elif kind in (">AUTOHOTKEY SCRIPT<", ">AHK WITH ICON<"):
            out.append(("script.ahk", bytes(blob)))
        else:
            out.append((f"stored-{len(out)}.bin", bytes(blob)))      # a file the script installs: read as its strings
    return out


def autoit_files(data: bytes, deadline=None) -> list:
    """[(name, bytes)] of the scripts a compiled AutoIt file holds (EA05 or EA06, in an .a3x, an overlay or
    a resource: the container is found by its 16-byte mark and `AU3!`). [] without the package."""
    at = data.find(AU3_MAGIC + b"AU3!")
    if at < 0:
        return []
    try:
        from autoit_ripper.utils import ByteStream, EA05Decryptor, EA06Decryptor
    except Exception:  # noqa: BLE001 - without the package the container is not read
        return []
    stream = ByteStream(data[at + 20:])
    magic = stream.get_bytes(4)
    if magic == b"EA05":
        checksum = sum(stream.get_bytes(16))
        return _au3_parse(stream, EA05Decryptor(), checksum, deadline)
    if magic == b"EA06":
        stream.get_bytes(16)
        return _au3_parse(stream, EA06Decryptor(), 0, deadline)
    return []


def ahk_script(data: bytes):
    """The script of a compiled AutoHotkey executable: its RCDATA resource `>AUTOHOTKEY SCRIPT<` (also
    `>AHK WITH ICON<`, and a script stored under the id 1 that begins as AutoHotkey text does)."""
    if data[:2] != b"MZ" or b"A\0U\0T\0O\0H\0O\0T\0K\0E\0Y" not in data:
        return None
    import pefile
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    for kind in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", ()):
        if kind.id != pefile.RESOURCE_TYPE["RT_RCDATA"]:
            continue
        for entry in kind.directory.entries:
            raw = entry.name.string if entry.name else b""       # pefile hands the name over as 8-bit text
            raw = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("latin-1", "replace")
            name = raw.decode("utf-16-le", "replace") if b"\0" in raw else raw.decode("latin-1")
            if name.upper() in (">AUTOHOTKEY SCRIPT<", ">AHK WITH ICON<"):
                item = entry.directory.entries[0].data.struct
                at = pe.get_offset_from_rva(item.OffsetToData)
                if at < 0 or at + item.Size > len(data):
                    raise Incomplete("AutoHotkey: the script resource ends past the file")
                return data[at:at + item.Size]
    return None


# ---------------------------------------------------------------------------- one way in

def is_text(name: str, blob: bytes) -> bool:
    """Whether an inner file is read as the text it is (a text name, a byte-order mark, or no NUL among its
    first bytes). Any other inner file is read as the strings it holds: it is never left out, because a
    second plan in it means the container has no ONE plan."""
    return (str(name).lower().endswith(TEXT_NAMES) or blob[:2] in (b"\xff\xfe", b"\xfe\xff")
            or b"\0" not in blob[:4096])


def kind_of(data: bytes):
    """The carrier a file is, by its own marks, or None."""
    if data[:4] == b"ITSF":
        return "chm"
    if data[:16] in (ONE_HEAD, ONETOC_HEAD):
        return "one"
    if len(data) >= 0x4C and data[:4] == b"L\0\0\0" and data[4:20] == LNK_CLSID:
        return "lnk"
    if AU3_MAGIC + b"AU3!" in data:
        return "au3"
    if data[:2] == b"MZ" and b">\0A\0U\0T\0O\0H\0O\0T\0K\0E\0Y\0 \0S\0C\0R\0I\0P\0T\0<" in data:
        return "ahk"
    if data[:8] == b"FasdUAS ":
        return "scpt"
    return None


def inner(name: str, data: bytes, budget: float = BUDGET):
    """(kind, [(inner name, bytes)], notes, loose) for a carrier, None for any other file. `loose` says the
    inner text is a strings view whose line ends are not the file's own. A reader that fails gives the
    kind with no files and the reason among the notes."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > CARRIER_MAX:
        return None
    data = bytes(data)
    kind = kind_of(data)
    if kind is None:
        return None
    deadline, notes, files, loose = time.perf_counter() + budget, [], [], False
    try:
        if kind == "chm":
            files = chm_files(data, deadline)
            notes.append(f"{len(files)} files in the directory, {sum(1 for n, b in files if is_text(n, b))} of them text")
        elif kind == "one":
            files = onenote_files(data)
            notes.append(f"{len(files)} embedded files, {sum(1 for n, b in files if is_text(n, b))} of them text")
        elif kind == "lnk":
            strings = lnk_strings(data)
            text = "".join(f"{value}\n" for _, value in strings)
            files = [("link.txt", text.encode("utf-8"))] if text else []
            notes.append("strings: " + ", ".join(what for what, _ in strings))
        elif kind == "au3":
            files = autoit_files(data, deadline)
            notes.append(f"{len(files)} compiled script{'' if len(files) == 1 else 's'} written out as source")
        elif kind == "ahk":
            script = ahk_script(data)
            files = [("script.ahk", script)] if script else []
            notes.append("the script resource" if script else "no script resource")
        elif kind == "scpt":
            runs = scpt_strings(data)
            files = [("script.applescript", runs.encode("utf-8"))] if runs else []
            loose = True
            notes.append("its strings (no table of the container is read)")
    except Timeout as e:
        return kind, [], [f"{e} took more than {budget:g} s: not read"], loose
    except Exception as e:  # noqa: BLE001 - a container that does not read is read as before
        return kind, [], [f"{type(e).__name__}: {str(e)[:120]}"], loose
    return kind, files, notes, loose


def scpt_strings(data: bytes) -> str:
    """The printable runs of a compiled AppleScript: 8-bit, UTF-16BE and UTF-16LE, one a line, in file order."""
    import re
    blob = data[:8 << 20]
    runs = [(m.start(), m.group(0).decode("latin-1")) for m in re.finditer(rb"[\x20-\x7e\t]{8,}", blob)]
    big = [m for m in re.finditer(rb"(?:\x00[\x20-\x7e\t]){8,}", blob)]
    runs += [(m.start(), m.group(0).decode("utf-16-be")) for m in big]
    # 2026-10-13: a UTF-16BE run read one byte later is a UTF-16LE run too, the same text without its last
    # character. On a real compiled script (osacompile) that was a second, cut copy of the tagged comment, and
    # the file was refused. A little-endian run that overlaps a big-endian one is that text, not another.
    spans = [(m.start(), m.end()) for m in big]
    runs += [(m.start(), m.group(0).decode("utf-16-le")) for m in re.finditer(rb"(?:[\x20-\x7e\t]\x00){8,}", blob)
             if not any(m.start() < b and m.end() > a for a, b in spans)]
    return "\n".join(s for _, s in sorted(runs)) + "\n" if runs else ""


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        got = inner(Path(arg).name, raw, budget=30.0)
        if got is None:
            print(f"{arg}: no carrier this module reads")
            continue
        print(f"{arg}: {got[0]}; {'; '.join(got[2])}")
        for inner_name, blob in got[1]:
            print(f"  {inner_name.encode('ascii', 'backslashreplace').decode()}  {len(blob)} bytes")
