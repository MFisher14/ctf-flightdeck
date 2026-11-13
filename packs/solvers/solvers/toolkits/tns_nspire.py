#!/usr/bin/env python3
"""Toolkit `tns_nspire` (B-132): TI-Nspire documents (.tns) read with no model.

A .tns file is a zip variant no archive tool opens: it starts `*TIMLP` and four version digits, the
first local header follows without a signature, the others start `PK\\x03\\x04`, and the end record
is `TIPD`. Its XML pages are stored with TI's method 13 (encrypted, then deflate), as a `TIXC` token
stream; scripts are plain deflate (method 8). Pink 2026 had two such handouts and both were read by
hand: in the first the flag was a list of indexes in one document's script into an alphabet held by
a second document's module; in the second it was drawn as points and segments on a Geometry page,
beside a text object holding a flag-shaped decoy.

  container   read_container(data): every member, by walking the local headers. Method 0 as stored,
              method 8 raw-inflated, method 13 decrypted then inflated; a TIXC stream is decoded to
              the XML it stands for, and the header's size and CRC-32 (which TI states for the XML)
              are checked against it. A member that cannot be read keeps a `problem` naming why.
  method 13   the first 40 bytes are a 3DES-ECB block under a fixed key: `TIEN0100`, a seed and three
              packed 56-bit DES keys. The rest is XORed with 3DES(key, 00000000 || LE32(seed + i mod
              0x400)) for 8-byte block i, and is a raw deflate stream. Needs pycryptodomex.
  TIXC        tixc_decode(stream): tag and attribute names are spelled once and then named by index
              (0x0c open, 0x0e close, 0x0f attribute), and text packs common letters and digits a
              nibble each. Ported from the public rust-tns reference by way of the Pink event port.
  pages       parse_page(xml): the points, segments and text objects of a Graphs & Geometry page;
              render_page(page): a PNG of them, y up as the calculator shows it, hidden objects in
              red, free text objects drawn where they sit. tesseract (image_carve.ocr_text) reads the
              picture when it is installed.
  flags       a flag in the event format read as it stands from a member that is not a document
              page (a script, a resource); an index list decoded through a quoted string of any
              member of any document in the handout (the flag prefix is the crib: only a decode that
              holds a flag counts); a flag read by OCR; and flag-shaped text inside a document page,
              which is reported as a POSSIBLE DECOY (evidence kind `decoy`), never as a proven
              flag, unless a script or an index list proves the same value: text typed onto a
              page beside a drawing is where the decoy sat. Intake reads that evidence and does
              not call the value `solved` either (CONTRACTS 19), and the sweep's walk marks page
              members (Walk.doubt) so the sweep disputes such a value even when this engine does
              not run.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  examine(files, ff, ...) -> Report                          the same over {name: bytes}, MAX_TOTAL in all
  read_container(data, max_member=...) -> Container
  headers(data) -> Container; read_member(m, data, max_member) the lazy form, one member at a time
  method13_decrypt(raw) -> bytes; expand_key(packed21) -> bytes; tixc_decode(stream) -> bytes
  parse_page(xml, name) -> Page | None; render_page(page, width=...) -> bytes; Page.to_pixel(x, y)
  index_decodes(texts, ff) -> [(flag, how, source)]

Status: one flag, read from such a member as it stands or decoded from an index list, is `solved`. Any
other flag (OCR, document text, several values) is `candidate`. A page with something drawn and no
flag is `unsure`: the PNG is written for a human or model read (a page of text objects only is not
a drawing: its text is in the written XML and in report.json). `blocked` names what is missing
(pycryptodomex for a method-13 member, Pillow for a rendering, tesseract when ocr=on). `none` when no
file is a TI-Nspire document, or one was read and holds nothing of the above.

This module's top level imports the standard library only, so tools/archive_expand.py loads it by
path for the intake sweep's walk. Nothing in a document is executed: scripts are only read.
"""
from __future__ import annotations

import json
import os
import re
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ENGINE = "toolkits.tns_nspire"
HERE = Path(__file__).resolve().parent
REPORT_NAME = "report.json"
REPORT_SCHEMA = 1
DEFAULT_SECONDS = 30.0                # under the manifest's intake timeout (45 s)

MAGIC = b"*TIMLP"
LOCAL_SIG = b"PK\x03\x04"
END_SIGS = (b"PK\x01\x02", b"TIPD")   # what follows the last member: the directory, or the end record
MAX_FILE = 64 << 20                   # bytes of one .tns that are read
MAX_MEMBER = 32 << 20                 # bytes one member may inflate or decode to
MAX_MEMBERS = 512                     # members of one document that are walked
MAX_DOCS = 32                         # documents of one handout that are read
MAX_TOTAL = 256 << 20                 # bytes the members of one handout's documents decode to, in all
SKIP_DIRS = {"recon", ".git", ".ctf", "__pycache__"}

HEADER_KEY = bytes.fromhex("79c4e0f45eef7a5b70137a57c2fd3d2cc2707cc1ad2f1575")   # every TI-Nspire's
TIEN = b"TIEN0100"
TIEN_BYTES = 40
KEYSTREAM_WRAP = 0x400                # the block counter runs 0 .. 0x3ff and starts again
TIXC = b"TIXC"

MAX_OBJECTS = 50_000                  # objects of one page that are read
RENDER_WIDTH = 1400
RENDER_MARGIN = 40
MAX_LISTS = 64                        # integer runs and quoted strings tried against each other
MAX_STRINGS = 256
MIN_RUN = 8                           # integers in a run before it counts as an index list
MIN_ALPHABET = 16


class TnsError(ValueError):
    """The bytes are not what the format says they are; the message names what and where."""


class ToolMissing(RuntimeError):
    """A module or program a reading needs is not installed; the message names it."""


# ---- container -------------------------------------------------------------------------------------

@dataclass
class Member:
    name: str
    method: int
    csize: int
    usize: int
    crc: int
    offset: int                       # of its stored bytes in the file
    data: bytes | None = None         # its content; a TIXC stream is the XML it decodes to
    encoding: str = ""                # stored | deflate | method13, then +tixc when a TIXC stream was decoded
    crc_ok: bool | None = None        # the header's size and CRC-32 against `data` (None: not read)
    problem: str | None = None        # why `data` is None
    note: str | None = None           # something about `data` a reader must know (TIXC kept as stored)
    missing: str | None = None        # the module whose absence is the problem (ToolMissing)


@dataclass
class Container:
    version: str                      # the four characters after *TIMLP
    members: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def is_tns(data) -> bool:
    return bytes(data[:6]) == MAGIC


def _inflate(raw: bytes, cap: int) -> bytes:
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(raw, cap + 1)
    except zlib.error as e:
        raise TnsError(f"the deflate stream does not inflate ({e})") from None
    if len(out) > cap:
        raise TnsError(f"inflates past the member limit of {cap} bytes")
    if not d.eof:
        raise TnsError("the deflate stream ends early")
    return out


def headers(data: bytes) -> Container:
    """The members' headers, in file order, without their content. TnsError when the file does not
    start as a TI-Nspire document. A walk that cannot go on stops with a note saying why."""
    if not is_tns(data):
        raise TnsError("no *TIMLP magic: not a TI-Nspire document")
    if len(data) < 10:
        raise TnsError("cut short inside the *TIMLP header")
    box = Container(version=data[6:10].decode("latin-1"))
    off, first = 10, True
    while True:
        if data[off:off + 4] in END_SIGS or off >= len(data):
            break
        if not first:
            if data[off:off + 4] != LOCAL_SIG:
                box.notes.append(f"the walk stopped at offset {off}: {bytes(data[off:off + 4])!r} starts neither "
                                 f"a member nor the directory")
                break
            off += 4
        first = False
        if len(box.members) >= MAX_MEMBERS:
            box.notes.append(f"more than {MAX_MEMBERS} members: the rest are not read")
            break
        if off + 26 > len(data):
            box.notes.append(f"the walk stopped at offset {off}: a member header is cut short")
            break
        _ver, flags, method, _t, _d, crc, csize, usize, nlen, xlen = struct.unpack_from("<HHHHHIIIHH", data, off)
        name = data[off + 26:off + 26 + nlen].decode("utf-8", "replace")
        start = off + 26 + nlen + xlen
        m = Member(name, method, csize, usize, crc, start)
        box.members.append(m)
        if flags & 8 and csize == 0:
            m.problem = "its sizes are in a data descriptor (flag bit 3), which this reader does not follow"
            box.notes.append(f"the walk stopped at {name!r}: {m.problem}")
            break
        if start + csize > len(data):
            m.problem = f"it runs past the end of the file ({csize} bytes stated, {max(0, len(data) - start)} there)"
            box.notes.append(f"the walk stopped at {name!r}: {m.problem}")
            break
        off = start + csize
    return box


def _read_member(m: Member, raw: bytes, cap: int) -> None:
    if m.usize > cap:
        m.problem = f"{m.usize} bytes stated, over the member limit of {cap}"
        return
    try:
        if m.method == 0:
            body, m.encoding = raw, "stored"
        elif m.method == 8:
            body, m.encoding = _inflate(raw, cap), "deflate"
        elif m.method == 13:
            body, m.encoding = _inflate(method13_decrypt(raw), cap), "method13"
        else:
            m.problem = f"compression method {m.method} is not one this reader knows (0, 8, 13)"
            return
    except ToolMissing as e:
        m.problem, m.missing = str(e), "py:Cryptodome"
        return
    except TnsError as e:
        m.problem = str(e)
        return
    if body[:4] == TIXC:
        try:
            body = tixc_decode(body, cap)
            m.encoding += "+tixc"
        except TnsError as e:
            m.note = f"its TIXC stream did not decode ({e}): kept as stored"
    m.data = body
    m.crc_ok = len(body) == m.usize and zlib.crc32(body) == m.crc
    if not m.crc_ok and m.note is None:
        m.note = (f"size or CRC-32 differs from the header ({len(body)} bytes, {zlib.crc32(body):08x}; "
                  f"header {m.usize} bytes, {m.crc:08x})")


def read_member(m: Member, data: bytes, max_member: int = MAX_MEMBER) -> Member:
    """Read one member that headers(data) gave (Member.data, or its `problem`), decoding at most
    `max_member` bytes. One at a time, so a caller with a budget (the sweep's walk, examine) checks it
    before the next member is decoded and never holds more than one member it will not keep."""
    if m.problem is None and m.data is None:
        _read_member(m, data[m.offset:m.offset + m.csize], int(max_member))
    return m


def read_container(data: bytes, max_member: int = MAX_MEMBER) -> Container:
    """headers(data) with every member's content read (Member.data), or its `problem`. Every member is
    held at once: a caller with a total budget walks headers() and read_member() instead."""
    data = bytes(data)
    box = headers(data)
    for m in box.members:
        read_member(m, data, max_member)
    return box


# ---- method 13 -------------------------------------------------------------------------------------

def _des():
    try:
        from Cryptodome.Cipher import DES
    except ImportError as e:
        raise ToolMissing("a TI method-13 (encrypted) member needs pycryptodomex (py:Cryptodome), "
                          "which is not importable") from e
    return DES


def _ede(key: bytes):
    """(encrypt, decrypt) of 3DES-EDE in ECB under a 24-byte key, built from single DES so that a key
    whose parts repeat (which a 3DES object refuses) still works: the file chooses the key."""
    des = _des()
    a, b, c = (des.new(key[i:i + 8], des.MODE_ECB) for i in (0, 8, 16))
    return (lambda x: c.encrypt(b.decrypt(a.encrypt(x)))), (lambda x: a.decrypt(b.encrypt(c.decrypt(x))))


def expand_key(packed: bytes) -> bytes:
    """Three packed 56-bit DES keys (21 bytes) as 24 key bytes: seven key bits in the top of each byte.
    The low (parity) bit is left clear; DES does not read it."""
    if len(packed) != 21:
        raise TnsError(f"a packed method-13 key is 21 bytes, not {len(packed)}")
    out = bytearray()
    for i in (0, 7, 14):
        v = int.from_bytes(packed[i:i + 7], "big")
        out += bytes(((v >> (49 - 7 * k)) & 0x7F) << 1 for k in range(8))
    return bytes(out)


def method13_decrypt(raw: bytes) -> bytes:
    """The deflate stream of a method-13 member. TnsError when its header does not decrypt to
    TIEN0100; ToolMissing without pycryptodomex."""
    if len(raw) < TIEN_BYTES:
        raise TnsError(f"a method-13 member starts with a {TIEN_BYTES}-byte header; this one is {len(raw)} bytes")
    _, dec = _ede(HEADER_KEY)
    head = dec(raw[:TIEN_BYTES])
    if head[:8] != TIEN:
        raise TnsError(f"its method-13 header does not decrypt to {TIEN.decode()} (got {head[:8]!r})")
    seed, = struct.unpack_from("<I", head, 12)
    enc, _ = _ede(expand_key(head[16:37]))
    body = raw[TIEN_BYTES:]
    blocks = (len(body) + 7) // 8
    counters = b"".join(b"\x00\x00\x00\x00" + struct.pack("<I", (seed + i % KEYSTREAM_WRAP) & 0xFFFFFFFF)
                        for i in range(blocks))
    stream = enc(counters)[:len(body)]
    return (int.from_bytes(body, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(body), "big")


# ---- TIXC ------------------------------------------------------------------------------------------

# Text packs two tables a nibble at a time. Letters: nibble 10 ends the run, 15 says the next nibble
# indexes the second half. Digits: nibble 10 says the next nibble indexes the second half, 15 ends.
_LETTERS = " etaionsrh\x00lcdu\x00mfpgybwvkxqjz,.'"
_DIGITS = "0123456789\x00N,.E\x00x; (){}[]^+-/*PB"
_LETTER_END, _LETTER_SHIFT = 10, 15
_DIGIT_SHIFT, _DIGIT_END = 10, 15
_DIGIT_WIDE = {"N": "\u2212", "E": "\uf000", "P": "))", "B": "]["}   # minus sign, TI's exponent E, pairs
_LITERAL_CONTROL = (0x09, 0x0A, 0x0D)

_IDLE, _LET, _LET2, _DIG, _DIG2, _U2, _U3A, _U3B, _U4 = range(9)


class _Text:
    """The text decoder of one attribute value or one run of content. `idle` is True between tokens:
    only then does the markup around the text read a quote or a tag byte as markup."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.state, self.count, self.acc = _IDLE, 0, 0

    @property
    def idle(self) -> bool:
        return self.state == _IDLE

    @staticmethod
    def _digit(ch: str) -> bytes:
        return _DIGIT_WIDE.get(ch, ch).encode("utf-8")

    def feed(self, b: int, out: bytearray) -> None:
        s = self.state
        if s == _IDLE:
            self._start(b, out)
        elif s == _LET:
            hi, lo = b >> 4, b & 15
            if hi == _LETTER_SHIFT:
                out += _LETTERS[16 + lo].encode()
                return
            if hi == _LETTER_END:
                self.state = _IDLE
                return
            out += _LETTERS[hi].encode()
            if lo == _LETTER_SHIFT:
                self.state = _LET2
            elif lo == _LETTER_END:
                self.state = _IDLE
            else:
                out += _LETTERS[lo].encode()
        elif s == _LET2:
            out += _LETTERS[16 + (b >> 4)].encode()
            lo = b & 15
            if lo == _LETTER_END:
                self.state = _IDLE
            elif lo != _LETTER_SHIFT:
                out += _LETTERS[lo].encode()
                self.state = _LET
        elif s == _DIG:
            hi, lo = b >> 4, b & 15
            if hi == _DIGIT_SHIFT:
                out += self._digit(_DIGITS[16 + lo])
                return
            if hi == _DIGIT_END:
                self.state = _IDLE
                return
            out += self._digit(_DIGITS[hi])
            if lo == _DIGIT_SHIFT:
                self.state = _DIG2
            elif lo == _DIGIT_END:
                self.state = _IDLE
            else:
                out += self._digit(_DIGITS[lo])
        elif s == _DIG2:
            out += self._digit(_DIGITS[16 + (b >> 4)])
            lo = b & 15
            if lo == _DIGIT_END:
                self.state = _IDLE
            elif lo != _DIGIT_SHIFT:
                out += self._digit(_DIGITS[lo])
                self.state = _DIG
        elif s == _U2:                               # the low byte of a code point under U+0800
            out += chr(self.acc << 8 | b).encode("utf-8")
            self.state = _IDLE
        elif s == _U3A:                              # the high byte of one 16-bit unit of a run
            self.acc, self.state = b, _U3B
        elif s == _U3B:
            out += chr(self.acc << 8 | b).encode("utf-8", "surrogatepass")
            self.count -= 1
            self.state = _U3A if self.count > 0 else _IDLE
        else:                                        # _U4: three bytes of one code point, high first
            self.acc = self.acc << 8 | b
            self.count -= 1
            if self.count == 0:
                if self.acc > 0x10FFFF:
                    raise TnsError(f"a TIXC character escape names U+{self.acc:X}, past the last code point")
                out += chr(self.acc).encode("utf-8", "surrogatepass")
                self.state = _IDLE

    def _start(self, b: int, out: bytearray) -> None:
        if b < 0xA0:
            if (0x20 <= b < 0x7F) or b in _LITERAL_CONTROL:
                out.append(b)
            elif b < 0x08:
                self.acc, self.state = b, _U2
            elif b == 0x08:
                self.acc, self.count, self.state = 0, 3, _U4
            elif b & 0xF0 == 0x80:
                self.count, self.state = (b & 15) + 1, _U3A
            else:
                raise TnsError(f"byte 0x{b:02x} is no text token of a TIXC stream")
        elif b & 0xF0 == 0xA0:
            n = b & 15
            if n == _LETTER_SHIFT:
                self.state = _LET2
            elif n != _LETTER_END:
                out += _LETTERS[n].encode()
                self.state = _LET
        elif b & 0xF0 == 0xF0:
            n = b & 15
            if n == _DIGIT_SHIFT:
                self.state = _DIG2
            elif n != _DIGIT_END:
                out += self._digit(_DIGITS[n])
                self.state = _DIG
        else:
            raise TnsError(f"byte 0x{b:02x} is no text token of a TIXC stream")


_TIXC_HEAD = re.compile(rb"TIXC\d{4}-([0-9.]{1,8})\?>")
_OPEN, _CLOSE, _ATTR = 0x0C, 0x0E, 0x0F     # a tag opened by index, closed by index; an attribute by index
(_S_NAME, _S_CONTENT, _S_ATTR_NAME, _S_ATTR_QUOTE, _S_ATTR_VALUE, _S_AFTER_ATTR, _S_AFTER_SLASH, _S_OPEN_INDEX,
 _S_CLOSE_INDEX, _S_ATTR_INDEX, _S_AFTER_INDEXED, _S_EMPTY_INDEXED, _S_MARKUP) = range(13)


def tixc_decode(stream: bytes, cap: int = MAX_MEMBER) -> bytes:
    """The XML document a TIXC stream stands for, as UTF-8. TnsError (with the offset) for a stream
    that is not TIXC, names an index that was never spelled, ends inside a token, or decodes past
    `cap` bytes."""
    head = _TIXC_HEAD.match(stream)
    if not head:
        raise TnsError("no TIXC header (TIXC, four digits, '-', the XML version, '?>')")
    pos = head.end()
    if stream[pos:pos + 1] != b"<":
        raise TnsError(f"offset {pos}: the document does not open with a tag")
    out = bytearray(b'<?xml version="' + head.group(1) + b'" encoding="UTF-8" ?><')
    pos += 1
    tags, attrs, tok, text, state = [], [], bytearray(), _Text(), _S_NAME

    def named(table, index, what):
        if index >= len(table):
            raise TnsError(f"offset {pos}: {what} index {index} was never spelled ({len(table)} so far)")
        return table[index]

    n = len(stream)
    while pos < n:
        if len(out) > cap:
            raise TnsError(f"decodes past the member limit of {cap} bytes")
        b = stream[pos]
        if state == _S_NAME:
            if b in (_CLOSE, _ATTR, 0x20, 0x2F, 0x3E):
                had = bool(tok)
                if had:
                    tags.append(bytes(tok))
                    tok = bytearray()
                if b == _CLOSE:
                    out += b"></"
                    state = _S_CLOSE_INDEX
                elif b == _ATTR:
                    out += b" "
                    state = _S_ATTR_INDEX
                elif b == 0x20:
                    out += b" "
                    state = _S_ATTR_NAME
                elif b == 0x2F:
                    out += b"/"
                    state = _S_AFTER_SLASH
                else:
                    out += b">"
                    state = _S_CONTENT
            else:
                tok.append(b)
                out.append(b)
            pos += 1
        elif state == _S_CONTENT:
            if not text.idle:
                text.feed(b, out)
                pos += 1
            elif b == 0x3C:
                if stream[pos + 1:pos + 2] == b"!":
                    if stream[pos:pos + 9] != b"<![CDATA[":
                        raise TnsError(f"offset {pos}: markup other than a CDATA section is not read")
                    end = stream.find(b"]]>", pos + 9)
                    if end < 0:
                        raise TnsError(f"offset {pos}: a CDATA section is not closed")
                    out += stream[pos:end + 3]
                    pos = end + 3
                else:
                    out += b"<"
                    tok = bytearray()
                    state = _S_NAME
                    pos += 1
            elif b == _OPEN:
                out += b"<"
                state = _S_OPEN_INDEX
                pos += 1
            elif b == _CLOSE:
                out += b"</"
                state = _S_CLOSE_INDEX
                pos += 1
            else:
                text.feed(b, out)
                pos += 1
        elif state == _S_ATTR_NAME:
            if b == 0x3D:
                attrs.append(bytes(tok))
                state = _S_ATTR_QUOTE
            else:
                tok.append(b)
            out.append(b)
            pos += 1
        elif state == _S_ATTR_QUOTE:
            if b != 0x22:
                raise TnsError(f"offset {pos}: an attribute value does not open with a quote")
            out.append(b)
            text.reset()
            state = _S_ATTR_VALUE
            pos += 1
        elif state == _S_ATTR_VALUE:
            if b == 0x22 and text.idle:
                out.append(b)
                tok = bytearray()
                state = _S_AFTER_ATTR
            else:
                text.feed(b, out)
            pos += 1
        elif state == _S_AFTER_ATTR:
            if b == 0x3E:
                out += b">"
                state = _S_CONTENT
            elif b == 0x2F:
                out += b"/"
                state = _S_AFTER_SLASH
            elif b == 0x20:
                out += b" "
                state = _S_ATTR_NAME
            elif b == _ATTR:
                out += b" "
                state = _S_ATTR_INDEX
            else:
                raise TnsError(f"offset {pos}: byte 0x{b:02x} after an attribute")
            pos += 1
        elif state == _S_AFTER_SLASH:                # the '>' of '/>'
            out.append(b)
            state = _S_CONTENT
            pos += 1
        elif state == _S_OPEN_INDEX:
            out += named(tags, b, "tag")
            state = _S_AFTER_INDEXED
            pos += 1
        elif state == _S_CLOSE_INDEX:
            out += named(tags, b, "tag") + b">"
            state = _S_CONTENT
            pos += 1
        elif state == _S_ATTR_INDEX:
            out += named(attrs, b, "attribute") + b'="'
            text.reset()
            state = _S_ATTR_VALUE
            pos += 1
        elif state == _S_AFTER_INDEXED:              # a tag opened by index closes itself unless more follows
            if b == 0x20:
                out += b" "
                state = _S_ATTR_NAME
                pos += 1
            elif b == 0x2F:
                state = _S_EMPTY_INDEXED
                pos += 1
            elif b == _ATTR:
                out += b" "
                state = _S_ATTR_INDEX
                pos += 1
            else:
                out += b">"
                state = _S_CONTENT
        else:                                        # _S_EMPTY_INDEXED: the '>' of '/>' after an indexed tag
            out += b"/>"
            state = _S_CONTENT
            pos += 1
    if state == _S_AFTER_INDEXED:
        out += b">"
        state = _S_CONTENT
    if state != _S_CONTENT or not text.idle:
        raise TnsError("the TIXC stream ends inside a tag or a text token")
    if len(out) > cap:
        raise TnsError(f"decodes past the member limit of {cap} bytes")
    return bytes(out)


# ---- Graphs & Geometry pages -----------------------------------------------------------------------

@dataclass
class Point:
    id: str
    x: float
    y: float
    hidden: bool = False


@dataclass
class Segment:
    id: str
    a: str                            # point ids
    b: str
    hidden: bool = False


@dataclass
class TextObject:
    id: str
    text: str
    x: float | None
    y: float | None
    w: float = 0.0
    h: float = 0.0
    attached: bool = False            # it hangs off another object (an axis number, a label): not drawn
    hidden: bool = False


@dataclass
class Page:
    name: str
    points: dict = field(default_factory=dict)        # id -> Point
    segments: list = field(default_factory=list)
    texts: list = field(default_factory=list)
    other: dict = field(default_factory=dict)         # object kind -> how many, of the kinds not drawn
    notes: list = field(default_factory=list)
    scale: float = 1.0                # set by layout(): pixels per unit ...
    origin: tuple = (0.0, 0.0)        # ... and the unit coordinates of the picture's top left margin corner
    size: tuple = (0, 0)
    margin: int = RENDER_MARGIN

    def drawn_segments(self) -> list:
        return [s for s in self.segments if s.a in self.points and s.b in self.points]

    def free_texts(self) -> list:
        return [t for t in self.texts if not t.attached and t.text.strip() and t.x is not None and t.y is not None]

    @property
    def drawn(self) -> bool:
        """Something is drawn on the page: a point or a segment (text alone is not a drawing)."""
        return bool(self.points) or bool(self.drawn_segments())

    def layout(self, width: int = RENDER_WIDTH, margin: int = RENDER_MARGIN) -> None:
        """Fit every point and free text box in a picture whose longer side is `width` pixels, one
        scale both ways, `margin` white pixels around."""
        xs = [p.x for p in self.points.values()]
        ys = [p.y for p in self.points.values()]
        for t in self.free_texts():
            xs += [t.x, t.x + t.w]
            ys += [t.y, t.y - t.h]
        self.margin = margin
        if not xs:
            self.scale, self.origin, self.size = 1.0, (0.0, 0.0), (2 * margin, 2 * margin)
            return
        span_x, span_y = max(xs) - min(xs), max(ys) - min(ys)
        longer = max(span_x, span_y)
        self.scale = (width - 2 * margin) / longer if longer > 0 else 1.0
        self.origin = (min(xs), max(ys))
        self.size = (int(round(span_x * self.scale)) + 2 * margin, int(round(span_y * self.scale)) + 2 * margin)

    def to_pixel(self, x: float, y: float) -> tuple:
        """Unit coordinates as picture pixels, after layout(). y grows upward on the page and downward
        in a picture, so it is flipped: what the calculator shows higher is nearer the top."""
        return (self.margin + (x - self.origin[0]) * self.scale, self.margin + (self.origin[1] - y) * self.scale)


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1] if isinstance(tag, str) else ""


def _number(text) -> float | None:
    try:
        v = float((text or "").strip().replace("\u2212", "-"))
    except ValueError:
        return None
    return v if v == v and abs(v) != float("inf") else None


def _chars(text: str) -> str:
    """The text of a `chrs` field: six numbers of formatting, then the characters."""
    parts = (text or "").split(" ", 6)
    if len(parts) == 7 and all(p.lstrip("-").isdigit() for p in parts[:6]):
        text = parts[6]
    return text.rstrip("\r\n")


def parse_page(xml: bytes, name: str = "") -> Page | None:
    """The drawable objects of a Graphs & Geometry page, or None when the XML holds no object list
    (a settings document, a Notes page). TnsError for XML that does not parse, or that declares a
    DOCTYPE (a TI document has none; an entity bomb needs one)."""
    if b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise TnsError("the XML declares a DOCTYPE or an entity: not parsed")
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        raise TnsError(f"the XML does not parse ({e})") from None
    lists = [el for el in root.iter() if _local(el.tag) == "objs"]
    if not lists:
        return None
    page = Page(name=name)
    seen = 0
    for objs in lists:
        for obj in objs:
            seen += 1
            if seen > MAX_OBJECTS:
                page.notes.append(f"more than {MAX_OBJECTS} objects: the rest are not read")
                return page
            kind = _local(obj.tag)
            f = {_local(c.tag): (c.text or "") for c in obj}
            oid = f.get("id", "").strip() or f"#{seen}"
            hidden = f.get("asho", "1").strip() == "0"
            parents = f.get("par", "").split()
            x, y = _number(f.get("x")), _number(f.get("y"))
            if kind == "point" and x is not None and y is not None:
                page.points[oid] = Point(oid, x, y, hidden)
            elif kind == "segment" and len(parents) == 2:
                page.segments.append(Segment(oid, parents[0], parents[1], hidden))
            elif "chrs" in f:
                page.texts.append(TextObject(oid, _chars(f["chrs"]), x, y, _number(f.get("w")) or 0.0,
                                             _number(f.get("h")) or 0.0, attached=bool(parents) or kind != "text",
                                             hidden=hidden))
            else:
                page.other[kind] = page.other.get(kind, 0) + 1
    undrawn = len(page.segments) - len(page.drawn_segments())
    if undrawn:
        page.notes.append(f"{undrawn} segment(s) name an end that is no point of the page: not drawn")
    return page


def render_page(page: Page, width: int = RENDER_WIDTH) -> bytes:
    """A PNG of the page: segments and points in black, hidden ones in red, free text objects in blue
    where they sit. ToolMissing without Pillow."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError as e:
        raise ToolMissing("a page rendering needs Pillow (py:PIL), which is not importable") from e
    import io
    page.layout(width)
    im = Image.new("RGB", (max(page.size[0], 8), max(page.size[1], 8)), "white")
    draw = ImageDraw.Draw(im)
    black, red, blue = (0, 0, 0), (220, 0, 0), (0, 0, 200)
    for s in page.drawn_segments():
        a, b = page.points[s.a], page.points[s.b]
        draw.line([page.to_pixel(a.x, a.y), page.to_pixel(b.x, b.y)], fill=red if s.hidden else black, width=4)
    for p in page.points.values():
        cx, cy = page.to_pixel(p.x, p.y)
        draw.ellipse([cx - 4, cy - 4, cx + 4, cy + 4], fill=red if p.hidden else black)
    for t in page.free_texts():
        px, py = page.to_pixel(t.x, t.y)
        size = max(12, int(round((t.h or 2.0) * page.scale * 0.7)))
        draw.text((px, py), t.text, fill=red if t.hidden else blue, font=ImageFont.load_default(size=size))
    out = io.BytesIO()
    im.save(out, "PNG")
    return out.getvalue()


# ---- flags -----------------------------------------------------------------------------------------

_INT_RUN = re.compile(r"(?<![\w.])\d{1,5}(?:\s*[,;\s]\s*\d{1,5}){%d,}(?![\w.])" % (MIN_RUN - 1))
_QUOTED = re.compile(r"\"([^\"\\\n]{%d,4096})\"|'([^'\\\n]{%d,4096})'" % (MIN_ALPHABET, MIN_ALPHABET))


def index_decodes(texts: dict, ff) -> list:
    """[(flag, how, source)] for every run of integers in `texts` ({name: str}) that, read as indexes (from 0,
    then from 1) into a quoted string of any of the texts, spells a flag in the event format. The
    format is the crib: a decode with no flag in it is dropped, so a list that fits no string, or
    indexes past its end, says nothing. `source` is the name of the text the run is in."""
    runs, strings = [], []
    for name, text in texts.items():
        for m in _INT_RUN.finditer(text):
            if len(runs) < MAX_LISTS:
                runs.append((name, [int(v) for v in re.findall(r"\d+", m.group(0))]))
        for m in _QUOTED.finditer(text):
            s = m.group(1) or m.group(2)
            if len(strings) < MAX_STRINGS:
                strings.append((name, s))
    found = []
    for rname, run in runs:
        for sname, s in strings:
            for base in (0, 1):
                if min(run) < base or max(run) - base >= len(s):
                    continue
                decoded = "".join(s[i - base] for i in run)
                for flag in ff.find_flags(decoded):
                    how = (f"{len(run)} indexes in {rname} into the {len(s)}-character string in {sname}"
                           + (", counted from 1" if base else ""))
                    if all(flag != f[0] for f in found):
                        found.append((flag, how, rname))
    return found


def is_document(m: Member) -> bool:
    """A page or settings document of the TI document itself (not a script the author wrote): text
    typed into it is where a decoy sits. The sweep's walk asks the same question (DOCUMENT_DOUBT)."""
    return m.encoding.endswith("+tixc") or m.name.lower().endswith(".xml")


DOCUMENT_DOUBT = "a TI-Nspire document page (text typed onto a page is where a decoy sits)"


# ---- one handout -----------------------------------------------------------------------------------

@dataclass
class Finding:
    flag: str
    kind: str                         # decoded | literal | ocr | document-text
    file: str                         # the .tns it came from
    member: str | None
    detail: str
    path: str | None = None           # the written file that shows it


@dataclass
class PageReport:
    file: str
    member: str
    points: int
    segments: int
    hidden: int
    texts: list                       # the free text objects' text
    other: dict
    rendered: bool = False            # a picture of it was made
    png: str | None = None            # where the rendering was written
    ocr: str | None = None            # tesseract's text of it
    notes: list = field(default_factory=list)


@dataclass
class Report:
    docs: dict = field(default_factory=dict)          # file -> {version, members: [...], notes: [...]}
    findings: list = field(default_factory=list)
    pages: list = field(default_factory=list)
    written: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    missing: list = field(default_factory=list)       # modules or programs a reading needed and did not have
    ocr: str = "not needed"                           # not needed | run | off | not run: <why>

    def flags(self) -> list:
        """Distinct flags: proven readings first, then OCR, then document text (possible decoys)."""
        order = {"decoded": 0, "literal": 0, "ocr": 1, "document-text": 2}
        out = []
        for f in sorted(self.findings, key=lambda f: order[f.kind]):
            if f.flag not in out:
                out.append(f.flag)
        return out

    def to_dict(self) -> dict:
        return {"schema": REPORT_SCHEMA, "engine": ENGINE, "documents": self.docs,
                "findings": [vars(f) for f in self.findings], "pages": [vars(p) for p in self.pages],
                "ocr": self.ocr, "missing": self.missing, "notes": self.notes}


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "member"


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    path.write_bytes(data)


OCR_MODULE = "_tns_nspire_image_carve"     # the sys.modules key of the loaded OCR reader (private)


def _ocr_module():
    """image_carve (the lane's tesseract reader), loaded by path (this module adds nothing to
    sys.path), or ToolMissing naming why it cannot be had. It is kept in sys.modules under a private
    name, so a later `import image_carve` (or `solvers.toolkits.image_carve`) is a normal import that
    this loader neither answers nor shadows."""
    name = OCR_MODULE
    if sys.modules.get(name) is not None:
        return sys.modules[name]
    path = HERE / "image_carve.py"
    if not path.is_file():
        raise ToolMissing(f"the OCR reader {path.name} is not beside this module")
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except ImportError as e:
        sys.modules.pop(name, None)
        raise ToolMissing(f"the OCR reader solvers/toolkits/image_carve.py is not importable ({e})") from e
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def _folder(file: str, used: set) -> str:
    """The output folder of one document: its path made safe, and a number added when another
    document of the handout already took that name (compared without case: macOS folders ignore it)."""
    base = _safe(file.replace("/", "_"))
    folder, n = base, 1
    while folder.casefold() in used:
        n += 1
        folder = f"{base}-{n}"
    used.add(folder.casefold())
    return folder


def examine(files: dict, ff, *, out_dir: Path | None = None, ocr: str = "auto", read=None, deadline=None,
            prefixes=()) -> Report:
    """Read every TI-Nspire document in `files` ({name: bytes}). Members and page renderings are
    written under `out_dir` when given. `ocr`: auto (read renderings when tesseract is there, say so
    when not), on (ToolMissing when it is not), off. `read(png, deadline=)` replaces the OCR call."""
    if ocr not in ("auto", "on", "off"):
        raise ValueError(f"ocr must be auto, on or off, not {ocr!r}")
    rep = Report()
    texts = {}                                        # "<file> -> <member>" -> str, for the index decode
    renders = []                                      # (PageReport, png bytes)
    folders, decoded, spent = set(), 0, False         # decoded: bytes of members read, against MAX_TOTAL
    for file in sorted(files):
        data = files[file]
        if not is_tns(data):
            continue
        if len(rep.docs) >= MAX_DOCS:
            rep.notes.append(f"more than {MAX_DOCS} TI-Nspire documents: {file} and what follows are not read")
            break
        try:
            box = headers(data)
        except TnsError as e:
            rep.notes.append(f"{file}: {e}")
            continue
        doc = {"version": box.version, "members": [], "notes": list(box.notes)}
        rep.docs[file] = doc
        folder = _folder(file, folders)
        for i, m in enumerate(box.members):
            if m.problem is None:                     # read one member at a time, against the total limit
                room = MAX_TOTAL - decoded
                if m.usize > room or room <= 0:
                    m.problem = (f"not read: the handout's documents already decoded to {decoded} bytes, and "
                                 f"{m.usize} more would pass the total limit of {MAX_TOTAL}")
                    if not spent:
                        rep.notes.append(f"the total limit of {MAX_TOTAL} decoded bytes was reached at "
                                         f"{file} -> {m.name}: it and any later member that does not fit are not read")
                    spent = True
                else:
                    read_member(m, data, min(MAX_MEMBER, room))
                    decoded += len(m.data or b"")
            row = {"name": m.name, "method": m.method, "stored_bytes": m.csize, "bytes": m.usize,
                   "encoding": m.encoding, "crc_ok": m.crc_ok, "problem": m.problem, "note": m.note, "written": None}
            doc["members"].append(row)
            if m.data is None:
                if m.missing and m.missing not in rep.missing:
                    rep.missing.append(m.missing)
                continue
            where = f"{file} -> {m.name}"
            if out_dir is not None:
                path = Path(out_dir) / folder / f"{i:02d}-{_safe(m.name)}"
                _write(path, m.data)
                rep.written.append(path)
                row["written"] = str(path)
            text = m.data.decode("utf-8", "replace")
            texts[where] = text
            page = None
            if is_document(m):
                try:
                    page = parse_page(m.data, m.name)
                except TnsError as e:
                    doc["notes"].append(f"{m.name}: {e}")
            for flag in ff.find_flags(text):
                if is_document(m):
                    detail = f"flag-shaped text in the document page {where}"
                    if page is not None:
                        holder = next((t for t in page.texts if flag in t.text), None)
                        if holder is not None:
                            detail = f"flag-shaped text typed into text object {holder.id} of the page {where}"
                        if page.drawn:
                            detail += (f", which also draws {len(page.points)} point(s) and "
                                       f"{len(page.drawn_segments())} segment(s)")
                    rep.findings.append(Finding(flag, "document-text", file, m.name, detail, row["written"]))
                else:
                    rep.findings.append(Finding(flag, "literal", file, m.name, f"as it stands in the member {where}",
                                                row["written"]))
            if page is not None and (page.drawn or page.free_texts()):
                pr = PageReport(file, m.name, len(page.points), len(page.drawn_segments()),
                                sum(p.hidden for p in page.points.values()) + sum(s.hidden for s in page.drawn_segments()),
                                [t.text for t in page.free_texts()], dict(page.other), notes=list(page.notes))
                rep.pages.append(pr)
                if page.drawn:
                    try:
                        png = render_page(page)
                    except ToolMissing as e:
                        pr.notes.append(str(e))
                        if "py:PIL" not in rep.missing:
                            rep.missing.append("py:PIL")
                        continue
                    renders.append((pr, png))
                    pr.rendered = True
                    if out_dir is not None:
                        path = Path(out_dir) / folder / f"{i:02d}-{_safe(m.name)}.png"
                        _write(path, png)
                        rep.written.append(path)
                        pr.png = str(path)
    for flag, how, source in index_decodes(texts, ff):
        file, _, member = source.partition(" -> ")
        rep.findings.append(Finding(flag, "decoded", file, member, how))
    _read_renderings(rep, renders, ff, ocr, read, deadline, prefixes)
    return rep


def _read_renderings(rep: Report, renders: list, ff, ocr: str, read, deadline, prefixes) -> None:
    if not renders:
        return
    if ocr == "off":
        rep.ocr = "off"
        return
    try:
        ic = _ocr_module()
        if read is None:
            import shutil
            if not shutil.which("tesseract"):
                raise ToolMissing("tesseract is not on PATH")
            read = ic.ocr_text
    except ToolMissing as e:
        if ocr == "on":
            raise
        rep.ocr = f"not run: {e}"
        return
    rep.ocr = "run"
    for pr, png in renders:
        if deadline is not None and time.monotonic() > deadline:
            pr.notes.append("not read by OCR: out of time")
            continue
        try:
            pr.ocr = read(png, deadline=deadline)
        except Exception as e:                        # image_carve's out-of-budget, a tesseract fault, a refused spawn
            pr.notes.append(f"not read by OCR: {type(e).__name__}: {str(e)[:160]}")
            continue
        for flag in ic.ocr_flags(pr.ocr, ff, prefixes):
            rep.findings.append(Finding(flag, "ocr", pr.file, pr.member,
                                        f"read by OCR from the rendering of {pr.file} -> {pr.member}", pr.png))


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        if p is None:
            return None
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    flags = rep.flags()
    proven_flags = {x.flag for x in rep.findings if x.kind in ("decoded", "literal")}
    proven = bool(proven_flags)
    # A possible decoy: typed into a document page and not proven by a script or an index list. OCR does
    # not clear it: the rendering draws the page's text objects, so OCR reads the typed text too.
    suspect = [f for f in flags if f not in proven_flags
               and any(x.kind == "document-text" for x in rep.findings if x.flag == f)]
    evidence, notes = [], []
    kinds = {"decoded": "decode", "literal": "match", "ocr": "ocr", "document-text": "decoy"}
    for x in rep.findings:
        if x.kind == "document-text" and x.flag not in suspect:
            # Proven elsewhere: the page text is a second sighting, not a dispute (CONTRACTS 7: the
            # `decoy` kind marks a value the engine leaves a candidate).
            evidence.append(Evidence("match", f"{x.flag}: also {x.detail}", path=rel(x.path)))
            continue
        lead = "possible decoy: " if x.kind == "document-text" else ""
        evidence.append(Evidence(kinds[x.kind], f"{lead}{x.flag}: {x.detail}", path=rel(x.path)))
    for p in rep.pages:
        if p.rendered:
            evidence.append(Evidence("render", f"{p.file} -> {p.member}: {p.points} point(s), {p.segments} segment(s)"
                                     + (f", {p.hidden} hidden (red)" if p.hidden else "")
                                     + (f", text objects {p.texts!r}" if p.texts else ""), path=rel(p.png)))
    for file, doc in sorted(rep.docs.items()):
        read = [m for m in doc["members"] if m["problem"] is None]
        notes.append(f"{file}: TI-Nspire document (container {doc['version']}), {len(read)} of {len(doc['members'])} "
                     f"member(s) read: " + ", ".join(f"{m['name']} ({m['encoding']})" for m in read))
        for m in doc["members"]:
            if m["problem"]:
                notes.append(f"{file} -> {m['name']} was not read: {m['problem']}")
            elif m["note"]:
                notes.append(f"{file} -> {m['name']}: {m['note']}")
        notes += [f"{file}: {n}" for n in doc["notes"]]
    for f in suspect:
        notes.append(f"{f} is text typed into a document page: a possible decoy, not a proven flag; "
                     "look at the rendering before sending it")
    for p in rep.pages:
        if p.other:
            notes.append(f"{p.file} -> {p.member}: not drawn: " + ", ".join(f"{k} x{v}" for k, v in sorted(p.other.items())))
        if p.ocr and p.ocr.strip():
            lines = [ln.strip() for ln in p.ocr.splitlines() if ln.strip()]
            notes.append(f"OCR of {p.file} -> {p.member}: " + " / ".join(dict.fromkeys(lines))[:300])
        notes += [f"{p.file} -> {p.member}: {n}" for n in p.notes]
    if rep.ocr not in ("not needed", "run"):
        notes.append(f"OCR {rep.ocr}")
    if rep.missing:
        notes.append("missing: " + ", ".join(rep.missing))
    notes += rep.notes
    if len(flags) == 1 and proven:
        status = "solved"
    elif flags:
        status = "candidate"
    elif rep.missing:
        status = "blocked"
    elif any(p.rendered for p in rep.pages):
        status = "unsure"
    else:
        status = "none"
    if not rep.docs:
        notes = ["no file of the challenge is a TI-Nspire document (*TIMLP)"] + rep.notes
    for p in rep.written:
        if Path(p).name == REPORT_NAME:
            evidence.append(Evidence("carve", "report written", path=rel(p)))
    return SolverResult(status=status, flags=flags, evidence=evidence, cost=Cost(seconds=round(seconds, 3)),
                        engine=ENGINE, challenge_id=challenge_id, notes="; ".join(dict.fromkeys(notes)))


def challenge_documents(challenge_dir: Path, notes: list) -> dict:
    """{relative name: bytes} of the TI-Nspire documents of a challenge: the sweep's scratch copy
    (`unpacked/`, originals and members) when there is one, else `files/`, else the folder itself.
    Only files that start *TIMLP are read; one over MAX_FILE is named in `notes`. No link is followed."""
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
            if p.is_symlink() or not p.is_file():
                continue
            with open(p, "rb") as fh:
                if fh.read(6) != MAGIC:
                    continue
            name = str(p.relative_to(challenge_dir))
            if p.stat().st_size > MAX_FILE:
                notes.append(f"{name} is a TI-Nspire document over {MAX_FILE} bytes: not read")
                continue
            out[name] = p.read_bytes()
    return out


def challenge_id_of(challenge_dir: Path) -> str | None:
    """The id in the challenge folder's challenge.json (written by intake and pull), or None."""
    try:
        cid = json.loads((Path(challenge_dir) / "challenge.json").read_text(encoding="utf-8")).get("id")
    except (OSError, ValueError, AttributeError):
        return None
    return str(cid) if cid not in (None, "") else None


def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: out (folder for the members, renderings and report.json; default
    <challenge>/recon/tns_nspire), ocr (auto|on|off), seconds (budget of the OCR step, default 30),
    challenge_id, read (a callable replacing the OCR call: read(png, deadline=) -> text)."""
    from ctf import flagfmt
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    cid = str(opts["challenge_id"]) if opts.get("challenge_id") else challenge_id_of(challenge_dir)
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "tns_nspire"
    try:
        seconds = float(opts.get("seconds", DEFAULT_SECONDS))
    except (TypeError, ValueError):
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid,
                            notes=f"bad option: seconds must be a number, not {opts.get('seconds')!r}")
    ocr = str(opts.get("ocr", "auto"))
    if ocr not in ("auto", "on", "off"):
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid,
                            notes=f"bad option: ocr must be auto, on or off, not {ocr!r}")
    skipped = []
    files = challenge_documents(challenge_dir, skipped)
    try:
        rep = examine(files, flagfmt.for_profile(profile), out_dir=out_dir, ocr=ocr,
                      read=opts["read"] if callable(opts.get("read")) else None, deadline=t0 + seconds,
                      prefixes=tuple(profile.flag.prefixes))
    except ToolMissing as e:
        return SolverResult(status="blocked", engine=ENGINE, challenge_id=cid, notes=f"OCR was asked for (ocr=on) but {e}")
    rep.notes += skipped
    if rep.docs:
        path = out_dir / REPORT_NAME
        _write(path, json.dumps(rep.to_dict(), indent=1, default=str).encode("utf-8"))
        rep.written.append(path)
    return result_of(rep, challenge_id=cid, seconds=time.monotonic() - t0, root=challenge_dir)
