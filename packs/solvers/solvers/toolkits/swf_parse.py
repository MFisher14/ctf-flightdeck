#!/usr/bin/env python3
"""Toolkit `swf_parse` (B-117): a Flash movie read statically. Header, tags, AVM1, bitmaps, codes.

A SWF is a container that hides the real artifact: a flag string an ActionScript pushes, a route a
getURL points at, seed and data arrays a class initialises, or a QR drawn into an embedded bitmap
with its finder patterns left out. The one general reader, Flash Player, is gone and would run the
file. This reads it without running anything, in plain Python (Pillow only turns bitmaps into PNG):

  header    `FWS` as it is, `CWS` inflated (zlib), `ZWS` decoded (LZMA; the alone header is rebuilt
            from the SWF's five property bytes and declared length), all capped against a
            decompression bomb. Bytes after the declared end are reported and searched.
  tags      the RECORDHEADER walk (short and long form), into DefineSprite, every tag named.
  AVM1      DoAction, DoInitAction and DefineButton2 actions disassembled: the constant pool, every
            Push, function headers (DefineFunction/2 with parameters and body size), With, Try,
            branches. A constant tracker follows Push, InitArray, InitObject, SetVariable,
            SetMember, DefineLocal and GetURL2 over the listing, so array and object literals come
            out whole and named (`Kiln.steps = [412, 96, ...]`) and stack-built URLs are read.
            A literal is weighed as it is built (the values it would print, shared ones counted
            each time): past a cap per literal, per movie, or in nesting depth it is left out and
            named, so a few bytes of PushDuplicate and InitArray cannot double their way to memory.
  bitmaps   DefineBits (with JPEGTables), DefineBitsJPEG2/3/4 and DefineBitsLossless(2) formats
            3, 4 and 5 carved to image files.
  codes     every bitmap goes to the camera decoders (carve_stego.decode_codes: zxing or zbar),
            and a small two-tone square that they do not read goes to qr_matrix with the repair
            decode, which reads a QR whose finders were removed (Reed--Solomon decides).

Not read: AVM2 (DoABC) bytecode, DefineButton (v1) and PlaceObject clip actions, DefineEditText
fields, shapes and sounds. A DoABC tag is named in the result so nobody takes its absence for a
movie without code; a flag anywhere in the decompressed body is still found as bytes.

  solve(challenge_dir, profile, **opts) -> SolverResult      the engine contract (python -m ctf run)
  examine(files, ff, ...) -> Report                          the same over {name: bytes}
  parse(data) -> dict                 header, frame, tags, action blocks, strings, urls, constants
  decompress(data) -> (header, body);  iter_tags(body);  walk(body) -> (tags, error)
  action_blocks(tags);  disassemble(code) -> dict;  listing(dis) -> str;  tag_strings(tags)
  extract_images(data) -> ([image], [notes]);  find_codes(images, ...) -> [dict]

  .venv/bin/python solvers/toolkits/swf_parse.py FILE... [--event SLUG] [--out DIR] [--seconds S]

Status: one flag read from the body's bytes or from a decoded code is `solved`, several are
`candidate`. A movie with no flag is `unsure`: its listing, constants, strings and bitmaps are
written for a model read (an author's own cipher over those arrays is not guessed at). A file that
is not a parseable SWF is named in the notes. Nothing is executed or sent.
"""
from __future__ import annotations

import argparse
import io
import json
import lzma
import re
import struct
import sys
import tempfile
import time
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

import _visual_stego as vs      # noqa: E402

ENGINE = "toolkits.swf_parse"
MAX_INPUT = 64 << 20                  # bytes of one SWF file
MAX_BODY = 128 << 20                  # decompressed body: a CWS/ZWS bomb stops here
MAX_TAGS = 200_000
MAX_SPRITE_DEPTH = 8
MAX_ACTIONS = 200_000                 # action records disassembled in one movie, all its blocks together:
                                      # each kept record costs about 300 bytes, so this is about 60 MB
MAX_CODE = 8 << 20                    # bytes of action code disassembled in one movie
MAX_STRINGS = 20_000
MAX_CONSTANTS = 5_000
MAX_LITERAL_NODES = 250_000           # values one array or object literal holds once written out (a shared
                                      # inner literal counts every time it appears; eight characters of a
                                      # string count as one value)
MAX_MOVIE_NODES = 1_000_000           # the same, over every constant one movie reports
MAX_LITERAL_DEPTH = 64                # arrays inside arrays
MAX_CUT_NOTES = 4                     # literals left out that are named one by one; the rest are counted
MAX_LISTING = 16 << 20                # characters of AVM1 listing written for one movie
MAX_SHOWN = 200                       # characters of one string shown in a listing line or a note
MAX_IMAGE_PIXELS = 16_000_000         # a larger bitmap is named, not rebuilt
MAX_IMAGES = 2_000                    # bitmaps carved out of one movie
MAX_MATRIX_PIXELS = 1_500_000         # the pure-Python QR sampler is tried on smaller bitmaps only
DEFAULT_SECONDS = 30.0

TAG_NAMES = {
    0: "End", 1: "ShowFrame", 2: "DefineShape", 4: "PlaceObject", 5: "RemoveObject",
    6: "DefineBits", 7: "DefineButton", 8: "JPEGTables", 9: "SetBackgroundColor",
    10: "DefineFont", 11: "DefineText", 12: "DoAction", 13: "DefineFontInfo",
    14: "DefineSound", 15: "StartSound", 17: "DefineButtonSound", 18: "SoundStreamHead",
    19: "SoundStreamBlock", 20: "DefineBitsLossless", 21: "DefineBitsJPEG2",
    22: "DefineShape2", 24: "Protect", 26: "PlaceObject2", 28: "RemoveObject2",
    32: "DefineShape3", 33: "DefineText2", 34: "DefineButton2", 35: "DefineBitsJPEG3",
    36: "DefineBitsLossless2", 37: "DefineEditText", 39: "DefineSprite", 43: "FrameLabel",
    45: "SoundStreamHead2", 46: "DefineMorphShape", 48: "DefineFont2", 56: "ExportAssets",
    57: "ImportAssets", 58: "EnableDebugger", 59: "DoInitAction", 60: "DefineVideoStream",
    61: "VideoFrame", 64: "EnableDebugger2", 65: "ScriptLimits", 69: "FileAttributes",
    70: "PlaceObject3", 71: "ImportAssets2", 73: "DefineFontAlignZones", 74: "CSMTextSettings",
    75: "DefineFont3", 76: "SymbolClass", 77: "Metadata", 78: "DefineScalingGrid", 82: "DoABC",
    83: "DefineShape4", 84: "DefineMorphShape2", 86: "DefineSceneAndFrameLabelData",
    87: "DefineBinaryData", 88: "DefineFontName", 89: "StartSound2", 90: "DefineBitsJPEG4",
    91: "DefineFont4",
}
JPEG_TAGS = (6, 21, 35, 90)
LOSSLESS_TAGS = (20, 36)


class SWFError(ValueError):
    """A structurally invalid SWF: a bad signature, a field that runs past its container, or a
    body that does not decompress."""


# ---- header ----------------------------------------------------------------------------------------

def decompress(data: bytes) -> tuple:
    """(header, body): the 8-byte SWF header as a dict and the bytes after it, decompressed for
    CWS and ZWS. `header["trailing"]` counts the bytes after the movie's own end (data appended to
    the file); they are returned in `header["trailing_bytes"]`. SWFError on a bad signature, a body
    that does not decompress, or one over MAX_BODY."""
    if not isinstance(data, (bytes, bytearray)):
        raise SWFError("SWF input must be bytes")
    data = bytes(data)
    if len(data) < 8:
        raise SWFError("too short to be a SWF (the header alone is 8 bytes)")
    sig = data[:3]
    if sig not in (b"FWS", b"CWS", b"ZWS"):
        raise SWFError(f"not a SWF: signature {sig!r}")
    file_length = struct.unpack_from("<I", data, 4)[0]
    declared = file_length - 8
    if declared < 0 or declared > MAX_BODY:
        raise SWFError(f"declared length {file_length} is outside 8..{MAX_BODY + 8} (decompression-bomb guard)")
    trailing = b""
    if sig == b"FWS":
        body, trailing = data[8:8 + declared], data[8 + declared:]
    elif sig == b"CWS":
        inflater = zlib.decompressobj()
        try:
            body = inflater.decompress(data[8:], MAX_BODY + 1)
        except zlib.error as exc:
            raise SWFError(f"CWS body does not inflate: {exc}") from exc
        if len(body) > MAX_BODY:
            raise SWFError(f"CWS body inflates past {MAX_BODY} bytes (decompression-bomb guard)")
        trailing = inflater.unused_data
    else:
        if len(data) < 17:
            raise SWFError("ZWS file is too short for its LZMA header")
        # after the SWF header: compressed length (4), LZMA properties (5), then the raw stream
        alone = data[12:17] + struct.pack("<Q", declared) + data[17:]
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        try:
            body = decoder.decompress(alone, MAX_BODY + 1)
        except lzma.LZMAError as exc:
            raise SWFError(f"ZWS body does not decode: {exc}") from exc
        if len(body) > MAX_BODY:
            raise SWFError(f"ZWS body decodes past {MAX_BODY} bytes (decompression-bomb guard)")
        trailing = decoder.unused_data
    header = {"signature": sig.decode("ascii"),
              "compression": {b"FWS": "none", b"CWS": "zlib", b"ZWS": "lzma"}[sig],
              "version": data[3], "file_length": file_length, "body_length": len(body),
              "trailing": len(trailing), "trailing_bytes": trailing}
    if len(body) != declared:
        header["length_mismatch"] = f"the header declares {declared} body bytes, the file holds {len(body)}"
    return header, body


def read_rect(body: bytes, pos: int = 0) -> tuple:
    """(rect, end): a RECT (signed twips, 5 bits of field width then four fields) and the offset
    of the byte after it."""
    if pos >= len(body):
        raise SWFError("SWF body ends before its frame size")
    nbits = body[pos] >> 3
    total = 5 + 4 * nbits
    end = pos + (total + 7) // 8
    if end > len(body):
        raise SWFError("SWF body ends inside its frame size")
    value = int.from_bytes(body[pos:end], "big") >> ((end - pos) * 8 - total)
    fields = []
    for i in range(4):
        raw = (value >> ((3 - i) * nbits)) & ((1 << nbits) - 1)
        fields.append(raw - (1 << nbits) if nbits and raw >> (nbits - 1) else raw)
    x_min, x_max, y_min, y_max = fields
    return ({"x_min": x_min, "x_max": x_max, "y_min": y_min, "y_max": y_max,
             "width_px": (x_max - x_min) / 20, "height_px": (y_max - y_min) / 20}, end)


# ---- tags ------------------------------------------------------------------------------------------

def iter_tags(body: bytes, *, _depth: int = 0, _base: int = 0, _count: list | None = None):
    """Walk the tag stream, yielding (code, name, tag_bytes, body offset of the tag's data, depth),
    into DefineSprite bodies. On the top call `body` is the whole decompressed body and the frame
    prologue is stepped over. A tag whose length runs past its container raises SWFError after the
    tags before it were yielded."""
    count = _count if _count is not None else [0]
    pos = 0
    if _depth == 0:
        _rect, pos = read_rect(body, 0)
        pos += 4                                        # frame rate and frame count
    while pos + 2 <= len(body):
        count[0] += 1
        if count[0] > MAX_TAGS:
            raise SWFError(f"more than {MAX_TAGS} tags")
        head = struct.unpack_from("<H", body, pos)[0]
        code, length = head >> 6, head & 0x3F
        pos += 2
        if length == 0x3F:
            if pos + 4 > len(body):
                raise SWFError(f"tag {code} at {_base + pos - 2:#x}: long header runs past the body")
            length = struct.unpack_from("<I", body, pos)[0]
            pos += 4
        if pos + length > len(body):
            raise SWFError(f"tag {code} at {_base + pos:#x}: length {length} runs past the body")
        tag_bytes = body[pos:pos + length]
        yield code, TAG_NAMES.get(code, f"tag{code}"), tag_bytes, _base + pos, _depth
        if code == 39 and length >= 4 and _depth < MAX_SPRITE_DEPTH:
            yield from iter_tags(tag_bytes[4:], _depth=_depth + 1, _base=_base + pos + 4, _count=count)
        if code == 0:
            break
        pos += length


def walk(body: bytes) -> tuple:
    """([(code, name, tag_bytes, offset, depth)], error): every tag iter_tags reaches, and the
    SWFError message that ended the walk early (None for a clean walk). What was read before a
    broken tag is kept."""
    tags = []
    try:
        for tag in iter_tags(body):
            tags.append(tag)
    except SWFError as exc:
        return tags, str(exc)
    return tags, None


# ---- AVM1 ------------------------------------------------------------------------------------------

AVM1_SHORT = {
    0x00: "End", 0x04: "NextFrame", 0x05: "PreviousFrame", 0x06: "Play", 0x07: "Stop",
    0x08: "ToggleQuality", 0x09: "StopSounds", 0x0A: "Add", 0x0B: "Subtract", 0x0C: "Multiply",
    0x0D: "Divide", 0x0E: "Equals", 0x0F: "Less", 0x10: "And", 0x11: "Or", 0x12: "Not",
    0x13: "StringEquals", 0x14: "StringLength", 0x15: "StringExtract", 0x17: "Pop",
    0x18: "ToInteger", 0x1C: "GetVariable", 0x1D: "SetVariable", 0x20: "SetTarget2",
    0x21: "StringAdd", 0x22: "GetProperty", 0x23: "SetProperty", 0x24: "CloneSprite",
    0x25: "RemoveSprite", 0x26: "Trace", 0x27: "StartDrag", 0x28: "EndDrag",
    0x29: "StringLess", 0x2A: "Throw", 0x2B: "CastOp", 0x2C: "ImplementsOp", 0x30: "RandomNumber",
    0x31: "MBStringLength", 0x32: "CharToAscii", 0x33: "AsciiToChar", 0x34: "GetTime",
    0x35: "MBStringExtract", 0x36: "MBCharToAscii", 0x37: "MBAsciiToChar", 0x3A: "Delete",
    0x3B: "Delete2", 0x3C: "DefineLocal", 0x3D: "CallFunction", 0x3E: "Return",
    0x3F: "Modulo", 0x40: "NewObject", 0x41: "DefineLocal2", 0x42: "InitArray",
    0x43: "InitObject", 0x44: "TypeOf", 0x45: "TargetPath", 0x46: "Enumerate",
    0x47: "Add2", 0x48: "Less2", 0x49: "Equals2", 0x4A: "ToNumber", 0x4B: "ToString",
    0x4C: "PushDuplicate", 0x4D: "StackSwap", 0x4E: "GetMember", 0x4F: "SetMember",
    0x50: "Increment", 0x51: "Decrement", 0x52: "CallMethod", 0x53: "NewMethod",
    0x54: "InstanceOf", 0x55: "Enumerate2", 0x60: "BitAnd", 0x61: "BitOr", 0x62: "BitXor",
    0x63: "BitLShift", 0x64: "BitRShift", 0x65: "BitURShift", 0x66: "StrictEquals",
    0x67: "Greater", 0x68: "StringGreater", 0x69: "Extends",
}
AVM1_LONG = {
    0x81: "GotoFrame", 0x83: "GetURL", 0x87: "StoreRegister", 0x88: "ConstantPool",
    0x8A: "WaitForFrame", 0x8B: "SetTarget", 0x8C: "GoToLabel", 0x8D: "WaitForFrame2",
    0x8E: "DefineFunction2", 0x8F: "Try", 0x94: "With", 0x96: "Push", 0x99: "Jump",
    0x9A: "GetURL2", 0x9B: "DefineFunction", 0x9D: "If", 0x9E: "Call", 0x9F: "GotoFrame2",
}


class Ref:
    """A value the constant tracker knows only by name: a variable, a member, a register."""

    def __init__(self, name: str):
        self.name = name

    def __repr__(self):
        return f"Ref({self.name!r})"


UNKNOWN = Ref("?")


def _cstr(payload: bytes, off: int) -> tuple:
    end = payload.find(b"\x00", off)
    if end < 0:
        end = len(payload)
    return payload[off:end].decode("utf-8", "replace"), end + 1


def _push_values(payload: bytes, pool: list) -> list:
    """The values of one ActionPush. A register is {"register": n}, undefined is the string
    "undefined", a constant-pool index past the pool is "<constant n>". An unknown type byte ends
    the record (the rest cannot be framed) and is named."""
    values, off = [], 0
    while off < len(payload):
        kind = payload[off]
        off += 1
        try:
            if kind == 0:
                value, off = _cstr(payload, off)
            elif kind == 1:
                value, off = struct.unpack_from("<f", payload, off)[0], off + 4
            elif kind == 2:
                value = None
            elif kind == 3:
                value = "undefined"
            elif kind == 4:
                value, off = {"register": payload[off]}, off + 1
            elif kind == 5:
                value, off = bool(payload[off]), off + 1
            elif kind == 6:
                high, low = payload[off:off + 4], payload[off + 4:off + 8]
                value, off = struct.unpack("<d", low + high)[0], off + 8
            elif kind == 7:
                value, off = struct.unpack_from("<i", payload, off)[0], off + 4
            elif kind in (8, 9):
                width = 1 if kind == 8 else 2
                index = int.from_bytes(payload[off:off + width], "little")
                if len(payload) < off + width:
                    raise IndexError
                value, off = (pool[index] if index < len(pool) else f"<constant {index}>"), off + width
            else:
                values.append(f"<push type {kind}>")
                break
        except (struct.error, IndexError):
            values.append("<truncated push>")
            break
        values.append(value)
    return values


def _decode(code: int, payload: bytes, pool: list) -> dict:
    """The arguments of one long action. A payload shorter than its fields is {"raw": hex}."""
    try:
        if code == 0x88:
            count, off, items = struct.unpack_from("<H", payload, 0)[0], 2, []
            while len(items) < min(count, MAX_STRINGS) and off < len(payload):
                text, off = _cstr(payload, off)
                items.append(text)
            return {"count": count, "values": items}
        if code == 0x96:
            return {"values": _push_values(payload, pool)}
        if code == 0x83:
            url, off = _cstr(payload, 0)
            return {"url": url, "target": _cstr(payload, off)[0]}
        if code == 0x8B:
            return {"target": _cstr(payload, 0)[0]}
        if code == 0x8C:
            return {"label": _cstr(payload, 0)[0]}
        if code == 0x81:
            return {"frame": struct.unpack_from("<H", payload, 0)[0]}
        if code in (0x99, 0x9D):
            return {"branch": struct.unpack_from("<h", payload, 0)[0]}
        if code == 0x87:
            return {"register": payload[0]}
        if code == 0x8A:
            return {"frame": struct.unpack_from("<H", payload, 0)[0], "skip": payload[2]}
        if code == 0x8D:
            return {"skip": payload[0]}
        if code == 0x9A:
            return {"method": ("none", "GET", "POST", "?")[payload[0] >> 6], "load_target": bool(payload[0] & 2),
                    "load_variables": bool(payload[0] & 1)}
        if code == 0x9F:
            out = {"play": bool(payload[0] & 1)}
            if payload[0] & 2:
                out["scene_bias"] = struct.unpack_from("<H", payload, 1)[0]
            return out
        if code == 0x94:
            return {"size": struct.unpack_from("<H", payload, 0)[0]}
        if code == 0x9B:
            name, off = _cstr(payload, 0)
            count = struct.unpack_from("<H", payload, off)[0]
            off += 2
            params = []
            for _ in range(count):
                text, off = _cstr(payload, off)
                params.append(text)
            return {"name": name, "params": params, "size": struct.unpack_from("<H", payload, off)[0]}
        if code == 0x8E:
            name, off = _cstr(payload, 0)
            count, registers, flags = struct.unpack_from("<HBH", payload, off)
            off += 5
            params = []
            for _ in range(count):
                register = payload[off]
                text, off = _cstr(payload, off + 1)
                params.append({"name": text, "register": register})
            return {"name": name, "params": params, "registers": registers, "flags": flags,
                    "size": struct.unpack_from("<H", payload, off)[0]}
        if code == 0x8F:
            flags = payload[0]
            try_size, catch_size, finally_size = struct.unpack_from("<HHH", payload, 1)
            out = {"try": try_size, "catch": catch_size, "finally": finally_size}
            if flags & 4:
                out["catch_register"] = payload[7]
            else:
                out["catch_name"] = _cstr(payload, 7)[0]
            return out
    except (struct.error, IndexError):
        pass
    return {"raw": payload.hex()} if payload else {}


class _Array(list):
    """An array literal the tracker built, with its weight: `nodes` is how many values it holds
    once written out (see _weigh), `depth` how deep its arrays nest."""
    __slots__ = ("nodes", "depth")


class _Object(dict):
    """An object literal the tracker built, weighed like an _Array."""
    __slots__ = ("nodes", "depth")


def _weigh(value) -> tuple:
    """(nodes, depth) of a tracked value: what writing it out costs. A literal carries its own
    count, taken when it was built, so this never walks one; a string is one value for each eight
    characters (a two-byte constant-pool push can name a string of 64 KiB)."""
    if isinstance(value, (_Array, _Object)):
        return value.nodes, value.depth
    if isinstance(value, str):
        return 1 + len(value) // 8, 0
    return 1, 0


def _plain(value):
    """A tracked value as JSON: a Ref is {"ref": name}, the unknown is "<unknown>". The tracker
    only keeps literals under MAX_LITERAL_NODES and MAX_LITERAL_DEPTH, which bounds this walk."""
    if value is UNKNOWN:
        return "<unknown>"
    if isinstance(value, Ref):
        return {"ref": value.name}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def _known(value) -> bool:
    if isinstance(value, Ref):
        return False
    if isinstance(value, list):
        return all(_known(v) for v in value)
    if isinstance(value, dict):
        return all(_known(v) for v in value.values())
    return True


class _Tracker:
    """Follows constants over a linear listing: what is pushed, built into arrays and objects,
    and assigned. It does not follow branches; an action whose stack effect it does not model
    empties what it knew, so a value it reports was built by the actions right before it."""

    def __init__(self, room: int | None = None):
        self.stack, self.constants, self.urls = [], [], []
        self._literal = {}                # id(list or dict literal) -> its constants row
        self.room = MAX_MOVIE_NODES if room is None else room     # nodes the constants may still hold
        self.spent = 0                    # nodes the constants rows hold
        self.left_out, self.uncounted = [], 0                     # literals not kept: why, and how many more

    def pop(self):
        return self.stack.pop() if self.stack else UNKNOWN

    def _take(self, count):
        if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= len(self.stack):
            self.stack.clear()
            return None
        return [self.stack.pop() for _ in range(count)]

    def _leave(self, offset, why):
        """Name a literal or constant that was left out (the first MAX_CUT_NOTES, then a count)."""
        if len(self.left_out) < MAX_CUT_NOTES:
            self.left_out.append(f"the constant at offset {offset:#x} was left out: {why}")
        else:
            self.uncounted += 1

    def _spend(self, nodes, offset) -> bool:
        """Take `nodes` from what this movie's constants may hold; False (and named) when they do not fit."""
        if nodes > self.room:
            self._leave(offset, f"the cap of {MAX_MOVIE_NODES} values over a movie's constants was reached")
            return False
        self.room -= nodes
        self.spent += nodes
        return True

    def _note(self, name, value, offset):
        row = self._literal.get(id(value))
        if row is not None:
            if row["name"] is None:
                row["name"] = name
            return
        if len(self.constants) < MAX_CONSTANTS and not isinstance(value, Ref) and self._spend(_weigh(value)[0], offset):
            self.constants.append({"offset": offset, "name": name, "value": value})

    def _build(self, literal, parts, offset):
        """Weigh a literal just built from `parts` and keep it (as a constants row, and as the
        value on the stack), or leave it out: UNKNOWN goes on the stack in its place, so nothing
        built on top of it can grow either. The weight is the sum of the parts' weights: a part
        that is itself a literal counts in full each time, which is what writing it out costs
        (PushDuplicate puts one list on the stack twice, and InitArray then holds it twice)."""
        nodes, depth = 1, 0
        for part in parts:
            n, d = _weigh(part)
            nodes += n
            depth = max(depth, d)
        depth += 1
        if depth > MAX_LITERAL_DEPTH:
            self._leave(offset, f"it nests deeper than {MAX_LITERAL_DEPTH} arrays")
            return UNKNOWN
        if nodes > MAX_LITERAL_NODES:
            self._leave(offset, f"written out it holds {nodes} values, over the cap of {MAX_LITERAL_NODES} a literal")
            return UNKNOWN
        literal.nodes, literal.depth = nodes, depth
        if len(self.constants) < MAX_CONSTANTS:
            if not self._spend(nodes, offset):
                return UNKNOWN
            row = {"offset": offset, "name": None, "value": literal}
            self.constants.append(row)
            self._literal[id(literal)] = row
        return literal

    @staticmethod
    def _label(value):
        return value.name if isinstance(value, Ref) else str(value) if isinstance(value, (str, int)) else "?"

    def step(self, code: int, args: dict, offset: int) -> None:
        if code == 0x96:
            for value in args.get("values", ()):
                self.stack.append(Ref(f"register{value['register']}") if isinstance(value, dict) else value)
        elif code == 0x1C:                              # GetVariable
            name = self.pop()
            self.stack.append(Ref(name) if isinstance(name, str) else UNKNOWN)
        elif code == 0x4E:                              # GetMember
            name, obj = self.pop(), self.pop()
            known = isinstance(obj, Ref) and obj is not UNKNOWN and isinstance(name, (str, int))
            self.stack.append(Ref(f"{obj.name}.{name}") if known else UNKNOWN)
        elif code in (0x1D, 0x3C):                      # SetVariable, DefineLocal
            value, name = self.pop(), self.pop()
            if isinstance(name, str):
                self._note(name, value, offset)
        elif code == 0x4F:                              # SetMember
            value, name, obj = self.pop(), self.pop(), self.pop()
            if isinstance(name, (str, int)) and not isinstance(name, bool):
                self._note(f"{self._label(obj)}.{name}", value, offset)
        elif code == 0x87:                              # StoreRegister: the value stays on the stack
            if self.stack and id(self.stack[-1]) in self._literal:
                self._note(f"register{args.get('register', '?')}", self.stack[-1], offset)
        elif code == 0x42:                              # InitArray
            items = self._take(self.pop())
            self.stack.append(UNKNOWN if items is None else self._build(_Array(items), items, offset))
        elif code == 0x43:                              # InitObject
            count = self.pop()
            pairs = self._take(count * 2 if isinstance(count, int) and not isinstance(count, bool) else None)
            if pairs is None:
                self.stack.append(UNKNOWN)
            else:
                obj = _Object((self._label(pairs[i + 1]), pairs[i]) for i in range(0, len(pairs), 2))
                self.stack.append(self._build(obj, list(obj) + list(obj.values()), offset))
        elif code == 0x9A:                              # GetURL2
            _target, url = self.pop(), self.pop()
            if isinstance(url, str) and url:
                self.urls.append(url)
        elif code == 0x17:                              # Pop
            self.pop()
        elif code == 0x4C:                              # PushDuplicate
            self.stack.append(self.stack[-1] if self.stack else UNKNOWN)
        elif code == 0x4D:                              # StackSwap
            a, b = self.pop(), self.pop()
            self.stack += [a, b]
        elif code in (0x3D, 0x40):                      # CallFunction, NewObject
            self.pop()
            self._take(self.pop())
            self.stack.append(UNKNOWN)
        elif code in (0x52, 0x53):                      # CallMethod, NewMethod
            self.pop()
            self.pop()
            self._take(self.pop())
            self.stack.append(UNKNOWN)
        elif code in (0x88, 0x8E, 0x9B, 0x41):          # ConstantPool, function headers, DefineLocal2
            if code == 0x41:
                self.pop()
        else:
            self.stack.clear()


def disassemble(code: bytes, *, max_actions: int | None = None, max_bytes: int | None = None, deadline=None,
                max_nodes: int | None = None) -> dict:
    """Disassemble one AVM1 action stream (the actions of a DoAction, DoInitAction or button
    condition). Returns {actions, strings, urls, constant_pool, constants, left_out, nodes,
    truncated, cut, consumed}:

      actions    [{offset, code, name, args, depth}] in stream order; `depth` counts the function,
                 With and Try bodies the action is inside; a branch carries its `target` offset.
      strings    every string the stream carries (constant pools, pushes, URLs, labels, names).
      urls       GetURL targets, and GetURL2 targets the constant tracker could read.
      constants  [{offset, name, value}]: array and object literals (named when the next actions
                 assign them, else name None) and constants assigned to a variable or member. A
                 value holds "<unknown>" or {"ref": name} where it was not a constant.
      left_out   why a literal or constant was not kept: it would hold more than
                 MAX_LITERAL_NODES values written out, nests deeper than MAX_LITERAL_DEPTH, or
                 the constants of the stream hold `max_nodes` values already (default
                 MAX_MOVIE_NODES). "<unknown>" stands where such a literal would have been.
      nodes      values the constants hold, written out (what `max_nodes` is spent on).
      truncated  None, or the offset where a record ran past the stream (the walk stops there).
      cut        None, or why the walk stopped before the stream's end: `max_actions` records
                 (default MAX_ACTIONS) were read, `max_bytes` of the stream were read, or
                 `deadline` (time.monotonic()) passed. What was read before is kept.
      consumed   bytes of the stream that were read.
    """
    actions, strings, urls, pool = [], [], [], []
    tracker = _Tracker(max_nodes)
    bodies = []                        # (end offset, the outer tracker stack or None, pushes a function)
    truncated = None

    def text(value):
        if isinstance(value, str) and value and len(strings) < MAX_STRINGS:
            strings.append(value)

    limit = MAX_ACTIONS if max_actions is None else max_actions
    cut = None
    pos, n = 0, len(code)
    while pos < n:
        if len(actions) >= limit:
            cut = f"stopped at offset {pos:#x} after {len(actions)} actions: the cap on a movie's actions"
            break
        if max_bytes is not None and pos >= max_bytes:
            cut = f"stopped at offset {pos:#x}: the cap on a movie's action bytes"
            break
        if deadline is not None and not len(actions) % 2048 and time.monotonic() > deadline:
            cut = f"stopped at offset {pos:#x} after {len(actions)} actions: out of time"
            break
        while bodies and pos >= bodies[-1][0]:
            _end, outer, pushes = bodies.pop()
            if outer is not None:                       # the outer stack comes back as it was left, not copied:
                if pushes:                              # a copy a function body made thousands of bodies quadratic
                    outer.append(UNKNOWN)
                tracker.stack = outer
        start, op = pos, code[pos]
        pos += 1
        args = {}
        if op >= 0x80:
            if pos + 2 > n:
                truncated = start
                break
            length = struct.unpack_from("<H", code, pos)[0]
            pos += 2
            if pos + length > n:
                truncated = start
                break
            args = _decode(op, code[pos:pos + length], pool)
            pos += length
        name = AVM1_LONG.get(op) if op >= 0x80 else AVM1_SHORT.get(op)
        action = {"offset": start, "code": op, "name": name or f"0x{op:02X}", "args": args, "depth": len(bodies)}
        if op in (0x99, 0x9D) and "branch" in args:
            action["target"] = pos + args["branch"]
        actions.append(action)
        if op == 0x88:
            pool[:] = args.get("values", [])
            for item in pool:
                text(item)
        elif op == 0x96:
            for value in args.get("values", ()):
                text(value)
        elif op == 0x83:
            if args.get("url"):
                urls.append(args["url"])
            text(args.get("url"))
            text(args.get("target"))
        elif op in (0x8B, 0x8C):
            text(args.get("target") or args.get("label"))
        elif op in (0x9B, 0x8E) and "size" in args:
            text(args["name"])
            for param in args["params"]:
                text(param["name"] if isinstance(param, dict) else param)
            bodies.append((pos + args["size"], tracker.stack, not args["name"]))
            tracker.stack = []
        elif op == 0x94 and "size" in args:
            bodies.append((pos + args["size"], None, False))
        elif op == 0x8F and "try" in args:
            text(args.get("catch_name"))
            bodies.append((pos + args["try"] + args["catch"] + args["finally"], None, False))
        before = len(tracker.urls)
        tracker.step(op, args, start)
        urls += tracker.urls[before:]
        if op == 0x00 and not bodies:
            break
    left_out = list(tracker.left_out)
    if tracker.uncounted:
        left_out.append(f"{tracker.uncounted} more constant(s) were left out for the same caps")
    return {"actions": actions, "strings": strings, "urls": list(dict.fromkeys(urls)), "constant_pool": pool,
            "constants": [{"offset": row["offset"], "name": row["name"], "value": _plain(row["value"]),
                           "complete": _known(row["value"])} for row in tracker.constants],
            "left_out": left_out, "nodes": tracker.spent, "truncated": truncated, "cut": cut, "consumed": pos}


def _clip(text: str, most: int = MAX_SHOWN) -> str:
    return text if len(text) <= most else f"{text[:most]}... ({len(text)} characters)"


def _show(value) -> str:
    """One value of a listing line. A string over MAX_SHOWN characters is clipped, with its
    length (the strings file holds it whole): a push of constant-pool indices names the same
    long string two bytes a time."""
    if isinstance(value, dict) and set(value) == {"register"}:
        return f"register{value['register']}"
    if isinstance(value, str):
        return json.dumps(_clip(value), ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False)


class _ListingFull(Exception):
    """The listing reached its character cap."""


def listing(dis: dict, clip: int = 16, limit: int | None = None) -> str:
    """A disassembly as text: the constants first (long arrays clipped to `clip` values, with
    their length), then one action a line, indented by body depth. The text stops at about
    `limit` characters (default MAX_LISTING) and its last line says so."""
    limit = MAX_LISTING if limit is None else limit
    lines, size = [], 0

    def emit(line):
        nonlocal size
        if size >= limit:
            raise _ListingFull
        lines.append(line)
        size += len(line) + 1

    try:
        _listing_lines(dis, clip, emit)
    except _ListingFull:
        lines.append(f"; the listing stops here: the cap of {limit} characters was reached")
    return "\n".join(lines) + "\n"


def _listing_lines(dis: dict, clip: int, emit) -> None:
    for row in dis["constants"]:
        value = row["value"]
        if isinstance(value, list) and len(value) > clip:
            shown = ", ".join(_show(v) for v in value[:clip]) + f", ... ({len(value)} values)"
            shown = f"[{shown}]"
        else:
            shown = _show(value)
        emit(f"; {row['offset']:06x} {row['name'] or '(unassigned)'} = {shown}")
    for note in dis.get("left_out", ()):
        emit(f"; {note}")
    for action in dis["actions"]:
        args = action["args"]
        if "values" in args:
            detail = ", ".join(_show(v) for v in args["values"])
        elif action["name"] in ("DefineFunction", "DefineFunction2"):
            params = ", ".join(p["name"] if isinstance(p, dict) else p for p in args.get("params", ()))
            detail = f"{args.get('name') or '(anonymous)'}({params}) {args.get('size')} bytes"
        else:
            detail = ", ".join(f"{k}={_show(v)}" for k, v in args.items())
        if "target" in action:
            detail += f" -> {action['target']:06x}"
        emit(f"{action['offset']:06x} {'  ' * action['depth']}{action['name']}{' ' + detail if detail else ''}")
    if dis["truncated"] is not None:
        emit(f"; the record at {dis['truncated']:06x} runs past the end of the stream")
    if dis.get("cut"):
        emit(f"; {dis['cut']}")


def action_blocks(tags: list) -> list:
    """[(label, offset, action bytes)] of every AVM1 block among walked tags: DoAction,
    DoInitAction (after its sprite id) and each DefineButton2 condition."""
    out = []
    for code, name, tag, offset, _depth in tags:
        if code == 12:
            out.append((name, offset, tag))
        elif code == 59 and len(tag) >= 2:
            out.append((f"{name} sprite {struct.unpack_from('<H', tag, 0)[0]}", offset + 2, tag[2:]))
        elif code == 34 and len(tag) >= 5:
            at = struct.unpack_from("<H", tag, 3)[0]
            pos = 3 + at if at else len(tag)
            while pos + 4 <= len(tag):
                size, conditions = struct.unpack_from("<HH", tag, pos)
                end = pos + size if size else len(tag)
                if end > len(tag) or end < pos + 4:
                    break
                button = struct.unpack_from("<H", tag, 0)[0]
                out.append((f"{name} {button} condition {conditions:#06x}", offset + pos + 4, tag[pos + 4:end]))
                if not size:
                    break
                pos = end
    return out


# ---- strings ---------------------------------------------------------------------------------------

def _printable_runs(blob: bytes, least: int = 4, most: int = MAX_STRINGS) -> list:
    """The runs of `least` or more printable ASCII bytes, at most `most` of them."""
    runs = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % least, blob):
        if len(runs) >= most:
            break
        runs.append(m.group(0).decode("ascii"))
    return runs


def tag_strings(tags: list) -> list:
    """The strings the non-code tags among walked tags carry, in movie order: frame labels,
    Metadata XML, exported and symbol-class names, the printable runs of each DefineBinaryData."""
    out = []
    for code, _name, tag, _offset, _depth in tags:
        if code == 43:
            out.append(_cstr(tag, 0)[0])
        elif code == 77:
            out.append(tag.split(b"\x00")[0].decode("utf-8", "replace"))
        elif code == 87:
            out += _printable_runs(tag[6:], most=max(0, MAX_STRINGS - len(out)))
        elif code in (56, 76) and len(tag) >= 2:
            off = 2
            for _ in range(struct.unpack_from("<H", tag, 0)[0]):
                if off + 2 >= len(tag):
                    break
                text, off = _cstr(tag, off + 2)
                out.append(text)
    return [s for s in out if s]


# ---- bitmaps ---------------------------------------------------------------------------------------

def _jpeg_stream(code: int, tag: bytes, tables: bytes | None) -> bytes | None:
    if code in (35, 90):
        if len(tag) < 6:
            return None
        head = 6 if code == 35 else 8
        size = struct.unpack_from("<I", tag, 2)[0]
        stream = tag[head:head + size]
    else:
        stream = tag[2:]
    if not stream:
        return None
    if stream.startswith((b"\x89PNG", b"GIF8")):
        return stream
    # Flash wrote an end-of-image and start-of-image pair before the stream, or between the
    # tables and the image: taking it out leaves one JPEG.
    stream = stream.replace(b"\xff\xd9\xff\xd8", b"", 1)
    if code == 6 and tables:
        tables = tables[:-2] if tables.endswith(b"\xff\xd9") else tables
        stream = tables + (stream[2:] if stream.startswith(b"\xff\xd8") else stream)
    return stream if stream.startswith(b"\xff\xd8") else b"\xff\xd8" + stream


def _lossless(code: int, tag: bytes):
    """(image, note): a DefineBitsLossless(2) bitmap as a PIL image, or (None, why not)."""
    if len(tag) < 7:
        return None, "tag is shorter than its header"
    _char, fmt, width, height = struct.unpack_from("<HBHH", tag, 0)
    if not width or not height or width * height > MAX_IMAGE_PIXELS:
        return None, f"{width}x{height} is empty or over the {MAX_IMAGE_PIXELS} pixel cap"
    alpha = code == 36
    off = 8 if fmt == 3 else 7
    stride = {3: (width + 3) & ~3, 4: (width * 2 + 3) & ~3, 5: width * 4}.get(fmt)
    if stride is None:
        return None, f"bitmap format {fmt} is not one of 3, 4, 5"
    colours = tag[7] + 1 if fmt == 3 and len(tag) > 7 else 0
    entry = 4 if alpha else 3
    need = colours * entry + stride * height
    try:
        raw = zlib.decompressobj().decompress(tag[off:], need)
    except zlib.error as exc:
        return None, f"pixel data does not inflate: {exc}"
    if len(raw) < need:
        return None, f"pixel data is {len(raw)} bytes, {need} needed"
    from PIL import Image
    if fmt == 5:
        return Image.frombytes("RGBA" if alpha else "RGB", (width, height), raw, "raw", "ARGB" if alpha else "XRGB"), ""
    if fmt == 3:
        table, pixels = raw[:colours * entry], raw[colours * entry:]
        rows = b"".join(pixels[y * stride:y * stride + width] for y in range(height))
        image = Image.frombytes("P", (width, height), rows)
        image.putpalette(table, rawmode="RGBA" if alpha else "RGB")
        return image.convert("RGBA" if alpha else "RGB"), ""
    # PIX15 is big-endian, a reserved bit then five bits each of red, green, blue. Pillow's raw
    # mode "BGR;15" is the same word little-endian, so each row's byte pairs are swapped, the row
    # padding dropped, and Pillow unpacks it in C (a Python loop cost 0.7 s CPU a megapixel).
    rows = bytearray(width * height * 2)
    for y in range(height):
        row = raw[y * stride:y * stride + width * 2]
        rows[y * width * 2:(y + 1) * width * 2:2] = row[1::2]
        rows[y * width * 2 + 1:(y + 1) * width * 2:2] = row[0::2]
    return Image.frombytes("RGB", (width, height), bytes(rows), "raw", "BGR;15"), ""


def extract_images(data: bytes, tags: list | None = None, deadline=None) -> tuple:
    """([image], [notes]) of a movie's embedded bitmaps, in movie order (`tags`: an earlier walk
    of the same movie, to save walking it again). An image is {char_id, tag, kind (png | jpeg |
    gif), image (the file's bytes), width, height}; a JPEG stream is passed on as it is, a
    lossless bitmap is rebuilt as PNG. A bitmap that cannot be rebuilt is named in the notes.
    At most MAX_IMAGES bitmaps are carved, and none after `deadline` (time.monotonic()): one
    16-megapixel lossless bitmap costs a tenth of a CPU second and a movie can hold thousands.
    The bitmaps left out are counted in the notes, the first of them named."""
    if tags is None:
        tags, _error = walk(decompress(data)[1])
    tables, out, notes = None, [], []
    stopped, first, left = "", "", 0
    for code, name, tag, _offset, _depth in tags:
        if code == 8:
            tables = tag
        if code not in JPEG_TAGS + LOSSLESS_TAGS or len(tag) < 2:
            continue
        char_id = struct.unpack_from("<H", tag, 0)[0]
        if not stopped:
            if len(out) >= MAX_IMAGES:
                stopped = f"the cap of {MAX_IMAGES} bitmaps a movie was reached"
            elif deadline is not None and time.monotonic() > deadline:
                stopped = "out of time"
        if stopped:
            first = first or f"{name} {char_id}"
            left += 1
            continue
        if code in JPEG_TAGS:
            stream = _jpeg_stream(code, tag, tables)
            if not stream:
                notes.append(f"{name} {char_id}: no image data")
                continue
            kind = "png" if stream.startswith(b"\x89PNG") else "gif" if stream.startswith(b"GIF8") else "jpeg"
            out.append({"char_id": char_id, "tag": name, "kind": kind, "image": stream, "width": None, "height": None})
        else:
            image, why = _lossless(code, tag)
            if image is None:
                notes.append(f"{name} {char_id}: {why}")
                continue
            buf = io.BytesIO()
            image.save(buf, format="PNG")
            out.append({"char_id": char_id, "tag": name, "kind": "png", "image": buf.getvalue(),
                        "width": image.width, "height": image.height})
    if left:
        notes.append(f"{left} bitmap(s), from {first} on, were not carved: {stopped}")
    return out, notes


def _camera_codes(image_bytes: bytes) -> list:
    """The picture as it is, and small ones enlarged; not its bit planes (a movie can hold many
    large bitmaps, and a plane sweep of each would spend the budget on backgrounds)."""
    import carve_stego
    return carve_stego.decode_codes(image_bytes, planes=False)


def _looks_like_modules(image_bytes: bytes) -> bool:
    """A small, roughly square, two-tone picture: what a matrix code drawn a few pixels a module
    looks like, and all the pure-Python sampler is worth trying on."""
    from PIL import Image
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
            if width * height > MAX_MATRIX_PIXELS or min(width, height) < 21 or not 0.8 <= width / height <= 1.25:
                return False
            histogram = image.convert("L").histogram()
    except Exception:
        return False
    return sum(sorted(histogram)[-2:]) >= 0.95 * width * height


def _matrix_codes(image_bytes: bytes) -> list:
    import qr_matrix
    with tempfile.TemporaryDirectory(prefix="swf_parse_") as folder:
        path = Path(folder) / "bitmap.png"
        path.write_bytes(image_bytes)
        found = qr_matrix.decode_path(path, repair=True)
    return [{"format": "qr_code" if item.get("symbology") == "qr" else item.get("symbology", "matrix"),
             "text": item.get("text"), "bytes": item["bytes"],
             "how": "module matrix, repair decode" if item.get("repaired") else "module matrix"}
            for item in found if "bytes" in item]


def find_codes(images: list, *, camera=None, matrix=None, deadline=None, skipped: list | None = None) -> list:
    """[{char_id, tag, codes}] for each carved bitmap that shows a barcode or matrix code.
    `camera(image_bytes)` is tried first (default carve_stego.decode_codes); a bitmap it reads
    nothing from that looks like a module matrix goes to `matrix(image_bytes)` (default: qr_matrix
    with the repair decode, for a QR with no finders). Past `deadline` no further bitmap is read:
    `skipped` names the first and counts them. A decoder that raises is named there too, never
    swallowed."""
    if camera is None and images and skipped is not None:
        note = vs.code_reader_missing()                 # then _camera_codes finds nothing in any bitmap
        if note and note not in skipped:
            skipped.append(note)
    camera, matrix = camera or _camera_codes, matrix or _matrix_codes
    out, late = [], []
    for image in images:
        label = f"{image['tag']} {image['char_id']}"
        if late or (deadline is not None and time.monotonic() > deadline):
            late.append(label)
            continue
        try:
            codes = camera(image["image"])
            if not codes and _looks_like_modules(image["image"]):
                codes = matrix(image["image"])
        except Exception as exc:
            if skipped is not None:
                skipped.append(f"codes: {label}: decoder failed: {type(exc).__name__}: {exc}")
            continue
        if codes:
            out.append({"char_id": image["char_id"], "tag": image["tag"], "codes": codes})
    if late and skipped is not None:                    # one note, not one a bitmap: a movie can hold thousands
        skipped.append(f"codes: out of time before {late[0]}; {len(late)} bitmap(s) were not read for codes")
    return out


# ---- the whole movie -------------------------------------------------------------------------------

def parse(data: bytes, deadline=None) -> dict:
    """A static summary of a movie: {header, frame_size, frame_rate, frame_count, tags, blocks,
    strings, urls, constants, has_doabc, error, cut}. `blocks` is one {label, offset, disassembly}
    per AVM1 block. A tag that runs past the body ends the walk: what was read before it is kept
    and `error` names it. The disassembly is capped over the whole movie, not per block
    (MAX_ACTIONS records, MAX_CODE bytes of action code, MAX_MOVIE_NODES values in its constants,
    `deadline`): a small compressed file can hold a hundred megabytes of one-byte actions, and
    each kept record costs hundreds of bytes. `cut` lists what the caps left out, and a block
    whose disassembly fails (its bytes are still searched by the caller). SWFError when the
    header or the body itself is unusable."""
    return _parse(data, deadline)[0]


def _parse(data: bytes, deadline=None) -> tuple:
    """(summary, header with the trailing bytes, body, walked tags)."""
    header, body = decompress(data)
    rect, pos = read_rect(body, 0)
    if pos + 4 > len(body):
        raise SWFError("SWF body ends inside its frame header")
    rate, frames = struct.unpack_from("<HH", body, pos)
    walked, error = walk(body)
    tags = [{"code": code, "name": name, "offset": offset, "length": len(tag), "depth": depth}
            for code, name, tag, offset, depth in walked]
    blocks, cut = [], []
    left, room, nodes = MAX_ACTIONS, MAX_CODE, MAX_MOVIE_NODES
    pending = action_blocks(walked)
    for k, (label, offset, code) in enumerate(pending):
        why = (f"the cap of {MAX_ACTIONS} actions a movie was reached" if left <= 0
               else f"the cap of {MAX_CODE} bytes of action code a movie was reached" if room <= 0
               else "out of time" if deadline is not None and time.monotonic() > deadline else None)
        if why:
            cut.append(f"{len(pending) - k} AVM1 block(s), from {label} at {offset:#x} on, were not disassembled: {why}")
            break
        try:
            dis = disassemble(code, max_actions=left, max_bytes=room, deadline=deadline, max_nodes=nodes)
        except Exception as exc:                        # a reader's bug on a hostile stream costs that block only
            cut.append(f"{label} at {offset:#x}: the disassembly failed ({type(exc).__name__}: {_clip(str(exc))}); "
                       "the block is still searched as bytes")
            continue
        left -= len(dis["actions"])
        room -= dis["consumed"]
        nodes -= dis["nodes"]
        if dis["cut"]:
            cut.append(f"{label} at {offset:#x}: {dis['cut']}")
        cut += [f"{label} at {offset:#x}: {note}" for note in dis["left_out"]]
        blocks.append({"label": label, "offset": offset, "disassembly": dis})
    strings, urls, constants = [], [], []
    for block in blocks:
        dis = block["disassembly"]
        strings += dis["strings"]
        urls += dis["urls"]
        constants += [{**row, "block": block["label"]} for row in dis["constants"]]
    strings += tag_strings(walked)
    summary = {"header": {k: v for k, v in header.items() if k != "trailing_bytes"}, "frame_size": rect,
               "frame_rate": rate / 256, "frame_count": frames, "tags": tags, "blocks": blocks,
               "strings": list(dict.fromkeys(strings))[:MAX_STRINGS], "urls": list(dict.fromkeys(urls)),
               "constants": constants, "has_doabc": any(t["code"] == 82 for t in tags), "error": error,
               "cut": cut}
    return summary, header, body, walked


# ---- one delivery ----------------------------------------------------------------------------------

@dataclass
class Movie:
    file: str
    summary: dict                     # parse()
    images: list                      # extract_images()
    codes: list                       # find_codes()
    flags: list = field(default_factory=list)          # [(flag, evidence kind, where)]


@dataclass
class Report:
    movies: list = field(default_factory=list)
    written: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


def is_swf(data: bytes) -> bool:
    return data[:3] in (b"FWS", b"CWS", b"ZWS") and len(data) >= 8 and 1 <= data[3] <= 60


def examine(files: dict, ff, *, out_dir: Path | None = None, deadline=None, camera=None, matrix=None) -> Report:
    """Read every SWF of {name: bytes}. Flags are searched in the decompressed body, in bytes
    appended after the movie, and in every decoded code. With out_dir, the listing, constants,
    strings and bitmaps of each movie are written there."""
    rep = Report()
    for name in sorted(files):
        data = files[name]
        if not is_swf(data):
            continue
        try:
            summary, header, body, walked = _parse(data, deadline)
        except SWFError as exc:
            rep.skipped.append(f"{name}: not read as a SWF: {exc}")
            continue
        try:
            images, notes = extract_images(data, walked, deadline)
        except ImportError as exc:
            images, notes = [], [f"bitmaps not rebuilt: Pillow is not importable (py:PIL): {exc}"]
        rep.skipped += [f"{name}: {note}" for note in notes]
        if summary["error"]:
            rep.skipped.append(f"{name}: tag walk stopped early, what came before it was read: {summary['error']}")
        rep.skipped += [f"{name}: AVM1: {note}" for note in summary["cut"]]
        codes = find_codes(images, camera=camera, matrix=matrix, deadline=deadline, skipped=rep.skipped)
        movie = Movie(name, summary, images, codes)
        seen = set()

        def add(found, kind, where):
            for flag in found:
                if flag not in seen:
                    seen.add(flag)
                    movie.flags.append((flag, kind, where))

        add(ff.find_flags(body), "carve", "the decompressed body")
        add(ff.find_flags(header["trailing_bytes"]), "carve", f"{header['trailing']} bytes appended after the movie")
        for hit in codes:
            for code in hit["codes"]:
                add(ff.find_flags(code["text"] if code.get("text") else code.get("bytes", b"")), "decode",
                    f"{code.get('format', 'code')} in {hit['tag']} {hit['char_id']} ({code.get('how', 'decoded')})")
        rep.movies.append(movie)
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            stem = vs.safe_name(name)
            if summary["blocks"]:
                parts, room = [], MAX_LISTING
                for k, block in enumerate(summary["blocks"]):
                    if room <= 0:
                        rep.skipped.append(f"{name}: AVM1: the listing of {len(summary['blocks']) - k} block(s), from "
                                           f"{block['label']} at {block['offset']:#x} on, was not written: the cap of "
                                           f"{MAX_LISTING} characters a movie's listing was reached")
                        break
                    parts.append(f"== {block['label']} at {block['offset']:#x}\n{listing(block['disassembly'], limit=room)}\n")
                    room -= len(parts[-1])
                rep.written.append(_write(out_dir / f"{stem}.avm1.txt", "".join(parts).encode("utf-8")))
            if summary["constants"]:
                path = out_dir / f"{stem}.constants.json"
                with path.open("w", encoding="utf-8") as handle:     # streamed: dumps() would hold every chunk
                    json.dump(summary["constants"], handle, ensure_ascii=False, indent=1)     # of a million values
                rep.written.append(path)
            if summary["strings"]:
                rep.written.append(_write(out_dir / f"{stem}.strings.txt", "\n".join(summary["strings"]).encode("utf-8") + b"\n"))
            for image in images:
                ext = {"jpeg": "jpg"}.get(image["kind"], image["kind"])
                rep.written.append(_write(out_dir / f"{stem}.char{image['char_id']}.{ext}", image["image"]))
    return rep


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _constant_line(row: dict) -> str:
    value = row["value"]
    size = f"{len(value)} values" if isinstance(value, (list, dict)) else _clip(repr(value), 80)
    return f"{row['name'] or '(unassigned)'} ({size})"


def result_of(rep: Report, *, challenge_id=None, seconds: float = 0.0, root: Path | None = None):
    """The SolverResult of a Report (status rules in the module docstring)."""
    from ctf.result import Cost, Evidence, SolverResult

    def rel(p):
        try:
            return str(Path(p).relative_to(root)) if root else str(p)
        except ValueError:
            return str(p)

    flags, evidence, notes = [], [], []
    for movie in rep.movies:
        s = movie.summary
        for flag, kind, where in movie.flags:
            flags.append(flag)
            evidence.append(Evidence(kind, f"flag in {where}", path=movie.file))
        h = s["header"]
        line = (f"{movie.file}: {h['signature']} v{h['version']} ({h['compression']}), {len(s['tags'])} tags, "
                f"{len(s['blocks'])} AVM1 block(s), {len(s['strings'])} strings, {len(movie.images)} bitmap(s)")
        if s["constants"]:
            line += "; constants: " + ", ".join(_constant_line(row) for row in s["constants"][:12])
            line += f" and {len(s['constants']) - 12} more" if len(s["constants"]) > 12 else ""
        if s["urls"]:
            line += "; URLs: " + ", ".join(_clip(url) for url in s["urls"][:8])
        notes.append(line)
        if s["has_doabc"]:
            notes.append(f"{movie.file}: has AVM2 code (DoABC), which this engine does not disassemble")
        if h["trailing"]:
            notes.append(f"{movie.file}: {h['trailing']} bytes are appended after the movie")
        if "length_mismatch" in h:
            notes.append(f"{movie.file}: {h['length_mismatch']}")
        for hit in movie.codes:
            for code in hit["codes"]:
                if not any(flag in str(code.get("text")) for flag, _kind, _where in movie.flags):
                    notes.append(f"{movie.file}: {code.get('format', 'code')} in {hit['tag']} {hit['char_id']} "
                                 f"reads {str(code.get('text'))[:200]!r}")
    for p in rep.written:
        evidence.append(Evidence("carve", "written", path=rel(p)))
    notes += rep.skipped
    flags = list(dict.fromkeys(flags))
    status = vs.status_of(flags, (), material=bool(rep.movies))
    return SolverResult(status=status, flags=flags, evidence=evidence, cost=Cost(seconds=round(seconds, 3)),
                        engine=ENGINE, challenge_id=challenge_id, notes="; ".join(notes))


# ---- the engine contract ---------------------------------------------------------------------------

def solve(challenge_dir: Path, profile, **opts):
    """Engine contract. opts: out (folder for the listing, constants, strings and bitmaps; default
    <challenge>/recon/swf_parse), seconds (budget for the disassembly, for rebuilding bitmaps and
    for reading codes out of them, default 30)."""
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "swf_parse"
    paths, skipped = vs.challenge_paths(challenge_dir, MAX_INPUT)
    files = {}
    for rel, path in paths:
        with path.open("rb") as handle:
            if is_swf(handle.read(8)):
                files[rel] = path.read_bytes()
    rep = examine(files, flagfmt.for_profile(profile), out_dir=out_dir,
                  deadline=t0 + float(opts.get("seconds", DEFAULT_SECONDS)))
    rep.skipped += skipped
    return result_of(rep, seconds=time.monotonic() - t0, root=challenge_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="swf_parse.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--out", type=Path, help="folder for the listing, constants, strings and bitmaps")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    ap.add_argument("--listing", action="store_true", help="print the AVM1 listing of every block")
    a = ap.parse_args(argv)
    from ctf import event
    profile = event.load(a.event) if a.event else event.current()
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"swf_parse.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    files = {str(p): p.read_bytes() for p in a.files}
    not_swf = [name for name, data in files.items() if not is_swf(data)]
    if not_swf:
        print(f"swf_parse.py: not a SWF (no FWS/CWS/ZWS signature): {', '.join(not_swf)}", file=sys.stderr)
        return 2
    rep = examine(files, flagfmt.for_profile(profile), out_dir=a.out, deadline=t0 + a.seconds)
    for movie in rep.movies:
        if a.listing:
            for block in movie.summary["blocks"]:
                print(f"== {movie.file}: {block['label']} at {block['offset']:#x}")
                print(listing(block["disassembly"]), end="")
        for text in movie.summary["strings"][:40]:
            print(f"string: {text!r}")
    for p in rep.written:
        print(f"written: {p}")
    print(result_of(rep, seconds=time.monotonic() - t0).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
