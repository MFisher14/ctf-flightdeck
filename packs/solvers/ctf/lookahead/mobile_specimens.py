"""Mobile look-ahead specimens for the B-174 gate: the Thumb and Hermes computed shapes (B-249).

Huntress row 494 (Day 23): the mobile look-ahead staged only named ciphers with their data in the document, never a
code the app COMPUTES, and the armed solver met three such shapes live. B-164 built the 32-bit ARM / Thumb JNI path
and the Hermes string-table reader exists (dynamic_members.hermes_strings), but no look-ahead specimen exercised
either through the gate. This module writes them as a B-174 matrix, built from code here (nothing is a challenge file
or comes from one; every answer is computed by a Python oracle that does not use a solver):

    thumb_jni        codec `analysis`: Release.code() builds 'ANS-' + 16 hex digits from two calls of a
                     `static native int derive(int)` whose only body is a Thumb (T32) function in an armeabi-v7a
                     lib/armeabi-v7a/libarena.so (ELF32, little-endian, the symbol's low bit set)
    hermes_bundle    codec `dynamic`, `data` names assets/index.android.bundle, a Hermes bytecode file whose string
                     table (the 128-byte header, small-string entries, storage) holds the code among other strings
    thumb_gate_fail  control: the same chain, the Thumb body returns 0 (the JNI gate-fail sentinel): no code may be
                     read from it, so the gate must report its id unanswered (a red verdict proves the gate looks)

    write(dest, controls=False) -> Path       the matrix folder (matrix.toml, one folder per specimen, forecast.toml)
    thumb_derive(x), thumb_code(), hermes_code()   the oracles

The specimens are the delivered members unpacked (encoding raw), which codec_search.solve_set reads as the runner's
unpacked files. `forecast.toml` names the ids these specimens ask (forecast.load reads it), so `ctf lookahead score`
can hold a day's qdiff against them.
"""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from ..openers.mobile_splits_synth import (ACC_NATIVE, ACC_PUBLIC, ACC_STATIC, SB, STR, Asm, DexWriter,
                                           jni_symbol)

LANE = "mobile-android"
READER = "solvers/mobile-android/codec_search.py"
PUZZLE = "assets/huntress_puzzle.json"
SO_PATH = "lib/armeabi-v7a/libarena.so"
BUNDLE = "assets/index.android.bundle"
N_CLS, REL_CLS = "Lcom/huntress/la/N;", "Lcom/huntress/la/Release;"
SEEDS = (0x0123, 0x4567)
SYNTAX = "ANS- followed by exactly 16 uppercase hexadecimal characters"
QUESTION = {"id": "answer", "question": "Recover the backend answer code computed by the app.",
            "answer_format": {"kind": "pattern", "syntax": SYNTAX}}
HERMES_MAGIC = 0x1F1903C103BC1FC6

# Thumb (T32): mov r0, r2 ; lsls r0, r0, #3 ; adds r0, #0x5b ; bx lr   (r2 is the first Java int after env, jclass)
THUMB_DERIVE = (0x4610, 0x00C0, 0x305B, 0x4770)
# Thumb: movs r0, #0 ; bx lr   (the gate-fail leg: the JNI function returns 0)
THUMB_ZERO = (0x2000, 0x4770)


def thumb_derive(x: int) -> int:
    return ((x << 3) + 0x5B) & 0xFFFFFFFF


def thumb_code() -> str:
    return "ANS-%08X%08X" % (thumb_derive(SEEDS[0]), thumb_derive(SEEDS[1]))


def hermes_code() -> str:
    return "ANS-" + hashlib.sha256(b"b249:hermes").hexdigest()[:16].upper()


# ----------------------------------------------------------------------------------------- builders

def _thumb(halfwords) -> bytes:
    return struct.pack("<%dH" % len(halfwords), *halfwords)


def elf32_thumb_so(name: str, halfwords) -> bytes:
    """A minimal armeabi-v7a shared object: ELF32 little-endian ET_DYN, machine 40, one executable PT_LOAD over a .text
    at 0x1000 holding the Thumb function, exported as a sized GLOBAL FUNC whose st_value has the Thumb bit set."""
    vaddr = 0x1000
    text = _thumb(halfwords)
    dynstr = b"\0" + name.encode() + b"\0"
    shstr = b"\0.text\0.dynstr\0.dynsym\0.shstrtab\0"
    off = {".text": 1, ".dynstr": 7, ".dynsym": 15, ".shstrtab": 23}
    dynsym = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    dynsym += struct.pack("<IIIBBH", 1, vaddr | 1, len(text), (1 << 4) | 2, 0, 1)
    ehsize, phentsize, shentsize = 52, 32, 40
    o = ehsize + phentsize
    text_off = o
    o += len(text)
    dynstr_off = o
    o += len(dynstr)
    dynsym_off = o
    o += len(dynsym)
    shstr_off = o
    o += len(shstr)
    o += -o % 8
    shoff = o
    secs = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (off[".text"], 1, 6, vaddr, text_off, len(text), 0, 0, 4, 0),
            (off[".dynstr"], 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
            (off[".dynsym"], 11, 0, 0, dynsym_off, len(dynsym), 2, 1, 4, 16),
            (off[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)]
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    hdr = ident + struct.pack("<HHIIIIIHHHHHH", 3, 40, 1, 0, ehsize, shoff, 0x05000000, ehsize, phentsize, 1,
                              shentsize, len(secs), 4)
    phdr = struct.pack("<IIIIIIII", 1, text_off, vaddr, vaddr, len(text), len(text), 5, 4)
    blob = hdr + phdr + text + dynstr + dynsym + shstr
    return blob + b"\0" * (shoff - len(blob)) + b"".join(struct.pack("<10I", *s) for s in secs)


def _hex_tail(d, a) -> None:
    """Return 'ANS-' + the 16 hex digits of the long in v0:v1 (upper case, high nibble first)."""
    a.op("new-instance", 2, d.t(SB)).op("invoke-direct", d.m(SB, "<init>"), [2])
    a.op("const-string", 3, d.s("ANS-")).op("invoke-virtual", d.m(SB, "append", SB, [STR]), [2, 3])
    a.op("const-string", 3, d.s("0123456789ABCDEF")).op("const/16", 4, 60)
    a.label("hex")
    a.op("ushr-long", 6, 0, 4).op("long-to-int", 8, 6).op("and-int/lit8", 8, 8, 15)
    a.op("invoke-virtual", d.m(STR, "charAt", "C", ["I"]), [3, 8]).op("move-result", 9)
    a.op("invoke-virtual", d.m(SB, "append", SB, ["C"]), [2, 9])
    a.op("add-int/lit8", 4, 4, -4).op("if-gez", 4, "hex")
    a.op("invoke-virtual", d.m(SB, "toString", STR), [2]).op("move-result-object", 2).op("return-object", 2)


def native_chain_dex(seeds=SEEDS) -> bytes:
    """Release.code(): (derive(seed_a) << 32) | derive(seed_b) as 16 hex digits, derive a JNI native of N."""
    d = DexWriter()
    d.cls(N_CLS)
    d.cls(REL_CLS)
    nat = d.method(N_CLS, "derive", "I", ["I"], None, flags=ACC_PUBLIC | ACC_STATIC | ACC_NATIVE)
    a = Asm()
    a.op("const/16", 3, seeds[0]).op("invoke-static", nat, [3]).op("move-result", 3)
    a.op("int-to-long", 0, 3).op("const/16", 10, 32).op("shl-long", 0, 0, 10)
    a.op("const/16", 3, seeds[1]).op("invoke-static", nat, [3]).op("move-result", 3)
    a.op("int-to-long", 4, 3).op("or-long", 0, 0, 4)
    _hex_tail(d, a)
    d.method(REL_CLS, "code", STR, [], a.finish(), regs=11)
    return d.build()


def hermes_bytecode(strings) -> bytes:
    """Hermes bytecode with a real string table: the 128-byte header (string count, overflow count, storage size),
    one function header, one string-kind run, the small-string entries (bit 0 utf16, 23 bits offset, 8 bits length)
    and the storage, the strings back to back."""
    storage, small = b"", []
    for text in strings:
        raw = text.encode("latin-1")
        assert len(raw) < 255
        small.append((len(storage) << 1) | (len(raw) << 24))
        storage += raw

    def pad(b):
        return b + b"\0" * (-len(b) % 4)
    n = len(strings)
    body = struct.pack("<4I", 0x40000001, 0x40000002, 0x40000003, 0x40000004) + struct.pack("<I", n)
    body = pad(pad(body + struct.pack("<%dI" % n, *small))) + pad(storage) + b"\0" * 64
    head = bytearray(128)
    struct.pack_into("<QI", head, 0, HERMES_MAGIC, 94)
    struct.pack_into("<8I", head, 32, 128 + len(body), 0, 1, 1, 0, n, 0, len(storage))
    return bytes(head) + body


def _doc(codec: str, **more) -> bytes:
    doc = {"schema": "huntress.mobile.puzzle.v2" if codec == "analysis" else "huntress.mobile.puzzle.v1",
           "day": 32, "codec": codec}
    doc.update(more)
    return json.dumps(doc, sort_keys=True).encode()


def thumb_members(gate_fail: bool = False) -> dict:
    sym = jni_symbol(N_CLS, "derive")
    return {"classes.dex": native_chain_dex(),
            SO_PATH: elf32_thumb_so(sym, THUMB_ZERO if gate_fail else THUMB_DERIVE),
            PUZZLE: _doc("analysis")}


def hermes_members() -> dict:
    return {BUNDLE: hermes_bytecode(["answerCode", "DAY32-BRIDGE:hermes", hermes_code(), "getAnswer"]),
            PUZZLE: _doc("dynamic", data=BUNDLE)}


# ----------------------------------------------------------------------------------------- the matrix

def _specimen(m: Path, name: str, members: dict, key: str | None, note: str) -> None:
    d = m / LANE / name
    for member, body in members.items():
        p = d / "files" / member
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    (d / "questions.json").write_text(json.dumps([QUESTION]), encoding="utf-8")
    if key is not None:
        (d / "key.json").write_text(json.dumps({"answer": key}), encoding="utf-8")
    (d / "specimen.toml").write_text('encoding = ["raw"]\nnote = %s\n' % json.dumps(note), encoding="utf-8")


SPECIMENS = ("thumb_jni", "hermes_bundle")


def write(dest, controls: bool = False, allow_unsure: bool = True, only=None) -> Path:
    """Write the mobile look-ahead matrix under `dest` and return its folder. `controls` adds thumb_gate_fail (a
    specimen whose id must come back unanswered, so the gate is red). `allow_unsure`: the lane answers a code only a
    new capability reads unsure until the judge accepts its route (the Hermes reader), which the gate then reports
    instead of counting as a gap; False holds the lane to plain answers only. `only`: the SPECIMENS to write (all by
    default). The Thumb specimens need the native emulator (Unicorn, through ctypes), which the gate's audit-hook guard
    refuses: under that guard alone the Thumb id comes back unanswered and the gate is red, never silently green."""
    chosen = tuple(SPECIMENS if only is None else only)
    unknown = [s for s in chosen if s not in SPECIMENS]
    if unknown:
        raise ValueError("unknown mobile specimen(s): %s (there are %s)" % (", ".join(unknown), ", ".join(SPECIMENS)))
    m = Path(dest)
    m.mkdir(parents=True, exist_ok=True)
    (m / "matrix.toml").write_text(
        "[lane.%s]\nreader = %s\ntimeout = 60\nallow_unsure = %s\n"
        % (LANE, json.dumps(READER), "true" if allow_unsure else "false"), encoding="utf-8")
    if "thumb_jni" in chosen:
        _specimen(m, "thumb_jni", thumb_members(), thumb_code(),
                  "analysis chain through a Thumb (T32) armeabi-v7a JNI native (B-164 path)")
    if "hermes_bundle" in chosen:
        _specimen(m, "hermes_bundle", hermes_members(), hermes_code(),
                  "a Hermes bytecode string table holds the code (dynamic_members.hermes_strings)")
    if controls:
        _specimen(m, "thumb_gate_fail", thumb_members(gate_fail=True), thumb_code(),
                  "control: the Thumb leg returns the gate-fail 0, so no code may be read")
    (m / "forecast.toml").write_text(
        'day = "b249-mobile"\n[lane.%s]\nnew = ["answer"]\ngaps = []\nnote = %s\n'
        % (LANE, json.dumps("computed shapes: Thumb JNI native, Hermes string table")), encoding="utf-8")
    return m
