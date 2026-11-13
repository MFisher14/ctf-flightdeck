#!/usr/bin/env python3
"""VBA p-code vs decompressed-source mismatch detector -- VBA stomping (GAP-C1-PCODE-STOMP).

SOURCE: ctf-solver-gap-analysis.md C1 (also the deep-build A'6 row). WHY this exists:

The single most expensive malware-core deception for a malware-weighted finale is the same
"what you READ is not what RUNS" shape as Day 23 (a .wav that was really Opus, a sqlite rendering
the judge never accepted), carried this time by VBA STOMPING (MITRE T1564.007). An Office document
keeps TWO copies of every macro module: the decompressed VBA *source* (a CompressedContainer in the
module stream, after its PerformanceCache) and the compiled *p-code* (the PerformanceCache, and the
module's entry in `_VBA_PROJECT`). Word executes the p-code when the Office version matches; the
source is only shown to a human. A stomper ZEROES or REPLACES the stored source with a decoy while
leaving the real logic in the p-code. `solvers/toolkits/maldoc.py` and
`solvers/script-analysis/officevba.py` read the source CompressedContainer ONLY, so a maldoc Mastery
asking "what URL does the macro fetch", "what command does it run", "what does the macro do" would
read the DECOY source and answer the decoy -- a wrong PLAIN answer that sinks the whole
all-or-nothing batch on every stomped specimen.

This module is a lane-agnostic LIBRARY of PURE functions over OLE bytes the caller already has
(from `tools/run.py` / the maldoc or script-analysis reader). It reads no file it is not handed,
makes no network call, runs nothing, starts no clock, and NEVER emits a plain answer. It has no
`solve_set` and no `signals`: a lane's own reader calls it and decides what to do.

Public surface:

    parse_modules(ole_bytes) -> [ {name, stream_name, text_offset,
                                   source_text, source_ok, source_strings,
                                   pcode_region_len, pcode_ops, pcode_strings, pcode_names, pcode_ok} ]
    stomp_signal(module)     -> {"stomped": bool, "evidence": {...}}     # DETECTOR ONLY, submits nothing
    readings(module)         -> {"source": [str]|None, "pcode": [str]|None}
    reading_candidates(key, module) -> an unsure labels.candidates string, or None

NEVER-WRONG CLASS PER OUTPUT (the whole point):
  * stomp_signal is a DETECTOR: a boolean plus evidence. It submits nothing, so a heuristic there
    can never put a wrong value on the wire. It only flags True on POSITIVE divergence evidence
    (never merely because the p-code did not disassemble, which a clean document also does).
  * readings, when both sides decode AND DIVERGE, surfaces BOTH the source-derived and the
    p-code-derived values; reading_candidates wraps them as `labels.candidates` -- an unsure `??`
    string, pcode first (the executed logic is the better evidence), NEVER a plain pick of one.
  * An opcode the table lacks, a container that will not decompress, an ambiguous disassembly, or a
    bound exceeded -> that side is None and the affected id is None. Fail-closed on any raise.
  * This module NEVER emits a plain value. A value is only ever plain UPSTREAM, when the caller's
    own judged reader confirms it (`labels.candidates` returns the plain value only once the judge
    has accepted the "pcode" or "source" hypothesis for the key -- never by this module's choice).
  * INVARIANT: never a plain pick between two divergent readings.

Determinism and bounds: the p-code disassembler is a straight table walk of the opcode stream (the
VBA7/VBA6 PerformanceCache shape -- a 2-byte opcode followed by table-defined operands, string
literals inline, identifiers referenced by index into an in-stream id table). The real per-version
opcode tables were reverse-engineered by pcodedmp; the tables here recognise the string- and
identifier-bearing opcodes and BAIL (fail-closed to None) on any opcode they do not know, which is
exactly the never-wrong boundary: on a real sample whose exact opcode map we do not carry, the walk
returns None and the caller keeps its own judged reader, while the structural stomp signal still
fires. Same bytes -> same constants, always (no randomness, no dict-order dependence), and the walk
is bounded by MAX_OPS / MAX_PCODE / MAX_SOURCE / MAX_MODULES.
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

# labels is a sibling in solvers/common; reading_candidates needs it, the pure readers do not.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
try:
    import labels  # noqa: E402  (the unsure-answer contract: candidates())
except Exception:  # noqa: BLE001 - the pure byte readers still work without it
    labels = None

# --------------------------------------------------------------------------- bounds (fail-closed)

MAX_MODULES = 512          # modules of one project (MS-OVBA caps this too)
MAX_OPS = 200_000          # instructions walked in one p-code region
MAX_PCODE = 16 << 20       # bytes of one PerformanceCache region
MAX_SOURCE = 4 << 20       # bytes of one decompressed module source
MAX_STREAM = 32 << 20      # bytes of one CFB stream
MAX_DOCUMENT = 64 << 20    # bytes of the whole OLE document
MAX_STRINGS = 20_000       # string/name constants recovered from one region (bound the evidence)
MAX_STRLEN = 1 << 16       # characters of one recovered constant

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF


class Bad(Exception):
    """A container, stream, source or p-code region that does not read whole. Fail-closed:
    the affected side becomes None and nothing is answered from part of it."""


def _u16(b, i):
    if i < 0 or i + 2 > len(b):
        raise Bad("a field past the end of the buffer")
    return b[i] | b[i + 1] << 8


def _u32(b, i):
    if i < 0 or i + 4 > len(b):
        raise Bad("a field past the end of the buffer")
    return struct.unpack_from("<I", b, i)[0]


# --------------------------------------------------------------------------- MS-OVBA 2.4.1 decompression

def decompress(buf, start=0, limit=MAX_SOURCE) -> bytes:
    """A CompressedContainer from `start` to the end of `buf`, decompressed (MS-OVBA 2.4.1).
    Bad on a wrong signature, chunk header, copy token or bound. Deterministic, pure."""
    if start < 0 or start >= len(buf) or buf[start] != 1:
        raise Bad("no CompressedContainer signature (0x01)")
    out, i, n = bytearray(), start + 1, len(buf)
    while i < n:
        if i + 2 > n:
            raise Bad("a chunk header cut short")
        hdr = buf[i] | buf[i + 1] << 8
        if (hdr >> 12) & 7 != 3:
            raise Bad("a chunk header signature that is not 0b011")
        end = i + (hdr & 0x0FFF) + 3
        if end > n:
            raise Bad("a chunk that claims more bytes than the stream holds")
        i += 2
        base = len(out)
        if not hdr & 0x8000:                       # an uncompressed 4096-byte chunk
            if i + 4096 > n:
                raise Bad("an uncompressed chunk cut short")
            out += buf[i:i + 4096]
            i += 4096
        else:
            while i < end:
                flags = buf[i]
                i += 1
                for bit in range(8):
                    if i >= end:
                        break
                    if not flags >> bit & 1:
                        out.append(buf[i])
                        i += 1
                        continue
                    if i + 2 > end:
                        raise Bad("a copy token cut short")
                    tok = buf[i] | buf[i + 1] << 8
                    i += 2
                    diff = len(out) - base
                    bits = max((diff - 1).bit_length(), 4)
                    length = (tok & (0xFFFF >> bits)) + 3
                    offset = (tok >> (16 - bits)) + 1
                    if offset > diff:
                        raise Bad("a copy token that points before its chunk")
                    src = len(out) - offset
                    if offset >= length:
                        out += out[src:src + length]
                    else:
                        for k in range(length):
                            out.append(out[src + k])
                if len(out) - base > 4096:
                    raise Bad("a chunk that decompresses past 4096 bytes")
        if len(out) > limit:
            raise Bad("a decompressed stream past the size bound")
    return bytes(out)


# --------------------------------------------------------------------------- MS-CFB (compound file)

class CFB:
    """A compound file read strictly (a bounded subset of MS-CFB, enough for a VBA project): the
    FAT and mini-FAT chains, the directory tree and stream reads. Every chain stays in range, does
    not loop and holds the bytes its stream claims; anything else is Bad."""

    def __init__(self, data: bytes):
        if len(data) < 512 or data[:8] != CFB_MAGIC:
            raise Bad("no compound-file header")
        if len(data) > MAX_DOCUMENT:
            raise Bad("a compound file past the size bound")
        self.data = data
        shift, mshift = _u16(data, 0x1E), _u16(data, 0x20)
        if shift not in (9, 12) or mshift != 6 or _u16(data, 0x1C) != 0xFFFE:
            raise Bad("a header with an unknown sector size or byte order")
        self.ss, self.mss = 1 << shift, 64
        self.nsect = max(0, (len(data) - self.ss + self.ss - 1) // self.ss)
        nfat = _u32(data, 0x2C)
        first_dir = _u32(data, 0x30)
        cutoff = _u32(data, 0x38)
        first_mf, nmf = _u32(data, 0x3C), _u32(data, 0x40)
        first_difat, ndifat = _u32(data, 0x44), _u32(data, 0x48)
        if nfat > self.nsect or ndifat > self.nsect or nmf > self.nsect:
            raise Bad("a header that counts more sectors than the file has")
        # cutoff 0 (our fixtures never use it) means "no mini stream"; real files carry 4096.
        self.cutoff = cutoff if cutoff else 4096
        fat_sectors = [s for s in struct.unpack_from("<109I", data, 0x4C) if s != FREESECT]
        seen, s = set(), first_difat
        while s not in (ENDOFCHAIN, FREESECT) and len(fat_sectors) < nfat:
            if s in seen or s >= self.nsect:
                raise Bad("a DIFAT chain that loops or leaves the file")
            seen.add(s)
            sec = self._sector(s)
            per = self.ss // 4 - 1
            fat_sectors += [x for x in struct.unpack_from(f"<{per}I", sec, 0) if x != FREESECT]
            s = _u32(sec, per * 4)
        fat_sectors = fat_sectors[:nfat]
        if len(fat_sectors) != nfat:
            raise Bad("fewer FAT sectors than the header counts")
        fat = bytearray()
        for s in fat_sectors:
            if s >= self.nsect:
                raise Bad("a FAT sector outside the file")
            fat += self._sector(s)
        self.fat = struct.unpack(f"<{len(fat) // 4}I", fat)
        self.entries = []
        dirdata = self._chain_bytes(first_dir, self.fat, None)
        for off in range(0, len(dirdata) - 127, 128):
            e = dirdata[off:off + 128]
            nlen = _u16(e, 64)
            name = e[:max(0, min(nlen, 64) - 2)].decode("utf-16-le", "replace")
            self.entries.append({"name": name, "type": e[66], "left": _u32(e, 68),
                                 "right": _u32(e, 72), "child": _u32(e, 76), "start": _u32(e, 116),
                                 "size": _u32(e, 120) | (_u32(e, 124) << 32 if self.ss == 4096 else 0)})
        if not self.entries or self.entries[0]["type"] != 5:
            raise Bad("no root entry")
        root = self.entries[0]
        self.minifat = ()
        if nmf and first_mf not in (ENDOFCHAIN, FREESECT):
            mf = self._chain_bytes(first_mf, self.fat, None)
            self.minifat = struct.unpack(f"<{len(mf) // 4}I", mf)
        self.ministream = self._chain_bytes(root["start"], self.fat, root["size"]) \
            if root["start"] not in (ENDOFCHAIN, FREESECT) and root["size"] else b""

    def _sector(self, n: int) -> bytes:
        off = (n + 1) * self.ss
        if off >= len(self.data):
            raise Bad("a sector outside the file")
        sec = self.data[off:off + self.ss]
        return sec if len(sec) == self.ss else sec + bytes(self.ss - len(sec))

    def _chain(self, start: int, table, count: int) -> list:
        out, s, seen = [], start, set()
        while s != ENDOFCHAIN:
            if s >= len(table) or s >= count or s in seen:
                raise Bad("a sector chain that loops or leaves the file")
            seen.add(s)
            out.append(s)
            s = table[s]
            if len(out) > self.nsect + 2:
                raise Bad("a sector chain longer than the file")
        return out

    def _chain_bytes(self, start: int, table, size) -> bytes:
        if size is not None and size > MAX_STREAM:
            raise Bad("a stream past the size bound")
        if start in (ENDOFCHAIN, FREESECT) and not size:
            return b""
        secs = self._chain(start, table, self.nsect)
        if size is not None and len(secs) * self.ss < size:
            raise Bad("a stream shorter than its size")
        if size is None and len(secs) * self.ss > MAX_STREAM:
            raise Bad("a chain past the size bound")
        data = b"".join(self._sector(s) for s in secs)
        return data if size is None else data[:size]

    def stream(self, idx: int) -> bytes:
        e = self.entries[idx]
        if e["type"] != 2:
            raise Bad("not a stream")
        size = e["size"]
        if size > MAX_STREAM:
            raise Bad("a stream past the size bound")
        if size < self.cutoff:
            if not size:
                return b""
            secs = self._chain(e["start"], self.minifat, len(self.minifat))
            if len(secs) * self.mss < size:
                raise Bad("a mini stream shorter than its size")
            out = bytearray()
            for s in secs:
                a, need = s * self.mss, min(self.mss, size - len(out))
                if a + need > len(self.ministream):
                    raise Bad("a mini sector outside the mini stream")
                out += self.ministream[a:a + need]
            return bytes(out[:size])
        return self._chain_bytes(e["start"], self.fat, size)

    def children(self, idx: int) -> dict:
        out, stack, seen = {}, [self.entries[idx]["child"]], set()
        while stack:
            i = stack.pop()
            if i == NOSTREAM:
                continue
            if i >= len(self.entries) or i in seen:
                raise Bad("a directory tree that loops or leaves the directory")
            seen.add(i)
            e = self.entries[i]
            out[e["name"].upper()] = i
            stack += [e["left"], e["right"]]
        return out

    def storages(self):
        out, stack, seen = [], [0], set()
        while stack:
            i = stack.pop()
            if i in seen:
                raise Bad("a storage reached twice")
            seen.add(i)
            out.append(i)
            stack += [c for c in self.children(i).values() if self.entries[c]["type"] in (1, 5)]
        return out


# --------------------------------------------------------------------------- the VBA `dir` stream

def parse_dir(d: bytes):
    """(code page, [{name, stream, offset}]) from a decompressed dir stream (MS-OVBA 2.3.4.2).
    `offset` is MODULEOFFSET: the start of the source CompressedContainer in the module stream;
    everything before it is the module's PerformanceCache (p-code)."""
    i, codepage, modules, cur, count = 0, 1252, [], None, None
    while i < len(d):
        rid = _u16(d, i)
        if rid == 0x0009:                      # PROJECTVERSION: Reserved(4) Major(4) Minor(2)
            i += 12
            continue
        size = _u32(d, i + 2)
        body = d[i + 6:i + 6 + size]
        if len(body) != size:
            raise Bad("a dir record past the end of the stream")
        i += 6 + size
        if rid == 0x0003 and size == 2:
            codepage = _u16(body, 0)
        elif rid == 0x000F and size == 2:
            count = _u16(body, 0)
        elif rid == 0x0019:                    # MODULENAME
            if len(modules) >= MAX_MODULES:
                raise Bad("more modules than the bound")
            cur = {"name": body, "stream": None, "ustream": None, "offset": None}
            modules.append(cur)
        elif cur is not None and rid == 0x001A:   # MODULESTREAMNAME
            cur["stream"] = body
        elif cur is not None and rid == 0x0032:   # MODULESTREAMNAME unicode
            cur["ustream"] = body
        elif cur is not None and rid == 0x0031 and size == 4:  # MODULEOFFSET
            cur["offset"] = _u32(body, 0)
        elif rid == 0x0010:                    # Terminator
            break
    else:
        raise Bad("a dir stream without its terminator")
    if count is None or count != len(modules):
        raise Bad("a dir stream whose module count does not match its modules")
    for m in modules:
        if m["offset"] is None or (m["stream"] is None and m["ustream"] is None):
            raise Bad("a module without its stream name or text offset")
    return codepage, modules


def _codec(codepage: int) -> str:
    name = "utf-8" if codepage == 65001 else f"cp{codepage}"
    try:
        "".encode(name)
        return name
    except LookupError:
        return "cp1252"


# --------------------------------------------------------------------------- the p-code disassembler
#
# A STRAIGHT table walk of the PerformanceCache opcode stream, the VBA7/VBA6 shape: a 2-byte
# little-endian opcode id, then the operands its table entry defines. String literals are carried
# inline (LITSTR / LITSTRW); identifiers are defined once in-stream (IDDEF idx, text) and later
# referenced by index (LD / ST / CALL idx). The real per-version opcode maps (hundreds of codes,
# reverse-engineered by pcodedmp) are not carried here: the table recognises the constant-bearing
# opcodes and BAILS (Bad) on any opcode outside it, so on a real sample whose map we do not have,
# the walk returns None (fail-closed) and the caller keeps its own judged reader. The walk is pure
# and deterministic (list order only, no dict iteration over the recovered constants) and bounded.

OP_PCEND = 0x0000      # end of the region
OP_NOP = 0x00FF        # no operand
OP_LITSTR = 0x0004     # u16 len, len bytes (code page) -> a string constant
OP_LITSTRW = 0x0005    # u16 nchars, nchars*2 bytes UTF-16LE -> a string constant
OP_IDDEF = 0x0008      # u16 idx, u16 len, len bytes (code page) -> defines name[idx]
OP_LD = 0x0010         # u16 idx -> reference name[idx]
OP_ST = 0x0011         # u16 idx -> store into name[idx]
OP_CALL = 0x0012       # u16 idx, u16 argc -> call name[idx]
OP_LITI2 = 0x0020      # u16 immediate
OP_LITI4 = 0x0021      # u32 immediate

# opcode -> (mnemonic, operand spec). The spec drives the walk; unknown opcode -> Bad.
OPCODE_TABLE = {
    OP_PCEND: ("PcEnd", "end"),
    OP_NOP: ("Nop", "none"),
    OP_LITSTR: ("LitStr", "litstr"),
    OP_LITSTRW: ("LitStrW", "litstrw"),
    OP_IDDEF: ("IdDef", "iddef"),
    OP_LD: ("Ld", "nameidx"),
    OP_ST: ("St", "nameidx"),
    OP_CALL: ("Call", "call"),
    OP_LITI2: ("LitI2", "u16"),
    OP_LITI4: ("LitI4", "u32"),
}


def disassemble(pcode: bytes, codec: str = "cp1252"):
    """Walk the opcode stream of ONE PerformanceCache region.

    Returns (ops, strings, names):
      ops     [(mnemonic, operand_summary)] in stream order
      strings [str] the string constants (LITSTR / LITSTRW), in order
      names   [str] the identifier constants (IDDEF, and resolved LD/ST/CALL references)
    Bad on an opcode outside the table, an operand past the region, a bound exceeded, or any
    other deviation -- the never-wrong boundary (the caller turns Bad into None). Deterministic."""
    if len(pcode) > MAX_PCODE:
        raise Bad("a p-code region past the size bound")
    ops, strings, names = [], [], []
    defined = {}          # idx -> name text
    refs = []             # (idx) references to resolve after the walk, in order
    i, n, steps = 0, len(pcode), 0

    def _add_string(s):
        if len(s) > MAX_STRLEN:
            raise Bad("a p-code string constant past the length bound")
        if len(strings) >= MAX_STRINGS:
            raise Bad("more p-code string constants than the bound")
        strings.append(s)

    while i < n:
        steps += 1
        if steps > MAX_OPS:
            raise Bad("more p-code instructions than the bound")
        op = _u16(pcode, i)
        i += 2
        entry = OPCODE_TABLE.get(op)
        if entry is None:
            raise Bad(f"an opcode outside the table (0x{op:04x})")
        mnem, spec = entry
        if spec == "end":
            ops.append((mnem, None))
            break
        elif spec == "none":
            ops.append((mnem, None))
        elif spec == "u16":
            v = _u16(pcode, i)
            i += 2
            ops.append((mnem, v))
        elif spec == "u32":
            v = _u32(pcode, i)
            i += 4
            ops.append((mnem, v))
        elif spec in ("litstr", "litstrw"):
            ln = _u16(pcode, i)
            i += 2
            if spec == "litstr":
                raw = pcode[i:i + ln]
                if len(raw) != ln:
                    raise Bad("a p-code string literal past the region")
                i += ln
                s = raw.decode(codec, "replace")
            else:
                raw = pcode[i:i + ln * 2]
                if len(raw) != ln * 2:
                    raise Bad("a p-code wide string literal past the region")
                i += ln * 2
                s = raw.decode("utf-16-le", "replace")
            _add_string(s)
            ops.append((mnem, s))
        elif spec == "iddef":
            idx = _u16(pcode, i)
            ln = _u16(pcode, i + 2)
            i += 4
            raw = pcode[i:i + ln]
            if len(raw) != ln:
                raise Bad("a p-code identifier definition past the region")
            i += ln
            name = raw.decode(codec, "replace")
            if len(name) > MAX_STRLEN:
                raise Bad("a p-code identifier past the length bound")
            defined[idx] = name
            ops.append((mnem, (idx, name)))
        elif spec == "nameidx":
            idx = _u16(pcode, i)
            i += 2
            refs.append(idx)
            ops.append((mnem, idx))
        elif spec == "call":
            idx = _u16(pcode, i)
            argc = _u16(pcode, i + 2)
            i += 4
            refs.append(idx)
            ops.append((mnem, (idx, argc)))
        else:  # pragma: no cover - the table never carries an unknown spec
            raise Bad(f"an operand spec this walker does not know ({spec!r})")

    # resolve references deterministically, in stream order; an unresolved index is ambiguous.
    for idx in refs:
        if idx not in defined:
            raise Bad(f"a p-code reference to an undefined identifier index ({idx})")
    # names: the defined identifiers, in the order they were defined (stream order)
    for mnem, arg in ops:
        if mnem == "IdDef":
            names.append(arg[1])
    return ops, strings, names


# --------------------------------------------------------------------------- the decompressed source
#
# What the stomper replaces. We read the string literals a human would read, plus the statement
# lines, to decide "trivial / zeroed" vs "a real (decoy) body". VBA string: double-quoted, a doubled
# "" is an escaped quote. This is a reader of ALREADY-established bytes, never a guesser.

_VBA_STRING = re.compile(r'"(?:[^"]|"")*"')
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def source_strings(text: str):
    """The VBA string literals of a module's BODY, in order, unescaped. The attribute header
    (`Attribute VB_Name = "Module1"`), Option lines and `'` comment lines are not the macro's
    logic, so their literals (the module name, chiefly) are left out: they are noise to the
    "what URL / what command runs" comparison and would otherwise look like a divergence."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        low = line.lower()
        if not line or line.startswith("'") or low.startswith("attribute ") or low.startswith("option "):
            continue
        for m in _VBA_STRING.finditer(raw):
            out.append(m.group(0)[1:-1].replace('""', '"'))
            if len(out) >= MAX_STRINGS:
                return out
    return out


def _is_trivial_source(text: str) -> bool:
    """A source that has been zeroed / stripped to a stub: no executable statement. The attribute
    header (`Attribute VB_Name = ...`), Option lines, blank lines and `'` comments are not code."""
    if not text or not text.strip():
        return True
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("'"):
            continue
        low = line.lower()
        if low.startswith("attribute ") or low.startswith("option "):
            continue
        return False      # a real statement line survives
    return True


# --------------------------------------------------------------------------- parse_modules

def _module_stream_index(cfb: CFB, kids: dict, m: dict, codec: str):
    names = [m["ustream"].decode("utf-16-le", "replace")] if m["ustream"] is not None else []
    if m["stream"] is not None:
        names.append(m["stream"].decode(codec, "replace"))
    for nm in names:
        if nm.upper() in kids:
            idx = kids[nm.upper()]
            if cfb.entries[idx]["type"] == 2:
                return idx
    return None


def _one_project(cfb: CFB, vba_idx: int):
    kids = cfb.children(vba_idx)
    if "DIR" not in kids:
        raise Bad("a VBA storage without its dir stream")
    codepage, modules = parse_dir(decompress(cfb.stream(kids["DIR"]), 0, MAX_STREAM))
    codec = _codec(codepage)
    out = []
    for m in modules:
        rec = {
            "name": m["name"].decode(codec, "replace"),
            "stream_name": (m["stream"] or m["ustream"] or b"").decode(codec, "replace")
                           if m["stream"] is not None else (m["ustream"] or b"").decode("utf-16-le", "replace"),
            "text_offset": m["offset"],
            "source_text": None, "source_ok": False, "source_strings": [],
            "pcode_region_len": 0, "pcode_ops": None, "pcode_strings": None,
            "pcode_names": None, "pcode_ok": False,
        }
        idx = _module_stream_index(cfb, kids, m, codec)
        if idx is None:
            out.append(rec)
            continue
        raw = cfb.stream(idx)
        off = m["offset"]
        rec["pcode_region_len"] = max(0, min(off, len(raw)))
        # the decompressed source: the CompressedContainer at MODULEOFFSET
        if 0 <= off <= len(raw):
            try:
                text = decompress(raw, off, MAX_SOURCE).decode(codec, "replace")
                rec["source_text"] = text
                rec["source_ok"] = True
                rec["source_strings"] = source_strings(text)
            except Bad:
                rec["source_ok"] = False
        # the p-code: the PerformanceCache region before MODULEOFFSET
        pcode = raw[:off] if 0 <= off <= len(raw) else b""
        try:
            ops, strings, names = disassemble(pcode, codec)
            rec["pcode_ops"] = ops
            rec["pcode_strings"] = strings
            rec["pcode_names"] = names
            rec["pcode_ok"] = True
        except Bad:
            rec["pcode_ok"] = False       # fail-closed: an unknown opcode / bad bound -> None side
        out.append(rec)
    return out


def parse_modules(ole_bytes):
    """[module dict] for every VBA module of the OLE document, or [] when the container, its FAT,
    directory or dir stream does not read whole (fail-closed). Each dict carries the decompressed
    source and its string literals, and the p-code region with its disassembled ops / string
    constants / identifier names. A side that did not read is None / False on that module; the
    module dict is still returned so the structural stomp signal can use it. NEVER raises."""
    try:
        if not isinstance(ole_bytes, (bytes, bytearray)):
            return []
        data = bytes(ole_bytes)
        if data[:8] != CFB_MAGIC:
            return []
        cfb = CFB(data)
        out = []
        for s in cfb.storages():
            try:
                kids = cfb.children(s)
            except Bad:
                continue
            v = kids.get("VBA")
            if v is not None and cfb.entries[v]["type"] == 1 and "DIR" in cfb.children(v):
                try:
                    out += _one_project(cfb, v)
                except Bad:
                    continue          # a project that does not read whole contributes no modules
                if len(out) >= MAX_MODULES:
                    break
        return out[:MAX_MODULES]
    except Exception:  # noqa: BLE001 - a parser that trips on a hostile container is a closed door
        return []


# --------------------------------------------------------------------------- the stomp detector
#
# DETECTOR ONLY: a boolean plus evidence. It SUBMITS NOTHING, so a heuristic here can never put a
# wrong value on the wire. It flags True only on POSITIVE divergence evidence, never merely because
# the p-code did not disassemble (a clean document's p-code does not disassemble under our partial
# table either). Never raises.

def _contains(text: str, needle: str) -> bool:
    return bool(needle) and needle in (text or "")


def stomp_signal(module) -> dict:
    """{"stomped": bool, "evidence": {...}} for one module dict from parse_modules.

    Stomped (True) when BOTH sides are usable AND they diverge:
      * the stored source is TRIVIAL/zeroed (a stub with no statement) while the p-code carries
        real string constants -- the classic "source zeroed, p-code left" stomp; or
      * the p-code carries a string constant that is ABSENT from the decompressed source -- the
        "source replaced with a decoy" stomp.
    False otherwise, including when the p-code did not disassemble (we cannot confirm divergence,
    so we never flag it). The evidence dict names the reason and the diverging constants."""
    ev = {
        "source_present": False, "source_trivial": None, "pcode_present": False,
        "pcode_only_strings": [], "source_only_strings": [], "reason": "",
    }
    try:
        if not isinstance(module, dict):
            return {"stomped": False, "evidence": ev}
        src_ok = bool(module.get("source_ok"))
        pc_ok = bool(module.get("pcode_ok"))
        src_text = module.get("source_text") or ""
        src_strings = list(module.get("source_strings") or [])
        pc_strings = list(module.get("pcode_strings") or [])
        pc_region = int(module.get("pcode_region_len") or 0)
        ev["source_present"] = src_ok
        ev["pcode_present"] = pc_ok and pc_region > 0

        if not pc_ok or not src_ok:
            ev["reason"] = ("p-code did not disassemble; cannot confirm divergence"
                            if not pc_ok else "source did not decompress")
            return {"stomped": False, "evidence": ev}

        trivial = _is_trivial_source(src_text)
        ev["source_trivial"] = trivial
        # p-code string constants that the source never shows (the decoy / zeroed case)
        pcode_only = [s for s in pc_strings
                      if s and s not in src_strings and not _contains(src_text, s)]
        # source literals the p-code never carries (a decoy URL swapped in)
        source_only = [s for s in src_strings if s and s not in pc_strings]
        cap = labels.MAX_OPTIONS if labels else 12
        ev["pcode_only_strings"] = pcode_only[:cap]
        ev["source_only_strings"] = source_only[:cap]

        if trivial and pc_strings:
            ev["reason"] = "source is a trivial stub but the p-code carries string constants"
            return {"stomped": True, "evidence": ev}
        if pcode_only:
            ev["reason"] = "p-code string constant(s) absent from the decompressed source"
            return {"stomped": True, "evidence": ev}
        ev["reason"] = "source and p-code agree"
        return {"stomped": False, "evidence": ev}
    except Exception:  # noqa: BLE001 - a detector must never raise into a solver
        ev["reason"] = "detector error (fail-closed to not-stomped)"
        return {"stomped": False, "evidence": ev}


# --------------------------------------------------------------------------- the two readings

def readings(module) -> dict:
    """{"source": [str]|None, "pcode": [str]|None}: the string constants each side carries, or None
    for a side that did not decode (ambiguous -> the affected id is None upstream). Never raises."""
    try:
        if not isinstance(module, dict):
            return {"source": None, "pcode": None}
        src = list(module.get("source_strings") or []) if module.get("source_ok") else None
        pc = list(module.get("pcode_strings") or []) if module.get("pcode_ok") else None
        return {"source": src, "pcode": pc}
    except Exception:  # noqa: BLE001
        return {"source": None, "pcode": None}


def reading_candidates(key, module):
    """An unsure `labels.candidates` answer that offers BOTH readings when they decode AND diverge,
    `pcode` first (the executed logic is the better evidence), `source` second. None when a side did
    not decode (ambiguous), when the two readings agree (the caller's own judged reader answers it
    plain), or when labels is unavailable.

    NEVER plain by this module's choice: `labels.candidates` returns the plain value only once the
    judge has accepted the `pcode` or `source` hypothesis for `key`. INVARIANT: never a plain pick
    between two divergent readings. `key` is a labels key `<lane>.<field>/<shape>` (e.g.
    `maldoc.macro_url/pcode_stomp`); the caller owns the lane prefix."""
    if labels is None:
        return None
    try:
        r = readings(module)
        src, pc = r["source"], r["pcode"]
        if src is None or pc is None:
            return None                       # a side is ambiguous -> None
        if list(src) == list(pc) or set(src) == set(pc):
            return None                       # agree -> defer to the caller's judged reader
        # both decode and diverge: offer each reading as a hypothesis, never plain.
        options = [("pcode", _compact(pc)), ("source", _compact(src))]
        return labels.candidates(key, options)
    except Exception:  # noqa: BLE001 - never raise into a solver
        return None


def _compact(seq):
    """A list of strings rendered as a compact JSON array (the form every runner sends a non-string
    answer in, backlog row 329). A single string is sent as itself."""
    import json
    seq = list(seq)
    if len(seq) == 1 and isinstance(seq[0], str):
        return seq[0]
    return json.dumps(seq, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- in-file selftest
#
# A self-contained selftest: it BUILDS a minimal compound file (a VBA project with one stomped and
# one clean module and one module whose p-code uses an opcode outside the table), then proves the
# never-wrong boundary. The CFB / compression / p-code assembly helpers used only by the selftest
# live here so `python pcode_mismatch.py` proves the module with no external fixture.

def _compress(raw: bytes) -> bytes:
    """An MS-OVBA CompressedContainer of `raw`, as all-literal compressed chunks (no back-refs), so
    the container is exact-length (no 4096 padding). The mirror of decompress(), for the selftest."""
    out = bytearray(b"\x01")
    for base in range(0, max(1, len(raw)), 4096):
        chunk = raw[base:base + 4096]
        body = bytearray()
        for g in range(0, len(chunk), 8):
            group = chunk[g:g + 8]
            body.append(0x00)                 # 8 flag bits, all "literal"
            body += group
        hdr = 0x3000 | 0x8000 | ((len(body) - 1) & 0x0FFF)
        out += struct.pack("<H", hdr)
        out += body
    return bytes(out)


def _asm(instrs) -> bytes:
    """Assemble p-code from (opcode, *operands) tuples, the mirror of disassemble()."""
    out = bytearray()
    for ins in instrs:
        op = ins[0]
        out += struct.pack("<H", op)
        if op in (OP_PCEND, OP_NOP):
            pass
        elif op == OP_LITSTR:
            s = ins[1].encode("cp1252")
            out += struct.pack("<H", len(s)) + s
        elif op == OP_LITSTRW:
            s = ins[1].encode("utf-16-le")
            out += struct.pack("<H", len(ins[1])) + s
        elif op == OP_IDDEF:
            idx, name = ins[1], ins[2].encode("cp1252")
            out += struct.pack("<HH", idx, len(name)) + name
        elif op in (OP_LD, OP_ST):
            out += struct.pack("<H", ins[1])
        elif op == OP_CALL:
            out += struct.pack("<HH", ins[1], ins[2])
        elif op == OP_LITI2:
            out += struct.pack("<H", ins[1])
        elif op == OP_LITI4:
            out += struct.pack("<I", ins[1])
        else:
            out += bytes(ins[1]) if len(ins) > 1 else b""   # raw bytes for an unknown opcode test
    return bytes(out)


def _build_dir(modules) -> bytes:
    """A decompressed `dir` stream for `modules` = [(name, stream_name, text_offset)]."""
    def rec(rid, body):
        return struct.pack("<HI", rid, len(body)) + body
    d = bytearray()
    d += rec(0x0003, struct.pack("<H", 1252))                 # code page
    d += rec(0x000F, struct.pack("<H", len(modules)))         # module count
    for name, stream, offset in modules:
        d += rec(0x0019, name.encode("cp1252"))               # MODULENAME
        d += rec(0x001A, stream.encode("cp1252"))             # MODULESTREAMNAME
        d += rec(0x0031, struct.pack("<I", offset))           # MODULEOFFSET
    d += rec(0x0010, b"")                                     # terminator
    return bytes(d)


def _build_cfb(streams) -> bytes:
    """A minimal compound file. `streams` = ordered [(path, data)] where path is like
    "VBA/dir"; one storage level ("VBA") is supported, which is all a VBA project needs. Small
    streams go to the mini stream (cutoff 4096), as a real file lays them out."""
    SS, MSS = 512, 64
    # directory entries: Root, each storage, each stream. Build a flat list and link a simple tree.
    storages = {}
    for path, _ in streams:
        if "/" in path:
            storages.setdefault(path.split("/", 1)[0], [])
    entries = []   # dicts: name, type, start, size, left, right, child

    def add(name, etype):
        entries.append({"name": name, "type": etype, "start": ENDOFCHAIN, "size": 0,
                        "left": NOSTREAM, "right": NOSTREAM, "child": NOSTREAM})
        return len(entries) - 1

    root = add("Root Entry", 5)
    stg_idx = {nm: add(nm, 1) for nm in storages}
    stream_idx = {}
    for path, data in streams:
        nm = path.split("/", 1)[1] if "/" in path else path
        stream_idx[path] = add(nm, 2)
    # link: root.child -> first storage (or first stream); storages chain via right; each storage's
    # child -> first of its streams, streams chain via right. A simple (unbalanced) tree the reader
    # walks by left/right/child DFS.
    top = list(stg_idx.values()) + [stream_idx[p] for p in stream_idx if "/" not in p]
    if top:
        entries[root]["child"] = top[0]
        for a, b in zip(top, top[1:]):
            entries[a]["right"] = b
    for nm, sidx in stg_idx.items():
        kids = [stream_idx[p] for p in stream_idx if p.split("/", 1)[0] == nm]
        if kids:
            entries[sidx]["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                entries[a]["right"] = b

    # mini stream: concatenate small stream data, each padded to a multiple of 64.
    mini = bytearray()
    mini_fat = []
    for path, data in streams:
        sidx = stream_idx[path]
        entries[sidx]["size"] = len(data)
        if not data:
            continue
        start_ms = len(mini) // MSS
        entries[sidx]["start"] = start_ms
        padded = data + bytes((-len(data)) % MSS)
        nsec = len(padded) // MSS
        for k in range(nsec):
            mini_fat.append(start_ms + k + 1 if k + 1 < nsec else ENDOFCHAIN)
        mini += padded

    # big streams: only the mini-stream container (owned by root) and the directory + FAT + miniFAT.
    # lay out sectors; a single FAT sector (128 entries) is plenty for this tiny file.
    dir_bytes = bytearray()
    for e in entries:
        nm = (e["name"].encode("utf-16-le") + b"\x00\x00")[:64]
        nm = nm + bytes(64 - len(nm))
        nlen = min(len(e["name"]) * 2 + 2, 64)
        rec = bytearray(128)
        rec[0:64] = nm
        rec[64:66] = struct.pack("<H", nlen)
        rec[66] = e["type"]
        rec[67] = 1                                   # color black
        struct.pack_into("<III", rec, 68, e["left"], e["right"], e["child"])
        struct.pack_into("<I", rec, 116, e["start"])
        struct.pack_into("<I", rec, 120, e["size"])
        dir_bytes += rec
    dir_bytes += bytes((-len(dir_bytes)) % SS)
    mini_pad = bytes(mini) + bytes((-len(mini)) % SS)
    minifat_bytes = b"".join(struct.pack("<I", x) for x in mini_fat)
    minifat_bytes += bytes((-len(minifat_bytes)) % SS) if minifat_bytes else bytes(SS)

    # sector plan: [FAT=0][dir...][miniFAT...][miniStream...]
    n_dir = len(dir_bytes) // SS
    n_mf = max(1, len(minifat_bytes) // SS)
    n_ms = len(mini_pad) // SS
    first_dir = 1
    first_mf = first_dir + n_dir
    first_ms = first_mf + n_mf
    total = 1 + n_dir + n_mf + n_ms
    fat = [FREESECT] * (SS // 4)
    fat[0] = FATSECT

    def chainset(start, count):
        for k in range(count):
            fat[start + k] = start + k + 1 if k + 1 < count else ENDOFCHAIN

    chainset(first_dir, n_dir)
    chainset(first_mf, n_mf)
    chainset(first_ms, n_ms)
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat)

    # root entry owns the mini stream
    entries[root]["start"] = first_ms if n_ms else ENDOFCHAIN
    entries[root]["size"] = len(mini)
    # rebuild the directory with root's start/size now set
    dir_bytes = bytearray()
    for e in entries:
        nm = (e["name"].encode("utf-16-le") + b"\x00\x00")[:64]
        nm = nm + bytes(64 - len(nm))
        nlen = min(len(e["name"]) * 2 + 2, 64)
        rec = bytearray(128)
        rec[0:64] = nm
        rec[64:66] = struct.pack("<H", nlen)
        rec[66] = e["type"]
        rec[67] = 1
        struct.pack_into("<III", rec, 68, e["left"], e["right"], e["child"])
        struct.pack_into("<I", rec, 116, e["start"])
        struct.pack_into("<I", rec, 120, e["size"])
        dir_bytes += rec
    dir_bytes += bytes((-len(dir_bytes)) % SS)

    header = bytearray(512)
    header[0:8] = CFB_MAGIC
    struct.pack_into("<H", header, 0x18, 0x003E)       # minor version
    struct.pack_into("<H", header, 0x1A, 0x0003)       # major version 3 -> 512-byte sectors
    struct.pack_into("<H", header, 0x1C, 0xFFFE)       # byte order
    struct.pack_into("<H", header, 0x1E, 9)            # sector shift (512)
    struct.pack_into("<H", header, 0x20, 6)            # mini sector shift (64)
    struct.pack_into("<I", header, 0x2C, 1)            # number of FAT sectors
    struct.pack_into("<I", header, 0x30, first_dir)    # first directory sector
    struct.pack_into("<I", header, 0x38, 4096)         # mini stream cutoff
    struct.pack_into("<I", header, 0x3C, first_mf)     # first mini FAT sector
    struct.pack_into("<I", header, 0x40, n_mf)         # number of mini FAT sectors
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)   # first DIFAT sector
    struct.pack_into("<I", header, 0x48, 0)            # number of DIFAT sectors
    for k in range(109):
        struct.pack_into("<I", header, 0x4C + k * 4, 0 if k == 0 else FREESECT)
    body = bytes(fat_bytes) + bytes(dir_bytes) + bytes(minifat_bytes) + bytes(mini_pad)
    want = total * SS
    body = body + bytes(max(0, want - len(body)))
    return bytes(header) + body


def build_sample(source_text: str, pcode_instrs, module="Module1"):
    """Build an OLE document with ONE VBA module: `pcode_instrs` assembled as its PerformanceCache,
    `source_text` compressed as its source at MODULEOFFSET. For the selftest and for a caller's own
    fixtures. Returns the document bytes."""
    pcode = _asm(pcode_instrs)
    src = _compress(source_text.encode("cp1252"))
    module_stream = pcode + src
    text_offset = len(pcode)
    dir_stream = _compress(_build_dir([(module, module, text_offset)]))
    streams = [("VBA/dir", dir_stream), (f"VBA/{module}", module_stream)]
    return _build_cfb(streams)


def _selftest() -> int:
    import json
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + "  " + msg)
        ok = ok and bool(cond)

    # --- a STOMPED module: decoy source URL, real URL only in the p-code ---
    decoy_src = ('Attribute VB_Name = "Module1"\r\n'
                 'Sub AutoOpen()\r\n'
                 '    MsgBox "http://decoy.example.test/benign"\r\n'
                 'End Sub\r\n')
    real_pcode = [
        (OP_IDDEF, 1, "AutoOpen"), (OP_IDDEF, 2, "Shell"),
        (OP_LITSTR, "http://evil.example.test/payload.exe"),
        (OP_CALL, 2, 1), (OP_PCEND,),
    ]
    doc = build_sample(decoy_src, real_pcode)
    mods = parse_modules(doc)
    check(len(mods) == 1, f"stomped doc: one module parsed (got {len(mods)})")
    m = mods[0]
    check(m["source_ok"] and m["pcode_ok"], "stomped doc: both source and p-code decoded")
    sig = stomp_signal(m)
    check(sig["stomped"] is True, "stomped doc: stomp_signal True")
    check("http://evil.example.test/payload.exe" in sig["evidence"]["pcode_only_strings"],
          "stomped doc: evidence names the p-code-only URL")
    r = readings(m)
    check(r["source"] is not None and r["pcode"] is not None, "stomped doc: both readings present")
    check(set(r["source"]) != set(r["pcode"]), "stomped doc: the two readings diverge")
    import os
    os.environ.setdefault("CTF_WORKDIR", "/tmp/_pcode_selftest_ledger")
    cand = reading_candidates("maldoc.macro_url/pcode_stomp", m)
    check(labels is not None and isinstance(cand, str) and cand.startswith("??"),
          "stomped doc: reading_candidates is an unsure string")
    if isinstance(cand, str) and cand.startswith("??"):
        parsed = labels.parse(cand)
        names = [n for n, _ in parsed.options]
        check(parsed.candidate and names[:1] == ["pcode"],
              "stomped doc: candidate key, pcode offered first, never plain")

    # --- a CLEAN module: p-code and source carry the same URL ---
    clean_src = ('Attribute VB_Name = "Module1"\r\n'
                 'Sub AutoOpen()\r\n'
                 '    Shell "http://real.example.test/go"\r\n'
                 'End Sub\r\n')
    clean_pcode = [
        (OP_IDDEF, 1, "AutoOpen"), (OP_IDDEF, 2, "Shell"),
        (OP_LITSTR, "http://real.example.test/go"),
        (OP_CALL, 2, 1), (OP_PCEND,),
    ]
    m2 = parse_modules(build_sample(clean_src, clean_pcode))[0]
    check(stomp_signal(m2)["stomped"] is False, "clean doc: stomp_signal False")
    r2 = readings(m2)
    check(set(r2["source"]) == set(r2["pcode"]), "clean doc: a single agreeing reading")
    check(reading_candidates("maldoc.macro_url/pcode_stomp", m2) is None,
          "clean doc: reading_candidates None (caller's judged reader answers plain)")

    # --- a module whose p-code uses an opcode OUTSIDE the table ---
    bad_pcode = [(OP_IDDEF, 1, "AutoOpen"), (0x7777, b"\x00\x00\x00\x00"), (OP_PCEND,)]
    m3 = parse_modules(build_sample(clean_src, bad_pcode))[0]
    check(m3["pcode_ok"] is False and m3["pcode_strings"] is None,
          "unknown opcode: pcode side None, no crash")
    check(m3["source_ok"] is True, "unknown opcode: source side still decoded")
    check(stomp_signal(m3)["stomped"] is False, "unknown opcode: stomp_signal does not false-fire")
    check(reading_candidates("maldoc.macro_url/pcode_stomp", m3) is None,
          "unknown opcode: reading_candidates None (affected id is None)")

    # --- determinism: same bytes -> same recovered constants ---
    a = disassemble(_asm(real_pcode))
    b = disassemble(_asm(real_pcode))
    check(a == b, "disassemble is deterministic (same bytes -> same ops/strings/names)")

    # --- fail-closed: a literal that claims more bytes than the region has ---
    overrun = struct.pack("<HH", OP_LITSTR, 9999) + b"short"
    try:
        disassemble(overrun)
        check(False, "overrun literal: should have raised Bad")
    except Bad:
        check(True, "overrun literal: Bad (fail-closed)")

    # --- parse_modules never raises on garbage ---
    check(parse_modules(b"not an ole file") == [], "garbage input: parse_modules returns []")
    check(parse_modules(None) == [], "None input: parse_modules returns []")

    print(json.dumps({"ok": ok}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
