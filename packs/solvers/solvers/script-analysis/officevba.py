#!/usr/bin/env python3
"""Macro source out of Office documents (backlog row 93): VBA modules and Excel 4.0 (XLM) macro sheets.

Usage:
  python3 solvers/script-analysis/officevba.py FILE...     print the macro text of each document

Static extraction only, in pure Python: nothing in a document is run, no Office, no olefile.

  OOXML    .docm .dotm .xlsm .xltm .xlam .xlsb .pptm .potm .ppsm .ppam .sldm (and the x forms, which
           hold no macros unless renamed): the zip's vbaProject.bin (any member of that name), read
           as below; and xl/macrosheets/*.xml, the Excel 4.0 macro sheets, rendered cell by cell.
  CFB      .doc .dot .xls .xlt .xla .ppt .pot .pps, and a bare vbaProject.bin: every storage that
           holds a `VBA` storage with a `dir` stream (Macros/VBA in Word, _VBA_PROJECT_CUR/VBA in
           Excel, VBA in a vbaProject.bin); in a .ppt the project is a zlib-compressed CFB inside
           an ExOleObjStg record of the `PowerPoint Document` stream. An .xls is also read for
           BIFF8 macro sheets (BOUNDSHEET type 1), where its formulas use the tokens rendered
           here (strings, numbers, &, arithmetic, references, functions by number).
  VBA      MS-OVBA: the `dir` stream is a CompressedContainer; its records give the code page and,
           per module, the stream name and the offset of the source in that stream (after the
           PerformanceCache); each module's source is the CompressedContainer from that offset,
           decompressed (2.4.1) and decoded under the project's code page.

What the reader gets (macro_text): the VBA modules in the order of the dir stream, then the macro
sheets. A sheet is read down each column, as Excel 4.0 runs a macro: a formula cell as `=formula`,
a text cell as a VBA string literal ("" for a quote), one cell a line. A document with VBA is read
as a .bas file (the VBA path: generic.py with the `bas` keys and techniques), one with macro sheets
only as an .xlm file.

Fail closed. A document of an Office extension whose bytes are a zip or a CFB, and that holds a
macro container, is read whole or not at all: a bad sector chain, a stream shorter than its size,
a dir stream or a module that does not decompress, a module the dir names that is not there, a
macro sheet with a DOCTYPE or a formula token not rendered here, any bound below that is passed:
routed() then gives a problem and analyze.py leaves every question of that specimen unanswered,
never answered from part of it. A file of an Office extension with no macro container (no
vbaProject.bin, no VBA storage, no macro sheet), or one that is neither a zip nor a CFB, is passed
through unchanged, as before this row.

Bounds: the document (64 MB), a zip member read (32 MB, and at most 200 times its compressed size),
a CFB stream (32 MB), one module's source (4 MB), the text of a document (16 MB), chain lengths
(the file's own sector count), records, modules (512), macro-sheet cells (200,000), one rendered
formula (64 K characters), the ExOleObjStg records of a .ppt (16, each counted, and 64 MB inflated in
all), and a 3 s deadline per document, checked on every module, formula cell and embedded object.
A CompressedChunk that claims more bytes than its stream holds is Bad, never read to the end.

A document whose macro text gives no plan candidate at all (a stub macro beside a plan kept in the
document body) is read as its raw bytes, as before this row (analyze.office_view).
"""
import io
import re
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

ZIP_EXT = {".docm", ".dotm", ".docx", ".dotx", ".xlsm", ".xltm", ".xlam", ".xlsx", ".xltx", ".xlsb",
           ".pptm", ".potm", ".ppsm", ".ppam", ".pptx", ".potx", ".ppsx", ".sldm"}
CFB_EXT = {".doc", ".dot", ".xls", ".xlt", ".xla", ".ppt", ".pot", ".pps"}
OFFICE_EXT = ZIP_EXT | CFB_EXT
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"

MAX_DOCUMENT = 64 << 20
MAX_MEMBER = 32 << 20
MAX_RATIO = 200
MAX_STREAM = 32 << 20
MAX_SOURCE = 4 << 20
MAX_TEXT = 16 << 20
MAX_MODULES = 512
MAX_CELLS = 200_000
MAX_RECORDS = 2_000_000
MAX_EMBEDDED = 16          # ExOleObjStg records of a .ppt (each one counts, whatever it holds)
MAX_FORMULA = 1 << 16      # characters of one rendered BIFF8 formula (a genuine one stays under 4 x 8224)
SECONDS = 3.0

FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF


class Bad(Exception):
    """A container that does not read: the document gives no text at all."""


class Clock:
    def __init__(self, seconds=SECONDS):
        self.end = time.monotonic() + seconds

    def tick(self):
        if time.monotonic() > self.end:
            raise Bad("the time bound was passed")


def u16(b, i):
    if i < 0 or i + 2 > len(b):
        raise Bad("a field past the end")
    return b[i] | b[i + 1] << 8


def u32(b, i):
    if i < 0 or i + 4 > len(b):
        raise Bad("a field past the end")
    return struct.unpack_from("<I", b, i)[0]


# ---------------------------------------------------------------- MS-OVBA 2.4.1

def decompress(buf, start=0, limit=MAX_SOURCE) -> bytes:
    """A CompressedContainer from `start` to the end of `buf`, decompressed. Bad when its signature,
    a chunk header, a copy token or a bound does not hold."""
    if start >= len(buf) or buf[start] != 1:
        raise Bad("no CompressedContainer signature")
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
        if not hdr & 0x8000:
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
            raise Bad("a module past the size bound")
    return bytes(out)


# ---------------------------------------------------------------- the compound file (MS-CFB)

class CFB:
    """A compound file, read strictly: every chain is in range, ends where it should, and holds
    the bytes its stream claims."""

    def __init__(self, data: bytes, clock: Clock):
        if len(data) < 512 or data[:8] != CFB_MAGIC:
            raise Bad("no compound-file header")
        if len(data) > MAX_DOCUMENT:
            raise Bad("a compound file past the size bound")
        self.data, self.clock = data, clock
        shift, mshift = u16(data, 0x1E), u16(data, 0x20)
        if shift not in (9, 12) or mshift != 6 or u16(data, 0x1C) != 0xFFFE:
            raise Bad("a header with an unknown sector size or byte order")
        self.ss, self.mss = 1 << shift, 64
        self.nsect = max(0, (len(data) - self.ss + self.ss - 1) // self.ss)
        nfat, first_dir, cutoff = u32(data, 0x2C), u32(data, 0x30), u32(data, 0x38)
        first_mf, nmf, first_difat, ndifat = u32(data, 0x3C), u32(data, 0x40), u32(data, 0x44), u32(data, 0x48)
        if nfat > self.nsect or ndifat > self.nsect or nmf > self.nsect:
            raise Bad("a header that counts more sectors than the file has")
        self.cutoff = cutoff if cutoff else 4096
        fat_sectors = [s for s in struct.unpack_from("<109I", data, 0x4C) if s != FREESECT]
        seen, s = set(), first_difat
        while s not in (ENDOFCHAIN, FREESECT) and len(fat_sectors) < nfat:
            if s in seen or s >= self.nsect:
                raise Bad("a DIFAT chain that loops or leaves the file")
            seen.add(s)
            sec = self.sector(s)
            per = self.ss // 4 - 1
            fat_sectors += [x for x in struct.unpack_from(f"<{per}I", sec, 0) if x != FREESECT]
            s = u32(sec, per * 4)
        fat_sectors = fat_sectors[:nfat]
        if len(fat_sectors) != nfat:
            raise Bad("fewer FAT sectors than the header counts")
        fat = bytearray()
        for s in fat_sectors:
            if s >= self.nsect:
                raise Bad("a FAT sector outside the file")
            fat += self.sector(s)
        self.fat = struct.unpack(f"<{len(fat) // 4}I", fat)
        self.entries = []
        dirdata = self.chain_bytes(first_dir, self.fat, None)
        for off in range(0, len(dirdata) - 127, 128):
            e = dirdata[off:off + 128]
            nlen = u16(e, 64)
            name = e[:max(0, min(nlen, 64) - 2)].decode("utf-16-le", "replace")
            self.entries.append({"name": name, "type": e[66], "left": u32(e, 68), "right": u32(e, 72),
                                 "child": u32(e, 76), "start": u32(e, 116),
                                 "size": u32(e, 120) | (u32(e, 124) << 32 if self.ss == 4096 else 0)})
        if not self.entries or self.entries[0]["type"] != 5:
            raise Bad("no root entry")
        root = self.entries[0]
        self.minifat = ()
        if nmf and first_mf not in (ENDOFCHAIN, FREESECT):
            mf = self.chain_bytes(first_mf, self.fat, None)
            self.minifat = struct.unpack(f"<{len(mf) // 4}I", mf)
        self.ministream = self.chain_bytes(root["start"], self.fat, root["size"]) \
            if root["start"] not in (ENDOFCHAIN, FREESECT) and root["size"] else b""

    def sector(self, n: int) -> bytes:
        off = (n + 1) * self.ss
        if off >= len(self.data):
            raise Bad("a sector outside the file")
        sec = self.data[off:off + self.ss]
        return sec if len(sec) == self.ss else sec + bytes(self.ss - len(sec))   # a last sector cut short

    def chain(self, start: int, table, count: int) -> list:
        out, s, seen = [], start, set()
        while s != ENDOFCHAIN:
            if s >= len(table) or s >= count or s in seen:
                raise Bad("a sector chain that loops or leaves the file")
            seen.add(s)
            out.append(s)
            s = table[s]
            if len(out) % 4096 == 0:
                self.clock.tick()
        return out

    def chain_bytes(self, start: int, table, size) -> bytes:
        if size is not None and size > MAX_STREAM:
            raise Bad("a stream past the size bound")
        if start in (ENDOFCHAIN, FREESECT) and not size:
            return b""
        secs = self.chain(start, table, self.nsect)
        if size is not None and len(secs) * self.ss < size:
            raise Bad("a stream shorter than its size")
        if size is None and len(secs) * self.ss > MAX_STREAM:
            raise Bad("a chain past the size bound")
        data = b"".join(self.sector(s) for s in secs)
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
            secs = self.chain(e["start"], self.minifat, len(self.minifat))
            if len(secs) * self.mss < size:
                raise Bad("a mini stream shorter than its size")
            out = bytearray()
            for s in secs:
                a, need = s * self.mss, min(self.mss, size - len(out))
                if a + need > len(self.ministream):
                    raise Bad("a mini sector outside the mini stream")
                out += self.ministream[a:a + need]
            return bytes(out[:size])
        return self.chain_bytes(e["start"], self.fat, size)

    def children(self, idx: int) -> dict:
        """{upper-case name: entry index} of a storage's children (the red-black tree walked)."""
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
        """Every storage index, the root first, each once."""
        out, stack, seen = [], [0], set()
        while stack:
            i = stack.pop()
            if i in seen:
                raise Bad("a storage reached twice")
            seen.add(i)
            out.append(i)
            stack += [c for c in self.children(i).values() if self.entries[c]["type"] in (1, 5)]
            self.clock.tick()
        return out


# ---------------------------------------------------------------- the VBA project

def parse_dir(d: bytes):
    """(code page, [{name, stream, offset}]) from a decompressed dir stream."""
    i, codepage, modules, cur, count = 0, 1252, [], None, None
    while i < len(d):
        rid = u16(d, i)
        if rid == 0x0009:                      # PROJECTVERSION: Reserved (4), Major (4), Minor (2)
            i += 12
            continue
        size = u32(d, i + 2)
        body = d[i + 6:i + 6 + size]
        if len(body) != size:
            raise Bad("a dir record past the end of the stream")
        i += 6 + size
        if rid == 0x0003 and size == 2:
            codepage = u16(body, 0)
        elif rid == 0x000F and size == 2:
            count = u16(body, 0)
        elif rid == 0x0019:
            if len(modules) >= MAX_MODULES:
                raise Bad("more modules than the bound")
            cur = {"name": body, "stream": None, "ustream": None, "offset": None}
            modules.append(cur)
        elif cur is not None and rid == 0x001A:
            cur["stream"] = body
        elif cur is not None and rid == 0x0032:
            cur["ustream"] = body
        elif cur is not None and rid == 0x0031 and size == 4:
            cur["offset"] = u32(body, 0)
        elif rid == 0x0010:
            break
    else:
        raise Bad("a dir stream without its terminator")
    if count is None or count != len(modules):
        raise Bad("a dir stream whose module count does not match its modules")
    for m in modules:
        if m["offset"] is None or (m["stream"] is None and m["ustream"] is None):
            raise Bad("a module without its stream name or text offset")
    return codepage, modules


def codec_of(codepage: int) -> str:
    name = "utf-8" if codepage == 65001 else f"cp{codepage}"
    try:
        "".encode(name)
        return name
    except LookupError:
        return "cp1252"


def project_sources(cfb: CFB, vba: int) -> list:
    """[(module name, source text)] of the VBA storage at entry `vba`, in dir order."""
    kids = cfb.children(vba)
    if "DIR" not in kids:
        raise Bad("a VBA storage without its dir stream")
    codepage, modules = parse_dir(decompress(cfb.stream(kids["DIR"]), 0, MAX_STREAM))
    enc = codec_of(codepage)
    out = []
    for m in modules:
        names = [m["ustream"].decode("utf-16-le", "replace")] if m["ustream"] is not None else []
        if m["stream"] is not None:
            names.append(m["stream"].decode(enc, "replace"))
        idx = next((kids[n.upper()] for n in names if n.upper() in kids), None)
        if idx is None or cfb.entries[idx]["type"] != 2:
            raise Bad(f"module stream {ascii(names[0])[:60]} named by the dir stream is not there")
        raw = cfb.stream(idx)
        if m["offset"] >= len(raw):
            raise Bad("a module text offset past its stream")
        text = decompress(raw, m["offset"], MAX_SOURCE).decode(enc, "replace")
        out.append((m["name"].decode(enc, "replace"), text))
        cfb.clock.tick()
    return out


def cfb_projects(cfb: CFB) -> list:
    """The VBA storages of a compound file: a `VBA` storage that holds a `dir` stream."""
    out = []
    for s in cfb.storages():
        kids = cfb.children(s)
        v = kids.get("VBA")
        if v is not None and cfb.entries[v]["type"] == 1 and "DIR" in cfb.children(v):
            out.append(v)
    return out


def ppt_atoms(data: bytes, clock: Clock):
    """[(recVer/recInstance, recType, body)] of every atom of a PowerPoint Document stream, the
    containers (recVer 0xF) walked into; None when the stream is not a run of records that ends
    where the stream ends."""
    out, i, n = [], 0, 0
    while i < len(data):
        if i + 8 > len(data):
            return None
        verinst, rtype, ln = struct.unpack_from("<HHI", data, i)
        n += 1
        if n > MAX_RECORDS:
            raise Bad("a PowerPoint Document stream past the record bound")
        if n % 4096 == 0:
            clock.tick()
        if verinst & 0xF == 0xF:
            i += 8
            continue
        if i + 8 + ln > len(data):
            return None
        out.append((verinst, rtype, data[i + 8:i + 8 + ln]))
        i += 8 + ln
    return out


def ppt_embedded(cfb: CFB, clock: Clock) -> list:
    """The compound files a .ppt holds in ExOleObjStg records (recType 0x1011; recInstance 1
    zlib-compressed, 0 stored) of its `PowerPoint Document` stream: where PowerPoint 97-2003 keeps
    the VBA project. Read whole or not at all: a record cut short, one that does not inflate whole to
    the size it states, more records than MAX_EMBEDDED, or a stream that does not walk as records but
    holds the record's signature, is Bad. Only an object that inflates whole and is no compound file
    (an embedded object of another kind) is passed over, and it counts toward the bounds all the same."""
    idx = cfb.children(0).get("POWERPOINT DOCUMENT")
    if idx is None:
        return []
    data = cfb.stream(idx)
    atoms = ppt_atoms(data, clock)
    if atoms is None:
        if b"\x10\x00\x11\x10" in data or b"\x00\x00\x11\x10" in data:
            raise Bad("a PowerPoint Document stream that does not walk as records and may hold an embedded object")
        return []
    out, tried, inflated = [], 0, 0
    for verinst, rtype, body in atoms:
        if rtype != 0x1011 or verinst not in (0x0000, 0x0010):
            continue
        tried += 1
        if tried > MAX_EMBEDDED:
            raise Bad("more embedded objects than the bound")
        clock.tick()
        if verinst == 0x0010:
            if len(body) < 4:
                raise Bad("an embedded object record cut short")
            want = u32(body, 0)
            if want > MAX_STREAM or inflated + want > MAX_DOCUMENT:
                raise Bad("an embedded object past the size bound")
            d = zlib.decompressobj()
            try:
                raw = d.decompress(body[4:], want + 1)
            except zlib.error as e:
                raise Bad(f"an embedded object that does not inflate ({e})")
            if len(raw) != want or not d.eof:
                raise Bad("an embedded object that does not inflate whole to the size it states")
        else:
            raw = body
        inflated += len(raw)
        if inflated > MAX_DOCUMENT:
            raise Bad("embedded objects past the size bound")
        if raw[:8] != CFB_MAGIC:
            continue
        out.append(CFB(raw, clock))
    return out


# ---------------------------------------------------------------- Excel 4.0 macro sheets

def literal(s: str) -> str:
    return '"' + s.replace('"', '""') + '"'


def col_row(ref: str):
    m = re.fullmatch(r"\$?([A-Z]{1,3})\$?(\d{1,7})", ref or "")
    if not m:
        raise Bad("a cell without a reference")
    col = 0
    for c in m.group(1):
        col = col * 26 + ord(c) - 64
    return col, int(m.group(2))


def xml_root(data: bytes):
    import xml.etree.ElementTree as ET
    head = data[:4096].lower()
    if b"<!doctype" in data.lower() or b"<!entity" in head:
        raise Bad("an XML part with a DOCTYPE")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise Bad(f"an XML part that does not parse ({e})")


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def text_of_si(si) -> str:
    return "".join(t.text or "" for t in si.iter() if local(t.tag) == "t")


def xlsx_macrosheet(data: bytes, shared: list, clock: Clock) -> str:
    """One xl/macrosheets/*.xml as lines: down each column, `=formula` or a text literal."""
    cells = []
    for c in xml_root(data).iter():
        if local(c.tag) != "c":
            continue
        if len(cells) >= MAX_CELLS:
            raise Bad("a macro sheet past the cell bound")
        col, row = col_row(c.get("r"))
        f = next((x for x in c if local(x.tag) == "f"), None)
        v = next((x for x in c if local(x.tag) == "v"), None)
        t = c.get("t") or "n"
        if f is not None and f.text:
            line = "=" + f.text
        elif f is not None:
            raise Bad("a shared or array formula the sheet does not spell out")
        elif t == "s" and v is not None:
            try:
                line = literal(shared[int(v.text)])
            except (ValueError, IndexError, TypeError):
                raise Bad("a shared-string index outside the table")
        elif t == "inlineStr":
            is_ = next((x for x in c if local(x.tag) == "is"), None)
            line = literal(text_of_si(is_)) if is_ is not None else None
        elif t == "str" and v is not None:
            line = literal(v.text or "")
        else:
            line = None
        if line is not None:
            cells.append((col, row, line))
        if len(cells) % 4096 == 0:
            clock.tick()
    return "\r\n".join(line for _, _, line in sorted(cells))


# BIFF8 formula tokens (MS-XLS 2.5.198): the ones rendered; any other makes the sheet no reading.
BINOPS = {0x03: "+", 0x04: "-", 0x05: "*", 0x06: "/", 0x07: "^", 0x08: "&", 0x09: "<", 0x0A: "<=",
          0x0B: "=", 0x0C: ">=", 0x0D: ">", 0x0E: "<>"}
# Fixed-arity functions (ptgFunc, iftab -> (name, argument count)) that a macro sheet is likely to use.
# A name is only how a function is shown: a number not listed is shown as FUNC<n>, and its arguments
# (the literals the plan is read from) are rendered all the same.
FUNCS = {111: ("CHAR", 1), 112: ("LOWER", 1), 113: ("UPPER", 1), 31: ("MID", 3), 32: ("LEN", 1), 48: ("TEXT", 2),
         121: ("CODE", 1)}
VARFUNCS = {0: "COUNT", 1: "IF", 4: "SUM", 36: "AND", 37: "OR", 89: "CALLER", 150: "CALL", 336: "CONCATENATE",
            110: "EXEC", 148: "INDIRECT", 88: "SET.NAME", 149: "REGISTER", 30: "REPT", 55: "RETURN",
            54: "HALT", 53: "GOTO", 101: "HLOOKUP", 102: "VLOOKUP", 124: "FIND", 120: "SUBSTITUTE", 255: "USERFUNC"}


class Capped(list):
    """A formula's value stack: a value longer than MAX_FORMULA is Bad. Without it a run of
    parentheses or unary signs rebuilds an ever longer string, work that grows with the square of
    the token count."""

    def append(self, v):
        if len(v) > MAX_FORMULA:
            raise Bad("a formula that renders past the length bound")
        super().append(v)


def rgce(b: bytes) -> str:
    """A BIFF8 formula's tokens rendered as text; Bad on a token not rendered here."""
    stack, i = Capped(), 0

    def pop(n):
        if len(stack) < n:
            raise Bad("a formula whose tokens do not add up")
        args = stack[len(stack) - n:]
        del stack[len(stack) - n:]
        return args
    while i < len(b):
        p = b[i]
        base = p & 0x1F if p & 0x60 and p >= 0x20 else p
        if p in BINOPS:
            x, y = pop(2)
            stack.append(f"{x}{BINOPS[p]}{y}")
            i += 1
        elif p in (0x12, 0x13):                 # unary plus, minus
            stack.append(("+" if p == 0x12 else "-") + pop(1)[0])
            i += 1
        elif p == 0x15:
            stack.append(f"({pop(1)[0]})")
            i += 1
        elif p == 0x16:
            stack.append("")
            i += 1
        elif p == 0x17:
            if i + 3 > len(b):
                raise Bad("a string token cut short")
            n, hi = b[i + 1], b[i + 2] & 1
            raw = b[i + 3:i + 3 + n * (2 if hi else 1)]
            if len(raw) != n * (2 if hi else 1):
                raise Bad("a string token cut short")
            stack.append(literal(raw.decode("utf-16-le" if hi else "latin-1")))
            i += 3 + len(raw)
        elif p == 0x19:                          # ptgAttr: no value of its own (tAttrSum wraps SUM)
            if i + 4 > len(b):
                raise Bad("an attribute token cut short")
            grbit = b[i + 1]
            if grbit & 0x04:                     # tAttrChoose: a jump table
                i += 4 + 2 * (u16(b, i + 2) + 1)
            else:
                if grbit & 0x10:
                    stack.append(f"SUM({pop(1)[0]})")
                i += 4
        elif p == 0x1C:
            stack.append(f"#ERR{b[i + 1] if i + 1 < len(b) else 0}")
            i += 2
        elif p == 0x1D:
            stack.append("TRUE" if i + 1 < len(b) and b[i + 1] else "FALSE")
            i += 2
        elif p == 0x1E:
            stack.append(str(u16(b, i + 1)))
            i += 3
        elif p == 0x1F:
            if i + 9 > len(b):
                raise Bad("a number token cut short")
            v = struct.unpack_from("<d", b, i + 1)[0]
            stack.append(str(int(v)) if v == int(v) else repr(v))
            i += 9
        elif p >= 0x20 and base == 0x01:         # ptgFunc
            tab = u16(b, i + 1)
            if tab not in FUNCS:
                raise Bad(f"a fixed function {tab} not rendered here")
            name, n = FUNCS[tab]
            stack.append(f"{name}({','.join(pop(n))})")
            i += 3
        elif p >= 0x20 and base == 0x02:         # ptgFuncVar
            if i + 4 > len(b):
                raise Bad("a function token cut short")
            n, tab = b[i + 1] & 0x7F, u16(b, i + 2)
            name = (f"CMD{tab & 0x7FFF}" if tab & 0x8000 else VARFUNCS.get(tab, f"FUNC{tab}"))
            stack.append(f"{name}({','.join(pop(n))})")
            i += 4
        elif p >= 0x20 and base == 0x04:         # ptgRef
            stack.append(f"R{u16(b, i + 1) + 1}C{(u16(b, i + 3) & 0x3FFF) + 1}")
            i += 5
        elif p >= 0x20 and base == 0x05:         # ptgArea
            stack.append(f"R{u16(b, i + 1) + 1}C{(u16(b, i + 5) & 0x3FFF) + 1}:"
                         f"R{u16(b, i + 3) + 1}C{(u16(b, i + 7) & 0x3FFF) + 1}")
            i += 9
        elif p >= 0x20 and base == 0x03:         # ptgName
            stack.append(f"NAME{u32(b, i + 1)}")
            i += 5
        elif p >= 0x20 and base == 0x1A:         # ptgRef3d
            stack.append(f"SHEET{u16(b, i + 1)}!R{u16(b, i + 3) + 1}C{(u16(b, i + 5) & 0x3FFF) + 1}")
            i += 7
        else:
            raise Bad(f"formula token 0x{p:02x} not rendered here")
    if len(stack) != 1:
        raise Bad("a formula whose tokens do not add up")
    return stack[0]


def biff_records(data: bytes, start: int, clock: Clock):
    i, n = start, 0
    while i + 4 <= len(data):
        rt, ln = u16(data, i), u16(data, i + 2)
        body = data[i + 4:i + 4 + ln]
        if len(body) != ln:
            raise Bad("a BIFF record past the end of the stream")
        yield i, rt, body
        i += 4 + ln
        n += 1
        if n > MAX_RECORDS:
            raise Bad("a workbook past the record bound")
        if n % 8192 == 0:
            clock.tick()


class Segments:
    """The SST record and its CONTINUE records, read as MS-XLS 2.5.293 says: a string's characters
    that cross into a CONTINUE record start there again with their own high-byte flag."""

    def __init__(self, parts):
        self.parts, self.k, self.i = parts, 0, 0

    def _next(self):
        self.k += 1
        self.i = 0
        if self.k >= len(self.parts):
            raise Bad("a shared-string table cut short")

    def raw(self, n):
        out = bytearray()
        while n:
            if self.i >= len(self.parts[self.k]):
                self._next()
            take = self.parts[self.k][self.i:self.i + n]
            out += take
            self.i += len(take)
            n -= len(take)
        return bytes(out)

    def chars(self, n, hi):
        out = []
        while n:
            if self.i >= len(self.parts[self.k]):
                self._next()
                hi = self.raw(1)[0] & 1
            avail = (len(self.parts[self.k]) - self.i) // (2 if hi else 1)
            take = min(n, avail)
            if take <= 0:
                raise Bad("a shared string split inside a character")
            raw = self.raw(take * (2 if hi else 1))
            out.append(raw.decode("utf-16-le" if hi else "latin-1"))
            n -= take
        return "".join(out)


def sst_strings(parts) -> list:
    seg = Segments(parts)
    head = seg.raw(8)
    count = u32(head, 4)
    if count > MAX_CELLS:
        raise Bad("a shared-string table past the bound")
    out = []
    for _ in range(count):
        cch = u16(seg.raw(2), 0)
        flags = seg.raw(1)[0]
        runs = u16(seg.raw(2), 0) if flags & 0x08 else 0
        ext = u32(seg.raw(4), 0) if flags & 0x04 else 0
        out.append(seg.chars(cch, flags & 1))
        if runs * 4 + ext > MAX_STREAM:
            raise Bad("a shared string past the bound")
        seg.raw(runs * 4 + ext)
    return out


def xl_unicode(b: bytes, i: int, wide_count: bool):
    n = u16(b, i) if wide_count else b[i]
    i += 2 if wide_count else 1
    hi = b[i] & 1 if i < len(b) else 0
    raw = b[i + 1:i + 1 + n * (2 if hi else 1)]
    if len(raw) != n * (2 if hi else 1):
        raise Bad("a string past the end of its record")
    return raw.decode("utf-16-le" if hi else "latin-1")


def biff_macrosheets(data: bytes, clock: Clock) -> list:
    """The macro sheets (BOUNDSHEET dt=1) of a BIFF8 Workbook stream, each as lines."""
    sheets, sst_parts, in_sst = [], [], False
    for at, rt, body in biff_records(data, 0, clock):
        if rt == 0x00FC:
            sst_parts, in_sst = [body], True
            continue
        if rt == 0x003C and in_sst:
            sst_parts.append(body)
            continue
        in_sst = False
        if rt == 0x0085 and len(body) >= 6 and body[5] == 0x01:
            sheets.append(u32(body, 0))
        elif rt == 0x000A:
            break                                     # the globals' EOF
    if not sheets:
        return []
    shared = sst_strings(sst_parts) if sst_parts else []
    out = []
    for pos in sheets:
        if pos + 4 > len(data) or u16(data, pos) != 0x0809:
            raise Bad("a macro sheet whose BOF is not where the workbook says")
        cells = []
        for at, rt, body in biff_records(data, pos, clock):
            if at != pos and rt == 0x000A:
                break
            if rt in (0x00FD, 0x0204, 0x0006):
                if len(cells) >= MAX_CELLS:
                    raise Bad("a macro sheet past the cell bound")
                row, col = u16(body, 0), u16(body, 2)
                if rt == 0x00FD:
                    k = u32(body, 6)
                    if k >= len(shared):
                        raise Bad("a shared-string index outside the table")
                    cells.append((col, row, literal(shared[k])))
                elif rt == 0x0204:
                    cells.append((col, row, literal(xl_unicode(body, 6, True))))
                else:
                    cce = u16(body, 20)
                    tokens = body[22:22 + cce]
                    if len(tokens) != cce:
                        raise Bad("a formula past the end of its record")
                    cells.append((col, row, "=" + rgce(tokens)))
                    clock.tick()
        else:
            raise Bad("a macro sheet without its EOF")
        out.append("\r\n".join(line for _, _, line in sorted(cells)))
    return out


# ---------------------------------------------------------------- one document

def read_member(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size > MAX_MEMBER or info.file_size > MAX_RATIO * max(info.compress_size, 1):
        raise Bad(f"zip member {ascii(info.filename)[:60]} past the size or ratio bound")
    with z.open(info) as f:
        data = f.read(MAX_MEMBER + 1)
    if len(data) > MAX_MEMBER:
        raise Bad("a zip member past the size bound")
    return data


def cfb_parts(data: bytes, clock: Clock, name: str):
    """(VBA sources, macro-sheet texts) of a compound file."""
    cfb = CFB(data, clock)
    files = [cfb] + (ppt_embedded(cfb, clock) if Path(name).suffix.lower() in (".ppt", ".pot", ".pps") else [])
    sources = []
    for f in files:
        for v in cfb_projects(f):
            sources += project_sources(f, v)
    sheets = []
    kids = cfb.children(0)
    book = kids.get("WORKBOOK", kids.get("BOOK"))
    if book is not None and cfb.entries[book]["type"] == 2:
        sheets = biff_macrosheets(cfb.stream(book), clock)
    return sources, sheets


def zip_parts(data: bytes, clock: Clock):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except (zipfile.BadZipFile, ValueError, EOFError, OSError) as e:
        raise Bad(f"a zip that does not open ({e})")
    sources, sheets = [], []
    try:
        projects = sorted((i for i in infos if i.filename.lower().rsplit("/", 1)[-1] == "vbaproject.bin"),
                          key=lambda i: i.filename)
        for info in projects:
            cfb = CFB(read_member(z, info), clock)
            for v in cfb_projects(cfb):
                sources += project_sources(cfb, v)
        macro = sorted((i for i in infos if re.fullmatch(r"(?i)xl/macrosheets/[^/]+\.xml", i.filename)),
                       key=lambda i: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", i.filename)])
        if macro:
            shared = []
            sst = next((i for i in infos if i.filename.lower() == "xl/sharedstrings.xml"), None)
            if sst is not None:
                shared = [text_of_si(si) for si in xml_root(read_member(z, sst)).iter() if local(si.tag) == "si"]
            for info in macro:
                sheets.append(xlsx_macrosheet(read_member(z, info), shared, clock))
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError, NotImplementedError) as e:
        raise Bad(f"a zip member that does not read ({type(e).__name__}: {e})")
    return sources, sheets


def macro_text(name: str, data: bytes, clock=None):
    """(text, ext) of a document's macros: the VBA modules (`.bas`) and macro sheets (`.xlm` when
    there is no VBA); None when it is no Office container or holds no macro container. Raises Bad."""
    clock = clock or Clock()
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if len(data) > MAX_DOCUMENT:
        raise Bad("a document past the size bound")
    if data[:4] == ZIP_MAGIC:
        sources, sheets = zip_parts(data, clock)
    elif data[:8] == CFB_MAGIC:
        sources, sheets = cfb_parts(data, clock, name)
    else:
        return None
    if not sources and not sheets:
        return None
    parts = [text for _, text in sources] + sheets
    text = "\r\n".join(p.rstrip("\r\n") for p in parts) + "\r\n"
    if len(text) > MAX_TEXT:
        raise Bad("macro text past the size bound")
    if not text.strip():
        raise Bad("a macro container with no source text")
    return text, (".bas" if sources else ".xlm")


def office(name) -> bool:
    return Path(name or "").suffix.lower() in OFFICE_EXT or Path(name or "").name.lower() == "vbaproject.bin"


def routed(member: str, files: dict, find=None):
    """None for a member this row does not read (no Office extension, no macro container): the
    caller goes on as before. Else (files, virtual member, problem): `files` with the macro text
    added under `<member>.bas` (or `.xlm`), which the caller reads in place of the member, and
    problem None; or problem the reason the container does not read, and nothing is to be read."""
    if not office(member):
        return None
    data = find(files, member) if find else files.get(member)
    if not isinstance(data, (bytes, bytearray)):
        return None
    try:
        got = macro_text(member, data)
    except Bad as e:
        return files, member, str(e)
    except Exception as e:  # noqa: BLE001 - a parser that trips on a hostile container is a container that does not read
        return files, member, f"{type(e).__name__}: {e}"
    if got is None:
        return None
    text, ext = got
    virtual = f"{member}{ext}"
    view = dict(files)
    view[virtual] = text.encode("utf-8")
    print(f"[officevba] {member}: macro text read ({len(text)} characters, as {ext})", file=sys.stderr)
    return view, virtual, None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: officevba.py FILE...   (prints the macro text of each document)")
    for arg in sys.argv[1:]:
        try:
            got = macro_text(arg, Path(arg).read_bytes())
        except (OSError, Bad) as e:
            print(f"{arg}: {e}", file=sys.stderr)
            continue
        print(f"===== {arg}: " + ("no macro container" if got is None else f"read as {got[1]}"))
        if got:
            sys.stdout.write(got[0])
