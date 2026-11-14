#!/usr/bin/env python3
"""Offline test of row 93: VBA and Excel 4.0 macros inside Office documents (officevba.py and its dispatch in analyze.py).

Usage:
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python solvers/script-analysis/test_wavec2_office.py [-v]

No Game Master request and no token. It reads the saved Script Analysis attempts of Days 2 to 4 (the
VBScript specimens, every saved variant) and the newest saved attempt with a key (for the row-71 VBA
rehearsal of tests/next_components.py) through gm.CHALLENGES, read only, and writes nothing but a scratch
label ledger under tempfile.mkdtemp() and the fixture files under /private/tmp/claude-501/wave-c2-office/.

Every document here is built by hand by the writers below, none by Office: an MS-OVBA compressor, a
compound-file (CFB v3) writer with a mini stream, the VBA project's dir stream, OOXML zips, a BIFF8 Workbook
stream with macro sheets and a .ppt PowerPoint Document stream with a compressed ExOleObjStg.

What it proves:

  ovba        the MS-OVBA 3.2.1 example decompresses to its text; the compressor round-trips random and
              repetitive data and every saved specimen (compressed and raw chunks, 0 to 20,000 bytes)
  cfb         streams of every size (mini stream and regular sectors, empty) read back byte for byte; where
              7-Zip is installed, every stream it extracts from a hand-built .doc, .xls and .ppt equals the read
  vbs         every distinct Day 2-4 .vbs specimen as Module1 of a .docm, .xls, .doc, .xlsb, .pptm and .ppt
              (with an empty ThisDocument/ThisWorkbook module beside it): the same answers as the same
              text read as a plain .bas file (plain, unsure and None alike); against key.json: answers
              equal, none wrong
  vba         every row-71 VBA rehearsal specimen (tests/next_components.py, every spelling that applies) in a .docm and an
              .xls: the same answers as the .bas specimen, and none wrong against its truth
  xlm         the rehearsal material as an Excel 4.0 macro sheet in an .xlsm and in a BIFF8 .xls: both read
              to the same text and the same answers; no plain answer wrong
  scope       a document without macros (a .docx, a .doc with no VBA storage) and a text file under an
              Office extension are read exactly as before the row; two modules that carry two different
              plans answer no plan question
  corrupt     a cut file, a FAT loop, a chunk signature, a module offset past its stream, a module count
              that does not match, a module stream that is not there, a bad vbaProject.bin inside a zip, a
              decompression bomb in a zip, a macro sheet with a DOCTYPE, a BIFF8 formula token not rendered:
              every question of that specimen unanswered, the other specimen of the set unchanged, covers()
              names the file
  bounds      a CompressedContainer that expands past 4 MB stops at the bound, fast
  speed       a 200 KB module through solve_set
  review      the five review blockers: a CompressedChunk cut short is Bad (every tail cut of every
              specimen's module, and cut Module1 streams through solve_set); a damaged ExOleObjStg beside
              a good one leaves the .ppt unanswered; BIFF8 formula cells keep the 3 s deadline and a
              rendered formula is bounded; every ExOleObjStg counts toward the bound; a stub macro beside
              a plan in the document body is read as the bytes, as before the row

Last line: `TEST_WAVEC2_OFFICE passed=<n> failed=<n>`. Exit 0 when nothing failed, 1 otherwise, 2 when the
saved attempts are not there.
"""
import contextlib
import io
import json
import re
import os
import random
import struct
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_wavec2_office_"))
os.environ["CTF_STATE_DIR"] = str(SCRATCH / "state")
for _name in ("ONLY", "CTF_HIDE", "CTF_LEDGER_MASK", "CTF_PLATFORM_URL"):
    os.environ.pop(_name, None)
os.environ["CTF_TESTING"] = "1"
for _p in (HERE.parent.parent / "tools", HERE.parent / "common", HERE):
    sys.path.insert(0, str(_p))

import gm    # noqa: E402 - resolves the real challenges folder
import run   # noqa: E402 - load_offline and split_sets: the runner's own reading of an attempt

CHALLENGES = gm.CHALLENGES
os.environ["CTF_WORKDIR"] = str(SCRATCH / "challenges")    # the label ledger: an empty scratch folder

import analyze      # noqa: E402
import officevba    # noqa: E402
import plan_codec   # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
DAYS = ("day-02", "day-03", "day-04")
FIXTURES = Path("/private/tmp/claude-501/wave-c2-office")
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


def solve(qs, files):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, files, {"set": 1})
    return out, err.getvalue()


def fixture(name: str, data: bytes):
    try:
        FIXTURES.mkdir(parents=True, exist_ok=True)
        (FIXTURES / name).write_bytes(data)
    except OSError:
        pass


# ================================================================ writers (fixtures only)

def ovba_chunk(chunk: bytes) -> bytes:
    """One CompressedChunk's data (MS-OVBA 2.4.1.3.7), greedy, matches inside the chunk only."""
    out, i, n, heads = bytearray(), 0, len(chunk), {}
    while i < n:
        at = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if i >= n:
                break
            bits = max((i - 1).bit_length(), 4)
            maxlen, best, off = (0xFFFF >> bits) + 3, 0, 0
            for j in reversed(heads.get(chunk[i:i + 3], [])[-48:]):
                k = 0
                while k < maxlen and i + k < n and chunk[j + k] == chunk[i + k]:
                    k += 1
                if k > best:
                    best, off = k, i - j
            if best >= 3:
                tok = ((off - 1) << (16 - bits)) | (best - 3)
                out += struct.pack("<H", tok)
                flags |= 1 << bit
                step = best
            else:
                out.append(chunk[i])
                step = 1
            for p in range(i, i + step):
                heads.setdefault(chunk[p:p + 3], []).append(p)
            i += step
        out[at] = flags
    return bytes(out)


def ovba_compress(data: bytes, raw_chunks=False) -> bytes:
    """A CompressedContainer of `data`: a raw chunk where a full chunk does not compress (or always,
    for full chunks, with raw_chunks)."""
    out = bytearray(b"\x01")
    for c in range(0, len(data), 4096):
        chunk = data[c:c + 4096]
        body = ovba_chunk(chunk)
        if len(chunk) == 4096 and (raw_chunks or len(body) + 2 > 4098):
            out += struct.pack("<H", 0x3FFF) + chunk
        else:
            if len(body) + 2 > 4098:
                raise ValueError("a last chunk that does not compress")
            out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def cfb_write(tree: dict) -> bytes:
    """A version 3 compound file of `tree` ({name: bytes | {..}}): streams under 4096 bytes in the mini
    stream, each storage's children as a chain of right siblings in CFB name order."""
    SS, MSS = 512, 64
    entries = [{"name": "Root Entry", "type": 5, "kids": []}]

    def add(name, node):
        idx = len(entries)
        e = {"name": name}
        entries.append(e)
        if isinstance(node, dict):
            e.update(type=1, kids=[add(k, v) for k, v in node.items()])
        else:
            e.update(type=2, data=bytes(node))
        return idx
    entries[0]["kids"] = [add(k, v) for k, v in tree.items()]
    for e in entries:
        e.update(left=0xFFFFFFFF, right=0xFFFFFFFF, child=0xFFFFFFFF, start=0xFFFFFFFE, size=0)
    for e in entries:
        kids = sorted(e.get("kids", []), key=lambda i: (len(entries[i]["name"]), entries[i]["name"].upper()))
        if kids:
            e["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                entries[a]["right"] = b
    sectors, fat = [], []

    def alloc(data: bytes) -> int:
        n = (len(data) + SS - 1) // SS
        start = len(sectors)
        for k in range(n):
            sectors.append(data[k * SS:(k + 1) * SS].ljust(SS, b"\0"))
            fat.append(start + k + 1 if k < n - 1 else 0xFFFFFFFE)
        return start if n else 0xFFFFFFFE
    mini, minifat = bytearray(), []
    for e in entries:
        if e["type"] != 2 or not e["data"]:
            continue
        e["size"] = len(e["data"])
        if len(e["data"]) >= 4096:
            e["start"] = alloc(e["data"])
        else:
            n = (len(e["data"]) + MSS - 1) // MSS
            e["start"] = len(mini) // MSS
            for k in range(n):
                minifat.append(e["start"] + k + 1 if k < n - 1 else 0xFFFFFFFE)
            mini += e["data"].ljust(n * MSS, b"\0")
    entries[0]["start"] = alloc(bytes(mini)) if mini else 0xFFFFFFFE
    entries[0]["size"] = len(mini)
    mf = struct.pack(f"<{len(minifat)}I", *minifat)
    mf += b"\xff" * ((-len(mf)) % SS)
    first_mf = alloc(mf) if minifat else 0xFFFFFFFE
    nmf = len(mf) // SS if minifat else 0
    dirdata = bytearray()
    for e in entries + [{"name": "", "type": 0, "left": 0xFFFFFFFF, "right": 0xFFFFFFFF, "child": 0xFFFFFFFF,
                         "start": 0, "size": 0}] * ((-len(entries)) % 4):
        name = e["name"].encode("utf-16-le")
        dirdata += name.ljust(64, b"\0") + struct.pack("<HBB3I", len(name) + 2 if e["name"] else 0, e["type"],
                                                         1, e["left"], e["right"], e["child"])
        dirdata += bytes(16 + 4 + 16) + struct.pack("<IQ", e["start"], e["size"])
    first_dir = alloc(bytes(dirdata))
    nfat = 1
    while nfat * (SS // 4) < len(sectors) + nfat:
        nfat += 1
    fat_start = len(sectors)
    table = fat + [0xFFFFFFFD] * nfat
    table += [0xFFFFFFFF] * (nfat * (SS // 4) - len(table))
    raw = struct.pack(f"<{len(table)}I", *table)
    for k in range(nfat):
        sectors.append(raw[k * SS:(k + 1) * SS])
    if nfat > 109:
        raise ValueError("a fixture too big for the header DIFAT")
    difat = [fat_start + k for k in range(nfat)] + [0xFFFFFFFF] * (109 - nfat)
    header = (officevba.CFB_MAGIC + bytes(16) + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + bytes(6)
              + struct.pack("<IIIIIIIII", 0, nfat, first_dir, 0, 4096, first_mf, nmf, 0xFFFFFFFE, 0)
              + struct.pack("<109I", *difat))
    assert len(header) == 512
    return header + b"".join(sectors)


def rec(rid: int, body: bytes) -> bytes:
    return struct.pack("<HI", rid, len(body)) + body


def dir_stream(modules: list, codepage=1252, bad=None) -> bytes:
    """The decompressed dir stream of a project of `modules` [(name, stream name, offset, document?)]."""
    enc = f"cp{codepage}"
    d = rec(0x0001, struct.pack("<I", 1)) + rec(0x0002, struct.pack("<I", 0x409)) + \
        rec(0x0014, struct.pack("<I", 0x409)) + rec(0x0003, struct.pack("<H", codepage)) + \
        rec(0x0004, b"VBAProject") + rec(0x0005, b"") + rec(0x0040, b"") + rec(0x0006, b"") + rec(0x003D, b"") + \
        rec(0x0007, struct.pack("<I", 0)) + rec(0x0008, struct.pack("<I", 0)) + \
        struct.pack("<HIIH", 0x0009, 4, 0x5D0A6A2D, 0x000E) + rec(0x000C, b"") + rec(0x003C, b"")
    libid = b"*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation"
    d += rec(0x0016, b"stdole") + rec(0x003E, "stdole".encode("utf-16-le")) + \
        rec(0x000D, struct.pack("<I", len(libid)) + libid + struct.pack("<IH", 0, 0))
    count = len(modules) + (1 if bad == "count" else 0)
    d += rec(0x000F, struct.pack("<H", count)) + rec(0x0013, struct.pack("<H", 0xFFFF))
    for name, stream, offset, document in modules:
        d += rec(0x0019, name.encode(enc)) + rec(0x0047, name.encode("utf-16-le")) + \
            rec(0x001A, stream.encode(enc)) + rec(0x0032, stream.encode("utf-16-le")) + \
            rec(0x001C, b"") + rec(0x0048, b"") + rec(0x0031, struct.pack("<I", offset)) + \
            rec(0x001E, struct.pack("<I", 0)) + rec(0x002C, struct.pack("<H", 0xFFFF)) + \
            rec(0x0022 if document else 0x0021, b"") + rec(0x002B, b"")
    return d + rec(0x0010, b"")


def this_document(name="ThisDocument", base="0{00020906-0000-0000-C000-000000000046}") -> str:
    """An empty document module, as Office saves one: only its attribute lines."""
    return (f'Attribute VB_Name = "{name}"\r\nAttribute VB_Base = "{base}"\r\nAttribute VB_GlobalNameSpace = False\r\n'
            'Attribute VB_Creatable = False\r\nAttribute VB_PredeclaredId = True\r\nAttribute VB_Exposed = True\r\n'
            'Attribute VB_TemplateDerived = False\r\nAttribute VB_Customizable = True\r\n')


def module_text(text: str, name="Module1") -> str:
    return text if text.lstrip().startswith("Attribute VB_Name") else f'Attribute VB_Name = "{name}"\r\n' + text


def vba_storage(modules: list, bad=None, codepage=1252) -> dict:
    """{'VBA': {...}, 'PROJECT': .., 'PROJECTwm': ..}: a project of `modules` [(name, source, document?)].
    `bad` corrupts it one way: chunk (a chunk signature), offset (a text offset past the stream), count
    (the dir counts one module more), missing (a module stream left out)."""
    vba, entries, rng = {"_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00"}, [], random.Random(93)
    for k, (name, source, document) in enumerate(modules):
        cache = bytes(rng.randrange(256) for _ in range(37 + 11 * k))     # a PerformanceCache stand-in
        body = ovba_compress(source.encode(f"cp{codepage}"))
        if bad == "chunk" and k == len(modules) - 1:
            body = body[:2] + bytes([body[2] ^ 0x40]) + body[3:]
        offset = len(cache) + (len(body) + 5 if bad == "offset" and k == len(modules) - 1 else 0)
        entries.append((name, name, offset, document))
        if not (bad == "missing" and k == len(modules) - 1):
            vba[name] = cache + body
    vba["dir"] = ovba_compress(dir_stream(entries, codepage, bad))
    project = "ID=\"{00000000-0000-0000-0000-000000000000}\"\r\n" + "".join(
        (f"Document={n}/&H00000000\r\n" if d else f"Module={n}\r\n") for n, _, d in modules) + 'Name="VBAProject"\r\n'
    return {"VBA": vba, "PROJECT": project.encode(), "PROJECTwm": b"".join(
        n.encode() + b"\0" + n.encode("utf-16-le") + b"\0\0" for n, _, _ in modules) + b"\0\0"}


def vba_project_bin(modules: list, bad=None) -> bytes:
    return cfb_write(vba_storage(modules, bad))


OOXML_DIR = {".docm": "word", ".dotm": "word", ".docx": "word", ".xlsm": "xl", ".xlsb": "xl", ".xlsx": "xl",
             ".pptm": "ppt", ".pptx": "ppt"}


def ooxml(ext: str, project=None, macrosheets=(), shared=None, extra=()) -> bytes:
    """An OOXML package: its main part, vbaProject.bin when given, xl/macrosheets/sheetN.xml."""
    top = OOXML_DIR[ext]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns='
                   '"http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType='
                   '"application/vnd.ms-office.vbaProject"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/relationships"/>')
        main = {"word": "word/document.xml", "xl": "xl/workbook.xml", "ppt": "ppt/presentation.xml"}[top]
        z.writestr(main, '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><root>fixture</root>')
        if project is not None:
            z.writestr(f"{top}/vbaProject.bin", project)
        for k, xml in enumerate(macrosheets, 1):
            z.writestr(f"xl/macrosheets/sheet{k}.xml", xml)
        if shared is not None:
            z.writestr("xl/sharedStrings.xml", '<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.'
                       'openxmlformats.org/spreadsheetml/2006/main">' + "".join(
                           f"<si><t>{xml_escape(s)}</t></si>" for s in shared) + "</sst>")
        for name, data in extra:
            z.writestr(name, data)
    return buf.getvalue()


def xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def col_name(c: int) -> str:
    s = ""
    while c:
        c, r = divmod(c - 1, 26)
        s = chr(65 + r) + s
    return s


def macrosheet_xml(cells: list) -> str:
    """cells: [(col, row, ('f', formula) | ('s', shared index) | ('str', text))], 1-based."""
    rows = {}
    for col, row, (kind, v) in cells:
        r = f"{col_name(col)}{row}"
        if kind == "f":
            rows.setdefault(row, []).append(f'<c r="{r}" t="str"><f>{xml_escape(v)}</f><v></v></c>')
        elif kind == "s":
            rows.setdefault(row, []).append(f'<c r="{r}" t="s"><v>{v}</v></c>')
        else:
            rows.setdefault(row, []).append(f'<c r="{r}" t="inlineStr"><is><t>{xml_escape(v)}</t></is></c>')
    body = "".join(f'<row r="{r}">{"".join(c)}</row>' for r, c in sorted(rows.items()))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<xm:macrosheet xmlns="http://schemas.'
            'openxmlformats.org/spreadsheetml/2006/main" xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">'
            f'<sheetData>{body}</sheetData></xm:macrosheet>')


def brec(rt: int, body: bytes) -> bytes:
    return struct.pack("<HH", rt, len(body)) + body


def ptg_str(s: str) -> bytes:
    raw = s.encode("latin-1")
    assert len(raw) <= 255
    return bytes([0x17, len(raw), 0]) + raw


def concat_tokens(pieces: list) -> bytes:
    t = ptg_str(pieces[0])
    for p in pieces[1:]:
        t += ptg_str(p) + b"\x08"
    return t


def sst_records(strings: list, limit=8224) -> bytes:
    """SST and CONTINUE records; a string whose characters cross `limit` goes on in a CONTINUE record
    that starts with its own flags byte (MS-XLS 2.5.293)."""
    parts, cur = [], bytearray(struct.pack("<II", len(strings), len(strings)))
    for s in strings:
        raw = s.encode("latin-1")
        head = struct.pack("<HB", len(raw), 0)
        if len(cur) + len(head) + 1 > limit:
            parts.append(bytes(cur))
            cur = bytearray()
        cur += head
        while raw:
            room = limit - len(cur)
            if room <= 0:
                parts.append(bytes(cur))
                cur = bytearray(b"\x00")
                continue
            cur += raw[:room]
            raw = raw[room:]
    parts.append(bytes(cur))
    return brec(0x00FC, parts[0]) + b"".join(brec(0x003C, p) for p in parts[1:])


def biff_workbook(sheet_cells: list, shared: list, sst_limit=8224) -> bytes:
    """A BIFF8 Workbook stream with one macro sheet. sheet_cells: [(col, row, ('sst', k) | ('rgce', tokens)
    | ('label', text))], 0-based."""
    bof = lambda dt: brec(0x0809, struct.pack("<HHHHII", 0x0600, dt, 0x0DBB, 0x07CC, 0, 0x0206))   # noqa: E731
    name = b"Macro1"
    sheet = bof(0x0040)
    for col, row, (kind, v) in sheet_cells:
        if kind == "sst":
            sheet += brec(0x00FD, struct.pack("<HHHI", row, col, 0x0F, v))
        elif kind == "label":
            raw = v.encode("latin-1")
            sheet += brec(0x0204, struct.pack("<HHHHB", row, col, 0x0F, len(raw), 0) + raw)
        else:
            sheet += brec(0x0006, struct.pack("<HHH", row, col, 0x0F) + b"\x00\x00\x00\x00\x00\x00\xff\xff"
                          + struct.pack("<HIH", 0, 0, len(v)) + v)
    sheet += brec(0x000A, b"")

    def globals_(pos):
        return (bof(0x0005) + brec(0x0085, struct.pack("<IBB", pos, 0, 1) + bytes([len(name), 0]) + name)
                + sst_records(shared, sst_limit) + brec(0x000A, b""))
    g = globals_(0)
    return globals_(len(g)) + sheet


def ppt_document(project_cfb: bytes) -> bytes:
    """A PowerPoint Document stream holding the project as ExOleObjStg (compressed): a DocumentContainer
    record around it, as the VBA project's storage is kept in a .ppt."""
    body = struct.pack("<I", len(project_cfb)) + zlib.compress(project_cfb)
    stg = struct.pack("<HHI", 0x0010, 0x1011, len(body)) + body
    atom = struct.pack("<HHI", 0x0000, 0x0FF5, 12) + bytes(12)       # an unrelated atom before it
    return struct.pack("<HHI", 0x000F, 0x03E8, len(atom)) + atom + stg


def document(ext: str, modules: list, bad=None) -> bytes:
    """A macro document of `ext` holding `modules` [(name, source, document?)]."""
    if ext in OOXML_DIR:
        return ooxml(ext, vba_project_bin(modules, bad))
    store = vba_storage(modules, bad)
    filler = bytes(range(256)) * 20
    if ext in (".doc", ".dot"):
        return cfb_write({"WordDocument": filler, "1Table": filler[:900], "Macros": store})
    if ext in (".xls", ".xlt"):
        return cfb_write({"Workbook": biff_workbook([], []), "_VBA_PROJECT_CUR": store})
    if ext in (".ppt", ".pps"):
        return cfb_write({"PowerPoint Document": ppt_document(cfb_write(store)), "Current User": filler[:60]})
    raise ValueError(ext)


def doc_modules(text: str, ext: str) -> list:
    host = {".xls": ("ThisWorkbook", "0{00020819-0000-0000-C000-000000000046}"),
            ".xlsb": ("ThisWorkbook", "0{00020819-0000-0000-C000-000000000046}"),
            ".xlsm": ("ThisWorkbook", "0{00020819-0000-0000-C000-000000000046}")}.get(
        ext, ("ThisDocument", "0{00020906-0000-0000-C000-000000000046}"))
    return [(host[0], this_document(*host), True), ("Module1", module_text(text), False)]


# ================================================================ the corpora

def load_variants():
    out = []
    for day in DAYS:
        for base in sorted((CHALLENGES / day).glob("script-analysis-*")):
            dirs = [base, base / "time_trial"] + sorted((base / "time_trial" / "history").glob("*")) + \
                [base / "mastery"] + sorted((base / "mastery" / "history").glob("*"))
            for d in dirs:
                if not (d / "attempt.json").exists():
                    continue
                try:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        attempt, blobs, _ = run.load_offline("", str(d))
                        sets = run.split_sets(attempt, blobs)
                except SystemExit:
                    continue
                key = json.loads((d / "key.json").read_text()) if (d / "key.json").exists() else None
                for n, qs, files, _ in sets:
                    out.append({"name": f"{d.relative_to(CHALLENGES)}#{n}", "qs": qs, "files": files,
                                "key": {q["qid"]: key["answers"].get(q["answer_id"]) for q in qs} if key else None})
    return out


def vbs_specimens(corpus):
    """[(name, text, questions, key or None)] of each distinct Day 2-4 .vbs specimen text."""
    out, seen = [], set()
    for v in corpus:
        by = {}
        for q in v["qs"]:
            by.setdefault(q["member"], []).append(q)
        for member, qs in by.items():
            if Path(member).suffix.lower() != ".vbs":
                continue
            data = analyze.generic.find(v["files"], member)
            if data is None:
                continue
            text = plan_codec.text_of(data)
            if text in seen:
                continue
            seen.add(text)
            key = {q["qid"]: v["key"].get(q["qid"]) for q in qs} if v["key"] else None
            out.append((f"{v['name']} {member}", text, qs, key))
    return out


def renamed(qs, new):
    out = []
    for q in qs:
        q = dict(q, member=new)
        if isinstance(q.get("artifact"), str) and "->" in q["artifact"]:
            q["artifact"] = q["artifact"].split("->")[0] + "-> " + new
        out.append(q)
    return out


def rehearsal_cases():
    """The row-71 VBA rehearsal: tests/next_components.py's `vba` cases (the .bas specimens, their
    questions and truth), built from the newest saved attempt with a key."""
    sys.path.insert(0, str(HERE.parent.parent / "tests"))
    import next_components as NC
    try:
        import pyzipper
    except ImportError:
        pyzipper = None
    # NC.script_cases rewrites the NEWEST day's own component, and only specimens that carry a `Material_` /
    # `Codec_` label. Since Day 8 the newest component is a tagged descriptor (polyglot-*), which has no such
    # label: the newest day gives no case at all, and this test failed with "0 polyglot specimen(s)" on every
    # tree since (2026-10-12: it is the fixture lookup, not officevba or the solver). So the days are tried
    # newest first, each alone through a folder that links only that day, until one has labelled specimens.
    import tempfile
    days = sorted((d for d in CHALLENGES.glob("day-*") if re.fullmatch(r"day-\d+", d.name)
                   and any(d.glob("script-analysis-*"))), reverse=True)
    for day in days:
        with tempfile.TemporaryDirectory(prefix="office-rehearsal-") as view:
            (Path(view) / day.name).symlink_to(day, target_is_directory=True)
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    cases, note, _ = NC.script_cases(Path(view), pyzipper, HERE.parent)
            except SystemExit:
                continue
        vba = [c for c in cases if c["group"] == "vba" and not c.get("na")]
        if vba:
            return vba, f"{day.name}: {note}"
    return [], "no saved day has a labelled component"


def tally(got: dict, qids) -> tuple:
    p = sum(analyze.plain(got.get(i)) for i in qids)
    n = sum(got.get(i) is None for i in qids)
    return p, len(qids) - p - n, n


# ================================================================ the codec and the container

def test_ovba(texts):
    # MS-OVBA 3.2.1, "No Compression Example".
    vec = bytes.fromhex("0119B0006162636465666768006 96A6B6C6D6E6F7000717273747576 2E".replace(" ", ""))
    check("ovba: the MS-OVBA 3.2.1 example decompresses to its text",
          officevba.decompress(vec) == b"abcdefghijklmnopqrstuv.")
    rng = random.Random(930)
    samples = [b"", b"a", b"abc" * 3000, bytes(20000), b"#aaabcdefaaaaghijaaaabcdefaaaaghij" * 60]
    samples += [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 9000))) for _ in range(12)]
    samples += [bytes(rng.choice(b"ab \r\n") for _ in range(rng.randrange(1, 20000))) for _ in range(12)]
    samples += [t.encode("utf-8") for t in texts]
    bad, raw_ok = [], True
    for s in samples:
        for raw in (False, True):
            try:
                if officevba.decompress(ovba_compress(s, raw)) != s:
                    bad.append(len(s))
            except Exception as e:  # noqa: BLE001
                bad.append(f"{len(s)}: {e}")
    check(f"ovba: {len(samples) * 2 - len(bad)}/{len(samples) * 2} round trips ({len(texts)} saved specimens, "
          f"random, repetitive; compressed and raw chunks)", not bad, str(bad[:5]))
    big = b"x" * 9000
    check("ovba: repetitive text compresses (the copy tokens are used)", len(ovba_compress(big)) < 60 and raw_ok)


def test_cfb():
    rng = random.Random(931)
    tree = {"a": b"", "small": b"s" * 63, "edge": bytes(rng.randrange(256) for _ in range(4095)),
            "big": bytes(rng.randrange(256) for _ in range(4096)), "bigger": bytes(rng.randrange(256) for _ in range(70001)),
            "Sub": {"inner": b"inner data" * 50, "Deep": {"x": b"x" * 5000}}}
    data = cfb_write(tree)
    cfb = officevba.CFB(data, officevba.Clock())
    got = {}

    def walk(idx, prefix):
        for name, i in cfb.children(idx).items():
            e = cfb.entries[i]
            if e["type"] == 2:
                got[prefix + e["name"]] = cfb.stream(i)
            else:
                walk(i, prefix + e["name"] + "/")
    walk(0, "")
    want = {"a": b"", "small": tree["small"], "edge": tree["edge"], "big": tree["big"], "bigger": tree["bigger"],
            "Sub/inner": tree["Sub"]["inner"], "Sub/Deep/x": tree["Sub"]["Deep"]["x"]}
    check(f"cfb: {len(want)} streams (empty, mini stream, regular sectors, nested storages) read back byte for byte",
          got == want, str(sorted(got))[:200])


def test_7zip(specs):
    """An independent reader of the writer's compound files: 7-Zip (7zz/7z, when installed) lists and
    extracts every stream of a .doc, an .xls and a .ppt fixture, and each equals what CFB reads."""
    import shutil
    import subprocess
    tool = shutil.which("7zz") or shutil.which("7z") or next(
        (p for p in ("/opt/homebrew/bin/7zz", "/usr/local/bin/7zz") if Path(p).exists()), None)
    if tool is None:
        print("note 7-zip: not installed; the cross-check of the compound-file writer is skipped")
        return
    text = specs[0][1]
    docs = {"x.doc": document(".doc", doc_modules(text, ".doc")), "x.xls": document(".xls", doc_modules(text, ".xls")),
            "x.ppt": document(".ppt", doc_modules(text, ".ppt"))}
    n, bad = 0, []
    for name, data in docs.items():
        work = Path(tempfile.mkdtemp(dir=SCRATCH))
        (work / name).write_bytes(data)
        out = work / "out"
        r = subprocess.run([tool, "x", "-y", f"-o{out}", str(work / name)], capture_output=True, timeout=60)
        if r.returncode:
            bad.append(f"{name}: 7-zip exit {r.returncode}")
            continue
        cfb = officevba.CFB(data, officevba.Clock())

        def walk(idx, prefix):
            for _, i in cfb.children(idx).items():
                e = cfb.entries[i]
                if e["type"] == 2:
                    yield prefix + e["name"], cfb.stream(i)
                else:
                    yield from walk(i, prefix + e["name"] + "/")
        mine = dict(walk(0, ""))
        theirs = {str(f.relative_to(out)): f.read_bytes() for f in out.rglob("*") if f.is_file()}
        n += len(mine)
        if mine != theirs:
            bad.append(f"{name}: {sorted(set(mine) ^ set(theirs))[:4]} or bytes differ")
    check(f"7-zip: {n} streams of 3 hand-built compound files (.doc, .xls, .ppt) extracted by {Path(tool).name} equal "
          f"what officevba reads", n > 0 and not bad, "; ".join(bad))


# ================================================================ through analyze.py

def compare(name, ref_qs, ref_files, doc_qs, doc_files):
    ref, _ = solve(ref_qs, ref_files)
    got, err = solve(doc_qs, doc_files)
    ids = [q["qid"] for q in ref_qs]
    diff = [(i, got.get(i), ref.get(i)) for i in ids if got.get(i) != ref.get(i)]
    return ref, got, err, diff


def test_vbs(specs):
    exts = (".docm", ".xls", ".doc", ".xlsb", ".pptm", ".ppt")
    total = same = docs = keyed = keyed_ok = wrong = 0
    plain_n = unsure_n = none_n = 0
    bad = []
    for k, (name, text, qs, key) in enumerate(specs):
        stem = Path(qs[0]["member"]).stem
        ref_member = stem + ".bas"
        ref_qs = renamed(qs, ref_member)
        for ext in exts if k < 6 else exts[:2]:
            member = stem + ext
            data = document(ext, doc_modules(text, ext))
            if k == 0:
                fixture(member, data)
            ref, got, err, diff = compare(name, ref_qs, {ref_member: text.encode("utf-8")},
                                          renamed(qs, member), {member: data})
            docs += 1
            if "[officevba]" not in err:
                bad.append(f"{name} {ext}: not read as an Office document")
            if diff:
                bad.append(f"{name} {ext}: {diff[:2]}")
            for q in qs:
                a = got.get(q["qid"])
                total += 1
                same += a == ref.get(q["qid"])
                p, u, n = tally(got, [q["qid"]])
                plain_n, unsure_n, none_n = plain_n + p, unsure_n + u, none_n + n
                if key is not None and key.get(q["qid"]) is not None and analyze.plain(a):
                    keyed += 1
                    keyed_ok += a == key[q["qid"]]
                    if a != key[q["qid"]]:
                        wrong += 1
                        bad.append(f"{name} {ext} {q['qid']}: {a!r} key {key[q['qid']]!r}")
    check(f"vbs: {len(specs)} distinct Day 2-4 .vbs specimens in {docs} documents ({', '.join(exts)}): {same}/{total} "
          f"answers the same as the text read as a .bas file ({plain_n} plain, {unsure_n} unsure, {none_n} None)",
          len(specs) >= 9 and same == total and total > 0 and not [b for b in bad if "not read" in b],
          "; ".join(bad[:5]))
    check(f"vbs: {keyed_ok}/{keyed} plain answers equal key.json, {wrong} wrong", keyed > 0 and wrong == 0,
          "; ".join(b for b in bad if " key " in b)[:600])


def test_rehearsal(cases, note):
    total = same = docs = wrong = 0
    plain_n = unsure_n = none_n = 0
    ref_wrong = 0
    bad, spellings = [], set()
    for k, c in enumerate(cases):
        text = c["files"][c["member"]]
        stem = Path(c["member"]).stem
        for ext in (".docm", ".xls") if k % 3 else (".docm", ".xls", ".pptm", ".doc"):
            member = f"{stem}-{c['spelling']}{ext}"
            data = document(ext, doc_modules(text, ext))
            if c["spelling"] in ("single", "chars_all") and k < 2 * len({x["spelling"] for x in cases}):
                fixture(member, data)
            ref, got, err, diff = compare(member, c["questions"], {c["member"]: text.encode("utf-8")},
                                          renamed(c["questions"], member), {member: data})
            docs += 1
            spellings.add(c["spelling"])
            if diff:
                bad.append(f"{member}: {diff[:2]}")
            for qid, want in c["want"].items():
                a = got.get(qid)
                total += 1
                same += a == ref.get(qid)
                p, u, n = tally(got, [qid])
                plain_n, unsure_n, none_n = plain_n + p, unsure_n + u, none_n + n
                if analyze.plain(a) and (want is None or a != want):
                    wrong += 1
                    bad.append(f"{member} {qid}: {a!r} want {want!r}")
                b = ref.get(qid)
                ref_wrong += analyze.plain(b) and (want is None or b != want)
    check(f"vba rehearsal ({note}): {len(cases)} .bas specimens, {len(spellings)} spellings, in {docs} documents: "
          f"{same}/{total} answers the same as the .bas file ({plain_n} plain, {unsure_n} unsure, {none_n} None); "
          f"{wrong} wrong (the .bas files themselves: {ref_wrong})",
          len(cases) >= 10 and same == total and wrong == 0 and total > 0, "; ".join(bad[:5]))


def xlm_pieces(value: str, n=3) -> list:
    """`value` cut into string tokens of at most 255 characters, at least n pieces."""
    size = min(255, max(1, -(-len(value) // n)))
    return [value[i:i + size] for i in range(0, len(value), size)]


def test_xlm(cases):
    """The rehearsal's material as Excel 4.0 macro sheets: an .xlsm (XML formulas, a shared string, an
    inline string) and a BIFF8 .xls (FORMULA tokens, LABELSST, CONTINUE)."""
    singles = [c for c in cases if c["spelling"] == "single"]
    total = same = wrong = docs = 0
    plain_n = unsure_n = none_n = 0
    texts_equal, bad = 0, []
    for c in singles:
        text = c["files"][c["member"]]
        value = next(line for line in text.splitlines() if line.startswith("Material_"))
        value = value.split("=", 1)[1].strip().strip('"')
        pieces = xlm_pieces(value)
        stem = Path(c["member"]).stem
        formula = "&".join('"' + p + '"' for p in pieces)
        xml_cells = [(1, 1, ("s", 0)), (1, 2, ("f", formula)), (1, 3, ("f", "RETURN()")),
                     (2, 1, ("str", "inert static-analysis fixture"))]
        shared = ["Huntress Script Triage -- inert static-analysis fixture (Excel 4.0)"]
        xlsm = ooxml(".xlsm", None, [macrosheet_xml(xml_cells)], shared)
        tokens = concat_tokens(pieces)
        bif_cells = [(0, 0, ("sst", 0)), (0, 1, ("rgce", tokens)), (0, 2, ("rgce", bytes([0x42, 0, 55, 0]))),
                     (1, 0, ("label", "inert static-analysis fixture"))]
        xls = cfb_write({"Workbook": biff_workbook(bif_cells, shared, sst_limit=40)})
        a = officevba.macro_text(stem + ".xlsm", xlsm)
        b = officevba.macro_text(stem + ".xls", xls)
        texts_equal += a is not None and b is not None and a == b
        if a != b:
            bad.append(f"{stem}: the two renderings differ: {a!r} {b!r}"[:300])
        answers = []
        for ext, data in ((".xlsm", xlsm), (".xls", xls)):
            member = f"{stem}-xlm{ext}"
            fixture(member, data)
            got, err = solve(renamed(c["questions"], member), {member: data})
            answers.append(got)
            docs += 1
            for qid, want in c["want"].items():
                v = got.get(qid)
                total += 1
                p, u, n = tally(got, [qid])
                plain_n, unsure_n, none_n = plain_n + p, unsure_n + u, none_n + n
                if analyze.plain(v) and (want is None or v != want):
                    wrong += 1
                    bad.append(f"{member} {qid}: {v!r} want {want!r}")
        same += answers[0] == answers[1]
    plan_ids = sum(1 for c in singles for qid in c["want"] if qid.endswith(("-adapter", "-campaign")))
    check(f"xlm: {len(singles)} materials as macro sheets in {docs} documents (.xlsm, BIFF8 .xls): {texts_equal} read to the "
          f"same text both ways, {same} answer the same; {plain_n} plain, {unsure_n} unsure, {none_n} None of {total}; "
          f"{wrong} wrong", singles and texts_equal == len(singles) and same == len(singles) and wrong == 0
          and plain_n >= plan_ids, "; ".join(bad[:4]))


def test_scope(specs):
    name, text, qs, key = specs[0]
    stem = Path(qs[0]["member"]).stem
    base_off = analyze.officevba
    plain_files = {}
    # 1. No macro container: answers exactly as before the row (officevba switched off).
    cases = {
        stem + ".docx": ooxml(".docx", None, extra=[("word/notes.txt", text)]),
        stem + ".doc": cfb_write({"WordDocument": text.encode("latin-1", "replace"), "1Table": b"\0" * 600}),
        stem + ".xls": text.encode("utf-8"),            # a text file under an Office extension
    }
    moved = []
    for member, data in cases.items():
        nqs = renamed(qs, member)
        analyze.officevba = None
        try:
            before, _ = solve(nqs, {member: data})
        finally:
            analyze.officevba = base_off
        after, err = solve(nqs, {member: data})
        plain_files[member] = sum(analyze.plain(v) for v in after.values())
        if before != after or "[officevba]" in err or officevba.routed(member, {member: data}) is not None:
            moved.append(member)
    check(f"scope: {len(cases)} files of an Office extension with no macro container (.docx, .doc without VBA, a text "
          f"file) are read exactly as before the row", not moved, str(moved))
    # 2. Two modules, two plans: no plan question answered plain.
    other = next((t for n, t, q, k in specs[1:] if t != text), None)
    member = stem + ".docm"
    data = document(".docm", [("Module1", module_text(text), False), ("Module2", module_text(other, "Module2"), False)])
    fixture("two-plans.docm", data)
    got, err = solve(renamed(qs, member), {member: data})
    plan_q = [q["qid"] for q in qs if analyze.generic.tail_of(q) in ("adapter", "campaign", "role", "url")]
    plain_plan = [i for i in plan_q if analyze.plain(got.get(i))]
    check(f"scope: two modules carrying two different plans answer none of {len(plan_q)} plan questions plain",
          plan_q and not plain_plan and "[officevba]" in err, f"{plain_plan} {got}"[:300])


def test_corrupt(specs):
    name, text, qs, key = specs[0]
    name2, text2, qs2, _ = next(s for s in specs[1:] if s[2][0]["member"] != qs[0]["member"])
    stem = Path(qs[0]["member"]).stem
    other_member = qs2[0]["member"]
    good_doc = document(".docm", doc_modules(text, ".docm"))
    good_xls = document(".xls", doc_modules(text, ".xls"))

    def fat_loop(data):
        b = bytearray(data)
        first_dir = struct.unpack_from("<I", b, 0x30)[0]
        fat0 = struct.unpack_from("<I", b, 0x4C)[0]
        struct.pack_into("<I", b, (fat0 + 1) * 512 + 4 * first_dir, first_dir)
        return bytes(b)
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", "<root/>")
        z.writestr("word/vbaProject.bin", b"\0" * (6 << 20))
    sheet_dtd = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><xm:macrosheet xmlns:xm="m"><c r="A1"><f>&a;</f></c></xm:macrosheet>'
    forms = {
        "a cut file": (".docm", good_doc[:len(good_doc) * 2 // 3]),
        "a cut compound file": (".xls", good_xls[:len(good_xls) // 2]),
        "a FAT loop in the directory chain": (".xls", fat_loop(good_xls)),
        "a chunk signature": (".docm", document(".docm", doc_modules(text, ".docm"), "chunk")),
        "a text offset past the module stream": (".xls", document(".xls", doc_modules(text, ".xls"), "offset")),
        "a module count that does not match": (".doc", document(".doc", doc_modules(text, ".doc"), "count")),
        "a module stream that is not there": (".pptm", document(".pptm", doc_modules(text, ".pptm"), "missing")),
        "a vbaProject.bin that is no compound file": (".docm", ooxml(".docm", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(700))),
        "a decompression bomb in the zip": (".docm", zbuf.getvalue()),
        "a macro sheet with a DOCTYPE": (".xlsm", ooxml(".xlsm", None, [sheet_dtd])),
        "a BIFF8 formula token not rendered": (".xls", cfb_write({"Workbook": biff_workbook(
            [(0, 0, ("rgce", b"\x01\x00\x00\x00\x00"))], [])})),
    }
    ok_n, bad = 0, []
    for what, (ext, data) in forms.items():
        member = stem + ext
        nqs = renamed(qs, member) + qs2
        files = {member: data, other_member: text2.encode("utf-8")}
        ref_other, _ = solve(qs2, {other_member: files[other_member]})
        got, err = solve(nqs, files)
        mine = [q["qid"] for q in qs]
        problems = analyze.covers(nqs, files)
        good = (all(got.get(i) is None for i in mine) and all(got.get(q["qid"]) == ref_other.get(q["qid"]) for q in qs2)
                and "does not read" in err and any(member in p for p in problems)
                and not any(other_member in p for p in problems))
        ok_n += good
        if not good:
            bad.append(f"{what}: answered {[i for i in mine if got.get(i) is not None][:3]}, covers {problems[:1]}")
        if what in ("a chunk signature", "a FAT loop in the directory chain"):
            fixture(f"corrupt-{what.split()[1]}{ext}", data)
    check(f"corrupt: {ok_n}/{len(forms)} damaged containers leave all their questions unanswered, the other specimen "
          f"unchanged, and covers() names the file", ok_n == len(forms), "; ".join(bad[:4]))
    good_problems = analyze.covers(renamed(qs, stem + ".docm"), {stem + ".docm": good_doc})
    check("corrupt: covers() finds the plan in an intact .docm (no problem)", good_problems == [], str(good_problems))


def test_bounds():
    # A CompressedContainer whose chunks each expand ~680 times: the 4 MB bound stops it.
    chunk = struct.pack("<H", 0xB000 | (6 - 3)) + bytes([0b10, 0x41]) + struct.pack("<H", 0x0FFC)
    bomb = b"\x01" + chunk * 3000
    t0 = time.perf_counter()
    try:
        officevba.decompress(bomb)
        stopped = False
    except officevba.Bad:
        stopped = True
    dt = time.perf_counter() - t0
    check(f"bounds: a decompression bomb stops at the 4 MB bound in {dt:.2f}s", stopped and dt < 2.0)


def test_speed(specs):
    name, text, qs, key = specs[0]
    stem = Path(qs[0]["member"]).stem
    padding = "".join(f"' padding line {i} of an inert fixture module\r\n" for i in range(4000))
    member = stem + ".docm"
    data = document(".docm", [("Module1", module_text(text), False), ("Module2", 'Attribute VB_Name = "Module2"\r\n'
                                                                       + padding, False)])
    t0 = time.perf_counter()
    got, err = solve(renamed(qs, member), {member: data})
    dt = time.perf_counter() - t0
    check(f"speed: a .docm with a {len(padding) // 1000} KB second module solved in {dt:.2f}s ({len(got)} answers)",
          dt < 3.0 and len(got) > 0)


def test_review(specs):
    """The five review blockers of 2026-10-07, each as its repro."""
    filler = bytes(range(256)) * 20

    def doc_with(st):
        return cfb_write({"WordDocument": filler, "1Table": filler[:900], "Macros": st})
    # 1. A CompressedChunk that claims more bytes than the stream holds is Bad. Exhaustive at the codec:
    # every tail cut of every specimen's module container either fails or ends on a chunk boundary
    # (each chunk but the last holds exactly 4096 bytes, so a cut there leaves a whole container).
    cuts = cut_bad = cut_whole = cut_wrong = 0
    for _, text, _, _ in specs:
        body = ovba_compress(module_text(text).encode("cp1252"))
        whole = officevba.decompress(body)
        for k in range(1, len(body)):
            cuts += 1
            try:
                got = officevba.decompress(body[:-k])
            except officevba.Bad:
                cut_bad += 1
                continue
            cut_whole += 1
            cut_wrong += not (whole.startswith(got) and len(got) % 4096 == 0)
    check(f"review 1: {cuts} tail cuts of {len(specs)} module containers: {cut_bad} Bad, {cut_whole} end on a chunk "
          f"boundary, {cut_wrong} give a cut module", cut_wrong == 0 and cut_bad > 0)
    # ... and through solve_set: a .doc whose Module1 stream is cut answers no plain value the intact one does not.
    pick = [s for s in specs if "remote-write" in s[0]][:1] + [s for s in specs if "remote-write" not in s[0]][:7]
    docs = answered = differ = 0
    detail = []
    for name, text, qs, key in pick:
        member = Path(qs[0]["member"]).stem + ".doc"
        nqs = renamed(qs, member)
        st = vba_storage(doc_modules(text, ".doc"))
        intact, _ = solve(nqs, {member: doc_with(st)})
        mod = st["VBA"]["Module1"]
        for k in sorted({686, 1, 2, 3, 50} | set(range(5, len(mod) - 40, 97))):
            if k >= len(mod):
                continue
            st2 = {**st, "VBA": {**st["VBA"], "Module1": mod[:-k]}}
            got, _ = solve(nqs, {member: doc_with(st2)})
            docs += 1
            answered += any(v is not None for v in got.values())
            bad = [i for i, v in got.items() if analyze.plain(v) and v != intact.get(i)]
            differ += len(bad)
            if bad and len(detail) < 3:
                detail.append(f"{name} cut {k}: {bad[0]}={got[bad[0]]!r}")
    check(f"review 1: {docs} .doc files with a cut Module1 stream ({len(pick)} specimens): {answered} answered at all, "
          f"{differ} plain answers that differ from the intact document", docs and differ == 0, "; ".join(detail))

    # 2. A .ppt with two ExOleObjStg: a damaged one is Bad, never passed over.
    (na, ta, qa, _), (nb, tb, qb, _) = specs[0], next(s for s in specs[1:] if s[1] != specs[0][1])
    proj_a, proj_b = cfb_write(vba_storage(doc_modules(ta, ".ppt"))), cfb_write(vba_storage(doc_modules(tb, ".ppt")))

    def stg(project, cut=0, want=None, inst=0x0010):
        z = zlib.compress(project) if inst == 0x0010 else project
        body = (struct.pack("<I", len(project) if want is None else want) + z[:len(z) - cut]) if inst == 0x0010 else z
        return struct.pack("<HHI", inst, 0x1011, len(body)) + body

    def ppt(stream):
        return cfb_write({"PowerPoint Document": stream, "Current User": filler[:60]})
    member = Path(qb[0]["member"]).stem + ".ppt"
    nqs = renamed(qb, member)
    ref, _ = solve(nqs, {member: ppt(stg(proj_b))})
    forms = {
        "a zlib stream cut by 50 bytes before the good project": stg(proj_a, cut=50) + stg(proj_b),
        "a stated size larger than the inflated object": stg(proj_a, want=len(proj_a) + 1) + stg(proj_b),
        "a stated size smaller than the inflated object": stg(proj_a, want=len(proj_a) - 1) + stg(proj_b),
        "a record that runs past the stream": stg(proj_b) + stg(proj_a)[:-30],
    }
    bad = []
    for what, stream in forms.items():
        files = {member: ppt(stream)}
        got, err = solve(nqs, files)
        if any(v is not None for v in got.values()) or not any(member in x for x in analyze.covers(nqs, files)):
            bad.append(f"{what}: {sum(analyze.plain(v) for v in got.values())} plain")
    check(f"review 2: {len(forms) - len(bad)}/{len(forms)} .ppt files with a damaged ExOleObjStg beside a good one answer "
          f"nothing (B alone answers {sum(analyze.plain(v) for v in ref.values())} plain)",
          not bad and sum(analyze.plain(v) for v in ref.values()) > 0, "; ".join(bad))
    other = struct.pack("<I", 300) + zlib.compress(bytes(300))
    ok_stream = struct.pack("<HHI", 0x0010, 0x1011, len(other)) + other + stg(proj_b, inst=0x0000)
    got, _ = solve(nqs, {member: ppt(ok_stream)})
    check("review 2: an object that inflates whole but is no compound file is passed over; a stored (instance 0) "
          "project beside it is read like the compressed one", got == ref, str(got)[:200])

    # 3. BIFF8 formulas: the per-document deadline holds on formula cells, and a rendered formula is bounded.
    for label, cells in (("8 cells of 65,509 parentheses", [(0, r, ("rgce", ptg_str("a") + b"\x15" * 65509)) for r in range(8)]),
                         ("200 cells of 32,000 parentheses", [(0, r, ("rgce", ptg_str("a") + b"\x15" * 32000)) for r in range(200)])):
        data = cfb_write({"Workbook": biff_workbook(cells, ["x"])})
        t0 = time.perf_counter()
        r = officevba.routed("a.xls", {"a.xls": data})
        dt = time.perf_counter() - t0
        check(f"review 3: a .xls of {label} ({len(data) // 1024} KB) stops in {dt:.2f}s: {r[2] if r else r}",
              r is not None and r[2] is not None and dt < officevba.SECONDS + 0.6)

    # 4. Every ExOleObjStg counts toward the bound, whatever it inflates to.
    bomb = struct.pack("<I", 32 << 20) + zlib.compress(b"\0" * (32 << 20), 9)
    data = ppt((struct.pack("<HHI", 0x0010, 0x1011, len(bomb)) + bomb) * 200)
    t0 = time.perf_counter()
    r = officevba.routed("a.ppt", {"a.ppt": data})
    dt = time.perf_counter() - t0
    check(f"review 4: a .ppt of 200 non-compound 32 MB objects ({len(data) >> 20} MB) stops in {dt:.2f}s: "
          f"{r[2] if r else r}", r is not None and r[2] is not None and dt < 1.0)
    small = struct.pack("<I", 64) + zlib.compress(bytes(64))
    data = ppt((struct.pack("<HHI", 0x0010, 0x1011, len(small)) + small) * 17)
    r = officevba.routed("a.ppt", {"a.ppt": data})
    check(f"review 4: 17 small non-compound objects pass the bound of {officevba.MAX_EMBEDDED}: {r[2] if r else r}",
          r is not None and r[2] is not None)

    # 5. A stub macro beside a plan in the document body: the body is read as before the row.
    rows = []
    for name, text, qs, key in specs[:12]:
        member = Path(qs[0]["member"]).stem + "-body.doc"
        nqs = renamed(qs, member)
        stub = vba_storage([("ThisDocument", this_document(), True), ("Module1", module_text(
            "Sub AutoOpen()\r\n x = ActiveDocument.Content.Text\r\nEnd Sub\r\n"), False)])
        data = cfb_write({"WordDocument": text.encode("latin-1", "replace"), "1Table": b"\0" * 600, "Macros": stub})
        off = analyze.officevba
        analyze.officevba = None
        try:
            before, _ = solve(nqs, {member: data})
        finally:
            analyze.officevba = off
        after, err = solve(nqs, {member: data})
        rows.append((sum(analyze.plain(v) for v in before.values()), sum(analyze.plain(v) for v in after.values()),
                     before == after, "read as its bytes" in err))
    same = sum(r[2] and r[3] for r in rows)
    check(f"review 5: {same}/{len(rows)} .doc files with a stub macro and the plan in the body answer as before the row "
          f"({sum(r[0] for r in rows)} plain before, {sum(r[1] for r in rows)} after)", same == len(rows) and rows[0][0] > 0,
          str(rows))


def main():
    corpus = load_variants()
    if not corpus:
        print("TEST_WAVEC2_OFFICE: the saved Day 2-4 Script Analysis attempts are not there")
        print("TEST_WAVEC2_OFFICE passed=0 failed=0")
        return 2
    specs = vbs_specimens(corpus)
    cases, note = rehearsal_cases()
    test_ovba([t for _, t, _, _ in specs])
    test_cfb()
    test_7zip(specs)
    test_vbs(specs)
    test_rehearsal(cases, note)
    test_xlm(cases)
    test_scope(specs)
    test_corrupt(specs)
    test_bounds()
    test_speed(specs)
    test_review(specs)
    passed = sum(ok for _, ok in results)
    failed = len(results) - passed
    print(f"TEST_WAVEC2_OFFICE passed={passed} failed={failed}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
