#!/usr/bin/env python3
"""Malicious document toolkit (backlog row 87, toolkit key "maldoc"). Static only: nothing in a
document is ever run, opened in its application or fetched. No Game Master request, no token.

  .venv/bin/python solvers/toolkits/maldoc.py <file>... [--json] [--source] [--extract DIR] [--sandbox]
  .venv/bin/python solvers/toolkits/maldoc.py --attempt <attempt dir>      (each question, the field and the answer)

What it reads, all in this process with plain Python (sub-second for a small file), by the bytes
and never by the file name:

  ole       compound files (Word, Excel, PowerPoint 97-2003, MSI, MSG, vbaProject.bin): streams and
            storages, SummaryInformation, the VBA project (modules and their source, MS-OVBA
            decompression, no oletools needed), Excel 4.0 (XLM) macro sheets and their formulas,
            \\x01Ole10Native packages, encryption marks, ActiveMime (MSO) wrappers
  ooxml     docx/docm/xlsx/xlsm/pptx/...: core and app properties, vbaProject.bin, external
            relationships (remote templates), DDE fields, macro sheets, hidden sheets, embeddings
  rtf       \\objdata objects (OLE1 header, class name, Package file names, the embedded OLE2 file)
  pdf       objects, object streams, decoded streams (Flate, ASCIIHex, ASCII85, RunLength), the
            Info dictionary, JavaScript, OpenAction, Launch, URIs, embedded files, #xx name escapes
  onenote   .one sections: every FileDataStoreObject (the embedded files)
  lnk       shell links: target, arguments, working directory, icon, times, tracker (machine id,
            MAC address), volume serial, data appended after the link
  iso/img/vhd  ISO 9660 with Joliet, MBR/GPT disk images with FAT12/16/32, fixed and dynamic VHD:
            volume label, the file listing, every file as a payload
  hta/wsf/sct  the script blocks with their language, handed to the Script Analysis lane as
            payloads named <file>#script<N>.<ext> (--extract writes them; analyze.py reads them)

Every payload found inside a document (an embedded object, a file of an image, a script block) is
identified and read the same way, three levels deep. VBA and XLM string building (Chr, ChrW, &,
StrReverse, Replace, Mid, Left, Right, Join(Array()), CHAR, base64 and hex literals, PowerShell
-EncodedCommand) is evaluated statically; what a user-written decoder function does is not.

For an agent, by hand:  parse(data, name) -> the document map;  cfb(data) / vba_modules(data) /
vba_decompress(b) / deobfuscate(source) / ole_properties(data) / ooxml(data) / rtf_objects(data) /
pdf(data) / pdf_pypdf(data) / pdf_text(data) / onenote_files(data) / lnk(data) / iso(data) /
disk_image(data) / vhd(data) / scripts(text) / yara_scan(data) / decrypt_office(data) and
sandbox_run(tool, data) for oletools, binwalk and 7z in the container of tools/sandbox.py (never
natively, never on a clock).

signals(questions, files) -> 0..1 says how much a delivery and its questions look like this
category. solve_set(questions, files, ctx) is the runner contract. It never guesses (AGENTS.md,
"Uncertain answers"):
  - a question a known lane owns (Determine <property> for <file>, -role/-attack ids, dNN_ ids,
    message, ANS-) is None: its lane's solver answers it;
  - the asked field is read from the end of the answer id, else from the question's own words; the
    document is the one the question names, else the only document of the delivery that has the
    field (or every one that has it agrees). Two documents with different values: None;
  - plain: a count above zero whose every definition gives the same number under an integer answer
    with no qualifier in the question or its answer id; the one option of a list the question
    itself gives when it is a positive read from the bytes; the one form the answer_format's own
    pattern lets through (never for a time whose UTC reading the file does not state);
  - never plain, at most offered: the hash of the one embedded payload (which object the question
    means is not judged), an ATT&CK id, a verdict (suspicious), a negative (no macros, not
    encrypted), a count of zero. A document that was not read whole (a PDF object that does not
    parse, a VBA project with no source read) answers no count and no "has none";
  - everything else is labels.pick('maldoc.<field>/<kind>', options): the value as it stands in
    the bytes first, then its other spellings or formats; tools/verify.py probes them on the
    untimed base and the ledger answers the next variant plain;
  - a singular question with several different values (three URLs, "the URL"), an encrypted
    document, a field that was not read: None.
"""
import base64
import binascii
import hashlib
import io
import json
import re
import struct
import sys
import time
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
TOOLS = HERE.parent.parent / "tools"
RULES = HERE / "maldoc_rules.yar"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)             # a sibling toolkit must never shadow a standard module (email, crypto, ...)
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
import labels   # noqa: E402
import triage   # noqa: E402

KEY = "maldoc"
DEOBFUSCATE_SECONDS = 1.0       # the static evaluator's time budget for one source
ARROW = " -> "
MAX_DEPTH = 3                   # payload levels read inside a document
MAX_PAYLOADS = 200
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
UTC = timezone.utc

# The label ledger knows five lanes. Until solvers/common/labels.py lists this toolkit, register its
# key prefix for this process (the tool that probes loads this module first, so parse and learn see
# it too). The seed is solvers/toolkits/conventions/maldoc/conventions.json, the ledger
# challenges/_ledger/maldoc.jsonl.
labels.LANE_DIRS.setdefault(KEY, "toolkits/conventions/" + KEY)


def pick(key, options):
    """labels.pick; were the key's lane unknown to labels, the unsure wire form (never sent)."""
    try:
        return labels.pick(key, options)
    except ValueError:
        opts = labels._pairs(options)
        return ("??" + json.dumps({"k": str(key).lower(), "o": [[n, v] for n, v in opts[:12]]},
                                  separators=(",", ":"))) if opts else None


class Alt(list):
    """One value with several formats: [(name, value), ...], best first (a MAC address with colons
    or dashes). With definitions=True the entries are different readings of the question (every
    module, or only the modules with code): the answer_format's pattern never chooses among those."""

    def __init__(self, items=(), definitions=False):
        super().__init__(items)
        self.definitions = definitions


class Labels(list):
    """One fact with several spellings: [label, ...], best first; `shape` goes into the key."""

    def __init__(self, items, shape=""):
        super().__init__(dict.fromkeys(items))
        self.shape = shape


# ---- small helpers -------------------------------------------------------------------------------

def _u16(b, o): return struct.unpack_from("<H", b, o)[0]
def _u32(b, o): return struct.unpack_from("<I", b, o)[0]
def _u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def filetime(v):
    """A Windows FILETIME (100 ns since 1601) as an aware UTC datetime; None for 0 or nonsense."""
    if not v or v >= 1 << 63:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=v // 10)
    except OverflowError:
        return None


def guid(b: bytes) -> str | None:
    """16 bytes in the Windows layout as UUID text, or None for an invalid length."""
    if len(b) != 16:
        return None
    a, b1, c = struct.unpack_from("<IHH", b, 0)
    return f"{a:08x}-{b1:04x}-{c:04x}-{b[8:10].hex()}-{b[10:16].hex()}"


def _text(b: bytes) -> str:
    """Bytes of a text file as str: BOMs honoured, else UTF-8, else Latin-1."""
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", "replace")
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


def _printable(s: str) -> bool:
    return bool(s) and sum(1 for c in s if c.isprintable() or c in "\r\n\t") >= 0.95 * len(s)


def _hashes(data: bytes) -> dict:
    return {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest()}


# ---- what a file is --------------------------------------------------------------------------------

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ONE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")       # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
ONETOC_MAGIC = bytes.fromhex("a12fff43d9ef764c9ee210ea5722765f")    # {43FF2FA1-EFD9-4C76-9EE2-10EA5722765F}
LNK_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")
DOC_KINDS = ("ole", "ooxml", "rtf", "pdf", "onenote", "lnk", "iso", "vhd", "vhdx", "disk_image", "hta", "wsf",
             "sct", "activemime", "slk", "xml2003", "csv_dde")

# A DDE formula in a cell: =cmd|'/c calc.exe'!A0 (also behind +, - or @, as a spreadsheet reads them)
_DDE_FORMULA = re.compile(r"""(?:^|[\t,;">])[ ]*[=+\-@][ ]*(?:[A-Za-z]{2,12}\()?[ ]*([A-Za-z0-9_.\\:\- ]{1,64}?)[ ]*\|[ ]*('(?:[^'\r\n]|'')*'|[^!\r\n,;"]{1,512})[ ]*![ ]*[A-Za-z0-9_$']{1,64}""", re.M)


def dde_formulas(text: str) -> list:
    """['service topic'] of the DDE formulas in spreadsheet text, the topic as written (quotes kept),
    as oletools' msodde prints them: =cmd|'/c calc.exe'!A0 gives "cmd '/c calc.exe'"."""
    out = []
    for m in _DDE_FORMULA.finditer(text):
        row = f"{m.group(1).strip()} {m.group(2).strip()}"
        if row not in out:
            out.append(row)
    return out


_DDE_APPS = re.compile(r"(?i)(?:.*[\\/])?(?:cmd|msexcel|excel|winword|powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|msiexec|wmic|"
                       r"dde(?:auto)?|[\w.-]+\.exe)$")


def _dde_cells(text: str) -> list:
    """The DDE formulas of delimited text that a spreadsheet would run, as dde_formulas() writes
    them: the service is a program's name (cmd, MSEXCEL, a path ending in .exe) or the topic is in
    single quotes. The looser dde_formulas() also takes `- item | other !note` of a Markdown list
    or a shell line; that must not make a text file a document of this toolkit."""
    out = []
    for m in _DDE_FORMULA.finditer(text):
        service, topic = m.group(1).strip(), m.group(2).strip()
        row = f"{service} {topic}"
        if " " not in service and row not in out and (_DDE_APPS.match(service) or (topic.startswith("'") and topic.endswith("'") and len(topic) > 2)):
            out.append(row)
    return out


SCRIPT_KINDS = ("hta", "wsf", "sct")


def kind_of(data: bytes, name: str = "") -> str:
    """The toolkit's family of a file, by its bytes: one of DOC_KINDS (ooxml only for a zip with
    [Content_Types].xml), else ''."""
    head = data[:16]
    if head.startswith(OLE_MAGIC):
        return "ole"
    if head.startswith(b"{\\rt"):
        return "rtf"
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if head == ONE_MAGIC or head == ONETOC_MAGIC:
        return "onenote"
    if data[:20] == LNK_MAGIC:
        return "lnk"
    if head.startswith(b"PK\x03\x04"):
        return "ooxml" if b"[Content_Types].xml" in data[:4096] or b"[Content_Types].xml" in data[-65536:] else ""
    if head.startswith(b"vhdxfile"):
        return "vhdx"
    if head.startswith(b"conectix") or data[-512:-504] == b"conectix" or data[-511:-503] == b"conectix":
        return "vhd"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if len(data) >= 512 and data[510:512] == b"\x55\xaa" and (_looks_fat(data[:512]) or _mbr_parts(data) or data[3:11] in (b"NTFS    ", b"EXFAT   ")):
        return "disk_image"
    if head.startswith(b"ActiveMime") or (b"ActiveMime" in data[:64]):
        return "activemime"
    if head.startswith(b"ID;P") and len(data) <= 16 << 20:
        return "slk"
    if len(data) <= 32 << 20 and b"<" in data[:256] and (
            b"<?mso-application" in data[:4096] or b"urn:schemas-microsoft-com:office:spreadsheet" in data[:4096]
            or b"schemas.microsoft.com/office/word/2003/wordml" in data[:4096]):
        return "xml2003"
    if len(data) <= 4 << 20 and b"|" in data[:1 << 16] and b"!" in data[:1 << 16] and b"\x00" not in data[:4096] \
            and b"<" not in data[:64] and _dde_cells(data[:1 << 16].decode("latin-1")):
        return "csv_dde"
    if len(data) <= 4 << 20 and (b"<" in data[:4096] or name.lower().endswith((".hta", ".wsf", ".sct", ".wsc"))):
        low = data[:1 << 20].replace(b"\x00", b"").lower()
        if b"<script" in low:
            if b"<hta:application" in low or name.lower().endswith(".hta"):
                return "hta"
            if b"<scriptlet" in low or b"<registration" in low:
                return "sct"
            if re.search(rb"<(?:job|package)\b", low):
                return "wsf"
    return ""


# ---- compound file (OLE2, MS-CFB) -----------------------------------------------------------------

class CFB:
    """A compound file read with struct only. entries: [{path, name, type ('stream'|'storage'|'root'),
    size, clsid, created, modified}]; stream(path) -> bytes (path compared case-insensitively)."""

    def __init__(self, data: bytes):
        if data[:8] != OLE_MAGIC or len(data) < 512:
            raise ValueError("not a compound file")
        self.data = data
        self.major = _u16(data, 0x1A)
        shift, mini_shift = _u16(data, 0x1E), _u16(data, 0x20)
        if (self.major, shift) not in ((3, 9), (4, 12)) or mini_shift != 6 or _u16(data, 0x1C) != 0xFFFE:
            raise ValueError("invalid compound file sector geometry")
        self.ss = 1 << shift
        self.mss = 1 << mini_shift
        nfat, dir_start = _u32(data, 0x2C), _u32(data, 0x30)
        self.cutoff = _u32(data, 0x38)
        minifat_start, difat_start, ndifat = _u32(data, 0x3C), _u32(data, 0x44), _u32(data, 0x48)
        difat = [x for x in struct.unpack_from("<109I", data, 0x4C)]
        sec, guard = difat_start, 0
        while sec < 0xFFFFFFFA and guard < max(ndifat, 0) + 4 and guard < 4096:
            raw = self._sector(sec)
            if len(raw) < self.ss:
                break
            vals = struct.unpack_from(f"<{self.ss // 4}I", raw)
            difat += vals[:-1]
            sec, guard = vals[-1], guard + 1
        self.fat = []
        for s in difat[:max(nfat, 0)]:
            if s >= 0xFFFFFFFA:
                continue
            raw = self._sector(s)
            self.fat += struct.unpack_from(f"<{len(raw) // 4}I", raw)
        raw = self._chain(minifat_start)
        self.minifat = list(struct.unpack_from(f"<{len(raw) // 4}I", raw))
        self._dir = self._chain(dir_start)
        self.entries, self._by_path = [], {}
        self._walk()
        root = self._raw_entry(0)
        self.root_clsid = guid(root["clsid"]) if root and any(root["clsid"]) else None
        self._mini = self._chain(root["start"], root["size"]) if root else b""

    def _sector(self, n):
        off = (n + 1) * self.ss
        return self.data[off:off + self.ss]

    def _chain(self, start, size=None):
        out, seen, sec = [], set(), start
        while sec < 0xFFFFFFFA and sec not in seen and sec < len(self.fat) and len(seen) < 1 << 20:
            seen.add(sec)
            out.append(self._sector(sec))
            sec = self.fat[sec]
        raw = b"".join(out)
        return raw if size is None else raw[:size]

    def _mini_chain(self, start, size):
        out, seen, sec = [], set(), start
        while sec < 0xFFFFFFFA and sec not in seen and sec < len(self.minifat) and len(seen) < 1 << 20:
            seen.add(sec)
            out.append(self._mini[sec * self.mss:(sec + 1) * self.mss])
            sec = self.minifat[sec]
        return b"".join(out)[:size]

    def _raw_entry(self, i):
        e = self._dir[i * 128:(i + 1) * 128]
        if len(e) < 128:
            return None
        nlen = min(_u16(e, 64), 64)
        name = e[:max(nlen - 2, 0)].decode("utf-16-le", "replace")
        size = _u64(e, 120) if self.major >= 4 else _u32(e, 120)
        return {"name": name, "type": e[66], "left": _u32(e, 68), "right": _u32(e, 72), "child": _u32(e, 76),
                "clsid": e[80:96], "created": _u64(e, 100), "modified": _u64(e, 108), "start": _u32(e, 116), "size": size}

    def _walk(self):
        root = self._raw_entry(0)
        if not root:
            return
        seen = set()
        stack = [(root["child"], "")]
        self.broken = False             # a tree link that leads to no stream or storage, or a walk cut short
        while stack and len(seen) < 20000:
            i, prefix = stack.pop()
            if i >= 0xFFFFFFFA:
                continue
            if i in seen:
                self.broken = True
                continue
            seen.add(i)
            e = self._raw_entry(i)
            if not e or e["type"] not in (1, 2):
                self.broken = True
                continue
            path = prefix + e["name"]
            entry = {"path": path, "name": e["name"], "type": "storage" if e["type"] == 1 else "stream",
                     "size": e["size"] if e["type"] == 2 else 0,
                     "clsid": guid(e["clsid"]) if any(e["clsid"]) else None,
                     "created": filetime(e["created"]), "modified": filetime(e["modified"]), "_raw": e, "_index": i}
            self.entries.append(entry)
            self._by_path[path.lower()] = entry
            stack.append((e["left"], prefix))
            stack.append((e["right"], prefix))
            if e["type"] == 1:
                stack.append((e["child"], path + "/"))
        self.broken = self.broken or bool(stack)
        self.entries.sort(key=lambda x: x["_index"])

    def intact(self) -> bool:
        """True when the directory tree has no broken link and every stream is there in full: the
        file was not cut, shifted or overwritten where this reader looks."""
        if getattr(self, "broken", True):
            return False
        for e in self.entries:
            if e["type"] == "stream":
                raw = e["_raw"]
                got = self._mini_chain(raw["start"], raw["size"]) if raw["size"] < self.cutoff else self._chain(raw["start"], raw["size"])
                if len(got) != raw["size"]:
                    return False
        return True

    def directory_entries(self) -> int:
        """Stream and storage entries in the directory, reachable from the root or not."""
        n = 0
        for i in range(1, min(len(self._dir) // 128, 40000)):
            e = self._raw_entry(i)
            n += bool(e and e["type"] in (1, 2))
        return n

    def paths(self, kind="stream"):
        return [e["path"] for e in self.entries if e["type"] == kind]

    def has(self, path):
        return path.lower() in self._by_path

    def stream(self, path) -> bytes:
        e = self._by_path.get(path.lower())
        if not e or e["type"] != "stream":
            raise KeyError(path)
        raw = e["_raw"]
        if raw["size"] < self.cutoff:
            return self._mini_chain(raw["start"], raw["size"])
        return self._chain(raw["start"], raw["size"])


def cfb(data: bytes) -> CFB:
    return CFB(data)


# ---- VBA (MS-OVBA) ----------------------------------------------------------------------------------

def vba_decompress(data: bytes) -> bytes:
    """A CompressedContainer (MS-OVBA 2.4.1) as its plain bytes; ValueError when it is not one."""
    if not data or data[0] != 1:
        raise ValueError("no VBA compressed container")
    out, pos, n = bytearray(), 1, len(data)
    while pos + 2 <= n:
        header = _u16(data, pos)
        pos += 2
        size = (header & 0x0FFF) + 3
        end = pos + size - 2
        if (header >> 12) & 7 != 3 or end > n:
            raise ValueError("invalid or truncated VBA chunk")
        if not header & 0x8000:
            if size != 4098:
                raise ValueError("invalid VBA raw chunk size")
            out += data[pos:end]
            pos = end
            continue
        start = len(out)
        while pos < end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= end:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > end:
                    raise ValueError("truncated VBA copy token")
                token = _u16(data, pos)
                pos += 2
                diff = len(out) - start
                if diff < 1:
                    raise ValueError("VBA copy token before any byte")
                bits = max(4, (diff - 1).bit_length())
                length = (token & (0xFFFF >> bits)) + 3
                offset = (token >> (16 - bits)) + 1
                if offset > len(out):
                    raise ValueError("VBA copy token points before the buffer")
                for _ in range(length):
                    out.append(out[-offset])
        pos = end
    if pos != n:
        raise ValueError("truncated VBA chunk header")
    return bytes(out)


_CODEPAGES = {10000: "mac_roman", 65001: "utf-8", 1200: "utf-16-le", 932: "cp932", 936: "gbk", 949: "cp949", 950: "big5"}


def _codec(cp):
    name = _CODEPAGES.get(cp) or f"cp{cp}"
    try:
        "".encode(name)
        return name
    except LookupError:
        return "cp1252"


def _vba_dir(raw: bytes) -> dict:
    """The decompressed `dir` stream: {codepage, project, references, modules: [{name, stream, offset, type}]}."""
    out = {"codepage": 1252, "project": None, "references": [], "modules": []}
    pos, n, mod = 0, len(raw), None
    while pos + 6 <= n:
        rid, size = _u16(raw, pos), _u32(raw, pos + 2)
        pos += 6
        if rid == 0x0009:                   # PROJECTVERSION: the size field says 4, six bytes follow
            pos += 6
            continue
        body = raw[pos:pos + size]
        pos += size
        if rid == 0x0003 and len(body) >= 2:
            out["codepage"] = _u16(body, 0)
        elif rid == 0x0004:
            out["project"] = body.decode(_codec(out["codepage"]), "replace")
        elif rid == 0x0016:
            out["references"].append(body.decode(_codec(out["codepage"]), "replace"))
        elif rid == 0x0019:
            mod = {"name": body.decode(_codec(out["codepage"]), "replace"), "stream": None, "offset": 0, "type": None}
            out["modules"].append(mod)
        elif mod is not None:
            if rid == 0x0047 and body:
                mod["name"] = body.decode("utf-16-le", "replace")
            elif rid == 0x001A:
                mod["stream"] = body.decode(_codec(out["codepage"]), "replace")
            elif rid == 0x0032 and body:
                mod["stream"] = body.decode("utf-16-le", "replace")
            elif rid == 0x0031 and len(body) >= 4:
                mod["offset"] = _u32(body, 0)
            elif rid == 0x0021:
                mod["type"] = "procedural"
            elif rid == 0x0022:
                mod["type"] = "document"
            elif rid == 0x002B:
                mod = None
    return out


_ATTR = re.compile(r"(?im)^\s*Attribute\s+VB_\w+.*$\n?")


def _code_lines(source: str) -> list:
    """The lines of a module that are code: no Attribute lines, no blank lines, no Option lines."""
    return [ln for ln in _ATTR.sub("", source).splitlines()
            if ln.strip() and not re.match(r"(?i)\s*(?:option\s+\w+|'|rem\b)", ln)]


def vba_project(c: CFB) -> dict:
    """The VBA project of a compound file, or {} when it has none:
    {storage, project, codepage, references, modules: [{name, stream, type, source, code_lines}], notes}."""
    dirs = [p for p in c.paths() if p.lower().endswith("vba/dir") or p.lower() == "dir"]
    if not dirs:
        return {}
    notes = []
    base = dirs[0][:-3]             # '.../VBA/'
    info = {"codepage": 1252, "project": None, "references": [], "modules": []}
    try:
        info = _vba_dir(vba_decompress(c.stream(dirs[0])))
    except (ValueError, KeyError, struct.error, IndexError) as e:
        notes.append(f"the dir stream could not be read ({e}); modules found by their compressed source")
    codec = _codec(info["codepage"])
    modules, used = [], set()
    for m in info["modules"]:
        path = base + (m["stream"] or m["name"])
        raw = None
        try:
            raw = c.stream(path)
            src = vba_decompress(raw[m["offset"]:]).decode(codec, "replace")
        except (KeyError, ValueError, struct.error, IndexError):
            notes.append(f"module {m['name']}: its source could not be decompressed")
            src = None
        # The bytes before MODULEOFFSET are the module's PerformanceCache (compiled VBA p-code). A
        # stomped module (MS-OVBA, MITRE T1564.007) keeps this p-code but has its source removed.
        perf = raw[:m["offset"]] if (raw is not None and m.get("offset")) else b""
        used.add(path.lower())
        modules.append({"name": m["name"], "stream": m["stream"] or m["name"], "type": m["type"], "source": src,
                        "code_lines": len(_code_lines(src)) if src is not None else None,
                        "pcode_size": (m.get("offset") or 0) if raw is not None else 0,
                        "pcode_nonzero": sum(1 for x in perf[:1 << 20] if x)})
    if not modules:                 # no usable dir: every stream of the storage that holds compressed source
        for p in c.paths():
            if not p.lower().startswith(base.lower()) or p.lower() in used or p.lower().endswith("/dir"):
                continue
            raw = c.stream(p)
            at = raw.find(b"\x00Attribut")
            if at >= 3:
                try:
                    src = vba_decompress(raw[at - 3:]).decode(codec, "replace")
                except (ValueError, struct.error, IndexError):
                    continue
                name = (re.search(r'(?im)^Attribute VB_Name = "([^"]+)"', src) or [None, p.rsplit("/", 1)[-1]])[1]
                modules.append({"name": name, "stream": p.rsplit("/", 1)[-1], "type": None, "source": src,
                                "code_lines": len(_code_lines(src))})
    # Project-level compiled p-code: the _VBA_PROJECT stream and any SRP_<n> performance-cache
    # streams. Their presence is what tells a stomped module (source gone, p-code kept) from an
    # ordinary empty module (no p-code to speak of).
    vba_project_size, srp = 0, []
    try:
        vp = base + "_VBA_PROJECT"
        if c.has(vp):
            vba_project_size = len(c.stream(vp))
        srp = [p for p in c.paths() if p.lower().startswith(base.lower()) and re.search(r"(?:^|/)srp_\d+$", p.lower())]
    except (KeyError, ValueError, struct.error, IndexError):
        pass
    return {"storage": base.rstrip("/"), "project": info["project"], "codepage": info["codepage"],
            "references": info["references"], "modules": modules, "notes": notes,
            "vba_project_size": vba_project_size, "srp_streams": srp}


PCODE_SIG_MIN = 40      # non-zero bytes in a module's PerformanceCache that count as real compiled p-code


def vba_stomped_modules(project: dict) -> list:
    """The modules whose source was removed/zeroed while compiled p-code remains (VBA stomping,
    MITRE T1564.007). Conservative and deterministic: a module whose source decompressed to ZERO
    executable lines but whose PerformanceCache carries substantial non-zero compiled bytes, in a
    project that carries compiled p-code (a _VBA_PROJECT or SRP_ stream). A module whose source
    could not be decompressed at all is NOT claimed (ambiguous: left to None elsewhere), and an
    ordinary empty module (a tiny p-code stub) stays below PCODE_SIG_MIN and is not flagged."""
    if not (project.get("vba_project_size") or project.get("srp_streams")):
        return []
    out = []
    for m in project.get("modules") or []:
        if m.get("source") is None:
            continue
        if (m.get("code_lines") or 0) == 0 and (m.get("pcode_nonzero") or 0) >= PCODE_SIG_MIN:
            out.append(m["name"])
    return out


def vba_modules(data: bytes) -> list:
    """[(module name, source)] of any file that carries VBA: a compound file, an OOXML file (its
    vbaProject.bin), an ActiveMime wrapper."""
    k = kind_of(data)
    if k == "activemime":
        data, k = activemime(data) or b"", "ole"
    if k == "ooxml":
        out = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for n in zf.namelist():
                    if n.lower().endswith("vbaproject.bin"):
                        out += vba_modules(zf.read(n))
        except (zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, OSError, EOFError, zlib.error):
            return []
        return out
    if k != "ole":
        return []
    try:
        compound = CFB(data)
    except ValueError:
        return []
    return [(m["name"], m["source"]) for m in vba_project(compound).get("modules", [])]


AUTOEXEC = ("autoopen", "autoexec", "autoclose", "autoexit", "autonew", "auto_open", "auto_close", "document_open",
            "document_close", "document_new", "documentopen", "document_beforeclose", "workbook_open", "workbook_activate",
            "workbook_beforeclose", "workbook_close", "worksheet_activate", "app_documentopen", "presentation_open")
_PROC = re.compile(r"(?im)^[ \t]*(?:(?:public|private|friend|static)[ \t]+)*(?:sub|function)[ \t]+([A-Za-z_]\w*)")
_PROC_KIND = re.compile(r"(?im)^[ \t]*(?:(?:public|private|friend|static)[ \t]+)*(sub|function)[ \t]+([A-Za-z_]\w*)")
_WRITE = re.compile(r"(?i)\b(?:open\b.{1,200}\bfor\s+(?:output|binary|append|random)|savetofile|createtextfile|"
                    r"urldownloadtofile|filecopy|adodb\.stream|\.write(?:line|text)?\b|put\s+#)")
_EXEC = re.compile(r"(?i)\b(?:shell|wscript\.shell|shellexecute\w*|createobject|getobject|callbyname|macscript|"
                   r"executeexcel4macro|application\.run|powershell|cmd\.exe|winexec|createprocess\w*|"
                   r"createthread|virtualalloc\w*|declare\s+(?:ptrsafe\s+)?(?:sub|function))\b|\.(?:run|exec)\b")


def mraptor(source: str) -> dict:
    """MacroRaptor's rule on VBA source: {autoexec: [procedures as written], write, execute, flags,
    suspicious}. suspicious = autoexec and (write or execute)."""
    procs = _PROC.findall(source)
    auto = [p for p in procs if p.lower() in AUTOEXEC]
    body = "\n".join(ln.split("'")[0] if '"' not in ln else ln for ln in source.splitlines()
                     if not re.match(r"(?i)\s*(?:'|rem\b|attribute\b)", ln))
    w, x = bool(_WRITE.search(body)), bool(_EXEC.search(body))
    return {"autoexec": list(dict.fromkeys(auto)), "write": w, "execute": x,
            "flags": ("A" if auto else "") + ("W" if w else "") + ("X" if x else ""),
            "suspicious": bool(auto) and (w or x)}


# ---- static evaluation of VBA and XLM string expressions --------------------------------------------

class _NoParse(Exception):
    pass


_FUNCS = ("chr", "chrw", "chrb", "char", "asc", "ascw", "strreverse", "replace", "mid", "left", "right", "lcase", "ucase",
          "lower", "upper", "trim", "ltrim", "rtrim", "cstr", "str", "cint", "clng", "val", "int", "len", "join", "array",
          "split", "hex", "space", "string", "concatenate", "substitute", "t", "unichar", "code")
_START = re.compile(r'"|(?<![\w.])(?:vba\.|strings\.)?(?:' + "|".join(_FUNCS) + r')\$?\s*\(', re.I)


class _Expr:
    """A recursive-descent reader of one VBA/XLM expression of literals and pure string functions.
    It stops where the grammar ends (the rest of the line is not its business) and raises _NoParse
    for a name it has no value for: an expression is evaluated whole or not at all."""

    def __init__(self, text, pos=0, env=None):
        self.t, self.i, self.env, self.ops = text, pos, env or {}, 0

    def ws(self):
        while self.i < len(self.t) and self.t[self.i] in " \t":
            self.i += 1

    def expr(self):
        v = self.term()
        while True:
            save = (self.i, self.ops)
            self.ws()
            op = self.t[self.i:self.i + 1]
            if op not in ("&", "+", "-"):
                self.i = save[0]
                return v
            self.i += 1
            try:
                r = self.term()
            except _NoParse:
                self.i, self.ops = save
                return v
            try:
                if op == "&":
                    v = self._s(v) + self._s(r)
                elif isinstance(v, str) and isinstance(r, str) and op == "+":
                    v = v + r
                else:
                    v = self._n(v) + self._n(r) if op == "+" else self._n(v) - self._n(r)
            except _NoParse:
                self.i, self.ops = save
                return v
            self.ops += 1
            if isinstance(v, str) and len(v) > 1 << 20:
                raise _NoParse

    def term(self):
        v = self.factor()
        while True:
            save = self.i
            self.ws()
            m = re.compile(r"\*|/|\\|\^|mod\b|xor\b", re.I).match(self.t, self.i)
            if not m or isinstance(v, (str, list)):
                self.i = save
                return v
            self.i = m.end()
            try:
                r = self.factor()
                if isinstance(r, (str, list)):
                    raise _NoParse
                op = m.group().lower()
                v = (v * r if op == "*" else v / r if op == "/" else int(v) // int(r) if op == "\\" else v ** r if op == "^" and abs(r) < 64
                     else int(v) % int(r) if op == "mod" else int(v) ^ int(r))
            except (_NoParse, ZeroDivisionError, OverflowError, TypeError):
                self.i = save
                return v

    @staticmethod
    def _s(v):
        if isinstance(v, str):
            return v
        if isinstance(v, list):
            raise _NoParse
        return str(int(v)) if float(v).is_integer() else str(v)

    @staticmethod
    def _n(v):
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return int(v) if float(v).is_integer() else v
        raise _NoParse

    def factor(self):
        self.ws()
        t, i = self.t, self.i
        if i >= len(t):
            raise _NoParse
        c = t[i]
        if c == '"':
            j, out = i + 1, []
            while j < len(t):
                if t[j] == '"':
                    if t[j + 1:j + 2] == '"':
                        out.append('"')
                        j += 2
                        continue
                    self.i = j + 1
                    return "".join(out)
                out.append(t[j])
                j += 1
            raise _NoParse
        m = re.compile(r"&h([0-9a-f]+)(?:&(?=\s*(?:[),]|$)))?|&o([0-7]+)(?:&(?=\s*(?:[),]|$)))?|(\d+(?:\.\d+)?)[#!%@]?", re.I).match(t, i)
        if m:
            self.i = m.end()
            if m.group(1):
                return int(m.group(1), 16)
            if m.group(2):
                return int(m.group(2), 8)
            return float(m.group(3)) if "." in m.group(3) else int(m.group(3))
        if c == "(":
            self.i += 1
            v = self.expr()
            self.ws()
            if t[self.i:self.i + 1] != ")":
                raise _NoParse
            self.i += 1
            return v
        if c == "-":
            self.i += 1
            return -self._n(self.factor())
        m = re.compile(r"((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\$?").match(t, i)
        if not m:
            raise _NoParse
        name = m.group(1).lower()
        self.i = m.end()
        save = self.i
        self.ws()
        if t[self.i:self.i + 1] == "(":
            fn = name.rsplit(".", 1)[-1]
            if fn not in _FUNCS or name not in (fn, "vba." + fn, "strings." + fn, "vba.strings." + fn, "application.worksheetfunction." + fn):
                raise _NoParse
            self.i += 1
            args = []
            self.ws()
            if t[self.i:self.i + 1] != ")":
                while True:
                    args.append(self.expr())
                    self.ws()
                    if t[self.i:self.i + 1] in (",", ";"):
                        self.i += 1
                        continue
                    break
            if t[self.i:self.i + 1] != ")":
                raise _NoParse
            self.i += 1
            self.ops += 1
            return self.call(fn, args)
        self.i = save
        if name in self.env:
            return self.env[name]
        raise _NoParse

    def call(self, fn, a):
        s, n = self._s, self._n
        try:
            if fn in ("chr", "chrw", "chrb", "char", "unichar") and len(a) == 1:
                v = int(n(a[0]))
                if fn in ("chr", "chrb", "char") and 0 <= v < 256:
                    return bytes([v]).decode("cp1252", "replace") if v >= 128 else chr(v)
                if 0 <= v < 0x110000:
                    return chr(v)
            elif fn in ("asc", "ascw", "code") and len(a) == 1 and isinstance(a[0], str) and a[0]:
                return ord(a[0][0])
            elif fn == "strreverse" and len(a) == 1:
                return s(a[0])[::-1]
            elif fn == "replace" and len(a) == 3:
                return s(a[0]).replace(s(a[1]), s(a[2])) if s(a[1]) else s(a[0])
            elif fn == "replace" and len(a) == 4 and not isinstance(a[1], str):       # XLM REPLACE(text, start, count, new)
                st, cnt = int(n(a[1])), int(n(a[2]))
                return s(a[0])[:st - 1] + s(a[3]) + s(a[0])[st - 1 + cnt:]
            elif fn == "substitute" and len(a) == 3:
                return s(a[0]).replace(s(a[1]), s(a[2])) if s(a[1]) else s(a[0])
            elif fn == "mid" and len(a) in (2, 3):
                st = int(n(a[1]))
                if st >= 1:
                    return s(a[0])[st - 1:] if len(a) == 2 else s(a[0])[st - 1:st - 1 + max(0, int(n(a[2])))]
            elif fn == "left" and len(a) in (1, 2):
                return s(a[0])[:max(0, int(n(a[1]))) if len(a) == 2 else 1]
            elif fn == "right" and len(a) in (1, 2):
                k = max(0, int(n(a[1]))) if len(a) == 2 else 1
                return s(a[0])[len(s(a[0])) - k:] if k else ""
            elif fn in ("lcase", "lower") and len(a) == 1:
                return s(a[0]).lower()
            elif fn in ("ucase", "upper") and len(a) == 1:
                return s(a[0]).upper()
            elif fn == "trim" and len(a) == 1:
                return s(a[0]).strip(" ")
            elif fn == "ltrim" and len(a) == 1:
                return s(a[0]).lstrip(" ")
            elif fn == "rtrim" and len(a) == 1:
                return s(a[0]).rstrip(" ")
            elif fn in ("cstr", "t") and len(a) == 1:
                return s(a[0])
            elif fn == "str" and len(a) == 1:
                v = n(a[0])
                return (" " if v >= 0 else "") + s(v)
            elif fn in ("cint", "clng", "int", "val") and len(a) == 1:
                if isinstance(a[0], str):
                    m = re.match(r"\s*-?\d+(?:\.\d+)?", a[0])
                    if not m:
                        raise _NoParse
                    v = float(m.group())
                else:
                    v = n(a[0])
                return int(round(v)) if fn in ("cint", "clng") else (int(v // 1) if fn == "int" else (int(v) if float(v).is_integer() else v))
            elif fn == "len" and len(a) == 1 and isinstance(a[0], str):
                return len(a[0])
            elif fn == "array":
                return list(a)
            elif fn == "join" and len(a) in (1, 2) and isinstance(a[0], list):
                return (s(a[1]) if len(a) == 2 else " ").join(s(x) for x in a[0])
            elif fn == "concatenate" and a:
                return "".join(s(x) for x in a)
            elif fn == "split" and len(a) in (1, 2) and isinstance(a[0], str):
                sep = s(a[1]) if len(a) == 2 else " "
                return a[0].split(sep) if sep else [a[0]]
            elif fn == "hex" and len(a) == 1:
                return format(int(n(a[0])), "X")
            elif fn == "space" and len(a) == 1 and 0 <= int(n(a[0])) <= 65536:
                return " " * int(n(a[0]))
            elif fn == "string" and len(a) == 2 and 0 <= int(n(a[0])) <= 65536:
                ch = a[1][:1] if isinstance(a[1], str) else chr(int(n(a[1])))
                return ch * int(n(a[0]))
        except (ValueError, TypeError, OverflowError, IndexError):
            pass
        raise _NoParse


_ASSIGN = re.compile(r"^\s*(?:(?:public|private|global|dim|static)\s+)?(?:const\s+)?(?:set\s+)?([A-Za-z_]\w*)\s*"
                     r"(?:as\s+\w+\s*)?=\s*(.+)$", re.I)
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEXS = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_ENC = re.compile(r"(?i)-e(?:nc(?:odedcommand)?|c)?\s+['\"]?([A-Za-z0-9+/]{16,}={0,2})")
_CALLS = re.compile(r"(?i)(?:(?<![\w.\"])(?:vba\.|interaction\.)?shell|\.run|\.exec|\.shellexecute|(?<![\w.\"])shellexecute[aw]?|(?<![\w.\"])winexec)\b\s*\(?\s*")
_VARUSE = re.compile(r"(?<![\w.\"])([A-Za-z_]\w*)\s*[&+]")


def _decode_blobs(text: str) -> list:
    """[(technique, decoded)] for the base64 and hex runs of a string that decode to printable text."""
    out = []
    for m in _ENC.finditer(text):
        try:
            raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
            dec = raw.decode("utf-16-le")
            if _printable(dec):
                out.append(("powershell_encoded_command", dec))
        except (ValueError, UnicodeDecodeError):
            pass
    for m in _B64.finditer(text):
        s = m.group()
        if len(s) % 4 or re.fullmatch(r"[0-9A-Fa-f]+", s) or not (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)):
            continue
        try:
            raw = base64.b64decode(s, validate=True)
        except (ValueError, binascii.Error):
            continue
        for codec in ("utf-8", "utf-16-le"):
            try:
                dec = raw.decode(codec)
            except UnicodeDecodeError:
                continue
            if _printable(dec) and len(dec) >= 6 and "\x00" not in dec:
                if ("powershell_encoded_command", dec) not in out:
                    out.append(("base64", dec))
                break
    for m in _HEXS.finditer(text):
        try:
            dec = bytes.fromhex(m.group()).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable(dec) and len(dec) >= 6:
            out.append(("hex", dec))
    return out


def deobfuscate(source: str, xlm: bool = False) -> dict:
    """Static string recovery from VBA source (or XLM formulas, one per line):
    {decoded: [strings built by an expression], commands: [strings handed to Shell/Run/Exec/EXEC],
    techniques: [chr_concat, str_reverse, replace, substring, array_join, string_concat, base64, hex,
    powershell_encoded_command], literals: [...]}. Assignments are followed top to bottom
    (s = s & "..." builds up); loops, branches and user-written functions are not run."""
    text = re.sub(r"[ \t]+_\r?\n[ \t]*", " ", source)
    env, env_ops, decoded, commands, tech, literals, dead = {}, {}, [], [], [], [], set()
    # Hostile source (fifty thousand nested Chr( on one line) made every start a deep failed parse:
    # 160 s. The evaluation has a time budget; past it the rest of the source is left unread.
    stop_at = time.monotonic() + DEOBFUSCATE_SECONDS
    truncated = False

    def note_tech(expr_text):
        low = expr_text.lower()
        for name, rx in (("chr_concat", r"\bchrw?\$?\s*\(|\bchar\s*\(|\bunichar\s*\("), ("str_reverse", r"\bstrreverse\s*\("),
                         ("replace", r"\b(?:replace|substitute)\s*\("), ("substring", r"\b(?:mid|left|right)\$?\s*\("),
                         ("array_join", r"\bjoin\s*\(|\bconcatenate\s*\(")):
            if re.search(rx, low) and name not in tech:
                tech.append(name)
        if not re.search(r"\b(?:chrw?|char|unichar|strreverse|replace|substitute|mid|left|right|join|concatenate)\$?\s*\(", low) \
                and "string_concat" not in tech:
            tech.append("string_concat")

    def add(v, expr_text, into=decoded):
        if isinstance(v, str) and len(v) >= 4 and v not in into:
            into.append(v)
            if into is decoded:
                note_tech(expr_text)

    for line in text.splitlines():
        if not line.strip() or re.match(r"(?i)\s*(?:'|rem\b|attribute\b)", line):
            continue
        if time.monotonic() > stop_at:
            truncated = True
            break
        for m in re.finditer(r'"((?:[^"]|"")*)"', line):
            if len(m.group(1)) >= 4 and m.group(1) not in literals:
                literals.append(m.group(1).replace('""', '"'))
        body = line.lstrip()
        if xlm and body.startswith("="):
            body = body[1:]
        a = None if xlm else _ASSIGN.match(body)
        assigned = False
        if a:
            p = _Expr(a.group(2), 0, env)
            try:
                v = p.expr()
                p.ws()
                rest = a.group(2)[p.i:]
                if rest.strip() and not rest.lstrip().startswith(("'", ":")):
                    raise _NoParse
                name = a.group(1).lower()
                own = re.search(r"(?i)(?<![\w.])" + re.escape(name) + r"(?![\w(])", a.group(2)) is not None
                assigned = True
                if isinstance(v, (str, list)):
                    env[name] = v
                    env_ops[name] = ((env_ops.get(name, (0, ""))[0] if own else 0) + p.ops, a.group(2))
                    if not own and p.ops >= 1:
                        add(v, a.group(2))
                elif name in env or name in dead:      # a number set twice is a counter, not a constant
                    env.pop(name, None)
                    dead.add(name)
                else:
                    env[name] = v
            except (_NoParse, RecursionError):
                env.pop(a.group(1).lower(), None)
                env_ops.pop(a.group(1).lower(), None)
                dead.add(a.group(1).lower())
        for cm in _CALLS.finditer(body):
            p = _Expr(body, cm.end(), env)
            try:
                v = p.expr()
                if isinstance(v, str) and len(v) >= 4 and v not in commands and not re.fullmatch(r"[\w.]+", v):
                    commands.append(v)
            except (_NoParse, RecursionError):
                pass
        i = len(body) if assigned else 0
        fails = 0
        while i < len(body):
            if fails >= 200:                # this line is not an expression the reader knows: leave it
                break
            if time.monotonic() > stop_at:
                truncated = True
                break
            m = _START.search(body, i)
            starts = [m.start()] if m else []
            for vm in _VARUSE.finditer(body, i):
                if vm.group(1).lower() in env and isinstance(env[vm.group(1).lower()], str):
                    starts.append(vm.start())
                    break
            if not starts:
                break
            st = min(starts)
            p = _Expr(body, st, env)
            try:
                v = p.expr()
            except RecursionError:
                fails += 50
                i = st + 1
                continue
            except _NoParse:
                fails += 1
                i = st + 1
                continue
            if p.ops >= 1:
                add(v, body[st:p.i])
            i = max(p.i, st + 1)
    for name, (ops, expr_text) in env_ops.items():
        if ops >= 1 and isinstance(env.get(name), str):
            add(env[name], expr_text)
    for s in list(decoded) + literals + list(commands):
        for technique, dec in _decode_blobs(s):
            if dec not in decoded:
                decoded.append(dec)
            if technique not in tech:
                tech.append(technique)
    # A partial build (s = "ab": s = s & "cd") is not a result once the whole is known.
    decoded = [d for d in decoded if not any(d != o and o.startswith(d) and len(o) > len(d) for o in decoded)] if len(decoded) < 400 else decoded
    if truncated:
        # a string built up over lines that were not all read is a cut value: none is reported
        return {"decoded": [], "commands": [], "techniques": [], "literals": literals, "truncated": True}
    return {"decoded": decoded, "commands": commands, "techniques": tech, "literals": literals, "truncated": False}


# ---- OLE property sets, packages, Excel 4.0 macros ---------------------------------------------------

_SUMMARY = {2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template", 8: "last_saved_by",
            9: "revision", 11: "last_printed", 12: "created", 13: "modified", 14: "pages", 15: "words", 16: "characters",
            18: "application", 19: "security"}
_DOCSUMMARY = {2: "category", 14: "manager", 15: "company"}


def _propset(raw: bytes, names: dict) -> dict:
    out = {}
    try:
        if _u32(raw, 24) < 1:
            return out
        base = _u32(raw, 44)
        count = _u32(raw, base + 4)
        props = [(_u32(raw, base + 8 + 8 * i), _u32(raw, base + 12 + 8 * i)) for i in range(min(count, 200))]
        cp = 1252
        for pid, off in props:
            if pid == 1 and _u32(raw, base + off) & 0xFFFF == 2:
                cp = _u16(raw, base + off + 4)
        for pid, off in props:
            if pid not in names:
                continue
            at = base + off
            vt = _u32(raw, at) & 0xFFFF
            if vt == 0x1E:
                n = _u32(raw, at + 4)
                v = raw[at + 8:at + 8 + n].split(b"\x00")[0].decode(_codec(cp), "replace") if cp != 1200 else \
                    raw[at + 8:at + 8 + n].decode("utf-16-le", "replace").split("\x00")[0]
            elif vt == 0x1F:
                n = _u32(raw, at + 4)
                v = raw[at + 8:at + 8 + 2 * n].decode("utf-16-le", "replace").split("\x00")[0]
            elif vt == 0x40:
                v = filetime(_u64(raw, at + 4))
            elif vt == 3:
                v = struct.unpack_from("<i", raw, at + 4)[0]
            elif vt == 2:
                v = struct.unpack_from("<h", raw, at + 4)[0]
            else:
                continue
            if v not in (None, ""):
                out[names[pid]] = v
        out["codepage"] = cp
    except (struct.error, IndexError):
        pass
    return out


def ole_properties(data: bytes) -> dict:
    """SummaryInformation and DocumentSummaryInformation of a compound file: {title, subject, author,
    last_saved_by, template, application, created, modified, last_printed (datetimes, UTC), company, ...}."""
    try:
        c = CFB(data) if not isinstance(data, CFB) else data
    except ValueError:
        return {}
    out = {}
    if c.has("\x05DocumentSummaryInformation"):
        out.update(_propset(c.stream("\x05DocumentSummaryInformation"), _DOCSUMMARY))
    if c.has("\x05SummaryInformation"):
        out.update(_propset(c.stream("\x05SummaryInformation"), _SUMMARY))
    return out


def ole10native(raw: bytes, package: bool = False):
    """An \\x01Ole10Native stream (or, with package=True, the data of an OLE1 'Package' object):
    {filename, source_path, temp_path, data}, or None."""
    try:
        pos = 0 if package else 4
        pos += 2
        end = raw.index(b"\x00", pos)
        filename = raw[pos:end].decode("latin-1")
        pos = end + 1
        end = raw.index(b"\x00", pos)
        src = raw[pos:end].decode("latin-1")
        pos = end + 1 + 8
        end = raw.index(b"\x00", pos)
        temp = raw[pos:end].decode("latin-1")
        pos = end + 1
        size = _u32(raw, pos)
        pos += 4
        if size > len(raw) - pos or not filename or len(filename) > 260:
            return None
        return {"filename": filename, "source_path": src, "temp_path": temp, "data": raw[pos:pos + size]}
    except (ValueError, struct.error, IndexError):
        return None


_XLM_FUNC = {111: ("CHAR", 1), 31: ("MID", 3), 32: ("LEN", 1), 53: ("GOTO", 1), 112: ("LOWER", 1), 113: ("UPPER", 1),
             118: ("TRIM", 1), 121: ("CODE", 1)}
_XLM_VAR = {110: "EXEC", 150: "CALL", 149: "REGISTER", 54: "HALT", 55: "RETURN", 60: "FORMULA", 17: "RUN", 336: "CONCATENATE",
            88: "SET.NAME", 1: "IF", 4: "SUM", 115: "LEFT", 116: "RIGHT", 120: "SUBSTITUTE", 148: "INDIRECT"}
_BINOPS = {3: "+", 4: "-", 5: "*", 6: "/", 7: "^", 8: "&", 9: "<", 10: "<=", 11: "=", 12: ">=", 13: ">", 14: "<>"}


def _col(n):
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def xlm_formula(rgce: bytes):
    """A BIFF8 parsed formula (Ptg tokens) as text, or None when it holds a token this reader
    does not know (the formula is then not shown rather than shown wrong)."""
    st, i, n = [], 0, len(rgce)
    try:
        while i < n:
            t = rgce[i]
            i += 1
            base = t if t < 0x20 else (t & 0x1F) | 0x20
            if t == 0x17:
                cch, fl = rgce[i], rgce[i + 1]
                i += 2
                if fl & 1:
                    s = rgce[i:i + 2 * cch].decode("utf-16-le")
                    i += 2 * cch
                else:
                    s = rgce[i:i + cch].decode("latin-1")
                    i += cch
                st.append('"' + s.replace('"', '""') + '"')
            elif t == 0x1E:
                st.append(str(_u16(rgce, i)))
                i += 2
            elif t == 0x1F:
                v = struct.unpack_from("<d", rgce, i)[0]
                st.append(str(int(v)) if v.is_integer() else repr(v))
                i += 8
            elif t == 0x1D:
                st.append("TRUE" if rgce[i] else "FALSE")
                i += 1
            elif t == 0x16:
                st.append("")
            elif t in _BINOPS:
                b, a = st.pop(), st.pop()
                st.append(a + _BINOPS[t] + b)
            elif t == 0x12:
                st.append("+" + st.pop())
            elif t == 0x13:
                st.append("-" + st.pop())
            elif t == 0x15:
                st.append("(" + st.pop() + ")")
            elif t == 0x19:
                fl, w = rgce[i], _u16(rgce, i + 1)
                i += 3
                if fl & 0x04:
                    i += (w + 1) * 2
                if fl & 0x10:
                    st.append("SUM(" + st.pop() + ")")
            elif base == 0x21:
                name, argc = _XLM_FUNC[_u16(rgce, i)]
                i += 2
                args = [st.pop() for _ in range(argc)][::-1]
                st.append(f"{name}({','.join(args)})")
            elif base == 0x22:
                argc, idx = rgce[i] & 0x7F, _u16(rgce, i + 1) & 0x7FFF
                i += 3
                args = [st.pop() for _ in range(argc)][::-1]
                if idx == 255 and args:
                    st.append(f"{args[0]}({','.join(args[1:])})")
                else:
                    st.append(f"{_XLM_VAR.get(idx) or (_XLM_FUNC.get(idx) or ('FUNC' + str(idx),))[0]}({','.join(args)})")
            elif base == 0x23:
                st.append(f"NAME{_u16(rgce, i)}")
                i += 4
            elif base in (0x24, 0x2C):
                st.append(f"{_col(_u16(rgce, i + 2) & 0xFF)}{_u16(rgce, i) + 1}")
                i += 4
            elif base in (0x25, 0x2D):
                st.append(f"{_col(_u16(rgce, i + 4) & 0xFF)}{_u16(rgce, i) + 1}:{_col(_u16(rgce, i + 6) & 0xFF)}{_u16(rgce, i + 2) + 1}")
                i += 8
            elif base == 0x3A:
                st.append(f"SHEET{_u16(rgce, i)}!{_col(_u16(rgce, i + 4) & 0xFF)}{_u16(rgce, i + 2) + 1}")
                i += 6
            elif base == 0x39:
                st.append(f"EXTNAME{_u16(rgce, i + 2)}")
                i += 6
            else:
                return None
        return "=" + st[-1] if len(st) == 1 else None
    except (IndexError, KeyError, struct.error, UnicodeDecodeError):
        return None


def biff_workbook(raw: bytes) -> dict:
    """An Excel 97-2003 Workbook stream: {sheets: [{name, type (worksheet|macro_sheet|chart|vba_module),
    state (visible|hidden|very_hidden)}], formulas: [text of every macro-sheet formula read], encrypted}."""
    sheets, formulas, pos, n, enc = [], [], 0, len(raw), False
    starts = {}
    current = None
    while pos + 4 <= n:
        rid, size = _u16(raw, pos), _u16(raw, pos + 2)
        body = raw[pos + 4:pos + 4 + size]
        if rid == 0x0809 and pos in starts:
            current = starts[pos]
        elif rid == 0x002F:
            enc = True
        elif rid == 0x0085 and len(body) >= 8:
            cch, fl = body[6], body[7]
            name = body[8:8 + 2 * cch].decode("utf-16-le", "replace") if fl & 1 else body[8:8 + cch].decode("latin-1")
            sh = {"name": name, "type": {0: "worksheet", 1: "macro_sheet", 2: "chart", 6: "vba_module"}.get(body[5] & 0x0F, "other"),
                  "state": {0: "visible", 1: "hidden", 2: "very_hidden"}.get(body[4] & 0x03, "visible")}
            sheets.append(sh)
            starts[_u32(body, 0)] = sh
        elif rid == 0x0006 and len(body) >= 22 and current is not None and current["type"] == "macro_sheet" and not enc:
            cce = _u16(body, 20)
            text = xlm_formula(body[22:22 + cce])
            if text:
                formulas.append(text)
        pos += 4 + size
    return {"sheets": sheets, "formulas": formulas, "encrypted": enc}


def activemime(data: bytes):
    """The compound file inside an ActiveMime (MSO) wrapper, or None."""
    at = data.find(b"ActiveMime")
    if at < 0:
        return None
    for off in (0x32, 0x22A, 0x22E):
        try:
            out = zlib.decompressobj().decompress(data[at + off:], MAX_PAYLOAD_BYTES)
            if out[:8] == OLE_MAGIC:
                return out
        except zlib.error:
            continue
    z = data.find(b"\x78", at)
    while 0 <= z < at + 4096:
        try:
            out = zlib.decompressobj().decompress(data[z:], MAX_PAYLOAD_BYTES)
            if out[:8] == OLE_MAGIC:
                return out
        except zlib.error:
            pass
        z = data.find(b"\x78", z + 1)
    return None


def decrypt_office(data: bytes, passwords=("VelvetSweatshop",)):
    """An encrypted Office file opened with one of the given passwords (the default is Excel's own
    built-in read password), through msoffcrypto: the decrypted bytes, or None. No password is
    ever generated; a password the player stored (tools/password.py) is tried as well."""
    try:
        import msoffcrypto
        sys.path.insert(0, str(COMMON)) if str(COMMON) not in sys.path else None
        try:
            import archive_passwords as pw
            extra = [p.decode("utf-8", "replace") for p in pw.candidates()]
        except Exception:
            extra = []
        for password in list(passwords) + extra:
            try:
                f = msoffcrypto.OfficeFile(io.BytesIO(data))
                f.load_key(password=password)
                out = io.BytesIO()
                f.decrypt(out)
                if out.getvalue():
                    return out.getvalue()
            except Exception:
                continue
    except Exception:
        pass
    return None


# ---- the VBA and XLM facts shared by ole and ooxml ----------------------------------------------------

def _sheet_count(sheets: list):
    """How many sheets: one number when every sheet is a visible worksheet, else each reading by name
    (a hidden macro sheet is a sheet to one question and not to the next)."""
    counts = [("all", len(sheets))]
    if all(s.get("type") for s in sheets):          # an OOXML workbook.xml does not say what kind a sheet is
        counts.append(("worksheets", sum(1 for s in sheets if s["type"] == "worksheet")))
    counts.append(("visible", sum(1 for s in sheets if s.get("state", "visible") == "visible")))
    return Alt(counts, definitions=True)


def _macro_fields(fields: dict, texts: list, project: dict, xlm_formulas=(), vba_present: bool = False):
    """vba_present: the file has a VBA project part or storage, read or not."""
    mods = project.get("modules") or []
    sources = [m["source"] for m in mods if m.get("source")]
    with_code = [m for m in mods if (m.get("code_lines") or 0) > 0]
    has_vba = bool(with_code)
    has_xlm = bool(xlm_formulas)
    fields["has_macros"] = has_vba or has_xlm or bool(fields.get("macro_sheets"))
    if not fields["has_macros"] and (vba_present or mods):
        # a VBA project is there and no source line was read from it (damaged, p-code only, or a
        # project with empty modules): "no macros" is not a fact these bytes prove
        del fields["has_macros"]
    if mods or has_xlm or fields.get("macro_sheets"):
        kinds = (["vba"] if has_vba else []) + (["xlm"] if has_xlm or fields.get("macro_sheets") else [])
        if len(kinds) == 1:
            fields["macro_type"] = Labels({"vba": ["vba", "vba_macro", "visual_basic_for_applications"],
                                           "xlm": ["xlm", "excel4", "excel_4_0", "xlm_macro", "excel4_macro"]}[kinds[0]], kinds[0])
    if mods:
        counts = [("all", len(mods)), ("with_code", len(with_code)),
                  ("procedural", sum(1 for m in mods if m.get("type") == "procedural"))]
        fields["module_count"] = Alt(counts if all(m.get("type") for m in mods) else counts[:2], definitions=True)
        fields["module_names"] = [m["name"] for m in mods]
        if with_code and len(with_code) != len(mods):
            fields["macro_module_names"] = [m["name"] for m in with_code]
        fields["module_stream_names"] = [m["stream"] for m in mods]
        if project.get("project"):
            fields["project_name"] = project["project"]
        if project.get("references"):
            fields["references"] = project["references"]
        fields["vba_codepage"] = project.get("codepage")
        # VBA stomping (T1564.007): source removed while the compiled p-code remains.
        stomped = vba_stomped_modules(project)
        if stomped:
            fields["vba_stomped"] = Labels(["stomped", "vba_stomped", "pcode_stomped", "yes", "true"], "vba")
            fields["vba_stomped_modules"] = stomped
        if project.get("vba_project_size") or project.get("srp_streams") or any((m.get("pcode_nonzero") or 0) > 0 for m in mods):
            fields["pcode_present"] = Labels(["present", "yes", "true", "pcode"], "vba")
    source = "\n".join(sources)
    if source.strip():
        r = mraptor(source)
        procs = list(dict.fromkeys(_PROC.findall(source)))
        if procs:
            fields["procedure_names"] = procs
            kinds = {}
            for kw, name in _PROC_KIND.findall(source):
                kinds.setdefault(name, kw.lower())
            # "how many functions" is not "how many procedures": each reading by name, never one number
            fields["procedure_count"] = Alt([("all", len(procs)), ("subs", sum(1 for p in procs if kinds.get(p) == "sub")),
                                             ("functions", sum(1 for p in procs if kinds.get(p) == "function"))], definitions=True)
        if r["autoexec"]:
            fields["autoexec"] = r["autoexec"]
        dashed = "".join(c if c in r["flags"] else "-" for c in "AWX")     # as mraptor prints them: A-X
        fields["mraptor_flags"] = Alt([("mraptor", dashed), ("compact", r["flags"])]) if r["flags"] else None
        fields["suspicious"] = r["suspicious"]
        d = deobfuscate(source)
        texts += sources + d["decoded"] + d["commands"]
        if d["decoded"]:
            fields["decoded_strings"] = d["decoded"]
        if d["commands"]:
            fields["shell_command"] = d["commands"]
        if d["techniques"]:
            fields["obfuscation"] = d["techniques"]
    if has_xlm:
        d = deobfuscate("\n".join(xlm_formulas), xlm=True)
        fields["xlm_formulas"] = list(xlm_formulas)
        texts += list(xlm_formulas) + d["decoded"]
        if d["decoded"]:
            fields["decoded_strings"] = (fields.get("decoded_strings") or []) + [x for x in d["decoded"] if x not in (fields.get("decoded_strings") or [])]
        cmds = []
        for f in xlm_formulas:
            for m in re.finditer(r"(?i)\b(?:EXEC|CALL|REGISTER|RUN)\(", f):
                p = _Expr(f, m.end(), {})
                try:
                    v = p.expr()
                    if isinstance(v, str) and len(v) >= 4 and v not in cmds and m.group().upper().startswith("EXEC"):
                        cmds.append(v)
                except (_NoParse, RecursionError):
                    pass
        if cmds:
            fields["shell_command"] = (fields.get("shell_command") or []) + [c for c in cmds if c not in (fields.get("shell_command") or [])]
        if any(re.search(r"(?i)auto_?open", f) for f in xlm_formulas):
            fields.setdefault("autoexec", ["Auto_Open"])


def _attack(fields: dict, kind: str):
    """The ATT&CK technique ids that name the mechanism established in the bytes, most specific first."""
    cmd = " ".join(str(x) for x in (fields.get("shell_command") or []) + [str(fields.get("arguments") or ""), str(fields.get("target") or "")]).lower()
    interp = ["T1059.001"] if "powershell" in cmd else ["T1218.005"] if "mshta" in cmd else ["T1059.003"] if re.search(r"\bcmd(?:\.exe)?\b", cmd) else []
    if fields.get("vba_stomped"):
        return Labels(["T1564.007", "T1059.005", "T1204.002", "T1566.001", "T1027"] + interp, "vba_stomp")
    if fields.get("remote_template"):
        return Labels(["T1221", "T1204.002", "T1566.001"], "remote_template")
    if fields.get("dde"):
        return Labels(["T1559.002", "T1204.002", "T1566.001"], "dde")
    if fields.get("cve"):
        return Labels(["T1203", "T1204.002", "T1566.001"], "exploit")
    if fields.get("macro_type") and fields["macro_type"][0] == "vba":
        return Labels(["T1059.005", "T1204.002", "T1566.001", "T1137"] + interp, "vba")
    if fields.get("macro_type") and fields["macro_type"][0] == "xlm":
        return Labels(["T1204.002", "T1059", "T1566.001"] + interp, "xlm")
    if kind == "pdf" and fields.get("has_javascript"):
        return Labels(["T1059.007", "T1204.002", "T1203", "T1566.001"], "javascript")
    if kind == "pdf" and fields.get("launch"):
        return Labels(["T1204.002", "T1059.003", "T1566.001"], "launch")
    if kind == "lnk":
        return Labels(interp + ["T1204.002", "T1547.009", "T1566.001"], "lnk" + ("." + interp[0].lower() if interp else ""))
    if kind == "onenote" and fields.get("embedded_count"):
        return Labels(["T1204.002", "T1566.001", "T1027.009"], "embedded")
    if kind in ("iso", "vhd", "disk_image"):
        return Labels(["T1553.005", "T1204.002", "T1566.001", "T1027"], "container")
    if kind == "hta":
        return Labels(["T1218.005", "T1059.005", "T1059.007", "T1204.002"], "hta")
    return None


# ---- OLE documents ---------------------------------------------------------------------------------------

_KIND_LABELS = {
    "slk": ["slk", "sylk", "symbolic_link_file", "excel"],
    "xml_excel_2003": ["xml_excel_2003", "spreadsheetml", "excel_2003_xml", "excel", "xml"],
    "xml_word_2003": ["xml_word_2003", "wordml", "word_2003_xml", "word", "xml"],
    "csv_dde": ["csv", "csv_dde", "delimited_text"],
    "ole_word": ["ole_word", "doc", "word_97_2003", "ms_word", "word", "ole", "ole2", "cfb", "compound_file"],
    "ole_excel": ["ole_excel", "xls", "excel_97_2003", "ms_excel", "excel", "ole", "ole2", "cfb", "compound_file"],
    "ole_powerpoint": ["ole_powerpoint", "ppt", "powerpoint_97_2003", "powerpoint", "ole", "ole2", "cfb"],
    "ole_msi": ["msi", "ole_msi", "windows_installer", "ole", "cfb"],
    "ole_msg": ["msg", "outlook_msg", "ole_msg", "ole", "cfb"],
    "ole_encrypted": ["encrypted_ooxml", "ole_encrypted", "encrypted_office", "ole", "cfb"],
    "ole_vba_project": ["vba_project", "ole_vba_project", "vbaproject_bin", "ole", "cfb"],
    "ole_package": ["ole_package", "package", "ole10native", "ole", "cfb"],
    "ole_equation": ["equation_native", "ole_equation", "equation", "ole", "cfb"],
    "ole": ["ole", "ole2", "cfb", "compound_file", "compound_file_binary"],
    "ooxml_word": ["ooxml_word", "docx", "docm", "word", "ooxml", "office_open_xml", "zip"],
    "ooxml_excel": ["ooxml_excel", "xlsx", "xlsm", "excel", "ooxml", "office_open_xml", "zip"],
    "ooxml_powerpoint": ["ooxml_powerpoint", "pptx", "pptm", "powerpoint", "ooxml", "office_open_xml", "zip"],
    "ooxml": ["ooxml", "office_open_xml", "zip"],
    "rtf": ["rtf", "rich_text", "rich_text_format"],
    "pdf": ["pdf", "portable_document_format"],
    "onenote": ["onenote", "one", "onenote_section"],
    "lnk": ["lnk", "shortcut", "windows_shortcut", "shell_link", "ms_shllink"],
    "iso": ["iso", "iso9660", "iso_9660", "disk_image", "optical_disc_image"],
    "vhd": ["vhd", "virtual_hard_disk", "disk_image"],
    "vhdx": ["vhdx", "virtual_hard_disk", "disk_image"],
    "disk_image": ["img", "disk_image", "raw_disk_image", "fat"],
    "hta": ["hta", "html_application"],
    "wsf": ["wsf", "windows_script_file"],
    "sct": ["sct", "scriptlet", "windows_script_component"],
    "activemime": ["activemime", "mso", "active_mime"],
}


PPT_INFLATE_MAX = 64 << 20       # bytes all the storages of one PowerPoint stream may inflate to (a 4 MB file could ask for 4 GB)


def ppt_storages(stream: bytes) -> list:
    """The compound files inside a 'PowerPoint Document' stream: every ExternalOleObjectStg record
    (type 0x1011), inflated when its instance says compressed. A PowerPoint 97-2003 file keeps its
    VBA project and its embedded objects there, not in storages of its own. At most 16 different
    storages and PPT_INFLATE_MAX bytes in all: what lies beyond is not read."""
    out, pos, budget, seen = [], 0, PPT_INFLATE_MAX, set()
    while len(out) < 16 and budget > 0:
        i = stream.find(b"\x11\x10", pos)
        if i < 0:
            break
        pos = i + 1
        h = i - 2
        if h < 0 or h + 8 > len(stream):
            continue
        inst, n = _u16(stream, h) >> 4, _u32(stream, h + 4)
        body = stream[h + 8:h + 8 + n]
        if n < 16 or len(body) != n:
            continue
        raw = None
        if inst == 1 and body[4] == 0x78:
            try:
                d = zlib.decompressobj()
                raw = d.decompress(body[4:], budget)
            except zlib.error:
                raw = None
        elif inst == 0 and body[:8] == OLE_MAGIC:
            raw = body
        if raw and raw[:8] == OLE_MAGIC:
            budget -= len(raw)
            mark = hashlib.sha256(raw).digest()
            if mark not in seen:            # the same storage a second time is read once
                seen.add(mark)
                out.append(raw)
            pos = h + 8 + n
    return out


def _slk_doc(data: bytes, doc: dict):
    """A SYLK file: its cell expressions (C;...;E<expr>) and names (NN;N<name>;E<ref>). A name that
    begins Auto_Open or Auto_Close makes the expressions an Excel 4 macro Excel runs on opening."""
    f, texts = doc["fields"], doc["texts"]
    text = _text(data[:8 << 20])
    names, cells = [], []
    for line in text.splitlines():
        if line.startswith("NN;N"):
            names.append(line[4:].split(";", 1)[0])
        elif line.startswith("C;") and ";E" in line:
            cells.append("=" + line.split(";E", 1)[1])
    auto = [n for n in names if re.match(r"(?i)auto_?(?:open|close)", n)]
    f["defined_names"] = names
    xlm = cells if auto or any(re.search(r"(?i)\b(?:EXEC|CALL|REGISTER|RUN|HALT|FORMULA(?:\.FILL)?|ALERT|FOPEN|FWRITE)\(", c) for c in cells) else []
    if xlm:
        f["macro_sheets"] = ["(the SYLK sheet)"]
        f["xlm_formulas"] = xlm[:400]
    _macro_fields(f, texts, {}, xlm)
    if auto:
        f["autoexec"] = auto
    dde = dde_formulas("\n".join(cells))
    if dde:
        f["dde"] = dde[:8]
    texts += cells


def _xml2003_doc(data: bytes, doc: dict):
    """An Office 2003 XML document (SpreadsheetML, WordprocessingML): the cell formulas and their DDE
    forms, the field instructions, and the ActiveMime block (w:binData editdata.mso) that carries a
    VBA project."""
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    text = _text(data[:32 << 20])
    progid = re.search(r'<\?mso-application\s+progid="([^"]+)"', text)
    excel = (progid and progid.group(1).lower().startswith("excel")) or "urn:schemas-microsoft-com:office:spreadsheet" in text[:4096]
    doc["kind"] = "xml_excel_2003" if excel else "xml_word_2003"
    dde = []
    if excel:
        formulas = [_xml_unescape(x) for x in re.findall(r'\bss:Formula="([^"]*)"', text)]
        f["formula_count"] = len(formulas)
        dde = dde_formulas("\n".join(formulas))
        texts += formulas
    else:
        instr = _xml_unescape("".join(re.findall(r"<w:instrText\b[^>]*>(.*?)</w:instrText>", text, re.S)))
        instr += " " + " ".join(_xml_unescape(v) for v in re.findall(r'<w:fldSimple\b[^>]*w:instr="([^"]*)"', text))
        for m in re.finditer(r"\bDDE(?:AUTO)?\b\s+.+?(?=\s+\bDDE(?:AUTO)?\b|$)", instr.strip(), re.S):
            dde.append(" ".join(m.group().split()))
        texts.append(_xml_unescape(re.sub(r"<[^>]+>", " ", text))[:1 << 20])
    if dde:
        f["dde"] = dde[:8]
    for m in re.finditer(r'<w:binData\b[^>]*w:name="([^"]+)"[^>]*>([A-Za-z0-9+/=\s]+)</w:binData>', text):
        try:
            pay.append((m.group(1), base64.b64decode(re.sub(r"\s+", "", m.group(2))), "w:binData of the 2003 XML document"))
        except (binascii.Error, ValueError):
            doc["notes"].append(f"w:binData {m.group(1)}: not base64")
    f["encrypted"] = False


def _csv_dde_doc(data: bytes, doc: dict):
    """Delimited text with a DDE formula in a cell: the formulas, as msodde prints them."""
    f, texts = doc["fields"], doc["texts"]
    text = _text(data[:4 << 20])
    f["dde"] = _dde_cells(text)[:8]
    texts.append(text[:1 << 20])


def _ole_doc(data: bytes, doc: dict):
    c = CFB(data)
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    streams, storages = c.paths("stream"), c.paths("storage")
    low = {p.lower() for p in streams}
    kind = ("ole_word" if "worddocument" in low else "ole_excel" if low & {"workbook", "book"} else
            "ole_powerpoint" if "powerpoint document" in low else "ole_encrypted" if "encryptedpackage" in low else
            "ole_msg" if "__properties_version1.0" in low else
            "ole_msi" if c.root_clsid and c.root_clsid.startswith("000c1084-") else
            "ole_vba_project" if "vba/dir" in low else "ole_package" if "\x01ole10native" in low else
            "ole_equation" if "equation native" in low else "ole")
    doc["kind"] = kind
    f["stream_names"] = streams
    f["storage_names"] = storages
    f["stream_count"] = Alt([("streams", len(streams)), ("streams_and_storages", len(streams) + len(storages)),
                             ("directory_entries", c.directory_entries())], definitions=True)
    if not c.intact():
        doc["partial"] = True
        doc["notes"].append("the compound file is cut or damaged (a broken directory link or a short stream): no count is answered plain")
    if c.root_clsid:
        f["clsid"] = c.root_clsid
    props = ole_properties(c)
    for k, v in props.items():
        f[k] = v
    f["encrypted"] = kind == "ole_encrypted"
    if kind == "ole_word":
        try:
            fib = c.stream("WordDocument")[:12]
            if len(fib) >= 12 and _u16(fib, 0x0A) & 0x0100:
                # FibBase.fEncrypted: the text and the macros are RC4/XOR-protected (seen in a real
                # one, read as "not encrypted" before); what this file reads of them is not the document
                f["encrypted"] = True
                doc["notes"].append("the Word document is encrypted (FibBase.fEncrypted): its text and macros are not read")
        except Exception:
            pass
    xlm, project = [], vba_project(c)
    doc["notes"] += project.get("notes", [])
    if kind == "ole_excel":
        wb = biff_workbook(c.stream("Workbook" if c.has("Workbook") else "Book"))
        f["sheet_names"] = [s["name"] for s in wb["sheets"]]
        f["sheet_count"] = _sheet_count(wb["sheets"])
        hidden = [s["name"] for s in wb["sheets"] if s["state"] != "visible"]
        f["hidden_sheets"] = hidden
        f["very_hidden_sheets"] = [s["name"] for s in wb["sheets"] if s["state"] == "very_hidden"]
        f["macro_sheets"] = [s["name"] for s in wb["sheets"] if s["type"] == "macro_sheet"]
        f["encrypted"] = wb["encrypted"]
        xlm = wb["formulas"]
        if wb["encrypted"]:
            doc["notes"].append("the workbook is encrypted (FILEPASS): decrypt_office(data) tries Excel's built-in password")
    if kind == "ole_powerpoint":
        try:
            inner = ppt_storages(c.stream("PowerPoint Document"))
        except Exception:
            inner = []
        for n, raw in enumerate(inner, 1):
            pay.append((f"ExternalOleObjectStg{n}", raw, "an OLE storage inside the PowerPoint Document stream"))
    if kind == "ole_encrypted":
        doc["notes"].append("an encrypted OOXML package: decrypt_office(data) tries Excel's built-in password and the stored ones")
        plain = decrypt_office(data)
        if plain:
            pay.append(("decrypted_package", plain, "decrypted with a known password"))
    _macro_fields(f, texts, project, xlm, vba_present=any(
        p == "vba" or p.endswith("/vba") or p.endswith("vba/dir") or p.endswith("_vba_project") for p in low | {s.lower() for s in storages}))
    doc["modules"] = [{k: m[k] for k in ("name", "stream", "type", "source", "code_lines")} for m in project.get("modules", [])]
    for p in streams:
        tail = p.rsplit("/", 1)[-1].lower()
        if tail == "\x01ole10native":
            o = ole10native(c.stream(p))
            if o:
                pay.append((o["filename"], o["data"], f"Ole10Native in {p}"))
                f.setdefault("package_source_paths", []).append(o["source_path"])
                f.setdefault("package_temp_paths", []).append(o["temp_path"])
        elif tail in ("package", "\x01ole", "contents") and c.stream(p)[:4] in (b"PK\x03\x04", OLE_MAGIC[:4]):
            pay.append((p, c.stream(p), "an embedded package stream"))
        elif tail == "equation native":
            f["cve"] = Labels(["cve_2017_11882", "CVE-2017-11882", "cve-2017-11882", "equation_editor"], "equation")
    if kind != "ole_vba_project":
        raw = triage.strings(data)
        texts += [s for s in raw if re.search(r"(?i)https?://|hxxps?://", s) and "schemas." not in s][:200]
        dde = [s for s in raw if re.search(r"\bDDEAUTO\b|\bDDE\s+\"?(?:[A-Za-z]:\\|cmd|powershell|mshta)", s)]
        if dde:
            f["dde"] = dde[:3]


# ---- OOXML ---------------------------------------------------------------------------------------------

_CORE = {"author": r"dc:creator", "last_saved_by": r"cp:lastModifiedBy", "created": r"dcterms:created",
         "modified": r"dcterms:modified", "title": r"dc:title", "subject": r"dc:subject", "revision": r"cp:revision",
         "comments": r"dc:description", "keywords": r"cp:keywords", "category": r"cp:category", "last_printed": r"cp:lastPrinted"}
_APP = {"application": "Application", "app_version": "AppVersion", "company": "Company", "template": "Template",
        "manager": "Manager", "pages": "Pages", "words": "Words"}


def _xml_unescape(s):
    return (s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&"))


def _parse_time(s):
    """An ISO 8601 / W3CDTF text as an aware datetime (UTC assumed when no zone is written), or None."""
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:\.(\d{1,6})\d*)?)?\s*(Z|[+-]\d\d:?\d\d)?", s.strip())
    if not m:
        return None
    try:
        tz = UTC
        if m.group(8) and m.group(8) != "Z":
            sign = 1 if m.group(8)[0] == "+" else -1
            hh, mm = int(m.group(8)[1:3]), int(m.group(8)[-2:])
            tz = timezone(sign * timedelta(hours=hh, minutes=mm))
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6) or 0),
                        int((m.group(7) or "0").ljust(6, "0")), tzinfo=tz)
    except ValueError:
        return None


def ooxml(data: bytes) -> dict:
    """An OOXML package read from its zip: {members, content_types, core, app, external: [(type, target,
    part)], vba: [(part, bytes)], embedded: [(part, bytes)], dde: [...], sheets: [{name, state, macro}],
    macro_formulas: [...], defined_names: {...}}."""
    out = {"members": [], "main": None, "macro_enabled": False, "core": {}, "app": {}, "external": [], "vba": [],
           "embedded": [], "dde": [], "sheets": [], "macro_formulas": [], "defined_names": {}, "notes": [], "text": []}
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError, OSError, EOFError):
        return {}
    with archive as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        out["members"] = [i.filename for i in infos]
        total = 0

        def read(info):
            nonlocal total
            if info.file_size > MAX_PAYLOAD_BYTES or total > 4 * MAX_PAYLOAD_BYTES:
                return b""
            try:
                raw = zf.read(info)
            except Exception:
                out["notes"].append(f"{info.filename} could not be read")
                return b""
            total += len(raw)
            return raw

        for info in infos:
            n = info.filename
            low = n.lower()
            if low == "[content_types].xml":
                ct = read(info).decode("utf-8", "replace")
                for w in re.findall(r'ContentType="([^"]+)"', ct):
                    if "main+xml" not in w and ".main" not in w:
                        continue
                    out["main"] = ("word" if ("wordprocessingml" in w or "ms-word" in w) else
                                   "excel" if ("spreadsheetml" in w or "ms-excel" in w) else
                                   "powerpoint" if ("presentationml" in w or "ms-powerpoint" in w) else out["main"])
                    out["macro_enabled"] = out["macro_enabled"] or "macroenabled" in w.lower()
            elif low == "docprops/core.xml":
                x = read(info).decode("utf-8", "replace")
                for k, tag in _CORE.items():
                    m = re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", x, re.S)
                    if m and m.group(1).strip():
                        out["core"][k] = _xml_unescape(m.group(1).strip())
            elif low == "docprops/app.xml":
                x = read(info).decode("utf-8", "replace")
                for k, tag in _APP.items():
                    m = re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", x, re.S)
                    if m and m.group(1).strip():
                        out["app"][k] = _xml_unescape(m.group(1).strip())
            elif low.endswith(".rels"):
                x = read(info).decode("utf-8", "replace")
                for m in re.finditer(r"<Relationship\b([^>]*)>", x):
                    attrs = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', m.group(1)))
                    if attrs.get("TargetMode", "").lower() == "external" and attrs.get("Target"):
                        out["external"].append((attrs.get("Type", "").rsplit("/", 1)[-1], _xml_unescape(attrs["Target"]), n))
            elif re.fullmatch(r"xl/externallinks/[^/]+\.xml", low):
                for m in re.finditer(r"<ddeLink\b([^>]*)>", read(info).decode("utf-8", "replace")):
                    attrs = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', m.group(1)))
                    if attrs.get("ddeService"):
                        out["dde"].append(f"{_xml_unescape(attrs['ddeService'])} {_xml_unescape(attrs.get('ddeTopic', ''))}".strip())
            elif low.endswith("vbaproject.bin"):
                out["vba"].append((n, read(info)))
            elif re.search(r"(?:^|/)(?:embeddings|activex)/[^/]+$", low) and not low.endswith(".xml") or low.endswith(".bin") and "/embeddings/" in low:
                out["embedded"].append((n, read(info)))
            elif re.fullmatch(r"word/(?:document|header\d*|footer\d*|footnotes|endnotes)\.xml", low):
                x = read(info).decode("utf-8", "replace")
                instr = _xml_unescape("".join(re.findall(r"<w:instrText\b[^>]*>(.*?)</w:instrText>", x, re.S)))
                instr += " " + " ".join(_xml_unescape(v) for v in re.findall(r'<w:fldSimple\b[^>]*w:instr="([^"]*)"', x))
                for m in re.finditer(r"\bDDE(?:AUTO)?\b\s+.+?(?=\s+\bDDE(?:AUTO)?\b|$)", instr.strip(), re.S):
                    out["dde"].append(" ".join(m.group().split()))
                out["text"].append(_xml_unescape(re.sub(r"<[^>]+>", " ", x))[:1 << 20])
            elif low == "xl/sharedstrings.xml" or re.fullmatch(r"ppt/slides/[^/]+\.xml", low):
                out["text"].append(_xml_unescape(re.sub(r"<[^>]+>", " ", read(info).decode("utf-8", "replace")))[:1 << 20])
            elif low == "xl/workbook.xml":
                x = read(info).decode("utf-8", "replace")
                for m in re.finditer(r"<sheet\b([^>]*)/?>", x):
                    attrs = dict(re.findall(r'([\w:]+)\s*=\s*"([^"]*)"', m.group(1)))
                    out["sheets"].append({"name": _xml_unescape(attrs.get("name", "")), "rid": attrs.get("r:id"),
                                          "state": {"hidden": "hidden", "veryHidden": "very_hidden"}.get(attrs.get("state"), "visible")})
                for m in re.finditer(r'<definedName\b[^>]*\bname="([^"]*)"[^>]*>(.*?)</definedName>', x, re.S):
                    out["defined_names"][_xml_unescape(m.group(1))] = _xml_unescape(m.group(2))
            elif re.fullmatch(r"xl/macrosheets/[^/]+\.xml", low):
                x = read(info).decode("utf-8", "replace")
                for m in re.finditer(r"<f\b[^>]*>(.*?)</f>", x, re.S):
                    out["macro_formulas"].append("=" + _xml_unescape(m.group(1)).lstrip("="))
                out.setdefault("macro_sheet_parts", []).append(n)
            elif low in ("xl/workbook.bin",) or low.startswith("xl/macrosheets/") and low.endswith(".bin"):
                out["notes"].append(f"{n}: a binary (xlsb) part, not read here")
        if out["main"] is None:
            lowset = {m.lower() for m in out["members"]}
            out["main"] = ("word" if "word/document.xml" in lowset else "excel" if lowset & {"xl/workbook.xml", "xl/workbook.bin"}
                           else "powerpoint" if "ppt/presentation.xml" in lowset else None)
    return out


def _ooxml_doc(data: bytes, doc: dict):
    o = ooxml(data)
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    doc["kind"] = "ooxml_" + o["main"] if o["main"] else "ooxml"
    doc["notes"] += o["notes"]
    texts += [t for t in o["text"] if re.search(r"(?i)https?://|hxxps?://", t)]
    f["member_count"] = len(o["members"])
    f["macro_enabled"] = o["macro_enabled"] or bool(o["vba"])
    for k, v in {**o["app"], **o["core"]}.items():
        if k in ("created", "modified", "last_printed"):
            t = _parse_time(v)
            if t:
                f[k] = t
                f[k + "__raw"] = v
        elif k in ("pages", "words") and v.isdigit():
            f[k] = int(v)
        else:
            f[k] = v
    f["encrypted"] = False
    project = {}
    for part, raw in o["vba"]:
        try:
            p = vba_project(CFB(raw))
        except (ValueError, struct.error, IndexError, KeyError):
            doc["notes"].append(f"{part} is not a readable compound file")
            continue
        if not project:
            project = p
            f["vba_part"] = part
        else:
            project["modules"] = project.get("modules", []) + p.get("modules", [])
    doc["notes"] += project.get("notes", [])
    if o["sheets"]:
        f["sheet_names"] = [s["name"] for s in o["sheets"]]
        f["sheet_count"] = _sheet_count(o["sheets"])
        f["hidden_sheets"] = [s["name"] for s in o["sheets"] if s["state"] != "visible"]
        f["very_hidden_sheets"] = [s["name"] for s in o["sheets"] if s["state"] == "very_hidden"]
    if o.get("macro_sheet_parts"):
        f["macro_sheets"] = o["macro_sheet_parts"]
        if isinstance(f.get("sheet_count"), Alt):
            f["sheet_count"].append(("without_macro_sheets", len(o["sheets"]) - len(o["macro_sheet_parts"])))
    auto = [k for k in o["defined_names"] if re.search(r"(?i)auto_?open|auto_?close", k)]
    _macro_fields(f, texts, project, o["macro_formulas"], vba_present=bool(o["vba"]) or bool(o["macro_enabled"]))
    if auto and "autoexec" not in f:
        f["autoexec"] = [re.sub(r"^_xlnm\.", "", k) for k in auto]
    doc["modules"] = [{k: m[k] for k in ("name", "stream", "type", "source", "code_lines")} for m in project.get("modules", [])]
    if o["external"]:
        f["external_targets"] = [t for _, t, _ in o["external"] if not t.lower().startswith("mailto:")] or None
        f["external_types"] = list(dict.fromkeys(t for t, _, _ in o["external"]))
        tmpl = [t for typ, t, _ in o["external"] if typ == "attachedTemplate"]
        if tmpl:
            f["remote_template"] = tmpl
        texts += [t for _, t, _ in o["external"]]
    if o["dde"]:
        f["dde"] = o["dde"]
        texts += o["dde"]
    for part, raw in o["embedded"]:
        pay.append((part, raw, "an embedded part"))


# ---- RTF -------------------------------------------------------------------------------------------------

def _rtf_hex(data: bytes, pos: int):
    """The bytes of an \\objdata destination that starts at pos, and where it ends: hex digits at
    any depth, control words skipped, \\binN taken raw; it ends when the destination's group closes."""
    out, depth, i, n = bytearray(), 0, pos, len(data)
    nib = None
    while i < n:
        c = data[i]
        if c == 0x7B:
            depth += 1
            i += 1
        elif c == 0x7D:
            depth -= 1
            i += 1
            if depth < 0:
                break
        elif c == 0x5C:
            m = re.compile(rb"\\([a-zA-Z]+)(-?\d+)? ?").match(data, i)
            if m:
                i = m.end()
                if m.group(1) == b"bin" and m.group(2):
                    k = max(0, int(m.group(2)))
                    out += data[i:i + k]
                    i += k
            elif data[i + 1:i + 2] == b"'":
                i += 4
            else:
                i += 2
        else:
            v = (c - 48 if 48 <= c <= 57 else c - 87 if 97 <= c <= 102 else c - 55 if 65 <= c <= 70 else None)
            if v is not None:
                if nib is None:
                    nib = v
                else:
                    out.append(nib << 4 | v)
                    nib = None
            i += 1
        if len(out) > MAX_PAYLOAD_BYTES:
            break
    return bytes(out), i


def _ole1(raw: bytes):
    """An OLE 1.0 object (the content of \\objdata): {class_name, topic, item, format (embedded|linked),
    data}, or None."""
    try:
        pos = 4
        fmt = _u32(raw, pos)
        pos += 4
        vals = []
        for _ in range(3):
            n = _u32(raw, pos)
            pos += 4
            if n > 4096:
                return None
            vals.append(raw[pos:pos + n].split(b"\x00")[0].decode("latin-1"))
            pos += n
        data = b""
        if fmt == 2:
            n = _u32(raw, pos)
            pos += 4
            data = raw[pos:pos + n]
        return {"class_name": vals[0], "topic": vals[1], "item": vals[2],
                "format": {1: "linked", 2: "embedded"}.get(fmt, str(fmt)), "data": data}
    except (struct.error, IndexError):
        return None


def rtf_objects(data: bytes) -> list:
    """[{index, class_name, format, data, declared_class (\\objclass), filename, source_path, temp_path,
    payload (the embedded file: the package's file, or the OLE2 file), updates (\\objupdate)}] of an RTF."""
    out = []
    for m in re.finditer(rb"\\objdata", data):
        raw, end = _rtf_hex(data, m.end())
        o = _ole1(raw) or {"class_name": None, "format": None, "data": raw, "topic": None, "item": None}
        start = data.rfind(b"\\object", 0, m.start())
        group = data[start if start >= 0 else max(0, m.start() - 2048):m.start()]
        cls = re.search(rb"\\objclass\s+([^}\\]+)", group)
        o.update(index=len(out), declared_class=cls.group(1).decode("latin-1").strip() if cls else None,
                 updates=b"\\objupdate" in group, filename=None, source_path=None, temp_path=None, payload=None, raw_size=len(raw))
        if o["class_name"] and o["class_name"].lower() == "package":
            p = ole10native(o["data"], package=True)
            if p:
                o.update(filename=p["filename"], source_path=p["source_path"], temp_path=p["temp_path"], payload=p["data"])
        elif o["data"][:8] == OLE_MAGIC:
            o["payload"] = o["data"]
        elif o["data"]:
            o["payload"] = o["data"]
        out.append(o)
    return out


def _rtf_doc(data: bytes, doc: dict):
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    objs = rtf_objects(data)
    f["object_count"] = len(objs)
    if not data.rstrip(b"\r\n\t \x00\x1a").endswith(b"}"):
        doc["partial"] = True
        doc["notes"].append("the RTF does not end with its closing brace (cut, or malformed on purpose): no count is answered plain")
    classes = [o["class_name"] for o in objs if o["class_name"]]
    if classes:
        f["object_classes"] = classes
    declared = [o["declared_class"] for o in objs if o["declared_class"]]
    if declared and declared != classes:
        f["declared_classes"] = declared
    f["objupdate"] = any(o["updates"] for o in objs)
    for o in objs:
        if o["payload"]:
            pay.append((o["filename"] or f"object{o['index'] + 1}" + (".ole" if o["payload"][:8] == OLE_MAGIC else ".bin"),
                        o["payload"], f"\\objdata {o['index'] + 1} ({o['class_name']})"))
        if o["source_path"]:
            f.setdefault("package_source_paths", []).append(o["source_path"])
        if o["temp_path"]:
            f.setdefault("package_temp_paths", []).append(o["temp_path"])
    if any(re.match(r"(?i)equation\.[23]", c or "") for c in classes + declared):
        f["cve"] = Labels(["cve_2017_11882", "CVE-2017-11882", "cve-2017-11882", "equation_editor"], "equation")
    body = re.sub(rb"\\objdata[0-9a-fA-F\s]+", b" ", data[:4 << 20])
    body = re.sub(rb"\\(?:[a-zA-Z]+-?\d* ?|\r?\n|\r)|[{}]", b" ", body.replace(b"\\\\", b"\x01")).replace(b"\x01", b"\\")
    texts += [s for s in triage.strings(body) if re.search(r"(?i)https?://|hxxps?://|\\\\[\w.-]+\\", s)][:200]
    tmpl = re.search(rb"\{\\\*\\template\s+([^}]+)\}", data)
    if tmpl:
        t = tmpl.group(1).decode("latin-1").strip()
        if re.match(r"(?i)https?://|\\\\", t):
            f["remote_template"] = [t]
        else:
            f["template"] = t
        texts.append(t)
    info = re.search(rb"\{\\info\b(.*?)\}\s*\}", data[:1 << 20], re.S)
    if info:
        for k, tag in (("author", b"author"), ("last_saved_by", b"operator"), ("title", b"title"), ("company", b"company"), ("subject", b"subject")):
            m = re.search(rb"\{\\" + tag + rb"\s+([^{}]*)\}", info.group(0))
            if m and m.group(1).strip():
                f[k] = m.group(1).decode("latin-1").strip()


# ---- PDF -------------------------------------------------------------------------------------------------

class PdfName(str):
    pass


class PdfRef(tuple):
    pass


_PDF_WS = b" \t\r\n\x0c\x00"
_PDF_DELIM = b"()<>[]{}/%"


def _pdf_skip(b, i):
    n = len(b)
    while i < n:
        if b[i] in _PDF_WS:
            i += 1
        elif b[i] == 0x25:
            while i < n and b[i] not in b"\r\n":
                i += 1
        else:
            break
    return i


def _pdf_value(b, i, depth=0):
    """One PDF object read at i: (value, next position). dict, list, PdfName, PdfRef, bytes (a
    string), int, float, bool, None. ValueError where no object stands."""
    if depth > 60:
        raise ValueError("too deep")
    i = _pdf_skip(b, i)
    c = b[i:i + 1]
    if not c:
        raise ValueError("end")
    if b[i:i + 2] == b"<<":
        i += 2
        d = {}
        while True:
            i = _pdf_skip(b, i)
            if b[i:i + 2] == b">>":
                return d, i + 2
            if b[i:i + 1] != b"/":
                raise ValueError("no key")
            k, i = _pdf_value(b, i, depth + 1)
            j = _pdf_skip(b, i)
            if b[j:j + 2] == b">>":
                d[str(k)] = None
                return d, j + 2
            v, i = _pdf_value(b, i, depth + 1)
            d[str(k)] = v
    if c == b"<":
        j = b.find(b">", i)
        if j < 0:
            raise ValueError("open hex string")
        h = re.sub(rb"[^0-9A-Fa-f]", b"", b[i + 1:j])
        return bytes.fromhex((h + b"0" * (len(h) % 2)).decode()), j + 1
    if c == b"(":
        out, j, level, n = bytearray(), i + 1, 1, len(b)
        while j < n:
            ch = b[j]
            if ch == 0x5C:
                e = b[j + 1:j + 2]
                if not e:
                    raise ValueError("open string")
                if e in b"nrtbf":
                    out.append({b"n": 10, b"r": 13, b"t": 9, b"b": 8, b"f": 12}[e])
                    j += 2
                elif e in b"01234567":
                    m = re.compile(rb"[0-7]{1,3}").match(b, j + 1)
                    out.append(int(m.group(), 8) & 0xFF)
                    j = m.end()
                elif e in b"\r\n":
                    j += 3 if b[j + 1:j + 3] == b"\r\n" else 2
                else:
                    out += e
                    j += 2
                continue
            if ch == 0x28:
                level += 1
            elif ch == 0x29:
                level -= 1
                if level == 0:
                    return bytes(out), j + 1
            out.append(ch)
            j += 1
        raise ValueError("open string")
    if c == b"[":
        i += 1
        arr = []
        while True:
            i = _pdf_skip(b, i)
            if b[i:i + 1] == b"]":
                return arr, i + 1
            v, i = _pdf_value(b, i, depth + 1)
            arr.append(v)
    if c == b"/":
        j = i + 1
        while j < len(b) and b[j] not in _PDF_WS and b[j] not in _PDF_DELIM:
            j += 1
        raw = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), b[i + 1:j])
        return PdfName(raw.decode("latin-1")), j
    m = re.compile(rb"(\d+)[ \t\r\n\x0c\x00]+(\d+)[ \t\r\n\x0c\x00]+R(?![A-Za-z0-9])").match(b, i)
    if m:
        return PdfRef((int(m.group(1)), int(m.group(2)))), m.end()
    m = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)").match(b, i)
    if m:
        t = m.group()
        return (float(t) if b"." in t else int(t)), m.end()
    for word, val in ((b"true", True), (b"false", False), (b"null", None)):
        if b[i:i + len(word)] == word:
            return val, i + len(word)
    raise ValueError("no object")


def _pdf_filters(d):
    f = d.get("Filter")
    f = f if isinstance(f, list) else [f] if f is not None else []
    return [str(x) for x in f]


def _pdf_decode(d: dict, raw: bytes):
    """A stream's data through its filters: (bytes, True) or (what was reached, False)."""
    for name in _pdf_filters(d):
        try:
            if name in ("FlateDecode", "Fl"):
                z = zlib.decompressobj()
                raw = z.decompress(raw, MAX_PAYLOAD_BYTES)
                if not z.eof:
                    return raw, False
            elif name in ("ASCIIHexDecode", "AHx"):
                h = re.sub(rb"[^0-9A-Fa-f]", b"", raw.split(b">")[0])
                raw = bytes.fromhex((h + b"0" * (len(h) % 2)).decode())
            elif name in ("ASCII85Decode", "A85"):
                body = raw.strip()
                body = body[2:] if body.startswith(b"<~") else body
                body = body.split(b"~>")[0]
                raw = base64.a85decode(body)
            elif name in ("RunLengthDecode", "RL"):
                out, i = bytearray(), 0
                complete = False
                while i < len(raw):
                    n = raw[i]
                    if n == 128:
                        complete = True
                        break
                    if n < 128:
                        if i + n + 2 > len(raw):
                            return bytes(out) + raw[i + 1:], False
                        out += raw[i + 1:i + 2 + n]
                        i += n + 2
                    else:
                        if i + 1 >= len(raw):
                            return bytes(out), False
                        out += raw[i + 1:i + 2] * (257 - n)
                        i += 2
                    if len(out) > MAX_PAYLOAD_BYTES:
                        return bytes(out[:MAX_PAYLOAD_BYTES]), False
                raw = bytes(out)
                if not complete:
                    return raw, False
            else:
                return raw, False
        except (zlib.error, ValueError, binascii.Error):
            return raw, False
    return raw, True


# PDF Reference 1.7, Table D.2: PDFDocEncoding differs from Latin-1 in
# these ranges. Undefined character codes are represented as replacements.
_PDF_DOC_ENCODING = {
    **dict(zip(range(0x18, 0x20), "\u02d8\u02c7\u02c6\u02d9\u02dd\u02db\u02da\u02dc")),
    **dict(zip(range(0x80, 0x9f), "\u2022\u2020\u2021\u2026\u2014\u2013\u0192\u2044\u2039\u203a\u2212\u2030\u201e\u201c\u201d\u2018\u2019\u201a\u2122\ufb01\ufb02\u0141\u0152\u0160\u0178\u017d\u0131\u0142\u0153\u0161\u017e")),
    0x7f: "\ufffd", 0x9f: "\ufffd", 0xa0: "\u20ac", 0xad: "\ufffd",
}


def _pdf_str(v):
    if isinstance(v, bytes):
        if v[:2] == b"\xfe\xff":
            return v[2:].decode("utf-16-be", "replace")
        if v[:2] == b"\xff\xfe":
            return v[2:].decode("utf-16-le", "replace")
        try:
            return v.decode("utf-8") if v[:3] == b"\xef\xbb\xbf" else v.decode("latin-1").translate(_PDF_DOC_ENCODING)
        except UnicodeDecodeError:
            return v.decode("latin-1")
    return None


def _pdf_date(s):
    m = re.match(r"D?:?(\d{4})(\d\d)?(\d\d)?(\d\d)?(\d\d)?(\d\d)?\s*([Zz+-])?(\d\d)?'?(\d\d)?", s or "")
    if not m:
        return None
    try:
        tz = UTC
        if m.group(7) in ("+", "-") and m.group(8):
            tz = timezone((1 if m.group(7) == "+" else -1) * timedelta(hours=int(m.group(8)), minutes=int(m.group(9) or 0)))
        return datetime(int(m.group(1)), int(m.group(2) or 1), int(m.group(3) or 1), int(m.group(4) or 0), int(m.group(5) or 0),
                        int(m.group(6) or 0), tzinfo=tz)
    except ValueError:
        return None


_PDF_KEYS = ("JS", "JavaScript", "OpenAction", "AA", "Launch", "EmbeddedFile", "URI", "AcroForm", "ObjStm", "Encrypt",
             "RichMedia", "XFA", "JBIG2Decode", "GoToR", "GoToE", "SubmitForm", "Colors")


def pdf(data: bytes) -> dict:
    """A PDF read object by object (no pypdf): {version, objects: {(num, gen): (value, stream bytes or
    None)}, object_count, stream_count, trailer, encrypted, info: {...}, pages_typed, pages_count,
    javascript: [text], open_action, additional_actions, launch: [text], uris: [...], embedded:
    [(name, bytes)], filters: [...], keywords: {name: count}, notes}. Streams are decoded on use
    (pdf_stream)."""
    out = {"version": None, "objects": {}, "trailer": {}, "notes": [], "info": {}, "javascript": [], "launch": [], "uris": [],
           "embedded": [], "filters": [], "open_action": None, "additional_actions": False}
    m = re.search(rb"%PDF-(\d\.\d)", data[:1024])
    out["version"] = m.group(1).decode() if m else None
    objs = out["objects"]
    count = 0
    for m in re.finditer(rb"(?<![\d.])(\d{1,10})[ \t\r\n\x0c\x00]+(\d{1,5})[ \t\r\n\x0c\x00]+obj(?![A-Za-z])", data):
        if count >= 20000:
            out["notes"].append("more than 20000 objects: the rest was not read")
            out["incomplete"] = True
            break
        try:
            val, end = _pdf_value(data, m.end())
        except (ValueError, IndexError, RecursionError):
            out["incomplete"] = True        # an object that does not parse: every count below is short
            continue
        count += 1
        stream = None
        j = _pdf_skip(data, end)
        if isinstance(val, dict) and data[j:j + 6] == b"stream":
            s = j + 6
            s += 2 if data[s:s + 2] == b"\r\n" else 1 if data[s:s + 1] in (b"\n", b"\r") else 0
            ln = val.get("Length")
            if isinstance(ln, int) and 0 <= ln <= len(data) - s and data[s + ln:s + ln + 20].lstrip(b"\r\n \t").startswith(b"endstream"):
                stream = data[s:s + ln]
            else:
                e = data.find(b"endstream", s)
                stream = data[s:e if e >= 0 else len(data)]
                stream = stream[:-2] if stream.endswith(b"\r\n") else stream[:-1] if stream.endswith((b"\n", b"\r")) else stream
        objs[(int(m.group(1)), int(m.group(2)))] = (val, stream)
    # object streams
    for key, (val, stream) in list(objs.items()):
        if isinstance(val, dict) and val.get("Type") == "ObjStm" and stream is not None:
            body, ok = _pdf_decode(val, stream)
            if not ok:
                out["notes"].append(f"object stream {key[0]} uses a filter this reader does not decode")
                out["incomplete"] = True
                continue
            try:
                first, n = int(val.get("First", 0)), int(val.get("N", 0))
                nums = [int(x) for x in body[:first].split()]
                for k in range(min(n, len(nums) // 2)):
                    try:
                        v, _ = _pdf_value(body, first + nums[2 * k + 1])
                    except (ValueError, IndexError, RecursionError):
                        continue
                    objs.setdefault((nums[2 * k], 0), (v, None))
            except (ValueError, TypeError):
                continue
    out["object_count"] = len(objs)
    out["stream_count"] = sum(1 for _, s in objs.values() if s is not None)
    # what a keyword counter (pdfid) reports: every "N G obj", superseded revisions included, and
    # no object that lives inside an object stream
    out["obj_keywords"] = len(re.findall(rb"(?<![\d.])\d{1,10}[ \t\r\n\x0c\x00]+\d{1,5}[ \t\r\n\x0c\x00]+obj(?![A-Za-z])", data))
    out["endstream_keywords"] = data.count(b"endstream")
    # trailer: the last one that parses, then any cross-reference stream's dictionary
    for t in [m.end() for m in re.finditer(rb"\btrailer\b", data)][::-1]:
        try:
            tr, _ = _pdf_value(data, t)
            if isinstance(tr, dict):
                for k, v in tr.items():
                    out["trailer"].setdefault(k, v)
        except (ValueError, IndexError):
            continue
    for val, _ in objs.values():
        if isinstance(val, dict) and val.get("Type") == "XRef":
            for k in ("Root", "Info", "Encrypt", "ID"):
                if k in val:
                    out["trailer"].setdefault(k, val[k])
    out["encrypted"] = "Encrypt" in out["trailer"]

    def res(v, hops=0):
        while isinstance(v, PdfRef) and hops < 20:
            v = (objs.get(tuple(v)) or objs.get((v[0], 0)) or (None, None))[0]
            hops += 1
        return v

    def stream_of(v):
        if isinstance(v, PdfRef):
            val, s = objs.get(tuple(v)) or objs.get((v[0], 0)) or (None, None)
            if isinstance(val, dict) and s is not None:
                return _pdf_decode(val, s)[0]
            v = res(v)
        return v if isinstance(v, bytes) else None

    out["resolve"], out["stream_of"] = res, stream_of
    info = res(out["trailer"].get("Info"))
    if isinstance(info, dict):
        for k, name in (("Author", "author"), ("Creator", "creator"), ("Producer", "producer"), ("Title", "title"),
                        ("Subject", "subject"), ("Keywords", "keywords"), ("CreationDate", "created"), ("ModDate", "modified")):
            s = _pdf_str(res(info.get(k)))
            if s:
                out["info"][name] = s
    seen_js, seen_embed = set(), set()

    def walk(v, depth=0):
        if depth > 40:
            return
        if isinstance(v, list):
            for x in v:
                walk(x, depth + 1)
            return
        if not isinstance(v, dict):
            return
        if "JS" in v:
            raw = stream_of(v["JS"])
            if raw is not None:
                txt = _pdf_str(raw)
                if txt is not None and txt not in seen_js:
                    seen_js.add(txt)
                    out["javascript"].append(txt)
        if v.get("S") == "Launch":
            target = res(v.get("F"))
            win = res(v.get("Win"))
            parts = []
            if isinstance(win, dict):
                parts = [_pdf_str(res(win.get("F"))), _pdf_str(res(win.get("P")))]
            elif isinstance(target, dict):
                parts = [_pdf_str(res(target.get("F")))]
            else:
                parts = [_pdf_str(target)]
            text = " ".join(p for p in parts if p)
            if text and text not in out["launch"]:
                out["launch"].append(text)
        if "URI" in v:
            u = _pdf_str(res(v["URI"]))
            if u and u not in out["uris"]:
                out["uris"].append(u)
        if "AA" in v:
            out["additional_actions"] = True
        if "EF" in v:
            ef = res(v["EF"])
            name = _pdf_str(res(v.get("UF"))) or _pdf_str(res(v.get("F"))) or "embedded"
            if isinstance(ef, dict):
                ref = ef.get("F") or ef.get("UF") or next(iter(ef.values()), None)
                body = stream_of(ref)
                if body is not None and isinstance(ref, PdfRef) and tuple(ref) not in seen_embed:
                    seen_embed.add(tuple(ref))
                    out["embedded"].append((name, body))
        for x in v.values():
            if isinstance(x, (dict, list)):
                walk(x, depth + 1)

    for key, (val, stream) in objs.items():
        walk(val)
        if isinstance(val, dict) and stream is not None:
            for name in _pdf_filters(val):
                if name not in out["filters"]:
                    out["filters"].append(name)
    for key, (val, stream) in objs.items():
        if isinstance(val, dict) and val.get("Type") == "EmbeddedFile" and stream is not None and key not in seen_embed:
            seen_embed.add(key)
            out["embedded"].append((f"embedded{len(out['embedded']) + 1}", _pdf_decode(val, stream)[0]))
    root = res(out["trailer"].get("Root"))
    if not isinstance(root, dict):
        root = next((v for v, _ in objs.values() if isinstance(v, dict) and v.get("Type") == "Catalog"), None)
    if isinstance(root, dict):
        oa = res(root.get("OpenAction"))
        if isinstance(oa, dict):
            out["open_action"] = str(oa.get("S")) if oa.get("S") is not None else "action"
        elif isinstance(oa, list):
            out["open_action"] = "GoTo"
        pages = res(root.get("Pages"))
        if isinstance(pages, dict) and isinstance(res(pages.get("Count")), int):
            out["pages_count"] = res(pages.get("Count"))
    out["pages_typed"] = sum(1 for v, _ in objs.values() if isinstance(v, dict) and v.get("Type") == "Page")
    norm = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)
    extra = b"".join(_pdf_decode(v, s)[0] for v, s in objs.values() if isinstance(v, dict) and v.get("Type") == "ObjStm" and s is not None)
    out["keywords"] = {k: len(re.findall(rb"/" + k.encode() + rb"(?![A-Za-z0-9])", norm + b"\n" + extra)) for k in _PDF_KEYS}
    return out


def pdf_stream(p: dict, num: int, gen: int = 0):
    """The decoded stream of object num of a pdf() result: (bytes, fully decoded?) or None."""
    objects = p.get("objects") if isinstance(p, dict) else None
    if not isinstance(objects, dict) or not isinstance(num, int) or not isinstance(gen, int):
        return None
    pair = objects.get((num, gen))
    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
        return None
    val, s = pair
    return _pdf_decode(val, s) if isinstance(val, dict) and isinstance(s, bytes) else None


def pdf_pypdf(data: bytes, password: str = "") -> dict:
    """The same PDF through pypdf, for a second opinion by hand: {pages, encrypted, metadata, attachments:
    {name: bytes}, decrypted: bytes of an unencrypted copy when it was encrypted and the password opened it}."""
    try:
        import logging
        import pypdf
        logging.getLogger("pypdf").setLevel(logging.ERROR)
        r = pypdf.PdfReader(io.BytesIO(data), strict=False)
        out = {"encrypted": bool(r.is_encrypted), "decrypted": None}
        if r.is_encrypted:
            if not r.decrypt(password):
                return {**out, "pages": None, "metadata": {}, "attachments": {}}
            w = pypdf.PdfWriter(clone_from=r)
            buf = io.BytesIO()
            w.write(buf)
            out["decrypted"] = buf.getvalue()
        out["pages"] = len(r.pages)
        out["metadata"] = {str(k).lstrip("/"): str(v) for k, v in (r.metadata or {}).items()}
        try:
            out["attachments"] = {k: (v[0] if isinstance(v, list) else v) for k, v in dict(r.attachments).items()}
        except Exception:
            out["attachments"] = {}
        return out
    except Exception:
        return {}


def pdf_text(data: bytes) -> str:
    """The page text, through pdfminer (by hand; slow on a big file, never on a clock)."""
    try:
        from pdfminer.high_level import extract_text
        return extract_text(io.BytesIO(data))
    except Exception:
        return ""


def _pdf_doc(data: bytes, doc: dict):
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    p = pdf(data)
    if p["encrypted"]:
        doc["notes"].append("the PDF is encrypted: strings and streams are read from a copy pypdf decrypted with the empty password")
        try:
            dec = pdf_pypdf(data).get("decrypted")
        except Exception:
            dec = None
        if dec:
            p = pdf(dec)
            p["encrypted"] = True
        else:
            f.update(encrypted=True, version=p["version"])
            doc["notes"].append("it did not open with the empty password: nothing more was read")
            doc["unreadable"] = True
            return
    doc["notes"] += p["notes"]
    doc["pdf"] = p
    f["version"] = Alt([("number", p["version"]), ("pdf_dash", f"PDF-{p['version']}"), ("percent", f"%PDF-{p['version']}")]) if p["version"] else None
    size = p["trailer"].get("Size")
    incomplete = bool(p.get("incomplete")) or p["object_count"] == 0
    if b"%%EOF" not in data[-2048:] or not p["trailer"]:
        doc["partial"] = True
        doc["notes"].append("no trailer or no %%EOF at the end (a cut file): no count is answered plain")
    if incomplete:
        doc["notes"].append("not every object was read: no count and no 'has none' is answered from this file")
    else:
        f["object_count"] = Alt([("objects", p["object_count"]), ("obj_keywords", p["obj_keywords"])]
                                + ([("xref_size", size)] if isinstance(size, int) and not isinstance(size, bool) else []), definitions=True)
        f["stream_count"] = Alt([("objects_with_stream", p["stream_count"]), ("endstream_keywords", p["endstream_keywords"])], definitions=True)
    f["encrypted"] = p["encrypted"]
    typed, counted = p.get("pages_typed"), p.get("pages_count")
    if (typed or counted is not None) and not (incomplete and (not typed or counted is None)):
        f["page_count"] = Alt([(n, v) for n, v in (("pages_count", counted), ("typed_pages", typed)) if v is not None], definitions=True)
    for k in ("author", "creator", "producer", "title", "subject", "keywords"):
        if p["info"].get(k):
            f[k] = p["info"][k]
    for k in ("created", "modified"):
        t = _pdf_date(p["info"].get(k))
        if t:
            f[k] = t
            f[k + "__raw"] = p["info"][k]
    f["has_javascript"] = bool(p["javascript"]) or p["keywords"]["JS"] > 0 or p["keywords"]["JavaScript"] > 0
    if incomplete and not f["has_javascript"]:
        del f["has_javascript"]
    if p["javascript"]:
        f["javascript"] = p["javascript"]
        texts += p["javascript"]
        for js in p["javascript"]:
            for _, dec in _decode_blobs(js):
                texts.append(dec)
                f.setdefault("decoded_strings", []).append(dec)
    if p["open_action"]:
        f["open_action"] = Labels({"JavaScript": ["javascript", "JavaScript", "js"], "Launch": ["launch", "Launch"],
                                   "URI": ["uri", "URI", "url"], "GoTo": ["goto", "GoTo", "go_to"], "GoToR": ["gotor", "GoToR", "go_to_remote"],
                                   "SubmitForm": ["submit_form", "SubmitForm"]}.get(p["open_action"], [p["open_action"].lower(), p["open_action"]]), p["open_action"])
    f["has_open_action"] = bool(p["open_action"])
    f["has_additional_actions"] = p["additional_actions"]
    if p["launch"]:
        f["launch"] = p["launch"]
        f["shell_command"] = p["launch"]
        texts += p["launch"]
    if p["uris"]:
        texts += p["uris"]
        f["uris"] = p["uris"]
    if p["filters"]:
        f["filters"] = p["filters"]
    f["keyword_counts"] = {k: v for k, v in p["keywords"].items() if v}
    for name, body in p["embedded"]:
        pay.append((name, body, "an embedded file"))


# ---- OneNote ---------------------------------------------------------------------------------------------

_FDSO_HEAD = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")      # {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
_FDSO_FOOT = bytes.fromhex("22a7fb71790f0b4abb13899256426b24")      # {71FBA722-0F79-4A0B-BB13-899256426B24}


def onenote_files(data: bytes) -> list:
    """[(offset, bytes)] of every FileDataStoreObject of a OneNote section: the embedded files."""
    out, at = [], data.find(_FDSO_HEAD)
    while at >= 0 and len(out) < MAX_PAYLOADS:
        try:
            size = _u64(data, at + 16)
        except struct.error:
            break
        start = at + 36
        if 0 < size <= len(data) - start:
            out.append((at, data[start:start + size]))
            at = data.find(_FDSO_HEAD, start + size)
        else:
            at = data.find(_FDSO_HEAD, at + 16)
    return out


_NAME_EXT = r"(?:bat|cmd|hta|vbs|vbe|js|jse|wsf|ps1|exe|dll|lnk|chm|msi|scr|png|jpg|jpeg|gif|pdf|docx?|xlsx?|zip|iso|txt|html?|one)"


def _one_doc(data: bytes, doc: dict):
    f, pay = doc["fields"], doc["payloads"]
    files = onenote_files(data)
    shell = bytearray(data)
    for off, body in files:
        shell[off + 36:off + 36 + len(body)] = b"\x00" * len(body)
    wide = [s for s in triage.strings(bytes(shell)) if re.fullmatch(r"[^\\/:*?\"<>|\r\n]{1,120}\." + _NAME_EXT, s, re.I)]
    names = list(dict.fromkeys(wide))
    for i, (off, body) in enumerate(files):
        pay.append((f"embedded{i + 1}", body, f"FileDataStoreObject at 0x{off:x}"))
    if names:
        f["embedded_name_candidates"] = names
    f["onenote_guid"] = guid(data[:16])


# ---- LNK (MS-SHLLINK) --------------------------------------------------------------------------------------

_SHOW = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}
_DRIVE = {0: "DRIVE_UNKNOWN", 1: "DRIVE_NO_ROOT_DIR", 2: "DRIVE_REMOVABLE", 3: "DRIVE_FIXED", 4: "DRIVE_REMOTE",
          5: "DRIVE_CDROM", 6: "DRIVE_RAMDISK"}


def lnk(data: bytes) -> dict:
    """A shell link: {flags, created, accessed, modified (the target's times, UTC), target_size,
    show_command, hotkey, icon_index, description, relative_path, working_dir, arguments,
    icon_location, local_base_path, common_path_suffix, target, volume_serial, drive_type,
    volume_label, env_target, machine_id, mac_address, droid_volume, droid_file, overlay (bytes
    after the last block)}. ValueError when it is not one."""
    if data[:20] != LNK_MAGIC or len(data) < 76:
        raise ValueError("not a shell link")
    flags = _u32(data, 20)
    out = {"flags": flags, "attributes": _u32(data, 24), "created": filetime(_u64(data, 28)), "accessed": filetime(_u64(data, 36)),
           "modified": filetime(_u64(data, 44)), "target_size": _u32(data, 52), "icon_index": struct.unpack_from("<i", data, 56)[0],
           "show_command": _u32(data, 60), "hotkey": _u16(data, 64)}
    pos = 76
    if flags & 0x01:
        if pos + 2 > len(data):
            raise ValueError("truncated shell link IDList size")
        # The items are walked to their terminator, as the shell does (a padded link may state a list
        # size that is not the list's), and the drive and the file entries give a path of their own:
        # a link with no LinkInfo names its target only here.
        q, parts = pos + 2, []
        while q + 2 <= len(data):
            n = _u16(data, q)
            if n < 2:
                q += 2
                break
            item = data[q:q + n]
            kind = item[2] if len(item) > 2 else 0
            if kind & 0x70 == 0x20:
                parts.append(item[3:].split(b"\x00")[0].decode("cp1252", "replace").rstrip("\\"))
            elif kind & 0x70 == 0x30 and len(item) > 14:
                ext = item.find(b"\x04\x00\xef\xbe")
                name = ""
                if ext >= 4:
                    ver = _u16(item, ext - 2)
                    off = ext - 4 + (46 if ver >= 9 else 42 if ver >= 8 else 38 if ver >= 7 else 20)
                    name = item[off:off + 520].decode("utf-16-le", "replace").split("\x00")[0]
                if not name:
                    name = (item[14:].decode("utf-16-le", "replace") if kind & 0x04 else item[14:].decode("cp1252", "replace")).split("\x00")[0]
                parts.append(name or "?")
            q += n
        if parts and re.fullmatch(r"[A-Za-z]:", parts[0]) and "?" not in parts:
            out["id_list_path"] = "\\".join(parts)
        pos = q if q <= len(data) else pos + 2 + _u16(data, pos)
    if flags & 0x02:
        if pos + 4 > len(data):
            raise ValueError("truncated shell link LinkInfo size")
        size = _u32(data, pos)
        if size < 0x1C or pos + size > len(data):
            raise ValueError("invalid or truncated shell link LinkInfo")
        li = data[pos:pos + size]
        try:
            hsize, lflags, vol_off, base_off, _, suffix_off = struct.unpack_from("<IIIIII", li, 4)

            def cstr(off):
                return li[off:li.index(b"\x00", off)].decode("cp1252", "replace") if 0 < off < len(li) else None

            def wstr(off):
                if not 0 < off < len(li):
                    return None
                end = off
                while end + 1 < len(li) and li[end:end + 2] != b"\x00\x00":
                    end += 2
                return li[off:end].decode("utf-16-le", "replace")

            if lflags & 1:
                out["local_base_path"] = (wstr(_u32(li, 28)) if hsize >= 0x24 and _u32(li, 28) else None) or cstr(base_off)
                if vol_off:
                    v = li[vol_off:]
                    out["drive_type"] = _u32(v, 4)
                    out["volume_serial"] = _u32(v, 8)
                    lo = _u32(v, 12)
                    label = v[lo:v.index(b"\x00", lo)].decode("cp1252", "replace") if 0 < lo < len(v) and lo != 0x14 else None
                    if label:
                        out["volume_label"] = label
            out["common_path_suffix"] = (wstr(_u32(li, 32)) if hsize >= 0x24 and _u32(li, 32) else None) or cstr(suffix_off)
        except (struct.error, ValueError, IndexError):
            pass
        pos += size
    for bit, name in ((0x04, "description"), (0x08, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"), (0x40, "icon_location")):
        if flags & bit:
            if pos + 2 > len(data):
                raise ValueError("truncated shell link StringData count")
            n = _u16(data, pos)
            if bit in (0x04, 0x08, 0x10) and n > 260:
                # NAME, RELATIVE_PATH and WORKING_DIR hold at most 260 characters whatever the count
                # says: a link that hides its arguments overstates it and pads with blanks
                n = 260
                out["padded"] = True
            pos += 2
            if pos + n * (2 if flags & 0x80 else 1) > len(data):
                raise ValueError("truncated shell link StringData")
            if flags & 0x80:
                out[name] = data[pos:pos + 2 * n].decode("utf-16-le", "replace")
                pos += 2 * n
            else:
                out[name] = data[pos:pos + n].decode("cp1252", "replace")
                pos += n
    while pos + 4 <= len(data):
        size = _u32(data, pos)
        if size < 4:
            pos += 4
            break
        block = data[pos:pos + size]
        if len(block) < 8:
            break
        sig = _u32(block, 4)
        if sig == 0xA0000003 and len(block) >= 96:
            out["machine_id"] = block[16:32].split(b"\x00")[0].decode("ascii", "replace")
            out["droid_volume"], out["droid_file"] = guid(block[32:48]), guid(block[48:64])
            out["droid_birth_volume"], out["droid_birth_file"] = guid(block[64:80]), guid(block[80:96])
            # Only a version-1 (time-based, RFC 4122 variant) object id carries a node: a random
            # (version 4) one has no MAC address in it. Two ids with two nodes: which is asked is open.
            def node_of(g):
                return bytes(g[10:16]) if len(g) == 16 and g[7] >> 4 == 1 and g[8] & 0xC0 == 0x80 else None
            node, birth = node_of(block[48:64]), node_of(block[80:96])
            if size == 0x60 and node is not None and birth in (None, node):
                out["mac_address"] = ":".join(f"{b:02x}" for b in node)
        elif sig in (0xA0000001, 0xA0000007, 0xA0000006) and len(block) >= 788:
            name = {0xA0000001: "env_target", 0xA0000007: "env_icon", 0xA0000006: "darwin"}[sig]
            wide = block[268:788].decode("utf-16-le", "replace").split("\x00")[0]
            out[name] = wide or block[8:268].split(b"\x00")[0].decode("cp1252", "replace")
        pos += size
    out["overlay"] = data[pos:] if pos < len(data) else b""
    base, suffix = out.get("local_base_path"), out.get("common_path_suffix")
    out["target"] = (base + (suffix or "")) if base else (out.get("env_target") or out.get("id_list_path"))
    for k in ("description", "relative_path", "working_dir"):
        if isinstance(out.get(k), str) and len(out[k]) - len(out[k].rstrip()) >= 32:
            out["padded"] = True                # blanks that push the arguments out of the Properties box
            out[k] = out[k].rstrip()
    return out


def _lnk_doc(data: bytes, doc: dict):
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    k = lnk(data)
    for name in ("description", "relative_path", "working_dir", "arguments", "icon_location", "target", "env_target",
                 "machine_id", "created", "accessed", "modified", "target_size", "volume_label", "local_base_path",
                 "droid_file", "droid_volume", "icon_index"):
        if k.get(name) not in (None, ""):
            f[name] = k[name]
    if k.get("mac_address") and k["mac_address"] != "00:00:00:00:00:00":
        m = k["mac_address"]
        f["mac_address"] = Alt([("colon_lower", m), ("colon_upper", m.upper()), ("dash_upper", m.upper().replace(":", "-")),
                                ("plain_lower", m.replace(":", "")), ("dash_lower", m.replace(":", "-"))])
    if "volume_serial" in k:
        v = k["volume_serial"]
        f["volume_serial"] = Alt([("dash_upper", f"{v >> 16:04X}-{v & 0xFFFF:04X}"), ("hex_lower", f"{v:08x}"), ("hex_upper", f"{v:08X}"),
                                  ("0x_lower", f"0x{v:08x}"), ("dash_lower", f"{v >> 16:04x}-{v & 0xFFFF:04x}"), ("decimal", str(v))])
    if "drive_type" in k and k["drive_type"] in _DRIVE:
        d = _DRIVE[k["drive_type"]]
        f["drive_type"] = Alt([("snake", d[6:].lower()), ("constant", d), ("int", str(k["drive_type"]))])
    sc = k["show_command"]
    if sc in _SHOW:
        f["show_command"] = Alt([("constant", _SHOW[sc]), ("snake", {1: "normal", 3: "maximized", 7: "minimized"}[sc]),
                                 ("constant_lower", _SHOW[sc].lower()), ("int", str(sc))])
    if f.get("target"):
        line = f["target"] + ((" " + k["arguments"]) if k.get("arguments") else "")
        f["command_line"] = line
        f["shell_command"] = [line]
        f["target_name"] = re.split(r"[\\/]", f["target"])[-1]
    f["overlay_size"] = len(k["overlay"])
    if k.get("padded"):
        f["padded"] = True
        doc["notes"].append("the link's strings are padded (a count over 260, or a run of blanks): what Explorer shows is not the whole command")
    texts += [str(k.get(x) or "") for x in ("arguments", "target", "description", "icon_location", "working_dir", "env_target")]
    for technique, dec in _decode_blobs(k.get("arguments") or ""):
        texts.append(dec)
        f.setdefault("decoded_strings", []).append(dec)
        f.setdefault("obfuscation", []).append(technique) if technique not in f.get("obfuscation", []) else None
    if len(k["overlay"]) >= 16:
        pay.append(("overlay.bin", k["overlay"], "bytes appended after the link"))


# ---- ISO 9660, FAT, VHD --------------------------------------------------------------------------------------

def iso(data: bytes) -> dict:
    """An ISO 9660 image (Joliet names when present): {volume_label, system_id, publisher, preparer,
    application, created, joliet, files: [{path, size, hidden, modified, data}], notes}."""
    out = {"files": [], "dirs": [], "notes": [], "joliet": False}
    pvd = svd = None
    for sec in range(16, 64):
        d = data[sec * 2048:(sec + 1) * 2048]
        if len(d) < 2048 or d[1:6] != b"CD001":
            if d[1:6] in (b"BEA01", b"NSR02", b"NSR03", b"TEA01"):
                out["udf"] = True
                continue
            break
        if d[0] == 1 and pvd is None:
            pvd = d
        elif d[0] == 2 and d[88:91] in (b"%/@", b"%/C", b"%/E"):
            svd = d
        elif d[0] == 255:
            continue
    if pvd is None:
        raise ValueError("no ISO 9660 primary volume descriptor")
    out["volume_label"] = pvd[40:72].decode("ascii", "replace").strip("\x00 ")
    out["system_id"] = pvd[8:40].decode("ascii", "replace").strip("\x00 ")
    out["publisher"] = pvd[318:446].decode("ascii", "replace").strip("\x00 ")
    out["preparer"] = pvd[446:574].decode("ascii", "replace").strip("\x00 ")
    out["application"] = pvd[574:702].decode("ascii", "replace").strip("\x00 ")
    raw = pvd[813:830]
    try:
        if raw[:16].isdigit() and int(raw[:4]):
            tz = timezone(timedelta(minutes=15 * struct.unpack("b", raw[16:17])[0]))
            out["created"] = datetime(int(raw[:4]), int(raw[4:6]), int(raw[6:8]), int(raw[8:10]), int(raw[10:12]), int(raw[12:14]),
                                      int(raw[14:16]) * 10000, tzinfo=tz)
    except (ValueError, struct.error):
        pass
    vd = svd or pvd
    out["joliet"] = svd is not None
    if svd is not None:
        out["joliet_label"] = svd[40:72].decode("utf-16-be", "replace").strip("\x00 ")
    seen, total = set(), 0

    def walk(extent, size, prefix, depth):
        nonlocal total
        if depth > 16 or extent in seen or len(out["files"]) >= 2000:
            return
        seen.add(extent)
        d = data[extent * 2048:extent * 2048 + size]
        i = 0
        while i < len(d):
            n = d[i]
            if n == 0:
                i = (i // 2048 + 1) * 2048
                continue
            rec = d[i:i + n]
            i += n
            if len(rec) < 34:
                break
            ext, sz, fl, nl = _u32(rec, 2), _u32(rec, 10), rec[25], rec[32]
            name = rec[33:33 + nl]
            if name in (b"\x00", b"\x01"):
                continue
            text = name.decode("utf-16-be", "replace") if svd is not None else name.decode("ascii", "replace")
            text = re.sub(r";\d+$", "", text)
            text = text[:-1] if text.endswith(".") and svd is None else text
            y, mo, dd, hh, mi, ss, off = struct.unpack_from("6Bb", rec, 18)
            try:
                when = datetime(1900 + y, mo, dd, hh, mi, ss, tzinfo=timezone(timedelta(minutes=15 * off)))
            except ValueError:
                when = None
            if fl & 2:
                out["dirs"].append(prefix + text)
                walk(ext, sz, prefix + text + "/", depth + 1)
            else:
                body = data[ext * 2048:ext * 2048 + sz] if total + sz <= MAX_PAYLOAD_BYTES else None
                total += sz
                out["files"].append({"path": prefix + text, "size": sz, "hidden": bool(fl & 1), "modified": when, "data": body})

    walk(_u32(vd, 156 + 2), _u32(vd, 156 + 10), "", 0)
    if out.get("udf") and not out["files"]:
        out["notes"].append("a UDF image with no ISO 9660 tree: list it with sandbox_run('7z', data, args=('l', '{in}'))")
    return out


def _looks_fat(bs: bytes) -> bool:
    if len(bs) < 512 or bs[510:512] != b"\x55\xaa":
        return False
    bps, spc, nfats = _u16(bs, 11), bs[13], bs[16]
    return bps in (512, 1024, 2048, 4096) and spc in (1, 2, 4, 8, 16, 32, 64, 128) and nfats in (1, 2) and \
        (bs[54:57] == b"FAT" or bs[82:85] == b"FAT" or (_u16(bs, 14) >= 1 and bs[21] in (0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF) and bs[3:8] not in (b"NTFS ", b"EXFAT")))


def _mbr_parts(img: bytes) -> list:
    """[(type, first byte, byte length)] of the partitions of an MBR or GPT image; [] when it has none."""
    if len(img) < 512 or img[510:512] != b"\x55\xaa":
        return []
    out = []
    for i in range(4):
        e = img[446 + 16 * i:462 + 16 * i]
        ptype, lba, count = e[4], _u32(e, 8), _u32(e, 12)
        if e[0] not in (0, 0x80) or not ptype or not lba or not count or lba * 512 >= len(img):
            return [] if e[0] not in (0, 0x80) else out
        out.append((ptype, lba * 512, count * 512))
    if out and out[0][0] == 0xEE and img[512:520] == b"EFI PART":
        gpt = []
        ent, num, esz = _u64(img, 512 + 72), min(_u32(img, 512 + 80), 128), _u32(img, 512 + 84)
        for i in range(num):
            e = img[ent * 512 + i * esz:ent * 512 + (i + 1) * esz]
            if len(e) >= 48 and any(e[:16]):
                first, last = _u64(e, 32), _u64(e, 40)
                if first * 512 < len(img):
                    gpt.append((0xEE, first * 512, (last - first + 1) * 512))
        return gpt
    return out


def fat(img: bytes, base: int = 0) -> dict:
    """A FAT12/16/32 volume at byte `base` of an image: {type, volume_label, files: [{path, size, hidden,
    deleted, modified, data}]}. ValueError when no FAT boot sector stands there."""
    bs = img[base:base + 512]
    if not _looks_fat(bs):
        raise ValueError("no FAT boot sector")
    bps, spc, rsvd, nfats, rootent = _u16(bs, 11), bs[13], _u16(bs, 14), bs[16], _u16(bs, 17)
    total = _u16(bs, 19) or _u32(bs, 32)
    fatsz = _u16(bs, 22) or _u32(bs, 36)
    rootsecs = (rootent * 32 + bps - 1) // bps
    first_data = rsvd + nfats * fatsz + rootsecs
    clusters = max(0, (total - first_data) // spc)
    ftype = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
    table = img[base + rsvd * bps:base + (rsvd + fatsz) * bps]
    csize = spc * bps
    out = {"type": f"fat{ftype}", "files": [], "dirs": [], "volume_label": None}
    boot_label = (bs[71:82] if ftype == 32 else bs[43:54]).decode("cp437", "replace").strip()

    def nxt(c):
        try:
            if ftype == 12:
                v = _u16(table, c * 3 // 2)
                v = v >> 4 if c & 1 else v & 0xFFF
                return v if v < 0xFF8 else None
            if ftype == 16:
                v = _u16(table, c * 2)
                return v if v < 0xFFF8 else None
            v = _u32(table, c * 4) & 0x0FFFFFFF
            return v if v < 0x0FFFFFF8 else None
        except struct.error:
            return None

    def chain(c, limit):
        parts, seen, got = [], set(), 0
        while c is not None and c >= 2 and c not in seen and got < limit:
            seen.add(c)
            off = base + (first_data + (c - 2) * spc) * bps
            parts.append(img[off:off + csize])
            got += csize
            c = nxt(c)
        return b"".join(parts)[:limit]

    budget = [MAX_PAYLOAD_BYTES]

    def read_dir(raw, prefix, depth):
        lfn, gone = [], []
        for i in range(0, len(raw) - 31, 32):
            e = raw[i:i + 32]
            if e[0] == 0:
                break
            attr = e[11]
            if attr & 0x3F == 0x0F:
                (gone if e[0] == 0xE5 else lfn).insert(0, e[1:11] + e[14:26] + e[28:32])
                continue
            deleted = e[0] == 0xE5
            parts = gone if deleted else lfn
            long = b"".join(parts).decode("utf-16-le", "replace").split("\x00")[0] if parts else ""
            lfn, gone = [], []
            stem = e[0:8].decode("cp437", "replace").rstrip()
            ext = e[8:11].decode("cp437", "replace").rstrip()
            if e[12] & 0x08:
                stem = stem.lower()
            if e[12] & 0x10:
                ext = ext.lower()
            short = (("?" + stem[1:]) if deleted else stem) + ("." + ext if ext else "")
            if attr & 0x08:
                if not deleted and out["volume_label"] is None:
                    out["volume_label"] = (e[0:11].decode("cp437", "replace")).strip()
                continue
            name = long or short
            if name in (".", ".."):
                continue
            cluster = _u16(e, 26) | (_u16(e, 20) << 16 if ftype == 32 else 0)
            size = _u32(e, 28)
            t, d = _u16(e, 22), _u16(e, 24)
            try:
                when = datetime(1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2)
            except ValueError:
                when = None
            if attr & 0x10:
                if not deleted and depth < 12 and len(out["files"]) < 2000:
                    out["dirs"].append(prefix + name)
                    read_dir(chain(cluster, 4 << 20), prefix + name + "/", depth + 1)
                continue
            body = None
            if not deleted and size <= budget[0]:
                body = chain(cluster, size) if size else b""
                budget[0] -= size
            out["files"].append({"path": prefix + name, "size": size, "hidden": bool(attr & 0x02), "deleted": deleted,
                                 "modified": when, "data": body})

    if ftype == 32:
        root = chain(_u32(bs, 44), 4 << 20)
    else:
        off = base + (rsvd + nfats * fatsz) * bps
        root = img[off:off + rootent * 32]
    read_dir(root, "", 0)
    if out["volume_label"] is None and boot_label and boot_label != "NO NAME":
        out["volume_label"] = boot_label
    return out


def disk_image(img: bytes) -> dict:
    """A raw disk or volume image: {partitions: [{type, offset, size, filesystem}], volumes: [fat() results],
    files (of every FAT volume), volume_label, notes}."""
    out = {"partitions": [], "volumes": [], "files": [], "dirs": [], "notes": [], "volume_label": None}
    spots = [(0, 0, len(img))] if _looks_fat(img[:512]) or img[3:11] in (b"NTFS    ", b"EXFAT   ") else _mbr_parts(img)
    for ptype, off, size in spots:
        bs = img[off:off + 512]
        fs = ("ntfs" if bs[3:11] == b"NTFS    " else "exfat" if bs[3:11] == b"EXFAT   " else "fat" if _looks_fat(bs) else "unknown")
        if fs == "fat":
            try:
                v = fat(img, off)
                fs = v["type"]
                out["volumes"].append(v)
                out["files"] += v["files"]
                out["dirs"] += v["dirs"]
                out["volume_label"] = out["volume_label"] or v["volume_label"]
            except (ValueError, struct.error, IndexError):
                fs = "fat (unreadable)"
        elif fs in ("ntfs", "exfat"):
            out["notes"].append(f"an {fs} volume at byte {off}: not read here; list it with sandbox_run('7z', data, args=('l', '{{in}}'))")
        out["partitions"].append({"type": ptype, "offset": off, "size": size, "filesystem": fs})
    return out


def vhd(data: bytes) -> dict:
    """A VHD: {disk_type (fixed|dynamic|differencing), creator_app, creator_os, created, disk_size, uuid,
    disk: the raw disk image (None for a differencing disk or one over the size limit)}."""
    foot = data[-512:] if data[-512:-504] == b"conectix" else data[-511:] if data[-511:-503] == b"conectix" else data[:512]
    if foot[:8] != b"conectix":
        raise ValueError("no VHD footer")
    dtype = struct.unpack_from(">I", foot, 60)[0]
    out = {"disk_type": {2: "fixed", 3: "dynamic", 4: "differencing"}.get(dtype, str(dtype)),
           "creator_app": foot[28:32].decode("ascii", "replace").strip("\x00 "),
           "creator_os": foot[36:40].decode("ascii", "replace").strip("\x00 "),
           "created": datetime(2000, 1, 1, tzinfo=UTC) + timedelta(seconds=struct.unpack_from(">I", foot, 24)[0]),
           "disk_size": struct.unpack_from(">Q", foot, 48)[0], "uuid": foot[68:84].hex(), "disk": None}
    if dtype == 2:
        out["disk"] = data[:-512] if data[-512:-504] == b"conectix" else data[:-511]
    elif dtype == 3:
        hdr_off = struct.unpack_from(">Q", foot, 16)[0]
        hdr = data[hdr_off:hdr_off + 1024]
        if hdr[:8] == b"cxsparse" and out["disk_size"] <= MAX_PAYLOAD_BYTES:
            bat_off, = struct.unpack_from(">Q", hdr, 16)
            entries, bsize = struct.unpack_from(">II", hdr, 28)
            bitmap = ((bsize // 512 + 7) // 8 + 511) // 512 * 512
            disk = bytearray(out["disk_size"])
            for i in range(min(entries, (out["disk_size"] + bsize - 1) // bsize)):
                sec = struct.unpack_from(">I", data, bat_off + 4 * i)[0]
                if sec != 0xFFFFFFFF:
                    blk = data[sec * 512 + bitmap:sec * 512 + bitmap + bsize]
                    disk[i * bsize:i * bsize + len(blk)] = blk[:max(0, len(disk) - i * bsize)]
            out["disk"] = bytes(disk)
    return out


def _container_doc(data: bytes, doc: dict):
    f, pay = doc["fields"], doc["payloads"]
    kind, files, label, dirs = doc["kind"], [], None, []
    if kind == "iso":
        i = iso(data)
        doc["notes"] += i["notes"]
        files, dirs = i["files"], i["dirs"]
        label = i.get("joliet_label") or i["volume_label"]
        if i.get("joliet_label") and i["joliet_label"] != i["volume_label"]:
            f["volume_label"] = Alt([("primary", i["volume_label"]), ("joliet", i["joliet_label"])], definitions=True)
            label = None
        for k in ("publisher", "preparer", "application", "system_id", "created"):
            if i.get(k):
                f[k] = i[k]
        f["joliet"] = i["joliet"]
    else:
        img = data
        if kind == "vhd":
            v = vhd(data)
            f["disk_type"] = Labels([v["disk_type"], v["disk_type"] + "_vhd"], v["disk_type"])
            for k in ("creator_app", "creator_os", "created", "disk_size", "uuid"):
                if v.get(k):
                    f[k] = v[k]
            img = v["disk"]
            if img is None:
                doc["notes"].append("the disk of this VHD was not rebuilt (differencing, or over the size limit)")
                return
        d = disk_image(img)
        doc["notes"] += d["notes"]
        files, label, dirs = d["files"], d["volume_label"], d["dirs"]
        fs = [p["filesystem"] for p in d["partitions"]]
        if fs:
            f["filesystem"] = Labels([fs[0]] + (["fat"] if fs[0].startswith("fat") else []), fs[0]) if len(set(fs)) == 1 else fs
            f["partition_count"] = len(d["partitions"])
        deleted = [x["path"] for x in files if x.get("deleted")]
        if deleted:
            f["deleted_files"] = deleted
    if label:
        f["volume_label"] = label
    live = [x for x in files if not x.get("deleted")]
    gone = len(files) - len(live)
    if any(isinstance(x.get("data"), (bytes, bytearray)) and isinstance(x.get("size"), int) and len(x["data"]) != x["size"] for x in live):
        doc["partial"] = True
        doc["notes"].append("a listed file reaches past the end of the image (a cut image): no count is answered plain")
    f["file_count"] = Alt([("files", len(live))] + ([("files_and_directories", len(live) + len(dirs))] if dirs else [])
                          + ([("with_deleted", len(files))] if gone else []), definitions=True)
    if dirs:
        f["directory_names"] = dirs
    f["file_names"] = [x["path"] for x in live]
    f["hidden_files"] = [x["path"] for x in live if x.get("hidden")]
    for x in live:
        if x.get("data") is not None:
            pay.append((x["path"], x["data"], "a file of the image"))


# ---- HTA, WSF, SCT: the script blocks, for the Script Analysis lane --------------------------------------------

_LANG_EXT = {"vbscript": ".vbs", "vbs": ".vbs", "vbscript.encode": ".vbe", "jscript": ".js", "javascript": ".js", "js": ".js",
             "jscript.encode": ".jse", "powershell": ".ps1", "python": ".py", "perlscript": ".pl"}


def scripts(text: str, default: str = "javascript") -> list:
    """[{language, ext, src, text}] of every <script> block of an HTA, WSF or scriptlet."""
    out = []
    for m in re.finditer(r"<script\b([^>]*?)(?:/>|>(.*?)</script\s*>)", text, re.I | re.S):
        attrs = dict((k.lower(), v) for k, v in re.findall(r'([\w:-]+)\s*=\s*["\']?([^"\'\s>]+)', m.group(1) or ""))
        lang = (attrs.get("language") or attrs.get("type", "").split("/")[-1] or default).lower()
        body = m.group(2) or ""
        body = re.sub(r"^\s*<!\[CDATA\[|\]\]>\s*$", "", body.strip())
        body = re.sub(r"^\s*<!--|(?://\s*)?-->\s*$", "", body).strip("\r\n")
        out.append({"language": lang, "ext": _LANG_EXT.get(lang, ".txt"), "src": attrs.get("src"), "text": body})
    return out


def _script_doc(data: bytes, doc: dict):
    f, texts, pay = doc["fields"], doc["texts"], doc["payloads"]
    text = _text(data)
    blocks = scripts(text, "jscript" if doc["kind"] != "hta" else "javascript")
    inline = sum(1 for b in blocks if b["text"].strip())
    f["script_count"] = Alt([("all", len(blocks)), ("inline", inline)], definitions=True)
    langs = list(dict.fromkeys(b["language"] for b in blocks))
    if langs:
        f["script_languages"] = langs
    srcs = [b["src"] for b in blocks if b["src"]]
    if srcs:
        f["external_scripts"] = srcs
    stem = Path(doc["name"]).name or "script"
    for i, b in enumerate(blocks):
        if b["text"].strip():
            pay.append((f"{stem}#script{i + 1}{b['ext']}", b["text"].encode("utf-8"), f"a {b['language']} script block (hand it to solvers/script-analysis/analyze.py)"))
            texts.append(b["text"])
            if b["language"].startswith(("vbs", "vbscript")):
                d = deobfuscate(b["text"])
                texts += d["decoded"] + d["commands"]
                if d["decoded"]:
                    f["decoded_strings"] = f.get("decoded_strings", []) + d["decoded"]
                if d["commands"]:
                    f["shell_command"] = f.get("shell_command", []) + d["commands"]
    m = re.search(r"<hta:application\b([^>]*)>", text, re.I | re.S)
    if m:
        for k, v in re.findall(r'([\w:-]+)\s*=\s*["\']([^"\']*)["\']', m.group(1)):
            f["hta_" + k.lower()] = v


# ---- one document, whatever it is --------------------------------------------------------------------------------

_NS_HOSTS = re.compile(r"(?i)^(?:https?://)?(?:schemas\.(?:openxmlformats|microsoft)\.(?:org|com)|www\.w3\.org|purl\.org|"
                       r"ns\.adobe\.com|schemas\.xmlsoap\.org|www\.iec\.ch|www\.color\.org|www\.aiim\.org|www\.npes\.org)")
_READERS = {"slk": _slk_doc, "xml2003": _xml2003_doc, "csv_dde": _csv_dde_doc,
            "ole": _ole_doc, "ooxml": _ooxml_doc, "rtf": _rtf_doc, "pdf": _pdf_doc, "onenote": _one_doc, "lnk": _lnk_doc,
            "iso": _container_doc, "vhd": _container_doc, "disk_image": _container_doc, "hta": _script_doc,
            "wsf": _script_doc, "sct": _script_doc}


def parse(data: bytes, name: str = "", depth: int = 0, how: str = "") -> dict:
    """The document map of one file: {name, kind, family, size, sha256, md5, sha1, fields, children: [maps
    of its payloads], notes, how}. A file of no document kind has kind 'other' and its type from
    solvers/common/triage.py in fields['type']. Nothing raises: what cannot be read is a note."""
    family = kind_of(data, name)
    doc = {"name": name, "kind": family or "other", "family": family, "size": len(data), **_hashes(data), "fields": {},
           "children": [], "payloads": [], "texts": [], "notes": [], "how": how, "data": data, "modules": []}
    f = doc["fields"]
    if family == "activemime":
        inner = activemime(data)
        if inner:
            doc["payloads"].append(("activemime.ole", inner, "the compound file inside the ActiveMime wrapper"))
        else:
            doc["notes"].append("the ActiveMime wrapper holds no readable compound file")
    elif family == "vhdx":
        doc["notes"].append("a VHDX image: not read here; list it with sandbox_run('7z', data, args=('l', '{in}'))")
    elif family in _READERS:
        try:
            _READERS[family](data, doc)
        except Exception as e:          # a damaged or hostile file is a note, never a crash
            doc["notes"].append(f"not fully read: {type(e).__name__}: {str(e)[:120]}")
            doc["damaged"] = True
    else:
        f["type"] = triage.identify(data, name)
        if depth and f["type"].startswith(("text", "script", "html", "xml")):
            doc["texts"].append(_text(data[:1 << 20]))
    kind = doc["kind"]
    if kind in _KIND_LABELS:
        f["kind"] = Labels(_KIND_LABELS[kind], "")
    # the payloads
    pay = doc["payloads"][:MAX_PAYLOADS]
    if family and family not in SCRIPT_KINDS:
        f["embedded_count"] = len(pay)
        if pay:
            f["embedded_names"] = [n for n, _, _ in pay if not _OWN_NAME.fullmatch(n)]
            for algo in ("sha256", "md5", "sha1"):
                f["embedded_" + algo] = [hashlib.new(algo, b).hexdigest() for _, b, _ in pay]
            f["embedded_sizes"] = [len(b) for _, b, _ in pay]
    if depth < MAX_DEPTH:
        for n, body, why in pay:
            child = parse(body, n, depth + 1, why)
            doc["children"].append(child)
            if child["kind"] == "other":
                doc["texts"] += child["texts"]
        if pay and family not in SCRIPT_KINDS:
            f["embedded_types"] = [c["fields"].get("type") or c["kind"] for c in doc["children"]]
        # A package decrypted with a known password, a storage inside a PowerPoint stream, the
        # ActiveMime block of a 2003 XML document: the macros found there are the document's own.
        inner = [c for c in flatten(doc)[1:] if c["fields"].get("has_macros") is True]
        wraps = [c for c in doc["children"] if c["how"].startswith(_WRAPS)]
        for c in wraps:
            c["wrapped"] = True
        if wraps and f.get("has_macros") is not True:
            mine = [c for c in inner if any(c is w or c in flatten(w) for w in wraps)]
            if mine:
                f["has_macros"] = True
                for k in ("macro_type", "autoexec", "procedure_names", "module_names", "mraptor_flags", "suspicious"):
                    if k in mine[0]["fields"] and k not in f:
                        f[k] = mine[0]["fields"][k]
                doc["notes"].append(f"macros are in {mine[0]['name']} ({mine[0]['how']})")
    # indicators, from what the document itself says (macro source, decoded strings, links), not its schema text
    ind = triage.indicators([t for t in doc["texts"] if isinstance(t, str)])
    urls = [u for u in ind.get("urls", []) if not _NS_HOSTS.match(u)]
    if urls:
        f["urls"] = urls
        hosts = list(dict.fromkeys(h for h in (re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split("@")[-1].split(":")[0] for u in urls) if h))
        names = [h for h in hosts if not re.fullmatch(r"[\d.]+", h)]
        if names:
            f["domains"] = names
    ips = [i for i in ind.get("ipv4", []) if not re.fullmatch(r"(?:\d\.){3}\d", i)]
    if ips:
        f["ipv4"] = ips
    if ind.get("emails"):
        f["emails"] = ind["emails"]
    if family:
        att = _attack(f, kind.split("_")[0] if kind.startswith(("ole", "ooxml")) else kind)
        if att:
            f["attack"] = att
    for k in [k for k, v in f.items() if v is None or (isinstance(v, (list, str, dict)) and not isinstance(v, (Alt, Labels)) and len(v) == 0 and k not in _EMPTY_OK)]:
        del f[k]
    del doc["payloads"]
    return doc


_EMPTY_OK = ("hidden_sheets", "very_hidden_sheets", "hidden_files", "macro_sheets")
# names parse() gives a payload that has none of its own: never an embedded file's name
_OWN_NAME = re.compile(r"decrypted_package|ExternalOleObjectStg\d+|object\d+\.bin|activemime\.ole")
# a child that is the document itself in another wrapping: its parent's fields speak for both
_WRAPS = ("decrypted with", "an OLE storage inside the PowerPoint", "w:binData of the 2003")


def flatten(doc: dict) -> list:
    out = [doc]
    for c in doc["children"]:
        out += flatten(c)
    return out


def handoff(doc: dict) -> list:
    """[(file name, bytes)] of the script blocks and script files found in a document map: what the
    Script Analysis lane's analyze.py reads."""
    out = []
    for d in flatten(doc)[1:]:
        if re.search(r"#script\d+\.\w+$", d["name"]) or Path(d["name"]).suffix.lower() in triage.SCRIPT_EXT:
            out.append((d["name"], d["data"]))
    return out


# ---- YARA and the sandbox (never on a clock) ------------------------------------------------------------------------

_yara = None


def yara_scan(data: bytes, extra: bytes = b"") -> list:
    """The names of the maldoc_rules.yar rules that match the bytes (and `extra`, appended after a
    gap: decoded material). [] when yara-python or the rule file is missing."""
    global _yara
    try:
        import yara
        if _yara is None:
            _yara = yara.compile(filepath=str(RULES))
        return sorted({m.rule for m in _yara.match(data=data + (b"\x00" * 16 + extra if extra else b""), timeout=10)})
    except Exception:
        return []


def derived(doc: dict) -> bytes:
    """What was decoded out of a document, as bytes for yara_scan's `extra`."""
    parts = [m["source"] for d in flatten(doc) for m in d.get("modules", []) if m.get("source")]
    parts += [t for d in flatten(doc) for t in d["texts"] if isinstance(t, str)]
    return "\n".join(parts).encode("utf-8", "replace")[:8 << 20]


def sandbox_run(tool: str, data: bytes, name: str = "sample.bin", args=("{in}",), timeout: float = 60):
    """One tool of tools/sandbox.py (olevba, oleid, mraptor, rtfobj, oleobj, msodde, binwalk, 7z, yara,
    file) on the bytes, inside the container: (exit status, stdout text, {output file: bytes}).
    (None, reason, {}) when the sandbox is down: nothing is ever run natively. Never on a clock."""
    try:
        if str(TOOLS) not in sys.path:
            sys.path.insert(0, str(TOOLS))
        import sandbox
        r = sandbox.run(tool, list(args), inputs=[(Path(name).name or "sample.bin", data)], timeout=timeout)
        return r.code, (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace"), dict(r.files or {})
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", {}


# ---- how much a delivery looks like this category -------------------------------------------------------------------

_Q_WORDS = re.compile(r"(?i)\b(?:macros?|vba|olevba|oletools|xlm|excel ?4|auto_?open|document_open|workbook_open|ole ?(?:object|stream|2)?|"
                      r"compound file|objdata|rtf|shortcut|lnk|shell link|onenote|openaction|javascript|embedded (?:file|object|payload)|"
                      r"dropper|maldoc|malicious document|phishing (?:attachment|document)|remote template|template injection|dde(?:auto)?|"
                      r"equation editor|pdf|iso image|vhd|mounted|hta|scriptlet|lure|attachment)\b")
_STRONG = {"slk": 0.6, "xml2003": 0.45, "csv_dde": 0.6, "ole": 0.75, "rtf": 0.75, "onenote": 0.85, "lnk": 0.8, "iso": 0.8, "vhd": 0.8, "vhdx": 0.6, "disk_image": 0.6,
           "activemime": 0.8, "ooxml": 0.45, "pdf": 0.4, "hta": 0.2, "wsf": 0.2, "sct": 0.25}


_SCRIPT_ONLY = re.compile(r"-(?:role|steps|adapter|campaign)$")


def _owned(q, script_set: bool = False) -> bool:
    """True when a known lane's marks are on the question: its own solver answers it. A set that
    asks the Script Analysis lane's -role, -steps, -adapter or -campaign is that lane's, whole (its
    specimens include HTA and WSF files, and its other ids end in -url or -domain like anyone's).
    An ATT&CK answer alone is no such mark: a document has a technique too."""
    if script_set:
        return True
    sig = triage.lane_signals([q], {})
    if set(sig) == {"script-analysis"}:
        aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("id") or ""))
        return bool(_SCRIPT_ONLY.search(aid))
    return bool(sig)


def _script_set(questions) -> bool:
    return any(_SCRIPT_ONLY.search(re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("id") or ""))) for q in questions or [])


def _top_files(files: dict) -> list:
    """[(short name, bytes, family)] of the delivered files that are documents, without the parts
    tools/run.py's expand lists for an OOXML package (word/document.xml, vbaProject.bin, ...)."""
    fam = {}

    def family(data, name):
        if id(data) not in fam:
            fam[id(data)] = kind_of(bytes(data), name)
        return fam[id(data)]

    out = []
    for key, data in triage.unique_files(files):
        if ARROW in key:
            parent = files.get(key.split(ARROW)[0])
            if isinstance(parent, (bytes, bytearray)) and family(parent, key.split(ARROW)[0]) == "ooxml":
                continue
        k = family(data, key.split(ARROW)[-1])
        if k:
            out.append((key.split(ARROW)[-1], data, k))
    return out


def signals(questions, files) -> float:
    """0..1: how strongly the delivery and its questions look like a malicious-document challenge.
    Cheap (magic bytes and words only). Questions a known lane owns pull it down to near zero."""
    try:
        kinds = [k for _, _, k in _top_files(files or {})]
        file_score = max([_STRONG.get(k, 0) for k in kinds] or [0])
        if any(k in ("lnk", "hta", "wsf", "sct") for k in kinds) and any(k in ("iso", "vhd", "disk_image", "onenote") for k in kinds):
            file_score = min(1.0, file_score + 0.1)
        qs = list(questions or [])
        hits = 0
        for q in qs:
            text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"), q.get("artifact")))
            hits += bool(_Q_WORDS.search(text.replace("_", " ").replace("-", " ")))
        word_score = hits / len(qs) if qs else 0.0
        script = _script_set(qs)
        owned = sum(1 for q in qs if _owned(q, script)) / len(qs) if qs else 0.0
        score = (0.65 * file_score + 0.35 * word_score) if file_score else 0.15 * word_score
        if file_score >= 0.75 and word_score >= 0.5:
            score = max(score, 0.9)
        return round(max(0.0, min(1.0, score * (1.0 - 0.9 * owned))), 3)
    except Exception:
        return 0.0


# ---- the question: which field, which document, which form ------------------------------------------------------------

def _w(*alts):
    return re.compile(r"(?:^|_)(?:" + "|".join(alts) + r")(?:_|$)")


# (field, a pattern on the answer id with every non-alphanumeric run as '_', a pattern on the question text).
# First match wins, the id before the text, so the specific rows stand above the general ones.
FIELDS = [
    ("attack", _w("attack", "mitre", "att_ck", "technique_id", "attack_id", "ttp"), r"\bATT&?CK\b|\bMITRE\b|\btechnique id\b"),
    ("embedded_sha256", _w(r"(?:embedded|payload|object|dropped|attachment)\w*_sha_?256"), r"sha-?256\b.{0,60}\b(?:embedded|payload|object|dropped|attach)|\b(?:embedded|payload|object|dropped|attach)\w*\b.{0,60}sha-?256"),
    ("embedded_md5", _w(r"(?:embedded|payload|object|dropped|attachment)\w*_md5"), r"md5\b.{0,60}\b(?:embedded|payload|object|dropped|attach)|\b(?:embedded|payload|object|dropped|attach)\w*\b.{0,60}md5"),
    ("embedded_sha1", _w(r"(?:embedded|payload|object|dropped|attachment)\w*_sha_?1"), r"sha-?1\b.{0,60}\b(?:embedded|payload|object|dropped|attach)|\b(?:embedded|payload|object|dropped|attach)\w*\b.{0,60}sha-?1\b"),
    ("embedded_count", _w(r"(?:embedded|payload|attachment)s?_?(?:file|object)?s?_count", r"num(?:ber)?_(?:of_)?embedded\w*", "embedded_count"), r"how many (?:files|objects|payloads|attachments)?\s*(?:are|is)?\s*embedded|how many embedded|number of embedded"),
    ("embedded_sizes", _w(r"(?:embedded|payload|object)\w*_size"), r"size of the (?:embedded|payload|dropped)"),
    ("embedded_types", _w(r"(?:embedded|payload)\w*_(?:type|kind|format)"), r"(?:type|kind|format) of the (?:embedded|payload|dropped)"),
    ("embedded_names", _w(r"(?:embedded|payload|dropped|attachment|package)\w*_?(?:file_?)?names?", "dropped_file", "embedded_file", "payload_file"), r"(?:file ?name|(?<!class )name) of the (?:embedded|dropped|attached|packaged)|embedded file(?:'s)? name|"
     r"name of the (?:file|object|attachment|document) (?:that is |which is )?(?:embedded|attached|dropped|packaged)"),
    ("external_targets", _w(r"external_(?:target|relationship|url|link|reference)s?"), r"external (?:relationship|target|link|reference)"),
    ("remote_template", _w("remote_template", r"template_(?:url|injection|target)", "attached_template", "external_template"), r"remote template|template injection|attached template"),
    ("dde", _w("dde", "ddeauto", "dde_command", "dde_field"), r"\bDDE(?:AUTO)?\b"),
    ("cve", _w("cve", "cve_id", "vulnerability", "exploit"), r"\bCVE\b|which vulnerability|what vulnerability"),
    ("object_classes", _w(r"obj(?:ect)?_?class(?:es|_name)?", "class_name", "prog_?id", "ole_class"), r"\b(?:object|ole) class\b|\bclass name\b|\bprogid\b"),
    ("object_count", _w(r"objects?_count", r"num(?:ber)?_(?:of_)?objects", r"ole_objects?", r"rtf_objects?"), r"how many (?:ole |rtf |embedded |indirect )?objects"),
    ("macro_module_names", _w(r"macro_module(?:_name)?s?", r"malicious_module"), r"which module (?:contains|holds|has) the (?:macro|code)|module that contains"),
    ("module_count", _w(r"(?:vba_)?modules?_count", r"num(?:ber)?_(?:of_)?(?:vba_)?modules", r"macros?_count", r"num(?:ber)?_(?:of_)?macros"), r"how many (?:vba )?(?:modules|macros)|number of (?:vba )?(?:modules|macros)"),
    ("module_names", _w(r"(?:vba_)?module_?names?", r"macro_?names?", "modules"), r"names? of the (?:vba )?(?:modules?|macros?)|which (?:vba )?modules?"),
    ("module_stream_names", _w(r"(?:module|macro|vba)_streams?(?:_names?)?"), r"stream(?:s)? (?:that )?(?:holds?|contains?|stores?) the (?:macro|vba)"),
    ("procedure_count", _w(r"(?:procedure|sub|function)s?_count"), r"how many (?:procedures|subs|subroutines|functions)"),
    ("autoexec", _w(r"auto_?exec\w*", "trigger", r"entry_?point", r"auto_?open", r"auto_?run", "autostart", r"auto_?exec_(?:sub|macro|procedure)"), r"auto-?exec|\btrigger|entry point|runs? (?:automatically|when the (?:document|workbook|file) (?:is )?open)|which (?:sub|procedure|macro|function) (?:runs|executes|is executed|fires)"),
    ("procedure_names", _w("procedures?", r"procedure_names?", r"subs?", r"sub_names?", r"function_names?"), r"names? of the (?:procedures?|subs?|subroutines?|functions?)"),
    ("has_macros", _w(r"has_(?:vba_|xlm_)?macros?", r"macros?_present", r"contains?_(?:vba_)?macros?", "has_vba", "macro_enabled", "is_macro_enabled"), r"(?:contain|have|has|include|carr)\w* (?:a |an |any )?(?:vba |xlm |excel 4\.0 )?macros?\b|macro-?enabled"),
    ("macro_type", _w(r"macro_(?:type|kind|language|family)"), r"(?:type|kind) of macros?|macro (?:type|language)"),
    ("mraptor_flags", _w("mraptor", r"mraptor_flags?"), r"\bmraptor\b|macroraptor"),
    ("vba_stomped", _w(r"vba_stomp\w*", r"is_stomp\w*", r"source_stomp\w*", r"pcode_stomp\w*", r"p_?code_stomp\w*", r"stomp(?:ed|ing)?"),
     r"vba[- ]?stomp|\bstomp(?:ed|ing)?\b|p-?code (?:and |vs\.? )?(?:source|decompiled)|source (?:code )?(?:was |is )?(?:removed|zeroed|stomped|replaced|stripped|wiped)"),
    ("pcode_present", _w(r"p_?code\w*", r"performance_?cache\w*", r"has_p_?code", r"compiled_(?:vba_)?code"),
     r"\bp-?code\b|performance ?cache|compiled (?:vba )?code"),
    ("suspicious", _w("suspicious", "malicious", r"is_(?:suspicious|malicious)"), r"\bis (?:the |this )?(?:document|file|macro) (?:suspicious|malicious)"),
    ("obfuscation", _w(r"obfuscation\w*", r"encoding(?:_technique|_method)?", r"string_(?:building|obfuscation)"), r"obfuscat\w+ (?:technique|method)|how (?:is|are) the (?:string|command|payload)s? (?:obfuscated|hidden|built|encoded)"),
    ("xlm_formulas", _w(r"xlm_formulas?", r"macro_formulas?", r"excel4_formulas?"), r"\bxlm formula|excel 4\.0 (?:macro )?formula"),
    ("macro_sheets", _w(r"macro_?sheets?(?:_names?)?"), r"macro sheet"),
    ("very_hidden_sheets", _w(r"very_?hidden\w*"), r"very ?hidden"),
    ("hidden_sheets", _w(r"hidden_sheets?(?:_names?)?"), r"hidden (?:work)?sheet"),
    ("sheet_count", _w(r"sheets?_count", r"num(?:ber)?_(?:of_)?sheets"), r"how many (?:work)?sheets"),
    ("sheet_names", _w(r"sheet_?names?", "sheets"), r"names? of the (?:work)?sheets?"),
    ("has_javascript", _w(r"has_(?:java)?script", r"(?:contains?|has)_js", r"javascript_present"), r"(?:contain|have|has|include)\w* (?:any )?javascript"),
    ("javascript", _w("javascript", r"js(?:_code|_source|_payload)?", "script_code"), r"\bjavascript (?:code|source|payload)\b|what javascript"),
    ("open_action", _w(r"open_?action(?:_type)?", r"auto_?action"), r"open ?action"),
    ("launch", _w("launch", r"launch_(?:action|command|target)"), r"/?launch action|launch(?:es|ed)? (?:command|action)"),
    ("decoded_strings", _w(r"decoded(?:_string|_payload|_value|_command|_text)?s?", r"deobfuscated\w*", "plaintext", "cleartext"), r"\bdecod(?:e|ed|es|ing)\b|deobfuscat"),
    ("shell_command", _w(r"(?:shell_|executed_|payload_|full_)?command(?:_line)?", "cmd", "cmdline", "shell", "exec", "executed"), r"command (?:that is |line )?(?:is )?(?:executed|run|launched|spawned)|what command|which command|command line"),
    ("urls", _w("urls?", "uris?", "c2", r"c2_(?:url|server)", r"download_(?:url|link|location)", r"remote_(?:url|host|resource)", "callback", r"callback_url", "link", r"payload_url"), r"\burls?\b|\buris?\b|download(?:s|ed)? (?:its payload |the payload )?from|\bc2\b|command and control|call(?:s)? ?back"),
    ("domains", _w("domains?", r"host(?:name)?s?", r"c2_(?:domain|host)", "fqdn"), r"\bdomains?\b|\bhost ?names?\b"),
    ("ipv4", _w(r"ip(?:v4)?(?:_address(?:es)?)?", "ips"), r"\bip(?:v4)? address"),
    ("emails", _w(r"e?_?mails?(?:_address(?:es)?)?"), r"e-?mail address"),
    ("last_saved_by", _w(r"last_(?:saved|modified)_by", r"last_author", "modifier", r"last_modified_user", "operator"), r"last (?:saved|modified|edited) by|who last (?:saved|modified|edited)"),
    ("author", _w("author", r"author_name", r"dc_creator", r"created_by"), r"\bauthor\b|who (?:created|wrote|authored)"),
    ("producer", _w("producer"), r"\bproducer\b"),
    ("creator", _w("creator", r"creator_tool", r"creating_(?:tool|application)"), r"\bcreator\b"),
    ("application", _w(r"app(?:lication)?(?:_name)?", "software", "generator", "program"), r"\bapplication (?:name )?(?:that )?(?:created|produced|saved)|which application|what (?:application|software|program)"),
    ("company", _w("company", "organi[sz]ation"), r"\bcompany\b|\borgani[sz]ation\b"),
    ("title", _w("title", r"doc(?:ument)?_title"), r"\btitle\b"),
    ("subject", _w("subject"), r"\bsubject\b"),
    ("keywords", _w("keywords?"), r"\bkeywords\b"),
    ("comments", _w("comments?", "description_property"), r"\bcomments? (?:property|field)\b"),
    ("template", _w("template", r"template_name"), r"\btemplate\b"),
    ("revision", _w("revision", r"revision_number"), r"\brevision\b"),
    ("last_printed", _w(r"last_printed\w*", r"printed\w*"), r"last printed"),
    ("accessed", _w(r"access(?:ed)?(?:_time|_date|_timestamp)?", r"last_access\w*", "atime"), r"\b(?:last )?access(?:ed)? (?:time|date|timestamp)|when .{0,40} last accessed"),
    ("modified", _w(r"modif(?:ied|ication)(?:_time|_date|_timestamp)?", r"last_saved(?:_time|_date)?", r"mod_?date", r"write_time", r"last_write\w*", "mtime", r"last_modified"), r"\b(?:last )?(?:modif\w+|saved|written|write) (?:time|date|timestamp)|when .{0,40} last (?:modified|saved)"),
    ("created", _w(r"creat(?:ed|ion)(?:_time|_date|_timestamp)?", r"create_?time", "ctime", r"creation", "birth_?time"), r"\bcreat(?:ed|ion) (?:time|date|timestamp)|when was .{0,60} created"),
    ("stream_count", _w(r"streams?_count", r"num(?:ber)?_(?:of_)?streams"), r"how many (?:ole )?streams"),
    ("stream_names", _w(r"stream_?names?", "streams", r"ole_streams?"), r"names? of the (?:ole )?streams?|which (?:ole )?streams?"),
    ("storage_names", _w(r"storage_?names?", "storages"), r"\bstorages?\b"),
    ("project_name", _w(r"(?:vba_)?project(?:_name)?"), r"vba project(?:'s)? name|name of the vba project"),
    ("references", _w("references?", r"vba_references?"), r"\bvba references?\b"),
    ("clsid", _w("clsid", r"class_id", r"root_clsid"), r"\bclsid\b"),
    ("page_count", _w(r"pages?(?:_count)?", r"num(?:ber)?_(?:of_)?pages"), r"how many pages|number of pages|page count"),
    ("version", _w(r"(?:pdf_|header_)?version"), r"\bpdf version\b|which version of (?:the )?pdf"),
    ("filters", _w(r"(?:stream_)?filters?"), r"\b(?:stream )?filters?\b"),
    ("encrypted", _w(r"(?:is_)?encrypted", r"password_protected", "encryption"), r"\bencrypted\b|password[- ]protected"),
    ("arguments", _w(r"arg(?:ument)?s?", r"command_?line_arg(?:ument)?s?", "parameters?", r"lnk_arg(?:ument)?s?"), r"\barguments?\b|\bparameters?\b"),
    ("working_dir", _w(r"working_dir(?:ectory)?", r"start_in", "workdir", "cwd"), r"working directory|start in"),
    ("icon_location", _w(r"icon(?:_location|_path|_file)?"), r"\bicon (?:location|path|file)\b"),
    ("relative_path", _w(r"relative_path"), r"relative path"),
    ("machine_id", _w(r"machine(?:_id|_name)?", "netbios", r"netbios_name", "hostname_tracker", r"computer(?:_name)?", "workstation"), r"machine (?:id|identifier|name)|netbios|computer name|which (?:machine|computer|host) (?:created|built)"),
    ("mac_address", _w(r"mac(?:_address)?"), r"\bmac address\b"),
    ("volume_serial", _w(r"(?:volume|drive)_serial(?:_number)?", "serial", r"serial_number"), r"(?:volume|drive) serial"),
    ("drive_type", _w(r"drive_type"), r"drive type"),
    ("volume_label", _w(r"volume_(?:label|name|id|identifier)", "label"), r"volume (?:label|name|id|identifier)"),
    ("show_command", _w(r"show_?(?:command|cmd|window)", r"window_?(?:style|state)"), r"show ?command|window (?:style|state)"),
    ("target_size", _w(r"target_(?:file_)?size", r"file_size_field"), r"size of the (?:link )?target"),
    ("target_name", _w(r"target_(?:name|file|executable|binary|program)", "lolbin", r"lol_?bin", "executable", "program", "binary_name"), r"which (?:program|executable|binary|lolbin) (?:does|is)|target (?:executable|program|binary)"),
    ("command_line", _w(r"full_command(?:_line)?", r"target_and_arguments"), r"full command line"),
    ("target", _w("target", r"target_path", r"link_target", r"local_base_path", r"lnk_target"), r"\btarget(?: path)?\b|points? to"),
    ("description", _w("description", r"name_string", r"lnk_(?:name|description|comment)", "comment"), r"\bdescription\b"),
    ("overlay_size", _w(r"overlay_size", r"appended_(?:size|bytes)"), r"appended (?:data|bytes)|overlay"),
    ("deleted_files", _w(r"deleted_files?(?:_names?)?"), r"deleted files?"),
    ("hidden_files", _w(r"hidden_files?(?:_names?)?"), r"hidden files?"),
    ("file_count", _w(r"files?_count", r"num(?:ber)?_(?:of_)?files", r"member_count"), r"how many files"),
    ("file_names", _w(r"file_?names?", "files", "contents", "listing", "members"), r"names? of the files?|which files?|what files?"),
    ("publisher", _w("publisher"), r"\bpublisher\b"),
    ("disk_type", _w(r"disk_type", r"vhd_type"), r"disk type|type of (?:vhd|virtual disk)"),
    ("filesystem", _w(r"file_?system"), r"file ?system"),
    ("creator_app", _w(r"creator_app(?:lication)?"), r"creator application"),
    ("creator_os", _w(r"creator_(?:os|host_os)"), r"creator (?:host )?os"),
    ("disk_size", _w(r"disk_size", r"virtual_size"), r"(?:virtual|disk) size"),
    ("script_count", _w(r"scripts?_count", r"num(?:ber)?_(?:of_)?scripts"), r"how many script"),
    ("script_languages", _w(r"script_?(?:language|type|engine)s?", "language", "languages"), r"(?:script|scripting) language|which language"),
    ("external_scripts", _w(r"external_scripts?", r"script_src"), r"external script"),
    ("kind", _w(r"(?:doc(?:ument)?|file|container|carrier|lure)_?(?:type|format|kind)", "format", "type", "kind", "container", "carrier"), r"(?:what|which) (?:type|kind|format) of (?:document|file|container)|(?:document|file|container) (?:type|format)"),
]
_KIND_HINT = (("lnk", r"\blnk\b|\bshortcut\b|shell link"), ("pdf", r"\bpdf\b"), ("rtf", r"\brtf\b|rich text"),
              ("onenote", r"\bonenote\b"), ("iso", r"\biso\b"), ("vhd", r"\bvhdx?\b"), ("hta", r"\bhta\b"),
              ("wsf", r"\bwsf\b"), ("ole", r"\bole\b|\bvba\b|\bmacros?\b|\bword\b|\bexcel\b|\bworkbook\b|\bdocm?\b|\bxlsm?\b|\bxlm\b"),
              ("ooxml", r"\booxml\b|\bdocx\b|\bdocm\b|\bxlsx\b|\bxlsm\b|\bpptx\b|\bvba\b|\bmacros?\b|\bword\b|\bexcel\b|\bworkbook\b|\bxlm\b"))
_COUNT_FIELDS = ("module_count", "object_count", "stream_count", "page_count", "sheet_count", "file_count",
                 "script_count", "procedure_count", "partition_count")
_QUALIFIED = re.compile(r"(?i)\b(?:that|which|whose|with|where|named|matching|containing|contain|other than|except|excluding|including|"
                        r"ending|starting|larger|smaller|more than|less than|at least|hidden|visible|malicious|suspicious|non-?empty|empty)\b")
_HASH_FIELDS = {"embedded_sha256": "sha256", "embedded_md5": "md5", "embedded_sha1": "sha1"}
# A word of the answer id that narrows a count (visible-sheet-count, exe-file-count): that count is
# not the plain one, whatever the question text says.
_ID_QUALIFIERS = frozenset("""visible hidden very deleted empty nonempty class standard form user malicious suspicious benign external
    internal unique distinct encoded compressed encrypted obfuscated js javascript exe dll executable script auto autoexec linked
    public private signed unsigned large small other extra active live real decoy text binary image font data code stomped
    orphan orphaned unused used referenced unreferenced free allocated""".split())
# Fields whose value is a judgement or one of several mechanisms, and the negative of a search: a
# listed option that matches is still only offered (one probe on the untimed base), never plain.
_NEVER_PLAIN = ("attack", "suspicious", "vba_stomped", "pcode_present")


def _id_qualified(q) -> bool:
    return bool(_ID_QUALIFIERS & set(_norm_id(q).split("_")))


def _utc_proven(value, raw) -> bool:
    """True when a time's UTC reading is the only one: no source text beside it (a FILETIME), or a
    source text that states UTC itself. A PDF date with an offset, or with none, has a second
    reading (the wall clock as written), so a pattern cannot choose its form."""
    if not isinstance(value, datetime):
        return True
    if value.utcoffset() or value.year < 1980:      # 1601 and its neighbours are an unset FILETIME, not a date
        return False
    if raw is None:
        return True
    r = str(raw).strip()
    return bool(re.search(r"(?:Z|[+-]00'?:?(?:00)?'?)$", r))

def _norm_id(q) -> str:
    aid = re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))
    return re.sub(r"[^a-z0-9]+", "_", aid.lower()).strip("_")


def resolve_field(q):
    """The field a question asks for, by its answer id first and its text second; None when neither says."""
    nid = _norm_id(q)
    for name, rx, _ in FIELDS:
        if nid and rx.search(nid):
            return name
    text = " ".join(str(q.get("question") or "").split())
    for name, _, rx in FIELDS:
        if text and re.search(rx, text, re.I):
            return name
    return None


def _plural(q, field) -> bool:
    nid = _norm_id(q)
    text = str(q.get("question") or "")
    kind = str(triage._fmt(q).get("kind") or "")
    return bool(kind in ("ordered_tokens", "json", "list", "set", "unordered_tokens")
                or re.search(r"(?:names|urls|uris|domains|hosts|ips|files|streams|storages|modules|macros|sheets|strings|addresses|classes|languages|"
                             r"filters|formulas|procedures|subs|targets|references|commands|scripts|emails|contents|listing|members)$", nid)
                or re.search(r"(?i)\b(?:all|every|each|list)\b|\bnames\b|\burls\b|\bdomains\b|comma-?separated", text))


def _named_docs(q, docs: list) -> list:
    """The documents a question names (its member, or a file name in its text); [] when it names none."""
    member = str(q.get("member") or "")
    text = str(q.get("question") or "") + " " + str(q.get("artifact") or "")
    hits = []
    for d in docs:
        base = Path(d["name"]).name
        if not base or len(base) < 3:
            continue
        if member and (member == d["name"] or Path(member).name == base):
            hits.append(d)
        elif re.search(r"(?<![\w.-])" + re.escape(base) + r"(?![\w-])", text):
            hits.append(d)
    return hits


def _time_options(t: datetime, raw=None) -> list:
    u = t.astimezone(UTC)
    opts = [("raw", raw)] if raw else []
    opts += [("iso_z", u.strftime("%Y-%m-%dT%H:%M:%SZ")), ("iso_space", u.strftime("%Y-%m-%d %H:%M:%S")),
             ("iso_offset", u.strftime("%Y-%m-%dT%H:%M:%S+00:00")), ("iso_naive", u.strftime("%Y-%m-%dT%H:%M:%S"))]
    if u.microsecond:
        opts.insert(1 if raw else 0, ("iso_z_frac", u.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"))
    if t.utcoffset() and raw is None:
        opts.append(("iso_local_offset", t.isoformat(timespec="seconds")))
    if t.utcoffset():
        # the wall clock as the file writes it is the other reading of a time with an offset
        w = t.replace(tzinfo=None)
        opts += [("wall_iso_z", w.strftime("%Y-%m-%dT%H:%M:%SZ")), ("wall_iso_space", w.strftime("%Y-%m-%d %H:%M:%S")),
                 ("wall_iso_naive", w.strftime("%Y-%m-%dT%H:%M:%S"))]
    opts += [("date", u.strftime("%Y-%m-%d")), ("epoch", str(int(u.timestamp()))), ("space_utc", u.strftime("%Y-%m-%d %H:%M:%S UTC"))]
    return opts


def _list_options(items: list) -> list:
    s = [str(x) for x in items]
    opts = [("comma", ",".join(s)), ("comma_space", ", ".join(s)), ("json", json.dumps(s, ensure_ascii=False, separators=(",", ":"))),
            ("space", " ".join(s)) if not any(" " in x for x in s) else None, ("semicolon", ";".join(s)), ("pipe", "|".join(s)),
            ("newline", "\n".join(s))]
    if sorted(s) != s:
        z = sorted(s)
        opts += [("sorted_comma", ",".join(z)), ("sorted_comma_space", ", ".join(z)),
                 ("sorted_json", json.dumps(z, ensure_ascii=False, separators=(",", ":")))]
    return [o for o in opts if o]


def _slug(s) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def _options(q, field, value, doc):
    """(mode, options, shape): mode 'plain' with one string, 'pick' with [(name, value)] or labels, or None."""
    fmt = triage._fmt(q)
    kind_fmt = str(fmt.get("kind") or "")
    text = str(q.get("question") or "")
    shape = doc["kind"]
    if isinstance(value, Labels):
        return "labels", list(value), shape + ("." + value.shape if value.shape else "")
    if isinstance(value, Alt):
        vals = {str(v) for _, v in value}
        if len(vals) == 1 and field in _COUNT_FIELDS:
            return _options(q, field, value[0][1], doc)
        return "pick", [(n, str(v)) for n, v in value], shape
    if isinstance(value, bool):
        t = value
        return "pick", [("true_false", "true" if t else "false"), ("yes_no", "yes" if t else "no"),
                        ("title", "True" if t else "False"), ("1_0", "1" if t else "0")], shape + ".bool"
    if isinstance(value, int):
        # zero is what a reader that found nothing reports too: offered, never plain
        if field in _COUNT_FIELDS and kind_fmt == "integer" and value > 0 and not doc.get("partial") \
                and not _QUALIFIED.search(text) and not _id_qualified(q):
            return "plain", str(value), shape
        return "pick", [("decimal", str(value))], shape
    if isinstance(value, datetime):
        return "pick", _time_options(value, doc["fields"].get(field + "__raw")), shape + ".time"
    if isinstance(value, dict):
        return None, None, shape
    if isinstance(value, list):
        if not value:
            return "pick", [("none", "none"), ("json", "[]")], shape + ".empty"
        vals = list(dict.fromkeys(str(v) for v in value))
        if field in _HASH_FIELDS:
            if len(vals) != 1:
                return None, None, shape
            # The hash is exact; which object the question means is not (the one payload read here, the
            # document that carries it, an object this reader did not find): offered, never plain.
            upper = re.search(r"(?i)\bupper-?case\b", str(fmt.get("syntax") or "") + " " + text) is not None
            return "pick", [("payload", vals[0].upper() if upper else vals[0])], shape
        if len(vals) == 1:
            return _options(q, field, value[0] if not isinstance(value[0], str) else vals[0], doc)
        if not _plural(q, field):
            return None, None, shape        # "the URL" with three different URLs: different facts, no answer
        return "pick", _list_options(vals), shape + ".list"
    v = str(value)
    opts = [("raw", v)]
    if field in ("autoexec", "procedure_names", "module_names", "macro_module_names", "object_classes", "target_name", "machine_id",
                 "script_languages", "filters", "obfuscation"):
        for name, alt in (("lower", v.lower()), ("snake", _slug(v))):
            if alt and alt not in [o[1] for o in opts]:
                opts.append((name, alt))
    if field in ("urls", "remote_template", "domains", "ipv4"):
        d = v.replace("http", "hxxp", 1).replace(".", "[.]") if field != "ipv4" else v.replace(".", "[.]")
        if re.search(r"(?i)defang", text + " " + str(fmt.get("syntax") or "")):
            opts.insert(0, ("defanged", d))
        if v.endswith("/") and field in ("urls", "remote_template"):
            opts.append(("no_trailing_slash", v.rstrip("/")))
    if field in ("clsid", "droid_file", "uuid"):
        opts += [("upper", v.upper()), ("braces", "{" + v.upper() + "}")]
    return "pick", opts, shape


# A question that negates or excludes ("the file that is NOT the attachment", "the size without the
# attachment", "other than", "except") asks for something this file's reading of it does not prove:
# never plain. A format instruction ("do not include the 0x prefix", "without quotes") is not one.
_FORMAT_NEG = re.compile(r"(?i)\b(?:do not|don't|not|without|no|excluding)\s+(?:\w+\s+){0,3}?(?:0x|prefix(?:es)?|quotes?|quotation marks?|units?|spaces?|"
                         r"extensions?|braces|brackets|dashes|hyphens|colons|separators?|padding|zeros?|punctuation|whitespace|newlines?|"
                         r"trailing \w+|leading \w+|scheme|defang\w*)\b")
_NEGATION = re.compile(r"(?i)\bnot\b|n't\b|\bwithout\b|\bexcluding\b|\bexcept\b|\bother than\b|\bnever\b|\bneither\b|\bminus\b|\bapart from\b")


def _negates(text) -> bool:
    return _NEGATION.search(_FORMAT_NEG.sub(" ", str(text or ""))) is not None


_NEGATED = re.compile(r"(?i)\bnot\b|n't\b|\bwithout\b|\bfree (?:of|from)\b|\blacks?\b|\blacking\b|\babsent\b|\bnever\b|\bno longer\b|\bfalse that\b")


def _match_enum(options: list, candidates: list):
    """The one option of the question's own list that is one of the candidates (compared as slugs)."""
    want = {_slug(c) for c in candidates if _slug(c)}
    hits = [o for o in options if _slug(o) in want]
    return hits[0] if len(hits) == 1 else None


def explain(q, docs: list, script_set: bool = False) -> dict:
    """{answer, field, doc, why} for one question over the parsed documents (see the module text).
    script_set: the question's set also asks the Script Analysis lane's own fields."""
    out = {"answer": None, "field": None, "doc": None, "why": ""}
    if _owned(q, script_set):
        out["why"] = "a known lane's question"
        return out
    fmt = triage._fmt(q)
    field = "attack" if str(fmt.get("kind") or "") == "mitre_attack_id" else resolve_field(q)
    out["field"] = field
    if not field:
        out["why"] = "no field of this toolkit is asked"
        return out
    pool = [d for d in docs if d["family"]]
    named = _named_docs(q, docs)
    if named:
        scope = []
        for d in named:
            scope += [x for x in flatten(d) if x["family"] and x not in scope]
        pool = scope
    else:
        # a kind word in the answer id narrows the documents; one in the text does too, except for
        # "what is this file" itself (its text may name what the file holds)
        nid = _norm_id(q).replace("_", " ")
        hint = nid if any(re.search(rx, nid) for _, rx in _KIND_HINT) else "" if field == "kind" else str(q.get("question") or "").lower()
        for fam, rx in _KIND_HINT:
            if re.search(rx, hint):
                hinted = [d for d in pool if d["family"] == fam or (fam == "ole" and d["family"] == "ooxml") or (fam == "ooxml" and d["family"] == "ole")]
                if hinted:
                    pool = hinted
                    break
    if field in _HASH_FIELDS:
        # the hash of an embedded file the question names (in its text, not as its artifact): that
        # payload's own bytes, never the hash of the storage or the document around it
        text = str(q.get("question") or "")
        kids = [d for d in docs if d.get("how") and len(Path(d["name"]).name) >= 3
                and re.search(r"(?<![\w.-])" + re.escape(Path(d["name"]).name) + r"(?![\w-])", text)]
        hashes = {d[_HASH_FIELDS[field]] for d in kids}
        if kids:
            if len(hashes) != 1:
                out["why"] = "the question names an embedded file that occurs with different contents"
                return out
            out["doc"] = kids[0]["name"]
            out["answer"] = pick(f"{KEY}.{field}/named_payload", [("payload", hashes.pop())])
            out["why"] = "the hash of the payload the question names; how it was carved is this file's reading"
            return out
    have = [d for d in pool if field in d["fields"] and not (d.get("unreadable") and field not in ("encrypted", "kind"))
            and not (d.get("damaged") and field != "kind")]
    # a wrapped child (the decrypted package, a storage inside a PowerPoint stream) is its parent in
    # another wrapping: where both state the field, the parent's is the document's
    # ... except behind an encrypted package, whose own fields are only what the wrapper shows: there
    # the decrypted child speaks for everything but the wrapper's own facts.
    outer_only = ("encrypted", "kind", "stream_names", "stream_count", "storage_names", "embedded_count")

    def child_speaks(parent):
        return parent["fields"].get("encrypted") is True and parent["family"] == "ole" and field not in outer_only

    kept = []
    for d in have:
        parent = next((o for o in have if any(d is c for c in o["children"])), None)
        if d.get("wrapped") and parent is not None and not child_speaks(parent):
            continue
        if child_speaks(d) and any(c.get("wrapped") and any(c is h for h in have) for c in d["children"]):
            continue
        kept.append(d)
    have = kept
    if not have:
        out["why"] = f"no document has the field {field}"
        return out
    if field not in ("encrypted", "kind", "stream_names", "stream_count", "storage_names", "embedded_count"):
        clear = [d for d in have if not (d["fields"].get("encrypted") is True and d["family"] == "ole")]
        if not clear:
            out["why"] = "the document is encrypted"
            return out
        have = clear

    def canon(v):
        return json.dumps(v, default=str, sort_keys=True)

    if len({canon(d["fields"][field]) for d in have}) != 1:
        # Only what a file is has an outermost reading (an ISO that holds a shortcut is an ISO).
        tops = [d for d in have if not any(d is not o and any(d is x for x in flatten(o)[1:]) for o in have)]
        if field not in ("kind", "encrypted", "embedded_count") or len(tops) != 1:
            out["why"] = f"{len(have)} documents have different values for {field}"
            return out
        have = tops
    doc = have[0]
    out["doc"] = doc["name"]
    value = doc["fields"][field]
    if isinstance(value, bool) and _NEGATED.search(str(q.get("question") or "")):
        # "does it NOT contain macros": the listed option that names the fact is then the wrong one
        out["why"] = "a negated yes/no question: which option the fact makes true is not read"
        return out
    mode, opts, shape = _options(q, field, value, doc)
    if mode is None:
        out["why"] = f"{field} has several different values and the question asks for one" if isinstance(value, list) else "no form to answer in"
        return out
    enum = triage.enum_options(q) or (labels.enum_from_question(str(q.get("question") or "")) if str(fmt.get("kind") or "") == "enum" else [])
    cands = [opts] if mode == "plain" else list(opts) if mode == "labels" else [v for _, v in opts]
    if enum:
        hit = _match_enum(enum, cands)
        if hit is not None and (field in _NEVER_PLAIN or value is False or field in _HASH_FIELDS or doc["kind"] == "ole_encrypted"
                                or (isinstance(value, Alt) and value.definitions and len({str(v) for _, v in value}) > 1)):
            out["answer"], out["why"] = pick(f"{KEY}.{field}/{shape}.enum", [hit]), "a listed option matches; the fact behind it is a reading, not a proof"
            return out
        if hit is not None and _negates(q.get("question")):
            out["answer"], out["why"] = pick(f"{KEY}.{field}/{shape}.enum", [hit]), "a listed option matches, in a question that negates or excludes"
            return out
        out["answer"], out["why"] = hit, ("the one listed option that is the fact" if hit else "none or several of the listed options match")
        return out
    key = f"{KEY}.{field}/{shape}"
    negated = _negates(q.get("question"))
    if mode == "plain" and negated:
        mode, opts = "pick", [("decimal", opts)]        # "how many pages does it NOT have": the count is not what is asked
    if mode == "plain":
        out["answer"], out["why"] = (opts if triage._fits(q, opts) else None), "proven, one form"
        return out
    has_rx = isinstance(fmt.get("pattern") or fmt.get("regex"), str) and (fmt.get("pattern") or fmt.get("regex")).strip()
    if mode == "labels":
        fit = [o for o in opts if triage._fits(q, o)]
        out["answer"], out["why"] = pick(key, fit), f"the fact is established; its name is not judged ({key})"
        return out
    fit = [(n, v) for n, v in opts if triage._fits(q, v)]
    distinct = list(dict.fromkeys(v for _, v in fit))
    if has_rx and len(distinct) == 1 and len({v for _, v in opts}) > 1 and not isinstance(value, bool) \
            and not (isinstance(value, Alt) and value.definitions) and field not in _NEVER_PLAIN and field not in _HASH_FIELDS \
            and _utc_proven(value, doc["fields"].get(field + "__raw")) and not negated:
        out["answer"], out["why"] = distinct[0], "the answer_format's pattern lets one form through"
        return out
    out["answer"], out["why"] = pick(key, fit), f"the fact is established; its form is not judged ({key})"
    return out


def documents(files: dict) -> list:
    """Every delivered document parsed, flattened with its payloads: the list explain() reads."""
    docs = []
    for name, data, _ in _top_files(files):
        docs += flatten(parse(data, name))
    return docs


def solve_set(questions, files, ctx) -> dict:
    out = {q.get("qid") or q.get("id"): None for q in questions}
    try:
        script = _script_set(questions)
        asked = [q for q in questions if not _owned(q, script) and (resolve_field(q) or str(triage._fmt(q).get("kind") or "") == "mitre_attack_id")]
        if not asked:
            return out
        docs = documents(files)
        if not docs:
            return out
    except Exception:
        return out
    for q in asked:
        try:
            out[q.get("qid") or q.get("id")] = explain(q, docs, script)["answer"]
        except Exception:               # a fact that cannot be read is no answer
            out[q.get("qid") or q.get("id")] = None
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


# ---- the command -------------------------------------------------------------------------------------------------------

def _show(v, width=160):
    if isinstance(v, datetime):
        return v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, Alt):
        vals = list(dict.fromkeys(str(x) for _, x in v))
        return vals[0] if len(vals) == 1 else " | ".join(f"{n}={x}" for n, x in v)
    if isinstance(v, Labels):
        return f"{v[0]}   (other spellings: {', '.join(v[1:5])})" if len(v) > 1 else v[0]
    if isinstance(v, list):
        s = "; ".join(_show(x, 300) for x in v[:12]) + (f"; ... ({len(v)})" if len(v) > 12 else "")
    else:
        s = str(v)
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return s if len(s) <= width else s[:width] + f"... ({len(s)} chars)"


def jsonable(doc: dict) -> dict:
    def conv(v):
        if isinstance(v, datetime):
            return v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if isinstance(v, Labels):
            return {"labels": list(v), "shape": v.shape}
        if isinstance(v, Alt):
            return {"alternatives": [[n, conv(x)] for n, x in v], "definitions": v.definitions}
        if isinstance(v, (list, tuple)):
            return [conv(x) for x in v]
        if isinstance(v, dict):
            return {str(k): conv(x) for k, x in v.items()}
        if isinstance(v, bytes):
            return {"bytes": len(v), "sha256": hashlib.sha256(v).hexdigest()}
        return v
    return {"name": doc["name"], "kind": doc["kind"], "size": doc["size"], "sha256": doc["sha256"], "md5": doc["md5"],
            "how": doc["how"], "fields": conv(doc["fields"]), "notes": doc["notes"],
            "modules": [{k: m.get(k) for k in ("name", "stream", "type", "code_lines")} for m in doc.get("modules", [])],
            "children": [jsonable(c) for c in doc["children"]]}


def report(doc: dict, indent: str = "", source: bool = False) -> list:
    lines = [f"{indent}{doc['name'] or '(bytes)'}: {doc['kind']}  {doc['size']} bytes  sha256 {doc['sha256']}"
             + (f"   [{doc['how']}]" if doc["how"] else "")]
    for k, v in doc["fields"].items():
        if k.endswith("__raw") or k == "keyword_counts" and not v:
            continue
        lines.append(f"{indent}  {k:<22} {_show(v)}")
    for m in doc.get("modules", []):
        lines.append(f"{indent}  module {m['name']} ({m.get('type') or '?'}, stream {m['stream']}, {m.get('code_lines')} code lines)")
        if source and m.get("source"):
            lines += [f"{indent}    | {ln}" for ln in m["source"].splitlines()]
    for n in doc["notes"]:
        lines.append(f"{indent}  NOTE {n}")
    for c in doc["children"]:
        lines += report(c, indent + "    ", source)
    return lines


def main(argv) -> int:
    flags = {a for a in argv if a.startswith("--")}
    args, extract, attempt, skip = [], None, None, False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a in ("--extract", "--attempt"):
            if i + 1 >= len(argv):
                print(__doc__.split("\n\n")[1], file=sys.stderr)
                return 2
            extract, attempt = (argv[i + 1], attempt) if a == "--extract" else (extract, argv[i + 1])
            skip = True
        elif not a.startswith("--"):
            args.append(a)
    if attempt:
        folder = Path(attempt).resolve()
        try:
            _, sets, notes = triage.load(folder)
        except SystemExit as e:
            print(f"maldoc.py: the saved attempt cannot be read ({e.code})", file=sys.stderr)
            return 1
        for qs, files, ctx in sets:
            docs = documents(files)
            print(f"SIGNALS maldoc={signals(qs, files)} documents={', '.join(d['name'] + ':' + d['kind'] for d in docs if d['family']) or '-'}")
            for q in qs:
                e = explain(q, docs, _script_set(qs))
                print(f"{q.get('answer_id')}: field={e['field'] or '-'} doc={e['doc'] or '-'} answer={_show(e['answer']) if e['answer'] is not None else 'None'}   ({e['why']})")
        for n in notes:
            print(f"NOTE {n}")
        return 0
    if not args:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    code, maps = 0, []
    for a in args:
        p = Path(a)
        if not p.is_file():
            print(f"maldoc.py: {a} is not a file", file=sys.stderr)
            code = 1
            continue
        t0 = time.monotonic()
        data = p.read_bytes()
        if data[:4] == b"PK\x03\x04" and not kind_of(data, p.name):
            # a plain zip around the document (the runner hands a solver the members; here they are read out)
            try:
                import archive_passwords            # solvers/common: `infected`, then the stored passwords; none is ever made up
                members, locked = archive_passwords.read_all(data)
            except Exception:
                members, locked = {}, []
            if members or locked:
                for inner_name, body in list(members.items())[:32]:
                    inner = parse(body, inner_name)
                    maps.append(jsonable(inner))
                    if "--json" not in flags:
                        print(f"{p.name} -> " + "\n".join(report(inner, source="--source" in flags)))
                if locked:
                    print(f"  NOTE {p.name}: {len(locked)} member(s) no stored password opens ({', '.join(map(str, locked[:4]))}); tools/password.py add stores one")
                continue
        doc = parse(data, p.name)
        maps.append(jsonable(doc))
        if "--json" not in flags:
            print("\n".join(report(doc, source="--source" in flags)))
            hits = yara_scan(data, derived(doc))
            if hits:
                print(f"  yara                   {', '.join(hits)}")
            hand = handoff(doc)
            if hand:
                print(f"  script lane            {len(hand)} script(s): --extract DIR writes them; then solvers/script-analysis/analyze.py")
            if "--sandbox" in flags and doc["family"] in ("ole", "ooxml", "rtf"):
                tool = "rtfobj" if doc["family"] == "rtf" else "olevba"
                status, text, _ = sandbox_run(tool, data, p.name)
                print(f"  sandbox {tool}: " + (f"exit {status}\n{text}" if status is not None else f"down ({text}); nothing was run natively"))
            print(f"  ({time.monotonic() - t0:.2f} s)")
        if extract:
            dest = Path(extract)
            dest.mkdir(parents=True, exist_ok=True)
            for i, d in enumerate(flatten(doc)[1:]):
                safe = re.sub(r"[^A-Za-z0-9._#-]+", "_", d["name"])[-120:] or "payload"
                (dest / f"{i + 1:02d}_{safe}").write_bytes(d["data"])
            for m in doc.get("modules", []):
                if m.get("source"):
                    (dest / (re.sub(r"[^A-Za-z0-9._-]+", "_", m["name"]) + ".vba")).write_text(m["source"])
            print(f"  extracted {len(flatten(doc)) - 1} payload(s) and {sum(1 for m in doc.get('modules', []) if m.get('source'))} module(s) to {dest}")
    if "--json" in flags:
        print(json.dumps(maps if len(maps) != 1 else maps[0], indent=1, ensure_ascii=False))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
