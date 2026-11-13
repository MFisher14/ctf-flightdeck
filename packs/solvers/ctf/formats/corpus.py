"""Synthetic format corpus (B-162): one deterministic builder per sample of every ranked format.

Every builder writes its file from invented values and returns a `Sample`: the delivered name, the bytes,
and the `checks` that hold on those bytes by construction: what the builder itself wrote (a ProductCode
row, a cabinet member's bytes, a shortcut's LocalBasePath), never what a reader printed. A check whose
reader needs an external decoder names it in `needs_tools` (an LZX cabinet folder: 7zz or bsdtar).

Nothing here is a real challenge file, nothing is downloaded, nothing is executed.

    BUILDERS            sample id -> builder()
    build(sample_id)    the Sample, or CorpusError naming an unknown id
    cfb_write(...)      a version 3 compound file (OLE/CFB) of {path: bytes}
    property_set(...)   a SummaryInformation property set stream
    msi_stream_name()   a stream name as an MSI database stores it
    cab_write(...)      a cabinet (MSCF): stored, MSZIP, LZX (uncompressed blocks) or pre-encoded blocks
    lzx_uncompressed()  an LZX stream of one uncompressed block (any LZX decoder unpacks it)
    png_write(...)      a PNG of (type, body) chunks with their CRCs (B-248)
    icc_profile(...)    a minimal ICC display profile with one desc tag (B-248)
    regf_hive(...)      a registry hive whose base-block file name is a decoy of its root key's name (B-248)
    ar_write(...)       a GNU ar archive of short-named members (B-248)
    gpt_image(...)      a GPT disk (protective MBR, primary and backup header and array, CRCs right) (B-221)
    mbr_image(...)      a classic MBR disk of up to four primary entries (B-221)
"""
from __future__ import annotations

import base64
import datetime as _dt
import functools
import hashlib
import io
import struct
import uuid as _uuid
import zipfile
import zlib
from dataclasses import dataclass, field

__all__ = ["CorpusError", "Check", "Sample", "BUILDERS", "build", "cfb_write", "property_set", "msi_stream_name",
           "cab_write", "lzx_uncompressed", "filetime", "MSI_CLSID", "png_write", "icc_profile", "regf_hive",
           "ar_write", "gpt_image", "mbr_image"]


class CorpusError(ValueError):
    """An unknown sample id or a builder input the format cannot hold."""


@dataclass(frozen=True)
class Check:
    """One property that holds on a sample by construction. `expected` is the value written (str, int, a
    list for a collection, a datetime for a time); `artifact` is the question's artifact chain when the
    property is about a member (a mail attachment); `needs_tools` names the decoders the reader needs."""
    prop: str
    expected: object
    artifact: str | None = None
    needs_tools: tuple = ()


@dataclass(frozen=True)
class Sample:
    id: str
    name: str
    data: bytes
    checks: tuple = field(default_factory=tuple)


# ------------------------------------------------------------------ compound file (OLE / CFB)

FREE, END, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
MINI_CUTOFF = 4096


def _cfb_order(name: str):
    """The order a compound file's directory keeps siblings in: shorter names first, then by upper case."""
    return (len(name), name.upper())


def cfb_write(streams: dict, clsid: bytes = b"\x00" * 16) -> bytes:
    """A version 3 compound file (512-byte sectors) of {path: bytes}; a path's '/' separates storages.
    Streams under 4096 bytes live in the mini stream. Siblings are chained in the directory's own order,
    a valid (if unbalanced) tree. At most 109 FAT sectors (no DIFAT chain): about 6.9 MB."""
    if len(clsid) != 16:
        raise CorpusError("a CLSID is 16 bytes")
    nodes = [{"name": "Root Entry", "type": 5, "kids": [], "data": b""}]
    index = {"": 0}

    def storage(parts):
        path = "/".join(parts)
        if path not in index:
            parent = storage(parts[:-1]) if len(parts) > 1 else 0
            nodes.append({"name": parts[-1], "type": 1, "kids": [], "data": b""})
            index[path] = len(nodes) - 1
            nodes[parent]["kids"].append(index[path])
        return index[path]

    for path, data in streams.items():
        parts = path.split("/")
        if any(not p or len(p) > 31 for p in parts):
            raise CorpusError(f"a compound file name is 1 to 31 characters: {path!r}")
        parent = storage(parts[:-1]) if len(parts) > 1 else 0
        nodes.append({"name": parts[-1], "type": 2, "kids": [], "data": bytes(data)})
        nodes[parent]["kids"].append(len(nodes) - 1)
    for n in nodes:
        n["kids"].sort(key=lambda i: _cfb_order(nodes[i]["name"]))
    mini, minifat, big = bytearray(), [], []
    for n in nodes:
        if n["type"] != 2:
            continue
        d = n["data"]
        if len(d) < MINI_CUTOFF:
            count = (len(d) + 63) // 64
            n["start"] = len(mini) // 64 if count else END
            for i in range(count):
                minifat.append(len(minifat) + 1 if i < count - 1 else END)
            mini += d + b"\x00" * (count * 64 - len(d))
        else:
            big.append(n)
    ndir = (len(nodes) * 128 + 511) // 512
    nminifat = (len(minifat) * 4 + 511) // 512
    sectors, fat = [], []

    def add(blob):
        start, count = len(sectors), (len(blob) + 511) // 512
        for i in range(count):
            sectors.append(blob[i * 512:(i + 1) * 512].ljust(512, b"\x00"))
            fat.append(start + i + 1 if i < count - 1 else END)
        return start if count else END

    dir_start = len(sectors)
    for i in range(ndir):
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
    if nfat > 109:
        raise CorpusError("a compound file this large needs a DIFAT chain, which this writer does not write")
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
        e[66], e[67] = n["type"], 1                       # black
        struct.pack_into("<III", e, 68, FREE, FREE, n["kids"][0] if n["kids"] else FREE)
        if i == 0:
            e[80:96] = clsid
        struct.pack_into("<I", e, 116, n.get("start", 0) if n["type"] != 1 else 0)
        struct.pack_into("<Q", e, 120, n.get("size", len(n["data"])) if n["type"] != 1 else 0)
        raw += e
    for n in nodes:                                       # each sibling's right is the next in order
        for a, b in zip(n["kids"], n["kids"][1:]):
            struct.pack_into("<I", raw, a * 128 + 72, b)
    raw = bytearray(bytes(raw).ljust(ndir * 512, b"\x00"))
    for i in range(len(nodes), ndir * 4):                 # unused entries: no siblings, no child
        struct.pack_into("<III", raw, i * 128 + 68, FREE, FREE, FREE)
    for i in range(ndir):
        sectors[dir_start + i] = bytes(raw[i * 512:(i + 1) * 512])
    head = bytearray(512)
    head[:8] = CFB_MAGIC
    struct.pack_into("<HHHHH", head, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<III", head, 0x2C, nfat, dir_start, 0)
    struct.pack_into("<IIIII", head, 0x38, MINI_CUTOFF, minifat_start, nminifat, END, 0)
    struct.pack_into("<109I", head, 0x4C, *([fat_start + i for i in range(nfat)] + [FREE] * (109 - nfat)))
    return bytes(head) + b"".join(sectors)


FMTID_SUMMARY = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")   # {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
VT_I2, VT_I4, VT_LPSTR, VT_FILETIME = 2, 3, 30, 64
PID = {"codepage": 1, "title": 2, "subject": 3, "author": 4, "keywords": 5, "comments": 6, "template": 7,
       "last_saved_by": 8, "revision_number": 9, "create_time": 12, "last_saved_time": 13, "page_count": 14,
       "word_count": 15, "creating_application": 18, "security": 19}
EPOCH_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)


def filetime(when: _dt.datetime) -> int:
    """A Windows FILETIME (100 ns since 1601) of an aware datetime."""
    return int((when - EPOCH_1601).total_seconds()) * 10_000_000


def property_set(props: dict, codepage: int = 1252) -> bytes:
    """A SummaryInformation stream: {field name of PID: value}; str is VT_LPSTR in the code page, int
    is VT_I4, an aware datetime is VT_FILETIME."""
    entries = [(PID["codepage"], struct.pack("<IhH", VT_I2, codepage, 0))]
    for name, value in props.items():
        if name not in PID:
            raise CorpusError(f"no SummaryInformation property {name!r}")
        if isinstance(value, str):
            raw = value.encode(f"cp{codepage}") + b"\x00"
            body = struct.pack("<II", VT_LPSTR, len(raw)) + raw + b"\x00" * (-len(raw) % 4)
        elif isinstance(value, _dt.datetime):
            body = struct.pack("<IQ", VT_FILETIME, filetime(value))
        elif isinstance(value, int):
            body = struct.pack("<Ii", VT_I4, value)
        else:
            raise CorpusError(f"no property type for {type(value).__name__}")
        entries.append((PID[name], body))
    head = 8 + 8 * len(entries)
    offsets, bodies = [], b""
    for pid, body in entries:
        offsets.append((pid, head + len(bodies)))
        bodies += body
    section = struct.pack("<II", head + len(bodies), len(entries)) + b"".join(struct.pack("<II", *o) for o in offsets) + bodies
    return (struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\x00" * 16 + struct.pack("<I", 1)
            + FMTID_SUMMARY + struct.pack("<I", 48) + section)


# ------------------------------------------------------------------ MSI database

MSI_CLSID = bytes.fromhex("8410 0c00 0000 0000 c000 000000000046".replace(" ", ""))   # {000C1084-0000-0000-C000-000000000046}
MSI_B64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
T_STRING, T_VALID, T_NULLABLE, T_KEY = 0x0800, 0x0100, 0x1000, 0x2000
COL_KEY_STR = T_KEY | T_STRING | 0x0500 | 72      # a key text column, s72
COL_STR = T_STRING | 0x0500 | 255                 # a text column
COL_STR_NULL = COL_STR | T_NULLABLE
COL_I2 = 0x0500 | 2
COL_I4 = 0x0100 | 4
COL_I4_NULL = COL_I4 | T_NULLABLE


def msi_stream_name(name: str, table: bool = False) -> str:
    """A stream name as an MSI database stores it: pairs of the 64 name characters in one code unit
    from U+3800, a lone one from U+4800, a table's name behind U+4840; any other character as it is."""
    out, i = ["\u4840"] if table else [], 0
    while i < len(name):
        a = MSI_B64.find(name[i])
        if a < 0:
            out.append(name[i])
            i += 1
            continue
        b = MSI_B64.find(name[i + 1]) if i + 1 < len(name) else -1
        if b >= 0:
            out.append(chr(0x3800 + a + (b << 6)))
            i += 2
        else:
            out.append(chr(0x4800 + a))
            i += 1
    return "".join(out)


def msi_database(tables: dict, extra_streams: dict | None = None, summary: dict | None = None,
                 codepage: int = 1252) -> bytes:
    """An MSI database: {table: ([(column, type)], [row tuple, ...])}, every other stream as
    {name: bytes} (stored under its MSI name), and the SummaryInformation fields. Text cells are string
    ids of one pool (2 bytes wide), an i2 cell is stored + 0x8000, an i4 cell + 0x80000000, None is 0."""
    strings, ids = [], {}

    def sid(text):
        if text is None:
            return 0
        if text not in ids:
            strings.append(text)
            ids[text] = len(strings)
        return ids[text]

    for name in tables:                     # the names first, so ids are stable
        sid(name)
    for name, (cols, _) in tables.items():
        for col, _ in cols:
            sid(col)
    streams = {}
    for name, (cols, rows) in tables.items():
        body = b""
        for c, (col, kind) in enumerate(cols):
            for row in rows:
                v = row[c]
                if kind & T_STRING:
                    body += struct.pack("<H", sid(v))
                elif kind & 0xFF == 4:
                    body += struct.pack("<I", 0 if v is None else (v + 0x80000000) & 0xFFFFFFFF)
                else:
                    body += struct.pack("<H", 0 if v is None else (v + 0x8000) & 0xFFFF)
        if rows:
            streams[msi_stream_name(name, table=True)] = body
    streams[msi_stream_name("_Tables", table=True)] = b"".join(struct.pack("<H", sid(n)) for n in tables)
    col_rows = [(t, i + 1, col, kind) for t, (cols, _) in tables.items() for i, (col, kind) in enumerate(cols)]
    streams[msi_stream_name("_Columns", table=True)] = (
        b"".join(struct.pack("<H", sid(r[0])) for r in col_rows) + b"".join(struct.pack("<H", r[1] + 0x8000) for r in col_rows)
        + b"".join(struct.pack("<H", sid(r[2])) for r in col_rows) + b"".join(struct.pack("<H", r[3] + 0x8000) for r in col_rows))
    raw = [s.encode(f"cp{codepage}") for s in strings]
    if any(len(r) >= 1 << 16 for r in raw):
        raise CorpusError("a pool string of 64 KiB or more needs the two-entry form, which this writer does not write")
    refs = {}
    for s in strings:
        refs[s] = 1
    streams[msi_stream_name("_StringPool", table=True)] = struct.pack("<HH", codepage, 0) + b"".join(
        struct.pack("<HH", len(r), refs[s]) for s, r in zip(strings, raw))
    streams[msi_stream_name("_StringData", table=True)] = b"".join(raw)
    for name, data in (extra_streams or {}).items():
        streams[msi_stream_name(name)] = data
    if summary:
        streams["\x05SummaryInformation"] = property_set(summary, codepage)
    return cfb_write(streams, MSI_CLSID)


# ------------------------------------------------------------------ cabinet (MSCF)

CAB_METHOD = {"stored": 0, "mszip": 1, "quantum": 2, "lzx": 3}


def lzx_uncompressed(data: bytes) -> bytes:
    """An LZX stream of one uncompressed block (block type 3), as a CAB LZX folder carries it: the E8
    header bit (0: no call translation), the block type (3 bits) and size (24 bits), read MSB first from
    16-bit little-endian words; then, at the next word boundary, R0 R1 R2 (u32 each) and the bytes, and
    a pad byte when the size is odd. One block holds at most one 32 KiB frame here."""
    if not 0 < len(data) <= 32768:
        raise CorpusError("this LZX writer holds 1 to 32768 bytes (one frame)")
    bits = (0 << 27) | (3 << 24) | len(data)            # 28 bits: e8=0, type=3, size
    value = bits << 4                                    # padded to two 16-bit words
    words = struct.pack("<HH", (value >> 16) & 0xFFFF, value & 0xFFFF)
    return words + struct.pack("<III", 1, 1, 1) + data + (b"\x00" if len(data) % 2 else b"")


def cab_write(files: list, method: str = "stored", window_bits: int = 16, set_id: int = 0x1234,
              stamp: _dt.datetime | None = None, blocks: list | None = None) -> bytes:
    """A one-folder cabinet of [(name, bytes)]. `method` stored or mszip (blocks of 32 KiB), lzx (one
    uncompressed LZX block: 32 KiB of data at most), or quantum/lzx with `blocks`: [(packed, unpacked
    size)] already encoded by the caller (an encoder of its own). CFDATA checksums are 0 (none)."""
    if method not in CAB_METHOD:
        raise CorpusError(f"no cabinet compression {method!r}")
    data = b"".join(d for _, d in files)
    if blocks is None:
        if method == "stored":
            blocks = [(data[i:i + 32768], len(data[i:i + 32768])) for i in range(0, len(data), 32768)] or [(b"", 0)]
        elif method == "mszip":
            blocks = []
            for i in range(0, len(data), 32768):
                chunk = data[i:i + 32768]
                c = zlib.compressobj(9, zlib.DEFLATED, -15)
                blocks.append((b"CK" + c.compress(chunk) + c.flush(), len(chunk)))
        elif method == "lzx":
            blocks = [(lzx_uncompressed(data), len(data))]
        else:
            raise CorpusError(f"a {method} cabinet needs its blocks encoded by the caller")
    stamp = stamp or _dt.datetime(2025, 3, 4, 5, 6, 8)
    date = ((stamp.year - 1980) << 9) | (stamp.month << 5) | stamp.day
    time = (stamp.hour << 11) | (stamp.minute << 5) | (stamp.second // 2)
    kind = CAB_METHOD[method] | ((window_bits << 8) if method in ("lzx", "quantum") else 0)
    if method == "quantum":
        kind = 2 | (4 << 4) | (window_bits << 8)        # level 4, window bits
    entries, offset = b"", 0
    for name, d in files:
        entries += struct.pack("<IIHHHH", len(d), offset, 0, date, time, 0x20) + name.encode("ascii") + b"\x00"
        offset += len(d)
    files_at = 36 + 8
    data_at = files_at + len(entries)
    body = b"".join(struct.pack("<IHH", 0, len(p), u) + p for p, u in blocks)
    size = data_at + len(body)
    head = struct.pack("<4sIIIIIBBHHHHH", b"MSCF", 0, size, 0, files_at, 0, 3, 1, 1, len(files), 0, set_id, 0)
    folder = struct.pack("<IHH", data_at, len(blocks), kind)
    return head + folder + entries + body


# ------------------------------------------------------------------ samples

WHEN = _dt.datetime(2025, 3, 4, 5, 6, 7, tzinfo=_dt.timezone.utc)
LATER = _dt.datetime(2025, 3, 5, 6, 7, 8, tzinfo=_dt.timezone.utc)
PRODUCT_CODE = "{3F2A6C1E-7B4D-4E8A-9C21-5D6E7F809A1B}"
UPGRADE_CODE = "{A1B2C3D4-E5F6-4789-8ABC-DEF012345678}"
PACKAGE_CODE = "{0C9D8E7F-6A5B-4C3D-8E2F-1A0B9C8D7E6F}"
CAB_MEMBERS = [("readme.txt", b"synthetic installer payload: readme\r\n" * 3),
               ("tool.cfg", b"[settings]\r\nmode=corpus\r\nlevel=7\r\n")]


def _msi(sample_id: str, cab: bytes, method: str, needs=()) -> Sample:
    prop_cols = [("Property", COL_KEY_STR), ("Value", COL_STR)]
    props = [("ProductCode", PRODUCT_CODE), ("UpgradeCode", UPGRADE_CODE), ("ProductVersion", "4.2.17"),
             ("ProductName", "Corpus Example Tool"), ("Manufacturer", "Synthetic Corpus Ltd"), ("ProductLanguage", "1033")]
    media_cols = [("DiskId", COL_I2 | T_KEY), ("LastSequence", COL_I4), ("DiskPrompt", COL_STR_NULL),
                  ("Cabinet", COL_STR_NULL), ("VolumeLabel", COL_STR_NULL), ("Source", COL_STR_NULL)]
    file_cols = [("File", COL_KEY_STR), ("Component_", COL_STR), ("FileName", COL_STR), ("FileSize", COL_I4),
                 ("Version", COL_STR_NULL), ("Language", COL_STR_NULL), ("Attributes", COL_I2 | T_NULLABLE), ("Sequence", COL_I2)]
    files = [(f"f{i}", "MainComponent", name, len(body), None, None, None, i + 1) for i, (name, body) in enumerate(CAB_MEMBERS)]
    data = msi_database(
        {"Property": (prop_cols, props),
         "Media": (media_cols, [(1, len(CAB_MEMBERS), None, "#payload.cab", None, None)]),
         "File": (file_cols, files)},
        extra_streams={"payload.cab": cab},
        summary={"title": "Installation Database", "subject": "Corpus Example Tool", "author": "Synthetic Corpus Ltd",
                 "template": "x64;1033", "revision_number": PACKAGE_CODE, "page_count": 200, "word_count": 2,
                 "create_time": WHEN, "creating_application": "corpus-writer 1.0"})
    checks = (Check("msi.product_code_guid", PRODUCT_CODE), Check("msi.upgrade_code_guid", UPGRADE_CODE),
              Check("msi.product_version", "4.2.17"), Check("msi.manufacturer", "Synthetic Corpus Ltd"),
              Check("msi.product_name", "Corpus Example Tool"), Check("msi.property_count", len(props)),
              Check("msi.package_code_guid", PACKAGE_CODE), Check("msi.media_cabinet", "#payload.cab"),
              Check("msi.file_names", [f[2] for f in files]),
              Check("msi.cabinet_member_names", [n for n, _ in CAB_MEMBERS]),
              Check("msi.cabinet_compression", method),
              Check("msi.cabinet_file_sha256_list", [hashlib.sha256(b).hexdigest() for _, b in CAB_MEMBERS], needs_tools=needs),
              Check("msi.cabinet_member_sizes", [len(b) for _, b in CAB_MEMBERS]),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample(sample_id, "corpus-setup.msi", data, _fill_identity(checks, "corpus-setup.msi", data))


def _fill_identity(checks, name, data):
    """The identity checks (size, sha256) are the bytes' own: filled in once the bytes are known."""
    out = []
    for c in checks:
        if c.prop == "file.size_bytes" and c.expected is None:
            c = Check(c.prop, len(data))
        elif c.prop == "sha256" and c.expected is None:
            c = Check(c.prop, hashlib.sha256(data).hexdigest())
        out.append(c)
    return tuple(out)


def msi_package() -> Sample:
    return _msi("msi_package", cab_write(CAB_MEMBERS, "mszip"), "mszip")


def msi_package_lzx() -> Sample:
    # The LZX folder is unpacked by 7zz or bsdtar (readers_msi CAB_DECODERS): either is enough.
    return _msi("msi_package_lzx", cab_write(CAB_MEMBERS, "lzx"), "lzx", needs=("7zz|bsdtar",))


def ole_document() -> Sample:
    """A legacy Office compound file: a WordDocument stream, a 1Table stream and its summary."""
    word = b"\xec\xa5" + b"\x00" * 510 + b"synthetic word body " * 300          # over the mini cutoff: a FAT stream
    data = cfb_write({"WordDocument": word, "1Table": b"\x00" * 600,
                      "\x05SummaryInformation": property_set({
                          "title": "Quarterly Corpus Memo", "subject": "Corpus", "author": "Ada Example",
                          "last_saved_by": "Grace Example", "revision_number": "7", "create_time": WHEN,
                          "last_saved_time": LATER, "creating_application": "Corpus Word 16.0", "page_count": 3})},
                     clsid=bytes.fromhex("0609020000000000c000000000000046"))
    checks = (Check("ole.title", "Quarterly Corpus Memo"), Check("ole.author", "Ada Example"),
              Check("ole.last_saved_by", "Grace Example"), Check("ole.revision_number", "7"),
              # the directory's entries in the order they were written (siblings are linked in name order,
              # the entries themselves are not)
              Check("ole.stream_count", 3), Check("ole.stream_names", ["WordDocument", "1Table", "\x05SummaryInformation"]),
              Check("ole.root_clsid", "00020906-0000-0000-c000-000000000046"),
              Check("ole.major_version", 3), Check("ole.sector_size", 512),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample("ole_document", "memo.doc", data, _fill_identity(checks, "memo.doc", data))


def cab_mszip() -> Sample:
    data = cab_write(CAB_MEMBERS, "mszip", set_id=0x2B1D)
    checks = (Check("cab.file_names", [n for n, _ in CAB_MEMBERS]), Check("cab.file_count", len(CAB_MEMBERS)),
              Check("cab.folder_count", 1), Check("cab.set_id", 0x2B1D), Check("cab.compression_type", "mszip"),
              Check("cab.first_file_name", CAB_MEMBERS[0][0]), Check("cab.first_file_size_bytes", len(CAB_MEMBERS[0][1])),
              Check("cab.cabinet_size_bytes", len(data)), Check("file.size_bytes", None), Check("sha256", None))
    return Sample("cab_mszip", "payload.cab", data, _fill_identity(checks, "payload.cab", data))


def cab_stored() -> Sample:
    data = cab_write(CAB_MEMBERS, "stored", set_id=0x0101)
    checks = (Check("cab.file_names", [n for n, _ in CAB_MEMBERS]), Check("cab.compression_type", "none"),
              Check("cab.set_id", 0x0101), Check("cab.cabinet_size_bytes", len(data)))
    return Sample("cab_stored", "stored.cab", data, checks)


def _zip(members: list) -> bytes:
    """A deflated zip of [(name, bytes)] in this order, every stamp fixed (byte-stable)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in members:
            info = zipfile.ZipInfo(name, date_time=(2025, 3, 4, 5, 6, 8))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, body)
    return buf.getvalue()


MS_PUBLISHER = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
MS_PUBLISHER_ID = "8wekyb3d8bbwe"   # the published suffix of every package signed under that name


def msix_package() -> Sample:
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Corpus.ExampleTool" Publisher="{MS_PUBLISHER}" Version="4.2.17.0" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Corpus Example Tool</DisplayName>
    <PublisherDisplayName>Synthetic Corpus Ltd</PublisherDisplayName>
    <Logo>Assets\\StoreLogo.png</Logo>
  </Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/></Dependencies>
  <Resources><Resource Language="en-us"/></Resources>
  <Applications>
    <Application Id="CorpusTool" Executable="CorpusTool.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Corpus Example Tool" Description="corpus" BackgroundColor="transparent"
        Square150x150Logo="Assets\\Square150x150Logo.png" Square44x44Logo="Assets\\Square44x44Logo.png"/>
    </Application>
  </Applications>
  <Capabilities><Capability Name="internetClient"/><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>
""".encode()
    data = _zip([("AppxManifest.xml", manifest), ("CorpusTool.exe", b"MZ" + b"\x00" * 62),
                 ("AppxBlockMap.xml", b'<?xml version="1.0"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
                                      b'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"/>'),
                 ("[Content_Types].xml", b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')])
    checks = (Check("msix.identity_name", "Corpus.ExampleTool"), Check("msix.identity_version", "4.2.17.0"),
              Check("msix.identity_publisher", MS_PUBLISHER), Check("msix.identity_processor_architecture", "x64"),
              Check("msix.display_name", "Corpus Example Tool"), Check("msix.publisher_id", MS_PUBLISHER_ID),
              Check("msix.full_name", f"Corpus.ExampleTool_4.2.17.0_x64__{MS_PUBLISHER_ID}"),
              Check("msix.family_name", f"Corpus.ExampleTool_{MS_PUBLISHER_ID}"),
              Check("msix.application_id", "CorpusTool"), Check("msix.executable", "CorpusTool.exe"),
              Check("msix.has_signature", "false"), Check("msix.has_block_map", "true"))
    return Sample("msix_package", "CorpusTool.msix", data, checks)


LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
LNK_TARGET = "C:\\Users\\Public\\Tools\\updater.exe"


def _lnk_string(text: str) -> bytes:
    return struct.pack("<H", len(text)) + text.encode("utf-16-le")


def lnk_shortcut() -> Sample:
    """A shell link with LinkInfo (VolumeID + LocalBasePath) and string data: description, relative path,
    working directory, arguments (Unicode)."""
    flags = 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x80        # LinkInfo, Name, RelativePath, WorkingDir, Arguments, Unicode
    header = struct.pack("<I16sIIQQQIiIHHII", 0x4C, LNK_CLSID, flags, 0x20, filetime(WHEN), filetime(LATER),
                         filetime(WHEN + _dt.timedelta(hours=1)), 48128, 0, 1, 0, 0, 0, 0)
    label = b"CORPUSVOL\x00"
    volume = struct.pack("<IIII", 16 + len(label), 3, 0x1A2B3C4D, 16) + label
    base = LNK_TARGET.encode("ascii") + b"\x00"
    info_head = 0x1C
    volume_at, base_at = info_head, info_head + len(volume)
    suffix_at = base_at + len(base)
    body = volume + base + b"\x00"
    info = struct.pack("<IIIIIII", info_head + len(body), info_head, 1, volume_at, base_at, 0, suffix_at) + body
    strings = (_lnk_string("Corpus updater") + _lnk_string("..\\..\\Public\\Tools\\updater.exe")
               + _lnk_string("C:\\Users\\Public\\Tools") + _lnk_string("--silent --channel corpus"))
    data = header + info + strings + struct.pack("<I", 0)
    checks = (Check("lnk.target_path", LNK_TARGET), Check("lnk.local_base_path", LNK_TARGET),
              Check("lnk.description", "Corpus updater"), Check("lnk.relative_path", "..\\..\\Public\\Tools\\updater.exe"),
              Check("lnk.working_directory", "C:\\Users\\Public\\Tools"), Check("lnk.arguments", "--silent --channel corpus"),
              Check("lnk.target_file_size", 48128), Check("lnk.volume_label", "CORPUSVOL"),
              Check("lnk.creation_time", WHEN), Check("lnk.access_time", LATER),
              Check("lnk.write_time", WHEN + _dt.timedelta(hours=1)),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample("lnk_shortcut", "updater.lnk", data, _fill_identity(checks, "updater.lnk", data))


CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"


def _core_xml(title, creator, last, revision):
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>{title}</dc:title><dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{last}</cp:lastModifiedBy><cp:revision>{revision}</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2025-03-04T05:06:07Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2025-03-05T06:07:08Z</dcterms:modified></cp:coreProperties>""".encode()


def _app_xml(application, company, extra=""):
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>{application}</Application><Company>{company}</Company><AppVersion>16.0300</AppVersion>{extra}</Properties>""".encode()


def _ooxml(main_part: str, main_type: str, main_body: bytes, more: list, title, creator, last, revision, app, company,
           app_extra="", overrides=()) -> bytes:
    types = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="{CT_NS}">'
             '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
             '<Default Extension="xml" ContentType="application/xml"/>'
             f'<Override PartName="/{main_part}" ContentType="{main_type}"/>'
             + "".join(f'<Override PartName="/{p}" ContentType="{t}"/>' for p, t in overrides)
             + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
             '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
             '</Types>').encode()
    rels = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{REL_NS}">'
            f'<Relationship Id="rId1" Type="{OFFICE_DOC}" Target="{main_part}"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            '</Relationships>').encode()
    return _zip([("[Content_Types].xml", types), ("_rels/.rels", rels), (main_part, main_body), *more,
                 ("docProps/core.xml", _core_xml(title, creator, last, revision)),
                 ("docProps/app.xml", _app_xml(app, company, app_extra))])


def _ooxml_checks(ns, title, creator, last, revision, company):
    return (Check(f"{ns}.title", title), Check(f"{ns}.creator", creator), Check(f"{ns}.last_modified_by", last),
            Check(f"{ns}.revision", revision), Check(f"{ns}.company", company),
            Check(f"{ns}.created", _dt.datetime(2025, 3, 4, 5, 6, 7, tzinfo=_dt.timezone.utc)),
            Check(f"{ns}.modified", _dt.datetime(2025, 3, 5, 6, 7, 8, tzinfo=_dt.timezone.utc)))


def ooxml_docx() -> Sample:
    body = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Corpus memo body</w:t></w:r></w:p></w:body></w:document>').encode()
    data = _ooxml("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                  body, [], "Corpus Board Minutes", "Ada Example", "Grace Example", "12", "Microsoft Office Word",
                  "Synthetic Corpus Ltd", "<Pages>2</Pages>")
    return Sample("ooxml_docx", "minutes.docx", data,
                  _ooxml_checks("docx", "Corpus Board Minutes", "Ada Example", "Grace Example", "12", "Synthetic Corpus Ltd"))


def ooxml_xlsx() -> Sample:
    sheets = ["Summary", "Q1 Figures", "Notes"]
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/'
          'spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
          + "".join(f'<sheet name="{s}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, s in enumerate(sheets))
          + "</sheets></workbook>").encode()
    sheet = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/'
             'spreadsheetml/2006/main"><sheetData/></worksheet>').encode()
    wb_rels = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{REL_NS}">'
               + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                         f'relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>' for i in range(len(sheets)))
               + "</Relationships>").encode()
    more = [("xl/_rels/workbook.xml.rels", wb_rels)] + [(f"xl/worksheets/sheet{i + 1}.xml", sheet) for i in range(len(sheets))]
    sheet_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
    data = _ooxml("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", wb, more,
                  "Corpus Ledger", "Ada Example", "Linus Example", "3", "Microsoft Excel", "Synthetic Corpus Ltd",
                  overrides=[(f"xl/worksheets/sheet{i + 1}.xml", sheet_type) for i in range(len(sheets))])
    checks = _ooxml_checks("xlsx", "Corpus Ledger", "Ada Example", "Linus Example", "3", "Synthetic Corpus Ltd") + (
        Check("xlsx.sheet_names", sheets), Check("xlsx.sheet_count", len(sheets)))
    return Sample("ooxml_xlsx", "ledger.xlsx", data, checks)


def ooxml_pptx() -> Sample:
    n = 4
    pres = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/'
            'presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldIdLst>'
            + "".join(f'<p:sldId id="{256 + i}" r:id="rId{i + 1}"/>' for i in range(n))
            + '</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/></p:presentation>').encode()
    slide = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld xmlns:p="http://schemas.openxmlformats.org/'
             'presentationml/2006/main"><p:cSld/></p:sld>').encode()
    rels = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{REL_NS}">'
            + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
                      f'slide" Target="slides/slide{i + 1}.xml"/>' for i in range(n)) + "</Relationships>").encode()
    more = [("ppt/_rels/presentation.xml.rels", rels)] + [(f"ppt/slides/slide{i + 1}.xml", slide) for i in range(n)]
    slide_type = "application/vnd.openxmlformats-officedocument.presentationml.slide+xml"
    data = _ooxml("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
                  pres, more, "Corpus Briefing", "Ada Example", "Grace Example", "5", "Microsoft Office PowerPoint",
                  "Synthetic Corpus Ltd", f"<Slides>{n}</Slides>",
                  overrides=[(f"ppt/slides/slide{i + 1}.xml", slide_type) for i in range(n)])
    checks = _ooxml_checks("pptx", "Corpus Briefing", "Ada Example", "Grace Example", "5", "Synthetic Corpus Ltd") + (
        Check("pptx.slide_count", n),)
    return Sample("ooxml_pptx", "briefing.pptx", data, checks)


def _chunk(cid: bytes, body: bytes) -> bytes:
    return cid + struct.pack("<I", len(body)) + body + (b"\x00" if len(body) % 2 else b"")


def _riff(form: bytes, chunks: bytes) -> bytes:
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + form + chunks


def riff_wav() -> Sample:
    rate, channels, bits, frames = 22050, 2, 16, 2205
    fmt = struct.pack("<HHIIHH", 1, channels, rate, rate * channels * bits // 8, channels * bits // 8, bits)
    pcm = bytes((i * 7) & 0xFF for i in range(frames * channels * bits // 8))
    info = b"INFO" + _chunk(b"INAM", b"Corpus Voice Note\x00") + _chunk(b"IART", b"Ada Example\x00")
    data = _riff(b"WAVE", _chunk(b"fmt ", fmt) + _chunk(b"LIST", info) + _chunk(b"data", pcm))
    checks = (Check("wav.sample_rate", rate), Check("wav.channels", channels), Check("wav.bits_per_sample", bits),
              Check("wav.audio_format", 1), Check("wav.byte_rate", rate * channels * bits // 8),
              Check("wav.block_align", channels * bits // 8), Check("wav.data_size_bytes", len(pcm)),
              Check("wav.riff_size_bytes", len(data) - 8), Check("wav.chunk_types", ["fmt ", "LIST", "data"]),
              Check("media.primary_audio_codec_name", "pcm_s16le"),
              Check("riff.form_type", "WAVE"), Check("riff.size_bytes", len(data) - 8),
              Check("riff.chunk_ids", ["fmt ", "LIST", "data"]), Check("riff.chunk_count", 3),
              Check("riff.list_types", ["INFO"]), Check("riff.info_tags", ["INAM", "IART"]),
              Check("riff.info_inam", "Corpus Voice Note"), Check("riff.info_iart", "Ada Example"),
              Check("riff.chunk_data_size_bytes", len(pcm)), Check("riff.trailing_bytes", 0),
              Check("riff.file_size_matches", True),
              Check("riff.sample_rate", rate), Check("riff.channels", channels),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample("riff_wav", "voice-note.wav", data, _fill_identity(checks, "voice-note.wav", data))


def riff_other() -> Sample:
    """A RIFF file of a form no reader namespace knows (RMID, a MIDI file in RIFF), with junk after the
    stated end: only the container's own facts can be read."""
    midi = b"MThd" + struct.pack(">IHHH", 6, 0, 1, 96) + b"MTrk" + struct.pack(">I", 4) + b"\x00\xff\x2f\x00"
    body = _riff(b"RMID", _chunk(b"data", midi) + _chunk(b"LIST", b"INFO" + _chunk(b"ICOP", b"(c) Corpus\x00")))
    data = body + b"TRAILER!"
    checks = (Check("riff.form_type", "RMID"), Check("riff.chunk_ids", ["data", "LIST"]), Check("riff.trailing_bytes", 8),
              Check("riff.file_size_matches", False), Check("riff.info_icop", "(c) Corpus"),
              Check("riff.size_bytes", len(body) - 8))
    return Sample("riff_other", "theme.rmi", data, checks)


def riff_avi() -> Sample:
    width, height, frames, usec = 320, 240, 48, 41708
    avih = struct.pack("<IIIIIIIIII", usec, 0, 0, 0x10, frames, 0, 1, 0, width, height) + b"\x00" * 16
    strh = struct.pack("<4s4sIHHIIIIIIIIhhhh", b"vids", b"MJPG", 0, 0, 0, 0, 1001, 24000, 0, frames, 0, 0xFFFFFFFF, 0,
                       0, 0, width, height)
    strf = struct.pack("<IiiHH4sIiiII", 40, width, height, 1, 24, b"MJPG", width * height * 3, 0, 0, 0, 0)
    hdrl = b"hdrl" + _chunk(b"avih", avih) + _chunk(b"LIST", b"strl" + _chunk(b"strh", strh) + _chunk(b"strf", strf))
    movi = b"movi" + b"".join(_chunk(b"00dc", b"\xff\xd8\xff\xd9") for _ in range(frames))
    data = _riff(b"AVI ", _chunk(b"LIST", hdrl) + _chunk(b"LIST", movi))
    checks = (Check("avi.width", width), Check("avi.height", height), Check("avi.total_frames", frames),
              Check("avi.microseconds_per_frame", usec), Check("avi.streams", 1),
              Check("avi.dimensions_pixels", f"{width}x{height}"),
              Check("riff.form_type", "AVI "), Check("riff.list_types", ["hdrl", "movi"]), Check("riff.width", width))
    return Sample("riff_avi", "clip.avi", data, checks)


def riff_webp() -> Sample:
    """A lossless (VP8L) WebP: only the 5-byte header carries the size; the bitstream after it is not decoded."""
    width, height = 97, 61
    bits = (width - 1) | ((height - 1) << 14) | (1 << 28)          # alpha_is_used = 1, version 0
    vp8l = b"\x2f" + struct.pack("<I", bits) + b"\x00" * 7
    data = _riff(b"WEBP", _chunk(b"VP8L", vp8l))
    checks = (Check("webp.dimensions_pixels", f"{width}x{height}"), Check("webp.vp8l_width", width),
              Check("webp.vp8l_height", height), Check("webp.has_alpha", "true"), Check("webp.chunk_types", ["VP8L"]),
              Check("file.size_bytes", None))
    return Sample("riff_webp", "still.webp", data, _fill_identity(checks, "still.webp", data))


# ------------------------------------------------------------------ media containers (B-223)
# Two media containers the RIFF family does not cover, each with a video and an audio stream, so the
# `media` namespace (solvers/metadata-forensics/readers_media.py) is proved on more than Day 17's WAV.
# Every expected value is what the builder wrote, in ffprobe's spelling where the media pack offers
# ffprobe's form first (a duration with six decimals, a frame rate as num/den, ffprobe's codec names).

def _box(kind: bytes, *body: bytes) -> bytes:
    payload = b"".join(body)
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def _full_box(kind: bytes, version: int, flags: int, *body: bytes) -> bytes:
    return _box(kind, bytes([version]) + flags.to_bytes(3, "big"), *body)


UNITY_MATRIX = struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)


def _mp4_trak(track_id: int, handler: bytes, scale: int, duration: int, movie_duration: int, entry: bytes,
              table: bytes, dims=(0, 0)) -> bytes:
    tkhd = _full_box(b"tkhd", 0, 3, struct.pack(">IIIII", 0, 0, track_id, 0, movie_duration), b"\x00" * 8,
                     struct.pack(">hhhH", 0, 0, 0x100 if handler == b"soun" else 0, 0), UNITY_MATRIX,
                     struct.pack(">II", dims[0] << 16, dims[1] << 16))
    mdhd = _full_box(b"mdhd", 0, 0, struct.pack(">IIIIHH", 0, 0, scale, duration, 0x55C4, 0))   # language 'und'
    hdlr = _full_box(b"hdlr", 0, 0, b"\x00" * 4, handler, b"\x00" * 12, b"Corpus Handler\x00")
    stsd = _full_box(b"stsd", 0, 0, struct.pack(">I", 1), entry)
    minf = _box(b"minf", _box(b"stbl", stsd, table))
    return _box(b"trak", tkhd, _box(b"mdia", mdhd, hdlr, minf))


def _esds_aac(object_type: int, rate_index: int, channels: int) -> bytes:
    """An esds box of MPEG-4 audio (objectTypeIndication 0x40) whose AudioSpecificConfig names the AAC
    object type, sampling-frequency index and channel configuration."""
    asc = ((object_type << 11) | (rate_index << 7) | (channels << 3)).to_bytes(2, "big")
    dsi = b"\x05" + bytes([len(asc)]) + asc
    dcd_body = bytes([0x40, 0x15]) + b"\x00\x00\x00" + struct.pack(">II", 128000, 128000) + dsi
    dcd = b"\x04" + bytes([len(dcd_body)]) + dcd_body
    es_body = struct.pack(">HB", 1, 0) + dcd + b"\x06\x01\x02"
    return _full_box(b"esds", 0, 0, b"\x03" + bytes([len(es_body)]) + es_body)


MP4_WIDTH, MP4_HEIGHT, MP4_FRAMES, MP4_VIDEO_SCALE, MP4_FRAME_TICKS = 320, 240, 50, 12800, 512   # 25 fps, 2 s
MP4_RATE, MP4_CHANNELS, MP4_MOVIE_SCALE, MP4_MOVIE_DURATION = 44100, 2, 1000, 2000


def media_mp4() -> Sample:
    """An ISO base media file (brand isom, moov before mdat): one H.264 video track (avc1, 320x240, 50
    frames at 25 fps) and one AAC-LC audio track (mp4a + esds, 44.1 kHz stereo), each 2 s long."""
    avc1 = _box(b"avc1", b"\x00" * 6, struct.pack(">H", 1), b"\x00" * 16,
                struct.pack(">HHIIIH", MP4_WIDTH, MP4_HEIGHT, 0x480000, 0x480000, 0, 1), b"\x00" * 32,
                struct.pack(">Hh", 24, -1))
    video_table = (_full_box(b"stts", 0, 0, struct.pack(">III", 1, MP4_FRAMES, MP4_FRAME_TICKS))
                   + _full_box(b"stsz", 0, 0, struct.pack(">II", 1000, MP4_FRAMES)))
    video = _mp4_trak(1, b"vide", MP4_VIDEO_SCALE, MP4_FRAMES * MP4_FRAME_TICKS, MP4_MOVIE_DURATION, avc1, video_table,
                      (MP4_WIDTH, MP4_HEIGHT))
    mp4a = _box(b"mp4a", b"\x00" * 6, struct.pack(">H", 1), struct.pack(">H", 0), b"\x00" * 6,
                struct.pack(">HHhHI", MP4_CHANNELS, 16, 0, 0, MP4_RATE << 16), _esds_aac(2, 4, MP4_CHANNELS))
    audio_table = (_full_box(b"stts", 0, 0, struct.pack(">III", 1, 87, 1024))
                   + _full_box(b"stsz", 0, 0, struct.pack(">II", 371, 87)))
    audio = _mp4_trak(2, b"soun", MP4_RATE, 2 * MP4_RATE, MP4_MOVIE_DURATION, mp4a, audio_table)
    mvhd = _full_box(b"mvhd", 0, 0, struct.pack(">IIIIIH", 0, 0, MP4_MOVIE_SCALE, MP4_MOVIE_DURATION, 0x10000, 0x100),
                     b"\x00" * 10, UNITY_MATRIX, b"\x00" * 24, struct.pack(">I", 3))
    ftyp = _box(b"ftyp", b"isom", struct.pack(">I", 512), b"isomiso2avc1mp41")
    data = ftyp + _box(b"moov", mvhd, video, audio) + _box(b"mdat", bytes((i * 31) & 0xFF for i in range(4096)))
    checks = (Check("media.format_name", "mov,mp4,m4a,3gp,3g2,mj2"), Check("media.duration_seconds", "2.000000"),
              Check("media.stream_count", 2), Check("media.video_stream_count", 1), Check("media.audio_stream_count", 1),
              Check("media.primary_video_codec_name", "h264"), Check("media.primary_audio_codec_name", "aac"),
              Check("media.primary_video_width_pixels", MP4_WIDTH), Check("media.primary_video_height_pixels", MP4_HEIGHT),
              Check("media.primary_video_dimensions_pixels", f"{MP4_WIDTH}x{MP4_HEIGHT}"),
              Check("media.primary_video_frame_rate", "25/1"), Check("media.primary_video_frame_count", MP4_FRAMES),
              Check("media.primary_audio_sample_rate_hz", MP4_RATE), Check("media.primary_audio_channel_count", MP4_CHANNELS),
              Check("media.primary_audio_duration_seconds", "2.000000"), Check("media.audio_codec_names", ["aac"]),
              Check("mp4.major_brand", "isom"), Check("file.size_bytes", None))
    return Sample("media_mp4", "corpus-clip.mp4", data, _fill_identity(checks, "corpus-clip.mp4", data))


def _vint_size(n: int) -> bytes:
    """An EBML data size: the shortest length that does not spell the reserved all-ones value."""
    for width in range(1, 9):
        if n < (1 << (7 * width)) - 1:
            return ((1 << (7 * width)) | n).to_bytes(width, "big")   # the length marker bit, then the value
    raise CorpusError(f"an EBML element of {n} bytes is too large")


def _ebml(eid: int, *body: bytes) -> bytes:
    payload = b"".join(body)
    return eid.to_bytes((eid.bit_length() + 7) // 8, "big") + _vint_size(len(payload)) + payload


def _ebml_uint(eid: int, v: int) -> bytes:
    return _ebml(eid, v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big"))


MKV_WIDTH, MKV_HEIGHT, MKV_FRAME_NS, MKV_RATE, MKV_CHANNELS = 640, 360, 40_000_000, 48000, 2   # 25 fps
MKV_TITLE, MKV_DURATION_MS = "Corpus Clip", 1500.0


def media_mkv() -> Sample:
    """A WebM file (Matroska with DocType webm): one VP9 video track (640x360, DefaultDuration 40 ms) and
    one Opus audio track (48 kHz stereo), a 1.5 s segment with a title and one empty cluster."""
    header = _ebml(0x1A45DFA3, _ebml_uint(0x4286, 1), _ebml_uint(0x42F7, 1), _ebml_uint(0x42F2, 4),
                   _ebml_uint(0x42F3, 8), _ebml(0x4282, b"webm"), _ebml_uint(0x4287, 4), _ebml_uint(0x4285, 2))
    info = _ebml(0x1549A966, _ebml_uint(0x2AD7B1, 1_000_000), _ebml(0x4489, struct.pack(">d", MKV_DURATION_MS)),
                 _ebml(0x4D80, b"corpus-mux"), _ebml(0x5741, b"corpus-writer"), _ebml(0x7BA9, MKV_TITLE.encode()))
    video = _ebml(0xAE, _ebml_uint(0xD7, 1), _ebml_uint(0x73C5, 0x1111), _ebml_uint(0x83, 1), _ebml(0x86, b"V_VP9"),
                  _ebml_uint(0x23E383, MKV_FRAME_NS),
                  _ebml(0xE0, _ebml_uint(0xB0, MKV_WIDTH), _ebml_uint(0xBA, MKV_HEIGHT)))
    audio = _ebml(0xAE, _ebml_uint(0xD7, 2), _ebml_uint(0x73C5, 0x2222), _ebml_uint(0x83, 2), _ebml(0x86, b"A_OPUS"),
                  _ebml(0xE1, _ebml(0xB5, struct.pack(">d", float(MKV_RATE))), _ebml_uint(0x9F, MKV_CHANNELS)))
    segment = _ebml(0x18538067, info, _ebml(0x1654AE6B, video, audio), _ebml(0x1F43B675, _ebml_uint(0xE7, 0)))
    data = header + segment
    checks = (Check("media.format_name", "matroska,webm"), Check("media.duration_seconds", "1.500000"),
              Check("media.stream_count", 2), Check("media.primary_video_codec_name", "vp9"),
              Check("media.primary_audio_codec_name", "opus"), Check("media.primary_video_width_pixels", MKV_WIDTH),
              Check("media.primary_video_height_pixels", MKV_HEIGHT), Check("media.primary_video_frame_rate", "25/1"),
              Check("media.primary_audio_sample_rate_hz", MKV_RATE), Check("media.primary_audio_channel_count", MKV_CHANNELS),
              Check("media.title_tag", MKV_TITLE), Check("media.video_codec_names", ["vp9"]),
              Check("mkv.doc_type", "webm"), Check("mkv.title", MKV_TITLE), Check("file.size_bytes", None))
    return Sample("media_mkv", "corpus-clip.webm", data, _fill_identity(checks, "corpus-clip.webm", data))


ATTACHMENT = b"%PDF-1.4\n% synthetic corpus attachment\n" + bytes(range(256)) * 4
NESTED_ATTACHMENT = b"inner note: the nested message carries this text\n"


def _b64_lines(b: bytes) -> str:
    s = base64.b64encode(b).decode()
    return "\r\n".join(s[i:i + 76] for i in range(0, len(s), 76))


def eml_attachments() -> Sample:
    """A multipart/mixed message: a quoted-printable text part, one base64 attachment, and an attached
    message/rfc822 that holds an attachment of its own (the chain goes through it)."""
    inner = ("From: Grace Example <grace@example.test>\r\nTo: ada@example.test\r\nSubject: inner\r\n"
             "Message-ID: <inner.0001@example.test>\r\nMIME-Version: 1.0\r\n"
             'Content-Type: multipart/mixed; boundary="in-b"\r\n\r\n'
             "--in-b\r\nContent-Type: text/plain\r\n\r\ninner body\r\n"
             '--in-b\r\nContent-Type: text/plain; name="inner-note.txt"\r\n'
             'Content-Disposition: attachment; filename="inner-note.txt"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
             + _b64_lines(NESTED_ATTACHMENT) + "\r\n--in-b--\r\n")
    text = ("From: \"Ada Example\" <ada@example.test>\r\nTo: Bob Example <bob@example.test>\r\n"
            "Subject: Corpus quarterly figures\r\nDate: Tue, 04 Mar 2025 05:06:07 +0000\r\n"
            "Message-ID: <corpus.0001@example.test>\r\nMIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="out-b"\r\n\r\n'
            "--out-b\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
            "Figures attached =3D see the PDF.\r\n"
            '--out-b\r\nContent-Type: application/pdf; name="figures.pdf"\r\n'
            'Content-Disposition: attachment; filename="figures.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
            + _b64_lines(ATTACHMENT) + "\r\n"
            '--out-b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename="forwarded.eml"\r\n\r\n'
            + inner + "\r\n--out-b--\r\n")
    data = text.encode("ascii")
    name = "message.eml"
    checks = (Check("eml.subject", "Corpus quarterly figures"), Check("eml.from_address", "ada@example.test"),
              Check("eml.message_id", "<corpus.0001@example.test>"), Check("eml.to_address", "bob@example.test"),
              Check("eml.from_display_name", "Ada Example"),
              Check("sha256", hashlib.sha256(ATTACHMENT).hexdigest(), artifact=f"{name} -> figures.pdf"),
              Check("size_bytes", len(ATTACHMENT), artifact=f"{name} -> figures.pdf"),
              Check("sha256", hashlib.sha256(NESTED_ATTACHMENT).hexdigest(),
                    artifact=f"{name} -> forwarded.eml -> inner-note.txt"),
              Check("file.size_bytes", None))
    return Sample("eml_attachments", name, data, _fill_identity(checks, name, data))


# ------------------------------------------------------------------ .NET / CLR assemblies (B-222)

def clr_compressed(n: int) -> bytes:
    """An ECMA-335 compressed unsigned integer (II.23.2)."""
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return struct.pack(">H", 0x8000 | n)
    if n < 0x20000000:
        return struct.pack(">I", 0xC0000000 | n)
    raise CorpusError(f"{n} is past what a compressed integer holds")


class _ClrHeap:
    """A #Strings or #Blob heap in the making: add() gives the index of what it stores (0 for nothing)."""

    def __init__(self, blob=False):
        self.data, self.blob = bytearray(b"\x00"), blob

    def add(self, value):
        if not value:
            return 0
        at = len(self.data)
        self.data += (clr_compressed(len(value)) + value) if self.blob else value.encode() + b"\x00"
        return at


CLR_MVID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
ECMA_TOKEN = bytes.fromhex("b77a5c561934e089")          # mscorlib's public key token
MS_TOKEN = bytes.fromhex("b03f5f7f11d50a3a")            # System.Runtime's
CLR_CTOR_STRING = b"\x20\x01\x01\x0e"                   # HASTHIS, one parameter, returns void, takes string
CLR_STRING_ATTRS = (("System.Reflection", "AssemblyTitleAttribute", "Corpus title"),
                    ("System.Reflection", "AssemblyCompanyAttribute", "Synthetic Corpus Ltd"),
                    ("System.Reflection", "AssemblyProductAttribute", "Corpus product"),
                    ("System.Reflection", "AssemblyCopyrightAttribute", "Copyright (c) Synthetic Corpus"),
                    ("System.Reflection", "AssemblyFileVersionAttribute", "1.2.3.4"),
                    ("System.Reflection", "AssemblyInformationalVersionAttribute", "1.2.3+abc"),
                    ("System.Runtime.Versioning", "TargetFrameworkAttribute", ".NETFramework,Version=v4.8"),
                    ("System.Runtime.InteropServices", "GuidAttribute", "0f8fad5b-d9cb-469f-a165-70867728950e"))


def clr_codeview(guid: str, age: int, path: str) -> bytes:
    """The data of a CodeView (RSDS) debug entry: GUID, age, the PDB path."""
    import uuid
    return b"RSDS" + uuid.UUID(guid).bytes_le + struct.pack("<I", age) + path.encode() + b"\x00"


def clr_repro(digest: bytes = b"") -> bytes:
    """The data of a Repro debug entry (type 16): nothing, or the hash's length and the hash."""
    return struct.pack("<I", len(digest)) + digest if digest else b""


def clr_image(name="Corpus.Fixture", version=(1, 2, 3, 4), culture="", public_key=b"",
              refs=(("mscorlib", (4, 0, 0, 0), ECMA_TOKEN),), attrs=CLR_STRING_ATTRS, user_strings=("hello", "wide é"),
              resources=(), flags=0x1, entry=0x06000001, version_string="v4.0.30319", wide=0, mvid=CLR_MVID,
              types=(("Corpus.App", "Program"),), typerefs=(), methods=("Main", "Helper"), ctor_sig=CLR_CTOR_STRING,
              display_name=None, streams_twice=False, clr=True, debug=(), module=None) -> bytes:
    """A PE32 image with one section that holds a CLR header, its metadata (ECMA-335 II.24) and a debug
    directory, built byte by byte. `wide` is the #~ HeapSizes byte (1 #Strings, 2 #GUID, 4 #Blob indexes of
    four bytes). `types` are the TypeDef rows after <Module> as (namespace, name); `typerefs` are TypeRef
    rows after the attributes' own. `debug` is [(IMAGE_DEBUG_TYPE, data)] in directory order (data b"" for
    an entry with none). `clr=False` leaves the CLR directory out: a native PE that still carries the bytes."""
    import uuid
    strings, blobs = _ClrHeap(), _ClrHeap(blob=True)
    S = lambda v: struct.pack("<I" if wide & 1 else "<H", v)   # noqa: E731
    G = lambda v: struct.pack("<I" if wide & 2 else "<H", v)   # noqa: E731
    B = lambda v: struct.pack("<I" if wide & 4 else "<H", v)   # noqa: E731
    H, I = (lambda v: struct.pack("<H", v)), (lambda v: struct.pack("<I", v))   # noqa: E731
    tables = {0x00: [H(0) + S(strings.add(module or name + ".dll")) + G(1) + G(0) + G(0)]}
    tables[0x01] = [H(1 << 2 | 2) + S(strings.add(t)) + S(strings.add(ns)) for ns, t, _ in attrs]
    tables[0x01] += [H(1 << 2 | 2) + S(strings.add(t)) + S(strings.add(ns)) for ns, t in typerefs]
    tables[0x02] = [I(0) + S(strings.add("<Module>")) + S(0) + H(0) + H(1) + H(1)]
    tables[0x02] += [I(0x100001) + S(strings.add(t)) + S(strings.add(ns)) + H(0) + H(1) + H(1 if i == 0 else len(methods) + 1)
                     for i, (ns, t) in enumerate(types)]
    sig = blobs.add(b"\x00\x00\x01")
    tables[0x06] = [I(0x2050) + H(0) + H(0x96) + S(strings.add(m)) + B(sig) + H(1) for m in methods]
    ctor, ctor_blob = strings.add(".ctor"), blobs.add(ctor_sig)
    tables[0x0A] = [H((i + 1) << 3 | 1) + S(ctor) + B(ctor_blob) for i in range(len(attrs))]

    def value(i, text):
        named = b"\x00\x00"
        if display_name is not None and attrs[i][1] == "TargetFrameworkAttribute":
            prop = b"FrameworkDisplayName"
            named = (b"\x01\x00\x54\x0e" + clr_compressed(len(prop)) + prop + clr_compressed(len(display_name.encode()))
                     + display_name.encode())
        return b"\x01\x00" + clr_compressed(len(text.encode())) + text.encode() + named
    tables[0x0C] = [H(1 << 5 | 14) + H((i + 1) << 3 | 3) + B(blobs.add(value(i, text))) for i, (_, _, text) in enumerate(attrs)]
    tables[0x20] = [I(0x8004) + b"".join(H(v) for v in version) + I(1 if public_key else 0) + B(blobs.add(public_key))
                    + S(strings.add(name)) + S(strings.add(culture))]
    tables[0x23] = [b"".join(H(v) for v in ver) + I(0) + B(blobs.add(token)) + S(strings.add(ref)) + S(0) + B(0)
                    for ref, ver, token in refs]
    tables[0x28] = [I(0) + I(1) + S(strings.add(r)) + H(0) for r in resources]
    present = sorted(t for t, rows in tables.items() if rows)
    body = I(0) + bytes([2, 0, wide, 1]) + struct.pack("<QQ", sum(1 << t for t in present), 0)
    body += b"".join(I(len(tables[t])) for t in present) + b"".join(b"".join(tables[t]) for t in present)
    us = bytearray(b"\x00")
    for s in user_strings:
        raw = s.encode("utf-16-le")
        us += clr_compressed(len(raw) + 1) + raw + (b"\x01" if any(ord(c) > 0x7E for c in s) else b"\x00")
    heaps = [("#~", body), ("#Strings", bytes(strings.data)), ("#US", bytes(us)), ("#GUID", uuid.UUID(mvid).bytes_le),
             ("#Blob", bytes(blobs.data))]
    if streams_twice:
        heaps.append(("#GUID", uuid.UUID(int=7).bytes_le))
    heaps = [(n, b + b"\x00" * (-len(b) % 4)) for n, b in heaps]
    ver = version_string.encode() + b"\x00"
    ver += b"\x00" * (-len(ver) % 4)
    head = len(b"BSJB") + 12 + len(ver) + 4 + sum(8 + ((len(n) + 4) & ~3) for n, _ in heaps)
    root = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(ver)) + ver + struct.pack("<HH", 0, len(heaps))
    at = head
    for n, b in heaps:
        root += struct.pack("<II", at, len(b)) + n.encode() + b"\x00" * (((len(n) + 4) & ~3) - len(n))
        at += len(b)
    root += b"".join(b for _, b in heaps)
    rva, raw = 0x2000, 0x200
    cor20 = struct.pack("<IHHIIIIIIII", 72, 2, 5, rva + 72, len(root), flags, entry, 0, 0, 0, 0) + b"\x00" * 32
    text = cor20 + root
    text += b"\x00" * (-len(text) % 4)
    dirs = [(0, 0)] * 16
    if debug:
        table_at = len(text)
        data_at = table_at + 28 * len(debug)
        entries, blob = b"", b""
        for typ, data in debug:
            where = data_at + len(blob)
            entries += struct.pack("<IIHHIIII", 0, 0, 0, 0, typ, len(data), rva + where if data else 0, raw + where if data else 0)
            blob += data + b"\x00" * (-len(data) % 4)
        text += entries + blob
        dirs[6] = (rva + table_at, 28 * len(debug))
    text += b"\x00" * (-len(text) % 0x200)
    if clr:
        dirs[14] = (rva, 72)
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 48, 0, len(text), 0, 0, 0, rva, 0, 0x400000, 0x2000, 0x200,
                      4, 0, 0, 0, 4, 0, 0, rva + 0x2000 + len(text), 0x200, 0, 3, 0x8540, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", *e) for e in dirs)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(opt), 0x2102)
    sect = struct.pack("<8sIIIIIIHHI", b".text", len(text), rva, len(text), raw, 0, 0, 0, 0, 0x60000020)
    image = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64 + b"PE\x00\x00" + coff + opt + sect
    return image + b"\x00" * (raw - len(image)) + text


DOTNET_TYPES = (("Corpus.Tool", "Program"), ("Corpus.Tool.Internal", "Helper"), ("Corpus.Tool", "Options"))
DOTNET_REFS = (("System.Runtime", (8, 0, 0, 0), MS_TOKEN), ("System.Console", (8, 0, 0, 1), MS_TOKEN))
DOTNET_PDB = ("9d2f3a10-77aa-4c21-8e01-aabbccddeeff", 1, "/build/obj/Release/net8.0/Corpus.Tool.pdb")
DOTNET_REPRO_HASH = bytes(range(0x20, 0x40))


def dotnet_assembly() -> Sample:
    """A managed console assembly of a deterministic build: Module, Assembly, TypeDef rows in two
    namespaces, two references, the string attributes, a CodeView and a Repro debug entry."""
    attrs = tuple((ns, t, ".NETCoreApp,Version=v8.0" if t == "TargetFrameworkAttribute" else v) for ns, t, v in CLR_STRING_ATTRS)
    data = clr_image(name="Corpus.Tool", version=(3, 1, 4, 1), refs=DOTNET_REFS, attrs=attrs, types=DOTNET_TYPES,
                     typerefs=(("System", "Object"), ("System", "Console")),
                     debug=((2, clr_codeview(*DOTNET_PDB)), (16, clr_repro(DOTNET_REPRO_HASH))))
    checks = (Check("dotnet.mvid_guid", CLR_MVID), Check("dotnet.mvid", CLR_MVID),
              Check("dotnet.module_name", "Corpus.Tool.dll"), Check("dotnet.assembly_name", "Corpus.Tool"),
              Check("dotnet.assembly_version", "3.1.4.1"), Check("dotnet.metadata_version", "v4.0.30319"),
              Check("dotnet.typedef_names", ["<Module>"] + [t for _, t in DOTNET_TYPES]),
              Check("dotnet.namespaces", ["Corpus.Tool", "Corpus.Tool.Internal"]),
              Check("dotnet.assembly_ref_names", [r for r, _, _ in DOTNET_REFS]),
              Check("dotnet.target_framework", ".NETCoreApp,Version=v8.0"),
              Check("dotnet.assembly_company", "Synthetic Corpus Ltd"),
              Check("dotnet.pdb_path", DOTNET_PDB[2]), Check("dotnet.is_deterministic", True),
              Check("dotnet.repro_hash", DOTNET_REPRO_HASH.hex()),
              Check("dotnet.debug_types", ["CODEVIEW", "REPRO"]),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample("dotnet_assembly", "Corpus.Tool.dll", data, _fill_identity(checks, "Corpus.Tool.dll", data))


# ------------------------------------------------------------------ B-248: the metadata lane's residual readers

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def png_write(chunks: list) -> bytes:
    """A PNG of (type, body) chunks, each with its CRC."""
    out = PNG_SIG
    for typ, body in chunks:
        out += struct.pack(">I", len(body)) + typ + body + struct.pack(">I", zlib.crc32(typ + body))
    return out


def png_text() -> Sample:
    """A 2x1 greyscale PNG with two tEXt chunks: the keyword list is asked under the name the png_text_<keyword>
    family used to capture (png.text_chunk_keywords, the Day 13 drill)."""
    ihdr = struct.pack(">IIBBBBB", 2, 1, 8, 0, 0, 0, 0)
    data = png_write([(b"IHDR", ihdr), (b"tEXt", b"Software\x00Corpus Cam 2.1"), (b"tEXt", b"Author\x00Ada Example"),
                      (b"IDAT", zlib.compress(b"\x00\x10\x20")), (b"IEND", b"")])
    checks = (Check("png.text_keywords", ["Software", "Author"]), Check("png.text_chunk_keywords", ["Software", "Author"]),
              Check("png.text_keyword_list", ["Software", "Author"]), Check("png.text_software", "Corpus Cam 2.1"),
              Check("png.text_chunk_count", 2), Check("png.ihdr_bit_depth", 8))
    return Sample("png_text", "frame.png", data, checks)


ICC_DESCRIPTION = "Corpus RGB v4"


def icc_profile(description: str = ICC_DESCRIPTION) -> bytes:
    """A minimal ICC display profile: a 128-byte header ('acsp' at 36) and one 'desc' tag of type desc."""
    text = description.encode("ascii") + b"\x00"
    desc = b"desc" + bytes(4) + struct.pack(">I", len(text)) + text + bytes(12)
    desc += bytes(-len(desc) % 4)
    size = 128 + 4 + 12 + len(desc)
    head = bytearray(128)
    struct.pack_into(">I4sI4s4s4s", head, 0, size, b"none", 0x02100000, b"mntr", b"RGB ", b"XYZ ")
    head[36:40] = b"acsp"
    return bytes(head) + struct.pack(">I", 1) + struct.pack(">4sII", b"desc", 144, len(desc)) + desc


def tiff_icc() -> Sample:
    """A 1x1 greyscale little-endian TIFF whose first IFD carries an ICC profile (tag 34675, InterColorProfile)."""
    icc = icc_profile()
    entries = [(256, 3, 1, 1), (257, 3, 1, 1), (258, 3, 1, 8), (259, 3, 1, 1), (262, 3, 1, 1), (273, 4, 1, None),
               (277, 3, 1, 1), (278, 3, 1, 1), (279, 4, 1, 1), (34675, 7, len(icc), None)]
    ifd_size = 2 + 12 * len(entries) + 4
    pixel_at = 8 + ifd_size
    icc_at = pixel_at + 2
    out = bytearray(b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", len(entries)))
    for tag, typ, count, value in entries:
        if tag == 273:
            value = pixel_at
        if tag == 34675:
            out += struct.pack("<HHII", tag, typ, count, icc_at)
        elif typ == 3:
            out += struct.pack("<HHIHH", tag, typ, count, value, 0)
        else:
            out += struct.pack("<HHII", tag, typ, count, value)
    out += struct.pack("<I", 0) + b"\x80\x00" + icc
    data = bytes(out)
    checks = (Check("tiff.icc_profile_description", ICC_DESCRIPTION), Check("icc.profile_description", ICC_DESCRIPTION),
              Check("tiff.icc_profile_size_bytes", len(icc)))
    return Sample("tiff_icc", "scan.tif", data, checks)


def heif_icc() -> Sample:
    """A HEIF still image (no coded data) whose primary item carries ispe 64x48 and a colr 'prof' ICC profile, beside
    an nclx colr (which carries no profile)."""
    icc = icc_profile()
    ftyp = _box(b"ftyp", b"heic" + struct.pack(">I", 0) + b"mif1heic")
    hdlr = _box(b"hdlr", bytes(4) + bytes(4) + b"pict" + bytes(12) + b"\x00")
    pitm = _box(b"pitm", bytes(4) + struct.pack(">H", 1))
    infe = _box(b"infe", b"\x02\x00\x00\x00" + struct.pack(">HH", 1, 0) + b"hvc1" + b"\x00")
    iinf = _box(b"iinf", bytes(4) + struct.pack(">H", 1) + infe)
    ispe = _box(b"ispe", bytes(4) + struct.pack(">II", 64, 48))
    prof = _box(b"colr", b"prof" + icc)
    nclx = _box(b"colr", b"nclx" + struct.pack(">HHHB", 1, 13, 6, 0x80))
    ipco = _box(b"ipco", ispe + nclx + prof)
    ipma = _box(b"ipma", bytes(4) + struct.pack(">I", 1) + struct.pack(">HB", 1, 3) + bytes([0x81, 0x02, 0x83]))
    iprp = _box(b"iprp", ipco + ipma)
    meta = _box(b"meta", bytes(4) + hdlr + pitm + iinf + iprp)
    data = ftyp + meta + _box(b"mdat", b"\x00" * 8)
    checks = (Check("heic.icc_profile_description", ICC_DESCRIPTION), Check("icc.profile_description", ICC_DESCRIPTION),
              Check("heic.width", 64))
    return Sample("heif_icc", "photo.heic", data, checks)


REGF_ROOT = "CorpusArtifactAssemblyLine"
REGF_DECOY = "ress-corpus-assembly.hiv"


def regf_hive(root: str = REGF_ROOT, embedded: str = REGF_DECOY) -> bytes:
    """A registry hive: a base block whose embedded file name (offset 48) is a host-label DECOY distinct from the
    root key's own name, one hive bin, the root key node (no subkeys, no values) and a free cell to the bin's end."""
    base = bytearray(4096)
    base[:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", base, 4, 3, 3, filetime(WHEN), 1, 5, 0, 1, 0x20, 4096, 1)
    name16 = embedded.encode("utf-16-le")[:62]
    base[48:48 + len(name16)] = name16
    struct.pack_into("<I", base, 508, functools.reduce(lambda a, w: a ^ w, struct.unpack("<127I", bytes(base[:508])), 0))
    hbin = bytearray(4096)
    hbin[:4] = b"hbin"
    struct.pack_into("<II", hbin, 4, 0, 4096)
    raw = root.encode("ascii")
    nk = bytearray(0x4C + len(raw))
    nk[:2] = b"nk"
    struct.pack_into("<HQ", nk, 2, 0x2C, filetime(WHEN))
    struct.pack_into("<IIIIIIIIII", nk, 16, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    struct.pack_into("<HH", nk, 0x48, len(raw), 0)
    nk[0x4C:] = raw
    cell = (4 + len(nk) + 7) & ~7
    struct.pack_into("<i", hbin, 0x20, -cell)
    hbin[0x24:0x24 + len(nk)] = nk
    struct.pack_into("<i", hbin, 0x20 + cell, 4096 - 0x20 - cell)
    return bytes(base) + bytes(hbin)


def regf_decoy() -> Sample:
    """The Day 25 hive shape: registry.hive_root_name is the root KEY's name, and the base block's embedded file name
    is a decoy that must never answer it (nor the other way round)."""
    data = regf_hive()
    checks = (Check("regf.root_key_name", REGF_ROOT), Check("regf.file_name", REGF_DECOY),
              Check("regf.major_version", 1), Check("regf.minor_version", 5), Check("regf.checksum_valid", True))
    return Sample("regf_decoy", "assembly-line.hiv", data, checks)


def _usn_v2(name: str, usn: int, reason: int) -> bytes:
    n = name.encode("utf-16-le")
    size = (60 + len(n) + 7) & ~7
    rec = struct.pack("<IHHQQQqIIIIHH", size, 2, 0, 0x0001000000000123, 0x0005000000000005, usn,
                      filetime(WHEN), reason, 0, 0, 0x20, len(n), 60) + n
    return rec + bytes(size - len(rec))


def _usn_v3(name: str, usn: int, reason: int) -> bytes:
    n = name.encode("utf-16-le")
    size = (76 + len(n) + 7) & ~7
    rec = (struct.pack("<IHH", size, 3, 0) + (0x123).to_bytes(16, "little") + (5).to_bytes(16, "little")
           + struct.pack("<QqIIIIHH", usn, filetime(LATER), reason, 0, 0, 0x20, len(n), 76) + n)
    return rec + bytes(size - len(rec))


USN_V4_EXTENTS = ((0x1000, 0x200), (0x3000, 0x80))


def _usn_v4(usn: int, extents=USN_V4_EXTENTS) -> bytes:
    rec = (struct.pack("<IHH", 64 + 16 * len(extents), 4, 0) + (0x123).to_bytes(16, "little") + (5).to_bytes(16, "little")
           + struct.pack("<QIIIHH", usn, 0x2, 0, 0, len(extents), 16))
    return rec + b"".join(struct.pack("<qq", o, n) for o, n in extents)


def usn_mixed() -> Sample:
    """A $J stream: sparse zeros, then a V3 record, a V4 range-tracking record and a V2 record, as a volume with range
    tracking on writes them."""
    data = bytes(4096) + _usn_v3("report.docx", 0x5000, 0x100) + _usn_v4(0x5068) + _usn_v2("notes.txt", 0x50C8, 0x2)
    checks = (Check("usn.record_count", 3), Check("usn.record_major_versions", [3, 4, 2]), Check("usn.v4_record_count", 1),
              Check("usn.first_record_file_name", "report.docx"), Check("usn.first_record_major_version", 3))
    return Sample("usn_mixed", "$J", data, checks)


def usn_v4_first() -> Sample:
    """A $J stream whose first record is a V4 range-tracking record (no name, no time) followed by a V3 record."""
    data = bytes(8192) + _usn_v4(0x9000) + _usn_v3("ledger.xlsx", 0x9060, 0x100)
    checks = (Check("usn.first_record_major_version", 4), Check("usn.first_record_extent_count", 2),
              Check("usn.first_record_extent_offsets", [o for o, _ in USN_V4_EXTENTS]),
              Check("usn.first_record_extent_lengths", [n for _, n in USN_V4_EXTENTS]),
              Check("usn.first_record_usn", 0x9000), Check("usn.record_count", 2))
    return Sample("usn_v4_first", "UsnJrnl_J.bin", data, checks)


BIGOBJ_CLSID = bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")   # {D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}
BIGOBJ_STAMP = 0x65A1B2C3
BIGOBJ_SECTIONS = (".text", ".data", ".rdata$zz_corpus_long")


def coff_bigobj() -> Sample:
    """A bigobj COFF object (cl /bigobj): a 56-byte header, three sections (the third a long name through the string
    table), one 20-byte symbol record and the string table after it."""
    nsec = len(BIGOBJ_SECTIONS)
    table = 56
    raw_at = table + 40 * nsec
    bodies = [b"\xc3\x90\x90\x90", b"DATA", b""]
    sym_at = raw_at + sum(len(b) for b in bodies)
    strtab = BIGOBJ_SECTIONS[2].encode() + b"\x00"
    head = struct.pack("<HHHHI", 0, 0xFFFF, 2, 0x8664, BIGOBJ_STAMP) + BIGOBJ_CLSID + struct.pack(
        "<7I", 0, 0, 0, 0, nsec, sym_at, 1)
    secs, at = b"", raw_at
    for name, body in zip(BIGOBJ_SECTIONS, bodies):
        field = name.encode() if len(name) <= 8 else b"/4"
        secs += struct.pack("<8sIIIIIIHHI", field, 0, 0, len(body), at if body else 0, 0, 0, 0, 0, 0x60000020)
        at += len(body)
    sym = b".file\x00\x00\x00" + struct.pack("<IiHBB", 0, -2, 0, 0x67, 0)   # IMAGE_SYMBOL_EX: 20 bytes
    data = head + secs + b"".join(bodies) + sym + struct.pack("<I", 4 + len(strtab)) + strtab
    checks = (Check("coff.number_of_sections", nsec), Check("coff.section_names", list(BIGOBJ_SECTIONS)),
              Check("coff.time_date_stamp", BIGOBJ_STAMP), Check("coff.is_bigobj", True), Check("coff.bigobj_version", 2),
              Check("coff.bigobj_class_id", "d1baa1c7-baee-4ba9-af20-faf66aa4dcb8"))
    return Sample("coff_bigobj", "module.obj", data, checks)


AR_MEMBER = b"synthetic ar member payload\n"
AR_MTIME = 1700000000


def ar_write(members: list) -> bytes:
    """A GNU ar archive of (name, mtime, uid, gid, mode, body) members, short names only."""
    out = b"!<arch>\n"
    for name, mtime, uid, gid, mode, body in members:
        out += (f"{name + '/':<16}{mtime:<12}{uid:<6}{gid:<6}{mode:<8o}{len(body):<10}".encode() + b"`\n" + body
                + (b"\n" if len(body) & 1 else b""))
    return out


def ar_single() -> Sample:
    """An ar archive with one member: the scalar ar.member_<field> names read that member's header."""
    data = ar_write([("notes.txt", AR_MTIME, 1000, 100, 0o100644, AR_MEMBER)])
    checks = (Check("ar.member_name", "notes.txt"), Check("ar.member_uid", 1000), Check("ar.member_gid", 100),
              Check("ar.member_size_bytes", len(AR_MEMBER)), Check("ar.member_mode", "100644"),
              Check("ar.member_mtime", AR_MTIME))
    return Sample("ar_single", "bundle.a", data, checks)


# ------------------------------------------------------------------ partitioned disk images (B-221)

GPT_EFI_SYSTEM = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"         # the UEFI specification's type GUIDs
GPT_LINUX_FS = "0fc63daf-8483-4772-8e79-3d69d8477de4"
GPT_MS_BASIC_DATA = "ebd0a0a2-b9e5-4433-87c0-68b9b72699c7"
GPT_DISK_GUID = "5eed0b1d-c0de-4a11-9d15-c0ffee000221"           # invented


def _guid_le(text: str) -> bytes:
    """A GUID as a GPT stores it: the first three fields little-endian (uuid's bytes_le)."""
    return _uuid.UUID(text).bytes_le


def gpt_image(parts: list, *, sector: int = 512, sectors: int = 512, disk_guid: str = GPT_DISK_GUID,
              entries: int = 128) -> bytes:
    """A GPT disk of `sectors` sectors: a protective MBR, the primary header at LBA 1 with its entry array at
    LBA 2, and the backup array and header at the end, both CRCs right. `parts` is [(type GUID, unique GUID,
    first LBA, last LBA, name)] in table order (entries 0, 1, ...)."""
    esize = 128
    table = bytearray(entries * esize)
    for i, (ptype, unique, first, last, name) in enumerate(parts):
        raw = name.encode("utf-16-le")
        if len(raw) > 72:
            raise CorpusError(f"a GPT partition name holds 36 UTF-16 units: {name!r}")
        struct.pack_into("<16s16sQQQ72s", table, i * esize, _guid_le(ptype), _guid_le(unique), first, last, 0, raw)
    array_sectors = (len(table) + sector - 1) // sector
    first_usable, last_usable = 2 + array_sectors, sectors - 2 - array_sectors
    if any(not first_usable <= p[2] <= p[3] <= last_usable for p in parts):
        raise CorpusError("a partition outside the usable LBA range")
    table_crc = zlib.crc32(table) & 0xFFFFFFFF
    data = bytearray(sector * sectors)
    data[446:462] = struct.pack("<B3xB3xII", 0, 0xEE, 1, min(sectors - 1, 0xFFFFFFFF))
    data[510:512] = b"\x55\xaa"

    def header(current: int, backup: int, array_lba: int) -> bytes:
        h = bytearray(92)
        struct.pack_into("<8sIIIIQQQQ16sQIII", h, 0, b"EFI PART", 0x00010000, 92, 0, 0, current, backup,
                         first_usable, last_usable, _guid_le(disk_guid), array_lba, entries, esize, table_crc)
        struct.pack_into("<I", h, 16, zlib.crc32(h) & 0xFFFFFFFF)
        return bytes(h)

    data[2 * sector:2 * sector + len(table)] = table
    backup_array = sectors - 1 - array_sectors
    data[backup_array * sector:backup_array * sector + len(table)] = table
    data[sector:sector + 92] = header(1, sectors - 1, 2)
    data[(sectors - 1) * sector:(sectors - 1) * sector + 92] = header(sectors - 1, 1, backup_array)
    return bytes(data)


def mbr_image(parts: list, *, sectors: int = 256, signature: int = 0) -> bytes:
    """A classic MBR disk of `sectors` 512-byte sectors: [(status, type, first LBA, sector count)] as the
    primary entries 0..3, the NT disk signature at 440 and the boot signature."""
    if len(parts) > 4:
        raise CorpusError("an MBR holds four primary entries")
    data = bytearray(512 * sectors)
    struct.pack_into("<I", data, 440, signature)
    for i, (status, ptype, first, count) in enumerate(parts):
        struct.pack_into("<B3xB3xII", data, 446 + 16 * i, status, ptype, first, count)
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def disk_gpt() -> Sample:
    """A GPT disk with an EFI system partition, a Linux filesystem and a Microsoft basic data partition, the
    entries NOT in LBA order (Day 28's sequence question is about table order)."""
    parts = [(GPT_EFI_SYSTEM, "11111111-2222-4333-8444-555555555501", 34, 97, "EFI system partition"),
             (GPT_MS_BASIC_DATA, "11111111-2222-4333-8444-555555555503", 354, 477, "data"),
             (GPT_LINUX_FS, "11111111-2222-4333-8444-555555555502", 98, 353, "rootfs")]
    data = gpt_image(parts)
    sizes = [p[3] - p[2] + 1 for p in parts]
    checks = (Check("disk.partition_start_lba_sequence", [p[2] for p in parts]),
              Check("disk.partition_table_type", "gpt"), Check("disk.partition_count", len(parts)),
              Check("disk.disk_guid", GPT_DISK_GUID),
              Check("disk.partition_type_guid_sequence", [p[0] for p in parts]),
              Check("disk.partition_guid_sequence", [p[1] for p in parts]),
              Check("disk.partition_name_sequence", [p[4] for p in parts]),
              Check("disk.partition_end_lba_sequence", [p[3] for p in parts]),
              Check("disk.partition_sector_count_sequence", sizes),
              Check("disk.partition_size_bytes_sequence", [n * 512 for n in sizes]),
              Check("disk.sector_size_bytes", 512), Check("disk.total_sectors", 512),
              Check("disk.first_usable_lba", 34), Check("disk.last_usable_lba", 478),
              Check("disk.backup_header_lba", 511), Check("disk.partition_entry_lba", 2),
              Check("disk.partition_entry_count", 128), Check("disk.partition_entry_size_bytes", 128),
              Check("disk.has_protective_mbr", True),
              Check("gpt.disk_guid", GPT_DISK_GUID), Check("gpt.partition_count", len(parts)),
              Check("gpt.first_partition_name", "EFI system partition"), Check("mbr.protective", True),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample("disk_gpt", "disk-001.img", data, _fill_identity(checks, "disk-001.img", data))


def disk_mbr() -> Sample:
    """A classic MBR disk: a bootable FAT32 (LBA) partition and a Linux one, with an NT disk signature."""
    parts = [(0x80, 0x0C, 63, 128), (0x00, 0x83, 191, 64)]
    signature = 0x1A2B3C4D
    data = mbr_image(parts, signature=signature)
    checks = (Check("disk.partition_start_lba_sequence", [p[2] for p in parts]),
              Check("disk.partition_table_type", "mbr"), Check("disk.partition_count", len(parts)),
              Check("disk.partition_type_code_sequence", [f"{p[1]:02x}" for p in parts]),
              Check("disk.partition_sector_count_sequence", [p[3] for p in parts]),
              Check("disk.partition_end_lba_sequence", [p[2] + p[3] - 1 for p in parts]),
              Check("disk.mbr_disk_signature", f"0x{signature:08x}"), Check("disk.has_protective_mbr", False),
              Check("mbr.partition_count", len(parts)), Check("mbr.bootable_partition_count", 1),
              Check("mbr.first_partition_start_lba", 63),
              Check("file.size_bytes", None), Check("sha256", None))
    return Sample("disk_mbr", "usb-stick.img", data, _fill_identity(checks, "usb-stick.img", data))


BUILDERS = {f.__name__: f for f in (ooxml_docx, ooxml_xlsx, ooxml_pptx, eml_attachments, lnk_shortcut, riff_wav,
                                    riff_avi, riff_webp, riff_other, ole_document, msi_package, msi_package_lzx, cab_mszip,
                                    cab_stored, msix_package, media_mp4, media_mkv, dotnet_assembly,
                                    png_text, tiff_icc, heif_icc, regf_decoy, usn_mixed,
                                    usn_v4_first, coff_bigobj, ar_single,
                                    disk_gpt, disk_mbr)}
from . import corpus_longtail as _longtail   # noqa: E402  (B-251: the long-tail formats' samples and writers)
BUILDERS.update(_longtail.SAMPLES)


def build(sample_id: str) -> Sample:
    """The sample `sample_id` (a BUILDERS key); CorpusError naming the known ids otherwise."""
    fn = BUILDERS.get(sample_id)
    if fn is None:
        raise CorpusError(f"no corpus builder {sample_id!r} (known: {', '.join(sorted(BUILDERS))})")
    return fn()
