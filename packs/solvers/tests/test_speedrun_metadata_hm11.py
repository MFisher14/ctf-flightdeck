"""Speedrun Metadata day readers merged in B-001 hand-merge batch hm-11 (Huntress speedrun copies checked
against the CSCTF / shipped readers): metadata_d12 (.NET Mvid), metadata_d14 (LNK target path),
metadata_d15 (OOXML external relationship targets), metadata_d21 (APK package name).

Every fixture is built here from scratch; no challenge file is read.
"""
import io
import json
import struct
import uuid
import zipfile

from speedrun.solvers import metadata_d12, metadata_d14, metadata_d15, metadata_d21

# -- metadata_d12: .NET Mvid ------------------------------------------------------------------------------

MVID = uuid.UUID("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
OTHER = uuid.UUID("11111111-2222-3333-4444-555555555555")


def _pad4(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 4)


def _dotnet_pe(heap: int = 0, extra: bool = False, guids=(MVID,), mvid_index: int = 1) -> bytes:
    """A PE32 with one section holding a CLR header and a metadata root with #~ and #GUID streams."""
    rows = struct.pack("<I", 1) + (struct.pack("<I", 0xDEADBEEF) if extra else b"")
    module_row = struct.pack("<HHHHH", 0, 0, mvid_index, 0, 0)   # Generation, Name, Mvid, EncId, EncBaseId
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, heap, 1, 1, 0) + rows + module_row
    guid_heap = b"".join(g.bytes_le for g in guids)
    version = _pad4(b"v4.0.30319\0")
    streams = [("#~", _pad4(tables)), ("#GUID", guid_heap)]
    hdr_len = 16 + len(version) + 4 + sum(8 + len(_pad4(n.encode() + b"\0")) for n, _ in streams)
    root = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, len(streams))
    body, off = b"", hdr_len
    for n, data in streams:
        root += struct.pack("<II", off, len(data)) + _pad4(n.encode() + b"\0")
        body += data
        off += len(data)
    md = root + body
    va, raw = 0x2000, 0x200
    clr = struct.pack("<IHHII", 72, 2, 5, va + 72, len(md)).ljust(72, b"\0")
    sec_data = clr + md
    dos = b"MZ".ljust(0x3C, b"\0") + struct.pack("<I", 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)                       # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 96 + 14 * 8, va, 72)         # CLR runtime header directory
    sec = b".text\0\0\0" + struct.pack("<IIII", len(sec_data), va, len(sec_data), raw) + b"\0" * 16
    head = (dos + coff + bytes(opt) + sec).ljust(raw, b"\0")
    return head + sec_data


def test_d12_reads_module_mvid():
    assert metadata_d12.dotnet_mvid("a.dll", _dotnet_pe()) == str(MVID)


def test_d12_skips_extra_data_dword_on_bit_0x40():
    # HeapSizes 0x40 (ExtraData) puts a dword after the row counts; the Huntress copy tested 0x20 and so
    # read the Module row 4 bytes early (Mvid index 0 -> None).
    assert metadata_d12.dotnet_mvid("a.dll", _dotnet_pe(heap=0x40, extra=True)) == str(MVID)


def test_d12_delta_only_bit_0x20_adds_no_dword():
    # 0x20 is DeltaOnly: no extra dword. Reading one would land on the wrong Mvid index (2 -> OTHER).
    pe = _dotnet_pe(heap=0x20, guids=(MVID, OTHER))
    assert metadata_d12.dotnet_mvid("a.dll", pe) == str(MVID)


def test_d12_fails_closed():
    assert metadata_d12.dotnet_mvid("a.dll", _dotnet_pe(mvid_index=2)) is None   # index past #GUID
    assert metadata_d12.dotnet_mvid("a.dll", _dotnet_pe()[:0x230]) is None       # truncated image
    assert metadata_d12.dotnet_mvid("a.txt", b"not a pe" * 20) is None
    assert metadata_d12.PROPS["dotnet-mvid-guid"] is metadata_d12.dotnet_mvid


# -- metadata_d14: LNK target path ------------------------------------------------------------------------

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _lnk(ansi_base: bytes, ansi_suffix: bytes = b"", ubase=None, usuffix=None) -> bytes:
    header = struct.pack("<I", 0x4C) + _LNK_CLSID + struct.pack("<I", 0x2 | 0x80)
    header = header.ljust(76, b"\0")
    unicode = ubase is not None or usuffix is not None
    head = 0x24 if unicode else 0x1C
    vol = b"\x10\0\0\0" + b"\0" * 12
    parts, off = [], head
    vol_at = off; parts.append(vol); off += len(vol)
    base_at = off; parts.append(ansi_base + b"\0"); off += len(ansi_base) + 1
    suffix_at = off; parts.append(ansi_suffix + b"\0"); off += len(ansi_suffix) + 1
    ub_at = us_at = 0
    if unicode:
        if off % 2:
            parts.append(b"\0"); off += 1
        ub_at = off; b = (ubase or "").encode("utf-16-le") + b"\0\0"; parts.append(b); off += len(b)
        us_at = off; b = (usuffix or "").encode("utf-16-le") + b"\0\0"; parts.append(b); off += len(b)
    fields = struct.pack("<IIIIIII", off, head, 1, vol_at, base_at, 0, suffix_at)
    if unicode:
        fields += struct.pack("<II", ub_at, us_at)
    return header + fields + b"".join(parts)


def test_d14_ansi_path_and_suffix():
    assert metadata_d14.lnk_target("x.lnk", _lnk(b"C:\\Tools\\", b"run.exe")) == "C:\\Tools\\run.exe"


def test_d14_unicode_path_preferred():
    d = _lnk(b"C:\\A\\", b"", ubase="C:\\Ü\\", usuffix="b.exe")
    assert metadata_d14.lnk_target("x.lnk", d) == "C:\\Ü\\b.exe"


def test_d14_empty_unicode_base_falls_back_to_ansi():
    # CSCTF reads an empty string as absent; the Huntress copy answered just the suffix here.
    d = _lnk(b"C:\\Win\\app.exe", b"", ubase="", usuffix="")
    assert metadata_d14.lnk_target("x.lnk", d) == "C:\\Win\\app.exe"


def test_d14_fails_closed():
    assert metadata_d14.lnk_target("x.lnk", _lnk(b"", b"")) is None      # no base path at all
    assert metadata_d14.lnk_target("x.lnk", _lnk(b"C:\\a")[:90]) is None  # LinkInfo cut
    assert metadata_d14.lnk_target("x.lnk", b"\0" * 100) is None


# -- metadata_d15: OOXML external relationship targets ----------------------------------------------------

_RELS = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/'
         'package/2006/relationships">{}</Relationships>')


def _rel(i, target, external=True):
    mode = ' TargetMode="External"' if external else ""
    return f'<Relationship Id="rId{i}" Type="t" Target="{target}"{mode}/>'


def _docx(rels_body, content_types=True, rels_bytes=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if content_types:
            z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/_rels/document.xml.rels",
                   rels_bytes if rels_bytes is not None else _RELS.format(rels_body).encode())
        z.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def test_d15_sorted_unescaped_targets():
    body = (_rel(1, "https://z.example/a?x=1&amp;y=2") + _rel(2, "styles.xml", external=False)
            + _rel(3, "https://a.example/t.dotm"))
    v = metadata_d15.external_targets("d.docx", _docx(body))
    assert v == '["https://a.example/t.dotm","https://z.example/a?x=1&y=2"]'


def test_d15_non_ascii_kept_as_written():
    v = metadata_d15.external_targets("d.docx", _docx(_rel(1, "https://例え.jp/ü")))
    assert v == '["https://例え.jp/ü"]'
    assert json.loads(v) == ["https://例え.jp/ü"]


def test_d15_fails_closed():
    one = _rel(1, "https://a.example/")
    assert metadata_d15.external_targets("d.zip", _docx(one, content_types=False)) is None   # not OOXML
    assert metadata_d15.external_targets("d.docx", _docx(one + _rel(2, "https://a.example/"))) is None
    bad = _RELS.format(one).encode().replace(b"https", b"\xff\xfe")                         # not UTF-8
    assert metadata_d15.external_targets("d.docx", _docx("", rels_bytes=bad)) is None
    assert metadata_d15.external_targets("d.docx", _docx(_rel(1, "x.xml", external=False))) is None


# -- metadata_d21: APK package name -----------------------------------------------------------------------

def _string_pool(strings):
    data, offs = b"", []
    for s in strings:
        b = s.encode()
        offs.append(len(data))
        data += bytes([len(s), len(b)]) + b + b"\0"
    data = _pad4(data)
    hs = 28
    sstart = hs + 4 * len(strings)
    size = sstart + len(data)
    return struct.pack("<HHIIIIII", 1, hs, size, len(strings), 0, 0x100, sstart, 0) + \
        struct.pack(f"<{len(strings)}I", *offs) + data


def _start_element(name_i, attrs, header_size=16):
    body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_i, 20, 20, len(attrs), 0, 0, 0)
    for an, raw, vt, vd in attrs:
        body += struct.pack("<IIIHBBI", 0xFFFFFFFF, an, raw, 8, 0, vt, vd)
    extra = b"\0" * (header_size - 16)
    size = header_size + len(body)
    return struct.pack("<HHIII", 0x0102, header_size, size, 1, 0xFFFFFFFF) + extra + body


def _axml(package="com.example.app", header_size=16, raw=True):
    strings = ["manifest", "package", package, "uses-sdk"]
    if raw:
        attr = (1, 2, 0x03, 2)
    else:
        attr = (1, 0xFFFFFFFF, 0x03, 2)
    chunks = _string_pool(strings) + _start_element(0, [attr], header_size)
    return struct.pack("<HHI", 3, 8, 8 + len(chunks)) + chunks


def _apk(manifest, extra_manifest=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\0")
        if extra_manifest:
            z.writestr("AndroidManifest.xml", manifest)
    return buf.getvalue()


def test_d21_reads_package():
    assert metadata_d21.apk_package("a.apk", _apk(_axml())) == "com.example.app"
    assert metadata_d21.axml_manifest_package(_axml(raw=False)) == "com.example.app"   # typed string value


def test_d21_uses_chunk_header_size():
    # A start-element chunk whose header is longer than 16 bytes: the Huntress copy read the element name
    # from a fixed offset and missed the manifest.
    assert metadata_d21.axml_manifest_package(_axml(header_size=24)) == "com.example.app"


def test_d21_fails_closed():
    assert metadata_d21.axml_manifest_package(_axml(package="")) is None
    assert metadata_d21.axml_manifest_package(b"<manifest package='x'/>") is None    # text manifest
    assert metadata_d21.axml_manifest_package(_axml()[:60]) is None                   # cut document
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        two = _apk(_axml(), extra_manifest=True)
    assert metadata_d21.apk_package("a.apk", two) is None
    assert metadata_d21.apk_package("a.apk", b"PK\x03\x04garbage") is None
