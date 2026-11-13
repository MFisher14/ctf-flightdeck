from __future__ import annotations

import io
import struct
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import pdf_revisions  # noqa: E402
import document_forensics as D  # noqa: E402


FREE = 0xFFFFFFFF
EOC = 0xFFFFFFFE
FAT = 0xFFFFFFFD


def _pdf(*, embedded_filter: bytes = b"") -> bytes:
    output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    def add(number: int, body: bytes) -> None:
        offsets[number] = len(output)
        output.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")

    add(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R "
           b"/Names << /EmbeddedFiles << /Names [(payload.bin) 6 0 R] >> >> >>")
    add(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>")
    filter_field = b" /Filter /" + embedded_filter if embedded_filter else b""
    add(4, b"<< /Type /EmbeddedFile /Length 7" + filter_field + b" >>\nstream\nPAYLOAD\nendstream")
    add(5, b"<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >>")
    add(6, b"<< /Type /Filespec /F (payload.bin) /EF << /F 4 0 R >> >>")
    startxref = len(output)
    output.extend(b"xref\n0 7\n0000000000 65535 f \n")
    for number in range(1, 7):
        output.extend(f"{offsets[number]:010d} 00000 n \n".encode())
    output.extend(
        b"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n"
        + str(startxref).encode() + b"\n%%EOF\n"
    )
    return bytes(output)


def _ooxml(*, bad_target: bool = False, traversal: bool = False, doctype: bool = False,
           invalid_mode: bool = False, undeclared: bool = False) -> bytes:
    content_types = (
        b'<!DOCTYPE Types [<!ENTITY x "boom">]>' if doctype else b""
    ) + b'''<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Default Extension="xml" ContentType="application/xml"/>
      <Default Extension="bin" ContentType="application/octet-stream"/>
      <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
      <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
      <Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>
    </Types>'''
    root_target = "xl/missing.xml" if bad_target else "xl/workbook.xml"
    parts = {
        "[Content_Types].xml": content_types,
        "_rels/.rels": f'''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
                        Target="{root_target}"/>
        </Relationships>'''.encode(),
        "xl/workbook.xml": b'''<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
          <sheets><sheet name="Macro1" sheetId="1"/></sheets>
          <definedNames><definedName name="Auto_Open">Macro1!$A$1</definedName></definedNames>
        </workbook>''',
        "xl/_rels/workbook.xml.rels": b'''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet"
                        Target="macrosheets/sheet1.xml"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
                        Target="https://example.invalid/template.xlam" TargetMode="External"/>
          <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/package"
                        Target="embeddings/payload.bin"/>
        </Relationships>''',
        "xl/macrosheets/sheet1.xml": b'''<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
          <sheetData><row r="1"><c r="A1"><f>EXEC(&quot;cmd.exe /c whoami&quot;)</f><v>0</v></c></row></sheetData>
        </worksheet>''',
        "xl/embeddings/payload.bin": b"PAYLOAD",
    }
    if traversal:
        parts["../escape.bin"] = b"no"
    if invalid_mode:
        parts["xl/_rels/workbook.xml.rels"] = parts["xl/_rels/workbook.xml.rels"].replace(
            b'TargetMode="External"', b'TargetMode="Sideways"'
        )
    if undeclared:
        parts["xl/orphan.xyz"] = b"untyped"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in parts.items():
            archive.writestr(name, body)
    return out.getvalue()


def _directory_entry(name: str, entry_type: int, *, left: int = FREE, right: int = FREE, child: int = FREE,
                     start: int = EOC, size: int = 0) -> bytes:
    entry = bytearray(128)
    encoded = (name + "\0").encode("utf-16-le")
    entry[:len(encoded)] = encoded
    struct.pack_into("<H", entry, 64, len(encoded))
    entry[66] = entry_type
    entry[67] = 1
    struct.pack_into("<III", entry, 68, left, right, child)
    struct.pack_into("<I", entry, 116, start)
    struct.pack_into("<Q", entry, 120, size)
    return bytes(entry)


def _native(payload: bytes = b"PAYLOAD", *, package: bool = False) -> bytes:
    body = bytearray()
    if not package:
        body.extend(b"\0" * 4)
    body.extend(b"\0\0")
    body.extend(b"drop.bin\0")
    body.extend(b"C:\\source\\drop.bin\0")
    body.extend(b"\0" * 8)
    body.extend(b"C:\\temp\\drop.bin\0")
    body.extend(struct.pack("<I", len(payload)))
    body.extend(payload)
    if not package:
        struct.pack_into("<I", body, 0, len(body) - 4)
    return bytes(body)


def _cfb(*, corrupt_chain: bool = False, stream_name: str = "\x01Ole10Native") -> bytes:
    stream = _native()
    stream += b"\0" * (4096 - len(stream))
    header = bytearray(512)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<H", header, 0x18, 0x3E)
    struct.pack_into("<HHHH", header, 0x1A, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, 1)
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<I", header, 0x3C, EOC)
    struct.pack_into("<I", header, 0x44, EOC)
    struct.pack_into("<I", header, 0x4C, 0)
    for offset in range(0x50, 512, 4):
        struct.pack_into("<I", header, offset, FREE)
    fat = [FREE] * 128
    fat[0], fat[1] = FAT, EOC
    for sector in range(2, 10):
        fat[sector] = sector + 1 if sector < 9 else EOC
    if corrupt_chain:
        fat[5] = 3
    directory = (
        _directory_entry("Root Entry", 5, child=1)
        + _directory_entry(stream_name, 2, start=2, size=4096)
        + bytes(256)
    )
    return bytes(header) + struct.pack("<128I", *fat) + directory + stream


def _vba_compress(raw: bytes) -> bytes:
    encoded = bytearray()
    for offset in range(0, len(raw), 8):
        encoded.append(0)  # eight literal tokens
        encoded.extend(raw[offset:offset + 8])
    return b"\x01" + struct.pack("<H", 0xB000 | (len(encoded) - 1)) + bytes(encoded)


def _vba_cfb() -> bytes:
    def record(kind: int, body: bytes) -> bytes:
        return struct.pack("<HI", kind, len(body)) + body

    directory_source = b"".join((
        record(0x0003, struct.pack("<H", 1252)),
        record(0x000F, struct.pack("<H", 1)),
        record(0x0019, b"Module1"),
        record(0x001A, b"Module1"),
        record(0x0031, struct.pack("<I", 0)),
        record(0x0021, b""), record(0x002B, b""), record(0x0010, b""),
    ))
    module_source = (
        b'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n'
        b'x = StrReverse("exe.dmc")\r\nShell "cmd.exe /c whoami"\r\nEnd Sub\r\n'
    )
    streams = (_vba_compress(directory_source), _vba_compress(module_source))
    header = bytearray(512)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<H", header, 0x18, 0x3E)
    struct.pack_into("<HHHH", header, 0x1A, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, 1)
    struct.pack_into("<I", header, 0x38, 1)  # keep these small streams in regular FAT sectors
    struct.pack_into("<I", header, 0x3C, EOC)
    struct.pack_into("<I", header, 0x44, EOC)
    struct.pack_into("<I", header, 0x4C, 0)
    for offset in range(0x50, 512, 4):
        struct.pack_into("<I", header, offset, FREE)
    fat = [FREE] * 128
    fat[0], fat[1], fat[2], fat[3] = FAT, EOC, EOC, EOC
    directory = (
        _directory_entry("Root Entry", 5, child=1)
        + _directory_entry("VBA", 1, child=2)
        + _directory_entry("dir", 2, right=3, start=2, size=len(streams[0]))
        + _directory_entry("Module1", 2, start=3, size=len(streams[1]))
    )
    return (
        bytes(header) + struct.pack("<128I", *fat) + directory
        + streams[0].ljust(512, b"\0") + streams[1].ljust(512, b"\0")
    )


def _rtf(*, odd_hex: bool = False, truncate: bool = False) -> bytes:
    payload = b"PAYLOAD"
    native = _native(payload, package=True)
    values = (b"Package\0", b"\0", b"\0")
    ole1 = (
        b"\0" * 4 + struct.pack("<I", 2)
        + b"".join(struct.pack("<I", len(value)) + value for value in values)
        + struct.pack("<I", len(native)) + native
    )
    encoded = ole1.hex().encode() + (b"f" if odd_hex else b"")
    data = b"{\\rtf1{\\object\\objclass Package {\\*\\objdata " + encoded + b"}}}"
    return data[:-1] if truncate else data


def test_macro_source_static_deobfuscation_and_shape_declines():
    source = '''Sub AutoOpen()
value = StrReverse("exe.dmc")
Shell "cmd.exe /c whoami"
End Sub'''
    macro = D.decode_macro_source(source, name="Module1", language="vba")
    assert macro is not None
    assert macro.autoexec == ("AutoOpen",)
    assert macro.decoded == ("cmd.exe",)
    assert macro.commands == ("cmd.exe /c whoami",)
    assert "str_reverse" in macro.techniques

    xlm = D.decode_macro_source('=EXEC("cmd.exe /c whoami")', language="xlm")
    assert xlm is not None and xlm.language == "xlm"
    assert D.decode_macro_source("ordinary prose") is None
    assert D.decode_macro_source("=EXEC(1)", language="javascript") is None
    assert D.decode_macro_source("Sub A()\x00\nEnd Sub") is None


def test_pdf_object_graph_actions_embeddings_revisions_and_corruption_declines():
    report = D.decode_pdf(_pdf())
    assert report is not None
    assert report.version == "1.7" and report.object_count == 6
    assert len(report.revisions) == 1
    assert ("6 0", "4 0") in report.reference_edges
    assert report.findings == (D.Finding("javascript", "app.alert(1)", "object 5 0"),)
    assert len(report.embedded) == 1 and report.embedded[0].data == b"PAYLOAD"
    assert {"maldoc", "pdf_revisions", "pypdf"} <= set(report.cross_checks)

    incremental = D.decode_pdf(pdf_revisions._build_incremental_pdf())
    assert incremental is not None and len(incremental.revisions) == 3
    broken = bytearray(pdf_revisions._build_incremental_pdf())
    marker = broken.rfind(b"/Prev ") + len(b"/Prev ")
    while marker < len(broken) and chr(broken[marker]).isdigit():
        broken[marker] = ord("9")
        marker += 1
    assert D.decode_pdf(bytes(broken)) is None
    bad_generation = _pdf().replace(b"/F 4 0 R", b"/F 4 1 R")
    assert D.decode_pdf(bad_generation) is None
    assert D.decode_pdf(_pdf(embedded_filter=b"UnsupportedDecode")) is None
    assert D.decode_pdf(_pdf()[:-6]) is None
    assert D.decode_pdf(b"%PDF-1.7\n%%EOF\n") is None


def test_ooxml_relationship_closure_xlm_embedded_and_corruption_declines():
    report = D.decode_ooxml(_ooxml())
    assert report is not None
    assert report.family == "excel" and report.main_part == "xl/workbook.xml"
    assert len(report.relationships) == 4
    assert any(item.kind == "external_relationship" for item in report.findings)
    assert len(report.macros) == 1 and report.macros[0].language == "xlm"
    assert len(report.embedded) == 1 and report.embedded[0].data == b"PAYLOAD"
    assert {"zipfile", "maldoc", "officevba"} <= set(report.cross_checks)

    assert D.decode_ooxml(_ooxml(bad_target=True)) is None
    assert D.decode_ooxml(_ooxml(traversal=True)) is None
    assert D.decode_ooxml(_ooxml(doctype=True)) is None
    assert D.decode_ooxml(_ooxml(invalid_mode=True)) is None
    assert D.decode_ooxml(_ooxml(undeclared=True)) is None
    assert D.decode_ooxml(b"PK\x03\x04broken") is None


def test_ole_stream_inventory_native_payload_cross_checks_and_corruption_declines():
    report = D.decode_ole(_cfb())
    assert report is not None
    assert report.streams[0].path == "\x01Ole10Native"
    assert report.streams[0].size == 4096
    assert report.embedded[0].name == "drop.bin"
    assert report.embedded[0].data == b"PAYLOAD"
    assert {"officevba", "maldoc", "olefile"} <= set(report.cross_checks)
    assert {item.kind for item in report.findings} == {"package_source_path", "package_temp_path"}

    vba = D.decode_ole(_vba_cfb())
    assert vba is not None and len(vba.macros) == 1
    assert vba.macros[0].name == "Module1"
    assert vba.macros[0].autoexec == ("AutoOpen",)
    assert vba.macros[0].decoded == ("cmd.exe",)
    assert vba.macros[0].commands == ("cmd.exe /c whoami",)
    assert "officevba-macro" in vba.cross_checks

    equation = D.decode_ole(_cfb(stream_name="Equation Native"))
    assert equation is not None
    assert D.Finding("equation_stream", "present", "Equation Native") in equation.findings
    assert not any(item.kind == "cve" for item in equation.findings)

    assert D.decode_ole(_cfb(corrupt_chain=True)) is None
    assert D.decode_ole(_cfb()[:-512]) is None
    assert D.decode_ole(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(504)) is None


def test_vba_cross_reader_disagreement_and_macro_cap_decline(monkeypatch):
    monkeypatch.setattr(D._officevba, "macro_text", lambda *args, **kwargs: None)
    assert D.decode_ole(_vba_cfb()) is None
    monkeypatch.undo()
    monkeypatch.setattr(D, "MAX_MACROS", 0)
    assert D.decode_ole(_vba_cfb()) is None


def test_rtf_strict_objdata_package_carving_and_corruption_declines():
    report = D.decode_rtf(_rtf())
    assert report is not None and report.object_count == 1
    assert report.classes == ("Package",)
    assert report.embedded[0].name == "drop.bin"
    assert report.embedded[0].data == b"PAYLOAD"
    assert not any(item.kind == "class_mismatch" for item in report.findings)

    assert D.decode_rtf(_rtf(odd_hex=True)) is None
    assert D.decode_rtf(_rtf(truncate=True)) is None
    assert D.decode_rtf(_rtf().replace(b"\\objdata ", b"\\objdata \\ignored ", 1)) is None
    assert D.decode_rtf(_rtf().replace(b"\\objdata ", b"\\objdata \\'00", 1)) is None
    assert D.decode_rtf(b"{\\rtf1{\\object{\\*\\objdata 00}}") is None
    assert D.decode_rtf(b"ordinary text") is None


def test_resource_and_type_gates_decline_without_partial_candidates(monkeypatch):
    monkeypatch.setattr(D, "MAX_DOCUMENT", 32)
    assert D.decode_pdf(_pdf()) is None
    assert D.decode_ooxml(_ooxml()) is None
    assert D.decode_ole(_cfb()) is None
    assert D.decode_rtf(_rtf()) is None
    assert D.decode_pdf(object()) is None
    assert D.decode_ooxml(None) is None
    assert D.decode_ole("not bytes") is None
    assert D.decode_rtf(bytearray()) is None
