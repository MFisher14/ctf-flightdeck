from __future__ import annotations

import io
import struct
import sys
import unicodedata
import zipfile
import zlib
from collections.abc import Sequence
from pathlib import Path

import pytest
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import text_metadata_stego as S  # noqa: E402
import pdf_revisions  # noqa: E402


def _bits(payload: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in payload)


def _unicode_tags(payload: bytes, *, prefix: bool = True) -> str:
    return (chr(0xE0001) if prefix else "") + "".join(chr(0xE0000 + byte) for byte in payload) + chr(0xE007F)


def _snow(payload: bytes) -> str:
    bits = _bits(payload + b"\0")
    bits += "0" * ((-len(bits)) % 3)
    values = [int(bits[offset:offset + 3], 2) for offset in range(0, len(bits), 3)]
    return "cover" + "\t" + "".join(" " * value + "\t" for value in values) + "\n"


def _snow_wrapped(payload: bytes, groups_per_line: int = 9) -> str:
    bits = _bits(payload + b"\0")
    bits += "0" * ((-len(bits)) % 3)
    groups = [" " * int(bits[offset:offset + 3], 2) + "\t" for offset in range(0, len(bits), 3)]
    lines = []
    for offset in range(0, len(groups), groups_per_line):
        lines.append(f"cover {len(lines)}" + "\t" + "".join(groups[offset:offset + groups_per_line]))
    return "\n".join(lines) + "\n"


def _image(fmt: str) -> bytes:
    output = io.BytesIO()
    image = Image.new("RGB", (3, 2), (31, 101, 193))
    image.save(output, format=fmt, quality=91, subsampling=0)
    return output.getvalue()


_FREE = 0xFFFFFFFF
_EOC = 0xFFFFFFFE
_FAT = 0xFFFFFFFD


def _directory_entry(name: str, entry_type: int, *, child: int = _FREE,
                     start: int = _EOC, size: int = 0) -> bytes:
    entry = bytearray(128)
    encoded = (name + "\0").encode("utf-16-le")
    entry[:len(encoded)] = encoded
    struct.pack_into("<H", entry, 64, len(encoded))
    entry[66] = entry_type
    entry[67] = 1
    struct.pack_into("<III", entry, 68, _FREE, _FREE, child)
    struct.pack_into("<I", entry, 116, start)
    struct.pack_into("<Q", entry, 120, size)
    return bytes(entry)


def _property_stream(*, corrupt: bool = False) -> bytes:
    stream = bytearray(4096)
    stream[:2] = b"\xfe\xff"
    struct.pack_into("<I", stream, 24, 1)
    base = 48
    struct.pack_into("<I", stream, 44, base)
    title = b"CSCTF{ole_summary}\0"
    comments = b"CSCTF{ole_comments}\0"
    count = 3
    table_end = 8 + count * 8
    codepage_at = table_end
    title_at = codepage_at + 8
    comments_at = title_at + 8 + len(title)
    size = comments_at + 8 + len(comments)
    struct.pack_into("<II", stream, base, size if not corrupt else size + 8192, count)
    struct.pack_into("<II", stream, base + 8, 1, codepage_at)
    struct.pack_into("<II", stream, base + 16, 2, title_at)
    struct.pack_into("<II", stream, base + 24, 6, comments_at)
    struct.pack_into("<IH", stream, base + codepage_at, 2, 1252)
    struct.pack_into("<II", stream, base + title_at, 0x1E, len(title))
    stream[base + title_at + 8:base + title_at + 8 + len(title)] = title
    struct.pack_into("<II", stream, base + comments_at, 0x1E, len(comments))
    stream[base + comments_at + 8:base + comments_at + 8 + len(comments)] = comments
    return bytes(stream)


def _ole_summary(*, corrupt_property_set: bool = False, corrupt_chain: bool = False) -> bytes:
    summary = _property_stream(corrupt=corrupt_property_set)
    header = bytearray(512)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<H", header, 0x18, 0x3E)
    struct.pack_into("<HHHH", header, 0x1A, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, 1)
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<I", header, 0x3C, _EOC)
    struct.pack_into("<I", header, 0x44, _EOC)
    struct.pack_into("<I", header, 0x4C, 0)
    for offset in range(0x50, 512, 4):
        struct.pack_into("<I", header, offset, _FREE)
    fat = [_FREE] * 128
    fat[0], fat[1] = _FAT, _EOC
    for sector in range(2, 10):
        fat[sector] = sector + 1 if sector < 9 else _EOC
    if corrupt_chain:
        fat[5] = 3
    directory = (
        _directory_entry("Root Entry", 5, child=1)
        + _directory_entry("\x05SummaryInformation", 2, start=2, size=4096)
        + bytes(256)
    )
    return bytes(header) + struct.pack("<128I", *fat) + directory + summary


def _zip(*, archive_comment: bytes = b"", member_comment: bytes = b"") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("evidence.txt")
        info.compress_type = zipfile.ZIP_DEFLATED
        info.comment = member_comment
        archive.writestr(info, b"ordinary member contents")
        archive.comment = archive_comment
    return output.getvalue()


def _corrupt_zip_member(blob: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        info = archive.getinfo(name)
        header = info.header_offset
        name_length, extra_length = struct.unpack_from("<HH", blob, header + 26)
        start = header + 30 + name_length + extra_length
        assert info.compress_size > 2
    output = bytearray(blob)
    output[start + info.compress_size // 2] ^= 0x40
    return bytes(output)


def _zip64_comment() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        with archive.open("zip64.txt", "w", force_zip64=True) as member:
            member.write(b"ZIP64 member")
        archive.comment = b"CSCTF{zip64_comment}"
    return output.getvalue()


class _Unseekable(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *_args, **_kwargs):
        raise io.UnsupportedOperation("unseekable")


def _descriptor_zip() -> bytes:
    output = _Unseekable()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("descriptor.txt", b"written through a data descriptor")
        archive.comment = b"CSCTF{descriptor_comment}"
    return output.getvalue()


def _encrypted_flags(blob: bytes) -> bytes:
    output = bytearray(blob)
    local = output.find(b"PK\x03\x04")
    central = output.find(b"PK\x01\x02")
    assert local >= 0 and central >= 0
    struct.pack_into("<H", output, local + 6, struct.unpack_from("<H", output, local + 6)[0] | 1)
    struct.pack_into("<H", output, central + 8, struct.unpack_from("<H", output, central + 8)[0] | 1)
    return bytes(output)


def _pdf(*, xmp_filter: bytes | None = None, indirect_types: bool = False) -> bytes:
    output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}

    def add(number: int, body: bytes) -> None:
        offsets[number] = len(output)
        output.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")

    xmp = b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><secret>CSCTF{xmp_field}</secret></x:xmpmeta>'
    xmp_body = zlib.compress(xmp) if xmp_filter == b"FlateDecode" else xmp
    type_value = b"7 0 R" if indirect_types else b"/Metadata"
    subtype_value = b"8 0 R" if indirect_types else b"/XML"
    add(1, b"<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>")
    add(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Annots [6 0 R] >>")
    add(4, b"<< /Title (CSCTF{pdf_info}) /Author (analyst) >>")
    filter_value = b" /Filter /" + xmp_filter if xmp_filter else b""
    add(5, b"<< /Type " + type_value + b" /Subtype " + subtype_value + b" /Length "
        + str(len(xmp_body)).encode() + filter_value + b" >>\nstream\n" + xmp_body + b"\nendstream")
    add(6, b"<< /Type /Annot /Subtype /Text /Contents (CSCTF{pdf_note}) >>")
    if indirect_types:
        add(7, b"/Metadata")
        add(8, b"/XML")
    startxref = len(output)
    size = max(offsets) + 1
    output.extend(b"xref\n0 " + str(size).encode() + b"\n0000000000 65535 f \n")
    for number in range(1, size):
        output.extend(f"{offsets[number]:010d} 00000 n \n".encode())
    output.extend(
        b"trailer\n<< /Size " + str(size).encode() + b" /Root 1 0 R /Info 4 0 R >>\nstartxref\n"
        + str(startxref).encode() + b"\n%%EOF\n"
    )
    return bytes(output)


def _ooxml(*, corrupt_comment: bool = False, external: bool = False,
           traversal: bool = False, undeclared: bool = False, split_comment: bool = False) -> bytes:
    external_rel = (
        b'<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid/no-fetch" TargetMode="External"/>'
        if external else b""
    )
    comment_text = (
        b"<w:r><w:t>CSCTF{office_</w:t></w:r><w:r><w:t>comment}</w:t></w:r>"
        if split_comment else b"<w:r><w:t>CSCTF{office_comment}</w:t></w:r>"
    )
    parts = {
        "[Content_Types].xml": b'''<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="xml" ContentType="application/xml"/>
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
        </Types>''',
        "_rels/.rels": b'''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
        </Relationships>''',
        "word/document.xml": b'''<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p/></w:body></w:document>''',
        "word/_rels/document.xml.rels": b'''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>''' + external_rel + b'''</Relationships>''',
        "docProps/core.xml": b'''<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><!--CSCTF{office_xml_comment}--><dc:title>CSCTF{office_title}</dc:title><dc:creator>analyst</dc:creator></cp:coreProperties>''',
        "docProps/app.xml": b'''<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>CSCTF{office_company}</Company></Properties>''',
        "docProps/custom.xml": b'''<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property name="hidden"><vt:lpwstr>CSCTF{office_custom}</vt:lpwstr></property></Properties>''',
        "word/comments.xml": (
            b'''<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0"><w:p>''' + comment_text + b'''</w:p></w:comment></w:comments>'''
            if not corrupt_comment else
            b'''<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment>unterminated'''
        ),
    }
    if traversal:
        parts["../escape.xml"] = b"<escape/>"
    if undeclared:
        parts["word/hidden.xyz"] = b"hidden"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in parts.items():
            archive.writestr(name, body)
    return output.getvalue()


def test_zero_width_checked_channel_and_corrupt_declines():
    payload = b"CSCTF{zero_width}"
    encoded = "visible:" + "".join("\u200b" if bit == "0" else "\u200c" for bit in _bits(payload))
    found = S.decode_zero_width(encoded)
    assert found is not None and found.data == payload and found.method == "zero-width"
    assert S.decode_zero_width(encoded[:-1]) is None
    assert S.decode_zero_width(encoded + "\u200d") is None
    assert S.decode_zero_width("ordinary text") is None
    assert S.decode_zero_width(encoded, expected_crc32=(zlib.crc32(payload) ^ 1) & 0xFFFFFFFF) is None
    assert S.decode_zero_width(encoded, expected_crc32=zlib.crc32(payload) & 0xFFFFFFFF).data == payload
    assert S.decode_zero_width("\ud800" + encoded) is None
    assert S.decode_zero_width(b"\xed\xa0\x80" + encoded.encode()) is None


def test_unicode_tags_complete_runs_and_malformed_decline():
    first = b"CSCTF{tag_one}"
    second = b"plain tag text"
    carrier = "before" + _unicode_tags(first) + "middle" + _unicode_tags(second, prefix=False) + "after"
    assert [item.data for item in S.decode_unicode_tags(carrier)] == [first, second]
    assert S.decode_unicode_tags(_unicode_tags(first)[:-1]) == ()
    assert S.decode_unicode_tags(chr(0xE007F)) == ()
    assert S.decode_unicode_tags("no tag controls") == ()


def test_explicit_homoglyph_mapping_crc_and_ambiguity_declines():
    payload = b"CSCTF{homoglyph}"
    latin, cyrillic = "a", "\u0430"
    encoded = "cover:" + "".join(latin if bit == "0" else cyrillic for bit in _bits(payload))
    found = S.decode_homoglyphs(encoded, ((latin, cyrillic),))
    assert found is not None and found.data == payload
    assert S.decode_homoglyphs(encoded[:-1], ((latin, cyrillic),)) is None
    assert S.decode_homoglyphs(encoded, ((latin, cyrillic), (latin, "o"))) is None
    assert S.decode_homoglyphs(encoded, ((latin, cyrillic),), expected_crc32=0) is None
    assert S.decode_homoglyphs("ordinary cover", ((latin, cyrillic),)) is None
    # Exact code points, not normalization, carry the supplied bit semantics.
    fullwidth = "".join("A" if bit == "0" else "\uff21" for bit in _bits(payload))
    assert S.decode_homoglyphs(fullwidth, (("A", "\uff21"),)).data == payload


def test_trailing_whitespace_and_snow_are_complete_or_decline():
    payload = b"CSCTF{trailing_bits}"
    channel = "".join(" " if bit == "0" else "\t" for bit in _bits(payload))
    carrier = "line one" + channel[:64] + "\nline two" + channel[64:] + "\n"
    found = S.decode_whitespace_bits(carrier)
    assert found is not None and found.data == payload
    assert S.decode_whitespace_bits(carrier.replace("\n", "\r", 1)) is None
    assert S.decode_whitespace_bits(carrier[:-2] + "\n") is None
    assert S.decode_whitespace_bits("ordinary text\n") is None

    snow_payload = b"CSCTF{snow}"
    snow = _snow(snow_payload)
    decoded = S.decode_snow(snow)
    assert decoded is not None and decoded.data == snow_payload
    wrapped = S.decode_snow(_snow_wrapped(snow_payload))
    assert wrapped is not None and wrapped.data == snow_payload
    assert S.decode_snow(snow[:-3] + "\n") is None
    assert S.decode_snow("cover\t        \t\n") is None  # group exceeds seven spaces
    assert S.decode_snow("ordinary text\n") is None


def test_zip_comments_require_exact_valid_container_and_crc():
    blob = _zip(archive_comment=b"CSCTF{zip_archive_comment}", member_comment=b"CSCTF{member_comment}")
    found = S.extract_zip_comments(blob)
    assert [(item.field, item.data) for item in found] == [
        ("archive.comment", b"CSCTF{zip_archive_comment}"),
        ("member:evidence.txt:comment", b"CSCTF{member_comment}"),
    ]
    assert S.extract_zip_comments(_zip()) == ()
    assert S.extract_zip_comments(_corrupt_zip_member(blob, "evidence.txt")) == ()
    assert S.extract_zip_comments(blob + b"junk") == ()


def test_zip64_descriptors_encryption_duplicates_and_comment_lengths():
    zip64 = _zip64_comment()
    assert [item.data for item in S.extract_zip_comments(zip64)] == [b"CSCTF{zip64_comment}"]
    descriptor = _descriptor_zip()
    assert [item.data for item in S.extract_zip_comments(descriptor)] == [b"CSCTF{descriptor_comment}"]
    assert S.extract_zip_comments(_encrypted_flags(_zip(archive_comment=b"secret"))) == ()

    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        first = zipfile.ZipInfo("caf\u00e9.txt")
        first.comment = b"first"
        archive.writestr(first, b"one")
        second = zipfile.ZipInfo("cafe\u0301.txt")
        second.comment = b"second"
        archive.writestr(second, b"two")
    assert unicodedata.normalize("NFC", "cafe\u0301.txt") == "caf\u00e9.txt"
    assert S.extract_zip_comments(duplicate.getvalue()) == ()

    bad_length = bytearray(_zip(archive_comment=b"abc"))
    eocd = bad_length.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<H", bad_length, eocd + 20, 4)
    assert S.extract_zip_comments(bytes(bad_length)) == ()


def test_pdf_info_xmp_and_annotation_metadata_require_strict_pdf():
    blob = _pdf()
    found = S.extract_pdf_metadata(blob)
    values = {(item.field, item.data) for item in found}
    assert ("Info.title", b"CSCTF{pdf_info}") in values
    assert ("XMP", b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><secret>CSCTF{xmp_field}</secret></x:xmpmeta>') in values
    assert ("annotation.Contents", b"CSCTF{pdf_note}") in values
    corrupt = blob.replace(b"startxref\n", b"startxref\n999999", 1)
    assert S.extract_pdf_metadata(corrupt) == ()
    assert S.extract_pdf_metadata(blob[:-8]) == ()
    assert S.extract_pdf_metadata(b"%PDF-1.7\nCSCTF{decoy}\n%%EOF") == ()


def test_pdf_filtered_indirect_and_incremental_metadata_edges():
    expected_xmp = b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><secret>CSCTF{xmp_field}</secret></x:xmpmeta>'
    filtered = S.extract_pdf_metadata(_pdf(xmp_filter=b"FlateDecode"))
    assert any(item.field == "XMP" and item.data == expected_xmp for item in filtered)
    indirect = S.extract_pdf_metadata(_pdf(indirect_types=True))
    assert any(item.field == "XMP" and item.data == expected_xmp for item in indirect)
    assert S.extract_pdf_metadata(_pdf(xmp_filter=b"UnsupportedDecode")) == ()

    incremental = pdf_revisions._build_incremental_pdf()
    assert S.extract_pdf_metadata(incremental) == ()
    broken = bytearray(incremental)
    marker = broken.rfind(b"/Prev ") + len(b"/Prev ")
    assert marker >= len(b"/Prev ")
    while marker < len(broken) and chr(broken[marker]).isdigit():
        broken[marker] = ord("9")
        marker += 1
    assert S.extract_pdf_metadata(bytes(broken)) == ()


def test_ooxml_properties_comments_and_corruption_decline():
    blob = _ooxml()
    found = S.extract_office_metadata(blob)
    values = {item.data for item in found}
    assert b"CSCTF{office_title}" in values
    assert b"CSCTF{office_company}" in values
    assert b"CSCTF{office_custom}" in values
    assert b"CSCTF{office_comment}" in values
    assert b"CSCTF{office_xml_comment}" in values
    assert b"hidden" in values  # custom-property name attribute
    assert S.extract_office_metadata(_ooxml(corrupt_comment=True)) == ()
    assert S.extract_office_metadata(_corrupt_zip_member(blob, "word/comments.xml")) == ()
    split = S.extract_office_metadata(_ooxml(split_comment=True))
    assert b"CSCTF{office_comment}" in {item.data for item in split}
    assert S.extract_office_metadata(_ooxml(external=True))
    assert S.extract_office_metadata(_ooxml(traversal=True)) == ()
    assert S.extract_office_metadata(_ooxml(undeclared=True)) == ()
    routed = S.extract_document_metadata(blob)
    assert {item.data for item in routed} >= values


def test_legacy_ole_summary_metadata_requires_complete_property_graph():
    blob = _ole_summary()
    found = S.extract_ole_metadata(blob)
    values = {item.data for item in found}
    assert b"CSCTF{ole_summary}" in values
    assert b"CSCTF{ole_comments}" in values
    assert {item.data for item in S.extract_document_metadata(blob)} == values
    assert S.extract_ole_metadata(_ole_summary(corrupt_property_set=True)) == ()
    overlap = bytearray(blob)
    stream_start, base = 3 * 512, 48
    title_relative = struct.unpack_from("<I", overlap, stream_start + base + 20)[0]
    struct.pack_into("<I", overlap, stream_start + base + 28, title_relative)
    assert S.extract_ole_metadata(bytes(overlap)) == ()
    assert S.extract_ole_metadata(_ole_summary(corrupt_chain=True)) == ()
    assert S.extract_ole_metadata(blob[:-512]) == ()


def test_appended_data_and_composed_polyglot_checks():
    png = _image("PNG")
    tail = b"CSCTF{appended_bytes}"
    found = S.extract_appended_data(png + tail)
    assert found is not None and found.data == tail and found.carrier == "png"
    assert S.extract_appended_data(png) is None
    assert S.extract_appended_data(png + b"\0 \r\n") is None
    assert S.extract_appended_data(png[:-5] + tail) is None
    pdf_tail = S.extract_appended_data(_pdf() + tail)
    assert pdf_tail is not None and pdf_tail.data == tail and pdf_tail.carrier == "pdf"

    jpeg, archive = _image("JPEG"), _zip(archive_comment=b"comment")
    polyglot = S.extract_polyglot(jpeg + archive)
    assert polyglot is not None
    assert polyglot.formats == ("jpeg", "zip")
    assert [part.data for part in polyglot.parts] == [jpeg, archive]
    assert S.extract_polyglot(jpeg + archive[:-5]) is None
    assert S.extract_polyglot(b"not a container") is None
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as outer:
        outer.writestr("image.png", png)
    assert S.extract_polyglot(nested.getvalue()) is None


@pytest.mark.parametrize("bad", [None, 1, True, 1.5, object(), [], {}, {"x"}, lambda: None])
def test_public_decoders_decline_wrong_types_without_exceptions(bad):
    assert S.decode_zero_width(bad) is None
    assert S.decode_unicode_tags(bad) == ()
    assert S.decode_homoglyphs(bad, (("a", "\u0430"),)) is None
    assert S.decode_whitespace_bits(bad) is None
    assert S.decode_snow(bad) is None
    assert S.decode_text_channels(bad) == ()
    assert S.extract_zip_comments(bad) == ()
    assert S.extract_pdf_metadata(bad) == ()
    assert S.extract_office_metadata(bad) == ()
    assert S.extract_ole_metadata(bad) == ()
    assert S.extract_document_metadata(bad) == ()
    assert S.extract_appended_data(bad) is None
    assert S.extract_polyglot(bad) is None


def test_keyword_types_and_resource_caps_fail_closed(monkeypatch: pytest.MonkeyPatch):
    encoded = "".join("\u200b" if bit == "0" else "\u200c" for bit in _bits(b"CSCTF{types}"))
    assert S.decode_zero_width(encoded, bit_order=[]) is None
    assert S.decode_zero_width(encoded, expected_crc32=True) is None
    assert S.decode_zero_width(encoded, zero=[]) is None
    assert S.decode_whitespace_bits("x \t\n", zero=[]) is None
    assert S.decode_homoglyphs(encoded, None) is None
    assert S.decode_homoglyphs(encoded, (("a", "aa"),)) is None

    class BrokenLength(Sequence):
        def __len__(self):
            raise RuntimeError("broken length")

        def __getitem__(self, _index):
            raise RuntimeError("broken item")

    class BrokenItem(Sequence):
        def __len__(self):
            return 1

        def __getitem__(self, _index):
            raise RuntimeError("broken item")

    assert S.decode_homoglyphs(encoded, BrokenLength()) is None
    assert S.decode_homoglyphs(encoded, BrokenItem()) is None

    monkeypatch.setattr(S, "MAX_TEXT_CHARS", 8)
    assert S.decode_zero_width(encoded) is None
    assert S.decode_unicode_tags(_unicode_tags(b"CSCTF{too_big}")) == ()


def test_result_caps_return_no_prefix(monkeypatch: pytest.MonkeyPatch):
    comments = _zip(archive_comment=b"one", member_comment=b"two")
    monkeypatch.setattr(S, "MAX_FIELDS", 1)
    assert S.extract_zip_comments(comments) == ()
    assert S.extract_pdf_metadata(_pdf()) == ()
    assert S.extract_office_metadata(_ooxml()) == ()
    assert S.decode_unicode_tags(_unicode_tags(b"first") + _unicode_tags(b"second")) == ()

    monkeypatch.setattr(S, "MAX_PAYLOAD", 8)
    assert S.extract_appended_data(_image("PNG") + b"long hidden payload") is None


def test_zip_bomb_ratio_declines_without_comment_prefix():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("compressible.bin", b"A" * (1 << 20))
        archive.comment = b"CSCTF{must_not_leak_before_ratio_check}"
    assert S.extract_zip_comments(output.getvalue()) == ()


def test_random_and_ordinary_inputs_do_not_become_payloads():
    for size in range(1, 256):
        raw = bytes(((index * 73 + size * 19) & 0xFF) for index in range(size))
        assert S.decode_zero_width(raw) is None
        assert S.decode_unicode_tags(raw) == ()
        assert S.decode_whitespace_bits(raw) is None
        assert S.decode_snow(raw) is None
        assert S.extract_zip_comments(raw) == ()
        assert S.extract_pdf_metadata(raw) == ()
        assert S.extract_office_metadata(raw) == ()
        assert S.extract_ole_metadata(raw) == ()
        assert S.extract_appended_data(raw) is None
        assert S.extract_polyglot(raw) is None

    for index in range(1000):
        text = f"ordinary clean line {index}" + (" " * (index % 7)) + ("\t" * (index % 3)) + "\n"
        assert S.decode_zero_width(text) is None
        assert S.decode_unicode_tags(text) == ()
        assert S.decode_whitespace_bits(text) is None
        assert S.decode_snow(text) is None
