"""Independent vectors and deterministic malformed-input regressions.

Unicode mapping: Unicode 16.0 UTS #51 emoji-sequences.txt / Tags code chart.
SNOW bit order/framing: author's snow-20130616 encode.c, main.c, description:
https://darkside.com.au/snow/description.html
https://darkside.com.au/snow/snow-20130616.tar.gz
Office/ZIP/image oracles are python-docx, olefile, zipfile, and Pillow.
"""
from __future__ import annotations

import io
import random
import struct
from datetime import datetime, timezone
from functools import lru_cache
import zipfile
import zlib

from docx import Document
import olefile
from PIL import Image
import pytest

import text_metadata_stego as target


PAYLOAD = b"CSCTF{document_vector}"
# Independent fixed ASCII bit vector for b'CSCTF{A}'; no engine encoder involved.
FLAG_BITS = "0100001101010011010000110101010001000110011110110100000101111101"


def _channel(alphabet, bits=FLAG_BITS):
    return "".join(alphabet[int(bit)] for bit in bits)


@lru_cache(maxsize=1)
def docx_bytes():
    document = Document()
    document.add_paragraph("benign synthetic document")
    document.core_properties.title = "CSCTF{docx_title}"
    document.core_properties.author = "Mélanie Vector"
    document.core_properties.subject = "Parser test"
    document.core_properties.comments = "CSCTF{docx_comment}"
    document.core_properties.created = datetime(2020, 1, 2, tzinfo=timezone.utc)
    document.core_properties.modified = datetime(2020, 1, 2, tzinfo=timezone.utc)
    stream = io.BytesIO()
    document.save(stream)
    # Stable ZIP transport timestamps keep mutation positions reproducible.
    final = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(stream.getvalue())) as src, zipfile.ZipFile(final, "w") as dst:
        for original in src.infolist():
            info = zipfile.ZipInfo(original.filename, (2020, 1, 2, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(info, src.read(original))
    return final.getvalue()


def zip_bytes():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo("memo.txt", (2020, 1, 2, 0, 0, 0))
        info.comment = b"CSCTF{member_comment}\xff"
        archive.writestr(info, b"static evidence")
        archive.comment = b"CSCTF{archive_comment}\x00"
    return stream.getvalue()


def image_bytes(format):
    stream = io.BytesIO()
    Image.new("RGB", (2, 2), (77, 31, 199)).save(stream, format=format)
    return stream.getvalue()


def test_vector_zero_width_and_survey_exact_ascii():
    carrier = "visible cover " + _channel(("\u200b", "\u200c")) + " end"
    # The literal ASCII vector is checked with an independent stdlib conversion.
    expected = int(FLAG_BITS, 2).to_bytes(8, "big")
    assert expected == b"CSCTF{A}"
    result = target.decode_zero_width(carrier)
    assert result is not None and result.data == expected
    assert result.crc32 == zlib.crc32(expected)
    survey = target.decode_text_channels(carrier)
    assert [(item.method, item.data) for item in survey] == [("zero-width", expected)]


def test_vector_bit_orders_crc_and_homoglyph_alphabet():
    expected = bytes.fromhex("0055aaff")
    bits = "00000000101010100101010111111111"  # each octet transmitted LSB first
    crc = zlib.crc32(expected)
    zero_width = _channel(("\u2060", "\u2063"), bits)
    result = target.decode_zero_width(zero_width, zero="\u2060", one="\u2063",
                                      bit_order="lsb", expected_crc32=crc)
    assert result is not None and result.data == expected
    homoglyph = _channel(("a", "\u0430"), bits)
    result = target.decode_homoglyphs(homoglyph, (("a", "\u0430"),),
                                     bit_order="lsb", expected_crc32=crc)
    assert result is not None and result.data == expected
    assert target.decode_homoglyphs(homoglyph, (("a", "\u0430"),),
                                   bit_order="lsb", expected_crc32=crc ^ 1) is None


def test_vector_whitespace_msb_and_crlf():
    rows = ["cover" + _channel((" ", "\t"), FLAG_BITS[i:i + 8]) for i in range(0, 64, 8)]
    result = target.decode_whitespace_bits("\r\n".join(rows) + "\r\n")
    assert result is not None and result.data == b"CSCTF{A}"


@pytest.mark.parametrize("sequence,expected", [
    ((0x1F3F4, 0xE0067, 0xE0062, 0xE0065, 0xE006E, 0xE0067, 0xE007F), b"gbeng"),
    ((0x1F3F4, 0xE0067, 0xE0062, 0xE0073, 0xE0063, 0xE0074, 0xE007F), b"gbsct"),
    ((0x1F3F4, 0xE0067, 0xE0062, 0xE0077, 0xE006C, 0xE0073, 0xE007F), b"gbwls"),
])
def test_vector_unicode_published_subdivision_sequences(sequence, expected):
    # https://www.unicode.org/Public/emoji/16.0/emoji-sequences.txt
    result = target.decode_unicode_tags("".join(map(chr, sequence)))
    assert len(result) == 1 and result[0].data == expected
    assert result[0].crc32 == zlib.crc32(expected)


def test_vector_zip_comments_against_stdlib():
    raw = zip_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as oracle:
        assert oracle.testzip() is None
        expected = {"archive.comment": oracle.comment,
                    "member:memo.txt:comment": oracle.getinfo("memo.txt").comment}
    actual = target.extract_zip_comments(raw)
    assert {item.field: item.data for item in actual} == expected
    assert {item.field: item.data for item in target.extract_document_metadata(raw)} == expected


def test_vector_docx_properties_against_python_docx():
    raw = docx_bytes()
    oracle = Document(io.BytesIO(raw)).core_properties
    expected = {"title": oracle.title, "creator": oracle.author,
                "subject": oracle.subject, "description": oracle.comments}
    actual = {item.field: item.data for item in target.extract_office_metadata(raw)}
    for name, value in expected.items():
        assert actual["docProps/core.xml:" + name + "[1]"] == value.encode("utf-8")
    routed = target.extract_document_metadata(raw)
    assert {item.field: item.data for item in routed} == actual


def summary_property_stream():
    """MS-OLEPS v0 SummaryInformation: codepage, title, author, comments.

    Independently serialize typed values and section-relative offsets, then let
    olefile parse them. Specs: MS-OLEPS PropertySetStream, SummaryInformation.
    """
    values = {1: struct.pack("<IhH", 2, 1252, 0)}
    for pid, text in ((2, "CSCTF{ole_title}"), (4, "Vector Author"), (6, "CSCTF{ole_comment}")):
        raw = text.encode("cp1252") + b"\0"
        item = struct.pack("<II", 30, len(raw)) + raw
        values[pid] = item + bytes(-len(item) % 4)
    offset = 8 + 8 * len(values)
    table, data = bytearray(), bytearray()
    for pid, value in values.items():
        table.extend(struct.pack("<II", pid, offset))
        data.extend(value)
        offset += len(value)
    # FMTID_SummaryInformation in little-endian GUID wire representation.
    fmtid = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
    header = struct.pack("<HHI16sI", 0xFFFE, 0, 0x00020006, bytes(16), 1)
    return header + fmtid + struct.pack("<I", 48) + struct.pack("<II", offset, len(values)) + table + data


def test_vector_ole_properties_against_olefile():
    from test_harden_doc_office import make_cfb
    raw = make_cfb({"\x05SummaryInformation": summary_property_stream()})
    with olefile.OleFileIO(io.BytesIO(raw)) as oracle:
        props = oracle.getproperties("\x05SummaryInformation")
    expected = {"title": props[2], "author": props[4], "comments": props[6]}
    actual = {item.field: item.data for item in target.extract_ole_metadata(raw)}
    for name, value in expected.items():
        assert actual["SummaryInformation." + name] == value
    assert {item.field: item.data for item in target.extract_document_metadata(raw)} == actual


def test_vector_appended_data_and_polyglot_against_real_containers():
    png, jpeg, archive = image_bytes("PNG"), image_bytes("JPEG"), zip_bytes()
    with Image.open(io.BytesIO(png)) as oracle:
        oracle.verify()
    with Image.open(io.BytesIO(jpeg)) as oracle:
        oracle.verify()
    with zipfile.ZipFile(io.BytesIO(archive)) as oracle:
        assert oracle.testzip() is None
    result = target.extract_appended_data(png + PAYLOAD)
    assert result is not None and result.data == PAYLOAD
    assert result.carrier == "png" and result.crc32 == zlib.crc32(PAYLOAD)
    polyglot = target.extract_polyglot(jpeg + archive)
    assert polyglot is not None and polyglot.formats == ("jpeg", "zip")
    assert [part.data for part in polyglot.parts] == [jpeg, archive]


def _snow_reference(payload):
    """Direct independent rendering of author's encode.c, one unwrapped line.

    main.c writes each byte MSB-first; encode_write_value reverses each 3-bit
    word; encode_append_whitespace separates positive runs with a tab, uses a
    single tab for zero, and does not add a separator after a final positive run.
    SNOW does NOT append a NUL byte to messages.
    """
    stream = "".join(format(byte, "08b") for byte in payload)
    stream += "0" * (-len(stream) % 3)
    out, needs_tab = "cover\t", False
    for i in range(0, len(stream), 3):
        count = int(stream[i:i + 3][::-1], 2)
        if needs_tab:
            out += "\t"
        out += " " * count if count else "\t"
        needs_tab = count != 0
    return out + "\n"


def test_vector_snow_author_reference():
    # Oracle is the author-published encoder algorithm, not the engine's inverse.
    result = target.decode_snow(_snow_reference(PAYLOAD))
    assert result is not None and result.data == PAYLOAD


@pytest.mark.parametrize("payload", [b"plain text", b"plain texts", b"plain texts!", PAYLOAD])
def test_snow_author_framing_and_zero_padding(payload):
    # The three consecutive lengths cover zero, one, and two packing bits.
    # A positive final group has no final tab; a zero group is itself one tab.
    for ending in ("\n", "\r\n"):
        carrier = _snow_reference(payload).replace("\n", ending)
        result = target.decode_snow("unused cover     " + ending + carrier)
        assert result is not None and result.data == payload
        assert result.crc32 == zlib.crc32(payload)


def test_snow_author_wraps_without_repeating_start_marker():
    bits = "".join(format(byte, "08b") for byte in PAYLOAD)
    bits += "0" * (-len(bits) % 3)
    counts = [int(bits[i:i + 3][::-1], 2) for i in range(0, len(bits), 3)]
    lines = []
    for start in range(0, len(counts), 9):
        run, needs_tab = "", False
        for count in counts[start:start + 9]:
            if needs_tab:
                run += "\t"
            run += " " * count if count else "\t"
            needs_tab = count != 0
        lines.append("cover" + ("\t" if start == 0 else "") + run)
    result = target.decode_snow("\n".join(lines) + "\n")
    assert result is not None and result.data == PAYLOAD


@pytest.mark.parametrize("width", [9, 1000])
@pytest.mark.parametrize("payload", [PAYLOAD, b"Ayls"])
def test_snow_legacy_msb_nul_format_remains_readable(width, payload):
    # Previous public behavior supports this nonstandard variant. Serialize it
    # directly from the specified payload, independently of either decoder.
    # Ayls is ambiguous: the standard interpretation also looks like UTF-8.
    # Keep the previously supported, more restrictive framing's result.
    bits = "".join(format(byte, "08b") for byte in payload + b"\0")
    bits += "0" * (-len(bits) % 3)
    groups = [" " * int(bits[i:i + 3], 2) + "\t" for i in range(0, len(bits), 3)]
    carrier = "\n".join("cover\t" + "".join(groups[i:i + width])
                        for i in range(0, len(groups), width)) + "\n"
    result = target.decode_snow(carrier)
    assert result is not None and result.data == payload


def test_snow_author_rejects_nonzero_packing_bits():
    # Eleven bytes leave two unused bits. Flip the last padding bit before
    # rendering the final group; no change to the independently known payload.
    carrier = _snow_reference(b"plain texts")
    assert carrier.endswith("\t \n")  # final bit group 100 -> one space
    assert target.decode_snow(carrier[:-2] + "     \n") is None


PUBLIC_READERS = (
    ("decode_zero_width", lambda data: target.decode_zero_width(data)),
    ("decode_unicode_tags", lambda data: target.decode_unicode_tags(data)),
    ("decode_homoglyphs", lambda data: target.decode_homoglyphs(data, (("a", "\u0430"),))),
    ("decode_whitespace_bits", lambda data: target.decode_whitespace_bits(data)),
    ("decode_snow", lambda data: target.decode_snow(data)),
    ("decode_text_channels", lambda data: target.decode_text_channels(data)),
    ("extract_zip_comments", lambda data: target.extract_zip_comments(data)),
    ("extract_pdf_metadata", lambda data: target.extract_pdf_metadata(data)),
    ("extract_office_metadata", lambda data: target.extract_office_metadata(data)),
    ("extract_ole_metadata", lambda data: target.extract_ole_metadata(data)),
    ("extract_document_metadata", lambda data: target.extract_document_metadata(data)),
    ("extract_appended_data", lambda data: target.extract_appended_data(data)),
    ("extract_polyglot", lambda data: target.extract_polyglot(data)),
)


def _malformed_bytes():
    rng = random.Random(0xD0C2026)
    yield b""
    for length in (1, 2, 3, 7, 15, 31, 64, 127, 255, 511):
        yield b"\xff" * length
        yield rng.randbytes(length)
    for magic in (b"%PDF-1.7\n", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1")):
        for end in range(len(magic) + 1):
            yield magic[:end]
        for length in (0, 1, 7, 31, 100):
            yield magic + rng.randbytes(length)
        for length in (512, 1024):
            yield magic + bytes(length - len(magic))
            yield magic + b"\xff" * (length - len(magic))


@pytest.mark.parametrize("name,reader", PUBLIC_READERS, ids=[name for name, _ in PUBLIC_READERS])
def test_fuzz_all_public_readers_no_declared_exception(name, reader):
    # This engine explicitly promises None/empty and declares no exception class.
    for data in _malformed_bytes():
        assert reader(data) in (None, ()), (name, data.hex())
    for data in (None, 17, {}, [], "\ud800", memoryview(b"\xff")):
        assert reader(data) in (None, ()), (name, repr(data))


@pytest.mark.parametrize("name,reader", PUBLIC_READERS, ids=[name for name, _ in PUBLIC_READERS])
def test_fuzz_valid_containers_truncated_and_bit_flipped(name, reader):
    from test_harden_doc_office import make_cfb
    from test_harden_doc_pdf import build_classic_pdf
    pdf, _ = build_classic_pdf()
    originals = (zip_bytes(), docx_bytes(), pdf,
                 make_cfb({"\x05SummaryInformation": summary_property_stream()}), image_bytes("PNG"))
    for data in originals:
        for end in sorted({0, 1, 4, 8, 15, 31, len(data) // 2, len(data) - 1}):
            result = reader(data[:end])
            assert result is None or isinstance(result, (tuple, target.HiddenPayload, target.PolyglotPayload))
        for position in sorted({0, 3, 7, 15, len(data) // 2, len(data) - 1}):
            mutated = bytearray(data)
            mutated[position] ^= 0x80
            result = reader(bytes(mutated))
            # A changed field may remain valid; this fuzz check is the exception
            # contract, not an assertion that every mutation must be rejected.
            assert result is None or isinstance(result, (tuple, target.HiddenPayload, target.PolyglotPayload))


def test_invalid_unicode_channel_crc_and_structure_fail_closed():
    valid = _channel(("\u200b", "\u200c"))
    for malformed in (valid[:-1], "\u200b" * 64, valid + "\u200d", "\ud800" + valid):
        assert target.decode_zero_width(malformed) is None
    for bad_crc in (True, -1, 1 << 32, "bad", []):
        assert target.decode_zero_width(valid, expected_crc32=bad_crc) is None
    for pairs in (None, [], [("a", "a")], [("a", "\u0430"), ("a", "z")]):
        assert target.decode_homoglyphs("a\u0430", pairs) is None
