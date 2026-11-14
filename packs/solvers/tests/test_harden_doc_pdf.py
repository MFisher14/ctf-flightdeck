"""Independent PDF vectors and regressions for malformed-input contracts.

The writers below implement byte offsets directly from the PDF file-format model,
not from any tested engine. pypdf independently verifies pages, objects and streams.
PDF 1.7 reference, sections 3.4 (file structure) and 3.3 (filters):
https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf
"""
from __future__ import annotations

import base64
import io
import json
import random
import zlib

import pytest
from pypdf import PdfReader
from pypdf.generic import IndirectObject

import document_forensics as documents
import maldoc
import pdf_revisions as revisions
import text_metadata_stego as metadata


TITLE = "CSCTF{PDF_Metadata_Vector}"
CONTENT = b"BT /F1 12 Tf 20 40 Td (CSCTF{PDF_Text_Vector}) Tj ET"


def _objects(content=CONTENT, *, encoded=None, filter_name=None, title=TITLE):
    stored = content if encoded is None else encoded
    stream_dict = b"<< /Length " + str(len(stored)).encode()
    if filter_name:
        stream_dict += b" /Filter /" + filter_name.encode()
    stream_dict += b" >>\nstream\n" + stored + b"\nendstream"
    return {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        4: stream_dict,
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        6: b"<< /Title (" + title.encode() + b") /Author (Independent fixture) >>",
    }


def build_classic_pdf(content=CONTENT, *, encoded=None, filter_name=None, title=TITLE, indirect_length=False):
    """Return bytes and independently tracked offsets/objects for one PDF revision."""
    objects = _objects(content, encoded=encoded, filter_name=filter_name, title=title)
    if indirect_length:
        length = len(content if encoded is None else encoded)
        objects[4] = objects[4].replace(b"/Length " + str(length).encode(), b"/Length 7 0 R", 1)
        objects[7] = str(length).encode()
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    serialized = {}
    for number, body in objects.items():
        offsets[number] = len(out)
        obj = str(number).encode() + b" 0 obj\n" + body + b"\nendobj"
        serialized[number] = obj
        out.extend(obj + b"\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for number in objects:
        out.extend(f"{offsets[number]:010d} 00000 n \n".encode())
    out.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n".encode())
    out.extend(str(xref).encode() + b"\n%%EOF\n")
    return bytes(out), {"xref": xref, "offsets": offsets, "objects": serialized}


def build_incremental_pdf():
    """Return two-revision bytes, exact first prefix, and second-xref expectations."""
    original, first = build_classic_pdf()
    out = bytearray(original)
    changed = b"4 0 obj\n<< /Length 13 >>\nstream\nREVISION TWO!\nendstream\nendobj"
    offset = len(out)
    out.extend(changed + b"\n")
    xref = len(out)
    out.extend(f"xref\n4 1\n{offset:010d} 00000 n \n".encode())
    out.extend(f"trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev {first['xref']} >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(out), original, {"offset": offset, "xref": xref, "object": changed, "first": first}


def build_xref_stream_pdf(*, truncate_rows=0, compressed=False, truncate_checksum=False):
    objects = _objects()
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for number, body in objects.items():
        offsets[number] = len(out)
        out.extend(str(number).encode() + b" 0 obj\n" + body + b"\nendobj\n")
    offset = len(out)
    offsets[7] = offset
    rows = b"\x00" + (0).to_bytes(4, "big") + (65535).to_bytes(2, "big")
    rows += b"".join(b"\x01" + offsets[n].to_bytes(4, "big") + b"\x00\x00" for n in range(1, 8))
    if truncate_rows:
        rows = rows[:-7 * truncate_rows]
    if compressed:
        rows = zlib.compress(rows)
        if truncate_checksum:
            rows = rows[:-4]
    filter_entry = " /Filter /FlateDecode" if compressed else ""
    out.extend(f"7 0 obj\n<< /Type /XRef /Size 8 /Root 1 0 R /Info 6 0 R /W [1 4 2] /Index [0 8] /Length {len(rows)}{filter_entry} >>\nstream\n".encode())
    out.extend(rows + b"\nendstream\nendobj\nstartxref\n" + str(offset).encode() + b"\n%%EOF\n")
    return bytes(out), offsets


def _oracle(data):
    return PdfReader(io.BytesIO(data), strict=True)


def test_classic_object_offsets_and_reconstruction_vector():
    data, expected = build_classic_pdf()
    oracle = _oracle(data)
    assert len(oracle.pages) == 1
    assert oracle.metadata.title == TITLE
    assert revisions.revision_count(data) == 1
    assert revisions.chain_resolves(data) is True
    row, = revisions.revisions(data)
    assert (row["index"], row["end_offset"], row["root"], row["size"], row["prev"], row["valid"]) == (
        1, len(data), "1 0 R", 7, None, True)
    assert row["objects"] == {0: (0, 65535, "f"), **{n: (off, 0, "n") for n, off in expected["offsets"].items()}}
    assert revisions.reconstruct(data, 1) == data
    for number, serialized in expected["objects"].items():
        assert revisions.object_at(data, number, 1) == serialized
    for number in (0, 7, 999):
        assert revisions.object_at(data, number, 1) is None
    for rev in (-1, 0, 2):
        assert revisions.reconstruct(data, rev) is None
        assert revisions.object_at(data, 1, rev) is None


def test_incremental_latest_and_prior_object_vectors():
    data, original, expected = build_incremental_pdf()
    assert IndirectObject(4, 0, _oracle(original)).get_object().get_data() == CONTENT
    assert IndirectObject(4, 0, _oracle(data)).get_object().get_data() == b"REVISION TWO!"
    assert revisions.revision_count(data) == 2
    assert revisions.chain_resolves(data)
    assert revisions.reconstruct(data, 1) == original
    assert revisions.reconstruct(data, 2) == data
    assert revisions.object_at(data, 4, 1) == expected["first"]["objects"][4]
    assert revisions.object_at(data, 4, 2) == expected["object"]
    assert revisions.object_at(data, 1, 2) == expected["first"]["objects"][1]
    row = revisions.revisions(data)[1]
    assert row["objects"] == {4: (expected["offset"], 0, "n")}
    assert row["prev"] == expected["first"]["xref"]


@pytest.mark.parametrize("compressed", [False, True])
def test_xref_stream_vector(compressed):
    data, offsets = build_xref_stream_pdf(compressed=compressed)
    oracle = _oracle(data)
    assert oracle.metadata.title == TITLE
    assert len(oracle.pages) == 1
    assert revisions.revision_count(data) == 1
    assert revisions.chain_resolves(data)
    row, = revisions.revisions(data)
    assert row["objects"] == {0: (0, 65535, "f"), **{n: (off, 0, "n") for n, off in offsets.items()}}
    assert revisions.object_at(data, 1, 1) == b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj"


@pytest.mark.parametrize("filter_name,encode", [(None, lambda x: x), ("FlateDecode", zlib.compress),
                                                ("ASCIIHexDecode", lambda x: x.hex().encode() + b">"),
                                                ("ASCII85Decode", lambda x: base64.a85encode(x) + b"~>")])
def test_maldoc_pdf_and_stream_against_independent_pypdf(filter_name, encode):
    data, _ = build_classic_pdf(encoded=encode(CONTENT), filter_name=filter_name)
    oracle = _oracle(data)
    expected_stream = IndirectObject(4, 0, oracle).get_object().get_data()
    parsed = maldoc.pdf(data)
    assert parsed["version"] == "1.4"
    assert parsed["object_count"] == 6
    assert parsed["stream_count"] == 1
    assert parsed["pages_count"] == len(oracle.pages) == 1
    assert parsed["info"]["title"] == oracle.metadata.title == TITLE
    assert maldoc.pdf_stream(parsed, 4) == (expected_stream, True)
    assert maldoc.pdf_stream(parsed, 99) is None


def test_pdf_pypdf_wrapper_vector():
    data, _ = build_classic_pdf()
    oracle = _oracle(data)
    result = maldoc.pdf_pypdf(data)
    assert result["pages"] == len(oracle.pages)
    assert result["encrypted"] is False
    assert result["metadata"] == {str(k)[1:]: str(v) for k, v in oracle.metadata.items()}
    assert result["attachments"] == {}
    assert result["decrypted"] is None


def test_pdf_text_against_independent_pypdf_text():
    data, _ = build_classic_pdf()
    expected = _oracle(data).pages[0].extract_text()
    assert expected == "CSCTF{PDF_Text_Vector}"
    assert maldoc.pdf_text(data).strip() == expected


def test_document_forensics_and_pdf_metadata_vector():
    data, _ = build_classic_pdf()
    oracle = _oracle(data)
    report = documents.decode_pdf(data)
    assert report is not None
    assert (report.version, report.object_count) == ("1.4", 6)
    assert report.reference_edges == (("1 0", "2 0"), ("2 0", "3 0"), ("3 0", "2 0"), ("3 0", "4 0"), ("3 0", "5 0"))
    assert [(r.index, r.end_offset, r.object_numbers) for r in report.revisions] == [(1, len(data), tuple(range(7)))]
    for decoder in (metadata.extract_pdf_metadata, metadata.extract_document_metadata):
        fields = {item.field: item.data for item in decoder(data)}
        assert fields["Info.title"] == oracle.metadata.title.encode() == TITLE.encode()
        assert fields["Info.author"] == oracle.metadata.author.encode()


def test_revision_runner_and_cli_vectors(tmp_path, capsys):
    data, _, _ = build_incremental_pdf()
    question = {"id": "pdf-count", "question": "How many revisions?", "answer_format": {"kind": "integer"}}
    assert revisions.solve_set([question], {"tiny.pdf": data}, {}) == {"pdf-count": 2}
    assert revisions.signals([question], {"tiny.pdf": data}) == 0.65
    path = tmp_path / "tiny.pdf"
    path.write_bytes(data)
    assert revisions.main([str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result[0]["revision_count"] == 2
    assert result[0]["chain_resolves"] is True


def _malformed_corpus():
    data, _ = build_classic_pdf()
    rng = random.Random(0xD0C2026)
    values = [b"", b"\xff" * 32, b"%PDF", b"%PDF-1.7\n", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1")]
    values += [data[:end] for end in (1, 5, 9, 23, len(data) // 2, len(data) - 1, len(data) - 6)]
    values += [rng.randbytes(length) for length in (1, 2, 8, 32, 128, 511)]
    for _ in range(24):
        changed = bytearray(data)
        at = rng.randrange(len(changed))
        changed[at] ^= 1 << rng.randrange(8)
        values.append(bytes(changed))
    return values


@pytest.mark.parametrize("data", _malformed_corpus(), ids=lambda b: f"len{len(b)}-{b[:6].hex()}")
def test_fail_closed_byte_parsers(data):
    # No custom exception is declared by these modules: every public parser must
    # return normally. Structural-inspection reports may be nonempty for mutations.
    assert isinstance(revisions.revisions(data), list)
    assert isinstance(revisions.revision_count(data), int)
    assert isinstance(revisions.chain_resolves(data), bool)
    selected = revisions.object_at(data, 4, 1)
    assert selected is None or isinstance(selected, bytes)
    reconstructed = revisions.reconstruct(data, 1)
    assert reconstructed is None or isinstance(reconstructed, bytes)
    report = documents.decode_pdf(data)
    assert report is None or isinstance(report, documents.PdfReport)
    parsed = maldoc.pdf(data)
    assert isinstance(parsed, dict)
    result = maldoc.pdf_stream(parsed, 4)
    assert result is None or (isinstance(result, tuple) and isinstance(result[0], bytes))
    assert isinstance(metadata.extract_pdf_metadata(data), tuple)


class _PdfMismatch(AssertionError):
    """Only the known engine comparison failed; setup/oracle failures remain failures."""


def _known_bug_equal(actual, expected):
    if actual != expected:
        raise _PdfMismatch(f"expected {expected!r}; got {actual!r}")


@pytest.mark.parametrize("content", [b"BT (literal endobj marker) Tj ET",
                                     b"BT (literal endstream endobj markers) Tj ET"])
def test_bug_object_at_literal_endobj_is_not_object_terminator(content):
    data, expected = build_classic_pdf(content=content)
    assert IndirectObject(4, 0, _oracle(data)).get_object().get_data() == content
    _known_bug_equal(revisions.object_at(data, 4, 1), expected["objects"][4])


def test_object_at_indirect_stream_length_matches_pypdf():
    content = b"BT (endstream endobj) Tj ET"
    data, expected = build_classic_pdf(content=content, indirect_length=True)
    assert IndirectObject(4, 0, _oracle(data)).get_object().get_data() == content
    assert revisions.object_at(data, 4, 1) == expected["objects"][4]


def test_revision_footer_horizontal_whitespace():
    data, _ = build_classic_pdf()
    data = data.replace(b"%%EOF\n", b"%%EOF \t\r\n")
    assert len(_oracle(data).pages) == 1
    assert revisions.revision_count(data) == 1
    assert revisions.chain_resolves(data) is True
    assert revisions.reconstruct(data, 1) == data


def test_bug_literal_eof_does_not_add_revision():
    content = b"BT (literal %%EOF marker) Tj ET"
    data, _ = build_classic_pdf(content=content)
    assert IndirectObject(4, 0, _oracle(data)).get_object().get_data() == content
    _known_bug_equal(revisions.revision_count(data), 1)


def test_bug_revisions_ignores_literal_eof():
    data, _ = build_classic_pdf(content=b"BT (literal %%EOF marker) Tj ET")
    assert len(_oracle(data).pages) == 1
    _known_bug_equal(len(revisions.revisions(data)), 1)


def test_bug_chain_resolves_literal_eof():
    data, _ = build_classic_pdf(content=b"BT (literal %%EOF marker) Tj ET")
    assert len(_oracle(data).pages) == 1
    _known_bug_equal(revisions.chain_resolves(data), True)


def test_bug_document_forensics_literal_eof():
    data, _ = build_classic_pdf(content=b"BT (literal %%EOF marker) Tj ET")
    assert len(_oracle(data).pages) == 1
    _known_bug_equal(documents.decode_pdf(data) is not None, True)


def test_bug_truncated_xref_stream_does_not_resolve():
    # W=[1,4,2], Index=[0,8] require 56 bytes. Seven rows (49 bytes)
    # cannot be a complete xref table; pypdf permissively repairs this, so the
    # oracle here is the explicit byte-width equation from PDF 1.7 section 3.4.7.
    data, _ = build_xref_stream_pdf(truncate_rows=1)
    _known_bug_equal(revisions.chain_resolves(data), False)


def test_xref_flate_missing_checksum_does_not_resolve():
    data, _ = build_xref_stream_pdf(compressed=True, truncate_checksum=True)
    assert revisions.chain_resolves(data) is False
    assert revisions.revisions(data)[0]["valid"] is False
    assert revisions.object_at(data, 1, 1) is None


def test_bug_pdfdocencoding_title_against_pypdf():
    data, _ = build_classic_pdf(title=r"\200")
    expected = _oracle(data).metadata.title
    assert expected == "\u2022"
    _known_bug_equal(maldoc.pdf(data)["info"]["title"], expected)


def test_pdfdocencoding_defined_special_characters_against_pypdf():
    codes = [*range(0x18, 0x20), *range(0x80, 0x9f), 0xa0]
    title = "".join(f"\\{code:03o}" for code in codes)
    data, _ = build_classic_pdf(title=title)
    assert maldoc.pdf(data)["info"]["title"] == _oracle(data).metadata.title


def test_bug_flate_missing_trailer_is_not_complete():
    encoded = zlib.compress(CONTENT)[:-4]
    with pytest.raises(zlib.error):
        zlib.decompress(encoded)
    data, _ = build_classic_pdf(encoded=encoded, filter_name="FlateDecode")
    result = maldoc.pdf_stream(maldoc.pdf(data), 4)
    _known_bug_equal(result is None or result[1] is False, True)


def test_bug_runlength_short_literal_is_not_complete():
    # PDF RunLength: control 2 requires three literal bytes; only two follow,
    # and required EOD 128 is absent (PDF 1.7 section 3.3.5).
    data, _ = build_classic_pdf(encoded=b"\x02AB", filter_name="RunLengthDecode")
    result = maldoc.pdf_stream(maldoc.pdf(data), 4)
    _known_bug_equal(result is None or result[1] is False, True)


@pytest.mark.parametrize("encoded,expected", [(b"\x02ABC\x80", b"ABC"),
                                               (b"\xfeA\x80", b"AAA"), (b"\x80", b"")])
def test_runlength_complete_vectors_against_pypdf(encoded, expected):
    data, _ = build_classic_pdf(encoded=encoded, filter_name="RunLengthDecode")
    assert IndirectObject(4, 0, _oracle(data)).get_object().get_data() == expected
    assert maldoc.pdf_stream(maldoc.pdf(data), 4) == (expected, True)


@pytest.mark.parametrize("encoded", [b"\x02ABC", b"\xfe", b""])
def test_runlength_missing_eod_or_repeat_byte_is_incomplete(encoded):
    data, _ = build_classic_pdf(encoded=encoded, filter_name="RunLengthDecode")
    result = maldoc.pdf_stream(maldoc.pdf(data), 4)
    assert result is None or result[1] is False


def test_flate_output_limit_is_not_reported_complete(monkeypatch):
    monkeypatch.setattr(maldoc, "MAX_PAYLOAD_BYTES", 8)
    data, _ = build_classic_pdf(encoded=zlib.compress(CONTENT), filter_name="FlateDecode")
    result = maldoc.pdf_stream(maldoc.pdf(data), 4)
    assert result == (CONTENT[:8], False)


@pytest.mark.parametrize("reader", [revisions.revisions, revisions.chain_resolves,
                                    lambda b: revisions.object_at(b, 1, 1), documents.decode_pdf],
                         ids=["revisions", "chain_resolves", "object_at", "decode_pdf"])
def test_bug_long_startxref_rejected_without_stdlib_exception(reader):
    data = b"%PDF-1.4\nstartxref\n" + b"9" * 5000 + b"\n%%EOF"
    reader(data)  # no custom parse exception is declared by these modules


def test_bug_pdf_stream_missing_objects_declines():
    assert maldoc.pdf_stream({}, 4) is None


@pytest.mark.parametrize("name,data", [
    ("empty", b""),
    ("random", random.Random(99).randbytes(41)),
    ("all-ff", b"\xff" * 64),
    ("truncated-magic", b"%PDF-1.7\n1"),
])
@pytest.mark.parametrize("reader", [maldoc.pdf_pypdf, maldoc.pdf_text], ids=["pdf_pypdf", "pdf_text"])
def test_bug_optional_pdf_wrappers_malformed_bytes(reader, name, data):
    # Retain each previously failing public-entrypoint/input pair as a regression.
    reader(data)


@pytest.mark.parametrize("bit", [0, 1, 2, 3, 4, 5, 6])
def test_pdf_wrapper_bitflip_corpus_keeps_error_contract(bit):
    raw, _ = build_classic_pdf()
    # Single-bit corruption in a literal metadata string preserves grammar and
    # byte offsets. A parser may report changed text but must not leak exceptions.
    mutated = bytearray(raw)
    mutated[raw.index(b"Independent fixture")] ^= 1 << bit
    data = bytes(mutated)
    oracle = _oracle(data)
    assert maldoc.pdf_pypdf(data)["metadata"]["Author"] == oracle.metadata.author
    assert maldoc.pdf_text(data).strip() == "CSCTF{PDF_Text_Vector}"


def test_bug_object_at_rejects_prev_cycle():
    raw, expected = build_classic_pdf()
    data = raw.replace(b"/Info 6 0 R >>\nstartxref", f"/Info 6 0 R /Prev {expected['xref']} >>\nstartxref".encode())
    assert revisions.chain_resolves(data) is False
    _known_bug_equal(revisions.object_at(data, 1, 1), None)
