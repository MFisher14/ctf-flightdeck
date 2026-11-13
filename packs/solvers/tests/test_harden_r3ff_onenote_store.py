"""Independent MS-ONESTORE vectors and fail-closed tests.

The fixture encoder below is a literal transcription of Microsoft
[MS-ONESTORE] 2.6.13 FileDataStoreObject.  It does not call target code:
https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26
"""

from __future__ import annotations

import hashlib
import random
import struct
import uuid

import pytest

import ff2_onenote_store as onestore


SECTION_GUID = uuid.UUID("7b5c52e4-d88c-4da7-aeb1-5378d02996d3").bytes_le
TOC_GUID = uuid.UUID("43ff2fa1-efd9-4c76-9ee2-10ea5722765f").bytes_le
OBJECT_HEADER = uuid.UUID("bde316e7-2665-4511-a4c4-8d4d0b7a9eac").bytes_le
OBJECT_FOOTER = uuid.UUID("71fba722-0f79-4a0b-bb13-899256426b24").bytes_le


def spec_object(
    payload: bytes,
    *,
    unused: int = 0,
    reserved: bytes = b"\0" * 8,
    padding_octet: int = 0,
) -> bytes:
    """Encode the published structure directly, independently of the engine."""

    assert 0 <= unused <= 0xFFFFFFFF
    assert len(reserved) == 8
    header = OBJECT_HEADER + struct.pack("<QI", len(payload), unused) + reserved
    padding_length = (-(len(header) + len(payload))) % 8
    return header + payload + bytes([padding_octet]) * padding_length + OBJECT_FOOTER


def published_fixture() -> tuple[bytes, tuple[bytes, bytes], tuple[int, int]]:
    # Known inert embedded content. Magic values are independently documented
    # by ISO 32000 (PDF) and the PE/COFF format respectively.
    pdf = b"%PDF-1.7\n% CSCTF{OneNote_Vector}\n%%EOF\n"
    pe = b"MZ" + bytes(range(1, 34))
    prefix = SECTION_GUID + b"REVISION-STORE" + bytes(range(11))
    first = spec_object(pdf)
    gap = b"\x01NODE-GAP\x02"
    second = spec_object(
        pe,
        unused=0x01020304,
        reserved=b"R\0\0\0\0\0\0\0",
        padding_octet=0xA5,
    )
    offsets = (len(prefix), len(prefix) + len(first) + len(gap))
    return prefix + first + gap + second, (pdf, pe), offsets


def test_vector_lock_published_filedatastore_layout() -> None:
    raw, payloads, offsets = published_fixture()
    report = onestore.inventory(raw)

    assert report["format"] == "onenote-section"
    assert report["file_type_guid"] == "{7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}"
    assert report["object_count"] == 2
    assert report["total_embedded_bytes"] == sum(map(len, payloads))

    first, second = report["objects"]
    assert [first["object_offset"], second["object_offset"]] == list(offsets)
    assert [first["header_length"], second["header_length"]] == [36, 36]
    assert [first["data_offset"], second["data_offset"]] == [
        offsets[0] + 36,
        offsets[1] + 36,
    ]
    assert [first["data_length"], second["data_length"]] == list(map(len, payloads))

    expected_padding = [(-(36 + len(payload))) % 8 for payload in payloads]
    assert [first["padding_length"], second["padding_length"]] == expected_padding
    assert [first["footer_offset"], second["footer_offset"]] == [
        offsets[index] + 36 + len(payloads[index]) + expected_padding[index]
        for index in range(2)
    ]
    assert [first["end_offset"], second["end_offset"]] == [
        first["footer_offset"] + 16,
        second["footer_offset"] + 16,
    ]
    assert [first["sha256"], second["sha256"]] == [
        hashlib.sha256(payload).hexdigest() for payload in payloads
    ]
    assert [first["kind"], second["kind"]] == ["pdf", "pe"]
    assert [first["generated_name"], second["generated_name"]] == [
        "embedded-0000.pdf",
        "embedded-0001.exe",
    ]
    assert first["header_fields_zero"] is True
    assert first["padding_zero"] is True
    assert second["header_fields_zero"] is False
    assert second["padding_zero"] is False
    assert report["warnings"] == [
        "object 1: unused field is nonzero",
        "object 1: reserved field is nonzero",
        "object 1: alignment padding is nonzero",
    ]


def test_vector_lock_extract_object_returns_exact_published_filedata() -> None:
    raw, payloads, _ = published_fixture()
    assert onestore.extract_object(raw, 0) == payloads[0]
    assert onestore.extract_object(raw, 1) == payloads[1]

    # Empty FileData is valid: cbLength excludes padding and is allowed to be 0.
    empty = spec_object(b"")
    assert onestore.extract_object(empty) == b""
    assert onestore.inventory(empty)["objects"][0]["data_length"] == 0


def test_vector_lock_toc_guid_is_not_a_section_file() -> None:
    with pytest.raises(onestore.FF2OneNoteError):
        onestore.inventory(TOC_GUID + spec_object(b"proof"))


def _assert_contract(function, *args) -> None:
    try:
        result = function(*args)
    except Exception as exc:  # the public parser must translate every failure
        assert type(exc) is onestore.FF2OneNoteError
    else:
        assert isinstance(result, (dict, bytes))


def test_fail_closed_fuzz_inventory_and_extract_object() -> None:
    valid, _payloads, _offsets = published_fixture()
    rng = random.Random(0x0E57_0BE)

    bit_flips: list[bytes] = []
    for position in (0, 15, 16, 30, 43, len(valid) // 2, len(valid) - 17, len(valid) - 1):
        mutated = bytearray(valid)
        mutated[position] ^= 1 << (position % 8)
        bit_flips.append(bytes(mutated))

    declared_too_large = (
        OBJECT_HEADER
        + struct.pack("<QI", onestore.MAX_EMBEDDED + 1, 0)
        + b"\0" * 8
        + OBJECT_FOOTER
    )
    corpus: list[object] = [
        b"",  # empty
        rng.randbytes(513),  # deterministic random
        b"\xff" * 513,  # all-0xff
        OBJECT_HEADER,  # real object magic, truncated
        OBJECT_HEADER + b"\0" * 19,
        valid[:-1],  # truncated-valid
        valid[:37],
        declared_too_large,  # oversized declared FileData without allocating it
        None,
        "not bytes",
        bytearray(valid),
    ]
    corpus.extend(bit_flips)

    for item in corpus:
        _assert_contract(onestore.inventory, item)
        _assert_contract(onestore.extract_object, item)


def test_fail_closed_fuzz_extract_index() -> None:
    valid, _payloads, _offsets = published_fixture()
    for index in (-1, 2, 2**63, True, None, "0", 1.5):
        _assert_contract(onestore.extract_object, valid, index)


def test_fail_closed_oversized_input_and_object_count(monkeypatch) -> None:
    valid, _payloads, _offsets = published_fixture()
    monkeypatch.setattr(onestore, "MAX_INPUT", len(valid) - 1)
    with pytest.raises(onestore.FF2OneNoteError) as caught:
        onestore.inventory(valid)
    assert type(caught.value) is onestore.FF2OneNoteError
    with pytest.raises(onestore.FF2OneNoteError) as caught_extract:
        onestore.extract_object(valid)
    assert type(caught_extract.value) is onestore.FF2OneNoteError

    # Restore the input budget, then independently trip the object-count cap.
    monkeypatch.setattr(onestore, "MAX_INPUT", len(valid) + 1)
    monkeypatch.setattr(onestore, "MAX_OBJECTS", 1)
    with pytest.raises(onestore.FF2OneNoteError) as caught_count:
        onestore.inventory(valid)
    assert type(caught_count.value) is onestore.FF2OneNoteError


def test_cli_argparse_is_guarded(tmp_path, capsys) -> None:
    raw, _payloads, _offsets = published_fixture()
    source = tmp_path / "vector.one"
    source.write_bytes(raw)
    assert onestore.main([str(source)]) == 0
    assert '"object_count": 2' in capsys.readouterr().out
    assert onestore.main(["--definitely-invalid"]) == 2
    assert isinstance(onestore.main(["--help"]), int)
