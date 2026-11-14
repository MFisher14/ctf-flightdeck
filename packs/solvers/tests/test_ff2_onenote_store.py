"""MS-ONESTORE FileDataStoreObject vectors independent of the target parser."""
from __future__ import annotations

import hashlib
import random
import struct
import uuid

import pytest

import ff2_onenote_store as store


ONE = uuid.UUID("7b5c52e4-d88c-4da7-aeb1-5378d02996d3").bytes_le
HEAD = uuid.UUID("bde316e7-2665-4511-a4c4-8d4d0b7a9eac").bytes_le
FOOT = uuid.UUID("71fba722-0f79-4a0b-bb13-899256426b24").bytes_le


def reference_object(payload: bytes, *, unused=0, reserved=b"\0" * 8,
                     padding_byte=b"\0") -> bytes:
    """Literal encoder from MS-ONESTORE 2.6.13, not target code."""
    header = HEAD + struct.pack("<QI", len(payload), unused) + reserved
    padding = (-(len(header) + len(payload))) & 7
    return header + payload + padding_byte * padding + FOOT


def fixture():
    first = b"PK\x03\x04" + b"CSCTF{OneNote_Object}"
    second = b"\x89PNG\r\n\x1a\n" + bytes(range(17))
    prefix = ONE + b"\0" * 48
    object0 = reference_object(first)
    gap = b"REVISION-STORE-GAP"
    object1 = reference_object(second, unused=7, reserved=b"R" + b"\0" * 7,
                               padding_byte=b"P")
    return prefix + object0 + gap + object1, first, second, len(prefix), len(prefix + object0 + gap)


def test_published_filedatastore_layout_and_exact_extraction():
    data, first, second, off0, off1 = fixture()
    report = store.inventory(data)
    assert report["format"] == "onenote-section"
    assert report["object_count"] == 2
    assert report["total_embedded_bytes"] == len(first) + len(second)
    assert [row["object_offset"] for row in report["objects"]] == [off0, off1]
    assert [row["data_offset"] for row in report["objects"]] == [off0 + 36, off1 + 36]
    assert [row["footer_offset"] for row in report["objects"]] == [
        off0 + 36 + len(first) + (-(36 + len(first)) & 7),
        off1 + 36 + len(second) + (-(36 + len(second)) & 7),
    ]
    assert report["objects"][0]["sha256"] == hashlib.sha256(first).hexdigest()
    assert report["objects"][0]["kind"] == "zip"
    assert report["objects"][1]["kind"] == "png"
    assert report["objects"][0]["header_fields_zero"] is True
    assert report["objects"][1]["header_fields_zero"] is False
    assert report["objects"][1]["padding_zero"] is False
    assert store.extract_object(data, 0) == first
    assert store.extract_object(data, 1) == second


def test_fragment_empty_payload_and_generated_name():
    data = reference_object(b"")
    report = store.inventory(data)
    assert report["format"] == "file-data-store-fragment"
    assert report["objects"][0]["data_length"] == 0
    assert report["objects"][0]["generated_name"] == "embedded-0000.bin"
    assert store.extract_object(data) == b""


def test_cli_guard_and_safe_extraction(tmp_path, capsys):
    data, first, _second, *_ = fixture()
    source = tmp_path / "sample.one"
    output = tmp_path / "payload.zip"
    source.write_bytes(data)
    assert store.main([str(source), "--extract", "0", "--output", str(output)]) == 0
    assert output.read_bytes() == first
    assert '"object_count": 2' in capsys.readouterr().out
    assert store.main(["--definitely-invalid"]) == 2


@pytest.mark.parametrize("mutator", [
    lambda raw: raw[:-1],
    lambda raw: raw[:24],
    lambda raw: raw[:-16] + b"X" * 16,
    lambda raw: raw[:16] + struct.pack("<Q", 1 << 63) + raw[24:],
])
def test_invalid_structure_raises_declared_error(mutator):
    raw = reference_object(b"proof")
    with pytest.raises(store.FF2OneNoteError):
        store.inventory(mutator(raw))


def test_fail_closed_fuzz_and_budget(monkeypatch):
    valid, *_ = fixture()
    rng = random.Random(0x0E0E)
    corpus = [None, "π.one", bytearray(b"x"), b"", b"not a notebook",
              rng.randbytes(257)]
    corpus.extend(valid[:cut] for cut in range(0, len(valid), 17))
    for _ in range(40):
        changed = bytearray(valid)
        changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
        corpus.append(bytes(changed))
    for raw in corpus:
        for function in (store.inventory, store.extract_object):
            try:
                result = function(raw)
                assert isinstance(result, (dict, bytes))
            except Exception as exc:  # exact fail-closed public contract
                assert type(exc) is store.FF2OneNoteError
    monkeypatch.setattr(store, "MAX_INPUT", 64)
    with pytest.raises(store.FF2OneNoteError):
        store.inventory(b"x" * 65)

