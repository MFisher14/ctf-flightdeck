"""Deterministic tests for the research_ff Zstandard static inspector."""

from __future__ import annotations

import argparse
import hashlib
import json
import random

import pytest
import zstandard

import research_ff_zstd as Z


EMPTY = bytes.fromhex("28b52ffd2000010000")
RAW_ABC = bytes.fromhex("28b52ffd2003190000616263")
UNKNOWN_FCS_ABC = bytes.fromhex("28b52ffd0000190000616263")
RLE_AAAAA = bytes.fromhex("28b52ffd20052b000041")
CHECKSUM_ABC = bytes.fromhex("28b52ffd2403190000616263990977ad")
SKIP_HI = bytes.fromhex("502a4d18020000006869")
SEEKABLE = bytes.fromhex(
    "28b52ffd2003190000616263"
    "502a4d18020000006869"
    "5e2a4d1819000000"
    "0c00000003000000"
    "0a00000000000000"
    "0200000000b1ea928f"
)
SEEKABLE_CHECKSUM = bytes.fromhex(
    "28b52ffd2003190000616263"
    "5e2a4d1815000000"
    "0c0000000300000044332211"
    "0100000080b1ea928f"
)


def _skippable(identifier: int, payload: bytes) -> bytes:
    magic = Z.SKIPPABLE_MAGIC_MIN | identifier
    return magic.to_bytes(4, "little") + len(payload).to_bytes(4, "little") + payload


def _seek_payload(entries: list[tuple[int, int, int | None]], descriptor: int = 0) -> bytes:
    checksum = bool(descriptor & 0x80)
    body = bytearray()
    for compressed, decompressed, value in entries:
        body += compressed.to_bytes(4, "little")
        body += decompressed.to_bytes(4, "little")
        if checksum:
            body += int(value or 0).to_bytes(4, "little")
    body += len(entries).to_bytes(4, "little")
    body += bytes((descriptor,))
    body += Z.SEEKABLE_FOOTER_MAGIC.to_bytes(4, "little")
    return bytes(body)


@pytest.mark.parametrize(
    ("wire", "content_size", "window_size", "block_type", "declared", "known"),
    [
        (EMPTY, 0, 0, "raw", 0, 0),
        (RAW_ABC, 3, 3, "raw", 3, 3),
        (UNKNOWN_FCS_ABC, None, 1024, "raw", 3, 3),
        (RLE_AAAAA, 5, 5, "rle", 5, 5),
        (CHECKSUM_ABC, 3, 3, "raw", 3, 3),
    ],
)
def test_hardcoded_spec_vectors(wire, content_size, window_size, block_type, declared, known):
    report = Z.inspect_zstd(wire)
    assert report["format"] == "zstd_stream"
    assert report["size"] == len(wire)
    assert report["frame_count"] == report["ordinary_frame_count"] == 1
    assert report["block_count"] == 1
    frame = report["frames"][0]
    assert frame["offset"] == 0 and frame["end_offset"] == len(wire)
    assert frame["header"]["frame_content_size"] == content_size
    assert frame["header"]["window_size"] == window_size
    assert frame["blocks"][0]["type"] == block_type
    assert frame["blocks"][0]["declared_size"] == declared
    assert frame["known_regenerated_size"] == known

    # These vectors are fixed spec-level bytes; the independent reference
    # implementation confirms that the inspector did not merely accept a
    # self-generated layout.
    expected = {EMPTY: b"", RAW_ABC: b"abc", UNKNOWN_FCS_ABC: b"abc",
                RLE_AAAAA: b"AAAAA", CHECKSUM_ABC: b"abc"}[wire]
    assert zstandard.ZstdDecompressor().decompress(wire, max_output_size=32) == expected


def test_checksum_is_inventoried_but_not_claimed_verified():
    checksum = Z.inspect_zstd(CHECKSUM_ABC)["frames"][0]["content_checksum"]
    assert checksum["value"] == 0xAD770999
    assert checksum["hex"] == "0xad770999"
    assert checksum["validated"] is False


def test_concatenated_frames_and_skippable_payload_inventory():
    wire = RAW_ABC + SKIP_HI + EMPTY
    report = Z.inspect_zstd(wire, preview_bytes=1)
    assert report["frame_count"] == 3
    assert report["ordinary_frame_count"] == 2
    assert report["skippable_frame_count"] == 1
    skip = report["frames"][1]
    assert skip["kind"] == "skippable_frame"
    assert skip["offset"] == len(RAW_ABC)
    assert skip["end_offset"] == len(RAW_ABC) + len(SKIP_HI)
    assert skip["payload_size"] == 2
    assert skip["payload_sha256"] == hashlib.sha256(b"hi").hexdigest()
    assert skip["payload_preview_hex"] == b"h".hex()
    assert skip["payload_preview_truncated"] is True
    assert report["frames"][2]["offset"] == len(RAW_ABC) + len(SKIP_HI)


def test_hardcoded_seekable_table_validates_exact_frame_mapping():
    report = Z.inspect_zstd(SEEKABLE)
    assert report["seekable"] == {
        "table_frame_index": 2,
        "table_offset": len(RAW_ABC) + len(SKIP_HI),
        "number_of_frames": 2,
        "checksum_flag": False,
        "total_compressed_size": len(RAW_ABC) + len(SKIP_HI),
        "total_decompressed_size": 3,
        "validated": True,
    }
    table_frame = report["frames"][2]
    assert table_frame["kind"] == "seek_table"
    table = table_frame["seek_table"]
    assert table["validated_against_stream"] is True
    assert [(e["compressed_size"], e["decompressed_size"], e["frame_kind"])
            for e in table["entries"]] == [
        (len(RAW_ABC), 3, "zstd_frame"),
        (len(SKIP_HI), 0, "skippable_frame"),
    ]


def test_seekable_checksum_entry_and_unused_descriptor_bits():
    report = Z.inspect_zstd(SEEKABLE_CHECKSUM)
    table = report["frames"][-1]["seek_table"]
    assert table["checksum_flag"] is True
    assert table["entry_size"] == 12
    assert table["entries"][0]["checksum"] == 0x11223344
    assert table["entries"][0]["checksum_hex"] == "0x11223344"

    # Descriptor bits 1..0 are explicitly non-breaking/unused, so retain them.
    payload = _seek_payload([(len(RAW_ABC), 3, None)], descriptor=0x03)
    report = Z.inspect_zstd(RAW_ABC + _skippable(0xE, payload))
    assert report["frames"][-1]["seek_table"]["unused_descriptor_bits"] == 3


def test_magic_0e_without_footer_remains_generic_skippable_metadata():
    wire = _skippable(0xE, b"ordinary metadata")
    report = Z.inspect_zstd(wire)
    assert report["frames"][0]["kind"] == "skippable_frame"
    assert report["frames"][0]["seek_table"] is None
    assert report["seekable"] is None


def test_formatted_dictionary_header_and_id_ranges():
    dictionary = bytes.fromhex("37a430ec00800000deadbeef")
    report = Z.inspect_zstd(dictionary, preview_bytes=2)
    assert report["format"] == "zstd_formatted_dictionary"
    assert report["dictionary"]["dictionary_id"] == 32768
    assert report["dictionary"]["dictionary_id_range"] == "public_free"
    assert report["dictionary"]["opaque_tail_size"] == 4
    assert report["dictionary"]["opaque_tail_preview_hex"] == "dead"
    assert "header only" in report["validation_scope"]

    low = Z.inspect_zstd(Z.DICTIONARY_MAGIC_BYTES + (7).to_bytes(4, "little"))
    assert low["dictionary"]["dictionary_id_range"] == "reserved_low"
    high = Z.inspect_zstd(Z.DICTIONARY_MAGIC_BYTES + (1 << 31).to_bytes(4, "little"))
    assert high["dictionary"]["dictionary_id_range"] == "reserved_high"


def test_reference_library_generated_frame_crosscheck():
    payload = (b"CSCTF{zstd_static_reference}" * 257) + bytes(range(256))
    wire = zstandard.ZstdCompressor(
        level=5, write_checksum=True, write_content_size=True, write_dict_id=True
    ).compress(payload)
    assert zstandard.ZstdDecompressor().decompress(wire) == payload

    report = Z.inspect_zstd(wire)
    frame = report["frames"][0]
    assert report["ordinary_frame_count"] == 1
    assert frame["end_offset"] == len(wire)
    assert frame["header"]["frame_content_size"] == len(payload)
    assert frame["content_checksum"] is not None
    assert frame["block_count"] >= 1
    for left, right in zip(frame["blocks"], frame["blocks"][1:]):
        assert left["end_offset"] == right["header_offset"]


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"not zstd",
        RAW_ABC + b"x",
        RAW_ABC + b"xxxx",
        bytes.fromhex("28b52ffd2800"),                 # reserved FHD bit
        bytes.fromhex("28b52ffd3000"),                 # unused FHD bit (encoder-invalid)
        bytes.fromhex("28b52ffd2000070000"),           # reserved block type
        bytes.fromhex("28b52ffd20011100004142"),       # raw size 2, single window 1
        bytes.fromhex("502a4d18050000006162"),         # cut skippable payload
        Z.DICTIONARY_MAGIC_BYTES,
        Z.DICTIONARY_MAGIC_BYTES + b"\x00\x00\x00\x00",
    ],
)
def test_malformed_inputs_raise_only_declared_error(bad):
    with pytest.raises(Z.ResearchFFZstdError):
        Z.inspect_zstd(bad)


def test_every_truncation_of_a_valid_frame_fails_closed():
    for end in range(len(CHECKSUM_ABC)):
        with pytest.raises(Z.ResearchFFZstdError):
            Z.inspect_zstd(CHECKSUM_ABC[:end])


def test_malformed_seek_tables_fail_closed():
    cases = []
    # Footer marker with too little payload to hold the footer.
    cases.append(_skippable(0xE, Z.SEEKABLE_FOOTER_MAGIC_BYTES))
    # Reserved descriptor bit 2.
    cases.append(RAW_ABC + _skippable(
        0xE, _seek_payload([(len(RAW_ABC), 3, None)], descriptor=0x04)
    ))
    # Structurally exact table, but count does not match preceding frames.
    cases.append(RAW_ABC + _skippable(
        0xE, _seek_payload([(len(RAW_ABC), 3, None), (1, 0, None)])
    ))
    # Compressed size differs from the actual first frame.
    cases.append(RAW_ABC + _skippable(
        0xE, _seek_payload([(len(RAW_ABC) - 1, 3, None)])
    ))
    # Decompressed size differs from the frame's declared FCS.
    cases.append(RAW_ABC + _skippable(
        0xE, _seek_payload([(len(RAW_ABC), 4, None)])
    ))
    # A recognized seek table must be final.
    cases.append(SEEKABLE + SKIP_HI)
    for wire in cases:
        with pytest.raises(Z.ResearchFFZstdError):
            Z.inspect_zstd(wire)


def test_wrong_types_fuzzish_bytes_and_options_never_leak_stdlib_exceptions():
    for value in (None, True, 1, "zstd", [], {}, object()):
        with pytest.raises(Z.ResearchFFZstdError):
            Z.inspect_zstd(value)
    for preview in (-1, 257, 1.5, "2", None, True):
        with pytest.raises(Z.ResearchFFZstdError):
            Z.inspect_zstd(RAW_ABC, preview_bytes=preview)

    rng = random.Random(0x5A7D)
    for size in range(1, 160):
        # Forced non-magic prefix makes each a deterministic malformed input,
        # while varied tails exercise the error boundary.
        raw = b"\x00" + bytes(rng.randrange(256) for _ in range(size - 1))
        with pytest.raises(Z.ResearchFFZstdError):
            Z.inspect_zstd(raw)

    assert Z.inspect_zstd(memoryview(RAW_ABC))["frames"][0]["end_offset"] == len(RAW_ABC)
    assert Z.inspect_zstd(bytearray(RAW_ABC))["ordinary_frame_count"] == 1


def test_resource_caps_are_fail_closed(monkeypatch):
    monkeypatch.setattr(Z, "MAX_INPUT", 8)
    with pytest.raises(Z.ResearchFFZstdError):
        Z.inspect_zstd(EMPTY)
    monkeypatch.setattr(Z, "MAX_INPUT", 128 * 1024 * 1024)

    monkeypatch.setattr(Z, "MAX_FRAMES", 1)
    with pytest.raises(Z.ResearchFFZstdError):
        Z.inspect_zstd(RAW_ABC + EMPTY)
    monkeypatch.setattr(Z, "MAX_FRAMES", 65_536)

    two_blocks = bytes.fromhex("28b52ffd20020800004109000042")
    assert Z.inspect_zstd(two_blocks)["block_count"] == 2
    monkeypatch.setattr(Z, "MAX_BLOCKS", 1)
    with pytest.raises(Z.ResearchFFZstdError):
        Z.inspect_zstd(two_blocks)


def test_cli_json_errors_and_guarded_argparse(capsys, tmp_path, monkeypatch):
    path = tmp_path / "seekable.zst"
    path.write_bytes(SEEKABLE)
    assert Z.main([str(path), "--pretty", "--preview-bytes", "2"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["seekable"]["validated"] is True

    malformed = tmp_path / "bad.zst"
    malformed.write_bytes(RAW_ABC[:-1])
    assert Z.main([str(malformed)]) == 1
    assert "research_ff_zstd:" in capsys.readouterr().err
    assert Z.main([str(tmp_path / "missing.zst")]) == 1
    assert "research_ff_zstd:" in capsys.readouterr().err

    assert Z.main([]) == 2
    assert "usage:" in capsys.readouterr().err
    assert Z.main(["--help"]) == 0
    assert "Zstandard" in capsys.readouterr().out
    assert Z.main([str(path), "--preview-bytes", "999"]) == 2
    capsys.readouterr()

    def non_integer_exit(self, args=None, namespace=None):
        raise SystemExit("non-integer")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert Z.main([str(path)]) == 2


def test_inspect_path_declared_error_contract(tmp_path):
    path = tmp_path / "raw.zst"
    path.write_bytes(RAW_ABC)
    assert Z.inspect_path(path)["sha256"] == hashlib.sha256(RAW_ABC).hexdigest()
    for pathlike in (tmp_path / "missing", None, object()):
        with pytest.raises(Z.ResearchFFZstdError):
            Z.inspect_path(pathlike)
