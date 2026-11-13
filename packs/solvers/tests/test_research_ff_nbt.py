"""Deterministic tests for the standalone research_ff_nbt engine."""
from __future__ import annotations

import ast
import gzip
import json
import struct
import sys
import zlib
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import research_ff_nbt as nbt  # noqa: E402


# Canonical test.nbt from the original NBT specification: a root compound named
# "hello world" containing TAG_String("name") == "Bananrama".  It is deliberately
# hardcoded rather than generated through the implementation under test.
HELLO_NBT = bytes.fromhex(
    "0a000b68656c6c6f20776f726c64"
    "0800046e616d65000942616e616e72616d61"
    "00"
)
SECTOR = 4096


def _record(payload: bytes, marker: int, sectors: int = 1, slack_byte: int | None = None) -> bytes:
    body = len(payload + bytes([marker])).to_bytes(4, "big") + bytes([marker]) + payload
    assert len(body) <= sectors * SECTOR
    body += bytes(sectors * SECTOR - len(body))
    if slack_byte is not None:
        body = body[:-1] + bytes([slack_byte])
    return body


def _region() -> bytes:
    """An independently assembled region with all supported codecs and one orphan."""
    image = bytearray(7 * SECTOR)
    locations = ((0, 2, 1), (1, 3, 1), (2, 4, 1), (3, 5, 1))
    for index, offset, count in locations:
        value = (offset << 8) | count
        image[index * 4:index * 4 + 4] = value.to_bytes(4, "big")
        image[SECTOR + index * 4:SECTOR + index * 4 + 4] = (100 + index).to_bytes(4, "big")
    image[2 * SECTOR:3 * SECTOR] = _record(
        zlib.compress(HELLO_NBT, level=9), 2, slack_byte=0xA5)
    image[3 * SECTOR:4 * SECTOR] = _record(
        gzip.compress(HELLO_NBT, compresslevel=9, mtime=0), 1)
    image[4 * SECTOR:5 * SECTOR] = _record(HELLO_NBT, 3)
    # Modern external-chunk flag combined with compression id 4 (LZ4).  The
    # inspector must inventory the stub without opening or decoding an .mcc file.
    image[5 * SECTOR:6 * SECTOR] = _record(b"", 0x84)
    # Sector six is not in the location table: the scanner may call it an orphan only
    # after independently validating its compressed compound NBT payload.
    image[6 * SECTOR:7 * SECTOR] = _record(zlib.compress(HELLO_NBT), 2)
    return bytes(image)


def _root_text(report: dict) -> str:
    root = report["root"]
    assert root["type"] == "compound" and root["name"] == "hello world"
    return root["value"][0]["value"]


def test_canonical_spec_vector_and_strict_full_consumption():
    report = nbt.parse_nbt(HELLO_NBT, "raw")
    assert report["compression"] == "raw" and report["tag_count"] == 2
    assert _root_text(report) == "Bananrama"
    with pytest.raises(nbt.ResearchFFNBTError, match="trailing bytes"):
        nbt.parse_nbt(HELLO_NBT + b"\x00", "raw")


def test_stdlib_gzip_and_zlib_wrappers_are_non_circular_references():
    gzip_blob = gzip.compress(HELLO_NBT, compresslevel=6, mtime=0)
    zlib_blob = zlib.compress(HELLO_NBT, level=6)
    assert _root_text(nbt.parse_nbt(gzip_blob)) == "Bananrama"
    assert nbt.parse_nbt(gzip_blob)["compression"] == "gzip"
    assert _root_text(nbt.parse_nbt(zlib_blob)) == "Bananrama"
    assert nbt.parse_nbt(zlib_blob)["compression"] == "zlib"
    with pytest.raises(nbt.ResearchFFNBTError, match="trailing bytes"):
        nbt.parse_nbt(gzip_blob + b"junk")
    with pytest.raises(nbt.ResearchFFNBTError):
        nbt.parse_nbt(zlib_blob[:-1])


def test_anvil_tables_codecs_external_slack_and_orphan():
    image = bytearray(_region())
    first_payload = zlib.compress(HELLO_NBT, level=9)
    hidden = b"CSCTF{region_allocation_slack}"
    hidden_at = 2 * SECTOR + 5 + len(first_payload) + 17
    image[hidden_at:hidden_at + len(hidden)] = hidden
    report = nbt.inspect_region(bytes(image))
    assert report["kind"] == "anvil-region" and report["complete_sectors"] == 7
    assert report["present_entries"] == 4
    assert report["valid_inline_chunks"] == 3 and report["external_chunks"] == 1
    chunks = [report["entries"][index]["chunk"] for index in range(4)]
    assert [row["compression"] for row in chunks] == ["zlib", "gzip", "raw", "lz4"]
    assert [_root_text(row["nbt"]) for row in chunks[:3]] == ["Bananrama"] * 3
    assert chunks[0]["slack"]["nonzero_bytes"] >= len(hidden) + 1
    assert any(run["text"] == hidden.decode() for run in chunks[0]["slack"]["ascii_runs"])
    assert chunks[3]["status"] == "external" and chunks[3]["external_file_accessed"] is False
    assert report["external_files_accessed"] is False
    assert len(report["orphan_chunks"]) == 1
    assert report["orphan_chunks"][0]["sector_offset"] == 6
    assert _root_text(report["orphan_chunks"][0]["nbt"]) == "Bananrama"


def test_anvil_allocation_corruption_is_reported_not_guessed():
    image = bytearray(_region())
    # Entry 4 duplicates entry 0 exactly; entry 5 overlaps it with a wider allocation.
    image[4 * 4:5 * 4] = ((2 << 8) | 1).to_bytes(4, "big")
    image[5 * 4:6 * 4] = ((2 << 8) | 2).to_bytes(4, "big")
    # Entry 6 points into the reserved header, 7 is out of bounds, 8 violates zero-pair rules.
    image[6 * 4:7 * 4] = ((1 << 8) | 1).to_bytes(4, "big")
    image[7 * 4:8 * 4] = ((99 << 8) | 1).to_bytes(4, "big")
    image[8 * 4:9 * 4] = (9 << 8).to_bytes(4, "big")
    report = nbt.inspect_region(bytes(image))
    assert report["allocation"]["duplicate_allocations"][0]["entries"] == [0, 4]
    assert [0, 4] in report["allocation"]["overlap_pairs"]
    alias = report["entries"][4]["chunk"]
    assert alias["status"] == "duplicate-reference" and alias["alias_of_entry"] == 0
    assert "nbt" not in alias and len(json.dumps(alias)) < 256
    assert any("overlaps" in issue for issue in report["entries"][5]["issues"])
    assert "allocation overlaps reserved header sectors" in report["entries"][6]["issues"]
    assert "allocation exceeds complete file sectors" in report["entries"][7]["issues"]
    assert report["entries"][8]["zero_pair_valid"] is False


def test_anvil_length_and_compression_corruption_stay_local():
    image = bytearray(_region())
    struct.pack_into(">I", image, 2 * SECTOR, SECTOR)
    report = nbt.inspect_region(bytes(image))
    assert report["entries"][0]["chunk"]["status"] == "invalid"
    assert "chunk length exceeds allocated sectors" in report["entries"][0]["chunk"]["issues"]

    image = bytearray(_region())
    image[2 * SECTOR + 4] = 4
    report = nbt.inspect_region(bytes(image))
    assert report["entries"][0]["chunk"]["compression"] == "lz4"
    assert "unsupported compression id 4 (LZ4)" in report["entries"][0]["chunk"]["issues"]


def test_all_nbt_tag_ids_and_modified_utf8():
    # Independent compound fixture containing scalar tags, arrays, an empty list, and
    # Java modified UTF-8's C0 80 null plus a surrogate-pair encoded emoji.
    def named(tag: int, name: bytes, payload: bytes) -> bytes:
        return bytes([tag]) + len(name).to_bytes(2, "big") + name + payload

    mutf = b"A\xc0\x80\xed\xa0\xbd\xed\xb8\x80"
    body = b"".join((
        named(1, b"b", b"\xff"),
        named(2, b"s", (-2).to_bytes(2, "big", signed=True)),
        named(3, b"i", (-3).to_bytes(4, "big", signed=True)),
        named(4, b"l", (-4).to_bytes(8, "big", signed=True)),
        named(5, b"f", struct.pack(">f", 1.25)),
        named(6, b"d", struct.pack(">d", 2.5)),
        named(7, b"ba", (2).to_bytes(4, "big", signed=True) + b"\x00\xff"),
        named(8, b"u", len(mutf).to_bytes(2, "big") + mutf),
        named(9, b"empty", b"\x00" + (0).to_bytes(4, "big", signed=True)),
        named(10, b"c", b"\x00"),
        named(11, b"ia", (2).to_bytes(4, "big", signed=True)
              + (7).to_bytes(4, "big", signed=True) + (-8).to_bytes(4, "big", signed=True)),
        named(12, b"la", (1).to_bytes(4, "big", signed=True)
              + (-9).to_bytes(8, "big", signed=True)),
    ))
    fixture = b"\x0a\x00\x00" + body + b"\x00"
    children = {row["name"]: row for row in nbt.parse_nbt(fixture, "raw")["root"]["value"]}
    assert set(row["type_id"] for row in children.values()) == set(range(1, 13))
    assert children["u"]["value"] == "A\x00😀"
    assert children["ba"]["value"]["hex"] == "00ff"
    assert children["ia"]["value"] == [7, -8] and children["la"]["value"] == [-9]


def test_declared_exception_contract_contains_all_malformed_inputs():
    malformed = [b"", b"\x00", HELLO_NBT[:-1], b"\x0a\x00\x00\x7f",
                 b"\x0a\x00\x00\x07\x00\x01x\xff\xff\xff\xff\x00",
                 b"\x78\x9cnot-zlib"]
    for blob in malformed:
        with pytest.raises(nbt.ResearchFFNBTError):
            nbt.parse_nbt(blob)
    for bad in (None, object(), "text", 123):
        with pytest.raises(nbt.ResearchFFNBTError):
            nbt.parse_nbt(bad)
        with pytest.raises(nbt.ResearchFFNBTError):
            nbt.inspect_region(bad)
        with pytest.raises(nbt.ResearchFFNBTError):
            nbt.analyze_bytes(bad)
    with pytest.raises(nbt.ResearchFFNBTError):
        nbt.inspect_region(b"short")

    for end in range(len(HELLO_NBT)):
        with pytest.raises(nbt.ResearchFFNBTError):
            nbt.parse_nbt(HELLO_NBT[:end], "raw")
    with pytest.raises(nbt.ResearchFFNBTError):
        nbt.parse_nbt(HELLO_NBT, [])
    assert _root_text(nbt.parse_nbt(memoryview(HELLO_NBT), "raw")) == "Bananrama"


def test_nbt_resource_caps_fail_closed(monkeypatch):
    monkeypatch.setattr(nbt, "MAX_NBT_INPUT", len(HELLO_NBT) - 1)
    with pytest.raises(nbt.ResearchFFNBTError, match="input exceeds"):
        nbt.parse_nbt(HELLO_NBT, "raw")

    monkeypatch.setattr(nbt, "MAX_NBT_INPUT", 64 << 20)
    monkeypatch.setattr(nbt, "MAX_DECOMPRESSED", 8)
    with pytest.raises(nbt.ResearchFFNBTError, match="decompression cap"):
        nbt.parse_nbt(gzip.compress(HELLO_NBT, mtime=0), "gzip")


def test_guarded_json_cli_and_import_safe_static_surface(tmp_path, capsys):
    path = tmp_path / "test.nbt"
    path.write_bytes(HELLO_NBT)
    assert nbt.main([str(path), "--kind", "nbt", "--compression", "raw"]) == 0
    assert json.loads(capsys.readouterr().out)["root"]["name"] == "hello world"
    assert nbt.main([]) == 2
    assert nbt.main(["--kind", "wrong", str(path)]) == 2
    assert nbt.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err

    bad = tmp_path / "bad.nbt"
    bad.write_bytes(b"\x0a")
    assert nbt.main([str(bad), "--kind", "nbt"]) == 2
    assert "Traceback" not in capsys.readouterr().err

    tree = ast.parse((REPO / "solvers" / "toolkits" / "research_ff_nbt.py").read_text())
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    assert not imported & {"socket", "subprocess", "requests", "urllib", "http", "ctf"}
