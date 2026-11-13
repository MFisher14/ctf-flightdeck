"""Deterministic tests for bounded static unpacking and inert Docker plans."""
from __future__ import annotations

import ast
import bz2
import gzip
import lzma
import struct
import sys
import zlib
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import packer_unpack as unpack  # noqa: E402


def _ap32(payload: bytes, original: bytes) -> bytes:
    return b"AP32" + struct.pack(
        "<IIIII", 24, len(payload), zlib.crc32(payload) & 0xFFFFFFFF,
        len(original), zlib.crc32(original) & 0xFFFFFFFF,
    ) + payload


def test_aplib_literals_termination_and_caps():
    single = unpack.decompress_aplib(b"A\xc0\x00")
    assert single.data == b"A"
    assert single.consumed == 3
    assert single.verified is True

    two = unpack.decompress_aplib(b"A\x60B\x00")
    assert two.data == b"AB"
    short_match = unpack.decompress_aplib(b"A\xd8\x02\x00")
    assert short_match.data == b"AAA"
    nibble_match = unpack.decompress_aplib(b"A\xe3\x80\x00")
    assert nibble_match.data == b"AA"
    with pytest.raises(unpack.UnpackError, match="truncated"):
        unpack.decompress_aplib(b"A")
    with pytest.raises(unpack.UnpackError, match="cap"):
        unpack.decompress_aplib(b"A\x60B\x00", max_output=1)


def test_ap32_size_and_both_crcs_are_verified():
    wrapped = _ap32(b"A\x60B\x00", b"AB")
    result = unpack.parse_ap32(wrapped)
    assert result.format == "ap32"
    assert result.data == b"AB"
    assert result.consumed == len(wrapped)

    corrupt_packed = bytearray(wrapped)
    corrupt_packed[12] ^= 1
    with pytest.raises(unpack.UnpackError, match="packed CRC"):
        unpack.parse_ap32(bytes(corrupt_packed))
    corrupt_original = bytearray(wrapped)
    corrupt_original[20] ^= 1
    with pytest.raises(unpack.UnpackError, match="original CRC"):
        unpack.parse_ap32(bytes(corrupt_original))
    with pytest.raises(unpack.UnpackError, match="truncated"):
        unpack.parse_ap32(wrapped[:-1])
    with pytest.raises(unpack.UnpackError, match="after the aPLib terminator"):
        unpack.parse_ap32(_ap32(b"A\x60B\x00junk", b"AB"))


def test_custom_stub_carving_and_safe_decompression_all_formats():
    plain = b"CSCTF static unpack fixture" * 4
    streams = {
        "gzip": gzip.compress(plain, mtime=0),
        "zlib": zlib.compress(plain),
        "bzip2": bz2.compress(plain),
        "xz": lzma.compress(plain, format=lzma.FORMAT_XZ),
    }
    blob = bytearray(b"STUB")
    expected_offsets = {}
    for name in ("gzip", "zlib", "bzip2", "xz"):
        expected_offsets[name] = len(blob)
        blob.extend(streams[name])
        blob.extend(b"PAD")
    candidates = unpack.carve_streams(bytes(blob))
    assert list(candidates) == sorted(candidates, key=lambda row: (row.offset, row.format))
    for name, offset in expected_offsets.items():
        candidate = next(row for row in candidates if row.format == name and row.offset == offset)
        result = unpack.decompress_carved(bytes(blob), candidate)
        assert result.data == plain
        assert result.consumed == len(streams[name])


def test_carving_caps_offsets_and_truncation_are_rejected():
    data = b"x" + zlib.compress(b"hello")
    candidate = unpack.carve_streams(data)[0]
    with pytest.raises(unpack.UnpackError, match="cap"):
        unpack.decompress_carved(data, candidate, max_output=4)
    with pytest.raises(unpack.UnpackError, match="outside"):
        unpack.decompress_carved(data, unpack.CarvedStream(999, "zlib", 1, "test"))
    with pytest.raises(unpack.UnpackError, match="truncated"):
        unpack.decompress_carved(data[:-1], candidate)
    with pytest.raises(ValueError, match="max_candidates"):
        unpack.carve_streams(data, max_candidates=0)
    early = gzip.compress(b"early", mtime=0) + b"AP32" * 5
    only = unpack.carve_streams(early, max_candidates=1)
    assert len(only) == 1 and only[0].format == "gzip" and only[0].offset == 0


def test_packer_leads_require_paired_evidence_except_structured_ap32():
    executable = b"\x7fELF\x02\x01" + b"\0" * 46
    leads = unpack.detect_packer_leads(executable + b"UPX0....UPX1....UPX!")
    assert [lead.name for lead in leads] == ["UPX"]
    assert unpack.detect_packer_leads(b"MZ....VMProtect only") == ()
    assert unpack.detect_packer_leads(b"documentation UPX0 UPX1 UPX!") == ()
    assert [lead.name for lead in unpack.detect_packer_leads(_ap32(b"A\xc0\x00", b"A"))] == ["aPLib"]


def test_upx_and_custom_stub_plans_are_argv_only_and_docker_locked():
    upx = unpack.build_upx_docker_plan("packed.bin", "clean.bin")
    assert upx.argv == ("upx", "-d", "-f", "-o", "/out/clean.bin", "/work/packed.bin")
    assert upx.network == "none" and upx.read_only_root
    assert upx.artifact_execution_expected is False

    custom = unpack.build_custom_stub_dump_plan(
        "stub.bin", oep=0x401000, dump_start=0x400000, dump_end=0x402000
    )
    assert custom.argv[0] == "gdb-multiarch"
    assert custom.artifact_execution_expected is True
    assert custom.generated_files[0][0] == "r5d_unpack.gdb"
    assert "set architecture i386:x86-64" in custom.generated_files[0][1]
    assert "dump binary memory /out/unpacked-memory.bin 0x400000 0x402000" in custom.generated_files[0][1]
    with pytest.raises(ValueError, match="unsafe"):
        unpack.build_upx_docker_plan("../packed.bin")
    with pytest.raises(ValueError, match="span"):
        unpack.build_custom_stub_dump_plan(
            "x", oep=1, dump_start=5, dump_end=4
        )


def test_module_ast_has_no_execution_or_deserialization_primitives():
    source = (REPO / "solvers" / "binary" / "packer_unpack.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported & {"subprocess", "socket", "requests", "marshal", "pickle", "importlib"}
    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"exec", "eval", "compile", "__import__", "open"}
