"""Offline ISO-TP/UDS coverage and deterministic parser mutation tests."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import automotive_depth as auto  # noqa: E402


def _isotp(can_id: int, payload: bytes, width: int = 8):
    assert len(payload) > width - 2
    first = bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:width - 2]
    rows = [(can_id, first)]
    at, sequence = width - 2, 1
    while at < len(payload):
        chunk = payload[at:at + width - 1]
        rows.append((can_id, bytes([0x20 | sequence]) + chunk.ljust(width - 1, b"\xaa")))
        at += width - 1
        sequence = (sequence + 1) & 0x0F
    return rows


def test_multiframe_isotp_and_uds_did_flag_roundtrip():
    payload = b"\x62\xf1\x90CSCTF{uds_multiframe}"
    rows = _isotp(0x7E8, payload)
    # Interleaved flow control and another CAN identifier do not corrupt state.
    rows.insert(1, (0x7E0, b"\x30\x00\x05"))
    rows.insert(2, (0x7E9, b"\x03\x7f\x27\x35"))
    result = auto.analyze(rows)
    complete = next(row for row in result["messages"] if row["can_id"] == 0x7E8)
    assert complete["payload"] == payload
    assert complete["uds"]["service"] == "ReadDataByIdentifier"
    assert complete["uds"]["data_identifier"] == 0xF190
    assert complete["flag_strings"] == ["CSCTF{uds_multiframe}"]
    negative = next(row for row in result["messages"] if row["can_id"] == 0x7E9)
    assert negative["uds"]["negative_response"] == "invalidKey"
    assert result["flow_control"][0]["st_min"] == 5


def test_can_fd_extended_lengths_and_sequence_failure_decline():
    single = auto.reassemble_isotp([(0x123, b"\x00\x12" + b"A" * 18)])
    assert single["messages"][0]["payload"] == b"A" * 18

    payload = bytes(range(100))
    first = b"\x10\x00" + len(payload).to_bytes(4, "big") + payload[:58]
    rest = b"\x21" + payload[58:]
    got = auto.reassemble_isotp([(0x18DAF110, first), (0x18DAF110, rest)])
    assert got["messages"][0]["payload"] == payload

    damaged = auto.reassemble_isotp([(0x7E8, b"\x10\x09abcdef"),
                                     (0x7E8, b"\x22ghi")])
    assert not damaged["messages"] and "sequence mismatch" in damaged["errors"][0]["reason"]


def test_uds_security_routine_download_and_dtcs():
    seed = auto.decode_uds(bytes.fromhex("6701deadbeef"))
    assert seed["security_operation"] == "seed" and seed["security_level"] == 1
    routine = auto.decode_uds(bytes.fromhex("7101ff00") + b"done")
    assert routine["routine_identifier"] == 0xFF00 and routine["routine_data"] == b"done"
    download = auto.decode_uds(bytes.fromhex("34112212345600"))
    assert download["memory_address"] == 0x1234 and download["memory_size"] == 0x5600
    dtcs = auto.decode_uds(bytes.fromhex("5902ff01345680c1234501"))
    assert [row["dtc"] for row in dtcs["dtcs"]] == ["P013456", "U012345"]


def test_candump_cli_and_guard(tmp_path, capsys):
    trace = tmp_path / "drive.log"
    trace.write_text("(1.25) can0 7E8#0362F190\ncan0 7E9 [4] 03 7F 27 35\n")
    frames = auto.parse_candump(trace.read_text())
    assert frames[0]["timestamp"] == 1.25 and frames[1]["data"] == bytes.fromhex("037f2735")
    assert auto.main([str(trace), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["messages"]) == 2 and report["offline"] is True
    assert auto.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_mutations_never_escape_expected_boundary():
    rng = random.Random(0x157652)
    seed = b"\x10\x16\x62\xf1\x90CSCTF{mutate}" + b"\x00" * 8
    for _ in range(1000):
        blob = bytearray(seed)
        for _ in range(rng.randrange(1, 8)):
            action = rng.randrange(3)
            if action == 0 and blob:
                blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
            elif action == 1 and blob:
                del blob[rng.randrange(len(blob))]
            elif len(blob) < 64:
                blob.insert(rng.randrange(len(blob) + 1), rng.randrange(256))
        if not blob:
            blob.append(0)
        result = auto.reassemble_isotp([(rng.randrange(0x800), bytes(blob[:64]))])
        assert set(result) == {"messages", "flow_control", "errors", "incomplete"}
        for row in result["messages"]:
            assert auto.decode_uds(row["payload"]) is not None


def test_caps_and_invalid_input_fail_closed():
    with pytest.raises(auto.AutomotiveError):
        auto.parse_candump("7E8#123")
    with pytest.raises(auto.AutomotiveError):
        auto.reassemble_isotp([(0x20000000, b"\x00")])
    assert auto.decode_uds(b"") is None
