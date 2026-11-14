"""Deterministic tests for offline CAN-FD, UDS, J1939, and keyless analysis."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import automotive_advanced as auto  # noqa: E402


def frame(can_id: int, data: bytes, index: int, *, timestamp: float | None = None, fd: bool = False) -> dict:
    return {"can_id": can_id, "data": data, "index": index, "timestamp": timestamp, "fd": fd}


def test_candump_classic_fd_verbose_dlc_and_strict_lengths() -> None:
    artifact = """
    (1.250000) can0 7E0#0210030000000000
    can1 123##1AABBCCDDEEFF001122
    (2.0) vcan0 18ECFF80 [8] 20 0A 00 02 FF CA FE 00
    """
    rows = auto.parse_candump(artifact)
    assert len(rows) == 3
    assert rows[0]["timestamp"] == 1.25 and rows[0]["data"][:3] == bytes.fromhex("021003")
    assert rows[1]["fd"] and rows[1]["bit_rate_switch"] and rows[1]["length"] == 9 and rows[1]["dlc"] == 9
    assert rows[2]["extended"] and rows[2]["can_id"] == 0x18ECFF80
    assert [auto.can_fd_dlc_length(value) for value in (8, 9, 10, 15)] == [8, 12, 16, 64]
    assert auto.can_fd_length_dlc(13) == 10
    with pytest.raises(auto.AutomotiveParseError, match="declared length"):
        auto.parse_candump_line("can0 123 [2] AA")
    with pytest.raises(auto.AutomotiveParseError, match="capacity"):
        auto.parse_candump_line("123#" + "00" * 9)


def isotp_frames(can_id: int, payload: bytes, start: int = 0, *, fd: bool = False) -> list[dict]:
    if len(payload) <= 7 and not fd:
        return [frame(can_id, bytes((len(payload),)) + payload + bytes(7 - len(payload)), start)]
    rows = [frame(can_id, bytes((0x10 | (len(payload) >> 8), len(payload) & 0xFF)) + payload[:6], start, timestamp=0.0, fd=fd)]
    cursor, sequence = 6, 1
    while cursor < len(payload):
        chunk = payload[cursor:cursor + (63 if fd else 7)]
        rows.append(frame(can_id, bytes((0x20 | sequence,)) + chunk + bytes((63 if fd else 7) - len(chunk)), start + len(rows),
                          timestamp=len(rows) * 0.01, fd=fd))
        cursor += len(chunk)
        sequence = (sequence + 1) & 0xF
    return rows


def test_isotp_single_multiframe_flow_control_padding_and_sequence_wrap() -> None:
    payload = bytes(range(1, 121))
    rows = isotp_frames(0x7E8, payload)
    # More than 15 CFs forces legal sequence wrap through zero.
    rows.insert(1, frame(0x7E0, bytes.fromhex("3005f30000000000"), 999, timestamp=0.001))
    report = auto.reassemble_isotp(rows)
    assert report["messages"][0]["data"] == payload
    assert len(report["messages"][0]["frame_indices"]) == 18
    assert report["flow_controls"][0]["status_name"] == "continue-to-send"
    assert report["flow_controls"][0]["stmin_seconds"] == pytest.approx(0.0003)
    assert report["issues"] == []

    single = auto.reassemble_isotp([frame(0x700, bytes.fromhex("03aabbcc00000000"), 0)])
    assert single["messages"][0]["data"] == bytes.fromhex("aabbcc")
    assert single["messages"][0]["padding"] == bytes(4)
    bad = rows.copy()
    bad[3] = {**bad[3], "data": bytes((0x2F,)) + bad[3]["data"][1:]}
    damaged = auto.reassemble_isotp(bad)
    assert any(issue["kind"] == "sequence-mismatch" for issue in damaged["issues"])
    noncanonical = auto.reassemble_isotp([frame(0x700, bytes.fromhex("1003010203000000"), 0)])
    assert noncanonical["issues"][0]["kind"] == "noncanonical-first-frame"


def test_isotp_can_fd_escape_single_extended_address_and_timeout() -> None:
    payload = bytes(range(20))
    fd_single = frame(0x18DAF110, bytes((0, len(payload))) + payload, 0, fd=True)
    report = auto.reassemble_isotp([fd_single])
    assert report["messages"][0]["data"] == payload

    addressed = frame(0x700, bytes.fromhex("f103112233000000"), 1)
    parsed = auto.reassemble_isotp([addressed], address_byte=0xF1)
    assert parsed["messages"][0]["address"] == 0xF1
    assert parsed["messages"][0]["data"] == bytes.fromhex("112233")

    timeout_rows = [
        frame(0x700, bytes.fromhex("100a010203040506"), 0, timestamp=0.0),
        frame(0x700, bytes.fromhex("210708090a000000"), 1, timestamp=2.0),
    ]
    timed = auto.reassemble_isotp(timeout_rows, timeout=1.0)
    assert [issue["kind"] for issue in timed["issues"]] == ["timeout", "orphan-consecutive-frame"]


def test_uds_service_depth_strict_fields_and_negative_response() -> None:
    assert auto.parse_uds_message(bytes.fromhex("1003"), direction="request")["subfunction"] == 3
    security = auto.parse_uds_message(bytes.fromhex("2702aabbcc"), direction="request")
    assert security["service_name"] == "SecurityAccess" and security["security_access_kind"] == "key"
    negative = auto.parse_uds_message(bytes.fromhex("7f2735"))
    assert negative["negative"] and negative["nrc_name"] == "invalidKey"
    download = auto.parse_uds_message(bytes.fromhex("3400440000100000002000"), direction="request")
    assert download["memory_address"] == 0x1000 and download["memory_size"] == 0x2000
    response = auto.parse_uds_message(bytes.fromhex("74200100"), direction="response")
    assert response["max_block_length"] == 0x100
    write = auto.parse_uds_message(bytes.fromhex("2ef1904353435446"), direction="request")
    assert write["did"] == 0xF190 and write["data"] == "4353435446"
    routine = auto.parse_uds_message(bytes.fromhex("3101ff001337"), direction="request")
    assert routine["routine_id"] == 0xFF00 and routine["subfunction"] == 1
    with pytest.raises(auto.AutomotiveParseError, match="address/length"):
        auto.parse_uds_message(bytes.fromhex("3400440010"), direction="request")


def test_stateful_uds_transactions_security_write_and_transfer_findings() -> None:
    messages = [
        (0x7E0, bytes.fromhex("2702aabb")),
        (0x7E8, bytes.fromhex("7f2735")),
        (0x7E0, bytes.fromhex("2ef1904353")),
        (0x7E8, bytes.fromhex("6ef190")),
        (0x7E0, bytes.fromhex("3601435446")),
        (0x7E8, bytes.fromhex("7601")),
    ]
    frames = []
    for index, (can_id, payload) in enumerate(messages):
        frames.extend(isotp_frames(can_id, payload, index * 10))
    report = auto.analyze_uds(frames, request_ids=(0x7E0,), response_ids=(0x7E8,))
    assert [(row["service"], row["negative"]) for row in report["transactions"]] == [(0x27, True), (0x2E, False), (0x36, False)]
    kinds = {row["kind"] for row in report["findings"]}
    assert kinds == {"security-key-attempt", "diagnostic-write", "firmware-transfer"}
    assert report["unanswered_requests"] == []


def test_j1939_identifier_bam_transport_sequence_and_dm1() -> None:
    source, target_pgn = 0x80, 0xFECA
    cm_id = auto.j1939_id(auto.J1939_TP_CM, source, destination=0xFF)
    dt_id = auto.j1939_id(auto.J1939_TP_DT, source, destination=0xFF)
    assert auto.parse_j1939_id(cm_id) == {
        "priority": 6, "reserved": 0, "data_page": 0, "pdu_format": 0xEC,
        "pdu_specific": 0xFF, "source": source, "destination": 0xFF, "pgn": auto.J1939_TP_CM,
    }
    payload = bytes.fromhex("55004523018102030405")
    announce = bytes((0x20, len(payload), 0, 2, 0xFF)) + target_pgn.to_bytes(3, "little")
    frames = [
        frame(cm_id, announce, 0, timestamp=0.0),
        frame(dt_id, b"\x01" + payload[:7], 1, timestamp=0.1),
        frame(dt_id, b"\x02" + payload[7:] + b"\xff" * 4, 2, timestamp=0.2),
    ]
    report = auto.reassemble_j1939_tp(frames)
    assert report["messages"][0]["pgn"] == target_pgn
    assert report["messages"][0]["data"] == payload
    assert report["controls"][0]["control_name"] == "BAM" and report["issues"] == []
    damaged = frames.copy(); damaged[2] = {**damaged[2], "data": b"\x03" + damaged[2]["data"][1:]}
    assert auto.reassemble_j1939_tp(damaged)["issues"][0]["kind"] == "tp-sequence-mismatch"

    spn, fmi = 0x12345, 7
    dtc = bytes((spn & 0xFF, (spn >> 8) & 0xFF, ((spn >> 16) << 5) | fmi, 0x82))
    dm1 = auto.parse_j1939_dm1(bytes((0x55, 0xAA)) + dtc + b"\xff\xff")
    assert dm1["dtcs"] == [{"spn": spn, "fmi": fmi, "occurrence_count": 2,
                             "conversion_method": True, "raw": dtc.hex()}]
    assert dm1["padding"] == "ffff"
    assert dm1["lamps"]["malfunction"] == 1 and dm1["lamp_flashes"]["malfunction"] == 2
    assert auto.parse_j1939_dm1(bytes((0, 0)) + b"\xff" * 4)["dtcs"] == []


def test_j1939_fast_packet_reassembly_and_orphan_detection() -> None:
    pgn, source, data = 0x1F112, 0x23, b"CSCTF{fast-packet}"
    can_id = auto.j1939_id(pgn, source)
    sequence = 3
    rows = [frame(can_id, bytes((sequence << 5, len(data))) + data[:6], 0)]
    cursor, counter = 6, 1
    while cursor < len(data):
        chunk = data[cursor:cursor + 7]
        rows.append(frame(can_id, bytes(((sequence << 5) | counter,)) + chunk + b"\xff" * (7 - len(chunk)), len(rows)))
        cursor += len(chunk); counter += 1
    report = auto.reassemble_j1939_fast_packets(rows)
    assert report["messages"][0]["data"] == data and report["issues"] == []
    orphan = auto.reassemble_j1939_fast_packets(rows[1:])
    assert orphan["issues"][0]["kind"] == "orphan-fast-packet"


def test_keeloq_known_vector_roundtrip_plaintext_and_sequence_analysis() -> None:
    plaintext, key, ciphertext = 0xF741E2DB, 0x5CEC6701B79FD949, 0xE44F4CDF
    assert auto.keeloq_encrypt(plaintext, key) == ciphertext
    assert auto.keeloq_decrypt(ciphertext, key) == plaintext
    decoded = auto.parse_keeloq_plaintext(plaintext)
    assert decoded["counter"] == 0xE2DB
    assert auto.keeloq_encrypt(auto.keeloq_decrypt(0x12345678, key), key) == 0x12345678
    assert auto.analyze_keeloq_frames([{"serial": "hex", "hopping_code": "E44F4CDF"}], key)["decoded"][0]["counter"] == 0xE2DB

    codes = []
    for counter in (100, 101, 120):
        plain = counter | (0x155 << 16) | (3 << 26)
        codes.append({"serial": "A1", "button": "lock", "hopping_code": auto.keeloq_encrypt(plain, key)})
    report = auto.analyze_keeloq_frames(codes, key)
    assert [row["counter"] for row in report["decoded"]] == [100, 101, 120]
    assert report["sequence_analysis"]["sequences"][0]["deltas"] == [1, 19]
    assert report["sequence_analysis"]["findings"][0]["kind"] == "resynchronization-gap"


def test_rolling_counter_wrap_replay_collision_rollback_and_fixed_code() -> None:
    records = [
        {"serial": "A", "button": "unlock", "counter": 65534, "hopping_code": 1},
        {"serial": "A", "button": "unlock", "counter": 1, "hopping_code": 2},
        {"serial": "A", "button": "unlock", "counter": 20, "hopping_code": 3},
        {"serial": "A", "button": "unlock", "counter": 20, "hopping_code": 3},
        {"serial": "A", "button": "unlock", "counter": 10, "hopping_code": 4},
        {"serial": "B", "button": "lock", "counter": 1, "hopping_code": 9},
        {"serial": "B", "button": "lock", "counter": 2, "hopping_code": 9},
    ]
    report = auto.analyze_rolling_codes(records)
    a = next(row for row in report["sequences"] if row["serial"] == "A")
    assert a["deltas"] == [3, 19, 0, 65526]
    kinds = {row["kind"] for row in report["findings"]}
    assert {"replayed-hopping-code", "duplicate-counter", "counter-rollback", "resynchronization-gap", "fixed-code-behavior"} <= kinds


def test_malformed_bounds_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    malformed = [
        frame(0x700, b"", 0), frame(0x700, b"\x10", 1), frame(0x700, b"\x21abc", 2),
        frame(0x700, b"\x30", 3), frame(0x700, b"\xf0", 4),
    ]
    report = auto.reassemble_isotp(malformed)
    assert {row["kind"] for row in report["issues"]} == {
        "missing-pci", "truncated-first-frame", "orphan-consecutive-frame", "truncated-flow-control", "unknown-pci",
    }
    with pytest.raises(auto.AutomotiveParseError):
        auto.parse_j1939_id(1 << 29)
    with pytest.raises(auto.AutomotiveParseError):
        auto.analyze_rolling_codes([{"counter": 1}])

    artifact = tmp_path / "capture.log"
    artifact.write_text("can0 7E0#0210030000000000\n", encoding="utf-8")
    assert auto.main(["isotp", str(artifact)]) == 0
    assert json.loads(capsys.readouterr().out)["messages"][0]["data"] == "1003"
