"""Independent wire-vector and fail-closed tests for sec_dds_rtps."""
from __future__ import annotations

from array import array
import json
import random
import struct

import pytest
from scapy.contrib.rtps.rtps import RTPS

import sec_dds_rtps as engine


RTPS_HEADER = bytes.fromhex("525450530205010f0102030405060708090a0b0c")
INFO_TS = bytes.fromhex("090108000100000000000080")
DATA_42 = bytes.fromhex(
    "15051c00"          # DATA, E|D, 28-byte body
    "00001000"          # extraFlags=0, octetsToInlineQos=16
    "00000000"          # reader unknown
    "000001c2"          # writer entity
    "0000000001000000"  # SequenceNumber high=0, low=1 in LE
    "000100002a000000"  # CDR_LE, options 0, uint32 42
)
HEARTBEAT = bytes.fromhex(
    "07031c00"          # HEARTBEAT E|F, 28 bytes
    "000001c7000001c2"  # reader, writer
    "0000000001000000"  # first=1
    "0000000003000000"  # last=3
    "02000000"          # count=2
)
COMPOUND = RTPS_HEADER + INFO_TS + DATA_42 + HEARTBEAT

XRCE_WRITE = bytes.fromhex("dd80010007010600aa0144051900")
XRCE_DATA_BE = bytes.fromhex("dd01010009000800aa01440600000013")
XRCE_CREATE_REAL = bytes.fromhex(
    "80000000" "00011000" "585243450100010faabbccdd8100fc07"
)
XRCE_HEARTBEAT_REAL = bytes.fromhex("810000000b0105000100010080")


def test_rtps_header_and_info_timestamp_match_scapy_oracle():
    # Scapy is an independent implementation of the RTPS 2.x header/INFO_TS grammar.
    oracle = RTPS(RTPS_HEADER + INFO_TS)
    expected_version = (oracle.protocolVersion.major, oracle.protocolVersion.minor)
    expected_ts = oracle.payload.submessages[0]
    out = engine.parse_rtps(RTPS_HEADER + INFO_TS)
    assert (out["header"]["protocol_version"]["major"],
            out["header"]["protocol_version"]["minor"]) == expected_version == (2, 5)
    assert out["header"]["vendor_name"] == "eProsima Fast DDS"
    assert out["submessages"][0]["seconds"] == expected_ts.ts_seconds == 1
    assert out["submessages"][0]["fraction"] == expected_ts.ts_fraction == 0x80000000


def test_published_compound_layout_and_cdr_preview():
    out = engine.parse_rtps(COMPOUND)
    assert out["length"] == 96
    assert [(item["name"], item["offset"]) for item in out["submessages"]] == [
        ("INFO_TS", 20), ("DATA", 32), ("HEARTBEAT", 64)]
    data = out["submessages"][1]
    assert data["writer_sn"]["value"] == 1
    assert data["serialized_payload"]["representation"] == "CDR_LE"
    assert data["serialized_payload"]["scalar_preview"]["u32"] == 42
    assert out["submessages"][2]["first_sn"]["value"] == 1
    assert out["submessages"][2]["last_sn"]["value"] == 3


def test_acknack_bitmap_uses_spec_msb_first_numbering():
    # OMG's SequenceNumberSet maps offset zero to bit 31. Base=5, bits 0 and 2.
    ack = bytes.fromhex(
        "06031c00" "000001c7" "000001c2" "0000000005000000"
        "03000000" "000000a0" "07000000"
    )
    out = engine.parse_rtps(RTPS_HEADER + ack)["submessages"][0]
    assert out["final"] is True
    assert out["reader_state"]["selected"] == [5, 7]
    assert out["count"] == 7


def test_inline_qos_parameter_list_and_key_payload():
    # Hand-built directly from RTPS 2.5 DATA and ParameterList layouts.
    qos = struct.pack("<HH", 0x0071, 4) + b"\x01\x00\x00\x00" + struct.pack("<HH", 1, 0)
    payload = b"\x00\x00\x00\x00" + struct.pack(">I", 9)
    fixed = struct.pack("<HH", 0, 16) + b"\0" * 4 + b"\x00\x00\x01\xc2" + struct.pack("<iI", 0, 9)
    body = fixed + qos + payload
    raw = RTPS_HEADER + bytes((0x15, 0x0B)) + struct.pack("<H", len(body)) + body
    item = engine.parse_rtps(raw)["submessages"][0]
    assert item["inline_qos"][0]["name"] == "PID_STATUS_INFO"
    assert item["inline_qos"][-1]["name"] == "PID_SENTINEL"
    assert item["payload_kind"] == "key"
    assert item["serialized_payload"]["representation"] == "CDR_BE"
    assert item["serialized_payload"]["scalar_preview"]["u32"] == 9


def test_xcdr2_mutable_preview_does_not_apply_legacy_parameter_list_grammar():
    # DDSI-RTPS 2.5 Table 10.3: 00 13 is PL_CDR2_LE.  XCDR2 uses a
    # DHEADER/EMHEADER stream, so this schema-free engine may expose only its
    # delimiter, never reinterpret it as an XCDR1 PID/length pair.
    payload = b"\x00\x13\x00\x00" + struct.pack("<I", 4) + b"\x00\x00\x00\x00"
    fixed = struct.pack("<HH", 0, 16) + b"\0" * 4 + b"\x00\x00\x01\xc2" + struct.pack("<iI", 0, 2)
    body = fixed + payload
    raw = RTPS_HEADER + bytes((0x15, 0x05)) + struct.pack("<H", len(body)) + body
    decoded = engine.parse_rtps(raw)["submessages"][0]["serialized_payload"]
    assert decoded["representation"] == "PL_CDR2_LE"
    assert decoded["delimiter_size"] == 4
    assert "parameters" not in decoded


def test_info_source_destination_and_reply_vectors():
    src = bytes.fromhex("0c011400000000000205010f0102030405060708090a0b0c")
    dst = bytes.fromhex("0e010c000102030405060708090a0b0c")
    reply = bytes.fromhex(
        "0f011c00" "01000000" "01000000" "e81c0000"
        "000000000000000000000000c0000201"
    )
    out = engine.parse_rtps(RTPS_HEADER + src + dst + reply)["submessages"]
    assert out[0]["protocol_version"] == {"major": 2, "minor": 5}
    assert out[1]["guid_prefix"] == "0102030405060708090a0b0c"
    assert out[2]["unicast_locators"][0]["kind"] == 1
    assert out[2]["unicast_locators"][0]["port"] == 7400
    assert out[2]["unicast_locators"][0]["ipv4"] == "192.0.2.1"


def test_xrce_published_omg_write_and_data_vectors():
    write = engine.parse_xrce(XRCE_WRITE)
    assert write["header"]["session_id"] == 0xDD
    assert write["header"]["stream_reliability"] == "reliable"
    assert write["submessages"][0]["name"] == "WRITE_DATA"
    assert write["submessages"][0]["serialized_data"]["preview_hex"] == "1900"
    data = engine.parse_xrce(XRCE_DATA_BE)
    assert data["header"]["stream_reliability"] == "best-effort"
    assert data["submessages"][0]["endianness"] == "big"
    assert int.from_bytes(bytes.fromhex(data["submessages"][0]["serialized_data"]["preview_hex"]), "big") == 19


def test_xrce_real_eprosima_and_microros_vectors():
    create = engine.parse_xrce(XRCE_CREATE_REAL)["submessages"][0]
    assert create["cookie"] == "XRCE"
    assert create["vendor_id"] == "010f"
    assert create["client_key"] == "aabbccdd"
    assert create["requested_session_id"] == 0x81
    assert create["eprosima_mtu_extension"] == 2044
    heartbeat = engine.parse_xrce(XRCE_HEARTBEAT_REAL)["submessages"][0]
    assert heartbeat == {"offset": 4, "id": 11, "name": "HEARTBEAT", "flags": 1,
        "endianness": "little", "payload_length": 5, "first_unacked": 1,
        "last_unacked": 1, "target_stream_id": 0x80}


def test_xrce_conditional_key_header_ack_bitmap_and_timestamp():
    ack = bytes.fromhex("01003412deadbeef0a0105006400400980")
    parsed = engine.parse_xrce(ack)
    assert parsed["header"]["client_key"] == "deadbeef"
    item = parsed["submessages"][0]
    assert item["first_unacked"] == 100
    assert item["missing"] == [100, 103, 114]
    ts = bytes.fromhex("810000000e0108008caa885a0065cd1d")
    stamp = engine.parse_xrce(ts)["submessages"][0]["transmit_timestamp"]
    assert stamp == {"seconds": 1518905996, "nanoseconds": 500000000, "valid_nanoseconds": True}


def test_published_malformed_data_offset_is_declared_error():
    raw = bytes.fromhex(
        "525450530204010f01030242ac11000245e5e2fd"
        "151718000000109200000000000100c2000000000200000001000000"
    )
    with pytest.raises(engine.SecDDSRTPSError, match="octetsToInlineQos"):
        engine.parse_rtps(raw)


@pytest.mark.parametrize("public", [engine.parse_rtps, engine.parse_xrce, engine.analyze])
def test_public_contract_rejects_wrong_types_and_empty(public):
    for value in (None, "RTPS", 1, object(), b""):
        with pytest.raises(engine.SecDDSRTPSError):
            public(value)


def test_fail_closed_fuzz_truncation_random_bitflips_and_oversize(monkeypatch):
    rng = random.Random(0xDD5A)
    cases = [b"", b"RTPS", b"\xff" * 97]
    cases += [COMPOUND[:i] for i in range(len(COMPOUND))]
    cases += [XRCE_CREATE_REAL[:i] for i in range(len(XRCE_CREATE_REAL))]
    cases += [rng.randbytes(rng.randrange(0, 160)) for _ in range(256)]
    for seed in (COMPOUND, XRCE_CREATE_REAL):
        for _ in range(128):
            raw = bytearray(seed)
            pos = rng.randrange(len(raw))
            raw[pos] ^= 1 << rng.randrange(8)
            cases.append(bytes(raw))
    for raw in cases:
        for parser in (engine.parse_rtps, engine.parse_xrce):
            try:
                assert isinstance(parser(raw), dict)
            except engine.SecDDSRTPSError:
                pass
    monkeypatch.setattr(engine, "MAX_INPUT", 8)
    with pytest.raises(engine.SecDDSRTPSError, match="limit"):
        engine.analyze(memoryview(array("I", [0, 0, 0])))


def test_cli_guard_json_and_clean_errors(tmp_path, capsys):
    assert engine.main([]) == 2
    assert engine.main(["--help"]) == 0
    path = tmp_path / "rtps.bin"
    path.write_bytes(COMPOUND)
    capsys.readouterr()
    assert engine.main([str(path), "--protocol", "rtps"]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "DDSI-RTPS"
    path.write_bytes(b"bad")
    assert engine.main([str(path)]) == 2
    assert "sec_dds_rtps:" in capsys.readouterr().err
