"""Independent SCP-ECG encoder and literal finite-difference vectors.

Container grammar: EN1064 record header, section IDs, section-0 pointers.
The vectors exercise the crucial second-difference rule: TWO leading values
are raw samples, not a sample followed by an initial first difference.
"""
import json
import struct

import pytest
from crccheck.crc import Crc16Ibm3740

from health2_scp import ScpError, main, parse_scp, read_scp


def section(sid, payload, protocol=20):
    payload += bytes(len(payload) % 2)
    body = struct.pack("<HIBB6s", sid, 16 + len(payload), 20, protocol,
                       b"SCPECG" if sid == 0 else bytes(6)) + payload
    return struct.pack("<H", Crc16Ibm3740.calc(body)) + body


def record(payloads, protocol=20):
    sections = {sid: section(sid, payload, protocol) for sid, payload in payloads.items()}
    assert 0 not in sections
    next_offset = 6 + 136
    pointers = struct.pack("<HII", 0, 136, 7)
    for sid in range(1, 12):
        value = sections.get(sid)
        if value is None:
            pointers += struct.pack("<HII", sid, 0, 0)
        else:
            pointers += struct.pack("<HII", sid, len(value), next_offset + 1)
            next_offset += len(value)
    body = section(0, pointers, protocol) + b"".join(sections[sid] for sid in sorted(sections))
    body = struct.pack("<I", len(body) + 6) + body
    return struct.pack("<H", Crc16Ibm3740.calc(body)) + body


def payloads(order=0):
    # From X1=(10,12,15,19,24), X2=(-5,-3,-4), using published recurrence.
    encoded = {
        0: (10, 12, 15, 19, 24, -5, -3, -4),
        1: (10, 2, 3, 4, 5, -5, 2, -1),
        2: (10, 12, 1, 1, 1, -5, -3, -3),
    }[order]
    comment = b"CSCTF{scp_tlv}\x00"
    patient = b"\x02\x06\x00P0001\x00" + struct.pack("<BH", 30, len(comment)) + comment + b"\xff\x00\x00"
    return {1: patient, 3: b"\x02\x00" + struct.pack("<IIBIIB", 1, 5, 1, 3, 5, 2),
            6: struct.pack("<HHBBHH8h", 1000, 2000, order, 0, 10, 6, *encoded)}


@pytest.mark.parametrize("order", [0, 1, 2])
def test_published_difference_algorithm(order):
    result = parse_scp(record(payloads(order)))
    assert result["leads"][0]["samples"] == [10, 12, 15, 19, 24]
    assert result["leads"][1]["samples"] == [-5, -3, -4]
    assert result["leads"][1]["start_sample"] == 3
    assert result["sample_rate_hz"] == 500
    assert result["resolution_nv"] == 1000
    assert result["difference_order"] == order
    assert result["flags"] == ["CSCTF{scp_tlv}"]
    assert result["patient_fields"][0]["text"] == "P0001"


@pytest.mark.parametrize("value", [None, "test", 1, {}, []])
def test_input_types(value):
    with pytest.raises(ScpError):
        parse_scp(value)


def test_every_truncation_and_trailing_byte():
    data = record(payloads())
    for length in range(len(data)):
        with pytest.raises(ScpError):
            parse_scp(data[:length])
    with pytest.raises(ScpError):
        parse_scp(data + b"\0")


def test_checksum_domains():
    data = bytearray(record(payloads()))
    data[-1] ^= 4
    with pytest.raises(ScpError, match="record"):
        parse_scp(data)
    data[:2] = struct.pack("<H", Crc16Ibm3740.calc(data[2:]))
    with pytest.raises(ScpError, match="section 6 CRC"):
        parse_scp(data)


@pytest.mark.parametrize("sid,offset,replacement", [
    (3, 0, b"\0"), (3, 1, b"\x01"), (3, 2, b"\0\0\0\0"),
    (3, 6, b"\xff\xff\xff\x7f"), (6, 0, b"\0\0"), (6, 2, b"\0\0"),
    (6, 4, b"\x03"), (6, 5, b"\x01"), (6, 6, b"\x08\0"),
])
def test_invalid_profile_fields(sid, offset, replacement):
    values = payloads()
    data = bytearray(values[sid])
    data[offset:offset + len(replacement)] = replacement
    values[sid] = bytes(data)
    with pytest.raises(ScpError):
        parse_scp(record(values))


def test_huffman_and_version_rejected():
    values = payloads()
    values[2] = b"\x1f\x4e"  # Standard Huffman table selector 19999
    with pytest.raises(ScpError, match="Huffman"):
        parse_scp(record(values))
    with pytest.raises(ScpError, match="v1/v2"):
        parse_scp(record(payloads(), protocol=30))


def test_simultaneous_lead_flag_is_bit_two():
    # PhysioNet parsescp.c section3() checks 0x04 for all-leads simultaneous.
    values = payloads()
    values[3] = values[3][:1] + b"\x14" + values[3][2:]
    assert parse_scp(record(values))["leads"][0]["samples"] == [10, 12, 15, 19, 24]
    values[3] = values[3][:1] + b"\x02" + values[3][2:]
    with pytest.raises(ScpError):
        parse_scp(record(values))


def test_missing_section_and_tlv_boundary():
    values = payloads()
    del values[1]
    with pytest.raises(ScpError, match="required"):
        parse_scp(record(values))
    values = payloads()
    values[1] = b"\x01\xff\xff"
    with pytest.raises(ScpError, match="truncated patient"):
        parse_scp(record(values))
    values[1] = b"\x01\x01\0a"
    with pytest.raises(ScpError, match="terminator"):
        parse_scp(record(values))


@pytest.mark.parametrize("limit", [None, "10", True, 0, -1, 7])
def test_limits(limit):
    with pytest.raises(ScpError):
        parse_scp(record(payloads()), max_samples=limit)


def test_overflow_reconstruction():
    values = payloads(1)
    rhythm = bytearray(values[6])
    rhythm[10:14] = struct.pack("<hh", 32767, 1)
    values[6] = bytes(rhythm)
    with pytest.raises(ScpError, match="signed 16"):
        parse_scp(record(values))


def test_pointer_offset_must_be_one_based():
    raw = bytearray(record(payloads()))
    # Section 0 first pointer begins at 22; index is at offset 28.
    raw[28:32] = struct.pack("<I", 6)
    raw[6:8] = struct.pack("<H", Crc16Ibm3740.calc(raw[8:142]))
    raw[:2] = struct.pack("<H", Crc16Ibm3740.calc(raw[2:]))
    with pytest.raises(ScpError, match="pointer"):
        parse_scp(raw)


def test_cli(tmp_path, capsys):
    path = tmp_path / "test.scp"
    path.write_bytes(record(payloads()))
    assert main([str(path), "--samples"]) == 0
    assert json.loads(capsys.readouterr().out)["leads"][0]["samples"] == [10, 12, 15, 19, 24]
    assert main([str(path)]) == 0
    assert "samples_preview" in json.loads(capsys.readouterr().out)["leads"][0]
    assert main([]) == 2
    assert main(["--help"]) == 0
    assert main([str(path / "missing")]) == 2
    with pytest.raises(ScpError):
        read_scp(tmp_path)


def test_cli_string_exit(monkeypatch):
    import argparse

    def fail(*args, **kwargs):
        raise SystemExit("text")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", fail)
    assert main([]) == 2
