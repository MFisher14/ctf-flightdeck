"""Synthetic classic-PCAP and PCAPNG tests for the r5f offline ICS capture engine."""
from __future__ import annotations

import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import ics_capture as capture  # noqa: E402
import ics_protocols as protocols  # noqa: E402


def modbus_tcp(transaction: int, pdu: bytes, unit: int = 1) -> bytes:
    return struct.pack(">HHHB", transaction, 0, len(pdu) + 1, unit) + pdu


def ethernet_ipv4_tcp(
    payload: bytes,
    source: bytes,
    destination: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
) -> bytes:
    tcp = (
        struct.pack(">HHII", source_port, destination_port, sequence, 0)
        + b"\x50\x18"
        + struct.pack(">HHH", 8192, 0, 0)
        + payload
    )
    total = 20 + len(tcp)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", total)
        + b"\x12\x34\x40\x00\x40\x06\x00\x00"
        + source
        + destination
        + tcp
    )
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip


def ethernet_ipv4_udp(
    payload: bytes,
    source: bytes,
    destination: bytes,
    source_port: int,
    destination_port: int,
) -> bytes:
    udp = struct.pack(">HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ip = (
        b"\x45\x00"
        + struct.pack(">H", 20 + len(udp))
        + b"\x56\x78\x00\x00\x40\x11\x00\x00"
        + source
        + destination
        + udp
    )
    return b"\xcc" * 6 + b"\xdd" * 6 + b"\x08\x00" + ip


def ethernet_ipv4_fragment(
    payload: bytes,
    source: bytes,
    destination: bytes,
    *,
    identification: int,
    offset: int,
    more: bool,
    protocol: int = 17,
) -> bytes:
    assert offset % 8 == 0
    fragment_field = (offset // 8) | (0x2000 if more else 0)
    ip = (
        b"\x45\x00"
        + struct.pack(">H", 20 + len(payload))
        + struct.pack(">HHBBH", identification, fragment_field, 64, protocol, 0)
        + source
        + destination
        + payload
    )
    return b"\xee" * 6 + b"\xff" * 6 + b"\x08\x00" + ip


def classic_pcap(frames: list[bytes]) -> bytes:
    out = bytearray(b"\xd4\xc3\xb2\xa1")
    out.extend(struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        out.extend(struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(frame), len(frame)))
        out.extend(frame)
    return bytes(out)


def pcapng_block(kind: int, body: bytes) -> bytes:
    body += b"\x00" * ((-len(body)) & 3)
    length = 12 + len(body)
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def pcapng(frame: bytes) -> bytes:
    section = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        + struct.pack("<I", 28)
    )
    options = struct.pack("<HHB", 9, 1, 6) + b"\x00\x00\x00" + b"\x00\x00\x00\x00"
    interface = pcapng_block(1, struct.pack("<HxxI", 1, 65535) + options)
    enhanced = pcapng_block(6, struct.pack("<IIIII", 0, 0, 1_000_000, len(frame), len(frame)) + frame)
    return section + interface + enhanced


def dnp3_frame(user: bytes) -> bytes:
    header = b"\x05\x64" + bytes([5 + len(user), 0xC4]) + struct.pack("<HH", 1, 2)
    out = header + struct.pack("<H", protocols.crc16_dnp3(header))
    for offset in range(0, len(user), 16):
        block = user[offset : offset + 16]
        out += block + struct.pack("<H", protocols.crc16_dnp3(block))
    return out


def s7_setup_frame() -> bytes:
    parameter = b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
    s7 = b"\x32\x01\x00\x00\x00\x01" + struct.pack(">HH", len(parameter), 0) + parameter
    return b"\x03\x00" + struct.pack(">H", 7 + len(s7)) + b"\x02\xf0\x80" + s7


def enip_register_frame() -> bytes:
    payload = b"\x01\x00\x00\x00"
    return struct.pack("<HHII", 0x65, len(payload), 0, 0) + b"\x00" * 8 + b"\x00" * 4 + payload


def test_classic_pcap_reassembly_transactions_udp_and_flags() -> None:
    client, server = bytes([10, 0, 0, 5]), bytes([10, 0, 0, 9])
    request = modbus_tcp(0x1234, b"\x03\x00\x10\x00\x02")
    response = modbus_tcp(0x1234, b"\x03\x04\x00\x2a\x00\x2b")
    cut = 5
    # Deliberately store the second TCP segment first; sequence sorting must recover the ADU.
    frames = [
        ethernet_ipv4_tcp(request[cut:], client, server, 40000, 502, 1000 + cut),
        ethernet_ipv4_tcp(request[:cut], client, server, 40000, 502, 1000),
        ethernet_ipv4_tcp(response, server, client, 502, 40000, 9000),
    ]
    bacnet = b"\x81\x0b\x00\x08\x01\x00\x10\x08"
    frames.append(ethernet_ipv4_udp(bacnet, client, server, 40001, 47808))
    report = capture.analyze_capture(classic_pcap(frames))
    assert report["packet_count"] == 4
    assert report["protocol_counts"] == {"bacnet": 1, "modbus": 2}
    assert report["messages"][0]["decoded"]["pdu"]["address"] == 0x10
    assert report["messages"][1]["decoded"]["pdu"]["registers"] == [42, 43]
    assert report["transactions"] == [{"protocol": "modbus", "request": 0, "response": 1, "id": 0x1234}]
    assert report["messages"][2]["decoded"]["apdu"]["service_name"] == "who-Is"


def test_pcapng_options_extraction_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    client, server = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
    request = modbus_tcp(3, b"\x06\x00\x01\x13\x37")
    frame = ethernet_ipv4_tcp(request, client, server, 50000, 502, 77)
    artifact = pcapng(frame)
    packets = list(capture.iter_capture(artifact))
    assert len(packets) == 1
    assert packets[0]["timestamp"] == 1.0
    report = capture.analyze_capture(artifact)
    assert report["format"] == "pcapng"
    assert report["messages"][0]["decoded"]["pdu"]["value"] == 0x1337
    assert report["messages"][0]["decoded"]["pdu"]["findings"][0]["kind"] == "register-write"
    assert any(row["kind"] == "register-write" and row["message"] == 0 for row in report["findings"])

    path = tmp_path / "one.pcapng"
    path.write_bytes(artifact)
    assert capture.main([str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output[0]["analysis"]["packet_count"] == 1


def test_capture_dispatches_every_supported_tcp_ics_protocol() -> None:
    client, server = bytes([198, 51, 100, 10]), bytes([198, 51, 100, 20])
    payloads = [
        (40001, 102, s7_setup_frame()),
        (40002, 20000, dnp3_frame(b"\xc0\xc1\x01\x3c\x02\x06")),
        (40003, 44818, enip_register_frame()),
        (40004, 2404, b"\x68\x04\x07\x00\x00\x00"),
    ]
    frames = [
        ethernet_ipv4_tcp(payload, client, server, source_port, destination_port, 1000 + index * 100)
        for index, (source_port, destination_port, payload) in enumerate(payloads)
    ]
    report = capture.analyze_capture(classic_pcap(frames))
    assert report["protocol_counts"] == {"dnp3": 1, "enip": 1, "iec104": 1, "s7comm": 1}
    by_protocol = {row["protocol"]: row["decoded"] for row in report["messages"]}
    assert by_protocol["s7comm"]["s7"]["function_name"] == "Setup Communication"
    assert by_protocol["dnp3"]["application"]["function_name"] == "READ"
    assert report["dnp3_reassemblies"] == []
    assert by_protocol["enip"]["protocol_version"] == 1
    assert by_protocol["iec104"]["u_function"] == "STARTDT act"


def test_split_frames_retransmission_gaps_and_malformed_capture() -> None:
    first = modbus_tcp(1, b"\x03\x00\x00\x00\x01")
    second = modbus_tcp(2, b"\x03\x00\x01\x00\x01")
    frames, trailing = capture.split_frames("modbus", first + second + b"\x00")
    assert frames == [first, second]
    assert trailing == b"\x00"

    packets = [
        {
            "transport": "tcp",
            "source": "a",
            "source_port": 1,
            "destination": "b",
            "destination_port": 502,
            "sequence": 10,
            "packet_index": 0,
            "payload": b"abcdef",
        },
        {
            "transport": "tcp",
            "source": "a",
            "source_port": 1,
            "destination": "b",
            "destination_port": 502,
            "sequence": 13,
            "packet_index": 1,
            "payload": b"dXfghi",
        },
        {
            "transport": "tcp",
            "source": "a",
            "source_port": 1,
            "destination": "b",
            "destination_port": 502,
            "sequence": 30,
            "packet_index": 2,
            "payload": b"tail",
        },
    ]
    stream = capture.reassemble_tcp(packets)[0]
    assert stream["retransmitted_bytes"] == 3
    assert stream["conflicting_retransmitted_bytes"] == 1
    assert stream["gaps"] == 1
    assert [chunk["data"] for chunk in stream["chunks"]] == [b"abcdefghi", b"tail"]

    with pytest.raises(capture.ParseError):
        list(capture.iter_capture(b"bad"))


def test_tcp_sequence_wrap_reused_sessions_and_dual_known_ports() -> None:
    wrap_packets = [
        {
            "transport": "tcp", "source": "a", "source_port": 40000,
            "destination": "b", "destination_port": 502,
            "sequence": 0xFFFFFFFC, "packet_index": 0, "tcp_flags": 0x18, "payload": b"abcd",
        },
        {
            "transport": "tcp", "source": "a", "source_port": 40000,
            "destination": "b", "destination_port": 502,
            "sequence": 0, "packet_index": 1, "tcp_flags": 0x18, "payload": b"efgh",
        },
    ]
    wrapped = capture.reassemble_tcp(wrap_packets)[0]
    assert wrapped["gaps"] == 0
    assert wrapped["chunks"][0]["data"] == b"abcdefgh"

    session_packets = [
        {
            "transport": "tcp", "source": "a", "source_port": 40000,
            "destination": "b", "destination_port": 502,
            "sequence": 100, "packet_index": 0, "tcp_flags": 0x02, "payload": b"",
        },
        {
            "transport": "tcp", "source": "a", "source_port": 40000,
            "destination": "b", "destination_port": 502,
            "sequence": 101, "packet_index": 1, "tcp_flags": 0x18, "payload": modbus_tcp(1, b"\x03\x00\x00\x00\x01"),
        },
        {
            "transport": "tcp", "source": "a", "source_port": 40000,
            "destination": "b", "destination_port": 502,
            "sequence": 500, "packet_index": 2, "tcp_flags": 0x02, "payload": b"",
        },
        {
            "transport": "tcp", "source": "a", "source_port": 40000,
            "destination": "b", "destination_port": 502,
            "sequence": 501, "packet_index": 3, "tcp_flags": 0x18, "payload": modbus_tcp(2, b"\x03\x00\x00\x00\x01"),
        },
    ]
    streams = capture.reassemble_tcp(session_packets)
    assert [stream["session"] for stream in streams] == [1, 2]

    response = modbus_tcp(3, b"\x03\x02\x00\x2a")
    assert capture._known_protocol(502, 2404, response) == "modbus"
    assert capture._direction("modbus", 502, 2404) == "response"


def test_dnp3_application_fragment_reassembly() -> None:
    application = b"\xc1\x01\x3c\x02\x06"  # READ, class-1 request with qualifier all-objects
    decoded = [
        protocols.parse_dnp3(dnp3_frame(b"\x40" + application[:2])),
        protocols.parse_dnp3(dnp3_frame(b"\x81" + application[2:])),
    ]
    messages = [
        {
            "protocol": "dnp3",
            "source": "master",
            "source_port": 30000,
            "destination": "outstation",
            "destination_port": 20000,
            "decoded": row,
        }
        for row in decoded
    ]
    findings: list[dict] = []
    completed = capture._reassemble_dnp3_applications(messages, findings)
    assert completed == [{"first_message": 0, "last_message": 1, "messages": [0, 1], "byte_length": 5}]
    assert messages[1]["decoded"]["reassembled_application"]["function_name"] == "READ"
    assert messages[1]["decoded"]["reassembled_application"]["objects"][0]["group_name"] == "Class Data"
    assert findings == []


def test_segmented_s7_ip_fragments_enip_io_and_dnp_link_sequence_keys() -> None:
    client, server = bytes([203, 0, 113, 10]), bytes([203, 0, 113, 20])
    whole = s7_setup_frame()
    s7_payload = whole[7:]
    split = len(s7_payload) // 2
    first_piece = b"\x03\x00" + struct.pack(">H", 7 + split) + b"\x02\xf0\x00" + s7_payload[:split]
    second_payload = s7_payload[split:]
    second_piece = b"\x03\x00" + struct.pack(">H", 7 + len(second_payload)) + b"\x02\xf0\x80" + second_payload
    s7_wire = first_piece + second_piece
    s7_frame = ethernet_ipv4_tcp(s7_wire, client, server, 41000, 102, 100)

    implicit = struct.pack("<II", 0x01020304, 8) + b"CSCTF{io}"
    io_frame = ethernet_ipv4_udp(implicit, client, server, 41001, 2222)

    bacnet = b"\x81\x0b\x00\x08\x01\x00\x10\x08"
    udp = struct.pack(">HHHH", 41002, 47808, 8 + len(bacnet), 0) + bacnet
    ip_fragments = [
        ethernet_ipv4_fragment(udp[:8], client, server, identification=77, offset=0, more=True),
        ethernet_ipv4_fragment(udp[8:], client, server, identification=77, offset=8, more=False),
    ]
    report = capture.analyze_capture(classic_pcap([s7_frame, io_frame, *ip_fragments]))
    assert report["packet_count"] == 4
    by_protocol = defaultdict(list)
    for message in report["messages"]:
        by_protocol[message["protocol"]].append(message["decoded"])
    assert by_protocol["s7comm"][0]["s7"]["function_name"] == "Setup Communication"
    assert by_protocol["enip"][0]["variant"] == "implicit-io"
    assert by_protocol["enip"][0]["flags"] == ["CSCTF{io}"]
    assert by_protocol["bacnet"][0]["apdu"]["service_name"] == "who-Is"

    dnp_messages = []
    for link_source, sequence in ((1, 0), (2, 10)):
        decoded = protocols.parse_dnp3(
            dnp3_frame(bytes([0xC0 | sequence, 0xC1, 0x01, 0x3C, 0x02, 0x06]))
        )
        decoded["source"] = link_source
        dnp_messages.append(
            {
                "protocol": "dnp3", "source": "master", "source_port": 30000,
                "destination": "outstation", "destination_port": 20000, "decoded": decoded,
            }
        )
    _, findings = capture._correlate(dnp_messages)
    assert not any(row["kind"] == "sequence-gap" for row in findings)


def test_capture_prefixes_fail_without_unbounded_or_low_level_errors() -> None:
    frame = ethernet_ipv4_udp(
        b"\x81\x0b\x00\x08\x01\x00\x10\x08",
        bytes([203, 0, 113, 1]),
        bytes([203, 0, 113, 2]),
        41000,
        47808,
    )
    artifact = classic_pcap([frame])
    for length in range(len(artifact)):
        try:
            list(capture.iter_capture(artifact[:length]))
        except capture.ParseError:
            pass

