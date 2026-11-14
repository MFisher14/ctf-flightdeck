"""Independent hardening vectors for the passive TriStation wire engine.

The fixture encoders are handwritten from the published Mandiant/Nozomi
TCM/TS offsets and ordinary PCAP/Ethernet/IPv4/UDP specifications.  They do not
call an encoder or fixture helper from the engine under test.
"""
from __future__ import annotations

import hashlib
import random
import struct
import zlib
from collections.abc import Callable

import pytest

import ot_tristation_wire as tristation


def _tcm_ts(
    command: int,
    payload: bytes = b"",
    *,
    direction: int = 0,
    channel: int = 3,
    controller_id: int = 7,
    sequence: int = 9,
    trailer: bytes = b"\xca\xfe",
) -> bytes:
    """Hand-pack the documented 4-byte TCM and 10-byte TS headers."""
    ts_size = 10 + len(payload)
    ts = (
        bytes((direction, controller_id, command, sequence))
        + b"\x12\x34"  # published as unknown
        + b"\x56\x78"  # published checksum word; algorithm is unspecified
        + struct.pack("<H", ts_size)
        + payload
    )
    return bytes((5, channel)) + struct.pack("<H", len(ts)) + ts + trailer


def _tcm_control(message_type: int, payload: bytes = b"", *, channel: int = 3) -> bytes:
    return bytes((message_type, channel)) + struct.pack("<H", len(payload)) + payload + b"\x00\x00"


def _allocate_program(
    program_id: int,
    total_blocks: int,
    block_offset: int,
    data: bytes,
    *,
    next_id: int = 0,
) -> bytes:
    assert len(data) % 4 == 0
    return struct.pack(
        "<HHHHH",
        program_id,
        next_id,
        total_blocks,
        block_offset,
        len(data) // 4,
    ) + data


def _ethernet_ipv4_udp(
    payload: bytes,
    *,
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, len(payload) + 8, 0) + payload
    ipv4 = (
        b"\x45\x00"
        + struct.pack("!H", len(udp) + 20)
        + b"\x12\x34\x00\x00\x40\x11\x00\x00"
        + source_ip
        + destination_ip
        + udp
    )
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    return ethernet + ipv4


def _pcap(frames: list[bytes]) -> bytes:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, frame in enumerate(frames):
        records.append(
            struct.pack("<IIII", 1_700_100_000 + index, index, len(frame), len(frame)) + frame
        )
    return global_header + b"".join(records)


def _clean_or_declared(call: Callable[[], object]) -> None:
    try:
        call()
    except BaseException as exc:  # explicitly reject leaked SystemExit/stdlib errors
        assert isinstance(exc, tristation.TriStationError), type(exc).__name__


@pytest.mark.parametrize(
    ("subcommand", "expected_name"),
    [(0x17, "read-memory"), (0x41, "write-memory"), (0xF9, "execute-address")],
)
def test_vector_documented_tcm_ts_command29(
    subcommand: int, expected_name: str
) -> None:
    arguments = b"\x04\x00\x00\x00\x00\x10\x00\x00"
    frame = _tcm_ts(29, bytes((subcommand, 0xFF)) + arguments)

    decoded = tristation.parse_datagram(
        frame, source_port=49152, destination_port=1502
    )

    assert decoded["protocol"] == "tristation"
    assert decoded["standard_port_1502"] is True
    assert decoded["tcm"] == {
        "message_type": 5,
        "message_type_name": "execution_command",
        "channel": 3,
        "body_length": 20,
        "trailer_hex": "cafe",
        "trailer_interpretation": "published as CRC-16; algorithm not verified",
        "trailer_verified": False,
    }
    ts = decoded["ts"]
    assert ts["direction_name"] == "workstation_to_controller"
    assert ts["controller_id"] == 7
    assert ts["command"] == 29
    assert ts["command_name"] == "Get MP status"
    assert ts["sequence"] == 9
    assert ts["unknown_word_hex"] == "1234"
    assert ts["checksum_word_hex"] == "5678"
    assert ts["command29_body"] == {
        "subcommand": subcommand,
        "subcommand_name": expected_name,
        "mp": 0xFF,
        "argument_hex": arguments.hex(),
        "documented_implant_shape": True,
        "executed": False,
    }
    evidence = decoded["evidence"][0]
    assert evidence["kind"] == "trisis-command-29-context"
    assert evidence["implant_subcommand"] == expected_name
    assert "not proof" in evidence["assessment"]


def test_vector_non_execution_tcm_payload() -> None:
    decoded = tristation.parse_datagram(_tcm_control(1, b"\x10\x20"))
    assert decoded["tcm"]["message_type"] == 1
    assert decoded["tcm"]["message_type_name"] == "connection_request"
    assert decoded["tcm"]["channel"] == 3
    assert decoded["tcm_payload_hex"] == "1020"
    assert "ts" not in decoded


def test_vector_command55_multichunk_carve_and_transaction() -> None:
    program = b"SAFE" * 6
    crc32 = zlib.crc32(program) & 0xFFFFFFFF
    # Nozomi's published detector: signature = CRC32(program) XOR 2068988371.
    signature = crc32 ^ 0x7B5241D3
    first = _allocate_program(0x1234, 8, 0, program[:8], next_id=0x1235)
    final = _allocate_program(
        0x1234,
        8,
        2,
        program[8:] + struct.pack("<I", signature) + struct.pack("!I", crc32),
    )
    records = [
        {
            "data": _tcm_ts(55, first, sequence=10),
            "source": "192.0.2.10",
            "destination": "192.0.2.20",
            "source_port": 41000,
            "destination_port": 1502,
        },
        {
            "data": _tcm_ts(55, final, sequence=11),
            "source": "192.0.2.10",
            "destination": "192.0.2.20",
            "source_port": 41000,
            "destination_port": 1502,
        },
        {
            "data": _tcm_ts(153, direction=1, sequence=11),
            "source": "192.0.2.20",
            "destination": "192.0.2.10",
            "source_port": 1502,
            "destination_port": 41000,
        },
    ]

    report = tristation.analyze_datagrams(records)

    assert report["summary"]["complete_program_carving_count"] == 1
    carving = report["program_carvings"][0]
    assert carving["complete"] is True
    assert carving["program_id"] == 0x1234
    assert carving["program_hex"] == program.hex()
    assert carving["program_sha256"] == hashlib.sha256(program).hexdigest()
    assert carving["crc32_computed"] == crc32
    assert carving["crc32_trailer_big"] == crc32
    assert carving["crc32_matches"] is True
    assert carving["signature_word_little"] == signature
    assert carving["nozomi_triton_signature_relation"] is True
    assert carving["executed"] is False
    assert report["transactions"] == [
        {
            "request_frame": 1,
            "response_frame": 2,
            "controller_id": 7,
            "sequence": 11,
            "request_command": 55,
            "response_command": 153,
        }
    ]


def test_vector_capture_and_auto_detection() -> None:
    workstation = b"\xc0\x00\x02\x0a"
    controller = b"\xc0\x00\x02\x14"
    request = _ethernet_ipv4_udp(
        _tcm_ts(19, controller_id=2, sequence=44),
        source_ip=workstation,
        destination_ip=controller,
        source_port=42000,
        destination_port=1502,
    )
    response = _ethernet_ipv4_udp(
        _tcm_ts(108, direction=1, controller_id=2, sequence=44),
        source_ip=controller,
        destination_ip=workstation,
        source_port=1502,
        destination_port=42000,
    )
    ignored = _ethernet_ipv4_udp(
        b"not tristation",
        source_ip=workstation,
        destination_ip=controller,
        source_port=42000,
        destination_port=9999,
    )
    capture = _pcap([request, response, ignored])

    direct = tristation.analyze_capture(capture)
    automatic = tristation.analyze_bytes(capture)

    assert direct["format"] == automatic["format"] == "pcap"
    assert direct["packet_count"] == automatic["packet_count"] == 3
    assert direct["tristation_frame_count"] == automatic["tristation_frame_count"] == 2
    assert direct["summary"]["session_count"] == 1
    assert direct["transactions"] == automatic["transactions"] == [
        {
            "request_frame": 0,
            "response_frame": 1,
            "controller_id": 2,
            "sequence": 44,
            "request_command": 19,
            "response_command": 108,
        }
    ]

    raw = tristation.analyze_bytes(
        _tcm_ts(24),
        input_format="raw",
        source_port=42000,
        destination_port=1502,
    )
    assert raw["format"] == "raw"
    assert raw["frames"][0]["ts"]["command_name"] == "Get chassis status"


def test_fail_closed_parse_datagram_truncation_bitflip_random_and_oversize() -> None:
    valid = _tcm_ts(19)
    rng = random.Random(0x1502)
    corpus: list[object] = [
        b"",
        b"\xff" * 32,
        b"\x05\x03",
        rng.randbytes(1),
        rng.randbytes(7),
        rng.randbytes(63),
        b"\x00" * 65_536,
        "not bytes",
        None,
    ]
    corpus.extend(valid[:cut] for cut in range(len(valid)))
    for index in range(len(valid)):
        changed = bytearray(valid)
        changed[index] ^= 1 << (index % 8)
        corpus.append(bytes(changed))
    for value in corpus:
        _clean_or_declared(lambda value=value: tristation.parse_datagram(value))

    for bad_port in (-1, 65_536, True, "1502"):
        _clean_or_declared(
            lambda bad_port=bad_port: tristation.parse_datagram(
                valid, destination_port=bad_port
            )
        )


def test_fail_closed_command55_and_command59_truncated_blocks() -> None:
    bad_command55 = [
        b"",
        b"\x00" * 9,
        struct.pack("<HHHHH", 1, 0, 0, 0, 1) + b"ABCD",
        struct.pack("<HHHHH", 1, 0, 2, 2, 1) + b"ABCD",
        struct.pack("<HHHHH", 1, 0, 2, 0, 2) + b"ABCD",
        struct.pack("<HHHHH", 1, 0, 1, 0, 1) + b"ABCD",
    ]
    for body in bad_command55:
        _clean_or_declared(lambda body=body: tristation.parse_datagram(_tcm_ts(55, body)))
    for size in range(26):
        _clean_or_declared(
            lambda size=size: tristation.parse_datagram(_tcm_ts(59, b"\x00" * size))
        )


def test_fail_closed_datagram_collection_entrypoint(monkeypatch) -> None:
    valid = _tcm_ts(19)
    flipped = bytearray(valid)
    flipped[len(flipped) // 2] ^= 0x80
    cases: list[object] = [
        [],
        b"not records",
        [None],
        [{}],
        [{"data": b""}],
        [{"data": valid[:-1]}],
        [{"data": b"\xff" * 32}],
        [{"data": random.Random(0xDADA).randbytes(31)}],
        [{"data": bytes(flipped)}],
        [{"data": valid, "unknown": 1}],
        [{"data": valid, "source": "bad\x00host"}],
        [{"data": valid, "timestamp": float("inf")}],
        [{"data": valid, "packet_index": -1}],
    ]
    for records in cases:
        _clean_or_declared(
            lambda records=records: tristation.analyze_datagrams(records)
        )

    monkeypatch.setattr(tristation, "MAX_FRAMES", 1)
    with pytest.raises(tristation.TriStationError):
        tristation.analyze_datagrams([{"data": valid}, {"data": valid}])


def test_fail_closed_capture_and_auto_entrypoints(monkeypatch) -> None:
    valid_capture = _pcap(
        [
            _ethernet_ipv4_udp(
                _tcm_ts(19),
                source_ip=b"\xc0\x00\x02\x01",
                destination_ip=b"\xc0\x00\x02\x02",
                source_port=43000,
                destination_port=1502,
            )
        ]
    )
    rng = random.Random(0xC0DE)
    flipped = bytearray(valid_capture)
    flipped[len(flipped) // 2] ^= 0x80
    corpus = [
        b"",
        b"\xff" * 64,
        rng.randbytes(47),
        b"\xd4\xc3\xb2\xa1",
        b"\x0a\x0d\x0d\x0a",
        valid_capture[:-1],
        valid_capture[:24],
        bytes(flipped),
    ]
    for value in corpus:
        _clean_or_declared(lambda value=value: tristation.analyze_capture(value))
        _clean_or_declared(
            lambda value=value: tristation.analyze_bytes(value, input_format="capture")
        )

    for value in (b"", b"\xff" * 32, _tcm_ts(19)[:-1]):
        _clean_or_declared(lambda value=value: tristation.analyze_bytes(value))
    _clean_or_declared(
        lambda: tristation.analyze_bytes(_tcm_ts(19), input_format="invalid")
    )

    monkeypatch.setattr(tristation, "MAX_CAPTURE", 128)
    oversized = b"\x00" * 129
    with pytest.raises(tristation.TriStationError):
        tristation.analyze_capture(oversized)
    with pytest.raises(tristation.TriStationError):
        tristation.analyze_bytes(oversized)


def test_vector_duplicate_command55_retransmission_is_one_transfer() -> None:
    program = b"RETX" * 4
    crc32 = zlib.crc32(program) & 0xFFFFFFFF
    first_body = _allocate_program(5, 6, 0, program[:8])
    final_body = _allocate_program(
        5,
        6,
        2,
        program[8:] + struct.pack("<I", 0) + struct.pack("!I", crc32),
    )
    first = _tcm_ts(55, first_body, sequence=30)
    final = _tcm_ts(55, final_body, sequence=31)

    report = tristation.analyze_datagrams(
        [{"data": first}, {"data": first}, {"data": final}]
    )

    assert len(report["program_carvings"]) == 1
    assert report["program_carvings"][0]["complete"] is True
    assert report["program_carvings"][0]["program_hex"] == program.hex()

