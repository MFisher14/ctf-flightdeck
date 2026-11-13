"""Synthetic, non-malware vectors for the passive TriStation wire decoder.

The fixture encoders below are deliberately independent of the engine.  Their
offsets follow Mandiant's published TCM/TS packet diagram and Nozomi's published
TriStation.lua field offsets; the PCAP/Ethernet/IPv4/UDP wrappers use their
respective public wire layouts.
"""
from __future__ import annotations

import hashlib
import json
import random
import struct
import zlib

import pytest

import ot_tristation_wire as tri


def documented_datagram(
    command: int | None = None,
    payload: bytes = b"",
    *,
    message_type: int = 5,
    channel: int = 2,
    direction: int = 0,
    controller_id: int = 7,
    sequence: int = 9,
    trailer: bytes = b"\xca\xfe",
) -> bytes:
    """Hand-encode the public TCM header and 10-byte TS command header."""
    if command is None:
        body = payload
    else:
        size = 10 + len(payload)
        body = (
            bytes((direction, controller_id, command, sequence))
            + b"\x12\x34"  # reverse-engineering sources leave this word unknown
            + b"\x56\x78"  # checksum word; public sources do not establish an algorithm
            + struct.pack("<H", size)
            + payload
        )
    return bytes((message_type, channel)) + struct.pack("<H", len(body)) + body + trailer


def allocate_program_body(
    *,
    program_id: int,
    total_blocks: int,
    offset: int,
    block_data: bytes,
    next_id: int = 0,
) -> bytes:
    assert len(block_data) % 4 == 0
    return struct.pack(
        "<HHHHH", program_id, next_id, total_blocks, offset, len(block_data) // 4
    ) + block_data


def ethernet_ipv4_udp(
    payload: bytes,
    *,
    source: bytes,
    destination: bytes,
    source_port: int,
    destination_port: int,
) -> bytes:
    """Hand-encode an Ethernet/IPv4/UDP packet; checksums are capture-zeroed."""
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ipv4 = (
        b"\x45\x00"
        + struct.pack("!H", 20 + len(udp))
        + b"\x12\x34\x00\x00\x40\x11\x00\x00"
        + source
        + destination
        + udp
    )
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ipv4


def classic_pcap(frames: list[bytes]) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for index, frame in enumerate(frames):
        records.append(struct.pack("<IIII", 1_700_000_000 + index, index, len(frame), len(frame)) + frame)
    return header + b"".join(records)


def little_endian_pcapng(frames: list[bytes]) -> bytes:
    """Hand-encode SHB, IDB, and Enhanced Packet Blocks from the PCAPNG spec."""
    shb_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
    shb_length = 12 + len(shb_body)
    shb = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", shb_length)
        + shb_body
        + struct.pack("<I", shb_length)
    )
    idb_body = struct.pack("<HxxI", 1, 65535)
    idb_length = 12 + len(idb_body)
    idb = struct.pack("<II", 1, idb_length) + idb_body + struct.pack("<I", idb_length)
    packets = []
    for index, frame in enumerate(frames):
        padded = frame + b"\x00" * ((-len(frame)) & 3)
        body = struct.pack("<IIIII", 0, 0, index, len(frame), len(frame)) + padded
        length = 12 + len(body)
        packets.append(struct.pack("<II", 6, length) + body + struct.pack("<I", length))
    return shb + idb + b"".join(packets)


def test_parse_published_execution_header_and_command29_context() -> None:
    frame = documented_datagram(29, b"\x17\xffSYNTHETIC")
    decoded = tri.parse_datagram(frame, source_port=40000, destination_port=1502)

    assert decoded["tcm"] == {
        "message_type": 5,
        "message_type_name": "execution_command",
        "channel": 2,
        "body_length": 21,
        "trailer_hex": "cafe",
        "trailer_interpretation": "published as CRC-16; algorithm not verified",
        "trailer_verified": False,
    }
    assert decoded["standard_port_1502"] is True
    assert decoded["ts"]["direction_name"] == "workstation_to_controller"
    assert decoded["ts"]["controller_id"] == 7
    assert decoded["ts"]["command"] == 29
    assert decoded["ts"]["command_name"] == "Get MP status"
    assert decoded["ts"]["sequence"] == 9
    assert decoded["ts"]["unknown_word_hex"] == "1234"
    assert decoded["ts"]["checksum_word_hex"] == "5678"
    assert decoded["ts"]["payload_hex"] == b"\x17\xffSYNTHETIC".hex()
    assert decoded["ts"]["command29_body"] == {
        "subcommand": 0x17,
        "subcommand_name": "read-memory",
        "mp": 0xFF,
        "argument_hex": b"SYNTHETIC".hex(),
        "documented_implant_shape": True,
        "executed": False,
    }
    assert decoded["evidence"][0]["kind"] == "trisis-command-29-context"
    assert decoded["evidence"][0]["confidence"] == "contextual-only"
    assert "not proof" in decoded["evidence"][0]["assessment"]
    assert decoded["evidence"][0]["implant_subcommand"] == "read-memory"


@pytest.mark.parametrize(
    ("subcommand", "name"),
    [(0x17, "read-memory"), (0x41, "write-memory"), (0xF9, "execute-address")],
)
def test_published_hatman_subcommand_labels_are_passive(subcommand: int, name: str) -> None:
    decoded = tri.parse_datagram(documented_datagram(29, bytes((subcommand, 0xFF)) + b"ARGS"))
    assert decoded["ts"]["command29_body"]["subcommand_name"] == name
    assert decoded["ts"]["command29_body"]["argument_hex"] == b"ARGS".hex()
    assert decoded["ts"]["command29_body"]["executed"] is False
    assert decoded["evidence"][0]["implant_subcommand"] == name
    assert "not proof" in decoded["evidence"][0]["assessment"]


def test_program_chunks_reassemble_and_lock_published_signature_relation() -> None:
    # Harmless synthetic bytes: two ordinary chunks, with the final eight-byte
    # trailer documented by Nozomi's dissector.  CRC is independently computed
    # by stdlib and the published XOR constant is hard-coded here as the oracle.
    program = b"ABCD" * 6
    crc32 = zlib.crc32(program) & 0xFFFFFFFF
    signature = crc32 ^ 0x7B5241D3
    first = allocate_program_body(
        program_id=0x1234,
        total_blocks=8,
        offset=0,
        block_data=program[:8],
        next_id=0x1235,
    )
    final = allocate_program_body(
        program_id=0x1234,
        total_blocks=8,
        offset=2,
        # Nozomi reads the signature little-endian and the CRC32 big-endian.
        block_data=program[8:] + struct.pack("<I", signature) + struct.pack("!I", crc32),
    )
    report = tri.analyze_datagrams(
        [
            {
                "data": documented_datagram(55, first, sequence=10),
                "source": "192.0.2.10",
                "destination": "192.0.2.20",
                "source_port": 41000,
                "destination_port": 1502,
            },
            {
                "data": documented_datagram(55, final, sequence=11),
                "source": "192.0.2.10",
                "destination": "192.0.2.20",
                "source_port": 41000,
                "destination_port": 1502,
            },
        ]
    )

    assert report["summary"]["program_activity_frame_count"] == 2
    assert report["summary"]["complete_program_carving_count"] == 1
    carving = report["program_carvings"][0]
    assert carving["complete"] is True
    assert carving["program_id"] == 0x1234
    assert carving["program_hex"] == program.hex()
    assert carving["program_size"] == len(program)
    assert carving["program_sha256"] == hashlib.sha256(program).hexdigest()
    assert carving["crc32_computed"] == crc32
    assert carving["crc32_matches"] is True
    assert carving["signature_word_little"] == signature
    assert carving["nozomi_triton_signature_relation"] is True
    assert carving["executed"] is False
    assert "not proof" in carving["indicator_assessment"]


def test_reused_program_slot_produces_distinct_carvings() -> None:
    records = []
    for sequence, program in enumerate((b"ONE!", b"TWO!"), start=20):
        crc32 = zlib.crc32(program) & 0xFFFFFFFF
        body = allocate_program_body(
            program_id=6,
            total_blocks=3,
            offset=0,
            block_data=program + struct.pack("<I", 0) + struct.pack("!I", crc32),
        )
        records.append({"data": documented_datagram(55, body, sequence=sequence)})
    report = tri.analyze_datagrams(records)
    assert report["summary"]["complete_program_carving_count"] == 2
    assert [row["transfer_index"] for row in report["program_carvings"]] == [1, 2]
    assert [bytes.fromhex(row["program_hex"]) for row in report["program_carvings"]] == [
        b"ONE!",
        b"TWO!",
    ]


def test_command59_documented_metadata_offsets() -> None:
    body = (
        b"\x01\x02\x03\x04\x05\x06"
        + struct.pack("<I", 0x12345678)
        + b"SAFEDEMO\x00\x00"
        + struct.pack("<HH", 3, 4)
        + b"\xaa\xbb"
    )
    decoded = tri.parse_datagram(documented_datagram(59, body))
    metadata = decoded["ts"]["download_metadata"]
    assert metadata == {
        "unknown_prefix_hex": "010203040506",
        "timestamp_raw_little": 0x12345678,
        "project_raw_hex": b"SAFEDEMO\x00\x00".hex(),
        "project": "SAFEDEMO",
        "function_count": 3,
        "program_count": 4,
        "unknown_suffix_hex": "aabb",
        "trailing_hex": "",
    }
    assert decoded["evidence"][0]["action"] == "start-ts2-program-download"


def test_capture_filter_session_and_transaction_correlation() -> None:
    workstation = b"\xc0\x00\x02\x0a"
    controller = b"\xc0\x00\x02\x14"
    connect = documented_datagram(None, message_type=1, channel=3)
    request = documented_datagram(19, channel=3, controller_id=2, sequence=44)
    response = documented_datagram(
        108, channel=3, direction=1, controller_id=2, sequence=44
    )
    ignored = b"not tristation"
    capture = classic_pcap(
        [
            ethernet_ipv4_udp(
                connect,
                source=workstation,
                destination=controller,
                source_port=42000,
                destination_port=1502,
            ),
            ethernet_ipv4_udp(
                request,
                source=workstation,
                destination=controller,
                source_port=42000,
                destination_port=1502,
            ),
            ethernet_ipv4_udp(
                response,
                source=controller,
                destination=workstation,
                source_port=1502,
                destination_port=42000,
            ),
            ethernet_ipv4_udp(
                ignored,
                source=workstation,
                destination=controller,
                source_port=42000,
                destination_port=9999,
            ),
        ]
    )
    report = tri.analyze_capture(capture)

    assert report["format"] == "pcap"
    assert report["packet_count"] == 4
    assert report["tristation_frame_count"] == 3
    assert report["summary"]["session_count"] == 1
    assert report["sessions"][0]["controller_ids"] == [2]
    assert report["sessions"][0]["tcm_type_counts"] == {"1": 1, "5": 2}
    assert report["transactions"] == [
        {
            "request_frame": 1,
            "response_frame": 2,
            "controller_id": 2,
            "sequence": 44,
            "request_command": 19,
            "response_command": 108,
        }
    ]
    assert report["orphan_request_frames"] == []

    auto = tri.analyze_bytes(capture)
    assert auto["tristation_frame_count"] == 3
    assert auto["transactions"] == report["transactions"]


def test_pcapng_integration_uses_the_existing_bounded_capture_reader() -> None:
    packet = ethernet_ipv4_udp(
        documented_datagram(24, controller_id=3),
        source=b"\xc6\x33\x64\x0a",
        destination=b"\xc6\x33\x64\x14",
        source_port=43000,
        destination_port=1502,
    )
    report = tri.analyze_capture(little_endian_pcapng([packet]))
    assert report["format"] == "pcapng"
    assert report["packet_count"] == 1
    assert report["tristation_frame_count"] == 1
    assert report["frames"][0]["ts"]["command_name"] == "Get chassis status"


def test_fail_closed_malformed_and_bounded_inputs() -> None:
    valid = documented_datagram(19)
    malformed = [
        b"",
        b"\xff" * 32,
        valid[:1],
        valid[:-1],
        valid[:2] + b"\xff\xff" + valid[4:],
        valid[:12],
        b"\x05\x00\x09\x00" + b"\x00" * 11,
        b"\x00" * (tri.MAX_DATAGRAM + 1),
        "not bytes",
    ]
    for value in malformed:
        with pytest.raises(tri.TriStationError):
            tri.parse_datagram(value)  # type: ignore[arg-type]

    # Valid non-execution framing returns cleanly, even with an unknown type.
    clean = tri.parse_datagram(documented_datagram(None, b"", message_type=250))
    assert clean["tcm"]["message_type_name"] == "unknown"

    with pytest.raises(tri.TriStationError):
        tri.analyze_capture(b"\xd4\xc3\xb2\xa1")
    with pytest.raises(tri.TriStationError):
        tri.analyze_datagrams([{"data": valid, "unexpected": 1}])
    with pytest.raises(tri.TriStationError):
        tri.analyze_bytes(valid, input_format="wrong")


def test_allocate_program_range_checks_are_declared_errors() -> None:
    bad_bodies = [
        b"\x00" * 9,
        struct.pack("<HHHHH", 1, 0, 0, 0, 1) + b"ABCD",
        struct.pack("<HHHHH", 1, 0, 2, 2, 1) + b"ABCD",
        struct.pack("<HHHHH", 1, 0, 2, 0, 2) + b"ABCD",
        struct.pack("<HHHHH", 1, 0, 1, 0, 1) + b"ABCD",
    ]
    for body in bad_bodies:
        with pytest.raises(tri.TriStationError):
            tri.parse_datagram(documented_datagram(55, body))


def test_deterministic_bitflips_and_random_bytes_never_leak_stdlib_errors() -> None:
    rng = random.Random(0x1502)
    valid = documented_datagram(55, allocate_program_body(
        program_id=1,
        total_blocks=3,
        offset=0,
        block_data=b"DATA" + b"\x00" * 8,
    ))
    samples = [rng.randbytes(size) for size in (1, 2, 5, 6, 10, 31, 255, 1024)]
    for index in range(min(len(valid), 32)):
        changed = bytearray(valid)
        changed[index] ^= 1 << (index % 8)
        samples.append(bytes(changed))
    for sample in samples:
        try:
            tri.parse_datagram(sample)
        except Exception as exc:  # the contract permits only the declared error
            assert isinstance(exc, tri.TriStationError), type(exc).__name__


def test_cli_is_guarded_and_offline(tmp_path, capsys) -> None:
    assert tri.main(["--definitely-invalid"]) == 2
    assert tri.main([123]) == 2  # type: ignore[list-item]

    artifact = tmp_path / "synthetic.ts"
    artifact.write_bytes(documented_datagram(19))
    code = tri.main(
        [str(artifact), "--format", "raw", "--destination-port", "1502"]
    )
    assert code == 0
    output = capsys.readouterr().out.strip().splitlines()[-1]
    report = json.loads(output)
    assert report["format"] == "raw"
    assert report["frames"][0]["ts"]["command"] == 19
    assert report["frames"][0]["standard_port_1502"] is True

