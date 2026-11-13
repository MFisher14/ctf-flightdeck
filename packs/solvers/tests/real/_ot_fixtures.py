"""Synthetic OT capture fixtures for the B-204 oracle tests.

These are built in memory, from this repo's own bytes, to exercise the oracle dispatch
(tests/real/_ot_oracle.py) on every engine without the real corpus. They are fixtures, never
committed captures and never a real challenge file. Each builder returns a classic-pcap byte string
(Ethernet link type) carrying one minimal, valid frame of its protocol, so the matching parser
recognises it. A mis-wired engine (wrong parser, wrong port/ethertype, dropped payload) fails to
recognise its fixture, which is what the tests assert.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
_TOOLKITS = str(REPO / "solvers" / "toolkits")
if _TOOLKITS not in sys.path:
    sys.path.insert(0, _TOOLKITS)

import ics_protocols  # noqa: E402 - only crc16_dnp3, a pure helper

_MAC_A = bytes.fromhex("020000000001")
_MAC_B = bytes.fromhex("020000000002")


# --------------------------------------------------------------------------- pcap container

def pcap(frames: list[bytes]) -> bytes:
    """A classic little-endian pcap (magic a1b2c3d4, Ethernet) wrapping `frames`."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", i, 0, len(frame), len(frame)) + frame
    return bytes(out)


def _eth(ethertype: int, payload: bytes) -> bytes:
    return _MAC_B + _MAC_A + struct.pack(">H", ethertype) + payload


def _ipv4(proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0,
                         bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return _eth(0x0800, header + payload)


def _tcp(sport: int, dport: int, payload: bytes) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0)
    return _ipv4(6, tcp + payload)


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return _ipv4(17, udp + payload)


# --------------------------------------------------------------------------- per-protocol payloads

def _modbus() -> bytes:
    pdu = bytes([0x03, 0x00, 0x00, 0x00, 0x01])            # read holding registers
    return struct.pack(">HHHB", 1, 0, 1 + len(pdu), 1) + pdu


def _dnp3() -> bytes:
    body = bytes([0x05, 0x64, 0x05, 0xC4, 0x01, 0x00, 0x02, 0x00])
    return body + struct.pack("<H", ics_protocols.crc16_dnp3(body))


def _s7() -> bytes:
    s7 = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
                0xF0, 0, 0, 1, 0, 1, 0x03, 0xC0])
    cotp = bytes([0x02, 0xF0, 0x80])
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp) + len(s7)) + cotp + s7


def _iec104() -> bytes:
    asdu = bytes([0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14])
    ctrl = bytes([0x00, 0x00, 0x00, 0x00])
    return bytes([0x68, len(ctrl) + len(asdu)]) + ctrl + asdu


def _enip() -> bytes:
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"\x00" * 8, 0)   # ListIdentity


def _bacnet() -> bytes:
    # BVLC (0x81) Original-Unicast-NPDU + NPDU (version 1, control 0 = no dest/src, data) +
    # a complete APDU: unconfirmed-request (0x10), service who-is (0x08). No truncated field.
    npdu_apdu = bytes([0x01, 0x00, 0x10, 0x08])
    return bytes([0x81, 0x0A, 0x00, 4 + len(npdu_apdu)]) + npdu_apdu


def _goose() -> bytes:
    content = bytes([0x80, 0x01, 0x01])                    # one child tag
    pdu = bytes([0x61, len(content)]) + content
    declared = 8 + len(pdu)
    return struct.pack(">HHHH", 0x0001, declared, 0, 0) + pdu


def _opcua() -> bytes:
    url = b"opc.tcp://host:4840"
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + struct.pack("<I", len(url)) + url
    return b"HELF" + struct.pack("<I", 8 + len(body)) + body


def _ethercat() -> bytes:
    payload = bytes([0xAA, 0xBB])
    dg = bytes([0x04, 0x00]) + bytes([0, 0, 0x20, 0x01]) + struct.pack("<H", len(payload)) \
        + bytes([0, 0]) + payload + struct.pack("<H", 1)
    header = (len(dg) & 0x07FF) | (1 << 12)               # length | frame-type 1
    return struct.pack("<H", header) + dg


def _profinet() -> bytes:
    # A Profinet DCP Identify request (frameID 0xFEFE) built with scapy's pnio_dcp contrib, captured
    # here as the layer-2 payload after ethertype 0x8892. ics_fieldbus (scapy) re-dissects it.
    return bytes.fromhex(
        "fefe050000000001000000000202000065743230307370"
        "0000000000000000000000000000000000000000000000")


def _mms() -> bytes:
    mms = bytes.fromhex("a006020101800100")               # confirmed-request status
    cotp = bytes([0x02, 0xF0, 0x80])                       # COTP DT
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp) + len(mms)) + cotp + mms


def captures() -> dict[str, bytes]:
    """{proto: pcap bytes} for every engine the oracle supports."""
    return {
        "modbus": pcap([_tcp(40000, 502, _modbus())]),
        "dnp3": pcap([_tcp(40000, 20000, _dnp3())]),
        "s7comm": pcap([_tcp(40000, 102, _s7())]),
        "iec104": pcap([_tcp(40000, 2404, _iec104())]),
        "enip": pcap([_tcp(40000, 44818, _enip())]),
        "bacnet": pcap([_udp(40000, 47808, _bacnet())]),
        "goose": pcap([_eth(0x88B8, _goose())]),
        "opcua": pcap([_tcp(40000, 4840, _opcua())]),
        "ethercat": pcap([_eth(0x88A4, _ethercat())]),
        "mms": pcap([_tcp(40000, 102, _mms())]),
        "profinet": pcap([_eth(0x8892, _profinet())]),
    }


# which engine reads which synthetic protocol (mirrors manifest_ot.json engine fields)
ENGINE_FOR = {
    "modbus": "ics_capture", "dnp3": "ics_capture", "s7comm": "ics_capture",
    "iec104": "ics_capture", "enip": "ics_capture",
    "bacnet": "ics_fieldbus", "goose": "goose", "opcua": "opcua",
    "ethercat": "ethercat", "mms": "mms", "profinet": "ics_fieldbus",
}


def write_captures(dest: Path) -> dict[str, Path]:
    """Write every synthetic capture under `dest` and return {proto: path}."""
    dest.mkdir(parents=True, exist_ok=True)
    paths = {}
    for proto, data in captures().items():
        p = dest / f"{proto}.pcap"
        p.write_bytes(data)
        paths[proto] = p
    return paths
