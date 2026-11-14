"""Triage -> new offline engine -> decoded flag-value integration fixtures.

All bytes are synthetic and local.  These tests never instantiate a transport,
open a target, or submit the recovered value.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import flagfmt

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "web"))

from ctf import triage as ctf_triage  # noqa: E402
import automotive_depth as automotive  # noqa: E402
import radio_capture as radio  # noqa: E402
import token_depth as token  # noqa: E402
import wire_decode as wire  # noqa: E402


FLAG = flagfmt.BYTES             # the event's flag format (the suite runs as csctf)


def _isotp_candump(can_id: int, payload: bytes) -> str:
    first = bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:6]
    lines = [f"can0 {can_id:03X}#{first.hex()}"]
    offset, sequence = 6, 1
    while offset < len(payload):
        frame = bytes([0x20 | sequence]) + payload[offset:offset + 7]
        lines.append(f"can0 {can_id:03X}#{frame.hex()}")
        offset += 7
        sequence = (sequence + 1) & 0x0F
    return "\n".join(lines)


def _jwe(plaintext: bytes, key: bytes) -> str:
    header = token.b64u_encode(json.dumps(
        {"alg": "dir", "enc": "A256GCM"}, sort_keys=True,
        separators=(",", ":"),
    ).encode())
    iv = bytes.fromhex("102030405060708090a0b0c0")
    sealed = AESGCM(key).encrypt(iv, plaintext, header.encode())
    return ".".join((header, "", token.b64u_encode(iv), token.b64u_encode(sealed[:-16]),
                     token.b64u_encode(sealed[-16:])))


def test_triage_to_isotp_uds_to_flag_value():
    route = ctf_triage.suggest("ics", "Saved CAN ISO-TP UDS ReadDataByIdentifier diagnostic trace")
    assert route["engines"][0] == "solvers/toolkits/automotive_depth.py"
    expected = b"CSCTF{uds_triage_chain}"
    trace = _isotp_candump(0x7E8, b"\x62\xf1\x90" + expected)
    report = automotive.analyze(automotive.parse_candump(trace))
    message = report["messages"][0]
    assert message["uds"]["data_identifier"] == 0xF190
    assert FLAG.search(message["payload"]).group() == expected


def test_triage_to_ble_advertising_to_flag_value():
    route = ctf_triage.suggest("networking", "Bluetooth LE BLE advertising capture with GATT clues")
    assert route["engines"][0] == "solvers/toolkits/radio_capture.py"
    expected = b"CSCTF{ble_triage_chain}"
    address = bytes.fromhex("665544332211")
    ad = bytes([len(expected) + 1, 0x09]) + expected
    pdu = b"\x00" + bytes([len(address + ad)]) + address + ad
    report = radio.parse_ble_advertising(pdu)
    name = next(row["text"] for row in report["advertising_data"] if row["name"] == "complete_name")
    assert name.encode() == expected and FLAG.fullmatch(name.encode())


def test_triage_to_authenticated_jwe_to_flag_value():
    route = ctf_triage.suggest("web", "Captured JWE A256GCM token and local JWK/JWKS material")
    assert route["engines"][0] == "solvers/web/token_depth.py"
    expected = "CSCTF{jwe_triage_chain}"
    key = bytes.fromhex("42" * 32)
    compact = _jwe(json.dumps({"role": "fixture", "flag": expected}).encode(), key)
    result = token.decrypt_jwe(compact, key)
    assert result["verified"] and result["nested"]["flag"] == expected
    assert FLAG.fullmatch(result["nested"]["flag"].encode())


def test_triage_to_grpc_frame_to_protobuf_flag_value():
    route = ctf_triage.suggest("networking", "Saved gRPC-web protobuf framed response body")
    assert route["engines"][0] == "solvers/toolkits/wire_decode.py"
    expected = b"CSCTF{grpc_triage_chain}"
    protobuf = b"\x0a" + bytes([len(expected)]) + expected
    framed = b"\x00" + len(protobuf).to_bytes(4, "big") + protobuf
    fields = wire.decode_grpc_frames(framed)[0]["protobuf"]
    assert fields[0]["field"] == 1
    assert fields[0]["value"]["string"].encode() == expected
    assert FLAG.fullmatch(fields[0]["value"]["string"].encode())


def test_new_keyword_routes_are_specific_and_offline():
    assert ctf_triage.suggest("web", "GraphQL introspection schema alias depth batch")["engines"][0] \
        == "solvers/web/graphql_analyzer.py"
    assert ctf_triage.suggest("ics", "PNIO-RPC Profinet RPC and OPC secure channel")["engines"][0] \
        == "solvers/toolkits/network_ics_depth.py"
    # Generic JWT and generic CAN retain the established first-pass tools; the
    # depth engines move forward only on their more specific evidence.
    assert ctf_triage.suggest("web", "JWT role cookie alg none")["engines"][0] \
        == "solvers/web/auth_trust.py"
    assert ctf_triage.suggest("networking", "J1939 CAN bus fleet capture")["engines"][0] \
        == "solvers/toolkits/transport.py"
