"""QUIC v2/Retry/frames plus authenticated OPC-UA and PNIO-RPC depth."""
from __future__ import annotations

import hashlib
import hmac
import random
import struct
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import network_ics_depth as depth  # noqa: E402


V2 = 0x6B3343CF


def _varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (0x4000 | value).to_bytes(2, "big")
    raise ValueError


def _v2_long(secret, dcid, scid, packet_number, plaintext, pn_length=2):
    # QUIC v2 wire type 3 is Handshake.
    first = 0xC0 | (3 << 4) | (pn_length - 1)
    prefix = bytes([first]) + V2.to_bytes(4, "big") + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    prefix += _varint(pn_length + len(plaintext) + 16)
    pn = packet_number.to_bytes(pn_length, "big")
    kind, hash_name, key, iv = depth._traffic_keys(secret, 0x1301, quic=True, quic_version=V2)
    header = prefix + pn
    ciphertext = AESGCM(key).encrypt(depth._nonce(iv, packet_number), plaintext, header)
    packet = bytearray(header + ciphertext)
    pn_offset = len(prefix)
    hp = depth.tls._hkdf_expand_label(secret, b"quicv2 hp", b"", 16, hash_name)
    mask = depth._hp_mask(kind, hp, bytes(packet[pn_offset + 4:pn_offset + 20]))
    packet[0] ^= mask[0] & 0x0F
    for index in range(pn_length):
        packet[pn_offset + index] ^= mask[index + 1]
    return bytes(packet)


def _retry(version, odcid, dcid, scid, token):
    key, nonce, wire_type = depth._QUIC_RETRY[version]
    first = 0xC0 | wire_type << 4
    without_tag = (bytes([first]) + version.to_bytes(4, "big") + bytes([len(dcid)]) + dcid +
                   bytes([len(scid)]) + scid + token)
    pseudo = bytes([len(odcid)]) + odcid + without_tag
    return without_tag + AESGCM(key).encrypt(nonce, b"", pseudo)


def _opcua_chunk(enc_key, sign_key, iv, body):
    node = b"\x01\x00" + (631).to_bytes(2, "little")
    content = struct.pack("<II", 44, 55) + node + body
    # Header length is independent of padding contents, so compute encrypted length first.
    sig_len = 32
    pad_len = 16 - ((len(content) + sig_len) % 16)
    encrypted_len = len(content) + sig_len + pad_len
    total = 16 + encrypted_len
    header = b"MSGF" + total.to_bytes(4, "little") + struct.pack("<II", 7, 9)
    pad_byte = pad_len - 1
    signed = content + bytes([pad_byte]) * pad_len
    signature = hmac.new(sign_key, header + signed, hashlib.sha256).digest()
    plain = signed + signature
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    return header + encryptor.update(plain) + encryptor.finalize()


def _pnio_rpc():
    ar_uuid = uuid.UUID("12345678-1234-5678-9abc-def012345678")
    body = b"\x00\x01" + ar_uuid.bytes_le
    block = b"\x01\x01" + (2 + len(body)).to_bytes(2, "big") + b"\x01\x00" + body
    stub = b"\x00" * 4 + block
    header = bytearray(80)
    header[0:2] = b"\x04\x00"  # connectionless v4 request
    header[4:7] = b"\x10\x00\x00"  # little-endian NDR
    header[7] = 0x12
    header[8:24] = uuid.UUID("dea00000-6c97-11d1-8271-00a02442df7d").bytes_le
    header[24:40] = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le
    header[40:56] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    header[60:64] = (1).to_bytes(4, "little")
    header[64:68] = (99).to_bytes(4, "little")
    header[68:70] = (0).to_bytes(2, "little")
    header[74:76] = len(stub).to_bytes(2, "little")
    header[79] = 0x34
    return bytes(header) + stub, str(ar_uuid)


def test_quic_v2_handshake_key_labels_and_frame_grammar():
    secret = bytes.fromhex("33" * 32)
    plaintext = (b"\x01" + b"\x06" + _varint(4) + _varint(5) + b"hello" +
                 b"\x0f" + _varint(3) + _varint(0) + _varint(4) + b"FLAG")
    packet = _v2_long(secret, b"dest", b"source", 9, plaintext)
    result = depth.decrypt_quic_long(packet, secret, 0x1301, largest_packet_number=8)
    assert result["verified"] and result["version"] == V2 and result["packet_type"] == "handshake"
    assert [row["name"] for row in result["frames"]] == ["ping", "crypto", "stream"]
    assert result["frames"][1]["offset"] == 4 and result["frames"][1]["data"] == b"hello"
    assert result["frames"][2]["fin"] is True and result["frames"][2]["data"] == b"FLAG"
    assert depth.decrypt_quic_long(packet[:-1] + bytes([packet[-1] ^ 1]), secret, 0x1301) is None


def test_quic_v1_and_v2_retry_integrity_and_initial_secrets():
    for version in (1, V2):
        odcid, dcid, scid = b"original", b"client", b"server"
        packet = _retry(version, odcid, dcid, scid, b"retry-token")
        result = depth.verify_quic_retry(packet, odcid)
        assert result and result["verified"] and result["token"] == b"retry-token"
        damaged = bytearray(packet); damaged[-1] ^= 1
        assert depth.verify_quic_retry(bytes(damaged), odcid) is None
        secrets = depth.quic_initial_secrets(dcid, version)
        assert len(secrets["client"]) == len(secrets["server"]) == 32
        assert secrets["client"] != secrets["server"]
    assert depth.quic_initial_secrets(b"client", 1) != depth.quic_initial_secrets(b"client", V2)


def test_quic_full_frame_grammar_and_malformed_decline():
    frames = (b"\x00\x00\x01" + b"\x02" + _varint(10) + _varint(1) + _varint(0) + _varint(2) +
              b"\x10" + _varint(1000) + b"\x1a12345678" + b"\x31\x04DATA" + b"\x1e")
    rows = depth.parse_quic_frames(frames)
    assert [row["name"] for row in rows] == ["padding", "ping", "ack", "max_data",
                                                   "path_challenge", "datagram", "handshake_done"]
    assert rows[2]["ranges"] == [{"smallest": 8, "largest": 10}]
    for bad in (b"\x06\x00\x05abc", b"\x18\x00\x00\x00", b"\xff"):
        try:
            depth.parse_quic_frames(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed QUIC frame was accepted")


def test_opcua_symmetric_chunk_requires_hmac_and_padding():
    enc, sign, iv = bytes.fromhex("10" * 32), bytes.fromhex("20" * 32), bytes.fromhex("30" * 16)
    chunk = _opcua_chunk(enc, sign, iv, b"CSCTF{opcua_secure}")
    result = depth.decrypt_opcua_symmetric_chunk(chunk, enc, iv, sign)
    assert result["verified"] and result["sequence_number"] == 44 and result["request_id"] == 55
    assert result["service_nodeid"]["service"] == "ReadRequest"
    assert result["service_body"] == b"CSCTF{opcua_secure}"
    damaged = bytearray(chunk); damaged[-17] ^= 1
    assert depth.decrypt_opcua_symmetric_chunk(bytes(damaged), enc, iv, sign) is None
    assert depth.decrypt_opcua_symmetric_chunk(chunk, enc, iv, b"wrong") is None


def test_pnio_connectionless_rpc_blocks_and_mms_tree():
    wire, ar_uuid = _pnio_rpc()
    result = depth.parse_pnio_rpc(wire)
    assert result["packet_type"] == "request" and result["operation"] == "Connect"
    assert result["serial"] == 0x1234 and result["block_offset"] == 4
    assert result["blocks"][0]["name"] == "ARBlockReq"
    assert result["blocks"][0]["ar_uuid"] == ar_uuid

    def ber(tag, value):
        return bytes([tag, len(value)]) + value
    mms = ber(0xA1, ber(0x02, b"\x07") + ber(0xA4, ber(0x1A, b"CSCTF{mms_tree}")))
    parsed = depth.parse_mms(mms)
    assert parsed["pdu"] == "confirmed_response" and parsed["tree"]["constructed"] is True
    assert "CSCTF{mms_tree}" in parsed["variable_identifiers"]


def test_new_protocol_parsers_seeded_mutation_boundaries():
    rng = random.Random(0x0A1C)
    pnio, _ = _pnio_rpc()
    seeds = [pnio, _opcua_chunk(bytes(32), bytes.fromhex("01" * 32), bytes(16), b"x")]
    for _ in range(1000):
        blob = bytearray(rng.choice(seeds))
        for _ in range(rng.randrange(1, 8)):
            if blob and rng.randrange(2):
                blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
            elif blob:
                del blob[rng.randrange(len(blob))]
        raw = bytes(blob)
        depth.parse_pnio_rpc(raw)
        depth.decrypt_opcua_symmetric_chunk(raw, bytes(32), bytes(16), bytes.fromhex("01" * 32))
        depth.verify_quic_retry(raw, b"odcid")
