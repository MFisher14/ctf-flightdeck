"""Synthetic, offline coverage for the round-3 network/ICS depth engine."""
from __future__ import annotations

import random
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import network_ics_depth as depth  # noqa: E402


def _encrypt(kind, key, nonce, plaintext, aad):
    if kind == "aesgcm":
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _tls13_record(secret, suite, sequence, content, content_type=23, padding=0):
    kind, _hash_name, key, iv = depth._traffic_keys(secret, suite)
    inner = content + bytes([content_type]) + bytes(padding)
    header = b"\x17\x03\x03" + (len(inner) + 16).to_bytes(2, "big")
    return header + _encrypt(kind, key, depth._nonce(iv, sequence), inner, header)


def _quic_short_packet(secret, suite, dcid, packet_number, plaintext, pn_length=2, key_phase=0):
    kind, hash_name, key, iv = depth._traffic_keys(secret, suite, quic=True)
    first = 0x40 | ((key_phase & 1) << 2) | (pn_length - 1)
    pn = packet_number.to_bytes(pn_length, "big")[-pn_length:]
    header = bytes([first]) + dcid + pn
    ciphertext = _encrypt(kind, key, depth._nonce(iv, packet_number), plaintext, header)
    packet = bytearray(header + ciphertext)
    pn_offset = 1 + len(dcid)
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    hp_len = 16 if kind == "aesgcm" and len(key) == 16 else 32
    hp = depth.tls._hkdf_expand_label(secret, b"quic hp", b"", hp_len, hash_name)
    mask = depth._hp_mask(kind, hp, sample)
    packet[0] ^= mask[0] & 0x1F
    for index in range(pn_length):
        packet[pn_offset + index] ^= mask[index + 1]
    return bytes(packet)


def _quic_varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (0x4000 | value).to_bytes(2, "big")
    raise ValueError("fixture value is too large")


def _quic_long_packet(secret, suite, dcid, scid, packet_number, plaintext, packet_type=2,
                      pn_length=2):
    kind, hash_name, key, iv = depth._traffic_keys(secret, suite, quic=True)
    first = 0xC0 | ((packet_type & 3) << 4) | (pn_length - 1)
    prefix = bytes([first]) + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid \
        + bytes([len(scid)]) + scid
    if packet_type == 0:
        prefix += b"\x00"  # empty Initial token
    protected_length = pn_length + len(plaintext) + 16
    prefix += _quic_varint(protected_length)
    pn = packet_number.to_bytes(pn_length, "big")[-pn_length:]
    header = prefix + pn
    ciphertext = _encrypt(kind, key, depth._nonce(iv, packet_number), plaintext, header)
    packet = bytearray(header + ciphertext)
    pn_offset = len(prefix)
    hp_len = 16 if kind == "aesgcm" and len(key) == 16 else 32
    hp = depth.tls._hkdf_expand_label(secret, b"quic hp", b"", hp_len, hash_name)
    mask = depth._hp_mask(kind, hp, bytes(packet[pn_offset + 4:pn_offset + 20]))
    packet[0] ^= mask[0] & 0x0F
    for index in range(pn_length):
        packet[pn_offset + index] ^= mask[index + 1]
    return bytes(packet)


def _ber(tag, value):
    if len(value) < 128:
        return bytes([tag, len(value)]) + value
    encoded = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + value


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        out += struct.pack("<IIII", 1_790_000_000 + index, 0, len(frame), len(frame)) + frame
    return out


def _eth(ethertype, payload):
    return bytes.fromhex("020000000002020000000001") + struct.pack(">H", ethertype) + payload


def _ip4(src, dst, payload, proto=6):
    source = bytes(int(part) for part in src.split("."))
    target = bytes(int(part) for part in dst.split("."))
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       source, target) + payload


def _tcp(sport, dport, sequence, ack, flags, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, sequence, ack, 0x50, flags, 65535, 0, 0) + payload


def _smb_header(command, flags=0):
    header = bytearray(64)
    header[:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<H", header, 12, command)
    struct.pack_into("<I", header, 16, flags)
    return bytes(header)


def _netbios(message):
    return b"\x00" + len(message).to_bytes(3, "big") + message


def _smb_capture():
    server_body = struct.pack("<HHH", 65, 1, 0x0311) + bytes(32)
    server = _netbios(_smb_header(0, 1) + server_body)
    share = r"\\fileserver\PAYROLL$".encode("utf-16-le")
    client_body = struct.pack("<HHHH", 9, 0, 72, len(share)) + share
    client = _netbios(_smb_header(3) + client_body)
    frames = [
        _eth(0x0800, _ip4("192.0.2.10", "192.0.2.20", _tcp(40001, 445, 100, 0, 0x02))),
        _eth(0x0800, _ip4("192.0.2.20", "192.0.2.10", _tcp(445, 40001, 200, 101, 0x12))),
        _eth(0x0800, _ip4("192.0.2.20", "192.0.2.10", _tcp(445, 40001, 201, 101, 0x18, server))),
        _eth(0x0800, _ip4("192.0.2.10", "192.0.2.20", _tcp(40001, 445, 101, 201 + len(server), 0x18, client))),
    ]
    return _pcap(frames)


def _goose_payload():
    fields = b"".join((
        _ber(0x80, b"LD0/LLN0$GO$gcb1"),
        _ber(0x81, (1000).to_bytes(2, "big")),
        _ber(0x82, b"LD0/LLN0$dataset1"),
        _ber(0x84, (1_700_000_000).to_bytes(4, "big") + b"\x80\x00\x00\x00"),
        _ber(0x85, b"\x01"),
        _ber(0x86, b"\x02"),
        _ber(0x87, b"\x00"),
        _ber(0x88, b"\x01"),
        _ber(0x89, b"\x00"),
        _ber(0x8A, b"\x02"),
        _ber(0xAB, _ber(0x83, b"\xff") + _ber(0x8A, b"CSCTF{goose}")),
    ))
    apdu = _ber(0x61, fields)
    return struct.pack(">HHHH", 0x1001, 8 + len(apdu), 0, 0) + apdu


def _mms_payload():
    request = _ber(0xA0, _ber(0x02, b"\x07") + _ber(0xA4, _ber(0x1A, b"LD0/MMXU1.TotW")))
    cotp = b"\x02\xf0\x80"
    length = 4 + len(cotp) + len(request)
    return b"\x03\x00" + length.to_bytes(2, "big") + cotp + request


def _opcua_payload():
    endpoint = b"opc.tcp://plc.example:4840"
    hello_body = struct.pack("<IIIII", 0, 65536, 65536, 1 << 20, 16)
    hello_body += struct.pack("<i", len(endpoint)) + endpoint
    hello = b"HELF" + (8 + len(hello_body)).to_bytes(4, "little") + hello_body
    # Symmetric security + sequence headers, followed by NodeId ns=0;i=631 (ReadRequest).
    msg_body = struct.pack("<IIII", 9, 3, 10, 11) + b"\x01\x00" + (631).to_bytes(2, "little")
    message = b"MSGF" + (8 + len(msg_body)).to_bytes(4, "little") + msg_body
    return hello + message


def _profinet_dcp_payload():
    raw = b"\x00\x00plc01"
    block = b"\x02\x02" + len(raw).to_bytes(2, "big") + raw
    if len(raw) & 1:
        block += b"\x00"
    return b"\xfe\xff\x05\x01" + (0x10203040).to_bytes(4, "big") + b"\x00\x00" \
        + len(block).to_bytes(2, "big") + block


def test_extended_keylog_preserves_unrelated_labels_on_conflict():
    random_hex = "00" * 32
    keylog = (f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {random_hex} {'11' * 32}\n"
              f"CLIENT_TRAFFIC_SECRET_0 {random_hex} {'22' * 32}\n"
              f"CLIENT_TRAFFIC_SECRET_0 {random_hex} {'33' * 32}\n").encode()
    result = depth.parse_extended_keylog(keylog)
    assert result["sessions"][random_hex]["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == "11" * 32
    assert "CLIENT_TRAFFIC_SECRET_0" not in result["sessions"][random_hex]
    assert result["conflicts"] == [{"client_random": random_hex,
                                    "label": "CLIENT_TRAFFIC_SECRET_0"}]
    assert depth.keylog_secret(keylog, random_hex, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") == bytes.fromhex("11" * 32)
    assert depth.keylog_secret(keylog, random_hex, "CLIENT_TRAFFIC_SECRET_0") is None


@pytest.mark.parametrize("suite", [0x1301, 0x1303])
def test_tls13_keyupdate_and_capture_after_update_are_authenticated(suite):
    secret = bytes.fromhex("11" * 32)
    update = b"\x18\x00\x00\x01\x00"
    epoch_one = depth.tls13_update_secret(secret)
    records = (_tls13_record(secret, suite, 0, update, content_type=22, padding=3)
               + _tls13_record(epoch_one, suite, 0, b"GET /flag HTTP/1.1\r\n", padding=7))
    result = depth.decrypt_tls13_records(records, secret, suite)
    assert result["verified"] and result["final_epoch"] == 1
    assert [row["epoch"] for row in result["records"]] == [0, 1]
    assert result["records"][1]["content"] == b"GET /flag HTTP/1.1\r\n"

    later = _tls13_record(epoch_one, suite, 0, b"capture started late")
    found = depth.decrypt_tls13_records(later, secret, suite, search_updates=1)
    assert found["verified"] and found["records"][0]["epoch"] == 1

    fragmented = (_tls13_record(secret, suite, 0, update[:3], content_type=22)
                  + _tls13_record(secret, suite, 1, update[3:], content_type=22)
                  + _tls13_record(epoch_one, suite, 0, b"after fragmented update"))
    reassembled = depth.decrypt_tls13_records(fragmented, secret, suite)
    assert reassembled["verified"] and reassembled["final_epoch"] == 1
    assert reassembled["pending_handshake_bytes"] == 0

    damaged = bytearray(records)
    damaged[-1] ^= 1
    assert depth.decrypt_tls13_records(bytes(damaged), secret, suite)["verified"] is False


@pytest.mark.parametrize("suite", [0x1301, 0x1303])
def test_quic_short_header_protection_and_aead_round_trip(suite):
    secret = bytes.fromhex("24" * 32)
    packet = _quic_short_packet(secret, suite, b"eightDID", 0x1234,
                                b"\x01authenticated QUIC stream payload")
    result = depth.decrypt_quic_short(packet, secret, suite, 8,
                                      largest_packet_number=0x1200)
    assert result and result["verified"] and result["packet_number"] == 0x1234
    assert result["plaintext"] == b"\x01authenticated QUIC stream payload"
    damaged = bytearray(packet)
    damaged[-1] ^= 1
    assert depth.decrypt_quic_short(bytes(damaged), secret, suite, 8,
                                    largest_packet_number=0x1200) is None


def test_quic_key_phase_update_and_long_handshake_packet():
    secret = bytes.fromhex("39" * 32)
    next_secret = depth.quic_update_secret(secret)
    short = _quic_short_packet(next_secret, 0x1301, b"eightDID", 9,
                               b"key phase one has enough ciphertext", key_phase=1)
    recovered = depth.decrypt_quic_short(short, secret, 0x1301, 8,
                                         largest_packet_number=8, search_updates=1)
    assert recovered and recovered["epoch"] == 1 and recovered["key_phase"] == 1

    long_packet = _quic_long_packet(secret, 0x1301, b"dest", b"source", 7,
                                    b"\x06authenticated CRYPTO frame bytes")
    handshake = depth.decrypt_quic_long(long_packet, secret, 0x1301,
                                        largest_packet_number=6)
    assert handshake and handshake["packet_type"] == "handshake"
    assert handshake["packet_number"] == 7
    assert handshake["plaintext"] == b"\x06authenticated CRYPTO frame bytes"


def test_unified_ntlm_kerberos_and_smb_artifact_extraction():
    ntlm_capture, ntlm_expected = depth.pcap_creds.build_ntlmv2_pcap()
    ntlm = depth.extract_auth_artifacts(ntlm_capture)
    assert ntlm_expected in ntlm["credential_material"][0]["renderings"]
    assert ntlm["credential_material"][0]["field"] == "netntlmv2_hashcat"

    kerberos_capture, kerberos_expected = depth.pcap_creds.build_kerberos_asrep_pcap()
    kerberos = depth.extract_auth_artifacts(kerberos_capture)
    assert kerberos_expected in kerberos["credential_material"][0]["renderings"]
    assert kerberos["kerberos"][0]["msg_type"] == "as_rep"
    assert kerberos["kerberos"][0]["realm"] == "CORP.LOCAL"

    smb = depth.extract_auth_artifacts(_smb_capture())["smb"]
    assert smb["dialect"] == "3.1.1"
    assert r"\\fileserver\PAYROLL$" in smb["shares"]


def test_individual_ics_decoders_and_capture_orchestration():
    goose = depth.parse_goose(_goose_payload())
    assert goose["fields"]["state_number"] == 1
    assert goose["all_data"][0]["value"] is True
    assert goose["all_data"][1]["value"] == "CSCTF{goose}"

    mms = depth.parse_mms(_mms_payload())
    assert mms["pdu"] == "confirmed_request" and mms["invoke_id"] == 7
    assert mms["service"]["name"] == "read"
    assert "LD0/MMXU1.TotW" in mms["strings"]

    opcua = depth.parse_opcua(_opcua_payload())
    assert opcua[0]["endpoint_url"] == "opc.tcp://plc.example:4840"
    assert opcua[1]["service_nodeid"]["service"] == "ReadRequest"

    dcp = depth.parse_profinet(_profinet_dcp_payload())
    assert dcp["dcp"]["service"] == "Identify"
    assert dcp["dcp"]["blocks"][0]["station_name"] == "plc01"
    cyclic = depth.parse_profinet(b"\x80\x00DATA\x12\x34\x80\x00")
    assert cyclic["rt"]["cycle_counter"] == 0x1234
    assert cyclic["rt"]["cyclic_data"] == b"DATA"

    mms_wire, opcua_wire = _mms_payload(), _opcua_payload()
    capture = _pcap([
        _eth(0x88B8, _goose_payload()),
        _eth(0x8892, _profinet_dcp_payload()),
        _eth(0x0800, _ip4("192.0.2.30", "192.0.2.40", _tcp(41000, 102, 100, 0, 0x02))),
        _eth(0x0800, _ip4("192.0.2.30", "192.0.2.40", _tcp(41000, 102, 101, 0, 0x18, mms_wire))),
        _eth(0x0800, _ip4("192.0.2.50", "192.0.2.60", _tcp(42000, 4840, 200, 0, 0x02))),
        _eth(0x0800, _ip4("192.0.2.50", "192.0.2.60", _tcp(42000, 4840, 201, 0, 0x18, opcua_wire))),
    ])
    analyzed = depth.analyze_ics_capture(capture)
    assert len(analyzed["goose"]) == len(analyzed["profinet"]) == 1
    assert analyzed["mms"][0]["service"]["name"] == "read"
    assert analyzed["opcua"][1]["service_nodeid"]["service"] == "ReadRequest"


def test_covert_channel_classifier_ranks_planted_channel():
    flag = b"CSCTF{ntp_channel}"
    padded = flag.ljust((len(flag) + 3) // 4 * 4, b"\x00")
    packets = [{"proto": "ntp", "dport": 123, "payload": bytes(12) + padded[i:i + 4]}
               for i in range(0, len(padded), 4)]
    result = depth.classify_covert_channel(packets)
    assert result["classification"] == "ntp"
    assert result["candidates"][0]["candidate"] == flag.decode()


def test_protocol_parsers_fail_closed_under_mutation():
    rng = random.Random(0xC5C7F)
    parsers = (depth.parse_goose, depth.parse_mms, depth.parse_opcua, depth.parse_profinet)
    seeds = (_goose_payload(), _mms_payload(), _opcua_payload(), _profinet_dcp_payload())
    for _ in range(250):
        base = bytearray(rng.choice(seeds))
        for _ in range(rng.randrange(1, 8)):
            if base:
                base[rng.randrange(len(base))] = rng.randrange(256)
        if rng.randrange(2):
            del base[rng.randrange(len(base) + 1):]
        for parser in parsers:
            parser(bytes(base))


def test_guarded_cli_help_no_args_and_garbage(tmp_path, capsys):
    script = REPO / "solvers" / "toolkits" / "network_ics_depth.py"
    help_run = subprocess.run([sys.executable, str(script), "--help"], capture_output=True,
                              text=True, check=False, timeout=10)
    assert help_run.returncode == 0 and "Traceback" not in help_run.stderr
    assert depth.main([]) == 2
    assert "network_ics_depth:" in capsys.readouterr().err
    garbage = tmp_path / "garbage.bin"
    garbage.write_bytes(b"not a protocol")
    assert depth.main(["goose", str(garbage)]) == 2
    assert "Traceback" not in capsys.readouterr().err

