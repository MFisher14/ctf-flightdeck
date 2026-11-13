"""Round-5 authenticated OPC-UA and conservative ICS grammar coverage."""
from __future__ import annotations

import datetime
import hashlib
import random
import struct
import sys
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import network_ics_depth as depth  # noqa: E402


def _blob(value: bytes) -> bytes:
    return len(value).to_bytes(4, "little", signed=True) + value


def _certificate(key, common_name: str) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2035, 1, 1)).sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))


def _opn_chunk(receiver, receiver_cert: bytes, signer, sender_cert: bytes, body: bytes,
               *, policy_name="Basic256Sha256", signing_key=None) -> bytes:
    policy = depth._UA_POLICY_PREFIX + policy_name
    enc_name, hash_name, sig_name = depth._UA_ASYMMETRIC_POLICIES[policy]
    digest = hashes.SHA1() if hash_name == "sha1" else hashes.SHA256()
    if enc_name == "pkcs1v15":
        encrypt_padding = padding.PKCS1v15()
        clear_block = receiver.key_size // 8 - 11
    else:
        oaep_hash = hashes.SHA1() if enc_name == "oaep-sha1" else hashes.SHA256()
        encrypt_padding = padding.OAEP(mgf=padding.MGF1(oaep_hash), algorithm=oaep_hash, label=None)
        clear_block = receiver.key_size // 8 - 2 * oaep_hash.digest_size - 2
    service = b"\x01\x00" + (631).to_bytes(2, "little")
    content = struct.pack("<II", 0x10203040, 0x50607080) + service + body
    signature_size = signer.key_size // 8
    pad_length = (-(len(content) + signature_size)) % clear_block or clear_block
    assert 1 <= pad_length <= 256
    signed = content + bytes([pad_length - 1]) * pad_length
    encrypted_blocks = (len(signed) + signature_size) // clear_block
    security_header = (_blob(policy.encode("ascii")) + _blob(sender_cert) +
                       _blob(hashlib.sha1(receiver_cert).digest()))
    header_length = 12 + len(security_header)
    total = header_length + encrypted_blocks * (receiver.key_size // 8)
    header = b"OPNF" + total.to_bytes(4, "little") + (7).to_bytes(4, "little") + security_header
    signer_for_wire = signing_key or signer
    sig_padding = (padding.PKCS1v15() if sig_name == "pkcs1v15" else
                   padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size))
    signature = signer_for_wire.sign(header + signed, sig_padding, digest)
    clear = signed + signature
    assert len(clear) % clear_block == 0
    encrypted = b"".join(receiver.public_key().encrypt(clear[at:at + clear_block], encrypt_padding)
                         for at in range(0, len(clear), clear_block))
    return header + encrypted


def _rpc_with_iod_write() -> tuple[bytes, uuid.UUID]:
    ar_uuid = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
    record = b"CSCTF{pnio_ndr}"
    body = ((0x1234).to_bytes(2, "big") + ar_uuid.bytes_le + (0x01020304).to_bytes(4, "big") +
            (0x0506).to_bytes(2, "big") + (0x0708).to_bytes(2, "big") + b"\x00\x00" +
            (0x0A0B).to_bytes(2, "big") + len(record).to_bytes(4, "big") + record)
    block = b"\x00\x09" + (2 + len(body)).to_bytes(2, "big") + b"\x01\x00" + body
    while len(block) % 4:
        block += b"\x00"
    stub = b"\x78\x56\x34\x12" + block
    header = bytearray(80)
    header[0:2] = b"\x04\x00"
    header[4:7] = b"\x10\x00\x00"
    header[24:40] = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le
    header[40:56] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    header[68:70] = (3).to_bytes(2, "little")
    header[70:72] = (0x1111).to_bytes(2, "little")
    header[72:74] = (0x2222).to_bytes(2, "little")
    header[74:76] = len(stub).to_bytes(2, "little")
    return bytes(header) + stub, ar_uuid


def _ber(tag: int, value: bytes) -> bytes:
    assert len(value) < 128
    return bytes([tag, len(value)]) + value


def _varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    if value < 16384:
        return (0x4000 | value).to_bytes(2, "big")
    raise ValueError


def test_opcua_opn_rsa_decrypt_is_signature_and_thumbprint_gated(tmp_path, capsys):
    receiver = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sender = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    receiver_cert, sender_cert = _certificate(receiver, "receiver"), _certificate(sender, "sender")
    chunk = _opn_chunk(receiver, receiver_cert, sender, sender_cert, b"CSCTF{verified_opn}")
    receiver_pem = receiver.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
    sender_der = sender.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    result = depth.decrypt_opcua_asymmetric_opn(
        chunk, receiver_pem, sender_public_key=sender_der, receiver_certificate=receiver_cert)
    assert result and result["verified"] and result["signature_verified"]
    assert result["receiver_thumbprint_checked"] is True
    assert result["service_nodeid"]["service"] == "ReadRequest"
    assert result["service_body"] == b"CSCTF{verified_opn}"
    # The certificate inside a message is self-asserted; authentication requires
    # the independently supplied sender key/certificate.
    assert depth.decrypt_opcua_asymmetric_opn(chunk, receiver_pem,
                                              receiver_certificate=receiver_cert) is None

    damaged = bytearray(chunk)
    damaged[-1] ^= 1
    assert depth.decrypt_opcua_asymmetric_opn(bytes(damaged), receiver_pem,
                                              sender_public_key=sender_der,
                                              receiver_certificate=receiver_cert) is None
    assert depth.decrypt_opcua_asymmetric_opn(chunk, receiver_pem,
                                              sender_public_key=sender_der,
                                              receiver_certificate=sender_cert) is None
    wrong_signed = _opn_chunk(receiver, receiver_cert, sender, sender_cert, b"wrong",
                              signing_key=wrong)
    assert depth.decrypt_opcua_asymmetric_opn(wrong_signed, receiver_pem,
                                              sender_public_key=sender_der,
                                              receiver_certificate=receiver_cert) is None

    chunk_path, key_path, cert_path = tmp_path / "opn.bin", tmp_path / "key.pem", tmp_path / "cert.der"
    chunk_path.write_bytes(chunk)
    key_path.write_bytes(receiver_pem)
    cert_path.write_bytes(receiver_cert)
    sender_path = tmp_path / "sender.der"
    sender_path.write_bytes(sender_der)
    assert depth.main(["opcua-opn", str(chunk_path), str(key_path), "--sender-public-key", str(sender_path),
                       "--receiver-certificate", str(cert_path)]) == 0
    assert '"signature_verified": true' in capsys.readouterr().out


def test_opcua_opn_rsapss_policy_and_explicit_sender_key():
    receiver = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sender = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    receiver_cert = _certificate(receiver, "receiver")
    chunk = _opn_chunk(receiver, receiver_cert, sender, b"", b"PSS",
                       policy_name="Aes256_Sha256_RsaPss")
    receiver_der = receiver.private_bytes(serialization.Encoding.DER,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
    sender_der = sender.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    result = depth.decrypt_opcua_asymmetric_opn(chunk, receiver_der,
                                                sender_public_key=sender_der,
                                                receiver_certificate=receiver_cert)
    assert result and result["rsa_encryption"] == "oaep-sha256"
    assert result["rsa_signature"] == "pss-sha256" and result["service_body"] == b"PSS"


def test_quic_rfc9368_frames_and_strict_ack_frequency_values():
    wire = b"\x1f" + _varint(0xAF) + b"".join(_varint(value) for value in (9, 2, 25, 1))
    rows = depth.parse_quic_frames(wire)
    assert rows == [
        {"type": 0x1F, "name": "immediate_ack"},
        {"type": 0xAF, "name": "ack_frequency", "sequence_number": 9,
         "packet_tolerance": 2, "maximum_ack_delay": 25, "reordering_threshold": 1},
    ]
    try:
        depth.parse_quic_frames(_varint(0xAF) + b"\x01\x00\x01\x00")
    except ValueError:
        pass
    else:
        raise AssertionError("zero ACK_FREQUENCY tolerance was accepted")


def test_pnio_iod_offsets_and_mms_semantics_are_conservative():
    wire, ar_uuid = _rpc_with_iod_write()
    parsed = depth.parse_pnio_rpc(wire)
    assert parsed and parsed["interface_name"] == "PNIO-Device" and parsed["operation"] == "Write"
    assert parsed["ndr_prefix"] == {"length": 4, "aligned": True, "u32": [0x12345678]}
    block = parsed["blocks"][0]
    assert block["ar_uuid"] == str(ar_uuid)
    assert (block["api"], block["slot"], block["subslot"], block["index"]) == (
        0x01020304, 0x0506, 0x0708, 0x0A0B)
    assert block["record_data"] == b"CSCTF{pnio_ndr}"
    # The old offsets interpreted bytes 2..5 of ARUUID as API; ensure that
    # attractive but wrong value can no longer escape as the decoded API.
    assert block["api"] != int.from_bytes(ar_uuid.bytes_le[:4], "big")

    info = _ber(0xA3, _ber(0xA0, _ber(0x85, b"\xff") + _ber(0x8A, b"CSCTF{mms}")))
    mms = depth.parse_mms(info)
    assert mms and mms["service"]["name"] == "information_report"
    typed = {row.get("data_type_candidate"): row for row in mms["data_values"]}
    assert typed["integer"]["typed_value"] == -1
    assert typed["visible_string"]["typed_value"] == "CSCTF{mms}"
    assert all(row["candidate_only"] and not row["schema_verified"]
               for row in mms["data_values"])

    semaphore = _ber(0xA0, _ber(0x02, b"\x01") + _ber(0x97, b"\x00"))
    assert depth.parse_mms(semaphore)["service"]["name"] == "report_semaphore_status"


def test_round5_network_parsers_5000_seeded_mutations_each():
    """Every new parser boundary sees the same 5,000 deterministic corruptions."""
    rng = random.Random(0xC5C72026)
    pnio, _ = _rpc_with_iod_write()
    mms = _ber(0xA3, _ber(0xA0, _ber(0x8A, b"saved bytes only")))
    frames = b"\x1f" + _varint(0xAF) + b"\x01\x02\x03\x01"
    seeds = [pnio, mms, frames, b"OPNF" + bytes(60)]
    for _ in range(5000):
        blob = bytearray(rng.choice(seeds))
        for _ in range(rng.randrange(1, 6)):
            action = rng.randrange(3)
            if blob and action == 0:
                blob[rng.randrange(len(blob))] ^= 1 << rng.randrange(8)
            elif blob and action == 1:
                del blob[rng.randrange(len(blob))]
            elif len(blob) < 512:
                blob.insert(rng.randrange(len(blob) + 1), rng.randrange(256))
        raw = bytes(blob)
        depth.parse_pnio_rpc(raw)
        depth.parse_mms(raw)
        depth._ua_opn_header(raw)
        try:
            depth.parse_quic_frames(raw, max_frames=512)
        except ValueError:
            pass
