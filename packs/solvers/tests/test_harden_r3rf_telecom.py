"""RFC/Scapy vector locks and complete public-boundary fuzz for telecom3."""
from __future__ import annotations

import hashlib
import json
import random

import pytest
from scapy.contrib import gtp_v2, pfcp
from scapy.layers.rtp import RTP

import telecom3_depth as telecom


MASTER_KEY = "E1F97A0D3E018BE0D64FA32C06DE4139"
MASTER_SALT = "0EC675AD498AFEEBB6960B3AABE6"
PLAIN_RTP = bytes.fromhex("800f1234decafbadcafebabe" + "ab" * 16)
SRTP_PACKET = bytes.fromhex(
    "800f1234decafbadcafebabe"
    "4e55dc4ce79978d88ca4d215949d2402"
    "b78d6acc99ea179b8dbb"
)
SRTCP_PACKET = bytes.fromhex(
    "81c8000bcafebabe"
    "7128035be487b9bdbef89041f977a5a8"
    "80000001"
    "993e08cd54d6c1230798"
)

GTP_REQUEST = bytes.fromhex(
    "482000320000000001020300"
    "0100080000010121436587f9"
    "4700040003696d73"
    "570009008a111111110a000001"
    "5d0005004900010005"
)
GTP_RESPONSE = bytes.fromhex(
    "4821002a1111111101020300"
    "020002001000"
    "570009008b222222220a000002"
    "5d000b004900010005020002001000"
)

PFCP_REQUEST = bytes.fromhex(
    "21320063000000000000000000000100"
    "0039000d0211223344556677880a000001"
    "0001001e003800020007006c000401020304006d0004111213140051000421222324"
    "00030008006c000401020304"
    "00070008006d000411121314"
    "000600080051000421222324"
)
PFCP_RESPONSE = bytes.fromhex(
    "21330022112233445566778800000100"
    "0013000101"
    "0039000d0288776655443322110a000002"
)


def _digest_md5(method: str, uri: str, username: str, realm: str,
                password: str, nonce: str, nc: str, cnonce: str) -> str:
    md5 = lambda value: hashlib.md5(value.encode()).hexdigest()  # noqa: S324 - RFC oracle
    ha1 = md5(f"{username}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    return md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")


def _sip_exchange() -> tuple[bytes, bytes, str]:
    response = _digest_md5(
        "MESSAGE", "sip:bob@example.test", "alice", "example.test",
        "swordfish", "nonce-123", "00000001", "client-token",
    )
    body = b"CSCTF{telecom_message}"
    request = (
        "MESSAGE sip:bob@example.test SIP/2.0\r\n"
        "Via: SIP/2.0/UDP ua.example.test;branch=z9hG4bK-r3rf\r\n"
        "From: <sip:alice@example.test>;tag=1\r\n"
        "To: <sip:bob@example.test>\r\n"
        "Call-ID: r3rf@example.test\r\n"
        "CSeq: 7 MESSAGE\r\n"
        "Content-Type: text/plain\r\n"
        f'Authorization: Digest username="alice", realm="example.test", '
        f'nonce="nonce-123", uri="sip:bob@example.test", response="{response}", '
        'algorithm=MD5, qop=auth, nc=00000001, cnonce="client-token"\r\n'
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    accepted = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP ua.example.test;branch=z9hG4bK-r3rf\r\n"
        b"From: <sip:alice@example.test>;tag=1\r\n"
        b"To: <sip:bob@example.test>;tag=2\r\n"
        b"Call-ID: r3rf@example.test\r\n"
        b"CSeq: 7 MESSAGE\r\nContent-Length: 0\r\n\r\n"
    )
    return request, accepted, response


def _accept_or_declared(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except telecom.Telecom3Error as exc:
        assert type(exc) is telecom.Telecom3Error
        return None
    except BaseException as exc:  # pragma: no cover - contract assertion
        pytest.fail(f"{function.__name__} leaked {type(exc).__name__}: {exc}")


def test_rfc3711_and_rfc4568_vector_locks_include_srtcp_labels():
    assert telecom.derive_srtp_keys(MASTER_KEY, MASTER_SALT) == {
        "kind": "SRTP",
        "encryption_key_hex": "c61e7a93744f39ee10734afe3ff7a087",
        "authentication_key_hex": "cebe321f6ff7716b6fd4ab49af256a156d38baa4",
        "salting_key_hex": "30cbbc08863d8c85d49db34a9ae1",
    }
    assert telecom.derive_srtp_keys(MASTER_KEY, MASTER_SALT, rtcp=True) == {
        "kind": "SRTCP",
        "encryption_key_hex": "4c1aa45a81f73d61c800bbb00fbb1eaa",
        "authentication_key_hex": "8d54534feb49ae8e7993a6bd0b844fc323a93dfd",
        "salting_key_hex": "9581c7ad87b3e530bf3e4454a8b3",
    }
    assert telecom.parse_srtp_context(
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
        "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4"
    ) == {
        "profile": "AES_CM_128_HMAC_SHA1_80",
        "master_key_hex": "774466766726542b2978473740666235",
        "master_salt_hex": "6a552c5261417d5c7c7030252a23",
        "lifetime_packets": 1_048_576,
        "mki_hex": "00000001",
        "mki_length": 4,
    }


def test_libsrtp_decryption_plaintext_is_independently_decoded_by_scapy():
    result = telecom.decrypt_srtp(
        SRTP_PACKET, master_key=MASTER_KEY, master_salt=MASTER_SALT
    )
    plaintext = bytes.fromhex(result["plaintext_packet_hex"])
    assert plaintext == PLAIN_RTP
    oracle = RTP(plaintext)
    assert int(oracle.version) == 2
    assert int(oracle.payload_type) == 15
    assert int(oracle.sequence) == 0x1234
    assert int(oracle.timestamp) == 0xDECAFBAD
    assert int(oracle.sourcesync) == 0xCAFEBABE
    assert bytes(oracle.payload) == b"\xab" * 16

    control = telecom.decrypt_srtcp(
        SRTCP_PACKET, master_key=MASTER_KEY, master_salt=MASTER_SALT
    )
    assert control["index"] == 1
    assert control["encrypted"] is True
    assert control["ssrc"] == 0xCAFEBABE
    assert control["payload_hex"] == "ab" * 16


def test_sip_public_entrypoints_match_independent_digest_and_flow_oracle():
    request, accepted, digest = _sip_exchange()
    parsed = telecom.parse_sip_message(request)
    assert parsed["method"] == "MESSAGE"
    assert parsed["request_uri"] == "sip:bob@example.test"
    assert parsed["body_text"] == "CSCTF{telecom_message}"
    assert telecom.compute_sip_digest(
        method="MESSAGE", uri="sip:bob@example.test", username="alice",
        realm="example.test", password="swordfish", nonce="nonce-123",
        qop="auth", nc="00000001", cnonce="client-token",
    ) == digest
    verification = telecom.verify_sip_digest(request, "swordfish")
    assert verification["verified"] is True
    assert verification["uri_matches_request"] is True
    trace = telecom.analyze_sip_trace([request, accepted],
                                      credentials={"alice": "swordfish"})
    assert trace["instant_messages"] == [{
        "message_index": 0,
        "call_id": "r3rf@example.test",
        "cseq": 7,
        "from": "<sip:alice@example.test>;tag=1",
        "to": "<sip:bob@example.test>",
        "request_uri": "sip:bob@example.test",
        "content_type": "text/plain",
        "body_hex": b"CSCTF{telecom_message}".hex(),
        "body_text": "CSCTF{telecom_message}",
        "final_status": 200,
        "accepted": True,
        "delivery_confirmed": True,
    }]


def test_gtpv2_and_pfcp_parse_and_correlation_match_scapy():
    for raw, expected_type, expected_teid in (
        (GTP_REQUEST, 32, 0), (GTP_RESPONSE, 33, 0x11111111),
    ):
        oracle = gtp_v2.GTPHeader(raw)
        assert bytes(oracle) == raw
        assert int(oracle.gtp_type) == expected_type
        assert int(oracle.teid) == expected_teid
        decoded = telecom.parse_gtpc_event(raw)
        assert decoded["message_type"] == int(oracle.gtp_type)
        assert decoded["sequence"] == int(oracle.seq) == 0x010203
        assert decoded["header_teid"] == int(oracle.teid)
    gtp_trace = telecom.correlate_gtpc([GTP_REQUEST, GTP_RESPONSE])
    assert gtp_trace["unanswered_requests"] == 0
    assert gtp_trace["transactions"][0]["matched"] is True
    assert gtp_trace["sessions"][0]["imsi"] == "001010123456789"
    assert gtp_trace["sessions"][0]["apn"] == "ims"
    assert gtp_trace["sessions"][0]["state"] == "active"
    assert gtp_trace["sessions"][0]["bearers"] == [5]

    for raw, expected_type, expected_seid in (
        (PFCP_REQUEST, 50, 0),
        (PFCP_RESPONSE, 51, 0x1122334455667788),
    ):
        oracle = pfcp.PFCP(raw)
        assert bytes(oracle) == raw
        assert int(oracle.message_type) == expected_type
        assert int(oracle.seid) == expected_seid
        decoded = telecom.parse_pfcp(raw)
        assert decoded["message_type"] == int(oracle.message_type)
        assert decoded["sequence"] == int(oracle.seq) == 1
        assert decoded["seid"] == int(oracle.seid)
    pfcp_trace = telecom.correlate_pfcp([PFCP_REQUEST, PFCP_RESPONSE])
    assert pfcp_trace["unanswered_requests"] == 0
    assert pfcp_trace["transactions"][0]["matched"] is True
    assert pfcp_trace["sessions"][0]["state"] == "active"
    assert pfcp_trace["sessions"][0]["pdr_ids"] == [7]
    assert pfcp_trace["sessions"][0]["far_ids"] == [0x01020304]


def test_binary_public_entrypoints_fail_closed_on_required_fuzz_classes():
    rng = random.Random(0x7233F)
    gtpc_corpus = [b"", b"\xff" * 64, rng.randbytes(127), GTP_REQUEST[:7],
                   GTP_REQUEST[:-1], b"x" * (telecom.MAX_PACKET + 1)]
    pfcp_corpus = [b"", b"\xff" * 64, rng.randbytes(127), PFCP_REQUEST[:7],
                   PFCP_REQUEST[:-1], b"x" * (telecom.MAX_PACKET + 1)]
    for raw, parser in ((*((value, telecom.parse_gtpc_event) for value in gtpc_corpus),
                         *((value, telecom.parse_pfcp) for value in pfcp_corpus))):
        _accept_or_declared(parser, raw)
    for valid, parser in ((GTP_REQUEST, telecom.parse_gtpc_event),
                          (PFCP_REQUEST, telecom.parse_pfcp)):
        for position in (0, 1, 2, 3, len(valid) // 2, len(valid) - 1):
            changed = bytearray(valid)
            changed[position] ^= 1
            _accept_or_declared(parser, bytes(changed))
        for cut in range(len(valid)):
            _accept_or_declared(parser, valid[:cut])

    sip, _, _ = _sip_exchange()
    sip_flipped = bytearray(sip)
    sip_flipped[0] ^= 1
    sip_corpus = [b"", b"\xff" * 64, rng.randbytes(113), sip[:20], sip[:-1],
                  bytes(sip_flipped), b"x" * (telecom.MAX_SIP + 1)]
    for raw in sip_corpus:
        _accept_or_declared(telecom.parse_sip_message, raw)
        _accept_or_declared(telecom.verify_sip_digest, raw, "swordfish")
    for packet, decryptor in ((SRTP_PACKET, telecom.decrypt_srtp),
                              (SRTCP_PACKET, telecom.decrypt_srtcp)):
        corpus = [b"", b"\xff" * 32, rng.randbytes(80), packet[:8], packet[:-1],
                  b"x" * (telecom.MAX_PACKET + 1)]
        corrupted = bytearray(packet)
        corrupted[-1] ^= 1
        corpus.append(bytes(corrupted))
        for raw in corpus:
            _accept_or_declared(decryptor, raw, master_key=MASTER_KEY,
                                master_salt=MASTER_SALT)


def test_every_auxiliary_public_entrypoint_and_cli_fail_closed(tmp_path, capsys):
    bad_calls = [
        lambda: telecom.parse_srtp_context(""),
        lambda: telecom.parse_srtp_context("x" * 4097),
        lambda: telecom.parse_srtp_context(b"inline:\xff"),
        lambda: telecom.derive_srtp_keys(b"", b""),
        lambda: telecom.derive_srtp_keys(b"x" * 17, b"x" * 15),
        lambda: telecom.derive_srtp_keys(MASTER_KEY, MASTER_SALT, rtcp=1),
        lambda: telecom.compute_sip_digest(
            method=None, uri="x", username="u", realm="r", password="p", nonce="n"),
        lambda: telecom.compute_sip_digest(
            method="x" * 8193, uri="x", username="u", realm="r", password="p", nonce="n"),
        lambda: telecom.verify_sip_digest({}, "password"),
        lambda: telecom.verify_sip_digest({"kind": "request"}, "password"),
        lambda: telecom.analyze_sip_trace([]),
        lambda: telecom.analyze_sip_trace([b"x"] * (telecom.MAX_TRACE_MESSAGES + 1)),
        lambda: telecom.correlate_gtpc([]),
        lambda: telecom.correlate_gtpc([GTP_REQUEST] * (telecom.MAX_TRACE_MESSAGES + 1)),
        lambda: telecom.correlate_pfcp([]),
        lambda: telecom.correlate_pfcp([PFCP_REQUEST] * (telecom.MAX_TRACE_MESSAGES + 1)),
    ]
    for call in bad_calls:
        try:
            call()
        except telecom.Telecom3Error as exc:
            assert type(exc) is telecom.Telecom3Error
        except BaseException as exc:  # pragma: no cover - contract assertion
            pytest.fail(f"auxiliary API leaked {type(exc).__name__}: {exc}")
        else:  # pragma: no cover - every listed input is malformed
            pytest.fail("malformed auxiliary input unexpectedly succeeded")

    pdu = tmp_path / "heartbeat.pfcp"
    pdu.write_bytes(bytes.fromhex("2001000c010203000060000412345678"))
    assert telecom.main(["pfcp", str(pdu)]) == 0
    assert json.loads(capsys.readouterr().out)["sequence"] == 0x010203
    oversized = tmp_path / "oversized.gtpc"
    oversized.write_bytes(b"x" * (telecom.MAX_PACKET + 1))
    assert telecom.main(["gtpc", str(oversized)]) == 2
    capsys.readouterr()
    assert telecom.main(["--help"]) == 0
    capsys.readouterr()
    assert telecom.main([]) == 2
    capsys.readouterr()
    assert telecom.main(["not-a-command"]) == 2
    capsys.readouterr()
