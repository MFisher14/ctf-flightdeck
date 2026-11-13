"""Independent vector locks for the offline telecom3 depth engine.

Published sources:
* RFC 3711 Appendix B and Cisco libSRTP's ``srtp_driver.c`` vectors.
* RFC 4568 section 9.1 SDES example.
* RFC 7616 section 3.9 Digest examples and RFC 3428 section 10.1 MESSAGE.
* 3GPP TS 29.274 / TS 29.244 layouts, independently decoded here with Scapy.
"""

import hashlib
import random

import pytest

import telecom3_depth as engine


MASTER_KEY = "E1F97A0D3E018BE0D64FA32C06DE4139"
MASTER_SALT = "0EC675AD498AFEEBB6960B3AABE6"

# Cisco libSRTP test/srtp_driver.c, itself based on RFC 3711 Appendix B material.
LIBSRTP_PLAIN_RTP = bytes.fromhex(
    "800f1234decafbadcafebabe" "abababababababababababababababab"
)
LIBSRTP_SRTP = bytes.fromhex(
    "800f1234decafbadcafebabe"
    "4e55dc4ce79978d88ca4d215949d2402"
    "b78d6acc99ea179b8dbb"
)
LIBSRTP_SRTP_MKI = bytes.fromhex(
    "800f1234decafbadcafebabe"
    "4e55dc4ce79978d88ca4d215949d2402"
    "e1f97a0d"
    "b78d6acc99ea179b8dbb"
)
LIBSRTP_SRTCP = bytes.fromhex(
    "81c8000bcafebabe"
    "7128035be487b9bdbef89041f977a5a8"
    "80000001"
    "993e08cd54d6c1230798"
)


def test_rfc3711_key_derivation_vector():
    derived = engine.derive_srtp_keys(MASTER_KEY, MASTER_SALT)
    assert derived == {
        "kind": "SRTP",
        "encryption_key_hex": "c61e7a93744f39ee10734afe3ff7a087",
        "authentication_key_hex": "cebe321f6ff7716b6fd4ab49af256a156d38baa4",
        "salting_key_hex": "30cbbc08863d8c85d49db34a9ae1",
    }


def test_rfc4568_inline_context_vector():
    context = engine.parse_srtp_context(
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 "
        "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4"
    )
    assert context == {
        "profile": "AES_CM_128_HMAC_SHA1_80",
        "master_key_hex": "774466766726542b2978473740666235",
        "master_salt_hex": "6a552c5261417d5c7c7030252a23",
        "lifetime_packets": 1048576,
        "mki_hex": "00000001",
        "mki_length": 4,
    }


def test_libsrtp_full_packet_decrypt_and_mki_boundary():
    plain = engine.decrypt_srtp(
        LIBSRTP_SRTP, master_key=MASTER_KEY, master_salt=MASTER_SALT
    )
    assert plain["plaintext_packet_hex"] == LIBSRTP_PLAIN_RTP.hex()
    assert plain["payload_hex"] == "ab" * 16
    assert plain["authentication_verified"] is True
    assert plain["packet_index"] == 0x1234

    with_mki = engine.decrypt_srtp(
        LIBSRTP_SRTP_MKI,
        master_key=MASTER_KEY,
        master_salt=MASTER_SALT,
        mki_length=4,
        expected_mki="e1f97a0d",
    )
    assert with_mki["plaintext_packet_hex"] == LIBSRTP_PLAIN_RTP.hex()
    assert with_mki["mki_hex"] == "e1f97a0d"


def test_libsrtp_srtcp_vector():
    result = engine.decrypt_srtcp(
        LIBSRTP_SRTCP, master_key=MASTER_KEY, master_salt=MASTER_SALT
    )
    assert result["index"] == 1
    assert result["encrypted"] is True
    assert result["payload_hex"] == "ab" * 16
    assert result["plaintext_packet_hex"] == (
        "81c8000bcafebabe" + "ab" * 16
    )


@pytest.mark.parametrize("packet,entrypoint", [
    (LIBSRTP_SRTP, engine.decrypt_srtp),
    (LIBSRTP_SRTCP, engine.decrypt_srtcp),
])
def test_srtp_authentication_fails_closed_on_bit_flip(packet, entrypoint):
    corrupted = bytearray(packet)
    corrupted[-1] ^= 1
    with pytest.raises(engine.Telecom3Error, match="authentication failed"):
        entrypoint(bytes(corrupted), master_key=MASTER_KEY, master_salt=MASTER_SALT)


RFC7616 = {
    "method": "GET",
    "uri": "/dir/index.html",
    "username": "Mufasa",
    "realm": "http-auth@example.org",
    "password": "Circle of Life",
    "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    "nc": "00000001",
    "cnonce": "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
    "qop": "auth",
}


@pytest.mark.parametrize("algorithm,expected", [
    ("MD5", "8ca523f5e9506fed4657c9700eebdbec"),
    ("SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"),
])
def test_rfc7616_digest_vectors(algorithm, expected):
    assert engine.compute_sip_digest(algorithm=algorithm, **RFC7616) == expected


def _reference_md5_digest(method, uri, username, realm, password, nonce, nc, cnonce):
    """Literal RFC 7616 equation, independent of the engine implementation."""
    md5 = lambda value: hashlib.md5(value.encode("utf-8")).hexdigest()  # noqa: S324
    ha1 = md5(f"{username}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    return md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")


def _register_trace():
    challenge = (
        b"SIP/2.0 401 Unauthorized\r\n"
        b"Via: SIP/2.0/UDP ua.example;branch=z9hG4bK-a\r\n"
        b"From: <sip:alice@example.org>;tag=1\r\n"
        b"To: <sip:alice@example.org>;tag=server\r\n"
        b"Call-ID: reg-1@example.org\r\n"
        b"CSeq: 1 REGISTER\r\n"
        b'WWW-Authenticate: Digest realm="example.org", nonce="n-123", '
        b'algorithm=MD5, qop="auth"\r\nContent-Length: 0\r\n\r\n'
    )
    response = _reference_md5_digest(
        "REGISTER", "sip:example.org", "alice", "example.org", "secret",
        "n-123", "00000001", "client-1",
    )
    request = (
        "REGISTER sip:example.org SIP/2.0\r\n"
        "Via: SIP/2.0/UDP ua.example;branch=z9hG4bK-b\r\n"
        "From: <sip:alice@example.org>;tag=1\r\n"
        "To: <sip:alice@example.org>\r\n"
        "Call-ID: reg-1@example.org\r\n"
        "CSeq: 2 REGISTER\r\n"
        "Contact: <sip:alice@192.0.2.10>\r\n"
        f'Authorization: Digest username="alice", realm="example.org", nonce="n-123", '
        f'uri="sip:example.org", response="{response}", algorithm=MD5, '
        'qop=auth, nc=00000001, cnonce="client-1"\r\n'
        "Content-Length: 0\r\n\r\n"
    ).encode()
    accepted = (
        b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP ua.example;branch=z9hG4bK-b\r\n"
        b"From: <sip:alice@example.org>;tag=1\r\nTo: <sip:alice@example.org>;tag=server\r\n"
        b"Call-ID: reg-1@example.org\r\nCSeq: 2 REGISTER\r\nContent-Length: 0\r\n\r\n"
    )
    return challenge, request, accepted


def test_sip_digest_verification_and_register_flow():
    challenge, request, accepted = _register_trace()
    verification = engine.verify_sip_digest(request, "secret")
    assert verification["verified"] is True
    assert verification["uri_matches_request"] is True
    assert engine.verify_sip_digest(request, "wrong")["verified"] is False

    trace = engine.analyze_sip_trace(
        [challenge, request, accepted], credentials={"alice": "secret"}
    )
    assert trace["message_count"] == 3
    assert trace["registrations"] == [{
        "message_index": 1,
        "call_id": "reg-1@example.org",
        "cseq": 2,
        "registrar_uri": "sip:example.org",
        "address_of_record": "<sip:alice@example.org>",
        "contact": "<sip:alice@192.0.2.10>",
        "challenged": True,
        "authenticated": True,
        "digest_verified": True,
        "final_status": 200,
        "accepted": True,
    }]


def test_rfc3428_message_body_and_flow_vector():
    request = (
        b"MESSAGE sip:user2@domain.com SIP/2.0\r\n"
        b"Via: SIP/2.0/TCP pc33.domain.com;branch=z9hG4bK776asdhds\r\n"
        b"Max-Forwards: 70\r\nTo: sip:user2@domain.com\r\n"
        b"From: sip:user1@domain.com;tag=49583\r\n"
        b"Call-ID: asd88asd77a@1.2.3.4\r\nCSeq: 1 MESSAGE\r\n"
        b"Content-Type: text/plain\r\nContent-Length: 18\r\n\r\n"
        b"Watson, come here."
    )
    response = (
        b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP pc33.domain.com;branch=z9hG4bK776asdhds\r\n"
        b"To: sip:user2@domain.com;tag=2\r\nFrom: sip:user1@domain.com;tag=49583\r\n"
        b"Call-ID: asd88asd77a@1.2.3.4\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"
    )
    parsed = engine.parse_sip_message(request)
    assert parsed["request_uri"] == "sip:user2@domain.com"
    assert parsed["body_text"] == "Watson, come here."
    assert parsed["body_length"] == 18
    message = engine.analyze_sip_trace([request, response])["instant_messages"][0]
    assert message["final_status"] == 200
    assert message["accepted"] is True
    assert message["delivery_confirmed"] is True


GTP_TRACE_HEX = [
    "4820003200000000010203000100080000010121436587f94700040003696d73570009008a111111110a0000015d0005004900010005",
    "4821002a1111111101020300020002001000570009008b222222220a0000025d000b004900010005020002001000",
    "4822001e22222222010204005d00120049000100055700090080aaaa0005c0000205",
    "4823000e1111111101020400020002001000",
    "485f0023111111110102050049000100055d00120049000100005700090081bbbb0006c6336406",
    "4860001d22222222010205000200020010005d000b004900010006020002001000",
    "4863000d11111111010206004900010106",
    "4864000e2222222201020600020002001000",
    "4824000d22222222010207004900010005",
    "4825000e1111111101020700020002001000",
]


def test_gtpc_pdus_against_scapy_and_session_lifecycle():
    from scapy.contrib import gtp_v2

    expected_types = [32, 33, 34, 35, 95, 96, 99, 100, 36, 37]
    pdus = [bytes.fromhex(value) for value in GTP_TRACE_HEX]
    for raw, expected_type in zip(pdus, expected_types):
        oracle = gtp_v2.GTPHeader(raw)
        assert int(oracle.gtp_type) == expected_type
        assert bytes(oracle) == raw
        decoded = engine.parse_gtpc_event(raw)
        assert decoded["message_type"] == int(oracle.gtp_type)
        assert decoded["sequence"] == int(oracle.seq)
        assert decoded["header_teid"] == int(oracle.teid)

    first = engine.parse_gtpc_event(pdus[0])
    assert first["imsi"] == "001010123456789"
    assert first["apn"] == "ims"
    assert first["bearer_ids"] == [5]
    correlated = engine.correlate_gtpc(pdus)
    assert correlated["event_count"] == 10
    assert correlated["unanswered_requests"] == 0
    assert len(correlated["transactions"]) == 5
    assert all(item["matched"] for item in correlated["transactions"])
    assert len(correlated["sessions"]) == 1
    session = correlated["sessions"][0]
    assert session["imsi"] == "001010123456789"
    assert session["apn"] == "ims"
    assert {0x11111111, 0x22222222}.issubset(session["teids"])
    assert session["state"] == "deleted"
    assert session["bearers"] == []


PFCP_HEX = {
    "establish_request": "213200630000000000000000000001000039000d0211223344556677880a0000010001001e003800020007006c000401020304006d000411121314005100042122232400030008006c00040102030400070008006d000411121314000600080051000421222324",
    "establish_response": "2133002211223344556677880000010000130001010039000d0288776655443322110a000002",
    "modify_request": "2134001e8877665544332211000002000009000e003800020007006c000401020304",
    "modify_response": "213500111122334455667788000002000013000101",
    "delete_request": "2136000c887766554433221100000300",
    "delete_response": "213700111122334455667788000003000013000101",
}


def test_pfcp_published_layout_against_scapy_and_rule_state():
    from scapy.contrib import pfcp

    pdus = [bytes.fromhex(value) for value in PFCP_HEX.values()]
    expected_types = [50, 51, 52, 53, 54, 55]
    for raw, expected_type in zip(pdus, expected_types):
        oracle = pfcp.PFCP(raw)
        assert int(oracle.message_type) == expected_type
        assert bytes(oracle) == raw
        decoded = engine.parse_pfcp(raw)
        assert decoded["message_type"] == int(oracle.message_type)
        assert decoded["sequence"] == int(oracle.seq)
        assert decoded["seid"] == int(oracle.seid)

    request = engine.parse_pfcp(pdus[0])
    assert request["fseids"] == [{
        "seid": 0x1122334455667788, "ipv4": "10.0.0.1"
    }]
    assert request["rule_ids"] == {
        "pdr_ids": [7], "far_ids": [0x01020304],
        "qer_ids": [0x11121314], "urr_ids": [0x21222324], "bar_ids": [],
    }
    trace = engine.correlate_pfcp(pdus)
    assert trace["event_count"] == 6
    assert trace["unanswered_requests"] == 0
    assert len(trace["transactions"]) == 3
    assert len(trace["sessions"]) == 1
    session = trace["sessions"][0]
    assert session["seids"] == [0x1122334455667788, 0x8877665544332211]
    assert session["state"] == "deleted"
    assert session["pdr_ids"] == []


def test_pfcp_non_session_heartbeat_vector():
    # TS 29.244 header + Recovery Time Stamp IE; Scapy is the independent decoder.
    from scapy.contrib import pfcp

    raw = bytes.fromhex("2001000c010203000060000412345678")
    oracle = pfcp.PFCP(raw)
    assert bytes(oracle) == raw
    result = engine.parse_pfcp(raw)
    assert result["message_type"] == 1
    assert result["session_header"] is False
    assert result["sequence"] == 0x010203
    assert result["ies"][0]["recovery_timestamp"] == 0x12345678


@pytest.mark.parametrize("entrypoint", [
    engine.parse_sip_message,
    engine.parse_gtpc_event,
    engine.parse_pfcp,
])
def test_binary_parsers_fail_closed_under_deterministic_fuzz(entrypoint):
    rng = random.Random(0x54454C45)
    corpus = [b"", b"\x00", b"\xff" * 7, b"\x00" * (engine.MAX_PACKET + 1)]
    corpus.extend(rng.randbytes(rng.randrange(0, 96)) for _ in range(80))
    for value in corpus:
        try:
            entrypoint(value)
        except engine.Telecom3Error:
            pass
        except Exception as exc:  # pragma: no cover - assertion explains contract failure
            pytest.fail(f"{entrypoint.__name__} leaked {type(exc).__name__}: {exc}")


def test_truncated_valid_pdus_and_oversized_traces_fail_closed():
    for raw, parser in [
        (bytes.fromhex(GTP_TRACE_HEX[0]), engine.parse_gtpc_event),
        (bytes.fromhex(PFCP_HEX["establish_request"]), engine.parse_pfcp),
    ]:
        for cut in range(len(raw)):
            with pytest.raises(engine.Telecom3Error):
                parser(raw[:cut])
    with pytest.raises(engine.Telecom3Error):
        engine.correlate_gtpc([bytes.fromhex(GTP_TRACE_HEX[0])] * (engine.MAX_TRACE_MESSAGES + 1))
    with pytest.raises(engine.Telecom3Error):
        engine.correlate_pfcp([bytes.fromhex(PFCP_HEX["delete_request"])] * (engine.MAX_TRACE_MESSAGES + 1))


def test_all_auxiliary_entrypoints_keep_declared_error_contract():
    calls = [
        lambda: engine.parse_srtp_context("inline:not-base64!"),
        lambda: engine.derive_srtp_keys(b"short", b"short"),
        lambda: engine.decrypt_srtp(b"", master_key=MASTER_KEY, master_salt=MASTER_SALT),
        lambda: engine.decrypt_srtcp(b"", master_key=MASTER_KEY, master_salt=MASTER_SALT),
        lambda: engine.compute_sip_digest(method=None, uri="x", username="u", realm="r", password="p", nonce="n"),
        lambda: engine.verify_sip_digest({}, "p"),
        lambda: engine.analyze_sip_trace([], credentials={}),
        lambda: engine.correlate_gtpc([{"surprise": b"x"}]),
        lambda: engine.correlate_pfcp([{"surprise": b"x"}]),
    ]
    for call in calls:
        with pytest.raises(engine.Telecom3Error):
            call()


def test_guarded_argparse_cli():
    assert engine.main([]) == 2
    assert engine.main(["not-a-command"]) == 2

