"""Independent vector and fail-closed tests for :mod:`sec_bas_knx`.

Wire locks are external to the engine:

* Calimero captures: https://github.com/calimero-project/calimero-core/issues/34
  and https://github.com/calimero-project/calimero-server/issues/21
* knxd capture: https://github.com/knxd/knxd/issues/515
* KNXnet/IP secure layouts: ISO 22510:2019 public preview
* CoAP/OSCORE: RFC 7252 and RFC 8613, hand-packed below
* DPT values: documented KNX field formulae, with ``struct`` as the independent
  IEEE-754 oracle for DPT 14.

No fixture is emitted by the engine under test.
"""

from __future__ import annotations

import json
import random
import struct

import pytest

import sec_bas_knx as knx


CALIMERO_TUNNEL = bytes.fromhex(
    "06 10 04 20 00 17 04 26 a8 00 "
    "11 00 bc 60 10 ff 11 0b 03 42 02 40 03"
)
CALIMERO_GROUP_WRITE = bytes.fromhex(
    "06 10 04 20 00 15 04 01 02 00 "
    "11 00 bc e0 66 d3 31 01 01 00 80"
)
CALIMERO_ROUTING_GROUP_WRITE = bytes.fromhex(
    "06 10 05 30 00 11 29 00 bc e0 66 d3 31 01 01 00 80"
)
KNXD_ROUTING = bytes.fromhex(
    "06 10 05 30 00 15 29 00 bc d0 11 10 f5 01 05 00 80 45 14 b0 00"
)


def _knxip(service: int, body: bytes) -> bytes:
    """Hand-apply the documented six-byte KNXnet/IP envelope."""

    size = 6 + len(body)
    return b"\x06\x10" + service.to_bytes(2, "big") + size.to_bytes(2, "big") + body


def _closed(call) -> None:
    """A malformed case may decode, or fail with only the declared exception."""

    try:
        call()
    except knx.SecBasKNXError:
        return


def test_calimero_tunnelling_request_published_capture() -> None:
    got = knx.parse_knxnetip(CALIMERO_TUNNEL)
    assert got["service_type"] == 0x0420
    assert got["service"] == "TUNNELLING_REQUEST"
    assert got["total_length"] == 23
    assert got["connection"] == {
        "structure_length": 4,
        "channel_id": 0x26,
        "sequence_counter": 0xA8,
        "reserved": 0,
    }
    cemi = got["cemi"]
    assert cemi["message"] == "L_Data.req"
    assert cemi["source"] == {"raw": 0x10FF, "individual": "1.0.255"}
    assert cemi["destination"] == {"raw": 0x110B, "individual": "1.1.11"}
    assert cemi["control2"]["destination_type"] == "individual"
    assert cemi["control2"]["hop_count"] == 6
    assert cemi["npdu_length"] == 3
    assert cemi["tpdu_hex"] == "42024003"


def test_calimero_group_write_and_explicit_dpt() -> None:
    got = knx.parse_knxnetip(CALIMERO_GROUP_WRITE, dpt="1")
    assert got["connection"]["channel_id"] == 1
    assert got["connection"]["sequence_counter"] == 2
    cemi = got["cemi"]
    assert cemi["source"]["individual"] == "6.6.211"
    assert cemi["destination"]["raw"] == 0x3101
    assert cemi["destination"]["three_level"] == "6/1/1"
    assert cemi["destination"]["two_level"] == "6/257"
    assert cemi["apci"]["service"] == "GroupValueWrite"
    assert cemi["apci"]["short_data"] == 0
    assert cemi["dpt"]["type"] == "boolean"
    assert cemi["dpt"]["value"] is False


def test_calimero_routing_indication_published_capture() -> None:
    got = knx.parse_knxnetip(CALIMERO_ROUTING_GROUP_WRITE)
    assert got["service_type"] == 0x0530
    assert got["cemi"]["message"] == "L_Data.ind"
    assert got["cemi"]["source"]["individual"] == "6.6.211"
    assert got["cemi"]["destination"]["three_level"] == "6/1/1"
    assert got["cemi"]["apci"]["service"] == "GroupValueWrite"


def test_knxd_routing_indication_published_capture() -> None:
    got = knx.parse_knxnetip(KNXD_ROUTING)
    cemi = got["cemi"]
    assert cemi["source"]["individual"] == "1.1.16"
    assert cemi["destination"]["raw"] == 0xF501
    assert cemi["destination"]["three_level"] == "30/5/1"
    assert cemi["control2"]["hop_count"] == 5
    assert cemi["apci"]["service"] == "GroupValueWrite"
    assert cemi["apci"]["extended_data_hex"] == "4514b000"


def test_common_dpt_documented_semantics() -> None:
    assert knx.decode_dpt(b"\x01", "DPT 1")["value"] is True
    assert knx.decode_dpt(b"\x03", "2")["control"] is True
    assert knx.decode_dpt(b"\x0d", "3") == {
        "dpt": "3", "raw_hex": "0d", "type": "control-step", "control": True, "step": 5,
    }
    dpt5 = knx.decode_dpt(b"\xff", "5.001")
    assert dpt5["dpt"] == "5.001" and dpt5["value"] == pytest.approx(100.0)
    assert knx.decode_dpt(b"\x80", "6")["value"] == -128
    assert knx.decode_dpt(b"\x12\x34", "7")["value"] == 0x1234
    assert knx.decode_dpt(b"\xff\xff", "8")["value"] == -1

    # KNX two-octet float: 0.01 * 2000 * 2**0 = 20.00.
    dpt9 = knx.decode_dpt(bytes.fromhex("07d0"), "9")
    assert dpt9["mantissa"] == 2000 and dpt9["exponent"] == 0
    assert dpt9["value"] == pytest.approx(20.0)
    assert knx.decode_dpt(bytes.fromhex("8000"), "9")["value"] == pytest.approx(-20.48)
    assert knx.decode_dpt(bytes.fromhex("7fff"), "9")["invalid"] is True

    time = knx.decode_dpt(bytes((1 << 5 | 14, 30, 45)), "10")
    assert (time["weekday"], time["value"]) == (1, "14:30:45")
    date = knx.decode_dpt(bytes((31, 12, 25)), "11")
    assert date["value"] == "2025-12-31"
    assert knx.decode_dpt(bytes.fromhex("ffffffff"), "12")["value"] == 0xFFFFFFFF
    assert knx.decode_dpt(bytes.fromhex("ffffffff"), "13")["value"] == -1
    assert knx.decode_dpt(struct.pack(">f", 12.5), "14")["value"] == pytest.approx(12.5)
    assert knx.decode_dpt(b"KNX\0" + b"\0" * 10, "16.000")["value"] == "KNX"
    assert knx.decode_dpt(b"\x3f", "17")["value"] == 63
    assert knx.decode_dpt(b"\x85", "18") == {
        "dpt": "18", "raw_hex": "85", "type": "scene-control", "control": True, "scene": 5,
    }
    assert knx.decode_dpt(b"\xfe", "20")["value"] == 254
    assert knx.decode_dpt(bytes((1, 2, 3)), "232") == {
        "dpt": "232", "raw_hex": "010203", "type": "rgb", "red": 1, "green": 2, "blue": 3,
    }


def test_data_secure_structure_is_not_claimed_decrypted() -> None:
    # APCISec 0x3f1, SCF 0x10, SeqNr=1, two protected octets, four-octet MAC.
    tpdu = bytes.fromhex("03 f1 10 00 00 00 00 00 01 aa bb 11 22 33 44")
    cemi = (
        bytes.fromhex("29 00 bc e0 11 01 31 01")
        + bytes((len(tpdu) - 1,))
        + tpdu
    )
    got = knx.parse_cemi(cemi)
    assert got["apci"]["raw"] == 0x3F1
    assert got["apci"]["service"] == "SecureService"
    secure = got["data_secure"]
    assert secure["algorithm"] == "aes-ccm-authentication-confidentiality"
    assert secure["sequence_number"] == 1
    assert secure["protected_data_hex"] == "aabb"
    assert secure["mac_hex"] == "11223344"
    assert secure["authenticated"] is None and secure["decrypted"] is False


def test_ip_secure_wrapper_documented_layout() -> None:
    body = (
        bytes.fromhex("0002")
        + (9).to_bytes(6, "big")
        + bytes.fromhex("001122334455")
        + b"\x00\x00"
        + bytes.fromhex("061005300011")
        + bytes(range(16))
    )
    got = knx.parse_knxnetip(_knxip(0x0950, body))
    secure = got["secure"]
    assert secure["session_id"] == 2
    assert secure["mode"] == "secure-session-unicast"
    assert secure["sequence_information"] == 9
    assert secure["serial_number_hex"] == "001122334455"
    assert secure["encrypted_inner_hex"] == "061005300011"
    assert secure["encrypted_mac_hex"] == bytes(range(16)).hex()
    assert secure["authenticated"] is None and secure["decrypted"] is False


def test_ip_secure_session_message_layouts() -> None:
    # Host protocol code 2 is TCP; zero host/port requests route-back.
    request = _knxip(0x0951, bytes.fromhex("0802000000000000") + bytes(range(32)))
    got = knx.parse_knxnetip(request)["secure"]
    assert got["hpai"]["route_back"] is True
    assert got["client_public_key_hex"] == bytes(range(32)).hex()

    response = _knxip(0x0952, b"\x12\x34" + bytes(range(32)) + bytes(range(16)))
    got = knx.parse_knxnetip(response)["secure"]
    assert got["session_id"] == 0x1234
    assert got["server_public_key_hex"] == bytes(range(32)).hex()

    authenticate = _knxip(0x0953, b"\x00\x02" + bytes(range(16)))
    got = knx.parse_knxnetip(authenticate)["secure"]
    assert got["user_id"] == 2 and got["user_class"] == "user"

    status = knx.parse_knxnetip(_knxip(0x0954, b"\x04\x00"))["secure"]
    assert status["status_name"] == "keepalive"

    timer_body = (123).to_bytes(6, "big") + bytes.fromhex("aabbccddeeff") + b"\x00\x07" + bytes(16)
    timer = knx.parse_knxnetip(_knxip(0x0955, timer_body))["secure"]
    assert timer["timer"] == 123 and timer["message_tag"] == 7


def test_rfc7252_rfc8613_knx_iot_oscore_fixture() -> None:
    # CON POST, token aabb. Option 9 OSCORE = flags(kid + one-byte PIV),
    # Partial IV 01, kid 7a. URI path is /.well-known/knx/ia.
    datagram = (
        bytes.fromhex("42 02 12 34 aa bb")
        + bytes.fromhex("93 09 01 7a")
        + b"\x2b.well-known"
        + b"\x03knx"
        + b"\x02ia"
        + bytes.fromhex("ff deadbeef")
    )
    got = knx.parse_coap(datagram)
    assert got["type"] == "CON" and got["code_text"] == "0.02"
    assert got["message_id"] == 0x1234 and got["token_hex"] == "aabb"
    assert got["uri_path"] == "/.well-known/knx/ia"
    assert got["knx_iot_candidate"] is True
    assert got["payload_hex"] == "deadbeef"
    assert got["oscore"] == {
        "flags": 9, "partial_iv_hex": "01", "kid_context_hex": None, "kid_hex": "7a",
    }
    assert got["encrypted"] is True and got["decrypted"] is False


def test_rfc8613_oscore_kid_context_layout() -> None:
    # h=1, k=1, n=1; PIV 01; context length 2/aabb; remaining byte is kid cc.
    got = knx.parse_oscore_option(bytes.fromhex("19 01 02 aa bb cc"))
    assert got == {
        "flags": 0x19,
        "partial_iv_hex": "01",
        "kid_context_hex": "aabb",
        "kid_hex": "cc",
    }


def test_plaintext_point_api_cbor_delegates_existing_decoder() -> None:
    # ACK 2.05, Uri-Path p/1, Content-Format 60 (application/cbor), then the
    # hand-canonical CBOR map {5:{1:true,6:"w",7:1}} from Point API semantics.
    cbor = bytes.fromhex("a1 05 a3 01 f5 06 61 77 07 01")
    datagram = bytes.fromhex("60 45 00 01") + b"\xb1p\x011\x11\x3c\xff" + cbor
    got = knx.parse_coap(datagram)
    assert got["uri_path"] == "/p/1"
    assert got["knx_iot_candidate"] is True
    assert got["cbor"] == {"5": {"1": True, "6": "w", "7": 1}}


def test_analyze_auto_and_explicit_modes() -> None:
    assert knx.analyze(CALIMERO_TUNNEL)["protocol"] == "knxnet-ip"
    assert knx.analyze(CALIMERO_ROUTING_GROUP_WRITE[6:])["protocol"] == "knx-cemi"
    assert knx.analyze(bytes.fromhex("40 01 00 01"))["protocol"] == "coap"
    assert knx.analyze(bytes.fromhex("07d0"), format="dpt", dpt="9")["value"] == 20.0


@pytest.mark.parametrize("value", [None, 0, 1.5, "bytes", object(), [1, 2]])
def test_wrong_input_types_fail_with_declared_error(value: object) -> None:
    calls = (
        lambda: knx.parse_knxnetip(value),
        lambda: knx.parse_cemi(value),
        lambda: knx.parse_coap(value),
        lambda: knx.parse_oscore_option(value),
        lambda: knx.decode_dpt(value, "1"),
        lambda: knx.analyze(value),
    )
    for call in calls:
        with pytest.raises(knx.SecBasKNXError):
            call()


def test_all_public_parsers_fail_closed_on_empty_random_and_oversized() -> None:
    rng = random.Random(0x4B4E58)
    parsers = (
        knx.parse_knxnetip,
        knx.parse_cemi,
        knx.parse_coap,
        knx.parse_oscore_option,
        knx.analyze,
    )
    corpus = [b"", b"\x00", b"\xff" * 64]
    corpus.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 257))) for _ in range(128))
    corpus.append(b"\x00" * (knx.MAX_INPUT + 1))
    for parser in parsers:
        for blob in corpus:
            _closed(lambda parser=parser, blob=blob: parser(blob))

    for dpt in ("1", "9", "10", "11", "14", "232", "bad", "9.1.2"):
        for blob in corpus[:40] + [b"\x00" * 1025]:
            _closed(lambda dpt=dpt, blob=blob: knx.decode_dpt(blob, dpt))


@pytest.mark.parametrize(
    "parser,valid",
    [
        (knx.parse_knxnetip, CALIMERO_TUNNEL),
        (knx.parse_knxnetip, KNXD_ROUTING),
        (knx.parse_cemi, CALIMERO_GROUP_WRITE[10:]),
        (knx.parse_coap, bytes.fromhex("40 01 12 34")),
        (knx.parse_oscore_option, bytes.fromhex("19 01 02 aa bb cc")),
        (knx.analyze, CALIMERO_TUNNEL),
        (lambda raw: knx.decode_dpt(raw, "9"), bytes.fromhex("07 d0")),
    ],
)
def test_truncated_and_bit_flipped_valid_inputs_never_leak(parser, valid: bytes) -> None:
    for end in range(len(valid)):
        _closed(lambda end=end: parser(valid[:end]))
    for index in range(len(valid)):
        mutated = bytearray(valid)
        mutated[index] ^= 1 << (index & 7)
        _closed(lambda mutated=bytes(mutated): parser(mutated))


def test_malformed_lengths_and_reserved_bits_are_rejected() -> None:
    bad_total = bytearray(CALIMERO_TUNNEL)
    bad_total[5] -= 1
    with pytest.raises(knx.SecBasKNXError):
        knx.parse_knxnetip(bytes(bad_total))

    bad_cemi = bytearray(CALIMERO_GROUP_WRITE[10:])
    bad_cemi[8] += 1
    with pytest.raises(knx.SecBasKNXError):
        knx.parse_cemi(bytes(bad_cemi))

    with pytest.raises(knx.SecBasKNXError):
        knx.parse_coap(bytes.fromhex("40 01 00 01 ff"))
    with pytest.raises(knx.SecBasKNXError):
        knx.parse_oscore_option(bytes.fromhex("e0"))
    with pytest.raises(knx.SecBasKNXError):
        knx.decode_dpt(bytes.fromhex("7f"), "1")
    with pytest.raises(knx.SecBasKNXError, match="reserved DPT 11 year"):
        knx.decode_dpt(bytes.fromhex("01 01 64"), "11")

    group_read = bytearray(CALIMERO_GROUP_WRITE[10:])
    group_read[-1] = 0x00
    with pytest.raises(knx.SecBasKNXError, match="carries no datapoint value"):
        knx.parse_cemi(bytes(group_read), dpt="1")

    # CoAP integer options are minimally encoded; code classes 1/6/7 are reserved.
    with pytest.raises(knx.SecBasKNXError, match="non-minimal"):
        knx.parse_coap(bytes.fromhex("40 01 00 01 c1 00"))
    with pytest.raises(knx.SecBasKNXError, match="reserved CoAP code class"):
        knx.parse_coap(bytes.fromhex("40 20 00 01"))

    # A secure session request must advertise TCP route-back, not a live endpoint.
    non_route_back = _knxip(
        0x0951, bytes.fromhex("08027f0000010e57") + bytes(range(32))
    )
    with pytest.raises(knx.SecBasKNXError, match="route-back"):
        knx.parse_knxnetip(non_route_back)


def test_guarded_cli_success_and_usage_error(tmp_path, capsys) -> None:
    path = tmp_path / "calimero.bin"
    path.write_bytes(CALIMERO_TUNNEL)
    assert knx.main(["knxnetip", str(path)]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["service"] == "TUNNELLING_REQUEST"

    assert knx.main([]) == 2
    captured = capsys.readouterr()
    assert "usage:" in captured.err.lower()

