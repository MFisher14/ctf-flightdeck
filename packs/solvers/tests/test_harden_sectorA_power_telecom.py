"""Independent vectors and fail-closed checks for sector-A power/telecom readers.

The fixtures below are handwritten from the named wire specifications.  They do
not call an encoder or any helper from the engines under test:

* IEC 61850-8-1/9-2 BER APPID framing and Ethernet EtherTypes;
* IEC 62056-53/62 A-XDR, logical-name GET and wrapper framing;
* IEEE C37.118.2 frame layout and CRC-16/IBM-3740 check value;
* SMPP 3.4 Issue 1.2 common headers and UCS-2 semantics;
* RFC 2865 section 7.1 RADIUS packets and RFC 6733 Diameter AVPs;
* RFC 9260 SCTP DATA framing and the standard CRC-32C check value;
* 3GPP TS 24.501 PLMN/DNN/NAS and TS 38.413 NGAP APER framing;
* 3GPP TS 29.002 TBCD, ISDN-AddressString, and MAP USSD BER.

Every public decoding entry point is also exercised with an empty input,
deterministic random bytes, a truncated valid value, a bit flip, and an input
over its resource budget.  A return is allowed; an exception must be exactly
the module's declared error family (and never a stdlib implementation detail).
"""

from __future__ import annotations

import random
import struct

import power_c37118 as c37118
import power_dlms as dlms
import power_iec61850 as iec61850
import telecom2_aaa as aaa
import telecom2_map as map_wire
import telecom2_nas as nas
import telecom2_ngap as ngap
import telecom2_sctp as sctp
import telecom2_smpp as smpp


def _mutations(valid: bytes, oversized: bytes, seed: int):
    """The five required deterministic byte-input hardening classes."""
    rng = random.Random(seed)
    random_size = max(1, min(len(valid) or 1, 73))
    random_bytes = rng.randbytes(random_size)
    truncated = valid[:-1]
    flipped = bytearray(valid or b"\x00")
    flipped[len(flipped) // 2] ^= 0x80
    return (
        ("empty", b""),
        ("random", random_bytes),
        ("truncated", truncated),
        ("bit-flipped", bytes(flipped)),
        ("oversized", oversized),
    )


def _declared_only(call, cases, error_type):
    for label, value in cases:
        try:
            call(value)
        except error_type:
            pass
        except BaseException as exc:  # includes accidental SystemExit from library code
            raise AssertionError(
                f"{label} leaked {type(exc).__name__}, expected only {error_type.__name__}"
            ) from exc


def _ber(tag: int, value: bytes) -> bytes:
    """Minimal definite-length BER writer, independent of IEC/MAP engines."""
    if len(value) < 128:
        length = bytes((len(value),))
    else:
        encoded = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        length = bytes((0x80 | len(encoded),)) + encoded
    return bytes((tag,)) + length + value


def _appid(outer_tag: int, body: bytes, appid: int) -> bytes:
    pdu = _ber(outer_tag, body)
    return struct.pack(">HHHH", appid, len(pdu) + 8, 0, 0) + pdu


def _sv_payload() -> bytes:
    # IEC 61850-9-2: noASDU [0], seqASDU [2], ASDU SEQUENCE containing
    # svID [0], smpCnt [2], confRev [3], and seqData [7].
    asdu = (
        _ber(0x80, b"MU01")
        + _ber(0x82, b"\x12\x34")
        + _ber(0x83, b"\x00\x00\x00\x07")
        + _ber(0x87, b"\x01\x02")
    )
    return _appid(0x60, _ber(0x80, b"\x01") + _ber(0xA2, _ber(0x30, asdu)), 0x4000)


def _goose_payload() -> bytes:
    # IEC 61850-8-1 GoosePdu with DEFAULT booleans omitted and one BOOLEAN
    # Data item.  UTC time is four seconds octets, three fraction octets, quality.
    body = (
        _ber(0x80, b"IED/LLN0$GO$gcb")
        + _ber(0x81, b"\x03\xe8")
        + _ber(0x82, b"IED/LLN0$dataset")
        + _ber(0x84, bytes.fromhex("650000008000008a"))
        + _ber(0x85, b"\x01")
        + _ber(0x86, b"\x00")
        + _ber(0x88, b"\x01")
        + _ber(0x8A, b"\x01")
        + _ber(0xAB, _ber(0x83, b"\xff"))
    )
    return _appid(0x61, body, 0x1000)


def _ethernet(payload: bytes, ethertype: int) -> bytes:
    return bytes.fromhex("010ccd040001001122334455") + struct.pack(">H", ethertype) + payload


def test_iec61850_documented_sv_and_goose_vectors():
    sv = iec61850.parse_sv(_sv_payload())
    assert sv["protocol"] == "iec61850-sv"
    assert sv["appid"] == 0x4000
    assert sv["asdu_count"] == 1
    assert sv["asdus"] == [{
        "sv_id": "MU01",
        "data_hex": "0102",
        "sample_count": 0x1234,
        "conf_revision": 7,
    }]

    goose = iec61850.parse_goose(_goose_payload())
    assert goose["appid"] == 0x1000
    assert goose["fields"]["gocb_ref"] == "IED/LLN0$GO$gcb"
    assert goose["fields"]["time_allowed_to_live"] == 1000
    assert goose["all_data"][0]["value"] is True
    assert goose["timestamp_detail"]["fraction_seconds"] == 0.5

    frame = iec61850.parse_frame(_ethernet(_sv_payload(), 0x88BA))
    assert frame["ethernet"]["source"] == "00:11:22:33:44:55"
    assert frame["ethernet"]["destination"] == "01:0c:cd:04:00:01"
    assert frame["ethernet"]["ethertype"] == 0x88BA


def test_iec61850_all_public_parsers_fail_closed():
    sv, goose = _sv_payload(), _goose_payload()
    frame = _ethernet(sv, 0x88BA)
    oversized = b"X" * (iec61850.MAX_FRAME + 1)
    for seed, parser, valid in (
        (101, iec61850.parse_sv, sv),
        (102, iec61850.parse_goose, goose),
        (103, iec61850.parse_frame, frame),
    ):
        _declared_only(parser, _mutations(valid, oversized, seed), iec61850.Power61850Error)

    damaged = bytearray(frame)
    damaged[len(damaged) // 2] ^= 0x80
    batch_cases = (
        ("empty", []),
        ("random", [random.Random(104).randbytes(31)]),
        ("truncated", [frame[:-1]]),
        ("bit-flipped", [bytes(damaged)]),
        ("oversized", [frame] * (iec61850.MAX_ITEMS + 1)),
    )
    _declared_only(iec61850.analyze_frames, batch_cases, iec61850.Power61850Error)


def _dlms_apdu() -> bytes:
    # IEC 62056 logical-name GET.request normal: invoke-id 0xc1, class 1,
    # OBIS 1-0:1.8.0*255, attribute 2, no selective access.
    return bytes.fromhex("c001c100010100010800ff0200")


def _dlms_wrapper(apdu: bytes | None = None) -> bytes:
    apdu = _dlms_apdu() if apdu is None else apdu
    return struct.pack(">HHHH", 1, 1, 16, len(apdu)) + apdu


def test_dlms_documented_axdr_apdu_wrapper_vectors():
    obis = dlms.parse_obis(bytes.fromhex("0100010800ff"))
    assert obis == {
        "groups": [1, 0, 1, 8, 0, 255],
        "canonical": "1-0:1.8.0*255",
        "dotted": "1.0.1.8.0.255",
        "name": "active energy import, total",
    }

    # A-XDR Structure(2): long-unsigned 0x1234, visible-string "OK".
    axdr = bytes.fromhex("02021212340a024f4b")
    decoded = dlms.parse_axdr(axdr)
    assert decoded["type"] == "structure"
    assert [(v["type"], v["value"]) for v in decoded["value"]] == [
        ("long-unsigned", 0x1234), ("visible-string", "OK")]

    request = dlms.parse_apdu(_dlms_apdu())
    assert request["service"] == "get-request"
    assert request["subtype"] == 1
    assert request["descriptor"]["class_id"] == 1
    assert request["descriptor"]["attribute_id"] == 2
    assert request["descriptor"]["obis"]["canonical"] == "1-0:1.8.0*255"

    wrapper = dlms.parse_wrapper(_dlms_wrapper())
    assert (wrapper["version"], wrapper["source_wport"], wrapper["destination_wport"]) == (1, 1, 16)
    assert wrapper["apdu"]["service"] == "get-request"
    assert len(dlms.parse_wrapper_stream(_dlms_wrapper() * 2)) == 2


def test_dlms_all_public_parsers_fail_closed():
    oversized = b"X" * (dlms.MAX_INPUT + 1)
    vectors = (
        (201, dlms.parse_obis, bytes.fromhex("0100010800ff")),
        (202, dlms.parse_axdr, bytes.fromhex("02021212340a024f4b")),
        (203, dlms.parse_apdu, _dlms_apdu()),
        (204, dlms.parse_wrapper, _dlms_wrapper()),
        (205, dlms.parse_wrapper_stream, _dlms_wrapper()),
    )
    for seed, parser, valid in vectors:
        _declared_only(parser, _mutations(valid, oversized, seed), dlms.PowerDLMSError)


def _crc16_reference(data: bytes) -> int:
    # Bit-at-a-time CRC-16/IBM-3740 reference, independent of the table/code under test.
    value = 0xFFFF
    for octet in data:
        value ^= octet << 8
        for _ in range(8):
            value = ((value << 1) ^ (0x1021 if value & 0x8000 else 0)) & 0xFFFF
    return value


def _c37118_command() -> bytes:
    # IEEE C37.118.2 command frame: version 2, IDCODE 0x1234, START_DATA (2).
    without_crc = (
        bytes.fromhex("aa42")
        + (18).to_bytes(2, "big")
        + bytes.fromhex("1234")
        + (0x65000000).to_bytes(4, "big")
        + (0x00800000).to_bytes(4, "big")
        + b"\x00\x02"
    )
    return without_crc + _crc16_reference(without_crc).to_bytes(2, "big")


def test_c37118_published_crc_check_and_command_vector():
    # CRC catalogue check value for CRC-16/IBM-3740 (aka CCITT-FALSE).
    assert c37118.crc16(b"123456789") == 0x29B1
    frame = c37118.parse_frame(_c37118_command())
    assert frame["protocol"] == "ieee-c37.118"
    assert frame["frame_type"] == "command"
    assert frame["version"] == 2
    assert frame["idcode"] == 0x1234
    assert frame["fraction"] == 0x800000
    assert frame["command"] == 2
    assert frame["command_name"] == "start_data"
    assert [r["offset"] for r in c37118.parse_stream(_c37118_command() * 2)] == [0, 18]


def test_c37118_all_public_byte_entrypoints_fail_closed():
    valid = _c37118_command()
    _declared_only(
        c37118.crc16,
        _mutations(b"123456789", b"X" * (c37118.MAX_INPUT + 1), 301),
        c37118.PowerC37118Error,
    )
    _declared_only(
        c37118.parse_frame,
        _mutations(valid, b"X" * 65536, 302),
        c37118.PowerC37118Error,
    )
    _declared_only(
        c37118.parse_stream,
        _mutations(valid, b"X" * (c37118.MAX_INPUT + 1), 303),
        c37118.PowerC37118Error,
    )


def _smpp_frame(command: int, body: bytes = b"", status: int = 0, sequence: int = 7) -> bytes:
    return struct.pack("!IIII", 16 + len(body), command, status, sequence) + body


def test_smpp_published_enquire_link_and_ucs2_vectors():
    # SMPP 3.4 common header examples: zero-body enquire_link and its response.
    request = bytes.fromhex("00000010000000150000000000000007")
    response = bytes.fromhex("00000010800000150000000000000007")
    rows = smpp.parse_stream(request + response)
    assert [(r["command"], r["sequence_number"], r["offset"]) for r in rows] == [
        ("enquire_link", 7, 0), ("enquire_link_resp", 7, 16)]
    assert smpp.decode_message(bytes.fromhex("00430053004300540046007b03a9007d"), 8) == "CSCTF{Ω}"


def test_smpp_all_public_parsers_fail_closed():
    pdu = _smpp_frame(0x15)
    ucs2 = bytes.fromhex("0043005300430054")
    _declared_only(
        lambda raw: smpp.decode_message(raw, 8),
        _mutations(ucs2, b"X" * (smpp.MAX_PDU + 1), 401),
        smpp.SMPPError,
    )
    _declared_only(
        smpp.parse_pdu,
        _mutations(pdu, b"X" * (smpp.MAX_PDU + 1), 402),
        smpp.SMPPError,
    )
    _declared_only(
        smpp.parse_stream,
        _mutations(pdu, b"X" * (smpp.MAX_STREAM + 1), 403),
        smpp.SMPPError,
    )


# Verbatim RFC 2865 section 7.1 packets, shared secret ``xyzzy5461``.
_RADIUS_REQUEST = bytes.fromhex(
    "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb"
    " 98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d"
    " 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8"
    " 01 10 05 06 00 00 00 03"
)
_RADIUS_RESPONSE = bytes.fromhex(
    "02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf"
    " 9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00"
    " 0e 06 c0 a8 01 03"
)
_RADIUS_PASSWORD = bytes.fromhex("0dbe708d93d413ce3196e43f782a0aee")


def _diameter_avp(code: int, value: bytes) -> bytes:
    length = 8 + len(value)
    raw = code.to_bytes(4, "big") + b"\x40" + length.to_bytes(3, "big") + value
    return raw + bytes((-len(raw)) % 4)


def _diameter_message() -> bytes:
    avp = _diameter_avp(1, b"alice")  # RFC 6733 User-Name
    return (
        b"\x01" + (20 + len(avp)).to_bytes(3, "big")
        + b"\x80" + (257).to_bytes(3, "big")
        + (0).to_bytes(4, "big") + (1).to_bytes(4, "big") + (2).to_bytes(4, "big")
        + avp
    )


def test_aaa_rfc2865_and_rfc6733_vectors():
    request = aaa.parse_radius(_RADIUS_REQUEST, secret=b"xyzzy5461")
    assert request["code_name"] == "Access-Request"
    assert request["identifier"] == 0
    assert request["attributes"][0]["value"] == "nemo"
    assert request["attributes"][1]["plaintext_text"] == "arctangent"
    assert aaa.decrypt_user_password(
        _RADIUS_PASSWORD, b"xyzzy5461", _RADIUS_REQUEST[4:20]
    ) == b"arctangent"
    assert aaa.verify_radius_response(
        _RADIUS_RESPONSE, _RADIUS_REQUEST, b"xyzzy5461"
    ) is True

    avps = aaa.walk_diameter_avps(_diameter_message()[20:])
    assert [(a["code"], a["name"], a["value"]) for a in avps] == [(1, "User-Name", "alice")]
    diameter = aaa.parse_diameter(_diameter_message())
    assert diameter["protocol"] == "Diameter"
    assert diameter["command_code"] == 257
    assert diameter["hop_by_hop"] == 1
    assert diameter["end_to_end"] == 2


def test_aaa_all_public_parsers_fail_closed():
    secret, authenticator = b"xyzzy5461", _RADIUS_REQUEST[4:20]
    _declared_only(
        lambda raw: aaa.decrypt_user_password(raw, secret, authenticator),
        _mutations(_RADIUS_PASSWORD, b"X" * 129, 501),
        aaa.AAAError,
    )
    _declared_only(
        aaa.parse_radius,
        _mutations(_RADIUS_REQUEST, b"X" * 4097, 502),
        aaa.AAAError,
    )
    _declared_only(
        lambda raw: aaa.verify_radius_response(raw, _RADIUS_REQUEST, secret),
        _mutations(_RADIUS_RESPONSE, b"X" * 4097, 503),
        aaa.AAAError,
    )
    avp = _diameter_message()[20:]
    _declared_only(
        aaa.walk_diameter_avps,
        _mutations(avp, b"X" * (aaa.MAX_INPUT + 1), 504),
        aaa.AAAError,
    )
    _declared_only(
        aaa.parse_diameter,
        _mutations(_diameter_message(), b"X" * (aaa.MAX_INPUT + 1), 505),
        aaa.AAAError,
    )


def _crc32c_reference(data: bytes) -> int:
    # Bit-at-a-time reflected Castagnoli polynomial, independent of engine table.
    value = 0xFFFFFFFF
    for octet in data:
        value ^= octet
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def _sctp_data_packet() -> bytes:
    payload = b"NAS"
    data_body = struct.pack("!IHHI", 1, 3, 4, 60) + payload
    chunk = b"\x00\x03" + (4 + len(data_body)).to_bytes(2, "big") + data_body
    chunk += bytes((-len(chunk)) % 4)
    packet = struct.pack("!HHI", 5000, 5001, 0x11223344) + b"\x00" * 4 + chunk
    checksum = _crc32c_reference(packet)
    return packet[:8] + checksum.to_bytes(4, "little") + packet[12:]


def test_sctp_published_crc32c_and_data_vector():
    # RFC 3720 section B.4 / CRC catalogue check value for CRC-32C.
    assert sctp.crc32c(b"123456789") == 0xE3069283
    packet = sctp.parse_packet(_sctp_data_packet(), require_checksum=True)
    assert packet["source_port"] == 5000
    assert packet["destination_port"] == 5001
    assert packet["verification_tag"] == 0x11223344
    assert packet["checksum_valid"] is True
    assert packet["chunks"][0]["name"] == "DATA"
    assert packet["chunks"][0]["tsn"] == 1
    assert packet["chunks"][0]["ppid"] == 60
    assert packet["chunks"][0]["protocol_hint"] == "NGAP"
    assert packet["chunks"][0]["payload_hex"] == b"NAS".hex()
    assert sctp.reassemble([_sctp_data_packet()])[0]["payload_hex"] == b"NAS".hex()


def test_sctp_all_public_parsers_fail_closed():
    packet = _sctp_data_packet()
    oversized = b"X" * (sctp.MAX_BYTES + 1)
    _declared_only(
        sctp.crc32c,
        _mutations(b"123456789", oversized, 601),
        sctp.SCTPError,
    )
    _declared_only(
        sctp.parse_packet,
        _mutations(packet, oversized, 602),
        sctp.SCTPError,
    )
    damaged = bytearray(packet)
    damaged[len(damaged) // 2] ^= 0x80
    reassembly_cases = (
        ("empty", []),
        ("random", [random.Random(603).randbytes(32)]),
        ("truncated", [packet[:-1]]),
        ("bit-flipped", [bytes(damaged)]),
        ("oversized", [packet] * (sctp.MAX_ITEMS + 1)),
    )
    _declared_only(sctp.reassemble, reassembly_cases, sctp.SCTPError)


def test_nas_documented_plmn_dnn_identity_and_message_vectors():
    # TS 24.501 PLMN encoding: MCC 310, three-digit MNC 260.
    assert nas.decode_plmn(bytes.fromhex("130062")) == {"mcc": "310", "mnc": "260"}
    assert nas.decode_identity(b"\x00") == {
        "type": 0, "type_name": "No identity", "raw_hex": "00"}
    assert nas.decode_dnn(b"\x08internet\x03mnc\x03mcc") == "internet.mnc.mcc"

    # Plain 5GMM Identity request: EPD, security header, message type, SUCI type.
    parsed = nas.parse_nas(bytes.fromhex("7e005b01"))
    assert parsed["protocol"] == "5GMM"
    assert parsed["message_name"] == "Identity request"
    assert parsed["fields"] == {"identity_type": "SUCI"}
    assert parsed["unparsed_tail_hex"] == ""


def test_nas_all_public_decoders_fail_closed():
    oversized = b"X" * (nas.MAX_BYTES + 1)
    vectors = (
        (701, nas.decode_plmn, bytes.fromhex("130062")),
        (702, nas.decode_identity, b"\x00"),
        (703, nas.decode_dnn, b"\x08internet\x03mnc\x03mcc"),
        (704, nas.parse_nas, bytes.fromhex("7e005b01")),
    )
    for seed, parser, valid in vectors:
        _declared_only(parser, _mutations(valid, oversized, seed), nas.NASError)


def test_ngap_ts38413_empty_error_indication_aper_vector():
    # TS 38.413: initiatingMessage, procedureCode 9 ErrorIndication,
    # criticality ignore, open type containing an empty ProtocolIE-Container.
    parsed = ngap.parse_ngap(bytes.fromhex("00094003000000"))
    assert parsed["protocol"] == "NGAP"
    assert parsed["encoding"] == "aligned PER"
    assert parsed["pdu_type"] == "initiatingMessage"
    assert parsed["procedure_code"] == 9
    assert parsed["criticality"] == "ignore"
    assert parsed["message_name"] == "ErrorIndication"
    assert parsed["nas_pdus"] == []


def test_ngap_public_parser_fail_closed():
    valid = bytes.fromhex("00094003000000")
    _declared_only(
        ngap.parse_ngap,
        _mutations(valid, b"X" * (ngap.MAX_BYTES + 1), 801),
        ngap.NGAPError,
    )


def _map_ussd() -> bytes:
    # MAP processUnstructuredSS-Request: DCS 0x48 (UCS2), string "CTF".
    content = _ber(0x04, b"\x48") + _ber(0x04, bytes.fromhex("004300540046"))
    return _ber(0x30, content)


def test_map_ts29002_tbcd_isdn_and_ussd_vectors():
    assert map_wire.decode_tbcd(bytes.fromhex("2143f5")) == "12345"
    assert map_wire.decode_isdn(bytes.fromhex("912143f5")) == {
        "ton": 1, "npi": 1, "digits": "12345", "raw_hex": "912143f5"}
    parsed = map_wire.parse_map(_map_ussd(), 59)
    assert parsed["namespace"] == "MAP"
    assert parsed["operation"] == 59
    assert parsed["name"] == "processUnstructuredSS-Request"
    assert parsed["direction"] == "argument"
    assert parsed["fields"]["ussd-DataCodingScheme"] == 0x48
    assert parsed["fields"]["ussd-String_hex"] == "004300540046"
    assert parsed["fields"]["text"] == "CTF"


def test_map_all_public_decoders_fail_closed():
    _declared_only(
        map_wire.decode_tbcd,
        _mutations(bytes.fromhex("2143f5"), b"X" * 33, 901),
        map_wire.MAPError,
    )
    _declared_only(
        map_wire.decode_isdn,
        _mutations(bytes.fromhex("912143f5"), b"X" * 10, 902),
        map_wire.MAPError,
    )
    _declared_only(
        lambda raw: map_wire.parse_map(raw, 59),
        _mutations(_map_ussd(), b"X" * (map_wire.MAX_INPUT + 1), 903),
        map_wire.MAPError,
    )
