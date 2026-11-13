"""Independent ANSI C12.18/.19/.22 vectors and fail-closed probes.

Oracles:
* ANSI C12.18 Annex-H/open C12Adapter identification frame
  ``EE0000000001201310``;
* EPRI c12test's published ST0/ST1 field layouts;
* Wireshark's public ``c1222.asn`` schema and RFC 6142 port mapping;
* pyasn1's BER encoder for INTEGER and OBJECT IDENTIFIER primitives.

The test-side CRC, checksum, TLV, and fixture builders do not call engine code.
"""
from __future__ import annotations

import random

from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.type import univ
import pytest

import sec_meter_ansi_c12 as c12


PUBLISHED_IDENT_FRAME = bytes.fromhex("EE0000000001201310")
# ANSI C12.18 Annex B session trace: one-rate negotiate, 64-byte packets,
# four packets, baud index 8 (19200 baud), CRC transmitted low byte first.
PUBLISHED_NEGOTIATE_FRAME = bytes.fromhex("EE002000000561004004088A5F")
MINIMAL_C1222 = bytes.fromhex(
    "6010"              # [APPLICATION 0], 16 content bytes
    "A803020101"        # calling-AP-invocation-id = 1
    "BE0928078105"      # user-information / EXTERNAL / octet-aligned
    "8003300001"        # clear EPSEM; Full Read ST1
)


def reference_c1218_crc(data: bytes) -> int:
    """Bit-at-a-time reflected CRC-16/IBM-SDLC, independent of the engine."""
    register = 0xFFFF
    for octet in data:
        register ^= octet
        for _ in range(8):
            register = ((register >> 1) ^ 0x8408
                        if register & 1 else register >> 1)
    return register ^ 0xFFFF


def check_byte(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def c1218_frame(payload: bytes, *, control: int = 0, sequence: int = 0) -> bytes:
    header = (bytes([0xEE, 0, control, sequence]) +
              len(payload).to_bytes(2, "big") + payload)
    return header + reference_c1218_crc(header).to_bytes(2, "little")


def length_octets(length: int) -> bytes:
    assert 0 <= length <= 0xFFFFFF
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    assert 0 <= tag <= 255
    return bytes([tag]) + length_octets(len(content)) + content


def primitive_content(encoded: bytes) -> bytes:
    """Extract content from a short pyasn1 BER primitive for implicit tagging."""
    assert len(encoded) >= 2
    first = encoded[1]
    if first < 0x80:
        start, size = 2, first
    else:
        count = first & 0x7F
        start = 2 + count
        size = int.from_bytes(encoded[2:start], "big")
    assert start + size == len(encoded)
    return encoded[start:]


def epsem(*services: bytes, control: int = 0x80, ed_class: bytes = b"",
          mac: bytes = b"") -> bytes:
    return (bytes([control]) + ed_class +
            b"".join(length_octets(len(service)) + service for service in services) +
            mac)


def c1222_apdu(epsem_bytes: bytes, *, rich: bool = False) -> bytes:
    integer = ber_encode(univ.Integer(7 if rich else 1))
    fields = []
    if rich:
        context_oid = ber_encode(univ.ObjectIdentifier("2.16.124.113620.1.22"))
        fields.append(tlv(0xA1, context_oid))
        fields.append(tlv(0xA2, ber_encode(univ.ObjectIdentifier("1.3.6.1.4.1.9999"))))
        # Relative calling title 113620.9, encoded directly as base-128 arcs.
        fields.append(tlv(0xA6, tlv(0x80, bytes.fromhex("86F75409"))))
    fields.append(tlv(0xA8, integer))
    if rich:
        mechanism = primitive_content(
            ber_encode(univ.ObjectIdentifier("2.16.124.113620.1.22.2.1"))
        )
        fields.append(tlv(0x8B, mechanism))
        c1222_value = tlv(0xA1, tlv(0x80, b"\x07") +
                         tlv(0x81, bytes.fromhex("01020304")))
        single_asn1 = tlv(0xA0, c1222_value)
        authentication_sequence = tlv(0xA2, single_asn1)
        fields.append(tlv(0xAC, authentication_sequence))
    fields.append(tlv(0xBE, tlv(0x28, tlv(0x81, epsem_bytes))))
    return tlv(0x60, b"".join(fields))


def st0_fixture() -> bytes:
    # DATA_ORDER=MSB first, ASCII identifiers, access method 2.
    header = bytes([
        0x01, 0x10, 0x21,       # FORMAT_CONTROL_1..3
        0x01, 0x02, 0x03, 0x04, # DEVICE_CLASS
        2, 3, 40, 50, 12, 34,   # through STD_REVISION_NO
        2, 1, 1, 1, 1, 2,      # five dimensions, NBR_PENDING
    ])
    assert len(header) == 19
    # std used[2], mfg used[1], std proc[1], mfg proc[1],
    # std writable[2], mfg writable[1].
    return header + bytes.fromhex("0501800208040180")


def st1_fixture() -> bytes:
    return (b"LYCO" + b"DDS71   " + bytes([14, 0, 19, 18]) +
            b"0123456789012345")


def test_published_c1218_crc_frame_and_link_flags():
    assert reference_c1218_crc(PUBLISHED_IDENT_FRAME[:-2]) == 0x1013
    assert c12.crc16_c1218(PUBLISHED_IDENT_FRAME[:-2]) == 0x1013
    assert PUBLISHED_IDENT_FRAME[-2:] == (0x1013).to_bytes(2, "little")

    parsed = c12.parse_c1218_frame(PUBLISHED_IDENT_FRAME)
    assert parsed["identity"] == 0
    assert parsed["data_length"] == 1
    assert parsed["crc_valid"] is True
    assert parsed["payload"]["service"] == "identify"
    assert parsed["payload"]["command"] == 0x20
    assert c12.parse_c1218_frame(b"\x06")["frame_type"] == "ack"
    assert c12.parse_c1218_frame(b"\x15")["frame_type"] == "nak"

    # Independent frame builder around the Annex-B identify response payload.
    # (The widely mirrored scan has a known OCR/printing mismatch in its CRC.)
    ident_response = c1218_frame(bytes.fromhex("0000020000"))
    response = c12.parse_c1218_frame(
        ident_response, direction="response", request_command=0x20
    )
    assert response["payload"]["status"] == 0
    assert response["payload"]["data_hex"] == "00020000"

    assert reference_c1218_crc(PUBLISHED_NEGOTIATE_FRAME[:-2]) == 0x5F8A
    negotiated = c12.parse_c1218_frame(PUBLISHED_NEGOTIATE_FRAME)
    assert negotiated["toggle"] is True
    assert negotiated["payload"]["service"] == "negotiate"
    assert negotiated["payload"]["packet_size"] == 64
    assert negotiated["payload"]["maximum_packets"] == 4
    assert negotiated["payload"]["baud_indices"] == [8]

    fragment = c12.parse_c1218_frame(
        c1218_frame(bytes.fromhex("000096010203"), control=0xC0, sequence=2)
    )
    assert fragment["multiple_packets"] is True
    assert fragment["first_packet"] is True
    assert fragment["sequence"] == 2
    assert fragment["payload_status"] == "fragment_not_reassembled"


def test_psem_requests_table_flags_and_checksums():
    table = c12.decode_table_id(0x1807)
    assert table == {
        "raw": 0x1807, "number": 7, "manufacturer": True,
        "user_defined": False, "pending": True,
        "kind": "manufacturer", "label": "PMT7",
    }
    assert c12.decode_table_id(0x2009)["label"] == "UDT9"
    assert c12.decode_table_id(0x3009)["label"] == "PUDT9"

    full_read = c12.parse_psem_request(bytes.fromhex("300001"))
    assert full_read["service"] == "full_read"
    assert full_read["table"]["label"] == "ST1"

    partial = c12.parse_psem_request(bytes.fromhex("3f00011234560020"))
    assert partial["offset"] == 0x123456 and partial["count"] == 0x20

    payload = b"CSCTF{meter-table}"
    write = (b"\x40" + (0x1807).to_bytes(2, "big") +
             len(payload).to_bytes(2, "big") + payload + bytes([check_byte(payload)]))
    decoded = c12.parse_psem_request(write)
    assert decoded["service"] == "full_write"
    assert decoded["data_hex"] == payload.hex()
    assert decoded["checksum_valid"] is True

    partial_write = (bytes.fromhex("4f0001000102") + len(payload).to_bytes(2, "big") +
                     payload + bytes([check_byte(payload)]))
    decoded = c12.parse_psem_request(partial_write)
    assert decoded["offset"] == 0x000102
    assert decoded["table"]["label"] == "ST1"


@pytest.mark.parametrize(("wire", "service"), [
    (b"\x20", "identify"),
    (b"\x21", "terminate"),
    (b"\x22", "disconnect"),
    (b"\x3e", "default_read"),
    (b"\x52", "logoff"),
    (b"\x50\x00\x2aoperator  \x00\x3c", "logon"),
    (b"\x51" + b"secret".ljust(20, b" ") + b"\x00\x2a", "security"),
    (b"\x53\x03abc", "authenticate"),
    (b"\x62\x04\x00\x05\x06\x07", "negotiate"),
    (b"\x70\x09", "wait"),
    (b"\x71\x01\x02\x03\x04", "timing_setup"),
])
def test_documented_psem_service_layouts(wire, service):
    assert c12.parse_psem_request(wire)["service"] == service


def test_psem_read_response_checksum_and_error_gate():
    value = bytes.fromhex("4c59434f")
    wire = b"\x00" + len(value).to_bytes(2, "big") + value + bytes([check_byte(value)])
    decoded = c12.parse_psem_response(wire, 0x30)
    assert decoded["status_name"] == "ok"
    assert decoded["data_hex"] == value.hex()
    assert decoded["checksum_valid"] is True

    denied = c12.parse_psem_response(b"\x03", 0x30)
    assert denied["status_name"] == "insufficient_security_clearance"
    with pytest.raises(c12.SecMeterC12Error):
        c12.parse_psem_response(b"\x03\x00", 0x30)
    with pytest.raises(c12.SecMeterC12Error):
        c12.parse_psem_response(wire[:-1] + bytes([wire[-1] ^ 1]), 0x30)


def test_epri_c1219_st0_layout_and_dynamic_bitmaps():
    raw = st0_fixture()
    decoded = c12.parse_c1219_st0(raw)
    assert decoded["data_order"] == "most_significant_byte_first"
    assert decoded["data_access_method"] == 2
    assert decoded["standard_version"] == 12
    assert decoded["standard_revision"] == 34
    assert decoded["dimensions"] == {
        "standard_tables": 2, "manufacturer_tables": 1,
        "standard_procedures": 1, "manufacturer_procedures": 1,
        "manufacturer_status": 1,
    }
    assert decoded["bitmaps"]["standard_tables_used"]["set_indices"] == [0, 2, 8]
    assert decoded["bitmaps"]["manufacturer_tables_used"]["set_indices"] == [7]
    assert c12.parse_c1219_table(0, raw)["table_id"]["label"] == "ST0"


def test_epri_c1219_st1_string_and_bcd_layouts():
    decoded = c12.parse_c1219_st1(st1_fixture())
    assert decoded["manufacturer"] == "LYCO"
    assert decoded["model"] == "DDS71"
    assert decoded["hardware_version"] == "14.0"
    assert decoded["firmware_version"] == "19.18"
    assert decoded["serial_number"] == "0123456789012345"
    assert c12.parse_c1219_table(1, st1_fixture())["table"] == "ST1"

    bcd = b"ABCD" + b"MODEL   " + bytes([1, 2, 3, 4]) + bytes.fromhex("01234567")
    assert c12.parse_c1219_st1(bcd, id_form=True)["serial_number"] == "01234567"


def test_published_minimal_c1222_asn1_and_epsem_vector():
    # This literal is the public ASN.1 schema rendered by hand, independent of
    # the richer helper below.  pyasn1 confirms the embedded INTEGER bytes.
    assert ber_encode(univ.Integer(1)) == bytes.fromhex("020101")
    assert c1222_apdu(epsem(bytes.fromhex("300001"))) == MINIMAL_C1222

    decoded = c12.parse_c1222_apdu(MINIMAL_C1222)
    assert decoded["calling_ap_invocation_id"] == 1
    assert decoded["epsem"]["security_mode_name"] == "clear"
    assert decoded["epsem"]["integrity_applicable"] is False
    assert decoded["epsem"]["integrity_verified"] is False
    service = decoded["epsem"]["services"][0]
    assert service["length"] == 3
    assert service["psem"]["service"] == "full_read"
    assert service["psem"]["table"]["label"] == "ST1"

    direct = c12.parse_epsem(bytes.fromhex("8003300001"))
    assert direct["services"][0]["psem"]["command"] == 0x30


def test_c1222_oids_titles_auth_metadata_and_unverified_mac():
    service = bytes.fromhex("300001")
    supplied_epsem = epsem(service, control=0x84, mac=bytes.fromhex("deadbeef"))
    wire = c1222_apdu(supplied_epsem, rich=True)
    decoded = c12.parse_c1222_apdu(wire)

    assert decoded["application_context_oid"] == "2.16.124.113620.1.22"
    assert decoded["known_application_context"] is True
    assert decoded["called_ap_title"] == {
        "form": "absolute", "oid": "1.3.6.1.4.1.9999"
    }
    assert decoded["calling_ap_title"] == {
        "form": "relative", "oid": "113620.9"
    }
    assert decoded["mechanism_name_oid"] == "2.16.124.113620.1.22.2.1"
    assert decoded["authentication"]["key_id"] == 7
    assert decoded["authentication"]["iv_hex"] == "01020304"
    assert decoded["epsem"]["mac_hex"] == "deadbeef"
    assert decoded["epsem"]["integrity_verified"] is False
    assert decoded["epsem"]["services"][0]["psem"]["service"] == "full_read"


def test_epsem_ed_class_and_encrypted_payload_remain_opaque():
    clear = epsem(bytes.fromhex("20"), control=0x90, ed_class=b"MTR1")
    decoded = c12.parse_epsem(clear)
    assert decoded["ed_class"] == "MTR1"
    assert decoded["ed_class_hex"] == "4d545231"
    assert decoded["services"][0]["psem"]["service"] == "identify"

    # ANSI C12.19 ST0 DEVICE_CLASS is binary.  This published-layout-style
    # value must not be rejected or decoded with replacement characters.
    binary_class = epsem(bytes.fromhex("20"), control=0x90,
                         ed_class=bytes.fromhex("c27b0300"))
    decoded = c12.parse_epsem(binary_class)
    assert decoded["ed_class_hex"] == "c27b0300"
    assert "ed_class" not in decoded
    assert decoded["services"][0]["psem"]["service"] == "identify"

    # In encrypted mode, ED class and services are both encrypted.  Bit 4
    # therefore describes plaintext metadata but does not expose four bytes.
    encrypted = b"\x98" + bytes.fromhex("010203040506") + bytes.fromhex("aabbccdd")
    decoded = c12.parse_epsem(encrypted)
    assert decoded["security_mode_name"] == "encrypted_authenticated"
    assert decoded["ciphertext_hex"] == "010203040506"
    assert decoded["mac_hex"] == "aabbccdd"
    assert decoded["services"] == []
    assert decoded["plaintext_available"] is False
    assert decoded["integrity_verified"] is False
    assert decoded["ed_class_encrypted"] is True
    assert "ed_class" not in decoded


def test_rfc6142_native_port_1153_classification_and_analyze_dispatch():
    classified = c12.classify_c1222_payload(
        MINIMAL_C1222, transport="udp", source_port=49152, destination_port=1153
    )
    assert classified["is_c1222"] is True
    assert classified["apdu"]["protocol"] == "c12.22"

    negative = c12.classify_c1222_payload(
        b"not c12", transport="tcp", source_port=40000, destination_port=443
    )
    assert negative["is_c1222"] is False
    assert c12.analyze(MINIMAL_C1222)["protocol"] == "c12.22"
    assert c12.analyze(PUBLISHED_IDENT_FRAME)["protocol"] == "c12.18"
    assert c12.analyze(st1_fixture(), kind="table", table_id=1)["table"] == "ST1"


@pytest.mark.parametrize("bad", [
    bytes.fromhex("6080100000"),       # indefinite length
    bytes.fromhex("608110"),           # non-minimal long length
    bytes.fromhex("6010A803020101BE092807810580033000"),  # truncated service
])
def test_noncanonical_or_truncated_ber_is_rejected(bad):
    with pytest.raises(c12.SecMeterC12Error):
        c12.parse_c1222_apdu(bad)


def test_exact_prefix_truncation_and_integrity_failures():
    vectors = [
        (c12.parse_c1218_frame, PUBLISHED_IDENT_FRAME),
        (c12.parse_psem_request,
         b"\x40\x00\x01\x00\x03abc" + bytes([check_byte(b"abc")])),
        (c12.parse_c1219_st0, st0_fixture()),
        (c12.parse_c1219_st1, st1_fixture()),
        (c12.parse_epsem, bytes.fromhex("8003300001")),
        (c12.parse_c1222_apdu, MINIMAL_C1222),
    ]
    for parser, valid in vectors:
        for cut in range(len(valid)):
            with pytest.raises(c12.SecMeterC12Error):
                parser(valid[:cut])

    for index in range(len(PUBLISHED_IDENT_FRAME)):
        changed = bytearray(PUBLISHED_IDENT_FRAME)
        changed[index] ^= 1
        with pytest.raises(c12.SecMeterC12Error):
            c12.parse_c1218_frame(changed)


def assert_declared_only(call):
    try:
        call()
    except c12.SecMeterC12Error:
        pass
    except Exception as exc:  # pragma: no cover - the assertion reports a leak
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_all_public_parsers_fail_closed_under_deterministic_fuzz():
    rng = random.Random(0xC1218)
    malformed = [b"", b"\xff" * 64, b"%PDF", b"PK\x03\x04", b"\xee", b"\x60"]
    malformed += [rng.randbytes(size) for size in range(1, 80)]
    malformed += [memoryview(b"\xff" * size) for size in (1, 7, 31)]

    for value in malformed:
        assert_declared_only(lambda value=value: c12.crc16_c1218(value))
        assert_declared_only(lambda value=value: c12.parse_c1218_frame(value))
        assert_declared_only(lambda value=value: c12.parse_psem_request(value))
        assert_declared_only(lambda value=value: c12.parse_psem_response(value, 0x30))
        assert_declared_only(lambda value=value: c12.parse_c1219_st0(value))
        assert_declared_only(lambda value=value: c12.parse_c1219_st1(value))
        assert_declared_only(lambda value=value: c12.parse_c1219_table(0, value))
        assert_declared_only(lambda value=value: c12.parse_epsem(value))
        assert_declared_only(lambda value=value: c12.parse_c1222_apdu(value))
        assert_declared_only(lambda value=value: c12.classify_c1222_payload(
            value, transport="tcp", source_port=1153, destination_port=50000))
        assert_declared_only(lambda value=value: c12.analyze(value, kind="c1222"))


@pytest.mark.parametrize("value", [None, 3, "bytes", object()])
def test_wrong_input_types_raise_only_declared_error(value):
    calls = [
        lambda: c12.crc16_c1218(value),
        lambda: c12.parse_c1218_frame(value),
        lambda: c12.parse_psem_request(value),
        lambda: c12.parse_psem_response(value, 0x30),
        lambda: c12.parse_c1219_st0(value),
        lambda: c12.parse_c1219_st1(value),
        lambda: c12.parse_c1219_table(0, value),
        lambda: c12.parse_epsem(value),
        lambda: c12.parse_c1222_apdu(value),
        lambda: c12.classify_c1222_payload(
            value, transport="udp", source_port=40000, destination_port=1153),
        lambda: c12.analyze(value),
    ]
    for call in calls:
        with pytest.raises(c12.SecMeterC12Error):
            call()


def test_released_memoryview_is_normalized_to_declared_error():
    view = memoryview(PUBLISHED_IDENT_FRAME)
    view.release()
    for parser in (c12.crc16_c1218, c12.parse_c1218_frame,
                   c12.parse_psem_request, c12.parse_epsem,
                   c12.parse_c1222_apdu, c12.analyze):
        with pytest.raises(c12.SecMeterC12Error):
            parser(view)


def test_cli_guard_and_vector_output(tmp_path, capsys):
    assert c12.main(["--help"]) == 0
    assert c12.main(["--definitely-invalid"]) == 2
    assert c12.main([
        "--hex", "--format", "c1218", PUBLISHED_IDENT_FRAME.hex()
    ]) == 0
    output = capsys.readouterr().out
    assert '"service": "identify"' in output

    path = tmp_path / "c1222.bin"
    path.write_bytes(MINIMAL_C1222)
    assert c12.main(["--format", "c1222", str(path)]) == 0
    output = capsys.readouterr().out
    assert '"protocol": "c12.22"' in output

    assert c12.main(["--hex", "--format", "c1222", "not-hex"]) == 2
