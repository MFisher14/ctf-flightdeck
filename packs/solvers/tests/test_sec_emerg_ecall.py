"""Independent oracles for the passive EU/EAEU eCall decoder.

The three immutable examples are published EN/UNECE interoperability values.
The remaining fixtures are written by this test-only bit writer from the ASN.1
field layout; they do not call an encoder or any implementation helper.
"""

from __future__ import annotations

import json

import pytest

import sec_emerg_ecall as ecall


PUBLISHED_V1 = bytes.fromhex(
    "015C0681D54970D65C3597CA0420C41464583ADE68AC52E9BB8413F149C07414"
    "FB414F6010180813E82181823230"
)
PUBLISHED_V2 = bytes.fromhex(
    "02251C0680E30A51439E2955D43800800437F80A3105669023F8A71166932185"
    "B004150043C040"
)
PUBLISHED_V3 = bytes.fromhex(
    "0324101A01C614A2873C52ABA870010010089AF166285C59A4C86408FE29C16C"
    "01054010F010"
)

VIN_ALPHABET = "0123456789ABCDEFGHJKLMNPRSTUVWXYZ"


class BitWriter:
    """Tiny independent MSB-first writer used only to construct oracle bytes."""

    def __init__(self):
        self.bits = []

    def put(self, value, width):
        assert isinstance(value, int) and not isinstance(value, bool)
        assert width >= 0 and 0 <= value < (1 << width)
        self.bits.extend((value >> shift) & 1 for shift in range(width - 1, -1, -1))

    def boolean(self, value):
        self.put(1 if value else 0, 1)

    def octets(self, value):
        for octet in value:
            self.put(octet, 8)

    def length(self, value):
        assert 0 <= value < 16384
        if value < 128:
            self.put(value, 8)
        else:
            self.put(0x8000 | value, 16)

    def finish(self):
        bit_length = len(self.bits)
        padded = self.bits + [0] * ((-bit_length) % 8)
        encoded = bytes(
            sum(padded[offset + index] << (7 - index) for index in range(8))
            for offset in range(0, len(padded), 8)
        )
        return encoded, bit_length


def relative_oid(*arcs):
    result = bytearray()
    for arc in arcs:
        assert arc >= 0
        groups = [arc & 0x7F]
        arc >>= 7
        while arc:
            groups.append(0x80 | (arc & 0x7F))
            arc >>= 7
        result.extend(reversed(groups))
    return bytes(result)


def encode_era(
    version,
    *,
    severity=None,
    diagnostic=(),
    crash=(),
    coordinate_present=False,
    coordinate=0,
):
    """Encode the documented GOST ERAAdditionalData root alternatives."""

    writer = BitWriter()
    writer.boolean(False)  # extensible SEQUENCE: root
    writer.boolean(severity is not None)
    writer.boolean(bool(diagnostic))
    writer.boolean(bool(crash))
    if version == 2:
        writer.boolean(coordinate_present)
    if severity is not None:
        writer.put(severity, 11)
    if diagnostic:
        values = dict(diagnostic)
        for index in range(21):
            writer.boolean(index in values)
        for index in range(21):
            if index in values:
                writer.boolean(values[index])
    if crash:
        values = dict(crash)
        for index in range(8):
            writer.boolean(index in values)
        for index in range(8):
            if index in values:
                writer.boolean(values[index])
    if version == 2 and coordinate_present:
        writer.put(coordinate, 1)
    return writer.finish()[0]


def encode_inner(
    version,
    *,
    identifier=7,
    automatic=True,
    test=False,
    trusted=True,
    vehicle=0,
    vin="ECALLEXAMPLE02020",
    propulsion=None,
    timestamp=1_700_000_000,
    latitude=187_996_428,
    longitude=18_859_320,
    direction=45,
    n1=(0, 10),
    n2=(0, 30),
    occupants=2,
    additional=None,
):
    """Construct one MSDMessage root using the published UPER constraints."""

    assert version in (1, 2, 3)
    if propulsion is None:
        propulsion = [(True, True)] + [(False, False)] * (5 if version == 1 else 6)
    count = 6 if version == 1 else 7
    assert len(propulsion) == count
    writer = BitWriter()
    writer.boolean(False)  # MSDMessage extension
    writer.boolean(additional is not None)
    writer.boolean(False)  # MSDStructure extension
    if version == 3:
        writer.boolean(occupants is not None)
    else:
        writer.boolean(n1 is not None)
        writer.boolean(n2 is not None)
        writer.boolean(occupants is not None)
    writer.put(identifier, 8)
    writer.boolean(automatic)
    writer.boolean(test)
    writer.boolean(trusted)
    writer.boolean(False)  # vehicle ENUMERATED extension
    writer.put(vehicle, 5 if version == 3 else 4)
    assert len(vin) == 17
    for char in vin:
        writer.put(VIN_ALPHABET.index(char), 6)
    writer.boolean(False)  # propulsion SEQUENCE extension
    for present, _value in propulsion:
        writer.boolean(present)
    for present, value in propulsion:
        if present:
            writer.boolean(value)
    writer.put(timestamp, 32)
    writer.put(latitude + (1 << 31), 32)
    writer.put(longitude + (1 << 31), 32)
    writer.put(direction, 8)
    if n1 is not None:
        writer.put(n1[0] + 512, 10)
        writer.put(n1[1] + 512, 10)
    if n2 is not None:
        writer.put(n2[0] + 512, 10)
        writer.put(n2[1] + 512, 10)
    if occupants is not None:
        writer.put(occupants, 8)
    if additional is not None:
        oid_arcs, value = additional
        oid = relative_oid(*oid_arcs)
        writer.length(len(oid))
        writer.octets(oid)
        writer.length(len(value))
        writer.octets(value)
    return writer.finish()


def wrap_msd(version, inner):
    if version == 1:
        return bytes([1]) + inner
    if len(inner) < 128:
        determinant = bytes([len(inner)])
    else:
        determinant = bytes([0x80 | (len(inner) >> 8), len(inner) & 0xFF])
    return bytes([version]) + determinant + inner


def multipart_sip(msd, *, automatic=True, duplicate=False, service_urn=None):
    boundary = "ecall-boundary-42"
    cid = "msd-1@example.test"
    part = (
        b"--" + boundary.encode() + b"\r\n"
        b"Content-Type: application/EmergencyCallData.eCall.MSD\r\n"
        b"Content-ID: <" + cid.encode() + b">\r\n"
        b"Content-Disposition: by-reference; handling=optional\r\n"
        b"Content-Transfer-Encoding: binary\r\n\r\n"
        + msd
        + b"\r\n"
    )
    body = part + (part if duplicate else b"") + b"--" + boundary.encode() + b"--\r\n"
    mode = "automatic" if automatic else "manual"
    service_urn = service_urn or f"urn:service:sos.ecall.{mode}"
    headers = (
        f"INVITE {service_urn} SIP/2.0\r\n"
        "Via: SIP/2.0/TCP ue.example.test;branch=z9hG4bK-1\r\n"
        "From: <sip:vehicle@example.test>;tag=a\r\n"
        "To: <urn:service:sos.ecall>\r\n"
        "Call-ID: oracle-call@example.test\r\n"
        "CSeq: 1 INVITE\r\n"
        f"Call-Info: <cid:{cid}>;purpose=EmergencyCallData.eCall.MSD\r\n"
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii")
    return headers + body


def test_published_en15722_v1_vector():
    report = ecall.decode_msd(PUBLISHED_V1)
    decoded = report["decoded"]
    assert report["version"] == 1
    assert report["version_status"] == "withdrawn_legacy"
    assert decoded["message_identifier"] == 1
    assert decoded["vin"]["value"] == "WM9VDSVDSYA123456"
    assert decoded["control"]["automatic_activation"] is True
    assert decoded["propulsion"]["active"] == ["gasoline", "electric"]
    assert decoded["timestamp"]["unix_seconds"] == 123_456_789
    assert decoded["vehicle_location"]["latitude_milliarcseconds"] == 173_881_200
    assert decoded["vehicle_location"]["longitude_milliarcseconds"] == 41_822_520
    assert decoded["vehicle_direction"]["raw"] == 14
    assert decoded["recent_vehicle_location_n1"]["latitude_units"] == 10
    assert decoded["recent_vehicle_location_n2"]["longitude_units"] == -20
    assert decoded["occupants"] == {"value": 2, "status": "present"}
    assert decoded["optional_additional_data"]["relative_oid"] == "1.2.125"
    assert decoded["optional_additional_data"]["data_hex"] == "30304646"


def test_published_en15722_v2_vector_and_default_bits():
    report = ecall.decode_msd(PUBLISHED_V2)
    decoded = report["decoded"]
    assert report["version"] == 2
    assert decoded["vin"]["value"] == "ECALLEXAMPLE02013"
    assert decoded["timestamp"]["utc"] == "2013-05-06T22:14:12Z"
    assert decoded["vehicle_direction"]["degrees"] == 90
    assert decoded["occupant_field_name"] == "numberOfPassengers"
    assert all(decoded["propulsion"]["present_on_wire"].values())
    assert decoded["propulsion"]["flags"]["diesel"] is False


def test_published_en15722_v3_vector_and_mandatory_deltas():
    report = ecall.decode_msd(PUBLISHED_V3)
    decoded = report["decoded"]
    assert report["version"] == 3
    assert decoded["vin"]["value"] == "ECALLEXAMPLE02020"
    assert decoded["occupant_field_name"] == "numberOfOccupants"
    assert decoded["recent_vehicle_location_n1"] == {
        "latitude_units": 0,
        "longitude_units": 10,
        "unit_milliarcseconds": 100,
    }
    assert decoded["recent_vehicle_location_n2"]["longitude_units"] == 30
    # N2 is relative to N1: longitude gains 40 units in total.
    current = decoded["vehicle_location"]["longitude_degrees"]
    assert decoded["recent_positions"]["n2"]["longitude_degrees"] == pytest.approx(
        current + 40 / 36_000
    )


def test_v3_23_value_vehicle_root_and_sentinels():
    inner, _ = encode_inner(
        3,
        identifier=0,
        vehicle=22,
        timestamp=0,
        latitude=0,
        longitude=0,
        direction=255,
        n1=(-512, 511),
        n2=(511, -512),
        occupants=255,
    )
    decoded = ecall.decode_msd(wrap_msd(3, inner))["decoded"]
    assert decoded["control"]["vehicle_type"] == "other"
    assert decoded["timestamp"]["status"] == "unavailable"
    assert decoded["vehicle_location"]["status"] == "unavailable"
    assert decoded["vehicle_direction"]["status"] == "unavailable"
    assert decoded["occupants"]["status"] == "unavailable"
    assert "message_identifier_zero_profile_specific" in decoded["issues"]


def test_v2_optional_fields_and_explicit_false_default():
    propulsion = [(True, False), (False, False), (True, True)] + [(False, False)] * 4
    inner, _ = encode_inner(
        2,
        propulsion=propulsion,
        n1=None,
        n2=None,
        occupants=None,
        direction=200,
    )
    decoded = ecall.decode_msd(wrap_msd(2, inner))["decoded"]
    assert decoded["propulsion"]["present_on_wire"]["gasoline"] is True
    assert decoded["propulsion"]["flags"]["gasoline"] is False
    assert decoded["propulsion"]["active"] == ["compressed_natural_gas"]
    assert decoded["recent_vehicle_location_n1"] is None
    assert decoded["recent_vehicle_location_n2"] is None
    assert decoded["occupants"]["status"] == "absent"
    assert decoded["vehicle_direction"]["status"] == "reserved_invalid"


def test_two_octet_containing_length_and_multioctet_oid_arc():
    chosen = None
    for size in range(70, 110):
        inner, _ = encode_inner(3, additional=((2, 16_384, 3), bytes(range(size))))
        if 128 <= len(inner) <= 137:
            chosen = inner
            break
    assert chosen is not None
    wire = wrap_msd(3, chosen)
    assert wire[1] & 0x80 and wire[2] == len(chosen)
    report = ecall.decode_msd(wire)
    additional = report["decoded"]["optional_additional_data"]
    assert additional["relative_oid"] == "2.16384.3"
    assert additional["length"] == size


def test_recovered_140_byte_modem_payload_preserves_zero_data():
    inner, _ = encode_inner(1, additional=((2, 4, 999), b"\x00\x00"))
    wire = wrap_msd(1, inner)
    recovered = wire + bytes(140 - len(wire))
    report = ecall.decode_msd(recovered)
    assert report["transport"]["kind"] == "recovered_in_band_modem_payload"
    assert report["transport"]["contained_msd_octets"] == len(inner)
    assert report["transport"]["trailing_zero_padding_octets"] == 139 - len(inner)
    assert report["decoded"]["optional_additional_data"]["data_hex"] == "0000"
    corrupt = bytearray(recovered)
    corrupt[-1] = 1
    with pytest.raises(ecall.ECallError):
        ecall.decode_msd(corrupt)


def test_v2_v3_contained_length_ignores_140_byte_transport_tail():
    for version in (2, 3):
        inner, _ = encode_inner(version)
        wire = wrap_msd(version, inner)
        tail = bytes((index * 37 + 9) & 0xFF for index in range(140 - len(wire)))
        recovered = wire + tail
        report = ecall.decode_msd(recovered)
        assert report["decoded"]["vin"]["value"] == "ECALLEXAMPLE02020"
        assert report["transport"]["trailing_transport_octets"] == len(tail)
        assert report["transport"]["trailing_transport_hex"] == tail.hex()
        assert report["transport"]["trailing_zero_padding_octets"] == 0


def test_era_v1_v2_oid_selection_and_wire_presence():
    era2 = encode_era(
        2,
        severity=321,
        diagnostic=((0, True), (1, False)),
        crash=((4, True),),
        coordinate_present=True,
        coordinate=1,
    )
    direct = ecall.decode_era_additional(era2, 2)
    assert direct["crash_severity_asi15_x100"] == 321
    assert direct["diagnostic_result"]["asserted"] == ["mic_connection_failure"]
    assert direct["diagnostic_result"]["values"]["mic_failure"] is False
    assert direct["crash_info"]["asserted"] == ["rollover"]
    assert direct["coordinate_system"] == "pz90"
    inner, _ = encode_inner(3, additional=((1, 4, 2), era2))
    report = ecall.decode_msd(wrap_msd(3, inner))
    assert report["profile"] == "era-glonass"
    assert report["decoded"]["optional_additional_data"]["era_glonass"] == direct

    era1 = encode_era(1, severity=2047)
    decoded1 = ecall.decode_era_additional(era1, 1)
    assert decoded1["crash_severity_status"] == "sentinel_or_high"
    assert decoded1["coordinate_system"] is None


def test_era_default_coordinate_and_recognized_malformed_is_fatal():
    era2 = encode_era(2)
    assert ecall.decode_era_additional(era2, 2)["coordinate_system"] == "wgs84"
    inner, _ = encode_inner(2, additional=((1, 4, 2), b""))
    with pytest.raises(ecall.ECallError):
        ecall.decode_msd(wrap_msd(2, inner))
    with pytest.raises(ecall.ECallError):
        ecall.decode_era_additional(era2, True)


def test_unknown_additional_profile_remains_opaque():
    inner, _ = encode_inner(3, additional=((9, 99), b"opaque\x00"))
    extra = ecall.decode_msd(wrap_msd(3, inner))["decoded"]["optional_additional_data"]
    assert extra == {
        "relative_oid": "9.99",
        "data_hex": "6f706171756500",
        "length": 7,
        "recognized_profile": None,
    }


def test_ng_ecall_rfc8147_multipart_and_cid_resolution():
    report = ecall.parse_ng_ecall_sip(multipart_sip(PUBLISHED_V3))
    assert report["protocol"] == "NG eCall over IMS"
    assert report["method"] == "INVITE"
    assert report["activation_from_service_urn"] == "automatic"
    assert report["issues"] == []
    assert report["call_info"][0]["resolved_content_id"] == "msd-1@example.test"
    part = report["parts"][0]
    assert part["media_type"] == "application/emergencycalldata.ecall.msd"
    assert part["decoded"]["decoded"]["vin"]["value"] == "ECALLEXAMPLE02020"
    assert part["activation_from_msd"] == "automatic"


def test_cid_url_percent_decoding_is_case_exact():
    encoded = multipart_sip(PUBLISHED_V3).replace(
        b"cid:msd-1@example.test", b"cid:msd-1%40example.test", 1
    )
    report = ecall.parse_ng_ecall_sip(encoded)
    assert report["issues"] == []
    assert report["call_info"][0]["resolved_content_id"] == "msd-1@example.test"

    wrong_case = multipart_sip(PUBLISHED_V3).replace(
        b"cid:msd-1@example.test", b"cid:MSD-1@example.test", 1
    )
    report = ecall.parse_ng_ecall_sip(wrong_case)
    assert "call_info_cid_unresolved" in report["issues"]
    assert "msd_part_call_info_reference_count_not_one" in report["issues"]

    malformed = multipart_sip(PUBLISHED_V3).replace(
        b"cid:msd-1@example.test", b"cid:msd-1%ZZexample.test", 1
    )
    with pytest.raises(ecall.ECallError):
        ecall.parse_ng_ecall_sip(malformed)


def test_ng_ecall_activation_mismatch_is_reported_not_overwritten():
    report = ecall.parse_ng_ecall_sip(multipart_sip(PUBLISHED_V3, automatic=False))
    assert report["activation_from_service_urn"] == "manual"
    assert report["parts"][0]["activation_from_msd"] == "automatic"
    assert "service_urn_msd_activation_mismatch" in report["issues"]


def test_ng_ecall_test_urn_mismatch_is_reported():
    report = ecall.parse_ng_ecall_sip(
        multipart_sip(PUBLISHED_V3, service_urn="urn:service:test.sos.ecall")
    )
    assert report["test_call_from_service_urn"] is True
    assert report["parts"][0]["test_call_from_msd"] is False
    assert "service_urn_msd_test_mismatch" in report["issues"]


def test_ng_ecall_info_control_xml():
    body = (
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"><request action="send-data" '
        b'datatype="eCall.MSD"/>'
        b'</EmergencyCallData.Control>'
    )
    boundary = b"control-boundary"
    cid = b"control-1@example.test"
    mime = (
        b"--" + boundary + b"\r\n"
        b"Content-Disposition: by-reference\r\n"
        b"Content-Type: application/EmergencyCallData.Control+xml\r\n"
        b"Content-ID: <" + cid + b">\r\n\r\n"
        + body
        + b"\r\n--" + boundary + b"--\r\n"
    )
    wire = (
        b"INFO sip:psap@example.test SIP/2.0\r\n"
        b"Call-ID: oracle-call@example.test\r\n"
        b"CSeq: 2 INFO\r\n"
        b"Call-Info: <cid:" + cid + b">;purpose=EmergencyCallData.Control\r\n"
        b"Info-Package: EmergencyCallData.eCall.MSD\r\n"
        b"Content-Disposition: Info-Package\r\n"
        b"Content-Type: multipart/mixed; boundary=control-boundary\r\n"
        + f"Content-Length: {len(mime)}\r\n\r\n".encode()
        + mime
    )
    report = ecall.parse_ng_ecall_sip(wire)
    assert report["method"] == "INFO"
    assert report["info_packages"] == ["EmergencyCallData.eCall.MSD"]
    assert report["issues"] == []
    assert report["call_info"][0]["resolved_content_id"] == cid.decode()
    assert report["parts"][0]["kind"] == "ecall_control"
    assert report["parts"][0]["decoded"]["event"] == "request"
    assert report["parts"][0]["decoded"]["events"][0]["element"] == "request"


def test_info_allows_multiple_control_parts_and_request_line_is_exact():
    boundary = b"two-controls"
    controls = (
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"><request action="send-data" '
        b'datatype="eCall.MSD"/></EmergencyCallData.Control>',
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"><ack ref="msd@example" received="true"/>'
        b'</EmergencyCallData.Control>',
    )
    mime = bytearray()
    call_info = bytearray()
    for index, control in enumerate(controls, 1):
        cid = f"control-{index}@example.test".encode()
        mime += (b"--" + boundary + b"\r\nContent-Disposition: by-reference\r\n"
                 b"Content-Type: application/EmergencyCallData.Control+xml\r\n"
                 b"Content-ID: <" + cid + b">\r\n\r\n" + control + b"\r\n")
        call_info += (b"Call-Info: <cid:" + cid
                      + b">;purpose=EmergencyCallData.Control\r\n")
    mime += b"--" + boundary + b"--\r\n"
    wire = (b"INFO sip:psap@example.test SIP/2.0\r\n" + call_info
            + b"Info-Package: EmergencyCallData.eCall.MSD\r\n"
              b"Content-Disposition: Info-Package\r\n"
              b"Content-Type: multipart/mixed; boundary=two-controls\r\n"
            + f"Content-Length: {len(mime)}\r\n\r\n".encode() + bytes(mime))
    report = ecall.parse_ng_ecall_sip(wire)
    assert len([part for part in report["parts"] if part["kind"] == "ecall_control"]) == 2
    assert "multiple_control_parts" not in report["issues"]

    malformed = wire.replace(
        b"INFO sip:psap@example.test SIP/2.0",
        b"INFO sip:psap@example.test ignored SIP/2.0",
        1,
    )
    with pytest.raises(ecall.ECallError):
        ecall.parse_ng_ecall_sip(malformed)


def test_msd_requires_binary_content_transfer_encoding_finding():
    wire = multipart_sip(PUBLISHED_V3).replace(
        b"Content-Transfer-Encoding: binary\r\n", b"", 1
    )
    head, body = wire.split(b"\r\n\r\n", 1)
    head = b"\r\n".join(
        b"Content-Length: " + str(len(body)).encode()
        if line.startswith(b"Content-Length:") else line
        for line in head.split(b"\r\n")
    )
    report = ecall.parse_ng_ecall_sip(head + b"\r\n\r\n" + body)
    assert "msd_part_transfer_encoding_not_binary" in report["issues"]


def test_control_xml_required_event_and_attributes():
    def direct(xml):
        return (
            b"INFO sip:p@example.test SIP/2.0\r\n"
            b"Info-Package: EmergencyCallData.eCall.MSD\r\n"
            b"Content-Type: application/EmergencyCallData.Control+xml\r\n"
            + f"Content-Length: {len(xml)}\r\n\r\n".encode()
            + xml
        )

    empty = (
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"/>'
    )
    missing_action = (
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"><request datatype="eCall.MSD"/>'
        b'</EmergencyCallData.Control>'
    )
    missing_ref = (
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"><ack received="true"/>'
        b'</EmergencyCallData.Control>'
    )
    for malformed in (empty, missing_action, missing_ref):
        with pytest.raises(ecall.ECallError):
            ecall.parse_ng_ecall_sip(direct(malformed))


def test_rfc8147_nonmultipart_control_is_extracted_but_flagged():
    xml = (
        b'<EmergencyCallData.Control xmlns="urn:ietf:params:xml:ns:'
        b'EmergencyCallData:control"><ack ref="msd@example" received="true"/>'
        b'</EmergencyCallData.Control>'
    )
    wire = (
        b"SIP/2.0 200 OK\r\n"
        b"Content-Type: application/EmergencyCallData.Control+xml\r\n"
        + f"Content-Length: {len(xml)}\r\n\r\n".encode()
        + xml
    )
    report = ecall.parse_ng_ecall_sip(wire)
    assert report["parts"][0]["decoded"]["event"] == "ack"
    assert "ecall_data_not_multipart" in report["issues"]
    assert "control_part_missing_content_id" in report["issues"]
    assert "control_part_call_info_reference_count_not_one" in report["issues"]
    assert "control_part_not_by_reference" in report["issues"]


def test_sip_rejects_content_length_duplicate_cid_and_xml_entities():
    valid = multipart_sip(PUBLISHED_V3)
    length_line = (
        f"Content-Length: {len(valid.split(b'\r\n\r\n', 1)[1])}\r\n".encode()
    )
    altered = valid.replace(
        f"Content-Length: {len(valid.split(b'\r\n\r\n', 1)[1])}".encode(),
        b"Content-Length: 1",
        1,
    )
    with pytest.raises(ecall.ECallError):
        ecall.parse_ng_ecall_sip(altered)
    with pytest.raises(ecall.ECallError):
        ecall.parse_ng_ecall_sip(valid.replace(length_line, length_line + length_line, 1))
    with pytest.raises(ecall.ECallError):
        ecall.parse_ng_ecall_sip(multipart_sip(PUBLISHED_V3, duplicate=True))

    xml = b'<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>'
    wire = (
        b"INFO sip:p@example.test SIP/2.0\r\n"
        b"Content-Type: application/EmergencyCallData.Control+xml\r\n"
        + f"Content-Length: {len(xml)}\r\n\r\n".encode()
        + xml
    )
    with pytest.raises(ecall.ECallError):
        ecall.parse_ng_ecall_sip(wire)


def test_malformed_uper_bounds_extensions_lengths_and_padding():
    for vector in (PUBLISHED_V1, PUBLISHED_V2, PUBLISHED_V3):
        for size in range(len(vector)):
            with pytest.raises(ecall.ECallError):
                ecall.decode_msd(vector[:size])

    # Declared inner length exceeds the bytes supplied.
    with pytest.raises(ecall.ECallError):
        ecall.decode_msd(bytes([2, len(PUBLISHED_V2)]) + PUBLISHED_V2[2:])
    # The MSDMessage extension marker is unsupported and must fail closed.
    inner, _ = encode_inner(3)
    extended = bytes([inner[0] | 0x80]) + inner[1:]
    with pytest.raises(ecall.ECallError):
        ecall.decode_msd(wrap_msd(3, extended))
    # Flip an otherwise-unused terminal padding bit.
    inner, used = encode_inner(2, n1=None, n2=None, occupants=None)
    assert used % 8
    bad_padding = inner[:-1] + bytes([inner[-1] | 1])
    with pytest.raises(ecall.ECallError):
        ecall.decode_msd(wrap_msd(2, bad_padding))


@pytest.mark.parametrize(
    "operation",
    [
        lambda: ecall.decode_msd(None),
        lambda: ecall.decode_msd("\ud800"),
        lambda: ecall.decode_msd(b""),
        lambda: ecall.decode_msd(b"\x04"),
        lambda: ecall.decode_era_additional(None, 1),
        lambda: ecall.decode_era_additional(b"\x00", None),
        lambda: ecall.parse_ng_ecall_sip(None),
        lambda: ecall.parse_ng_ecall_sip("\ud800"),
        lambda: ecall.parse_ng_ecall_sip(b"INVITE \xff"),
        lambda: ecall.analyze(None),
        lambda: ecall.analyze(b"x", kind="\ud800"),
    ],
)
def test_public_apis_have_one_declared_exception(operation):
    with pytest.raises(ecall.ECallError):
        operation()


def test_cli_guard_and_json(tmp_path, capsys):
    assert ecall.main([]) == 2
    assert ecall.main(42) == 2
    assert ecall.main(["msd", "\ud800"]) == 2
    path = tmp_path / "msd.bin"
    path.write_bytes(PUBLISHED_V3)
    assert ecall.main(["msd", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["decoded"]["vin"]["value"] == "ECALLEXAMPLE02020"

