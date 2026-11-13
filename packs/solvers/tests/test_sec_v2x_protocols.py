"""Independent vectors for the passive EU/US V2X decoders.

The GeoNetworking/BTP fixtures are packed directly from ETSI EN 302 636-4-1
V1.4.1, clauses 9.5--9.8, and EN 302 636-5-1 V2.2.1, clause 7.  The WSMP
fixtures follow IEEE 1609.3's version-3 header and IEEE 1609.12 p-encoding as
implemented by Wireshark's independent ``packet-wsmp.c`` dissector.

The BSM/SPaT vectors and their decoded values are published by USDOT/FHWA at
https://github.com/usdot-fhwa-stol/j2735decoder (develop commit
98a13583ebdebe3c6861236ac851b3377d33df22, ``Sample Data``).  The legacy CAM
literal was independently encoded with asn1tools from ETSI's tagged
V1.4.1/V1.3.1 ASN.1 modules; the current CAM prefix came from V2XFlexStack's
asn1tools coder; and the COER bytes are IEEE's published module vector.  SRM
and SSM are USDOT JPO ODE receiver fixtures under
``jpo-ode-svcs/src/test/resources/us/dot/its/jpo/ode/udp/{srm,ssm}``.
"""

from __future__ import annotations

from copy import deepcopy
import random
import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import sec_v2x_etsi as etsi
import sec_v2x_j2735 as j2735

# The USDOT/FHWA generated pycrate schema (github usdot-fhwa-stol/j2735decoder) is not on PyPI and
# is built from git by hand (docs/build-log/SH-01.md). Without it every J2735 decode raises
# V2XJ2735Error, so the tests that decode real J2735 vectors report NOT RUN instead of failing.
NEEDS_J2735 = pytest.mark.needs_tool("py:j2735_202409")

USDOT_BSM_1 = bytes.fromhex(
    "001425067c0eb5842562e66e8a2b9ea6c96408b97fffffff900027d9637d07d"
    "0007fff8000640fa0"
)
USDOT_SPAT_1 = bytes.fromhex(
    "00131900100b5a81000021a6100007047f8000001400140014780000"
)
USDOT_SRM = bytes.fromhex(
    "001d2130000010090bd341080d00855c6c0c6899853000a534f7c24cb2989769"
    "4759b7c0"
)
USDOT_SSM = bytes.fromhex("001e120000000005e9c04071a26614c06000040ba0")
USDOT_BSM_UNAVAILABLE = bytes.fromhex(
    "001425067c0eb5842562f5a4e900eb49d20008b97fffffff9ffff080637d07d"
    "0007fff8000640fa0"
)
MINIMAL_TIM_FRAME = bytes.fromhex(
    "001f1a00700042468000f600f1800000000082a94f8311043993e9c588"
)
V2XFLEXSTACK_CAM_V2 = bytes.fromhex(
    "0202000000000000000d693a403ad274803ffffffc23b7743e00e11fdffffebf"
    "e9ed0737feebfff600"
)


def _cam_oracle() -> bytes:
    """Literal from asn1tools + official CAM V1.4.1/CDD V1.3.1 ASN.1."""
    return bytes.fromhex(
        "01020000000000010006b49d214d693a41400200200030d4000000000000000000"
        "02840bff01fff800"
    )


def _coer_oracle() -> bytes:
    """Published IEEE module-documentation unsecured COER example."""
    return bytes.fromhex("03 80 08 01 23 45 67 89 ab cd ef")


def _j2735_message_frame_oracle(
    message_id: int, choice: str, fields: dict[str, Any], expected_hex: str,
) -> bytes:
    """Encode a MessageFrame with USDOT's generated pycrate schema package."""
    import j2735_202409

    oracle = deepcopy(j2735_202409.MessageFrame.MessageFrame)
    oracle.set_val({"messageId": message_id, "value": (choice, fields)})
    encoded = oracle.to_uper()
    # A literal lock makes accidental fixture/schema drift visible.
    assert encoded.hex() == expected_hex
    return encoded


def _shb_cam_frame(cam: bytes) -> bytes:
    """Build Basic + Common + SHB Extended + BTP-B + CAM by documented layout."""
    btp = struct.pack(">HH", 2001, 0) + cam
    # Version 1, Basic NH=Common; LT multiplier 10/base 50 ms; RHL 1.
    basic = bytes((0x11, 0x00, (10 << 2) | 0, 0x01))
    # Common NH=BTP-B, HT/HST=SHB/0, TC=2, flags=0, PL, MHL=1.
    common = struct.pack(">BBBBHBB", 0x20, 0x50, 0x02, 0, len(btp), 1, 0)
    # GN address: manual=0, station type=5, 10 reserved bits=0, six-byte MID.
    gn_address = b"\x14\x00\x02\x00\x00\x00\x00\x01"
    # TST; latitude/longitude in 1e-7 degrees; PAI + 12.34 m/s; 90 degrees.
    position = struct.pack(
        ">8sIiiHH", gn_address, 0x01020304, 481234567, 112345678,
        0x8000 | 1234, 900,
    )
    assert len(position) == 24
    return basic + common + position + struct.pack(">I", 0x01020304) + btp


def _release2_single_hop_frame(header_type: int = 7) -> bytes:
    """Build TS 103 836-4-3 SHU/SHG with version-1 C-V2X media data."""
    assert header_type in (7, 8)
    facilities = bytes.fromhex("020411223344deadbeef")
    btp = struct.pack(">HH", 2004, 0) + facilities
    basic = bytes((0x11, 0x00, (10 << 2) | 0, 0x01))
    # BTP-B, HT/HST=SHU/0, TC ID 3 -> Release-2 PPPP 4.
    common = struct.pack(">BBBBHBB", 0x20, header_type << 4, 0x03, 0, len(btp), 1, 0)
    position = struct.pack(
        ">8sIiiHH", bytes.fromhex("1400020000000001"), 0x01020304,
        481234567, 112345678, 0x8000 | 1234, 900,
    )
    # Media version 1, CTC 5 (<0.5 us with 95% confidence), 24 reserved zero bits.
    return basic + common + position + bytes.fromhex("15000000") + btp


def _nested_values(value: Any, key: str) -> Iterator[Any]:
    if isinstance(value, dict):
        for name, child in value.items():
            if name == key:
                yield child
            yield from _nested_values(child, key)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _nested_values(child, key)


def _field(mapping: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    raise AssertionError(f"none of {names!r} present in {sorted(mapping)}")


def _closed(call: Callable[[], Any], error: type[BaseException]) -> None:
    """Malformed input may decline with None or the one declared exception only."""
    try:
        result = call()
    except error:
        return
    assert result is None


def test_btp_a_and_b_documented_layouts() -> None:
    a = etsi.parse_btp(bytes.fromhex("07d1beefaabb"), variant="A")
    assert a["variant"].upper() == "A"
    assert a["destination_port"] == 2001
    assert a["source_port"] == 0xBEEF
    assert a["payload"] == b"\xaa\xbb"

    b = etsi.parse_btp(bytes.fromhex("07d11234aabb"), variant="B")
    assert b["variant"].upper() == "B"
    assert b["destination_port"] == 2001
    assert b["destination_port_info"] == 0x1234
    assert b["payload"] == b"\xaa\xbb"


@pytest.mark.parametrize(
    ("port", "facility"),
    ((2001, "cam"), (2002, "denm"), (2003, "mapem"),
     (2004, "spatem"), (2006, "ivim"), (2009, "cpm")),
)
def test_btp_registered_facilities_ports(port: int, facility: str) -> None:
    got = etsi.parse_btp(struct.pack(">HH", port, 0), variant="B")
    assert got["facility_hint"] == facility


def test_geonetworking_shb_btp_cam_stack() -> None:
    cam = _cam_oracle()
    frame = _shb_cam_frame(cam)
    got = etsi.parse_geonetworking(frame)
    basic, common = got["basic"], got["common"]
    assert basic["version"] == 1 and basic["next_header"] == 1
    assert basic["lifetime_raw"] == 0x28
    assert basic["lifetime_seconds"] == pytest.approx(0.5)
    assert basic["remaining_hop_limit"] == 1
    assert common["next_header"] == 2
    assert common["header_type"] == 5 and common["header_subtype"] == 0
    assert common["payload_length"] == len(cam) + 4
    assert common["maximum_hop_limit"] == 1

    ext = got["extended"]
    assert ext["kind"].lower() == "shb"
    pos = ext["source_position"]
    assert pos["gn_address"] == bytes.fromhex("1400020000000001")
    assert pos["gn_address_fields"]["raw_hex"] == "1400020000000001"
    assert pos["gn_address_fields"]["station_type"] == 5
    assert pos["timestamp_ms"] == 0x01020304
    assert pos["latitude_raw"] == 481234567
    assert pos["longitude_raw"] == 112345678
    assert pos["position_accurate"] is True
    assert pos["speed_raw"] == 1234
    assert pos["heading_raw"] == 900
    assert ext["media_dependent_data_hex"] == "01020304"
    assert got["btp"]["destination_port"] == 2001
    assert got["btp"]["destination_port_info"] == 0
    assert got["payload"] == cam


@pytest.mark.parametrize(
    ("header_type", "kind"), ((7, "single-hop-unicast"), (8, "single-hop-groupcast")),
)
def test_geonetworking_release2_single_hop_cv2x_profile(
    header_type: int, kind: str,
) -> None:
    frame = _release2_single_hop_frame(header_type)
    got = etsi.parse_geonetworking(frame, profile="release2")
    assert got["profile"] == "release2"
    assert got["common"]["header_type"] == header_type
    assert got["common"]["release2_pppp"] == 4
    assert got["extended"]["kind"] == kind
    media = got["extended"]["release2_media_dependent"]
    assert media["version"] == 1 and media["ctc"] == 5
    assert media["ctc_max_time_error_microseconds_exclusive"] == 0.5
    assert got["btp"]["destination_port"] == 2004

    assert etsi.parse_geonetworking(frame)["profile"] == "release2"
    with pytest.raises(etsi.V2XETSIError):
        etsi.parse_geonetworking(frame, profile="release1")

    reserved_tc = bytearray(frame)
    reserved_tc[6] |= 0x40
    with pytest.raises(etsi.V2XETSIError):
        etsi.parse_geonetworking(reserved_tc, profile="release2")

    reserved_ctc = bytearray(frame)
    reserved_ctc[36] = 0x18
    with pytest.raises(etsi.V2XETSIError):
        etsi.parse_geonetworking(reserved_ctc, profile="release2")

    negative_speed = bytearray(frame)
    struct.pack_into(">H", negative_speed, 32, 0x4001)
    parsed_speed = etsi.parse_geonetworking(negative_speed, profile="release2")
    assert parsed_speed["extended"]["source_position"]["speed_raw"] == -16383


def test_etsi_cam_real_uper_oracle() -> None:
    got = etsi.parse_its_pdu(_cam_oracle(), message_type="cam")
    assert _field(got, "message_type", "type").lower() == "cam"
    assert got["header"] == {"protocol_version": 1, "message_id": 2, "station_id": 0}
    assert 1 in set(_nested_values(got, "generationDeltaTime"))
    assert 10 in set(_nested_values(got, "latitude"))
    assert "forward" in set(_nested_values(got, "driveDirection"))


def test_current_etsi_facilities_fixed_header_inventory() -> None:
    # Independently encoded by V2XFlexStack 0.11.3's asn1tools CAMCoder from
    # its documented white-CAM value (TS 103 900 V2.2.1 / CDD 4.2).
    raw = V2XFLEXSTACK_CAM_V2
    got = etsi.parse_its_pdu(raw, message_type="cam")
    assert got["header"] == {
        "protocol_version": 2, "message_id": 2, "station_id": 0,
    }
    assert got["schema_decoded"] is False
    assert got["opaque_body"] == raw[6:]
    assert got["opaque_body_length"] == len(raw) - 6


def test_ieee1609dot2_coer_metadata_in_both_variants() -> None:
    raw = _coer_oracle()
    for module in (etsi, j2735):
        got = module.parse_secured_envelope(raw)
        assert _field(got, "protocol_version", "protocolVersion") == 3
        content = _field(got, "content_type", "contentType")
        assert content.replace("_", "").lower() == "unsecureddata"
        assert got["payload"] == bytes.fromhex("0123456789abcdef")


def test_ieee1609dot2_rejects_noncanonical_coer_length() -> None:
    # Same semantic content as the published vector, but length 8 is encoded
    # in a forbidden non-minimal long form.
    malformed = bytes.fromhex("03 80 81 08 01 23 45 67 89 ab cd ef")
    for module, error in (
        (etsi, etsi.V2XETSIError), (j2735, j2735.V2XJ2735Error),
    ):
        with pytest.raises(error):
            module.parse_secured_envelope(malformed)


def test_wsmp_v3_psid_and_length_vectors() -> None:
    # TPID 0, one-octet PSID 0x20, one-octet length 3.
    got = j2735.parse_wsmp(bytes.fromhex("03 00 20 03 aa bb cc"))
    assert got["version"] == 3 and got["subtype"] == 0
    assert got["option_indicator"] is False and got["tpid"] == 0
    assert got["psid"] == 0x20 and got["payload_length"] == 3
    assert got["payload"] == b"\xaa\xbb\xcc"

    # IEEE 1609.12 p-encoded two-octet PSID 0x82 is 0p80-02.
    got = j2735.parse_wsmp(bytes.fromhex("03 00 80 02 02 aa bb"))
    assert got["psid"] == 0x82 and got["payload"] == b"\xaa\xbb"


def test_wsmp_v3_information_element_extension() -> None:
    # Option bit, count=1, IE id=4 (transmit power), len=1, value=0x7f.
    got = j2735.parse_wsmp(bytes.fromhex("0b 01 04 01 7f 00 20 01 aa"))
    assert got["option_indicator"] is True
    assert got["tpid"] == 0 and got["psid"] == 0x20
    assert got["information_elements"] == [
        {"id": 4, "name": "transmit_power", "data": b"\x7f"}
    ]
    assert got["payload"] == b"\xaa"


def test_wsmp_reserved_transport_and_ie_width_fail_closed() -> None:
    # ShortMsgTpdus contributes the high seven TPID bits, followed by the
    # ShortMsgBcPDU optional-field bit.  Only subtype 0 and TPID 0 are active.
    for raw in (
        # Reserved WSMP-N networking subtype 1.
        bytes.fromhex("13 00 20 00"),
        # TPID 0 with unsupported T-extension branch present.
        bytes.fromhex("03 01 20 00"),
        # Reserved TPID 1 with no T-extension branch.
        bytes.fromhex("03 02 20 00"),
        # Known WSM-N TxPower IE 4 has exactly one value octet, not two.
        bytes.fromhex("0b 01 04 02 7f 00 00 20 00"),
    ):
        with pytest.raises(j2735.V2XJ2735Error):
            j2735.parse_wsmp(raw)


@NEEDS_J2735
def test_usdot_published_bsm_vector() -> None:
    got = j2735.parse_j2735_message(USDOT_BSM_1, message_type="bsm")
    assert _field(got, "message_type", "type").lower() == "bsm"
    assert _field(got, "message_id", "messageId") == 20
    for key, expected in {
        "msgCnt": 25,
        "secMark": 38283,
        "lat": 389557079,
        "long": -771505975,
        "elev": 370,
        "speed": 0,
        "heading": 10201,
        "width": 200,
        "length": 500,
    }.items():
        assert expected in set(_nested_values(got, key))
    identifiers = list(_nested_values(got, "id"))
    assert any(value in (b"\xf0:\xd6\x10", "F03AD610", "f03ad610") for value in identifiers)


@NEEDS_J2735
def test_j2735_bsm_unavailable_sentinels_stay_unavailable() -> None:
    # Generated independently with USDOT's schema by replacing the published
    # BSM's four physical values with J2735 unavailable sentinels.
    got = j2735.parse_j2735_message(USDOT_BSM_UNAVAILABLE, message_type="bsm")
    assert got["summary"]["latitude_degrees"] is None
    assert got["summary"]["longitude_degrees"] is None
    assert got["summary"]["speed_mps"] is None
    assert got["summary"]["heading_degrees"] is None


@NEEDS_J2735
def test_usdot_published_spat_vector() -> None:
    got = j2735.parse_j2735_message(USDOT_SPAT_1, message_type="spat")
    assert _field(got, "message_type", "type").lower() == "spat"
    assert _field(got, "message_id", "messageId") == 19
    for key, expected in {
        "revision": 1,
        "moy": 137825,
        "signalGroup": 7,
        "minEndTime": 40,
        "maxEndTime": 40,
        "likelyTime": 40,
    }.items():
        assert expected in set(_nested_values(got, key))
    assert "permissive-clearance" in set(_nested_values(got, "eventState"))
    assert 5813 in list(_nested_values(got, "id"))


@NEEDS_J2735
def test_usdot_jpo_ode_published_srm_vector() -> None:
    # jpo-ode/.../udp/srm/SrmReceiverTest_ValidData.txt on branch develop.
    got = j2735.parse_j2735_message(USDOT_SRM, message_type="srm")
    assert got["message_type"] == "srm" and got["message_id"] == 29
    assert got["message_frame"] is True
    fields = got["fields"]
    assert fields["second"] == 0 and fields["sequenceNumber"] == 1
    assert len(fields["requests"]) == 1
    request = fields["requests"][0]
    assert request["request"] == {
        "id": {"id": 12109},
        "requestID": 4,
        "requestType": "priorityRequest",
        "inBoundLane": {"lane": 13},
        "outBoundLane": {"lane": 4},
    }
    assert request["duration"] == 10979
    requestor = fields["requestor"]
    assert requestor["id"] == {"stationID": 2366845094}
    assert requestor["type"]["role"] == "publicTransport"
    assert requestor["position"] == {
        "position": {"lat": 395904915, "long": -1050913829, "elevation": 16854},
        "heading": 14072,
    }


@NEEDS_J2735
def test_usdot_jpo_ode_published_ssm_vector() -> None:
    # jpo-ode/.../udp/ssm/SsmReceiverTest_ValidSSM.txt on branch develop.
    got = j2735.parse_j2735_message(USDOT_SSM, message_type="ssm")
    assert got["message_type"] == "ssm" and got["message_id"] == 30
    assert got["message_frame"] is True
    assert got["fields"]["second"] == 0
    assert len(got["fields"]["status"]) == 1
    intersection = got["fields"]["status"][0]
    assert intersection["sequenceNumber"] == 0
    assert intersection["id"] == {"id": 12110}
    assert len(intersection["sigStatus"]) == 1
    status = intersection["sigStatus"][0]
    assert status["requester"] == {
        "id": {"stationID": 2366845094},
        "request": 3,
        "sequenceNumber": 0,
        "typeData": {"role": "publicTransport"},
    }
    assert status["inboundOn"] == {"lane": 23}
    assert status["status"] == "granted"


@NEEDS_J2735
def test_map_minimal_usdot_pycrate_encoder_oracle() -> None:
    raw = _j2735_message_frame_oracle(
        18,
        "MapData",
        {
            "msgIssueRevision": 9,
            "timeStamp": 12345,
            "layerType": "intersectionData",
            "layerID": 4,
        },
        "001206700181c89308",
    )
    got = j2735.parse_j2735_message(raw, message_type="map")
    assert got["message_type"] == "map" and got["message_id"] == 18
    assert got["message_frame"] is True
    assert got["fields"] == {
        "timeStamp": 12345,
        "msgIssueRevision": 9,
        "layerType": "intersectionData",
        "layerID": 4,
    }


@NEEDS_J2735
def test_tim_advisory_usdot_pycrate_encoder_oracle() -> None:
    fields = {
        "msgCnt": 7,
        "dataFrames": [{
            "doNotUse1": 0,
            "frameType": "advisory",
            "msgId": ("furtherInfoID", b"\x12\x34"),
            "startTime": 123,
            "durationTime": 60,
            "priority": 3,
            "doNotUse2": 0,
            "regions": [{}],
            "doNotUse3": 0,
            "doNotUse4": 0,
            "content": ("advisory", [{"item": ("text", "ROAD CLOSED")}]),
        }],
    }
    raw = _j2735_message_frame_oracle(
        31,
        "TravelerInformation",
        fields,
        MINIMAL_TIM_FRAME.hex(),
    )
    got = j2735.parse_j2735_message(raw, message_type="tim")
    assert got["message_type"] == "tim" and got["message_id"] == 31
    assert got["message_frame"] is True
    assert got["fields"]["msgCnt"] == 7
    frame = got["fields"]["dataFrames"][0]
    assert frame["frameType"] == "advisory"
    assert frame["msgId"] == {"furtherInfoID": "1234"}
    assert frame["startTime"] == 123 and frame["durationTime"] == 60
    assert frame["priority"] == 3 and frame["regions"] == [{}]
    assert frame["content"] == {"advisory": [{"item": {"text": "ROAD CLOSED"}}]}


@NEEDS_J2735
def test_j2735_direct_tim_and_noncanonical_open_type() -> None:
    # The first two octets are MessageFrame ID 31 and the third is the
    # canonical open-type length; the remainder is a direct TIM PDU.
    direct = j2735.parse_j2735_message(MINIMAL_TIM_FRAME[3:], message_type="tim")
    assert direct["message_frame"] is False
    assert direct["fields"]["dataFrames"][0]["content"] == {
        "advisory": [{"item": {"text": "ROAD CLOSED"}}]
    }

    # BSM body length 0x25 expressed as non-minimal 0x80 0x25.
    noncanonical = USDOT_BSM_1[:2] + b"\x80" + USDOT_BSM_1[2:]
    with pytest.raises(j2735.V2XJ2735Error):
        j2735.parse_j2735_message(noncanonical, message_type="bsm")


@pytest.mark.parametrize(
    ("module", "error"),
    ((etsi, etsi.V2XETSIError), (j2735, j2735.V2XJ2735Error)),
)
def test_nr_sidelink_sci_2a_authoritative_bit_layout(module: Any, error: type[BaseException]) -> None:
    # 3GPP TS 38.212 V16.8.0 section 8.4.1.1: fields are mapped in the
    # listed order, MSB first.  The 35 information bits below are padded with
    # five zero bits solely to form supplied octets.
    fields = ((10, 4), (1, 1), (2, 2), (0x5A, 8), (0xBEEF, 16),
              (1, 1), (2, 2), (1, 1))
    bits = "".join(format(value, f"0{width}b") for value, width in fields)
    assert len(bits) == 35
    raw = int(bits.ljust(40, "0"), 2).to_bytes(5, "big")
    assert raw.hex() == "acb57ddfa0"

    got = module.parse_nr_sidelink_sci(raw, "2a")
    assert str(_field(got, "format", "sci_format")).lower().replace("-", "") == "2a"
    parsed = got.get("fields", got)
    assert _field(parsed, "harq_process_number", "harq_process") == 10
    assert parsed["new_data_indicator"] == 1
    assert parsed["redundancy_version"] == 2
    assert parsed["source_id"] == 0x5A
    assert parsed["destination_id"] == 0xBEEF
    assert parsed["harq_feedback_enabled"] is True
    assert _field(parsed, "cast_type_raw", "cast_type") == 2
    cast_name = parsed.get("cast_type_name")
    if cast_name is None and isinstance(parsed.get("cast_type"), str):
        cast_name = parsed["cast_type"]
    assert cast_name == "unicast"
    assert parsed["csi_request"] in (1, True)

    # Non-zero alignment bits are not part of the SCI and must not be
    # silently interpreted as a different message.
    _closed(lambda: module.parse_nr_sidelink_sci(raw[:-1] + bytes((raw[-1] | 1,)), "2a"), error)

    # Release 17+ adds conditional fields requiring RRC context not represented
    # by this focused Release-16 parser; it must not silently use the old layout.
    with pytest.raises(error):
        module.parse_nr_sidelink_sci(raw, "2a", nr_release=17)


@pytest.mark.parametrize(
    ("module", "error"),
    ((etsi, etsi.V2XETSIError), (j2735, j2735.V2XJ2735Error)),
)
def test_nr_release16_reserved_second_stage_format_rejected(
    module: Any, error: type[BaseException],
) -> None:
    # With one subchannel, 1-A starts priority(3), time assignment(5), then
    # the 2-bit second-stage format.  Raw 11 is reserved in Release 16.
    with pytest.raises(error):
        module.parse_nr_sidelink_sci(
            bytes.fromhex("00c000"), "1-a", num_subchannels=1, nr_release=16,
        )


def test_truncation_and_wrong_type_contracts() -> None:
    cam = _cam_oracle()
    vectors = (
        # BTP has a four-octet mandatory header; an empty facilities payload
        # is legal, so only prefixes of this header are malformed.
        (lambda raw: etsi.parse_btp(raw, variant="B"), etsi.V2XETSIError, b"\x07\xd1\0\0"),
        (etsi.parse_geonetworking, etsi.V2XETSIError, _shb_cam_frame(cam)),
        (lambda raw: etsi.parse_its_pdu(raw, message_type="cam"), etsi.V2XETSIError, cam),
        (etsi.parse_secured_envelope, etsi.V2XETSIError, _coer_oracle()),
        (lambda raw: etsi.parse_nr_sidelink_sci(raw, "2a"), etsi.V2XETSIError,
         bytes.fromhex("ac b5 7d df a0")),
        (j2735.parse_wsmp, j2735.V2XJ2735Error, bytes.fromhex("03 00 20 03 aa bb cc")),
        (lambda raw: j2735.parse_nr_sidelink_sci(raw, "2a"), j2735.V2XJ2735Error,
         bytes.fromhex("ac b5 7d df a0")),
        (lambda raw: j2735.parse_j2735_message(raw, message_type="bsm"), j2735.V2XJ2735Error, USDOT_BSM_1),
        (j2735.parse_secured_envelope, j2735.V2XJ2735Error, _coer_oracle()),
    )
    for function, error, valid in vectors:
        for cut in range(len(valid)):
            _closed(lambda f=function, raw=valid[:cut]: f(raw), error)
        for wrong in (None, True, 1, "00", [], {}, object()):
            _closed(lambda f=function, value=wrong: f(value), error)


def test_seeded_random_never_leaks_stdlib_exceptions() -> None:
    rng = random.Random(0xC2C)
    calls = (
        (etsi.parse_geonetworking, etsi.V2XETSIError),
        (lambda raw: etsi.parse_its_pdu(raw, message_type="cam"), etsi.V2XETSIError),
        (etsi.parse_secured_envelope, etsi.V2XETSIError),
        (lambda raw: etsi.parse_nr_sidelink_sci(raw, "2a"), etsi.V2XETSIError),
        (j2735.parse_wsmp, j2735.V2XJ2735Error),
        (lambda raw: j2735.parse_nr_sidelink_sci(raw, "2a"), j2735.V2XJ2735Error),
        (lambda raw: j2735.parse_j2735_message(raw, message_type="bsm"), j2735.V2XJ2735Error),
        (j2735.parse_secured_envelope, j2735.V2XJ2735Error),
    )
    for _ in range(100):
        raw = rng.randbytes(rng.randrange(0, 128))
        for function, error in calls:
            try:
                result = function(raw)
            except error:
                continue
            assert result is None or isinstance(result, dict)


def test_oversized_inputs_fail_with_declared_errors() -> None:
    with pytest.raises(etsi.V2XETSIError):
        etsi.parse_geonetworking(b"\0" * (etsi.MAX_INPUT + 1))
    with pytest.raises(j2735.V2XJ2735Error):
        j2735.parse_wsmp(b"\0" * (j2735.MAX_INPUT + 1))


def test_guarded_argparse() -> None:
    for module in (etsi, j2735):
        assert module.main(["--help"]) == 0
        assert module.main([]) == 2

