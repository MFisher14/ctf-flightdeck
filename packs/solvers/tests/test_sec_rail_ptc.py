"""Independent public-layout vectors for the passive US rail engine."""
from __future__ import annotations

import binascii
import hashlib
import hmac
import random

import pytest

import sec_rail_ptc as ptc


# AAR S-9354 layout carrying S-9361 decimal type 02051 (=2051=0x0803).
EMP_PREFIX = bytes.fromhex(
    "04 0803 01 09 00000f 10203040 65000000 10 "
    "003b 0030 6c6f636f2e343200 626f7300 "
    "424e5346 1234 02 01020304 aabbccdd"
)
EMP_CRC = bytes.fromhex("b6921ca8")
EMP_FIXTURE = EMP_PREFIX + EMP_CRC

# AAR S-5800 published address example wrapped in a hand-built single packet.
ATCS_FIXTURE = bytes.fromhex(
    "20 000000 85 99999a12345670 00 0603020c81 464c4147"
)

# AAR S-9362 published bit layout, hand-packed fields.
WIU_FIXTURE = bytes.fromhex("0102030405 820a 2a d6 deadbeef")


def test_emp_crc_catalogue_and_complete_fixture():
    assert binascii.crc32(b"123456789") & 0xFFFFFFFF == 0xCBF43926
    assert (binascii.crc32(EMP_PREFIX) & 0xFFFFFFFF).to_bytes(4, "big") == EMP_CRC
    decoded = ptc.parse_emp(EMP_FIXTURE)
    assert decoded["protocol_version"] == 4
    assert decoded["message_type"] == 2051
    assert decoded["message_name"] == "request movement authority dataset"
    assert decoded["message_number"] == 0x10203040
    assert decoded["routing"]["source"] == "loco.42"
    assert decoded["routing"]["destination"] == "bos"
    assert decoded["integrity_verified"] is True
    body = decoded["payload"]["decoded"]
    assert body == {
        "SCAC": "BNSF", "subdivision": 0x1234, "authority_count": 2,
        "authority_references": [0x01020304, 0xAABBCCDD],
    }


def test_emp_application_hmac_uses_supplied_key_only():
    key = b"published-fixture-test-key"
    body = b""
    # v4, type decimal 5200, version 1, absolute+application-integrity.
    prefix = bytes.fromhex("04 1450 00 11 000000 00000001 00000000 00") + body
    tag = hmac.new(key, prefix, hashlib.sha1).digest()[:4]
    decoded = ptc.parse_emp(prefix + tag, key)
    assert decoded["message_type"] == 5200
    assert decoded["integrity_method"] == "application-specific"
    assert decoded["integrity_verified"] is True
    assert decoded["payload"]["decoded"] == {}


def test_itcm_decimal_ids_and_confirmation_layouts():
    body2052 = (b"UP  " + b"\x01" + bytes.fromhex(
        "1234 01020304 cbf43926 01"
    ))
    result = ptc.parse_itcm_message(2052, body2052, 3)["decoded"]
    assert result["SCAC"] == "UP  "
    assert result["confirmations"][0] == {
        "subdivision": 0x1234, "authority_reference": 0x01020304,
        "authority_crc32": "cbf43926", "acknowledgement": 1,
    }
    body2053 = b"BNSF" + bytes.fromhex("0007 11223344 89abcdef 03")
    assert ptc.parse_itcm_message(2053, body2053)["decoded"]["acknowledgement"] == 3
    context = ptc.parse_itcm_message(2090, b"future")["version_context"]
    assert "legacy S-9361" in context and "FMB research" in context


def test_public_message_versions_and_wiu_correlation_are_locked():
    request = b"BNSF" + bytes.fromhex("1234 00")
    with pytest.raises(ptc.SecRailPTCError):
        ptc.parse_itcm_message(2051, request, 2)
    wrong_inner_version = bytearray(WIU_FIXTURE)
    wrong_inner_version[6] |= 0x10
    with pytest.raises(ptc.SecRailPTCError):
        ptc.parse_wiu_status(wrong_inner_version)
    with pytest.raises(ptc.SecRailPTCError):
        ptc.parse_itcm_message(5101, WIU_FIXTURE, 0)


def test_emp_no_integrity_div_and_220mhz_qos():
    no_integrity = bytes.fromhex(
        "04 1450 00 01 000000 00000001 00000000 00 00000000"
    )
    assert ptc.parse_emp(no_integrity)["integrity_method"] == "none"
    with pytest.raises(ptc.SecRailPTCError):
        ptc.parse_emp(no_integrity[:-4] + bytes.fromhex("deadbeef"))

    variable = bytes.fromhex("003b 0040") + b"loco\0office\0"
    prefix = (bytes.fromhex("04 1450 00 09 000000 00000002 00000000") +
              bytes([len(variable)]) + variable)
    crc = (binascii.crc32(prefix) & 0xFFFFFFFF).to_bytes(4, "big")
    decoded = ptc.parse_emp(prefix + crc)
    assert decoded["routing"]["network_preference"] == 1
    assert decoded["routing"]["network_preference_name"] == "ITC 220 MHz"


def test_wiu_status_published_bit_semantics():
    decoded = ptc.parse_wiu_status(WIU_FIXTURE, ["switch", "signal", "hazard"])
    assert decoded["WIU_ID"] == 0x0102030405
    assert decoded["TTL_indicator"] == 1
    assert decoded["vital_message_type"] == 1
    assert decoded["vital_message_version"] == 0
    assert decoded["modulo_16_time"] == 10
    assert decoded["sequence"] == 42
    assert decoded["devices"] == [
        {"kind": "switch", "code": 2, "state": "normal"},
        {"kind": "signal", "code": 21},
        {"kind": "hazard", "code": 1, "condition": "none"},
    ]
    assert decoded["vital_integrity_hex"] == "deadbeef"
    assert decoded["vital_integrity_verified"] is None


def test_atcs_published_address_and_label_formula():
    decoded = ptc.parse_atcs_packet(ATCS_FIXTURE)
    assert decoded["Q"] == 0 and decoded["originating_packet"] is True
    assert decoded["source"] == "01234567"
    assert decoded["destination"] == "99999"
    assert decoded["message_number"] == 3
    assert decoded["part_number"] == decoded["total_parts"] == 1
    assert decoded["message_label"] == 3201
    assert (decoded["function"], decoded["message_type"], decoded["specifier"]) == (6, 2, 1)
    assert bytes.fromhex(decoded["layer7_hex"]) == b"FLAG"


def test_atcs_fragment_reassembly_is_address_parameterized():
    common = bytes.fromhex("20 000000 85 99999a12345670 00")
    first = common + bytes.fromhex("07 02 04 0c81") + b"AB"
    second = common + bytes.fromhex("06 04 04 0c81") + b"CD"
    result = ptc.reassemble_atcs_packets([second, first])
    assert result["source"] == "01234567"
    assert result["destination"] == "99999"
    assert bytes.fromhex(result["layer7_hex"]) == b"ABCD"


def test_atcs_vital_boundary_and_extended_ceiling():
    common = bytes.fromhex("20 000000 85 99999a12345670 00")
    vital = common + bytes.fromhex("06 02 03 0c81") + b"V" + bytes.fromhex("01234567")
    decoded = ptc.parse_atcs_packet(vital)
    assert decoded["vital"] is True
    assert bytes.fromhex(decoded["layer7_hex"]) == b"V"
    assert decoded["redundancy_code_hex"] == "01234567"

    with pytest.raises(ptc.SecRailPTCError):
        ptc.parse_atcs_packet(
            common + bytes.fromhex("06 02 03 0c81") + b"A" * 120 + b"\0\0\0\1"
        )
    with pytest.raises(ptc.SecRailPTCError):
        ptc.parse_atcs_packet(
            common + bytes.fromhex("06 02 02 0c81") + b"A" * 252
        )


def test_ptc_public_entrypoints_fail_closed():
    rng = random.Random(0x9354)
    for value in (b"", b"\0" * 20, rng.randbytes(51), EMP_FIXTURE[:-1],
                  EMP_FIXTURE[:-4] + b"\0\0\0\0"):
        with pytest.raises(ptc.SecRailPTCError):
            ptc.parse_emp(value)
    for value in (b"", rng.randbytes(12), b"\0" * 257):
        with pytest.raises(ptc.SecRailPTCError):
            ptc.parse_wiu_status(value)
    for value in (b"", rng.randbytes(11), rng.randbytes(30), b"\0" * 513):
        with pytest.raises(ptc.SecRailPTCError):
            ptc.parse_atcs_packet(value)
    for args in ((-1, b""), (65536, b""), (2051, b"short"), (5100, b"bad")):
        with pytest.raises(ptc.SecRailPTCError):
            ptc.parse_itcm_message(*args)
    with pytest.raises(ptc.SecRailPTCError):
        ptc.reassemble_atcs_packets([])
    with pytest.raises(ptc.SecRailPTCError):
        ptc.reassemble_atcs_packets([ATCS_FIXTURE, b"bad"])
    assert ptc.main(["--not-an-option"]) == 2
    assert ptc.main(["--help"]) == 0
