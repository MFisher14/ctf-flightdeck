"""Independent/published vectors for the passive ERTMS engine."""
from __future__ import annotations

import random

import pytest
from Crypto.Cipher import DES

import sec_rail_ertms as ertms


# ERA SUBSET-085 v3.0.0, Table 25 ID 1 and Table 23 decoded user data.
SUBSET_085_SHORT = bytes.fromhex(
    "75 BB BF 37 1E 7F 76 B9 25 D3 FD ED 46 BA D7 69 "
    "85 7B ED 37 F6 A5 F2 F4 3E FD 8C DF 5A 40 DA 7F "
    "BB 71 22 C5 BF 22 CD A3 9B 07 78"
)
SUBSET_085_SHORT_USER = bytes.fromhex(
    "80 10 01 1C D8 00 00 42 91 D3 08 59 4D 17 9D D5 "
    "88 1A 3F FF FF FF FF FF FF FF C0"
)

# ERA SUBSET-085 v3.0.0, Table 25 ID 10 (first 1023 bits).
SUBSET_085_LONG = bytes.fromhex(
    "BE 09 4B AD 38 41 5F E7 42 D4 6B A0 79 61 36 1B "
    "64 27 9C DF 2B ED 3D E5 BC D9 E2 F6 DF 78 CC 52 "
    "E2 B3 16 BC B9 5D CD 8E 73 D7 5B F6 08 B9 0E F5 "
    "A3 E5 03 5B 3D D7 B3 15 E4 0C FB 45 55 D6 8F 75 "
    "5F 6D 75 1A 4F 7F 69 7C F6 7B 6D 8A 19 3F 4C 07 "
    "B7 A9 6E FC 73 F4 C6 EF D4 D8 70 DB F7 EF 79 90 "
    "C9 A1 25 8E 67 6E CA D0 E1 C2 69 CE D9 25 AE 0F "
    "F1 21 90 11 CD A9 7D BF A5 60 F6 F5 F4 BD 0B D8"
)


def _field(value: int, width: int) -> str:
    assert 0 <= value < 1 << width
    return f"{value:0{width}b}"


def _container(bits: str) -> bytes:
    return int(bits + "0" * (-len(bits) % 8), 2).to_bytes((len(bits) + 7) // 8, "big")


def _ordinary_packet(packet_id: int, direction: int, body: str) -> str:
    length = 23 + len(body)
    return _field(packet_id, 8) + _field(direction, 2) + _field(length, 13) + body


def _current_long_user_fixture() -> bytes:
    # Hand-packed directly from SUBSET-026 v4 chapter 7; no engine encoder.
    header = "".join((
        _field(1, 1), _field(33, 7), _field(0, 1), _field(2, 3),
        _field(3, 3), _field(0, 2), _field(17, 8), _field(351, 10),
        _field(0x1234, 14), _field(1, 1),
    ))
    p2 = _ordinary_packet(2, 1, _field(33, 7))
    p21_body = "".join((
        _field(1, 2), _field(125, 15), _field(1, 1), _field(17, 8),
        _field(1, 5), _field(250, 15), _field(0, 1), _field(9, 8),
    ))
    p21 = _ordinary_packet(21, 2, p21_body)
    p31 = _ordinary_packet(31, 1, "".join((
        _field(2, 2), _field(123, 15), _field(351, 10),
        _field(0x1234, 14), _field(1, 1),
    )))
    p32 = _ordinary_packet(32, 0, "".join((
        _field(1, 1), _field(351, 10), _field(0x1234, 14), _field(0, 1),
    )))
    bits = header + p2 + p21 + p31 + p32 + _field(255, 8)
    return _container(bits + "1" * (830 - len(bits)))


def _reference_mac(message: bytes, key: bytes) -> bytes:
    # Literal Annex-B algorithm using PyCryptodome solely as the DES oracle.
    padded = message + b"\0" * (-len(message) % 8)
    state = b"\0" * 8
    for offset in range(0, len(padded), 8):
        mixed = bytes(a ^ b for a, b in zip(state, padded[offset:offset + 8]))
        state = DES.new(key[:8], DES.MODE_ECB).encrypt(mixed)
    state = DES.new(key[8:16], DES.MODE_ECB).decrypt(state)
    return DES.new(key[16:], DES.MODE_ECB).encrypt(state)


def test_subset085_short_end_to_end_published_vector():
    decoded = ertms.decode_balise_telegram(SUBSET_085_SHORT)
    assert decoded["kind"] == "short"
    assert decoded["telegram_length"] == 341
    assert decoded["check_bits_valid"] is True
    assert bytes.fromhex(decoded["user_data_hex"]) == SUBSET_085_SHORT_USER


def test_subset085_long_published_candidate_is_accepted():
    decoded = ertms.decode_balise_telegram(SUBSET_085_LONG)
    assert decoded["kind"] == "long"
    assert decoded["telegram_length"] == 1023
    assert decoded["shaped_words"] == 83
    assert decoded["alphabet_words_checked"] == 93
    assert len(bytes.fromhex(decoded["user_data_hex"])) == 104


def test_subset085_one_bit_corruption_fails_closed():
    corrupt = bytearray(SUBSET_085_SHORT)
    corrupt[9] ^= 0x04
    with pytest.raises(ertms.SecRailERTMSError):
        ertms.decode_balise_telegram(corrupt)


def test_current_subset026_packet_and_frmcs_fields():
    decoded = ertms.parse_etcs_user_data(_current_long_user_fixture(), 830)
    assert decoded["header"] == {
        "Q_UPDOWN": 1, "M_VERSION": 33, "Q_MEDIA": 0, "N_PIG": 2,
        "N_TOTAL": 3, "M_DUP": 0, "M_MCOUNT": 17, "NID_C": 351,
        "NID_BG": 0x1234, "Q_LINK": 1,
    }
    by_id = {packet["NID_PACKET"]: packet for packet in decoded["packets"]}
    assert by_id[2]["M_VERSION"] == 33
    assert by_id[21]["D_GRADIENT"] == 125
    assert by_id[21]["d_gradient_metres"] == 125.0
    assert by_id[21]["gradients"][0]["G_A"] == 9
    assert by_id[31]["D_RBCTR"] == 123
    assert by_id[31]["d_rbctr_metres"] == 1230.0
    assert by_id[31]["transport_profile"] == "FRMCS-capable RBC transition"
    assert by_id[32]["NID_RBC"] == 0x1234
    assert by_id[255]["name"] == "end_of_information"


def test_subset026_packet_zero_special_layout():
    header = "".join((_field(1, 1), _field(33, 7), _field(0, 1),
                      _field(0, 3), _field(0, 3), _field(0, 2),
                      _field(1, 8), _field(2, 10), _field(3, 14), _field(0, 1)))
    bits = header + _field(0, 8) + _field(37, 6) + _field(255, 8)
    decoded = ertms.parse_etcs_user_data(_container(bits + "1" * (210 - len(bits))), 210)
    assert decoded["packets"][0] == {
        "NID_PACKET": 0, "name": "virtual_balise_cover_marker",
        "NID_VBCMK": 37, "L_PACKET": 14,
    }


def test_euroradio_annex_b_published_mac_vector():
    message = bytes(range(0x15))
    key = bytes.fromhex(
        "01 02 04 07 08 0B 0D 0E 10 13 15 16 19 1A 1C 1F "
        "20 23 25 26 29 2A 2C 2F"
    )
    assert _reference_mac(message, key).hex() == "361d431ed396c175"
    assert ertms.euroradio_mac(message, key).hex() == "361d431ed396c175"


def test_euroradio_dt_boundaries_and_protocol_mac_wrapper():
    key = bytes.fromhex(
        "01 02 04 07 08 0B 0D 0E 10 13 15 16 19 1A 1C 1F "
        "20 23 25 26 29 2A 2C 2F"
    )
    receiver = bytes.fromhex("123456")
    body = bytes([0b00001011]) + b"CSCTF{rail}"  # DT, direction responder->initiator
    covered = (len(receiver) + len(body)).to_bytes(2, "big") + receiver + body
    tag = _reference_mac(covered, key)
    decoded = ertms.parse_euroradio_sapdu(body + tag, receiver, key)
    assert decoded["type"] == "DT"
    assert decoded["direction_flag"] == 1
    assert bytes.fromhex(decoded["user_data_hex"]) == b"CSCTF{rail}"
    assert decoded["mac_valid"] is True
    assert ertms.verify_euroradio_mac(body, tag, receiver, key) is True


def test_euroradio_fixed_pdus():
    au1 = bytes([0b00100010]) + bytes.fromhex("010203") + b"\x01" + bytes(range(8))
    assert ertms.parse_euroradio_sapdu(au1)["source_id"] == 0x010203
    assert ertms.parse_euroradio_sapdu(b"\x10\x07\x09") == {
        "format": "EuroRadio SaPDU", "type": "DI", "message_type": 8,
        "direction_flag": 0, "entity_type": 0, "length": 3,
        "reason": 7, "sub_reason": 9,
    }
    with pytest.raises(ertms.SecRailERTMSError):
        ertms.parse_euroradio_sapdu(bytes([0b00100011]) + au1[1:])


def test_subset098_documented_adaptation_layout():
    au1 = bytes([0b00100010]) + bytes.fromhex("010203") + b"\x01" + bytes(range(8))
    # packet_length excludes its own two octets; checksum is inventory-only.
    frame = (21).to_bytes(2, "big") + bytes.fromhex("01 02 1234 00 01 beef") + au1
    decoded = ertms.parse_rbc_rbc_frame(frame)
    assert decoded["packet_length"] == 21
    assert decoded["version"] == 1
    assert decoded["application"] == 2
    assert decoded["transmission_sequence"] == 0x1234
    assert decoded["packet_type_name"] == "AU1"
    assert decoded["header_checksum_hex"] == "beef"
    assert decoded["header_checksum_verified"] is None
    assert decoded["sapdu"]["source_id"] == 0x010203


def test_ertms_public_entrypoints_fail_closed(tmp_path):
    rng = random.Random(0x3637)
    failures = [b"", b"\0", rng.randbytes(42), rng.randbytes(127), b"x" * 129]
    for value in failures:
        with pytest.raises(ertms.SecRailERTMSError):
            ertms.decode_balise_telegram(value)
    for value in (b"", rng.randbytes(26), rng.randbytes(27), rng.randbytes(103)):
        with pytest.raises(ertms.SecRailERTMSError):
            ertms.parse_etcs_user_data(value)
    for args in ((b"", b""), (b"x", b"short"), (None, b"x" * 24)):
        with pytest.raises(ertms.SecRailERTMSError):
            ertms.euroradio_mac(*args)
    for value in (b"", rng.randbytes(8), rng.randbytes(2000)):
        with pytest.raises(ertms.SecRailERTMSError):
            ertms.parse_euroradio_sapdu(value)
    with pytest.raises(ertms.SecRailERTMSError):
        ertms.verify_euroradio_mac(b"x", b"short", 1, b"k" * 24)
    for value in (b"", rng.randbytes(9), rng.randbytes(1043)):
        with pytest.raises(ertms.SecRailERTMSError):
            ertms.parse_rbc_rbc_frame(value)
    assert ertms.main(["--not-an-option"]) == 2
    assert ertms.main(["--help"]) == 0

