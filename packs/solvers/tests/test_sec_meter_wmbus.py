"""Independent vectors for the passive EN 13757 / OMS meter reader.

The literal clear telegram is published by wmbusmeters.  Framing, CRC, wired
M-Bus and DIF/VIF fixtures are assembled here from the documented wire layout,
not by the engine.  Crypto fixtures use the independent ``cryptography``
implementation as their oracle (the engine itself uses PyCryptodome).

Sources:
* https://github.com/wmbusmeters/wmbusmeters (README clear telegram example)
* EN 13757-4: Format A first block is 10 octets and later blocks are 16;
  CRC-16/EN-13757 is poly 0x3d65, init 0, xorout 0xffff, non-reflected.
* OMS Volume 2 v5.0.1, clauses 7.2.4 and 9.2.5/9.3.
"""
from __future__ import annotations

import argparse
import random

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

import sec_meter_wmbus as wmbus


PUBLISHED_CLEAR = bytes.fromhex(
    "234433300602010014007a8e0000002f2f"
    "0efd3a1147000000008e40fd3a341200000000"
)
PUBLISHED_ANALYZE = bytes.fromhex(
    "1844AE4C4455223368077A55000000041389E20100023B0000"
)

M_FIELD = bytes.fromhex("3330")       # packed manufacturer LAS, wire order
IDENT = bytes.fromhex("04030201")     # displayed identification 01020304
VERSION = 0x01
DEVICE_TYPE = 0x07
ACCESS = 0x21
KEY = bytes(range(16))


def reference_crc16_en13757(data: bytes) -> int:
    """Straight polynomial division for CRC-16/EN-13757 (not engine code)."""
    crc = 0
    for octet in data:
        crc ^= octet << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x3D65) if crc & 0x8000 else (crc << 1)) & 0xFFFF
    return crc ^ 0xFFFF


def reference_format_a(stripped: bytes) -> bytes:
    """Insert big-endian CRC fields after the 10-byte/16-byte Format-A blocks."""
    assert stripped and stripped[0] == len(stripped) - 1
    chunks = [stripped[:10]]
    chunks.extend(stripped[pos:pos + 16] for pos in range(10, len(stripped), 16))
    return b"".join(chunk + reference_crc16_en13757(chunk).to_bytes(2, "big")
                    for chunk in chunks)


def reference_format_b(stripped: bytes) -> bytes:
    """Make a one-block Format-B frame; its L field includes the final CRC."""
    assert 11 <= len(stripped) <= 126
    body = bytes((len(stripped) + 1,)) + stripped[1:]
    return body + reference_crc16_en13757(body).to_bytes(2, "big")


def reference_wired_short(control: int, address: int) -> bytes:
    checksum = (control + address) & 0xFF
    return bytes((0x10, control, address, checksum, 0x16))


def reference_wired_long(control: int, address: int, ci: int, payload: bytes = b"") -> bytes:
    body = bytes((control, address, ci)) + payload
    return bytes((0x68, len(body), len(body), 0x68)) + body + bytes((sum(body) & 0xFF, 0x16))


def reference_stripped(tpdu: bytes) -> bytes:
    body = bytes((0x44,)) + M_FIELD + IDENT + bytes((VERSION, DEVICE_TYPE)) + tpdu
    assert len(body) <= 255
    return bytes((len(body),)) + body


def reference_application_block(value: int = 123456789) -> bytes:
    # 2f2f decryption-verification/fillers, then DIF=32-bit integer,
    # VIF=10^0 Wh, little-endian data, and filler to one AES block.
    head = b"\x2f\x2f\x04\x03" + value.to_bytes(4, "little", signed=True)
    return head + b"\x2f" * (16 - len(head))


def reference_cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC through cryptography, independent of the engine's Crypto code."""
    authenticator = cmac.CMAC(algorithms.AES128(key))
    authenticator.update(data)
    return authenticator.finalize()


def reference_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES128(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def reference_kdf_a(key: bytes, direction: int, counter: bytes) -> bytes:
    # OMS KDF-A: CMAC(CSK, DC || message counter LE || meter ID wire || 07*7).
    return reference_cmac(key, bytes((direction,)) + counter + IDENT + b"\x07" * 7)


def reference_mode5(value: int = 123456789, key: bytes = KEY) -> bytes:
    plaintext = reference_application_block(value)
    iv = M_FIELD + IDENT + bytes((VERSION, DEVICE_TYPE)) + bytes((ACCESS,)) * 8
    ciphertext = reference_cbc_encrypt(key, iv, plaintext)
    configuration = (5 << 8) | (1 << 4)  # mode 5, one encrypted block
    tpdu = bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little") + ciphertext
    return reference_stripped(tpdu)


def reference_mode7(value: int = 123456789, key: bytes = KEY) -> bytes:
    """OMS profile-B telegram built directly from the published field grammar."""
    counter = bytes.fromhex("04030201")
    # KI is a little-endian 16-bit field: key-id 0, KDF-A 1, reserved 0,
    # key-version 1.  MCL mirrors global MCR/KI presence and AT=5.
    key_info = (0x0110).to_bytes(2, "little")
    message_control = 0x35
    configuration = (7 << 8) | (1 << 4)
    configuration_extension = 0x10  # KDF-A, key id zero
    plaintext = reference_application_block(value)
    encryption_key = reference_kdf_a(key, 0x00, counter)
    ciphertext = reference_cbc_encrypt(encryption_key, bytes(16), plaintext)
    tpdu = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
            + bytes((configuration_extension,)) + ciphertext)

    # FCL flags: MCL/KI/message-counter/MAC present.  AFLL
    # counts FCL and all optional fields, but not CI=90 nor AFLL itself.
    fcl = 0x2E00
    physical_fields = bytes((message_control,)) + key_info + counter
    authentication_key = reference_kdf_a(key, 0x01, counter)
    # OMS-B CMAC excludes KI: MCL || MCR || optional ML || TPDU.
    tag = reference_cmac(authentication_key, bytes((message_control,)) + counter + tpdu)[:8]
    afl_body = (fcl.to_bytes(2, "little") + physical_fields + tag)
    afl = bytes((0x90, len(afl_body))) + afl_body
    return reference_stripped(afl + tpdu)


def reference_mode7_with_padding(*, valid: bool, key: bytes = KEY) -> tuple[bytes, bytes]:
    """Build authenticated mode 7 with CF.P and independently encrypted padding."""
    counter = bytes.fromhex("08070605")
    key_info = (0x0210).to_bytes(2, "little")
    message_control = 0x35
    application = b"\x2f\x2f\x04\x03" + (654321).to_bytes(4, "little")
    padding = b"\x08" * 8 if valid else b"\x08" * 7 + b"\x00"
    plaintext = application + padding
    configuration = (7 << 8) | (1 << 4) | 0x0008  # N=1 and P=1
    encryption_key = reference_kdf_a(key, 0x00, counter)
    ciphertext = reference_cbc_encrypt(encryption_key, bytes(16), plaintext)
    tpdu = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
            + b"\x10" + ciphertext)

    fcl = 0x2E00
    physical_fields = bytes((message_control,)) + key_info + counter
    authentication_key = reference_kdf_a(key, 0x01, counter)
    # The invalid-padding case still has a correct CMAC over its ciphertext,
    # proving any rejection happens after authentication rather than at MAC.
    tag = reference_cmac(authentication_key, bytes((message_control,)) + counter + tpdu)[:8]
    afl_body = fcl.to_bytes(2, "little") + physical_fields + tag
    return reference_stripped(bytes((0x90, len(afl_body))) + afl_body + tpdu), application


def reference_mode7_with_message_length(declared: int | None = None, key: bytes = KEY) -> bytes:
    counter = bytes.fromhex("0c0b0a09")
    key_info = (0x0310).to_bytes(2, "little")
    message_control = 0x75  # ML, MCR, KI, and AT=5 globally present
    configuration = (7 << 8) | (1 << 4)
    plaintext = reference_application_block(8080)
    ciphertext = reference_cbc_encrypt(reference_kdf_a(key, 0, counter), bytes(16), plaintext)
    tpdu = bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little") + b"\x10" + ciphertext
    message_length = (len(tpdu) if declared is None else declared).to_bytes(2, "little")
    fcl = 0x3E00  # MCL, ML, MCR, MAC, and KI all present in this frame
    tag = reference_cmac(reference_kdf_a(key, 1, counter),
                         bytes((message_control,)) + counter + message_length + tpdu)[:8]
    afl_body = (fcl.to_bytes(2, "little") + bytes((message_control,)) + key_info
                + counter + tag + message_length)
    return reference_stripped(bytes((0x90, len(afl_body))) + afl_body + tpdu)


def reference_mode5_clear(value: int = 123456789) -> bytes:
    configuration = 5 << 8  # mode 5, N=0: no encrypted blocks
    application = b"\x04\x03" + value.to_bytes(4, "little", signed=True)
    tpdu = bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little") + application
    return reference_stripped(tpdu)


def reference_mode5_n15_with_clear_tail(key: bytes = KEY) -> bytes:
    plaintext = reference_application_block()
    iv = M_FIELD + IDENT + bytes((VERSION, DEVICE_TYPE)) + bytes((ACCESS,)) * 8
    ciphertext = reference_cbc_encrypt(key, iv, plaintext)
    configuration = (5 << 8) | (15 << 4)
    tpdu = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
            + ciphertext + b"\x2f")
    return reference_stripped(tpdu)


def reference_mode10() -> bytes:
    # Z=1, mode 10, N=0; CFE: tag-size=1 (8 bytes), KDF-A, KeyID 0.
    configuration = (10 << 8) | 0x2000
    cfe = (0x0110).to_bytes(2, "little")
    counter = bytes.fromhex("04030201")
    tpdu = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
            + cfe + counter + b"\xa5" * 8)
    return reference_stripped(tpdu)


def reference_mode13() -> bytes:
    # Current OMS Annex F fixes N=FF.  CFE protocol type 1 is followed by a
    # complete empty TLS 1.2 application-data record header.
    configuration = (13 << 8) | 0x00FF
    tls_record = bytes.fromhex("1703030000")
    tpdu = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
            + b"\x01" + tls_record)
    return reference_stripped(tpdu)


def reference_wired_mode5(value: int = 123456789, key: bytes = KEY) -> bytes:
    plaintext = reference_application_block(value)
    iv = M_FIELD + IDENT + bytes((VERSION, DEVICE_TYPE)) + bytes((ACCESS,)) * 8
    ciphertext = reference_cbc_encrypt(key, iv, plaintext)
    configuration = (5 << 8) | (1 << 4)
    # Long TPL CI=72 carries ID, manufacturer, version and type before its
    # ACC/STS/CF header, providing the address required by the mode-5 IV.
    tpl_after_ci = (IDENT + M_FIELD + bytes((VERSION, DEVICE_TYPE, ACCESS, 0))
                    + configuration.to_bytes(2, "little") + ciphertext)
    return reference_wired_long(0x53, 0x01, 0x72, tpl_after_ci)


def reference_mode9(value: int = 123456789, key: bytes = KEY) -> bytes:
    """EN 13757-7 mode-9 GCM telegram using a 96-bit truncated GCM tag."""
    counter = bytes.fromhex("04030201")
    key_version = 2
    encrypted = b"\x04\x03" + value.to_bytes(4, "little", signed=True)
    clear = b"\x02\x13" + (1234).to_bytes(2, "little")
    # Mode 9, tag present, key-version present, two-byte E/U lengths, KDF-A,
    # and key id 3.  Bit 15 (reserved) remains clear.
    configuration = (9 << 8) | 0x2000 | 0x4000 | 0x0040 | 0x0080 | 0x0010 | 3
    e_raw = len(encrypted).to_bytes(2, "little")
    u_raw = len(clear).to_bytes(2, "little")
    optional = bytes((key_version,)) + e_raw + u_raw
    nonce = (M_FIELD + IDENT + bytes((VERSION, DEVICE_TYPE))
             + int.from_bytes(counter, "little").to_bytes(4, "big"))
    aad = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
           + optional + clear)
    encryption_key = reference_kdf_a(key, 0x00, counter)
    encryptor = Cipher(algorithms.AES128(encryption_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(encrypted) + encryptor.finalize()
    tag = encryptor.tag[:12]
    tpdu = (bytes((0x7A, ACCESS, 0)) + configuration.to_bytes(2, "little")
            + optional + counter + ciphertext + clear + tag)
    return reference_stripped(tpdu)


def assert_clean_or_declared(callable_):
    try:
        callable_()
    except wmbus.SecMeterWMBusError:
        pass


def test_crc16_en13757_published_check_value_and_independent_reference():
    # Catalogue/TI check value for CRC-16/EN-13757.
    assert reference_crc16_en13757(b"123456789") == 0xC2B7
    assert wmbus.crc16_en13757(b"123456789") == 0xC2B7
    for raw in (b"", b"\0", bytes(range(32)), PUBLISHED_CLEAR[:10]):
        assert wmbus.crc16_en13757(raw) == reference_crc16_en13757(raw)


def test_wired_ack_short_and_long_frames_from_hand_layout():
    assert wmbus.parse_wired(b"\xe5")["frame_type"] == "ack"

    short = wmbus.parse_wired(reference_wired_short(0x40, 0x01))
    assert short["frame_type"] == "short"
    assert short["control"] == 0x40
    assert short["address"] == 0x01

    frame = reference_wired_long(0x53, 0x01, 0x51, b"\xaa\x55")
    long = wmbus.parse_wired(frame)
    assert long["frame_type"] == "long"
    assert long["control"] == 0x53
    assert long["address"] == 0x01
    assert long["ci"] == 0x51
    assert long["data_hex"] == "aa55"

    for changed in (
        frame[:2] + bytes((frame[2] ^ 1,)) + frame[3:],  # duplicate L mismatch
        frame[:-2] + bytes((frame[-2] ^ 1, frame[-1])),  # checksum mismatch
        frame[:-1] + b"\x17",                           # wrong stop
        frame + b"\x00",                                # trailing byte
    ):
        with pytest.raises(wmbus.SecMeterWMBusError):
            wmbus.parse_wired(changed)


def test_published_wmbusmeters_clear_telegram_stripped_and_format_a():
    report = wmbus.parse_wmbus(PUBLISHED_CLEAR, framing="stripped")
    assert report["protocol"] == "wireless-m-bus"
    assert report["dll"]["length"] == 0x23
    assert report["dll"]["control"] == 0x44
    assert report["dll"]["manufacturer"] == "LAS"
    assert report["dll"]["manufacturer_code"] == 0x3033
    assert report["dll"]["identification"] == "00010206"
    assert report["tpl"]["ci"] == 0x7A
    assert report["tpl"]["access_number"] == 0x8E
    assert report["tpl"]["security_mode"] == 0
    assert [row["value"] for row in report["records"]] == [4711, 1234]

    encoded = reference_format_a(PUBLISHED_CLEAR)
    framed = wmbus.parse_wmbus(encoded, framing="format-a")
    assert framed["dll"] == report["dll"]
    assert framed["tpl"] == report["tpl"]
    assert framed["records"] == report["records"]

    damaged = bytearray(encoded)
    damaged[10] ^= 1  # first block's transmitted CRC, not a payload byte
    with pytest.raises(wmbus.SecMeterWMBusError):
        wmbus.parse_wmbus(bytes(damaged), framing="format-a")


def test_second_published_wmbusmeters_analyzer_vector_and_format_b_auto():
    # Values shown by wmbusmeters' public analyzer for this exact telegram:
    # SEN 33225544, total volume 123.529 m3, instantaneous flow 0 m3/h.
    report = wmbus.parse_wmbus(PUBLISHED_ANALYZE, framing="stripped")
    assert report["dll"]["manufacturer"] == "SEN"
    assert report["dll"]["identification"] == "33225544"
    assert [row["value"] for row in report["records"]] == [123529, 0]
    assert [row["scaled_value"] for row in report["records"]] == pytest.approx([123.529, 0.0])
    assert [row["unit"] for row in report["records"]] == ["m3", "m3/h"]

    encoded = reference_format_b(PUBLISHED_ANALYZE)
    explicit = wmbus.parse_wmbus(encoded, framing="format-b")
    automatic = wmbus.parse_wmbus(encoded, framing="auto")
    assert explicit["framing"] == automatic["framing"] == "format-b"
    assert explicit["wire_length_field"] == len(encoded) - 1
    assert explicit["records"] == report["records"] == automatic["records"]

    damaged = bytearray(encoded)
    damaged[-1] ^= 1
    with pytest.raises(wmbus.SecMeterWMBusError):
        wmbus.parse_wmbus(bytes(damaged), framing="format-b")


def test_dif_vif_records_have_documented_little_endian_values_and_scales():
    # Record 1: 32-bit integer, VIF 03 => 10^0 Wh.
    # Record 2: 16-bit integer, VIF 13 => 10^-3 m^3.
    raw = (b"\x2f\x04\x03" + (123456789).to_bytes(4, "little", signed=True)
           + b"\x02\x13" + (1234).to_bytes(2, "little"))
    rows = wmbus.parse_records(raw)
    assert [row["value"] for row in rows] == [123456789, 1234]
    assert rows[0]["dif"] == 0x04 and rows[0]["vif"] == 0x03
    assert rows[0]["unit"] == "Wh" and rows[0]["exponent"] == 0
    assert rows[0]["scaled_value"] == 123456789
    assert rows[1]["dif"] == 0x02 and rows[1]["vif"] == 0x13
    assert rows[1]["unit"] == "m3" and rows[1]["exponent"] == -3
    assert rows[1]["scaled_value"] == pytest.approx(1.234)


def test_mode5_cbc_is_oracled_by_cryptography_and_not_claimed_authenticated():
    frame = reference_mode5()
    report = wmbus.parse_wmbus(frame, framing="stripped", key=KEY)
    assert report["tpl"]["security_mode"] == 5
    assert report["security"]["mode"] == 5
    assert report["security"]["authenticated"] is False
    assert report["security"]["decrypted"] is True
    assert report["application_hex"] == reference_application_block().hex()
    assert [row["value"] for row in report["records"]] == [123456789]

    # A key is optional for structural inspection, but unauthenticated ciphertext
    # must never be exposed as decoded records.
    locked = wmbus.parse_wmbus(frame, framing="stripped")
    assert locked["security"]["decrypted"] is False
    assert not locked.get("records")
    with pytest.raises(wmbus.SecMeterWMBusError):
        wmbus.parse_wmbus(frame, framing="stripped", key=bytes(reversed(KEY)))


def test_mode5_zero_encrypted_blocks_parses_clear_records_without_a_key():
    report = wmbus.parse_wmbus(reference_mode5_clear(), framing="stripped")
    assert report["tpl"]["security_mode"] == 5
    assert report["tpl"]["encrypted_block_count"] == 0
    assert report["security"]["decrypted"] is True
    assert report["security"]["authenticated"] is False
    assert [row["value"] for row in report["records"]] == [123456789]


def test_mode7_kdf_cbc_and_afl_cmac_against_cryptography_oracle():
    frame = reference_mode7()
    report = wmbus.parse_wmbus(frame, framing="stripped", key=KEY)
    assert report["afl"]["fragment_control"] == 0x2E00
    assert report["afl"]["message_counter"] == 0x01020304
    assert report["afl"]["authentication_type"] == 5
    assert report["afl"]["key_id"] == 0
    assert report["afl"]["key_derivation"] == 1
    assert report["afl"]["key_version"] == 1
    assert report["tpl"]["security_mode"] == 7
    assert report["security"]["profile"] == "OMS-B"
    assert report["security"]["kdf"] == 1
    assert report["security"]["authenticated"] is True
    assert report["security"]["decrypted"] is True
    assert report["application_hex"] == reference_application_block().hex()
    assert [row["value"] for row in report["records"]] == [123456789]

    locked = wmbus.parse_wmbus(frame, framing="stripped")
    assert locked["security"]["authenticated"] is False
    assert locked["security"]["decrypted"] is False
    assert locked["records"] == []

    # The AFL tag precedes the TPDU; mutate it without touching any lengths.
    tampered = bytearray(frame)
    tag_start = 10 + 2 + 2 + 1 + 2 + 4
    tampered[tag_start] ^= 0x80
    with pytest.raises(wmbus.SecMeterWMBusError, match="authentication tag"):
        wmbus.parse_wmbus(bytes(tampered), framing="stripped", key=KEY)

    bad_ki = bytearray(frame)
    bad_ki[15] |= 0x40  # KI reserved bit 6
    with pytest.raises(wmbus.SecMeterWMBusError, match="reserved AFL key-information"):
        wmbus.parse_wmbus(bytes(bad_ki), framing="stripped", key=KEY)


def test_mode7_cf_padding_is_removed_only_after_valid_cmac():
    frame, unpadded = reference_mode7_with_padding(valid=True)
    report = wmbus.parse_wmbus(frame, framing="stripped", key=KEY)
    assert report["tpl"]["configuration"] & 0x0008
    assert report["security"]["authenticated"] is True
    assert report["security"]["padding_removed"] == 8
    assert report["application_hex"] == unpadded.hex()
    assert [row["value"] for row in report["records"]] == [654321]

    malformed, _ = reference_mode7_with_padding(valid=False)
    with pytest.raises(wmbus.SecMeterWMBusError, match="padding is invalid"):
        wmbus.parse_wmbus(malformed, framing="stripped", key=KEY)


def test_oms_b_message_length_is_bounded_and_matches_unfragmented_tpdu():
    valid = wmbus.parse_wmbus(reference_mode7_with_message_length(),
                              framing="stripped", key=KEY)
    assert valid["afl"]["message_length"] == 22  # CI+short TPL+CFE+one AES block
    assert valid["security"]["authenticated"] is True
    assert [row["value"] for row in valid["records"]] == [8080]

    # The consistency check is structural and applies even without a key.
    with pytest.raises(wmbus.SecMeterWMBusError, match="message length disagrees"):
        wmbus.parse_wmbus(reference_mode7_with_message_length(23), framing="stripped")
    with pytest.raises(wmbus.SecMeterWMBusError, match="16 KiB"):
        wmbus.parse_wmbus(reference_mode7_with_message_length(16 * 1024 + 1), framing="stripped")


def test_fragment_mcl_is_global_while_fcl_presence_is_per_fragment():
    # First fragment: MCL says the complete message has KI and a MAC, while
    # neither field occurs in this fragment's FCL.  This asymmetry is valid.
    fcl = 0x6001  # MF, MCL present, fragment id 1
    afl = b"\x90\x03" + fcl.to_bytes(2, "little") + b"\x15"
    clear_tpdu = b"\x7a\x21\x00\x00\x00\x04\x03\x01\x00\x00\x00"
    report = wmbus.parse_wmbus(reference_stripped(afl + clear_tpdu), framing="stripped")
    assert report["afl"]["more_fragments"] is True
    assert report["afl"]["fragment_id"] == 1

    # The converse is impossible: a fragment cannot contain KI when the
    # message-wide MCL says that no KI exists.
    bad_fcl = 0x6201
    bad_afl = (b"\x90\x05" + bad_fcl.to_bytes(2, "little") + b"\x05"
               + (0x0110).to_bytes(2, "little"))
    with pytest.raises(wmbus.SecMeterWMBusError, match="key information presence"):
        wmbus.parse_wmbus(reference_stripped(bad_afl + clear_tpdu), framing="stripped")


def test_mode9_kdf_gcm_aad_and_tag_against_cryptography_oracle():
    frame = reference_mode9()
    report = wmbus.parse_wmbus(frame, framing="stripped", key=KEY)
    assert report["tpl"]["security_mode"] == 9
    assert report["security"]["standard_scope"] == "EN-13757-7"
    assert report["security"]["message_counter"] == 0x01020304
    assert report["security"]["key_version"] == 2
    assert report["security"]["key_id"] == 3
    assert report["security"]["authenticated"] is True
    assert report["security"]["decrypted"] is True
    expected_application = (b"\x04\x03" + (123456789).to_bytes(4, "little", signed=True)
                            + b"\x02\x13" + (1234).to_bytes(2, "little"))
    assert report["application_hex"] == expected_application.hex()
    assert [row["value"] for row in report["records"]] == [123456789, 1234]

    locked = wmbus.parse_wmbus(frame, framing="stripped")
    assert locked["security"]["authenticated"] is False
    assert locked["security"]["decrypted"] is False
    assert locked["records"] == []

    tampered = bytearray(frame)
    tampered[-1] ^= 1
    with pytest.raises(wmbus.SecMeterWMBusError, match="GCM authentication"):
        wmbus.parse_wmbus(bytes(tampered), framing="stripped", key=KEY)


def test_secured_wired_long_tpl_uses_the_explicit_supplied_key():
    frame = reference_wired_mode5()
    report = wmbus.parse_wired(frame, key=KEY)
    assert report["frame_type"] == "long"
    assert report["tpl"]["ci"] == 0x72
    assert report["tpl"]["address"]["identification"] == "01020304"
    assert report["security"]["mode"] == 5
    assert report["security"]["decrypted"] is True
    assert [row["value"] for row in report["records"]] == [123456789]

    locked = wmbus.parse_wired(frame)
    assert locked["security"]["decrypted"] is False
    assert locked["records"] == []


def test_n15_rejects_any_short_clear_tail_instead_of_flooring_blocks():
    frame = reference_mode5_n15_with_clear_tail()
    with pytest.raises(wmbus.SecMeterWMBusError, match="N=15"):
        wmbus.parse_wmbus(frame, framing="stripped", key=KEY)
    # Structural rejection does not depend on possessing the key.
    with pytest.raises(wmbus.SecMeterWMBusError, match="N=15"):
        wmbus.parse_wmbus(frame, framing="stripped")


@pytest.mark.parametrize(("frame", "mode", "profile", "algorithm"), [
    (reference_mode10(), 10, "OMS-D", "AES-CCM"),
    (reference_mode13(), 13, "OMS-C", "TLS-1.2"),
])
def test_next_generation_mode_recognition_requires_its_header(frame, mode, profile, algorithm):
    report = wmbus.parse_wmbus(frame, framing="stripped")
    assert report["tpl"]["security_mode"] == mode
    assert report["security"]["profile"] == profile
    assert report["security"]["algorithm"] == algorithm
    assert report["security"]["decryption_supported"] is False
    assert report["records"] == []
    if mode == 10:
        assert report["security"]["kdf"] == 1
        assert report["security"]["authentication_tag_size"] == 8
        assert report["security"]["message_counter"] == 0x01020304
    else:
        assert report["security"]["protocol_name"] == "TLSPROT"
        assert report["security"]["tls_version"] == "1.2"

    # The mode bits alone are not sufficient evidence for an OMS profile.
    bare = reference_stripped(bytes((0x7A, ACCESS, 0))
                               + ((mode << 8) | (0x2000 if mode == 10 else 0x00FF)).to_bytes(2, "little"))
    with pytest.raises(wmbus.SecMeterWMBusError):
        wmbus.parse_wmbus(bare, framing="stripped")


def test_dife_storage_tariff_and_subunit_bits_follow_en13757_layout():
    # DIF extension set, then DIFE: storage bits=5, tariff bits=2, subunit=1.
    # The base DIF storage LSB is zero, so complete storage number is 5 << 1.
    row = wmbus.parse_records(
        b"\x84\x65\x03" + (0x01020304).to_bytes(4, "little")
    )[0]
    assert row["difes"] == [0x65]
    assert row["storage_number"] == 10
    assert row["tariff"] == 2
    assert row["subunit"] == 1
    assert row["value"] == 0x01020304


def test_truncation_random_and_wrong_types_never_leak_stdlib_exceptions():
    valid_calls = (
        (wmbus.parse_wired, reference_wired_long(0x53, 1, 0x51, b"\xaa"), {}),
        (wmbus.parse_wmbus, PUBLISHED_CLEAR, {"framing": "stripped"}),
        (wmbus.parse_wmbus, reference_format_a(PUBLISHED_CLEAR), {"framing": "format-a"}),
        (wmbus.parse_wmbus, reference_format_b(PUBLISHED_ANALYZE), {"framing": "format-b"}),
        (wmbus.parse_wmbus, reference_mode5(), {"framing": "stripped", "key": KEY}),
        (wmbus.parse_wmbus, reference_mode7(), {"framing": "stripped", "key": KEY}),
        (wmbus.parse_wmbus, reference_mode9(), {"framing": "stripped", "key": KEY}),
        (wmbus.parse_records, b"\x04\x03\x15\xcd\x5b\x07", {}),
    )
    for parser, raw, kwargs in valid_calls:
        for end in range(len(raw)):
            assert_clean_or_declared(lambda parser=parser, raw=raw, end=end, kwargs=kwargs:
                                     parser(raw[:end], **kwargs))
        assert_clean_or_declared(lambda parser=parser, raw=raw, kwargs=kwargs:
                                 parser(raw + b"\xff", **kwargs))

    rng = random.Random(0x13757)
    malformed = [b"", b"\xff" * 256, b"\x68", b"\x10", b"\xe5\0"]
    malformed.extend(rng.randbytes(rng.randrange(0, 192)) for _ in range(300))
    for raw in malformed:
        assert_clean_or_declared(lambda raw=raw: wmbus.parse_wired(raw))
        assert_clean_or_declared(lambda raw=raw: wmbus.parse_records(raw))
        assert_clean_or_declared(lambda raw=raw: wmbus.parse_wmbus(raw, framing="stripped"))
        assert_clean_or_declared(lambda raw=raw: wmbus.parse_wmbus(raw, framing="format-a"))

    for bad in (None, True, 1, "00", [], {}):
        for parser in (wmbus.crc16_en13757, wmbus.parse_wired, wmbus.parse_records):
            with pytest.raises(wmbus.SecMeterWMBusError):
                parser(bad)
        with pytest.raises(wmbus.SecMeterWMBusError):
            wmbus.parse_wmbus(bad)


def test_cli_guard_and_local_file(tmp_path, capsys, monkeypatch):
    artifact = tmp_path / "telegram.bin"
    artifact.write_bytes(PUBLISHED_CLEAR)
    assert wmbus.main([str(artifact), "--kind", "wmbus", "--framing", "stripped"]) == 0
    assert '"wireless-m-bus"' in capsys.readouterr().out
    assert wmbus.main(["--help"]) == 0
    assert wmbus.main(["--not-an-option"]) == 2
    assert wmbus.main([str(tmp_path / "missing")]) == 2

    def unusual_exit(*_args, **_kwargs):
        raise SystemExit("not-an-int")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", unusual_exit)
    assert wmbus.main([]) == 2

