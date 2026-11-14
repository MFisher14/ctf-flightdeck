"""Independent payment-protocol vectors and fail-closed parser fuzzing.

Oracles and semantics:

* ISO/IEC 7816-4 APDU cases and status-word layout (Oracle Java Card summary)
* EMV Book 3 response-template, AFL, DOL, and issuer-authentication layouts
* ``psec``'s independent ISO 9564 PIN-block implementation
* AWS Payment Cryptography's published ANSI X9.143/TR-31 export example

No fixture is produced by the engines under test.
"""
from __future__ import annotations

import random

import pytest
from Crypto.Cipher import DES3
from psec import pinblock as pin_oracle

import payment_hw_apdu as apdu
import payment_hw_emv as emv
import payment_hw_pinblock as pinblock
import payment_hw_tr31 as tr31


AWS_TR31_D = (
    "D0144K0AB00E0000A24D3ACF3005F30A6E31D533E07F2E1B17A2A003B338B1E79"
    "E5B3AD4FBF7850FACF9A3784489581A543C84816C8D3542AE888CE6D4EDDFD09C39957B131617BC"
)
# Synthetic ISO/IEC 7813 PAN: 15 payload digits plus independently calculated
# Luhn check digit 2.  It is test data, not a real account number.
PAN = "1234567890123452"


def _iso7813_luhn_valid(value: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(value)):
        digit = int(char)
        if index % 2:
            digit *= 2
        total += digit // 10 + digit % 10
    return total % 10 == 0


def _tlv(tag: str, value: bytes) -> bytes:
    """Minimal independent definite-length BER encoder for synthetic vectors."""
    if len(value) < 0x80:
        length = bytes((len(value),))
    else:
        width = (len(value).bit_length() + 7) // 8
        length = bytes((0x80 | width,)) + len(value).to_bytes(width, "big")
    return bytes.fromhex(tag) + length + value


def _bit_flips(value: bytes) -> list[bytes]:
    result = []
    for index in range(len(value)):
        changed = bytearray(value)
        changed[index] ^= 1 << (index % 8)
        result.append(bytes(changed))
    return result


def _text_flips(value: str) -> list[str]:
    result = []
    for index in range(len(value)):
        codepoint = ord(value[index])
        replacement = chr(32 + ((codepoint - 31) % 95))
        result.append(value[:index] + replacement + value[index + 1:])
    return result


def _assert_closed(call, declared, label: str) -> None:
    """Permit a clean result or exactly the parser's declared exception."""
    try:
        call()
    except declared as exc:
        assert type(exc) is declared, f"{label}: exception subclass escaped contract"
    except Exception as exc:  # pragma: no cover - this is the regression detector
        pytest.fail(f"{label}: leaked {type(exc).__name__}: {exc}")


def test_vector_lock_iso7816_command_response_and_trace():
    # ISO 7816 case 4S SELECT by DF name: Lc=7, AID, Le=00 meaning 256.
    command = bytes.fromhex("00A4040007A000000003101000")
    parsed = apdu.parse_command(command)
    assert parsed["case"] == "4S"
    assert parsed["cla"] == 0 and parsed["ins"] == 0xA4
    assert parsed["lc"] == 7 and parsed["le"] == 256
    assert parsed["data_hex"] == "A0000000031010"
    assert parsed["command"] == "SELECT" and parsed["selection"] == "DF name"

    # R-APDU is response data followed by the two status bytes SW1/SW2.
    response = bytes.fromhex("6F008407A00000000310109000")
    reply = apdu.parse_response(response)
    assert reply["data_hex"] == "6F008407A0000000031010"
    assert reply["sw"] == "9000" and reply["success"] is True

    exchange = apdu.parse_trace(
        "> 00 A4 04 00 07 A0 00 00 00 03 10 10 00\n"
        "< 6F 00 84 07 A0 00 00 00 03 10 10 90 00\n"
    )
    assert len(exchange) == 1
    assert exchange[0]["command"] == parsed
    assert exchange[0]["response"] == reply


def test_vector_lock_emv_templates_afl_dol_mapping_and_issuer_authentication():
    # EMV format-1 GENERATE AC: CID || ATC || AC || optional IAD.
    ac = bytes.fromhex("0102030405060708")
    iad = bytes.fromhex("06010A03A00000")
    cryptogram = _tlv("80", b"\x80\x00\x2A" + ac + iad)
    parsed = emv.parse_cryptogram(cryptogram)
    assert parsed["cryptogram_type"] == "ARQC"
    assert parsed["atc"] == 42
    assert parsed["application_cryptogram"] == "0102030405060708"
    assert parsed["issuer_application_data"] == "06010A03A00000"
    assert parsed["cryptogram_verified"] is False

    # AFL bytes: SFI 2 (2 << 3), records 1..3, two records in offline auth.
    afl = bytes((0x10, 1, 3, 2))
    assert emv.parse_afl(afl) == [{
        "sfi": 2,
        "first_record": 1,
        "last_record": 3,
        "offline_authentication_records": 2,
    }]
    gpo = _tlv("80", bytes.fromhex("5800") + afl)
    assert emv.parse_gpo(gpo) == {
        "template": "80",
        "aip": "5800",
        "afl": [{
            "sfi": 2,
            "first_record": 1,
            "last_record": 3,
            "offline_authentication_records": 2,
        }],
        "fields": {"82": "5800", "94": "10010302"},
    }

    # DOL is tag + one-byte requested length, not BER-TLV.
    dol = bytes.fromhex("9F02065F2A029A03")
    transaction = bytes.fromhex("0000000012340840261106")
    spec = emv.parse_dol(dol)
    assert [(row["tag"], row["length"], row["offset"]) for row in spec] == [
        ("9F02", 6, 0), ("5F2A", 2, 6), ("9A", 3, 8),
    ]
    mapped = emv.map_dol(dol, transaction)
    assert [(row["tag"], row["value"]) for row in mapped] == [
        ("9F02", "000000001234"), ("5F2A", "0840"), ("9A", "261106"),
    ]

    # EMV ARPC method 2: four-byte ARPC, four-byte CSU, optional proprietary bytes.
    issuer = emv.parse_issuer_authentication("0102030405060708AABB", 2)
    assert issuer["arpc"] == "01020304"
    assert issuer["card_status_update"] == "05060708"
    assert issuer["issuer_additional_data"] == "AABB"
    assert issuer["cryptogram_verified"] is False


def test_vector_lock_iso9564_clear_and_known_key(monkeypatch):
    # psec is an independent ISO 9564 implementation. Freeze only its random
    # filler source so formats 3/4 are reproducible.
    assert len(PAN) == 16 and _iso7813_luhn_valid(PAN)
    monkeypatch.setattr(pin_oracle._secrets, "choice", lambda choices: choices[0])
    monkeypatch.setattr(pin_oracle, "_urandom", lambda size: bytes(range(size)))
    vectors = [
        (0, pin_oracle.encode_pinblock_iso_0("1234", PAN), PAN),
        (1, bytes.fromhex("141234012345ABCD"), None),
        (2, pin_oracle.encode_pinblock_iso_2("1234"), None),
        (3, pin_oracle.encode_pinblock_iso_3("1234", PAN), PAN),
        (4, pin_oracle.encode_pin_field_iso_4("1234"), None),
    ]
    for format_number, block, pan in vectors:
        result = pinblock.decode_pin_block(block, format_number, pan)
        assert result["format"] == format_number
        assert result["pin"] == "1234" and result["pin_length"] == 4
        assert result["authenticated"] is False

    # Independently encrypt an ISO-2 clear block using supplied-key TDES-ECB.
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    clear = pin_oracle.encode_pinblock_iso_2("9876")
    encrypted = DES3.new(key, DES3.MODE_ECB).encrypt(clear)
    decrypted = pinblock.decrypt_pin_block(encrypted, 2, key)
    assert decrypted["pin"] == "9876"
    assert decrypted["cipher"] == "TDES-ECB"
    assert decrypted["input_kind"] == "encrypted_pin_block"


def test_vector_lock_published_aws_tr31_d_block():
    # AWS Payment Cryptography export-key documentation, ANSI X9.143/TR-31 D.
    parsed = tr31.parse_key_block(AWS_TR31_D)
    assert parsed["version"] == "D" and parsed["length"] == 144
    assert parsed["header"] == "D0144K0AB00E0000"
    assert parsed["key_usage"] == "K0"
    assert parsed["algorithm"] == "A"
    assert parsed["mode_of_use"] == "B"
    assert parsed["exportability"] == "E"
    assert parsed["ciphertext_bytes"] == 48
    assert parsed["mac"] == "AE888CE6D4EDDFD09C39957B131617BC"
    assert parsed["mac_bytes"] == 16 and parsed["authenticated"] is False


def test_fail_closed_fuzz_all_apdu_parse_entrypoints():
    rng = random.Random(0x7816)
    command = bytes.fromhex("00A4040007A000000003101000")
    response = bytes.fromhex("6F008407A00000000310109000")
    trace = ">00A4040007A000000003101000\n<6F008407A00000000310109000\n"

    command_cases = [b"", *[rng.randbytes(rng.randrange(96)) for _ in range(32)],
                     *[command[:end] for end in range(len(command))],
                     *_bit_flips(command), b"\0" * (apdu.MAX_COMMAND + 1)]
    response_cases = [b"", *[rng.randbytes(rng.randrange(96)) for _ in range(32)],
                      *[response[:end] for end in range(len(response))],
                      *_bit_flips(response), b"\0" * (apdu.MAX_RESPONSE + 1)]
    trace_cases = ["", *[
        "".join(chr(rng.randrange(32, 127)) for _ in range(rng.randrange(96)))
        for _ in range(32)
    ], *[trace[:end] for end in range(len(trace))], *_text_flips(trace),
                   "X" * (apdu.MAX_TRACE + 1)]

    for index, value in enumerate(command_cases):
        _assert_closed(lambda value=value: apdu.parse_command(value), apdu.APDUError, f"command[{index}]")
    for index, value in enumerate(response_cases):
        _assert_closed(lambda value=value: apdu.parse_response(value), apdu.APDUError, f"response[{index}]")
    for index, value in enumerate(trace_cases):
        _assert_closed(lambda value=value: apdu.parse_trace(value), apdu.APDUError, f"trace[{index}]")


def test_fail_closed_fuzz_all_emv_parse_entrypoints():
    rng = random.Random(0xE4)
    ac = bytes.fromhex("800B80002A0102030405060708")
    afl = bytes.fromhex("10010302")
    gpo = bytes.fromhex("8006580010010302")
    dol = bytes.fromhex("9F02065F2A029A03")
    transaction = bytes.fromhex("0000000012340840261106")
    issuer = bytes.fromhex("0102030405060708AABB")
    oversized = b"\0" * (emv.MAX_INPUT + 1)

    unary = [
        ("cryptogram", emv.parse_cryptogram, ac),
        ("afl", emv.parse_afl, afl),
        ("gpo", emv.parse_gpo, gpo),
        ("dol", emv.parse_dol, dol),
    ]
    for name, parser, valid in unary:
        cases = [b"", *[rng.randbytes(rng.randrange(96)) for _ in range(40)],
                 *[valid[:end] for end in range(len(valid))], *_bit_flips(valid), oversized]
        for index, value in enumerate(cases):
            _assert_closed(lambda parser=parser, value=value: parser(value),
                           emv.PaymentEMVError, f"{name}[{index}]")

    map_cases = [
        (b"", b""),
        *[(rng.randbytes(rng.randrange(40)), rng.randbytes(rng.randrange(40))) for _ in range(40)],
        *[(dol[:end], transaction) for end in range(len(dol))],
        *[(dol, transaction[:end]) for end in range(len(transaction))],
        *[(changed, transaction) for changed in _bit_flips(dol)],
        (oversized, b""),
    ]
    for index, (definition, data) in enumerate(map_cases):
        _assert_closed(lambda definition=definition, data=data: emv.map_dol(definition, data),
                       emv.PaymentEMVError, f"map_dol[{index}]")

    issuer_cases = [b"", *[rng.randbytes(rng.randrange(40)) for _ in range(40)],
                    *[issuer[:end] for end in range(len(issuer))],
                    *_bit_flips(issuer), oversized]
    for index, value in enumerate(issuer_cases):
        _assert_closed(lambda value=value: emv.parse_issuer_authentication(value, 2),
                       emv.PaymentEMVError, f"issuer[{index}]")


def test_fail_closed_fuzz_all_pinblock_parse_entrypoints():
    rng = random.Random(0x9564)
    clear = pin_oracle.encode_pinblock_iso_2("9876")
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    encrypted = DES3.new(key, DES3.MODE_ECB).encrypt(clear)

    decode_cases = [b"", *[rng.randbytes(8) for _ in range(64)],
                    *[clear[:end] for end in range(len(clear))],
                    *_bit_flips(clear), clear + b"\0"]
    for index, value in enumerate(decode_cases):
        _assert_closed(lambda value=value: pinblock.decode_pin_block(value, 2),
                       pinblock.PinBlockError, f"decode_pin_block[{index}]")

    decrypt_cases = [b"", *[rng.randbytes(8) for _ in range(64)],
                     *[encrypted[:end] for end in range(len(encrypted))],
                     *_bit_flips(encrypted), encrypted + b"\0"]
    for index, value in enumerate(decrypt_cases):
        _assert_closed(lambda value=value: pinblock.decrypt_pin_block(value, 2, key),
                       pinblock.PinBlockError, f"decrypt_pin_block[{index}]")


def test_fail_closed_fuzz_tr31_parse_entrypoint():
    rng = random.Random(0x31)
    random_blocks = [
        "".join(chr(rng.randrange(0, 256)) for _ in range(rng.randrange(256)))
        for _ in range(64)
    ]
    cases = ["", *random_blocks,
             *[AWS_TR31_D[:end] for end in range(len(AWS_TR31_D))],
             *_text_flips(AWS_TR31_D), "A" * (tr31.MAX_BLOCK + 1)]
    for index, value in enumerate(cases):
        _assert_closed(lambda value=value: tr31.parse_key_block(value),
                       tr31.PaymentHWTR31Error, f"parse_key_block[{index}]")
