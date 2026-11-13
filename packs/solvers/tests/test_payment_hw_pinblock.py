"""Independent psec oracle, published examples, and malformed-input tests."""

import json
import random

import pytest
import psec.pinblock as oracle
from Crypto.Cipher import DES3

import payment_hw_pinblock as P


PAN = "5544332211009966"


@pytest.mark.parametrize("pin", ["0000", "1234", "012345", "012345678901"])
def test_oracle_clear_formats(pin, monkeypatch):
    # Fix oracle randomness. The engine contains no encoder and does not use psec.
    monkeypatch.setattr(oracle._secrets, "choice", lambda seq: seq[0])
    monkeypatch.setattr(oracle, "_urandom", lambda n: bytes(range(n)))
    samples = [
        (0, oracle.encode_pinblock_iso_0(pin, PAN), PAN),
        (2, oracle.encode_pinblock_iso_2(pin), None),
        (3, oracle.encode_pinblock_iso_3(pin, PAN), PAN),
        (4, oracle.encode_pin_field_iso_4(pin), None),
    ]
    for fmt, block, pan in samples:
        result = P.decode_pin_block(block, fmt, pan)
        assert result["pin"] == pin
        assert result["pin_length"] == len(pin)
        assert result["authenticated"] is False


@pytest.mark.parametrize("fmt,hexblock,pin,pan", [
    # Literal published examples from psec's documentation.
    (0, "041277CDDEEFF669", "1234", PAN),
    (2, "241234FFFFFFFFFF", "1234", None),
    (2, "2C123456789012FF", "123456789012", None),
    (3, "341277EEEFCCB43C", "1234", PAN),
    (4, "441234AAAAAAAAAA548ED7FD65495950", "1234", None),
])
def test_published_examples(fmt, hexblock, pin, pan):
    assert P.decode_pin_block(bytes.fromhex(hexblock), fmt, pan)["pin"] == pin


def test_iso1_non_circular_reference():
    # ISO-1 control/length/PIN followed by transaction/random data, no PAN XOR.
    # This explicit nibble stream exercises random hexadecimal filler, not F padding.
    nibbles = [1, 6, 0, 0, 1, 2, 3, 4, 0, 1, 2, 3, 10, 11, 12, 13]
    block = bytes((a << 4) | b for a, b in zip(nibbles[::2], nibbles[1::2]))
    result = P.decode_pin_block(block, 1)
    assert result["pin"] == "001234"
    assert result["filler_hex"] == "0123ABCD"
    assert result["pan_binding"] is False


@pytest.mark.parametrize("keysize", [16, 24, 32])
@pytest.mark.parametrize("pan", ["1", "123456789012", "1234567890123456", "1234567890123456789"])
def test_iso4_two_stage_against_psec(keysize, pan, monkeypatch):
    monkeypatch.setattr(oracle, "_urandom", lambda n: bytes(range(n)))
    key = bytes(range(keysize))
    encrypted = oracle.encipher_pinblock_iso_4(key, "009876543210", pan)
    result = P.decrypt_pin_block(encrypted, 4, key, pan)
    assert result["pin"] == "009876543210"
    assert result["random_field_hex"] == "0001020304050607"
    assert result["pan_binding"] is True
    assert result["cipher"] == "AES-ISO4"


def test_iso4_published_ciphertext():
    result = P.decrypt_pin_block(
        bytes.fromhex("E4BE5B623AF7E006AC319E5B93544564"), 4,
        bytes.fromhex("00112233445566778899AABBCCDDEEFF"), "1234567890123456")
    assert result["pin"] == "1234"


@pytest.mark.parametrize("fmt", [0, 1, 2, 3])
@pytest.mark.parametrize("keysize", [16, 24])
def test_tdes_known_key(fmt, keysize, monkeypatch):
    monkeypatch.setattr(oracle._secrets, "choice", lambda seq: seq[-1])
    pan = PAN if fmt in (0, 3) else None
    if fmt == 0:
        clear = oracle.encode_pinblock_iso_0("9876", PAN)
    elif fmt == 1:
        clear = bytes.fromhex("149876012345ABCD")
    elif fmt == 2:
        clear = oracle.encode_pinblock_iso_2("9876")
    else:
        clear = oracle.encode_pinblock_iso_3("9876", PAN)
    key = bytes(range(keysize))
    cipher = DES3.new(key, DES3.MODE_ECB).encrypt(clear)
    assert P.decrypt_pin_block(cipher, fmt, key, pan)["pin"] == "9876"


@pytest.mark.parametrize("block,fmt,pan", [
    (None, 0, PAN), ("241234FFFFFFFFFF", 2, None), (1, 2, None),
    ([], 2, None), (b"", 2, None), (b"\x00" * 9, 0, PAN),
    (b"\x00" * 8, False, None), (b"\x00" * 8, "0", PAN),
    (b"\x00" * 8, [], PAN), (b"\x00" * 8, 5, None),
    (bytes.fromhex("241234FFFFFFFFFF"), 2, PAN),
    (bytes.fromhex("241234FFFFFFFFF0"), 2, None),
    (bytes.fromhex("241A34FFFFFFFFFF"), 2, None),
    (bytes.fromhex("23123FFFFFFFFFFF"), 2, None),
    (bytes.fromhex("2D1234567890123F"), 2, None),
    (bytes.fromhex("441234FFFFFFFFFF") * 2, 4, None),
    (bytes.fromhex("041277CDDEEFF669"), 0, "123456789012"),
    (bytes.fromhex("041277CDDEEFF669"), 0, "1" * 20),
    (bytes.fromhex("041277CDDEEFF669"), 0, "１" * 16),
    (bytes.fromhex("041277CDDEEFF669"), 0, []),
    (bytes.fromhex("041277CDDEEFF669"), 0, None),
])
def test_malformed_inputs_raise_declared_error(block, fmt, pan):
    with pytest.raises(P.PinBlockError):
        P.decode_pin_block(block, fmt, pan)


def test_format3_numeric_filler_rejected():
    # Direct independent XOR construction of a deliberately invalid field.
    bad = bytes.fromhex("3412340123456789")
    pan_field = bytes.fromhex("0000" + PAN[-13:-1])
    with pytest.raises(P.PinBlockError):
        P.decode_pin_block(bytes(a ^ b for a, b in zip(bad, pan_field)), 3, PAN)


@pytest.mark.parametrize("key", [None, "abc", b"", b"x" * 15, b"x" * 33, []])
def test_bad_keys(key):
    with pytest.raises(P.PinBlockError):
        P.decrypt_pin_block(b"\x00" * 16, 4, key, PAN)


def test_bad_decrypt_parameters():
    for fmt, block, key, pan in [
        (4, b"\x00" * 15, bytes(range(16)), PAN),
        (4, b"\x00" * 16, bytes(range(16)), None),
        (4, b"\x00" * 16, bytes(range(16)), ""),
        (1, b"\x00" * 8, bytes(range(16)), PAN),
        (0, b"\x00" * 8, b"\x00" * 16, PAN),
    ]:
        with pytest.raises(P.PinBlockError):
            P.decrypt_pin_block(block, fmt, key, pan)


def test_deterministic_random_malformed_blocks():
    rng = random.Random(9564)
    for fmt in range(5):
        for _ in range(100):
            block = rng.randbytes(16 if fmt == 4 else 8)
            try:
                result = P.decode_pin_block(block, fmt, PAN if fmt in (0, 3) else None)
                assert result["pin"].isascii() and result["pin"].isdigit()
            except P.PinBlockError:
                pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "block.hex"
    path.write_text("24 12 34 FF FF FF FF FF\n")
    assert P.main([str(path), "--hex", "--format", "2"]) == 0
    assert json.loads(capsys.readouterr().out)["pin"] == "1234"
    assert P.main([]) == 2
    assert P.main(["--help"]) == 0
    assert P.main([str(path), "--hex", "--format", "8"]) == 2
    path.write_bytes(b"\xff")
    assert P.main([str(path), "--hex", "--format", "2"]) == 2
    path.write_text("F")
    assert P.main([str(path), "--hex", "--format", "2"]) == 2
    path.write_text("24" * 3000)
    assert P.main([str(path), "--hex", "--format", "2"]) == 2
    assert P.main([str(path) + "missing", "--format", "2"]) == 2


def test_cli_known_key(tmp_path, capsys):
    path = tmp_path / "block.bin"
    path.write_bytes(bytes.fromhex("E4BE5B623AF7E006AC319E5B93544564"))
    assert P.main([str(path), "--format", "4", "--key", "00112233445566778899AABBCCDDEEFF",
                   "--pan", "1234567890123456"]) == 0
    assert json.loads(capsys.readouterr().out)["pin"] == "1234"
    assert P.main([str(path), "--format", "4", "--key", "xyz", "--pan", PAN]) == 2
