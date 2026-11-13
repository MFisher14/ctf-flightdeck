from __future__ import annotations

import base64
import hashlib

import base58
import base91
import pytest

import codec_decoders as C


PAYLOAD = b"CSCTF codec depth 2026"


def test_python_codec_discovery_and_roundtrip_decline():
    names = C.python_character_codecs()
    assert "utf-8" in names
    assert "utf-16" in names
    assert "utf-32" in names
    assert "cp037" in names
    assert len(names) >= 80
    for name in names:
        encoded = "A".encode(name)
        candidate = C.decode_python_codec(encoded, name)
        assert candidate is not None and candidate.payload == b"A", name

    utf16 = "Snowman \N{SNOWMAN}".encode("utf-16")
    got = C.decode_python_codec(utf16, "utf-16")
    assert got and got.payload.decode() == "Snowman \N{SNOWMAN}"
    assert C.decode_python_codec(b"\xffbroken", "utf-8") is None

    ebcdic = "EBCDIC 2026".encode("cp037")
    got = C.decode_python_codec(ebcdic, "cp037")
    assert got and got.payload == b"EBCDIC 2026"
    candidates = C.decode_character_encodings(ebcdic, ["utf-8", "cp037"])
    assert [(item.codec, item.payload) for item in candidates] == [("charset:cp037", b"EBCDIC 2026")]


def _ita2_bits(text: str) -> bytes:
    letters = {value: key for key, value in C._ITA2_LTRS.items()}
    figures = {value: key for key, value in C._ITA2_FIGS.items()}
    table = letters
    values = []
    for char in text:
        if char in table:
            values.append(table[char])
            continue
        if char in figures:
            values.append(27)
            table = figures
        elif char in letters:
            values.append(31)
            table = letters
        else:
            raise AssertionError(char)
        values.append(table[char])
    return " ".join(f"{value:05b}" for value in values).encode()


def test_ita2_positive_and_corrupt_decline():
    assert any(item.payload == b"HELLO 42" for item in C.decode_ita2(_ita2_bits("HELLO 42")))
    assert C.decode_ita2(b"00001 101") == []


def test_morse_variants_and_corrupt_decline():
    assert any(item.payload == b"SOS 2026" for item in C.decode_morse(
        b"... --- ... / ..--- ----- ..--- -...."
    ))
    assert any(item.payload == b"SOS" for item in C.decode_morse(b"000 111 000"))
    assert C.decode_morse(b"... --- ... ..-.-") == []


def test_polybius_tap_and_corrupt_decline():
    assert C.decode_polybius(b"11 12 13")[0].payload == b"ABC"
    assert C.decode_tap_code(b"11-12-13")[0].payload == b"ABC"
    assert C.decode_polybius(b"11 16") == []
    assert C.decode_tap_code(b"11 66") == []


def test_bacon_and_corrupt_decline():
    encoded = " ".join(f"{ord(char) - 65:05b}".translate(str.maketrans("01", "AB")) for char in "HELLO")
    assert any(item.codec == "bacon:26" and item.payload == b"HELLO" for item in C.decode_bacon(encoded.encode()))
    assert C.decode_bacon(b"ABABA ABAB") == []


def test_dtmf_multitap_and_corrupt_decline():
    got = C.decode_dtmf_text(b"44 33 555 555 666")
    assert got and got[0].payload == b"HELLO"
    assert C.decode_dtmf_text(b"4433555") == []
    assert C.decode_dtmf_text(b"22222 3") == []


def _encoded_samples(payload: bytes):
    b58 = C.BASE58_ALPHABETS["base58"]
    checked = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return {
        "base16": base64.b16encode(payload),
        "base32": base64.b32encode(payload).rstrip(b"="),
        "base32hex": base64.b32hexencode(payload).rstrip(b"="),
        "crockford32": C._encode_custom_base32(payload, C.CROCKFORD32_ALPHABET).encode(),
        "zbase32": C._encode_custom_base32(payload, C.ZBASE32_ALPHABET).encode(),
        "base45": C._encode_base45(payload).encode(),
        "base58": base58.b58encode(payload),
        "base58:flickr": C._numeric_encode(payload, C.BASE58_ALPHABETS["base58:flickr"]).encode(),
        "base58:ripple": C._numeric_encode(payload, C.BASE58_ALPHABETS["base58:ripple"]).encode(),
        "base58check": C._numeric_encode(checked, b58).encode(),
        "base62": C._numeric_encode(payload, C.BASE62_ALPHABETS["base62"]).encode(),
        "base62:lower": C._numeric_encode(payload, C.BASE62_ALPHABETS["base62:lower"]).encode(),
        "base62:letters": C._numeric_encode(payload, C.BASE62_ALPHABETS["base62:letters"]).encode(),
        "base64": base64.b64encode(payload).rstrip(b"="),
        "base64url": base64.urlsafe_b64encode(payload).rstrip(b"="),
        "ascii85": base64.a85encode(payload),
        "base85": base64.b85encode(payload),
        "z85": C._encode_z85(payload + b"\x00" * ((-len(payload)) % 4)).encode(),
        "base91": base91.encode(payload).encode(),
        "base92": C._encode_base92(payload).encode(),
        "base122": C._encode_base122(payload),
    }


@pytest.mark.parametrize("name", C.BASE_NAMES)
def test_every_base_decoder_positive_and_corrupt_decline(name):
    expected = PAYLOAD + (b"\x00" * ((-len(PAYLOAD)) % 4) if name == "z85" else b"")
    encoded = _encoded_samples(PAYLOAD)[name]
    got = C.decode_base(encoded, name)
    assert got is not None and got.payload == expected

    corrupt = {
        "base16": b"0G",
        "base32": b"ABC!",
        "base32hex": b"ABCZ",
        "crockford32": b"ABC*",
        "zbase32": b"abc0",
        "base45": b"AB~",
        "base58": b"0OIl",
        "base58:flickr": b"0OIl",
        "base58:ripple": b"0OIl",
        "base58check": encoded[:-1] + (b"1" if encoded[-1:] != b"1" else b"2"),
        "base62": b"abc!",
        "base62:lower": b"abc!",
        "base62:letters": b"abc!",
        "base64": b"%%%%",
        "base64url": b"%%%%",
        "ascii85": b"~~~~",
        "base85": b"~~~~",
        "z85": b"abc?",
        "base91": b"abc\\",
        "base92": b"abc\"",
        "base122": b"\xc2",
    }[name]
    assert C.decode_base(corrupt, name) is None


def test_installed_base_libraries_cross_check_and_registry():
    assert C.decode_base(base58.b58encode(PAYLOAD), "base58").payload == PAYLOAD
    assert C.decode_base(base91.encode(PAYLOAD).encode(), "base91").payload == PAYLOAD
    assert ("base64", PAYLOAD) in C.steps(base64.b64encode(PAYLOAD))
    assert C.step_fn("missing") is None
    ambiguous = C.step_fn("bacon")
    # HELLO is valid in both Bacon alphabets with different readings, so the adapter must not choose.
    encoded = "".join(f"{ord(char) - 65:05b}" for char in "HELLO").translate(str.maketrans("01", "AB"))
    assert ambiguous and ambiguous(encoded.encode()) is None


def test_uncommon_bitpacking_length_sweep():
    for length in range(1, 97):
        payload = bytes((length * 11 + index * 37) & 255 for index in range(length))
        samples = {
            "base92": C._encode_base92(payload).encode(),
            "base122": C._encode_base122(payload),
            "crockford32": C._encode_custom_base32(payload, C.CROCKFORD32_ALPHABET).encode(),
            "zbase32": C._encode_custom_base32(payload, C.ZBASE32_ALPHABET).encode(),
        }
        for name, encoded in samples.items():
            candidate = C.decode_base(encoded, name)
            assert candidate is not None and candidate.payload == payload, (name, length)
