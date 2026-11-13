from __future__ import annotations

import sys
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "warmups"))
import exotic_codecs as codecs  # noqa: E402


def _dna(payload: bytes, alphabet: str = "ACGT") -> str:
    return "".join(alphabet[(byte >> shift) & 3] for byte in payload for shift in (6, 4, 2, 0))


def test_dna_2bit_exact_inverse_crc_and_declines() -> None:
    payload = b"CSCTF{DNA}"
    encoded = _dna(payload)
    got = codecs.decode_dna_2bit("\n".join((encoded[:20], encoded[20:])))
    assert got is not None and got.payload == payload and got.codec == "dna:2bit:ACGT"

    alternate = _dna(payload, "TGCA")
    got = codecs.decode_dna_2bit(alternate, alphabet="TGCA")
    assert got is not None and got.payload == payload
    binary = b"\x00\xff\x10"
    assert codecs.decode_dna_2bit(_dna(binary)) is None
    got = codecs.decode_dna_2bit(_dna(binary), expected_crc32=zlib.crc32(binary))
    assert got is not None and got.payload == binary and got.confidence == 1.0

    assert codecs.decode_dna_2bit(encoded + "N") is None
    assert codecs.decode_dna_2bit(encoded[:-1]) is None
    assert codecs.decode_dna_2bit(encoded, alphabet="AAAA") is None
    assert codecs.decode_dna_2bit(encoded, expected_crc32=True) is None
    assert codecs.decode_dna_2bit(1234) is None


def test_standard_codon_orf_and_corruption_declines() -> None:
    # ATG=M, GCT=A, TGG=W, TAA=stop.
    got = codecs.translate_codons("ATG GCT TGG TAA")
    assert got is not None and got.payload == b"MAW"
    assert codecs.translate_codons("GCT TGG TAA") is None
    assert codecs.translate_codons("ATG TAA TGG TAA") is None
    assert codecs.translate_codons("ATG GCT TGG") is None
    assert codecs.translate_codons("ATG GCN TAA") is None
    assert codecs.translate_codons("ATG GCT TGG", require_stop=False).payload == b"MAW"
    assert codecs.translate_codons("ATG GCT TGG TAA", require_stop=False).payload == b"MAW"
    assert codecs.translate_codons("ATG GCT TGG", require_start=1) is None


def _braille(text: str) -> str:
    inverse = {char: value for value, char in codecs._BRAILLE_G1.items() if char.isalpha()}
    digit_inverse = {digit: value for value, digit in codecs._BRAILLE_DIGITS.items()}
    out: list[str] = []
    numeric = False
    for char in text:
        if char == " ":
            out.append(chr(0x2800))
            numeric = False
        elif char.isdigit():
            if not numeric:
                out.append(chr(0x2800 + codecs._BRAILLE_NUMBER))
                numeric = True
            out.append(chr(0x2800 + digit_inverse[char]))
        else:
            if numeric:
                out.append(chr(0x2800 + codecs._BRAILLE_LETTER))
                numeric = False
            if char.isupper():
                out.append(chr(0x2800 + codecs._BRAILLE_CAPITAL))
            out.append(chr(0x2800 + inverse[char.lower()]))
    return "".join(out)


def test_grade1_braille_state_machine_and_existing_reader_crosscheck() -> None:
    encoded = _braille("CSCTF 2026")
    got = codecs.decode_braille_grade1(encoded)
    assert got is not None and got.payload == b"CSCTF 2026"

    import crib_decode  # existing independent broad reader

    assert crib_decode.d_braille(encoded.encode()) == got.payload
    assert codecs.decode_braille_grade1(encoded + chr(0x2800 + codecs._BRAILLE_CAPITAL)) is None
    assert codecs.decode_braille_grade1(encoded + chr(0x2800 + codecs._BRAILLE_NUMBER)) is None
    assert codecs.decode_braille_grade1(
        encoded + chr(0x2800 + codecs._BRAILLE_CAPITAL) + chr(0x2800 + 0x32)
    ) is None
    triple_capital = chr(0x2800 + codecs._BRAILLE_CAPITAL) * 3 + _braille("abcd")
    assert codecs.decode_braille_grade1(triple_capital) is None
    assert codecs.decode_braille_grade1(chr(0x2840) * 5) is None
    assert codecs.decode_braille_grade1("ordinary text") is None
    assert codecs.decode_braille_grade1(None) is None


def test_eight_dot_braille_bytes_shape_crc_and_crosscheck() -> None:
    payload = b"CSCTF{braille8}"
    encoded = " ".join(chr(0x2800 + byte) for byte in payload)
    got = codecs.decode_braille8(encoded)
    assert got is not None and got.payload == payload

    import crib_decode

    assert crib_decode.d_braille8(encoded.encode()) == payload
    binary = b"\x00\xff\x01"
    hidden = "".join(chr(0x2800 + byte) for byte in binary)
    assert codecs.decode_braille8(hidden) is None
    assert codecs.decode_braille8(hidden, expected_crc32=zlib.crc32(binary)).payload == binary
    assert codecs.decode_braille8(hidden + "x", expected_crc32=zlib.crc32(binary)) is None
    assert codecs.decode_braille8(hidden, expected_crc32=False) is None


def _semaphore(text: str) -> str:
    names = ("n", "ne", "e", "se", "s", "sw", "w", "nw")
    return " ".join(f"{names[a]}-{names[b]}" for char in text for a, b in [codecs._SEMAPHORE_VIEW[char]])


def test_semaphore_complete_pairs_and_declines() -> None:
    encoded = _semaphore("flag")
    got = codecs.decode_semaphore(encoded)
    assert got is not None and got.payload == b"flag"

    import formats_more

    assert formats_more.semaphore_decode(encoded) == "flag"
    mirrored = " ".join(
        f"{('n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw')[(-a) % 8]}-"
        f"{('n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw')[(-b) % 8]}"
        for char in "flag" for a, b in [codecs._SEMAPHORE_VIEW[char]]
    )
    assert codecs.decode_semaphore(mirrored, mirror=True).payload == b"flag"
    numbered = encoded + " | n-ne s-sw s-w"
    got = codecs.decode_semaphore(numbered)
    assert got is not None and got.payload == b"flag 12"
    assert codecs.decode_semaphore("s-e s-sw s-w") is None  # fewer than four symbols
    assert codecs.decode_semaphore(encoded + " bogus") is None
    assert codecs.decode_semaphore("ne ne ne ne") is None
    assert codecs.decode_semaphore("se se se se") is None
    assert codecs.decode_semaphore("n-n " + encoded) is None
    assert codecs.decode_semaphore(encoded + " n-ne | " + encoded) is None
    assert codecs.decode_semaphore(encoded, mirror=1) is None


def test_nato_icao_is_all_or_nothing() -> None:
    got = codecs.decode_nato_phonetic("Charlie Sierra Charlie Tango Foxtrot / Two Zero Two Six")
    assert got is not None and got.payload == b"CSCTF 2026"
    assert codecs.decode_nato_phonetic("Charlie Sierra nope Tango") is None
    assert codecs.decode_nato_phonetic("Alfa Bravo") is None
    assert codecs.decode_nato_phonetic("Alfa / / Bravo Charlie") is None
    assert codecs.decode_nato_phonetic(b"\xff") is None


def test_keyboard_shift_requires_exact_inverse_and_optional_crib() -> None:
    plain = "CSCTF{Key Shift}"
    encoded = codecs._keyboard_transform(plain, 1)
    assert encoded is not None
    got = codecs.decode_keyboard_shift(encoded, written_offset=1, expected_prefix="CSCTF{")
    assert got is not None and got.payload == plain.encode() and got.confidence == 1.0
    assert codecs.decode_keyboard_shift(encoded, written_offset=1, expected_prefix="wrong") is None
    assert codecs.decode_keyboard_shift("=", written_offset=1) is None
    assert codecs.decode_keyboard_shift(encoded, written_offset=0) is None
    assert codecs.decode_keyboard_shift(encoded, written_offset=True) is None
    assert codecs.decode_keyboard_shift(encoded, written_offset=1, expected_prefix="\ud800") is None
    assert codecs.decode_keyboard_shift(encoded + "\u2003", written_offset=1) is None
    left_encoded = codecs._keyboard_transform(plain, -1)
    assert left_encoded is not None
    assert codecs.decode_keyboard_shift(left_encoded, written_offset=-1,
                                         expected_prefix="CSCTF{").payload == plain.encode()


def test_book_coordinates_all_resolve_or_decline() -> None:
    book = "Cat Sun Code Token Flag\nsecond line"
    coordinates = "1:1:1 1:2:1 1:3:1 1:4:1 1:5:1"
    got = codecs.decode_book_coordinates(coordinates, book)
    assert got is not None and got.payload == b"CSCTF"
    assert codecs.decode_book_coordinates(coordinates + " 3:1:1", book) is None
    assert codecs.decode_book_coordinates("1:1:1 1:2:1 bad", book) is None
    assert codecs.decode_book_coordinates("1:1:99 1:2:1 1:3:1", book) is None
    assert codecs.decode_book_coordinates(coordinates, b"\xff") is None
    assert codecs.decode_book_coordinates(coordinates, "bad\ud800book") is None
    huge = "9" * 5000
    assert codecs.decode_book_coordinates(f"{huge}:1:1 1:2:1 1:3:1", book) is None


def _running_encrypt(plain: str, key_letters: str, mode: str) -> str:
    values = iter(ord(char) - 97 for char in key_letters)
    out: list[str] = []
    for char in plain:
        if char.isascii() and char.isalpha():
            key = next(values)
            value = codecs._runkey_cipher(ord(char.lower()) - 97, key, mode)
            out.append(chr(value + (65 if char.isupper() else 97)))
        else:
            out.append(char)
    return "".join(out)


def test_running_key_is_proven_by_unique_source_and_reencryption() -> None:
    plain = "CSCTF RUNNING KEY CHECK"
    source = "packmyboxwithfivedozenliquorjugsandthencontinue"
    offset = 7
    needed = sum(char.isalpha() for char in plain)
    key = source[offset:offset + needed]
    for mode in ("vigenere", "beaufort", "variant"):
        cipher = _running_encrypt(plain, key, mode)
        got = codecs.detect_running_key(cipher, "CSCTF RUN", {"pangram": source}, modes=[mode])
        assert len(got) == 1 and got[0].payload == plain.encode()
        assert got[0].codec == f"running-key:{mode}:pangram@{offset}"

    cipher = _running_encrypt(plain, key, "vigenere")
    assert codecs.detect_running_key(cipher, "WRONG CRIB", {"pangram": source}) == ()
    assert codecs.detect_running_key(cipher, "CSCTF RUN", {"one": source, "two": source}) == ()
    assert codecs.detect_running_key(cipher, "short", {"pangram": source}) == ()
    assert codecs.detect_running_key(cipher, "CSCTF RUN", {"pangram": source}, modes=["bad"]) == ()
    assert codecs.detect_running_key(cipher + " é", "CSCTF RUN é", {"pangram": source}) == ()


def test_public_wrong_type_and_resource_boundaries_decline(monkeypatch) -> None:
    monkeypatch.setattr(codecs, "MAX_TOKENS", 8)
    assert codecs.decode_dna_2bit("ACGT" * 3) is None
    assert codecs.decode_nato_phonetic("Alfa " * 9) is None
    assert codecs.decode_book_coordinates(1, "book") is None
    assert codecs.decode_book_coordinates("1:1:1", object()) is None
    assert codecs.detect_running_key("A" * 8, "A" * 8, {str(i): "A" * 8 for i in range(65)}) == ()

