"""Deterministic round-trip, recovery, and ambiguity tests for r5c classical depth."""

from __future__ import annotations

import itertools
import importlib
import random
import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import classical_advanced as classical  # noqa: E402


def test_package_and_direct_imports_expose_identical_roundtrips():
    package = importlib.import_module("solvers.common.classical_advanced")
    key = ((3, 3), (2, 5))
    direct_cipher = classical.hill_encrypt("PACKAGEIMPORT", key)
    package_cipher = package.hill_encrypt("PACKAGEIMPORT", key)
    assert package_cipher == direct_cipher
    assert package.hill_decrypt(package_cipher, key, plaintext_length=13) == "PACKAGEIMPORT"


def test_hill_n_by_n_roundtrip_key_recovery_and_padding():
    key2 = ((3, 3), (2, 5))
    cipher = classical.hill_encrypt("HELP", key2)
    assert cipher == "HIAT"
    assert classical.hill_decrypt(cipher, key2) == "HELP"
    assert classical.hill_encrypt("HELLO", key2, pad="X") == classical.hill_encrypt("HELLOX", key2)
    padded = classical.hill_encrypt("HELLO", key2)
    assert classical.hill_decrypt(padded, key2, plaintext_length=5) == "HELLO"

    key3 = ((6, 24, 1), (13, 16, 10), (20, 17, 15))
    plain = "ACTPAYMOREMONEY"
    cipher3 = classical.hill_encrypt(plain, key3)
    assert classical.hill_decrypt(cipher3, key3) == plain
    recovery_plain = "BAAABAAABACT"
    recovery_cipher = classical.hill_encrypt(recovery_plain, key3)
    assert classical.hill_recover_key(recovery_plain, recovery_cipher, 3) == key3
    assert classical.hill_recover_key("AAAAAA", "BBBBBB", 2) is None


def test_hill_bounded_break_verifies_and_equal_top_declines(monkeypatch):
    correct = ((3, 3), (2, 5))
    wrong = ((5, 8), (17, 3))
    cipher = classical.hill_encrypt("MEETMEATNOON", correct)
    got = classical.hill_break_bounded(cipher, candidate_keys=[wrong, correct], crib="MEETME")
    assert got == ("MEETMEATNOON", correct)
    monkeypatch.setattr(classical, "_english_score", lambda _text: 0.0)
    assert classical.hill_break_bounded(
        cipher, candidate_keys=[wrong, correct], verifier=lambda _text: True, scorer=classical._english_score
    ) is None
    binary_key = ((1, 1), (1, 0))
    binary_plain = "ABBAAABBABBA"
    binary_cipher = classical.hill_encrypt(binary_plain, binary_key, alphabet="AB")
    assert classical.hill_break_bounded(
        binary_cipher, n=2, alphabet="AB", max_keys=16, crib=binary_plain
    ) == (binary_plain, binary_key)


def test_adfgvx_roundtrip_break_and_ambiguity(monkeypatch):
    square_key, column_key = "CARGO", "ZEBRA"
    plain = "ATTACKAT1200"
    cipher = classical.adfgvx_encrypt(plain, square_key, column_key)
    assert classical.adfgvx_decrypt(cipher, square_key, column_key) == plain
    got = classical.adfgvx_break(cipher, ["WRONG", square_key], ["PLANE", column_key], crib="ATTACK")
    assert got and got[0] == plain
    assert classical.adfgvx_decrypt(cipher + "A", square_key, column_key) is None
    assert classical.adfgvx_break(
        cipher, ["WRONG", square_key], [column_key], verifier=lambda _text: True, scorer=lambda _text: 0.0
    ) is None


def test_running_key_roundtrip_position_recovery_and_tie_decline():
    plain = "DEFENDTHEEASTWALL"
    passage = "SOMEPREFACEFORTUNEFAvORSTHEBOLDANDMORETEXT".upper()
    offset = 13
    key = passage[offset:offset + len(plain)]
    cipher = classical.running_key_encrypt(plain, key)
    assert classical.running_key_decrypt(cipher, key) == plain
    assert classical.running_key_break(cipher, [passage], crib="DEFEND", crib_position=0) == (plain, 0, offset)
    assert classical.running_key_break(cipher, [passage, passage], crib="DEFEND", crib_position=0) is None


def test_book_cipher_roundtrip_offset_recovery_and_ambiguity():
    corpus = "alpha brave cedar delta echo forest garden harbor island jungle kilo lemon"
    indices = classical.book_cipher_encode("BDFH", corpus)
    assert indices is not None
    assert classical.book_cipher_decode(indices, corpus) == "BDFH"
    assert classical.book_cipher_break(indices, [corpus], [0, 1], crib="BDFH", crib_position=0) == (
        "BDFH", 0, 0, 1
    )
    assert classical.book_cipher_break(indices, [corpus, corpus], [0], crib="BDFH") is None


def test_playfair_roundtrip_break_and_tied_keys_decline():
    key, plain = "MONARCHY", "INSTRUMENTS"
    cipher = classical.playfair_encrypt(plain, key)
    assert cipher == "GATLMZCLRQXA"
    assert classical.playfair_decrypt(cipher, key) == "INSTRUMENTSX"
    got = classical.playfair_break(cipher, ["KEYWORD", key], crib="INSTRUMENTS")
    assert got and got[0] == "INSTRUMENTSX"
    assert classical.playfair_break(
        cipher, ["KEYWORD", key], verifier=lambda _text: True, scorer=lambda _text: 0.0
    ) is None
    tail_cipher = classical.playfair_encrypt("ABX", key)
    assert classical.playfair_decrypt(tail_cipher, key) == "ABXQ"


@pytest.mark.parametrize("orientation", ["horizontal", "vertical"])
def test_two_square_variants_are_self_reciprocal_and_breakable(orientation):
    first, second, plain = "EXAMPLE", "KEYWORD", "ATTACKATDAWN"
    cipher = classical.two_square_transform(plain, first, second, orientation=orientation)
    assert classical.two_square_transform(cipher, first, second, orientation=orientation) == plain
    got = classical.two_square_break(
        cipher, [("WRONG", "WORDS"), (first, second)], orientations=[orientation], crib="ATTACK"
    )
    assert got and got[0] == plain and got[3] == orientation
    assert classical.two_square_break(
        cipher,
        [("WRONG", "WORDS"), (first, second)],
        orientations=[orientation],
        verifier=lambda _text: True,
        scorer=lambda _text: 0.0,
    ) is None


def test_autokey_roundtrip_primer_recovery_and_short_crib_ambiguity():
    primer, plain = "QUEEN", "ATTACKATDAWNRETREAT"
    cipher = classical.autokey_encrypt(plain, primer)
    assert classical.autokey_decrypt(cipher, primer) == plain
    assert classical.autokey_recover_primer(cipher, plain, max_primer=8) == (plain, primer)
    assert classical.autokey_recover_primer(cipher, "ATT", max_primer=3) is None


def test_straddling_checkerboard_roundtrip_break_and_tie_decline():
    config = (classical.ALPHABET26, "0123456789", ("2", "6"))
    plain = "RENDEZVOUS"
    cipher = classical.checkerboard_encode(plain, alphabet=config[0], columns=config[1], row_digits=config[2])
    assert classical.checkerboard_decode(cipher, alphabet=config[0], columns=config[1], row_digits=config[2]) == plain
    other = (classical.ALPHABET26[::-1], "0123456789", ("2", "6"))
    got = classical.checkerboard_break(cipher, [other, config], crib="RENDEZ")
    assert got and got[0] == plain
    assert classical.checkerboard_break(
        cipher, [other, config], verifier=lambda _text: True, scorer=lambda _text: 0.0
    ) is None
    assert classical.checkerboard_decode("2", alphabet=config[0], columns=config[1], row_digits=config[2]) is None


def test_breakers_and_iterables_are_bounded_and_malformed_inputs_decline():
    def failing_keys():
        yield "KEY"
        raise RuntimeError("broken candidate source")

    assert classical.hill_encrypt("ABC", ((2, 4), (2, 4))) is None
    assert classical.hill_decrypt("ABC", ((3, 3), (2, 5))) is None
    assert classical.hill_break_bounded("AB", candidate_keys=itertools.repeat(((1, 0), (0, 1))), max_keys=4) is None
    assert classical.adfgvx_break("AD", itertools.repeat("A"), ["KEY"], max_candidates=4) is None
    assert classical.running_key_break("ABC", itertools.repeat("ABC"), crib="A") is None
    assert classical.book_cipher_decode([True], "alpha") is None
    assert classical.playfair_decrypt("ABC", "KEY") is None
    assert classical.two_square_transform("ABC", "ONE", "TWO") is None
    assert classical.autokey_encrypt("ABC", "") is None
    assert classical.checkerboard_encode("ABC", columns="0012345678") is None
    assert classical.checkerboard_encode("ABC", row_digits=itertools.repeat("2")) is None
    assert classical.hill_break_bounded("") is None
    assert classical.adfgvx_break("", ["KEY"], ["WORD"]) is None
    assert classical.playfair_break("", ["KEY"]) is None
    assert classical.two_square_break("", [("ONE", "TWO")]) is None
    assert classical.checkerboard_break("", [(classical.ALPHABET26, "0123456789", ("2", "6"))]) is None
    assert classical.hill_encrypt("AB", itertools.repeat(1)) is None
    assert classical.adfgvx_encrypt("ABC", "KEY", itertools.count()) is None
    assert classical.book_cipher_break([1], ["alpha"], itertools.count(), crib="A") is None
    assert classical.playfair_break("AB", itertools.repeat("KEY")) is None
    assert classical.two_square_break("AB", itertools.repeat(("ONE", "TWO"))) is None
    assert classical.checkerboard_break(
        "01", itertools.repeat((classical.ALPHABET26, "0123456789", ("2", "6")))
    ) is None
    assert classical.playfair_break("AB", failing_keys()) is None


def test_invalid_scores_and_monkeypatched_plaintexts_never_bypass_proof(monkeypatch):
    key, plain = "FORTUNE", "DEFENDTHEWALL"
    cipher = classical.running_key_encrypt(plain, key * 2)
    assert classical.running_key_break(
        cipher, [key * 2], crib="DEFEND", scorer=lambda _text: float("nan")
    ) is None
    monkeypatch.setattr(classical, "running_key_decrypt", lambda *_args, **_kwargs: plain)
    assert classical.running_key_break(cipher, ["A" * len(cipher)], crib="DEFEND") is None


def test_deterministic_randomized_roundtrip_properties():
    rng = random.Random(0xC1A551C)
    hill_key = ((3, 3), (2, 5))
    for length in range(1, 20):
        letters = "".join(rng.choice(classical.ALPHABET26) for _ in range(length))
        hill_cipher = classical.hill_encrypt(letters, hill_key)
        assert classical.hill_decrypt(hill_cipher, hill_key, plaintext_length=length) == letters

        running_key = "".join(rng.choice(classical.ALPHABET26) for _ in range(length))
        running_cipher = classical.running_key_encrypt(letters, running_key)
        assert classical.running_key_decrypt(running_cipher, running_key) == letters

        auto_cipher = classical.autokey_encrypt(letters, "SEED")
        assert classical.autokey_decrypt(auto_cipher, "SEED") == letters

        adf_plain = "".join(rng.choice(classical.ALPHABET36) for _ in range(length))
        adf_cipher = classical.adfgvx_encrypt(adf_plain, "CARGO", "ZEBRA")
        assert classical.adfgvx_decrypt(adf_cipher, "CARGO", "ZEBRA") == adf_plain

        board_cipher = classical.checkerboard_encode(letters)
        assert classical.checkerboard_decode(board_cipher) == letters

    for length in range(2, 20, 2):
        plain25 = "".join(rng.choice(classical.ALPHABET25) for _ in range(length))
        playfair_cipher = classical.playfair_encrypt(plain25, "MONARCHY")
        assert classical.playfair_decrypt(playfair_cipher, "MONARCHY") == classical._playfair_prepare(plain25)
        for orientation in ("horizontal", "vertical"):
            two_cipher = classical.two_square_transform(
                plain25, "EXAMPLE", "KEYWORD", orientation=orientation
            )
            assert classical.two_square_transform(
                two_cipher, "EXAMPLE", "KEYWORD", orientation=orientation
            ) == plain25
