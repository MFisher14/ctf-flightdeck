"""Independent oracle locks for classical known-plaintext recovery helpers.

Both same-named modules are loaded explicitly. pycipher supplies ciphertexts;
SymPy supplies independent matrix multiplication/inversion. No production encoder
is used to construct a test input. Public cipher round-trip APIs have their own
companion hardening files; these tests lock the recovered key and orientation.

References:
https://pycipher.readthedocs.io/en/master/
https://docs.sympy.org/latest/modules/matrices/matrices.html
https://sites.google.com/site/cryptocrackprogram/user-guide/cipher-types/substitution/nihilist-substitution
"""
import importlib.util
from pathlib import Path
import random

import pycipher
import pytest
from sympy import Matrix


ROOT = Path(__file__).resolve().parents[1]


def _load(relative, alias):
    spec = importlib.util.spec_from_file_location(alias, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


common = _load("solvers/common/classical.py", "_harden_classical_recovery_common")
toolkit = _load("solvers/toolkits/classical.py", "_harden_classical_recovery_toolkit")
PLAIN = "DEFENDTHEEASTWALLOFTHECASTLE"


@pytest.mark.parametrize("kind,oracle", [("vigenere", pycipher.Vigenere), ("beaufort", pycipher.Beaufort)])
def test_common_recovers_key_from_pycipher(kind, oracle):
    cipher = oracle("FORTIFICATION").encipher(PLAIN * 3)
    assert common.crib_vigenere(cipher, PLAIN * 3) == (kind, "fortification", False)


def test_toolkit_known_start_recovers_lemon_textbook_key():
    # Published canonical ATTACKATDAWN / LEMON vector, independently checked.
    cipher = pycipher.Vigenere("LEMON").encipher("ATTACKATDAWN")
    assert cipher == "LXFOPVEFRNHR"
    assert toolkit.vigenere_known_plaintext(cipher, "ATTACKATDAWN") == [("lemon", "ATTACKATDAWN", 0)]


def test_toolkit_anywhere_crib_correct_phase_at_full_key_boundary():
    source = "XXXXXATTACKATDAWN"
    cipher = pycipher.Vigenere("LEMON").encipher(source)
    candidates = toolkit.vigenere_known_plaintext(cipher, "ATTACKATDAWN", at_start=False)
    assert ("lemon", source, 5) in candidates


@pytest.mark.parametrize("offset", range(1, 10))
def test_bug_toolkit_anywhere_crib_key_phase(offset):
    source = "X" * offset + "ATTACKATDAWN"
    cipher = pycipher.Vigenere("LEMON").encipher(source)
    candidates = toolkit.vigenere_known_plaintext(cipher, "ATTACKATDAWN", at_start=False)
    assert ("lemon", source, offset) in candidates


def test_anywhere_crib_phase_counts_letters_not_punctuation():
    source = "X-X--ATTACK AT DAWN!"
    encoded = iter(pycipher.Vigenere("LEMON").encipher(source))
    cipher = "".join(next(encoded) if ch.isalpha() else ch for ch in source)
    candidates = toolkit.vigenere_known_plaintext(cipher, "ATTACK AT DAWN", at_start=False)
    assert ("lemon", source, 2) in candidates


def test_common_railfence_recovery_independent_oracle():
    cipher = pycipher.Railfence(3).encipher(PLAIN)
    assert common.crib_railfence(cipher, PLAIN, max_rails=5) == (3, 0)


def test_common_columnar_recovery_independent_oracle():
    # Enough known rows to satisfy the documented four-per-column requirement.
    plain = PLAIN * 2
    key = "ZEBRAS"
    cipher = pycipher.ColTrans(key).encipher(plain)
    expected_order = (4, 2, 1, 3, 5, 0)  # alphabetic column order A B E R S Z
    assert common.crib_columnar(cipher, plain, max_columns=6) == expected_order


@pytest.mark.parametrize("key", [
    [[3, 3], [2, 5]],
    [[6, 24, 1], [13, 16, 10], [20, 17, 15]],
    [[0, 1], [1, 0]],  # invertible with a zero leading diagonal element
])
def test_hill_recovery_orientation_and_decryption_sympy(key):
    matrix = Matrix(key)
    size = len(key)
    # Identity columns provide independent basis vectors: BAA ABA AAB for n=3.
    plain_matrix = Matrix.eye(size)
    cipher_matrix = matrix * plain_matrix % 26
    plain = "".join(chr(65 + int(plain_matrix[r, c])) for c in range(size) for r in range(size))
    cipher = "".join(chr(65 + int(cipher_matrix[r, c])) for c in range(size) for r in range(size))
    assert common.crib_hill(cipher, plain, size) == key
    assert common.hill_decrypt(cipher, key) == plain.lower()
    if size == 2:
        inverse = matrix.inv_mod(26)
        expected_inverse = tuple(int(inverse[r, c]) for r in range(2) for c in range(2))
        assert toolkit.hill_invert_2x2(tuple(x for row in key for x in row)) == expected_inverse
        assert toolkit.hill_decrypt_2x2(cipher, expected_inverse) == plain


def test_nihilist_crib_author_worked_example():
    # CryptoCrack author's YOUNGMAN square / HENNY key, first twenty letters.
    cipher = "54 42 67 48 43 64 56 58 45 56 78 62 59 65 23 68 65 55 55 56"
    plain = "MYWIFEDRESSESTOKILLS"
    assert len(plain) == 20
    expected = ("henny" * 4)[:len(plain)]
    assert common.crib_nihilist(cipher, plain, "YOUNGMAN") == expected


def test_key_length_statistics_worked_repetition():
    # ABC repeated 8 times: k1 IoC=7/23; k2=3/11; k3=1; k4=1/5.
    # Values follow unordered collision counting, independently of both engines.
    text = "ABC" * 8
    assert common.kasiski(text, low=2, high=4) == [(3, 19)]
    lengths = common.key_lengths(text, low=1, high=4)
    assert [k for k, _ in lengths] == [3, 1, 2, 4]
    assert [score for _, score in lengths] == pytest.approx([1, 7/23, 3/11, 1/5])
    # Toolkit deliberately ranks closeness to English IoC 0.066 rather than
    # maximum IoC. This convention differs from the common engine's ordering.
    assert toolkit.kasiski_lengths(text, max_len=4) == [4, 2, 1, 3]


JUNK = [
    pytest.param("", id="empty"),
    pytest.param("\x00\x01\x7f", id="controls"),
    pytest.param("\ud800\udfff\ufffe\uffff", id="surrogates"),
    pytest.param("ßİﬃKＡαЖعא\u0301\u200d🙂", id="mixed-unicode"),
    pytest.param("".join(random.Random(4401).choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?", k=257)), id="random-seed4401"),
    pytest.param("\x00\u0301" * 32769, id="very-long-65538-codepoints"),
]


@pytest.mark.parametrize("junk", JUNK)
@pytest.mark.parametrize("function", ("crib_vigenere", "crib_railfence", "crib_columnar", "crib_hill", "crib_nihilist"))
def test_common_recovery_fuzz_returns_cleanly(function, junk):
    # No declared exception exists in this module: leaking any exception fails.
    if function == "crib_hill":
        common.crib_hill(junk, "KNOWNPLAINTEXT", 2)
    elif function == "crib_railfence":
        common.crib_railfence(junk, "KNOWNPLAINTEXT", max_rails=3)
    elif function == "crib_columnar":
        common.crib_columnar(junk, "KNOWNPLAINTEXT", max_columns=3)
    else:
        getattr(common, function)(junk, "KNOWNPLAINTEXT")


@pytest.mark.parametrize("junk", [p for p in JUNK if p.id != "mixed-unicode"])
def test_toolkit_recovery_fuzz_returns_cleanly(junk):
    toolkit.vigenere_known_plaintext(junk, "KNOWNPLAINTEXT")
    toolkit.kasiski_lengths(junk, max_len=3)


def test_bug_toolkit_crib_unicode_lowercase_expansion():
    assert toolkit.vigenere_known_plaintext("İ" * 20, "KNOWNPLAINTEXT") is None


def test_bug_nihilist_crib_oversized_integer():
    assert common.crib_nihilist("9" * 5000, "A") is None


@pytest.mark.parametrize("token", ("22", "00022", "0" * 5000 + "22"))
def test_nihilist_crib_accepts_leading_zeroes(token):
    # Default square: plaintext A=11 plus key A=11 gives 22.
    assert common.crib_nihilist(token, "A") == "a"
