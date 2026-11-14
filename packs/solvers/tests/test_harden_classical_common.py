"""Independent locks for common/classical.py (not its same-name toolkit).

Worked ACA handbook examples are cited next to each vector. pycipher is a second
implementation for its Python-3-working ciphers. Foursquare in pycipher 0.5.2
uses Python-2 `/` indexing and cannot be an oracle on Python 3; use the published
ACA pair table instead. Common declares no custom exception, so fuzz cases
require clean return (there is no stdlib-exception allowlist).
"""
import importlib.util
from pathlib import Path
import random
import string
from types import SimpleNamespace

import pycipher
import pytest

_PATH = Path(__file__).resolve().parents[1] / "solvers/common/classical.py"
_SPEC = importlib.util.spec_from_file_location("harden_classical_common_under_test", _PATH)
c = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(c)


# Full published squares, transcribed from ACA diagrams, not engine key builders.
PLAYFAIR_SQUARE = "LOGARITHMBCDEFKNPQSUVWXYZ"
BIFID_SQUARE = "EXTRAKLMPOHWZQDGVUSIFCBYN"
FOUR_FIRST = "GRDLUEYFNVOAHPWMBIQXTCKSZ"
FOUR_SECOND = "LICNVOTDPWGHEQXAMFSYRBKUZ"
ADFGVX_SQUARE = "PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8"


def test_correct_same_basename_module_loaded():
    assert Path(c.__file__).resolve() == _PATH
    assert hasattr(c, "vigenere_encrypt")
    assert hasattr(c, "trifid_encrypt")


@pytest.mark.parametrize("kind,key,plain,cipher", [
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Vigenere.pdf
    ("vigenere", "POLYALPHABETIC", "INTHEVIGENERECEQUALSKPLUSPWHEREAISZEROBISONEETC",
     "XBEFEGXNEOIKMETEFYLDZWLVWIEJTFPYIDOLRPFBAQCSPRC"),
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Beaufort.pdf
    ("beaufort", "RECIPROCAL", "CEQUALSKMINUSP", "PAMOPGWSODEKKT"),
])
def test_periodic_worked_handbook_vector_and_pycipher(kind, key, plain, cipher):
    oracle = (pycipher.Vigenere if kind == "vigenere" else pycipher.Beaufort)(key)
    assert oracle.encipher(plain) == cipher
    assert oracle.decipher(cipher) == plain
    assert c.vigenere_encrypt(plain, key, kind) == cipher
    assert c.vigenere_decrypt(cipher, key, kind) == plain


@pytest.mark.parametrize("kind", ["vigenere", "beaufort"])
def test_periodic_exhaustive_alphabet_boundaries(kind):
    oracle_type = pycipher.Vigenere if kind == "vigenere" else pycipher.Beaufort
    for letter in string.ascii_uppercase:
        oracle = oracle_type(letter)
        encoded = oracle.encipher(string.ascii_uppercase)
        assert c.vigenere_encrypt(string.ascii_uppercase, letter, kind) == encoded
        assert c.vigenere_decrypt(encoded, letter, kind) == string.ascii_uppercase


def test_playfair_worked_handbook_vector():
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Playfair.pdf
    # Published digraphs have an inserted X between the doubled E. pycipher's
    # splitter uses a different duplicate convention; supply prepared pairs.
    prepared = "COMEQUICKLYWENEXEDHELP"
    cipher = "DLHFSNCNCRZXCQQGFEEQON"
    oracle = pycipher.Playfair(PLAYFAIR_SQUARE)
    assert oracle.encipher(prepared) == cipher
    assert oracle.decipher(cipher) == prepared
    assert c.playfair_encrypt("COMEQUICKLYWENEEDHELP", PLAYFAIR_SQUARE) == cipher.lower()
    assert c.playfair_decrypt(cipher, PLAYFAIR_SQUARE) == prepared.lower()


def test_playfair_j_i_mapping_and_key_deduplication():
    # Full MONARCHY square, standard I/J merge, explicitly transcribed.
    square = "MONARCHYBDEFGIKLPQSTUVWXZ"
    # Avoid pycipher's duplicate splitter by supplying actual I/X/I/G/S/A/W/X pairs.
    expected = pycipher.Playfair(square).encipher("IXIGSAWX")
    assert c.playfair_square("MONARCHY") == square.lower()
    assert c.playfair_encrypt("JIGSAW", "MONARCHY") == expected.lower()
    assert c.playfair_decrypt(expected, "MONARCHY") == "ixigsawx"


def test_bifid_worked_handbook_vector_and_pycipher():
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Bifid.pdf
    plain, cipher = "ODDPERIODSAREPOPULAR", "MWEINGIMGEOYYRLVEYWY"
    oracle = pycipher.Bifid(BIFID_SQUARE, 7)
    assert oracle.encipher(plain) == cipher
    assert oracle.decipher(cipher) == plain
    assert c.bifid_encrypt(plain, BIFID_SQUARE, 7) == cipher.lower()
    assert c.bifid_decrypt(cipher, BIFID_SQUARE, 7) == plain.lower()


@pytest.mark.parametrize("period", [1, 2, 5, 6, 26])
def test_bifid_block_tails_against_pycipher(period):
    plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".replace("J", "I")
    oracle = pycipher.Bifid(BIFID_SQUARE, period)
    expected = oracle.encipher(plain)
    assert c.bifid_encrypt(plain, BIFID_SQUARE, period) == expected.lower()
    assert c.bifid_decrypt(expected, BIFID_SQUARE, period) == plain.lower()


def test_trifid_worked_handbook_vector():
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Trifid.pdf
    plain = "TRIFIDSAREFRACTIONATEDCIPHERS"
    cipher = "EYMXVUCRYYYYEAYVYOVVXITDPATHE"
    assert c.trifid_square("EXTRAORDINARY", "#") == "extraodinybcfghjklmpqsuvwz#"
    assert c.trifid_encrypt(plain, "EXTRAORDINARY", 10, "#") == cipher.lower()
    assert c.trifid_decrypt(cipher, "EXTRAORDINARY", 10, "#") == plain.lower()


def test_four_square_worked_handbook_vector():
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Foursquare.pdf
    # These squares are printed in vertical-key order; pass the full row-major
    # square, rather than ask the engine to generate a different keyword route.
    plain, cipher = "COMEQUICKLYWENEEDHELPX", "LEWIXAFNEXCUDXUVDPGXHZ"
    assert c.four_square_encrypt(plain, FOUR_FIRST, FOUR_SECOND) == cipher.lower()
    assert c.four_square_decrypt(cipher, FOUR_FIRST, FOUR_SECOND) == plain.lower()


def test_hill_3x3_published_act_poh_vector():
    # University course worked example, pages 25/26:
    # https://www.uomus.edu.iq/img/lectures21/MUCLecture_2023_101935712.pdf
    # A=0, K=(6,24,1;13,16,10;20,17,15), K*(0,2,19)=(67,222,319)%26.
    assert c.hill_encrypt("ACT", "GYBNQKURP") == "poh"
    assert c.hill_decrypt("POH", "GYBNQKURP") == "act"


def test_hill_singular_key_has_no_decryption():
    # Determinant is 0, so there is no inverse over Z/26Z.
    assert c.hill_decrypt("AB", [[1, 2], [2, 4]]) is None


def test_hill_existing_single_cell_matrix_and_flat_iterable():
    # The nested-matrix form historically also accepts one-cell Hill keys.
    assert c.hill_encrypt("ABC", [[3]]) == "adg"
    assert c.hill_decrypt("ADG", [[3]]) == "abc"
    assert c.hill_key_matrix(iter((3, 3, 2, 5))) == [[3, 3], [2, 5]]


def test_adfgvx_published_library_example():
    # https://pycipher.readthedocs.io/en/master/ (Example usage)
    cipher = "FVFDAGXAFFFFGFAGADFG"
    oracle = pycipher.ADFGVX(ADFGVX_SQUARE, "GERMAN")
    assert oracle.encipher("HELLOWORLD") == cipher
    assert oracle.decipher(cipher) == "HELLOWORLD"
    # Common exposes only decryption, unlike the toolkit engine.
    assert c.adfgvx_decrypt(cipher, ADFGVX_SQUARE, "GERMAN") == "helloworld"


def test_adfgvx_does_not_infer_square_width_from_observed_symbols():
    # Six-column A..Z0..9 square has G at row D, column A, regardless of whether
    # any V appears. Both coordinates and the independent library give DA -> G.
    square = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    assert pycipher.ADFGVX(square, "A").decipher("DA") == "G"
    assert c.adfgvx_decrypt("DA", square, "A") == "g"


def test_adfgvx_explicit_25_square_keeps_adfgx_alphabet():
    square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    assert pycipher.ADFGX(square, "A").decipher("DA") == "F"
    assert c.adfgvx_decrypt("DA", square, "A") == "f"
    assert c.adfgvx_decrypt("VA", square, "A") is None


def test_adfgvx_digit_keyword_identifies_36_square():
    # Keyword 0 gives 0,A,B,C,D,E / F,G,H,I,J,K / ... in a 6x6 square.
    square = "0ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
    assert pycipher.ADFGVX(square, "A").decipher("DA") == "F"
    assert c.adfgvx_decrypt("DA", "0", "A") == "f"


def test_nihilist_published_cryptocrack_worked_example():
    # Author's worked example: https://sites.google.com/site/cryptocrackprogram/
    # user-guide/cipher-types/substitution/nihilist-substitution
    plain = "MYWIFEDRESSESTOKILLSHECOOKSTHESAMEWAY"
    cipher = "54 42 67 48 43 64 56 58 45 56 78 62 59 65 23 68 65 55 55 56 66 62 38 26 23 68 76 65 47 42 78 53 35 45 64 55 42"
    assert c.nihilist_encrypt(plain, "YOUNGMAN", "HENNY") == cipher
    assert c.nihilist_decrypt(cipher, "YOUNGMAN", "HENNY") == plain.lower()


def test_railfence_worked_handbook_vector_and_pycipher():
    # https://www.cryptogram.org/downloads/aca.info/ciphers/Railfence.pdf
    plain, cipher = "CIVILWARFIELDCIPHER", "CLFDHIIWRILCPEVAEIR"
    oracle = pycipher.Railfence(3)
    assert oracle.encipher(plain) == cipher
    assert oracle.decipher(cipher) == plain
    assert c.railfence_encrypt(plain, 3) == cipher
    assert c.railfence_decrypt(cipher, 3) == plain


def test_columnar_worked_handbook_vector_and_pycipher():
    # https://www.cryptogram.org/downloads/aca.info/ciphers/CompleteColTransposition.pdf
    # The printed grid includes an explicit X null: common does not add padding.
    plain, cipher = "FILLEDBLOCKX", "IELKLDOXFLBC"
    oracle = pycipher.ColTrans("CAB")  # ranks 3,1,2 in the printed example
    assert oracle.encipher(plain) == cipher
    assert oracle.decipher(cipher) == plain
    assert c.columnar_encrypt(plain, "312") == cipher
    assert c.columnar_decrypt(cipher, "312") == plain


def test_columnar_irregular_tail_and_duplicate_keyword():
    plain = "WEAREDISCOVEREDFLEEATONCE"
    oracle = pycipher.ColTrans("BALLOON")
    expected = oracle.encipher(plain)
    assert c.columnar_encrypt(plain, "BALLOON") == expected
    assert c.columnar_decrypt(expected, "BALLOON") == plain


def test_caesar_breaker_candidates_have_the_reported_shift():
    plain = "WEAREDISCOVEREDFLEEATONCE"
    cipher = pycipher.Caesar(3).encipher(plain)
    rows = c.crack_caesar(cipher)
    assert len(rows) == 25
    for _, key, candidate in rows:
        assert candidate == pycipher.Caesar(key).decipher(cipher)
    assert any(key == 3 and candidate == plain for _, key, candidate in rows)


def test_affine_breaker_candidates_have_the_reported_key():
    plain = "WEAREDISCOVEREDFLEEATONCE"
    cipher = pycipher.Affine(5, 8).encipher(plain)
    rows = c.crack_affine(cipher)
    assert len(rows) == 312
    for _, (a, b), candidate in rows:
        assert candidate == pycipher.Affine(a, b).decipher(cipher)
    assert any(key == (5, 8) and candidate == plain for _, key, candidate in rows)


def test_vigenere_breaker_candidates_have_the_reported_key():
    # Do not mistake scoring rank for a cryptographic proof. Check every proposed
    # key/reading against the independent cipher on a fixed known-key input.
    cipher = pycipher.Vigenere("KEY").encipher("WEAREDISCOVEREDFLEEATONCE" * 3)
    rows = c.crack_vigenere(cipher, max_len=3)
    assert rows
    for _, key, candidate in rows:
        assert candidate == pycipher.Vigenere(key).decipher(cipher)


def test_rail_breaker_includes_published_handbook_reading():
    rows = c.crack_railfence("CLFDHIIWRILCPEVAEIR", max_rails=3)
    assert any(key == (3, 0) and value == "CIVILWARFIELDCIPHER" for _, key, value in rows)


def test_columnar_breaker_includes_published_handbook_reading():
    rows = c.crack_columnar("IELKLDOXFLBC", max_columns=3)
    assert any(order == (1, 2, 0) and value == "FILLEDBLOCKX" for _, order, value in rows)


def test_substitution_breaker_candidate_matches_reported_alphabet(monkeypatch):
    # Freeze only this isolated module's clock reference. The finite stale=1500
    # and restarts=1 loop controls execute deterministically instead of timing out.
    monkeypatch.setattr(c, "time", SimpleNamespace(perf_counter=lambda: 0.0))
    cipher = pycipher.SimpleSubstitution("AJPCZWRLFBDKOTYUQGENHXMIVS").encipher(
        "WEAREDISCOVEREDFLEEATONCE")
    rows = c.crack_substitution(cipher, seconds=1.0, restarts=1, seed=7)
    assert len(rows) == 1
    for _, alphabet, candidate in rows:
        assert candidate == pycipher.SimpleSubstitution(alphabet).decipher(cipher)


# Explicit breakers only: common.keyless/crack/identify may dispatch Brainfuck or
# COW. This suite never calls those execution paths. Time-limited substitution
# gets zero iterations; other searches get fixed tiny bounds, not wall time.
_BREAKERS = [
    ("crack_caesar", {}),
    ("crack_affine", {}),
    ("crack_vigenere", {"max_len": 3}),
    ("crack_railfence", {"max_rails": 3}),
    ("crack_columnar", {"max_columns": 3}),
    ("crack_substitution", {"seconds": 0.0, "restarts": 0, "seed": 7}),
]
_rng = random.Random(0xC1A551C)
_JUNK = [
    pytest.param("", id="empty"),
    pytest.param("".join(_rng.choices(string.printable, k=97)), id="seeded-ascii"),
    pytest.param("\x00\ud800\udfff\u202e\u200b\ufefféΣ漢字💥٠１２ßİ", id="unicode-and-surrogates"),
    pytest.param("!" * 65537, id="very-long-nonletters"),
]


@pytest.mark.parametrize("name,kwargs", _BREAKERS, ids=[n for n, _ in _BREAKERS])
@pytest.mark.parametrize("text", _JUNK)
def test_breakers_fail_closed_on_junk(name, kwargs, text):
    # No declared exception exists; letting any exception escape fails the test.
    assert isinstance(getattr(c, name)(text, **kwargs), list)


@pytest.mark.parametrize("name", ["bifid_encrypt", "bifid_decrypt"])
def test_bifid_empty_default_period_is_a_clean_empty_result(name):
    assert getattr(c, name)("") == ""


@pytest.mark.parametrize("name", ["hill_encrypt", "hill_decrypt"])
def test_hill_ragged_matrix_fails_closed(name):
    # A malformed 2x? key cannot be a matrix over Z/26Z. No declared error class.
    assert getattr(c, name)("AB", [[1, 2], [3]]) is None


def test_columnar_empty_key_fails_closed():
    assert c.columnar_decrypt("AB", "") is None


def test_breaker_wrong_type_fails_closed():
    assert c.crack_vigenere(None, max_len=3) is None
