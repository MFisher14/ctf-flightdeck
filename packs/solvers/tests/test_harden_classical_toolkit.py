"""Independent vector locks and deterministic malformed-input probes.

This file intentionally loads solvers/toolkits/classical.py by path: importing
``classical`` alone can silently test the different common/classical.py instead.
No engine's encoder supplies an expected ciphertext. Published sources:
* CrypTool HistoCrypt 2018 workshop, p4 (Vigenere and columnar):
  https://www.cryptool.org/download/ct2/WS-2018_(Automated)-Cryptanalysis-of-Classical-Ciphers-with-CrypTool-2.pdf
* ASU Playfair and rail-fence teaching notes:
  https://math.asu.edu/sites/g/files/litvpz216/files/playfair.pdf
  https://math.asu.edu/sites/g/files/litvpz216/files/railfence.pdf
* American Cryptogram Association worked examples:
  https://www.cryptogram.org/downloads/aca.info/ciphers/Bifid.pdf
  https://www.cryptogram.org/downloads/aca.info/ciphers/Trifid.pdf
  https://www.cryptogram.org/downloads/aca.info/ciphers/Foursquare.pdf
* Hill worked HELP/HIAT example, Dr. Muhanad Tahrir Younis, p27:
  https://uomustansiriyah.edu.iq/media/lectures/6/6_2020_06_02%2109_18_36_AM.pdf
  Also indexed: https://koclab.cs.ucsb.edu/teaching/ccs130h/2016/02b-affine.pdf
* pycipher's published ADFGVX example and independent implementation:
  https://pycipher.readthedocs.io/en/master/

pycipher 0.5.2 Playfair accepts prepaired plaintext; it does not insert split-Xs.
The independently prepared digraph text below makes that convention explicit.
This legacy engine has no declared exception class: fail-closed probes demand a
clean return, never blanket-accept ValueError/TypeError or other stdlib failures.
"""
import importlib.util
from pathlib import Path
import random
import string

import pycipher
import pytest


_PATH = Path(__file__).resolve().parents[1] / 'solvers/toolkits/classical.py'
_SPEC = importlib.util.spec_from_file_location('harden_classical_toolkit_subject', _PATH)
C = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(C)


@pytest.mark.parametrize('key,plain,cipher', [
    ('SECRET', 'HELLOWORLDHOWAREYOU', 'ZINCSPGVNULHOETVCHM'),
    ('LEMON', 'ATTACKATDAWN', 'LXFOPVEFRNHR'),
])
def test_vigenere_published_and_library(key, plain, cipher):
    assert pycipher.Vigenere(key).encipher(plain) == cipher
    assert C.vigenere_decrypt(cipher, key) == plain
    assert C.vigenere_decrypt(cipher, key) == pycipher.Vigenere(key).decipher(cipher)


@pytest.mark.parametrize('plain,prepared,cipher', [
    ('ROCKYMOUNTAINMEADOW', 'ROCKYMOUNTAINMEADOWX', 'BXHCVQNBOMSFONFLBTXY'),
    ('SUNNYMOUNTAINMEADOW', 'SUNXNYMOUNTAINMEADOW', 'ADOWQWNQFWNSFTVMSUNX'),
])
def test_playfair_asu_worked_examples(plain, prepared, cipher):
    square = 'LARKSPUBCDEFGHIMNOQTVWXYZ'
    oracle = pycipher.Playfair(square)
    assert oracle.encipher(prepared) == cipher
    assert C.playfair_encrypt(plain, 'LARKSPUR') == cipher
    assert C.playfair_decrypt(cipher, square) == oracle.decipher(cipher) == prepared


def test_playfair_j_i_merge_and_row_column_wrap():
    square = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    # J is I; same-row DE -> EA; last-row YZ -> ZV; last-column EZ -> KE.
    for plain, prepared in [('JIG', 'IXIG'), ('DEYZ', 'DEYZ'), ('EZ', 'EZ')]:
        expected = pycipher.Playfair(square).encipher(prepared)
        assert C.playfair_encrypt(plain, square) == expected
        assert C.playfair_decrypt(expected, square) == prepared


def test_hill_ucsb_worked_example_and_exact_inverse():
    encryption = (3, 3, 2, 5)
    inverse = (15, 17, 20, 9)
    # Independently published K and K^-1, not an inverse produced by this engine.
    assert C.hill_encrypt_2x2('HELP', encryption) == 'HIAT'
    assert C.hill_decrypt_2x2('HIAT', inverse) == 'HELP'
    assert C.hill_invert_2x2(encryption) == inverse
    # det=2 and det=13 are nonzero but nonunits in Z/26Z.
    assert C.hill_invert_2x2((2, 0, 0, 1)) is None
    assert C.hill_invert_2x2((13, 0, 0, 1)) is None


def test_hill_odd_padding_independent_arithmetic():
    # LX -> (3*11+3*23, 2*11+5*23) mod26 = (24,7) = YH.
    assert C.hill_encrypt_2x2('HEL', (3, 3, 2, 5)) == 'HIYH'
    assert C.hill_decrypt_2x2('HIYH', (15, 17, 20, 9)) == 'HELX'


def test_adfgvx_published_pycipher_example():
    square = 'PH0QG64MEA1YL2NOFDXKR3CVS5ZW7BJ9UTI8'
    cipher = 'FVFDAGXAFFFFGFAGADFG'
    oracle = pycipher.ADFGVX(square, 'GERMAN')
    assert oracle.encipher('HELLOWORLD') == cipher
    assert C.adfgvx_encrypt('HELLOWORLD', square, 'GERMAN') == cipher
    assert C.adfgvx_decrypt(cipher, square, 'GERMAN') == oracle.decipher(cipher) == 'HELLOWORLD'
    assert C.adfgvx_detect(cipher) is True
    assert C.adfgvx_detect('THISISNOTADFGVX') is False


@pytest.mark.parametrize('plain,fractions,key', [('A0Z9', 'AAVFVDXX', 'BALLOON'), ('9', 'XX', 'LONGKEY')])
def test_adfgvx_digits_repeated_keyword_and_ragged_tail(plain, fractions, key):
    square = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    # pycipher.ADFGVX 0.5.2 incorrectly drops digits, so independently transcribe
    # the standard-square coordinates A=AA,0=VF,Z=VD,9=XX, then use its working
    # columnar implementation as the second-stage oracle.
    expected = pycipher.ColTrans(key).encipher(fractions)
    assert C.adfgvx_encrypt(plain, square, key) == expected
    assert C.adfgvx_decrypt(expected, square, key) == plain


def test_bifid_aca_worked_example():
    square = 'EXTRAKLMPOHWZQDGVUSIFCBYN'
    plain, cipher = 'ODDPERIODSAREPOPULAR', 'MWEINGIMGEOYYRLVEYWY'
    oracle = pycipher.Bifid(square, 7)
    assert oracle.encipher(plain) == cipher
    assert C.bifid_encrypt(plain, square, 7) == cipher
    assert C.bifid_decrypt(cipher, square, 7) == oracle.decipher(cipher) == plain


def test_trifid_aca_worked_example():
    # ACA spells this permutation out under its 111,112,...,333 coordinates.
    cube = 'EXTRAODINYBCFGHJKLMPQSUVWZ#'
    assert C.trifid_decrypt_stated('EYMXVUCRYYYYEAYVYOVVXITDPATHE', cube, 10) == 'TRIFIDSAREFRACTIONATEDCIPHERS'


def test_four_square_aca_worked_example():
    tr, bl = 'GRDLUEYFNVOAHPWMBIQXTCKSZ', 'LICNVOTDPWGHEQXAMFSYRBKUZ'
    plain, cipher = 'COMEQUICKLYWENEEDHELPX', 'LEWIXAFNEXCUDXUVDPGXHZ'
    # pycipher.Foursquare 0.5.2 is unusable on Python3 (/ makes float indices).
    # Use the ACA's printed worked example directly; no engine-derived oracle.
    assert C.four_square_decrypt_stated(cipher, 'ABCDEFGHIKLMNOPQRSTUVWXYZ', tr, bl) == plain


def test_rail_fence_asu_worked_example():
    plain, cipher = 'BUYYOURBOOKSINAUGUST', 'BOOIGUYUBOSNUUTYRKAS'
    assert pycipher.Railfence(3).encipher(plain) == cipher
    assert C.rail_fence_decrypt(cipher, 3) == plain
    assert (3, plain) in C.rail_fence_all(cipher, max_rails=5)


def test_columnar_cryptool_worked_example():
    plain, cipher = 'HELLOWORLDHOWAREYOU', 'LLRERAOHYLDEHOWUWOO'
    # SECRET has stable sorted column order C,E,E,R,S,T = 2,1,4,3,0,5.
    assert pycipher.ColTrans('SECRET').encipher(plain) == cipher
    assert C.columnar_decrypt(cipher, (2, 1, 4, 3, 0, 5)) == plain


def test_columnar_all_contains_independently_encoded_plaintext():
    plain = 'ATTACKATDAWN'
    expected = pycipher.ColTrans('CAB').encipher(plain)
    assert ((1, 2, 0), plain) in C.columnar_all(expected, max_cols=3)


def test_columnar_short_vector_oracle():
    # Five columns over three cells still permute the occupied columns.
    assert pycipher.ColTrans('CABDE').encipher('ABC') == 'BCA'


def test_columnar_short_ciphertext_independent_oracle():
    assert C.columnar_decrypt('BCA', (1, 2, 0, 3, 4)) == 'ABC'


_BREAKERS = {
    'caesar_all': lambda text: C.caesar_all(text),
    'affine_all': lambda text: C.affine_all(text),
    'rail_fence_all': lambda text: C.rail_fence_all(text, max_rails=3),
    'columnar_all': lambda text: C.columnar_all(text, max_cols=3),
    'substitution_hillclimb': lambda text: C.substitution_hillclimb(text, deadline=0, restarts=1),
    'playfair_crack': lambda text: C.playfair_crack(text, deadline=0, restarts=1),
    'bifid_crack': lambda text: C.bifid_crack(text, deadline=0, restarts=1),
    'hill_crack_2x2': lambda text: C.hill_crack_2x2(text, deadline=0, top=1),
    'adfgvx_crack': lambda text: C.adfgvx_crack(text, deadline=0, max_width=2, restarts=1, iters=1),
    'polygraphic_candidates': lambda text: C.polygraphic_candidates(text, deadline=0),
    'solve_classical': lambda text: C.solve_classical(text, deadline=0),
}
_RNG = random.Random(0xC1A551CA1)
_FUZZ_TEXTS = [
    '', '\x00\x01\x7f', '\ud800\udfff\x00éİß中😀\u202e',
    ''.join(_RNG.choice(string.printable) for _ in range(137)),
    ''.join(chr(_RNG.randrange(0x110000)) for _ in range(67)),
]


@pytest.mark.parametrize('name', _BREAKERS)
@pytest.mark.parametrize('text', _FUZZ_TEXTS, ids=['empty', 'controls', 'unicode', 'seeded-ascii', 'seeded-unicode'])
def test_breaker_fail_closed_string_fuzz(name, text):
    # No try/except by design: there is no declared engine exception to accept.
    result = _BREAKERS[name](text)
    assert result is None or isinstance(result, (list, tuple))


@pytest.mark.parametrize('name', ['substitution_hillclimb', 'playfair_crack', 'bifid_crack',
                                  'hill_crack_2x2', 'adfgvx_crack', 'polygraphic_candidates'])
def test_breaker_very_long_junk_fails_closed(name):
    # Exceeds MAX_TEXT. No cipher alphabet means no key search is requested.
    result = _BREAKERS[name]('\x00' * (C.MAX_TEXT + 1))
    assert result is None or isinstance(result, (list, tuple))


@pytest.mark.parametrize('name', ['substitution_hillclimb', 'playfair_crack', 'bifid_crack',
                                  'hill_crack_2x2', 'adfgvx_crack'])
def test_tolerant_breaker_none_fails_closed(name):
    result = _BREAKERS[name](None)
    assert result is None or isinstance(result, (list, tuple))


@pytest.mark.parametrize('name', ['caesar_all', 'affine_all', 'rail_fence_all', 'columnar_all',
                                  'polygraphic_candidates', 'solve_classical'])
def test_breaker_none_must_not_leak_stdlib(name):
    assert _BREAKERS[name](None) is None


@pytest.mark.parametrize('name', ['caesar_all', 'affine_all', 'solve_classical'])
def test_breaker_byte_input_must_not_leak_stdlib(name):
    assert _BREAKERS[name](b'\xff') is None


def test_adfgvx_empty_key_fails_closed():
    assert C.adfgvx_decrypt('ADFGVX', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', '') is None


def test_columnar_bad_permutation_fails_closed():
    assert C.columnar_decrypt('ABCDEFGH', (0, 99)) is None


def test_trifid_invalid_coordinate_order_fails_closed():
    assert C.trifid_decrypt_stated('ABC', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ#', 3, coordinate_order=None) is None


@pytest.mark.parametrize('order', [(), (0, 0), (0, 99), (-1, 0), (0, '1'), None])
def test_columnar_and_adfgvx_invalid_permutations(order):
    assert C.columnar_decrypt('ABCD', order) is None
    assert C.adfgvx_decrypt('ADFGVX', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', order) is None
    assert C.adfgvx_encrypt('ABCD', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', order) is None


def test_solve_classical_rejected_crib_does_not_leak():
    assert isinstance(C.solve_classical('HELLO', crib='İ', deadline=0), list)


def test_empty_breaker_reference_results():
    # Empty input has no analyzable symbols; simple exhaustive transforms retain
    # each mathematical key while actual cryptanalytic candidates stay empty.
    assert C.caesar_all('') == [(key, '') for key in range(26)]
    assert C.affine_all('') == [((a, b), '') for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25) for b in range(26)]
    for name in ('rail_fence_all', 'columnar_all', 'playfair_crack', 'bifid_crack',
                 'hill_crack_2x2', 'adfgvx_crack', 'polygraphic_candidates', 'solve_classical'):
        assert _BREAKERS[name]('') == []
    assert _BREAKERS['substitution_hillclimb']('') is None
