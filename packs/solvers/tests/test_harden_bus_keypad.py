"""ITU-T Q.23 frequency pairs and documented telephone multitap semantics.

https://www.itu.int/rec/T-REC-Q.23-198811-I/en
No engine tables/output are used as an oracle.
"""
import random

import pytest

import keypad


PAIRS = [(lo, hi, key) for lo, row in [(697, '123A'), (770, '456B'), (852, '789C'), (941, '*0#D')]
         for hi, key in zip([1209, 1336, 1477, 1633], row)]


@pytest.mark.parametrize('low,high,key', PAIRS)
def test_q23_exact_and_swapped_pairs(low, high, key):
    assert keypad.dtmf_key(low, high) == key
    assert keypad.dtmf_key(high, low) == key
    assert keypad.dtmf_key(low * 1.01, high * .99) == key


def test_frequency_sequence_is_all_or_nothing():
    assert keypad.dtmf_from_frequencies([(low, high) for low, high, _ in PAIRS]) == '123A456B789C*0#D'
    assert keypad.dtmf_from_frequencies([(697, 1209), (1, 2), (770, 1336)]) is None
    assert keypad.dtmf_from_frequencies([]) == ''


@pytest.mark.parametrize('presses,expected', [
    ('44 33 555 555 666', 'HELLO'), ('7777-666-7777', 'SOS'),
    (['2', '22', '222', '2222'], 'ABCA'), ('9999 7777 0 1', 'ZS 1'),
    ('', ''), ('23', None), ('*', None), (None, None),
])
def test_multitap_reference_vectors(presses, expected):
    assert keypad.multitap_decode(presses) == expected


@pytest.mark.parametrize('digit,expected', [(2, 'ABC'), (3, 'DEF'), (4, 'GHI'), (5, 'JKL'),
                                          (6, 'MNO'), (7, 'PQRS'), (8, 'TUV'), (9, 'WXYZ'), ('x', '')])
def test_keycap_letters(digit, expected):
    assert keypad.keypad_letters(digit) == expected


def test_deterministic_invalid_inputs_and_large_finite_runs():
    rng = random.Random(2026)
    for size in (0, 1, 2, 7, 31, 1000):
        raw = rng.randbytes(size)
        assert keypad.dtmf_key(raw, 1336) is None
        result = keypad.multitap_decode(raw)
        assert result is None or isinstance(result, str)
        assert keypad.dtmf_from_frequencies([raw]) is None
    assert keypad.multitap_decode('7' * 100000) == 'S'
    assert keypad.dtmf_from_frequencies([(697, 1209)] * 10000) == '1' * 10000


@pytest.mark.parametrize('low,high', [(float('nan'), 1209), (697, float('nan'))])
def test_nan_frequency_is_not_a_valid_key(low, high):
    assert keypad.dtmf_key(low, high) is None


def test_oversized_integer_declines_cleanly():
    assert keypad.dtmf_key(10 ** 1000, 1336) is None


def test_none_frequency_sequence_declines_cleanly():
    assert keypad.dtmf_from_frequencies(None) is None
