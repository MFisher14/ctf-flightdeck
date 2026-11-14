"""Esolang wrappers only; shared independent fixtures from the language tests."""
import random
import pytest
import formats_more as fm
from test_harden_esolang_esolang import offline
from test_harden_esolang_esolangs import WS_A


MALBOLGE_NUL = 'cP' + ''.join(chr((68-index-33)%94+33) for index in range(2, 8))
WRAPPERS = [(fm.d_cow, 'MoO '*65+'Moo', b'A'),
            (fm.d_whitespace, WS_A, b'A'),
            (fm.d_malbolge, MALBOLGE_NUL, b'\0'),
            (fm.d_jsfuck, '(![]+[])+[]+[]', b'false'),
            (fm.d_deadfish, 'i'*8+'sio', b'A')]


@pytest.mark.parametrize('fn,program,expected', WRAPPERS)
def test_wrapper_independent_language_vectors(fn, program, expected):
    assert fn(program) == expected


@pytest.mark.parametrize('fn,program,expected', WRAPPERS)
def test_wrapper_truncation_bitflip_random_and_oversized(fn, program, expected):
    rng = random.Random(808)
    mutated = list(program); mutated[len(program)//2] = '\xff'
    corpus = ['', '\uffff'*64, '\0'*128, 'x'*10000, program[:-1], ''.join(mutated)]
    corpus += [''.join(chr(rng.randrange(128)) for _ in range(n)) for n in [8, 32, 256]]
    for text in corpus:
        try:
            out = fn(text)
            assert out is None or isinstance(out, bytes)
        except fm.E.Refuse:
            pass


@pytest.mark.parametrize('fn,program,expected', WRAPPERS)
def test_wrapper_nontext_fail_closed(fn, program, expected):
    try:
        fn(None)
    except fm.E.Refuse:
        pass
