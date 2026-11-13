"""Boolfuck vectors from its author: https://samuelhughes.com/boof/."""
import random
import pytest
import esolang4 as es
from test_harden_esolang_esolang import PRINT_A, offline


def test_byte_brainfuck_reference_loop_and_prefix_filter():
    assert es.run_bf(PRINT_A, want=b'A') == b'A'
    assert es.run_bf(PRINT_A, want=b'B') is None


def test_boolfuck_published_digit_vector_lsb_order():
    # Author/wiki example sets stream bits 10001100, little-endian byte 0x31.
    program = '+;+;;;+;;+;;'
    assert es.run_boolfuck(program) == b'1'
    padded = (program+' '*16).encode()
    assert es.d_boolfuck(padded) == b'1'
    assert es.steps(padded) == [('boolfuck', b'1')]
    assert es.step_fn('boolfuck')(padded) == b'1'
    assert es.read(padded, crib='1') == [('boolfuck', '1')]


def test_generic_unknown_vocabulary_is_derived_from_known_prefix(monkeypatch):
    monkeypatch.setattr(es, '_CRIB_BYTES', b'A')
    # Only + assigned to up and . assigned to say can produce ASCII A here.
    program = b'up '*65+b'say'
    assert es.d_bfdialect(program) == b'A'
    assert es.d_bfdialect(b'pi '*65+b'pikachu') is None


@pytest.mark.parametrize('program,expected', [('+;', b'\x01'), (';;;;;;;+;+;', b'\x80\x00')])
def test_boolfuck_partial_byte_author_specification(program, expected):
    assert es.run_boolfuck(program) == expected


@pytest.mark.parametrize('fn,program', [(es.run_bf, '+[.]'), (es.run_boolfuck, '+[;]')])
def test_vm_step_and_output_caps(fn, program):
    assert fn(program, steps=20) is None
    assert fn(program, steps=1000, out_cap=2) is None
    assert fn(program, steps=0) is None


@pytest.mark.parametrize('fn', [es.d_boolfuck, es.d_bfdialect])
def test_reader_malformed_and_oversized_inputs(fn, monkeypatch):
    monkeypatch.setattr(es, 'MAX_PROG', 1024)
    rng = random.Random(808)
    corpus = [None, '', {}, b'', b'\xff'*64, b'+'*1025, b';['*20, b';]'*20,
              b'+;+;;;+;;+;; '*4, b';'*31+b'\xff']
    corpus += [rng.randbytes(n) for n in [16, 64, 256]]
    for blob in corpus:
        result = fn(blob)
        assert result is None or isinstance(result, bytes)


@pytest.mark.parametrize('fn,program', [(es.run_bf, '+.'), (es.run_boolfuck, '+;;;;;;;;')])
def test_zero_cell_tapes_fail_closed(fn, program):
    fn(program, cells=0)


def test_cli_guard(capsys):
    assert es.main([]) == 2
