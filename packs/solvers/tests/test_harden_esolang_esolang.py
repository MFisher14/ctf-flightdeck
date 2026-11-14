"""BF dialect locks from esolangs.org language command tables, not repo encoders."""
import os
import random
import socket
import subprocess

import pytest
import esolang as es


# Eight times eight, then one: independently reasoned two-cell program prints A.
PRINT_A = '++++++++[>++++++++<-]>+.'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    calls = []
    def blocked(*args, **kwargs):
        calls.append('forbidden execution/network')
        raise AssertionError(calls[-1])
    for obj, names in [(os, ['system', 'popen']), (subprocess, ['Popen', 'run', 'call']),
                       (socket, ['create_connection'])]:
        for name in names:
            monkeypatch.setattr(obj, name, blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    yield
    assert calls == []


def test_brainfuck_multiply_loop_and_byte_wrap():
    assert es.run_bf(PRINT_A, steps=500) == b'A'
    assert es.run_bf('-.+.') == b'\xff\x00'
    assert es.run_bf('[,]+++.') == b'\x03'


# Literals use the published command tables: 65 increments then output.
DIALECTS = [
    ('alphuck', es.d_alphuck, b'e'*65+b'j'),
    ('pikalang', es.d_pikalang, b'pi '*65+b'pikachu'),
    ('blub', es.d_blub, b'Blub. Blub. '*65+b'Blub! Blub.'),
    ('spoon', es.d_spoon, b'1'*65+b'00101000101111'),
]


@pytest.mark.parametrize('name,fn,program', DIALECTS)
def test_published_dialect_commands_and_public_routing(name, fn, program):
    assert fn(program) == b'A'
    assert (name, b'A') in es.steps(program)
    assert es.step_fn(name)(program) == b'A'
    assert es.read(program, crib='A') == [(name, 'A')]
    assert es.read(program, crib='CSCTF{') == []


@pytest.mark.parametrize('program,kwargs', [
    ('+[.]', {'steps': 20}), ('.'*5, {'out_cap': 4}),
    ('>+.', {'cells': 1}), ('<+.', {}), (',.', {}), ('[+.', {}), (']+.', {}),
])
def test_small_limits_and_malformed_programs_return_no_partial_output(program, kwargs):
    assert es.run_bf(program, **kwargs) is None


@pytest.mark.parametrize('name,fn,program', DIALECTS)
def test_dialect_seeded_fuzz_input_cap_and_truncation(name, fn, program, monkeypatch):
    rng = random.Random(808)
    corpus = [None, '', {}, b'', b'\xff'*64, b'x'*1025, program[:17], program[:-1]]
    corpus += [rng.randbytes(n) for n in [1, 16, 64, 256]]
    flipped = bytearray(program); flipped[len(flipped)//2] ^= 0x80; corpus.append(bytes(flipped))
    monkeypatch.setattr(es, 'MAX_PROG', 1024)
    for blob in corpus:
        result = fn(blob)
        assert result is None or isinstance(result, bytes)


def test_zero_cell_tape_fail_closed():
    es.run_bf('+.', cells=0)


def test_released_input_buffer_fail_closed():
    view = memoryview(b'e'*65+b'j'); view.release()
    es.d_alphuck(view)


def test_cli_guard(capsys):
    assert es.main([]) == 2
    assert es.main(['--unknown']) == 2
