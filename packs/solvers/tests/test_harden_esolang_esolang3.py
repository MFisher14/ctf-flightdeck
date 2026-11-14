"""Published Fish Hello World and LOLCODE 1.2 expression/output semantics.

References: esolangs.org/wiki/Fish and
github.com/justinmeza/lolcode-spec/blob/master/v1.2/lolcode-spec-v1.2.md.
"""
import random
import socket
import subprocess

import pytest

import esolang3 as engine


@pytest.fixture(autouse=True)
def bounded_offline(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("interpreter attempted external execution/network")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(engine, "STEPS", 512)
    monkeypatch.setattr(engine, "_deadline", lambda: float("inf"))
    monkeypatch.setattr(engine, "DEADLINE", [None])
    monkeypatch.setattr(engine, "_FM", None)


def fish(source):
    return source.encode() + b" " * 20


def lol(source):
    return ("HAI 1.2\n" + source + "\nKTHXBYE\n").encode()


def test_fish_published_hello_world():
    raw = b'"!dlrow ,olleH"l?!;oe0.'
    assert engine.d_fish(raw) == b"Hello, world!"
    assert engine.steps(raw) == [("fish", b"Hello, world!")]
    assert engine.step_fn("fish")(raw) == b"Hello, world!"


@pytest.mark.parametrize("source,expected", [
    ("123@nnn;", b"213"),
    ("123{nnn;", b"132"),
    ("123}nnn;", b"213"),
    ("123rnnn;", b"123"),
    ("a2*n;", b"20"),
    ("9&3&-n;", b"-6"),
    ("73-n;", b"4"),
    ("84,n;", b"2"),
    ("83%n;", b"2"),
])
def test_fish_documented_stack_and_arithmetic(source, expected):
    assert engine.d_fish(fish(source)) == expected


@pytest.mark.parametrize("source,expected", [
    ('VISIBLE "Hello World!"', b"Hello World!\n"),
    ('VISIBLE "Hello"!', b"Hello"),
    ('I HAS A X ITZ 40\nX R SUM OF X AN 2\nVISIBLE X', b"42\n"),
    ('VISIBLE SMOOSH "CSCTF" AN "{fixture}" MKAY!', b"CSCTF{fixture}"),
    ('VISIBLE "A:)B:>C::D:(41)"!', b"A\nB\tC:DA"),
    ('I HAS A X ITZ 4\nI HAS A x ITZ 7\nVISIBLE DIFF OF x AN X', b"3\n"),
    ('BTW comment\nVISIBLE PRODUKT OF 6 AN 7', b"42\n"),
])
def test_lolcode_spec_semantics(source, expected):
    raw = lol(source)
    assert engine.d_lolcode(raw) == expected
    assert engine.step_fn("lolcode")(raw) == expected
    assert engine.read(raw) == []


def test_step_output_and_grid_caps(monkeypatch):
    assert engine.d_fish(fish(">")) is None
    assert engine.d_fish(fish("1")) is None  # growing stack, no terminating instruction
    assert engine.d_lolcode(lol("IM IN YR LOOP\nVISIBLE 1\nIM OUTTA YR LOOP")) is None
    monkeypatch.setattr(engine, "OUTPUT", 2)
    assert engine.d_fish(fish('"ABC"ooo;')) is None
    assert engine.d_lolcode(lol('VISIBLE "ABC"!')) is None
    monkeypatch.setattr(engine, "FISH_GRID", 16)
    assert engine.d_fish(fish('"A"o;')) is None


def test_all_decoder_fuzz_and_no_input_execution():
    valid = lol('VISIBLE "Hello World!"')
    samples = [None, [], {}, "text", b"", b"\xff" * 4096, random.Random(802).randbytes(2048), b"x" * (engine.MAX_PROG + 1)]
    samples += [valid[:n] for n in range(0, len(valid), 3)]
    for index in range(0, len(valid), 5):
        changed = bytearray(valid); changed[index] ^= 0x80; samples.append(bytes(changed))
    for raw in samples:
        for function in [engine.d_fish, engine.d_lolcode, engine.steps, engine.read]:
            function(raw)
    for source in ["i;", "x;", "10,n;", "+;"]:
        assert engine.d_fish(fish(source)) is None
    assert engine.d_lolcode(lol("GIMMEH X\nVISIBLE X")) is None
