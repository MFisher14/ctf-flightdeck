"""Aheui and SNUSP vectors from documented language instructions and examples.

https://esolangs.org/wiki/Aheui
https://esolangs.org/wiki/SNUSP
Hangul fixtures are literal source, never encoded with engine.compose_aheui.
"""
import random
import socket
import subprocess

import pytest
import esolangs_remaining as engine


@pytest.fixture(autouse=True)
def no_host_execution(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("esolang attempted host execution or networking")
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def test_aheui_published_addition_and_queue():
    assert engine.run_aheui("방방다망희", number_input=[7, 5], steps=100)["output_text"] == "12"
    assert engine.run_aheui("상박받망망하", steps=100)["output_text"] == "23"
    result = engine.run_aheui("밯맣하", char_input="界", steps=100)
    assert result["output_text"] == "界" and result["output_hex"] == "e7958c"


def test_aheui_published_hello_world():
    source = "밤밣따빠밣밟따뿌\n빠맣파빨받밤뚜뭏\n돋밬탕빠맣붏두붇\n볻뫃박발뚷투뭏붖\n뫃도뫃희멓뭏뭏붘\n뫃봌토범더벌뿌뚜\n뽑뽀멓멓더벓뻐뚠\n뽀덩벐멓뻐덕더벅"
    # The author's annotated spiral ends 박(push 2), 발(push 5), 뚷(mul),
    # 멓(output character), 희(halt): the final output is LF (2*5).
    # https://hut.mearie.org/aheui/
    assert engine.run_aheui(source, steps=2000)["output_text"] == "Hello, world!\n"


def test_unicode_hangul_composition_known_codepoints():
    # Unicode Hangul algorithm AC00 + (L*21 + V)*28 + T.
    assert engine.compose_aheui(0, 0, 0) == "가"
    assert engine.compose_aheui(18, 20, 27) == "힣"
    assert engine.decompose_aheui("가") == (0, 0, 0)
    assert engine.decompose_aheui("힣") == (18, 20, 27)
    assert engine.decompose_aheui("A") is None


def test_snusp_io_arithmetic_and_conditional_skip():
    result = engine.run_snusp("$,.,.,.", b"ABC", steps=100)
    assert result["output_text"] == "ABC" and result["output_hex"] == "414243"
    assert engine.run_snusp("$-.+.", steps=100)["output_hex"] == "ff00"
    assert engine.run_snusp("$?+.", steps=100)["output_hex"] == "00"
    assert engine.run_snusp("$!+.", steps=100)["output_hex"] == "00"


@pytest.mark.parametrize("function,source", [(engine.run_aheui, "아"), (engine.run_snusp, "/$\\\n\\ /")])
def test_nonterminating_step_cap(function, source):
    with pytest.raises(engine.Refuse):
        function(source, steps=20)


def test_input_source_output_bounds(monkeypatch):
    monkeypatch.setattr(engine, "MAX_STORAGE", 2)
    consumed = []
    def numbers():
        for i in range(20):
            consumed.append(i)
            yield i
    with pytest.raises(engine.Refuse):
        engine.run_aheui("하", number_input=numbers(), steps=20)
    assert consumed == [0, 1, 2]
    monkeypatch.setattr(engine, "MAX_OUTPUT", 2)
    with pytest.raises(engine.Refuse):
        engine.run_snusp("$,.,.,.", b"ABC", steps=100)
    with pytest.raises(engine.Refuse):
        engine.run_aheui("밯맣하", char_input="界", steps=100)
    monkeypatch.setattr(engine, "MAX_SOURCE", 16)
    for function in (engine.run_aheui, engine.run_snusp):
        with pytest.raises(engine.Refuse):
            function(" " * 17, steps=20)


@pytest.mark.parametrize("function,seed", [(engine.run_aheui, "박망하"), (engine.run_snusp, "$++.")])
def test_seeded_source_fuzz(function, seed):
    rng = random.Random(123)
    corpus = ["", "\xff" * 40, "".join(chr(rng.randrange(32, 127)) for _ in range(40)),
              seed[:-1], chr(ord(seed[0]) ^ 1) + seed[1:], "\ud800", None]
    for source in corpus:
        try:
            function(source, steps=30)
        except engine.Refuse:
            pass


@pytest.mark.parametrize("function", [engine.run_aheui, engine.run_snusp])
@pytest.mark.parametrize("steps", [None, float("nan")])
def test_invalid_step_budget(function, steps):
    try:
        function("하", steps=steps)
    except engine.Refuse:
        pass


@pytest.mark.parametrize("function", [engine.identify_aheui, engine.identify_snusp])
def test_identifier_invalid_source(function):
    try:
        function(None)
    except engine.Refuse:
        pass


def test_cli_help_guard(capsys):
    assert engine.main(["--help"]) == 0
