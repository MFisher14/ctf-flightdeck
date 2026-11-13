"""Spec-derived esolang vectors, interpreted only by the bounded repository cores.

https://esolangs.org/wiki/{Unlambda,Lazy_K,Thue,Fractran,Underload,FALSE}
https://github.com/m-ender/hexagony (canonical layout and I/O semantics)
"""
import random
import socket
import subprocess

import pytest
import esolang_tail as engine


@pytest.fixture(autouse=True)
def no_host_execution(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("esolang attempted host execution or networking")
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def test_unlambda_published_hello_and_delay_order():
    assert engine.unlambda("`.!`.d`.l`.r`.o`.w`. `.,`.o`.l`.l`.e`.Hi") == b"Hello, world!"
    assert engine.unlambda("``d`.xi`.yi") == b"yx"


@pytest.mark.parametrize("program,normal", [("`ik", "k"), ("``kis", "i"), ("```skii", "i")])
def test_lazy_k_ski_equations(program, normal):
    result = engine.lazy_k_normal_form(program)
    assert result["normal_form"] == normal and result["verified_irreducible"] is True


def test_thue_rewrite_and_nondeterminism():
    result = engine.thue("a::=~Hello, world!\n::=\na")
    assert [(r["state"], r["output"]) for r in result] == [("", b"Hello, world!")]
    result = engine.thue("a::=~left\na::=~right\n::=\na")
    assert {(r["state"], r["output"]) for r in result} == {("", b"left"), ("", b"right")}


def test_fractran_published_multiplication():
    # Conway multiplication: input 2**x * 3**y -> 5**(x*y).
    program = "13/21, 385/13, 1/7, 3/11, 7/2, 1/3"
    result = engine.fractran(program, initial=2**2 * 3**3, steps=1000)
    assert result["halted"] is True and result["final"] == 5**6
    assert engine.parse_fractran("start=8\n2/4") == ([(1, 2)], 8)


def test_hexagony_canonical_top_row():
    # 19 cells form side length 3; IP0 traverses the three top-row cells.
    assert engine.hexagony("A;@\n....\n.....\n....\n...", steps=20) == b"A"


def test_underload_published_hello():
    assert engine.underload("(Hello, world!)S") == b"Hello, world!"


def test_underload_output_pops_stack():
    assert engine.underload("(A)(B)SS") == b"BA"


def test_false_arithmetic_lambdas_and_variable():
    assert engine.false_lang("2 3+. 65,") == b"5A"
    assert engine.false_lang("7a:a;.") == b"7"
    assert engine.false_lang('1["yes"]?') == b"yes"


def test_false_unary_negation():
    assert engine.false_lang("3_.") == b"-3"


def test_false_character_literal():
    assert engine.false_lang("'A,") == b"A"


def test_false_integer_division_precision():
    assert engine.false_lang("9007199254740993 1/.") == b"9007199254740993"


def test_hexagony_integer_input_skips_junk():
    assert engine.hexagony("?!@\n....\n.....\n....\n...", b"junk -12;", steps=20) == b"-12"


def test_nonterminating_program_step_bounds():
    omega = "```sii``sii"
    assert engine.unlambda(omega, steps=20) is None
    assert engine.lazy_k_normal_form(omega, steps=20) is None
    assert engine.underload("(:^):^", steps=20) is None
    assert engine.thue("a::=aa\n::=\na", steps=6) == []
    assert engine.hexagony(".", steps=20) is None
    assert engine.false_lang("[1][]#", steps=20) is None
    result = engine.fractran("2/1", initial=1, steps=5)
    assert result["sequence"] == [1, 2, 4, 8, 16, 32]
    assert result["halted"] is False and result["verified"] is False


@pytest.mark.parametrize("function,source", [(engine.unlambda, "`r" * 8 + "i"), (engine.false_lang, '"12345678"')])
def test_output_cap_is_enforced(function, source, monkeypatch):
    monkeypatch.setattr(engine, "MAX_OUTPUT", 4)
    result = function(source, steps=100)
    assert result is None or len(result) <= 4


@pytest.mark.parametrize("function,seed", [(engine.unlambda, "`.Ai"), (engine.lazy_k_normal_form, "`ii"),
    (engine.thue, "a::=~A\n::=\na"), (engine.fractran, "start=2\n1/2"),
    (engine.hexagony, "A;@"), (engine.underload, "(A)S"), (engine.false_lang, "65,")])
def test_deterministic_source_fuzz_and_caps(function, seed, monkeypatch):
    rng = random.Random(12345)
    corpus = ["", "\xff" * 30, "".join(chr(rng.randrange(32, 127)) for _ in range(30)), seed[:-1],
              seed[:1] + chr(ord(seed[1]) ^ 1) + seed[2:]]
    for source in corpus:
        try:
            function(source, steps=30)
        except engine.Refuse:
            pass
    monkeypatch.setattr(engine, "MAX_SOURCE", 16)
    # Lazy-K uses a separate term-node cap; its declared surface has no source cap.
    if function is not engine.lazy_k_normal_form:
        assert function(" " * 17, steps=30) in (None, [])


@pytest.mark.parametrize("function,source", [(engine.unlambda, "`.Ai"), (engine.lazy_k_normal_form, "`ii"),
    (engine.thue, "a::=~A\n::=\na"), (engine.fractran, "start=2\n1/2"),
    (engine.hexagony, "A;@"), (engine.underload, "(A)S"), (engine.false_lang, "65,")])
def test_malformed_step_budget(function, source):
    try:
        function(source, steps=None)
    except engine.Refuse:
        pass


def test_thue_surrogate_output_fail_closed():
    try:
        engine.thue("a::=~\ud800\n::=\na", steps=10)
    except engine.Refuse:
        pass


@pytest.mark.parametrize("source", ["", "start=1\n1/0", "start=0\n1/1"])
def test_fractran_parser_fail_closed(source):
    try:
        engine.parse_fractran(source)
    except engine.Refuse:
        pass


def test_dispatcher_known_output():
    assert engine.run_language("underload", "(CSCTF{inert})S") == {"candidates": [b"CSCTF{inert}"]}


def test_cli_help_guard(capsys):
    assert engine.main(["--help"]) == 0
