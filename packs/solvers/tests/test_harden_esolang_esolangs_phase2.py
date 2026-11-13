"""Published Whirl addition and Kipple Hello World/cat, plus bounded fuzz.

https://esolangs.org/wiki/Whirl
https://esolangs.org/wiki/Kipple
"""
import random
import socket
import subprocess

import pytest
import esolangs_phase2 as engine

WHIRL_ADD = "0110010000110001100010011001100011110000011100"
KIPPLE_HELLO = "33>o 100>o 108>o 114>o 111>o 87>o 32>o 111>o 108>o 108>o 101>o 72>o"


@pytest.fixture(autouse=True)
def no_host_execution(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("esolang attempted host execution or networking")
    monkeypatch.setattr(subprocess, "Popen", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


@pytest.mark.parametrize("left,right", [(7, 5), (-7, 5), (0, 0)])
def test_whirl_published_addition(left, right):
    result = engine.run_whirl(WHIRL_ADD, integer_input=[left, right], max_steps=1000)
    assert result["output"] == str(left + right)
    assert result["input_consumed"] == {"integers": 2, "characters": 0}


def test_whirl_exit_and_latch():
    result = engine.run_whirl("100", max_steps=10)
    assert result["stop_reason"] == "exit" and result["steps"] == 3
    assert result["trace"][0]["command"] == "exit"


def test_kipple_published_hello_cat_and_reverse():
    assert engine.run_kipple(KIPPLE_HELLO)["output"] == "Hello World!"
    assert engine.run_kipple('"Hello World!">o')["output"] == "Hello World!"
    assert engine.run_kipple("(i>o)", input_text="CSCTF{cat}")["output"] == "CSCTF{cat}"
    assert engine.run_kipple("(i>p)(p>o)", input_text="ABC")["output"] == "CBA"


def test_kipple_arithmetic_signed_wrap_and_number_stack():
    assert engine.run_kipple("2147483647>a a+1")["stacks"]["a"] == [2147483647, -2147483648]
    assert engine.run_kipple("123>@ (@>o)")["output"] == "123"


def test_step_output_and_storage_limits():
    result = engine.run_whirl("1" * 100, max_steps=5)
    assert result["steps"] == 5 and result["stop_reason"] == "step_limit"
    with pytest.raises(engine.Refuse):
        engine.run_kipple("1>a (a)", max_steps=10)
    with pytest.raises(engine.Refuse):
        engine.run_kipple(KIPPLE_HELLO, max_output=5)
    with pytest.raises(engine.Refuse):
        engine.run_kipple("1>a 2>a 3>a", max_stack_items=2)
    with pytest.raises(engine.Refuse):
        engine.run_whirl(WHIRL_ADD, integer_input=[999, 1], max_output=2)


def test_identification_is_static():
    assert any(r["language"] == "whirl" for r in engine.identify_esolangs(WHIRL_ADD, filename="known.whirl"))
    assert any(r["language"] == "kipple" for r in engine.identify_esolangs(KIPPLE_HELLO, filename="known.kip"))
    assert isinstance(engine.analyze(KIPPLE_HELLO, filename="known.kip"), dict)


@pytest.mark.parametrize("function,seed", [(engine.run_whirl, WHIRL_ADD), (engine.run_kipple, KIPPLE_HELLO)])
def test_seeded_source_fuzz_and_source_cap(function, seed, monkeypatch):
    rng = random.Random(321)
    corpus = [None, "", "\xff" * 30, "\ud800", seed[:-1], seed[:1] + chr(ord(seed[1]) ^ 1) + seed[2:],
              "".join(chr(rng.randrange(32, 127)) for _ in range(40))]
    for source in corpus:
        try:
            function(source, max_steps=30)
        except engine.Refuse:
            pass
    monkeypatch.setattr(engine, "MAX_SOURCE_CHARS", 16)
    with pytest.raises(engine.Refuse):
        function(" " * 17, max_steps=20)


@pytest.mark.parametrize("function,source", [(engine.run_whirl, "100"), (engine.run_kipple, "65>o")])
@pytest.mark.parametrize("field", ["max_steps", "max_output"])
def test_malformed_budget(function, source, field):
    try:
        function(source, **{field: None})
    except engine.Refuse:
        pass


@pytest.mark.parametrize("argv,expected", [(["--help"], 0), ([], 2), (["--unknown"], 2)])
def test_cli_guard(argv, expected, capsys):
    assert engine.main(argv) == expected
