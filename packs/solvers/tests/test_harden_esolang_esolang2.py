"""Original small programs derived from Chef and SPL documented semantics.

Oracles: dangermouse.net/esoteric/chef.html; esolangs.org/wiki/Shakespeare.
No engine encoder is used. Only the bounded interpreter consumes these fixtures.
"""
import random
import socket
import subprocess

import pytest

import esolang2 as engine


@pytest.fixture(autouse=True)
def bounded_offline(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("interpreter attempted external execution/network")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(engine, "STEPS", 256)
    monkeypatch.setattr(engine, "_deadline", lambda: float("inf"))


def recipe(ingredients, method):
    return ("Fixture Soup.\n\nIngredients.\n" + ingredients + "\n\nMethod.\n" + method + "\n\nServes 1.\n").encode()


def play(speech):
    return ("A Fixture.\n\nRomeo, a man.\nJuliet, a woman.\n\nAct I: Counting.\nScene I: Values.\n[Enter Romeo and Juliet]\nRomeo:\n" + speech + "\n[Exeunt]\n").encode()


POUR = "Pour contents of the mixing bowl into the baking dish."


@pytest.mark.parametrize("ingredients,method,expected", [
    ("65 ml milk", "Put milk into the mixing bowl. " + POUR, b"A"),
    ("2 g flour\n3 g salt", "Put flour into the mixing bowl. Add salt. " + POUR, b"5"),
    ("65 ml milk\n66 ml water", "Put milk into the mixing bowl. Put water into the mixing bowl. " + POUR, b"BA"),
    ("65 g flour", "Put flour into the mixing bowl. Liquefy contents of the mixing bowl. " + POUR, b"A"),
])
def test_chef_documented_stack_and_arithmetic(ingredients, method, expected):
    raw = recipe(ingredients, method)
    assert engine.d_chef(raw) == expected
    assert engine.steps(raw) == [("chef", expected)]
    assert engine.step_fn("chef")(raw) == expected
    assert engine.read(raw) == []  # a decoded byte is not a matching challenge crib


@pytest.mark.parametrize("speech,expected", [
    ("You are a beautiful flower. Open your heart.", b"2"),
    ("You are a vile coward. Open your heart.", b"-2"),
    ("You are the sum of a beautiful flower and a flower. Open your heart.", b"3"),
    ("You are the sum of a beautiful beautiful beautiful beautiful beautiful beautiful flower and a flower. Speak your mind.", b"A"),
])
def test_spl_documented_sign_adjectives_arithmetic_and_output(speech, expected):
    raw = play(speech)
    assert engine.d_shakespeare(raw) == expected
    assert engine.step_fn("shakespeare")(raw) == expected


def test_caps_and_nonterminating_spl(monkeypatch):
    assert engine.d_shakespeare(play("Let us proceed to scene I.")) is None
    monkeypatch.setattr(engine, "OUTPUT", 1)
    assert engine.d_chef(recipe("65 ml milk", "Put milk into the mixing bowl. Put milk into the mixing bowl. " + POUR)) is None
    assert engine.d_shakespeare(play("You are a beautiful flower. Open your heart. Open your heart.")) is None
    monkeypatch.setattr(engine, "MAX_PROG", 32)
    assert engine.d_chef(recipe("65 ml milk", "Put milk into the mixing bowl. " + POUR)) is None


def test_parser_fuzz_and_refused_input():
    valid = recipe("65 ml milk", "Put milk into the mixing bowl. " + POUR)
    samples = [None, [], {}, "text", b"", b"\xff" * 2048, random.Random(801).randbytes(2048), b"x" * (engine.MAX_PROG + 1)]
    samples += [valid[:n] for n in range(0, len(valid), 13)]
    for index in range(0, len(valid), 17):
        changed = bytearray(valid); changed[index] ^= 0x80; samples.append(bytes(changed))
    for raw in samples:
        for function in [engine.d_chef, engine.d_shakespeare, engine.steps, engine.read]:
            function(raw)
    assert engine.d_chef(recipe("1 g flour", "Take flour from refrigerator. " + POUR)) is None
    assert engine.d_shakespeare(play("Listen to your heart. Open your heart.")) is None


def test_chef_add_dry_excludes_liquid():
    assert engine.d_chef(recipe("2 g flour\n65 ml milk", "Add dry ingredients. " + POUR)) == b"2"


def test_chef_oversized_integer_fail_closed():
    assert engine.d_chef(recipe("9" * 5000 + " g flour", "Put flour into the mixing bowl. " + POUR)) is None
