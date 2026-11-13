"""Funge98/Rockstar specification vectors and independent Chef/SPL programs.

Sources: github.com/catseye/Funge-98/blob/master/doc/funge98.markdown;
github.com/RockstarLang/rockstar/blob/main/spec.md; Chef/SPL language specs.
"""
import random
import socket
import subprocess

import pytest

import esolang_more as engine


@pytest.fixture(autouse=True)
def bounded_offline(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("interpreter attempted external execution/network")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(engine, "STEPS", 512)
    monkeypatch.setattr(engine, "_deadline", lambda: float("inf"))


def pad(raw):
    return raw + b" " * 20


def recipe(ingredients, method):
    return ("Fixture Soup.\n\nIngredients.\n" + ingredients + "\n\nMethod.\n" + method + "\n\nServes 1.\n").encode()


def play(speech):
    return ("A Fixture.\n\nRomeo, a man.\nJuliet, a woman.\n\nAct I: Counting.\nScene I: Values.\n[Enter Romeo and Juliet]\nRomeo:\n" + speech + "\n[Exeunt]\n").encode()


POUR = "Pour contents of the mixing bowl into the baking dish."


@pytest.mark.parametrize("source,expected", [
    (b'"!dlroW ,olleH",,,,,,,,,,,,,@', b"Hello, World!"),
    (b"23+.@", b"5 "),
    (b"07-2/.@", b"-3 "),
    (b"'A,@", b"A"),
    (b";skipped text;23*.@", b"6 "),
    (b". @", b"0 "),
])
def test_befunge98_documented_operations(source, expected):
    assert engine.befunge98(pad(source)) == expected


@pytest.mark.parametrize("source,expected", [
    (b'Say "Hello world!"\n', b"Hello world!\n"),
    (b"Tommy was a big bad brother\nShout Tommy\n", b"1337\n"),
    (b"My heart is 5\nYour heart is 4\nPut my heart plus your heart into the total\nShout the total\n", b"9\n"),
    (b"My soul is 65\nCast my soul\nSay my soul\n", b"A\n"),
    (b"My heart is 2\nWhile my heart is greater than 0\nSay my heart\nKnock my heart down\n\n", b"2\n1\n"),
])
def test_rockstar_published_semantics(source, expected):
    assert engine.rockstar(source) == expected


def test_chef_dry_only_and_spl_signs():
    assert engine.chef(recipe("2 g flour\n65 ml milk", "Add dry ingredients. " + POUR)) == b"2"
    assert engine.chef(recipe("65 ml milk\n66 ml water", "Put milk into the mixing bowl. Put water into the mixing bowl. " + POUR)) == b"BA"
    assert engine.shakespeare(play("You are a beautiful flower. Open your heart.")) == b"2"
    assert engine.shakespeare(play("You are a vile coward. Open your heart.")) == b"-2"


def test_registry_wrappers_and_crib_decline():
    raw = b"My heart is 42\nShout my heart\n"
    assert engine.steps(raw) == [("rockstar", b"42\n")]
    assert engine.step_fn("rockstar")(raw) == b"42\n"
    assert engine.read(raw) == []


def test_nonterminating_programs_and_output_caps(monkeypatch):
    assert engine.befunge98(pad(b">")) is None
    assert engine.rockstar(b"My heart is 1\nWhile my heart is 1\nSay my heart\n\n") is None
    assert engine.shakespeare(play("Let us proceed to scene I.")) is None
    assert engine.chef(recipe("1 g flour", "Whisk the flour. Put flour into the mixing bowl. Whisk until whisked. " + POUR)) is None
    monkeypatch.setattr(engine, "OUTPUT", 1)
    assert engine.befunge98(pad(b'"ABC",,,@')) is None
    assert engine.rockstar(b'Say "Too many bytes"\n') is None
    assert engine.chef(recipe("65 ml milk", "Put milk into the mixing bowl. Put milk into the mixing bowl. " + POUR)) is None
    assert engine.shakespeare(play("You are a beautiful flower. Open your heart. Open your heart.")) is None


def test_malformed_corpus_and_refused_external_operations():
    valid = b"My heart is 42\nShout my heart\n"
    samples = [None, [], {}, b"", b"\xff" * 2048, random.Random(803).randbytes(2048), b"x" * (engine.MAX_PROG + 1)]
    samples += [valid[:n] for n in range(0, len(valid), 3)]
    for index in range(0, len(valid), 5):
        changed = bytearray(valid); changed[index] ^= 128; samples.append(bytes(changed))
    for raw in samples:
        for function in [engine.befunge98, engine.chef, engine.rockstar, engine.shakespeare, engine.steps, engine.read]:
            function(raw)
    for op in b"&~?=ytio()":
        assert engine.befunge98(pad(bytes([op]) + b"@")) is None
    assert engine.rockstar(b"Listen to my heart\nSay my heart\n") is None


@pytest.mark.parametrize("function", [engine.befunge98, engine.chef, engine.rockstar, engine.shakespeare])
def test_unicode_surrogate_fail_closed(function):
    assert function("\ud800" * 20) is None


def test_rockstar_subtraction_associativity():
    assert engine.rockstar(b"Put 10 minus 3 minus 2 into my heart\nSay my heart\n") == b"5\n"


def test_befunge98_stringmode_space_compression():
    assert engine.befunge98(pad(b'"A  B",,,@')) == b"B A"


def test_rockstar_quoted_parentheses_preserved():
    assert engine.rockstar(b'Say "Hello (world)!"\n') == b"Hello (world)!\n"


def test_rockstar_quoted_surrogate_fail_closed():
    assert engine.rockstar('Say "a surrogate: \ud800"\n') is None


def test_chef_oversized_arithmetic_fail_closed():
    source = recipe("9" * 400 + " g flour\n2 g salt", "Put flour into the mixing bowl. Divide salt. " + POUR)
    assert engine.chef(source) is None
