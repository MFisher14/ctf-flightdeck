"""Brain-Flak vectors from https://brain-flak.github.io/ and the language wiki.

Expected stacks follow nilad/monad arithmetic, never the engine's encoder.
"""
import random
import socket
import subprocess

import pytest
import esolang_round5 as engine


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("unexpected external execution or network")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


@pytest.mark.parametrize("source,stacks,active,total", [
    ("()", [[], []], 0, 1),
    ("(()()())", [[3], []], 0, 3),
    ("((()()()))", [[3, 3], []], 0, 3),
    ("(()())(()()())({}{})", [[5], []], 0, 10),
    ("(()())<>((()))", [[2], [1, 1]], 1, 3),
    ("([()()])", [[-2], []], 0, -2),
    ("<(()())>([])", [[2, 1], []], 0, 1),
    ("(()()()){({}[()])}{}", [[], []], 0, 6),
])
def test_spec_nilads_and_monads(source, stacks, active, total):
    result = engine.execute(source)
    assert result["stacks"] == stacks
    assert result["active_stack"] == active
    assert result["accumulator"] == total
    assert result["halted"] is True


def test_parse_shape_and_independent_output_report():
    assert engine.parse(" (() []) < > ") == [("(", [("(", []), ("[", [])]), ("<", [])]
    report = {"stacks": [[65, 66], []], "active_stack": 0}
    rows = engine.output_candidates(report)
    assert [(r["convention"], r["text"], r["bytes_hex"]) for r in rows] == [
        ("bottom_to_top", "AB", "4142"), ("top_to_bottom", "BA", "4241")]
    assert all(r["candidate_only"] and r["verified_from_stack"] for r in rows)
    # Sum 65 nilads pushes A. No engine fixture encoder is used.
    analyzed = engine.analyze("(" + "()" * 65 + ")")
    assert analyzed["output_candidates"][0]["text"] == "A"
    assert analyzed["answer"] is None


def test_nonterminating_step_bound_and_storage_bounds(monkeypatch):
    with pytest.raises(engine.Refuse, match="step cap"):
        engine.execute("(()){()}", steps=20)
    monkeypatch.setattr(engine, "MAX_STACK", 2)
    with pytest.raises(engine.Refuse, match="stack cap"):
        engine.execute("(())" * 3)
    monkeypatch.setattr(engine, "MAX_BITS", 3)
    with pytest.raises(engine.Refuse, match="integer bound"):
        engine.execute("(" + "()" * 8 + ")")
    monkeypatch.setattr(engine, "MAX_DEPTH", 3)
    with pytest.raises(engine.Refuse, match="nesting"):
        engine.parse("(" * 5 + ")" * 5)


def test_seeded_source_fuzz(monkeypatch):
    monkeypatch.setattr(engine, "MAX_SOURCE", 128)
    monkeypatch.setattr(engine, "MAX_STEPS", 100)
    rng = random.Random(508)
    valid = "(()())"
    corpus = ["", "\xff" * 32, "\ud800", "()" * 65, None]
    corpus += [valid[:i] for i in range(len(valid))]
    corpus += [valid[:i] + chr(ord(c) ^ 1) + valid[i + 1:] for i, c in enumerate(valid)]
    corpus += ["".join(rng.choice("()[]{}<>xyz \n") for _ in range(30)) for _ in range(30)]
    for source in corpus:
        for function in (engine.parse, engine.execute, engine.analyze):
            try:
                function(source)
            except engine.Refuse:
                pass


@pytest.mark.parametrize("report", [
    {"stacks": [1, []], "active_stack": 0},
    {"stacks": [[65], []], "active_stack": 0.0},
])
def test_output_report_fail_closed(report):
    try:
        engine.output_candidates(report)
    except engine.Refuse:
        pass


@pytest.mark.parametrize("steps", [None, "5"])
def test_step_parameter_fail_closed(steps):
    try:
        engine.execute("()", steps=steps)
    except engine.Refuse:
        pass


def test_cli_file_and_error(tmp_path, capsys):
    path = tmp_path / "one.flak"
    path.write_text("(())")
    assert engine.main([str(path)]) == 0
    assert '"halted": true' in capsys.readouterr().out
    assert engine.main([]) == 2


def test_cli_help_guard():
    assert engine.main(["--help"]) == 0
