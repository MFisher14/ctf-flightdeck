"""Bounded fixtures for the round-3 esolang tail and explicit-input APIs."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "warmups"))
import esolang_tail as eso  # noqa: E402


def test_unlambda_output_and_lazy_k_normal_form():
    assert eso.unlambda("`.Ai") == b"A"
    assert eso.unlambda("c") is None  # call/cc is an explicit honest decline
    assert eso.lazy_k_normal_form("``kii") == {
        "normal_form": "i", "steps": 1, "verified_irreducible": True
    }


def test_thue_output_nondeterminism_and_supplied_input():
    program = "a::=~A\na::=~B\n::=\na\n"
    terminal = eso.thue(program)
    assert {item["output"] for item in terminal} == {b"A", b"B"}
    assert all(item["state"] == "" for item in terminal)

    input_program = "x::=:::\n::=\nx\n"
    terminal = eso.thue(input_program, b"supplied\nignored")
    assert terminal == [{"state": "supplied", "output": b"", "steps": 1}]


def test_fractran_exact_sequence_and_bit_cap():
    result = eso.fractran("3/2, 5/3\nN=2")
    assert result["sequence"] == [2, 3, 5]
    assert result["final"] == 5
    assert result["halted"] is True and result["verified"] is True
    assert eso.fractran("3/0\nN=2") is None


def test_hexagony_wrapping_geometry_memory_and_input():
    assert eso.hexagony("65;@") == b"A"
    assert eso.hexagony(",;@", b"Z") == b"Z"
    # Radius-two canonical layout: IP0 reads 6,5, branches down-right, prints, then terminates.
    assert eso.hexagony("65>...;....@.......") == b"A"
    assert eso._hex_step((2, -2), 0, 2) == ((0, -2), True)
    assert eso.hexagony("65;") is None   # wrapping loop is stopped by the step cap


def test_underload_stack_strings_concatenation_and_execution():
    assert eso.underload("(Hello)( world!)*S") == b"Hello world!"
    assert eso.underload("((A)S)^", steps=100) == b"A"
    assert eso.underload("S") is None
    assert eso.run_language("underload", "(CSCTF{underload})S") == {
        "candidates": [b"CSCTF{underload}"]
    }


def test_false_arithmetic_variables_lambdas_and_input():
    assert eso.false_lang('"Hi"') == b"Hi"
    assert eso.false_lang("65,") == b"A"
    assert eso.false_lang("65a:a;,") == b"A"
    assert eso.false_lang('1["Y"]?') == b"Y"
    assert eso.false_lang("^,", b"Q") == b"Q"
    assert eso.false_lang("+") is None


def test_mutated_text_never_escapes_reader_boundaries():
    rng = random.Random(20261104)
    alphabet = "`ski.?[]{}+-*/@^,;:#øßXYZ0123456789\udcff"
    for _ in range(500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 80)))
        assert eso.unlambda(text, b"x", steps=200) is None or isinstance(
            eso.unlambda(text, b"x", steps=200), bytes)
        assert eso.false_lang(text, b"x", steps=200) is None or isinstance(
            eso.false_lang(text, b"x", steps=200), bytes)
        assert eso.hexagony(text, b"x", steps=200) is None or isinstance(
            eso.hexagony(text, b"x", steps=200), bytes)
        assert eso.underload(text, steps=200) is None or isinstance(
            eso.underload(text, steps=200), bytes)


def test_guarded_cli_and_explicit_input(tmp_path, capsys):
    program = tmp_path / "echo.false"
    program.write_text("^,", encoding="utf-8")
    assert eso.main(["false", str(program), "--input-text", "R", "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidates"] == [{"hex": "52", "text": "R"}]

    missing = tmp_path / "missing"
    assert eso.main(["thue", str(missing)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("esolang_tail: ")
    assert "Traceback" not in captured.err

