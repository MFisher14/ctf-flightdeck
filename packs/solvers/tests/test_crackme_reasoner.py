"""Unique-only crackme/license constraint reasoning tests."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import crackme_reasoner as reason  # noqa: E402


def _forward(value: bytes, steps: list[dict]) -> bytes:
    data = bytearray(value)
    for step in steps:
        if step["kind"] == "xor":
            data = bytearray(byte ^ step["value"] for byte in data)
        elif step["kind"] == "add":
            data = bytearray((byte + step["value"]) & 0xFF for byte in data)
        elif step["kind"] == "reverse":
            data.reverse()
        elif step["kind"] == "permutation":
            data = bytearray(data[index] for index in step["order"])
    return bytes(data)


def test_transform_pipeline_inverts_only_stated_bijective_steps():
    original = b"R5D!"
    steps = [
        {"kind": "xor", "value": 0x23},
        {"kind": "add", "value": 7},
        {"kind": "permutation", "order": [2, 0, 3, 1]},
        {"kind": "reverse"},
    ]
    expected = _forward(original, steps)
    result = reason.reverse_transform_pipeline(expected, steps)
    assert result.unique and result.candidate == original
    assert len(result.derivation) == len(steps)
    assert result.unresolved_positions == ()


def test_repeating_xor_nibble_and_affine_inverse_are_reasoned():
    plain = b"KEY"
    key = b"ab"
    encrypted = bytes((((byte ^ key[index % 2]) * 3 + 5) & 0xFF) for index, byte in enumerate(plain))
    result = reason.reverse_transform_pipeline(encrypted, [
        {"kind": "xor_repeating", "key": key},
        {"kind": "mul_add", "multiplier": 3, "addend": 5},
    ])
    assert result.candidate == plain
    with pytest.raises(reason.ConstraintInputError, match="not uniquely"):
        reason.reverse_transform_pipeline(b"x", [{"kind": "mul_add", "multiplier": 2, "addend": 1}])


def test_constraint_spec_combines_fixed_xor_affine_and_full_rank_linear():
    spec = {
        "length": 4,
        "alphabet": "printable",
        "fixed": [{"index": 0, "value": ord("F")}],
        "xor": [{"index": 1, "key": 0x20, "expected": ord("L") ^ 0x20}],
        "affine": [{"index": 2, "multiplier": 3, "addend": 7,
                    "expected": (3 * ord("A") + 7) & 0xFF}],
        "linear": {"modulus": 257, "equations": [
            {"coefficients": [0, 0, 0, 1], "expected": ord("G")},
        ]},
    }
    result = reason.solve_constraint_spec(spec)
    assert result.unique and result.candidate == b"FLAG"
    assert "rank 1" in result.evidence[0]
    assert result.to_dict()["candidate_hex"] == b"FLAG".hex()


def test_underdetermined_or_inconsistent_systems_never_enumerate():
    under = reason.solve_constraint_spec({
        "length": 2,
        "linear": {"modulus": 257, "equations": [
            {"coefficients": [1, 1], "expected": 100},
        ]},
    })
    assert under.candidate is None and not under.unique
    assert under.unresolved_positions == (0, 1)
    assert "free variable" in under.evidence[0]
    with pytest.raises(reason.ConstraintInputError, match="conflicting"):
        reason.solve_constraint_spec({
            "length": 1,
            "fixed": [{"index": 0, "value": 1}, {"index": 0, "value": 2}],
        })
    with pytest.raises(reason.ConstraintInputError, match="prime"):
        reason.solve_constraint_spec({
            "length": 1,
            "linear": {"modulus": 256, "equations": [{"coefficients": [1], "expected": 1}]},
        })
    with pytest.raises(reason.ConstraintInputError, match="unique bytes"):
        reason.solve_constraint_spec({
            "length": 1,
            "linear": {"modulus": 251, "equations": [{"coefficients": [1], "expected": 0}]},
        })
    with pytest.raises(reason.ConstraintInputError, match="shape"):
        reason.solve_constraint_spec({
            "length": 1,
            "linear": {"modulus": 257, "equations": [
                {"coefficients": [1 << 1000], "expected": 0},
            ]},
        })
    with pytest.raises(reason.ConstraintInputError, match="inconsistent"):
        reason.solve_constraint_spec({
            "length": 1,
            "fixed": [{"index": 0, "value": 65}],
            "linear": {"modulus": 257, "equations": [
                {"coefficients": [1], "expected": 66},
            ]},
        })
    with pytest.raises(reason.ConstraintInputError, match="alphabet"):
        reason.solve_constraint_spec({
            "length": 2, "alphabet": "printable",
            "fixed": [{"index": 0, "value": 0}],
        })


def test_luhn_and_mod97_digits_are_derived_not_searched():
    digit = reason.derive_luhn_check_digit("7992739871")
    assert digit == "3" and reason.validate_luhn("79927398713")
    assert not reason.validate_luhn("79927398714")
    suffix = reason.derive_mod97_suffix("123456")
    assert int("123456" + suffix) % 97 == 1


def test_crackme_pattern_leads_are_ordered_and_specific():
    text = "serial bytes XOR 0x20; checksum CRC32; strcmp(input, expected); invalid serial"
    rows = reason.detect_crackme_patterns(text)
    assert [row.offset for row in rows] == sorted(row.offset for row in rows)
    assert {row.pattern for row in rows} >= {"xor-transform", "checksum", "direct-compare", "success-failure-branch"}
    assert all("enumerat" not in row.recommended_solver for row in rows)


def test_caps_invalid_shapes_and_ast_safety(monkeypatch):
    with pytest.raises(reason.ConstraintInputError, match="unknown"):
        reason.solve_constraint_spec({"length": 1, "guess": True})
    with pytest.raises(reason.ConstraintInputError, match="unknown field"):
        reason.reverse_transform_pipeline(b"x", [{"kind": "xor", "value": 1, "typo": 2}])
    monkeypatch.setattr(reason, "MAX_TEXT", 3)
    with pytest.raises(reason.ConstraintInputError, match="cap"):
        reason.detect_crackme_patterns("four")
    tree = ast.parse((REPO / "solvers" / "binary" / "crackme_reasoner.py").read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not imports & {"subprocess", "socket", "requests", "marshal", "pickle", "itertools"}
    assert not calls & {"open", "exec", "eval", "compile", "__import__", "product", "permutations"}
