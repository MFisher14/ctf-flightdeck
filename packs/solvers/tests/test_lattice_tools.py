"""Synthetic exact-membership tests for general lattice helpers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import lattice_tools as lattice  # noqa: E402


def test_babai_cvp_exact_arithmetic_and_membership():
    result = lattice.closest_vector([[4, 0], [0, 3]], [7, 5], reduce=False)
    assert result is not None
    assert result.vector == (8, 6)
    assert result.coefficients == (2, 2)
    assert result.squared_distance == 2
    assert tuple(sum(c * row[j] for c, row in zip(result.coefficients, result.reduced_basis))
                 for j in range(2)) == result.vector


def test_cvp_rejects_dependent_or_unbounded_basis():
    assert lattice.closest_vector([[1, 2], [2, 4]], [1, 1]) is None
    with pytest.raises(ValueError):
        lattice.closest_vector([[1, 2], [3]], [1, 1])


def test_subset_sum_is_exact_and_returns_none_when_unsatisfied():
    values = [3, 34, 4, 12, 5, 2]
    bits = lattice.solve_subset_sum(values, 9)
    assert bits is not None
    assert sum(a * b for a, b in zip(values, bits)) == 9
    assert lattice.solve_subset_sum([4, 8, 12], 5) is None


def test_merkle_hellman_round_trip_and_bit_packing():
    private = [2, 3, 7, 14, 30, 57, 120, 251]
    modulus, multiplier = 491, 41
    public = [(multiplier * weight) % modulus for weight in private]
    expected = [0, 1, 0, 0, 0, 0, 0, 1]  # ASCII A
    ciphertext = sum(weight * bit for weight, bit in zip(public, expected))
    bits = lattice.merkle_hellman_decrypt(ciphertext, private, multiplier, modulus)
    assert bits == expected
    assert lattice.bits_to_bytes(bits) == b"A"

    with pytest.raises(ValueError):
        lattice.merkle_hellman_decrypt(ciphertext, [2, 3, 4], multiplier, modulus)


def test_guarded_json_cli(tmp_path, capsys):
    fixture = tmp_path / "cvp.json"
    fixture.write_text(json.dumps({"basis": [[4, 0], [0, 3]], "target": [7, 5]}))
    assert lattice.main(["cvp", str(fixture), "--no-reduce", "--json"]) == 0
    assert '"squared_distance": 2' in capsys.readouterr().out

    broken = tmp_path / "broken.json"
    broken.write_text("[")
    assert lattice.main(["subset-sum", str(broken)]) == 2
    assert "lattice_tools:" in capsys.readouterr().err
