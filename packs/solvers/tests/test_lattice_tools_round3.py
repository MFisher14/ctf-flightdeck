"""Verified multivariate-small-root and approximate-common-divisor fixtures."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import lattice_tools as lattice  # noqa: E402


def test_multivariate_small_roots_are_directly_verified():
    # (x-3)^2 + (y-2)^2 has one integer zero in this box.  The fixture exercises sparse
    # multivariate powers, the exact LLL construction, HG certification, and bounded recovery.
    polynomial = {
        (2, 0): 1,
        (1, 0): -6,
        (0, 2): 1,
        (0, 1): -4,
        (0, 0): 13,
    }
    result = lattice.small_roots_detailed(
        polynomial, 1_000_003, [[0, 7], [0, 7]], m=1, t=0
    )
    assert result.roots == ((3, 2),)
    assert result.methods == ("bounded-enumeration",)
    assert result.lattice_rows >= 2
    assert result.certified_relations >= 1
    assert all(sum(coefficient * (root[0] ** powers[0]) * (root[1] ** powers[1])
                   for powers, coefficient in polynomial.items()) % 1_000_003 == 0
               for root in result.roots)


def test_small_root_from_certified_relation_without_enumeration():
    result = lattice.small_roots_detailed(
        [-7, 1],
        1_000_003,
        [[0, 100_000]],
        m=1,
        t=0,
        max_enumeration=0,
    )
    assert result.roots == ((7,),)
    assert result.methods == ("certified-linear-relations",)
    assert result.certified_relations >= 1


def test_bivariate_root_from_independent_hg_relations_without_box_search():
    modulus = 1_000_003
    # f(3, 5) = modulus.  LLL combines f and N shifts into two certified affine equations;
    # recovery therefore does not depend on walking the 10,201-point box.
    polynomial = {(1, 0): 1, (0, 1): 257, (0, 0): modulus - 1_288}
    result = lattice.small_roots_detailed(
        polynomial,
        modulus,
        [[0, 100], [0, 100]],
        m=1,
        t=1,
        max_enumeration=0,
        max_projection=0,
    )
    assert result.roots == ((3, 5),)
    assert result.methods == ("certified-linear-relations",)
    assert result.certified_relations >= 2


def test_small_root_caps_reject_explosive_or_malformed_inputs():
    with pytest.raises(ValueError, match="degree"):
        lattice.small_roots({(9,): 1, (0,): -1}, 101, [8])
    with pytest.raises(ValueError, match="cap exceeded"):
        lattice.small_roots(
            {(2, 0): 1, (0, 2): 1, (0, 0): -1},
            101,
            [8, 8],
            m=4,
            t=4,
            max_dimension=8,
        )


def test_acd_simultaneous_lattice_recovers_and_round_trips():
    divisor = 10_007
    quotients = [101, 137, 223, 311]
    noises = [3, -2, 5, 1]
    samples = [divisor * quotient + noise for quotient, noise in zip(quotients, noises)]
    results = lattice.approximate_common_divisors(samples, 5, max_noise_pairs=0)
    assert results
    assert results[0] == lattice.ACDResult(
        divisor, tuple(quotients), tuple(noises), "lll-simultaneous"
    )
    for result in results:
        assert all(sample == result.divisor * quotient + noise
                   for sample, quotient, noise in zip(samples, result.quotients, result.noises))
        assert max(map(abs, result.noises)) <= 5


def test_acd_exact_noise_fixture_and_guarded_clis(tmp_path, capsys):
    divisor = 65_537
    samples = [divisor * 17 + 2, divisor * 29 - 1, divisor * 43 + 3]
    result = lattice.approximate_common_divisor(samples, 3)
    assert result is not None
    assert result.divisor == divisor

    small_fixture = tmp_path / "small.json"
    small_fixture.write_text(json.dumps({
        "terms": [
            {"powers": [1, 0], "coefficient": 1},
            {"powers": [0, 1], "coefficient": 1},
            {"powers": [0, 0], "coefficient": -5},
        ],
        "modulus": 101,
        "bounds": [[2, 2], [3, 3]],
        "m": 1,
        "t": 0,
    }))
    assert lattice.main(["small-roots", str(small_fixture), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidates"][0]["root"] == [2, 3]
    assert output["candidates"][0]["verified"] is True

    acd_fixture = tmp_path / "acd.json"
    acd_fixture.write_text(json.dumps({"samples": samples, "noise_bound": 3}))
    assert lattice.main(["acd", str(acd_fixture), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["candidates"][0]["divisor"] == divisor

    garbage = tmp_path / "garbage.json"
    garbage.write_bytes(b"\xff\xfe")
    assert lattice.main(["small-roots", str(garbage)]) == 2
    assert "lattice_tools:" in capsys.readouterr().err

