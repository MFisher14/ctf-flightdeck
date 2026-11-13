"""B-157: the lattice and polynomial-ideal service (solvers/common/algebra_service.py).

Three layers are tested: the job parser and the checks the service runs on every backend's answer
(pure functions); the python backend's mathematics against hand-derived answers; and the Sage
backends through a stub `sage` and a stub `docker` that run the real worker against a fake `sage`
package (tests/algebra_stubs.py). No real Sage, Docker or network is touched; the fake proves the
worker's and the service's own code, not Sage's API (the build log lists that as a human step).
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import random
import subprocess
import sys
import time
from fractions import Fraction
from pathlib import Path

import pytest

import algebra_service as alg
import algebra_stubs as stubs
from ctf import paths
from ctf.toolchain import images

ROOT = paths.repo_root()
SERVICE = ROOT / "solvers" / "common" / "algebra_service.py"
WORKER = ROOT / "solvers" / "common" / alg.WORKER_NAME
QQ = alg.Ring("QQ")
F7 = alg.Ring("GF", 7)
P127 = (1 << 127) - 1


def P(text, names=("x", "y"), ring=QQ):
    return alg.parse_polynomial(text, names, ring)


def local(job):
    """The python backend without its child process: the same parse, run and check as `execute`."""
    parsed = alg.parse_job(job)
    raw = alg._python_run(dict(parsed.wire, timeout=120))
    assert raw["status"] == "ok", raw
    return alg._check(parsed, raw["data"])


SYMMETRIC = ["a + b + c - 6", "a*b + b*c + c*a - 11", "a*b*c - 6"]      # roots: the permutations of 1, 2, 3


# ------------------------------------------------------------------------------------- the parser

def test_parser_reads_sums_products_powers_and_parentheses():
    assert P("x^2 + 3*x*y - 7") == {(2, 0): 1, (1, 1): 3, (0, 0): -7}
    assert P("2*(x + y)**2") == {(2, 0): 2, (1, 1): 4, (0, 2): 2}
    assert P("(x + 1)*(x - 1)") == {(2, 0): 1, (0, 0): -1}
    assert P("0x10*x") == {(1, 0): 16}
    assert P("x - x") == {}


def test_parser_precedence_and_associativity():
    assert P("-x^2") == {(2, 0): -1}                       # the power binds tighter than the sign
    assert P("x - y - 1") == {(1, 0): 1, (0, 1): -1, (0, 0): -1}      # left to right
    assert P("2 + 3*x^2") == {(0, 0): 2, (2, 0): 3}        # * before +, ^ before *
    assert P("-(x - y)") == {(1, 0): -1, (0, 1): 1}
    assert P("x*-y") == {(1, 1): -1}


def test_parser_divides_by_integer_constants_only():
    assert P("x/2 + 3/4") == {(1, 0): Fraction(1, 2), (0, 0): Fraction(3, 4)}
    assert P("x/2 + 10", ring=F7) == {(1, 0): 4, (0, 0): 3}          # 1/2 = 4 and 10 = 3 mod 7
    with pytest.raises(alg.JobError, match="integer constant"):
        P("x/y")
    with pytest.raises(alg.JobError, match="zero denominator"):
        P("x/0")
    with pytest.raises(alg.JobError, match="not invertible"):
        P("x/2", ring=alg.Ring("Zmod", 6))


@pytest.mark.parametrize("text", ["x +", "x y", "2x", "x^y", "x^-1", "z", "x $ y", "(x", "x)", "", "x**",
                                  "x^100001", "x.y", "x[0]", "lambda: 1"])
def test_parser_rejects(text):
    with pytest.raises(alg.JobError):
        P(text)


def test_polynomial_strings_are_parsed_never_evaluated(tmp_path):
    marker = tmp_path / "pwned"
    hostile = f'__import__("os").system("touch {marker}")'
    with pytest.raises(alg.JobError):
        P(hostile)
    with pytest.raises(alg.JobError):
        alg.execute({"op": "groebner", "ring": "QQ", "vars": ["x"], "polys": [hostile]}, backend="python")
    with pytest.raises(alg.JobError, match="identifier"):
        alg.parse_job({"op": "groebner", "ring": "QQ", "vars": ["x;import os"], "polys": ["1"]})
    assert not marker.exists()


@pytest.mark.parametrize("ring", [QQ, alg.Ring("GF", 65537), alg.Ring("Zmod", 1 << 64)], ids=lambda r: r.text())
def test_poly_text_round_trips_through_the_parser(ring):
    rng = random.Random(157)
    names = ("x", "y", "z")
    for _ in range(40):
        f = {}
        for _ in range(rng.randrange(0, 7)):
            e = tuple(rng.randrange(0, 4) for _ in names)
            c = ring.coerce(Fraction(rng.randrange(-50, 50), rng.randrange(1, 9)) if ring.kind == "QQ"
                            else rng.randrange(ring.modulus))
            if c:
                f[e] = c
        text = alg.poly_text(ring, f, names)
        assert alg.parse_polynomial(text, names, ring) == f, text


def test_poly_text_spells_signs_and_unit_coefficients():
    assert alg.poly_text(QQ, P("x^2 - x*y + 1/2"), ("x", "y")) == "x^2 - x*y + 1/2"
    assert alg.poly_text(QQ, P("-x - 3/2*y"), ("x", "y")) == "-x - 3*y/2"
    assert alg.poly_text(F7, P("x - 1", ring=F7), ("x", "y")) == "x + 6"
    assert alg.poly_text(QQ, {}, ("x",)) == "0"


def test_polynomial_arithmetic_is_capped():
    f = P("x + y + 1")
    assert len(alg.poly_mul(QQ, f, f, cap=6)) == 6
    with pytest.raises(alg.JobError, match="cap of 5 terms"):
        alg.poly_mul(QQ, f, f, cap=5)
    with pytest.raises(alg.JobError, match="exponent"):
        alg.poly_mul(QQ, {(alg.MAX_EXPONENT, 0): 1}, {(1, 0): 1})


def test_parentheses_nest_to_the_cap_and_no_deeper():
    deep = alg.MAX_NESTING
    assert P("(" * deep + "x + 1" + ")" * deep) == {(1, 0): 1, (0, 0): 1}
    for over in (deep + 1, 3000):                            # 3000: past Python's recursion limit
        with pytest.raises(alg.JobError, match="nest deeper than the cap"):
            P("(" * over + "x" + ")" * over)
    # the cap is on depth, not on how many groups there are: closing a group gives its level back
    siblings = " + ".join(["(x)"] * (deep * 3))
    assert P(siblings) == {(1, 0): deep * 3}
    near_cap = "(" * (deep - 1) + "x" + ")" * (deep - 1)
    assert P(" * ".join([near_cap] * 4)) == {(4, 0): 1}
    with pytest.raises(alg.JobError, match="nest deeper than the cap"):   # and still counts inside one
        P(" + ".join(["(x)"] * deep) + " + " + "(" * (deep + 1) + "x" + ")" * (deep + 1))


def test_a_long_run_of_signs_is_read_without_recursion():
    assert P("-" * 5000 + "x") == {(1, 0): 1}
    assert P("-" * 5001 + "x^2") == {(2, 0): -1}             # the sign still binds looser than the power
    assert P("+-+" * 3000 + "y") == {(0, 1): 1}              # 3000 minus signs: even
    assert P("+-+" * 3000 + "-y") == {(0, 1): -1}            # 3001: odd
    assert P("x*" + "-" * 4001 + "y") == {(1, 1): -1}


def test_deep_polynomials_and_deep_json_are_bad_jobs_on_the_cli(tmp_path):
    """The verifier's reproduction: a real CLI process, which used to print a RecursionError traceback
    and exit 1. A malformed job exits 2 with a named reason."""
    jobs = {"parens.json": json.dumps({"op": "groebner", "ring": "QQ", "vars": ["x"],
                                       "polys": ["(" * 3000 + "x" + ")" * 3000]}),
            "nested.json": "[" * 200_000 + "]" * 200_000}
    for name, text in jobs.items():
        (tmp_path / name).write_text(text)
        p = subprocess.run([sys.executable, "-I", str(SERVICE), "run", str(tmp_path / name)],
                           capture_output=True, text=True, timeout=600, cwd=tmp_path)
        assert p.returncode == 2, (name, p.stderr[-400:])
        assert "Traceback" not in p.stderr and p.stderr.startswith("algebra_service: "), p.stderr[-400:]
        assert ("nest deeper" if name == "parens.json" else "too deeply") in p.stderr


def _work(text, names=("x", "y"), ring=QQ):
    meter = alg._Meter(10 ** 18)
    alg.parse_polynomial(text, names, ring, meter=meter)
    return meter.used


def test_expansion_work_is_capped_per_job_and_charged_before_it_is_done(monkeypatch):
    big = "(x + y + 1)^12"
    need = _work(big)
    assert need > 0
    monkeypatch.setattr(alg, "MAX_PARSE_WORK", need)        # exactly enough: allowed
    assert len(P(big)) == 91
    job = {"op": "groebner", "ring": "QQ", "vars": ["x", "y"], "polys": [big]}
    assert alg.parse_job(job).polys[0] == P(big)
    with pytest.raises(alg.JobError, match="parse-work cap"):   # the budget is the job's, not each poly's
        alg.parse_job(dict(job, polys=[big, big]))
    monkeypatch.setattr(alg, "MAX_PARSE_WORK", need - 1)    # one unit short: refused
    with pytest.raises(alg.JobError, match="parse-work cap"):
        P(big)
    with pytest.raises(alg.JobError, match="parse-work cap"):
        alg.parse_job(job)
    lone = "(x + 1)^400"                                     # small_roots parses under the same cap
    assert _work(lone, ("x",), alg.Ring("Zmod", 91)) > need
    with pytest.raises(alg.JobError, match="parse-work cap"):
        alg.parse_job({"op": "small_roots", "modulus": 91, "poly": lone, "bound": 2})


def test_a_modular_ring_pays_twice_the_limb_work_for_its_reduction():
    """Each coefficient product costs PARSE_PRODUCT_COST plus its limb product; in GF/Zmod the limb
    product is charged twice, for the reduction mod the modulus."""
    one_plus_x = {(1,): 1, (0,): 1}
    row_base = alg.PARSE_PRODUCT_COST * 2                    # b has two terms
    limb_work = 1 * 2                                        # one-limb a coefficient by two one-limb b terms
    expected = {"QQ": 2 * (row_base + limb_work), "GF": 2 * (row_base + 2 * limb_work),
                "Zmod": 2 * (row_base + 2 * limb_work)}
    for ring in (QQ, alg.Ring("GF", 65537), alg.Ring("Zmod", 91)):
        meter = alg._Meter(10 ** 18)
        alg.poly_mul(ring, {e: ring.coerce(c) for e, c in one_plus_x.items()},
                     {e: ring.coerce(c) for e, c in one_plus_x.items()}, meter=meter)
        assert meter.used == expected[ring.kind], ring.kind
    # through the parser: the same expansion costs more over GF(p) than over QQ, by the limb work
    p = (1 << 61) - 1                                        # big enough that nothing reduces
    qq, gf = _work("(x + y + 1)^6"), _work("(x + y + 1)^6", ring=alg.Ring("GF", p))
    assert gf > qq
    assert P("(x + y + 1)^6") == P("(x + y + 1)^6", ring=alg.Ring("GF", p))


def test_an_expansion_too_big_for_the_caller_is_refused_with_little_cpu():
    """(x+1)^3000 over QQ cost 8 s of CPU in the calling process before the cap; GF(65537) and a
    constant raised to a huge power were worse. Each is refused, and the refusal costs at most the
    budget (CPU time, not wall-clock, so the bound holds on a loaded machine)."""
    gf = alg.Ring("GF", 65537)
    for text, ring in (("(x + 1)^3000", QQ), ("(x + y + 1)^400", gf), ("(2^60000 + x)^5000", QQ),
                       ("(x - 3)^20000", gf)):
        started = time.process_time()
        with pytest.raises(alg.JobError, match="parse-work cap"):
            P(text, ring=ring)
        assert time.process_time() - started < 30, text
    # charged per row before the row is multiplied: one product of two huge constants is refused
    with pytest.raises(alg.JobError, match="parse-work cap"):
        alg.poly_mul(QQ, {(0, 0): 1 << 3_000_000}, {(0, 0): 1 << 3_000_000}, meter=alg._Meter(10 ** 6))
    # a realistic Coppersmith polynomial over a 4096-bit modulus stays far inside the cap
    n = (1 << 4096) - 159
    assert _work(f"(x + {n // 3})^3 - 12345", ("x",), alg.Ring("Zmod", n)) < alg.MAX_PARSE_WORK // 1000


def test_poly_eval_matches_a_direct_evaluation():
    f = P("x^3*y - 2*x + 5")
    assert alg.poly_eval(QQ, f, (Fraction(1, 2), Fraction(3))) == Fraction(3, 8) - 1 + 5
    ring = alg.Ring("GF", 101)
    g = P("x^3*y - 2*x + 5", ring=ring)
    assert alg.poly_eval(ring, g, (7, 9)) == (7 ** 3 * 9 - 14 + 5) % 101


# --------------------------------------------------------------------------------------- job parsing

def test_parse_job_builds_a_wire_form_without_names_or_strings():
    job = alg.parse_job({"op": "eliminate", "ring": "GF(101)", "vars": ["key_hi", "key_lo"],
                         "polys": ["key_hi*key_lo - 1", [[1, [1, 0]], [-1, [0, 1]]]], "eliminate": ["key_lo"]})
    assert job.wire == {"schema": 1, "op": "eliminate", "ring": {"kind": "GF", "modulus": 101}, "nvars": 2,
                        "order": "lex", "eliminate": [1],
                        "polys": [[[1, [1, 1]], [100, [0, 0]]], [[1, [1, 0]], [100, [0, 1]]]]}
    assert "key" not in json.dumps(job.wire) and job.names == ("key_hi", "key_lo")


def test_parse_job_accepts_ring_objects_rationals_and_integer_strings():
    job = alg.parse_job({"op": "groebner", "ring": {"kind": "QQ"}, "vars": ["x"],
                         "polys": [[["3/4", [1]], [[1, 2], [0]]]], "order": "degrevlex"})
    assert job.wire["polys"] == [[[[3, 4], [1]], [[1, 2], [0]]]] and job.wire["order"] == "degrevlex"
    lat = alg.parse_job({"op": "bkz", "basis": [["0x10", 0], [1, "-3"]], "block_size": 2, "tours": 5})
    assert lat.wire == {"schema": 1, "op": "bkz", "basis": [[16, 0], [1, -3]], "block_size": 2, "tours": 5}
    assert alg.parse_job({"op": "bkz", "basis": [[1, 0], [0, 1]], "block_size": 2}).wire["tours"] is None


def test_parse_job_small_roots_wire_is_dense_and_reduced():
    job = alg.parse_job({"op": "small_roots", "modulus": 91, "poly": "x^2 + 100*x - 1", "bound": 5, "beta": 0.5})
    assert job.wire == {"schema": 1, "op": "small_roots", "modulus": 91, "poly": [90, 9, 1], "bound": 5,
                        "beta": 0.5, "epsilon": None}


BAD_JOBS = {
    "not an object": [],
    "unknown op": {"op": "factor"},
    "schema": {"op": "lll", "schema": 2, "basis": [[1]]},
    "unknown key": {"op": "lll", "basis": [[1]], "delta": 0.99},
    "lll with block_size": {"op": "lll", "basis": [[1, 0], [0, 1]], "block_size": 2},
    "ragged basis": {"op": "lll", "basis": [[1, 2], [3]]},
    "more rows than columns": {"op": "lll", "basis": [[1], [2]]},
    "float entry": {"op": "lll", "basis": [[1.5, 2]]},
    "boolean entry": {"op": "lll", "basis": [[True, 2]]},
    "entry over the cap": {"op": "lll", "basis": [[1 << (alg.MAX_BITS + 1), 2]]},
    "block size 1": {"op": "bkz", "basis": [[1, 0], [0, 1]], "block_size": 1},
    "block size above the rows": {"op": "bkz", "basis": [[1, 0], [0, 1]], "block_size": 3},
    "tours 0": {"op": "bkz", "basis": [[1, 0], [0, 1]], "block_size": 2, "tours": 0},
    "no ring": {"op": "groebner", "vars": ["x"], "polys": ["x"]},
    "ring text": {"op": "groebner", "ring": "GF(7); import os", "vars": ["x"], "polys": ["x"]},
    "ring modulus 1": {"op": "groebner", "ring": "GF(1)", "vars": ["x"], "polys": ["x"]},
    "QQ with modulus": {"op": "groebner", "ring": {"kind": "QQ", "modulus": 7}, "vars": ["x"], "polys": ["x"]},
    "ring unknown key": {"op": "groebner", "ring": {"kind": "QQ", "char": 0}, "vars": ["x"], "polys": ["x"]},
    "duplicate vars": {"op": "groebner", "ring": "QQ", "vars": ["x", "x"], "polys": ["x"]},
    "no polys": {"op": "groebner", "ring": "QQ", "vars": ["x"], "polys": []},
    "order": {"op": "groebner", "ring": "QQ", "vars": ["x"], "polys": ["x"], "order": "invlex"},
    "term exponents": {"op": "groebner", "ring": "QQ", "vars": ["x", "y"], "polys": [[[1, [1]]]]},
    "negative exponent": {"op": "groebner", "ring": "QQ", "vars": ["x"], "polys": [[[1, [-1]]]]},
    "rational pair in GF": {"op": "groebner", "ring": "GF(7)", "vars": ["x"], "polys": [[[[1, 2], [1]]]]},
    "eliminate on groebner": {"op": "groebner", "ring": "QQ", "vars": ["x"], "polys": ["x"], "eliminate": ["x"]},
    "eliminate unknown": {"op": "eliminate", "ring": "QQ", "vars": ["x", "y"], "polys": ["x"], "eliminate": ["z"]},
    "eliminate everything": {"op": "eliminate", "ring": "QQ", "vars": ["x", "y"], "polys": ["x"],
                             "eliminate": ["x", "y"]},
    "eliminate nothing": {"op": "eliminate", "ring": "QQ", "vars": ["x", "y"], "polys": ["x"], "eliminate": []},
    "resultant of three": {"op": "resultant", "ring": "QQ", "vars": ["x"], "polys": ["x", "x", "x"], "var": "x"},
    "resultant var": {"op": "resultant", "ring": "QQ", "vars": ["x"], "polys": ["x", "x + 1"], "var": "y"},
    "resultant of zero": {"op": "resultant", "ring": "QQ", "vars": ["x"], "polys": ["x", "x - x"], "var": "x"},
    "roots in two variables": {"op": "roots", "ring": "QQ", "vars": ["x", "y"], "polys": ["x"]},
    "roots over Zmod": {"op": "roots", "ring": "Zmod(15)", "vars": ["x"], "polys": ["x^2 - 1"]},
    "variety over Zmod": {"op": "variety", "ring": "Zmod(15)", "vars": ["x"], "polys": ["x^2 - 1"]},
    "small_roots constant": {"op": "small_roots", "modulus": 91, "poly": "5", "bound": 3},
    "small_roots lead not a unit": {"op": "small_roots", "modulus": 91, "poly": "7*x + 1", "bound": 3},
    "small_roots bound": {"op": "small_roots", "modulus": 91, "poly": "x + 1", "bound": 0},
    "small_roots beta": {"op": "small_roots", "modulus": 91, "poly": "x + 1", "bound": 3, "beta": 1.5},
    "small_roots epsilon": {"op": "small_roots", "modulus": 91, "poly": "x + 1", "bound": 3, "epsilon": 1},
    "small_roots two variables": {"op": "small_roots", "modulus": 91, "vars": ["x", "y"], "poly": "x + 1",
                                  "bound": 3},
}


@pytest.mark.parametrize("name", sorted(BAD_JOBS))
def test_parse_job_rejects(name):
    with pytest.raises(alg.JobError):
        alg.parse_job(BAD_JOBS[name])


def test_execute_rejects_a_bad_timeout_backend_and_version():
    job = {"op": "lll", "basis": [[1, 0], [0, 1]]}
    for bad in (0, -1, 1.5, True, alg.MAX_TIMEOUT + 1):
        with pytest.raises(alg.JobError, match="timeout"):
            alg.execute(job, timeout=bad)
    with pytest.raises(alg.JobError, match="backend"):
        alg.execute(job, backend="magma")
    with pytest.raises(alg.JobError, match="sage_version"):
        alg.execute(job, backend="sage-image", sage_version="10.5; rm")
    with pytest.raises(alg.JobError, match="python backend"):
        alg.execute(job, backend="python", sage_version="10.5")


# --------------------------------------------------------------------------- lattice certificates

def test_same_lattice_accepts_a_unimodular_change_only():
    b = [[1, 2, 3], [0, 1, 4]]
    u, v = [[1, 0], [-2, 1]], [[1, 0], [2, 1]]
    r = [[1, 2, 3], [-2, -3, -2]]
    assert alg.same_lattice(b, r, u, v)
    assert not alg.same_lattice(b, [[1, 2, 3], [-2, -3, -1]], u, v)          # a row off the lattice
    assert not alg.same_lattice(b, r, [[1, 0], [-2, 2]], v)                  # U does not give R
    assert not alg.same_lattice(b, r, u, [[1, 0], [2, 2]])                   # V does not give B back
    assert not alg.same_lattice(b, r, u, None)
    assert not alg.same_lattice(b, r, [[1.0, 0], [-2, 1]], v)                # not integers
    assert not alg.same_lattice(b, r[:1], [[1, 0]], v)                       # a row is missing
    assert not alg.same_lattice(b, [[1, 2], [-2, -3]], u, v)                 # a column is missing


def test_same_lattice_refuses_a_sublattice():
    b = [[1, 0], [0, 1]]
    doubled = [[2, 0], [0, 2]]
    assert not alg.same_lattice(b, doubled, [[2, 0], [0, 2]], [[1, 0], [0, 1]])
    assert alg.solve_left(doubled, b) is None                                # no integer V exists


def test_solve_left_finds_the_integer_transform_or_nothing():
    m = [[2, 1, 0], [1, 3, 5]]
    x = [[3, -1], [4, 7]]
    t = alg._matmul(x, m)
    assert alg.solve_left(m, t) == x
    assert alg.solve_left(m, [[1, 0, 0]]) is None                            # outside the row space
    assert alg.solve_left([[1, 0, 0], [0, 1, 0]], [[1, 1, 5]]) is None       # integer on the pivots only
    assert alg.solve_left([[1, 0, 0], [0, 1, 0]], [[1, 1, 0]]) == [[1, 1]]
    assert alg.solve_left(m, [[1, 2, 5]]) is None                           # in the span, not in the lattice
    assert alg.solve_left([[1, 2], [2, 4]], [[1, 2]]) is None                # dependent rows
    assert alg.solve_left([[0, 3], [5, 0]], [[5, 3]]) == [[1, 1]]            # needs a row swap


# ------------------------------------------------------------------- the python backend's answers

def test_lll_returns_the_short_basis_with_a_checked_transform():
    short = [[2, 0, 0], [0, 3, 0], [0, 0, 5]]
    basis = alg._matmul([[1, 0, 0], [977, 1, 0], [-613, 359, 1]], short)
    proof, checks, result = local({"op": "lll", "basis": basis})
    assert proof == "exact" and "same lattice" in checks[0]
    assert sorted(sum(x * x for x in row) for row in result["basis"]) == [4, 9, 25]
    assert alg._matmul(result["transform"], basis) == result["basis"]


def test_groebner_bases_match_hand_derived_ones():
    proof, checks, res = local({"op": "groebner", "ring": "GF(101)", "vars": ["x", "y"],
                                "polys": ["x*y - 1", "x - y"]})
    assert (proof, checks) == ("none", [])
    assert sorted(res["basis"]) == ["x + 100*y", "y^2 + 100"] and res["order"] == "lex"
    assert res["basis_terms"][res["basis"].index("y^2 + 100")] == [[1, [0, 2]], [100, [0, 0]]]
    _, _, lex = local({"op": "groebner", "ring": "QQ", "vars": ["a", "b", "c"], "polys": SYMMETRIC})
    assert sorted(lex["basis"]) == ["a + b + c - 6", "b^2 + b*c - 6*b + c^2 - 6*c + 11",
                                    "c^3 - 6*c^2 + 11*c - 6"]


def test_groebner_order_is_passed_through():
    polys = ["x^2 - y", "x*y - 1"]
    _, _, lex = local({"op": "groebner", "ring": "QQ", "vars": ["x", "y"], "polys": polys})
    _, _, deg = local({"op": "groebner", "ring": "QQ", "vars": ["x", "y"], "polys": polys, "order": "degrevlex"})
    assert sorted(lex["basis"]) == ["x - y^2", "y^3 - 1"]
    assert sorted(deg["basis"]) == ["-x + y^2", "x*y - 1", "x^2 - y"] and deg["order"] == "degrevlex"


def test_variety_over_a_large_prime_field_finds_the_planted_points():
    a, b = 0x1234567890abcdef, 0xfedcba9876543
    proof, checks, res = local({"op": "variety", "ring": f"GF({P127})", "vars": ["x", "y"],
                                "polys": [f"x + y - {a + b}", f"x*y - {a * b}"]})
    assert proof == "exact" and "substituted" in checks[0]
    assert sorted((p["x"], p["y"]) for p in res["points"]) == sorted([(a, b), (b, a)])
    assert res["complete"] == "claimed by the backend"


def test_variety_three_variables_and_rational_points():
    _, _, res = local({"op": "variety", "ring": "GF(65537)", "vars": ["a", "b", "c"], "polys": SYMMETRIC})
    assert sorted((p["a"], p["b"], p["c"]) for p in res["points"]) == [
        (1, 2, 3), (1, 3, 2), (2, 1, 3), (2, 3, 1), (3, 1, 2), (3, 2, 1)]
    _, _, rat = local({"op": "variety", "ring": "QQ", "vars": ["x", "y"], "polys": ["4*x^2 - 1", "x + y - 2"]})
    assert rat["points"] == [{"x": "-1/2", "y": "5/2"}, {"x": "1/2", "y": "3/2"}]
    _, _, irr = local({"op": "variety", "ring": "QQ", "vars": ["x"], "polys": ["x^2 - 2"]})
    assert irr["points"] == []                               # no rational point: the base field only


def test_variety_of_an_inconsistent_system_is_empty():
    _, _, res = local({"op": "variety", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x - 1", "x - 2", "y"]})
    assert res["points"] == []


def test_variety_refuses_an_ideal_with_a_free_variable():
    res = alg.execute({"op": "variety", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x*y"]},
                      backend="python")
    assert res.status == "error" and "zero-dimensional" in res.reason and res.result is None


def test_variety_uses_every_basis_polynomial_at_each_level():
    # y is pinned by y^2 = 1 and by y = 1 together: the second point of the first must go.
    _, _, res = local({"op": "variety", "ring": "GF(101)", "vars": ["x", "y"],
                       "polys": ["(y - 1)*(y + 1)", "(y - 1)*(y - 5)", "x - y - 3"]})
    assert res["points"] == [{"x": 4, "y": 1}]
    # Above y = 1 two basis polynomials bound x: (x - 1)(x - 2) and y(x - 1). Only x = 1 satisfies both;
    # above y = 0 the second vanishes and both roots stay.
    _, _, fibre = local({"op": "variety", "ring": "QQ", "vars": ["x", "y"],
                         "polys": ["y*(y - 1)", "y*(x - 1)", "(x - 1)*(x - 2)"]})
    assert fibre["points"] == [{"x": 1, "y": 0}, {"x": 1, "y": 1}, {"x": 2, "y": 0}]


def test_eliminate_and_resultant_drop_the_variable():
    proof, checks, res = local({"op": "eliminate", "ring": "QQ", "vars": ["x", "y"],
                                "polys": ["x^2 + y^2 - 5", "x - y - 1"], "eliminate": ["x"]})
    assert (proof, checks) == ("partial", ["the eliminated variables are absent"])
    assert res["basis"] == ["y^2 + y - 2"]
    _, _, second = local({"op": "eliminate", "ring": "QQ", "vars": ["x", "y"],
                          "polys": ["x^2 + y^2 - 5", "x - y - 1"], "eliminate": ["y"]})
    assert second["basis"] == ["x^2 - x - 2"]                # the other variable: the order is honoured
    _, _, two = local({"op": "eliminate", "ring": "GF(65537)", "vars": ["a", "b", "c"], "polys": SYMMETRIC,
                       "eliminate": ["b", "a"]})
    assert two["basis"] == ["c^3 + 65531*c^2 + 11*c + 65531"]
    proof, _, r = local({"op": "resultant", "ring": "QQ", "vars": ["x", "y"],
                         "polys": ["x^2 + y^2 - 5", "x - y - 1"], "var": "x"})
    assert proof == "partial" and r["poly"] == "2*y^2 + 2*y - 4" and r["poly_terms"][0] == [2, [0, 2]]
    _, _, ry = local({"op": "resultant", "ring": "QQ", "vars": ["x", "y"],
                      "polys": ["x^2 + y^2 - 5", "x - y - 1"], "var": "y"})
    assert ry["poly"] == "2*x^2 - 2*x - 4"
    _, _, const = local({"op": "resultant", "ring": "GF(101)", "vars": ["x"], "polys": ["x - 3", "x - 10"],
                         "var": "x"})
    assert const["poly"] == "94"                             # 3 - 10 mod 101: a constant


def test_roots_over_a_prime_field_and_the_rationals():
    proof, _, res = local({"op": "roots", "ring": f"GF({P127})", "vars": ["x"], "polys": ["x^3 - 7*x + 6"]})
    assert proof == "exact" and res["roots"] == [1, 2, P127 - 3]
    _, _, rat = local({"op": "roots", "ring": "QQ", "vars": ["t"], "polys": ["(2*t - 1)*(t + 3)*(t^2 + 1)"]})
    assert rat["roots"] == [-3, "1/2"]
    _, _, none = local({"op": "roots", "ring": "GF(7)", "vars": ["x"], "polys": ["x^2 - 3"]})
    assert none["roots"] == []                               # 3 is not a square mod 7


def test_small_roots_recovers_a_stereotyped_message_and_reports_the_divisor():
    n = 18446744073709551629 * 18446744073709551653
    m0, x0 = 0xc0ffee << 64, 0xbeef
    c = pow(m0 + x0, 3, n)
    proof, checks, res = local({"op": "small_roots", "modulus": n, "poly": f"(x + {m0})^3 - {c}",
                                "bound": 1 << 20})
    assert proof == "exact" and "f(root) = 0 mod N" in checks[0]
    assert res["roots"] == [{"root": x0, "divisor": n}]


def test_small_roots_with_beta_finds_a_factor_from_its_known_high_bits():
    p, q = 4294967311, 4294967357                            # primes just above 2^32
    n, low = p * q, p & 0xff
    proof, checks, res = local({"op": "small_roots", "modulus": n, "poly": f"x + {p - low}", "bound": 1 << 8,
                                "beta": 0.4})
    assert proof == "exact" and "gcd(f(root), N) > 1" in checks[0]
    assert {"root": low, "divisor": p} in res["roots"]


def test_python_backend_names_a_composite_field_modulus():
    res = alg.execute({"op": "groebner", "ring": "GF(15)", "vars": ["x"], "polys": ["x^2 - 1"]}, backend="python")
    assert res.status == "error" and "not prime" in res.reason and "15" in res.reason


# ------------------------------------------------------------------------ checks on backend answers

def checked(job, data):
    return alg._check(alg.parse_job(job), data)


VARIETY = {"op": "variety", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x*y - 1", "x - y"]}


def test_check_rejects_a_point_that_is_not_a_root():
    assert checked(VARIETY, {"points": [[1, 1], [100, 100]]})[2]["points"] == [{"x": 1, "y": 1},
                                                                             {"x": 100, "y": 100}]
    with pytest.raises(alg.ServiceError, match="not a common root"):
        checked(VARIETY, {"points": [[1, 1], [2, 51]]})      # 2*51 = 1 mod 101, but x != y
    with pytest.raises(alg.ServiceError, match="not a common root"):
        checked(VARIETY, {"points": [[5, 5]]})               # x = y, but 25 != 1
    for bad in ({"points": [[1]]}, {"points": "none"}, {"points": [[1, [1, 2]]]}, {}, None):
        with pytest.raises(alg.ServiceError):
            checked(VARIETY, bad)


def test_check_rejects_a_wrong_root_and_an_out_of_bound_small_root():
    roots = {"op": "roots", "ring": "GF(7)", "vars": ["x"], "polys": ["x^2 - 2"]}
    assert checked(roots, {"roots": [4, 3]})[2]["roots"] == [3, 4]
    with pytest.raises(alg.ServiceError, match="not a root"):
        checked(roots, {"roots": [3, 5]})
    small = {"op": "small_roots", "modulus": 91, "poly": "x^2 - 4", "bound": 3}
    assert checked(small, {"roots": [2, 89]})[2]["roots"] == [{"root": -2, "divisor": 91}, {"root": 2, "divisor": 91}]
    with pytest.raises(alg.ServiceError, match="not a root within the bound"):
        checked(small, {"roots": [3]})                       # 9 - 4 = 5: no common factor at all
    with pytest.raises(alg.ServiceError, match="not a root within the bound"):
        checked(dict(small, bound=9), {"roots": [9]})        # 81 - 4 = 77 shares 7 with 91: not a root mod N
    with pytest.raises(alg.ServiceError, match="not a root within the bound"):
        checked(dict(small, bound=1), {"roots": [2]})        # a root, but outside the bound
    partial = dict(small, beta=0.5)                          # beta < 1: a root modulo a divisor counts
    assert checked(dict(partial, bound=9), {"roots": [9]})[2]["roots"] == [{"root": 9, "divisor": 7}]
    with pytest.raises(alg.ServiceError):
        checked(dict(partial, bound=9), {"roots": [3]})      # gcd 1: nothing learned, so not a root
    with pytest.raises(alg.ServiceError, match="integer root list"):
        checked(small, {"roots": ["2"]})


def test_check_rejects_a_surviving_eliminated_variable_and_malformed_polynomials():
    elim = {"op": "eliminate", "ring": "QQ", "vars": ["x", "y"], "polys": ["x - y"], "eliminate": ["x"]}
    assert checked(elim, {"basis": [[[1, [0, 2]]]]})[2]["basis"] == ["y^2"]
    assert checked(elim, {"basis": [[], [[1, [0, 2]]], [[0, [0, 1]]]]})[2] == {
        "basis": ["y^2"], "basis_terms": [[[1, [0, 2]]]]}    # zero generators are dropped
    gb = {"op": "groebner", "ring": "QQ", "vars": ["x", "y"], "polys": ["x - y"]}
    assert checked(gb, {"basis": [[], [[1, [1, 0]], [-1, [0, 1]]]]})[2]["basis"] == ["x - y"]
    with pytest.raises(alg.ServiceError, match="eliminated variable"):
        checked(elim, {"basis": [[[1, [0, 2]]], [[1, [1, 1]]]]})
    res = {"op": "resultant", "ring": "QQ", "vars": ["x", "y"], "polys": ["x - y", "x + y"], "var": "y"}
    assert checked(res, {"poly": [[2, [1, 0]]]})[2]["poly"] == "2*x"
    with pytest.raises(alg.ServiceError, match="eliminated variable"):
        checked(res, {"poly": [[2, [1, 1]]]})
    for bad in ({"basis": [[[1, [0]]]]}, {"basis": [[["x", [0, 1]]]]}, {"basis": "y"}, {}):
        with pytest.raises(alg.ServiceError):
            checked(elim, bad)


def test_check_rejects_a_reduction_whose_transforms_do_not_multiply_out():
    job = {"op": "lll", "basis": [[1, 2], [3, 5]]}
    good = {"basis": [[1, 0], [0, 1]], "u": [[-5, 2], [3, -1]], "v": [[1, 2], [3, 5]]}
    assert checked(job, good) == ("exact", ["same lattice: U·B = R and V·R = B over the integers"],
                                  {"basis": [[1, 0], [0, 1]], "transform": [[-5, 2], [3, -1]]})
    for key, value in (("basis", [[1, 0], [0, 2]]), ("u", [[-5, 2], [3, -2]]), ("v", [[1, 2], [3, 6]])):
        with pytest.raises(alg.ServiceError, match="lattice check"):
            checked(job, dict(good, **{key: value}))
    for key in good:
        with pytest.raises(alg.ServiceError, match="lattice check"):
            checked(job, {k: v for k, v in good.items() if k != key})


# -------------------------------------------------------------------------- backends and routing

def no_tools(tmp_path):
    """An environ with nothing on PATH: no sage, no docker."""
    (tmp_path / "empty").mkdir(exist_ok=True)
    return {"PATH": str(tmp_path / "empty"), "CTF_TESTING": "1", "HOME": str(tmp_path)}


def test_execute_runs_the_python_backend_in_a_child_and_names_it():
    res = alg.execute(VARIETY)
    assert res.ok and res.backend == "python" and res.detail.startswith("SymPy ")
    assert res.proof == "exact" and res.require()["points"] == [{"x": 1, "y": 1}, {"x": 100, "y": 100}]
    d = res.to_dict()
    assert d["status"] == "ok" and d["schema"] == 1 and d["needs_tool"] == [] and d["seconds"] >= 0
    assert json.loads(json.dumps(d)) == d


def test_bkz_without_fpylll_is_blocked_never_downgraded_to_lll(monkeypatch, tmp_path):
    monkeypatch.setattr(alg, "_has_module", lambda name: name != "fpylll")
    job = {"op": "bkz", "basis": [[1, 2], [3, 5]], "block_size": 2}
    res = alg.execute(job, backend="python")
    assert res.status == "blocked" and res.needs_tool == ("py:fpylll",) and res.result is None
    assert res.backend == "python" and "fpylll" in res.reason and res.fix
    with pytest.raises(alg.BackendUnavailable) as ex:
        res.require()
    assert ex.value.needs_tool == ("py:fpylll",)
    with pytest.raises(alg.BackendUnavailable):
        alg.reduce_basis(job["basis"], method="bkz", block_size=2, backend="python")
    auto = alg.execute(job, environ=no_tools(tmp_path))
    assert auto.status == "blocked" and auto.result is None
    assert set(auto.needs_tool) == {"py:fpylll", "sage", "image:ctf-sage:10.7"}
    for part in ("python:", "sage-local:", "sage-image:"):
        assert part in auto.reason
    lll = alg.reduce_basis(job["basis"], backend="python")   # LLL itself still runs: det 1, so unit rows
    assert [sum(x * x for x in row) for row in lll] == [1, 1]


def test_the_python_child_reports_a_missing_fpylll_itself(monkeypatch):
    """The parent's probe says fpylll is there; the child must still refuse BKZ when it is not."""
    monkeypatch.setattr(alg, "_has_module", lambda name: True)
    res = alg.execute({"op": "bkz", "basis": [[1, 2], [3, 5]], "block_size": 2}, backend="python")
    if importlib.util.find_spec("fpylll") is None:
        assert res.status == "blocked" and res.needs_tool == ("py:fpylll",) and res.result is None
    else:
        assert res.ok and res.proof == "exact" and "fpylll" in res.detail


@pytest.mark.needs_tool("py:fpylll")
def test_bkz_on_a_local_fpylll_is_checked_like_any_reduction():
    short = [[2, 0, 0], [0, 3, 0], [0, 0, 5]]
    basis = alg._matmul([[1, 0, 0], [977, 1, 0], [-613, 359, 1]], short)
    res = alg.execute({"op": "bkz", "basis": basis, "block_size": 3}, backend="python")
    assert res.ok and res.proof == "exact" and "fpylll" in res.detail
    assert sorted(sum(x * x for x in row) for row in res.result["basis"]) == [4, 9, 25]


def test_auto_gives_small_jobs_to_python_and_large_ones_to_sage(tmp_path):
    env = no_tools(tmp_path)
    small = alg.parse_job({"op": "lll", "basis": [[1, 0], [0, 1]]})
    assert alg.plan_backend(small, "auto", environ=env).backend == "python"
    n = alg.AUTO_LATTICE_ROWS + 1
    big = alg.parse_job({"op": "lll", "basis": [[int(i == j) for j in range(n)] for i in range(n)]})
    with pytest.raises(alg.BackendUnavailable) as ex:
        alg.plan_backend(big, "auto", environ=env)
    assert f"{n} rows" in ex.value.reason and "sage" in ex.value.needs_tool
    assert alg.plan_backend(big, "python", environ=env).backend == "python"      # asked for by name: allowed
    at = alg.parse_job({"op": "lll", "basis": [[int(i == j) for j in range(n - 1)] for i in range(n - 1)]})
    assert alg.plan_backend(at, "auto", environ=env).backend == "python"
    names = [f"v{i}" for i in range(alg.AUTO_IDEAL_VARS + 1)]
    wide = alg.parse_job({"op": "groebner", "ring": "QQ", "vars": names, "polys": ["v0 - 1"]})
    with pytest.raises(alg.BackendUnavailable, match="variables"):
        alg.plan_backend(wide, "auto", environ=env)
    steep = alg.parse_job({"op": "groebner", "ring": "QQ", "vars": ["x"],
                           "polys": [f"x^{alg.AUTO_IDEAL_DEGREE + 1} - 1"]})
    with pytest.raises(alg.BackendUnavailable, match="degree"):
        alg.plan_backend(steep, "auto", environ=env)
    ring = alg.parse_job({"op": "groebner", "ring": "Zmod(15)", "vars": ["x"], "polys": ["x^2 - 1"]})
    with pytest.raises(alg.BackendUnavailable, match=r"Zmod\(15\)"):
        alg.plan_backend(ring, "python", environ=env)
    deg = alg.parse_job({"op": "small_roots", "modulus": 91,
                         "poly": f"x^{alg.AUTO_SMALL_ROOTS_DEGREE + 1} - 1", "bound": 2})
    with pytest.raises(alg.BackendUnavailable, match="degree"):
        alg.plan_backend(deg, "auto", environ=env)


def test_a_job_that_outlives_its_timeout_is_stopped_and_reported(monkeypatch):
    monkeypatch.setattr(alg, "PYTHON_GRACE", 0)
    names = [f"x{i}" for i in range(7)]
    cyclic = ["*".join(names) + " - 1"] + [
        " + ".join("*".join(names[(i + j) % 7] for j in range(k)) for i in range(7)) for k in range(1, 7)]
    res = alg.execute({"op": "groebner", "ring": "QQ", "vars": names, "polys": cyclic}, backend="python",
                      timeout=1)
    assert res.status == "timeout" and res.result is None and res.backend == "python"
    with pytest.raises(alg.ServiceError, match="timeout"):
        res.require()


def test_the_python_worker_starts_isolated_from_the_callers_python_path(tmp_path):
    """The child runs `python -I`: a module planted on PYTHONPATH (here a sitecustomize, which Python
    imports at start-up) is not loaded, so a challenge folder on the path cannot inject code."""
    planted = tmp_path / "planted"
    planted.mkdir()
    marker = tmp_path / "planted-ran"
    (planted / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w').write('ran')\n")
    env = dict(no_tools(tmp_path), PYTHONPATH=str(planted))
    subprocess.run([sys.executable, "-c", "pass"], env=env, check=True, timeout=600)
    assert marker.exists()                                   # the plant works on a plain interpreter
    marker.unlink()
    res = alg.execute({"op": "lll", "basis": [[1, 2], [3, 5]]}, backend="python", environ=env, timeout=120)
    assert res.ok, res.reason
    assert not marker.exists()


def test_backend_status_names_what_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(alg, "_has_module", lambda name: name != "fpylll")
    st = alg.backend_status(environ=no_tools(tmp_path))
    assert st["python"] == {"available": True, "lll": True, "bkz": False, "ideals": True,
                            "rings": ["QQ", "GF"], "needs_tool": ["py:fpylll"]}
    assert st["sage-local"] == {"available": False, "path": None, "needs_tool": ["sage"]}
    img = st["sage-image"]
    assert img["available"] is False and img["default"] == "ctf-sage:10.7"
    assert sorted(i["tag"] for i in img["images"]) == ["ctf-sage:10.5", "ctf-sage:10.7"]
    assert {i["state"] for i in img["images"]} == {"unknown"}
    assert sorted(img["needs_tool"]) == ["image:ctf-sage:10.5", "image:ctf-sage:10.7"]


# ------------------------------------------------------------------------------- the Sage backends

JOBS = {
    "lll": {"op": "lll", "basis": [[1, 2, 3], [4, 5, 7], [7, 8, 8]]},
    "bkz": {"op": "bkz", "basis": [[1, 2, 3], [4, 5, 7], [7, 8, 8]], "block_size": 2, "tours": 3},
    "groebner": {"op": "groebner", "ring": "QQ", "vars": ["a", "b", "c"], "polys": SYMMETRIC, "order": "degrevlex"},
    "variety": {"op": "variety", "ring": "QQ", "vars": ["x", "y"], "polys": ["4*x^2 - 1", "x + y - 2"]},
    "eliminate": {"op": "eliminate", "ring": "GF(65537)", "vars": ["a", "b", "c"], "polys": SYMMETRIC,
                  "eliminate": ["a", "b"]},
    "resultant": {"op": "resultant", "ring": "QQ", "vars": ["x", "y"], "polys": ["x^2 + y^2 - 5", "x - y - 1"],
                  "var": "x"},
    "roots": {"op": "roots", "ring": "QQ", "vars": ["t"], "polys": ["(2*t - 1)*(t + 3)"]},
    "small_roots": {"op": "small_roots", "modulus": 91, "poly": "x^2 - 4", "bound": 3},
}


@pytest.fixture
def image_env(tmp_path):
    return stubs.docker_stub(tmp_path, {"images": stubs.built("10.5", "10.7")})


@pytest.mark.parametrize("op", sorted(JOBS))
def test_sage_image_answers_match_the_python_backend(op, image_env):
    res = alg.execute(JOBS[op], backend="sage-image", environ=image_env, timeout=120)
    assert res.ok, res.reason
    assert res.backend == "sage-image" and res.detail == "SageMath 10.7 (ctf-sage:10.7)"
    if op == "bkz":
        assert res.proof == "exact" and alg._matmul(res.result["transform"], JOBS[op]["basis"]) == res.result["basis"]
        assert {"call": "BKZ", "block_size": 2, "kw": {"max_loops": 3}} in stubs.calls(image_env, "fake")
        assert not any(c["call"] == "LLL" for c in stubs.calls(image_env, "fake"))
    else:
        proof, checks, result = local(JOBS[op])
        assert (res.proof, list(res.checks), res.result) == (proof, checks, result)
    if op == "lll":
        assert stubs.calls(image_env, "fake") == [{"call": "LLL", "rows": 3}]


def test_sage_image_runs_the_pinned_image_without_network_or_pull(image_env):
    res = alg.execute(JOBS["roots"], backend="sage-image", environ=image_env, timeout=77)
    assert res.ok
    inspect, run = [c["argv"] for c in stubs.calls(image_env, "docker")]
    assert inspect[:2] == ["image", "inspect"] and inspect[-1] == "ctf-sage:10.7"
    assert run[0] == "run" and "--rm" in run and "--pull=never" in run
    assert run[run.index("--network") + 1] == "none"
    assert run[run.index("--cap-drop") + 1] == "ALL"
    assert run[run.index("--platform") + 1] == "linux/amd64"
    mount = run[run.index("-v") + 1]
    assert mount.endswith(":/work") and not Path(mount.rsplit(":", 1)[0]).exists()      # the job folder is gone
    assert run[run.index("ctf-sage:10.7") + 1:] == ["timeout", "-k", "10", "77", "sage", "-python",
                                                   "/work/worker.py", "/work/job.json"]
    # inside, the same limit is set as an alarm and cleared once the answer is in hand
    assert stubs.calls(image_env, "alarm") == [{"call": "alarm", "seconds": 77}, {"call": "cancel_alarm"}]


def test_an_image_job_past_its_limit_kills_its_own_container_by_name(tmp_path, monkeypatch):
    """Killing the docker CLI leaves its container running: on the outer timeout the service kills the
    container it named, and only that one (wall-clock by nature: the stub hangs 600 s, the limit is 1 s)."""
    monkeypatch.setattr(alg, "IMAGE_START_GRACE", 0)
    env = stubs.docker_stub(tmp_path, {})
    names = []
    for kill in ("ok", "fails", "gone"):
        stubs.set_state(env, {"images": stubs.built("10.7"), "mode": "hang", "hang": 600,
                              "kill_fails": kill == "fails", "kill_gone": kill == "gone"})
        res = alg.execute(JOBS["roots"], backend="sage-image", environ=env, timeout=1)
        assert res.status == "timeout" and res.result is None
        runs = [c["argv"] for c in stubs.calls(env, "docker") if c["argv"][:1] == ["run"]]
        name = runs[-1][runs[-1].index("--name") + 1]
        assert name.startswith(alg.CONTAINER_PREFIX) and len(name) > len(alg.CONTAINER_PREFIX) + 16
        kills = [c["argv"] for c in stubs.calls(env, "docker") if c["argv"][:1] == ["kill"]]
        assert kills[-1] == ["kill", name]
        names.append(name)
        if kill == "fails":
            assert f"`docker kill {name}` exited 1" in res.reason and "cannot kill" in res.reason
        elif kill == "gone":                                 # it ended between the timeout and the kill
            assert f"container {name} had already ended" in res.reason
            assert "exited 1" not in res.reason and "killed" not in res.reason
        else:
            assert f"container {name} killed" in res.reason
    assert len(set(names)) == 3                              # every job names its own container
    assert len([c for c in stubs.calls(env, "docker") if c["argv"][:1] == ["kill"]]) == 3


def test_sage_gets_the_resultant_variable_and_the_small_roots_parameters(image_env):
    by_y = dict(JOBS["resultant"], var="y")
    res = alg.execute(by_y, backend="sage-image", environ=image_env)
    assert res.ok and res.result["poly"] == "2*x^2 - 2*x - 4" == local(by_y)[2]["poly"]
    n = 18446744073709551629 * 18446744073709551653
    m0, x0 = 0xc0ffee << 64, 0xbeef
    job = {"op": "small_roots", "modulus": n, "poly": f"(x + {m0})^3 - {pow(m0 + x0, 3, n)}", "bound": 1 << 20,
           "beta": 1, "epsilon": 0.05}
    got = alg.execute(job, backend="sage-image", environ=image_env)
    assert got.ok and got.result["roots"] == [{"root": x0, "divisor": n}]
    assert stubs.calls(image_env, "fake") == [{"call": "small_roots", "X": 1 << 20, "beta": 1.0, "epsilon": 0.05}]


def test_sage_version_picks_its_image_and_only_an_image(tmp_path):
    stubs.sage_stub(tmp_path)                                # a local sage sits on the same PATH
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.5", "10.7")})
    for wanted in ("10.5", "10.5.1"):
        res = alg.execute(JOBS["roots"], backend="sage", sage_version=wanted, environ=env)
        assert res.ok and res.backend == "sage-image" and res.detail == "SageMath 10.5 (ctf-sage:10.5)"
    assert stubs.calls(env, "sage") == []
    for missing in ("9.8", "10.50", "10"):
        res = alg.execute(JOBS["roots"], backend="auto", sage_version=missing, environ=env)
        assert res.status == "blocked" and "no single entry" in res.reason and missing in res.reason
        assert "10.5 (ctf-sage:10.5)" in res.reason and res.needs_tool == ("image:ctf-sage",)
    plain = alg.execute(JOBS["roots"], backend="sage", environ=env)
    assert plain.ok and plain.backend == "sage-local"        # no release asked for: the local one first


def test_sage_local_runs_the_worker_and_reports_its_release(tmp_path):
    env = stubs.sage_stub(tmp_path, {"sage_version": "10.6"})
    res = alg.execute(JOBS["variety"], backend="sage-local", environ=env)
    assert res.ok and res.backend == "sage-local"
    assert res.detail == f"SageMath 10.6 ({tmp_path / 'stubbin' / 'sage'})"
    assert res.result["points"] == [{"x": "-1/2", "y": "5/2"}, {"x": "1/2", "y": "3/2"}]
    (call,) = stubs.calls(env, "sage")
    assert call["argv"][0] == "-python" and call["argv"][1].endswith("worker.py")
    wrong = alg.execute(JOBS["variety"], backend="sage-local", sage_version="10.5", environ=env)
    assert wrong.status == "blocked" and "10.5" in wrong.reason and "10.6" in wrong.reason
    assert wrong.result is None and wrong.needs_tool == ("sage",)


def test_auto_sends_what_python_cannot_do_to_sage(image_env):
    res = alg.execute({"op": "bkz", "basis": [[1, 2], [3, 5]], "block_size": 2}, environ=image_env)
    if importlib.util.find_spec("fpylll") is None:
        assert res.ok and res.backend == "sage-image"
    else:
        assert res.ok and res.backend == "python"
    zmod = alg.execute({"op": "groebner", "ring": "Zmod(15)", "vars": ["x"], "polys": ["x^2 - 1"]},
                       environ=image_env)
    assert zmod.backend == "sage-image"                      # routed to Sage; the fake has no Zmod ideals
    assert zmod.status == "error" and "Zmod" in zmod.reason


@pytest.mark.parametrize("state, needle", [
    ({"images": {}}, "missing"),
    ({"images": {"ctf-sage:10.7": {images.LABEL: "0" * 64}}}, "stale"),
    ({"images": {"ctf-sage:10.7": {}}}, "unlabelled"),
    ({"down": True}, "unknown"),
], ids=["missing", "stale", "unlabelled", "docker down"])
def test_an_image_that_is_not_built_and_fresh_blocks_the_job(tmp_path, state, needle):
    env = stubs.docker_stub(tmp_path, state)
    res = alg.execute(JOBS["roots"], backend="sage-image", environ=env)
    assert res.status == "blocked" and res.backend == "sage-image" and res.result is None
    assert needle in res.reason and res.needs_tool == ("image:ctf-sage:10.7",)
    if needle != "unknown":
        assert "toolchain build --apply --only sage-10.7" in res.fix
    assert all(c["argv"][0] != "run" for c in stubs.calls(env, "docker"))            # nothing was started


def test_no_docker_and_a_real_docker_under_testing_both_block(tmp_path):
    res = alg.execute(JOBS["roots"], backend="sage-image", environ=no_tools(tmp_path))
    assert res.status == "blocked" and "docker is not on PATH" in res.reason
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7")}, marker=False)
    refused = alg.execute(JOBS["roots"], backend="sage-image", environ=env)
    assert refused.status == "blocked" and "not a test stub" in refused.reason
    assert stubs.calls(env) == []                            # the unmarked docker was never run
    local_missing = alg.execute(JOBS["roots"], backend="sage-local", environ=no_tools(tmp_path))
    assert local_missing.status == "blocked" and local_missing.needs_tool == ("sage",)


def test_a_manifest_without_a_default_sage_image_blocks(tmp_path):
    root = tmp_path / "root"
    (root / "tools").mkdir(parents=True)
    (root / "docker" / "sage").mkdir(parents=True)
    (root / "docker" / "sage" / "Dockerfile").write_text("ARG SAGE_TAG\nFROM sagemath/sagemath:${SAGE_TAG}\n")
    (root / "requirements.in").write_text("")
    (root / "tools" / "images.toml").write_text(
        '[[image]]\nname = "sage-10.5"\ntag = "ctf-sage:10.5"\ndockerfile = "docker/sage/Dockerfile"\n'
        'context = "docker/sage"\nrole = "optional"\nargs = { SAGE_TAG = "10.5" }\nversions = { sage = "10.5" }\n'
        'smoke = [["sage", "--version"]]\n')
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.5", root=root)})
    res = alg.execute(JOBS["roots"], backend="sage-image", environ=env, root=root)
    assert res.status == "blocked" and "default Sage image" in res.reason
    named = alg.execute(JOBS["roots"], backend="sage-image", sage_version="10.5", environ=env, root=root)
    assert named.ok and named.detail == "SageMath 10.5 (ctf-sage:10.5)"


def test_a_worker_of_another_release_than_its_image_is_blocked(tmp_path):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7"), "sage_version": "9.5"})
    res = alg.execute(JOBS["roots"], backend="sage-image", environ=env)
    assert res.status == "blocked" and "10.7" in res.reason and "9.5" in res.reason and res.result is None


@pytest.mark.parametrize("mode, op, needle", [
    ("bad_basis", "lll", "lattice check"),
    ("bad_transform", "lll", "lattice check"),
    ("half_lattice", "bkz", "lattice check"),
    ("bad_point", "variety", "not a common root"),
    ("bad_root", "roots", "not a root"),
    ("bad_root", "small_roots", "not a root within the bound"),
    ("keep_var", "eliminate", "eliminated variable"),
    ("keep_var", "resultant", "eliminated variable"),
    ("noversion", "roots", "did not report its release"),
    ("silent", "roots", "without a result"),
])
def test_a_wrong_or_silent_sage_answer_is_an_error_never_a_result(tmp_path, mode, op, needle):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7"), "mode": mode})
    res = alg.execute(JOBS[op], backend="sage-image", environ=env)
    assert res.status == "error" and needle in res.reason and res.result is None
    with pytest.raises(alg.ServiceError):
        res.require()


def test_a_worker_stopped_at_its_limit_is_a_timeout(tmp_path, monkeypatch):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7"), "mode": "exit124"})
    res = alg.execute(JOBS["roots"], backend="sage-image", environ=env)
    assert res.status == "timeout" and res.result is None
    monkeypatch.setattr(alg, "SAGE_LOCAL_GRACE", 0)
    slow = stubs.sage_stub(tmp_path / "slow", {"mode": "hang", "hang": 600})
    pidfile = Path(slow["STUB_LOG"] + ".pid")
    # The stub `sage` is a wrapper around the interpreter that does the work, as the real one is: the
    # whole process group is killed, so the worker behind the wrapper is gone too. Wall-clock by
    # nature: the limit is raised until the worker was up (it writes its pid) before the kill, then
    # the kernel gets 120 s to reap it; left alone it would sleep 600 s.
    for limit in (1, 4, 16, 64):
        hung = alg.execute(JOBS["roots"], backend="sage-local", environ=slow, timeout=limit)
        assert hung.status == "timeout" and "no answer within" in hung.reason and hung.result is None
        if pidfile.exists():
            break
    pid = int(pidfile.read_text())                           # no pid file: the worker never started
    deadline = time.monotonic() + 120
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _alive(pid)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_the_worker_ends_an_overlong_computation_itself_and_says_so(tmp_path, monkeypatch):
    """Inside Sage the job's limit is an alarm: the worker itself reports the timeout. The outside
    kill is moved an hour away here, so on a loaded machine only the worker's alarm can end the run
    (wall-clock: the fake reduction sleeps 3000 s, the alarm is set for 1 s)."""
    monkeypatch.setattr(alg, "SAGE_LOCAL_GRACE", 3600)
    env = stubs.sage_stub(tmp_path, {"mode": "slow_lll", "hang": 3000})
    res = alg.execute(JOBS["lll"], backend="sage-local", environ=env, timeout=1)
    assert res.status == "timeout" and "interrupted at the job's time limit" in res.reason
    assert res.result is None
    stubs.set_state(env, {})
    again = alg.execute(JOBS["lll"], backend="sage-local", environ=env, timeout=3000)
    assert again.ok and "alarm" not in again.detail          # a job inside its limit is not interrupted
    stubs.set_state(env, {"mode": "noalarm"})
    bare = alg.execute(JOBS["lll"], backend="sage-local", environ=env, timeout=3000)
    assert bare.ok and "no cysignals alarm" in bare.detail   # said, not hidden: only the outside kill applies
    assert stubs.calls(env, "alarm")[-2:] == [{"call": "alarm", "seconds": 3000}, {"call": "cancel_alarm"}]


def test_a_sage_error_comes_back_with_its_message(image_env):
    res = alg.execute({"op": "groebner", "ring": "GF(15)", "vars": ["x"], "polys": ["x^2 - 1"]},
                      backend="sage-image", environ=image_env)
    assert res.status == "error" and "ValueError" in res.reason and "prime" in res.reason
    dep = alg.execute({"op": "lll", "basis": [[1, 2, 3], [2, 4, 6]]}, backend="sage-image", environ=image_env)
    assert dep.status == "error" and "the basis rows are linearly dependent" in dep.reason   # the worker's check


def test_the_worker_checks_the_dimension_before_asking_for_a_variety(image_env):
    free = alg.execute({"op": "variety", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x*y"]},
                       backend="sage-image", environ=image_env)
    assert free.status == "error" and "not zero-dimensional (dimension 1)" in free.reason
    unit = alg.execute({"op": "variety", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x - 1", "x - 2", "y"]},
                       backend="sage-image", environ=image_env)
    assert unit.ok and unit.result["points"] == []           # the unit ideal: no point, and no error


def test_selftest_passes_on_a_working_backend_and_fails_on_a_wrong_one(tmp_path):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7")})
    rep = alg.selftest(backend="sage-image", environ=env)
    assert rep["status"] == "passed" and rep["counts"] == {"passed": 8, "failed": 0, "blocked": 0}
    assert [c["case"] for c in rep["cases"]] == list(alg.OPS)
    stubs.set_state(env, {"images": stubs.built("10.7"), "mode": "bad_root"})
    bad = alg.selftest(backend="sage-image", environ=env)
    assert bad["status"] == "failed"
    assert {c["case"] for c in bad["cases"] if c["verdict"] == "failed"} == {"roots", "small_roots"}
    stubs.set_state(env, {"images": {}})
    none = alg.selftest(backend="sage-image", environ=env)
    assert none["status"] == "blocked" and none["counts"]["blocked"] == 8
    assert none["cases"][0]["needs_tool"] == ["image:ctf-sage:10.7"]


def test_selftest_compares_the_answer_not_just_the_status(monkeypatch):
    """A backend that answers a different (valid) question must fail the known-answer check."""
    real = alg.execute

    def other(job, **kw):
        if job["op"] == "roots":
            job = dict(job, polys=["x^3 - 7*x - 6"])         # still checkable roots, not the expected ones
        return real(job, **kw)

    monkeypatch.setattr(alg, "execute", other)
    rep = alg.selftest(backend="python")
    row = next(c for c in rep["cases"] if c["case"] == "roots")
    assert row["verdict"] == "failed" and "differs" in row["reason"] and rep["status"] == "failed"


@pytest.mark.needs_tool("sage")
def test_selftest_on_a_real_local_sage():
    rep = alg.selftest(backend="sage-local")
    assert rep["status"] == "passed", rep


# --------------------------------------------------------------------------------- the worker file

def load_worker():
    spec = importlib.util.spec_from_file_location("_algebra_sage_worker_under_test", WORKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_worker_and_service_agree_on_the_protocol():
    worker = load_worker()                                   # importable without Sage: it imports it lazily
    assert worker.SENTINEL == alg.SENTINEL
    assert worker.OPS == alg.OPS and set(worker.HANDLERS) == set(alg.OPS)


def test_worker_imports_only_the_standard_library_and_sage_and_never_evaluates():
    tree = ast.parse(WORKER.read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add((node.module or "").split(".")[0])
    assert modules == {"json", "sys", "sage", "cysignals"}
    called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not called & {"eval", "exec", "compile", "__import__", "sage_eval", "preparse", "load", "attach"}
    assert not names & {"eval", "exec", "__import__", "sage_eval", "preparse", "SR", "system", "popen"}


def test_worker_reports_usage_and_unknown_ops_without_sage(tmp_path, capsys):
    worker = load_worker()
    assert worker.main(["worker.py"]) == 2
    assert json.loads(capsys.readouterr().out.strip().split(alg.SENTINEL, 1)[1])["status"] == "error"
    env = stubs.sage_stub(tmp_path)
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"op": "factor", "timeout": 5}))
    p = subprocess.run([str(tmp_path / "stubbin" / "sage"), "-python", str(WORKER), str(job)],
                       capture_output=True, text=True, env=env, timeout=300)
    line = next(x for x in p.stdout.splitlines() if x.startswith(alg.SENTINEL))
    out = json.loads(line[len(alg.SENTINEL):])
    assert out["status"] == "error" and "unknown op" in out["error"]


# --------------------------------------------------------------------------------------------- CLI

def write_job(tmp_path, job, name="job.json"):
    path = tmp_path / name
    path.write_text(json.dumps(job))
    return str(path)


def test_cli_run_prints_the_result_and_exit_codes_follow_the_status(tmp_path, capsys, monkeypatch):
    assert alg.main(["run", write_job(tmp_path, VARIETY), "--backend", "python"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "ok" and out["result"]["points"][0] == {"x": 1, "y": 1}
    free = write_job(tmp_path, {"op": "variety", "ring": "GF(101)", "vars": ["x", "y"], "polys": ["x*y"]}, "f.json")
    assert alg.main(["run", free, "--backend", "python"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"
    monkeypatch.setattr(alg, "_has_module", lambda name: name != "fpylll")
    bkz = write_job(tmp_path, {"op": "bkz", "basis": [[1, 2], [3, 5]], "block_size": 2}, "b.json")
    assert alg.main(["run", bkz, "--backend", "python"]) == 3
    assert json.loads(capsys.readouterr().out)["needs_tool"] == ["py:fpylll"]


@pytest.mark.parametrize("argv", [[], ["run"], ["run", "/nonexistent/job.json"], ["frobnicate"],
                                  ["run", "JOB", "--backend", "magma"], ["run", "JOB", "--timeout", "0"],
                                  ["run", "BAD"], ["run", "LIST"], ["run", "NOTJSON"]])
def test_cli_usage_and_bad_jobs_exit_2(tmp_path, capsys, argv):
    files = {"JOB": write_job(tmp_path, VARIETY), "BAD": write_job(tmp_path, {"op": "factor"}, "bad.json"),
             "LIST": write_job(tmp_path, [1, 2], "list.json"), "NOTJSON": str(tmp_path / "raw.json")}
    (tmp_path / "raw.json").write_text("{not json")
    assert alg.main([files.get(a, a) for a in argv]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("algebra_service: ")


def test_cli_status_and_selftest(tmp_path, capsys, monkeypatch):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7")})
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert alg.main(["status"]) == 0
    st = json.loads(capsys.readouterr().out)
    assert st["sage-image"]["available"] is True and st["sage-image"]["default"] == "ctf-sage:10.7"
    assert alg.main(["selftest", "--backend", "sage-image"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"
    stubs.set_state(env, {"images": {}})
    assert alg.main(["selftest", "--backend", "sage-image"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "blocked"
    stubs.set_state(env, {"images": stubs.built("10.7"), "mode": "bad_point"})
    assert alg.main(["selftest", "--backend", "sage-image"]) == 1
    assert json.loads(capsys.readouterr().out)["counts"]["failed"] == 1


def test_the_script_runs_as_an_engine_entry(tmp_path):
    """`cli:python solvers/common/algebra_service.py`: the file itself, its child worker included."""
    job = write_job(tmp_path, {"op": "roots", "ring": "GF(7)", "vars": ["x"], "polys": ["x^2 - 2"]})
    p = subprocess.run([sys.executable, str(SERVICE), "run", job, "--backend", "python"], capture_output=True,
                       text=True, cwd=str(tmp_path), timeout=600)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout)
    assert out["result"]["roots"] == [3, 4] and out["backend"] == "python" and out["proof"] == "exact"


def test_big_integers_survive_the_round_trip(tmp_path):
    """Entries past Python's 4300-digit decimal cap: the job file, both JSON hops and the result."""
    big = 10 ** 4500 + 7
    with alg._bigints():
        job = write_job(tmp_path, {"op": "lll", "basis": [[1, big], [0, 3]]})
    res = alg.execute(alg.load_job(job), backend="python")
    assert res.ok and alg._matmul(res.result["transform"], [[1, big], [0, 3]]) == res.result["basis"]
    assert sys.get_int_max_str_digits() < 4500               # the process-wide cap was restored


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
