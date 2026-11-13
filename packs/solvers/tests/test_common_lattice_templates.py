"""B-157: template lattice constructions (solvers/common/lattice_templates.py).

Each template is solved on a planted instance through the real python backend (exact LLL), its
`extract` is fed rows that must be refused (an off-by-one unknown, an out-of-bound value, a wrong
output), and the BKZ path is driven through the stub Sage image of tests/algebra_stubs.py: BKZ with no
backend is BackendUnavailable, never an LLL answer.
"""
from __future__ import annotations

import json
import random
import sys

import pytest

import algebra_service as alg
import algebra_stubs as stubs
import lattice_templates as lt

Q127 = (1 << 127) - 1


def reduced(template):
    """The template's basis after the python backend's exact LLL."""
    return alg.reduce_basis(template.basis, backend="python")


def hnp_instance(seed=7, samples=8, bound=1 << 100):
    rng = random.Random(seed)
    x = rng.randrange(Q127)
    pairs = []
    while len(pairs) < samples:
        t = rng.randrange(1, Q127)
        pairs.append([t, (rng.randrange(bound) - t * x) % Q127])
    return x, pairs, bound


def lcg_instance(seed=11, outputs=8, unknown_bits=40):
    rng = random.Random(seed)
    m, a, c = (1 << 64) - 59, 6364136223846793005, 1442695040888963407
    states = [rng.randrange(m)]
    for _ in range(outputs - 1):
        states.append((a * states[-1] + c) % m)
    return a, c, m, states, unknown_bits


# ------------------------------------------------------------------------------ bounded_linear

def test_bounded_linear_recovers_the_planted_solution_of_two_congruences():
    rng = random.Random(3)
    p = (1 << 61) - 1
    sol = [-656, 245567, 68]
    a = [[rng.randrange(p) for _ in range(3)] for _ in range(2)]
    b = [sum(c * v for c, v in zip(row, sol)) % p for row in a]
    bounds = [[-1000, 1000], [0, 1 << 20], [5, 99]]
    t = lt.bounded_linear(a, b, p, bounds)
    assert t.name == "bounded_linear" and t.dimension == 3 + 2 + 1 and len(t.basis[0]) == 3 + 2 + 1
    assert lt.solve(t, backend="python") == [sol]


def test_bounded_linear_mixes_integer_and_modular_equations():
    # x + y + z = 60 over the integers and 7x + 3y = 5 (mod 1009): planted (11, 20, 29)
    t = lt.bounded_linear([[1, 1, 1], [7, 3, 0]], [60, (77 + 60) % 1009], [None, 1009],
                          [[0, 31], [0, 31], [0, 31]])
    assert t.dimension == 3 + 1 + 1                          # one modulus row only
    found = lt.solve(t, backend="python")
    assert found and all(sum(x) == 60 and (7 * x[0] + 3 * x[1] - 137) % 1009 == 0 for x in found)
    assert all(0 <= v <= 31 for x in found for v in x)


def test_bounded_linear_extract_checks_bounds_and_equations_exactly():
    p = 1000003
    a, sol = [[3, 5], [7, 11]], [40, 9]                      # two congruences, two unknowns: one solution
    b = [sum(c * v for c, v in zip(row, sol)) % p for row in a]
    t = lt.bounded_linear(a, b, p, [[0, 100], [0, 100]])
    rows = reduced(t)
    assert t.extract(rows) == [sol]
    assert t.extract([]) == []                               # the centre (50, 50) is not a solution
    hit = next(r for r in rows if t.extract([r]))
    assert hit[2:4] == [0, 0] and abs(hit[4]) == 50          # equations exactly zero, the embedding +-W
    off = list(hit)
    off[0] += 1                                              # one unknown off by one: the equations fail
    assert t.extract([off]) == []
    assert t.extract([[-x for x in hit]]) == [sol]           # the sign of the row is free
    for column in (2, 3):
        kernel = list(hit)
        kernel[column] = 1                                   # an equation column is not zero
        assert t.extract([kernel]) == []
    assert t.extract([hit[:4] + [2 * hit[4]]]) == []         # not the embedding row
    sign = hit[4] // 50
    assert t.extract([[-sign * v for v in hit[:4]] + [0]]) == []         # the mirrored unknowns, no embedding
    tight = lt.bounded_linear(a, b, p, [[0, 39], [0, 100]])  # the same system with x = 40 out of bounds
    assert lt.solve(tight, backend="python") == []
    edge = lt.bounded_linear(a, b, p, [[0, 40], [9, 100]])   # both bounds are inclusive
    assert lt.solve(edge, backend="python") == [sol]


def test_bounded_linear_returns_the_centre_when_it_solves_the_system():
    t = lt.bounded_linear([[1, 1]], [10], None, [[0, 10], [0, 10]])
    assert t.extract([]) == [[5, 5]]


@pytest.mark.parametrize("args", [
    ([[1, 2]], [1, 2], 7, [[0, 1], [0, 1]]),                 # rhs length
    ([[1, 2]], [1], 7, [[0, 1]]),                            # bounds length
    ([[1, 2]], [1], 7, [[0, 1], [3, 2]]),                    # low above high
    ([[1, 2]], [1], 1, [[0, 1], [0, 1]]),                    # modulus below 2
    ([[1, 2]], [1], [7, 7], [[0, 1], [0, 1]]),               # moduli length
    ([[1, 2], [3]], [1, 2], 7, [[0, 1], [0, 1]]),            # ragged matrix
    ([], [], 7, []),                                         # no equation
    ([[1.5, 2]], [1], 7, [[0, 1], [0, 1]]),                  # not an integer
])
def test_bounded_linear_rejects_malformed_systems(args):
    with pytest.raises(lt.JobError):
        lt.bounded_linear(*args)


# -------------------------------------------------------------------------------- short_kernel

def test_modular_ratio_recovers_the_small_numerator_and_denominator():
    q = (1 << 89) - 1
    f, g = 180734720488, 440015909379
    h = g * pow(f, -1, q) % q
    t = lt.modular_ratio(h, q, 1 << 41, 1 << 41)
    assert t.name == "modular_ratio" and t.dimension == 3
    assert lt.solve(t, backend="python") == [[f, g]]
    assert lt.solve(lt.modular_ratio(h, q, 1 << 37, 1 << 41), backend="python") == []    # f is above 2^37


def test_integer_relation_finds_small_relations_and_normalises_their_sign():
    found = lt.solve(lt.integer_relation([6, 10, 15], 5), backend="python")
    assert found and all(6 * a + 10 * b + 15 * c == 0 for a, b, c in found)
    assert all(max(map(abs, rel)) <= 5 and next(v for v in rel if v) > 0 for rel in found)
    assert lt.solve(lt.integer_relation([6, 10, 15], 1), backend="python") == []         # none that small
    with pytest.raises(lt.JobError):
        lt.integer_relation([6], 5)


def test_short_kernel_extract_refuses_zero_wide_and_wrong_rows():
    t = lt.short_kernel([[6, 10, 15]], None, [5, 5, 5])
    assert t.extract([[0, 0, 0, 0]]) == []                   # the zero vector is not a relation
    assert t.extract([[5, -3, 0, 0], [-5, 3, 0, 0]]) == [[5, -3, 0]]     # found once, sign normalised
    assert t.extract([[5, -3, 1, 0]]) == []                  # 30 - 30 + 15 != 0
    assert t.extract([[10, -6, 0, 0]]) == []                 # a relation, but wider than the bound
    assert t.extract([[5, -3, 0, 7]]) == []                  # the equation column is not zero
    with pytest.raises(lt.JobError):
        lt.short_kernel([[1, 2]], None, [1, 0])


def test_short_kernel_scales_unknowns_of_different_width():
    # f*h = g (mod q) with f tiny and g wide: the unknowns are weighted by their bounds.
    q = (1 << 61) - 1
    f, g = 777, (1 << 39) + 12345
    h = g * pow(f, -1, q) % q
    t = lt.short_kernel([[h, -1]], [q], [1 << 10, 1 << 40])
    assert t.basis[0][0] == 1 << 30 and t.basis[1][1] == 1   # f is weighted up to the size of g
    assert lt.solve(t, backend="python") == [[f, g]]


# ------------------------------------------------------------------------------- hidden_number

def test_hidden_number_recovers_the_secret_from_small_nonces():
    x, pairs, bound = hnp_instance()
    t = lt.hidden_number(Q127, pairs, bound)
    assert t.name == "hidden_number" and t.dimension == len(pairs) + 2
    assert lt.solve(t, backend="python") == [x]


def test_hidden_number_extract_checks_every_inequality():
    x, pairs, bound = hnp_instance()
    t = lt.hidden_number(Q127, pairs, bound)
    rows = reduced(t)
    hit = next(r for r in rows if t.extract([r]))
    off = list(hit)
    off[len(pairs)] += t.basis[len(pairs)][len(pairs)]       # the secret moved by one
    assert t.extract([off]) == []
    assert t.extract([[-v for v in hit]]) == [x]
    assert t.extract([hit[:-1] + [0]]) == []                 # not the embedding row
    spoiled = [list(p) for p in pairs]
    spoiled[3][1] = (spoiled[3][1] + (1 << 110)) % Q127      # one sample no longer has a small nonce
    assert lt.hidden_number(Q127, spoiled, bound).extract(rows) == []


def test_hidden_number_honours_a_secret_bound():
    rng = random.Random(21)
    q, x, bound = Q127, 0xdeadbeefcafe, 1 << 110
    pairs = [[t, (rng.randrange(bound) - t * x) % q] for t in (rng.randrange(1, q) for _ in range(6))]
    assert lt.solve(lt.hidden_number(q, pairs, bound, secret_bound=1 << 48), backend="python") == [x]
    assert lt.solve(lt.hidden_number(q, pairs, bound, secret_bound=1 << 40), backend="python") == []
    assert lt.solve(lt.hidden_number(q, pairs, bound, secret_bound=x + 1), backend="python") == [x]
    assert lt.solve(lt.hidden_number(q, pairs, bound, secret_bound=x), backend="python") == []   # exclusive
    for bad in ((1, pairs, bound), (q, [], bound), (q, pairs, 0), (q, pairs, q + 1), (q, [[1]], bound)):
        with pytest.raises(lt.JobError):
            lt.hidden_number(*bad)
    with pytest.raises(lt.JobError):
        lt.hidden_number(q, pairs, bound, secret_bound=q + 1)


# ------------------------------------------------------------------------------- truncated_lcg

def test_truncated_lcg_recovers_the_first_state():
    a, c, m, states, u = lcg_instance()
    t = lt.truncated_lcg(a, c, m, [s >> u for s in states], u)
    assert t.name == "truncated_lcg" and t.dimension == len(states) + 1
    assert t.basis[0][0] == (1 << (u - 1)) * m               # the secret is the low bits: half-width 2^(u-1)
    assert t.basis[-1][-1] == 1 << (2 * (u - 1))             # and so is every unknown low part
    assert lt.solve(t, backend="python") == [states[0]]


def test_truncated_lcg_returns_nothing_when_an_output_does_not_fit():
    a, c, m, states, u = lcg_instance()
    highs = [s >> u for s in states]
    rows = reduced(lt.truncated_lcg(a, c, m, highs, u))
    wrong = list(highs)
    wrong[-1] ^= 1                                           # the last output is off by one
    assert lt.truncated_lcg(a, c, m, wrong, u).extract(rows) == []
    assert lt.truncated_lcg(a, c, m, highs, u).extract(rows) == [states[0]]
    assert lt.truncated_lcg(a + 2, c, m, highs, u).extract(rows) == []   # another generator
    for bad in ((a, c, 1, highs, u), (a, c, m, highs[:1], u), (a, c, m, highs, 0), (a, c, m, [-1, 2], u)):
        with pytest.raises(lt.JobError):
            lt.truncated_lcg(*bad)


def test_truncated_lcg_regenerates_the_outputs_before_it_returns_a_state():
    """With a power-of-two modulus an output raised by modulus >> unknown_bits gives the same lattice
    and the same inequalities; only regenerating the sequence shows that it cannot be an output."""
    rng = random.Random(64)
    m, a, c, u = 1 << 64, 6364136223846793005, 1442695040888963407, 40
    states = [rng.randrange(m)]
    for _ in range(7):
        states.append((a * states[-1] + c) % m)
    highs = [s >> u for s in states]
    t = lt.truncated_lcg(a, c, m, highs, u)
    rows = reduced(t)
    assert t.extract(rows) == [states[0]]
    lifted = list(highs)
    lifted[4] += m >> u
    again = lt.truncated_lcg(a, c, m, lifted, u)
    assert again.basis == t.basis and again.extract(rows) == []


def test_truncated_lcg_refuses_a_seed_equal_to_the_modulus():
    """highs[0] = m >> u with low bits m mod 2^u gives the candidate seed m itself: not a state (states
    are below m), although it regenerates exactly like state 0 and so fits every later output."""
    _, _, m, _, u = lcg_instance()
    a, c = 6364136223846793005, 1442695040888963407
    zero = [0]
    for _ in range(7):
        zero.append((a * zero[-1] + c) % m)
    highs = [m >> u] + [s >> u for s in zero[1:]]
    t = lt.truncated_lcg(a, c, m, highs, u)
    rows = reduced(t)
    assert t.extract(rows) == []
    assert lt.solve(t, backend="python") == []


# ---------------------------------------------------------------------------------- subset_sum

def test_subset_sum_finds_the_exact_selection():
    rng = random.Random(5)
    values = [rng.randrange(1, 1 << 40) for _ in range(12)]
    bits = [1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0]
    target = sum(v * b for v, b in zip(values, bits))
    t = lt.subset_sum(values, target)
    assert t.name == "subset_sum" and t.dimension == 13
    assert lt.solve(t, backend="python") == [bits]


def test_subset_sum_extract_accepts_only_an_exact_sum():
    t = lt.subset_sum([3, 5, 9], 12)                         # 3 + 9
    assert t.extract([[-1, 1, -1, 0]]) == [[1, 0, 1]]        # 2x - 1 with the sign flipped
    assert t.extract([[1, -1, 1, 0]]) == [[1, 0, 1]]
    assert t.extract([[1, 1, 1, 0]]) == []                   # 0 or 17, never 12
    assert t.extract([[-1, 1, -1, 3]]) == []                 # the sum column is not zero
    assert t.extract([[-1, 0, -1, 0]]) == []                 # not a +-1 vector
    assert lt.solve(lt.subset_sum([3, 5, 9], 4), backend="python") == []


# ------------------------------------------------------------------------- solving and backends

def test_solve_never_answers_a_bkz_request_with_lll(monkeypatch, tmp_path):
    monkeypatch.setattr(alg, "_has_module", lambda name: name != "fpylll")
    x, pairs, bound = hnp_instance()
    t = lt.hidden_number(Q127, pairs, bound)
    (tmp_path / "empty").mkdir()
    env = {"PATH": str(tmp_path / "empty"), "CTF_TESTING": "1", "HOME": str(tmp_path)}
    with pytest.raises(lt.BackendUnavailable) as ex:
        lt.solve(t, method="bkz", environ=env)
    assert "py:fpylll" in ex.value.needs_tool and "sage" in ex.value.needs_tool
    found, res = lt.solve_detailed(t, method="bkz", backend="python")
    assert found == [] and res.status == "blocked" and res.needs_tool == ("py:fpylll",)
    with pytest.raises(lt.JobError):
        lt.solve(t, method="hkz")
    with pytest.raises(lt.JobError):
        lt.solve(t, method="bkz", block_size=1)


def test_solve_runs_bkz_on_the_sage_image_with_a_clamped_block_size(tmp_path):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7")})
    x, pairs, bound = hnp_instance(samples=6)
    t = lt.hidden_number(Q127, pairs, bound)
    found, res = lt.solve_detailed(t, method="bkz", block_size=50, backend="sage-image", environ=env)
    assert found == [x] and res.ok and res.backend == "sage-image" and res.proof == "exact"
    assert stubs.calls(env, "fake") == [{"call": "BKZ", "block_size": t.dimension, "kw": {}}]
    lt.solve(t, method="bkz", block_size=4, tours=2, backend="sage-image", environ=env)
    assert stubs.calls(env, "fake")[-1] == {"call": "BKZ", "block_size": 4, "kw": {"max_loops": 2}}


def test_solve_raises_when_the_reduction_itself_failed(tmp_path):
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7"), "mode": "bad_basis"})
    t = lt.subset_sum([3, 5, 9], 12)
    with pytest.raises(lt.ServiceError, match="lattice check"):
        lt.solve(t, backend="sage-image", environ=env)
    found, res = lt.solve_detailed(t, backend="sage-image", environ=env)
    assert found == [] and res.status == "error"


def test_build_checks_the_template_name_and_arguments():
    t = lt.build("subset_sum", {"values": [3, 5, "0x9"], "target": "12"})
    assert t.name == "subset_sum" and t.basis[2][-1] == t.basis[0][-1] * 3
    assert sorted(lt.TEMPLATES) == ["bounded_linear", "hidden_number", "integer_relation", "modular_ratio",
                                    "short_kernel", "subset_sum", "truncated_lcg"]
    for name, args in (("knapsack", {}), ("subset_sum", {"values": [1]}),
                       ("subset_sum", {"values": [1], "target": 1, "extra": 2}), ("subset_sum", [1, 2])):
        with pytest.raises(lt.JobError):
            lt.build(name, args)
    assert lt.build("hidden_number", {"modulus": 101, "samples": [[3, 4]], "bound": 5}).dimension == 3


# --------------------------------------------------------------------------------------------- CLI

def write_job(tmp_path, job, name="job.json"):
    path = tmp_path / name
    path.write_text(json.dumps(job))
    return str(path)


def test_cli_list_basis_and_solve(tmp_path, capsys):
    assert lt.main(["list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert sorted(listed) == sorted(lt.TEMPLATES)
    assert listed["truncated_lcg"]["args"] == ["multiplier", "increment", "modulus", "highs", "unknown_bits"]
    assert listed["subset_sum"]["what"].startswith("0/1 choices")
    a, c, m, states, u = lcg_instance()
    job = write_job(tmp_path, {"template": "truncated_lcg", "args": {
        "multiplier": a, "increment": c, "modulus": hex(m), "highs": [s >> u for s in states],
        "unknown_bits": u}})
    assert lt.main(["basis", job]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["template"] == "truncated_lcg" and shown["dimension"] == len(shown["basis"]) == 9
    assert lt.main(["solve", job, "--backend", "python"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["solutions"] == [states[0]] and out["status"] == "ok" and out["backend"] == "python"
    assert out["method"] == "lll" and out["proof"] == "exact" and out["dimension"] == 9


def test_cli_exit_codes(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(alg, "_has_module", lambda name: name != "fpylll")
    job = write_job(tmp_path, {"template": "subset_sum", "args": {"values": [3, 5, 9], "target": 12}})
    assert lt.main(["solve", job, "--method", "bkz", "--backend", "python"]) == 3
    blocked = json.loads(capsys.readouterr().out)
    assert blocked["status"] == "blocked" and blocked["solutions"] == [] and blocked["proof"] == "none"
    assert blocked["needs_tool"] == ["py:fpylll"]
    env = stubs.docker_stub(tmp_path, {"images": stubs.built("10.7"), "mode": "bad_transform"})
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert lt.main(["solve", job, "--backend", "sage-image"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "error"
    bad = write_job(tmp_path, {"template": "subset_sum", "args": {"values": [3]}}, "bad.json")
    extra = write_job(tmp_path, {"template": "subset_sum", "args": {"values": [3], "target": 3}, "x": 1}, "x.json")
    for argv in ([], ["solve"], ["solve", bad], ["basis", extra], ["solve", job, "--method", "hkz"],
                 ["basis", str(tmp_path / "absent.json")]):
        assert lt.main(argv) == 2
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err.startswith("lattice_templates: ")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
