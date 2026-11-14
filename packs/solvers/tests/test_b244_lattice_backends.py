"""B-244: the faster lattice backends (gmpy2 exact LLL, optional fpylll) and their wiring into
rsa_lattice (reducer hook, Boneh-Durfee ladder). Deadlines count CPU seconds (tests/loadclock)."""
from __future__ import annotations

import json
import math
import random
import sys
import types

import pytest

import lattice_backends as LB
import loadclock
import rsa_lattice as R


def _prime(rng, bits):
    import sympy
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if sympy.isprime(c):
            return c


def _bd_key(rng, bits, delta):
    p, q = _prime(rng, bits // 2), _prime(rng, bits // 2)
    n, phi = p * q, (p - 1) * (q - 1)
    nb = int(bits * delta)
    while True:
        d = rng.getrandbits(nb) | 1 | (1 << (nb - 1))
        if math.gcd(d, phi) == 1:
            return n, pow(d, -1, phi), d, p, q


def _coppersmith_basis(rng, bits=256, m=4, t=4):
    """A Howgrave-Graham basis with big entries (the shape the RSA attacks reduce)."""
    n = _prime(rng, bits // 2) * _prime(rng, bits // 2)
    a0 = rng.randrange(n)
    X = 1 << (bits // 5)
    f = [a0, 1]
    pw = [[1]]
    for _ in range(m):
        pw.append(R._pmul(pw[-1], f))
    rows = [[c * n ** (m - i) for c in pw[i]] for i in range(m)] + [[0] * j + pw[m] for j in range(t)]
    w = m + t
    return [[(r[k] if k < len(r) else 0) * X ** k for k in range(w)] for r in rows]


# ---- exact LLL on gmpy2 integers --------------------------------------------------------------------------

def test_gmpy2_lll_is_bit_identical_to_python_int_lll():
    rng = random.Random(244)
    for dim in (2, 3, 5, 8):
        rows = [[rng.randrange(-10 ** 6, 10 ** 6) for _ in range(dim + 1)] for _ in range(dim)]
        assert R.lll(rows, arith="gmpy2") == R.lll(rows, arith="python-int")
    big = _coppersmith_basis(rng)
    a, b = R.lll(big, arith="gmpy2"), R.lll(big, arith="python-int")
    assert a == b
    assert all(type(x) is int for row in a for x in row)          # callers get Python ints back


def test_gmpy2_is_the_default_and_much_cheaper_in_cpu_time():
    assert R.LLL_ARITHMETIC == "gmpy2"
    rows = _coppersmith_basis(random.Random(7), bits=384, m=4, t=3)
    _, slow = loadclock.cpu_seconds(R.lll, rows, arith="python-int")
    _, fast = loadclock.cpu_seconds(R.lll, rows, arith="gmpy2")
    assert fast < slow / 2, (fast, slow)


def test_lll_arith_is_validated_and_never_silently_downgraded(monkeypatch):
    with pytest.raises(ValueError, match="arith"):
        R.lll([[1, 0], [0, 1]], arith="float")
    monkeypatch.setattr(R, "_mpz", None)
    with pytest.raises(RuntimeError, match="gmpy2"):
        R.lll([[1, 0], [0, 1]], arith="gmpy2")


def test_dependent_rows_still_decline_on_both_arithmetics():
    for arith in R.ARITHMETICS:
        assert R.lll([[1, 2, 3], [2, 4, 6]], arith=arith) is None


# ---- backend selection --------------------------------------------------------------------------------------

def _fake_have(monkeypatch, **present):
    monkeypatch.setattr(LB, "_has", lambda name: present.get(name, False))


def test_auto_picks_the_fastest_present_backend(monkeypatch):
    _fake_have(monkeypatch, gmpy2=True)
    assert LB.resolve_backend("auto") == "gmpy2"
    _fake_have(monkeypatch, gmpy2=True, fpylll=True)
    assert LB.resolve_backend("auto") == "fpylll"
    _fake_have(monkeypatch)
    assert LB.resolve_backend("auto") == "python"


def test_explicit_fpylll_without_it_fails_loudly_naming_the_tool(monkeypatch):
    _fake_have(monkeypatch, gmpy2=True)
    with pytest.raises(LB.BackendUnavailable) as err:
        LB.make_reducer("fpylll")
    assert err.value.tool == "py:fpylll" and "B-188" in str(err.value)
    with pytest.raises(LB.BackendUnavailable, match="py:gmpy2"):
        _fake_have(monkeypatch)
        LB.resolve_backend("gmpy2")
    with pytest.raises(ValueError, match="LLL backend"):
        LB.resolve_backend("ntl")


def test_reduce_lattice_backend_and_cli_exit_code(monkeypatch, tmp_path, capsys):
    res = LB.reduce_lattice([[105, 821, 37], [12, 93, 41]], method="lll", backend="gmpy2")
    assert res.lattice_verified and res.backend == "in-repo exact integer LLL (gmpy2)"
    assert res.basis == LB.reduce_lattice([[105, 821, 37], [12, 93, 41]], method="lll").basis
    _fake_have(monkeypatch, gmpy2=True)
    with pytest.raises(LB.BackendUnavailable):
        LB.reduce_lattice([[1, 0], [0, 1]], method="lll", backend="fpylll")
    doc = tmp_path / "in.json"
    doc.write_text(json.dumps({"basis": [[1, 0], [0, 1]], "backend": "fpylll"}))
    assert LB.main(["reduce", str(doc)]) == 3
    assert "py:fpylll" in capsys.readouterr().err
    status = LB.backend_status()
    assert status["lll_backends"]["fpylll"] is False and status["lll_auto"] == "gmpy2"


def test_fpylll_dispatch_converts_and_moves_zero_rows_last(monkeypatch):
    """fpylll is absent here, so a stand-in module records what the dispatch hands it; the real
    library is exercised by test_fpylll_real_reduction below when it is installed."""
    seen = {}

    class Matrix:
        def __init__(self, rows):
            self.rows = rows
            self.nrows, self.ncols = len(rows), len(rows[0])

        @classmethod
        def from_matrix(cls, rows, int_type=None):
            seen["int_type"] = int_type
            seen["types"] = {type(x) for r in rows for x in r}
            return cls([list(r) for r in rows])

        def __getitem__(self, ij):
            return self.rows[ij[0]][ij[1]]

    class FakeLLL:
        @staticmethod
        def reduction(matrix):
            seen["reduced"] = True
            matrix.rows = [[0, 0, 0], [1, 2, 3], [0, 0, 0], [4, 5, 6]]
            matrix.nrows = 4

    monkeypatch.setitem(sys.modules, "fpylll", types.SimpleNamespace(IntegerMatrix=Matrix, LLL=FakeLLL))
    red = LB.make_reducer("fpylll")
    assert red.backend == "fpylll"
    import gmpy2
    out = red([[gmpy2.mpz(1), 2, 3], [4, 5, 6]])
    assert seen == {"int_type": "mpz", "types": {int}, "reduced": True}
    assert out == [[1, 2, 3], [4, 5, 6], [0, 0, 0], [0, 0, 0]]
    assert red.calls == 1


@pytest.mark.needs_tool("py:fpylll")
def test_fpylll_real_reduction():
    rows = _coppersmith_basis(random.Random(3))
    red = LB.make_reducer("fpylll")(rows)
    ref = R.lll(rows)
    assert LB._same_row_lattice(rows, red)
    assert sum(x * x for x in red[0]) <= 2 ** len(rows) * sum(x * x for x in ref[0])


def test_reducer_gmpy2_really_reduces_on_gmpy2_integers(monkeypatch):
    """The backend name in a run record must match the arithmetic that ran: Reducer('gmpy2') and
    reduce_lattice(backend='gmpy2') convert the basis to gmpy2.mpz (rsa_lattice._mpz), and the
    Python-int backend never does. The real conversion function is wrapped, not replaced."""
    import gmpy2
    converted = []

    def counting_mpz(x):
        converted.append(1)
        return gmpy2.mpz(x)

    monkeypatch.setattr(R, "_mpz", counting_mpz)
    rows = [[105, 821, 37], [12, 93, 41]]
    want = R.lll(rows, arith="python-int")
    assert converted == []

    fast = LB.make_reducer("gmpy2")
    assert fast(rows) == want and len(converted) == 6        # every entry went through gmpy2.mpz
    converted.clear()
    res = LB.reduce_lattice(rows, method="lll", backend="gmpy2")
    assert res.backend.endswith("(gmpy2)") and len(converted) == 6
    converted.clear()
    assert LB.make_reducer("python")(rows) == want and converted == []
    assert LB.reduce_lattice(rows, method="lll", backend="python").backend == "in-repo exact integer LLL"
    assert converted == []


def test_reducer_deadline_is_checked_before_reducing():
    red = LB.make_reducer("python")
    assert red([[1, 0], [0, 1]], deadline=-1.0) is None
    assert red.calls == 1


# ---- the reducer hook in rsa_lattice --------------------------------------------------------------------------

def test_coppersmith_uses_the_given_reducer():
    rng = random.Random(11)
    p, q = _prime(rng, 64), _prime(rng, 64)
    n = p * q
    known = p >> 20
    f = [known << 20, 1]
    red = LB.make_reducer("gmpy2")
    roots = R.coppersmith_roots(f, n, 1 << 20, 0.5, reducer=red)
    assert red.calls >= 1
    assert any(R._peval(f, r) == p for r in roots)
    # a reducer that finds nothing gives no candidates (the hook really replaces the LLL)
    assert R.coppersmith_roots(f, n, 1 << 20, 0.5, m=3, reducer=lambda rows, dl: None) == []


def test_boneh_durfee_with_reducer_and_ladder_verify_the_key():
    rng = random.Random(26)
    n, e, d, p, q = _bd_key(rng, 256, 0.25)
    red = LB.make_reducer("gmpy2")
    with loadclock.cpu_clock():
        got = R.boneh_durfee_ladder(n, e, delta=0.26, ms=(4,), deadline=R.time.monotonic() + 60, reducer=red)
    assert got == (d, min(p, q), max(p, q))
    assert red.calls == 1
    assert R.boneh_durfee(n, e, delta=0.26, m=4, t=2, reducer=lambda rows, dl: None) is None


def test_ladder_stops_at_the_deadline_without_reducing():
    rng = random.Random(5)
    n, e, *_ = _bd_key(rng, 256, 0.25)
    calls = []
    assert R.boneh_durfee_ladder(n, e, deadline=-1.0, reducer=lambda r, dl: calls.append(1)) is None
    assert calls == []


def test_ladder_grows_m_until_one_succeeds():
    rng = random.Random(26)
    n, e, d, *_ = _bd_key(rng, 256, 0.25)
    ms = []

    def reducer(rows, dl):
        ms.append(len(rows))
        return R.lll(rows, deadline=dl)

    got = R.boneh_durfee_ladder(n, e, delta=0.26, ms=(2, 4), reducer=reducer)
    assert got is not None and got[0] == d
    assert len(ms) == 2 and ms[0] < ms[1]                   # m=2 tried first, then the larger lattice


def test_512_bit_boneh_durfee_at_n_026_finishes_in_cpu_budget():
    """The reach row 525 asked for: a 512-bit key with d ~ n^0.26 (beyond Wiener) recovered with the
    in-repo exact LLL on gmpy2 inside 40 CPU seconds (the Python-int LLL alone takes about 40 s on this
    lattice before any root finding)."""
    rng = random.Random(512)
    n, e, d, *_ = _bd_key(rng, 512, 0.26)
    with loadclock.cpu_clock():
        got = R.boneh_durfee(n, e, delta=0.265, m=4, t=2, deadline=R.time.monotonic() + 40)
    assert got is not None and got[0] == d
