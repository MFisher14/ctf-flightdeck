"""B-244: ROCA (CVE-2017-15361) key recovery beyond detection (solvers/common/roca.py).

Keys are synthetic Infineon-form moduli built in each test (roca_like_prime); no real key is used.
A 512-bit RSALib-size key runs the paper's parameters for single lattice steps; the whole search on
toy keys. Deadlines count CPU seconds (tests/loadclock)."""
from __future__ import annotations

import json
import math
import random

import pytest

import lattice_backends as LB
import loadclock
import roca
import rsa_lattice as R


def _prime(rng, bits):
    import sympy
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if sympy.isprime(c):
            return c


def _key(seed, bits, n_primes):
    rng = random.Random(seed)
    ap, aq = rng.randrange(1, 10 ** 9), rng.randrange(1, 10 ** 9)
    p = roca.roca_like_prime(bits // 2, n_primes, ap, rng)
    q = roca.roca_like_prime(bits // 2, n_primes, aq, rng)
    return p * q, p, q, ap, aq


def _hits(pl, ap, aq):
    """The exponents a' in the plan's search range that give a factor (p's or q's exponent mod ord')."""
    want = {ap % pl.order, aq % pl.order}
    return [a for a in range(pl.a_lo, pl.a_hi + 1) if a % pl.order in want]


# a toy key: 128-bit n, M of the first 14 primes, lattice m=3 t=4 (finishes in about a second of CPU)
TOY = dict(n_primes=14, m=3, t=4)


@pytest.fixture(scope="module")
def toy():
    n, p, q, ap, aq = _key(1, 128, 14)
    pl = roca.plan(n, **TOY)
    return n, p, q, ap, aq, pl


@pytest.fixture(scope="module")
def key512():
    n, p, q, ap, aq = _key(512, 512, 39)
    return n, p, q, ap, aq, roca.plan(n)


# ---- parameters -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bits, want", [
    (512, (39, 5, 6)), (511, (39, 5, 6)), (960, (39, 5, 6)), (1024, (71, 4, 5)), (2048, (126, 6, 7)),
    (4096, (225, 25, 26)), (480, None), (8192, None)])
def test_paper_parameter_table(bits, want):
    assert roca.paper_params(bits) == want


def test_x_bound_is_where_howgrave_graham_stops_holding():
    """log2 det / w < (m/2) log2 N - log2(sqrt w), det = N^(m(m+1)/2) X^(w(w-1)/2): true just below the
    bound x_bound_bits returns, false just above."""
    for nbits, m, t in ((512, 5, 6), (1024, 4, 5), (128, 3, 4)):
        xb = roca.x_bound_bits(nbits, m, t)
        w = m + t

        def holds(xbits):
            log_det = nbits * m * (m + 1) / 2 + xbits * w * (w - 1) / 2
            return log_det / w < m / 2 * nbits - math.log2(w) / 2

        assert holds(xb - 0.01) and not holds(xb + 0.01)
    with pytest.raises(ValueError):
        roca.x_bound_bits(512, 0, 6)


def test_optimise_keeps_a_divisor_large_enough_with_a_smaller_order():
    primes = roca.PRIMES[:39]
    full_order = roca._lcm(roca._order(65537, p) for p in primes)
    kept = roca.optimise(primes, 142.0)
    assert set(kept) < set(primes)
    assert sum(math.log2(p) for p in kept) >= 142.0
    order = roca._lcm(roca._order(65537, p) for p in kept)
    assert order * 1000 < full_order                          # the point of M': far fewer steps
    # asking for more bits than M has keeps every prime
    assert roca.optimise(primes, 10_000.0) == sorted(primes)


def test_plan_on_a_512_bit_rsalib_key_uses_the_paper_parameters(key512):
    n, p, q, ap, aq, pl = key512
    assert (pl.source, pl.n_primes, pl.m, pl.t) == ("paper", 39, 5, 6)
    assert math.prod(roca.PRIMES[:39]) % pl.mprime == 0
    # the discrete log is right: 65537^c == n mod M', and c == a + b mod ord'
    assert pow(65537, pl.c, pl.mprime) == n % pl.mprime
    assert pl.c == (ap + aq) % pl.order
    # the search range holds one of the two exponents, and it is ord'/2 wide (the attack's work)
    assert _hits(pl, ap, aq)
    assert pl.steps == pl.a_hi - pl.a_lo + 1 and abs(pl.steps - pl.order // 2) <= 1
    # the unknown part of p (k < 2^x_bits) is inside the Howgrave-Graham bound
    assert pl.x_bits <= roca.x_bound_bits(n.bit_length(), pl.m, pl.t)
    assert (p - pow(65537, ap, pl.mprime)) // pl.mprime < (1 << pl.x_bits)


def _order_by_brute_force(g, primes):
    """ord of g modulo prod(primes), computed here without roca's helpers."""
    out = 1
    for p in primes:
        k, x = 1, g % p
        while x != 1:
            x, k = x * g % p, k + 1
        out = out * k // math.gcd(out, k)
    return out


def _range_hit(primes, ap, aq):
    """The exponent the paper's range argument points at, from the key's own exponents: with
    a = ap mod ord', b = aq mod ord' and c' = (a + b) mod ord', a + b is c' or c' + ord'. In the first
    case max(a, b) lies in [c'/2, c']; in the second min(a, b) lies in [c' + 1, (c' + ord')/2]."""
    order = _order_by_brute_force(roca.GENERATOR, primes)
    a, b = ap % order, aq % order
    c = (a + b) % order
    hit = max(a, b) if a + b == c else min(a, b)
    return hit, c, order


def _equal_exponent_key(seed, a):
    """A toy key whose two primes share the exponent a: the range argument's boundary case a == b."""
    rng = random.Random(seed)
    p = roca.roca_like_prime(64, 14, a, rng)
    q = p
    while q == p:
        q = roca.roca_like_prime(64, 14, a, rng)
    return p * q, p, q


@pytest.mark.parametrize("fixture", ["toy", "key512"])
def test_search_range_holds_the_exponent_by_an_independent_count(fixture, request):
    n, p, q, ap, aq, pl = request.getfixturevalue(fixture)
    hit, c, order = _range_hit(pl.mprime_primes, ap, aq)
    assert (pl.order, pl.c) == (order, c)
    assert pl.a_lo <= hit <= pl.a_hi
    assert pow(roca.GENERATOR, hit, pl.mprime) in (p % pl.mprime, q % pl.mprime)


@pytest.mark.parametrize("side", ["low", "high"])
def test_equal_exponents_sit_on_the_range_edge_and_are_found(toy, side):
    """a == b mod ord' puts the only right a' exactly on an end of [c'/2, (c'+ord')/2]: on a_lo when
    2a < ord' (c' = 2a), on a_hi when 2a >= ord' (c' = 2a - ord'). The search must include both ends."""
    toy_plan = toy[-1]
    order = _order_by_brute_force(roca.GENERATOR, toy_plan.mprime_primes)
    a = order // 4 + 7 if side == "low" else order - order // 4
    n, p, q = _equal_exponent_key(40 if side == "low" else 41, a)
    pl = roca.plan(n, **TOY)
    assert pl.mprime_primes == toy_plan.mprime_primes
    hit, c, _ = _range_hit(pl.mprime_primes, a, a)
    assert hit == a % order and c == (2 * a) % order
    assert hit == (c // 2 if side == "low" else (c + order) // 2)
    with loadclock.cpu_clock():
        run = roca.factor(n, pl, reducer=LB.make_reducer("gmpy2"), deadline=R.time.monotonic() + 120)
    assert run.factors == tuple(sorted((p, q)))
    assert run.tried == (1 if side == "low" else pl.steps)


def test_attempt_reads_past_a_useless_first_reduced_vector(toy):
    """A reducer may put a lattice vector without the small root first (fplll's ordering differs from
    the in-repo LLL); attempt still reads the next one. The stand-in first vector is the basis row
    N^m, a constant polynomial with no root."""
    n, p, q, ap, aq, pl = toy
    a = _hits(pl, ap, aq)[0]

    def junk_first(rows, deadline):
        return [rows[0]] + R.lll(rows, deadline=deadline)

    assert roca.attempt(n, pl, a, reducer=junk_first) == tuple(sorted((p, q)))


def test_a_modulus_of_another_form_is_not_roca():
    rng = random.Random(4)
    n = _prime(rng, 256) * _prime(rng, 256)
    with pytest.raises(roca.NotRocaForm):
        roca.plan(n)
    assert roca.dlog(n, roca.PRIMES[:39]) is None


@pytest.mark.parametrize("bad", [13, 2 ** 40, -15, (1 << 9000) | 1, 15.0])
def test_plan_rejects_unusable_moduli(bad):
    with pytest.raises(ValueError):
        roca.plan(bad)


def test_plan_off_the_table_needs_explicit_parameters(toy):
    n = toy[0]
    with pytest.raises(ValueError, match="pass n_primes, m and t"):
        roca.plan(n)
    with pytest.raises(ValueError, match="too small"):
        roca.plan(n, n_primes=3, m=3, t=4)


def test_roca_like_prime_has_the_infineon_form():
    rng = random.Random(9)
    p = roca.roca_like_prime(128, 20, 12345, rng)
    M = math.prod(roca.PRIMES[:20])
    import sympy
    assert p.bit_length() == 128 and sympy.isprime(p) and p % M == pow(65537, 12345, M)
    with pytest.raises(ValueError):
        roca.roca_like_prime(64, 20, 1, rng)


# ---- the lattice step and the search ------------------------------------------------------------------------

def test_one_step_recovers_a_512_bit_rsalib_key_at_the_right_exponent(key512):
    """The full-size attack's lattice step (dimension 11, paper parameters) with the in-repo gmpy2 LLL:
    the right a' factors the key, the next one does not."""
    n, p, q, ap, aq, pl = key512
    a = _hits(pl, ap, aq)[0]
    red = LB.make_reducer("gmpy2")
    assert roca.attempt(n, pl, a, reducer=red) == tuple(sorted((p, q)))
    wrong = next(x for x in (a + 1, a - 1) if x not in _hits(pl, ap, aq))
    assert roca.attempt(n, pl, wrong, reducer=red) is None
    assert red.calls == 2


def test_full_search_on_a_toy_key_finds_the_factors(toy):
    n, p, q, ap, aq, pl = toy
    first = _hits(pl, ap, aq)[0]
    calls = []

    def reducer(rows, deadline):
        calls.append(len(rows))
        return R.lll(rows, deadline=deadline)

    with loadclock.cpu_clock():
        run = roca.factor(n, pl, reducer=reducer, deadline=R.time.monotonic() + 120)
    assert run.factors == tuple(sorted((p, q)))
    assert run.tried == first - pl.a_lo + 1 == len(calls)       # stopped at the first right exponent
    assert set(calls) == {pl.m + pl.t}
    assert run.next_a == first + 1 and run.done is False
    assert run.plan["order"] == pl.order


def test_default_reducer_is_the_in_repo_lll(toy):
    n, p, q, ap, aq, pl = toy
    a = _hits(pl, ap, aq)[0]
    run = roca.factor(n, pl, a_start=a, a_stop=a + 1)
    assert run.factors == tuple(sorted((p, q))) and run.backend == "in-repo exact LLL"


def test_chunks_resume_and_a_chunk_without_the_exponent_ends_done(toy):
    n, p, q, ap, aq, pl = toy
    hits = _hits(pl, ap, aq)
    start = next(a for a in range(pl.a_lo, pl.a_hi - 6) if not any(a <= h < a + 6 for h in hits))
    red = LB.make_reducer("gmpy2")
    miss = roca.factor(n, pl, a_start=start, a_stop=start + 6, reducer=red)
    assert (miss.factors, miss.tried, miss.next_a, miss.done) == (None, 6, start + 6, True)
    assert miss.backend == "gmpy2"
    got = roca.factor(n, pl, a_start=hits[0] - 2, a_stop=hits[0] + 3, reducer=red)
    assert got.factors == tuple(sorted((p, q))) and got.tried == 3


def test_a_passed_deadline_stops_before_any_lattice(toy):
    n, *_, pl = toy
    calls = []
    run = roca.factor(n, pl, reducer=lambda rows, dl: calls.append(1), deadline=-1.0)
    assert (run.factors, run.tried, run.next_a, run.done) == (None, 0, pl.a_lo, False)
    assert calls == []


def test_a_reducer_that_finds_nothing_gives_no_factor(toy):
    n, p, q, ap, aq, pl = toy
    a = _hits(pl, ap, aq)[0]
    assert roca.attempt(n, pl, a, reducer=lambda rows, dl: None) is None
    # a reduction returning the unreduced basis gives a vector that is not a small-root polynomial
    assert roca.attempt(n, pl, a, reducer=lambda rows, dl: rows) is None


def test_bad_chunk_bounds_are_refused(toy):
    n, *_, pl = toy
    with pytest.raises(ValueError):
        roca.factor(n, pl, a_start=10, a_stop=5)
    with pytest.raises(ValueError):
        roca.factor(n, pl, a_start=-1, a_stop=5)


def test_progress_is_reported_every_256_steps(toy):
    n, p, q, ap, aq, pl = toy
    hits = set(_hits(pl, ap, aq))
    start = next(a for a in range(pl.a_lo, pl.a_hi) if not any(a <= h < a + 300 for h in hits))
    seen = []
    roca.factor(n, pl, a_start=start, a_stop=start + 300, reducer=lambda rows, dl: None,
                progress=lambda a, tried: seen.append((a, tried)))
    assert seen == [(start + 255, 256)]


def test_root_finder_returns_integer_roots_only():
    # (x - 3)(x - 10)(x + 4) = x^3 - 9x^2 - 22x + 120, plus a polynomial with no integer root
    assert roca._int_roots_in([120, -22, -9, 1], 0, 100) == [3, 10]
    assert roca._int_roots_in([-2, 0, 1], 0, 100) == []                 # sqrt 2
    assert roca._int_roots_in([0, 1], 0, 5) == [0]


# ---- CLI ------------------------------------------------------------------------------------------------------

def test_cli_plan_and_factor(toy, capsys, monkeypatch):
    n, p, q, ap, aq, pl = toy
    args = ["--n-primes", "14", "--m", "3", "--t", "4"]
    assert roca.main(["plan", hex(n)] + args) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["steps"] == pl.steps and info["order"] == pl.order
    a = _hits(pl, ap, aq)[0]
    assert roca.main(["factor", str(n), "--backend", "gmpy2", "--a-start", str(a), "--a-stop", str(a + 1)] + args) == 0
    out = json.loads(capsys.readouterr().out)
    assert {int(out["p"]), int(out["q"])} == {p, q} and out["verified"] and out["backend"] == "gmpy2"
    hits = _hits(pl, ap, aq)
    start = next(x for x in range(pl.a_lo, pl.a_hi) if not any(x <= h < x + 2 for h in hits))
    assert roca.main(["factor", str(n), "--a-start", str(start), "--a-stop", str(start + 2)] + args) == 1
    assert json.loads(capsys.readouterr().out) == {"tried": 2, "next_a": start + 2, "done": True,
                                                   "backend": LB.resolve_backend("auto")}


def test_cli_missing_fpylll_and_bad_input_exit_codes(toy, capsys, monkeypatch):
    n = toy[0]
    monkeypatch.setattr(LB, "_has", lambda name: name == "gmpy2")
    assert roca.main(["factor", str(n), "--n-primes", "14", "--m", "3", "--t", "4", "--backend", "fpylll"]) == 3
    assert "py:fpylll" in capsys.readouterr().err
    rng = random.Random(4)
    plain = _prime(rng, 256) * _prime(rng, 256)
    assert roca.main(["plan", str(plain)]) == 1
    assert "not the RSALib form" in capsys.readouterr().err
    assert roca.main(["plan", str(n)]) == 2
    assert "pass n_primes" in capsys.readouterr().err


@pytest.mark.needs_tool("py:fpylll")
def test_fpylll_reducer_runs_the_512_bit_step(key512):
    n, p, q, ap, aq, pl = key512
    a = _hits(pl, ap, aq)[0]
    assert roca.attempt(n, pl, a, reducer=LB.make_reducer("fpylll")) == tuple(sorted((p, q)))
