"""Lattice and partial-key RSA attacks (pure Python; sympy only for integer polynomial roots).

  coppersmith_roots(coeffs, N, X, beta)   small roots |x| <= X of f(x) = 0 mod b, b | N, b >= N^beta
  stereotyped_message(n, e, c, ...)       a message with a known prefix / suffix and a short unknown part
  partial_prime(n, known, ...)            n's factor p when its high or low bits are known
  boneh_durfee(n, e, ...)                 small private exponent beyond Wiener's bound
  roca_fingerprint(n)                     the CVE-2017-15361 test (a modulus of the Infineon form)
  roca_factor(n, ...)                     recovery, only where the search is small enough to finish
  boneh_durfee_ladder(n, e, ...)          boneh_durfee over growing m until a deadline (B-244)

The one rule (AGENTS.md "Uncertain answers"): a function returns a value ONLY after verifying it in
code: p*q == n with both factors above 1 (and n % p == 0), d*e == 1 mod phi AND a random message
round-trips, or pow(m, e, n) == c for a recovered message. Anything unverified is None. Every attack
takes a `deadline` (time.monotonic()) and gives up with None when it passes: LLL is checked once per
reduction step, so a cap holds. No file, network or clock beyond that.

Not covered here, said plainly: real ROCA keys (512 to 2048 bit) need the optimised Coppersmith search
of the original paper (CPU-hours to CPU-years); roca_factor finishes only on toy-sized Infineon-form
moduli and returns None otherwise, while roca_fingerprint detects the real thing at any size. The
paper's search (greedy M', resumable chunks, fpylll when built) is solvers/common/roca.py (B-244).

Faster reduction (B-244): lll() runs on gmpy2 integers when they import (bit-identical, much cheaper),
and coppersmith_roots / boneh_durfee take `reducer=` (lattice_backends.make_reducer: fpylll when
built); boneh_durfee_ladder grows m to a deadline.
"""
from __future__ import annotations

import math
import random
import time

# ---- exact integer LLL (Cohen, algorithm 2.6.7) ------------------------------------------------------
#
# B-244: the same exact algorithm runs on GMP integers (gmpy2, a pinned requirement) when they import.
# Every step is an exact integer operation, so the reduced basis is bit-identical to the Python-int run
# (tests/test_b244_lattice_backends.py proves it); only the big-number arithmetic is faster (about 10x on
# a 512-bit Boneh-Durfee lattice). LLL_ARITHMETIC names what runs; lll(..., arith=...) picks one, and
# asking for "gmpy2" without gmpy2 raises instead of quietly running the slower path.

try:
    from gmpy2 import mpz as _mpz
except ImportError:                         # pragma: no cover - gmpy2 is pinned in requirements.in
    _mpz = None

ARITHMETICS = ("gmpy2", "python-int")
LLL_ARITHMETIC = "gmpy2" if _mpz is not None else "python-int"


def lll(rows, delta=(99, 100), deadline=None, arith=None):
    """LLL-reduced copy of an integer basis (a list of rows, linearly independent), or None when the
    deadline passes first. Exact integer arithmetic; `arith` ("gmpy2" / "python-int", default
    LLL_ARITHMETIC) picks the integer type, never the result. The rows returned are Python ints."""
    arith = LLL_ARITHMETIC if arith is None else arith
    if arith not in ARITHMETICS:
        raise ValueError(f"arith must be one of {ARITHMETICS}, got {arith!r}")
    if arith == "gmpy2":
        if _mpz is None:
            raise RuntimeError("lll(arith='gmpy2') needs py:gmpy2, which does not import here")
        out = _lll_exact([[_mpz(x) for x in r] for r in rows], delta, deadline)
        return None if out is None else [[int(x) for x in r] for r in out]
    return _lll_exact(rows, delta, deadline)


def _lll_exact(rows, delta, deadline):
    b = [list(r) for r in rows]
    n = len(b)
    if n == 0:
        return b
    dn, dd = delta
    lam = [[0] * n for _ in range(n)]
    d = [0] * (n + 1)
    d[0] = 1
    d[1] = sum(x * x for x in b[0])
    if d[1] == 0:
        return None

    def dot(u, v):
        return sum(x * y for x, y in zip(u, v))

    def red(k, l):
        if 2 * abs(lam[k][l]) > d[l + 1]:
            q = (2 * lam[k][l] + d[l + 1]) // (2 * d[l + 1])
            bk, bl = b[k], b[l]
            for i in range(len(bk)):
                bk[i] -= q * bl[i]
            lam[k][l] -= q * d[l + 1]
            for i in range(l):
                lam[k][i] -= q * lam[l][i]

    def swap(k, kmax):
        b[k], b[k - 1] = b[k - 1], b[k]
        for j in range(k - 1):
            lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
        l_ = lam[k][k - 1]
        B = (d[k - 1] * d[k + 1] + l_ * l_) // d[k]
        for i in range(k + 1, kmax + 1):
            t = lam[i][k]
            lam[i][k] = (d[k + 1] * lam[i][k - 1] - l_ * t) // d[k]
            lam[i][k - 1] = (B * t + l_ * lam[i][k]) // d[k + 1]
        d[k] = B

    k, kmax = 1, 0
    steps = 0
    while k < n:
        steps += 1
        if deadline is not None and steps % 8 == 0 and time.monotonic() > deadline:
            return None
        if k > kmax:
            kmax = k
            for j in range(k + 1):
                u = dot(b[k], b[j])
                for i in range(j):
                    u = (d[i + 1] * u - lam[k][i] * lam[j][i]) // d[i]
                if j < k:
                    lam[k][j] = u
                else:
                    if u == 0:
                        return None         # dependent rows
                    d[k + 1] = u
        red(k, k - 1)
        if dd * d[k + 1] * d[k - 1] < dn * d[k] * d[k] - dd * lam[k][k - 1] ** 2:
            swap(k, kmax)
            k = max(1, k - 1)
        else:
            for l in range(k - 2, -1, -1):
                red(k, l)
            k += 1
    return b


# ---- integer polynomials (coefficient lists, lowest degree first) --------------------------------------

def _pmul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] += x * y
    return out


def _ppow(a, k):
    out = [1]
    for _ in range(k):
        out = _pmul(out, a)
    return out


def _peval(a, x):
    r = 0
    for c in reversed(a):
        r = r * x + c
    return r


def _int_roots(coeffs):
    """Integer roots of an integer polynomial (lowest degree first), by sympy."""
    while coeffs and coeffs[-1] == 0:
        coeffs = coeffs[:-1]
    if len(coeffs) < 2:
        return []
    try:
        import sympy
    except Exception:                       # pragma: no cover
        return []
    x = sympy.Symbol("x")
    poly = sympy.Poly(list(reversed(coeffs)), x, domain="ZZ")
    out = []
    for fac, _ in poly.factor_list()[1]:
        if fac.degree() == 1:
            a, b = fac.all_coeffs()
            if b % a == 0:
                out.append(int(-b // a))
    return out


def _left(deadline):
    return deadline is None or time.monotonic() < deadline


def _reduce(basis, deadline, reducer):
    """The in-repo exact LLL, or a caller's reducer(basis, deadline) -> rows | None (B-244)."""
    if reducer is None:
        return lll(basis, deadline=deadline)
    return reducer(basis, deadline)


# ---- Coppersmith / Howgrave-Graham, univariate, modulus with an unknown divisor ----------------------------

def coppersmith_roots(coeffs, N, X, beta=1.0, m=None, t=None, deadline=None, reducer=None):
    """Candidate integers x with |x| <= X and gcd(f(x), N) above 1 (beta < 1) or f(x) == 0 mod N
    (beta == 1), for f given lowest degree first. `coeffs` need not be monic (made monic mod N when
    the leading coefficient is invertible). The candidates are NOT yet trusted: callers check them.
    Tries growing lattices (m = 2, 3, ...) until `deadline`. `reducer(basis, deadline)` replaces the
    in-repo LLL (lattice_backends.make_reducer: fpylll when built); the candidates are checked the same."""
    coeffs = [c % N for c in coeffs]
    while coeffs and coeffs[-1] == 0:
        coeffs.pop()
    dgr = len(coeffs) - 1
    if dgr < 1:
        return []
    lead = coeffs[-1]
    if lead != 1:
        inv = pow(lead, -1, N) if math.gcd(lead, N) == 1 else None
        if inv is None:
            return []
        coeffs = [c * inv % N for c in coeffs]
    sizes = [m] if m else range(2, 9)
    for mm in sizes:
        if not _left(deadline):
            break
        tt = t if t is not None else int(dgr * mm * (1 / beta - 1))
        if beta >= 1.0 or tt < 1:
            tt = max(tt, 1)
        found = _coppersmith_once(coeffs, N, X, mm, tt, dgr, deadline, reducer)
        good = []
        for r in found:
            g = math.gcd(_peval(coeffs, r) % N, N)
            if (beta >= 1.0 and _peval(coeffs, r) % N == 0) or (beta < 1.0 and 1 < g < N):
                good.append(r)
        if good:
            return sorted(set(good))
    return []


def _coppersmith_once(f, N, X, m, t, dgr, deadline, reducer=None):
    dim = dgr * m + t
    fp = [[1]]
    for _ in range(m):
        fp.append(_pmul(fp[-1], f))
    rows = []
    for i in range(m):
        for j in range(dgr):
            poly = _pmul([0] * j + [1], fp[i])
            poly = [c * N ** (m - i) for c in poly]
            rows.append(poly)
    for i in range(t):
        rows.append(_pmul([0] * i + [1], fp[m]))
    basis = []
    for poly in rows:
        row = [0] * dim
        for k, c in enumerate(poly):
            if k < dim:
                row[k] = c * X ** k
            elif c:
                return []
        basis.append(row)
    red = _reduce(basis, deadline, reducer)
    if red is None:
        return []
    roots = []
    for vec in red[:3]:
        h = []
        for k, c in enumerate(vec):
            if c % X ** k:
                h = None
                break
            h.append(c // X ** k)
        if h:
            roots += _int_roots(h)
    return roots


# ---- stereotyped message -----------------------------------------------------------------------------------

def stereotyped_message(n, e, c, prefix=b"", suffix=b"", unknown_len=0, total_len=None, deadline=None):
    """The plaintext bytes of c = m^e mod n when m = prefix || unknown || suffix with `unknown_len`
    unknown bytes (small e, unknown part below n^(1/e)); verified by re-encryption. None otherwise.
    `total_len` (when given) pads the message to that many bytes; otherwise it is the three parts."""
    if e < 2 or e > 17 or unknown_len < 1 or not (0 < c < n):
        return None
    L = unknown_len
    base = int.from_bytes(prefix, "big") << (8 * (L + len(suffix)))
    base += int.from_bytes(suffix, "big") if suffix else 0
    # f(x) = (base + x * 256^len(suffix))^e - c
    lin = [base, 1 << (8 * len(suffix))]
    f = _ppow(lin, e)
    f[0] -= c
    X = 1 << (8 * L)
    if e == 1 or X ** e >= n * 4:               # beyond the Coppersmith bound (with slack): cannot work
        return None
    for r in coppersmith_roots(f, n, X, 1.0, deadline=deadline):
        if 0 <= r < X:
            mval = base + r * (1 << (8 * len(suffix)))
            if pow(mval, e, n) == c:
                size = (total_len if total_len else len(prefix) + L + len(suffix))
                if mval.bit_length() <= 8 * size:
                    return mval.to_bytes(size, "big")
    return None


# ---- partial prime ------------------------------------------------------------------------------------------

def partial_prime(n, known, known_bits, kind="high", p_bits=None, deadline=None):
    """(p, q) with p*q == n from a few known bits of the factor p: `known` holds the top
    `known_bits` bits of p (kind "high", p_bits = bit length of p, default ceil(bits(n)/2)) or the low
    `known_bits` bits (kind "low"). Needs about half of p's bits. Verified: p * q == n, both above 1. None else."""
    if n < 15:
        return None
    pb = p_bits or (n.bit_length() + 1) // 2
    unknown = pb - known_bits
    if unknown < 1:
        g = math.gcd(known, n)
        return _split(n, known) if 1 < g < n else None
    if kind == "high":
        f = [known << unknown, 1]
        X = 1 << unknown
    else:
        f = [known, 1 << known_bits]
        X = 1 << unknown
    # beta = 0.5 (p ~ sqrt n); the bound is X < n^(beta^2) = n^(1/4): about half of p unknown
    if X.bit_length() - 1 > n.bit_length() // 4 + 1:
        return None
    for r in coppersmith_roots(f, n, X, 0.5, deadline=deadline):
        p = _peval(f, r)
        got = _split(n, p)
        if got:
            return got
    return None


def _split(n, p):
    if p > 1 and n % p == 0 and 1 < p < n:
        q = n // p
        return tuple(sorted((p, q))) if p * q == n else None
    return None


# ---- Boneh-Durfee ----------------------------------------------------------------------------------------------

def boneh_durfee(n, e, delta=0.27, m=3, t=1, deadline=None, reducer=None):
    """(d, p, q) for a private exponent d < n^delta, or None. Bivariate lattice on
    f(x, y) = 1 + x (A + y) mod e with A = (n + 1) / 2, x = k, y = -(p + q) / 2; the solution is read
    from a resultant and verified: p*q == n, d*e == 1 mod (p-1)(q-1), and a test message round-trips.
    Pure Python: m up to 4 is practical on 256 to 512-bit moduli, with a limited delta (about 0.26).
    `reducer` swaps the LLL (lattice_backends.make_reducer); boneh_durfee_ladder grows m to a deadline."""
    try:
        import sympy
    except Exception:                       # pragma: no cover
        return None
    if n < 1 << 40 or e < 3:
        return None
    X = 2 * int(n ** delta)
    Y = int(math.isqrt(n)) * 3 // 2 + 1         # |p+q|/2 < ~ sqrt(n) (the factors are close in size)
    A = (n + 1) // 2
    x, y = sympy.symbols("x y")
    f = 1 + x * (A + y)
    polys = []
    for ii in range(m + 1):
        for jj in range(ii + 1):
            polys.append(sympy.expand(x ** (ii - jj) * f ** jj * e ** (m - jj)))
    for jj in range(1, t + 1):
        for kk in range((m // t) * jj, m + 1):
            polys.append(sympy.expand(y ** jj * f ** kk * e ** (m - kk)))
    cols = sorted({mon for p in polys for mon in sympy.Poly(p, x, y).monoms()}, key=lambda mm: (mm[0] + mm[1], mm))
    parsed = [sympy.Poly(p, x, y).as_dict() for p in polys]     # fewer rows than columns is fine
    basis = [[int(dct.get(mm, 0)) * X ** mm[0] * Y ** mm[1] for mm in cols] for dct in parsed]
    red = _reduce(basis, deadline, reducer)
    if red is None:
        return None
    hs = []
    for vec in red[:6]:
        h = 0
        for coef, mm in zip(vec, cols):
            if coef % (X ** mm[0] * Y ** mm[1]):
                h = None
                break
            h += (coef // (X ** mm[0] * Y ** mm[1])) * x ** mm[0] * y ** mm[1]
        if h is not None and h != 0:
            hs.append(h)
    tried = 0
    for i in range(len(hs)):
        for j in range(i + 1, len(hs)):
            if not _left(deadline) or tried > 12:
                return None
            tried += 1
            try:
                res = sympy.resultant(hs[i], hs[j], x)
            except Exception:
                continue
            if res == 0:
                continue
            for y0 in _sym_int_roots(sympy, res, y):
                s = -2 * y0                      # p + q
                disc = s * s - 4 * n
                if disc < 0:
                    continue
                r = math.isqrt(disc)
                if r * r != disc or (s + r) % 2:
                    continue
                p, q = (s + r) // 2, (s - r) // 2
                got = _split(n, p) if p * q == n else None
                if got:
                    phi = (got[0] - 1) * (got[1] - 1)
                    d = pow(e, -1, phi) if math.gcd(e, phi) == 1 else None
                    if d is not None and _roundtrip(n, e, d):
                        return d, got[0], got[1]
    return None


def boneh_durfee_ladder(n, e, delta=0.27, ms=(3, 4, 5, 6), deadline=None, reducer=None):
    """boneh_durfee over growing lattices (m in `ms`, t = max(1, round((1 - 2 delta) m))) until one
    returns a verified (d, p, q) or `deadline` passes. A larger m reaches a larger delta and costs much
    more: with the gmpy2 LLL a 512-bit key at d ~ n^0.26 takes m = 4 (seconds); n^0.27 and above needs
    the larger m that only fpylll (lattice_backends.make_reducer) finishes in reasonable time."""
    for m in ms:
        if not _left(deadline):
            return None
        t = max(1, round((1 - 2 * delta) * m))
        got = boneh_durfee(n, e, delta=delta, m=m, t=t, deadline=deadline, reducer=reducer)
        if got:
            return got
    return None


def _sym_int_roots(sympy, expr, var):
    try:
        poly = sympy.Poly(expr, var, domain="ZZ")
    except Exception:
        return []
    out = []
    for fac, _ in poly.factor_list()[1]:
        if fac.degree() == 1:
            a, b = fac.all_coeffs()
            if b % a == 0:
                out.append(int(-b // a))
    return out


def _roundtrip(n, e, d, tries=4):
    rng = random.Random(n ^ e)
    for _ in range(tries):
        msg = rng.randrange(2, n - 1)
        if pow(pow(msg, e, n), d, n) != msg:
            return False
    return True


# ---- ROCA (CVE-2017-15361) -----------------------------------------------------------------------------------------

_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
           101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
           197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
           311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
           431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
           557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
           661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
           809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
           937, 941, 947, 953, 967, 971, 977, 983, 991, 997]


def _subgroup(prime, g=65537):
    s, x = set(), 1
    while True:
        x = x * g % prime
        s.add(x)
        if x == 1:
            return s


_SUBGROUPS = {}


def roca_fingerprint(n, g=65537):
    """True when n has the Infineon (ROCA) form: n mod p lies in the subgroup <65537> of Z_p* for each
    of the first 39 primes (2 to 167), the published test (Nemec et al., 2017). A random modulus passes
    with probability about 2^-45 (the product of the subgroup indices), so a True is a detection, not
    a guess; False means this test finds no sign (the structure may still be one with another generator)."""
    if n < 3 or n % 2 == 0:
        return False
    for p in _PRIMES[:39]:
        sg = _SUBGROUPS.get((p, g))
        if sg is None:
            sg = _SUBGROUPS[(p, g)] = _subgroup(p, g) if g % p else None
        if sg is None:
            return False
        if n % p not in sg:
            return False
    return True


def roca_factor(n, g=65537, max_primes=12, deadline=None, check=True, n_primes=None):
    """(p, q) of an Infineon-form modulus, by the Coppersmith search of the ROCA paper (primes of
    the form k * M + g^a mod M, M a primorial), or None. Only toy sizes finish in pure Python: the
    search runs a over the order of g mod M' (M' the largest primorial the Coppersmith bound allows)
    and stops at the deadline. Verified: p * q == n. A genuine 512-bit-and-up key returns None here."""
    if check and not roca_fingerprint(n, g):
        return None
    bits = n.bit_length()
    # the prime p has about bits/2 bits; p = k * Mp + r, k < 2^(bits/2) / Mp, need k < n^(1/4)
    best = None
    Mp, ordr = 1, 1
    for cnt in ([n_primes] if n_primes else range(1, max_primes + 1)):
        M = 1
        for pr in _PRIMES[:cnt]:
            M *= pr
        o = 1
        for pr in _PRIMES[:cnt]:
            o = o * _mult_order(g, pr) // math.gcd(o, _mult_order(g, pr))
        if M.bit_length() > (bits + 1) // 2 - 4 and not n_primes:
            break
        # unknown bits of p after fixing p mod M: (bits/2 - bits(M)) must fit n^(1/4) -> M above n^(1/4)
        if n_primes or (bits // 2 - M.bit_length()) <= bits // 4 + 1:
            best = (M, o)
            if o > 4096:
                break
    if best is None:
        return None
    Mp, ordr = best
    if ordr > 200_000:
        return None                         # a real key: the search would not finish
    pb = (bits + 1) // 2
    X = 1 << max(1, pb - Mp.bit_length() + 1)
    for a in range(ordr):
        if not _left(deadline):
            return None
        r = pow(g, a, Mp)
        for rr in {r}:
            f = [rr, Mp]
            for k in coppersmith_roots(f, n, X, 0.5, m=3, t=2, deadline=deadline):
                got = _split(n, _peval(f, k))
                if got:
                    return got
    return None


def _mult_order(g, p):
    x, k = g % p, 1
    while x != 1:
        x = x * g % p
        k += 1
    return k
