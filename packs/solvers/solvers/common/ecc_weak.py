"""Weak-curve elliptic-curve private-scalar recovery (never-wrong).

Given a short Weierstrass curve ``y^2 = x^3 + a*x + b`` over ``F_p``, a base point ``G`` and a
public point ``Q = [d]G``, this module recovers the private scalar ``d`` when the curve is weak,
by one of three classical routes:

* a **singular** curve (``4a^3 + 27b^2 == 0``): the non-singular points form a group isomorphic to
  ``F_p^+`` (a cusp, ``y^2 = x^3``) or to ``F_p^*`` (a split node), so the ECDLP collapses to an
  ordinary discrete log that Pohlig-Hellman solves when ``p-1`` is smooth;
* an **anomalous** curve (``#E == p``): Smart's p-adic attack recovers ``d`` in linear time;
* a **smooth group order**: Pohlig-Hellman over the points, when the order ``n`` is given and its
  largest prime factor is small enough for a bounded baby-step/giant-step search.

The never-wrong contract is enforced in one place: a scalar ``d`` is returned ONLY after
``[d]G == Q`` is checked on the curve (the elliptic analogue of ``pq == n`` or ``d*G == pubkey``,
the same bar the shipped ECDSA solver uses). Every route is tried and the first ``d`` that
verifies is returned; a route whose maths does not reproduce the point simply contributes nothing,
so a wrong value can never be emitted. Anything unproven is ``None``.

Nothing here reads a file, makes a request or imports the Game Master. Pure integer arithmetic.
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
from pathlib import Path
import sys
import time

# A baby-step/giant-step table of about this many entries is the most this module will build for
# one prime factor of a group order: ~1M int keys (F_p^*) / tuple keys (a curve). A prime factor
# whose square root exceeds it makes the discrete log decline (None), never a wrong or endless run.
BSGS_LIMIT_INT = 1 << 20
BSGS_LIMIT_EC = 1 << 19
SMART_PREC = 16                 # p-adic relative precision (digits) for Smart's attack
MAX_INVALID_OBSERVATIONS = 64
MAX_CRT_CANDIDATES = 1 << 20
MAX_PAIRING_BITS = 4096
MAX_JSON_BYTES = 1 << 20


# ---- small number theory (self-contained; see solvers/common/modern_crypto.py for the shared set)

def _left(deadline) -> bool:
    return deadline is None or time.monotonic() < deadline


def inverse(a: int, m: int):
    try:
        return pow(a % m, -1, m)
    except ValueError:
        return None


def crt(residues, moduli):
    """(x, N) with x == r_i mod m_i for pairwise-coprime moduli, else None."""
    x, n = 0, 1
    for r, m in zip(residues, moduli):
        if math.gcd(n, m) != 1:
            return None
        x += n * ((r - x) * pow(n, -1, m) % m)
        n *= m
    return x % n, n


_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _MR_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# A factor usable by the bounded discrete log is at most ~2^40 (BSGS_LIMIT_EC squared), which
# Pollard rho finds within ~2^20 steps; beyond that the factor is too large for the search anyway,
# so the cap makes a hard semiprime (a non-smooth order) decline in well under a second, never hang.
RHO_STEPS = 1 << 20


def _pollard_rho(n: int, deadline=None):
    if n % 2 == 0:
        return 2
    for c in (1, 3, 5):
        x = y = 2
        g = 1
        steps = 0
        while g == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            g = math.gcd(abs(x - y), n)
            steps += 1
            if steps >= RHO_STEPS:
                break
            if steps & 0x1FFFF == 0 and not _left(deadline):
                return None
        if 1 < g < n:
            return g
    return None


def factorize(n: int, deadline=None):
    """{prime: exponent} of n, or None when a factor was not found in time. Trial division over
    small primes, then Pollard rho. A group order for Pohlig-Hellman must factor fully here."""
    if n <= 0:
        return None
    out = {}
    for p in range(2, 1 << 16):
        if p * p > n:
            break
        while n % p == 0:
            out[p] = out.get(p, 0) + 1
            n //= p
    todo = [n] if n > 1 else []
    while todo:
        m = todo.pop()
        if m == 1:
            continue
        if is_prime(m):
            out[m] = out.get(m, 0) + 1
            continue
        f = _pollard_rho(m, deadline)
        if not f or f in (1, m):
            return None
        todo.append(f)
        todo.append(m // f)
    return out


def tonelli(a: int, p: int):
    """A square root of a modulo an odd prime p, or None when a is a non-residue."""
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b * b % p, t * b * b % p, r * b % p
    return r


# ---- elliptic-curve group law over F_p (short Weierstrass) ------------------------------------------
# A point is an (x, y) tuple; None is the point at infinity. The same chord-and-tangent law is the
# group law on the non-singular points of a singular curve, so these are reused for verification
# there too.

def ec_add(P, Q, p: int, a: int):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        den = inverse(2 * y1 % p, p)
        if den is None:
            return None
        lam = (3 * x1 * x1 + a) * den % p
    else:
        den = inverse((x2 - x1) % p, p)
        if den is None:
            return None
        lam = (y2 - y1) * den % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def ec_mul(k: int, P, p: int, a: int):
    if P is None or k == 0:
        return None
    if k < 0:
        P = (P[0], (-P[1]) % p)
        k = -k
    acc, add = None, P
    while k:
        if k & 1:
            acc = ec_add(acc, add, p, a)
        add = ec_add(add, add, p, a)
        k >>= 1
    return acc


def on_curve(P, p: int, a: int, b: int) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


# ---- a generic group, for Pohlig-Hellman over F_p^* and over a curve --------------------------------

class _Group:
    """op(x, y), inv(x) and an identity; keys hashable. Scalar powers by square-and-multiply."""

    def __init__(self, op, inv, identity):
        self.op = op
        self.inv = inv
        self.identity = identity

    def pow(self, g, k: int):
        if k < 0:
            g = self.inv(g)
            k = -k
        acc = self.identity
        while k:
            if k & 1:
                acc = self.op(acc, g)
            g = self.op(g, g)
            k >>= 1
        return acc


def _mult_group(p: int) -> _Group:
    return _Group(lambda x, y: x * y % p, lambda x: pow(x, -1, p), 1)


def _curve_group(p: int, a: int) -> _Group:
    return _Group(lambda P, Q: ec_add(P, Q, p, a),
                  lambda P: None if P is None else (P[0], (-P[1]) % p), None)


def _bsgs(g, h, order: int, grp: _Group, limit: int, deadline=None):
    """The least x in [0, order) with g^x == h, where g has prime order `order`, or None.
    Declines (None) when ceil(sqrt(order)) exceeds `limit`, so the table stays bounded."""
    if h == grp.identity:
        return 0
    m = math.isqrt(order - 1) + 1
    if m > limit:
        return None
    table = {}
    e = grp.identity
    for j in range(m):
        if e not in table:
            table[e] = j
        e = grp.op(e, g)
        if j & 0x3FFFF == 0x3FFFF and not _left(deadline):
            return None
    factor = grp.pow(grp.inv(g), m)        # g^(-m)
    gamma = h
    for i in range(m):
        hit = table.get(gamma)
        if hit is not None:
            return i * m + hit
        gamma = grp.op(gamma, factor)
        if i & 0x3FFFF == 0x3FFFF and not _left(deadline):
            return None
    return None


def _order_in(g, group_order: int, factors: dict, grp: _Group) -> int:
    """The order of g given that it divides group_order (with factorisation `factors`)."""
    order = group_order
    for pr in factors:
        while order % pr == 0 and grp.pow(g, order // pr) == grp.identity:
            order //= pr
    return order


def discrete_log(g, h, group_order: int, grp: _Group, limit: int, deadline=None):
    """x with g^x == h via Pohlig-Hellman, where h is in <g> and <g> has order dividing
    group_order; None when the order does not factor smoothly enough for the bounded search."""
    factors = factorize(group_order, deadline)
    if factors is None:
        return None
    order = _order_in(g, group_order, factors, grp)
    if order == 1:
        return 0 if h == grp.identity else None
    ofac = factorize(order, deadline)
    if ofac is None:
        return None
    residues, moduli = [], []
    for pr, e in ofac.items():
        pe = pr ** e
        cof = order // pe
        gi = grp.pow(g, cof)
        hi = grp.pow(h, cof)
        gamma = grp.pow(gi, pr ** (e - 1))     # order pr
        gi_inv = grp.inv(gi)
        x = 0
        for k in range(e):
            t = grp.op(hi, grp.pow(gi_inv, x))
            hk = grp.pow(t, pr ** (e - 1 - k))
            dk = _bsgs(gamma, hk, pr, grp, limit, deadline)
            if dk is None:
                return None
            x += dk * pr ** k
        residues.append(x)
        moduli.append(pe)
    got = crt(residues, moduli)
    return None if got is None else got[0]


# ---- the three weak-curve routes --------------------------------------------------------------------

def _singular_scalar(p, a, b, G, Q, deadline=None):
    """d on a singular curve y^2 = x^3 + ax + b (cusp -> F_p^+, split node -> F_p^*), else None.
    A non-split node (the node's tangents live in F_{p^2}) is declined."""
    a %= p
    b %= p
    gx, gy = G[0] % p, G[1] % p
    qx, qy = Q[0] % p, Q[1] % p
    if a == 0 and b == 0:
        # cusp y^2 = x^3; the map (x, y) -> x/y is an isomorphism to (F_p, +).
        if gy == 0 or qy == 0 or gx == 0:
            return None
        ug = gx * pow(gy, -1, p) % p
        uq = qx * pow(qy, -1, p) % p
        if ug == 0:
            return None
        return uq * pow(ug, -1, p) % p
    # node: the depressed cubic x^3+ax+b has a double root alpha and single root -2*alpha, with
    # alpha^2 == -a/3 and alpha^3 == b/2. Translating X = x - alpha gives y^2 = X^2 * (X + 3*alpha).
    inv3 = inverse(3, p)
    if inv3 is None:
        return None
    alpha = tonelli((-a * inv3) % p, p)
    if alpha is None:
        return None
    half_b = b * pow(2, -1, p) % p
    if pow(alpha, 3, p) != half_b:
        alpha = (-alpha) % p
        if pow(alpha, 3, p) != half_b:
            return None            # not a double root of this depressed cubic
    c = 3 * alpha % p
    if c == 0:
        return None
    t = tonelli(c, p)
    if t is None:
        return None                # non-split node: DLP would live in F_{p^2}, not built

    def phi(P):
        x, y = P[0] % p, P[1] % p
        X = (x - alpha) % p
        num = (y + t * X) % p
        den = (y - t * X) % p
        if den == 0:
            return None
        return num * pow(den, -1, p) % p

    ug = phi(G)
    uq = phi(Q)
    if ug is None or uq is None or ug in (0, 1):
        return None
    return discrete_log(ug, uq, p - 1, _mult_group(p), BSGS_LIMIT_INT, deadline)


def _smooth_scalar(p, a, b, G, Q, order, deadline=None):
    """d by Pohlig-Hellman over the curve's points, when `order` (a multiple of ord(G)) is given
    and its largest prime factor is small enough for the bounded search; else None."""
    if not order or order <= 1:
        return None
    return discrete_log(G, Q, order, _curve_group(p, a), BSGS_LIMIT_EC, deadline)


# ---- Smart's attack: p-adic arithmetic at fixed relative precision ----------------------------------

class _Qp:
    """A p-adic number p^val * unit, with `unit` a p-adic unit known to `prec` digits (mod p^prec),
    or a sentinel zero. Enough for Smart's attack: a handful of elliptic operations whose only
    precision loss is the few digits lost as [p]P lands in the kernel of reduction."""

    __slots__ = ("p", "prec", "val", "unit", "zero")

    def __init__(self, p, prec, val, unit, zero=False):
        self.p = p
        self.prec = prec
        self.zero = zero
        if zero:
            self.val = val
            self.unit = 0
        else:
            self.val = val
            self.unit = unit % (p ** prec)

    @classmethod
    def from_int(cls, p, prec, n):
        n %= p ** (prec + 8)
        if n == 0:
            return cls(p, prec, prec, 0, zero=True)
        v = 0
        while n % p == 0:
            n //= p
            v += 1
        return cls(p, prec, v, n)

    def _mk(self, val, unit, zero=False):
        return _Qp(self.p, self.prec, val, unit, zero)

    def mul(self, o):
        if self.zero or o.zero:
            return self._mk(self.val + o.val, 0, zero=True)
        return self._mk(self.val + o.val, self.unit * o.unit)

    def inv(self):
        if self.zero:
            raise ZeroDivisionError("p-adic inverse of zero")
        return self._mk(-self.val, pow(self.unit % (self.p ** self.prec), -1, self.p ** self.prec))

    def neg(self):
        if self.zero:
            return self
        return self._mk(self.val, -self.unit)

    def add(self, o):
        p, prec = self.p, self.prec
        if self.zero:
            return o
        if o.zero:
            return self
        vm = min(self.val, o.val)
        mod = p ** (prec + 8)
        s = (self.unit * pow(p, self.val - vm, mod) + o.unit * pow(p, o.val - vm, mod)) % mod
        if s == 0:
            return self._mk(vm + prec, 0, zero=True)
        w = 0
        while s % p == 0:
            s //= p
            w += 1
        return self._mk(vm + w, s)

    def sub(self, o):
        return self.add(o.neg())

    def residue(self) -> int:
        """The value mod p, valid only when val >= 0 (no pole)."""
        if self.zero or self.val > 0:
            return 0
        if self.val < 0:
            raise ValueError("residue of a p-adic number with a pole")
        return self.unit % self.p


def _qp_lift_y(p, prec, a, b, x_int, y0):
    """Hensel-lift y so that y^2 == x^3 + a*x + b over Z/p^prec' with y ≡ y0 (mod p); y0 != 0."""
    mod = p ** (prec + 8)
    rhs = (x_int * x_int % mod * x_int + a * x_int + b) % mod
    y = y0 % p
    cur = p
    while cur < mod:
        cur = min(cur * cur, mod)
        inv = pow(2 * y % cur, -1, cur)
        y = (y - (y * y - rhs) * inv) % cur
    return y % mod


def _qp_double(P, p, prec, a_qp):
    x, y = P
    three = _Qp.from_int(p, prec, 3)
    two = _Qp.from_int(p, prec, 2)
    lam = x.mul(x).mul(three).add(a_qp).mul(two.mul(y).inv())
    x3 = lam.mul(lam).sub(x).sub(x)
    y3 = lam.mul(x.sub(x3)).sub(y)
    return x3, y3


def _qp_add(P, Qpt, p, prec, a_qp):
    if P is None:
        return Qpt
    if Qpt is None:
        return P
    x1, y1 = P
    x2, y2 = Qpt
    lam = y2.sub(y1).mul(x2.sub(x1).inv())
    x3 = lam.mul(lam).sub(x1).sub(x2)
    y3 = lam.mul(x1.sub(x3)).sub(y1)
    return x3, y3


def _qp_mul(k, P, p, prec, a_qp):
    acc, add = None, P
    while k:
        if k & 1:
            acc = add if acc is None else _qp_add(acc, add, p, prec, a_qp)
        add = _qp_double(add, p, prec, a_qp)
        k >>= 1
    return acc


def _smart_scalar(p, a, b, G, Q, deadline=None):
    """Smart's attack on an anomalous curve (#E == p): d or None. Cheap; a curve that is not
    anomalous yields a value that simply fails the [d]G == Q check in the caller."""
    if p < 5 or not is_prime(p):
        return None
    gx, gy = G[0] % p, G[1] % p
    qx, qy = Q[0] % p, Q[1] % p
    if gy == 0 or qy == 0:
        return None
    prec = SMART_PREC
    a_qp = _Qp.from_int(p, prec, a)
    try:
        gy_l = _qp_lift_y(p, prec, a, b, gx, gy)
        qy_l = _qp_lift_y(p, prec, a, b, qx, qy)
        Gl = (_Qp.from_int(p, prec, gx), _Qp.from_int(p, prec, gy_l))
        Ql = (_Qp.from_int(p, prec, qx), _Qp.from_int(p, prec, qy_l))
        pG = _qp_mul(p, Gl, p, prec, a_qp)
        pQ = _qp_mul(p, Ql, p, prec, a_qp)
        if pG is None or pQ is None:
            return None
        # psi(R) = -x(R)/y(R) is the formal-group logarithm; for a kernel point it has valuation 1.
        phi_g = pG[0].mul(pG[1].inv()).neg()
        phi_q = pQ[0].mul(pQ[1].inv()).neg()
        if phi_g.val != 1:
            return None            # [p]G did not land in the kernel: the curve is not anomalous
        d = phi_q.mul(phi_g.inv())
        if d.val != 0:
            return None
        return d.residue() % p
    except (ZeroDivisionError, ValueError):
        return None


# ---- invalid-curve weak subgroups + CRT ------------------------------------------------------------

def invalid_curve_residue(p: int, a: int, b: int, point, response, subgroup_order: int,
                          deadline=None):
    """Return ``(d mod r, r)`` from ``response == [d]point`` on one invalid curve.

    The target's short-Weierstrass addition formulas depend on ``a`` but not ``b``.  Supplying a
    point on a different ``b`` can therefore confine its response to a weak subgroup.  This helper
    performs only the offline last step: it validates the supplied point/response/order, solves the
    bounded subgroup DLP, and replays the multiplication before returning a residue.
    """
    if not (isinstance(p, int) and 3 < p and is_prime(p) and isinstance(a, int)
            and isinstance(b, int) and isinstance(subgroup_order, int) and subgroup_order > 1):
        return None
    if subgroup_order.bit_length() > MAX_PAIRING_BITS:
        return None
    if not (isinstance(point, (tuple, list)) and len(point) == 2):
        return None
    P = (int(point[0]) % p, int(point[1]) % p)
    if response is None:
        R = None
    elif isinstance(response, (tuple, list)) and len(response) == 2:
        R = (int(response[0]) % p, int(response[1]) % p)
    else:
        return None
    if not on_curve(P, p, a % p, b % p) or not on_curve(R, p, a % p, b % p):
        return None
    factors = factorize(subgroup_order, deadline)
    if factors is None or ec_mul(subgroup_order, P, p, a) is not None:
        return None
    exact_order = _order_in(P, subgroup_order, factors, _curve_group(p, a % p))
    if exact_order <= 1:
        return None
    residue = discrete_log(P, R, exact_order, _curve_group(p, a % p), BSGS_LIMIT_EC, deadline)
    if residue is None or ec_mul(residue, P, p, a) != R:
        return None
    return residue % exact_order, exact_order


def _crt_merge(left: tuple[int, int], right: tuple[int, int]):
    """Generalized CRT merge, accepting consistent non-coprime moduli."""
    x, m = left
    y, n = right
    g = math.gcd(m, n)
    if (y - x) % g:
        return None
    mg, ng = m // g, n // g
    step = ((y - x) // g * pow(mg, -1, ng)) % ng if ng > 1 else 0
    modulus = m * ng
    return (x + m * step) % modulus, modulus


def recover_invalid_curve_scalar(observations, *, verification=None, scalar_bound: int | None = None,
                                 deadline=None):
    """Combine weak-subgroup invalid-curve responses with CRT.

    ``observations`` contains mappings with ``p,a,b,point,response,order``.  The result always carries
    a proven ``residue`` and ``modulus``.  ``scalar`` is populated only when a caller-supplied bound
    leaves one CRT representative and, when ``verification`` is supplied, that representative also
    reproduces ``Q=[d]G`` on the real curve.
    """
    try:
        iterator = iter(observations)
        rows = list(itertools.islice(iterator, MAX_INVALID_OBSERVATIONS + 1))
    except (TypeError, MemoryError):
        return None
    if not rows or len(rows) > MAX_INVALID_OBSERVATIONS:
        return None
    if deadline is None:
        deadline = time.monotonic() + 10.0
    combined = (0, 1)
    proven = []
    for row in rows:
        if not isinstance(row, dict) or not _left(deadline):
            return None
        try:
            got = invalid_curve_residue(int(row["p"]), int(row["a"]), int(row["b"]),
                                        row["point"], row.get("response"), int(row["order"]), deadline)
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        if got is None:
            return None
        merged = _crt_merge(combined, got)
        if merged is None:
            return None
        combined = merged
        proven.append({"residue": got[0], "modulus": got[1]})
    residue, modulus = combined
    scalar = None
    if scalar_bound is not None:
        if not isinstance(scalar_bound, int) or scalar_bound <= 0:
            return None
        count = 0 if residue >= scalar_bound else 1 + (scalar_bound - 1 - residue) // modulus
        if count > MAX_CRT_CANDIDATES:
            return None
        candidates = [residue + i * modulus for i in range(count)]
        point_checked = False
        if verification is not None:
            if not isinstance(verification, dict):
                return None
            try:
                vp, va, vb = int(verification["p"]), int(verification["a"]), int(verification["b"])
                G0, Q0 = verification["G"], verification["Q"]
                G = (int(G0[0]) % vp, int(G0[1]) % vp)
                Q = (int(Q0[0]) % vp, int(Q0[1]) % vp)
            except (KeyError, TypeError, ValueError, IndexError):
                return None
            if not on_curve(G, vp, va, vb) or not on_curve(Q, vp, va, vb):
                return None
            candidates = [candidate for candidate in candidates if ec_mul(candidate, G, vp, va) == Q]
            point_checked = True
        if len(candidates) == 1:
            scalar = candidates[0]
    # ``verified`` is a CRYPTOGRAPHIC proof stamp: True only when the scalar was checked to
    # reproduce the real target point Q (``[scalar]G == Q``).  A CRT residue that is merely the
    # unique representative under the caller-supplied ``scalar_bound`` is a strong candidate (correct
    # when that bound truly exceeds the key) but is NOT point-proven, so it returns verified=False to
    # avoid labelling a value proven when the maths never reproduced Q — a too-tight bound would
    # otherwise emit a wrong scalar stamped verified.  Supply ``verification`` {p,a,b,G,Q} to prove it.
    return {"residue": residue, "modulus": modulus, "scalar": scalar,
            "observations": proven, "verified": scalar is not None and point_checked}


# ---- reduced Tate pairing and MOV/Frey-Ruck transfer ----------------------------------------------

def embedding_degree(p: int, subgroup_order: int, max_degree: int = 12):
    """Least k <= ``max_degree`` with ``subgroup_order | p^k-1``, else ``None``."""
    if not (isinstance(p, int) and isinstance(subgroup_order, int) and subgroup_order > 1
            and isinstance(max_degree, int) and 1 <= max_degree <= 64):
        return None
    value = 1
    for degree in range(1, max_degree + 1):
        value = value * (p % subgroup_order) % subgroup_order
        if value == 1:
            return degree
    return None


class _Fp2:
    """Tiny F_(p^2) arithmetic for pairings; values are ``(real, imag)`` tuples."""

    def __init__(self, p: int, non_residue: int = -1):
        if p.bit_length() > MAX_PAIRING_BITS:
            raise ValueError("pairing field exceeds the bit cap")
        self.p = p
        self.nr = non_residue % p
        if pow(self.nr, (p - 1) // 2, p) != p - 1:
            raise ValueError("quadratic extension parameter is not a non-residue")

    def val(self, value):
        if isinstance(value, tuple):
            return value[0] % self.p, value[1] % self.p
        return value % self.p, 0

    def add(self, x, y):
        x, y = self.val(x), self.val(y)
        return (x[0] + y[0]) % self.p, (x[1] + y[1]) % self.p

    def neg(self, x):
        x = self.val(x)
        return (-x[0]) % self.p, (-x[1]) % self.p

    def sub(self, x, y):
        return self.add(x, self.neg(y))

    def mul(self, x, y):
        x, y = self.val(x), self.val(y)
        return ((x[0] * y[0] + x[1] * y[1] * self.nr) % self.p,
                (x[0] * y[1] + x[1] * y[0]) % self.p)

    def inv(self, x):
        x = self.val(x)
        den = (x[0] * x[0] - self.nr * x[1] * x[1]) % self.p
        if den == 0:
            raise ZeroDivisionError("F_p2 inverse of zero")
        den = pow(den, -1, self.p)
        return x[0] * den % self.p, -x[1] * den % self.p

    def div(self, x, y):
        return self.mul(x, self.inv(y))

    def pow(self, x, exponent: int):
        if exponent < 0:
            x, exponent = self.inv(x), -exponent
        out, base = (1, 0), self.val(x)
        while exponent:
            if exponent & 1:
                out = self.mul(out, base)
            base = self.mul(base, base)
            exponent >>= 1
        return out


class _FpK:
    """Polynomial-basis arithmetic in ``F_p[x]/(modulus)``.

    Coefficients and elements are low-degree first.  The caller supplies the
    monic irreducible polynomial because there is no single canonical basis for
    general pairing fields.  Rabin's finite-field irreducibility criterion is
    checked before any pairing value is accepted.
    """

    def __init__(self, p: int, degree: int, modulus):
        if (not isinstance(degree, int) or not 2 <= degree <= 64
                or p.bit_length() * degree > MAX_PAIRING_BITS):
            raise ValueError("pairing extension exceeds the bit cap")
        if (not isinstance(modulus, (tuple, list)) or len(modulus) != degree + 1):
            raise ValueError("extension_modulus must contain degree+1 coefficients")
        self.p = p
        self.degree = degree
        self.modulus = tuple(int(value) % p for value in modulus)
        if self.modulus[-1] != 1 or self.modulus[0] == 0:
            raise ValueError("extension polynomial must be monic with nonzero constant")
        if not self._irreducible():
            raise ValueError("extension polynomial is reducible over F_p")

    def val(self, value):
        if isinstance(value, (tuple, list)):
            if len(value) > self.degree:
                raise ValueError("extension element has too many coefficients")
            return tuple([*(int(item) % self.p for item in value),
                          *([0] * (self.degree - len(value)))])
        return (int(value) % self.p,) + (0,) * (self.degree - 1)

    def add(self, left, right):
        left, right = self.val(left), self.val(right)
        return tuple((a + b) % self.p for a, b in zip(left, right))

    def neg(self, value):
        return tuple(-coefficient % self.p for coefficient in self.val(value))

    def sub(self, left, right):
        return self.add(left, self.neg(right))

    def mul(self, left, right):
        left, right = self.val(left), self.val(right)
        work = [0] * (2 * self.degree - 1)
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                work[i + j] = (work[i + j] + a * b) % self.p
        for power in range(len(work) - 1, self.degree - 1, -1):
            coefficient = work[power] % self.p
            if not coefficient:
                continue
            for offset in range(self.degree):
                work[power - self.degree + offset] = (
                    work[power - self.degree + offset]
                    - coefficient * self.modulus[offset]
                ) % self.p
        return tuple(work[:self.degree])

    def pow(self, value, exponent: int):
        if exponent < 0:
            value, exponent = self.inv(value), -exponent
        result, base = self.val(1), self.val(value)
        while exponent:
            if exponent & 1:
                result = self.mul(result, base)
            base = self.mul(base, base)
            exponent >>= 1
        return result

    def inv(self, value):
        value = self.val(value)
        if not any(value):
            raise ZeroDivisionError("extension-field inverse of zero")
        return self.pow(value, pow(self.p, self.degree) - 2)

    def div(self, left, right):
        return self.mul(left, self.inv(right))

    def _poly_trim(self, poly):
        poly = [value % self.p for value in poly]
        while len(poly) > 1 and poly[-1] == 0:
            poly.pop()
        return poly

    def _poly_divmod(self, left, right):
        left, right = self._poly_trim(left), self._poly_trim(right)
        if right == [0]:
            raise ZeroDivisionError
        quotient = [0] * max(1, len(left) - len(right) + 1)
        inverse = pow(right[-1], -1, self.p)
        while left != [0] and len(left) >= len(right):
            offset = len(left) - len(right)
            factor = left[-1] * inverse % self.p
            quotient[offset] = factor
            for index, coefficient in enumerate(right):
                left[offset + index] = (left[offset + index] - factor * coefficient) % self.p
            left = self._poly_trim(left)
        return self._poly_trim(quotient), left

    def _poly_gcd(self, left, right):
        left, right = self._poly_trim(left), self._poly_trim(right)
        while right != [0]:
            left, right = right, self._poly_divmod(left, right)[1]
        inverse = pow(left[-1], -1, self.p)
        return [(value * inverse) % self.p for value in left]

    def _poly_mul_mod(self, left, right):
        product = [0] * (len(left) + len(right) - 1)
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                product[i + j] = (product[i + j] + a * b) % self.p
        return self._poly_divmod(product, list(self.modulus))[1]

    def _poly_pow_mod(self, base, exponent):
        result = [1]
        while exponent:
            if exponent & 1:
                result = self._poly_mul_mod(result, base)
            base = self._poly_mul_mod(base, base)
            exponent >>= 1
        return result

    def _irreducible(self):
        # Rabin: x^(p^n)-x == 0 mod f, and gcd(x^(p^(n/q))-x,f)==1
        # for every prime divisor q of n.
        prime_divisors = set()
        remaining, divisor = self.degree, 2
        while divisor * divisor <= remaining:
            if remaining % divisor == 0:
                prime_divisors.add(divisor)
                while remaining % divisor == 0:
                    remaining //= divisor
            divisor += 1
        if remaining > 1:
            prime_divisors.add(remaining)
        x = [0, 1]
        frobenius = {0: x}
        current = x
        for step in range(1, self.degree + 1):
            current = self._poly_pow_mod(current, self.p)
            frobenius[step] = current
        if self._poly_trim(frobenius[self.degree]) != x:
            return False
        for prime in prime_divisors:
            test = list(frobenius[self.degree // prime])
            if len(test) < 2:
                test += [0] * (2 - len(test))
            test[1] = (test[1] - 1) % self.p
            if len(self._poly_gcd(list(self.modulus), test)) > 1:
                return False
        return True


def _pairing_ops(p: int, degree: int, non_residue: int, extension_modulus=None):
    if degree == 1:
        def val(x):
            return x % p
        return {"val": val, "add": lambda x, y: (x + y) % p,
                "sub": lambda x, y: (x - y) % p, "mul": lambda x, y: x * y % p,
                "div": lambda x, y: x * pow(y, -1, p) % p,
                "pow": lambda x, n: pow(x, n, p), "one": 1, "zero": 0}
    if degree == 2 and extension_modulus is None:
        field = _Fp2(p, non_residue)
        return {"val": field.val, "add": field.add, "sub": field.sub, "mul": field.mul,
                "div": field.div, "pow": field.pow, "one": (1, 0), "zero": (0, 0),
                "field": field}
    if degree >= 2 and extension_modulus is not None:
        field = _FpK(p, degree, extension_modulus)
        return {"val": field.val, "add": field.add, "sub": field.sub, "mul": field.mul,
                "div": field.div, "pow": field.pow, "one": field.val(1),
                "zero": field.val(0), "field": field}
    raise ValueError("embedding degree > 2 requires extension_modulus")


def _miller_line(A, B, T, p: int, a: int, ops):
    """Miller g_(A,B)(T), with A/B over F_p and T over the pairing field."""
    if A is None or B is None:
        raise ValueError("Miller line received infinity")
    x1, y1 = A
    x2, y2 = B
    tx, ty = T
    if x1 == x2 and (y1 + y2) % p == 0:
        return ops["sub"](tx, ops["val"](x1))
    if A == B:
        denominator = 2 * y1 % p
        if denominator == 0:
            return ops["sub"](tx, ops["val"](x1))
        slope = (3 * x1 * x1 + a) * pow(denominator, -1, p) % p
    else:
        denominator = (x2 - x1) % p
        slope = (y2 - y1) * pow(denominator, -1, p) % p
    line = ops["sub"](ops["sub"](ty, ops["val"](y1)),
                       ops["mul"](ops["val"](slope), ops["sub"](tx, ops["val"](x1))))
    result = ec_add(A, B, p, a)
    if result is None:
        return line
    vertical = ops["sub"](tx, ops["val"](result[0]))
    return ops["div"](line, vertical)


def reduced_tate_pairing(P, T, subgroup_order: int, p: int, a: int, *, embedding: int = 1,
                         non_residue: int = -1, extension_modulus=None):
    """Reduced Tate pairing over F_(p^k), or ``None`` on invalid/degenerate input."""
    if not (isinstance(subgroup_order, int) and subgroup_order > 1 and subgroup_order.bit_length() <= MAX_PAIRING_BITS
            and ec_mul(subgroup_order, P, p, a) is None):
        return None
    if (pow(p, embedding) - 1) % subgroup_order:
        return None
    try:
        ops = _pairing_ops(p, embedding, non_residue, extension_modulus)
        tx, ty = ops["val"](T[0]), ops["val"](T[1])
        # ``b`` is not needed by Miller lines and is unavailable in this low-level
        # API, so callers of the general transfer perform the full curve check.
        value, current = ops["one"], P
        for bit in bin(subgroup_order)[3:]:
            value = ops["mul"](ops["mul"](value, value),
                                _miller_line(current, current, (tx, ty), p, a, ops))
            current = ec_add(current, current, p, a)
            if bit == "1":
                value = ops["mul"](value, _miller_line(current, P, (tx, ty), p, a, ops))
                current = ec_add(current, P, p, a)
        return ops["pow"](value, (pow(p, embedding) - 1) // subgroup_order)
    except (ValueError, ZeroDivisionError, TypeError, IndexError):
        return None


def mov_frey_ruck_recover(p: int, a: int, b: int, P, Q, subgroup_order: int, *,
                          embedding: int | None = None, auxiliary=None, non_residue: int = -1,
                          extension_modulus=None, deadline=None):
    """Transfer an ECDLP to F_(p^k)* with a reduced Tate pairing.

    Generic extension fields require a caller-supplied irreducible polynomial and auxiliary point;
    the polynomial is checked before use.  For the common supersingular k=2 family ``y^2=x^3+a*x`` with
    ``p == 3 mod 4``, the standard distortion map ``(x,y)->(-x,i*y)`` supplies it automatically.
    A scalar is returned only after replaying ``[d]P == Q``.
    """
    if not (isinstance(p, int) and is_prime(p) and 3 < p and p.bit_length() <= MAX_PAIRING_BITS
            and isinstance(subgroup_order, int) and 1 < subgroup_order
            and subgroup_order.bit_length() <= MAX_PAIRING_BITS):
        return None
    try:
        P = (int(P[0]) % p, int(P[1]) % p)
        Q = (int(Q[0]) % p, int(Q[1]) % p)
    except (TypeError, ValueError, IndexError):
        return None
    if not on_curve(P, p, a, b) or not on_curve(Q, p, a, b):
        return None
    if ec_mul(subgroup_order, P, p, a) is not None or ec_mul(subgroup_order, Q, p, a) is not None:
        return None
    if embedding is not None and (not isinstance(embedding, int) or isinstance(embedding, bool)):
        return None  # a non-int embedding would crash the range check below
    degree = embedding or embedding_degree(p, subgroup_order, 12)
    if degree is None or not 1 <= degree <= 64:
        return None
    if degree == 2 and auxiliary is None:
        if b % p != 0 or p % 4 != 3 or non_residue % p != p - 1:
            return None
        auxiliary = (((-P[0]) % p, 0), (0, P[1] % p))
    elif degree == 1:
        if not (isinstance(auxiliary, (tuple, list)) and len(auxiliary) == 2):
            return None
        auxiliary = (int(auxiliary[0]) % p, int(auxiliary[1]) % p)
        if not on_curve(auxiliary, p, a, b):
            return None
    elif auxiliary is None or extension_modulus is None:
        return None
    try:
        ops = _pairing_ops(p, degree, non_residue, extension_modulus)
        ax, ay = ops["val"](auxiliary[0]), ops["val"](auxiliary[1])
        rhs = ops["add"](
            ops["add"](ops["mul"](ops["mul"](ax, ax), ax),
                       ops["mul"](ops["val"](a), ax)),
            ops["val"](b),
        )
        if ops["mul"](ay, ay) != rhs:
            return None
        auxiliary = (ax, ay)
    except (TypeError, ValueError, IndexError, ZeroDivisionError):
        return None
    if deadline is None:
        deadline = time.monotonic() + 10.0
    base = reduced_tate_pairing(P, auxiliary, subgroup_order, p, a,
                                embedding=degree, non_residue=non_residue,
                                extension_modulus=extension_modulus)
    target = reduced_tate_pairing(Q, auxiliary, subgroup_order, p, a,
                                  embedding=degree, non_residue=non_residue,
                                  extension_modulus=extension_modulus)
    if base is None or target is None:
        return None
    try:
        if degree == 1:
            group = _mult_group(p)
        elif degree == 2 and extension_modulus is None:
            field = _Fp2(p, non_residue)
            group = _Group(field.mul, field.inv, (1, 0))
        else:
            field = _FpK(p, degree, extension_modulus)
            group = _Group(field.mul, field.inv, field.val(1))
        factors = factorize(subgroup_order, deadline)
        if factors is None or _order_in(base, subgroup_order, factors, group) != subgroup_order:
            return None
        scalar = discrete_log(base, target, subgroup_order, group, BSGS_LIMIT_INT, deadline)
    except (ValueError, ZeroDivisionError):
        return None
    if scalar is None or ec_mul(scalar, P, p, a) != Q:
        return None
    return {"scalar": scalar, "embedding_degree": degree, "pairing_base": base,
            "pairing_target": target, "verified": True}


# ---- the never-wrong entry point --------------------------------------------------------------------

def recover_scalar(p, a, b, G, Q, order=None, deadline=None):
    """The private scalar d with [d]G == Q on y^2 = x^3 + ax + b over F_p, or None.

    Tries the singular, anomalous and smooth-order routes and returns the FIRST d that verifies
    ``[d]G == Q`` on the curve. A route whose maths does not reproduce the point contributes
    nothing, so the returned value is always correct; anything unproven is None.
    """
    if not (isinstance(p, int) and p > 3 and isinstance(a, int) and isinstance(b, int)):
        return None
    if deadline is None:
        deadline = time.monotonic() + 5.0     # a backstop; the routes self-bound regardless
    a %= p
    b %= p
    if not (isinstance(G, (tuple, list)) and len(G) == 2 and isinstance(Q, (tuple, list)) and len(Q) == 2):
        return None
    G = (G[0] % p, G[1] % p)
    Q = (Q[0] % p, Q[1] % p)
    if not (on_curve(G, p, a, b) and on_curve(Q, p, a, b)):
        return None
    if G == Q:
        return 1 if ec_mul(1, G, p, a) == Q else None

    singular = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0
    routes = []
    if singular:
        routes.append(("singular", lambda: _singular_scalar(p, a, b, G, Q, deadline)))
    else:
        if order is None or order == p:
            routes.append(("anomalous", lambda: _smart_scalar(p, a, b, G, Q, deadline)))
        if order:
            routes.append(("smooth", lambda: _smooth_scalar(p, a, b, G, Q, order, deadline)))

    for _name, fn in routes:
        if not _left(deadline):
            return None
        try:
            d = fn()
        except (ValueError, ZeroDivisionError, OverflowError):
            d = None
        if d is None:
            continue
        d %= (order or p)
        if ec_mul(d, G, p, a) == Q:
            return d
    return None


def weakness(p, a, b, order=None) -> str:
    """The name of the weakness the parameters show, for labelling only ('singular' | 'anomalous'
    | 'smooth' | ''). Never a claim that d was recovered."""
    if not (isinstance(p, int) and p > 3):
        return ""
    a %= p
    b %= p
    if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0:
        return "singular"
    if order == p:
        return "anomalous"
    if order:
        return "smooth"
    return "anomalous"


# ---- guarded command line -------------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise ValueError(message)


def _load_json(path: str) -> dict:
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds 1 MiB cap")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    """Offline CLI for the two interaction-transcript attacks.

    ``invalid-crt`` consumes ``{"observations": [...], "scalar_bound": ...}``; ``mov`` consumes
    curve parameters plus ``P``, ``Q`` and ``order``.  Inputs are observations already collected by
    the player.  This command performs no request and never probes an oracle or judge.
    """
    parser = _Parser(prog="ecc_weak.py")
    parser.add_argument("operation", choices=("invalid-crt", "mov"))
    parser.add_argument("input", help="bounded JSON transcript/curve description")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        data = _load_json(args.input)
        if args.operation == "invalid-crt":
            result = recover_invalid_curve_scalar(
                data["observations"],
                verification=data.get("verification"),
                scalar_bound=data.get("scalar_bound"),
            )
        else:
            result = mov_frey_ruck_recover(
                int(data["p"]), int(data["a"]), int(data["b"]), data["P"], data["Q"],
                int(data["order"]), embedding=data.get("embedding"),
                auxiliary=data.get("auxiliary"), non_residue=int(data.get("non_residue", -1)),
                extension_modulus=data.get("extension_modulus"),
            )
        output = {"candidate": result, "verified": bool(result and result.get("verified"))}
        if args.json:
            print(json.dumps(output, sort_keys=True))
        else:
            label = "verified" if output["verified"] else "unproven"
            print(f"CANDIDATE [{label}] " + json.dumps(output["candidate"], sort_keys=True))
        return 0
    except (KeyError, OSError, TypeError, ValueError, OverflowError, UnicodeError,
            RecursionError, MemoryError, json.JSONDecodeError) as exc:
        print(f"ecc_weak: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
