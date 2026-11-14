"""Discrete logarithms in Z_p^* (ElGamal / Diffie-Hellman in a weak group), verified-only.

  solve_dlog(p, g, h, ...)        x with pow(g, x, p) == h: Pohlig-Hellman over a (partly) smooth group order,
                                  BSGS or Pollard rho per prime, CRT; the small-subgroup case; Pollard's
                                  kangaroo when the exponent is stated to lie in a small interval
  parse_bound(text)               a stated bound on the exponent ("x < 2^40", "a 32-bit secret")
  dh_shared(...), elgamal_decrypt(...)   the answer paths a question router asks
  read_instance(text), merge_instances(a, b), unread_elements(inst), modelled_spans(text)
                                  what a text states of an instance (the roles alice / bob / client / server kept apart)
  range_claims(text), bound_spans(text)   the range statements of a text WITH their subject (a letter, a party, `the private
                                  key`, or another thing): a range counts for the variable it is about and for no other
  group_order_of(...)             the exact order of g, one full-size exponentiation per prime of p - 1 (a product tree), with a deadline

KB-10 fix round 4: every full-size exponentiation goes through gmpy2 (`_pw`: the builtin pow is 11 times slower at 4096
bits), a wide cofactor is not primality-tested past the deadline, rho checks the deadline every 4096 steps, and a solved
problem is remembered (`_DLOG_CACHE`, verified successes with a known order only). Nothing here decides how sure an answer
is: the toolkit offers every value as a candidate pick (solvers/toolkits/modern_crypto.py, `_dlog_answer`).

The one rule (AGENTS.md "Uncertain answers"): a value is returned ONLY after the in-code check
pow(g, x, p) == h (and, for a Diffie-Hellman secret or an ElGamal plaintext, only for a base that lies in
<g>, which is also checked). Anything else is None: p not prime, g or h outside the group, a prime factor of
the group order too large for the bounded search, the deadline passing. Every function takes a `deadline`
(time.monotonic()) and gives up with None when it passes; DEFAULT_BUDGET (0.5 s) is the cap for one problem
when the caller gives none: the order of g, the cofactor powers, every baby step and every giant step check it, so a 4000-bit
group, a Proth prime p = k * 2^n + 1 or 250 prime factors of p - 1 return (an answer or None) inside the budget; a stated private value
more than PRIV_SLACK_BITS wider than p, or a number of more than MAX_TOKEN_CHARS characters, is never exponentiated or converted.
Memory is bounded (a BSGS table of at most MAX_TABLE entries). No file, network or clock beyond that. gmpy2 is used when installed
(powmod, is_prime, and mpz in the baby-step / giant-step loops: 7 to 10 times faster than a Python int at 1000 to 4000 bits) and is optional.
"""
from __future__ import annotations

import math
import random
import re
import time

try:                                    # optional speed-up; every result is re-checked with pow()
    import gmpy2 as _gm
except Exception:                       # pragma: no cover
    _gm = None

DEFAULT_BUDGET = 0.5                    # seconds for one problem
MAX_TABLE = 1 << 18                     # BSGS baby steps (entries) per prime: a prime up to ~2^36
PRIME_CAP = 1 << 44                     # a prime factor above this is never attempted (rho cannot finish)
SMALL_PRIMES_LIMIT = 1 << 16
MAX_P_BITS = 4096                       # larger moduli are declined outright
KANGAROO_MAX = 1 << 40                  # a wider stated interval cannot be walked in the budget: declined at once
READ_LIMIT = 400000                     # characters of text read_instance reads; a longer text is ambiguous (a statement past it is unseen)

_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)


def _left(deadline) -> bool:
    return deadline is None or time.monotonic() < deadline


def deadline_for(deadline=None, budget: float = DEFAULT_BUDGET):
    """The earlier of the caller's deadline and now + budget."""
    own = time.monotonic() + budget
    return own if deadline is None else min(deadline, own)


_PRIME_CACHE = {}


def is_prime(n: int) -> bool:
    """Miller-Rabin (gmpy2 when installed), cached for the large values a problem asks about again and again."""
    if n < (1 << 64):
        return _is_prime(n)
    hit = _PRIME_CACHE.get(n)
    if hit is None:
        hit = _is_prime(n)
        if len(_PRIME_CACHE) > 64:
            _PRIME_CACHE.clear()
        _PRIME_CACHE[n] = hit
    return hit


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    if _gm is not None:
        return bool(_gm.is_prime(n, 30))
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


_SMALL = None


def _small_primes():
    global _SMALL
    if _SMALL is None:
        sieve = bytearray([1]) * SMALL_PRIMES_LIMIT
        sieve[0:2] = b"\x00\x00"
        for i in range(2, int(SMALL_PRIMES_LIMIT ** 0.5) + 1):
            if sieve[i]:
                sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
        _SMALL = [i for i, v in enumerate(sieve) if v]
    return _SMALL


def _rho_factor(n: int, deadline):
    """A nontrivial factor of the composite n (Brent's variant), or None at the deadline."""
    if n % 2 == 0:
        return 2
    rnd = random.Random(n & 0xFFFFFFFF)
    for _ in range(40):
        c = rnd.randrange(1, n - 1)
        y = rnd.randrange(0, n)
        m = 128
        g = r = q = 1
        x = ys = y
        while g == 1:
            x = y
            todo = r
            while todo > 0:
                chunk = min(todo, 2048)
                for _ in range(chunk):
                    y = (y * y + c) % n
                todo -= chunk
                if not _left(deadline):
                    return None
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
                if not _left(deadline):
                    return None
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
        if not _left(deadline):
            return None
    return None


def partial_factor(n: int, deadline=None):
    """(factors {prime: exponent}, remainder). Trial division by the primes below 2^16, then Brent rho on
    what is left; every prime found is Miller-Rabin proven (of any size: a large proven prime is a factor, even
    though the search will not take its logarithm). The remainder is 1 when n was fully factored; otherwise
    it is the product of the composites rho did not split before the deadline. prod(p^e) * remainder == n."""
    out = {}
    if n < 1:
        return out, 1
    for p in _small_primes():
        if p * p > n:
            break
        if n % p == 0:
            e = 0
            while n % p == 0:
                n //= p
                e += 1
            out[p] = e
        if not _left(deadline):
            break
    rest = 1
    todo = [n] if n > 1 else []
    while todo:
        m = todo.pop()
        if m == 1:
            continue
        if m.bit_length() > 512 and not _left(deadline):
            rest *= m                   # past the deadline a wide cofactor is not even tested (a 4000-bit prime takes 0.09 s): unfactored
            continue
        if is_prime(m):
            out[m] = out.get(m, 0) + 1
            continue
        f = _rho_factor(m, deadline) if _left(deadline) else None
        if not f or f in (1, m):
            rest *= m
            continue
        todo.append(f)
        todo.append(m // f)
    return out, rest


def _crt(residues, moduli):
    x, n = 0, 1
    for r, m in zip(residues, moduli):
        if math.gcd(n, m) != 1:
            return None
        x += n * ((r - x) * pow(n, -1, m) % m)
        n *= m
    return x % n, n


def _pw(b, e, m):
    if _gm is not None:
        return int(_gm.powmod(b, e, m))
    return pow(b, e, m)


def _mp(x):
    """x as a gmpy2 mpz when gmpy2 is installed (its modular multiplication of 1000 to 4000-bit numbers is 7 to 10 times
    faster than a Python int's: the baby-step / giant-step loops of Pohlig-Hellman do hundreds of thousands of them), else x."""
    return _gm.mpz(x) if _gm is not None else x


# ---- a prime-order subgroup: BSGS, then Pollard rho --------------------------------------------------------

def _bsgs(p, gamma, hk, ell, table_cache, deadline):
    """The x in [0, ell) with gamma^x == hk (mod p), gamma of prime order ell, or None. The baby-step table
    of gamma (at most MAX_TABLE entries) is cached per (gamma, ell) so a prime power reuses it."""
    if hk == 1:
        return 0
    m = math.isqrt(ell - 1) + 1
    if m > MAX_TABLE:
        return None
    key = (gamma, ell)
    table = table_cache.get(key)
    pm = _mp(p)
    if table is None:
        table = {}
        e, gm = _mp(1), _mp(gamma)
        for j in range(m):
            if e not in table:
                table[e] = j
            e = e * gm % pm
            if j & 0x3FFF == 0x3FFF and not _left(deadline):
                return None
        table_cache[key] = table
    factor = _mp(_pw(gamma, (ell - 1) * m, p))          # gamma^(-m): gamma has order ell, so gamma^-1 = gamma^(ell-1)
    cur = _mp(hk)
    for i in range(m):
        hit = table.get(cur)
        if hit is not None:
            x = i * m + hit
            return x if x < ell else x % ell
        cur = cur * factor % pm
        if i & 0x3FFF == 0x3FFF and not _left(deadline):
            return None
    return None


def _rho_dlog(p, gamma, hk, ell, deadline):
    """The x with gamma^x == hk by Pollard rho in the subgroup of prime order ell, or None (deadline,
    degenerate walk). Verified by the caller."""
    if hk == 1:
        return 0
    rnd = random.Random(ell ^ hk & 0xFFFFFFFF)

    def step(y, a, b):
        s = y % 3
        if s == 0:
            return y * gamma % p, (a + 1) % ell, b
        if s == 1:
            return y * hk % p, a, (b + 1) % ell
        return y * y % p, a * 2 % ell, b * 2 % ell

    for _ in range(20):
        a0, b0 = rnd.randrange(ell), rnd.randrange(ell)
        y0 = pow(gamma, a0, p) * pow(hk, b0, p) % p
        x, xa, xb = y0, a0, b0
        y, ya, yb = y0, a0, b0
        n = 0
        while True:
            x, xa, xb = step(x, xa, xb)
            y, ya, yb = step(*step(y, ya, yb))
            n += 1
            if x == y:
                break
            if n & 0xFF == 0 and not _left(deadline):      # (three products a step: a 4096-step chunk took 0.39 s at 4096 bits in review; 256 keeps the overrun under ~25 ms)
                return None
        db = (xb - yb) % ell
        if db == 0:
            continue
        cand = (ya - xa) * pow(db, -1, ell) % ell
        if _pw(gamma, cand, p) == hk:
            return cand
    return None


# ---- Pohlig-Hellman ----------------------------------------------------------------------------------------

class Dlog:
    """x: the least non-negative exponent with g^x == h; order: ord(g) when it was determined (None for a
    kangaroo-only result); primitive: ord(g) == p - 1; method: 'pohlig_hellman' | 'kangaroo'."""

    def __init__(self, x, order, primitive, method):
        self.x, self.order, self.primitive, self.method = x, order, primitive, method

    def __repr__(self):  # pragma: no cover
        return f"Dlog(x={self.x}, order={self.order}, primitive={self.primitive}, method={self.method})"


_ORDER_CACHE = {}                       # (p, g, order) -> a determined group order (successes only)
_TREE_CACHE = {}                        # (p, g, ord(g)) -> [g^(ord(g) / q) for each prime power q of it], when group_order_of had them


def _cof_pows(base: int, qs: list, p: int, deadline):
    """[base^(prod(qs) / q) mod p for q in qs] (the cofactor power of every entry), or None when the deadline passes.
    A product tree: the left half is the base raised to the product of the right half and the other way round, so
    the exponents shrink by half at every level and the whole list costs about log2(len(qs)) full-size
    exponentiations, not len(qs) of them (a 4000-bit modulus whose p - 1 has 250 prime factors took 2.3 s one
    factor at a time: review of the KB-10 head 95699e2)."""
    n = len(qs)
    if n == 0:
        return []
    if n == 1:
        return [base % p]
    if not _left(deadline):
        return None
    mid = n // 2
    left, right = qs[:mid], qs[mid:]
    bl = _pw(base, math.prod(right), p)
    if not _left(deadline):
        return None
    got_left = _cof_pows(bl, left, p, deadline)
    if got_left is None:
        return None
    br = _pw(base, math.prod(left), p)
    if not _left(deadline):
        return None
    got_right = _cof_pows(br, right, p, deadline)
    if got_right is None:
        return None
    return got_left + got_right


def group_order_of(p: int, g: int, order=None, deadline=None):
    """(ord(g), primitive, fac, smooth) where fac is the factorisation of ord(g), or None when ord(g) cannot
    be fully determined (a prime factor of the group order above PRIME_CAP, or an unsplit composite, that g does
    not annihilate) or the deadline passes. `order`, when given, is a stated multiple of ord(g): it is checked
    (g^order == 1) and used instead of p - 1. The order is found prime by prime: with q = ell^e exactly dividing
    the group order, t = g^(order / q) has an order that divides q, so its exponent k is the number of times t is
    raised to ell before it reaches 1 (at most e raisings by the small exponent ell): one full-size exponentiation
    per prime (a product tree for all of them) instead of one per factor of ell, which took 15 s for p = 2247 * 2^4000 + 1."""
    ck = (p, g % p, order)
    hit = _ORDER_CACHE.get(ck)
    if hit is not None:
        return hit
    big = p - 1
    if not _left(deadline):
        return None
    if order is not None:
        if order < 2 or order > p or _pw(g, order, p) != 1:
            return None
        big = order
    now = time.monotonic()
    fdl = None if deadline is None else now + 0.5 * max(0.0, deadline - now)    # the rest of the time is for the logarithm
    fac, rest = partial_factor(big, fdl)
    if not _left(deadline):
        return None
    if rest > 1:
        smooth = big // rest
        if _pw(g, smooth, p) != 1:
            return None                      # g needs the unfactored part: out of reach
        big = smooth
    if not _left(deadline):
        return None
    items = sorted(fac.items())
    ts = _cof_pows(g % p, [ell ** e for ell, e in items], p, deadline)
    if ts is None:
        return None
    o, ofac = 1, {}
    for (ell, e), t in zip(items, ts):
        k = 0
        while t != 1:
            if k >= e:
                return None                  # g^big != 1: the group is not what it was said to be
            t = _pw(t, ell, p)
            k += 1
            if k & 0xFF == 0 and not _left(deadline):
                return None
        if k:
            ofac[ell] = k
            o *= ell ** k
    if _pw(g, o, p) != 1:
        return None
    got = (o, (o == p - 1), ofac)
    if len(_ORDER_CACHE) > 64:
        _ORDER_CACHE.clear()
        _TREE_CACHE.clear()
    _ORDER_CACHE[ck] = got
    if o == big:
        _TREE_CACHE[(p, g % p, o)] = ts           # the order is the whole group size: g^(o / q) is g^(big / q), already computed
    return got


def _ph(p, g, h, order, deadline):
    """Pohlig-Hellman: x mod ord(g), or None. h must lie in <g>."""
    info = group_order_of(p, g, order, deadline)
    if info is None:
        return None
    o, primitive, ofac = info
    if o == 1:
        return Dlog(0, 1, False, "pohlig_hellman") if h == 1 else None
    if _pw(h, o, p) != 1:
        return None                          # h is outside <g>
    if ofac and max(ofac) > PRIME_CAP:
        return None                          # a prime factor too large to take a logarithm in
    residues, moduli = [], []
    cache = {}
    items = sorted(ofac.items())
    qs = [ell ** e for ell, e in items]
    gis = _TREE_CACHE.get((p, g, o)) or _cof_pows(g, qs, p, deadline)      # g^(o / q) for every prime power q of o, as a product tree
    his = _cof_pows(h, qs, p, deadline)
    if gis is None or his is None:
        return None
    for (ell, e), gi, hi in zip(items, gis, his):
        pe = ell ** e
        gamma = _pw(gi, ell ** (e - 1), p)
        gi_inv = _pw(gi, pe - 1, p)                         # gi has order pe, so gi^-1 = gi^(pe-1)
        x = 0
        for k in range(e):
            if not _left(deadline):
                return None
            t = hi * _pw(gi_inv, x, p) % p
            hk = _pw(t, ell ** (e - 1 - k), p)
            dk = _bsgs(p, gamma, hk, ell, cache, deadline)
            if dk is None:
                dk = _rho_dlog(p, gamma, hk, ell, deadline) if (math.isqrt(ell - 1) + 1) > MAX_TABLE else None
            if dk is None:
                return None
            x += dk * ell ** k
        residues.append(x)
        moduli.append(pe)
    got = _crt(residues, moduli)
    if got is None:
        return None
    return Dlog(got[0], o, primitive, "pohlig_hellman")


# ---- Pollard's kangaroo (lambda) ---------------------------------------------------------------------------

def kangaroo(p: int, g: int, h: int, lo: int, hi: int, deadline=None):
    """x in [lo, hi] with g^x == h by Pollard's lambda method, or None (not found before the deadline, or no
    such x). Expected ~2*sqrt(hi - lo) group operations, constant memory. Verified by the caller."""
    w = hi - lo
    if w < 0 or w > KANGAROO_MAX:
        return None
    g %= p
    h %= p
    hp = h * pow(g, -lo, p) % p          # x' = x - lo in [0, w]
    if w < 4:
        y = 1
        for x in range(w + 1):
            if y == hp:
                return lo + x
            y = y * g % p
        return None
    K = 32
    mean = max(2, math.isqrt(w) // 2)
    for attempt in range(8):
        rnd = random.Random(w * 31 + attempt)
        jumps = [rnd.randint(max(1, mean // 2), mean * 3 // 2 + 1) for _ in range(K)]
        gj = [_pw(g, s, p) for s in jumps]
        steps = 4 * max(1, math.isqrt(w)) + 64
        y = _pw(g, w, p)                 # tame starts at the top of the interval
        d = w
        for n in range(steps):
            i = y & (K - 1)
            y = y * gj[i] % p
            d += jumps[i]
            if n & 0x3FF == 0x3FF and not _left(deadline):    # every 1024 steps: a 16384-step chunk took 0.45 s at 4096 bits
                return None
        tame_y, tame_d = y, d
        y, d = hp, 0                     # wild starts at the unknown x'
        limit = tame_d - 0 + 1           # past the tame end the wild one can no longer meet it
        n = 0
        while d <= limit:
            if y == tame_y:
                x = tame_d - d
                if 0 <= x <= w and _pw(g, x, p) == hp:
                    return lo + x
                break
            i = y & (K - 1)
            y = y * gj[i] % p
            d += jumps[i]
            n += 1
            if n & 0x3FF == 0 and not _left(deadline):
                return None
        if not _left(deadline):
            return None
    return None


# ---- the public entry --------------------------------------------------------------------------------------

def _usable(p, g, h) -> bool:
    return (isinstance(p, int) and isinstance(g, int) and isinstance(h, int) and 5 <= p and p.bit_length() <= MAX_P_BITS
            and 1 < g % p and 0 < h % p and is_prime(p))


_DLOG_CACHE = {}                        # (p, g, h, order, bound) -> a verified Dlog (successes only: the same problem asked again,
                                        # by another question of the set or an alternative of the same one, costs nothing)


def solve_dlog(p: int, g: int, h: int, order=None, bound=None, deadline=None):
    """Dlog (x, ord(g), primitive, method) with pow(g, x, p) == h verified, or None. `order` is a stated
    multiple of ord(g) (a subgroup order q); `bound` a stated limit x < bound. Never raises, never hangs
    past `deadline` (default 0.5 s from the call); Pohlig-Hellman gets the first 40 % of it, the kangaroo
    the rest. A success is kept (at most 64) and returned again for the same problem."""
    deadline = deadline_for(deadline)
    try:
        if not _usable(p, g, h):
            return None
        g %= p
        h %= p
        ck = (p, g, h, order, bound)
        hit = _DLOG_CACHE.get(ck)
        if hit is not None:
            return hit
        res = _solve_dlog(p, g, h, order, bound, deadline)
        if res is not None and res.order is not None:      # (a kangaroo-only result, order unknown, may depend on the time left)
            if len(_DLOG_CACHE) > 64:
                _DLOG_CACHE.clear()
            _DLOG_CACHE[ck] = res
        return res
    except (ValueError, OverflowError, ZeroDivisionError, MemoryError):
        return None


def _solve_dlog(p: int, g: int, h: int, order, bound, deadline):
    try:
        if not _left(deadline):
            return None
        now = time.monotonic()
        ph_deadline = now + 0.4 * (deadline - now) if bound is not None else deadline
        res = _ph(p, g, h, order, ph_deadline)
        if res is not None and _pw(g, res.x, p) == h:
            return res
        if bound is not None and 1 < bound <= KANGAROO_MAX and _left(deadline):
            x = kangaroo(p, g, h, 0, bound - 1, deadline)
            if x is not None and _pw(g, x, p) == h:
                info = group_order_of(p, g, order, ph_deadline)
                if info is not None and x >= info[0]:
                    return None                  # the stated bound and the group disagree
                return Dlog(x, info[0] if info else None, bool(info and info[1]), "kangaroo")
    except (ValueError, OverflowError, ZeroDivisionError, MemoryError):
        return None
    return None


# ---- a stated bound on the exponent ------------------------------------------------------------------------

_NUM = r"(?:2\s*\^\s*\d{1,3}|2\s*\*\*\s*\d{1,3}|0x[0-9a-fA-F]+|\d+)"
_WHO = (r"(?:(?:private|secret)(?:[ _](?:key|exponent|value|number|scalar|integer))?|(?:secret|private)[ _]exponent|exponent|"
        r"(?:key|x|a|b|k))")
_BOUND_RX = (
    re.compile(r"(?<![A-Za-z0-9_])" + _WHO + r"(?![A-Za-z0-9_])\s*(?:is|are|<=|<|:|\u2264)?\s*(?:<=|<|\u2264|at most|less than|below|under|smaller than)\s*(" + _NUM + ")", re.I),
    re.compile(r"(?<![A-Za-z0-9_])x\s*(?:<=|<|\u2264)\s*(" + _NUM + ")", re.I),
    re.compile(r"\b(?:(?:exponent|secret|private|x|key)[_ ])?(?:bound|upper[_ ]bound)\s*(?:=|:|is)\s*(" + _NUM + ")|"
               r"\bmax(?:imum)?[_ ](?:exponent|x|secret|private[_ ]key)\s*(?:=|:|is)\s*(" + _NUM + ")", re.I),
)
# `N-bit` counts only when the same phrase calls it the private value / exponent / secret (an IV or a block is not)
_BITS_RX = re.compile(r"\b(\d{1,3})[- ]?bits?\s+(?:(?:private|secret)\s+(?:exponent|key|number|integer|value|scalar)|exponent|secret|scalar)\b|"
                      r"\b(?:exponent|secret|private (?:key|exponent|value)|x)\s+(?:is\s+)?(?:only\s+)?(?:an?\s+)?(\d{1,3})[- ]?bits?\b|"
                      r"\b(?:exponent|secret)\s+(?:bits|bit[_ ]length|bit[_ ]size)\s*(?:=|:|is)\s*(\d{1,3})\b", re.I)


def _num(s: str):
    s = s.replace(" ", "")
    if s.startswith("2^"):
        return 1 << int(s[2:])
    if s.startswith("2**"):
        return 1 << int(s[3:])
    return int(s, 16) if s[:2].lower() == "0x" else int(s)


def parse_bound(text: str):
    """A bound B on the exponent (x < B) stated in the text, or None: `x < 2^40`, `exponent at most 10**9`,
    `a 32-bit secret`, `bound = 1048576`. Several different bounds stated -> None (ambiguous)."""
    found = set()
    text = text or ""
    for rx in _BOUND_RX:
        for m in rx.finditer(text):
            try:
                v = _num(next(g for g in m.groups() if g))
            except (ValueError, OverflowError):
                continue
            if v > 1:
                found.add(v)
    for m in _BITS_RX.finditer(text):
        bits = next((g for g in m.groups() if g), None)
        if bits and 2 <= int(bits) <= 64:
            found.add(1 << int(bits))
    return next(iter(found)) if len(found) == 1 else None


# ---- range statements WITH their subject ---------------------------------------------------------------------
# A range counts for the variable it is stated about and for no other (review of 95699e2: `k = randrange(2, p-1)` for the
# ephemeral key, `b < p-1`, or `The sender's private key is less than 2^15` made ANOTHER variable's exponent look unique, and
# its least residue went out plain). range_claims reads each statement with its subject; the router applies only the claims
# whose subject is the asked variable (or a generic `the private key` / `exponents`) and lets any other subject, an unknown
# one included, count for nothing.

_RB_NUM = r"(?:2\s*\^\s*\d{1,4}|2\s*\*\*\s*\d{1,4}|1\s*<<\s*\d{1,4}|0[xX][0-9a-fA-F]+|\d+)"
_RB_SYM = r"(?:[pq]\s*-\s*\d+|[pq]|order|ord\s*\(\s*g\s*\))"
_RB = r"(?:" + _RB_NUM + r"|" + _RB_SYM + r")(?![A-Za-z0-9_])"
_RC_EX = r"(?:<|less\s+than|below|under|smaller\s+than)"
_RC_IN = r"(?:<=|≤|at\s+most|no\s+(?:more|larger|greater|bigger)\s+than|not\s+(?:more|larger|greater)\s+than)"
_RC = r"(?:" + _RC_IN + r"|" + _RC_EX + r")"
_PARTY = r"(?:alice|bob|client|server|sender|receiver|recipient|peer)"
_NP = (r"(?:(?:the|a|an|each|every|all|both|their|its|our|these|those)\s+)?(?:" + _PARTY + r"(?:['’]s)?\s+)?"
       r"(?:(?:private|secret)\s+(?:key|exponent|value|number|scalar|integer)s?|exponents?|secrets?)")
_GAP = (r"(?:is|are|was|were|must|be|should|always|only|just|strictly|chosen|drawn|picked|selected|sampled|generated|taken|random|"
        r"randomly|uniform|uniformly|at|from|in|within|the|range|with|such|that|an|a|integer|value|number|any|bounded|by)")
_F1 = re.compile(r"(?<![A-Za-z0-9_.'’])(?P<s>[a-z])(?![A-Za-z0-9_'’])\s*(?i:(?:(?:is|are)\s+)?)(?P<c>(?i:" + _RC + r"))\s*(?P<b>(?i:" + _RB + r"))")
_F2 = re.compile(r"(?<![A-Za-z0-9_])[01]\s*(?:<=|<|≤)\s*(?P<s>[a-z])(?![A-Za-z0-9_])\s*(?P<c><=|<|≤)\s*(?P<b>(?i:" + _RB + r"))")
_F3 = re.compile(r"(?<![A-Za-z0-9_])(?P<np>(?i:" + _NP + r"))(?P<gap>(?i:(?:\s+" + _GAP + r")*))\s*(?:(?P<l>[a-z])(?![A-Za-z0-9_])\s*)?(?P<c>(?i:" + _RC + r"))\s*(?P<b>(?i:" + _RB + r"))")
_F5L = re.compile(r"(?<![A-Za-z0-9_.'’])(?P<s>[a-z])(?![A-Za-z0-9_'’])\s+(?i:(?:is|are)\s+(?:an?\s+)?)(?P<n>\d{1,4})(?i:[- ]bits?\b)")
_F5P = re.compile(r"(?P<pre>[^.;\n]{0,60}?)(?:an?\s+)?(?P<n>\d{1,4})[- ]bits?\s+(?:(?:private|secret)\s+(?:key|exponent|value|number|integer|scalar)|exponent|secret|scalar)s?\b", re.I)
_CALL = re.compile(r"(?<![A-Za-z0-9_])(?P<fn>randrange|randint|rand_range|random_?int|getrandrange|randbelow|getrandbits|randbits)\s*\(", re.I)
_NOT_PRIV = re.compile(r"(?:shared|common|session|agreed|derived|public|ephemeral|signing|encryption|mac|hmac|nonce|one[- ]time)\s*$", re.I)
_OTHER_NAME = re.compile(r"ephemeral|nonce|session|salt|\biv\b|message|plaintext|commit|blind|random(?:ness)?|\bk\b|\br\b|\bm\b|temp|one[_ ]time", re.I)


def _classify_bound(tok: str, inclusive: bool):
    """(kind, value) of a stated upper bound: 'p1' (every value below p-1), 'p' (below p: values up to p-1), 'q' (below the
    stated order), 'num' (value = the exclusive limit), 'big' (not below the group order) or 'unknown'."""
    t = re.sub(r"\s+", "", tok.lower())
    m = re.fullmatch(r"([pq])-(\d+)", t)
    if m:
        k = int(m.group(2))
        if m.group(1) == "p":
            if inclusive:
                return ("p", None) if k == 1 else ("p1", None) if k >= 2 else ("big", None)
            return ("p1", None) if k >= 1 else ("p", None)
        return ("q", None) if (k >= 1 or not inclusive) else ("big", None)
    if t == "p":
        return ("big", None) if inclusive else ("p", None)
    if t in ("q", "order", "ord(g)"):
        return ("big", None) if inclusive else ("q", None)
    try:
        if t.startswith("2^"):
            v = 1 << int(t[2:])
        elif t.startswith("2**"):
            v = 1 << int(t[3:])
        elif t.startswith("1<<"):
            v = 1 << int(t[3:])
        elif t[:2] == "0x":
            v = int(t, 16)
        else:
            v = int(t)
    except (ValueError, OverflowError):
        return ("unknown", None)
    return ("num", v + 1 if inclusive else v)


def _subject_of(text: str):
    """('party', name) | ('letter', l) | ('generic', None) | ('other', None) | ('unknown', None): whose private value a phrase
    is about. An `other` noun (ephemeral, nonce, session, ...) wins over everything, then a party word."""
    t = (text or "").lower()
    if _OTHER_NAME.search(t) or _NOT_PRIV.search(t):
        return ("other", None)
    m = re.search(r"\b" + _PARTY + r"\b", t)
    if m:
        return ("party", m.group(0))
    m = re.search(r"(?<![A-Za-z0-9_'\u2019])([a-z])(?![A-Za-z0-9_'\u2019])\s*(?:(?:is|are)\s*)?$", t)
    if m and not re.search(r"\b(?:private|secret)\s+(?:key|exponent|value|number|scalar|integer)", t):
        return ("letter", m.group(1))
    if re.search(r"\b(?:private|secret)\s+(?:key|exponent|value|number|scalar|integer)|\bexponents?\b|\bsecrets?\b", t):
        return ("generic", None)
    return ("unknown", None)


def _name_subject(nm: str):
    """The subject of a variable NAME in code: `x`, `a` a letter; `alice_priv` / `bob_secret` a party; `a_priv`, `priv_b`,
    `secretA` that letter's; `secret`, `private_key`, `priv`, `exponent`, `sk` the private key in general; any other name
    (`k`, `nonce`, `r`, `session_key`, `key`) is some other value."""
    toks = [t for t in re.split(r"[_\W]+|(?<=[a-z])(?=[A-Z])", nm) if t]
    low = [t.lower() for t in toks]
    if len(nm) == 1 and nm.islower():
        return ("letter", nm)
    if any(t in ("alice", "bob", "client", "server", "sender", "receiver") for t in low):
        party = next(t for t in low if t in ("alice", "bob", "client", "server", "sender", "receiver"))
        return ("party", party)
    if _OTHER_NAME.search(" ".join(low)):
        return ("other", None)
    privish = any(t in ("priv", "private", "secret", "sk", "exponent", "exp", "key") for t in low) and any(
        t in ("priv", "private", "secret", "sk", "exponent", "exp") for t in low)
    letters = [t for t in toks if len(t) == 1 and t.isalpha()]
    if privish and len(letters) == 1:
        return ("letter", letters[0].lower())
    if privish and not letters:
        return ("generic", None)
    return ("other", None)


def _paren_args(s: str, start: int):
    """The top-level comma-separated arguments of the call whose '(' is at s[start - 1], or None."""
    depth, cur, args = 1, [], []
    for i in range(start, min(len(s), start + 300)):
        c = s[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args
        elif c == "," and depth == 1:
            args.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    return None


# a subject phrase counts as `the private key in general` only when nothing but a conjunction stands before it in its clause:
# `Eve's private key is below p-1` (the NP found is `private key`, after `Eve's`), `the signing private key ...`, `We pick
# private keys below ...` are about another thing or about an unread one, and the review of 95699e2's class of misattribution
# (a statement about one variable applied to another) is exactly this
_CLAUSE_LEAD = re.compile(r"\s*(?:(?:and|but|also|then|so|if|when|that|because|since|while|where|note|hint|here)\b[\s,:]*)*", re.I)


_EPHEMERAL = re.compile(r"\b(?:ephemeral|nonce|session|salt|iv|message|plaintext|commit\w*|blind\w*|randomness|temporary|one[- ]time)\b", re.I)


def _about_other(text: str, pos: int) -> bool:
    """True when the clause before text[pos] is about an ephemeral or other non-private value (`The ephemeral exponent b is drawn
    with b < p-1`: the letter b there is the ephemeral exponent, not Bob's key)."""
    cs = max(text.rfind("\n", 0, pos), text.rfind(". ", 0, pos), text.rfind(";", 0, pos)) + 1
    return _EPHEMERAL.search(text[cs:pos]) is not None


def _anchored(text: str, pos: int) -> bool:
    """True when only a conjunction (or nothing) stands between the start of the clause and text[pos]."""
    cs = max(text.rfind("\n", 0, pos), text.rfind(". ", 0, pos), text.rfind(";", 0, pos), text.rfind(":", 0, pos),
             text.rfind(",", 0, pos), text.rfind("(", 0, pos)) + 1
    return _CLAUSE_LEAD.fullmatch(text[cs:pos]) is not None


def _scan_claims(text: str) -> list:
    """[(start, end, (subject_class, subject_name, kind, value))] for every range statement of the first 20000 characters."""
    text = (text or "")[:20000]
    out = []
    for m in _F1.finditer(text):
        kind, val = _classify_bound(m.group("b"), bool(re.fullmatch(_RC_IN, m.group("c"), re.I)))
        out.append((m.start(), m.end(), ("other" if _about_other(text, m.start()) else "letter", m.group("s").lower(), kind, val)))
    for m in _F2.finditer(text):
        kind, val = _classify_bound(m.group("b"), m.group("c") != "<")
        out.append((m.start(), m.end(), ("other" if _about_other(text, m.start()) else "letter", m.group("s").lower(), kind, val)))
    for m in _F3.finditer(text):
        before = text[max(0, m.start() - 14):m.start()]
        if _NOT_PRIV.search(before):
            out.append((m.start(), m.end(), ("other", None, "unknown", None)))
            continue
        kind, val = _classify_bound(m.group("b"), bool(re.fullmatch(_RC_IN, m.group("c"), re.I)))
        cls, name = _subject_of(m.group("np"))
        if not _anchored(text, m.start()):
            cls, name = "other", None
        out.append((m.start(), m.end(), (cls, name, kind, val)))
    for m in _F5L.finditer(text):
        out.append((m.start(), m.end(), ("other" if _about_other(text, m.start()) else "letter", m.group("s").lower(), "num", 1 << int(m.group("n")))))
    for m in _F5P.finditer(text):
        if re.search(r"(?<![A-Za-z0-9_'\u2019])[a-z]\s+(?:is|are)\s*$", m.group("pre"), re.I):
            continue                                  # `x is a 28-bit exponent`: the letter form above has it
        cls, name = _subject_of(m.group("pre"))
        if cls == "unknown":
            cls = "generic" if _CLAUSE_LEAD.fullmatch(m.group("pre")) else "other"     # `a 32-bit secret` alone, not `Eve picked a 32-bit secret`
        out.append((m.start("n"), m.end(), (cls, name, "num", 1 << int(m.group("n")))))
    for m in _CALL.finditer(text):
        args = _paren_args(text, m.end())
        if not args:
            continue
        fn = m.group("fn").lower().replace("_", "")
        line_start = max(text.rfind("\n", 0, m.start()), text.rfind(". ", 0, m.start()), text.rfind(";", 0, m.start())) + 1
        prefix = text[line_start:m.start()]
        asg = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(?:[A-Za-z_][\w.]*\.)?$", prefix)
        if asg:
            cls, name = _name_subject(asg.group(1))
        else:
            nps = list(re.finditer(_NP, prefix, re.I))
            cls, name = _subject_of(nps[-1].group(0)) if nps else ("unknown", None)
            if nps and (_NOT_PRIV.search(prefix[:nps[-1].start()][-14:]) or not _anchored(prefix, nps[-1].start())):
                cls, name = "other", None
        if fn in ("getrandbits", "randbits"):
            a = re.sub(r"\s+", "", args[0]).lower()
            if re.fullmatch(r"\d{1,4}", a):
                out.append((m.start(), m.end(), (cls, name, "num", 1 << int(a))))
            elif re.search(r"bit_length|bits|\bp\b|p\.|len\(", a):
                out.append((m.start(), m.end(), (cls, name, "big", None)))
            else:
                out.append((m.start(), m.end(), (cls, name, "unknown", None)))
            continue
        ub = args[1] if (len(args) >= 2 and fn != "randbelow") else args[0]
        kind, val = _classify_bound(ub.strip(), fn in ("randint", "randomint"))
        out.append((m.start(), m.end(), (cls, name, kind, val)))
    return out


def range_claims(text: str) -> list:
    """[(subject_class, subject_name, kind, value)] for the range statements of `text` (see _classify_bound for kind).
    Read: `x < 2^40`, `a <= p-1`, `1 < x < p-2`, `The private key is less than p-1`, `Private exponents are chosen with
    x < p-1`, `x is a 28-bit number`, `Alice picked a 32-bit secret`, and the calls `k = randrange(2, p-1)`,
    `a = getrandbits(64)`, `The secret is generated as random.randrange(2, p-1)`. Anything else is no claim."""
    return [c for _, _, c in _scan_claims(text)]


def bound_spans(text: str) -> list:
    """[(start, end)] of the range statements of `text` whose subject is a private value (a letter, a party, `the private
    key`): the statements a question may carry besides its ask without changing what is asked. A call such as
    `randrange(2, p-1)` is code, not a statement, and is not one."""
    return [(a, b) for a, b, c in _scan_claims(text) if c[0] in ("letter", "party", "generic") and not text[a:b].lstrip().lower().startswith(
        ("randrange", "randint", "rand_range", "random", "getrand", "randbelow", "randbits"))]


# ---- the answer paths --------------------------------------------------------------------------------------

PRIV_SLACK_BITS = 64                    # a stated private value more than this many bits wider than p is not tried


def plausible_priv(p: int, v) -> bool:
    """A stated private value worth one exponentiation: a positive integer no wider than p plus PRIV_SLACK_BITS.
    (A labelled blob of a megabyte beside a DH instance made `pow(g, v, p)` take 22 s: review of 95699e2.)"""
    return isinstance(v, int) and not isinstance(v, bool) and v > 0 and v.bit_length() <= p.bit_length() + PRIV_SLACK_BITS


def stated_priv(privs, g: int, p: int, pub: int, deadline=None, limit: int = 16):
    """The first of at most `limit` stated private values that reproduces `pub` (g^v == pub, checked), or None;
    gives up when the deadline passes and skips every value that is not plausible_priv."""
    tried = 0
    for v in privs or ():
        if not plausible_priv(p, v):
            continue
        if tried >= limit or not _left(deadline):
            return None
        tried += 1
        if _pw(g, v, p) == pub:
            return v
    return None


def dh_shared(p, g, A, B, priv_a=None, priv_b=None, order=None, bound=None, deadline=None):
    """(s, how) with s = g^(a*b) mod p, or None. The secret of one side is read from a stated private value
    that reproduces its public value (g^priv == pub), or recovered by solve_dlog; the other side's public value
    is raised to it. Only a base in <g> (pow(base, ord(g)) == 1, or ord(g) == p - 1) is accepted: otherwise the
    exponent's residue class would not fix the result."""
    deadline = deadline_for(deadline)
    try:
        if not (_usable(p, g, A) and _usable(p, g, B)):
            return None
        g %= p
        A %= p
        B %= p
        sides = []
        for pub, other, priv in ((A, B, priv_a), (B, A, priv_b)):
            if plausible_priv(p, priv) and _left(deadline) and _pw(g, priv, p) == pub:
                sides.append((pub, other, priv, "stated"))
        for pub, other, _ in ((A, B, None), (B, A, None)):
            if not any(s[0] == pub for s in sides):
                sides.append((pub, other, None, "dlog"))
        for pub, other, priv, how in sides:
            if not _left(deadline):
                return None
            order_g = None
            if priv is None:
                res = solve_dlog(p, g, pub, order=order, bound=bound, deadline=deadline)
                if res is None:
                    continue
                priv, order_g = res.x, res.order
                if order_g is None:          # kangaroo-only: the order of g is unknown, so is <g> membership
                    info = group_order_of(p, g, order, deadline)
                    order_g = info[0] if info else None
                    if order_g is None:
                        continue
            else:
                info = group_order_of(p, g, order, deadline)
                order_g = info[0] if info else None
                if order_g is None:
                    continue
            if _pw(other, order_g, p) != 1:
                continue                     # the other public value is outside <g>
            return _pw(other, priv, p), how
        return None
    except (ValueError, OverflowError, ZeroDivisionError, MemoryError):
        return None


def elgamal_decrypt(p, g, h, c1, c2, priv=None, order=None, bound=None, deadline=None):
    """(m, how) with m = c2 * c1^(-x) mod p, where g^x == h is verified and c1 lies in <g> (so the residue
    class of x fixes the value), or None. When x is out of reach, a recoverable ephemeral exponent k
    (g^k == c1 verified) gives the same m = c2 * h^(-k) for an h in <g>."""
    deadline = deadline_for(deadline)
    try:
        if not (_usable(p, g, h) and 0 < c1 % p and 0 < c2 % p):
            return None
        g %= p
        h %= p
        c1 %= p
        c2 %= p
        info = group_order_of(p, g, order, deadline)
        if info is None:
            return None
        o = info[0]
        if _pw(c1, o, p) != 1 or _pw(h, o, p) != 1:
            return None
        x, how = None, "dlog"
        if plausible_priv(p, priv) and _left(deadline) and _pw(g, priv, p) == h:
            x, how = priv, "stated"
        else:
            res = solve_dlog(p, g, h, order=order, bound=bound, deadline=deadline)
            if res is not None and _pw(g, res.x, p) == h:
                x = res.x
        if x is not None:
            return c2 * pow(_pw(c1, x, p), -1, p) % p, how
        k = solve_dlog(p, g, c1, order=order, bound=bound, deadline=deadline)
        if k is not None and _pw(g, k.x, p) == c1:
            return c2 * pow(_pw(h, k.x, p), -1, p) % p, "ephemeral"
        return None
    except (ValueError, OverflowError, ZeroDivisionError, MemoryError):
        return None


# ---- reading an instance from text (case-preserving: A and a are different labels) --------------------------

_NUMTOK = r"(?:0[xX][0-9a-fA-F]+|\d+)"
# A number that goes on as an expression (`7 * 2**26 + 1`, `2^255 - 19`, `10**9 + 7`, `2 ** 3`), as a digit group
# (`1,000,003`, `1 000 003`, `23 45`, `2.5`), as an ellipsis or onto an indented next line (a wrapped modulus) is not the
# value of its first piece: it is never read as one (review round 2: `p = 7 * 2**26 + 1` was read as p = 7 and `g = 2 ** 3`
# as g = 2, and a verified-looking logarithm of the wrong problem went out as a plain answer). Blanks only inside a line
# (a bullet list's next line may start with a dash).
_CONT = (r"(?![ \t]*(?:\*|\^|/|%|<<|>>|[×·⋅∙²³¹⁰-⁹]|[-+][ \t]*[0-9A-Za-z_(]"
         r"|\.\d|\.\.|…|,\d{3}(?!\d)|[ \t]\d)|[ \t]*\r?\n[ \t]+[0-9A-Fa-f]{8})")
_LV = re.compile(r"(?<![A-Za-z0-9_^*])[\"']?([A-Za-z][A-Za-z0-9_ ]{0,28}?)[\"']?\s*(?::=|=|:)\s*[\"']?(" + _NUMTOK + r")[\"']?(?![0-9A-Za-z_])" + _CONT)
_PAIR = re.compile(r"(?<![A-Za-z0-9_^*])[\"']?([A-Za-z][A-Za-z0-9_ ]{0,28}?)[\"']?\s*(?::=|=|:)\s*[\(\[]\s*(" + _NUMTOK + r")\s*,\s*(" + _NUMTOK + r")\s*[\)\]]")
MAX_TOKEN_CHARS = 1400                  # a number written with more digits than this is no value of ours (4096 bits are 1234 digits)
MAX_PRIVS = 64                          # stated private values kept per text

# The roles stay APART (review of 95699e2): `client` and `server` are slots of their own, never the A / B slots, because
# a transcript may print the server's value first under the bare label A (client := A was a guess, and the client's
# exponent went out plain as the server's key).
P_LABELS = ("p", "prime", "modulus", "mod", "field_prime", "group_prime", "dh_prime", "safe_prime", "group_modulus", "prime_modulus")
G_LABELS = ("g", "generator", "base", "alpha", "gen", "group_generator", "dh_generator")
ORDER_LABELS = ("q", "order", "subgroup_order", "group_order", "ord_g", "prime_order")
PUB_A = ("a_pub", "a_public", "pub_a", "public_a", "pk_a", "alice_pub", "alice_public", "alice_public_key", "alice_pubkey",
         "alice_public_value", "alice_pk", "ya", "y_a", "a_public_key", "alice_sends", "alice_sent")
PUB_B = ("b_pub", "b_public", "pub_b", "public_b", "pk_b", "bob_pub", "bob_public", "bob_public_key", "bob_pubkey",
         "bob_public_value", "bob_pk", "yb", "y_b", "b_public_key", "bob_sends", "bob_sent")
PUB_CLIENT = ("client_public", "client_public_key", "client_pub", "client_pk", "client_pubkey", "client_public_value",
              "client_sends", "client_sent", "pub_client", "public_client")
PUB_SERVER = ("server_public", "server_public_key", "server_pub", "server_pk", "server_pubkey", "server_public_value",
              "server_sends", "server_sent", "pub_server", "public_server")
PUB_ONE = ("h", "y", "public", "pub", "public_key", "pubkey", "pk", "public_value", "beta", "target", "elgamal_public",
           "elgamal_public_key")
C1_LABELS = ("c1", "c_1", "ct1", "ciphertext_1", "ciphertext1", "gamma", "ephemeral", "ephemeral_key", "ephemeral_public")
C2_LABELS = ("c2", "c_2", "ct2", "ciphertext_2", "ciphertext2", "delta", "masked", "masked_message")
CT_PAIR = ("ciphertext", "ct", "cipher", "enc", "encrypted", "c")
ROLE_RAW = ("A", "B", "X_a", "X_b", "Y", "X")      # the case-sensitive labels of a public value
MODEL_SINGLE = frozenset(P_LABELS + G_LABELS + ORDER_LABELS + PUB_A + PUB_B + PUB_CLIENT + PUB_SERVER + PUB_ONE
                         + C1_LABELS + C2_LABELS)       # labels the reader takes ONE number from
MODEL_PAIR = frozenset(CT_PAIR)                         # labels it takes a (c1, c2) pair from: `C = 5` alone is no ciphertext
MODEL_NORMS = MODEL_SINGLE | MODEL_PAIR
# a JSON key that names a role: the keys below it belong to that role (`{"server": {"public": 5}}` is `server_public`)
ROLE_KEYS = frozenset(("alice", "bob", "client", "server", "sender", "receiver", "recipient", "peer", "initiator", "responder",
                       "a", "b", "party_a", "party_b", "user_a", "user_b"))


def _norm(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")


def _ival(tok: str):
    """The integer a token writes (decimal or 0x hex), or None; a token of more than MAX_TOKEN_CHARS characters is never
    converted (a labelled megabyte of hex next to a DH instance made the reader and the exponentiation after it take 22 s)."""
    if len(tok) > MAX_TOKEN_CHARS:
        return None
    try:
        return int(tok, 16) if tok[:2].lower() == "0x" else int(tok)
    except ValueError:
        return None


def _json_pairs(text: str):
    import json
    s = text.strip()
    if s[:1] not in "{[":
        return None
    try:
        doc = json.loads(s)
    except (ValueError, RecursionError):               # (a text of 3000 nested brackets is no JSON of ours: read as text)
        return None
    out, pairs, big = [], [], []

    def labelled(name, role):
        # the parent key carries the owner of what is below it: {"server": {"A": 5}} is `server_A`, which no slot reads
        # (it is neither Alice's A nor Bob's B); {"server": {"public": 5}} is `server_public`
        if role is None:
            return name
        n = _norm(name)
        return name if (n == role or n.startswith(role + "_")) else f"{role}_{name}"

    def walk(node, name=None, role=None):
        if isinstance(node, dict):
            for k, v in node.items():
                kn = _norm(str(k))
                walk(v, str(k), kn if (kn in ROLE_KEYS and isinstance(v, (dict, list))) else role)
        elif isinstance(node, list):
            if name is not None and len(node) == 2 and all(isinstance(v, int) and not isinstance(v, bool) for v in node):
                pairs.append((labelled(name, role), node[0], node[1]))
            else:
                for v in node:
                    walk(v, name, role)
        elif name is not None and not isinstance(node, bool):
            if isinstance(node, int):
                out.append((labelled(name, role), node))
            elif isinstance(node, str) and re.fullmatch(_NUMTOK, node.strip()):
                v = _ival(node.strip())
                if v is None:
                    big.append(labelled(name, role))
                else:
                    out.append((labelled(name, role), v))

    try:
        walk(doc)
    except RecursionError:
        return None
    return out, pairs, big


def read_instance(text: str) -> dict:
    """What a text states of a prime-field instance: {p, g, order, pubs: {'a','b','client','server','one'}: value,
    privs: [int], c1, c2, ambiguous: [what], third, raw, pairs}. Each quantity is read only when every label for it
    carries ONE distinct value; conflicting labels leave it None (never guessed) and name it under `ambiguous`.
    `raw` and `pairs` are every labelled number and number pair of the text (the router's check for a group element
    the instance does not model)."""
    oversize = len(text or "") > READ_LIMIT
    text = (text or "")[:READ_LIMIT]
    raw = []                                  # (raw label, int)
    pairs = []                                # (raw label, int, int)
    big = []                                  # labels whose value is too long to be one of ours
    js = _json_pairs(text)
    if js is not None:
        raw, pairs, big = js
    else:
        for m in _LV.finditer(text):
            v = _ival(m.group(2))
            if v is not None:
                raw.append((m.group(1).strip(), v))
            elif len(m.group(2)) > MAX_TOKEN_CHARS:
                big.append(m.group(1).strip())
        for m in _PAIR.finditer(text):
            a, b = _ival(m.group(2)), _ival(m.group(3))
            if a is not None and b is not None:
                pairs.append((m.group(1).strip(), a, b))
            elif max(len(m.group(2)), len(m.group(3))) > MAX_TOKEN_CHARS:
                big.append(m.group(1).strip())
    by_norm, by_raw = {}, {}
    for lab, v in raw:
        by_norm.setdefault(_norm(lab), []).append(v)
        by_raw.setdefault(lab, []).append(v)
    amb = []
    if oversize:
        # past the read limit nothing is read, so a second or conflicting statement there would go unseen: not answered
        amb.append("oversize")
    if any(_SIBLING.fullmatch(n) for n in by_norm):
        # a numbered sibling of the group's own labels (`A2`, `B_2`, `p2`, `g_2`, `alice_public_2`): the text states more
        # than one instance (a second exchange) and which one a question means is not read. Never the unnumbered first.
        amb.append("numbered")
    if any(_norm(lab) in MODEL_NORMS or lab in ROLE_RAW for lab in big):
        # a modelled quantity written with a number too long to read: it may be a second, conflicting statement of it
        amb.append("oversize_value")

    def one(what, labels, raw_labels=()):
        vals = []
        for lab in labels:
            vals += by_norm.get(lab, [])
        for lab in raw_labels:
            vals += by_raw.get(lab, [])
        vals = list(dict.fromkeys(vals))
        if len(vals) > 1:
            amb.append(what)
            return None
        return vals[0] if vals else None

    inst = {"p": one("p", P_LABELS), "g": one("g", G_LABELS), "order": one("order", ORDER_LABELS)}
    pubs = {"a": one("pub_a", PUB_A, ("A", "X_a")), "b": one("pub_b", PUB_B, ("B", "X_b")),
            "client": one("pub_client", PUB_CLIENT), "server": one("pub_server", PUB_SERVER),
            "one": one("pub", PUB_ONE, ("Y", "X"))}
    inst["pubs"] = {k: v for k, v in pubs.items() if v is not None}
    privs = []
    for lab, v in raw:
        n = _norm(lab)
        if re.search(r"priv|secret|exponent", n) or lab in ("a", "b", "x"):
            privs.append(v)
    inst["privs"] = list(dict.fromkeys(privs))[:MAX_PRIVS]
    c1, c2 = one("c1", C1_LABELS), one("c2", C2_LABELS)
    if c1 is None or c2 is None:
        cp = list(dict.fromkeys((a, b) for lab, a, b in pairs if _norm(lab) in CT_PAIR))
        if len(cp) == 1:
            c1, c2 = cp[0]
        elif len(cp) > 1:
            amb.append("ciphertext")
    inst["c1"], inst["c2"] = c1, c2
    inst["ambiguous"] = amb
    inst["third"] = sorted({lab for lab, _ in raw if lab in THIRD_RAW or THIRD_NORM.search(_norm(lab))}
                           | {lab for lab, _, _ in pairs if THIRD_NORM.search(_norm(lab))})
    inst["raw"] = raw
    inst["pairs"] = pairs
    return inst


_SIBLING = re.compile(r"(?:p|prime|modulus|g|generator|a|b|h|y|[ab]_pub(?:lic)?|pub(?:lic)?_[ab]|pk_[ab]|"
                      r"alice_pub(?:lic)?(?:_key|_value)?|bob_pub(?:lic)?(?:_key|_value)?|client_pub(?:lic)?|server_pub(?:lic)?)_?\d+"
                      r"|c_?[12]_?\d+")                  # (c1_2, c2_2: a second ciphertext; a bare c1 / c2 is not one)
THIRD_RAW = ("C", "E", "M", "Z", "X_c", "X_e", "X_m")
THIRD_NORM = re.compile(r"(?:^|_)(?:eve|mallory|mallet|carol|charlie|dave|trudy|attacker|adversary|eavesdropper|mitm|third|"
                        r"party_?c|user_?c|c_pub\w*|pub_?c|public_?c|pk_?c|yc|y_c)(?:_|$)")


def _label_rx(labels):
    return re.compile(r"(?<![A-Za-z0-9_])[\"']?(?:" + "|".join(lab.replace("_", "[ _]") for lab in labels) + r")[\"']?\s*(?::=|=|:)", re.I)


_HAS_P, _HAS_G = _label_rx(P_LABELS), _label_rx(G_LABELS)


def may_state_group(text: str) -> bool:
    """A cheap superset test: does the text carry a label for a prime AND one for a generator at all? (One regex
    pass each, no number parsing: a 500 KB log of other fields is declined before read_instance is run on it.)"""
    text = (text or "")[:READ_LIMIT]
    return _HAS_P.search(text) is not None and _HAS_G.search(text) is not None


def merge_instances(a: dict, b: dict) -> dict:
    """The instance two texts state together (the material's, parsed once, and one question's own words): a
    quantity stated by both with different values is ambiguous (None), as inside one text."""
    out = {"ambiguous": list(dict.fromkeys(a["ambiguous"] + b["ambiguous"]))}
    for k in ("p", "g", "order"):
        va, vb = a[k], b[k]
        if va is not None and vb is not None and va != vb:
            out[k] = None
            if k not in out["ambiguous"]:
                out["ambiguous"].append(k)
        else:
            out[k] = va if va is not None else vb
    pubs = dict(a["pubs"])
    for k, v in b["pubs"].items():
        if k in pubs and pubs[k] != v:
            pubs.pop(k)
            out["ambiguous"].append("pub_" + k)
        else:
            pubs.setdefault(k, v)
    out["pubs"] = pubs
    out["privs"] = list(dict.fromkeys(a["privs"] + b["privs"]))[:MAX_PRIVS]
    pair_a, pair_b = (a["c1"], a["c2"]), (b["c1"], b["c2"])
    if None not in pair_a and None not in pair_b and pair_a != pair_b:
        out["c1"] = out["c2"] = None
        out["ambiguous"].append("ciphertext")
    else:
        out["c1"], out["c2"] = pair_a if None not in pair_a else pair_b
    out["third"] = sorted(set(a.get("third", [])) | set(b.get("third", [])))
    out["raw"] = list(a.get("raw", [])) + list(b.get("raw", []))
    out["pairs"] = list(a.get("pairs", [])) + list(b.get("pairs", []))
    return out


def unread_elements(inst: dict) -> list:
    """Labels of the numbers a text states that look like GROUP ELEMENTS (below p and about as wide as p) under a label the
    instance does not model: a Pedersen commitment `C = g^m h^r`, a second ciphertext, a third party's value, a value under a
    label nobody reads (`T`, `commit`, `u`). A question that asks for 'the discrete log' or 'the secret value' may mean
    that element's, so a router that answers from the one public value it did read has no proof which one is asked
    (review of 95699e2: `What is the secret value?` over a Pedersen file gave log_g(h), and the truth was m). Private-looking
    labels (a stated private value is only ever used when g^v reproduces a public value) and values equal to a modelled one
    are not counted; an element must have at least 32 bits and three quarters of p's bits, so counters, ports, hashes and
    ids do not count."""
    p = inst.get("p")
    if not isinstance(p, int) or p < 2:
        return []
    lo = max(32, (3 * p.bit_length() + 3) // 4)
    known = {v for v in (inst.get("p"), inst.get("g"), inst.get("order"), inst.get("c1"), inst.get("c2")) if v is not None}
    known |= set(inst.get("pubs", {}).values()) | set(inst.get("privs", ()))
    out = set()
    for lab, v in inst.get("raw", ()):
        n = _norm(lab)
        if n in MODEL_SINGLE or lab in ROLE_RAW or re.search(r"priv|secret|exponent", n) or lab in ("a", "b", "x"):
            continue
        if 2 < v < p and v.bit_length() >= lo and v not in known:
            out.add(lab)
    for lab, a, b in inst.get("pairs", ()):
        if _norm(lab) in MODEL_PAIR:
            continue
        if any(2 < v < p and v.bit_length() >= lo and v not in known for v in (a, b)):
            out.add(lab)
    return sorted(out)


def modelled_spans(text: str) -> list:
    """[(start, end)] of the `label = number` and `label = (number, number)` statements of `text` whose label is one the
    instance reader models (p, g, q, a public value, a ciphertext, a stated private value): a question that restates
    its own parameters inline is reading them, not asking about them."""
    out = []
    for m in _LV.finditer(text or ""):
        n = _norm(m.group(1))
        if n in MODEL_SINGLE or m.group(1).strip() in ROLE_RAW or re.search(r"priv|secret|exponent", n) or m.group(1).strip() in ("a", "b", "x"):
            out.append((m.start(), m.end()))
    for m in _PAIR.finditer(text or ""):
        if _norm(m.group(1)) in MODEL_PAIR:
            out.append((m.start(), m.end()))
    return out
