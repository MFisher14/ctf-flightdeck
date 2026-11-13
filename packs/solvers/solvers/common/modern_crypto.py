#!/usr/bin/env python3
"""Modern crypto: the maths and the readers (toolkit `modern_crypto`; the question side is
solvers/toolkits/modern_crypto.py).

Everything here is offline, standard-library integers first; `gmpy2` only makes it faster, and
`cryptography` / pycryptodome are imported inside the functions that need them (key files, AES,
DES, ChaCha20), so the module loads with nothing but Python.

The one rule (AGENTS.md, "Uncertain answers"): an attack answers only when its precondition is
PROVEN from the inputs, and says None otherwise. A root must be exact, a gcd above 1, a
convergent must factor n, a factorisation must multiply back to n, a recovered nonce must
reproduce r, a recovered generator must reproduce an output it was not built from. Nothing here
scores "how English" a text looks: whether a plaintext is the answer is the caller's proof
(the question's pattern, a crib, the stated grammar).

Readers
  read_params(text)            labelled integers in text or JSON: n, e, d, p, q, c, dp, dq, phi,
                               r, s, z ... (hex or decimal, n1/n2/..., lists)
  read_fields(text)            labelled strings (key, iv, nonce, ciphertext, ...) as written
  read_keys(data)              PEM, DER, JWK, OpenSSH: RSA and EC numbers
  blobs(value)                 the byte strings a written value may mean (hex, base64, raw)
  find_jwts(text), jwt_parts   JSON Web Tokens

RSA
  rsa_private(P)               (n, d, factors, how) from any sufficient subset of parameters
  rsa_attack(P, deadline)      the proven attacks, in order of cost
  iroot, small_e_root, common_modulus, shared_primes, wiener, fermat, pollard_rho, pollard_p1,
  hastad, dp_leak, factor, consistency, repair_digit, rsa_messages

XOR and ciphers
  xor, xor_crib, keystream_reuse, crib_drag, sym_candidates (AES/DES/3DES/RC4/ChaCha20 with a
  stated key), ecb_duplicates

Signatures and generators
  ecdsa_nonce_reuse (secp256k1, P-256), mt_untemper, mt_clone, lcg_recover, hash_candidates,
  glibc_rand_outputs / glibc_seed_recover (srand+rand forward model, B-135)
  MT19937 backwards (B-063): mt_untwist (inverse twist), mt_extend, mt_rewind, mt_runs (the
  >= 624-word stretches of a word list that are MT19937), mt_seed_from_state, mt_seed_search
"""
import base64
import binascii
import hashlib
import hmac
import itertools
import json
import math
import re
import time
from collections.abc import Sequence

try:                                    # optional speed; every function works without it
    import gmpy2
except Exception:                       # pragma: no cover
    gmpy2 = None


# ---- integers --------------------------------------------------------------------------------------

def _left(deadline) -> bool:
    return deadline is None or time.monotonic() < deadline


def iroot(n: int, k: int):
    """(floor of the k-th root of n, True when it is exact). n >= 0, k >= 1."""
    if n < 0 or k < 1:
        raise ValueError("iroot of a negative number or a root below 1")
    if n < 2 or k == 1:
        return n, True
    if gmpy2 is not None:
        r, exact = gmpy2.iroot(gmpy2.mpz(n), k)
        return int(r), bool(exact)
    if k == 2:
        r = math.isqrt(n)
        return r, r * r == n
    x = 1 << -(-n.bit_length() // k)            # at or above the root
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            break
        x = y
    return x, x ** k == n


def egcd(a: int, b: int):
    """(g, x, y) with a*x + b*y == g."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inverse(a: int, m: int):
    """a^-1 mod m, or None when gcd(a, m) != 1."""
    try:
        return pow(a, -1, m)
    except ValueError:
        return None


def crt(residues, moduli):
    """(x, N) with x = r_i mod m_i; None unless the moduli are pairwise coprime."""
    x, n = 0, 1
    for r, m in zip(residues, moduli):
        if math.gcd(n, m) != 1:
            return None
        x += n * ((r - x) * pow(n, -1, m) % m)
        n *= m
    return x % n, n


def to_bytes(m: int) -> bytes:
    return m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")


def to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


_SMALL = None
TRIAL_BOUND = 1 << 20               # every prime below it is tried on a modulus (about 82,000 divisions, 30 ms)
FR_MAX_E = 17                       # Franklin-Reiter poly-gcd degree cap (covers e = 3, 5, 7, 11, 13, 17)


def small_primes(limit: int = 10000):
    global _SMALL
    if _SMALL is None or _SMALL[0] < limit:
        sieve = bytearray([1]) * (limit + 1)
        sieve[:2] = b"\0\0"
        for i in range(2, math.isqrt(limit) + 1):
            if sieve[i]:
                sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
        _SMALL = (limit, [i for i, v in enumerate(sieve) if v])
    return [p for p in _SMALL[1] if p <= limit]


_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89)
_MR_EXACT_BOUND = 3317044064679887385961981  # bases through 41 are deterministic below this value
_PRIME_CACHE_MAX = 64
_PRIME_CACHE = {}


def _miller_rabin(n: int) -> bool:
    """The original pure-Python first-24-prime Miller-Rabin test."""
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


def _large_is_prime(n: int) -> bool:
    """Probable-prime test for values above the deterministic Miller-Rabin range."""
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    if gmpy2 is not None:
        try:
            return bool(gmpy2.is_prime(n, 30))
        except Exception:
            pass
    return _miller_rabin(n)


def is_prime(n: int) -> bool:
    """Exact Miller-Rabin below 3.3e24; cached 30-round gmpy2 above it when available.

    The optional fast path changes no result below the documented deterministic bound.  A missing
    or unusable gmpy2 falls back to the former pure-Python first-24-prime test.
    """
    if n < _MR_EXACT_BOUND:
        return _miller_rabin(n)
    if n in _PRIME_CACHE:
        return _PRIME_CACHE[n]
    result = _large_is_prime(n)
    if len(_PRIME_CACHE) >= _PRIME_CACHE_MAX:
        _PRIME_CACHE.pop(next(iter(_PRIME_CACHE)))
    _PRIME_CACHE[n] = result
    return result


# ---- factoring, each with its own proof (the factors multiply back to n) -----------------------------

def fermat(n: int, deadline=None, max_steps: int = 2_000_000):
    """(p, q) with p*q == n for close primes, else None."""
    if n < 4 or n % 2 == 0:
        return (2, n // 2) if n >= 4 and n % 2 == 0 else None
    a, exact = iroot(n, 2)
    if exact:
        return a, a
    a += 1
    b2 = a * a - n
    for step in range(max_steps):
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            return (p, q) if p > 1 and p * q == n else None
        b2 += 2 * a + 1
        a += 1
        if step & 1023 == 1023 and not _left(deadline):
            return None
    return None


def pollard_rho(n: int, deadline=None):
    """A non-trivial factor of a composite n (Brent's cycle), else None when time runs out."""
    if n % 2 == 0:
        return 2
    for c in (1, 3, 5, 7, 11):
        y, r, q, g = 2, 1, 1, 1
        x = ys = y
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(128, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += 128
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
    return None


def pollard_p1(n: int, bound: int = 100_000, deadline=None):
    """A factor p of n whose p-1 is `bound`-smooth, else None."""
    a = 2
    for i, p in enumerate(small_primes(bound)):
        a = pow(a, p ** max(1, int(math.log(bound, p))), n)
        if i & 63 == 63:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
            if g == n or not _left(deadline):
                return None
    g = math.gcd(a - 1, n)
    return g if 1 < g < n else None


def factor(n: int, deadline=None):
    """The prime factors of n with multiplicity, ascending, or None when they were not all found
    in time. Proven: every factor passes is_prime and their product is n."""
    if n < 2:
        return None
    out, todo = [], [n]
    while todo:
        m = todo.pop()
        if m == 1:
            continue
        if is_prime(m):
            out.append(m)
            continue
        f = None
        for p in small_primes(10000):
            if m % p == 0:
                f = p
                break
        if f is None:
            for k in (2, 3, 5, 7, 11, 13):
                r, exact = iroot(m, k)
                if exact:
                    todo.extend([r] * k)
                    f = 0
                    break
            if f == 0:
                continue
        if f is None:
            got = fermat(m, deadline, max_steps=200_000)
            f = got[0] if got and got[0] > 1 else None
        if f is None and m.bit_length() <= 140:
            f = pollard_rho(m, deadline)
        if f is None:
            f = pollard_p1(m, 100_000, deadline)
        if f is None and m.bit_length() <= 200:
            f = pollard_rho(m, deadline)
        if not f or f in (1, m) or m % f:
            return None
        todo.extend([f, m // f])
    out.sort()
    prod = 1
    for p in out:
        prod *= p
    return out if prod == n else None


def phi_of(factors) -> int:
    phi, seen = 1, {}
    for p in factors:
        seen[p] = seen.get(p, 0) + 1
    for p, k in seen.items():
        phi *= (p - 1) * p ** (k - 1)
    return phi


# ---- RSA attacks -------------------------------------------------------------------------------------

def small_e_root(c: int, e: int, n: int = None, max_k: int = 0, deadline=None):
    """m with m^e == c + k*n exactly for some 0 <= k <= max_k (k > 0 needs n); else None."""
    if e < 2 or e > 257 or c < 0:
        return None
    for k in range(max_k + 1 if n else 1):
        r, exact = iroot(c + k * (n or 0), e)
        if exact and r > 1:
            return r
        if k & 31 == 31 and not _left(deadline):
            return None
    return None


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int):
    """m from two encryptions of one message under one modulus and two exponents. When
    gcd(e1, e2) = g > 1 the result is m^g mod n, answered only if its g-th root is exact."""
    if e1 == e2:
        return None
    g, a, b = egcd(e1, e2)
    try:
        mg = pow(c1, a, n) * pow(c2, b, n) % n
    except ValueError:                  # a ciphertext shares a factor with n
        return None
    if g == 1:
        return mg
    if g < 0:
        return None
    r, exact = iroot(mg, g)
    return r if exact and r > 1 else None


def shared_primes(moduli):
    """{index: (p, q)} for every modulus that shares a prime with another one (gcd > 1)."""
    out = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            a, b = moduli[i], moduli[j]
            if a == b:
                continue
            g = math.gcd(a, b)
            if 1 < g < a and 1 < g < b:
                out.setdefault(i, (g, a // g))
                out.setdefault(j, (g, b // g))
    return out


def wiener(n: int, e: int):
    """(d, p, q) when a convergent of e/n gives a phi that factors n; else None."""
    a, b = e, n
    h0, h1, k0, k1 = 0, 1, 1, 0
    while b:
        qt = a // b
        a, b = b, a - qt * b
        h0, h1 = h1, qt * h1 + h0       # k / d convergents: h = k, k = d
        k0, k1 = k1, qt * k1 + k0
        k, d = h1, k1
        if k == 0 or d <= 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        t = math.isqrt(disc)
        if t * t == disc and (s + t) % 2 == 0:
            p, q = (s - t) // 2, (s + t) // 2
            if p > 1 and p * q == n:
                return d, p, q
    return None


def hastad(pairs, e: int):
    """m from [(n_i, c_i)] of one message under one small e: CRT, then an exact e-th root."""
    pairs = list(dict.fromkeys(pairs))
    if len(pairs) < 2 or e < 2 or e > 257:
        return None
    got = crt([c for _, c in pairs], [n for n, _ in pairs])
    if got is None:
        return None
    r, exact = iroot(got[0], e)
    return r if exact and r > 1 else None


def dp_leak(n: int, e: int, dp: int, max_e: int = 1 << 22):
    """(p, q) from n, e and d mod (p-1): e*dp - 1 = k*(p-1) for some k < e."""
    if e > max_e or dp <= 0:
        return None
    x = e * dp - 1
    for k in range(1, e + 1):
        if x % k == 0:
            p = x // k + 1
            if 1 < p < n and n % p == 0:
                return p, n // p
    return None


def factor_from_d(n: int, e: int, d: int):
    """(p, q) from a full key pair, or None."""
    k = e * d - 1
    if k <= 0 or k % 2:
        return None
    t = k
    while t % 2 == 0:
        t //= 2
    for g in _MR_BASES:
        x = pow(g, t, n)
        while x not in (1, n - 1):
            y = x * x % n
            if y == 1:
                p = math.gcd(x - 1, n)
                if 1 < p < n:
                    return tuple(sorted((p, n // p)))
                break
            if y == n - 1:
                break
            x = y
    return None


def factor_from_phi(n: int, phi: int):
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    t = math.isqrt(disc)
    if t * t != disc or (s + t) % 2:
        return None
    p, q = (s - t) // 2, (s + t) // 2
    return (p, q) if p > 1 and p * q == n else None


# ---- fault and related-message RSA (each self-verifying) --------------------------------------------
# These three recover a factor, a full key or a message and prove it on the spot: the Bellcore factor
# divides n, the multi-prime factors multiply back to n and d decrypts a probe, the Franklin-Reiter
# message re-encrypts to its ciphertext. A wrong reading of the inputs cannot pass these checks, so a
# caller may trust what they return and must treat None as "not proven" (never a guess).

def bellcore(m: int, e: int, n: int, sig: int):
    """One prime factor of n from a faulty CRT-RSA signature (the Bellcore attack). A correct
    signature s has s**e == m (mod n); a signature faulty modulo exactly one prime p of n has
    sig**e == m (mod p) but not (mod q), so gcd(sig**e - m, n) == p. Returns that p (1 < p < n,
    n % p == 0), else None. A correct signature gives gcd == n and is rejected here. Needs only
    the message m, the public (e, n) and ONE faulty signature; the correct signature is not used."""
    if n < 6 or e < 2 or not (1 < sig < n):
        return None
    g = math.gcd((pow(sig, e, n) - m) % n, n)
    return g if 1 < g < n else None


def rsa_multiprime(n: int, e: int, primes) -> tuple:
    """(n, d, sorted factors) for a modulus whose prime factors are given (p*q, p*q*r, p**2*q, ...),
    proven: every factor is prime, their product is exactly n, and d = e**-1 mod phi(n) both
    decrypts and re-encrypts a probe. None when any check fails. Repeated primes (prime powers) are
    honoured by phi_of. `factor()` already peels small or close primes from a multi-prime modulus;
    this is the path for a modulus whose primes are stated in the delivery."""
    try:
        fs = sorted(int(p) for p in primes)
    except (TypeError, ValueError):
        return None
    if len(fs) < 2 or any(p < 2 for p in fs):
        return None
    prod = 1
    for p in fs:
        prod *= p
    if prod != n or any(not is_prime(p) for p in fs):
        return None
    phi = phi_of(fs)
    d = inverse(e, phi)
    if d is None or pow(pow(2, e, n), d, n) != 2 % n:
        return None
    return n, d, fs


class _ModFactor(Exception):
    """A modular polynomial step hit a leading coefficient not invertible mod n; its gcd with n is a
    proper factor of n, carried in `.factor`. Franklin-Reiter stops conservatively when this occurs."""

    def __init__(self, factor):
        super().__init__("non-invertible leading coefficient mod n")
        self.factor = factor


def _poly_trim(p, n):
    out = [c % n for c in p]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def _poly_mod(a, b, n):
    """a mod b in Z_n[x] (coefficients low->high). Raises _ModFactor when b's leading coefficient
    shares a factor with n (so n can be factored and the result is not trusted as a field remainder)."""
    a = _poly_trim(list(a), n)
    b = _poly_trim(list(b), n)
    lead = b[-1]
    g = math.gcd(lead, n)
    if g != 1:
        raise _ModFactor(g)                 # 0 < lead < n, so 1 < g < n: a proper factor of n
    inv = inverse(lead, n)
    while len(a) >= len(b) and a != [0]:
        coef = a[-1] * inv % n
        shift = len(a) - len(b)
        for i, bc in enumerate(b):
            a[shift + i] = (a[shift + i] - coef * bc) % n
        a = _poly_trim(a, n)
    return a


def _poly_gcd(a, b, n):
    a, b = _poly_trim(list(a), n), _poly_trim(list(b), n)
    while b != [0]:
        a, b = b, _poly_mod(a, b, n)
    return _poly_trim(a, n)


def _binom_pow(a: int, b: int, e: int, n: int):
    """(a*x + b)**e over Z_n[x], low->high coefficients (coefficient of x**k is C(e,k) a**k b**(e-k))."""
    out = [0] * (e + 1)
    comb = 1
    for k in range(e + 1):
        out[k] = comb % n * pow(a, k, n) % n * pow(b % n, e - k, n) % n
        comb = comb * (e - k) // (k + 1)
    return out


def franklin_reiter(c1: int, c2: int, e: int, n: int, a: int = 1, b: int = 0):
    """The message m1 with m1**e == c1 (mod n) when a second ciphertext c2 encrypts
    m2 == a*m1 + b (mod n) under the SAME small e and modulus n (the Franklin-Reiter related-message
    attack). poly-gcd(x**e - c1, (a x + b)**e - c2) is x - m1 up to a unit; m1 is returned only when
    pow(m1, e, n) == c1 (mod n), else None. e is bounded small (poly-gcd degree), and a leading
    coefficient not invertible mod n ends the attempt conservatively (None)."""
    if e < 2 or e > FR_MAX_E or n < 6 or a % n == 0:
        return None
    f1 = [(-c1) % n] + [0] * (e - 1) + [1 % n]
    f2 = _binom_pow(a % n, b % n, e, n)
    f2[0] = (f2[0] - c2) % n
    try:
        g = _poly_gcd(f1, f2, n)
    except _ModFactor:
        return None
    if len(g) != 2:
        return None
    lead = g[1] % n
    if math.gcd(lead, n) != 1:
        return None
    m1 = (-g[0]) * inverse(lead, n) % n
    return m1 if pow(m1, e, n) == c1 % n else None


# ---- parameters: reading, consistency, repair ----------------------------------------------------------

_CANON = {
    "modulus": "n", "mod": "n", "public_modulus": "n", "rsa_modulus": "n",
    "exponent": "e", "public_exponent": "e", "pubexp": "e", "publicexponent": "e",
    "private_exponent": "d", "privateexponent": "d", "privexp": "d",
    "ciphertext": "c", "cipher": "c", "ct": "c", "enc": "c", "encrypted": "c", "cipher_text": "c",
    "prime1": "p", "prime2": "q", "prime_p": "p", "prime_q": "q",
    "exponent1": "dp", "exponent2": "dq", "dmp1": "dp", "dmq1": "dq", "d_p": "dp", "d_q": "dq",
    "coefficient": "qinv", "iqmp": "qinv", "qi": "qinv", "totient": "phi", "phi_n": "phi",
    "hash": "z", "h": "z", "msg_hash": "z", "digest": "z",
}
_INT_NAMES = ("n", "e", "d", "p", "q", "c", "dp", "dq", "qinv", "phi", "r", "s", "z", "m", "a", "b", "x", "y", "k")
_LABEL = re.compile(
    r"(?<![A-Za-z0-9])[\"']?([A-Za-z][A-Za-z_ ]{0,24}?)[ _]?\[?(\d{0,3})\]?[\"']?\s*(?::=|=|:)\s*"
    r"[\"']?(0[xX][0-9a-fA-F?]+|[0-9][0-9a-fA-F?]*|[a-fA-F?][0-9a-fA-F?]{15,})[\"']?(?![0-9A-Za-z?])")


def canonical(name: str) -> str:
    """The parameter a written label means: the label itself, else its last two words, else its
    last word ("the public exponent" -> e, "value of n" -> n)."""
    key = re.sub(r"[\s-]+", "_", name.strip().lower()).strip("_")
    words = key.split("_")
    for cand in (key, "_".join(words[-2:]), words[-1]):
        cand = _CANON.get(cand, cand)
        if cand in _INT_NAMES:
            return cand
    return _CANON.get(key, key)


def _number(raw: str):
    """(value, radix) of a written number, or None. A bare run with a-f in it is hex."""
    raw = raw.strip()
    try:
        if raw[:2].lower() == "0x":
            return int(raw, 16), 16
        if re.fullmatch(r"\d+", raw):
            return int(raw), 10
        if re.fullmatch(r"[0-9a-fA-F]+", raw):
            return int(raw, 16), 16
    except ValueError:
        pass
    return None


class Params(dict):
    """{name: [int, ...]} in the order written, with `raw` {name: [(text, radix), ...]} beside
    it. `one(name)` is the value when exactly one distinct value was written under the name."""

    def __init__(self):
        super().__init__()
        self.raw = {}
        self.sources = {}

    def add(self, name: str, value: int, raw: str = None, radix: int = 10, source: str = ""):
        self.setdefault(name, []).append(value)
        self.raw.setdefault(name, []).append((raw if raw is not None else str(value), radix))
        self.sources.setdefault(name, []).append(source)

    def one(self, name: str):
        vals = list(dict.fromkeys(self.get(name) or []))
        return vals[0] if len(vals) == 1 else None

    def many(self, name: str):
        return list(self.get(name) or [])

    def copy(self):
        new = Params()
        for k, v in self.items():
            new[k] = list(v)
        new.raw = {k: list(v) for k, v in self.raw.items()}
        new.sources = {k: list(v) for k, v in self.sources.items()}
        return new

    def merged(self, other):
        new = self.copy()
        for k, vals in other.items():
            for i, v in enumerate(vals):
                raw, radix = other.raw[k][i]
                new.add(k, v, raw, radix, other.sources.get(k, [""] * len(vals))[i])
        return new


def _json_walk(node, out: Params, source: str, name: str = None):
    if isinstance(node, dict):
        for k, v in node.items():
            _json_walk(v, out, source, str(k))
    elif isinstance(node, list):
        for v in node:
            _json_walk(v, out, source, name)
    elif name is not None and not isinstance(node, bool):
        m = re.fullmatch(r"(.*?)[_ ]?\[?(\d{0,3})\]?", name.strip())
        base = canonical(m.group(1)) if m else canonical(name)
        if base not in _INT_NAMES:
            return
        if isinstance(node, int):
            out.add(base, node, str(node), 10, source)
        elif isinstance(node, str):
            got = _number(node)
            if got:
                out.add(base, got[0], node.strip(), got[1], source)


_B64_LABEL = re.compile(
    r"(?<![A-Za-z0-9])[\"']?([A-Za-z][A-Za-z_ ]{0,24}?)[ _]?\[?(\d{0,3})\]?[\"']?\s*(?::=|=|:)\s*"
    r"[\"']?([A-Za-z0-9+/_-]{24,}={0,2})[\"']?(?![0-9A-Za-z+/=_-])")


def _b64_int(raw: str):
    """The big-endian integer of a base64 (standard or URL-safe) value that is no hex or decimal run,
    or None. Needs a character outside the hex alphabet, and 24+ characters (16+ bytes)."""
    import base64 as _b64
    raw = raw.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", raw) or raw[:2].lower() == "0x":
        return None
    core = raw.rstrip("=")
    try:
        b = _b64.b64decode(core.replace("-", "+").replace("_", "/") + "=" * (-len(core) % 4), validate=True)
    except ValueError:
        return None
    return int.from_bytes(b, "big") if len(b) >= 16 else None



def read_params(text, source: str = "") -> Params:
    """Labelled integers of a text or a JSON document. `n = 0x..`, `e: 65537`, `"c": "1f.."`,
    `n1 = ..`, `c[2] = ..`, `modulus = ..`; a value written with `?` in place of a digit
    is kept in `raw` only (repair_digit reads it). A JWK's base64url numbers are read_keys' job."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    out = Params()
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            _json_walk(json.loads(stripped), out, source)
            if out:
                return out
        except ValueError:
            pass
    # a long value continued over several lines ("n = 1234\\\n   5678")
    text = re.sub(r"\\\r?\n\s*", "", text)
    for m in _LABEL.finditer(text):
        name = canonical(m.group(1))
        if name not in _INT_NAMES:
            continue
        raw = m.group(3)
        got = _number(raw)
        if got:
            out.add(name, got[0], raw, got[1], source)
        elif "?" in raw:
            out.raw.setdefault(name + "?", []).append((raw, 16 if raw[:2].lower() == "0x" or re.search(r"[a-fA-F]", raw) else 10))
    # Day 26 depth: a modulus or ciphertext written as BASE64 on a labelled line (`c = Zm9v...`). Only a
    # value the hex/decimal reader above could not take (it has a non-hex letter, +, / or =) and only the
    # labels n and c; the RSA paths verify whatever is read (n by its factors, c by re-encryption), so a
    # wrong reading can only decline.
    for m in _B64_LABEL.finditer(text):
        name = canonical(m.group(1))
        if name not in ("n", "c"):
            continue
        raw = m.group(3)
        v = _b64_int(raw)
        if v is not None and v not in out.get(name, []):
            out.add(name, v, raw, 16, source)
    return out


_FIELD = re.compile(r"(?<![A-Za-z0-9])[\"']?([A-Za-z][A-Za-z0-9_ -]{0,30}?)[\"']?\s*(?::=|=|:)\s*"
                    r"(?:b?\"([^\"\n]{1,8192})\"|b?'([^'\n]{1,8192})'|([^\s,;\"'{}\[\]]{1,8192}))")


def read_fields(text, source: str = "") -> dict:
    """{canonical name: [value as written, ...]} for every `name = value` / `"name": "value"` of a
    text or JSON document. Names are lowercased with `_`; nothing is decoded here (see blobs)."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    out = {}
    stripped = text.strip()
    if stripped[:1] in "{[":
        try:
            def walk(node, name=None):
                if isinstance(node, dict):
                    for k, v in node.items():
                        walk(v, str(k))
                elif isinstance(node, list):
                    for v in node:
                        walk(v, name)
                elif name is not None and isinstance(node, (str, int)) and not isinstance(node, bool):
                    out.setdefault(re.sub(r"[\s-]+", "_", name.strip().lower()), []).append(str(node))
            walk(json.loads(stripped))
            return out
        except ValueError:
            out = {}
    for m in _FIELD.finditer(text):
        value = next(v for v in m.groups()[1:] if v is not None)
        out.setdefault(re.sub(r"[\s-]+", "_", m.group(1).strip().lower()), []).append(value)
    return out


def blobs(value) -> list:
    """[(reading, bytes)] a written value may mean, each once: hex (with or without 0x, spaces,
    colons), base64 (standard and url-safe), and the text itself. The caller's proof decides."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value)
        try:
            text = value.decode("ascii").strip()
        except UnicodeDecodeError:
            return [("raw", value)]
    else:
        text = str(value).strip()
        value = text.encode("utf-8")
    out, seen = [], set()

    def add(name, b):
        if b and b not in seen:
            seen.add(b)
            out.append((name, b))

    compact = re.sub(r"^0[xX]", "", re.sub(r"[\s:,-]|\\x", "", text))
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        add("hex", bytes.fromhex(compact))
    b64 = re.sub(r"\s+", "", text)
    if len(b64) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", b64):
        core = b64.rstrip("=").replace("-", "+").replace("_", "/")
        try:
            if len(core) % 4 != 1:
                add("base64", base64.b64decode(core + "=" * (-len(core) % 4), validate=True))
        except (binascii.Error, ValueError):
            pass
    add("raw", value)
    return out


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)
_SSH = re.compile(rb"\b(ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{40,}")


def _key_numbers(key, kind: str) -> dict:
    out = {"kind": kind}
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except Exception:
        return out
    if isinstance(key, rsa.RSAPrivateKey):
        pn = key.private_numbers()
        out.update(type="rsa", private=True, n=pn.public_numbers.n, e=pn.public_numbers.e, d=pn.d, p=pn.p, q=pn.q,
                   dp=pn.dmp1, dq=pn.dmq1, qinv=pn.iqmp)
    elif isinstance(key, rsa.RSAPublicKey):
        pn = key.public_numbers()
        out.update(type="rsa", private=False, n=pn.n, e=pn.e)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        pn = key.private_numbers()
        out.update(type="ec", private=True, curve=key.curve.name, d=pn.private_value, x=pn.public_numbers.x, y=pn.public_numbers.y)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        pn = key.public_numbers()
        out.update(type="ec", private=False, curve=key.curve.name, x=pn.x, y=pn.y)
    else:
        out.update(type=type(key).__name__.lower(), private="Private" in type(key).__name__)
    if out.get("type") == "rsa":
        out["bits"] = out["n"].bit_length()
    return out


def read_keys(data) -> list:
    """Every key the bytes hold, as dicts: {kind: pem|der|jwk|ssh|x509, type: rsa|ec, private,
    n, e, d, p, q, dp, dq, qinv | curve, x, y, d, bits}. An encrypted private key, or anything
    that does not parse, is {kind, type: 'unread', why}. A weak RSA key that the library refuses
    (a tiny or even modulus) is still read from its DER numbers."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = bytes(data)
    out = []
    stripped = data.strip()
    if stripped[:1] == b"{":
        try:
            doc = json.loads(stripped)
            for jwk in (doc.get("keys") if isinstance(doc.get("keys"), list) else [doc]):
                if isinstance(jwk, dict) and jwk.get("kty") == "RSA" and "n" in jwk and "e" in jwk:
                    k = {"kind": "jwk", "type": "rsa", "private": "d" in jwk}
                    for name in ("n", "e", "d", "p", "q", "dp", "dq", "qi"):
                        if isinstance(jwk.get(name), str):
                            k["qinv" if name == "qi" else name] = to_int(_b64u(jwk[name]))
                    k["bits"] = k["n"].bit_length()
                    out.append(k)
                elif isinstance(jwk, dict) and jwk.get("kty") == "EC" and "x" in jwk and "y" in jwk:
                    k = {"kind": "jwk", "type": "ec", "private": "d" in jwk, "curve": str(jwk.get("crv") or ""),
                         "x": to_int(_b64u(jwk["x"])), "y": to_int(_b64u(jwk["y"]))}
                    if isinstance(jwk.get("d"), str):
                        k["d"] = to_int(_b64u(jwk["d"]))
                    out.append(k)
                elif isinstance(jwk, dict) and jwk.get("kty") == "oct" and isinstance(jwk.get("k"), str):
                    out.append({"kind": "jwk", "type": "oct", "private": True, "k": _b64u(jwk["k"])})
        except (ValueError, AttributeError, TypeError, binascii.Error):
            pass
        return out
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization as ser
    except Exception:                   # pragma: no cover
        return out
    for m in _PEM.finditer(data):
        label, block = m.group(1).decode(), m.group(0)
        try:
            if "CERTIFICATE" in label and "REQUEST" not in label:
                out.append(_key_numbers(x509.load_pem_x509_certificate(block).public_key(), "x509"))
            elif "PRIVATE" in label:
                if b"ENCRYPTED" in block:
                    out.append({"kind": "pem", "type": "unread", "why": "an encrypted private key"})
                else:
                    try:
                        out.append(_key_numbers(ser.load_pem_private_key(block, None, unsafe_skip_rsa_key_validation=True), "pem"))
                    except TypeError:
                        out.append(_key_numbers(ser.load_pem_private_key(block, None), "pem"))
            elif "PUBLIC" in label:
                out.append(_key_numbers(ser.load_pem_public_key(block), "pem"))
        except Exception as e:
            weak = _der_rsa(_pem_body(block))
            out.append(dict(weak, kind="pem") if weak else {"kind": "pem", "type": "unread", "why": f"{type(e).__name__}: {str(e)[:80]}"})
    for m in _SSH.finditer(data):
        try:
            out.append(_key_numbers(ser.load_ssh_public_key(m.group(0)), "ssh"))
        except Exception as e:
            out.append({"kind": "ssh", "type": "unread", "why": f"{type(e).__name__}: {str(e)[:80]}"})
    if not out and data[:1] == b"\x30":
        for loader, kind in ((lambda d: ser.load_der_public_key(d), "der"), (lambda d: ser.load_der_private_key(d, None), "der"),
                             (lambda d: x509.load_der_x509_certificate(d).public_key(), "x509")):
            try:
                out.append(_key_numbers(loader(data), kind))
                break
            except Exception:
                continue
        else:
            weak = _der_rsa(data)
            if weak:
                out.append(dict(weak, kind="der"))
    return out


def _pem_body(block: bytes) -> bytes:
    lines = [ln for ln in block.splitlines() if ln and not ln.startswith(b"-----") and b":" not in ln]
    try:
        return base64.b64decode(b"".join(lines))
    except (binascii.Error, ValueError):
        return b""


def _der_ints(data: bytes, depth: int = 0, out=None, limit: int = 64):
    """The INTEGERs of a DER structure in order (SEQUENCE, BIT STRING and OCTET STRING entered)."""
    out = [] if out is None else out
    i = 0
    while i + 2 <= len(data) and len(out) < limit:
        tag, ln = data[i], data[i + 1]
        i += 2
        if ln & 0x80:
            k = ln & 0x7F
            if not 1 <= k <= 4 or i + k > len(data):
                break
            ln = int.from_bytes(data[i:i + k], "big")
            i += k
        body = data[i:i + ln]
        if len(body) != ln:
            break
        i += ln
        if tag == 0x02:
            out.append(int.from_bytes(body, "big"))
        elif tag in (0x30, 0x31) and depth < 6:
            _der_ints(body, depth + 1, out, limit)
        elif tag == 0x03 and body[:1] == b"\x00" and body[1:2] == b"\x30" and depth < 6:
            _der_ints(body[1:], depth + 1, out, limit)
        elif tag == 0x04 and body[:1] == b"\x30" and depth < 6:
            _der_ints(body, depth + 1, out, limit)
    return out


def _der_rsa(der: bytes):
    """RSA numbers straight from DER, for a key the library refuses: PKCS#1 or SPKI public (n, e),
    PKCS#1 or PKCS#8 private (0, n, e, d, p, q, dp, dq, qinv)."""
    if not der or der[:1] != b"\x30":
        return None
    ints = _der_ints(der)
    if len(ints) >= 9 and ints[0] == 0 and ints[1] == 0:
        ints = ints[1:]                 # PKCS#8: its own version, then PKCS#1's
    if len(ints) >= 9 and ints[0] == 0 and ints[1] > 3 and ints[4] * ints[5] == ints[1]:
        n, e, d, p, q, dp, dq, qinv = ints[1:9]
        return {"type": "rsa", "private": True, "n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq,
                "qinv": qinv, "bits": n.bit_length(), "weak": True}
    if len(ints) == 2 and ints[0] > 3 and 1 < ints[1] < ints[0]:
        return {"type": "rsa", "private": False, "n": ints[0], "e": ints[1], "bits": ints[0].bit_length(), "weak": True}
    return None


def consistency(P: dict):
    """(relations checked, relations broken) over the single-valued parameters present.
    P is {name: int}. Relations: n = p*q, p | n, q | n, e*d = 1 mod lcm(p-1, q-1), dp = d mod
    (p-1), dq = d mod (q-1), e*dp = 1 mod (p-1), e*dq = 1 mod (q-1), qinv*q = 1 mod p,
    phi = (p-1)(q-1), and with n, e, d but no prime: (2^e)^d = 2 mod n."""
    g = P.get
    n, e, d, p, q, dp, dq, qinv, phi = (g(k) for k in ("n", "e", "d", "p", "q", "dp", "dq", "qinv", "phi"))
    checks = []
    if n and p and q:
        checks.append(n == p * q)
    elif n and p:
        checks.append(p > 1 and n % p == 0)
    elif n and q:
        checks.append(q > 1 and n % q == 0)
    if e and d and p and q and p > 1 and q > 1:
        checks.append((e * d - 1) % math.lcm(p - 1, q - 1) == 0)
    elif e and d and n and not p and not q:
        checks.append(n > 3 and pow(pow(2, e, n), d, n) == 2)
    for dx, px in ((dp, p), (dq, q)):
        if dx and px and px > 1:
            if d:
                checks.append(dx == d % (px - 1))
            if e:
                checks.append((e * dx - 1) % (px - 1) == 0)
    if qinv and p and q and p > 1:
        checks.append(qinv * q % p == 1)
    if phi and p and q:
        checks.append(phi == (p - 1) * (q - 1))
    elif phi and n:
        checks.append(factor_from_phi(n, phi) is not None)
    return len(checks), sum(1 for c in checks if not c)


_DIGITS = {10: "0123456789", 16: "0123456789abcdef"}


def repair_digit(P: Params, deadline=None, names=("n", "e", "d", "p", "q", "dp", "dq", "qinv", "phi")):
    """A garbled parameter put right, only when it is proven: the parameters as written break a
    relation (consistency), and EXACTLY ONE change of one digit of one parameter makes every
    relation hold. Returns (name, repaired value, position, {name: int} repaired) or None. A
    value written with one `?` in place of a digit is repaired the same way (that position
    only). None when the search did not finish in time: 'exactly one' needs all of it."""
    single, written = {}, {}
    for name in names:
        v = P.one(name)
        holes = P.raw.get(name + "?") or []
        if v is not None and not holes:
            single[name] = v
            raws = list(dict.fromkeys(P.raw.get(name) or []))
            if len(raws) == 1:
                written[name] = raws[0]
        elif v is None and len(holes) == 1 and holes[0][0].count("?") == 1 and not P.get(name):
            written[name] = holes[0]
    holed = [n for n in written if n not in single]
    if len(holed) > 1:
        return None
    if not holed:
        checked, broken = consistency(single)
        if not checked or not broken:
            return None
    fixes = []
    for name in (holed or list(written)):
        raw, radix = written[name]
        body = raw[2:] if raw[:2].lower() == "0x" else raw
        low = body.lower()
        positions = [i for i, ch in enumerate(low) if ch == "?"] if name in holed else range(len(low))
        for i in positions:
            for ch in _DIGITS[radix]:
                if ch == low[i]:
                    continue
                try:
                    value = int(low[:i] + ch + low[i + 1:], radix)
                except ValueError:
                    continue
                trial = dict(single)
                trial[name] = value
                checked, broken = consistency(trial)
                if checked and not broken:
                    fixes.append((name, value, i, trial))
                    if len(fixes) > 1:
                        return None
            if not _left(deadline):
                return None
    return fixes[0] if len(fixes) == 1 else None


def rsa_private(P: dict):
    """(n, d, factors or None, how) from any sufficient subset of {n, e, d, p, q, phi, dp, dq},
    or None. Every route checks itself: primes multiply to n, a d is the inverse of e."""
    g = P.get
    n, e, d, p, q, phi, dp, dq = (g(k) for k in ("n", "e", "d", "p", "q", "phi", "dp", "dq"))
    if p and q and (not n or n == p * q) and p > 1 and q > 1:
        n = p * q
        if e:
            lam = math.lcm(p - 1, q - 1) if p != q else p * (p - 1)
            dd = inverse(e, lam)
            if dd is not None:
                return n, dd, sorted((p, q)), "p_q"
        if d:
            return n, d, sorted((p, q)), "p_q_d"
        if dp and dq:
            return n, None, sorted((p, q)), "crt"
    if n and e and (p or q):
        f = p or q
        if 1 < f < n and n % f == 0:
            return rsa_private({"n": n, "e": e, "p": f, "q": n // f, "d": d})
    if n and d:
        if not e or pow(pow(2, e, n), d, n) == 2 % n:
            return n, d, None, "n_d"
    if n and e and phi:
        dd = inverse(e, phi)
        if dd is not None and (factor_from_phi(n, phi) or pow(pow(2, e, n), dd, n) == 2 % n):
            pq = factor_from_phi(n, phi)
            return n, dd, sorted(pq) if pq else None, "phi"
    if n and e and (dp or dq):
        got = dp_leak(n, e, dp or dq)
        full = rsa_private({"n": n, "e": e, "p": got[0], "q": got[1]}) if got else None
        if full:
            return full[:3] + ("dp_leak",)
    return None


def rsa_attack(n: int, e: int, deadline=None, level: int = 2):
    """(d, factors, attack name) for a weak public key, or None. Each is proven by its own
    check: the factors found are prime and multiply to n. level 0: instant structure (prime n,
    square, small factor); 1: + Wiener, Fermat; 2: + Pollard p-1 and rho until the deadline."""
    if n < 4 or e < 2:
        return None

    def done(factors, how):
        phi = phi_of(factors)
        d = inverse(e, phi)
        return (d, factors, how) if d is not None else None

    if is_prime(n):
        return done([n], "prime_modulus")
    for p in small_primes(TRIAL_BOUND):
        if n % p == 0:
            fs = [p] + (factor(n // p, deadline) or []) if n.bit_length() > 256 else factor(n, deadline)
            return done(sorted(fs), "small_factor") if fs and len(fs) > 1 else None
    for k in (2, 3):
        r, exact = iroot(n, k)
        if exact and is_prime(r):
            return done([r] * k, "square_modulus" if k == 2 else "prime_power_modulus")
    if level < 1:
        return None
    got = wiener(n, e)
    if got:
        d, p, q = got
        return (d, sorted((p, q)), "wiener") if is_prime(p) and is_prime(q) else None
    got = fermat(n, deadline, max_steps=200_000)
    if got and got[0] > 1:
        fs = []
        for f in got:
            sub = [f] if is_prime(f) else factor(f, deadline)
            if not sub:
                return None
            fs += sub
        return done(sorted(fs), "fermat")
    if level < 2 or not _left(deadline):
        return None
    f = pollard_p1(n, 100_000, deadline)
    how = "pollard_p_minus_1"
    if f is None and _left(deadline) and (n.bit_length() <= 200 or deadline is not None):
        # rho finds a factor of up to about 45 bits inside a second whatever the size of n; with no
        # deadline it is only run on a modulus it can finish
        f, how = pollard_rho(n, deadline), "pollard_rho"
    if f and 1 < f < n and n % f == 0:
        a = [f] if is_prime(f) else factor(f, deadline)
        b = [n // f] if is_prime(n // f) else factor(n // f, deadline)
        if a and b:
            return done(sorted(a + b), how)
    return None


def rsa_messages(m: int, n: int = None, key: dict = None, c: int = None) -> list:
    """[(reading, bytes)] of a recovered message integer: the bytes as they are, with PKCS#1 v1.5
    type-2 padding taken off, and, when the whole private key is known (key with n, e, d, p, q),
    OAEP with SHA-1 and SHA-256 over the ciphertext c (an OAEP that unpads has checked its hash)."""
    out = []
    raw = to_bytes(m)
    out.append(("raw", raw))
    if n:
        k = (n.bit_length() + 7) // 8
        em = m.to_bytes(k, "big") if m.bit_length() <= 8 * k else raw
        if em[:2] == b"\x00\x02" and b"\x00" in em[10:]:
            out.append(("pkcs1_v1_5", em[em.index(b"\x00", 10) + 1:]))
        for name, h in (("oaep_sha1", hashlib.sha1), ("oaep_sha256", hashlib.sha256)):
            pt = _oaep_unpad(em, k, h)
            if pt is not None:
                out.append((name, pt))
    return out


def _mgf1(seed: bytes, length: int, h) -> bytes:
    out = b""
    for i in range(-(-length // h().digest_size)):
        out += h(seed + i.to_bytes(4, "big")).digest()
    return out[:length]


def _oaep_unpad(em: bytes, k: int, h, label: bytes = b""):
    hl = h().digest_size
    if len(em) != k or k < 2 * hl + 2 or em[0] != 0:
        return None
    seed = bytes(a ^ b for a, b in zip(em[1:1 + hl], _mgf1(em[1 + hl:], hl, h)))
    db = bytes(a ^ b for a, b in zip(em[1 + hl:], _mgf1(seed, k - hl - 1, h)))
    if db[:hl] != h(label).digest():
        return None
    rest = db[hl:].lstrip(b"\x00")
    return rest[1:] if rest[:1] == b"\x01" else None


# ---- XOR and stream reuse ------------------------------------------------------------------------------

def xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    n = len(key)
    if n == 1:
        return bytes(b ^ key[0] for b in data)
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def xor_crib(ct: bytes, crib: bytes, max_key: int = 64, anywhere: bool = False, max_offsets: int = 2048) -> list:
    """[(key, offset, plaintext)] for every repeating key of length <= min(max_key, len(crib))
    under which `crib` sits at `offset` (0 only, unless anywhere) and the key bytes the crib
    gives agree wherever the crib covers a key position twice. A key as long as the crib has no
    such check: the caller's proof over the whole plaintext is what decides. Keys are reported at
    their shortest period."""
    out, seen = [], set()
    if not crib or len(ct) < len(crib):
        return out
    offsets = range(min(len(ct) - len(crib) + 1, max_offsets)) if anywhere else (0,)
    for off in offsets:
        ks = bytes(a ^ b for a, b in zip(ct[off:off + len(crib)], crib))
        for k in range(1, min(max_key, len(crib)) + 1):
            if any(ks[i] != ks[i - k] for i in range(k, len(ks))):
                continue
            key = bytearray(k)
            for i in range(k):
                key[(off + i) % k] = ks[i]
            key = bytes(key)
            if key not in seen:
                seen.add(key)
                out.append((key, off, xor(ct, key)))
            break                       # longer periods of the same stream repeat this key
    return out


def keystream_reuse(known_pt: bytes, known_ct: bytes, target_ct: bytes):
    """The target's plaintext when one keystream encrypted both and the known plaintext covers it
    (a two-time pad with a whole known message); None when the known pair is shorter."""
    n = len(target_ct)
    if len(known_pt) < n or len(known_ct) < n or not n:
        return None
    return bytes(a ^ b ^ c for a, b, c in zip(known_pt, known_ct, target_ct))


def crib_drag(c1: bytes, c2: bytes, crib: bytes) -> list:
    """[(offset, bytes)]: for each offset, what the other message reads if `crib` sits there in
    one of them, kept when it is printable ASCII. For work by hand; nothing here is an answer."""
    x = bytes(a ^ b for a, b in zip(c1, c2))
    out = []
    for off in range(len(x) - len(crib) + 1):
        other = bytes(a ^ b for a, b in zip(x[off:off + len(crib)], crib))
        if all(32 <= b < 127 for b in other):
            out.append((off, other))
    return out


def keystream_from_known(known_pt: bytes, known_ct: bytes) -> bytes:
    """The additive keystream that turned `known_pt` into `known_ct` under a stream cipher (CTR,
    OFB, GCM's CTR core, RC4, ChaCha20, a one-time pad): known_ct XOR known_pt, over the bytes both
    cover. When the same key and nonce were reused, this keystream also decrypts any other
    ciphertext of the overlapping length: pt = xor(other_ct, keystream). Deterministic."""
    n = min(len(known_pt), len(known_ct))
    return bytes(known_ct[i] ^ known_pt[i] for i in range(n))


# ---- oracle-free CBC / CTR malleability -----------------------------------------------------------

MAX_MALLEABILITY_BYTES = 64 * 1024 * 1024
MAX_MALLEABILITY_EDITS = 4096
MAX_MALLEABILITY_EDIT_BYTES = 1 * 1024 * 1024


class MalleabilityError(ValueError):
    """The requested offline edit is ambiguous, out of bounds, or cannot be guaranteed."""


def _edit_triplet(edit):
    """Normalise one mapping or ``(offset, known, desired)`` edit without coercing text."""
    if isinstance(edit, dict):
        try:
            offset = edit["offset"]
            known = edit.get("known", edit.get("original"))
            desired = edit.get("desired", edit.get("replacement"))
        except (KeyError, TypeError) as exc:
            raise MalleabilityError("each edit needs offset, known, and desired") from exc
    elif isinstance(edit, (tuple, list)) and len(edit) == 3:
        offset, known, desired = edit
    else:
        raise MalleabilityError("each edit must be (offset, known, desired) or a mapping")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise MalleabilityError("edit offsets must be non-negative integers")
    if not isinstance(known, (bytes, bytearray)) or not isinstance(desired, (bytes, bytearray)):
        raise MalleabilityError("known and desired plaintext must be bytes")
    if len(known) > MAX_MALLEABILITY_EDIT_BYTES or len(desired) > MAX_MALLEABILITY_EDIT_BYTES:
        raise MalleabilityError(f"one edit is capped at {MAX_MALLEABILITY_EDIT_BYTES} bytes")
    known, desired = bytes(known), bytes(desired)
    if not known or len(known) != len(desired):
        raise MalleabilityError("known and desired plaintext must have the same non-zero length")
    return offset, known, desired


def _normalise_malleability_edits(edits, plaintext_len: int):
    """Return ``(per_byte, ranges)`` after strict overlap and allocation checks.

    ``per_byte`` maps plaintext offsets to their exact ``(known, desired)`` byte premise.  Repeated
    coverage is accepted only when both bytes agree; this prevents two overlapping edits with the
    same XOR delta but contradictory known-plaintext claims from looking valid.
    """
    if isinstance(plaintext_len, bool) or not isinstance(plaintext_len, int) \
            or not 0 <= plaintext_len <= MAX_MALLEABILITY_BYTES:
        raise MalleabilityError(f"plaintext length must be 0..{MAX_MALLEABILITY_BYTES}")
    try:
        iterator = iter(edits)
    except TypeError as exc:
        raise MalleabilityError("edits must be an iterable") from exc
    per_byte = {}
    ranges = []
    total = 0
    count = 0
    for raw in iterator:
        count += 1
        if count > MAX_MALLEABILITY_EDITS:
            raise MalleabilityError(f"give at most {MAX_MALLEABILITY_EDITS} edits")
        offset, known, desired = _edit_triplet(raw)
        total += len(known)
        if total > MAX_MALLEABILITY_EDIT_BYTES:
            raise MalleabilityError(f"edited plaintext is capped at {MAX_MALLEABILITY_EDIT_BYTES} bytes")
        if offset > plaintext_len or len(known) > plaintext_len - offset:
            raise MalleabilityError("an edit extends past the plaintext/ciphertext length")
        ranges.append({"offset": offset, "length": len(known)})
        for index, pair in enumerate(zip(known, desired)):
            position = offset + index
            previous = per_byte.get(position)
            if previous is not None and previous != pair:
                raise MalleabilityError(f"contradictory overlapping edits at plaintext offset {position}")
            per_byte[position] = pair
    if count == 0:
        raise MalleabilityError("give at least one edit")
    return per_byte, ranges


def _offset_ranges(offsets):
    """Compress sorted integer offsets to ``[{offset, length}, ...]`` metadata."""
    values = sorted(set(offsets))
    out = []
    if not values:
        return out
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        out.append({"offset": start, "length": previous - start + 1})
        start = previous = value
    out.append({"offset": start, "length": previous - start + 1})
    return out


def cbc_bitflip_forge(iv: bytes, ciphertext: bytes, edits, block_size: int = 16) -> dict:
    """Forge CBC IV/previous-block bytes for chosen plaintext edits at known offsets.

    ``edits`` is an iterable of ``(offset, known_bytes, desired_bytes)`` or mappings with
    ``offset``, ``known``/``original``, and ``desired``/``replacement``.  The function applies
    ``known XOR desired`` to the IV for plaintext block 0 and to ciphertext block ``i-1`` for
    plaintext block ``i``.  It returns the forged bytes plus explicit collateral metadata.

    Changing ciphertext block ``i-1`` predictably edits plaintext block ``i`` but makes plaintext
    block ``i-1`` decrypt unpredictably.  Therefore edits in adjacent plaintext blocks cannot both
    be guaranteed without the key/oracle; such requests raise :class:`MalleabilityError` rather
    than emitting a misleading payload.  Non-adjacent multi-block edits are supported.

    The guarantee is conditional on the caller's supplied known plaintext being exact.  Nothing is
    encrypted, decrypted, sent, or oracle-checked here.
    """
    if not isinstance(iv, (bytes, bytearray)) or not isinstance(ciphertext, (bytes, bytearray)):
        raise MalleabilityError("iv and ciphertext must be bytes")
    if isinstance(block_size, bool) or not isinstance(block_size, int) or not 2 <= block_size <= 256:
        raise MalleabilityError("block_size must be an integer in 2..256")
    iv, ciphertext = bytes(iv), bytes(ciphertext)
    if len(iv) != block_size:
        raise MalleabilityError("IV length must equal block_size")
    if not ciphertext or len(ciphertext) > MAX_MALLEABILITY_BYTES or len(ciphertext) % block_size:
        raise MalleabilityError("ciphertext must be non-empty, bounded, and block aligned")
    per_byte, requested_ranges = _normalise_malleability_edits(edits, len(ciphertext))
    requested_blocks = {position // block_size for position in per_byte}
    changed_positions = {position for position, (known, desired) in per_byte.items() if known != desired}
    changed_target_blocks = {position // block_size for position in changed_positions}
    collateral_blocks = {block - 1 for block in changed_target_blocks if block > 0}
    conflicts = sorted(requested_blocks & collateral_blocks)
    if conflicts:
        joined = ", ".join(map(str, conflicts))
        raise MalleabilityError(
            f"CBC edits cannot be guaranteed: target plaintext block(s) {joined} are also collateral"
        )

    forged_iv, forged_ct = bytearray(iv), bytearray(ciphertext)
    iv_offsets, ciphertext_offsets = [], []
    for position in sorted(changed_positions):
        known, desired = per_byte[position]
        delta = known ^ desired
        block, within = divmod(position, block_size)
        if block == 0:
            forged_iv[within] ^= delta
            iv_offsets.append(within)
        else:
            control = (block - 1) * block_size + within
            forged_ct[control] ^= delta
            ciphertext_offsets.append(control)
    return {
        "mode": "cbc-bitflip",
        "iv": bytes(forged_iv),
        "ciphertext": bytes(forged_ct),
        "block_size": block_size,
        "requested_plaintext_ranges": requested_ranges,
        "target_plaintext_blocks": sorted(requested_blocks),
        "collateral_plaintext_blocks": sorted(collateral_blocks),
        "modified_iv_ranges": _offset_ranges(iv_offsets),
        "modified_ciphertext_ranges": _offset_ranges(ciphertext_offsets),
        "changed_byte_count": len(changed_positions),
        "conditional_guarantee": "supplied known plaintext bytes are exact",
        "collateral_effect": "listed CBC plaintext blocks decrypt unpredictably",
    }


def cbc_bitflip(iv: bytes, ciphertext: bytes, offset: int, known_plaintext: bytes,
                desired_plaintext: bytes, block_size: int = 16) -> dict:
    """Convenience wrapper for one contiguous :func:`cbc_bitflip_forge` edit."""
    return cbc_bitflip_forge(iv, ciphertext,
                             [(offset, known_plaintext, desired_plaintext)], block_size=block_size)


def ctr_edit_forge(ciphertext: bytes, edits) -> dict:
    """Forge CTR ciphertext bytes for chosen plaintext edits at known offsets.

    CTR is a stream cipher construction: ``C' = C XOR known XOR desired`` at each edited byte.
    Unlike CBC, no neighbouring plaintext is damaged.  The nonce/counter is not needed to compute
    the edit and must remain unchanged when the caller uses the returned ciphertext.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise MalleabilityError("ciphertext must be bytes")
    ciphertext = bytes(ciphertext)
    if not ciphertext or len(ciphertext) > MAX_MALLEABILITY_BYTES:
        raise MalleabilityError("ciphertext must be non-empty and bounded")
    per_byte, requested_ranges = _normalise_malleability_edits(edits, len(ciphertext))
    forged = bytearray(ciphertext)
    changed_positions = []
    for position, (known, desired) in sorted(per_byte.items()):
        if known == desired:
            continue
        forged[position] ^= known ^ desired
        changed_positions.append(position)
    return {
        "mode": "ctr-edit",
        "ciphertext": bytes(forged),
        "requested_plaintext_ranges": requested_ranges,
        "modified_ciphertext_ranges": _offset_ranges(changed_positions),
        "changed_byte_count": len(changed_positions),
        "collateral_plaintext_blocks": [],
        "conditional_guarantee": "supplied known plaintext bytes are exact and nonce/counter is unchanged",
        "collateral_effect": "none",
    }


def ctr_known_edit(ciphertext: bytes, offset: int, known_plaintext: bytes,
                   desired_plaintext: bytes) -> dict:
    """Convenience wrapper for one contiguous :func:`ctr_edit_forge` edit."""
    return ctr_edit_forge(ciphertext, [(offset, known_plaintext, desired_plaintext)])


def two_time_pad(ct_a: bytes, ct_b: bytes, crib: bytes) -> list:
    """Two ciphertexts under ONE reused keystream (key+nonce reuse). x = ct_a XOR ct_b equals
    pt_a XOR pt_b, so for a crib believed to sit in one plaintext at offset o the OTHER plaintext
    reads x[o:o+len(crib)] XOR crib. Returns [(offset, recovered)] for every offset the crib fits;
    x is symmetric, so one list covers 'crib in a' and 'crib in b' alike. Deterministic; nothing
    here is an answer -- the caller confirms a hit (printable text, a format, a second crib)."""
    x = bytes(a ^ b for a, b in zip(ct_a, ct_b))
    m = len(crib)
    if not crib or m > len(x):
        return []
    return [(o, bytes(x[o + i] ^ crib[i] for i in range(m))) for o in range(len(x) - m + 1)]


def ecb_duplicates(ct: bytes, block: int = 16) -> dict:
    """Repeated blocks of a ciphertext: {blocks, distinct, repeated_values (distinct blocks seen
    more than once), repeats (blocks that repeat an earlier one), aligned}."""
    blocks = [ct[i:i + block] for i in range(0, len(ct) - len(ct) % block, block)]
    counts = {}
    for b in blocks:
        counts[b] = counts.get(b, 0) + 1
    return {"blocks": len(blocks), "distinct": len(counts), "repeated_values": sum(1 for v in counts.values() if v > 1),
            "repeats": len(blocks) - len(counts), "aligned": len(ct) % block == 0 and len(ct) > 0}


# ---- ciphers with a stated key --------------------------------------------------------------------------

def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def _unpad(pt: bytes, block: int):
    if not pt or len(pt) % block:
        return None
    n = pt[-1]
    return pt[:-n] if 1 <= n <= block and pt.endswith(bytes([n]) * n) else None


def _cipher_lib():
    try:
        from Crypto.Cipher import AES, DES, DES3, ChaCha20      # pycryptodome
        return AES, DES, DES3, ChaCha20
    except Exception:
        try:
            from Cryptodome.Cipher import AES, DES, DES3, ChaCha20      # pycryptodomex
            return AES, DES, DES3, ChaCha20
        except Exception:
            return None


def poly1305_mac(otk: bytes, msg: bytes) -> bytes | None:
    """Poly1305 (RFC 8439 section 2.5), or ``None`` for malformed input.

    The one-time key is exactly 32 bytes.  Bytes-like values are copied to immutable bytes so
    callers cannot mutate them during the calculation; text and other implicit encodings are
    rejected.  The implementation is kept separate from the cipher library used by
    :func:`chacha_poly_open` so that successful authentication has an independent check.
    """
    if not isinstance(otk, (bytes, bytearray, memoryview)) \
            or not isinstance(msg, (bytes, bytearray, memoryview)):
        return None
    try:
        otk = bytes(otk)
        msg = bytes(msg)
    except (TypeError, ValueError, OverflowError, MemoryError):
        return None
    if len(otk) != 32:
        return None
    r = int.from_bytes(otk[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    sk = int.from_bytes(otk[16:], "little")
    acc, pm = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        acc = (acc + int.from_bytes(blk + b"\x01", "little")) * r % pm
    return ((acc + sk) & ((1 << 128) - 1)).to_bytes(16, "little")


def chacha_poly_open(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
    """The plaintext of a ChaCha20-Poly1305 (12-byte nonce, RFC 8439) or XChaCha20-Poly1305
    (24-byte nonce) message, or None. The plaintext is returned ONLY when the 16-byte Poly1305
    tag, recomputed here over aad || pad || ciphertext || pad || lengths with the one-time key
    from keystream block 0, equals the written tag (constant-time compare). Any other size,
    a missing library or a mismatch gives None."""
    import hmac
    if len(key) != 32 or len(nonce) not in (12, 24) or len(tag) != 16:
        return None
    lib = _cipher_lib()
    if lib is None:
        return None
    ChaCha20 = lib[3]
    try:
        otk = ChaCha20.new(key=key, nonce=nonce).encrypt(b"\x00" * 32)
        pad = lambda b: b"\x00" * (-len(b) % 16)
        mac_data = aad + pad(aad) + ct + pad(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
        expected = poly1305_mac(otk, mac_data)
        if expected is None or not hmac.compare_digest(expected, tag):
            return None
        c = ChaCha20.new(key=key, nonce=nonce)
        c.seek(64)                      # block 0 went to the Poly1305 key
        return c.decrypt(ct)
    except (ValueError, TypeError):
        return None


# ---- AES Key Wrap (RFC 3394), Key Wrap with Padding (RFC 5649), CCM, SIV, XTS (Day 26) ----------------------
#
# Every mode below but XTS has an integrity check of its own, and the plaintext is returned ONLY when that
# check passes in this code: the 64-bit integrity register of KW (A6A6A6A6A6A6A6A6), the AIV and length of
# KWP, the CCM MAC, the SIV synthetic IV. A wrong key, a tampered byte or a wrong size gives None. XTS has
# no tag: aes_xts_decrypt only decrypts, and the caller's proof (readable text of 32 bytes or more, the
# question's crib or pattern) is the only check.

_KW_IV = b"\xa6" * 8


def _aes_ecb(key: bytes):
    lib = _cipher_lib()
    if lib is None or len(key) not in (16, 24, 32):
        return None
    try:
        return lib[0].new(key, lib[0].MODE_ECB)
    except (ValueError, TypeError):
        return None


def _xor8(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _kw_unwrap_core(c, blocks: list, a: bytes):
    """RFC 3394 section 2.2.2: (A, R[1..n]) after the 6 * n steps run backwards."""
    n = len(blocks)
    r = list(blocks)
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            b = c.decrypt(_xor8(a, (n * j + i).to_bytes(8, "big")) + r[i - 1])
            a, r[i - 1] = b[:8], b[8:]
    return a, r


def _kw_wrap_core(c, a: bytes, r: list):
    n = len(r)
    r = list(r)
    for j in range(6):
        for i in range(1, n + 1):
            b = c.encrypt(a + r[i - 1])
            a = _xor8(b[:8], (n * j + i).to_bytes(8, "big"))
            r[i - 1] = b[8:]
    return a + b"".join(r)


def aes_kw_unwrap(kek: bytes, wrapped: bytes):
    """The key inside an RFC 3394 AES-KW blob, or None. A wrapped blob is n + 1 blocks of 8 bytes,
    n >= 2; the plaintext is returned ONLY when the recovered integrity register equals the default
    initial value A6A6A6A6A6A6A6A6 (constant-time compare)."""
    import hmac
    if len(wrapped) < 24 or len(wrapped) % 8 or len(wrapped) > 1 << 20:
        return None
    c = _aes_ecb(kek)
    if c is None:
        return None
    a, r = _kw_unwrap_core(c, [wrapped[i:i + 8] for i in range(8, len(wrapped), 8)], wrapped[:8])
    return b"".join(r) if hmac.compare_digest(a, _KW_IV) else None


def aes_kw_wrap(kek: bytes, key: bytes):
    """RFC 3394 AES-KW of a key of 16 bytes or more (a multiple of 8); None for other sizes. For tests."""
    c = _aes_ecb(kek)
    if c is None or len(key) < 16 or len(key) % 8:
        return None
    return _kw_wrap_core(c, _KW_IV, [key[i:i + 8] for i in range(0, len(key), 8)])


def aes_kwp_unwrap(kek: bytes, wrapped: bytes):
    """The key inside an RFC 5649 AES-KWP blob, or None. The plaintext is returned ONLY when the
    alternative initial value is A65959A6 followed by the 32-bit message length, that length is
    consistent with the number of 8-byte blocks (8 * (n - 1) < length <= 8 * n), and every padding
    byte is zero."""
    import hmac
    if len(wrapped) < 16 or len(wrapped) % 8 or len(wrapped) > 1 << 20:
        return None
    c = _aes_ecb(kek)
    if c is None:
        return None
    if len(wrapped) == 16:                  # n = 1: a single ECB block
        b = c.decrypt(wrapped)
        a, padded = b[:8], b[8:]
    else:
        a, r = _kw_unwrap_core(c, [wrapped[i:i + 8] for i in range(8, len(wrapped), 8)], wrapped[:8])
        padded = b"".join(r)
    mli = int.from_bytes(a[4:], "big")
    n = len(padded) // 8
    ok = hmac.compare_digest(a[:4], b"\xa6\x59\x59\xa6") and 8 * (n - 1) < mli <= 8 * n and not any(padded[mli:])
    return padded[:mli] if ok else None


def aes_kwp_wrap(kek: bytes, key: bytes):
    """RFC 5649 AES-KWP, for tests."""
    c = _aes_ecb(kek)
    if c is None or not key:
        return None
    padded = key + b"\x00" * (-len(key) % 8)
    a = b"\xa6\x59\x59\xa6" + len(key).to_bytes(4, "big")
    if len(padded) == 8:
        return c.encrypt(a + padded)
    return _kw_wrap_core(c, a, [padded[i:i + 8] for i in range(0, len(padded), 8)])


def aes_ccm_open(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b""):
    """The plaintext of an AES-CCM message (RFC 3610 / NIST 800-38C), or None. Returned ONLY when the
    CCM MAC verifies (pycryptodome's decrypt_and_verify, constant-time). Nonce 7 to 13 bytes, tag 4 to
    16 bytes and even."""
    lib = _cipher_lib()
    if lib is None or len(key) not in (16, 24, 32) or not 7 <= len(nonce) <= 13 \
            or not (4 <= len(tag) <= 16 and len(tag) % 2 == 0):
        return None
    try:
        c = lib[0].new(key, lib[0].MODE_CCM, nonce=nonce, mac_len=len(tag))
        if aad:
            c.update(aad)
        return c.decrypt_and_verify(ct, tag)
    except (ValueError, TypeError, KeyError):
        return None


MAX_SIV_AAD_COMPONENTS = 126
MAX_SIV_AAD_BYTES = 64 * 1024 * 1024


def _siv_aad_components(aad, nonce_present: bool):
    """Normalize RFC 5297's ordered vector of associated-data components.

    A bare byte string keeps the historical API: an empty value means no component.  A sequence
    represents its components exactly, so ``[b""]`` is distinct from ``[]``.  S2V accepts at most
    127 strings; plaintext consumes one, and an explicit nonce consumes another.
    """
    if isinstance(aad, (bytes, bytearray, memoryview)):
        try:
            raw = bytes(aad)
        except (TypeError, ValueError, OverflowError, MemoryError):
            return None
        if len(raw) > MAX_SIV_AAD_BYTES:
            return None
        return [raw] if raw else []
    if isinstance(aad, (str, bytes, bytearray, memoryview)) or not isinstance(aad, Sequence):
        return None
    try:
        component_limit = MAX_SIV_AAD_COMPONENTS - int(nonce_present)
        if len(aad) > component_limit:
            return None
        parts = []
        total = 0
        for component in aad:
            if not isinstance(component, (bytes, bytearray, memoryview)):
                return None
            raw = bytes(component)
            total += len(raw)
            if total > MAX_SIV_AAD_BYTES:
                return None
            parts.append(raw)
        return parts
    except Exception:
        # A hostile custom Sequence must not leak its indexing/iteration exception.
        return None


def aes_siv_open(key: bytes, ct: bytes, tag: bytes, aad=b"", nonce: bytes = None):
    """The plaintext of an AES-SIV message (RFC 5297), or ``None``.

    ``aad`` may be one bytes-like component (the backward-compatible form) or an ordered sequence
    of bytes-like components.  An explicit nonce is authenticated after every supplied component,
    as required by RFC 5297, and before the plaintext.  The plaintext is returned only when the
    16-byte synthetic IV verifies.  The total AAD and component count are bounded; malformed input,
    a wrong key/tag/order, or a missing cipher library returns ``None``.
    """
    if not isinstance(key, (bytes, bytearray, memoryview)) \
            or not isinstance(ct, (bytes, bytearray, memoryview)) \
            or not isinstance(tag, (bytes, bytearray, memoryview)):
        return None
    try:
        key, ct, tag = bytes(key), bytes(ct), bytes(tag)
    except (TypeError, ValueError, OverflowError, MemoryError):
        return None
    lib = _cipher_lib()
    if lib is None or len(key) not in (32, 48, 64) or len(tag) != 16:
        return None
    nonce_present = nonce is not None
    if nonce_present:
        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            return None
        try:
            nonce = bytes(nonce)
        except (TypeError, ValueError, OverflowError, MemoryError):
            return None
        if not nonce or len(nonce) > MAX_SIV_AAD_BYTES:
            return None
    components = _siv_aad_components(aad, nonce_present)
    if components is None:
        return None
    try:
        c = lib[0].new(key, lib[0].MODE_SIV, nonce=nonce) if nonce_present else lib[0].new(key, lib[0].MODE_SIV)
        for component in components:
            c.update(component)
        return c.decrypt_and_verify(ct, tag)
    except (ValueError, TypeError, KeyError, OverflowError, MemoryError):
        return None


def _xts_double(t: bytes) -> bytes:
    n = int.from_bytes(t, "little") << 1
    if n >> 128:
        n = (n & ((1 << 128) - 1)) ^ 0x87
    return n.to_bytes(16, "little")


def aes_xts_decrypt(key: bytes, tweak: bytes, ct: bytes):
    """AES-XTS (IEEE 1619) decryption of one data unit, ciphertext stealing included: key = key1 ||
    key2 (32 or 64 bytes), tweak 16 bytes, ct 16 bytes or more. There is NO tag, so nothing here says
    the key is right: the caller must prove the plaintext."""
    lib = _cipher_lib()
    if lib is None or len(key) not in (32, 64) or len(tweak) != 16 or not 16 <= len(ct) <= 1 << 20:
        return None
    try:
        AES = lib[0]
        h = len(key) // 2
        c1, c2 = AES.new(key[:h], AES.MODE_ECB), AES.new(key[h:], AES.MODE_ECB)
    except (ValueError, TypeError):
        return None
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    dec = lambda blk, tw: xor(c1.decrypt(xor(blk, tw)), tw)
    t = c2.encrypt(tweak)
    full, rem = divmod(len(ct), 16)
    out = []
    for i in range(full if rem == 0 else full - 1):
        out.append(dec(ct[16 * i:16 * i + 16], t))
        t = _xts_double(t)
    if rem:
        pp = dec(ct[16 * (full - 1):16 * full], _xts_double(t))
        last = ct[16 * full:]
        out.append(dec(last + pp[rem:], t))
        out.append(pp[:rem])
    return b"".join(out)


def aes_xts_encrypt(key: bytes, tweak: bytes, pt: bytes):
    """AES-XTS encryption of whole blocks, for tests."""
    AES = _cipher_lib()[0]
    h = len(key) // 2
    c1, c2 = AES.new(key[:h], AES.MODE_ECB), AES.new(key[h:], AES.MODE_ECB)
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    t, out = c2.encrypt(tweak), []
    for i in range(0, len(pt), 16):
        out.append(xor(c1.encrypt(xor(pt[i:i + 16], t)), t))
        t = _xts_double(t)
    return b"".join(out)


def sym_candidates(key: bytes, ct: bytes, iv: bytes = None, tag: bytes = None, algs=None, modes=None, aad: bytes = b"",
                   tweaks=None) -> list:
    """[(name, plaintext)] of every decryption the sizes allow, for a key stated in the artifact.
    name is `<alg>-<mode>` (`aes-256-cbc`, `aes-128-ecb`, `des-cbc`, `3des-cbc`, `rc4`,
    `chacha20`), with `:iv_prefix` when the IV was taken from the first block of the ciphertext
    and `:nopad` when the last block is not PKCS#7 (trailing zero bytes then come off).
    aes-*-gcm is listed only with a tag that verifies. `algs` / `modes` (lowercase sets) narrow
    it to what the artifact states. Which one is the plaintext is the caller's proof."""
    out = []
    lib = _cipher_lib()

    def want(alg, mode=None):
        return (not algs or alg in algs) and (mode is None or not modes or mode in modes)

    def block(alg_name, mod, bs, k, c, ivs):
        if len(c) % bs == 0 and c and want(alg_name.split("-")[0], "ecb"):
            try:
                pt = mod.new(k, mod.MODE_ECB).decrypt(c)
                un = _unpad(pt, bs)
                out.append((f"{alg_name}-ecb" + ("" if un is not None else ":nopad"), un if un is not None else pt.rstrip(b"\x00")))
            except ValueError:
                pass
        for iv_name, v, body in ivs:
            if len(v) != bs:
                continue
            if len(body) % bs == 0 and body and want(alg_name.split("-")[0], "cbc"):
                try:
                    pt = mod.new(k, mod.MODE_CBC, iv=v).decrypt(body)
                    un = _unpad(pt, bs)
                    out.append((f"{alg_name}-cbc{iv_name}" + ("" if un is not None else ":nopad"),
                                un if un is not None else pt.rstrip(b"\x00")))
                except ValueError:
                    pass
            for mode_name, mode, kw in (("cfb", mod.MODE_CFB, {"segment_size": bs * 8}), ("cfb8", mod.MODE_CFB, {"segment_size": 8}),
                                        ("ofb", mod.MODE_OFB, {})):
                if body and want(alg_name.split("-")[0], mode_name):
                    try:
                        out.append((f"{alg_name}-{mode_name}{iv_name}", mod.new(k, mode, iv=v, **kw).decrypt(body)))
                    except ValueError:
                        pass
            if body and want(alg_name.split("-")[0], "ctr"):
                try:
                    out.append((f"{alg_name}-ctr{iv_name}",
                                mod.new(k, mod.MODE_CTR, initial_value=int.from_bytes(v, "big"), nonce=b"").decrypt(body)))
                except ValueError:
                    pass

    if lib is not None:
        AES, DES, DES3, ChaCha20 = lib
        if len(key) in (16, 24, 32):
            ivs = [("", iv, ct)] if iv else ([(":iv_prefix", ct[:16], ct[16:])] if len(ct) > 16 else [])
            block(f"aes-{len(key) * 8}", AES, 16, key, ct, ivs)
            if iv and len(iv) in (8, 12) and want("aes", "ctr"):
                try:
                    out.append((f"aes-{len(key) * 8}-ctr:nonce", AES.new(key, AES.MODE_CTR, nonce=iv).decrypt(ct)))
                except ValueError:
                    pass
            if iv and tag and want("aes", "gcm"):
                try:
                    out.append((f"aes-{len(key) * 8}-gcm", AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)))
                except ValueError:
                    pass
            if want("aes"):
                # integrity-checked modes: each is listed only when its own check passes in this code
                nb = f"aes-{len(key) * 8}"
                pt = aes_kw_unwrap(key, ct)
                if pt is not None:
                    out.append((f"{nb}-kw", pt))
                pt = aes_kwp_unwrap(key, ct)
                if pt is not None:
                    out.append((f"{nb}-kwp", pt))
                if iv and 7 <= len(iv) <= 13:
                    splits = [(ct, tag)] if tag and len(tag) % 2 == 0 and 4 <= len(tag) <= 16 else []
                    splits += [(ct[:-n], ct[-n:]) for n in (16, 12, 8) if len(ct) > n]
                    for body, tg in splits:
                        pt = aes_ccm_open(key, iv, body, tg, aad or b"")
                        if pt is not None:
                            out.append((f"{nb}-ccm", pt))
                            break
        if len(key) in (32, 48, 64) and want("aes"):
            nonce = iv if iv and len(iv) <= 16 else None
            splits = [(ct, tag)] if tag and len(tag) == 16 else []
            splits += [(ct[16:], ct[:16])] if len(ct) >= 16 else []
            for body, tg in splits:
                pt = aes_siv_open(key, body, tg, aad or b"", nonce)
                if pt is not None:
                    out.append(("aes-siv", pt))
                    break
        if len(key) in (32, 64) and tweaks and want("aes"):
            for tw in tweaks[:4]:
                pt = aes_xts_decrypt(key, tw, ct)
                if pt is not None:
                    out.append((f"aes-{len(key) * 4}-xts", pt))
        if len(key) == 8:
            ivs = [("", iv, ct)] if iv else ([(":iv_prefix", ct[:8], ct[8:])] if len(ct) > 8 else [])
            block("des", DES, 8, key, ct, ivs)
        if len(key) in (16, 24):
            try:
                DES3.adjust_key_parity(key)
                ivs = [("", iv, ct)] if iv else ([(":iv_prefix", ct[:8], ct[8:])] if len(ct) > 8 else [])
                block("3des", DES3, 8, key, ct, ivs)
            except ValueError:
                pass
        if len(key) == 32 and iv and len(iv) in (8, 12) and want("chacha20"):
            try:
                out.append(("chacha20", ChaCha20.new(key=key, nonce=iv).decrypt(ct)))
            except ValueError:
                pass
        if len(key) == 32 and iv and len(iv) in (12, 24) and want("chacha20"):
            # AEAD: the plaintext exists only when the Poly1305 tag verifies; a tag may also be the last
            # 16 bytes of the ciphertext
            for body, tg in ((ct, tag), (ct[:-16], ct[-16:] if len(ct) >= 16 else None)):
                if tg is None or len(tg) != 16:
                    continue
                pt = chacha_poly_open(key, iv, body, tg, aad or b"")
                if pt is not None:
                    out.append(("xchacha20-poly1305" if len(iv) == 24 else "chacha20-poly1305", pt))
                    break
        if algs and "salsa20" in algs and len(key) in (16, 32) and iv and len(iv) == 8 and ct:
            # a raw stream: stated by name only; the caller's readable-text proof is its only check
            try:
                from Crypto.Cipher import Salsa20
                out.append(("salsa20", Salsa20.new(key=key, nonce=iv).decrypt(ct)))
            except (ImportError, ValueError):
                pass
        if algs and "blowfish" in algs and 4 <= len(key) <= 56:
            # only when the artifact or the question names it: any key length fits Blowfish
            try:
                from Crypto.Cipher import Blowfish
                ivs = [("", iv, ct)] if iv else ([(":iv_prefix", ct[:8], ct[8:])] if len(ct) > 8 else [])
                block("blowfish", Blowfish, 8, key, ct, ivs)
            except (ImportError, ValueError):
                pass
    if 1 <= len(key) <= 256 and ct and want("rc4"):
        out.append(("rc4", rc4(key, ct)))
    return out


# ---- ECDSA with a repeated nonce --------------------------------------------------------------------------

CURVES = {
    "secp256k1": {"p": 2 ** 256 - 2 ** 32 - 977, "a": 0, "b": 7,
                  "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                  "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
                  "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141},
    "secp256r1": {"p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF, "a": -3,
                  "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
                  "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                  "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
                  "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551},
}
CURVE_NAMES = {"secp256k1": "secp256k1", "p-256": "secp256r1", "p256": "secp256r1", "prime256v1": "secp256r1",
               "secp256r1": "secp256r1", "nistp256": "secp256r1", "nist p-256": "secp256r1"}


def ec_add(P, Q, curve: dict):
    """P + Q on a short Weierstrass curve; None is the point at infinity."""
    if P is None:
        return Q
    if Q is None:
        return P
    p = curve["p"]
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + curve["a"]) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def ec_mul(k: int, curve: dict, point=None):
    """k * point (the generator by default); None at infinity. 256 affine steps: milliseconds."""
    k %= curve["n"]
    addend = point or (curve["gx"], curve["gy"])
    acc = None
    while k:
        if k & 1:
            acc = ec_add(acc, addend, curve)
        addend = ec_add(addend, addend, curve)
        k >>= 1
    return acc


def ecdsa_nonce_reuse(r: int, s1: int, z1: int, s2: int, z2: int, curve=None, public=None):
    """(d, k, curve name) of two signatures (r, s1) over hash z1 and (r, s2) over z2 that share
    their nonce, or None. Proven: x(k*G) mod n == r for the recovered k on the curve, both
    signatures give the same d, and d*G is the public key when one is given. With no curve named
    both are tried; a signature may have been written with either sign of s (low-s). None when
    more than one private key passes."""
    names = [CURVE_NAMES.get(str(curve).lower(), None)] if curve else list(CURVES)
    found = {}
    for name in names:
        if name not in CURVES:
            continue
        cv = CURVES[name]
        n = cv["n"]
        if not (0 < r < n and 0 < s1 < n and 0 < s2 < n) or z1 % n == z2 % n and s1 == s2:
            continue
        for a in (s1, n - s1):
            for b in (s2, n - s2):
                den = (a - b) % n
                if den == 0:
                    continue
                k = (z1 - z2) * pow(den, -1, n) % n
                if k == 0:
                    continue
                pt = ec_mul(k, cv)
                if pt is None or pt[0] % n != r:
                    continue
                rinv = pow(r, -1, n)
                d = (a * k - z1) * rinv % n
                if d == 0 or d != (b * k - z2) * rinv % n:
                    continue
                if public is not None and ec_mul(d, cv) != tuple(public):
                    continue
                found.setdefault((d, name), k)
    if len(found) != 1:
        return None
    (d, name), k = next(iter(found.items()))
    return d, k, name



def dsa_nonce_reuse(p: int, q: int, g: int, y: int, sig1, sig2):
    """The private key x of two DSA signatures (r, s, z) with one r (one nonce), or None. z is the
    hash already cut to q's size. Proven in code: g has order q mod p (q | p-1, g^q = 1, g > 1),
    pow(g, k, p) % q == r for the recovered nonce, both signatures give the same x, and
    pow(g, x, p) == y, the written public key (required: no y, no answer)."""
    try:
        r, s1, z1 = sig1
        r2, s2, z2 = sig2
        if r != r2 or not (p > q > 2 and 1 < g < p and 1 < y < p and (p - 1) % q == 0):
            return None
        if pow(g, q, p) != 1 or not (0 < r < q and 0 < s1 < q and 0 < s2 < q) or s1 == s2:
            return None
        k = (z1 - z2) * pow((s1 - s2) % q, -1, q) % q
        if k == 0 or pow(g, k, p) % q != r:
            return None
        x = (s1 * k - z1) * pow(r, -1, q) % q
        if x == 0 or x != (s2 * k - z2) * pow(r, -1, q) % q or pow(g, x, p) != y:
            return None
        return x
    except (ValueError, TypeError, ZeroDivisionError):
        return None


# ---- generators ---------------------------------------------------------------------------------------------

def mt_untemper(y: int) -> int:
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    x = y
    for _ in range(5):
        x = y ^ ((x << 7) & 0x9D2C5680)
    y = x & 0xFFFFFFFF
    x = y
    for _ in range(3):
        x = y ^ (x >> 11)
    return x & 0xFFFFFFFF


def _mt_temper(y: int) -> int:
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    return (y ^ (y >> 18)) & 0xFFFFFFFF


def _mt_twist(state: list) -> list:
    s = list(state)
    for i in range(624):
        y = (s[i] & 0x80000000) | (s[(i + 1) % 624] & 0x7FFFFFFF)
        s[i] = s[(i + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
    return s


def mt_clone(outputs, count: int = 1):
    """(next `count` outputs, how many given outputs were verified) from >= 624 consecutive
    32-bit MT19937 outputs (`random.getrandbits(32)`). The first 624 give the state; every
    further given output must equal the clone's, or the result is None. 0 verified means the
    prediction rests on the premise alone: the caller must not answer it plain."""
    outputs = _bounded_prng_sequence(outputs, MAX_PRNG_WORDS)
    if outputs is None:
        return None
    # Reject non-integer elements cleanly (e.g. strings) instead of raising a TypeError in the
    # comparison below — parity with java_random_recover, which declines bad input.
    if any(not isinstance(v, int) or isinstance(v, bool) for v in outputs):
        return None
    if len(outputs) < 624 or any(not 0 <= v < 1 << 32 for v in outputs):
        return None
    state = [mt_untemper(v) for v in outputs[:624]]
    pos, produced = 624, []
    need = len(outputs) - 624 + count
    while len(produced) < need:
        if pos == 624:
            state, pos = _mt_twist(state), 0
        produced.append(_mt_temper(state[pos]))
        pos += 1
    extra = outputs[624:]
    if produced[:len(extra)] != extra:
        return None
    return produced[len(extra):], len(extra)


# ---- MT19937 backwards: inverse twist, rewind, run detector, seed boundary (B-063) -----------------
#
# The state is read as one sequence x[0], x[1], ... of 32-bit state words: x[0..623] is what the
# seeding wrote, and every later word follows the recurrence
#     x[n + 624] = x[n + 397] ^ mix(upper(x[n]) | lower(x[n + 1]))     mix(y) = (y >> 1) ^ (A if y & 1)
# (the twist is 624 steps of it). Output k is temper(x[624 + k]). Any 624 consecutive words are a
# full generator state, at any alignment: `_mt_twist` of them is the next 624. The recurrence also
# runs backwards one word at a time: mix is invertible (A's top bit is set and y >> 1's is not, so
# the top bit of mix(y) is y's low bit), and x[n] is split over two neighbouring steps.

_MT_A = 0x9908B0DF
_MT_UPPER, _MT_LOWER = 0x80000000, 0x7FFFFFFF
MAX_MT_SCAN_WORDS = 1 << 20        # words mt_runs reads from one list
MAX_MT_REWIND = 1 << 16            # words one call rewinds, extends or walks back in a seed search
MT_SEED_SEARCH = 4096              # outputs before a window that a seed search covers by default
MT_SEED_KEY_WORDS = 64             # init_by_array keys a seed search tries: up to 2048 bits
MAX_MT_SEED_KEY_WORDS = 310        # two periods of the key must fit in the words the inversion reads

mt_temper = _mt_temper


def _mt_mix(y: int) -> int:
    return (y >> 1) ^ (_MT_A if y & 1 else 0)


def _mt_unmix(v: int) -> int:
    """The y with _mt_mix(y) == v."""
    return ((v ^ _MT_A) << 1) | 1 if v & _MT_UPPER else v << 1


def _mt_step(x, t: int) -> int:
    """x[t] from the words before it."""
    return x[t - 227] ^ _mt_mix((x[t - 624] & _MT_UPPER) | (x[t - 623] & _MT_LOWER))


def _mt_window_ok(x, at: int = 0) -> bool:
    """The 31-bit self-check of the 624 state words x[at:at+624]: the step that made the last
    word read the low 31 bits of the first. True for every window of a real MT19937 sequence;
    one random window in 2**31 passes."""
    return _mt_unmix(x[at + 623] ^ x[at + 396]) & _MT_LOWER == x[at] & _MT_LOWER


def _mt_back(window, count: int) -> list:
    """The `count` state words before a 624-word window that passes _mt_window_ok, oldest first."""
    ext = [0] * count + list(window[:624])
    for i in range(count - 1, -1, -1):
        ext[i] = ((_mt_unmix(ext[i + 624] ^ ext[i + 397]) & _MT_UPPER)
                  | (_mt_unmix(ext[i + 623] ^ ext[i + 396]) & _MT_LOWER))
    return ext[:count]


def _mt_words(values, limit: int):
    """`values` as a list of at most `limit` 32-bit words, or None."""
    rows = _bounded_prng_sequence(values, limit)
    if rows is None:
        return None
    for v in rows:
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < 1 << 32:
            return None
    return rows


def _mt_count(value, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _mt_balanced(words, at: int) -> bool:
    """words[at:at+624] look like full-width random words: each of the 32 bit positions is set
    in a quarter to three quarters of them (a real stream sits within a few percent of half).
    The recurrence checks are linear, so counters, small numbers and text codes can satisfy
    them by accident; such lists fail here."""
    window = words[at:at + 624]
    return all(156 <= sum(v >> bit & 1 for v in window) <= 468 for bit in range(32))


def mt_untwist(state):
    """The 624 state words before `state` (624 words): the generation that twists into it, so
    `_mt_twist(mt_untwist(s)) == s`. None when `state` is not a twist output (the 31-bit
    self-check fails: no earlier generation exists) or is not 624 32-bit words.

    Word 0 of the result is exact only when that generation was itself a twist output. The twist
    reads nothing but its top bit, so for a freshly seeded state (which is not a twist output) the
    low 31 bits are what the recurrence implies, not what the seeding wrote."""
    s = _mt_words(state, 624)
    if s is None or len(s) != 624 or not _mt_window_ok(s):
        return None
    return _mt_back(s, 624)


def mt_extend(window, *, before: int = 0, after: int = 0):
    """(the `before` state words that precede a 624-word state window, the `after` words that
    follow it), both oldest first, raw state words (mt_temper turns one into an output). None
    when the window is not 624 32-bit words, fails the 31-bit self-check, or a count is outside
    0..MAX_MT_REWIND. Arithmetic only: it does not know where the stream began, so words from
    before the seeding are extrapolation (mt_seed_search finds the boundary)."""
    w = _mt_words(window, 624)
    if w is None or len(w) != 624 or not _mt_window_ok(w):
        return None
    if not _mt_count(before, 0, MAX_MT_REWIND) or not _mt_count(after, 0, MAX_MT_REWIND):
        return None
    ext = list(w)
    for t in range(624, 624 + after):
        ext.append(_mt_step(ext, t))
    return _mt_back(w, before), ext[624:]


def mt_rewind(outputs, count: int = 1, *, tempered: bool = True):
    """(the `count` outputs that came before outputs[0], oldest first; how many given outputs
    were verified) from >= 624 consecutive 32-bit MT19937 outputs: the mirror of mt_clone.
    `tempered=False` reads and returns raw state words.

    The first 624 give the state. They must pass the 31-bit self-check and every further given
    output must follow the recurrence, or the result is None. 0 verified means the rewind rests
    on that self-check alone: the caller must not answer it plain. Each further output checks
    the three earlier words its step reads; 624 of them check every given word. Like
    mt_extend, it does not know where the stream began."""
    words = _mt_words(outputs, MAX_PRNG_WORDS)
    if words is None or len(words) < 624 or not _mt_count(count, 1, MAX_MT_REWIND):
        return None
    x = [mt_untemper(v) for v in words] if tempered else words
    if not _mt_window_ok(x) or any(x[t] != _mt_step(x, t) for t in range(624, len(x))):
        return None
    prev = _mt_back(x, count)
    return ([_mt_temper(v) for v in prev] if tempered else prev), len(x) - 624


def mt_runs(words, *, modes=("outputs", "state")):
    """Every stretch of >= 624 consecutive MT19937 words in a list of 32-bit integers.

    Each mode is one reading of the list: "outputs" (tempered, what getrandbits(32) returns) and
    "state" (raw state words, a dumped table). A run is `{"mode", "start", "length", "verified"}`:
    in words[start:start+length] every step that can be checked holds, i.e. the first 624 pass
    the 31-bit self-check and each of the `verified` = length - 624 further words was
    reproduced (32 bits apiece). A 624-word window with nothing after it is reported with
    verified 0: the self-check alone, which the caller must not answer plain. `verified`
    counts checks, not words covered: a step reads three earlier words, so only from 624
    verified on has every given word been read by one (before that a damaged word can sit in
    a run unnoticed, and shows as a second, overlapping run). The first 624 words must also look like
    full-width random words (every bit position set in 25-75% of them), so zeros, counters and
    other small numbers, which can satisfy the linear checks by accident, are never runs. Words
    that are not MT (a header, a trailer, other fields) may surround a run. None when `words`
    is not a list of at most MAX_MT_SCAN_WORDS 32-bit integers or a mode is unknown; [] when it
    holds no run."""
    try:
        modes = list(dict.fromkeys(modes))
    except TypeError:
        return None
    rows = _mt_words(words, MAX_MT_SCAN_WORDS)
    if rows is None or not modes or any(m not in ("outputs", "state") for m in modes):
        return None
    out, n = [], len(rows)
    if n < 624:
        return out
    for mode in modes:
        x = [mt_untemper(v) for v in rows] if mode == "outputs" else rows
        found, t = [], 624
        while t < n:
            if x[t] != _mt_step(x, t):
                t += 1
                continue
            first = t
            while t < n and x[t] == _mt_step(x, t):
                t += 1
            a = first - 624
            # The step that made x[a + 624] read one bit of x[a], so a foreign word in front of a
            # run passes it half the time. Only the self-check says whether x[a] belongs; the
            # window one word on always passes it (it is the low 31 bits of that same step).
            if not _mt_window_ok(x, a):
                a += 1
            if t - a > 624 and _mt_balanced(rows, a):
                found.append((a, t))
        covered = bytearray(n - 623)
        for a, b in found:
            covered[a:b - 623] = b"\x01" * (b - 623 - a)
        for m in range(n - 623):
            if not covered[m] and _mt_window_ok(x, m) and _mt_balanced(rows, m):
                found.append((m, m + 624))
        out.extend({"mode": mode, "start": a, "length": b - a, "verified": b - a - 624}
                   for a, b in sorted(found))
    return out


def _mt_init_genrand(seed: int) -> list:
    s = [seed & 0xFFFFFFFF]
    for i in range(1, 624):
        s.append((1812433253 * (s[-1] ^ (s[-1] >> 30)) + i) & 0xFFFFFFFF)
    return s


_MT_ARRAY_BASE = tuple(_mt_init_genrand(19650218))


def _mt_init_by_array(key) -> list:
    s = list(_MT_ARRAY_BASE)
    i, j = 1, 0
    for _ in range(max(624, len(key))):
        s[i] = ((s[i] ^ ((s[i - 1] ^ (s[i - 1] >> 30)) * 1664525)) + key[j] + j) & 0xFFFFFFFF
        i, j = i + 1, j + 1
        if i >= 624:
            s[0], i = s[623], 1
        if j >= len(key):
            j = 0
    for _ in range(623):
        s[i] = ((s[i] ^ ((s[i - 1] ^ (s[i - 1] >> 30)) * 1566083941)) - i) & 0xFFFFFFFF
        i += 1
        if i >= 624:
            s[0], i = s[623], 1
    s[0] = 0x80000000
    return s


def _mt_seed_at(x, at: int, max_key_words: int):
    """mt_seed_from_state on x[at:at+624], without the copy or the argument checks."""
    mask = 0xFFFFFFFF
    # init_genrand(seed): each word is a fixed function of the one before it.
    if x[at + 2] == (1812433253 * (x[at + 1] ^ (x[at + 1] >> 30)) + 2) & mask:
        v = ((x[at + 1] - 1) * pow(1812433253, -1, 1 << 32)) & mask
        seed = v ^ (v >> 30)
        if seed & _MT_UPPER == x[at] & _MT_UPPER and _mt_init_genrand(seed)[1:] == x[at + 1:at + 624]:
            return {"kind": "init_genrand", "seed": seed}
    # init_by_array(key) ends by setting word 0 to 0x80000000. Undo its second pass (a = the words
    # after the first pass), then read d[j] = key[j % L] + j % L off the first pass: it repeats
    # with the key's length L. The proof is regenerating the state from the key.
    if not x[at] & _MT_UPPER:
        return None
    span = max_key_words + 4
    a = [0, ((x[at + 1] + 1) & mask) ^ (((x[at + 623] ^ (x[at + 623] >> 30)) * 1566083941) & mask)]
    for i in range(2, span + 1):
        prev = a[1] if i == 2 else x[at + i - 1]
        a.append(((x[at + i] + i) & mask) ^ (((prev ^ (prev >> 30)) * 1566083941) & mask))
    d = [(a[j + 1] - (_MT_ARRAY_BASE[j + 1] ^ (((a[j] ^ (a[j] >> 30)) * 1664525) & mask))) & mask
         for j in range(2, span)]                      # d[0] is j = 2
    for length in range(1, max_key_words + 1):
        if d[length] != d[0] or d[length + 1] != d[1]:
            continue
        key = [0] * length
        for j in range(2, 2 + length):
            key[j % length] = (d[j - 2] - j % length) & mask
        if _mt_init_by_array(key)[1:] == x[at + 1:at + 624]:
            return _mt_key_seed(key)
    return None


def _mt_key_seed(key) -> dict:
    seed = sum(word << (32 * i) for i, word in enumerate(key))
    out = {"kind": "init_by_array", "key": list(key), "python_seed": seed}
    # CPython seeds from a str or bytes `a` with the integer of a + sha512(a) (seed version 2).
    # Leading zero bytes of `a` are lost in the integer: the shortest such `a` is reported.
    raw = seed.to_bytes(4 * len(key), "big").lstrip(b"\0")
    if len(raw) >= 64 and hashlib.sha512(raw[:-64]).digest() == raw[-64:]:
        out["python_seed_bytes"] = raw[:-64].hex()
    return out


def mt_seed_from_state(state, *, max_key_words: int = MT_SEED_KEY_WORDS):
    """How a freshly seeded 624-word MT19937 state was made, or None. Proven by regenerating it.

      {"kind": "init_genrand", "seed": s}
          init_genrand(s): C++ std::mt19937(s), numpy RandomState(s), the reference mt19937ar.
      {"kind": "init_by_array", "key": [...], "python_seed": n}
          init_by_array(key): the shortest key, of at most `max_key_words` 32-bit words, that
          regenerates the state. CPython random.seed(n) uses the key of abs(n), read
          little-endian, so n is a seed that reproduces the stream (seeds whose key[j] + j
          repeat with a shorter period share one state). "python_seed_bytes" (hex) is added when
          n is a + sha512(a): random.seed(a) for a str or bytes a.

    Only the top bit of word 0 is compared: the twist never reads the rest, so a rewound state
    does not carry it. None for a state that is mid-stream, seeded another way (a longer key,
    os.urandom), or not 624 32-bit words."""
    s = _mt_words(state, 624)
    if s is None or len(s) != 624 or not _mt_count(max_key_words, 1, MAX_MT_SEED_KEY_WORDS):
        return None
    return _mt_seed_at(s, 0, max_key_words)


def mt_seed_search(window, *, max_outputs: int = MT_SEED_SEARCH, max_key_words: int = MT_SEED_KEY_WORDS):
    """Where the stream of a 624-word state window began: `{"outputs_before": k, **seed}` for the
    smallest k <= max_outputs such that the 624 words ending k words before the window are a
    freshly seeded state (mt_seed_from_state), i.e. the generator had produced exactly k outputs
    before the window's first word. None when no boundary lies in range, the window is not 624
    32-bit words or fails the 31-bit self-check, or a bound is out of range (max_outputs at most
    MAX_MT_REWIND - 624, max_key_words at most MAX_MT_SEED_KEY_WORDS)."""
    w = _mt_words(window, 624)
    if w is None or len(w) != 624 or not _mt_window_ok(w):
        return None
    if not _mt_count(max_outputs, 0, MAX_MT_REWIND - 624) or not _mt_count(max_key_words, 1, MAX_MT_SEED_KEY_WORDS):
        return None
    back = max_outputs + 624
    x = _mt_back(w, back) + w
    for k in range(max_outputs + 1):
        seed = _mt_seed_at(x, back - k - 624, max_key_words)
        if seed is not None:
            return {"outputs_before": k, **seed}
    return None


# ---- exact mixed-observation PRNG recovery ---------------------------------------------------------

MAX_PRNG_OBSERVATIONS = 4096
MAX_PRNG_WORDS = 4096
MAX_PRNG_SCENARIOS = 256
MAX_SEED_CANDIDATES = 1_000_000


def _bounded_prng_sequence(values, limit=MAX_PRNG_OBSERVATIONS):
    """Materialize at most ``limit`` caller observations, declining oversized/infinite streams."""
    try:
        rows = list(itertools.islice(iter(values), limit + 1))
    except (TypeError, MemoryError):
        return None
    return rows if len(rows) <= limit else None


def python_shuffle_observations(before, after):
    """Recover Fisher--Yates ``randrange(i+1)`` results from a permutation of unique values.

    The returned observation list is suitable for :func:`python_random_recover`. Rejection counts
    remain unknown and are bounded there. Duplicate elements make the swap sequence ambiguous and
    are declined.
    """
    try:
        source = _bounded_prng_sequence(before, 10000)
        target = _bounded_prng_sequence(after, 10000)
    except (TypeError, MemoryError):
        return None
    if source is None or target is None or not 2 <= len(source) <= 10000 or len(source) != len(target):
        return None
    try:
        if len(set(source)) != len(source) or set(source) != set(target):
            return None
    except TypeError:
        return None
    work, observations = source[:], []
    for index in range(len(work) - 1, 0, -1):
        try:
            chosen = work.index(target[index], 0, index + 1)
        except ValueError:
            return None
        observations.append({"kind": "randrange", "stop": index + 1, "value": chosen})
        work[index], work[chosen] = work[chosen], work[index]
    return observations if work == target else None


def python_sample_observations(population, sample):
    """Invert CPython's pool-path ``random.sample`` choices for unique caller-supplied values."""
    try:
        pool = _bounded_prng_sequence(population, 10000)
        selected = _bounded_prng_sequence(sample, 10000)
    except (TypeError, MemoryError):
        return None
    if pool is None or selected is None or not selected or len(selected) > len(pool) or len(pool) > 10000:
        return None
    try:
        if len(set(pool)) != len(pool) or len(set(selected)) != len(selected):
            return None
    except TypeError:
        return None
    observations = []
    for i, value in enumerate(selected):
        limit = len(pool) - i
        try:
            choice = pool.index(value, 0, limit)
        except ValueError:
            return None
        observations.append({"kind": "randrange", "stop": limit, "value": choice})
        pool[choice] = pool[limit - 1]
    return observations


def _expand_random_scenarios(observations, max_rejections):
    try:
        bounded = _bounded_prng_sequence(observations)
        if bounded is None:
            return None
        rows = [dict(row) for row in bounded]
    except (TypeError, ValueError, MemoryError):
        return None
    if not rows or len(rows) > MAX_PRNG_OBSERVATIONS or not 0 <= max_rejections <= 8:
        return None
    scenarios = [[]]
    for row in rows:
        if row.get("kind") == "randrange" and "rejections" not in row:
            choices = range(max_rejections + 1)
        else:
            choices = (row.get("rejections", 0),)
        new = []
        for scenario in scenarios:
            for rejected in choices:
                if not isinstance(rejected, int) or isinstance(rejected, bool) or rejected < 0:
                    return None
                candidate = dict(row)
                candidate["rejections"] = rejected
                new.append(scenario + [candidate])
                if len(new) > MAX_PRNG_SCENARIOS:
                    return None
        scenarios = new
    return scenarios


def _random_words_used(scenario):
    total = 0
    for row in scenario:
        kind = row.get("kind")
        if kind == "random":
            total += 2
        elif kind in ("uint32", "getrandbits"):
            bits = row.get("bits", 32) if kind == "getrandbits" else 32
            total += int(bits > 0)
        elif kind == "randrange":
            total += row.get("rejections", 0) + 1
        else:
            return None
    return total


def _replay_random_words(words, scenario):
    cursor = 0
    for row in scenario:
        kind, value = row.get("kind"), row.get("value")
        if kind == "uint32":
            if not isinstance(value, int) or words[cursor] != value:
                return False
            cursor += 1
        elif kind == "getrandbits":
            bits = row.get("bits")
            if not isinstance(bits, int) or not 0 <= bits <= 32 or not isinstance(value, int):
                return False
            if bits == 0:
                if value != 0:
                    return False
            else:
                if words[cursor] >> (32 - bits) != value:
                    return False
                cursor += 1
        elif kind == "random":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return False
            numerator = (words[cursor] >> 5) * (1 << 26) + (words[cursor + 1] >> 6)
            if numerator / float(1 << 53) != float(value):
                return False
            cursor += 2
        elif kind == "randrange":
            stop = row.get("stop")
            if not isinstance(stop, int) or isinstance(stop, bool) or not 1 <= stop <= 1 << 32:
                return False
            bits = stop.bit_length()
            if bits > 32 or not isinstance(value, int) or not 0 <= value < stop:
                return False
            for _ in range(row.get("rejections", 0)):
                if words[cursor] >> (32 - bits) < stop:
                    return False
                cursor += 1
            if words[cursor] >> (32 - bits) != value:
                return False
            cursor += 1
        else:
            return False
    return cursor == len(words)


def _z3_mt_outputs(z3, count):
    state = [z3.BitVec(f"mt_{i}", 32) for i in range(624)]
    current, position, outputs = state, 0, []

    def temper(value):
        value = value ^ z3.LShR(value, 11)
        value = value ^ ((value << 7) & z3.BitVecVal(0x9D2C5680, 32))
        value = value ^ ((value << 15) & z3.BitVecVal(0xEFC60000, 32))
        return value ^ z3.LShR(value, 18)

    while len(outputs) < count:
        if position == 624:
            twisted = list(current)
            for i in range(624):
                value = ((twisted[i] & z3.BitVecVal(0x80000000, 32)) |
                         (twisted[(i + 1) % 624] & z3.BitVecVal(0x7FFFFFFF, 32)))
                magic = z3.If((value & 1) == 1, z3.BitVecVal(0x9908B0DF, 32), z3.BitVecVal(0, 32))
                twisted[i] = twisted[(i + 397) % 624] ^ z3.LShR(value, 1) ^ magic
            current, position = twisted, 0
        outputs.append(temper(current[position]))
        position += 1
    return state, outputs


def _solve_python_scenario(scenario, timeout_ms):
    try:
        import z3
    except Exception:
        return None, "unavailable"
    used = _random_words_used(scenario)
    if used is None or used > MAX_PRNG_WORDS:
        return None, "invalid"
    _, outputs = _z3_mt_outputs(z3, used + 1)
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    cursor = 0
    for row in scenario:
        kind, value = row.get("kind"), row.get("value")
        if kind == "uint32":
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << 32:
                return None, "invalid"
            solver.add(outputs[cursor] == value)
            cursor += 1
        elif kind == "getrandbits":
            bits = row.get("bits")
            if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 32 \
                    or not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << bits if bits else 1):
                return None, "invalid"
            if bits:
                solver.add(z3.LShR(outputs[cursor], 32 - bits) == value)
                cursor += 1
        elif kind == "random":
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= float(value) < 1:
                return None, "invalid"
            numerator = int(float(value) * (1 << 53))
            if numerator / float(1 << 53) != float(value):
                return None, "invalid"
            solver.add(z3.LShR(outputs[cursor], 5) == numerator >> 26)
            solver.add(z3.LShR(outputs[cursor + 1], 6) == numerator & ((1 << 26) - 1))
            cursor += 2
        elif kind == "randrange":
            stop, accepted, rejected = row.get("stop"), value, row.get("rejections", 0)
            if not isinstance(stop, int) or isinstance(stop, bool) or not 1 <= stop <= 1 << 32 \
                    or not isinstance(accepted, int) or isinstance(accepted, bool) or not 0 <= accepted < stop:
                return None, "invalid"
            bits = stop.bit_length()
            if bits > 32:
                return None, "invalid"
            for _ in range(rejected):
                solver.add(z3.UGE(z3.LShR(outputs[cursor], 32 - bits), stop))
                cursor += 1
            solver.add(z3.LShR(outputs[cursor], 32 - bits) == accepted)
            cursor += 1
        else:
            return None, "invalid"
    status = solver.check()
    if status == z3.unknown:
        return None, "unknown"
    if status != z3.sat:
        return None, "unsat"
    model = solver.model()
    concrete = [model.eval(output, model_completion=True).as_long() for output in outputs[:used]]
    if not _replay_random_words(concrete, scenario):
        return None, "invalid"
    prediction = model.eval(outputs[used], model_completion=True).as_long()
    solver.push()
    solver.add(outputs[used] != prediction)
    unique = solver.check()
    solver.pop()
    if unique == z3.unknown:
        return None, "unknown"
    if unique == z3.sat:
        return None, "ambiguous"
    return {"next_uint32": prediction, "consumed_words": used,
            "verified_observations": len(scenario)}, "sat"


def python_random_recover(observations, *, max_rejections: int = 2, timeout_ms: int = 20000):
    """Predict CPython MT19937's next 32-bit word from mixed exact observations.

    Observations are mappings of ``kind``: ``uint32``, ``getrandbits`` (``bits<=32``), ``random``
    (the exact float), or ``randrange`` (``stop,value`` and optional exact ``rejections``). Unknown
    randrange rejection counts are enumerated up to ``max_rejections``. The result is returned only
    when every feasible hidden-rejection scenario proves the same unique next word; otherwise None.
    The capture is assumed to start at an MT state-array boundary, as with classic cloning traces.
    """
    scenarios = _expand_random_scenarios(observations, max_rejections)
    if not scenarios:
        return None
    # Soundness of the "verified" stamp: when a randrange row has an UNKNOWN rejection count and a
    # rejection-capable stop (not a power of two — CPython's _randbelow only rejects then), the true
    # draw may have rejected MORE than max_rejections times, so its real scenario is not enumerated and
    # the uniqueness vote below could miss it. In that case we still return the prediction but mark it
    # unproven (verified=False) so the caller treats it as a candidate, not a proof.
    def _rejection_capable(obs):
        for row in obs if isinstance(obs, (list, tuple)) else ():
            if not isinstance(row, dict) or row.get("kind") != "randrange":
                continue
            rej = row.get("rejections")
            if isinstance(rej, int) and not isinstance(rej, bool):
                continue  # exact rejection count supplied → fully determined, no assumption
            stop = row.get("stop")
            if isinstance(stop, int) and stop > 1 and (stop & (stop - 1)) != 0:
                return True  # non-power-of-two stop with unknown rejections → bounded assumption
        return False
    bounded_assumption = _rejection_capable(observations)
    proven = not bounded_assumption
    if len(scenarios) == 1 and len(scenarios[0]) >= 624 and all(
            row.get("kind") == "uint32" for row in scenarios[0]):
        values = [row.get("value") for row in scenarios[0]]
        cloned = mt_clone(values, 1)
        if cloned is not None:
            return {"next_uint32": cloned[0][0], "feasible_scenarios": 1,
                    "verified": True, "aligned_state_boundary": True}
    predictions, feasible = set(), 0
    for scenario in scenarios:
        got, status = _solve_python_scenario(scenario, timeout_ms)
        if status in ("unavailable", "invalid", "unknown", "ambiguous"):
            return None
        if status == "unsat":
            continue
        feasible += 1
        predictions.add(got["next_uint32"])
        if len(predictions) > 1:
            return None
    if feasible == 0 or len(predictions) != 1:
        return None
    return {"next_uint32": predictions.pop(), "feasible_scenarios": feasible,
            "verified": proven, "aligned_state_boundary": True,
            "assumed_max_rejections": None if proven else max_rejections}


def python_random_float_recover(values, *, timeout_ms: int = 30000):
    """Predict the next CPython ``random()`` float from aligned consecutive float outputs.

    The first 312 floats expose the high 27/26 bits of one full MT state array. Missing low bits are
    symbolic, later floats constrain the next twisted array, and the 53-bit next numerator must be
    unique. This intentionally returns None for underdetermined traces.
    """
    try:
        bounded = _bounded_prng_sequence(values, 2048)
        if bounded is None:
            return None
        floats = [float(value) for value in bounded]
        import z3
    except Exception:
        return None
    if not 312 <= len(floats) <= 2048 or any(not 0 <= value < 1 for value in floats):
        return None
    numerators = [int(value * (1 << 53)) for value in floats]
    if any(numerator / float(1 << 53) != value for numerator, value in zip(numerators, floats)):
        return None

    def untemper(value):
        value = value ^ z3.LShR(value, 18)
        value = value ^ ((value << 15) & z3.BitVecVal(0xEFC60000, 32))
        fixed = value
        for _ in range(5):
            fixed = value ^ ((fixed << 7) & z3.BitVecVal(0x9D2C5680, 32))
        value = fixed
        fixed = value
        for _ in range(3):
            fixed = value ^ z3.LShR(fixed, 11)
        return fixed

    def temper(value):
        value = value ^ z3.LShR(value, 11)
        value = value ^ ((value << 7) & z3.BitVecVal(0x9D2C5680, 32))
        value = value ^ ((value << 15) & z3.BitVecVal(0xEFC60000, 32))
        return value ^ z3.LShR(value, 18)

    tempered, state = [], []
    for index, numerator in enumerate(numerators[:312]):
        for suffix, high, missing in (("a", numerator >> 26, 5),
                                      ("b", numerator & ((1 << 26) - 1), 6)):
            low = z3.BitVec(f"pyfloat_{index}_{suffix}", missing)
            word = (z3.BitVecVal(high, 32) << missing) | z3.ZeroExt(32 - missing, low)
            tempered.append(word)
            state.append(untemper(word))
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    produced = []
    position = 624
    need = (len(floats) - 312) * 2 + 2
    while len(produced) < need:
        if position == 624:
            twisted = list(state)
            for i in range(624):
                word = ((twisted[i] & z3.BitVecVal(0x80000000, 32)) |
                        (twisted[(i + 1) % 624] & z3.BitVecVal(0x7FFFFFFF, 32)))
                twisted[i] = (twisted[(i + 397) % 624] ^ z3.LShR(word, 1) ^
                              z3.If((word & 1) == 1, z3.BitVecVal(0x9908B0DF, 32), z3.BitVecVal(0, 32)))
            state, position = twisted, 0
        produced.append(temper(state[position]))
        position += 1
    for pair, numerator in enumerate(numerators[312:]):
        solver.add(z3.LShR(produced[pair * 2], 5) == numerator >> 26)
        solver.add(z3.LShR(produced[pair * 2 + 1], 6) == numerator & ((1 << 26) - 1))
    next_a, next_b = produced[-2], produced[-1]
    next_numerator = (z3.BV2Int(z3.LShR(next_a, 5)) * (1 << 26)
                      + z3.BV2Int(z3.LShR(next_b, 6)))
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    predicted = model.eval(next_numerator, model_completion=True).as_long()
    # Exact replay of every supplied float from the selected model.
    all_words = tempered + produced[:-2]
    concrete = [model.eval(word, model_completion=True).as_long() for word in all_words]
    if len(concrete) != len(floats) * 2 or any(
            ((concrete[i * 2] >> 5) * (1 << 26) + (concrete[i * 2 + 1] >> 6)) != numerators[i]
            for i in range(len(floats))):
        return None
    solver.add(next_numerator != predicted)
    if solver.check() != z3.unsat:
        return None
    return {"next": predicted / float(1 << 53), "numerator": predicted,
            "verified_outputs": len(floats), "verified": True,
            "aligned_state_boundary": True}


def python_seed_recover(observations, seed_start: int, seed_stop: int):
    """Bounded exact CPython seed/time-seed search; returns a next word only when candidates agree."""
    import random
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (seed_start, seed_stop)) \
            or seed_stop <= seed_start or seed_stop - seed_start > MAX_SEED_CANDIDATES:
        return None
    scenarios = _expand_random_scenarios(observations, 0)
    if not scenarios or len(scenarios) != 1:
        return None
    scenario = scenarios[0]
    # Validate every row ONCE before the seed loop (mirrors _solve_python_scenario's guard). A
    # getrandbits row with an unbounded ``bits`` would otherwise make each of up to MAX_SEED_CANDIDATES
    # seeds allocate/generate a giant integer before the value mismatch — a resource-exhaustion vector.
    for row in scenario:
        kind = row.get("kind")
        if kind == "getrandbits":
            bits = row.get("bits")
            if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 32:
                return None
        elif kind == "randrange":
            stop = row.get("stop")
            if not isinstance(stop, int) or isinstance(stop, bool) or stop <= 0 or stop > 1 << 64:
                return None
        elif kind not in ("uint32", "random"):
            return None
    matches = []
    for seed in range(seed_start, seed_stop):
        generator = random.Random(seed)
        ok = True
        for row in scenario:
            kind, value = row.get("kind"), row.get("value")
            if kind == "uint32":
                got = generator.getrandbits(32)
            elif kind == "getrandbits":
                got = generator.getrandbits(row.get("bits"))
            elif kind == "random":
                got = generator.random()
            elif kind == "randrange":
                got = generator.randrange(row.get("stop"))
            else:
                return None
            if got != value:
                ok = False
                break
        if ok:
            matches.append((seed, generator.getrandbits(32)))
    if not matches or len({value for _, value in matches}) != 1:
        return None
    return {"seed": matches[0][0] if len(matches) == 1 else None,
            "candidate_count": len(matches), "next_uint32": matches[0][1], "verified": True}


JAVA_RANDOM_MULTIPLIER = 0x5DEECE66D
JAVA_RANDOM_ADDEND = 0xB
JAVA_RANDOM_MASK = (1 << 48) - 1


def java_random_recover(outputs):
    """Recover java.util.Random from consecutive ``nextInt()`` outputs by its exact low-16 search."""
    try:
        bounded = _bounded_prng_sequence(outputs)
        if bounded is None:
            return None
        values = [int(value) & 0xFFFFFFFF for value in bounded]
    except (TypeError, ValueError, MemoryError):
        return None
    if not 2 <= len(values) <= MAX_PRNG_OBSERVATIONS:
        return None
    states = []
    for low in range(1 << 16):
        state = (values[0] << 16) | low
        nxt = (state * JAVA_RANDOM_MULTIPLIER + JAVA_RANDOM_ADDEND) & JAVA_RANDOM_MASK
        if nxt >> 16 != values[1]:
            continue
        probe = nxt
        if all(((probe := (probe * JAVA_RANDOM_MULTIPLIER + JAVA_RANDOM_ADDEND) & JAVA_RANDOM_MASK) >> 16)
               == value for value in values[2:]):
            states.append(probe)
    predictions = {((state * JAVA_RANDOM_MULTIPLIER + JAVA_RANDOM_ADDEND) & JAVA_RANDOM_MASK) >> 16
                   for state in states}
    if not states or len(predictions) != 1:
        return None
    return {"next_uint32": predictions.pop(), "state_candidates": len(states),
            "verified_outputs": len(values), "verified": True}


def java_random_truncated_recover(outputs, bits: int, *, timeout_ms: int = 20000):
    """Recover ``java.util.Random.next(bits)`` from truncated high-bit outputs.

    The 48-bit LCG is encoded exactly as bit-vectors.  A prediction is returned
    only if every supplied output is satisfiable and *all* satisfying internal
    states agree on the next output.  This covers any Java ``next(bits)`` width
    from 1 through 32 without enumerating the missing ``48-bits`` state bits.
    """
    try:
        bounded = _bounded_prng_sequence(outputs)
        values = [int(value) for value in bounded] if bounded is not None else []
        import z3
    except Exception:
        return None
    if (isinstance(bits, bool) or not isinstance(bits, int) or not 1 <= bits <= 32
            or not 2 <= len(values) <= MAX_PRNG_OBSERVATIONS
            or any(not 0 <= value < 1 << bits for value in values)):
        return None
    # The modular-interval path is exact and dramatically faster when the first
    # two high-bit observations leave a bounded number of low-state candidates.
    fast = lcg_truncated_predict(
        values, JAVA_RANDOM_MULTIPLIER, JAVA_RANDOM_ADDEND, 1 << 48, 48 - bits
    )
    if fast is not None:
        return {"next": fast[0], "bits": bits, "verified_outputs": len(values),
                "verified": True, "method": "modular-interval"}
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    state = z3.BitVec("java_truncated_state_0", 48)
    states = []
    for index, expected in enumerate(values):
        if index:
            state = (state * z3.BitVecVal(JAVA_RANDOM_MULTIPLIER, 48)
                     + z3.BitVecVal(JAVA_RANDOM_ADDEND, 48))
        states.append(state)
        solver.add(z3.LShR(state, 48 - bits) == expected)
    next_state = (state * z3.BitVecVal(JAVA_RANDOM_MULTIPLIER, 48)
                  + z3.BitVecVal(JAVA_RANDOM_ADDEND, 48))
    next_output = z3.LShR(next_state, 48 - bits)
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    concrete = [model.eval(item, model_completion=True).as_long() for item in states]
    if (any((item >> (48 - bits)) != expected for item, expected in zip(concrete, values))
            or any(concrete[index] != (
                concrete[index - 1] * JAVA_RANDOM_MULTIPLIER + JAVA_RANDOM_ADDEND
            ) & JAVA_RANDOM_MASK for index in range(1, len(concrete)))):
        return None
    prediction = model.eval(next_output, model_completion=True).as_long()
    solver.add(next_output != prediction)
    if solver.check() != z3.unsat:
        return None
    return {"next": prediction, "bits": bits, "verified_outputs": len(values),
            "verified": True}


def java_seed_recover(outputs, seed_start: int, seed_stop: int):
    try:
        bounded = _bounded_prng_sequence(outputs)
        if bounded is None:
            return None
        values = [int(value) & 0xFFFFFFFF for value in bounded]
    except (TypeError, ValueError, MemoryError):
        return None
    if not values or not all(isinstance(v, int) and not isinstance(v, bool) for v in (seed_start, seed_stop)) \
            or seed_stop <= seed_start or seed_stop - seed_start > MAX_SEED_CANDIDATES:
        return None
    matches = []
    for seed in range(seed_start, seed_stop):
        state = (seed ^ JAVA_RANDOM_MULTIPLIER) & JAVA_RANDOM_MASK
        produced = []
        for _ in range(len(values) + 1):
            state = (state * JAVA_RANDOM_MULTIPLIER + JAVA_RANDOM_ADDEND) & JAVA_RANDOM_MASK
            produced.append(state >> 16)
        if produced[:-1] == values:
            matches.append((seed, produced[-1]))
    if not matches or len({value for _, value in matches}) != 1:
        return None
    return {"seed": matches[0][0] if len(matches) == 1 else None,
            "candidate_count": len(matches), "next_uint32": matches[0][1], "verified": True}


def glibc_random_type3_recover(outputs, *, timeout_ms: int = 10000):
    """Predict glibc ``random()`` TYPE_3 from >=32 consecutive 31-bit outputs using exact SMT."""
    try:
        bounded = _bounded_prng_sequence(outputs)
        if bounded is None:
            return None
        values = [int(value) for value in bounded]
        import z3
    except Exception:
        return None
    if not 32 <= len(values) <= MAX_PRNG_OBSERVATIONS or any(not 0 <= value < 1 << 31 for value in values):
        return None
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    states = [(z3.BitVecVal(value << 1, 32) | z3.ZeroExt(31, z3.BitVec(f"glibc_bit_{i}", 1)))
              for i, value in enumerate(values[:31])]
    for i in range(31, len(values)):
        state = states[i - 3] + states[i - 31]
        states.append(state)
        solver.add(z3.LShR(state, 1) == values[i])
    next_state = states[-3] + states[-31]
    next_output = z3.LShR(next_state, 1)
    status = solver.check()
    if status != z3.sat:
        return None
    model = solver.model()
    prediction = model.eval(next_output, model_completion=True).as_long()
    # Concrete round-trip of every recurrence from the chosen exact low bits.
    concrete = [model.eval(state, model_completion=True).as_long() for state in states]
    if any((concrete[i] >> 1) != values[i] for i in range(len(values))) or any(
            concrete[i] != (concrete[i - 3] + concrete[i - 31]) & 0xFFFFFFFF
            for i in range(31, len(values))):
        return None
    solver.add(next_output != prediction)
    if solver.check() != z3.unsat:
        return None
    return {"next": prediction, "verified_outputs": len(values), "verified": True}


# B-135: glibc srand()/rand() forward model (TYPE_3, the default 128-byte state), for seed searches.
GLIBC_RAND_DEG, GLIBC_RAND_SEP, GLIBC_RAND_DISCARD = 31, 3, 310


def _c_divmod(a: int, b: int) -> tuple[int, int]:
    """C99 integer division (quotient truncated toward zero) of a by b > 0."""
    q = abs(a) // b
    q = -q if a < 0 else q
    return q, a - q * b


def glibc_srand_state(seed: int) -> list[int]:
    """The 34 words srandom_r() leaves before its 310 discarded outputs: r[0] = seed (0 becomes 1),
    r[1..30] by Schrage's 16807 * r mod 2^31-1 on the seed read as int32, r[31..33] = r[0..2]."""
    seed = int(seed) & 0xFFFFFFFF
    if seed == 0:
        seed = 1
    r = [seed]
    word = seed - (1 << 32) if seed & 0x80000000 else seed
    for _ in range(1, GLIBC_RAND_DEG):
        hi, lo = _c_divmod(word, 127773)
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += 2147483647
        r.append(word & 0xFFFFFFFF)
    r.extend(r[:GLIBC_RAND_SEP])
    return r


def glibc_rand_outputs(seed: int, count: int) -> list[int]:
    """The first `count` values of glibc rand() after srand(seed): r[i] = r[i-31] + r[i-3] (mod 2^32)
    from i = 34, the first 310 discarded, each output r[i] >> 1."""
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 1 << 24:
        raise ValueError("count must be an int in [0, 2^24]")
    r = glibc_srand_state(seed)
    first = GLIBC_RAND_DEG + GLIBC_RAND_SEP + GLIBC_RAND_DISCARD           # 344
    for i in range(len(r), first + count):
        r.append((r[i - 31] + r[i - 3]) & 0xFFFFFFFF)
    return [v >> 1 for v in r[first:first + count]]


def glibc_seed_recover(outputs, seed_start: int, seed_stop: int):
    """The srand() seed(s) in [seed_start, seed_stop) whose rand() stream starts with `outputs`."""
    try:
        bounded = _bounded_prng_sequence(outputs)
        if bounded is None:
            return None
        values = [int(value) for value in bounded]
    except (TypeError, ValueError, MemoryError):
        return None
    if (not values or any(not 0 <= v <= 0x7FFFFFFF for v in values)
            or not all(isinstance(v, int) and not isinstance(v, bool) for v in (seed_start, seed_stop))
            or seed_stop <= seed_start or seed_stop - seed_start > MAX_SEED_CANDIDATES
            or seed_start < 0 or seed_stop > 1 << 32):
        return None
    matches = []
    for seed in range(seed_start, seed_stop):
        produced = glibc_rand_outputs(seed, len(values) + 1)
        if produced[:-1] == values:
            matches.append((seed, produced[-1]))
    if not matches or len({value for _, value in matches}) != 1:
        return None
    return {"seed": matches[0][0] if len(matches) == 1 else None,
            "candidate_count": len(matches), "next": matches[0][1], "verified": True}


def php_mt_rand_recover(outputs, *, timeout_ms: int = 20000):
    """Predict modern PHP mt_rand() (31 high MT19937 bits) at an aligned state boundary."""
    try:
        bounded = _bounded_prng_sequence(outputs)
        if bounded is None:
            return None
        values = [int(value) for value in bounded]
        import z3
    except Exception:
        return None
    if not 624 <= len(values) <= MAX_PRNG_OBSERVATIONS or any(not 0 <= value < 1 << 31 for value in values):
        return None
    # Each observed word has exactly two possible tempered values. Untemper both, so the solver has
    # only one Boolean per state word rather than 624 unconstrained 32-bit vectors.
    choices = [(mt_untemper(value << 1), mt_untemper((value << 1) | 1)) for value in values[:624]]
    state = [z3.If(z3.Bool(f"php_lsb_{i}"), z3.BitVecVal(one, 32), z3.BitVecVal(zero, 32))
             for i, (zero, one) in enumerate(choices)]
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    produced = []
    position = 624
    while len(produced) < len(values) - 624 + 1:
        if position == 624:
            twisted = list(state)
            for i in range(624):
                word = ((twisted[i] & z3.BitVecVal(0x80000000, 32)) |
                        (twisted[(i + 1) % 624] & z3.BitVecVal(0x7FFFFFFF, 32)))
                twisted[i] = (twisted[(i + 397) % 624] ^ z3.LShR(word, 1) ^
                              z3.If((word & 1) == 1, z3.BitVecVal(0x9908B0DF, 32), z3.BitVecVal(0, 32)))
            state, position = twisted, 0
        word = state[position]
        word = word ^ z3.LShR(word, 11)
        word = word ^ ((word << 7) & z3.BitVecVal(0x9D2C5680, 32))
        word = word ^ ((word << 15) & z3.BitVecVal(0xEFC60000, 32))
        word = word ^ z3.LShR(word, 18)
        produced.append(z3.LShR(word, 1))
        position += 1
    for expression, expected in zip(produced, values[624:]):
        solver.add(expression == expected)
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    prediction = model.eval(produced[-1], model_completion=True).as_long()
    solver.add(produced[-1] != prediction)
    if solver.check() != z3.unsat:
        return None
    return {"next": prediction, "verified_outputs": len(values),
            "verified": True, "variant": "MT19937/PHP-7.1+"}


def lcg_recover(outputs, m: int = None, a: int = None, c: int = None):
    """(m, a, c, next output, verified) of x' = (a*x + c) mod m from consecutive outputs, or None.
    Whatever is not given is solved for (m from the gcd of the determinants t_i*t_(i+2) -
    t_(i+1)^2, which needs six outputs), and every transition of the sequence must then hold.
    With m not given, None also when the divisors of that gcd that fit the sequence disagree
    about the next output (the m returned is then the smallest that fits, not a proven modulus).
    `verified` counts the transitions that were not used to derive a parameter; with 0 the
    caller must not answer plain."""
    xs = _bounded_prng_sequence(outputs)  # caps length + catches TypeError/MemoryError on a lazy/huge stream
    if xs is None:
        return None
    # Decline non-integer elements cleanly (parity with the other recoverers) rather than crashing in
    # the arithmetic below; bools are excluded since they would masquerade as 0/1 ints.
    if any(not isinstance(v, int) or isinstance(v, bool) for v in xs):
        return None
    if len(xs) < 2:
        return None
    used = 0
    if m is None:
        t = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
        if len(t) < 4:
            return None
        g = 0
        for i in range(len(t) - 2):
            g = math.gcd(g, t[i + 2] * t[i] - t[i + 1] * t[i + 1])
        g = abs(g)
        if g <= max(xs):
            return None
        # The gcd is the modulus or a multiple of it, and the sequence holds under EVERY multiple
        # of the modulus that divides the gcd (the determinants are how it was built), so a
        # sequence that holds under a divisor proves nothing about which divisor is the modulus.
        # Every divisor above the outputs under which the sequence holds is a candidate; the
        # next output is answered only when all of them give the same one (measured before this
        # rule: 33 wrong next outputs in 1500 sequences of six to eight outputs).
        # A divisor that cannot be solved (a first difference with no inverse under it) may be
        # the modulus all the same, so it leaves the question open too.
        cands = []
        for k in range(1, 4097):
            if g % k == 0 and g // k > max(xs):
                got = lcg_recover(xs, g // k, a, c)
                if got:
                    cands.append(got)
                elif a is None:
                    return None         # with a given multiplier a failed transition refutes the divisor
        if not cands or len({got[3] for got in cands}) != 1:
            return None
        got = min(cands, key=lambda t: t[0])
        return got[:4] + (max(0, len(xs) - 1 - 4),)
    if a is None:
        if len(xs) < 3:
            return None
        d0 = (xs[1] - xs[0]) % m
        inv = inverse(d0, m)
        if inv is None:
            return None
        a = (xs[2] - xs[1]) * inv % m
        used = max(used, 2)
    if c is None:
        c = (xs[1] - a * xs[0]) % m
        used = max(used, 1)
    if any(v < 0 or v >= m for v in xs):
        return None
    for i in range(len(xs) - 1):
        if (a * xs[i] + c) % m != xs[i + 1]:
            return None
    return m, a % m, c % m, (a * xs[-1] + c) % m, len(xs) - 1 - used


# ---- more PRNG predictors: xorshift, PCG, truncated LCG -----------------------------------------------------
#
# Each predictor reconstructs the generator's internal state (or step) from the GIVEN consecutive
# outputs, re-derives EVERY given output from that reconstruction, and only then returns the one
# NEXT output. The returned `verified` counts the output transitions that were CHECKED and not
# consumed to seed the reconstruction. The never-wrong contract these keep:
#   * a prediction is returned ONLY when the reconstruction reproduces every given output exactly
#     (a roundtrip proof), so a wrong or coincidental reconstruction yields None, never a wrong value;
#   * when two admissible reconstructions disagree on the next output, the result is None;
#   * `verified == 0` means the prediction rests on the premise alone and the caller must not answer
#     it plain (the toolkit passes it to _int_answer(unverified=...), exactly as it does for mt_clone).
# A format too complex for a bounded, pure-Python reconstruction is declined (None), by design.

_M32 = (1 << 32) - 1
_M64 = (1 << 64) - 1

# Marsaglia scalar "xorshift" generators return the WHOLE state after three in-place xorshift steps,
# so output[i+1] == step(output[i]). A step is an ordered list of ('L', s) = x ^= x << s and
# ('R', s) = x ^= x >> s, masked to the width. The catalog holds full-period triples named in
# Marsaglia's 2003 paper "Xorshift RNGs" and the two common step orders; a wrong entry simply fails
# the roundtrip and is dropped, so a generous catalog only widens coverage, never correctness.
_XS32_TRIPLES = ((13, 17, 5), (1, 3, 10), (1, 5, 16), (2, 5, 15), (5, 9, 7), (5, 15, 17),
                 (6, 21, 7), (7, 1, 9), (9, 11, 19), (13, 7, 17), (17, 15, 23), (11, 19, 13))
_XS64_TRIPLES = ((13, 7, 17), (11, 29, 14), (12, 25, 27), (23, 17, 26), (21, 17, 26),
                 (20, 41, 5), (17, 23, 29), (8, 29, 19))


def _xorshift_catalog():
    cat = {32: [], 64: []}
    for width, triples in ((32, _XS32_TRIPLES), (64, _XS64_TRIPLES)):
        for (a, b, c) in triples:
            # LRL: x^=x<<a; x^=x>>b; x^=x<<c   and   RLR: x^=x>>a; x^=x<<b; x^=x>>c
            cat[width].append((f"xorshift{width}_lrl_{a}_{b}_{c}", (("L", a), ("R", b), ("L", c))))
            cat[width].append((f"xorshift{width}_rlr_{a}_{b}_{c}", (("R", a), ("L", b), ("R", c))))
    return cat


_XORSHIFT_CATALOG = _xorshift_catalog()


def _xorshift_step(x, width, ops):
    mask = _M32 if width == 32 else _M64
    for d, s in ops:
        x ^= (x << s) & mask if d == "L" else x >> s
        x &= mask
    return x


def _xorshift128_next(o4, o3, o2, o1):
    """The next output of Marsaglia's 4x32 xor128 (shifts 11, 8, 19) given the previous four
    outputs oldest-first (state == the window of the last four outputs, from the 5th output on)."""
    t = (o4 ^ ((o4 << 11) & _M32)) & _M32
    return ((o1 ^ (o1 >> 19)) ^ (t ^ (t >> 8))) & _M32


def xorshift_predict(outputs):
    """(next output, width, variant name, verified) for a whole-state xorshift32/xorshift64 or a
    4-word xorshift128 generator, from consecutive outputs, or None. Every admissible variant must
    reproduce EVERY given output and they must all agree on the next output."""
    xs = [int(v) for v in outputs]
    if len(xs) < 3 or any(v < 0 for v in xs):
        return None
    preds = {}                                  # variant name -> next output
    best_verified = 0
    for width in (32, 64):
        mask = _M32 if width == 32 else _M64
        if any(v > mask for v in xs):
            continue
        for name, ops in _XORSHIFT_CATALOG[width]:
            if all(_xorshift_step(xs[i], width, ops) == xs[i + 1] for i in range(len(xs) - 1)):
                preds[name] = _xorshift_step(xs[-1], width, ops)
                best_verified = max(best_verified, len(xs) - 1)
    # xorshift128 window (needs >= 4 to seed + >= 2 to verify)
    if len(xs) >= 6 and all(0 <= v <= _M32 for v in xs):
        ok = all(_xorshift128_next(xs[i - 4], xs[i - 3], xs[i - 2], xs[i - 1]) == xs[i]
                 for i in range(4, len(xs)))
        if ok:
            preds["xorshift128_marsaglia_11_8_19"] = _xorshift128_next(xs[-4], xs[-3], xs[-2], xs[-1])
            best_verified = max(best_verified, len(xs) - 4)
    distinct = set(preds.values())
    if len(distinct) != 1:
        return None                             # none fit, or admissible variants disagree
    name = sorted(preds)[0]
    width = 128 if name.startswith("xorshift128") else (64 if "64" in name.split("_")[0] else 32)
    return distinct.pop(), width, name, best_verified


def _gf2_unique_solution(equations, variables: int):
    """A unique GF(2) solution for ``(coefficient_mask, rhs)`` rows, else None."""
    pivots = {}
    for mask, rhs in equations:
        mask, rhs = int(mask), int(rhs) & 1
        while mask:
            pivot = mask.bit_length() - 1
            if pivot not in pivots:
                pivots[pivot] = (mask, rhs)
                break
            previous, value = pivots[pivot]
            mask ^= previous
            rhs ^= value
        else:
            if rhs:
                return None
    if len(pivots) != variables:
        return None
    value = 0
    for pivot in sorted(pivots):
        row, rhs = pivots[pivot]
        lower = row & ((1 << pivot) - 1)
        bit = rhs ^ ((lower & value).bit_count() & 1)
        value |= bit << pivot
    return value


def xorshift_truncated_recover(outputs, width: int, operations, output_bits: int):
    """Recover a scalar xorshift state from consecutive high-bit outputs.

    ``operations`` is the exact ordered xorshift recipe, for example
    ``[("L",13),("R",17),("L",5)]``.  The first observation describes the
    current emitted state and later observations follow transitions.  State
    recovery is a bounded GF(2) linear solve, not low-bit enumeration.
    """
    try:
        values = [int(value) for value in outputs]
        ops = tuple((str(direction).upper(), int(shift)) for direction, shift in operations)
    except (TypeError, ValueError):
        return None
    if (width not in (8, 16, 32, 64, 128, 256)
            or not 1 <= output_bits <= width or not 1 <= len(ops) <= 16
            or any(direction not in ("L", "R") or not 1 <= shift < width
                   for direction, shift in ops)
            or not 2 <= len(values) <= MAX_PRNG_OBSERVATIONS
            or any(not 0 <= value < 1 << output_bits for value in values)):
        return None
    symbolic = [1 << bit for bit in range(width)]
    equations = []
    for expected in values:
        for output_index in range(output_bits):
            state_bit = width - output_bits + output_index
            equations.append((symbolic[state_bit], (expected >> output_index) & 1))
        next_symbolic = list(symbolic)
        for direction, shift in ops:
            before = list(next_symbolic)
            for bit in range(width):
                source = bit - shift if direction == "L" else bit + shift
                if 0 <= source < width:
                    next_symbolic[bit] = before[bit] ^ before[source]
        symbolic = next_symbolic
    first_state = _gf2_unique_solution(equations, width)
    if first_state is None:
        return None
    mask = (1 << width) - 1

    def step(value):
        for direction, shift in ops:
            value ^= ((value << shift) & mask) if direction == "L" else (value >> shift)
            value &= mask
        return value

    state = first_state
    for expected in values:
        if state >> (width - output_bits) != expected:
            return None
        state = step(state)
    return {"next": state >> (width - output_bits), "state": first_state,
            "width": width, "output_bits": output_bits,
            "verified_outputs": len(values), "verified": True}


# A floor-sum based modular-interval enumerator, used to recover the discarded low state bits of a
# truncated generator (PCG32, truncated LCG). floor_sum is the standard AtCoder routine (sum of
# floor((a*i+b)/m) for i in [0,n)); enum_mod_interval finds every x in [0,X) whose a*x mod m lands
# in a window, by counting with floor_sum and splitting the x-range (empty halves pruned). Both are
# validated against brute force in the test. Correctness here only affects COVERAGE: a missed or
# spurious candidate is filtered by the caller's roundtrip proof, so it can never make a wrong answer.

def _floor_sum(n, m, a, b):
    if n <= 0:
        return 0
    ans = 0
    if a < 0:
        a2 = a % m
        ans -= n * (n - 1) // 2 * ((a2 - a) // m)
        a = a2
    if b < 0:
        b2 = b % m
        ans -= n * ((b2 - b) // m)
        b = b2
    while True:
        if a >= m:
            ans += n * (n - 1) // 2 * (a // m)
            a %= m
        if b >= m:
            ans += n * (b // m)
            b %= m
        y_max = a * n + b
        if y_max < m:
            break
        n = y_max // m
        b = y_max % m
        m, a = a, m
    return ans


def _count_lt(n, a, b, m, w):
    """#{ i in [0,n) : (a*i + b) mod m < w }, for 0 <= w <= m."""
    if w <= 0:
        return 0
    if w >= m:
        return n
    return _floor_sum(n, m, a, b) - _floor_sum(n, m, a, b - w)


def _enum_mod_interval(a, m, lo, hi, X, cap=200000):
    """Sorted x in [0, X) with (a*x) mod m in [lo, hi); None if more than `cap` solutions (so the
    caller declines rather than spends unbounded time)."""
    a %= m
    total = _count_lt(X, a, 0, m, hi) - _count_lt(X, a, 0, m, lo)
    if total <= 0:
        return []
    if total > cap:
        return None
    out = []
    stack = [(0, X)]
    while stack:
        a0, b0 = stack.pop()
        if a0 >= b0:
            continue
        shift = (a * a0) % m
        c = _count_lt(b0 - a0, a, shift, m, hi) - _count_lt(b0 - a0, a, shift, m, lo)
        if c == 0:
            continue
        if b0 - a0 == 1:
            out.append(a0)
            continue
        mid = (a0 + b0) // 2
        stack.append((mid, b0))
        stack.append((a0, mid))
    out.sort()
    return out


# PCG32 (XSH-RR 64/32), M. O'Neill's default. Each 32-bit output is a permutation of the TOP bits of
# the 64-bit pre-advance state, so one output reveals state bits 27..63 exactly (for the right
# rotation) and nothing of the low 27 bits. The low bits are recovered from the next output through
# the LCG step with the interval enumerator, and every candidate is replayed to prove it. The stream
# increment is the default (or a stated one): an unknown stream is not recoverable and is declined.
PCG32_MULT = 6364136223846793005
PCG32_DEFAULT_INC = 1442695040888963407


def _ror32(x, r):
    r &= 31
    return ((x >> r) | (x << ((-r) & 31))) & _M32


def _rol32(x, r):
    r &= 31
    return ((x << r) | (x >> ((-r) & 31))) & _M32


def _pcg32_output(state):
    xorshifted = (((state >> 18) ^ state) >> 27) & _M32
    return _ror32(xorshifted, state >> 59)


def _pcg32_top_candidates(out):
    """For each rotation guess, the partial 64-bit state with bits 27..63 fixed (bits 0..26 zero)."""
    res = []
    for rot in range(32):
        x = _rol32(out, rot)                    # candidate 32-bit xorshifted = ((s>>18)^s)>>27
        s = rot << 59                           # bits 59..63 are the rotation
        for k in range(58, 26, -1):             # y_k = s_k ^ s_{k+18}; solve downward
            ybit = (x >> (k - 27)) & 1
            hk = (s >> (k + 18)) & 1 if (k + 18) <= 63 else 0
            s |= ((ybit ^ hk) << k)
        res.append((rot, s & _M64))
    return res


def pcg32_predict(outputs, incs=None, mult=PCG32_MULT, deadline=None):
    """(next output, verified) for PCG32 XSH-RR 64/32 with a known/stated stream increment, from
    consecutive 32-bit outputs, or None. Each candidate state is replayed against EVERY given output;
    only a unique surviving next output is returned."""
    xs = [int(v) for v in outputs]
    if len(xs) < 4 or any(not 0 <= v <= _M32 for v in xs):
        return None
    inc_list = []
    for inc in (incs if incs is not None else [PCG32_DEFAULT_INC]):
        inc = int(inc) & _M64
        if inc not in inc_list:
            inc_list.append(inc)
    o0, o1 = xs[0], xs[1]
    cands1 = _pcg32_top_candidates(o1)
    nexts = set()
    verified = 0
    for inc in inc_list:
        for _rot0, base0 in _pcg32_top_candidates(o0):
            if deadline is not None and time.monotonic() > deadline:
                return None
            for _rot1, base1 in cands1:
                T1 = base1 >> 27                # known top 37 bits of s1
                A = ((T1 << 27) - inc - base0 * mult) % (1 << 64)
                us = _enum_mod_interval(mult, 1 << 64, A, A + (1 << 27), 1 << 27, cap=4096)
                if not us:
                    continue
                for u in us:
                    s = base0 + u
                    ok = True
                    for exp in xs:              # roundtrip proof: reproduce EVERY given output
                        if _pcg32_output(s) != exp:
                            ok = False
                            break
                        s = (s * mult + inc) & _M64
                    if ok:
                        nexts.add(_pcg32_output(s))
                        verified = len(xs)
    if len(nexts) != 1:
        return None
    return nexts.pop(), verified


def pcg32_unknown_increment_recover(outputs, *, mult=PCG32_MULT, timeout_ms: int = 30000):
    """Predict PCG32 XSH-RR while recovering an unknown odd stream increment.

    Exact bit-vector constraints replace the round-3 supplied-increment path.
    The selected model is concretely replayed, and the next output must be
    unique across every satisfying state/increment pair.
    """
    try:
        values = [int(value) for value in outputs]
        import z3
    except Exception:
        return None
    if (not 5 <= len(values) <= 64 or any(not 0 <= value <= _M32 for value in values)
            or not isinstance(mult, int) or isinstance(mult, bool) or mult % 2 == 0):
        return None
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    state = z3.BitVec("pcg_unknown_state", 64)
    increment = z3.BitVec("pcg_unknown_increment", 64)
    solver.add((increment & 1) == 1)

    def output(expression):
        mixed64 = z3.LShR(expression ^ z3.LShR(expression, 18), 27)
        mixed = z3.Extract(31, 0, mixed64)
        rotation = z3.Extract(63, 59, expression)
        result = z3.RotateRight(mixed, 0)
        for amount in range(1, 32):
            result = z3.If(rotation == amount, z3.RotateRight(mixed, amount), result)
        return result

    start = state
    for expected in values:
        solver.add(output(state) == expected)
        state = state * z3.BitVecVal(int(mult) & _M64, 64) + increment
    next_output = output(state)
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    concrete_state = model.eval(start, model_completion=True).as_long()
    concrete_increment = model.eval(increment, model_completion=True).as_long()
    replay = concrete_state
    for expected in values:
        if _pcg32_output(replay) != expected:
            return None
        replay = (replay * mult + concrete_increment) & _M64
    prediction = _pcg32_output(replay)
    solver.add(next_output != prediction)
    if solver.check() != z3.unsat:
        return None
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    # The output is proven even if several stream parameters happen to agree;
    # disclose the increment only when the model parameter itself is unique.
    state = z3.BitVec("pcg_unique_state", 64)
    inc2 = z3.BitVec("pcg_unique_increment", 64)
    solver.add((inc2 & 1) == 1)
    probe = state
    for expected in values:
        solver.add(output(probe) == expected)
        probe = probe * z3.BitVecVal(int(mult) & _M64, 64) + inc2
    solver.add(inc2 != concrete_increment)
    increment_unique = solver.check() == z3.unsat
    return {"next": prediction, "increment": concrete_increment if increment_unique else None,
            "verified_outputs": len(values), "verified": True}


def _rotl64(value, shift):
    shift &= 63
    return ((value << shift) | (value >> ((-shift) & 63))) & _M64


def _xoshiro256ss_output(state):
    return (_rotl64((state[1] * 5) & _M64, 7) * 9) & _M64


def _xoshiro256_step(state):
    s0, s1, s2, s3 = state
    temporary = (s1 << 17) & _M64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= temporary
    s3 = _rotl64(s3, 45)
    return s0 & _M64, s1 & _M64, s2 & _M64, s3 & _M64


def xoshiro256ss_truncated_recover(outputs, output_bits: int = 64, *, timeout_ms: int = 30000):
    """Recover/predict xoshiro256** from full or truncated high outputs.

    The transition and ``**`` scrambler are represented exactly in QF_BV.
    This remains bounded to 128 observations and returns only a next value that
    is unique across all states compatible with the capture.
    """
    try:
        values = [int(value) for value in outputs]
        import z3
    except Exception:
        return None
    if (isinstance(output_bits, bool) or not isinstance(output_bits, int)
            or not 1 <= output_bits <= 64 or not 4 <= len(values) <= 128
            or any(not 0 <= value < 1 << output_bits for value in values)):
        return None
    solver = z3.Solver()
    solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
    initial = tuple(z3.BitVec(f"xoshiro_state_{index}", 64) for index in range(4))
    solver.add(z3.Or(*(word != 0 for word in initial)))
    state = initial

    def output(words):
        return z3.RotateLeft(words[1] * z3.BitVecVal(5, 64), 7) * z3.BitVecVal(9, 64)

    def advance(words):
        s0, s1, s2, s3 = words
        temporary = s1 << 17
        s2 = s2 ^ s0
        s3 = s3 ^ s1
        s1 = s1 ^ s2
        s0 = s0 ^ s3
        s2 = s2 ^ temporary
        s3 = z3.RotateLeft(s3, 45)
        return s0, s1, s2, s3

    for expected in values:
        solver.add(z3.LShR(output(state), 64 - output_bits) == expected)
        state = advance(state)
    next_output = z3.LShR(output(state), 64 - output_bits)
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    concrete = tuple(model.eval(word, model_completion=True).as_long() for word in initial)
    replay = concrete
    for expected in values:
        if _xoshiro256ss_output(replay) >> (64 - output_bits) != expected:
            return None
        replay = _xoshiro256_step(replay)
    prediction = _xoshiro256ss_output(replay) >> (64 - output_bits)
    solver.add(next_output != prediction)
    if solver.check() != z3.unsat:
        return None
    return {"next": prediction, "state": concrete, "output_bits": output_bits,
            "verified_outputs": len(values), "verified": True,
            "variant": "xoshiro256**"}


def lcg_truncated_predict(outputs, a, c, m, shift, deadline=None):
    """(next output, verified) of a truncated LCG whose output is state >> `shift` (the top bits),
    given the multiplier a, increment c, modulus m and shift, or None. The low `shift` bits of the
    first state are recovered with the interval enumerator (the next output pins them down), and every
    candidate state is replayed against EVERY given output; a unique surviving next output is returned."""
    xs = [int(v) for v in outputs]
    if len(xs) < 3 or shift <= 0 or shift > 48 or m <= 0 or a <= 0:
        return None
    # Coincidence bound. xs[0] is baked into base0 and xs[1] into the enumerator interval, so they
    # do not test a candidate: only the remaining len(xs)-2 outputs are INDEPENDENT roundtrip checks,
    # each worth out_bits = m.bit_length()-shift output bits. At small output width a wrong candidate
    # survives the roundtrip by coincidence, and if the stated (a,c,m,shift) do not describe the given
    # outputs (a decoy/ambiguous shift, a stray param) a wrong value would be returned as a proven fact.
    # Require at least ~2^-64 of coincidence (match xorshift/PCG, whose roundtrip is always >64 bits);
    # otherwise decline. Realistic truncated LCGs (out_bits >= 12 with enough outputs) are unaffected;
    # the narrow small-output path now returns None instead of guessing.
    out_bits = max(1, m.bit_length() - shift)
    if (len(xs) - 2) * out_bits < 64:
        return None
    base0 = xs[0] << shift
    if base0 >= m:
        return None
    span = 1 << shift
    # (s0 >> shift) == xs[0] is already fixed by base0; the next output pins the low bits:
    #   (s1 >> shift) == xs[1]  <=>  (a*s0 + c) mod m in [xs[1]<<shift, xs[1]<<shift + span) n [0, m)
    #   <=>  (a*u) mod m in [A, A + span)  (mod m), with A = (xs[1]<<shift - c - a*base0) mod m
    A = ((xs[1] << shift) - c - a * base0) % m
    hi = A + span
    if hi <= m:                                 # window does not wrap
        cands = _enum_mod_interval(a, m, A, hi, span, cap=8192)
    else:                                       # window wraps past m: [A, m) U [0, hi-m)
        left = _enum_mod_interval(a, m, A, m, span, cap=8192)
        right = _enum_mod_interval(a, m, 0, hi - m, span, cap=8192)
        cands = None if left is None or right is None else sorted(set(left) | set(right))
    if cands is None:
        return None
    nexts = set()
    verified = 0
    for u in cands:
        if deadline is not None and time.monotonic() > deadline:
            return None
        s = base0 + u
        if s >= m:
            continue
        ok = True
        for exp in xs:
            if (s >> shift) != exp:
                ok = False
                break
            s = (a * s + c) % m
        if ok:
            nexts.add(s >> shift)
            verified = len(xs)
    if len(nexts) != 1:
        return None
    return nexts.pop(), verified


def lcg_power2_truncated_recover(
    outputs, output_bits: int, *, state_bits=None, a=None, c=None,
    require_odd_multiplier: bool = False, require_odd_increment: bool = False,
    timeout_ms: int = 30000,
):
    """Recover a top-bit LCG with unknown increment and/or power-of-two modulus.

    ``state_bits`` may be one width or a bounded iterable of candidate widths;
    when omitted, the next sixteen widths above ``output_bits`` are tried.  The
    multiplier and increment may be supplied or solved.  Every model is
    concretely replayed and all feasible moduli must agree on the next output.
    Arbitrary non-power-of-two moduli remain covered by :func:`lcg_recover` when
    full outputs are available; this routine does not pretend to infer an
    unbounded modulus family from lossy evidence.
    """
    try:
        values = [int(value) for value in outputs]
        import z3
    except Exception:
        return None
    if (isinstance(output_bits, bool) or not isinstance(output_bits, int)
            or not 1 <= output_bits <= 63 or not 4 <= len(values) <= 128
            or any(not 0 <= value < 1 << output_bits for value in values)):
        return None
    if state_bits is None:
        widths = list(range(output_bits + 1, min(64, output_bits + 16) + 1))
    elif isinstance(state_bits, int) and not isinstance(state_bits, bool):
        widths = [state_bits]
    else:
        try:
            widths = sorted(set(int(value) for value in state_bits))
        except (TypeError, ValueError):
            return None
    if not widths or len(widths) > 32 or any(not output_bits < width <= 64 for width in widths):
        return None
    if a is not None and (isinstance(a, bool) or not isinstance(a, int) or a < 0):
        return None
    if c is not None and (isinstance(c, bool) or not isinstance(c, int) or c < 0):
        return None
    feasible = []
    for width in widths:
        solver = z3.Solver()
        solver.set(timeout=max(1, min(int(timeout_ms), 120000)))
        multiplier = (z3.BitVecVal(a % (1 << width), width) if a is not None
                      else z3.BitVec(f"lcg_multiplier_{width}", width))
        increment = (z3.BitVecVal(c % (1 << width), width) if c is not None
                     else z3.BitVec(f"lcg_increment_{width}", width))
        initial = z3.BitVec(f"lcg_state_{width}", width)
        if require_odd_multiplier:
            solver.add((multiplier & 1) == 1)
        if require_odd_increment:
            solver.add((increment & 1) == 1)
        state = initial
        shift = width - output_bits
        for expected in values:
            solver.add(z3.LShR(state, shift) == expected)
            state = state * multiplier + increment
        prediction_expr = z3.LShR(state, shift)
        status = solver.check()
        if status == z3.unknown:
            return None
        if status != z3.sat:
            continue
        model = solver.model()
        state_i = model.eval(initial, model_completion=True).as_long()
        a_i = model.eval(multiplier, model_completion=True).as_long()
        c_i = model.eval(increment, model_completion=True).as_long()
        mask = (1 << width) - 1
        replay = state_i
        for expected in values:
            if replay >> shift != expected:
                return None
            replay = (a_i * replay + c_i) & mask
        prediction = replay >> shift
        solver.add(prediction_expr != prediction)
        if solver.check() == z3.unknown:
            return None
        if solver.check() != z3.unsat:
            # This width reproduces the observed (truncated) outputs but does NOT force a unique next
            # output — the prediction is undetermined under it. Reproducing lossy outputs never proves
            # a modulus, so a narrower overfit width must not be allowed to win while a wider, equally
            # consistent width is silently dropped. Decline the whole call (never emit a guessed value).
            return None
        feasible.append((width, prediction, a_i, c_i, state_i))
    if not feasible or len({item[1] for item in feasible}) != 1:
        return None
    prediction = feasible[0][1]
    unique_width = len(feasible) == 1
    return {"next": prediction,
            "modulus": (1 << feasible[0][0]) if unique_width else None,
            "state_bits": feasible[0][0] if unique_width else None,
            "candidate_state_bits": [item[0] for item in feasible],
            "multiplier": feasible[0][2] if unique_width else None,
            "increment": feasible[0][3] if unique_width else None,
            "verified_outputs": len(values), "verified": True}


# ---- hashes and tokens --------------------------------------------------------------------------------------

_HASH_LEN = {8: ["crc32", "adler32"], 16: ["mysql323", "crc64"], 32: ["md5", "ntlm", "md4", "lm"], 40: ["sha1", "ripemd160", "mysql5"],
             56: ["sha224", "sha3_224"], 64: ["sha256", "sha3_256", "blake2s"], 96: ["sha384", "sha3_384"],
             128: ["sha512", "sha3_512", "blake2b", "whirlpool"]}
_HASH_PREFIX = (("$2a$", "bcrypt"), ("$2b$", "bcrypt"), ("$2y$", "bcrypt"), ("$1$", "md5crypt"), ("$5$", "sha256crypt"),
                ("$6$", "sha512crypt"), ("$argon2id$", "argon2id"), ("$argon2i$", "argon2i"), ("$argon2d$", "argon2d"),
                ("$apr1$", "apr1_md5"), ("$y$", "yescrypt"), ("$pbkdf2-sha256$", "pbkdf2_sha256"), ("pbkdf2_sha256$", "django_pbkdf2_sha256"),
                ("$scrypt$", "scrypt"), ("{SSHA}", "ssha"), ("{SHA}", "sha1_base64"), ("$P$", "phpass"), ("$H$", "phpass"))


def hash_candidates(value: str) -> list:
    """The algorithms a hash string's shape allows, most usual first. The shape never says which
    one it is: the result is material for labels.pick, never a plain answer."""
    v = value.strip()
    for prefix, name in _HASH_PREFIX:
        if v.startswith(prefix):
            return [name]
    if re.fullmatch(r"[0-9a-fA-F]+", v):
        return list(_HASH_LEN.get(len(v), []))
    return []


# ---- Merkle-Damgard hash length extension (offline; no secret, self-verifying) ----
# MD5, SHA-1 and SHA-256 absorb a message block by block into a running state that IS the digest.
# Given H = <algo>(secret || data) and the secret's LENGTH, that state is the state after
# secret||data||glue-padding, so an attacker who never sees the secret resumes from it and hashes
# any suffix. Correct by construction; the caller still proves the premise (a known secret, or a
# supplied tag the forgery round-trips against). The tests round-trip every forgery against hashlib.

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF
# Only the hashes whose digest IS the whole internal state are length-extendable: MD4, MD5, SHA-1,
# SHA-256 and SHA-512. SHA-224 and SHA-384 (and SHA-512/224, SHA-512/256) truncate the final state,
# so the state cannot be recovered from the digest and `_md_algo` rejects them -- there is no safe
# forgery to make for them, and the never-wrong rule forbids pretending otherwise.
_MD_DIGEST_LEN = {"md4": 16, "md5": 16, "sha1": 20, "sha256": 32, "sha512": 64}
# (block size, word size in bytes, length-field size in bytes, length-field endianness). MD4/MD5
# are little-endian throughout; the SHA family is big-endian. SHA-512 has a 128-byte block and a
# 128-bit length field.
_MD_PARAMS = {
    "md4": (64, 4, 8, "little"),
    "md5": (64, 4, 8, "little"),
    "sha1": (64, 4, 8, "big"),
    "sha256": (64, 4, 8, "big"),
    "sha512": (128, 8, 16, "big"),
}
_MD_INIT = {
    "md4": (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    "md5": (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    "sha1": (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
    "sha256": (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
    "sha512": (0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
               0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179),
}


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & _MASK64


def _rotl32m(x, n):             # a left rotate that masks its input (MD4's variables carry the mask)
    x &= _MASK32
    return ((x << n) | (x >> (32 - n))) & _MASK32


_MD5_S = (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
          5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21)
_MD5_K = tuple(int(abs(math.sin(i + 1)) * 2 ** 32) & _MASK32 for i in range(64))


def _md5_block(state, block):
    a, b, c, d = state
    M = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]
    A, B, C, D = a, b, c, d
    for i in range(64):
        if i < 16:
            f, g = (B & C) | (~B & D), i
        elif i < 32:
            f, g = (D & B) | (~D & C), (5 * i + 1) % 16
        elif i < 48:
            f, g = B ^ C ^ D, (3 * i + 5) % 16
        else:
            f, g = C ^ (B | (~D & _MASK32)), (7 * i) % 16
        f = (f + A + _MD5_K[i] + M[g]) & _MASK32
        A, D, C = D, C, B
        B = (B + _rotl32(f, _MD5_S[i])) & _MASK32
    return [(a + A) & _MASK32, (b + B) & _MASK32, (c + C) & _MASK32, (d + D) & _MASK32]


def _sha1_block(state, block):
    h = list(state)
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 80):
        w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = h
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        t = (_rotl32(a, 5) + f + e + k + w[i]) & _MASK32
        e, d, c, b, a = d, c, _rotl32(b, 30), a, t
    return [(x + y) & _MASK32 for x, y in zip(h, (a, b, c, d, e))]


_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)


def _sha256_block(state, block):
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _SHA256_K[i] + w[i]) & _MASK32
        S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32
    return [(x + y) & _MASK32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def _md4_block(state, block):
    """MD4 (RFC 1320) compression: 32-bit little-endian words, three rounds of sixteen operations."""
    a, b, c, d = state
    X = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]

    def f(x, y, z):
        return (x & y) | ((~x & _MASK32) & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    for i in range(0, 16, 4):           # round 1
        a = _rotl32m(a + f(b, c, d) + X[i], 3)
        d = _rotl32m(d + f(a, b, c) + X[i + 1], 7)
        c = _rotl32m(c + f(d, a, b) + X[i + 2], 11)
        b = _rotl32m(b + f(c, d, a) + X[i + 3], 19)
    for i in range(4):                  # round 2
        a = _rotl32m(a + g(b, c, d) + X[i] + 0x5A827999, 3)
        d = _rotl32m(d + g(a, b, c) + X[i + 4] + 0x5A827999, 5)
        c = _rotl32m(c + g(d, a, b) + X[i + 8] + 0x5A827999, 9)
        b = _rotl32m(b + g(c, d, a) + X[i + 12] + 0x5A827999, 13)
    for i in (0, 2, 1, 3):              # round 3
        a = _rotl32m(a + h(b, c, d) + X[i] + 0x6ED9EBA1, 3)
        d = _rotl32m(d + h(a, b, c) + X[i + 8] + 0x6ED9EBA1, 9)
        c = _rotl32m(c + h(d, a, b) + X[i + 4] + 0x6ED9EBA1, 11)
        b = _rotl32m(b + h(c, d, a) + X[i + 12] + 0x6ED9EBA1, 15)
    return [(state[0] + a) & _MASK32, (state[1] + b) & _MASK32, (state[2] + c) & _MASK32, (state[3] + d) & _MASK32]


_SHA512_K = (
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817)


def _sha512_block(state, block):
    """SHA-512 (FIPS 180-4) compression: 64-bit big-endian words, eighty rounds, 128-byte block."""
    w = [int.from_bytes(block[i:i + 8], "big") for i in range(0, 128, 8)]
    for i in range(16, 80):
        s0 = _rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
        s1 = _rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK64)
    a, b, c, d, e, f, g, h = state
    for i in range(80):
        S1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _SHA512_K[i] + w[i]) & _MASK64
        S0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK64
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK64, c, b, a, (t1 + t2) & _MASK64
    return [(x + y) & _MASK64 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


_MD_BLOCK = {"md4": _md4_block, "md5": _md5_block, "sha1": _sha1_block, "sha256": _sha256_block, "sha512": _sha512_block}


def _md_algo(algo: str) -> str:
    a = str(algo).lower().replace("-", "").replace("_", "")
    if a not in _MD_PARAMS:
        raise ValueError(f"length extension is md4/md5/sha1/sha256/sha512 only, not {algo!r}")
    return a


def md_padding(msg_len: int, algo: str = "sha256") -> bytes:
    """The glue padding a Merkle-Damgard hash appends to a message of `msg_len` bytes: 0x80, zero
    bytes up to the length field, then the bit length. MD4/MD5 use a 64-byte block with an 8-byte
    little-endian length; SHA-1/SHA-256 a 64-byte block with an 8-byte big-endian length; SHA-512 a
    128-byte block with a 16-byte big-endian length."""
    algo = _md_algo(algo)
    block, _, lenb, endian = _MD_PARAMS[algo]
    bit_len = (msg_len * 8) & ((1 << (lenb * 8)) - 1)
    pad = b"\x80" + b"\x00" * ((block - lenb - 1 - (msg_len % block)) % block)
    return pad + bit_len.to_bytes(lenb, endian)


def _state_from_digest(algo, digest):
    _, wbytes, _, endian = _MD_PARAMS[algo]
    return [int.from_bytes(digest[i * wbytes:(i + 1) * wbytes], endian) for i in range(len(digest) // wbytes)]


def _digest_from_state(algo, state):
    _, wbytes, _, endian = _MD_PARAMS[algo]
    return b"".join(w.to_bytes(wbytes, endian) for w in state)


def md_hash(algo: str, data: bytes, state=None, already: int = 0) -> bytes:
    """`<algo>(data)` from an optional starting state and a count of bytes already absorbed before
    `data` (`already` must be a multiple of the block size). With state=None and already=0 it equals
    hashlib.<algo>(data).digest(). md4/md5/sha1/sha256/sha512 only."""
    algo = _md_algo(algo)
    block_size = _MD_PARAMS[algo][0]
    if already % block_size:
        raise ValueError(f"`already` must be a multiple of the {block_size}-byte block size")
    block = _MD_BLOCK[algo]
    st = list(state) if state is not None else list(_MD_INIT[algo])
    msg = bytes(data) + md_padding(already + len(data), algo)
    for i in range(0, len(msg), block_size):
        st = block(st, msg[i:i + block_size])
    return _digest_from_state(algo, st)


def length_extension(algo: str, orig_digest, orig_data: bytes, append: bytes, secret_len: int):
    """Merkle-Damgard length-extension forgery, computed WITHOUT the secret. Given
    orig_digest = <algo>(secret || orig_data) (hex str or bytes), the known `orig_data`, the bytes
    to `append`, and the secret's length in bytes, returns (forged_message, forged_digest_hex) with
        forged_message = orig_data + md_padding(secret_len + len(orig_data)) + append
        forged_digest  = <algo>(secret || forged_message)
    Deterministic and correct by construction for md4/md5/sha1/sha256/sha512 -- the caller still
    proves the premise. Raises ValueError on an unknown algo (including the truncated SHA-224/384,
    which are not length-extendable), a digest of the wrong length, or a negative secret length."""
    algo = _md_algo(algo)
    if isinstance(orig_digest, str):
        orig_digest = bytes.fromhex(orig_digest.strip())
    orig_digest = bytes(orig_digest)
    if len(orig_digest) != _MD_DIGEST_LEN[algo]:
        raise ValueError(f"{algo} digest is {_MD_DIGEST_LEN[algo]} bytes, got {len(orig_digest)}")
    if secret_len < 0:
        raise ValueError("the secret length cannot be negative")
    orig_data, append = bytes(orig_data), bytes(append)
    glue = md_padding(secret_len + len(orig_data), algo)
    forged_message = orig_data + glue + append
    state = _state_from_digest(algo, orig_digest)
    already = secret_len + len(orig_data) + len(glue)   # block-aligned by construction
    forged_digest = md_hash(algo, append, state=state, already=already)
    return forged_message, forged_digest.hex()


def length_extension_verified(algo, secret, orig_data, orig_digest) -> bool:
    """True when <algo>(secret || orig_data) equals orig_digest (hex or bytes): the offline proof
    that a length-extension premise holds when the secret is present in the delivery."""
    try:
        algo = _md_algo(algo)
    except ValueError:
        return False
    if isinstance(orig_digest, str):
        try:
            orig_digest = bytes.fromhex(orig_digest.strip())
        except ValueError:
            return False
    return md_hash(algo, bytes(secret) + bytes(orig_data)) == bytes(orig_digest)


# ---- MD5 / SHA-1 collision detection (offline; byte-proven facts, no construction guessed) ----
# Two distinct byte strings with one MD5 or one SHA-1 digest are a practical hash collision (fastcoll,
# UniColl, SHAttered, HashClash). Everything reported here is read straight from the bytes -- the shared
# digest, the first differing byte, the 64-byte-aligned differing blocks and their count, and the
# structural class (identical-prefix when only a run of middle blocks differs). The construction
# METHOD/TOOL is never named: fingerprinting fastcoll vs UniColl vs a chosen-prefix path is not
# byte-provable here, so it stays unknown (the never-wrong rule). SHA-256/SHA-512 are not scanned: a
# shared 256/512-bit digest of distinct bytes is no known collision and would be a false finding.

_COLLISION_ALGOS = (("md5", 16, 64), ("sha1", 20, 64))     # (name, digest bytes, block size)
_MAX_COLLISION_MEMBERS = 64
_MAX_COLLISION_BYTES = 64 * 1024 * 1024


def _collision_members(members):
    """Normalise {name: bytes} / [(name, bytes)] / [bytes] to [(name, bytes)], de-duplicating by the
    exact bytes (the same file delivered twice is one input, never a self-collision)."""
    out = []
    if isinstance(members, dict):
        items = list(members.items())
    else:
        items = []
        for i, m in enumerate(members or []):
            if isinstance(m, (tuple, list)) and len(m) == 2:
                items.append((m[0], m[1]))
            else:
                items.append((f"member_{i}", m))
    seen = set()
    for name, data in items:
        if not isinstance(data, (bytes, bytearray)) or len(data) > _MAX_COLLISION_BYTES:
            continue
        data = bytes(data)
        if data in seen:
            continue
        seen.add(data)
        out.append((str(name), data))
        if len(out) >= _MAX_COLLISION_MEMBERS:
            break
    return out


def _diff_structure(a: bytes, b: bytes, block: int) -> dict:
    """The byte-proven difference of two equal-length strings: the first differing byte, the aligned
    block indices that differ and their count, the common prefix/suffix lengths, and whether only a
    contiguous run of middle blocks differs (identical-prefix)."""
    n = len(a)
    first = next((i for i in range(n) if a[i] != b[i]), None)
    diff_blocks = [k for k in range((n + block - 1) // block) if a[k * block:(k + 1) * block] != b[k * block:(k + 1) * block]]
    prefix = first if first is not None else n
    suffix = 0
    while suffix < n and a[n - 1 - suffix] == b[n - 1 - suffix]:
        suffix += 1
    contiguous = bool(diff_blocks) and diff_blocks == list(range(diff_blocks[0], diff_blocks[-1] + 1))
    identical_prefix = bool(diff_blocks) and diff_blocks[0] > 0 and contiguous
    return {
        "first_diff_offset": first,
        "diff_blocks": diff_blocks,
        "diff_block_count": len(diff_blocks),
        "first_diff_block_offset": diff_blocks[0] * block if diff_blocks else None,
        "common_prefix_len": prefix,
        "common_suffix_len": suffix,
        "contiguous_diff": contiguous,
        "identical_prefix": identical_prefix,
    }


def hash_collisions(members) -> list:
    """Every MD5/SHA-1 collision among the given members: distinct byte strings that share a digest.
    `members` is a dict {name: bytes}, a list of (name, bytes), or a list of bytes. Returns a list of
    findings, one per (algo, colliding group), each a dict:
        {"algo", "digest" (hex), "members" [(name, size), ...], "count" (how many share the digest),
         "pairs" [{"names", "sizes", "equal_length", and, for equal-length pairs, the fields of
         `_diff_structure`}]}.
    Byte-proven and never a guess: the digests are recomputed here and the inputs really differ. The
    construction method is not named."""
    found = []
    mem = _collision_members(members)
    if len(mem) < 2:
        return found
    for algo, _dlen, block in _COLLISION_ALGOS:
        groups = {}
        for name, data in mem:
            groups.setdefault(hashlib.new(algo, data).hexdigest(), []).append((name, data))
        for digest, grp in groups.items():
            if len(grp) < 2:
                continue
            pairs = []
            a_name, a_data = grp[0]
            for b_name, b_data in grp[1:]:
                pair = {"names": [a_name, b_name], "sizes": [len(a_data), len(b_data)],
                        "equal_length": len(a_data) == len(b_data)}
                if pair["equal_length"]:
                    pair.update(_diff_structure(a_data, b_data, block))
                pairs.append(pair)
            found.append({"algo": algo, "digest": digest,
                          "members": [(n, len(d)) for n, d in grp], "count": len(grp), "pairs": pairs})
    return found


_JWT = re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{4,})\.(eyJ[A-Za-z0-9_-]{2,}|e30)\.([A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")


def find_jwts(text) -> list:
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    return list(dict.fromkeys(m.group(0) for m in _JWT.finditer(text)))


def jwt_parts(token: str):
    """{header, payload, signature (bytes), signed (bytes: what the signature covers)} or None."""
    try:
        h, p, s = token.strip().split(".")
        header, payload = json.loads(_b64u(h)), json.loads(_b64u(p))
        if not isinstance(header, dict):
            return None
        return {"header": header, "payload": payload, "signature": _b64u(s) if s else b"", "signed": f"{h}.{p}".encode()}
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


_HS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def jwt_hmac_ok(token: str, secret: bytes) -> bool:
    parts = jwt_parts(token)
    if not parts or parts["header"].get("alg") not in _HS or not parts["signature"]:
        return False
    return hmac.compare_digest(hmac.new(secret, parts["signed"], _HS[parts["header"]["alg"]]).digest(), parts["signature"])


def jwt_secret(token: str, candidates) -> list:
    """The candidates (bytes) whose HMAC is the token's signature, each once. An HMAC that
    verifies is a proof; the candidates are the caller's (strings of the delivery, never a list
    brought from outside)."""
    return [c for c in dict.fromkeys(candidates) if c and jwt_hmac_ok(token, c)]
