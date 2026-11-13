"""Verified offline lattice and nonce-recovery helpers for CSCTF 2026.

This module is intentionally conservative.  A lattice reduction is returned only
after proving that it spans the same integer row lattice and satisfies the LLL
conditions.  A private scalar is returned only after the supplied public key and
every original signature verify, and after every advertised nonce leak is replayed.

The implementation builds on :mod:`crypto_depth`'s exact-Fraction LLL and elliptic
curve arithmetic.  SymPy's independent LLL implementation is used as a cross-check
when installed.  There is no network, target, judge, or submission functionality.
"""

from __future__ import annotations

from fractions import Fraction
from itertools import combinations
from math import gcd
from numbers import Integral
from typing import Callable, Iterable, Sequence

try:  # Support both ``sys.path += solvers/common`` and package imports.
    from . import crypto_depth as _depth
except ImportError:  # pragma: no cover - exercised by repository-style imports
    import crypto_depth as _depth


MAX_LATTICE_ROWS = 64
MAX_LATTICE_COLS = 128
MAX_BRUTE_NONCE_BITS = 20
MAX_HNP_SAMPLES = 64


def _as_int(value) -> int:
    """Accept exact integral evidence (including decimal text), never rounded floats."""

    if isinstance(value, bool):
        raise TypeError("boolean is not integer evidence")
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        unsigned = text[1:] if text[:1] in {"+", "-"} else text
        if unsigned and unsigned.isdecimal():
            return int(text, 10)
    raise TypeError("value is not exact integer evidence")


def _integer_basis(basis: Iterable[Iterable[int]]) -> list[list[int]] | None:
    try:
        outer = iter(basis)
    except (TypeError, ValueError):
        return None
    rows: list[list[int]] = []
    try:
        for row_index, row in enumerate(outer):
            if row_index >= MAX_LATTICE_ROWS:
                return None
            values = []
            for column_index, value in enumerate(iter(row)):
                if column_index >= MAX_LATTICE_COLS:
                    return None
                values.append(value)
            rows.append(values)
    except (TypeError, ValueError):
        return None
    if not rows:
        return None
    width = len(rows[0])
    if width < len(rows) or width > MAX_LATTICE_COLS:
        return None
    if any(len(row) != width for row in rows):
        return None
    if any(not isinstance(x, int) or isinstance(x, bool) for row in rows for x in row):
        return None
    return rows


def _solve_fraction(matrix: Sequence[Sequence[int | Fraction]], rhs: Sequence[int | Fraction]):
    """Solve a square exact system, or return ``None`` when singular."""

    n = len(matrix)
    if n == 0 or len(rhs) != n or any(len(row) != n for row in matrix):
        return None
    a = [[Fraction(x) for x in row] + [Fraction(rhs[i])] for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = next((row for row in range(col, n) if a[row][col]), None)
        if pivot is None:
            return None
        a[col], a[pivot] = a[pivot], a[col]
        scale = a[col][col]
        a[col] = [x / scale for x in a[col]]
        for row in range(n):
            if row == col or not a[row][col]:
                continue
            scale = a[row][col]
            a[row] = [a[row][j] - scale * a[col][j] for j in range(n + 1)]
    return [a[i][-1] for i in range(n)]


def _coordinates(vector: Sequence[int], basis: Sequence[Sequence[int]]):
    """Exact row coordinates of *vector* in an independent (possibly rectangular) basis."""

    gram = [[sum(x * y for x, y in zip(a, b)) for b in basis] for a in basis]
    rhs = [sum(x * y for x, y in zip(vector, row)) for row in basis]
    return _solve_fraction(gram, rhs)


def _same_integer_lattice(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]) -> bool:
    if len(a) != len(b) or (a and len(a[0]) != len(b[0])):
        return False
    for source, target in ((a, b), (b, a)):
        for row in target:
            coords = _coordinates(row, source)
            if coords is None or any(value.denominator != 1 for value in coords):
                return False
    return True


def _gram_schmidt(rows: Sequence[Sequence[int]]):
    stars: list[list[Fraction]] = []
    mu = [[Fraction(0) for _ in rows] for _ in rows]
    norms: list[Fraction] = []
    for i, row in enumerate(rows):
        star = [Fraction(x) for x in row]
        for j in range(i):
            if norms[j] == 0:
                return None
            mu[i][j] = sum(Fraction(x) * y for x, y in zip(row, stars[j])) / norms[j]
            star = [x - mu[i][j] * y for x, y in zip(star, stars[j])]
        norm = sum(x * x for x in star)
        if norm == 0:
            return None
        stars.append(star)
        norms.append(norm)
    return mu, norms


def _is_lll_reduced(rows: Sequence[Sequence[int]], delta: Fraction) -> bool:
    gs = _gram_schmidt(rows)
    if gs is None:
        return False
    mu, norms = gs
    for i in range(1, len(rows)):
        if any(abs(mu[i][j]) > Fraction(1, 2) for j in range(i)):
            return False
        if norms[i] < (delta - mu[i][i - 1] ** 2) * norms[i - 1]:
            return False
    return True


def _sympy_cross_check(original: list[list[int]], delta: Fraction) -> bool:
    """Independently reduce with SymPy and prove its result is the same lattice."""

    try:
        from sympy import Matrix, Rational
    except ImportError:  # Optional library: the exact in-repo proof still applies.
        return True
    try:
        other = Matrix(original).lll(delta=Rational(delta.numerator, delta.denominator))
        rows = [[int(other[i, j]) for j in range(other.cols)] for i in range(other.rows)]
    except Exception:
        return False
    return _same_integer_lattice(original, rows) and _is_lll_reduced(rows, delta)


def reduce_lll_verified(
    basis: Iterable[Iterable[int]],
    *,
    delta: Fraction | tuple[int, int] = Fraction(99, 100),
    max_steps: int = 200_000,
    cross_check: bool = True,
) -> tuple[tuple[int, ...], ...] | None:
    """Exact LLL reduction with a same-lattice and reduced-basis proof.

    Dependent, malformed, truncated, non-integral, or independently inconsistent
    reductions decline with ``None``.  ``delta`` must be in ``(1/4, 1)``.
    """

    rows = _integer_basis(basis)
    try:
        d = Fraction(*delta) if isinstance(delta, tuple) else Fraction(delta)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    if (
        rows is None
        or not Fraction(1, 4) < d < 1
        or not isinstance(max_steps, int)
        or isinstance(max_steps, bool)
        or max_steps < 1
    ):
        return None
    if _gram_schmidt(rows) is None:
        return None
    try:
        raw = _depth.lll(rows, delta=d, max_steps=max_steps)
        reduced = []
        for row in raw:
            converted = []
            for value in row:
                value = Fraction(value)
                if value.denominator != 1:
                    return None
                converted.append(int(value))
            reduced.append(converted)
    except Exception:
        return None
    if not _same_integer_lattice(rows, reduced) or not _is_lll_reduced(reduced, d):
        return None
    if cross_check and not _sympy_cross_check(rows, d):
        return None
    return tuple(tuple(row) for row in reduced)


def reduce_bkz_verified(
    basis: Iterable[Iterable[int]],
    *,
    block_size: int = 8,
    tours: int = 2,
    delta: Fraction | tuple[int, int] = Fraction(99, 100),
    cross_check: bool = True,
) -> tuple[tuple[int, ...], ...] | None:
    """Bounded exact block-LLL (BKZ-style) tours with full lattice verification.

    This intentionally provides a predictable pure-Python harness rather than
    claiming an SVP oracle.  Each overlapping block is exactly LLL-reduced, a
    global LLL pass closes each tour, and the final basis must still be a proven
    basis of the original lattice.  Parameters outside the bounded harness decline.
    """

    original = _integer_basis(basis)
    if (
        original is None
        or not isinstance(block_size, int)
        or isinstance(block_size, bool)
        or not isinstance(tours, int)
        or isinstance(tours, bool)
    ):
        return None
    if not 2 <= block_size <= len(original) or not 1 <= tours <= 16:
        return None
    first = reduce_lll_verified(original, delta=delta, cross_check=False)
    if first is None:
        return None
    current = [list(row) for row in first]
    for _ in range(tours):
        before = tuple(tuple(row) for row in current)
        for start in range(0, len(current) - block_size + 1):
            block = reduce_lll_verified(
                current[start : start + block_size], delta=delta, cross_check=False
            )
            if block is None:
                return None
            current[start : start + block_size] = [list(row) for row in block]
        closed = reduce_lll_verified(current, delta=delta, cross_check=False)
        if closed is None:
            return None
        current = [list(row) for row in closed]
        if tuple(tuple(row) for row in current) == before:
            break
    try:
        d = Fraction(*delta) if isinstance(delta, tuple) else Fraction(delta)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    if not _same_integer_lattice(original, current) or not _is_lll_reduced(current, d):
        return None
    if cross_check and not _sympy_cross_check(original, d):
        return None
    return tuple(tuple(row) for row in current)


def _normalise_hnp_samples(modulus: int, samples, bound: int):
    if (
        not isinstance(modulus, int)
        or isinstance(modulus, bool)
        or modulus <= 3
        or not isinstance(bound, int)
        or isinstance(bound, bool)
        or not 1 < bound < modulus
    ):
        return None
    try:
        rows = [(_as_int(t) % modulus, _as_int(a) % modulus) for t, a in samples]
    except (TypeError, ValueError):
        return None
    if not 2 <= len(rows) <= MAX_HNP_SAMPLES or any(t == 0 for t, _ in rows):
        return None
    return rows


def hidden_number_recover(
    modulus: int,
    samples: Iterable[tuple[int, int]],
    nonce_bound: int,
    verify_candidate: Callable[[int], bool],
) -> int | None:
    """Recover ``x`` from ``k_i = a_i + t_i*x (mod modulus) < nonce_bound``.

    The lattice is the same exact HNP embedding used by the repository's ECDSA
    engine.  A tiny-modulus exhaustive pass is an independent deterministic
    cross-check for synthetic/CTF toy groups.  A result is emitted only when one
    candidate alone satisfies every inequality *and* ``verify_candidate``.
    """

    rows = _normalise_hnp_samples(modulus, samples, nonce_bound)
    if rows is None or not callable(verify_candidate):
        return None
    q = modulus
    bound = nonce_bound
    candidates: set[int] = set()

    def finish():
        if len(candidates) != 1:
            return None
        result = next(iter(candidates))
        try:
            # Re-run the caller's original-problem proof at the emission gate.
            return result if bool(verify_candidate(result)) else None
        except Exception:
            return None

    def accept(candidate):
        try:
            value = int(candidate) % q
            if value == 0 or any(not 0 < (a + t * value) % q < bound for t, a in rows):
                return
            if bool(verify_candidate(value)):
                candidates.add(value)
        except Exception:
            return

    # Tiny groups are common in challenge fixtures and provide an independent
    # exhaustive check, while the bounded threshold prevents accidental scaling.
    if q <= 1_000_000:
        for candidate in range(1, q):
            accept(candidate)
            if len(candidates) > 1:
                return None
        return finish()

    m = len(rows)
    dim = m + 2
    basis = [[0] * dim for _ in range(dim)]
    for i in range(m):
        basis[i][i] = q * q
        basis[m][i] = q * rows[i][0]
        basis[m + 1][i] = q * rows[i][1]
    basis[m][m] = bound
    basis[m + 1][m + 1] = q * bound
    reduced = reduce_lll_verified(basis, cross_check=False)
    if reduced is None:
        return None
    for row in reduced:
        for sign in (1, -1):
            scaled = sign * row[m]
            if scaled % bound == 0:
                accept(scaled // bound)
        if abs(row[m + 1]) == q * bound:
            sign = 1 if row[m + 1] > 0 else -1
            for i, (t, a) in enumerate(rows):
                coordinate = sign * row[i]
                if coordinate % q == 0 and gcd(t, q) == 1:
                    k = coordinate // q
                    accept((k - a) * pow(t, -1, q))
    return finish()


def _ec_mul_raw(scalar: int, cv, point=None):
    """Scalar multiplication without reducing by the claimed subgroup order."""

    addend = point if point is not None else (cv["gx"], cv["gy"])
    result = None
    while scalar > 0:
        if scalar & 1:
            result = _depth.ec_add(result, addend, cv)
        addend = _depth.ec_add(addend, addend, cv)
        scalar >>= 1
    return result


def _curve(curve):
    try:
        cv = _depth._resolve_curve(curve)
    except Exception:
        return None
    if cv is None:
        return None
    try:
        required = ("p", "a", "b", "gx", "gy", "n")
        if any(not isinstance(cv[key], int) or isinstance(cv[key], bool) for key in required):
            return None
        p, a, b, gx, gy, n = (cv[key] for key in required)
        if not (_probable_prime(p) and _probable_prime(n)) or p <= 3 or n <= 3:
            return None
        if not (0 <= gx < p and 0 <= gy < p):
            return None
        if (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0:
            return None
        if (gy * gy - (gx * gx * gx + a * gx + b)) % p:
            return None
        if _ec_mul_raw(n, cv, (gx, gy)) is not None:
            return None
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    return cv


def _valid_public(cv, public_key):
    try:
        x, y = _as_int(public_key[0]), _as_int(public_key[1])
    except (TypeError, ValueError, IndexError):
        return None
    p = cv["p"]
    if not (0 <= x < p and 0 <= y < p):
        return None
    if (y * y - (x * x * x + cv["a"] * x + cv["b"])) % p:
        return None
    if _ec_mul_raw(cv["n"], cv, (x, y)) is not None:
        return None
    return x, y


def _ecdsa_signatures(cv, signatures):
    n = cv["n"]
    try:
        rows = [(_as_int(r), _as_int(s), _as_int(z)) for r, s, z in signatures]
    except (TypeError, ValueError):
        return None
    if not rows or len(rows) > MAX_HNP_SAMPLES:
        return None
    if any(not 0 < r < n or not 0 < s < n or z < 0 for r, s, z in rows):
        return None
    return rows


def _ecdsa_verify_native(cv, public_key, signature) -> bool:
    r, s, z = signature
    n = cv["n"]
    try:
        w = pow(s, -1, n)
        u1, u2 = (z % n) * w % n, r * w % n
        point = _depth.ec_add(_depth.ec_mul(u1, cv), _depth.ec_mul(u2, cv, public_key), cv)
        return point is not None and point[0] % n == r
    except (ValueError, TypeError, ZeroDivisionError):
        return False


def _ecdsa_verify_library(curve, public_key, signature) -> bool:
    """Cross-check ECDSA with cryptography when the named curve is supported."""

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        return True
    if isinstance(curve, dict):
        return True  # Custom curve dictionaries have no independent library adapter.
    name = str(curve).strip().lower()
    if name == "secp256k1":
        curve_obj = ec.SECP256K1()
    elif name in {"p-256", "p256", "prime256v1", "secp256r1", "nistp256", "nist p-256"}:
        curve_obj = ec.SECP256R1()
    else:
        return True
    r, s, z = signature
    if z.bit_length() > 256:
        return True  # No matching fixed-length Prehashed adapter for this fixture.
    try:
        key = ec.EllipticCurvePublicNumbers(public_key[0], public_key[1], curve_obj).public_key()
        key.verify(
            utils.encode_dss_signature(r, s),
            z.to_bytes(32, "big"),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def _valid_ecdsa_problem(curve, public_key, signatures):
    cv = _curve(curve)
    if cv is None or public_key is None:
        return None
    public = _valid_public(cv, public_key)
    rows = _ecdsa_signatures(cv, signatures)
    if public is None or rows is None:
        return None
    if any(not _ecdsa_verify_native(cv, public, row) for row in rows):
        return None
    if any(not _ecdsa_verify_library(curve, public, row) for row in rows):
        return None
    return cv, public, rows


def _verify_ecdsa_secret(cv, public, signatures, secret: int) -> bool:
    return (
        isinstance(secret, int)
        and 0 < secret < cv["n"]
        and _depth.ec_mul(secret, cv) == public
        and all(_ecdsa_verify_native(cv, public, sig) for sig in signatures)
    )


def ecdsa_repeated_nonce_recover(curve, public_key, signatures) -> int | None:
    """Recover an ECDSA scalar from any repeated-``r`` pair, then verify all input."""

    problem = _valid_ecdsa_problem(curve, public_key, signatures)
    if problem is None:
        return None
    cv, public, rows = problem
    n = cv["n"]
    candidates: set[int] = set()
    for first, second in combinations(rows, 2):
        r1, s1, z1 = first
        r2, s2, z2 = second
        if r1 != r2 or z1 == z2:
            continue
        for a in (s1, n - s1):
            for b in (s2, n - s2):
                denominator = (a - b) % n
                if denominator == 0:
                    continue
                try:
                    nonce = (z1 - z2) * pow(denominator, -1, n) % n
                    point = _depth.ec_mul(nonce, cv)
                    if nonce == 0 or point is None or point[0] % n != r1:
                        continue
                    secret = (a * nonce - z1) * pow(r1, -1, n) % n
                except (ValueError, ZeroDivisionError):
                    continue
                if (
                    (b * nonce - z2) * pow(r1, -1, n) % n == secret
                    and _verify_ecdsa_secret(cv, public, rows, secret)
                ):
                    candidates.add(secret)
    return next(iter(candidates)) if len(candidates) == 1 else None


def ecdsa_low_nonce_recover(curve, public_key, signature, max_nonce: int) -> int | None:
    """Recover from one ECDSA nonce in ``[1, max_nonce]`` (bounded to 20 bits)."""

    problem = _valid_ecdsa_problem(curve, public_key, [signature])
    if (
        problem is None
        or not isinstance(max_nonce, int)
        or isinstance(max_nonce, bool)
        or not 1 <= max_nonce <= 1 << MAX_BRUTE_NONCE_BITS
    ):
        return None
    cv, public, rows = problem
    r, s, z = rows[0]
    n = cv["n"]
    candidates: set[int] = set()
    for nonce in range(1, max_nonce + 1):
        point = _depth.ec_mul(nonce, cv)
        if point is None or point[0] % n != r:
            continue
        secret = (s * nonce - z) * pow(r, -1, n) % n
        if _verify_ecdsa_secret(cv, public, rows, secret):
            candidates.add(secret)
    return next(iter(candidates)) if len(candidates) == 1 else None


def _nonce_matches(nonce: int, known: int, unknown_bits: int, position: str, known_bits: int | None):
    if position == "high":
        return nonce >> unknown_bits == known
    if position == "low" and isinstance(known_bits, int) and known_bits > 0:
        return nonce & ((1 << known_bits) - 1) == known
    return False


def ecdsa_partial_nonce_recover(
    curve,
    public_key,
    signatures,
    known_parts,
    unknown_bits: int,
    *,
    known_position: str = "high",
    known_bits: int | None = None,
) -> int | None:
    """Recover ECDSA from known high or low nonce bits plus <=20 unknown bits."""

    problem = _valid_ecdsa_problem(curve, public_key, signatures)
    try:
        known = [_as_int(value) for value in known_parts]
    except (TypeError, ValueError):
        return None
    if (
        problem is None
        or len(known) != len(problem[2])
        or not isinstance(unknown_bits, int)
        or isinstance(unknown_bits, bool)
        or not 0 <= unknown_bits <= MAX_BRUTE_NONCE_BITS
        or known_position not in {"high", "low"}
        or (known_position == "low" and (not isinstance(known_bits, int) or known_bits <= 0))
        or any(value < 0 for value in known)
    ):
        return None
    cv, public, rows = problem
    n = cv["n"]
    if known_position == "high" and any((value << unknown_bits) >= n for value in known):
        return None
    if known_position == "low" and (
        isinstance(known_bits, bool)
        or known_bits + unknown_bits > n.bit_length()
        or any(value >= 1 << known_bits for value in known)
    ):
        return None
    r, s, z = rows[0]
    candidates: set[int] = set()
    for unknown in range(1 << unknown_bits):
        nonce = (
            (known[0] << unknown_bits) | unknown
            if known_position == "high"
            else (unknown << known_bits) | known[0]
        )
        if not 0 < nonce < n:
            continue
        point = _depth.ec_mul(nonce, cv)
        if point is None or point[0] % n != r:
            continue
        secret = (s * nonce - z) * pow(r, -1, n) % n
        if not _verify_ecdsa_secret(cv, public, rows, secret):
            continue
        recovered = [(zz + rr * secret) * pow(ss, -1, n) % n for rr, ss, zz in rows]
        if all(
            _nonce_matches(k, part, unknown_bits, known_position, known_bits)
            for k, part in zip(recovered, known)
        ):
            candidates.add(secret)
    return next(iter(candidates)) if len(candidates) == 1 else None


def ecdsa_hnp_recover(curve, public_key, signatures, nonce_bits: int) -> int | None:
    """Recover an ECDSA scalar from short/biased nonces via exact LLL HNP."""

    problem = _valid_ecdsa_problem(curve, public_key, signatures)
    if (
        problem is None
        or not isinstance(nonce_bits, int)
        or isinstance(nonce_bits, bool)
        or nonce_bits <= 0
    ):
        return None
    cv, public, rows = problem
    if nonce_bits >= cv["n"].bit_length():
        return None
    try:
        secret = _depth.ecdsa_hnp_recover(curve, public, rows, nonce_bits)
    except Exception:
        return None
    if secret is None or not _verify_ecdsa_secret(cv, public, rows, secret):
        return None
    bound = 1 << nonce_bits
    n = cv["n"]
    nonces = [(z + r * secret) * pow(s, -1, n) % n for r, s, z in rows]
    return secret if all(0 < nonce < bound for nonce in nonces) else None


def ecdsa_nonce_reuse_recover(curve, public_key, signatures) -> int | None:
    """Routing spelling for :func:`ecdsa_repeated_nonce_recover`."""

    return ecdsa_repeated_nonce_recover(curve, public_key, signatures)


def ecdsa_nonce_bias_recover(curve, public_key, signatures, nonce_bits: int) -> int | None:
    """Routing spelling for short/biased-nonce HNP recovery."""

    return ecdsa_hnp_recover(curve, public_key, signatures, nonce_bits)


def _probable_prime(value: int) -> bool:
    if value < 2:
        return False
    try:
        from Crypto.Util.number import isPrime

        return bool(isPrime(value))
    except ImportError:  # Deterministic bases for toy groups; probable-prime for larger fixtures.
        small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
        if value in small:
            return True
        if any(value % prime == 0 for prime in small):
            return False
        d, shifts = value - 1, 0
        while d % 2 == 0:
            d //= 2
            shifts += 1
        for base in small:
            x = pow(base, d, value)
            if x in (1, value - 1):
                continue
            for _ in range(shifts - 1):
                x = x * x % value
                if x == value - 1:
                    break
            else:
                return False
        return True


def _valid_dsa_problem(p, q, g, public_key, signatures):
    try:
        p, q, g, public = _as_int(p), _as_int(q), _as_int(g), _as_int(public_key)
        rows = [(_as_int(r), _as_int(s), _as_int(z)) for r, s, z in signatures]
    except (TypeError, ValueError):
        return None
    if (
        not 1 <= len(rows) <= MAX_HNP_SAMPLES
        or not (_probable_prime(p) and _probable_prime(q))
        or not p > q > 2
        or (p - 1) % q
        or not 1 < g < p
        or pow(g, q, p) != 1
        or not 1 < public < p
        or pow(public, q, p) != 1
        or any(not 0 < r < q or not 0 < s < q or z < 0 for r, s, z in rows)
    ):
        return None
    if any(not _dsa_verify(p, q, g, public, row) for row in rows):
        return None
    return p, q, g, public, rows


def _dsa_verify(p, q, g, public, signature) -> bool:
    try:
        r, s, z = signature
        w = pow(s, -1, q)
        value = (pow(g, (z % q) * w % q, p) * pow(public, r * w % q, p) % p) % q
        return value == r
    except (ValueError, TypeError, ZeroDivisionError):
        return False


def _verify_dsa_secret(problem, secret: int) -> bool:
    p, q, g, public, rows = problem
    return (
        isinstance(secret, int)
        and 0 < secret < q
        and pow(g, secret, p) == public
        and all(_dsa_verify(p, q, g, public, row) for row in rows)
    )


def dsa_repeated_nonce_recover(p, q, g, public_key, signatures) -> int | None:
    """Recover a DSA scalar from repeated ``r`` and re-verify every signature."""

    problem = _valid_dsa_problem(p, q, g, public_key, signatures)
    if problem is None:
        return None
    p, q, g, public, rows = problem
    candidates: set[int] = set()
    for first, second in combinations(rows, 2):
        r1, s1, z1 = first
        r2, s2, z2 = second
        if r1 != r2 or s1 == s2:
            continue
        try:
            nonce = (z1 - z2) * pow((s1 - s2) % q, -1, q) % q
            if nonce == 0 or pow(g, nonce, p) % q != r1:
                continue
            secret = (s1 * nonce - z1) * pow(r1, -1, q) % q
        except (ValueError, ZeroDivisionError):
            continue
        if (
            (s2 * nonce - z2) * pow(r1, -1, q) % q == secret
            and _verify_dsa_secret(problem, secret)
        ):
            candidates.add(secret)
    return next(iter(candidates)) if len(candidates) == 1 else None


def dsa_low_nonce_recover(p, q, g, public_key, signature, max_nonce: int) -> int | None:
    """Recover one DSA nonce in ``[1, max_nonce]`` with public-key proof."""

    problem = _valid_dsa_problem(p, q, g, public_key, [signature])
    if (
        problem is None
        or not isinstance(max_nonce, int)
        or isinstance(max_nonce, bool)
        or not 1 <= max_nonce <= 1 << MAX_BRUTE_NONCE_BITS
    ):
        return None
    p, q, g, public, rows = problem
    r, s, z = rows[0]
    candidates: set[int] = set()
    for nonce in range(1, min(max_nonce, q - 1) + 1):
        if pow(g, nonce, p) % q != r:
            continue
        secret = (s * nonce - z) * pow(r, -1, q) % q
        if _verify_dsa_secret(problem, secret):
            candidates.add(secret)
    return next(iter(candidates)) if len(candidates) == 1 else None


def dsa_partial_nonce_recover(
    p,
    q,
    g,
    public_key,
    signatures,
    known_parts,
    unknown_bits: int,
    *,
    known_position: str = "high",
    known_bits: int | None = None,
) -> int | None:
    """Recover DSA from known high/low nonce parts plus <=20 unknown bits."""

    problem = _valid_dsa_problem(p, q, g, public_key, signatures)
    try:
        known = [_as_int(value) for value in known_parts]
    except (TypeError, ValueError):
        return None
    if (
        problem is None
        or len(known) != len(problem[4])
        or not isinstance(unknown_bits, int)
        or isinstance(unknown_bits, bool)
        or not 0 <= unknown_bits <= MAX_BRUTE_NONCE_BITS
        or known_position not in {"high", "low"}
        or (known_position == "low" and (not isinstance(known_bits, int) or known_bits <= 0))
        or any(value < 0 for value in known)
    ):
        return None
    p, q, g, public, rows = problem
    if known_position == "high" and any((value << unknown_bits) >= q for value in known):
        return None
    if known_position == "low" and (
        isinstance(known_bits, bool)
        or known_bits + unknown_bits > q.bit_length()
        or any(value >= 1 << known_bits for value in known)
    ):
        return None
    r, s, z = rows[0]
    candidates: set[int] = set()
    for unknown in range(1 << unknown_bits):
        nonce = (
            (known[0] << unknown_bits) | unknown
            if known_position == "high"
            else (unknown << known_bits) | known[0]
        )
        if not 0 < nonce < q or pow(g, nonce, p) % q != r:
            continue
        secret = (s * nonce - z) * pow(r, -1, q) % q
        if not _verify_dsa_secret(problem, secret):
            continue
        recovered = [(zz + rr * secret) * pow(ss, -1, q) % q for rr, ss, zz in rows]
        if all(
            _nonce_matches(k, part, unknown_bits, known_position, known_bits)
            for k, part in zip(recovered, known)
        ):
            candidates.add(secret)
    return next(iter(candidates)) if len(candidates) == 1 else None


def dsa_hnp_recover(p, q, g, public_key, signatures, nonce_bits: int) -> int | None:
    """Recover a DSA scalar from short/biased nonces through the generic HNP."""

    problem = _valid_dsa_problem(p, q, g, public_key, signatures)
    if (
        problem is None
        or not isinstance(nonce_bits, int)
        or isinstance(nonce_bits, bool)
        or not 1 <= nonce_bits < int(q).bit_length()
    ):
        return None
    p, q, g, public, rows = problem
    samples = []
    for r, s, z in rows:
        inverse = pow(s, -1, q)
        samples.append((r * inverse % q, z * inverse % q))
    secret = hidden_number_recover(
        q, samples, 1 << nonce_bits, lambda candidate: _verify_dsa_secret(problem, candidate)
    )
    if secret is None:
        return None
    nonces = [(z + r * secret) * pow(s, -1, q) % q for r, s, z in rows]
    return secret if all(0 < nonce < 1 << nonce_bits for nonce in nonces) else None


def dsa_nonce_reuse_recover(p, q, g, public_key, signatures) -> int | None:
    """Routing spelling for :func:`dsa_repeated_nonce_recover`."""

    return dsa_repeated_nonce_recover(p, q, g, public_key, signatures)


def dsa_nonce_bias_recover(p, q, g, public_key, signatures, nonce_bits: int) -> int | None:
    """Routing spelling for short/biased-nonce HNP recovery."""

    return dsa_hnp_recover(p, q, g, public_key, signatures, nonce_bits)


__all__ = [
    "reduce_lll_verified",
    "reduce_bkz_verified",
    "hidden_number_recover",
    "ecdsa_repeated_nonce_recover",
    "ecdsa_nonce_reuse_recover",
    "ecdsa_low_nonce_recover",
    "ecdsa_partial_nonce_recover",
    "ecdsa_hnp_recover",
    "ecdsa_nonce_bias_recover",
    "dsa_repeated_nonce_recover",
    "dsa_nonce_reuse_recover",
    "dsa_low_nonce_recover",
    "dsa_partial_nonce_recover",
    "dsa_hnp_recover",
    "dsa_nonce_bias_recover",
]
