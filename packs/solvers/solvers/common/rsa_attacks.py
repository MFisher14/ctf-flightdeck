"""Verified, offline RSA attack emitters for the CSCTF r5c crypto lane.

This module deliberately separates *candidate generation* from *evidence*.  Every
public recovery routine recomputes the relation that defines the original
problem, collects every proven candidate it sees, and returns a value only when
that set has exactly one member.  An unsupported, malformed, contradictory, or
ambiguous instance therefore returns ``None``.

The expensive lattice operations are supplied by :mod:`rsa_lattice`, whose LLL
uses exact integer arithmetic.  Private keys are checked with RSA round trips,
the congruence ``e*d == 1 (mod lcm(p-1,q-1))``, and (when installed)
PyCryptodome's independent RSA consistency checker.  This module performs no
I/O, networking, submission, or probabilistic guessing.
"""

from __future__ import annotations

import itertools
import math
import time
from typing import Iterable, Optional, Sequence

try:  # Imported both as ``solvers.common...`` and as a standalone common module.
    from . import modern_crypto as _mc
    from . import rsa_lattice as _rl
except ImportError:  # pragma: no cover - exercised by the repository's CLI style
    from _shadowed import common_module
    _mc = common_module("modern_crypto")  # solvers/toolkits/modern_crypto.py wins a flat import
    import rsa_lattice as _rl


__all__ = [
    "recover_common_modulus",
    "recover_fermat_factors",
    "recover_close_prime_factors",
    "recover_wiener_private_key",
    "recover_hastad_broadcast",
    "recover_franklin_reiter",
    "recover_related_message",
    "recover_coppersmith_root",
    "recover_stereotyped_message",
    "recover_partial_prime",
    "recover_private_exponent_known_bits",
    "recover_boneh_durfee_private_key",
    "recover_crt_fault_private_key",
    "recover_seeded_private_key",
]


MAX_RSA_OBSERVATIONS = 512
MAX_COPPERSMITH_COEFFICIENTS = 32
MAX_STEREOTYPED_BYTES = 4096


def _left(deadline: Optional[float]) -> bool:
    return deadline is None or time.monotonic() < deadline


def _integers(*values: object) -> bool:
    """True for real Python integers, deliberately excluding booleans."""
    return all(isinstance(value, int) and not isinstance(value, bool) for value in values)


def _deadline(deadline: object) -> bool:
    if deadline is None:
        return True
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        return False
    return not (isinstance(deadline, float) and math.isnan(deadline))


def _bounded_items(values: object, cap: int) -> Optional[list[object]]:
    """Materialize at most ``cap`` items; regular infinite iterators decline."""
    try:
        items = list(itertools.islice(iter(values), cap + 1))
    except (TypeError, ValueError):
        return None
    return items if len(items) <= cap else None


def _prime_split(n: int, p: int, q: int) -> Optional[tuple[int, int]]:
    """Canonical, independently primality-checked RSA factorisation."""
    if not _integers(n, p, q):
        return None
    if p <= 1 or q <= 1 or p * q != n:
        return None
    if not _mc.is_prime(p) or not _mc.is_prime(q):
        return None
    try:
        import sympy
    except ImportError:  # pragma: no cover - optional independent checker
        pass
    else:
        if not bool(sympy.isprime(p)) or not bool(sympy.isprime(q)):
            return None
    return tuple(sorted((p, q)))


def _library_key_check(n: int, e: int, d: int, p: int, q: int) -> bool:
    """Cross-check with PyCryptodome when present, without making it a dependency."""
    try:
        from Crypto.PublicKey import RSA
    except ImportError:  # pragma: no cover - optional dependency
        return True
    try:
        key = RSA.construct((n, e, d, p, q), consistency_check=True)
    except (ValueError, TypeError, IndexError):
        return False
    return key.n == n and key.e == e and key.d == d and {key.p, key.q} == {p, q}


def _private_key(n: int, e: int, d: int, p: int, q: int) -> Optional[tuple[int, int, int]]:
    """Return ``(d,p,q)`` only after arithmetic and library verification."""
    split = _prime_split(n, p, q)
    if split is None or e <= 1 or d <= 0:
        return None
    p, q = split
    lam = math.lcm(p - 1, q - 1)
    if math.gcd(e, lam) != 1 or (e * d - 1) % lam:
        return None
    # Include non-units (p and q) so this is stronger than a single coprime probe.
    probes = {0, 1, 2, p, q, 42 % n, n - 1}
    if any(pow(pow(m, e, n), d, n) != m % n for m in probes):
        return None
    if not _library_key_check(n, e, d, p, q):
        return None
    return d, p, q


def _private_from_split(n: int, e: int, p: int, q: int) -> Optional[tuple[int, int, int]]:
    split = _prime_split(n, p, q)
    if split is None:
        return None
    p, q = split
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        return None
    return _private_key(n, e, pow(e, -1, phi), p, q)


def recover_seeded_private_key(
    n: int, e: int, candidate_prime: int
) -> Optional[tuple[int, int, int]]:
    """``(d, p, q)`` when ``candidate_prime`` is a prime factor of ``n`` and ``e`` admits a key.

    The seeded-keygen engine (``solvers/common/seeded_keygen.py``, B-064) reconstructs a PRNG prime
    generator and hands this one prime it found dividing ``n``.  The key is returned only after the
    full factorisation gate: ``candidate_prime`` and its cofactor ``n // candidate_prime`` must each
    be independently prime, ``gcd(e, phi) == 1``, and the resulting key must pass the round-trip,
    congruence and (when PyCryptodome is installed) library checks shared by every recovery here.
    A prime that divides ``n`` but whose cofactor is composite yields ``None``."""
    if not _integers(n, e, candidate_prime) or e <= 1:
        return None
    if candidate_prime <= 1 or n <= candidate_prime or n % candidate_prime:
        return None
    return _private_from_split(n, e, candidate_prime, n // candidate_prime)


def _signed_pow(base: int, exponent: int, modulus: int) -> Optional[int]:
    try:
        return pow(base, exponent, modulus) if exponent >= 0 else pow(pow(base, -1, modulus), -exponent, modulus)
    except ValueError:
        return None


def recover_common_modulus(
    n: int,
    samples: Iterable[tuple[int, int]],
    *,
    message_bound: Optional[int] = None,
) -> Optional[int]:
    """Recover one plaintext from same-modulus ``(exponent, ciphertext)`` samples.

    Every coprime-exponent pair produces a candidate with Bezout coefficients.
    When the exponent gcd is greater than one, recovery additionally requires an
    explicit original-problem promise ``0 <= m < message_bound`` with
    ``message_bound**g <= n``; otherwise modular ``g``-th roots are ambiguous.
    A candidate is emitted only if it re-encrypts to *all* supplied ciphertexts
    and all productive pairs agree.  Duplicate exponents alone are insufficient.
    """
    if not _integers(n) or n < 6:
        return None
    if message_bound is not None and (not _integers(message_bound) or message_bound < 1):
        return None
    observations = _bounded_items(samples, MAX_RSA_OBSERVATIONS)
    if observations is None:
        return None
    if len(observations) < 2:
        return None
    if any(not isinstance(item, (tuple, list)) or len(item) != 2 for item in observations):
        return None
    if any(not _integers(item[0], item[1]) for item in observations):
        return None
    observations = [(item[0], item[1]) for item in observations]
    if any(e < 2 or not (0 <= c < n) for e, c in observations):
        return None
    candidates: set[int] = set()
    for (e1, c1), (e2, c2) in itertools.combinations(observations, 2):
        if e1 == e2:
            continue
        g, a, b = _mc.egcd(e1, e2)
        if g < 1:
            continue
        x, y = _signed_pow(c1, a, n), _signed_pow(c2, b, n)
        if x is None or y is None:
            continue
        combined = x * y % n
        if g == 1:
            candidate = combined
        else:
            if message_bound is None or g > 257 or message_bound**g > n:
                continue
            candidate, exact = _mc.iroot(combined, g)
            if not exact or candidate >= message_bound:
                continue
        if all(pow(candidate, e, n) == c for e, c in observations):
            candidates.add(candidate)
    return next(iter(candidates)) if len(candidates) == 1 else None


def recover_fermat_factors(
    n: int,
    *,
    max_steps: int = 2_000_000,
    max_gap: Optional[int] = None,
    deadline: Optional[float] = None,
) -> Optional[tuple[int, int]]:
    """Factor an odd close-prime RSA modulus with Fermat's difference of squares."""
    if not _integers(n, max_steps) or not _deadline(deadline):
        return None
    if max_gap is not None and (not _integers(max_gap) or max_gap < 0):
        return None
    if n < 6 or n % 2 == 0 or max_steps < 0 or not _left(deadline):
        return None
    got = _mc.fermat(n, deadline=deadline, max_steps=max_steps)
    if got is None:
        return None
    split = _prime_split(n, got[0], got[1])
    if split is None or (max_gap is not None and abs(split[1] - split[0]) > max_gap):
        return None
    return split


def recover_close_prime_factors(
    n: int,
    *,
    max_steps: int = 2_000_000,
    max_gap: Optional[int] = None,
    deadline: Optional[float] = None,
) -> Optional[tuple[int, int]]:
    """Explicit routing name for the verified Fermat close-prime attack."""
    return recover_fermat_factors(n, max_steps=max_steps, max_gap=max_gap, deadline=deadline)


def recover_wiener_private_key(n: int, e: int) -> Optional[tuple[int, int, int]]:
    """Recover and verify ``(d,p,q)`` through Wiener's continued fractions."""
    if not _integers(n, e) or n < 6 or e < 2:
        return None
    got = _mc.wiener(n, e)
    if got is None:
        return None
    return _private_key(n, e, got[0], got[1], got[2])


def recover_hastad_broadcast(pairs: Iterable[tuple[int, int]], e: int) -> Optional[int]:
    """Recover a broadcast plaintext after CRT and an exact ``e``-th root.

    At least ``e`` distinct, pairwise-coprime moduli are required.  The root must
    be exact over the integers and must re-encrypt under every original modulus.
    """
    if not _integers(e) or e < 2 or e > 257:
        return None
    observations = _bounded_items(pairs, MAX_RSA_OBSERVATIONS)
    if observations is None:
        return None
    if len(observations) < e:
        return None
    if any(not isinstance(item, (tuple, list)) or len(item) != 2 for item in observations):
        return None
    if any(not _integers(item[0], item[1]) for item in observations):
        return None
    observations = [(item[0], item[1]) for item in observations]
    if any(n < 3 or not (0 <= c < n) for n, c in observations):
        return None
    # Repeated identical observations add no evidence; contradictory repeats decline.
    by_modulus: dict[int, int] = {}
    for n, c in observations:
        if n in by_modulus and by_modulus[n] != c:
            return None
        by_modulus[n] = c
    unique = list(by_modulus.items())
    if len(unique) < e:
        return None
    got = _mc.crt([c for n, c in unique], [n for n, c in unique])
    if got is None:
        return None
    root, exact = _mc.iroot(got[0], e)
    if not exact or root < 0 or root**e != got[0]:
        return None
    if any(pow(root, e, n) != c for n, c in observations):
        return None
    return root


def recover_franklin_reiter(
    n: int,
    e: int,
    c1: int,
    c2: int,
    *,
    a: int = 1,
    b: int = 0,
) -> Optional[int]:
    """Recover ``m`` when the second RSA message is ``a*m+b (mod n)``."""
    if not _integers(n, e, c1, c2, a, b):
        return None
    if n < 6 or not (0 <= c1 < n and 0 <= c2 < n):
        return None
    candidate = _mc.franklin_reiter(c1, c2, e, n, a, b)
    if candidate is None:
        return None
    related = (a * candidate + b) % n
    if pow(candidate, e, n) != c1 or pow(related, e, n) != c2:
        return None
    return candidate


def recover_related_message(
    n: int,
    e: int,
    c1: int,
    c2: int,
    *,
    a: int = 1,
    b: int = 0,
) -> Optional[int]:
    """Explicit routing name for the Franklin--Reiter related-message attack."""
    return recover_franklin_reiter(n, e, c1, c2, a=a, b=b)


def _poly_eval(coefficients: Sequence[int], x: int) -> int:
    value = 0
    for coefficient in reversed(coefficients):
        value = value * x + coefficient
    return value


def _poly_mul(a: Sequence[int], b: Sequence[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b):
            out[i + j] += av * bv
    return out


def _poly_pow(a: Sequence[int], exponent: int) -> list[int]:
    out = [1]
    for _ in range(exponent):
        out = _poly_mul(out, a)
    return out


def recover_coppersmith_root(
    coefficients: Sequence[int],
    n: int,
    bound: int,
    *,
    max_enumeration: int = 1 << 16,
    deadline: Optional[float] = None,
) -> Optional[int]:
    """Return the unique ``0 <= x < bound`` satisfying ``f(x) == 0 (mod n)``.

    Small fixtures are enumerated exactly; larger bounds use the repository's
    exact-LLL univariate Coppersmith implementation.  In either route every root
    is re-evaluated and multiple roots are an explicit ambiguity (``None``).
    """
    coeffs = _bounded_items(coefficients, MAX_COPPERSMITH_COEFFICIENTS)
    if coeffs is None:
        return None
    if not _integers(n, bound, max_enumeration) or not _deadline(deadline):
        return None
    if any(not _integers(coefficient) for coefficient in coeffs):
        return None
    while coeffs and coeffs[-1] == 0:
        coeffs.pop()
    if n < 3 or bound < 1 or not (2 <= len(coeffs) <= MAX_COPPERSMITH_COEFFICIENTS) or max_enumeration < 0 or not _left(deadline):
        return None
    candidates: set[int] = set()
    if bound <= max_enumeration:
        for root in range(bound):
            if _poly_eval(coeffs, root) % n == 0:
                candidates.add(root)
            if root & 4095 == 4095 and not _left(deadline):
                return None
    else:
        for root in _rl.coppersmith_roots(coeffs, n, bound, 1.0, deadline=deadline):
            if 0 <= root < bound and _poly_eval(coeffs, root) % n == 0:
                candidates.add(root)
    return next(iter(candidates)) if len(candidates) == 1 else None


def recover_stereotyped_message(
    n: int,
    e: int,
    ciphertext: int,
    *,
    prefix: bytes = b"",
    suffix: bytes = b"",
    unknown_len: int,
    max_enumeration: int = 1 << 16,
    deadline: Optional[float] = None,
) -> Optional[bytes]:
    """Recover ``prefix || unknown || suffix`` and verify its RSA ciphertext."""
    if not isinstance(prefix, bytes) or not isinstance(suffix, bytes):
        return None
    if not _integers(n, e, ciphertext, unknown_len, max_enumeration) or not _deadline(deadline):
        return None
    if n < 3 or not (2 <= e <= 17) or not (1 <= unknown_len <= 1024) or not (0 <= ciphertext < n):
        return None
    if len(prefix) + unknown_len + len(suffix) > MAX_STEREOTYPED_BYTES:
        return None
    shift = 1 << (8 * len(suffix))
    base = (int.from_bytes(prefix, "big") << (8 * (unknown_len + len(suffix)))) + int.from_bytes(suffix, "big")
    polynomial = _poly_pow([base, shift], e)
    polynomial[0] -= ciphertext
    bound = 1 << (8 * unknown_len)
    root = recover_coppersmith_root(
        polynomial,
        n,
        bound,
        max_enumeration=max_enumeration,
        deadline=deadline,
    )
    if root is None:
        return None
    message = prefix + root.to_bytes(unknown_len, "big") + suffix
    value = int.from_bytes(message, "big")
    if pow(value, e, n) != ciphertext:
        return None
    return message


def _hint_matches(factor: int, known: int, known_bits: int, p_bits: int, kind: str) -> bool:
    if factor.bit_length() > p_bits:
        return False
    unknown = p_bits - known_bits
    if kind == "high":
        return factor >> unknown == known
    mask = (1 << known_bits) - 1
    return factor & mask == known


def recover_partial_prime(
    n: int,
    known: int,
    known_bits: int,
    *,
    kind: str = "high",
    p_bits: Optional[int] = None,
    max_enumeration: int = 1 << 16,
    deadline: Optional[float] = None,
) -> Optional[tuple[int, int]]:
    """Recover an RSA prime from its known high or low bits.

    Bounded unknown spaces are searched exactly; larger ones go through the
    exact-LLL partial-prime Coppersmith implementation.  Both returned factors
    must independently pass primality tests and multiply back to ``n``.
    """
    if not _integers(n, known, known_bits, max_enumeration) or not _deadline(deadline):
        return None
    if p_bits is not None and not _integers(p_bits):
        return None
    bits = p_bits if p_bits is not None else (n.bit_length() + 1) // 2
    if not isinstance(kind, str):
        return None
    if n < 6 or kind not in {"high", "low"} or not (2 <= bits <= 16384) or not (1 <= known_bits <= bits):
        return None
    if known < 0 or known >= 1 << known_bits or max_enumeration < 0 or not _left(deadline):
        return None
    unknown = bits - known_bits
    space = 1 << unknown
    candidates: set[tuple[int, int]] = set()
    if space <= max_enumeration:
        for tail in range(space):
            factor = (known << unknown) | tail if kind == "high" else known | (tail << known_bits)
            if factor > 1 and n % factor == 0:
                split = _prime_split(n, factor, n // factor)
                if split is not None and any(_hint_matches(x, known, known_bits, bits, kind) for x in split):
                    candidates.add(split)
            if tail & 4095 == 4095 and not _left(deadline):
                return None
    else:
        got = _rl.partial_prime(n, known, known_bits, kind, bits, deadline=deadline)
        if got is not None:
            split = _prime_split(n, got[0], got[1])
            if split is not None and any(_hint_matches(x, known, known_bits, bits, kind) for x in split):
                candidates.add(split)
    return next(iter(candidates)) if len(candidates) == 1 else None


def recover_private_exponent_known_bits(
    n: int,
    e: int,
    known: int,
    known_bits: int,
    total_bits: int,
    *,
    kind: str = "high",
    max_candidates: int = 1 << 20,
    deadline: Optional[float] = None,
) -> Optional[tuple[int, int, int]]:
    """Complete a bounded high/low-bit leak of ``d`` and verify the private key.

    This exact completion helper intentionally refuses spaces above
    ``max_candidates``; those require a challenge-specific multivariate lattice.
    Equivalent private exponents can coexist, so all verified completions are
    collected and more than one is treated as ambiguous.
    """
    values = (n, e, known, known_bits, total_bits, max_candidates)
    if not _integers(*values) or not _deadline(deadline):
        return None
    if not isinstance(kind, str):
        return None
    if n < 6 or e < 2 or kind not in {"high", "low"} or not (1 <= known_bits <= total_bits):
        return None
    if known < 0 or known >= 1 << known_bits or max_candidates < 1:
        return None
    unknown = total_bits - known_bits
    if unknown >= max_candidates.bit_length() or (1 << unknown) > max_candidates or not _left(deadline):
        return None
    candidates: set[tuple[int, int, int]] = set()
    for tail in range(1 << unknown):
        d = (known << unknown) | tail if kind == "high" else known | (tail << known_bits)
        if d <= 0 or d.bit_length() > total_bits:
            continue
        split = _bounded_factor_from_d(n, e, d)
        if split is not None:
            verified = _private_key(n, e, d, split[0], split[1])
            if verified is not None:
                candidates.add(verified)
        if tail & 4095 == 4095 and not _left(deadline):
            return None
    return next(iter(candidates)) if len(candidates) == 1 else None


def _bounded_factor_from_d(n: int, e: int, d: int) -> Optional[tuple[int, int]]:
    """Standard factor-from-private-exponent algorithm with a finite squaring cap.

    For a genuine key, ``k=e*d-1`` is a multiple of lambda(n), so at most the
    two-adic valuation of ``k`` squarings are needed.  A wrong completion is not
    allowed to enter an unbounded modular cycle.
    """
    k = e * d - 1
    if k <= 0 or k & 1:
        return None
    odd, powers = k, 0
    while odd & 1 == 0:
        odd //= 2
        powers += 1
    for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if math.gcd(base, n) != 1:
            factor = math.gcd(base, n)
            split = _prime_split(n, factor, n // factor) if 1 < factor < n else None
            if split is not None:
                return split
            continue
        x = pow(base, odd, n)
        if x in (1, n - 1):
            continue
        for _ in range(powers):
            y = x * x % n
            if y == 1:
                factor = math.gcd(x - 1, n)
                split = _prime_split(n, factor, n // factor) if 1 < factor < n else None
                if split is not None:
                    return split
                break
            if y == n - 1:
                break
            x = y
    return None


def recover_boneh_durfee_private_key(
    n: int,
    e: int,
    *,
    delta: float = 0.27,
    m: int = 3,
    t: int = 1,
    deadline: Optional[float] = None,
) -> Optional[tuple[int, int, int]]:
    """Recover and verify a low-``d`` key through Boneh--Durfee's lattice."""
    if not _integers(n, e, m, t) or isinstance(delta, bool) or not isinstance(delta, (int, float)):
        return None
    if not math.isfinite(float(delta)) or not _deadline(deadline):
        return None
    if n < 6 or e < 2 or not (0.20 <= delta < 0.35) or not (2 <= m <= 6) or not (1 <= t <= m) or not _left(deadline):
        return None
    got = _rl.boneh_durfee(n, e, delta=delta, m=m, t=t, deadline=deadline)
    if got is None:
        return None
    return _private_key(n, e, got[0], got[1], got[2])


def recover_crt_fault_private_key(
    n: int,
    e: int,
    message: int,
    faulty_signature: int,
    *,
    correct_signature: Optional[int] = None,
) -> Optional[tuple[int, int, int]]:
    """Recover ``(d,p,q)`` from one Bellcore CRT-RSA signature fault.

    With a known correct signature, both ``gcd(s-s',n)`` and the public
    verification residue are used.  All productive gcds must describe the same
    prime split, and the derived private key is fully checked before emission.
    """
    vals = (n, e, message, faulty_signature)
    if not _integers(*vals):
        return None
    if n < 6 or e < 2 or not (0 <= faulty_signature < n):
        return None
    target = message % n
    faulty_residue = pow(faulty_signature, e, n)
    if faulty_residue == target:
        return None
    splits: set[tuple[int, int]] = set()
    residue_factor = math.gcd((faulty_residue - target) % n, n)
    if 1 < residue_factor < n:
        split = _prime_split(n, residue_factor, n // residue_factor)
        if split is not None:
            splits.add(split)
    if correct_signature is not None:
        if not _integers(correct_signature) or not (0 <= correct_signature < n):
            return None
        if pow(correct_signature, e, n) != target:
            return None
        difference_factor = math.gcd((correct_signature - faulty_signature) % n, n)
        if 1 < difference_factor < n:
            split = _prime_split(n, difference_factor, n // difference_factor)
            if split is not None:
                splits.add(split)
    if len(splits) != 1:
        return None
    p, q = next(iter(splits))
    return _private_from_split(n, e, p, q)
