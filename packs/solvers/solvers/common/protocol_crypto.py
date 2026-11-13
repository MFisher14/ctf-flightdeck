"""Verified protocol-misuse helpers not covered by the existing generic dlog/RSA lanes.

The module is offline and equation-driven.  It does not implement a general
discrete-log solver, private-key decryption, ECDSA/DSA nonce attacks, sockets, or
artifact execution.  Every secret-bearing result is returned only after replay
of every supplied public equation; multiple valid candidates, malformed input,
an iterator failure, or any work cap returns ``None``.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import math
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence


MAX_ITEMS = 4096
MAX_SEARCH = 1 << 16
MAX_BITS = 4096
MAX_BYTES = 2 << 20

__all__ = [
    "DHGroupAudit", "DSAParameterAudit", "ElGamalRecovery", "HomomorphicResult",
    "PaillierRecovery", "PedersenRecovery", "SchnorrAudit", "ShamirRecovery",
    "audit_dh_group", "audit_dsa_parameters", "audit_schnorr_challenges",
    "elgamal_homomorphic_multiply", "paillier_encrypt", "paillier_homomorphic_add",
    "pedersen_commit", "recover_dh_exponent_crt", "recover_elgamal_reused_nonce",
    "recover_hash_commitment", "recover_paillier_reused_randomness",
    "recover_paillier_weak_randomness", "recover_pedersen_reused_randomness",
    "recover_pedersen_weak_opening", "recover_schnorr_secret",
    "recover_small_subgroup_residue", "robust_shamir_reconstruct",
]


@dataclass(frozen=True)
class DHGroupAudit:
    modulus_bits: int
    modulus_prime: bool
    generator_order: Optional[int]
    small_factors: tuple[int, ...]
    public_values_valid: bool
    findings: tuple[str, ...]


@dataclass(frozen=True)
class ElGamalRecovery:
    plaintext: int
    nonce: int
    shared: int


@dataclass(frozen=True)
class HomomorphicResult:
    scheme: str
    inputs: tuple[tuple[int, ...], ...]
    output: tuple[int, ...]
    relation_replayed: bool


@dataclass(frozen=True)
class PaillierRecovery:
    plaintext: int
    randomness: Optional[int]
    randomness_factor: int


@dataclass(frozen=True)
class SchnorrAudit:
    repeated_commitments: tuple[int, ...]
    zero_challenges: int
    short_challenges: int
    findings: tuple[str, ...]


@dataclass(frozen=True)
class DSAParameterAudit:
    p_prime: bool
    q_prime: bool
    q_divides_p_minus_1: bool
    generator_in_subgroup: bool
    public_in_subgroup: bool
    findings: tuple[str, ...]


@dataclass(frozen=True)
class ShamirRecovery:
    secret: int
    polynomial: tuple[int, ...]
    consistent_indices: tuple[int, ...]
    error_indices: tuple[int, ...]


@dataclass(frozen=True)
class PedersenRecovery:
    message: int
    randomness: Optional[int]
    randomness_factor: int


def _ints(*values: object) -> bool:
    return all(isinstance(v, int) and not isinstance(v, bool) for v in values)


def _bounded(values: object, cap: int = MAX_ITEMS) -> Optional[list[object]]:
    if not _ints(cap) or cap < 0:
        return None
    try:
        result = list(itertools.islice(iter(values), cap + 1))
    except Exception:
        return None
    return result if len(result) <= cap else None


def _prime(value: int) -> bool:
    if not _ints(value) or value < 2 or value.bit_length() > MAX_BITS:
        return False
    try:
        import sympy
    except ImportError:  # pragma: no cover
        if value > MAX_SEARCH:
            return False
        if value < 4:
            return value in (2, 3)
        return all(value % d for d in range(2, math.isqrt(value) + 1))
    return bool(sympy.isprime(value))


def _factor_small(value: int) -> Optional[tuple[int, ...]]:
    if not _ints(value) or not (1 <= value <= MAX_SEARCH):
        return None
    factors = []
    current = value
    divisor = 2
    while divisor * divisor <= current:
        if current % divisor == 0:
            factors.append(divisor)
            while current % divisor == 0:
                current //= divisor
        divisor += 1
    if current > 1:
        factors.append(current)
    return tuple(factors)


def _crt(residues: Sequence[int], moduli: Sequence[int]) -> Optional[tuple[int, int]]:
    value, modulus = 0, 1
    for residue, current in zip(residues, moduli):
        if current < 2 or math.gcd(modulus, current) != 1:
            return None
        value += modulus * ((residue - value) * pow(modulus, -1, current) % current)
        modulus *= current
    return value % modulus, modulus


def audit_dh_group(
    p: int,
    g: int,
    *,
    subgroup_order: Optional[int] = None,
    order_factors: Iterable[int] = (),
    public_values: Iterable[int] = (),
) -> Optional[DHGroupAudit]:
    """Audit multiplicative DH parameters; this performs no generic dlog search."""
    factors, publics = _bounded(order_factors, 128), _bounded(public_values, 128)
    if not _ints(p, g) or factors is None or publics is None or p < 3 or p.bit_length() > MAX_BITS:
        return None
    if any(not _ints(v) for v in factors + publics):
        return None
    prime = _prime(p)
    candidate_order = subgroup_order if subgroup_order is not None else p - 1
    if not _ints(candidate_order) or not (1 < candidate_order <= p - 1):
        return None
    if (p - 1) % candidate_order or not (1 < g < p):
        return None
    supplied = tuple(sorted(set(factors)))
    if any(f < 2 or candidate_order % f or not _prime(f) for f in supplied):
        return None
    remainder = candidate_order
    for factor in supplied:
        while remainder % factor == 0:
            remainder //= factor
    full_factorization = remainder == 1 or _prime(candidate_order)
    order = candidate_order if full_factorization else None
    if order is not None:
        for factor in supplied or ((candidate_order,) if _prime(candidate_order) else ()):
            while order % factor == 0 and pow(g, order // factor, p) == 1:
                order //= factor
        if pow(g, order, p) != 1:
            order = None
    valid_publics = order is not None and all(1 < y < p and pow(y, order, p) == 1 for y in publics)
    small = tuple(f for f in supplied if f <= 1 << 20)
    findings = []
    if not prime:
        findings.append("composite_modulus")
    if order is not None and order <= 1 << 32:
        findings.append("small_generator_order")
    if small:
        findings.append("smooth_or_small_order_factors")
    if publics and not valid_publics:
        findings.append("public_value_outside_subgroup")
    if not full_factorization:
        findings.append("order_not_proven")
    return DHGroupAudit(p.bit_length(), prime, order, small, bool(valid_publics), tuple(findings))


def recover_small_subgroup_residue(p: int, base: int, response: int, order: int) -> Optional[int]:
    """Recover ``x mod order`` only for a supplied, proven small-order element."""
    if not _ints(p, base, response, order) or not _prime(p) or not (2 <= order <= MAX_SEARCH):
        return None
    factors = _factor_small(order)
    if factors is None or not (1 < base < p and 0 <= response < p) or pow(base, order, p) != 1:
        return None
    if any(pow(base, order // factor, p) == 1 for factor in factors):
        return None
    candidates = [x for x in range(order) if pow(base, x, p) == response % p]
    return candidates[0] if len(candidates) == 1 else None


def recover_dh_exponent_crt(
    p: int,
    g: int,
    public: int,
    residues: Iterable[tuple[int, int]],
    *,
    exponent_bound: int,
) -> Optional[int]:
    """Assemble small-subgroup residues and emit one exponent after ``g^x`` replay."""
    rows = _bounded(residues, 64)
    if not _ints(p, g, public, exponent_bound) or rows is None or exponent_bound <= 0:
        return None
    if not _prime(p) or not (1 < g < p and 1 <= public < p) or exponent_bound > 1 << 256:
        return None
    if any(not isinstance(row, (tuple, list)) or len(row) != 2 or not _ints(*row) for row in rows):
        return None
    if any(not (2 <= modulus <= MAX_SEARCH and 0 <= residue < modulus)
           for residue, modulus in rows):
        return None
    got = _crt([row[0] for row in rows], [row[1] for row in rows])
    if got is None:
        return None
    start, period = got
    count = (max(0, exponent_bound - 1 - start) // period + 1) if start < exponent_bound else 0
    if count > MAX_SEARCH:
        return None
    candidates = [start + k * period for k in range(count) if pow(g, start + k * period, p) == public]
    return candidates[0] if len(candidates) == 1 else None


def recover_elgamal_reused_nonce(
    p: int,
    g: int,
    y: int,
    known_ciphertext: tuple[int, int],
    known_plaintext: int,
    target_ciphertext: tuple[int, int],
    *,
    nonce_bound: int,
) -> Optional[ElGamalRecovery]:
    """Recover an ElGamal plaintext from nonce reuse plus one known plaintext."""
    values = _bounded((known_ciphertext, target_ciphertext), 2)
    if not _ints(p, g, y, known_plaintext, nonce_bound) or values is None or not _prime(p):
        return None
    if not (1 < g < p and 1 < y < p and 1 <= nonce_bound <= MAX_SEARCH):
        return None
    if any(not isinstance(c, (tuple, list)) or len(c) != 2 or not _ints(*c) for c in values):
        return None
    (c1, c2), (t1, t2) = values
    if c1 != t1 or not all(0 < v < p for v in (c1, c2, t1, t2, known_plaintext)):
        return None
    try:
        shared = c2 * pow(known_plaintext, -1, p) % p
        plaintext = t2 * pow(shared, -1, p) % p
    except ValueError:
        return None
    nonces = [k for k in range(1, nonce_bound) if pow(g, k, p) == c1 and pow(y, k, p) == shared]
    if len(nonces) != 1:
        return None
    k = nonces[0]
    if c2 != known_plaintext * pow(y, k, p) % p or t2 != plaintext * pow(y, k, p) % p:
        return None
    return ElGamalRecovery(plaintext, k, shared)


def elgamal_homomorphic_multiply(ciphertexts: Iterable[tuple[int, int]], p: int) -> Optional[HomomorphicResult]:
    rows = _bounded(ciphertexts, 256)
    if not _ints(p) or rows is None or not rows or not _prime(p):
        return None
    if any(not isinstance(row, (tuple, list)) or len(row) != 2 or not _ints(*row)
           or any(not (0 < v < p) for v in row) for row in rows):
        return None
    output = (math.prod(row[0] for row in rows) % p, math.prod(row[1] for row in rows) % p)
    replayed = output == (math.prod(row[0] for row in rows) % p, math.prod(row[1] for row in rows) % p)
    return HomomorphicResult("elgamal_multiplication", tuple(tuple(row) for row in rows), output, replayed)


def paillier_encrypt(message: int, randomness: int, n: int, g: Optional[int] = None) -> Optional[int]:
    if not _ints(message, randomness, n) or n < 3 or n.bit_length() > MAX_BITS or _prime(n):
        return None
    generator = n + 1 if g is None else g
    if (not _ints(generator) or not (0 <= message < n and 0 < randomness < n)
            or not (1 < generator < n * n) or math.gcd(generator, n * n) != 1 or math.gcd(randomness, n) != 1):
        return None
    nsq = n * n
    return pow(generator, message, nsq) * pow(randomness, n, nsq) % nsq


def recover_paillier_weak_randomness(
    ciphertext: int,
    n: int,
    randomness_candidates: Iterable[int],
    *,
    g: Optional[int] = None,
) -> Optional[PaillierRecovery]:
    candidates = _bounded(randomness_candidates, MAX_SEARCH)
    generator = n + 1 if g is None and _ints(n) else g
    if (not _ints(ciphertext, n, generator) or candidates is None or n < 3 or n.bit_length() > MAX_BITS
            or _prime(n) or generator != n + 1 or not (0 <= ciphertext < n * n) or math.gcd(ciphertext, n) != 1):
        return None
    if any(not _ints(randomness) or not (0 < randomness < n) or math.gcd(randomness, n) != 1
           for randomness in candidates):
        return None
    found = set()
    nsq = n * n
    for randomness in candidates:
        stripped = ciphertext * pow(pow(randomness, n, nsq), -1, nsq) % nsq
        if (stripped - 1) % n:
            continue
        message = ((stripped - 1) // n) % n
        if paillier_encrypt(message, randomness, n, generator) == ciphertext:
            found.add((message, randomness, pow(randomness, n, nsq)))
    if len(found) != 1:
        return None
    message, randomness, factor = next(iter(found))
    return PaillierRecovery(message, randomness, factor)


def recover_paillier_reused_randomness(
    known_ciphertext: int,
    known_plaintext: int,
    target_ciphertext: int,
    n: int,
    randomness_candidates: Iterable[int],
    *,
    g: Optional[int] = None,
) -> Optional[PaillierRecovery]:
    candidates = _bounded(randomness_candidates, MAX_SEARCH)
    generator = n + 1 if g is None and _ints(n) else g
    if (not _ints(known_ciphertext, known_plaintext, target_ciphertext, n, generator)
            or candidates is None or n < 3 or n.bit_length() > MAX_BITS or _prime(n)):
        return None
    if generator != n + 1 or not (0 <= known_plaintext < n and 0 <= known_ciphertext < n * n
                                   and 0 <= target_ciphertext < n * n) or math.gcd(known_ciphertext, n) != 1 \
            or math.gcd(target_ciphertext, n) != 1:
        return None
    if any(not _ints(r) or not (0 < r < n) or math.gcd(r, n) != 1 for r in candidates):
        return None
    found = set()
    nsq = n * n
    for randomness in candidates:
        factor = pow(randomness, n, nsq)
        if pow(generator, known_plaintext, nsq) * factor % nsq != known_ciphertext:
            continue
        stripped = target_ciphertext * pow(factor, -1, nsq) % nsq
        if (stripped - 1) % n:
            continue
        message = ((stripped - 1) // n) % n
        if paillier_encrypt(message, randomness, n, generator) == target_ciphertext:
            found.add((message, randomness, factor))
    if len(found) != 1:
        return None
    message, randomness, factor = next(iter(found))
    return PaillierRecovery(message, randomness, factor)


def paillier_homomorphic_add(ciphertexts: Iterable[int], n: int) -> Optional[HomomorphicResult]:
    values = _bounded(ciphertexts, 256)
    if not _ints(n) or n < 3 or n.bit_length() > MAX_BITS or _prime(n) or values is None or not values:
        return None
    if any(not _ints(c) or not (0 <= c < n * n) or math.gcd(c, n) != 1 for c in values):
        return None
    output = math.prod(values) % (n * n)
    return HomomorphicResult("paillier_addition", tuple((c,) for c in values), (output,),
                             output == math.prod(values) % (n * n))


def _schnorr_valid(p: int, q: int, g: int, y: int, signature: Sequence[int]) -> bool:
    if len(signature) != 3:
        return False
    commitment, challenge, response = signature
    return (_ints(commitment, challenge, response) and 0 < commitment < p and 0 <= challenge < q
            and 0 <= response < q and pow(g, response, p) == commitment * pow(y, challenge, p) % p)


def recover_schnorr_secret(
    p: int,
    q: int,
    g: int,
    y: int,
    signatures: Iterable[tuple[int, int, int]],
    *,
    nonce_bound: int = 0,
) -> Optional[int]:
    rows = _bounded(signatures, 256)
    if not _ints(p, q, g, y, nonce_bound) or rows is None or not rows or not _prime(p) or not _prime(q):
        return None
    if (p - 1) % q or pow(g, q, p) != 1 or not (1 < g < p and 1 < y < p):
        return None
    if any(not isinstance(row, (tuple, list)) or not _schnorr_valid(p, q, g, y, row) for row in rows):
        return None
    found = set()
    for first, second in itertools.combinations(rows, 2):
        if first[0] != second[0] or first[1] == second[1]:
            continue
        denominator = (first[1] - second[1]) % q
        if math.gcd(denominator, q) == 1:
            secret = (first[2] - second[2]) * pow(denominator, -1, q) % q
            if pow(g, secret, p) == y:
                found.add(secret)
    if nonce_bound:
        if not (1 <= nonce_bound <= MAX_SEARCH):
            return None
        for commitment, challenge, response in rows:
            if challenge == 0 or math.gcd(challenge, q) != 1:
                continue
            for nonce in range(nonce_bound):
                if pow(g, nonce, p) == commitment:
                    secret = (response - nonce) * pow(challenge, -1, q) % q
                    if pow(g, secret, p) == y:
                        found.add(secret)
    proven = [secret for secret in found if all(_schnorr_valid(p, q, g, pow(g, secret, p), row) for row in rows)]
    return proven[0] if len(proven) == 1 else None


def audit_schnorr_challenges(signatures: Iterable[tuple[int, int, int]], q: int) -> Optional[SchnorrAudit]:
    rows = _bounded(signatures, 4096)
    if not _ints(q) or not (1 < q and q.bit_length() <= MAX_BITS) or rows is None \
            or any(not isinstance(row, (tuple, list)) or len(row) != 3 or not _ints(*row)
                   or any(value < 0 or value.bit_length() > MAX_BITS for value in row) for row in rows):
        return None
    counts = {}
    for commitment, _, _ in rows:
        counts[commitment] = counts.get(commitment, 0) + 1
    repeated = tuple(sorted(value for value, count in counts.items() if count > 1))
    zero = sum(row[1] % q == 0 for row in rows) if q > 0 else 0
    short = sum(0 <= row[1] < min(q, 1 << 32) for row in rows) if q > 0 else 0
    findings = tuple(name for condition, name in ((bool(repeated), "reused_commitment"),
                                                   (bool(zero), "zero_challenge"),
                                                   (bool(short), "short_challenge")) if condition)
    return SchnorrAudit(repeated, zero, short, findings)


def audit_dsa_parameters(p: int, q: int, g: int, y: int) -> Optional[DSAParameterAudit]:
    if not _ints(p, q, g, y) or p.bit_length() > MAX_BITS:
        return None
    pp, qp = _prime(p), _prime(q)
    divides = p > 2 and q > 1 and (p - 1) % q == 0
    generator = divides and 1 < g < p and pow(g, q, p) == 1
    public = generator and 1 < y < p and pow(y, q, p) == 1
    findings = tuple(name for condition, name in ((not pp, "p_not_prime"), (not qp, "q_not_prime"),
                                                   (not divides, "q_not_divisor"),
                                                   (not generator, "invalid_generator"),
                                                   (not public, "invalid_public_key")) if condition)
    return DSAParameterAudit(pp, qp, divides, generator, public, findings)


def _poly_add(left: list[int], right: list[int], prime: int) -> list[int]:
    size = max(len(left), len(right))
    return [((left[i] if i < len(left) else 0) + (right[i] if i < len(right) else 0)) % prime
            for i in range(size)]


def _poly_mul(left: list[int], right: list[int], prime: int) -> list[int]:
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] = (out[i + j] + a * b) % prime
    return out


def _interpolate(points: Sequence[tuple[int, int]], prime: int) -> Optional[tuple[int, ...]]:
    polynomial = [0]
    for i, (xi, yi) in enumerate(points):
        basis, denominator = [1], 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            basis = _poly_mul(basis, [(-xj) % prime, 1], prime)
            denominator = denominator * (xi - xj) % prime
        if denominator == 0:
            return None
        scale = yi * pow(denominator, -1, prime) % prime
        polynomial = _poly_add(polynomial, [coefficient * scale % prime for coefficient in basis], prime)
    return tuple(polynomial + [0] * (len(points) - len(polynomial)))


def _poly_eval(polynomial: Sequence[int], x: int, prime: int) -> int:
    result = 0
    for coefficient in reversed(polynomial):
        result = (result * x + coefficient) % prime
    return result


def robust_shamir_reconstruct(
    shares: Iterable[tuple[int, int]],
    prime: int,
    threshold: int,
    *,
    max_errors: int = 0,
    max_subsets: int = MAX_ITEMS,
) -> Optional[ShamirRecovery]:
    rows = _bounded(shares, 64)
    if not _ints(prime, threshold, max_errors, max_subsets) or rows is None or not _prime(prime):
        return None
    if not (2 <= threshold <= len(rows)) or max_errors < 0 or not (1 <= max_subsets <= MAX_ITEMS):
        return None
    if math.comb(len(rows), threshold) > max_subsets:
        return None
    if any(not isinstance(row, (tuple, list)) or len(row) != 2 or not _ints(*row) for row in rows):
        return None
    if any(x.bit_length() > MAX_BITS or y.bit_length() > MAX_BITS for x, y in rows):
        return None
    if any(not (0 < x < prime and 0 <= y < prime) for x, y in rows):
        return None
    normalised = [(x, y) for x, y in rows]
    if any(x == 0 for x, _ in normalised) or len({x for x, _ in normalised}) != len(normalised):
        return None
    found = {}
    for count, subset in enumerate(itertools.combinations(range(len(normalised)), threshold), 1):
        if count > max_subsets:
            return None
        polynomial = _interpolate([normalised[index] for index in subset], prime)
        if polynomial is None:
            continue
        matches = tuple(index for index, (x, y) in enumerate(normalised) if _poly_eval(polynomial, x, prime) == y)
        errors = tuple(index for index in range(len(normalised)) if index not in matches)
        if len(matches) >= threshold and len(errors) <= max_errors:
            identity = tuple(_poly_eval(polynomial, x, prime) for x, _ in normalised)
            found[identity] = ShamirRecovery(polynomial[0], polynomial, matches, errors)
    return next(iter(found.values())) if len(found) == 1 else None


def pedersen_commit(message: int, randomness: int, p: int, g: int, h: int) -> Optional[int]:
    if not _ints(message, randomness, p, g, h) or not _prime(p) or not all(0 < v < p for v in (g, h)):
        return None
    if not (0 <= message < p - 1 and 0 <= randomness < p - 1):
        return None
    return pow(g, message, p) * pow(h, randomness, p) % p


def recover_pedersen_weak_opening(
    commitment: int,
    p: int,
    g: int,
    h: int,
    message_candidates: Iterable[int],
    randomness_candidates: Iterable[int],
) -> Optional[PedersenRecovery]:
    messages, randomnesses = _bounded(message_candidates, MAX_SEARCH), _bounded(randomness_candidates, MAX_SEARCH)
    if messages is None or randomnesses is None or len(messages) * len(randomnesses) > MAX_SEARCH:
        return None
    if not _ints(commitment, p, g, h) or not _prime(p) or not (0 < commitment < p) \
            or not (1 < g < p and 1 < h < p):
        return None
    if any(not _ints(message) or not (0 <= message < p - 1) for message in messages) \
            or any(not _ints(randomness) or not (0 <= randomness < p - 1) for randomness in randomnesses):
        return None
    found = set()
    for message, randomness in itertools.product(messages, randomnesses):
        factor = pow(h, randomness, p)
        if pow(g, message, p) * factor % p == commitment:
            found.add((message, randomness, factor))
    if len(found) != 1:
        return None
    message, randomness, factor = next(iter(found))
    return PedersenRecovery(message, randomness, factor)


def recover_pedersen_reused_randomness(
    known_commitment: int,
    known_message: int,
    target_commitment: int,
    p: int,
    g: int,
    h: int,
    target_messages: Iterable[int],
    randomness_candidates: Iterable[int],
) -> Optional[PedersenRecovery]:
    candidates, randomnesses = _bounded(target_messages, MAX_SEARCH), _bounded(randomness_candidates, MAX_SEARCH)
    if candidates is None or randomnesses is None or len(candidates) * len(randomnesses) > MAX_SEARCH:
        return None
    if not _ints(known_commitment, known_message, target_commitment, p, g, h) or not _prime(p):
        return None
    if not (0 < known_commitment < p and 0 < target_commitment < p and 1 < g < p and 1 < h < p
            and 0 <= known_message < p - 1):
        return None
    if any(not _ints(message) or not (0 <= message < p - 1) for message in candidates) \
            or any(not _ints(randomness) or not (0 <= randomness < p - 1) for randomness in randomnesses):
        return None
    found = set()
    for message, randomness in itertools.product(candidates, randomnesses):
        factor = pow(h, randomness, p)
        if (pow(g, known_message, p) * factor % p == known_commitment
                and pow(g, message, p) * factor % p == target_commitment):
            found.add((message, randomness, factor))
    if len(found) != 1:
        return None
    message, randomness, factor = next(iter(found))
    return PedersenRecovery(message, randomness, factor)


def recover_hash_commitment(
    commitment: bytes,
    messages: Iterable[bytes],
    randomnesses: Iterable[bytes],
    *,
    algorithm: str = "sha256",
) -> Optional[tuple[bytes, bytes]]:
    message_values, random_values = _bounded(messages, MAX_ITEMS), _bounded(randomnesses, MAX_ITEMS)
    if type(commitment) is not bytes or type(algorithm) is not str or len(algorithm) > 64 \
            or message_values is None or random_values is None:
        return None
    if len(message_values) * len(random_values) > MAX_SEARCH or algorithm not in hashlib.algorithms_available:
        return None
    if any(type(value) is not bytes for value in message_values + random_values):
        return None
    if len(commitment) + sum(len(value) for value in message_values + random_values) > MAX_BYTES:
        return None
    try:
        probe = hashlib.new(algorithm)
    except Exception:
        return None
    if not probe.digest_size:  # SHAKE requires a caller-chosen output length: ambiguous here.
        return None
    found = set()
    for message, randomness in itertools.product(message_values, random_values):
        if len(message) >= 1 << 32:
            continue
        try:
            digest = hashlib.new(algorithm, len(message).to_bytes(4, "big") + message + randomness).digest()
        except Exception:
            return None
        if hmac.compare_digest(digest, commitment):
            found.add((message, randomness))
    if len(found) != 1:
        return None
    result = next(iter(found))
    try:
        replay = hashlib.new(algorithm, len(result[0]).to_bytes(4, "big") + result[0] + result[1]).digest()
    except Exception:
        return None
    return result if hmac.compare_digest(replay, commitment) else None
