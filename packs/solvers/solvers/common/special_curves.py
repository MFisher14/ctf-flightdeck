"""Verified offline attacks for special curves, pairings, twists, and toy isogenies.

All scalar emitters are fail closed: a candidate is returned only after replaying
``g**x == h`` or ``[x]G == Q`` in the original group.  Structure analyzers return
a record only after their supplied transcript is checked.  Every search has a
hard table, relation, candidate, depth, or field-size bound; this module performs
no networking.

The mature p-adic and Miller-loop arithmetic already present in ``ecc_weak`` is
reused for Smart and concrete MOV/Frey--Rueck transfers.  This module adds stricter
order/public-point checks around those helpers, a non-split singular-node route,
quadratic-twist transcript recovery, generic higher-embedding pairing transcripts,
and toy isogeny validation/path recovery.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import itertools
import math
import time
from typing import Any, Callable, Iterable, Optional, Sequence

try:  # Package import from the repository root.
    from . import ecc_weak as _ecc
except ImportError:  # Direct legacy import with solvers/common on sys.path.
    import ecc_weak as _ecc


MAX_ORDER = 1 << 63
MAX_BSGS_TABLE = 1 << 20
MAX_FACTOR_TRIAL = 1 << 20
MAX_INDEX_RELATIONS = 1 << 16
MAX_INDEX_FACTOR_BASE = 64
MAX_TWIST_OBSERVATIONS = 64
MAX_CRT_CANDIDATES = 1 << 18
MAX_EXTENSION_DEGREE = 16
MAX_EXTENSION_BITS = 4096
MAX_ISOGENY_NODES = 4096


# ---------------------------------------------------------------------------
# Exact small/bounded number theory


def _plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_prime(value: int) -> bool:
    if (
        not _plain_int(value)
        or value < 2
        or value >= 1 << 64
    ):
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small:
        if value % prime == 0:
            return value == prime
    d, s = value - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic for unsigned 64-bit integers.
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % value == 0:
            continue
        x = pow(base, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(s - 1):
            x = x * x % value
            if x == value - 1:
                break
        else:
            return False
    return True


def _factor_complete(value: int) -> Optional[dict[int, int]]:
    """Fully factor a bounded integer, or decline instead of guessing primality."""

    if not _plain_int(value) or not (1 <= value <= MAX_ORDER):
        return None
    remaining = value
    factors: dict[int, int] = {}
    divisor = 2
    trials = 0
    while divisor * divisor <= remaining:
        if trials >= MAX_FACTOR_TRIAL:
            if _is_prime(remaining):
                factors[remaining] = factors.get(remaining, 0) + 1
                remaining = 1
                break
            return None
        while remaining % divisor == 0:
            factors[divisor] = factors.get(divisor, 0) + 1
            remaining //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
        trials += 1
    if remaining > 1:
        if not _is_prime(remaining):
            return None
        factors[remaining] = factors.get(remaining, 0) + 1
    product = math.prod(prime**exponent for prime, exponent in factors.items())
    return factors if product == value else None


def _crt_merge(left: tuple[int, int], right: tuple[int, int]) -> Optional[tuple[int, int]]:
    x, m = left
    y, n = right
    common = math.gcd(m, n)
    if (y - x) % common:
        return None
    reduced_m, reduced_n = m // common, n // common
    try:
        step = ((y - x) // common * pow(reduced_m, -1, reduced_n)) % reduced_n if reduced_n > 1 else 0
    except ValueError:
        return None
    modulus = m * reduced_n
    return (x + m * step) % modulus, modulus


def _legendre(value: int, prime: int) -> int:
    residue = pow(value % prime, (prime - 1) // 2, prime)
    return -1 if residue == prime - 1 else residue


def _tonelli(value: int, prime: int) -> Optional[int]:
    value %= prime
    if value == 0:
        return 0
    if prime == 2 or _legendre(value, prime) != 1:
        return None
    if prime % 4 == 3:
        return pow(value, (prime + 1) // 4, prime)
    q, s = prime - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while _legendre(z, prime) != -1:
        z += 1
    root = pow(value, (q + 1) // 2, prime)
    current = pow(value, q, prime)
    factor = pow(z, q, prime)
    exponent = s
    while current != 1:
        i, probe = 0, current
        while probe != 1 and i < exponent:
            probe = probe * probe % prime
            i += 1
        if i == exponent:
            return None
        adjustment = pow(factor, 1 << (exponent - i - 1), prime)
        root = root * adjustment % prime
        current = current * adjustment * adjustment % prime
        factor = adjustment * adjustment % prime
        exponent = i
    return root


# ---------------------------------------------------------------------------
# Generic verified DLP helpers


def _bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise TypeError("group equality callback must return bool")
    return value


@dataclass(frozen=True)
class GroupOps:
    identity: Any
    combine: Callable[[Any, Any], Any]
    inverse: Callable[[Any], Any]
    equal: Callable[[Any, Any], bool] = lambda left, right: left == right
    encode: Callable[[Any], Any] = lambda value: value

    def same(self, left: Any, right: Any) -> bool:
        return _bool(self.equal(left, right))

    def power(self, base: Any, exponent: int) -> Any:
        if not _plain_int(exponent):
            raise TypeError("group exponent must be an integer")
        if exponent < 0:
            base, exponent = self.inverse(base), -exponent
        result = self.identity
        while exponent:
            if exponent & 1:
                result = self.combine(result, base)
            base = self.combine(base, base)
            exponent >>= 1
        return result


def multiplicative_group(prime: int) -> Optional[GroupOps]:
    if not _is_prime(prime):
        return None
    return GroupOps(
        1,
        lambda left, right: left * right % prime,
        lambda value: pow(value % prime, -1, prime),
        encode=lambda value: value % prime,
    )


def _has_exact_order(generator: Any, order: int, group: GroupOps) -> bool:
    factors = _factor_complete(order)
    if factors is None:
        return False
    try:
        if not group.same(group.power(generator, order), group.identity):
            return False
        return all(
            not group.same(group.power(generator, order // prime), group.identity)
            for prime in factors
        )
    except Exception:
        return False


def _element_order(generator: Any, multiple: int, group: GroupOps) -> Optional[int]:
    factors = _factor_complete(multiple)
    if factors is None:
        return None
    try:
        if not group.same(group.power(generator, multiple), group.identity):
            return None
        order = multiple
        for prime in factors:
            while order % prime == 0 and group.same(
                group.power(generator, order // prime), group.identity
            ):
                order //= prime
        return order if _has_exact_order(generator, order, group) else None
    except Exception:
        return None


def bounded_bsgs(
    generator: Any,
    target: Any,
    order: int,
    group: GroupOps,
    *,
    max_table: int = MAX_BSGS_TABLE,
) -> Optional[int]:
    """Bounded baby-step/giant-step with exact-order and final equality proofs."""

    if (
        not isinstance(group, GroupOps)
        or not _plain_int(order)
        or not (1 < order <= MAX_ORDER)
        or not _plain_int(max_table)
        or not (0 < max_table <= MAX_BSGS_TABLE)
        or not _has_exact_order(generator, order, group)
    ):
        return None
    try:
        if not group.same(group.power(target, order), group.identity):
            return None
        width = math.isqrt(order - 1) + 1
        if width > max_table:
            return None
        table: dict[Any, int] = {}
        value = group.identity
        for exponent in range(width):
            key = group.encode(value)
            try:
                hash(key)
            except TypeError:
                return None
            table.setdefault(key, exponent)
            value = group.combine(value, generator)
        stride = group.power(group.inverse(generator), width)
        giant = target
        candidates: set[int] = set()
        for index in range(width + 1):
            hit = table.get(group.encode(giant))
            if hit is not None:
                candidate = (index * width + hit) % order
                if group.same(group.power(generator, candidate), target):
                    candidates.add(candidate)
            giant = group.combine(giant, stride)
        return next(iter(candidates)) if len(candidates) == 1 else None
    except Exception:
        return None


def verified_pohlig_hellman(
    generator: Any,
    target: Any,
    order: int,
    group: GroupOps,
    *,
    max_prime_table: int = MAX_BSGS_TABLE,
) -> Optional[int]:
    """Pohlig--Hellman returning one scalar only after original-group replay."""

    factors = _factor_complete(order)
    if (
        factors is None
        or not _has_exact_order(generator, order, group)
        or not _plain_int(max_prime_table)
        or not (0 < max_prime_table <= MAX_BSGS_TABLE)
    ):
        return None
    try:
        if not group.same(group.power(target, order), group.identity):
            return None
        residues: list[tuple[int, int]] = []
        for prime, exponent in factors.items():
            prime_power = prime**exponent
            cofactor = order // prime_power
            reduced_generator = group.power(generator, cofactor)
            reduced_target = group.power(target, cofactor)
            digit_generator = group.power(reduced_generator, prime ** (exponent - 1))
            inverse_generator = group.inverse(reduced_generator)
            residue = 0
            for position in range(exponent):
                adjusted = group.combine(
                    reduced_target, group.power(inverse_generator, residue)
                )
                digit_target = group.power(adjusted, prime ** (exponent - 1 - position))
                digit = bounded_bsgs(
                    digit_generator,
                    digit_target,
                    prime,
                    group,
                    max_table=max_prime_table,
                )
                if digit is None:
                    return None
                residue += digit * prime**position
            residues.append((residue, prime_power))
        combined = (0, 1)
        for residue in residues:
            merged = _crt_merge(combined, residue)
            if merged is None:
                return None
            combined = merged
        candidate = combined[0] % order
        return candidate if group.same(group.power(generator, candidate), target) else None
    except Exception:
        return None


def bsgs_mod_prime(
    generator: int,
    target: int,
    prime: int,
    order: int,
    *,
    max_table: int = MAX_BSGS_TABLE,
) -> Optional[int]:
    group = multiplicative_group(prime)
    if group is None or not _plain_int(generator) or not _plain_int(target):
        return None
    return bounded_bsgs(generator % prime, target % prime, order, group, max_table=max_table)


def pohlig_hellman_mod_prime(
    generator: int,
    target: int,
    prime: int,
    order: int,
    *,
    max_prime_table: int = MAX_BSGS_TABLE,
) -> Optional[int]:
    group = multiplicative_group(prime)
    if group is None or not _plain_int(generator) or not _plain_int(target):
        return None
    return verified_pohlig_hellman(
        generator % prime,
        target % prime,
        order,
        group,
        max_prime_table=max_prime_table,
    )


def _smooth_exponents(value: int, factor_base: Sequence[int]) -> Optional[list[int]]:
    remaining = value
    exponents: list[int] = []
    for prime in factor_base:
        exponent = 0
        while remaining % prime == 0:
            remaining //= prime
            exponent += 1
        exponents.append(exponent)
    return exponents if remaining == 1 else None


def _solve_linear_prime(rows: list[list[int]], rhs: list[int], modulus: int) -> Optional[list[int]]:
    """Unique solution of a rectangular system over F_modulus."""

    if not _is_prime(modulus) or not rows or len(rows) != len(rhs):
        return None
    columns = len(rows[0])
    if columns == 0 or any(len(row) != columns for row in rows):
        return None
    matrix = [[value % modulus for value in row] + [answer % modulus] for row, answer in zip(rows, rhs)]
    pivot_row = 0
    pivots: list[int] = []
    for column in range(columns):
        pivot = next((row for row in range(pivot_row, len(matrix)) if matrix[row][column]), None)
        if pivot is None:
            continue
        matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
        inverse = pow(matrix[pivot_row][column], -1, modulus)
        matrix[pivot_row] = [value * inverse % modulus for value in matrix[pivot_row]]
        for row in range(len(matrix)):
            if row == pivot_row or matrix[row][column] == 0:
                continue
            factor = matrix[row][column]
            matrix[row] = [
                (left - factor * right) % modulus
                for left, right in zip(matrix[row], matrix[pivot_row])
            ]
        pivots.append(column)
        pivot_row += 1
        if pivot_row == len(matrix):
            break
    if len(pivots) != columns:
        return None
    if any(all(value == 0 for value in row[:-1]) and row[-1] for row in matrix):
        return None
    solution = [0] * columns
    for row, column in enumerate(pivots):
        solution[column] = matrix[row][-1]
    return solution


def toy_index_calculus(
    generator: int,
    target: int,
    prime: int,
    order: int,
    *,
    factor_base: Iterable[int] = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37),
    relation_limit: int = 4096,
) -> Optional[int]:
    """Small deterministic index-calculus demonstrator for a prime-order subgroup.

    Only factor-base primes that themselves lie in ``<generator>`` are used.
    Relation linear algebra is over the prime subgroup order, and the recovered
    logarithm is replayed before return.
    """

    if (
        not _is_prime(prime)
        or not _is_prime(order)
        or not _plain_int(generator)
        or not _plain_int(target)
        or (prime - 1) % order
        or not _plain_int(relation_limit)
        or not (1 <= relation_limit <= MAX_INDEX_RELATIONS)
    ):
        return None
    generator %= prime
    target %= prime
    if pow(generator, order, prime) != 1 or generator == 1 or pow(target, order, prime) != 1:
        return None
    try:
        base_iterator = iter(factor_base)
        supplied_bases = list(
            itertools.islice(base_iterator, MAX_INDEX_FACTOR_BASE + 1)
        )
    except Exception:
        return None
    if (
        len(supplied_bases) > MAX_INDEX_FACTOR_BASE
        or any(not _plain_int(base) for base in supplied_bases)
    ):
        return None
    bases = tuple(
        sorted(
            {
                int(base)
                for base in supplied_bases
                if _is_prime(int(base))
                and 1 < int(base) < prime
                and pow(int(base), order, prime) == 1
            }
        )
    )
    if not (2 <= len(bases) <= 32):
        return None
    rows: list[list[int]] = []
    answers: list[int] = []
    for exponent in range(1, min(order, relation_limit + 1)):
        smooth = _smooth_exponents(pow(generator, exponent, prime), bases)
        if smooth is not None:
            rows.append([value % order for value in smooth])
            answers.append(exponent % order)
    logs = _solve_linear_prime(rows, answers, order)
    if logs is None or any(pow(generator, log, prime) != base % prime for base, log in zip(bases, logs)):
        return None
    for shift in range(min(order, relation_limit + 1)):
        smooth = _smooth_exponents(target * pow(generator, shift, prime) % prime, bases)
        if smooth is None:
            continue
        candidate = (sum(exponent * log for exponent, log in zip(smooth, logs)) - shift) % order
        if pow(generator, candidate, prime) == target:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Elliptic arithmetic


ECPoint = Optional[tuple[int, int]]


def ec_on_curve(point: ECPoint, prime: int, a: int, b: int) -> bool:
    if point is None:
        return True
    return (
        isinstance(point, tuple)
        and len(point) == 2
        and all(_plain_int(value) for value in point)
        and 0 <= point[0] < prime
        and 0 <= point[1] < prime
        and (point[1] * point[1] - (point[0] ** 3 + a * point[0] + b)) % prime == 0
    )


def ec_add(left: ECPoint, right: ECPoint, prime: int, a: int) -> ECPoint:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % prime == 0:
        return None
    try:
        if left == right:
            slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, prime) % prime
        else:
            slope = (y2 - y1) * pow((x2 - x1) % prime, -1, prime) % prime
    except ValueError:
        return None
    x3 = (slope * slope - x1 - x2) % prime
    return x3, (slope * (x1 - x3) - y1) % prime


def ec_mul(scalar: int, point: ECPoint, prime: int, a: int) -> ECPoint:
    if not _plain_int(scalar) or point is None or scalar == 0:
        return None
    if scalar < 0:
        point, scalar = (point[0], -point[1] % prime), -scalar
    result: ECPoint = None
    addend = point
    while scalar:
        if scalar & 1:
            result = ec_add(result, addend, prime, a)
        addend = ec_add(addend, addend, prime, a)
        scalar >>= 1
    return result


def elliptic_group(prime: int, a: int) -> GroupOps:
    return GroupOps(
        None,
        lambda left, right: ec_add(left, right, prime, a),
        lambda point: None if point is None else (point[0], -point[1] % prime),
    )


# ---------------------------------------------------------------------------
# Singular curves: cusp, split node, and non-split node


class QuadraticField:
    """F_p[t]/(t^2-non_residue), used by non-split nodal curves."""

    def __init__(self, prime: int, non_residue: int):
        if not _is_prime(prime) or _legendre(non_residue, prime) != -1:
            raise ValueError("quadratic parameter must be a non-residue")
        self.p = prime
        self.nr = non_residue % prime
        self.zero = (0, 0)
        self.one = (1, 0)

    def val(self, value: Any) -> tuple[int, int]:
        if isinstance(value, (tuple, list)) and len(value) == 2:
            if not all(_plain_int(coefficient) for coefficient in value):
                raise TypeError("quadratic-field coefficients must be integers")
            return value[0] % self.p, value[1] % self.p
        if not _plain_int(value):
            raise TypeError("quadratic-field value must be an integer or coefficient pair")
        return value % self.p, 0

    def add(self, left: Any, right: Any) -> tuple[int, int]:
        left, right = self.val(left), self.val(right)
        return (left[0] + right[0]) % self.p, (left[1] + right[1]) % self.p

    def sub(self, left: Any, right: Any) -> tuple[int, int]:
        left, right = self.val(left), self.val(right)
        return (left[0] - right[0]) % self.p, (left[1] - right[1]) % self.p

    def mul(self, left: Any, right: Any) -> tuple[int, int]:
        left, right = self.val(left), self.val(right)
        return (
            (left[0] * right[0] + self.nr * left[1] * right[1]) % self.p,
            (left[0] * right[1] + left[1] * right[0]) % self.p,
        )

    def inverse(self, value: Any) -> tuple[int, int]:
        value = self.val(value)
        denominator = (value[0] * value[0] - self.nr * value[1] * value[1]) % self.p
        if denominator == 0:
            raise ZeroDivisionError("quadratic-field inverse of zero")
        inverse = pow(denominator, -1, self.p)
        return value[0] * inverse % self.p, -value[1] * inverse % self.p


def _valid_curve_inputs(prime: int, a: int, b: int, generator: Any, target: Any) -> Optional[tuple[tuple[int, int], tuple[int, int]]]:
    if (
        not _is_prime(prime)
        or prime <= 3
        or not _plain_int(a)
        or not _plain_int(b)
    ):
        return None
    if not (
        isinstance(generator, (tuple, list))
        and len(generator) == 2
        and isinstance(target, (tuple, list))
        and len(target) == 2
        and all(_plain_int(value) for value in generator)
        and all(_plain_int(value) for value in target)
    ):
        return None
    g = (generator[0] % prime, generator[1] % prime)
    h = (target[0] % prime, target[1] % prime)
    return (g, h) if ec_on_curve(g, prime, a % prime, b % prime) and ec_on_curve(h, prime, a % prime, b % prime) else None


def recover_singular_curve_dlp(
    prime: int,
    a: int,
    b: int,
    generator: Any,
    target: Any,
    *,
    max_prime_table: int = MAX_BSGS_TABLE,
) -> Optional[int]:
    """Recover a DLP on a singular cusp or split/non-split node."""

    parsed = _valid_curve_inputs(prime, a, b, generator, target)
    if parsed is None:
        return None
    a, b = a % prime, b % prime
    if (4 * pow(a, 3, prime) + 27 * pow(b, 2, prime)) % prime:
        return None
    generator, target = parsed
    if a == 0 and b == 0:
        if generator == (0, 0) or target == (0, 0) or generator[1] == 0 or target[1] == 0:
            return None
        parameter_g = generator[0] * pow(generator[1], -1, prime) % prime
        parameter_h = target[0] * pow(target[1], -1, prime) % prime
        if parameter_g == 0:
            return None
        scalar = parameter_h * pow(parameter_g, -1, prime) % prime
        return scalar if ec_mul(scalar, generator, prime, a) == target else None

    try:
        alpha = -3 * b * pow(2 * a, -1, prime) % prime
    except ValueError:
        return None
    if (3 * alpha * alpha + a) % prime or (alpha**3 + a * alpha + b) % prime:
        return None
    singular_point = (alpha, 0)
    if generator == singular_point or target == singular_point:
        return None
    c = 3 * alpha % prime
    split_root = _tonelli(c, prime)
    if split_root is not None:
        field: Any = None

        def parameter(point: tuple[int, int]) -> Optional[int]:
            translated = (point[0] - alpha) % prime
            numerator = (point[1] + split_root * translated) % prime
            denominator = (point[1] - split_root * translated) % prime
            if denominator == 0:
                return None
            return numerator * pow(denominator, -1, prime) % prime

        parameter_g, parameter_h = parameter(generator), parameter(target)
        if parameter_g in (None, 0) or parameter_h in (None, 0):
            return None
        group = multiplicative_group(prime)
        group_multiple = prime - 1
    else:
        try:
            field = QuadraticField(prime, c)
        except ValueError:
            return None
        root = (0, 1)

        def parameter(point: tuple[int, int]) -> Optional[tuple[int, int]]:
            translated = (point[0] - alpha) % prime
            term = field.mul(root, translated)
            numerator = field.add(point[1], term)
            denominator = field.sub(point[1], term)
            try:
                return field.mul(numerator, field.inverse(denominator))
            except ZeroDivisionError:
                return None

        parameter_g, parameter_h = parameter(generator), parameter(target)
        if parameter_g in (None, field.zero) or parameter_h in (None, field.zero):
            return None
        group = GroupOps(field.one, field.mul, field.inverse)
        group_multiple = prime + 1
    if group is None:
        return None
    order = _element_order(parameter_g, group_multiple, group)
    if order is None:
        return None
    scalar = verified_pohlig_hellman(
        parameter_g,
        parameter_h,
        order,
        group,
        max_prime_table=max_prime_table,
    )
    return scalar if scalar is not None and ec_mul(scalar, generator, prime, a) == target else None


# ---------------------------------------------------------------------------
# Anomalous curves / Smart attack


def recover_anomalous_smart(
    prime: int,
    a: int,
    b: int,
    generator: Any,
    target: Any,
    *,
    deadline_seconds: float = 5.0,
) -> Optional[int]:
    """Smart attack with order-p and final public-point verification."""

    parsed = _valid_curve_inputs(prime, a, b, generator, target)
    if parsed is None:
        return None
    a, b = a % prime, b % prime
    if (
        isinstance(deadline_seconds, bool)
        or not isinstance(deadline_seconds, (int, float))
        or not (0 < deadline_seconds <= 30)
        or (4 * pow(a, 3, prime) + 27 * pow(b, 2, prime)) % prime == 0
    ):
        return None
    generator, target = parsed
    # Since p is prime, these checks prove both nonidentity points have order p.
    if ec_mul(prime, generator, prime, a) is not None or ec_mul(prime, target, prime, a) is not None:
        return None
    if generator is None or target is None:
        return None
    # For small fixtures independently count #E; for large p, a point of order p
    # and Hasse's bound (p > 5) force #E(F_p)=p.
    if prime <= 4096:
        count = 1
        for x in range(prime):
            rhs = (x**3 + a * x + b) % prime
            count += 1 if rhs == 0 else 2 if _legendre(rhs, prime) == 1 else 0
        if count != prime:
            return None
    try:
        scalar = _ecc._smart_scalar(
            prime, a, b, generator, target, time.monotonic() + float(deadline_seconds)
        )
    except Exception:
        return None
    if not _plain_int(scalar):
        return None
    scalar %= prime
    return scalar if ec_mul(scalar, generator, prime, a) == target else None


# ---------------------------------------------------------------------------
# Quadratic-twist transcripts and CRT recovery


@dataclass(frozen=True)
class TwistObservation:
    prime: int
    a: int
    b: int
    twist_nonresidue: int
    point: tuple[int, int]
    response: ECPoint
    order: int


def recover_quadratic_twist_residue(observation: TwistObservation) -> Optional[tuple[int, int]]:
    """Recover and replay one residue from an explicitly related quadratic twist."""

    if not isinstance(observation, TwistObservation):
        return None
    p, a, b, d, order = (
        observation.prime,
        observation.a,
        observation.b,
        observation.twist_nonresidue,
        observation.order,
    )
    if (
        not _is_prime(p)
        or p <= 3
        or not _plain_int(a)
        or not _plain_int(b)
        or not _plain_int(d)
        or _legendre(d, p) != -1
        or not _plain_int(order)
        or not (1 < order <= MAX_ORDER)
        or (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p == 0
    ):
        return None
    twist_a, twist_b = a * d * d % p, b * d * d * d % p
    if not (
        isinstance(observation.point, (tuple, list))
        and len(observation.point) == 2
        and all(_plain_int(value) for value in observation.point)
    ):
        return None
    if observation.response is not None and not (
        isinstance(observation.response, (tuple, list))
        and len(observation.response) == 2
        and all(_plain_int(value) for value in observation.response)
    ):
        return None
    point = (observation.point[0] % p, observation.point[1] % p)
    response = None if observation.response is None else (
        observation.response[0] % p,
        observation.response[1] % p,
    )
    if not ec_on_curve(point, p, twist_a, twist_b) or not ec_on_curve(response, p, twist_a, twist_b):
        return None
    group = elliptic_group(p, twist_a)
    if not _has_exact_order(point, order, group):
        return None
    scalar = verified_pohlig_hellman(point, response, order, group)
    if scalar is None or ec_mul(scalar, point, p, twist_a) != response:
        return None
    return scalar, order


def recover_quadratic_twist_private_scalar(
    observations: Iterable[TwistObservation],
    prime: int,
    a: int,
    b: int,
    generator: Any,
    public_key: Any,
    group_order: int,
    *,
    max_candidates: int = MAX_CRT_CANDIDATES,
) -> Optional[int]:
    """CRT-combine twist residues, then require ``[d]G == Q`` on the real curve."""

    parsed = _valid_curve_inputs(prime, a, b, generator, public_key)
    if (
        parsed is None
        or not _plain_int(group_order)
        or not (2 < group_order <= MAX_ORDER)
        or not _plain_int(max_candidates)
        or not (0 < max_candidates <= MAX_CRT_CANDIDATES)
        or (4 * pow(a, 3, prime) + 27 * pow(b, 2, prime)) % prime == 0
    ):
        return None
    generator, public_key = parsed
    real_group = elliptic_group(prime, a % prime)
    if not _has_exact_order(generator, group_order, real_group):
        return None
    try:
        iterator = iter(observations)
        rows = list(itertools.islice(iterator, MAX_TWIST_OBSERVATIONS + 1))
    except Exception:
        return None
    if not rows or len(rows) > MAX_TWIST_OBSERVATIONS:
        return None
    combined = (0, 1)
    for observation in rows:
        residue = recover_quadratic_twist_residue(observation)
        if residue is None:
            return None
        merged = _crt_merge(combined, residue)
        if merged is None:
            return None
        combined = merged
    residue, modulus = combined
    first = residue if residue else modulus
    if first >= group_order:
        return None
    count = 1 + (group_order - 1 - first) // modulus
    if count > max_candidates:
        return None
    matches = [
        candidate
        for candidate in range(first, group_order, modulus)
        if ec_mul(candidate, generator, prime, a % prime) == public_key
        and all(
            ec_mul(
                candidate,
                observation.point,
                observation.prime,
                observation.a * observation.twist_nonresidue**2 % observation.prime,
            )
            == observation.response
            for observation in rows
        )
    ]
    return matches[0] if len(matches) == 1 else None


# ---------------------------------------------------------------------------
# Extension fields and pairing/MOV helpers


class ExtensionField:
    """Bounded checked polynomial-basis F_(p^k), backed by the exact in-repo field."""

    def __init__(self, prime: int, degree: int, modulus: Sequence[int]):
        if (
            not _is_prime(prime)
            or not _plain_int(degree)
            or not (2 <= degree <= MAX_EXTENSION_DEGREE)
            or prime.bit_length() * degree > MAX_EXTENSION_BITS
        ):
            raise ValueError("extension field exceeds verified bounds")
        if (
            not isinstance(modulus, (tuple, list))
            or len(modulus) != degree + 1
            or any(not _plain_int(coefficient) for coefficient in modulus)
        ):
            raise ValueError("extension modulus must be a bounded integer sequence")
        self.p = prime
        self.degree = degree
        self._field = _ecc._FpK(prime, degree, modulus)
        self.zero = self._field.val(0)
        self.one = self._field.val(1)

    def val(self, value: Any) -> tuple[int, ...]:
        if isinstance(value, (tuple, list)):
            if len(value) > self.degree or any(
                not _plain_int(coefficient) for coefficient in value
            ):
                raise TypeError("extension-field coefficients must be integers")
        elif not _plain_int(value):
            raise TypeError("extension-field value must be an integer or coefficient sequence")
        return self._field.val(value)

    def add(self, left: Any, right: Any) -> tuple[int, ...]:
        return self._field.add(left, right)

    def sub(self, left: Any, right: Any) -> tuple[int, ...]:
        return self._field.sub(left, right)

    def mul(self, left: Any, right: Any) -> tuple[int, ...]:
        return self._field.mul(left, right)

    def inverse(self, value: Any) -> tuple[int, ...]:
        return self._field.inv(value)

    def power(self, value: Any, exponent: int) -> tuple[int, ...]:
        if not _plain_int(exponent):
            raise TypeError("extension-field exponent must be an integer")
        return self._field.pow(value, exponent)

    def group(self) -> GroupOps:
        return GroupOps(self.one, self.mul, self.inverse, encode=self.val)


def embedding_degree(prime: int, subgroup_order: int, *, max_degree: int = 64) -> Optional[int]:
    if (
        not _is_prime(prime)
        or not _plain_int(subgroup_order)
        or subgroup_order <= 1
        or math.gcd(prime, subgroup_order) != 1
        or not _plain_int(max_degree)
        or not (1 <= max_degree <= 64)
    ):
        return None
    value = 1
    for degree in range(1, max_degree + 1):
        value = value * (prime % subgroup_order) % subgroup_order
        if value == 1:
            return degree
    return None


def analyze_pairing_weak_parameters(
    prime: int,
    subgroup_order: int,
    *,
    claimed_embedding: Optional[int] = None,
    max_embedding: int = 12,
    max_field_bits: int = MAX_EXTENSION_BITS,
) -> Optional[dict[str, Any]]:
    """Return a verified low-embedding warning, never an unverified scalar."""

    if (
        not _is_prime(prime)
        or not _is_prime(subgroup_order)
        or not _plain_int(max_embedding)
        or not (1 <= max_embedding <= 64)
        or not _plain_int(max_field_bits)
        or max_field_bits <= 0
    ):
        return None
    if claimed_embedding is not None and not _plain_int(claimed_embedding):
        return None
    degree = embedding_degree(prime, subgroup_order, max_degree=max_embedding)
    if degree is None or (claimed_embedding is not None and claimed_embedding != degree):
        return None
    field_bits = (pow(prime, degree) - 1).bit_length()
    if field_bits > max_field_bits or (pow(prime, degree) - 1) % subgroup_order:
        return None
    return {
        "embedding_degree": degree,
        "extension_field_bits": field_bits,
        "subgroup_bits": subgroup_order.bit_length(),
        "verified": True,
    }


def recover_pairing_transcript_dlp(
    prime: int,
    embedding: int,
    extension_modulus: Sequence[int],
    subgroup_order: int,
    source_generator: Any,
    source_target: Any,
    source_group: GroupOps,
    auxiliary: Any,
    pairing_evaluator: Callable[[Any, Any], Any],
    *,
    auxiliary_group: Optional[GroupOps] = None,
    max_prime_table: int = MAX_BSGS_TABLE,
) -> Optional[int]:
    """Recover a source DLP from a checked higher-embedding pairing transcript."""

    auxiliary_group = source_group if auxiliary_group is None else auxiliary_group
    if (
        not callable(pairing_evaluator)
        or embedding_degree(prime, subgroup_order, max_degree=embedding) != embedding
        or not _has_exact_order(source_generator, subgroup_order, source_group)
        or not _has_exact_order(auxiliary, subgroup_order, auxiliary_group)
    ):
        return None
    try:
        field = ExtensionField(prime, embedding, extension_modulus)
        field_group = field.group()
        base = field.val(pairing_evaluator(source_generator, auxiliary))
        target = field.val(pairing_evaluator(source_target, auxiliary))
        if base == field.zero or target == field.zero:
            return None
        if not _has_exact_order(base, subgroup_order, field_group):
            return None
        # Transcript-level non-degeneracy and bilinearity checks.  The final
        # source-group replay below remains authoritative even for a bad callback.
        for scalar in (0, 2, 3):
            source_point = source_group.power(source_generator, scalar)
            paired = field.val(pairing_evaluator(source_point, auxiliary))
            if paired != field.power(base, scalar):
                return None
            auxiliary_point = auxiliary_group.power(auxiliary, scalar)
            paired_auxiliary = field.val(
                pairing_evaluator(source_generator, auxiliary_point)
            )
            if paired_auxiliary != field.power(base, scalar):
                return None
        scalar = verified_pohlig_hellman(
            base,
            target,
            subgroup_order,
            field_group,
            max_prime_table=max_prime_table,
        )
        if scalar is None:
            return None
        if field.power(base, scalar) != target:
            return None
        if not source_group.same(source_group.power(source_generator, scalar), source_target):
            return None
        return scalar
    except Exception:
        return None


def recover_mov_frey_ruck(
    prime: int,
    a: int,
    b: int,
    generator: Any,
    target: Any,
    subgroup_order: int,
    **kwargs: Any,
) -> Optional[int]:
    """Strict scalar-only wrapper around the in-repo Miller/MOV implementation."""

    parsed = _valid_curve_inputs(prime, a, b, generator, target)
    if parsed is None or not _plain_int(subgroup_order) or not (1 < subgroup_order <= MAX_ORDER):
        return None
    generator, target = parsed
    group = elliptic_group(prime, a % prime)
    if not _has_exact_order(generator, subgroup_order, group):
        return None
    supplied_embedding = kwargs.get("embedding")
    minimal = embedding_degree(prime, subgroup_order, max_degree=64)
    if minimal is None or (supplied_embedding is not None and supplied_embedding != minimal):
        return None
    try:
        result = _ecc.mov_frey_ruck_recover(
            prime, a, b, generator, target, subgroup_order, **kwargs
        )
    except Exception:
        return None
    if not isinstance(result, dict) or result.get("verified") is not True:
        return None
    scalar = result.get("scalar")
    if not _plain_int(scalar) or result.get("embedding_degree") != minimal:
        return None
    return scalar if ec_mul(scalar, generator, prime, a % prime) == target else None


# ---------------------------------------------------------------------------
# Toy isogeny transcript and weak-path analyzers


@dataclass(frozen=True)
class IsogenyTranscript:
    degree: int
    domain_order: int
    codomain_order: int
    kernel_generator: Any
    domain_group: GroupOps
    codomain_group: GroupOps
    point_map: Callable[[Any], Any]
    image_witness: Any
    homomorphism_samples: Sequence[tuple[Any, Any]]


def validate_isogeny_transcript(transcript: IsogenyTranscript) -> Optional[dict[str, Any]]:
    """Validate a finite cyclic-kernel isogeny-like homomorphism transcript."""

    if not isinstance(transcript, IsogenyTranscript):
        return None
    degree = transcript.degree
    try:
        sample_iterator = iter(transcript.homomorphism_samples)
        samples = list(itertools.islice(sample_iterator, 65))
    except Exception:
        return None
    sample_count = len(samples)
    if (
        not _plain_int(degree)
        or not (1 < degree <= MAX_ORDER)
        or not _plain_int(transcript.domain_order)
        or not _plain_int(transcript.codomain_order)
        or not (1 < transcript.domain_order <= MAX_ORDER)
        or not (0 < transcript.codomain_order <= MAX_ORDER)
        or transcript.domain_order != degree * transcript.codomain_order
        or sample_count < 3
        or sample_count > 64
        or not callable(transcript.point_map)
        or not _has_exact_order(transcript.kernel_generator, degree, transcript.domain_group)
    ):
        return None
    try:
        if not transcript.codomain_group.same(
            transcript.point_map(transcript.domain_group.identity),
            transcript.codomain_group.identity,
        ):
            return None
        if not transcript.codomain_group.same(
            transcript.point_map(transcript.kernel_generator),
            transcript.codomain_group.identity,
        ):
            return None
        mapped_witness = transcript.point_map(transcript.image_witness)
        if not _has_exact_order(
            mapped_witness, transcript.codomain_order, transcript.codomain_group
        ):
            return None
        seen_samples: set[Any] = set()
        for left, right in samples:
            sample_key = (
                transcript.domain_group.encode(left),
                transcript.domain_group.encode(right),
            )
            hash(sample_key)
            if sample_key in seen_samples:
                return None
            seen_samples.add(sample_key)
            mapped_sum = transcript.point_map(transcript.domain_group.combine(left, right))
            sum_mapped = transcript.codomain_group.combine(
                transcript.point_map(left), transcript.point_map(right)
            )
            if not transcript.codomain_group.same(mapped_sum, sum_mapped):
                return None
        return {
            "degree": degree,
            "kernel_order": degree,
            "domain_order": transcript.domain_order,
            "codomain_order": transcript.codomain_order,
            "verified": True,
        }
    except Exception:
        return None


@dataclass(frozen=True)
class IsogenyPath:
    nodes: tuple[Any, ...]
    degrees: tuple[int, ...]
    degree_product: int
    verified: bool = True


def recover_unique_small_degree_isogeny_path(
    source: Any,
    target: Any,
    neighbors: Callable[[Any], Iterable[tuple[Any, int, Any]]],
    edge_validator: Callable[[Any, Any, int, Any], bool],
    *,
    max_depth: int = 8,
    max_degree: int = 13,
    max_nodes: int = MAX_ISOGENY_NODES,
) -> Optional[IsogenyPath]:
    """Bounded BFS returning only one uniquely proven shortest small-degree path."""

    if (
        not callable(neighbors)
        or not callable(edge_validator)
        or not _plain_int(max_depth)
        or not (1 <= max_depth <= 32)
        or not _plain_int(max_degree)
        or not (2 <= max_degree <= 64)
        or not _plain_int(max_nodes)
        or not (1 <= max_nodes <= MAX_ISOGENY_NODES)
    ):
        return None
    if source == target:
        return None
    queue = deque([(source, (source,), (), ())])
    shortest: Optional[int] = None
    solutions: list[tuple[tuple[Any, ...], tuple[int, ...], tuple[Any, ...]]] = []
    visited_depth: dict[Any, int] = {}
    explored = 0
    try:
        while queue:
            node, path, degrees, proofs = queue.popleft()
            depth = len(degrees)
            if shortest is not None and depth > shortest:
                break
            if node == target:
                shortest = depth
                solutions.append((path, degrees, proofs))
                if len(solutions) > 1:
                    return None
                continue
            if depth >= max_depth:
                continue
            previous = visited_depth.get(node)
            if previous is not None and previous < depth:
                continue
            visited_depth[node] = depth
            edges = list(itertools.islice(iter(neighbors(node)), max_nodes + 1))
            if len(edges) > max_nodes:
                return None
            for next_node, degree, proof in edges:
                explored += 1
                if explored > max_nodes or not _plain_int(degree) or not (2 <= degree <= max_degree):
                    return None
                verdict = edge_validator(node, next_node, degree, proof)
                if not isinstance(verdict, bool) or not verdict:
                    continue
                if next_node in path:
                    continue
                queue.append((next_node, path + (next_node,), degrees + (degree,), proofs + (proof,)))
    except Exception:
        return None
    if len(solutions) != 1:
        return None
    path, degrees, proofs = solutions[0]
    try:
        for left, right, degree, proof in zip(path, path[1:], degrees, proofs):
            verdict = edge_validator(left, right, degree, proof)
            if not isinstance(verdict, bool) or not verdict:
                return None
    except Exception:
        return None
    return IsogenyPath(path, degrees, math.prod(degrees), True)


__all__ = [
    "ExtensionField",
    "GroupOps",
    "IsogenyPath",
    "IsogenyTranscript",
    "QuadraticField",
    "TwistObservation",
    "analyze_pairing_weak_parameters",
    "bounded_bsgs",
    "bsgs_mod_prime",
    "ec_add",
    "ec_mul",
    "ec_on_curve",
    "elliptic_group",
    "embedding_degree",
    "multiplicative_group",
    "pohlig_hellman_mod_prime",
    "recover_anomalous_smart",
    "recover_mov_frey_ruck",
    "recover_pairing_transcript_dlp",
    "recover_quadratic_twist_private_scalar",
    "recover_quadratic_twist_residue",
    "recover_singular_curve_dlp",
    "recover_unique_small_degree_isogeny_path",
    "toy_index_calculus",
    "validate_isogeny_transcript",
    "verified_pohlig_hellman",
]
