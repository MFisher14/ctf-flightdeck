#!/usr/bin/env python3
"""Small, reusable lattice/CVP, small-root, ACD, and knapsack primitives.

The module builds on :func:`rsa_lattice.lll`, the repository's exact-integer LLL reducer.  Babai's
nearest-plane algorithm uses exact :class:`fractions.Fraction` Gram--Schmidt arithmetic, avoiding
the silent precision failures that large CTF coordinates cause with floats.  Knapsack recovery uses
a bounded exact meet-in-the-middle pass where possible, then a classic LLL embedding; a bit vector is
returned only when its weighted sum exactly equals the target.  Merkle--Hellman recovery additionally
checks the private sequence, modular inverse, and public-ciphertext round trip.

The multivariate small-root helper accepts an arbitrary supplied sparse integer polynomial and builds
bounded Howgrave--Graham shifts on the in-repo exact LLL.  It is deliberately a practical CTF helper,
not a claim that arbitrary polynomial ideals are solved: up to sixteen variables are accepted under a
strict 72-column lattice cap, reduced relations are used only when the Howgrave--Graham norm condition
holds, and every returned tuple is checked in the original congruence.  Tiny boxes may use an explicit
bounded enumeration fallback after LLL; the selected method is available from the detailed API.

The approximate-common-divisor helper uses a simultaneous-approximation lattice to recover quotient
relations, then optionally a bounded two-noise exact fallback.  A divisor is returned only with exact
quotients/noises whose absolute noise is within the caller's bound.

This is pure offline computation: no files are interpreted as code and no networking is present.
The CLI accepts a bounded JSON object for ``cvp``, ``small-roots``, ``acd``, ``subset-sum``, or
``merkle-hellman``.
"""
from __future__ import annotations

import argparse
import itertools
import json
import math
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path

from rsa_lattice import lll


MAX_DIMENSION = 256
MAX_COORD_BITS = 8192
MAX_JSON_BYTES = 1 << 20
MAX_MITM_STATES = 1 << 20
MAX_VARIABLES = 16
MAX_POLY_TERMS = 128
MAX_TOTAL_DEGREE = 8
MAX_HG_DIMENSION = 72
MAX_HG_COORD_BITS = 32_768
MAX_ROOT_ENUMERATION = 1_000_000
MAX_ROOT_PROJECTION = 100_000
MAX_ROOT_CANDIDATES = 256
MAX_ACD_SAMPLES = 64
MAX_ACD_NOISE_PAIRS = 1_000_000
MAX_ACD_RESULTS = 64
MAX_ACD_LATTICE_SAMPLES = 12


@dataclass(frozen=True)
class CVPResult:
    """Babai output relative to the (possibly LLL-reduced) basis."""

    vector: tuple[int, ...]
    coefficients: tuple[int, ...]
    squared_distance: int
    reduced_basis: tuple[tuple[int, ...], ...]


@dataclass(frozen=True)
class SmallRootsResult:
    """Verified roots plus bounded lattice diagnostics."""

    roots: tuple[tuple[int, ...], ...]
    methods: tuple[str, ...]
    lattice_rows: int
    lattice_columns: int
    certified_relations: int


@dataclass(frozen=True)
class ACDResult:
    """One exact approximate-common-divisor explanation."""

    divisor: int
    quotients: tuple[int, ...]
    noises: tuple[int, ...]
    method: str


def _integer_vector(value, name: str) -> list[int]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError(f"{name} must be a non-empty integer vector")
    out = []
    for coordinate in value:
        if isinstance(coordinate, bool) or not isinstance(coordinate, int):
            raise ValueError(f"{name} coordinates must be integers")
        if coordinate.bit_length() > MAX_COORD_BITS:
            raise ValueError(f"{name} coordinate exceeds {MAX_COORD_BITS}-bit cap")
        out.append(coordinate)
    return out


def _basis(value) -> list[list[int]]:
    if not isinstance(value, (list, tuple)) or not value or len(value) > MAX_DIMENSION:
        raise ValueError(f"basis must have 1..{MAX_DIMENSION} rows")
    rows = [_integer_vector(row, "basis row") for row in value]
    width = len(rows[0])
    if width > MAX_DIMENSION or any(len(row) != width for row in rows):
        raise ValueError("basis must be rectangular and bounded")
    if len(rows) > width:
        raise ValueError("basis has more rows than ambient dimension")
    return rows


def _dot(left, right):
    return sum(a * b for a, b in zip(left, right))


def _nearest_integer(value: Fraction) -> int:
    """Round a fraction to nearest integer, with ties away from zero."""
    if value >= 0:
        return (2 * value.numerator + value.denominator) // (2 * value.denominator)
    return -_nearest_integer(-value)


def closest_vector(
    basis,
    target,
    *,
    reduce: bool = True,
    delta: tuple[int, int] = (99, 100),
    deadline: float | None = None,
) -> CVPResult | None:
    """Babai nearest-plane approximation to CVP.

    ``basis`` contains row vectors.  If ``reduce`` is true (the default), exact LLL is applied first.
    ``None`` means the deadline expired or LLL rejected a dependent basis.  The result records the
    reduced basis and coefficients so callers can independently check the lattice membership.
    """
    rows = _basis(basis)
    target_i = _integer_vector(target, "target")
    if len(target_i) != len(rows[0]):
        raise ValueError("target dimension does not match basis")
    if deadline is not None and time.monotonic() > deadline:
        return None
    work = lll(rows, delta=delta, deadline=deadline) if reduce else [row[:] for row in rows]
    if work is None:
        return None

    stars: list[list[Fraction]] = []
    norms: list[Fraction] = []
    for row in work:
        star = [Fraction(x) for x in row]
        for previous, norm in zip(stars, norms):
            coefficient = _dot(row, previous) / norm
            star = [x - coefficient * y for x, y in zip(star, previous)]
        norm = _dot(star, star)
        if norm == 0:
            return None
        stars.append(star)
        norms.append(norm)

    residual = [Fraction(x) for x in target_i]
    coefficients = [0] * len(work)
    for i in range(len(work) - 1, -1, -1):
        coefficient = _nearest_integer(_dot(residual, stars[i]) / norms[i])
        coefficients[i] = coefficient
        residual = [x - coefficient * y for x, y in zip(residual, work[i])]
    vector = tuple(sum(coefficients[i] * work[i][j] for i in range(len(work)))
                   for j in range(len(target_i)))
    distance = sum((a - b) ** 2 for a, b in zip(vector, target_i))
    return CVPResult(vector, tuple(coefficients), distance,
                     tuple(tuple(row) for row in work))


# ---- bounded multivariate Howgrave--Graham ----------------------------------------------

SparsePolynomial = dict[tuple[int, ...], int]


def _bounded_integer(value, name: str, *, bits: int = MAX_COORD_BITS) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value.bit_length() > bits:
        raise ValueError(f"{name} exceeds {bits}-bit cap")
    return value


def _normalise_bounds(bounds) -> tuple[tuple[tuple[int, int], ...], tuple[int, ...]]:
    """Return inclusive ranges and absolute monomial scales.

    A positive integer ``X`` denotes ``-X <= x <= X``.  A two-item sequence denotes an explicit
    inclusive ``[low, high]`` range.  Explicit ranges are useful for non-negative unknown chunks.
    """
    if (not isinstance(bounds, Sequence) or isinstance(bounds, (str, bytes)) or not bounds
            or len(bounds) > MAX_VARIABLES):
        raise ValueError(f"bounds must describe 1..{MAX_VARIABLES} variables")
    ranges: list[tuple[int, int]] = []
    scales: list[int] = []
    for index, bound in enumerate(bounds):
        if isinstance(bound, int) and not isinstance(bound, bool):
            extent = _bounded_integer(bound, f"bounds[{index}]")
            if extent <= 0:
                raise ValueError("integer bounds must be positive")
            low, high = -extent, extent
        elif (isinstance(bound, Sequence) and not isinstance(bound, (str, bytes))
              and len(bound) == 2):
            low = _bounded_integer(bound[0], f"bounds[{index}][0]")
            high = _bounded_integer(bound[1], f"bounds[{index}][1]")
            if low > high:
                raise ValueError("explicit bounds must be ordered")
        else:
            raise ValueError("each bound must be a positive integer or [low, high]")
        ranges.append((low, high))
        scales.append(max(1, abs(low), abs(high)))
    return tuple(ranges), tuple(scales)


def _exponents(value, variables: int) -> tuple[int, ...]:
    if isinstance(value, int) and not isinstance(value, bool) and variables == 1:
        raw = (value,)
    elif isinstance(value, str):
        token = value.strip()
        if token[:1] in "([" and token[-1:] in ")]":
            token = token[1:-1]
        if not token or len(token) > 128:
            raise ValueError("invalid polynomial exponent key")
        try:
            raw = tuple(int(piece.strip(), 10) for piece in token.split(","))
        except ValueError as exc:
            raise ValueError("polynomial exponent keys must be comma-separated integers") from exc
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        raw = tuple(value)
    else:
        raise ValueError("polynomial exponents must be a tuple/list (or comma-separated JSON key)")
    if len(raw) != variables:
        raise ValueError("polynomial exponent width does not match bounds")
    out = []
    for exponent in raw:
        if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 0:
            raise ValueError("polynomial exponents must be non-negative integers")
        out.append(exponent)
    if sum(out) > MAX_TOTAL_DEGREE:
        raise ValueError(f"input polynomial total degree exceeds {MAX_TOTAL_DEGREE}")
    return tuple(out)


def _normalise_polynomial(value, variables: int) -> SparsePolynomial:
    """Parse the public sparse representation without evaluating source text.

    Accepted forms are ``{exponent_tuple: coefficient}``, a list of
    ``(exponent_tuple, coefficient)`` pairs, or JSON-friendly dictionaries with ``powers`` (or
    ``exponents``) and ``coefficient`` (or ``coeff``).  A dense integer list is also accepted for a
    univariate polynomial, lowest coefficient first.
    """
    if isinstance(value, (Mapping, Sequence)) and not isinstance(value, (str, bytes)):
        if not 1 <= len(value) <= MAX_POLY_TERMS:
            raise ValueError(f"polynomial must have 1..{MAX_POLY_TERMS} supplied terms")
    if isinstance(value, Mapping):
        items = list(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if variables == 1 and value and all(isinstance(item, int) and not isinstance(item, bool)
                                             for item in value):
            items = [((degree,), coefficient) for degree, coefficient in enumerate(value)]
        else:
            items = []
            for term in value:
                if isinstance(term, Mapping):
                    powers = term.get("powers", term.get("exponents"))
                    coefficient = term.get("coefficient", term.get("coeff"))
                    if powers is None or coefficient is None:
                        raise ValueError("polynomial term needs powers/exponents and coefficient")
                    items.append((powers, coefficient))
                elif (isinstance(term, Sequence) and not isinstance(term, (str, bytes))
                      and len(term) == 2):
                    items.append((term[0], term[1]))
                else:
                    raise ValueError("invalid sparse polynomial term")
    else:
        raise ValueError("polynomial must be a sparse mapping/term list")
    polynomial: SparsePolynomial = {}
    for powers, coefficient in items:
        exponent = _exponents(powers, variables)
        number = _bounded_integer(coefficient, "polynomial coefficient")
        polynomial[exponent] = polynomial.get(exponent, 0) + number
        if polynomial[exponent] == 0:
            del polynomial[exponent]
    if not polynomial:
        raise ValueError("polynomial is identically zero")
    if max(map(sum, polynomial)) == 0:
        raise ValueError("polynomial must have positive degree")
    return polynomial


def _poly_multiply(left: SparsePolynomial, right: SparsePolynomial, *, term_cap: int) -> SparsePolynomial:
    product: SparsePolynomial = {}
    for left_power, left_coefficient in left.items():
        for right_power, right_coefficient in right.items():
            power = tuple(a + b for a, b in zip(left_power, right_power))
            product[power] = product.get(power, 0) + left_coefficient * right_coefficient
            if product[power] == 0:
                del product[power]
            if len(product) > term_cap:
                raise ValueError("polynomial-power monomial cap exceeded")
    return product


def _shift_polynomial(polynomial: SparsePolynomial, shift: tuple[int, ...], factor: int) -> SparsePolynomial:
    return {tuple(a + b for a, b in zip(power, shift)): coefficient * factor
            for power, coefficient in polynomial.items()}


def _monomial_shifts(variables: int, degree: int, cap: int) -> list[tuple[int, ...]]:
    """Enumerate weak compositions directly, not ``(degree+1)**variables`` candidates.

    The former Cartesian-product implementation made even a sparse 12-variable request spend an
    unreasonable amount of time rejecting over-degree tuples.  The lattice column cap is enforced
    during generation, so widening the accepted variable count does not widen the allocation cap.
    """
    shifts: list[tuple[int, ...]] = []

    def visit(prefix: tuple[int, ...], remaining_variables: int, remaining_degree: int) -> None:
        if len(shifts) > cap:
            return
        if remaining_variables == 1:
            for value in range(remaining_degree + 1):
                shifts.append(prefix + (value,))
                if len(shifts) > cap:
                    return
            return
        for value in range(remaining_degree + 1):
            visit(prefix + (value,), remaining_variables - 1, remaining_degree - value)
            if len(shifts) > cap:
                return

    visit((), variables, degree)
    if len(shifts) > cap:
        raise ValueError(f"monomial shifts exceed the {cap}-column lattice cap")
    return shifts


def _hg_lattice(
    polynomial: SparsePolynomial,
    modulus: int,
    scales: tuple[int, ...],
    m: int,
    t: int,
    max_dimension: int,
) -> tuple[list[list[int]], tuple[tuple[int, ...], ...], tuple[int, ...]]:
    """Construct independent ``x^a f^i N^(m-i)`` rows, scaled at the supplied bounds."""
    variables = len(scales)
    one = {(0,) * variables: 1}
    powers = [one]
    for _ in range(m):
        powers.append(_poly_multiply(powers[-1], polynomial, term_cap=max_dimension))

    shifts = _monomial_shifts(variables, t, max_dimension)
    polynomials: list[SparsePolynomial] = []
    leading_seen: set[tuple[int, ...]] = set()
    monomial_union: set[tuple[int, ...]] = set()
    # High powers first: when two rows have the same leading monomial, retain the row carrying the
    # most information about f rather than the bare N^m monomial.
    for power_index in range(m, -1, -1):
        factor = modulus ** (m - power_index)
        for shift in shifts:
            row_poly = _shift_polynomial(powers[power_index], shift, factor)
            leading = max(row_poly, key=lambda item: (sum(item), item))
            if leading in leading_seen:
                continue
            proposed = monomial_union | row_poly.keys()
            if len(proposed) > max_dimension:
                raise ValueError(
                    f"requested Howgrave-Graham lattice exceeds {max_dimension}-column cap; "
                    "lower m/t or use a sparser polynomial"
                )
            leading_seen.add(leading)
            monomial_union = proposed
            polynomials.append(row_poly)
            if len(polynomials) > max_dimension:
                raise ValueError("Howgrave-Graham row cap exceeded")

    monomials = tuple(sorted(monomial_union, key=lambda item: (sum(item), item)))
    scale_by_column = tuple(math.prod(scale ** exponent for scale, exponent in zip(scales, powers_))
                            for powers_ in monomials)
    basis: list[list[int]] = []
    for row_poly in polynomials:
        row = [row_poly.get(powers_, 0) * scale
               for powers_, scale in zip(monomials, scale_by_column)]
        if any(coordinate.bit_length() > MAX_HG_COORD_BITS for coordinate in row):
            raise ValueError(f"Howgrave-Graham coordinate exceeds {MAX_HG_COORD_BITS}-bit cap")
        basis.append(row)
    return basis, monomials, scale_by_column


def _evaluate_polynomial(polynomial: SparsePolynomial, point: tuple[int, ...]) -> int:
    return sum(coefficient * math.prod(value ** exponent for value, exponent in zip(point, powers))
               for powers, coefficient in polynomial.items())


def _primitive_polynomial(polynomial: SparsePolynomial) -> SparsePolynomial:
    divisor = 0
    for coefficient in polynomial.values():
        divisor = math.gcd(divisor, abs(coefficient))
    if divisor > 1:
        polynomial = {power: coefficient // divisor for power, coefficient in polynomial.items()}
    leading = max(polynomial, key=lambda item: (sum(item), item))
    if polynomial[leading] < 0:
        polynomial = {power: -coefficient for power, coefficient in polynomial.items()}
    return polynomial


def _certified_relations(
    reduced: list[list[int]],
    monomials: tuple[tuple[int, ...], ...],
    scales: tuple[int, ...],
    modulus: int,
    m: int,
) -> list[SparsePolynomial]:
    relations: list[SparsePolynomial] = []
    seen: set[tuple[tuple[tuple[int, ...], int], ...]] = set()
    threshold_squared = modulus ** (2 * m)
    for vector in reduced:
        # ||g(x_i X_i)||_2 * sqrt(number of monomials) < N^m is the standard sufficient
        # Howgrave--Graham condition.  Only such rows are treated as equations over Z.
        if sum(coordinate * coordinate for coordinate in vector) * len(monomials) >= threshold_squared:
            continue
        coefficients: SparsePolynomial = {}
        for powers, scale, coordinate in zip(monomials, scales, vector):
            if coordinate % scale:
                coefficients = {}
                break
            coefficient = coordinate // scale
            if coefficient:
                coefficients[powers] = coefficient
        if not coefficients:
            continue
        coefficients = _primitive_polynomial(coefficients)
        marker = tuple(sorted(coefficients.items()))
        if marker not in seen:
            seen.add(marker)
            relations.append(coefficients)
    return relations


def _solve_fraction_matrix(rows: Sequence[Sequence[int]], variables: int) -> tuple[int, ...] | None:
    matrix = [[Fraction(value) for value in row] for row in rows]
    pivot_row = 0
    for column in range(variables):
        pivot = next((index for index in range(pivot_row, len(matrix))
                      if matrix[index][column]), None)
        if pivot is None:
            return None
        matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
        factor = matrix[pivot_row][column]
        matrix[pivot_row] = [entry / factor for entry in matrix[pivot_row]]
        for index in range(len(matrix)):
            if index == pivot_row or not matrix[index][column]:
                continue
            factor = matrix[index][column]
            matrix[index] = [a - factor * b for a, b in zip(matrix[index], matrix[pivot_row])]
        pivot_row += 1
    solution = tuple(matrix[index][-1] for index in range(variables))
    if any(value.denominator != 1 for value in solution):
        return None
    return tuple(value.numerator for value in solution)


def _linear_relation_candidates(relations: Sequence[SparsePolynomial], variables: int):
    affine = []
    zero = (0,) * variables
    for relation in relations:
        if any(sum(power) > 1 for power in relation):
            continue
        row = [relation.get(tuple(1 if i == j else 0 for i in range(variables)), 0)
               for j in range(variables)]
        row.append(-relation.get(zero, 0))
        affine.append(row)
    for index, selected in enumerate(itertools.combinations(affine, variables)):
        if index >= 64:
            break
        candidate = _solve_fraction_matrix(selected, variables)
        if candidate is not None:
            yield candidate


def _affine_projection_candidates(
    relations: Sequence[SparsePolynomial],
    ranges: Sequence[tuple[int, int]],
    max_projection: int,
    deadline: float | None,
):
    """Solve one coordinate from a certified affine relation while enumerating a small projection."""
    if max_projection == 0:
        return
    variables = len(ranges)
    zero = (0,) * variables
    unit = [tuple(1 if i == j else 0 for i in range(variables)) for j in range(variables)]
    for relation in relations:
        if any(sum(power) > 1 for power in relation):
            continue
        coefficients = [relation.get(power, 0) for power in unit]
        choices = [index for index, coefficient in enumerate(coefficients) if coefficient]
        if not choices:
            continue
        # Solve the widest non-zero coordinate, minimizing the projection that must be visited.
        solved = max(choices, key=lambda index: ranges[index][1] - ranges[index][0])
        projected = [index for index in range(variables) if index != solved]
        volume = 1
        for index in projected:
            width = ranges[index][1] - ranges[index][0] + 1
            if volume > max_projection // width:
                volume = max_projection + 1
                break
            volume *= width
        if volume > max_projection:
            continue
        iterables = [range(ranges[index][0], ranges[index][1] + 1) for index in projected]
        for values in itertools.product(*iterables):
            if deadline is not None and time.monotonic() > deadline:
                return
            numerator = -relation.get(zero, 0)
            numerator -= sum(coefficients[index] * value
                             for index, value in zip(projected, values))
            coefficient = coefficients[solved]
            if numerator % coefficient:
                continue
            point = [0] * variables
            for index, value in zip(projected, values):
                point[index] = value
            point[solved] = numerator // coefficient
            if ranges[solved][0] <= point[solved] <= ranges[solved][1]:
                yield tuple(point)


def _bounded_sympy_candidates(
    relations: Sequence[SparsePolynomial],
    variables: int,
    deadline: float | None,
):
    """Yield integer zero-dimensional solutions for deliberately tiny relation systems."""
    suitable = []
    for relation in relations:
        degree = max(map(sum, relation))
        coefficient_bits = max(abs(value).bit_length() for value in relation.values())
        if degree <= 6 and len(relation) <= 32 and coefficient_bits <= 2048:
            suitable.append(relation)
    suitable.sort(key=lambda relation: (max(map(sum, relation)), len(relation)))
    suitable = suitable[:6]
    if len(suitable) < variables:
        return
    try:
        import sympy
    except Exception:  # pragma: no cover - optional dependency
        return
    symbols = sympy.symbols(f"x0:{variables}")

    def expression(relation):
        return sum(coefficient * math.prod(symbol ** exponent
                                           for symbol, exponent in zip(symbols, powers))
                   for powers, coefficient in relation.items())

    attempts = 0
    for selected in itertools.combinations(suitable, variables):
        if attempts >= 10 or (deadline is not None and time.monotonic() > deadline):
            break
        attempts += 1
        try:
            solutions = sympy.solve_poly_system([expression(item) for item in selected], *symbols)
        except Exception:
            continue
        if not solutions:
            continue
        for solution in solutions[:MAX_ROOT_CANDIDATES]:
            if len(solution) != variables or any(value.is_Integer is not True for value in solution):
                continue
            yield tuple(int(value) for value in solution)


def small_roots_detailed(
    f,
    N: int,
    bounds,
    *,
    m: int = 2,
    t: int = 1,
    max_dimension: int = MAX_HG_DIMENSION,
    max_enumeration: int = MAX_ROOT_ENUMERATION,
    max_projection: int = MAX_ROOT_PROJECTION,
    max_roots: int = MAX_ROOT_CANDIDATES,
    deadline: float | None = None,
) -> SmallRootsResult:
    """Find and exactly verify bounded roots of ``f(x_0,...) == 0 (mod N)``.

    ``f`` uses the sparse representation documented by :func:`_normalise_polynomial`.  Positive
    integer bounds mean ``abs(x_i) <= bound``; explicit ``[low, high]`` pairs are inclusive.  The
    implementation supports at most sixteen variables, input total degree eight, and caller-selected
    ``m,t <= 6`` under a 72-column hard cap.  LLL-reduced rows become integer equations only after the
    Howgrave--Graham norm proof.  Affine systems, affine relations with a projection of at most
    ``max_projection`` points, and deliberately small zero-dimensional systems are solved; a box of
    at most ``max_enumeration`` points is also searched completely.  Thus large hard systems may
    return no root, but every tuple returned is proven by direct substitution modulo N.
    """
    modulus = _bounded_integer(N, "N")
    if modulus <= 2:
        raise ValueError("N must be greater than two")
    if (isinstance(m, bool) or not isinstance(m, int) or not 1 <= m <= 6
            or isinstance(t, bool) or not isinstance(t, int) or not 0 <= t <= 6):
        raise ValueError("m must be in 1..6 and t in 0..6")
    if (isinstance(max_dimension, bool) or not isinstance(max_dimension, int)
            or not 2 <= max_dimension <= MAX_HG_DIMENSION):
        raise ValueError(f"max_dimension must be in 2..{MAX_HG_DIMENSION}")
    if (isinstance(max_enumeration, bool) or not isinstance(max_enumeration, int)
            or not 0 <= max_enumeration <= MAX_ROOT_ENUMERATION):
        raise ValueError(f"max_enumeration must be in 0..{MAX_ROOT_ENUMERATION}")
    if (isinstance(max_projection, bool) or not isinstance(max_projection, int)
            or not 0 <= max_projection <= MAX_ROOT_PROJECTION):
        raise ValueError(f"max_projection must be in 0..{MAX_ROOT_PROJECTION}")
    if (isinstance(max_roots, bool) or not isinstance(max_roots, int)
            or not 1 <= max_roots <= MAX_ROOT_CANDIDATES):
        raise ValueError(f"max_roots must be in 1..{MAX_ROOT_CANDIDATES}")
    ranges, variable_scales = _normalise_bounds(bounds)
    polynomial = _normalise_polynomial(f, len(ranges))
    basis, monomials, column_scales = _hg_lattice(
        polynomial, modulus, variable_scales, m, t, max_dimension
    )
    if deadline is not None and time.monotonic() > deadline:
        return SmallRootsResult((), (), len(basis), len(monomials), 0)
    reduced = lll(basis, deadline=deadline)
    if reduced is None:
        return SmallRootsResult((), (), len(basis), len(monomials), 0)
    relations = _certified_relations(reduced, monomials, column_scales, modulus, m)

    found: dict[tuple[int, ...], str] = {}

    def consider(candidate, method: str) -> None:
        if len(found) >= max_roots:
            return
        point = tuple(candidate)
        if (len(point) == len(ranges)
                and all(low <= value <= high for value, (low, high) in zip(point, ranges))
                and _evaluate_polynomial(polynomial, point) % modulus == 0):
            found.setdefault(point, method)

    for candidate in _linear_relation_candidates(relations, len(ranges)):
        consider(candidate, "certified-linear-relations")
    if len(found) < max_roots:
        for candidate in _affine_projection_candidates(relations, ranges, max_projection, deadline):
            consider(candidate, "certified-affine-projection")
            if len(found) >= max_roots:
                break
    if len(found) < max_roots:
        for candidate in _bounded_sympy_candidates(relations, len(ranges), deadline):
            consider(candidate, "certified-polynomial-relations")
            if len(found) >= max_roots:
                break

    volume = 1
    enumerable = max_enumeration > 0
    for low, high in ranges:
        width = high - low + 1
        if not enumerable or volume > max_enumeration // width:
            enumerable = False
            break
        volume *= width
    if enumerable and (deadline is None or time.monotonic() <= deadline):
        for point in itertools.product(*(range(low, high + 1) for low, high in ranges)):
            if deadline is not None and time.monotonic() > deadline:
                break
            consider(point, "bounded-enumeration")
            if len(found) >= max_roots:
                break

    ordered = tuple(sorted(found))
    methods = tuple(found[root] for root in ordered)
    return SmallRootsResult(ordered, methods, len(basis), len(monomials), len(relations))


def small_roots(f, N: int, bounds, **kwargs) -> list[tuple[int, ...]]:
    """Convenience wrapper returning only exactly verified root tuples.

    Use :func:`small_roots_detailed` when the recovery method and lattice diagnostics matter.
    """
    return list(small_roots_detailed(f, N, bounds, **kwargs).roots)


# ---- approximate common divisor ----------------------------------------------------------

def _verify_acd_candidate(divisor: int, samples: Sequence[int], noise_bound: int, method: str):
    if divisor <= max(1, 2 * noise_bound):
        return None
    quotients = []
    noises = []
    for sample in samples:
        quotient = _nearest_integer(Fraction(sample, divisor))
        noise = sample - quotient * divisor
        if quotient <= 0 or abs(noise) > noise_bound:
            return None
        quotients.append(quotient)
        noises.append(noise)
    if any(sample != quotient * divisor + noise
           for sample, quotient, noise in zip(samples, quotients, noises)):
        return None
    return ACDResult(divisor, tuple(quotients), tuple(noises), method)


def approximate_common_divisors(
    samples,
    noise_bound: int,
    *,
    max_results: int = 16,
    max_noise_pairs: int = MAX_ACD_NOISE_PAIRS,
    lattice_samples: int = MAX_ACD_LATTICE_SAMPLES,
    deadline: float | None = None,
) -> list[ACDResult]:
    """Return ranked, exactly verified approximate common divisors.

    The model is ``sample_i = q_i * p + r_i`` with positive ``q_i``, ``p > 2*noise_bound``, and
    ``abs(r_i) <= noise_bound``.  Up to 64 samples are accepted; the simultaneous-approximation LLL
    uses at most ``lattice_samples`` of them and verifies candidates against *all* samples.  When
    ``(2*noise_bound+1)^2`` fits ``max_noise_pairs``, up to three sample pairs additionally receive a
    complete two-noise gcd search.  This is useful for CTF ACD instances but is not a theorem that all
    parameter regimes are recoverable.  No unverified divisor is returned.
    """
    if (not isinstance(samples, (list, tuple))
            or not 2 <= len(samples) <= MAX_ACD_SAMPLES):
        raise ValueError(f"samples must contain 2..{MAX_ACD_SAMPLES} positive integers")
    values = _integer_vector(samples, "samples")
    if any(value <= 0 for value in values):
        raise ValueError(f"samples must contain 2..{MAX_ACD_SAMPLES} positive integers")
    bound = _bounded_integer(noise_bound, "noise_bound")
    if bound < 0 or bound.bit_length() > 20:
        raise ValueError("noise_bound must be non-negative and at most 20 bits")
    if (isinstance(max_results, bool) or not isinstance(max_results, int)
            or not 1 <= max_results <= MAX_ACD_RESULTS):
        raise ValueError(f"max_results must be in 1..{MAX_ACD_RESULTS}")
    if (isinstance(max_noise_pairs, bool) or not isinstance(max_noise_pairs, int)
            or not 0 <= max_noise_pairs <= MAX_ACD_NOISE_PAIRS):
        raise ValueError(f"max_noise_pairs must be in 0..{MAX_ACD_NOISE_PAIRS}")
    if (isinstance(lattice_samples, bool) or not isinstance(lattice_samples, int)
            or not 2 <= lattice_samples <= MAX_ACD_LATTICE_SAMPLES):
        raise ValueError(f"lattice_samples must be in 2..{MAX_ACD_LATTICE_SAMPLES}")

    candidates: dict[int, ACDResult] = {}
    rejected_cache: set[int] = set()

    def consider(divisor: int, method: str) -> None:
        current = candidates.get(divisor)
        if current is not None:
            if current.method != "lll-simultaneous" and method == "lll-simultaneous":
                candidates[divisor] = ACDResult(
                    current.divisor, current.quotients, current.noises, method
                )
            return
        if divisor in rejected_cache:
            return
        verified = _verify_acd_candidate(divisor, values, bound, method)
        if verified is None:
            if len(rejected_cache) < 65_536:
                rejected_cache.add(divisor)
            return
        if len(candidates) >= MAX_ACD_RESULTS:
            worst = min(candidates)
            if divisor <= worst:
                return
            del candidates[worst]
        candidates[divisor] = verified

    selected_count = min(len(values), lattice_samples)
    selected_indices = list(range(selected_count))
    scales = sorted({1, max(1, bound), max(1, math.isqrt(max(1, bound))), max(1, 2 * bound + 1)})
    # Trying a few anchors avoids making recovery depend on a single unusually small quotient.
    for anchor_index in selected_indices[:min(3, selected_count)]:
        if deadline is not None and time.monotonic() > deadline:
            break
        other_indices = [index for index in selected_indices if index != anchor_index]
        anchor = values[anchor_index]
        for scale in scales:
            dimension = 1 + len(other_indices)
            basis = [[scale] + [values[index] for index in other_indices]]
            for column in range(1, dimension):
                row = [0] * dimension
                row[column] = -anchor
                basis.append(row)
            reduced = lll(basis, deadline=deadline)
            if reduced is None:
                continue
            for vector in reduced:
                if not vector[0] or vector[0] % scale:
                    continue
                anchor_quotient = abs(vector[0] // scale)
                quotient_options = {anchor_quotient}
                # A reduced vector can be a small integer multiple of the primitive quotient
                # relation.  Approximate the other quotients and remove a common factor when clear.
                approximate = [anchor_quotient]
                approximate.extend(_nearest_integer(Fraction(anchor_quotient * values[index], anchor))
                                   for index in other_indices)
                common = math.gcd(*map(abs, approximate))
                if common > 1:
                    quotient_options.add(anchor_quotient // common)
                for quotient in quotient_options:
                    if quotient <= 0:
                        continue
                    floor = anchor // quotient
                    for divisor in (floor - 1, floor, floor + 1,
                                    _nearest_integer(Fraction(anchor, quotient))):
                        consider(divisor, "lll-simultaneous")

    pair_space = (2 * bound + 1) ** 2
    if pair_space and pair_space <= max_noise_pairs:
        pair_budget = max_noise_pairs
        expired = False
        for left_index, right_index in itertools.combinations(range(min(len(values), 4)), 2):
            if pair_budget < pair_space or (deadline is not None and time.monotonic() > deadline):
                break
            pair_budget -= pair_space
            left, right = values[left_index], values[right_index]
            for left_noise in range(-bound, bound + 1):
                adjusted_left = left - left_noise
                for right_noise in range(-bound, bound + 1):
                    if ((right_noise + bound) % 256 == 0
                            and deadline is not None and time.monotonic() > deadline):
                        expired = True
                        break
                    divisor = math.gcd(adjusted_left, right - right_noise)
                    consider(divisor, "bounded-noise-gcd")
                if expired:
                    break
            if expired:
                break

    ranked = sorted(candidates.values(),
                    key=lambda result: (-result.divisor, sum(map(abs, result.noises)), result.method))
    return ranked[:max_results]


def approximate_common_divisor(samples, noise_bound: int, **kwargs) -> ACDResult | None:
    """Return the highest-ranked exactly verified ACD explanation, or ``None``."""
    kwargs.pop("max_results", None)
    results = approximate_common_divisors(samples, noise_bound, max_results=1, **kwargs)
    return results[0] if results else None


def _subset_mitm(values: list[int], target: int, max_states: int) -> list[int] | None:
    split = len(values) // 2
    left, right = values[:split], values[split:]
    if (1 << len(left)) > max_states or (1 << len(right)) > max_states:
        return None
    sums: dict[int, int] = {}
    for mask in range(1 << len(left)):
        total = sum(value for i, value in enumerate(left) if mask >> i & 1)
        sums.setdefault(total, mask)
    for right_mask in range(1 << len(right)):
        right_sum = sum(value for i, value in enumerate(right) if right_mask >> i & 1)
        left_mask = sums.get(target - right_sum)
        if left_mask is None:
            continue
        bits = [(left_mask >> i) & 1 for i in range(len(left))]
        bits += [(right_mask >> i) & 1 for i in range(len(right))]
        if sum(v * bit for v, bit in zip(values, bits)) == target:
            return bits
    return None


def solve_subset_sum(
    values,
    target: int,
    *,
    max_states: int = MAX_MITM_STATES,
    deadline: float | None = None,
) -> list[int] | None:
    """Recover a 0/1 subset whose weighted sum is exactly ``target``.

    A bounded meet-in-the-middle search is complete when both halves fit ``max_states``.  Larger
    instances use a low-density LLL embedding.  Either path returns only an exact, round-tripped bit
    vector; hard/high-density instances may therefore return ``None`` rather than a false candidate.
    """
    weights = _integer_vector(values, "values")
    if len(weights) > 128:
        raise ValueError("subset-sum is capped at 128 items")
    if isinstance(target, bool) or not isinstance(target, int) or target.bit_length() > MAX_COORD_BITS:
        raise ValueError("target must be a bounded integer")
    if not isinstance(max_states, int) or not 1 <= max_states <= MAX_MITM_STATES:
        raise ValueError(f"max_states must be in 1..{MAX_MITM_STATES}")
    if deadline is not None and time.monotonic() > deadline:
        return None
    exact = _subset_mitm(weights, target, max_states)
    if exact is not None:
        return exact

    n = len(weights)
    scale = max(2, math.isqrt(n) + 1)
    embedding = []
    for i, weight in enumerate(weights):
        row = [0] * (n + 1)
        row[i] = 2
        row[-1] = scale * weight
        embedding.append(row)
    embedding.append([1] * n + [scale * target])
    reduced = lll(embedding, deadline=deadline)
    if reduced is None:
        return None
    for row in reduced:
        for signed in (row, [-x for x in row]):
            if signed[-1] != 0 or any(x not in (-1, 1) for x in signed[:-1]):
                continue
            bits = [(1 - x) // 2 for x in signed[:-1]]
            if sum(weight * bit for weight, bit in zip(weights, bits)) == target:
                return bits
    return None


def is_superincreasing(sequence) -> bool:
    """True when every positive weight exceeds the sum of all predecessors."""
    try:
        weights = _integer_vector(sequence, "private sequence")
    except ValueError:
        return False
    total = 0
    for weight in weights:
        if weight <= total:
            return False
        total += weight
    return True


def merkle_hellman_decrypt(
    ciphertext: int,
    private_sequence,
    multiplier: int,
    modulus: int,
) -> list[int] | None:
    """Decrypt a classic Merkle--Hellman sum and verify against the derived public key."""
    weights = _integer_vector(private_sequence, "private sequence")
    if not is_superincreasing(weights):
        raise ValueError("private sequence is not superincreasing")
    if not all(isinstance(x, int) and not isinstance(x, bool)
               for x in (ciphertext, multiplier, modulus)):
        raise ValueError("ciphertext, multiplier, and modulus must be integers")
    if any(x.bit_length() > MAX_COORD_BITS for x in (ciphertext, multiplier, modulus)):
        raise ValueError("Merkle-Hellman integer exceeds coordinate cap")
    if modulus <= sum(weights) or not 1 < multiplier < modulus or math.gcd(multiplier, modulus) != 1:
        raise ValueError("invalid Merkle-Hellman modulus/multiplier")
    transformed = (ciphertext * pow(multiplier, -1, modulus)) % modulus
    remainder = transformed
    bits = [0] * len(weights)
    for i in range(len(weights) - 1, -1, -1):
        if weights[i] <= remainder:
            bits[i] = 1
            remainder -= weights[i]
    if remainder:
        return None
    public = [(multiplier * weight) % modulus for weight in weights]
    if sum(weight * bit for weight, bit in zip(public, bits)) != ciphertext:
        return None
    return bits


def bits_to_bytes(bits, *, msb_first: bool = True) -> bytes:
    """Pack a verified 0/1 vector, requiring a whole number of bytes."""
    if not isinstance(bits, (list, tuple)) or not bits or len(bits) % 8:
        raise ValueError("bits must be a non-empty whole-byte sequence")
    if any(bit not in (0, 1, False, True) for bit in bits):
        raise ValueError("bits must contain only 0/1")
    out = bytearray()
    for offset in range(0, len(bits), 8):
        chunk = bits[offset:offset + 8]
        value = 0
        if msb_first:
            for bit in chunk:
                value = (value << 1) | int(bit)
        else:
            for i, bit in enumerate(chunk):
                value |= int(bit) << i
        out.append(value)
    return bytes(out)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def _load_json(path: str) -> dict:
    source = Path(path)
    with source.open("rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds 1 MiB cap")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="lattice_tools.py")
    parser.add_argument(
        "operation",
        choices=("cvp", "small-roots", "acd", "subset-sum", "merkle-hellman"),
    )
    parser.add_argument("input", help="bounded JSON object")
    parser.add_argument("--no-reduce", action="store_true")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        data = _load_json(args.input)
        if args.operation == "cvp":
            result = closest_vector(data["basis"], data["target"], reduce=not args.no_reduce)
            if result is None:
                output = {"candidate": None}
            else:
                output = {"candidate": asdict(result), "verified_lattice_vector": True}
        elif args.operation == "small-roots":
            polynomial = data.get("polynomial", data.get("terms"))
            if polynomial is None:
                raise ValueError("small-roots input needs polynomial or terms")
            result = small_roots_detailed(
                polynomial,
                data["modulus"],
                data["bounds"],
                m=data.get("m", 2),
                t=data.get("t", 1),
                max_dimension=data.get("max_dimension", MAX_HG_DIMENSION),
                max_enumeration=data.get("max_enumeration", MAX_ROOT_ENUMERATION),
                max_projection=data.get("max_projection", MAX_ROOT_PROJECTION),
                max_roots=data.get("max_roots", MAX_ROOT_CANDIDATES),
            )
            output = {
                "candidates": [
                    {"rank": rank, "root": root, "method": method, "verified": True}
                    for rank, (root, method) in enumerate(zip(result.roots, result.methods), 1)
                ],
                "lattice": {
                    "rows": result.lattice_rows,
                    "columns": result.lattice_columns,
                    "certified_relations": result.certified_relations,
                },
            }
        elif args.operation == "acd":
            results = approximate_common_divisors(
                data["samples"],
                data["noise_bound"],
                max_results=data.get("max_results", 16),
                max_noise_pairs=data.get("max_noise_pairs", MAX_ACD_NOISE_PAIRS),
                lattice_samples=data.get("lattice_samples", MAX_ACD_LATTICE_SAMPLES),
            )
            output = {
                "candidates": [dict(rank=rank, verified=True, **asdict(result))
                               for rank, result in enumerate(results, 1)]
            }
        elif args.operation == "subset-sum":
            bits = solve_subset_sum(data["values"], data["target"])
            output = {"candidate_bits": bits, "verified": bits is not None}
        else:
            bits = merkle_hellman_decrypt(data["ciphertext"], data["private_sequence"],
                                          data["multiplier"], data["modulus"])
            output = {"candidate_bits": bits, "verified": bits is not None}
        if args.json:
            print(json.dumps(output, sort_keys=True))
        else:
            print("CANDIDATE [verified] " + json.dumps(output, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"lattice_tools: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
