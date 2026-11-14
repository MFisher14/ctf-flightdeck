"""Verified toy-only post-quantum weak-parameter analyzers.

The attacks in this module are deliberately bounded CTF helpers, not attacks on
production LWE/NTRU/Kyber/Dilithium parameter sets.  Every recovery is accepted
only when it is unique and reproduces all supplied equations, ciphertexts,
signatures, or rejection observations.  Production-sized inputs exceed hard caps
and return ``None``.

Polynomial arithmetic uses coefficient lists in ascending degree.  NTRU helpers
work in ``Z_q[x]/(x^n-1)``; Kyber/Dilithium-like helpers work in
``Z_q[x]/(x^n+1)``.  Final polynomial and vector equations are independently
cross-checked with SymPy when it is installed.  No network functionality exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from math import gcd
from numbers import Integral
from typing import Iterable, Sequence


MAX_ENUM_CANDIDATES = 1_000_000
MAX_ATTACK_DIMENSION = 12
MAX_ATTACK_POLY_DEGREE = 16
MAX_ATTACK_SAMPLES = 64
MAX_ATTACK_MODULUS = (1 << 31) - 1
MAX_AUDIT_DIMENSION = 4096
MAX_AUDIT_MATRIX_DIMENSION = 512
MAX_INPUT_COEFFICIENT = (1 << 63) - 1


@dataclass(frozen=True)
class ParameterFinding:
    """One concrete unsafe/malformed/toy indicator; absence is not a safety claim."""

    code: str
    severity: str
    detail: str


@dataclass(frozen=True)
class PQParameterAudit:
    """Immutable parameter review.

    ``toy_attackable`` only means that this module's explicit enumeration caps
    admit the input.  ``findings == ()`` never asserts cryptographic security.
    """

    scheme: str
    dimension: int
    modulus: int
    noise_bound: int
    rank: int | None
    toy_attackable: bool
    findings: tuple[ParameterFinding, ...]


def _as_int(value) -> int:
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


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    try:
        from Crypto.Util.number import isPrime

        return bool(isPrime(value))
    except ImportError:  # pragma: no cover - pycryptodome is installed in the repo
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


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _candidate_count(values: Sequence[int], dimension: int) -> int | None:
    return _candidate_cardinality(len(values), dimension)


def _candidate_cardinality(cardinality: int, dimension: int) -> int | None:
    if cardinality < 1 or dimension < 0:
        return None
    count = 1
    for _ in range(dimension):
        count *= cardinality
        if count > MAX_ENUM_CANDIDATES:
            return None
    return count


def _bounded_items(values, limit: int):
    try:
        iterator = iter(values)
    except TypeError:
        return None
    result = []
    try:
        for index, value in enumerate(iterator):
            if index >= limit:
                return None
            result.append(value)
    except Exception:
        return None
    return tuple(result)


def _coefficient(value) -> int:
    result = _as_int(value)
    if abs(result) > MAX_INPUT_COEFFICIENT:
        raise ValueError("coefficient exceeds input cap")
    return result


def _normalise_values(values: Iterable[int], *, max_values: int = 17):
    raw = _bounded_items(values, max_values)
    if raw is None:
        return None
    try:
        result = tuple(sorted({_coefficient(value) for value in raw}))
    except (TypeError, ValueError):
        return None
    if not result or len(result) > max_values or any(abs(value) > 1 << 20 for value in result):
        return None
    return result


def _normalise_vector(vector, *, length=None, max_length=MAX_ATTACK_SAMPLES):
    raw = _bounded_items(vector, max_length)
    if raw is None:
        return None
    try:
        result = tuple(_coefficient(value) for value in raw)
    except (TypeError, ValueError):
        return None
    if not result or len(result) > max_length or (length is not None and len(result) != length):
        return None
    return result


def _normalise_matrix(matrix, *, max_rows=MAX_ATTACK_SAMPLES, max_cols=MAX_ATTACK_DIMENSION):
    outer = _bounded_items(matrix, max_rows)
    if outer is None:
        return None
    rows = []
    try:
        for row in outer:
            raw = _bounded_items(row, max_cols)
            if raw is None:
                return None
            rows.append(tuple(_coefficient(value) for value in raw))
    except (TypeError, ValueError):
        return None
    rows = tuple(rows)
    if not rows or len(rows) > max_rows:
        return None
    width = len(rows[0])
    if not 1 <= width <= max_cols or any(len(row) != width for row in rows):
        return None
    return rows


def _center(value: int, modulus: int) -> int:
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def _modular_rank(matrix: Sequence[Sequence[int]], modulus: int) -> int | None:
    """Rank over F_q, declining when q is not prime."""

    if not _is_prime(modulus) or not matrix:
        return None
    rows = [[value % modulus for value in row] for row in matrix]
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        return None
    rank = 0
    for column in range(width):
        pivot = next((row for row in range(rank, len(rows)) if rows[row][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, modulus)
        rows[rank] = [value * inverse % modulus for value in rows[rank]]
        for row in range(len(rows)):
            if row == rank or rows[row][column] == 0:
                continue
            scale = rows[row][column]
            rows[row] = [
                (rows[row][i] - scale * rows[rank][i]) % modulus for i in range(width)
            ]
        rank += 1
        if rank == len(rows):
            break
    return rank


def _solve_mod_unique(matrix: Sequence[Sequence[int]], target: Sequence[int], modulus: int):
    """Unique solution of a modular linear system, or ``None``."""

    if not _is_prime(modulus) or not matrix or len(matrix) != len(target):
        return None
    rows = [[value % modulus for value in row] + [target[i] % modulus] for i, row in enumerate(matrix)]
    width = len(matrix[0])
    if width == 0 or any(len(row) != width + 1 for row in rows):
        return None
    pivots = []
    rank = 0
    for column in range(width):
        pivot = next((row for row in range(rank, len(rows)) if rows[row][column]), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, modulus)
        rows[rank] = [value * inverse % modulus for value in rows[rank]]
        for row in range(len(rows)):
            if row == rank or not rows[row][column]:
                continue
            scale = rows[row][column]
            rows[row] = [
                (rows[row][i] - scale * rows[rank][i]) % modulus for i in range(width + 1)
            ]
        pivots.append(column)
        rank += 1
    if any(all(value % modulus == 0 for value in row[:width]) and row[-1] % modulus for row in rows):
        return None
    if rank != width:
        return None
    solution = [0] * width
    for row, column in enumerate(pivots):
        solution[column] = rows[row][-1] % modulus
    if any(
        sum(matrix[row][column] * solution[column] for column in range(width)) % modulus
        != target[row] % modulus
        for row in range(len(matrix))
    ):
        return None
    return tuple(solution)


def _sympy_linear_check(matrix, vector, error, target, modulus) -> bool:
    try:
        from sympy import Matrix
    except ImportError:
        return True
    try:
        lhs = Matrix(matrix) * Matrix(vector) + Matrix(error)
        return all(int(lhs[i]) % modulus == target[i] % modulus for i in range(len(target)))
    except Exception:
        return False


def _poly_mul(left, right, modulus: int, *, negacyclic: bool):
    n = len(left)
    if n == 0 or len(right) != n:
        return None
    raw = [0] * (2 * n - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            raw[i + j] += a * b
    for degree in range(2 * n - 2, n - 1, -1):
        if negacyclic:
            raw[degree - n] -= raw[degree]
        else:
            raw[degree - n] += raw[degree]
    return tuple(value % modulus for value in raw[:n])


def _sympy_poly_mul(left, right, modulus: int, *, negacyclic: bool):
    try:
        from sympy import Poly, symbols
    except ImportError:
        return _poly_mul(left, right, modulus, negacyclic=negacyclic)
    try:
        x = symbols("x")
        n = len(left)
        lhs = Poly(sum(value * x**i for i, value in enumerate(left)), x)
        rhs = Poly(sum(value * x**i for i, value in enumerate(right)), x)
        ring = Poly(x**n + (1 if negacyclic else -1), x)
        reduced = (lhs * rhs).rem(ring)
        return tuple(int(reduced.nth(i)) % modulus for i in range(n))
    except Exception:
        return None


def _convolution_matrix(poly, modulus: int, *, negacyclic: bool):
    n = len(poly)
    columns = []
    for index in range(n):
        basis = [0] * n
        basis[index] = 1
        columns.append(_poly_mul(poly, basis, modulus, negacyclic=negacyclic))
    return tuple(tuple(columns[column][row] for column in range(n)) for row in range(n))


def _poly_inverse(poly, modulus: int, *, negacyclic: bool):
    matrix = _convolution_matrix(poly, modulus, negacyclic=negacyclic)
    target = (1,) + (0,) * (len(poly) - 1)
    inverse = _solve_mod_unique(matrix, target, modulus)
    if inverse is None:
        return None
    product_value = _poly_mul(poly, inverse, modulus, negacyclic=negacyclic)
    product_sympy = _sympy_poly_mul(poly, inverse, modulus, negacyclic=negacyclic)
    return inverse if product_value == target and product_sympy == target else None


def _finding(code, severity, detail):
    return ParameterFinding(code=code, severity=severity, detail=detail)


def audit_lwe_parameters(
    matrix,
    modulus,
    error_bound,
    secret_bound,
) -> PQParameterAudit | None:
    """Audit concrete LWE dimensions/rank without claiming unflagged inputs safe."""

    rows = _normalise_matrix(
        matrix,
        max_rows=MAX_AUDIT_MATRIX_DIMENSION,
        max_cols=MAX_AUDIT_MATRIX_DIMENSION,
    )
    try:
        q, error, secret = _as_int(modulus), _as_int(error_bound), _as_int(secret_bound)
    except (TypeError, ValueError):
        return None
    if rows is None or not 2 <= q <= MAX_ATTACK_MODULUS or error < 0 or secret < 0:
        return None
    dimension = len(rows[0])
    rank = _modular_rank(rows, q)
    findings = []
    if not _is_prime(q):
        findings.append(_finding("non_field_modulus", "malformed", "rank/linear algebra over Z_q is not a field"))
    if q < 257:
        findings.append(_finding("tiny_modulus", "unsafe", "small modulus is intended only for toy exercises"))
    if dimension <= MAX_ATTACK_DIMENSION:
        findings.append(_finding("toy_dimension", "unsafe", "secret dimension falls inside bounded enumeration caps"))
    if error == 0:
        findings.append(_finding("zero_noise", "unsafe", "no error hides the linear equations"))
    if 2 * error >= q:
        findings.append(_finding("ambiguous_error_interval", "malformed", "centered error bound spans the modulus"))
    if rank is not None and rank < dimension:
        findings.append(_finding("rank_deficient", "unsafe", "public equation matrix lacks full column rank"))
    toy = (
        dimension <= MAX_ATTACK_DIMENSION
        and _candidate_cardinality(2 * secret + 1, dimension) is not None
        and _is_prime(q)
        and q >= 3
        and q % 2 == 1
        and 2 * error < q
    )
    return PQParameterAudit("LWE", dimension, q, error, rank, toy, tuple(findings))


def audit_ntru_parameters(degree, modulus, plaintext_modulus, small_bound) -> PQParameterAudit | None:
    """Audit NTRU-like toy dimensions and malformed modulus relationships."""

    try:
        n, q, p, bound = map(_as_int, (degree, modulus, plaintext_modulus, small_bound))
    except (TypeError, ValueError):
        return None
    if not 1 <= n <= MAX_AUDIT_DIMENSION or not 2 <= q <= MAX_ATTACK_MODULUS or p < 2 or bound < 0:
        return None
    findings = []
    if gcd(p, q) != 1 or p >= q:
        findings.append(_finding("malformed_moduli", "malformed", "p and q must be coprime with p < q"))
    if not _is_prime(q):
        findings.append(_finding("nonprime_modulus", "notice", "valid NTRU variants may use this; this toy field solver declines it"))
    if n <= MAX_ATTACK_POLY_DEGREE:
        findings.append(_finding("toy_degree", "unsafe", "polynomial degree is inside exhaustive-search caps"))
    if q < 257:
        findings.append(_finding("tiny_modulus", "unsafe", "ciphertext modulus is toy-sized"))
    toy = (
        n <= MAX_ATTACK_POLY_DEGREE
        and _candidate_cardinality(2 * bound + 1, n) is not None
        and _is_prime(q)
        and gcd(p, q) == 1
        and p < q
    )
    return PQParameterAudit("NTRU-like", n, q, bound, None, toy, tuple(findings))


def audit_kyber_like_parameters(
    module_rank,
    polynomial_degree,
    modulus,
    eta,
    *,
    flattened_matrix_rank=None,
    compression_bits=(10, 4),
) -> PQParameterAudit | None:
    """Audit Kyber-like structural parameters and supplied flattened rank."""

    try:
        k, n, q, noise = map(_as_int, (module_rank, polynomial_degree, modulus, eta))
        widths = _bounded_items(compression_bits, 2)
        if widths is None or len(widths) != 2:
            return None
        du, dv = (_as_int(widths[0]), _as_int(widths[1]))
        rank = None if flattened_matrix_rank is None else _as_int(flattened_matrix_rank)
    except (TypeError, ValueError, IndexError):
        return None
    dimension = k * n
    if not 1 <= k <= 64 or not 1 <= n <= MAX_AUDIT_DIMENSION or not 2 <= q <= MAX_ATTACK_MODULUS or noise < 0:
        return None
    findings = []
    if not _power_of_two(n):
        findings.append(_finding("malformed_degree", "malformed", "negacyclic NTT degree should be a power of two"))
    if not _is_prime(q) or q % 2 == 0:
        findings.append(_finding("malformed_modulus", "malformed", "toy solver requires an odd prime modulus"))
    if noise == 0:
        findings.append(_finding("zero_noise", "unsafe", "zero-noise module equations expose the secret"))
    if 2 * noise >= q:
        findings.append(_finding("ambiguous_noise_interval", "malformed", "centered noise interval spans the modulus"))
    if dimension <= MAX_ATTACK_DIMENSION:
        findings.append(_finding("toy_dimension", "unsafe", "flattened module secret is enumerable"))
    if rank is not None and (rank < 0 or rank > dimension):
        findings.append(_finding("impossible_rank", "malformed", "flattened rank lies outside [0, dimension]"))
    elif rank is not None and rank < dimension:
        findings.append(_finding("rank_deficient", "unsafe", "flattened public matrix is rank deficient"))
    if du <= 0 or dv <= 0 or du > q.bit_length() or dv > q.bit_length():
        findings.append(_finding("malformed_compression", "malformed", "compression widths are outside modulus bit width"))
    toy = (
        dimension <= MAX_ATTACK_DIMENSION
        and _candidate_cardinality(2 * noise + 1, dimension) is not None
        and _is_prime(q)
        and q % 2 == 1
        and _power_of_two(n)
        and noise > 0
        and 2 * noise < q
    )
    return PQParameterAudit("Kyber-like", dimension, q, noise, rank, toy, tuple(findings))


def audit_dilithium_like_parameters(
    vector_rank,
    polynomial_degree,
    modulus,
    eta,
    nonce_bound,
    *,
    reused_nonce_observed=False,
) -> PQParameterAudit | None:
    """Audit Dilithium-like dimensions and explicit nonce-reuse evidence."""

    try:
        rank, n, q, noise, gamma = map(
            _as_int, (vector_rank, polynomial_degree, modulus, eta, nonce_bound)
        )
    except (TypeError, ValueError):
        return None
    dimension = rank * n
    if not 1 <= rank <= 64 or not 1 <= n <= MAX_AUDIT_DIMENSION or not 2 <= q <= MAX_ATTACK_MODULUS or noise < 0 or gamma < 1:
        return None
    findings = []
    if not _power_of_two(n):
        findings.append(_finding("malformed_degree", "malformed", "negacyclic polynomial degree should be a power of two"))
    if not _is_prime(q) or q % 2 == 0:
        findings.append(_finding("malformed_modulus", "malformed", "toy solver requires an odd prime modulus"))
    if noise == 0:
        findings.append(_finding("zero_secret_noise", "unsafe", "zero secret width is structurally degenerate"))
    if 2 * noise >= q:
        findings.append(_finding("ambiguous_secret_interval", "malformed", "centered secret interval spans the modulus"))
    if dimension <= MAX_ATTACK_DIMENSION:
        findings.append(_finding("toy_dimension", "unsafe", "secret vector is inside bounded enumeration caps"))
    if gamma >= q // 2:
        findings.append(_finding("malformed_nonce_bound", "malformed", "centered nonce bound must stay below q/2"))
    if reused_nonce_observed is True:
        findings.append(_finding("reused_y", "unsafe", "reusing the masking vector y gives linear secret equations"))
    elif reused_nonce_observed not in (False, 0):
        return None
    toy = (
        dimension <= MAX_ATTACK_DIMENSION
        and _candidate_cardinality(2 * noise + 1, dimension) is not None
        and _is_prime(q)
        and q % 2 == 1
        and _power_of_two(n)
        and gamma < q // 2
        and noise > 0
        and 2 * noise < q
    )
    return PQParameterAudit("Dilithium-like", dimension, q, noise, rank, toy, tuple(findings))


def recover_lwe_secret(
    matrix,
    target,
    modulus,
    *,
    secret_values=(-1, 0, 1),
    error_bound=1,
) -> tuple[int, ...] | None:
    """Uniquely recover a tiny LWE secret by bounded enumeration.

    The returned secret is independently rechecked against every equation with a
    centered error in ``[-error_bound, error_bound]``.  Production dimensions and
    candidate spaces above :data:`MAX_ENUM_CANDIDATES` decline.
    """

    rows = _normalise_matrix(matrix)
    if rows is None:
        return None
    vector = _normalise_vector(target, length=len(rows))
    values = _normalise_values(secret_values)
    try:
        q, bound = _as_int(modulus), _as_int(error_bound)
    except (TypeError, ValueError):
        return None
    dimension = len(rows[0])
    if (
        vector is None
        or values is None
        or not _is_prime(q)
        or not 3 <= q <= MAX_ATTACK_MODULUS
        or q % 2 == 0
        or not 0 <= bound < q // 2
        or dimension > MAX_ATTACK_DIMENSION
        or _candidate_count(values, dimension) is None
    ):
        return None
    candidates = []
    for secret in product(values, repeat=dimension):
        error = tuple(
            _center(vector[row] - sum(rows[row][column] * secret[column] for column in range(dimension)), q)
            for row in range(len(rows))
        )
        if all(abs(value) <= bound for value in error):
            candidates.append((tuple(secret), error))
            if len(candidates) > 1:
                return None
    if len(candidates) != 1:
        return None
    secret, error = candidates[0]
    if any(
        (sum(rows[row][column] * secret[column] for column in range(dimension)) + error[row] - vector[row]) % q
        for row in range(len(rows))
    ):
        return None
    return secret if _sympy_linear_check(rows, secret, error, vector, q) else None


def recover_ntru_private_key(
    public_h,
    plaintext_modulus,
    modulus,
    *,
    small_values=(-1, 0, 1),
) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    """Recover a toy NTRU key ``f=1+pF, g`` from ``h=p*g/f``.

    Both ``F`` and ``g`` must use ``small_values``.  The normalized ``1+pF`` form
    removes the otherwise unavoidable ``(f,g)``/``(-f,-g)`` ambiguity.
    """

    h = _normalise_vector(public_h, max_length=MAX_ATTACK_POLY_DEGREE)
    values = _normalise_values(small_values)
    try:
        p, q = _as_int(plaintext_modulus), _as_int(modulus)
    except (TypeError, ValueError):
        return None
    if (
        h is None
        or values is None
        or len(h) > MAX_ATTACK_POLY_DEGREE
        or _candidate_count(values, len(h)) is None
        or not _is_prime(q)
        or not 2 <= p < q <= MAX_ATTACK_MODULUS
        or gcd(p, q) != 1
    ):
        return None
    h = tuple(value % q for value in h)
    candidates = []
    p_inverse = pow(p, -1, q)
    value_set = set(values)
    for small_f in product(values, repeat=len(h)):
        f = tuple((1 if index == 0 else 0) + p * small_f[index] for index in range(len(h)))
        inverse = _poly_inverse(tuple(value % q for value in f), q, negacyclic=False)
        if inverse is None:
            continue
        fh = _poly_mul(f, h, q, negacyclic=False)
        g = tuple(_center(value * p_inverse, q) for value in fh)
        if not any(g) or any(value not in value_set for value in g):
            continue
        rebuilt = _poly_mul(tuple(p * value % q for value in g), inverse, q, negacyclic=False)
        sympy_rebuilt = _sympy_poly_mul(tuple(p * value % q for value in g), inverse, q, negacyclic=False)
        if rebuilt == h and sympy_rebuilt == h:
            candidates.append((f, g))
            if len(candidates) > 1:
                return None
    return candidates[0] if len(candidates) == 1 else None


def recover_ntru_message(
    ciphertext,
    public_h,
    modulus,
    *,
    blinding_values=(-1, 0, 1),
    message_values=(-1, 0, 1),
) -> tuple[int, ...] | None:
    """Recover a toy NTRU message from ``e=r*h+m`` by enumerating small ``r``."""

    e = _normalise_vector(ciphertext, max_length=MAX_ATTACK_POLY_DEGREE)
    h = _normalise_vector(public_h, length=len(e) if e else None, max_length=MAX_ATTACK_POLY_DEGREE)
    blind = _normalise_values(blinding_values)
    messages = _normalise_values(message_values)
    try:
        q = _as_int(modulus)
    except (TypeError, ValueError):
        return None
    if (
        e is None
        or h is None
        or blind is None
        or messages is None
        or not _is_prime(q)
        or not 3 <= q <= MAX_ATTACK_MODULUS
        or _candidate_count(blind, len(e)) is None
    ):
        return None
    e = tuple(value % q for value in e)
    h = tuple(value % q for value in h)
    message_set = set(messages)
    candidates = []
    for r in product(blind, repeat=len(e)):
        product_value = _poly_mul(r, h, q, negacyclic=False)
        message = tuple(_center(e[index] - product_value[index], q) for index in range(len(e)))
        if any(value not in message_set for value in message):
            continue
        rebuilt = tuple((product_value[index] + message[index]) % q for index in range(len(e)))
        sympy_product = _sympy_poly_mul(r, h, q, negacyclic=False)
        if rebuilt == e and sympy_product == product_value:
            candidates.append((tuple(r), message))
            if len(candidates) > 1:
                return None
    return candidates[0][1] if len(candidates) == 1 else None


def _normalise_module_matrix(matrix_polynomials, modulus: int):
    outer_raw = _bounded_items(matrix_polynomials, 8)
    if outer_raw is None:
        return None
    outer = []
    try:
        for row in outer_raw:
            row_raw = _bounded_items(row, 8)
            if row_raw is None:
                return None
            parsed_row = []
            for poly in row_raw:
                poly_raw = _bounded_items(poly, MAX_ATTACK_POLY_DEGREE)
                if poly_raw is None:
                    return None
                parsed_row.append(tuple(_coefficient(x) % modulus for x in poly_raw))
            outer.append(tuple(parsed_row))
    except (TypeError, ValueError):
        return None
    outer = tuple(outer)
    k = len(outer)
    if not 1 <= k <= 8 or any(len(row) != k for row in outer):
        return None
    n = len(outer[0][0])
    if not 1 <= n <= MAX_ATTACK_POLY_DEGREE or any(len(poly) != n for row in outer for poly in row):
        return None
    return outer


def _normalise_poly_vector(vectors, modulus: int, *, count=None, degree=None):
    outer = _bounded_items(vectors, 8)
    if outer is None:
        return None
    result = []
    try:
        for poly in outer:
            raw = _bounded_items(poly, MAX_ATTACK_POLY_DEGREE)
            if raw is None:
                return None
            result.append(tuple(_coefficient(x) % modulus for x in raw))
    except (TypeError, ValueError):
        return None
    result = tuple(result)
    if not result or (count is not None and len(result) != count):
        return None
    n = len(result[0])
    if not 1 <= n <= MAX_ATTACK_POLY_DEGREE or (degree is not None and n != degree):
        return None
    if any(len(poly) != n for poly in result):
        return None
    return result


def _flatten_module_matrix(matrix, modulus: int):
    k, n = len(matrix), len(matrix[0][0])
    blocks = [[_convolution_matrix(matrix[i][j], modulus, negacyclic=True) for j in range(k)] for i in range(k)]
    return tuple(
        tuple(blocks[i][j][row][column] for j in range(k) for column in range(n))
        for i in range(k)
        for row in range(n)
    )


def _module_product(matrix, secret, modulus: int):
    k, n = len(matrix), len(matrix[0][0])
    output = []
    for i in range(k):
        total = [0] * n
        for j in range(k):
            term = _poly_mul(matrix[i][j], secret[j], modulus, negacyclic=True)
            for index in range(n):
                total[index] = (total[index] + term[index]) % modulus
        output.append(tuple(total))
    return tuple(output)


def recover_kyber_like_secret(
    matrix_polynomials,
    public_vector,
    modulus,
    *,
    secret_values=(-1, 0, 1),
    error_bound=1,
) -> tuple[tuple[int, ...], ...] | None:
    """Recover a tiny module-LWE/Kyber-like secret and verify every polynomial."""

    try:
        q = _as_int(modulus)
    except (TypeError, ValueError):
        return None
    if not _is_prime(q) or q % 2 == 0 or not 3 <= q <= MAX_ATTACK_MODULUS:
        return None
    matrix = _normalise_module_matrix(matrix_polynomials, q)
    if matrix is None:
        return None
    k, n = len(matrix), len(matrix[0][0])
    public = _normalise_poly_vector(public_vector, q, count=k, degree=n)
    if public is None or k * n > MAX_ATTACK_DIMENSION:
        return None
    flat_matrix = _flatten_module_matrix(matrix, q)
    flat_public = tuple(value for poly in public for value in poly)
    flat_secret = recover_lwe_secret(
        flat_matrix,
        flat_public,
        q,
        secret_values=secret_values,
        error_bound=error_bound,
    )
    if flat_secret is None:
        return None
    secret = tuple(tuple(flat_secret[i * n : (i + 1) * n]) for i in range(k))
    product_value = _module_product(matrix, secret, q)
    errors = tuple(
        tuple(_center(public[i][j] - product_value[i][j], q) for j in range(n)) for i in range(k)
    )
    try:
        bound = _as_int(error_bound)
    except (TypeError, ValueError):
        return None
    if any(abs(value) > bound for poly in errors for value in poly):
        return None
    for i in range(k):
        sympy_total = [0] * n
        for j in range(k):
            term = _sympy_poly_mul(matrix[i][j], secret[j], q, negacyclic=True)
            if term is None:
                return None
            sympy_total = [(sympy_total[x] + term[x]) % q for x in range(n)]
        if tuple(sympy_total) != product_value[i]:
            return None
    return secret


def _normalise_dilithium_signatures(signatures, modulus: int):
    raw = _bounded_items(signatures, 16)
    if raw is None:
        return None
    if not 2 <= len(raw) <= 16:
        return None
    parsed = []
    n = vectors = None
    for item in raw:
        try:
            challenge_raw, z_raw = item
        except (TypeError, ValueError):
            return None
        challenge = _normalise_vector(challenge_raw, max_length=MAX_ATTACK_POLY_DEGREE)
        if challenge is None:
            return None
        challenge = tuple(value % modulus for value in challenge)
        if n is None:
            n = len(challenge)
        if len(challenge) != n:
            return None
        z = _normalise_poly_vector(z_raw, modulus, degree=n)
        if z is None:
            return None
        if vectors is None:
            vectors = len(z)
        if len(z) != vectors:
            return None
        parsed.append((challenge, z))
    if n * vectors > 8 * MAX_ATTACK_POLY_DEGREE:
        return None
    return tuple(parsed)


def _challenge_times_secret(challenge, secret, modulus):
    return tuple(_poly_mul(challenge, poly, modulus, negacyclic=True) for poly in secret)


def _verify_reused_y(
    signatures,
    secret,
    nonce,
    modulus,
    secret_bound,
    nonce_bound,
    rejection_bound,
    *,
    cross_check=False,
):
    if any(abs(_center(value, modulus)) > secret_bound for poly in secret for value in poly):
        return False
    if any(abs(_center(value, modulus)) > nonce_bound for poly in nonce for value in poly):
        return False
    for challenge, observed_z in signatures:
        product_value = _challenge_times_secret(challenge, secret, modulus)
        for vector in range(len(secret)):
            expected = tuple((nonce[vector][i] + product_value[vector][i]) % modulus for i in range(len(challenge)))
            if expected != observed_z[vector]:
                return False
            if any(abs(_center(value, modulus)) > rejection_bound for value in observed_z[vector]):
                return False
            if cross_check:
                sympy = _sympy_poly_mul(challenge, secret[vector], modulus, negacyclic=True)
                if sympy != product_value[vector]:
                    return False
    return True


def recover_dilithium_reused_y(
    signatures,
    modulus,
    *,
    secret_bound,
    nonce_bound,
    rejection_bound,
) -> tuple[tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]] | None:
    """Recover ``(s, y)`` from Dilithium-like ``z=y+c*s`` with reused ``y``.

    Invertible challenge differences give a direct modular solution.  Singular
    differences receive a bounded small-secret fallback only when its complete
    search space fits the module's strict toy cap.  Native exact arithmetic filters
    all candidates; independent SymPy polynomial products run only once, at the
    unique emission gate.  The recovered small secret, nonce, rejection norm, and
    every supplied signature must all verify.
    """

    try:
        q, sb, yb, zb = map(_as_int, (modulus, secret_bound, nonce_bound, rejection_bound))
    except (TypeError, ValueError):
        return None
    if (
        not _is_prime(q)
        or q % 2 == 0
        or not 3 <= q <= MAX_ATTACK_MODULUS
        or not 0 <= sb < q // 2
        or not 0 <= yb < q // 2
        or not 0 <= zb < q // 2
    ):
        return None
    parsed = _normalise_dilithium_signatures(signatures, q)
    if parsed is None:
        return None
    n = len(parsed[0][0])
    if n > MAX_ATTACK_POLY_DEGREE:
        return None
    candidates = set()
    for left_index in range(len(parsed)):
        for right_index in range(left_index + 1, len(parsed)):
            c1, z1 = parsed[left_index]
            c2, z2 = parsed[right_index]
            delta = tuple((c1[i] - c2[i]) % q for i in range(n))
            matrix = _convolution_matrix(delta, q, negacyclic=True)
            recovered = []
            for vector in range(len(z1)):
                target = tuple((z1[vector][i] - z2[vector][i]) % q for i in range(n))
                solution = _solve_mod_unique(matrix, target, q)
                if solution is None:
                    break
                recovered.append(tuple(_center(value, q) for value in solution))
            else:
                secret = tuple(recovered)
                first_product = _challenge_times_secret(c1, secret, q)
                nonce = tuple(
                    tuple(_center(z1[v][i] - first_product[v][i], q) for i in range(n))
                    for v in range(len(secret))
                )
                if _verify_reused_y(parsed, secret, nonce, q, sb, yb, zb, cross_check=False):
                    candidates.add((secret, nonce))
                    if len(candidates) > 1:
                        return None
    # A singular challenge-difference can still have one solution after the
    # declared small-secret and nonce bounds are applied.  Exhaustively close
    # that gap only inside the same strict toy candidate cap.
    vectors = len(parsed[0][1])
    secret_dimension = vectors * n
    if (
        secret_dimension <= MAX_ATTACK_DIMENSION
        and _candidate_cardinality(2 * sb + 1, secret_dimension) is not None
    ):
        first_challenge, first_z = parsed[0]
        for flat in product(range(-sb, sb + 1), repeat=secret_dimension):
            secret = tuple(tuple(flat[v * n : (v + 1) * n]) for v in range(vectors))
            first_product = _challenge_times_secret(first_challenge, secret, q)
            nonce = tuple(
                tuple(_center(first_z[v][i] - first_product[v][i], q) for i in range(n))
                for v in range(vectors)
            )
            if _verify_reused_y(parsed, secret, nonce, q, sb, yb, zb, cross_check=False):
                candidates.add((secret, nonce))
                if len(candidates) > 1:
                    return None
    if len(candidates) != 1:
        return None
    candidate = next(iter(candidates))
    return (
        candidate
        if _verify_reused_y(
            parsed, candidate[0], candidate[1], q, sb, yb, zb, cross_check=True
        )
        else None
    )


def recover_dilithium_rejection_secret(
    nonce_y,
    challenges,
    accepted,
    modulus,
    *,
    secret_values=(-1, 0, 1),
    rejection_bound,
    observed_z=None,
) -> tuple[tuple[int, ...], ...] | None:
    """Recover a tiny secret from exact rejection outcomes for known/reused ``y``.

    For each observation, acceptance is defined by the centered infinity norm of
    ``z=y+c*s`` being at most ``rejection_bound``.  Optional ``observed_z`` entries
    (use ``None`` for unavailable responses) are also reproduced coefficient-for-
    coefficient.  The secret is emitted only if exactly one bounded vector fits.
    """

    try:
        q, bound = _as_int(modulus), _as_int(rejection_bound)
    except (TypeError, ValueError):
        return None
    decisions = _bounded_items(accepted, 32)
    challenges_raw = _bounded_items(challenges, 32)
    if decisions is None or challenges_raw is None or any(not isinstance(value, bool) for value in decisions):
        return None
    values = _normalise_values(secret_values)
    if (
        values is None
        or not _is_prime(q)
        or q % 2 == 0
        or not 3 <= q <= MAX_ATTACK_MODULUS
        or not 0 <= bound < q // 2
        or not 2 <= len(challenges_raw) <= 32
        or len(decisions) != len(challenges_raw)
    ):
        return None
    nonce = _normalise_poly_vector(nonce_y, q)
    if nonce is None:
        return None
    vectors, n = len(nonce), len(nonce[0])
    challenge_list = []
    for challenge in challenges_raw:
        parsed = _normalise_vector(challenge, length=n, max_length=MAX_ATTACK_POLY_DEGREE)
        if parsed is None:
            return None
        challenge_list.append(tuple(value % q for value in parsed))
    if vectors * n > MAX_ATTACK_DIMENSION or _candidate_count(values, vectors * n) is None:
        return None
    if observed_z is None:
        observed = (None,) * len(challenge_list)
    else:
        observed_raw = _bounded_items(observed_z, 32)
        if observed_raw is None:
            return None
        if len(observed_raw) != len(challenge_list):
            return None
        observed_list = []
        for entry in observed_raw:
            if entry is None:
                observed_list.append(None)
            else:
                parsed = _normalise_poly_vector(entry, q, count=vectors, degree=n)
                if parsed is None:
                    return None
                observed_list.append(parsed)
        observed = tuple(observed_list)
    candidates = []
    for flat in product(values, repeat=vectors * n):
        secret = tuple(tuple(flat[v * n : (v + 1) * n]) for v in range(vectors))
        valid = True
        for index, challenge in enumerate(challenge_list):
            product_value = _challenge_times_secret(challenge, secret, q)
            z = tuple(
                tuple((nonce[v][i] + product_value[v][i]) % q for i in range(n))
                for v in range(vectors)
            )
            decision = max(abs(_center(value, q)) for poly in z for value in poly) <= bound
            if decision != decisions[index] or (observed[index] is not None and z != observed[index]):
                valid = False
                break
        if valid:
            candidates.append(secret)
            if len(candidates) > 1:
                return None
    if len(candidates) != 1:
        return None
    secret = candidates[0]
    # Independent exact-polynomial proof is deliberately at the emission gate,
    # not inside up to a million enumeration iterations.
    for index, challenge in enumerate(challenge_list):
        product_value = _challenge_times_secret(challenge, secret, q)
        if any(
            _sympy_poly_mul(challenge, secret[v], q, negacyclic=True) != product_value[v]
            for v in range(vectors)
        ):
            return None
        z = tuple(
            tuple((nonce[v][i] + product_value[v][i]) % q for i in range(n))
            for v in range(vectors)
        )
        decision = max(abs(_center(value, q)) for poly in z for value in poly) <= bound
        if decision != decisions[index] or (observed[index] is not None and z != observed[index]):
            return None
    return secret


__all__ = [
    "ParameterFinding",
    "PQParameterAudit",
    "audit_lwe_parameters",
    "audit_ntru_parameters",
    "audit_kyber_like_parameters",
    "audit_dilithium_like_parameters",
    "recover_lwe_secret",
    "recover_ntru_private_key",
    "recover_ntru_message",
    "recover_kyber_like_secret",
    "recover_dilithium_reused_y",
    "recover_dilithium_rejection_secret",
]
