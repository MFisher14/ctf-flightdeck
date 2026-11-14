"""Verified offline hash-structure and checksum attacks for the r5c crypto lane.

Length extension already lives in :mod:`oracle_aead`; this module does not
duplicate it.  It adds bounded chosen-prefix/multicollision validation, a toy
polynomial-hash key/forgery helper, and an exact GF(2) CRC patch solver.

Every emitter replays the original equation and returns ``None`` when the
evidence admits more than one answer.  There is no transport or file execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import itertools
from typing import Any, Callable, Iterable, Optional, Sequence


MAX_BYTES = 16 * 1024 * 1024
MAX_CANDIDATES = 4096
MAX_COLLISION_LEVELS = 12
MAX_COLLISION_BLOCK = 4096
MAX_COLLISION_MESSAGE = 1 << 20
MAX_POLY_MODULUS = 1 << 16
MAX_POLY_BLOCKS = 4096
MAX_POLY_WORK = 5_000_000
MAX_CRC_WIDTH = 64
MAX_CRC_PATCH_BYTES = 8
MAX_CRC_WORK_BYTES = 64 * 1024 * 1024


def _bounded_items(values: Any, cap: int) -> Optional[list[Any]]:
    try:
        iterator = iter(values)
    except TypeError:
        return None
    out: list[Any] = []
    try:
        for index, item in enumerate(iterator):
            if index >= cap:
                return None
            out.append(item)
    except Exception:
        return None
    return out


def _bytes(value: Any) -> Optional[bytes]:
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(value) > MAX_BYTES:
        return None
    return bytes(value)


def _strict_true(callback: Callable[..., Any], *args: Any) -> bool:
    if not callable(callback):
        return False
    try:
        result = callback(*args)
    except Exception:
        return False
    return result is True or (isinstance(result, int) and not isinstance(result, bool) and result == 1)


@dataclass(frozen=True)
class ChosenPrefixCollision:
    left_message: bytes
    right_message: bytes
    digest: bytes


def recover_chosen_prefix_collision(
    left_prefix: bytes,
    right_prefix: bytes,
    suffix_pairs: Iterable[tuple[bytes, bytes]],
    hash_function: Callable[[bytes], bytes],
    *,
    expected_digest: bytes | None = None,
    verify: Callable[[bytes, bytes, bytes], bool] | None = None,
) -> ChosenPrefixCollision | None:
    """Return the one supplied bridge pair producing a proven chosen-prefix collision.

    Candidate suffixes are caller-supplied and bounded; this function does not
    perform an unbounded collision search.  Multiple distinct valid bridges are
    intentionally an ambiguity, even if they happen to share the same digest.
    """

    left = _bytes(left_prefix)
    right = _bytes(right_prefix)
    expected = None if expected_digest is None else _bytes(expected_digest)
    pairs = _bounded_items(suffix_pairs, MAX_CANDIDATES)
    if (
        left is None
        or right is None
        or left == right
        or expected_digest is not None and expected is None
        or pairs is None
        or not pairs
        or not callable(hash_function)
    ):
        return None
    found: set[ChosenPrefixCollision] = set()
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            return None
        left_suffix, right_suffix = _bytes(pair[0]), _bytes(pair[1])
        if left_suffix is None or right_suffix is None:
            return None
        left_message, right_message = left + left_suffix, right + right_suffix
        if (
            left_message == right_message
            or len(left_message) > MAX_BYTES
            or len(right_message) > MAX_BYTES
        ):
            continue
        try:
            left_digest = hash_function(left_message)
            right_digest = hash_function(right_message)
        except Exception:
            return None
        if not isinstance(left_digest, bytes) or not isinstance(right_digest, bytes):
            return None
        if not left_digest or len(left_digest) > 1024 or left_digest != right_digest:
            continue
        if expected is not None and left_digest != expected:
            continue
        if verify is not None and not _strict_true(
            verify, left_message, right_message, left_digest
        ):
            continue
        found.add(ChosenPrefixCollision(left_message, right_message, left_digest))
        if len(found) > 1:
            return None
    return next(iter(found)) if len(found) == 1 else None


@dataclass(frozen=True)
class MulticollisionResult:
    final_state: bytes | int
    messages: tuple[bytes, ...]


def build_verified_multicollision(
    initial_state: bytes | int,
    collision_pairs: Iterable[tuple[bytes, bytes]],
    compress: Callable[[bytes | int, bytes], bytes | int],
) -> MulticollisionResult | None:
    """Validate a Joux-style collision chain and enumerate every proven path.

    At most twelve levels (4096 messages) are accepted.  Each pair must contain
    distinct equal-length blocks and collide from the exact state produced by
    the previous level.  Every final message is independently replayed.
    """

    if (
        isinstance(initial_state, bool)
        or not isinstance(initial_state, (bytes, int))
        or isinstance(initial_state, bytes) and len(initial_state) > MAX_COLLISION_BLOCK
    ):
        return None
    pairs = _bounded_items(collision_pairs, MAX_COLLISION_LEVELS)
    if pairs is None or not pairs or not callable(compress):
        return None
    normalised: list[tuple[bytes, bytes]] = []
    state: bytes | int = initial_state
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            return None
        left, right = _bytes(pair[0]), _bytes(pair[1])
        if (
            left is None
            or right is None
            or not left
            or left == right
            or len(left) != len(right)
            or len(left) > MAX_COLLISION_BLOCK
        ):
            return None
        try:
            next_left = compress(state, left)
            next_right = compress(state, right)
        except Exception:
            return None
        if (
            isinstance(next_left, bool)
            or not isinstance(next_left, (bytes, int))
            or isinstance(next_left, bytes) and len(next_left) > MAX_COLLISION_BLOCK
            or type(next_left) is not type(next_right)
            or next_left != next_right
        ):
            return None
        normalised.append((left, right))
        state = next_left
    message_count = 1 << len(normalised)
    message_length = sum(len(left) for left, _right in normalised)
    if (
        message_length > MAX_COLLISION_MESSAGE
        or message_count * message_length > MAX_BYTES
    ):
        return None
    messages = tuple(b"".join(choice) for choice in itertools.product(*normalised))
    if (
        len(set(messages)) != len(messages)
        or any(len(message) > MAX_COLLISION_MESSAGE for message in messages)
    ):
        return None
    for message in messages:
        replay: bytes | int = initial_state
        offset = 0
        try:
            for left, _right in normalised:
                size = len(left)
                replay = compress(replay, message[offset : offset + size])
                offset += size
        except Exception:
            return None
        if replay != state:
            return None
    return MulticollisionResult(state, messages)


def _normalise_blocks(blocks: Any, modulus: int) -> Optional[tuple[int, ...]]:
    values = _bounded_items(blocks, MAX_POLY_BLOCKS)
    if values is None or not values:
        return None
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        return None
    if any(not 0 <= value < modulus for value in values):
        return None
    return tuple(values)


def polynomial_hash(
    blocks: Sequence[int], multiplier: int, modulus: int, *, offset: int = 0
) -> int:
    """Horner polynomial hash ``state = state*r + block (mod p)``."""

    if (
        isinstance(multiplier, bool)
        or isinstance(modulus, bool)
        or isinstance(offset, bool)
        or not all(isinstance(value, int) for value in (multiplier, modulus, offset))
        or modulus <= 2
        or not 0 < multiplier < modulus
        or not 0 <= offset < modulus
    ):
        raise ValueError("invalid polynomial-hash parameters")
    values = _normalise_blocks(blocks, modulus)
    if values is None:
        raise ValueError("invalid polynomial-hash blocks")
    state = offset
    for value in values:
        state = (state * multiplier + value) % modulus
    return state


def _prime(value: int) -> bool:
    if value < 2:
        return False
    try:
        import sympy

        return bool(sympy.isprime(value))
    except ImportError:  # pragma: no cover - SymPy is installed in the solver venv
        if value % 2 == 0:
            return value == 2
        divisor = 3
        while divisor * divisor <= value:
            if value % divisor == 0:
                return False
            divisor += 2
        return True


def _normalise_poly_observations(
    observations: Any, modulus: int
) -> Optional[list[tuple[tuple[int, ...], int]]]:
    rows = _bounded_items(observations, MAX_CANDIDATES)
    if rows is None or len(rows) < 2:
        return None
    out: list[tuple[tuple[int, ...], int]] = []
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) != 2:
            return None
        blocks = _normalise_blocks(row[0], modulus)
        tag = row[1]
        if blocks is None or isinstance(tag, bool) or not isinstance(tag, int) or not 0 <= tag < modulus:
            return None
        out.append((blocks, tag))
    return out


def recover_polynomial_hash_key(
    observations: Iterable[tuple[Sequence[int], int]],
    modulus: int,
    *,
    multiplier_candidates: Iterable[int] | None = None,
) -> tuple[int, int] | None:
    """Recover the unique ``(multiplier, offset)`` explaining every tag.

    The modulus must be prime.  When candidates are omitted, bounded exhaustive
    recovery is supported only for toy moduli below ``2**16``.
    """

    if (
        isinstance(modulus, bool)
        or not isinstance(modulus, int)
        or not 3 <= modulus <= MAX_POLY_MODULUS
        or not _prime(modulus)
    ):
        return None
    rows = _normalise_poly_observations(observations, modulus)
    if rows is None:
        return None
    if multiplier_candidates is None:
        candidates = range(1, modulus)
    else:
        supplied = _bounded_items(multiplier_candidates, MAX_POLY_MODULUS)
        if supplied is None or not supplied:
            return None
        if any(isinstance(value, bool) or not isinstance(value, int) for value in supplied):
            return None
        candidates = tuple(dict.fromkeys(supplied))
    first_blocks, first_tag = rows[0]
    total_blocks = sum(len(blocks) for blocks, _tag in rows)
    candidate_count = modulus - 1 if multiplier_candidates is None else len(candidates)
    if candidate_count * total_blocks > MAX_POLY_WORK:
        return None
    found: set[tuple[int, int]] = set()
    for multiplier in candidates:
        if not 0 < multiplier < modulus:
            continue
        no_offset = polynomial_hash(first_blocks, multiplier, modulus, offset=0)
        scale = pow(multiplier, len(first_blocks), modulus)
        try:
            offset = (first_tag - no_offset) * pow(scale, -1, modulus) % modulus
        except ValueError:
            continue
        if all(
            polynomial_hash(blocks, multiplier, modulus, offset=offset) == tag
            for blocks, tag in rows
        ):
            found.add((multiplier, offset))
            if len(found) > 1:
                return None
    return next(iter(found)) if len(found) == 1 else None


def forge_polynomial_hash(
    observations: Iterable[tuple[Sequence[int], int]],
    target_blocks: Sequence[int],
    modulus: int,
    verify: Callable[[Sequence[int], int], bool],
    *,
    multiplier_candidates: Iterable[int] | None = None,
) -> tuple[int, int, int] | None:
    """Return ``(tag, multiplier, offset)`` only after baseline and target checks."""

    if (
        isinstance(modulus, bool)
        or not isinstance(modulus, int)
        or not 3 <= modulus <= MAX_POLY_MODULUS
        or not _prime(modulus)
    ):
        return None
    rows = _normalise_poly_observations(observations, modulus)
    target = _normalise_blocks(target_blocks, modulus)
    if rows is None or target is None:
        return None
    key = recover_polynomial_hash_key(
        rows, modulus, multiplier_candidates=multiplier_candidates
    )
    if key is None:
        return None
    multiplier, offset = key
    original_blocks, original_tag = rows[0]
    if (
        not _strict_true(verify, original_blocks, original_tag)
        or _strict_true(verify, original_blocks, (original_tag + 1) % modulus)
    ):
        return None
    tag = polynomial_hash(target, multiplier, modulus, offset=offset)
    if not _strict_true(verify, target, tag):
        return None
    return tag, multiplier, offset


def crc_msb(
    data: bytes,
    width: int,
    polynomial: int,
    *,
    init: int = 0,
    xor_out: int = 0,
) -> int | None:
    """Compute a direct, MSB-first CRC, or return None for invalid parameters.

    The polynomial's top bit is omitted.
    """

    raw = _bytes(data)
    values = (width, polynomial, init, xor_out)
    if (
        raw is None
        or any(isinstance(value, bool) or not isinstance(value, int) for value in values)
        or not 1 <= width <= MAX_CRC_WIDTH
    ):
        return None
    mask = (1 << width) - 1
    if not 0 < polynomial <= mask or not 0 <= init <= mask or not 0 <= xor_out <= mask:
        return None
    register = init
    for byte in raw:
        for shift in range(7, -1, -1):
            feedback = ((register >> (width - 1)) ^ (byte >> shift)) & 1
            register = register << 1 & mask
            if feedback:
                register ^= polynomial
    return register ^ xor_out


def _gf2_unique_solution(rows: list[tuple[int, int]], variables: int) -> Optional[int]:
    work = [[mask, rhs] for mask, rhs in rows]
    pivot_row = 0
    pivots: dict[int, int] = {}
    for column in range(variables):
        selected = next(
            (index for index in range(pivot_row, len(work)) if work[index][0] >> column & 1),
            None,
        )
        if selected is None:
            continue
        work[pivot_row], work[selected] = work[selected], work[pivot_row]
        for index in range(len(work)):
            if index != pivot_row and work[index][0] >> column & 1:
                work[index][0] ^= work[pivot_row][0]
                work[index][1] ^= work[pivot_row][1]
        pivots[column] = pivot_row
        pivot_row += 1
    if any(mask == 0 and rhs for mask, rhs in work) or len(pivots) != variables:
        return None
    solution = 0
    for column, row_index in pivots.items():
        if work[row_index][1]:
            solution |= 1 << column
    return solution


def forge_crc_patch(
    message: bytes,
    target_crc: int,
    patch_offset: int,
    patch_length: int,
    width: int,
    polynomial: int,
    *,
    init: int = 0,
    xor_out: int = 0,
    verify: Callable[[bytes, int], bool] | None = None,
) -> bytes | None:
    """Replace a bounded byte range with the unique patch reaching ``target_crc``.

    The CRC map is linear-affine over GF(2).  The influence matrix is solved
    exactly; a rank-deficient system (multiple patches) returns ``None``.
    The returned value is the complete patched message after CRC replay.
    """

    raw = _bytes(message)
    integers = (target_crc, patch_offset, patch_length, width, polynomial, init, xor_out)
    if (
        raw is None
        or any(isinstance(value, bool) or not isinstance(value, int) for value in integers)
        or not 1 <= width <= MAX_CRC_WIDTH
        or not 1 <= patch_length <= MAX_CRC_PATCH_BYTES
        or not 0 <= patch_offset <= len(raw) - patch_length
        or not 0 <= target_crc < 1 << width
        or len(raw) * (patch_length * 8 + 2) > MAX_CRC_WORK_BYTES
    ):
        return None
    original_crc = crc_msb(raw, width, polynomial, init=init, xor_out=xor_out)
    if original_crc is None:
        return None
    base = bytearray(raw)
    base[patch_offset : patch_offset + patch_length] = bytes(patch_length)
    base_crc = crc_msb(bytes(base), width, polynomial, init=init, xor_out=xor_out)
    variables = patch_length * 8
    influences: list[int] = []
    for variable in range(variables):
        probe = bytearray(base)
        byte_index, bit_index = divmod(variable, 8)
        probe[patch_offset + byte_index] = 1 << (7 - bit_index)
        influences.append(
            crc_msb(bytes(probe), width, polynomial, init=init, xor_out=xor_out) ^ base_crc
        )
    delta = target_crc ^ base_crc
    equations: list[tuple[int, int]] = []
    for output_bit in range(width):
        mask = sum(
            1 << variable
            for variable, influence in enumerate(influences)
            if influence >> output_bit & 1
        )
        equations.append((mask, delta >> output_bit & 1))
    solution = _gf2_unique_solution(equations, variables)
    if solution is None:
        return None
    forged = bytearray(base)
    for variable in range(variables):
        if solution >> variable & 1:
            byte_index, bit_index = divmod(variable, 8)
            forged[patch_offset + byte_index] ^= 1 << (7 - bit_index)
    result = bytes(forged)
    if crc_msb(result, width, polynomial, init=init, xor_out=xor_out) != target_crc:
        return None
    if verify is not None:
        if (
            not _strict_true(verify, raw, original_crc)
            or _strict_true(verify, raw, original_crc ^ 1)
            or not _strict_true(verify, result, target_crc)
        ):
            return None
    return result


__all__ = [
    "ChosenPrefixCollision",
    "MulticollisionResult",
    "build_verified_multicollision",
    "crc_msb",
    "forge_crc_patch",
    "forge_polynomial_hash",
    "polynomial_hash",
    "recover_chosen_prefix_collision",
    "recover_polynomial_hash_key",
]
