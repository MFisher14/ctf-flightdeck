"""Bounded, replay-verified symmetric cryptanalysis helpers.

All functions are offline.  Differential, linear, slide, related-key, and
meet-in-the-middle logic may *rank* or *generate* candidates, but a recovered
key is returned only when exactly one candidate reproduces every original
transcript.  Mode-misuse plaintexts and forgeries additionally require a
discriminating caller verifier that accepts the result and rejects a one-bit
near miss.  Iterator, callback, ambiguity, and work-cap failures return
``None`` rather than leaking an unverified value.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence


MAX_INPUT_BYTES = 1 << 20
MAX_BLOCK_SIZE = 256
MAX_TRANSCRIPTS = 4096
MAX_CANDIDATES = 65_536
MAX_TOTAL_WORK = 8_000_000
MAX_COLLISIONS = 262_144
MAX_SPN_WIDTH = 32
MAX_ROUNDS = 32
MAX_STREAM_SAMPLES = 65_536
MAX_KEY_BYTES = 256
MAX_KEY_INT_BITS = 4096


__all__ = [
    "ECBPatternReport",
    "IVReuseFinding",
    "StreamDistinguisherReport",
    "recover_differential_key",
    "recover_linear_key",
    "meet_in_middle_double_encryption",
    "recover_slide_key",
    "recover_related_key",
    "feistel_encrypt",
    "feistel_decrypt",
    "recover_feistel_key",
    "recover_feistel_structure",
    "spn_encrypt",
    "spn_decrypt",
    "recover_spn_key",
    "recover_spn_structure",
    "detect_ecb_patterns",
    "forge_ecb_cut_and_paste",
    "forge_cbc_bitflip",
    "detect_cbc_iv_reuse",
    "recover_cbc_iv",
    "recover_cbc_iv_equals_key",
    "recover_ctr_ofb_reuse_plaintext",
    "recover_cfb_reused_segment",
    "distinguish_stream_samples",
]


@dataclass(frozen=True)
class ECBPatternReport:
    block_size: int
    block_count: int
    repeated_blocks: tuple[tuple[bytes, tuple[int, ...]], ...]


@dataclass(frozen=True)
class IVReuseFinding:
    iv: bytes
    record_indices: tuple[int, ...]


@dataclass(frozen=True)
class StreamDistinguisherReport:
    sample_count: int
    hits: int
    expected_probability: float
    z_score: float
    threshold: float
    distinguished: bool


def _bounded_items(values, limit: int):
    try:
        iterator = iter(values)
    except TypeError:
        return None
    out = []
    try:
        for index, value in enumerate(iterator):
            if index >= limit:
                return None
            out.append(value)
    except Exception:
        return None
    return out


def _bytes(value, *, maximum: int = MAX_INPUT_BYTES) -> Optional[bytes]:
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(value) > maximum:
        return None
    return bytes(value)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


_BOOL_ERROR = object()


def _call_bool(callback: Callable, *args):
    if not callable(callback):
        return _BOOL_ERROR
    try:
        answer = callback(*args)
    except Exception:
        return _BOOL_ERROR
    if isinstance(answer, bool):
        return answer
    if isinstance(answer, int) and answer in (0, 1):
        return bool(answer)
    return _BOOL_ERROR


def _call_bytes(callback: Callable, *args, expected: Optional[int] = None):
    if not callable(callback):
        return None
    try:
        result = callback(*args)
    except Exception:
        return None
    output = _bytes(result)
    if output is None or (expected is not None and len(output) != expected):
        return None
    return output


def _keys(values):
    items = _bounded_items(values, MAX_CANDIDATES)
    if items is None or not items:
        return None
    out = []
    total = 0
    for value in items:
        if isinstance(value, (bytearray, memoryview)):
            value = bytes(value)
        if isinstance(value, bool) or not isinstance(value, (int, bytes)):
            return None
        if isinstance(value, bytes):
            if not value or len(value) > MAX_KEY_BYTES:
                return None
            total += len(value)
        else:
            if value < 0 or value.bit_length() > MAX_KEY_INT_BITS:
                return None
            total += max(1, (value.bit_length() + 7) // 8)
        if total > MAX_INPUT_BYTES:
            return None
        out.append(value)
    return tuple(dict.fromkeys(out))


def _byte_pairs(values, *, minimum: int = 1):
    items = _bounded_items(values, MAX_TRANSCRIPTS)
    if items is None or len(items) < minimum:
        return None
    out = []
    total = 0
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            return None
        plaintext, ciphertext = _bytes(item[0]), _bytes(item[1])
        if plaintext is None or ciphertext is None or not plaintext or len(plaintext) != len(ciphertext):
            return None
        total += len(plaintext) + len(ciphertext)
        if total > MAX_INPUT_BYTES:
            return None
        out.append((plaintext, ciphertext))
    return tuple(out)


def _negative_bytes(value: bytes) -> Optional[bytes]:
    return bytes([value[0] ^ 1]) + value[1:] if value else None


def _verified_bytes(value: bytes, verify: Callable[[bytes], bool]) -> bool:
    negative = _negative_bytes(value)
    if negative is None:
        return False
    accepted, rejected = _call_bool(verify, value), _call_bool(verify, negative)
    return accepted is True and rejected is False


# -- generic reduced-round key-recovery harnesses ---------------------------

def recover_differential_key(
    pairs,
    key_candidates,
    encrypt: Callable,
    *,
    expected_input_xor: Optional[bytes] = None,
    expected_output_xor: Optional[bytes] = None,
    differential_test: Optional[Callable] = None,
    verify: Optional[Callable] = None,
    max_work: int = MAX_TOTAL_WORK,
):
    """Recover a unique key from chosen-plaintext differential transcripts.

    Each item is ``(p0,p1,c0,c1)``.  Optional differences validate the original
    experiment before any candidate is considered.  ``differential_test`` may
    implement a reduced/last-round filter, but exact encryption of both sides
    of every pair is mandatory for emission.
    """
    items = _bounded_items(pairs, MAX_TRANSCRIPTS)
    keys = _keys(key_candidates)
    if items is None or not items or keys is None or not callable(encrypt):
        return None
    per_pair = 2 + (1 if differential_test is not None else 0)
    work = len(keys) * (len(items) * per_pair + (1 if verify is not None else 0))
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK
            or work > max_work):
        return None
    input_delta = None if expected_input_xor is None else _bytes(expected_input_xor)
    output_delta = None if expected_output_xor is None else _bytes(expected_output_xor)
    transcripts = []
    total = 0
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 4:
            return None
        values = tuple(_bytes(value) for value in item)
        if any(value is None for value in values):
            return None
        p0, p1, c0, c1 = values
        if not p0 or not (len(p0) == len(p1) == len(c0) == len(c1)):
            return None
        if input_delta is not None and (len(input_delta) != len(p0) or _xor(p0, p1) != input_delta):
            return None
        if output_delta is not None and (len(output_delta) != len(c0) or _xor(c0, c1) != output_delta):
            return None
        total += sum(map(len, values))
        if total > MAX_INPUT_BYTES:
            return None
        transcripts.append(values)
    matches = set()
    for key in keys:
        if differential_test is not None:
            try:
                decisions = [differential_test(key, *item) for item in transcripts]
            except Exception:
                return None
            if any(not isinstance(value, (bool, int)) or value not in (False, True, 0, 1)
                   for value in decisions):
                return None
            if not all(bool(value) for value in decisions):
                continue
        exact = True
        for p0, p1, c0, c1 in transcripts:
            result0 = _call_bytes(encrypt, key, p0, expected=len(c0))
            result1 = _call_bytes(encrypt, key, p1, expected=len(c1))
            if result0 is None or result1 is None:
                return None
            if result0 != c0 or result1 != c1:
                exact = False
                break
        verified = True
        if exact and verify is not None:
            verified = _call_bool(verify, key)
            if verified is _BOOL_ERROR:
                return None
        if exact and verified is True:
            matches.add(key)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def recover_linear_key(
    samples,
    key_candidates,
    encrypt: Callable,
    approximation: Callable,
    *,
    min_abs_bias: float = 1.0,
    max_work: int = MAX_TOTAL_WORK,
):
    """Linear-cryptanalysis harness with exact replay after bias ranking.

    ``approximation(key, plaintext, ciphertext)`` returns one relation bit.
    Only candidates with the greatest absolute zero/one imbalance are replayed.
    """
    pairs, keys = _byte_pairs(samples, minimum=2), _keys(key_candidates)
    if pairs is None or keys is None or not callable(encrypt) or not callable(approximation):
        return None
    if (isinstance(min_abs_bias, bool) or not isinstance(min_abs_bias, (int, float))
            or not math.isfinite(float(min_abs_bias)) or min_abs_bias < 0):
        return None
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK
            or len(pairs) * len(keys) * 2 > max_work):
        return None
    scores = {}
    for key in keys:
        zeros = 0
        for plaintext, ciphertext in pairs:
            try:
                bit = approximation(key, plaintext, ciphertext)
            except Exception:
                return None
            if isinstance(bit, bool):
                bit = int(bit)
            if not isinstance(bit, int) or bit not in (0, 1):
                return None
            zeros += bit == 0
        scores[key] = abs(zeros - len(pairs) / 2.0)
    best = max(scores.values())
    if best < float(min_abs_bias):
        return None
    matches = set()
    for key in keys:
        if scores[key] != best:
            continue
        exact = True
        for plaintext, ciphertext in pairs:
            result = _call_bytes(encrypt, key, plaintext, expected=len(ciphertext))
            if result is None:
                return None
            if result != ciphertext:
                exact = False
                break
        if exact:
            matches.add(key)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


# -- MITM, slide, and related-key ------------------------------------------

def meet_in_middle_double_encryption(
    pairs,
    first_key_candidates,
    second_key_candidates,
    encrypt_first: Callable,
    encrypt_second: Callable,
    decrypt_second: Callable,
    *,
    max_work: int = MAX_TOTAL_WORK,
):
    """MITM for ``C=E2(k2,E1(k1,P))``, followed by full replay."""
    transcripts = _byte_pairs(pairs)
    first_keys, second_keys = _keys(first_key_candidates), _keys(second_key_candidates)
    if (transcripts is None or first_keys is None or second_keys is None
            or not all(callable(value) for value in (encrypt_first, encrypt_second, decrypt_second))):
        return None
    work = (len(first_keys) + len(second_keys)
            + 2 * len(transcripts) * len(first_keys) * len(second_keys))
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK or work > max_work):
        return None
    plaintext0, ciphertext0 = transcripts[0]
    if (len(first_keys) * len(plaintext0) > MAX_INPUT_BYTES
            or len(second_keys) * len(ciphertext0) > MAX_INPUT_BYTES):
        return None
    middle: dict[bytes, list] = {}
    for key in first_keys:
        value = _call_bytes(encrypt_first, key, plaintext0, expected=len(plaintext0))
        if value is None:
            return None
        middle.setdefault(value, []).append(key)
    collision_count = 0
    matches = set()
    for second in second_keys:
        value = _call_bytes(decrypt_second, second, ciphertext0, expected=len(ciphertext0))
        if value is None:
            return None
        for first in middle.get(value, ()):
            collision_count += 1
            if collision_count > MAX_COLLISIONS:
                return None
            exact = True
            for plaintext, ciphertext in transcripts:
                inner = _call_bytes(encrypt_first, first, plaintext, expected=len(plaintext))
                if inner is None:
                    return None
                outer = _call_bytes(encrypt_second, second, inner, expected=len(ciphertext))
                if outer is None:
                    return None
                if outer != ciphertext:
                    exact = False
                    break
            if exact:
                matches.add((first, second))
                if len(matches) > 1:
                    return None
    return next(iter(matches)) if len(matches) == 1 else None


def recover_slide_key(
    transcripts,
    key_candidates,
    round_function: Callable,
    encrypt_full: Callable,
    *,
    max_work: int = MAX_TOTAL_WORK,
):
    """Recover a key from a slid transcript pair and replay every encryption."""
    pairs, keys = _byte_pairs(transcripts, minimum=2), _keys(key_candidates)
    if pairs is None or keys is None or not callable(round_function) or not callable(encrypt_full):
        return None
    work = len(keys) * (2 * len(pairs) * (len(pairs) - 1) + len(pairs))
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK or work > max_work):
        return None
    matches = set()
    for key in keys:
        replayed = []
        for p, c in pairs:
            result = _call_bytes(encrypt_full, key, p, expected=len(c))
            if result is None:
                return None
            replayed.append(result == c)
        if not all(replayed):
            continue
        slid = False
        for left, (p0, c0) in enumerate(pairs):
            for right, (p1, c1) in enumerate(pairs):
                if left == right:
                    continue
                round_p = _call_bytes(round_function, key, p0, expected=len(p1))
                round_c = _call_bytes(round_function, key, c0, expected=len(c1))
                if round_p is None or round_c is None:
                    return None
                if round_p == p1 and round_c == c1:
                    slid = True
                    break
            if slid:
                break
        if slid:
            matches.add(key)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def recover_related_key(
    transcripts,
    master_key_candidates,
    derive_related: Callable,
    encrypt: Callable,
    *,
    max_work: int = MAX_TOTAL_WORK,
):
    """Recover one master key from ``(relation, plaintext, ciphertext)`` rows."""
    items, masters = _bounded_items(transcripts, MAX_TRANSCRIPTS), _keys(master_key_candidates)
    if items is None or not items or masters is None or not callable(derive_related) or not callable(encrypt):
        return None
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK
            or 2 * len(items) * len(masters) > max_work):
        return None
    normal = []
    total = 0
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 3:
            return None
        relation, plaintext, ciphertext = item
        plaintext, ciphertext = _bytes(plaintext), _bytes(ciphertext)
        if plaintext is None or ciphertext is None or not plaintext or len(plaintext) != len(ciphertext):
            return None
        total += len(plaintext) + len(ciphertext)
        if total > MAX_INPUT_BYTES:
            return None
        normal.append((relation, plaintext, ciphertext))
    matches = set()
    for master in masters:
        exact = True
        for relation, plaintext, ciphertext in normal:
            try:
                related = derive_related(master, relation)
            except Exception:
                return None
            result = _call_bytes(encrypt, related, plaintext, expected=len(ciphertext))
            if result is None:
                return None
            if result != ciphertext:
                exact = False
                break
        if exact:
            matches.add(master)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


# -- Feistel and SPN --------------------------------------------------------

def feistel_encrypt(block, key, rounds: int, round_function: Callable) -> Optional[bytes]:
    value = _bytes(block, maximum=MAX_BLOCK_SIZE)
    if (value is None or not value or len(value) % 2 or isinstance(rounds, bool)
            or not isinstance(rounds, int) or not 1 <= rounds <= MAX_ROUNDS
            or not callable(round_function)):
        return None
    half = len(value) // 2
    left, right = value[:half], value[half:]
    for index in range(rounds):
        transformed = _call_bytes(round_function, key, index, right, expected=half)
        if transformed is None:
            return None
        left, right = right, _xor(left, transformed)
    return left + right


def feistel_decrypt(block, key, rounds: int, round_function: Callable) -> Optional[bytes]:
    value = _bytes(block, maximum=MAX_BLOCK_SIZE)
    if (value is None or not value or len(value) % 2 or isinstance(rounds, bool)
            or not isinstance(rounds, int) or not 1 <= rounds <= MAX_ROUNDS
            or not callable(round_function)):
        return None
    half = len(value) // 2
    left, right = value[:half], value[half:]
    for index in range(rounds - 1, -1, -1):
        previous_right = left
        transformed = _call_bytes(round_function, key, index, previous_right, expected=half)
        if transformed is None:
            return None
        previous_left = _xor(right, transformed)
        left, right = previous_left, previous_right
    return left + right


def recover_feistel_key(
    pairs, key_candidates, rounds: int, round_function: Callable,
    *, max_work: int = MAX_TOTAL_WORK,
):
    transcripts, keys = _byte_pairs(pairs), _keys(key_candidates)
    if (transcripts is None or keys is None or isinstance(rounds, bool)
            or not isinstance(rounds, int) or not 1 <= rounds <= MAX_ROUNDS):
        return None
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK
            or len(transcripts) * len(keys) * rounds * 2 > max_work):
        return None
    matches = set()
    for key in keys:
        exact = True
        for p, c in transcripts:
            encrypted = feistel_encrypt(p, key, rounds, round_function)
            decrypted = feistel_decrypt(c, key, rounds, round_function)
            if encrypted is None or decrypted is None:
                return None
            if encrypted != c or decrypted != p:
                exact = False
                break
        if exact:
            matches.add(key)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def _structure_candidates(values):
    items = _bounded_items(values, MAX_CANDIDATES)
    if items is None or not items:
        return None
    out = []
    total = 0
    for value in items:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            if value < 0 or value.bit_length() > MAX_KEY_INT_BITS:
                return None
            weight = max(1, (value.bit_length() + 7) // 8)
        elif isinstance(value, bytes):
            if not value or len(value) > MAX_KEY_BYTES:
                return None
            weight = len(value)
        elif isinstance(value, str):
            try:
                weight = len(value.encode("utf-8"))
            except UnicodeError:
                return None
            if not 1 <= weight <= MAX_KEY_BYTES:
                return None
        elif isinstance(value, tuple):
            if (not 1 <= len(value) <= 64
                    or any(isinstance(part, bool) or not isinstance(part, int)
                           or part < 0 or part.bit_length() > MAX_KEY_INT_BITS for part in value)):
                return None
            weight = sum(max(1, (part.bit_length() + 7) // 8) for part in value)
            if weight > MAX_KEY_BYTES:
                return None
        else:
            return None
        try:
            hash(value)
        except (TypeError, ValueError):
            return None
        total += weight
        if total > MAX_INPUT_BYTES:
            return None
        out.append(value)
    return tuple(dict.fromkeys(out))


def _recover_structure(pairs, key, candidates, encrypt_structure, max_work):
    transcripts = _byte_pairs(pairs)
    structures = _structure_candidates(candidates)
    normal_key = _keys([key])
    if (transcripts is None or structures is None or normal_key is None
            or len(normal_key) != 1 or not callable(encrypt_structure)):
        return None
    key = normal_key[0]
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK
            or len(transcripts) * len(structures) > max_work):
        return None
    matches = set()
    for structure in structures:
        exact = True
        for plaintext, ciphertext in transcripts:
            result = _call_bytes(
                encrypt_structure, key, structure, plaintext, expected=len(ciphertext)
            )
            if result is None:
                return None
            if result != ciphertext:
                exact = False
                break
        if exact:
            matches.add(structure)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def recover_feistel_structure(
    pairs, key, structure_candidates, encrypt_structure: Callable, *,
    max_work: int = MAX_TOTAL_WORK,
):
    """Recover one Feistel round/config descriptor by full transcript replay."""
    return _recover_structure(pairs, key, structure_candidates, encrypt_structure, max_work)


def _spn_parameters(width: int, rounds: int, sbox, permutation):
    if (isinstance(width, bool) or not isinstance(width, int) or width < 4
            or width > MAX_SPN_WIDTH or width % 4
            or isinstance(rounds, bool) or not isinstance(rounds, int)
            or not 1 <= rounds <= MAX_ROUNDS):
        return None
    boxes, perm = _bounded_items(sbox, 16), _bounded_items(permutation, width)
    if boxes is None or perm is None or len(boxes) != 16 or len(perm) != width:
        return None
    if any(isinstance(value, bool) or not isinstance(value, int) for value in boxes + perm):
        return None
    if set(boxes) != set(range(16)) or set(perm) != set(range(width)):
        return None
    return tuple(boxes), tuple(perm)


def _rotl_width(value: int, amount: int, width: int) -> int:
    amount %= width
    mask = (1 << width) - 1
    return ((value << amount) | (value >> (width - amount))) & mask if amount else value & mask


def _spn_substitute(value: int, table: Sequence[int], width: int) -> int:
    output = 0
    for offset in range(0, width, 4):
        output |= table[(value >> offset) & 0xF] << offset
    return output


def _spn_permute(value: int, permutation: Sequence[int]) -> int:
    output = 0
    for source, destination in enumerate(permutation):
        output |= ((value >> source) & 1) << destination
    return output


def spn_encrypt(value: int, key: int, rounds: int, sbox, permutation, *, width: int = 16) -> Optional[int]:
    parameters = _spn_parameters(width, rounds, sbox, permutation)
    if (parameters is None or isinstance(value, bool) or not isinstance(value, int)
            or isinstance(key, bool) or not isinstance(key, int)
            or not 0 <= value < 1 << width or not 0 <= key < 1 << width):
        return None
    boxes, perm = parameters
    state = value
    for index in range(rounds):
        state ^= _rotl_width(key, index, width)
        state = _spn_substitute(state, boxes, width)
        state = _spn_permute(state, perm)
    return state ^ _rotl_width(key, rounds, width)


def spn_decrypt(value: int, key: int, rounds: int, sbox, permutation, *, width: int = 16) -> Optional[int]:
    parameters = _spn_parameters(width, rounds, sbox, permutation)
    if (parameters is None or isinstance(value, bool) or not isinstance(value, int)
            or isinstance(key, bool) or not isinstance(key, int)
            or not 0 <= value < 1 << width or not 0 <= key < 1 << width):
        return None
    boxes, perm = parameters
    inverse_box = [0] * 16
    for source, destination in enumerate(boxes):
        inverse_box[destination] = source
    inverse_perm = [0] * width
    for source, destination in enumerate(perm):
        inverse_perm[destination] = source
    state = value ^ _rotl_width(key, rounds, width)
    for index in range(rounds - 1, -1, -1):
        state = _spn_permute(state, inverse_perm)
        state = _spn_substitute(state, inverse_box, width)
        state ^= _rotl_width(key, index, width)
    return state


def recover_spn_key(
    pairs, key_candidates, rounds: int, sbox, permutation, *, width: int = 16,
    max_work: int = MAX_TOTAL_WORK,
) -> Optional[int]:
    items, keys = _bounded_items(pairs, MAX_TRANSCRIPTS), _keys(key_candidates)
    if items is None or not items or keys is None or _spn_parameters(width, rounds, sbox, permutation) is None:
        return None
    if any(isinstance(key, bytes) or not 0 <= key < 1 << width for key in keys):
        return None
    normal = []
    for item in items:
        if (not isinstance(item, (tuple, list)) or len(item) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) for value in item)
                or any(not 0 <= value < 1 << width for value in item)):
            return None
        normal.append(tuple(item))
    if (isinstance(max_work, bool) or not isinstance(max_work, int)
            or not 1 <= max_work <= MAX_TOTAL_WORK
            or len(normal) * len(keys) * rounds * 2 > max_work):
        return None
    matches = set()
    for key in keys:
        if all(spn_encrypt(p, key, rounds, sbox, permutation, width=width) == c
               and spn_decrypt(c, key, rounds, sbox, permutation, width=width) == p
               for p, c in normal):
            matches.add(key)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def recover_spn_structure(
    pairs, key, structure_candidates, encrypt_structure: Callable, *,
    max_work: int = MAX_TOTAL_WORK,
):
    """Recover one SPN round/config descriptor by full transcript replay."""
    return _recover_structure(pairs, key, structure_candidates, encrypt_structure, max_work)


# -- block/stream mode misuse ----------------------------------------------

def detect_ecb_patterns(ciphertext, *, block_size: int = 16) -> Optional[ECBPatternReport]:
    data = _bytes(ciphertext)
    if (data is None or isinstance(block_size, bool) or not isinstance(block_size, int)
            or not 1 <= block_size <= MAX_BLOCK_SIZE or not data or len(data) % block_size):
        return None
    positions: dict[bytes, list[int]] = {}
    blocks = [data[offset:offset + block_size] for offset in range(0, len(data), block_size)]
    for index, block in enumerate(blocks):
        positions.setdefault(block, []).append(index)
    repeated = tuple(sorted(
        ((block, tuple(indices)) for block, indices in positions.items() if len(indices) > 1),
        key=lambda item: item[1],
    ))
    return ECBPatternReport(block_size, len(blocks), repeated)


def forge_ecb_cut_and_paste(
    ciphertext, block_order, verify: Callable[[bytes], bool], *, block_size: int = 16,
) -> Optional[bytes]:
    data = _bytes(ciphertext)
    order = _bounded_items(block_order, MAX_TRANSCRIPTS)
    if (data is None or order is None or not order or isinstance(block_size, bool)
            or not isinstance(block_size, int) or not 1 <= block_size <= MAX_BLOCK_SIZE
            or not data or len(data) % block_size):
        return None
    blocks = [data[offset:offset + block_size] for offset in range(0, len(data), block_size)]
    if any(isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(blocks)
           for index in order):
        return None
    forged = b"".join(blocks[index] for index in order)
    if forged == data or len(forged) > MAX_INPUT_BYTES:
        return None
    return forged if _verified_bytes(forged, verify) else None


def forge_cbc_bitflip(
    iv, ciphertext, offset: int, known_plaintext, desired_plaintext,
    verify: Callable[[bytes, bytes], bool], *, block_size: int = 16,
) -> Optional[tuple[bytes, bytes]]:
    iv_b, ciphertext_b = _bytes(iv), _bytes(ciphertext)
    known, desired = _bytes(known_plaintext), _bytes(desired_plaintext)
    if (iv_b is None or ciphertext_b is None or known is None or desired is None
            or isinstance(block_size, bool) or not isinstance(block_size, int)
            or not 1 <= block_size <= MAX_BLOCK_SIZE or len(iv_b) != block_size
            or not ciphertext_b or len(ciphertext_b) % block_size
            or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
            or not known or len(known) != len(desired)
            or offset + len(known) > len(ciphertext_b) or known == desired):
        return None
    forged_iv, forged_ct = bytearray(iv_b), bytearray(ciphertext_b)
    for index, (old, new) in enumerate(zip(known, desired)):
        position = offset + index
        delta = old ^ new
        if position < block_size:
            forged_iv[position] ^= delta
        else:
            forged_ct[position - block_size] ^= delta
    result = (bytes(forged_iv), bytes(forged_ct))
    accepted = _call_bool(verify, *result)
    if accepted is not True:
        return None
    negative_iv = bytes([result[0][0] ^ 1]) + result[0][1:]
    rejected = _call_bool(verify, negative_iv, result[1])
    if rejected is not False:
        return None
    return result


def detect_cbc_iv_reuse(records) -> Optional[tuple[IVReuseFinding, ...]]:
    items = _bounded_items(records, MAX_TRANSCRIPTS)
    if items is None or not items:
        return None
    groups: dict[bytes, list[int]] = {}
    iv_size = None
    total = 0
    for index, item in enumerate(items):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            return None
        iv, ciphertext = _bytes(item[0]), _bytes(item[1])
        if iv is None or ciphertext is None or not iv or not ciphertext:
            return None
        if len(iv) > MAX_BLOCK_SIZE:
            return None
        if iv_size is None:
            iv_size = len(iv)
        if len(iv) != iv_size or len(ciphertext) % iv_size:
            return None
        total += len(iv) + len(ciphertext)
        if total > MAX_INPUT_BYTES:
            return None
        groups.setdefault(iv, []).append(index)
    return tuple(IVReuseFinding(iv, tuple(indices)) for iv, indices in sorted(groups.items())
                 if len(indices) > 1)


def recover_cbc_iv(
    plaintext_block, ciphertext_block, decrypt_block: Callable,
    encrypt_block: Callable, verify: Callable[[bytes], bool],
) -> Optional[bytes]:
    plaintext, ciphertext = _bytes(plaintext_block), _bytes(ciphertext_block)
    if (plaintext is None or ciphertext is None or not plaintext
            or len(plaintext) != len(ciphertext) or len(plaintext) > MAX_BLOCK_SIZE):
        return None
    intermediate = _call_bytes(decrypt_block, ciphertext, expected=len(ciphertext))
    if intermediate is None:
        return None
    candidate = _xor(intermediate, plaintext)
    if _call_bytes(encrypt_block, _xor(plaintext, candidate), expected=len(ciphertext)) != ciphertext:
        return None
    return candidate if _verified_bytes(candidate, verify) else None


def recover_cbc_iv_equals_key(
    crafted_ciphertext, leaked_plaintext, verify_key: Callable[[bytes], bool], *, block_size: int = 16,
) -> Optional[bytes]:
    ciphertext, plaintext = _bytes(crafted_ciphertext), _bytes(leaked_plaintext)
    if (ciphertext is None or plaintext is None or isinstance(block_size, bool)
            or not isinstance(block_size, int) or not 1 <= block_size <= MAX_BLOCK_SIZE
            or len(ciphertext) != 3 * block_size or len(plaintext) != 3 * block_size):
        return None
    c1, c2, c3 = (ciphertext[index * block_size:(index + 1) * block_size] for index in range(3))
    if c1 != c3 or c2 != bytes(block_size):
        return None
    p1, p3 = plaintext[:block_size], plaintext[2 * block_size:3 * block_size]
    candidate = _xor(p1, p3)
    return candidate if _verified_bytes(candidate, verify_key) else None


def recover_ctr_ofb_reuse_plaintext(
    known_plaintext, known_ciphertext, target_ciphertext,
    verify: Callable[[bytes], bool], *, mode: str,
) -> Optional[bytes]:
    known, known_ct, target = (_bytes(known_plaintext), _bytes(known_ciphertext),
                               _bytes(target_ciphertext))
    if (not isinstance(mode, str) or mode.lower() not in {"ctr", "ofb"}
            or known is None or known_ct is None
            or target is None or not target or len(known) != len(known_ct)
            or len(target) > len(known)):
        return None
    keystream = _xor(known, known_ct)
    plaintext = _xor(target, keystream)
    if _xor(plaintext, keystream) != target:
        return None
    return plaintext if _verified_bytes(plaintext, verify) else None


def recover_cfb_reused_segment(
    known_plaintext, known_ciphertext, target_ciphertext,
    known_feedback, target_feedback, verify: Callable[[bytes], bool],
) -> Optional[bytes]:
    known, known_ct, target = (_bytes(known_plaintext), _bytes(known_ciphertext),
                               _bytes(target_ciphertext))
    feedback, target_fb = _bytes(known_feedback), _bytes(target_feedback)
    if (known is None or known_ct is None or target is None or feedback is None or target_fb is None
            or not known or len(known) != len(known_ct) or len(target) != len(known)
            or not feedback or len(feedback) > MAX_BLOCK_SIZE or feedback != target_fb
            or len(known) > len(feedback)):
        return None
    keystream = _xor(known, known_ct)
    plaintext = _xor(target, keystream)
    if _xor(plaintext, keystream) != target:
        return None
    return plaintext if _verified_bytes(plaintext, verify) else None


# -- supplied-sample stream distinguisher ----------------------------------

def distinguish_stream_samples(
    samples, predicate: Callable[[bytes], bool], *,
    expected_probability: float = 0.5, z_threshold: float = 3.0,
) -> Optional[StreamDistinguisherReport]:
    items = _bounded_items(samples, MAX_STREAM_SAMPLES)
    if items is None or len(items) < 2 or not callable(predicate):
        return None
    if (isinstance(expected_probability, bool)
            or not isinstance(expected_probability, (int, float))
            or not 0 < float(expected_probability) < 1
            or isinstance(z_threshold, bool) or not isinstance(z_threshold, (int, float))
            or not math.isfinite(float(z_threshold)) or z_threshold <= 0):
        return None
    normal = []
    total = 0
    for item in items:
        value = _bytes(item)
        if value is None or not value:
            return None
        total += len(value)
        if total > MAX_INPUT_BYTES:
            return None
        normal.append(value)
    hits = 0
    for value in normal:
        try:
            result = predicate(value)
        except Exception:
            return None
        if isinstance(result, bool):
            hits += result
        elif isinstance(result, int) and result in (0, 1):
            hits += result
        else:
            return None
    probability = float(expected_probability)
    denominator = math.sqrt(len(normal) * probability * (1.0 - probability))
    z_score = (hits - len(normal) * probability) / denominator
    threshold = float(z_threshold)
    return StreamDistinguisherReport(
        len(normal), hits, probability, z_score, threshold, abs(z_score) >= threshold
    )
