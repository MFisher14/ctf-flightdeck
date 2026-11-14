"""Verified, bounded stream-cipher and LFSR recovery primitives.

The module is deliberately offline and transport-free.  Candidate generation
(linear algebra, correlation ordering, statistical voting) is never sufficient
for emission: recovered recurrences, states, keys, and keystreams are replayed
against every original observation, and multiple exact explanations return
``None``.

Conventions
-----------
An LFSR is represented by its first ``L`` output bits and recurrence

``s[n] = c[0]*s[n-1] XOR ... XOR c[L-1]*s[n-L]``.

This makes Berlekamp--Massey output directly reusable by every generator helper.
RC4 follows the byte-for-byte KSA/PRGA definition; FMS packets use WEP-style
``RC4(iv || secret_key)`` with a three-byte IV.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence


MAX_BITS = 65_536
MAX_LFSR_LENGTH = 64
MAX_BM_WORK = 8_000_000
MAX_ENUM_LFSR_LENGTH = 12
MAX_STATE_CANDIDATES = 65_536
MAX_GENERATOR_COMBINATIONS = 1_000_000
MAX_GENERATOR_WORK = 8_000_000
MAX_FILTER_INPUTS = 12
MAX_RC4_BYTES = 1 << 20
MAX_RC4_PACKETS = 4096
MAX_RC4_KEY_BYTES = 256
MAX_FMS_SECRET_BYTES = 16
MAX_PACKET_BYTES = 256
MAX_BIAS_SAMPLES = 65_536


__all__ = [
    "LFSRRecovery",
    "RC4BiasReport",
    "berlekamp_massey",
    "lfsr_generate",
    "recover_lfsr",
    "geffe_combine",
    "recover_geffe_states",
    "recover_filtered_lfsr_state",
    "shrinking_generate",
    "recover_shrinking_generator",
    "alternating_generate",
    "recover_alternating_generator",
    "rc4_ksa",
    "rc4_prga",
    "rc4_keystream",
    "rc4_crypt",
    "recover_rc4_fms_key",
    "analyze_rc4_bias",
    "recover_known_plaintext_keystream",
]


@dataclass(frozen=True)
class LFSRRecovery:
    length: int
    state: tuple[int, ...]
    coefficients: tuple[int, ...]


@dataclass(frozen=True)
class RC4BiasReport:
    position: int
    sample_count: int
    counts: tuple[int, ...]
    most_common: tuple[int, ...]
    chi_square: float
    zero_frequency: float


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


def _strict_bool(callback: Callable, *args) -> bool:
    if not callable(callback):
        return False
    try:
        answer = callback(*args)
    except Exception:
        return False
    return answer is True or (isinstance(answer, int) and not isinstance(answer, bool) and answer == 1)


def _bits(values, *, allow_empty: bool = False, limit: int = MAX_BITS):
    items = _bounded_items(values, limit)
    if items is None or (not items and not allow_empty):
        return None
    if any(isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1)
           for value in items):
        return None
    return tuple(items)


def _bytes(value, *, maximum: int = MAX_RC4_BYTES) -> Optional[bytes]:
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(value) > maximum:
        return None
    return bytes(value)


def _state_from_int(value: int, length: int) -> Optional[tuple[int, ...]]:
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < 0 or value >= (1 << length)):
        return None
    return tuple((value >> (length - 1 - index)) & 1 for index in range(length))


def _normalise_state(value, length: int) -> Optional[tuple[int, ...]]:
    if isinstance(value, int) and not isinstance(value, bool):
        return _state_from_int(value, length)
    bits = _bits(value, limit=length)
    return bits if bits is not None and len(bits) == length else None


def _normalise_coefficients(coefficients) -> Optional[tuple[int, ...]]:
    coeffs = _bits(coefficients, limit=MAX_LFSR_LENGTH)
    if (coeffs is None or not 1 <= len(coeffs) <= MAX_LFSR_LENGTH
            or coeffs[-1] != 1):
        return None
    return coeffs


# -- exact LFSR recovery -----------------------------------------------------

def berlekamp_massey(sequence: Iterable[int]) -> Optional[tuple[int, ...]]:
    """Return the minimal GF(2) recurrence after exact replay verification.

    The all-zero sequence has linear complexity zero and returns ``()``.  Bad
    input or a recurrence that does not replay the finite observation declines.
    """
    bits = _bits(sequence)
    if bits is None:
        return None
    size = len(bits)
    # Keep connection polynomials compact.  A size-N allocation/copy at every
    # discrepancy turns a long, low-complexity trace into quadratic work even
    # though the supported polynomial degree is only 64.
    connection = [1]
    previous = [1]
    complexity, last_update = 0, -1
    work = 0
    for index in range(size):
        work += complexity + 1
        if work > MAX_BM_WORK:
            return None
        discrepancy = bits[index]
        for offset in range(1, complexity + 1):
            discrepancy ^= (connection[offset] if offset < len(connection) else 0) & bits[index - offset]
        if discrepancy == 0:
            continue
        old = connection[:]
        shift = index - last_update
        required = shift + len(previous)
        if required > MAX_LFSR_LENGTH + 1:
            return None
        work += len(connection) + len(previous)
        if work > MAX_BM_WORK:
            return None
        connection.extend([0] * (required - len(connection)))
        for position, value in enumerate(previous):
            connection[position + shift] ^= value
        if 2 * complexity <= index:
            complexity = index + 1 - complexity
            if complexity > MAX_LFSR_LENGTH:
                return None
            previous = old
            last_update = index
    coefficients = tuple(connection[1:complexity + 1])
    if complexity == 0:
        return () if not any(bits) else None
    if coefficients[-1] != 1 or complexity > len(bits):
        return None
    replay = lfsr_generate(bits[:complexity], coefficients, len(bits))
    return coefficients if replay == bits else None


def lfsr_generate(state, coefficients, count: int) -> Optional[tuple[int, ...]]:
    """Generate ``count`` bits under the module's recurrence convention."""
    coeffs = _normalise_coefficients(coefficients)
    if (coeffs is None or isinstance(count, bool) or not isinstance(count, int)
            or not 0 <= count <= MAX_BITS):
        return None
    initial = _normalise_state(state, len(coeffs))
    if initial is None:
        return None
    output = list(initial[:count])
    while len(output) < count:
        output.append(sum(coeffs[index] & output[-1 - index]
                          for index in range(len(coeffs))) & 1)
    return tuple(output)


def _gf2_status(rows: Sequence[int], rhs: Sequence[int], width: int):
    """Return (status, solution), status in {'none','multiple','unique'}."""
    # Compact augmented integer rows avoid millions of Python int objects for a
    # long capture. Bits 0..width-1 are coefficients; bit width is the RHS.
    matrix = [row | (value << width) for row, value in zip(rows, rhs)]
    coefficient_mask = (1 << width) - 1
    pivots: list[int] = []
    pivot_row = 0
    for column in range(width):
        found = next((row for row in range(pivot_row, len(matrix))
                      if (matrix[row] >> column) & 1), None)
        if found is None:
            continue
        matrix[pivot_row], matrix[found] = matrix[found], matrix[pivot_row]
        for row in range(len(matrix)):
            if row != pivot_row and ((matrix[row] >> column) & 1):
                matrix[row] ^= matrix[pivot_row]
        pivots.append(column)
        pivot_row += 1
    if any(not (row & coefficient_mask) and ((row >> width) & 1) for row in matrix):
        return "none", None
    if len(pivots) < width:
        return "multiple", None
    solution = [0] * width
    for row, column in enumerate(pivots):
        solution[column] = (matrix[row] >> width) & 1
    return "unique", tuple(solution)


def _recurrence_system(bits: tuple[int, ...], length: int):
    rows, rhs = [], []
    for index in range(length, len(bits)):
        row = 0
        for offset in range(1, length + 1):
            row |= bits[index - offset] << (offset - 1)
        rows.append(row)
        rhs.append(bits[index])
    return rows, rhs


def recover_lfsr(sequence: Iterable[int], *, max_length: int = MAX_LFSR_LENGTH) -> Optional[LFSRRecovery]:
    """Recover the unique minimal recurrence and observed initial state.

    Berlekamp--Massey proposes the minimal length; independent GF(2) Gaussian
    elimination must show its taps are unique, no shorter recurrence may fit,
    at least ``2L`` bits are required, and full replay must match.
    """
    bits = _bits(sequence)
    if (bits is None or isinstance(max_length, bool) or not isinstance(max_length, int)
            or not 1 <= max_length <= MAX_LFSR_LENGTH):
        return None
    coefficients = berlekamp_massey(bits)
    if coefficients is None or not coefficients:
        return None
    length = len(coefficients)
    if length > max_length or len(bits) < 2 * length:
        return None
    rows, rhs = _recurrence_system(bits, length)
    status, solved = _gf2_status(rows, rhs, length)
    if status != "unique" or solved != coefficients:
        return None
    # Any recurrence shorter than L also solves the (L-1)-wide system after
    # zero-padding its high coefficients, so one consistency check proves that
    # no shorter recurrence exists without repeating elimination L times.
    if length > 1:
        small_rows, small_rhs = _recurrence_system(bits, length - 1)
        small_status, _ = _gf2_status(small_rows, small_rhs, length - 1)
        if small_status != "none":
            return None
    state = bits[:length]
    if lfsr_generate(state, coefficients, len(bits)) != bits:
        return None
    return LFSRRecovery(length, state, coefficients)


def _enumerated_states(length: int, allow_zero: bool = False):
    if not 1 <= length <= MAX_ENUM_LFSR_LENGTH:
        return None
    start = 0 if allow_zero else 1
    return tuple(_state_from_int(value, length) for value in range(start, 1 << length))


def _candidate_states(values, length: int, *, allow_zero: bool = False):
    if values is None:
        return _enumerated_states(length, allow_zero)
    items = _bounded_items(values, MAX_STATE_CANDIDATES)
    if items is None or not items:
        return None
    states = []
    for value in items:
        state = _normalise_state(value, length)
        if state is None or (not allow_zero and not any(state)):
            return None
        states.append(state)
    return tuple(dict.fromkeys(states))


# -- combining and nonlinear generators ------------------------------------

def geffe_combine(selector, if_one, if_zero) -> Optional[tuple[int, ...]]:
    x, y, z = _bits(selector), _bits(if_one), _bits(if_zero)
    if x is None or y is None or z is None or not (len(x) == len(y) == len(z)):
        return None
    return tuple(ybit if choose else zbit for choose, ybit, zbit in zip(x, y, z))


def recover_geffe_states(
    observed,
    selector_coefficients,
    if_one_coefficients,
    if_zero_coefficients,
    *,
    max_combinations: int = MAX_GENERATOR_COMBINATIONS,
    verify: Optional[Callable[[tuple[tuple[int, ...], ...]], bool]] = None,
) -> Optional[tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]]:
    """Bounded correlation-ordered Geffe recovery with exact full replay."""
    target = _bits(observed)
    coeffs = tuple(_normalise_coefficients(value) for value in
                   (selector_coefficients, if_one_coefficients, if_zero_coefficients))
    if target is None or any(value is None for value in coeffs):
        return None
    states = tuple(_enumerated_states(len(value)) for value in coeffs)
    if any(value is None for value in states):
        return None
    combinations = math.prod(len(value) for value in states)
    if (isinstance(max_combinations, bool) or not isinstance(max_combinations, int)
            or max_combinations < 1 or max_combinations > MAX_GENERATOR_COMBINATIONS
            or combinations > max_combinations):
        return None
    if (sum(len(group) * len(target) for group in states) > MAX_GENERATOR_WORK
            or combinations * max(1, len(target)) > MAX_GENERATOR_WORK):
        return None
    streams = [
        [(state, lfsr_generate(state, coefficient, len(target))) for state in group]
        for group, coefficient in zip(states, coeffs)
    ]
    # Geffe output is correlated with both data registers.  Correlation orders
    # the exhaustive bounded search, while only exact replay can accept a tuple.
    for index in (1, 2):
        streams[index].sort(
            key=lambda item: sum(a == b for a, b in zip(item[1], target)), reverse=True
        )
    matches = set()
    for selector_state, selector_stream in streams[0]:
        for one_state, one_stream in streams[1]:
            for zero_state, zero_stream in streams[2]:
                if geffe_combine(selector_stream, one_stream, zero_stream) != target:
                    continue
                result = (selector_state, one_state, zero_state)
                if verify is None or _strict_bool(verify, result):
                    matches.add(result)
                    if len(matches) > 1:
                        return None
    return next(iter(matches)) if len(matches) == 1 else None


def recover_filtered_lfsr_state(
    observed,
    coefficients,
    filter_offsets: Sequence[int],
    truth_table: Sequence[int],
    candidate_states,
    *,
    verify: Optional[Callable[[tuple[int, ...]], bool]] = None,
) -> Optional[tuple[int, ...]]:
    """Recover a nonlinear-filter LFSR state from supplied bounded candidates.

    At time ``t`` the truth-table index is formed, most-significant input first,
    from ``stream[t + offset]`` for every supplied offset.
    """
    target, coeffs = _bits(observed), _normalise_coefficients(coefficients)
    offsets = _bounded_items(filter_offsets, MAX_FILTER_INPUTS)
    table = _bits(truth_table, limit=1 << MAX_FILTER_INPUTS)
    if target is None or coeffs is None or offsets is None or not offsets or table is None:
        return None
    if (any(isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in offsets)
            or len(set(offsets)) != len(offsets)
            or len(table) != 1 << len(offsets)
            or max(offsets) >= MAX_BITS - len(target)):
        return None
    states = _candidate_states(candidate_states, len(coeffs))
    if states is None:
        return None
    if len(states) * (len(target) + max(offsets)) > MAX_GENERATOR_WORK:
        return None
    matches = set()
    for state in states:
        stream = lfsr_generate(state, coeffs, len(target) + max(offsets))
        if stream is None:
            return None
        produced = []
        for time in range(len(target)):
            index = 0
            for offset in offsets:
                index = (index << 1) | stream[time + offset]
            produced.append(table[index])
        if tuple(produced) == target and (verify is None or _strict_bool(verify, state)):
            matches.add(state)
            if len(matches) > 1:
                return None
    return next(iter(matches)) if len(matches) == 1 else None


def shrinking_generate(
    control_state,
    control_coefficients,
    data_state,
    data_coefficients,
    count: int,
    *,
    max_steps: Optional[int] = None,
) -> Optional[tuple[int, ...]]:
    """Generate the classic shrinking generator (emit data when control=1)."""
    ccoeff, dcoeff = (_normalise_coefficients(control_coefficients),
                      _normalise_coefficients(data_coefficients))
    if (ccoeff is None or dcoeff is None or isinstance(count, bool)
            or not isinstance(count, int) or not 0 <= count <= MAX_BITS):
        return None
    cstate = _normalise_state(control_state, len(ccoeff))
    dstate = _normalise_state(data_state, len(dcoeff))
    if cstate is None or dstate is None:
        return None
    limit = max_steps if max_steps is not None else min(MAX_BITS, max(64, count * 8 + 16))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 0 <= limit <= MAX_BITS:
        return None
    control = lfsr_generate(cstate, ccoeff, limit)
    data = lfsr_generate(dstate, dcoeff, limit)
    output = [data[index] for index in range(limit) if control[index]][:count]
    return tuple(output) if len(output) == count else None


def recover_shrinking_generator(
    observed,
    control_coefficients,
    data_coefficients,
    *,
    max_combinations: int = MAX_GENERATOR_COMBINATIONS,
) -> Optional[tuple[tuple[int, ...], tuple[int, ...]]]:
    target = _bits(observed)
    ccoeff, dcoeff = (_normalise_coefficients(control_coefficients),
                      _normalise_coefficients(data_coefficients))
    if target is None or ccoeff is None or dcoeff is None:
        return None
    controls, data_states = (_enumerated_states(len(ccoeff)), _enumerated_states(len(dcoeff)))
    if controls is None or data_states is None:
        return None
    combinations = len(controls) * len(data_states)
    if (isinstance(max_combinations, bool) or not isinstance(max_combinations, int)
            or max_combinations < 1 or max_combinations > MAX_GENERATOR_COMBINATIONS
            or combinations > max_combinations):
        return None
    if combinations * max(1, len(target)) * 8 > MAX_GENERATOR_WORK:
        return None
    matches = set()
    for cstate in controls:
        for dstate in data_states:
            if shrinking_generate(cstate, ccoeff, dstate, dcoeff, len(target)) == target:
                matches.add((cstate, dstate))
                if len(matches) > 1:
                    return None
    return next(iter(matches)) if len(matches) == 1 else None


def alternating_generate(
    selector_state,
    selector_coefficients,
    first_state,
    first_coefficients,
    second_state,
    second_coefficients,
    count: int,
) -> Optional[tuple[int, ...]]:
    """Generate an alternating-step combiner; only the selected data LFSR advances."""
    coeffs = tuple(_normalise_coefficients(value) for value in
                   (selector_coefficients, first_coefficients, second_coefficients))
    if (any(value is None for value in coeffs) or isinstance(count, bool)
            or not isinstance(count, int) or not 0 <= count <= MAX_BITS):
        return None
    states = tuple(_normalise_state(value, len(coefficient))
                   for value, coefficient in zip(
                       (selector_state, first_state, second_state), coeffs))
    if any(value is None for value in states):
        return None
    streams = tuple(lfsr_generate(state, coefficient, count)
                    for state, coefficient in zip(states, coeffs))
    first_index = second_index = 0
    output = []
    for choose in streams[0]:
        if choose:
            output.append(streams[1][first_index])
            first_index += 1
        else:
            output.append(streams[2][second_index])
            second_index += 1
    return tuple(output)


def recover_alternating_generator(
    observed,
    selector_coefficients,
    first_coefficients,
    second_coefficients,
    *,
    max_combinations: int = MAX_GENERATOR_COMBINATIONS,
) -> Optional[tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]]:
    target = _bits(observed)
    coeffs = tuple(_normalise_coefficients(value) for value in
                   (selector_coefficients, first_coefficients, second_coefficients))
    if target is None or any(value is None for value in coeffs):
        return None
    states = tuple(_enumerated_states(len(value)) for value in coeffs)
    if any(value is None for value in states):
        return None
    combinations = math.prod(len(value) for value in states)
    if (isinstance(max_combinations, bool) or not isinstance(max_combinations, int)
            or max_combinations < 1 or max_combinations > MAX_GENERATOR_COMBINATIONS
            or combinations > max_combinations):
        return None
    if combinations * max(1, len(target)) > MAX_GENERATOR_WORK:
        return None
    matches = set()
    for selector in states[0]:
        for first in states[1]:
            for second in states[2]:
                if alternating_generate(selector, coeffs[0], first, coeffs[1],
                                        second, coeffs[2], len(target)) == target:
                    matches.add((selector, first, second))
                    if len(matches) > 1:
                        return None
    return next(iter(matches)) if len(matches) == 1 else None


# -- RC4 and FMS -------------------------------------------------------------

def rc4_ksa(key) -> Optional[tuple[int, ...]]:
    key_bytes = _bytes(key, maximum=MAX_RC4_KEY_BYTES)
    if key_bytes is None or not key_bytes:
        return None
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key_bytes[index % len(key_bytes)]) & 0xFF
        state[index], state[j] = state[j], state[index]
    return tuple(state)


def rc4_prga(state, count: int, *, drop: int = 0) -> Optional[bytes]:
    values = _bounded_items(state, 256)
    if (values is None or len(values) != 256
            or any(isinstance(value, bool) or not isinstance(value, int) for value in values)
            or set(values) != set(range(256))
            or isinstance(count, bool) or not isinstance(count, int)
            or isinstance(drop, bool) or not isinstance(drop, int)
            or count < 0 or drop < 0 or count + drop > MAX_RC4_BYTES):
        return None
    permutation = list(values)
    i = j = 0
    output = bytearray()
    for index in range(count + drop):
        i = (i + 1) & 0xFF
        j = (j + permutation[i]) & 0xFF
        permutation[i], permutation[j] = permutation[j], permutation[i]
        value = permutation[(permutation[i] + permutation[j]) & 0xFF]
        if index >= drop:
            output.append(value)
    return bytes(output)


def rc4_keystream(key, count: int, *, drop: int = 0) -> Optional[bytes]:
    state = rc4_ksa(key)
    return None if state is None else rc4_prga(state, count, drop=drop)


def rc4_crypt(key, data, *, drop: int = 0) -> Optional[bytes]:
    payload = _bytes(data)
    if payload is None:
        return None
    stream = rc4_keystream(key, len(payload), drop=drop)
    return None if stream is None else bytes(a ^ b for a, b in zip(payload, stream))


def _normalise_fms_packets(packets):
    items = _bounded_items(packets, MAX_RC4_PACKETS)
    if items is None or not items:
        return None
    out = []
    seen_ivs = set()
    total = 0
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 3:
            return None
        iv, ciphertext, plaintext = (_bytes(item[0], maximum=3),
                                     _bytes(item[1], maximum=MAX_PACKET_BYTES),
                                     _bytes(item[2], maximum=MAX_PACKET_BYTES))
        if iv is None or len(iv) != 3 or ciphertext is None or plaintext is None:
            return None
        if not ciphertext or len(ciphertext) != len(plaintext):
            return None
        # Duplicate weak IVs are not independent statistical evidence and can
        # otherwise manufacture an arbitrary vote margin.
        if iv in seen_ivs:
            return None
        seen_ivs.add(iv)
        total += len(iv) + len(ciphertext) + len(plaintext)
        if total > MAX_RC4_BYTES:
            return None
        out.append((iv, ciphertext, plaintext))
    return tuple(out)


def recover_rc4_fms_key(
    packets,
    secret_length: int,
    *,
    min_packets_per_byte: int = 16,
    min_votes: int = 3,
    min_margin: int = 1,
) -> Optional[bytes]:
    """Recover a WEP-style RC4 secret through FMS voting, then exact replay.

    Only packets with IV ``(A+3, 0xff, N)`` vote for secret byte ``A``.  Every
    byte needs one strict top vote with the requested margin.  The completed
    key is emitted only when ``RC4(iv || key)`` reproduces every supplied
    ciphertext from its full known plaintext.
    """
    observations = _normalise_fms_packets(packets)
    integers = (secret_length, min_packets_per_byte, min_votes, min_margin)
    if (observations is None or any(isinstance(value, bool) or not isinstance(value, int)
                                    for value in integers)
            or not 1 <= secret_length <= MAX_FMS_SECRET_BYTES
            or min_packets_per_byte < 1 or min_votes < 1 or min_margin < 1):
        return None
    recovered = bytearray()
    for target_index in range(secret_length):
        relevant = [item for item in observations
                    if item[0][0] == target_index + 3 and item[0][1] == 0xFF]
        if len(relevant) < min_packets_per_byte:
            return None
        votes: Counter[int] = Counter()
        for iv, ciphertext, plaintext in relevant:
            first_keystream = ciphertext[0] ^ plaintext[0]
            partial_key = iv + bytes(recovered)
            state = list(range(256))
            j = 0
            for round_index in range(target_index + 3):
                j = (j + state[round_index] + partial_key[round_index]) & 0xFF
                state[round_index], state[j] = state[j], state[round_index]
            candidate = (first_keystream - j - state[target_index + 3]) & 0xFF
            votes[candidate] += 1
        ordered = votes.most_common()
        if not ordered or ordered[0][1] < min_votes:
            return None
        runner_up = ordered[1][1] if len(ordered) > 1 else 0
        if ordered[0][1] - runner_up < min_margin:
            return None
        recovered.append(ordered[0][0])
    secret = bytes(recovered)
    for iv, ciphertext, plaintext in observations:
        if rc4_crypt(iv + secret, plaintext) != ciphertext:
            return None
    return secret


def analyze_rc4_bias(samples, *, position: int = 1) -> Optional[RC4BiasReport]:
    """Return an exact byte-frequency/chi-square report for one RC4 position."""
    if isinstance(position, bool) or not isinstance(position, int) or position < 0:
        return None
    items = _bounded_items(samples, MAX_BIAS_SAMPLES)
    if items is None or len(items) < 2:
        return None
    counts = [0] * 256
    total_bytes = 0
    for sample in items:
        data = _bytes(sample)
        if data is None or len(data) <= position:
            return None
        total_bytes += len(data)
        if total_bytes > MAX_RC4_BYTES:
            return None
        counts[data[position]] += 1
    expected = len(items) / 256.0
    chi_square = sum((count - expected) ** 2 / expected for count in counts)
    maximum = max(counts)
    common = tuple(index for index, count in enumerate(counts) if count == maximum)
    return RC4BiasReport(position, len(items), tuple(counts), common,
                         chi_square, counts[0] / len(items))


# -- known-plaintext stream proof ------------------------------------------

def recover_known_plaintext_keystream(
    observations,
    verify: Callable[[bytes], bool],
) -> Optional[bytes]:
    """Recover one reused keystream from exact plaintext/ciphertext pairs.

    Every observation starts at keystream offset zero.  All overlapping XORs
    must agree, the longest observation uniquely fixes every returned byte, and
    the caller's verifier must explicitly accept the final stream.
    """
    items = _bounded_items(observations, MAX_STATE_CANDIDATES)
    if items is None or not items or not callable(verify):
        return None
    derived = []
    total = 0
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            return None
        plaintext, ciphertext = _bytes(item[0]), _bytes(item[1])
        if plaintext is None or ciphertext is None or not plaintext or len(plaintext) != len(ciphertext):
            return None
        total += len(plaintext) + len(ciphertext)
        if total > MAX_RC4_BYTES:
            return None
        derived.append(bytes(a ^ b for a, b in zip(plaintext, ciphertext)))
    longest = max(derived, key=len)
    if any(longest[:len(stream)] != stream for stream in derived):
        return None
    if any(bytes(a ^ b for a, b in zip(plaintext, longest)) != ciphertext
           for plaintext, ciphertext in items):
        return None
    if not _strict_bool(verify, longest):
        return None
    # A callback that accepts everything contributes no independent evidence.
    # XOR already fixes the candidate uniquely; this negative control proves the
    # verifier at least discriminates the recovered stream from a near miss.
    negative_control = bytes([longest[0] ^ 1]) + longest[1:]
    if _strict_bool(verify, negative_control):
        return None
    return longest
