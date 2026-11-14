"""Bounded, offline-only side-channel and fault-structure analysis.

All inputs are already-captured observations.  This module has no acquisition,
instrumentation, hardware, process, network, or submission functionality.  Every
recovery uses strict work caps, a unique-best/margin rule, and a final replay of
all supplied evidence.  Ambiguous, non-finite, malformed, oversized, or failing
iterators/callbacks decline with ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite, sqrt
from numbers import Integral, Real
from typing import Callable, Iterable, Sequence


MAX_TRACES = 4096
MAX_SAMPLES = 8192
MAX_CANDIDATES = 4096
MAX_AES_BYTES = 32
MAX_CACHE_SETS = 256
MAX_OPERATIONS = 64
MAX_VECTOR_DIMENSION = 256
MAX_WORK = 100_000_000
MAX_TRACE_CELLS = 8_000_000
MAX_INTEGER = (1 << 63) - 1
MAX_INTEGER_BITS = MAX_INTEGER.bit_length()


_AES_SBOX = tuple(
    bytes.fromhex(
        "637c777bf26b6fc53001672bfed7ab76"
        "ca82c97dfa5947f0add4a2af9ca472c0"
        "b7fd9326363ff7cc34a5e5f171d83115"
        "04c723c31896059a071280e2eb27b275"
        "09832c1a1b6e5aa0523bd6b329e32f84"
        "53d100ed20fcb15b6acbbe394a4c58cf"
        "d0efaafb434d338545f9027f503c9fa8"
        "51a3408f929d38f5bcb6da2110fff3d2"
        "cd0c13ec5f974417c4a77e3d645d1973"
        "60814fdc222a908846eeb814de5e0bdb"
        "e0323a0a4906245cc2d3ac629195e479"
        "e7c8376d8dd54ea96c56f4ea657aae08"
        "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
        "703eb5664803f60e613557b986c11d9e"
        "e1f8981169d98e949b1e87e9ce5528df"
        "8ca1890dbfe6426841992d0fb054bb16"
    )
)


@dataclass(frozen=True)
class FaultCluster:
    """One exact offline fault-difference cluster."""

    signature: tuple[int, ...]
    count: int
    indices: tuple[int, ...]


def _bounded_items(values, limit: int):
    try:
        iterator = iter(values)
    except Exception:
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


def _as_int(value) -> int:
    if isinstance(value, bool):
        raise TypeError("boolean is not integer evidence")
    if isinstance(value, Integral):
        result = int(value)
    elif isinstance(value, str):
        text = value.strip()
        unsigned = text[1:] if text[:1] in {"+", "-"} else text
        if not unsigned or not unsigned.isdecimal():
            raise TypeError("not decimal integer evidence")
        result = int(text, 10)
    else:
        raise TypeError("not exact integer evidence")
    if abs(result) > MAX_INTEGER:
        raise ValueError("integer evidence exceeds cap")
    return result


def _as_float(value) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError("not real-valued evidence")
    result = float(value)
    if not isfinite(result):
        raise ValueError("non-finite evidence")
    return result


def _float_vector(values, *, length=None, limit=MAX_TRACES):
    raw = _bounded_items(values, limit)
    if raw is None:
        return None
    try:
        result = tuple(_as_float(value) for value in raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if len(result) < 2 or (length is not None and len(result) != length):
        return None
    return result


def _int_vector(values, *, length=None, limit=MAX_TRACES, low=None, high=None):
    raw = _bounded_items(values, limit)
    if raw is None:
        return None
    try:
        result = tuple(_as_int(value) for value in raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if not result or (length is not None and len(result) != length):
        return None
    if low is not None and any(value < low for value in result):
        return None
    if high is not None and any(value > high for value in result):
        return None
    return result


def _trace_matrix(traces, *, rows=None):
    outer = _bounded_items(traces, MAX_TRACES)
    if outer is None or len(outer) < 2 or (rows is not None and len(outer) != rows):
        return None
    parsed = []
    width = None
    try:
        for trace in outer:
            raw = _bounded_items(trace, MAX_SAMPLES)
            if raw is None:
                return None
            row = tuple(_as_float(value) for value in raw)
            if width is None:
                width = len(row)
            if not 1 <= len(row) <= MAX_SAMPLES or len(row) != width:
                return None
            if len(outer) * width > MAX_TRACE_CELLS:
                return None
            parsed.append(row)
    except (TypeError, ValueError, OverflowError):
        return None
    return tuple(parsed)


def _pearson_raw(left: Sequence[float], right: Sequence[float]) -> float | None:
    if len(left) != len(right) or len(left) < 2:
        return None
    mean_left = sum(left) / len(left)
    mean_right = sum(right) / len(right)
    numerator = sum((x - mean_left) * (y - mean_right) for x, y in zip(left, right))
    left_norm = sum((x - mean_left) ** 2 for x in left)
    right_norm = sum((y - mean_right) ** 2 for y in right)
    if left_norm <= 0.0 or right_norm <= 0.0:
        return None
    result = numerator / sqrt(left_norm * right_norm)
    if not isfinite(result):
        return None
    return max(-1.0, min(1.0, result))


def pearson_correlation(left, right) -> float | None:
    """Pearson correlation with finite-input and NumPy/SciPy cross-checks."""

    x = _float_vector(left)
    y = _float_vector(right, length=len(x) if x else None)
    if x is None or y is None:
        return None
    result = _pearson_raw(x, y)
    if result is None:
        return None
    try:
        import numpy as np

        independent = float(np.corrcoef(np.asarray(x), np.asarray(y))[0, 1])
        if not isfinite(independent) or abs(independent - result) > 1e-10:
            return None
    except ImportError:
        pass
    try:
        from scipy.stats import pearsonr

        independent = float(pearsonr(x, y).statistic)
        if not isfinite(independent) or abs(independent - result) > 1e-10:
            return None
    except ImportError:
        pass
    return result


def _average_ranks(values: Sequence[float]):
    ordered = sorted(range(len(values)), key=lambda index: (values[index], index))
    ranks = [0.0] * len(values)
    start = 0
    while start < len(ordered):
        end = start + 1
        while end < len(ordered) and values[ordered[end]] == values[ordered[start]]:
            end += 1
        rank = (start + 1 + end) / 2.0
        for offset in range(start, end):
            ranks[ordered[offset]] = rank
        start = end
    return tuple(ranks)


def spearman_correlation(left, right) -> float | None:
    """Tie-aware Spearman rank correlation with SciPy cross-check."""

    x = _float_vector(left)
    y = _float_vector(right, length=len(x) if x else None)
    if x is None or y is None:
        return None
    result = _pearson_raw(_average_ranks(x), _average_ranks(y))
    if result is None:
        return None
    try:
        from scipy.stats import spearmanr

        independent = float(spearmanr(x, y).statistic)
        if not isfinite(independent) or abs(independent - result) > 1e-10:
            return None
    except ImportError:
        pass
    return result


def _difference_of_means_normalized(matrix, groups):
    zeros = [matrix[index] for index, value in enumerate(groups) if value == 0]
    ones = [matrix[index] for index, value in enumerate(groups) if value == 1]
    if not zeros or not ones:
        return None
    return tuple(
        sum(row[sample] for row in ones) / len(ones)
        - sum(row[sample] for row in zeros) / len(zeros)
        for sample in range(len(matrix[0]))
    )


def difference_of_means(traces, groups) -> tuple[float, ...] | None:
    """Per-sample mean(group=1) - mean(group=0), requiring both groups."""

    matrix = _trace_matrix(traces)
    raw_groups = _bounded_items(groups, MAX_TRACES)
    if matrix is None or raw_groups is None or len(raw_groups) != len(matrix):
        return None
    parsed = []
    for value in raw_groups:
        if isinstance(value, bool):
            parsed.append(int(value))
        else:
            try:
                number = _as_int(value)
            except (TypeError, ValueError):
                return None
            if number not in (0, 1):
                return None
            parsed.append(number)
    result = _difference_of_means_normalized(matrix, parsed)
    if result is None:
        return None
    try:
        import numpy as np

        data = np.asarray(matrix, dtype=float)
        labels = np.asarray(parsed, dtype=int)
        independent = data[labels == 1].mean(axis=0) - data[labels == 0].mean(axis=0)
        if any(abs(float(independent[i]) - result[i]) > 1e-10 for i in range(len(result))):
            return None
    except ImportError:
        pass
    return result


def hamming_weight(value, width=None) -> int | None:
    """Hamming weight of a non-negative exact integer within an optional width."""

    try:
        number = _as_int(value)
        bits = None if width is None else _as_int(width)
    except (TypeError, ValueError):
        return None
    if number < 0 or (
        bits is not None
        and (bits < 1 or bits > MAX_INTEGER_BITS or number >= 1 << bits)
    ):
        return None
    return number.bit_count()


def hamming_distance(left, right, width=None) -> int | None:
    """Hamming distance of exact non-negative integers under an optional width."""

    try:
        first, second = _as_int(left), _as_int(right)
        bits = None if width is None else _as_int(width)
    except (TypeError, ValueError):
        return None
    if first < 0 or second < 0:
        return None
    if bits is not None and (
        bits < 1
        or bits > MAX_INTEGER_BITS
        or first >= 1 << bits
        or second >= 1 << bits
    ):
        return None
    return (first ^ second).bit_count()


def _gf_mul_byte(left: int, right: int) -> int:
    result = 0
    a, b = left, right
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def _aes_sbox_reference(value: int) -> int:
    inverse = 0 if value == 0 else 1
    if value:
        base, exponent = value, 254
        while exponent:
            if exponent & 1:
                inverse = _gf_mul_byte(inverse, base)
            base = _gf_mul_byte(base, base)
            exponent >>= 1
    result = inverse
    for shift in (1, 2, 3, 4):
        result ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
    return result ^ 0x63


def _aes_inputs(values):
    return _int_vector(values, limit=MAX_TRACES, low=0, high=255)


def _leakage_model(inputs, key: int, model: str):
    if model == "sbox_hw":
        return tuple(float(_AES_SBOX[value ^ key].bit_count()) for value in inputs)
    if model == "sbox_hd_input":
        return tuple(float((_AES_SBOX[value ^ key] ^ value).bit_count()) for value in inputs)
    return None


def _unique_max(scores, *, minimum: float, margin: float):
    if not scores or not isfinite(minimum) or not isfinite(margin) or margin < 0:
        return None
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    if not isfinite(ordered[0][1]) or ordered[0][1] < minimum:
        return None
    if len(ordered) > 1:
        difference = ordered[0][1] - ordered[1][1]
        if difference <= 0 or difference < margin:
            return None
    return ordered[0]


def _recover_aes_cpa(inputs, matrix, *, model, min_correlation, margin):
    if len(inputs) != len(matrix) or len(inputs) < 8:
        return None
    samples = len(matrix[0])
    if 256 * len(inputs) * samples > MAX_WORK:
        return None
    columns = tuple(tuple(matrix[row][sample] for row in range(len(matrix))) for sample in range(samples))
    scores = {}
    for key in range(256):
        leakage = _leakage_model(inputs, key, model)
        if leakage is None:
            return None
        correlations = [_pearson_raw(leakage, column) for column in columns]
        scores[key] = max((abs(value) for value in correlations if value is not None), default=-1.0)
    winner = _unique_max(scores, minimum=min_correlation, margin=margin)
    if winner is None:
        return None
    key, score = winner
    leakage = _leakage_model(inputs, key, model)
    replay = [pearson_correlation(leakage, column) for column in columns]
    replay_score = max((abs(value) for value in replay if value is not None), default=-1.0)
    if abs(replay_score - score) > 1e-10:
        return None
    if any(_AES_SBOX[value ^ key] != _aes_sbox_reference(value ^ key) for value in inputs):
        return None
    return key


def recover_aes_sbox_byte_cpa(
    input_bytes,
    traces,
    *,
    leakage_model="sbox_hw",
    min_correlation=0.2,
    margin=0.03,
) -> int | None:
    """Recover one AES S-box key byte by bounded CPA and full model replay."""

    inputs = _aes_inputs(input_bytes)
    matrix = _trace_matrix(traces, rows=len(inputs) if inputs else None)
    try:
        minimum, separation = _as_float(min_correlation), _as_float(margin)
    except (TypeError, ValueError):
        return None
    if inputs is None or matrix is None or leakage_model not in {"sbox_hw", "sbox_hd_input"}:
        return None
    return _recover_aes_cpa(
        inputs, matrix, model=leakage_model, min_correlation=minimum, margin=separation
    )


def _recover_aes_dpa(inputs, matrix, *, bit_index, min_effect, margin):
    if len(inputs) != len(matrix) or len(inputs) < 8 or not 0 <= bit_index <= 7:
        return None
    if 256 * len(inputs) * len(matrix[0]) > MAX_WORK:
        return None
    scores = {}
    for key in range(256):
        groups = tuple((_AES_SBOX[value ^ key] >> bit_index) & 1 for value in inputs)
        effect = _difference_of_means_normalized(matrix, groups)
        scores[key] = max((abs(value) for value in effect), default=-1.0) if effect else -1.0
    winner = _unique_max(scores, minimum=min_effect, margin=margin)
    if winner is None:
        return None
    key, score = winner
    groups = tuple((_AES_SBOX[value ^ key] >> bit_index) & 1 for value in inputs)
    effect = difference_of_means(matrix, groups)
    replay_score = max((abs(value) for value in effect), default=-1.0) if effect else -1.0
    if abs(score - replay_score) > 1e-10:
        return None
    if any(_AES_SBOX[value ^ key] != _aes_sbox_reference(value ^ key) for value in inputs):
        return None
    return key


def recover_aes_sbox_byte_dpa(
    input_bytes,
    traces,
    *,
    bit_index=0,
    min_effect=0.5,
    margin=0.05,
) -> int | None:
    """Recover one AES S-box key byte by bit-partition difference-of-means."""

    inputs = _aes_inputs(input_bytes)
    matrix = _trace_matrix(traces, rows=len(inputs) if inputs else None)
    try:
        bit = _as_int(bit_index)
        minimum, separation = _as_float(min_effect), _as_float(margin)
    except (TypeError, ValueError):
        return None
    if inputs is None or matrix is None:
        return None
    return _recover_aes_dpa(
        inputs, matrix, bit_index=bit, min_effect=minimum, margin=separation
    )


def _plaintext_matrix(plaintexts):
    raw = _bounded_items(plaintexts, MAX_TRACES)
    if raw is None or len(raw) < 8:
        return None
    parsed = []
    width = None
    for value in raw:
        try:
            row = tuple(value) if isinstance(value, (bytes, bytearray)) else _bounded_items(value, MAX_AES_BYTES)
        except Exception:
            return None
        if row is None:
            return None
        try:
            row = tuple(_as_int(item) for item in row)
        except (TypeError, ValueError):
            return None
        if any(not 0 <= item <= 255 for item in row):
            return None
        if width is None:
            width = len(row)
        if not 1 <= len(row) <= MAX_AES_BYTES or len(row) != width:
            return None
        parsed.append(row)
    return tuple(parsed)


def _verify_cipher_pairs(key: bytes, pairs) -> bool:
    raw = _bounded_items(pairs, 32)
    if raw is None or not raw or len(key) not in (16, 24, 32):
        return False
    try:
        from Crypto.Cipher import AES

        cipher = AES.new(key, AES.MODE_ECB)
        for pair in raw:
            plaintext, ciphertext = pair
            if not isinstance(plaintext, (bytes, bytearray)) or not isinstance(ciphertext, (bytes, bytearray)):
                return False
            if len(plaintext) != 16 or len(ciphertext) != 16:
                return False
            if cipher.encrypt(bytes(plaintext)) != bytes(ciphertext):
                return False
        return True
    except (ImportError, TypeError, ValueError):
        return False


def recover_aes_key_cpa(
    plaintexts,
    traces,
    *,
    byte_indices=None,
    leakage_model="sbox_hw",
    min_correlation=0.2,
    margin=0.03,
    verifier: Callable[[bytes], bool] | None = None,
    negative_control=None,
    verification_pairs=None,
) -> bytes | None:
    """Recover ordered AES bytes only when every byte and optional verifier prove.

    The returned byte string follows ``byte_indices`` order; without a verifier it
    is explicitly partial-key CPA evidence.  A custom ``verifier`` receives that
    exact byte string.  Full AES ``verification_pairs`` require indices ``0..15``
    and independently validate a complete AES-128 key with PyCryptodome.  When
    either verifier is supplied, the selected key must be accepted and a distinct
    negative-control key must be rejected.
    """

    texts = _plaintext_matrix(plaintexts)
    matrix = _trace_matrix(traces, rows=len(texts) if texts else None)
    if texts is None or matrix is None:
        return None
    if byte_indices is None:
        indices = tuple(range(len(texts[0])))
    else:
        indices = _int_vector(byte_indices, limit=MAX_AES_BYTES, low=0, high=len(texts[0]) - 1)
    try:
        minimum, separation = _as_float(min_correlation), _as_float(margin)
    except (TypeError, ValueError):
        return None
    if (
        indices is None
        or len(set(indices)) != len(indices)
        or leakage_model not in {"sbox_hw", "sbox_hd_input"}
        or len(indices) * 256 * len(texts) * len(matrix[0]) > MAX_WORK
    ):
        return None
    recovered = []
    for index in indices:
        key_byte = _recover_aes_cpa(
            tuple(row[index] for row in texts),
            matrix,
            model=leakage_model,
            min_correlation=minimum,
            margin=separation,
        )
        if key_byte is None:
            return None
        recovered.append(key_byte)
    key = bytes(recovered)
    if negative_control is None:
        negative = bytes([key[0] ^ 1]) + key[1:] if key else b""
    elif isinstance(negative_control, (bytes, bytearray)):
        negative = bytes(negative_control)
    else:
        return None
    if len(negative) != len(key) or negative == key:
        return None
    if verifier is not None:
        if not callable(verifier):
            return None
        try:
            accepted = verifier(key)
            rejected = verifier(negative)
            if accepted is not True or rejected is not False:
                return None
        except Exception:
            return None
    if verification_pairs is not None:
        if len(key) != 16 or indices != tuple(range(16)):
            return None
        pairs = _bounded_items(verification_pairs, 32)
        if pairs is None or not pairs or not _verify_cipher_pairs(key, pairs):
            return None
        if _verify_cipher_pairs(negative, pairs):
            return None
    return key


def _candidate_integers(candidates):
    raw = _bounded_items(candidates, MAX_CANDIDATES)
    if raw is None:
        return None
    try:
        values = tuple(_as_int(value) for value in raw)
    except (TypeError, ValueError):
        return None
    if not values or len(set(values)) != len(values):
        return None
    return values


def recover_timing_candidate(
    inputs,
    timings,
    candidates,
    model: Callable[[int, int], float],
    *,
    method="correlation",
    min_score=0.5,
    margin=0.05,
    max_rmse=1.0,
) -> int | None:
    """Recover a unique timing-model candidate by correlation, rank, or likelihood."""

    observed_inputs = _int_vector(inputs, limit=MAX_TRACES)
    observed_times = _float_vector(timings, length=len(observed_inputs) if observed_inputs else None)
    choices = _candidate_integers(candidates)
    try:
        minimum, separation, maximum_error = map(_as_float, (min_score, margin, max_rmse))
    except (TypeError, ValueError):
        return None
    if (
        observed_inputs is None
        or observed_times is None
        or choices is None
        or len(observed_inputs) < 4
        or not callable(model)
        or method not in {"correlation", "rank", "likelihood"}
        or len(observed_inputs) * len(choices) > MAX_WORK
        or separation < 0
        or maximum_error < 0
    ):
        return None
    predictions = {}
    scores = {}
    try:
        for candidate in choices:
            values = tuple(_as_float(model(candidate, value)) for value in observed_inputs)
            predictions[candidate] = values
            if method == "correlation":
                correlation = _pearson_raw(values, observed_times)
                scores[candidate] = abs(correlation) if correlation is not None else -1.0
            elif method == "rank":
                correlation = _pearson_raw(_average_ranks(values), _average_ranks(observed_times))
                scores[candidate] = abs(correlation) if correlation is not None else -1.0
            else:
                residuals = tuple(observed_times[i] - values[i] for i in range(len(values)))
                offset = sum(residuals) / len(residuals)
                scores[candidate] = sqrt(sum((value - offset) ** 2 for value in residuals) / len(residuals))
    except Exception:
        return None
    if method in {"correlation", "rank"}:
        winner = _unique_max(scores, minimum=minimum, margin=separation)
    else:
        ordered = sorted(scores.items(), key=lambda item: (item[1], item[0]))
        if (
            not ordered
            or not isfinite(ordered[0][1])
            or ordered[0][1] > maximum_error
            or (
                len(ordered) > 1
                and (
                    ordered[1][1] - ordered[0][1] <= 0
                    or ordered[1][1] - ordered[0][1] < separation
                )
            )
        ):
            return None
        winner = ordered[0]
    if winner is None:
        return None
    candidate = winner[0]
    try:
        replay = tuple(_as_float(model(candidate, value)) for value in observed_inputs)
    except Exception:
        return None
    if any(abs(replay[i] - predictions[candidate][i]) > 1e-12 for i in range(len(replay))):
        return None
    if method == "correlation":
        independent = pearson_correlation(replay, observed_times)
        if independent is None or abs(abs(independent) - scores[candidate]) > 1e-10:
            return None
    elif method == "rank":
        independent = spearman_correlation(replay, observed_times)
        if independent is None or abs(abs(independent) - scores[candidate]) > 1e-10:
            return None
    else:
        residuals = tuple(observed_times[i] - replay[i] for i in range(len(replay)))
        offset = sum(residuals) / len(residuals)
        error = sqrt(sum((value - offset) ** 2 for value in residuals) / len(residuals))
        if abs(error - scores[candidate]) > 1e-10:
            return None
    return candidate


def square_multiply_timing_model(base, exponent, modulus) -> float | None:
    """Toy left-to-right square/multiply cost including extra-reduction events."""

    try:
        value, secret, mod = map(_as_int, (base, exponent, modulus))
    except (TypeError, ValueError):
        return None
    if not 0 <= value < mod or not 1 <= secret <= MAX_INTEGER or not 3 <= mod <= MAX_INTEGER:
        return None
    accumulator = 1
    cost = 0.0
    for bit in bin(secret)[2:]:
        product_value = accumulator * accumulator
        cost += 1.0 + (1.0 if product_value >= mod else 0.0)
        accumulator = product_value % mod
        if bit == "1":
            product_value = accumulator * value
            cost += 1.0 + (1.0 if product_value >= mod else 0.0)
            accumulator = product_value % mod
    return cost


def recover_modexp_timing_exponent(
    bases,
    timings,
    modulus,
    candidates,
    *,
    method="likelihood",
    min_score=0.5,
    margin=0.1,
    max_rmse=0.5,
) -> int | None:
    """Recover a toy modular/RSA exponent from supplied square-multiply timings."""

    try:
        mod = _as_int(modulus)
    except (TypeError, ValueError):
        return None
    if not 3 <= mod <= MAX_INTEGER:
        return None

    def model(candidate, base):
        result = square_multiply_timing_model(base, candidate, mod)
        if result is None:
            raise ValueError("invalid square-multiply model input")
        return result

    return recover_timing_candidate(
        bases,
        timings,
        candidates,
        model,
        method=method,
        min_score=min_score,
        margin=margin,
        max_rmse=max_rmse,
    )


def _cache_observations(traces):
    matrix = _trace_matrix(traces)
    if matrix is None or len(matrix[0]) > MAX_CACHE_SETS:
        return None
    observed = []
    for row in matrix:
        maximum = max(row)
        winners = [index for index, value in enumerate(row) if value == maximum]
        observed.append(winners[0] if len(winners) == 1 else None)
    try:
        import numpy as np

        data = np.asarray(matrix)
        for index, row in enumerate(matrix):
            if observed[index] is not None and int(np.argmax(data[index])) != observed[index]:
                return None
    except ImportError:
        pass
    return matrix, tuple(observed)


def infer_cache_access_pattern(
    traces,
    candidate_patterns,
    *,
    min_accuracy=1.0,
    margin=0.05,
) -> tuple[int, ...] | None:
    """Infer a unique per-trace cache-set access pattern and replay every trace."""

    observations = _cache_observations(traces)
    raw_patterns = _bounded_items(candidate_patterns, MAX_CANDIDATES)
    try:
        minimum, separation = _as_float(min_accuracy), _as_float(margin)
    except (TypeError, ValueError):
        return None
    if observations is None or raw_patterns is None or not 0 <= minimum <= 1 or separation < 0:
        return None
    matrix, observed = observations
    patterns = set()
    for pattern in raw_patterns:
        parsed = _int_vector(pattern, length=len(matrix), limit=MAX_TRACES, low=0, high=len(matrix[0]) - 1)
        if parsed is None:
            return None
        patterns.add(parsed)
    if not patterns or len(patterns) * len(matrix) > MAX_WORK:
        return None
    scores = {
        pattern: sum(observed[i] == pattern[i] for i in range(len(matrix))) / len(matrix)
        for pattern in patterns
    }
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    if ordered[0][1] < minimum:
        return None
    if len(ordered) > 1:
        difference = ordered[0][1] - ordered[1][1]
        if difference <= 0 or difference < separation:
            return None
    selected = ordered[0][0]
    replay = tuple(
        next((i for i, value in enumerate(row) if value == max(row) and row.count(max(row)) == 1), None)
        for row in matrix
    )
    return selected if replay == observed and scores[selected] >= minimum else None


def infer_cache_set_mapping(
    access_labels,
    traces,
    candidate_mappings,
    *,
    min_accuracy=1.0,
    margin=0.05,
) -> tuple[tuple[object, int], ...] | None:
    """Infer a unique label->cache-set mapping from supplied activity traces."""

    labels = _bounded_items(access_labels, MAX_TRACES)
    observations = _cache_observations(traces)
    raw_mappings = _bounded_items(candidate_mappings, MAX_CANDIDATES)
    if labels is None or observations is None or raw_mappings is None or len(labels) != len(observations[0]):
        return None
    matrix, _observed = observations
    try:
        unique_labels = set(labels)
    except (TypeError, ValueError):
        return None
    candidates = {}
    for mapping in raw_mappings:
        if not isinstance(mapping, dict) or set(mapping) != unique_labels:
            return None
        canonical = []
        try:
            for label in sorted(unique_labels, key=repr):
                cache_set = _as_int(mapping[label])
                if not 0 <= cache_set < len(observations[0][0]):
                    return None
                canonical.append((label, cache_set))
        except (TypeError, ValueError):
            return None
        candidate = tuple(canonical)
        lookup = dict(candidate)
        candidates[candidate] = tuple(lookup[label] for label in labels)
    if not candidates:
        return None
    patterns = tuple(candidates.values())
    selected_pattern = infer_cache_access_pattern(
        matrix, patterns, min_accuracy=min_accuracy, margin=margin
    )
    if selected_pattern is None:
        return None
    matches = [mapping for mapping, pattern in candidates.items() if pattern == selected_pattern]
    return matches[0] if len(matches) == 1 else None


def recover_aes_dfa_byte(inputs, good_outputs, faulty_outputs, fault_masks) -> int | None:
    """Recover one AES byte from pre-S-box XOR faults with a shared output mask.

    The nuisance output mask models unknown identical post-S-box transformations.
    A key is emitted only when one key and one mask reproduce every good/faulty pair.
    """

    known = _int_vector(inputs, limit=MAX_TRACES, low=0, high=255)
    good = _int_vector(good_outputs, length=len(known) if known else None, low=0, high=255)
    faulty = _int_vector(faulty_outputs, length=len(known) if known else None, low=0, high=255)
    masks = _int_vector(fault_masks, length=len(known) if known else None, low=0, high=255)
    if (
        known is None
        or good is None
        or faulty is None
        or masks is None
        or len(known) < 2
        or any(mask == 0 for mask in masks)
    ):
        return None
    candidates = []
    for key in range(256):
        output_mask = good[0] ^ _AES_SBOX[known[0] ^ key]
        if all(
            (_AES_SBOX[known[i] ^ key] ^ output_mask) == good[i]
            and (_AES_SBOX[(known[i] ^ masks[i]) ^ key] ^ output_mask) == faulty[i]
            for i in range(len(known))
        ):
            candidates.append((key, output_mask))
            if len(candidates) > 1:
                return None
    if len(candidates) != 1:
        return None
    key, output_mask = candidates[0]
    for index in range(len(known)):
        if _aes_sbox_reference(known[index] ^ key) ^ output_mask != good[index]:
            return None
        if _aes_sbox_reference((known[index] ^ masks[index]) ^ key) ^ output_mask != faulty[index]:
            return None
    return key


def recover_instruction_skip(inputs, good_outputs, faulty_outputs, operations) -> int | None:
    """Identify one skipped pure integer operation by replaying every observation."""

    known = _int_vector(inputs, limit=MAX_TRACES)
    good = _int_vector(good_outputs, length=len(known) if known else None)
    faulty = _int_vector(faulty_outputs, length=len(known) if known else None)
    ops = _bounded_items(operations, MAX_OPERATIONS)
    if (
        known is None
        or good is None
        or faulty is None
        or ops is None
        or not ops
        or all(good[index] == faulty[index] for index in range(len(good)))
        or any(not callable(op) for op in ops)
    ):
        return None

    def replay(value, skip=None):
        state = value
        for index, operation in enumerate(ops):
            if index == skip:
                continue
            state = _as_int(operation(state))
        return state

    try:
        if any(replay(known[i]) != good[i] for i in range(len(known))):
            return None
        candidates = [
            skipped
            for skipped in range(len(ops))
            if all(replay(known[i], skipped) == faulty[i] for i in range(len(known)))
        ]
    except Exception:
        return None
    if len(candidates) != 1:
        return None
    selected = candidates[0]
    try:
        return selected if all(replay(known[i], selected) == faulty[i] for i in range(len(known))) else None
    except Exception:
        return None


def recover_redundant_candidate(
    inputs,
    primary_outputs,
    redundant_outputs,
    faulty_outputs,
    fault_labels,
    candidates,
    primary_model: Callable[[int, int], int],
    redundant_model: Callable[[int, int], int],
    fault_model: Callable[[int, int], int],
) -> int | None:
    """Recover a unique candidate that replays primary, redundant, and faulty paths."""

    known = _int_vector(inputs, limit=MAX_TRACES)
    primary = _int_vector(primary_outputs, length=len(known) if known else None)
    redundant = _int_vector(redundant_outputs, length=len(known) if known else None)
    faulty = _int_vector(faulty_outputs, length=len(known) if known else None)
    labels = _int_vector(fault_labels, length=len(known) if known else None)
    choices = _candidate_integers(candidates)
    if (
        known is None
        or primary is None
        or redundant is None
        or faulty is None
        or labels is None
        or choices is None
        or all(redundant[index] == faulty[index] for index in range(len(redundant)))
        or not all(callable(model) for model in (primary_model, redundant_model, fault_model))
        or len(known) * len(choices) > MAX_WORK
    ):
        return None

    def matches(candidate):
        for index, value in enumerate(known):
            first = _as_int(primary_model(candidate, value))
            second = _as_int(redundant_model(candidate, value))
            damaged = _as_int(fault_model(second, labels[index]))
            if first != primary[index] or second != redundant[index] or damaged != faulty[index]:
                return False
        return True

    try:
        fits = [candidate for candidate in choices if matches(candidate)]
    except Exception:
        return None
    if len(fits) != 1:
        return None
    try:
        return fits[0] if matches(fits[0]) else None
    except Exception:
        return None


def cluster_fault_differences(
    good_vectors,
    faulty_vectors,
    *,
    mode="xor",
    expected_clusters=None,
    min_cluster_size=1,
) -> tuple[FaultCluster, ...] | None:
    """Exact fault clustering by XOR masks or signed difference vectors."""

    good = _bounded_items(good_vectors, MAX_TRACES)
    faulty = _bounded_items(faulty_vectors, MAX_TRACES)
    try:
        minimum = _as_int(min_cluster_size)
        expected = None if expected_clusters is None else _as_int(expected_clusters)
    except (TypeError, ValueError):
        return None
    if good is None or faulty is None or not good or len(good) != len(faulty) or mode not in {"xor", "difference"} or minimum < 1:
        return None
    parsed_good, parsed_faulty = [], []
    width = None
    for left, right in zip(good, faulty):
        first = _int_vector(left, limit=MAX_VECTOR_DIMENSION)
        second = _int_vector(right, length=len(first) if first else None, limit=MAX_VECTOR_DIMENSION)
        if first is None or second is None:
            return None
        if width is None:
            width = len(first)
        if len(first) != width:
            return None
        parsed_good.append(first)
        parsed_faulty.append(second)
    groups = {}
    for index, (first, second) in enumerate(zip(parsed_good, parsed_faulty)):
        signature = tuple(
            (first[i] ^ second[i]) if mode == "xor" else (second[i] - first[i])
            for i in range(width)
        )
        groups.setdefault(signature, []).append(index)
    if expected is not None and len(groups) != expected:
        return None
    if any(len(indices) < minimum for indices in groups.values()):
        return None
    clusters = tuple(
        sorted(
            (
                FaultCluster(signature, len(indices), tuple(indices))
                for signature, indices in groups.items()
            ),
            key=lambda item: (-item.count, item.signature),
        )
    )
    for cluster in clusters:
        for index in cluster.indices:
            rebuilt = tuple(
                (parsed_good[index][i] ^ cluster.signature[i])
                if mode == "xor"
                else (parsed_good[index][i] + cluster.signature[i])
                for i in range(width)
            )
            if rebuilt != parsed_faulty[index]:
                return None
    return clusters


__all__ = [
    "FaultCluster",
    "pearson_correlation",
    "spearman_correlation",
    "difference_of_means",
    "hamming_weight",
    "hamming_distance",
    "recover_aes_sbox_byte_cpa",
    "recover_aes_sbox_byte_dpa",
    "recover_aes_key_cpa",
    "recover_timing_candidate",
    "square_multiply_timing_model",
    "recover_modexp_timing_exponent",
    "infer_cache_access_pattern",
    "infer_cache_set_mapping",
    "recover_aes_dfa_byte",
    "recover_instruction_skip",
    "recover_redundant_candidate",
    "cluster_fault_differences",
]
