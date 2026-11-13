#!/usr/bin/env python3
"""Dependency-free error-correcting-code and checksum helpers.

The decoders separate *structural verification* (zero syndrome, re-encoding, checksum) from
claims about the originally transmitted value.  A corrected result is a candidate unless an
independent checksum/container proves the payload.  Nothing is sent or executed.

Coverage: shortened Reed--Solomon over caller-selected GF(2^m), binary narrow-sense BCH,
general Hamming SECDED, hard-decision convolutional/Viterbi, exact bounded LDPC nearest-codeword,
generic CRC plus common checksums, and a conservative survey of Python text codecs.
"""
from __future__ import annotations

import argparse
import codecs
import dataclasses
import encodings.aliases
import json
import math
import re
import sys
import zlib
from itertools import combinations
from pathlib import Path
from typing import Iterable, Sequence


MAX_SYMBOLS = 65536
MAX_BITS = 1 << 20
MAX_CODEC_INPUT = 1 << 20
MAX_LDPC_TRIALS = 200000


class ECCError(ValueError):
    pass


class GF2m:
    """Log/exp arithmetic for GF(2^m), with a proven primitive generator cycle."""

    def __init__(self, primitive: int, generator: int = 2):
        if not isinstance(primitive, int) or primitive <= 0:
            raise ECCError("primitive polynomial must be a positive integer")
        self.m = primitive.bit_length() - 1
        if not 2 <= self.m <= 16 or primitive >> self.m != 1:
            raise ECCError("field degree must be 2..16")
        self.primitive = primitive
        self.size = 1 << self.m
        self.order = self.size - 1
        if not isinstance(generator, int) or not 1 < generator < self.size:
            raise ECCError("invalid field generator")
        self.generator = generator
        self.exp = [0] * (self.order * 2)
        self.log = [-1] * self.size
        value = 1
        seen = set()
        for index in range(self.order):
            if value == 0 or value in seen:
                raise ECCError("polynomial/generator does not span the field")
            seen.add(value)
            self.exp[index] = value
            self.log[value] = index
            value = self._mul_poly(value, generator)
        if value != 1 or len(seen) != self.order:
            raise ECCError("polynomial/generator is not primitive")
        for index in range(self.order, len(self.exp)):
            self.exp[index] = self.exp[index - self.order]

    def _mul_poly(self, left: int, right: int) -> int:
        result = 0
        while right:
            if right & 1:
                result ^= left
            right >>= 1
            left <<= 1
            if left & self.size:
                left ^= self.primitive
        return result & (self.size - 1)

    @staticmethod
    def add(left: int, right: int) -> int:
        if not isinstance(left, int) or not isinstance(right, int) or left < 0 or right < 0:
            raise ECCError("field operands must be nonnegative integers")
        return left ^ right

    def _check_element(self, value: int) -> None:
        if not isinstance(value, int) or not 0 <= value < self.size:
            raise ECCError("operand is outside the field")

    def mul(self, left: int, right: int) -> int:
        self._check_element(left)
        self._check_element(right)
        return 0 if left == 0 or right == 0 else self.exp[self.log[left] + self.log[right]]

    def div(self, left: int, right: int) -> int:
        self._check_element(left)
        self._check_element(right)
        if right == 0:
            raise ECCError("GF division by zero")
        return 0 if left == 0 else self.exp[(self.log[left] - self.log[right]) % self.order]

    def pow(self, value: int, exponent: int) -> int:
        self._check_element(value)
        if not isinstance(exponent, int):
            raise ECCError("field exponent must be an integer")
        if exponent == 0:
            return 1
        if value == 0:
            return 0
        return self.exp[(self.log[value] * exponent) % self.order]


def _poly_mul_high(left: Sequence[int], right: Sequence[int], field: GF2m) -> list[int]:
    out = [0] * (len(left) + len(right) - 1)
    for i, x in enumerate(left):
        for j, y in enumerate(right):
            out[i + j] ^= field.mul(x, y)
    return out


def _poly_eval_high(poly: Sequence[int], x: int, field: GF2m) -> int:
    value = 0
    for coefficient in poly:
        value = field.mul(value, x) ^ coefficient
    return value


def _eval_low(poly: Sequence[int], x: int, field: GF2m) -> int:
    value, power = 0, 1
    for coefficient in poly:
        value ^= field.mul(coefficient, power)
        power = field.mul(power, x)
    return value


def _bm(syndromes: Sequence[int], field: GF2m) -> tuple[list[int], int]:
    count = len(syndromes)
    current, previous = [1] + [0] * count, [1] + [0] * count
    degree, shift, scale = 0, 1, 1
    for n in range(count):
        discrepancy = syndromes[n]
        for index in range(1, degree + 1):
            discrepancy ^= field.mul(current[index], syndromes[n - index])
        if discrepancy == 0:
            shift += 1
            continue
        saved = current[:]
        factor = field.div(discrepancy, scale)
        for index in range(count + 1 - shift):
            if previous[index]:
                current[index + shift] ^= field.mul(factor, previous[index])
        if 2 * degree <= n:
            degree = n + 1 - degree
            previous, scale, shift = saved, discrepancy, 1
        else:
            shift += 1
    return current[:degree + 1], degree


def _solve(matrix: list[list[int]], field: GF2m) -> list[int] | None:
    size = len(matrix)
    for column in range(size):
        pivot = next((row for row in range(column, size) if matrix[row][column]), None)
        if pivot is None:
            return None
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inv = field.div(1, matrix[column][column])
        matrix[column] = [field.mul(value, inv) for value in matrix[column]]
        for row in range(size):
            if row == column or matrix[row][column] == 0:
                continue
            factor = matrix[row][column]
            matrix[row] = [left ^ field.mul(factor, right)
                           for left, right in zip(matrix[row], matrix[column])]
    return [matrix[row][-1] for row in range(size)]


def _symbols(values: Iterable[int], field: GF2m) -> list[int]:
    try:
        out = list(values)
    except TypeError as exc:
        raise ECCError("symbols must be iterable integers") from exc
    if not out or len(out) > MAX_SYMBOLS or any(not isinstance(v, int) or isinstance(v, bool)
                                                or not 0 <= v < field.size for v in out):
        raise ECCError("invalid or overlong field-symbol stream")
    return out


def rs_generator(nsym: int, field: GF2m, fcr: int = 0) -> list[int]:
    if (not isinstance(field, GF2m) or not isinstance(nsym, int)
            or not isinstance(fcr, int) or not 1 <= nsym < field.order):
        raise ECCError("invalid Reed-Solomon parity length")
    result = [1]
    for index in range(nsym):
        result = _poly_mul_high(result, [1, field.exp[(fcr + index) % field.order]], field)
    return result


def rs_encode_symbols(data: Iterable[int], nsym: int, *, primitive: int = 0x11D,
                      generator: int = 2, fcr: int = 0) -> list[int]:
    field = GF2m(primitive, generator)
    values = _symbols(data, field)
    if not isinstance(nsym, int) or not isinstance(fcr, int):
        raise ECCError("Reed-Solomon parity length and first root must be integers")
    if len(values) + nsym > field.order:
        raise ECCError("Reed-Solomon word exceeds field order")
    gen = rs_generator(nsym, field, fcr)
    work = values + [0] * nsym
    for index in range(len(values)):
        coefficient = work[index]
        if coefficient:
            for j, factor in enumerate(gen):
                work[index + j] ^= field.mul(coefficient, factor)
    return values + work[-nsym:]


@dataclasses.dataclass(frozen=True)
class RSResult:
    data: tuple[int, ...]
    codeword: tuple[int, ...]
    corrected_positions: tuple[int, ...]
    zero_syndrome: bool
    reencoded: bool
    value_verified: bool
    note: str


def rs_decode_symbols(codeword: Iterable[int], nsym: int, *, primitive: int = 0x11D,
                      generator: int = 2, fcr: int = 0,
                      erasures: Iterable[int] = ()) -> RSResult | None:
    """Bounded-distance RS decode, accepted only after syndrome and re-encode checks."""
    try:
        field = GF2m(primitive, generator)
        message = _symbols(codeword, field)
    except ECCError:
        return None
    if (not isinstance(nsym, int) or not isinstance(fcr, int)
            or not 1 <= nsym < len(message) or len(message) > field.order):
        return None
    try:
        erase = sorted(set(int(position) for position in erasures))
    except (TypeError, ValueError, OverflowError):
        return None
    if len(erase) > nsym or any(position < 0 or position >= len(message) for position in erase):
        return None
    syndromes = [_poly_eval_high(message, field.exp[(fcr + i) % field.order], field)
                 for i in range(nsym)]
    positions: list[int] = []
    fixed = message[:]
    if any(syndromes):
        reduced = syndromes[:]
        for position in erase:
            x = field.exp[(len(message) - 1 - position) % field.order]
            reduced = [field.mul(reduced[i], x) ^ reduced[i + 1]
                       for i in range(len(reduced) - 1)]
        locator, errors = _bm(reduced, field)
        if errors < 0 or 2 * errors + len(erase) > nsym:
            return None
        unknown = []
        if errors:
            for position in range(len(message)):
                power = len(message) - 1 - position
                root = field.exp[(-power) % field.order]
                if _eval_low(locator, root, field) == 0:
                    unknown.append(position)
            if len(unknown) != errors:
                return None
        positions = sorted(set(unknown + erase))
        if len(positions) != errors + len(erase):
            return None
        system = []
        for row in range(len(positions)):
            exponent = fcr + row
            system.append([field.exp[(exponent * (len(message) - 1 - position)) % field.order]
                           for position in positions] + [syndromes[row]])
        magnitudes = _solve(system, field)
        if magnitudes is None:
            return None
        for position, magnitude in zip(positions, magnitudes):
            fixed[position] ^= magnitude
    check = [_poly_eval_high(fixed, field.exp[(fcr + i) % field.order], field)
             for i in range(nsym)]
    if any(check):
        return None
    data = fixed[:-nsym]
    try:
        replay = rs_encode_symbols(data, nsym, primitive=primitive, generator=generator, fcr=fcr)
    except ECCError:
        return None
    if replay != fixed:
        return None
    # Within the declared RS bounded-distance model, the result is unique. An external checksum is
    # still preferred before a human treats it as a submit value.
    return RSResult(tuple(data), tuple(fixed), tuple(positions), True, True, not positions,
                    "corrected RS data is a candidate until an independent checksum validates it")


def rs_encode(data: bytes, nsym: int, **kwargs) -> bytes:
    if not isinstance(data, bytes):
        raise ECCError("GF(256) byte encoder requires bytes")
    try:
        return bytes(rs_encode_symbols(data, nsym, **kwargs))
    except (TypeError, ValueError) as exc:
        raise ECCError("invalid byte-encoder parameters or symbols outside byte range") from exc


def rs_decode(codeword: bytes, nsym: int, **kwargs) -> RSResult | None:
    if not isinstance(codeword, bytes):
        return None
    try:
        return rs_decode_symbols(codeword, nsym, **kwargs)
    except (TypeError, ValueError):
        return None


def _bits(values: Iterable[int], *, max_bits: int = MAX_BITS) -> list[int]:
    try:
        out = list(values)
    except TypeError as exc:
        raise ECCError("bits must be iterable") from exc
    if not out or len(out) > max_bits or any(not isinstance(v, int) or v not in (0, 1)
                                           or isinstance(v, bool) for v in out):
        raise ECCError("invalid or overlong bit stream")
    return out


def hamming_secded_encode(data_bits: Iterable[int]) -> list[int]:
    data = _bits(data_bits)
    k = len(data)
    r = next((r for r in range(2, 17) if (1 << r) - r - 1 == k), None)
    if r is None:
        raise ECCError("data length must be 2^r-r-1 for r=2..16")
    n = (1 << r) - 1
    word = [0] * (n + 1)  # indexes 0..n-1 represent positions 1..n; last is overall parity
    cursor = 0
    for position in range(1, n + 1):
        if position & (position - 1):
            word[position - 1] = data[cursor]; cursor += 1
    for bit in range(r):
        parity_position = 1 << bit
        parity = 0
        for position in range(1, n + 1):
            if position & parity_position:
                parity ^= word[position - 1]
        word[parity_position - 1] = parity
    word[-1] = sum(word[:-1]) & 1
    return word


@dataclasses.dataclass(frozen=True)
class HammingResult:
    data: tuple[int, ...]
    codeword: tuple[int, ...]
    status: str
    corrected_position: int | None
    zero_syndrome: bool
    reencoded: bool
    value_verified: bool
    note: str


def hamming_secded_decode(codeword: Iterable[int]) -> HammingResult | None:
    try:
        word = _bits(codeword)
    except ECCError:
        return None
    if len(word) < 4 or len(word) & (len(word) - 1):
        return None
    r = len(word).bit_length() - 1
    n = len(word) - 1
    syndrome = 0
    for bit in range(r):
        parity_position = 1 << bit
        parity = 0
        for position in range(1, n + 1):
            if position & parity_position:
                parity ^= word[position - 1]
        if parity:
            syndrome |= parity_position
    overall = sum(word) & 1
    fixed = word[:]
    corrected = None
    if syndrome == 0 and overall == 0:
        status = "clean"
    elif syndrome == 0 and overall == 1:
        fixed[-1] ^= 1; corrected = n + 1; status = "corrected_overall_parity"
    elif syndrome != 0 and overall == 1 and syndrome <= n:
        fixed[syndrome - 1] ^= 1; corrected = syndrome; status = "corrected_single_bit"
    else:
        return None  # detected double-bit error or impossible syndrome
    data = [fixed[position - 1] for position in range(1, n + 1)
            if position & (position - 1)]
    try:
        replay = hamming_secded_encode(data)
    except ECCError:
        return None
    if replay != fixed:
        return None
    # SECDED cannot detect every 3+ bit error. Corrected data is therefore a candidate unless a
    # separate checksum validates it. Clean codewords are exact codewords but could still be an
    # attacker-chosen different codeword; callers retain provenance.
    return HammingResult(tuple(data), tuple(fixed), status, corrected, True, True,
                         corrected is None,
                         "corrected value assumes at most two channel errors; use an external checksum")


def hamming84_encode(nibble: int) -> int:
    if not isinstance(nibble, int) or isinstance(nibble, bool) or not 0 <= nibble < 16:
        raise ECCError("nibble must be 0..15")
    bits = [(nibble >> shift) & 1 for shift in range(3, -1, -1)]
    word = hamming_secded_encode(bits)
    return sum(bit << (7 - index) for index, bit in enumerate(word))


def hamming84_decode(value: int) -> HammingResult | None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 256:
        return None
    return hamming_secded_decode([(value >> shift) & 1 for shift in range(7, -1, -1)])


def bch_generator(m: int, t: int, primitive: int) -> list[int]:
    field = GF2m(primitive)
    if (not isinstance(m, int) or not isinstance(t, int)
            or field.m != m or not 1 <= t <= min(16, (field.order - 1) // 2)):
        raise ECCError("invalid BCH field/correction strength")
    exponents: set[int] = set()
    for root in range(1, 2 * t + 1):
        value = root % field.order
        while value not in exponents:
            exponents.add(value)
            value = (value * 2) % field.order
    poly = [1]
    for exponent in sorted(exponents):
        poly = _poly_mul_high(poly, [1, field.exp[exponent]], field)
    if any(value not in (0, 1) for value in poly):
        raise ECCError("BCH generator did not reduce to GF(2)")
    return poly


def bch_encode(data_bits: Iterable[int], m: int, t: int, primitive: int) -> list[int]:
    data = _bits(data_bits)
    generator = bch_generator(m, t, primitive)
    parity = len(generator) - 1
    field = GF2m(primitive)
    if len(data) + parity > field.order:
        raise ECCError("BCH word exceeds field order")
    work = data + [0] * parity
    for index in range(len(data)):
        if work[index]:
            for offset, bit in enumerate(generator):
                work[index + offset] ^= bit
    return data + work[-parity:]


@dataclasses.dataclass(frozen=True)
class BCHResult:
    data: tuple[int, ...]
    codeword: tuple[int, ...]
    corrected_positions: tuple[int, ...]
    zero_syndrome: bool
    reencoded: bool
    value_verified: bool
    note: str


def bch_decode(codeword: Iterable[int], m: int, t: int, primitive: int) -> BCHResult | None:
    try:
        word = _bits(codeword)
        field = GF2m(primitive)
        generator = bch_generator(m, t, primitive)
    except ECCError:
        return None
    parity = len(generator) - 1
    if field.m != m or len(word) <= parity or len(word) > field.order:
        return None
    syndromes = [_poly_eval_high(word, field.exp[index], field) for index in range(1, 2 * t + 1)]
    positions: list[int] = []
    fixed = word[:]
    if any(syndromes):
        locator, errors = _bm(syndromes, field)
        if not 1 <= errors <= t:
            return None
        for position in range(len(word)):
            power = len(word) - 1 - position
            if _eval_low(locator, field.exp[(-power) % field.order], field) == 0:
                positions.append(position)
        if len(positions) != errors:
            return None
        for position in positions:
            fixed[position] ^= 1
    check = [_poly_eval_high(fixed, field.exp[index], field) for index in range(1, 2 * t + 1)]
    if any(check):
        return None
    data = fixed[:-parity]
    try:
        replay = bch_encode(data, m, t, primitive)
    except ECCError:
        return None
    if replay != fixed:
        return None
    return BCHResult(tuple(data), tuple(fixed), tuple(positions), True, True, not positions,
                     "corrected BCH data is a candidate until an independent checksum validates it")


def convolutional_encode(bits: Iterable[int], constraint: int = 3,
                         generators: Sequence[int] = (0o7, 0o5), *, terminate: bool = False) -> list[int]:
    data = _bits(bits)
    try:
        if (not isinstance(constraint, int) or not 2 <= constraint <= 12
                or not generators or len(generators) > 8):
            raise ECCError("unsupported convolutional code")
    except TypeError as exc:
        raise ECCError("convolutional generators must be a finite collection") from exc
    mask = (1 << constraint) - 1
    if any(not isinstance(g, int) or g <= 0 or g > mask for g in generators):
        raise ECCError("invalid convolutional generators")
    stream = data + ([0] * (constraint - 1) if terminate else [])
    state = 0
    out = []
    for bit in stream:
        state = ((state << 1) | bit) & mask
        out.extend((state & generator).bit_count() & 1 for generator in generators)
    return out


@dataclasses.dataclass(frozen=True)
class ViterbiResult:
    data: tuple[int, ...]
    path_metric: int
    unique_ml: bool
    reencoded_exact: bool
    value_verified: bool
    note: str


def viterbi_decode(encoded_bits: Iterable[int], constraint: int = 3,
                   generators: Sequence[int] = (0o7, 0o5), *,
                   initial_state: int = 0, final_state: int | None = None,
                   terminated: bool = False) -> ViterbiResult | None:
    try:
        encoded = _bits(encoded_bits)
    except ECCError:
        return None
    try:
        if (not isinstance(constraint, int) or not 2 <= constraint <= 12
                or not generators or len(generators) > 8 or len(encoded) % len(generators)):
            return None
    except TypeError:
        return None
    states = 1 << (constraint - 1)
    if (not isinstance(initial_state, int) or not 0 <= initial_state < states
            or (final_state is not None and (not isinstance(final_state, int)
                                            or not 0 <= final_state < states))):
        return None
    mask = (1 << constraint) - 1
    if any(not isinstance(g, int) or g <= 0 or g > mask for g in generators):
        return None
    paths: dict[int, tuple[int, tuple[int, ...], int]] = {initial_state: (0, (), 1)}
    width = len(generators)
    for offset in range(0, len(encoded), width):
        received = encoded[offset:offset + width]
        nxt: dict[int, tuple[int, tuple[int, ...], int]] = {}
        for state, (metric, bits, ways) in paths.items():
            for bit in (0, 1):
                register = ((state << 1) | bit) & mask
                new_state = register & (states - 1)
                expected = [(register & generator).bit_count() & 1 for generator in generators]
                candidate = metric + sum(a != b for a, b in zip(expected, received))
                old = nxt.get(new_state)
                if old is None or candidate < old[0]:
                    nxt[new_state] = (candidate, bits + (bit,), ways)
                elif candidate == old[0]:
                    # Retain a deterministic representative but record ambiguity.
                    representative = min(old[1], bits + (bit,))
                    nxt[new_state] = (candidate, representative, min(2, old[2] + ways))
        paths = nxt
    targets = [final_state] if final_state is not None else list(paths)
    viable = [(paths[state][0], paths[state][1], paths[state][2], state)
              for state in targets if state in paths]
    if not viable:
        return None
    best_metric = min(item[0] for item in viable)
    best = [item for item in viable if item[0] == best_metric]
    unique = len(best) == 1 and best[0][2] == 1
    bits = best[0][1]
    if terminated:
        if len(bits) < constraint - 1 or any(bits[-(constraint - 1):]):
            return None
        payload = bits[:-(constraint - 1)]
    else:
        payload = bits
    # Replay the entire decoded path (including any tail) from the caller's
    # initial state; convolutional_encode always starts from zero.
    state = initial_state
    replay = []
    for bit in bits:
        state = ((state << 1) | bit) & mask
        replay.extend((state & generator).bit_count() & 1 for generator in generators)
    exact = replay == encoded
    # A nonzero-distance Viterbi output is a unique ML candidate, not independently proven original data.
    return ViterbiResult(tuple(payload), best_metric, unique, exact, bool(unique and exact),
                         "nonzero-distance output is a ranked candidate unless protected by a checksum")


def syndrome(bits: Sequence[int], parity_check: Sequence[Sequence[int]]) -> tuple[int, ...]:
    try:
        if len(bits) > 256 or not parity_check or len(parity_check) > 256:
            raise ECCError("LDPC matrix is empty or over cap")
        if any(not isinstance(v, int) or v not in (0, 1) for v in bits):
            raise ECCError("invalid binary word")
        if any(len(row) != len(bits) or any(not isinstance(v, int) or v not in (0, 1)
                                          for v in row) for row in parity_check):
            raise ECCError("invalid binary parity-check matrix")
    except TypeError as exc:
        raise ECCError("bits and parity-check rows must be binary sequences") from exc
    return tuple(sum(bit & coefficient for bit, coefficient in zip(bits, row)) & 1
                 for row in parity_check)


@dataclasses.dataclass(frozen=True)
class LDPCResult:
    codeword: tuple[int, ...]
    distance: int
    unique_nearest: bool
    zero_syndrome: bool
    value_verified: bool
    note: str


def ldpc_decode_exact(received_bits: Iterable[int], parity_check: Sequence[Sequence[int]],
                      max_distance: int = 3) -> LDPCResult | None:
    """Exhaustively find a unique nearest valid word within a small Hamming radius."""
    try:
        received = _bits(received_bits, max_bits=256)
    except ECCError:
        return None
    if not isinstance(max_distance, int) or not 0 <= max_distance <= 6:
        return None
    trials = 0
    for distance in range(max_distance + 1):
        hits = []
        for positions in combinations(range(len(received)), distance):
            trials += 1
            if trials > MAX_LDPC_TRIALS:
                return None
            candidate = received[:]
            for position in positions:
                candidate[position] ^= 1
            try:
                ok = not any(syndrome(candidate, parity_check))
            except ECCError:
                return None
            if ok:
                hits.append(candidate)
                if len(hits) > 1:
                    return None
        if len(hits) == 1:
            return LDPCResult(tuple(hits[0]), distance, True, True, distance == 0,
                              "corrected nearest codeword is a candidate until independently checksummed")
    return None


def crc_compute(data: bytes, width: int, polynomial: int, *, init: int = 0,
                xorout: int = 0, refin: bool = False, refout: bool = False) -> int:
    if (not isinstance(data, bytes) or len(data) > MAX_CODEC_INPUT
            or not isinstance(width, int) or not 1 <= width <= 64):
        raise ECCError("invalid CRC input/width")
    mask = (1 << width) - 1
    if (not isinstance(polynomial, int) or not 0 < polynomial <= mask
            or any(not isinstance(value, int) or not 0 <= value <= mask for value in (init, xorout))):
        raise ECCError("invalid CRC parameters")

    def reflect(value: int, bits: int) -> int:
        return int(f"{value:0{bits}b}"[::-1], 2)

    register = init
    top = 1 << (width - 1)
    for byte in data:
        if refin:
            byte = reflect(byte, 8)
        if width >= 8:
            register ^= byte << (width - 8)
            for _ in range(8):
                register = ((register << 1) ^ (polynomial if register & top else 0)) & mask
        else:
            # A sub-byte CRC still consumes all eight input bits.  Truncating the byte to
            # ``width`` bits silently produced wrong CRC-3/4/5/7 values while looking like a
            # successful deterministic calculation.  Feed one bit at a time instead because
            # the byte-at-once XOR used above cannot fit in a register narrower than a byte.
            for shift in range(7, -1, -1):
                feedback = bool(register & top) ^ bool((byte >> shift) & 1)
                register = (register << 1) & mask
                if feedback:
                    register ^= polynomial
    if refout:
        register = reflect(register, width)
    return register ^ xorout


CRC_CATALOG = {
    "crc8": (8, 0x07, 0x00, 0x00, False, False),
    "crc8_maxim": (8, 0x31, 0x00, 0x00, True, True),
    "crc16_ccitt_false": (16, 0x1021, 0xFFFF, 0x0000, False, False),
    "crc16_xmodem": (16, 0x1021, 0x0000, 0x0000, False, False),
    "crc16_modbus": (16, 0x8005, 0xFFFF, 0x0000, True, True),
    "crc32_iso_hdlc": (32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True),
}


def recover_crc_catalog(data: bytes, observed: int, names: Iterable[str] = CRC_CATALOG) -> dict:
    if not isinstance(observed, int) or observed < 0:
        raise ECCError("observed CRC must be nonnegative")
    try:
        names = list(names)[:128]
    except TypeError as exc:
        raise ECCError("CRC names must be iterable") from exc
    matches = []
    for name in names:
        params = CRC_CATALOG.get(str(name))
        if params is None:
            continue
        width, poly, init, xorout, refin, refout = params
        value = crc_compute(data, width, poly, init=init, xorout=xorout, refin=refin, refout=refout)
        if value == observed:
            matches.append({"name": name, "width": width, "polynomial": poly, "init": init,
                            "xorout": xorout, "refin": refin, "refout": refout, "verified": True})
    return {"matches": matches, "unique": len(matches) == 1,
            "value": matches[0] if len(matches) == 1 else None}


def fletcher16(data: bytes) -> int:
    if not isinstance(data, (bytes, bytearray)):
        raise ECCError("checksum input must be bytes")
    a = b = 0
    for value in data:
        a = (a + value) % 255; b = (b + a) % 255
    return (b << 8) | a


def internet_checksum(data: bytes) -> int:
    if not isinstance(data, (bytes, bytearray)):
        raise ECCError("checksum input must be bytes")
    blob = data + (b"\0" if len(data) & 1 else b"")
    total = sum(int.from_bytes(blob[i:i + 2], "big") for i in range(0, len(blob), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def python_codec_candidates(data: bytes, *, min_printable: float = 0.85) -> list[dict]:
    """Strict, exact-roundtrip candidates from every registered Python text codec alias.

    The function returns all distinct readings and never selects a best one. Transform codecs and
    codecs that do not advertise text encoding are skipped.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_CODEC_INPUT:
        raise ECCError("codec input is empty or over cap")
    try:
        if not 0 <= min_printable <= 1:
            raise ECCError("invalid printable threshold")
    except TypeError as exc:
        raise ECCError("invalid printable threshold") from exc
    names = sorted(set(encodings.aliases.aliases) | set(encodings.aliases.aliases.values()) |
                   {"utf-8", "utf-16", "utf-16-be", "utf-16-le", "utf-32", "latin-1",
                    "cp037", "cp273", "cp500"})
    grouped: dict[str, set[str]] = {}
    for name in names:
        try:
            info = codecs.lookup(name)
            if getattr(info, "_is_text_encoding", True) is False:
                continue
            text = data.decode(name, "strict")
            if text.encode(name, "strict") != data:
                continue
        except (LookupError, UnicodeError, ValueError, TypeError, MemoryError):
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
        if printable < min_printable:
            continue
        grouped.setdefault(text, set()).add(info.name)
    rows = [{"text": text, "codecs": sorted(codecs_), "roundtrip_verified": True,
             "printable_ratio": sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text)),
             "candidate_only": True}
            for text, codecs_ in grouped.items()]
    return sorted(rows, key=lambda row: (-row["printable_ratio"], row["codecs"], row["text"]))[:512]


def turbo_decode(*_args, **_kwargs):
    """Honest boundary: generic turbo decoding needs constituent polynomials/interleaver/LLRs."""
    return {"supported": False,
            "reason": "supply constituent encoders, interleaver and soft metrics to a reference decoder",
            "candidate": None}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ECCError(message)


def _parse_bits(value: str) -> list[int]:
    compact = re.sub(r"[\s_,]", "", value)
    if not compact or len(compact) > MAX_BITS or set(compact) - {"0", "1"}:
        raise ECCError("expected a bounded binary bit string")
    return [int(ch) for ch in compact]


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline ECC/checksum decoder; emits verified structures/candidates")
    sub = parser.add_subparsers(dest="command", required=True)
    rs = sub.add_parser("rs"); rs.add_argument("hexword"); rs.add_argument("nsym", type=int)
    rs.add_argument("--primitive", type=lambda value: int(value, 0), default=0x11D)
    rs.add_argument("--generator", type=lambda value: int(value, 0), default=2)
    rs.add_argument("--fcr", type=int, default=0)
    rs.add_argument("--erasure", action="append", type=int, default=[])
    ham = sub.add_parser("hamming"); ham.add_argument("bits")
    bch = sub.add_parser("bch"); bch.add_argument("bits"); bch.add_argument("m", type=int)
    bch.add_argument("t", type=int); bch.add_argument("primitive", type=lambda value: int(value, 0))
    vit = sub.add_parser("viterbi"); vit.add_argument("bits"); vit.add_argument("--constraint", type=int, default=3)
    crc = sub.add_parser("crc"); crc.add_argument("file"); crc.add_argument("observed", type=lambda value: int(value, 0))
    codec = sub.add_parser("codecs"); codec.add_argument("file")
    try:
        args = parser.parse_args(argv)
        if args.command == "rs":
            result = rs_decode(bytes.fromhex(args.hexword), args.nsym, primitive=args.primitive,
                               generator=args.generator, fcr=args.fcr, erasures=args.erasure)
        elif args.command == "hamming":
            result = hamming_secded_decode(_parse_bits(args.bits))
        elif args.command == "bch":
            result = bch_decode(_parse_bits(args.bits), args.m, args.t, args.primitive)
        elif args.command == "viterbi":
            result = viterbi_decode(_parse_bits(args.bits), args.constraint)
        elif args.command == "crc":
            raw = Path(args.file).read_bytes()
            if len(raw) > MAX_CODEC_INPUT:
                raise ECCError("input file exceeds cap")
            result = recover_crc_catalog(raw, args.observed)
        else:
            raw = Path(args.file).read_bytes()
            result = python_codec_candidates(raw)
        if result is None:
            raise ECCError("no verified decode")
        print(json.dumps(dataclasses.asdict(result) if dataclasses.is_dataclass(result) else result,
                         indent=2, ensure_ascii=False, default=str))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (ECCError, OSError, ValueError, TypeError, UnicodeError, OverflowError,
            MemoryError, RecursionError) as exc:
        print(f"ecc_codes: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
