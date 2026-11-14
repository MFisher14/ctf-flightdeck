"""Checked, dependency-free error-correcting-code decoders for offline CTF work.

The public decoders in this module have a deliberately conservative contract:
they return payload bytes only after the code's parity/syndrome (and, for the
framed codecs, a CRC) verifies.  Malformed input and uncorrectable corruption
return ``None`` instead of a best-effort string.

The implementations are intentionally small enough to audit while covering the
families that commonly occur in CTF artifacts: extended Hamming, Reed-Solomon
over configurable GF(2**m), binary BCH, convolutional/Viterbi, bounded sparse
parity-check (LDPC) decoding, a tractable turbo/Chase decoder, CRC parameter
recovery, and common parity/checksum trailers.
"""

from __future__ import annotations

import binascii
import itertools
import math
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence


def bytes_to_bits(data: bytes) -> list[int]:
    """Return MSB-first bits."""
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Pack MSB-first bits, padding the final byte with zeroes."""
    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("bits must contain only zero and one")
    out = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        out[index // 8] |= bit << (7 - index % 8)
    return bytes(out)


_FRAME_MAGIC = b"R5EC"


def _frame(payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("payload is too large for an r5e ECC frame")
    head = _FRAME_MAGIC + struct.pack(">H", len(payload)) + payload
    return head + struct.pack(">I", zlib.crc32(head) & 0xFFFFFFFF)


def _unframe(data: bytes) -> bytes | None:
    if len(data) < 10 or data[:4] != _FRAME_MAGIC:
        return None
    length = struct.unpack_from(">H", data, 4)[0]
    end = 6 + length
    if len(data) != end + 4:
        return None
    expected = struct.unpack_from(">I", data, end)[0]
    if zlib.crc32(data[:end]) & 0xFFFFFFFF != expected:
        return None
    return data[6:end]


# ---------------------------------------------------------------------------
# Extended Hamming SECDED


def _hamming84_word(nibble: int) -> int:
    if not 0 <= nibble < 16:
        raise ValueError("nibble is outside 0..15")
    word = [0] * 9  # positions 1..8; position 8 is overall parity
    for position, shift in zip((3, 5, 6, 7), (3, 2, 1, 0)):
        word[position] = (nibble >> shift) & 1
    for parity in (1, 2, 4):
        word[parity] = sum(word[p] for p in range(1, 8) if p & parity) & 1
    word[8] = sum(word[1:8]) & 1
    return sum(word[position] << (position - 1) for position in range(1, 9))


def _hamming84_nibble(encoded: int) -> int | None:
    if not 0 <= encoded <= 0xFF:
        return None
    word = [0] + [(encoded >> (position - 1)) & 1 for position in range(1, 9)]
    syndrome = 0
    for position in range(1, 8):
        if word[position]:
            syndrome ^= position
    overall = sum(word[1:9]) & 1
    if syndrome and overall:
        word[syndrome] ^= 1              # one error in the Hamming portion
    elif not syndrome and overall:
        word[8] ^= 1                     # error in the extension parity bit
    elif syndrome and not overall:
        return None                      # detected double-bit error
    check = 0
    for position in range(1, 8):
        if word[position]:
            check ^= position
    if check or (sum(word[1:9]) & 1):
        return None
    return sum(word[position] << shift
               for position, shift in zip((3, 5, 6, 7), (3, 2, 1, 0)))


def hamming84_encode_raw(payload: bytes) -> bytes:
    """Encode raw bytes as two extended-Hamming codewords per byte, without framing."""
    return bytes(codeword for byte in payload
                 for codeword in (_hamming84_word(byte >> 4), _hamming84_word(byte & 15)))


def hamming84_decode_nibbles(encoded: Sequence[int]) -> tuple[int, ...] | None:
    """Decode checked SECDED codewords to raw nibble candidates.

    This is the lowest-level API for supplied codewords: it does not require the
    module's synthetic CRC frame, and its tuple form preserves an odd final
    nibble.  Every codeword must pass the extended-Hamming syndrome/parity check.
    """
    if not encoded:
        return None
    decoded: list[int] = []
    for codeword in encoded:
        if not isinstance(codeword, int) or isinstance(codeword, bool):
            return None
        nibble = _hamming84_nibble(codeword)
        if nibble is None:
            return None
        decoded.append(nibble)
    return tuple(decoded)


def hamming84_decode_raw(encoded: Sequence[int]) -> bytes | None:
    """Decode an even number of checked SECDED codewords to raw bytes."""
    if not encoded or len(encoded) % 2:
        return None
    nibbles = hamming84_decode_nibbles(encoded)
    if nibbles is None:
        return None
    return bytes((nibbles[i] << 4) | nibbles[i + 1]
                 for i in range(0, len(nibbles), 2))


def hamming_secded_encode(payload: bytes) -> bytes:
    """Frame *payload* and encode every nibble as extended Hamming(8,4)."""
    return hamming84_encode_raw(_frame(payload))


def hamming_secded_decode(encoded: bytes) -> bytes | None:
    """Correct one bit per codeword and reject detected doubles or a bad frame."""
    raw = hamming84_decode_raw(encoded)
    if raw is None:
        return None
    return _unframe(raw)


# ---------------------------------------------------------------------------
# Finite fields and Reed-Solomon


class GF2m:
    """Log/antilog arithmetic for GF(2**m).

    ``primitive_polynomial`` includes the x**m term (for example 0x11d for
    GF(256)).  ``generator`` must be a primitive field element; supporting it
    separately also permits irreducible-but-not-primitive moduli such as
    0x11b with generator 3.  Construction checks the full multiplicative
    cycle, preventing silently broken tables from accepting a damaged word.
    """

    def __init__(self, m: int = 8, primitive_polynomial: int = 0x11D,
                 generator: int = 2):
        if not 2 <= m <= 16:
            raise ValueError("m must be in 2..16")
        if primitive_polynomial.bit_length() != m + 1:
            raise ValueError("primitive polynomial must include x**m")
        self.m = m
        self.primitive_polynomial = primitive_polynomial
        self.order = 1 << m
        self.period = self.order - 1
        if not 1 < generator < self.order:
            raise ValueError("field generator is outside 2..2**m-1")
        self.generator = generator
        self.exp = [0] * (2 * self.period)
        self.log = [-1] * self.order

        def raw_multiply(left: int, right: int) -> int:
            result = 0
            while right:
                if right & 1:
                    result ^= left
                right >>= 1
                left <<= 1
                if left & self.order:
                    left ^= primitive_polynomial
                left &= self.period
            return result

        value = 1
        seen: set[int] = set()
        for index in range(self.period):
            if value in seen or value == 0:
                raise ValueError("polynomial is not primitive for generator x")
            seen.add(value)
            self.exp[index] = value
            self.log[value] = index
            value = raw_multiply(value, generator)
        if value != 1 or len(seen) != self.period:
            raise ValueError("generator does not span the complete multiplicative field")
        self.exp[self.period:] = self.exp[:self.period]

    def add(self, left: int, right: int) -> int:
        return left ^ right

    def mul(self, left: int, right: int) -> int:
        if left == 0 or right == 0:
            return 0
        return self.exp[(self.log[left] + self.log[right]) % self.period]

    def div(self, left: int, right: int) -> int:
        if right == 0:
            raise ZeroDivisionError("finite-field division by zero")
        if left == 0:
            return 0
        return self.exp[(self.log[left] - self.log[right]) % self.period]

    def inv(self, value: int) -> int:
        if value == 0:
            raise ZeroDivisionError("zero has no finite-field inverse")
        return self.exp[-self.log[value] % self.period]

    def pow(self, value: int, exponent: int) -> int:
        if exponent == 0:
            return 1
        if value == 0:
            return 0
        return self.exp[(self.log[value] * exponent) % self.period]

    def alpha(self, exponent: int) -> int:
        return self.exp[exponent % self.period]


def _gf_poly_mul(left: Sequence[int], right: Sequence[int], gf: GF2m) -> list[int]:
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            out[i + j] ^= gf.mul(a, b)
    return out


def _gf_poly_eval_desc(poly: Sequence[int], value: int, gf: GF2m) -> int:
    result = 0
    for coefficient in poly:
        result = gf.mul(result, value) ^ coefficient
    return result


def _gf_poly_eval_asc(poly: Sequence[int], value: int, gf: GF2m) -> int:
    result = 0
    power = 1
    for coefficient in poly:
        result ^= gf.mul(coefficient, power)
        power = gf.mul(power, value)
    return result


def _berlekamp_massey(syndromes: Sequence[int], gf: GF2m) -> list[int]:
    """Return ascending error-locator coefficients, constant term first."""
    size = len(syndromes)
    locator = [1] + [0] * size
    previous = [1] + [0] * size
    degree = 0
    gap = 1
    last_discrepancy = 1
    for n in range(size):
        discrepancy = syndromes[n]
        for i in range(1, degree + 1):
            discrepancy ^= gf.mul(locator[i], syndromes[n - i])
        if discrepancy == 0:
            gap += 1
            continue
        old = locator[:]
        scale = gf.div(discrepancy, last_discrepancy)
        for j in range(size + 1 - gap):
            if previous[j]:
                locator[j + gap] ^= gf.mul(scale, previous[j])
        if 2 * degree <= n:
            degree = n + 1 - degree
            previous = old
            last_discrepancy = discrepancy
            gap = 1
        else:
            gap += 1
    return locator[:degree + 1]


def _solve_square(matrix: list[list[int]], rhs: list[int], gf: GF2m) -> list[int] | None:
    """Finite-field Gaussian elimination, declining singular systems."""
    n = len(rhs)
    aug = [row[:] + [value] for row, value in zip(matrix, rhs)]
    for column in range(n):
        pivot = next((row for row in range(column, n) if aug[row][column]), None)
        if pivot is None:
            return None
        aug[column], aug[pivot] = aug[pivot], aug[column]
        inverse = gf.inv(aug[column][column])
        aug[column] = [gf.mul(value, inverse) for value in aug[column]]
        for row in range(n):
            if row == column or not aug[row][column]:
                continue
            factor = aug[row][column]
            aug[row] = [a ^ gf.mul(factor, b)
                        for a, b in zip(aug[row], aug[column])]
    return [aug[row][-1] for row in range(n)]


@dataclass(frozen=True)
class ReedSolomon:
    """A shortened systematic RS codec over a configurable GF(2**m)."""

    nsym: int
    m: int = 8
    primitive_polynomial: int = 0x11D
    first_consecutive_root: int = 1
    field_generator: int = 2

    def __post_init__(self):
        gf = self._field()
        if not isinstance(self.nsym, int) or isinstance(self.nsym, bool) or not 1 <= self.nsym < gf.period:
            raise ValueError("invalid parity-symbol count")
        if not isinstance(self.first_consecutive_root, int):
            raise ValueError("first consecutive root must be an integer")

    def _field(self) -> GF2m:
        return GF2m(self.m, self.primitive_polynomial, self.field_generator)

    def _generator(self, gf: GF2m) -> list[int]:
        generator = [1]
        for i in range(self.nsym):
            generator = _gf_poly_mul(
                generator, [1, gf.alpha(self.first_consecutive_root + i)], gf)
        return generator

    def encode_symbols(self, message: Sequence[int]) -> tuple[int, ...]:
        gf = self._field()
        if not message or len(message) + self.nsym > gf.period:
            raise ValueError("message length is outside this field's RS limit")
        if any(not isinstance(symbol, int) or isinstance(symbol, bool)
               or not 0 <= symbol < gf.order for symbol in message):
            raise ValueError("symbol is outside the finite field")
        generator = self._generator(gf)
        work = list(message) + [0] * self.nsym
        for index in range(len(message)):
            coefficient = work[index]
            if coefficient:
                for offset in range(1, len(generator)):
                    work[index + offset] ^= gf.mul(generator[offset], coefficient)
        return tuple(message) + tuple(work[-self.nsym:])

    def syndromes(self, codeword: Sequence[int]) -> tuple[int, ...]:
        gf = self._field()
        return tuple(_gf_poly_eval_desc(
            codeword, gf.alpha(self.first_consecutive_root + i), gf)
                     for i in range(self.nsym))

    def decode_symbols(self, codeword: Sequence[int], *,
                       erasures: Sequence[int] = ()) -> tuple[int, ...] | None:
        gf = self._field()
        if (not codeword or len(codeword) > gf.period or len(codeword) <= self.nsym
                or any(not isinstance(symbol, int) or isinstance(symbol, bool)
                       or not 0 <= symbol < gf.order for symbol in codeword)):
            return None
        if (any(not isinstance(position, int) or isinstance(position, bool)
                or not 0 <= position < len(codeword) for position in erasures)
                or len(set(erasures)) != len(erasures) or len(erasures) > self.nsym):
            return None
        syndromes = list(self.syndromes(codeword))
        if not any(syndromes):
            return tuple(codeword[:-self.nsym])
        n = len(codeword)
        erasure_powers = [gf.alpha(n - 1 - position) for position in erasures]
        erasure_locator = [1]
        for power in erasure_powers:
            erasure_locator = _gf_poly_mul(erasure_locator, [1, power], gf)

        # Remove each known erasure's exponential component before BM.  With
        # S_k=sum(e_i*X_i**(fcr+k)), S_{k+1}+X*S_k cancels the known X term.
        forney_syndromes = syndromes[:]
        for power in erasure_powers:
            forney_syndromes = [forney_syndromes[i + 1]
                                ^ gf.mul(power, forney_syndromes[i])
                                for i in range(len(forney_syndromes) - 1)]
        unknown_locator = _berlekamp_massey(forney_syndromes, gf)
        unknown_errors = len(unknown_locator) - 1
        if 2 * unknown_errors + len(erasures) > self.nsym:
            return None
        locator = _gf_poly_mul(unknown_locator, erasure_locator, gf)
        errors = len(locator) - 1
        if errors == 0:
            return None
        positions: list[int] = []
        powers: list[int] = []
        for position in range(n):
            power = gf.alpha(n - 1 - position)
            if _gf_poly_eval_asc(locator, gf.inv(power), gf) == 0:
                positions.append(position)
                powers.append(power)
        if len(positions) != errors:
            return None
        if not set(erasures).issubset(positions):
            return None
        matrix = [[gf.pow(power, self.first_consecutive_root + row)
                   for power in powers] for row in range(errors)]
        magnitudes = _solve_square(matrix, syndromes[:errors], gf)
        if magnitudes is None:
            return None
        corrected = list(codeword)
        for position, magnitude in zip(positions, magnitudes):
            corrected[position] ^= magnitude
        if any(self.syndromes(corrected)):
            return None
        return tuple(corrected[:-self.nsym])

    def encode(self, payload: bytes) -> bytes:
        if self.m != 8:
            raise ValueError("byte convenience API requires GF(256)")
        return bytes(self.encode_symbols(payload))

    def decode(self, codeword: bytes, *, erasures: Sequence[int] = ()) -> bytes | None:
        if self.m != 8:
            raise ValueError("byte convenience API requires GF(256)")
        decoded = self.decode_symbols(codeword, erasures=erasures)
        return bytes(decoded) if decoded is not None else None


# ---------------------------------------------------------------------------
# Binary BCH


@dataclass(frozen=True)
class BCH:
    """Primitive narrow-sense binary BCH with systematic shortening support."""

    m: int
    primitive_polynomial: int
    t: int
    field_generator: int = 2

    def __post_init__(self):
        gf = self._field()
        if not isinstance(self.t, int) or isinstance(self.t, bool) or not 1 <= self.t <= (gf.period - 1) // 2:
            raise ValueError("BCH correction radius is outside 1..(n-1)/2")
        if len(self.generator()) - 1 >= gf.period:
            raise ValueError("BCH generator leaves no message symbols")

    def _field(self) -> GF2m:
        return GF2m(self.m, self.primitive_polynomial, self.field_generator)

    def generator(self) -> tuple[int, ...]:
        gf = self._field()
        n = gf.period
        covered: set[int] = set()
        generator = [1]
        for root in range(1, 2 * self.t + 1):
            if root in covered:
                continue
            coset: list[int] = []
            value = root % n
            while value not in coset:
                coset.append(value)
                covered.add(value)
                value = (2 * value) % n
            minimal = [1]
            for exponent in coset:
                minimal = _gf_poly_mul(minimal, [1, gf.alpha(exponent)], gf)
            if any(coefficient not in (0, 1) for coefficient in minimal):
                raise ValueError("minimal polynomial did not descend to GF(2)")
            generator = _gf_poly_mul(generator, minimal, gf)
        if any(coefficient not in (0, 1) for coefficient in generator):
            raise ValueError("BCH generator did not descend to GF(2)")
        return tuple(generator)

    @property
    def n(self) -> int:
        return (1 << self.m) - 1

    @property
    def parity_bits(self) -> int:
        return len(self.generator()) - 1

    @property
    def k(self) -> int:
        return self.n - self.parity_bits

    def encode_bits(self, message: Sequence[int]) -> tuple[int, ...]:
        if (not message or len(message) > self.k
                or any(not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1)
                       for bit in message)):
            raise ValueError("invalid BCH message bits")
        shortening = self.k - len(message)
        full_message = [0] * shortening + list(message)
        generator = self.generator()
        work = full_message + [0] * self.parity_bits
        for index in range(self.k):
            if work[index]:
                for offset, coefficient in enumerate(generator):
                    work[index + offset] ^= coefficient
        full_codeword = full_message + work[self.k:]
        return tuple(full_codeword[shortening:])

    def decode_bits(self, codeword: Sequence[int]) -> tuple[int, ...] | None:
        if (not codeword or len(codeword) > self.n or len(codeword) <= self.parity_bits
                or any(not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1)
                       for bit in codeword)):
            return None
        gf = self._field()
        shortening = self.n - len(codeword)
        full = [0] * shortening + list(codeword)
        syndromes = [_gf_poly_eval_desc(full, gf.alpha(i), gf)
                     for i in range(1, 2 * self.t + 1)]
        if any(syndromes):
            locator = _berlekamp_massey(syndromes, gf)
            errors = len(locator) - 1
            if errors == 0 or errors > self.t:
                return None
            positions = []
            for position in range(self.n):
                power = gf.alpha(self.n - 1 - position)
                if _gf_poly_eval_asc(locator, gf.inv(power), gf) == 0:
                    positions.append(position)
            if len(positions) != errors:
                return None
            for position in positions:
                full[position] ^= 1
            if any(_gf_poly_eval_desc(full, gf.alpha(i), gf)
                   for i in range(1, 2 * self.t + 1)):
                return None
        if any(full[:shortening]):
            return None
        return tuple(full[shortening:self.k])

    def encode(self, payload: bytes, *, bit_length: int | None = None) -> tuple[int, ...]:
        bits = bytes_to_bits(payload)
        if bit_length is not None:
            if not 1 <= bit_length <= len(bits):
                raise ValueError("invalid payload bit length")
            bits = bits[:bit_length]
        return self.encode_bits(bits)

    def decode(self, codeword: Sequence[int]) -> bytes | None:
        decoded = self.decode_bits(codeword)
        return bits_to_bytes(decoded) if decoded is not None else None


# ---------------------------------------------------------------------------
# Convolutional coding and checked Viterbi


def _conv_transitions(constraint: int, generators: Sequence[int]):
    states = 1 << (constraint - 1)
    transitions: list[list[tuple[int, tuple[int, ...]]]] = []
    for state in range(states):
        row = []
        for bit in (0, 1):
            register = (bit << (constraint - 1)) | state
            outputs = tuple((register & generator).bit_count() & 1
                            for generator in generators)
            row.append((register >> 1, outputs))
        transitions.append(row)
    return transitions


def _valid_conv_config(constraint: int, generators: Sequence[int]) -> bool:
    return (isinstance(constraint, int) and not isinstance(constraint, bool)
            and 2 <= constraint <= 12 and bool(generators)
            and len(generators) <= 8
            and all(isinstance(g, int) and not isinstance(g, bool)
                    and 0 < g < 1 << constraint for g in generators))


def convolutional_encode_bits(bits: Sequence[int], *, constraint: int = 3,
                              generators: Sequence[int] = (0o7, 0o5)) -> tuple[int, ...]:
    """Rate-1/n encode raw candidate bits and append a zero-termination tail."""
    if not _valid_conv_config(constraint, generators):
        raise ValueError("invalid convolutional-code configuration")
    if not bits or any(not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1)
                       for bit in bits):
        raise ValueError("convolutional input must be a non-empty bit sequence")
    transitions = _conv_transitions(constraint, generators)
    state = 0
    out: list[int] = []
    for bit in list(bits) + [0] * (constraint - 1):
        state, emitted = transitions[state][bit]
        out.extend(emitted)
    if state != 0:
        raise AssertionError("zero tail failed to terminate convolutional encoder")
    return tuple(out)


def convolutional_encode(payload: bytes, *, constraint: int = 3,
                         generators: Sequence[int] = (0o7, 0o5)) -> tuple[int, ...]:
    """CRC-frame and rate-1/n convolutionally encode *payload* with zero tail."""
    return convolutional_encode_bits(bytes_to_bits(_frame(payload)), constraint=constraint,
                                     generators=generators)


def viterbi_decode_bits(encoded: Sequence[int], *, constraint: int = 3,
                        generators: Sequence[int] = (0o7, 0o5),
                        max_bit_errors: int = 2,
                        max_trellis_cells: int = 2_000_000) -> tuple[int, ...] | None:
    """Decode a raw zero-terminated convolutional word to a checked bit candidate."""
    if not _valid_conv_config(constraint, generators):
        return None
    rate = len(generators)
    if (not encoded or len(encoded) % rate
            or any(not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1)
                   for bit in encoded)
            or not isinstance(max_bit_errors, int) or isinstance(max_bit_errors, bool)
            or max_bit_errors < 0
            or not isinstance(max_trellis_cells, int) or max_trellis_cells <= 0):
        return None
    steps = len(encoded) // rate
    raw_steps = steps - (constraint - 1)
    states = 1 << (constraint - 1)
    if raw_steps <= 0 or steps * states > max_trellis_cells:
        return None
    transitions = _conv_transitions(constraint, generators)
    # Backpointers avoid the quadratic tuple copying of a path-per-state Viterbi.
    metrics: dict[int, int] = {0: 0}
    decisions: list[list[tuple[int, int] | None]] = []
    for offset in range(0, len(encoded), rate):
        observed = tuple(encoded[offset:offset + rate])
        next_metrics: dict[int, int] = {}
        step_decisions: list[tuple[int, int] | None] = [None] * states
        for state in sorted(metrics):
            metric = metrics[state]
            for bit in (0, 1):
                next_state, emitted = transitions[state][bit]
                candidate = metric + sum(a != b for a, b in zip(observed, emitted))
                if candidate > max_bit_errors:
                    continue
                old = next_metrics.get(next_state)
                if old is None or candidate < old:
                    next_metrics[next_state] = candidate
                    step_decisions[next_state] = (state, bit)
                # Equal metrics deliberately retain the first state/bit reached;
                # sorted state traversal and bit order make this deterministic.
        if not next_metrics:
            return None
        metrics = next_metrics
        decisions.append(step_decisions)
    metric = metrics.get(0)
    if metric is None:
        return None
    state = 0
    reversed_bits: list[int] = []
    for step_decisions in reversed(decisions):
        decision = step_decisions[state]
        if decision is None:
            return None
        state, bit = decision
        reversed_bits.append(bit)
    if state != 0:
        return None
    bits = tuple(reversed(reversed_bits))
    if len(bits) <= constraint - 1 or any(bits[-(constraint - 1):]):
        return None
    raw_bits = bits[:-(constraint - 1)]
    # A final exact re-encode check guards implementation/configuration mismatch.
    expected = convolutional_encode_bits(raw_bits, constraint=constraint, generators=generators)
    if len(expected) != len(encoded) or sum(a != b for a, b in zip(expected, encoded)) != metric:
        return None
    return raw_bits


def viterbi_decode(encoded: Sequence[int], *, constraint: int = 3,
                   generators: Sequence[int] = (0o7, 0o5),
                   max_bit_errors: int = 2,
                   max_trellis_cells: int = 2_000_000) -> bytes | None:
    """Hard-decision Viterbi; return only a zero-tail, CRC-valid framed payload."""
    raw_bits = viterbi_decode_bits(
        encoded, constraint=constraint, generators=generators,
        max_bit_errors=max_bit_errors, max_trellis_cells=max_trellis_cells)
    if raw_bits is None or len(raw_bits) % 8:
        return None
    return _unframe(bits_to_bytes(raw_bits))


# ---------------------------------------------------------------------------
# CRC discovery and single-bit reversal


def _reflect(value: int, width: int) -> int:
    return sum(((value >> index) & 1) << (width - 1 - index) for index in range(width))


@dataclass(frozen=True, order=True)
class CRCParameters:
    width: int
    polynomial: int
    init: int = 0
    xorout: int = 0
    reflect_in: bool = False
    reflect_out: bool = False


def crc_value(data: bytes, params: CRCParameters) -> int:
    """Compute an arbitrary bitwise CRC (polynomial omits the x**width term)."""
    width = params.width
    if not isinstance(width, int) or isinstance(width, bool) or not 3 <= width <= 32:
        raise ValueError("CRC width must be in 3..32")
    mask = (1 << width) - 1
    if (not all(isinstance(value, int) and not isinstance(value, bool)
                for value in (params.polynomial, params.init, params.xorout))
            or params.polynomial <= 0 or not params.polynomial & 1
            or any(value < 0 or value & ~mask
                   for value in (params.polynomial, params.init, params.xorout))):
        raise ValueError("CRC parameter exceeds width")
    register = params.init
    if params.reflect_in:
        polynomial = _reflect(params.polynomial, width)
        for byte in data:
            for shift in range(8):
                incoming = (byte >> shift) & 1
                feedback = (register & 1) ^ incoming
                register >>= 1
                if feedback:
                    register ^= polynomial
    else:
        top = 1 << (width - 1)
        for byte in data:
            for shift in range(7, -1, -1):
                incoming = (byte >> shift) & 1
                feedback = bool(register & top) ^ bool(incoming)
                register = (register << 1) & mask
                if feedback:
                    register ^= params.polynomial
    if params.reflect_out != params.reflect_in:
        register = _reflect(register, width)
    return (register ^ params.xorout) & mask


_COMMON_CRC_PARAMETERS = (
    CRCParameters(8, 0x07, 0x00, 0x00, False, False),       # CRC-8/SMBUS
    CRCParameters(8, 0x31, 0x00, 0x00, True, True),         # CRC-8/MAXIM-DOW
    CRCParameters(16, 0x1021, 0xFFFF, 0x0000, False, False), # CRC-16/CCITT-FALSE
    CRCParameters(16, 0x8005, 0x0000, 0x0000, True, True),   # CRC-16/ARC
    CRCParameters(16, 0x1021, 0xFFFF, 0xFFFF, True, True),   # CRC-16/X-25
    CRCParameters(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True),
)


def recover_crc_parameters(samples: Sequence[tuple[bytes, int]], *,
                           candidates: Iterable[CRCParameters] | None = None,
                           exhaustive_width: int | None = None,
                           init_values: Sequence[int] = (0,),
                           xorout_values: Sequence[int] = (0,),
                           reflection_options: Sequence[tuple[bool, bool]] = ((False, False),)
                           ) -> tuple[CRCParameters, ...]:
    """Return only parameter sets that reproduce every observed CRC.

    ``exhaustive_width`` enumerates every odd polynomial at widths up to 16;
    larger searches must supply an explicit candidate iterable.
    """
    if not samples:
        return ()
    pool: Iterable[CRCParameters]
    if candidates is not None and exhaustive_width is not None:
        raise ValueError("choose explicit candidates or exhaustive polynomial search")
    if exhaustive_width is not None:
        if not 3 <= exhaustive_width <= 16:
            raise ValueError("exhaustive CRC search is capped at 16 bits")
        mask = (1 << exhaustive_width) - 1
        pool = (CRCParameters(exhaustive_width, polynomial, init & mask, xorout & mask, rin, rout)
                for polynomial in range(1, 1 << exhaustive_width, 2)
                for init in init_values for xorout in xorout_values
                for rin, rout in reflection_options)
    else:
        pool = candidates if candidates is not None else _COMMON_CRC_PARAMETERS
    found = [params for params in pool
             if all(crc_value(data, params) == expected for data, expected in samples)]
    return tuple(sorted(set(found)))


def repair_crc_single_bit(data: bytes, expected: int, params: CRCParameters, *,
                          max_bits: int = 1_000_000) -> bytes | None:
    """Reverse exactly one damaged data bit when the CRC identifies one unique repair."""
    if not isinstance(max_bits, int) or max_bits <= 0 or len(data) * 8 > max_bits:
        return None
    if crc_value(data, params) == expected:
        return data
    candidates: list[bytes] = []
    for bit_index in range(len(data) * 8):
        repaired = bytearray(data)
        repaired[bit_index // 8] ^= 1 << (7 - bit_index % 8)
        if crc_value(repaired, params) == expected:
            candidates.append(bytes(repaired))
            if len(candidates) > 1:
                return None
    return candidates[0] if len(candidates) == 1 else None


# ---------------------------------------------------------------------------
# Sparse parity-check / tractable LDPC


def _binary_rank(matrix: Sequence[Sequence[int]]) -> int:
    rows = [sum((bit & 1) << column for column, bit in enumerate(row)) for row in matrix]
    rank = 0
    column = 0
    width = len(matrix[0]) if matrix else 0
    while column < width and rank < len(rows):
        pivot = next((i for i in range(rank, len(rows)) if rows[i] >> column & 1), None)
        if pivot is None:
            column += 1
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and rows[i] >> column & 1:
                rows[i] ^= rows[rank]
        rank += 1
        column += 1
    return rank


@dataclass(frozen=True)
class LDPCCode:
    """Small sparse systematic H=[A|I] code with checked bounded decoding."""

    parity_check: tuple[tuple[int, ...], ...]
    data_bits: int

    def __post_init__(self):
        rows = self.parity_check
        if not rows or self.data_bits <= 0 or any(len(row) != len(rows[0]) for row in rows):
            raise ValueError("invalid parity-check matrix")
        n = len(rows[0])
        m = len(rows)
        if n != self.data_bits + m or any(bit not in (0, 1) for row in rows for bit in row):
            raise ValueError("LDPC encoder requires systematic H=[A|I]")
        right = [row[self.data_bits:] for row in rows]
        if any(right[i][j] != (i == j) for i in range(m) for j in range(m)):
            raise ValueError("right side of parity-check matrix must be identity")
        if _binary_rank(rows) != m:
            raise ValueError("parity-check rows are not independent")

    @property
    def n(self) -> int:
        return len(self.parity_check[0])

    def syndrome(self, word: Sequence[int]) -> tuple[int, ...]:
        if len(word) != self.n or any(bit not in (0, 1) for bit in word):
            raise ValueError("invalid LDPC word")
        return tuple(sum(bit * coefficient for bit, coefficient in zip(word, row)) & 1
                     for row in self.parity_check)

    def encode_bits(self, data: Sequence[int]) -> tuple[int, ...]:
        if len(data) != self.data_bits or any(bit not in (0, 1) for bit in data):
            raise ValueError("invalid LDPC data bits")
        parity = [sum(row[i] * data[i] for i in range(self.data_bits)) & 1
                  for row in self.parity_check]
        word = tuple(data) + tuple(parity)
        if any(self.syndrome(word)):
            raise AssertionError("LDPC systematic encoder produced a non-codeword")
        return word

    def decode_bits(self, received: Sequence[int], *, max_flips: int = 2,
                    max_trials: int = 1_000_000) -> tuple[int, ...] | None:
        """Unique bounded-distance decode, suitable for small offline sparse codes."""
        if (len(received) != self.n or any(bit not in (0, 1) for bit in received)
                or not isinstance(max_flips, int) or isinstance(max_flips, bool)
                or not 0 <= max_flips <= 4
                or not isinstance(max_trials, int) or max_trials <= 0):
            return None
        if sum(math.comb(self.n, weight) for weight in range(max_flips + 1)) > max_trials:
            return None
        raw = tuple(received)
        for weight in range(max_flips + 1):
            candidates: list[tuple[int, ...]] = []
            for positions in itertools.combinations(range(self.n), weight):
                candidate = list(raw)
                for position in positions:
                    candidate[position] ^= 1
                if not any(self.syndrome(candidate)):
                    candidates.append(tuple(candidate))
                    if len(candidates) > 1:
                        return None
            if len(candidates) == 1:
                return candidates[0][:self.data_bits]
        return None

    def decode(self, received: Sequence[int], *, max_flips: int = 2,
               max_trials: int = 1_000_000) -> bytes | None:
        decoded = self.decode_bits(received, max_flips=max_flips, max_trials=max_trials)
        return bits_to_bytes(decoded) if decoded is not None else None

    def decode_min_sum(self, llrs: Sequence[float], *, iterations: int = 20) -> bytes | None:
        """Normalized min-sum belief propagation; parity-check before returning."""
        if (len(llrs) != self.n or not isinstance(iterations, int) or iterations <= 0
                or any(not isinstance(x, (int, float)) or isinstance(x, bool)
                       or not math.isfinite(x) for x in llrs)):
            return None
        checks = [[j for j, bit in enumerate(row) if bit] for row in self.parity_check]
        variables = [[i for i, row in enumerate(self.parity_check) if row[j]]
                     for j in range(self.n)]
        q = {(i, j): float(llrs[j]) for i, js in enumerate(checks) for j in js}
        r = {(i, j): 0.0 for i, js in enumerate(checks) for j in js}
        hard = [0] * self.n
        for _ in range(iterations):
            for i, js in enumerate(checks):
                for j in js:
                    others = [q[i, k] for k in js if k != j]
                    if not others:
                        r[i, j] = 0.0
                    else:
                        sign = -1.0 if sum(value < 0 for value in others) & 1 else 1.0
                        r[i, j] = 0.8 * sign * min(abs(value) for value in others)
            post = []
            for j in range(self.n):
                value = float(llrs[j]) + sum(r[i, j] for i in variables[j])
                post.append(value)
                hard[j] = int(value < 0)
            if not any(self.syndrome(hard)):
                # Exactly-zero posterior bits make more than one hard decision
                # equally likely.  A parity-satisfying tie is not evidence.
                if any(abs(value) <= 1e-12 for value in post):
                    return None
                return bits_to_bytes(hard[:self.data_bits])
            for j in range(self.n):
                for i in variables[j]:
                    q[i, j] = float(llrs[j]) + sum(r[k, j] for k in variables[j] if k != i)
        return None


# ---------------------------------------------------------------------------
# Tractable turbo code / bounded Chase decoder


def turbo_interleaver(length: int) -> tuple[int, ...]:
    if length <= 0:
        raise ValueError("interleaver length must be positive")
    step = max(2, math.isqrt(length) + 1)
    while math.gcd(step, length) != 1:
        step += 1
    return tuple((index * step + length // 3) % length for index in range(length))


def _rsc_parity(bits: Sequence[int]) -> list[int]:
    """A constraint-3 recursive systematic constituent encoder (7,5 octal)."""
    first = second = 0
    parity: list[int] = []
    for bit in bits:
        feedback = bit ^ second
        parity.append(feedback ^ first ^ second)
        first, second = feedback, first
    return parity


def _valid_permutation(order: Sequence[int], length: int) -> bool:
    return (len(order) == length
            and all(isinstance(index, int) and not isinstance(index, bool)
                    and 0 <= index < length for index in order)
            and len(set(order)) == length)


def _turbo_encode_raw(raw_bits: Sequence[int], interleaver: Sequence[int]) -> tuple[int, ...]:
    if not _valid_permutation(interleaver, len(raw_bits)):
        raise ValueError("interleaver is not a permutation of the input")
    first = _rsc_parity(raw_bits)
    permuted = [raw_bits[index] for index in interleaver]
    second = _rsc_parity(permuted)
    return tuple(value for triple in zip(raw_bits, first, second) for value in triple)


def turbo_encode(payload: bytes, *, interleaver: Sequence[int] | None = None) -> tuple[int, ...]:
    raw = bytes_to_bits(_frame(payload))
    order = tuple(interleaver) if interleaver is not None else turbo_interleaver(len(raw))
    return _turbo_encode_raw(raw, order)


def turbo_decode(encoded: Sequence[int], *, interleaver: Sequence[int] | None = None,
                 max_systematic_flips: int = 2, max_bit_errors: int = 3,
                 max_frame_bits: int = 256,
                 max_candidates: int = 100_000) -> bytes | None:
    """Bounded Chase/ML turbo decode for short CTF frames.

    Candidates are generated around the systematic stream, rejected unless the
    embedded frame CRC holds, then scored against both recursive parity streams.
    This is exponential only in ``max_systematic_flips`` and explicitly capped.
    """
    if (not encoded or len(encoded) % 3
            or any(not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1)
                   for bit in encoded)
            or not isinstance(max_systematic_flips, int) or isinstance(max_systematic_flips, bool)
            or not 0 <= max_systematic_flips <= 3
            or not isinstance(max_bit_errors, int) or isinstance(max_bit_errors, bool)
            or max_bit_errors < 0
            or not isinstance(max_frame_bits, int) or max_frame_bits <= 0
            or not isinstance(max_candidates, int) or max_candidates <= 0):
        return None
    length = len(encoded) // 3
    if length % 8 or length > max_frame_bits:
        return None
    if sum(math.comb(length, weight) for weight in range(max_systematic_flips + 1)) > max_candidates:
        return None
    order = tuple(interleaver) if interleaver is not None else turbo_interleaver(length)
    if not _valid_permutation(order, length):
        return None
    systematic = [encoded[3 * i] for i in range(length)]
    best_distance: int | None = None
    best_payloads: set[bytes] = set()
    for weight in range(max_systematic_flips + 1):
        for positions in itertools.combinations(range(length), weight):
            candidate = systematic[:]
            for position in positions:
                candidate[position] ^= 1
            payload = _unframe(bits_to_bytes(candidate))
            if payload is None:
                continue
            expected = _turbo_encode_raw(candidate, order)
            distance = sum(a != b for a, b in zip(expected, encoded))
            if distance > max_bit_errors:
                continue
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_payloads = {payload}
            elif distance == best_distance:
                best_payloads.add(payload)
    return next(iter(best_payloads)) if len(best_payloads) == 1 else None


# ---------------------------------------------------------------------------
# Parity and checksum trailer families


def character_parity_encode(payload: bytes, *, odd: bool = False) -> bytes:
    """Store 7-bit characters with an even (default) or odd MSB parity bit."""
    if any(byte & 0x80 for byte in payload):
        raise ValueError("character parity accepts only 7-bit input")
    target = int(bool(odd))
    return bytes(byte | (((byte.bit_count() & 1) ^ target) << 7) for byte in payload)


def character_parity_decode(encoded: bytes, *, odd: bool = False) -> bytes | None:
    """Verify and remove a per-character even/odd parity bit."""
    if not encoded:
        return None
    target = int(bool(odd))
    if any((byte.bit_count() & 1) != target for byte in encoded):
        return None
    return bytes(byte & 0x7F for byte in encoded)


def parity_encode(payload: bytes, *, block_size: int = 8) -> bytes:
    """Append one XOR parity byte to every fixed-size data block."""
    if block_size <= 0 or not payload or len(payload) % block_size:
        raise ValueError("payload must contain complete non-empty parity blocks")
    out = bytearray()
    for offset in range(0, len(payload), block_size):
        block = payload[offset:offset + block_size]
        out.extend(block)
        out.append(0 if not block else _xor_bytes(block))
    return bytes(out)


def _xor_bytes(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value


def parity_decode(encoded: bytes, *, block_size: int = 8) -> bytes | None:
    stride = block_size + 1
    if block_size <= 0 or not encoded or len(encoded) % stride:
        return None
    out = bytearray()
    for offset in range(0, len(encoded), stride):
        block = encoded[offset:offset + block_size]
        if _xor_bytes(block) != encoded[offset + block_size]:
            return None
        out.extend(block)
    return bytes(out)


def _fletcher16(data: bytes) -> int:
    first = second = 0
    for byte in data:
        first = (first + byte) % 255
        second = (second + first) % 255
    return (second << 8) | first


def _internet16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _fletcher32(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    first = second = 0
    for index in range(0, len(data), 2):
        first = (first + ((data[index] << 8) | data[index + 1])) % 65535
        second = (second + first) % 65535
    return (second << 16) | first


def _bsd16(data: bytes) -> int:
    value = 0
    for byte in data:
        value = ((value >> 1) | ((value & 1) << 15))
        value = (value + byte) & 0xFFFF
    return value


def _sysv16(data: bytes) -> int:
    value = sum(data)
    value = (value & 0xFFFF) + (value >> 16)
    value = (value & 0xFFFF) + (value >> 16)
    return value & 0xFFFF


def _checksum(payload: bytes, family: str) -> tuple[int, int]:
    if family == "xor8":
        return _xor_bytes(payload), 1
    if family == "sum8":
        return sum(payload) & 0xFF, 1
    if family == "sum16":
        return sum(payload) & 0xFFFF, 2
    if family == "fletcher16":
        return _fletcher16(payload), 2
    if family == "fletcher32":
        return _fletcher32(payload), 4
    if family == "internet16":
        return _internet16(payload), 2
    if family == "bsd16":
        return _bsd16(payload), 2
    if family == "sysv16":
        return _sysv16(payload), 2
    if family == "adler32":
        return zlib.adler32(payload) & 0xFFFFFFFF, 4
    if family == "crc32":
        return binascii.crc32(payload) & 0xFFFFFFFF, 4
    raise ValueError(f"unknown checksum family: {family}")


def checksum_encode(payload: bytes, family: str, *, byteorder: str = "big") -> bytes:
    value, width = _checksum(payload, family)
    return payload + value.to_bytes(width, byteorder)


def checksum_decode(encoded: bytes, family: str, *, byteorder: str = "big") -> bytes | None:
    try:
        _, width = _checksum(b"", family)
    except ValueError:
        raise
    if len(encoded) <= width or byteorder not in ("big", "little"):
        return None
    payload, trailer = encoded[:-width], encoded[-width:]
    expected, _ = _checksum(payload, family)
    return payload if int.from_bytes(trailer, byteorder) == expected else None


__all__ = [
    "BCH", "CRCParameters", "GF2m", "LDPCCode", "ReedSolomon",
    "bits_to_bytes", "bytes_to_bits", "character_parity_decode",
    "character_parity_encode", "checksum_decode", "checksum_encode",
    "convolutional_encode", "convolutional_encode_bits", "crc_value",
    "hamming84_decode_nibbles",
    "hamming84_decode_raw", "hamming84_encode_raw", "hamming_secded_decode",
    "hamming_secded_encode", "parity_decode", "parity_encode",
    "recover_crc_parameters", "repair_crc_single_bit", "turbo_decode",
    "turbo_encode", "turbo_interleaver", "viterbi_decode", "viterbi_decode_bits",
]
