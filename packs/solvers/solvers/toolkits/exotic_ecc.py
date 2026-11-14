"""Checked offline decoders for Golay, Reed--Muller, general SECDED, and LT codes.

Raw block APIs implement standard binary codes and return data only inside the unique decoding
radius.  Payload APIs add a small length-and-CRC envelope so a corrected sequence is not confused
with a proven payload.  The LT implementation accepts only complete, CRC-protected equations and
verifies the recovered source against every supplied equation.  No external process, path, or
network facility is used.
"""

from __future__ import annotations

import math
import struct
import zlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Sequence


MAX_PAYLOAD = 8 * 1024 * 1024
MAX_BITS = 64 * 1024 * 1024
MAX_CODEWORDS = 100_000
MAX_LT_BLOCKS = 4096
MAX_LT_PACKETS = 65536
MAX_LT_BLOCK_SIZE = 65535
MAX_LT_ARTIFACT = 128 * 1024 * 1024
_FRAME_MAGIC = b"R5X3"
_LT_MAGIC = b"R5LT"


def bytes_to_bits(data: object) -> tuple[int, ...] | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size == 0 or size > MAX_PAYLOAD:
        return None
    raw = bytes(data)
    if len(raw) != size:
        return None
    return tuple((byte >> shift) & 1 for byte in raw for shift in range(7, -1, -1))


def bits_to_bytes(bits: object) -> bytes | None:
    checked = _bit_tuple(bits)
    if checked is None or len(checked) % 8:
        return None
    out = bytearray(len(checked) // 8)
    for index, bit in enumerate(checked):
        out[index // 8] |= bit << (7 - index % 8)
    return bytes(out)


def _bit_tuple(value: object, *, exact: int | None = None) -> tuple[int, ...] | None:
    # Only concrete built-in containers are admitted.  A user-defined Sequence can report a
    # small length while yielding forever, defeating a resource cap before a mismatch is noticed.
    if type(value) not in (tuple, list):
        return None
    try:
        length = len(value)
    except Exception:
        return None
    if exact is not None and length != exact:
        return None
    if length == 0 or length > MAX_BITS:
        return None
    out: list[int] = []
    try:
        for index in range(length):
            bit = value[index]
            if not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1):
                return None
            out.append(bit)
    except Exception:
        return None
    if len(out) != length:
        return None
    return tuple(out)


def _frame(payload: object) -> bytes | None:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return None
    size = payload.nbytes if isinstance(payload, memoryview) else len(payload)
    if size == 0 or size > MAX_PAYLOAD:
        return None
    raw = bytes(payload)
    if len(raw) != size:
        return None
    head = _FRAME_MAGIC + struct.pack(">I", len(raw)) + raw
    return head + struct.pack(">I", zlib.crc32(head) & 0xFFFFFFFF)


def _unframe_padded(bits: Sequence[int]) -> bytes | None:
    if len(bits) < 12 * 8:
        return None
    complete = len(bits) // 8 * 8
    raw = bytearray(complete // 8)
    for index in range(complete):
        raw[index // 8] |= bits[index] << (7 - index % 8)
    if raw[:4] != _FRAME_MAGIC:
        return None
    length = struct.unpack_from(">I", raw, 4)[0]
    if length == 0 or length > MAX_PAYLOAD:
        return None
    end = 8 + length
    if end + 4 > len(raw):
        return None
    expected = struct.unpack_from(">I", raw, end)[0]
    if zlib.crc32(raw[:end]) & 0xFFFFFFFF != expected:
        return None
    used_bits = (end + 4) * 8
    if any(bits[used_bits:]):
        return None
    return bytes(raw[8:end])


def _encode_framed(payload: object, data_bits: int, encoder) -> tuple[int, ...] | None:
    framed = _frame(payload)
    if framed is None:
        return None
    if (len(framed) * 8 + data_bits - 1) // data_bits > MAX_CODEWORDS:
        return None
    source = list(bytes_to_bits(framed) or ())
    padding = (-len(source)) % data_bits
    source.extend([0] * padding)
    out: list[int] = []
    for offset in range(0, len(source), data_bits):
        encoded = encoder(tuple(source[offset:offset + data_bits]))
        if encoded is None:
            return None
        out.extend(encoded)
    return tuple(out)


def _decode_framed(encoded: object, code_bits: int, decoder) -> bytes | None:
    if not isinstance(encoded, Sequence) or isinstance(encoded, (str, bytes, bytearray, memoryview)):
        return None
    try:
        length = len(encoded)
    except Exception:
        return None
    if length == 0 or length % code_bits or length // code_bits > MAX_CODEWORDS:
        return None
    bits = _bit_tuple(encoded)
    if bits is None:
        return None
    source: list[int] = []
    for offset in range(0, len(bits), code_bits):
        decoded = decoder(bits[offset:offset + code_bits])
        if decoded is None:
            return None
        source.extend(decoded)
    return _unframe_padded(source)


# ---------------------------------------------------------------------------
# General binary extended Hamming SECDED


def extended_hamming_encode_block(data: object, *, m: int) -> tuple[int, ...] | None:
    """Encode one standard extended Hamming ``(2**m, 2**m-m-1)`` block."""

    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 12:
        return None
    n = 1 << m
    k = n - m - 1
    source = _bit_tuple(data, exact=k)
    if source is None:
        return None
    word = [0] * (n + 1)  # conventional positions 1..n; n is extension parity
    iterator = iter(source)
    parity_positions = {1 << power for power in range(m)}
    for position in range(1, n):
        if position not in parity_positions:
            word[position] = next(iterator)
    for parity in parity_positions:
        word[parity] = sum(word[position] for position in range(1, n) if position & parity) & 1
    word[n] = sum(word[1:n]) & 1
    return tuple(word[1:])


def extended_hamming_decode_block(codeword: object, *, m: int) -> tuple[int, ...] | None:
    """Correct one bit and reject the detected two-bit case in a general SECDED block."""

    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 12:
        return None
    n = 1 << m
    raw = _bit_tuple(codeword, exact=n)
    if raw is None:
        return None
    word = [0] + list(raw)
    syndrome = 0
    for position in range(1, n):
        if word[position]:
            syndrome ^= position
    overall = sum(word[1:n + 1]) & 1
    if syndrome and overall:
        word[syndrome] ^= 1
    elif not syndrome and overall:
        word[n] ^= 1
    elif syndrome and not overall:
        return None
    verify = 0
    for position in range(1, n):
        if word[position]:
            verify ^= position
    if verify or sum(word[1:n + 1]) & 1:
        return None
    parity_positions = {1 << power for power in range(m)}
    return tuple(word[position] for position in range(1, n) if position not in parity_positions)


def extended_hamming_encode(payload: object, *, m: int = 4) -> tuple[int, ...] | None:
    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 12:
        return None
    return _encode_framed(payload, (1 << m) - m - 1,
                          lambda block: extended_hamming_encode_block(block, m=m))


def extended_hamming_decode(encoded: object, *, m: int = 4) -> bytes | None:
    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 12:
        return None
    return _decode_framed(encoded, 1 << m,
                          lambda block: extended_hamming_decode_block(block, m=m))


# ---------------------------------------------------------------------------
# Extended binary Golay (24, 12, 8)


_GOLAY_GENERATOR = 0xAE3  # x^11 + x^9 + x^7 + x^6 + x^5 + x + 1


def _poly_remainder(value: int, divisor: int) -> int:
    while value.bit_length() >= divisor.bit_length():
        value ^= divisor << (value.bit_length() - divisor.bit_length())
    return value


def golay24_encode_word(message: object) -> int | None:
    """Encode a 12-bit integer using the standard cyclic Golay polynomial plus even parity."""

    if not isinstance(message, int) or isinstance(message, bool) or not 0 <= message < (1 << 12):
        return None
    shifted = message << 11
    cyclic = shifted | _poly_remainder(shifted, _GOLAY_GENERATOR)
    return (cyclic << 1) | (cyclic.bit_count() & 1)


@lru_cache(maxsize=1)
def _golay_words() -> tuple[int, ...]:
    return tuple(golay24_encode_word(message) or 0 for message in range(1 << 12))


def golay24_decode_word(codeword: object) -> tuple[int, int] | None:
    """Return ``(message, corrected_bits)`` only for a unique word at distance at most three."""

    if not isinstance(codeword, int) or isinstance(codeword, bool) or not 0 <= codeword < (1 << 24):
        return None
    best_distance = 25
    best_message = -1
    tied = False
    for message, candidate in enumerate(_golay_words()):
        distance = (candidate ^ codeword).bit_count()
        if distance < best_distance:
            best_distance = distance
            best_message = message
            tied = False
        elif distance == best_distance:
            tied = True
    if tied or best_distance > 3:
        return None
    return best_message, best_distance


def _golay_encode_bits(block: Sequence[int]) -> tuple[int, ...] | None:
    message = 0
    for bit in block:
        message = (message << 1) | bit
    word = golay24_encode_word(message)
    if word is None:
        return None
    return tuple((word >> shift) & 1 for shift in range(23, -1, -1))


def _golay_decode_bits(block: Sequence[int]) -> tuple[int, ...] | None:
    word = 0
    for bit in block:
        word = (word << 1) | bit
    decoded = golay24_decode_word(word)
    if decoded is None:
        return None
    message, _distance = decoded
    return tuple((message >> shift) & 1 for shift in range(11, -1, -1))


def golay24_encode(payload: object) -> tuple[int, ...] | None:
    return _encode_framed(payload, 12, _golay_encode_bits)


def golay24_decode(encoded: object) -> bytes | None:
    return _decode_framed(encoded, 24, _golay_decode_bits)


# ---------------------------------------------------------------------------
# First-order Reed--Muller RM(1, m)


def reed_muller_encode_block(data: object, *, m: int) -> tuple[int, ...] | None:
    """Encode affine-function coefficients as an RM(1, m) word."""

    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 10:
        return None
    source = _bit_tuple(data, exact=m + 1)
    if source is None:
        return None
    constant, coefficients = source[0], source[1:]
    out: list[int] = []
    for point in range(1 << m):
        value = constant
        for index, coefficient in enumerate(coefficients):
            value ^= coefficient & ((point >> index) & 1)
        out.append(value)
    return tuple(out)


def reed_muller_decode_block(codeword: object, *, m: int) -> tuple[int, ...] | None:
    """Uniquely decode RM(1, m) with a Walsh--Hadamard transform."""

    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 10:
        return None
    n = 1 << m
    raw = _bit_tuple(codeword, exact=n)
    if raw is None:
        return None
    spectrum = [1 if bit == 0 else -1 for bit in raw]
    width = 1
    while width < n:
        for start in range(0, n, width * 2):
            for offset in range(width):
                left = spectrum[start + offset]
                right = spectrum[start + offset + width]
                spectrum[start + offset] = left + right
                spectrum[start + offset + width] = left - right
        width *= 2
    magnitude = max(abs(value) for value in spectrum)
    maxima = [index for index, value in enumerate(spectrum) if abs(value) == magnitude]
    if len(maxima) != 1:
        return None
    linear = maxima[0]
    constant = 0 if spectrum[linear] > 0 else 1
    coefficients = tuple((linear >> index) & 1 for index in range(m))
    message = (constant,) + coefficients
    rebuilt = reed_muller_encode_block(message, m=m)
    if rebuilt is None:
        return None
    distance = sum(left != right for left, right in zip(raw, rebuilt))
    minimum_distance = 1 << (m - 1)
    if distance > (minimum_distance - 1) // 2:
        return None
    return message


def reed_muller_encode(payload: object, *, m: int = 5) -> tuple[int, ...] | None:
    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 10:
        return None
    return _encode_framed(payload, m + 1, lambda block: reed_muller_encode_block(block, m=m))


def reed_muller_decode(encoded: object, *, m: int = 5) -> bytes | None:
    if not isinstance(m, int) or isinstance(m, bool) or not 3 <= m <= 10:
        return None
    return _decode_framed(encoded, 1 << m, lambda block: reed_muller_decode_block(block, m=m))


# ---------------------------------------------------------------------------
# LT fountain equations and a bounded binary artifact format


@dataclass(frozen=True, slots=True)
class LTPacket:
    seed: int
    indices: tuple[int, ...]
    payload: bytes
    checksum: int


@dataclass(frozen=True, slots=True)
class LTBundle:
    source_count: int
    block_size: int
    packets: tuple[LTPacket, ...]


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _packet_material(source_count: int, block_size: int, seed: int,
                     indices: Sequence[int], payload: bytes) -> bytes:
    head = struct.pack(">HHQH", source_count, block_size, seed, len(indices))
    return head + b"".join(struct.pack(">H", index) for index in indices) + payload


def _packet_checksum(source_count: int, block_size: int, seed: int,
                     indices: Sequence[int], payload: bytes) -> int:
    return zlib.crc32(_packet_material(source_count, block_size, seed, indices, payload)) & 0xFFFFFFFF


def _xorshift64(state: int) -> int:
    state &= 0xFFFFFFFFFFFFFFFF
    state ^= state >> 12
    state ^= state << 25 & 0xFFFFFFFFFFFFFFFF
    state ^= state >> 27
    return state * 0x2545F4914F6CDD1D & 0xFFFFFFFFFFFFFFFF


def _lt_indices(source_count: int, seed: int, *, c: float = 0.1,
                delta: float = 0.5, allow_systematic: bool = True) -> tuple[int, ...] | None:
    if (not isinstance(source_count, int) or isinstance(source_count, bool) or
            not 1 <= source_count <= MAX_LT_BLOCKS):
        return None
    if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        return None
    if (not isinstance(c, (int, float)) or isinstance(c, bool) or not math.isfinite(c) or
            not 0 < c <= 1 or not isinstance(delta, (int, float)) or isinstance(delta, bool) or
            not math.isfinite(delta) or not 0 < delta < 1):
        return None
    if not isinstance(allow_systematic, bool):
        return None
    if allow_systematic and seed < source_count:
        return (seed,)
    r = c * math.log(source_count / delta) * math.sqrt(source_count)
    pivot = max(1, min(source_count, int(source_count / max(r, 1e-12))))
    weights: list[float] = []
    for degree in range(1, source_count + 1):
        rho = 1.0 / source_count if degree == 1 else 1.0 / (degree * (degree - 1))
        if degree < pivot:
            tau = r / (degree * source_count)
        elif degree == pivot:
            tau = r * math.log(max(r / delta, 1.0)) / source_count
        else:
            tau = 0.0
        weights.append(rho + tau)
    state = _xorshift64(seed ^ 0x9E3779B97F4A7C15)
    target = (state >> 11) / float(1 << 53) * sum(weights)
    cumulative = 0.0
    degree = source_count
    for index, weight in enumerate(weights, 1):
        cumulative += weight
        if target < cumulative:
            degree = index
            break
    pool = list(range(source_count))
    for index in range(degree):
        state = _xorshift64(state)
        selected = index + state % (source_count - index)
        pool[index], pool[selected] = pool[selected], pool[index]
    return tuple(sorted(pool[:degree]))


def lt_encode(payload: object, *, block_size: int = 64,
              packet_count: int | None = None, seed: int = 0) -> LTBundle | None:
    """Frame payload bytes and make systematic plus robust-soliton LT packets."""

    framed = _frame(payload)
    if framed is None:
        return None
    if not isinstance(block_size, int) or isinstance(block_size, bool) or not 1 <= block_size <= MAX_LT_BLOCK_SIZE:
        return None
    if not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        return None
    source_count = (len(framed) + block_size - 1) // block_size
    if not 1 <= source_count <= MAX_LT_BLOCKS:
        return None
    if packet_count is None:
        packet_count = source_count + max(4, source_count // 2)
    if not isinstance(packet_count, int) or isinstance(packet_count, bool):
        return None
    if not source_count <= packet_count <= MAX_LT_PACKETS:
        return None
    if packet_count * (block_size + 16) > MAX_LT_ARTIFACT:
        return None
    padded = framed + b"\0" * (source_count * block_size - len(framed))
    blocks = [padded[index:index + block_size] for index in range(0, len(padded), block_size)]
    packets: list[LTPacket] = []
    aggregate = 13
    for number in range(packet_count):
        packet_seed = (seed + number) & 0xFFFFFFFFFFFFFFFF
        # The first source_count packet numbers remain systematic even with a nonzero base seed.
        derived_seed = (packet_seed + source_count) & 0xFFFFFFFFFFFFFFFF
        indices = ((number,) if number < source_count else
                   _lt_indices(source_count, derived_seed, allow_systematic=False))
        if indices is None:
            return None
        aggregate += 14 + len(indices) * 2 + block_size
        if aggregate > MAX_LT_ARTIFACT:
            return None
        encoded = bytes(block_size)
        for index in indices:
            encoded = _xor_bytes(encoded, blocks[index])
        checksum = _packet_checksum(source_count, block_size, packet_seed, indices, encoded)
        packets.append(LTPacket(packet_seed, indices, encoded, checksum))
    return LTBundle(source_count, block_size, tuple(packets))


def _validated_bundle(bundle: object) -> LTBundle | None:
    if type(bundle) is not LTBundle:
        return None
    source_count, block_size, packets = bundle.source_count, bundle.block_size, bundle.packets
    if (not isinstance(source_count, int) or isinstance(source_count, bool) or
            not 1 <= source_count <= MAX_LT_BLOCKS):
        return None
    if (not isinstance(block_size, int) or isinstance(block_size, bool) or
            not 1 <= block_size <= MAX_LT_BLOCK_SIZE):
        return None
    if type(packets) is not tuple or not source_count <= len(packets) <= MAX_LT_PACKETS:
        return None
    if source_count * block_size > MAX_PAYLOAD + block_size + 12:
        return None
    checked: list[LTPacket] = []
    aggregate = 13
    for packet in packets:
        if type(packet) is not LTPacket:
            return None
        if (not isinstance(packet.seed, int) or isinstance(packet.seed, bool) or
                not 0 <= packet.seed <= 0xFFFFFFFFFFFFFFFF):
            return None
        if type(packet.indices) is not tuple or not 1 <= len(packet.indices) <= source_count:
            return None
        if any(not isinstance(index, int) or isinstance(index, bool) for index in packet.indices):
            return None
        if (tuple(sorted(set(packet.indices))) != packet.indices or packet.indices[0] < 0 or
                packet.indices[-1] >= source_count):
            return None
        if type(packet.payload) is not bytes or len(packet.payload) != block_size:
            return None
        if (not isinstance(packet.checksum, int) or isinstance(packet.checksum, bool) or
                not 0 <= packet.checksum <= 0xFFFFFFFF):
            return None
        expected = _packet_checksum(source_count, block_size, packet.seed, packet.indices, packet.payload)
        if packet.checksum != expected:
            return None
        aggregate += 14 + len(packet.indices) * 2 + block_size
        if aggregate > MAX_LT_ARTIFACT:
            return None
        checked.append(packet)
    return LTBundle(source_count, block_size, tuple(checked))


def lt_decode(bundle: object) -> bytes | None:
    """Solve a complete set of checked LT equations and verify every equation."""

    valid = _validated_bundle(bundle)
    if valid is None:
        return None
    k = valid.source_count
    originals: list[tuple[int, bytes]] = []
    seen: dict[int, bytes] = {}
    for packet in valid.packets:
        mask = sum(1 << index for index in packet.indices)
        previous = seen.get(mask)
        if previous is not None and previous != packet.payload:
            return None
        seen[mask] = packet.payload
        originals.append((mask, packet.payload))
    basis: dict[int, tuple[int, bytes]] = {}
    for mask, payload in originals:
        right = payload
        while mask:
            pivot = (mask & -mask).bit_length() - 1
            row = basis.get(pivot)
            if row is None:
                basis[pivot] = (mask, right)
                break
            mask ^= row[0]
            right = _xor_bytes(right, row[1])
        if not mask and any(right):
            return None
    if len(basis) != k or any(index not in basis for index in range(k)):
        return None
    blocks = [bytes(valid.block_size) for _ in range(k)]
    for pivot in range(k - 1, -1, -1):
        mask, right = basis[pivot]
        value = right
        for index in range(pivot + 1, k):
            if mask >> index & 1:
                value = _xor_bytes(value, blocks[index])
        blocks[pivot] = value
    for mask, expected in originals:
        actual = bytes(valid.block_size)
        for index in range(k):
            if mask >> index & 1:
                actual = _xor_bytes(actual, blocks[index])
        if actual != expected:
            return None
    recovered = b"".join(blocks)
    bits = tuple((byte >> shift) & 1 for byte in recovered for shift in range(7, -1, -1))
    return _unframe_padded(bits)


def serialize_lt(bundle: object) -> bytes | None:
    valid = _validated_bundle(bundle)
    if valid is None:
        return None
    out = bytearray(_LT_MAGIC + struct.pack(">BHHI", 1, valid.source_count,
                                            valid.block_size, len(valid.packets)))
    for packet in valid.packets:
        out += struct.pack(">QH", packet.seed, len(packet.indices))
        out += b"".join(struct.pack(">H", index) for index in packet.indices)
        out += packet.payload
        out += struct.pack(">I", packet.checksum)
    if len(out) > MAX_LT_ARTIFACT:
        return None
    return bytes(out)


def parse_lt(data: object) -> LTBundle | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if not 13 <= size <= MAX_LT_ARTIFACT:
        return None
    raw = bytes(data)
    if len(raw) != size or raw[:4] != _LT_MAGIC:
        return None
    version, source_count, block_size, packet_count = struct.unpack_from(">BHHI", raw, 4)
    if (version != 1 or not 1 <= source_count <= MAX_LT_BLOCKS or
            not 1 <= block_size <= MAX_LT_BLOCK_SIZE or
            not source_count <= packet_count <= MAX_LT_PACKETS):
        return None
    offset = 13
    packets: list[LTPacket] = []
    for _ in range(packet_count):
        if offset + 10 > len(raw):
            return None
        seed, degree = struct.unpack_from(">QH", raw, offset)
        offset += 10
        if not 1 <= degree <= source_count or offset + degree * 2 + block_size + 4 > len(raw):
            return None
        indices = struct.unpack_from(f">{degree}H", raw, offset)
        offset += degree * 2
        payload = raw[offset:offset + block_size]
        offset += block_size
        checksum = struct.unpack_from(">I", raw, offset)[0]
        offset += 4
        packets.append(LTPacket(seed, tuple(indices), payload, checksum))
    if offset != len(raw):
        return None
    return _validated_bundle(LTBundle(source_count, block_size, tuple(packets)))


def decode_lt(data: object) -> bytes | None:
    bundle = parse_lt(data)
    return None if bundle is None else lt_decode(bundle)

