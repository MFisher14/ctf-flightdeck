#!/usr/bin/env python3
"""Verified transform/spread/adaptive steganography over bounded grayscale matrices.

This fills the non-JPEG transform gap beside :mod:`jpeg_stego` and :mod:`f5_stego`:

* 8x8 spatial-image DCT QIM;
* reversible one-level 2x2 Haar-DWT HH QIM;
* keyed direct-sequence spread spectrum;
* stable edge-adaptive pixel LSB (selection uses the upper six bits only);
* generic Hamming/matrix syndrome embedding.

Every extractor accepts a payload only when the embedded C5TG frame's declared length and CRC-32
verify.  A correlation/parity reading without that gate returns ``None`` rather than a best guess.
Embedding helpers exist for deterministic fixtures and return new matrices only; they execute and
send nothing.  The CLI reads strict binary PGM (P5) data, never an executable artifact.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import math
import struct
import sys
from pathlib import Path


MAGIC = b"C5TG"
MAX_PAYLOAD = 1 << 20
MAX_PIXELS = 16_000_000
MAX_BLOCKS = 250_000
HEADER = 12


class StegoError(ValueError):
    pass


def pack_frame(payload: bytes) -> bytes:
    payload = bytes(payload)
    if len(payload) > MAX_PAYLOAD:
        raise StegoError("payload exceeds 1 MiB cap")
    return MAGIC + len(payload).to_bytes(4, "big") + struct.pack(">I", binascii.crc32(payload) & 0xFFFFFFFF) + payload


def verify_frame(stream: bytes):
    """Return payload only for a complete length+CRC frame; otherwise ``None``."""
    stream = bytes(stream)
    if len(stream) < HEADER or stream[:4] != MAGIC:
        return None
    length = int.from_bytes(stream[4:8], "big")
    if length > MAX_PAYLOAD or HEADER + length > len(stream):
        return None
    payload = stream[HEADER:HEADER + length]
    expected = int.from_bytes(stream[8:12], "big")
    if (binascii.crc32(payload) & 0xFFFFFFFF) != expected:
        return None
    return payload


def _matrix(matrix) -> tuple[list[list[int]], int, int]:
    try:
        rows = [list(map(int, row)) for row in matrix]
    except (TypeError, ValueError, OverflowError) as exc:
        raise StegoError("matrix must contain integer samples") from exc
    if not rows or not rows[0] or len(rows) * len(rows[0]) > MAX_PIXELS:
        raise StegoError("matrix is empty or exceeds pixel cap")
    width = len(rows[0])
    if any(len(row) != width for row in rows) or any(not 0 <= value <= 255 for row in rows for value in row):
        raise StegoError("matrix must be rectangular 8-bit grayscale")
    return rows, width, len(rows)


def _bits(data: bytes):
    for value in data:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 1


def _bytes(bits, cap=MAX_PAYLOAD + HEADER) -> bytes:
    out, acc, count = bytearray(), 0, 0
    for bit in bits:
        acc = (acc << 1) | (int(bit) & 1)
        count += 1
        if count == 8:
            out.append(acc)
            if len(out) >= cap:
                break
            acc = count = 0
    return bytes(out)


_COS = [[math.cos((2 * x + 1) * u * math.pi / 16) for x in range(8)] for u in range(8)]
_SCALE = [1 / math.sqrt(2)] + [1.0] * 7


def _dct(block):
    result = [[0.0] * 8 for _ in range(8)]
    for u in range(8):
        for v in range(8):
            total = 0.0
            for y in range(8):
                for x in range(8):
                    total += (block[y][x] - 128) * _COS[u][x] * _COS[v][y]
            result[v][u] = 0.25 * _SCALE[u] * _SCALE[v] * total
    return result


def _idct(coeff):
    result = [[0] * 8 for _ in range(8)]
    for y in range(8):
        for x in range(8):
            total = 0.0
            for v in range(8):
                for u in range(8):
                    total += (_SCALE[u] * _SCALE[v] * coeff[v][u]
                              * _COS[u][x] * _COS[v][y])
            result[y][x] = max(0, min(255, round(0.25 * total + 128)))
    return result


def _qim_bit(value: float, delta: float) -> int:
    return int(round(abs(value) / delta)) & 1


def _qim_set(value: float, bit: int, delta: float) -> float:
    sign = -1.0 if value < 0 else 1.0
    level = max(1, int(round(abs(value) / delta)))
    if (level & 1) != bit:
        # Choose the nearer positive level with the requested parity.
        choices = [candidate for candidate in (level - 1, level + 1) if candidate >= 1 and candidate & 1 == bit]
        level = min(choices, key=lambda candidate: abs(candidate * delta - abs(value)))
    return sign * level * delta


def dct_embed(matrix, payload: bytes, *, delta: float = 36.0, coefficient=(3, 2)):
    rows, width, height = _matrix(matrix)
    u, v = map(int, coefficient)
    if not (0 <= u < 8 and 0 <= v < 8) or (u, v) == (0, 0) or not 8 <= delta <= 128:
        raise StegoError("invalid DCT coefficient/delta")
    bits = list(_bits(pack_frame(payload)))
    blocks = (width // 8) * (height // 8)
    if len(bits) > blocks or blocks > MAX_BLOCKS:
        raise StegoError("insufficient/capped DCT blocks")
    out = [row[:] for row in rows]
    at = 0
    for by in range(0, height - 7, 8):
        for bx in range(0, width - 7, 8):
            if at >= len(bits):
                return out
            block = [row[bx:bx + 8] for row in out[by:by + 8]]
            coeff = _dct(block)
            coeff[v][u] = _qim_set(coeff[v][u], bits[at], delta)
            rebuilt = _idct(coeff)
            # Pixel rounding slightly moves the coefficient. Re-quantize at most twice.
            for _ in range(2):
                check = _dct(rebuilt)[v][u]
                if _qim_bit(check, delta) == bits[at]:
                    break
                coeff = _dct(rebuilt)
                coeff[v][u] = _qim_set(coeff[v][u], bits[at], delta) + (delta if bits[at] else -delta)
                rebuilt = _idct(coeff)
            for y in range(8):
                out[by + y][bx:bx + 8] = rebuilt[y]
            at += 1
    return out


def dct_extract(matrix, *, delta: float = 36.0, coefficient=(3, 2)):
    rows, width, height = _matrix(matrix)
    u, v = map(int, coefficient)
    if not (0 <= u < 8 and 0 <= v < 8) or (u, v) == (0, 0) or not 8 <= delta <= 128:
        raise StegoError("invalid DCT coefficient/delta")
    blocks = (width // 8) * (height // 8)
    if blocks > MAX_BLOCKS:
        raise StegoError("DCT block cap exceeded")
    bits = []
    for by in range(0, height - 7, 8):
        for bx in range(0, width - 7, 8):
            coeff = _dct([row[bx:bx + 8] for row in rows[by:by + 8]])
            bits.append(_qim_bit(coeff[v][u], delta))
    return verify_frame(_bytes(bits))


def _haar_block(values):
    a, b, c, d = values
    return ((a + b + c + d) / 4, (a - b + c - d) / 4,
            (a + b - c - d) / 4, (a - b - c + d) / 4)


def _ihaar(ll, lh, hl, hh):
    return (ll + lh + hl + hh, ll - lh + hl - hh,
            ll + lh - hl - hh, ll - lh - hl + hh)


def dwt_embed(matrix, payload: bytes, *, delta: float = 24.0):
    rows, width, height = _matrix(matrix)
    if not 4 <= delta <= 128:
        raise StegoError("invalid DWT delta")
    bits = list(_bits(pack_frame(payload)))
    capacity = (width // 2) * (height // 2)
    if len(bits) > capacity:
        raise StegoError("insufficient DWT coefficients")
    out, at = [row[:] for row in rows], 0
    for y in range(0, height - 1, 2):
        for x in range(0, width - 1, 2):
            if at >= len(bits):
                return out
            ll, lh, hl, hh = _haar_block((out[y][x], out[y][x + 1], out[y + 1][x], out[y + 1][x + 1]))
            hh = _qim_set(hh, bits[at], delta)
            values = [max(0, min(255, round(value))) for value in _ihaar(ll, lh, hl, hh)]
            out[y][x], out[y][x + 1], out[y + 1][x], out[y + 1][x + 1] = values
            at += 1
    return out


def dwt_extract(matrix, *, delta: float = 24.0):
    rows, width, height = _matrix(matrix)
    if not 4 <= delta <= 128:
        raise StegoError("invalid DWT delta")
    bits = []
    for y in range(0, height - 1, 2):
        for x in range(0, width - 1, 2):
            bits.append(_qim_bit(_haar_block((rows[y][x], rows[y][x + 1],
                                              rows[y + 1][x], rows[y + 1][x + 1]))[3], delta))
    return verify_frame(_bytes(bits))


def _pn(seed: bytes, bit_index: int, chips: int):
    out, counter = [], 0
    while len(out) < chips:
        block = hashlib.sha256(seed + bit_index.to_bytes(8, "big") + counter.to_bytes(4, "big")).digest()
        out.extend(1 if byte & (1 << shift) else -1 for byte in block for shift in range(8))
        counter += 1
    values = out[:chips]
    # Remove any DC bias while retaining deterministic +/- chips.
    return [value - sum(values) / chips for value in values]


def spread_embed(matrix, payload: bytes, seed: bytes, *, chips: int = 64, strength: int = 8):
    rows, width, height = _matrix(matrix)
    seed = bytes(seed)
    if not seed or not 16 <= chips <= 4096 or not 1 <= strength <= 32:
        raise StegoError("invalid spread-spectrum parameters")
    bits = list(_bits(pack_frame(payload)))
    flat = [value for row in rows for value in row]
    if len(bits) * chips > len(flat):
        raise StegoError("insufficient spread-spectrum samples")
    for index, bit in enumerate(bits):
        signs = _pn(seed, index, chips)
        factor = strength if bit else -strength
        start = index * chips
        for offset, sign in enumerate(signs):
            flat[start + offset] = max(0, min(255, round(flat[start + offset] + factor * sign)))
    return [flat[y * width:(y + 1) * width] for y in range(height)]


def spread_extract(matrix, seed: bytes, *, chips: int = 64):
    rows, _width, _height = _matrix(matrix)
    seed = bytes(seed)
    if not seed or not 16 <= chips <= 4096:
        raise StegoError("invalid spread-spectrum parameters")
    flat = [value for row in rows for value in row]
    bits = []
    for index in range(min(len(flat) // chips, (MAX_PAYLOAD + HEADER) * 8)):
        block = flat[index * chips:(index + 1) * chips]
        mean = sum(block) / chips
        corr = sum((value - mean) * sign for value, sign in zip(block, _pn(seed, index, chips)))
        bits.append(1 if corr >= 0 else 0)
    return verify_frame(_bytes(bits))


def _edge_positions(rows, width, height, threshold):
    masked = [[value & 0xFC for value in row] for row in rows]
    for y in range(1, height - 1):
        for x in range(1, width - 1):
            gx = abs(masked[y][x + 1] - masked[y][x - 1])
            gy = abs(masked[y + 1][x] - masked[y - 1][x])
            if gx + gy >= threshold:
                yield y, x


def adaptive_embed(matrix, payload: bytes, *, threshold: int = 48):
    rows, width, height = _matrix(matrix)
    if not 0 <= threshold <= 510:
        raise StegoError("invalid edge threshold")
    positions = list(_edge_positions(rows, width, height, threshold))
    bits = list(_bits(pack_frame(payload)))
    if len(bits) > len(positions):
        raise StegoError("insufficient stable edge carriers")
    out = [row[:] for row in rows]
    for (y, x), bit in zip(positions, bits):
        out[y][x] = (out[y][x] & 0xFE) | bit
    return out


def adaptive_extract(matrix, *, threshold: int = 48):
    rows, width, height = _matrix(matrix)
    if not 0 <= threshold <= 510:
        raise StegoError("invalid edge threshold")
    bits = (rows[y][x] & 1 for y, x in _edge_positions(rows, width, height, threshold))
    return verify_frame(_bytes(bits))


def matrix_embed(samples, payload: bytes, *, k: int = 3):
    """Hamming/matrix encoding over sample LSBs; at most one carrier changes per group."""
    if not 1 <= k <= 8:
        raise StegoError("matrix k must be 1..8")
    values = [int(value) for value in samples]
    if len(values) > MAX_PIXELS or any(not 0 <= value <= 255 for value in values):
        raise StegoError("invalid matrix carriers")
    n = (1 << k) - 1
    bits = list(_bits(pack_frame(payload)))
    groups = (len(bits) + k - 1) // k
    if groups * n > len(values):
        raise StegoError("insufficient matrix carriers")
    bits.extend([0] * (groups * k - len(bits)))
    out = values[:]
    for group in range(groups):
        start = group * n
        syndrome = 0
        for pos in range(1, n + 1):
            if out[start + pos - 1] & 1:
                syndrome ^= pos
        target = 0
        for bit in bits[group * k:(group + 1) * k]:
            target = (target << 1) | bit
        flip = syndrome ^ target
        if flip:
            out[start + flip - 1] ^= 1
    return out


def matrix_extract(samples, *, k: int = 3):
    if not 1 <= k <= 8:
        raise StegoError("matrix k must be 1..8")
    values = [int(value) for value in samples]
    if len(values) > MAX_PIXELS or any(not 0 <= value <= 255 for value in values):
        raise StegoError("invalid matrix carriers")
    n, bits = (1 << k) - 1, []
    for start in range(0, len(values) - n + 1, n):
        syndrome = 0
        for pos in range(1, n + 1):
            if values[start + pos - 1] & 1:
                syndrome ^= pos
        bits.extend((syndrome >> shift) & 1 for shift in range(k - 1, -1, -1))
    return verify_frame(_bytes(bits))


def read_pgm(data: bytes):
    """Strict bounded P5 PGM parser used by the guarded CLI."""
    if not isinstance(data, bytes) or len(data) > MAX_PIXELS + 4096 or not data.startswith(b"P5"):
        raise StegoError("input is not a bounded binary PGM")
    tokens, at = [], 2
    while len(tokens) < 3:
        while at < len(data) and data[at] in b" \t\r\n": at += 1
        if at < len(data) and data[at] == 0x23:
            end = data.find(b"\n", at)
            if end < 0: raise StegoError("unterminated PGM comment")
            at = end + 1; continue
        end = at
        while end < len(data) and data[end] not in b" \t\r\n": end += 1
        if end == at: raise StegoError("truncated PGM header")
        tokens.append(data[at:end]); at = end
    try:
        width, height, maximum = map(int, tokens)
    except ValueError as exc:
        raise StegoError("invalid PGM header") from exc
    if maximum != 255 or width <= 0 or height <= 0 or width * height > MAX_PIXELS:
        raise StegoError("unsupported PGM dimensions/depth")
    if at >= len(data) or data[at] not in b" \t\r\n": raise StegoError("missing PGM separator")
    at += 1
    pixels = data[at:]
    if len(pixels) != width * height: raise StegoError("PGM pixel length mismatch")
    return [list(pixels[y * width:(y + 1) * width]) for y in range(height)]


class _Parser(argparse.ArgumentParser):
    def error(self, message): raise StegoError(message)


def main(argv=None) -> int:
    parser = _Parser(description="CRC-gated DCT/DWT/spread/adaptive stego extractor for P5 PGM")
    parser.add_argument("method", choices=("dct", "dwt", "spread", "adaptive", "matrix"))
    parser.add_argument("input")
    parser.add_argument("--seed", help="hex seed required by spread")
    parser.add_argument("--delta", type=float)
    parser.add_argument("--chips", type=int, default=64)
    parser.add_argument("--threshold", type=int, default=48)
    parser.add_argument("--k", type=int, default=3)
    try:
        args = parser.parse_args(argv)
        matrix = read_pgm(Path(args.input).read_bytes())
        if args.method == "dct": payload = dct_extract(matrix, delta=args.delta or 36.0)
        elif args.method == "dwt": payload = dwt_extract(matrix, delta=args.delta or 24.0)
        elif args.method == "spread":
            if not args.seed: raise StegoError("spread extraction requires --seed")
            payload = spread_extract(matrix, bytes.fromhex(args.seed), chips=args.chips)
        elif args.method == "adaptive": payload = adaptive_extract(matrix, threshold=args.threshold)
        else: payload = matrix_extract([value for row in matrix for value in row], k=args.k)
        print(json.dumps({"method": args.method, "verified": payload is not None,
                          "payload_hex": payload.hex() if payload is not None else None,
                          "note": "payload emitted only after C5TG length+CRC verification"}))
        return 0
    except (OSError, StegoError, ValueError, TypeError, OverflowError, MemoryError) as exc:
        print(f"transform_stego: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
