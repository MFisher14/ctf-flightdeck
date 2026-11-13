#!/usr/bin/env python3
"""Bounded, offline QR/Data Matrix/Aztec/PDF417 decoder with no barcode dependency.

Accepted inputs are a 0/1 matrix, an ASCII grid, or a raster image (Pillow is used only to read
pixels).  QR decoding itself is implemented here: orientation/polarity search, BCH format recovery,
all eight masks, function-module removal, block deinterleaving, GF(256) Reed--Solomon correction,
and numeric/alphanumeric/byte/Kanji segment parsing.  A result is returned only after corrected
blocks have zero syndromes and the payload bitstream parses exactly.

The sibling :mod:`matrix_barcodes` implements ECC200/DMRE Data Matrix, compact/full Aztec, ordinary/
Compact PDF417, and MicroPDF417 payload decoding, including their error correction and high-level
modes.  Raster inputs support bounded projective and cylindrical resampling; those samplers only
produce matrices, while finder metadata plus Reed--Solomon remain the payload acceptance boundary.
Nothing is uploaded or sent to a service.

Probe and repair (B-117), for a QR whose finder patterns were masked, removed or damaged or whose
format string is destroyed: :func:`probe` scores what is left of the fixed structure in every
orientation, ``decode_matrix(matrix, repair=True)`` (CLI ``--repair``) drops the finder gate and
forces every mask and error-correction level, :func:`force_format` reads with a stated format,
and :func:`restore_finders` paints the fixed patterns back for a camera decoder
(:func:`apply_transform` orients the matrix first, :func:`render_png` draws it).
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from pathlib import Path

try:
    import matrix_barcodes
except ImportError:  # package-style use
    from . import matrix_barcodes


MAX_SIDE = 177
# Python's matrix/list representation is much larger than the raster itself; keep the decoded
# working set comfortably bounded even when Pillow's own decompression-bomb limit is higher.
MAX_PIXELS = 4_000_000
MAX_INPUT = 16 << 20
MAX_RESULTS = 64

ALPHANUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

# Tables from ISO/IEC 18004, indexed [ECL][version]. ECL order is L, M, Q, H.
ECC_PER_BLOCK = (
    (-1, 7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30),
    (-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28),
    (-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30),
    (-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30),
)
NUM_BLOCKS = (
    (-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25),
    (-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49),
    (-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68),
    (-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81),
)
ECL_NAMES = ("L", "M", "Q", "H")
FORMAT_ECL = {1: 0, 0: 1, 3: 2, 2: 3}  # two format bits -> table row


def _matrix(value) -> list[list[bool]]:
    if not isinstance(value, (list, tuple)) or not value or len(value) > MAX_SIDE:
        raise ValueError("matrix must contain 1..177 rows")
    side = len(value)
    if side > MAX_SIDE:
        raise ValueError("matrix side exceeds QR cap")
    out = []
    for row in value:
        if not isinstance(row, (list, tuple)) or len(row) != side:
            raise ValueError("matrix must be square")
        converted = []
        for cell in row:
            if cell in (0, False, "0", ".", " "):
                converted.append(False)
            elif cell in (1, True, "1", "#", "X", "x", "@", "█"):
                converted.append(True)
            else:
                raise ValueError("matrix cells must be binary")
        out.append(converted)
    return out


def _rect_matrix(value) -> list[list[bool]]:
    if not isinstance(value, (list, tuple)) or not value or len(value) > MAX_SIDE:
        raise ValueError("matrix must contain 1..177 rows")
    width = len(value[0]) if isinstance(value[0], (list, tuple)) else 0
    if not 1 <= width <= 4 * MAX_SIDE:
        raise ValueError("matrix width exceeds cap")
    out = []
    for row in value:
        if not isinstance(row, (list, tuple)) or len(row) != width:
            raise ValueError("matrix rows must have equal width")
        converted = []
        for cell in row:
            if cell in (0, False, "0", ".", " "):
                converted.append(False)
            elif cell in (1, True, "1", "#", "X", "x", "@", "█"):
                converted.append(True)
            else:
                raise ValueError("matrix cells must be binary")
        out.append(converted)
    return out


def _parse_ascii_rows(text: str) -> list[list[str]]:
    if not isinstance(text, str) or len(text.encode("utf-8", "ignore")) > MAX_INPUT:
        raise ValueError("ASCII grid exceeds input cap")
    rows = [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]
    if not rows:
        raise ValueError("ASCII grid is empty")
    parsed = []
    for row in rows:
        tokens = row.split()
        if len(tokens) > 1 and all(token in ("0", "1", ".", "#", "X", "x", "@", "█") for token in tokens):
            parsed.append(tokens)
        else:
            compact = row.strip()
            if not compact or any(ch not in "01.#Xx@ █" for ch in compact):
                raise ValueError("ASCII grid contains an unknown cell")
            # Spaces inside an otherwise glyph-based grid are light modules, but spaces around a
            # compact 0/1 row are already stripped.
            parsed.append(list(compact))
    return parsed


def parse_ascii(text: str) -> list[list[bool]]:
    """Parse a square ASCII QR matrix."""
    return _matrix(_parse_ascii_rows(text))


def parse_ascii_rect(text: str) -> list[list[bool]]:
    """Parse a bounded rectangular matrix for non-QR structural routing."""
    return _rect_matrix(_parse_ascii_rows(text))


def _rotate(m):
    return [list(row) for row in zip(*m[::-1])]


def _transpose(m):
    return [list(row) for row in zip(*m)]


def transformations(matrix):
    """The 4 rotations x normal/mirrored x normal/inverted, deduplicated."""
    base = _matrix(matrix)
    seen = set()
    for inverted in (False, True):
        first = [[not c for c in row] for row in base] if inverted else [row[:] for row in base]
        for mirrored in (False, True):
            current = _transpose(first) if mirrored else [row[:] for row in first]
            for rotation in range(4):
                key = tuple(tuple(row) for row in current)
                if key not in seen:
                    seen.add(key)
                    yield current, {"inverted": inverted, "mirrored": mirrored, "rotation": rotation * 90}
                current = _rotate(current)


def _format_code(data5: int) -> int:
    value = data5 << 10
    rem = value
    while rem.bit_length() >= 11:
        rem ^= 0x537 << (rem.bit_length() - 11)
    return (value | rem) ^ 0x5412


def _read_format(m) -> int:
    coords = ([(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)]
              + [(i, 8) for i in range(5, -1, -1)])
    value = 0
    for bit, (x, y) in enumerate(coords):
        value |= int(m[y][x]) << bit
    return value


def _format_candidates(m):
    observed = _read_format(m)
    candidates = []
    for data in range(32):
        distance = (observed ^ _format_code(data)).bit_count()
        ecl_bits, mask = data >> 3, data & 7
        candidates.append((distance, FORMAT_ECL[ecl_bits], mask))
    return sorted(candidates)


def _alignment_positions(version: int) -> list[int]:
    if version == 1:
        return []
    count = version // 7 + 2
    step = 26 if version == 32 else ((version * 4 + count * 2 + 1) // (count * 2 - 2)) * 2
    result = [6]
    position = version * 4 + 10
    for _ in range(count - 1):
        result.insert(1, position)
        position -= step
    return result


def _function_modules(version: int) -> list[list[bool]]:
    size = version * 4 + 17
    f = [[False] * size for _ in range(size)]

    def mark(cx, cy, radius):
        for y in range(max(0, cy - radius), min(size, cy + radius + 1)):
            for x in range(max(0, cx - radius), min(size, cx + radius + 1)):
                f[y][x] = True

    mark(3, 3, 4)
    mark(size - 4, 3, 4)
    mark(3, size - 4, 4)
    for i in range(size):
        f[6][i] = True
        f[i][6] = True
    positions = _alignment_positions(version)
    for y in positions:
        for x in positions:
            if (x == 6 and y == 6) or (x == 6 and y == size - 7) or (x == size - 7 and y == 6):
                continue
            mark(x, y, 2)
    # Both format strings and the fixed dark module.
    for x, y in ([(8, i) for i in range(9)] + [(i, 8) for i in range(9)]
                 + [(8, size - 1 - i) for i in range(7)]
                 + [(size - 1 - i, 8) for i in range(8)] + [(8, size - 8)]):
        f[y][x] = True
    if version >= 7:
        for i in range(18):
            a, b = size - 11 + i % 3, i // 3
            f[b][a] = True
            f[a][b] = True
    return f


def _mask(mask: int, x: int, y: int) -> bool:
    return (
        (x + y) % 2 == 0 if mask == 0 else
        y % 2 == 0 if mask == 1 else
        x % 3 == 0 if mask == 2 else
        (x + y) % 3 == 0 if mask == 3 else
        (x // 3 + y // 2) % 2 == 0 if mask == 4 else
        x * y % 2 + x * y % 3 == 0 if mask == 5 else
        (x * y % 2 + x * y % 3) % 2 == 0 if mask == 6 else
        ((x + y) % 2 + x * y % 3) % 2 == 0
    )


def _raw_codewords(version: int) -> int:
    result = (16 * version + 128) * version + 64
    if version >= 2:
        align = version // 7 + 2
        result -= (25 * align - 10) * align - 55
        if version >= 7:
            result -= 36
    return result // 8


def _extract(m, version: int, mask: int) -> bytes | None:
    size, function = len(m), _function_modules(version)
    bits = []
    right = size - 1
    upward = True
    while right >= 1:
        if right == 6:
            right = 5
        for vertical in range(size):
            y = size - 1 - vertical if upward else vertical
            for x in (right, right - 1):
                if not function[y][x]:
                    bits.append(int(m[y][x]) ^ int(_mask(mask, x, y)))
        upward = not upward
        right -= 2
    count = _raw_codewords(version)
    if len(bits) < count * 8:
        return None
    return bytes(sum(bits[i * 8 + j] << (7 - j) for j in range(8)) for i in range(count))


# ---- GF(256) / Reed--Solomon ----------------------------------------------------------------------

GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]


def _gf_mul(x, y):
    return 0 if x == 0 or y == 0 else GF_EXP[GF_LOG[x] + GF_LOG[y]]


def _gf_div(x, y):
    if y == 0:
        raise ZeroDivisionError
    return 0 if x == 0 else GF_EXP[(GF_LOG[x] + 255 - GF_LOG[y]) % 255]


def _gf_pow(x, power):
    return 1 if power == 0 else (0 if x == 0 else GF_EXP[(GF_LOG[x] * power) % 255])


def _poly_scale(poly, scalar):
    return [_gf_mul(value, scalar) for value in poly]


def _poly_add(left, right):
    out = [0] * max(len(left), len(right))
    for i, value in enumerate(left):
        out[i + len(out) - len(left)] ^= value
    for i, value in enumerate(right):
        out[i + len(out) - len(right)] ^= value
    return out


def _poly_mul(left, right):
    out = [0] * (len(left) + len(right) - 1)
    for i, x in enumerate(left):
        for j, y in enumerate(right):
            out[i + j] ^= _gf_mul(x, y)
    return out


def _poly_eval(poly, x):
    value = poly[0]
    for coefficient in poly[1:]:
        value = _gf_mul(value, x) ^ coefficient
    return value


def _syndromes(message, count):
    return [0] + [_poly_eval(message, _gf_pow(2, i)) for i in range(count)]


def _error_locator(synd, nsym):
    err_loc, old_loc = [1], [1]
    shift = len(synd) - nsym
    for i in range(nsym):
        k = i + shift
        delta = synd[k]
        for j in range(1, len(err_loc)):
            delta ^= _gf_mul(err_loc[-(j + 1)], synd[k - j])
        old_loc.append(0)
        if delta:
            if len(old_loc) > len(err_loc):
                new_loc = _poly_scale(old_loc, delta)
                old_loc = _poly_scale(err_loc, _gf_div(1, delta))
                err_loc = new_loc
            err_loc = _poly_add(err_loc, _poly_scale(old_loc, delta))
    while err_loc and err_loc[0] == 0:
        del err_loc[0]
    errors = len(err_loc) - 1
    return err_loc if errors * 2 <= nsym else None


def _error_positions(locator, length):
    expected = len(locator) - 1
    positions = [length - 1 - i for i in range(length)
                 if _poly_eval(locator, _gf_pow(2, i)) == 0]
    return positions if len(positions) == expected else None


def _errata_locator(coef_positions):
    locator = [1]
    for position in coef_positions:
        locator = _poly_mul(locator, [1, _gf_pow(2, position)])
    return locator


def _error_evaluator(synd, locator, count):
    product = _poly_mul(synd, locator)
    # Remainder modulo x^(count+1): retain count+1 low-degree coefficients.
    return product[-(count + 1):] if count >= 0 else []


def _solve_error_magnitudes(synd, positions, length):
    """Solve the syndrome Vandermonde system for magnitudes at known symbol positions."""
    count = len(positions)
    if not count:
        return []
    matrix = []
    for row in range(count):
        matrix.append([_gf_pow(2, row * (length - 1 - position)) for position in positions]
                      + [synd[row + 1]])
    for column in range(count):
        pivot = next((row for row in range(column, count) if matrix[row][column]), None)
        if pivot is None:
            return None
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inv = _gf_div(1, matrix[column][column])
        matrix[column] = [_gf_mul(value, inv) for value in matrix[column]]
        for row in range(count):
            if row == column or matrix[row][column] == 0:
                continue
            factor = matrix[row][column]
            matrix[row] = [left ^ _gf_mul(factor, right)
                           for left, right in zip(matrix[row], matrix[column])]
    return [matrix[row][-1] for row in range(count)]


def rs_correct(message: bytes, nsym: int, erasures=()) -> tuple[bytes, int] | None:
    """Correct a QR RS block and return (block, corrected-symbol-count), or None."""
    if not (isinstance(message, bytes) and isinstance(nsym, int) and
            0 < nsym < len(message) <= 255):
        return None
    try:
        erase = list(dict.fromkeys(int(pos) for pos in erasures))
    except (TypeError, ValueError, OverflowError):
        return None
    if any(pos < 0 or pos >= len(message) for pos in erase) or len(erase) > nsym:
        return None
    msg = list(message)
    synd = _syndromes(msg, nsym)
    if max(synd) == 0:
        return message, 0
    # Remove known erasure contributions from the syndrome before locating any additional errors.
    # Magnitudes are solved against the original syndrome after all positions are known.
    if erase:
        fsynd = synd[1:]
        for pos in erase:
            x = _gf_pow(2, len(msg) - 1 - pos)
            fsynd = [_gf_mul(fsynd[i], x) ^ fsynd[i + 1] for i in range(len(fsynd) - 1)]
        locator = _error_locator([0] + fsynd, nsym - len(erase))
        if locator is None:
            return None
        unknown = _error_positions(locator[::-1], len(msg))
        if unknown is None:
            return None
        positions = sorted(set(unknown + erase))
        if 2 * len(unknown) + len(erase) > nsym:
            return None
    else:
        locator = _error_locator(synd, nsym)
        if locator is None:
            return None
        positions = _error_positions(locator[::-1], len(msg))
        if positions is None:
            return None
    magnitudes = _solve_error_magnitudes(synd, positions, len(msg))
    if magnitudes is None:
        return None
    corrections = [0] * len(msg)
    for position, magnitude in zip(positions, magnitudes):
        corrections[position] = magnitude
    fixed = bytes(a ^ b for a, b in zip(msg, corrections))
    return (fixed, len(positions)) if max(_syndromes(list(fixed), nsym)) == 0 else None


def _deinterleave(raw: bytes, version: int, ecl: int):
    blocks = NUM_BLOCKS[ecl][version]
    ecc = ECC_PER_BLOCK[ecl][version]
    if len(raw) != _raw_codewords(version):
        return None
    short_len = len(raw) // blocks
    short_count = blocks - len(raw) % blocks
    short_data = short_len - ecc
    data_lengths = [short_data + (0 if i < short_count else 1) for i in range(blocks)]
    rows = [bytearray(length + ecc) for length in data_lengths]
    cursor = 0
    for column in range(max(data_lengths)):
        for index, length in enumerate(data_lengths):
            if column < length:
                rows[index][column] = raw[cursor]
                cursor += 1
    for column in range(ecc):
        for index, length in enumerate(data_lengths):
            rows[index][length + column] = raw[cursor]
            cursor += 1
    if cursor != len(raw):
        return None
    data, corrected = bytearray(), 0
    for row, length in zip(rows, data_lengths):
        fixed = rs_correct(bytes(row), ecc)
        if fixed is None:
            return None
        data.extend(fixed[0][:length])
        corrected += fixed[1]
    return bytes(data), corrected


class _Bits:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data) * 8:
            raise ValueError("truncated QR segment")
        value = 0
        for _ in range(count):
            value = (value << 1) | ((self.data[self.pos // 8] >> (7 - self.pos % 8)) & 1)
            self.pos += 1
        return value

    def left(self):
        return len(self.data) * 8 - self.pos


def _count_bits(mode: int, version: int) -> int:
    group = 0 if version <= 9 else 1 if version <= 26 else 2
    return {1: (10, 12, 14), 2: (9, 11, 13), 4: (8, 16, 16), 8: (8, 10, 12)}[mode][group]


def _payload(data: bytes, version: int):
    bits = _Bits(data)
    chunks, segments, encoding = bytearray(), [], "iso-8859-1"
    fnc1 = False
    try:
        while bits.left() >= 4:
            mode = bits.take(4)
            if mode == 0:
                break
            if mode == 7:  # ECI
                first = bits.take(8)
                if first & 0x80 == 0:
                    assignment = first
                elif first & 0xC0 == 0x80:
                    assignment = ((first & 0x3F) << 8) | bits.take(8)
                elif first & 0xE0 == 0xC0:
                    assignment = ((first & 0x1F) << 16) | bits.take(16)
                else:
                    return None
                if assignment > 999999:
                    return None
                encoding = {3: "iso-8859-1", 4: "iso-8859-2", 20: "shift_jis",
                            26: "utf-8"}.get(assignment, encoding)
                segments.append({"mode": "eci", "assignment": assignment})
                continue
            if mode in (3, 5, 9):  # structured append / FNC1 / FNC1 second position
                if mode == 3:
                    if bits.left() < 16:
                        return None
                    segments.append({"mode": "structured-append", "value": bits.take(16)})
                else:
                    fnc1 = True
                    segments.append({"mode": "fnc1", "second": mode == 9})
                    if mode == 9:
                        segments[-1]["indicator"] = bits.take(8)
                continue
            if mode not in (1, 2, 4, 8):
                return None
            count = bits.take(_count_bits(mode, version))
            if count > 1 << 20:
                return None
            start = len(chunks)
            if mode == 1:
                remaining = count
                while remaining >= 3:
                    value = bits.take(10)
                    if value >= 1000:
                        return None
                    chunks.extend(f"{value:03d}".encode())
                    remaining -= 3
                if remaining:
                    width = 7 if remaining == 2 else 4
                    value = bits.take(width)
                    if value >= (100 if remaining == 2 else 10):
                        return None
                    chunks.extend(f"{value:0{remaining}d}".encode())
            elif mode == 2:
                remaining = count
                while remaining >= 2:
                    value = bits.take(11)
                    if value >= 45 * 45:
                        return None
                    chunks.extend((ALPHANUM[value // 45] + ALPHANUM[value % 45]).encode())
                    remaining -= 2
                if remaining:
                    value = bits.take(6)
                    if value >= 45:
                        return None
                    chunks.extend(ALPHANUM[value].encode())
                if fnc1:
                    # In FNC1 alphanumeric segments, %% is literal and % is GS.
                    chunks[start:] = re.sub(
                        b"%%|%", lambda match: b"%" if match[0] == b"%%" else b"\x1d",
                        chunks[start:])
            elif mode == 4:
                chunks.extend(bits.take(8) for _ in range(count))
            else:
                encoded = bytearray()
                for _ in range(count):
                    value = bits.take(13)
                    sub = ((value // 0xC0) << 8) | (value % 0xC0)
                    encoded.extend((sub + (0x8140 if sub < 0x1F00 else 0xC140)).to_bytes(2, "big"))
                try:
                    chunks.extend(encoded.decode("shift_jis").encode("utf-8"))
                except UnicodeError:
                    return None
            segments.append({"mode": {1: "numeric", 2: "alphanumeric", 4: "byte", 8: "kanji"}[mode],
                             "count": count, "offset": start, "length": len(chunks) - start,
                             "encoding": (encoding if mode == 4 else "utf-8" if mode == 8 else "ascii")})
        # Remaining terminator/alignment/pad data is not semantic. Re-encoding it is unnecessary;
        # RS plus a structurally valid segment stream is the proof boundary.
        raw = bytes(chunks)
        text_parts = []
        try:
            for segment in segments:
                if not segment.get("length"):
                    continue
                part = raw[segment["offset"]:segment["offset"] + segment["length"]]
                text_parts.append(part.decode(segment.get("encoding", "iso-8859-1")))
            text = "".join(text_parts)
        except (LookupError, UnicodeDecodeError):
            text = None
        return {"bytes": raw, "text": text, "segments": segments, "encoding": encoding}
    except (ValueError, OverflowError):
        return None


def _finder_score(m) -> int:
    size = len(m)
    score = 0
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        good = total = 0
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                expected = max(abs(dx), abs(dy)) in (0, 1, 3)
                good += m[cy + dy][cx + dx] == expected
                total += 1
        score += good * 100 // total
    return score // 3


FINDER_GATE = 70                # percent of finder modules an orientation needs before a strict decode
FINDER_CORNERS = ("top-left", "top-right", "bottom-left")


def _corner_scores(m) -> tuple[int, int, int]:
    """Percent of the 7x7 finder modules that are right, for the three finder corners in turn."""
    size = len(m)
    out = []
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        good = 0
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                good += m[cy + dy][cx + dx] == (max(abs(dx), abs(dy)) in (0, 1, 3))
        out.append(good * 100 // 49)
    return tuple(out)


def _timing_score(m) -> int:
    """Percent of the two timing lines (row 6 and column 6, between the finders) that alternate
    dark on the even modules. 100 when the symbol is too small to have any."""
    size = len(m)
    good = total = 0
    for i in range(8, size - 8):
        expected = i % 2 == 0
        good += (m[6][i] == expected) + (m[i][6] == expected)
        total += 2
    return good * 100 // total if total else 100


def _alignment_score(m, version: int) -> int | None:
    """Percent of the alignment-pattern modules that are right, or None for a version without one."""
    size = len(m)
    positions = _alignment_positions(version)
    good = total = 0
    for cy in positions:
        for cx in positions:
            if (cx == 6 and cy == 6) or (cx == 6 and cy == size - 7) or (cx == size - 7 and cy == 6):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    good += m[cy + dy][cx + dx] == (max(abs(dx), abs(dy)) != 1)
                    total += 1
    return good * 100 // total if total else None


def _structure(m, version: int) -> dict:
    corners = _corner_scores(m)
    return {"finder_score": sum(corners) // 3, "finders": dict(zip(FINDER_CORNERS, corners)),
            "timing_score": _timing_score(m), "alignment_score": _alignment_score(m, version),
            "format_distance": _format_candidates(m)[0][0]}


def _structure_rank(s: dict) -> int:
    """How much of the fixed structure one orientation shows; higher is tried first by a repair."""
    return (s["finder_score"] + s["timing_score"] + (s["alignment_score"] or 0)
            + (15 - s["format_distance"]) * 2)


def probe(matrix) -> dict:
    """What is left of a QR's fixed structure in a square module matrix, without decoding it.

    For each of the 16 orientations (4 rotations, mirrored, inverted) the three finder patterns,
    the timing lines, the alignment patterns and the format string are scored. The best orientation
    is reported with the parts that are damaged there: ``finder top-left`` (and the other two
    corners) under the strict gate, ``timing`` under 85 percent, ``alignment`` under 80, ``format``
    when no format code is within BCH reach (distance over 3). ``plausible`` says a repair decode is
    worth its cost: some orientation still shows finders, or clean timing lines (from version 2,
    whose lines are long enough to mean something), or flawless timing lines beside a format code
    within BCH reach (version 1). Not a decode: :func:`decode_matrix` with ``repair=True`` is, and
    Reed--Solomon stays its acceptance boundary.
    """
    base = _matrix(matrix)
    size = len(base)
    if size < 21 or size > 177 or (size - 17) % 4:
        return {"size": size, "version": None, "plausible": False, "orientations": [],
                "damaged": ["size is not 17 + 4 * version"]}
    version = (size - 17) // 4
    rows = []
    for transformed, transform in transformations(base):
        rows.append({"transform": transform, **_structure(transformed, version)})
    rows.sort(key=lambda row: -_structure_rank(row))
    best = rows[0]
    damaged = [f"finder {name}" for name, score in best["finders"].items() if score < FINDER_GATE]
    if best["timing_score"] < 85:
        damaged.append("timing")
    if best["alignment_score"] is not None and best["alignment_score"] < 80:
        damaged.append("alignment")
    if best["format_distance"] > 3:
        damaged.append("format")
    plausible = any(row["finder_score"] >= FINDER_GATE
                    or (row["timing_score"] >= 85 and size >= 25)
                    or (row["timing_score"] == 100 and row["format_distance"] <= 3) for row in rows)
    return {"size": size, "version": version, "plausible": plausible, "damaged": damaged,
            "best": best, "orientations": rows}


def apply_transform(matrix, transform: dict) -> list[list[bool]]:
    """The matrix in the orientation a decode result's ``transform`` names (finders top-left,
    top-right and bottom-left, dark modules True)."""
    current = _matrix(matrix)
    if transform.get("inverted"):
        current = [[not cell for cell in row] for row in current]
    if transform.get("mirrored"):
        current = _transpose(current)
    turns = int(transform.get("rotation", 0)) // 90
    if int(transform.get("rotation", 0)) % 90 or not 0 <= turns <= 3:
        raise ValueError("rotation must be 0, 90, 180 or 270")
    for _ in range(turns):
        current = _rotate(current)
    return current


def restore_finders(matrix) -> list[list[bool]]:
    """A copy of an upright QR matrix with its fixed function patterns painted back: the three
    finder patterns with their light separators, both timing lines, the alignment patterns and the
    dark module. Format and version information and every data module are left as they are. For a
    symbol whose finders were removed or painted over, so that a camera decoder (zbar, zxing) or a
    person can find it again; orient the matrix first (:func:`apply_transform`)."""
    m = _matrix(matrix)
    size = len(m)
    if size < 21 or size > 177 or (size - 17) % 4:
        raise ValueError("matrix side is not 17 + 4 * version")
    version = (size - 17) // 4
    for i in range(8, size - 8):
        m[6][i] = m[i][6] = i % 2 == 0
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    m[y][x] = max(abs(dx), abs(dy)) in (0, 1, 3)
    positions = _alignment_positions(version)
    for cy in positions:
        for cx in positions:
            if (cx == 6 and cy == 6) or (cx == 6 and cy == size - 7) or (cx == size - 7 and cy == 6):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    m[cy + dy][cx + dx] = max(abs(dx), abs(dy)) != 1
    m[size - 8][8] = True
    return m


def render_png(matrix, scale: int = 8, border: int = 4) -> bytes:
    """PNG bytes of a module matrix, ``scale`` pixels a module inside a light ``border``."""
    m = _rect_matrix(matrix)
    if not (1 <= scale <= 64 and 0 <= border <= 64):
        raise ValueError("scale must be 1..64 and border 0..64")
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover
        raise ValueError("rendering a matrix requires Pillow") from exc
    import io
    height, width = len(m), len(m[0])
    image = Image.new("L", (width + 2 * border, height + 2 * border), 255)
    for y, row in enumerate(m):
        for x, cell in enumerate(row):
            if cell:
                image.putpixel((x + border, y + border), 0)
    if scale > 1:
        image = image.resize((image.width * scale, image.height * scale), Image.NEAREST)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def _result_order(item):
    return (item["format_distance"], item["corrected_symbols"], -item["finder_score"])


def decode_matrix(matrix, *, repair: bool = False) -> list[dict]:
    """Decode a square QR module matrix in every orientation and polarity.

    Strict (the default): an orientation is read only when its finder patterns score at least
    ``FINDER_GATE``, and a format code within BCH reach that verifies ends that orientation.

    ``repair=True`` is for a symbol whose finders are masked, removed or damaged, or whose format
    string is destroyed: the finder gate is dropped, the orientations are tried in the order of
    how much fixed structure they show (:func:`probe`), and every mask and error-correction level
    is forced through in each. The first orientation that reads ends the search. Reed--Solomon
    with zero syndromes plus an exactly parsing, non-empty payload stays the acceptance boundary
    (a matrix that is one of the mask patterns unmasks to the all-zero codeword, which carries no
    payload and is refused). Every result says ``repaired``: True when the strict path would not
    have read it (finders under the gate, or a format string out of BCH reach)."""
    base = _matrix(matrix)
    size = len(base)
    if size < 21 or size > 177 or (size - 17) % 4:
        return []
    version = (size - 17) // 4
    orientations = [(transformed, transform, _finder_score(transformed))
                    for transformed, transform in transformations(base)]
    if repair:
        ranked = sorted(((-_structure_rank(_structure(transformed, version)), index)
                         for index, (transformed, _t, _f) in enumerate(orientations)))
        orientations = [orientations[index] for _rank, index in ranked]
    results, seen = [], set()
    for transformed, transform, finder in orientations:
        if finder < FINDER_GATE and not repair:
            continue
        for distance, ecl, mask in _format_candidates(transformed):
            raw = _extract(transformed, version, mask)
            if raw is None:
                continue
            fixed = _deinterleave(raw, version, ecl)
            if fixed is None:
                continue
            payload = _payload(fixed[0], version)
            if payload is None or (repair and not payload["bytes"]):
                continue
            key = payload["bytes"]
            if key in seen:
                continue
            seen.add(key)
            results.append({"symbology": "qr", "version": version, "ecl": ECL_NAMES[ecl],
                            "mask": mask, "format_distance": distance, "finder_score": finder,
                            "corrected_symbols": fixed[1], "transform": transform,
                            "repaired": finder < FINDER_GATE or distance > 3, **payload})
            if len(results) >= MAX_RESULTS:
                return sorted(results, key=_result_order)
            # A BCH-valid format candidate plus verified RS has no reason to try weaker formats for
            # this orientation. Damaged-format cases continue through all masks/ECLs.
            if distance <= 3:
                break
        if repair and results:
            break
    return sorted(results, key=_result_order)


def force_format(matrix, ecl, mask: int) -> dict | None:
    """Read one upright matrix with a stated error-correction level (0..3 or "L", "M", "Q", "H")
    and mask (0..7), never looking at the format string. For a symbol whose format modules are
    painted over while the data survives and the format is known or being enumerated by hand.
    Returns the reading, or None when Reed--Solomon or the payload parse fails. No orientation
    search is made: ``decode_matrix(matrix, repair=True)`` forces every format in every
    orientation."""
    if isinstance(ecl, str) and ecl.upper() in ECL_NAMES:
        ecl = ECL_NAMES.index(ecl.upper())
    if isinstance(ecl, bool) or isinstance(mask, bool) or not isinstance(ecl, int) \
            or not isinstance(mask, int) or not (0 <= ecl <= 3 and 0 <= mask <= 7):
        raise ValueError("ecl must be 0..3 or L/M/Q/H, and mask 0..7")
    base = _matrix(matrix)
    size = len(base)
    if size < 21 or size > 177 or (size - 17) % 4:
        return None
    version = (size - 17) // 4
    raw = _extract(base, version, mask)
    fixed = _deinterleave(raw, version, ecl) if raw is not None else None
    payload = _payload(fixed[0], version) if fixed is not None else None
    if payload is None or not payload["bytes"]:
        return None
    return {"symbology": "qr", "version": version, "ecl": ECL_NAMES[ecl], "mask": mask,
            "format_distance": None, "finder_score": _finder_score(base),
            "corrected_symbols": fixed[1], "forced_format": True, "repaired": True, **payload}


def recognize_other(matrix) -> list[dict]:
    """Decode non-QR families, or return honest structural evidence after integrity failure."""
    m = _rect_matrix(matrix)
    h, width = len(m), len(m[0])
    decoded = matrix_barcodes.decode_other(m)
    if decoded:
        return decoded
    out = []
    # Square DataMatrix ECC200: solid left/bottom borders, alternating top/right borders.
    if width == h and 10 <= h <= 144 and h % 2 == 0:
        solid = sum(m[y][0] for y in range(h)) + sum(m[h - 1][x] for x in range(h))
        alternating = sum(m[0][x] == (x % 2 == 0) for x in range(h)) + sum(
            m[y][h - 1] == (y % 2 == 1) for y in range(h))
        score = (solid + alternating) * 100 // (4 * h)
        if score >= 75:
            out.append({"symbology": "datamatrix", "score": score, "payload": None,
                        "status": "recognized; finder/placement/RS/payload validation failed"})
    # Aztec has concentric alternating square rings around one center.
    if width == h and h >= 15 and h % 2 == 1:
        c, matches, total = h // 2, 0, 0
        for radius in range(0, min(7, c + 1)):
            expected = radius % 2 == 0
            for x, y in ((c - radius, c), (c + radius, c), (c, c - radius), (c, c + radius)):
                matches += m[y][x] == expected
                total += 1
        score = matches * 100 // max(1, total)
        if score >= 80:
            out.append({"symbology": "aztec", "score": score, "payload": None,
                        "status": "recognized; mode-message/payload RS validation failed"})
    # PDF417 rows use fixed 17-module start and 18-module stop patterns. Accept a bounded number of
    # bit errors because a raster sampler may trim one edge; this is routing evidence, never payload.
    if 3 <= h <= 90 and width >= 35 and width >= h * 2:
        start, stop = "11111111010101000", "111111101000101001"

        def distance(bits, pattern):
            return sum(a != b for a, b in zip(bits, pattern))

        matches = 0
        for row in m:
            bits = "".join("1" if cell else "0" for cell in row)
            normal = distance(bits[:17], start) <= 2 and distance(bits[-18:], stop) <= 2
            reverse = distance(bits[-17:][::-1], start) <= 2 and distance(bits[:18][::-1], stop) <= 2
            matches += normal or reverse
        score = matches * 100 // h
        if score >= 60:
            out.append({"symbology": "pdf417", "score": score, "payload": None,
                        "status": "recognized; row-indicator/RS/payload validation failed"})
    return sorted(out, key=lambda item: -item["score"])


def parse_dimensions(value: str) -> tuple[int, int]:
    """Parse guarded ``WIDTHxHEIGHT`` module dimensions for the raster sampler."""
    if not isinstance(value, str):
        raise ValueError("dimensions must be WIDTHxHEIGHT")
    match = re.fullmatch(r"\s*(\d{1,3})\s*[xX,]\s*(\d{1,3})\s*", value or "")
    if not match:
        raise ValueError("dimensions must be WIDTHxHEIGHT")
    width, height = map(int, match.groups())
    if not (1 <= height <= 180 and 1 <= width <= 720 and width * height <= 100_000):
        raise ValueError("module dimensions exceed sampler cap")
    return width, height


def parse_corners(value: str) -> tuple[tuple[float, float], ...]:
    """Parse ``TLx,TLy;TRx,TRy;BRx,BRy;BLx,BLy`` without evaluating input."""
    if not isinstance(value, str):
        raise ValueError("corners require TL;TR;BR;BL coordinate pairs")
    pieces = (value or "").split(";")
    if len(pieces) != 4:
        raise ValueError("corners require TL;TR;BR;BL coordinate pairs")
    corners = []
    for piece in pieces:
        match = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*", piece)
        if not match:
            raise ValueError("each corner must be x,y")
        point = tuple(map(float, match.groups()))
        if not all(math.isfinite(item) and abs(item) <= 100_000 for item in point):
            raise ValueError("corner coordinate outside cap")
        corners.append(point)
    return tuple(corners)


def _solve_linear(system):
    """Small partial-pivot Gaussian solve used for a four-point homography."""
    size = len(system)
    work = [list(map(float, row)) for row in system]
    if size != 8 or any(len(row) != 9 for row in work):
        raise ValueError("invalid homography system")
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(work[row][column]))
        if abs(work[pivot][column]) < 1e-10:
            raise ValueError("degenerate sampling quadrilateral")
        work[column], work[pivot] = work[pivot], work[column]
        scale = work[column][column]
        work[column] = [value / scale for value in work[column]]
        for row in range(size):
            if row == column:
                continue
            factor = work[row][column]
            if factor:
                work[row] = [left - factor * right
                             for left, right in zip(work[row], work[column])]
    answer = [work[row][-1] for row in range(size)]
    if not all(math.isfinite(value) and abs(value) < 1e9 for value in answer):
        raise ValueError("unstable sampling homography")
    return answer


def _homography(corners):
    system = []
    for (u, v), (x, y) in zip(((0, 0), (1, 0), (1, 1), (0, 1)), corners):
        system.append([u, v, 1, 0, 0, 0, -x * u, -x * v, x])
        system.append([0, 0, 0, u, v, 1, -y * u, -y * v, y])
    return _solve_linear(system)


def _cylindrical_u(value, curvature):
    if curvature == 0:
        return value
    angle = math.asin(curvature)
    return 0.5 + math.sin((2 * value - 1) * angle) / (2 * curvature)


def _project_point(coefficients, u, v):
    a, b, c, d, e, f, g, h = coefficients
    denominator = g * u + h * v + 1
    if abs(denominator) < 1e-9:
        raise ValueError("sampling point crosses projective horizon")
    return ((a * u + b * v + c) / denominator,
            (d * u + e * v + f) / denominator)


def projective_sample(pixels, pixel_width, pixel_height, dimensions, corners, *,
                      curvature=0.0, threshold=None):
    """Sample a perspective/cylindrically warped symbol into a binary module matrix.

    ``corners`` are the outer TL/TR/BR/BL module-boundary points.  ``curvature`` is a normalized
    cylinder projection in ``[0, .95]``.  A 3x3 vote per module avoids committing a single noisy
    pixel; this function never decodes or returns a payload.
    """
    modules_w, modules_h = dimensions
    if not (isinstance(pixels, (list, tuple)) and len(pixels) == pixel_width * pixel_height and
            1 <= modules_h <= 180 and 1 <= modules_w <= 720 and
            modules_h * modules_w <= 100_000):
        raise ValueError("invalid projective sampler dimensions")
    if any(not isinstance(value, (int, float)) or not 0 <= value <= 255 for value in pixels):
        raise ValueError("raster pixels must be numeric grayscale values in 0..255")
    if not 0 <= curvature <= 0.95 or not math.isfinite(curvature):
        raise ValueError("curvature must be between 0 and 0.95")
    corners = tuple(tuple(map(float, point)) for point in corners)
    if len(corners) != 4 or any(len(point) != 2 for point in corners):
        raise ValueError("four sampling corners are required")
    # Convexity/area rejects crossed, repeated, and nearly collinear user coordinates.
    crosses = []
    for index in range(4):
        p, q, r = corners[index], corners[(index + 1) % 4], corners[(index + 2) % 4]
        crosses.append((q[0] - p[0]) * (r[1] - q[1]) - (q[1] - p[1]) * (r[0] - q[0]))
    if min(abs(value) for value in crosses) < 1e-5 or not (
            all(value > 0 for value in crosses) or all(value < 0 for value in crosses)):
        raise ValueError("sampling corners must form a convex TL/TR/BR/BL quadrilateral")
    if any(x < -1 or y < -1 or x > pixel_width + 1 or y > pixel_height + 1
           for x, y in corners):
        raise ValueError("sampling corner outside raster")
    coefficients = _homography(corners)
    if threshold is None:
        threshold = (min(pixels) + max(pixels)) / 2
    offsets = (-0.22, 0.0, 0.22)
    result = []
    for module_y in range(modules_h):
        row = []
        for module_x in range(modules_w):
            votes = 0
            for dy in offsets:
                v = (module_y + 0.5 + dy) / modules_h
                for dx in offsets:
                    u = _cylindrical_u((module_x + 0.5 + dx) / modules_w, curvature)
                    x, y = _project_point(coefficients, u, v)
                    ix, iy = int(math.floor(x)), int(math.floor(y))
                    if not (0 <= ix < pixel_width and 0 <= iy < pixel_height):
                        raise ValueError("projected sample outside raster")
                    votes += pixels[iy * pixel_width + ix] <= threshold
            row.append(votes >= 5)
        result.append(row)
    return result


def _otsu_threshold(pixels):
    histogram = [0] * 256
    for value in pixels:
        histogram[value] += 1
    total, weighted = len(pixels), sum(index * count for index, count in enumerate(histogram))
    background_weight = background_sum = 0
    best_variance, best = -1.0, (min(pixels) + max(pixels)) // 2
    for threshold, count in enumerate(histogram):
        background_weight += count
        if not background_weight:
            continue
        foreground_weight = total - background_weight
        if not foreground_weight:
            break
        background_sum += threshold * count
        left = background_sum / background_weight
        right = (weighted - background_sum) / foreground_weight
        variance = background_weight * foreground_weight * (left - right) ** 2
        if variance > best_variance:
            best_variance, best = variance, threshold
    return best


def _dark_geometry(bitmap):
    height, width = len(bitmap), len(bitmap[0])
    points = [(x, y) for y, row in enumerate(bitmap) for x, value in enumerate(row) if value]
    if not points:
        return None, None
    left, right = min(x for x, _ in points), max(x for x, _ in points)
    top, bottom = min(y for _, y in points), max(y for _, y in points)
    box = ((left, top), (right + 1, top), (right + 1, bottom + 1), (left, bottom + 1))
    extreme = (min(points, key=lambda p: p[0] + p[1]),
               max(points, key=lambda p: p[0] - p[1]),
               max(points, key=lambda p: p[0] + p[1]),
               min(points, key=lambda p: p[0] - p[1]))
    try:
        _homography(extreme)
    except ValueError:
        extreme = box
    return box, extreme


def _known_perspective_dimensions(box):
    dimensions = {(17 + 4 * version, 17 + 4 * version) for version in range(1, 41)}
    dimensions.update((symbol.width, symbol.height)
                      for symbol in matrix_barcodes._DM_SYMBOLS.values())
    dimensions.update((width, variant.rows) for width, columns in
                      ((38, 1), (55, 2), (82, 3), (99, 4))
                      for variant in matrix_barcodes._MICRO_VARIANTS.values()
                      if variant.columns == columns)
    for compact in (False, True):
        limit = 4 if compact else 32
        for layers in range(1, limit + 1):
            size = matrix_barcodes._aztec_expected_size(layers, compact)
            dimensions.add((size, size))
    left, top = box[0]
    right, bottom = box[2]
    boxw, boxh = right - left, bottom - top
    ranked = []
    for width, height in dimensions:
        sx, sy = boxw / width, boxh / height
        if min(sx, sy) < 0.75 or not 0.5 <= sx / sy <= 2.0:
            continue
        ranked.append((abs(math.log(sx / sy)), -min(sx, sy), width, height))
    return [(width, height) for _, _, width, height in sorted(ranked)[:16]]


def raster_matrices(path, *, dimensions=None, corners=None, curvatures=None) -> list[list[list[bool]]]:
    try:
        from PIL import Image
    except Exception as exc:  # pragma: no cover
        raise ValueError("raster input requires Pillow") from exc
    try:
        with Image.open(path) as image:
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
                raise ValueError("raster pixel count exceeds cap")
            image = image.convert("L")
            pixels = list(image.get_flattened_data() if hasattr(image, "get_flattened_data") else image.getdata())
    except Exception as exc:
        # Pillow's decoders expose format-specific exceptions for malformed bytes.
        raise ValueError(f"cannot read raster: {exc}") from exc
    threshold = _otsu_threshold(pixels)
    base = [[pixels[y * width + x] <= threshold for x in range(width)] for y in range(height)]
    candidates, seen = [], set()

    # Perspective/cylindrical candidates go first so an explicitly supplied geometry cannot be
    # displaced by the legacy integral-scale search's candidate cap.
    box, extreme = _dark_geometry(base)
    if box is not None:
        if dimensions is not None:
            if not (isinstance(dimensions, tuple) and len(dimensions) == 2):
                raise ValueError("dimensions must be a (width, height) tuple")
            perspective_dimensions = [dimensions]
        else:
            perspective_dimensions = _known_perspective_dimensions(box)
        quadrilaterals = [corners] if corners is not None else [extreme, box]
        curves = tuple(curvatures) if curvatures is not None else (0.0, 0.4, 0.7)
        if not 1 <= len(curves) <= 8:
            raise ValueError("one to eight curvature candidates are allowed")
        for sample_dimensions in perspective_dimensions:
            for quadrilateral in quadrilaterals:
                for curvature in curves:
                    try:
                        matrix = projective_sample(
                            pixels, width, height, sample_dimensions, quadrilateral,
                            curvature=float(curvature), threshold=threshold)
                    except (TypeError, ValueError, OverflowError):
                        continue
                    key = tuple(tuple(row) for row in matrix)
                    if key not in seen:
                        seen.add(key)
                        candidates.append(matrix)
                    if len(candidates) >= 256:
                        return candidates
    for polarity in (False, True):
        bitmap = [[not cell for cell in row] for row in base] if polarity else base
        # Full-image sampling supports normal quiet zones; bounding-box sampling supports crops.
        boxes = [(0, 0, width, height)]
        left_black, top_black, right_black, bottom_black = width, height, -1, -1
        for y, row in enumerate(bitmap):
            for x, cell in enumerate(row):
                if cell:
                    left_black, top_black = min(left_black, x), min(top_black, y)
                    right_black, bottom_black = max(right_black, x), max(bottom_black, y)
        if right_black >= 0:
            boxes.append((left_black, top_black, right_black + 1, bottom_black + 1))
        for left, top, right, bottom in boxes:
            boxw, boxh = right - left, bottom - top
            # Generic exact-module sampler for Data Matrix/Aztec/PDF417 and tightly cropped QR.
            # Try only integral scales and retain bounded grids; downstream finder + RS checks are
            # the acceptance boundary, so extra candidates cannot fabricate a payload.
            for scale in range(1, min(32, boxw, boxh) + 1):
                if boxw % scale or boxh % scale:
                    continue
                modules_w, modules_h = boxw // scale, boxh // scale
                if not (1 <= modules_h <= 180 and 1 <= modules_w <= 4 * 180):
                    continue
                matrix = [[bitmap[top + y * scale + scale // 2]
                           [left + x * scale + scale // 2]
                           for x in range(modules_w)] for y in range(modules_h)]
                key = tuple(tuple(row) for row in matrix)
                if key not in seen:
                    seen.add(key)
                    candidates.append(matrix)
                if len(candidates) >= 256:
                    return candidates
            for version in range(1, 41):
                size = 17 + 4 * version
                for border in range(0, 17):
                    total = size + border * 2
                    scale_x, scale_y = boxw / total, boxh / total
                    if scale_x < 1 or abs(scale_x - scale_y) > 0.08 * max(scale_x, scale_y):
                        continue
                    scale = (scale_x + scale_y) / 2
                    if abs(scale - round(scale)) > 0.08:
                        continue
                    matrix = []
                    for y in range(size):
                        py = min(bottom - 1, top + int((border + y + 0.5) * scale_y))
                        matrix.append([bitmap[py][min(right - 1, left + int((border + x + 0.5) * scale_x))]
                                       for x in range(size)])
                    key = tuple(tuple(row) for row in matrix)
                    if key not in seen:
                        seen.add(key)
                        candidates.append(matrix)
                    if len(candidates) >= 256:
                        return candidates
    return candidates


REPAIR_CANDIDATES = 8           # sampled matrices one --repair run forces through, best structure first


def repair_matrices(matrices, *, limit: int | None = None, deadline: float | None = None) -> list[dict]:
    """Repair-decode the square candidates that still look like a QR (:func:`probe` plausible),
    best structure first, at most ``limit`` of them (default ``REPAIR_CANDIDATES``); the first
    that reads ends it. One forced decode of a candidate that does not read costs most of a CPU
    second, so a caller for whom the repair is a last resort passes a smaller ``limit``, or a
    ``deadline`` (``time.monotonic()``) after which no further candidate is probed or forced."""
    limit = REPAIR_CANDIDATES if limit is None else limit
    ranked = []
    for index, matrix in enumerate(matrices):
        if len(matrix) != len(matrix[0]):
            continue
        if deadline is not None and time.monotonic() > deadline:
            break
        report = probe(matrix)
        if report["plausible"]:
            ranked.append((-_structure_rank(report["best"]), index))
    for _rank, index in sorted(ranked)[:max(0, limit)]:
        if deadline is not None and time.monotonic() > deadline:
            break
        found = decode_matrix(matrices[index], repair=True)
        if found:
            return found
    return []


def decode_path(path, *, dimensions=None, corners=None, curvatures=None, repair=False,
                repair_limit: int | None = None, repair_deadline: float | None = None) -> list[dict]:
    """Decode a matrix file (ASCII grid or raster). With ``repair`` a file that gives no payload
    the strict way is read again through :func:`repair_matrices` (masked or damaged finders, a
    destroyed format string), on at most ``repair_limit`` candidates and not past
    ``repair_deadline``."""
    p = Path(path)
    with p.open("rb") as handle:
        raw = handle.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("input exceeds 16 MiB cap")
    matrices = []
    try:
        text = raw.decode("utf-8")
        matrices.append(parse_ascii_rect(text))
    except (UnicodeError, ValueError):
        matrices = raster_matrices(p, dimensions=dimensions, corners=corners,
                                   curvatures=curvatures)
    results = []
    for matrix in matrices:
        qr_results = decode_matrix(matrix) if len(matrix) == len(matrix[0]) else []
        results.extend(qr_results if qr_results else recognize_other(matrix))
        if len(results) >= MAX_RESULTS:
            break
    if repair and not any("bytes" in item for item in results):
        results = repair_matrices(matrices, limit=repair_limit, deadline=repair_deadline) + results
    unique = {}
    for item in results:
        key = (("payload", item["bytes"]) if "bytes" in item else
               ("route", item.get("symbology"), item.get("status"), item.get("score")))
        unique.setdefault(key, item)
    return list(unique.values())


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv=None) -> int:
    parser = _Parser(prog="qr_matrix.py")
    parser.add_argument("input")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--dimensions", metavar="WIDTHxHEIGHT",
                        help="logical modules for perspective/curved raster sampling")
    parser.add_argument("--corners", metavar="TLx,TLy;TRx,TRy;BRx,BRy;BLx,BLy",
                        help="outer symbol corners in raster pixels")
    parser.add_argument("--curve", type=float, action="append", metavar="0..0.95",
                        help="normalized cylindrical warp; repeat to rank several")
    parser.add_argument("--repair", action="store_true",
                        help="when nothing reads: drop the finder gate and force every mask and "
                             "error-correction level (masked or damaged finders, destroyed format)")
    try:
        args = parser.parse_args(argv)
        dimensions = parse_dimensions(args.dimensions) if args.dimensions else None
        corners = parse_corners(args.corners) if args.corners else None
        if corners is not None and dimensions is None:
            raise ValueError("--corners requires --dimensions")
        if args.curve is not None and dimensions is None:
            raise ValueError("--curve requires --dimensions")
        results = decode_path(args.input, dimensions=dimensions, corners=corners,
                              curvatures=args.curve, repair=args.repair)
        rendered = [{**item, **({"bytes": item["bytes"].hex()} if "bytes" in item else {})}
                    for item in results]
        if args.json:
            print(json.dumps({"candidates": rendered}, sort_keys=True))
        else:
            for rank, item in enumerate(results, 1):
                if "bytes" in item:
                    details = (f"v{item['version']}-{item['ecl']} mask={item['mask']}"
                               + (" repaired" if item.get("repaired") else "")
                               if item.get("symbology") == "qr" else
                               f"corrected={item.get('corrected_symbols', 0)}")
                    print(f"{rank}. {item.get('symbology', 'matrix').upper()} {details}: "
                          f"{item.get('text')!r}")
                else:
                    print(f"{rank}. {item.get('symbology', 'matrix')} score={item.get('score')}: "
                          f"{item.get('status', 'unsupported payload')}")
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError,
            RecursionError, MemoryError) as exc:
        print(f"qr_matrix: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
