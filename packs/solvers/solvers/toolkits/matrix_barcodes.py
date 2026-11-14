#!/usr/bin/env python3
"""Dependency-free Data Matrix ECC200/DMRE, Aztec, and PDF417 matrix decoders.

The public functions consume already-sampled binary module matrices.  They do not import a native
barcode library, open files, or execute delivered data.  Every accepted result has passed the
symbology's Reed--Solomon check and high-level compaction parser; malformed/corrupt inputs return an
empty list.  The raster/ASCII sampling and guarded CLI live in :mod:`qr_matrix`.

Implemented standards surface:

* ECC200 Data Matrix (all classic and ISO/IEC 21471 DMRE symbols, ASCII/C40/Text/X12/EDIFACT/
  Base256/ECI);
* compact/full Aztec (1--32 layers, parameter and payload RS, stuffing, table/binary/ECI decode);
* ordinary and Compact PDF417 plus all 34 MicroPDF417 variants (row-address patterns, all three
  clusters, mod-929 RS, text/byte/numeric/ECI/macro compaction).

The code is deliberately bounded for hostile challenge input.  It consumes already sampled module
matrices; perspective and cylindrical sampling live in :mod:`qr_matrix`.
"""
from __future__ import annotations

from dataclasses import dataclass


MAX_SIDE = 180
MAX_CODEWORDS = 4096
MAX_OUTPUT = 1 << 20


# ---- shared helpers ------------------------------------------------------------------------------

def _rect(matrix):
    if not isinstance(matrix, (list, tuple)) or not matrix or len(matrix) > MAX_SIDE:
        raise ValueError("matrix height outside decoder cap")
    width = len(matrix[0]) if isinstance(matrix[0], (list, tuple)) else 0
    if not 1 <= width <= 4 * MAX_SIDE:
        raise ValueError("matrix width outside decoder cap")
    out = []
    for row in matrix:
        if not isinstance(row, (list, tuple)) or len(row) != width:
            raise ValueError("matrix rows must have equal width")
        converted = []
        for value in row:
            if value in (0, False, "0", ".", " "):
                converted.append(False)
            elif value in (1, True, "1", "#", "X", "x", "@", "█"):
                converted.append(True)
            else:
                raise ValueError("matrix cells must be binary")
        out.append(converted)
    return out


def _rotate(m):
    return [list(row) for row in zip(*m[::-1])]


def _transpose(m):
    return [list(row) for row in zip(*m)]


def _transforms(matrix):
    """All rotations/reflections/polarities, including rectangular matrices."""
    try:
        base = _rect(matrix)  # malformed/non-binary/ragged input → decline (yield nothing), not crash
    except ValueError:
        return
    seen = set()
    for inverted in (False, True):
        first = [[not bit for bit in row] for row in base] if inverted else [row[:] for row in base]
        for mirrored in (False, True):
            current = _transpose(first) if mirrored else [row[:] for row in first]
            for rotation in range(4):
                key = tuple(tuple(row) for row in current)
                if key not in seen:
                    seen.add(key)
                    yield current, {"inverted": inverted, "mirrored": mirrored,
                                    "rotation": rotation * 90}
                current = _rotate(current)


class _GF:
    def __init__(self, primitive: int, size: int, base: int = 1):
        if size & (size - 1):
            raise ValueError("binary field size must be a power of two")
        self.size, self.base = size, base
        self.exp = [0] * (size * 2)
        self.log = [0] * size
        value = 1
        for index in range(size - 1):
            self.exp[index] = value
            self.log[value] = index
            value <<= 1
            if value & size:
                value ^= primitive
        for index in range(size - 1, size * 2):
            self.exp[index] = self.exp[index - (size - 1)]

    @staticmethod
    def add(left, right):
        return left ^ right

    def mul(self, left, right):
        return 0 if left == 0 or right == 0 else self.exp[self.log[left] + self.log[right]]

    def div(self, left, right):
        if right == 0:
            raise ZeroDivisionError
        return 0 if left == 0 else self.exp[(self.log[left] - self.log[right]) % (self.size - 1)]

    def pow(self, value, exponent):
        if exponent == 0:
            return 1
        if value == 0:
            return 0
        return self.exp[(self.log[value] * exponent) % (self.size - 1)]


def _poly_eval_high(poly, x, field: _GF):
    value = 0
    for coefficient in poly:
        value = field.mul(value, x) ^ coefficient
    return value


def _bm_binary(syndromes, field: _GF):
    """Berlekamp--Massey; locator coefficients are returned low degree first."""
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


def _eval_low(poly, x, field: _GF):
    value, power = 0, 1
    for coefficient in poly:
        value ^= field.mul(coefficient, power)
        power = field.mul(power, x)
    return value


def _solve_binary(matrix, field: _GF):
    size = len(matrix)
    for column in range(size):
        pivot = next((row for row in range(column, size) if matrix[row][column]), None)
        if pivot is None:
            return None
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inverse = field.div(1, matrix[column][column])
        matrix[column] = [field.mul(value, inverse) for value in matrix[column]]
        for row in range(size):
            if row == column or matrix[row][column] == 0:
                continue
            factor = matrix[row][column]
            matrix[row] = [left ^ field.mul(factor, right)
                           for left, right in zip(matrix[row], matrix[column])]
    return [matrix[row][-1] for row in range(size)]


def rs_binary(words, parity: int, field: _GF):
    """Correct a binary-field RS word stream and prove all post-correction syndromes are zero."""
    if not (isinstance(words, (list, tuple)) and isinstance(parity, int) and
            not isinstance(parity, bool) and 0 < parity < len(words) < field.size and
            all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < field.size for v in words)):
        return None
    message = list(words)
    syndromes = [_poly_eval_high(message, field.exp[field.base + i], field)
                 for i in range(parity)]
    if not any(syndromes):
        return message, 0
    locator, errors = _bm_binary(syndromes, field)
    if errors <= 0 or errors * 2 > parity:
        return None
    positions = []
    length = len(message)
    for position in range(length):
        power = length - 1 - position
        root = field.exp[(-power) % (field.size - 1)]
        if _eval_low(locator, root, field) == 0:
            positions.append(position)
    if len(positions) != errors:
        return None
    system = []
    for row in range(errors):
        exponent = field.base + row
        system.append([field.exp[(exponent * (length - 1 - position)) % (field.size - 1)]
                       for position in positions] + [syndromes[row]])
    magnitudes = _solve_binary(system, field)
    if magnitudes is None:
        return None
    for position, magnitude in zip(positions, magnitudes):
        message[position] ^= magnitude
    check = [_poly_eval_high(message, field.exp[field.base + i], field)
             for i in range(parity)]
    return (message, errors) if not any(check) else None


# ---- Data Matrix ECC200 --------------------------------------------------------------------------

@dataclass(frozen=True)
class _DMSymbol:
    width: int
    height: int
    data: int
    ecc: int
    region_width: int
    region_height: int
    regions: int
    block_data: int
    block_ecc: int


def _dm(width, height, data, ecc, region_width, region_height, regions,
        block_data=None, block_ecc=None):
    return _DMSymbol(width, height, data, ecc, region_width, region_height, regions,
                     block_data or data, block_ecc or ecc)


# ISO/IEC 16022 ECC200 plus ISO/IEC 21471 DMRE symbol attributes.  Dimensions include region
# borders.  DMRE uses the same Utah/corner placement and GF(256) Reed--Solomon construction; its
# additional aspect ratios and region tilings are standards-defined rather than inferred.
_DM_SYMBOLS = {
    (symbol.height, symbol.width): symbol for symbol in (
        _dm(10,10,3,5,8,8,1), _dm(12,12,5,7,10,10,1), _dm(14,14,8,10,12,12,1),
        _dm(16,16,12,12,14,14,1), _dm(18,18,18,14,16,16,1), _dm(20,20,22,18,18,18,1),
        _dm(22,22,30,20,20,20,1), _dm(24,24,36,24,22,22,1), _dm(26,26,44,28,24,24,1),
        _dm(32,32,62,36,14,14,4), _dm(36,36,86,42,16,16,4), _dm(40,40,114,48,18,18,4),
        _dm(44,44,144,56,20,20,4), _dm(48,48,174,68,22,22,4),
        _dm(52,52,204,84,24,24,4,102,42), _dm(64,64,280,112,14,14,16,140,56),
        _dm(72,72,368,144,16,16,16,92,36), _dm(80,80,456,192,18,18,16,114,48),
        _dm(88,88,576,224,20,20,16,144,56), _dm(96,96,696,272,22,22,16,174,68),
        _dm(104,104,816,336,24,24,16,136,56), _dm(120,120,1050,408,18,18,36,175,68),
        _dm(132,132,1304,496,20,20,36,163,62), _dm(144,144,1558,620,22,22,36,156,62),
        _dm(18,8,5,7,16,6,1), _dm(32,8,10,11,14,6,2), _dm(26,12,16,14,24,10,1),
        _dm(36,12,22,18,16,10,2), _dm(36,16,32,24,16,14,2), _dm(48,16,49,28,22,14,2),
        _dm(48,8,18,15,22,6,2), _dm(64,8,24,18,14,6,4),
        _dm(80,8,32,22,18,6,4), _dm(96,8,38,28,22,6,4),
        _dm(120,8,49,32,18,6,6), _dm(144,8,63,36,22,6,6),
        _dm(64,12,43,27,14,10,4), _dm(88,12,64,36,20,10,4),
        _dm(64,16,62,36,14,14,4), _dm(36,20,44,28,16,18,2),
        _dm(44,20,56,34,20,18,2), _dm(64,20,84,42,14,18,4),
        _dm(48,22,72,38,22,20,2), _dm(48,24,80,41,22,22,2),
        _dm(64,24,108,46,14,22,4), _dm(40,26,70,38,18,24,2),
        _dm(48,26,90,42,22,24,2), _dm(64,26,118,50,14,24,4),
    )
}


def _dm_region_shape(symbol):
    """Return horizontal/vertical region counts, including non-square DMRE tilings."""
    cell_width, cell_height = symbol.region_width + 2, symbol.region_height + 2
    if symbol.width % cell_width or symbol.height % cell_height:
        raise ValueError("invalid Data Matrix region geometry")
    horizontal, vertical = symbol.width // cell_width, symbol.height // cell_height
    if horizontal * vertical != symbol.regions:
        raise ValueError("invalid Data Matrix region count")
    return horizontal, vertical


def _dm_finder_score(matrix, symbol):
    horizontal, vertical = _dm_region_shape(symbol)
    good = total = 0
    for ry in range(vertical):
        top = ry * (symbol.region_height + 2)
        bottom = top + symbol.region_height + 1
        for rx in range(horizontal):
            left = rx * (symbol.region_width + 2)
            right = left + symbol.region_width + 1
            for x in range(left, right + 1):
                good += matrix[bottom][x]
                # Accommodate the standard's alternating phase at shared corner modules.
                good += matrix[top][x] == ((x - left) % 2 == 0)
                total += 2
            for y in range(top, bottom + 1):
                good += matrix[y][left]
                expected_a = (y - top) % 2 == 1
                expected_b = not expected_a
                good += matrix[y][right] in (expected_a, expected_b) and (
                    matrix[y][right] == expected_a or y in (top, bottom))
                total += 2
    return good * 100 // max(1, total)


def _dm_data_region(matrix, symbol):
    horizontal, vertical = _dm_region_shape(symbol)
    out = []
    for ry in range(vertical):
        for y in range(1, symbol.region_height + 1):
            row = []
            source_y = ry * (symbol.region_height + 2) + y
            for rx in range(horizontal):
                start = rx * (symbol.region_width + 2) + 1
                row.extend(matrix[source_y][start:start + symbol.region_width])
            out.append(row)
    return out


def _dm_placement(rows, columns):
    assigned = {}

    def module(row, column, position, bit):
        if row < 0:
            row += rows
            column += 4 - ((rows + 4) % 8)
        if column < 0:
            column += columns
            row += 4 - ((columns + 4) % 8)
        # DMRE 26x40 and 26x48 exercise the positive wrap produced by the second adjustment.
        # Older ECC200 pseudocode often omits this final modulo because classic dimensions never
        # need it; ISO/IEC 21471 placement applies the coordinates toroidally.
        row %= rows
        column %= columns
        assigned[(row, column)] = (position, bit)

    def utah(row, column, position):
        for dr, dc, bit in ((-2,-2,1),(-2,-1,2),(-1,-2,3),(-1,-1,4),
                            (-1,0,5),(0,-2,6),(0,-1,7),(0,0,8)):
            module(row + dr, column + dc, position, bit)

    def corner1(position):
        for row, column, bit in ((rows-1,0,1),(rows-1,1,2),(rows-1,2,3),(0,columns-2,4),
                                 (0,columns-1,5),(1,columns-1,6),(2,columns-1,7),(3,columns-1,8)):
            module(row, column, position, bit)

    def corner2(position):
        for row, column, bit in ((rows-3,0,1),(rows-2,0,2),(rows-1,0,3),(0,columns-4,4),
                                 (0,columns-3,5),(0,columns-2,6),(0,columns-1,7),(1,columns-1,8)):
            module(row, column, position, bit)

    def corner3(position):
        for row, column, bit in ((rows-3,0,1),(rows-2,0,2),(rows-1,0,3),(0,columns-2,4),
                                 (0,columns-1,5),(1,columns-1,6),(2,columns-1,7),(3,columns-1,8)):
            module(row, column, position, bit)

    def corner4(position):
        for row, column, bit in ((rows-1,0,1),(rows-1,columns-1,2),(0,columns-3,3),
                                 (0,columns-2,4),(0,columns-1,5),(1,columns-3,6),
                                 (1,columns-2,7),(1,columns-1,8)):
            module(row, column, position, bit)

    row, column, position = 4, 0, 0
    while row < rows or column < columns:
        if row == rows and column == 0:
            corner1(position); position += 1
        if row == rows - 2 and column == 0 and columns % 4:
            corner2(position); position += 1
        if row == rows - 2 and column == 0 and columns % 8 == 4:
            corner3(position); position += 1
        if row == rows + 4 and column == 2 and columns % 8 == 0:
            corner4(position); position += 1
        while row >= 0 and column < columns:
            if row < rows and column >= 0 and (row, column) not in assigned:
                utah(row, column, position); position += 1
            row -= 2; column += 2
        row += 1; column += 3
        while row < rows and column >= 0:
            if row >= 0 and column < columns and (row, column) not in assigned:
                utah(row, column, position); position += 1
            row += 2; column -= 2
        row += 3; column += 1
    return assigned


def _dm_extract(matrix, symbol):
    data_region = _dm_data_region(matrix, symbol)
    rows, columns = len(data_region), len(data_region[0])
    placement = _dm_placement(rows, columns)
    total = symbol.data + symbol.ecc
    words = [0] * total
    seen = [0] * total
    for (row, column), (position, bit) in placement.items():
        if position < total:
            words[position] |= int(data_region[row][column]) << (8 - bit)
            seen[position] |= 1 << (8 - bit)
    return words if all(value == 0xFF for value in seen) else None


_DM_FIELD = _GF(0x12D, 256, 1)


def _dm_deinterleave(words, symbol):
    if len(words) != symbol.data + symbol.ecc:
        return None
    if symbol.width == 144 and symbol.height == 144:
        data_lengths = [156] * 8 + [155] * 2
    else:
        if symbol.data % symbol.block_data:
            return None
        data_lengths = [symbol.block_data] * (symbol.data // symbol.block_data)
    blocks = [([0] * (length + symbol.block_ecc)) for length in data_lengths]
    cursor = 0
    for column in range(max(data_lengths)):
        for block, length in enumerate(data_lengths):
            if column < length:
                blocks[block][column] = words[cursor]; cursor += 1
    for column in range(symbol.block_ecc):
        for ordinal in range(len(blocks)):
            # Parity remains in block ordinal order; the two short 144x144 blocks merely start
            # their parity one array slot earlier because they lack data column 155.
            block = ordinal
            at = data_lengths[block] + column
            blocks[block][at] = words[cursor]; cursor += 1
    if cursor != len(words):
        return None
    fixed, corrected = [], 0
    for block, length in zip(blocks, data_lengths):
        result = rs_binary(block, symbol.block_ecc, _DM_FIELD)
        if result is None:
            return None
        fixed.append(result[0][:length]); corrected += result[1]
    # Data Matrix consumes corrected data in original interleaved order.
    data = []
    for column in range(max(data_lengths)):
        for block, length in zip(fixed, data_lengths):
            if column < length:
                data.append(block[column])
    return data, corrected


_C40_BASIC = ["*"] * 40
_C40_BASIC[:4] = ["<S1>", "<S2>", "<S3>", " "]
_C40_BASIC[4:14] = list("0123456789")
_C40_BASIC[14:40] = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_TEXT_BASIC = _C40_BASIC[:14] + list("abcdefghijklmnopqrstuvwxyz")
_SHIFT2 = list("!\"#$%&'()*+,-./:;<=>?@[\\]^_")
_C40_SHIFT3 = list("`abcdefghijklmnopqrstuvwxyz{|}~\x7f")
_TEXT_SHIFT3 = ["`"] + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ") + ["{", "|", "}", "~", "\x7f"]


def _dm_triplet(words, at, mode, output, segments):
    start = len(output)
    shift, upper = 0, False
    basic = _TEXT_BASIC if mode == "text" else _C40_BASIC
    shift3 = _TEXT_SHIFT3 if mode == "text" else _C40_SHIFT3
    while at < len(words):
        if words[at] == 254:
            at += 1
            break
        if at + 1 >= len(words):
            return None
        value = (words[at] << 8) + words[at + 1] - 1
        values = (value // 1600, (value // 40) % 40, value % 40)
        at += 2
        for item in values:
            if shift == 0:
                token = basic[item]
                if token == "<S1>": shift = 1; continue
                if token == "<S2>": shift = 2; continue
                if token == "<S3>": shift = 3; continue
                char = token
            elif shift == 1:
                char = chr(item); shift = 0
            elif shift == 2:
                if item < len(_SHIFT2):
                    char = _SHIFT2[item]
                elif item == 27:
                    char = "\x1d"
                elif item == 30:
                    upper = True; shift = 0; continue
                else:
                    return None
                shift = 0
            else:
                if item >= len(shift3):
                    return None
                char = shift3[item]; shift = 0
            code = ord(char)
            if upper:
                code += 128; upper = False
            output.append(code & 0xFF)
            if len(output) > MAX_OUTPUT:
                return None
    segments.append({"mode": mode, "offset": start, "length": len(output) - start})
    return at


def _dm_x12(words, at, output, segments):
    start = len(output)
    while at < len(words):
        if words[at] == 254:
            at += 1; break
        if at + 1 >= len(words):
            return None
        value = (words[at] << 8) + words[at + 1] - 1
        at += 2
        for item in (value // 1600, (value // 40) % 40, value % 40):
            if item == 0: char = "\r"
            elif item == 1: char = "*"
            elif item == 2: char = ">"
            elif item == 3: char = " "
            elif 4 <= item <= 13: char = chr(ord("0") + item - 4)
            elif 14 <= item <= 39: char = chr(ord("A") + item - 14)
            else: return None
            output.append(ord(char))
    segments.append({"mode": "x12", "offset": start, "length": len(output) - start})
    return at


def _dm_edifact(words, at, output, segments):
    start = len(output)
    while at < len(words):
        # ECC200 implicit EDIFACT unlatch: when <= 2 data codewords remain, EDIFACT ends and those
        # words resume ordinary ASCII compaction. Checked at the TOP of the loop (before reading a
        # triplet) so a spec-valid short tail decodes instead of being declined as a missed solve.
        if len(words) - at <= 2:
            break
        value = (words[at] << 16) | (words[at + 1] << 8) | words[at + 2]
        at += 3
        for shift in (18, 12, 6, 0):
            item = (value >> shift) & 0x3F
            if item == 31:  # explicit unlatch
                segments.append({"mode": "edifact", "offset": start,
                                 "length": len(output) - start})
                return at
            output.append(item | (0x40 if item & 0x20 == 0 else 0))
    segments.append({"mode": "edifact", "offset": start, "length": len(output) - start})
    return at


def _dm_unrandom(word, position):
    value = word - (((149 * position) % 255) + 1)
    return value + 256 if value < 0 else value


def _dm_payload(words):
    output, segments, at, upper, encoding = bytearray(), [], 0, False, "iso-8859-1"
    macro = None
    try:
        while at < len(words):
            word = words[at]; at += 1
            if word == 129:
                break
            if 1 <= word <= 128:
                value = word - 1 + (128 if upper else 0); upper = False
                output.append(value & 0xFF)
            elif 130 <= word <= 229:
                output.extend(f"{word - 130:02d}".encode())
            elif word in (230, 239):
                at = _dm_triplet(words, at, "c40" if word == 230 else "text", output, segments)
                if at is None: return None
            elif word == 231:
                if at >= len(words): return None
                length = _dm_unrandom(words[at], at + 1); at += 1
                if length == 0:
                    length = len(words) - at
                elif length >= 250:
                    if at >= len(words): return None
                    length = 250 * (length - 249) + _dm_unrandom(words[at], at + 1); at += 1
                if length < 0 or at + length > len(words) or length > MAX_OUTPUT:
                    return None
                start = len(output)
                for _ in range(length):
                    output.append(_dm_unrandom(words[at], at + 1)); at += 1
                segments.append({"mode": "base256", "offset": start, "length": length})
            elif word == 232:
                output.append(0x1D); segments.append({"mode": "fnc1"})
            elif word == 233:
                if at + 2 > len(words): return None
                segments.append({"mode": "structured-append", "file_id": words[at],
                                 "position": words[at + 1]}); at += 2
            elif word == 234:
                segments.append({"mode": "reader-programming"})
            elif word == 235:
                upper = True
            elif word in (236, 237):
                macro = "05" if word == 236 else "06"
                output.extend(b"[)>\x1e" + macro.encode() + b"\x1d")
            elif word == 238:
                at = _dm_x12(words, at, output, segments)
                if at is None: return None
            elif word == 240:
                at = _dm_edifact(words, at, output, segments)
                if at is None: return None
            elif word == 241:
                if at >= len(words): return None
                first = words[at]; at += 1
                if 1 <= first <= 127:
                    assignment = first - 1
                elif 128 <= first <= 191 and at < len(words) and 1 <= words[at] <= 254:
                    assignment = (first - 128) * 254 + (words[at] - 1) + 127; at += 1
                elif (192 <= first <= 207 and at + 1 < len(words) and
                      1 <= words[at] <= 254 and 1 <= words[at + 1] <= 254):
                    assignment = (first - 192) * 64516 + (words[at] - 1) * 254 + (words[at + 1] - 1) + 16383
                    at += 2
                else: return None
                if assignment > 999999: return None
                encoding = {3: "iso-8859-1", 20: "shift_jis", 26: "utf-8"}.get(assignment, encoding)
                segments.append({"mode": "eci", "assignment": assignment})
            elif word in (254,):
                continue
            else:
                return None
            if len(output) > MAX_OUTPUT:
                return None
        if macro:
            output.extend(b"\x1e\x04")
        raw = bytes(output)
        try: text = raw.decode(encoding)
        except (LookupError, UnicodeError): text = None
        return {"bytes": raw, "text": text, "encoding": encoding, "segments": segments}
    except (IndexError, OverflowError, ValueError):
        return None


def decode_datamatrix(matrix):
    results, seen = [], set()
    for candidate, transform in _transforms(matrix):
        symbol = _DM_SYMBOLS.get((len(candidate), len(candidate[0])))
        if symbol is None:
            continue
        finder = _dm_finder_score(candidate, symbol)
        if finder < 85:
            continue
        words = _dm_extract(candidate, symbol)
        if words is None:
            continue
        fixed = _dm_deinterleave(words, symbol)
        if fixed is None:
            continue
        payload = _dm_payload(fixed[0])
        if payload is None or payload["bytes"] in seen:
            continue
        seen.add(payload["bytes"])
        results.append({"symbology": "datamatrix", "version": f"{symbol.width}x{symbol.height}",
                        "finder_score": finder, "corrected_symbols": fixed[1],
                        "transform": transform, **payload})
    return sorted(results, key=lambda item: (item["corrected_symbols"], -item["finder_score"]))


# ---- Aztec ---------------------------------------------------------------------------------------

_AZTEC_FIELDS = {
    6: _GF(0x43, 64, 1), 8: _DM_FIELD, 10: _GF(0x409, 1024, 1),
    12: _GF(0x1069, 4096, 1), 4: _GF(0x13, 16, 1),
}


def _aztec_mode_bits(matrix, compact):
    center = len(matrix) // 2
    bits = [0] * (28 if compact else 40)
    if compact:
        for index in range(7):
            offset = center - 3 + index
            bits[index] = int(matrix[center - 5][offset])
            bits[index + 7] = int(matrix[offset][center + 5])
            bits[20 - index] = int(matrix[center + 5][offset])
            bits[27 - index] = int(matrix[offset][center - 5])
    else:
        for index in range(10):
            offset = center - 5 + index + index // 5
            bits[index] = int(matrix[center - 7][offset])
            bits[index + 10] = int(matrix[offset][center + 7])
            bits[29 - index] = int(matrix[center + 7][offset])
            bits[39 - index] = int(matrix[offset][center - 7])
    return bits


def _aztec_parameters(matrix, compact):
    bits = _aztec_mode_bits(matrix, compact)
    words = [sum(bits[index * 4 + bit] << (3 - bit) for bit in range(4))
             for index in range(len(bits) // 4)]
    data_words = 2 if compact else 4
    fixed = rs_binary(words, len(words) - data_words, _AZTEC_FIELDS[4])
    if fixed is None:
        return None
    value = 0
    for word in fixed[0][:data_words]:
        value = (value << 4) | word
    if compact:
        layers, data = (value >> 6) + 1, (value & 0x3F) + 1
    else:
        layers, data = (value >> 11) + 1, (value & 0x7FF) + 1
    if not (1 <= layers <= (4 if compact else 32) and 1 <= data <= MAX_CODEWORDS):
        return None
    return layers, data, fixed[1]


def _aztec_expected_size(layers, compact):
    base = (11 if compact else 14) + layers * 4
    return base if compact else base + 1 + 2 * ((base // 2 - 1) // 15)


def _aztec_extract(matrix, layers, compact):
    base = (11 if compact else 14) + layers * 4
    if compact:
        alignment = list(range(base))
    else:
        alignment = [0] * base
        original_center, center = base // 2, len(matrix) // 2
        for index in range(original_center):
            offset = index + index // 15
            alignment[original_center - index - 1] = center - offset - 1
            alignment[original_center + index] = center + offset + 1
    bits = []
    for layer in range(layers):
        row_size = (layers - layer) * 4 + (9 if compact else 12)
        low, high = layer * 2, base - 1 - layer * 2
        for index in range(row_size):
            for offset in range(2):
                bits.append(int(matrix[alignment[low + index]][alignment[low + offset]]))
        for index in range(row_size):
            for offset in range(2):
                bits.append(int(matrix[alignment[high - offset]][alignment[low + index]]))
        for index in range(row_size):
            for offset in range(2):
                bits.append(int(matrix[alignment[high - index]][alignment[high - offset]]))
        for index in range(row_size):
            for offset in range(2):
                bits.append(int(matrix[alignment[low + offset]][alignment[high - index]]))
    return bits


def _aztec_correct(bits, layers, data_words):
    size = 6 if layers <= 2 else 8 if layers <= 8 else 10 if layers <= 22 else 12
    total_words = len(bits) // size
    if not (data_words <= total_words < _AZTEC_FIELDS[size].size):
        return None
    offset = len(bits) % size
    words = [sum(bits[offset + index * size + bit] << (size - 1 - bit) for bit in range(size))
             for index in range(total_words)]
    fixed = rs_binary(words, total_words - data_words, _AZTEC_FIELDS[size])
    if fixed is None:
        return None
    mask = (1 << size) - 1
    unstuffed = []
    for word in fixed[0][:data_words]:
        if word in (0, mask):
            return None
        if word in (1, mask - 1):
            unstuffed.extend([word > 1] * (size - 1))
        else:
            unstuffed.extend(bool(word & (1 << bit)) for bit in range(size - 1, -1, -1))
    return unstuffed, fixed[1], size


_AZTEC_TABLES = {
    "UPPER": ["CTRL_PS", " "] + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ") +
             ["CTRL_LL", "CTRL_ML", "CTRL_DL", "CTRL_BS"],
    "LOWER": ["CTRL_PS", " "] + list("abcdefghijklmnopqrstuvwxyz") +
             ["CTRL_US", "CTRL_ML", "CTRL_DL", "CTRL_BS"],
    "MIXED": ["CTRL_PS", " ", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",
              "\b", "\t", "\n", "\x0b", "\f", "\r", "\x1b", "\x1c", "\x1d", "\x1e",
              "\x1f", "@", "\\", "^", "_", "`", "|", "~", "\x7f", "CTRL_LL", "CTRL_UL",
              "CTRL_PL", "CTRL_BS"],
    "PUNCT": ["FLG(n)", "\r", "\r\n", ". ", ", ", ": ", "!", "\"", "#", "$", "%", "&",
              "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?",
              "[", "]", "{", "}", "CTRL_UL"],
    "DIGIT": ["CTRL_PS", " "] + list("0123456789") + [",", ".", "CTRL_UL", "CTRL_US"],
}
_AZTEC_TARGET = {"U": "UPPER", "L": "LOWER", "M": "MIXED", "P": "PUNCT", "D": "DIGIT"}


class _BoolBits:
    def __init__(self, bits):
        self.bits, self.at = bits, 0

    def take(self, count):
        if count < 0 or self.at + count > len(self.bits):
            raise ValueError("truncated Aztec payload")
        value = 0
        for _ in range(count):
            value = (value << 1) | int(self.bits[self.at]); self.at += 1
        return value

    def left(self):
        return len(self.bits) - self.at


def _aztec_payload(bits):
    reader = _BoolBits(bits)
    output, segments = bytearray(), []
    latch, table, encoding = "UPPER", "UPPER", "iso-8859-1"
    try:
        while reader.left() >= (4 if table == "DIGIT" else 5):
            if table == "BINARY":
                length = reader.take(5)
                if length == 0:
                    length = reader.take(11) + 31
                if length > reader.left() // 8 or len(output) + length > MAX_OUTPUT:
                    return None
                start = len(output)
                output.extend(reader.take(8) for _ in range(length))
                segments.append({"mode": "binary", "offset": start, "length": length})
                table = latch
                continue
            width = 4 if table == "DIGIT" else 5
            token = _AZTEC_TABLES[table][reader.take(width)]
            if token == "FLG(n)":
                if reader.left() < 3: return None
                count = reader.take(3)
                if count == 0:
                    output.append(0x1D); segments.append({"mode": "fnc1"})
                elif count == 7 or reader.left() < count * 4:
                    return None
                else:
                    assignment = 0
                    for _ in range(count):
                        digit = reader.take(4)
                        if not 2 <= digit <= 11: return None
                        assignment = assignment * 10 + digit - 2
                    encoding = {3: "iso-8859-1", 20: "shift_jis", 26: "utf-8"}.get(
                        assignment, encoding)
                    segments.append({"mode": "eci", "assignment": assignment})
                table = latch
            elif token.startswith("CTRL_"):
                target, action = token[5], token[6]
                table = "BINARY" if target == "B" else _AZTEC_TARGET[target]
                if action == "L":
                    latch = table
            else:
                output.extend(token.encode("latin-1"))
                if len(output) > MAX_OUTPUT: return None
                table = latch
        raw = bytes(output)
        try: text = raw.decode(encoding)
        except (LookupError, UnicodeError): text = None
        return {"bytes": raw, "text": text, "encoding": encoding, "segments": segments}
    except (IndexError, KeyError, ValueError, OverflowError):
        return None


def _aztec_bullseye_score(matrix, compact):
    center, rings = len(matrix) // 2, 5 if compact else 7
    good = total = 0
    for radius in range(rings):
        expected = radius % 2 == 0
        for offset in range(-radius, radius + 1):
            for x, y in ((center + offset, center - radius), (center + radius, center + offset),
                         (center + offset, center + radius), (center - radius, center + offset)):
                good += matrix[y][x] == expected; total += 1
    return good * 100 // max(1, total)


def decode_aztec(matrix):
    results, seen = [], set()
    for candidate, transform in _transforms(matrix):
        if len(candidate) != len(candidate[0]) or len(candidate) < 15:
            continue
        for compact in (True, False):
            if _aztec_bullseye_score(candidate, compact) < 80:
                continue
            params = _aztec_parameters(candidate, compact)
            if params is None or _aztec_expected_size(params[0], compact) != len(candidate):
                continue
            raw = _aztec_extract(candidate, params[0], compact)
            fixed = _aztec_correct(raw, params[0], params[1])
            if fixed is None:
                continue
            payload = _aztec_payload(fixed[0])
            if payload is None or payload["bytes"] in seen:
                continue
            seen.add(payload["bytes"])
            results.append({"symbology": "aztec", "compact": compact, "layers": params[0],
                            "data_codewords": params[1], "word_size": fixed[2],
                            "parameter_corrections": params[2], "corrected_symbols": fixed[1],
                            "transform": transform, **payload})
    return sorted(results, key=lambda item: (item["parameter_corrections"] + item["corrected_symbols"],
                                             item["layers"]))


# PDF417 is below; its factual pattern dictionary is kept in a small sibling module so this file's
# algorithms remain reviewable.
try:
    from pdf417_patterns import PDF417_PATTERNS
except ImportError:  # package-style import in tests/tools
    try:
        from .pdf417_patterns import PDF417_PATTERNS
    except ImportError:  # pragma: no cover - guarded explicit decline
        PDF417_PATTERNS = {}


_PDF_START = int("11111111010101000", 2)
_PDF_STOP = int("111111101000101001", 2)


def _bits_int(row, start, length):
    return sum(int(row[start + index]) << (length - 1 - index) for index in range(length))


def _pdf_pattern(pattern):
    exact = PDF417_PATTERNS.get(pattern & 0xFFFF)
    if exact is not None:
        return exact + (0,)
    # A module sampler may flip a small number of modules.  Commit only a unique nearest codeword.
    ranked = []
    for known, (value, cluster) in PDF417_PATTERNS.items():
        distance = ((known ^ (pattern & 0xFFFF))).bit_count()
        if distance <= 2:
            ranked.append((distance, value, cluster))
    ranked.sort()
    if ranked and (len(ranked) == 1 or ranked[0][0] < ranked[1][0]):
        return ranked[0][1], ranked[0][2], ranked[0][0]
    return None


def _pdf_rows(matrix):
    """Decode ordinary/Compact PDF417 rows and collapse repeated raster-height rows.

    Compact PDF417 retains the start pattern and left row indicator, omits the right indicator and
    18-module stop pattern, and terminates each row with one dark module.  Keeping both framings in
    one parser makes their cluster/codeword correction path identical.
    """
    unique = []
    for row in matrix:
        if not unique or row != unique[-1]:
            unique.append(row)
    decoded = []
    for ordinal, row in enumerate(unique):
        if len(row) < 17 + 17 + 17 + 1 or _bits_int(row, 0, 17) != _PDF_START:
            return None
        ordinary = len(row) >= 17 + 17 * 3 + 18 and \
            _bits_int(row, len(row) - 18, 18) == _PDF_STOP and (len(row) - 35) % 17 == 0
        compact = bool(row[-1]) and (len(row) - 18) % 17 == 0
        if ordinary:
            body, compact = len(row) - 35, False
        elif compact:
            body = len(row) - 18
        else:
            return None
        minimum = 2 if compact else 3  # left + >=1 data [+ right]
        if body % 17 or body // 17 < minimum:
            return None
        patterns = [_pdf_pattern(_bits_int(row, 17 + index * 17, 17))
                    for index in range(body // 17)]
        if any(value is None for value in patterns):
            return None
        clusters = {value[1] for value in patterns}
        if len(clusters) != 1:
            return None
        decoded.append({"ordinal": ordinal, "cluster": clusters.pop(),
                        "compact": compact, "left": patterns[0][0],
                        "right": None if compact else patterns[-1][0],
                        "data": [value[0] for value in
                                 (patterns[1:] if compact else patterns[1:-1])],
                        "pattern_corrections": sum(value[2] for value in patterns)})
    if len({row["compact"] for row in decoded}) != 1:
        return None
    return decoded


def _pdf_metadata(rows):
    candidates = []
    compact = rows[0].get("compact", False)
    for row in rows:
        cluster = row["cluster"]
        if cluster not in (0, 1, 2):
            return None
        row_group = row["ordinal"] // 3
        if row["ordinal"] % 3 != cluster:
            return None
        left = row["left"] - 30 * row_group
        right = None if compact else row["right"] - 30 * row_group
        if cluster == 0:
            candidates.append(("row_div", left))
            if right is not None: candidates.append(("columns", right + 1))
        elif cluster == 1:
            candidates.append(("ec_rem", left))
            if right is not None: candidates.append(("row_div", right))
        else:
            candidates.append(("columns", left + 1))
            if right is not None: candidates.append(("ec_rem", right))
    values = {}
    for name in ("row_div", "columns", "ec_rem"):
        found = [value for key, value in candidates if key == name]
        if found and len(set(found)) != 1:
            return None
        if found:
            values[name] = found[0]
    columns = values.get("columns", len(rows[0]["data"]))
    if columns != len(rows[0]["data"]) or any(len(row["data"]) != columns for row in rows):
        return None
    row_count = len(rows)
    if "row_div" in values and "ec_rem" in values:
        expected = values["row_div"] * 3 + (values["ec_rem"] % 3) + 1
        if expected != row_count:
            return None
        ec_level = values["ec_rem"] // 3
    else:
        ec_level = None
    if not (1 <= columns <= 30 and 3 <= row_count <= 90 and
            (ec_level is None or 0 <= ec_level <= 8)):
        return None
    return row_count, columns, ec_level


def _mod_inverse(value, modulus=929):
    if value % modulus == 0:
        raise ZeroDivisionError
    return pow(value, modulus - 2, modulus)


def _pdf_syndromes(words, count):
    return [sum(value * pow(3, (index + 1) * (len(words) - 1 - position), 929)
                for position, value in enumerate(words)) % 929 for index in range(count)]


def _bm_prime(syndromes):
    nmax = len(syndromes)
    current, previous = [1] + [0] * nmax, [1] + [0] * nmax
    degree, shift, scale = 0, 1, 1
    for n in range(nmax):
        discrepancy = (syndromes[n] + sum(current[i] * syndromes[n - i]
                                           for i in range(1, degree + 1))) % 929
        if discrepancy == 0:
            shift += 1; continue
        saved = current[:]
        factor = discrepancy * _mod_inverse(scale) % 929
        for index in range(nmax + 1 - shift):
            current[index + shift] = (current[index + shift] - factor * previous[index]) % 929
        if 2 * degree <= n:
            degree, previous, scale, shift = n + 1 - degree, saved, discrepancy, 1
        else:
            shift += 1
    return current[:degree + 1], degree


def _solve_prime(matrix):
    size = len(matrix)
    for column in range(size):
        pivot = next((row for row in range(column, size) if matrix[row][column] % 929), None)
        if pivot is None: return None
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inverse = _mod_inverse(matrix[column][column])
        matrix[column] = [value * inverse % 929 for value in matrix[column]]
        for row in range(size):
            if row == column: continue
            factor = matrix[row][column]
            matrix[row] = [(left - factor * right) % 929
                           for left, right in zip(matrix[row], matrix[column])]
    return [row[-1] for row in matrix]


def rs_pdf417(words, parity):
    if not (isinstance(words, (list, tuple)) and isinstance(parity, int) and
            not isinstance(parity, bool) and 0 < parity < len(words) <= 2700 and
            all(isinstance(v, int) and 0 <= v < 929 for v in words)):
        return None
    message = list(words)
    syndromes = _pdf_syndromes(message, parity)
    if not any(syndromes): return message, 0
    locator, errors = _bm_prime(syndromes)
    if errors <= 0 or errors * 2 > parity: return None
    positions = []
    for position in range(len(message)):
        power = len(message) - 1 - position
        root = pow(pow(3, power, 929), 927, 929)
        value, factor = 0, 1
        for coefficient in locator:
            value = (value + coefficient * factor) % 929; factor = factor * root % 929
        if value == 0: positions.append(position)
    if len(positions) != errors: return None
    system = []
    for row in range(errors):
        system.append([pow(3, (row + 1) * (len(message) - 1 - position), 929)
                       for position in positions] + [syndromes[row]])
    magnitudes = _solve_prime(system)
    if magnitudes is None: return None
    for position, magnitude in zip(positions, magnitudes):
        message[position] = (message[position] - magnitude) % 929
    return (message, errors) if not any(_pdf_syndromes(message, parity)) else None


_PDF_MIXED = "0123456789&\r\t,:#-.$/+%*=^"
_PDF_PUNCT = ";<>@[\\]_`~!\r\t,:\n-.$/\"|*()?{}'"


def _pdf_text(codewords, output):
    sub = []
    for word in codewords:
        if word < 900: sub.extend((word // 30, word % 30))
        elif word == 913: sub.append(913)
        else: break
    mode, prior, at = "A", "A", 0
    while at < len(sub):
        value = sub[at]; at += 1
        char = None
        if value == 913:
            return False
        if mode == "A":
            if value < 26: char = chr(65 + value)
            elif value == 26: char = " "
            elif value == 27: mode = "L"
            elif value == 28: mode = "M"
            else: prior, mode = mode, "PS"
        elif mode == "L":
            if value < 26: char = chr(97 + value)
            elif value == 26: char = " "
            elif value == 27: prior, mode = mode, "AS"
            elif value == 28: mode = "M"
            else: prior, mode = mode, "PS"
        elif mode == "M":
            if value < 25: char = _PDF_MIXED[value]
            elif value == 25: mode = "P"
            elif value == 26: char = " "
            elif value == 27: mode = "L"
            elif value == 28: mode = "A"
            else: prior, mode = mode, "PS"
        elif mode == "P":
            if value < 29: char = _PDF_PUNCT[value]
            else: mode = "A"
        elif mode == "AS":
            if value < 26: char = chr(65 + value)
            elif value == 26: char = " "
            mode = prior
        else:
            if value < 29: char = _PDF_PUNCT[value]
            mode = prior
        if char is not None: output.extend(char.encode("latin-1"))
    return True


def _pdf_payload(words):
    if not words or not 1 <= words[0] <= len(words): return None
    end, at, output, segments, encoding = words[0], 1, bytearray(), [], "iso-8859-1"
    try:
        while at < end:
            mode = words[at]
            if mode < 900:
                mode = 900
            else:
                at += 1
            if mode == 900:
                start_at, start = at, len(output)
                chunk = []
                while at < end and words[at] < 900:
                    chunk.append(words[at]); at += 1
                if not _pdf_text(chunk, output): return None
                segments.append({"mode": "text", "codewords": at - start_at,
                                 "offset": start, "length": len(output) - start})
            elif mode in (901, 924):
                start = len(output); values = []
                while at < end and words[at] < 900:
                    values.append(words[at]); at += 1
                # Mode 901 leaves its final one to five codewords as literal bytes.
                groups = len(values) // 5 if mode == 924 else max(0, (len(values) - 1) // 5)
                consumed = 0
                while consumed < groups * 5:
                    value = 0
                    for word in values[consumed:consumed + 5]: value = value * 900 + word
                    output.extend(value.to_bytes(6, "big")); consumed += 5
                if mode == 901:
                    for word in values[consumed:]:
                        if word > 255: return None
                        output.append(word)
                elif consumed != len(values): return None
                segments.append({"mode": "byte", "offset": start, "length": len(output)-start})
            elif mode == 902:
                start = len(output)
                while at < end and words[at] < 900:
                    take = []
                    while at < end and words[at] < 900 and len(take) < 15:
                        take.append(words[at]); at += 1
                    value = 0
                    for word in take: value = value * 900 + word
                    digits = str(value)
                    if not digits.startswith("1"): return None
                    output.extend(digits[1:].encode())
                segments.append({"mode": "numeric", "offset": start, "length": len(output)-start})
            elif mode == 913:
                if at >= end or words[at] > 255: return None
                output.append(words[at]); at += 1
            elif mode == 927:
                if at >= end: return None
                assignment = words[at]; at += 1
                encoding = {3:"iso-8859-1",20:"shift_jis",26:"utf-8"}.get(assignment, encoding)
                segments.append({"mode":"eci", "assignment":assignment})
            elif mode == 926:
                if at + 1 >= end: return None
                assignment = (words[at] + 1) * 900 + words[at + 1]; at += 2
                segments.append({"mode":"eci-general", "assignment":assignment})
            elif mode == 925:
                if at >= end: return None
                segments.append({"mode":"eci-user", "assignment":words[at]}); at += 1
            elif mode == 928:
                # Macro PDF417 metadata is retained as codewords; file data still decodes normally.
                if at + 1 >= end: return None
                segment_index = words[at] * 900 + words[at + 1]; at += 2
                segments.append({"mode":"macro", "segment_index":segment_index})
                while at < end and words[at] not in (922, 923) and words[at] < 900:
                    at += 1
                if at < end and words[at] == 922:
                    segments[-1]["last"] = True; at += 1
                elif at < end and words[at] == 923:
                    at += 1
            elif mode in (922, 923):
                return None
            else:
                return None
            if len(output) > MAX_OUTPUT: return None
        raw = bytes(output)
        try: text = raw.decode(encoding)
        except (LookupError, UnicodeError): text = None
        return {"bytes": raw, "text": text, "encoding": encoding, "segments": segments}
    except (IndexError, OverflowError, ValueError):
        return None


# ISO/IEC 24728 MicroPDF417 row-address patterns.  The left and right sets share the same 52-value
# sequence (right patterns are offset by 12 and carry a final dark module); the center set is
# independent.  Values are module patterns, not decoded payload candidates.
_MICRO_SIDE_RAPS = tuple(int(bits, 2) for bits in (
    "1100100010", "1110100010", "1110110010", "1100110010", "1101110010",
    "1101111010", "1100111010", "1110111010", "1110011010", "1111011010",
    "1111001010", "1110001010", "1100001010", "1100011010", "1100010010",
    "1110010010", "1111010010", "1111010110", "1111010100", "1110010100",
    "1110110100", "1110100100", "1110100110", "1110101110", "1110101100",
    "1110101000", "1100101000", "1100101100", "1100101110", "1100100110",
    "1100110110", "1110110110", "1110010110", "1100010110", "1100010100",
    "1100110100", "1101110100", "1101100100", "1101100110", "1101101110",
    "1101101100", "1101101000", "1101001000", "1101011000", "1101011100",
    "1101011110", "1101001110", "1101001100", "1101000100", "1101000110",
    "1101000010", "1101100010",
))
_MICRO_CENTER_RAPS = tuple(int(bits, 2) for bits in (
    "1000010010", "1000011010", "1000111010", "1000110010", "1000100010",
    "1001100010", "1001110010", "1001111010", "1011111010", "1011110010",
    "1011110110", "1001110110", "1001110100", "1001100100", "1001100110",
    "1001000110", "1001000010", "1011000010", "1011100010", "1011100110",
    "1011100100", "1011101100", "1001101100", "1000101100", "1000101000",
    "1001101000", "1011101000", "1011001000", "1011001100", "1011000100",
    "1011000110", "1010000110", "1010001110", "1010001100", "1010011100",
    "1010011000", "1010111000", "1010110000", "1010010000", "1011010000",
    "1001010000", "1001011000", "1001011100", "1011011100", "1011011110",
    "1011001110", "1001001110", "1001101110", "1000101110", "1000100110",
    "1000110110", "1000010110",
))


@dataclass(frozen=True)
class _MicroVariant:
    columns: int
    rows: int
    data: int
    ecc: int
    left: int
    center: int | None
    right: int
    cluster: int


def _mv(columns, rows, data, ecc, left, center, right, cluster):
    return _MicroVariant(columns, rows, data, ecc, left, center, right, cluster)


# All 34 standardized variants.  (columns, rows) uniquely identifies a MicroPDF417 symbol.
_MICRO_VARIANTS = {(v.columns, v.rows): v for v in (
    _mv(1,11,4,7,0,None,48,0), _mv(1,14,7,7,7,None,47,1),
    _mv(1,17,10,7,35,None,23,2), _mv(1,20,12,8,18,None,6,0),
    _mv(1,24,16,8,8,None,4,2), _mv(1,28,20,8,24,None,20,0),
    _mv(2,8,8,8,0,None,40,0), _mv(2,11,13,9,0,None,48,0),
    _mv(2,14,19,9,7,None,47,1), _mv(2,17,24,10,35,None,23,2),
    _mv(2,20,29,11,18,None,6,0), _mv(2,23,33,13,8,None,4,2),
    _mv(2,26,37,15,26,None,22,2),
    _mv(3,6,6,12,0,45,40,0), _mv(3,8,10,14,6,51,46,0),
    _mv(3,10,14,16,14,7,2,2), _mv(3,12,18,18,24,17,12,0),
    _mv(3,15,24,21,36,29,24,0), _mv(3,20,34,26,0,9,20,0),
    _mv(3,26,46,32,0,1,4,0), _mv(3,32,58,38,20,21,24,2),
    _mv(3,38,70,44,14,23,34,2), _mv(3,44,82,50,0,17,36,0),
    _mv(4,4,8,8,46,11,30,1), _mv(4,6,12,12,0,45,40,0),
    _mv(4,8,18,14,6,51,46,0), _mv(4,10,24,16,14,7,2,2),
    _mv(4,12,30,18,24,17,12,0), _mv(4,15,39,21,36,29,24,0),
    _mv(4,20,54,26,0,9,20,0), _mv(4,26,72,32,0,1,4,0),
    _mv(4,32,90,38,20,21,24,2), _mv(4,38,108,44,14,23,34,2),
    _mv(4,44,126,50,0,17,36,0),
)}
_MICRO_WIDTH_COLUMNS = {38: 1, 55: 2, 82: 3, 99: 4}
_MICRO_CODEWORD_OFFSETS = {
    1: (10,), 2: (10, 27), 3: (10, 37, 54), 4: (10, 27, 54, 71),
}


def _micro_rap_distance(observed, expected, bits):
    return (_bits_int(observed, 0, bits) ^ expected).bit_count()


def _micro_rows(matrix, variant):
    """Validate RAPs/clusters and extract row-major MicroPDF417 codewords."""
    unique = []
    for row in matrix:
        if not unique or row != unique[-1]:
            unique.append(row)
    if len(unique) != variant.rows:
        return None
    offsets = _MICRO_CODEWORD_OFFSETS[variant.columns]
    center_at = 27 if variant.columns == 3 else 44 if variant.columns == 4 else None
    words, pattern_corrections, rap_corrections = [], 0, 0
    for ordinal, row in enumerate(unique):
        expected_left = _MICRO_SIDE_RAPS[(variant.left + ordinal) % 52]
        # Right RAP index zero corresponds to side index 12 and has an extra terminal dark module.
        expected_right = (_MICRO_SIDE_RAPS[(variant.right + ordinal + 12) % 52] << 1) | 1
        distances = [_micro_rap_distance(row[:10], expected_left, 10),
                     _micro_rap_distance(row[-11:], expected_right, 11)]
        if center_at is not None:
            expected_center = _MICRO_CENTER_RAPS[(variant.center + ordinal) % 52]
            distances.append(_micro_rap_distance(row[center_at:center_at + 10],
                                                 expected_center, 10))
        if any(distance > 1 for distance in distances):
            return None
        rap_corrections += sum(distances)
        decoded = [_pdf_pattern(_bits_int(row, offset, 17)) for offset in offsets]
        if any(value is None for value in decoded):
            return None
        expected_cluster = (variant.cluster + ordinal) % 3
        if any(value[1] != expected_cluster for value in decoded):
            return None
        pattern_corrections += sum(value[2] for value in decoded)
        words.extend(value[0] for value in decoded)
    if len(words) != variant.data + variant.ecc:
        return None
    return words, pattern_corrections, rap_corrections


def decode_micropdf417(matrix):
    """Decode every standardized MicroPDF417 variant; corrupt/unknown variants decline."""
    results, seen = [], set()
    for candidate, transform in _transforms(matrix):
        # Raster writers normally repeat each logical MicroPDF417 row two or more times.
        logical = []
        for row in candidate:
            if not logical or row != logical[-1]:
                logical.append(row)
        columns = _MICRO_WIDTH_COLUMNS.get(len(candidate[0]))
        variant = _MICRO_VARIANTS.get((columns, len(logical))) if columns else None
        if variant is None:
            continue
        rows = _micro_rows(logical, variant)
        if rows is None:
            continue
        fixed = rs_pdf417(rows[0], variant.ecc)
        if fixed is None:
            continue
        data = fixed[0][:variant.data]
        # MicroPDF417 omits PDF417's Symbol Length Descriptor.  Supplying the proven standardized
        # data capacity lets the shared high-level parser consume data/padding without inventing it.
        payload = _pdf_payload([len(data) + 1] + data)
        if payload is None or payload["bytes"] in seen:
            continue
        seen.add(payload["bytes"])
        results.append({"symbology": "micropdf417", "variant":
                        f"{variant.columns}x{variant.rows}", "rows": variant.rows,
                        "columns": variant.columns, "data_codewords": variant.data,
                        "ecc_codewords": variant.ecc, "corrected_symbols": fixed[1],
                        "pattern_corrections": rows[1], "rap_corrections": rows[2],
                        "transform": transform, **payload})
    return sorted(results, key=lambda item: (item["corrected_symbols"],
                                             item["pattern_corrections"] +
                                             item["rap_corrections"]))


def decode_pdf417(matrix):
    results, seen = [], set()
    for candidate, transform in _transforms(matrix):
        rows = _pdf_rows(candidate)
        if not rows: continue
        metadata = _pdf_metadata(rows)
        if metadata is None or metadata[2] is None: continue
        row_count, columns, ec_level = metadata
        words = [word for row in rows for word in row["data"]]
        parity = 1 << (ec_level + 1)
        if parity >= len(words): continue
        fixed = rs_pdf417(words, parity)
        if fixed is None: continue
        payload = _pdf_payload(fixed[0][:-parity])
        if payload is None or payload["bytes"] in seen: continue
        seen.add(payload["bytes"])
        results.append({"symbology":"compact_pdf417" if rows[0]["compact"] else "pdf417",
                        "rows":row_count, "columns":columns,
                        "ec_level":ec_level, "corrected_symbols":fixed[1],
                        "pattern_corrections":sum(row["pattern_corrections"] for row in rows),
                        "transform":transform, **payload})
    return sorted(results, key=lambda item:(item["corrected_symbols"],item["pattern_corrections"]))


def decode_other(matrix):
    """Decode all supported non-QR matrix symbologies, deduplicated and ranked."""
    try:
        matrix = _rect(matrix)  # decline malformed input with [] rather than leaking a ValueError
    except ValueError:
        return []
    results = (decode_datamatrix(matrix) + decode_aztec(matrix) + decode_pdf417(matrix) +
               decode_micropdf417(matrix))
    unique = {}
    for result in results:
        unique.setdefault((result["symbology"], result["bytes"]), result)
    return list(unique.values())


__all__ = ["decode_datamatrix", "decode_aztec", "decode_pdf417", "decode_micropdf417",
           "decode_other", "rs_binary", "rs_pdf417"]
