"""Unique-only crackme/keygen/license reasoning over declarative constraints.

The solver inverts supplied transforms and solves finite linear systems; it
never enumerates candidates, executes a checker, or probes an artifact.  An
underdetermined system returns no candidate and lists unresolved positions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import re
from typing import Mapping, Sequence


MAX_INPUT_LENGTH = 256
MAX_STEPS = 128
MAX_EQUATIONS = 512
MAX_TEXT = 4 << 20


class ConstraintInputError(ValueError):
    pass


@dataclass(frozen=True)
class ReasoningResult:
    candidate: bytes | None
    unique: bool
    derivation: tuple[str, ...]
    evidence: tuple[str, ...]
    unresolved_positions: tuple[int, ...]

    def to_dict(self) -> dict:
        row = asdict(self)
        row["candidate_hex"] = self.candidate.hex() if self.candidate is not None else None
        del row["candidate"]
        return row


@dataclass(frozen=True)
class CrackmeLead:
    pattern: str
    confidence: int
    offset: int
    evidence: str
    recommended_solver: str


def _data(value: bytes, label: str = "value") -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be immutable bytes")
    if len(value) > MAX_INPUT_LENGTH:
        raise ConstraintInputError(f"{label} exceeds 256 bytes")
    return value


def _byte(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255:
        raise ConstraintInputError(f"{field} must be a byte")
    return value


def _rotate_right(value: int, count: int) -> int:
    count %= 8
    return ((value >> count) | (value << (8 - count))) & 0xFF if count else value


def _rotate_left(value: int, count: int) -> int:
    count %= 8
    return ((value << count) | (value >> (8 - count))) & 0xFF if count else value


def reverse_transform_pipeline(expected: bytes, steps: Sequence[Mapping[str, object]]) -> ReasoningResult:
    """Invert a stated forward transform pipeline in reverse order."""
    value = bytearray(_data(expected, "expected"))
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)) or len(steps) > MAX_STEPS:
        raise ConstraintInputError("steps must contain at most 128 mappings")
    derivation = []
    for reverse_index, raw in enumerate(reversed(steps)):
        if not isinstance(raw, Mapping):
            raise ConstraintInputError("transform step must be a mapping")
        kind = raw.get("kind")
        allowed_by_kind = {
            "reverse": {"kind"}, "xor": {"kind", "value"}, "add": {"kind", "value"},
            "sub": {"kind", "value"}, "rol": {"kind", "value"}, "ror": {"kind", "value"},
            "mul_add": {"kind", "multiplier", "addend"},
            "xor_repeating": {"kind", "key"}, "nibble_swap": {"kind"},
            "permutation": {"kind", "order"},
        }
        if not isinstance(kind, str) or kind not in allowed_by_kind:
            raise ConstraintInputError(f"unsupported transform kind {kind!r}")
        if any(key not in allowed_by_kind[kind] for key in raw):
            raise ConstraintInputError(f"transform {kind!r} contains an unknown field")
        if kind == "reverse":
            value.reverse()
            derivation.append("inverted reverse")
        elif kind in {"xor", "add", "sub", "rol", "ror", "mul_add"}:
            amount = _byte(raw.get("value", raw.get("addend", 0)), f"{kind} value")
            if kind == "xor":
                value = bytearray(byte ^ amount for byte in value)
            elif kind == "add":
                value = bytearray((byte - amount) & 0xFF for byte in value)
            elif kind == "sub":
                value = bytearray((byte + amount) & 0xFF for byte in value)
            elif kind == "rol":
                value = bytearray(_rotate_right(byte, amount) for byte in value)
            elif kind == "ror":
                value = bytearray(_rotate_left(byte, amount) for byte in value)
            else:
                multiplier = _byte(raw.get("multiplier"), "multiplier")
                if math.gcd(multiplier, 256) != 1:
                    raise ConstraintInputError("mul_add multiplier is not uniquely invertible modulo 256")
                inverse = pow(multiplier, -1, 256)
                value = bytearray(((byte - amount) * inverse) & 0xFF for byte in value)
            derivation.append(f"inverted {kind} step #{len(steps) - reverse_index}")
        elif kind == "xor_repeating":
            key = raw.get("key")
            if not isinstance(key, bytes) or not key or len(key) > MAX_INPUT_LENGTH:
                raise ConstraintInputError("xor_repeating key must be bounded non-empty bytes")
            value = bytearray(byte ^ key[index % len(key)] for index, byte in enumerate(value))
            derivation.append(f"inverted repeating XOR with stated {len(key)}-byte key")
        elif kind == "nibble_swap":
            value = bytearray(((byte & 0x0F) << 4) | (byte >> 4) for byte in value)
            derivation.append("inverted self-inverse nibble swap")
        elif kind == "permutation":
            order = raw.get("order")
            if (not isinstance(order, (list, tuple)) or len(order) != len(value)
                    or any(not isinstance(item, int) or isinstance(item, bool) for item in order)
                    or sorted(order) != list(range(len(value)))):
                raise ConstraintInputError("permutation must contain every input index exactly once")
            restored = bytearray(len(value))
            for output_index, input_index in enumerate(order):
                restored[input_index] = value[output_index]
            value = restored
            derivation.append("inverted stated permutation")
    candidate = bytes(value)
    return ReasoningResult(candidate, True, tuple(derivation),
                           ("every forward step had one stated inverse",), ())


def _alphabet(value: object) -> frozenset[int]:
    if value in (None, "bytes"):
        return frozenset(range(256))
    if value == "printable":
        return frozenset(range(0x20, 0x7F))
    if value == "alnum":
        return frozenset(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    if isinstance(value, bytes):
        values = value
    elif isinstance(value, (list, tuple)):
        values = value
    else:
        raise ConstraintInputError("alphabet must be bytes, printable, alnum, or byte values")
    if not 1 <= len(values) <= 256 or any(not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255 for item in values):
        raise ConstraintInputError("alphabet contains invalid byte values")
    return frozenset(values)


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def _assign(values: list[int | None], index: object, value: int, reason: str, derivation: list[str]) -> None:
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(values):
        raise ConstraintInputError("constraint index is outside the input")
    if values[index] is not None and values[index] != value:
        raise ConstraintInputError(f"conflicting constraints at index {index}")
    values[index] = value
    derivation.append(f"x[{index}]={value} from {reason}")


def _rows(value: object, field: str) -> Sequence[Mapping[str, object]]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_EQUATIONS:
        raise ConstraintInputError(f"{field} must be a bounded sequence")
    if any(not isinstance(item, Mapping) for item in value):
        raise ConstraintInputError(f"{field} entries must be mappings")
    return value


def _solve_linear(
    values: list[int | None], equations: Sequence[Mapping[str, object]], modulus: int
) -> tuple[list[int | None], tuple[str, ...]]:
    # A full-rank system modulo p determines a unique *byte* only when every
    # byte 0..255 has a distinct residue.  Smaller prime fields would make,
    # for example, 0 and p indistinguishable even at full rank.
    if not _is_prime(modulus) or not 255 < modulus <= 65521:
        raise ConstraintInputError("linear modulus must be a prime in 256..65521 for unique bytes")
    unknown = [index for index, value in enumerate(values) if value is None]
    matrix = []
    for equation in equations:
        if set(equation) - {"coefficients", "expected"}:
            raise ConstraintInputError("linear equation contains an unknown field")
        coefficients = equation.get("coefficients")
        expected = equation.get("expected")
        if (not isinstance(coefficients, (list, tuple)) or len(coefficients) != len(values)
                or any(not isinstance(item, int) or isinstance(item, bool)
                       or abs(item) > (1 << 63) - 1 for item in coefficients)
                or not isinstance(expected, int) or isinstance(expected, bool)
                or abs(expected) > (1 << 63) - 1):
            raise ConstraintInputError("linear equation shape is invalid")
        rhs = expected % modulus
        for index, known in enumerate(values):
            if known is not None:
                rhs = (rhs - coefficients[index] * known) % modulus
        matrix.append([*(coefficients[index] % modulus for index in unknown), rhs])
    pivot_columns = []
    row = 0
    for column in range(len(unknown)):
        pivot = next((candidate for candidate in range(row, len(matrix)) if matrix[candidate][column]), None)
        if pivot is None:
            continue
        matrix[row], matrix[pivot] = matrix[pivot], matrix[row]
        inverse = pow(matrix[row][column], -1, modulus)
        matrix[row] = [(item * inverse) % modulus for item in matrix[row]]
        for other in range(len(matrix)):
            if other == row or not matrix[other][column]:
                continue
            factor = matrix[other][column]
            matrix[other] = [(left - factor * right) % modulus for left, right in zip(matrix[other], matrix[row])]
        pivot_columns.append(column)
        row += 1
        if row == len(matrix):
            break
    if any(not any(entry[:-1]) and entry[-1] for entry in matrix):
        raise ConstraintInputError("linear constraints are inconsistent")
    if len(pivot_columns) != len(unknown):
        return values, (f"linear system rank {len(pivot_columns)} leaves {len(unknown) - len(pivot_columns)} free variable(s)",)
    for matrix_row, column in enumerate(pivot_columns):
        solution = matrix[matrix_row][-1]
        if solution > 255:
            raise ConstraintInputError("linear solution is not a byte")
        values[unknown[column]] = solution
    return values, (f"prime-field elimination produced rank {len(pivot_columns)}",)


def solve_constraint_spec(spec: Mapping[str, object]) -> ReasoningResult:
    """Solve only direct/uniquely invertible and full-rank stated constraints."""
    if not isinstance(spec, Mapping):
        raise TypeError("constraint spec must be a mapping")
    allowed = {"length", "alphabet", "fixed", "xor", "affine", "linear"}
    unknown_keys = [key for key in spec if key not in allowed]
    if unknown_keys:
        raise ConstraintInputError(f"unknown constraint keys: {sorted(map(repr, unknown_keys))}")
    length = spec.get("length")
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= MAX_INPUT_LENGTH:
        raise ConstraintInputError("length must be in 1..256")
    alphabet = _alphabet(spec.get("alphabet"))
    values: list[int | None] = [None] * length
    derivation = []
    for row in _rows(spec.get("fixed", ()), "fixed"):
        if set(row) - {"index", "value"}:
            raise ConstraintInputError("fixed constraint contains an unknown field")
        _assign(values, row.get("index"), _byte(row.get("value"), "fixed value"), "fixed equality", derivation)
    for row in _rows(spec.get("xor", ()), "xor"):
        if set(row) - {"index", "key", "expected"}:
            raise ConstraintInputError("xor constraint contains an unknown field")
        key = _byte(row.get("key"), "xor key")
        expected = _byte(row.get("expected"), "xor expected")
        _assign(values, row.get("index"), expected ^ key, "stated XOR equality", derivation)
    for row in _rows(spec.get("affine", ()), "affine"):
        if set(row) - {"index", "multiplier", "addend", "expected", "modulus"}:
            raise ConstraintInputError("affine constraint contains an unknown field")
        multiplier = _byte(row.get("multiplier"), "affine multiplier")
        addend = _byte(row.get("addend", 0), "affine addend")
        expected = _byte(row.get("expected"), "affine expected")
        modulus = row.get("modulus", 256)
        if modulus != 256 or math.gcd(multiplier, 256) != 1:
            raise ConstraintInputError("affine byte constraint must be uniquely invertible modulo 256")
        solved = ((expected - addend) * pow(multiplier, -1, 256)) & 0xFF
        _assign(values, row.get("index"), solved, "invertible affine equality", derivation)
    linear = spec.get("linear")
    evidence = []
    if linear is not None:
        if not isinstance(linear, Mapping) or set(linear) - {"modulus", "equations"}:
            raise ConstraintInputError("linear constraint object is invalid")
        modulus = linear.get("modulus")
        if not isinstance(modulus, int) or isinstance(modulus, bool):
            raise ConstraintInputError("linear modulus is invalid")
        values, facts = _solve_linear(values, _rows(linear.get("equations", ()), "linear equations"), modulus)
        evidence.extend(facts)
    unresolved = tuple(index for index, value in enumerate(values) if value is None)
    violations = tuple(index for index, value in enumerate(values) if value is not None and value not in alphabet)
    if violations:
        raise ConstraintInputError(f"derived values violate alphabet at positions {violations}")
    if unresolved:
        return ReasoningResult(None, False, tuple(derivation), tuple(evidence or ("constraints are underdetermined",)), unresolved)
    candidate = bytes(value for value in values if value is not None)
    return ReasoningResult(candidate, True, tuple(derivation),
                           tuple(evidence or ("every byte was uniquely derived",)), ())


def derive_luhn_check_digit(prefix: str) -> str:
    if not isinstance(prefix, str) or not 1 <= len(prefix) <= MAX_INPUT_LENGTH or not prefix.isascii() or not prefix.isdigit():
        raise ConstraintInputError("Luhn prefix must be 1..256 ASCII digits")
    digits = [int(char) for char in prefix + "0"]
    parity = len(digits) % 2
    total = 0
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((-total) % 10)


def validate_luhn(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_INPUT_LENGTH or not value.isascii() or not value.isdigit():
        return False
    return value[-1] == derive_luhn_check_digit(value[:-1]) if len(value) > 1 else value == "0"


def derive_mod97_suffix(prefix: str, *, width: int = 2, target_remainder: int = 1) -> str:
    if not isinstance(prefix, str) or not prefix or len(prefix) > MAX_INPUT_LENGTH or not prefix.isascii() or not prefix.isdigit():
        raise ConstraintInputError("mod97 prefix must be bounded ASCII digits")
    if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 4:
        raise ConstraintInputError("mod97 width must be in 1..4")
    if not isinstance(target_remainder, int) or isinstance(target_remainder, bool) or not 0 <= target_remainder < 97:
        raise ConstraintInputError("target remainder must be in 0..96")
    base = int(prefix) % 97
    suffix = (target_remainder - base * pow(10, width, 97)) % 97
    if suffix >= 10 ** width:
        raise ConstraintInputError("no fixed-width mod97 suffix exists")
    return f"{suffix:0{width}d}"


_PATTERNS: tuple[tuple[str, int, re.Pattern[str], str], ...] = (
    ("direct-compare", 90, re.compile(r"(?i)\b(?:strcmp|strncmp|memcmp|SequenceEqual|compareTo)\b"), "inspect the compared buffer and expected constant"),
    ("xor-transform", 82, re.compile(
        r"(?i)(?:(?:serial|key|input|byte)s?.{0,40}(?:\bxor\b|\^)|(?:\bxor\b|\^).{0,40}(?:serial|key|input|byte)s?)"
    ), "encode the stated XOR equations directly"),
    ("affine-transform", 78, re.compile(r"(?i)(?:serial|key|input).{0,100}(?:\badd\b|\bsub\b|\bimul\b|\*|\+)"), "invert only coefficients coprime to the stated modulus"),
    ("checksum", 80, re.compile(r"(?i)\b(?:crc32|adler32|checksum|luhn|mod\s*97)\b"), "derive the documented check field from the fixed prefix"),
    ("hardware-bound", 84, re.compile(r"(?i)\b(?:GetVolumeInformation|MachineGuid|CPUID|IOPlatformUUID|product_uuid)\b"), "separate the stated hardware identifier from the serial transform"),
    ("success-failure-branch", 72, re.compile(r"(?i)\b(?:invalid serial|license accepted|wrong key|good job|access granted)\b"), "trace the exact branch reaching the success/failure string"),
)


def detect_crackme_patterns(value: bytes | str) -> tuple[CrackmeLead, ...]:
    if isinstance(value, bytes):
        raw = value
        text = value.decode("latin1", "replace")
    elif isinstance(value, str):
        text = value
        raw = value.encode("utf-8", "replace")
    else:
        raise TypeError("pattern input must be bytes or text")
    if len(raw) > MAX_TEXT:
        raise ConstraintInputError("pattern input exceeds the 4 MiB cap")
    rows = []
    for name, confidence, pattern, solver in _PATTERNS:
        match = pattern.search(text)
        if match:
            rows.append(CrackmeLead(name, confidence, match.start(), match.group(0)[:160], solver))
    return tuple(sorted(rows, key=lambda row: (row.offset, row.pattern)))


__all__ = [
    "ConstraintInputError", "ReasoningResult", "CrackmeLead", "reverse_transform_pipeline",
    "solve_constraint_spec", "derive_luhn_check_digit", "validate_luhn",
    "derive_mod97_suffix", "detect_crackme_patterns",
]
