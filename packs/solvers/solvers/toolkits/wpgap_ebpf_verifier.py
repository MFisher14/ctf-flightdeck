#!/usr/bin/env python3
"""Audit contradictions in saved Linux eBPF verifier logs, entirely offline.

This module reads bounded UTF-8 text only.  It never opens or loads a BPF
program, never invokes the kernel verifier, never emulates instructions, and
never performs network I/O.  Findings describe contradictions in state that
the supplied log explicitly printed; they are not a verifier-acceptance,
reachability, kernel-version, or exploitability decision.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


MAX_LOG_BYTES = 4 << 20
MAX_LOG_LINES = 50_000
MAX_LINE_CHARS = 64 << 10
MAX_STATES = 12_000
MAX_REGISTERS_PER_STATE = 64
MAX_BPF_STACK_BYTES = 2_048
MAX_STACK_SLOTS_PER_STATE = MAX_BPF_STACK_BYTES // 8
MAX_FINDINGS = 4_096
MAX_WARNINGS = 4_096
MAX_DIAGNOSTICS = 4_096
MAX_ATTRIBUTES = 128
MAX_REFERENCES_PER_STATE = MAX_LINE_CHARS // 2

U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
S32_MIN = -(1 << 31)
S32_MAX = (1 << 31) - 1
S64_MIN = -(1 << 63)
S64_MAX = (1 << 63) - 1

DISCLAIMER = (
    "Static audit of explicitly logged verifier state only; this report does "
    "not determine verifier acceptance, kernel version, path reachability, or exploitability."
)


class WPGAPEBPFError(ValueError):
    """The only exception intentionally raised by public analysis APIs."""


@dataclass(frozen=True, slots=True)
class ScalarState:
    """One scalar value domain, or the variable-offset domain of a pointer."""

    representation: str
    precise: bool
    constant: int | None
    tnum_value: int | None
    tnum_mask: int | None
    bounds: tuple[tuple[str, int], ...]
    out_of_width_bounds: tuple[str, ...] = ()
    conflicting_bounds: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "representation": self.representation,
            "precise": self.precise,
            "constant": self.constant,
            "tnum": (
                None if self.tnum_value is None or self.tnum_mask is None else
                {"value": self.tnum_value, "mask": self.tnum_mask}
            ),
            "bounds": dict(self.bounds),
            "out_of_width_bounds": list(self.out_of_width_bounds),
            "conflicting_bounds": list(self.conflicting_bounds),
        }


@dataclass(frozen=True, slots=True)
class RegisterState:
    line_number: int
    pc: int | None
    frame: int
    register: str
    number: int
    liveness: str
    value_kind: str
    type_name: str
    numeric_state: ScalarState | None
    scalar_id: int | None
    ref_obj_id: int | None
    non_own_ref: bool
    attributes: tuple[tuple[str, str | None], ...]
    raw: str

    def as_dict(self) -> dict[str, object]:
        return {
            "line_number": self.line_number,
            "pc": self.pc,
            "frame": self.frame,
            "register": self.register,
            "number": self.number,
            "liveness": self.liveness,
            "value_kind": self.value_kind,
            "type_name": self.type_name,
            "numeric_state": None if self.numeric_state is None else self.numeric_state.as_dict(),
            "scalar_id": self.scalar_id,
            "ref_obj_id": self.ref_obj_id,
            "non_own_ref": self.non_own_ref,
            "attributes": [
                {"name": name, "value": value} for name, value in self.attributes
            ],
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class StackSlotState:
    """One stack slot printed by the verifier's ``fp-N=...`` formatter."""

    line_number: int
    pc: int | None
    frame: int
    register: str
    offset: int
    liveness: str
    value_kind: str
    type_name: str
    numeric_state: ScalarState | None
    scalar_id: int | None
    identity_id: int | None
    ref_obj_id: int | None
    reference_id: int | None
    dynptr_id: int | None
    parent_id: int | None
    non_own_ref: bool
    attributes: tuple[tuple[str, str | None], ...]
    raw: str

    def as_dict(self) -> dict[str, object]:
        return {
            "line_number": self.line_number,
            "pc": self.pc,
            "frame": self.frame,
            "slot": self.register,
            "offset": self.offset,
            "liveness": self.liveness,
            "value_kind": self.value_kind,
            "type_name": self.type_name,
            "numeric_state": None if self.numeric_state is None else self.numeric_state.as_dict(),
            "scalar_id": self.scalar_id,
            "identity_id": self.identity_id,
            "ref_obj_id": self.ref_obj_id,
            "reference_id": self.reference_id,
            "dynptr_id": self.dynptr_id,
            "parent_id": self.parent_id,
            "non_own_ref": self.non_own_ref,
            "attributes": [
                {"name": name, "value": value} for name, value in self.attributes
            ],
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class VerifierState:
    line_number: int
    pc: int | None
    frame: int
    registers: tuple[RegisterState, ...]
    stack_slots: tuple[StackSlotState, ...]
    refs: tuple[int, ...] | None
    raw: str

    def as_dict(self) -> dict[str, object]:
        return {
            "line_number": self.line_number,
            "pc": self.pc,
            "frame": self.frame,
            "registers": [register.as_dict() for register in self.registers],
            "stack_slots": [slot.as_dict() for slot in self.stack_slots],
            "refs": None if self.refs is None else list(self.refs),
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: str
    line_number: int
    register: str | None
    message: str
    evidence: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "line_number": self.line_number,
            "register": self.register,
            "message": self.message,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class AuditWarning:
    code: str
    line_number: int | None
    message: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "line_number": self.line_number,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class KernelDiagnostic:
    code: str
    line_number: int
    context: str | None
    message: str
    raw: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "line_number": self.line_number,
            "context": self.context,
            "message": self.message,
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class ParsedVerifierLog:
    states: tuple[VerifierState, ...]
    kernel_diagnostics: tuple[KernelDiagnostic, ...]
    warnings: tuple[AuditWarning, ...]
    lines: tuple[str, ...]
    ignored_line_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "states": [state.as_dict() for state in self.states],
            "kernel_diagnostics": [item.as_dict() for item in self.kernel_diagnostics],
            "warnings": [item.as_dict() for item in self.warnings],
            "line_count": len(self.lines),
            "ignored_line_count": self.ignored_line_count,
        }


@dataclass(frozen=True, slots=True)
class AuditReport:
    states: tuple[VerifierState, ...]
    findings: tuple[Finding, ...]
    kernel_diagnostics: tuple[KernelDiagnostic, ...]
    warnings: tuple[AuditWarning, ...]
    ignored_line_count: int
    offline: bool = True
    requests_sent: int = 0
    verifier_acceptance_claimed: bool = False
    disclaimer: str = DISCLAIMER

    @property
    def parsed_states(self) -> int:
        """Number of independently printed state snapshots in the log."""

        return len(self.states)

    def as_dict(self) -> dict[str, object]:
        return {
            "format": "wpgap-ebpf-verifier-audit-v1",
            "offline": self.offline,
            "requests_sent": self.requests_sent,
            "verifier_acceptance_claimed": self.verifier_acceptance_claimed,
            "disclaimer": self.disclaimer,
            "state_count": len(self.states),
            "parsed_states": self.parsed_states,
            "finding_count": len(self.findings),
            "kernel_diagnostic_count": len(self.kernel_diagnostics),
            "warning_count": len(self.warnings),
            "ignored_line_count": self.ignored_line_count,
            "states": [state.as_dict() for state in self.states],
            "findings": [finding.as_dict() for finding in self.findings],
            "kernel_diagnostics": [item.as_dict() for item in self.kernel_diagnostics],
            "warnings": [warning.as_dict() for warning in self.warnings],
        }


_BOUND_ALIASES = {
    "smin": "smin",
    "smax": "smax",
    "umin": "umin",
    "umax": "umax",
    "smin32": "smin32",
    "smax32": "smax32",
    "umin32": "umin32",
    "umax32": "umax32",
    "smin_value": "smin",
    "smax_value": "smax",
    "umin_value": "umin",
    "umax_value": "umax",
    "s32_min_value": "smin32",
    "s32_max_value": "smax32",
    "u32_min_value": "umin32",
    "u32_max_value": "umax32",
}

_BOUND_INFO = {
    "smin": (True, 64),
    "smax": (True, 64),
    "umin": (False, 64),
    "umax": (False, 64),
    "smin32": (True, 32),
    "smax32": (True, 32),
    "umin32": (False, 32),
    "umax32": (False, 32),
}

# Keep regular-expression construction visibly separate from any form of
# source-code compilation: this module has no dynamic execution surface.
_regex = re.compile
_REGISTER_RE = _regex(r"(?<![A-Za-z0-9_])R(?P<number>\d{1,3})(?P<live>_[A-Za-z]+)?=")
_STACK_RE = _regex(r"(?<![A-Za-z0-9_\[])fp(?P<offset>-?\d+)(?P<live>_[A-Za-z]+)?=")
_STACK_POINTER_RE = _regex(
    r"^fp(?:\[(?P<frameno>\d+)\])?"
    r"(?P<offset>[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))$"
)
_CROSS_FRAME_STACK_POINTER_RE = _regex(
    r"^fp\[(?P<frameno>\d+)\]\((?P<inner>.*)\)$"
)
_STACK_BYTE_MAP_RE = _regex(r"^[?rm0dipf]{8}$")
_PARTIAL_SCALAR_SPILL_RE = _regex(
    r"^(?P<mask>[?m0dipf]{1,7})(?P<state>"
    r"(?:(?:Pscalar|scalar|invP|Pinv|inv)\(.*\)|"
    r"(?:invP?|P)?[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)))$"
)
_REFS_RE = _regex(r"(?<![A-Za-z0-9_])refs=(?P<refs>[^\s;]*)")
_NUMBER_RE = _regex(r"^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)$")
_LINKED_ID_RE = _regex(r"^(?P<base>[0-9]+)(?P<delta>[+-][0-9]+)$")
_TNUM_RE = _regex(
    r"^\(\s*(?P<value>[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))\s*"
    r"(?P<separator>[;,])\s*"
    r"(?P<mask>[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))\s*\)$"
)
_PC_RE = _regex(r"^\s*(?P<pc>\d+):")
_FROM_TO_RE = _regex(
    r"\bfrom\s+\d+\s+to\s+(?P<pc>\d+)"
    r"(?:\s+\(speculative execution\))?:"
)
_CALLER_PC_RE = _regex(r"\bto\s+caller\s+at\s+(?P<pc>\d+):")
_FRAME_RE = _regex(r"\bframe(?P<frame>\d+):")
_STATE_LABEL_RE = _regex(
    r"^\s*(?:(?:cur|old) state:|stack=(?:-\d+(?:,-\d+)*)?:|"
    r"mark_precise:\s+frame\d+:\s+parent state regs="
    r"(?:r\d+(?:,r\d+)*)?\s+stack=(?:-\d+(?:,-\d+)*)?:)"
    r"(?:\s+frame\d+:)?\s*$"
)
_VALID_LIVENESS = frozenset({"r", "w", "D", "rw", "rD", "wD", "rwD"})
_REG_DIAGNOSTIC_RE = _regex(
    r"^\s*REG INVARIANTS VIOLATION\s*\((?P<context>[^)\r\n]{1,128})\)\s*:\s*"
    r"(?P<message>.+)$"
)
_REG_DIAGNOSTIC_PREFIX_RE = _regex(r"^\s*REG INVARIANTS VIOLATION\b")
_UNRELEASED_RE = _regex(
    r"^\s*Unreleased reference id=(?P<id>-?\d+)"
    r"(?:,?\s+alloc_insn=(?P<insn>-?\d+))?\s*$"
)
_READ_ERROR_RE = _regex(r"^\s*(?P<register>R\d+)\s+!read_ok\b.*$")
_REFERENCE_NOT_ACQUIRED_RE = _regex(
    r"^\s*(?P<context>(?:(?:func|kfunc)\s+)?[^\s]+(?:#\d+)?)\s+"
    r"reference has not been acquired before\s*$"
)
_UNACQUIRED_ARGUMENT_RE = _regex(
    r"^\s*(?P<context>(?:arg(?:ument)?|R)\s*#?\d+)\s+is an unacquired reference\s*$",
    re.IGNORECASE,
)
_BOUNDS_DIAGNOSTIC_RE = _regex(
    r"^\s*(?P<register>R\d+)\s+(?P<message>"
    r"(?:min value is negative\b.*|"
    r"max value is outside of the allowed memory range\b.*|"
    r"has unknown scalar with mixed signed bounds\b.*))$"
)
_CVE_BRANCH_RE = _regex(
    r"\bif\s+w(?P<register>\d+)\s*!=\s*0[xX]0*7ffffffd\b", re.IGNORECASE
)


def _add_warning(
    warnings: list[AuditWarning], code: str, line_number: int | None, message: str
) -> None:
    if len(warnings) >= MAX_WARNINGS:
        raise WPGAPEBPFError(f"warning count exceeds {MAX_WARNINGS}")
    warnings.append(AuditWarning(code, line_number, message))


def _add_finding(findings: list[Finding], finding: Finding) -> None:
    if len(findings) >= MAX_FINDINGS:
        raise WPGAPEBPFError(f"finding count exceeds {MAX_FINDINGS}")
    findings.append(finding)


def _coerce_text(data: object) -> tuple[str, ...]:
    if isinstance(data, str):
        if len(data) > MAX_LOG_BYTES:
            raise WPGAPEBPFError(f"log exceeds {MAX_LOG_BYTES}-byte cap")
        try:
            encoded = data.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise WPGAPEBPFError("log text is not valid UTF-8") from exc
    elif isinstance(data, (bytes, bytearray, memoryview)):
        try:
            size = data.nbytes if isinstance(data, memoryview) else len(data)
            if size > MAX_LOG_BYTES:
                raise WPGAPEBPFError(f"log exceeds {MAX_LOG_BYTES}-byte cap")
            encoded = bytes(data)
        except WPGAPEBPFError:
            raise
        except Exception as exc:
            raise WPGAPEBPFError("log bytes are not readable") from exc
    else:
        raise WPGAPEBPFError("log must be UTF-8 text or bytes")
    if len(encoded) > MAX_LOG_BYTES:
        raise WPGAPEBPFError(f"log exceeds {MAX_LOG_BYTES}-byte cap")
    if not encoded:
        raise WPGAPEBPFError("log is empty")
    try:
        text = encoded.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise WPGAPEBPFError("log bytes are not valid UTF-8") from exc
    if "\x00" in text:
        raise WPGAPEBPFError("log contains a NUL character")
    if text.count("\n") + 1 > MAX_LOG_LINES:
        raise WPGAPEBPFError(f"log exceeds {MAX_LOG_LINES}-line cap")
    lines = tuple(text.splitlines())
    if not lines or not any(line.strip() for line in lines):
        raise WPGAPEBPFError("log contains no text")
    for number, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_CHARS:
            raise WPGAPEBPFError(
                f"line {number} exceeds {MAX_LINE_CHARS}-character cap"
            )
    return lines


def _plain_int(text: str) -> int | None:
    value = text.strip()
    if not _NUMBER_RE.fullmatch(value):
        return None
    try:
        return int(value, 0 if "x" in value.lower() else 10)
    except (ValueError, OverflowError):
        return None


def _verifier_id(text: str) -> tuple[int, int | None] | None:
    """Parse a plain ID or current-kernel ``id=N+delta`` relation.

    The kernel stores the delta as ``s32`` and prints it in signed decimal.
    ``None`` in the second tuple position distinguishes a plain ID from a
    linked relation, including a linked relation whose delta happens to be 0.
    """

    plain = _plain_int(text)
    if plain is not None:
        return plain, None
    match = _LINKED_ID_RE.fullmatch(text.strip())
    if match is None:
        return None
    try:
        base = int(match.group("base"), 10)
        delta = int(match.group("delta"), 10)
    except (ValueError, OverflowError):
        return None
    if not S32_MIN <= delta <= S32_MAX:
        return None
    return base, delta


def _linked_id(
    attributes: tuple[tuple[str, str | None], ...],
) -> tuple[int, int] | None:
    """Return a parsed linked ``id`` relation retained in raw attributes."""

    for name, value in attributes:
        if name != "id" or value is None:
            continue
        parsed = _verifier_id(value)
        if parsed is not None and parsed[1] is not None:
            return parsed[0], parsed[1]
    return None


def _bound_value(text: str, signed: bool, width: int) -> tuple[int | None, bool]:
    raw = _plain_int(text)
    if raw is None:
        return None, False
    maximum = (1 << width) - 1
    if signed:
        minimum_signed = -(1 << (width - 1))
        maximum_signed = (1 << (width - 1)) - 1
        stripped = text.strip().lower()
        is_nonnegative_hex = not stripped.startswith("-") and (
            stripped.startswith("0x") or stripped.startswith("+0x")
        )
        if is_nonnegative_hex:
            if not 0 <= raw <= maximum:
                return raw, False
            if raw & (1 << (width - 1)):
                raw -= 1 << width
            return raw, True
        return raw, minimum_signed <= raw <= maximum_signed
    return raw, 0 <= raw <= maximum


def _u64_constant(text: str) -> int | None:
    raw = _plain_int(text)
    if raw is None or raw < S64_MIN or raw > U64_MAX:
        return None
    return raw & U64_MAX


def _split_attributes(inner: str) -> list[str] | None:
    rows: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(inner):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                return None
        elif character == "," and depth == 0:
            rows.append(inner[start:index].strip())
            start = index + 1
    if depth:
        return None
    rows.append(inner[start:].strip())
    if len(rows) > MAX_ATTRIBUTES:
        return None
    return rows


def _parse_attributes(
    inner: str,
    *,
    line_number: int,
    register: str,
    representation: str,
    precise: bool,
    force_numeric: bool,
    warnings: list[AuditWarning],
) -> tuple[
    ScalarState | None,
    int | None,
    int | None,
    bool,
    tuple[tuple[str, str | None], ...],
] | None:
    pieces = _split_attributes(inner)
    if pieces is None:
        _add_warning(
            warnings,
            "truncated_register_state",
            line_number,
            f"{register} has unbalanced or excessive attributes",
        )
        return None

    bounds: dict[str, int] = {}
    out_of_width: set[str] = set()
    conflicts: set[str] = set()
    tnum_value: int | None = None
    tnum_mask: int | None = None
    seen_var_off = False
    scalar_id: int | None = None
    ref_obj_id: int | None = None
    non_own_ref = False
    seen_non_own_ref = False
    attributes: list[tuple[str, str | None]] = []
    seen_identifiers: set[str] = set()

    for piece in pieces:
        if not piece:
            continue
        if piece == "non_own_ref":
            attributes.append((piece, None))
            if seen_non_own_ref:
                non_own_ref = False
                _add_warning(
                    warnings,
                    "duplicate_non_own_ref",
                    line_number,
                    f"{register} prints non_own_ref more than once",
                )
            else:
                seen_non_own_ref = True
                non_own_ref = True
            continue
        if "=" not in piece:
            attributes.append((piece, None))
            continue
        names, raw_value = piece.rsplit("=", 1)
        raw_names = [name.strip() for name in names.split("=")]
        value_text = raw_value.strip()
        if any(not name for name in raw_names):
            _add_warning(
                warnings,
                "malformed_attribute",
                line_number,
                f"{register} has an empty attribute name",
            )
            continue
        normalized = [_BOUND_ALIASES.get(name) for name in raw_names]
        if all(name is not None for name in normalized):
            for original, name in zip(raw_names, normalized):
                assert name is not None
                signed, width = _BOUND_INFO[name]
                value, valid = _bound_value(value_text, signed, width)
                attributes.append((original, value_text))
                if value is None:
                    _add_warning(
                        warnings,
                        "malformed_bound",
                        line_number,
                        f"{register} {original} is not an integer",
                    )
                    continue
                if name in bounds and bounds[name] != value:
                    conflicts.add(name)
                else:
                    bounds[name] = value
                if not valid:
                    out_of_width.add(name)
            continue

        if len(raw_names) != 1:
            for name in raw_names:
                attributes.append((name, value_text))
            continue
        name = raw_names[0]
        attributes.append((name, value_text))
        if name == "var_off":
            if seen_var_off:
                tnum_value = None
                tnum_mask = None
                _add_warning(
                    warnings,
                    "duplicate_tnum",
                    line_number,
                    f"{register} prints var_off more than once",
                )
                continue
            seen_var_off = True
            match = _TNUM_RE.fullmatch(value_text)
            if match is None or match.group("separator") != ";":
                _add_warning(
                    warnings,
                    "malformed_tnum",
                    line_number,
                    f"{register} var_off is not '(value; mask)'",
                )
                continue
            parsed_value = _plain_int(match.group("value"))
            parsed_mask = _plain_int(match.group("mask"))
            if parsed_value is None or parsed_mask is None:
                _add_warning(
                    warnings,
                    "malformed_tnum",
                    line_number,
                    f"{register} var_off contains a non-integer",
                )
                continue
            tnum_value, tnum_mask = parsed_value, parsed_mask
        elif name in {"id", "ref_obj_id"}:
            if name in seen_identifiers:
                if name == "id":
                    scalar_id = None
                else:
                    ref_obj_id = None
                _add_warning(
                    warnings,
                    "duplicate_identifier",
                    line_number,
                    f"{register} prints {name} more than once",
                )
                continue
            seen_identifiers.add(name)
            parsed_id = (
                _verifier_id(value_text)
                if name == "id"
                else None
            )
            parsed = (
                parsed_id[0]
                if parsed_id is not None
                else _plain_int(value_text)
            )
            if parsed is None:
                _add_warning(
                    warnings,
                    "malformed_identifier",
                    line_number,
                    f"{register} {name} has an invalid verifier-ID spelling",
                )
            elif name == "id":
                scalar_id = parsed
            else:
                ref_obj_id = parsed
        elif name == "non_own_ref":
            seen_non_own_ref = True
            non_own_ref = False
            _add_warning(
                warnings,
                "malformed_non_own_ref",
                line_number,
                f"{register} non_own_ref must use the kernel's bare-flag spelling",
            )

    numeric = None
    if force_numeric or bounds or tnum_value is not None:
        numeric = ScalarState(
            representation=representation,
            precise=precise,
            constant=None,
            tnum_value=tnum_value,
            tnum_mask=tnum_mask,
            bounds=tuple(sorted(bounds.items())),
            out_of_width_bounds=tuple(sorted(out_of_width)),
            conflicting_bounds=tuple(sorted(conflicts)),
        )
    return numeric, scalar_id, ref_obj_id, non_own_ref, tuple(attributes)


def _extract_atom(line: str, start: int) -> tuple[str, int] | None:
    index = start
    while index < len(line) and line[index].isspace():
        index += 1
    if index >= len(line):
        return None
    atom_start = index
    depth = 0
    opened = False
    while index < len(line):
        character = line[index]
        if character == "(":
            depth += 1
            opened = True
        elif character == ")":
            if depth == 0:
                return None
            depth -= 1
            if opened and depth == 0:
                return line[atom_start:index + 1], index + 1
        elif depth == 0 and (character.isspace() or character == ";"):
            break
        index += 1
    if depth:
        return None
    atom = line[atom_start:index]
    return (atom, index) if atom else None


def _location(prefix: str) -> tuple[int | None, int]:
    frame_match = _FRAME_RE.search(prefix)
    frame = int(frame_match.group("frame")) if frame_match else 0
    for expression in (_PC_RE, _FROM_TO_RE, _CALLER_PC_RE):
        match = expression.search(prefix)
        if match:
            return int(match.group("pc")), frame
    return None, frame


def _parse_register(
    atom: str,
    *,
    line_number: int,
    pc: int | None,
    frame: int,
    number: int,
    live: str,
    warnings: list[AuditWarning],
    label: str | None = None,
) -> RegisterState | None:
    register = label if label is not None else f"R{number}"
    precise = False
    representation = ""
    inner: str | None = None
    value_kind = "other"
    type_name = atom.split("(", 1)[0]

    scalar_prefixes = (
        ("Pscalar(", "scalar", True),
        ("scalar(", "scalar", False),
        ("invP(", "inv", True),
        ("Pinv(", "inv", True),
        ("inv(", "inv", False),
    )
    for prefix, name, is_precise in scalar_prefixes:
        if atom.startswith(prefix) and atom.endswith(")"):
            representation = name
            precise = is_precise
            type_name = name
            inner = atom[len(prefix):-1]
            value_kind = "scalar"
            break

    if value_kind != "scalar":
        legacy = re.fullmatch(
            r"inv(?P<precise>P)?(?P<number>[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))",
            atom,
        )
        modern_constant = re.fullmatch(
            r"(?P<precise>P)?(?P<number>[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+))",
            atom,
        )
        constant_match = legacy or modern_constant
        if constant_match is not None:
            constant = _u64_constant(constant_match.group("number"))
            if constant is None:
                _add_warning(
                    warnings,
                    "malformed_constant",
                    line_number,
                    f"{register} scalar constant is outside 64 bits",
                )
                return None
            precise = bool(constant_match.group("precise"))
            representation = "inv" if legacy is not None else "scalar"
            numeric = ScalarState(
                representation=representation,
                precise=precise,
                constant=constant,
                tnum_value=constant,
                tnum_mask=0,
                bounds=(),
            )
            return RegisterState(
                line_number, pc, frame, register, number, live, "scalar",
                representation, numeric, None, None, False, (), atom,
            )

    if inner is not None:
        parsed = _parse_attributes(
            inner,
            line_number=line_number,
            register=register,
            representation=representation,
            precise=precise,
            force_numeric=True,
            warnings=warnings,
        )
        if parsed is None:
            return None
        numeric, scalar_id, ref_obj_id, non_own_ref, attributes = parsed
        return RegisterState(
            line_number, pc, frame, register, number, live, "scalar", type_name,
            numeric, scalar_id, ref_obj_id, non_own_ref, attributes, atom,
        )

    stack_pointer = _STACK_POINTER_RE.fullmatch(atom)
    if stack_pointer is not None:
        attributes: list[tuple[str, str | None]] = []
        pointed_frame = stack_pointer.group("frameno")
        if pointed_frame is not None:
            attributes.append(("frameno", pointed_frame))
        attributes.append(("off", stack_pointer.group("offset")))
        return RegisterState(
            line_number,
            pc,
            frame,
            register,
            number,
            live,
            "pointer",
            "fp",
            None,
            None,
            None,
            False,
            tuple(attributes),
            atom,
        )

    cross_frame_stack_pointer = _CROSS_FRAME_STACK_POINTER_RE.fullmatch(atom)
    if cross_frame_stack_pointer is not None:
        parsed = _parse_attributes(
            cross_frame_stack_pointer.group("inner"),
            line_number=line_number,
            register=register,
            representation="pointer_offset",
            precise=False,
            force_numeric=False,
            warnings=warnings,
        )
        if parsed is None:
            return None
        numeric, scalar_id, ref_obj_id, non_own_ref, attributes = parsed
        attributes = (
            ("frameno", cross_frame_stack_pointer.group("frameno")),
        ) + attributes
        return RegisterState(
            line_number,
            pc,
            frame,
            register,
            number,
            live,
            "pointer",
            "fp",
            numeric,
            scalar_id,
            ref_obj_id,
            non_own_ref,
            attributes,
            atom,
        )

    pointer_match = re.fullmatch(r"(?P<type>[A-Za-z_?][A-Za-z0-9_?]*)(?:\((?P<inner>.*)\))?", atom)
    if pointer_match is None:
        _add_warning(
            warnings,
            "unrecognized_register_state",
            line_number,
            f"{register} has an unsupported state spelling",
        )
        return None
    type_name = pointer_match.group("type")
    pointer_inner = pointer_match.group("inner")
    if pointer_inner is None:
        return RegisterState(
            line_number, pc, frame, register, number, live, "other", type_name,
            None, None, None, False, (), atom,
        )
    parsed = _parse_attributes(
        pointer_inner,
        line_number=line_number,
        register=register,
        representation="pointer_offset",
        precise=False,
        force_numeric=False,
        warnings=warnings,
    )
    if parsed is None:
        return None
    numeric, scalar_id, ref_obj_id, non_own_ref, attributes = parsed
    return RegisterState(
        line_number, pc, frame, register, number, live, "pointer", type_name,
        numeric, scalar_id, ref_obj_id, non_own_ref, attributes, atom,
    )


def _stack_attribute_int(
    attributes: tuple[tuple[str, str | None], ...],
    name: str,
    *,
    line_number: int,
    slot: str,
    warnings: list[AuditWarning],
) -> int | None:
    values = [value for attribute, value in attributes if attribute == name]
    if not values:
        return None
    if len(values) > 1:
        _add_warning(
            warnings,
            "duplicate_stack_attribute",
            line_number,
            f"{slot} prints {name} more than once",
        )
        return None
    value = values[0]
    parsed = None if value is None else _plain_int(value)
    if parsed is None:
        _add_warning(
            warnings,
            "malformed_identifier",
            line_number,
            f"{slot} {name} is not an integer",
        )
    return parsed


def _parse_stack_slot(
    atom: str,
    *,
    line_number: int,
    pc: int | None,
    frame: int,
    offset: int,
    live: str,
    warnings: list[AuditWarning],
) -> StackSlotState | None:
    slot = f"fp{offset}"
    if _STACK_BYTE_MAP_RE.fullmatch(atom):
        return StackSlotState(
            line_number=line_number,
            pc=pc,
            frame=frame,
            register=slot,
            offset=offset,
            liveness=live,
            value_kind="bytes",
            type_name="slot_bytes",
            numeric_state=None,
            scalar_id=None,
            identity_id=None,
            ref_obj_id=None,
            reference_id=None,
            dynptr_id=None,
            parent_id=None,
            non_own_ref=False,
            attributes=(("byte_map", atom),),
            raw=atom,
        )

    state_atom = atom
    byte_prefix: str | None = None
    partial_spill = _PARTIAL_SCALAR_SPILL_RE.fullmatch(atom)
    if partial_spill is not None:
        byte_prefix = partial_spill.group("mask")
        state_atom = partial_spill.group("state")
    parsed = _parse_register(
        state_atom,
        line_number=line_number,
        pc=pc,
        frame=frame,
        number=offset,
        live=live,
        warnings=warnings,
        label=slot,
    )
    if parsed is None:
        return None

    if state_atom.startswith("dynptr_"):
        value_kind = "dynptr"
    elif state_atom.startswith("iter_"):
        value_kind = "iterator"
    else:
        value_kind = parsed.value_kind

    scalar_id = parsed.scalar_id if value_kind == "scalar" else None
    identity_id = parsed.scalar_id if value_kind != "scalar" else None
    reference_id = _stack_attribute_int(
        parsed.attributes,
        "ref_id",
        line_number=line_number,
        slot=slot,
        warnings=warnings,
    )
    dynptr_id = _stack_attribute_int(
        parsed.attributes,
        "dynptr_id",
        line_number=line_number,
        slot=slot,
        warnings=warnings,
    )
    parent_id = _stack_attribute_int(
        parsed.attributes,
        "parent_id",
        line_number=line_number,
        slot=slot,
        warnings=warnings,
    )
    attributes = parsed.attributes
    if byte_prefix is not None:
        attributes = (("byte_prefix", byte_prefix),) + attributes
    return StackSlotState(
        line_number=line_number,
        pc=pc,
        frame=frame,
        register=slot,
        offset=offset,
        liveness=live,
        value_kind=value_kind,
        type_name=parsed.type_name,
        numeric_state=parsed.numeric_state,
        scalar_id=scalar_id,
        identity_id=identity_id,
        ref_obj_id=parsed.ref_obj_id,
        reference_id=reference_id,
        dynptr_id=dynptr_id,
        parent_id=parent_id,
        non_own_ref=parsed.non_own_ref,
        attributes=attributes,
        raw=atom,
    )


def _parse_refs(
    line: str, line_number: int, warnings: list[AuditWarning]
) -> tuple[tuple[int, ...] | None, int | None]:
    matches = list(_REFS_RE.finditer(line))
    if not matches:
        return None, None
    if len(matches) > 1:
        _add_warning(
            warnings,
            "multiple_refs_fields",
            line_number,
            "state line contains more than one refs field",
        )
        return None, matches[0].start()
    match = matches[0]
    raw = match.group("refs")
    if not raw:
        _add_warning(
            warnings,
            "truncated_refs",
            line_number,
            "refs field is incomplete",
        )
        return None, match.start()
    values: list[int] = []
    for item in raw.split(","):
        parsed = _plain_int(item)
        if parsed is None:
            _add_warning(
                warnings,
                "malformed_refs",
                line_number,
                "refs field contains a non-integer identifier",
            )
            return None, match.start()
        values.append(parsed)
    if len(values) > MAX_REFERENCES_PER_STATE:
        raise WPGAPEBPFError(
            f"line {line_number} exceeds {MAX_REFERENCES_PER_STATE} reference identifiers"
        )
    return tuple(values), match.start()


def _credible_state_prefix(line: str, first_at: int) -> bool:
    prefix = line[:first_at]
    if not prefix.strip():
        return True
    if _PC_RE.search(prefix):
        return True
    stripped = prefix.strip()
    if any(
        expression.fullmatch(stripped)
        for expression in (_FRAME_RE, _FROM_TO_RE, _CALLER_PC_RE)
    ):
        return True
    return _STATE_LABEL_RE.fullmatch(prefix) is not None


def _diagnostic(line: str, line_number: int) -> KernelDiagnostic | None:
    match = _REG_DIAGNOSTIC_RE.match(line)
    if match is not None:
        message = match.group("message").strip()
        if message.startswith("range bounds violation"):
            code = "range_bounds_violation"
        elif message.startswith("const subreg tnum out of sync with range bounds"):
            code = "const_subreg_tnum_out_of_sync"
        elif message.startswith("const tnum out of sync with range bounds"):
            code = "const_tnum_out_of_sync"
        else:
            code = "register_invariants_violation"
        return KernelDiagnostic(code, line_number, match.group("context"), message, line.strip())
    match = _UNRELEASED_RE.match(line)
    if match is not None:
        message = match.group(0)
        return KernelDiagnostic("unreleased_reference", line_number, None, message, line.strip())
    match = _READ_ERROR_RE.match(line)
    if match is not None:
        message = line.strip()
        return KernelDiagnostic(
            "register_not_readable",
            line_number,
            match.group("register"),
            message,
            message,
        )
    match = _BOUNDS_DIAGNOSTIC_RE.fullmatch(line)
    if match is not None:
        message = match.group("message").strip()
        if message.startswith("min value is negative"):
            code = "negative_minimum_bound"
        elif message.startswith("max value is outside"):
            code = "maximum_outside_allowed_range"
        else:
            code = "mixed_signed_bounds"
        return KernelDiagnostic(
            code,
            line_number,
            match.group("register"),
            message,
            line.strip(),
        )
    match = _REFERENCE_NOT_ACQUIRED_RE.match(line)
    if match is not None:
        message = line.strip()
        return KernelDiagnostic(
            "reference_not_acquired", line_number, match.group("context"), message, message
        )
    match = _UNACQUIRED_ARGUMENT_RE.match(line)
    if match is not None:
        message = line.strip()
        return KernelDiagnostic(
            "reference_not_acquired", line_number, match.group("context"), message, message
        )
    return None


def _parse_verifier_log(data: object) -> ParsedVerifierLog:
    lines = _coerce_text(data)
    warnings: list[AuditWarning] = []
    diagnostics: list[KernelDiagnostic] = []
    states: list[VerifierState] = []
    recognized_lines: set[int] = set()

    for line_number, line in enumerate(lines, 1):
        diagnostic = _diagnostic(line, line_number)
        if diagnostic is not None:
            if len(diagnostics) >= MAX_DIAGNOSTICS:
                raise WPGAPEBPFError(f"diagnostic count exceeds {MAX_DIAGNOSTICS}")
            diagnostics.append(diagnostic)
            recognized_lines.add(line_number)
        elif _REG_DIAGNOSTIC_PREFIX_RE.match(line):
            _add_warning(
                warnings,
                "truncated_kernel_diagnostic",
                line_number,
                "kernel invariant diagnostic is incomplete",
            )
            recognized_lines.add(line_number)

        register_matches = list(_REGISTER_RE.finditer(line))
        stack_matches = list(_STACK_RE.finditer(line))
        warning_mark = len(warnings)
        refs, refs_at = _parse_refs(line, line_number, warnings)
        if not register_matches and not stack_matches and refs_at is None:
            continue
        if len(register_matches) > MAX_REGISTERS_PER_STATE:
            raise WPGAPEBPFError(
                f"line {line_number} exceeds {MAX_REGISTERS_PER_STATE} register states"
            )
        if len(stack_matches) > MAX_STACK_SLOTS_PER_STATE:
            raise WPGAPEBPFError(
                f"line {line_number} exceeds {MAX_STACK_SLOTS_PER_STATE} stack slots"
            )
        first_at = min(
            [match.start() for match in register_matches]
            + [match.start() for match in stack_matches]
            + ([] if refs_at is None else [refs_at])
        )
        if not _credible_state_prefix(line, first_at):
            del warnings[warning_mark:]
            continue
        pc, frame = _location(line[:first_at])
        registers: list[RegisterState] = []
        register_counts: dict[int, int] = {}
        for candidate in register_matches:
            number = int(candidate.group("number"))
            register_counts[number] = register_counts.get(number, 0) + 1
        duplicate_registers = {
            number for number, count in register_counts.items() if count > 1
        }
        warned_registers: set[int] = set()
        for match in register_matches:
            number = int(match.group("number"))
            live = (match.group("live") or "").removeprefix("_")
            if live and live not in _VALID_LIVENESS:
                _add_warning(
                    warnings,
                    "invalid_liveness",
                    line_number,
                    f"R{number} has a non-kernel liveness suffix",
                )
                continue
            if not 0 <= number <= 10:
                _add_warning(
                    warnings,
                    "invalid_register_number",
                    line_number,
                    f"R{number} is outside the eBPF register set R0-R10",
                )
                continue
            if number in duplicate_registers:
                if number not in warned_registers:
                    _add_warning(
                        warnings,
                        "duplicate_register_state",
                        line_number,
                        f"R{number} is printed more than once in one snapshot",
                    )
                    warned_registers.add(number)
                continue
            extracted = _extract_atom(line, match.end())
            register_name = f"R{number}"
            if extracted is None:
                _add_warning(
                    warnings,
                    "truncated_register_state",
                    line_number,
                    f"{register_name} state is incomplete",
                )
                continue
            atom, _end = extracted
            parsed = _parse_register(
                atom,
                line_number=line_number,
                pc=pc,
                frame=frame,
                number=number,
                live=live,
                warnings=warnings,
            )
            if parsed is not None:
                registers.append(parsed)
        stack_slots: list[StackSlotState] = []
        stack_counts: dict[int, int] = {}
        for candidate in stack_matches:
            offset = int(candidate.group("offset"))
            stack_counts[offset] = stack_counts.get(offset, 0) + 1
        duplicate_offsets = {
            offset for offset, count in stack_counts.items() if count > 1
        }
        warned_offsets: set[int] = set()
        for match in stack_matches:
            offset = int(match.group("offset"))
            slot_name = f"fp{offset}"
            live = (match.group("live") or "").removeprefix("_")
            if live and live not in _VALID_LIVENESS:
                _add_warning(
                    warnings,
                    "invalid_liveness",
                    line_number,
                    f"{slot_name} has a non-kernel liveness suffix",
                )
                continue
            if offset in duplicate_offsets:
                if offset not in warned_offsets:
                    _add_warning(
                        warnings,
                        "duplicate_stack_slot",
                        line_number,
                        f"{slot_name} is printed more than once in one snapshot",
                    )
                    warned_offsets.add(offset)
                continue
            extracted = _extract_atom(line, match.end())
            if extracted is None:
                _add_warning(
                    warnings,
                    "truncated_stack_state",
                    line_number,
                    f"{slot_name} state is incomplete",
                )
                continue
            atom, _end = extracted
            parsed = _parse_stack_slot(
                atom,
                line_number=line_number,
                pc=pc,
                frame=frame,
                offset=offset,
                live=live,
                warnings=warnings,
            )
            if parsed is not None:
                stack_slots.append(parsed)
        if registers or stack_slots or refs is not None:
            if len(states) >= MAX_STATES:
                raise WPGAPEBPFError(f"state count exceeds {MAX_STATES}")
            states.append(
                VerifierState(
                    line_number,
                    pc,
                    frame,
                    tuple(registers),
                    tuple(stack_slots),
                    refs,
                    line.strip(),
                )
            )
            recognized_lines.add(line_number)
        elif register_matches or stack_matches or refs_at is not None:
            recognized_lines.add(line_number)

    return ParsedVerifierLog(
        tuple(states),
        tuple(diagnostics),
        tuple(warnings),
        lines,
        len(lines) - len(recognized_lines),
    )


def parse_verifier_log(data: object) -> ParsedVerifierLog:
    """Parse bounded saved verifier-log text without interpreting a BPF program."""

    try:
        return _parse_verifier_log(data)
    except WPGAPEBPFError:
        raise
    except Exception as exc:
        raise WPGAPEBPFError("verifier-log parsing failed within declared bounds") from exc


def _to_signed(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    full = (1 << width) - 1
    value &= full
    return value - (1 << width) if value & sign else value


def _bounds_dict(state: ScalarState) -> dict[str, int]:
    return dict(state.bounds)


def _tnum_has_value_in_interval(
    value: int, mask: int, lower: int, upper: int, width: int
) -> bool:
    """Return whether a canonical tnum has a member in an unsigned interval."""

    full = (1 << width) - 1
    value &= full
    mask &= full
    if lower < 0 or upper > full or lower > upper:
        return False
    if value > upper or (value | mask) < lower:
        return False

    memo: dict[tuple[int, bool], int | None] = {}

    def minimum_at_least(bit: int, greater: bool) -> int | None:
        key = (bit, greater)
        if key in memo:
            return memo[key]
        if bit < 0:
            return 0
        lower_bit = (lower >> bit) & 1
        if mask & (1 << bit):
            choices = (0, 1)
        else:
            choices = ((value >> bit) & 1,)
        result: int | None = None
        for choice in choices:
            if not greater and choice < lower_bit:
                continue
            suffix = minimum_at_least(
                bit - 1, greater or (not greater and choice > lower_bit)
            )
            if suffix is not None:
                result = (choice << bit) | suffix
                break
        memo[key] = result
        return result

    candidate = minimum_at_least(width - 1, False)
    return candidate is not None and candidate <= upper


def _signed_bitpattern_segments(lower: int, upper: int, width: int) -> tuple[tuple[int, int], ...]:
    full = (1 << width) - 1
    if lower >= 0:
        return ((lower, upper),)
    if upper < 0:
        return (((1 << width) + lower, (1 << width) + upper),)
    return (((1 << width) + lower, full), (0, upper))


def _tnum_has_value_with_low32_interval(
    value: int,
    mask: int,
    lower64: int,
    upper64: int,
    lower32: int,
    upper32: int,
) -> bool:
    """Solve one 64-bit interval and one low-32 interval simultaneously."""

    memo: dict[tuple[int, bool, bool, bool, bool], bool] = {}

    def feasible(
        bit: int,
        above_lower64: bool,
        below_upper64: bool,
        above_lower32: bool,
        below_upper32: bool,
    ) -> bool:
        key = (
            bit,
            above_lower64,
            below_upper64,
            above_lower32,
            below_upper32,
        )
        if key in memo:
            return memo[key]
        if bit < 0:
            return True
        low64_bit = (lower64 >> bit) & 1
        high64_bit = (upper64 >> bit) & 1
        choices = (0, 1) if mask & (1 << bit) else ((value >> bit) & 1,)
        for choice in choices:
            if not above_lower64 and choice < low64_bit:
                continue
            if not below_upper64 and choice > high64_bit:
                continue
            next_above32 = above_lower32
            next_below32 = below_upper32
            if bit <= 31:
                low32_bit = (lower32 >> bit) & 1
                high32_bit = (upper32 >> bit) & 1
                if not above_lower32 and choice < low32_bit:
                    continue
                if not below_upper32 and choice > high32_bit:
                    continue
                next_above32 = above_lower32 or choice > low32_bit
                next_below32 = below_upper32 or choice < high32_bit
            if feasible(
                bit - 1,
                above_lower64 or choice > low64_bit,
                below_upper64 or choice < high64_bit,
                next_above32,
                next_below32,
            ):
                memo[key] = True
                return True
        memo[key] = False
        return False

    return feasible(63, False, False, False, False)


def _constraint_segments(
    states: Sequence[ScalarState], width: int
) -> tuple[tuple[int, int], ...] | None:
    suffix = "32" if width == 32 else ""
    umin_name, umax_name = f"umin{suffix}", f"umax{suffix}"
    smin_name, smax_name = f"smin{suffix}", f"smax{suffix}"
    names = {umin_name, umax_name, smin_name, smax_name}
    full = (1 << width) - 1
    unsigned_lower = 0
    unsigned_upper = full
    signed_lower = -(1 << (width - 1))
    signed_upper = (1 << (width - 1)) - 1
    for state in states:
        if state.conflicting_bounds or set(state.out_of_width_bounds).intersection(names):
            return None
        bounds = _bounds_dict(state)
        unsigned_lower = max(unsigned_lower, bounds.get(umin_name, 0))
        unsigned_upper = min(unsigned_upper, bounds.get(umax_name, full))
        signed_lower = max(signed_lower, bounds.get(smin_name, -(1 << (width - 1))))
        signed_upper = min(signed_upper, bounds.get(smax_name, (1 << (width - 1)) - 1))
    if unsigned_lower > unsigned_upper or signed_lower > signed_upper:
        return ()
    intersections: list[tuple[int, int]] = []
    for segment_lower, segment_upper in _signed_bitpattern_segments(
        signed_lower, signed_upper, width
    ):
        lower = max(unsigned_lower, segment_lower)
        upper = min(unsigned_upper, segment_upper)
        if lower <= upper:
            intersections.append((lower, upper))
    return tuple(intersections)


def _combined_tnum(
    states: Sequence[ScalarState],
) -> tuple[int, int, bool] | None:
    combined_value = 0
    combined_mask = U64_MAX
    for state in states:
        value, mask = state.tnum_value, state.tnum_mask
        if value is None and mask is None:
            continue
        if value is None or mask is None:
            return None
        if not (0 <= value <= U64_MAX and 0 <= mask <= U64_MAX) or value & mask:
            return None
        if (combined_value ^ value) & ~(combined_mask | mask) & U64_MAX:
            return combined_value, combined_mask, False
        combined_value |= value
        combined_mask &= mask
    return combined_value, combined_mask, True


def _constraints_have_common_value(
    states: Sequence[ScalarState], *, use_tnum: bool = True
) -> bool | None:
    segments64 = _constraint_segments(states, 64)
    segments32 = _constraint_segments(states, 32)
    if segments64 is None or segments32 is None:
        return None
    if not segments64 or not segments32:
        return False
    if use_tnum:
        combined = _combined_tnum(states)
        if combined is None:
            return None
        value, mask, compatible = combined
        if not compatible:
            return False
    else:
        value, mask = 0, U64_MAX
    return any(
        _tnum_has_value_with_low32_interval(
            value, mask, lower64, upper64, lower32, upper32
        )
        for lower64, upper64 in segments64
        for lower32, upper32 in segments32
    )


def _audit_numeric(
    register: RegisterState | StackSlotState, findings: list[Finding]
) -> None:
    state = register.numeric_state
    if state is None:
        return
    bounds = _bounds_dict(state)
    invalid = set(state.out_of_width_bounds) | set(state.conflicting_bounds)

    if state.conflicting_bounds:
        _add_finding(findings, Finding(
            "conflicting_bound_field",
            "high",
            register.line_number,
            register.register,
            "the same bound is printed with conflicting values",
            state.conflicting_bounds,
        ))
    for name in state.out_of_width_bounds:
        code = (
            "signed_bounds_out_of_width"
            if name.startswith("s")
            else "unsigned_bounds_out_of_width"
        )
        _add_finding(findings, Finding(
            code,
            "high",
            register.line_number,
            register.register,
            f"{name} is outside its declared numeric width",
            (f"{name}={bounds.get(name)!r}",),
        ))

    domains = (
        ("umin", "umax", "unsigned_bounds_inverted", "u64"),
        ("umin32", "umax32", "unsigned_bounds_inverted", "u32"),
        ("smin", "smax", "signed_bounds_inverted", "s64"),
        ("smin32", "smax32", "signed_bounds_inverted", "s32"),
    )
    inverted: set[str] = set()
    for minimum, maximum, code, domain in domains:
        if minimum in invalid or maximum in invalid:
            continue
        if minimum in bounds and maximum in bounds and bounds[minimum] > bounds[maximum]:
            inverted.add(domain)
            _add_finding(findings, Finding(
                code,
                "high",
                register.line_number,
                register.register,
                f"{domain} minimum exceeds maximum",
                (f"{minimum}={bounds[minimum]}", f"{maximum}={bounds[maximum]}"),
            ))

    value, mask = state.tnum_value, state.tnum_mask
    has_tnum = value is not None and mask is not None
    if has_tnum and not (0 <= value <= U64_MAX and 0 <= mask <= U64_MAX):
        assert value is not None and mask is not None
        which = []
        if not 0 <= value <= U64_MAX:
            which.append("value")
        if not 0 <= mask <= U64_MAX:
            which.append("mask")
        _add_finding(findings, Finding(
            "tnum_out_of_width",
            "high",
            register.line_number,
            register.register,
            "tnum component is outside 64 bits",
            tuple(which),
        ))
        return
    if has_tnum and value & mask:
        assert value is not None and mask is not None
        _add_finding(findings, Finding(
            "tnum_value_mask_overlap",
            "high",
            register.line_number,
            register.register,
            "tnum value and unknown-bit mask overlap",
            (f"value={value:#x}", f"mask={mask:#x}", f"overlap={value & mask:#x}"),
        ))
        return

    width_domains = (
        (64, "umin", "umax", "smin", "smax", "u64", "s64"),
        (32, "umin32", "umax32", "smin32", "smax32", "u32", "s32"),
    )
    segments_by_width: dict[int, tuple[tuple[int, int], ...]] = {}
    tnum_feasible_by_width: dict[int, bool] = {}
    for width, umin_name, umax_name, smin_name, smax_name, udomain, sdomain in width_domains:
        names = {umin_name, umax_name, smin_name, smax_name}
        if udomain in inverted or sdomain in inverted or invalid.intersection(names):
            continue
        full = (1 << width) - 1
        unsigned_lower = bounds.get(umin_name, 0)
        unsigned_upper = bounds.get(umax_name, full)
        signed_lower = bounds.get(smin_name, -(1 << (width - 1)))
        signed_upper = bounds.get(smax_name, (1 << (width - 1)) - 1)
        intersections: list[tuple[int, int]] = []
        for segment_lower, segment_upper in _signed_bitpattern_segments(
            signed_lower, signed_upper, width
        ):
            lower = max(unsigned_lower, segment_lower)
            upper = min(unsigned_upper, segment_upper)
            if lower <= upper:
                intersections.append((lower, upper))
        explicit = tuple(
            f"{name}={bounds[name]}"
            for name in (umin_name, umax_name, smin_name, smax_name)
            if name in bounds
        )
        if not intersections:
            _add_finding(findings, Finding(
                "signed_unsigned_bounds_disjoint",
                "high",
                register.line_number,
                register.register,
                f"{width}-bit signed and unsigned bounds have no common bit pattern",
                explicit,
            ))
            continue
        segments_by_width[width] = tuple(intersections)
        if has_tnum:
            assert value is not None and mask is not None
            feasible = any(
                _tnum_has_value_in_interval(value, mask, lower, upper, width)
                for lower, upper in intersections
            )
            tnum_feasible_by_width[width] = feasible
            if not feasible:
                _add_finding(findings, Finding(
                    "tnum_bounds_disjoint",
                    "high",
                    register.line_number,
                    register.register,
                    f"{width}-bit bounds contain no bit pattern represented by the tnum",
                    (
                        f"tnum=({value & ((1 << width) - 1):#x};"
                        f"{mask & ((1 << width) - 1):#x})",
                    ) + explicit,
                ))

    has_64_bounds = any(name in bounds for name in ("umin", "umax", "smin", "smax"))
    has_32_bounds = any(
        name in bounds for name in ("umin32", "umax32", "smin32", "smax32")
    )
    if has_64_bounds and has_32_bounds and set(segments_by_width) == {32, 64} and (
        not has_tnum or all(tnum_feasible_by_width.get(width, False) for width in (32, 64))
    ):
        without_tnum = _constraints_have_common_value((state,), use_tnum=False)
        with_tnum = _constraints_have_common_value((state,), use_tnum=True)
        all_explicit = tuple(f"{name}={bounds[name]}" for name in sorted(bounds))
        if without_tnum is False:
            _add_finding(findings, Finding(
                "cross_width_bounds_disjoint",
                "high",
                register.line_number,
                register.register,
                "64-bit and low-32 bounds cannot describe one bit pattern",
                all_explicit,
            ))
        elif has_tnum and with_tnum is False:
            assert value is not None and mask is not None
            _add_finding(findings, Finding(
                "tnum_bounds_disjoint",
                "high",
                register.line_number,
                register.register,
                "combined 64-bit and low-32 bounds contain no value represented by the tnum",
                (f"tnum=({value:#x};{mask:#x})",) + all_explicit,
            ))

    mismatches: list[str] = []
    if not has_tnum:
        return
    assert value is not None and mask is not None
    if mask == 0:
        expected64 = {
            "umin": value,
            "umax": value,
            "smin": _to_signed(value, 64),
            "smax": _to_signed(value, 64),
        }
        for name, expected in expected64.items():
            if name in bounds and name not in invalid and bounds[name] != expected:
                mismatches.append(f"{name}={bounds[name]} expected {expected}")
    if mask & U32_MAX == 0:
        low = value & U32_MAX
        expected32 = {
            "umin32": low,
            "umax32": low,
            "smin32": _to_signed(low, 32),
            "smax32": _to_signed(low, 32),
        }
        for name, expected in expected32.items():
            if name in bounds and name not in invalid and bounds[name] != expected:
                mismatches.append(f"{name}={bounds[name]} expected {expected}")
    if mismatches:
        _add_finding(findings, Finding(
            "constant_bounds_mismatch",
            "high",
            register.line_number,
            register.register,
            "constant tnum and explicit bounds disagree",
            tuple(mismatches),
        ))


def _audit_scalar_ids(state: VerifierState, findings: list[Finding]) -> None:
    grouped: dict[int, list[RegisterState | StackSlotState]] = {}
    for register in (*state.registers, *state.stack_slots):
        if register.value_kind != "scalar" or register.scalar_id in (None, 0):
            continue
        if register.scalar_id is not None and not 0 <= register.scalar_id <= U32_MAX:
            _add_finding(findings, Finding(
                "invalid_identifier",
                "high",
                register.line_number,
                register.register,
                "scalar equality ID is outside unsigned 32-bit range",
                (f"id={register.scalar_id}",),
            ))
            continue
        # Current kernels print linked scalar relations as id=N+delta.  The
        # hidden ID flag also records whether the add was 32- or 64-bit, so
        # equal printed N/delta pairs alone do not prove exact equality.
        if _linked_id(register.attributes) is not None:
            continue
        grouped.setdefault(register.scalar_id, []).append(register)

    for scalar_id, registers in sorted(grouped.items()):
        usable: list[RegisterState | StackSlotState] = []
        numeric_states: list[ScalarState] = []
        for register in registers:
            numeric = register.numeric_state
            if numeric is None:
                continue
            segments64 = _constraint_segments((numeric,), 64)
            segments32 = _constraint_segments((numeric,), 32)
            tnum = _combined_tnum((numeric,))
            if (
                segments64
                and segments32
                and tnum is not None
                and tnum[2]
            ):
                usable.append(register)
                numeric_states.append(numeric)
        if len(numeric_states) < 2:
            continue
        jointly_feasible = _constraints_have_common_value(tuple(numeric_states))
        if jointly_feasible is False:
            shown = usable[:8]
            evidence = tuple(f"{register.register}={register.raw}" for register in shown)
            if len(usable) > len(shown):
                evidence += (f"and {len(usable) - len(shown)} more aliases",)
            _add_finding(findings, Finding(
                "scalar_id_disjoint",
                "high",
                state.line_number,
                ",".join(register.register for register in shown),
                f"scalars sharing nonzero id={scalar_id} have no common bit pattern",
                evidence,
            ))


def _audit_references(state: VerifierState, findings: list[Finding]) -> None:
    if state.refs is not None:
        for reference in state.refs:
            if not 1 <= reference <= U32_MAX:
                _add_finding(findings, Finding(
                    "invalid_reference_id",
                    "high",
                    state.line_number,
                    None,
                    "refs contains an identifier outside the positive 32-bit range",
                    (f"refs id={reference}",),
                ))

    for register in state.registers:
        if (
            register.value_kind == "pointer"
            and register.scalar_id is not None
            and not 0 <= register.scalar_id <= U32_MAX
        ):
            _add_finding(findings, Finding(
                "invalid_identifier",
                "high",
                state.line_number,
                register.register,
                "pointer identity ID is outside unsigned 32-bit range",
                (f"id={register.scalar_id}",),
            ))

    for stack_slot in state.stack_slots:
        if (
            stack_slot.offset > -8
            or stack_slot.offset < -MAX_BPF_STACK_BYTES
            or stack_slot.offset % 8
        ):
            _add_finding(findings, Finding(
                "invalid_stack_slot_offset",
                "high",
                state.line_number,
                stack_slot.register,
                "verifier stack slots use aligned offsets from -8 through -2048",
                (f"offset={stack_slot.offset}",),
            ))
        for name, identifier in (
            ("id", stack_slot.identity_id),
            ("dynptr_id", stack_slot.dynptr_id),
            ("parent_id", stack_slot.parent_id),
        ):
            if identifier is not None and not 0 <= identifier <= U32_MAX:
                _add_finding(findings, Finding(
                    "invalid_identifier",
                    "high",
                    state.line_number,
                    stack_slot.register,
                    f"stack {name} is outside unsigned 32-bit range",
                    (f"{name}={identifier}",),
                ))

    owners: list[tuple[RegisterState | StackSlotState, str, int]] = []
    for register in state.registers:
        if register.ref_obj_id is not None:
            owners.append((register, "ref_obj_id", register.ref_obj_id))
    for stack_slot in state.stack_slots:
        if stack_slot.ref_obj_id is not None:
            owners.append((stack_slot, "ref_obj_id", stack_slot.ref_obj_id))
        if stack_slot.reference_id is not None:
            owners.append((stack_slot, "ref_id", stack_slot.reference_id))
        if stack_slot.value_kind == "iterator" and stack_slot.identity_id not in (None, 0):
            owners.append((stack_slot, "id", stack_slot.identity_id))
        if (
            stack_slot.value_kind == "dynptr"
            and stack_slot.type_name in {"dynptr_ringbuf", "dynptr_file"}
            and stack_slot.parent_id not in (None, 0)
        ):
            owners.append((stack_slot, "parent_id", stack_slot.parent_id))

    for owner, name, reference in owners:
        if not 1 <= reference <= U32_MAX:
            _add_finding(findings, Finding(
                "invalid_reference_id",
                "high",
                state.line_number,
                owner.register,
                f"{name} is outside the positive 32-bit range",
                (f"{name}={reference}",),
            ))
            continue
        if owner.non_own_ref and name == "ref_obj_id":
            _add_finding(findings, Finding(
                "non_own_reference_conflict",
                "high",
                state.line_number,
                owner.register,
                "non_own_ref cannot retain an owning reference identity",
                (f"ref_obj_id={reference}",),
            ))
        elif state.refs is not None and reference not in state.refs:
            _add_finding(findings, Finding(
                "orphan_reference",
                "high",
                state.line_number,
                owner.register,
                f"owning {name} is absent from this explicit refs set",
                (f"{name}={reference}", f"refs={state.refs}"),
            ))


def _audit_cve_pattern(parsed: ParsedVerifierLog, findings: list[Finding]) -> None:
    characteristic: dict[int, dict[int, RegisterState]] = {}
    for state in parsed.states:
        for register in state.registers:
            numeric = register.numeric_state
            if (register.value_kind == "scalar" and numeric is not None
                    and numeric.tnum_value == 0x2 and numeric.tnum_mask == 0x7FFFFFFD):
                characteristic.setdefault(register.number, {})[register.line_number] = register

    diagnostics_by_line: dict[int, list[KernelDiagnostic]] = {}
    for diagnostic in parsed.kernel_diagnostics:
        diagnostics_by_line.setdefault(diagnostic.line_number, []).append(diagnostic)

    emitted: set[tuple[int, int]] = set()
    for line_number, line in enumerate(parsed.lines, 1):
        for match in _CVE_BRANCH_RE.finditer(line):
            branch_register = int(match.group("register"))
            key = (line_number, branch_register)
            if key in emitted:
                continue
            candidates = characteristic.get(branch_register, {})
            register = next(
                (
                    candidates[candidate_line]
                    for candidate_line in range(line_number, line_number - 4, -1)
                    if candidate_line in candidates
                ),
                None,
            )
            if register is None:
                continue
            nearby = [
                diagnostic
                for candidate_line in range(line_number, line_number + 5)
                for diagnostic in diagnostics_by_line.get(candidate_line, ())
            ]

            def select(context: str, codes: set[str]) -> KernelDiagnostic | None:
                return next(
                    (
                        diagnostic for diagnostic in nearby
                        if (diagnostic.context or "").strip() == context
                        and diagnostic.code in codes
                    ),
                    None,
                )

            required = (
                select("true_reg2", {"range_bounds_violation"}),
                select("false_reg1", {"range_bounds_violation"}),
                select(
                    "false_reg2",
                    {"const_tnum_out_of_sync", "const_subreg_tnum_out_of_sync"},
                ),
            )
            if any(diagnostic is None for diagnostic in required):
                continue
            diagnostics = tuple(
                sorted(
                    (diagnostic for diagnostic in required if diagnostic is not None),
                    key=lambda diagnostic: diagnostic.line_number,
                )
            )
            emitted.add(key)
            _add_finding(findings, Finding(
                "cve_2024_41003_pattern",
                "high",
                line_number,
                register.register,
                (
                    "saved trace matches the narrow CVE-2024-41003 fake-register corruption "
                    "signature; this does not establish kernel version, "
                    "acceptance, or exploitability"
                ),
                (
                    f"line {register.line_number}: {register.raw}",
                    f"line {line_number}: {line.strip()}",
                ) + tuple(
                    f"line {diagnostic.line_number}: {diagnostic.raw}"
                    for diagnostic in diagnostics
                ),
            ))


def _audit(parsed: ParsedVerifierLog) -> AuditReport:
    findings: list[Finding] = []
    for state in parsed.states:
        for register in (*state.registers, *state.stack_slots):
            _audit_numeric(register, findings)
        _audit_scalar_ids(state, findings)
        _audit_references(state, findings)
    _audit_cve_pattern(parsed, findings)
    return AuditReport(
        states=parsed.states,
        findings=tuple(findings),
        kernel_diagnostics=parsed.kernel_diagnostics,
        warnings=parsed.warnings,
        ignored_line_count=parsed.ignored_line_count,
    )


def audit_verifier_log(data: object) -> AuditReport:
    """Audit one saved verifier log and return local contradictions only.

    Malformed top-level input raises :class:`WPGAPEBPFError`.  Incomplete
    state-like lines inside an otherwise readable log are preserved as report
    warnings and never promoted to invariant findings.
    """

    try:
        return _audit(parse_verifier_log(data))
    except WPGAPEBPFError:
        raise
    except Exception as exc:
        raise WPGAPEBPFError("verifier-log audit failed within declared bounds") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wpgap_ebpf_verifier.py",
        description="Offline invariant audit of a saved Linux eBPF verifier log",
    )
    parser.add_argument("log", metavar="LOG", help="saved UTF-8 verifier log")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(arguments.log)
        with path.open("rb") as stream:
            raw = stream.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            raise WPGAPEBPFError(f"log exceeds {MAX_LOG_BYTES}-byte cap")
        report = audit_verifier_log(raw)
        if arguments.pretty:
            output = json.dumps(report.as_dict(), indent=2, sort_keys=True)
        else:
            output = json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":"))
        print(output)
        return 0
    except (OSError, WPGAPEBPFError) as exc:
        parser._print_message(f"wpgap_ebpf_verifier: error: {exc}\n", sys.stderr)
        return 2
    except Exception:
        parser._print_message(
            "wpgap_ebpf_verifier: error: malformed saved log\n", sys.stderr
        )
        return 2


__all__ = [
    "MAX_LOG_BYTES",
    "WPGAPEBPFError",
    "ScalarState",
    "RegisterState",
    "StackSlotState",
    "VerifierState",
    "Finding",
    "AuditWarning",
    "KernelDiagnostic",
    "ParsedVerifierLog",
    "AuditReport",
    "parse_verifier_log",
    "audit_verifier_log",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
