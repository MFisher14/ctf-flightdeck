#!/usr/bin/env python3
"""Semantic restricted-character and allowlist transformation planning.

This module is intentionally distinct from transport/WAF encoding catalogs.
It does not URL-, HTML-, Unicode-, Base64-, or percent-encode text.  Instead it
builds explicit derivations from allowed literals, case swaps, slices of named
already-available fragments, numeric code points, addition, and XOR.  Plans are
metadata; no expression is evaluated and no generated string is executed.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Mapping


OPERATIONS: tuple[str, ...] = (
    "literal",
    "concat",
    "case_swap",
    "fragment_slice",
    "codepoint",
    "add",
    "xor",
)
MAX_TARGET_CHARS = 256
MAX_ALLOWED_CHARS = 512
MAX_FRAGMENTS = 32
MAX_FRAGMENT_CHARS = 1024
MAX_PLANS = 16
MAX_STEPS = 512
MAX_OPERAND_SPAN = 4096
_NAME_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,31}\Z")


class RestrictedCharsetInputError(ValueError):
    """A construction profile or target is malformed or over cap."""


@dataclass(frozen=True)
class NamedFragment:
    name: str
    value: str


@dataclass(frozen=True)
class RestrictionProfile:
    allowed_characters: frozenset[str]
    operations: frozenset[str] = frozenset({"literal"})
    fragments: tuple[NamedFragment, ...] = ()
    operand_min: int = 1
    operand_max: int = 127

    def validate(self) -> None:
        if not isinstance(self.allowed_characters, (set, frozenset, tuple, list)):
            raise RestrictedCharsetInputError("allowed_characters must be a bounded collection")
        if not isinstance(self.operations, (set, frozenset, tuple, list)):
            raise RestrictedCharsetInputError("operations must be a bounded collection")
        if not isinstance(self.fragments, (tuple, list)):
            raise RestrictedCharsetInputError("fragments must be a bounded sequence")
        if len(self.allowed_characters) > MAX_ALLOWED_CHARS:
            raise RestrictedCharsetInputError("allowed-character cap exceeded")
        if any(not isinstance(item, str) or len(item) != 1 for item in self.allowed_characters):
            raise RestrictedCharsetInputError("allowed_characters must contain single characters")
        if not self.operations or len(self.operations) > len(OPERATIONS):
            raise RestrictedCharsetInputError("operations must be a non-empty bounded set")
        if any(not isinstance(item, str) for item in self.operations):
            raise RestrictedCharsetInputError("operations must contain text names")
        unknown = sorted(set(self.operations).difference(OPERATIONS))
        if unknown:
            raise RestrictedCharsetInputError("unknown operations: " + ", ".join(unknown))
        if len(self.fragments) > MAX_FRAGMENTS:
            raise RestrictedCharsetInputError("fragment cap exceeded")
        names: set[str] = set()
        for fragment in self.fragments:
            if not isinstance(fragment, NamedFragment):
                raise RestrictedCharsetInputError("fragments must be NamedFragment values")
            if not _NAME_RE.fullmatch(fragment.name) or fragment.name in names:
                raise RestrictedCharsetInputError("fragment names must be unique safe identifiers")
            if not fragment.value or len(fragment.value) > MAX_FRAGMENT_CHARS or "\x00" in fragment.value:
                raise RestrictedCharsetInputError("fragment value is empty, overlong, or contains NUL")
            names.add(fragment.name)
        if (
            isinstance(self.operand_min, bool)
            or isinstance(self.operand_max, bool)
            or not isinstance(self.operand_min, int)
            or not isinstance(self.operand_max, int)
            or not 0 <= self.operand_min <= self.operand_max <= 0x10FFFF
        ):
            raise RestrictedCharsetInputError("operand bounds must be ordered Unicode-range integers")
        if self.operand_max - self.operand_min > MAX_OPERAND_SPAN:
            raise RestrictedCharsetInputError(f"operand span exceeds {MAX_OPERAND_SPAN}")


@dataclass(frozen=True)
class TransformationStep:
    operation: str
    output: str
    operands: tuple[str, ...]
    explanation: str

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["operands"] = list(self.operands)
        return row


@dataclass(frozen=True)
class TransformationPlan:
    plan_id: str
    target: str
    descriptor: str
    steps: tuple[TransformationStep, ...]
    required_operations: tuple[str, ...]
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    cost: int
    inert: bool = True
    expression_emitted: bool = False
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["steps"] = [step.as_dict() for step in self.steps]
        row["required_operations"] = list(self.required_operations)
        row["derivation"] = list(self.derivation)
        row["preconditions"] = list(self.preconditions)
        return row


def _characters(value: object) -> frozenset[str]:
    if isinstance(value, str):
        rows = tuple(value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        rows = tuple(value)
    else:
        raise RestrictedCharsetInputError("allowed_characters must be text or a bounded sequence")
    if len(rows) > MAX_ALLOWED_CHARS or any(not isinstance(item, str) or len(item) != 1 for item in rows):
        raise RestrictedCharsetInputError("allowed_characters must contain bounded single characters")
    return frozenset(rows)


def _operations(value: object) -> frozenset[str]:
    if isinstance(value, str):
        rows = (value,)
    elif isinstance(value, (list, tuple, set, frozenset)):
        rows = tuple(value)
    else:
        raise RestrictedCharsetInputError("operations must be text or a bounded sequence")
    if len(rows) > len(OPERATIONS) or any(not isinstance(item, str) for item in rows):
        raise RestrictedCharsetInputError("operations contain invalid or too many entries")
    return frozenset(rows)


def profile_from_mapping(mapping: Mapping[str, object]) -> RestrictionProfile:
    if not isinstance(mapping, Mapping) or len(mapping) > 16:
        raise RestrictedCharsetInputError("profile must be a small mapping")
    fragments_raw = mapping.get("fragments", {})
    if not isinstance(fragments_raw, Mapping) or len(fragments_raw) > MAX_FRAGMENTS:
        raise RestrictedCharsetInputError("fragments must be a bounded mapping")
    fragments: list[NamedFragment] = []
    for name, value in fragments_raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise RestrictedCharsetInputError("fragment names and values must be text")
        fragments.append(NamedFragment(name, value))
    operand_min = mapping.get("operand_min", 1)
    operand_max = mapping.get("operand_max", 127)
    profile = RestrictionProfile(
        allowed_characters=_characters(mapping.get("allowed_characters", "")),
        operations=_operations(mapping.get("operations", ("literal",))),
        fragments=tuple(fragments),
        operand_min=operand_min if isinstance(operand_min, int) else -1,
        operand_max=operand_max if isinstance(operand_max, int) else -1,
    )
    profile.validate()
    return profile


def _target(value: object) -> str:
    if not isinstance(value, str):
        raise RestrictedCharsetInputError("target must be text")
    if not value or len(value) > MAX_TARGET_CHARS or "\x00" in value:
        raise RestrictedCharsetInputError(f"target must contain 1..{MAX_TARGET_CHARS} non-NUL characters")
    return value


def _descriptor(plan_id: str, target: str, steps: tuple[TransformationStep, ...]) -> str:
    return (
        "R5D_CHAR_PLAN"
        f"|strategy={plan_id}"
        f"|target_length={len(target)}"
        f"|steps={len(steps)}"
        "|expression=NOT_EMITTED"
        "|action=REVIEW_ONLY"
    )


def _make_plan(
    plan_id: str,
    target: str,
    steps: tuple[TransformationStep, ...],
    required: tuple[str, ...],
    derivation: tuple[str, ...],
    preconditions: tuple[str, ...],
) -> TransformationPlan:
    if not steps or len(steps) > MAX_STEPS:
        raise RestrictedCharsetInputError("plan step cap exceeded")
    return TransformationPlan(
        plan_id=plan_id,
        target=target,
        descriptor=_descriptor(plan_id, target, steps),
        steps=steps,
        required_operations=required,
        derivation=derivation,
        preconditions=preconditions,
        cost=len(steps) + len(required),
    )


def _concat_requirement(steps: tuple[TransformationStep, ...]) -> tuple[str, ...]:
    return ("concat",) if len(steps) > 1 else ()


def _literal_plan(target: str, profile: RestrictionProfile) -> TransformationPlan | None:
    if "literal" not in profile.operations or not set(target) <= profile.allowed_characters:
        return None
    steps = (TransformationStep("literal", target, (target,), "use the allowed target text directly"),)
    return _make_plan(
        "literal", target, steps, ("literal",),
        ("compare every target character with the allowlist", "retain the text unchanged"),
        ("the surrounding jail accepts a literal value in this context",),
    )


def _case_plan(target: str, profile: RestrictionProfile) -> TransformationPlan | None:
    if "case_swap" not in profile.operations:
        return None
    steps: list[TransformationStep] = []
    used_swap = False
    for character in target:
        if character in profile.allowed_characters:
            steps.append(TransformationStep("literal", character, (character,), "use an allowed character"))
            continue
        alternate = character.swapcase()
        if alternate == character or alternate not in profile.allowed_characters:
            return None
        used_swap = True
        steps.append(TransformationStep("case_swap", character, (alternate,), "swap the case of an allowed counterpart"))
    frozen = tuple(steps)
    if len(frozen) > 1 and "concat" not in profile.operations:
        return None
    if not used_swap:
        return None
    required = ("case_swap",) + _concat_requirement(frozen)
    return _make_plan(
        "case_swap", target, frozen, required,
        ("select an allowed same-letter opposite-case source for each blocked character", "apply case swap where needed", "concatenate outputs in target order"),
        ("case conversion is deterministic in the jail's character model", "concatenation is available for multi-character output"),
    )


def _fragment_path(target: str, fragments: tuple[NamedFragment, ...]) -> tuple[TransformationStep, ...] | None:
    # Dynamic programming chooses the fewest slices, then the stable fragment/start order.
    paths: list[tuple[TransformationStep, ...] | None] = [None] * (len(target) + 1)
    paths[0] = ()
    for position in range(len(target)):
        path = paths[position]
        if path is None:
            continue
        for fragment in fragments:
            maximum = min(len(fragment.value), len(target) - position)
            for length in range(maximum, 0, -1):
                output = target[position:position + length]
                start = fragment.value.find(output)
                if start < 0:
                    continue
                end_position = position + length
                step = TransformationStep(
                    "fragment_slice",
                    output,
                    (fragment.name, str(start), str(start + length), fragment.value),
                    f"slice {fragment.name}[{start}:{start + length}]",
                )
                candidate = path + (step,)
                current = paths[end_position]
                if current is None or len(candidate) < len(current):
                    paths[end_position] = candidate
    return paths[-1]


def _fragment_plan(target: str, profile: RestrictionProfile) -> TransformationPlan | None:
    if "fragment_slice" not in profile.operations or not profile.fragments:
        return None
    steps = _fragment_path(target, profile.fragments)
    if steps is None:
        return None
    if len(steps) > 1 and "concat" not in profile.operations:
        return None
    required = ("fragment_slice",) + _concat_requirement(steps)
    return _make_plan(
        "fragment_slice", target, steps, required,
        ("search named available fragments for target substrings", "choose a deterministic minimum-slice cover", "concatenate slices in target order"),
        ("the named fragments really exist in the jail context", "slice/index access is permitted", "concatenation is available when multiple slices are needed"),
    )


def _codepoint_plan(target: str, profile: RestrictionProfile) -> TransformationPlan | None:
    if "codepoint" not in profile.operations:
        return None
    steps = tuple(
        TransformationStep("codepoint", character, (str(ord(character)),), "construct the character from its Unicode code point")
        for character in target
    )
    if len(steps) > 1 and "concat" not in profile.operations:
        return None
    required = ("codepoint",) + _concat_requirement(steps)
    return _make_plan(
        "codepoint", target, steps, required,
        ("map each target character to its integer code point", "apply the jail's reviewed codepoint-to-character primitive", "concatenate outputs"),
        ("a codepoint-to-character primitive is allowlisted", "numeric literals are expressible", "the character model is Unicode-compatible"),
    )


def _pair(value: int, operation: str, minimum: int, maximum: int) -> tuple[int, int] | None:
    if operation == "add":
        left = max(minimum, value - maximum)
        right = value - left
        return (left, right) if minimum <= left <= maximum and minimum <= right <= maximum else None
    for left in range(minimum, maximum + 1):
        right = value ^ left
        if minimum <= right <= maximum:
            return left, right
    return None


def _numeric_plan(target: str, profile: RestrictionProfile, operation: str) -> TransformationPlan | None:
    if operation not in profile.operations or "codepoint" not in profile.operations:
        return None
    steps: list[TransformationStep] = []
    for character in target:
        operands = _pair(ord(character), operation, profile.operand_min, profile.operand_max)
        if operands is None:
            return None
        left, right = operands
        symbol = "+" if operation == "add" else "XOR"
        steps.append(TransformationStep(
            operation,
            character,
            (str(left), str(right)),
            f"derive code point {ord(character)} as {left} {symbol} {right}, then convert it to a character",
        ))
    frozen = tuple(steps)
    if len(frozen) > 1 and "concat" not in profile.operations:
        return None
    required = (operation, "codepoint") + _concat_requirement(frozen)
    return _make_plan(
        f"{operation}_codepoint", target, frozen, required,
        (f"find bounded numeric {operation} operands for each code point", "apply the arithmetic operation", "convert the result to a character", "concatenate outputs"),
        (f"numeric {operation} and codepoint conversion are allowlisted", "operand literals fall inside the configured range", "concatenation is available for multi-character output"),
    )


def _mixed_plan(target: str, profile: RestrictionProfile) -> TransformationPlan | None:
    steps: list[TransformationStep] = []
    used: list[str] = []
    for character in target:
        if "literal" in profile.operations and character in profile.allowed_characters:
            step = TransformationStep("literal", character, (character,), "use an allowed character")
        elif "case_swap" in profile.operations and character.swapcase() in profile.allowed_characters and character.swapcase() != character:
            step = TransformationStep("case_swap", character, (character.swapcase(),), "swap an allowed counterpart's case")
        elif "codepoint" in profile.operations:
            step = TransformationStep("codepoint", character, (str(ord(character)),), "construct from a code point")
        else:
            return None
        steps.append(step)
        if step.operation not in used:
            used.append(step.operation)
    frozen = tuple(steps)
    if len(frozen) > 1 and "concat" not in profile.operations:
        return None
    if len(used) < 2:
        return None
    required = tuple(used) + _concat_requirement(frozen)
    return _make_plan(
        "mixed_character", target, frozen, required,
        ("choose the cheapest available primitive per target character", "preserve target order", "concatenate the derived characters"),
        ("each selected primitive is allowlisted", "concatenation is available for multi-character output"),
    )


def plan_restricted_text(
    target: object,
    profile: RestrictionProfile,
    *,
    limit: int = MAX_PLANS,
) -> tuple[TransformationPlan, ...]:
    """Return all feasible semantic construction plans in stable cost order."""

    text = _target(target)
    profile.validate()
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PLANS:
        raise RestrictedCharsetInputError(f"limit must be 1..{MAX_PLANS}")
    candidates = (
        _literal_plan(text, profile),
        _case_plan(text, profile),
        _fragment_plan(text, profile),
        _codepoint_plan(text, profile),
        _numeric_plan(text, profile, "add"),
        _numeric_plan(text, profile, "xor"),
        _mixed_plan(text, profile),
    )
    rows = [row for row in candidates if row is not None]
    rows.sort(key=lambda row: (row.cost, row.plan_id))
    return tuple(rows[:limit])


def verify_plan(plan: TransformationPlan) -> bool:
    """Reconstruct a plan with fixed pure operations; never evaluate an expression."""

    if not isinstance(plan, TransformationPlan) or len(plan.steps) > MAX_STEPS:
        return False
    output: list[str] = []
    for step in plan.steps:
        try:
            if step.operation == "literal":
                produced = step.operands[0]
            elif step.operation == "case_swap":
                produced = step.operands[0].swapcase()
            elif step.operation == "fragment_slice":
                _, start, end, fragment = step.operands
                produced = fragment[int(start):int(end)]
            elif step.operation == "codepoint":
                produced = chr(int(step.operands[0]))
            elif step.operation == "add":
                produced = chr(int(step.operands[0]) + int(step.operands[1]))
            elif step.operation == "xor":
                produced = chr(int(step.operands[0]) ^ int(step.operands[1]))
            else:
                return False
        except (IndexError, TypeError, ValueError, OverflowError):
            return False
        if produced != step.output:
            return False
        output.append(produced)
    return "".join(output) == plan.target

