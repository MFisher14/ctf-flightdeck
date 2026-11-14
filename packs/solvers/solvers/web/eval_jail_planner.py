#!/usr/bin/env python3
"""Static candidate planning for eval, calculator, and template-expression jails.

Unlike the SSTI engine catalog, this module emits no template delimiters and
does not fingerprint a renderer.  It models expression grammar restrictions
for Python, JavaScript, Ruby, PHP, calculator, and generic template-expression
contexts.  Candidates are constants or harmless type/length observations and
are never evaluated, compiled, imported, rendered, or executed here.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Mapping


MODES: tuple[str, ...] = (
    "python_eval",
    "javascript_eval",
    "ruby_eval",
    "php_eval",
    "calculator",
    "template_expression",
)
MAX_ITEMS = 128
MAX_ITEM_CHARS = 128
MAX_CANDIDATES = 32
MAX_TEXT_CHARS = 256_000
MAX_TEXT_BYTES = 1_048_576
MAX_CANDIDATE_LENGTH = 2048
_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{3,31}\Z")
_ALIASES = {
    "python": "python_eval", "py": "python_eval",
    "javascript": "javascript_eval", "js": "javascript_eval",
    "ruby": "ruby_eval", "php": "php_eval", "calc": "calculator",
    "template": "template_expression",
}


class EvalJailInputError(ValueError):
    """An eval-jail profile or supplied policy text is malformed/over cap."""


@dataclass(frozen=True)
class EvalJailProfile:
    mode: str
    strings_allowed: bool = True
    calls_allowed: bool = True
    attributes_allowed: bool = True
    indexing_allowed: bool = True
    allowed_operators: frozenset[str] | None = None
    allowed_functions: frozenset[str] | None = None
    allowed_characters: frozenset[str] | None = None
    banned_characters: frozenset[str] = frozenset()
    banned_tokens: tuple[str, ...] = ()
    max_candidate_length: int = 512

    def validate(self) -> None:
        if self.mode not in MODES:
            raise EvalJailInputError(f"unknown mode {self.mode!r}; choose one of: {', '.join(MODES)}")
        if any(not isinstance(value, bool) for value in (
            self.strings_allowed, self.calls_allowed, self.attributes_allowed, self.indexing_allowed
        )):
            raise EvalJailInputError("profile flags must be boolean")
        for name, values in (
            ("allowed_operators", self.allowed_operators),
            ("allowed_functions", self.allowed_functions),
            ("allowed_characters", self.allowed_characters),
        ):
            if values is not None and not isinstance(values, (set, frozenset, tuple, list)):
                raise EvalJailInputError(f"{name} must be a bounded collection")
            if values is not None and len(values) > MAX_ITEMS:
                raise EvalJailInputError(f"{name} cap exceeded")
            if values is not None and any(
                not isinstance(item, str) or not item or len(item) > MAX_ITEM_CHARS for item in values
            ):
                raise EvalJailInputError(f"{name} entries must be bounded non-empty text")
        if self.allowed_characters is not None and any(len(item) != 1 for item in self.allowed_characters):
            raise EvalJailInputError("allowed_characters entries must be single characters")
        if not isinstance(self.banned_characters, (set, frozenset, tuple, list)):
            raise EvalJailInputError("banned_characters must be a bounded collection")
        if not isinstance(self.banned_tokens, (tuple, list)):
            raise EvalJailInputError("banned_tokens must be a bounded sequence")
        if len(self.banned_characters) > MAX_ITEMS or len(self.banned_tokens) > MAX_ITEMS:
            raise EvalJailInputError("ban cap exceeded")
        if any(not isinstance(item, str) or len(item) != 1 for item in self.banned_characters):
            raise EvalJailInputError("banned characters must be single characters")
        if any(not isinstance(item, str) or not item or len(item) > MAX_ITEM_CHARS or "\x00" in item for item in self.banned_tokens):
            raise EvalJailInputError("banned token is empty, overlong, or contains NUL")
        if isinstance(self.max_candidate_length, bool) or not isinstance(self.max_candidate_length, int):
            raise EvalJailInputError("max_candidate_length must be an integer")
        if not 1 <= self.max_candidate_length <= MAX_CANDIDATE_LENGTH:
            raise EvalJailInputError(f"max_candidate_length must be 1..{MAX_CANDIDATE_LENGTH}")


@dataclass(frozen=True)
class EvalCandidate:
    candidate_id: str
    mode: str
    value: str
    purpose: str
    expected_observation: str
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    operators: tuple[str, ...]
    functions: tuple[str, ...]
    features: tuple[str, ...]
    violations: tuple[str, ...]
    compatible: bool
    rank: int
    inert: bool = True
    active_effect: bool = False
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        for key in ("derivation", "preconditions", "operators", "functions", "features", "violations"):
            row[key] = list(row[key])
        return row


@dataclass(frozen=True)
class EvalPolicyFinding:
    category: str
    name: str
    evidence: str
    offset: int
    confidence: str
    implication: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class _Spec:
    mode: str
    candidate_id: str
    template: str
    purpose: str
    expected: str
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    operators: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    features: tuple[str, ...] = ()
    rank: int = 50


def _common(mode: str, concat: str) -> tuple[_Spec, ...]:
    return (
        _Spec(
            mode, "constant_arithmetic", "7*7", "confirm constant arithmetic evaluation", "49",
            ("choose integer literals", "apply multiplication", "compare exact numeric output"),
            ("integer literals and multiplication are accepted",),
            ("*",), rank=100,
        ),
        _Spec(
            mode, "marker_literal", "'{marker}'", "confirm constant string output", "{marker}",
            ("validate marker alphabet", "quote it as a constant", "compare exact marker output"),
            ("single-quoted string literals are accepted",),
            features=("string",), rank=95,
        ),
        _Spec(
            mode, "marker_concatenation", f"'{{left}}'{concat}'{{right}}'",
            "confirm string concatenation without invoking a capability", "{marker}",
            ("split the marker deterministically", "quote both halves", "join with the language concatenation operator"),
            ("string literals and the concatenation operator are accepted",),
            operators=(concat,), features=("string",), rank=90,
        ),
    )


_SPECS: tuple[_Spec, ...] = (
    *_common("python_eval", "+"),
    _Spec(
        "python_eval", "type_name", "type(0).__name__", "observe a constant value's type name", "int",
        ("construct integer zero", "call type", "read only the class name metadata"),
        ("type is allowed", "calls, attributes, and dunder names are allowed"),
        functions=("type",), features=("call", "attribute"), rank=65,
    ),
    _Spec(
        "python_eval", "constant_length", "len((1,2,3))", "observe constant tuple length", "3",
        ("construct a constant tuple", "call the pure length builtin", "compare exact integer output"),
        ("len and calls are allowed",), functions=("len",), features=("call",), rank=70,
    ),
    *_common("javascript_eval", "+"),
    _Spec(
        "javascript_eval", "constructor_name", "({{}}).constructor.name", "observe the constant object's constructor name", "Object",
        ("construct an empty object literal", "read constructor metadata", "read its name"),
        ("object literals and property access are allowed",), features=("attribute",), rank=65,
    ),
    _Spec(
        "javascript_eval", "constant_length", "[1,2,3].length", "observe constant array length", "3",
        ("construct a constant array", "read its length property"),
        ("array literals and property access are allowed",), features=("attribute", "indexing"), rank=70,
    ),
    *_common("ruby_eval", "+"),
    _Spec(
        "ruby_eval", "class_name", "1.class.name", "observe a constant value's class name", "Integer",
        ("construct integer one", "read class metadata", "read the class name"),
        ("method/property access is allowed",), features=("attribute",), rank=65,
    ),
    _Spec(
        "ruby_eval", "constant_length", "[1,2,3].length", "observe constant array length", "3",
        ("construct a constant array", "read its length"),
        ("array literals and method access are allowed",), features=("attribute", "indexing"), rank=70,
    ),
    *_common("php_eval", "."),
    _Spec(
        "php_eval", "type_name", "gettype(1)", "observe a constant value's type name", "integer",
        ("construct integer one", "call the type-inspection function", "compare its constant result"),
        ("gettype and function calls are allowed",), functions=("gettype",), features=("call",), rank=65,
    ),
    _Spec(
        "php_eval", "constant_count", "count([1,2,3])", "observe constant array count", "3",
        ("construct a constant array", "call count", "compare exact integer output"),
        ("count, calls, and array literals are allowed",), functions=("count",), features=("call", "indexing"), rank=70,
    ),
    _Spec(
        "calculator", "constant_arithmetic", "7*7", "confirm multiplication", "49",
        ("choose integer literals", "apply multiplication", "compare exact numeric output"),
        ("multiplication is allowed",), operators=("*",), rank=100,
    ),
    _Spec(
        "calculator", "precedence_probe", "(7+2)*5", "measure parentheses and operator precedence", "45",
        ("construct a parenthesized addition", "multiply the result", "compare exact numeric output"),
        ("parentheses, addition, and multiplication are allowed",), operators=("+", "*"), rank=85,
    ),
    _Spec(
        "calculator", "sqrt_probe", "sqrt(81)", "test an allowlisted pure math function", "9",
        ("choose a perfect-square constant", "call sqrt", "compare exact numeric output"),
        ("sqrt and calls are allowed",), functions=("sqrt",), features=("call",), rank=75,
    ),
    _Spec(
        "calculator", "sin_zero_probe", "sin(0)", "test a second pure math function", "0",
        ("choose zero", "call sin", "compare exact numeric output"),
        ("sin and calls are allowed",), functions=("sin",), features=("call",), rank=70,
    ),
    _Spec(
        "template_expression", "constant_arithmetic", "7*7", "confirm expression-body arithmetic without delimiters", "49",
        ("omit all template delimiters", "use constant multiplication", "compare exact numeric output"),
        ("the challenge already places input inside an expression body", "multiplication is accepted"),
        operators=("*",), rank=100,
    ),
    _Spec(
        "template_expression", "constant_addition", "7+42", "distinguish arithmetic from literal reflection", "49",
        ("omit all renderer-specific delimiters", "add two constants", "compare exact numeric output"),
        ("the challenge places input inside an expression body", "addition is accepted"),
        operators=("+",), rank=90,
    ),
    _Spec(
        "template_expression", "marker_literal", "'{marker}'", "confirm a constant expression string", "{marker}",
        ("omit renderer-specific delimiters", "quote a validated marker", "compare exact marker output"),
        ("the challenge places input inside an expression body", "string constants are accepted"),
        features=("string",), rank=80,
    ),
)


_POLICY_PATTERNS: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
    ("sink", "python_eval", "high", "Python eval/exec-style evaluation is referenced; globals/builtins and AST policy need inspection.", re.compile(r"(?i)\b(?:eval|exec)\s*\(")),
    ("sink", "literal_eval", "medium", "ast.literal_eval accepts literals only and should be treated differently from general eval.", re.compile(r"\bast\.literal_eval\s*\(")),
    ("sink", "javascript_function", "high", "JavaScript Function/eval construction is referenced.", re.compile(r"(?i)\b(?:eval|Function)\s*\(")),
    ("sink", "ruby_eval", "high", "Ruby eval/instance_eval-style evaluation is referenced.", re.compile(r"\b(?:eval|instance_eval|class_eval)\b")),
    ("sink", "php_eval", "high", "PHP eval/assert-style evaluation is referenced.", re.compile(r"(?i)\b(?:eval|assert)\s*\(")),
    ("calculator", "math_parser", "medium", "A calculator/expression library is referenced; inspect its exact grammar and function table.", re.compile(r"(?i)\b(?:numexpr|asteval|simpleeval|mathjs|expr-eval|muparser)\b")),
    ("policy", "allowlist", "medium", "An explicit operator/function allowlist is present and should drive candidate compatibility.", re.compile(r"(?i)\b(?:allowed_(?:functions|operators)|function_allowlist|operator_allowlist|whitelist)\b")),
    ("policy", "denylist", "medium", "A token denylist is present; it is evidence, not proof of the parser grammar.", re.compile(r"(?i)\b(?:banned_tokens|blacklist|denylist|forbidden)\b")),
)


def normalize_mode(mode: str) -> str:
    if not isinstance(mode, str):
        raise EvalJailInputError("mode must be text")
    name = _ALIASES.get(mode.strip().lower(), mode.strip().lower())
    if name not in MODES:
        raise EvalJailInputError(f"unknown mode {mode!r}; choose one of: {', '.join(MODES)}")
    return name


def _bounded_set(value: object, *, name: str, character_mode: bool = False) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        rows = tuple(value) if character_mode else (value,)
    elif isinstance(value, (list, tuple, set, frozenset)):
        rows = tuple(value)
    else:
        raise EvalJailInputError(f"{name} must be text or a bounded sequence")
    if len(rows) > MAX_ITEMS or any(not isinstance(item, str) or not item or len(item) > MAX_ITEM_CHARS for item in rows):
        raise EvalJailInputError(f"{name} contains invalid or too many entries")
    if character_mode and any(len(item) != 1 for item in rows):
        raise EvalJailInputError(f"{name} entries must be single characters")
    return frozenset(rows)


def _bool(mapping: Mapping[str, object], name: str, default: bool) -> bool:
    value = mapping.get(name, default)
    if not isinstance(value, bool):
        raise EvalJailInputError(f"{name} must be boolean")
    return value


def profile_from_mapping(mapping: Mapping[str, object]) -> EvalJailProfile:
    if not isinstance(mapping, Mapping) or len(mapping) > 32:
        raise EvalJailInputError("profile must be a small mapping")
    banned_tokens = _bounded_set(mapping.get("banned_tokens", ()), name="banned_tokens") or frozenset()
    max_length = mapping.get("max_candidate_length", 512)
    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise EvalJailInputError("max_candidate_length must be an integer")
    mode = mapping.get("mode", "calculator")
    if not isinstance(mode, str):
        raise EvalJailInputError("mode must be text")
    profile = EvalJailProfile(
        mode=normalize_mode(mode),
        strings_allowed=_bool(mapping, "strings_allowed", True),
        calls_allowed=_bool(mapping, "calls_allowed", True),
        attributes_allowed=_bool(mapping, "attributes_allowed", True),
        indexing_allowed=_bool(mapping, "indexing_allowed", True),
        allowed_operators=_bounded_set(mapping.get("allowed_operators"), name="allowed_operators"),
        allowed_functions=_bounded_set(mapping.get("allowed_functions"), name="allowed_functions"),
        allowed_characters=_bounded_set(mapping.get("allowed_characters"), name="allowed_characters", character_mode=True),
        banned_characters=_bounded_set(mapping.get("banned_characters", ()), name="banned_characters", character_mode=True) or frozenset(),
        banned_tokens=tuple(sorted(banned_tokens)),
        max_candidate_length=max_length,
    )
    profile.validate()
    return profile


def _render(spec: _Spec, marker: str) -> tuple[str, str]:
    split = max(1, len(marker) // 2)
    values = {"marker": marker, "left": marker[:split], "right": marker[split:]}
    return spec.template.format(**values), spec.expected.format(**values)


def _assess(spec: _Spec, value: str, profile: EvalJailProfile) -> tuple[str, ...]:
    violations: list[str] = []
    if len(value) > profile.max_candidate_length:
        violations.append("candidate exceeds profile length cap")
    if profile.allowed_characters is not None:
        outside = sorted(set(value).difference(profile.allowed_characters))
        if outside:
            violations.append("characters outside allowlist: " + " ".join(repr(item) for item in outside))
    present = sorted(item for item in profile.banned_characters if item in value)
    if present:
        violations.append("banned characters present: " + " ".join(repr(item) for item in present))
    tokens = [item for item in profile.banned_tokens if item.casefold() in value.casefold()]
    if tokens:
        violations.append("banned tokens present: " + ", ".join(repr(item) for item in tokens))
    if not profile.strings_allowed and "string" in spec.features:
        violations.append("uses a string literal")
    if not profile.calls_allowed and "call" in spec.features:
        violations.append("uses a function call")
    if not profile.attributes_allowed and "attribute" in spec.features:
        violations.append("uses attribute/property access")
    if not profile.indexing_allowed and "indexing" in spec.features:
        violations.append("uses an array/tuple literal or indexing surface")
    if profile.allowed_operators is not None:
        missing = [item for item in spec.operators if item not in profile.allowed_operators]
        if missing:
            violations.append("operators outside allowlist: " + ", ".join(missing))
    if profile.allowed_functions is not None:
        missing = [item for item in spec.functions if item not in profile.allowed_functions]
        if missing:
            violations.append("functions outside allowlist: " + ", ".join(missing))
    return tuple(violations)


def generate_eval_candidates(
    profile: EvalJailProfile,
    *,
    marker: str = "R5D_MARKER",
    include_blocked: bool = True,
    limit: int = MAX_CANDIDATES,
) -> tuple[EvalCandidate, ...]:
    profile.validate()
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise EvalJailInputError("marker must be 4-32 letters, digits, or underscores")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_CANDIDATES:
        raise EvalJailInputError(f"limit must be 1..{MAX_CANDIDATES}")
    rows: list[EvalCandidate] = []
    for spec in _SPECS:
        if spec.mode != profile.mode:
            continue
        value, expected = _render(spec, marker)
        violations = _assess(spec, value, profile)
        if violations and not include_blocked:
            continue
        rows.append(EvalCandidate(
            candidate_id=spec.candidate_id,
            mode=profile.mode,
            value=value,
            purpose=spec.purpose,
            expected_observation=expected,
            derivation=spec.derivation,
            preconditions=spec.preconditions,
            operators=spec.operators,
            functions=spec.functions,
            features=spec.features,
            violations=violations,
            compatible=not violations,
            rank=max(0, spec.rank - 12 * len(violations)),
        ))
    rows.sort(key=lambda row: (not row.compatible, -row.rank, row.candidate_id))
    return tuple(rows[:limit])


def analyze_eval_policy(saved_text: str | bytes | bytearray) -> tuple[EvalPolicyFinding, ...]:
    if isinstance(saved_text, str):
        text = saved_text
    elif isinstance(saved_text, (bytes, bytearray)):
        raw = bytes(saved_text)
        if len(raw) > MAX_TEXT_BYTES:
            raise EvalJailInputError(f"saved_text exceeds {MAX_TEXT_BYTES} bytes")
        text = raw.decode("utf-8", "replace")
    else:
        raise EvalJailInputError("saved_text must be text or bytes")
    if len(text) > MAX_TEXT_CHARS:
        raise EvalJailInputError(f"saved_text exceeds {MAX_TEXT_CHARS} characters")
    rows: list[EvalPolicyFinding] = []
    for category, name, confidence, implication, pattern in _POLICY_PATTERNS:
        match = pattern.search(text)
        if match:
            rows.append(EvalPolicyFinding(
                category=category,
                name=name,
                evidence=text[max(0, match.start() - 48):min(len(text), match.end() + 96)],
                offset=match.start(),
                confidence=confidence,
                implication=implication,
            ))
    rows.sort(key=lambda row: (row.offset, row.category, row.name))
    return tuple(rows)

