#!/usr/bin/env python3
"""Bounded, deterministic Python-jail candidate and derivation planner.

All values returned here are inert strings.  The module never evaluates,
compiles, imports, deserializes, or executes a candidate.  Expression
candidates are limited to constant output or capability discovery; they never
read a file, spawn a process, open a socket, or call an import.  CPython
bytecode entries are metadata-only plans and contain no code-object bytes.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Iterable, Mapping


MAX_BANNED = 128
MAX_TOKEN_CHARS = 128
MAX_ALLOWED_CHARS = 256
MAX_CANDIDATE_LENGTH = 4096
MAX_CANDIDATES = 32

_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9]{3,31}\Z")
_VERSION_RE = re.compile(r"\A3\.(\d{1,2})(?:\.\d{1,2})?\Z")


class PythonJailInputError(ValueError):
    """A Python-jail profile is malformed or exceeds a fixed cap."""


@dataclass(frozen=True)
class PythonJailProfile:
    builtins_stripped: bool = False
    imports_blocked: bool = False
    underscores_blocked: bool = False
    dunders_blocked: bool = False
    audit_hook: bool = False
    bytecode_allowed: bool = False
    expression_only: bool = True
    attributes_allowed: bool = True
    calls_allowed: bool = True
    comprehensions_allowed: bool = True
    allowed_characters: frozenset[str] | None = None
    banned_characters: frozenset[str] = frozenset()
    banned_tokens: tuple[str, ...] = ()
    python_version: str | None = None
    max_candidate_length: int = 512

    def validate(self) -> None:
        boolean_fields = (
            self.builtins_stripped, self.imports_blocked, self.underscores_blocked,
            self.dunders_blocked, self.audit_hook, self.bytecode_allowed,
            self.expression_only, self.attributes_allowed, self.calls_allowed,
            self.comprehensions_allowed,
        )
        if any(not isinstance(value, bool) for value in boolean_fields):
            raise PythonJailInputError("profile flags must be boolean")
        if self.allowed_characters is not None and not isinstance(
            self.allowed_characters, (set, frozenset, tuple, list)
        ):
            raise PythonJailInputError("allowed_characters must be a bounded character collection")
        if not isinstance(self.banned_characters, (set, frozenset, tuple, list)):
            raise PythonJailInputError("banned_characters must be a bounded character collection")
        if not isinstance(self.banned_tokens, (tuple, list)):
            raise PythonJailInputError("banned_tokens must be a bounded sequence")
        if self.allowed_characters is not None and len(self.allowed_characters) > MAX_ALLOWED_CHARS:
            raise PythonJailInputError("allowed-character cap exceeded")
        if self.allowed_characters is not None and any(
            not isinstance(item, str) or len(item) != 1 for item in self.allowed_characters
        ):
            raise PythonJailInputError("allowed_characters entries must be one character")
        if len(self.banned_characters) > MAX_BANNED or len(self.banned_tokens) > MAX_BANNED:
            raise PythonJailInputError("ban cap exceeded")
        if any(not isinstance(item, str) or len(item) != 1 for item in self.banned_characters):
            raise PythonJailInputError("banned_characters entries must be one character")
        if any(not item or len(item) > MAX_TOKEN_CHARS or "\x00" in item for item in self.banned_tokens):
            raise PythonJailInputError("banned token is empty, overlong, or contains NUL")
        if self.python_version is not None and (
            not isinstance(self.python_version, str) or not _VERSION_RE.fullmatch(self.python_version)
        ):
            raise PythonJailInputError("python_version must look like 3.MINOR or 3.MINOR.PATCH")
        if isinstance(self.max_candidate_length, bool) or not isinstance(self.max_candidate_length, int):
            raise PythonJailInputError("max_candidate_length must be an integer")
        if not 1 <= self.max_candidate_length <= MAX_CANDIDATE_LENGTH:
            raise PythonJailInputError(f"max_candidate_length must be 1..{MAX_CANDIDATE_LENGTH}")


@dataclass(frozen=True)
class PythonJailCandidate:
    candidate_id: str
    kind: str
    value: str
    purpose: str
    expected_observation: str
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    features: tuple[str, ...]
    audit_events: tuple[str, ...]
    violations: tuple[str, ...]
    compatible: bool
    rank: int
    submitted_value: bool
    inert: bool = True
    active_effect: bool = False
    offline: bool = True

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        for key in ("derivation", "preconditions", "features", "audit_events", "violations"):
            row[key] = list(row[key])
        return row


@dataclass(frozen=True)
class _Spec:
    candidate_id: str
    value_template: str
    purpose: str
    expected_template: str
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    features: tuple[str, ...]
    audit_events: tuple[str, ...] = ()
    rank: int = 50
    kind: str = "expression"
    submitted_value: bool = True
    version_family: str | None = None


_SPECS: tuple[_Spec, ...] = (
    _Spec(
        "constant_arithmetic",
        "7*7",
        "confirm expression evaluation with constants only",
        "49",
        ("select two small integer literals", "apply an arithmetic operator", "compare exact numeric output"),
        ("multiplication and integer literals are accepted",),
        ("expression",),
        rank=100,
    ),
    _Spec(
        "marker_literal",
        "'{marker}'",
        "confirm string-literal output without invoking a capability",
        "{marker}",
        ("validate the marker alphabet", "place it in a single-quoted constant", "compare exact marker output"),
        ("string literals and single quotes are accepted",),
        ("expression", "string", "quotes"),
        rank=95,
    ),
    _Spec(
        "marker_concatenation",
        "'{left}'+'{right}'",
        "test constant folding/concatenation without a sensitive operation",
        "{marker}",
        ("split the marker deterministically", "quote both constant halves", "join with the addition operator"),
        ("string literals and string addition are accepted",),
        ("expression", "string", "quotes"),
        rank=90,
    ),
    _Spec(
        "import_name_probe",
        "__import__",
        "observe whether the import builtin name is reachable without calling it",
        "a builtin/function representation or a name error",
        ("reference the capability name", "do not add call parentheses", "classify the saved result"),
        ("builtins remain reachable", "the import name is not filtered"),
        ("expression", "builtin", "import_name", "underscore", "dunder"),
        ("object.__getattr__",),
        rank=65,
    ),
    _Spec(
        "subclasses_discovery",
        "().__class__.__base__.__subclasses__()",
        "enumerate already-loaded class capabilities without importing or invoking a sink",
        "a bounded class list or a policy error",
        ("start from an empty tuple literal", "walk class then base metadata", "request the loaded subclass list"),
        ("attribute access, dunder names, and calls are accepted",),
        ("expression", "attributes", "calls", "underscore", "dunder", "importless"),
        ("object.__getattr__",),
        rank=60,
    ),
    _Spec(
        "function_builtins_discovery",
        "help.__call__.__builtins__",
        "inspect a function-associated builtins mapping without using it",
        "a mapping/object representation or a policy error",
        ("use an already-present global helper", "walk its call method", "observe only the builtins reference"),
        ("help remains in globals", "attribute and dunder access are accepted"),
        ("expression", "attributes", "underscore", "dunder", "global_help"),
        ("object.__getattr__",),
        rank=55,
    ),
    _Spec(
        "underscore_derivation",
        "getattr((),chr(95)*2+'class'+chr(95)*2)",
        "derive a dunder attribute name without literal underscore characters",
        "the tuple class object or a policy error",
        ("derive underscore from code point 95", "repeat it twice around a constant name", "use getattr for lookup"),
        ("getattr and chr are reachable builtins", "calls and string literals are accepted"),
        ("expression", "builtin", "calls", "quotes", "attributes", "derived_dunder"),
        ("object.__getattr__",),
        rank=52,
    ),
    _Spec(
        "importless_warning_class",
        "next(c for c in ().__class__.__base__.__subclasses__() if c.__name__=='catch_warnings')",
        "locate a preloaded warnings class without importing or instantiating it",
        "a class object or a policy error",
        ("enumerate loaded subclasses", "filter by a constant class name", "select the first matching class"),
        ("warnings.catch_warnings is already loaded", "next, comprehensions, attributes, calls, and dunders are accepted"),
        ("expression", "builtin", "calls", "attributes", "comprehension", "underscore", "dunder", "importless"),
        ("object.__getattr__",),
        rank=45,
    ),
    _Spec(
        "bytecode_constant_pre311",
        "R5D_BYTECODE_PLAN|family=cpython_pre311|ops=LOAD_CONST,RETURN_VALUE|constant={marker}",
        "describe a constant-return bytecode experiment without emitting code bytes",
        "metadata plan only; never submit this descriptor",
        ("pin the exact CPython minor version", "derive stack effect for LOAD_CONST then RETURN_VALUE", "defer any CodeType work to reviewed offline Docker tooling"),
        ("bytecode construction is explicitly in scope", "the interpreter is CPython 3.8 through 3.10", "code-object signatures and flags are separately reviewed"),
        ("bytecode", "metadata_only"),
        rank=35,
        kind="bytecode_plan",
        submitted_value=False,
        version_family="pre311",
    ),
    _Spec(
        "bytecode_constant_311plus",
        "R5D_BYTECODE_PLAN|family=cpython_311plus|ops=RESUME,LOAD_CONST,RETURN_VALUE|constant={marker}",
        "describe a 3.11+ constant-return bytecode experiment without emitting code bytes",
        "metadata plan only; never submit this descriptor",
        ("pin the exact CPython minor version", "account for RESUME and inline-cache layout", "derive stack size and exception table metadata", "defer construction to reviewed offline Docker tooling"),
        ("bytecode construction is explicitly in scope", "the interpreter is CPython 3.11 or newer", "minor-version opcode/cache details are separately reviewed"),
        ("bytecode", "metadata_only"),
        rank=35,
        kind="bytecode_plan",
        submitted_value=False,
        version_family="311plus",
    ),
)


def _bool(mapping: Mapping[str, object], name: str, default: bool) -> bool:
    value = mapping.get(name, default)
    if not isinstance(value, bool):
        raise PythonJailInputError(f"{name} must be boolean")
    return value


def _string_sequence(value: object, *, name: str, character_mode: bool = False) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        rows = tuple(value) if character_mode else (value,)
    elif isinstance(value, (list, tuple, set, frozenset)):
        if len(value) > MAX_BANNED:
            raise PythonJailInputError(f"{name} cap exceeded")
        rows = tuple(value)
    else:
        raise PythonJailInputError(f"{name} must be text or a bounded sequence")
    if any(not isinstance(item, str) for item in rows):
        raise PythonJailInputError(f"{name} entries must be text")
    return rows


def profile_from_mapping(mapping: Mapping[str, object]) -> PythonJailProfile:
    if not isinstance(mapping, Mapping) or len(mapping) > 32:
        raise PythonJailInputError("profile must be a small mapping")
    allowed_raw = mapping.get("allowed_characters")
    allowed = None if allowed_raw is None else frozenset(
        _string_sequence(allowed_raw, name="allowed_characters", character_mode=True)
    )
    banned_chars = frozenset(_string_sequence(
        mapping.get("banned_characters", ()), name="banned_characters", character_mode=True
    ))
    banned_tokens = _string_sequence(mapping.get("banned_tokens", ()), name="banned_tokens")
    max_length = mapping.get("max_candidate_length", 512)
    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise PythonJailInputError("max_candidate_length must be an integer")
    version = mapping.get("python_version")
    if version is not None and not isinstance(version, str):
        raise PythonJailInputError("python_version must be text or None")
    profile = PythonJailProfile(
        builtins_stripped=_bool(mapping, "builtins_stripped", False),
        imports_blocked=_bool(mapping, "imports_blocked", False),
        underscores_blocked=_bool(mapping, "underscores_blocked", False),
        dunders_blocked=_bool(mapping, "dunders_blocked", False),
        audit_hook=_bool(mapping, "audit_hook", False),
        bytecode_allowed=_bool(mapping, "bytecode_allowed", False),
        expression_only=_bool(mapping, "expression_only", True),
        attributes_allowed=_bool(mapping, "attributes_allowed", True),
        calls_allowed=_bool(mapping, "calls_allowed", True),
        comprehensions_allowed=_bool(mapping, "comprehensions_allowed", True),
        allowed_characters=allowed,
        banned_characters=banned_chars,
        banned_tokens=banned_tokens,
        python_version=version,
        max_candidate_length=max_length,
    )
    profile.validate()
    return profile


def _version_family(version: str | None) -> str | None:
    if version is None:
        return None
    match = _VERSION_RE.fullmatch(version)
    assert match is not None
    return "311plus" if int(match.group(1)) >= 11 else "pre311"


def _render(spec: _Spec, marker: str) -> tuple[str, str]:
    split = max(1, len(marker) // 2)
    substitutions = {"marker": marker, "left": marker[:split], "right": marker[split:]}
    return spec.value_template.format(**substitutions), spec.expected_template.format(**substitutions)


def _assess(spec: _Spec, value: str, profile: PythonJailProfile) -> tuple[str, ...]:
    violations: list[str] = []
    if len(value) > profile.max_candidate_length:
        violations.append("candidate exceeds profile length cap")
    if spec.submitted_value:
        if profile.allowed_characters is not None:
            disallowed = sorted(set(value).difference(profile.allowed_characters))
            if disallowed:
                violations.append("characters outside allowlist: " + " ".join(repr(item) for item in disallowed))
        present = sorted(character for character in profile.banned_characters if character in value)
        if present:
            violations.append("banned characters present: " + " ".join(repr(item) for item in present))
        tokens = [token for token in profile.banned_tokens if token.casefold() in value.casefold()]
        if tokens:
            violations.append("banned tokens present: " + ", ".join(repr(item) for item in tokens))
        if profile.underscores_blocked and "_" in value:
            violations.append("contains literal underscore")
        if profile.dunders_blocked and re.search(r"__[A-Za-z][A-Za-z0-9_]*__", value):
            violations.append("contains a literal dunder name")
        if profile.dunders_blocked and ("dunder" in spec.features or "derived_dunder" in spec.features):
            violations.append("accesses or derives dunder semantics")
    if profile.builtins_stripped and ("builtin" in spec.features or "global_help" in spec.features):
        violations.append("requires a reachable builtin/global helper")
    if profile.imports_blocked and "import_name" in spec.features:
        violations.append("requires the import capability name")
    if not profile.attributes_allowed and "attributes" in spec.features:
        violations.append("uses attribute access")
    if not profile.calls_allowed and "calls" in spec.features:
        violations.append("uses call syntax")
    if not profile.comprehensions_allowed and "comprehension" in spec.features:
        violations.append("uses a comprehension")
    if profile.expression_only and "statement" in spec.features:
        violations.append("requires statement mode")
    if profile.audit_hook and spec.audit_events:
        violations.append("may emit audited events: " + ", ".join(spec.audit_events))
    if spec.kind == "bytecode_plan":
        if not profile.bytecode_allowed:
            violations.append("bytecode construction is not allowed")
        family = _version_family(profile.python_version)
        if family is None:
            violations.append("exact Python minor version is required")
        elif family != spec.version_family:
            violations.append(f"bytecode plan targets {spec.version_family}, profile is {family}")
    return tuple(violations)


def generate_python_candidates(
    profile: PythonJailProfile,
    *,
    marker: str = "R5DMARKER",
    include_blocked: bool = True,
    limit: int = MAX_CANDIDATES,
) -> tuple[PythonJailCandidate, ...]:
    """Return ranked inert candidate strings and explicit derivations."""

    profile.validate()
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise PythonJailInputError("marker must be 4-32 ASCII alphanumeric characters")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_CANDIDATES:
        raise PythonJailInputError(f"limit must be 1..{MAX_CANDIDATES}")
    rows: list[PythonJailCandidate] = []
    for spec in _SPECS:
        value, expected = _render(spec, marker)
        violations = _assess(spec, value, profile)
        if violations and not include_blocked:
            continue
        rows.append(PythonJailCandidate(
            candidate_id=spec.candidate_id,
            kind=spec.kind,
            value=value,
            purpose=spec.purpose,
            expected_observation=expected,
            derivation=spec.derivation,
            preconditions=spec.preconditions,
            features=spec.features,
            audit_events=spec.audit_events,
            violations=violations,
            compatible=not violations,
            rank=max(0, spec.rank - 12 * len(violations)),
            submitted_value=spec.submitted_value,
        ))
    rows.sort(key=lambda row: (not row.compatible, -row.rank, row.candidate_id))
    return tuple(rows[:limit])


def profile_matrix() -> tuple[tuple[str, PythonJailProfile], ...]:
    """Return canonical profiles for the requested jail archetypes."""

    return (
        ("builtins_stripped", PythonJailProfile(builtins_stripped=True)),
        ("no_import", PythonJailProfile(imports_blocked=True)),
        ("no_underscore", PythonJailProfile(underscores_blocked=True)),
        ("no_dunder", PythonJailProfile(dunders_blocked=True)),
        ("audit_hook", PythonJailProfile(audit_hook=True)),
        ("bytecode_310", PythonJailProfile(bytecode_allowed=True, python_version="3.10")),
        ("bytecode_311", PythonJailProfile(bytecode_allowed=True, python_version="3.11")),
    )

