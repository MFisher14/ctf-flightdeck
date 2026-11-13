#!/usr/bin/env python3
"""Offline rbash/shell-restriction candidate planner.

Candidates only print a validated marker or inspect shell builtin availability;
none read files, change directories, launch a shell, contact a network, or
invoke an external utility.  They are returned as inert strings and are never
passed to a shell or process API by this module.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Mapping


MAX_BANS = 128
MAX_TOKEN = 128
MAX_CANDIDATES = 32
MAX_CANDIDATE_LENGTH = 2048
_MARKER_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{3,31}\Z")


class ShellJailInputError(ValueError):
    """A shell profile or output request is malformed or over cap."""


@dataclass(frozen=True)
class ShellJailProfile:
    rbash: bool = False
    no_space: bool = False
    no_slash: bool = False
    parameter_expansion: bool = True
    brace_expansion: bool = True
    globbing: bool = True
    input_redirection: bool = True
    command_substitution: bool = False
    builtins_only: bool = True
    allowed_characters: frozenset[str] | None = None
    banned_characters: frozenset[str] = frozenset()
    banned_tokens: tuple[str, ...] = ()
    max_candidate_length: int = 512

    def validate(self) -> None:
        boolean_fields = (
            self.rbash, self.no_space, self.no_slash, self.parameter_expansion,
            self.brace_expansion, self.globbing, self.input_redirection,
            self.command_substitution, self.builtins_only,
        )
        if any(not isinstance(value, bool) for value in boolean_fields):
            raise ShellJailInputError("profile flags must be boolean")
        if self.allowed_characters is not None and not isinstance(
            self.allowed_characters, (set, frozenset, tuple, list)
        ):
            raise ShellJailInputError("allowed characters must be a bounded collection")
        if not isinstance(self.banned_characters, (set, frozenset, tuple, list)):
            raise ShellJailInputError("banned characters must be a bounded collection")
        if not isinstance(self.banned_tokens, (tuple, list)):
            raise ShellJailInputError("banned_tokens must be a bounded sequence")
        if self.allowed_characters is not None and len(self.allowed_characters) > 256:
            raise ShellJailInputError("allowed-character cap exceeded")
        if self.allowed_characters is not None and any(
            not isinstance(item, str) or len(item) != 1 for item in self.allowed_characters
        ):
            raise ShellJailInputError("allowed characters must be single characters")
        if len(self.banned_characters) > MAX_BANS or len(self.banned_tokens) > MAX_BANS:
            raise ShellJailInputError("ban cap exceeded")
        if any(not isinstance(item, str) or len(item) != 1 for item in self.banned_characters):
            raise ShellJailInputError("banned characters must be single characters")
        if any(not isinstance(item, str) or not item or len(item) > MAX_TOKEN or "\x00" in item for item in self.banned_tokens):
            raise ShellJailInputError("banned token is empty, overlong, or contains NUL")
        if isinstance(self.max_candidate_length, bool) or not isinstance(self.max_candidate_length, int):
            raise ShellJailInputError("max_candidate_length must be an integer")
        if not 1 <= self.max_candidate_length <= MAX_CANDIDATE_LENGTH:
            raise ShellJailInputError(f"max_candidate_length must be 1..{MAX_CANDIDATE_LENGTH}")


@dataclass(frozen=True)
class ShellJailCandidate:
    candidate_id: str
    value: str
    purpose: str
    expected_observation: str
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    features: tuple[str, ...]
    violations: tuple[str, ...]
    compatible: bool
    rank: int
    effect: str
    inert: bool = True
    offline: bool = True
    process_invoked: bool = False

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        for key in ("derivation", "preconditions", "features", "violations"):
            row[key] = list(row[key])
        return row


@dataclass(frozen=True)
class _Spec:
    candidate_id: str
    template: str
    purpose: str
    expected: str
    derivation: tuple[str, ...]
    preconditions: tuple[str, ...]
    features: tuple[str, ...]
    rank: int
    effect: str = "marker_output_only"


_SPECS: tuple[_Spec, ...] = (
    _Spec(
        "literal_space_marker",
        "printf %s {marker}",
        "baseline marker output using a literal argument separator",
        "{marker}",
        ("select the printf shell builtin", "separate format and marker with spaces", "compare exact marker output"),
        ("printf is available as a shell builtin", "literal spaces are accepted"),
        ("builtin", "space"),
        100,
    ),
    _Spec(
        "ifs_marker",
        "printf${{IFS}}%s${{IFS}}{marker}",
        "replace literal spaces with field-separator expansion",
        "{marker}",
        ("start from the baseline builtin invocation", "replace each separator with ${IFS}", "retain a constant marker argument"),
        ("parameter expansion is enabled", "IFS contains a splitting character", "printf is a builtin"),
        ("builtin", "parameter_expansion", "ifs", "no_literal_space"),
        95,
    ),
    _Spec(
        "brace_marker",
        "{{printf,%s,{marker}}}",
        "use brace expansion to create builtin arguments without spaces",
        "{marker}",
        ("place command and arguments in one brace list", "let brace expansion create words", "invoke only the printf builtin"),
        ("brace expansion occurs before command execution", "printf is a builtin"),
        ("builtin", "brace_expansion", "no_literal_space"),
        90,
    ),
    _Spec(
        "herestring_marker",
        "read<<<{marker}",
        "feed a constant marker to the read builtin without a space",
        "read stores the marker in REPLY and produces no external effect",
        ("select the read builtin", "attach a here-string redirection", "store the constant marker in REPLY"),
        ("Bash-style here strings and input redirection are enabled", "read is a builtin"),
        ("builtin", "input_redirection", "no_literal_space"),
        80,
        "shell_variable_only",
    ),
    _Spec(
        "slash_from_path",
        "printf${{IFS}}%s${{IFS}}${{PATH:0:1}}",
        "derive a slash character from PATH without a literal slash",
        "/ when PATH begins with slash",
        ("take the first character of PATH", "pass it to the printf builtin", "observe whether it is a slash"),
        ("Bash substring expansion is enabled", "PATH begins with slash", "parameter expansion is enabled"),
        ("builtin", "parameter_expansion", "ifs", "slash_derivation", "no_literal_space", "no_literal_slash"),
        75,
        "capability_discovery",
    ),
    _Spec(
        "glob_marker",
        "printf${{IFS}}%s${{IFS}}{prefix}?",
        "test whether one wildcard can synthesize a restricted final character",
        "a unique matching name or the literal pattern",
        ("retain an allowed marker prefix", "replace the final character with one question-mark glob", "print the expansion through a builtin"),
        ("globbing is enabled", "the intended expansion is unique in the current directory", "parameter expansion is enabled for separators"),
        ("builtin", "parameter_expansion", "ifs", "globbing", "no_literal_space"),
        65,
        "directory_name_discovery",
    ),
    _Spec(
        "nested_builtin_marker",
        "printf${{IFS}}%s${{IFS}}$(printf${{IFS}}{marker})",
        "derive the marker through builtin-only command substitution",
        "{marker}",
        ("run an inner printf builtin", "capture its constant output", "pass it to an outer printf builtin"),
        ("command substitution and parameter expansion are enabled", "both printf resolutions are builtins"),
        ("builtin", "parameter_expansion", "ifs", "command_substitution", "no_literal_space"),
        55,
    ),
    _Spec(
        "rbash_builtin_lookup",
        "command${{IFS}}-v${{IFS}}printf",
        "inspect builtin resolution without executing an external program",
        "the resolution/type of printf",
        ("use the command shell builtin", "supply -v through IFS separators", "query only the printf name"),
        ("command and printf are shell builtins", "parameter expansion is enabled"),
        ("builtin", "parameter_expansion", "ifs", "no_literal_space", "rbash_safe_lookup"),
        70,
        "capability_discovery",
    ),
    _Spec(
        "rbash_type_lookup",
        "type${{IFS}}-a${{IFS}}printf",
        "inspect all shell resolutions for a harmless builtin name",
        "the available printf resolutions",
        ("use the type shell builtin", "request all resolutions", "do not execute any returned path"),
        ("type is a shell builtin", "parameter expansion is enabled"),
        ("builtin", "parameter_expansion", "ifs", "no_literal_space", "rbash_safe_lookup"),
        68,
        "capability_discovery",
    ),
)


def _bool(mapping: Mapping[str, object], name: str, default: bool) -> bool:
    value = mapping.get(name, default)
    if not isinstance(value, bool):
        raise ShellJailInputError(f"{name} must be boolean")
    return value


def _characters(value: object, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        rows = tuple(value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        rows = tuple(value)
    else:
        raise ShellJailInputError(f"{name} must be text or a bounded sequence")
    if len(rows) > 256 or any(not isinstance(item, str) or len(item) != 1 for item in rows):
        raise ShellJailInputError(f"{name} must contain at most 256 single characters")
    return frozenset(rows)


def _tokens(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    rows = (value,) if isinstance(value, str) else tuple(value) if isinstance(value, (list, tuple)) else None
    if rows is None or len(rows) > MAX_BANS or any(not isinstance(item, str) for item in rows):
        raise ShellJailInputError("banned_tokens must be bounded text")
    return rows


def profile_from_mapping(mapping: Mapping[str, object]) -> ShellJailProfile:
    if not isinstance(mapping, Mapping) or len(mapping) > 32:
        raise ShellJailInputError("profile must be a small mapping")
    allowed_raw = mapping.get("allowed_characters")
    allowed = None if allowed_raw is None else _characters(allowed_raw, "allowed_characters")
    max_length = mapping.get("max_candidate_length", 512)
    if isinstance(max_length, bool) or not isinstance(max_length, int):
        raise ShellJailInputError("max_candidate_length must be an integer")
    profile = ShellJailProfile(
        rbash=_bool(mapping, "rbash", False),
        no_space=_bool(mapping, "no_space", False),
        no_slash=_bool(mapping, "no_slash", False),
        parameter_expansion=_bool(mapping, "parameter_expansion", True),
        brace_expansion=_bool(mapping, "brace_expansion", True),
        globbing=_bool(mapping, "globbing", True),
        input_redirection=_bool(mapping, "input_redirection", True),
        command_substitution=_bool(mapping, "command_substitution", False),
        builtins_only=_bool(mapping, "builtins_only", True),
        allowed_characters=allowed,
        banned_characters=_characters(mapping.get("banned_characters"), "banned_characters"),
        banned_tokens=_tokens(mapping.get("banned_tokens")),
        max_candidate_length=max_length,
    )
    profile.validate()
    return profile


def _assess(spec: _Spec, value: str, profile: ShellJailProfile) -> tuple[str, ...]:
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
    if profile.no_space and " " in value:
        violations.append("contains a literal space")
    if profile.no_slash and "/" in value:
        violations.append("contains a literal slash")
    feature_policy = (
        ("parameter_expansion", profile.parameter_expansion),
        ("brace_expansion", profile.brace_expansion),
        ("globbing", profile.globbing),
        ("input_redirection", profile.input_redirection),
        ("command_substitution", profile.command_substitution),
    )
    for feature, enabled in feature_policy:
        if feature in spec.features and not enabled:
            violations.append(f"requires disabled {feature}")
    if profile.builtins_only and "builtin" not in spec.features:
        violations.append("may resolve an external command")
    if profile.rbash and "rbash_unsafe" in spec.features:
        violations.append("blocked by restricted-shell policy")
    return tuple(violations)


def generate_shell_candidates(
    profile: ShellJailProfile,
    *,
    marker: str = "R5D_MARKER",
    include_blocked: bool = True,
    limit: int = MAX_CANDIDATES,
) -> tuple[ShellJailCandidate, ...]:
    profile.validate()
    if not isinstance(marker, str) or not _MARKER_RE.fullmatch(marker):
        raise ShellJailInputError("marker must be 4-32 letters, digits, or underscores")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_CANDIDATES:
        raise ShellJailInputError(f"limit must be 1..{MAX_CANDIDATES}")
    prefix = marker[:-1] if len(marker) > 1 else marker
    rows: list[ShellJailCandidate] = []
    for spec in _SPECS:
        value = spec.template.format(marker=marker, prefix=prefix)
        expected = spec.expected.format(marker=marker)
        violations = _assess(spec, value, profile)
        if violations and not include_blocked:
            continue
        rows.append(ShellJailCandidate(
            candidate_id=spec.candidate_id,
            value=value,
            purpose=spec.purpose,
            expected_observation=expected,
            derivation=spec.derivation,
            preconditions=spec.preconditions,
            features=spec.features,
            violations=violations,
            compatible=not violations,
            rank=max(0, spec.rank - 12 * len(violations)),
            effect=spec.effect,
        ))
    rows.sort(key=lambda row: (not row.compatible, -row.rank, row.candidate_id))
    return tuple(rows[:limit])


def rbash_profile(*, no_space: bool = False, no_slash: bool = True) -> ShellJailProfile:
    """Canonical restricted-Bash review profile."""

    return ShellJailProfile(
        rbash=True,
        no_space=no_space,
        no_slash=no_slash,
        parameter_expansion=True,
        brace_expansion=True,
        globbing=True,
        input_redirection=True,
        command_substitution=False,
        builtins_only=True,
    )

