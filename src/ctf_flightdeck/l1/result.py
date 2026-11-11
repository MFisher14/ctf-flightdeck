"""What an L1 engine reports: a `SolverResult`.

Statuses:
- solved: the engine found the flag and can show why (at least one flag and one piece of
  evidence). It is still only "found": only the platform accepts a flag.
- candidate: one or more flags that may be right.
- none: the engine ran and found nothing.
- unsure: the engine ran but its answer cannot be trusted either way (it crashed, timed
  out, or printed something that is not a result).
- blocked: the engine could not run; `notes` names what is missing.

On the wire a result is one JSON object, {"schema": 1, "status": ..., ...}: a python engine
returns a SolverResult and flightdeck's boot script prints it; an engine in any other
language prints that object as the last non-empty line of its output. Reading one back is
strict (a field this version does not know, another schema, a wrong type: ResultError),
because the line comes from a process that read untrusted challenge data.

This module uses the standard library only and Python 3.8 syntax, so an engine can import
it under whatever python3 the player's PATH (or a lane image) has.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

SCHEMA = 1
STATUSES = ("solved", "candidate", "none", "unsure", "blocked")

_RESULT_KEYS = ("schema", "status", "flags", "evidence", "cost", "engine", "challenge_id", "notes")
_EVIDENCE_KEYS = ("kind", "detail", "path", "offset")
_COST_KEYS = ("seconds", "usd", "tokens")


class ResultError(ValueError):
    """Not a valid SolverResult. The message names the field and the rule."""


@dataclass(frozen=True)
class Evidence:
    """Why a flag is believed: something a human can check."""

    kind: str  # short tag: decode | carve | decompile | oracle | match | ...
    detail: str  # one line a human can check
    path: str | None = None  # artifact path relative to the challenge dir
    offset: int | None = None  # byte offset in path

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise ResultError("evidence.kind must be a non-empty string")
        if not isinstance(self.detail, str):
            raise ResultError("evidence.detail must be a string")
        if self.path is not None and not isinstance(self.path, str):
            raise ResultError("evidence.path must be a string or null")
        if self.offset is not None and not (_is_int(self.offset) and self.offset >= 0):
            raise ResultError("evidence.offset must be a whole number, 0 or more, or null")

    def to_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "path": self.path, "offset": self.offset}

    @classmethod
    def from_dict(cls, d: object) -> Evidence:
        if not isinstance(d, dict):
            raise ResultError("each evidence item must be an object")
        _known("evidence", d, _EVIDENCE_KEYS)
        for key in ("kind", "detail"):
            if key not in d:
                raise ResultError(f"evidence.{key} is missing")
        return cls(d["kind"], d["detail"], d.get("path"), d.get("offset"))


@dataclass(frozen=True)
class Cost:
    """What a run cost. An L1 engine uses no model, so usd and tokens are usually 0."""

    seconds: float = 0.0
    usd: float = 0.0
    tokens: int = 0

    def __post_init__(self) -> None:
        for name in ("seconds", "usd"):
            value = getattr(self, name)
            if not _is_number(value):
                raise ResultError(f"cost.{name} must be a finite number, 0 or more")
            try:
                number = float(value)  # a whole number past 1e308 does not fit: OverflowError
            except OverflowError:
                raise ResultError(f"cost.{name} is too large") from None
            if not (math.isfinite(number) and number >= 0):
                raise ResultError(f"cost.{name} must be a finite number, 0 or more")
            object.__setattr__(self, name, number)
        if not (_is_int(self.tokens) and self.tokens >= 0):
            raise ResultError("cost.tokens must be a whole number, 0 or more")

    def to_dict(self) -> dict:
        return {"seconds": self.seconds, "usd": self.usd, "tokens": self.tokens}

    @classmethod
    def from_dict(cls, d: object) -> Cost:
        if not isinstance(d, dict):
            raise ResultError("cost must be an object")
        _known("cost", d, _COST_KEYS)
        return cls(**d)


@dataclass(frozen=True)
class SolverResult:
    """One engine's answer for one challenge. Lists given for flags or evidence are kept as
    tuples. Breaking a rule raises ResultError."""

    status: str
    flags: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    cost: Cost = field(default_factory=Cost)
    engine: str | None = None
    challenge_id: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, str) or self.status not in STATUSES:
            raise ResultError(f"status must be one of {', '.join(STATUSES)}, not {_short(self.status)}")
        flags = _sequence("flags", self.flags)
        for flag in flags:
            if not isinstance(flag, str) or not flag.strip():
                raise ResultError("flags must be non-empty strings")
        evidence = _sequence("evidence", self.evidence)
        for item in evidence:
            if not isinstance(item, Evidence):
                raise ResultError("evidence items must be Evidence objects")
        object.__setattr__(self, "flags", flags)
        object.__setattr__(self, "evidence", evidence)
        if not isinstance(self.cost, Cost):
            raise ResultError("cost must be a Cost object")
        for name in ("engine", "challenge_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ResultError(f"{name} must be a string or null")
        if not isinstance(self.notes, str):
            raise ResultError("notes must be a string")
        if self.status == "solved" and not (flags and evidence):
            raise ResultError(
                "a solved result needs at least one flag and one piece of evidence "
                "(without evidence, report it as a candidate)"
            )
        if self.status == "candidate" and not flags:
            raise ResultError("a candidate result needs at least one flag")
        if self.status in ("none", "blocked") and flags:
            raise ResultError(f"a {self.status} result carries no flags (report them as a candidate)")
        if self.status == "blocked" and not self.notes.strip():
            raise ResultError("a blocked result needs notes naming what is missing")

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "status": self.status,
            "flags": list(self.flags),
            "evidence": [item.to_dict() for item in self.evidence],
            "cost": self.cost.to_dict(),
            "engine": self.engine,
            "challenge_id": self.challenge_id,
            "notes": self.notes,
        }

    def to_json(self, **kw) -> str:
        """One line of JSON (unless `indent` is passed), ASCII only: every other character
        is escaped, so the line cannot be split by a line separator inside a flag."""
        return json.dumps(self.to_dict(), **kw)

    @classmethod
    def from_dict(cls, d: object) -> SolverResult:
        if not isinstance(d, dict):
            raise ResultError("a result must be a JSON object")
        _known("result", d, _RESULT_KEYS)
        if "schema" not in d:
            raise ResultError(f'"schema" is missing; a result says {{"schema": {SCHEMA}, ...}}')
        schema = d["schema"]
        if not (_is_int(schema) and schema == SCHEMA):
            raise ResultError(f"schema {_short(schema)} is not supported; this flightdeck reads schema {SCHEMA}")
        if "status" not in d:
            raise ResultError('"status" is missing')
        flags = d.get("flags", [])
        if not isinstance(flags, (list, tuple)):
            raise ResultError("flags must be a list of strings")
        evidence = d.get("evidence", [])
        if not isinstance(evidence, (list, tuple)):
            raise ResultError("evidence must be a list of objects")
        return cls(
            status=d["status"],
            flags=tuple(flags),
            evidence=tuple(Evidence.from_dict(item) for item in evidence),
            cost=Cost.from_dict(d["cost"]) if "cost" in d else Cost(),
            engine=d.get("engine"),
            challenge_id=d.get("challenge_id"),
            notes=d.get("notes", ""),
        )

    @classmethod
    def from_json(cls, s: str | bytes) -> SolverResult:
        if isinstance(s, (bytes, bytearray)):
            try:
                s = bytes(s).decode("utf-8")
            except UnicodeDecodeError:
                raise ResultError("a result must be UTF-8 text") from None
        if not isinstance(s, str):
            raise ResultError("a result must be text")
        try:
            data = json.loads(s, object_pairs_hook=_unique, parse_constant=_no_constant)
        except ResultError:
            raise
        except json.JSONDecodeError as exc:
            raise ResultError(f"not JSON ({exc.msg} at column {exc.colno})") from None
        except (ValueError, RecursionError):  # a number too long to convert, or nesting too deep
            raise ResultError("not JSON flightdeck can read (a number too long or nesting too deep)") from None
        return cls.from_dict(data)


# ---------------------------------------------------------------- checks


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _sequence(name: str, value: object) -> tuple:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ResultError(f"{name} must be a list, not {type(value).__name__}")
    return tuple(value)


def _known(where: str, d: dict, known: tuple) -> None:
    unknown = sorted(str(key) for key in d if key not in known)
    if unknown:
        names = ", ".join(_short(key) for key in unknown[:5])
        raise ResultError(f"{where} has unknown field {names} (known: {', '.join(known)})")


def _short(value: object) -> str:
    """A value from untrusted output, shown short and on one line in an error message."""
    text = json.dumps(value, ensure_ascii=True, default=repr) if not isinstance(value, str) else json.dumps(value)
    return text if len(text) <= 40 else text[:37] + "..."


def _unique(pairs: list) -> dict:
    """json object hook: a key given twice is an error (json would keep the last one)."""
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ResultError(f"the field {_short(key)} is given twice")
        out[key] = value
    return out


def _no_constant(name: str) -> object:
    raise ResultError(f"{name} is not a JSON number")
