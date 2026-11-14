"""What every engine returns: one SolverResult, serialisable to JSON.

    from ctf.result import SolverResult, Evidence, Cost
    r = SolverResult(status="solved", flags=["CSCTF{x}"],
                     evidence=[Evidence("decode", "base64 of files/a.txt line 3", path="files/a.txt")],
                     engine="warmups.crib_decode", challenge_id="12")
    s = r.to_json(); SolverResult.from_json(s) == r

Status vocabulary (B-172 builds the agent-facing contract on it):
  solved     the engine recovered a value in the event flag format, backed by evidence from the
             artifact. This is "flag found", NOT "accepted": acceptance is only ever a platform
             SubmitResult (ctf.platform.base). Needs >= 1 flag and >= 1 evidence item.
  candidate  plausible value(s) not proven (variant, partial decode, format mismatch). Needs >= 1 flag.
  none       the engine ran to completion and found nothing. No flags.
  unsure     the engine ran but cannot tell (ambiguous output, needs a human/model read). Flags optional.
  blocked    the engine could not run (missing tool, pack, corpus, permission). No flags; `notes`
             must say what is missing (no silent fallbacks).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA = 1
STATUSES = ("solved", "candidate", "none", "unsure", "blocked")


class ResultError(ValueError):
    pass


@dataclass(frozen=True)
class Evidence:
    kind: str                 # short tag: decode | carve | decompile | oracle | wire | match | ...
    detail: str               # one line a human can check
    path: str | None = None   # artifact path relative to the challenge dir, when there is one
    offset: int | None = None # byte offset in `path`, when meaningful


@dataclass(frozen=True)
class Cost:
    seconds: float = 0.0
    usd: float = 0.0
    tokens: int = 0


@dataclass(frozen=True)
class SolverResult:
    status: str
    flags: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    cost: Cost = field(default_factory=Cost)
    engine: str | None = None
    challenge_id: str | None = None
    notes: str = ""

    def __post_init__(self):
        object.__setattr__(self, "flags", tuple(self.flags))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        if self.status not in STATUSES:
            raise ResultError(f"status must be one of {', '.join(STATUSES)}; got {self.status!r}")
        if not all(isinstance(f, str) and f for f in self.flags):
            raise ResultError("flags must be non-empty strings")
        if not all(isinstance(e, Evidence) for e in self.evidence):
            raise ResultError("evidence items must be Evidence")
        if self.status == "solved" and not (self.flags and self.evidence):
            raise ResultError("status 'solved' needs at least one flag and one evidence item")
        if self.status == "candidate" and not self.flags:
            raise ResultError("status 'candidate' needs at least one flag")
        if self.status in ("none", "blocked") and self.flags:
            raise ResultError(f"status {self.status!r} carries no flags")
        if self.status == "blocked" and not self.notes.strip():
            raise ResultError("status 'blocked' needs notes naming what is missing")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["flags"] = list(self.flags)
        d["evidence"] = [asdict(e) for e in self.evidence]
        return {"schema": SCHEMA, **d}

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(), **kw)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SolverResult":
        if not isinstance(d, dict):
            raise ResultError("a result must be a JSON object")
        d = dict(d)
        if d.pop("schema", None) != SCHEMA:
            raise ResultError(f"unsupported result schema (want {SCHEMA})")
        known = {"status", "flags", "evidence", "cost", "engine", "challenge_id", "notes"}
        extra = set(d) - known
        if extra:
            raise ResultError(f"unknown result field(s): {', '.join(sorted(extra))}")
        try:
            ev = tuple(Evidence(**e) for e in d.pop("evidence", []))
            cost = Cost(**d.pop("cost", {}))
        except TypeError as e:
            raise ResultError(f"bad evidence/cost: {e}") from None
        return cls(evidence=ev, cost=cost, **d)

    @classmethod
    def from_json(cls, s: str | bytes) -> "SolverResult":
        try:
            return cls.from_dict(json.loads(s))
        except json.JSONDecodeError as e:
            raise ResultError(f"not JSON: {e}") from None
