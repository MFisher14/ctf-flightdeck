"""The secrets a run holds, taken out of a lane's text by value.

A run holds secrets (run.py's _held_secrets: each value in the keys file, the [api] and
[fallback] keys, the CTFd token; a coding-agent lane's own credential too), and a lane can
read them: a host lane the keys file itself, or another process's environment. Secrets
replaces each value with [NAME] in text a lane produced, for both kinds of lane
(agent/driver.py's own lanes: what a tool call gave, before the model or the deck has it;
agent/external.py's: what the CLI wrote). credentials.py's patterns come after, for what
flightdeck keeps: they match the shapes of keys, not their values, so a key in a shape they
do not know is caught only here, and a secret the run does not hold only there.

On the host this is cleanup, not a fence: a lane that has read a key can use it or encode
it. It keeps the value itself out of the model's context and out of every record.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace

from ..core.driver import TurnReport

MIN_SECRET = 8  # a secret shorter than this is not looked for in a lane's text: it would hide too much


class Secrets:
    """Secret values flightdeck knows (a coding agent's own credential above all, which the
    commands it runs can read and print), each replaced by [NAME] in text a lane produced.
    Applied where that text first arrives, before anything cuts it: a key cut in two would
    keep its first part. Never shows a value, in its repr either."""

    def __init__(self, named: Mapping[str, str] | None = None) -> None:
        pairs: dict[str, str] = {}
        for name, value in (named or {}).items():
            if not isinstance(value, str) or len(value) < MIN_SECRET:
                continue
            for form in (value, json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]):  # as JSON writes it
                pairs.setdefault(form, f"[{name}]")
        self.pairs = sorted(pairs.items(), key=lambda pair: -len(pair[0]))  # a longer one first: it may hold a shorter

    def __call__(self, text: str) -> str:
        for value, label in self.pairs:
            if value in text:
                text = text.replace(value, label)
        return text

    def __bool__(self) -> bool:
        return bool(self.pairs)

    def __repr__(self) -> str:
        return f"Secrets({len({label for _, label in self.pairs})} names)"

    def scrub(self, rep: TurnReport) -> TurnReport:
        """`rep` with every secret out of its text (never its flag: that is what would be submitted)."""
        if not self.pairs:
            return rep
        return replace(
            rep,
            action=self(rep.action),
            output=self(rep.output),
            plan=None if rep.plan is None else self(rep.plan),
            gave_up=None if rep.gave_up is None else self(rep.gave_up),
            files=tuple(replace(change, path=self(change.path), diff=self(change.diff)) for change in rep.files),
            artifacts=tuple(self(item) for item in rep.artifacts),
            why=self(rep.why),
        )
