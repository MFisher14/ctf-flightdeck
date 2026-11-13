"""Timestamped stage events for the event ledger (B-101), so a wave's second-by-second ledger is
generated from what the tools wrote, not reconstructed from raw logs afterwards.

    from ctf import stages
    stages.mark("claim", challenge_id="12", by="dispatcher")
    stages.record_wave(["11", "12"], label="W2", announced=1730000000.0)   # `ctf wait` calls this
    stages.try_mark("intake_start", challenge_id="12")                     # from a live path

The stages (STAGES) and who writes them today:

    wave_open     {wave, count, announced?}   `ctf wait` when the board opens (record_wave)
    detect        {challenge_id, wave}        `ctf wait`: every listed challenge not detected before
    claim         {challenge_id, by?}         a dispatcher / orchestrator (`ctf ledger mark claim`)
    intake_start  {challenge_id}              `ctf pull`
    intake_done   {challenge_id, ok}          `ctf pull`
    first_tool    {challenge_id, by, tool?}   the agent launchers (AgentStreamTap); engine runs are
                                              read from engine.run instead
    candidate     {challenge_id, by, flag_sha256?}  the launchers (a flag-format value in the agent's
                                              output); engine runs with status solved/candidate
    submit / accepted / rejected              read from platform.submit (the submit gate); `mark`
                                              covers paths outside it

Other records the replay reads as stages: agent_launch (tools/launch_gate.py), engine.run
(ctf/engines/runner.py), platform.submit (ctf/platform/rules.py). ctf/replay.py turns all of them
into the wave ledger; `python -m ctf ledger replay` prints it.

Spend categories (SPEND_CATEGORIES) follow the token efficiency plan's split of the money: a `spend`
record may carry `category`; challenge spend without one is "solve". record_spend() writes spend
that belongs to no challenge (build, verify, doc, orchestration); challenge spend goes through the
budget meter (ctf.budget.LedgerMeter.add_spend) so the cap is checked.

A flag value is never written here: a candidate carries only the SHA-256 of the normalized flag.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

from . import ledger

STAGES = ("wave_open", "detect", "claim", "intake_start", "intake_done", "first_tool", "candidate",
          "submit", "accepted", "rejected")
SPEND_CATEGORIES = ("solve", "build", "verify", "doc", "orchestrate", "guardian", "other")

# Codex `exec --json` item types that are tool calls (agent_message / reasoning / todo_list are not).
CODEX_TOOL_ITEMS = frozenset({"command_execution", "file_change", "mcp_tool_call", "web_search"})

_notified: set[str] = set()


class StageError(ValueError):
    """A stage event that cannot be recorded as asked (unknown stage, missing challenge id)."""


def _cid(challenge_id) -> str:
    if challenge_id is None or not str(challenge_id).strip():
        raise StageError("this stage needs a challenge id")
    return str(challenge_id).strip()


def mark(stage: str, challenge_id: str | None = None, *, workdir: Path | None = None, **fields: Any) -> dict:
    """Append one stage event. wave_open needs `wave`; every other stage needs a challenge id."""
    if stage not in STAGES:
        raise StageError(f"unknown stage {stage!r}; stages are: {', '.join(STAGES)}")
    if stage == "wave_open":
        if challenge_id is not None:
            raise StageError("wave_open is for the whole board, not one challenge")
        if not str(fields.get("wave") or "").strip():
            raise StageError("wave_open needs a wave label (wave=...)")
        return ledger.append(stage, workdir=workdir, **fields)
    return ledger.append(stage, workdir=workdir, challenge_id=_cid(challenge_id), **fields)


def try_mark(stage: str, challenge_id: str | None = None, *, workdir: Path | None = None,
             err=None, **fields: Any) -> dict | None:
    """mark() for a live path (wait, pull) that must not fail because the ledger cannot be written:
    when no workdir resolves, or the write fails, say so on stderr (once per reason per process)
    and return None. A bad stage or a missing challenge id is a programming error and still raises."""
    from .event import EventError
    try:
        return mark(stage, challenge_id, workdir=workdir, **fields)
    except StageError:
        raise
    except (EventError, OSError) as e:
        _notice(f"ctf: stage {stage!r} not recorded in the ledger: {e} "
                "(set CTF_WORKDIR or CTF_EVENT)", err)
        return None


def _notice(msg: str, err=None) -> None:
    if msg in _notified:
        return
    _notified.add(msg)
    print(msg, file=err if err is not None else sys.stderr)


def detected_ids(workdir: Path | None = None) -> set[str]:
    return {str(r["challenge_id"]) for r in ledger.read(workdir)
            if r.get("event") == "detect" and r.get("challenge_id") is not None}


def wave_labels(workdir: Path | None = None) -> list[str]:
    return [str(r.get("wave")) for r in ledger.read(workdir) if r.get("event") == "wave_open"]


def record_wave(challenge_ids: Iterable, *, label: str | None = None, announced: float | None = None,
                workdir: Path | None = None) -> tuple[dict, list[dict]]:
    """The board opened: write wave_open, then one detect per listed challenge not detected in an
    earlier wave. The label defaults to W<n> (n = waves already in the ledger + 1). `announced` is the
    published start (epoch seconds); the replay times the wave from it when given."""
    ids = []
    for c in challenge_ids:
        c = _cid(c)
        if c not in ids:
            ids.append(c)
    if label is None:
        label = f"W{len(wave_labels(workdir)) + 1}"
    elif label in wave_labels(workdir):
        raise StageError(f"wave {label!r} is already in the ledger; pick another label")
    fields: dict = {"wave": label, "count": len(ids)}
    if announced is not None:
        if isinstance(announced, bool) or not isinstance(announced, (int, float)) or not math.isfinite(announced):
            raise StageError(f"announced must be epoch seconds, got {announced!r}")
        fields["announced"] = float(announced)
    before = detected_ids(workdir)
    opened = mark("wave_open", workdir=workdir, **fields)
    detects = [mark("detect", c, workdir=workdir, wave=label) for c in ids if c not in before]
    return opened, detects


def record_spend(usd: float, tok: int, category: str, *, source: str | None = None, note: str | None = None,
                 workdir: Path | None = None) -> dict:
    """Spend that belongs to no challenge (build, verify, doc, orchestration). Challenge spend is
    charged through ctf.budget.LedgerMeter.add_spend so the cap is checked."""
    if category not in SPEND_CATEGORIES:
        raise StageError(f"unknown spend category {category!r}; categories are: {', '.join(SPEND_CATEGORIES)}")
    if isinstance(usd, bool) or not isinstance(usd, (int, float)) or not math.isfinite(usd) or usd < 0:
        raise StageError(f"usd must be a finite number >= 0, got {usd!r}")
    if isinstance(tok, bool) or not isinstance(tok, int) or tok < 0:
        raise StageError(f"tok must be an int >= 0, got {tok!r}")
    fields: dict = {"usd": float(usd), "tok": tok, "category": category}
    if source:
        fields["source"] = source
    if note:
        fields["note"] = note
    return ledger.append("spend", workdir=workdir, **fields)


def flag_hash(flag: str) -> str:
    return hashlib.sha256(flag.encode("utf-8")).hexdigest()


_PLACEHOLDER_WORDS = {"flag", "example", "fake", "placeholder", "redacted", "your_flag", "the_flag",
                      "test", "sample", "dummy", "flag_here", "insert_flag_here"}


def is_placeholder(flag: str) -> bool:
    """A format example rather than a found value: CSCTF{...}, flag{xxx}, CTF{<flag>}, CTF{example}."""
    body = flag[flag.find("{") + 1:-1] if "{" in flag and flag.endswith("}") else flag
    if body.strip(".xX_*?<>- ") == "":
        return True
    b = body.strip("<> ").lower()
    return b in _PLACEHOLDER_WORDS


def _strings(obj) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


class AgentStreamTap:
    """Wraps a launcher usage reader (feed(line) -> increments) and records, from the same agent
    output lines, the challenge's first tool call and every distinct flag-format value the agent
    sees (a candidate). `record(event_type, **fields)` is Gate.record (it adds challenge_id and
    harness). `flags` is the event's FlagFormat; candidates are not looked for when it is None or the
    format is not known (any word{...} would match), and the launcher says so.

    Agent output is data: it is parsed as JSON and only tool-call markers and flag-format strings
    are read. A ledger write that fails is reported on stderr once and the output keeps flowing."""

    def __init__(self, inner, record: Callable[..., Any], *, harness: str, flags=None, err=None,
                 model: str | None = None):
        self.inner, self.record, self.harness = inner, record, harness
        self.flags = flags if flags is not None and getattr(flags, "known", False) else None
        self.err = err
        self.tool_seen = False
        self.seen_flags: set[str] = set()
        self.stops_seen = 0                   # agent_stop records written: at most one per launched agent
        m = model if model is not None else getattr(inner, "model", None)
        self.model = m.strip() if isinstance(m, str) and m.strip() else None

    def __getattr__(self, name):              # usd, tokens, ... of the wrapped reader
        return getattr(self.inner, name)

    def feed(self, line: str):
        try:
            self._observe(line)
        except Exception as e:   # noqa: BLE001 -- reported, never hidden; the usage feed must go on
            _notice(f"{self.harness}_launch: stage events not recorded: {type(e).__name__}: {e}", self.err)
        return self.inner.feed(line)

    # -- what a line says
    def _observe(self, line: str) -> None:
        if not line.lstrip().startswith("{"):
            return
        try:
            d = json.loads(line)
        except ValueError:
            return
        if not isinstance(d, dict):
            return
        kind = d.get("type")
        if self.model is None:                # Claude stream-json names its model (init / message)
            m = d.get("model") if kind == "system" else (
                d["message"].get("model") if kind == "assistant" and isinstance(d.get("message"), dict)
                else None)
            if isinstance(m, str) and m.strip():
                self.model = m.strip()
        # B-016: a terminal refusal / provider error becomes one agent_stop (per launched agent) the
        # escalator reroutes on; later error lines of the same dying run add nothing.
        if not self.stops_seen:
            from . import escalation as _escalation
            stop = _escalation.detect_stop(line)
            if stop is not None:
                self.stops_seen = 1
                self.record(_escalation.STOP_EVENT, reason=stop[0], detail=stop[1],
                            **({"model": self.model} if self.model else {}))
        if not self.tool_seen:
            tool = self.tool_in(d)
            if tool is not None:
                self.tool_seen = True
                self.record("first_tool", by=f"agent:{self.harness}", tool=tool)
        if self.flags is not None and kind in ("assistant", "user", "item.started", "item.updated",
                                               "item.completed"):
            for s in _strings(d.get("message") if kind in ("assistant", "user") else d.get("item")):
                for f in self.flags.find_flags(s):
                    if is_placeholder(f):
                        continue
                    h = flag_hash(self.flags.normalize(f))
                    if h not in self.seen_flags:
                        self.seen_flags.add(h)
                        self.record("candidate", by=f"agent:{self.harness}", flag_sha256=h)

    @staticmethod
    def tool_in(d: dict) -> str | None:
        """The tool named by one stream line, or None. Claude stream-json: an assistant message with a
        tool_use block. Codex exec --json: an item.started / item.completed of a tool item type."""
        kind = d.get("type")
        if kind == "assistant":
            msg = d.get("message")
            content = msg.get("content") if isinstance(msg, dict) else None
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    return str(block.get("name") or "tool_use")
        elif kind in ("item.started", "item.completed"):
            item = d.get("item")
            if isinstance(item, dict) and item.get("type") in CODEX_TOOL_ITEMS:
                return str(item["type"])
        return None
