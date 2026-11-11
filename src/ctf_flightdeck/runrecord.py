"""A finished (or crashed) run, read back from its folder: the event log and the lane
transcripts. Post-flight reports, the gap report, writeups and scoring all start here.

Everything read is untrusted: the logs hold challenge text, commands, outputs, flags and
diffs. A line that is not valid JSON (a run that crashed mid-write) is skipped and named
in `problems`, never silently dropped; a missing event log is an error.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

EVENTS = "events.jsonl"
LANES = "lanes"


class RunFolderError(Exception):
    """The folder is not a run folder (no event log), or cannot be read."""


@dataclass(frozen=True)
class EventLine:
    at: float  # seconds since the run started (the deck's clock)
    wall: str  # ISO-8601 UTC when the line was written
    kind: str  # core.model.EventKind value, or run-start / run-end
    text: str
    lane: str | None
    challenge: str | None
    alert: str | None
    data: Mapping[str, object]


@dataclass(frozen=True)
class ActionLine:
    at: float
    turn: int
    kind: str  # core.model.ActionKind value: step, message, player, note, alert, approval
    by: str  # lane, player, flightdeck
    text: str
    output: str
    alert: str | None


@dataclass(frozen=True)
class FileLine:
    file: str
    status: str  # added, modified, deleted
    turn: int
    at: float
    diff: str


@dataclass(frozen=True)
class LaneRecord:
    lane: str
    challenge: str
    name: str
    category: str
    points: int
    model: str
    state: str  # core.model.LaneState value at the end
    result: str
    turns: int
    tokens: int
    cached_tokens: int
    dollars: float | None
    started_at: float
    ended_at: float | None
    parent: str | None
    attempt: int
    plan: str
    actions: tuple[ActionLine, ...]
    files: tuple[FileLine, ...]


@dataclass(frozen=True)
class RunRecord:
    dir: Path
    events: tuple[EventLine, ...]
    lanes: Mapping[str, LaneRecord]  # lane id -> record, in lane order
    problems: tuple[str, ...] = field(default=())  # lines skipped, with file:line and why

    def of(self, *kinds: str) -> list[EventLine]:
        """Events of the given kinds, in order."""
        return [e for e in self.events if e.kind in kinds]

    @property
    def started(self) -> str | None:
        start = next((e for e in self.events if e.kind == "run-start"), None)
        return start.wall if start else None

    @property
    def ended(self) -> str | None:
        end = next((e for e in reversed(self.events) if e.kind == "run-end"), None)
        return end.wall if end else None

    @property
    def duration(self) -> float:
        """Seconds from the first to the last deck event."""
        times = [e.at for e in self.events if e.kind not in ("run-start", "run-end")]
        return max(times) - min(times) if times else 0.0


def load_run(run_dir: Path) -> RunRecord:
    """Read a run folder. RunFolderError if it has no event log."""
    events_path = run_dir / EVENTS
    if not events_path.is_file():
        raise RunFolderError(f"{run_dir}: no {EVENTS} (is this a flightdeck run folder?)")
    problems: list[str] = []
    events = tuple(_event(raw) for raw in _lines(events_path, problems))
    lanes: dict[str, LaneRecord] = {}
    folder = run_dir / LANES
    if folder.is_dir():
        for path in sorted(folder.glob("*.jsonl"), key=lambda p: (len(p.stem), p.stem)):
            rows = list(_lines(path, problems))
            if not rows or "lane" not in rows[0]:
                problems.append(f"{path.name}: no header line; skipped")
                continue
            record = _lane(rows)
            lanes[record.lane] = record
    return RunRecord(run_dir, events, lanes, tuple(problems))


def _lines(path: Path, problems: list[str]):
    with path.open(encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except ValueError as exc:
                problems.append(f"{path.name}:{number}: not JSON ({exc.msg}); skipped")
                continue
            if not isinstance(value, dict):
                problems.append(f"{path.name}:{number}: not a JSON object; skipped")
                continue
            yield value


def _text(value: object) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _number(value: object, default: float = 0.0) -> float:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else default


def _event(raw: Mapping[str, object]) -> EventLine:
    data = raw.get("data")
    return EventLine(
        at=_number(raw.get("at")),
        wall=_text(raw.get("wall")),
        kind=_text(raw.get("kind")),
        text=_text(raw.get("text")),
        lane=raw.get("lane") if isinstance(raw.get("lane"), str) else None,
        challenge=raw.get("challenge") if isinstance(raw.get("challenge"), str) else None,
        alert=raw.get("alert") if isinstance(raw.get("alert"), str) else None,
        data=data if isinstance(data, dict) else {},
    )


def _lane(rows: list[Mapping[str, object]]) -> LaneRecord:
    head = rows[0]
    actions = tuple(
        ActionLine(
            at=_number(r.get("at")), turn=int(_number(r.get("turn"))), kind=_text(r.get("kind")), by=_text(r.get("by")),
            text=_text(r.get("text")), output=_text(r.get("output")),
            alert=r.get("alert") if isinstance(r.get("alert"), str) else None,
        )
        for r in rows[1:]
        if "kind" in r
    )
    files = tuple(
        FileLine(file=_text(r.get("file")), status=_text(r.get("status")), turn=int(_number(r.get("turn"))),
                 at=_number(r.get("at")), diff=_text(r.get("diff")))
        for r in rows[1:]
        if "file" in r
    )
    dollars = head.get("dollars")
    ended = head.get("ended_at")
    return LaneRecord(
        lane=_text(head.get("lane")), challenge=_text(head.get("challenge")), name=_text(head.get("name")),
        category=_text(head.get("category")), points=int(_number(head.get("points"))), model=_text(head.get("model")),
        state=_text(head.get("state")), result=_text(head.get("result")), turns=int(_number(head.get("turns"))),
        tokens=int(_number(head.get("tokens"))), cached_tokens=int(_number(head.get("cached_tokens"))),
        dollars=_number(dollars) if isinstance(dollars, (int, float)) and not isinstance(dollars, bool) else None,
        started_at=_number(head.get("started_at")), ended_at=_number(ended) if isinstance(ended, (int, float)) else None,
        parent=head.get("parent") if isinstance(head.get("parent"), str) else None,
        attempt=int(_number(head.get("attempt"), 1)), plan=_text(head.get("plan")),
        actions=actions, files=files,
    )
