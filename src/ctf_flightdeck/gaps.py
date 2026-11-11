"""The gap report: the challenges of a run that no L1 engine solved, and why.

`gap_report(record)` reads a run (runrecord.load_run) and gives a `Gap` for every challenge
in it that no L1 engine solved, whatever solved it in the end: who did (`solved_by`), every
L1 run on it (engine and status, in log order) and why L1 did not solve it (`reason`).
`gaps()` is that list alone. `gaps_markdown()` renders it for the player (RUN_DIR/gaps.md),
`gaps_json()` for build mode (RUN_DIR/gaps.json), `summary()` in a few terminal lines.

An L1 engine solved a challenge when one of its runs on it reported status "solved" with a
flag not known to be wrong. A flag is known wrong, as the deck sees it (Deck.not_flag), when
a submit of it on that challenge was rejected (by the platform, or by you after a hand
submit) or you declined to submit it; and also when the challenge was solved with another
flag (a challenge has one flag). A "solved" result that was never submitted still counts:
the engine showed evidence and nothing in the run says otherwise. A "candidate" never
counts, even when its flag was the one accepted: the bar for an engine is a "solved" result
(build mode's test asks for one).

Who solved it in the end (`solved_by`) is the first solve in the log:
- "l1:<engine>": an accepted flag that an L1 run on that challenge reported before it was
  accepted (a candidate whose flag a lane then submitted);
- "lane": a lane's accepted flag that no L1 run reported first;
- "teammate": a teammate's solve (team mode);
- "player": your own (a solve recorded for "me", or an accepted submit with no lane);
- "": nobody solved it in this run.

Why L1 did not solve it (`reason`):
- "no engine routed": the run has L1 results, none on this challenge;
- NO_L1: the run has no L1 results at all, so L1 did not run or reached no challenge;
- "routed: " and each run on it: the engine, its status, what became of its flags, and its
  notes cut short ("routed: strings none; zsteg blocked (missing tools: zsteg; nothing ran)").

With a pack (and the board the run played: the handouts are there), each gap is routed again
offline with l1.router.route: `routed` names the engines that would reach it now, best first,
with the router's reasons. Routing reads manifests and the first bytes of handout files; it
never runs an engine and writes nothing.

Everything read from a run is untrusted: challenge ids and names, engine ids, statuses, notes.
A Gap keeps ids and names as the run has them; a reason is our words around untrusted pieces,
each folded onto one line with control and invisible characters made visible
(text.untrusted). gaps_markdown() shows every value as literal one-line text
(postflight.md_text), so nothing in it acts as Markdown or HTML, and a lone surrogate (valid
in JSON, not in UTF-8) becomes a visible mark. gaps_json() is ASCII JSON. The report never
shows a flag: a reason says what became of a flag, not what it was (an engine's notes are
its own words).
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from .core.model import ME, EventKind, PendingKind
from .l1.result import STATUSES
from .postflight import md_text
from .runrecord import EventLine, RunRecord
from .text import MARK, untrusted

if TYPE_CHECKING:
    from .l1.manifest import Manifest
    from .platform.manual import Board

__all__ = [
    "MARKDOWN_FILE", "JSON_FILE", "NO_L1", "NO_ROUTE", "SCHEMA", "Gap", "GapError", "GapReport", "L1Solve",
    "Routed", "gap_report", "gaps", "gaps_json", "gaps_markdown", "summary",
]

SCHEMA = 1  # gaps.json's "schema"
MARKDOWN_FILE = "gaps.md"
JSON_FILE = "gaps.json"
NO_ROUTE = "no engine routed"
NO_L1 = "no L1 run: this run has no L1 results at all"
NOTES_LIMIT = 120  # an engine's notes are cut to this many characters in a reason
ID_LIMIT = 60  # an engine id or status in a reason
REASON_LIMIT = 4000  # a reason in the Markdown (its parts are cut already)

L1 = EventKind.L1.value
SKIPPED = frozenset({EventKind.INTERVENTION.value, EventKind.OUTCOME.value})
"""Events whose challenge id was typed by the player (a claim or queue of any id): they do
not put a challenge in the run."""

ACCEPTED, REJECTED, DECLINED, ANOTHER, UNSUBMITTED = "accepted", "rejected", "declined", "another", "unsubmitted"
_ONE_FLAG = {
    ACCEPTED: "its flag was accepted",
    REJECTED: "its flag was rejected",
    DECLINED: "you declined to submit its flag",
    ANOTHER: "its flag is not the one accepted",
    UNSUBMITTED: "its flag was not submitted",
}
_MANY_FLAGS = {
    ACCEPTED: "accepted", REJECTED: "rejected", DECLINED: "declined by you", ANOTHER: "not the one accepted",
    UNSUBMITTED: "not submitted",
}
_SURROGATE = re.compile("[\ud800-\udfff]")


class GapError(Exception):
    """The gap report cannot be made as asked; the message says why."""


@dataclass(frozen=True)
class Routed:
    """An engine the pack routes a challenge to now."""

    engine: str
    priority: int
    why: str  # the router's reason, e.g. "category cry, keyword 'base64'"


@dataclass(frozen=True)
class Gap:
    """A challenge of the run that no L1 engine solved."""

    challenge: str
    name: str  # "" when neither the run nor the board names it
    category: str  # "" when unknown
    points: int | None  # None when unknown
    solved_by: str  # "l1:<engine>" | "lane" | "teammate" | "player" | "" (unsolved)
    l1: tuple[tuple[str, str], ...]  # (engine, status) for every L1 run on it, in log order
    reason: str  # why L1 did not solve it (module docstring)
    routed: tuple[Routed, ...] | None = None  # with a pack: the engines that reach it now; None: not routed


@dataclass(frozen=True)
class L1Solve:
    """A challenge an L1 engine solved: not a gap."""

    challenge: str
    name: str
    engine: str  # the first engine whose run solved it


@dataclass(frozen=True)
class GapReport:
    """The gaps, and what the report says around them."""

    gaps: tuple[Gap, ...]
    run: str = ""  # the run folder's name
    event: str | None = None  # the event's name, from the board
    challenges: int | None = None  # challenges in the run
    l1_runs: int | None = None  # L1 results in the run
    l1_solved: tuple[L1Solve, ...] = ()
    pack: str | None = None  # the pack the gaps were routed with
    engines: int | None = None  # engines in that pack
    notes: tuple[str, ...] = ()  # problems reading the run, and what the report could not know


# ---------------------------------------------------------------------- reading the run


@dataclass
class _Facts:
    name: str = ""
    category: str = ""
    points: int | None = None


@dataclass(frozen=True)
class _Run:
    """One L1 result, as the log has it."""

    engine: str
    status: str
    flags: tuple[str, ...]
    notes: str


class _Flags:
    """What became of the flags found on each challenge: accepted or rejected when submitted,
    or declined by the player before a submit.

    A decline names no flag in the log: it answers the approval its lane waits on, which is
    the lane's last `pending` event not marked "queued" (the deck logs one each time an
    approval becomes the current one). It counts once its `outcome` says it was applied."""

    def __init__(self, record: RunRecord) -> None:
        self.accepted: dict[str, set[str]] = {}
        self.rejected: dict[str, set[str]] = {}
        self.declined: dict[str, set[str]] = {}
        waiting: dict[str, tuple[str, str, str | None]] = {}  # lane -> (challenge, kind, flag) it waits on now
        declining: dict[str, tuple[str, str]] = {}  # lane -> (challenge, flag) of a decline not yet answered
        for event in record.events:
            data, lane = event.data, event.lane
            if event.kind == EventKind.SUBMIT:
                flag = data.get("flag")
                if not event.challenge or not isinstance(flag, str) or not flag:
                    continue
                if data.get("correct") is True:
                    self.accepted.setdefault(event.challenge, set()).add(flag)
                elif data.get("correct") is False:
                    self.rejected.setdefault(event.challenge, set()).add(flag)
            elif not lane:
                continue
            elif event.kind == EventKind.PENDING and data.get("queued") is not True and event.challenge:
                flag = data.get("flag")
                waiting[lane] = (event.challenge, _str(data.get("kind")), flag if isinstance(flag, str) and flag else None)
            elif event.kind in (EventKind.INTERVENTION, EventKind.OUTCOME) and data.get("intervention") == "decline":
                if event.kind == EventKind.INTERVENTION:
                    cid, kind, flag = waiting.get(lane, ("", "", None))
                    if kind == PendingKind.SUBMIT.value and flag is not None:
                        declining[lane] = (cid, flag)
                    else:
                        declining.pop(lane, None)
                elif lane in declining:
                    cid, flag = declining.pop(lane)
                    if data.get("ok") is True:
                        self.declined.setdefault(cid, set()).add(flag)

    def fate(self, challenge: str, flag: str) -> str:
        if flag in self.accepted.get(challenge, ()):
            return ACCEPTED
        if flag in self.rejected.get(challenge, ()):
            return REJECTED
        if flag in self.declined.get(challenge, ()):
            return DECLINED
        if self.accepted.get(challenge):
            return ANOTHER
        return UNSUBMITTED

    def solved(self, challenge: str, run: _Run) -> bool:
        """The run solved the challenge: status "solved" with a flag not known to be wrong
        (a solved result whose log line lost its flags is taken at its word)."""
        if run.status != "solved":
            return False
        return not run.flags or any(self.fate(challenge, flag) in (ACCEPTED, UNSUBMITTED) for flag in run.flags)


def gap_report(record: RunRecord, *, pack: Path | None = None, board: Board | None = None) -> GapReport:
    """The gaps of a run, with what the report says around them. With `pack`, each gap is
    routed again offline, which needs `board` (the board the run played) for the handouts:
    GapError without it; l1.manifest.ManifestError when the pack cannot be read."""
    if pack is not None and board is None:
        raise GapError("routing with a pack needs the board the run played, whose folders hold the handouts")
    manifests: list[Manifest] | None = None
    if pack is not None:
        from .l1.manifest import discover

        manifests = discover(pack)
    notes = list(record.problems)
    facts = _facts(record)

    flags = _Flags(record)
    runs: dict[str, list[_Run]] = {}
    reported: dict[str, dict[str, str]] = {}  # challenge -> flag -> the engine that reported it first
    first: dict[str, str] = {}  # challenge -> who solved it first
    l1_count = nameless = 0
    for event in record.events:
        cid = event.challenge
        if event.kind == L1:
            l1_count += 1
            if not cid:
                nameless += 1
                continue
            run = _run(event)
            runs.setdefault(cid, []).append(run)
            for flag in run.flags:
                reported.setdefault(cid, {}).setdefault(flag, run.engine)
            if cid not in first and flags.solved(cid, run):
                first[cid] = f"l1:{run.engine}"
        elif not cid or cid in first:
            continue
        elif event.kind == EventKind.SUBMIT and event.data.get("correct") is True:
            flag = event.data.get("flag")
            engine = reported.get(cid, {}).get(flag) if isinstance(flag, str) and flag else None
            first[cid] = f"l1:{engine}" if engine is not None else ("lane" if event.lane else "player")
        elif event.kind == EventKind.TEAMMATE and event.data.get("solved") is True:
            first[cid] = "player" if event.data.get("who") == ME else "teammate"
    if nameless:
        notes.append(f"{_plural(nameless, 'L1 result names', 'L1 results name')} no challenge; left out")

    event_name = None
    on_board = {}
    if board is not None:
        event_name = board.event
        on_board = {item.challenge.id: item for item in board.challenges}
        if facts and not set(facts) & set(on_board):
            notes.append("the board has none of this run's challenges (is it the board this run played?)")
        for cid, info in facts.items():
            known = on_board.get(cid)
            if known is not None:
                info.name = info.name or known.challenge.name
                info.category = info.category or known.challenge.category
                info.points = known.challenge.points if info.points is None else info.points
    unknown = [cid for cid, info in facts.items() if info.points is None]
    if unknown:
        notes.append(
            f"no name or points in the run for {', '.join(unknown)}"
            + (" (and not on the board)" if board is not None else " (give --board to fill them in)")
        )
    if record.ended is None:
        notes.append("the run log has no run-end line: the run did not close cleanly (it crashed, or is still running)")

    found: list[Gap] = []
    solved: list[L1Solve] = []
    for cid, info in facts.items():
        on = runs.get(cid, [])
        winner = next((run for run in on if flags.solved(cid, run)), None)
        if winner is not None:
            solved.append(L1Solve(cid, info.name, winner.engine))
            continue
        found.append(Gap(
            cid, info.name, info.category, info.points, first.get(cid, ""),
            tuple((run.engine, run.status) for run in on), _reason(cid, on, flags, l1_count > 0),
        ))

    if manifests is not None:
        found = _route_now(found, manifests, on_board, notes)
    return GapReport(
        gaps=tuple(found), run=record.dir.name or record.dir.resolve().name, event=event_name,
        challenges=len(facts), l1_runs=l1_count, l1_solved=tuple(solved),
        pack=str(pack) if pack is not None else None, engines=len(manifests) if manifests is not None else None,
        notes=tuple(notes),
    )


def gaps(record: RunRecord, *, pack: Path | None = None, board: Board | None = None) -> list[Gap]:
    """The challenges of a run that no L1 engine solved (gap_report() has the rest)."""
    return list(gap_report(record, pack=pack, board=board).gaps)


def _facts(record: RunRecord) -> dict[str, _Facts]:
    """The challenges of the run, in release order, with the names and points the lane
    transcripts give."""
    found: dict[str, _Facts] = {}
    for event in record.of(EventKind.RELEASE.value):
        ids = event.data.get("challenges")
        for cid in ids if isinstance(ids, list) else ():
            if isinstance(cid, str) and cid:
                found.setdefault(cid, _Facts())
    for event in record.events:  # a log that lost its release line still names its challenges
        if event.challenge and event.kind not in SKIPPED:
            found.setdefault(event.challenge, _Facts())
    for lane in record.lanes.values():
        if not lane.challenge:
            continue
        info = found.setdefault(lane.challenge, _Facts())
        info.name = info.name or lane.name
        info.category = info.category or lane.category
        info.points = lane.points if info.points is None else info.points
    return found


def _run(event: EventLine) -> _Run:
    data = event.data
    flags = data.get("flags")
    return _Run(
        engine=_str(data.get("engine")) or "?",
        status=_str(data.get("status")) or "?",
        flags=tuple(flag for flag in flags if isinstance(flag, str) and flag) if isinstance(flags, list) else (),
        notes=_str(data.get("notes")),
    )


def _reason(cid: str, runs: Sequence[_Run], flags: _Flags, any_l1: bool) -> str:
    if not runs:
        return NO_ROUTE if any_l1 else NO_L1
    return "routed: " + "; ".join(_phrase(cid, run, flags) for run in runs)


def _phrase(cid: str, run: _Run, flags: _Flags) -> str:
    """One L1 run in a reason: "<engine> <status>", then what became of its flags and its notes."""
    details = []
    if run.flags:
        details.append(_fates(cid, run, flags))
    elif run.status == "candidate":
        details.append("no flag in the log")
    if run.status not in STATUSES:
        details.append("not a status flightdeck knows")
    notes = _one(run.notes, NOTES_LIMIT)
    if notes:
        details.append(notes)
    text = f"{_one(run.engine, ID_LIMIT)} {_one(run.status, ID_LIMIT)}"
    return text + (f" ({'; '.join(details)})" if details else "")


def _fates(cid: str, run: _Run, flags: _Flags) -> str:
    fates = [flags.fate(cid, flag) for flag in run.flags]
    if len(fates) == 1:
        text = _ONE_FLAG[fates[0]]
    else:
        counts = Counter(fates)
        text = f"its {len(fates)} flags: " + ", ".join(f"{counts[k]} {word}" for k, word in _MANY_FLAGS.items() if counts[k])
    if ACCEPTED in fates and run.status != "solved":
        text += ", but the engine did not report it solved"
    return text


def _route_now(found: list[Gap], manifests: list[Manifest], on_board: dict, notes: list[str]) -> list[Gap]:
    """Each gap on the board routed again with the pack (never run)."""
    from .l1.router import route

    out: list[Gap] = []
    missing: list[str] = []
    for gap in found:
        item = on_board.get(gap.challenge)
        if item is None:
            missing.append(gap.challenge)
            out.append(gap)
            continue
        try:
            hits = route(manifests, item.challenge, item.handout)
        except ValueError as exc:  # its folder went away after the board was read
            notes.append(f"not routed now: {gap.challenge}: {exc}")
            out.append(gap)
            continue
        out.append(replace(gap, routed=tuple(Routed(hit.manifest.id, hit.priority, hit.reason) for hit in hits)))
    if missing:
        notes.append(f"not routed now, since the board does not have them: {', '.join(missing)}")
    return out


# ---------------------------------------------------------------------- Markdown


def gaps_markdown(gaps: Sequence[Gap] | GapReport) -> str:
    """The gap report as Markdown. Given a list of gaps alone, it says what it can."""
    rep = _report_of(gaps)
    title = _md(rep.event) if rep.event else (f"run {_md(rep.run)}" if rep.run else "a run")
    out = [f"# Gaps: {title}", ""]
    out += _glance(rep)
    out += _gap_sections(rep)
    if rep.challenges is not None:
        out += [f"## Solved by L1 ({len(rep.l1_solved)})", ""]
        out += [f"- {_md(s.name or s.challenge)}: {_md(s.engine)}" for s in rep.l1_solved] or ["None."]
        out.append("")
    if rep.notes:
        out += ["## Problems reading the run", ""]
        out += [f"- {_md(note, 400)}" for note in rep.notes]
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def _glance(rep: GapReport) -> list[str]:
    another = Counter(_solver(gap.solved_by) for gap in rep.gaps if gap.solved_by)
    unsolved = sum(1 for gap in rep.gaps if not gap.solved_by)
    out = ["## At a glance", ""]
    if rep.challenges is not None:
        out.append(f"- Challenges in the run: {rep.challenges}, {len(rep.l1_solved)} solved by an L1 engine")
    out.append(
        f"- Gaps: {len(rep.gaps)}, no L1 engine solved them: {sum(another.values())} solved another way "
        f"(lanes {another['lane']}, teammates {another['teammate']}, you {another['player']}, "
        f"with an L1 candidate's flag {another['l1']}), {unsolved} not solved"
    )
    if rep.l1_runs is not None:
        out.append(
            f"- L1 results in the run: {rep.l1_runs}" if rep.l1_runs
            else "- L1 results in the run: none, so L1 did not run or reached no challenge"
        )
    if rep.pack is not None:
        routed = [gap for gap in rep.gaps if gap.routed is not None]
        reach = sum(1 for gap in routed if gap.routed)
        engines = f" ({_plural(rep.engines, 'engine')})" if rep.engines is not None else ""
        line = f"- Routed now with the pack {_md(rep.pack)}{engines}: {reach} of {_plural(len(routed), 'gap')} reach an engine"
        if len(routed) < len(rep.gaps):
            line += f", {len(rep.gaps) - len(routed)} not routed"
        out.append(line)
    out.append("")
    return out


def _gap_sections(rep: GapReport) -> list[str]:
    out = [f"## Gaps ({len(rep.gaps)})", ""]
    if not rep.gaps:
        if rep.challenges == 0:
            return out + ["No challenges in this run.", ""]
        if rep.challenges is not None:
            return out + ["None: an L1 engine solved every challenge in this run.", ""]
        return out + ["None.", ""]
    for gap in rep.gaps:
        out += [f"### {_md(gap.name or gap.challenge)} ({_where(gap)}): {_outcome(gap.solved_by)}", ""]
        out.append(f"- Id: {_md(gap.challenge)}")
        out.append(f"- Why L1 did not solve it: {_md(gap.reason, REASON_LIMIT)}")
        if gap.routed is not None:
            now = "; ".join(f"{_md(r.engine)} (priority {r.priority}: {_md(r.why)})" for r in gap.routed)
            out.append(f"- Routed now: {now or 'no engine in the pack'}")
        elif rep.pack is not None:
            out.append("- Routed now: not routed (see the problems below)")
        out.append("")
    return out


def _where(gap: Gap) -> str:
    category = _md(gap.category) if gap.category else "category unknown"
    points = f"{gap.points} pts" if gap.points is not None else "points unknown"
    return f"{category}, {points}"


def _solver(solved_by: str) -> str:
    return "l1" if solved_by.startswith("l1:") else solved_by


def _outcome(solved_by: str) -> str:
    if not solved_by:
        return "not solved"
    if solved_by.startswith("l1:"):
        return f"solved with the flag L1 engine {_md(solved_by[3:])} found"
    words = {"lane": "solved by a lane", "teammate": "solved by a teammate", "player": "solved by you"}
    return words.get(solved_by) or f"solved by {_md(solved_by)}"


# ---------------------------------------------------------------------- JSON and the terminal


def gaps_json(gaps: Sequence[Gap] | GapReport) -> str:
    """The gap report as ASCII JSON for build mode: {"schema": 1, ..., "gaps": [...]}. Ids,
    names and reasons as the report has them; "points" is null when unknown, "routed" null
    when the gap was not routed with a pack."""
    rep = _report_of(gaps)
    data = {
        "schema": SCHEMA,
        "run": rep.run or None,
        "event": rep.event,
        "challenges": rep.challenges,
        "l1_results": rep.l1_runs,
        "pack": rep.pack,
        "engines": rep.engines,
        "gaps": [
            {
                "challenge": gap.challenge, "name": gap.name, "category": gap.category, "points": gap.points,
                "solved_by": gap.solved_by,
                "l1": [{"engine": engine, "status": status} for engine, status in gap.l1],
                "reason": gap.reason,
                "routed": None if gap.routed is None else [
                    {"engine": r.engine, "priority": r.priority, "why": r.why} for r in gap.routed
                ],
            }
            for gap in rep.gaps
        ],
        "solved_by_l1": [{"challenge": s.challenge, "name": s.name, "engine": s.engine} for s in rep.l1_solved],
        "notes": list(rep.notes),
    }
    return json.dumps(data, indent=2, ensure_ascii=True) + "\n"


def summary(rep: GapReport) -> str:
    """The report in a few plain lines for the terminal (untrusted text folded and made visible)."""
    another = sum(1 for gap in rep.gaps if gap.solved_by)
    of = f" of {rep.challenges}" if rep.challenges is not None else ""
    lines = [
        f"Gaps: {len(rep.gaps)}{of} challenges no L1 engine solved ({another} solved another way, "
        f"{len(rep.gaps) - another} not solved); L1 solved {len(rep.l1_solved)}",
    ]
    if rep.pack is not None:
        routed = [gap for gap in rep.gaps if gap.routed is not None]
        reach = sum(1 for gap in routed if gap.routed)
        lines.append(f"Routed now: {reach} of {_plural(len(routed), 'gap')} on the board reach an engine in the pack")
    if rep.notes:
        lines.append(f"{_plural(len(rep.notes), 'problem')} reading the run: see {MARKDOWN_FILE}")
    return "\n".join(_visible(line) for line in lines) + "\n"


# ---------------------------------------------------------------------- helpers


def _report_of(gaps: Sequence[Gap] | GapReport) -> GapReport:
    return gaps if isinstance(gaps, GapReport) else GapReport(tuple(gaps))


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _visible(text: str) -> str:
    """`text` with control and invisible characters made visible and lone surrogates marked,
    so it can be printed and written as UTF-8."""
    return _SURROGATE.sub(MARK, untrusted(text))


def _one(text: str, limit: int) -> str:
    """Untrusted text in a reason: on one line, made visible, cut to `limit`."""
    folded = _visible(untrusted(text, one_line=True)).strip()
    return folded if len(folded) <= limit else folded[: limit - 1] + "\u2026"


def _md(value: object, limit: int = 200) -> str:
    """Untrusted text as literal Markdown on one line (postflight.md_text), lone surrogates marked."""
    return md_text(_SURROGATE.sub(MARK, value if isinstance(value, str) else str(value)), limit)


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"
