"""The post-flight report: what happened in a run, read back from its folder.

`report()` turns a RunRecord (runrecord.load_run) into Markdown, in six sections:

- the run at a glance: event, duration, challenges, solves by lanes, L1, teammates and you,
  points, tokens and the cached share, dollars (or "unknown") and the cost per solve;
- a timeline per challenge: release, L1 runs, lanes starting and ending with their models,
  alerts, interventions and what came of them, flags submitted right or wrong, the solve;
- where lanes stalled: each alert about a lane's course or budget, when it fired (at the
  turn its line in the lane's transcript has), how it was answered and whether the lane
  then solved within 10 turns (flag-found and teammate alerts are not stalls; they are in
  the timeline). An approve or decline answers a budget alert only when it answered the
  budget request (or approved more budget with nothing waiting), not a flag's verdict or
  the live box: the lane's current approval is replayed from its pending events;
- the hints, redirects, forks and escalations that helped (a lane solved that challenge
  within 10 turns or 15 minutes, with a flag it proposed after the step) and those with no
  effect seen (a step taken while the solving flag already waited did not help);
- spend by model and the five most expensive lanes;
- the lanes that gave up, were killed or were stopped, with their reasons.

`summary()` is the same run in a few plain lines for the terminal.

Who solved a challenge is the first solve in the log: a flag accepted (a submit event with
`correct` true: the platform checked it, or the player said it accepted it), a teammate's
solve, or the player's own (a solve recorded for "me"). An accepted flag is L1's when an
earlier `l1` event on that challenge reported it, whatever that event's status and whether
or not a lane submitted it; otherwise it is the submitting lane's (yours, with no lane).
An L1 result alone is never a solve: "solved" there means found, and only the platform
accepts a flag (l1/result.py). writeup.solves() credits accepted flags by the same rule.
`solves()` gives them, one per challenge.

A damaged run folder is reported, never trusted or crashed on: a time that is not one (not
a number, infinite or negative; json reads NaN, Infinity and 1e400) shows as "T+?" and is
left out of the duration, a price that is not a finite number is unknown, and a value of the
wrong type is unknown, not zero.

Everything read from a run is untrusted: challenge names, alert reasons, hints, flags,
commands, model names, even lane ids. In the Markdown, untrusted text is one line with
control and invisible characters made visible (text.untrusted), cut short, and every
character Markdown reads as syntax is backslash-escaped, so it shows as itself: no HTML, no
links or images, no emphasis, no extra table cells, no headings. Flags are inline code and
commands are fenced code blocks, each fence longer than any backtick run inside. Nothing a
run holds is ever emitted as raw HTML.
"""

from __future__ import annotations

import math
import re
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import fmt
from .core.model import FINISHED, ME, ActionKind, Actor, AlertKind, EventKind, PendingKind
from .runrecord import EventLine, LaneRecord, RunRecord
from .text import untrusted

if TYPE_CHECKING:
    from .platform.manual import Board

__all__ = [
    "HELP_SECONDS", "HELP_TURNS", "STALL_TURNS", "TOP_LANES", "Flight", "Solve",
    "analyse", "md_code", "md_fence", "md_text", "report", "solves", "summary",
]

L1 = "l1"  # an L1 engine run (M2's L1 stage): data {engine, status, flags, seconds, notes}
RUN_START, RUN_END = "run-start", "run-end"

HELP_TURNS = 10  # an intervention helped if a lane solved the challenge within this many turns...
HELP_SECONDS = 15 * 60  # ...or within this many seconds
STALL_TURNS = 10  # an alert was followed by a solve if its lane solved within this many turns
TOP_LANES = 5
STEPS_SHOWN = 3  # each stall shows the lane's last few steps before the alert
TEXT_LIMIT = 200  # untrusted text is cut to this many characters
STEP_LIMIT = 160

JUDGED = ("hint", "redirect", "fork", "escalate")
"""Interventions judged by what followed them."""
NOT_STALLS = frozenset({AlertKind.FLAG.value, AlertKind.TEAMMATE.value})
COURSE_ANSWERS = frozenset({"hint", "redirect", "fork", "escalate", "kill", "takeover"})
BUDGET_ANSWERS = frozenset({"approve", "decline", "kill", "escalate"})
VERDICTS = frozenset({"approve", "decline"})
"""Interventions that answer the lane's current approval, whatever it is."""
BUDGET = PendingKind.BUDGET.value
CANDIDATE = "candidate flag "  # core/deck.py's transcript note when a lane first proposes a flag
FINISHED_STATES = frozenset(state.value for state in FINISHED)
ENDED_WITHOUT_FLAG = ("gave up", "killed", "stopped")
SHOWN_PENDING = frozenset({"budget", "live box"})  # flag approvals show as the flag alert and the submit
READ = frozenset(
    {RUN_START, RUN_END, L1}
    | {kind.value for kind in EventKind if kind is not EventKind.BOARD}
)
STEP_NAMES = {"takeover": "take over", "handback": "hand back"}


# ---------------------------------------------------------------------- Markdown for untrusted text

_SYNTAX = re.compile(r"[\\`*_~\[\]<>&|#$]")
_BLOCK_START = re.compile(r"^(?:[-+=]|\d+(?=[.)]))")
_TICKS = re.compile(r"`+")


def _str(value: object) -> str:
    if isinstance(value, str):
        return value
    return "" if value is None else str(value)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def md_text(value: object, limit: int = TEXT_LIMIT) -> str:
    """Untrusted text as literal Markdown inline text, on one line, cut to `limit`.

    Control and invisible characters are made visible, newlines folded, and every
    character Markdown could read as syntax is backslash-escaped: it renders as itself,
    never as HTML, a link, an image, emphasis, a table cell, a heading or a list.
    """
    text = _cut(untrusted(_str(value), one_line=True).strip(), limit)
    text = _SYNTAX.sub(lambda m: "\\" + m.group(), text)
    match = _BLOCK_START.match(text)
    if match:  # "- x", "+ x", "1. x" or "===" would start a block if it began a line
        end = match.end()
        text = "\\" + text if not text[0].isdigit() else text[:end] + "\\" + text[end:]
    return text


def md_code(value: object, limit: int = TEXT_LIMIT) -> str:
    """Untrusted text (a flag) as an inline code span: one line, control characters made
    visible, and a backtick fence longer than any backtick run inside."""
    text = _cut(untrusted(_str(value), one_line=True), limit)
    if not text.strip():
        return "(empty)" if not text else f"({len(text)} spaces)"
    longest = max((len(run) for run in _TICKS.findall(text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text[0] in " `" or text[-1] in " `" else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_fence(lines: Sequence[object], limit: int = STEP_LIMIT, info: str = "text") -> list[str]:
    """Untrusted lines (commands) as a fenced code block: each folded to one line, control
    characters made visible, cut to `limit`, inside a fence longer than any backtick run."""
    body = [_cut(untrusted(_str(line), one_line=True), limit) for line in lines]
    longest = max((len(run) for line in body for run in _TICKS.findall(line)), default=0)
    ticks = "`" * max(3, longest + 1)
    return [ticks + info, *body, ticks]


def _plain(value: object, limit: int = TEXT_LIMIT) -> str:
    """Untrusted text for the terminal: one line, control characters made visible."""
    return _cut(untrusted(_str(value), one_line=True).strip(), limit)


# ---------------------------------------------------------------------- facts read from the log


def _num(value: object) -> float | None:
    """A finite number as a float; None for anything else: not a number, a bool, NaN, an
    infinity (json reads NaN, Infinity and 1e400 as floats), or an int too large for a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _time(value: object) -> float | None:
    """A time in the run (seconds since it started, never negative), or None: unknown."""
    number = _num(value)
    return number if number is not None and number >= 0 else None


def _int(value: object, default: int = 0) -> int:
    number = _num(value)
    return int(number) if number is not None else default


def _flags(data: Mapping[str, object]) -> list[str]:
    """An L1 event's flags: the non-empty strings in its list (none when it is not a list)."""
    flags = data.get("flags")
    return [f for f in flags if isinstance(f, str) and f] if isinstance(flags, list) else []


@dataclass(frozen=True)
class Solve:
    """Who solved a challenge, and when."""

    challenge: str
    by: str  # "lane", "l1", "teammate" or "player"
    who: str  # the lane id, the L1 engine, the teammate's handle, or "me"
    at: float | None  # None: the log's time for it is not a time
    index: int  # the event's position in the run log
    flag: str | None = None
    lane: str | None = None  # the lane that submitted the accepted flag (an L1 flag goes through one)


@dataclass
class ChallengeFacts:
    id: str
    name: str = ""
    category: str = ""
    points: int | None = None


@dataclass
class LaneFacts:
    id: str
    challenge: str = ""
    models: list[str] = field(default_factory=list)  # in the order the lane used them
    parent: str | None = None
    attempt: int = 1
    approach: str = ""
    start: int | None = None  # event index of lane.start
    started_at: float | None = None
    end: int | None = None  # event index of lane.end
    ended_at: float | None = None
    state: str = ""  # as it ended; while open, the transcript's last state
    result: str = ""
    turns: int = 0
    tokens: int = 0
    cached: int = 0
    dollars: float | None = 0.0  # None: a turn had no known price
    plan: str = ""
    record: LaneRecord | None = None
    turn_index: list[int] = field(default_factory=list)  # event indices of its turns
    turn_number: list[int] = field(default_factory=list)  # its turn count after each
    turn_tokens: int = 0
    turn_cached: int = 0
    turn_dollars: float = 0.0
    turn_unpriced: int = 0

    @property
    def finished(self) -> bool:
        return self.end is not None or self.state in FINISHED_STATES

    def turn_before(self, index: int) -> int:
        """The lane's turn count just before event `index`."""
        k = bisect_left(self.turn_index, index)
        return self.turn_number[k - 1] if k else 0

    def turns_between(self, after: int, upto: int) -> int:
        """Turns the lane took after event `after` and before event `upto`."""
        return max(0, bisect_left(self.turn_index, upto) - bisect_right(self.turn_index, after))

    def add_model(self, model: str) -> None:
        if model and (not self.models or self.models[-1] != model):
            self.models.append(model)


@dataclass
class Step:
    """One intervention by the player, with what came of it."""

    index: int
    at: float | None  # None: the log's time for it is not a time
    name: str
    lane: str | None
    challenge: str | None
    data: Mapping[str, object]
    ok: bool | None = None  # None: no outcome in the log
    message: str = ""
    answers: str | None = None  # an approve or decline: the kind of approval it answered; None when none waited


@dataclass(frozen=True)
class Stall:
    """An alert about a lane's course or budget."""

    index: int
    at: float | None
    lane: str
    challenge: str
    kind: str
    reason: str
    turn: int  # the lane's turn when it fired
    answer: Step | None  # the first intervention on the lane that answers it
    unanswered: str  # why there was no answer, when there was none
    solved_turns: int | None  # turns from the alert until this lane solved, if it did
    steps: tuple[str, ...]  # the lane's last steps before the alert

    @property
    def solved_within(self) -> bool:
        return self.solved_turns is not None and self.solved_turns <= STALL_TURNS


@dataclass(frozen=True)
class Judged:
    """A hint, redirect, fork or escalation, and whether a solve followed it in time."""

    step: Step
    solve: Solve | None  # the challenge's solve after the step, if a lane got it
    turns: int | None  # turns the solving lane took after the step
    seconds: float | None
    helped: bool
    waited: bool = False  # the solving flag was already proposed (waiting for you) before the step
    since: float | None = None  # when it was first proposed, when waited


@dataclass(frozen=True)
class ModelSpend:
    model: str
    turns: int
    tokens: int
    cached: int
    dollars: float
    unpriced: int  # turns with no known price


@dataclass(frozen=True)
class Flight:
    """Everything the report says, worked out once from the run."""

    record: RunRecord
    event: str | None  # the event's name, from the board
    challenges: dict[str, ChallengeFacts]  # in release order
    lanes: dict[str, LaneFacts]  # in start order
    solves: dict[str, Solve]
    steps: list[Step]
    stalls: list[Stall]
    judged: list[Judged]
    models: list[ModelSpend]
    outside: tuple[int, int, float | None]  # tokens, cached tokens, dollars counted outside a turn
    l1_runs: int
    by_challenge: dict[str, list[int]]  # event indices shown on each challenge's timeline
    notes: list[str]  # problems reading the run, and things the report could not know
    duration: float = 0.0  # seconds from the first to the last deck event with a usable time

    # ------------------------------------------------------------------ totals

    @property
    def tokens(self) -> int:
        return sum(lane.tokens for lane in self.lanes.values())

    @property
    def cached(self) -> int:
        return sum(lane.cached for lane in self.lanes.values())

    @property
    def turns(self) -> int:
        return sum(lane.turns for lane in self.lanes.values())

    @property
    def dollars(self) -> tuple[float, int]:
        """Dollars known, and how many lanes had a turn with no price."""
        return _known_dollars(self.lanes.values())

    @property
    def priced_turns(self) -> int:
        return sum(spend.turns - spend.unpriced for spend in self.models)

    def solved_by(self, by: str) -> int:
        return sum(1 for solve in self.solves.values() if solve.by == by)

    def points(self) -> tuple[int, int, int, int]:
        """Points solved, points on the board, and how many solved and released challenges
        have no known points."""
        solved = [self.challenges[c].points for c in self.solves if c in self.challenges]
        every = [facts.points for facts in self.challenges.values()]
        return (
            sum(p for p in solved if p is not None), sum(p for p in every if p is not None),
            sum(1 for p in solved if p is None), sum(1 for p in every if p is None),
        )

    def name(self, challenge: str) -> str:
        facts = self.challenges.get(challenge)
        return facts.name if facts and facts.name else challenge


def _known_dollars(lanes) -> tuple[float, int]:
    """Dollars known over these lanes, and how many had a turn with no price. A lane with
    an unpriced turn still counts the turns that had a price."""
    known, unpriced = 0.0, 0
    for lane in lanes:
        if lane.dollars is None:
            unpriced += 1
            known += lane.turn_dollars
        else:
            known += lane.dollars
    return known, unpriced


def analyse(record: RunRecord, *, board: Board | None = None) -> Flight:
    """Work out the facts of a run; report() and summary() render them."""
    events = record.events
    notes = list(record.problems)
    challenges: dict[str, ChallengeFacts] = {}
    lanes: dict[str, LaneFacts] = {}
    steps: list[Step] = []
    open_steps: list[Step] = []
    by_challenge: dict[str, list[int]] = {}
    unread: Counter[str] = Counter()
    model_spend: dict[str, list[float]] = {}
    # lane -> the kind of approval it waits on now. The deck logs a pending event each time an
    # approval becomes the lane's current one ("queued" ones wait behind it); an approve or
    # decline answers the current one, and the lane's end drops what is left.
    current: dict[str, str] = {}
    asked: dict[tuple[str, str], int] = {}  # (lane, flag) -> the first pending event asking about it

    def challenge(cid: str) -> ChallengeFacts:
        if cid not in challenges:
            challenges[cid] = ChallengeFacts(cid)
            by_challenge[cid] = []
        return challenges[cid]

    def lane(lid: str) -> LaneFacts:
        if lid not in lanes:
            lanes[lid] = LaneFacts(lid)
        return lanes[lid]

    def challenge_of(event: EventLine) -> str | None:
        if event.challenge:
            return event.challenge
        if event.lane and event.lane in lanes and lanes[event.lane].challenge:
            return lanes[event.lane].challenge
        if event.lane and event.lane in record.lanes:
            return record.lanes[event.lane].challenge or None
        return None

    for event in record.of(EventKind.RELEASE.value):  # challenges in the order they were released
        ids = event.data.get("challenges")
        for cid in ids if isinstance(ids, list) else ():
            if isinstance(cid, str) and cid:
                challenge(cid)

    for index, event in enumerate(events):
        kind, data = event.kind, event.data
        if kind not in READ:
            unread[kind or "(none)"] += 1
            continue
        if kind in (RUN_START, RUN_END):
            continue
        if event.lane:
            facts = lane(event.lane)
            if event.challenge and not facts.challenge:
                facts.challenge = event.challenge
        if kind == EventKind.RELEASE:
            ids = data.get("challenges")
            for cid in ids if isinstance(ids, list) else ():
                if isinstance(cid, str) and cid:
                    challenge(cid)
                    by_challenge[cid].append(index)
            continue
        cid = challenge_of(event)
        if cid:
            challenge(cid)
        if kind == EventKind.LANE_START and event.lane:
            facts = lanes[event.lane]
            facts.start, facts.started_at = index, _time(event.at)
            facts.add_model(_str(data.get("model")))
            parent = data.get("parent")
            facts.parent = parent if isinstance(parent, str) and parent else None
            facts.attempt = _int(data.get("attempt"), 1)
            facts.approach = _str(data.get("approach"))
        elif kind == EventKind.LANE_END and event.lane:
            facts = lanes[event.lane]
            facts.end, facts.ended_at = index, _time(event.at)
            facts.state, facts.result = _str(data.get("state")), _str(data.get("result"))
            current.pop(event.lane, None)
        elif kind == EventKind.TURN and event.lane:
            facts = lanes[event.lane]
            facts.turn_index.append(index)
            facts.turn_number.append(_int(data.get("turn"), len(facts.turn_index)))
            model = _str(data.get("model"))
            facts.add_model(model)
            tokens, cached = _int(data.get("tokens")), _int(data.get("cached_tokens"))
            dollars = _num(data.get("dollars"))
            facts.turn_tokens += tokens
            facts.turn_cached += cached
            spend = model_spend.setdefault(model, [0, 0, 0, 0.0, 0])
            spend[0] += 1
            spend[1] += tokens
            spend[2] += cached
            if dollars is None:
                facts.turn_unpriced += 1
                spend[4] += 1
            else:
                facts.turn_dollars += dollars
                spend[3] += dollars
            continue  # turns are summed, not listed
        elif kind == EventKind.INTERVENTION:
            name = _str(data.get("intervention")) or "intervention"
            step = Step(index, _time(event.at), name, event.lane, cid, data)
            if name in VERDICTS and event.lane:  # logged before its effects: what waits now is what it answers
                step.answers = current.pop(event.lane, None)
            steps.append(step)
            open_steps.append(step)
        elif kind == EventKind.OUTCOME:
            name = _str(data.get("intervention"))
            for step in reversed(open_steps):
                if step.name == name and step.lane == event.lane:
                    open_steps.remove(step)
                    ok = data.get("ok")
                    step.ok = ok if isinstance(ok, bool) else None
                    step.message = _str(data.get("message"))
                    if step.ok is False and step.answers is not None and step.lane:
                        current[step.lane] = step.answers  # refused, so it changed nothing: it still waits
                    break
            continue  # shown with its intervention
        elif kind == EventKind.PENDING:
            if event.lane and data.get("queued") is not True:
                current[event.lane] = _str(data.get("kind"))
                flag = data.get("flag")
                if isinstance(flag, str) and flag:
                    asked.setdefault((event.lane, flag), index)
            if _str(data.get("kind")) not in SHOWN_PENDING:
                continue
        if cid:
            by_challenge[cid].append(index)

    # The transcripts: totals the deck kept, names and points, and lanes the log lost.
    for lid, head in record.lanes.items():
        facts = lane(lid)
        facts.record = head
        facts.challenge = facts.challenge or head.challenge
        if head.challenge:
            info = challenge(head.challenge)
            info.name = info.name or head.name
            info.category = info.category or head.category
            info.points = head.points if info.points is None else info.points
        facts.turns, facts.tokens, facts.cached = head.turns, head.tokens, head.cached_tokens
        facts.dollars = _num(head.dollars)  # None stays unknown, and so does a price that is not a number
        facts.add_model(head.model)
        facts.plan = head.plan
        if facts.end is None:
            facts.state = head.state
            facts.result = facts.result or head.result
            facts.ended_at = _time(head.ended_at)
        if facts.start is None:
            facts.started_at = _time(head.started_at)
            facts.parent, facts.attempt = head.parent, head.attempt
    for lid, facts in lanes.items():
        if facts.record is None:
            facts.turns = len(facts.turn_index)
            facts.tokens, facts.cached = facts.turn_tokens, facts.turn_cached
            facts.dollars = None if facts.turn_unpriced else facts.turn_dollars
            notes.append(f"{lid} has no transcript in lanes/ (the run did not close cleanly?): its numbers come from the event log")

    event_name = None
    if board is not None:
        event_name = board.event
        on_board = {item.challenge.id: item.challenge for item in board.challenges}
        if challenges and not set(challenges) & set(on_board):
            notes.append("the board has none of this run's challenges (is it the board this run played?)")
        for cid, info in challenges.items():
            known = on_board.get(cid)
            if known is not None:
                info.name = info.name or known.name
                info.category = info.category or known.category
                info.points = known.points if info.points is None else info.points
    missing = [cid for cid, info in challenges.items() if info.points is None]
    if missing:
        notes.append(
            f"no name or points in the run for {', '.join(missing)}"
            + (" (and not on the board)" if board is not None else " (give --board to fill them in)")
        )
    if unread:
        notes.append(
            "events this report does not read: " + ", ".join(f"{kind} ({count})" for kind, count in sorted(unread.items()))
        )
    if record.ended is None:
        notes.append("the run log has no run-end line: the run did not close cleanly (it crashed, or is still running)")
    duration, untimed = _duration(record)
    if untimed:
        notes.append(
            f"{_plural(untimed, 'event')} in the run log {'has' if untimed == 1 else 'have'} a time that is not "
            "one (not a number, infinite or negative): shown as T+? and left out of the duration"
        )

    solved = solves(record)
    stalls = _stalls(events, lanes, steps)
    judged = _judged(steps, lanes, solved, _proposed(record, asked))
    models = [
        ModelSpend(model, int(s[0]), int(s[1]), int(s[2]), float(s[3]), int(s[4])) for model, s in model_spend.items()
    ]
    return Flight(
        record=record, event=event_name, challenges=challenges, lanes=lanes, solves=solved, steps=steps,
        stalls=stalls, judged=judged, models=models, outside=_outside(lanes),
        l1_runs=len(record.of(L1)), by_challenge=by_challenge, notes=notes, duration=duration,
    )


def solves(record: RunRecord) -> dict[str, Solve]:
    """Who solved each solved challenge: the first solve in the log, by challenge id.

    A solve is an accepted flag (a submit event with `correct` true), a teammate's solve or
    the player's own. An accepted flag that an earlier `l1` event on the challenge reported
    (any status) is L1's, as writeup.solves() has it; an L1 result alone is never a solve."""
    l1_flags: dict[str, dict[str, str]] = {}  # challenge -> flag -> the first engine that reported it
    found: dict[str, Solve] = {}
    for index, event in enumerate(record.events):
        cid, data = event.challenge, event.data
        if not cid or cid in found:
            continue
        at = _time(event.at)
        if event.kind == L1:
            engine = _str(data.get("engine")) or "?"
            for flag in _flags(data):
                l1_flags.setdefault(cid, {}).setdefault(flag, engine)
        elif event.kind == EventKind.SUBMIT and data.get("correct") is True:
            flag = _str(data.get("flag"))
            if flag and flag in l1_flags.get(cid, {}):
                found[cid] = Solve(cid, "l1", l1_flags[cid][flag], at, index, flag, event.lane)
            elif event.lane:
                found[cid] = Solve(cid, "lane", event.lane, at, index, flag, event.lane)
            else:
                found[cid] = Solve(cid, "player", ME, at, index, flag)
        elif event.kind == EventKind.TEAMMATE and data.get("solved") is True:
            who = _str(data.get("who"))
            found[cid] = Solve(cid, "player" if who == ME else "teammate", who, at, index)
    return found


def _stalls(events: Sequence[EventLine], lanes: Mapping[str, LaneFacts], steps: Sequence[Step]) -> list[Stall]:
    on_lane: dict[str, list[Step]] = {}
    for step in steps:
        if step.lane and step.ok:
            on_lane.setdefault(step.lane, []).append(step)
    lines = _alert_lines(events, lanes)
    out = []
    for index, event in enumerate(events):
        if event.kind != EventKind.ALERT or not event.lane or (event.alert or "") in NOT_STALLS:
            continue
        facts = lanes[event.lane]
        kind = event.alert or "?"
        answer = next((s for s in on_lane.get(event.lane, ()) if s.index > index and _answers(s, kind)), None)
        if answer is not None and facts.end is not None and answer.index > facts.end:
            answer = None
        unanswered = ""
        if answer is None:
            if facts.finished:
                unanswered = f"no answer before the lane ended ({facts.state})"
            else:
                unanswered = "no answer; the lane was still open when the run ended"
        head, line = facts.record, lines.get(index)
        # The transcript has the turn the deck counted when it raised the alert; the log's turn
        # events cannot say, since an alert for a turn with no price comes before that turn's event.
        turn = head.actions[line].turn if head is not None and line is not None else facts.turn_before(index)
        solved_turns = None
        if facts.state == "solved":
            if facts.end is not None:
                solved_turns = max(0, facts.turn_before(facts.end) - turn) if facts.end > index else None
            else:  # the log lost its lane.end line; the transcript has its final turn count
                solved_turns = max(0, facts.turns - turn)
        out.append(Stall(
            index, _time(event.at), event.lane, facts.challenge, kind, _str(event.data.get("reason")) or event.text,
            turn, answer, unanswered, solved_turns, _steps_before(head, line, event),
        ))
    return out


def _alert_lines(events: Sequence[EventLine], lanes: Mapping[str, LaneFacts]) -> dict[int, int]:
    """Each lane alert's line in its lane's transcript, as event index -> action index. The
    deck writes the line and the event together (Deck._raise), so the k-th alert of a kind on
    a lane is the k-th alert line of that kind, whatever the clock. When that line does not
    fit (a damaged folder), the last line of that kind no later than the alert stands in."""
    found: dict[tuple[str, str], list[int]] = {}
    for lid, facts in lanes.items():
        for i, action in enumerate(facts.record.actions if facts.record is not None else ()):
            if action.kind == ActionKind.ALERT.value and action.alert:
                found.setdefault((lid, action.alert), []).append(i)
    seen: Counter[tuple[str, str]] = Counter()
    out: dict[int, int] = {}
    for index, event in enumerate(events):
        if event.kind != EventKind.ALERT or not event.lane or not event.alert:
            continue
        key = (event.lane, event.alert)
        k, seen[key] = seen[key], seen[key] + 1
        candidates = found.get(key)
        record = lanes[event.lane].record
        if not candidates or record is None:
            continue
        at = _time(event.at)
        if k < len(candidates) and (at is None or record.actions[candidates[k]].at <= at):
            out[index] = candidates[k]
            continue
        earlier = [i for i in candidates if at is not None and record.actions[i].at <= at]
        if earlier:
            out[index] = earlier[-1]
    return out


def _answers(step: Step, alert: str) -> bool:
    """Whether a step of the player's answers an alert of this kind. An approve or decline
    answers a budget alert only when it answered the budget request, or approved more budget
    with nothing waiting; not when it was a flag's verdict or the live box's."""
    if alert != AlertKind.BUDGET.value:
        return step.name in COURSE_ANSWERS
    if step.name in VERDICTS:
        return step.answers in (None, BUDGET)
    return step.name in BUDGET_ANSWERS


def _steps_before(head: LaneRecord | None, line: int | None, alert: EventLine) -> tuple[str, ...]:
    """The lane's last few steps before an alert, from its transcript: those before the
    alert's own line, or without one, those no later than the alert."""
    at = _time(alert.at)
    if head is None or (line is None and at is None):
        return ()
    before = head.actions[:line] if line is not None else [a for a in head.actions if at is not None and a.at <= at]
    return tuple(a.text for a in before if a.kind == ActionKind.STEP.value)[-STEPS_SHOWN:]


def _proposed(
    record: RunRecord, asked: Mapping[tuple[str, str], int],
) -> dict[tuple[str, str], tuple[int | None, float | None]]:
    """When each lane first proposed each flag, by (lane, flag): the index of the first
    pending event asking about it, and the earliest time known. The transcript's "candidate
    flag" note is written as the lane proposes it, so it is earlier than the pending event of
    a flag that waited behind another."""
    out = {key: (index, _time(record.events[index].at)) for key, index in asked.items()}
    for lid, head in record.lanes.items():
        for action in head.actions:
            if action.kind != ActionKind.NOTE.value or action.by != Actor.DECK.value or not action.text.startswith(CANDIDATE):
                continue
            key, at = (lid, action.text[len(CANDIDATE):]), _time(action.at)
            index, known = out.get(key, (None, None))
            if at is not None and (known is None or at < known):
                out[key] = (index, at)
    return out


def _judged(
    steps: Sequence[Step], lanes: Mapping[str, LaneFacts], solved: Mapping[str, Solve],
    proposed: Mapping[tuple[str, str], tuple[int | None, float | None]],
) -> list[Judged]:
    out = []
    for step in steps:
        if step.name not in JUDGED or not step.ok or not step.challenge:
            continue
        solve = solved.get(step.challenge)
        if solve is None or solve.by != "lane" or solve.index < step.index:
            out.append(Judged(step, solve, None, None, False))
            continue
        index, at = proposed.get((solve.who, solve.flag or ""), (None, None))
        if (index is not None and index < step.index) or (at is not None and step.at is not None and at < step.at):
            out.append(Judged(step, solve, None, None, False, waited=True, since=at))  # its flag came before it
            continue
        solver = lanes.get(solve.who)
        turns = solver.turns_between(step.index, solve.index) if solver else 0
        seconds = solve.at - step.at if solve.at is not None and step.at is not None else None
        helped = turns <= HELP_TURNS or (seconds is not None and seconds <= HELP_SECONDS)
        out.append(Judged(step, solve, turns, seconds, helped))
    return out


def _outside(lanes: Mapping[str, LaneFacts]) -> tuple[int, int, float | None]:
    """Tokens and dollars the transcripts count that no turn event carries (a model reply
    dropped on escalation, for one)."""
    tokens = cached = 0
    dollars: float | None = 0.0
    for facts in lanes.values():
        if facts.record is None:
            continue
        tokens += max(0, facts.tokens - facts.turn_tokens)
        cached += max(0, facts.cached - facts.turn_cached)
        if facts.dollars is None or facts.turn_unpriced:
            if facts.tokens > facts.turn_tokens:
                dollars = None
        elif dollars is not None:
            dollars += max(0.0, facts.dollars - facts.turn_dollars)
    if dollars is not None and abs(dollars) < 1e-9:
        dollars = 0.0
    return tokens, cached, dollars


# ---------------------------------------------------------------------- rendering


def _money(amount: float, unpriced: int, total: int, what: str) -> str:
    """Dollars; or "unknown" when some of `total` ("lanes" or "turns") had no price, with the
    known part as a floor whenever it is above zero. A lane is unpriced when any turn of it
    had no price, though its other turns' dollars are known: every lane can be unpriced while
    most turns had a price."""
    if not unpriced:
        return f"${fmt.dollars(amount)}"
    if amount <= 0:
        return "unknown"
    if what == "lanes":
        which = "the lane" if total == 1 else "every lane" if unpriced >= total else f"{unpriced} of {total} lanes"
        return f"unknown (at least ${fmt.dollars(amount)}; {which} had a turn with no price)"
    return f"unknown (at least ${fmt.dollars(amount)}; {unpriced} of {total} {what} had no price)"


def _spent(flight: Flight) -> str:
    """The run's dollars, for the glance and the summary."""
    dollars, unpriced = flight.dollars
    money = _money(dollars, unpriced, len(flight.lanes), "lanes")
    return money + " (no turn had a price)" if money == "unknown" and not flight.priced_turns else money


def _share(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "0%"


def _clock(at: float | None) -> str:
    return fmt.clock(at) if at is not None else "T+?"


def _later(start: float | None, end: float | None) -> str:
    """How long after `start` `end` came: "30s later", or "at an unknown time"."""
    if start is None or end is None:
        return "at an unknown time"
    return f"{fmt.duration(max(0.0, end - start))} later"


def _duration(record: RunRecord) -> tuple[float, int]:
    """Seconds from the first to the last deck event, and how many deck events have a time
    that is not one (left out)."""
    times = [_time(e.at) for e in record.events if e.kind not in (RUN_START, RUN_END)]
    known = [at for at in times if at is not None]
    return (max(known) - min(known) if known else 0.0), len(times) - len(known)


def _plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _who(solve: Solve) -> str:
    if solve.by == "lane":
        return f"lane {md_text(solve.who)}"
    if solve.by == "l1":
        return f"L1 engine {md_text(solve.who)}"
    if solve.by == "teammate":
        return f"teammate {md_text(solve.who)}"
    return "you"


def _run_name(record: RunRecord) -> str:
    return record.dir.name or record.dir.resolve().name


def report(record: RunRecord, *, board: Board | None = None) -> str:
    """The post-flight report as Markdown."""
    flight = analyse(record, board=board)
    out: list[str] = []
    title = md_text(flight.event) if flight.event else f"run {md_text(_run_name(record))}"
    out += [f"# Post-flight: {title}", ""]
    out += _glance(flight)
    out += _timeline(flight)
    out += _stall_section(flight)
    out += _intervention_section(flight)
    out += _spend_section(flight)
    out += _ended_section(flight)
    if flight.notes:
        out += ["## Problems reading the run", ""]
        out += [f"- {md_text(note, 400)}" for note in flight.notes]
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


def _glance(flight: Flight) -> list[str]:
    record = flight.record
    solved = len(flight.solves)
    got, total, got_unknown, total_unknown = flight.points()
    dollars, unpriced = flight.dollars
    lane_solves = flight.solved_by("lane")
    event = md_text(flight.event) + " (from the board)" if flight.event else "not in the run log (give --board to name it)"
    ended = md_text(record.ended) if record.ended else "no run-end line (the run did not close cleanly)"
    points = f"{'at least ' if got_unknown else ''}{got} of {'at least ' if total_unknown else ''}{total}"
    if total_unknown:
        points += f" ({_plural(total_unknown, 'challenge')} with no known points)"
    if lane_solves and not unpriced:
        per = (f"${fmt.dollars(dollars / lane_solves)} per lane solve "
               f"(${fmt.dollars(dollars)} over {_plural(lane_solves, 'lane solve')})")
    elif lane_solves:
        floor = f"unknown (at least ${fmt.dollars(dollars / lane_solves)} per lane solve); " if dollars else "unknown in dollars; "
        per = floor + f"{fmt.tokens(round(flight.tokens / lane_solves))} tokens per lane solve"
    else:
        per = "no lane solves"
    return [
        "## At a glance", "",
        f"- Event: {event}",
        f"- Run: {md_text(_run_name(record))}, started {md_text(record.started or 'unknown')}, ended {ended}",
        f"- Duration: {fmt.duration(flight.duration)} (first to last event)",
        f"- Challenges: {len(flight.challenges)} on the board, {solved} solved, {len(flight.challenges) - solved} not solved",
        f"- Solves: {solved} (lanes {lane_solves}, L1 {flight.solved_by('l1')}, "
        f"teammates {flight.solved_by('teammate')}, you {flight.solved_by('player')})",
        f"- Points: {points}",
        f"- L1: {_plural(flight.l1_runs, 'engine run')}",
        f"- Lanes: {len(flight.lanes)}, {_plural(flight.turns, 'turn')}",
        f"- Tokens: {fmt.tokens(flight.tokens)} ({flight.tokens:,}), {_share(flight.cached, flight.tokens)} cached",
        f"- Dollars: {_spent(flight)}",
        f"- Cost per solve: {per}",
        "",
    ]


def _timeline(flight: Flight) -> list[str]:
    out = ["## Timeline", ""]
    if not flight.challenges:
        return out + ["No challenges in this run.", ""]
    events = flight.record.events
    steps = {step.index: step for step in flight.steps}
    began = _release_began(events, flight.by_challenge)
    for cid, info in flight.challenges.items():
        solve = flight.solves.get(cid)
        name = md_text(info.name or cid)
        category = md_text(info.category) if info.category else "category unknown"
        points = f"{info.points} pts" if info.points is not None else "points unknown"
        outcome = f"solved by {_who(solve)}" if solve else "not solved"
        out += [f"### {name} ({category}, {points}): {outcome}", ""]
        on = [lane for lane in flight.lanes.values() if lane.challenge == cid]
        if on:
            known, unpriced = _known_dollars(on)
            money = _money(known, unpriced, len(on), "lanes")
            out.append(
                f"{_plural(len(on), 'lane')} ({', '.join(md_text(lane.id) for lane in on)}), "
                f"{_plural(sum(lane.turns for lane in on), 'turn')}, "
                f"{fmt.tokens(sum(lane.tokens for lane in on))} tokens, "
                + (f"dollars {money}" if money.startswith("unknown") else money)
            )
        else:
            out.append("No lanes.")
        out.append("")
        for index, at in _in_order(events, flight.by_challenge.get(cid, ()), began):
            line = _entry(flight, index, events[index], solve, steps)
            if line:
                out.append(f"- {_clock(at)} · {line}")
        out.append("")
    return out


def _first_release(events: Sequence[EventLine], indices: Sequence[int]) -> int | None:
    return next((i for i in sorted(indices) if events[i].kind == EventKind.RELEASE), None)


def _release_began(events: Sequence[EventLine], by_challenge: Mapping[str, Sequence[int]]) -> dict[int, float]:
    """When each release began, by its event index. The deck logs a release after the lanes
    it started and the warnings it raised, a little later on a real clock; the events of its
    challenges logged before it are those (a challenge has nothing before its release), and
    the first of them is when it began."""
    began: dict[int, float] = {}
    for indices in by_challenge.values():
        release = _first_release(events, indices)
        times = [at for i in indices if release is not None and i <= release and (at := _time(events[i].at)) is not None]
        if times:
            began[release] = min(began.get(release, min(times)), min(times))
    return began


def _in_order(
    events: Sequence[EventLine], indices: Sequence[int], began: Mapping[int, float],
) -> list[tuple[int, float | None]]:
    """A challenge's events in the order they were logged (the deck's clock only moves on),
    each with the time to show, except its release, which goes first, at the time it began."""
    order = sorted(indices)
    release = _first_release(events, order)
    if release is None:
        return [(i, _time(events[i].at)) for i in order]
    return [(release, began.get(release))] + [(i, _time(events[i].at)) for i in order if i != release]


def _entry(flight: Flight, index: int, event: EventLine, solve: Solve | None, steps: Mapping[int, Step]) -> str:
    data = event.data
    kind = event.kind
    lane = md_text(event.lane or "?")
    mark = " (the solve)" if solve is not None and solve.index == index else ""
    if kind == EventKind.RELEASE:
        return f"released ({md_text(data.get('label') or 'release')})"
    if kind == L1:  # never the solve itself: its flag is, once accepted
        flags = _flags(data)
        seconds = _num(data.get("seconds"))
        text = f"L1 {md_text(data.get('engine') or '?')}: {md_text(data.get('status') or '?')}"
        text += f" in {seconds:.1f}s" if seconds is not None else ""
        if flags:
            text += ", " + ", ".join(md_code(f) for f in flags[:3]) + (f" and {len(flags) - 3} more" if len(flags) > 3 else "")
        notes = _str(data.get("notes"))
        return text + (f": {md_text(notes)}" if notes else "")
    if kind == EventKind.LANE_START:
        facts = flight.lanes.get(event.lane or "")
        text = f"{lane} started on {md_text(data.get('model') or '?')}"
        if facts and facts.parent:
            text += f", a fork of {md_text(facts.parent)}"
        attempt = _int(data.get("attempt"), 1)
        if attempt > 1:
            text += f", attempt {attempt}"
        approach = _str(data.get("approach"))
        return text + (f": {md_text(approach)}" if approach else "")
    if kind == EventKind.LANE_END:
        facts = flight.lanes.get(event.lane or "")
        state = md_text(data.get("state") or "ended")
        text = f"{lane} {state}"
        if facts:
            models = " → ".join(md_text(m) for m in facts.models) or "?"
            dollars = f"${fmt.dollars(facts.dollars)}" if facts.dollars is not None else "dollars unknown"
            text += f" after {_plural(facts.turns, 'turn')} on {models} ({fmt.tokens(facts.tokens)} tokens, {dollars})"
        result = _str(data.get("result"))
        return text + (f": {md_text(result)}" if result else "")
    if kind == EventKind.ALERT:
        label = _alert_label(event.alert)
        return f"{lane} alert, {label}: {md_text(data.get('reason') or event.text)}"
    if kind == EventKind.INTERVENTION:
        step = steps.get(index)
        return _step_text(step, flight) if step else ""
    if kind == EventKind.SUBMIT:
        ok = data.get("correct")
        verdict = "correct" if ok is True else "wrong" if ok is False else "no verdict"
        how = " (you said the platform accepted it)" if ok is True and data.get("by") == "player" else ""
        how = " (you said the platform rejected it)" if ok is False and data.get("by") == "player" else how
        who = lane if event.lane else "you"
        if mark and solve is not None and solve.by == "l1":
            mark = f" (the solve: the flag L1 engine {md_text(solve.who)} found)"
        return f"{who} submitted {md_code(data.get('flag'))}: {verdict}{how}{mark}"
    if kind == EventKind.TEAMMATE:
        who = md_text(data.get("who") or "a teammate")
        if data.get("solved") is True:
            stopped = data.get("stopped")
            text = f"teammate {who} solved it" if _str(data.get("who")) != ME else "you solved it"
            if isinstance(stopped, list) and stopped:
                text += "; flightdeck stopped " + ", ".join(md_text(s) for s in stopped)
            return text + mark
        if data.get("claimed") is True:
            return f"teammate {who} claimed it"
        return md_text(event.text)
    if kind == EventKind.PENDING:
        return f"{lane} asked for approval: {md_text(data.get('detail') or event.text)}"
    if kind == EventKind.WARNING:
        return f"warning: {md_text(event.text)}"
    return md_text(event.text)


def _alert_label(kind: str | None) -> str:
    try:
        return AlertKind(kind).label
    except ValueError:
        return md_text(kind or "alert")


def _step_text(step: Step, flight: Flight) -> str:
    data = step.data
    name = STEP_NAMES.get(step.name, step.name)
    target = md_text(step.lane) if step.lane else md_text(flight.name(step.challenge or "?"))
    text = f"you: {md_text(name)} {target}"
    if step.name in ("hint", "redirect"):
        text += f": {md_text(data.get('text'))}"
    elif step.name == "fork":
        model = _str(data.get("model"))
        approach = _str(data.get("approach"))
        text += f" on {md_text(model)}" if model else ""
        text += f": {md_text(approach)}" if approach else ""
    elif step.name == "kill":
        text += " (re-queue)" if data.get("requeue") is not False else " (park)"
    elif step.name == "handback" and _str(data.get("note")):
        text += f": {md_text(data.get('note'))}"
    if step.ok is None:
        return text + " (no outcome in the log)"
    if not step.ok:
        return text + f", refused: {md_text(step.message)}"
    return text + (f" → {md_text(step.message)}" if step.message else "")


def _stall_section(flight: Flight) -> list[str]:
    out = ["## Where lanes stalled", ""]
    others = Counter(
        e.alert for e in flight.record.events if e.kind == EventKind.ALERT and (e.alert or "") in NOT_STALLS
    )
    aside = ""
    if others:
        aside = " Not stalls, so only in the timeline: " + ", ".join(
            f"{_plural(n, _alert_label(kind).lower() + ' alert')}" for kind, n in sorted(others.items(), key=lambda kv: str(kv[0]))
        ) + "."
    stalls = flight.stalls
    if not stalls:
        return out + ["No lane raised an alert about its course or budget." + aside, ""]
    answered = sum(1 for s in stalls if s.answer is not None)
    then = sum(1 for s in stalls if s.solved_within)
    lanes = len({s.lane for s in stalls})
    out += [
        f"{_plural(len(stalls), 'alert')} on {_plural(lanes, 'lane')}: {answered} answered, "
        f"{then} followed by that lane solving within {STALL_TURNS} turns.{aside}",
        "",
    ]
    for stall in stalls:
        name = md_text(flight.name(stall.challenge)) if stall.challenge else "an unknown challenge"
        out += [f"### {_clock(stall.at)} · {md_text(stall.lane)} on {name}: {_alert_label(stall.kind)}", ""]
        out.append(f"- When: {_clock(stall.at)}, at turn {stall.turn}")
        out.append(f"- Why: {md_text(stall.reason)}")
        if stall.answer is not None:
            step = stall.answer
            out.append(f"- Answered: {_later(stall.at, step.at)}, {_step_text(step, flight)}")
        else:
            out.append(f"- Answered: {stall.unanswered}")
        out.append(f"- Solved within {STALL_TURNS} turns: {_then(stall, flight)}")
        out.append("")
        if stall.steps:
            out += ["Its last steps before the alert:", "", *md_fence(stall.steps), ""]
    return out


def _then(stall: Stall, flight: Flight) -> str:
    lane = md_text(stall.lane)
    if stall.solved_turns is not None:
        verdict = "yes" if stall.solved_within else "no"
        return f"{verdict}, {lane} solved it {_plural(stall.solved_turns, 'turn')} later"
    solve = flight.solves.get(stall.challenge)
    if solve is not None and solve.index > stall.index:
        return f"no, {lane} did not solve it ({_who(solve)} did)"
    return f"no, {lane} did not solve it"


def _intervention_section(flight: Flight) -> list[str]:
    out = ["## Interventions", ""]
    steps = flight.steps
    if not steps:
        return out + ["No interventions in this run.", ""]
    refused = [s for s in steps if s.ok is False]
    helped = [j for j in flight.judged if j.helped]
    no_effect = [j for j in flight.judged if not j.helped]
    out += [
        f"{_plural(len(steps), 'intervention')}, {len(refused)} refused. A hint, redirect, fork or escalation "
        f"helped when a lane solved that challenge within {HELP_TURNS} turns or {HELP_SECONDS // 60} minutes of it, "
        "with a flag it found after it.",
        "",
        f"### Helped ({len(helped)})", "",
    ]
    out += [_judged_line(j, flight) for j in helped] or ["None."]
    out += ["", f"### No effect seen ({len(no_effect)})", ""]
    out += [_judged_line(j, flight) for j in no_effect] or ["None."]
    out.append("")
    other = Counter(STEP_NAMES.get(s.name, s.name) for s in steps if s.name not in JUDGED and s.ok is not False)
    if other:
        out += [f"### Not judged ({sum(other.values())})", ""]
        out += [", ".join(f"{md_text(name)} {n}" for name, n in sorted(other.items())) + ".", ""]
    if refused:
        out += [f"### Refused, nothing changed ({len(refused)})", ""]
        out += [f"- {_clock(s.at)} · {_step_text(s, flight)}" for s in refused]
        out.append("")
    return out


def _judged_line(judged: Judged, flight: Flight) -> str:
    step = judged.step
    on = md_text(flight.name(step.challenge or "?"))
    head = f"- {_clock(step.at)} · {_step_text(step, flight)} (on {on})"
    solve = judged.solve
    if solve is None:
        return head + "; not solved"
    if judged.waited:
        since = f" since {_clock(judged.since)}" if judged.since is not None else ""
        return head + f"; {md_text(solve.who)} solved it with a flag already waiting{since}"
    if judged.turns is None:
        return head + f"; solved by {_who(solve)}"
    later = f" and {fmt.duration(max(0.0, judged.seconds))}" if judged.seconds is not None else ""
    return head + f"; {md_text(solve.who)} solved it {_plural(judged.turns, 'turn')}{later} later"


def _spend_section(flight: Flight) -> list[str]:
    out = ["## Spend", ""]
    if not flight.lanes:
        return out + ["No lanes ran, so no model spend.", ""]
    out += ["### By model", "", "| Model | Turns | Tokens | Cached | Dollars |", "|---|---:|---:|---:|---:|"]
    for spend in sorted(flight.models, key=lambda s: (-s.tokens, s.model)):
        dollars = _money(spend.dollars, spend.unpriced, spend.turns, "turns")
        out.append(
            f"| {md_text(spend.model) or '(none)'} | {spend.turns} | {spend.tokens:,} | {_share(spend.cached, spend.tokens)} | {dollars} |"
        )
    tokens, cached, dollars = flight.outside
    if tokens or (dollars or 0.0) > 0:
        shown = f"${fmt.dollars(dollars)}" if dollars is not None else "unknown"
        out.append(f"| outside a turn (a reply dropped on escalation, for one) | - | {tokens:,} | {_share(cached, tokens)} | {shown} |")
    out.append("")
    lanes = list(flight.lanes.values())
    priced = all(lane.dollars is not None for lane in lanes)
    if priced:
        top = sorted(lanes, key=lambda lane: (-(lane.dollars or 0.0), -lane.tokens))[:TOP_LANES]
        how = "by dollars"
    else:
        top = sorted(lanes, key=lambda lane: -lane.tokens)[:TOP_LANES]
        unpriced = sum(1 for lane in lanes if lane.dollars is None)
        how = f"by tokens, since {_plural(unpriced, 'lane has', 'lanes have')} no price"
    out += [
        f"### The {min(TOP_LANES, len(lanes))} most expensive lanes", "", f"Ranked {how}.", "",
        "| Lane | Challenge | Models | Turns | Tokens | Cached | Dollars | Ended |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for lane in top:
        models = " → ".join(md_text(m) for m in lane.models) or "-"
        dollars = f"${fmt.dollars(lane.dollars)}" if lane.dollars is not None else "unknown"
        state = md_text(lane.state) if lane.finished else "still open"
        out.append(
            f"| {md_text(lane.id)} | {md_text(flight.name(lane.challenge)) or '-'} | {models} | {lane.turns} | "
            f"{lane.tokens:,} | {_share(lane.cached, lane.tokens)} | {dollars} | {state} |"
        )
    out.append("")
    return out


def _ended_section(flight: Flight) -> list[str]:
    out = ["## Lanes that gave up or were killed", ""]
    ended = [lane for lane in flight.lanes.values() if lane.finished and lane.state in ENDED_WITHOUT_FLAG]
    if not ended:
        out += ["None."]
    words = {"gave up": "gave up", "killed": "was killed", "stopped": "was stopped"}
    for lane in ended:
        when = f" at {_clock(lane.ended_at)}" if lane.ended_at is not None else ""
        reason = md_text(lane.result) if lane.result else "no reason recorded"
        out.append(
            f"- {md_text(lane.id)} on {md_text(flight.name(lane.challenge))} {words[lane.state]}{when} "
            f"after {_plural(lane.turns, 'turn')}: {reason}"
        )
    still = [lane for lane in flight.lanes.values() if not lane.finished]
    if still:
        out += ["", "Still open when the run ended:", ""]
        out += [
            f"- {md_text(lane.id)} on {md_text(flight.name(lane.challenge))} "
            f"({md_text(lane.state or 'state unknown')}, {_plural(lane.turns, 'turn')})"
            for lane in still
        ]
    out.append("")
    return out


def summary(record: RunRecord, *, board: Board | None = None) -> str:
    """The run in a few plain lines for the terminal (untrusted text folded and made visible)."""
    flight = analyse(record, board=board)
    got, total, got_unknown, total_unknown = flight.points()
    dollars, unpriced = flight.dollars
    lane_solves = flight.solved_by("lane")
    title = _plain(flight.event) if flight.event else "event not in the run log"
    points = f"{got} of {total} points" + (" (some points unknown)" if got_unknown or total_unknown else "")
    if not unpriced:
        money = f"${fmt.dollars(dollars)}"
        if lane_solves:
            money += f", ${fmt.dollars(dollars / lane_solves)} per lane solve"
    else:
        money = "dollars " + _spent(flight)
    lines = [
        f"Post-flight: {title}, run {_plain(_run_name(record))}",
        f"{fmt.duration(flight.duration)}, {_plural(len(flight.challenges), 'challenge')}, {len(flight.solves)} solved "
        f"(lanes {lane_solves}, L1 {flight.solved_by('l1')}, teammates {flight.solved_by('teammate')}, "
        f"you {flight.solved_by('player')}), {points}",
        f"Spend: {fmt.tokens(flight.tokens)} tokens ({_share(flight.cached, flight.tokens)} cached), {money}",
    ]
    stalls = flight.stalls
    if stalls:
        answered = sum(1 for s in stalls if s.answer is not None)
        then = sum(1 for s in stalls if s.solved_within)
        lines.append(
            f"Stalls: {_plural(len(stalls), 'alert')}, {answered} answered, {then} then solved within {STALL_TURNS} turns"
        )
    if flight.judged:
        helped = sum(1 for j in flight.judged if j.helped)
        lines.append(f"Interventions: {helped} helped, {len(flight.judged) - helped} no effect seen")
    states = Counter(lane.state if lane.finished else "still open" for lane in flight.lanes.values())
    if states:
        order = ("solved", "gave up", "killed", "stopped", "still open")
        parts = [f"{states[s]} {s}" for s in order if states.get(s)]
        parts += [f"{n} {_plain(s)}" for s, n in sorted(states.items()) if s not in order]
        lines.append(f"Lanes: {len(flight.lanes)} ({', '.join(parts)})")
    if record.ended is None:
        lines.append("The run did not close cleanly (no run-end line).")
    if flight.notes:
        lines.append(f"{_plural(len(flight.notes), 'problem')} reading the run: see the report")
    return "\n".join(lines) + "\n"
