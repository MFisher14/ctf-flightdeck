"""A lane's state in a few lines: what a stronger model reads on escalation, and what the
console can show about a lane.

The deck's EscalationSummary (core/model.py) is thin: the challenge, the plan, the last
four commands and the alerts. lane_summary() says more, in this order:

    Challenge: name (category, 50 pts, 88 solves); files: the handout
    Plan: the lane's plan
    So far: turns, tokens and the models that took the turns (and how a finished lane ended)
    Last steps (n of m):              then one line per step, newest last:
      turn 12: the command → its output
    Files changed: path (status, turn n), ...
    Candidate flags: "flag" (what became of it); ...
    Not the flag: "flag" (why); ...                  only when a flag is known not to be it
    Open alerts: label: reason; ...
    Player's messages: text (turn n); ...

Everything that came from a challenge, a lane, a tool, a model or the player is untrusted.
Each such field is folded onto one line (text.untrusted with one_line=True) and then
shortened, so no value can start a line of its own: the lines and their labels are
flightdeck's. A flag is also shown as a JSON string (in double quotes, with its own quotes
and backslashes escaped), so where it ends is plain and no flag text can pass for a
verdict. A model gets the summary inside agent/prompts.fenced(), which marks all of it
as data and removes anything that reads as a fence marker.

The whole summary stays within max_chars: the oldest steps go first; if the
other lines alone are still too long, the longest of them are cut to fair shares.

What became of a lane's candidate flags is read from its log, in order: the deck's own
notes (a lane's steps, which a model writes, are never read for it) and the player's
answers. The kind and flag of each approval come from the PENDING event the deck logs
whenever an approval comes up, so a decline counts against a flag only when the player
declined a submit. Which flags are known not to be the flag comes from Deck.not_flag().
The notes are matched by deck.py's wording; tests/test_summary.py pins it through a real
Deck.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import TYPE_CHECKING

from .. import fmt
from ..text import untrusted
from .model import FLAG_PENDING, ActionKind, Actor, Challenge, EscalationSummary, EventKind, Lane, PendingKind

if TYPE_CHECKING:
    from .deck import Deck

STEPS = 6  # the newest steps shown
MIN_CHARS = 300  # less cannot hold the eight lines' labels
CUT = "…"  # marks text that was shortened

# Longest shown, in characters after folding: one field each.
NAME = 80  # a challenge name, a model, a handout file
CATEGORY = 40
PLAN = 400
COMMAND = 160
OUTPUT = 160
PATH = 100  # a file the lane changed
STATUS = 20
FLAG = 100  # before it is quoted
WHY = 80  # why a flag is known not to be the flag
ALERT = 240  # an alert's label and reason
MESSAGE = 200
RESULT = 160  # how a finished lane ended

# How many shown: the rest are counted.
HANDOUT = 12  # the first ones, in board order
FILES = 12  # the newest ones
FLAGS = 8  # the newest ones (candidate flags, and flags known not to be the flag)
MESSAGES = 6  # the newest ones

# The deck's notes about candidate flags (deck.py: _candidate, _verdict), matched exactly.
CANDIDATE = "candidate flag "
MALFORMED = re.compile(r"candidate (?P<flag>.*) does not match the flag format; not submitted", re.DOTALL)
AGAIN = re.compile(r"candidate (?P<flag>.*) again; not asked: .*", re.DOTALL)  # a flag known not to be it
SUBMITTED = "submitted "
VERDICTS = (  # how the note ends (no ending is the end of another), and what it means
    (": correct (you said so)", "correct"),
    (": incorrect (you said so)", "wrong"),
    (": correct", "correct"),
    (": incorrect", "wrong"),
)
DECLINED = "declined: "  # the player's note on declining the approval that was up (deck.py: _decline)


def lane_summary(
    deck: Deck, lane: Lane, *, max_chars: int = 3000, before: EscalationSummary | None = None
) -> str:
    """`lane` as a compact summary of at most `max_chars` characters (see the module doc).

    `before` is the snapshot the deck hands LaneDriver.escalate(). By the time the driver
    runs, the deck has moved the lane to the stronger model and cleared the course alerts
    the player answered by escalating; pass it from escalate() so the summary still names
    them (its alerts replace the lane's). The models come from the deck's turn events, so
    the summary says which model took the turns and which one has the lane now.
    """
    if max_chars < MIN_CHARS:
        raise ValueError(f"max_chars must be at least {MIN_CHARS} to hold the summary's labels, got {max_chars}")
    if before is not None and before.lane != lane.id:
        raise ValueError(f"`before` is the summary of {before.lane}, not of {lane.id}")
    challenge = deck.challenges[lane.challenge_id]
    head = [_challenge_line(challenge), _plan_line(lane), _so_far_line(deck, lane)]
    tail = [
        line
        for line in (
            _files_line(lane),
            _flags_line(deck, lane),
            _not_flags_line(deck, lane),
            _alerts_line(lane, before),
            _messages_line(lane),
        )
        if line is not None
    ]
    every_step = [a for a in lane.actions if a.kind is ActionKind.STEP]
    steps = [_step_line(a.turn, a.text, a.output) for a in every_step[-STEPS:]]
    while True:
        lines = [*head, _steps_header(len(steps), len(every_step)), *steps, *tail]
        text = "\n".join(lines)
        if len(text) <= max_chars or not steps:
            break
        steps.pop(0)  # the oldest step goes first
    if len(text) > max_chars:  # no steps left, and the other lines alone are too long
        text = "\n".join(_fair_cut(lines, max_chars - (len(lines) - 1)))
    return text


# ---------------------------------------------------------------------- the lines


def _challenge_line(ch: Challenge) -> str:
    files = [_one(name, NAME) for name in ch.files]
    shown = ", ".join(files[:HANDOUT]) or "none"
    if len(files) > HANDOUT:
        shown += f" and {len(files) - HANDOUT} more"
    return (
        f"Challenge: {_one(ch.name, NAME)} ({_one(ch.category, CATEGORY)}, {ch.points} pts, "
        f"{ch.solves} solves); files: {shown}"
    )


def _plan_line(lane: Lane) -> str:
    return f"Plan: {_one(lane.plan, PLAN) or '(none)'}"


def _so_far_line(deck: Deck, lane: Lane) -> str:
    runs: list[list] = []  # [model, turns] for each run of turns on one model, oldest first
    for event in deck.events:
        if event.kind is EventKind.TURN and event.lane == lane.id:
            model = str(event.data["model"])
            if runs and runs[-1][0] == model:
                runs[-1][1] += 1
            else:
                runs.append([model, 1])
    line = f"So far: {_count(lane.turns, 'turn')}, {fmt.tokens(lane.tokens)} tokens on "
    if len(runs) > 1:
        line += ", then ".join(f"{_one(model, NAME)} ({_count(n, 'turn')})" for model, n in runs)
    else:
        line += _one(runs[0][0] if runs else lane.model, NAME)
    if runs and runs[-1][0] != lane.model:
        line += f"; now on {_one(lane.model, NAME)}"
    if lane.finished:
        line += f"; {lane.state.value}: {_one(lane.result, RESULT) or 'no reason given'}"
    return line


def _steps_header(shown: int, total: int) -> str:
    if total == 0:
        return "Last steps: none yet"
    if shown == 0:
        return f"Last steps: {total}, none shown (cut to fit)"
    return f"Last steps ({shown} of {total}):"


def _step_line(turn: int, command: str, output: str) -> str:
    return f"  turn {turn}: {_one(command, COMMAND) or '(no command)'} → {_one(output, OUTPUT) or '(no output)'}"


def _files_line(lane: Lane) -> str:
    items = [f"{_one(c.path, PATH)} ({_one(c.status, STATUS)}, turn {c.turn})" for c in lane.files.values()]
    return _listing("Files changed", items, FILES, ", ")


def _flags_line(deck: Deck, lane: Lane) -> str:
    items = [f"{_quoted(flag)} ({', then '.join(fates)})" for flag, fates in _flag_fates(deck, lane).items()]
    return _listing("Candidate flags", items, FLAGS)


def _not_flags_line(deck: Deck, lane: Lane) -> str | None:
    """The flags known not to be the flag of the lane's challenge, found by any lane, with
    the deck's reason (Deck.not_flag); None if there are none. Every such flag was up for
    approval (a PENDING event) or submitted (a SUBMIT event): they are listed in the order
    they first came up."""
    seen: set[str] = set()
    items: list[str] = []
    for event in deck.events:
        if event.challenge != lane.challenge_id or event.kind not in (EventKind.PENDING, EventKind.SUBMIT):
            continue
        flag = event.data.get("flag")
        if not isinstance(flag, str) or flag in seen:
            continue
        seen.add(flag)
        why = deck.not_flag(lane.challenge_id, flag)
        if why is not None:
            items.append(f"{_quoted(flag)} ({_one(why, WHY)})")
    return _listing("Not the flag", items, FLAGS) if items else None


def _alerts_line(lane: Lane, before: EscalationSummary | None) -> str:
    alerts = before.alerts if before is not None else tuple(f"{a.kind.label}: {a.reason}" for a in lane.alerts)
    return _listing("Open alerts", [_one(a, ALERT) for a in alerts], None)


def _messages_line(lane: Lane) -> str:
    """The player's messages (hints), oldest first. Those still in lane.hints were sent
    after the lane's last turn: the newest ones, as the deck queues them in order."""
    messages = [a for a in lane.actions if a.kind is ActionKind.MESSAGE and a.by is Actor.PLAYER]
    first_unread = len(messages) - min(len(lane.hints), len(messages))
    items = [
        f"{_one(a.text, MESSAGE)} (turn {a.turn}{', not read yet' if i >= first_unread else ''})"
        for i, a in enumerate(messages)
    ]
    return _listing("Player's messages", items, MESSAGES)


# ---------------------------------------------------------------------- flags


def _flag_fates(deck: Deck, lane: Lane) -> dict[str, list[str]]:
    """Each candidate flag (in the order the lane found them) and what became of it, in
    order. Read from the deck's notes, the player's answers and the approvals only."""
    flag_re = re.compile(deck.config.flag_format)
    approvals = _approvals(deck, lane)
    up: Mapping[str, object] | None = None  # the approval that is up: its PENDING event's data
    fates: dict[str, list[str]] = {}
    for n, action in enumerate(lane.actions):
        text = action.text
        if action.by is Actor.DECK and action.kind is ActionKind.APPROVAL:
            up = next(approvals, None)
            if up is None or up.get("detail") != text:
                raise RuntimeError(
                    f"{lane.id}'s log and the deck's PENDING events disagree about the approval at "
                    f"entry {n}, so the summary cannot tell what the player approved or declined"
                )
            if up.get("kind") in FLAG_PENDING and isinstance(up.get("flag"), str):
                fates.setdefault(str(up["flag"]), [])
        elif action.by is Actor.DECK and action.kind is ActionKind.NOTE:
            if text.startswith(CANDIDATE) and flag_re.fullmatch(text[len(CANDIDATE):]):
                fates.setdefault(text[len(CANDIDATE):], [])
            elif (malformed := MALFORMED.fullmatch(text)) is not None:
                _fate(fates, malformed["flag"], "not the flag format")
            elif (again := AGAIN.fullmatch(text)) is not None and (
                deck.not_flag(lane.challenge_id, again["flag"]) is not None  # the deck says so only of such a flag
            ):
                _fate(fates, again["flag"], "not asked again")
            elif text.startswith(SUBMITTED):
                for suffix, fate in VERDICTS:
                    if text.endswith(suffix):
                        flag = text[len(SUBMITTED) : -len(suffix)]
                        if flag in fates:
                            _fate(fates, flag, fate)
                        break
        elif action.by is Actor.PLAYER and action.kind is ActionKind.PLAYER and text.startswith(DECLINED):
            # The player said no to the approval that was up. Only a declined submit is a
            # flag not submitted: a confirmation answered no is a verdict (a note of its
            # own), and a live box or a budget is no flag, whatever its detail says.
            if up is not None and up.get("kind") == PendingKind.SUBMIT and isinstance(up.get("flag"), str):
                _fate(fates, str(up["flag"]), "declined by the player")
    for pending in [lane.pending, *lane.waiting]:
        if pending is not None and pending.kind in FLAG_PENDING and pending.flag is not None:
            if pending.kind is PendingKind.SUBMIT:
                _fate(fates, pending.flag, "waits for approval")
            else:
                _fate(fates, pending.flag, "waits for the player to submit it and confirm")
    for said in fates.values():
        if not said:
            said.append("not answered before the lane ended" if lane.finished else "not answered")
    return fates


def _approvals(deck: Deck, lane: Lane) -> Iterator[Mapping[str, object]]:
    """The data (kind, detail, flag) of each approval that came up on the lane, in order:
    the deck logs a PENDING event with each APPROVAL entry in the lane's log. A PENDING
    event marked "queued" is an approval waiting behind another: it comes up later."""
    for event in deck.events:
        if event.kind is EventKind.PENDING and event.lane == lane.id and not event.data.get("queued"):
            yield event.data


def _fate(fates: dict[str, list[str]], flag: str, fate: str) -> None:
    said = fates.setdefault(flag, [])
    if not said or said[-1] != fate:
        said.append(fate)


# ---------------------------------------------------------------------- helpers


def _one(text: str, cap: int) -> str:
    """`text` on one line and safe to show, at most `cap` characters (CUT marks a cut).

    Folded first and cut after, so a fold (a newline becomes three characters) cannot
    take a field past its cap. Folding never shortens text, so folding `cap + 1`
    characters is enough to know whether it must be cut."""
    text = text.strip()
    folded = untrusted(text[: cap + 1], one_line=True)
    return folded if len(folded) <= cap else folded[: cap - 1] + CUT


def _quoted(flag: str) -> str:
    """A flag on one line, at most FLAG characters, as a JSON string: in double quotes, its
    own quotes and backslashes escaped, so a flag cannot seem to end early."""
    return json.dumps(_one(flag, FLAG), ensure_ascii=False)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" + ("" if n == 1 else "s")


def _listing(label: str, items: Sequence[str], limit: int | None, sep: str = "; ") -> str:
    """`label: a; b; c`, or the newest `limit` items with the count in the label."""
    if not items:
        return f"{label}: none"
    if limit is None or len(items) <= limit:
        return f"{label}: {sep.join(items)}"
    return f"{label} (the last {limit} of {len(items)}): {sep.join(items[-limit:])}"


def _fair_cut(lines: list[str], budget: int) -> list[str]:
    """`lines` cut to `budget` characters in all: lines shorter than a fair share stay
    whole, and the longer ones share what they leave equally."""
    limits = [0] * len(lines)
    left = budget
    for k, i in enumerate(sorted(range(len(lines)), key=lambda i: len(lines[i]))):
        limits[i] = min(len(lines[i]), left // (len(lines) - k))
        left -= limits[i]
    return [_cut(line, n) for line, n in zip(lines, limits)]


def _cut(line: str, n: int) -> str:
    if len(line) <= n:
        return line
    return line[: n - 1] + CUT if n > 0 else ""
