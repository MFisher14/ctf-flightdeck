"""What the lanes of one challenge share: the record of what each lane tried and how it came out.

A challenge is worked by several lanes over a run: a fork, a fresh lane after a kill or a park,
the next rung of the model ladder, an escalation. Without a shared record the work repeats: a
second lane runs the scans the first one ran, and a wrong "found it" is found again. The record
is the harness's own. Nothing asks a model to write it: it is read from what the deck already
holds of each lane (its log, its plan, its files, the deck's events), so a lane cannot leave
its entry out, and what an entry says of a flag is the deck's word, never the lane's.

The grain is one entry per lane (Attempt), not one per command. A lane runs tens to hundreds of
commands, and the harness does not know which of them "found something": what it knows is the
plan the lane set, which programs its shell commands ran and how often, its last steps, what it
reported finding, the files it changed, what became of each flag it gave (the deck's notes and
the player's answers: core/summary.py), the alerts the detectors raised on it (a loop, a stall,
effort past the challenge's value: the harness's own verdict on its course) and how it ended
(gave up and why, killed, stopped, still running). So an entry says "this approach, with these
tools, ended this way", which is what a later lane needs to not repeat it:

    L02 (small, then big; fork of L01; 14 turns): gave up: 3 replies in a row without a tool call
      The player asked for: try the audio track
      Plan: the lane's plan
      Ran: zsteg (9), binwalk (3), python (2); 14 steps in all
      turn 13: the command → its output             the newest LAST_STEPS steps, newest last
      Found: what the lane reported finding, ...
      Files it changed: path (status), ...
      Flags it gave: "flag" (what became of it); ...
      Alerts on it: label: reason; ...

A line with nothing to say is left out. A lane that solved its challenge is said to have solved
it, without its result line (which holds the flag).

"Ran" counts programs, not commands: of each shell command (a step that starts with "$ ", and
every tool call of a turn of flightdeck's own loop) the first word of each part between `|`,
`;`, `&&` and `||`, without its folder, past a variable assignment or a wrapper (sudo, timeout
N, ...), kept only when it reads as a program's name (PROGRAM); a use of the python tool counts
as "python". The words that say nothing of a method (cd, ls, cat, echo, ...: PLAIN) are not
counted. It is a count of names read from text a model wrote, so it can miss or miscount; it
never runs or parses anything.

What a later lane reads (others_text). The entries of every other lane on its challenge, the
most useful first: the lanes still open (what they do now is what a new lane must not double;
a fork's parent first of them), then the ended ones by the turns they took, most first (a lane
that worked for forty turns ruled out more than one killed at its first), newer first among
equals. Each entry is at most ENTRY characters (its longest lines cut to fair shares, its first line last) and the
whole at most `max_chars` (MAX_TEXT): the text is in every fresh context of the lane that reads
it, so it costs every turn. MAX_TEXT is 3,000 characters, some 750 tokens: what a lane's own
summary gets (core/summary.lane_summary), under the L1 results' 4,000 and half a description's
6,000, and about 1.5% of the 50,000 prompt tokens at which a lane's context is refreshed. At
least three whole entries fit; the lanes that do not are counted and named, not shown.

Everything in an entry but its counts, the lane ids and flightdeck's own labels came from a
challenge, a lane, a tool, a model or the player: untrusted. Each such field is folded onto one
line and cut (core/summary's helpers), so no value can start a line of its own; a flag is shown
as a JSON string. Hand the text to a model inside agent/prompts.fenced(), as agent/sharing.py
does. A lane's reports have the run's held secrets out of them already (agent/held.py).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from .model import ActionKind, EventKind, Lane, LaneState
from .summary import ALERT, ARTIFACT, NAME, PATH, RESULT, STATUS, _count, _fair_cut, _flag_fates, _one, _quoted

if TYPE_CHECKING:
    from .deck import Deck

MAX_TEXT = 3000  # characters of what a lane reads of the other lanes on its challenge (see the module doc)
ENTRY = 900  # characters of one lane's entry
MIN_TEXT = 400  # a smaller cap would hold little more than an entry's first line
MORE = 160  # characters kept free for the line that counts the lanes not shown
MORE_NAMES = 12  # the lanes that line names
LAST_STEPS = 2  # the newest steps of a lane kept in its entry
PROGRAMS = 12  # the programs named in "Ran", most used first
FOUND = 6  # the newest things a lane reported finding
FILES = 8  # the newest files a lane changed
FLAGS = 6  # the newest flags a lane gave
ALERTS = 4  # the newest kinds of alert raised on a lane
APPROACH = 200  # characters of the player's own direction
PLAN = 300
COMMAND = 120
OUTPUT = 120
MAX_COMMAND = 4000  # characters of one command read for the programs it ran

PROGRAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,31}")
_PARTS = re.compile(r"\|\||&&|[|;\n]")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
WRAPPERS = frozenset({"sudo", "time", "nice", "nohup", "env", "exec", "command", "stdbuf", "timeout"})
PLAIN = frozenset({
    "cd", "ls", "cat", "echo", "pwd", "head", "tail", "true", "false", "test", "mkdir", "cp", "mv", "rm", "chmod",
    "export", "printf", "wc", "sort", "uniq", "touch", "less", "more", "which", "id", "sleep", "set", "source",
})
"""Shell words that say nothing of a lane's method: never counted in "Ran"."""

OPEN_STATES = {
    LaneState.RUNNING: "working now",
    LaneState.WAITING: "waiting for the player's answer",
    LaneState.PAUSED: "paused by the player",
    LaneState.TAKEOVER: "in the player's hands (a take-over)",
}
SOLVED = "solved the challenge"


@dataclass(frozen=True)
class Attempt:
    """One lane's entry in its challenge's record, as the deck holds the lane now. Every text
    field is as the lane, the model or the player wrote it (untrusted, not cut): entry() makes
    it safe to show."""

    lane: str
    challenge: str  # the challenge's id
    models: tuple[str, ...]  # the models that took its turns, in order; the lane's model when it took none
    how: str  # "fork of L01", "attempt 2", or ""
    state: str  # the lane's state (LaneState's value)
    open: bool  # the lane has not ended
    ended: str  # how it ended, one line; "" while it is open; never the flag that solved it
    turns: int
    approach: str  # the player's own direction for it
    plan: str  # the lane's plan, as it last set it
    programs: tuple[tuple[str, int], ...]  # each program its shell commands ran and how often, most used first
    steps: int  # the steps it took
    last_steps: tuple[tuple[int, str, str], ...]  # its newest steps, newest last: (turn, command, output)
    found: tuple[str, ...]  # what it reported finding, oldest first
    files: tuple[tuple[str, str], ...]  # the files it changed, newest last: (path, status)
    flags: tuple[tuple[str, tuple[str, ...]], ...]  # each flag it gave and what became of it, in order
    alerts: tuple[tuple[str, str], ...]  # each kind of alert raised on it, with its newest reason: (label, reason)

    def data(self) -> dict[str, object]:
        """The entry as plain data (for the run folder's record)."""
        return asdict(self)


def attempt(deck: Deck, lane: Lane) -> Attempt:
    """`lane`'s entry, read from the deck as it stands (see the module doc)."""
    steps = [a for a in lane.actions if a.kind is ActionKind.STEP]
    alerts: dict[str, str] = {}
    for action in lane.actions:
        if action.kind is ActionKind.ALERT:
            alerts.pop(action.text, None)
            alerts[action.text] = action.output  # the newest reason, and the newest kind last
    how = f"fork of {lane.parent}" if lane.parent else ""
    if lane.attempt > 1:
        how += ("; " if how else "") + f"attempt {lane.attempt}"
    if not lane.finished:
        ended = ""
    elif lane.state is LaneState.SOLVED:
        ended = SOLVED  # its result line holds the flag
    else:
        ended = f"{lane.state.value}: {lane.result or 'no reason given'}"
    return Attempt(
        lane=lane.id,
        challenge=lane.challenge_id,
        models=_models(deck, lane),
        how=how,
        state=lane.state.value,
        open=not lane.finished,
        ended=ended,
        turns=lane.turns,
        approach=lane.approach,
        plan=lane.plan,
        programs=programs(text for step in steps for text in ([call.text for call in step.calls] or [step.text])),
        steps=len(steps),
        last_steps=tuple((a.turn, a.text, a.output) for a in steps[-LAST_STEPS:]),
        found=tuple(lane.artifacts),
        files=tuple((change.path, change.status) for change in lane.files.values()),
        flags=tuple((flag, tuple(fates)) for flag, fates in _flag_fates(deck, lane).items()),
        alerts=tuple(alerts.items()),
    )


def record(deck: Deck, challenge_id: str) -> list[Attempt]:
    """The challenge's record: the entry of every lane that worked or works it, oldest lane first."""
    lanes = sorted((lane for lane in deck.lanes.values() if lane.challenge_id == challenge_id), key=lambda lane: lane.number)
    return [attempt(deck, lane) for lane in lanes]


def others(deck: Deck, lane: Lane) -> list[Attempt]:
    """The entries of the other lanes on `lane`'s challenge, the most useful first: the open
    ones (its parent first), then the ended ones by turns, most first; newer first among equals."""
    lanes = [other for other in deck.lanes.values() if other.challenge_id == lane.challenge_id and other.id != lane.id]
    lanes.sort(key=lambda other: (other.finished, other.id != lane.parent, -other.turns if other.finished else 0, -other.number))
    return [attempt(deck, other) for other in lanes]


def others_text(deck: Deck, lane: Lane, *, max_chars: int = MAX_TEXT) -> str:
    """What `lane` reads of the other lanes on its challenge, in at most `max_chars`
    characters; "" when it is the only lane that ever worked it. Untrusted text: hand it to a
    model fenced (see the module doc)."""
    if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars < MIN_TEXT:
        raise ValueError(f"max_chars must be a whole number of at least {MIN_TEXT}, got {max_chars!r}: a smaller text "
                         "would hold little more than an entry's first line")
    attempts = others(deck, lane)
    return listing([entry(a, max_chars=min(ENTRY, max_chars - MORE)) for a in attempts], [a.lane for a in attempts], max_chars)


def listing(entries: list[str], names: list[str], max_chars: int) -> str:
    """`entries` (each a lane's, named in `names`; each at most `max_chars` - MORE characters),
    a line apart: as many of the first as fit in `max_chars` together with the line that counts
    and names the rest. The first entry is always shown."""
    shown: list[str] = []
    for i, text in enumerate(entries):
        rest = names[i + 1:]
        size = sum(len(s) + 1 for s in shown) + len(text) + (len(_more(rest)) + 1 if rest else 0)
        if size > max_chars and shown:
            break
        shown.append(text)
    left = names[len(shown):]
    if left:
        shown.append(_more(left))
    return "\n".join(shown)


def _more(names: list[str]) -> str:
    """The line for the lanes not shown: at most MORE characters, with its line break."""
    named = ", ".join(names[:MORE_NAMES]) + (", ..." if len(names) > MORE_NAMES else "")
    return f"{_count(len(names), 'more lane')} not shown, to keep this short: {named}"


def entry(a: Attempt, *, flags: bool = True, max_chars: int = ENTRY) -> str:
    """One lane's entry as text (the module doc shows its lines), in at most `max_chars`
    characters. `flags` False leaves out the flags it gave (a sibling challenge's lane: its
    flags are no business of another challenge's lane)."""
    models = ", then ".join(_one(model, NAME) for model in a.models)
    turns = _count(a.turns, "turn") + (" so far" if a.open else "")
    how = f"{_one(a.how, NAME)}; " if a.how else ""
    state = OPEN_STATES.get(LaneState(a.state), a.state) if a.open else _one(a.ended, RESULT)
    lines = [f"{a.lane} ({models}; {how}{turns}): {state}"]
    if a.approach.strip():
        lines.append(f"  The player asked for: {_one(a.approach, APPROACH)}")
    if a.plan.strip():
        lines.append(f"  Plan: {_one(a.plan, PLAN)}")
    if a.steps:
        ran = ", ".join(f"{name} ({n})" for name, n in a.programs)
        lines.append(f"  Ran: {ran + '; ' if ran else ''}{_count(a.steps, 'step')} in all")
    for turn, command, output in a.last_steps:
        lines.append(f"  turn {turn}: {_one(command, COMMAND) or '(no command)'} → {_one(output, OUTPUT) or '(no output)'}")
    if a.found:
        lines.append("  " + _newest("Found", [_one(item, ARTIFACT) for item in a.found], FOUND, ", "))
    if a.files:
        lines.append("  " + _newest("Files it changed", [f"{_one(path, PATH)} ({_one(status, STATUS)})" for path, status in a.files],
                                    FILES, ", "))
    if flags and a.flags:
        lines.append("  " + _newest("Flags it gave", [f"{_quoted(flag)} ({', then '.join(fates)})" for flag, fates in a.flags],
                                    FLAGS, "; "))
    if a.alerts:
        lines.append("  " + _newest("Alerts on it", [_one(f"{label}: {reason}", ALERT) for label, reason in a.alerts], ALERTS, "; "))
    if sum(len(line) + 1 for line in lines) - 1 > max_chars:
        # the first line (who, and how it ended) stays whole while it fits; the others share what is left
        head = lines[:1] if len(lines[0]) + len(lines) - 1 <= max_chars else []
        rest = lines[len(head):]
        budget = max_chars - sum(len(line) + 1 for line in head) - (len(rest) - 1)
        lines = head + [line for line in _fair_cut(rest, max(0, budget)) if line]
    return "\n".join(lines)


def programs(commands) -> tuple[tuple[str, int], ...]:
    """The programs the shell commands among `commands` ran (step texts: "$ zsteg -a x.png |
    grep flag", "python: ..."), each with how often, most used first (ties: first seen first), at
    most PROGRAMS. See the module doc: names read from text, nothing parsed or run."""
    counts: Counter[str] = Counter()
    for text in commands:
        if text.startswith("python:"):
            counts["python"] += 1
            continue
        if not text.startswith("$ "):
            continue
        for part in _PARTS.split(text[2 : 2 + MAX_COMMAND]):
            name = _program(part.split())
            if name is not None:
                counts[name] += 1
    return tuple(counts.most_common(PROGRAMS))


def _program(words: list[str]) -> str | None:
    """The program a part of a command line runs, or None when its first word is no program's
    name or one of PLAIN."""
    i = 0
    while i < len(words):
        word = words[i]
        if _ASSIGNMENT.match(word) or word.startswith("-"):
            i += 1  # VAR=value before the command, an option of a wrapper
        elif word in WRAPPERS:
            i += 1
            if word == "timeout" and i < len(words) and words[i][:1].isdigit():
                i += 1  # its duration
        else:
            break
    if i >= len(words):
        return None
    name = words[i].rsplit("/", 1)[-1]
    if PROGRAM.fullmatch(name) is None or name in PLAIN:
        return None
    return name


def _models(deck: Deck, lane: Lane) -> tuple[str, ...]:
    """The models that took the lane's turns, in order (the deck's turn events), each once in
    a row; the lane's own model when it took no turn."""
    models: list[str] = []
    for event in deck.events:
        if event.kind is EventKind.TURN and event.lane == lane.id:
            model = str(event.data["model"])
            if not models or models[-1] != model:
                models.append(model)
    return tuple(models) or (lane.model,)


def _newest(label: str, items: list[str], limit: int, sep: str) -> str:
    if len(items) <= limit:
        return f"{label}: {sep.join(items)}"
    return f"{label} (the last {limit} of {len(items)}): {sep.join(items[-limit:])}"

