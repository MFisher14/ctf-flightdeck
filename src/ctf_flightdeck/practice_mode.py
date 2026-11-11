"""Practice mode: replay an archived board offline, and score a run from its event log.

An archive is a folder board (platform/manual.py) with, optionally:

- `timeline.json` at the board's root: when each challenge reached the board in the real
  event, as waves: {"waves": [{"at": <seconds from the start>, "ids": [<challenge id>, ...]}]}.
  A challenge that no wave lists goes out at the start (0); without the file the whole
  board goes out at the start. Unknown keys are an error, as in every board file.
- an answers file outside every challenge directory (`answers.sha256.json` at the board's
  root, or one named with --answers): the sha256 of each flag. load_board() checks that it
  sits outside the handouts.

`Release` puts each wave on the deck when the deck's clock reaches its time. It has no
timer of its own: call tick() from one on the console's event loop (the deck's thread).

`score()` reads a run's events.jsonl and nothing else, so it works on any past run: what
was solved, when and by which lane, the tokens and dollars of the model turns, the
player's interventions and the wrong submissions. With an answers file on the board, each
submitted flag is checked against it again, so a run is scored against the answers and not
only by what it was told at the time. Tokens and dollars come from the log's turn events: a
cost the deck was told about outside a turn (a non-turn report) is not in the log, so it is
not in the score either. `scorecard()` is a score as plain text for the terminal. It never
shows a flag, and every name in it is folded to one safe line.

Everything read from a board, a timeline or a log is untrusted: checked field by field, and
shown in messages only made safe.
"""

from __future__ import annotations

import json
import math
import stat
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType

from rich.cells import cell_len, set_cell_size

from . import fmt
from .core.deck import Deck, QueueEntry
from .core.model import ME, EventKind
from .platform.manual import AnswerVerifier, Board
from .text import untrusted

TIMELINE_FILE = "timeline.json"
TIMELINE_KEYS = ("waves",)
WAVE_KEYS = ("at", "ids")
MAX_JSON_BYTES = 1_000_000  # a timeline bigger than this is refused before it is parsed
TIMELINE_FORM = '{"waves": [{"at": <seconds from the start>, "ids": [<challenge id>, ...]}]}'

_MISSING = object()


# ---------------------------------------------------------------------- the timeline


@dataclass(frozen=True)
class Wave:
    at: float  # seconds from the start of the run (the deck's clock)
    ids: tuple[str, ...]  # challenge ids, in the order they are listed


@dataclass(frozen=True)
class Timeline:
    waves: tuple[Wave, ...]  # in time order; every challenge of the board in exactly one


class TimelineError(Exception):
    """The timeline cannot be used. The message names the file and what is wrong."""


def load_timeline(board: Board, path: Path | None = None) -> Timeline:
    """The board's release timeline: from `path` if given, else from the timeline.json at
    the board's root if there is one, else the whole board at the start.

    Waves come out in time order and every challenge on the board is in exactly one: the
    challenges no wave lists join the wave at 0 (after its own ids), or make one.
    """
    ids = [item.challenge.id for item in board.challenges]
    if path is None:
        own = _root(board) / TIMELINE_FILE
        if not _present(own):
            return Timeline((Wave(0.0, tuple(ids)),))
        where, data = own, _read_json(own, follow=False)
    else:
        where = Path(path).expanduser()
        data = _read_json(where, follow=True)  # the player named it: a symlink is theirs to follow
    return _timeline(_show(where), data, ids)


def _timeline(where: str, data: object, ids: list[str]) -> Timeline:
    if not isinstance(data, dict):
        raise TimelineError(f"{where}: must be a JSON object: {TIMELINE_FORM}")
    _known(where, data, TIMELINE_KEYS)
    if "waves" not in data:
        raise TimelineError(f'{where}: "waves" is missing; it must be a list of waves: {TIMELINE_FORM}')
    items = data["waves"]
    if not isinstance(items, list):
        raise TimelineError(f'{where}: "waves" must be a list of waves: {TIMELINE_FORM}')
    on_board = set(ids)
    wave_of: dict[str, int] = {}  # challenge id -> the index of the wave that lists it
    time_of: dict[float, int] = {}  # wave time -> the index of the wave at that time
    waves: list[Wave] = []
    for i, item in enumerate(items):
        at_where = f'{where}: "waves"[{i}]'
        if not isinstance(item, dict):
            raise TimelineError(f'{at_where} must be an object with "at" and "ids"')
        _known(at_where, item, WAVE_KEYS)
        if "at" not in item:
            raise TimelineError(f'{at_where}: "at" is missing; it must be the seconds from the start, 0 or more')
        at = _amount(item["at"])
        if at is None:
            raise TimelineError(f'{at_where}: "at" must be a number of seconds from the start, 0 or more')
        if "ids" not in item:
            raise TimelineError(f'{at_where}: "ids" is missing; it must be a list of challenge ids')
        listed = item["ids"]
        if not isinstance(listed, list) or not listed:
            raise TimelineError(f'{at_where}: "ids" must be a non-empty list of challenge ids')
        unknown: list[str] = []
        for j, cid in enumerate(listed):
            if not isinstance(cid, str):
                raise TimelineError(f'{at_where}: "ids"[{j}] must be a challenge id (a string)')
            if cid not in on_board:
                unknown.append(cid)
                continue
            if cid in wave_of:
                other = wave_of[cid]
                again = "twice" if other == i else f'again; it is already in "waves"[{other}]'
                raise TimelineError(f"{at_where} lists {_quote(cid)} {again}")
            wave_of[cid] = i
        if unknown:
            names = ", ".join(_quote(cid) for cid in unknown[:10]) + (", ..." if len(unknown) > 10 else "")
            raise TimelineError(f"{at_where} names challenges that are not on the board: {names}")
        if at in time_of:
            raise TimelineError(
                f'{at_where} is at {at:g} s, like "waves"[{time_of[at]}]; put their ids in one wave'
            )
        time_of[at] = i
        waves.append(Wave(at, tuple(listed)))
    rest = tuple(cid for cid in ids if cid not in wave_of)
    if rest:
        if 0.0 in time_of:
            index = next(n for n, wave in enumerate(waves) if wave.at == 0.0)
            waves[index] = Wave(0.0, waves[index].ids + rest)
        else:
            waves.append(Wave(0.0, rest))
    waves.sort(key=lambda wave: wave.at)
    return Timeline(tuple(waves))


def _amount(value: object) -> float | None:
    """`value` (seconds, dollars) as a float, or None if it is not a finite number, 0 or more."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        amount = float(value)
    except OverflowError:  # an integer too big for a float
        return None
    return amount if math.isfinite(amount) and amount >= 0 else None


# ---------------------------------------------------------------------- releasing waves


class Release:
    """Puts a board on the deck wave by wave, each when the deck's clock reaches its time.

    Call tick() from a timer on the console's event loop (the deck's thread); the first
    call puts out the waves at 0. `entries_for` turns a wave's challenge ids into the queue
    entries to start them with, in triage order (an id may have none: it is put on the
    board and not queued). A wave goes out once however often tick() runs, even when putting
    it on the deck raised: the error reaches the caller and the wave is not tried again.
    The deck gets copies of the board's challenges, so the board stays as it was loaded.
    """

    def __init__(
        self,
        deck: Deck,
        board: Board,
        timeline: Timeline,
        entries_for: Callable[[list[str]], list[QueueEntry]],
    ) -> None:
        self.deck = deck
        self.board = board
        self.entries_for = entries_for
        self._challenges = {item.challenge.id: item.challenge for item in board.challenges}
        _check_covers(timeline, list(self._challenges))
        self._waves = tuple(sorted(timeline.waves, key=lambda wave: wave.at))
        self._next = 0  # the index of the next wave to put out
        self.released: list[Wave] = []  # the waves put out, in order

    @property
    def waiting(self) -> tuple[Wave, ...]:
        """The waves not yet due, in time order."""
        return self._waves[self._next :]

    @property
    def next_at(self) -> float | None:
        """When the next wave is due, or None once every wave is out."""
        return self._waves[self._next].at if self._next < len(self._waves) else None

    @property
    def done(self) -> bool:
        return self._next >= len(self._waves)

    def tick(self) -> list[Wave]:
        """Put out every wave that is due by the deck's clock. Returns them, in order."""
        now = self.deck.now
        out: list[Wave] = []
        while self._next < len(self._waves) and self._waves[self._next].at <= now:
            index = self._next
            wave = self._waves[index]
            self._next += 1  # before the release: a wave whose release raised is not tried again
            entries = list(self.entries_for(list(wave.ids)))
            stray = [entry.challenge for entry in entries if entry.challenge not in wave.ids]
            if stray:
                raise ValueError(
                    f"entries_for returned queue entries for challenges that are not in this wave: "
                    f"{', '.join(_quote(cid) for cid in stray)}"
                )
            challenges = [replace(self._challenges[cid]) for cid in wave.ids]
            self.deck.release(challenges, entries, self._label(index))
            self.released.append(wave)
            out.append(wave)
        return out

    def _label(self, index: int) -> str:
        total = len(self._waves)
        return "Board" if total == 1 else f"Wave {index + 1} of {total}"


def _check_covers(timeline: Timeline, ids: list[str]) -> None:
    """Every challenge of the board in exactly one wave, and nothing else (a Timeline can be
    made by hand, not only by load_timeline)."""
    on_board = set(ids)
    seen: set[str] = set()
    for i, wave in enumerate(timeline.waves):
        if _amount(wave.at) is None:
            raise TimelineError(f"wave {i} is at {wave.at!r}; a wave's time must be a number of seconds, 0 or more")
        for cid in wave.ids:
            if cid not in on_board:
                raise TimelineError(f"wave {i} names {_quote(cid)}, which is not on the board")
            if cid in seen:
                raise TimelineError(f"{_quote(cid)} is in more than one wave")
            seen.add(cid)
    left = [cid for cid in ids if cid not in seen]
    if left:
        names = ", ".join(_quote(cid) for cid in left[:10]) + (", ..." if len(left) > 10 else "")
        raise TimelineError(f"the timeline leaves out challenges on the board, so they would never be released: {names}")


# ---------------------------------------------------------------------- scoring


@dataclass(frozen=True)
class LaneScore:
    """One lane, from the log: what it worked on and what its model turns cost."""

    id: str
    challenge: str
    model: str  # the model it started on
    parent: str | None  # the lane it was forked from
    turns: int
    tokens: int
    dollars: float | None  # None once any of its turns had no price
    state: str | None  # how it ended (solved, killed, stopped, gave up); None if still open


@dataclass(frozen=True)
class ChallengeScore:
    """One challenge of the board, and what the run made of it."""

    id: str
    name: str
    category: str
    points: int
    released_at: float | None  # when it reached the board; None if it never did in this run
    solved_at: float | None  # the first accepted submission
    solved_by: str | None  # the lane that submitted it (ME when the log names no lane)
    checked: str | None  # how the solve was checked: "answers" (the answers file), "platform", "player"
    lanes: tuple[str, ...]  # the lanes that worked it, in start order
    turns: int
    tokens: int  # every lane on it, forks and killed attempts included
    dollars: float | None  # the same; None when any of its turns had no price
    interventions: int
    wrong_submissions: int
    teammate: str | None = None  # team mode: the teammate who solved it

    @property
    def solved(self) -> bool:
        return self.solved_at is not None

    @property
    def time_to_solve(self) -> float | None:
        """Seconds from its release to its solve."""
        if self.solved_at is None or self.released_at is None:
            return None
        return max(0.0, self.solved_at - self.released_at)


def _empty() -> Mapping:
    return MappingProxyType({})


@dataclass(frozen=True)
class Score:
    solved: tuple[str, ...]  # challenge ids, in solve order
    points: int  # the board's points for them
    possible: int  # every challenge on the board
    first_solve_at: float | None
    per_challenge: Mapping[str, ChallengeScore]  # every challenge on the board, in board order
    tokens: int  # all model turns in the log
    dollars: float | None  # None when any turn had no price (known_dollars has the priced part)
    interventions: int  # the player's interventions that the deck carried out (not the refused ones)
    wrong_submissions: int
    event: str = ""
    lanes: Mapping[str, LaneScore] = field(default_factory=_empty)  # in start order
    known_dollars: float = 0.0  # the dollars of every turn that had a price
    unpriced: tuple[str, ...] = ()  # lanes with a turn that had no price
    intervention_kinds: Mapping[str, int] = field(default_factory=_empty)  # e.g. {"hint": 2}, most first
    ended_at: float | None = None  # the time of the log's last event
    answers: Path | None = None  # the answers file the flags were checked against
    notes: tuple[str, ...] = ()  # what the player should know about the log

    @property
    def cost_per_solve(self) -> float | None:
        """The run's dollars over its solves; None with no solve or an unknown cost."""
        if not self.solved or self.dollars is None:
            return None
        return self.dollars / len(self.solved)


class ScoreError(Exception):
    """The log cannot be scored against this board. The message says why."""


@dataclass
class _Lane:
    challenge: str
    model: str = ""
    parent: str | None = None
    turns: int = 0
    tokens: int = 0
    dollars: float | None = 0.0
    state: str | None = None


@dataclass(frozen=True)
class _Submit:
    at: float
    lane: str | None
    flag: str
    correct: bool
    by: str


@dataclass
class _Asked:
    """An intervention waiting for its outcome."""

    name: str
    lane: str | None
    challenge: str | None


def score(events_jsonl: Path, board: Board) -> Score:
    """Score a run from its event log (events.jsonl) alone, against the board it played.

    Raises ScoreError when the file is not a flightdeck event log, holds more than one run,
    has a malformed event, or names challenges that are not on the board.
    """
    path = Path(events_jsonl).expanduser()
    where = _show(path)
    records, notes = _read_log(path)
    on_board = {item.challenge.id: item.challenge for item in board.challenges}
    unknown: set[str] = set()

    def known(cid: str) -> str:
        if cid not in on_board:
            unknown.add(cid)
        return cid

    released: dict[str, float] = {}
    lanes: dict[str, _Lane] = {}
    submits: dict[str, list[_Submit]] = {}
    teammates: dict[str, str] = {}
    asked: list[_Asked] = []  # interventions waiting for their outcomes (they nest)
    done: list[_Asked] = []  # interventions the deck carried out
    ended_at: float | None = None
    priced = 0.0

    for n, rec in records:
        kind = rec["kind"]
        if kind in ("run-start", "run-end"):
            continue
        get = _Fields(where, n, kind, rec)
        at = float(get.top("at", _is_time, "a time (seconds, 0 or more)"))
        ended_at = at if ended_at is None else max(ended_at, at)
        if kind == "release":
            for cid in get.data("challenges", _is_ids, "a list of challenge ids"):
                released.setdefault(known(cid), at)
        elif kind == "lane.start":
            lane = get.top("lane", _is_text, "a lane id")
            cid = known(get.top("challenge", _is_text, "a challenge id"))
            model = get.data("model", _is_text_or_none, "a model name", default=None) or ""
            parent = get.data("parent", _is_text_or_none, "a lane id or null", default=None)
            lanes.setdefault(lane, _Lane(cid, model, parent))
        elif kind == "turn":
            lane = get.top("lane", _is_text, "a lane id")
            cid = known(get.top("challenge", _is_text, "a challenge id"))
            tokens = get.data("tokens", _is_count, "a token count (a whole number, 0 or more)")
            dollars = get.data("dollars", _is_money, "a dollar amount (0 or more) or null")
            dollars = None if dollars is None else float(dollars)
            acc = lanes.setdefault(lane, _Lane(cid))
            acc.turns += 1
            acc.tokens += tokens
            if dollars is None:
                acc.dollars = None
            else:
                priced += dollars
                if acc.dollars is not None:
                    acc.dollars += dollars
        elif kind == "lane.end":
            lane = get.top("lane", _is_text, "a lane id")
            state = get.data("state", _is_text, "the state the lane ended in")
            cid = get.top("challenge", _is_text_or_none, "a challenge id or null")
            acc = lanes.get(lane)
            if acc is None:
                if cid is None:
                    raise ScoreError(f"{where}: line {n}: a lane.end event for {_quote(lane)} names no challenge")
                acc = lanes.setdefault(lane, _Lane(known(cid)))
            acc.state = state
        elif kind == "submit":
            cid = known(get.top("challenge", _is_text, "a challenge id"))
            submits.setdefault(cid, []).append(
                _Submit(
                    at,
                    get.top("lane", _is_text_or_none, "a lane id or null"),
                    get.data("flag", _is_string, "the flag submitted"),
                    get.data("correct", _is_bool, "correct: true or false"),
                    get.data("by", _is_text, "who checked it (platform or player)", default="platform"),
                )
            )
        elif kind == "teammate":
            cid = known(get.top("challenge", _is_text, "a challenge id"))
            if get.data("solved", _is_bool, "solved: true or false", default=False):
                teammates.setdefault(cid, get.data("who", _is_text, "the teammate's name"))
        elif kind == "intervention":
            asked.append(
                _Asked(
                    get.data("intervention", _is_text, "the intervention's name"),
                    get.top("lane", _is_text_or_none, "a lane id or null"),
                    get.top("challenge", _is_text_or_none, "a challenge id or null"),
                )
            )
        elif kind == "outcome":
            name = get.data("intervention", _is_text, "the intervention's name")
            ok = get.data("ok", _is_bool, "ok: true or false")
            if not asked or asked[-1].name != name:
                raise ScoreError(f"{where}: line {n}: an outcome of {_quote(name)} with no intervention before it")
            iv = asked.pop()
            if ok:
                done.append(iv)
    done += asked  # asked for, and the log ends before its outcome: the player did step in

    if unknown:
        names = ", ".join(_quote(cid) for cid in sorted(unknown)[:10]) + (", ..." if len(unknown) > 10 else "")
        raise ScoreError(
            f"{where}: the run played challenges that are not on the board {_quote(board.event)}: {names}; "
            "score it against the board it played (--board)"
        )

    verifier = AnswerVerifier(board.answers) if board.answers is not None else None
    per: dict[str, ChallengeScore] = {}
    solved_at: dict[str, float] = {}
    total_wrong = 0
    lane_challenge = {lane: acc.challenge for lane, acc in lanes.items()}
    iv_by_challenge = Counter(
        cid for cid in ((iv.challenge or lane_challenge.get(iv.lane or "")) for iv in done) if cid in on_board
    )
    for item in board.challenges:
        ch = item.challenge
        first: _Submit | None = None
        checked: str | None = None
        wrong = 0
        for sub in submits.get(ch.id, []):
            verdict, how = sub.correct, sub.by
            if verifier is not None:
                expected = verifier(ch.id, sub.flag)
                if expected is not None:
                    if expected != sub.correct:
                        notes.append(_disagrees(ch.name, sub.correct))
                    verdict, how = expected, "answers"
            if not verdict:
                wrong += 1
            elif first is None:
                first, checked = sub, how
        on_it = [lane for lane, acc in lanes.items() if acc.challenge == ch.id]
        costs = [lanes[lane].dollars for lane in on_it]
        if first is not None:
            solved_at[ch.id] = first.at
        total_wrong += wrong
        per[ch.id] = ChallengeScore(
            id=ch.id,
            name=ch.name,
            category=ch.category,
            points=ch.points,
            released_at=released.get(ch.id),
            solved_at=first.at if first else None,
            solved_by=(first.lane or ME) if first else None,
            checked=checked,
            lanes=tuple(on_it),
            turns=sum(lanes[lane].turns for lane in on_it),
            tokens=sum(lanes[lane].tokens for lane in on_it),
            dollars=None if any(c is None for c in costs) else sum((c for c in costs if c is not None), 0.0),
            interventions=iv_by_challenge[ch.id],
            wrong_submissions=wrong,
            teammate=teammates.get(ch.id) if first is None else None,
        )
    solved = tuple(sorted(solved_at, key=lambda cid: solved_at[cid]))  # sorted() is stable: log order on a tie
    unpriced = tuple(lane for lane, acc in lanes.items() if acc.dollars is None)
    for lane in unpriced:
        notes.append(f"{lane} had turns with no price, so its cost is not fully known: the dollars count only priced turns.")
    kinds = Counter(iv.name for iv in done)
    return Score(
        solved=solved,
        points=sum(on_board[cid].points for cid in solved),
        possible=sum(item.challenge.points for item in board.challenges),
        first_solve_at=min(solved_at.values()) if solved_at else None,
        per_challenge=MappingProxyType(per),
        tokens=sum(acc.tokens for acc in lanes.values()),
        dollars=None if unpriced else priced,
        interventions=len(done),
        wrong_submissions=total_wrong,
        event=board.event,
        lanes=MappingProxyType(
            {
                lane: LaneScore(lane, acc.challenge, acc.model, acc.parent, acc.turns, acc.tokens, acc.dollars, acc.state)
                for lane, acc in lanes.items()
            }
        ),
        known_dollars=priced,
        unpriced=unpriced,
        intervention_kinds=MappingProxyType(dict(sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0])))),
        ended_at=ended_at,
        answers=board.answers,
        notes=tuple(dict.fromkeys(notes)),  # each note once, in order
    )


def _disagrees(name: str, run_said: bool) -> str:
    if run_said:
        return f"The answers file rejects a flag the run took for {name}, so it is not counted."
    return f"The answers file accepts a flag the run was told was wrong for {name}, so it is counted."


def _read_log(path: Path) -> tuple[list[tuple[int, dict]], list[str]]:
    """The log's lines as (line number, record), and notes on how it ended."""
    where = _show(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ScoreError(f"{where}: no such file") from None
    except IsADirectoryError:
        raise ScoreError(f"{where}: is a directory, not an event log") from None
    except OSError as exc:
        raise ScoreError(f"{where}: cannot read it ({exc.strerror})") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ScoreError(f"{where}: is not text, so not a flightdeck event log") from None
    if not text.strip():
        raise ScoreError(f"{where}: is empty, not an event log")
    lines = text.split("\n")
    cut = lines[-1] != ""  # the last line has no newline: it was being written when the run stopped
    notes: list[str] = []
    records: list[tuple[int, dict]] = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
            if cut and n == len(lines):
                notes.append("The log's last line was cut off (the run did not close cleanly); it is left out.")
                continue
            raise ScoreError(f"{where}: line {n} is not JSON; is it a flightdeck event log (events.jsonl)?") from None
        if not isinstance(record, dict) or not isinstance(record.get("kind"), str):
            raise ScoreError(f"{where}: line {n} is not a flightdeck event (an object with a kind)")
        records.append((n, record))
    if not records or records[0][1]["kind"] != "run-start":
        raise ScoreError(f"{where}: does not start with a run-start line; is it a flightdeck event log (events.jsonl)?")
    runs = sum(1 for _, record in records if record["kind"] == "run-start")
    if runs > 1:
        raise ScoreError(f"{where}: holds {runs} runs (run-start lines); score one run at a time")
    if not any(record["kind"] == "run-end" for _, record in records):
        notes.append("The log has no run-end line: the run is still going, or it did not close cleanly.")
    return records, notes


_KINDS = frozenset({"run-start", "run-end", *(kind.value for kind in EventKind)})


class _Fields:
    """Checked access to one event's fields; a missing or malformed one is a ScoreError naming the line."""

    def __init__(self, where: str, line: int, kind: str, record: dict) -> None:
        # a kind flightdeck does not write is untrusted text: quoted, folded and cut like any other
        self.where, self.line, self.record = where, line, record
        self.kind = kind if kind in _KINDS else _quote(kind)
        data = record.get("data", {})
        if not isinstance(data, dict):
            raise ScoreError(f"{where}: line {line}: the {self.kind} event's data must be an object")
        self._data = data

    def top(self, name: str, check: Callable[[object], bool], what: str):
        return self._get(self.record, name, check, what, _MISSING, name)

    def data(self, name: str, check: Callable[[object], bool], what: str, default: object = _MISSING):
        return self._get(self._data, name, check, what, default, f"data.{name}")

    def _get(self, source: dict, name: str, check, what: str, default: object, shown: str):
        if name not in source:
            if default is _MISSING:
                raise ScoreError(f"{self.where}: line {self.line}: the {self.kind} event has no {shown} ({what})")
            return default
        value = source[name]
        if not check(value):
            raise ScoreError(f"{self.where}: line {self.line}: the {self.kind} event's {shown} must be {what}")
        return value


def _is_time(value: object) -> bool:
    return _amount(value) is not None


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_text_or_none(value: object) -> bool:
    return value is None or _is_text(value)


def _is_string(value: object) -> bool:
    return isinstance(value, str)


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_money(value: object) -> bool:
    return value is None or _amount(value) is not None  # a finite number, 0 or more


def _is_ids(value: object) -> bool:
    return isinstance(value, list) and all(_is_text(item) for item in value)


# ---------------------------------------------------------------------- the scorecard

NAME_CELLS = 24  # a longer challenge name is cut in the table
CHECKED = {"platform": "the run's board said so", "player": "you said the platform accepted it"}
MARKS = {"platform": "*", "player": "**"}  # a solve checked some other way than by the answers file


def scorecard(score: Score) -> str:
    """The score as plain text for the terminal: totals, one row per challenge, then notes.
    It never shows a flag; every name is folded to one safe line."""
    rows = list(score.per_challenge.values())
    total = len(rows)
    lines = [f"{_one(score.event) or 'Board'}: solved {len(score.solved)} of {total} · {score.points:,} of {score.possible:,} points"]
    released = sum(1 for row in rows if row.released_at is not None)
    if released < total:
        lines.append(f"Released {released} of {total}: {total - released} never reached the board in this run")
    when = f"First solve {fmt.clock(score.first_solve_at)}" if score.first_solve_at is not None else "No solve"
    if score.ended_at is not None:
        when += f" · last event {fmt.clock(score.ended_at)}"
    lines.append(when)
    partial = score.dollars is None  # some turns had no price: what is shown is a floor
    spent = f"Spent {fmt.tokens(score.tokens)} tokens · {_money(score.known_dollars, partial)}"
    if score.solved:
        spent += f" · {_money(score.known_dollars / len(score.solved), partial)} per solve"
    lines.append(spent)
    kinds = ", ".join(f"{_one(name)} {count}" for name, count in score.intervention_kinds.items())
    lines.append(
        f"Interventions {score.interventions}" + (f" ({kinds})" if kinds else "")
        + f" · wrong submissions {score.wrong_submissions}"
    )
    if score.answers is not None:
        lines.append(f"Flags checked against {_one(score.answers.name)}")
    else:
        lines.append("No answers file: solves are as the run recorded them")
    lines.append("")
    lines += _table(_ordered(rows, score), score.lanes)
    lines.append(KEY)
    for how, mark in MARKS.items():
        if any(row.checked == how for row in rows if row.solved):
            lines.append(f"{mark} not checked against an answers file: {CHECKED[how]}")
    if score.notes:
        lines.append("")
        lines += [f"- {_one(note)}" for note in score.notes]
    return "\n".join(lines) + "\n"


def _ordered(rows: list[ChallengeScore], score: Score) -> list[ChallengeScore]:
    """Solved first (in solve order), then tried (most tokens first), then the rest, then
    those never released; board order within each."""
    order = {cid: i for i, cid in enumerate(score.solved)}

    def key(row: ChallengeScore):
        if row.solved:
            return (0, order[row.id], 0)
        if row.teammate:
            return (1, 0, 0)
        if row.lanes:
            return (2, -row.tokens, 0)
        if row.released_at is not None:
            return (3, 0, 0)
        return (4, 0, 0)

    return sorted(rows, key=key)


def _result(row: ChallengeScore, lanes: Mapping[str, LaneScore]) -> str:
    if row.solved:
        mark = MARKS.get(row.checked or "")
        who = "by you" if row.solved_by in (None, ME) else _one(row.solved_by)
        return f"solved {who}" + (f" {mark}" if mark else "")
    if row.teammate:
        return f"teammate {_one(row.teammate)}"
    if row.lanes:
        last = lanes[row.lanes[-1]].state if row.lanes[-1] in lanes else None
        return f"tried ({_one(last) if last else 'open'})"
    if row.released_at is not None:
        return "not tried"
    return "not released"


HEADER = ("challenge", "cat", "pts", "result", "solved", "took", "lanes", "tokens", "cost", "iv", "wrong")
RIGHT = frozenset({"pts", "took", "lanes", "tokens", "cost", "iv", "wrong"})
KEY = "took: release to solve · iv: your interventions · wrong: wrong flags submitted"


def _cells(row: ChallengeScore, lanes: Mapping[str, LaneScore]) -> tuple[str, ...]:
    took = row.time_to_solve
    return (
        _cut(_one(row.name), NAME_CELLS),
        _cut(_one(row.category), 8),
        str(row.points),
        _result(row, lanes),
        fmt.clock(row.solved_at) if row.solved_at is not None else "",
        fmt.duration(took) if took is not None else "",
        str(len(row.lanes)) if row.lanes else "",
        fmt.tokens(row.tokens) if row.lanes else "",
        (f"${fmt.dollars(row.dollars)}" if row.dollars is not None else "-") if row.lanes else "",
        str(row.interventions) if row.interventions else "",
        str(row.wrong_submissions) if row.wrong_submissions else "",
    )


def _table(rows: list[ChallengeScore], lanes: Mapping[str, LaneScore]) -> list[str]:
    """Columns padded to their widest cell (in terminal cells), numbers on the right."""
    table = [HEADER] + [_cells(row, lanes) for row in rows]
    widths = [max(cell_len(cells[i]) for cells in table) for i in range(len(HEADER))]
    out = []
    for cells in table:
        padded = []
        for name, cell, width in zip(HEADER, cells, widths):
            pad = " " * (width - cell_len(cell))
            padded.append(pad + cell if name in RIGHT else cell + pad)
        out.append("  ".join(padded).rstrip())
    return out


def _money(amount: float, partial: bool) -> str:
    """$0.84, or $0.84+ when part of the cost has no price (as the console's header shows it)."""
    return f"${fmt.dollars(amount)}" + ("+" if partial else "")


def _cut(text: str, cells: int) -> str:
    return text if cell_len(text) <= cells else set_cell_size(text, cells - 1) + "…"


def _one(text: str) -> str:
    return untrusted(text, one_line=True)


# ---------------------------------------------------------------------- reading board files


class _Duplicate(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """json object hook: a key given twice is an error (json would keep the last one silently)."""
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise _Duplicate(key)
        out[key] = value
    return out


def _read_json(path: Path, *, follow: bool) -> object:
    """The JSON in `path`: a regular file (a symlink only with follow=True) of at most MAX_JSON_BYTES."""
    where = _show(path)
    try:
        info = path.stat() if follow else path.lstat()
    except FileNotFoundError:
        raise TimelineError(f"{where}: no such file") from None
    except OSError as exc:
        raise TimelineError(f"{where}: cannot read it ({exc.strerror})") from None
    if stat.S_ISLNK(info.st_mode):
        raise TimelineError(
            f"{where}: is a symlink; flightdeck does not follow symlinks in a board (name the timeline file explicitly instead)"
        )
    if not stat.S_ISREG(info.st_mode):
        raise TimelineError(f"{where}: is not a regular file")
    if info.st_size > MAX_JSON_BYTES:
        raise TimelineError(f"{where}: is over {MAX_JSON_BYTES:,} bytes, too big for a timeline")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except OSError as exc:
        raise TimelineError(f"{where}: cannot read it ({exc.strerror})") from None
    except UnicodeDecodeError:
        raise TimelineError(f"{where}: is not UTF-8 text") from None
    try:
        return json.loads(text, object_pairs_hook=_unique)
    except _Duplicate as exc:
        raise TimelineError(f"{where}: has the key {_quote(exc.key)} twice") from None
    except json.JSONDecodeError as exc:
        raise TimelineError(f"{where}: is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})") from None
    except (ValueError, RecursionError):  # a number too long to convert, or nesting too deep
        raise TimelineError(f"{where}: is not JSON flightdeck can read (a number too long or nesting too deep)") from None


def _known(where: str, data: dict, known: tuple[str, ...]) -> None:
    unknown = [key for key in data if key not in known]
    if unknown:
        names = ", ".join(_quote(key) for key in unknown)
        raise TimelineError(f"{where}: unknown key {names} (known: {', '.join(known)})")


def _root(board: Board) -> Path:
    """The board's folder: the one folder that holds its challenge directories."""
    parents = {item.handout.parent for item in board.challenges}
    if len(parents) != 1:
        raise TimelineError("the board's challenges are not in one folder, so there is no timeline.json to look for; name the timeline file")
    return parents.pop()


def _present(path: Path) -> bool:
    """There is something at `path`, a dangling symlink included."""
    return path.is_symlink() or path.exists()


def _show(value: object) -> str:
    """A path or message, safe to print: control and invisible characters made visible."""
    return untrusted(str(value), one_line=True)


def _quote(text: str) -> str:
    """Untrusted text quoted for a message: made safe, and cut short."""
    safe = untrusted(text, one_line=True)
    return json.dumps(safe if len(safe) <= 60 else safe[:57] + "...", ensure_ascii=False)
