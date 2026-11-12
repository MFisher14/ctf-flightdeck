"""A finished (or crashed) run, read back from its folder: the event log and the lane
transcripts. Post-flight reports, the gap report, writeups and scoring all start here, and
all of them credit a solve by the one rule here (Credit, solves()).

Everything read is untrusted: the logs hold challenge text, commands, outputs, flags and
diffs. A line that is not valid JSON (a run that crashed mid-write) is skipped and named
in `problems`, never silently dropped; a missing event log is an error.

A run folder also holds run.json, written as the run starts (write_run_info): the board
folder and the answers file the run played, so the commands after a run can find them.
Those are paths on the player's machine, so they stay out of the event log, which holds the
deck's events and nothing else.

`resolve_run(arg, say=...)` is how every command that takes RUN_DIR reads it: a run folder,
its events.jsonl, or the word `latest` for the newest run under the config's [run] dir
(latest_run). Newest is by the time each run started, the "wall" of the run-start line that
opens its events.jsonl, never a folder's modification time (reading a run writes reports into
it) and never its name (local time). Whatever is really there under the name `latest` is
taken as the path it is.
"""

from __future__ import annotations

import json
import math
import os
import stat
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .core.model import ME

EVENTS = "events.jsonl"
LANES = "lanes"
RUN_INFO = "run.json"
RUN_SETUP = "setup.json"  # how the run was set up, for `flightdeck share`
MAX_RUN_INFO = 64 * 1024  # a run.json bigger than this was not written by a run
LATEST = "latest"  # in place of a run folder: the newest run under the config's [run] dir
MAX_RUN_START = 64 * 1024  # a first line of events.jsonl longer than this is not a run-start line

# Who solved a challenge (Solve.by).
LANE, L1, TEAMMATE, PLAYER, TEAM = "lane", "l1", "teammate", "player", "team"
YOU = "you"  # the platform's word for this account (Deck.platform_solved)
YOUR_TEAM = "your team"  # ...for its team, as run.py says it; no team handle can be this (it has a space)


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
class CallLine:
    """One tool call of a step's turn: its one line and the transcript's longer excerpt of its output."""

    text: str
    output: str


@dataclass(frozen=True)
class ActionLine:
    at: float
    turn: int
    kind: str  # core.model.ActionKind value: step, message, player, note, alert, approval
    by: str  # lane, player, flightdeck
    text: str
    output: str
    alert: str | None
    calls: tuple[CallLine, ...] = ()  # a step of flightdeck's own loop: every tool call of its turn; none in an older transcript


@dataclass(frozen=True)
class FileLine:
    file: str
    status: str  # added, modified, deleted
    turn: int
    at: float
    diff: str
    by: str = "lane"  # "player": the player changed it in a take-over (a transcript older than the field says nothing)


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
    known_dollars: float | None = None  # every priced amount, also after one with no price; None: not in the transcript
    dollars_later: bool = False  # written while a coding-agent CLI's turn was under way: its cost never came, so dollars is not all of it


@dataclass(frozen=True)
class Released:
    """A challenge as a release put it on the board. A format 2 log names each one; in an
    older log only the id is known."""

    id: str
    name: str = ""
    category: str = ""
    points: int | None = None


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

    @property
    def format(self) -> int:
        """The log's format (eventlog.FORMAT when it was written): 1 for a log older than the field."""
        start = next((e for e in self.events if e.kind == "run-start"), None)
        value = start.data.get("format") if start is not None else None
        return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 1

    @property
    def event(self) -> str | None:
        """The event's name, as the last release that named it recorded it (None in an older log)."""
        for line in reversed(self.events):
            name = line.data.get("event") if line.kind == "release" else None
            if isinstance(name, str) and name:
                return name
        return None

    @property
    def board(self) -> dict[str, Released]:
        """Every challenge a release named, in release order, with the name, category and
        points the release recorded (none in an older log)."""
        out: dict[str, Released] = {}
        for line in self.of("release"):
            ids = line.data.get("challenges")
            facts = _facts(line.data.get("board"))
            for cid in ids if isinstance(ids, list) else ():
                if isinstance(cid, str) and cid and cid not in out:
                    out[cid] = facts.get(cid, Released(cid))
        return out


def load_run(run_dir: Path) -> RunRecord:
    """Read a run folder. RunFolderError if it has no event log."""
    events_path = run_dir / EVENTS
    if not events_path.is_file():
        raise RunFolderError(f"{run_dir}: no {EVENTS} (is this a flightdeck run folder?)")
    problems: list[str] = []
    events = tuple(event_line(raw) for raw in _lines(events_path, problems))
    lanes: dict[str, LaneRecord] = {}
    folder = run_dir / LANES
    if folder.is_dir():
        for path in sorted(folder.glob("*.jsonl"), key=lambda p: (len(p.stem), p.stem)):
            rows = list(_lines(path, problems))
            if not rows or "lane" not in rows[0]:
                problems.append(f"{path.name}: no header line; skipped")
                continue
            record = _lane(rows, path.name, problems)
            lanes[record.lane] = record
    return RunRecord(run_dir, events, lanes, tuple(problems))


def run_folder(path: Path) -> Path:
    """The run folder a player named: the folder itself, or the folder of the events.jsonl
    they gave (the path a run prints when it ends). RunFolderError when it is neither."""
    path = Path(path)
    if path.is_dir():
        return path
    if path.name == EVENTS and path.is_file():
        return path.parent
    if path.exists():
        raise RunFolderError(f"{path}: not a run folder; give the run folder (the one holding {EVENTS}) or its {EVENTS}")
    raise RunFolderError(f"{path}: no such run folder or {EVENTS}")


def asks_latest(arg: Path | str) -> bool:
    """Whether a RUN_DIR argument is the word `latest` with nothing of that name where it
    points (the current directory): a folder or file really named latest is that path."""
    return str(arg) == LATEST and not os.path.lexists(LATEST)


def resolve_run(arg: Path | str, *, say: Callable[[str], None], config: Path | None = None) -> Path:
    """The run folder a command's RUN_DIR argument names: a run folder or its events.jsonl
    (run_folder), or `latest` for the newest run under the config's [run] dir (latest_run),
    unless something named latest is really there, which is taken as the path it is.

    `say` gets one line, safe to print, naming the folder whenever the word chose it (the
    caller prints it on stderr as `flightdeck: <line>`); it is not called for a path the
    player named. `config` names the config file `latest` reads, by default the usual one
    ($FLIGHTDECK_CONFIG, else ~/.config/ctf-flightdeck/config.toml); it is read only for
    `latest`, and no API key is. RunFolderError when the path is not a run folder or there
    is no run to pick; config.ConfigError when `latest` cannot read the config."""
    if asks_latest(arg):
        return latest_run(say=say, config=config)
    return run_folder(Path(arg))


def latest_run(*, say: Callable[[str], None], config: Path | None = None) -> Path:
    """The newest run folder under the config's [run] dir: of the folders there that hold an
    events.jsonl, the one whose run started last (equal times: the last by name). `say` gets
    the line that names it, and the folders left out because their log does not say when
    the run started. RunFolderError, in one line, when there is none; config.ConfigError
    when the config cannot be read (resolve_run has the rest)."""
    from .config import load_config
    from .text import untrusted

    loaded = load_config(config)
    runs = loaded.run_dir
    where = f"{runs} ([run] dir in {loaded.source})"
    try:
        folders = sorted(entry for entry in runs.iterdir() if (entry / EVENTS).is_file())
    except FileNotFoundError:
        raise RunFolderError(f"{LATEST}: there is no runs folder {where} yet: no run has been written there") from None
    except OSError as exc:
        raise RunFolderError(f"{LATEST}: cannot read the runs folder {where}: {exc.strerror or exc}") from None
    if not folders:
        raise RunFolderError(f"{LATEST}: no run in {where}: no folder there holds an {EVENTS}")
    dated = [(started, folder) for folder in folders if (started := run_started(folder)) is not None]
    undated = [folder.name for folder in folders if folder not in {f for _, f in dated}]
    if not dated:
        raise RunFolderError(
            f"{LATEST}: no run in {where} says when it started: {_count_of(len(folders), 'folder')} there "
            f"with an {EVENTS}, none with a run-start line and its time; name the run folder"
        )
    picked = max(dated, key=lambda pair: (pair[0], pair[1].name))[1]
    line = f"run: {picked} ({LATEST}: the newest of {_count_of(len(dated), 'run')} in {runs})"
    if undated:
        line += f"; left out, with no run-start time in its {EVENTS}: {', '.join(undated)}"
    say(untrusted(line, one_line=True))
    return picked


def run_started(run_dir: Path) -> datetime | None:
    """When the run in `run_dir` started: the "wall" time of the run-start line that opens its
    events.jsonl (a time without a zone is UTC, as the log writes it). None when the log
    cannot be read or its first line is not a run-start line with a time: untrusted, like
    every line of a log."""
    try:
        with (Path(run_dir) / EVENTS).open("rb") as handle:
            first = b""
            while not first.strip():  # the first line with anything on it, as load_run reads
                first = handle.readline(MAX_RUN_START + 1)
                if not first or len(first) > MAX_RUN_START:
                    return None
        raw = json.loads(first)
        if not isinstance(raw, dict) or raw.get("kind") != "run-start" or not isinstance(raw.get("wall"), str):
            return None
        started = datetime.fromisoformat(raw["wall"])
    except (OSError, ValueError, RecursionError):
        return None
    return started if started.tzinfo is not None else started.replace(tzinfo=timezone.utc)


def _count_of(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


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


def finite(value: object) -> float | None:
    """A finite number as a float; None for anything else: not a number, a bool, NaN, an
    infinity (json reads NaN, Infinity and 1e400 as floats), or an int too large for a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def run_time(value: object) -> float | None:
    """A time in the run (seconds since it started, never negative), or None: unknown."""
    number = finite(value)
    return number if number is not None and number >= 0 else None


def _count(value: object, default: int = 0, *, where: str = "", problems: list[str] | None = None) -> int:
    """A whole-number count from a log: the default for anything else, NaN, Infinity and
    numbers too big for a float included (int() of those raises), named in `problems`."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    try:
        number = float(value)
    except OverflowError:
        number = math.inf
    if not math.isfinite(number):
        if problems is not None:
            problems.append(f"{where}: is not a usable number; read as {default}")
        return default
    return int(number)


def event_line(raw: Mapping[str, object]) -> EventLine:
    """One line of an event log as an EventLine: a field of the wrong type reads as nothing."""
    data = raw.get("data")
    return EventLine(
        at=_number(raw.get("at")),
        wall=_text(raw.get("wall")),
        kind=_text(raw.get("kind")),
        text=_text(raw.get("text")),
        lane=raw.get("lane") if isinstance(raw.get("lane"), str) else None,
        challenge=raw.get("challenge") if isinstance(raw.get("challenge"), str) else None,
        alert=raw.get("alert") if isinstance(raw.get("alert"), str) else None,
        data=(data if isinstance(data, dict) else {}) if raw.get("kind") != "run-start" else _start_data(raw),
    )


def _start_data(raw: Mapping[str, object]) -> Mapping[str, object]:
    """A run-start line keeps its fields at the top (version, format): read as its data."""
    return {key: value for key, value in raw.items() if key not in ("kind", "wall", "at")}


def _facts(value: object) -> dict[str, Released]:
    """A release's "board" list ({id, name, category, points} per challenge) by id; a value of
    the wrong type is left out."""
    out: dict[str, Released] = {}
    for item in value if isinstance(value, list) else ():
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str) or not item["id"]:
            continue
        points = item.get("points")
        name, category = item.get("name"), item.get("category")
        out[item["id"]] = Released(
            item["id"], name if isinstance(name, str) else "", category if isinstance(category, str) else "",
            points if isinstance(points, int) and not isinstance(points, bool) else None,
        )
    return out


def _calls(value: object) -> tuple[CallLine, ...]:
    """A step's "calls" (every tool call of its turn); none for a transcript written before
    the field, and an entry of the wrong type is left out."""
    if not isinstance(value, list):
        return ()
    return tuple(CallLine(text=_text(item.get("text")), output=_text(item.get("output")))
                 for item in value if isinstance(item, Mapping))


def _lane(rows: list[Mapping[str, object]], name: str = "", problems: list[str] | None = None) -> LaneRecord:
    head = rows[0]

    def count(key: str, default: int = 0) -> int:
        return _count(head.get(key), default, where=f"{name}: header {key}", problems=problems)

    actions = tuple(
        ActionLine(
            at=_number(r.get("at")), turn=_count(r.get("turn")), kind=_text(r.get("kind")), by=_text(r.get("by")),
            text=_text(r.get("text")), output=_text(r.get("output")),
            alert=r.get("alert") if isinstance(r.get("alert"), str) else None,
            calls=_calls(r.get("calls")),
        )
        for r in rows[1:]
        if "kind" in r
    )
    files = tuple(
        FileLine(file=_text(r.get("file")), status=_text(r.get("status")), turn=_count(r.get("turn")),
                 at=_number(r.get("at")), diff=_text(r.get("diff")),
                 by="player" if r.get("by") == "player" else "lane")
        for r in rows[1:]
        if "file" in r
    )
    dollars = head.get("dollars")
    ended = head.get("ended_at")
    known = finite(head.get("known_dollars"))
    return LaneRecord(
        lane=_text(head.get("lane")), challenge=_text(head.get("challenge")), name=_text(head.get("name")),
        category=_text(head.get("category")), points=count("points"), model=_text(head.get("model")),
        state=_text(head.get("state")), result=_text(head.get("result")), turns=count("turns"),
        tokens=count("tokens"), cached_tokens=count("cached_tokens"),
        dollars=_number(dollars) if isinstance(dollars, (int, float)) and not isinstance(dollars, bool) else None,
        started_at=_number(head.get("started_at")), ended_at=_number(ended) if isinstance(ended, (int, float)) else None,
        parent=head.get("parent") if isinstance(head.get("parent"), str) else None,
        attempt=count("attempt", 1), plan=_text(head.get("plan")),
        actions=actions, files=files,
        known_dollars=known if known is not None and known >= 0 else None,
        dollars_later=head.get("dollars_later") is True,
    )


# ---------------------------------------------------------------------- who solved what


@dataclass(frozen=True)
class Solve:
    """Who solved a challenge, and when, as Credit gives it."""

    challenge: str
    by: str  # LANE, L1, TEAMMATE, PLAYER (you) or TEAM (your team, as the platform lists it)
    who: str  # the lane id, the L1 engine, the teammate's handle, "me", or the platform's word ("you", "your team")
    at: float | None  # None: the log's time for it is not a time
    index: int  # the event's position in the run log
    flag: str | None = None  # the accepted flag; None for a solve that came with none
    lane: str | None = None  # the lane that submitted the accepted flag (an L1 flag goes through one)
    found: int | None = None  # an L1 solve: the position of the l1 event that reported the flag first
    platform: bool = False  # the platform lists it as solved (it is no flag of this run)
    before_run: bool = False  # it was solved when the run started (the platform, or the team folder, said so then)


def l1_flags(data: Mapping[str, object]) -> list[str]:
    """An L1 event's flags: the non-empty strings in its list (none when it is not a list)."""
    flags = data.get("flags")
    return [f for f in flags if isinstance(f, str) and f] if isinstance(flags, list) else []


# What a coding-agent CLI's report of a turn's cost said as its why before spend events were
# marked turn_end (agent/external.py at the time): a log written then is read the same way.
_EARLIER_TURN_ENDS = frozenset(
    text.format(kind=kind)
    for kind in ("claude", "codex")
    for text in (
        "what {kind} reported when its turn ended: the turn's cost, and tokens no step carried",
        "what {kind} reported for a turn it was stopped in (an escalation, or the lane's end)",
        "tokens {kind} counted after its last step, when it exited",
    )
)


def turn_end(data: Mapping[str, object]) -> bool:
    """Whether a spend event is a coding-agent CLI's own cost of a turn, which it reports when
    the turn ends (TurnReport.turn_end), and so not spend outside a turn: marked so, or in a
    log from before the mark, said so by its why."""
    why = data.get("why")
    return data.get("turn_end") is True or (isinstance(why, str) and why in _EARLIER_TURN_ENDS)


class Credit:
    """Who a solve goes to: the one rule every report uses (the post-flight report, writeups,
    the gap report and the scorecard), so no two of them give the same solve to different
    solvers. Read the log in order, see() every event, and ask flag() about an accepted flag
    and other() about any other event.

    - An accepted flag is L1's when an earlier `l1` event on that challenge reported it,
      whatever that event's status and whether or not a lane submitted it: it goes to the
      first engine that reported it. Otherwise it is the submitting lane's, or yours when no
      lane submitted it (a flag you submitted by hand). An L1 result alone is never a solve:
      "solved" there means found, and only the platform accepts a flag (l1/result.py).
    - A `teammate` event with `solved` true is a solve that came with no flag: a teammate's
      (team mode), or yours when it is recorded for "me". When the platform lists the
      challenge as solved (`source` "platform", Deck.platform_solved) it is yours if the
      platform says "you", else your team's on the platform: you or a teammate, the platform
      cannot say which. An older log wrote those as a teammate called "your team".
    """

    def __init__(self) -> None:
        self._found: dict[str, dict[str, tuple[str, int]]] = {}  # challenge -> flag -> (engine, l1 event's index)

    def see(self, index: int, event: EventLine) -> None:
        """Note what `event` (at `index` in the log) tells about later solves."""
        if event.kind == L1 and event.challenge:
            engine = _text(event.data.get("engine")) or "?"
            for flag in l1_flags(event.data):
                self._found.setdefault(event.challenge, {}).setdefault(flag, (engine, index))

    def flag(self, index: int, event: EventLine, flag: str) -> Solve:
        """The solve an accepted flag makes: `event` is its submit (at `index`)."""
        cid = event.challenge or ""
        at = run_time(event.at)
        found = self._found.get(cid, {}).get(flag) if flag else None
        if found is not None:
            return Solve(cid, L1, found[0], at, index, flag, event.lane, found=found[1])
        if event.lane:
            return Solve(cid, LANE, event.lane, at, index, flag, event.lane)
        return Solve(cid, PLAYER, ME, at, index, flag)

    @staticmethod
    def other(index: int, event: EventLine) -> Solve | None:
        """The solve a teammate or platform event makes; None when `event` is no solve."""
        if event.kind != "teammate" or event.data.get("solved") is not True or not event.challenge:
            return None
        who = _text(event.data.get("who")) if isinstance(event.data.get("who"), str) else ""
        platform = event.data.get("source") == "platform" or who == YOUR_TEAM
        if who == ME or (platform and who == YOU):
            by = PLAYER
        else:
            by = TEAM if platform else TEAMMATE
        return Solve(event.challenge, by, who, run_time(event.at), index, platform=platform,
                     before_run=event.data.get("before_run") is True)


SOLVERS = ((LANE, "lanes"), (L1, "L1"), (TEAMMATE, "teammates"), (PLAYER, "you"), (TEAM, "your team on the platform"))
"""Who a solve went to (Solve.by), as every report counts the solves, in this order."""


def solvers(found: Iterable[Solve]) -> str:
    """The solves by whom they went to, as every report says them: "lanes 3, L1 0, teammates
    0, you 1, your team on the platform 1", the last only when there are some. The post-flight
    report and the scorecard both count them so, by the same rule (Credit, solves()), each
    after the number of solves: "Solves: 5 (lanes 3, ...)"."""
    by = Counter(solve.by for solve in found)
    return ", ".join(f"{label} {by[who]}" for who, label in SOLVERS if who != TEAM or by[who])


def accepted(event: EventLine) -> bool:
    """A submit event whose flag was accepted (the platform checked it, or you said it did)."""
    return event.kind == "submit" and event.data.get("correct") is True


def solves(events: Sequence[EventLine], *, flags_only: bool = False) -> dict[str, Solve]:
    """Who solved each challenge: its first solve in the log, credited by Credit, by challenge
    id in the order they were solved. With `flags_only`, only accepted flags count (a draft
    needs one), not a teammate's or the platform's solve."""
    credit = Credit()
    found: dict[str, Solve] = {}
    for index, event in enumerate(events):
        credit.see(index, event)
        cid = event.challenge
        if not cid or cid in found:
            continue
        if accepted(event):
            flag = event.data.get("flag")
            found[cid] = credit.flag(index, event, flag if isinstance(flag, str) else "")
        elif not flags_only and (solve := Credit.other(index, event)) is not None:
            found[cid] = solve
    return found


# ---------------------------------------------------------------------- what the run played


@dataclass(frozen=True)
class RunInfo:
    """What a run played, from its run.json: local paths, never in the event log."""

    board: Path | None  # the board folder (a CTFd event's: the folder its board was pulled into)
    answers: Path | None  # the answers file it was given (--answers); None: the board's own, if any


def write_run_info(run_dir: Path, *, board: Path | None, answers: Path | None = None) -> Path:
    """Write RUN_DIR/run.json for a run that is starting: the board folder and answers file,
    as absolute paths. The run folder is new, so the file is created, never replaced (and so
    never written through a symlink)."""
    path = Path(run_dir) / RUN_INFO
    info = {
        "board": str(Path(board).resolve()) if board is not None else None,
        "answers": str(Path(answers).resolve()) if answers is not None else None,
    }
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
    with os.fdopen(handle, "w", encoding="ascii") as out:
        out.write(json.dumps(info, ensure_ascii=True) + "\n")
    return path


def write_run_setup(run_dir: Path, setup: Mapping[str, object]) -> Path:
    """Write RUN_DIR/setup.json for a run that is starting: how it was set up (the runtime,
    the lanes, the models), which the flight card of `flightdeck share` shows. No path, key,
    address or challenge is in it (run.py's _setup builds it). The run folder is new, so the
    file is created, never replaced (and so never written through a symlink)."""
    path = Path(run_dir) / RUN_SETUP
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
    with os.fdopen(handle, "w", encoding="ascii") as out:
        out.write(json.dumps(dict(setup), ensure_ascii=True) + "\n")
    return path


def read_run_setup(run_dir: Path) -> dict[str, object] | None:
    """What the run recorded about its setup; None when it recorded nothing (a run older than
    setup.json). RunFolderError, with the reason, when the file is there but cannot be used.
    A lane on the host can write in the run folder, so a reader treats every value as
    untrusted text."""
    path = Path(run_dir) / RUN_SETUP
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise RunFolderError(f"{path}: is not a regular file")
        if info.st_size > MAX_RUN_INFO:
            raise RunFolderError(f"{path}: is over {MAX_RUN_INFO:,} bytes, too big for what a run writes there")
        text = path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RunFolderError(f"{path}: cannot read it ({exc.strerror or exc})") from None
    except UnicodeDecodeError:
        raise RunFolderError(f"{path}: is not text") from None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise RunFolderError(f"{path}: is not JSON") from None
    if not isinstance(data, dict):
        raise RunFolderError(f"{path}: is not a JSON object")
    return data


def read_run_info(run_dir: Path) -> RunInfo | None:
    """What the run recorded it played; None when it recorded nothing (a run older than
    run.json). RunFolderError, with the reason, when the file is there but cannot be used."""
    path = Path(run_dir) / RUN_INFO
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):  # a lane on the host can write in the run folder: no symlink, no FIFO
            raise RunFolderError(f"{path}: is not a regular file")
        if info.st_size > MAX_RUN_INFO:
            raise RunFolderError(f"{path}: is over {MAX_RUN_INFO:,} bytes, too big for what a run writes there")
        text = path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RunFolderError(f"{path}: cannot read it ({exc.strerror or exc})") from None
    except UnicodeDecodeError:
        raise RunFolderError(f"{path}: is not text") from None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise RunFolderError(f"{path}: is not JSON") from None
    if not isinstance(data, dict):
        raise RunFolderError(f"{path}: is not a JSON object")
    paths: dict[str, Path | None] = {}
    for key in ("board", "answers"):
        value = data.get(key)
        if value is not None and not (isinstance(value, str) and value and "\x00" not in value):
            raise RunFolderError(f"{path}: {key} must be a path or null")
        paths[key] = Path(value) if value is not None else None
    return RunInfo(paths["board"], paths["answers"])
