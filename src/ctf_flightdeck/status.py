"""The status file: RUN_DIR/status.json, the run as it stands, for whatever is not the console.

A script, a tmux pane or a phone over SSH reads it during any run (`play` and `practice`, with
the console or headless): the lanes, what needs the player, the queue, the spend and the
solves. It is the deck's own state, read where the console reads it, so the two never differ.

It is written when the run is prepared, after a deck event (at most every MIN_GAP seconds: a
burst of events is one write at once and one more MIN_GAP later, with all of them in it), on
a timer while the run flies (run(): every INTERVAL seconds, so the runtime moves on with no
event), and once more when the run closes, with "closed": true. Each write is atomic: the whole document goes to a new file in
the run folder (made with O_EXCL and O_NOFOLLOW, so never through a link someone left there),
is flushed to disk and renamed over status.json. A reader sees the last document or the new
one, never a part of one, and a status.json that is a symbolic link is replaced, not followed.

What it holds comes from challenges, lanes and platforms: untrusted text. It is written as
JSON strings, pure ASCII (json escapes every control character, so nothing in it can reach a
terminal that shows the file as an escape sequence), long fields are cut (MAX_NAME,
MAX_TEXT), and it is data: nothing reads it back as instructions. Like events.jsonl it names
the flags lanes found (an approval's detail and flag), so it is the player's own file (mode
600). It never holds a secret: a lane's text has each held secret as [NAME] already
(agent/held.py); the same replacement is made again here on every string, and the value of
anything shaped like a credential is taken out of the text lanes wrote (credentials.py), as
in events.jsonl. The notification webhook's URL is one of the held secrets.

A status file that cannot be written never stops the run: it is a deck warning, said once
while the same failure lasts, and one of the run's exit lines (`problem`).

FORMAT 1, every field (docs/GUIDE.md has the same list for players):

    format            1
    flightdeck        the version that wrote it
    written           UTC time of this write, ISO 8601
    run               the run folder's name
    event             the event's name (the board's, or the event profile's)
    runtime_seconds   seconds since the run started
    closed            true in the last write, when the run has shut down
    lanes             each lane, by number: id, challenge {id, name}, state, model, turns,
                      tokens, dollars (what is known), unpriced (some of its spend had no
                      price), needs_you, pending (null, or {kind, detail, flag}: the approval
                      it waits for), waiting (further approvals behind it), alerts ([{kind,
                      reason}]), result (one line, once it ended)
    needs_you         the lanes that need the player, most urgent first (the console's
                      attention order): lane, challenge (its name), pending (the approval's
                      kind, or null), alerts (the kinds that want an answer)
    queue             length, held, held_reason (null unless held)
    totals            tokens, dollars, unpriced: over all lanes (the console's header)
    challenges        total, solved (by this run or a teammate)
    solves            each closed challenge: id, name, points, by (a lane id, "me" or a
                      teammate's handle), teammate (true when a teammate solved it)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__, credentials
from .agent.held import Secrets
from .core.model import FLAG_PENDING, INFORMATIONAL_ALERTS, ChallengeStatus, Event, Lane
from .eventlog import json_safe

if TYPE_CHECKING:
    from .core.deck import Deck

FORMAT = 1
NAME = "status.json"
INTERVAL = 2.0  # seconds between the timer's writes
MIN_GAP = 0.5  # an event within this many seconds of the last write is written once they have passed
MAX_NAME = 200  # characters of a name (a challenge, an event, a model) kept
MAX_TEXT = 500  # characters of any longer text (an approval's detail, an alert's reason, a result) kept
CUT = "..."


class StatusFile:
    """RUN_DIR/status.json for one deck. attach() writes it and follows the deck; run() is
    the timer (a task on the run's loop); close() writes it a last time, closed."""

    def __init__(
        self, path: Path, deck: Deck, *, run: str, held: Mapping[str, str] | None = None,
        interval: float = INTERVAL, min_gap: float = MIN_GAP,
    ) -> None:
        self.path = Path(path)
        self.deck = deck
        self.run_name = run
        self.interval = interval
        self.min_gap = min_gap
        self.problem = ""  # why the last write failed; "" when it worked
        self._held = Secrets(held)
        self._unsubscribe: Callable[[], None] | None = None
        self._last = float("-inf")  # time.monotonic() of the last write
        self._closed = False
        self._later: asyncio.TimerHandle | None = None  # the write of events that came within min_gap of the last

    def attach(self) -> None:
        """Write the file now and after the deck's events from now on."""
        if self._unsubscribe is not None:
            raise RuntimeError(f"the status file {self.path} is already attached")
        self._unsubscribe = self.deck.subscribe(self._event)
        self.write()

    async def run(self) -> None:
        """The timer: a write every `interval` seconds, until cancelled."""
        while True:
            await asyncio.sleep(self.interval)
            self.write()

    def close(self) -> None:
        """The run has shut down: the last write, with closed true. Once."""
        if self._closed:
            return
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        self.write(closed=True)
        self._closed = True

    def write(self, *, closed: bool = False) -> None:
        """Write the deck as it stands (on the deck's thread). Never raises for a file that
        cannot be written: that is `problem`, and a deck warning said once."""
        if self._closed:
            return
        self._last = time.monotonic()
        if self._later is not None:
            self._later.cancel()
            self._later = None
        try:
            data = (json.dumps(self.document(closed=closed), ensure_ascii=True, allow_nan=False, indent=1) + "\n").encode("ascii")
            write_atomically(self.path, data)
        except (OSError, ValueError) as exc:
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else f"{type(exc).__name__}: {exc}"
            self._failed(f"cannot write the status file {NAME} in the run folder: {reason}")
        else:
            self.problem = ""

    def document(self, *, closed: bool = False) -> dict[str, object]:
        """The status as plain JSON data."""
        deck = self.deck
        lanes = sorted(deck.lanes.values(), key=lambda lane: lane.number)
        flags = _flags(lanes)
        tokens, dollars, unpriced = deck.totals()
        challenges = list(deck.challenges.values())
        doc = {
            "format": FORMAT,
            "flightdeck": __version__,
            "written": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "run": self.run_name,
            "event": _name(deck.config.event),
            "runtime_seconds": round(deck.now, 1),
            "closed": closed,
            "lanes": [self._lane(lane, flags) for lane in lanes],
            "needs_you": [
                {
                    "lane": lane.id,
                    "challenge": _name(deck.challenges[lane.challenge_id].name),
                    "pending": lane.pending.kind.value if lane.pending is not None else None,
                    "alerts": [alert.kind.value for alert in lane.alerts if alert.kind not in INFORMATIONAL_ALERTS],
                }
                for lane in deck.needing()
            ],
            "queue": {
                "length": len(deck.queue),
                "held": bool(deck.held),
                "held_reason": _text(deck.held, flags) if deck.held else None,
            },
            "totals": {"tokens": tokens, "dollars": dollars, "unpriced": unpriced},
            "challenges": {"total": len(challenges), "solved": sum(1 for ch in challenges if ch.closed)},
            "solves": [
                {
                    "id": _name(ch.id), "name": _name(ch.name), "points": ch.points,
                    "by": _name(ch.solved_by) if ch.solved_by else None,
                    "teammate": ch.status is ChallengeStatus.TEAMMATE,
                }
                for ch in challenges if ch.closed
            ],
        }
        return self._without_secrets(json_safe(doc))

    def _lane(self, lane: Lane, flags: tuple[str, ...]) -> dict[str, object]:
        ch = self.deck.challenges[lane.challenge_id]
        pending = lane.pending
        return {
            "id": lane.id,
            "challenge": {"id": _name(ch.id), "name": _name(ch.name)},
            "state": lane.state.value,
            "model": _name(lane.model),
            "turns": lane.turns,
            "tokens": lane.tokens,
            "dollars": lane.known_dollars,
            "unpriced": lane.dollars is None,
            "needs_you": lane.needs_you,
            "pending": None if pending is None else {
                "kind": pending.kind.value,
                "detail": _text(self._held(pending.detail), flags),
                "flag": _cut(pending.flag, MAX_TEXT) if pending.flag is not None else None,
            },
            "waiting": len(lane.waiting),
            "alerts": [{"kind": alert.kind.value, "reason": _text(self._held(alert.reason), flags)} for alert in lane.alerts],
            "result": _text(self._held(lane.result), flags),
        }

    def _without_secrets(self, value: object) -> object:
        """Every string of the document with each held secret as [NAME]: the last line of
        defence, whatever field one would be in."""
        if isinstance(value, str):
            return self._held(value)
        if isinstance(value, dict):
            return {key: self._without_secrets(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._without_secrets(item) for item in value]
        return value

    def _event(self, event: Event) -> None:
        wait = self.min_gap - (time.monotonic() - self._last)
        if wait <= 0:
            self.write()
        elif self._later is None:
            try:
                self._later = asyncio.get_running_loop().call_later(wait, self.write)
            except RuntimeError:  # no loop yet (the run is being prepared): the next event or the timer writes it
                pass

    def _failed(self, problem: str) -> None:
        if problem == self.problem:
            return
        self.problem = problem
        with contextlib.suppress(Exception):  # the warning is a courtesy: `problem` is what the run's end reports
            self.deck.warn(problem, data={"source": "status"})


def write_atomically(path: Path, data: bytes) -> None:
    """Write `data` to a new file next to `path` (never an existing one, never through a
    link), flush it to disk and rename it over `path`: a reader sees the old content or the
    new, never a part of one, and a `path` that is a symbolic link is replaced, not followed."""
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _flags(lanes: list[Lane]) -> tuple[str, ...]:
    """The flags that wait for the player: kept whole where credentials are taken out."""
    found = []
    for lane in lanes:
        for pending in ([lane.pending] if lane.pending is not None else []) + list(lane.waiting):
            if pending.kind in FLAG_PENDING and pending.flag:
                found.append(pending.flag)
    return tuple(dict.fromkeys(found))


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - len(CUT)] + CUT


def _name(text: str) -> str:
    """A name from the board or the config: kept as it is, cut."""
    return _cut(str(text), MAX_NAME)


def _text(text: str, flags: tuple[str, ...]) -> str:
    """Text a lane or a platform wrote: credential values out (the waiting flags stay), cut."""
    return _cut(credentials.redact(str(text), keep=flags), MAX_TEXT)
