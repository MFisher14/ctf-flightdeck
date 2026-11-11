"""The run log: every deck event as one JSON object per line, appended as it happens.

The deck already describes every change as an Event with a structured payload, so the
log is that stream and nothing else: no environment, no config, no keys. "at" is the
deck's clock (seconds since the event started) and "wall" the UTC time the line was
written. Each line is flushed as it is written, so a crash loses at most the line in
progress. Lines are
plain ASCII (json escapes everything else), so a newline, a line separator or an escape
sequence in a flag or a command can never split a line or reach a terminal that shows
the file.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import IO, TYPE_CHECKING

from . import __version__
from .core.model import Event

if TYPE_CHECKING:
    from .core.deck import Deck

MAX_DEPTH = 32  # deeper data is written as its repr


class EventLog:
    """Append-only JSONL of a run's deck events, one object per line, flushed per line."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file: IO[str] | None = self.path.open("a", encoding="ascii")
        self._unsubscribe: list[Callable[[], None]] = []
        self._decks: list[Deck] = []
        try:
            self._write({"kind": "run-start", "wall": _wall(), "version": __version__})
        except BaseException:
            self._file.close()
            raise

    def attach(self, deck: Deck) -> None:
        """Log every event the deck emits from now on. Events it emitted before are written
        first (their "wall" is when they were written; "at" is when they happened), so the
        file holds the whole run however late the log is attached."""
        if self._file is None:
            raise RuntimeError(f"the event log {self.path} is closed")
        if any(attached is deck for attached in self._decks):
            raise RuntimeError(f"the event log {self.path} is already attached to this deck")
        for event in list(deck.events):
            self._event(event)
        self._unsubscribe.append(deck.subscribe(self._event))
        self._decks.append(deck)

    def close(self) -> None:
        """Stop listening and write the run-end line. Calling it again does nothing."""
        if self._file is None:
            return
        for unsubscribe in self._unsubscribe:
            unsubscribe()
        self._unsubscribe.clear()
        self._decks.clear()
        try:
            self._write({"kind": "run-end", "wall": _wall()})
        finally:
            self._file.close()
            self._file = None

    def __enter__(self) -> EventLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _event(self, event: Event) -> None:
        self._write(
            {
                "at": event.at,
                "wall": _wall(),
                "kind": event.kind.value,
                "text": event.text,
                "lane": event.lane,
                "challenge": event.challenge,
                "alert": event.alert.value if event.alert is not None else None,
                "data": event.data,
            }
        )

    def _write(self, record: dict[str, object]) -> None:
        assert self._file is not None
        self._file.write(json.dumps(json_safe(record), ensure_ascii=True, allow_nan=False) + "\n")
        self._file.flush()


def new_run_dir(base: Path, now: datetime | None = None) -> Path:
    """A new folder for one run: base/<YYYYmmdd-HHMMSS> (local time), or with -2, -3... when
    that name is taken. Created here, so two runs started in the same second get two folders."""
    base = Path(base).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    stamp = (now if now is not None else datetime.now()).strftime("%Y%m%d-%H%M%S")
    n = 1
    while True:
        run_dir = base / (stamp if n == 1 else f"{stamp}-{n}")
        try:
            run_dir.mkdir()
        except FileExistsError:
            n += 1
            continue
        return run_dir


def json_safe(value: object, _depth: int = 0) -> object:
    """`value` as plain JSON data: enums by their value, tuples, lists and sets as lists,
    mappings with string keys, floats that are not finite as strings ("nan", "inf"), and
    any other object as its repr. It never raises, so a listener built on it cannot break
    the deck."""
    if _depth > MAX_DEPTH:
        return repr(value)
    if isinstance(value, Enum):
        return json_safe(value.value, _depth + 1)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, Mapping):
        return {_key(key): json_safe(item, _depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item, _depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return [json_safe(item, _depth + 1) for item in sorted(value, key=repr)]  # sorted: the same run, the same line
    return repr(value)


def _key(key: object) -> str:
    if isinstance(key, Enum):
        key = key.value
    return key if isinstance(key, str) else repr(key)


def _wall() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
