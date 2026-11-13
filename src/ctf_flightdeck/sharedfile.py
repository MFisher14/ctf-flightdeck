"""shared.json: what each lane of each challenge tried, kept in the run folder (core/shared.py's
record, as a file).

During a run the record lives in the deck: a lane's entry is read from the deck when another
lane needs it (agent/sharing.py). This file is that record for after the run, and for whoever
is not the console: every challenge a lane worked, with each lane's entry. It is written when a
lane ends and when the run closes (never on a timer: an entry is settled when its lane ends),
atomically and owner-only, the way status.json is (status.write_atomically).

It never holds a secret: a lane's text has each held secret as [NAME] already (agent/held.py);
the same replacement is made again here on every string, and the value of anything shaped like
a credential is taken out of what lanes wrote (credentials.py), the flags they gave kept whole.
Every text is cut to MAX_TEXT characters. The flags a lane gave are in it, with what became of
each, as they are in events.jsonl: the run folder is the player's own.

A file that cannot be written never stops the run: it is a deck warning, said once while the
same failure lasts, and one of the run's exit lines (`problem`).

FORMAT 1:

    format       1
    flightdeck   the version that wrote it
    written      UTC time of this write, ISO 8601
    run          the run folder's name
    closed       true in the last write, when the run has shut down
    challenges   each challenge a lane worked, by id: name, series (its series key,
                 core/series.py, or null), lanes: each lane's entry, oldest lane first, with the
                 fields of core/shared.Attempt (lane, challenge, models, how, state, open,
                 ended, turns, approach, plan, programs [[name, count]], steps, last_steps
                 [[turn, command, output]], found, files [[path, status]], flags [[flag,
                 [what became of it]]], alerts [[label, reason]])
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__, credentials
from .agent.held import Secrets
from .core import series, shared
from .core.model import Event, EventKind
from .eventlog import json_safe
from .status import write_atomically

if TYPE_CHECKING:
    from .core.deck import Deck

FORMAT = 1
NAME = "shared.json"
MAX_TEXT = 500  # characters of any text kept
CUT = "..."


class SharedFile:
    """RUN_DIR/shared.json for one deck. attach() follows the deck (a write at each lane's
    end); close() writes it a last time, closed."""

    def __init__(self, path: Path, deck: Deck, *, run: str, held: Mapping[str, str] | None = None) -> None:
        self.path = Path(path)
        self.deck = deck
        self.run_name = run
        self.problem = ""  # why the last write failed; "" when it worked
        self._held = Secrets(held)
        self._unsubscribe: Callable[[], None] | None = None
        self._closed = False

    def attach(self) -> None:
        """Write the file after every lane's end from now on."""
        if self._unsubscribe is not None:
            raise RuntimeError(f"the shared record {self.path} is already attached")
        self._unsubscribe = self.deck.subscribe(self._event)

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
        """Write the record as the deck holds it (on the deck's thread). Never raises for a
        file that cannot be written, or a record that cannot be read from the deck: that is
        `problem`, and a deck warning said once."""
        if self._closed:
            return
        try:
            data = (json.dumps(self.document(closed=closed), ensure_ascii=True, allow_nan=False, indent=1) + "\n").encode("ascii")
            write_atomically(self.path, data)
        except (OSError, ValueError, RuntimeError) as exc:
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else f"{type(exc).__name__}: {exc}"
            self._failed(f"cannot write the lanes' shared record {NAME} in the run folder: {reason}")
        else:
            self.problem = ""

    def document(self, *, closed: bool = False) -> dict[str, object]:
        """The record as plain JSON data."""
        deck = self.deck
        worked = dict.fromkeys(lane.challenge_id for lane in sorted(deck.lanes.values(), key=lambda lane: lane.number))
        challenges: dict[str, object] = {}
        flags: list[str] = []
        for cid in worked:
            attempts = shared.record(deck, cid)
            flags += [flag for attempt in attempts for flag, _ in attempt.flags]
            name = deck.challenges[cid].name
            lanes = credentials.redact_data(json_safe([attempt.data() for attempt in attempts]), keep=tuple(dict.fromkeys(flags)))
            challenges[cid] = {"name": name, "series": series.series_key(name), "lanes": lanes}  # the board's names stay as they are
        doc = {
            "format": FORMAT,
            "flightdeck": __version__,
            "written": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "run": self.run_name,
            "closed": closed,
            "challenges": challenges,
        }
        return self._safe(doc)  # type: ignore[return-value]

    def _safe(self, value: object) -> object:
        """Every string of the document with each held secret as [NAME], cut to MAX_TEXT."""
        if isinstance(value, str):
            text = self._held(value)
            return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - len(CUT)] + CUT
        if isinstance(value, dict):
            return {key: self._safe(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._safe(item) for item in value]
        return value

    def _event(self, event: Event) -> None:
        if event.kind is EventKind.LANE_END:
            self.write()

    def _failed(self, problem: str) -> None:
        if problem == self.problem:
            return
        self.problem = problem
        with contextlib.suppress(Exception):  # the warning is a courtesy: `problem` is what the run's end reports
            self.deck.warn(problem, data={"source": "shared"})
