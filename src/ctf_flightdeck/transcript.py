"""Each lane's whole log, kept for post-flight and writeups.

The event log (eventlog.py) records what happened across the run, one line per event; a
step there is one line. Post-flight reports and writeup drafts need more: every step
with its output, flightdeck's notes, the alerts, and the files a lane changed with their
diffs. This writes them to `<run>/lanes/<lane id>.jsonl` when a lane ends (again when
spend comes in after its end), and for every lane still open when the run closes. Lines
are JSON objects (pure ASCII), first a header for the lane, then one per action, then one
per changed file.

A step of flightdeck's own loop is one turn: its `text` and `output` are what the console
showed (the turn's first real tool call, "(+N more)" for the rest, at most 3 lines and 300
characters of output), and its `calls` are every tool call the turn ran, in order, each with
its one line and a longer excerpt of its output (agent/tools.py: up to 40 lines and 4000
characters). A line without `calls` is any other entry, a coding-agent CLI's step (one per
tool call already), or a transcript written before the field.

What the lane wrote (its plan and result, each action's text and output, each call's, each
file's diff) is written with the value of anything shaped like a credential taken out (credentials.py):
a host lane can read the player's keys file or another process's environment, and a run
folder is read, shared and drafted into writeups. The flags the run knows for the
challenge (proposed, waiting, submitted, or reported by L1) stay as they are.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import credentials
from .core.deck import Deck
from .core.model import EventKind, Lane


class TranscriptLog:
    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.written: set[str] = set()
        self._deck: Deck | None = None
        self._unsubscribe = None

    def attach(self, deck: Deck) -> None:
        self._deck = deck
        self._unsubscribe = deck.subscribe(self._event)

    def _event(self, event) -> None:
        # Written when the lane ends, and again for spend that comes after its end (a
        # coding-agent CLI reports a turn's cost when the turn ends), so the header holds the
        # lane's final totals.
        late = event.kind is EventKind.SPEND and event.lane in self.written
        if (event.kind is EventKind.LANE_END or late) and event.lane and self._deck is not None:
            lane = self._deck.lanes.get(event.lane)
            if lane is not None:
                self.write(lane)

    def write(self, lane: Lane) -> Path:
        """Write (or rewrite) one lane's transcript."""
        assert self._deck is not None, "attach() first"
        challenge = self._deck.challenges[lane.challenge_id]
        flags = self._flags(challenge.id)

        def clean(text: str) -> str:
            return credentials.redact(text, keep=flags)

        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / f"{lane.id}.jsonl"
        lines = [{
            "lane": lane.id, "challenge": challenge.id, "name": challenge.name, "category": challenge.category,
            "points": challenge.points, "model": lane.model, "state": lane.state.value, "result": clean(lane.result),
            "turns": lane.turns, "tokens": lane.tokens, "cached_tokens": lane.cached_tokens, "dollars": lane.dollars, "known_dollars": lane.known_dollars,
            "started_at": lane.started_at, "ended_at": lane.ended_at, "parent": lane.parent, "attempt": lane.attempt,
            "plan": clean(lane.plan),
            "dollars_later": lane.dollars_later,  # a CLI's turn was under way: its cost had not come yet, so dollars is not all of it
        }]
        for a in lane.actions:
            line = {
                "at": a.at, "turn": a.turn, "kind": a.kind.value, "by": a.by.value, "text": clean(a.text), "output": clean(a.output),
                "alert": a.alert.value if a.alert else None,
            }
            if a.calls:  # every tool call of the turn; the fields above stay the console's one step
                line["calls"] = [{"text": clean(call.text), "output": clean(call.output)} for call in a.calls]
            lines.append(line)
        lines += [
            {"file": f.path, "status": f.status, "turn": f.turn, "at": f.at, "diff": clean(f.diff), "by": f.by}
            for f in lane.files.values()
        ]
        path.write_text("".join(json.dumps(line, ensure_ascii=True) + "\n" for line in lines), encoding="ascii")
        self.written.add(lane.id)
        return path

    def _flags(self, challenge_id: str) -> tuple[str, ...]:
        """Every flag the run knows for a challenge, from the deck's events: proposed and
        waiting (pending), submitted, and reported by an L1 engine."""
        assert self._deck is not None
        flags: dict[str, None] = {}
        for event in self._deck.events:
            if event.challenge != challenge_id:
                continue
            flag, found = event.data.get("flag"), event.data.get("flags")
            if isinstance(flag, str):
                flags[flag] = None
            if isinstance(found, (list, tuple)):
                flags.update((item, None) for item in found if isinstance(item, str))
        return tuple(flags)

    def close(self) -> None:
        """Write every lane not yet written (those still open at the end of the run)."""
        if self._deck is None:
            return
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        for lane in self._deck.lanes.values():
            if lane.id not in self.written:
                self.write(lane)
