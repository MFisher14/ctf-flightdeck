"""Each lane's whole log, kept for post-flight and writeups.

The event log (eventlog.py) records what happened across the run, one line per event; a
step there is one line. Post-flight reports and writeup drafts need more: every step
with its output, flightdeck's notes, the alerts, and the files a lane changed with their
diffs. This writes them to `<run>/lanes/<lane id>.jsonl` when a lane ends (again when
spend comes in after its end), and for every lane still open when the run closes. Lines
are JSON objects (pure ASCII), first a header
for the lane, then one per action, then one per changed file.
"""

from __future__ import annotations

import json
from pathlib import Path

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
        self.folder.mkdir(parents=True, exist_ok=True)
        path = self.folder / f"{lane.id}.jsonl"
        lines = [{
            "lane": lane.id, "challenge": challenge.id, "name": challenge.name, "category": challenge.category,
            "points": challenge.points, "model": lane.model, "state": lane.state.value, "result": lane.result,
            "turns": lane.turns, "tokens": lane.tokens, "cached_tokens": lane.cached_tokens, "dollars": lane.dollars, "known_dollars": lane.known_dollars,
            "started_at": lane.started_at, "ended_at": lane.ended_at, "parent": lane.parent, "attempt": lane.attempt,
            "plan": lane.plan,
        }]
        lines += [{
            "at": a.at, "turn": a.turn, "kind": a.kind.value, "by": a.by.value, "text": a.text, "output": a.output,
            "alert": a.alert.value if a.alert else None,
        } for a in lane.actions]
        lines += [
            {"file": f.path, "status": f.status, "turn": f.turn, "at": f.at, "diff": f.diff, "by": f.by}
            for f in lane.files.values()
        ]
        path.write_text("".join(json.dumps(line, ensure_ascii=True) + "\n" for line in lines), encoding="ascii")
        self.written.add(lane.id)
        return path

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
