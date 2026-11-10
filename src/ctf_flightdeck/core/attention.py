"""Lane ordering for the console: what needs the player first.

Attention order (CONSOLE-SPEC, refined at the M0 review):
0. lanes that need the player: an approval waiting or an alert that wants an answer,
   by urgency (a flag first, then any other approval, then budget, then the course
   alerts), oldest first within the same urgency;
1. lanes with only an informational alert (flightdeck already acted, e.g. a teammate
   holds the live box);
2. running lanes by idle time, in whole minutes (the precision the console shows), so
   lanes active within the same minute keep their order instead of reshuffling;
3. paused and taken-over lanes;
4. finished lanes, most recently ended first (the console collapses them).
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from .model import INFORMATIONAL_ALERTS, AlertKind, Lane, LaneState

ALERT_URGENCY = {
    AlertKind.FLAG: 0,  # points waiting for one key press
    AlertKind.BUDGET: 2,  # the lane is about to stop, or has
    AlertKind.LOOP: 3,
    AlertKind.EFFORT: 4,
    AlertKind.HINT: 5,
    AlertKind.DIRECTION: 6,
    AlertKind.STALL: 7,
    AlertKind.TEAMMATE: 8,  # informational
}
PENDING_URGENCY = 1  # an approval with no alert of its own, e.g. live-box access


class SortMode(StrEnum):
    ATTENTION = "attention"
    IDLE = "idle"
    COST = "cost"
    TURNS = "turns"
    LANE = "lane"

    def next(self) -> SortMode:
        modes = list(SortMode)
        return modes[(modes.index(self) + 1) % len(modes)]


def attention_group(lane: Lane) -> int:
    if lane.finished:
        return 4
    if lane.needs_you:
        return 0
    if lane.alerts:
        return 1
    if lane.state is LaneState.RUNNING:
        return 2
    return 3


def top_item(lane: Lane) -> tuple[int, float]:
    """(urgency, since) of the most urgent thing the lane needs the player for."""
    items = [(ALERT_URGENCY[a.kind], a.at) for a in lane.alerts if a.kind not in INFORMATIONAL_ALERTS]
    if lane.pending is not None:
        items.append((PENDING_URGENCY, lane.pending.at))
    return min(items)


def attention_key(lane: Lane, now: float) -> tuple:
    group = attention_group(lane)
    if group == 0:
        urgency, since = top_item(lane)
        return (0, urgency, since, lane.number)
    if group == 1:
        return (1, 0, min(a.at for a in lane.alerts), lane.number)
    if group == 2:
        return (2, -int(lane.idle(now) // 60), 0, lane.number)
    return (group, 0, 0, lane.number)


def sort_lanes(lanes: Iterable[Lane], mode: SortMode, now: float) -> list[Lane]:
    """Active lanes in `mode` order, then finished lanes, most recent first."""
    lanes = list(lanes)
    active = [lane for lane in lanes if not lane.finished]
    finished = [lane for lane in lanes if lane.finished]
    if mode is SortMode.ATTENTION:
        active.sort(key=lambda lane: attention_key(lane, now))
    elif mode is SortMode.IDLE:
        active.sort(key=lambda lane: (-lane.idle(now), lane.number))
    elif mode is SortMode.COST:
        active.sort(key=lambda lane: (-(lane.dollars or 0.0), -lane.tokens, lane.number))
    elif mode is SortMode.TURNS:
        active.sort(key=lambda lane: (-lane.turns, lane.number))
    else:
        active.sort(key=lambda lane: lane.number)
    finished.sort(key=lambda lane: (-(lane.ended_at or 0.0), lane.number))
    return active + finished
