"""Lane ordering for the console: what needs the player first.

Attention order (CONSOLE-SPEC): lanes with alerts first, then lanes waiting for an
approval, then running lanes by idle time, then paused and taken-over lanes. Finished
lanes always go last (the console collapses them).

Idle time is compared in whole minutes, the precision the console shows, so running
lanes that were active within the same minute keep a stable order instead of
reshuffling on every tick.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from .model import AlertKind, Lane, LaneState

ALERT_URGENCY = {
    AlertKind.FLAG: 0,  # points waiting for one key press
    AlertKind.BUDGET: 1,  # the lane is about to stop, or has
    AlertKind.LOOP: 2,
    AlertKind.EFFORT: 3,
    AlertKind.HINT: 4,
    AlertKind.DIRECTION: 5,
    AlertKind.STALL: 6,
    AlertKind.TEAMMATE: 7,  # stopping is automatic; informational
}


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
    """0 alerts, 1 waiting for approval, 2 running, 3 paused or taken over, 4 finished."""
    if lane.finished:
        return 4
    if lane.alerts:
        return 0
    if lane.pending is not None:
        return 1
    if lane.state is LaneState.RUNNING:
        return 2
    return 3


def attention_key(lane: Lane, now: float) -> tuple:
    group = attention_group(lane)
    if group == 0:
        top = min(lane.alerts, key=lambda a: (ALERT_URGENCY[a.kind], a.at))
        return (0, ALERT_URGENCY[top.kind], top.at, lane.number)
    if group == 1:
        assert lane.pending is not None
        return (1, 0, lane.pending.at, lane.number)
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
