"""Attention order: alerts first, then approvals, then running lanes by idle time."""

from __future__ import annotations

from ctf_flightdeck.core.attention import SortMode, sort_lanes
from ctf_flightdeck.core.model import Alert, AlertKind, Lane, LaneState, Pending, PendingKind

NOW = 10_000.0


def lane(n, *, state=LaneState.RUNNING, idle=0.0, alerts=(), pending=None, ended=None, dollars=0.0, turns=0):
    return Lane(
        number=n,
        challenge_id=f"c{n}",
        model="m",
        state=state,
        last_active_at=NOW - idle,
        alerts=list(alerts),
        pending=pending,
        ended_at=ended,
        dollars=dollars,
        turns=turns,
    )


def ids(lanes):
    return [x.id for x in lanes]


def test_alerts_first_then_approvals_then_running_by_idle_then_paused_then_finished():
    lanes = [
        lane(1, idle=30),
        lane(2, idle=600),
        lane(3, state=LaneState.PAUSED, idle=9000),
        lane(4, alerts=[Alert(AlertKind.STALL, "x", at=NOW - 10)]),
        lane(5, state=LaneState.WAITING, pending=Pending(PendingKind.LIVE_BOX, "box", at=NOW - 5)),
        lane(6, state=LaneState.SOLVED, ended=NOW - 100),
        lane(7, idle=180),
    ]
    assert ids(sort_lanes(lanes, SortMode.ATTENTION, NOW)) == ["L04", "L05", "L02", "L07", "L01", "L03", "L06"]


def test_among_alerts_flag_and_budget_come_before_course_alerts():
    lanes = [
        lane(1, alerts=[Alert(AlertKind.STALL, "x", at=NOW - 500)]),
        lane(2, alerts=[Alert(AlertKind.FLAG, "x", at=NOW - 1)]),
        lane(3, alerts=[Alert(AlertKind.BUDGET, "x", at=NOW - 1)]),
        lane(4, alerts=[Alert(AlertKind.HINT, "x", at=NOW - 50), Alert(AlertKind.LOOP, "x", at=NOW - 2)]),
    ]
    assert ids(sort_lanes(lanes, SortMode.ATTENTION, NOW)) == ["L02", "L03", "L04", "L01"]


def test_same_alert_kind_oldest_first():
    lanes = [
        lane(1, alerts=[Alert(AlertKind.LOOP, "x", at=NOW - 10)]),
        lane(2, alerts=[Alert(AlertKind.LOOP, "x", at=NOW - 90)]),
    ]
    assert ids(sort_lanes(lanes, SortMode.ATTENTION, NOW)) == ["L02", "L01"]


def test_running_lanes_active_in_the_same_minute_keep_lane_order():
    # 5 s and 40 s idle both show as "under a minute": order must not flip on every tick
    lanes = [lane(2, idle=5), lane(1, idle=40)]
    assert ids(sort_lanes(lanes, SortMode.ATTENTION, NOW)) == ["L01", "L02"]


def test_finished_lanes_go_last_in_every_mode():
    lanes = [lane(1, state=LaneState.KILLED, ended=NOW, dollars=99.0, turns=99, idle=9999), lane(2, idle=1)]
    for mode in SortMode:
        assert ids(sort_lanes(lanes, mode, NOW)) == ["L02", "L01"], mode


def test_other_sort_modes():
    lanes = [
        lane(1, idle=10, dollars=0.5, turns=40),
        lane(2, idle=900, dollars=2.0, turns=5),
        lane(3, idle=300, dollars=None, turns=12),
    ]
    assert ids(sort_lanes(lanes, SortMode.IDLE, NOW)) == ["L02", "L03", "L01"]
    assert ids(sort_lanes(lanes, SortMode.COST, NOW)) == ["L02", "L01", "L03"]
    assert ids(sort_lanes(lanes, SortMode.TURNS, NOW)) == ["L01", "L03", "L02"]
    assert ids(sort_lanes(lanes[::-1], SortMode.LANE, NOW)) == ["L01", "L02", "L03"]


def test_sort_mode_cycles_through_every_mode():
    mode, seen = SortMode.ATTENTION, []
    for _ in SortMode:
        seen.append(mode)
        mode = mode.next()
    assert mode is SortMode.ATTENTION and set(seen) == set(SortMode)
