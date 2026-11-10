"""Lane order for the console: what needs the player first, then the rest by group."""

from __future__ import annotations

from ctf_flightdeck.core.attention import SortMode, sort_lanes
from ctf_flightdeck.core.model import Alert, AlertKind, Lane, LaneState, Pending, PendingKind

NOW = 10_000.0


def lane(n, *, state=LaneState.RUNNING, idle=0.0, alerts=(), pending=None, ended=None, dollars=0.0, tokens=0, turns=0):
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
        tokens=tokens,
        turns=turns,
    )


def alert(kind, age=0.0):
    return Alert(kind, "x", at=NOW - age)


def box(age=0.0):
    """An approval with no alert of its own."""
    return Pending(PendingKind.LIVE_BOX, "connect to the box", at=NOW - age)


def ids(lanes):
    return [x.id for x in lanes]


def attention(lanes):
    return ids(sort_lanes(lanes, SortMode.ATTENTION, NOW))


def test_groups_needs_you_then_informational_then_running_then_held_then_finished():
    # lane numbers run against the expected order, so only the grouping can produce it
    lanes = [
        lane(1, state=LaneState.SOLVED, ended=NOW - 10),
        lane(2, state=LaneState.TAKEOVER),
        lane(3, state=LaneState.PAUSED),
        lane(4, idle=30),
        lane(5, idle=600),
        lane(6, alerts=[alert(AlertKind.TEAMMATE)]),  # flightdeck already acted: nothing to answer
        lane(7, alerts=[alert(AlertKind.STALL)]),
    ]
    assert attention(lanes) == ["L07", "L06", "L05", "L04", "L02", "L03", "L01"]


def test_a_waiting_approval_needs_the_player_even_without_an_alert():
    lanes = [lane(1, idle=900), lane(2, state=LaneState.WAITING, pending=box())]
    assert attention(lanes) == ["L02", "L01"]


def test_urgency_flag_then_other_approvals_then_budget_then_the_course_alerts():
    # the least urgent item is the oldest and the most urgent is on the highest lane number,
    # so neither age nor lane order can produce this order
    items = [
        AlertKind.FLAG,
        None,  # an approval with no alert of its own
        AlertKind.BUDGET,
        AlertKind.LOOP,
        AlertKind.EFFORT,
        AlertKind.HINT,
        AlertKind.DIRECTION,
        AlertKind.STALL,
    ]
    lanes = []
    for rank, kind in enumerate(items):
        number, age = 8 - rank, 100.0 * rank
        if kind is None:
            lanes.append(lane(number, state=LaneState.WAITING, pending=box(age)))
        else:
            lanes.append(lane(number, alerts=[alert(kind, age)]))
    assert attention(lanes) == ["L08", "L07", "L06", "L05", "L04", "L03", "L02", "L01"]


def test_a_lane_is_ranked_by_its_most_urgent_item_not_its_first():
    lanes = [
        lane(1, alerts=[alert(AlertKind.STALL, 300), alert(AlertKind.LOOP, 10)]),  # a loop, raised second
        lane(2, alerts=[alert(AlertKind.EFFORT, 900)]),
    ]
    assert attention(lanes) == ["L01", "L02"]
    lanes = [
        lane(1, alerts=[alert(AlertKind.BUDGET, 900)]),
        lane(2, state=LaneState.WAITING, alerts=[alert(AlertKind.STALL, 50)], pending=box(5)),  # the approval counts
    ]
    assert attention(lanes) == ["L02", "L01"]


def test_the_same_urgency_goes_oldest_first():
    lanes = [lane(1, alerts=[alert(AlertKind.LOOP, 10)]), lane(2, alerts=[alert(AlertKind.LOOP, 90)])]
    assert attention(lanes) == ["L02", "L01"]
    lanes = [
        lane(3, state=LaneState.WAITING, pending=box(10)),
        lane(4, state=LaneState.WAITING, pending=box(90)),
    ]
    assert attention(lanes) == ["L04", "L03"]
    # lanes with only an informational alert, too
    lanes = [lane(5, alerts=[alert(AlertKind.TEAMMATE, 10)]), lane(6, alerts=[alert(AlertKind.TEAMMATE, 90)])]
    assert attention(lanes) == ["L06", "L05"]


def test_running_lanes_go_by_idle_minute_and_keep_lane_order_within_a_minute():
    # 5 s and 40 s both show as "under a minute": the order must not flip on every tick
    assert attention([lane(1, idle=5), lane(2, idle=40)]) == ["L01", "L02"]
    assert attention([lane(1, idle=125), lane(2, idle=170)]) == ["L01", "L02"]
    # different minutes (a new one starts at 60 s, 120 s, ...): the longer idle goes first
    assert attention([lane(1, idle=59), lane(2, idle=61)]) == ["L02", "L01"]
    assert attention([lane(1, idle=0), lane(2, idle=60)]) == ["L02", "L01"]
    assert attention([lane(1, idle=119), lane(2, idle=120)]) == ["L02", "L01"]


def test_finished_lanes_go_last_in_every_mode_most_recently_ended_first():
    lanes = [
        lane(1, state=LaneState.KILLED, ended=NOW - 500, dollars=99.0, tokens=10**7, turns=99, idle=9999),
        lane(2, state=LaneState.SOLVED, ended=NOW - 10, dollars=50.0, tokens=10**6, turns=50, idle=9000),
        lane(3, idle=1, dollars=0.1, turns=1),
        lane(4, idle=2, dollars=0.2, turns=2),
    ]
    for mode in SortMode:
        order = ids(sort_lanes(lanes, mode, NOW))
        assert sorted(order[:2]) == ["L03", "L04"], mode
        assert order[2:] == ["L02", "L01"], mode


def test_any_iterable_of_lanes_can_be_sorted():
    lanes = [lane(1, state=LaneState.KILLED, ended=NOW), lane(2)]
    for mode in SortMode:
        assert ids(sort_lanes((x for x in lanes), mode, NOW)) == ["L02", "L01"], mode


def test_the_other_sort_modes():
    lanes = [
        lane(1, idle=10, dollars=0.5, tokens=900, turns=40),
        lane(2, idle=900, dollars=2.0, tokens=100, turns=5),
        lane(3, idle=300, dollars=None, tokens=5000, turns=12),  # unknown price sorts as no cost
        lane(4, idle=300, dollars=0.5, tokens=2000, turns=12),
    ]
    assert ids(sort_lanes(lanes, SortMode.IDLE, NOW)) == ["L02", "L03", "L04", "L01"]
    assert ids(sort_lanes(lanes, SortMode.COST, NOW)) == ["L02", "L04", "L01", "L03"]
    assert ids(sort_lanes(lanes, SortMode.TURNS, NOW)) == ["L01", "L03", "L04", "L02"]
    assert ids(sort_lanes(lanes[::-1], SortMode.LANE, NOW)) == ["L01", "L02", "L03", "L04"]


def test_sort_mode_next_cycles_through_every_mode_in_order():
    mode, seen = SortMode.ATTENTION, []
    for _ in SortMode:
        seen.append(mode)
        mode = mode.next()
    assert seen == list(SortMode)
    assert mode is SortMode.ATTENTION
