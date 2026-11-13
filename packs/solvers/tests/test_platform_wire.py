"""B-140: the platform wire -- the per-request journal and the release-minute request budget.

Every test runs on synthetic requests: a recorded-fixture session (tests/platform_fixture_session.py)
or a stub request function. Nothing here touches the network.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import io
import json
import os
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

from ctf import cli, env, event
from ctf import eventscaffold as sc
from ctf.event import EventError, WirePace
from ctf.platform import gamemaster, get_adapter, wire
from ctf.platform.wire import POLL, PRIORITY, READ, decide

from platform_fixture_session import FakeSession, load

REPO = Path(__file__).resolve().parents[1]
FX = load("gamemaster_api.json")
GM = FX["base_url"]
TOKEN = "wire-test-token-zz9"
T0 = 1_760_000_400.0             # a whole minute (divisible by 60): the release anchor of the tests


class Clock:
    def __init__(self, t: float = T0):
        self.t = t
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.t += s


class Resp:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {}


def huntress(**wire_kw):
    p = event.load("huntress")
    return dataclasses.replace(p, wire=dataclasses.replace(WirePace(), **wire_kw))


def rows_at(*spec):
    """[ts, lane, cls] rows from (offset from T0, lane, cls) tuples."""
    return [[T0 + o, lane, cls] for o, lane, cls in spec]


# ------------------------------------------------------------------------------------------ ops

@pytest.mark.parametrize("method,params,body,want", [
    ("GET", {"op": "list", "all": "true"}, None, ("list", None)),
    ("GET", {"op": "status", "challenge": "metadata-day-01"}, None, ("status", "metadata-day-01")),
    ("GET", {"op": "artifact", "challenge": "c1", "delivery": 0}, None, ("artifact", "c1")),
    ("GET", {}, None, ("get", None)),
    ("POST", None, {"challenge": "c1", "answers": {"a": "flag{x}"}}, ("submit", "c1")),
    ("POST", None, {"challenge": "c1"}, ("start", "c1")),
    ("POST", None, {"other": 1}, ("post", None)),
])
def test_gamemaster_ops(method, params, body, want):
    assert wire.op_of("gamemaster", method, GM, params=params, json_body=body) == want


@pytest.mark.parametrize("method,path,body,want", [
    ("GET", "/api/v1/challenges", None, ("list", None)),
    ("GET", "/api/v1/challenges/17", None, ("challenge", "17")),
    ("POST", "/api/v1/challenges/attempt", {"challenge_id": 17, "submission": "CSCTF{x}"}, ("submit", "17")),
    ("GET", "/api/v1/teams/me/solves", None, ("solves", None)),
    ("GET", "/api/v1/users/me/solves", None, ("solves", None)),
    ("GET", "/api/v1/scoreboard", None, ("scoreboard", None)),
    ("GET", "/api/v1/containers/info", None, ("api:containers", None)),
    ("GET", "/", None, ("home", None)),
    ("HEAD", "/", None, ("time", None)),
    ("GET", "/files/abc/x.zip", None, ("file", None)),
    ("GET", "/elsewhere", None, ("get", None)),
])
def test_ctfd_ops_under_a_base_path(method, path, body, want):
    base = "https://ctf.example/sub"
    assert wire.op_of("ctfd", method, base + path + "?token=sig", base_url=base, json_body=body) == want


def test_classes():
    assert [wire.op_class(o) for o in ("submit", "start", "list", "status", "challenge")] == \
        [PRIORITY, PRIORITY, POLL, READ, READ]


# ------------------------------------------------------------------------------------------ decide

def test_pause_holds_every_class_until_it_ends():
    p = WirePace()
    for cls in (PRIORITY, POLL, READ):
        assert decide(p, [], T0, lane="x", cls=cls, pause_until=T0 + 7.5) == (7.5, "pause")
    assert decide(p, [], T0 + 7.5, lane="x", cls=READ, pause_until=T0 + 7.5) == (0.0, None)


def test_team_cap_keeps_the_reserve_for_priority_requests():
    p = WirePace(per_minute=5, reserve=2)
    rows = rows_at((-50, "a", READ), (-40, "a", READ), (-30, "b", READ))
    # 3 counted: a read stops at 5 - 2 = 3, and waits for the oldest row to leave the window
    assert decide(p, rows, T0, lane="a", cls=READ) == pytest.approx((10.0, "team"))
    assert decide(p, rows, T0, lane="a", cls=PRIORITY) == (0.0, None)
    rows += rows_at((-20, "a", PRIORITY), (-10, "a", PRIORITY))
    # 5 counted: a priority request waits too, until one row leaves (-50 + 60 = +10)
    assert decide(p, rows, T0, lane="a", cls=PRIORITY) == pytest.approx((10.0, "team"))
    # a row exactly 60 s old is out of the window
    assert decide(WirePace(per_minute=1), rows_at((-60, "a", READ)), T0, lane="a", cls=READ) == (0.0, None)
    assert decide(WirePace(per_minute=0), rows * 10, T0, lane="a", cls=READ) == (0.0, None)


def test_release_budget_holds_reads_to_the_window_end_and_only_inside_it():
    p = WirePace(release_budget=4, reserve=1)
    rows = rows_at((-5, "a", READ), (1, "a", READ), (2, "b", READ), (3, "c", POLL))
    # the row before the anchor does not count; 3 in the window = 4 - 1: a read waits to +60
    assert decide(p, rows, T0 + 10, lane="a", cls=READ, anchors=[T0]) == pytest.approx((50.0, "release"))
    assert decide(p, rows, T0 + 10, lane="a", cls=PRIORITY, anchors=[T0]) == (0.0, None)
    # no anchor, or an anchor whose window is over: no release rule
    assert decide(p, rows, T0 + 10, lane="a", cls=READ) == (0.0, None)
    assert decide(p, rows, T0 + 60, lane="a", cls=READ, anchors=[T0]) == (0.0, None)
    assert decide(p, rows, T0 - 0.1, lane="a", cls=READ, anchors=[T0]) == (0.0, None)


def test_poll_gap_spreads_list_polls_after_the_free_period_only():
    p = WirePace(release_poll_gap_s=4.0, release_poll_free_s=5.0)
    rows = rows_at((4.0, "watch", POLL), (4.5, "x", READ))
    # inside the free period: no gap
    assert decide(p, rows, T0 + 4.9, lane="watch", cls=POLL, anchors=[T0]) == (0.0, None)
    # past it: 4 s from the last poll of ANY lane (the read at 4.5 does not count)
    assert decide(p, rows, T0 + 5.0, lane="other", cls=POLL, anchors=[T0]) == pytest.approx((3.0, "poll_gap"))
    assert decide(p, rows, T0 + 8.0, lane="watch", cls=POLL, anchors=[T0]) == (0.0, None)
    # reads are never spread, and outside a window polls are not either
    assert decide(p, rows, T0 + 5.0, lane="watch", cls=READ, anchors=[T0]) == (0.0, None)
    assert decide(p, rows, T0 + 5.0, lane="watch", cls=POLL) == (0.0, None)
    # a poll counted at this very instant (another process) holds the next one the full gap;
    # one stamped after `now` (a clock ahead of ours) is not counted
    assert decide(p, rows_at((6.0, "x", POLL)), T0 + 6.0, lane="watch", cls=POLL,
                  anchors=[T0]) == pytest.approx((4.0, "poll_gap"))
    assert decide(p, rows_at((6.5, "x", POLL)), T0 + 6.0, lane="watch", cls=POLL, anchors=[T0]) == (0.0, None)


def test_lift_leaves_out_the_spreading_rules_only():
    p = WirePace(per_minute=2, release_budget=1, release_lane_budget=1, release_poll_gap_s=5.0,
                 release_poll_free_s=0.0)
    rows = rows_at((1, "a", POLL))
    for cls, why in ((READ, "release"), (POLL, "release")):
        assert decide(p, rows, T0 + 2, lane="a", cls=cls, anchors=[T0])[1] == why
        assert decide(p, rows, T0 + 2, lane="a", cls=cls, anchors=[T0], lift=wire.FORCEABLE) == (0.0, None)
    # each rule is lifted by its own name only
    assert decide(p, rows, T0 + 2, lane="a", cls=READ, anchors=[T0], lift={"release"}) == \
        pytest.approx((58.0, "lane"))
    assert decide(p, rows, T0 + 2, lane="a", cls=POLL, anchors=[T0], lift={"release"}) == \
        pytest.approx((4.0, "poll_gap"))
    # the team cap and a pause are not liftable
    full = rows_at((1, "a", POLL), (1.5, "b", READ))
    assert decide(p, full, T0 + 2, lane="c", cls=READ, anchors=[T0], lift=wire.FORCEABLE) == \
        pytest.approx((59.0, "team"))
    assert decide(p, [], T0, lane="c", cls=READ, pause_until=T0 + 3, lift=wire.FORCEABLE) == (3.0, "pause")
    for bad in ({"team"}, {"pause"}, {"releas"}):
        with pytest.raises(ValueError, match="can be lifted"):
            decide(p, [], T0, lane="c", cls=READ, lift=bad)


def test_lane_budget_counts_every_request_of_the_lane_and_holds_only_its_reads():
    p = WirePace(release_lane_budget=3, release_lanes=(("watch", 1),))
    rows = rows_at((1, "bin", POLL), (2, "bin", PRIORITY), (3, "bin", READ), (4, "web", READ))
    assert decide(p, rows, T0 + 10, lane="bin", cls=READ, anchors=[T0]) == pytest.approx((50.0, "lane"))
    assert decide(p, rows, T0 + 10, lane="bin", cls=POLL, anchors=[T0]) == (0.0, None)
    assert decide(p, rows, T0 + 10, lane="bin", cls=PRIORITY, anchors=[T0]) == (0.0, None)
    assert decide(p, rows, T0 + 10, lane="web", cls=READ, anchors=[T0]) == (0.0, None)
    # the override: watch gets 1
    assert decide(p, rows_at((1, "watch", POLL)), T0 + 2, lane="watch", cls=READ,
                  anchors=[T0]) == pytest.approx((58.0, "lane"))
    # an unnamed lane has no lane budget, however many it sent
    assert decide(p, rows_at(*[(i, None, READ) for i in range(9)]), T0 + 10, lane=None, cls=READ,
                  anchors=[T0]) == (0.0, None)


def test_the_longest_hold_wins():
    p = WirePace(per_minute=2, release_lane_budget=1)
    rows = rows_at((-59, "a", READ), (1, "a", READ))
    # team: wait 1 s (the -59 row leaves); lane: wait to +60
    assert decide(p, rows, T0 + 2, lane="a", cls=READ, anchors=[T0]) == pytest.approx((58.0, "lane"))


def test_next_pause():
    p = WirePace(pause_s=20.0, pause_max_s=60.0)
    assert wire.next_pause(p, T0, 7.0, 0.0, 0.0) == 7.0
    assert wire.next_pause(p, T0, 500.0, 0.0, 0.0) == 60.0
    assert wire.next_pause(p, T0, None, 0.0, 0.0) == 20.0
    assert wire.next_pause(p, T0, None, T0 - 100, 20.0) == 40.0
    assert wire.next_pause(p, T0, None, T0 - 100, 40.0) == 60.0
    assert wire.next_pause(p, T0, None, T0 - 121, 40.0) == 20.0
    # exactly REPEAT_WINDOW_S after the previous 429 is still a repeat
    q = WirePace(pause_s=10.0, pause_max_s=100.0)
    assert wire.next_pause(q, T0, None, T0 - wire.REPEAT_WINDOW_S, 20.0) == 40.0
    assert wire.next_pause(q, T0, None, T0 - wire.REPEAT_WINDOW_S - 0.5, 20.0) == 10.0


def test_limit_headers_keep_only_rate_limit_headers():
    r = Resp(429, {"Retry-After": "12", "X-RateLimit-Remaining": "0", "RateLimit-Reset": "30",
                   "Authorization": "Bearer x", "Set-Cookie": "session=y", "Date": "now"})
    assert wire.limit_headers(r) == {"retry-after": "12", "x-ratelimit-remaining": "0", "ratelimit-reset": "30"}


# ------------------------------------------------------------------------------------------ the wire

def stub_wire(tmp_path, clock, err=None, lane="bin", **kw):
    return wire.Wire(huntress(**kw), workdir=tmp_path, clock=clock, sleep=clock.sleep, lane=lane,
                     err=err if err is not None else io.StringIO())


def test_send_journals_op_status_timing_and_counts(tmp_path):
    clk = Clock()
    w = stub_wire(tmp_path, clk)

    def req(method, url, **kw):
        clk.t += 0.25
        return Resp(200)

    w.send(req, "GET", GM, params={"op": "status", "challenge": "c9"})
    w.send(req, "POST", GM, json={"challenge": "c9", "answers": {"q": "flag{secretvalue}"}})
    rows, bad = wire.read_journal(tmp_path)
    assert bad == 0 and len(rows) == 2
    a, b = rows
    assert (a["op"], a["cls"], a["status"], a["lane"], a["challenge"], a["method"]) == \
        ("status", READ, 200, "bin", "c9", "GET")
    assert a["ts"] == T0 and a["dur_s"] == 0.25 and a["held_s"] == 0 and a["held_by"] is None
    assert (a["n60"], a["nmin"], b["n60"], b["nmin"]) == (1, 1, 2, 2)
    assert (b["op"], b["cls"]) == ("submit", PRIORITY) and b["ts"] == T0 + 0.25
    assert a["pid"] == os.getpid() and a["forced"] is False and a["kind"] == "gamemaster"
    text = (tmp_path / "wire" / "journal.jsonl").read_text()
    assert "secretvalue" not in text and GM not in text
    assert (tmp_path / "wire" / "journal.jsonl").stat().st_mode & 0o777 == 0o600


def test_nmin_restarts_on_the_calendar_minute(tmp_path):
    clk = Clock(T0 + 59.0)
    w = stub_wire(tmp_path, clk)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    clk.t = T0 + 61.0
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    rows, _ = wire.read_journal(tmp_path)
    assert [(r["n60"], r["nmin"]) for r in rows] == [(1, 1), (2, 1)]


def test_a_held_request_waits_and_says_why(tmp_path):
    clk = Clock()
    w = stub_wire(tmp_path, clk, per_minute=2, max_wait_s=100.0)
    for _ in range(3):
        w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
        clk.t += 1.0
    rows, _ = wire.read_journal(tmp_path)
    third = rows[2]
    # rows at T0 and T0+1; asked at T0+2, sent when the T0 row leaves the window (T0+60)
    assert third["held_by"] == "team" and third["ts"] == pytest.approx(T0 + 60.0, abs=1e-3)
    assert third["held_s"] == pytest.approx(58.0) and third["forced"] is False


@pytest.mark.parametrize("kw,held_by", [
    ({"release_budget": 1}, "release"),
    ({"release_lane_budget": 1}, "lane"),
])
def test_max_wait_sends_forced_and_says_so(tmp_path, kw, held_by):
    clk = Clock()
    err = io.StringIO()
    wire.mark_releases(tmp_path, [T0], now=T0)
    w = stub_wire(tmp_path, clk, err=err, max_wait_s=5.0, **kw)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status", "challenge": "c2"})
    rows, _ = wire.read_journal(tmp_path)
    assert rows[1]["forced"] is True and rows[1]["held_by"] == held_by
    assert rows[1]["ts"] == pytest.approx(T0 + 5.0, abs=1e-4)      # at max_wait_s, not a tick after
    assert f"sent after 5 s held by the {held_by} budget" in err.getvalue()


def test_max_wait_forces_a_poll_past_the_poll_gap(tmp_path):
    clk = Clock(T0 + 10)
    wire.mark_releases(tmp_path, [T0], now=T0)
    w = stub_wire(tmp_path, clk, release_poll_free_s=0.0, release_poll_gap_s=50.0, max_wait_s=5.0)
    for _ in range(2):
        w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "list"})
    rows, _ = wire.read_journal(tmp_path)
    assert (rows[1]["held_by"], rows[1]["forced"]) == ("poll_gap", True)
    assert rows[1]["ts"] == pytest.approx(T0 + 15.0, abs=1e-3)


def test_max_wait_never_lifts_the_team_cap(tmp_path):
    """per_minute stands for the platform's limit: a read held past max_wait_s by it waits on (and says
    so) until the oldest counted request leaves the window, instead of drawing the 429."""
    clk = Clock()
    err = io.StringIO()
    w = stub_wire(tmp_path, clk, err=err, per_minute=1, max_wait_s=5.0)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status", "challenge": "c2"})
    rows, _ = wire.read_journal(tmp_path)
    assert (rows[1]["held_by"], rows[1]["forced"]) == ("team", False)
    assert rows[1]["ts"] == pytest.approx(T0 + 60.0, abs=1e-3)
    assert "held 60 s by the team cap (per_minute 1); max_wait_s never lifts it" in err.getvalue()
    assert "journaled forced" not in err.getvalue()


def test_a_forced_request_still_waits_for_the_team_cap(tmp_path):
    """Held by the release budget past max_wait_s, a read is let go by that budget only: the team cap
    (2 a minute: one row before the anchor, one in the window) still holds it until +50 s."""
    clk = Clock(T0 - 10)
    wire.mark_releases(tmp_path, [T0], now=T0)
    w = stub_wire(tmp_path, clk, per_minute=2, release_budget=1, max_wait_s=5.0)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    clk.t = T0
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    clk.t = T0 + 1
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    third = wire.read_journal(tmp_path)[0][2]
    assert (third["held_by"], third["forced"]) == ("release", True)
    assert third["ts"] == pytest.approx(T0 + 50.0, abs=1e-3)
    assert third["n60"] == 2


def test_max_wait_never_cuts_a_pause_short(tmp_path):
    """A request held past max_wait_s by a budget still sits out a 429 pause that began meanwhile."""
    clk = Clock()
    wire.mark_releases(tmp_path, [T0], now=T0)
    other = stub_wire(tmp_path, clk, lane="web")        # no budget of its own: it sends at once
    fired = []

    def sleep(s):
        clk.sleep(s)
        if not fired:           # while we wait, another process gets a 429 with Retry-After 20
            fired.append(1)
            other.send(lambda *a, **k: Resp(429, {"Retry-After": "20"}), "GET", GM, params={"op": "list"})
    w = wire.Wire(huntress(release_budget=1, max_wait_s=5.0), workdir=tmp_path, clock=clk, sleep=sleep,
                  lane="bin", err=io.StringIO())
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    sent = [r for r in wire.read_journal(tmp_path)[0] if r["lane"] == "bin"][1]
    assert sent["forced"] is True and sent["held_by"] == "release"
    assert sent["ts"] == pytest.approx(T0 + 25.0, abs=1e-3)     # 5 s budget hold, then the 20 s pause


def test_time_in_a_pause_does_not_count_toward_max_wait(tmp_path):
    """Paused 20 s first, then held by the release budget: forced after 5 s of the budget hold (+25),
    not at once when the pause ends."""
    clk = Clock()
    wire.mark_releases(tmp_path, [T0], now=T0)
    w = stub_wire(tmp_path, clk, release_budget=1, max_wait_s=5.0)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    stub_wire(tmp_path, clk, lane="web").send(lambda *a, **k: Resp(429, {"Retry-After": "20"}), "GET", GM,
                                              params={"op": "list"})
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    sent = [r for r in wire.read_journal(tmp_path)[0] if r["lane"] == "bin"][1]
    assert (sent["held_by"], sent["forced"]) == ("pause", True)
    assert sent["ts"] == pytest.approx(T0 + 25.0, abs=1e-4)


def test_a_shorter_429_never_cuts_a_longer_shared_pause(tmp_path):
    """Two requests in flight: process B's 429 pauses everyone 60 s; process A's answer, a 429 with
    Retry-After 1, arrives after it and must leave the 60 s pause in place."""
    clk = Clock()
    a = stub_wire(tmp_path, clk, lane="a")
    b = stub_wire(tmp_path, clk, lane="b")

    def a_request(*_a, **_k):
        b.send(lambda *x, **y: Resp(429, {"Retry-After": "60"}), "GET", GM, params={"op": "list"})
        return Resp(429, {"Retry-After": "1"})
    a.send(a_request, "GET", GM, params={"op": "status"})
    st = json.loads((tmp_path / "wire" / "state.json").read_text())
    assert st["pause_until"] == T0 + 60.0 and st["last_pause_s"] == 1.0
    c = stub_wire(tmp_path, clk, lane="c")
    c.send(lambda *x, **y: Resp(), "GET", GM, params={"op": "status"})
    last = wire.read_journal(tmp_path)[0][-1]
    assert (last["lane"], last["held_by"]) == ("c", "pause")
    assert last["ts"] == pytest.approx(T0 + 60.0, abs=1e-3)


def test_a_429_pauses_every_process_and_is_journaled_whole(tmp_path):
    clk = Clock()
    err = io.StringIO()
    w1 = stub_wire(tmp_path, clk, err=err)
    w2 = stub_wire(tmp_path, clk, lane="web")          # another process of the same workdir
    hdr = {"Retry-After": "12", "X-RateLimit-Remaining": "0", "Authorization": "Bearer nope"}
    w1.send(lambda *a, **k: Resp(429, hdr), "GET", GM, params={"op": "list", "all": "true"})
    w2.send(lambda *a, **k: Resp(200), "POST", GM, json={"challenge": "c1", "answers": {"q": "v"}})
    rows, _ = wire.read_journal(tmp_path)
    r429, after = rows
    assert (r429["status"], r429["op"], r429["retry_after"], r429["pause_s"]) == (429, "list", 12.0, 12.0)
    assert r429["limit_headers"] == {"retry-after": "12", "x-ratelimit-remaining": "0"}
    assert after["held_by"] == "pause" and after["ts"] == pytest.approx(T0 + 12.0, abs=1e-3)
    assert "HTTP 429 on list (lane bin; 1 request(s) in the last 60 s" in err.getvalue()
    assert "Bearer" not in (tmp_path / "wire" / "journal.jsonl").read_text()


def test_a_repeat_429_doubles_the_pause(tmp_path):
    clk = Clock()
    w = stub_wire(tmp_path, clk, pause_s=10.0, pause_max_s=100.0)
    for _ in range(3):
        w.send(lambda *a, **k: Resp(429), "GET", GM, params={"op": "list"})
    rows, _ = wire.read_journal(tmp_path)
    assert [r["pause_s"] for r in rows] == [10.0, 20.0, 40.0]
    assert [r["held_by"] for r in rows] == [None, "pause", "pause"]


def test_a_send_that_raises_is_journaled_and_reraised(tmp_path):
    clk = Clock()
    w = stub_wire(tmp_path, clk)

    def boom(*a, **k):
        raise TimeoutError("slow")
    with pytest.raises(TimeoutError):
        w.send(boom, "GET", GM, params={"op": "status"})
    (r,), _ = wire.read_journal(tmp_path)
    assert r["status"] is None and r["error"] == "TimeoutError"


def test_lane_comes_from_the_environment_and_is_checked(tmp_path):
    clk = Clock()
    w = wire.Wire(huntress(), workdir=tmp_path, clock=clk, sleep=clk.sleep, environ={"CTF_WIRE_LANE": "mobile"})
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    assert wire.read_journal(tmp_path)[0][0]["lane"] == "mobile"
    bad = wire.Wire(huntress(), workdir=tmp_path, environ={"CTF_WIRE_LANE": "../x"})
    with pytest.raises(wire.WireError, match="CTF_WIRE_LANE"):
        bad.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    with pytest.raises(wire.WireError):
        w.lane = "a b"
    unnamed = wire.Wire(huntress(), workdir=tmp_path, environ={})
    assert unnamed.lane is None


def test_an_unusable_wire_dir_fails_loudly_and_sends_nothing(tmp_path):
    blocker = tmp_path / "work"
    blocker.write_text("a file, not a folder")
    sent = []
    w = wire.Wire(huntress(), workdir=blocker, environ={})
    with pytest.raises(wire.WireError, match="unusable"):
        w.send(lambda *a, **k: sent.append(1), "GET", GM, params={"op": "list"})
    assert sent == []


def test_a_torn_state_is_rebuilt_from_the_journal(tmp_path):
    clk = Clock()
    err = io.StringIO()
    w = stub_wire(tmp_path, clk, err=err, per_minute=3, max_wait_s=1000.0)
    for _ in range(3):
        w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    (tmp_path / "wire" / "state.json").write_text("{torn")
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    rows, _ = wire.read_journal(tmp_path)
    assert rows[3]["held_by"] == "team" and rows[3]["ts"] == pytest.approx(T0 + 60.0, abs=1e-3)
    assert "did not parse; rebuilt 3 recent request(s) from the journal" in err.getvalue()


def test_release_anchors_are_shared_and_old_ones_dropped(tmp_path):
    clk = Clock(T0 + 3)
    wire.mark_releases(tmp_path, [T0, T0 - 2 * 86400], now=clk.t)
    w = stub_wire(tmp_path, clk, release_budget=1)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "status"})
    rows, _ = wire.read_journal(tmp_path)
    assert rows[0]["rel_s"] == 3.0
    assert rows[1]["held_by"] == "release" and rows[1]["ts"] == pytest.approx(T0 + 33.0, abs=1e-3)   # max_wait 30
    assert rows[1]["forced"] is True
    st = json.loads((tmp_path / "wire" / "state.json").read_text())
    assert st["releases"] == [T0]
    s = w.status()
    assert s["windows"][0]["requests"] == 2 and s["windows"][0]["by_lane"] == {"bin": 2}


def test_profile_dates_start_is_an_anchor():
    p = dataclasses.replace(event.load("huntress"), start=dt.datetime.fromtimestamp(T0, dt.timezone.utc))
    assert wire.profile_anchors(p) == [T0]
    assert wire.profile_anchors(event.load("huntress")) == []      # a bare date is not a time


def test_two_processes_share_one_budget(tmp_path):
    """Real processes, real clock: a release budget of 5 across both; the rest wait max_wait_s and go
    forced."""
    import time
    wire.mark_releases(tmp_path, [time.time()])
    script = textwrap.dedent(f"""
        import dataclasses, sys
        sys.path.insert(0, {str(REPO)!r})
        from ctf import event
        from ctf.event import WirePace
        from ctf.platform import wire
        class R: status_code = 200; headers = {{}}
        p = dataclasses.replace(event.load("huntress"),
                                wire=WirePace(release_budget=5, release_window_s=600.0, max_wait_s=0.3))
        w = wire.Wire(p, workdir={str(tmp_path)!r}, lane=sys.argv[1])
        for _ in range(4):
            w.send(lambda *a, **k: R(), "GET", "http://x.invalid/", params={{"op": "status"}})
    """)
    procs = [subprocess.Popen([sys.executable, "-I", "-c", script, lane], stderr=subprocess.PIPE)
             for lane in ("a", "b")]
    errs = [p.communicate(timeout=60)[1].decode() for p in procs]
    assert [p.returncode for p in procs] == [0, 0], errs
    rows, bad = wire.read_journal(tmp_path)
    assert bad == 0 and len(rows) == 8
    assert sum(1 for r in rows if not r["forced"]) == 5
    assert sum(1 for r in rows if r["forced"]) == 3
    assert sorted(r["n60"] for r in rows) == list(range(1, 9))      # every admission counted once
    assert sum(e.count("journaled forced") for e in errs) == 3


# ------------------------------------------------------------------------------------------ wiring

def test_get_adapter_routes_the_game_master_session_through_the_wire(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_WIRE_LANE", "metadata")
    fake = FakeSession(FX["routes"])
    monkeypatch.setattr(gamemaster, "make_adapter",
                        lambda p: gamemaster.GameMasterAdapter(GM, token=TOKEN, session=fake))
    gate = get_adapter(event.load("huntress"))
    w = wire.of(gate)
    assert isinstance(w, wire.Wire) and w.pace == event.load("huntress").wire
    gate.get_challenge("metadata-day-01")                 # a list, then a status
    res = gate.submit("metadata-day-01", "Alice Example", provenance="test", allow_nonstandard=True)
    assert res.accepted
    rows, _ = wire.read_journal(tmp_path)
    assert [(r["op"], r["status"], r["lane"]) for r in rows] == [
        ("list", 200, "metadata"), ("status", 200, "metadata"),
        ("status", 200, "metadata"), ("submit", 200, "metadata")]
    assert fake.calls[0]["headers"]["Authorization"] == "Bearer " + TOKEN   # attributes pass through
    text = (tmp_path / "wire" / "journal.jsonl").read_text()
    assert TOKEN not in text and "Alice Example" not in text
    assert wire.install(gate, gate._adapter) is w          # idempotent: never wrapped twice


def test_get_adapter_wraps_the_ctfd_session_and_skips_adapters_without_one(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    # Many suite modules set CTF_PLATFORM_URL at import; under xdist every worker imports them all, and
    # the ctfd adapter refuses a URL that differs from the profile's. Clear it (and its legacy names).
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL")):
        monkeypatch.delenv(name, raising=False)
    gate = get_adapter(event.load("csctf"))
    assert isinstance(gate._adapter._s, wire.WireSession) and wire.of(gate).kind == "ctfd"
    mod = types.ModuleType("ctf.platform.ctfd")

    class NoHTTP:
        kind = "ctfd"

        def list_challenges(self): return []
        def get_challenge(self, cid): raise AssertionError
        def download_files(self, cid, dest): return []
        def submit(self, cid, flag): raise AssertionError
        def team_solves(self): return []
        def scoreboard(self): return []
    mod.make_adapter = lambda p: NoHTTP()
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    assert wire.of(get_adapter(event.load("csctf"))) is None


def test_watch_run_marks_its_anchors_and_journals_as_the_watch_lane(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.delenv("CTF_WIRE_LANE", raising=False)
    fake = FakeSession(FX["routes"])
    monkeypatch.setattr(gamemaster, "make_adapter",
                        lambda p: gamemaster.GameMasterAdapter(GM, token=TOKEN, session=fake))
    when = "2030-01-01T09:00:00Z"
    assert cli.main(["watch", "--event", "huntress", "run", "--once", "--wave", when]) == 0
    st = json.loads((tmp_path / "wire" / "state.json").read_text())
    assert dt.datetime(2030, 1, 1, 9, tzinfo=dt.timezone.utc).timestamp() in st["releases"]
    rows, _ = wire.read_journal(tmp_path)
    assert rows and {r["lane"] for r in rows} == {"watch"} and rows[0]["op"] == "list"


# ------------------------------------------------------------------------------------------ the release minute

def simulate(tmp_path, pace: WirePace, until: float = 60.0):
    """A Day-10-shaped release minute through the shipped admission path (Wire.admission: the shared
    state file, every budget rule, max_wait_s forcing), on a virtual clock. Each actor is one
    sequential process: the watcher fast-polls each second (a list and 2 detail reads, the next poll
    1 s after the last began, or at once if it fell behind) from 20 s before the anchor; five lanes
    each fetch their challenge (list + status) and 3 artifacts from +1 s, then poll status every 3 s;
    at +30 s a sixth process resumes lane3 with a submit. Requests take no time.
    Returns the admissions ([ts, lane, cls, forced, held_by]) and the resume's (asked, sent) offsets."""
    import heapq
    clk = Clock(T0 - 20)
    wire.mark_releases(tmp_path, [T0], now=clk.t)
    prof = dataclasses.replace(event.load("huntress"), wire=pace)

    def watcher():
        t = T0 - 20.0
        while t < T0 + until:
            for op in ("list", "status", "status"):
                yield t, op
            t = max(t + 1.0, clk.t)

    def lane(i):
        t = T0 + 1.0 + i * 0.01
        for op in ("list", "status", "artifact", "artifact", "artifact"):
            yield t, op
        while True:
            t = max(t + 3.0, clk.t)
            if t >= T0 + until:
                return
            yield t, "status"

    def resume():
        yield T0 + 30.0, "submit"

    actors = [("watch", watcher()), *((f"lane{i}", lane(i)) for i in range(5)), ("lane3", resume())]
    out: list = []
    sent_resume = None
    heap: list = []
    seq = 0

    def plan_next(name, plan):
        nonlocal seq
        nxt = next(plan, None)
        if nxt is not None:
            heapq.heappush(heap, (max(nxt[0], clk.t), seq, name, plan, nxt[1], None))
            seq += 1

    for name, plan in actors:
        plan_next(name, plan)
    while heap:
        at, _s, name, plan, op, steps = heapq.heappop(heap)
        clk.t = at
        if steps is None:
            # poll_inflight=0: this simulation drives admission() directly (never send()), so a
            # poll-inflight slot would never be freed; and with "requests take no time" there is no
            # real concurrency to cap. The poll-inflight cap (B-252) is exercised in test_release_latency.
            w = wire.Wire(prof, workdir=tmp_path, clock=clk, sleep=clk.sleep, lane=name,
                          err=io.StringIO(), poll_inflight=0)
            steps = w.admission(name, wire.op_class(op))
        try:
            wait = next(steps)
        except StopIteration as done:
            adm = done.value
            out.append([adm["ts"], name, wire.op_class(op), adm["forced"], adm["held_by"]])
            if op == "submit":
                sent_resume = (30.0, adm["ts"] - T0)
            plan_next(name, plan)
            continue
        heapq.heappush(heap, (at + wait, seq, name, plan, op, steps))
        seq += 1
    return out, sent_resume


def test_the_huntress_budget_keeps_the_release_minute_under_the_refusals_and_sends_the_resume(tmp_path):
    pace = event.load("huntress").wire
    rows, resume = simulate(tmp_path / "budget", pace)
    in_minute = [r for r in rows if T0 <= r[0] < T0 + 60]
    rolling = max(sum(1 for x in rows if r[0] - 60 < x[0] <= r[0]) for r in rows)
    assert len(in_minute) <= pace.release_budget < 51       # under the earliest release-minute refusal
    assert rolling <= pace.per_minute < 88                  # under the lowest rolling refusal, forced sends too
    assert resume == (30.0, 30.0)                           # the +30 s submit was not held at all
    assert any(r[4] for r in in_minute)                     # the budget did hold traffic in the minute
    # without the budget, the same traffic spends the minute before +30 s
    bare, _ = simulate(tmp_path / "bare", WirePace())
    by30 = sum(1 for r in bare if T0 <= r[0] < T0 + 30)
    assert by30 > 51


def test_forced_sends_in_the_release_minute_never_pass_the_team_cap(tmp_path):
    """A tight team cap with a 5 s max wait: the release and lane budgets are forced open again and
    again, yet no rolling 60 s ever holds more than per_minute."""
    pace = dataclasses.replace(event.load("huntress").wire, per_minute=40, reserve=4, release_budget=30,
                               max_wait_s=5.0)
    rows, resume = simulate(tmp_path, pace)
    assert sum(1 for r in rows if r[3]) >= 5                # forcing happened
    assert max(sum(1 for x in rows if r[0] - 60 < x[0] <= r[0]) for r in rows) <= 40
    assert resume is not None


# ------------------------------------------------------------------------------------------ profile

def _parse(**wire_table):
    data = sc.profile_data("acme", name="A", start=dt.date(2026, 1, 1), end=dt.date(2026, 1, 2), kind="ctfd",
                           base_url="https://x.example", prefixes=["A"], submit_mode="confirm",
                           ai_on_platform="allowed")
    data["wire"] = wire_table
    return event.parse(data, src="t")


def test_profile_wire_table_parses_and_defaults():
    assert _parse().wire == WirePace()
    p = _parse(per_minute=85, release_budget=48, reserve=8, release_poll_gap_s=4, release_lane_budget=8,
               release_lanes={"watch": 6, "bin": 0})
    assert p.wire.release_poll_gap_s == 4.0 and p.wire.release_lanes == (("bin", 0), ("watch", 6))
    assert p.wire.lane_budget("watch") == 6 and p.wire.lane_budget("bin") == 0
    assert p.wire.lane_budget("web") == 8 and p.wire.lane_budget(None) == 0
    assert event.load("huntress").wire.per_minute == 85


@pytest.mark.parametrize("table,msg", [
    ({"per_minut": 1}, "unknown key"),
    ({"per_minute": 1.5}, "must be int"),
    ({"per_minute": True}, "boolean"),
    ({"reserve": -1}, "wire.reserve must be >= 0"),
    ({"per_minute": 5, "reserve": 5}, "below wire.per_minute"),
    ({"release_budget": 3, "reserve": 3}, "below wire.release_budget"),
    ({"release_window_s": 0}, "release_window_s must be > 0"),
    ({"release_poll_free_s": 61}, "longer than wire.release_window_s"),
    ({"pause_s": 200}, "above wire.pause_max_s"),
    ({"release_lanes": {"a b": 1}}, "release_lanes key"),
    ({"release_lanes": {"bin": -1}}, "release_lanes.bin"),
    ({"release_lanes": {"bin": True}}, "release_lanes.bin"),
])
def test_profile_wire_table_is_validated(table, msg):
    with pytest.raises(EventError, match=msg):
        _parse(**table)


def test_new_event_scaffold_writes_the_wire_table():
    data = sc.profile_data("acme", name="A", start=dt.date(2026, 1, 1), end=dt.date(2026, 1, 2), kind="ctfd",
                           base_url="https://x.example", prefixes=["A"], submit_mode="confirm",
                           ai_on_platform="allowed")
    text = sc.to_toml(data)
    assert "\n[wire]\nper_minute = 0\n" in text
    assert sc.validate(data, "acme").wire == WirePace()


# ------------------------------------------------------------------------------------------ CLI

def _journal(tmp_path, rows):
    d = tmp_path / "wire"
    d.mkdir(parents=True, exist_ok=True)
    (d / "journal.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows) + "not json\n")


def test_cli_ratelimits_gives_the_mix_before_each_429(tmp_path, capsys):
    rows = [{"ts": T0 + i, "op": "list" if i % 2 else "status", "lane": "watch" if i % 2 else "bin",
             "cls": POLL if i % 2 else READ, "status": 200, "n60": i + 1, "nmin": i + 1} for i in range(6)]
    rows.append({"ts": T0 + 29.0, "op": "list", "lane": "web", "cls": POLL, "status": 429, "n60": 7,
                 "nmin": 7, "rel_s": 29.0, "pause_s": 20.0, "retry_after": None,
                 "limit_headers": {"x-ratelimit-remaining": "0"}})
    rows.append({"ts": T0 - 40.0, "op": "status", "lane": "bin", "cls": READ, "status": 200})   # out of the 60 s
    _journal(tmp_path, rows)
    assert cli.main(["wire", "--event", "huntress", "--workdir", str(tmp_path), "ratelimits", "--json"]) == 0
    out, err = capsys.readouterr()
    (x,) = json.loads(out)
    assert x["by_op"] == {"list": 4, "status": 3} and x["by_lane"] == {"watch": 3, "bin": 3, "web": 1}
    assert x["journal_60s"] == 7 and x["second"] == 29.0 and x["rel_s"] == 29.0
    assert "1 unreadable line(s) skipped" in err
    assert cli.main(["wire", "--event", "huntress", "--workdir", str(tmp_path), "ratelimits"]) == 0
    out = capsys.readouterr().out
    assert "429 at" in out and "on list lane=web: 7 in the last 60 s" in out and "x-ratelimit-remaining: 0" in out


def test_ratelimit_report_window_is_the_60_s_up_to_the_429():
    t = T0 + 100.0
    rows = [{"ts": t - 60.0, "op": "status", "lane": "old", "cls": READ, "status": 200},
            {"ts": t - 59.5, "op": "list", "lane": "watch", "cls": POLL, "status": 200},
            {"ts": t, "op": "list", "lane": "web", "cls": POLL, "status": 429},
            {"ts": t + 0.5, "op": "status", "lane": "late", "cls": READ, "status": 200}]
    (x,) = wire.ratelimit_report(rows)
    assert x["journal_60s"] == 2 and x["by_lane"] == {"watch": 1, "web": 1}
    assert x["journal_minute"] == 1 and x["second"] == 40.0       # the calendar minute began at t - 40


def test_wait_not_before_records_a_release_anchor(tmp_path, monkeypatch):
    import time
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))

    class C:
        class cfg:
            @staticmethod
            def require_auth():
                pass

        @staticmethod
        def challenges():
            return []
    monkeypatch.setattr(cli, "_ctfd", lambda: C())
    monkeypatch.setattr(cli, "wait_for_open", lambda fn, **kw: (1, "timed out"))
    at = float(int(time.time()) + 3600)
    assert cli.main(["wait", "--not-before", str(int(at))]) == 1
    st = json.loads((tmp_path / "wire" / "state.json").read_text())
    assert st["releases"] == [at]


def test_wait_not_before_says_so_when_the_anchor_cannot_be_recorded(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "work"
    blocker.write_text("a file, not a folder")
    monkeypatch.setenv("CTF_WORKDIR", str(blocker))

    class C:
        class cfg:
            @staticmethod
            def require_auth():
                pass

        @staticmethod
        def challenges():
            return []
    monkeypatch.setattr(cli, "_ctfd", lambda: C())
    monkeypatch.setattr(cli, "wait_for_open", lambda fn, **kw: (1, "timed out"))
    assert cli.main(["wait", "--not-before", "4000000000"]) == 1
    assert "--not-before not recorded as a release anchor" in capsys.readouterr().err


def test_cli_journal_filters_and_status(tmp_path, capsys):
    clk = Clock()
    w = stub_wire(tmp_path, clk)
    w.send(lambda *a, **k: Resp(), "GET", GM, params={"op": "list"})
    w.send(lambda *a, **k: Resp(404), "GET", GM, params={"op": "status", "challenge": "c1"})
    base = ["wire", "--event", "huntress", "--workdir", str(tmp_path)]
    assert cli.main(base + ["journal", "--op", "status", "--json"]) == 0
    (r,) = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert r["status"] == 404 and r["challenge"] == "c1"
    assert cli.main(base + ["journal", "--status", "200"]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and " list " in out and "lane=bin" in out
    assert cli.main(base + ["journal", "--lane", "nobody"]) == 0
    assert "for that filter" in capsys.readouterr().out
    assert cli.main(base + ["mark-release", "--at", "2030-01-01T09:00:00Z"]) == 0
    assert "release anchor 2030-01-01T09:00:00.000Z recorded" in capsys.readouterr().out
    assert cli.main(base + ["status"]) == 0
    out = capsys.readouterr().out
    assert "per_minute 85" in out and "next anchor 2030-01-01T09:00:00.000Z" in out
    assert cli.main(base + ["status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["pace"]["release_budget"] == 48
    assert cli.main(base + ["mark-release", "--at", "yesterday"]) == 2
    assert "ctf wire mark-release:" in capsys.readouterr().err
