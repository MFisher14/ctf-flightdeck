"""B-036: the serial path's failure handling in ctf/adapt/setpool.py (the pool itself is in
tests/test_adapt_pool_queue.py, the per-set share in tests/test_ladder_set_share.py)."""
from __future__ import annotations

import signal
import sys

from ctf.adapt import setpool as P


def one(n, ctx=None):
    return (n, [{"qid": "a", "answer_id": f"s{n}.a"}, {"qid": "b", "answer_id": f"s{n}.b"}], {},
            ctx if ctx is not None else {"set": n})


class Script:
    def __init__(self, how):
        self.how = how

    def solve_set(self, qs, files, ctx):
        how = self.how.get(ctx["set"], "ok")
        ctx["partial"]["a"] = f"p{ctx['set']}"
        if how == "exit":
            sys.exit(3)
        if how == "raise":
            raise ValueError("bad member")
        if how == "blank":
            return {"a": "   ", "b": "v"}
        return {"a": f"a{ctx['set']}", "b": f"b{ctx['set']}"}


def test_exit_and_raise_keep_partials_and_cost_only_their_set():
    errors = []
    raw, timed_out, said = P.solve(Script({1: "exit", 2: "raise"}), [one(1), one(2), one(3)], 5.0, errors)
    assert raw == {"s1.a": "p1", "s2.a": "p2", "s3.a": "a3", "s3.b": "b3"}
    assert not timed_out
    assert any("sys.exit(3)" in e for e in errors) and any("ValueError: bad member" in e for e in errors)


def test_a_blank_answer_is_no_answer():
    raw, _, _ = P.solve(Script({1: "blank"}), [one(1)], None, [])
    assert raw == {"s1.b": "v"}


def test_a_set_without_its_delivery_is_not_solved():
    errors = []
    raw, _, _ = P.solve(Script({}), [one(1, {"set": 1, "delivery": b""}), one(2)], None, errors)
    assert set(raw) == {"s2.a", "s2.b"} and "set 1: its delivery was not downloaded" in errors[0]


def test_a_spent_budget_skips_the_rest_and_says_so():
    class Slow:
        def solve_set(self, qs, files, ctx):
            while True:
                pass
    errors = []
    raw, timed_out, _ = P.solve(Slow(), [one(1), one(2)], 0.3, errors)
    assert timed_out and raw == {}
    assert any("set 1: solver stopped" in e for e in errors)
    assert any(e.startswith("set 2:") for e in errors)


def test_the_watchdog_leaves_no_alarm_behind():
    P.solve(Script({}), [one(1)], 1.0, [])
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
