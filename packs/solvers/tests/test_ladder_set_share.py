"""Huntress backlog row 163: each set of a timed attempt gets a share of the solve budget.

The serial path of the timed runner, carried into ctf/adapt/setpool.py by B-036 (the Huntress
timed_ladder.py that first held it needs the archived Game Master client and cannot be imported in the
master; these tests used to be reported not run for that reason). No network and no token. A fake
solver hangs on one set (a hostile or huge member); the sets after it must still be answered, the hung
set's partial answers must be taken, and the whole run must end near its budget.
"""
from __future__ import annotations

import time

import pytest

from ctf.adapt import setpool as L


class Hangs:
    """Answers every set at once, except set `bad`, where it fills one partial answer and then spins."""

    def __init__(self, bad):
        self.bad = bad

    def solve_set(self, qs, files, ctx):
        if ctx["set"] == self.bad:
            ctx["partial"][qs[0]["qid"]] = "early"
            while True:
                time.sleep(0.01)
        return {q["qid"]: f"v{ctx['set']}" for q in qs}


def sets(n, per=2):
    out = []
    for s in range(1, n + 1):
        qs = [{"qid": f"q{i}", "answer_id": f"set{s}.q{i}"} for i in range(per)]
        out.append((s, qs, {}, {"set": s, "delivery": b"x"}))
    return out


@pytest.mark.parametrize("bad, n, budget", [(1, 5, 2.0), (3, 5, 2.0), (1, 2, 1.0)])
def test_a_hung_set_gets_only_its_share(bad, n, budget):
    errors = []
    t0 = time.perf_counter()
    raw, timed_out, _ = L.solve(Hangs(bad), sets(n), budget, errors)
    took = time.perf_counter() - t0
    others = {f"set{s}.q{i}" for s in range(1, n + 1) if s != bad for i in range(2)}
    assert others <= set(raw) and all(raw[a] == f"v{a[3]}" for a in others), \
        f"set {bad} of {n} hangs: every other set is answered ({sorted(raw)})"
    assert raw.get(f"set{bad}.q0") == "early" and f"set{bad}.q1" not in raw, \
        f"set {bad} of {n}: its partial answer is taken, its unanswered id stays out ({raw})"
    assert timed_out and took < budget + 0.5, f"set {bad} of {n}: timed out within the {budget:g} s budget ({took:.2f} s)"
    assert any(f"set {bad}: solver stopped after its" in e for e in errors)


def test_no_set_hangs_all_answered():
    raw, timed_out, _ = L.solve(Hangs(0), sets(4), 2.0, [])
    assert len(raw) == 8 and not timed_out


def test_no_budget_runs_untimed():
    raw, timed_out, _ = L.solve(Hangs(0), sets(3), None, [])
    assert len(raw) == 6 and not timed_out
