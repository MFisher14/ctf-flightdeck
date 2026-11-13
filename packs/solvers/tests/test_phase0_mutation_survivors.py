"""R-07: tests that kill the four mutants the Phase 0 mutation audit left alive.

1. ctf/budget.py LedgerMeter._apply, "stop" branch: a team solve is final on the reader side too, so a
   later stop record (a concurrent writer that raced past stop()'s own check) never changes the state.
2. ctf/engines/router.py route(): hits are ordered by priority (highest first), ids only break ties.
3. ctf/event.py: a negative rules.guess_budget is refused with a named error.
4. ctf/event.py: rules.wrong_answer_stop below 1 is refused with a named error.
"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from ctf import budget, event, ledger
from ctf.engines import manifest as M
from ctf.engines import router
from ctf.event import Budget


# ------------------------------------------------------------------ 1. team solve is final (reader side)

def _raw_stop(wd: Path, cid: str, reason: str, by: str) -> None:
    """Append a stop record directly, as a second writer that did not see the team solve would."""
    ledger.append("stop", workdir=wd, challenge_id=cid, reason=reason, by=by)


@pytest.mark.parametrize("later", ["manual", "no_progress"])
def test_a_later_stop_record_never_replaces_a_team_solve(tmp_path, later):
    assert budget.on_team_solve("7", solver="teammate", workdir=tmp_path) is True
    _raw_stop(tmp_path, "7", later, "racer")
    assert [r["reason"] for r in ledger.read(tmp_path) if r["event"] == "stop"] == ["team_solve", later]

    m = budget.LedgerMeter(Budget(), workdir=tmp_path, on_cap=lambda st, p: None)
    st = m.status("7")
    assert (st.state, st.stop_reason, st.stop_by) == ("stopped", "team_solve", "teammate")
    with pytest.raises(budget.ChallengeStopped) as ei:
        m.check("7")
    assert ei.value.reason == "team_solve"
    with pytest.raises(ValueError, match="team_solve; that stop is final"):
        m.resume("7", by="max")
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"


def test_team_solve_stays_final_when_the_later_stop_arrives_after_the_meter_has_read(tmp_path):
    """The incremental reader path: the meter already holds the team solve, then the stray stop and a
    stray resume land in the ledger. Neither may reopen the challenge."""
    m = budget.LedgerMeter(Budget(), workdir=tmp_path, on_cap=lambda st, p: None)
    budget.on_team_solve("7", solver="teammate", workdir=tmp_path)
    assert m.status("7").stop_reason == "team_solve"
    _raw_stop(tmp_path, "7", "manual", "racer")
    ledger.append("budget_resume", workdir=tmp_path, challenge_id="7", by="racer")
    st = m.status("7")
    assert (st.state, st.stop_reason, st.stop_by) == ("stopped", "team_solve", "teammate")
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"


def test_a_stop_before_the_team_solve_is_still_replaced(tmp_path):
    """The guard only protects a team solve; ordinary stops still take the latest record."""
    _raw_stop(tmp_path, "7", "no_progress", "timer")
    _raw_stop(tmp_path, "7", "manual", "max")
    m = budget.LedgerMeter(Budget(), workdir=tmp_path, on_cap=lambda st, p: None)
    assert (m.status("7").stop_reason, m.status("7").stop_by) == ("manual", "max")
    budget.on_team_solve("7", solver="teammate", workdir=tmp_path)
    assert (m.status("7").stop_reason, m.status("7").stop_by) == ("team_solve", "teammate")


# ------------------------------------------------------------------ 2. router orders by priority, not id

def _eng(root: Path, lane: str, name: str, priority: int) -> None:
    d = root / "solvers" / lane
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.py").write_text("def solve(d, p): pass\n", encoding="utf-8")
    (d / f"{name}.manifest.toml").write_text(
        f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n'
        f'[[routes]]\ncategory = ["crypto"]\npriority = {priority}\n', encoding="utf-8")


def _ids(hits):
    return [h.manifest.id for h in hits]


def test_route_orders_by_priority_even_when_the_higher_ids_sort_later(tmp_path):
    _eng(tmp_path, "aaa", "low", 20)          # sorts first by id, lowest priority
    _eng(tmp_path, "mmm", "mid", 50)
    _eng(tmp_path, "zzz", "high", 90)         # sorts last by id, highest priority
    hits = router.route("crypto", "", root=tmp_path)
    assert _ids(hits) == ["zzz.high", "mmm.mid", "aaa.low"]
    assert [h.priority for h in hits] == [90, 50, 20]


def test_route_breaks_priority_ties_by_id_whatever_the_input_order(tmp_path):
    _eng(tmp_path, "bbb", "tie", 50)
    _eng(tmp_path, "aaa", "tie", 50)
    _eng(tmp_path, "zzz", "top", 90)
    ms = M.discover(tmp_path)
    for order in (ms, list(reversed(ms))):
        assert _ids(router.route("crypto", "", manifests=order)) == ["zzz.top", "aaa.tie", "bbb.tie"]


def test_route_takes_the_highest_priority_matching_route_within_one_manifest(tmp_path):
    """A manifest with several matching routes is ranked by its best one, not its first or last one.
    The routes are listed low, high, mid, so first-wins, last-wins and lowest-wins all give a different
    priority, and the reason must be the high route's (the only one with a keyword)."""
    d = tmp_path / "solvers" / "crypto"
    d.mkdir(parents=True)
    (d / "multi.py").write_text("def solve(d, p): pass\n", encoding="utf-8")
    (d / "multi.manifest.toml").write_text(
        'id = "crypto.multi"\nlane = "crypto"\nentry = "solvers.crypto.multi:solve"\n'
        '[[routes]]\ncategory = ["crypto"]\npriority = 20\n'
        '[[routes]]\ncategory = ["crypto"]\nkeywords = ["rsa"]\npriority = 80\n'
        '[[routes]]\ncategory = ["crypto"]\npriority = 40\n', encoding="utf-8")
    [hit] = router.route("crypto", "small RSA modulus", root=tmp_path)
    assert hit.manifest.id == "crypto.multi"
    assert hit.priority == 80
    assert "keyword 'rsa'" in hit.reason
    # Without the keyword only the two plain routes match; the better of them (40) wins, not the first (20).
    [hit] = router.route("crypto", "nothing here", root=tmp_path)
    assert hit.priority == 40
    assert "keyword" not in hit.reason


def test_route_reports_the_first_listed_route_when_matching_routes_tie_on_priority(tmp_path):
    """Two matching routes of equal priority: the first one listed gives the hit's reason (docs/CONTRACTS.md
    section 6). Both keywords are in the description, so only the tie rule decides which reason is shown."""
    d = tmp_path / "solvers" / "crypto"
    d.mkdir(parents=True)
    (d / "tie.py").write_text("def solve(d, p): pass\n", encoding="utf-8")
    (d / "tie.manifest.toml").write_text(
        'id = "crypto.tie"\nlane = "crypto"\nentry = "solvers.crypto.tie:solve"\n'
        '[[routes]]\ncategory = ["crypto"]\nkeywords = ["lattice"]\npriority = 60\n'
        '[[routes]]\ncategory = ["crypto"]\nkeywords = ["modulus"]\npriority = 60\n', encoding="utf-8")
    [hit] = router.route("crypto", "a lattice attack on the modulus", root=tmp_path)
    assert hit.priority == 60
    assert "keyword 'lattice'" in hit.reason
    assert "modulus" not in hit.reason


# ------------------------------------------------------------------ 3 and 4. rules bounds in event profiles

BASE = textwrap.dedent("""\
    slug = "demo"
    name = "Demo CTF"
    categories = ["Web"]
    dates = { start = 2027-01-01, end = 2027-01-02 }

    [platform]
    kind = "ctfd"
    base_url = "https://demo.example/"

    [flag]
    prefixes = ["DEMO"]

    [rules]
    submit_mode = "auto"
    flag_sharing = "allowed"
    ai_on_platform = "allowed"
    """)


def _load(tmp_path: Path, extra_rules: str):
    d = tmp_path / "demo"
    d.mkdir(parents=True, exist_ok=True)
    (d / "event.toml").write_text(BASE + extra_rules, encoding="utf-8")
    return event.load("demo", root=tmp_path)


@pytest.mark.parametrize("value", [-1, -50])
def test_negative_guess_budget_is_refused_with_a_named_error(tmp_path, value):
    with pytest.raises(event.EventError, match=re.escape("rules.guess_budget must be >= 0")) as ei:
        _load(tmp_path, f"guess_budget = {value}\n")
    assert "event.toml" in str(ei.value)                 # names the file it came from


def test_guess_budget_zero_and_positive_are_accepted(tmp_path):
    assert _load(tmp_path, "guess_budget = 0\n").rules.guess_budget == 0
    assert _load(tmp_path, "guess_budget = 4\n").rules.guess_budget == 4


@pytest.mark.parametrize("value", [0, -1])
def test_wrong_answer_stop_below_one_is_refused_with_a_named_error(tmp_path, value):
    with pytest.raises(event.EventError, match=re.escape("rules.wrong_answer_stop must be >= 1")) as ei:
        _load(tmp_path, f"wrong_answer_stop = {value}\n")
    assert "event.toml" in str(ei.value)


def test_wrong_answer_stop_one_is_accepted(tmp_path):
    assert _load(tmp_path, "wrong_answer_stop = 1\n").rules.wrong_answer_stop == 1
