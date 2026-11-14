"""B-137: every release-path guard has a test proving it FIRES, and no broad except swallows a guard.

The Oct 9 incident had a guard "armed twice while dead": a suppressed NameError meant it never fired
and its test could not tell. Here each guard in ctf/gate/guards.py is driven to actually refuse/raise,
the registry is checked to point at a real fires-test, and tools/guard_audit.py is run over the shipped
release path to prove no broad except can silently skip a guard. No network, no binary."""
from __future__ import annotations

import ast
import datetime
import types
from pathlib import Path

import pytest

from ctf import budget, ledger
from ctf.event import Budget
from ctf import event as E
from ctf.gate import guards
from ctf.platform import halloffame as hof
from ctf.platform.policy import AttemptRef, SubmitGate, SubmitRequest, base_checks

import guard_audit
from ctf import paths

PROFILE = E.parse({
    "slug": "guards-fire", "name": "guard fires test",
    "dates": {"start": datetime.date(2026, 1, 1), "end": datetime.date(2026, 12, 31)},
    "platform": {"kind": "ctfd", "base_url": "https://board.guards-fire.test"},
    "flag": {"prefixes": ["TESTCTF"]},
    "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
}, src="tests/test_release_guards_fire.py")


# ------------------------------------------------------------------ one fires-test per guard

def test_base_checks_fires():
    # a submission with no provenance note must be refused (base_checks returns a reason).
    good = SubmitRequest("c1", "TESTCTF{ok}", provenance="found it")
    bad = SubmitRequest("c1", "TESTCTF{ok}", provenance="   ")
    assert base_checks(PROFILE, good) is None
    reason = base_checks(PROFILE, bad)
    assert reason and "provenance" in reason


def test_submit_gate_refusal_fires():
    gate = SubmitGate(types.SimpleNamespace(kind="ctfd"), PROFILE)
    bad = SubmitRequest("c1", "TESTCTF{ok}", provenance="")
    reason = gate.refusal(bad)
    assert reason and "provenance" in reason
    assert gate.refusal(SubmitRequest("c1", "TESTCTF{ok}", provenance="ok")) is None


def test_halloffame_check_fires():
    # a teammate's (foreign) attempt is refused unless the player confirms it.
    foreign = SubmitRequest("warmups-day-08/time_trial", "TESTCTF{x}", provenance="p",
                            attempt=AttemptRef(attempt_id="a1", origin="foreign"))
    reason = hof.check(PROFILE, foreign)
    assert reason and "teammate" in reason.lower()
    confirmed = SubmitRequest("warmups-day-08/time_trial", "TESTCTF{x}", provenance="p", confirmed=True,
                              attempt=AttemptRef(attempt_id="a1", origin="foreign"))
    assert hof.check(PROFILE, confirmed) is None


def test_budget_cap_fires(tmp_path):
    # past the per-challenge cap (default floor $25), the meter's gate raises instead of allowing work.
    m = budget.LedgerMeter(Budget(), workdir=tmp_path)
    assert m.check("c1").spent_usd == 0.0        # under the cap: check allows work
    # record spend over the $25 floor cap straight to the shared ledger, so it is the gate in check()
    # (not add_spend's own gate) that we drive to fire.
    ledger.append("spend", workdir=tmp_path, challenge_id="c1", usd=30.0, tok=1000)
    with pytest.raises(budget.BudgetExceeded):
        m.check("c1")


# ------------------------------------------------------------------ the registry holds its promises

def _this_files_tests() -> set[str]:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    return {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}


def test_every_guard_names_a_fires_test_that_exists():
    here = _this_files_tests()
    repo = paths.repo_root()
    for g in guards.GUARDS:
        file_part, _, test_name = g.fires_test.partition("::")
        assert test_name, f"guard {g.id}: fires_test must be file::test"
        assert (repo / file_part).is_file(), f"guard {g.id}: {file_part} missing"
        if file_part == "tests/test_release_guards_fire.py":
            assert test_name in here, f"guard {g.id}: {test_name} not defined here"


def test_guard_call_patterns_are_each_matched_by_the_lint():
    # every declared call spelling must actually be recognized as that guard, or the lint is blind to it.
    for g in guards.GUARDS:
        for pat in g.call_patterns:
            call = ast.parse(f"{pat}(a, b)", mode="eval").body
            matched = guard_audit._guard_for_call(call)
            assert matched is not None and matched.id == g.id, f"{pat!r} did not map to {g.id}"


def test_no_guard_call_is_swallowed_in_the_release_path():
    repo = paths.repo_root()
    roots = [repo / p for p in guard_audit.DEFAULT_PATHS]
    findings, errors = guard_audit.audit(roots, display_base=repo)
    assert errors == []
    assert findings == [], "a broad except may silently skip a guard:\n" + "\n".join(x.text() for x in findings)
