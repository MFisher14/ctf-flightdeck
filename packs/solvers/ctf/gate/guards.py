"""The release-path guards, named once so the gate can hold them to two rules (B-137).

On Oct 9 a safety guard in the release path "was armed twice while dead: a suppressed NameError meant
it never fired and its test could not tell." A guard is any check that stands between the solver and an
irreversible act -- posting a flag, posting at a teammate's time, spending past a cap. If a refactor
makes the guard call raise and a broad ``except`` swallows it, the guard silently stops guarding, and a
test that only checks the happy path never notices.

So every guard here gets both:

  * **no broad except may swallow its call.** ``tools/guard_audit.py`` reads this registry and flags a
    bare/broad ``except`` that wraps a guard call and neither re-raises nor exits -- the exact shape
    that let the NameError pass. ``call_patterns`` is how the lint spots a call to the guard.
  * **a fires-test.** ``fires_test`` names a test that drives the guard to actually fire (return its
    refusal, or raise its stop). ``tests/test_release_guards_fire.py`` asserts each guard fires and that
    the lint finds no swallow over the release-path sources.

``module``/``attr`` locate the guard in code (for humans and for the fires-test to import). Add a guard
here when you add a check to the release path; the fires-test enforces that it is more than a label.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Guard:
    id: str
    summary: str
    module: str                       # where the guard lives
    attr: str                         # the function/method name (dotted for a method)
    call_patterns: tuple[str, ...]    # dotted call spellings the lint treats as invoking this guard
    fires_test: str                   # "tests/<file>.py::<test>" that drives the guard to fire


GUARDS: tuple[Guard, ...] = (
    Guard(
        id="submit-base-checks",
        summary="the submit gate's base checks: manual event, provenance, flag format, confirm",
        module="ctf.platform.policy",
        attr="base_checks",
        call_patterns=("base_checks",),
        fires_test="tests/test_release_guards_fire.py::test_base_checks_fires",
    ),
    Guard(
        id="submit-gate-refusal",
        summary="SubmitGate.refusal: runs every registered check before a raw send",
        module="ctf.platform.policy",
        attr="SubmitGate.refusal",
        call_patterns=("refusal", "gate.refusal"),
        fires_test="tests/test_release_guards_fire.py::test_submit_gate_refusal_fires",
    ),
    Guard(
        id="halloffame-check",
        summary="the Hall of Fame check: a teammate's attempt, or an ineligible/exhausted ranked retry",
        module="ctf.platform.halloffame",
        attr="check",
        call_patterns=("halloffame.check", "hof.check"),
        fires_test="tests/test_release_guards_fire.py::test_halloffame_check_fires",
    ),
    Guard(
        id="budget-cap",
        summary="the budget meter's cap/stop gate: LedgerMeter.check raises past the cap or a stop",
        module="ctf.budget",
        attr="LedgerMeter.check",
        call_patterns=("meter.check", "budget.check"),
        fires_test="tests/test_release_guards_fire.py::test_budget_cap_fires",
    ),
)


def by_id(guard_id: str) -> Guard:
    for g in GUARDS:
        if g.id == guard_id:
            return g
    raise KeyError(guard_id)
