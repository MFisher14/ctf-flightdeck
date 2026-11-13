"""B-137: tools/guard_audit.py flags a broad `except` that could silently kill a release-path guard --
the Oct 9 shape where a suppressed NameError left a guard "armed twice while dead" -- and does not flag
a handler that re-raises, a narrow handler, or a broad handler around a non-guard call."""
from __future__ import annotations

import textwrap

from ctf import paths

import guard_audit
from guard_audit import audit, audit_tree
import ast


def _findings(src: str):
    tree = ast.parse(textwrap.dedent(src))
    return audit_tree(tree, "x.py")


def test_broad_except_swallowing_a_guard_is_flagged():
    f = _findings("""
        def send(gate, req):
            try:
                reason = gate.refusal(req)
                if reason:
                    return refuse(reason)
            except Exception:
                pass          # a NameError here would skip the guard, exactly the Oct 9 bug
            return raw_send(req)
    """)
    assert len(f) == 1 and f[0].guard == "submit-gate-refusal"


def test_a_bare_except_is_flagged():
    f = _findings("""
        def go(profile, req):
            try:
                r = base_checks(profile, req)
            except:
                r = None
            return r
    """)
    assert len(f) == 1 and f[0].guard == "submit-base-checks"


def test_a_handler_that_reraises_is_not_flagged():
    f = _findings("""
        def go(profile, req):
            try:
                r = base_checks(profile, req)
            except Exception:
                raise
            return r
    """)
    assert f == []


def test_a_handler_that_exits_is_not_flagged():
    f = _findings("""
        import sys
        def go(profile, req):
            try:
                r = base_checks(profile, req)
            except Exception:
                sys.exit(2)
            return r
    """)
    assert f == []


def test_a_narrow_except_is_a_contract_not_a_swallow():
    f = _findings("""
        def go(profile, req):
            try:
                r = base_checks(profile, req)
            except KeyError:
                r = None
            return r
    """)
    assert f == []


def test_a_broad_except_around_a_non_guard_call_is_not_flagged():
    f = _findings("""
        def go():
            try:
                x = helper.compute(1)
            except Exception:
                x = 0
            return x
    """)
    assert f == []


def test_a_stray_dot_check_is_not_mistaken_for_the_budget_guard():
    # `.check` is only a guard when spelled meter.check / budget.check; an unrelated obj.check() is not.
    f = _findings("""
        def go(validator):
            try:
                validator.check(thing)
            except Exception:
                pass
            return 1
    """)
    assert f == []


def test_halloffame_check_is_matched_by_its_dotted_pattern():
    f = _findings("""
        def go(profile, req):
            try:
                reason = halloffame.check(profile, req)
            except Exception:
                reason = None
            return reason
    """)
    assert len(f) == 1 and f[0].guard == "halloffame-check"


def test_the_real_release_path_has_no_swallowed_guard():
    # The guard against regressions in the shipped code: ctf/platform, ctf/budget.py, ctf/arm.py.
    repo = paths.repo_root()
    roots = [repo / p for p in guard_audit.DEFAULT_PATHS]
    findings, errors = audit(roots, display_base=repo)
    assert errors == []
    assert findings == [], "swallowed guard(s): " + "; ".join(x.text() for x in findings)
