"""B-115: the threat-intel lookup kit's guess-budget guardrail -- the pure helper and the --online
gate on both kit entrypoints (osint_pivot, osint_online). No network: the online path is never reached
because the guard refuses before any client is built.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_online as OO  # noqa: E402
import osint_pivot as OP  # noqa: E402


def test_guess_budget_block_allows_then_blocks():
    assert OO.guess_budget_block(0, 3) is None
    assert OO.guess_budget_block(2, 3) is None
    msg = OO.guess_budget_block(3, 3)
    assert msg is not None and "stop and ask the player" in msg
    # a player approval reopens exactly one lookup past the budget
    assert OO.guess_budget_block(3, 3, approvals_left=1) is None


def test_guess_budget_block_rejects_bad_counts():
    with pytest.raises(OO.OSINTGuardError):
        OO.guess_budget_block(-1, 3)
    with pytest.raises(OO.OSINTGuardError):
        OO.guess_budget_block(0, -3)
    with pytest.raises(OO.OSINTGuardError):
        OO.guess_budget_block(True, 3)   # a bool is not a wrong-answer count


def test_pivot_guess_budget_default_tracks_osint_online_constant(monkeypatch, capsys):
    # The two kit entrypoints must share one guess-budget default so they cannot drift: osint_pivot's
    # --guess-budget default is osint_online.DEFAULT_GUESS_BUDGET, not a hardcoded literal. Move the
    # constant and confirm the --online path passes the moved value, not 3, to the guard. The guard is
    # stubbed to block, so main returns 3 and never builds a client or touches the network.
    seen = {}

    def spy(wrong_count, guess_budget, approvals_left=0):
        seen["guess_budget"] = guess_budget
        return "blocked (test stub)"       # non-None: refused before any client is built

    monkeypatch.setattr(OO, "DEFAULT_GUESS_BUDGET", 11)
    monkeypatch.setattr(OO, "guess_budget_block", spy)
    rc = OP.main(["--lead", "username=alice", "--online", "--wrong-count", "0"])
    assert rc == 3
    assert seen["guess_budget"] == 11      # the moved shared constant, not a hardcoded 3


@pytest.mark.parametrize("given", [0, 7])
def test_pivot_passes_an_explicit_guess_budget_through_unchanged(monkeypatch, given):
    # The default is resolved on the --online path (so the offline path never imports the online
    # adapter); that resolution must not replace a value the caller gave. 0 is the case a truthiness
    # test would lose: "no candidate lookups at all" must not become the default of 3.
    seen = {}

    def spy(wrong_count, guess_budget, approvals_left=0):
        seen["guess_budget"] = guess_budget
        return "blocked (test stub)"       # refused before any client is built

    monkeypatch.setattr(OO, "DEFAULT_GUESS_BUDGET", 11)
    monkeypatch.setattr(OO, "guess_budget_block", spy)
    rc = OP.main(["--lead", "username=alice", "--online", "--guess-budget", str(given)])
    assert rc == 3
    assert seen["guess_budget"] == given


def test_pivot_offline_path_with_budget_flags_never_imports_the_online_adapter(monkeypatch, capsys):
    # sys.modules[name] = None makes any `import osint_online` raise: the offline plan must still
    # build, with the guess-budget flags given, because the guard only belongs to the --online path.
    monkeypatch.setitem(sys.modules, "osint_online", None)
    rc = OP.main(["--lead", "username=alice", "--json", "--wrong-count", "9", "--guess-budget", "3"])
    assert rc == 0
    assert "GitHub" in capsys.readouterr().out


def test_osint_online_cli_refuses_a_lookup_once_the_budget_is_spent(capsys):
    # Over the guess budget: must exit 3 and never build a client / touch the network.
    rc = OO.main(["search", "chronos widget", "--online", "--wrong-count", "3", "--guess-budget", "3"])
    assert rc == 3
    assert "guess budget" in capsys.readouterr().err


def test_osint_pivot_cli_refuses_online_once_the_budget_is_spent(capsys):
    rc = OP.main(["--lead", "username=alice", "--online", "--wrong-count", "5", "--guess-budget", "3"])
    assert rc == 3
    err = capsys.readouterr().err
    assert "osint_pivot:" in err and "guess budget" in err


def test_osint_pivot_offline_plan_is_unaffected_by_the_guess_budget(capsys):
    # The guard only gates the --online path; the offline plan still builds.
    rc = OP.main(["--lead", "username=alice", "--json", "--wrong-count", "9", "--guess-budget", "3"])
    assert rc == 0
    assert "GitHub" in capsys.readouterr().out
