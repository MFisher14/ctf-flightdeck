"""B-096: per-role, per-model cost in tools/ledger/usage.py summarize, and the usage.role ledger
event (assign_role / roles_from_ledger). Rows are built in-memory; no session log is read.
"""
from __future__ import annotations

import pytest

from ctf import ledger
from tools.ledger import pricing, usage

PRICES = pricing.load_prices()
OPUS = "claude-opus-5-5"
SONNET = "claude-sonnet-5-5"


def row(key, agent, model, *, inp=1000, out=1000, ts="2026-11-06T14:00:00Z"):
    return {"key": key, "harness": "claude", "agent": agent, "model": model, "speed": "standard",
            "input": inp, "cache_read": 0, "cache_5m": 0, "cache_1h": 0, "output": out,
            "cwd": "/nope", "ts": ts}


def att(wd):
    # no challenge folders: attribution is irrelevant to the role split under test.
    return usage.Attributor(wd, records=[])


def test_no_roles_map_leaves_the_role_breakdown_empty(tmp_path):
    rows = [row("claude:a", "ag1", OPUS)]
    rep = usage.summarize(rows, PRICES, att(tmp_path))
    assert rep.by_role == [] and rep.by_role_model == []
    assert rep.responses == 1 and rep.usd > 0


def test_cost_split_per_role_and_per_role_model(tmp_path):
    rows = [
        row("claude:1", "verifier", OPUS),
        row("claude:2", "verifier", SONNET),
        row("claude:3", "solver", OPUS),
        row("claude:4", "stranger", OPUS),      # no role recorded -> DEFAULT_ROLE
    ]
    roles = {"verifier": "verify", "solver": "solve"}
    rep = usage.summarize(rows, PRICES, att(tmp_path), roles=roles)

    by_role = {r["role"]: r for r in rep.by_role}
    assert set(by_role) == {"verify", "solve", usage.DEFAULT_ROLE}
    assert by_role["verify"]["responses"] == 2
    assert by_role["solve"]["responses"] == 1
    assert by_role[usage.DEFAULT_ROLE]["responses"] == 1

    # verify-role dollars are split across the two models (the whole point of 3.8).
    verify_models = {(m["model"]): m for m in rep.by_role_model if m["role"] == "verify"}
    assert set(verify_models) == {OPUS, SONNET}
    # the per-role-model dollars sum back to the per-role total.
    assert sum(m["usd"] for m in verify_models.values()) == pytest.approx(by_role["verify"]["usd"])
    # and Opus verify costs more than the same tokens on Sonnet.
    assert verify_models[OPUS]["usd"] > verify_models[SONNET]["usd"]

    # the role split never changes the grand total.
    assert sum(r["usd"] for r in rep.by_role) == pytest.approx(rep.usd)


def test_assign_role_and_roles_from_ledger_roundtrip(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    usage.assign_role(wd, "verifier", "verify", by="max")
    usage.assign_role(wd, "solver", "solve", by="max", note="block B")
    roles = usage.roles_from_ledger(ledger.read(wd))
    assert roles == {"verifier": "verify", "solver": "solve"}
    # the event is on the ledger with its fields.
    recs = [r for r in ledger.read(wd) if r["event"] == usage.ROLE_EVENT]
    assert len(recs) == 2 and recs[1]["note"] == "block B"


def test_roles_from_ledger_latest_assignment_wins(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    usage.assign_role(wd, "ag", "solve", by="max")
    usage.assign_role(wd, "ag", "verify", by="max")      # re-labelled
    assert usage.roles_from_ledger(ledger.read(wd)) == {"ag": "verify"}


def test_assign_role_rejects_an_unknown_role(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    with pytest.raises(usage.UsageError):
        usage.assign_role(wd, "ag", "not-a-category", by="max")
    with pytest.raises(usage.UsageError):
        usage.assign_role(wd, "ag", "verify", by="")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
