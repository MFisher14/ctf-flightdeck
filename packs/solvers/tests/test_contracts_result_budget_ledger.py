"""B-001 contracts: ctf.result (SolverResult), ctf.budget (cap rule, Meter protocol), ctf.ledger."""
from __future__ import annotations

import json
import multiprocessing as mp

import pytest

from ctf import budget, ledger
from ctf.event import Budget
from ctf.result import Cost, Evidence, ResultError, SolverResult


def solved():
    return SolverResult(status="solved", flags=["PINK{x}"],
                        evidence=[Evidence("decode", "base64 of line 3", path="files/a.txt", offset=12)],
                        cost=Cost(seconds=1.5, usd=0.02, tokens=900), engine="warmups.crib_decode",
                        challenge_id="12", notes="n")


def test_round_trip_is_exact():
    r = solved()
    s = r.to_json()
    assert json.loads(s)["schema"] == 1
    back = SolverResult.from_json(s)
    assert back == r
    assert back.evidence[0].offset == 12 and back.cost.tokens == 900


@pytest.mark.parametrize("kw, msg", [
    (dict(status="won"), "status must be one of"),
    (dict(status="solved", flags=["F{x}"]), "needs at least one flag and one evidence"),
    (dict(status="solved", evidence=[Evidence("x", "y")]), "needs at least one flag and one evidence"),
    (dict(status="candidate"), "'candidate' needs at least one flag"),
    (dict(status="none", flags=["F{x}"]), "carries no flags"),
    (dict(status="blocked"), "needs notes naming what is missing"),
    (dict(status="unsure", flags=[""]), "non-empty strings"),
])
def test_status_invariants(kw, msg):
    with pytest.raises(ResultError, match=msg):
        SolverResult(**kw)


def test_valid_non_solved_statuses():
    assert SolverResult(status="none").flags == ()
    assert SolverResult(status="blocked", notes="radare2 missing").status == "blocked"
    assert SolverResult(status="unsure").evidence == ()
    assert SolverResult(status="candidate", flags=("F{x}",)).flags == ("F{x}",)


@pytest.mark.parametrize("payload, msg", [
    ('{"status": "none"}', "unsupported result schema"),
    ('{"schema": 1, "status": "none", "extra": 1}', "unknown result field"),
    ('{"schema": 1, "status": "none", "cost": {"usd": 1, "euros": 2}}', "bad evidence/cost"),
    ('[1]', "must be a JSON object"),
    ('{nope', "not JSON"),
])
def test_from_json_rejects_bad_input(payload, msg):
    with pytest.raises(ResultError, match=msg):
        SolverResult.from_json(payload)


# ------------------------------------------------------------------ budget

def test_cap_rule_per_point_with_floor_and_ceiling():
    b = Budget()
    assert budget.cap_usd(b, 10) == 25.0          # 5.0 -> floor
    assert budget.cap_usd(b, 200) == 100.0
    assert budget.cap_usd(b, 1000) == 250.0       # 500 -> ceiling
    assert budget.cap_usd(b, None) == 25.0
    with pytest.raises(ValueError):
        budget.cap_usd(b, -1)


def test_cap_rule_per_challenge_day():
    b = Budget(per_challenge_day=50.0)
    assert budget.cap_usd(b, 999, days_open=2) == 100.0
    assert budget.cap_usd(b, None, days_open=9) == 250.0
    with pytest.raises(ValueError, match="days_open"):
        budget.cap_usd(b, 100)


def test_meter_protocol_is_structural():
    class M:
        def add_spend(self, challenge_id, usd, tokens): ...
        def spent(self, challenge_id): return budget.Spend()
        def cap(self, challenge_id): return 1.0

    class NotM:
        def spent(self, challenge_id): ...

    assert isinstance(M(), budget.Meter)
    assert not isinstance(NotM(), budget.Meter)
    e = budget.BudgetExceeded("7", 26.0, 25.0)
    assert "ask the player to extend" in str(e)


# ------------------------------------------------------------------ ledger

def test_append_and_read(tmp_path):
    rec = ledger.append("candidate", workdir=tmp_path, challenge_id="12", engine="x")
    assert rec["event"] == "candidate" and isinstance(rec["ts"], float)
    ledger.append("web.request", workdir=tmp_path, path="/a")
    got = list(ledger.read(tmp_path))
    assert [r["event"] for r in got] == ["candidate", "web.request"]
    assert got[0]["challenge_id"] == "12"
    assert (tmp_path / "ledger.jsonl").stat().st_mode & 0o077 == 0


def test_append_defaults_to_the_workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    ledger.append("detect", challenge_id="1")
    assert json.loads((tmp_path / "ledger.jsonl").read_text())["event"] == "detect"


@pytest.mark.parametrize("etype, fields, msg", [
    ("Bad Type", {}, "bad ledger event type"),
    ("submit", {"api_key": "x"}, "may not carry secrets"),
    ("submit", {"auth_token": "x"}, "may not carry secrets"),
    ("submit", {"Cookie": "x"}, "may not carry secrets"),
    ("submit", {"ts": 1}, "reserved key"),
])
def test_append_refuses(tmp_path, etype, fields, msg):
    with pytest.raises(ValueError, match=msg):
        ledger.append(etype, workdir=tmp_path, **fields)
    assert not (tmp_path / "ledger.jsonl").exists()


def test_read_reports_corrupt_line(tmp_path):
    (tmp_path / "ledger.jsonl").write_text('{"event":"a","ts":1}\n{oops\n')
    with pytest.raises(ValueError, match="ledger.jsonl:2: corrupt"):
        list(ledger.read(tmp_path))


def _writer(wd, n):
    for i in range(n):
        ledger.append("spend", workdir=wd, i=i, pad="x" * 3000)


def test_concurrent_appends_do_not_interleave(tmp_path):
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(tmp_path, 40)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    recs = list(ledger.read(tmp_path))      # raises on any torn line
    assert len(recs) == 160
