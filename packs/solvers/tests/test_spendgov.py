"""B-202: build and review spend governors (ctf/spendgov.py, python -m ctf spend)."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import time

import pytest

from ctf import ledger, spendgov as sg
from ctf.cli import spend as scli

UTC = dt.timezone.utc
NOON = dt.datetime(2026, 11, 6, 12, 0, tzinfo=UTC).timestamp()
DAY = 86400.0


def spend(usd, ts, *, category=None, challenge_id=None, source=None):
    r = {"event": "spend", "ts": ts, "usd": usd, "tok": 1}
    if category:
        r["category"] = category
    if challenge_id:
        r["challenge_id"] = challenge_id
    if source:
        r["source"] = source
    return r


def cap(phase, usd, ts, period="day"):
    return {"event": "spend.cap", "ts": ts, "phase": phase, "usd": usd, "period": period, "by": "max", "reason": "r"}


def mode(name, usd, ts, challenges=None):
    r = {"event": "spend.mode", "ts": ts, "mode": name, "usd": usd, "by": "max", "reason": "r"}
    if challenges:
        r["challenges"] = challenges
    return r


# ------------------------------------------------------------------------------------- phase caps

def test_uncapped_phase_is_held_with_the_command_that_decides_it():
    v = sg.gate(phase="build", records=[], now=NOON)
    assert not v.allowed and v.checked == ("phase build",)
    assert "no build cap is decided" in v.reasons[0] and "ctf spend cap build" in v.reasons[0]


def test_phase_cap_allows_under_and_holds_at_the_cap():
    recs = [cap("build", 10.0, NOON - 3600), spend(9.99, NOON - 60, category="build")]
    assert sg.gate(phase="build", records=recs, now=NOON).allowed
    recs.append(spend(0.01, NOON - 30, category="build"))
    v = sg.gate(phase="build", records=recs, now=NOON)
    assert not v.allowed and "spent $10.00 of its $10.00 day cap" in v.reasons[0]


def test_only_the_phases_own_spend_counts():
    recs = [cap("verify", 5.0, NOON - 3600), spend(50.0, NOON - 60, category="build"),
            spend(50.0, NOON - 60, challenge_id="7"), spend(4.0, NOON - 60, category="verify")]
    st = sg.phase_status("verify", recs, now=NOON)
    assert st.spent == 4.0 and st.state == "ok" and st.left == 1.0
    # challenge spend with no category is solve; other spend with no category is no phase's
    assert sg.spend_phase(spend(1, 0, challenge_id="7")) == "solve"
    assert sg.spend_phase(spend(1, 0)) == "uncategorized"
    assert sg.status(records=recs + [spend(2.5, NOON)], now=NOON).uncategorized_usd == 2.5


def test_day_cap_resets_at_midnight_in_the_zone_and_event_cap_does_not():
    recs = [cap("build", 10.0, NOON - 2 * DAY), spend(9.0, NOON - DAY, category="build"),
            spend(2.0, NOON - 60, category="build")]
    assert sg.phase_status("build", recs, now=NOON).spent == 2.0
    # now is 07:00 in New York (EST): a spend at 03:00 UTC today is 22:00 yesterday there, so it
    # counts toward today's UTC day but not toward today's New York day
    late = recs + [spend(3.0, NOON - 9 * 3600, category="build")]
    assert sg.phase_status("build", late, now=NOON, tz="UTC").spent == 5.0
    assert sg.phase_status("build", late, now=NOON, tz="America/New_York").spent == 2.0
    ev = [cap("build", 10.0, NOON - 2 * DAY, period="event")] + recs[1:]
    st = sg.phase_status("build", ev, now=NOON)
    assert st.spent == 11.0 and st.state == "over" and st.since is None
    with pytest.raises(sg.SpendGovError, match="IANA"):
        sg.day_start(NOON, "Mars/Olympus")


def test_latest_cap_wins_and_cap_inputs_are_checked(tmp_path):
    recs = [cap("build", 1.0, NOON - 100), cap("build", 20.0, NOON - 50), spend(5.0, NOON - 10, category="build")]
    assert sg.gate(phase="build", records=recs, now=NOON).allowed
    with pytest.raises(sg.SpendGovError, match="phase"):
        sg.set_cap("buidl", 5, by="max", reason="r", workdir=tmp_path)
    with pytest.raises(sg.SpendGovError, match="period"):
        sg.set_cap("build", 5, period="week", by="max", reason="r", workdir=tmp_path)
    for bad in (0, -1, float("nan"), True, "5"):
        with pytest.raises(sg.SpendGovError, match="usd"):
            sg.set_cap("build", bad, by="max", reason="r", workdir=tmp_path)
    with pytest.raises(sg.SpendGovError, match="by"):
        sg.set_cap("build", 5, by=" ", reason="r", workdir=tmp_path)
    assert not ledger.path(tmp_path).exists()
    rec = sg.set_cap("verify", 7, period="event", by="max", reason="quarter of spend", workdir=tmp_path)
    assert (rec["phase"], rec["usd"], rec["period"]) == ("verify", 7.0, "event")
    assert sg.caps(ledger.read(tmp_path))["verify"].usd == 7.0


# ------------------------------------------------------------------------------------- mode budgets

TT = "w-day-01/time_trial"


def test_speedrun_work_on_a_solved_timed_id_is_held_until_its_budget_is_decided(tmp_path):
    solved = {"event": "stop", "ts": NOON - 3600, "challenge_id": TT, "reason": "team_solve"}
    # before the solve: ordinary solve work, no mode
    assert sg.gate(challenge_id=TT, records=[], now=NOON).allowed
    v = sg.gate(challenge_id=TT, records=[solved], now=NOON)
    assert not v.allowed and "mode speedrun" in v.checked and "no speedrun budget is decided" in v.reasons[0]
    # an untimed solved id is not speed-run work
    plain = {**solved, "challenge_id": "w-day-01/q1"}
    assert sg.gate(challenge_id="w-day-01/q1", records=[plain], now=NOON).allowed
    recs = [solved, mode("speedrun", 20.0, NOON - 1800)]
    assert sg.gate(challenge_id=TT, records=recs, now=NOON).allowed
    # spend before the solve was the solve itself; after it, speed-run spend
    recs += [spend(100.0, NOON - 7200, challenge_id=TT), spend(19.0, NOON - 600, challenge_id=TT)]
    assert sg.mode_status("speedrun", recs).spent == 19.0
    recs.append(spend(1.0, NOON - 60, challenge_id=TT))
    v = sg.gate(challenge_id=TT, records=recs, now=NOON)
    assert not v.allowed and "speedrun spent $20.00 of its $20.00 budget" in v.reasons[0]


@pytest.mark.parametrize("rec", [
    {"event": "accepted", "challenge_id": TT},
    {"event": "platform.submit", "challenge_id": TT, "status": "correct"},
    {"event": "platform.submit", "challenge_id": TT, "status": "already_solved"},
])
def test_solved_at_reads_every_solve_signal(rec):
    assert sg.solved_at([{**rec, "ts": 5.0}, {**rec, "ts": 3.0}]) == {TT: 3.0}


def test_rejected_submit_and_manual_stop_are_not_solves():
    assert sg.solved_at([{"event": "platform.submit", "challenge_id": TT, "status": "incorrect", "ts": 1.0},
                         {"event": "stop", "challenge_id": TT, "reason": "manual", "ts": 1.0},
                         {"event": "stop", "challenge_id": TT, "reason": "no_progress", "ts": 1.0}]) == {}


def test_custom_mode_counts_matching_spend_from_its_first_decision(tmp_path):
    recs = [spend(9.0, NOON - 7200, challenge_id="hof/a"), mode("polish", 5.0, NOON - 3600, ["hof/*"]),
            spend(3.0, NOON - 60, challenge_id="hof/b"), spend(9.0, NOON - 60, challenge_id="other"),
            mode("polish", 4.0, NOON - 30, ["hof/*"])]
    st = sg.mode_status("polish", recs)
    assert st.spent == 3.0 and st.budget.usd == 4.0 and st.state == "ok"
    assert sg.gate(challenge_id="hof/c", records=recs, now=NOON).allowed
    assert not sg.gate(mode="never", records=recs, now=NOON).allowed
    with pytest.raises(sg.SpendGovError, match="built in"):
        sg.decide_mode("speedrun", 5, by="max", reason="r", challenges=["x"], workdir=tmp_path)
    with pytest.raises(sg.SpendGovError, match="glob"):
        sg.decide_mode("polish", 5, by="max", reason="r", workdir=tmp_path)
    assert not ledger.path(tmp_path).exists()
    rec = sg.decide_mode("speedrun", 150, by="max", reason="r", value="$12 per first place", workdir=tmp_path)
    assert rec["value"] == "$12 per first place" and "challenges" not in rec


def test_gate_needs_something_to_check():
    with pytest.raises(sg.SpendGovError):
        sg.gate(records=[], now=NOON)


# ------------------------------------------------------------------------------------ review tiers

@pytest.mark.parametrize("path,tier", [
    ("docs/x.md", "none"), ("README.md", "none"), ("tests/test_a.py", "light"),
    ("solvers/crypto/rsa.py", "full"), ("ctf/platform/ctfd.py", "full"), ("ctf/submit.py", "full"),
    ("./.githooks/pre-commit", "full"), ("ctf/fence_launch.py", "full"), ("tools/codex_launch", "full"),
    ("ctf/spendgov.py", "standard"), ("weird/thing.bin", "standard"),
])
def test_tier_of(path, tier):
    assert sg.tier_of(path) == tier


def test_scope_tier_is_the_riskiest_file_and_an_unknown_file_is_reviewed():
    assert sg.scope_tier(["docs/a.md", "tests/t.py"]) == "light"
    assert sg.scope_tier(["docs/a.md", "ctf/platform/x.py", "tests/t.py"]) == "full"
    assert sg.tier_of("x.py", rules=(("docs/*", "none"),)) == "standard"
    with pytest.raises(sg.SpendGovError):
        sg.scope_tier([])


def R(n, tree, **findings):
    return sg.Round("s", tree, "standard", findings, float(n))


def test_stopping_rule():
    ns = sg.next_step
    assert ns([], "none", "t").action == "stop"
    assert ns([], "standard", "t").action == "review"
    # standard: continue at high, 2 rounds
    assert ns([R(1, "a", medium=3)], "standard", "b").action == "stop"            # last round mild
    assert ns([R(1, "a", high=1)], "standard", "b").action == "review"            # serious, rounds left
    assert ns([R(1, "a", high=1)], "standard", "b").round == 2
    assert ns([R(1, "a", high=1)], "standard", "a").action == "fix"               # same tree: fix first
    assert ns([R(1, "a")], "standard", "a").action == "stop"                      # same tree, clean
    assert ns([R(1, "a", high=1), R(2, "b", critical=1)], "standard", "c").action == "escalate"
    # the tier decides what is serious: medium continues a full review, not a standard one
    assert ns([R(1, "a", medium=1)], "full", "b").action == "review"
    assert ns([R(1, "a", high=0)], "full", "b").action == "stop"                  # zero counts are nothing
    assert ns([R(1, "a", medium=1), R(2, "b", medium=1)], "full", "c").action == "review"
    assert ns([R(1, "a", medium=1)] * 3, "full", "c").action == "escalate"
    assert ns([R(1, "a", high=1)], "light", "b").action == "stop"                 # light: only critical
    assert ns([R(1, "a", critical=1)], "light", "b").action == "escalate"


def test_findings_are_checked():
    assert sg.check_findings({"high": 2, "info": 0}) == {"high": 2, "info": 0}
    for bad in ({"severe": 1}, {"high": -1}, {"high": 1.5}, {"high": True}, [("high", 1)]):
        with pytest.raises(sg.SpendGovError):
            sg.check_findings(bad)


# ---------------------------------------------------------------------------- scope files and trees

def tree(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_resolve_scope(tmp_path):
    root = tree(tmp_path / "r", {"ctf/a.py": "a", "ctf/b.py": "b", "docs/x.md": "x"})
    assert sg.resolve_scope(root, ["ctf/*.py", "docs/x.md", "ctf/a.py"]) == ["ctf/a.py", "ctf/b.py", "docs/x.md"]
    for bad in (["nope.py"], ["*.rs"], ["../r/ctf/a.py"], [str(root / "ctf/a.py")], [""]):
        with pytest.raises(sg.SpendGovError):
            sg.resolve_scope(root, bad)
    (tmp_path / "secret.txt").write_text("s")
    os.symlink(tmp_path / "secret.txt", root / "link.txt")
    with pytest.raises(sg.SpendGovError, match="outside the root"):
        sg.resolve_scope(root, ["link.txt"])


def test_record_round_and_the_standing_diff_audit(tmp_path):
    root = tree(tmp_path / "r", {"ctf/a.py": "a", "ctf/b.py": "b", "tests/t.py": "t"})
    wd = tmp_path / "wd"
    files = sg.resolve_scope(root, ["ctf/*.py", "tests/t.py"])
    rec = sg.record_round("gate", root, files, {"medium": 1}, by="max", workdir=wd)
    assert rec["tier"] == "standard" and rec["files"] == 3 and rec["tree"] == sg.tree_hash(sg.file_hashes(root, files))
    assert [r["event"] for r in ledger.read(wd)] == ["review.round"]
    assert sg.diff_since_review("gate", root, files, workdir=wd).clean
    (root / "ctf/a.py").write_text("a2")
    (root / "ctf/c.py").write_text("c")
    (root / "tests/t.py").unlink()
    d = sg.diff_since_review("gate", root, sg.resolve_scope(root, ["ctf/*.py"]), workdir=wd)
    assert (d.added, d.changed, d.removed, d.unchanged, d.clean) == (("ctf/c.py",), ("ctf/a.py",), ("tests/t.py",), 1, False)
    assert d.base_tree == rec["tree"] and d.tree != rec["tree"]
    # with no files given the audit covers what the round reviewed
    d2 = sg.diff_since_review("gate", root, workdir=wd)
    assert (d2.added, d2.changed, d2.removed) == ((), ("ctf/a.py",), ("tests/t.py",))
    with pytest.raises(sg.SpendGovError, match="record a round first"):
        sg.diff_since_review("other", root, files, workdir=wd)
    sg.snapshot_path("gate", wd).write_text(json.dumps({"files": {"../../etc/passwd": "x"}}))
    with pytest.raises(sg.SpendGovError, match="corrupt"):
        sg.diff_since_review("gate", root, workdir=wd)


def test_record_round_refuses_bad_input_and_writes_nothing(tmp_path):
    root = tree(tmp_path / "r", {"a.py": "a"})
    wd = tmp_path / "wd"
    with pytest.raises(sg.SpendGovError):
        sg.record_round("../x", root, ["a.py"], {}, workdir=wd)
    with pytest.raises(sg.SpendGovError):
        sg.record_round("s", root, ["a.py"], {"bad": 1}, workdir=wd)
    with pytest.raises(sg.SpendGovError, match="missing"):
        sg.record_round("s", root, ["gone.py"], {}, workdir=wd)
    with pytest.raises(sg.SpendGovError):
        sg.record_round("s", root, [], {}, workdir=wd)
    assert not ledger.path(wd).exists()


# ------------------------------------------------------------------------------- review dispatcher

def test_plan_folds_duplicates_applies_the_stopping_rule_and_caps_spawns(tmp_path):
    root = tree(tmp_path / "r", {"ctf/platform/p.py": "p", "ctf/x.py": "x", "ctf/y.py": "y", "tests/t.py": "t",
                                 "docs/d.md": "d"})
    tasks = sg.load_tasks([
        {"name": "small", "scope": ["ctf/x.py"]},
        {"name": "wide", "scope": ["ctf/*.py", "ctf/platform/p.py"]},
        {"name": "plat", "scope": ["ctf/platform/p.py"]},
        {"name": "tests", "scope": ["tests/t.py"]},
        {"name": "docs", "scope": ["docs/d.md"]},
    ])
    plan = sg.plan_reviews(tasks, root, max_agents=2)
    by = {e.name: e for e in plan.entries}
    assert by["wide"].action == "spawn" and by["wide"].tier == "full" and by["wide"].agents == 2
    assert by["small"].action == "duplicate" and by["small"].covered_by == "wide"
    assert by["plat"].action == "duplicate" and by["plat"].covered_by == "wide"
    assert by["tests"].action == "over_cap" and by["tests"].agents == 0      # 2 + 1 > 2
    assert by["docs"].action == "stop"
    assert plan.agents == 2 and plan.needs_person
    assert sg.plan_reviews(tasks, root, max_agents=4).agents == 3
    # a recorded clean round on the same tree stops the wide task: nothing spawns for it again
    wd = tmp_path / "wd"
    files = sg.resolve_scope(root, ["ctf/*.py", "ctf/platform/p.py"])
    sg.record_round("wide", root, files, {"low": 2}, workdir=wd)
    again = sg.plan_reviews(tasks, root, records=list(ledger.read(wd)), max_agents=4)
    assert {e.name: e.action for e in again.entries}["wide"] == "stop" and again.agents == 1
    with pytest.raises(sg.SpendGovError):
        sg.plan_reviews(tasks, root, max_agents=-1)


@pytest.mark.parametrize("data", [[], {}, [{"name": "a"}], [{"name": "a", "scope": []}],
                                  [{"name": "a", "scope": ["x"], "extra": 1}],
                                  [{"name": "a", "scope": ["x"]}, {"name": "a", "scope": ["y"]}],
                                  [{"name": "a b", "scope": ["x"]}]])
def test_load_tasks_refuses_bad_task_lists(data):
    with pytest.raises(sg.SpendGovError):
        sg.load_tasks(data)


# ---------------------------------------------------------------------------------- investigations

def test_investigation_time_box_dollar_cap_and_answer(tmp_path):
    wd = tmp_path / "wd"
    sg.open_investigation("poll", "Does cutting the poll save over 20 requests/min?", metric="requests/min saved",
                          threshold=20, minutes=60, usd=40, by="max", workdir=wd)
    with pytest.raises(sg.SpendGovError, match="already open"):
        sg.open_investigation("poll", "q", metric="m", threshold=1, minutes=1, usd=1, by="max", workdir=wd)
    t0 = next(ledger.read(wd))["ts"]
    recs = list(ledger.read(wd))
    assert sg.investigation("poll", recs, now=t0 + 600).state == "open"
    assert sg.investigation("poll", recs, now=t0 + 3600).state == "over_time"
    recs.append(spend(40.0, t0 + 60, category="other", source="investigation:poll"))
    recs.append(spend(99.0, t0 + 60, category="other", source="investigation:pollx"))
    st = sg.investigation("poll", recs, now=t0 + 600)
    assert st.state == "over_budget" and st.spent == 40.0
    sg.close_investigation("poll", 12.5, by="max", note="measured", workdir=wd)
    st = sg.investigation("poll", list(ledger.read(wd)), now=t0 + 9999)
    assert (st.state, st.answer, st.crossed, st.note) == ("closed", 12.5, False, "measured")
    with pytest.raises(sg.SpendGovError, match="already closed"):
        sg.close_investigation("poll", 1, by="max", workdir=wd)
    with pytest.raises(sg.SpendGovError, match="no investigation"):
        sg.close_investigation("nope", 1, by="max", workdir=wd)
    with pytest.raises(sg.SpendGovError, match="no investigation"):
        sg.investigation("nope", [], now=0)


@pytest.mark.parametrize("kw", [{"minutes": 0}, {"usd": 0}, {"threshold": float("inf")}, {"metric": ""}])
def test_investigation_needs_a_numeric_question_a_time_box_and_a_cap(tmp_path, kw):
    base = dict(metric="m", threshold=1.0, minutes=10, usd=5, by="max")
    with pytest.raises(sg.SpendGovError):
        sg.open_investigation("i", "q", workdir=tmp_path, **{**base, **kw})
    assert not ledger.path(tmp_path).exists()


# ------------------------------------------------------------------------------------------ CLI

def _args(*argv):
    p = argparse.ArgumentParser()
    scli.add_arguments(p)
    return p.parse_args(["--event", "csctf", *argv])


@pytest.fixture
def wd(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    return tmp_path / "wd"


def test_cli_cap_and_decide_refuse_without_a_terminal(wd, capsys):
    assert scli.run(_args("cap", "build", "--usd", "10", "--reason", "r")) == 2
    assert "player's decision" in capsys.readouterr().err
    assert scli.run(_args("decide", "speedrun", "--usd", "10", "--reason", "r")) == 2
    assert not ledger.path(wd).exists()


def test_cli_cap_with_a_terminal_and_the_name_typed_back(wd, monkeypatch, capsys):
    monkeypatch.setattr(scli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(scli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "verify")
    assert scli.run(_args("cap", "build", "--usd", "10", "--reason", "r")) == 2       # typed the wrong name
    assert not ledger.path(wd).exists()
    assert scli.run(_args("cap", "verify", "--usd", "10", "--reason", "quarter")) == 0
    (rec,) = list(ledger.read(wd))
    assert (rec["event"], rec["phase"], rec["usd"]) == ("spend.cap", "verify", 10.0) and rec["by"]


def test_cli_gate_exit_codes(wd, capsys):
    assert scli.run(_args("gate", "--phase", "build")) == scli.HELD_EXIT
    assert "no build cap" in capsys.readouterr().out
    sg.set_cap("build", 10, by="max", reason="r", workdir=wd)
    assert scli.run(_args("gate", "--phase", "build", "--json")) == 0
    assert json.loads(capsys.readouterr().out)["allowed"] is True
    ledger.append("spend", workdir=wd, usd=10.0, tok=1, category="build")
    assert scli.run(_args("gate", "--phase", "build")) == scli.HELD_EXIT
    assert scli.run(_args("gate")) == 2


def test_cli_review_round_next_and_diff(wd, tmp_path, capsys):
    root = tree(tmp_path / "r", {"ctf/a.py": "a"})
    r = ("--root", str(root))
    assert scli.run(_args("next", "s", "ctf/*.py", *r)) == 0
    assert capsys.readouterr().out.startswith("review:")
    assert scli.run(_args("record", "s", "ctf/*.py", "--findings", "high=1,low=2", *r)) == 0
    assert [x["findings"] for x in ledger.read(wd)] == [{"high": 1, "low": 2}]
    capsys.readouterr()
    assert scli.run(_args("next", "s", "ctf/*.py", *r)) == 0
    assert capsys.readouterr().out.startswith("fix:")
    assert scli.run(_args("diff", "s", *r)) == 0
    assert "no change" in capsys.readouterr().out
    (root / "ctf/a.py").write_text("a2")
    assert scli.run(_args("diff", "s", *r, "--json")) == 1
    assert json.loads(capsys.readouterr().out)["changed"] == ["ctf/a.py"]
    assert scli.run(_args("record", "s", "ctf/*.py", "--findings", "critical=1", *r)) == 0
    (root / "ctf/a.py").write_text("a3")
    assert scli.run(_args("next", "s", "ctf/*.py", *r)) == scli.HELD_EXIT          # 2 rounds, still serious
    assert scli.run(_args("record", "s", "ctf/*.py", "--findings", "high", *r)) == 2


def test_count_findings_from_reviewer_output():
    findings = [{"severity": "medium", "where": "a"}, {"severity": "Low"}, {"severity": " low "},
                {"severity": "critical", "fixable": False}]
    assert sg.count_findings(findings) == {"medium": 1, "low": 2, "critical": 1}
    assert sg.count_findings({"verdict": "partly", "findings": findings[:2]}) == {"medium": 1, "low": 1}
    assert sg.count_findings([]) == {} and sg.count_findings({"findings": []}) == {}


@pytest.mark.parametrize("report,match", [
    ([{"where": "a"}], "finding 0 has no severity"),
    ([{"severity": "high"}, {"severity": ""}], "finding 1 has no severity"),
    ([{"severity": 3}], "finding 0 has no severity"),
    ([{"severity": "moderate"}], "unknown severity 'moderate'"),
    ([{"severity": "high"}, "high"], "finding 1 is not an object"),
    ({"verdict": "ok"}, 'no "findings" list'),
    ({"findings": {"high": 1}}, "must be a list"),
    ("high=1", "must be a list"),
])
def test_count_findings_refuses_output_it_cannot_count(report, match):
    with pytest.raises(sg.SpendGovError, match=match):
        sg.count_findings(report)


def test_cli_record_counts_a_reviewer_findings_file(wd, tmp_path, capsys):
    root = tree(tmp_path / "r", {"ctf/a.py": "a"})
    r = ("--root", str(root))
    out = tmp_path / "review.json"
    out.write_text(json.dumps({"findings": [{"severity": "high"}, {"severity": "low"}, {"severity": "low"}]}))
    assert scli.run(_args("record", "s", "ctf/*.py", "--findings-file", str(out), *r)) == 0
    assert [x["findings"] for x in ledger.read(wd)] == [{"high": 1, "low": 2}]
    assert scli.run(_args("next", "s", "ctf/*.py", *r)) == 0
    assert capsys.readouterr().out.splitlines()[-1].startswith("fix:")      # the high finding is serious
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert scli.run(_args("record", "s", "ctf/*.py", "--findings-file", str(bad), *r)) == 2
    assert "not JSON" in capsys.readouterr().err
    bad.write_text(json.dumps([{"title": "no severity"}]))
    assert scli.run(_args("record", "s", "ctf/*.py", "--findings-file", str(bad), *r)) == 2
    assert "finding 0 has no severity" in capsys.readouterr().err
    assert len(list(ledger.read(wd))) == 1                                   # refused rounds write nothing
    with pytest.raises(SystemExit):                                          # one source of findings, not both
        scli.run(_args("record", "s", "ctf/*.py", "--findings", "none", "--findings-file", str(out), *r))


def test_parse_findings():
    assert scli.parse_findings("none") == {}
    assert scli.parse_findings("high=1, low=2,high=1") == {"high": 2, "low": 2}
    with pytest.raises(sg.SpendGovError):
        scli.parse_findings("high=x")


def test_cli_review_plan_dry_run(wd, tmp_path, capsys):
    root = tree(tmp_path / "r", {"ctf/platform/p.py": "p", "tests/t.py": "t"})
    tasks = tmp_path / "tasks.json"
    tasks.write_text(json.dumps([{"name": "p", "scope": ["ctf/platform/p.py"]}, {"name": "t", "scope": ["tests/t.py"]}]))
    assert scli.run(_args("review-plan", "--tasks", str(tasks), "--root", str(root))) == 0
    assert "would start 3 review agent(s) (cap 4)" in capsys.readouterr().out
    assert scli.run(_args("review-plan", "--tasks", str(tasks), "--root", str(root), "--max-agents", "2",
                          "--json")) == scli.HELD_EXIT
    assert json.loads(capsys.readouterr().out)["agents"] == 2
    tasks.write_text("{not json")
    assert scli.run(_args("review-plan", "--tasks", str(tasks), "--root", str(root))) == 2


def test_cli_investigation_and_status(wd, capsys):
    assert scli.run(_args("investigate", "open", "rl", "--question", "q?", "--metric", "req/min", "--threshold", "20",
                          "--minutes", "60", "--usd", "5", "--by", "max")) == 0
    assert scli.run(_args("investigate", "status", "rl")) == 0
    ledger.append("spend", workdir=wd, usd=5.0, tok=1, category="other", source="investigation:rl")
    assert scli.run(_args("investigate", "status")) == scli.HELD_EXIT
    assert scli.run(_args("investigate", "close", "rl", "--answer", "25", "--by", "max")) == 0
    assert "at or above 20" in capsys.readouterr().out
    assert scli.run(_args("status", "--json")) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [i["state"] for i in doc["investigations"]] == ["closed"]
    assert {p["phase"]: p["spent"] for p in doc["phases"]}["other"] == 5.0
    assert "speedrun" in [m["mode"] for m in doc["modes"]]
    assert scli.run(_args("status")) == 0
    assert "NO CAP (held)" in capsys.readouterr().out


# ------------------------------------------------------------------- verification round 1 (B-202)

def test_plan_folds_a_task_with_exactly_the_same_files(tmp_path):
    root = tree(tmp_path / "r", {"ctf/x.py": "x", "ctf/y.py": "y"})
    tasks = sg.load_tasks([{"name": "first", "scope": ["ctf/x.py", "ctf/y.py"]},
                           {"name": "again", "scope": ["ctf/*.py"]}])          # same two files, other spelling
    plan = sg.plan_reviews(tasks, root, max_agents=4)
    by = {e.name: e for e in plan.entries}
    assert by["first"].action == "spawn" and by["first"].agents == 1
    assert by["again"].action == "duplicate" and by["again"].covered_by == "first" and by["again"].agents == 0
    assert plan.agents == 1


def _hint_argv(reason: str) -> list[str]:
    """The command a held gate tells the player to run, with its placeholders filled in."""
    cmd = reason.split("python -m ctf spend ", 1)[1].split(" (in an interactive terminal)")[0]
    cmd = re.sub(r"\[[^\]]*\]", "", cmd)                     # optional parts left out
    return cmd.replace("--usd N", "--usd 10").replace("WHY", "r").replace("GLOB", "hof/*").split()


def test_held_gate_hints_are_commands_the_cli_accepts():
    reasons = [sg.gate(phase="build", records=[], now=NOON).reasons[0],
               sg.gate(mode="speedrun", records=[], now=NOON).reasons[0],
               sg.gate(mode="polish", records=[], now=NOON).reasons[0]]
    p = argparse.ArgumentParser()
    scli.add_arguments(p)
    for reason in reasons:
        assert "--by" not in reason                       # `by` is the typed-back confirmer, not a flag
        ns = p.parse_args(_hint_argv(reason))              # SystemExit(2) on an unknown argument
        assert ns.action in ("cap", "decide") and ns.usd == 10.0 and ns.reason == "r"


@pytest.mark.parametrize("path", ["CLAUDE.md", "events/x/CLAUDE.md", "AGENTS.md", "events/x/AGENTS.md",
                                  ".claude/skills/s/SKILL.md", "skills/s/SKILL.md", ".claude/commands/go.md",
                                  "events/x/.claude/settings.json", "events/x/.claude/commands/go.md",
                                  "requirements.txt", "requirements.in",
                                  "tools/requirements-dev.txt"])
def test_agent_steering_and_dependency_files_are_reviewed(path):
    assert sg.tier_of(path) == "standard"


def test_absolute_paths_take_the_tier_of_their_repo_relative_path(tmp_path):
    from ctf import paths
    assert sg.tier_of(str(paths.repo_root() / "ctf/platform/x.py")) == "full"
    assert sg.tier_of(str(paths.repo_root() / "docs/x.md")) == "none"
    root = tmp_path / "r"
    root.mkdir()
    assert sg.tier_of(str(root / "tests" / "t.py"), root=root) == "light"
    assert sg.scope_tier([str(root / "docs/a.md"), str(root / "solvers/s.py")], root=root) == "full"
    with pytest.raises(sg.SpendGovError, match="outside the root"):
        sg.tier_of(str(tmp_path / "elsewhere" / "ctf/platform/x.py"), root=root)


@pytest.mark.parametrize("path,tier", [
    ("docs/../solvers/x.py", "full"), ("tests/../ctf/platform/x.py", "full"), ("./docs/./a.md", "none"),
    ("docs//../tests/t.py", "light"), ("solvers/../docs/a.md", "none")])
def test_relative_paths_are_normalized_before_the_tier_is_decided(path, tier):
    assert sg.tier_of(path) == tier


@pytest.mark.parametrize("path", ["../x.py", "docs/../../solvers/x.py", ".."])
def test_a_relative_path_that_climbs_out_of_the_root_is_an_error(path):
    with pytest.raises(sg.SpendGovError, match="climbs out"):
        sg.tier_of(path)


def test_absolute_paths_are_resolved_before_the_tier_is_decided(tmp_path):
    from ctf import paths
    assert sg.tier_of(str(paths.repo_root()) + "/docs/../solvers/x.py") == "full"
    root = tmp_path / "r"
    (root / "solvers").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "notes").symlink_to(root / "solvers", target_is_directory=True)
    (root / "solvers" / "s.py").write_text("x = 1\n")
    assert sg.tier_of(str(root) + "/docs/../solvers/s.py", root=root) == "full"
    assert sg.tier_of(str(root / "notes" / "s.py"), root=root) == "full"   # a symlink is judged by its target
    with pytest.raises(sg.SpendGovError, match="outside the root"):
        sg.tier_of(str(root) + "/../elsewhere/solvers/s.py", root=root)


def test_cli_tier_makes_absolute_paths_relative(wd, tmp_path, capsys):
    root = tmp_path / "r"
    root.mkdir()
    assert scli.run(_args("tier", str(root / "ctf/platform/x.py"), "--root", str(root))) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "scope tier: full"


def test_cli_tier_normalizes_relative_paths_and_refuses_one_that_climbs_out(wd, capsys):
    assert scli.run(_args("tier", "docs/../solvers/x.py")) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "scope tier: full"
    assert scli.run(_args("tier", "../x.py")) == 2
    assert "climbs out of the repo root" in capsys.readouterr().err


def test_undated_spend_counts_toward_an_event_cap_but_not_a_day_cap():
    undated = {"event": "spend", "usd": 4.0, "tok": 1, "category": "build"}
    day = sg.phase_status("build", [cap("build", 10.0, NOON - 60), undated, spend(1.0, NOON - 60, category="build")],
                          now=NOON)
    assert (day.spent, day.undated) == (1.0, 1)
    ev = sg.phase_status("build", [cap("build", 10.0, NOON - 60, period="event"), undated,
                                   spend(1.0, NOON - 60, category="build")], now=NOON)
    assert (ev.spent, ev.undated) == (5.0, 1)


def test_day_cap_counts_spend_at_exactly_midnight_and_at_now():
    midnight = sg.day_start(NOON)
    assert midnight == dt.datetime(2026, 11, 6, tzinfo=UTC).timestamp()
    recs = [cap("build", 10.0, NOON - DAY), spend(2.0, midnight, category="build"),
            spend(1.0, NOON, category="build"), spend(7.0, midnight - 0.001, category="build")]
    assert sg.phase_status("build", recs, now=NOON).spent == 3.0


def test_spend_at_the_solve_instant_is_speedrun_spend():
    solved = {"event": "stop", "ts": NOON - 3600, "challenge_id": TT, "reason": "team_solve"}
    recs = [solved, mode("speedrun", 50.0, NOON - 7200), spend(5.0, NOON - 3600, challenge_id=TT),
            spend(9.0, NOON - 3600.001, challenge_id=TT)]
    assert sg.mode_status("speedrun", recs, now=NOON).spent == 5.0
    assert sg.modes_of(TT, NOON - 3600, {TT: NOON - 3600}, {}) == ["speedrun"]


def test_investigation_answer_equal_to_the_threshold_crossed_it(tmp_path):
    wd = tmp_path / "wd"
    sg.open_investigation("eq", "q?", metric="m", threshold=20, minutes=60, usd=5, by="max", workdir=wd)
    sg.close_investigation("eq", 20, by="max", workdir=wd)
    st = sg.investigation("eq", list(ledger.read(wd)), now=time.time())
    assert st.answer == 20.0 and st.crossed is True


def test_mode_time_box_holds_once_its_minutes_pass_from_the_first_spend(tmp_path):
    solved = {"event": "stop", "ts": NOON - 3 * 3600, "challenge_id": TT, "reason": "team_solve"}
    first = NOON - 2 * 3600                          # speed-run work began 120 min before NOON
    recs = [solved, {**mode("speedrun", 100.0, NOON - 4 * 3600), "minutes": 120.0},
            spend(1.0, first, challenge_id=TT), spend(1.0, NOON - 60, challenge_id=TT)]
    st = sg.mode_status("speedrun", recs, now=NOON - 1)
    assert (st.state, st.started, st.budget.minutes) == ("ok", first, 120.0)
    assert sg.gate(challenge_id=TT, records=recs, now=NOON - 1).allowed
    v = sg.gate(challenge_id=TT, records=recs, now=NOON)          # exactly 120 minutes in
    assert not v.allowed and "120 minute time box" in v.reasons[0]
    assert sg.mode_status("speedrun", recs, now=NOON).state == "over_time"
    # a budget with no minutes has no time box; the dollar cap still decides first
    no_box = [solved, mode("speedrun", 100.0, NOON - 4 * 3600), spend(1.0, first, challenge_id=TT)]
    assert sg.mode_status("speedrun", no_box, now=NOON + 30 * DAY).state == "ok"
    spent = [solved, {**mode("speedrun", 1.0, NOON - 4 * 3600), "minutes": 120.0}, spend(1.0, first, challenge_id=TT)]
    assert sg.mode_status("speedrun", spent, now=NOON).state == "over"
    # the time box is recorded with the decision and checked
    rec = sg.decide_mode("speedrun", 50, by="max", reason="r", minutes=90, workdir=tmp_path)
    assert rec["minutes"] == 90.0 and sg.mode_budgets(ledger.read(tmp_path))["speedrun"].minutes == 90.0
    for bad in (0, -5, float("nan"), True):
        with pytest.raises(sg.SpendGovError, match="minutes"):
            sg.decide_mode("speedrun", 50, by="max", reason="r", minutes=bad, workdir=tmp_path / "x")
    assert not ledger.path(tmp_path / "x").exists()


def test_cli_decide_records_the_time_box(wd, monkeypatch):
    monkeypatch.setattr(scli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(scli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt: "speedrun")
    assert scli.run(_args("decide", "speedrun", "--usd", "40", "--minutes", "720", "--reason", "hardening box")) == 0
    (rec,) = list(ledger.read(wd))
    assert (rec["event"], rec["mode"], rec["usd"], rec["minutes"]) == ("spend.mode", "speedrun", 40.0, 720.0)
