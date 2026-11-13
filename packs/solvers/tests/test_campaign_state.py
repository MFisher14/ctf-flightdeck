"""B-178: checkpointed goals and crash-safe campaign state (ctf.campaign), resume file and briefs."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from ctf import budget, campaign, event, ledger, paths, scratch
from ctf.campaign import Campaign, CampaignError


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def camp(tmp_path, clock):
    return Campaign(tmp_path, event="csctf", now=clock)


def _rev_marker(camp):
    head = camp.resume_path.read_text().splitlines()[0]
    return int(head.split("rev=")[1].split()[0])


# ---------------------------------------------------------------------------- storage


def test_empty_campaign_loads_without_files(camp):
    st = camp.load()
    assert st["rev"] == 0 and st["goals"] == {} and st["agents"] == {}
    assert not camp.state_path.exists()


def test_every_change_bumps_rev_writes_prev_and_regenerates_resume(camp):
    camp.add_goal("g1", "first goal", next_step="look")
    assert camp.load()["rev"] == 1 and _rev_marker(camp) == 1
    assert not camp.prev_path.exists()
    camp.checkpoint("g1", "did a thing", next_step="do the next thing")
    assert camp.load()["rev"] == 2 and _rev_marker(camp) == 2
    prev = json.loads(camp.prev_path.read_text())
    assert prev["rev"] == 1 and prev["goals"]["g1"]["checkpoints"] == []
    assert "do the next thing" in camp.resume_path.read_text()


def test_crash_mid_write_leaves_the_last_good_state(camp, monkeypatch):
    camp.add_goal("g1", "goal")
    real_replace = os.replace

    def crash(src, dst):
        if str(dst).endswith(campaign.STATE_NAME):
            raise OSError("power cut")
        return real_replace(src, dst)

    monkeypatch.setattr(campaign.os, "replace", crash)
    with pytest.raises(OSError, match="power cut"):
        camp.checkpoint("g1", "lost work")
    monkeypatch.setattr(campaign.os, "replace", real_replace)
    st = camp.load()
    assert st["rev"] == 1 and st["goals"]["g1"]["checkpoints"] == []


def test_exception_inside_a_transaction_writes_nothing(camp):
    camp.add_goal("g1", "goal")
    with pytest.raises(RuntimeError):
        with camp.transaction() as st:
            st["goals"]["g1"]["title"] = "changed"
            raise RuntimeError("abort")
    assert camp.load()["goals"]["g1"]["title"] == "goal" and camp.load()["rev"] == 1


def test_corrupt_state_fails_loudly_and_recover_restores_prev(camp):
    camp.add_goal("g1", "goal")
    camp.checkpoint("g1", "note one")
    camp.state_path.write_text('{"schema": 1, "rev": ')
    with pytest.raises(CampaignError, match="corrupt campaign state.*recover"):
        camp.load()
    msg = camp.recover()
    assert "restored rev 1" in msg
    st = camp.load()
    assert st["rev"] == 1 and "g1" in st["goals"]
    kept = [p for p in camp.dir.iterdir() if p.name.startswith("state.json.corrupt-")]
    assert len(kept) == 1 and kept[0].read_text() == '{"schema": 1, "rev": '
    assert _rev_marker(camp) == 1


def test_missing_state_beside_prev_is_not_treated_as_empty(camp):
    camp.add_goal("g1", "goal")
    camp.add_goal("g2", "goal")
    camp.state_path.unlink()
    with pytest.raises(CampaignError, match="missing but .*prev exists"):
        camp.load()


def test_wrong_schema_is_rejected(camp):
    camp.dir.mkdir(parents=True)
    camp.state_path.write_text(json.dumps({"schema": 99}))
    with pytest.raises(CampaignError, match="schema-1"):
        camp.load()
    camp.state_path.write_text(json.dumps({**campaign.empty_state(), "goals": {"x": {"status": "weird"}}}))
    with pytest.raises(CampaignError, match="goal 'x' is malformed"):
        camp.load()


def test_recover_without_prev_fails(camp):
    with pytest.raises(CampaignError, match="nothing to recover"):
        camp.recover()


_WORKER = """
import sys
from pathlib import Path
from ctf.campaign import Campaign
c = Campaign(Path(sys.argv[1]))
for i in range(int(sys.argv[3])):
    c.checkpoint("g", f"{sys.argv[2]}-{i}")
"""


def test_concurrent_writers_lose_no_checkpoint(camp, tmp_path):
    camp.add_goal("g", "shared goal")
    env = {**os.environ, "PYTHONPATH": str(paths.repo_root())}
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(tmp_path), f"w{k}", "15"], env=env)
             for k in range(4)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0, 0]
    st = camp.load()
    notes = sorted(c["note"] for c in st["goals"]["g"]["checkpoints"])
    assert notes == sorted(f"w{k}-{i}" for k in range(4) for i in range(15))
    assert st["rev"] == 1 + 60


# ---------------------------------------------------------------------------- goals


def test_goal_lifecycle(camp, clock):
    g = camp.add_goal("web12", "SSTI on 12", challenge="12", lane="web", next_step="try jinja", by="max")
    assert g["status"] == "open" and g["next"] == "try jinja"
    clock.t += 10
    cp = camp.checkpoint("web12", "ruled out ERB", by="agent-a")
    g = camp.load()["goals"]["web12"]
    assert g["status"] == "active", "a checkpoint starts an open goal"
    assert g["next"] == "try jinja", "a checkpoint without --next keeps the old next step"
    assert cp["ts"] == clock.t and g["updated"] == clock.t
    camp.checkpoint("web12", "jinja confirmed", next_step="read config")
    assert camp.load()["goals"]["web12"]["next"] == "read config"
    with pytest.raises(CampaignError, match="blocker"):
        camp.set_goal_status("web12", "blocked")
    camp.set_goal_status("web12", "blocked", blocker="instance down")
    g = camp.load()["goals"]["web12"]
    assert g["status"] == "blocked" and g["blocker"] == "instance down"
    camp.set_goal_status("web12", "done", note="flag accepted")
    g = camp.load()["goals"]["web12"]
    assert g["status"] == "done" and g["blocker"] is None
    assert [c.get("to") for c in g["checkpoints"] if c["kind"] == "status"] == ["blocked", "done"]
    with pytest.raises(CampaignError, match="is done; reopen"):
        camp.checkpoint("web12", "more")


def test_goal_validation(camp):
    with pytest.raises(CampaignError, match="bad goal id"):
        camp.add_goal("Bad Id", "x")
    with pytest.raises(CampaignError, match="title"):
        camp.add_goal("g", "   ")
    with pytest.raises(CampaignError, match="bad lane"):
        camp.add_goal("g", "x", lane="Web Lane")
    camp.add_goal("g", "x")
    with pytest.raises(CampaignError, match="already exists"):
        camp.add_goal("g", "y")
    with pytest.raises(CampaignError, match="no goal"):
        camp.checkpoint("nope", "x")
    with pytest.raises(CampaignError, match="note"):
        camp.checkpoint("g", "")
    with pytest.raises(CampaignError, match="goal status"):
        camp.set_goal_status("g", "finished")


# ---------------------------------------------------------------------------- registered agents


def test_registered_agent_is_lost_after_stale_heartbeat(camp, clock):
    camp.add_goal("g", "goal", next_step="n")
    camp.register("codex-web", "codex", challenge="12", goal="g")
    clock.t += campaign.STALE_HEARTBEAT_SECONDS - 60
    assert camp.reconcile() == []
    camp.heartbeat("codex-web", note="still probing")
    clock.t += campaign.STALE_HEARTBEAT_SECONDS - 60
    assert camp.reconcile() == [], "a heartbeat resets the clock"
    clock.t += 120
    assert camp.reconcile() == ["codex-web"]
    rec = camp.load()["agents"]["codex-web"]
    assert rec["status"] == "lost" and "no heartbeat" in rec["lost_reason"]
    assert camp.reconcile() == [], "already lost: not reported twice"
    with pytest.raises(CampaignError, match="not running"):
        camp.heartbeat("codex-web")
    rl = camp.relaunch_list()
    assert [(x["agent"], x["eligible"]) for x in rl] == [("codex-web", False)]
    assert "registered by hand" in rl[0]["reason"]
    assert "codex-web" in camp.resume_path.read_text().split("## Relaunch list")[1].split("##")[0]
    led = [r for r in ledger.read(camp.workdir) if r["event"] == "campaign.lost"]
    assert led and led[0]["agents"] == ["codex-web"]


def test_reconcile_writes_nothing_when_nothing_changed(camp):
    camp.add_goal("g", "goal")
    camp.register("a", "claude")
    rev = camp.load()["rev"]
    assert camp.reconcile() == []
    assert camp.load()["rev"] == rev


def test_agent_finish_and_registration_rules(camp):
    with pytest.raises(CampaignError, match="harness"):
        camp.register("a", "gpt")
    with pytest.raises(CampaignError, match="no goal"):
        camp.register("a", "claude", goal="missing")
    assert camp.register("a", "claude")["launches"] == 1
    with pytest.raises(CampaignError, match="already running"):
        camp.register("a", "claude")
    assert camp.finish("a", "done", note="solved") is True
    assert camp.finish("a", "failed") is False, "a finished agent is not re-finished"
    with pytest.raises(CampaignError, match="done or failed"):
        camp.finish("a", "lost")
    assert camp.load()["agents"]["a"]["status"] == "done"
    again = camp.register("a", "claude")
    assert again["launches"] == 2 and camp.load()["agents"]["a"]["launches"] == 2, \
        "re-registering a finished agent counts its launches on"


def test_set_pid_only_for_the_current_launch_and_keeps_resume_current(camp):
    camp.register("a", "claude")
    camp.set_pid("a", 2, 999)
    assert camp.load()["agents"]["a"].get("pid") is None
    camp.set_pid("a", 1, 4242)
    st = camp.load()
    assert st["agents"]["a"]["pid"] == 4242 and camp.resume_current(st)


def test_finish_with_stale_launch_number_changes_nothing(camp):
    camp.register("a", "claude")
    assert camp.finish("a", "done", launch=7) is False
    assert camp.load()["agents"]["a"]["status"] == "running"


# ---------------------------------------------------------------------------- relaunch list rules


def _fake_lost(camp, aid, *, goal=None, challenge=None, launches=1):
    with camp.transaction() as st:
        st["agents"][aid] = {"id": aid, "harness": "codex", "supervised": True, "status": "lost",
                             "argv": ["/x/codex_launch"], "cwd": "/", "goal": goal, "challenge": challenge,
                             "launches": launches, "lost_reason": "machine restart"}


def test_relaunch_list_skips_closed_goals_and_respects_cap_and_budget_stops(camp):
    camp.add_goal("live", "live goal", next_step="n")
    camp.add_goal("finished", "done goal")
    camp.set_goal_status("finished", "done")
    _fake_lost(camp, "a1", goal="live")
    _fake_lost(camp, "a2", goal="finished")
    _fake_lost(camp, "a3", goal="live", launches=campaign.MAX_LAUNCHES)
    _fake_lost(camp, "a4", challenge="12")
    budget.on_team_solve("12", solver="teammate", workdir=camp.workdir)
    rl = {x["agent"]: x for x in camp.relaunch_list()}
    assert set(rl) == {"a1", "a3", "a4"}, "an agent whose goal is done is not relaunched"
    assert rl["a1"]["eligible"] and rl["a1"]["reason"] == ""
    assert not rl["a3"]["eligible"] and "cap" in rl["a3"]["reason"]
    assert not rl["a4"]["eligible"] and "team_solve" in rl["a4"]["reason"]
    with pytest.raises(CampaignError, match="team_solve"):
        camp.relaunch("a4")
    with pytest.raises(CampaignError, match="only lost agents"):
        camp.relaunch("a2")


def test_failed_agents_relaunch_only_when_asked(camp):
    camp.register("f", "claude")
    camp.finish("f", "failed")
    assert camp.relaunch_list() == []
    assert [x["agent"] for x in camp.relaunch_list(include_failed=True)] == ["f"]


def test_unreadable_ledger_blocks_relaunch_with_a_named_reason(camp):
    _fake_lost(camp, "a", challenge="12")
    (camp.workdir / ledger.LEDGER_NAME).write_text("{not json\n")
    x = camp.relaunch_list()[0]
    assert not x["eligible"] and "ledger unreadable" in x["reason"]


def test_relaunch_list_blocks_a_challenge_at_its_budget_cap(camp):
    _fake_lost(camp, "a", challenge="12")
    _fake_lost(camp, "b", challenge="13")
    meter = budget.LedgerMeter(event.load("csctf"), workdir=camp.workdir, on_cap=lambda st, path: None)

    def spend(cid, usd):
        try:
            meter.add_spend(cid, usd, 1)
        except budget.BudgetExceeded:      # recorded, then refused: the cap is reached
            pass

    cap = meter.cap("12")
    spend("12", cap - 0.01)
    rl = {x["agent"]: x for x in camp.relaunch_list()}
    assert rl["a"]["eligible"], "under the cap a relaunch is allowed"
    spend("13", cap)                       # exactly at the cap is at cap, as the R-09 gate counts it
    spend("12", 0.01)
    rl = {x["agent"]: x for x in camp.relaunch_list()}
    for aid, cid in (("a", "12"), ("b", "13")):
        assert not rl[aid]["eligible"] and "budget cap" in rl[aid]["reason"]
        assert f"python -m ctf budget extend {cid}" in rl[aid]["reason"]
    with pytest.raises(CampaignError, match="budget cap"):
        camp.relaunch("a")
    assert camp.load()["agents"]["a"]["status"] == "lost"
    meter.extend("12", 10.0, by="max", reason="test")
    assert {x["agent"]: x for x in camp.relaunch_list()}["a"]["eligible"], "an extended cap lifts the block"


def test_budget_cap_unknown_without_an_event_profile_blocks_relaunch(tmp_path):
    camp = Campaign(tmp_path, event="no-such-event")
    _fake_lost(camp, "a", challenge="12")
    _fake_lost(camp, "b")
    rl = {x["agent"]: x for x in camp.relaunch_list()}
    assert not rl["a"]["eligible"] and "cannot check challenge 12's budget cap" in rl["a"]["reason"]
    assert "no-such-event" in rl["a"]["reason"]
    assert rl["b"]["eligible"], "an agent with no challenge has no budget to check"


# ---------------------------------------------------------------------------- session end, check


def test_end_refuses_live_goal_without_next_step(camp):
    camp.add_goal("g1", "has next", next_step="x")
    camp.add_goal("g2", "no next")
    camp.add_goal("g3", "closed, no next")
    camp.set_goal_status("g3", "dropped")
    with pytest.raises(CampaignError, match="no next step.*g2"):
        camp.end_session("night 1")
    assert camp.load()["sessions"] == []
    assert not (camp.briefs_dir / "next-session.md").exists()


def test_end_writes_resume_and_briefs_and_records_the_end(camp, tmp_path, clock):
    (tmp_path / "12-login").mkdir()
    camp.add_goal("web12", "SSTI", challenge="12", lane="web", next_step="probe")
    camp.add_goal("rev3", "VM", challenge="3", lane="rev", next_step="lift handlers")
    camp.add_goal("old", "solved earlier", lane="crypto")
    camp.set_goal_status("old", "done")
    closed = camp.resume_path.read_text().split("## Closed goals")[1].split("## ")[0]
    assert "`old`" in closed, "before any session end every closed goal is listed"
    clock.t += 10
    prof = event.load("csctf")
    written = camp.end_session("night 1 wrap", by="max", profile=prof)
    names = sorted(p.name for p in written)
    assert names == ["RESUME.md", "next-session.md", "rev-gap.md", "web-gap.md"], \
        "a gap brief per lane with live goals, none for a lane with only closed goals"
    st = camp.load()
    assert st["sessions"][-1]["summary"] == "night 1 wrap" and st["sessions"][-1]["by"] == "max"
    assert _rev_marker(camp) == st["rev"]
    assert "night 1 wrap" in camp.resume_path.read_text()
    assert any(r["event"] == "campaign.end" for r in ledger.read(camp.workdir))
    assert camp.check() == []
    clock.t += 10
    camp.set_goal_status("rev3", "done")
    resume = camp.resume_path.read_text()
    assert "## Closed goals" not in resume
    since = resume.split("## Closed since the last session end")[1].split("## ")[0]
    assert "`rev3`" in since, "a goal closed after the last end is listed"
    assert "`old`" not in since, "a goal closed before the last end is not"


def test_check_reports_stale_resume_missing_next_and_lost_agents(camp, clock):
    assert camp.check() == [], "a workdir that never used the campaign has nothing to resume"
    assert not camp.state_path.exists() and not camp.resume_path.exists()
    assert not camp.dir.exists(), "a check of a workdir that never used the campaign creates nothing in it"
    camp.add_goal("g", "goal")
    camp.resume_path.unlink()
    assert any("missing or older" in p for p in camp.check()), "once state exists, a missing RESUME.md is unfit"
    camp.reconcile()
    probs = camp.check()
    assert any("without a next step: g" in p for p in probs)
    assert not any("missing or older" in p for p in probs)
    camp.checkpoint("g", "x", next_step="y")
    camp.resume_path.write_text("hand edited\n")
    assert any("missing or older" in p for p in camp.check())
    camp.reconcile()        # rebuilds a stale resume even when no agent changed
    assert camp.check() == []
    camp.register("a", "claude", goal="g")
    clock.t += campaign.STALE_HEARTBEAT_SECONDS + 1
    camp.reconcile()
    assert any("agent a is lost" in p for p in camp.check())


# ---------------------------------------------------------------------------- briefs


def test_resume_lists_goals_in_priority_order_with_recent_checkpoints(camp, clock, tmp_path):
    (tmp_path / "5-pwn").mkdir()
    camp.add_goal("o", "open one", next_step="start")
    camp.add_goal("b", "blocked one", next_step="wait")
    camp.set_goal_status("b", "blocked", blocker="instance")
    camp.add_goal("a", "active one", challenge="5")
    for i in range(5):
        clock.t += 1
        camp.checkpoint("a", f"step {i}", next_step=f"after {i}")
    scratch.open_pass(tmp_path / "5-pwn", "fuzz")
    text = camp.resume_path.read_text()
    goals = text.split("## Goals in progress")[1]
    assert goals.index("`a`") < goals.index("`b`") < goals.index("`o`")
    assert "step 4" in goals and "step 2" in goals and "step 1" not in goals, "last 3 checkpoints only"
    assert "blocked on: instance" in goals
    # the scratch line reflects the folder as of the last write
    camp.checkpoint("a", "step 5")
    assert "001-fuzz" in camp.resume_path.read_text()
    assert campaign._DATA_NOTE in text


def test_gap_brief_carries_every_checkpoint_rules_and_only_its_lane(camp, tmp_path, monkeypatch):
    (tmp_path / "12-login").mkdir()
    camp.add_goal("web12", "SSTI", challenge="12", lane="web", next_step="probe")
    for i in range(5):
        camp.checkpoint("web12", f"ruled out {i}")
    camp.add_goal("rev3", "VM thing", lane="rev", next_step="x")
    p = scratch.open_pass(tmp_path / "12-login", "probe")
    scratch.close_pass(p, note="nothing in headers")
    prof = event.load("huntress")
    path = camp.write_brief("gap", lane="web", profile=prof)
    text = path.read_text()
    assert path.name == "web-gap.md"
    assert all(f"ruled out {i}" in text for i in range(5)), "the gap brief keeps the whole history"
    assert "VM thing" not in text
    assert "Do not submit" in text and "codex_result.md" in text
    assert "nothing in headers" in text and "001-probe" in text
    scope = prof.rules.live_service_scope
    if scope:
        assert f"`{scope[0]}`" in text
    else:
        assert "No live host is in scope" in text
    assert ("State-changing web requests are allowed" in text) == prof.rules.web_state_changing
    no_prof = camp.write_brief("gap", lane="web").read_text()
    assert "No event profile was loaded" in no_prof
    with pytest.raises(CampaignError, match="unknown brief"):
        camp.write_brief("weekly")


def test_next_session_brief_marks_budget_stopped_challenges(camp):
    camp.add_goal("g12", "on 12", challenge="12", next_step="a")
    camp.add_goal("g13", "on 13", challenge="13", next_step="b")
    budget.on_team_solve("12", workdir=camp.workdir)
    text = camp.write_brief("next-session").read_text()
    q = text.split("## Work queue")[1].split("##")[0]
    line12 = next(l for l in q.splitlines() if "g12" in l)
    line13 = next(l for l in q.splitlines() if "g13" in l)
    assert "STOPPED (team_solve)" in line12 and "STOPPED" not in line13
    assert "python -m ctf campaign resume --relaunch" in text
