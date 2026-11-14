"""B-212: no-model helper launch on a lane STOP, warm standby only where predicted (ctf/helpers.py).

Offline. STOPs are real ledger records (the shapes ctf.adapt.chain and ctf.adapt.regress write; one test
drives the real chain and lane gate on the synthetic checkout of tests/adapt_repo.py). Warm hand-offs go
through the real warm pool (ctf.standby take/lease). Cold launches go through a recording campaign
stand-in, except the tests marked real-campaign, which start the real ctf.campaign supervisor on a stub
launcher script the test writes: no real Claude or Codex session, no model, no network. Time is an
injected step clock everywhere except the real-supervisor wait (rule 16, commented there).
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from ctf import campaign, cli, ledger, standby
from ctf import helpers as H
from ctf.campaign import CampaignError
from ctf.lookahead import forecast

LANE = "binary"
BASE = "binary-day-04"


# --------------------------------------------------------------------------------------- fixtures

class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        """An injected sleep that advances the clock, so a take that finds nothing reaches its timeout and
        raises instead of spinning forever on a frozen clock."""
        self.t += s


class RecordingCampaign:
    """The campaign the watcher launches cold helpers through, recording each launch. The watcher's
    decisions (what it launched, with which handout, and what it did when the agent ended) are what the
    tests assert; Campaign.launch itself is covered by the real-campaign tests below and B-178's."""

    def __init__(self, refuse: str | None = None):
        self.launches: list[dict] = []
        self.agents: dict[str, dict] = {}
        self.refuse = refuse

    def launch(self, aid, argv, *, harness, cwd=None, challenge=None, prompt_file=None, **_kw):
        if self.refuse:
            raise CampaignError(self.refuse)
        self.launches.append({"aid": aid, "argv": list(argv), "harness": harness, "cwd": cwd,
                              "challenge": challenge, "prompt": Path(prompt_file).read_text(encoding="utf-8")})
        self.agents[aid] = {"id": aid, "status": "running"}
        return self.agents[aid]

    def load(self):
        return {"agents": self.agents}


class Step:
    def __init__(self, action, reason="r"):
        self.action, self.reason = action, reason


@pytest.fixture
def wd(tmp_path):
    w = tmp_path / "work"
    (w / "briefs").mkdir(parents=True)
    (w / "briefs" / f"{LANE}-gap.md").write_text("# binary gap brief\nWARM-BRIEF-MARKER: fold the go fingerprints\n")
    return w


def cfg(**over) -> H.Config:
    h = {"launcher": ["/bin/true"], "harness": "claude", "handoff_wait": 20, "max_per_lane": 3}
    lanes = over.pop("lanes", {})
    h.update(over)
    return H.parse_config({"helpers": h, "lane": lanes}, "test")


def watcher(wd, config=None, *, clock=None, camp=None, resume=None, start="beginning"):
    resumed = []

    def _resume(base, lane):
        resumed.append((base, lane))
        return Step("start", "lane gate green")
    w = H.Watcher(wd, config or cfg(), clock=clock or Clock(), campaign=camp if camp is not None else RecordingCampaign(),
                  resume=resume or _resume, start=start)
    w.resumed = resumed
    return w


def chain_stop(wd, cid=BASE + "/time_trial", lane=LANE, reason="lane gate NO: probe exited 4"):
    ledger.append("adapt.chain", workdir=wd, challenge_id=cid, lane=lane, action="stop", reason=reason)


def gate_rec(wd, verdict, lane=LANE):
    ledger.append("adapt.gate", workdir=wd, lane=lane, verdict=verdict, lane_key="k", reason="x")


def events(wd, name):
    return [r for r in ledger.read(wd) if r["event"] == name]


def warm_agent(wd, name="hw-binary-01", lane=LANE, clock=None, pid=standby.OWN_PROCESS):
    standby.register(wd, name, status=standby.WAITING, pool=standby.HELPERS_POOL, lane=lane,
                     clock=clock or time.time, pid=pid)


# --------------------------------------------------------------------------------------- config

def test_config_is_strict_and_fails_loudly(tmp_path):
    with pytest.raises(H.HelperError, match="no helper config"):
        H.load_config(tmp_path / "missing.toml")
    with pytest.raises(H.HelperError, match="launcher is required"):
        H.parse_config({"helpers": {}})
    with pytest.raises(H.HelperError, match="no \\[helpers\\] table"):
        H.parse_config({"lane": {}})
    with pytest.raises(H.HelperError, match="unknown key"):
        cfg(spawn_everything=True)
    with pytest.raises(H.HelperError, match="mode 'hot'"):
        cfg(lanes={LANE: {"mode": "hot"}})
    with pytest.raises(H.HelperError, match="exceeds the standby take cap"):
        cfg(warm_timeout=standby.MAX_TIMEOUT + 1)
    with pytest.raises(H.HelperError, match="cannot name a helper"):
        cfg(lanes={"../x": {}})
    with pytest.raises(H.HelperError, match="max_per_lane"):
        cfg(max_per_lane=0)
    with pytest.raises(H.HelperError, match="lease_ttl must be a number > 0"):
        cfg(lease_ttl=0)
    assert cfg().lease_ttl == H.DEFAULT_LEASE_TTL and cfg(lease_ttl=60).lease_ttl == 60
    p = tmp_path / "h.toml"
    p.write_text('[helpers]\nlauncher = ["tools/claude_launch"]\ndefault_mode = "cold"\n[lane.web]\nwarm_agents = 2\n')
    c = H.load_config(p)
    assert c.lane("web").mode == "cold" and c.lane("web").warm_agents == 2     # inherits default_mode
    assert c.lane("unlisted").mode == "cold"
    assert c.launcher_for("web")[0] == str(H._paths.repo_root() / "tools/claude_launch")


def test_brief_path_defaults_to_the_campaign_gap_brief(wd):
    c = cfg(lanes={"web": {"brief": "notes/web.md"}})
    assert c.brief_path(LANE, wd) == wd / "briefs" / f"{LANE}-gap.md"
    assert c.brief_path("web", wd) == wd / "notes" / "web.md"


# --------------------------------------------------------------------------------------- classification + tail

def test_stop_and_healthy_classification():
    s = H.stop_of({"event": "adapt.chain", "action": "stop", "lane": LANE, "challenge_id": f"{BASE}/mastery",
                   "reason": "2 failed"})
    assert s["lane"] == LANE and s["base"] == BASE                      # the mode id maps to its base
    g = H.stop_of({"event": "adapt.gate", "verdict": "no", "lane": LANE, "reason": "x"})
    assert g["lane"] == LANE and g["base"] is None
    assert H.stop_of({"event": "adapt.gate", "verdict": "yes", "lane": LANE}) is None
    assert H.stop_of({"event": "adapt.chain", "action": "hold", "lane": LANE}) is None
    assert H.healthy_lane({"event": "adapt.gate", "verdict": "yes", "lane": LANE}) == LANE
    assert H.healthy_lane({"event": "adapt.chain", "action": "start", "lane": LANE}) == LANE
    assert H.healthy_lane({"event": "adapt.chain", "action": "retry", "lane": LANE}) == LANE
    assert H.healthy_lane({"event": "adapt.chain", "action": "wait", "lane": LANE}) is None
    # a chain `done` runs no lane gate: it is no evidence the lane is healthy
    assert H.healthy_lane({"event": "adapt.chain", "action": "done", "lane": LANE}) is None
    assert H.healthy_lane({"event": "adapt.gate", "verdict": "not-run", "lane": LANE}) is None


def test_tail_reads_only_complete_lines_and_refuses_a_shrunk_ledger(wd):
    chain_stop(wd)
    p = ledger.path(wd)
    size = p.stat().st_size
    with open(p, "a") as fh:
        fh.write('{"event": "adapt.chain", "action": "st')            # a half-written line
    recs, off = H.tail(wd, 0)
    assert [r["event"] for r in recs] == ["adapt.chain"] and off == size
    assert H.tail(wd, off) == ([], off)                                # the partial line waits
    with pytest.raises(H.HelperError, match="shorter than the watcher's cursor"):
        H.tail(wd, p.stat().st_size + 5)
    p.write_text("not json\n")
    with pytest.raises(H.HelperError, match="corrupt ledger line"):
        H.tail(wd, 0)


def test_a_first_start_tails_from_the_end_unless_told_otherwise(wd):
    chain_stop(wd)                                 # before the watcher started: someone else's business
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp, start="end")
    assert w.tick().empty() and camp.launches == []
    chain_stop(wd, cid="other-day-05/time_trial")  # after: ours
    r = w.tick()
    assert [x["bases"] for x in r.launched] == [["other-day-05"]]


# --------------------------------------------------------------------------------------- cold launch

def test_a_stop_launches_one_cold_helper_from_the_warm_brief_and_absorbs_later_stops(wd):
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp)
    chain_stop(wd)
    r = w.tick()
    assert [(x["helper_id"], x["mode"]) for x in r.launched] == [("helper-binary-001", "cold")]
    (launch,) = camp.launches
    assert launch["aid"] == "helper-binary-001" and launch["challenge"] == BASE
    assert launch["argv"] == ["/bin/true"] and launch["harness"] == "claude"
    prompt = launch["prompt"]
    assert "WARM-BRIEF-MARKER" in prompt                           # started from the lane's warm brief
    assert "lane gate NO: probe exited 4" in prompt                # with the STOP it answers
    assert "helpers deliver helper-binary-001" in prompt           # and how to hand it back
    assert "data, not instructions" in prompt
    (rec,) = events(wd, "helpers.launch")
    assert rec["mode"] == "cold" and rec["helper_id"] == "helper-binary-001" and rec["bases"] == [BASE]
    # a gate NO and another base's stop on the same lane join the open helper; no second launch
    gate_rec(wd, "no")
    chain_stop(wd, cid="binary-day-05/time_trial")
    r = w.tick()
    assert r.launched == [] and len(camp.launches) == 1
    assert r.absorbed == [{"helper_id": "helper-binary-001", "base": "binary-day-05"}]
    assert H.status(wd)["helpers"][0]["bases"] == [BASE, "binary-day-05"]
    # another lane is independent
    chain_stop(wd, cid="web-1", lane="web")
    (wd / "briefs" / "web-gap.md").write_text("web brief")
    r = w.tick()
    assert [x["helper_id"] for x in r.launched] == ["helper-web-002"]


def test_stops_in_one_pass_make_one_helper_with_every_base(wd):
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp)
    gate_rec(wd, "no")
    chain_stop(wd)
    chain_stop(wd, cid="binary-day-07/mastery")
    w.tick()
    assert len(camp.launches) == 1
    assert H.status(wd)["helpers"][0]["bases"] == [BASE, "binary-day-07"]


def test_a_lane_healthy_again_in_the_same_pass_launches_nothing(wd):
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp)
    chain_stop(wd)
    gate_rec(wd, "yes")
    assert w.tick().launched == [] and camp.launches == []


def test_a_lane_with_no_warm_brief_launches_nothing_and_says_so(wd):
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp)
    chain_stop(wd, cid="web-1", lane="web")
    r = w.tick()
    assert camp.launches == [] and r.launched == []
    (err,) = events(wd, "helpers.error")
    assert "no warm brief" in err["reason"] and "web-gap.md" in err["reason"]
    assert H.load_state(wd)["next_seq"] == 1                       # no id was spent on it


def test_a_refused_cold_launch_is_a_named_error_and_a_failed_helper(wd):
    w = watcher(wd, camp=RecordingCampaign(refuse="challenge binary-day-04 is at its budget cap"))
    chain_stop(wd)
    r = w.tick()
    assert r.launched == [] and "budget cap" in r.errors[0]
    (h,) = H.status(wd)["helpers"]
    assert h["status"] == "failed" and h["outcome"] == "launch-failed"
    assert "budget cap" in events(wd, "helpers.error")[0]["reason"]
    chain_stop(wd)                                                 # the lane has no open helper now
    assert len(w.tick().errors) == 1                               # tried again, refused again, loudly


def test_a_bad_lane_name_is_an_error_not_a_path(wd):
    w = watcher(wd)
    chain_stop(wd, lane="../etc")
    r = w.tick()
    assert r.launched == [] and "cannot name a helper" in r.errors[0]


# --------------------------------------------------------------------------------------- warm hand-off

def test_a_waiting_warm_agent_is_handed_the_helper_through_the_standby_pool(wd):
    clock = Clock()
    camp = RecordingCampaign()
    w = watcher(wd, clock=clock, camp=camp)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    r = w.tick()
    assert [(x["helper_id"], x["mode"]) for x in r.launched] == [("helper-binary-001", "warm")]
    assert camp.launches == []                                     # no cold launch
    # the waiting agent's own take returns the helper at once, with its handout
    a = standby.take(wd, "hw-binary-01", timeout=1, poll=0.01, record=False, pool=standby.HELPERS_POOL,
                     lane=LANE, clock=clock, wall=clock, sleep=clock.sleep)
    assert a.challenge_id == "helper-binary-001" and a.lane == LANE
    assert "WARM-BRIEF-MARKER" in a.handout and a.claim["kind"] == "helper"
    clock.t += 3
    r = w.tick()
    assert r.taken == [{"helper_id": "helper-binary-001", "agent": "hw-binary-01", "waited": 3.0}]
    assert H.status(wd)["helpers"][0]["status"] == "taken"
    # past the hand-off wait nothing falls back: it was taken
    clock.t += 100
    assert w.tick().fallbacks == [] and camp.launches == []


def test_helper_claims_never_reach_the_challenge_pool_or_another_lane(wd):
    clock = Clock()
    w = watcher(wd, clock=clock)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    w.tick()
    nap = dict(timeout=0.05, poll=0.01, record=False, clock=clock, wall=clock)
    with pytest.raises(standby.StandbyTimeout):
        standby.take(wd, "wave-01", sleep=lambda s: setattr(clock, "t", clock.t + s), **nap)   # dispatch pool
    with pytest.raises(standby.StandbyTimeout):
        standby.take(wd, "hw-web-01", pool=standby.HELPERS_POOL, lane="web",
                     sleep=lambda s: setattr(clock, "t", clock.t + s), **nap)
    a = standby.take(wd, "hw-any-01", pool=standby.HELPERS_POOL, sleep=clock.sleep, **nap)
    assert a.challenge_id == "helper-binary-001"                   # a lane-less helper agent takes any lane


def test_a_warm_agent_for_another_lane_does_not_count(wd):
    clock = Clock()
    camp = RecordingCampaign()
    w = watcher(wd, clock=clock, camp=camp)
    warm_agent(wd, name="hw-web-01", lane="web", clock=clock)
    standby.register(wd, "wave-01", status=standby.WAITING, clock=clock)    # a challenge-pool agent
    chain_stop(wd)
    assert [x["mode"] for x in w.tick().launched] == ["cold"] and len(camp.launches) == 1
    assert not H.claim_path(wd, "helper-binary-001").exists()


def test_one_any_lane_agent_is_counted_for_one_lane_only(wd):
    clock = Clock()
    camp = RecordingCampaign()
    (wd / "briefs" / "web-gap.md").write_text("web brief")
    (wd / "briefs" / "crypto-gap.md").write_text("crypto brief")
    w = watcher(wd, clock=clock, camp=camp)
    warm_agent(wd, name="hw-any-01", lane=None, clock=clock)       # waits for any lane
    warm_agent(wd, name="hw-crypto-01", lane="crypto", clock=clock)
    chain_stop(wd, cid="web-1", lane="web")
    chain_stop(wd, cid="b-1", lane=LANE)
    chain_stop(wd, cid="c-1", lane="crypto")
    modes = {x["lane"]: x["mode"] for x in w.tick().launched}
    # the any-lane agent goes to the first lane; the second lane cannot count on it too; crypto has its own
    assert modes == {"web": "warm", LANE: "cold", "crypto": "warm"}
    assert [x["aid"] for x in camp.launches] == ["helper-binary-002"]


def test_dead_or_stale_waiting_agents_do_not_count(wd, tmp_path):
    import subprocess
    p = subprocess.Popen([sys.executable, "-c", ""])
    p.wait()
    clock = Clock()
    warm_agent(wd, name="hw-binary-01", clock=clock, pid=p.pid)                  # its pid is gone
    warm_agent(wd, name="hw-binary-02", clock=lambda: clock.t - H.PRESENCE_FRESH - 1, pid=None)   # too old
    assert H.waiting_agents(wd, LANE, now=clock()) == []
    warm_agent(wd, name="hw-binary-03", clock=lambda: clock.t - 5, pid=None)      # fresh, no pid
    assert H.waiting_agents(wd, LANE, now=clock()) == ["hw-binary-03"]


def test_a_cold_lane_is_never_handed_to_a_warm_agent(wd):
    clock = Clock()
    camp = RecordingCampaign()
    w = watcher(wd, cfg(lanes={LANE: {"mode": "cold"}}), clock=clock, camp=camp)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    assert [x["mode"] for x in w.tick().launched] == ["cold"]
    assert events(wd, "helpers.launch")[0]["why"] == "lane configured cold"


def test_an_offer_no_agent_takes_falls_back_cold_after_the_handoff_wait(wd):
    clock = Clock()
    camp = RecordingCampaign()
    w = watcher(wd, cfg(handoff_wait=20), clock=clock, camp=camp)
    warm_agent(wd, clock=clock)                                    # waiting, but it never takes
    chain_stop(wd)
    w.tick()
    clock.t += 19.9
    assert w.tick().fallbacks == [] and camp.launches == []
    clock.t += 0.1
    r = w.tick()
    assert r.fallbacks and "within 20s" in r.fallbacks[0]["reason"]
    assert [x["mode"] for x in r.launched] == ["cold"] and len(camp.launches) == 1
    assert json.loads(H.claim_path(wd, "helper-binary-001").read_text())["status"] == H.WITHDRAWN
    assert "helper-binary-001" not in standby.read_leases(wd)     # the watcher's own lease is dropped
    with pytest.raises(standby.StandbyTimeout):                    # and no warm agent can take it now
        standby.take(wd, "hw-binary-01", pool=standby.HELPERS_POOL, timeout=0.02, poll=0.01, record=False,
                     clock=clock, wall=clock, sleep=lambda s: setattr(clock, "t", clock.t + s))
    assert H.status(wd)["helpers"][0]["status"] == "running"


def test_an_agent_that_leased_before_the_deadline_wins_over_the_fallback(wd):
    clock = Clock()
    camp = RecordingCampaign()
    w = watcher(wd, clock=clock, camp=camp)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    w.tick()
    clock.t += 25
    assert standby.try_lease(wd, "helper-binary-001", "hw-binary-01", owner_pid=None, clock=clock)
    r = w.tick()
    assert r.fallbacks == [] and r.taken[0]["agent"] == "hw-binary-01" and camp.launches == []


def test_a_helper_reclaimed_by_another_agent_follows_its_new_holder(wd):
    clock = Clock()
    w = watcher(wd, clock=clock)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    w.tick()
    standby.try_lease(wd, "helper-binary-001", "hw-binary-01", owner_pid=None, clock=clock)
    w.tick()
    standby.release(wd, "operator", "helper-binary-001", force=True, clock=clock, record=False)
    standby.try_lease(wd, "helper-binary-001", "hw-binary-02", owner_pid=None, clock=clock)
    w.tick()
    h = H.status(wd)["helpers"][0]
    assert (h["status"], h["agent"]) == ("taken", "hw-binary-02")


def test_a_deliver_record_for_no_open_helper_is_reported(wd):
    w = watcher(wd)
    ledger.append("helpers.deliver", workdir=wd, helper_id="helper-binary-009", outcome="delivered")
    r = w.tick()
    assert r.delivered == [] and "helper-binary-009: unknown" in r.errors[0]


def test_a_released_helper_is_offered_again(wd):
    clock = Clock()
    w = watcher(wd, clock=clock)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    w.tick()
    standby.try_lease(wd, "helper-binary-001", "hw-binary-01", owner_pid=None, clock=clock)
    w.tick()
    standby.release(wd, "hw-binary-01", "helper-binary-001", clock=clock, record=False)
    w.tick()
    assert H.status(wd)["helpers"][0]["status"] == "offered"
    assert events(wd, "helpers.returned")


def test_a_cold_launch_names_the_challenge_it_is_metered_against(wd):
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp)
    gate_rec(wd, "no")                                             # a gate NO with no chain base
    r = w.tick()
    assert [x["bases"] for x in r.launched] == [[]]
    assert camp.launches[0]["challenge"] is None
    assert events(wd, "helpers.launch")[0]["metered"] is None      # unmetered, and says so
    (wd / "briefs" / "web-gap.md").write_text("web brief")
    chain_stop(wd, cid="web-day-02/mastery", lane="web")
    w.tick()
    assert camp.launches[1]["challenge"] == "web-day-02"
    assert events(wd, "helpers.launch")[1]["metered"] == "web-day-02"
    assert H.status(wd)["helpers"][1]["metered"] == "web-day-02"


def _taken_with_ttl(wd, clock, ttl=60.0):
    w = watcher(wd, cfg(lease_ttl=ttl), clock=clock)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    w.tick()
    a = standby.take(wd, "hw-binary-01", timeout=1, poll=0.01, record=False, pool=standby.HELPERS_POOL,
                     lane=LANE, clock=clock, wall=clock, sleep=clock.sleep, owner_pid=None, ttl=ttl)
    assert a.challenge_id == "helper-binary-001"
    assert w.tick().taken
    return w


def test_a_warm_helper_whose_lease_lapses_is_reclaimed_and_offered_again(wd):
    clock = Clock()
    w = _taken_with_ttl(wd, clock)
    handout = Path(H.status(wd)["helpers"][0]["handout"]).read_text()
    assert "standby renew --agent <your agent name> helper-binary-001" in handout and "every 20s" in handout
    clock.t += 59
    r = w.tick()
    assert r.returned == [] and H.status(wd)["helpers"][0]["status"] == "taken"   # still inside its ttl
    clock.t += 1
    r = w.tick()
    assert r.returned == [{"helper_id": "helper-binary-001", "agent": "hw-binary-01",
                           "reason": "lease lapsed (not renewed, or its owner pid is gone)"}]
    h = H.status(wd)["helpers"][0]
    assert (h["status"], h["agent"], h["offered_at"]) == ("offered", None, round(clock.t, 3))
    assert "helper-binary-001" not in standby.read_leases(wd)      # the watcher's reclaim lease is dropped
    (rec,) = events(wd, "helpers.returned")
    assert rec["agent"] == "hw-binary-01" and "lapsed" in rec["reason"]
    # another warm agent can take it now
    a = standby.take(wd, "hw-binary-02", timeout=1, poll=0.01, record=False, pool=standby.HELPERS_POOL,
                     clock=clock, wall=clock, sleep=clock.sleep)
    assert a.challenge_id == "helper-binary-001"
    assert w.tick().taken[0]["agent"] == "hw-binary-02"


def test_a_renewed_lease_is_never_reclaimed(wd):
    clock = Clock()
    w = _taken_with_ttl(wd, clock)
    for _ in range(4):
        clock.t += 40
        assert standby.renew(wd, "hw-binary-01", "helper-binary-001", clock=clock) is not None
        assert w.tick().returned == []
    h = H.status(wd)["helpers"][0]
    assert (h["status"], h["agent"]) == ("taken", "hw-binary-01")
    assert standby.read_leases(wd)["helper-binary-001"]["agent"] == "hw-binary-01"


def test_a_renewal_that_wins_the_reclaim_race_keeps_the_helper_taken(wd, monkeypatch):
    # The watcher read a lapsed lease, but the agent renews before the reclaim takes the lock: try_lease
    # re-checks under the lock, finds a live lease and returns None. Nothing may be reported or changed.
    clock = Clock()
    w = _taken_with_ttl(wd, clock)
    clock.t += 61                                                  # lapsed when the watcher reads it
    real = standby.try_lease
    raced = []

    def renew_then_lease(*a, **kw):
        raced.append(standby.renew(wd, "hw-binary-01", "helper-binary-001", clock=clock))
        return real(*a, **kw)

    monkeypatch.setattr(standby, "try_lease", renew_then_lease)
    r = w.tick()
    assert raced and raced[0] is not None                          # the race really happened
    assert r.returned == [] and r.errors == []
    h = H.status(wd)["helpers"][0]
    assert (h["status"], h["agent"]) == ("taken", "hw-binary-01")
    assert standby.read_leases(wd)["helper-binary-001"]["agent"] == "hw-binary-01"
    assert events(wd, "helpers.returned") == []


def test_public_lease_wrappers_match_the_lease_rules(wd):
    clock = Clock()
    lease = standby.try_lease(wd, "c-1", "agent-a", owner_pid=None, ttl=10.0, clock=clock)
    assert standby.lease_is_stale(lease, clock=clock) is False
    clock.t += 10
    assert standby.lease_is_stale(lease, clock=clock) is True
    held = standby.try_lease(wd, "c-2", "agent-a", owner_pid=None, clock=clock)
    clock.t += 100_000
    assert standby.lease_is_stale(held, clock=clock) is False      # neither pid nor ttl: never stale
    assert standby.unlease(wd, "c-1", "agent-b") is None           # not the holder: untouched
    assert "c-1" in standby.read_leases(wd)
    assert standby.unlease(wd, "c-1", "agent-a")["agent"] == "agent-a"
    assert "c-1" not in standby.read_leases(wd)
    assert standby.unlease(wd, "c-2", None)["agent"] == "agent-a"   # None: whoever holds it
    assert standby.read_leases(wd) == {}


def test_a_held_lease_is_never_reclaimed(wd):
    clock = Clock()
    w = watcher(wd, clock=clock)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    w.tick()
    standby.try_lease(wd, "helper-binary-001", "hw-binary-01", owner_pid=None, clock=clock)   # no pid, no ttl
    w.tick()
    clock.t += 100_000
    assert w.tick().returned == [] and H.status(wd)["helpers"][0]["status"] == "taken"


# --------------------------------------------------------------------------------------- delivery and resume

def test_delivery_is_integrated_and_the_chain_resumes_for_every_base(wd):
    clock = Clock()
    w = watcher(wd, clock=clock)
    warm_agent(wd, clock=clock)
    chain_stop(wd)
    chain_stop(wd, cid="binary-day-05/mastery")
    w.tick()
    standby.take(wd, "hw-binary-01", timeout=1, poll=0.01, record=False, pool=standby.HELPERS_POOL,
                 clock=clock, wall=clock, sleep=clock.sleep)
    w.tick()
    H.deliver(wd, "helper-binary-001", note="folded the fix")
    r = w.tick()
    assert r.delivered == [{"helper_id": "helper-binary-001", "outcome": "delivered", "by": "deliver"}]
    assert w.resumed == [(BASE, LANE), ("binary-day-05", LANE)]
    assert [(x["base"], x["action"]) for x in r.resumed] == [(BASE, "start"), ("binary-day-05", "start")]
    assert [x["challenge_id"] for x in events(wd, "helpers.resume")] == [BASE, "binary-day-05"]
    assert json.loads(H.claim_path(wd, "helper-binary-001").read_text())["status"] == "delivered"
    assert "helper-binary-001" not in standby.read_leases(wd)
    assert H.status(wd)["open"] == []
    with pytest.raises(H.HelperError, match="already delivered"):
        H.deliver(wd, "helper-binary-001")


def test_a_failed_delivery_closes_the_helper_without_resuming(wd):
    w = watcher(wd)
    chain_stop(wd)
    w.tick()
    H.deliver(wd, "helper-binary-001", outcome="failed", note="cannot fold it")
    r = w.tick()
    assert r.delivered[0]["outcome"] == "failed" and w.resumed == [] and r.resumed == []


def test_deliver_refuses_unknown_and_bad_requests(wd):
    with pytest.raises(H.HelperError, match="no helper"):
        H.deliver(wd, "helper-binary-001")
    with pytest.raises(H.HelperError, match="bad helper id"):
        H.deliver(wd, "../x")
    w = watcher(wd)
    chain_stop(wd)
    w.tick()
    with pytest.raises(H.HelperError, match="outcome"):
        H.deliver(wd, "helper-binary-001", outcome="maybe")


def test_a_cold_helper_that_ends_is_integrated_from_the_campaign_state(wd):
    camp = RecordingCampaign()
    w = watcher(wd, camp=camp)
    chain_stop(wd)
    chain_stop(wd, cid="web-1", lane="web")
    (wd / "briefs" / "web-gap.md").write_text("web brief")
    w.tick()
    assert w.tick().delivered == []                                # still running
    camp.agents["helper-binary-001"].update(status="done", rc=0)
    camp.agents["helper-web-002"].update(status="lost", lost_reason="supervisor gone")
    r = w.tick()
    assert sorted((x["helper_id"], x["outcome"], x["by"]) for x in r.delivered) == [
        ("helper-binary-001", "delivered", "campaign"), ("helper-web-002", "failed", "campaign")]
    assert w.resumed == [(BASE, LANE)]                             # only the delivered one resumes


def test_a_resume_that_raises_is_reported_not_fatal(wd):
    def boom(base, lane):
        raise RuntimeError("gate blew up")
    w = watcher(wd, resume=boom)
    chain_stop(wd)
    w.tick()
    H.deliver(wd, "helper-binary-001")
    r = w.tick()
    assert r.delivered and "gate blew up" in r.errors[0]
    assert H.status(wd)["helpers"][0]["status"] == "delivered"


def test_the_per_lane_cap_holds_until_the_lane_is_healthy_and_names_stay_unique(wd):
    camp = RecordingCampaign()
    w = watcher(wd, cfg(max_per_lane=2), camp=camp)
    for n in (1, 2):
        chain_stop(wd)
        w.tick()
        H.deliver(wd, f"helper-binary-00{n}", outcome="failed")
        w.tick()
    chain_stop(wd)
    r = w.tick()
    assert r.launched == [] and r.capped == [{"lane": LANE, "launched": 2}]
    chain_stop(wd)
    assert w.tick().capped == []                                   # recorded once
    assert len(events(wd, "helpers.capped")) == 1
    # a chain `done` (no lane gate ran) is not a healthy signal: the lane stays capped
    ledger.append("adapt.chain", workdir=wd, challenge_id="other-day-09", lane=LANE, action="done", reason="x")
    chain_stop(wd)
    r = w.tick()
    assert r.launched == [] and r.capped == []
    gate_rec(wd, "yes")                                            # healthy again: the count resets
    chain_stop(wd)
    assert [x["helper_id"] for x in w.tick().launched] == ["helper-binary-003"]
    H.deliver(wd, "helper-binary-003", outcome="failed")
    w.tick()
    chain_stop(wd)
    assert [x["helper_id"] for x in w.tick().launched] == ["helper-binary-004"]
    H.deliver(wd, "helper-binary-004", outcome="failed")
    w.tick()
    chain_stop(wd)                                                 # the cap again, after the reset
    r = w.tick()
    assert r.launched == [] and r.capped == [{"lane": LANE, "launched": 2}]
    assert len(events(wd, "helpers.capped")) == 2                  # a second cap cycle is recorded too
    ids = [x["aid"] for x in camp.launches]
    assert ids == ["helper-binary-001", "helper-binary-002", "helper-binary-003", "helper-binary-004"]
    for i in ids:
        standby.safe_agent(i)
        campaign._check_id("agent", i)


def test_the_cursor_survives_a_restart(wd):
    camp = RecordingCampaign()
    watcher(wd, camp=camp).tick()
    chain_stop(wd)
    watcher(wd, camp=camp).tick()
    watcher(wd, camp=camp).tick()                                  # a new watcher: same state, no repeat
    assert len(camp.launches) == 1


# --------------------------------------------------------------------------------------- arm: warm where predicted

def _report(lane, gaps=()):
    return {"lane": lane, "gaps": [{"kind": "wrong", "qid": q} for q in gaps]}


def test_arm_warms_only_the_lanes_the_forecast_predicts_or_config_forces(wd):
    q = {"questions": [{"id": "a", "kind": "str"}]}
    plans = forecast.plan([_report("binary", ["q1"]), _report("metadata"), _report("web"), _report("script")],
                          {"binary": (q, q), "metadata": (q, q), "web": (q, q), "script": None})
    c = cfg(lanes={"web": {"mode": "warm", "warm_agents": 2}, "script": {"mode": "cold"},
                   "mobile": {"mode": "auto"}})
    plan = H.arm(plans, c, workdir=wd)
    by = {w.lane: w for w in plan.lanes}
    assert by["binary"].warm and "predicts" in by["binary"].reason          # open gap: predicted
    assert not by["metadata"].warm                                         # green, unchanged: cold
    assert by["web"].warm and len(by["web"].agents) == 2                   # config warm
    assert not by["script"].warm                                           # config cold beats the forecast
    assert not by["mobile"].warm and "not in the forecast" in by["mobile"].reason
    assert [a["agent"] for a in plan.warm_agents] == ["hw-binary-01", "hw-web-01", "hw-web-02"]
    assert plan.missing_briefs == ["metadata", "mobile", "script", "web"]
    argv = by["binary"].agents[0]["argv"]
    assert argv[:3] == ["python", "-m", "ctf"]
    # the argv is a real `ctf standby take` the CLI accepts, on the helpers pool and this lane
    import argparse
    from ctf.cli import standby as standby_cli
    sp = argparse.ArgumentParser()
    standby_cli.add_arguments(sp)
    assert argv[3] == "standby"
    ns = sp.parse_args(argv[4:])
    assert (ns.action, ns.pool, ns.lane, ns.agent) == ("take", "helpers", "binary", "hw-binary-01")
    assert ns.ttl == H.DEFAULT_LEASE_TTL                                   # a warm helper's lease can lapse
    (rec,) = events(wd, "helpers.arm")
    assert rec["warm"] == ["binary", "web"] and rec["agents"] == 3


def test_arm_gives_warm_agents_the_configured_lease_ttl_and_timeout(wd):
    # The handout tells a helper to renew every lease_ttl/3 s, so the lease it takes must carry that ttl.
    import argparse
    from ctf.cli import standby as standby_cli
    c = cfg(lease_ttl=60, warm_timeout=123, lanes={"binary": {"mode": "warm"}})
    (agent,) = H.arm([], c, workdir=wd, record=False).warm_agents
    sp = argparse.ArgumentParser()
    standby_cli.add_arguments(sp)
    ns = sp.parse_args(agent["argv"][4:])
    assert ns.ttl == 60 and ns.ttl != H.DEFAULT_LEASE_TTL
    assert ns.timeout == 123


def test_arm_takes_lookahead_plan_json_and_rejects_junk(wd):
    plan = H.arm([{"lane": "binary", "agent": True, "reasons": ["1 open gap(s) (wrong)"]}], cfg(), workdir=wd,
                 record=False)
    assert plan.lanes[0].warm and plan.missing_briefs == []
    with pytest.raises(H.HelperError, match="boolean"):
        H.arm([{"lane": "binary"}], cfg(), workdir=wd, record=False)


# --------------------------------------------------------------------------------------- CLI

def _cli(*argv) -> int:
    return cli.main(list(argv))


def _write_cfg(wd, extra="") -> Path:
    p = wd / "helpers.toml"
    p.write_text('[helpers]\nlauncher = ["/bin/true"]\n' + extra)
    return p


def test_cli_deliver_status_check_and_arm(wd, capsys):
    _write_cfg(wd, '[lane.binary]\nmode = "warm"\n[lane.web]\nmode = "auto"\n')
    assert _cli("helpers", "check", "--workdir", str(wd)) == 1                 # web has no brief
    assert "MISS web" in capsys.readouterr().out
    assert _cli("helpers", "deliver", "helper-binary-001", "--workdir", str(wd)) == 2
    w = watcher(wd)
    chain_stop(wd)
    w.tick()
    assert _cli("helpers", "status", "--workdir", str(wd), "--json") == 0
    st = json.loads(capsys.readouterr().out)
    assert st["open"] == ["helper-binary-001"]
    assert _cli("helpers", "deliver", "helper-binary-001", "--workdir", str(wd), "--note", "done") == 0
    assert events(wd, "helpers.deliver")[0]["note"] == "done"
    lp = wd / "plan.json"
    lp.write_text(json.dumps([{"lane": "web", "agent": False, "reasons": ["gate green"]}]))
    assert _cli("helpers", "arm", "--lane-plan", str(lp), "--workdir", str(wd), "--no-record") == 1
    out = capsys.readouterr().out
    assert "WARM binary" in out and "cold web" in out and "hw-binary-01" in out
    assert _cli("helpers", "arm", "--matrix", str(lp), "--workdir", str(wd)) == 2   # --matrix needs --report


def test_cli_arm_from_a_matrix_reads_each_lanes_previous_and_base(wd, tmp_path, capsys):
    import lookahead_build as LB
    _write_cfg(wd)
    (wd / "briefs" / "web-gap.md").write_text("web brief")
    reader = LB.write_reader(tmp_path)
    m = tmp_path / "matrix"
    m.mkdir()
    (m / "same.json").write_text(json.dumps([LB.q("a")]))
    (m / "grown.json").write_text(json.dumps([LB.q("a"), LB.q("b")]))
    LB.matrix(tmp_path, {"binary": {"reader": reader, "base": "same.json", "previous": "same.json"},
                         "web": {"reader": reader, "base": "grown.json", "previous": "same.json"}})
    rep = tmp_path / "report.json"
    rep.write_text(json.dumps([{"lane": "binary", "gaps": []}, {"lane": "web", "gaps": []}]))
    assert _cli("helpers", "arm", "--matrix", str(m), "--report", str(rep), "--workdir", str(wd),
                "--no-record") == 0
    out = capsys.readouterr().out
    # both gates green: only the lane whose base grew a new id gets a warm agent
    assert "cold binary: auto: forecast predicts nothing new" in out
    assert "WARM web: auto: forecast predicts" in out and "new shape: 1 changed id(s)" in out
    assert "hw-web-01" in out and "hw-binary-01" not in out
    (m / "grown.json").unlink()
    assert _cli("helpers", "arm", "--matrix", str(m), "--report", str(rep), "--workdir", str(wd)) == 2
    assert "grown.json" in capsys.readouterr().err


def test_cli_watch_once_launches_and_standby_cli_takes_from_the_helpers_pool(wd, capsys, monkeypatch):
    _write_cfg(wd)
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    warm_agent(wd)
    chain_stop(wd)
    assert _cli("helpers", "watch", "--once", "--from-start", "--workdir", str(wd)) == 0
    assert "LAUNCH  helper-binary-001 [binary] warm" in capsys.readouterr().out
    assert _cli("standby", "--event", "csctf", "take", "--agent", "hw-binary-01", "--pool", "helpers",
                "--lane", LANE, "--timeout", "2", "--poll", "0.01") == 0
    out = capsys.readouterr().out
    assert "claimed helper-binary-001 [binary]" in out and "WARM-BRIEF-MARKER" in out
    assert standby.read_presence(wd)["hw-binary-01"]["pool"] == "helpers"


# --------------------------------------------------------------------------------------- real campaign launches

STUB = """#!{python}
import os, sys
from pathlib import Path
Path(os.environ["STUB_OUT"]).write_text(sys.stdin.read())
sys.exit(0)
"""

# Rule 16: the real campaign supervisor is a detached process no injected clock can drive, so this wait is
# genuinely wall-clock. It is a ceiling for the failure case only; what is asserted is that the agent ends.
WALL_CLOCK_CEILING = 180.0


def _wait(pred, what):
    end = time.time() + WALL_CLOCK_CEILING
    while time.time() < end:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture
def real(wd, tmp_path, monkeypatch):
    tools = tmp_path / "launchers"
    tools.mkdir()
    stub = tools / "fake_helper"
    stub.write_text(STUB.format(python=sys.executable))
    stub.chmod(0o755)
    out = tmp_path / "stub-stdin.md"
    monkeypatch.setenv("STUB_OUT", str(out))
    monkeypatch.setenv(campaign.LAUNCHERS_ENV, str(stub))
    monkeypatch.setattr(campaign, "SUPERVISOR_START_WAIT", WALL_CLOCK_CEILING)
    yield {"stub": stub, "out": out}
    for rec in campaign.Campaign(wd).load()["agents"].values():
        pid = rec.get("supervisor_pid")
        if pid and rec["status"] == "running":
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def test_real_cold_launch_hands_the_stub_the_handout_and_its_end_resumes(wd, real):
    c = cfg(launcher=[str(real["stub"])], event="csctf")
    w = H.Watcher(wd, c, clock=Clock(), resume=lambda b, l: Step("start"), start="beginning")
    chain_stop(wd)
    r = w.tick()
    assert [x["mode"] for x in r.launched] == ["cold"], r.errors
    camp = campaign.Campaign(wd)
    _wait(lambda: camp.load()["agents"]["helper-binary-001"]["status"] in ("done", "failed"), "the stub to end")
    assert camp.load()["agents"]["helper-binary-001"]["status"] == "done"
    stdin = real["out"].read_text()
    assert "WARM-BRIEF-MARKER" in stdin and "helpers deliver helper-binary-001" in stdin
    r = w.tick()
    assert r.delivered == [{"helper_id": "helper-binary-001", "outcome": "delivered", "by": "campaign"}]
    assert r.resumed[0]["base"] == BASE


def test_real_campaign_refuses_an_unfenced_launcher(wd, real):
    w = H.Watcher(wd, cfg(launcher=["/bin/echo"], event="csctf"), clock=Clock(), start="beginning")
    chain_stop(wd)
    r = w.tick()
    assert r.launched == [] and "not allowed" in r.errors[0]
    assert campaign.Campaign(wd).load()["agents"] == {}


# --------------------------------------------------------------------------------------- the real chain

@pytest.mark.needs_tool("git")
def test_a_real_chain_stop_launches_a_helper_and_its_delivery_resumes_the_chain(wd, tmp_path, monkeypatch):
    import adapt_repo as AR
    from ctf.adapt import chain as C
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path)
    gate_kw = dict(load=0.0, cpus=1, guard="hook")
    (wd / "briefs" / "probe-gap.md").write_text("probe lane brief")
    base = "binary-reverse-engineering-day-04-go-runtime-fingerprints"
    ledger.append("platform.submit", workdir=wd, event_slug="huntress", challenge_id=base, status="correct",
                  judged=True, guess=False, confirmed=False, provenance="test", post_stop=False)
    camp = RecordingCampaign()
    w = H.Watcher(wd, cfg(), clock=Clock(), campaign=camp, plan_kw={"root": root, "gate_kw": gate_kw},
                  start="beginning")
    monkeypatch.setenv("ADAPT_PROBE_EXIT", "4")                    # the lane is broken
    assert C.plan(base, "probe", workdir=wd, root=root, gate_kw=gate_kw).action == "stop"
    r = w.tick()
    assert [(x["helper_id"], x["bases"]) for x in r.launched] == [("helper-probe-001", [base])]
    monkeypatch.delenv("ADAPT_PROBE_EXIT")                          # the helper's fix
    H.deliver(wd, "helper-probe-001")
    r = w.tick()                                                   # integrate + the real chain.plan
    assert [(x["base"], x["action"]) for x in r.resumed] == [(base, "start")]
    w.tick()                                                       # the re-plan's gate yes resets the lane
    assert H.status(wd)["lanes"]["probe"]["launched"] == 0
