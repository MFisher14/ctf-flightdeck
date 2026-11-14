"""Instances on demand in a run: the plan, and the runner against a real deck and a fake
platform client (no network: the client's own wire is tests/test_instances.py's)."""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig
from ctf_flightdeck.instancerun import RENEW_BEFORE, RETRY_FULL, WAITS, InstanceRunner, Need, on_demand, plan
from ctf_flightdeck.platform.instances import Instance, InstanceError, InstanceRefused

from test_deck import FLAG_FORMAT, MODELS, Clock, RecordingDriver, RecordingVerifier


def test_the_plan_stops_what_nobody_works_first_and_starts_in_line_up_to_the_cap():
    needs = [
        Need("solved", wanted=False, running=True),
        Need("working", wanted=True, running=True, place=-1),
        Need("next", wanted=True, running=False, place=0),
        Need("later", wanted=True, running=False, place=1),
        Need("last", wanted=True, running=False, place=2),
        Need("parked", wanted=False, running=False),
    ]
    assert plan(needs, 3) == plan(list(reversed(needs)), 3)  # the order given does not matter
    todo = plan(needs, 3)
    assert todo.stop == ("solved",) and todo.start == ("next", "later") and todo.waiting == ("last",)
    assert plan(needs, 1).start == () and plan(needs, 1).waiting == ("next", "later", "last")  # never evicts the one worked


def test_an_adopted_instance_is_never_stopped_and_still_takes_a_slot():
    needs = [Need("theirs", wanted=False, running=True, ours=False), Need("mine", wanted=True, running=False)]
    assert plan(needs, 1) == plan(needs, 1) and plan(needs, 1).stop == () and plan(needs, 1).start == ()
    assert plan(needs, 2).start == ("mine",)
    with pytest.raises(ValueError, match="max_running"):
        plan(needs, 0)


def test_on_demand_marks_the_challenges_of_the_events_types():
    plain, boxed, marked = Challenge("a", "A", "misc", 1), Challenge("b", "B", "web", 1, platform_type="container"), Challenge("c", "C", "pwn", 1, on_demand=True)
    assert [c.id for c in on_demand([plain, boxed, marked], ["container"])] == ["b", "c"]
    assert not plain.on_demand and boxed.on_demand


class Platform:
    """A fake InstanceClient: what runs, what was asked, and what to refuse."""

    def __init__(self, cap: int = 3, seconds: float | None = None, clock=None) -> None:
        self.up: dict[str, int] = {}
        self.calls: list[tuple[str, str]] = []
        self.cap, self.seconds, self.clock = cap, seconds, clock
        self.theirs = 0  # slots a teammate holds
        self.fail: dict[str, Exception] = {}  # action -> raised once
        self.port = 31000

    def _instance(self, cid: str) -> Instance:
        return Instance(cid, "box.example.test", self.up[cid], None, self.clock() + self.seconds if self.seconds else None)

    def _maybe(self, action: str) -> None:
        if action in self.fail:
            raise self.fail.pop(action)

    def status(self, cid):
        self.calls.append(("status", cid))
        return self._instance(cid) if cid in self.up else None

    def start(self, cid):
        self.calls.append(("start", cid))
        self._maybe("start")
        if len(self.up) + self.theirs >= self.cap:
            raise InstanceRefused(f"the platform refused instance start: Max containers ({self.cap}) reached", full=True)
        self.up[cid] = self.port
        self.port += 1
        return self._instance(cid)

    def renew(self, cid):
        self.calls.append(("renew", cid))
        self._maybe("renew")
        return None

    def stop(self, cid):
        self.calls.append(("stop", cid))
        self._maybe("stop")
        del self.up[cid]


def lab(n=3, max_lanes=4, cap=3, seconds=None, categories=None):
    clock = Clock()
    deck = Deck(DeckConfig(event="t", flag_format=FLAG_FORMAT, models=MODELS, max_lanes=max_lanes), RecordingDriver(), clock, RecordingVerifier())
    platform = Platform(cap, seconds, clock=clock.now)
    urls, driver_urls = {}, {}
    runner = InstanceRunner(deck, platform, max_running=cap, urls=[urls, driver_urls], clock=clock.now)
    challenges = [Challenge(f"c{i}", f"Chall {i}", (categories or ["web"] * n)[i], 100, on_demand=True) for i in range(n)]
    challenges.append(Challenge("plain", "Plain", "misc", 100))
    runner.hold(challenges)
    deck.release(challenges, [QueueEntry(c.id, "small") for c in challenges])
    return deck, runner, platform, urls, clock


def step(runner):
    return asyncio.run(runner.step())


def test_no_lane_starts_on_an_on_demand_challenge_before_its_instance_and_the_rest_go_on():
    deck, runner, platform, urls, _ = lab(n=2, categories=["web", "pwn"])
    assert [lane.challenge_id for lane in deck.active_lanes()] == ["plain"]  # passed over, not waited behind
    assert deck.waits == {"c0": WAITS, "c1": WAITS}
    step(runner)
    assert sorted(lane.challenge_id for lane in deck.active_lanes()) == ["c0", "c1", "plain"] and deck.waits == {}
    assert urls == {"c0": ("http://box.example.test:31000",), "c1": ("tcp://box.example.test:31001",)}  # web is http, the rest tcp
    assert runner.urls[1] == urls and deck.challenges["c0"].live
    assert platform.calls == [("status", "c0"), ("start", "c0"), ("status", "c1"), ("start", "c1")]
    started = [e for e in deck.events if e.data.get("source") == "instances"]
    assert "the instance of Chall 0 started: http://box.example.test:31000" in started[0].text


def test_the_cap_holds_and_a_solve_frees_its_slot_for_the_next_in_line():
    deck, runner, platform, urls, _ = lab(n=3, cap=2)
    step(runner)
    assert sorted(platform.up) == ["c0", "c1"] and "c2" in deck.waits
    lane = deck.lanes_on("c0")[0]
    deck.report(lane.id, TurnReport(flag="t{c0}"))  # RecordingVerifier: right
    assert deck.apply(iv.Approve(lane.id)).ok and deck.challenges["c0"].closed
    step(runner)
    assert sorted(platform.up) == ["c1", "c2"] and urls["c0"] == () and not deck.challenges["c0"].live
    assert [call for call in platform.calls if call[0] == "stop"] == [("stop", "c0")]
    assert [lane.challenge_id for lane in deck.active_lanes() if lane.challenge_id == "c2"] == ["c2"]


def test_a_parked_challenges_instance_is_stopped_and_started_again_when_it_is_queued():
    deck, runner, platform, urls, _ = lab(n=1)
    step(runner)
    lane = deck.lanes_on("c0")[0]
    assert deck.apply(iv.Kill(lane.id, requeue=False)).ok  # parked: nobody works it
    step(runner)
    assert platform.up == {} and deck.waits == {"c0": WAITS}
    assert deck.apply(iv.Queue("c0")).ok and deck.lanes_on("c0") == []  # queued, and waiting: no new lane yet
    step(runner)
    assert list(platform.up) == ["c0"] and len(deck.lanes_on("c0")) == 1


def test_a_teams_cap_reached_is_said_once_and_asked_again_later_and_takes_no_slot():
    deck, runner, platform, urls, clock = lab(n=1, cap=1)
    platform.theirs = 1  # a teammate's instance holds the only slot
    step(runner)
    step(runner)
    full = [e for e in deck.events if e.data.get("full")]
    assert len(full) == 1 and "the platform's cap on running instances is reached" in full[0].text
    assert runner.running == {} and "c0" in deck.waits and len([c for c in platform.calls if c[0] == "start"]) == 1  # not asked again yet
    platform.theirs = 0
    clock.t += RETRY_FULL + 1
    step(runner)
    assert list(runner.running) == ["c0"] and deck.waits == {}


def test_an_instance_already_running_is_adopted_and_never_stopped_by_this_run():
    deck, runner, platform, urls, _ = lab(n=1)
    platform.up["c0"] = 40000  # a teammate started it
    step(runner)
    assert runner.adopted == {"c0"} and ("start", "c0") not in platform.calls
    assert urls["c0"] == ("http://box.example.test:40000",)
    assert "was already running" in [e for e in deck.events if e.data.get("adopted")][0].text
    lane = deck.lanes_on("c0")[0]
    assert deck.apply(iv.Kill(lane.id, requeue=False)).ok
    step(runner)
    assert platform.up == {"c0": 40000} and ("stop", "c0") not in platform.calls
    assert asyncio.run(runner.close()) == [] and platform.up == {"c0": 40000}


def test_a_start_that_fails_is_said_once_with_the_platforms_words_and_tried_again_after_a_wait():
    deck, runner, platform, urls, clock = lab(n=1)
    platform.fail["start"] = InstanceError("the platform refused instance start for challenge 1: image build failed")
    step(runner)
    step(runner)
    warned = [e.text for e in deck.events if e.data.get("source") == "instances"]
    assert len(warned) == 1 and "could not start the instance of Chall 0" in warned[0] and "image build failed" in warned[0]
    assert len([c for c in platform.calls if c[0] == "start"]) == 1 and "c0" in deck.waits
    clock.t += 31
    step(runner)
    assert list(platform.up) == ["c0"] and deck.waits == {}


def test_an_instance_is_renewed_before_its_end_while_its_challenge_is_worked():
    deck, runner, platform, urls, clock = lab(n=1, seconds=1800)
    step(runner)
    step(runner)
    assert ("renew", "c0") not in platform.calls
    clock.t += 1800 - RENEW_BEFORE + 1
    step(runner)
    assert platform.calls[-2:] == [("renew", "c0"), ("status", "c0")]
    assert runner.running["c0"].expires_at == pytest.approx(clock.t + 1800)


def test_an_instance_that_ended_is_started_again_and_a_new_address_is_told_to_its_lanes_and_the_player():
    deck, runner, platform, urls, clock = lab(n=1, seconds=600)
    step(runner)
    platform.fail["renew"] = InstanceRefused("the platform refused instance renew: not allowed")
    clock.t += 400
    step(runner)
    assert any("could not renew the instance of Chall 0" in e.text for e in deck.events)
    del platform.up["c0"]  # the platform ended it
    clock.t += 300
    step(runner)
    assert urls["c0"] == ("http://box.example.test:31001",) and runner.adopted == set()
    lane = deck.lanes_on("c0")[0]
    assert any("this challenge's instance was started again and is now at http://box.example.test:31001" in a.text for a in lane.actions)
    assert any(e.data.get("moved") and "kill such a lane and queue the challenge again" in e.text for e in deck.events)


def test_close_stops_what_this_run_started_and_says_what_it_could_not():
    deck, runner, platform, urls, _ = lab(n=2)
    step(runner)
    platform.fail["stop"] = InstanceError("no answer from the platform")
    left = asyncio.run(runner.close())
    assert len(left) == 1 and "may still run on the platform: no answer from the platform" in left[0]
    assert len(platform.up) == 1 and runner.running == {}


# ---------------------------------------------------------------- in a real run, against the fake CTFd


def test_a_run_starts_an_instance_before_its_lane_names_it_in_the_brief_and_stops_it_on_the_solve(tmp_path, monkeypatch):
    from ctf_flightdeck.core.model import LaneState
    from ctf_flightdeck.run import RunOptions, prepare_run

    from fake_ctfd import FakeChallenge, FakeCTFd
    from fake_model import FakeModelServer
    from test_event_run import TOKEN_VAR, Model, config, event, play, submit, wait_for
    from fake_ctfd import TOKEN

    monkeypatch.setenv(TOKEN_VAR, TOKEN)
    board = [FakeChallenge(1, "Boxed", category="Web", value=50, flag="test{boxed}", type="container"),
             FakeChallenge(2, "Second Box", category="Pwn", value=60, flag="test{second}", type="container"),
             FakeChallenge(3, "Plain", category="Misc", value=10, flag="test{plain}")]
    model = Model({"Boxed": [submit("test{boxed}")], "Second Box": [submit("test{second}")]})
    with FakeCTFd(board) as fake, FakeModelServer(responder=model) as server:
        fake.container_cap = 1  # one at a time: the second waits for the first's slot
        profile = event(tmp_path, url=fake.base_url, submit="auto")
        profile.write_text(profile.read_text() + '\n[instances]\nplugin = "docker_per_team"\ntypes = ["container"]\nmax_running = 1\n')
        run = prepare_run(RunOptions(board=tmp_path / "board", event=profile, config=config(tmp_path, server.base_url, max_lanes=3)))
        run.instances.every = 0.05
        assert any(note.startswith("instances: flightdeck starts a challenge's instance on the platform before a lane works it (2 on the board now)")
                   for note in run.notes())

        async def body(run):
            await wait_for(lambda: all(lane.state is LaneState.SOLVED for lane in run.deck.lanes.values()
                                       if lane.challenge_id in ("boxed", "second-box")) and len(run.deck.lanes) == 3
                           and run.deck.challenges["second-box"].closed, "both boxed challenges solved, one after the other")
            await wait_for(lambda: fake.containers == {}, "the last instance stopped after its solve")

        play(run, body)
    briefs = {re_name(r): r["json"]["messages"][1]["content"] for r in server.chats()}
    assert "\nLive instance: http://instances.example.test:31000\n" in briefs["Boxed"]
    assert "\nLive instance: tcp://instances.example.test:31001 (nc instances.example.test 31001)\n" in briefs["Second Box"]
    assert "\nLive instance: none\n" in briefs["Plain"]
    asked = [(r.path.rsplit("/", 1)[1], r.json["chal_id"]) for r in fake.requests if r.path.startswith("/containers/api/")]
    assert asked.index(("stop", 1)) < asked.index(("request", 2))  # the slot was freed first
    assert ("request", 3) not in asked and fake.containers == {}


def re_name(record: dict) -> str:
    import re

    return re.search(r"^Challenge: (.+?) \(", record["json"]["messages"][1]["content"], re.MULTILINE).group(1)


def test_a_run_whose_instance_policy_is_not_auto_starts_none_and_says_why(tmp_path, monkeypatch):
    from ctf_flightdeck.run import RunOptions, prepare_run

    from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd
    from fake_model import FakeModelServer
    from test_event_run import TOKEN_VAR, config, event

    monkeypatch.setenv(TOKEN_VAR, TOKEN)
    with FakeCTFd([FakeChallenge(1, "Boxed", category="Web", type="container")]) as fake, FakeModelServer() as server:
        profile = event(tmp_path, url=fake.base_url, live="confirm")
        profile.write_text(profile.read_text() + '\n[instances]\nplugin = "docker_per_team"\ntypes = ["container"]\n')
        run = prepare_run(RunOptions(board=tmp_path / "board", event=profile, config=config(tmp_path, server.base_url)))
        try:
            assert run.instances is None and run.deck is not None
            (note,) = [n for n in run.notes() if n.startswith("instances:")]
            assert "1 challenge on this board need an instance" in note and 'the instance policy is "confirm"' in note
        finally:
            run.close()
    assert not any(r.path.startswith("/containers/api/") for r in fake.requests)
