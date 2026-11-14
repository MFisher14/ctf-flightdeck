"""Instances on demand in a run: the plan, and the runner against a real deck and a fake
platform client (no network: the client's own wire is tests/test_instances.py's)."""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig
from ctf_flightdeck.instancerun import CLAIM_FOR, RENEW_BEFORE, RETRY_FULL, RETRY_MOST, WAITS, InstanceRunner, Need, on_demand, plan
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
        self.unanswered: set[str] = set()  # challenges whose next start is done, and whose answer never comes
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
        if cid in self.unanswered:
            self.unanswered.discard(cid)
            raise NO_ANSWER
        return self._instance(cid)

    def renew(self, cid):
        self.calls.append(("renew", cid))
        self._maybe("renew")
        return None

    def stop(self, cid):
        self.calls.append(("stop", cid))
        self._maybe("stop")
        del self.up[cid]


NO_ANSWER = InstanceError("no answer from the platform to instance start for challenge 1 within 20 s; it may have been done: "
                          "look at the challenge on the site", maybe_done=True)


def lab(n=3, max_lanes=4, cap=3, seconds=None, categories=None, client=None):
    """A deck with `n` on-demand challenges and a plain one, a runner, and its platform: the
    fake above, or `client` (a real InstanceClient against a fake site)."""
    clock = Clock()
    deck = Deck(DeckConfig(event="t", flag_format=FLAG_FORMAT, models=MODELS, max_lanes=max_lanes), RecordingDriver(), clock, RecordingVerifier())
    platform = client if client is not None else Platform(cap, seconds, clock=clock.now)
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


# ---------------------------------------------------------------- a start that got no answer


def said(deck) -> list[str]:
    return [e.text for e in deck.events if e.data.get("source") == "instances"]


def test_a_start_that_got_no_answer_and_turns_up_in_the_status_is_this_runs_and_is_stopped():
    deck, runner, platform, urls, clock = lab(n=1)
    platform.unanswered.add("c0")  # the platform started it; the answer came too late for the client
    step(runner)
    assert runner.running == {} and "c0" in deck.waits and platform.up == {"c0": 31000}
    assert "could not start the instance of Chall 0" in said(deck)[0] and "it may have been done" in said(deck)[0]
    assert "If the instance is up when it asks again (within 10 minutes), flightdeck takes it as the one it started" in said(deck)[0]
    clock.t += 31
    step(runner)
    assert platform.calls == [("status", "c0"), ("start", "c0"), ("status", "c0")]  # the start is not sent again
    assert runner.adopted == set() and urls["c0"] == ("http://box.example.test:31000",) and deck.waits == {}
    (found,) = [e for e in deck.events if e.data.get("url")]
    assert found.data["adopted"] is False and "was already running" not in found.text
    assert "the instance of Chall 0 is up: http://box.example.test:31000 (the start flightdeck sent earlier got no answer" in found.text
    lane = deck.lanes_on("c0")[0]
    assert deck.apply(iv.Kill(lane.id, requeue=False)).ok  # nobody works it any more
    step(runner)
    assert platform.calls[-1] == ("stop", "c0") and platform.up == {}  # its slot is free again


def test_an_instance_that_turns_up_after_a_start_the_platform_refused_is_a_teammates():
    deck, runner, platform, urls, clock = lab(n=1)
    platform.fail["start"] = InstanceRefused("the platform refused instance start for challenge 1: image build failed")
    step(runner)
    assert "takes it as the one it started" not in said(deck)[0]
    platform.up["c0"] = 40000  # a teammate started it meanwhile: the platform said no to this run's start
    clock.t += 31
    step(runner)
    assert runner.adopted == {"c0"} and "was already running" in [e for e in deck.events if e.data.get("adopted")][0].text
    assert asyncio.run(runner.close()) == [] and platform.up == {"c0": 40000}


def test_an_instance_that_turns_up_long_after_the_unanswered_start_is_a_teammates():
    deck, runner, platform, urls, clock = lab(n=1)
    platform.fail["start"] = NO_ANSWER  # no answer, and the start was not done: nothing is up
    step(runner)
    platform.fail["start"] = InstanceRefused("the platform refused instance start for challenge 1: not open yet")
    clock.t += 31
    step(runner)  # asked again, and refused in so many words
    assert runner.running == {} and len([c for c in platform.calls if c[0] == "start"]) == 2
    clock.t += CLAIM_FOR
    platform.up["c0"] = 40000  # much later, a teammate starts it
    step(runner)
    assert runner.adopted == {"c0"}
    assert asyncio.run(runner.close()) == [] and platform.up == {"c0": 40000}


def test_a_later_start_that_is_answered_makes_the_instance_this_runs_as_ever():
    deck, runner, platform, urls, clock = lab(n=1)
    platform.fail["start"] = NO_ANSWER  # not done
    step(runner)
    clock.t += 31
    step(runner)
    assert platform.calls == [("status", "c0"), ("start", "c0"), ("status", "c0"), ("start", "c0")]
    assert runner.adopted == set() and "the instance of Chall 0 started: " in said(deck)[-1]
    assert asyncio.run(runner.close()) == [] and platform.up == {}


def test_an_unanswered_start_of_a_challenge_nobody_works_any_more_is_stopped_when_it_turns_up():
    deck, runner, platform, urls, clock = lab(n=2, cap=1)
    platform.unanswered.add("c0")
    step(runner)
    deck.platform_solved("c0", "your team")  # solved elsewhere before the instance was seen: no lane will ask for it
    clock.t += 31
    step(runner)
    assert ("stop", "c0") in platform.calls and "c0" not in platform.up  # found by its status, and stopped
    assert any("the instance of Chall 0 came up after a start that got no answer, and nobody works it now: flightdeck stopped it" in text
               for text in said(deck))
    assert list(platform.up) == ["c1"] and runner.unanswered == {}  # stopped before the next start, so the slot went to the next in line
    assert not any(e.data.get("full") for e in deck.events)


def test_an_unanswered_start_nobody_works_is_looked_for_now_and_then_and_not_for_ever():
    deck, runner, platform, urls, clock = lab(n=1)
    platform.fail["start"] = NO_ANSWER  # not done, or not up yet
    step(runner)
    deck.platform_solved("c0", "your team")
    for _ in range(4):  # four looks 5 s apart: asked once more, not four times
        clock.t += 5
        step(runner)
    assert platform.calls == [("status", "c0"), ("start", "c0")]
    clock.t += 31
    step(runner)
    assert platform.calls[2:] == [("status", "c0")]  # not up
    for _ in range(4):
        clock.t += 5
        step(runner)
    assert len(platform.calls) == 3  # and not asked again at every look
    clock.t += 11
    step(runner)
    assert platform.calls[3:] == [("status", "c0")]
    clock.t += CLAIM_FOR
    step(runner)
    step(runner)
    assert len(platform.calls) == 4 and runner.unanswered == {}  # past the time a start may take, it is let go


def test_close_stops_an_instance_whose_start_got_no_answer_and_says_when_it_cannot_tell():
    deck, runner, platform, urls, clock = lab(n=2)
    platform.unanswered.add("c0")
    step(runner)  # c0: done with no answer; c1: started
    assert list(runner.running) == ["c1"] and sorted(platform.up) == ["c0", "c1"]
    assert asyncio.run(runner.close()) == [] and platform.up == {}

    deck, runner, platform, urls, clock = lab(n=1)
    platform.fail["start"] = NO_ANSWER  # nothing is up when the run ends: it may still come
    step(runner)
    (left,) = asyncio.run(runner.close())
    assert "the start of Chall 0's instance got no answer, and the platform names no instance of it yet: if one comes up" in left
    assert ("stop", "c0") not in platform.calls

    deck, runner, platform, urls, clock = lab(n=1)
    platform.unanswered.add("c0")
    step(runner)
    platform.fail["stop"] = InstanceError("no answer from the platform")
    (left,) = asyncio.run(runner.close())
    assert "the instance of Chall 0 may still run on the platform: no answer from the platform" in left


def test_a_wanted_start_that_got_no_answer_keeps_the_one_slot_ahead_of_a_challenge_put_before_it():
    """One slot (ctfd-owl). c0's start was done with no answer, then c1 is put ahead of it in
    line. Given c1's turn, c1 would be refused as full every 30 s and c0's own container
    would never be looked for again: every on-demand challenge stalls for its hour."""
    needs = [Need("a", wanted=True, running=False, place=0, claimed=True), Need("b", wanted=True, running=False, place=-1)]
    assert plan(needs, 1).start == ("a",) and plan(needs, 1).waiting == ("b",)

    deck, runner, platform, urls, clock = lab(n=2, cap=1)
    platform.unanswered.add("c0")
    step(runner)
    assert platform.up == {"c0": 31000} and runner.running == {}
    deck.queue.sort(key=lambda entry: entry.challenge != "c1")  # the player puts c1 first
    clock.t += 31
    step(runner)
    assert ("start", "c1") not in platform.calls  # it is not given the slot c0's container holds
    assert list(runner.running) == ["c0"] and runner.adopted == set() and urls["c0"] == ("http://box.example.test:31000",)
    deck.platform_solved("c0", "your team")
    step(runner)
    assert ("stop", "c0") in platform.calls and list(platform.up) == ["c1"]  # c0 was this run's, stopped, and c1 has its turn
    assert not any(e.data.get("full") for e in deck.events)


def test_a_start_the_runs_end_cuts_off_is_waited_for_and_its_instance_stopped_by_close():
    """The run's end cancels the instances task while a start is out. The worker thread goes
    on and the platform starts the instance: close() must know of it and stop it."""
    import threading

    deck, runner, platform, urls, clock = lab(n=1)
    sent, release, done = threading.Event(), threading.Event(), threading.Event()
    start = platform.start

    def slow_start(cid):
        sent.set()
        release.wait(5)
        try:
            return start(cid)
        finally:
            done.set()

    platform.start = slow_start

    async def scenario():
        task = asyncio.create_task(runner.step())
        while not sent.is_set():
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()  # the platform answers after the cancel
        left = await runner.close()
        await asyncio.to_thread(done.wait, 5)
        return left

    assert asyncio.run(scenario()) == []
    assert platform.calls == [("status", "c0"), ("start", "c0"), ("stop", "c0")] and platform.up == {}


class Unusable(Platform):
    """A platform that starts the instance and names it at an address flightdeck will not use."""

    def _instance(self, cid):
        raise InstanceError(f"the platform's answer for {cid} names no usable address (chal_web.ctf.test)", up=True)

    def start(self, cid):
        try:
            return super().start(cid)
        except InstanceError as exc:
            exc.maybe_done = True  # as the client marks a start's own answer
            raise


def test_an_instance_this_run_started_at_an_address_it_will_not_use_is_stopped_when_nobody_works_it():
    deck, runner, _, urls, clock = lab(n=1)
    platform = runner.client = Unusable(clock=clock.now)
    step(runner)
    assert platform.up == {"c0": 31000} and runner.running == {} and "c0" in deck.waits
    clock.t += 31
    step(runner)
    assert [c for c in platform.calls if c[0] == "start"] == [("start", "c0")]  # never sent again
    clock.t += CLAIM_FOR  # long past the time a start with no answer is remembered
    step(runner)
    deck.platform_solved("c0", "your team")
    clock.t += RETRY_MOST  # past the wait before its next try
    step(runner)
    assert platform.calls[-1] == ("stop", "c0") and platform.up == {}
    assert any("the instance of Chall 0 runs at an address flightdeck will not use, and nobody works it now: flightdeck stopped it"
               in text for text in said(deck))

    deck, runner, _, urls, clock = lab(n=1)
    platform = runner.client = Unusable(clock=clock.now)
    step(runner)
    clock.t += CLAIM_FOR + 1
    assert asyncio.run(runner.close()) == [] and platform.calls[-1] == ("stop", "c0") and platform.up == {}


class UnusableFor(Unusable):
    """Unusable for the challenges named, and a plain platform for the rest."""

    def __init__(self, names, **kw) -> None:
        super().__init__(**kw)
        self.names = set(names)

    def _instance(self, cid):
        return super()._instance(cid) if cid in self.names else Platform._instance(self, cid)

    def start(self, cid):
        return super().start(cid) if cid in self.names else Platform.start(self, cid)


def test_an_instance_at_an_address_it_will_not_use_keeps_its_one_slot_past_the_claim_time():
    """One slot (ctfd-owl). c0's start was done at an address flightdeck will not use, so its
    container holds the only slot for as long as it runs. Past CLAIM_FOR, c1 put ahead of it
    must not get that slot: it would be refused as full every 30 s, and c0 never asked again."""
    needs = [Need("a", wanted=True, running=False, place=0, claimed=True, held=True), Need("b", wanted=True, running=False, place=-1)]
    assert plan(needs, 1).start == ("a",) and plan(needs, 1).waiting == ("b",)
    needs = [Need("a", wanted=False, running=False, claimed=True, held=True), Need("b", wanted=True, running=False)]
    assert plan(needs, 1).start == () and plan(needs, 2).start == ("b",)  # unwanted, it holds the slot until it is stopped

    deck, runner, _, urls, clock = lab(n=2, cap=1)
    platform = runner.client = UnusableFor({"c0"}, cap=1, clock=clock.now)
    step(runner)
    assert platform.up == {"c0": 31000} and runner.unusable == {"c0"}
    deck.queue.sort(key=lambda entry: entry.challenge != "c1")  # the player puts c1 first
    clock.t += CLAIM_FOR + RETRY_MOST
    step(runner)
    assert ("start", "c1") not in platform.calls and platform.calls[-1] == ("status", "c0")  # c0 is asked again, c1 waits
    assert not any(e.data.get("full") for e in deck.events)
    deck.platform_solved("c0", "your team")
    clock.t += RETRY_MOST
    step(runner)
    assert platform.calls[-1] == ("stop", "c0") and platform.up == {} and runner.unusable == set()
    step(runner)
    assert list(platform.up) == ["c1"]  # c1 has its turn


def test_an_adopted_instance_that_ended_and_is_started_again_by_this_run_is_this_runs():
    deck, runner, platform, urls, clock = lab(n=1, seconds=600)
    platform.up["c0"] = 40000  # a teammate's
    step(runner)
    assert runner.adopted == {"c0"}
    del platform.up["c0"]  # it ended
    clock.t += 601
    step(runner)
    assert platform.calls[-1] == ("start", "c0") and runner.adopted == set()  # this run started the new one
    assert asyncio.run(runner.close()) == [] and platform.up == {}


def test_owl_a_start_slower_than_the_client_waits_is_found_and_stopped_and_the_next_challenge_gets_its_turn():
    """The whole of it with the real client against the fake of ctfd-owl: the plugin starts the
    container inside the POST, the client stops waiting first, and the container is there
    when the status is asked. Taken for a teammate's it would never be stopped, and the
    account's one container would keep every other challenge out for its hour."""
    import threading

    from ctf_flightdeck.platform.instances import InstanceClient, parse_config

    from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd
    from fake_instance_plugins import OWL_ROUTE, OWL_TYPE

    board = [FakeChallenge(1, "Boxed", category="Web", type=OWL_TYPE), FakeChallenge(2, "Second", category="Pwn", type=OWL_TYPE)]
    with FakeCTFd(board) as fake:
        fake.owl.limit = 0  # the plugin's one-second rule is tests/test_instance_plugins.py's
        fake.owl.slow = threading.Event()  # the POST's answer waits for this: the container is up long before
        client = InstanceClient(fake.base_url, TOKEN, {"c0": 1, "c1": 2}, parse_config({"plugin": "ctfd_owl"}), timeout=0.3,
                                sleep=lambda seconds: None)
        try:
            deck, runner, _, urls, clock = lab(n=2, cap=1, client=client, categories=["web", "pwn"])
            step(runner)
            assert runner.running == {} and fake.owl.container["challenge"] == 1  # up on the site, unknown to the run
            assert "no answer from the platform to instance start for challenge 1 " in said(deck)[0] and "it may have been done" in said(deck)[0]
            fake.owl.slow.set()
            fake.owl.slow = None
            clock.t += 31
            step(runner)
            assert runner.adopted == set() and urls["c0"] == ("http://198.51.100.7:28001",)
            assert len([r for r in fake.to(OWL_ROUTE) if r.method == "POST"]) == 1  # the start was sent once
            deck.platform_solved("c0", "your team")
            step(runner)
            assert [(r.method, r.path) for r in fake.to(OWL_ROUTE) if r.method == "DELETE"] == [("DELETE", f"{OWL_ROUTE}?challenge_id=1")]
            assert fake.owl.container["challenge"] == 2 and urls["c1"] == ("tcp://198.51.100.7:28002",)
            assert not any("cap on running instances" in text for text in said(deck))
        finally:
            client.close()


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


@pytest.mark.parametrize(("plugin", "kind", "table", "first", "second"), [
    ("ctfd_owl", "dynamic_check_docker", "", "http://198.51.100.7:28001", "tcp://198.51.100.7:28002 (nc 198.51.100.7 28002)"),
    ("chall_manager", "dynamic_iac", "max_running = 1\n", "http://cm.example.test:30001", "tcp://cm.example.test:30002 (nc cm.example.test 30002)"),
])
def test_a_run_plays_a_board_through_the_owl_and_chall_manager_plugins(tmp_path, monkeypatch, plugin, kind, table, first, second):
    """The whole path against the fakes of the two plugins (tests/fake_instance_plugins.py):
    the profile's plugin name, a start, the address in the lane's brief, the stop on the solve
    and the next start. ctfd-owl's own clock runs here: two changes within a second are
    refused, so a refusal in this run would mean the client did not space them."""
    from ctf_flightdeck.core.model import LaneState
    from ctf_flightdeck.run import RunOptions, prepare_run

    from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd
    from fake_model import FakeModelServer
    from test_event_run import TOKEN_VAR, Model, config, event, play, submit, wait_for

    monkeypatch.setenv(TOKEN_VAR, TOKEN)
    board = [FakeChallenge(1, "Boxed", category="Web", value=50, flag="test{boxed}", type=kind),
             FakeChallenge(2, "Second Box", category="Pwn", value=60, flag="test{second}", type=kind),
             FakeChallenge(3, "Plain", category="Misc", value=10, flag="test{plain}")]
    model = Model({"Boxed": [submit("test{boxed}")], "Second Box": [submit("test{second}")]})
    said: list[str] = []
    with FakeCTFd(board) as fake, FakeModelServer(responder=model) as server:
        profile = event(tmp_path, url=fake.base_url, submit="auto")
        profile.write_text(profile.read_text() + f'\n[instances]\nplugin = "{plugin}"\ntypes = ["{kind}"]\n{table}')
        run = prepare_run(RunOptions(board=tmp_path / "board", event=profile, config=config(tmp_path, server.base_url, max_lanes=3)))
        run.instances.every = 0.05
        assert run.instances.max_running == 1  # the owl shape's own; the table's for chall-manager

        async def body(run):
            await wait_for(lambda: all(lane.state is LaneState.SOLVED for lane in run.deck.lanes.values()
                                       if lane.challenge_id in ("boxed", "second-box")) and len(run.deck.lanes) == 3
                           and run.deck.challenges["second-box"].closed, "both boxed challenges solved, one after the other")
            # ... and the runner has its answer: a run that ends while the stop is still out sends it again at its close
            await wait_for(lambda: fake.owl.container is None and fake.chall_manager.instances == {} and not run.instances.running,
                           "the last instance stopped after its solve")
            said.extend(e.text for e in run.deck.events if e.data.get("source") == "instances")

        play(run, body)
    briefs = {re_name(r): r["json"]["messages"][1]["content"] for r in server.chats()}
    assert f"\nLive instance: {first}\n" in briefs["Boxed"]
    assert f"\nLive instance: {second}\n" in briefs["Second Box"]
    assert "\nLive instance: none\n" in briefs["Plain"]
    assert len(said) == 2 and all("started: " in text for text in said), said  # two starts, and no refusal or failure said
    changes = [(r.method, r.path.rsplit("=", 1)[-1] if "=" in r.path else str(r.json["challengeId"]))
               for r in fake.requests if "/plugins/" in r.path and r.method != "GET"]
    assert changes == [("POST", "1"), ("DELETE", "1"), ("POST", "2"), ("DELETE", "2")]  # each sent once, the slot freed first
