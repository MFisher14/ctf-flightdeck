"""What an Anthropic lane's calls cost, on the lane's meter: the tokens written to the cache at
their own rate, and every attempt of a call Anthropic's refusal fallback ran on more than one
model, each priced as the model that ran it.

A real Deck and AgentDriver on a host workspace in tmp_path, and the real SDK against
FakeAnthropicServer on 127.0.0.1, whose replies report usage as the API does (cache writes by
TTL; usage.iterations, one entry per attempt). No real API is called, and no key here is real.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from ctf_flightdeck.agent.anthropic_client import AnthropicClient
from ctf_flightdeck.agent.driver import AgentDriver
from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import Challenge, DeckConfig, EventKind, LaneState, PendingKind
from ctf_flightdeck.pricing import Price
from fake_anthropic import FakeAnthropicServer, attempt, message, refusal, tool_message
from test_agent_driver import Gate
from test_fallback import until

KEY = "test-anthropic-key-6Hc1-not-real"
FLAG = r"t\{[a-z0-9_]+\}"
SONNET = "claude-sonnet-5-5"
SPARE = "claude-sonnet-5"  # what Anthropic's refusal fallback answers with for Claude Sonnet 5.5
# dollars per million tokens: input, output, cache reads, 5-minute cache writes
PRICES = {SONNET: Price(2.0, 10.0, 0.10, 2.5), SPARE: Price(2.0, 10.0, 0.20, 2.5)}
SWITCH = {"type": "fallback", "from": {"model": SONNET}, "to": {"model": SPARE}, "trigger": {"type": "refusal", "category": "cyber"}}


class Lane:
    """One lane on `model` (SONNET), with the driver on an AnthropicClient against `server`;
    `ladder` is the deck's model ladder (the lane's model alone by default)."""

    def __init__(self, tmp_path: Path, server: FakeAnthropicServer, prices: dict[str, Price], *,
                 dollar_cap: float | None = None, model: str = SONNET, ladder: tuple[str, ...] = ()) -> None:
        folder = tmp_path / "board" / "note"
        folder.mkdir(parents=True)
        (folder / "note.txt").write_text("the flag is t{note}\n")
        self.client = AnthropicClient(server.base_url, KEY, max_retries=0)
        self.driver = AgentDriver(self.client, lambda lane, ch: HostWorkspace(tmp_path / "runs" / lane.id / "work", folder),
                                  run_id="run1", files={"note": ["note.txt"]}, prices=prices)
        config = DeckConfig(event="t", flag_format=FLAG, models=ladder or (model,), max_lanes=1)
        self.deck = Deck(config, self.driver, RunClock(), lambda cid, flag: flag == "t{note}")
        self.deck.release([Challenge("note", "Note", "misc", 50, solves=10, description="About note.")],
                          [QueueEntry("note", model, dollar_cap=dollar_cap)])
        (self.lane,) = self.deck.lanes.values()

    def events(self, kind: EventKind) -> list[dict]:
        return [dict(e.data) for e in self.deck.events if e.kind is kind]

    async def finish(self) -> None:
        await self.driver.shutdown()
        await self.client.aclose()


def run(main) -> None:
    asyncio.run(main())


def per_million(*pairs: tuple[int, float]) -> float:
    return sum(tokens * rate for tokens, rate in pairs) / 1_000_000


def submit(**usage) -> dict:
    """The reply that hands over the flag, so the lane stops at the approval after it."""
    return tool_message("submit_flag", {"flag": "t{note}"}, call_id="toolu_9", signature="fake-signature-9", **usage)


def test_a_turn_that_wrote_to_the_cache_is_priced_at_the_cache_write_rate(tmp_path):
    reply = submit(input_tokens=300, output_tokens=40, cache_read=2000, cache_write=1500)
    server = FakeAnthropicServer([reply])

    async def main():
        with server:
            lab = Lane(tmp_path, server, PRICES)
            lane = lab.lane
            await until(lambda: lane.pending is not None or lane.finished, "the candidate flag")
            assert (lane.pending.kind, lane.tokens, lane.cached_tokens) == (PendingKind.SUBMIT, 3840, 2000)
            # 300 plain input at $2, 2000 read at $0.10, 1500 written at $2.50 (not at the $2 input rate), 40 out at $10
            assert lane.dollars == pytest.approx(per_million((300, 2.0), (2000, 0.10), (1500, 2.5), (40, 10.0)))
            assert lab.deck.apply(iv.Approve(lane.id)).ok and lane.state is LaneState.SOLVED
            await lab.finish()

    run(main)


def fell_back() -> dict:
    """A reply Claude Sonnet 5.5 declined and Claude Sonnet 5 answered, as usage.iterations tells it."""
    return message(
        [SWITCH, *submit()["content"]], stop_reason="tool_use", model=SPARE,
        iterations=[attempt(SONNET, input_tokens=500, cache_read=3000),
                    attempt(SPARE, kind="fallback_message", input_tokens=600, output_tokens=50, cache_write=2900)],
    )


def test_every_attempt_of_a_call_the_refusal_fallback_answered_counts_priced_as_the_model_that_ran_it(tmp_path):
    server = FakeAnthropicServer([fell_back()])

    async def main():
        with server:
            lab = Lane(tmp_path, server, PRICES)
            lane = lab.lane
            await until(lambda: lane.pending is not None or lane.finished, "the candidate flag")
            assert lane.pending.kind is PendingKind.SUBMIT
            declined = per_million((500, 2.0), (3000, 0.10))  # Claude Sonnet 5.5's attempt, at its rates
            answered = per_million((600, 2.0), (2900, 2.5), (50, 10.0))  # Claude Sonnet 5's, at its own
            assert lane.tokens == 3500 + 3550 and lane.cached_tokens == 3000  # both attempts, neither counted twice
            assert lane.dollars == pytest.approx(declined + answered)
            (turn,) = lab.events(EventKind.TURN)
            assert (turn["model"], turn["tokens"], turn["dollars"]) == (SPARE, 3550, pytest.approx(answered))
            (spent,) = lab.events(EventKind.SPEND)
            assert (spent["model"], spent["tokens"], spent["cached_tokens"]) == (SONNET, 3500, 3000)
            assert spent["dollars"] == pytest.approx(declined)
            assert spent["why"] == f"{SONNET} declined, so Anthropic's refusal fallback ran the call on {SPARE}"
            assert lab.deck.apply(iv.Approve(lane.id)).ok and lane.state is LaneState.SOLVED
            await lab.finish()

    run(main)


def test_an_attempt_by_a_model_with_no_price_leaves_the_lanes_dollars_not_fully_known_and_asks_once(tmp_path):
    server = FakeAnthropicServer([fell_back()])

    async def main():
        with server:
            lab = Lane(tmp_path, server, {SONNET: PRICES[SONNET]}, dollar_cap=2.0)
            lane = lab.lane
            await until(lambda: any(p.kind is PendingKind.BUDGET for p in (lane.pending, *lane.waiting) if p), "the question")
            assert lane.dollars is None  # not fully known
            assert lane.known_dollars == pytest.approx(per_million((500, 2.0), (3000, 0.10)))  # what is known still counts
            assert lane.tokens == 3500 + 3550
            budget = next(p for p in (lane.pending, *lane.waiting) if p and p.kind is PendingKind.BUDGET)
            assert budget.detail == f"carry on with no dollar cap (no price for {SPARE})"  # the model that ran it, named
            await lab.finish()

    run(main)


def test_an_attempt_on_a_model_between_the_one_asked_for_and_the_one_that_answered_is_priced_as_its_own(tmp_path):
    # Claude Opus 5.5 declined, Claude Opus 5 declined too, Claude Opus 4.8 answered
    opus, middle, last = "claude-opus-5-5", "claude-opus-5", "claude-opus-4-8"
    prices = {opus: Price(4.0, 20.0, 0.20, 5.0), middle: Price(5.0, 25.0, 0.50, 6.25), last: Price(5.0, 25.0, 0.50, 6.25)}
    chain = message(submit()["content"], stop_reason="tool_use", model=last, iterations=[
        attempt(opus, input_tokens=1000), attempt(middle, input_tokens=2000),
        attempt(last, kind="fallback_message", input_tokens=3000, output_tokens=100)])
    server = FakeAnthropicServer([chain])

    async def main():
        with server:
            lab = Lane(tmp_path, server, prices, model=opus)
            lane = lab.lane
            await until(lambda: lane.pending is not None or lane.finished, "the candidate flag")
            assert lane.tokens == 1000 + 2000 + 3100
            assert lane.dollars == pytest.approx(per_million((1000, 4.0), (2000, 5.0), (3000, 5.0), (100, 25.0)))
            spent = {e["model"]: (e["tokens"], e["dollars"]) for e in lab.events(EventKind.SPEND)}
            assert spent == {opus: (1000, pytest.approx(per_million((1000, 4.0)))),
                             middle: (2000, pytest.approx(per_million((2000, 5.0))))}  # Claude Opus 5's rate, not 5.5's
            (turn,) = lab.events(EventKind.TURN)
            assert (turn["model"], turn["tokens"]) == (last, 3100)
            await lab.finish()

    run(main)


def test_a_call_every_model_declined_ends_the_lane_with_each_attempt_counted_as_its_model(tmp_path):
    declined = refusal("cyber", model=SPARE, iterations=[attempt(SONNET, input_tokens=800), attempt(SPARE, input_tokens=900)])
    server = FakeAnthropicServer([declined])

    async def main():
        with server:
            lab = Lane(tmp_path, server, PRICES)
            lane = lab.lane
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP and lane.result == "the model declined (cyber)"
            assert lane.tokens == 800 + 900
            assert lane.dollars == pytest.approx(per_million((800, 2.0), (900, 2.0)))
            (spent,) = [e for e in lab.events(EventKind.SPEND) if e["model"] == SONNET]
            assert spent["tokens"] == 800
            await lab.finish()

    run(main)


OPUS = "claude-opus-5-5"  # the rung above SONNET on the ladder of the tests below
OPUS_PRICE = Price(4.0, 20.0, 0.20, 5.0)
HOLD = 30.0  # seconds the fake server holds a reply at most: the test lets it go once it has acted, however loaded the machine


@pytest.mark.parametrize("overtake", ["escalate", "take over"])
def test_a_call_every_model_declined_after_the_lane_was_escalated_or_taken_over_counts_each_attempt(tmp_path, overtake):
    # the call no longer counts (the lane goes on), but Anthropic billed both attempts of it
    gate = threading.Event()
    declined = refusal("cyber", model=SPARE, iterations=[attempt(SONNET, input_tokens=800, cache_read=1000),
                                                         attempt(SPARE, input_tokens=900, cache_read=2000)])

    def responder(record):
        if len(server.requests) == 1:
            gate.wait(HOLD)  # the models are still at it when the player steps in
            return declined
        return submit(input_tokens=60, output_tokens=40)

    server = FakeAnthropicServer(responder=responder)

    async def main():
        with server:
            lab = Lane(tmp_path, server, {**PRICES, OPUS: OPUS_PRICE}, ladder=(SONNET, OPUS))
            lane = lab.lane
            await until(lambda: len(server.requests) >= 1, "the call to Claude Sonnet 5.5")
            if overtake == "escalate":
                assert lab.deck.apply(iv.Escalate(lane.id)).ok and lane.model == OPUS
            else:
                session = lab.driver.takeover(lane)
                assert lab.deck.apply(iv.TakeOver(lane.id)).ok
                await asyncio.wait_for(session.begin(), 10)
            gate.set()
            await until(lambda: lane.tokens >= 1800 + 2900, "the declined call's tokens counted")
            if overtake == "take over":
                assert lab.deck.apply(iv.HandBack(lane.id, session.finish())).ok
            await until(lambda: lane.pending is not None or lane.finished, "the next call's candidate")
            assert lane.state is LaneState.WAITING, lane.result  # the refusal of a call that no longer counts ends nothing
            assert (lane.tokens, lane.cached_tokens) == (1800 + 2900 + 100, 1000 + 2000)
            # each attempt in its model's name, at its rates (cache reads: Claude Sonnet 5.5 $0.10, Claude Sonnet 5 $0.20)
            sonnet, spare = per_million((800, 2.0), (1000, 0.10)), per_million((900, 2.0), (2000, 0.20))
            spent = {e["model"]: (e["tokens"], e["cached_tokens"], e["dollars"]) for e in lab.events(EventKind.SPEND)}
            assert spent == {SONNET: (1800, 1000, pytest.approx(sonnet)), SPARE: (2900, 2000, pytest.approx(spare))}
            dropped = "a refusal dropped: the lane was escalated or taken over while the model answered"
            assert {e["model"]: e["why"] for e in lab.events(EventKind.SPEND)} == {
                SONNET: f"{SONNET} declined, so Anthropic's refusal fallback ran the call on {SPARE}; {dropped}",
                SPARE: dropped}
            asked = server.requests[1]["json"]["model"]
            assert asked == (OPUS if overtake == "escalate" else SONNET)
            last = per_million((60, 4.0), (40, 20.0)) if asked == OPUS else per_million((60, 2.0), (40, 10.0))
            assert lane.dollars == pytest.approx(sonnet + spare + last)
            assert lab.deck.totals()[0] == 4800
            await lab.finish()

    run(main)


@pytest.mark.parametrize("cut", ["killed while its reply waits", "killed during its tool call", "quit while its reply waits"])
def test_a_reply_the_lane_stopped_before_its_turn_was_done_still_counts_every_attempt(tmp_path, cut):
    # the reply came (Anthropic billed both attempts of its call), and then the lane stopped:
    # the player killed it, or quit, while the reply waited for the paused lane or its tool call ran
    hold = Gate(tmp_path)  # the tool call runs until the test has stopped the lane
    call = tool_message("shell", {"command": hold.command("true")})
    reply = message([SWITCH, *call["content"]], stop_reason="tool_use", model=SPARE, iterations=[
        attempt(SONNET, input_tokens=800, cache_read=1000),
        attempt(SPARE, kind="fallback_message", input_tokens=900, output_tokens=10)])
    gate = threading.Event()

    def responder(record):
        gate.wait(HOLD)  # held until the test is ready for it (the lane paused, or not)
        return reply

    server = FakeAnthropicServer(responder=responder)

    async def main():
        with server:
            lab = Lane(tmp_path, server, PRICES)
            lane = lab.lane
            if "waits" in cut:
                await until(lambda: len(server.requests) >= 1, "the call")
                assert lab.deck.apply(iv.Pause(lane.id)).ok
                gate.set()
                await until(lambda: SONNET in lab.driver.answered, "the reply, held: the lane is paused")
            else:
                gate.set()
                await until(hold.started.exists, "the tool call running")
            if cut.startswith("quit"):
                lab.deck.close()  # as the run does when the player quits, before the driver's shutdown
                await lab.driver.shutdown()
            else:
                assert lab.deck.apply(iv.Kill(lane.id, requeue=False)).ok
            hold.open()
            await until(lambda: lane.tokens >= 2710, "the reply's tokens counted")
            assert (lane.tokens, lane.cached_tokens, lane.turns) == (1800 + 910, 1000, 0)
            sonnet, spare = per_million((800, 2.0), (1000, 0.10)), per_million((900, 2.0), (10, 10.0))
            assert lane.dollars == pytest.approx(sonnet + spare)
            spent = {e["model"]: (e["tokens"], e["dollars"], e["why"]) for e in lab.events(EventKind.SPEND)}
            stopped = "a reply cut short: the lane stopped before its turn was done"
            assert spent == {
                SONNET: (1800, pytest.approx(sonnet), f"{SONNET} declined, so Anthropic's refusal fallback ran the call on "
                                                      f"{SPARE}; {stopped}"),
                SPARE: (910, pytest.approx(spare), stopped)}
            assert lab.deck.totals()[:2] == (2710, pytest.approx(sonnet + spare))
            await lab.finish()

    run(main)


@pytest.mark.parametrize("counted", ["by its turn", "by its drop"])
def test_a_reply_already_counted_is_not_counted_again_when_the_lane_stops(tmp_path, counted):
    # its turn reported it (then the flag was approved), or it was dropped on an escalation (then
    # the lane was killed while the stronger model's call was under way: that call is cancelled)
    gates = [threading.Event(), threading.Event()]

    def responder(record):
        n = len(server.requests)
        if counted == "by its turn":
            return submit(input_tokens=300, output_tokens=40)
        gates[min(n, 2) - 1].wait(HOLD)
        return tool_message("shell", {"command": "ls"}, input_tokens=300, output_tokens=40)

    server = FakeAnthropicServer(responder=responder)

    async def main():
        with server:
            lab = Lane(tmp_path, server, {**PRICES, OPUS: OPUS_PRICE}, ladder=(SONNET, OPUS))
            lane = lab.lane
            if counted == "by its turn":
                await until(lambda: lane.pending is not None, "the candidate flag")
                assert lab.deck.apply(iv.Approve(lane.id)).ok and lane.state is LaneState.SOLVED
            else:
                await until(lambda: len(server.requests) >= 1, "the call to Claude Sonnet 5.5")
                assert lab.deck.apply(iv.Escalate(lane.id)).ok
                gates[0].set()
                await until(lambda: len(server.requests) >= 2, "the call to Claude Opus 5.5")
                assert lane.tokens == 340  # the dropped reply, counted
                assert lab.deck.apply(iv.Kill(lane.id, requeue=False)).ok
            await lab.finish()  # the lane's task has ended: nothing more is reported
            gates[1].set()
            assert lane.tokens == 340 and lab.deck.totals()[0] == 340
            assert len(lab.events(EventKind.SPEND)) == (0 if counted == "by its turn" else 1)

    run(main)
