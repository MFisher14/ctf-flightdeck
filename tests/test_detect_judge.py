"""The optional hint judge, end to end against the fake OpenAI-compatible server (nothing
mocked): it confirms or denies a rules HINT signal, is rate-limited per lane, reports its
spend to the deck, and never raises an alert on its own. The description it sends is fenced
and folded, so challenge text cannot steer the model or forge a line."""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.agent.client import ModelClient
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig
from ctf_flightdeck.detect.base import DetectConfig
from ctf_flightdeck.detect.hints import lexicon
from ctf_flightdeck.detect.judge import FENCE_CLOSE, FENCE_OPEN, HintJudge

from fake_model import FakeModelServer, error_reply, text_reply

KEY = "unit-test-key"  # not a token shape; the fake server ignores auth
MODELS = ("small", "big")
DESC = "A numbers station. There is a picture in it if you scan it slowly enough."


class RecDriver:
    def attach(self, deck):
        self.deck = deck

    def start(self, lane, challenge):
        pass

    def __getattr__(self, name):
        return lambda *a, **k: None


def make_deck(description: str = DESC) -> Deck:
    deck = Deck(
        DeckConfig(event="t", flag_format=r"t\{\w+\}", models=MODELS, max_lanes=2),
        RecDriver(),
        type("C", (), {"now": lambda self: 100.0})(),
        verify=lambda cid, flag: False,
    )
    deck.release(
        [Challenge("c1", "Static Hiss", "for", 50, solves=88, description=description)],
        [QueueEntry("c1", "small")],
    )
    deck.report("L01", TurnReport(action="$ python3 diff_channels.py left.wav right.wav", output="max |L-R| tiny"))
    return deck


def run(coro):
    asyncio.run(coro)


def test_judge_confirms_when_the_model_says_the_lane_is_not_using_the_technique():
    server = FakeModelServer([text_reply("no", prompt_tokens=90, completion_tokens=10, cost=0.0007)])

    async def main():
        with server:
            deck = make_deck()
            lane, ch = deck.lanes["L01"], deck.challenges["c1"]
            async with ModelClient(server.base_url, KEY, max_retries=0, backoff=0.0) as client:
                judge = HintJudge(client, "small")
                tokens_before = lane.tokens
                j = await judge.judge(lane, ch, lexicon().get("sstv"), deck=deck)
                assert j.confirmed is True  # "no, not using it" -> the lane ignores the hint -> raise
                assert j.answer == "no" and j.reason == "" and not j.cached
                assert j.tokens == 100 and j.cost == pytest.approx(0.0007)
                assert lane.tokens == tokens_before + 100  # the judge's tokens land on the lane's meter
                assert lane.dollars == pytest.approx(0.0007)

    run(main())


def test_judge_denies_when_the_model_says_the_lane_is_using_the_technique():
    server = FakeModelServer([text_reply("yes")])

    async def main():
        with server:
            deck = make_deck()
            lane, ch = deck.lanes["L01"], deck.challenges["c1"]
            async with ModelClient(server.base_url, KEY, max_retries=0, backoff=0.0) as client:
                judge = HintJudge(client, "small")
                j = await judge.judge(lane, ch, lexicon().get("sstv"), deck=deck)
                assert j.confirmed is False  # "yes, using it" -> suppress the rules signal

    run(main())


def test_judge_returns_no_verdict_when_the_answer_is_not_yes_or_no():
    server = FakeModelServer([text_reply("perhaps, it is hard to say")])

    async def main():
        with server:
            deck = make_deck()
            lane, ch = deck.lanes["L01"], deck.challenges["c1"]
            async with ModelClient(server.base_url, KEY, max_retries=0, backoff=0.0) as client:
                judge = HintJudge(client, "small")
                j = await judge.judge(lane, ch, lexicon().get("sstv"), deck=deck)
                assert j.confirmed is None and "did not answer yes or no" in j.reason
                assert lane.tokens == 120  # the call still happened, so its tokens are reported

    run(main())


def test_judge_is_rate_limited_per_lane_then_asks_again_after_the_window():
    server = FakeModelServer([text_reply("no"), text_reply("yes")])

    async def main():
        with server:
            deck = make_deck()
            lane, ch = deck.lanes["L01"], deck.challenges["c1"]
            async with ModelClient(server.base_url, KEY, max_retries=0, backoff=0.0) as client:
                judge = HintJudge(client, "small", DetectConfig(judge_every_turns=5))
                tech = lexicon().get("sstv")
                first = await judge.judge(lane, ch, tech, deck=deck)
                assert first.confirmed is True and not first.cached
                cached = await judge.judge(lane, ch, tech, deck=deck)  # same turn
                assert cached.confirmed is True and cached.cached and cached.tokens == 0
                assert len([r for r in server.requests if r["json"]]) == 1  # the model was asked once
                lane.turns += 5  # past the window
                again = await judge.judge(lane, ch, tech, deck=deck)
                assert again.confirmed is False and not again.cached  # a fresh call, the "yes" reply
                assert len([r for r in server.requests if r["json"]]) == 2

    run(main())


def test_judge_gives_no_verdict_and_charges_nothing_when_the_call_fails():
    server = FakeModelServer([error_reply(500, "fake model server: boom")])

    async def main():
        with server:
            deck = make_deck()
            lane, ch = deck.lanes["L01"], deck.challenges["c1"]
            before = lane.tokens
            async with ModelClient(server.base_url, KEY, max_retries=0, backoff=0.0) as client:
                judge = HintJudge(client, "small")
                j = await judge.judge(lane, ch, lexicon().get("sstv"), deck=deck)
                assert j.confirmed is None and "judge call failed" in j.reason
                assert lane.tokens == before  # a call that did not land does not charge the lane

    run(main())


def test_the_prompt_fences_and_folds_the_untrusted_description():
    nasty = "line one\x1b[31m and a hidden\nsecond line about slow scan radio"
    server = FakeModelServer([text_reply("no")])

    async def main():
        with server:
            deck = make_deck(nasty)
            lane, ch = deck.lanes["L01"], deck.challenges["c1"]
            async with ModelClient(server.base_url, KEY, max_retries=0, backoff=0.0) as client:
                judge = HintJudge(client, "small")
                await judge.judge(lane, ch, lexicon().get("sstv"), deck=deck)
            messages = server.requests[0]["json"]["messages"]
            assert [m["role"] for m in messages] == ["system", "user"]
            user = messages[1]["content"]
            assert FENCE_OPEN in user and FENCE_CLOSE in user
            assert "slow scan radio" in user  # the words survive
            assert "\x1b" not in user and "\n and a hidden\nsecond" not in user  # folded to one line, escape stripped
            assert server.requests[0]["json"].get("tools") in (None, [])  # the judge sends no tools
            assert server.requests[0]["json"]["session_id"].startswith("flightdeck-judge-L01")

    run(main())
