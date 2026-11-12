"""The first look in a coding-agent CLI's lane (agent/external.py, ExternalLane.opening): the
CLI's first opening takes it as far as it is back, in its own fence after the challenge's, and
an escalation's opening repeats it as it was; a lane without route or recon gets the opening it
always got, byte for byte. The CLIs are tests/fake_agent_cli.py, never the real ones; the light
model is a fake server (light_kit.py)."""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.agent.prompts import FENCE_CLOSE, FENCE_OPEN, FIRST_LOOK
from ctf_flightdeck.core import interventions as iv
from light_kit import LightModel, lights, until
from test_external import Lab as CliLab
from test_external import no_real_agents  # noqa: F401  (autouse: no real claude or codex on PATH)

BRIEF = "Files: note.txt is plain text.\nLikely: a rotation cipher.\nFirst steps: cat note.txt; try rot13 with tr."
TODAY = (  # the opening a CLI lane of test_external's challenge got before recon, byte for byte
    "The challenge, as the board gives it:\n"
    "<<<challenge-text\n"
    "Challenge: Note (misc, 50 points, 10 solves)\n"
    "Files in the workspace: note.txt\n"
    "Live instance: none\n"
    "Flag format (a regular expression): t\\{[a-z0-9_]+\\}\n"
    "Description:\n"
    "About note.\n"
    "challenge-text>>>"
)


def first_look_of(brief: str) -> str:
    block = brief.split(FIRST_LOOK + "\n", 1)[1]
    return block.split(FENCE_OPEN + "\n", 1)[1].split("\n" + FENCE_CLOSE, 1)[0]


@pytest.mark.parametrize("kind", ["claude", "codex"])
def test_a_cli_lanes_opening_carries_the_first_look_and_its_escalation_repeats_it(tmp_path, kind):
    if kind == "claude":
        script = {"turns": [{"calls": [{"text": "Looking around."}, {"think": 30.0}]}, {"calls": [{"text": "Bigger."}]}]}
    else:
        script = {"turns": [{"items": [{"message": "Looking around."}, {"sleep": 30.0}]}, {"items": [{"message": "Bigger."}]}]}
    with LightModel({"family": "classical-crypto", "recon": BRIEF}) as light:
        async def main():
            lab = CliLab(tmp_path, script, kind=kind)
            engines = lab.driver.lights = lights(light.engine())

            def opening(n: int) -> str | None:
                """The n-th start's first message (claude) or prompt (codex), if it has come."""
                if kind == "codex":
                    return lab.fake.prompts()[n] if len(lab.fake.prompts()) > n else None
                starts = lab.fake.starts()
                told = lab.fake.messages(starts[n]["pid"]) if len(starts) > n else []
                return told[0] if told else None

            try:
                lab.release()
                lane = lab.lane()
                assert lab.deck.apply(iv.Pause(lane.id)).ok
                await until(lambda: lab.driver.looks.done("note"), "the first look")
                assert lab.deck.apply(iv.Resume(lane.id)).ok
                await until(lambda: opening(0), "the CLI's first message")
                first = opening(0)
                assert first.index(FENCE_CLOSE) < first.index(FIRST_LOOK)  # after the challenge's own fence
                assert first_look_of(first) == (
                    "Specialist it suits: classical-crypto (classical ciphers and encodings: Caesar, Vigenere, substitution, "
                    "XOR, base64)\n" + BRIEF)
                assert lab.deck.apply(iv.Escalate(lane.id)).ok
                await until(lambda: opening(1), "the stronger model's opening")
                again = opening(1)
                assert first_look_of(again) == first_look_of(first)  # the brief as the lane first took it
                assert "Another model worked on this challenge before you" in again
                assert sorted(light.asked()) == ["family", "recon"]  # asked once
            finally:
                await lab.finish()
                await engines.aclose()

        asyncio.run(main())


@pytest.mark.parametrize("engines", ["none", "the judge only"])
def test_a_cli_lane_without_recon_gets_the_opening_it_got_before(tmp_path, engines):
    script = {"turns": [{"calls": [{"text": "Looking around."}]}]}
    with LightModel({"family": "classical-crypto", "recon": BRIEF}) as light:
        async def main():
            lab = CliLab(tmp_path, script)
            given = lab.driver.lights = lights(light.engine(), ("judge",)) if engines != "none" else None
            try:
                lab.release()
                await until(lambda: lab.fake.messages(), "the CLI's first message")
                assert lab.fake.messages()[0] == TODAY
                assert not lab.driver.looks.done("note") and light.asked() == []  # no first look was started
            finally:
                await lab.finish()
                if given is not None:
                    await given.aclose()

        asyncio.run(main())
