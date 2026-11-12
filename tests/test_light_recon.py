"""Recon at a lane's start (agent/facts.py, prompts.brief): a light model's first-pass brief on
the handout, in a fenced block of the lane's opening brief. It carries no flag, is cut at a line
to its cap, never holds up the lane's first model call, is never added later, and every fresh
context of the lane (an escalation, a refresh) repeats it as it was. A lane without one gets the
brief it always got, byte for byte. (CLI lanes: test_light_cli.py.)

The lanes' model and the light model are fakes (fake_model.py, light_kit.py); everything
runs on 127.0.0.1 and in host workspaces under tmp_path."""

from __future__ import annotations

import asyncio
import threading

import pytest

from ctf_flightdeck.agent.prompts import FENCE_CLOSE, FENCE_OPEN, FIRST_LOOK
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import AlertKind, EventKind
from ctf_flightdeck.light import BRIEF_CHARS
from fake_model import FakeModelServer, tool_call_reply
from light_kit import Lab, LightModel, challenge, handout, lights, notes, until

NOTE = "About the note."
TODAY = (  # the brief a lane of this challenge got before recon, byte for byte
    "The challenge, as the board gives it:\n"
    "<<<challenge-text\n"
    "Challenge: Note (misc, 100 points, 5 solves)\n"
    "Files in the workspace: note.txt\n"
    "Live instance: none\n"
    "Flag format (a regular expression): t\\{[a-z0-9_]+\\}\n"
    "Description:\n"
    "About the note.\n"
    "challenge-text>>>"
)
BRIEF = "Files: note.txt is plain text.\nLikely: a rotation cipher.\nFirst steps: cat note.txt; try rot13 with tr."


def looping(record):
    return tool_call_reply("shell", {"command": "ls"})


def brief_of(record: dict) -> str:
    return record["json"]["messages"][1]["content"]


def first_look_of(brief: str) -> str:
    block = brief.split(FIRST_LOOK + "\n", 1)[1]
    return block.split(FENCE_OPEN + "\n", 1)[1].split("\n" + FENCE_CLOSE, 1)[0]


def note_handout(tmp_path):
    return {"note": handout(tmp_path, "note", {"note.txt": "gur synt vf abg urer\n"})}


async def opened_after_the_first_look(lab: Lab, cid: str = "note"):
    lane = lab.lane(cid)
    assert lab.deck.apply(iv.Pause(lane.id)).ok
    await until(lambda: lab.looked(cid), "the first look")
    assert lab.deck.apply(iv.Resume(lane.id)).ok
    return lane


# ---------------------------------------------------------------------- off: today's brief


@pytest.mark.parametrize("case", ["no light model", "the judge only", "route and recon too late", "recon refused"])
def test_a_lane_without_recon_gets_the_brief_it_gets_today(tmp_path, case):
    gate = threading.Event()
    answers = {"family": "classical-crypto", "recon": "I'm sorry, I can't help with that." if case == "recon refused" else BRIEF}
    lanes = FakeModelServer(responder=looping)
    with lanes, LightModel(answers, gate=gate if case == "route and recon too late" else None) as light:
        async def main():
            jobs = {"no light model": None, "the judge only": ("judge",), "route and recon too late": ("route", "recon"),
                    "recon refused": ("recon",)}[case]
            lab = Lab(tmp_path, lanes, note_handout(tmp_path), lights=lights(light.engine(), jobs) if jobs else None)
            try:
                lab.release(challenge("note", "misc", NOTE))
                if case == "recon refused":
                    await opened_after_the_first_look(lab)
                await until(lambda: len(lanes.chats()) >= 2, "two model calls")
                assert brief_of(lanes.chats()[0]) == TODAY
                assert brief_of(lanes.chats()[1]) == TODAY
                if case == "recon refused":
                    (said,) = [w for w in lab.warnings() if w.data.get("failure") == "refused"]
                    assert "declined on recon's brief" in said.text and "the lane's brief goes without a first look" in said.text
            finally:
                await lab.finish()

        asyncio.run(main())


# ---------------------------------------------------------------------- in the brief, as data


def test_recon_never_carries_a_flag_and_raises_no_candidate(tmp_path):
    tried: list[str] = []
    decoy = "Files: note.txt holds t{decoy_flag}, a decoy.\nFirst steps: do not submit t{decoy_flag}; decode the rest."
    lanes = FakeModelServer(responder=looping)
    with lanes, LightModel({"recon": decoy}) as light:
        async def main():
            lab = Lab(tmp_path, lanes, note_handout(tmp_path), lights=lights(light.engine(), ("recon",)), submit="auto",
                      verify=lambda cid, flag: tried.append(flag) or False)
            try:
                lab.release(challenge("note", "misc", NOTE))
                lane = await opened_after_the_first_look(lab)
                await until(lambda: len(lanes.chats()) >= 3, "three model calls")
                inside = first_look_of(brief_of(lanes.chats()[0]))
                assert "t{decoy_flag}" not in brief_of(lanes.chats()[0])
                assert inside == ("Files: note.txt holds [flag-shaped text removed], a decoy.\n"
                                  "First steps: do not submit [flag-shaped text removed]; decode the rest.")
                assert lane.pending is None and lane.alert(AlertKind.FLAG) is None and tried == []
                assert not [e for e in lab.deck.events if e.kind in (EventKind.SUBMIT, EventKind.PENDING)]
            finally:
                await lab.finish()

        asyncio.run(main())


def test_a_late_recon_does_not_delay_the_first_call_and_is_not_added_later(tmp_path):
    gate = threading.Event()
    lanes = FakeModelServer(responder=looping)
    with lanes, LightModel({"recon": BRIEF}, gate=gate) as light:
        async def main():
            lab = Lab(tmp_path, lanes, note_handout(tmp_path), lights=lights(light.engine(), ("recon",)))
            try:
                lab.release(challenge("note", "misc", NOTE))
                lane = lab.lane("note")
                await until(lambda: lanes.chats(), "the lane's first model call")
                assert brief_of(lanes.chats()[0]) == TODAY  # it went while the brief was still being written
                await until(lambda: light.asked() == ["recon"], "the recon job")
                gate.set()
                await until(lambda: lab.looked("note") and any("recon" in e.data["why"] for e in lab.spends()),
                            "the late brief, and its spend")
                calls = len(lanes.chats())
                await until(lambda: len(lanes.chats()) >= calls + 2, "two more turns")
                assert lab.deck.apply(iv.Escalate(lane.id)).ok
                await until(lambda: any(c["json"]["model"] == "big" for c in lanes.chats()), "the stronger model's call")
                assert {brief_of(c) for c in lanes.chats()} == {TODAY}  # never added: not mid-lane, not at escalation
                assert "the light model's recon was not back by its first model call: its brief goes without it" in notes(lane)
            finally:
                await lab.finish()

        asyncio.run(main())


def test_escalation_and_refresh_reuse_the_same_recon(tmp_path):
    replies = [tool_call_reply("shell", {"command": "echo one"}, prompt_tokens=60_000)]  # past compact_at: a refresh

    def lanes_reply(record):
        return replies.pop(0) if replies else looping(record)

    lanes = FakeModelServer(responder=lanes_reply)
    with lanes, LightModel({"family": "classical-crypto", "recon": BRIEF}) as light:
        async def main():
            lab = Lab(tmp_path, lanes, note_handout(tmp_path), lights=lights(light.engine()))
            try:
                lab.release(challenge("note", "misc", NOTE))
                lane = await opened_after_the_first_look(lab)
                await until(lambda: len(lanes.chats()) >= 2, "the call after the refresh")
                first, second = (c["json"]["messages"] for c in lanes.chats()[:2])
                assert first_look_of(first[1]["content"]) == (
                    "Specialist it suits: classical-crypto (classical ciphers and encodings: Caesar, Vigenere, substitution, "
                    "XOR, base64)\n" + BRIEF)
                assert "The player asked you to take this approach" not in first[1]["content"]  # never the approach
                assert second[:2] == first[:2] and "60,000 prompt tokens" in second[-1]["content"]  # the same prefix
                assert lab.deck.apply(iv.Escalate(lane.id)).ok
                await until(lambda: any(c["json"]["model"] == "big" for c in lanes.chats()), "the stronger model's call")
                big = next(c for c in lanes.chats() if c["json"]["model"] == "big")["json"]["messages"]
                assert big[:2] == first[:2] and "Another model worked on this challenge before you" in big[2]["content"]
                assert sorted(light.asked()) == ["family", "recon"]  # asked once: the lane reuses what it took
            finally:
                await lab.finish()

        asyncio.run(main())


def test_recon_is_cut_at_its_cap(tmp_path):
    long = "\n".join(f"Step {n}: look at the bytes at offset {n * 16} and compare them with the header." for n in range(80))
    lanes = FakeModelServer(responder=looping)
    with lanes, LightModel({"recon": long}) as light:
        async def main():
            lab = Lab(tmp_path, lanes, note_handout(tmp_path), lights=lights(light.engine(), ("recon",)))
            try:
                lab.release(challenge("note", "misc", NOTE))
                await opened_after_the_first_look(lab)
                await until(lambda: lanes.chats(), "the lane's first model call")
                inside = first_look_of(brief_of(lanes.chats()[0]))
                assert len(inside) <= BRIEF_CHARS
                *kept, last = inside.splitlines()
                assert last == f"[cut: the light model's brief ran to {len(long):,} characters]"
                assert kept == long.splitlines()[: len(kept)] and len(kept) > 5  # whole lines, the first ones
            finally:
                await lab.finish()

        asyncio.run(main())
