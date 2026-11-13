"""A rotating flag on real lanes: flightdeck's own loop against a fake model server, a
coding-agent CLI lane against the fake CLI, and the mock's scripted lane. Each hears, in
flightdeck's words, that its flag rotated out and was not submitted; the brief of the lane of
a rotating challenge says how to submit such a flag."""

from __future__ import annotations

from ctf_flightdeck.agent import prompts
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import QueueEntry
from ctf_flightdeck.core.model import Challenge
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld

import test_agent_driver as loop
import test_external as cli
from fake_model import FakeModelServer, text_reply, tool_call_reply

NOTE = ("Note from flightdeck: t{wrong} was not submitted: this challenge's flag rotates every 300 seconds, and that one's "
        "window was over, or about to end, when its turn came. It was not judged. Fetch a fresh flag now and submit it at once.")


class Wall:
    def __init__(self) -> None:
        self.t = 1_000_020.0

    def __call__(self) -> float:
        return self.t


def release_rotating(lab, wall: Wall):
    lab.deck.wall = wall
    lab.deck.release([Challenge("note", "Note", "misc", 50, solves=10, description="About note.", rotates=300)],
                     [QueueEntry("note", "small")])
    return lab.lane()


def test_a_lane_of_flightdecks_own_loop_reads_the_rule_in_its_brief_and_hears_when_its_flag_rotated_out(tmp_path):
    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": "t{wrong}"}), text_reply("ok")])

    async def main():
        with server:
            lab = loop.Lab(tmp_path, server)
            wall = Wall()
            lane = release_rotating(lab, wall)
            await loop.until(lambda: lane.pending is not None, "the candidate flag")
            first = [m["content"] for m in server.requests[0]["json"]["messages"] if m["role"] == "user"][0]
            assert first.split(prompts.FENCE_CLOSE)[1].strip() == prompts.rotates(300)
            wall.t += 400  # the approval comes in a later window
            assert not lab.deck.apply(iv.Approve(lane.id)).ok
            await loop.until(lambda: len(server.requests) >= 2, "the next model call")
            assert NOTE in loop.last_user(server.requests[1])
            assert "is not correct" not in loop.last_user(server.requests[1])  # nothing was judged
            await lab.finish()

    loop.run(main())


def test_a_coding_agent_lane_hears_at_once_that_its_flag_rotated_out(tmp_path):
    script = {"turns": [
        {"calls": [{"tools": [cli.bash("echo t{wrong}")]}, {"think": 5.0, "text": "still on it"}]},
        {"calls": [{"tools": [cli.bash("echo next")]}]},
    ]}

    async def main():
        lab = cli.Lab(tmp_path, script)
        try:
            wall = Wall()
            lane = release_rotating(lab, wall)
            await cli.until(lambda: lane.pending is not None, "the candidate")
            assert prompts.rotates(300) in lab.fake.messages()[0]
            wall.t += 400
            assert not lab.deck.apply(iv.Approve(lane.id)).ok
            await cli.until(lambda: len(lab.fake.messages()) >= 2, "the next message")
            assert lab.fake.messages()[1] == NOTE
        finally:
            await lab.finish()

    cli.run(main())


def test_the_mocks_scripted_lane_takes_a_step_for_a_flag_that_rotated_out():
    world = FakeWorld(scenarios.default())
    lane = next(lane for lane in world.deck.lanes.values() if not lane.finished)
    world.driver.rotated(lane, "t{old}", 300)
    assert world.driver.runs[lane.id].inserted[-1].do == "t{old} rotated out before it was sent; fetching a fresh one"
