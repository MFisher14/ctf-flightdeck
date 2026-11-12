"""The instance rule (no model): a TCP service a challenge's description names (`nc host port`)
that the board does not list as its instance raises a note for the player at the lane's start,
and opens nothing: no network, the http tool still off, the challenge's instances unchanged.

A real Deck and the agent driver against a fake OpenAI-compatible server on 127.0.0.1, lanes in
host workspaces under tmp_path; a run end to end with prepare_run. Every host is under .test.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent.client import ModelClient
from ctf_flightdeck.agent.driver import AgentDriver, instance_note, unlisted_services
from ctf_flightdeck.agent.workspace import DockerWorkspace, HostWorkspace
from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import ActionKind, Challenge, DeckConfig, PendingKind
from ctf_flightdeck.run import RunOptions, lane_network, prepare_run
from fake_model import FakeModelServer, text_reply, tool_call_reply, tool_calls_reply

GATE = "The gate opens only for the right password. The checker binary is attached; nc gate.chal.example.test 6000"
NOTE = ("the description names tcp://gate.chal.example.test:6000 (nc gate.chal.example.test 6000), which the board does "
        "not list as this challenge's instance: flightdeck does not give it to this lane as its instance. If it is the "
        "challenge's instance, add it to \"urls\" in its challenge.json; flightdeck opens nothing and adds no instance on "
        "its own")


async def until(cond, what: str, timeout: float = 20.0) -> None:
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.01)


class Recording(HostWorkspace):
    """A host workspace that notes every attempt to give it a network (a docker lane's
    connect_network, which the driver calls once the player allows the live instance)."""

    connected: list[str] = []

    async def connect_network(self, network: str) -> None:
        Recording.connected.append(network)


def notes(lane) -> list[str]:
    return [a.text for a in lane.actions if a.kind is ActionKind.NOTE]


def lane_run(tmp_path: Path, description: str, *, urls=None, instance: str = "auto", replies=()):
    """One lane on a challenge with `description`; returns the lane, the driver, the requests the
    lane's model got and the results of its tool calls, once its replies have run out."""
    folder = tmp_path / "board" / "gate"
    folder.mkdir(parents=True)
    (folder / "checker").write_text("not really a binary\n")
    Recording.connected = []

    async def main():
        with FakeModelServer([*replies, text_reply("done"), text_reply("done"), text_reply("done")]) as server:
            client = ModelClient(server.base_url, "sk-test-not-a-real-key", max_retries=0)
            driver = AgentDriver(client, lambda lane, ch: Recording(tmp_path / "runs" / lane.id / "work", folder),
                                 run_id="run1", files={"gate": ["checker"]}, urls=urls, instance=instance)
            deck = Deck(DeckConfig(event="t", models=("small", "big"), max_lanes=1), driver, RunClock(),
                        lambda cid, flag: None)
            deck.release([Challenge("gate", "Toll Gate", "rev", 100, description=description)], [QueueEntry("gate", "small")])
            (lane,) = deck.lanes.values()
            try:
                await until(lambda: lane.finished, "the lane to end")
                return lane, driver, server.chats()
            finally:
                await driver.shutdown()
                await client.aclose()

    return asyncio.run(main())


def tool_results(requests: list[dict]) -> list[str]:
    return [m["content"] for m in requests[-1]["json"]["messages"] if m["role"] == "tool"]


@pytest.mark.parametrize("instance", ["auto", "confirm"])
def test_nc_in_the_description_raises_a_note_and_opens_nothing(tmp_path, instance):
    calls = tool_calls_reply([("shell", {"command": "echo hi"}),
                              ("http", {"method": "GET", "url": "http://gate.chal.example.test:6000/"})])
    lane, driver, requests = lane_run(tmp_path, GATE, instance=instance, replies=[calls])
    assert notes(lane).count(NOTE) == 1 and notes(lane)[0] == NOTE  # said at the lane's start, once
    assert driver.urls == {}  # no instance added for it
    run = driver.runs[lane.id]
    assert run.toolbox.http_allow == {} and run.instance == ""  # nothing opened, nothing asked
    assert not any(p.kind is PendingKind.LIVE_BOX for p in [lane.pending, *lane.waiting] if p is not None)
    assert Recording.connected == []  # no network given
    brief = requests[0]["json"]["messages"][1]["content"]
    assert "Live instance: none" in brief
    shell, http = tool_results(requests)
    assert shell.startswith("exit 0") and http == "error: http is off: this challenge has no instance to reach"


def test_a_service_the_board_lists_or_a_web_address_raises_no_note(tmp_path):
    lane, driver, _ = lane_run(tmp_path, GATE, urls={"gate": ["tcp://gate.chal.example.test:6000"]})
    assert not any("the description names" in n for n in notes(lane))
    lane, _, _ = lane_run(tmp_path / "web", "Log in at https://shop.chal.example.test/ as admin.")
    assert not any("the description names" in n for n in notes(lane))


def test_when_the_event_keeps_lanes_off_every_instance_no_note_is_raised(tmp_path):
    lane, _, _ = lane_run(tmp_path, GATE, instance="off")
    assert not any("the description names" in n for n in notes(lane))


def test_unlisted_services_reads_connection_info_written_in_a_description():
    text = ("Connect with nc a.chal.example.test 1337, or ncat --ssl b.chal.example.test 443; the relay is "
            "socat - TCP:c.chal.example.test:31337. Docs: https://d.chal.example.test:8443/ and nc a.chal.example.test 1337")
    assert unlisted_services(text, ("tcp://b.chal.example.test:443", "https://d.chal.example.test:8443")) == (
        "tcp://a.chal.example.test:1337", "tcp://c.chal.example.test:31337")
    assert unlisted_services("telnet e.chal.example.test 23 or openssl s_client -connect f.chal.example.test:4433", ()) == (
        "tcp://e.chal.example.test:23", "tcp://f.chal.example.test:4433")
    assert unlisted_services("No server: everything is in the attached file.", ()) == ()


@pytest.mark.parametrize("text", [
    "The crash is at vuln.c:57; the binary is attached.",
    "Hint: look at main.rs:120 and lib.rs:44.",
    "Our logger writes to app.log:1 every minute. Find the leak.",
    "The service runs at g.chal.example.test:1337.",  # a bare HOST:PORT: a description names a service with a command
    "A local copy listens on localhost:31337 when you run ./server",
    "Run ./server, then nc localhost 31337 to try it before the real one.",
    "I tested it with nc 127.0.0.1 9000 before shipping.",
    "Locally the relay is socat - TCP:[::1]:9000.",
])
def test_a_line_of_source_a_bare_address_or_a_local_copy_is_no_service_to_note(text):
    """In a description a bare HOST:PORT is often a line of source (vuln.c:57), and a loopback
    address is a copy of the service the player runs on their own machine: neither is an
    instance the board might be missing."""
    assert unlisted_services(text, ()) == ()


def test_a_lane_on_a_challenge_that_names_its_source_lines_and_a_local_copy_gets_no_note(tmp_path):
    lane, _, _ = lane_run(tmp_path, "The crash is at vuln.c:57 (see main.rs:120). Run ./checker, then nc localhost "
                                    "31337 to try your input on it.")
    assert not any("the description names" in n for n in notes(lane))


def test_in_a_container_with_no_network_the_note_says_the_lane_cannot_reach_it(tmp_path):
    services = ("tcp://a.chal.example.test:1337", "tcp://c.chal.example.test:31337")
    boxed = DockerWorkspace(tmp_path / "w", tmp_path, image="debian:bookworm-slim", name="flightdeck-test-l01",
                            network="none")
    said = instance_note(services, boxed)
    assert said.startswith("the description names tcp://a.chal.example.test:1337 (nc a.chal.example.test 1337), "
                           "tcp://c.chal.example.test:31337 (nc c.chal.example.test 31337), which the board does not list")
    assert "this lane's container has no network, so it cannot reach them. If they are the challenge's instance" in said
    networked = DockerWorkspace(tmp_path / "w", tmp_path, image="debian:bookworm-slim", name="flightdeck-test-l02")
    assert "flightdeck does not give them to this lane as its instance" in instance_note(services, networked)


def test_a_run_notes_the_service_and_its_lanes_stay_without_an_instance(tmp_path):
    root = tmp_path / "board"
    folder = root / "gate"
    folder.mkdir(parents=True)
    (folder / "checker").write_text("not really a binary\n")
    (folder / "challenge.json").write_text(json.dumps({"name": "Toll Gate", "category": "rev", "points": 100,
                                                       "description": GATE}))
    (root / "board.json").write_text(json.dumps({"event": "Instance Test", "flag_format": r"t\{[a-z0-9_]+\}"}))
    with FakeModelServer(responder=lambda r: time.sleep(0.05) or tool_call_reply("set_plan", {"plan": "look"})) as lanes:
        path = tmp_path / "config.toml"
        path.write_text(
            f'[api]\nbase_url = "{lanes.base_url}"\nkey_env = ""\n[models]\nladder = ["fake/small", "fake/big"]\n'
            '[lanes]\nmax_lanes = 1\nruntime = "host"\ntoken_cap = false\ndollar_cap = false\n'
            f'[run]\ndir = "{tmp_path / "runs"}"\n'
        )
        run = prepare_run(RunOptions(board=root, config=path))

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            await until(lambda: any(n.startswith("the description names") for n in notes(lane)), "the note")
            await run.shutdown()
            return lane

        lane = asyncio.run(main())
        run.close()
    assert NOTE in notes(lane)
    (cid,) = run.driver.urls
    assert run.driver.urls[cid] == () and lane_network(run.driver.urls[cid]) == "none"  # a docker lane would get none
