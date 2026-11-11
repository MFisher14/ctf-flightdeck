"""A real run wired together: config, folder board, agent lanes, event log and console,
against the fake model server (no spend), on host workspaces in tmp_path."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.agent.workspace import DockerWorkspace, docker_unavailable
from ctf_flightdeck.core.model import ChallengeStatus, EventKind, LaneState
from ctf_flightdeck.lane import IMAGE, build_command, dockerfile
from ctf_flightdeck.pricing import Price
from ctf_flightdeck.run import RunError, RunOptions, lane_network, prepare_run

from fake_model import FakeModelServer, FakeReply, tool_call_reply

FLAG = "t{note}"
LADDER = ("fake/small", "fake/big")  # the test config's


def board(tmp_path: Path, *, urls: tuple[str, ...] = ()) -> Path:
    root = tmp_path / "board"
    folder = root / "note"
    folder.mkdir(parents=True)
    (folder / "note.txt").write_text(f"the flag is {FLAG}\n")
    spec = {"name": "Note", "category": "misc", "points": 50, "solves": 9, "description": "Read the note."}
    if urls:
        spec["urls"] = list(urls)
    (folder / "challenge.json").write_text(json.dumps(spec))
    (root / "board.json").write_text(json.dumps({"event": "Test Event", "flag_format": r"t\{[a-z0-9_]+\}"}))
    (root / "answers.sha256.json").write_text(json.dumps({"note": hashlib.sha256(FLAG.encode()).hexdigest()}))
    return root


def config(tmp_path: Path, base_url: str, *, runtime: str = "host", image: str = "debian:bookworm-slim", key_env: str = "") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[api]\nbase_url = "{base_url}"\nkey_env = "{key_env}"\n'
        '[models]\nladder = ["fake/small", "fake/big"]\n'
        '[prices."fake/small"]\ninput = 1.0\noutput = 2.0\n'
        f'[lanes]\nmax_lanes = 2\nruntime = "{runtime}"\nimage = "{image}"\n'
        f'[run]\ndir = "{tmp_path / "runs"}"\n'
    )
    return path


def test_a_run_plays_a_lane_from_the_board_to_a_solve_through_the_console(tmp_path):
    server = FakeModelServer([
        tool_call_reply("shell", {"command": "cat note.txt"}),
        tool_call_reply("submit_flag", {"flag": FLAG}),
    ])

    async def main():
        with server:
            run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
            assert run.runtime == "host" and run.model == "fake/small"
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                deck = run.deck
                (lane,) = deck.lanes.values()  # released on the console's loop by on_start
                for _ in range(500):
                    if lane.pending is not None:
                        break
                    await pilot.pause(0.01)
                assert lane.pending is not None and lane.pending.flag == FLAG
                app.refresh_view()
                app.fleet.select_lane(lane.id)
                await pilot.pause()
                await pilot.press("1")  # quick answer: submit it
                await pilot.pause()
                assert lane.state is LaneState.SOLVED
                assert deck.challenges["note"].status is ChallengeStatus.SOLVED
                await pilot.press("q")
                for _ in range(200):
                    if not app.is_running:
                        break
                    await pilot.pause(0.01)
            run.close()
            lines = [json.loads(line) for line in run.log.path.read_text().splitlines()]
            kinds = [line["kind"] for line in lines]
            assert kinds[0] == "run-start" and kinds[-1] == "run-end"
            assert EventKind.RELEASE.value in kinds and EventKind.LANE_START.value in kinds
            submit = next(line for line in lines if line["kind"] == EventKind.SUBMIT.value)
            assert submit["data"]["correct"] is True and submit["data"]["by"] == "platform"
            assert all(run.driver.runs[x].closed for x in run.driver.runs)
            transcript = [json.loads(line) for line in (run.dir / "lanes" / f"{lane.id}.jsonl").read_text().splitlines()]
            head, steps = transcript[0], [x for x in transcript[1:] if "kind" in x]
            assert (head["lane"], head["challenge"], head["state"]) == (lane.id, "note", "solved")
            cat = next(x for x in steps if x["text"] == "$ cat note.txt")
            assert cat["kind"] == "step" and f"the flag is {FLAG}" in cat["output"]
            chat = server.chats()[0]
            assert chat["json"]["model"] == "fake/small" and "authorization" not in chat["headers"]
            assert server.requests[0]["path"] == "/v1/models"  # asked before anything started

    asyncio.run(main())


def test_play_names_a_flag_left_waiting_for_approval_when_the_player_quits(tmp_path, monkeypatch):
    """Quitting stops the lane with its flag never submitted: play says which, as it exits."""
    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.console.screens import QuitPrompt

    def player(self, *args, **kwargs) -> None:  # the console, headless, with a player who quits
        async def main() -> None:
            async with self.run_test(size=(160, 46)) as pilot:
                for _ in range(500):
                    if any(lane.pending is not None for lane in self.deck.lanes.values()):
                        break
                    await pilot.pause(0.01)
                await pilot.press("q")
                await pilot.pause()
                assert isinstance(self.screen, QuitPrompt)
                await pilot.press("y")
                for _ in range(200):
                    if not self.is_running:
                        break
                    await pilot.pause(0.01)

        asyncio.run(main())

    monkeypatch.setattr(FlightdeckApp, "run", player)
    root = board(tmp_path)
    spec = root / "note" / "challenge.json"
    spec.write_text(json.dumps({**json.loads(spec.read_text()), "name": "Note\x1b]0;pwned\x07"}))  # board text is untrusted
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})]) as server:
        result = CliRunner().invoke(cli.app, ["play", str(root), "--config", str(config(tmp_path, server.base_url))])
    assert result.exit_code == 0, result.output
    expected = f"flightdeck: not submitted, still waiting for your approval when the run ended: L01 Note^[]0;pwned^G: {FLAG}"
    assert expected in result.stderr, result.stderr
    assert "\x1b" not in result.output + result.stderr and "\x07" not in result.output + result.stderr


def headless(monkeypatch, player) -> None:
    """`play` opens the console headless (160x46) and `player(app, pilot)` plays it; then the
    console is given time to quit, as `q` with no lane open does."""
    from ctf_flightdeck.console.app import FlightdeckApp

    def run(self, *args, **kwargs) -> None:
        async def main() -> None:
            async with self.run_test(size=(160, 46)) as pilot:
                await player(self, pilot)
                for _ in range(400):
                    if not self.is_running:
                        break
                    await pilot.pause(0.01)

        asyncio.run(main())

    monkeypatch.setattr(FlightdeckApp, "run", run)


async def until(pilot, cond, what: str, seconds: float = 20.0) -> None:
    for _ in range(int(seconds / 0.02)):
        if cond():
            return
        await pilot.pause(0.02)
    raise AssertionError(f"{what}: not within {seconds} s")


async def solve_then_quit(app, pilot) -> None:
    """The lane submits its flag; then the player quits. The board's note.txt holds the flag
    word for word, so even under submit auto the flag waits for the player (a flag the
    challenge's own files hold is usually a stand-in): the player approves it."""
    lanes = app.deck.lanes.values
    await until(pilot, lambda: any(lane.state is LaneState.SOLVED or lane.pending is not None for lane in lanes()),
                "the flag")
    waiting = next((lane for lane in lanes() if lane.pending is not None), None)
    if waiting is not None:
        assert waiting.pending.flag == FLAG
        app.refresh_view()
        app.fleet.select_lane(waiting.id)
        await pilot.pause()
        await pilot.press("1")  # quick answer: submit it
    await until(pilot, lambda: any(lane.state is LaneState.SOLVED for lane in lanes()), "the solve")
    await pilot.press("q")


async def flag_then_quit(app, pilot) -> None:
    """The lane's flag waits for the player (a board with no answers cannot check it), who quits all the same."""
    await until(pilot, lambda: any(lane.pending is not None for lane in app.deck.lanes.values()), "the flag's approval")
    await pilot.press("q")
    await pilot.pause()
    await pilot.press("y")


def next_steps(stdout: str) -> tuple[Path, list[str]]:
    """The run folder `play` printed after the run log line, and the commands it said come next."""
    lines = stdout.splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith("run log: "))
    assert lines[at + 1].startswith("run folder: ") and lines[at + 2] == "next:", lines[at:]
    folder = Path(lines[at + 1].removeprefix("run folder: "))
    assert lines[at] == f"run log: {folder / 'events.jsonl'}"
    commands = []
    for line in lines[at + 3:]:
        if not line.startswith("  flightdeck "):
            break
        commands.append(re.split(r"\s{2,}", line.strip())[0])
    return folder, commands


def test_play_ends_with_the_run_folder_and_the_commands_that_read_it_and_each_works_as_printed(tmp_path, monkeypatch):
    headless(monkeypatch, solve_then_quit)
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})]) as server:
        result = CliRunner().invoke(cli.app, ["play", str(board(tmp_path)), "--config", str(config(tmp_path, server.base_url)),
                                              "--submit", "auto"])
    assert result.exit_code == 0, result.output
    folder, commands = next_steps(result.stdout)
    assert folder.parent == tmp_path / "runs" and (folder / "events.jsonl").is_file()
    assert result.stdout.index("solved 1 of 1") < result.stdout.index("run log: ")  # the scorecard comes first
    assert commands == [f"flightdeck {name} {folder}" for name in ("report", "writeups", "gaps", "score")]
    for command in commands:
        ran = CliRunner().invoke(cli.app, shlex.split(command)[1:])
        assert ran.exit_code == 0, (command, ran.output)
    assert (folder / "report.md").is_file() and (folder / "gaps.md").is_file() and list((folder / "writeups").iterdir())


def test_play_offers_score_only_for_a_board_with_answers_and_finds_an_answers_file_given_with_the_option(tmp_path, monkeypatch):
    root = board(tmp_path)
    answers = tmp_path / "answers.json"
    (root / "answers.sha256.json").rename(answers)  # the board has none of its own now
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})] * 2) as server:
        cfg = str(config(tmp_path, server.base_url))
        headless(monkeypatch, flag_then_quit)
        plain = CliRunner().invoke(cli.app, ["play", str(root), "--config", cfg, "--submit", "auto"])
        headless(monkeypatch, solve_then_quit)
        given = CliRunner().invoke(cli.app, ["play", str(root), "--config", cfg, "--submit", "auto", "--answers", str(answers)])
    assert plain.exit_code == 0 and given.exit_code == 0, plain.output + given.output
    _, commands = next_steps(plain.stdout)
    assert [command.split()[1] for command in commands] == ["report", "writeups", "gaps"]  # nothing to score against
    folder, commands = next_steps(given.stdout)
    assert commands[-1] == f"flightdeck score {folder}"
    scored = CliRunner().invoke(cli.app, shlex.split(commands[-1])[1:])
    assert scored.exit_code == 0 and "Flags checked against answers.json" in scored.stdout, scored.output


def test_play_quotes_a_run_folder_with_a_space_so_its_commands_paste_whole(tmp_path, monkeypatch):
    headless(monkeypatch, solve_then_quit)
    cfg = config(tmp_path, "http://127.0.0.1:9/v1")
    runs = tmp_path / "my runs"
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})]) as server:
        cfg.write_text(cfg.read_text().replace("http://127.0.0.1:9/v1", server.base_url).replace(str(tmp_path / "runs"), str(runs)))
        result = CliRunner().invoke(cli.app, ["play", str(board(tmp_path)), "--config", str(cfg), "--submit", "auto"])
    assert result.exit_code == 0, result.output
    folder, commands = next_steps(result.stdout)
    assert folder.parent == runs and commands[0] == f"flightdeck report '{folder}'"
    assert CliRunner().invoke(cli.app, shlex.split(commands[0])[1:]).exit_code == 0


def test_play_says_why_the_queue_was_held_when_the_run_ended_after_the_scorecard(tmp_path, monkeypatch):
    """Every model call is refused (HTTP 401): the first lanes end, the queue is held, and the
    player quits. play says the queue was held, why, and what never started."""
    root = board(tmp_path)
    for name in ("memo", "list"):
        (root / name).mkdir()
        (root / name / "challenge.json").write_text(json.dumps({"name": name.title(), "category": "misc", "points": 100}))

    async def player(app, pilot) -> None:
        await until(pilot, lambda: app.deck.held and all(lane.finished for lane in app.deck.lanes.values()), "the hold")
        await pilot.press("q")

    headless(monkeypatch, player)
    refused = FakeReply(401, {"error": {"message": "No auth credentials found"}})
    with FakeModelServer(responder=lambda record: refused) as server:
        result = CliRunner().invoke(cli.app, ["play", str(root), "--config", str(config(tmp_path, server.base_url))])
    assert result.exit_code == 0, result.output
    said = re.search(r"flightdeck: the queue was held when the run ended \(1 challenge queued, not started\): L0[12]'s "
                     r"call to fake/small failed in a way every lane would \(check the API key\): .*HTTP 401", result.stderr)
    assert said is not None, result.stderr  # the lane that hit it first: two started at once
    out = result.output  # stdout and stderr, in the order they were written
    assert out.index("Test Event: solved 0 of 3") < out.index(said.group(0)) < out.index("run log: ")  # after the scorecard


def test_play_says_nothing_of_a_hold_the_player_lifted(tmp_path, monkeypatch):
    async def player(app, pilot) -> None:
        app.deck.hold_queue("the model API does not answer: is it running, and is base_url right?")
        assert app.deck.release_hold().ok
        await solve_then_quit(app, pilot)

    headless(monkeypatch, player)
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})]) as server:
        result = CliRunner().invoke(cli.app, ["play", str(board(tmp_path)), "--config", str(config(tmp_path, server.base_url)),
                                              "--submit", "auto"])
    assert result.exit_code == 0, result.output
    assert "held" not in result.stderr and "run folder: " in result.stdout


def test_practice_ends_as_play_does_with_a_held_queue_the_run_folder_and_the_commands_that_read_it(tmp_path, monkeypatch):
    """practice plays the set that ships with flightdeck. Every model call is refused (HTTP
    401): its two lanes end, the queue is held with twelve challenges in it, and the player
    quits. On the way out it says why the queue was held, then the run folder and the commands,
    score among them (the set has answers), each of which works as printed."""
    async def player(app, pilot) -> None:
        await until(pilot, lambda: app.deck.held and all(lane.finished for lane in app.deck.lanes.values()), "the hold")
        await pilot.press("q")

    headless(monkeypatch, player)
    refused = FakeReply(401, {"error": {"message": "No auth credentials found"}})
    with FakeModelServer(responder=lambda record: refused) as server:
        result = CliRunner().invoke(cli.app, ["practice", "--config", str(config(tmp_path, server.base_url))])
    assert result.exit_code == 0, result.output
    held = "flightdeck: the queue was held when the run ended (12 challenges queued, not started): "
    assert held in result.stderr and "(check the API key)" in result.stderr, result.stderr
    out = result.output
    assert out.index("Practice Range: solved 0 of 14") < out.index(held) < out.index("run log: ")
    folder, commands = next_steps(result.stdout)
    assert commands == [f"flightdeck {name} {folder}" for name in ("report", "writeups", "gaps", "score")]
    for command in commands:
        ran = CliRunner().invoke(cli.app, shlex.split(command)[1:])
        assert ran.exit_code == 0, (command, ran.output)
    assert "Flags checked against answers.sha256.json" in ran.stdout  # score, last: against the set's answers


def test_the_event_log_and_the_lane_workspaces_go_in_a_new_folder_per_run(tmp_path):
    with FakeModelServer() as server:
        cfg = config(tmp_path, server.base_url)
        first = prepare_run(RunOptions(board=board(tmp_path), config=cfg))
        second = prepare_run(RunOptions(board=tmp_path / "board", config=cfg))
        first.close()
        second.close()
    assert first.dir != second.dir and first.dir.parent == second.dir.parent == tmp_path / "runs"
    assert first.log.path == first.dir / "events.jsonl"


@pytest.mark.parametrize(
    "problem, expected",
    [
        ("no-config", "config"),
        ("no-board", "no challenge directories"),
        ("missing-key", "MY_TEST_KEY"),
        ("unknown-model", "not in the ladder"),
    ],
)
def test_a_run_that_cannot_start_says_why(tmp_path, monkeypatch, problem, expected):
    monkeypatch.delenv("MY_TEST_KEY", raising=False)
    root = board(tmp_path)
    options = {"board": root, "config": config(tmp_path, "http://127.0.0.1:9/v1")}
    if problem == "no-config":
        options["config"] = tmp_path / "missing.toml"
    elif problem == "no-board":
        empty = tmp_path / "empty"
        empty.mkdir()
        options["board"] = empty
    elif problem == "missing-key":
        options["config"] = config(tmp_path, "http://127.0.0.1:9/v1", key_env="MY_TEST_KEY")
    elif problem == "unknown-model":
        options["model"] = "fake/huge"
    with pytest.raises(RunError, match=expected):
        prepare_run(RunOptions(**options))


def test_the_api_key_is_read_from_the_variable_the_config_names_and_never_shown(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TEST_KEY", "player-key-NOT-SHOWN-ANYWHERE")
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url, key_env="MY_TEST_KEY")))
        run.close()
    assert "NOT-SHOWN" not in repr(run.client)


def test_docker_lanes_get_a_network_only_when_their_challenge_has_a_live_instance():
    assert lane_network(()) == "none"
    assert lane_network(("http://127.0.0.1:8080",)) == "bridge"


def _image_present(image: str) -> bool:
    import subprocess

    return subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0


@pytest.mark.parametrize(
    "urls, instance, network",
    [
        ((), "auto", "none"),
        (("http://127.0.0.1:8080",), "auto", "bridge"),
        (("http://127.0.0.1:8080",), "confirm", "none"),  # connected when the player allows it
        (("http://127.0.0.1:8080",), "off", "none"),
        (("tcp://127.0.0.1:1337",), "auto", "bridge"),  # what `nc host port` reaches is an instance too
        (("tcp://127.0.0.1:1337",), "confirm", "none"),
        (("tcp://127.0.0.1:1337",), "off", "none"),
    ],
)
def test_a_docker_run_builds_lanes_with_that_network(tmp_path, urls, instance, network):
    reason = docker_unavailable()
    if reason:
        pytest.skip(f"not run: {reason}")
    if not _image_present("debian:bookworm-slim"):
        pytest.skip("not run: the image debian:bookworm-slim is not on this machine")
    with FakeModelServer() as server:
        cfg = config(tmp_path, server.base_url, runtime="docker")
        run = prepare_run(RunOptions(board=board(tmp_path, urls=urls), config=cfg, instance=instance))
        run.close()
    bc = run.board.challenges[0]
    lane = type("L", (), {"id": "L01"})()
    workspace = run.driver.workspaces(lane, bc.challenge)
    assert isinstance(workspace, DockerWorkspace)
    args = workspace.run_args()
    assert args[args.index("--network") + 1] == network


def test_a_docker_run_with_a_missing_image_names_the_command_that_builds_it(tmp_path):
    reason = docker_unavailable()
    if reason:
        pytest.skip(f"not run: {reason}")
    if _image_present(IMAGE):
        pytest.skip(f"not run: {IMAGE} is built on this machine, so it is not missing")
    with pytest.raises(RunError, match="flightdeck image build"):
        prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, "http://127.0.0.1:9/v1", runtime="docker", image=IMAGE)))


def test_the_lane_image_has_the_tools_a_lane_needs_and_builds_from_the_shipped_dockerfile():
    text = dockerfile()
    assert text.startswith("# The lane image") and "FROM debian:bookworm-slim" in text
    for tool in ("python3", "file", "xxd", "binutils", "unzip", "curl", "libimage-exiftool-perl"):
        assert tool in text, tool
    argv = build_command(docker="docker")
    assert argv == ["docker", "build", "--tag", IMAGE, "--file", "Dockerfile", "."]


def test_image_build_without_docker_fails_with_the_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))  # no docker on this PATH
    result = CliRunner().invoke(cli.app, ["image", "build"])
    assert result.exit_code == 2
    assert "needs Docker" in result.output


def test_the_image_dockerfile_command_prints_it():
    result = CliRunner().invoke(cli.app, ["image", "dockerfile"])
    assert result.exit_code == 0 and result.output == dockerfile()


def anthropic_config(tmp_path: Path, claude_url: str, router_url: str, *, spare: str = "anthropic/claude-haiku-5.5") -> Path:
    """Lanes on the Anthropic API (the fake at `claude_url`), with an OpenAI-style fallback at `router_url`."""
    path = tmp_path / "config.toml"
    path.write_text(
        f'[api]\nprovider = "anthropic"\nbase_url = "{claude_url}"\nkey_env = "FD_TEST_CLAUDE_KEY"\n'
        '[models]\nladder = ["claude-haiku-5-5"]\n[prices."claude-haiku-5-5"]\ninput = 0.1\noutput = 0.5\n'
        f'[fallback]\nbase_url = "{router_url}"\nkey_env = "FD_TEST_ROUTER_KEY"\nladder = ["{spare}"]\n'
        f'[lanes]\nruntime = "host"\n[run]\ndir = "{tmp_path / "runs"}"\n'
    )
    return path


def test_a_run_on_anthropic_with_a_fallback_needs_both_keys_and_says_where_a_failing_lane_goes(tmp_path, monkeypatch):
    from ctf_flightdeck.agent.anthropic_client import AnthropicClient
    from ctf_flightdeck.agent.client import ModelClient
    from ctf_flightdeck.agent.fallback import FallbackClient
    from fake_anthropic import FakeAnthropicServer

    monkeypatch.setenv("FD_TEST_CLAUDE_KEY", "fake-claude-key-NOT-SHOWN")
    monkeypatch.delenv("FD_TEST_ROUTER_KEY", raising=False)
    with FakeAnthropicServer(models=["claude-haiku-5-5"], key="fake-claude-key-NOT-SHOWN") as claude, \
            FakeModelServer(models=["anthropic/claude-haiku-5.5"], key="fake-router-key-NOT-SHOWN") as router:
        path = anthropic_config(tmp_path, claude.base_url, router.base_url)
        with pytest.raises(RunError, match="fallback.key_env names the variable FD_TEST_ROUTER_KEY, which is not set"):
            prepare_run(RunOptions(board=board(tmp_path), config=path))
        monkeypatch.setenv("FD_TEST_ROUTER_KEY", "fake-router-key-NOT-SHOWN")
        run = prepare_run(RunOptions(board=tmp_path / "board", config=path))
        run.close()
    try:
        client = run.client
        assert isinstance(client, FallbackClient) and run.driver.client is client
        assert isinstance(client.primary, AnthropicClient) and isinstance(client.fallback, ModelClient)
        assert client.models == {"claude-haiku-5-5": "anthropic/claude-haiku-5.5"}
        primary, spare = client.primary_name, client.fallback_name
        assert f"a lane whose calls to {primary} keep failing moves to {spare} for the rest of its context" in run.notes()
        assert "NOT-SHOWN" not in repr(client)
    finally:
        asyncio.run(client.aclose())
    # both APIs were asked, with their own keys, before anything started
    assert [r["path"].split("?")[0] for r in claude.requests] == ["/v1/models"]
    assert [r["path"] for r in router.requests] == ["/v1/models"]


# ---------------------------------------------------------------------- the model APIs, asked before anything starts


def test_a_model_the_api_does_not_serve_stops_the_run_before_anything_starts(tmp_path):
    with FakeModelServer(models=["fake/small", "fake/bigger"]) as server:
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
    said = str(caught.value)
    assert said.startswith(f"the model API at {server.base_url} does not serve fake/big (closest it lists: fake/bigger, "
                           "fake/small), so every lane on it would fail at its first call")
    assert f"change models.ladder in {tmp_path / 'config.toml'} to ids it serves" in said
    assert server.chats() == [] and not (tmp_path / "runs").exists()


def test_a_key_the_api_refuses_stops_the_run_before_anything_starts_and_is_never_shown(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TEST_KEY", "player-key-NOT-SHOWN-ANYWHERE")
    with FakeModelServer(models=LADDER, key="the-key-this-api-takes") as server:
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url, key_env="MY_TEST_KEY")))
    said = str(caught.value)
    assert said.startswith(f"the model API at {server.base_url} refused the key in MY_TEST_KEY (HTTP 401")
    assert "NOT-SHOWN" not in said and not (tmp_path / "runs").exists()


def test_a_model_server_that_is_not_up_stops_the_run_before_anything_starts(tmp_path):
    with pytest.raises(RunError, match=r"nothing answers at http://127\.0\.0\.1:9/v1 \(ConnectError.*start your local model server"):
        prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, "http://127.0.0.1:9/v1")))
    assert not (tmp_path / "runs").exists()


def test_a_fallback_model_its_api_does_not_serve_stops_the_run_too(tmp_path, monkeypatch):
    from fake_anthropic import FakeAnthropicServer

    monkeypatch.setenv("FD_TEST_CLAUDE_KEY", "fake-claude-key")
    monkeypatch.setenv("FD_TEST_ROUTER_KEY", "fake-router-key")
    with FakeAnthropicServer(models=["claude-haiku-5-5"]) as claude, FakeModelServer(models=["anthropic/claude-haiku-5.5"]) as router:
        path = anthropic_config(tmp_path, claude.base_url, router.base_url, spare="anthropic/claude-haiku-5-5")
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=board(tmp_path), config=path))
    assert str(caught.value).startswith(
        f"the [fallback] API at {router.base_url} does not serve anthropic/claude-haiku-5-5 (closest it lists: "
        "anthropic/claude-haiku-5.5)"
    )
    assert f"change fallback.ladder in {path}" in str(caught.value)


def test_an_api_that_does_not_list_its_models_is_a_note_before_the_console(tmp_path):
    with FakeModelServer() as server:  # answers GET /v1/models with 404
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
        run.close()
    assert any(note.startswith(f"the model API at {server.base_url} does not list its models (GET /models answered HTTP "
                               "404), so flightdeck could not check models.ladder against it") for note in run.notes())


def test_coding_agent_lanes_never_ask_the_api_they_do_not_use(tmp_path, fake_claude):
    run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, "http://127.0.0.1:9/v1"),
                                 agent="claude", runtime="host"))
    run.close()
    assert run.client is None


def test_a_run_notes_models_with_no_known_price_when_the_api_may_not_report_one(tmp_path):
    with FakeModelServer(models=LADDER) as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
        run.close()
    (note,) = run.notes()
    assert "fake/big" in note and "fake/small" not in note  # fake/small has a price in the test config
    assert "asks you once" in note


def test_the_practice_set_ships_with_flightdeck_and_loads_as_a_board():
    from ctf_flightdeck.platform.manual import AnswerVerifier, load_board
    from ctf_flightdeck.practice_set import practice_dir

    folder = practice_dir()
    board = load_board(folder)
    assert board.event == "Practice Range" and len(board.challenges) == 14
    assert board.answers is not None
    assert AnswerVerifier(board.answers).ids == {b.challenge.id for b in board.challenges}


def test_practice_without_a_config_says_how_to_make_one(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "none.toml"))
    result = CliRunner().invoke(cli.app, ["practice"])
    assert result.exit_code == 2
    assert "none.toml" in result.output and "config" in result.output


# ---------------------------------------------------------------------- M2-M3 wiring: L1 first, detectors on


READER = """
    from ctf_flightdeck.l1.result import Evidence, SolverResult

    def solve(challenge_dir):
        flag = (challenge_dir / "note.txt").read_text().split()[-1]
        return SolverResult("solved", flags=[flag], evidence=[Evidence("read", "the note says so", "note.txt", 0)])
    """


async def wait_for(cond, what: str, seconds: float = 20.0) -> None:
    for _ in range(int(seconds * 100)):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def http_at_the_service() -> dict:
    return tool_call_reply("http", {"method": "GET", "url": "http://127.0.0.1:1337/"})


def last_tool_result(request: dict) -> str:
    return [m for m in request["json"]["messages"] if m["role"] == "tool"][-1]["content"]


@pytest.mark.parametrize("instance", ["auto", "confirm"])
def test_a_lane_on_a_tcp_service_is_told_of_it_and_reaches_it_from_the_shell_not_http(tmp_path, instance):
    from ctf_flightdeck.core import interventions as iv
    from ctf_flightdeck.core.model import PendingKind

    with FakeModelServer(models=LADDER, responder=lambda record: http_at_the_service()) as server:
        run = prepare_run(RunOptions(board=board(tmp_path, urls=("tcp://127.0.0.1:1337",)), config=config(tmp_path, server.base_url),
                                     instance=instance))

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            if instance == "confirm":
                await wait_for(lambda: lane.pending is not None, "the live-box question")
                assert lane.pending.kind is PendingKind.LIVE_BOX and server.chats() == []
                assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: len(server.chats()) >= 2, "two model calls")
            assert not lane.finished
            await run.shutdown()

        asyncio.run(main())
        run.close()
    first, second = server.chats()[:2]
    assert "Live instance: tcp://127.0.0.1:1337" in first["json"]["messages"][1]["content"]
    assert "this challenge's instance is not a web server (tcp://127.0.0.1:1337): reach it from the shell" in last_tool_result(second)


def test_a_run_with_an_l1_pack_runs_its_engines_before_any_model_call(tmp_path):
    from l1_kit import python_engine

    pack = tmp_path / "pack"
    python_engine(pack, "reader", READER, route='keywords = ["note"]')
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), pack=pack))
        assert [m.id for m in run.driver.l1.manifests] == ["reader"]
        assert any(note.startswith("L1: 1 engine(s) from your pack run first") for note in run.notes())

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.pending is not None, "the L1 flag's approval")
            assert lane.pending.flag == FLAG
            await run.shutdown()

        asyncio.run(main())
        run.close()
        assert server.chats() == []
    l1 = [json.loads(line) for line in run.log.path.read_text().splitlines() if '"kind": "l1"' in line]
    assert [(e["data"]["engine"], e["data"]["status"]) for e in l1] == [("reader", "solved")]


@pytest.mark.parametrize("runtime", ["host", "docker"])
def test_l1_engines_run_where_the_lanes_do_and_the_notes_say_where(tmp_path, runtime):
    """D17: in Docker each engine runs in a container of the lane image, the pack mounted."""
    from l1_kit import python_engine

    if runtime == "docker":
        reason = docker_unavailable()
        if reason:
            pytest.skip(f"not run: {reason}")
        if not _image_present("debian:bookworm-slim"):
            pytest.skip("not run: the image debian:bookworm-slim is not on this machine")
    pack = tmp_path / "pack"
    python_engine(pack, "reader", READER, route='keywords = ["note"]')
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url, runtime=runtime), pack=pack))
        (note,) = [n for n in run.notes() if n.startswith("L1: ")]
        run.close()
    l1 = run.driver.l1
    if runtime == "docker":
        assert (l1.image, l1.pack) == ("debian:bookworm-slim", pack)
        assert "each in a container of the lane image debian:bookworm-slim with your pack mounted read-only" in note
        assert "no network unless lanes may reach the challenge's live instance at once" in note
    else:
        assert l1.image is None and note.endswith("run first on each challenge, on this machine, as you")


def test_an_l1_pack_that_cannot_be_used_stops_the_run_before_it_starts(tmp_path):
    (tmp_path / "empty").mkdir()
    with FakeModelServer() as server:
        cfg = config(tmp_path, server.base_url)
        with pytest.raises(RunError, match="the L1 pack cannot be used: .*no such pack folder"):
            prepare_run(RunOptions(board=board(tmp_path), config=cfg, pack=tmp_path / "nowhere"))
        with pytest.raises(RunError, match="has no engines .*flightdeck l1 import"):
            prepare_run(RunOptions(board=tmp_path / "board", config=cfg, pack=tmp_path / "empty"))


def test_a_real_run_has_the_course_detectors_watching_its_lanes(tmp_path):
    from ctf_flightdeck.core.model import AlertKind

    with FakeModelServer(responder=lambda record: tool_call_reply("shell", {"command": "ls"})) as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.alert(AlertKind.LOOP) is not None, "the loop alert")
            await run.shutdown()

        asyncio.run(main())
        run.close()


def test_a_run_on_a_board_with_answers_ends_with_a_scorecard(tmp_path):
    from l1_kit import python_engine

    pack = tmp_path / "pack"
    python_engine(pack, "reader", READER, route='keywords = ["note"]')
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), pack=pack))

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.pending is not None, "the L1 flag's approval")
            from ctf_flightdeck.core import interventions as iv

            assert run.deck.apply(iv.Approve(lane.id)).ok
            await run.shutdown()

        asyncio.run(main())
        run.close()
    card = run.scorecard()
    assert card is not None and "solved 1 of 1" in card, card
    assert "Note       misc   50  solved by L1 reader via L01" in card, card  # the L1 engine's flag, as every report credits it


def test_the_console_credits_a_flag_an_l1_engine_found_to_that_engine_as_the_scorecard_does(tmp_path):
    from textual.widgets import DataTable

    from l1_kit import python_engine

    pack = tmp_path / "pack"
    python_engine(pack, "reader", READER, route='keywords = ["note"]')
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), pack=pack))
        app = run.app(refresh_seconds=None)

        async def main():
            async with app.run_test(size=(160, 46)) as pilot:
                await until(pilot, lambda: any(lane.pending is not None for lane in run.deck.lanes.values()), "the L1 flag")
                app.refresh_view()
                await pilot.pause()
                await pilot.press("1")  # the selected lane's quick answer: submit it
                await until(pilot, lambda: run.deck.challenges["note"].closed, "the solve")
                app.refresh_view()
                await pilot.pause()
                own = app.fleet.query_one("#board", DataTable).get_cell("note", "own")
                assert str(own) == "L1·reader"  # not the lane that submitted it, L01
                await pilot.press("q")
                await until(pilot, lambda: not app.is_running, "the console to quit")

        asyncio.run(main())
        run.close()
        assert server.chats() == []  # the engine solved it: no model was asked
    assert "Note       misc   50  solved by L1 reader via L01" in run.scorecard()


# ---------------------------------------------------------------------- coding-agent CLIs as lanes (--agent)


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """A `claude` that does nothing, first on PATH, and no folder holding a real one."""
    bin_dir = tmp_path / "agent-bin"
    bin_dir.mkdir()
    exe = bin_dir / "claude"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    keep = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not any(os.access(os.path.join(d, cli), os.X_OK) for cli in ("claude", "codex"))]
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), *keep]))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-credential-for-tests")
    monkeypatch.delenv("FLIGHTDECK_TEST_UNSET_KEY", raising=False)
    return exe


def test_a_run_with_a_coding_agent_needs_no_api_key_and_uses_the_agents_ladder(tmp_path, fake_claude):
    from ctf_flightdeck.agent.external import ExternalDriver

    with FakeModelServer() as server:
        cfg = config(tmp_path, server.base_url, key_env="FLIGHTDECK_TEST_UNSET_KEY")  # not set, and not needed
        run = prepare_run(RunOptions(board=board(tmp_path), config=cfg, agent="claude", runtime="host"))
        run.close()
    assert isinstance(run.driver, ExternalDriver) and run.client is None
    assert run.deck.config.models == ("sonnet", "opus") and run.model == "sonnet"
    notes = run.notes()
    assert any(note.startswith("lanes are claude on sonnet") for note in notes)
    assert any("claude lanes start on sonnet and escalate to opus" in note for note in notes)
    assert "fake-anthropic-credential-for-tests" not in " ".join(notes)


FAKE_CLI = Path(__file__).with_name("fake_agent_cli.py")  # plays claude and codex: never the real tools


@pytest.fixture
def scripted_claude(tmp_path, monkeypatch):
    """tests/fake_agent_cli.py as `claude`, first on PATH (no folder holding a real one stays
    there): call it with the script it plays. Whatever it left running is killed afterwards."""
    bin_dir = tmp_path / "agent-bin"
    bin_dir.mkdir()
    record = tmp_path / "agent-record.jsonl"

    def play(script: dict) -> None:
        (tmp_path / "agent-script.json").write_text(json.dumps(script))
        env = {"FAKE_AGENT_SCRIPT": str(tmp_path / "agent-script.json"), "FAKE_AGENT_RECORD": str(record),
               "FAKE_AGENT_STATE": str(tmp_path / "agent-state.json")}
        exe = bin_dir / "claude"
        exe.write_text(f"#!{sys.executable} -I\nimport os, sys\nos.environ.update({env!r})\n"
                       f"os.execv(sys.executable, [sys.executable, '-I', {str(FAKE_CLI)!r}, 'claude', *sys.argv[1:]])\n")
        exe.chmod(0o755)

    keep = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not any(os.access(os.path.join(d, cli), os.X_OK) for cli in ("claude", "codex"))]
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), *keep]))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-credential-for-tests")
    yield play
    lines = record.read_text().splitlines() if record.exists() else []
    for pid in {json.loads(line).get("pid") for line in lines if line.strip()}:
        command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True).stdout
        if isinstance(pid, int) and "fake_agent_cli" in command:
            os.kill(pid, signal.SIGKILL)


def test_what_claude_reports_after_its_lane_solved_is_in_the_scorecard_play_prints_and_in_post_flight(tmp_path, scripted_claude):
    """A coding-agent CLI reports a turn's cost when the turn ends, here after the lane solved
    in the middle of it: on the way out (the console's on_exit) that cost reaches the deck,
    the run log and the transcripts, so every summary of the run counts it."""
    from ctf_flightdeck import postflight
    from ctf_flightdeck.core import interventions as iv
    from ctf_flightdeck.runrecord import load_run

    scripted_claude({"turns": [{"calls": [
        {"tools": [{"bash": "cat note.txt"}], "usage": [100, 10, 0, 0], "cost": 0.02},
        {"text": f"FLAG: {FLAG}", "usage": [50, 5, 0, 0], "cost": 0.01},
        {"think": 30.0},  # its turn goes on after the flag
    ]}]})
    with FakeModelServer() as server:  # the config's API, which a claude lane never calls
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), agent="claude",
                                     runtime="host"))

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.pending is not None, "the flag claude claimed")
            assert run.deck.apply(iv.Approve(lane.id)).ok and lane.state is LaneState.SOLVED
            assert lane.dollars_later and lane.dollars == 0.0  # solved mid-turn: claude has not reported its cost yet
            await run.shutdown()  # as play does on the way out

        asyncio.run(main())
        run.close()
    lane = run.deck.lanes["L01"]
    assert (lane.tokens, lane.dollars, lane.dollars_later) == (165, pytest.approx(0.03), False)
    assert run.deck.totals() == (165, pytest.approx(0.03), False)  # the console's header
    card = run.scorecard()
    assert card is not None and "Spent 165 tokens · $0.03 · $0.03 per solve" in card.splitlines(), card
    summary = postflight.summary(load_run(run.dir))
    assert "Spend: 165 tokens (0% cached), $0.03, $0.03 per lane solve" in summary.splitlines(), summary


def test_a_coding_agent_lane_cannot_be_held_to_an_instance_policy(tmp_path, fake_claude):
    with FakeModelServer() as server:
        with pytest.raises(RunError, match='the instance policy is "confirm", but a claude lane reaches whatever its CLI can reach'):
            prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url),
                                   agent="claude", runtime="host", instance="confirm"))


def test_codex_lanes_need_their_ladder_in_the_config(tmp_path):
    with FakeModelServer() as server:
        with pytest.raises(RunError, match=r"no model ladder for codex lanes: add \[agents\] codex"):
            prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), agent="codex", runtime="host"))


@pytest.fixture
def fake_codex(tmp_path, monkeypatch):
    """A `codex` that does nothing, first on PATH, with a key of its own, and no folder holding a real one."""
    bin_dir = tmp_path / "agent-bin"
    bin_dir.mkdir()
    exe = bin_dir / "codex"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    keep = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not any(os.access(os.path.join(d, cli), os.X_OK) for cli in ("claude", "codex"))]
    monkeypatch.setenv("PATH", os.pathsep.join([str(bin_dir), *keep]))
    monkeypatch.setenv("CODEX_API_KEY", "fake-codex-credential-for-tests")
    return exe


def test_codex_lanes_get_the_configs_price_for_their_model_and_play_names_the_models_with_none(tmp_path, fake_codex):
    folder = board(tmp_path)
    with FakeModelServer() as server:
        path = config(tmp_path, server.base_url)
        path.write_text(path.read_text() + '[agents]\ncodex = ["cx-small", "cx-big"]\n[prices.cx-small]\ninput = 1.25\noutput = 10\n')
        run = prepare_run(RunOptions(board=folder, config=path, agent="codex", runtime="host"))
        run.close()
    assert run.deck.config.models == ("cx-small", "cx-big") and run.driver.prices["cx-small"] == Price(input=1.25, output=10.0)
    assert (
        "codex reports its tokens but no cost, and your config has no price for cx-big: a lane on it shows its dollars "
        'as unknown and asks you once before it carries on without its $2 cap; a table like [prices."cx-big"] in your '
        "config (input and output, in dollars per million tokens) prices one"
    ) in run.notes()
    assert "fake-codex-credential-for-tests" not in " ".join(run.notes())
    path.write_text(path.read_text() + '[prices.cx-big]\ninput = 2\noutput = 20\n')  # every model priced: nothing to say
    run = prepare_run(RunOptions(board=folder, config=path, agent="codex", runtime="host"))
    run.close()
    assert not any("no cost" in note for note in run.notes())


def test_docker_agent_lanes_need_the_cli_in_the_lane_image(tmp_path, fake_claude):
    reason = docker_unavailable()
    if reason:
        pytest.skip(f"not run: {reason}")
    if not _image_present("debian:bookworm-slim"):
        pytest.skip("not run: the image debian:bookworm-slim is not on this machine")
    with FakeModelServer() as server:
        cfg = config(tmp_path, server.base_url, runtime="docker")
        with pytest.raises(RunError, match="the lane image debian:bookworm-slim has no claude CLI.*--host"):
            prepare_run(RunOptions(board=board(tmp_path), config=cfg, agent="claude"))
