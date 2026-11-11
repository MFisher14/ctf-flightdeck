"""A real run wired together: config, folder board, agent lanes, event log and console,
against the fake model server (no spend), on host workspaces in tmp_path."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.agent.workspace import DockerWorkspace, docker_unavailable
from ctf_flightdeck.core.model import ChallengeStatus, EventKind, LaneState
from ctf_flightdeck.lane import IMAGE, build_command, dockerfile
from ctf_flightdeck.run import RunError, RunOptions, lane_network, prepare_run

from fake_model import FakeModelServer, tool_call_reply

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
    assert "\nLive instance: tcp://127.0.0.1:1337 (nc 127.0.0.1 1337)\n" in first["json"]["messages"][1]["content"]
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


def test_a_coding_agent_lane_cannot_be_held_to_an_instance_policy(tmp_path, fake_claude):
    with FakeModelServer() as server:
        with pytest.raises(RunError, match='the instance policy is "confirm", but a claude lane reaches whatever its CLI can reach'):
            prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url),
                                   agent="claude", runtime="host", instance="confirm"))


def test_codex_lanes_need_their_ladder_in_the_config(tmp_path):
    with FakeModelServer() as server:
        with pytest.raises(RunError, match=r"no model ladder for codex lanes: add \[agents\] codex"):
            prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), agent="codex", runtime="host"))


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
