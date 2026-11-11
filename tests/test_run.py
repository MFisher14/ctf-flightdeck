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
            first = server.requests[0]["json"]
            assert first["model"] == "fake/small" and "authorization" not in server.requests[0]["headers"]

    asyncio.run(main())


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


@pytest.mark.parametrize("urls, network", [((), "none"), (("http://127.0.0.1:8080",), "bridge")])
def test_a_docker_run_builds_lanes_with_that_network(tmp_path, urls, network):
    reason = docker_unavailable()
    if reason:
        pytest.skip(f"not run: {reason}")
    if not _image_present("debian:bookworm-slim"):
        pytest.skip("not run: the image debian:bookworm-slim is not on this machine")
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path, urls=urls), config=config(tmp_path, server.base_url, runtime="docker")))
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


def test_a_run_notes_models_with_no_known_price_when_the_api_may_not_report_one(tmp_path):
    with FakeModelServer() as server:
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
        assert server.requests == []
    l1 = [json.loads(line) for line in run.log.path.read_text().splitlines() if '"kind": "l1"' in line]
    assert [(e["data"]["engine"], e["data"]["status"]) for e in l1] == [("reader", "solved")]


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
