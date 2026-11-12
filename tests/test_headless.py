"""`play --headless` and `practice --headless`: a run with no console (headless.py).

In-process tests run the real command through Typer's runner on the test's main thread (where
the run's loop takes its signals), against the fake model server, on host workspaces in
tmp_path. The signal tests start the real command as a process of its own, as tmux or nohup
would, with no terminal at all, and are modelled on test_play_signals.py. The docker test runs
only when docker answers and debian:bookworm-slim is already on this machine; otherwise it
reports as not run."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.headless import Headless
from ctf_flightdeck.run import RunOptions, prepare_run

from fake_model import FakeModelServer, FakeReply, text_reply, tool_call_reply
from l1_kit import docker_not_run
from test_play_signals import IMAGE, QUIET, _docker_missing, container_exists, env_for, gone, group_alive, lane_pid_file, make_board, make_config, run_end
from test_run import FLAG, board, config

HIDDEN = "t{not_in_the_handout}"  # a flag the challenge's own files do not hold: auto submit sends it


def status_of(tmp_path: Path) -> dict | None:
    found = sorted((tmp_path / "runs").glob("*/status.json"))
    return json.loads(found[0].read_text()) if found else None


def events_of(tmp_path: Path) -> list[dict]:
    (log,) = (tmp_path / "runs").glob("*/events.jsonl")
    return [json.loads(line) for line in log.read_text().splitlines()]


@pytest.fixture
def flying(monkeypatch) -> dict:
    """Says whether a headless run is flying in this process (its signal handlers are in
    place from then until its loop closes, after the shutdown): the tests signal their own
    process, and must never do so when nothing would catch it. Headless.fly runs as it is."""
    state = {"up": False}
    fly = Headless.fly

    async def noted(self) -> None:
        state["up"] = True
        try:
            await fly(self)
        finally:
            state["up"] = False

    monkeypatch.setattr(Headless, "fly", noted)
    return state


def stop_once(tmp_path: Path, flying: dict, cond, *, after: float = 0.0, sig: int = signal.SIGTERM) -> tuple[threading.Thread, list]:
    """A thread that signals this process once status.json satisfies `cond` (and `after`
    seconds more have passed): what a script watching the status file would do. The signal
    is sent only while the headless run flies; if it is not flying by then, the test fails
    on what `seen` holds instead."""
    seen: list = []

    def watch() -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                doc = status_of(tmp_path)
            except ValueError as exc:  # never: the file is written atomically
                seen.append(exc)
                return
            if doc is not None and cond(doc):
                time.sleep(after)
                seen.append(status_of(tmp_path))
                if flying["up"]:
                    os.kill(os.getpid(), sig)
                else:
                    seen.append("the run was not flying any more: no signal was sent")
                return
            time.sleep(0.05)

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return thread, seen


def test_a_headless_run_leaves_a_flag_waiting_approves_nothing_and_names_it_when_it_is_stopped(tmp_path, flying):
    """The lane finds its flag under submit "confirm": it waits, as at the console. Nobody
    answers, so the run stays up (well past the two polls after which it would end if nothing
    were left to do) until SIGTERM; then it is shut down as quitting does and the exit lines
    name the flag that was never submitted."""
    watcher, seen = stop_once(tmp_path, flying, lambda doc: doc["needs_you"], after=3.0)
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})]) as server:
        result = CliRunner().invoke(cli.app, ["play", str(board(tmp_path)), "--config", str(config(tmp_path, server.base_url)),
                                              "--headless"])
    watcher.join(10)
    assert result.exit_code == 128 + signal.SIGTERM, result.output
    (run_dir,) = (tmp_path / "runs").iterdir()
    start = (f"flightdeck: headless: no console. The run's status is in {run_dir / 'status.json'}, rewritten as the run goes. "
             "Approvals wait: nothing is approved or declined in a headless run, and a flag left waiting is named when the "
             "run ends. It ends on its own once no lane is open and nothing is queued, or when you stop it: SIGTERM "
             f"(kill {os.getpid()}), SIGHUP or Ctrl-C stops every lane as quitting the console does.")
    assert start in result.stderr, result.stderr
    assert "flightdeck: SIGTERM: stopping the lanes and closing their workspaces..." in result.stderr
    assert f"flightdeck: not submitted, still waiting for your approval when the run ended: L01 Note: {FLAG}" in result.stderr
    assert "flightdeck: SIGTERM: the run's lanes were stopped as when you quit" in result.stderr
    assert "Test Event: solved 0 of 1" in result.stdout and f"run log: {run_dir / 'events.jsonl'}" in result.stdout
    # what a reader of the status file saw three seconds after the flag came up: it still waited
    (before,) = seen
    assert before["closed"] is False and before["needs_you"] == [
        {"lane": "L01", "challenge": "Note", "pending": "submit", "alerts": ["flag"]}]
    assert before["lanes"][0]["pending"]["flag"] == FLAG and before["lanes"][0]["state"] == "wait"
    # nothing was approved, declined or submitted, by anyone
    events = events_of(tmp_path)
    kinds = [event["kind"] for event in events]
    assert "pending" in kinds and kinds[-1] == "run-end"
    assert not {"submit", "intervention", "outcome"} & set(kinds)
    after = status_of(tmp_path)
    assert after["closed"] is True and after["lanes"][0]["pending"]["kind"] == "submit" and after["solves"] == []


def hidden_flag_board(tmp_path: Path) -> Path:
    root = board(tmp_path)
    (root / "note" / "note.txt").write_text("nothing to see\n")
    (root / "answers.sha256.json").write_text(json.dumps({"note": hashlib.sha256(HIDDEN.encode()).hexdigest()}))
    return root


def test_a_headless_run_ends_on_its_own_with_exit_0_once_nothing_is_left_to_do(tmp_path):
    """Under submit "auto" the flag goes at once and is accepted: the lane ends, nothing is
    queued, and the run closes without anyone stopping it."""
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": HIDDEN})]) as server:
        result = CliRunner().invoke(cli.app, ["play", str(hidden_flag_board(tmp_path)), "--config",
                                              str(config(tmp_path, server.base_url)), "--headless", "--submit", "auto"])
    assert result.exit_code == 0, result.output
    assert "flightdeck: nothing is left to do (no lane is open, nothing is queued): closing the run" in result.stderr
    assert "Test Event: solved 1 of 1" in result.stdout
    assert "still waiting for your approval" not in result.stderr and "stopped as when you quit" not in result.stderr
    doc = status_of(tmp_path)
    assert doc["closed"] is True and doc["needs_you"] == []
    assert doc["solves"] == [{"id": "note", "name": "Note", "points": 50, "by": "L01", "teammate": False}]
    assert [event["kind"] for event in events_of(tmp_path)][-1] == "run-end"


def test_a_headless_run_whose_queue_is_held_stays_up_and_says_so_in_the_status_file(tmp_path, flying):
    """Every model call is refused: the lanes end and the queue is held. Something is left
    to do (a queued challenge, once the player fixes the key), so the run does not end on its
    own; a script that reads the status file sees the hold and stops it."""
    root = board(tmp_path)
    for name in ("memo", "list"):
        (root / name).mkdir()
        (root / name / "challenge.json").write_text(json.dumps({"name": name.title(), "category": "misc", "points": 100}))
    refused = FakeReply(401, {"error": {"message": "No auth credentials found"}})
    held = lambda doc: doc["queue"]["held"] and all(lane["state"] != "run" for lane in doc["lanes"])  # noqa: E731
    watcher, seen = stop_once(tmp_path, flying, held, after=3.0, sig=signal.SIGINT)
    with FakeModelServer(responder=lambda record: refused) as server:
        result = CliRunner().invoke(cli.app, ["play", str(root), "--config", str(config(tmp_path, server.base_url)), "--headless"])
    watcher.join(10)
    assert result.exit_code == 128 + signal.SIGINT, result.output
    (before,) = seen
    assert before["closed"] is False and before["queue"]["length"] == 1
    assert "(check the API key)" in before["queue"]["held_reason"]
    assert "flightdeck: the queue was held when the run ended (1 challenge queued, not started): " in result.stderr
    assert "flightdeck: SIGINT: the run's lanes were stopped as when you quit" in result.stderr


def test_practice_takes_headless_too_and_plays_the_set_to_its_end(tmp_path):
    """Every lane gives up at once (the model only talks), so the practice set of 14 is over
    quickly: the run ends on its own with the practice scorecard."""
    cfg = config(tmp_path, "http://127.0.0.1:9/v1")
    with FakeModelServer(responder=lambda record: text_reply("I give up.")) as server:
        cfg.write_text(cfg.read_text().replace("http://127.0.0.1:9/v1", server.base_url).replace("max_lanes = 2", "max_lanes = 14"))
        result = CliRunner().invoke(cli.app, ["practice", "--config", str(cfg), "--headless"])
    assert result.exit_code == 0, result.output
    assert "flightdeck: headless: no console." in result.stderr and "closing the run" in result.stderr
    assert "Practice Range: solved 0 of 14" in result.stdout
    doc = status_of(tmp_path)
    assert doc["closed"] is True and doc["event"] == "Practice Range" and len(doc["lanes"]) == 14
    assert doc["queue"] == {"length": 0, "held": False, "held_reason": None}


def test_the_help_of_play_and_practice_names_headless():
    for command in ("play", "practice"):
        shown = " ".join(CliRunner().invoke(cli.app, [command, "--help"]).output.replace("│", " ").split())
        assert "--headless" in shown and "approvals wait (nothing is approved)" in shown, shown


def test_a_run_that_more_work_can_reach_does_not_end_on_its_own(tmp_path):
    """nothing_left is what ends a headless run: an open lane, a queued challenge, a hold or
    a caller that says more may come (an autopilot) each keep it up."""
    with FakeModelServer([tool_call_reply("submit_flag", {"flag": HIDDEN})]) as server:
        run = prepare_run(RunOptions(board=hidden_flag_board(tmp_path), config=config(tmp_path, server.base_url), submit="auto"))
        more = [True]
        said: list[str] = []
        flight = Headless(run, say=said.append, poll_seconds=0.05, more_to_come=lambda: more[0])

        async def main() -> None:
            task = asyncio.ensure_future(flight.fly())
            deadline = time.monotonic() + 30
            while not all(lane.finished for lane in run.deck.lanes.values()) or not run.deck.lanes:
                assert time.monotonic() < deadline, "the lane did not end"
                await asyncio.sleep(0.02)
            await asyncio.sleep(0.5)  # ten polls: it would have ended by now
            assert not task.done() and not flight.nothing_left()
            assert flight.more_can_come() == "autopilot may queue a challenge again"
            run.deck.hold_queue("a hold")
            more[0] = False
            await asyncio.sleep(0.3)
            assert not task.done(), "a held queue is something left to do"
            assert run.deck.release_hold().ok
            await asyncio.wait_for(task, 5)
            await run.shutdown()

        asyncio.run(main())
        run.close()
    assert flight.stopped_by is None and flight.return_code == 0
    assert "It runs until you stop it (autopilot may queue a challenge again)" in said[0]
    assert said[-1] == "nothing is left to do (no lane is open, nothing is queued): closing the run"


# ---------------------------------------------------------------------- as a process of its own


def start(tmp_path: Path, cfg: Path, *, ignore_hangup: bool = False) -> subprocess.Popen:
    """`flightdeck play BOARD --headless` in a session of its own with no terminal: stdin
    is /dev/null, stdout and stderr go to files (as under nohup)."""
    def setup() -> None:
        # nohup ignores SIGHUP before it runs the command; without it, the default (also when the tests run under nohup)
        signal.signal(signal.SIGHUP, signal.SIG_IGN if ignore_hangup else signal.SIG_DFL)

    return subprocess.Popen(
        [sys.executable, "-m", "ctf_flightdeck", "play", str(make_board(tmp_path)), "--config", str(cfg), "--headless"],
        stdin=subprocess.DEVNULL, stdout=(tmp_path / "out.txt").open("w"), stderr=(tmp_path / "err.txt").open("w"),
        env=env_for(tmp_path), cwd=tmp_path, start_new_session=True, preexec_fn=setup,
    )


def said(tmp_path: Path) -> str:
    return (tmp_path / "out.txt").read_text() + (tmp_path / "err.txt").read_text()


def wait_until(cond, what: str, proc: subprocess.Popen, tmp_path: Path, timeout: float = 60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = cond()
        if value:
            return value
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    raise AssertionError(f"{what}: not seen (flightdeck exit {proc.poll()}); it said:\n{said(tmp_path)[-3000:]}")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_stops_a_headless_runs_host_lane_ends_the_run_log_and_closes_the_status_file(tmp_path, sig):
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        proc = start(tmp_path, make_config(tmp_path, server.base_url))
        pgid = None
        try:
            pid_file = wait_until(lambda: lane_pid_file(tmp_path), "the lane's command", proc, tmp_path)
            pgid = int(pid_file.read_text())  # the command's shell leads its own process group
            assert group_alive(pgid)
            running = wait_until(lambda: (doc := status_of(tmp_path)) and doc["lanes"] and doc, "the lane in status.json", proc,
                                 tmp_path, timeout=10)
            assert running["closed"] is False and [lane["state"] for lane in running["lanes"]] == ["run"]
            os.kill(proc.pid, sig)
            status = proc.wait(timeout=60)
            assert status == 128 + sig, f"flightdeck ended with {status}; it said:\n{said(tmp_path)[-3000:]}"
            assert gone(lambda: group_alive(pgid)), "the lane's command outlived flightdeck"
            assert run_end(tmp_path)[-1] == "run-end"
            assert status_of(tmp_path)["closed"] is True
            err = (tmp_path / "err.txt").read_text()
            assert f"flightdeck: {sig.name}: the run's lanes were stopped as when you quit" in err
            assert "run log: " in (tmp_path / "out.txt").read_text()
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if pgid is not None and group_alive(pgid):
                os.killpg(pgid, signal.SIGKILL)


def test_under_nohup_a_hang_up_is_ignored_and_sigterm_still_stops_the_run(tmp_path):
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        proc = start(tmp_path, make_config(tmp_path, server.base_url), ignore_hangup=True)
        pgid = None
        try:
            pid_file = wait_until(lambda: lane_pid_file(tmp_path), "the lane's command", proc, tmp_path)
            pgid = int(pid_file.read_text())
            os.kill(proc.pid, signal.SIGHUP)
            time.sleep(2.5)  # more than two polls: it neither stopped nor ended on its own
            assert proc.poll() is None and group_alive(pgid) and status_of(tmp_path)["closed"] is False
            os.kill(proc.pid, signal.SIGTERM)
            assert proc.wait(timeout=60) == 128 + signal.SIGTERM, said(tmp_path)[-3000:]
            assert gone(lambda: group_alive(pgid)) and run_end(tmp_path)[-1] == "run-end"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if pgid is not None and group_alive(pgid):
                os.killpg(pgid, signal.SIGKILL)


def test_sigterm_removes_a_headless_runs_docker_lanes_container(tmp_path):
    missing = _docker_missing()
    if missing:
        docker_not_run(f"not run: needs docker and {IMAGE}: {missing}")
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        proc = start(tmp_path, make_config(tmp_path, server.base_url, runtime="docker"))
        name = None
        try:
            wait_until(lambda: lane_pid_file(tmp_path), "the lane's command in its container", proc, tmp_path, timeout=120)
            (run_dir,) = (tmp_path / "runs").iterdir()
            name = f"flightdeck-{run_dir.name}-l01"
            assert container_exists(name)
            os.kill(proc.pid, signal.SIGTERM)
            status = proc.wait(timeout=90)
            assert status == 128 + signal.SIGTERM, f"flightdeck ended with {status}; it said:\n{said(tmp_path)[-3000:]}"
            assert not container_exists(name), "the lane's container outlived flightdeck"
            assert run_end(tmp_path)[-1] == "run-end" and status_of(tmp_path)["closed"] is True
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if name is not None and container_exists(name):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
