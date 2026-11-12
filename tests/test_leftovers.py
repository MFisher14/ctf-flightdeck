"""The backstop for what a run leaves running when flightdeck itself is killed (leftovers.py).

SIGKILL and a power loss give flightdeck no handler to run, so a run marks what it starts:
its containers carry flightdeck's labels, and its process groups on this machine are in
processes.json in its run folder. The next play or practice, and doctor, find what such a
run left: play removes it and says what; doctor reports it, and removes it with --clean.

The process tests start real processes (sleep) in groups of their own, and kill every one
they start, even when a test fails. The container tests use l1_kit's fake docker script (it
starts nothing), except one that runs only when docker answers and debian:bookworm-slim is
already on this machine (tests never pull, and use no other image); otherwise it reports as
not run. The play tests start the real command on a pty, as test_play_signals.py does, and
kill it with SIGKILL.
"""

from __future__ import annotations

import asyncio
import contextlib
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

from ctf_flightdeck import cli, leftovers
from ctf_flightdeck.agent.l1stage import L1Stage
from ctf_flightdeck.agent.workspace import DockerWorkspace, HostWorkspace
from ctf_flightdeck.leftovers import RECORD, Owner, ProcessRecord, host_id, labels, sweep
from ctf_flightdeck.l1.manifest import discover
from ctf_flightdeck.run import RunOptions, prepare_run
from ctf_flightdeck.setup import doctor

from fake_model import FakeModelServer, tool_call_reply
from l1_kit import FAKE_IMAGE, FLAG, challenge, challenge_dir, cli_engine, docker_not_run, install_fake_docker

RUN = "20261111-120000"  # a killed run's folder name
STARTED: list[subprocess.Popen] = []


@pytest.fixture(autouse=True)
def kill_what_tests_start():
    """Every process group a test started is killed afterwards, whatever happened."""
    yield
    while STARTED:
        proc = STARTED.pop()
        if proc.poll() is None:  # still our child (or its zombie): the group number is still its own
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)


def start(argv: list[str], cwd: Path) -> subprocess.Popen:
    """A process in a group of its own, working in cwd: what a lane's command leaves running."""
    cwd.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(argv, cwd=cwd, start_new_session=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    STARTED.append(proc)
    return proc


def killed(proc: subprocess.Popen) -> bool:
    """The process was killed with SIGKILL (and is reaped here)."""
    try:
        return proc.wait(timeout=10) == -signal.SIGKILL
    except subprocess.TimeoutExpired:
        return False


def killed_flightdeck() -> Owner:
    """The flightdeck of a run that was killed: this machine and user, and a pid whose process
    has exited (should the system give the pid out again, the start time cannot match)."""
    proc = subprocess.Popen(["sleep", "30"])
    proc.kill()
    proc.wait()
    return Owner(host_id(), os.getuid(), proc.pid, "darwin:1.000001" if sys.platform == "darwin" else "linux:old-boot:1")


def killed_run(runs: Path, name: str = RUN, *, docker: bool = False, owner: Owner | None = None) -> ProcessRecord:
    """A run folder whose record says its flightdeck has gone (or is `owner`)."""
    run_dir = runs / name
    run_dir.mkdir(parents=True)
    return ProcessRecord.start(run_dir, docker=docker, owner=owner or killed_flightdeck())


def record_of(run_dir: Path) -> dict:
    return json.loads((run_dir / RECORD).read_text())


def lane_command(record: ProcessRecord, argv: list[str] | None = None) -> subprocess.Popen:
    """A lane's command the run recorded, left running in the lane's work folder."""
    work = record.run_dir / "l01" / "work"
    proc = start(argv or ["sleep", "300"], work)
    record.add(proc.pid, work, "a lane command")
    return proc


def wait_until(cond, what: str, timeout: float = 30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = cond()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


# ---------------------------------------------------------------- containers carry the run's labels


def test_a_container_carries_the_runs_labels_and_a_label_that_could_break_its_argument_is_refused(tmp_path):
    handout = challenge_dir(tmp_path / "board", "demo")
    marks = {"flightdeck.run": RUN, "flightdeck.pid": "4242"}
    box = DockerWorkspace(tmp_path / "w", handout, image=FAKE_IMAGE, name="flightdeck-test-labels", labels=marks)
    args = box.run_args()
    assert args[args.index("--label"):args.index("--network")] == [
        "--label", "flightdeck.pid=4242", "--label", f"flightdeck.run={RUN}"]
    assert args[-2:] == [FAKE_IMAGE, "infinity"]  # the labels are options, before the image
    for bad in ({"Flightdeck.Run": "x"}, {"a=b": "x"}, {"flightdeck.run": "two\nlines"}, {"flightdeck.run": "a\tb"}):
        with pytest.raises(ValueError, match="label"):
            DockerWorkspace(tmp_path / "w", handout, image=FAKE_IMAGE, name="flightdeck-test-labels", labels=bad)


def test_a_docker_run_labels_its_lanes_and_l1_engines_with_the_run_and_the_flightdeck_running_it(tmp_path, monkeypatch):
    install_fake_docker(tmp_path, monkeypatch)
    pack = tmp_path / "pack"
    cli_engine(pack, "e", "echo t{x}\n")
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url, runtime="docker"),
                                     pack=pack))
        assert record_of(run.dir)["docker"] is True  # a sweep from a host run looks in Docker for this run's containers
        run.close()
    me = leftovers.process(os.getpid())
    assert me is not None
    expected = {"flightdeck.run": run.dir.name, "flightdeck.host": host_id(), "flightdeck.uid": str(os.getuid()),
                "flightdeck.pid": str(os.getpid()), "flightdeck.started": me.started, "flightdeck.state": leftovers.state_id()}
    assert labels(run.dir.name) == expected
    lane = type("L", (), {"id": "L01"})()
    workspace = run.driver.workspaces(lane, run.board.challenges[0].challenge)
    assert isinstance(workspace, DockerWorkspace) and workspace.labels == expected
    args = workspace.run_args()
    assert f"flightdeck.run={run.dir.name}" in args and f"flightdeck.started={me.started}" in args
    assert run.driver.l1.labels == expected and run.driver.l1.record is run.processes


def test_an_l1_engine_container_is_started_with_its_stages_labels(tmp_path, monkeypatch):
    runs_log = install_fake_docker(tmp_path, monkeypatch)
    pack = tmp_path / "pack"
    cli_engine(pack, "e", "echo t{x}\n")
    handout = challenge_dir(tmp_path / "board", "demo", {"note.txt": "x"}, id="demo")
    marks = labels("r1")
    stage = L1Stage(discover(pack), {"demo": handout}, tmp_path / "r1", FLAG, image=FAKE_IMAGE, pack=pack, labels=marks)
    asyncio.run(stage.run("L01", challenge("Demo", description="a demo challenge")))
    (started,) = runs_log.read_text().splitlines()
    words = started.split()
    assert [words[i + 1] for i, word in enumerate(words) if word == "--label"] == [f"{k}={v}" for k, v in sorted(marks.items())]


# ---------------------------------------------------------------- the run's record of its process groups


def test_a_run_records_its_flightdeck_and_the_record_goes_when_the_run_ends_cleanly(tmp_path):
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
        data = record_of(run.dir)
        me = leftovers.process(os.getpid())
        assert me is not None
        assert data == {"flightdeck": 1, "run": run.dir.name, "docker": False, "groups": [],
                        "owner": {"host": host_id(), "uid": os.getuid(), "pid": os.getpid(), "started": me.started}}
        (note,) = leftovers.open_runs().iterdir()  # what finds the run wherever its folder is
        assert json.loads(note.read_text()) == {"flightdeck": 1, "folder": os.path.realpath(run.dir)}
        run.close()
    assert not (run.dir / RECORD).exists() and run.errors == []
    assert list(leftovers.open_runs().iterdir()) == []  # the note goes with the record


def test_a_record_that_cannot_be_kept_current_never_stops_the_run_and_is_said_when_it_ends(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("not run: as root, a folder's mode does not stop a write to it")
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
        assert run.processes is not None and run.errors == []
        work = run.dir / "l01" / "work"
        proc = start(["sleep", "300"], work)
        os.chmod(run.dir, 0o500)  # the run folder can no longer take a new file
        try:
            run.processes.add(proc.pid, work, "a lane command")  # no exception: only the backstop is lost
        finally:
            os.chmod(run.dir, 0o700)
        run.close()
    assert run.errors == [f"could not keep {run.dir / RECORD} current (Permission denied): if flightdeck is killed, what "
                          "this run left running on this machine will not be found by the next start"]


def test_a_run_whose_record_cannot_be_written_does_not_start(tmp_path, monkeypatch):
    from ctf_flightdeck.run import RunError

    def failing(path: Path, data: bytes) -> None:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(leftovers, "_write_atomically", failing)
    with FakeModelServer() as server, pytest.raises(RunError) as caught:
        prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
    (run_dir,) = (tmp_path / "runs").iterdir()
    assert str(caught.value) == f"cannot write {run_dir / RECORD}: Input/output error"


def test_a_run_whose_note_cannot_be_written_does_not_start_and_leaves_no_record(tmp_path, monkeypatch):
    from ctf_flightdeck.run import RunError

    blocked = tmp_path / "state"
    blocked.write_text("")  # a file where the state folder would be: nothing can go in it
    monkeypatch.setenv("XDG_STATE_HOME", str(blocked))
    with FakeModelServer() as server, pytest.raises(RunError) as caught:
        prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
    assert str(caught.value) == f"cannot write {blocked / 'ctf-flightdeck' / 'open-runs'}: Not a directory"
    (run_dir,) = (tmp_path / "runs").iterdir()
    assert not (run_dir / RECORD).exists()  # a record no note names is not left behind


def test_a_host_lanes_command_is_in_the_record_while_it_may_run_with_what_it_left_running(tmp_path):
    runs = tmp_path / "runs"
    record = killed_run(runs, owner=Owner.this())
    handout = challenge_dir(tmp_path / "board", "demo")
    ws = HostWorkspace(record.run_dir / "l01" / "work", handout, record=record)

    async def scenario():
        await ws.prepare()
        out = await ws.run("sleep 300 > /dev/null 2>&1 & echo $!", timeout=30)
        child = int(out.output.decode().strip())
        (entry,) = record_of(record.run_dir)["groups"]
        assert entry["what"] == "a lane command" and entry["folder"] == str(ws.root)
        seen = leftovers.process(child)
        assert seen is not None and seen.pgid == entry["pgid"]
        assert entry["processes"] == [[child, seen.started]]  # the shell has exited; what it left is noted
        await ws.close()
        assert record_of(record.run_dir)["groups"] == []
        return child

    child = asyncio.run(scenario())
    wait_until(lambda: leftovers.process(child) is None, "close() to stop what the command left running")


def test_the_record_is_replaced_whole_each_time_never_written_in_place(tmp_path):
    record = killed_run(tmp_path / "runs", owner=Owner.this())
    path = record.run_dir / RECORD
    proc = start(["sleep", "300"], record.run_dir / "l01" / "work")
    bad: list[str] = []
    stop = threading.Event()

    def reader() -> None:
        while not stop.is_set():
            try:
                json.loads(path.read_bytes())
            except ValueError as exc:
                bad.append(str(exc))

    watcher = threading.Thread(target=reader)
    watcher.start()
    inodes = set()
    try:
        for _ in range(300):
            record.add(proc.pid, record.run_dir / "l01" / "work", "a lane command")
            inodes.add(path.stat().st_ino)
            record.drop([proc.pid])
            inodes.add(path.stat().st_ino)
    finally:
        stop.set()
        watcher.join()
    assert bad == []  # a reader never saw half a file
    assert len(inodes) > 1  # each write is a new file renamed over the old
    assert sorted(p.name for p in record.run_dir.iterdir()) == ["l01", RECORD]  # no temporary file left


def test_a_record_with_a_group_still_in_it_stays_when_the_run_ends(tmp_path):
    record = killed_run(tmp_path / "runs", owner=Owner.this())
    proc = lane_command(record)
    record.finish()
    assert [g["pgid"] for g in record_of(record.run_dir)["groups"]] == [proc.pid]
    record.drop([proc.pid])
    record.finish()
    assert not (record.run_dir / RECORD).exists()


def test_an_l1_engine_on_this_machine_is_in_the_record_while_it_runs(tmp_path):
    pack = tmp_path / "pack"
    cli_engine(pack, "hang", "sleep 300\n", extra="timeout_seconds = 60")
    handout = challenge_dir(tmp_path / "board", "demo", {"note.txt": "x"}, id="demo")
    record = killed_run(tmp_path / "runs", owner=Owner.this())
    stage = L1Stage(discover(pack), {"demo": handout}, record.run_dir, FLAG, record=record)

    async def scenario():
        task = asyncio.ensure_future(stage.run("L01", challenge("Demo", description="a demo challenge")))
        deadline = time.monotonic() + 30
        groups: list = []
        while time.monotonic() < deadline and not groups:
            groups = [g for g in record_of(record.run_dir)["groups"] if g["what"] == "the L1 engine hang"]
            await asyncio.sleep(0.05)
        assert groups, "the engine never showed in the record"
        (entry,) = groups
        assert entry["folder"] == str(record.run_dir / "l01" / "l1" / "hang")
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert record_of(record.run_dir)["groups"] == []  # the cancel stopped it, and the record says so
        return entry["pgid"]

    pgid = asyncio.run(scenario())
    wait_until(lambda: leftovers.group(pgid) == [], "the engine to be gone")


def test_a_coding_agent_cli_on_this_machine_is_in_the_record_while_it_runs(tmp_path):
    from ctf_flightdeck.agent.external import ExternalDriver, find_agent
    from ctf_flightdeck.clock import RunClock
    from ctf_flightdeck.core.deck import Deck, QueueEntry
    from ctf_flightdeck.core.model import Challenge, DeckConfig

    from test_external import KEY, MODELS, Fake

    fake = Fake(tmp_path, {"turns": [{"calls": [{"think": 120}]}]})  # it works on while the test looks
    agent = find_agent("claude", MODELS[0], environ={"PATH": str(fake.bin), "ANTHROPIC_API_KEY": KEY})
    record = killed_run(tmp_path / "runs", owner=Owner.this())
    handout = challenge_dir(tmp_path / "board", "note")

    async def scenario():
        driver = ExternalDriver(
            agent, lambda lane, ch: HostWorkspace(record.run_dir / lane.id.lower() / "work", handout, record=record),
            run_id=RUN, stop_grace=0.3,
        )
        deck = Deck(DeckConfig(event="t", flag_format=FLAG, models=MODELS), driver, RunClock(), lambda c, f: False)
        deck.release([Challenge("note", "Note", "misc", 50)], [QueueEntry("note", "small")])
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not fake.starts():
                await asyncio.sleep(0.05)
            (begun,) = fake.starts()
            cli = leftovers.process(begun["pid"])
            assert cli is not None
            groups = record_of(record.run_dir)["groups"]
            assert [(g["what"], g["pgid"], g["processes"][0]) for g in groups] == [
                ("the claude CLI", begun["pid"], [begun["pid"], cli.started])]
        finally:
            await driver.shutdown()
        assert record_of(record.run_dir)["groups"] == []

    asyncio.run(scenario())


def test_what_a_group_starts_after_its_leader_is_noted_so_the_group_is_known_once_the_leader_has_exited(
        tmp_path, monkeypatch):
    """A coding-agent CLI killed with flightdeck can leave what it started running in its
    group: the notes taken while the run lived still tell that group apart."""
    from ctf_flightdeck.agent import workspace

    monkeypatch.setattr(workspace, "RECORD_NOTES", 0.1)
    runs = tmp_path / "runs"
    owner = killed_flightdeck()
    record = killed_run(runs, owner=owner)
    handout = challenge_dir(tmp_path / "board", "demo")
    work = record.run_dir / "l01" / "work"
    ws = HostWorkspace(work, handout, record=record)
    pids = work.parent / "pids"
    cli = start(["sh", "-c", f"sleep 1; sleep 300 & echo $! > {pids}; wait"], work)

    async def scenario():
        ws.adopt(cli.pid, "the claude CLI")
        assert [p[0] for p in record_of(record.run_dir)["groups"][0]["processes"]] == [cli.pid]  # what it has started so far
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            noted = [p[0] for p in record_of(record.run_dir)["groups"][0]["processes"]]
            if pids.exists() and pids.read_text().strip() and int(pids.read_text()) in noted:
                return int(pids.read_text())
            await asyncio.sleep(0.05)
        raise AssertionError("what the CLI started was never noted in the record")

    child = asyncio.run(scenario())  # the loop ends as flightdeck's would: close() never runs
    try:
        os.kill(cli.pid, signal.SIGKILL)  # the CLI goes too; what it started runs on in its group
        assert killed(cli)
        assert [p.pid for p in leftovers.group(cli.pid)] == [child]
        swept = sweep(runs, docker=None, clean=True)
        assert swept.done == (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed "
                              f"what it left running: its process group {cli.pid} (the claude CLI in l01/work)",)
        wait_until(lambda: leftovers.group(cli.pid) == [], "what the CLI started to be stopped")
    finally:
        if child in [p.pid for p in leftovers.group(cli.pid)]:
            os.killpg(cli.pid, signal.SIGKILL)


# ---------------------------------------------------------------- the sweep: what killed runs left


def test_doctor_names_a_killed_runs_process_group_and_removes_it_only_with_clean(tmp_path):
    record = killed_run(tmp_path / "runs")
    proc = lane_command(record)
    cfg = config(tmp_path, "http://127.0.0.1:9/v1")
    line = (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped) and left running: its "
            f"process group {proc.pid} (a lane command in l01/work)")
    result = CliRunner().invoke(cli.app, ["doctor", "--config", str(cfg)])
    assert f"warn leftovers: {line}\n     fix: `flightdeck doctor --clean` removes them (play and practice also do when they " \
           "start)\n" in result.output
    assert proc.poll() is None and (record.run_dir / RECORD).exists()  # doctor looked; it changed nothing
    result = CliRunner().invoke(cli.app, ["doctor", "--config", str(cfg), "--clean"])
    assert (f"ok   leftovers: run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what "
            f"it left running: its process group {proc.pid} (a lane command in l01/work)\n") in result.output
    assert killed(proc) and not (record.run_dir / RECORD).exists()
    again = {c.name: c for c in doctor(cfg, environ={})}["leftovers"]
    assert again.ok and again.detail == (f"no run left anything running (runs in {tmp_path / 'runs'}, and those noted in "
                                         f"{leftovers.open_runs()})")


def test_doctor_says_clean_removes_only_what_clean_removes(tmp_path):
    """A group the sweep leaves alone is named with what to do about it, never with a fix that
    says `--clean` removes it."""
    record = killed_run(tmp_path / "runs")
    left = lane_command(record)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    moved = start(["sh", "-c", f"cd {elsewhere} && exec sleep 300"], record.run_dir / "l02" / "work")
    wait_until(lambda: leftovers.working_folder(moved.pid) == os.path.realpath(elsewhere), "the command to move out")
    record.add(moved.pid, record.run_dir / "l02" / "work", "a lane command")
    cfg = config(tmp_path, "http://127.0.0.1:9/v1")
    found = (f"warn leftovers: run {RUN} did not shut down (its flightdeck was killed, or the machine stopped) and left "
             f"running: its process group {left.pid} (a lane command in l01/work)")
    alone = (f"warn leftovers: run {RUN}: process group {moved.pid} (a lane command in l02/work) was left alone: the "
             f"processes flightdeck recorded in it (pid {moved.pid}) run on, but no longer work in a folder under the run's "
             f"folder; if it is a leftover, stop it yourself (kill -KILL -- -{moved.pid})")
    lines = CliRunner().invoke(cli.app, ["doctor", "--config", str(cfg)]).output.splitlines()
    assert fix_after(lines, found) == "`flightdeck doctor --clean` removes them (play and practice also do when they start)"
    assert fix_after(lines, alone) is None
    lines = CliRunner().invoke(cli.app, ["doctor", "--config", str(cfg), "--clean"]).output.splitlines()
    assert fix_after(lines, alone) is None
    assert killed(left)
    time.sleep(0.2)
    assert moved.poll() is None  # --clean left it alone, as the line says


def fix_after(lines: list[str], line: str) -> str | None:
    """The fix doctor printed under this line (which must be there), or None."""
    after = lines[lines.index(line) + 1:][:1]
    return after[0].removeprefix("     fix: ") if after and after[0].startswith("     fix: ") else None


def test_play_removes_what_a_killed_run_left_running_and_says_what(tmp_path):
    record = killed_run(tmp_path / "runs")
    proc = lane_command(record)
    with FakeModelServer() as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url)))
        run.close()
    assert (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what it left "
            f"running: its process group {proc.pid} (a lane command in l01/work)") in run.notes()
    assert killed(proc) and not (record.run_dir / RECORD).exists()


def test_a_killed_runs_note_goes_with_its_record_and_a_note_whose_record_has_gone_goes_unsaid(tmp_path):
    """Each run is found once, whether through the runs folder swept or the note naming its
    folder; a run found only through its note is named by its folder's path. A clean sweep
    removes a killed run's note with its record, and a note whose record is gone (its run
    ended as its flightdeck was killed, or its folder was deleted) without a word."""
    runs = tmp_path / "runs"
    here = killed_run(runs)
    here_cmd = lane_command(here)
    there = killed_run(tmp_path / "event" / "runs")  # play --run-dir put it outside the runs folder swept
    there_cmd = lane_command(there)
    ended = killed_run(tmp_path / "old" / "runs")
    ended.path.unlink()  # its flightdeck was killed between removing its record and its note
    notes = sorted(leftovers.open_runs().iterdir())
    assert len(notes) == 3
    where = os.path.realpath(there.run_dir)
    found = sweep(runs, docker=None, clean=False)
    assert found == leftovers.Swept(found=(
        f"run {where} did not shut down (its flightdeck was killed, or the machine stopped) and left running: its process "
        f"group {there_cmd.pid} (a lane command in l01/work)",
        f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped) and left running: its process "
        f"group {here_cmd.pid} (a lane command in l01/work)",
    ))
    assert sorted(leftovers.open_runs().iterdir()) == notes  # without clean nothing changes
    swept = sweep(runs, docker=None, clean=True)
    assert swept == leftovers.Swept(done=(
        f"run {where} did not shut down (its flightdeck was killed, or the machine stopped); removed what it left running: "
        f"its process group {there_cmd.pid} (a lane command in l01/work)",
        f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what it left running: "
        f"its process group {here_cmd.pid} (a lane command in l01/work)",
    ))
    assert killed(here_cmd) and killed(there_cmd)
    assert not here.path.exists() and not there.path.exists() and list(leftovers.open_runs().iterdir()) == []


def test_a_note_that_cannot_be_read_is_named_and_kept(tmp_path):
    notes = leftovers.open_runs()
    notes.mkdir(parents=True)
    (notes / "20261111-120000-0a1b2c3d4e5f.json").write_text('{"flightdeck": 1, "folder": "relative/folder"}')
    swept = sweep(tmp_path / "runs", docker=None, clean=True)
    assert swept == leftovers.Swept(alone=(
        f"a note in {notes} cannot be read (it is not a note this flightdeck wrote), so the run it names cannot be found; "
        f"remove {notes / '20261111-120000-0a1b2c3d4e5f.json'}",))
    assert (notes / "20261111-120000-0a1b2c3d4e5f.json").exists()


def test_a_group_number_now_held_by_processes_flightdeck_did_not_record_is_never_signalled(tmp_path):
    """The pid was given out again: the recorded start time is not the live process's."""
    runs = tmp_path / "runs"
    record = killed_run(runs)
    elsewhere = start(["sleep", "300"], tmp_path / "elsewhere")  # another program's group, outside the run folder
    inside = start(["sleep", "300"], record.run_dir / "l02" / "work")  # and one working in the run's folder
    for proc in (elsewhere, inside):
        record._groups[proc.pid] = {"what": "a lane command", "folder": str(record.run_dir / "l01" / "work"),
                                    "processes": [[proc.pid, "darwin:1.000002" if sys.platform == "darwin" else "linux:x:2"]]}
    record._write()
    found = sweep(runs, docker=None, clean=False)
    assert found.found == () and found.alone == (f"run {RUN}: process group {inside.pid} (a lane command in l01/work) was left alone: none of the "
                           "processes flightdeck recorded in it is left, and processes it did not record that work in the "
                           f"run's folder are in a group of that number now (pid {inside.pid})",)
    swept = sweep(runs, docker=None, clean=True)
    assert swept.done == () and swept.alone == found.alone
    assert (record.run_dir / RECORD).exists()  # the next sweep looks again
    time.sleep(0.2)
    assert elsewhere.poll() is None and inside.poll() is None  # neither was signalled
    os.killpg(inside.pid, signal.SIGKILL)
    assert killed(inside)
    assert sweep(runs, docker=None, clean=True) == leftovers.Swept() and not (record.run_dir / RECORD).exists()


def test_a_recorded_process_that_no_longer_works_under_the_runs_folder_is_left_alone_and_named(tmp_path):
    runs = tmp_path / "runs"
    record = killed_run(runs)
    work = record.run_dir / "l01" / "work"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proc = start(["sh", "-c", f"cd {elsewhere} && exec sleep 300"], work)
    wait_until(lambda: leftovers.working_folder(proc.pid) == os.path.realpath(elsewhere), "the command to move out")
    record.add(proc.pid, work, "a lane command")
    swept = sweep(runs, docker=None, clean=True)
    assert swept.done == () and swept.found == ()
    assert swept.alone == (f"run {RUN}: process group {proc.pid} (a lane command in l01/work) was left alone: the processes "
                           f"flightdeck recorded in it (pid {proc.pid}) run on, but no longer work in a folder under the "
                           f"run's folder; if it is a leftover, stop it yourself (kill -KILL -- -{proc.pid})",)
    time.sleep(0.2)
    assert proc.poll() is None and (record.run_dir / RECORD).exists()


@pytest.mark.parametrize("on_disk, spelled", [("CaseRuns", "caseruns"), ("Café-runs", "Café-runs")],
                         ids=["upper and lower case", "a decomposed and a composed accent"])
def test_a_runs_folder_spelled_otherwise_than_on_disk_is_still_that_folder(tmp_path, on_disk, spelled):
    """Where the file system does not tell these spellings apart (macOS's default), [run] dir
    or --run-dir may spell the runs folder otherwise than the folder on disk, which is how the
    kernel names a process's working folder: what the run left still works under its folder."""
    (tmp_path / on_disk).mkdir()
    runs = tmp_path / spelled
    if not runs.is_dir():
        pytest.skip("not run: this file system tells these spellings apart, so a folder has one spelling")
    record = killed_run(runs)
    proc = lane_command(record)
    swept = sweep(runs, docker=None, clean=True)
    assert swept.done == (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what "
                          f"it left running: its process group {proc.pid} (a lane command in l01/work)",)
    assert killed(proc)


def test_a_run_whose_flightdeck_still_runs_is_never_touched(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    record = killed_run(runs, owner=Owner.this())  # this test process is that run's flightdeck, alive
    proc = lane_command(record)
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    (fake_bin / "ps.txt").write_text(ps_line("a" * 64, "flightdeck-live-l01", RUN, Owner.this()))
    assert sweep(runs, docker=True, clean=True) == leftovers.Swept()
    time.sleep(0.2)
    assert proc.poll() is None and (record.run_dir / RECORD).exists() and not (fake_bin / "rm.log").exists()


def test_a_flightdeck_pid_now_held_by_another_process_counts_as_gone(tmp_path):
    runs = tmp_path / "runs"
    me = Owner.this()
    record = killed_run(runs, owner=Owner(me.host, me.uid, me.pid, "linux:another-boot:7"))  # this pid, another start
    proc = lane_command(record)
    swept = sweep(runs, docker=None, clean=True)
    assert len(swept.done) == 1 and f"its process group {proc.pid}" in swept.done[0]
    assert killed(proc)


def test_a_flightdeck_that_has_exited_but_is_not_reaped_yet_counts_as_gone(tmp_path):
    runs = tmp_path / "runs"
    exited = subprocess.Popen(["sleep", "300"])
    try:
        seen = leftovers.process(exited.pid)
        assert seen is not None
        os.kill(exited.pid, signal.SIGKILL)  # not waited for until the end: a zombie meanwhile
        wait_until(lambda: ps_state(exited.pid).startswith("Z"), "the process to be a zombie")
        record = killed_run(runs, owner=Owner(host_id(), os.getuid(), exited.pid, seen.started))
        proc = lane_command(record)
        swept = sweep(runs, docker=None, clean=True)
        assert len(swept.done) == 1 and f"its process group {proc.pid}" in swept.done[0]
        assert killed(proc)
    finally:
        exited.wait()


def ps_state(pid: int) -> str:
    return subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False).stdout.strip()


def test_runs_of_another_machine_or_user_are_never_touched(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    gone = killed_flightdeck()
    others = (Owner("another-machine", gone.uid, gone.pid, gone.started), Owner(gone.host, gone.uid + 1, gone.pid, gone.started))
    procs = [lane_command(killed_run(runs, f"{RUN}-{i}", owner=owner)) for i, owner in enumerate(others)]
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    (fake_bin / "ps.txt").write_text("".join(ps_line(f"{i:064x}", f"flightdeck-other-{i}", RUN, owner) for i, owner in enumerate(others)))
    assert sweep(runs, docker=True, clean=True) == leftovers.Swept()
    time.sleep(0.2)
    assert all(proc.poll() is None for proc in procs) and not (fake_bin / "rm.log").exists()


def ps_line(box_id: str, name: str, run: str, owner: Owner) -> str:
    """A line of `docker ps` in the sweep's format: id, name, then flightdeck's labels."""
    return "\t".join([box_id, name, *labels(run, owner).values()]) + "\n"


def test_only_containers_with_flightdecks_labels_whose_flightdeck_has_gone_are_removed(tmp_path, monkeypatch):
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    gone, me = killed_flightdeck(), Owner.this()
    left, live, unsure = "a" * 64, "b" * 64, "c" * 64
    (fake_bin / "ps.txt").write_text(
        ps_line(left, f"flightdeck-{RUN}-l01", RUN, gone)
        + ps_line(live, "flightdeck-now-l01", "now", me)  # a run that still runs
        + ps_line(unsure, "flightdeck-old-l01", "old", Owner(gone.host, gone.uid, gone.pid, ""))  # when it started: unknown
        + f"{'d' * 64}\tnot-ours\t{RUN}\t\t\t\t\t\n"  # without the rest of flightdeck's labels
        + "garbage line\n"
    )
    found = sweep(None, docker=True, clean=False)
    assert found.found == (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped) and left "
                           f"running: its container flightdeck-{RUN}-l01",)
    assert found.alone == ("run old: its container flightdeck-old-l01 was left alone: its labels do not say when its "
                           "flightdeck started",)
    assert not (fake_bin / "rm.log").exists()
    swept = sweep(None, docker=True, clean=True)
    assert swept.done == (f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what it "
                          f"left running: its container flightdeck-{RUN}-l01",)
    assert (fake_bin / "rm.log").read_text().splitlines() == [f"rm -f {left}"]
    assert "label=flightdeck.run" in (fake_bin / "ps.log").read_text()


def test_a_container_of_a_flightdeck_that_keeps_its_notes_elsewhere_is_never_removed(tmp_path, monkeypatch):
    """Containers started by a flightdeck with another state folder (another setup, or another
    test suite on this machine) are that setup's: only a sweep with the same state folder
    removes them."""
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    gone = killed_flightdeck()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "theirs"))
    (fake_bin / "ps.txt").write_text(ps_line("a" * 64, f"flightdeck-{RUN}-l01", RUN, gone))  # labelled by that flightdeck
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "ours"))
    assert sweep(None, docker=True, clean=True) == leftovers.Swept()
    assert not (fake_bin / "rm.log").exists()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "theirs"))
    assert sweep(None, docker=True, clean=True).done == (
        f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what it left running: "
        f"its container flightdeck-{RUN}-l01",)
    assert (fake_bin / "rm.log").read_text().splitlines() == [f"rm -f {'a' * 64}"]


def test_docker_is_asked_only_when_lanes_run_there_or_a_killed_run_used_it(tmp_path, monkeypatch):
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    runs = tmp_path / "runs"
    killed_run(runs, f"{RUN}-host")
    assert sweep(runs, docker=None, clean=False) == leftovers.Swept()
    assert not (fake_bin / "ps.log").exists()  # a host run's record: Docker is not asked
    in_docker = killed_run(runs, f"{RUN}-docker", docker=True)
    (fake_bin / "ps.txt").write_text(ps_line("e" * 64, f"flightdeck-{RUN}-docker-l01", f"{RUN}-docker", killed_flightdeck()))
    swept = sweep(runs, docker=None, clean=True)
    assert swept.done == (f"run {RUN}-docker did not shut down (its flightdeck was killed, or the machine stopped); removed "
                          f"what it left running: its container flightdeck-{RUN}-docker-l01",)
    assert not (in_docker.run_dir / RECORD).exists()


def test_a_killed_docker_run_found_through_its_note_has_its_containers_removed_with_it(tmp_path, monkeypatch):
    """A docker run started with --run-dir elsewhere: a sweep from a host-runtime config finds
    it through its note, asks Docker because its record says it used it, and names its
    container with it."""
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    owner = killed_flightdeck()
    there = killed_run(tmp_path / "event" / "runs", docker=True, owner=owner)
    (fake_bin / "ps.txt").write_text(ps_line("e" * 64, f"flightdeck-{RUN}-l01", RUN, owner)
                                     + ps_line("f" * 64, f"flightdeck-{RUN}-l02", RUN, killed_flightdeck()))  # another run of that name
    swept = sweep(tmp_path / "runs", docker=None, clean=True)
    assert swept.done == (
        f"run {os.path.realpath(there.run_dir)} did not shut down (its flightdeck was killed, or the machine stopped); removed "
        f"what it left running: its container flightdeck-{RUN}-l01",
        f"run {RUN} did not shut down (its flightdeck was killed, or the machine stopped); removed what it left running: its "
        f"container flightdeck-{RUN}-l02",
    )
    assert not there.path.exists() and list(leftovers.open_runs().iterdir()) == []


def test_without_docker_a_killed_docker_runs_containers_are_not_looked_for_and_its_record_stays(tmp_path, monkeypatch):
    fake_bin = install_fake_docker(tmp_path, monkeypatch).parent
    runs = tmp_path / "runs"
    record = killed_run(runs, docker=True)
    swept = sweep(runs, docker=False, clean=True)
    assert swept.alone == (f"run {RUN}: it ran lanes in Docker, which is not available now, so its containers were not "
                           "looked for",)
    assert (record.run_dir / RECORD).exists() and not (fake_bin / "ps.log").exists()
    (fake_bin / "ps.fail").write_text("Cannot connect to the Docker daemon\n")
    swept = sweep(runs, docker=True, clean=True)
    assert swept.alone == ("the containers of runs that did not shut down could not be looked for (Cannot connect to the "
                           "Docker daemon); once Docker runs, `flightdeck doctor --clean` removes them",)
    assert (record.run_dir / RECORD).exists()  # kept until its containers can be looked for


def test_a_record_that_cannot_be_read_is_named_and_kept(tmp_path):
    runs = tmp_path / "runs"
    (runs / RUN).mkdir(parents=True)
    (runs / RUN / RECORD).write_text('{"flightdeck": 1, "owner": ')
    swept = sweep(runs, docker=None, clean=True)
    (line,) = swept.alone
    assert line.startswith(f"run {RUN}: its {RECORD} cannot be read (JSONDecodeError: ") and line.endswith(
        f"so what it left cannot be checked; remove {runs / RUN / RECORD} once no flightdeck runs from that folder")
    assert (runs / RUN / RECORD).exists()


def test_where_start_times_cannot_be_read_nothing_is_removed_and_the_sweep_says_why(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    proc = lane_command(killed_run(runs))
    monkeypatch.setattr(sys, "platform", "sunos5")
    swept = sweep(runs, docker=None, clean=True)
    assert swept == leftovers.Swept(alone=("what an earlier run left running cannot be checked here: flightdeck reads "
                                           "process start times on Linux and macOS only, not on sunos5",))
    monkeypatch.undo()
    time.sleep(0.2)
    assert proc.poll() is None


# ---------------------------------------------------------------- reading processes


def test_a_start_time_tells_one_process_from_another_and_a_group_lists_its_leader_first(tmp_path):
    proc = start(["sh", "-c", "sleep 300 & sleep 300 & wait"], tmp_path)
    members = wait_until(lambda: (lambda g: g if len(g) == 3 else None)(leftovers.group(proc.pid)), "the group's 3 processes")
    assert members[0].pid == proc.pid and {m.pgid for m in members} == {proc.pid}
    assert leftovers.process(proc.pid) == members[0]  # the same process, read again: the same start time
    assert leftovers.working_folder(proc.pid) == os.path.realpath(tmp_path)
    os.killpg(proc.pid, signal.SIGKILL)
    assert killed(proc)
    wait_until(lambda: leftovers.group(proc.pid) == [], "the group to be gone")
    assert leftovers.process(proc.pid) is None and leftovers.supported() is None


def stat_line(pid: int, name: str, state: str, pgid: int, started: int) -> str:
    """/proc/<pid>/stat as Linux writes it: pid (comm) state ppid pgrp session ... starttime ..."""
    return f"{pid} ({name}) {state} 1 {pgid} {pgid} 0 -1 4194560 120 0 0 0 3 1 0 0 20 0 1 0 {started} 2502656 220 18446744073709551615\n"


def test_on_linux_start_times_groups_and_folders_come_from_proc(tmp_path, monkeypatch):
    proc_dir = tmp_path / "proc"
    (proc_dir / "sys/kernel/random").mkdir(parents=True)
    (proc_dir / "sys/kernel/random/boot_id").write_text("6a1f-boot\n")
    work = tmp_path / "work"
    work.mkdir()
    for pid, name, state, pgid, started in [(700, "bash", "S", 700, 5000), (701, "sl) S 1 2 3 (eep", "R", 700, 5100),
                                            (702, "sleep", "Z", 700, 5200), (900, "other", "S", 900, 6000)]:
        (proc_dir / str(pid)).mkdir()
        (proc_dir / str(pid) / "stat").write_text(stat_line(pid, name, state, pgid, started))
        (proc_dir / str(pid) / "cwd").symlink_to(work)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(leftovers, "_PROC", str(proc_dir))
    leftovers._boot_id.cache_clear()
    try:
        assert leftovers.process(701) == leftovers.Proc(701, 700, "linux:6a1f-boot:5100")  # a name with ") S" in it
        assert leftovers.process(702) is None  # a zombie has exited
        assert leftovers.process(703) is None
        assert leftovers.processes_in([700, 900, 901]) == {
            700: [leftovers.Proc(700, 700, "linux:6a1f-boot:5000"), leftovers.Proc(701, 700, "linux:6a1f-boot:5100")],
            900: [leftovers.Proc(900, 900, "linux:6a1f-boot:6000")],
            901: [],
        }
        assert leftovers.working_folder(701) == str(work) and leftovers.working_folder(703) is None
    finally:
        leftovers._boot_id.cache_clear()


# ---------------------------------------------------------------- after flightdeck itself is killed


def pid_file_in(runs: Path) -> Path | None:
    """The lane's command's pid file in a run folder under `runs`, once written."""
    found = sorted(runs.glob("*/**/lane-pid.txt"))
    return found[0] if found and found[0].read_text().strip() else None


@pytest.mark.parametrize("where", ["in the config's runs folder", "in a folder play was given with --run-dir"])
def test_after_flightdeck_is_killed_doctor_names_its_lanes_command_and_the_next_play_stops_it(tmp_path, where):
    """Wherever the killed run's folder is, the next plain `doctor` names what it left and the
    next plain `play` stops it (a run outside the runs folder looked at is named by its path)."""
    from test_play_signals import QUIET, Terminal, env_for, gone, group_alive, make_board, make_config, wait_for

    elsewhere = where.endswith("--run-dir")
    runs = tmp_path / "event" / "runs" if elsewhere else tmp_path / "runs"  # the config's [run] dir is tmp_path/runs
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        cfg = make_config(tmp_path, server.base_url)
        played = make_board(tmp_path)
        argv = ["play", str(played), "--config", str(cfg), *(["--run-dir", str(runs)] if elsewhere else [])]
        term = Terminal(argv, env_for(tmp_path, XDG_STATE_HOME=os.environ["XDG_STATE_HOME"]), tmp_path)
        pgid = None
        try:
            pgid = int(wait_for(lambda: pid_file_in(runs), "the lane's command", term).read_text())
            (run_dir,) = runs.iterdir()
            # the command may write its pid file before flightdeck's loop has put its group in the record
            recorded = wait_for(lambda: [(g["pgid"], g["what"]) for g in record_of(run_dir)["groups"]],
                                "the lane's command in the run's record", term)
            assert recorded == [(pgid, "a lane command")]
            os.kill(term.proc.pid, signal.SIGKILL)  # no handler runs: the lane's command is left running
            term.proc.wait(timeout=60)
            time.sleep(0.5)
            assert group_alive(pgid)
            name = os.path.realpath(run_dir) if elsewhere else run_dir.name
            report = CliRunner().invoke(cli.app, ["doctor", "--config", str(cfg)]).output
            assert (f"warn leftovers: run {name} did not shut down (its flightdeck was killed, or the machine "
                    f"stopped) and left running: its process group {pgid} (a lane command in l01/work)") in report
            assert group_alive(pgid)
            run = prepare_run(RunOptions(board=played, config=cfg))
            run.close()
            assert (f"run {name} did not shut down (its flightdeck was killed, or the machine stopped); removed "
                    f"what it left running: its process group {pgid} (a lane command in l01/work)") in run.notes()
            assert gone(lambda: group_alive(pgid)), "the killed run's lane command is still running"
            assert not (run_dir / RECORD).exists() and list(leftovers.open_runs().iterdir()) == []  # and its note
        finally:
            term.close()
            if pgid is not None and group_alive(pgid):
                os.killpg(pgid, signal.SIGKILL)


def test_after_flightdeck_is_killed_its_lanes_container_is_removed_by_the_next_play(tmp_path):
    from test_play_signals import (
        IMAGE,
        QUIET,
        Terminal,
        _docker_missing,
        container_exists,
        env_for,
        lane_pid_file,
        make_board,
        make_config,
        wait_for,
    )

    missing = _docker_missing()
    if missing:
        docker_not_run(f"not run: needs docker and {IMAGE}: {missing}")
    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        cfg = make_config(tmp_path, server.base_url, runtime="docker")
        played = make_board(tmp_path)
        # the same state folder as the sweeps below: a sweep removes only its own setup's containers
        term = Terminal(["play", str(played), "--config", str(cfg)], env_for(tmp_path, XDG_STATE_HOME=os.environ["XDG_STATE_HOME"]),
                        tmp_path)
        name = None
        try:
            wait_for(lambda: lane_pid_file(tmp_path), "the lane's command in its container", term, timeout=180)
            (run_dir,) = (tmp_path / "runs").iterdir()
            name = f"flightdeck-{run_dir.name}-l01"
            inspect = subprocess.run(["docker", "container", "inspect", "--format", "{{json .Config.Labels}}", name],
                                     capture_output=True, text=True, timeout=60)
            marks = json.loads(inspect.stdout)
            assert (marks["flightdeck.run"], marks["flightdeck.pid"]) == (run_dir.name, str(term.proc.pid))
            os.kill(term.proc.pid, signal.SIGKILL)  # no handler runs: the container is left running
            term.proc.wait(timeout=60)
            assert container_exists(name)
            report = CliRunner().invoke(cli.app, ["doctor", "--config", str(cfg)]).output
            assert (f"warn leftovers: run {run_dir.name} did not shut down (its flightdeck was killed, or the machine "
                    f"stopped) and left running: its container {name}") in report
            run = prepare_run(RunOptions(board=played, config=cfg))
            run.close()
            assert (f"run {run_dir.name} did not shut down (its flightdeck was killed, or the machine stopped); removed "
                    f"what it left running: its container {name}") in run.notes()
            assert not container_exists(name)
        finally:
            term.close()
            if name is not None and container_exists(name):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)


# ---------------------------------------------------------------- a board and a config


def board(tmp_path: Path) -> Path:
    root = tmp_path / "board"
    if not root.exists():
        challenge_dir(root, "note", {"note.txt": "nothing here\n"}, id="note", description="a note")
        (root / "board.json").write_text(json.dumps({"event": "Leftovers", "flag_format": r"t\{[a-z0-9_]+\}"}))
    return root


def config(tmp_path: Path, base_url: str, *, runtime: str = "host") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[api]\nbase_url = "{base_url}"\nkey_env = ""\n'
        '[models]\nladder = ["fake/small", "fake/big"]\n'
        f'[lanes]\nmax_lanes = 1\nruntime = "{runtime}"\nimage = "{FAKE_IMAGE if runtime == "docker" else "unused"}"\n'
        f'[run]\ndir = "{tmp_path / "runs"}"\n'
    )
    return path
