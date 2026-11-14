"""A turn (turns.py): one test at a time, across the processes of a parallel run.

The other holder here is a real second process, as another worker of `pytest -n` is: it says
when it was refused and when it got the turn by writing a file of each name into tmp_path.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from test_play_signals import make_config
from turns import DOCKER_RUN, docker_run, in_docker_run, shared_folder, turn

TESTS = Path(__file__).resolve().parent
FAILED = pytest.fail.Exception
# Takes the turn on argv[2] and says so in the folder argv[3]: "refused" when it found it held, "held" once it has it.
OTHER = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from turns import turn
out = Path(sys.argv[3])
with turn(Path(sys.argv[2]), "the other process's turn", refused=lambda: (out / "refused").write_text("")):
    (out / "held").write_text("")
"""


def other_process(lock: Path, out: Path) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", OTHER, str(TESTS), str(lock), str(out)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def seen(path: Path, proc: subprocess.Popen, timeout: float = 60.0) -> bool:
    """`path` is there; False once the process has ended without it, or the time is up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        if proc.poll() is not None:
            return path.exists()
        time.sleep(0.02)
    return False


def test_a_turn_is_one_process_at_a_time_and_the_next_gets_it_when_it_is_given_up(tmp_path):
    lock = tmp_path / "turn.lock"
    other = None
    try:
        with turn(lock, "this test's turn"):
            other = other_process(lock, tmp_path)
            assert seen(tmp_path / "refused", other), "the other process was never refused the turn this test holds"
            assert not (tmp_path / "held").exists() and other.poll() is None  # it waits
        assert seen(tmp_path / "held", other), "the other process never got the turn this test gave up"
        assert other.wait(timeout=30) == 0, other.stdout.read()
    finally:
        if other is not None and other.poll() is None:
            other.kill()
            other.wait()


def test_a_turn_nobody_holds_is_had_at_once_without_being_refused(tmp_path):
    other = other_process(tmp_path / "turn.lock", tmp_path)
    assert other.wait(timeout=60) == 0, other.stdout.read()
    assert (tmp_path / "held").exists() and not (tmp_path / "refused").exists()


def test_a_turn_is_given_up_when_its_block_fails(tmp_path):
    lock = tmp_path / "turn.lock"
    with pytest.raises(RuntimeError, match="the test failed"), turn(lock, "a turn"):
        raise RuntimeError("the test failed")
    with turn(lock, "a turn", wait=5):
        pass


def test_a_wait_for_a_turn_that_runs_out_fails_the_test_naming_the_turn(tmp_path):
    lock = tmp_path / "turn.lock"
    refusals = []
    with turn(lock, "a turn"):
        with pytest.raises(FAILED) as caught, turn(lock, "the turn to start a real run in Docker", wait=0.3,
                                                   refused=lambda: refusals.append(1)):
            pytest.fail("the turn was had while another held it")
    assert str(caught.value) == (f"waited 0.3 s for the turn to start a real run in Docker ({lock}): "
                                 "another test still holds it")
    assert refusals == [1]  # told once, however long the wait


def test_the_workers_of_a_parallel_run_share_the_runs_folder_not_their_own(tmp_path, monkeypatch):
    class Factory:
        def __init__(self, base: Path) -> None:
            self.base = base

        def getbasetemp(self) -> Path:
            return self.base

    run = tmp_path / "pytest-7"
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    assert shared_folder(Factory(run)) == run  # one process: its own base folder
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw3")
    assert shared_folder(Factory(run / "popen-gw3")) == run
    with pytest.raises(AssertionError, match="worker gw3's temporary folder is .*elsewhere, not a popen-gw3"):
        shared_folder(Factory(tmp_path / "elsewhere"))


def test_this_runs_shared_folder_is_the_one_every_worker_has(tmp_path_factory):
    """In the run this test is part of, parallel or not: the shared folder holds this process's base folder (or is it)."""
    shared = shared_folder(tmp_path_factory)
    base = tmp_path_factory.getbasetemp()
    worker = os.environ.get("PYTEST_XDIST_WORKER")
    assert shared == (base if worker is None else base.parent) and shared.is_dir()


def test_the_docker_run_turn_is_held_for_the_block_on_the_runs_shared_lock(tmp_path_factory):
    lock = shared_folder(tmp_path_factory) / DOCKER_RUN
    assert not in_docker_run()
    with docker_run(tmp_path_factory):
        assert in_docker_run()
        with pytest.raises(FAILED, match="another test still holds it"), turn(lock, "the same turn", wait=0.2):
            pytest.fail("the Docker-run turn was had twice")
    assert not in_docker_run()


def test_the_fixture_gives_a_test_the_docker_run_turn(one_docker_run_at_a_time):
    assert in_docker_run()


def test_a_config_for_a_real_run_in_docker_is_refused_outside_the_turn_and_a_host_one_is_not(tmp_path):
    with pytest.raises(AssertionError, match="one_docker_run_at_a_time"):
        make_config(tmp_path, "http://127.0.0.1:9/v1", runtime="docker")
    assert not (tmp_path / "config.toml").exists()
    assert 'runtime = "host"' in make_config(tmp_path, "http://127.0.0.1:9/v1").read_text()


def test_inside_the_turn_the_docker_config_is_written(tmp_path, one_docker_run_at_a_time):
    assert 'runtime = "docker"' in make_config(tmp_path, "http://127.0.0.1:9/v1", runtime="docker").read_text()
