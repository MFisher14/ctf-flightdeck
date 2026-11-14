"""A turn: what only one test at a time may do, across the processes of a parallel run
(`pytest -n`, CONTRIBUTING.md).

Tests run at once because each has its own temporary folder, state folder and ports. The
Docker daemon is the machine's, though, and a lane's container is named after its run folder,
which is named after the second the run started (flightdeck-<YYYYmmdd-HHMMSS>-l01: run.py,
eventlog.new_run_dir). Two tests that each start a real run in Docker in the same second ask
for the same container name, and the second one's lane gives up before it starts ("container
name ... is already in use"): its test then waits minutes for a command that never runs. So a
test that starts a real run in Docker holds the Docker-run turn from before the run starts
until its container is gone (the fixture one_docker_run_at_a_time, conftest.py), and the
config helper those tests share refuses to write a Docker config outside it
(test_play_signals.make_config).

A turn is an exclusive lock (flock) on a file in the folder every worker of the run shares
(shared_folder): the system gives it up when its holder ends, however it ends. A test that
names its containers itself (uuid, the time in nanoseconds) needs no turn.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

WAIT = 900.0  # seconds a test waits for its turn: longer than the tests before it can hold it
DOCKER_RUN = "docker-run.lock"

_in_docker_run = False


@contextlib.contextmanager
def turn(lock: Path, what: str, *, wait: float = WAIT, refused: Callable[[], None] | None = None) -> Iterator[None]:
    """Hold `lock` (a file, made here if absent) for the block: one holder at a time, in this
    process or any other. While another holds it this waits, for at most `wait` seconds, and
    then fails the test naming `what`. `refused` is called once, the first time the lock is
    found held."""
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + wait
        told = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                pass
            if not told and refused is not None:
                refused()
            told = True
            if time.monotonic() >= deadline:
                pytest.fail(f"waited {wait:g} s for {what} ({lock}): another test still holds it", pytrace=False)
            time.sleep(0.05)
        yield
    finally:
        os.close(fd)  # closing the file gives the lock up


def shared_folder(factory: pytest.TempPathFactory) -> Path:
    """The temporary folder every process of this test run shares: the run's base folder, of
    which a worker of a parallel run (pytest-xdist) has its own folder popen-<worker>."""
    base = factory.getbasetemp()
    worker = os.environ.get("PYTEST_XDIST_WORKER")
    if worker is None:
        return base
    if base.name != f"popen-{worker}":
        raise AssertionError(f"worker {worker}'s temporary folder is {base}, not a popen-{worker} in the run's: "
                             "where the workers' shared folder is cannot be told (tests/turns.py)")
    return base.parent


@contextlib.contextmanager
def docker_run(factory: pytest.TempPathFactory) -> Iterator[None]:
    """The Docker-run turn: the one test of this run that has a real run in Docker going."""
    global _in_docker_run
    with turn(shared_folder(factory) / DOCKER_RUN, "the turn to start a real run in Docker"):
        _in_docker_run = True
        try:
            yield
        finally:
            _in_docker_run = False


def in_docker_run() -> bool:
    """Whether this test holds the Docker-run turn."""
    return _in_docker_run
