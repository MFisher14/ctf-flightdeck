"""Shared test setup.

Textual reads a few environment variables that would make headless runs press keys or
take screenshots on their own; clear them so tests only see what they do themselves.
"""

from __future__ import annotations

import os

for _name in list(os.environ):
    if _name.startswith(("TEXTUAL_PRESS", "TEXTUAL_SCREENSHOT")):
        del os.environ[_name]
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"  # plain CLI output in CliRunner


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def no_real_keys_file(tmp_path_factory, monkeypatch):
    """No test reads the player's real keys file: FLIGHTDECK_KEYS points at a file that does
    not exist, unless a test sets its own."""
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path_factory.mktemp("keys") / "absent-keys.env"))


@pytest.fixture(autouse=True)
def own_state_folder(tmp_path_factory, monkeypatch):
    """Each test has a state folder of its own (XDG_STATE_HOME), never the player's: what a
    run notes there, and the containers a sweep may remove (leftovers.py), are the test's
    only. Commands a test starts get it through the environment they inherit."""
    state = tmp_path_factory.mktemp("state")
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    # the player has seen the welcome screen: a test's console opens on the dashboard (cli._first_console)
    (state / "ctf-flightdeck").mkdir()
    (state / "ctf-flightdeck" / "welcomed").write_text("")


@pytest.fixture
def one_docker_run_at_a_time(tmp_path_factory):
    """For a test that starts a real run in Docker (`flightdeck play` with runtime = "docker"):
    it holds the Docker-run turn for its whole length, so no other test of this run, in this
    process or another worker's (`pytest -n`), has such a run going beside it. A lane's
    container is named after the second its run started, so two such runs started in the same
    second ask Docker for one name, and the second one's lane never starts (turns.py)."""
    from turns import docker_run

    with docker_run(tmp_path_factory):
        yield


@pytest.fixture(autouse=True)
def calm_host(monkeypatch):
    """No test depends on this machine's load, RAM or disk: what a run's host governor and
    doctor's host line read (governor.probe) is a calm machine, the same everywhere. The tests
    of the probe itself (test_governor.py) replace this fixture with one that does nothing;
    a test that wants a busy machine gives its own reading (RunOptions.host_reading, or the
    Governor's `read`)."""
    from ctf_flightdeck import governor
    from ctf_flightdeck.hardware import GIB, Fact

    def calm(path, host=None, **readers):
        return governor.Reading(load=Fact(0.5), cpus=Fact(8), free_ram=Fact(16 * GIB), free_disk=Fact(200 * GIB), disk_path=str(path))

    monkeypatch.setattr(governor, "probe", calm)


@pytest.fixture(autouse=True)
def no_real_file_window(monkeypatch):
    """No test opens the operating system's file window (filepick.choose): one that would
    fails instead. A test of the window gives its own stand-in."""
    from ctf_flightdeck import filepick

    real = filepick.choose

    def guarded(*args, **kwargs):
        if "run" not in kwargs and "which" not in kwargs:
            raise AssertionError("a test would have opened a real file window: give filepick.choose a stand-in")
        return real(*args, **kwargs)

    monkeypatch.setattr(filepick, "choose", guarded)


@pytest.fixture(autouse=True)
def no_real_clipboard(monkeypatch):
    """No test changes the real clipboard (clipboard.copy_text): one that would fails instead.
    A console under test gets its own copier; a test of the tools gives its own runner."""
    import subprocess

    from ctf_flightdeck import clipboard

    real = clipboard.copy_text

    def guarded(*args, **kwargs):
        if kwargs.get("run", subprocess.run) is subprocess.run:
            raise AssertionError("a test would have changed the real clipboard: give FlightdeckApp a copier, or clipboard.copy_text a runner")
        return real(*args, **kwargs)

    monkeypatch.setattr(clipboard, "copy_text", guarded)


@pytest.fixture(autouse=True)
def default_palette():
    """Each test starts and ends in the default theme: the palette in use is one for the whole
    process (console/theme.py), and a console a test opened in another theme would colour the
    next test's."""
    from ctf_flightdeck import themes
    from ctf_flightdeck.console import theme

    theme.use(themes.DEFAULT)
    yield
    theme.use(themes.DEFAULT)
