"""Settings and health on the home screen (P79): the config's main settings with where each is
set, and doctor's checks, run in a child process the screen stops when the player leaves."""

from __future__ import annotations

import asyncio
import sys
import time

import pytest
from test_home import SLOW_DOCKER, docker_asked, drive_home, ended, slow_docker

from ctf_flightdeck import health, setup
from ctf_flightdeck.console import health as screen
from ctf_flightdeck.console import home as homes
from ctf_flightdeck.setup import Check

SECRET = "never-shown-value-7f3a9c"


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A home folder, a config and a keys file of the test's own; no key in the environment and
    no Docker. The config's path is returned for the test to write."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["m"]\n')
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    for variable in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MY_KEY"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "no-docker-here"))
    return config


def shown(rows) -> str:
    return screen.settings_text(rows).plain


def row(rows, name):
    (found,) = [r for r in rows if r.name == name]
    return found


def test_the_settings_say_what_each_is_and_where_it_is_set_and_never_a_keys_value(machine, tmp_path):
    machine.write_text('[api]\nbase_url = "https://models.example.org/v1?api_key=hunter2"\nkey_env = "MY_KEY"\n'
                       '[models]\nladder = ["small", "big"]\n'
                       '[lanes]\nruntime = "host"\n'
                       '[console]\nlayout = "deck"\nbell = false\n')
    keys = tmp_path / "keys.env"
    keys.write_text(f"MY_KEY={SECRET}\n")
    keys.chmod(0o600)
    rows = screen.settings()
    assert row(rows, "Config").value == str(machine) and row(rows, "Config").where == "named by $FLIGHTDECK_CONFIG"
    assert row(rows, "Model API").value == "openai, https://models.example.org/v1"  # no query, which may carry a key
    assert row(rows, "Models").value == "small, big (weakest first)"
    assert row(rows, "Models").where == "your config: [models] ladder"
    assert row(rows, "Lanes run").value == "on this machine (host)"
    assert (row(rows, "Layout").value, row(rows, "Layout").where) == (
        "deck", "your config: [console] layout. In a run: /layout, then s saves one.")
    assert (row(rows, "Theme").value, row(rows, "Theme").where) == (
        "flightdeck", "the default: your config has no [console] theme. In a run: /theme, then s saves one.")
    assert row(rows, "Bell").value == "off" and row(rows, "Bell").where.startswith("your config: [console] bell")
    assert row(rows, "Title").value == "on" and row(rows, "Title").where.startswith("the default: your config has no [console] title")
    assert row(rows, "Mouse").value == "on"
    key = row(rows, "API key")
    assert (key.value, key.where) == ("MY_KEY: set", f"in your keys file, {keys}")
    text = shown(rows)
    assert SECRET not in text and "hunter2" not in text
    assert [line.split()[0] for line in text.splitlines()[1::2]] == [
        "Config", "Model", "API", "Models", "Lanes", "Layout", "Theme", "Bell", "Title", "Mouse"]


def test_the_bell_unwritten_says_a_run_rings_it_and_the_mock_does_not(machine):
    bell = row(screen.settings(), "Bell")
    assert bell.value == "on in a run, off in the mock"
    assert bell.where.startswith("the default: your config has no [console] bell")
    machine.write_text('[models]\nladder = ["m"]\n[console]\nbell = true\n')
    assert row(screen.settings(), "Bell").value == "on"


def test_a_key_that_is_not_set_says_where_it_goes_and_one_set_in_the_environment_says_so(machine, tmp_path, monkeypatch):
    rows = screen.settings()
    key = row(rows, "API key")
    assert key.value == "OPENROUTER_API_KEY: not set"
    assert key.where == f"put OPENROUTER_API_KEY=<your key> in {tmp_path / 'keys.env'}, or export it"
    assert row(rows, "Model API").where == "the default: your config has no [api] base_url"
    monkeypatch.setenv("OPENROUTER_API_KEY", SECRET)
    key = row(screen.settings(), "API key")
    assert key.value == "OPENROUTER_API_KEY: set" and key.where.startswith("in your environment")
    assert SECRET not in shown(screen.settings())


def test_with_no_config_or_one_that_cannot_be_read_the_settings_say_so(machine):
    machine.unlink()
    rows = screen.settings()
    assert [r.name for r in rows] == ["Config", "Settings"] and rows[1].value == "none yet" and "Get started" in rows[1].where
    machine.write_text('[console]\nlayout = "sideways"\n[models]\nladder = ["m"]\n')
    rows = screen.settings()
    assert rows[1].value == "cannot be read" and "layout" in rows[1].where


def test_each_check_shows_its_state_and_a_fix_only_under_one_that_is_not_ok_and_the_verdict_counts_them():
    checks = [Check("python", True, "Python 3.12", "never shown"),
              Check("api key", False, "K is not set", "put K=<your key> in the keys file"),
              Check("terminal", False, "80x24: leaves out the board", "from 120x40 nothing", essential=False),
              Check("leftovers", False, "a container is left", essential=False)]
    text = screen.checks_text(checks).plain.splitlines()
    assert text == ["Health",
                    "1 thing to fix before a run: the FAIL line below. Besides, 2 warnings, which a run does not wait for.",
                    "ok   python: Python 3.12",
                    "FAIL api key: K is not set",
                    "     fix: put K=<your key> in the keys file",
                    "warn terminal: 80x24: leaves out the board",
                    "     fix: from 120x40 nothing",
                    "warn leftovers: a container is left"]
    assert screen.verdict(checks[2:])[0] == "Ready, with 2 warnings below that a run does not wait for."
    assert screen.verdict(checks[:1]) == ("Ready: nothing to fix.", "GREEN")


def test_check_text_from_a_file_cannot_draw_on_the_screen():
    text = screen.checks_text([Check("plugin x", False, "bad\x1b[2Jname\nsecond line", essential=False)]).plain
    (line,) = [line for line in text.splitlines() if line.startswith("warn")]
    assert "\x1b" not in text and "bad" in line and "second line" in line  # one line, and no escape reaches the terminal


def test_doctor_measures_the_terminal_its_caller_names(machine):
    (check,) = [c for c in setup.doctor(machine, terminal=(80, 24)) if c.name == "terminal"]
    assert check.detail.startswith("80x24:")
    assert not [c for c in setup.doctor(machine, terminal=(0, 0)) if c.name == "terminal"]


def test_the_wait_line_promises_the_checks_real_cap_never_a_shorter_one():
    # doctor's lane-image check alone may wait 60 s on Docker; only the cap bounds the whole run
    assert f"up to {health.CHECKS_TIMEOUT / 60:g} minutes" in screen.WAIT
    assert "20 s" not in screen.WAIT


def test_the_child_runs_doctors_checks_and_the_screen_reads_them(machine):
    checks = asyncio.run(health.run_checks(132, 41))
    names = [c.name for c in checks]
    assert names[:2] == ["python", "machine"] and "config" in names and "api key" in names
    (key,) = [c for c in checks if c.name == "api key"]
    assert not key.ok and key.essential and key.detail == "OPENROUTER_API_KEY is not set"
    (terminal,) = [c for c in checks if c.name == "terminal"]
    assert terminal.detail.startswith("132x41:")  # the size it was given: its own output is a pipe


@pytest.mark.parametrize("out", [b"not json", b'{"a": 1}', b'[{"name": "x"}]',
                                 b'[{"name": "x", "ok": "yes", "detail": "", "fix": "", "essential": true}]', b"\xff"])
def test_an_answer_that_is_not_the_checks_is_an_error_never_an_empty_list(out):
    with pytest.raises(health.HealthError, match="flightdeck doctor"):
        health.parse(out)


def test_a_child_that_fails_says_so_with_its_last_line(monkeypatch):
    monkeypatch.setattr(health, "child_command",
                        lambda c, l, config="", agent="": [sys.executable, "-c", "import sys; sys.stderr.write('first\\nboom here\\n'); sys.exit(3)"])
    with pytest.raises(health.HealthError, match=r"status 3 \(boom here\)"):
        asyncio.run(health.run_checks(80, 24))


def test_checks_that_take_too_long_are_stopped_with_docker_and_said(machine, tmp_path, monkeypatch):
    docker = slow_docker(tmp_path, monkeypatch, "timeout")
    began = time.monotonic()
    with pytest.raises(health.HealthError, match="longer than 3 s"):
        asyncio.run(health.run_checks(80, 24, timeout=3))
    assert time.monotonic() - began < SLOW_DOCKER / 2
    assert ended(int((docker / "pid").read_text()))


def drive(script, menu=None):
    return drive_home(menu or homes.items(have_config=True), script)


async def open_health(app, pilot):
    await pilot.press(*["down"] * (len(app.menu) - 1), "enter")
    await pilot.pause()
    assert isinstance(app.screen, screen.HealthScreen)
    return app.screen


def body(app) -> str:
    return "\n".join(str(w.render()) for w in app.screen.query("Static"))


def test_the_home_menu_offers_settings_and_health_last_and_after_setup_home_names_it(machine):
    menu = homes.items(have_config=True, pack_installed=True)
    assert [item.choice for item in menu][-1] == ("health",) and menu[-1].title == "Settings and health"
    assert "health" not in [item.choice[0] for item in homes.items(have_config=False)]  # setup comes first
    assert "settings and health" in homes.ready_items(homes.Ready())[-1].detail


def test_the_screen_shows_the_settings_at_once_waits_for_the_checks_and_r_runs_them_again(machine, monkeypatch):
    gate = asyncio.Event()
    calls = []

    async def stand_in(columns, lines):
        calls.append((columns, lines))
        await gate.wait()
        return [Check("python", True, "fine"), Check("api key", False, "X is not set", "set X")]

    monkeypatch.setattr(health, "run_checks", stand_in)

    async def script(app, pilot):
        page = await open_health(app, pilot)
        text = body(app)
        assert "Settings and health" in text and "Layout    simple" in text and screen.WAIT in text
        assert calls == [(140, 60)]  # the size of the terminal it was opened in
        gate.set()
        await app.workers.wait_for_complete()
        await pilot.pause()
        text = body(app)
        assert screen.WAIT not in text and "FAIL api key: X is not set" in text and "fix: set X" in text
        assert page.checked is not None and len(page.checked) == 2
        gate.clear()
        await pilot.press("r")
        await pilot.pause()
        assert len(calls) == 2 and screen.WAIT in body(app) and page.checked is None
        gate.set()
        await app.workers.wait_for_complete()
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Menu"
        await pilot.press("q")

    assert drive(script) is None


def test_checks_that_cannot_run_are_said_on_the_screen(machine, monkeypatch):
    async def broken(columns, lines):
        raise health.HealthError("the checks stopped with status 3 (boom)")

    monkeypatch.setattr(health, "run_checks", broken)

    async def script(app, pilot):
        page = await open_health(app, pilot)
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "The checks could not be run: the checks stopped with status 3 (boom)" in body(app)
        assert page.checked is None
        await pilot.press("escape", "q")

    drive(script)


def test_leaving_the_screen_stops_the_checks_and_leaves_no_docker_running(machine, tmp_path, monkeypatch):
    docker = slow_docker(tmp_path, monkeypatch, "leave")
    pids = []

    async def script(app, pilot):
        await open_health(app, pilot)
        pids.append(await docker_asked(pilot, docker))
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Menu"
        await pilot.press("q")

    began = time.monotonic()
    assert drive(script) is None
    assert time.monotonic() - began < SLOW_DOCKER / 2
    assert ended(pids[0]), "`docker version` was left running"
