"""Settings and health in a running console (P90): `/settings` opens the home screen's screen
over the lanes, with this run's own settings on top, and its checks never wait on the console.

The consoles are test_layout's synthetic decks (a driver that does no work); the checks are a
stand-in the test controls, except where the real child process is the point, and then it runs
against a config of the test's own with no Docker on PATH.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys

import pytest
from test_console import assert_warning, press
from test_health import machine  # noqa: F401  (the fixture: a home, a config and a keys file of the test's own)
from test_layout import SIZE, drive, three_lanes

from ctf_flightdeck import health
from ctf_flightdeck.console import health as screen
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.setup import API_CHECKS, Check


def body(app) -> str:
    return "\n".join(str(w.render()) for w in app.screen.query("Static"))


class StandIn:
    """Checks the test answers: each call is recorded with its config, and waits for `gate`.
    The run's agent, when the screen names one, is recorded in `agents`."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, int, str | None]] = []
        self.gate = asyncio.Event()
        self.cancelled = 0
        self.agents: list[str | None] = []

    async def __call__(self, columns, lines, *, config=None, agent=None):
        self.calls.append((columns, lines, config))
        self.agents.append(agent)
        try:
            await self.gate.wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        return [Check("python", True, "fine"), Check("docker", False, "not found", "install Docker", essential=False)]


@pytest.fixture
def checks(monkeypatch):
    stand_in = StandIn()
    monkeypatch.setattr(health, "run_checks", stand_in)
    monkeypatch.setattr(screen.HealthScreen, "TICK", 0.05)
    return stand_in


def test_settings_in_a_run_shows_the_runs_settings_the_setup_of_its_config_and_the_lanes_that_wait(machine, checks):
    machine.write_text('[models]\nladder = ["m"]\n[console]\ntheme = "nord"\n')
    deck, app = three_lanes("simple", config_path=str(machine))

    async def script(pilot):
        gate = checks.gate
        await press(pilot, "slash", *"settings", "enter")
        assert isinstance(app.screen, screen.HealthScreen)
        text = body(app)
        assert "This run (/config changes these; c opens it)" in text
        assert "Lanes     4 at once" in text and "for this run: /config lanes N, or the dialog" in text
        assert "Flags     each waits for your yes" in text and "Layout    simple" in text
        assert "Your setup" in text and f"Config    {machine}" in text and "Theme     nord" in text  # the config's, read for the screen
        assert "2 lanes need you: esc goes back to the lanes." in text  # L02's flag and L03's alert
        assert screen.WAIT in text
        assert checks.calls == [(SIZE[0], SIZE[1], str(machine))]  # the run's config, at the terminal's size
        deck.report("L01", TurnReport(action="cat flag.txt", flag="flag{another}"))  # the lanes go on while it is open
        await pilot.pause(0.3)
        assert "3 lanes need you" in body(app)
        gate.set()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "warn docker: not found" in body(app) and screen.WAIT not in body(app)
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)

    drive(app, script, SIZE)


def test_settings_opened_again_shows_the_checks_it_found_with_their_age_and_runs_nothing_until_r(machine, checks):
    deck, app = three_lanes("simple", config_path=str(machine))

    async def script(pilot):
        checks.gate.set()
        await press(pilot, "slash", *"settings", "enter")
        await app.workers.wait_for_complete()
        await press(pilot, "escape")
        await press(pilot, "slash", *"settings", "enter")
        assert isinstance(app.screen, screen.HealthScreen) and len(checks.calls) == 1
        text = body(app)
        assert "warn docker: not found" in text and "Checked less than a minute ago: r checks again." in text
        assert screen.WAIT not in text
        checks.gate.clear()
        await press(pilot, "r")
        assert len(checks.calls) == 2 and screen.WAIT in body(app)
        await press(pilot, "escape")  # left before they answered: nothing is kept, so the next open checks again
        assert checks.cancelled == 1
        checks.gate.set()
        await press(pilot, "slash", *"settings", "enter")
        assert len(checks.calls) == 3
        await app.workers.wait_for_complete()
        await press(pilot, "escape")

    drive(app, script, SIZE)


def test_leaving_settings_while_the_checks_wait_stops_them_and_the_console_answers_at_once(machine, checks):
    deck, app = three_lanes("simple", config_path=str(machine))

    async def script(pilot):
        await press(pilot, "slash", *"settings", "enter")
        assert screen.WAIT in body(app) and checks.calls
        await press(pilot, "escape")  # the checks never answer: the console is the player's all the same
        assert isinstance(app.screen, FleetScreen) and checks.cancelled == 1
        await press(pilot, "slash", *"config", "enter")
        assert type(app.screen).__name__ == "ConfigPrompt"
        await press(pilot, "escape")

    drive(app, script, SIZE)


def test_c_on_settings_opens_configs_dialog_in_its_place(machine, checks):
    deck, app = three_lanes("simple", config_path=str(machine))

    async def script(pilot):
        checks.gate.set()
        await press(pilot, "slash", *"settings", "enter")
        await app.workers.wait_for_complete()
        await press(pilot, "c")
        assert type(app.screen).__name__ == "ConfigPrompt"
        assert not any(isinstance(s, screen.HealthScreen) for s in app.screen_stack)
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)

    drive(app, script, SIZE)


def test_settings_in_the_mock_says_it_reads_no_config_and_checks_the_one_flightdeck_reads(machine, checks):
    deck, app = three_lanes("simple")  # config_path "": the mock's console

    async def script(pilot):
        checks.gate.set()
        await press(pilot, "slash", *"settings", "enter")
        text = body(app)
        assert "the mock reads none: below is the one flightdeck reads" in text and f"Config    {machine}" in text
        assert checks.calls == [(SIZE[0], SIZE[1], None)]  # no config named: the child reads the usual one
        await app.workers.wait_for_complete()
        await press(pilot, "escape")

    drive(app, script, SIZE)


@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_settings_in_an_agent_run_checks_that_agent_as_doctor_agent_does(machine, checks, agent):
    deck, app = three_lanes("simple", config_path=str(machine), agent=agent)

    async def script(pilot):
        checks.gate.set()
        await press(pilot, "slash", *"settings", "enter")
        await app.workers.wait_for_complete()
        assert checks.calls == [(SIZE[0], SIZE[1], str(machine))] and checks.agents == [agent]
        await press(pilot, "escape")

    drive(app, script, SIZE)


def test_settings_in_a_run_of_flightdecks_own_lanes_names_no_agent(machine, checks):
    deck, app = three_lanes("simple", config_path=str(machine))

    async def script(pilot):
        checks.gate.set()
        await press(pilot, "slash", *"settings", "enter")
        await app.workers.wait_for_complete()
        assert checks.agents == [None]
        await press(pilot, "escape")

    drive(app, script, SIZE)


def test_a_run_started_with_an_agent_gives_its_console_that_agent(machine):
    from types import SimpleNamespace

    from test_console import FakeWorld, scenarios

    from ctf_flightdeck.config import load_config
    from ctf_flightdeck.run import Run

    machine.write_text('[models]\nladder = ["m"]\n')
    for agent, told in (("claude", "claude"), (None, "")):
        of_a_run = SimpleNamespace(config=load_config(machine), deck=FakeWorld(scenarios.get("sstv")).deck, dir=machine.parent,
                                   by_hand=False, release=None, shutdown=None, options=SimpleNamespace(agent=agent))
        assert Run.app(of_a_run).agent == told


def test_the_child_is_told_the_agent_and_checks_it_as_doctor_agent_does(monkeypatch, capsys):
    from pathlib import Path

    from ctf_flightdeck import setup

    assert health.child_command(80, 24, "/x/event.toml", "codex")[-5:] == ["80", "24", "--agent", "codex", "/x/event.toml"]
    assert health.child_command(80, 24, "", "claude")[-4:] == ["80", "24", "--agent", "claude"]
    said = []
    monkeypatch.setattr(health, "lower_priority", lambda: None)
    monkeypatch.setattr(setup, "doctor", lambda path, agent, terminal: said.append((path, agent, terminal)) or [])
    assert health.main(["80", "24", "--agent", "claude", "/x/event.toml"]) == 0
    assert health.main(["80", "24", "--agent", "codex"]) == 0
    assert said == [(Path("/x/event.toml"), "claude", (80, 24)), (None, "codex", (80, 24))]
    for wrong in (["80", "24", "--agent"], ["80", "24", "--agent", "gpt"], ["80", "24", "--agent", "claude", "a", "b"]):
        assert health.main(wrong) == 64
    assert said == [(Path("/x/event.toml"), "claude", (80, 24)), (None, "codex", (80, 24))]


def test_the_childs_checks_for_an_agent_run_make_the_api_key_a_warning(machine):
    """The real child, with no key in the environment (machine): for flightdeck's own lanes
    the [api] key is essential; told the run's agent, it is a warning, and that agent's CLI
    is checked."""
    own = {c.name: c for c in asyncio.run(health.run_checks(0, 0, config=str(machine)))}
    told = {c.name: c for c in asyncio.run(health.run_checks(0, 0, config=str(machine), agent="claude"))}
    api = [name for name in API_CHECKS if name in own and not own[name].ok]
    assert api, f"the test's machine has no failing [api] check to compare: {sorted(own)}"
    for name in api:
        assert own[name].essential and not told[name].essential
    assert set(told) - set(own), "told the agent, the child checks something more: that agent's CLI"


def test_settings_with_a_word_is_refused_with_where_configs_went_and_changes_nothing(machine, checks):
    deck, app = three_lanes("simple", config_path=str(machine))

    async def script(pilot):
        await press(pilot, "slash", *"settings lanes 8", "enter")
        assert_warning(app, "/settings takes no argument: /config lanes 8 changes this run's")
        assert isinstance(app.screen, FleetScreen) and deck.config.max_lanes == 4 and checks.calls == []

    drive(app, script, SIZE)


def test_the_settings_of_a_run_started_with_another_config_are_that_configs(machine, tmp_path):
    other = tmp_path / "event.toml"
    other.write_text('[models]\nladder = ["one", "two"]\n[console]\nlayout = "deck"\n')
    rows = {row.name: row for row in screen.settings(other)}
    assert rows["Config"].value == str(other) and rows["Config"].where == "the config this run started with (--config)"
    assert rows["Models"].value == "one, two (weakest first)" and rows["Layout"].where.startswith("your config: [console] layout")
    same = {row.name: row for row in screen.settings(machine)}  # the usual one, named: said as the usual one
    assert same["Config"].where == "named by $FLIGHTDECK_CONFIG"


def test_the_child_checks_the_config_it_is_named_not_the_usual_one(machine, tmp_path):
    other = tmp_path / "event.toml"
    other.write_text('[models]\nladder = ["one", "two"]\n')
    assert health.child_command(80, 24, str(other))[-3:] == ["80", "24", str(other)]
    (config,) = [c for c in asyncio.run(health.run_checks(80, 24, config=str(other))) if c.name == "config"]
    assert config.ok and config.detail.startswith(f"{other}: 2 model(s)")


def test_the_child_lowers_its_own_priority_before_it_checks_anything():
    if os.nice(0) + health.NICE > 19:
        pytest.skip("this test already runs at the lowest priority: the child could go no lower (not run)")
    probe = ("import os; from ctf_flightdeck import health; before = os.nice(0); health.lower_priority(); "
             "print(os.nice(0) - before)")
    out = subprocess.run([sys.executable, "-P", "-c", probe], capture_output=True, text=True, check=True).stdout
    assert out.strip() == str(health.NICE)


def test_the_childs_main_lowers_its_priority_before_doctor_runs(monkeypatch, capsys):
    from ctf_flightdeck import setup

    said = []
    monkeypatch.setattr(health, "lower_priority", lambda: said.append("lowered"))
    monkeypatch.setattr(setup, "doctor", lambda path, agent, terminal: said.append(("doctor", path, terminal)) or [])
    assert health.main(["80", "24", "/x/event.toml"]) == 0
    assert said == ["lowered", ("doctor", __import__("pathlib").Path("/x/event.toml"), (80, 24))]
    assert health.main(["80", "24", ""]) == 64 and health.main(["80"]) == 64


def test_on_the_home_screen_c_is_no_key(machine, monkeypatch):
    from test_health import drive as drive_home_screen
    from test_health import open_health

    async def answered(columns, lines):
        return [Check("python", True, "fine")]

    monkeypatch.setattr(health, "run_checks", answered)

    async def script(app, pilot):
        page = await open_health(app, pilot)
        assert "change this run's" not in body(app)
        await pilot.press("c")
        await pilot.pause()
        assert app.screen is page  # nothing to change from home: c is not bound there
        await pilot.press("escape", "q")

    drive_home_screen(script)
