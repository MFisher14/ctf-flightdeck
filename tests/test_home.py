"""`flightdeck` alone: the opening menu at a terminal, and the events it offers to resume."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli, events, start, start_cli


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A home folder, a config and a terminal of the test's own; what the menu launched."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home" / "ctf").mkdir(parents=True)
    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["m"]\n')
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    monkeypatch.setattr(cli, "_at_terminal", lambda: True)
    monkeypatch.setattr(cli, "_at_terminal_out", lambda: True)
    launched = []
    monkeypatch.setattr(cli, "play", lambda **kw: launched.append(("play", kw.get("board"))))
    monkeypatch.setattr(cli, "practice", lambda **kw: launched.append(("practice", None)))
    monkeypatch.setattr(cli, "mock", lambda **kw: launched.append(("mock", None)))
    monkeypatch.setattr(start_cli, "start", lambda **kw: launched.append(("start", None)))
    return tmp_path / "home", launched


def event(folder, name):
    start.write(folder, start.EventAnswers(name=name, platform="manual"))
    return folder


def test_events_are_found_in_the_note_and_in_the_ctf_folder_newest_first_and_gone_ones_dropped(home, tmp_path):
    root, _ = home
    old = event(root / "ctf" / "old-ctf", "Old CTF")  # made before the note existed: found in ~/ctf
    new = event(tmp_path / "elsewhere" / "new", "New CTF")
    gone = event(tmp_path / "gone", "Gone")
    events.remember(new, now=2_000_000_000.0)
    events.remember(gone, now=2_000_000_001.0)
    (gone / "event.toml").unlink()
    (new / "board" / "one").mkdir()
    (new / "board" / "one" / "challenge.json").write_text("{}")
    (root / "ctf" / "notes").mkdir()  # a folder that is no event
    found = events.known()
    assert [(e.title, e.challenges) for e in found] == [("New CTF", 1), ("Old CTF", 0)]
    assert found[0].folder == new.resolve() and found[0].played == 2_000_000_000.0


def test_how_long_ago_reads_in_a_few_words():
    assert [events.ago(1000 - s, now=1000) for s in (5, 120, 7200, 86400 * 3)] == ["just now", "2 minutes ago", "2 hours ago", "3 days ago"]


def test_flightdeck_alone_offers_to_resume_the_last_event_first_and_plays_it_on_enter(home):
    root, launched = home
    folder = event(root / "ctf" / "example", "Example CTF")
    result = CliRunner().invoke(cli.app, [], input="\n")
    assert result.exit_code == 0, result.output
    assert "1  Resume Example CTF" in result.output and "2  Start a new CTF" in result.output
    assert "3  Practice" in result.output and "4  Mock" in result.output and "solvers (L1): none installed" in result.output
    assert launched == [("play", folder.resolve())]


@pytest.mark.parametrize(("typed", "what"), [("1", "start"), ("2", "practice"), ("3", "mock")])
def test_with_no_event_yet_the_menu_starts_one_or_practices_or_opens_the_mock(home, typed, what):
    _, launched = home
    result = CliRunner().invoke(cli.app, [], input=f"{typed}\n")
    assert result.exit_code == 0 and "Resume" not in result.output
    assert launched == [(what, None)]


def test_the_menu_asks_again_for_a_number_it_does_not_have_and_q_launches_nothing(home):
    _, launched = home
    result = CliRunner().invoke(cli.app, [], input="9\nq\n")
    assert result.exit_code == 0 and "choose a number from 1 to 3, or q" in result.output
    assert launched == [] and "flightdeck --help" in result.output


def test_with_no_config_the_menu_offers_setup_and_the_mock_only(home, monkeypatch, tmp_path):
    root, launched = home
    event(root / "ctf" / "example", "Example CTF")
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "absent.toml"))
    result = CliRunner().invoke(cli.app, [], input="1\n")
    assert "1  Set up flightdeck and start a CTF" in result.output and "2  Mock" in result.output
    assert "Resume" not in result.output and "Practice" not in result.output
    assert launched == [("start", None)]


def test_away_from_a_terminal_flightdeck_alone_prints_the_next_steps_and_asks_nothing(home, monkeypatch):
    _, launched = home
    monkeypatch.setattr(cli, "_at_terminal_out", lambda: False)
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0 and "flightdeck start" in result.output and "Choose" not in result.output
    assert launched == []


def test_setting_an_event_up_and_playing_it_both_note_it_for_the_menu(home, tmp_path, monkeypatch):
    from ctf_flightdeck import run as runs

    monkeypatch.undo()
    monkeypatch.setenv("HOME", str(tmp_path / "home2"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state2"))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    config = tmp_path / "config.toml"
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    monkeypatch.setattr(cli, "_at_terminal", lambda: False)
    folder = tmp_path / "far" / "away"
    result = CliRunner().invoke(cli.app, ["start", str(folder), "--name", "Far CTF", "--platform", "manual", "--ai-allowed"])
    assert result.exit_code == 0, result.output
    assert [e.title for e in events.known()] == ["Far CTF"]
    first = events.known()[0].played
    monkeypatch.setattr(runs, "prepare_run", lambda options: (_ for _ in ()).throw(runs.RunError("stopped by the test")))
    monkeypatch.setattr(events.time, "time", lambda: first + 500)
    CliRunner().invoke(cli.app, ["play", str(folder)])
    assert events.known()[0].played == first + 500


# ---------------------------------------------------------------------- the welcome screen


def test_the_first_real_console_is_noted_so_only_it_opens_on_the_welcome():
    from ctf_flightdeck.leftovers import state_folder

    (state_folder() / "welcomed").unlink()  # a machine flightdeck has not opened a console on
    assert cli._first_console() is True and cli._first_console() is False


def test_the_live_mock_opens_on_a_welcome_that_enter_closes(monkeypatch):
    import asyncio

    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    async def main():
        world = FakeWorld(scenarios.get("default"))
        app = FlightdeckApp(world.deck, ticker=world.tick, tick_seconds=None, refresh_seconds=None, mock="MOCK", welcome=True)
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            assert type(app.screen).__name__ == "WelcomeScreen"
            shown = " ".join(str(w.render()) for w in app.screen.query("Static"))
            assert "demo on fake data" in shown and "nothing spent" in shown and "open the console" in shown
            await pilot.press("enter")
            await pilot.pause()
            assert type(app.screen).__name__ == "FleetScreen"

    asyncio.run(main())
    built = {}
    monkeypatch.setattr(FlightdeckApp, "run", lambda self, **kw: built.update(welcome=self.welcome))
    assert CliRunner().invoke(cli.app, ["mock"]).exit_code == 0 and built == {"welcome": True}


def test_on_an_empty_board_the_welcome_leads_straight_to_adding_a_challenge(tmp_path):
    import asyncio

    from ctf_flightdeck.run import prepare_run
    from fake_model import FakeModelServer
    from test_addchallenge import options

    async def main():
        with FakeModelServer([]) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None, welcome=True)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                shown = " ".join(str(w.render()) for w in app.screen.query("Static"))
                assert "Your board is empty" in shown and "add your first challenge" in shown
                await pilot.press("enter")
                await pilot.pause()
                assert type(app.screen).__name__ == "NewChallengePrompt"
                await pilot.press("escape")
            await run.shutdown()
            run.close()

    asyncio.run(main())
