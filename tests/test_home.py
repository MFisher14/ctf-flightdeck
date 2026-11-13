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


def choose(monkeypatch, choice):
    """The home screen ends with `choice`; what it was given is returned for the test to read."""
    given = {}

    def stand_in(menu, status):
        given.update(menu=menu, status=status)
        return choice

    monkeypatch.setattr(cli, "_home_choice", stand_in)
    return given


def drive_home(menu, script, status=""):
    import asyncio

    from ctf_flightdeck.console.home import HomeApp

    app = HomeApp(menu, status)

    async def main():
        async with app.run_test(size=(140, 60)) as pilot:
            await pilot.pause()
            await script(app, pilot)

    asyncio.run(main())
    return app.return_value


def test_the_home_menu_puts_the_last_event_first_and_offers_the_pack_only_when_it_is_missing(home):
    from ctf_flightdeck.console import home as homes

    root, _ = home
    event(root / "ctf" / "example", "Example CTF")
    menu = homes.items(have_config=True, events=events.known(), pack_installed=False)
    assert [item.choice[0] for item in menu] == ["resume", "new", "practice", "mock", "pack"]
    assert menu[0].title == "Resume Example CTF" and "0 challenges" in menu[0].detail
    assert "pack" not in [item.choice[0] for item in homes.items(have_config=True, pack_installed=True)]
    assert [item.choice[0] for item in homes.items(have_config=False, events=events.known())] == ["setup", "mock"]


def test_the_home_screen_opens_in_the_console_and_enter_takes_the_first_choice(home):
    from ctf_flightdeck.console import home as homes

    root, _ = home
    folder = event(root / "ctf" / "example", "Example CTF")
    menu = homes.items(have_config=True, events=events.known())

    async def script(app, pilot):
        shown = " ".join(str(w.render()) for w in app.screen.query("Static"))
        assert "What would you like to do?" in shown and "solvers: none" in shown
        await pilot.press("enter")

    assert drive_home(menu, script, "solvers: none") == ("resume", folder.resolve())

    async def down_twice(app, pilot):
        await pilot.press("down", "down", "enter")

    assert drive_home(menu, down_twice) == ("practice",)

    async def quit_it(app, pilot):
        await pilot.press("q")

    assert drive_home(menu, quit_it) is None


def test_the_new_ctf_form_says_what_is_missing_and_ends_with_the_event_it_describes(home, tmp_path):
    from ctf_flightdeck.console import home as homes

    vpn_file = tmp_path / "team.ovpn"
    vpn_file.write_text("client\n")

    async def script(app, pilot):
        await pilot.press("enter")  # Start a new CTF: the only event choice
        await pilot.pause()
        form = app.screen
        problem = lambda: str(form.query_one("#problem").render())  # noqa: E731
        await pilot.press("ctrl+s")
        assert "name" in problem()
        form.query_one("#name").value = "Example CTF 2026"
        await pilot.press("ctrl+s")
        assert "address" in problem()
        form.query_one("#url").value = "ctf.example.org"
        form.query_one("#flag").value = "EX"
        form.query_one("#token").value = "ctfd_synthetic"
        form.query_one("#vpn").value = str(vpn_file)
        await pilot.press("ctrl+s")
        assert "rules forbid" in problem() and app.return_value is None  # the AI question is never assumed
        form.query_one("#ai").value = "yes"
        assert form.query_one("#token").password is True
        await pilot.press("ctrl+s")

    kind, new = drive_home(homes.items(have_config=True), script)
    assert kind == "new" and new.folder == tmp_path / "home" / "ctf" / "example-ctf-2026"
    assert (new.answers.platform, new.answers.url, new.answers.token_env) == ("ctfd", "https://ctf.example.org", "CTFD_TOKEN_EXAMPLE_CTF_2026")
    assert (new.token, new.vpn) == ("ctfd_synthetic", vpn_file)


def test_flightdeck_alone_does_what_the_home_screen_ended_with(home, monkeypatch):
    root, launched = home
    folder = event(root / "ctf" / "example", "Example CTF")
    given = choose(monkeypatch, ("resume", folder))
    assert CliRunner().invoke(cli.app, []).exit_code == 0
    assert launched == [("play", folder)] and given["menu"][0].title == "Resume Example CTF"
    assert given["status"].startswith("solvers (L1): none installed")
    for choice, what in ((("practice",), "practice"), (("mock",), "mock"), (("setup",), "start")):
        launched.clear()
        choose(monkeypatch, choice)
        assert CliRunner().invoke(cli.app, []).exit_code == 0 and launched == [(what, None)]
    launched.clear()
    choose(monkeypatch, None)
    assert CliRunner().invoke(cli.app, []).exit_code == 0 and launched == []


def test_an_event_from_the_form_is_set_up_with_its_token_out_of_sight_and_played(home, tmp_path, monkeypatch):
    from ctf_flightdeck import keys
    from ctf_flightdeck.console.home import NewEvent
    from ctf_flightdeck.preflight import load_profile

    root, launched = home
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    folder = root / "ctf" / "example"
    answers = start.EventAnswers(name="Example", platform="ctfd", url="https://ctf.example.org", token_env="CTFD_TOKEN_EXAMPLE")
    choose(monkeypatch, ("new", NewEvent(answers, folder, "ctfd_synthetic", None)))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE": "ctfd_synthetic"} and "ctfd_synthetic" not in result.output
    assert load_profile(folder / "event.toml")[0].url == "https://ctf.example.org"
    assert launched == [("play", folder)] and [e.title for e in events.known()] == ["Example"]
    choose(monkeypatch, ("new", NewEvent(start.EventAnswers(name="Two", platform="ctfd", url="https://b.example.org",
                                                           token_env="CTFD_TOKEN_TWO"), root / "ctf" / "two", "", None)))
    result = CliRunner().invoke(cli.app, [])  # no token given and none kept: set up, said, not played
    assert result.exit_code == 2 and "no token yet: put CTFD_TOKEN_TWO=" in result.output and len(launched) == 1


def test_away_from_a_terminal_flightdeck_alone_prints_the_next_steps_and_asks_nothing(home, monkeypatch):
    _, launched = home
    monkeypatch.setattr(cli, "_at_terminal_out", lambda: False)
    monkeypatch.setattr(cli, "_home_choice", lambda *a: pytest.fail("no home screen without a terminal"))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0 and "flightdeck start" in result.output
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
