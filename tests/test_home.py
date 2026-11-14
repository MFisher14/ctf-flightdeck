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
    monkeypatch.setattr(cli, "image_build", lambda **kw: launched.append(("image build", kw.get("tag"))))  # never a real docker build
    monkeypatch.setattr(start_cli, "start", lambda **kw: pytest.fail("the home screen asks nothing in the terminal"))
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


def choose(monkeypatch, *choices):
    """The home screen ends with each of `choices` in turn, and then with the player quitting
    it (None): flightdeck opens it again after each choice it has done. What it was given is
    returned for the test to read: the first time under "menu", "status", "palette" and
    "ready", and every time, in order, under "calls"."""
    given = {"calls": []}
    left = list(choices)

    def stand_in(menu, status, *, palette=None, ready=None):
        call = dict(menu=menu, status=status, palette=palette, ready=ready)
        if not given["calls"]:
            given.update(call)
        given["calls"].append(call)
        return left.pop(0) if left else None

    monkeypatch.setattr(cli, "_home_choice", stand_in)
    return given


def drive_home(menu, script, status="", ready=None):
    import asyncio

    from ctf_flightdeck.console.home import HomeApp

    app = HomeApp(menu, status, ready=ready)

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
    assert [item.choice[0] for item in menu] == ["resume", "new", "practice", "mock", "pack", "health"]
    assert menu[0].title == "Resume Example CTF" and "0 challenges" in menu[0].detail
    assert "pack" not in [item.choice[0] for item in homes.items(have_config=True, pack_installed=True)]
    # no config yet: setup that leads to the practice set first, starting an event one below (setup first too), the demo
    first_time = homes.items(have_config=False, events=events.known())
    assert [item.choice for item in first_time] == [("setup", "practice"), ("setup", "new"), ("mock",)]
    assert [item.title for item in first_time] == ["Get started", "Start a new CTF", "See a demo"]


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
        form.query_one("#label").value = "see https://example.org"
        await pilot.press("ctrl+s")
        assert "give the label as a few words" in problem() and app.return_value is None  # no label: said while the form is open
        form.query_one("#label").value = "Human-Led AI"
        assert form.query_one("#token").password is True
        await pilot.press("ctrl+s")

    kind, new = drive_home(homes.items(have_config=True), script)
    assert kind == "new" and new.folder == tmp_path / "home" / "ctf" / "example-ctf-2026"
    assert new.answers.label == "Human-Led AI"
    assert (new.answers.platform, new.answers.url, new.answers.token_env) == ("ctfd", "https://ctf.example.org", "CTFD_TOKEN_EXAMPLE_CTF_2026")
    assert (new.token, new.vpn) == ("ctfd_synthetic", vpn_file)


def fill(form, **fields):
    for field, value in fields.items():
        form.query_one(f"#{field}").value = value


def test_the_new_ctf_form_refuses_a_folder_that_cannot_be_made_and_a_token_that_cannot_be_kept_while_it_is_open(home, tmp_path, monkeypatch):
    """What would stop the event being set up is said in the form, with every answer still
    in it: not after the app has gone, with the token already in the keys file."""
    from ctf_flightdeck import keys
    from ctf_flightdeck.console import home as homes

    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    (tmp_path / "plainfile").write_text("a file\n")

    async def script(app, pilot):
        await pilot.press("enter")
        await pilot.pause()
        form = app.screen
        problem = lambda: str(form.query_one("#problem").render())  # noqa: E731
        fill(form, name="Example CTF", url="ctf.example.org", token="ctfd_synthetic", ai="yes", folder=str(tmp_path / "plainfile" / "sub"))
        await pilot.press("ctrl+s")
        assert f"Folder: {tmp_path / 'plainfile' / 'sub'} cannot be made: {tmp_path / 'plainfile'} is a file, not a folder" in problem()
        assert app.return_value is None and form.query_one("#name").value == "Example CTF"  # still open, the answers still there
        fill(form, folder=str(tmp_path / "events" / "example"), token='"ctfd_synthetic"')
        await pilot.press("ctrl+s")
        assert "Token: it is in quotes: give it without them" in problem() and "ctfd_synthetic" not in problem()
        fill(form, token="ctfd_syn\u2028thetic")
        await pilot.press("ctrl+s")
        assert "Token: it has a line break in it (U+2028)" in problem() and app.return_value is None
        (tmp_path / "keys.env").write_text("OTHER=one\n")
        (tmp_path / "keys.env").chmod(0o644)
        fill(form, token="ctfd_synthetic")
        await pilot.press("ctrl+s")
        assert "Token: " in problem() and "chmod 600" in problem() and app.return_value is None  # a keys file that would refuse it
        (tmp_path / "keys.env").chmod(0o600)
        await pilot.press("ctrl+s")

    kind, new = drive_home(homes.items(have_config=True), script)
    assert kind == "new" and (new.folder, new.token) == (tmp_path / "events" / "example", "ctfd_synthetic")
    assert not (tmp_path / "events").exists() and keys.load_keys(tmp_path / "keys.env") == {"OTHER": "one"}  # the form itself writes nothing


def test_the_new_ctf_form_says_what_it_made_of_the_flag_format_as_it_is_typed(home, tmp_path):
    from ctf_flightdeck.console import home as homes

    async def script(app, pilot):
        await pilot.press("enter")
        await pilot.pause()
        form = app.screen
        read = lambda: str(form.query_one("#flagread").render())  # noqa: E731
        assert read() == ""
        fill(form, flag="CTF{s0me_t3xt}")  # the rules' example flag, pasted
        await pilot.pause()
        assert read() == ("read CTF{s0me_t3xt} as an example flag: flags look like CTF{...}, with any text between the braces "
                          "(the regular expression CTF\\{[^}]+\\})")
        fill(form, flag="CTF\\{[")
        await pilot.pause()
        assert "neither a prefix (like PP) nor a regular expression" in read()
        fill(form, flag="")
        await pilot.pause()
        assert read() == ""
        fill(form, name="Example CTF", url="ctf.example.org", ai="yes", flag="CTF{s0me_t3xt}")
        await pilot.press("ctrl+s")

    kind, new = drive_home(homes.items(have_config=True), script)
    assert kind == "new" and new.answers.flag_format == r"CTF\{[^}]+\}"


def test_the_new_ctf_form_never_takes_another_sites_token_for_this_event(home, tmp_path, monkeypatch):
    """An event of the same name at another site was set up before, and its token is in the
    keys file. The form does not go on with that token: it asks for this event's own, and
    keeps it under a variable of its own."""
    from ctf_flightdeck import keys
    from ctf_flightdeck.console import home as homes

    root, _ = home
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    old = root / "ctf" / "example-ctf"
    start.write(old, start.EventAnswers(name="Example CTF", platform="ctfd", url="https://old.example.org", token_env="CTFD_TOKEN_EXAMPLE_CTF"))
    keys.save("CTFD_TOKEN_EXAMPLE_CTF", "ctfd_old_synthetic", path=tmp_path / "keys.env")

    async def script(app, pilot):
        await pilot.press("down", "enter")  # past "Resume Example CTF", to "Start a new CTF"
        await pilot.pause()
        form = app.screen
        problem = lambda: str(form.query_one("#problem").render())  # noqa: E731
        fill(form, name="Example CTF", url="ctf.example.org", ai="yes", folder=str(tmp_path / "this-year"))
        await pilot.press("ctrl+s")  # no token typed: last year's is there under the name's variable
        assert "Token: CTFD_TOKEN_EXAMPLE_CTF is the token for old.example.org" in problem()
        assert "Paste this event's token: it is kept as CTFD_TOKEN_EXAMPLE_CTF_2" in problem() and app.return_value is None
        assert "ctfd_old_synthetic" not in problem()
        fill(form, token="ctfd_new_synthetic")
        await pilot.press("ctrl+s")

    kind, new = drive_home(homes.items(have_config=True, events=events.known()), script)
    assert kind == "new" and (new.answers.token_env, new.token) == ("CTFD_TOKEN_EXAMPLE_CTF_2", "ctfd_new_synthetic")
    assert new.notes == (f"CTFD_TOKEN_EXAMPLE_CTF is the token for old.example.org (the event in {old.resolve()}), so it is not used for this event",)
    choose(monkeypatch, (kind, new))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE_CTF": "ctfd_old_synthetic", "CTFD_TOKEN_EXAMPLE_CTF_2": "ctfd_new_synthetic"}
    assert "flightdeck: token: CTFD_TOKEN_EXAMPLE_CTF is the token for old.example.org" in result.output
    assert "ctfd_new_synthetic" not in result.output and "ctfd_old_synthetic" not in result.output


def test_no_token_is_kept_for_an_event_from_the_form_that_could_not_be_set_up(home, tmp_path, monkeypatch):
    from ctf_flightdeck import keys
    from ctf_flightdeck.console.home import NewEvent

    _, launched = home
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "keys.env"))
    (tmp_path / "plainfile").write_text("a file\n")
    answers = start.EventAnswers(name="Example", platform="ctfd", url="https://ctf.example.org", token_env="CTFD_TOKEN_EXAMPLE")
    choose(monkeypatch, ("new", NewEvent(answers, tmp_path / "plainfile" / "sub", "ctfd_synthetic", None)))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 2 and "cannot write" in result.output
    assert not (tmp_path / "keys.env").exists() and launched == [] and events.known() == []


def test_flightdeck_alone_does_what_the_home_screen_ended_with(home, monkeypatch):
    root, launched = home
    folder = event(root / "ctf" / "example", "Example CTF")
    given = choose(monkeypatch, ("resume", folder))
    assert CliRunner().invoke(cli.app, []).exit_code == 0
    assert launched == [("play", folder)] and given["menu"][0].title == "Resume Example CTF"
    assert given["status"].startswith("solvers (L1): none installed")
    for choice, what in ((("practice",), "practice"), (("mock",), "mock")):
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
    given = choose(monkeypatch, ("new", NewEvent(answers, folder, "ctfd_synthetic", None)))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    assert keys.load_keys(tmp_path / "keys.env") == {"CTFD_TOKEN_EXAMPLE": "ctfd_synthetic"} and "ctfd_synthetic" not in result.output
    assert load_profile(folder / "event.toml")[0].url == "https://ctf.example.org"
    assert launched == [("play", folder)] and [e.title for e in events.known()] == ["Example"]
    back = given["calls"][1]  # its console quit: the home screen again, the event just played first
    assert back["menu"][0].title == "Resume Example" and back["status"].startswith("Back from your run.")
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


# ---------------------------------------------------------------------- first-time setup, in the home screen

SETUP_KEY = "sk-or-synthetic-" + "0123456789abcdef" * 2  # synthetic: the key a player pastes into the form
CLAUDE_ON_OPENROUTER = "anthropic/claude-haiku-5.5,anthropic/claude-sonnet-5.5,anthropic/claude-opus-5.5"


def docker_on_path(tmp_path, monkeypatch, *, running: bool, image: bool = False):
    """A stand-in `docker`, the only one on PATH: `docker version` answers as a running daemon
    does, or fails as a stopped one; `docker image inspect` finds the image or not. Never the
    real docker, and it runs nothing. Its folder is returned: what it was asked is in `asked`
    there, a line a call."""
    folder = tmp_path / f"docker-{'up' if running else 'down'}-{'image' if image else 'bare'}"
    folder.mkdir()
    exe = folder / "docker"
    version = "echo 27.0.0; exit 0" if running else "echo down >&2; exit 1"
    exe.write_text(f'#!/bin/sh\necho "$1 $2" >> "{folder}/asked"\n[ "$1" = "version" ] && {{ {version}; }}\n'
                   f'[ "$1 $2" = "image inspect" ] && exit {0 if image else 1}\nexit 64\n')
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(folder))
    return folder


SLOW_DOCKER = 10  # seconds a slow stand-in docker takes at most, when nothing lets it go on and nothing kills it


def slow_docker(tmp_path, monkeypatch, name: str, *, running: bool = False):
    """A stand-in `docker`, the only one on PATH, whose `docker version` does not answer, as a
    daemon that hangs does not: it writes its process id to `pid` in its folder (returned) and
    waits for a file `go` there, then fails as a stopped daemon does (or answers as a running
    one). It runs nothing, and ends by itself after SLOW_DOCKER seconds."""
    folder = tmp_path / f"docker-slow-{name}"
    folder.mkdir()
    exe = folder / "docker"
    exe.write_text(f'#!/bin/sh\n[ "$1" = "version" ] || exit 64\necho $$ > "{folder}/pid"\nn=0\n'
                   f'while [ ! -e "{folder}/go" ] && [ $n -lt {SLOW_DOCKER * 10} ]; do /bin/sleep 0.1; n=$((n+1)); done\n'
                   + ("echo 27.0.0; exit 0\n" if running else "echo down >&2; exit 1\n"))
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(folder))
    return folder


async def docker_asked(pilot, folder) -> int:
    """Wait until the slow stand-in docker is running; its process id."""
    for _ in range(100):
        if (folder / "pid").exists() and (folder / "pid").read_text().strip():
            return int((folder / "pid").read_text())
        await pilot.pause(0.05)
    pytest.fail("the form never asked docker")


def gone(pid: int) -> bool:
    import os

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def ended(pid: int) -> bool:
    """Whether process `pid` is gone, given a moment for what killed it to collect it."""
    import time

    for _ in range(40):
        if gone(pid):
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def fresh(home, tmp_path, monkeypatch):
    """A machine flightdeck is not set up on: no config (the path it would have is returned),
    no key anywhere, a keys file of the test's own that is not there yet, and no Docker."""
    config = tmp_path / "fresh" / "config.toml"
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "fresh" / "keys.env"))
    for variable in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "no-docker-here"))
    return config


async def looked_for_docker(app, pilot) -> None:
    await app.workers.wait_for_complete()
    await pilot.pause()


async def open_setup(app, pilot, *keys, looked: bool = True):
    """Take the menu's choice (Enter, after `keys`): the setup form, once it has looked for
    Docker; or at once, while it may still be looking (`looked` false)."""
    await pilot.press(*keys, "enter")
    await pilot.pause()
    form = app.screen
    assert type(form).__name__ == "SetupForm"
    if looked:
        await looked_for_docker(app, pilot)
    return form


def said(form, field: str) -> str:
    return str(form.query_one(f"#{field}").render())


def test_get_started_is_a_form_in_the_home_screen_with_models_to_offer_for_every_provider(fresh):
    from ctf_flightdeck import setup
    from ctf_flightdeck.console import home as homes

    async def script(app, pilot):
        form = await open_setup(app, pilot)  # "Get started": the first choice with no config
        shown = " ".join(str(w.render()) for w in form.query("Static"))
        assert "Which model API do the lanes use?" in shown and "A coding-agent CLI (Claude Code, Codex) is not chosen here" in shown
        offered, key_asked, address_asked = {}, [], []
        for provider in setup.PROVIDER_CHOICES:  # each is a choice of the form's: a value that is none is refused
            fill(form, provider=provider)
            await pilot.pause()
            offered[provider] = form.query_one("#models").value
            key_asked += [provider] if form.query_one("#key").display else []
            address_asked += [provider] if form.query_one("#url").display and form.query_one("#keyenv").display else []
        assert offered == {
            "openrouter": CLAUDE_ON_OPENROUTER, "anthropic": "claude-haiku-5-5,claude-sonnet-5-5,claude-opus-5-5",
            "openai": "gpt-5.4-mini,gpt-5.4", "local": "gpt-oss:20b", "mlx": "mlx-community/Qwen3.5-9B-MLX-4bit",
            "custom": "",  # only its server can name its models
        }
        assert key_asked == ["openrouter", "anthropic", "openai"] and address_asked == ["custom"]
        fill(form, provider="openai")
        await pilot.pause()
        assert "flightdeck has not measured them" in said(form, "modelswhy")  # why these, and that they are a suggestion
        fill(form, models="my/own-model", provider="local")  # what the player typed is not replaced by the next offer
        await pilot.pause()
        assert form.query_one("#models").value == "my/own-model"
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Menu"
        await pilot.press("q")

    assert drive_home(homes.items(have_config=False), script) is None


def test_the_setup_form_says_what_is_missing_and_ends_with_the_config_and_the_key_having_written_nothing(fresh, tmp_path):
    from ctf_flightdeck import setup
    from ctf_flightdeck.console import home as homes

    async def script(app, pilot):
        form = await open_setup(app, pilot)
        assert form.query_one("#key").password is True  # typed out of sight
        assert "it goes to your keys file as OPENROUTER_API_KEY, never into the config" in said(form, "keyq")
        assert form.query_one("#runtime").value == "host"
        assert "Docker cannot run lanes here (docker not found on PATH), so host is offered" in said(form, "dockerfound")
        await pilot.press("ctrl+s")
        assert "API key: paste your key (it is kept in your keys file as OPENROUTER_API_KEY)" in said(form, "problem")
        assert app.return_value is None
        fill(form, key=f'"{SETUP_KEY}"')
        await pilot.press("ctrl+s")
        assert "API key: it is in quotes: give it without them" in said(form, "problem") and SETUP_KEY not in said(form, "problem")
        fill(form, key=SETUP_KEY, models=" , ")
        await pilot.press("ctrl+s")
        assert "Models: give at least one model id" in said(form, "problem") and app.return_value is None
        assert form.query_one("#key").value == SETUP_KEY  # still open, the answers still in it
        fill(form, models="vendor/small, vendor/big")
        await pilot.press("ctrl+s")

    kind, done = drive_home(homes.items(have_config=False), script)
    assert kind == "setup" and done.answers == setup.answers_for("openrouter", ("vendor/small", "vendor/big"), "host")
    assert (done.provider, done.key, done.then) == ("openrouter", SETUP_KEY, "practice")
    assert SETUP_KEY not in repr(done)  # the key is in no text made of what the form ended with
    assert not fresh.exists() and not (tmp_path / "fresh" / "keys.env").exists()  # the form itself writes nothing


def test_the_setup_form_offers_docker_where_docker_runs_and_host_where_it_does_not_and_the_players_choice_stands(fresh, tmp_path, monkeypatch):
    from ctf_flightdeck import setup
    from ctf_flightdeck.console import home as homes

    async def docker_here(app, pilot):
        form = await open_setup(app, pilot)
        assert form.query_one("#runtime").value == "docker"
        assert "Docker is running here, so docker is offered" in said(form, "dockerfound")
        fill(form, provider="local")  # a server on this machine: no key to ask for
        await pilot.pause()
        assert "none needed for a server on this machine" in said(form, "keyq") and not form.query_one("#key").display
        await pilot.press("ctrl+s")

    docker_on_path(tmp_path, monkeypatch, running=True)
    kind, done = drive_home(homes.items(have_config=False), docker_here)
    assert kind == "setup" and done.answers == setup.answers_for("local", ("gpt-oss:20b",), "docker") and done.key == ""

    async def docker_down(app, pilot):
        form = await open_setup(app, pilot)
        assert form.query_one("#runtime").value == "host"
        assert "Docker cannot run lanes here (docker daemon not running (down)), so host is offered" in said(form, "dockerfound")
        fill(form, provider="local", runtime="docker")  # the player's own choice: Docker will be started later
        await pilot.pause()
        await pilot.press("ctrl+s")

    docker_on_path(tmp_path, monkeypatch, running=False)
    kind, done = drive_home(homes.items(have_config=False), docker_down)
    assert kind == "setup" and done.answers.runtime == "docker"


def test_the_setup_form_saves_no_runtime_while_it_still_looks_for_docker_and_a_choice_made_meanwhile_stands(fresh, tmp_path, monkeypatch):
    from textual.widgets.select import InvalidSelectValueError

    from ctf_flightdeck.console import home as homes

    async def saved_too_soon(app, pilot):
        form = await open_setup(app, pilot, looked=False)
        await docker_asked(pilot, docker)
        assert form.query_one("#runtime").value == "" and "Looking for Docker" in said(form, "dockerfound")  # nothing offered yet
        fill(form, provider="local")  # no key to ask for: nothing else stops the save
        await pilot.pause()
        await pilot.press("ctrl+s")
        assert "Runtime: still looking for Docker" in said(form, "problem") and "choose docker or host yourself" in said(form, "problem")
        assert app.return_value is None  # never a runtime nobody chose and nothing decided
        (docker / "go").touch()  # Docker answers at last: its daemon is not running
        await looked_for_docker(app, pilot)
        assert form.query_one("#runtime").value == "host"
        assert "Docker cannot run lanes here (docker daemon not running (down)), so host is offered" in said(form, "dockerfound")
        with pytest.raises(InvalidSelectValueError):  # decided now: "not decided" is no choice any more
            fill(form, runtime="")
        await pilot.press("ctrl+s")

    docker = slow_docker(tmp_path, monkeypatch, "soon")
    kind, done = drive_home(homes.items(have_config=False), saved_too_soon)
    assert kind == "setup" and done.answers.runtime == "host"

    async def chosen_meanwhile(app, pilot):
        form = await open_setup(app, pilot, looked=False)
        await docker_asked(pilot, docker)
        fill(form, provider="local", runtime="docker")  # the player's own choice, made while the form still looks
        await pilot.pause()
        (docker / "go").touch()
        await looked_for_docker(app, pilot)
        assert form.query_one("#runtime").value == "docker"  # not turned into host: it was chosen, not left alone
        assert ("Docker cannot run lanes here (docker daemon not running (down)). Your choice, docker, stands: install or start "
                "Docker before a run") in said(form, "dockerfound")
        await pilot.press("ctrl+s")

    docker = slow_docker(tmp_path, monkeypatch, "meanwhile")
    kind, done = drive_home(homes.items(have_config=False), chosen_meanwhile)
    assert kind == "setup" and done.answers.runtime == "docker"

    async def host_chosen_where_docker_runs(app, pilot):
        form = await open_setup(app, pilot, looked=False)
        await docker_asked(pilot, docker)
        fill(form, provider="local", runtime="host")
        await pilot.pause()
        (docker / "go").touch()
        await looked_for_docker(app, pilot)
        assert form.query_one("#runtime").value == "host"  # theirs too, with what it gives up said
        assert "Docker is running here. Your choice, host, stands: docker is the safer one." in said(form, "dockerfound")
        await pilot.press("ctrl+s")

    docker = slow_docker(tmp_path, monkeypatch, "host", running=True)
    kind, done = drive_home(homes.items(have_config=False), host_chosen_where_docker_runs)
    assert kind == "setup" and done.answers.runtime == "host"


def test_leaving_the_setup_form_never_waits_for_a_docker_that_does_not_answer_and_leaves_none_running(fresh, tmp_path, monkeypatch):
    import time

    from ctf_flightdeck.console import home as homes

    asked = []

    async def back_and_quit(app, pilot):
        await open_setup(app, pilot, looked=False)
        asked.append(await docker_asked(pilot, docker))
        await pilot.press("escape")
        for _ in range(40):
            await pilot.pause(0.05)
            if gone(asked[-1]):
                break
        assert gone(asked[-1])  # the form closed: nothing goes on asking Docker behind the menu
        await pilot.press("q")

    async def chosen_and_saved(app, pilot):
        form = await open_setup(app, pilot, looked=False)
        asked.append(await docker_asked(pilot, docker))
        fill(form, provider="local", runtime="host")  # the player's own choice: nothing to wait for
        await pilot.pause()
        await pilot.press("ctrl+s")

    for name, script in (("quit", back_and_quit), ("saved", chosen_and_saved)):
        docker = slow_docker(tmp_path, monkeypatch, name)
        began = time.monotonic()
        result = drive_home(homes.items(have_config=False), script)
        took = time.monotonic() - began
        assert took < SLOW_DOCKER / 2, f"{name}: the home screen took {took:.1f} s to end"  # the stand-in takes SLOW_DOCKER
        assert ended(asked[-1]), f"{name}: `docker version` was left running"
        assert (result is None) if name == "quit" else (result[0] == "setup" and result[1].answers.runtime == "host")
    assert len(asked) == 2


def test_the_setup_form_asks_for_no_key_that_is_set_already(fresh, monkeypatch):
    from ctf_flightdeck import setup
    from ctf_flightdeck.console import home as homes

    secret = "sk-ant-synthetic-" + "k" * 24
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)

    async def script(app, pilot):
        form = await open_setup(app, pilot)
        fill(form, provider="anthropic")
        await pilot.pause()
        assert "ANTHROPIC_API_KEY is already set in your environment. Leave this empty to use it" in said(form, "keyq")
        assert secret not in " ".join(str(w.render()) for w in form.query("Static"))
        await pilot.press("ctrl+s")

    kind, done = drive_home(homes.items(have_config=False), script)
    ladder = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
    assert kind == "setup" and done.key == "" and done.answers == setup.answers_for("anthropic", ladder, "host")
    assert done.answers.key_env == "ANTHROPIC_API_KEY" and "claude-opus-5-5" in done.answers.prices  # as init writes it


def test_the_setup_form_for_a_custom_api_wants_its_address_and_never_shows_a_key_typed_as_its_variable(fresh):
    from ctf_flightdeck import setup
    from ctf_flightdeck.console import home as homes

    async def script(app, pilot):
        form = await open_setup(app, pilot)
        fill(form, provider="custom")
        await pilot.pause()
        await pilot.press("ctrl+s")
        assert "Address: give the API's address: http:// or https://" in said(form, "problem")
        fill(form, url="https://models.example.test/v1", keyenv=SETUP_KEY)  # the key, pasted where its variable's name goes
        await pilot.pause()
        assert "asked for once the variable above is named" in said(form, "keyq") and not form.query_one("#key").display
        await pilot.press("ctrl+s")
        assert "Variable: give the name of an environment variable" in said(form, "problem") and SETUP_KEY not in said(form, "problem")
        fill(form, keyenv="MY_MODEL_KEY")
        await pilot.pause()
        assert "it goes to your keys file as MY_MODEL_KEY" in said(form, "keyq") and form.query_one("#key").display
        await pilot.press("ctrl+s")
        assert "Models: give at least one model id" in said(form, "problem")  # a custom server's models are its own to name
        fill(form, models="m1")
        await pilot.press("ctrl+s")
        assert "API key: paste your key (it is kept in your keys file as MY_MODEL_KEY)" in said(form, "problem")
        fill(form, key=SETUP_KEY)
        await pilot.press("ctrl+s")

    kind, done = drive_home(homes.items(have_config=False), script)
    assert kind == "setup" and done.key == SETUP_KEY and done.provider == "custom"
    assert done.answers == setup.answers_for("custom", ("m1",), "host", base_url="https://models.example.test/v1", key_env="MY_MODEL_KEY")


def test_the_setup_form_says_while_it_is_open_that_the_keys_file_would_refuse_the_key(fresh, tmp_path):
    from ctf_flightdeck.console import home as homes

    keys_file = tmp_path / "fresh" / "keys.env"
    keys_file.parent.mkdir()
    keys_file.write_text("OTHER=one\n")
    keys_file.chmod(0o644)  # readable by others: flightdeck refuses it

    async def script(app, pilot):
        form = await open_setup(app, pilot)
        assert "chmod 600" in said(form, "keyq")  # said where the key is asked for, before anything is typed
        fill(form, key=SETUP_KEY)
        await pilot.press("ctrl+s")
        assert "API key: " in said(form, "problem") and "chmod 600" in said(form, "problem") and app.return_value is None
        keys_file.chmod(0o600)
        await pilot.press("ctrl+s")

    kind, done = drive_home(homes.items(have_config=False), script)
    assert kind == "setup" and done.key == SETUP_KEY and keys_file.read_text() == "OTHER=one\n"  # the form itself writes nothing


def test_starting_a_ctf_with_no_config_is_one_below_and_asks_the_same_setup_first(fresh):
    from ctf_flightdeck.console import home as homes

    async def script(app, pilot):
        form = await open_setup(app, pilot, "down")  # "Start a new CTF": one below "Get started"
        fill(form, key=SETUP_KEY)
        await pilot.press("ctrl+s")

    kind, done = drive_home(homes.items(have_config=False), script)
    assert kind == "setup" and done.then == "new"  # the event's form is what it is offered first, once set up


def test_once_set_up_the_home_screen_offers_the_practice_set_first_and_an_event_one_below(home):
    from ctf_flightdeck.console import home as homes
    from ctf_flightdeck.console.home import Ready

    ready = Ready(("Your config: /somewhere/config.toml", "Your key: kept"))
    assert [item.choice for item in homes.ready_items(ready)] == [("practice",), ("new",), ("menu",)]
    assert [item.choice for item in homes.ready_items(Ready(first="new"))] == [("new",), ("practice",), ("menu",)]
    assert [item.choice for item in homes.ready_items(Ready(build=True))] == [("image", "practice"), ("practice",), ("new",), ("menu",)]
    assert "14 small challenges that ship with flightdeck" in homes.ready_items(ready)[0].detail
    menu = homes.items(have_config=True)

    async def practice(app, pilot):
        shown = " ".join(str(w.render()) for w in app.screen.query("Static"))
        assert "flightdeck is set up. What next?" in shown and "Your config: /somewhere/config.toml" in shown
        await pilot.press("enter")

    assert drive_home(menu, practice, ready=ready) == ("practice",)

    async def an_event(app, pilot):
        await pilot.press("down", "enter")
        await pilot.pause()
        assert type(app.screen).__name__ == "NewEventForm"  # the event's questions come only now
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Menu"
        await pilot.press("q")

    assert drive_home(menu, an_event, ready=ready) is None

    async def first(app, pilot):
        await pilot.press("enter")

    assert drive_home(menu, first, ready=Ready(build=True, first="new")) == ("image", "new")  # the image first, where it is to build

    async def everything_else(app, pilot):
        await pilot.press("end", "enter")  # "Home", the last choice: the menu itself
        await pilot.pause()
        shown = " ".join(str(w.render()) for w in app.screen.query("Static"))
        assert "What would you like to do?" in shown and "solvers: none" in shown and "What next?" not in shown
        await pilot.press("down", "down", "enter")

    assert drive_home(menu, everything_else, "solvers: none", ready=ready) == ("mock",)


def test_setup_from_the_home_screen_is_written_with_its_key_out_of_sight_and_the_practice_set_is_offered(home, fresh, tmp_path, monkeypatch):
    from ctf_flightdeck import keys, setup
    from ctf_flightdeck.config import load_config
    from ctf_flightdeck.console.home import Setup

    _, launched = home
    keys_file = tmp_path / "fresh" / "keys.env"
    done = Setup(setup.answers_for("openrouter", ("vendor/small",), "host"), "openrouter", SETUP_KEY, "practice")
    given = choose(monkeypatch, ("setup", done), ("practice",))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    assert load_config(fresh).models == ("vendor/small",) and keys.load_keys(keys_file) == {"OPENROUTER_API_KEY": SETUP_KEY}
    assert keys_file.stat().st_mode & 0o777 == 0o600
    assert SETUP_KEY not in result.output and SETUP_KEY not in fresh.read_text()
    first, second, third = given["calls"]  # the menu; then what setup did and what next; then back from the practice run
    assert [item.choice for item in first["menu"]] == [("setup", "practice"), ("setup", "new"), ("mock",)] and first["ready"] is None
    ready = second["ready"]
    assert (ready.first, ready.build) == ("practice", False)
    assert ready.notes[0] == f"Your config: {fresh}"
    assert ready.notes[1] == f"Your key: kept in {keys_file} as OPENROUTER_API_KEY, which only you can read (never shown, never in the config)"
    assert ready.notes[2].startswith("Lanes run on this machine (runtime host)") and len(ready.notes) == 3  # what host means
    assert [item.choice[0] for item in second["menu"]] == ["new", "practice", "mock", "pack", "health"]  # set up now: the menu behind it
    assert f"flightdeck: Your config: {fresh}" in result.output  # said in the terminal too, for after the home screen
    assert launched == [("practice", None)]
    assert third["ready"] is None and third["status"].startswith("Back from your run.")


def test_what_the_setup_form_ends_with_is_what_flightdeck_writes_and_doctor_then_finds_the_key(home, fresh, tmp_path, monkeypatch):
    """The form and the command line, end to end: the provider chosen and its offered models
    taken in the form, then the config and the keys file as `flightdeck` alone leaves them."""
    from ctf_flightdeck import keys
    from ctf_flightdeck.config import load_config
    from ctf_flightdeck.console import home as homes
    from ctf_flightdeck.setup import doctor

    async def script(app, pilot):
        form = await open_setup(app, pilot)
        fill(form, provider="openai", key=SETUP_KEY)
        await pilot.pause()
        await pilot.press("ctrl+s")

    given = choose(monkeypatch, drive_home(homes.items(have_config=False), script))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    config = load_config(fresh)
    assert (config.api.base_url, config.api.key_env) == ("https://api.openai.com/v1", "OPENAI_API_KEY")
    assert (config.models, config.lanes.runtime, config.light.engine) == (("gpt-5.4-mini", "gpt-5.4"), "host", "rules")
    assert keys.load_keys(tmp_path / "fresh" / "keys.env") == {"OPENAI_API_KEY": SETUP_KEY}
    assert SETUP_KEY not in result.output and SETUP_KEY not in fresh.read_text()
    found = {check.name: check for check in doctor(fresh, environ={})}
    assert found["config"].ok and found["api key"].ok and found["api key"].detail == "OPENAI_API_KEY is set (in your keys file)"
    assert given["calls"][1]["ready"].first == "practice"


def test_after_setup_the_lane_image_is_offered_first_only_when_docker_lanes_need_it_and_docker_can_build_it(home, fresh, tmp_path, monkeypatch):
    from ctf_flightdeck import setup
    from ctf_flightdeck.console.home import Ready, Setup

    _, launched = home
    done = Setup(setup.answers_for("local", ("m",), "docker"), "local", "", "new")
    docker_on_path(tmp_path, monkeypatch, running=True)
    given = choose(monkeypatch, ("setup", done), ("image", "new"))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    _, second, third = given["calls"]
    assert (second["ready"].build, second["ready"].first) == (True, "new")
    assert second["ready"].notes[-1] == "Docker lanes run in the lane image, which is not built yet: the first choice here builds it."
    assert launched == [("image build", "")]  # flightdeck's own image, built in the plain terminal
    assert third["ready"] == Ready(("The lane image is built: Docker lanes can start.",), build=False, first="new")
    fresh.unlink()
    docker_on_path(tmp_path, monkeypatch, running=False)  # Docker was chosen and is not running: said, and nothing to choose
    given = choose(monkeypatch, ("setup", done))
    assert CliRunner().invoke(cli.app, []).exit_code == 0
    ready = given["calls"][1]["ready"]
    assert ready.build is False and ready.notes[-1].startswith("Docker lanes cannot start: Docker cannot run them now (docker "
                                                               "daemon not running (down)). Start Docker;")
    fresh.unlink()
    docker_on_path(tmp_path, monkeypatch, running=True, image=True)  # built already: nothing to do, nothing said
    given = choose(monkeypatch, ("setup", done))
    assert CliRunner().invoke(cli.app, []).exit_code == 0
    ready = given["calls"][1]["ready"]
    assert ready.build is False and not any("lane image" in note for note in ready.notes)
    assert launched == [("image build", "")]


def test_after_setup_the_wait_for_docker_is_said_before_it_and_a_docker_that_is_down_is_not_asked_for_the_image(home, fresh, tmp_path, monkeypatch, capsys):
    from ctf_flightdeck import setup
    from ctf_flightdeck.agent import workspace
    from ctf_flightdeck.console.home import Setup

    real, heard = workspace.docker_unavailable, []

    def asked():  # the real check, noting what the terminal had been told when it began
        heard.append(capsys.readouterr().err)
        return real()

    monkeypatch.setattr(workspace, "docker_unavailable", asked)
    folder = docker_on_path(tmp_path, monkeypatch, running=False)
    ready = cli._set_up(Setup(setup.answers_for("local", ("m",), "docker"), "local", "", "practice"))
    assert len(heard) == 1 and "flightdeck: asking Docker whether it can run lanes" in heard[0] and "up to 20 s" in heard[0]
    assert (folder / "asked").read_text().splitlines() == ["version --format"]  # down: no second question to wait for
    assert ready.build is False and "(docker daemon not running (down))" in ready.notes[-1]
    fresh.unlink()
    folder = docker_on_path(tmp_path, monkeypatch, running=True)
    ready = cli._set_up(Setup(setup.answers_for("local", ("m",), "docker"), "local", "", "practice"))
    assert (folder / "asked").read_text().splitlines()[0] == "version --format" and len(heard) == 2  # Docker first, then its image
    assert "image inspect" in (folder / "asked").read_text() and ready.build is True
    fresh.unlink()
    (folder / "asked").unlink()
    capsys.readouterr()
    cli._set_up(Setup(setup.answers_for("local", ("m",), "host"), "local", "", "practice"))  # lanes on this machine: Docker is not asked
    assert len(heard) == 2 and not (folder / "asked").exists() and "asking Docker" not in capsys.readouterr().err


def test_a_setup_that_cannot_be_kept_stops_with_nothing_written_and_never_shows_the_key(home, fresh, tmp_path, monkeypatch):
    from ctf_flightdeck import keys, setup
    from ctf_flightdeck.console.home import Setup

    _, launched = home
    keys_file = tmp_path / "fresh" / "keys.env"
    keys_file.parent.mkdir()
    keys_file.write_text("OTHER=one\n")
    keys_file.chmod(0o644)  # became readable by others after the form checked it
    done = Setup(setup.answers_for("openrouter", ("a/b",), "host"), "openrouter", SETUP_KEY)
    given = choose(monkeypatch, ("setup", done), ("practice",))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 2 and "chmod 600" in result.output and "Nothing was set up" in result.output
    assert SETUP_KEY not in result.output and not fresh.exists() and keys_file.read_text() == "OTHER=one\n"
    assert len(given["calls"]) == 1 and launched == []  # it leaves, the reason the last thing said
    keys_file.chmod(0o600)
    fresh.write_text('[models]\nladder = ["m"]\n')  # a config written meanwhile (another terminal)
    given = choose(monkeypatch, ("setup", done), ("practice",))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 2 and f"{fresh} was written meanwhile, so nothing was set up" in result.output
    assert keys.load_keys(keys_file) == {"OTHER": "one"} and fresh.read_text() == '[models]\nladder = ["m"]\n' and launched == []


# ---------------------------------------------------------------------- back to the home screen when a run ends


def test_when_a_run_from_the_home_screen_ends_flightdeck_is_back_there_with_that_event_first(home, monkeypatch):
    root, launched = home
    old = event(root / "ctf" / "old", "Old CTF").resolve()
    new = event(root / "ctf" / "new", "New CTF").resolve()
    events.remember(old, now=1_000_000_000.0)
    events.remember(new, now=1_500_000_000.0)
    given = choose(monkeypatch, ("resume", old))  # the older one is played; then the player quits the home screen
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 0, result.output
    before, after = given["calls"]  # the home screen opened twice, and quitting it the second time left
    assert [item.title for item in before["menu"][:2]] == ["Resume New CTF", "Resume Old CTF"]
    assert [item.title for item in after["menu"][:2]] == ["Resume Old CTF", "Resume New CTF"]
    assert "played just now" in after["menu"][0].detail
    assert after["status"].startswith(cli.BACK_FROM_A_RUN) and "solvers (L1): none installed" in after["status"]
    assert before["status"].startswith("solvers (L1): none installed")
    assert launched == [("play", old)]


def test_practice_and_the_demo_come_back_to_the_home_screen_and_a_step_that_fails_or_the_pack_leaves(home, monkeypatch):
    import typer

    from ctf_flightdeck import pack_cli

    root, launched = home
    given = choose(monkeypatch, ("practice",), ("mock",), ("practice",))
    assert CliRunner().invoke(cli.app, []).exit_code == 0
    assert launched == [("practice", None), ("mock", None), ("practice", None)] and len(given["calls"]) == 4
    assert [call["status"].startswith("Back from your run.") for call in given["calls"]] == [False, True, False, True]  # the demo is no run

    def stopped(**kw):
        typer.echo("flightdeck: stopped by the test", err=True)
        raise typer.Exit(2)

    monkeypatch.setattr(cli, "play", stopped)  # a run that could not start: its reason is the last thing said
    folder = event(root / "ctf" / "example", "Example CTF").resolve()
    given = choose(monkeypatch, ("resume", folder), ("practice",))
    result = CliRunner().invoke(cli.app, [])
    assert result.exit_code == 2 and result.output.strip().endswith("flightdeck: stopped by the test")
    assert len(given["calls"]) == 1 and launched[3:] == []
    monkeypatch.setattr(pack_cli, "install", lambda **kw: launched.append(("pack", None)))
    given = choose(monkeypatch, ("pack",), ("practice",))  # what the install says stays on the terminal
    assert CliRunner().invoke(cli.app, []).exit_code == 0
    assert len(given["calls"]) == 1 and launched[3:] == [("pack", None)]


# ---------------------------------------------------------------------- the welcome screen


def test_the_first_real_console_is_noted_so_only_it_opens_on_the_welcome():
    from ctf_flightdeck.leftovers import state_folder

    (state_folder() / "welcomed").unlink()  # a machine flightdeck has not opened a console on
    assert cli._first_console() is True and cli._first_console() is False


def test_the_live_mock_opens_on_a_welcome_that_enter_closes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))  # no config of the player's: the mock reads its look from one
    monkeypatch.delenv("FLIGHTDECK_CONFIG", raising=False)
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
