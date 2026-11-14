"""What the console says outside its own window (console/terminal.py, Beacon): how many lanes
need the player, in the terminal's title, and the terminal's bell once each time that count
goes up; and the title the terminal had, put back when the console leaves.

Textual's headless driver writes nothing, and App.bell() does not even call it. So these tests
record what the console hands the driver's write, which is the path a real terminal's bytes
take; one test runs the real command on a pty and reads what the terminal was sent.
"""

from __future__ import annotations

import asyncio
import os
import re

import pytest
from textual.drivers.headless_driver import HeadlessDriver

from ctf_flightdeck.console import views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.terminal import BELL, HELD, TITLE_BACK, TITLE_SAVE, Beacon, set_title, title_text
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.scenarios import Scenario, Spec
from ctf_flightdeck.mock.world import FakeWorld

SAVE = "\x1b[22;0t"  # xterm: save the icon and window title on the stack
BACK = "\x1b[23;0t"  # and restore them
LEAVE = "\x1b]0;\x07" + BACK  # what the console writes as it lets the terminal go
TITLE = re.compile(r"\x1b\]0;(.*)\x07", re.DOTALL)  # OSC 0: set the icon and window title
ALLOWED = re.compile(r"(▲ [1-9][0-9]* need you · )?(queue held · )?flightdeck")  # a count and fixed words


def title(text: str) -> str:
    return f"\x1b]0;{text}\x07"


# ---------------------------------------------------------------------- the words


@pytest.mark.parametrize("need, held, text", [
    (0, False, "flightdeck"),
    (1, False, "▲ 1 need you · flightdeck"),
    (2, False, "▲ 2 need you · flightdeck"),
    (0, True, "queue held · flightdeck"),
    (12, True, "▲ 12 need you · queue held · flightdeck"),
])
def test_the_title_is_the_count_the_hold_and_the_name(need, held, text):
    assert title_text(need, held) == text
    assert ALLOWED.fullmatch(text)
    assert set_title(text) == title(text)


def test_the_title_uses_the_headers_own_words():
    """The header and the title say the same thing; one must not drift from the other."""
    assert HELD == views.HELD
    world = FakeWorld(scenarios.get("sstv"))
    for _ in range(400):
        world.tick()
    need = len(world.deck.needing())
    assert need > 0
    header = views.header(world.deck, mock="", note="", width=200, compact=False, simple=True).plain
    assert title_text(need, False).removesuffix(" · flightdeck") in header


def test_the_codes_are_xterms_title_stack_and_title():
    assert (TITLE_SAVE, TITLE_BACK, BELL) == (SAVE, BACK, "\x07")


# ---------------------------------------------------------------------- when it writes


def beacon(**kw) -> tuple[Beacon, list[str]]:
    written: list[str] = []
    return Beacon(written.append, **kw), written


def test_a_count_of_1_1_2_1_writes_the_title_three_times_and_rings_once():
    it, written = beacon()
    it.open()
    for need in (1, 1, 2, 1):
        it.show(need, False)
    assert written == [
        SAVE,
        title("▲ 1 need you · flightdeck"),  # the first count: the player is at the console, so no bell
        title("▲ 2 need you · flightdeck"), BELL,  # it rose
        title("▲ 1 need you · flightdeck"),  # it fell: the title follows, the bell does not
    ]


def test_the_bell_rings_each_time_the_count_rises_and_never_otherwise():
    it, written = beacon(title=False)
    it.open()
    rings = []
    for need in (0, 1, 1, 3, 2, 2, 0, 0, 1):
        before = len(written)
        it.show(need, False)
        rings.append(written[before:])
    assert rings == [[], [BELL], [], [BELL], [], [], [], [], [BELL]]
    assert written == [BELL] * 3  # and with the title off, nothing else: no save, no title


def test_a_hold_changes_the_title_and_rings_no_bell():
    it, written = beacon()
    it.open()
    it.show(0, False)
    it.show(0, True)
    it.show(0, True)
    it.show(0, False)
    assert written == [SAVE, title("flightdeck"), title("queue held · flightdeck"), title("flightdeck")]


def test_with_the_bell_off_only_the_title_is_written_and_with_both_off_nothing():
    it, written = beacon(bell=False)
    it.open()
    for need in (0, 2, 5):
        it.show(need, False)
    it.close()
    assert written == [SAVE, title("flightdeck"), title("▲ 2 need you · flightdeck"), title("▲ 5 need you · flightdeck"), LEAVE]

    it, written = beacon(title=False, bell=False)
    it.open()
    for need in (0, 2, 5):
        it.show(need, True)
    it.close()
    assert written == []


def test_leaving_puts_the_title_back_and_nothing_is_written_until_the_console_is_back():
    it, written = beacon()
    it.show(3, False)  # before the console has the terminal
    assert written == []
    it.open()
    it.open()  # once
    it.show(1, False)
    it.close()
    it.close()  # once
    assert written == [SAVE, title("▲ 1 need you · flightdeck"), LEAVE]
    it.show(4, True)  # a shell has the terminal: its title is its own, and its bell
    assert written[3:] == []
    it.open()
    it.show(4, True)  # back: the title is written again, and the player is there, so no bell
    it.show(4, True)
    it.show(5, True)
    assert written[3:] == [SAVE, title("▲ 4 need you · queue held · flightdeck"), title("▲ 5 need you · queue held · flightdeck"), BELL]


# ---------------------------------------------------------------------- the console


@pytest.fixture
def written(monkeypatch) -> list[str]:
    """Everything a headless console hands its driver's write (Textual's own writes too)."""
    out: list[str] = []
    monkeypatch.setattr(HeadlessDriver, "write", lambda self, data: out.append(data))
    return out


def ours(written: list[str]) -> list[str]:
    """The title and bell writes among `written`."""
    return [data for data in written if data == BELL or data.startswith(("\x1b]0;", SAVE, BACK))]


def titles(written: list[str]) -> list[str]:
    return [found.group(1) for data in written if (found := TITLE.match(data))]


HOSTILE = "pwn\x1b]0;owned\x07 ▲ 99 need you"  # a challenge's name that would like to be the title


def hostile_world() -> FakeWorld:
    """The sstv scenario with a challenge whose name carries a title of its own."""
    base = scenarios.get("sstv")
    specs = [Spec(**{**vars(spec), "name": HOSTILE}) if i == 0 else spec for i, spec in enumerate(base.specs)]
    return FakeWorld(Scenario(**{**vars(base), "specs": tuple(specs)}))


def run(app: FlightdeckApp, script) -> None:
    async def main() -> None:
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            await script(pilot)

    asyncio.run(main())


def test_the_console_writes_the_count_rings_as_it_rises_and_puts_the_title_back_when_it_leaves(written):
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)
    counts: list[int] = []

    async def script(pilot) -> None:
        assert ours(written) == [SAVE, title("flightdeck")]  # the console opened with no lane needing the player
        for _ in range(400):
            world.tick()
            if len(world.deck.needing()) != ([0, *counts])[-1]:
                counts.append(len(world.deck.needing()))
                await pilot.pause()  # the console redraws, as it does after the deck's events

    run(app, script)
    assert max(counts) >= 2, "the scenario never had two lanes needing the player"
    mine = ours(written)
    assert mine[:2] == [SAVE, title("flightdeck")]
    assert mine[-1] == LEAVE and mine.count(LEAVE) == 1 and mine.count(SAVE) == 1
    # each count the deck went through is a title, in order, and each rise is one bell right after its title
    expected = [title_text(need, False) for need in [0, *counts]]
    assert titles(mine)[:-1] == [text for i, text in enumerate(expected) if i == 0 or text != expected[i - 1]]
    rises = sum(1 for before, after in zip([0, *counts], counts) if after > before)
    assert mine.count(BELL) == rises >= 2
    for i, data in enumerate(mine):
        if data == BELL:
            assert TITLE.match(mine[i - 1]), "a bell with no rise in the title before it"


def test_no_text_of_a_challenge_or_of_a_hold_reaches_the_title(written):
    """Rule 5: the title is a count and fixed words. A challenge's name and the reason the queue
    is held are text flightdeck did not write; neither is ever in what the terminal is sent."""
    world = hostile_world()
    app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)
    reason = "the API said: \x1b]0;gotcha\x07 ▲ 7 need you"

    async def script(pilot) -> None:
        for _ in range(400):
            world.tick()
        await pilot.pause()
        assert any(lane.needs_you for lane in world.deck.lanes.values())
        assert any(HOSTILE in challenge.name for challenge in world.deck.challenges.values())
        world.deck.hold_queue(reason)
        await pilot.pause()
        assert world.deck.held == reason

    run(app, script)
    mine = ours(written)
    assert any("queue held" in text for text in titles(mine))
    for text in titles(mine)[:-1]:
        assert ALLOWED.fullmatch(text), text
    assert titles(mine)[-1] == ""
    for data in written:  # nothing the terminal was sent, by anyone
        assert "owned" not in data and "gotcha" not in data and "99" not in data


def test_a_shell_that_takes_the_terminal_gets_the_old_title_and_the_console_takes_it_again(written):
    """Take over suspends the console: Textual says so before it lets the terminal go
    (app_suspend_signal) and after it has it again (app_resume_signal)."""
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)

    async def script(pilot) -> None:
        for _ in range(400):
            world.tick()
        await pilot.pause()
        need = len(world.deck.needing())
        assert need > 0
        del written[:]
        app.app_suspend_signal.publish(app)
        assert ours(written) == [LEAVE]  # at once: the driver lets go of the terminal right after
        app.refresh_view()  # the console's timer goes on while the shell has the terminal
        assert ours(written) == [LEAVE]
        app.app_resume_signal.publish(app)
        assert ours(written) == [LEAVE, SAVE, title(title_text(need, False))]  # and no bell: the player is back

    run(app, script)
    assert ours(written)[-1] == LEAVE


def test_a_console_that_fails_still_puts_the_title_back(written):
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)

    def fail() -> None:
        raise RuntimeError("the console failed")

    async def script(pilot) -> None:
        assert ours(written) == [SAVE, title("flightdeck")]
        app.call_later(fail)
        await pilot.pause()

    with pytest.raises(RuntimeError, match="the console failed"):
        run(app, script)
    assert ours(written) == [SAVE, title("flightdeck"), LEAVE]


def test_a_console_told_to_leave_the_title_and_the_bell_writes_neither(written):
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None,
                        terminal_title=False, terminal_bell=False)

    async def script(pilot) -> None:
        for _ in range(400):
            world.tick()
        await pilot.pause()
        assert world.deck.needing()

    run(app, script)
    assert ours(written) == []


@pytest.mark.parametrize("table, title_on, bell_on", [
    ("", True, True),
    ("[console]\ntitle = false\n", False, True),
    ("[console]\nbell = false\n", True, False),
    ("[console]\ntitle = false\nbell = false\n", False, False),
])
def test_the_mock_and_a_run_take_the_title_and_the_bell_from_the_config(tmp_path, monkeypatch, table, title_on, bell_on):
    from types import SimpleNamespace

    from typer.testing import CliRunner

    from ctf_flightdeck import cli
    from ctf_flightdeck.config import load_config
    from ctf_flightdeck.run import Run

    config = tmp_path / "config.toml"
    config.write_text('[models]\nladder = ["m"]\n' + table)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    opened = []
    monkeypatch.setattr(FlightdeckApp, "run", lambda self, **kw: opened.append((self._beacon.title, self._beacon.bell)))
    result = CliRunner().invoke(cli.app, ["mock"])
    assert result.exit_code == 0, result.output
    assert opened == [(title_on, bell_on)]

    # what Run.app reads of a run: its console is made by the code a real run's is
    of_a_run = SimpleNamespace(config=load_config(config), deck=FakeWorld(scenarios.get("sstv")).deck, dir=tmp_path, by_hand=False,
                               release=None, shutdown=None)
    beacon = Run.app(of_a_run)._beacon
    assert (beacon.title, beacon.bell) == (title_on, bell_on)


# ---------------------------------------------------------------------- a real terminal


def test_on_a_terminal_the_mock_sets_the_title_rings_and_puts_the_title_back_when_it_quits(tmp_path):
    """The real command on a pty, through the driver a terminal window gets: what the terminal
    is sent while the mock runs, and after `ctrl+q`."""
    from test_play_signals import Terminal, env_for, wait_for

    term = Terminal(["mock", "--speed", "20"], env_for(tmp_path), tmp_path)
    try:
        first = wait_for(lambda: re.search(r"\x1b\[22;0t\x1b\]0;([^\x07]*)\x07(.)", term.text(), re.DOTALL),
                         "the title saved, then flightdeck's", term)
        assert ALLOWED.fullmatch(first.group(1)) and first.group(2) != BELL  # no bell for what is there as it opens
        wait_for(lambda: re.search(r"\x1b\]0;▲ [0-9]+ need you · flightdeck\x07\x07", term.text()), "a bell after a rise", term)
        assert LEAVE not in term.text()
        os.write(term.master, b"\x11")  # ctrl+q
        assert term.proc.wait(timeout=30) == 0, term.text()[-2000:]
        wait_for(lambda: LEAVE in term.text(), "the title put back", term, timeout=5.0)
    finally:
        term.close()
    sent = term.text()
    assert sent.count(SAVE) == 1 and sent.count(LEAVE) == 1
    assert sent.rindex(LEAVE) > max(found.end() for found in re.finditer(r"\x1b\]0;[^\x07]+\x07", sent))  # the last title written
    for text in re.findall(r"\x1b\]0;([^\x07]+)\x07", sent):
        assert ALLOWED.fullmatch(text), text


def test_a_run_stopped_by_sigterm_puts_the_title_back_before_it_prints_its_last_lines(tmp_path):
    """A real run on a pty, its lane asking the fake model server on 127.0.0.1: SIGTERM stops
    it as quitting does, and the terminal has its title back before `play` prints what it
    prints on the way out."""
    import signal

    from fake_model import FakeModelServer, tool_call_reply
    from test_play_signals import QUIET, Terminal, env_for, lane_pid_file, make_board, make_config, wait_for

    with FakeModelServer([tool_call_reply("shell", {"command": QUIET, "timeout_seconds": 300})]) as server:
        config = make_config(tmp_path, server.base_url)
        term = Terminal(["play", str(make_board(tmp_path)), "--config", str(config)], env_for(tmp_path), tmp_path)
        try:
            wait_for(lambda: lane_pid_file(tmp_path), "the lane's command", term)
            assert SAVE + title("flightdeck") in term.text() and LEAVE not in term.text()
            os.kill(term.proc.pid, signal.SIGTERM)
            assert term.proc.wait(timeout=60) == 128 + signal.SIGTERM, term.text()[-2000:]
            wait_for(lambda: "the run's lanes were stopped" in term.text(), "play's last line", term, timeout=5.0)
        finally:
            term.close()
    sent = term.text()
    assert sent.count(SAVE) == 1 and sent.count(LEAVE) == 1
    assert sent.index(LEAVE) < sent.index("the run's lanes were stopped")
