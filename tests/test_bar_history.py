"""The command bar's history and editor key (P71).

Up and down walk back through what was sent this run, as a shell's history does; ctrl+g
opens what is typed in the player's editor and puts what it holds back in the bar, sending
nothing. These tests type into the bars of a console and read the bar, the lane and the
status line.

The editor is never a real program here. A console under test cannot hand the terminal over
(one test lets the real hand-over say so), so `takeover.run_in_terminal`, the hand-over
itself, is replaced by a stand-in that plays the editor: it reads the file it was given and
writes the player's text into it. Everything between the key and the bar (which variable
names the editor, the file, reading it back, what is said) is the code under test. VISUAL
and EDITOR are the test's own, naming programs that exist on every system (`true`), which
are never run.
"""

from __future__ import annotations

import os
import re
import shutil

import pytest
from textual.app import App
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Input

from ctf_flightdeck.console import editor, screens, takeover
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import BOTH_KEY_HELP
from ctf_flightdeck.console.widgets import BarInput, CommandBar, History
from test_console import assert_warning, bar, open_focus, press, prompt_text, status_line
from test_layout import SIZE, drive, three_lanes

TRUE = shutil.which("true")


@pytest.fixture
def editor_env(monkeypatch):
    """VISUAL and EDITOR as the test sets them, none from the machine running the tests."""
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)
    return monkeypatch


class StandIn:
    """Plays the editor for run_in_terminal: records what it was asked to run and what the
    file held, then writes `writes` into the file (or removes it, as an editor or a wrapper
    that moves the file does) and exits with `status`."""

    def __init__(self, writes: str = "", status: int = 0, removes: bool = False) -> None:
        self.writes, self.status, self.removes = writes, status, removes
        self.calls: list[tuple[list[str], str, int]] = []  # (argv, the file's text, its mode)

    async def __call__(self, app, argv, cwd, env) -> int:
        path = argv[-1]
        with open(path, encoding="utf-8") as file:
            self.calls.append((list(argv), file.read(), os.stat(path).st_mode & 0o777))
        if self.removes:
            os.unlink(path)
        else:
            with open(path, "w", encoding="utf-8") as file:
                file.write(self.writes)
        return self.status


async def typed(pilot, text: str) -> None:
    await press(pilot, *text)


async def send(pilot, text: str) -> None:
    await typed(pilot, text)
    await press(pilot, "enter")


# ---------------------------------------------------------------------- the history


def test_the_history_keeps_what_was_sent_once_in_a_row_and_lets_the_oldest_go():
    history = History()
    for text in ("a", "a", "", "b", "a"):
        history.add(text)
    assert history.entries == ["a", "b", "a"]  # a repeat of the last is kept once; nothing empty
    for n in range(History.LIMIT + 3):
        history.add(str(n))
    assert len(history.entries) == History.LIMIT and history.entries[0] == "3" and history.entries[-1] == str(History.LIMIT + 2)


def test_up_walks_back_through_what_was_sent_and_down_past_the_newest_brings_the_draft_back():
    deck, app = three_lanes("simple")
    lane = deck.lanes["L01"]

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        chat = bar(app)
        await send(pilot, "first try")
        await send(pilot, "/details")
        await send(pilot, "second try")
        assert lane.hints == ["first try", "second try"]
        await typed(pilot, "half")
        for want in ("second try", "/details", "first try", "first try"):  # up at the oldest stays there
            await press(pilot, "up")
            assert chat.field.value == want
            assert not chat.menu_open  # a recalled command opens no menu, so the arrows stay on the history
        for want in ("/details", "second try", "half", "half"):  # past the newest: what was typed; then nothing more
            await press(pilot, "down")
            assert chat.field.value == want
        assert lane.hints == ["first try", "second try"]  # walking sends nothing
        await press(pilot, "up", "up", "enter")
        assert lane.hints == ["first try", "second try"] and chat.field.value == ""  # /details ran again
        await press(pilot, "up")
        assert chat.field.value == "/details"  # sent again, it is the newest, once

    drive(app, script, SIZE)


def test_typing_into_a_recalled_entry_ends_the_walk_and_the_next_up_keeps_what_was_typed():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        chat = bar(app)
        await send(pilot, "one")
        await send(pilot, "two")
        await press(pilot, "up", "up")
        assert chat.field.value == "one"
        await typed(pilot, " more")
        assert chat.field.value == "one more"
        await press(pilot, "up")
        assert chat.field.value == "two"  # from the newest again, not on from "one"
        await press(pilot, "down")
        assert chat.field.value == "one more"

    drive(app, script, SIZE)


def test_with_the_menu_open_the_arrows_move_in_the_menu_and_an_empty_history_leaves_the_bar_alone():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        chat = bar(app)
        await press(pilot, "up", "down")
        assert chat.field.value == ""  # nothing sent yet
        await send(pilot, "hello")
        await typed(pilot, "/")
        assert chat.menu_open and chat.menu.highlighted == 0
        await press(pilot, "down")
        assert chat.field.value == "/" and chat.menu.highlighted == 1  # the menu's row, not the history
        await press(pilot, "up")
        assert chat.field.value == "/" and chat.menu.highlighted == 0
        await press(pilot, "escape", "up")  # the menu closed: up is the history again
        assert chat.field.value == "hello"

    drive(app, script, SIZE)


def test_the_lane_list_and_a_lane_share_one_history_for_the_run():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, "from the lane")
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)
        await press(pilot, "slash", "backspace")  # the bar, empty
        fleet_bar = bar(app)
        assert fleet_bar.field.has_focus and fleet_bar.field.value == ""
        await press(pilot, "up")
        assert fleet_bar.field.value == "from the lane"
        assert app.bar_history.entries == ["from the lane"]

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the editor


def test_ctrl_g_puts_the_editors_text_in_the_bar_as_one_line_and_sends_nothing_until_enter(editor_env):
    stand_in = StandIn(writes="look at the\n\n   PNG chunks\t first\n")
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("VISUAL", f"{TRUE} --wait")
    editor_env.setenv("EDITOR", "/no/such/editor")  # VISUAL comes first
    deck, app = three_lanes("simple")
    lane = deck.lanes["L01"]

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        chat = bar(app)
        await typed(pilot, "a draft")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        [(argv, held, mode)] = stand_in.calls
        assert argv[:2] == [TRUE, "--wait"] and held == "a draft\n" and mode == 0o600  # the player's own file
        assert not os.path.exists(argv[-1])  # removed afterwards
        assert chat.field.value == "look at the PNG chunks  first" and chat.field.has_focus
        assert lane.hints == []  # nothing sent
        assert "Your editor's 2 lines are one line here, joined by spaces: enter sends it" in status_line(app)
        await press(pilot, "enter")
        assert lane.hints == ["look at the PNG chunks  first"]

    drive(app, script, SIZE)


def test_what_the_editor_writes_cannot_reach_the_terminal_raw(editor_env):
    editor_env.setattr(takeover, "run_in_terminal", StandIn(writes="\x1b[2Jred\x07"))
    editor_env.setenv("EDITOR", TRUE)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert bar(app).field.value == "^[[2Jred^G"
        assert "Back from your editor: enter sends it" in status_line(app)

    drive(app, script, SIZE)


def test_ctrl_g_with_no_editor_set_says_so_and_runs_nothing(editor_env):
    stand_in = StandIn(writes="never")
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await typed(pilot, "kept")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert stand_in.calls == [] and bar(app).field.value == "kept"
        assert_warning(app, "ctrl+g needs an editor: set VISUAL or EDITOR")

    drive(app, script, SIZE)


def test_an_editor_that_cannot_be_run_is_named_and_the_other_variable_is_not_tried(editor_env):
    stand_in = StandIn(writes="never")
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("VISUAL", "no-such-editor-flightdeck --wait")
    editor_env.setenv("EDITOR", TRUE)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert stand_in.calls == []
        assert_warning(app, "VISUAL names 'no-such-editor-flightdeck', which is not a program on PATH")

    drive(app, script, SIZE)


def test_an_editor_that_exits_badly_leaves_the_bar_as_it_was(editor_env):
    stand_in = StandIn(writes="half written", status=1)
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("EDITOR", TRUE)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await typed(pilot, "kept")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert bar(app).field.value == "kept" and not os.path.exists(stand_in.calls[0][0][-1])
        assert_warning(app, "exited with status 1: the box keeps what it had")

    drive(app, script, SIZE)


def test_an_editor_that_leaves_the_file_empty_leaves_the_bar_as_it_was(editor_env):
    stand_in = StandIn(writes="  \n\t\n")
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("EDITOR", TRUE)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await typed(pilot, "kept")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert bar(app).field.value == "kept" and len(stand_in.calls) == 1
        assert "Back from your editor" not in status_line(app)
        assert_warning(app, "the editor left the file empty: the box keeps what it had")

    drive(app, script, SIZE)


def test_an_editor_that_removes_its_file_is_said_and_the_bar_keeps_what_it_had(editor_env):
    stand_in = StandIn(removes=True)
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("EDITOR", TRUE)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await typed(pilot, "kept")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert bar(app).field.value == "kept" and len(stand_in.calls) == 1
        assert_warning(app, "the editor's file could not be read back")

    drive(app, script, SIZE)


def test_no_file_for_the_editor_is_said_and_no_editor_runs(editor_env):
    stand_in = StandIn(writes="never")
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("EDITOR", TRUE)

    def full(*args, **kwargs):
        raise OSError(28, "No space left on device")

    editor_env.setattr(editor.tempfile, "mkstemp", full)
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await typed(pilot, "kept")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert stand_in.calls == [] and bar(app).field.value == "kept"
        assert_warning(app, "no file for the editor could be made")

    drive(app, script, SIZE)


def test_a_console_that_cannot_hand_over_the_terminal_says_so(editor_env):
    editor_env.setenv("EDITOR", TRUE)  # the real hand-over: a console under test has no terminal to give
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await typed(pilot, "kept")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert bar(app).field.value == "kept"
        assert_warning(app, "this console cannot hand the terminal to an editor")

    drive(app, script, SIZE)


def test_editor_command_reads_visual_then_editor_and_refuses_what_it_cannot_run():
    path = os.path.dirname(TRUE)
    assert editor.editor_command({"VISUAL": f"{TRUE} -f", "EDITOR": "x", "PATH": path}) == [TRUE, "-f"]
    assert editor.editor_command({"VISUAL": "  ", "EDITOR": "true", "PATH": path}) == ["true"]  # blank is not set
    for environ, said in (
        ({"PATH": path}, editor.NO_EDITOR),
        ({"EDITOR": "'unclosed", "PATH": path}, "EDITOR is not a command line"),
        ({"EDITOR": "''", "PATH": path}, "EDITOR is set but names no program"),
        ({"EDITOR": "true", "PATH": "/nowhere"}, "EDITOR names 'true', which is not a program on PATH"),
    ):
        with pytest.raises(editor.EditorError, match=re.escape(said)):
            editor.editor_command(environ)


@pytest.mark.parametrize("layout,size", [("simple", SIZE), ("deck", SIZE), ("simple", (80, 40))])  # the last is the compact layout
def test_ctrl_g_opens_the_editor_from_both_bars_in_every_layout(editor_env, layout, size):
    stand_in = StandIn(writes="edited")
    editor_env.setattr(takeover, "run_in_terminal", stand_in)
    editor_env.setenv("EDITOR", TRUE)
    deck, app = three_lanes(layout)

    async def script(pilot):
        await press(pilot, "slash", "backspace")
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert isinstance(app.screen, FleetScreen) and bar(app).field.value == "edited"
        await press(pilot, "escape")
        await open_focus(pilot, app, "L01")
        assert isinstance(app.screen, FocusScreen)
        await press(pilot, "ctrl+g")
        await pilot.pause()
        assert bar(app).field.value == "edited" and len(stand_in.calls) == 2

    drive(app, script, size)


def test_no_other_key_of_the_console_is_ctrl_g():
    """ctrl+g was free before P71: nothing else in the app, the two views, their modal
    dialogs or the field binds it, so the bar's binding is the one that runs."""
    def keys(bindings) -> set[str]:
        out = set()
        for binding in bindings:
            key = binding.key if isinstance(binding, Binding) else binding[0]
            out |= {part.strip() for part in key.split(",")}
        return out

    holders = [App, FlightdeckApp, Screen, FleetScreen, FocusScreen, Input, BarInput]
    holders += [cls for cls in vars(screens).values() if isinstance(cls, type) and issubclass(cls, Screen)]
    for holder in holders:
        assert "ctrl+g" not in keys(getattr(holder, "BINDINGS", ())), holder
    assert "ctrl+g" in keys(CommandBar.BINDINGS)


def test_help_lists_the_history_and_the_editor_key():
    rows = dict(BOTH_KEY_HELP)
    assert rows["↑ ↓"].startswith("In the command bar or the chat box: what you sent this run")
    assert rows["ctrl+g"].startswith("In the command bar or the chat box: write what is in it in your editor")
    deck, app = three_lanes("simple")

    async def script(pilot):
        await press(pilot, "question_mark")
        said = prompt_text(app)
        assert f"ctrl+g {rows['ctrl+g']}" in said and f"↑ ↓ {rows['↑ ↓']}" in said

    drive(app, script, (160, 200))
