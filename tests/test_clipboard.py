"""Selecting and copying: the mouse in the lane's view, ctrl+c, esc, /copy, and the tools
that reach the operating system's clipboard (clipboard.py).

No test touches the real clipboard: a console here has its own copier (Clip, or clipboard.put
with a stand-in runner), and conftest.py refuses any other. The mouse is the pilot's; a drag is
a button down, a move with it down, and the button up. Every lane is synthetic.
"""

from __future__ import annotations

import asyncio
import base64
import re
import subprocess
from functools import partial

import pytest
from textual import events
from textual.color import Color
from textual.widgets import Static

from ctf_flightdeck import clipboard, themes
from ctf_flightdeck.console import views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.commands import BY_NAME
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.lanelog import RowText
from ctf_flightdeck.console.screens import KEY_HELP
from ctf_flightdeck.core.deck import Deck
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Call, Lane
from ctf_flightdeck.text import NEWLINE
from test_console import (
    NARROW,
    OPENROUTER,
    VALUES,
    assert_warning,
    bar,
    color_of,
    drive,
    open_focus,
    osc,
    press,
    region_text,
    screen_text,
    send,
    shown,
    status_line,
)
from test_lanelog import BIG, COMMANDS, RODATA, busy_lane, log_of, one_lane, says, shell

UNPROVEN = ("sent to the terminal's clipboard (OSC 52). If paste is empty, this terminal does not take it: install xclip or wl-copy, or "
            "hold fn (Terminal.app), Option (iTerm2) or Shift while you drag")
QUIT_HINT = "to quit the app"  # Textual's own answer to a ctrl+c that copies nothing
OSC52 = re.compile(r"\x1b\]52;c;([A-Za-z0-9+/=]*)\x07")


class Clip:
    """A console's copier: the operating system's clipboard, standing in. `problem` is what it
    answers: "" (a tool took the text) or what the player must be told."""

    def __init__(self, problem: str = "") -> None:
        self.texts: list[str] = []
        self.problem = problem

    def __call__(self, text: str) -> str:
        self.texts.append(text)
        return self.problem


class Runner:
    """Stands in for subprocess.run: notes each call, and answers with `codes` by tool (0 otherwise)."""

    def __init__(self, **codes: int) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.codes = codes

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, self.codes.get(argv[0].replace("-", "_"), 0))

    @property
    def ran(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]


def has(*tools: str):
    """A stand-in for shutil.which on a machine with only `tools`."""
    return lambda tool: f"/usr/bin/{tool}" if tool in tools else None


def console(layout: str = "simple") -> tuple[Deck, FlightdeckApp, Lane, Clip]:
    """The lane of the report (test_lanelog.busy_lane) in a console with a clipboard of its own."""
    deck, app, lane = busy_lane(layout)
    app.copier = clip = Clip()
    return deck, app, lane, clip


def terminal(app: FlightdeckApp) -> list[str]:
    """Everything the console writes to its terminal from now on (the test's driver draws nothing)."""
    written: list[str] = []
    driver = app._driver
    real = driver.write
    driver.write = lambda data: (written.append(data), real(data))[1]
    return written


def osc52(written: list[str]) -> list[str]:
    """The texts the console sent to the terminal's clipboard."""
    return [base64.b64decode(found).decode() for found in OSC52.findall("".join(written))]


async def drag(pilot, widget, start: tuple[int, int], end: tuple[int, int]) -> None:
    """Press the mouse button at `start` of `widget`, move to `end` with it down, let it go."""
    await pilot.mouse_down(widget, offset=start)
    await pilot._post_mouse_events([events.MouseMove], widget, end, button=1)  # pilot.hover moves with no button down
    await pilot.mouse_up(widget, offset=end)
    await pilot.pause()


def backgrounds(widget: Static) -> list[Color | None]:
    """The background colour of each cell of the first row of `widget`, as it is drawn."""
    return [Color.from_rich_color(segment.style.bgcolor) if segment.style and segment.style.bgcolor else None
            for segment in widget.render_line(0) for _ in range(segment.cell_length)]


def row(app: FlightdeckApp, start: str) -> RowText:
    """The transcript's row whose text starts with `start`."""
    found = [widget for widget in log_of(app).query(RowText) if str(widget.render()).startswith(start)]
    assert len(found) == 1, (start, log_of(app).texts())
    return found[0]


# ---------------------------------------------------------------------- the tools


def test_on_macos_pbcopy_gets_the_text_as_utf8_whatever_the_locale():
    run = Runner()
    used = clipboard.copy_text("flag{naïve ⏺}\nline 2", platform="darwin", which=has("pbcopy"), run=run, environ={"LANG": "C", "HOME": "/home/p"})
    assert used == "pbcopy" and run.ran == [["pbcopy"]]
    kwargs = run.calls[0][1]
    assert kwargs["input"] == "flag{naïve ⏺}\nline 2".encode()
    assert kwargs["env"] == {"LANG": "C", "HOME": "/home/p", "LC_CTYPE": "UTF-8"}  # pbcopy reads in the locale's encoding


def test_on_linux_the_first_tool_there_is_takes_the_text():
    for tools, argv in ((("wl-copy", "xclip", "xsel"), ["wl-copy"]),
                        (("xclip",), ["xclip", "-selection", "clipboard"]),
                        (("xsel",), ["xsel", "--clipboard", "--input"])):
        run = Runner()
        environ = {"DISPLAY": ":0"}
        assert clipboard.copy_text("abc", platform="linux", which=has(*tools), run=run, environ=environ) == argv[0]
        assert run.ran == [argv] and run.calls[0][1]["input"] == b"abc" and run.calls[0][1]["env"] == environ


def test_a_tool_that_fails_is_followed_by_the_next_and_when_all_fail_each_is_named():
    run = Runner(wl_copy=1)  # Wayland's tool on an X11 session
    assert clipboard.copy_text("abc", platform="linux", which=has("wl-copy", "xclip"), run=run, environ={}) == "xclip"
    assert run.ran == [["wl-copy"], ["xclip", "-selection", "clipboard"]]

    def never(argv, **kwargs):
        if argv[0] == "xclip":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if argv[0] == "xsel":
            raise FileNotFoundError(argv[0])
        return subprocess.CompletedProcess(argv, 1)

    with pytest.raises(clipboard.ClipboardError) as failed:
        clipboard.copy_text("abc", platform="linux", which=has("wl-copy", "xclip", "xsel"), run=never, environ={})
    assert str(failed.value) == "wl-copy failed (exit 1), xclip did not end in 2 s, xsel did not start (FileNotFoundError)"
    said = clipboard.put("abc", platform="linux", which=has("wl-copy"), run=never, environ={})
    assert said == ("wl-copy failed (exit 1); sent to the terminal's clipboard (OSC 52). If paste is empty, this terminal does not take "
                    "it: hold fn (Terminal.app), Option (iTerm2) or Shift while you drag")  # a tool is there: installing one is not the advice


def test_over_ssh_no_tool_is_run_and_no_tool_at_all_is_said_not_passed_over():
    for variable in ("SSH_TTY", "SSH_CONNECTION"):
        run = Runner()
        environ = {variable: "/dev/pts/3"}
        assert clipboard.copy_text("abc", platform="linux", which=has("wl-copy", "xclip", "xsel"), run=run, environ=environ) is None
        assert clipboard.copy_text("abc", platform="darwin", which=has("pbcopy"), run=run, environ=environ) is None
        assert run.calls == []  # the tool would fill the clipboard of the machine flightdeck runs on
        said = clipboard.put("abc", platform="linux", which=has("xclip"), run=run, environ=environ)
        assert said.startswith("sent to the terminal's clipboard (OSC 52).") and "install" not in said and run.calls == []
    run = Runner()
    assert clipboard.copy_text("abc", platform="linux", which=has(), run=run, environ={}) is None and run.calls == []
    assert clipboard.put("abc", platform="linux", which=has(), run=run, environ={}) == UNPROVEN
    assert "install" not in clipboard.put("abc", platform="darwin", which=has(), run=run, environ={})  # xclip is no help on a Mac
    assert clipboard.put("abc", platform="linux", which=has("xclip"), run=run, environ={}) == ""  # a tool took it: nothing to say


def test_a_tool_that_stays_behind_to_serve_the_clipboard_does_not_hold_the_copy_up(tmp_path):
    """xclip, xsel and wl-copy take the text and stay, with what they inherited still open: a
    pipe for what the tool says would be read until they end. The tool here is a script that
    does the same; it writes what it was given to a file under tmp_path."""
    tool = tmp_path / "bin" / "xclip"
    tool.parent.mkdir()
    taken = tmp_path / "taken.txt"
    tool.write_text(f'#!/bin/sh\ncat > "{taken}"\nsleep 5 &\nexit 0\n')
    tool.chmod(0o755)
    environ = {"PATH": f"{tool.parent}:/usr/bin:/bin"}

    def run(argv, **kwargs):  # the real one, by another name: this tool is the test's own
        return subprocess.run(argv, **kwargs)

    used = clipboard.copy_text("naïve\nline 2", platform="linux", which=lambda name: str(tool) if name == "xclip" else None, run=run,
                               environ=environ)
    assert used == "xclip" and taken.read_text(encoding="utf-8") == "naïve\nline 2"


# ---------------------------------------------------------------------- the mouse


def test_a_drag_over_a_transcript_entry_copies_exactly_the_dragged_text_both_ways_and_says_how_much():
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        written = terminal(app)
        note = row(app, "· tokens are at 96%")
        await drag(pilot, note, (2, 0), (7, 0))
        assert clip.texts == ["tokens"]  # the operating system's clipboard
        assert osc52(written) == ["tokens"]  # and the terminal's
        assert status_line(app).strip() == "● copied 6 characters"
        await drag(pilot, note, (2, 0), (2, 0))  # a press and release where it was: a click
        await pilot.click(note, offset=(9, 0))
        await pilot.pause()
        assert clip.texts == ["tokens"] and osc52(written) == ["tokens"]  # a click copies nothing
        assert not app.screen.selections  # and takes the selection down
        # over two entries: the end of one row, the start of the next, a newline between them
        log = log_of(app)
        first, second = row(app, "▲ Loop alert"), row(app, "▲ Effort vs value alert")
        assert second.region.y == first.region.y + 1
        await drag(pilot, log, (first.region.x - log.region.x + 2, first.region.y - log.region.y),
                   (second.region.x - log.region.x + 7, second.region.y - log.region.y))
        end, start = clip.texts[-1].split("\n")
        assert end == "Loop alert · turn 13" and start.startswith("▲ Effo") and "▲ Effort vs value alert · turn 13".startswith(start)
        assert status_line(app).strip() == f"● copied {len(clip.texts[-1])} characters"

    drive(app, script, BIG)


def test_a_double_click_copies_the_whole_entry_with_what_the_edge_hides_and_a_triple_click_the_transcript():
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        intake = row(app, "· L1 intake: unsure")
        whole = views.entry_text(deck, lane, views.entries(lane.actions)[1]).plain
        assert len(whole) > intake.size.width and "…" in region_text(app, "#transcript").splitlines()[1]  # the edge cuts it
        await pilot.click(intake, offset=(5, 0))
        await pilot.pause()
        assert clip.texts == []  # a click copies nothing
        await pilot.double_click(intake, offset=(5, 0))
        await pilot.pause()
        assert clip.texts == [whole] and whole.endswith("frida_trace …+14 lines")  # also what the edge hides
        assert status_line(app).strip() == f"● copied {len(whole)} characters"
        run = row(app, "⏺ 10 tool calls")  # an entry of two rows is copied as its two lines
        await pilot.double_click(run, offset=(5, 1))
        await pilot.pause()
        assert clip.texts[-1] == views.entry_text(deck, lane, views.entries(lane.actions)[2]).plain and clip.texts[-1].count("\n") == 1
        await pilot.triple_click(run, offset=(5, 1))
        await pilot.pause()
        assert clip.texts[-1] == "\n".join(log_of(app).texts())  # every entry that is mounted, in order

    drive(app, script, BIG)


def test_a_double_click_as_a_terminal_reports_it_copies_the_entry_once():
    """A terminal sends the button down and up, twice; the console makes the clicks of them
    itself, and hears that the button came up only after the second click has selected the
    entry. Both the button and the click would copy it: it is copied once."""
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        note = row(app, "· tokens are at 96%")
        x, y = note.region.x + 5, note.region.y
        for _ in range(2):
            for kind in (events.MouseDown, events.MouseUp):
                app.post_message(kind(None, x, y, 0, 0, 1, False, False, False, screen_x=x, screen_y=y))
        await pilot.pause()
        await pilot.pause()
        assert clip.texts == ["· tokens are at 96% of this lane's cap"]
        assert status_line(app).strip() == "● copied 38 characters"

    drive(app, script, BIG)


def test_a_details_row_wrapped_over_three_rows_copies_as_one_line():
    deck, app, lane, clip = console("deck")
    words = "I think main compares against a table built at run time. " * 4
    says(deck, words.strip())

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        said = row(app, "⏺ says: I think main compares")
        line = str(said.render())
        assert said.region.height >= 3 and "\n" not in line  # one line of the log, on three rows of the view or more
        await drag(pilot, said, (2, 0), (20, 2))
        copied = clip.texts[-1]
        assert "\n" not in copied and copied.startswith("says: I think main") and copied in line
        assert len(copied) > 2 * said.size.width  # it runs from the first row into the third
        await pilot.double_click(said, offset=(4, 1))
        await pilot.pause()
        assert clip.texts[-1] == line == f"⏺ says: {words.strip()}"

    drive(app, script, NARROW)


def test_a_drag_over_the_calm_card_the_header_or_the_status_line_copies_its_text():
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        card = app.screen.query_one("#now", Static)
        await drag(pilot, card, (4, 1), (18, 1))  # inside its border and padding: the question's row
        assert clip.texts == ["waiting for you"]
        await drag(pilot, card, (4, 2), (16, 3))  # the answers' row into the row of what else is open
        assert clip.texts[-1] == "1 more budget   0 stop the lane\n  also: looping"
        await drag(pilot, app.screen.query_one("#header"), (1, 0), (10, 0))
        assert clip.texts[-1] == "flightdeck"
        app.say("the status line is text too")
        await pilot.pause()
        await drag(pilot, app.screen.query_one("#status"), (2, 0), (11, 0))
        assert clip.texts[-1] == "the status" and status_line(app).strip() == "● copied 10 characters"

    drive(app, script, BIG)


def test_the_full_card_and_the_lane_list_do_not_select_and_a_copy_is_never_claimed():
    deck, app, lane, clip = console("deck")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await drag(pilot, app.screen.query_one("#now", Static), (4, 1), (30, 2))  # the full card is a panel, not text
        assert clip.texts == [] and "copied" not in status_line(app)
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)
        await drag(pilot, app.screen.query_one("#lanes"), (4, 1), (30, 1))  # a table of rows to pick, not text
        assert clip.texts == [] and "copied" not in status_line(app)
        await drag(pilot, app.screen.query_one("#header"), (1, 0), (10, 0))  # the lane list's header selects as the lane's does
        assert clip.texts == ["flightdeck"] and status_line(app).strip() == "● copied 10 characters"

    drive(app, script, NARROW)


def test_a_selection_already_copied_is_not_copied_again_by_a_drag_of_the_scroll_bar():
    deck, app, lane, clip = console("deck")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        log = log_of(app)
        assert log.max_scroll_y > 0
        note = row(app, "· flightdeck  tokens are at 96%")
        await drag(pilot, note, (2, 0), (11, 0))
        assert clip.texts == ["flightdeck"]
        app.say("something else since")
        await pilot.pause()
        await drag(pilot, log, (log.size.width - 1, 3), (log.size.width - 1, 1))  # the scroll bar, dragged up
        assert app.screen.get_selected_text() == "flightdeck"  # the selection stays while the player scrolls
        assert clip.texts == ["flightdeck"] and "copied" not in status_line(app)  # and is not copied a second time
        await press(pilot, "ctrl+c")  # asked for, it is
        assert clip.texts == ["flightdeck", "flightdeck"] and status_line(app).strip() == "● copied 10 characters"

    drive(app, script, NARROW)


# ---------------------------------------------------------------------- no tool, and over SSH


def test_with_no_clipboard_tool_the_copy_warns_what_to_do_instead_of_claiming_it():
    deck, app, lane = busy_lane("simple")
    run = Runner()
    app.copier = partial(clipboard.put, platform="linux", which=has(), run=run, environ={})

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        written = terminal(app)
        await drag(pilot, row(app, "· tokens are at 96%"), (2, 0), (7, 0))
        assert osc52(written) == ["tokens"] and run.calls == []  # all that could be done was done
        assert_warning(app, UNPROVEN)
        assert "copied" not in status_line(app)

    drive(app, script, BIG)


def test_over_ssh_the_copy_goes_to_the_terminal_only_and_says_so():
    deck, app, lane = busy_lane("simple")
    run = Runner()
    app.copier = partial(clipboard.put, platform="linux", which=has("wl-copy", "xclip", "xsel"), run=run, environ={"SSH_TTY": "/dev/pts/3"})

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        written = terminal(app)
        await drag(pilot, row(app, "· tokens are at 96%"), (2, 0), (7, 0))
        assert run.calls == []  # no tool on the far machine
        assert osc52(written) == ["tokens"]  # the terminal carries it to the machine the player sits at
        assert_warning(app, "sent to the terminal's clipboard (OSC 52). If paste is empty, this terminal does not take it: hold fn")
        assert "install" not in status_line(app) and "copied" not in status_line(app)

    drive(app, script, BIG)


# ---------------------------------------------------------------------- ctrl+c and esc


def test_ctrl_c_copies_the_selection_with_no_quit_hint_and_with_none_the_hint_shows_as_before():
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, "ctrl+c")
        assert clip.texts == [] and QUIT_HINT in screen_text(app)  # nothing selected: Textual's hint that ctrl+q quits
        app.clear_notifications()
        await pilot.pause()
        await drag(pilot, row(app, "· tokens are at 96%"), (2, 0), (7, 0))
        app.say("something else since")
        await press(pilot, "ctrl+c")
        assert clip.texts == ["tokens", "tokens"] and status_line(app).strip() == "● copied 6 characters"
        assert QUIT_HINT not in screen_text(app)
        # the lane list: the same key
        await press(pilot, "escape", "escape")
        assert isinstance(app.screen, FleetScreen)
        await drag(pilot, app.screen.query_one("#header"), (1, 0), (10, 0))
        app.say("something else since")
        await press(pilot, "ctrl+c")
        assert clip.texts[-2:] == ["flightdeck", "flightdeck"] and status_line(app).strip() == "● copied 10 characters"
        assert QUIT_HINT not in screen_text(app)
        await press(pilot, "escape")  # the selection goes
        await press(pilot, "ctrl+c")
        assert len(clip.texts) == 4 and QUIT_HINT in screen_text(app)

    async def main():  # with Textual's toasts, which a test's console leaves out otherwise: the hint is one
        async with app.run_test(size=BIG, notifications=True) as pilot:
            await pilot.pause()
            await script(pilot)

    asyncio.run(main())


def test_ctrl_c_in_the_chat_box_copies_what_is_selected_there():
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await pilot.press(*"try the table", "shift+left", "shift+left", "shift+left", "shift+left", "shift+left")
        await press(pilot, "ctrl+c")
        assert clip.texts == ["table"] and status_line(app).strip() == "● copied 5 characters"
        assert bar(app).field.value == "try the table"

    drive(app, script, BIG)


def test_esc_with_a_selection_takes_it_down_and_the_view_stays_and_the_next_esc_goes_back():
    deck, app, lane, clip = console()

    async def script(pilot):
        focus = await open_focus(pilot, app, "L01")
        await drag(pilot, row(app, "· tokens are at 96%"), (2, 0), (7, 0))
        assert app.screen.get_selected_text() == "tokens"
        await press(pilot, "escape")
        assert app.screen is focus and not focus.selections  # still in the lane, nothing selected
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)
        # the lane list: esc takes a selection down before it clears the filter
        await press(pilot, "/")
        await send(pilot, app, "filter crack")
        fleet = app.screen
        assert fleet.filter_text == "crack"
        await drag(pilot, fleet.query_one("#header"), (1, 0), (10, 0))
        assert fleet.get_selected_text() == "flightdeck"
        await press(pilot, "escape")
        assert not fleet.selections and fleet.filter_text == "crack"
        await press(pilot, "escape")
        assert fleet.filter_text == ""

    drive(app, script, BIG)


def test_the_chat_box_keeps_the_focus_through_a_drag_and_a_key_typed_next_lands_in_it():
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await pilot.press(*"look at ")
        await drag(pilot, row(app, "· tokens are at 96%"), (2, 0), (7, 0))
        assert bar(app).field.has_focus and bar(app).field.value == "look at " and clip.texts == ["tokens"]
        await press(pilot, "x")
        assert bar(app).field.value == "look at x"
        assert not app.screen.selections  # typing takes the selection down
        await drag(pilot, app.screen.query_one("#now", Static), (4, 1), (18, 1))  # the card's box takes no focus either
        assert bar(app).field.has_focus
        await press(pilot, "y")
        assert bar(app).field.value == "look at xy" and lane.hints == []  # typed, not sent

    drive(app, script, BIG)


def test_help_says_how_to_select_and_copy():
    keys = dict(KEY_HELP)
    assert keys["mouse drag"] == "Select text: copied as you let go (double-click: a whole entry; triple-click: all)"
    assert keys["ctrl+c"] == "Copy the selected text again; esc takes the selection down. /copy copies with no mouse"
    deck, app, lane, clip = console("deck")

    async def script(pilot):
        await press(pilot, "question_mark")
        text = " ".join(screen_text(app).split())
        assert "mouse drag Select text: copied as you let go" in text and "ctrl+c Copy the selected text again" in text

    drive(app, script, (160, 60))


# ---------------------------------------------------------------------- the highlight


@pytest.mark.parametrize("name", sorted(themes.BUILTIN))
def test_selected_text_is_on_the_themes_selected_colour_and_keeps_its_own(name):
    """The highlight is the palette's colour for a selected row, which every theme must give
    a contrast with its text (themes.CONTRAST); the text keeps the colour it had."""
    palette = themes.BUILTIN[name]
    deck, _, lane = busy_lane("simple")
    app = FlightdeckApp(deck, refresh_seconds=None, layout="simple", palette=palette, copier=Clip())
    assert themes.contrast(palette.text, palette.selected_focus) >= themes.MIN_CONTRAST

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        said = row(app, "⏺ I have the table now")
        selected = Color.parse(palette.selected_focus)
        before = color_of(app, "I have the table now", said.region.y)
        assert selected not in backgrounds(said)
        await drag(pilot, said, (2, 0), (21, 0))
        assert app.screen.get_selected_text() == "I have the table now"
        behind = backgrounds(said)
        assert set(behind[2:22]) == {selected} and selected not in behind[:2] + behind[22:]  # behind the selected text, and only there
        assert color_of(app, "I have the table now", said.region.y) == before == palette.text.lower()
        await press(pilot, "escape")
        assert selected not in backgrounds(said)

    drive(app, script, BIG)


# ---------------------------------------------------------------------- /copy


def test_copy_gives_the_last_output_with_real_newlines_and_no_credential():
    deck, app, lane = one_lane()
    app.copier = clip = Clip()
    shell(deck, "cat .env && objdump -s -j .rodata work/crackme | head -30", f"OPENROUTER_API_KEY={OPENROUTER}\n{osc('out')}\n" + RODATA)
    says(deck, "The table is in .rodata.")  # the model's words are not a tool call
    step = lane.actions[0]
    assert OPENROUTER in step.calls[0].output  # the deck keeps it as it was

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        written = terminal(app)
        await send(pilot, app, "/copy")
        (copied,) = clip.texts
        lines = copied.split("\n")
        assert lines[0] == "OPENROUTER_API_KEY=[redacted]" and lines[1] == shown("out") + "^[\\"  # no key, no escape sequence
        assert lines[2:] == RODATA.rstrip("\n").split("\n") and len(lines) == 32  # the transcript's excerpt, line by line
        assert not [value for value in VALUES if value in copied] and "\x1b" not in copied and NEWLINE not in copied
        assert osc52(written) == [copied]
        assert status_line(app).strip() == "● copied L01's last output: 32 lines"
        await send(pilot, app, "/copy output")  # the same, by name
        assert clip.texts == [copied, copied]

    drive(app, script, BIG)


def test_copy_command_gives_that_calls_command_with_its_lines_and_copy_all_every_line_in_detail():
    deck, app, lane = one_lane()
    app.copier = clip = Clip()
    command, out, _ = COMMANDS[6]  # a here-document of seven lines
    shell(deck, command, out)
    calls = (Call("$ ls work", "crackme\nREADME.txt"), Call("plan: read the loop that fills the table", ""))
    deck.report("L01", TurnReport(action=calls[0].text + "  (+1 more)", output=calls[0].output, calls=calls, tokens=100))

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, app, "/copy command")
        assert clip.texts == ["ls work"]  # the last call that printed something, without the mark of a shell call
        assert status_line(app).strip() == "● copied L01's last command: 1 line"
        await send(pilot, app, "/copy")
        assert clip.texts[-1] == "crackme\nREADME.txt"  # and /copy is that call's output
        await send(pilot, app, "/copy all")
        every = [line.plain for action in lane.actions for line in views.transcript_lines(deck, lane, action)]
        assert clip.texts[-1] == "\n".join(every) and len(every) == 4
        assert status_line(app).strip() == "● copied L01's transcript: 4 lines"

    drive(app, script, BIG)
    deck, app, lane = one_lane()
    app.copier = clip = Clip()
    shell(deck, command, out)

    async def heredoc(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, app, "/copy command")
        assert clip.texts == [command] and command.count("\n") == 6 and NEWLINE in lane.actions[0].text  # folded in the log, lines again here
        assert status_line(app).strip() == "● copied L01's last command: 7 lines"

    drive(app, heredoc, BIG)


def test_copy_of_a_coding_agent_clis_step_unfolds_the_newlines_its_runtime_folded():
    deck, app, lane = one_lane()
    app.copier = clip = Clip()
    deck.report("L01", TurnReport(action="$ cat notes.txt", output=f"first{NEWLINE}second{NEWLINE}third"))  # one step for each call, no calls kept

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, app, "/copy")
        assert clip.texts == ["first\nsecond\nthird"] and status_line(app).strip() == "● copied L01's last output: 3 lines"
        await send(pilot, app, "/copy command")
        assert clip.texts[-1] == "cat notes.txt"

    drive(app, script, BIG)


def test_copy_flag_gives_the_flag_that_waits_else_the_newest_the_run_knows_and_warns_when_there_is_none():
    deck, app, lane = one_lane()
    app.copier = clip = Clip()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, app, "/copy flag")
        assert_warning(app, "L01 has no flag yet")
        assert clip.texts == []
        deck.record_l1("crackme", "strings_sweep", "candidate", flags=["flag{from_l1}", "flag{second_of_l1}"], lane_id="L01")
        await send(pilot, app, "/copy flag")
        assert clip.texts == ["flag{second_of_l1}"] and status_line(app).strip() == "● copied L01's flag: flag{second_of_l1}"
        deck.report("L01", TurnReport(flag="flag{the_lane_found}"))
        assert lane.pending is not None and lane.pending.flag == "flag{the_lane_found}"
        deck.record_l1("crackme", "xor_single", "candidate", flags=["flag{later_but_not_asked}"], lane_id="L01")
        await send(pilot, app, "/copy flag")
        assert clip.texts[-1] == "flag{the_lane_found}"  # the one the lane waits for an answer about
        assert status_line(app).strip() == "● copied L01's flag: flag{the_lane_found}"  # the status line says which

    drive(app, script, BIG)


def test_copy_flag_gives_the_flag_the_lane_proposed_last_when_the_run_knew_it_before():
    deck, app, lane = one_lane()
    app.copier = clip = Clip()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        deck.record_l1("crackme", "strings_sweep", "candidate", flags=["flag{right_from_l1}"], lane_id="L01")
        deck.report("L01", TurnReport(flag="flag{wrong_guess}"))
        await send(pilot, app, "/decline")
        assert lane.pending is None and "Not submitted: flag{wrong_guess}" in status_line(app)
        await send(pilot, app, "/copy flag")
        assert clip.texts == ["flag{wrong_guess}"]  # the last one the run met, though the player declined it
        assert status_line(app).strip() == "● copied L01's flag: flag{wrong_guess}"  # so the status line names what a paste will give
        deck.report("L01", TurnReport(flag="flag{right_from_l1}"))  # the lane comes to the flag L1 had reported before its guess
        await send(pilot, app, "/approve")
        assert lane.pending is None and "flag{right_from_l1}" in status_line(app)  # submitted: nothing waits
        await send(pilot, app, "/copy flag")
        assert clip.texts[-1] == "flag{right_from_l1}"  # the one just submitted, not the guess declined before it
        assert views.known_flags(deck, "crackme") == ("flag{wrong_guess}", "flag{right_from_l1}")  # each once, the last met last

    drive(app, script, BIG)


def test_copy_warns_when_the_lane_has_nothing_of_it_or_the_word_is_not_one_of_its():
    deck, app, lane = one_lane()
    app.copier = clip = Clip()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert lane.actions == []
        for command, warning in (("/copy", "L01 has no output yet"), ("/copy command", "L01 has made no tool call yet"),
                                 ("/copy all", "L01 has nothing in its transcript yet"),
                                 ("/copy everything", "/copy takes nothing (the last output) or one of: output, command, flag, all")):
            await send(pilot, app, command)
            assert_warning(app, warning)
        says(deck, "nothing run yet")  # the model's words are no tool call
        await send(pilot, app, "/copy command")
        assert_warning(app, "L01 has made no tool call yet")
        deck.report("L01", TurnReport(action="plan: read the header", calls=(Call("plan: read the header", ""),)))
        await send(pilot, app, "/copy")
        assert_warning(app, "L01 has no output yet")  # a call that printed nothing
        assert clip.texts == []
        await send(pilot, app, "/copy command")
        assert clip.texts == ["plan: read the header"]  # no call has printed anything: the last call's line
        # from the lane list it acts on the selected lane, or on the one named
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)
        await press(pilot, "/")
        await send(pilot, app, "copy L01 all")
        assert clip.texts[-1] == "⏺ says: nothing run yet\n⏺ plan: read the header"
        assert status_line(app).strip() == "● copied L01's transcript: 2 lines"

    drive(app, script, BIG)


def test_a_tool_that_fails_is_named_in_the_warning():
    deck, app, lane = busy_lane("simple")
    app.copier = partial(clipboard.put, platform="linux", which=has("xclip"), run=Runner(xclip=1), environ={})

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, app, "/copy")
        assert_warning(app, "xclip failed (exit 1); sent to the terminal's clipboard (OSC 52).")

    drive(app, script, BIG)


def test_the_command_menu_lists_copy_and_it_acts_on_a_lane():
    assert BY_NAME["copy"].args == "[output|command|flag|all]" and BY_NAME["copy"].lane
    deck, app, lane, clip = console()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await pilot.press(*"/cop")
        await pilot.pause()
        assert [completion.label for completion in bar(app).completions] == ["/copy [output|command|flag|all]"]

    drive(app, script, BIG)
