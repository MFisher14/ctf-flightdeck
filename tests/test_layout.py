"""The calm console: what both layouts say on an empty board and in the command menu, and the
`simple` layout (the default: one list of lanes, a short header, only the keys that apply now)
beside `deck` (the dashboard as it was).

Read from the screen as a player sees it (test_console's helpers rebuild the terminal from the
SVG export). Decks here are synthetic: a driver that does no work, and lanes whose turns the
test reports itself. Nothing needs a model or a network.
"""

from __future__ import annotations

import os
import re
from dataclasses import replace

import pytest
from rich.cells import cell_len
from textual.widgets import DataTable
from typer.testing import CliRunner

from ctf_flightdeck import cli, config
from ctf_flightdeck.addchallenge import slug
from ctf_flightdeck.console import fleet, focus, room, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.commands import BY_NAME, COMMANDS, complete, needs_lane, parse
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import HelpScreen
from ctf_flightdeck.core.attention import SortMode
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, Challenge, DeckConfig, FileChange, LaneState, Suggestion
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld
from test_console import (
    WIDE,
    assert_warning,
    bar,
    columns,
    cursor_key,
    drive,
    footer_line,
    lane_rows,
    open_focus,
    press,
    prompt_text,
    quiet_deck,
    region_text,
    screen_text,
    status_line,
    step_until,
    type_line,
)

SIZE = (160, 46)
LAYOUTS = ("simple", "deck")
SIMPLE_COLUMNS = ["bar", "!", "lane", "chall", "state", "cost", "last"]
DECK_COLUMNS = ["bar", "!", "lane", "chall", "model", "state", "turns", "cost", "idle", "last"]


async def added(new) -> tuple[bool, str]:
    """A stand-in for a run's adder (/new): the board is one the player fills."""
    return True, "added"


def console(*, by_hand: bool, layout: str = "deck", adder=None, **kw) -> tuple[Deck, FlightdeckApp]:
    """A console on an empty board: one the player fills (`by_hand`; `adder`: what /new calls),
    or one a platform fills."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=4))
    app = FlightdeckApp(deck, refresh_seconds=3600.0, adder=(adder or added) if by_hand else None, layout=layout, **kw)  # the timer is on; it never fires here
    return deck, app


def release(deck: Deck, *ids: str) -> None:
    deck.release([Challenge(cid, cid.title(), "misc", 100) for cid in ids], [QueueEntry(cid, "glm") for cid in ids])


COURSE = Alert(AlertKind.HINT, "the description says SSTV", (Suggestion("r", "Redirect", "decode it as SSTV"), Suggestion("h", "Hint", "think slow-scan")))


def three_lanes(layout: str = "simple", **kw) -> tuple[Deck, FlightdeckApp]:
    """A console with a lane of each kind a key line can be about: L01 at work with nothing to
    answer, L02 waiting with a flag to approve, L03 with an alert about its course."""
    deck, app = console(by_hand=True, layout=layout, **kw)
    release(deck, "alpha", "beta", "gamma")
    deck.report("L01", TurnReport(action="file alpha.bin", plan="look inside"))
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{synthetic}"))
    deck.report("L03", TurnReport(action="strings gamma.wav", alerts=(COURSE,)))
    assert deck.lanes["L02"].pending is not None and deck.lanes["L03"].alerts and not deck.lanes["L01"].needs_you
    return deck, app


# ---------------------------------------------------------------------- an empty board


@pytest.mark.parametrize("layout", LAYOUTS)
def test_an_empty_by_hand_board_says_how_to_add_a_challenge_and_keeps_saying_it(layout):
    deck, app = console(by_hand=True, layout=layout)
    now = [500.0]
    app.status_clock = lambda: now[0]

    async def script(pilot):
        assert fleet.EMPTY_BY_HAND == "No challenges yet. Type /new to hand one over (its text, files, a screenshot)."
        assert fleet.EMPTY_BY_HAND in region_text(app, "#empty") and not app.fleet.query_one("#main").display
        assert bar(app).field.placeholder == "/new to add a challenge · / for commands"
        app.say("a line that expires")
        await pilot.pause()
        assert "a line that expires" in status_line(app)
        now[0] += 60.0  # well past the 12 seconds a status line lasts
        app.refresh_view()
        await pilot.pause()
        assert status_line(app).strip() == "" and fleet.EMPTY_BY_HAND in screen_text(app)
        await press(pilot, "question_mark")  # nothing has the focus, and the keys act all the same
        assert type(app.screen).__name__ == "HelpScreen"
        await press(pilot, "escape")
        assert bar(app).field.value == ""  # no key went into the command bar

    drive(app, script, SIZE)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_an_empty_platform_board_says_the_challenges_come_by_themselves(layout):
    deck, app = console(by_hand=False, layout=layout)

    async def script(pilot):
        shown = region_text(app, "#empty")
        assert "Waiting for the board: challenges appear here when the event releases them." in shown
        assert "/new" not in screen_text(app)  # /new is refused on this board: nothing tells the player to type it
        assert bar(app).field.placeholder == "/ for commands"

    drive(app, script, SIZE)


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("by_hand", [True, False], ids=["by hand", "platform"])
def test_the_lane_list_takes_the_empty_pages_place_once_a_challenge_is_released(layout, by_hand):
    deck, app = console(by_hand=by_hand, layout=layout)

    async def script(pilot):
        assert app.fleet.query_one("#empty").display
        release(deck, "alpha", "beta")
        await pilot.pause()
        await pilot.pause()
        assert not app.fleet.query_one("#empty").display and app.fleet.query_one("#main").display
        shown = screen_text(app)
        assert fleet.EMPTY_BY_HAND not in shown and fleet.EMPTY_PLATFORM not in shown
        assert lane_rows(app) == ["L01", "L02"] and "Alpha" in region_text(app, "#lanes")
        assert bar(app).field.placeholder == fleet.BAR
        assert isinstance(app.focused, DataTable) and app.focused.id == "lanes"  # the keys act on the lane under the cursor
        await press(pilot, "p")
        assert deck.lanes["L01"].state is LaneState.PAUSED

    drive(app, script, SIZE)


def test_a_player_typing_in_the_bar_goes_on_typing_when_the_first_challenge_arrives():
    deck, app = console(by_hand=True)

    async def script(pilot):
        await press(pilot, "slash", *"ne")
        assert bar(app).field.has_focus and bar(app).field.value == "/ne"
        release(deck, "alpha")
        await pilot.pause()
        await pilot.pause()
        assert app.fleet.query_one("#main").display
        assert bar(app).field.has_focus and bar(app).field.value == "/ne"  # the draft and the focus are where they were
        await press(pilot, "w")
        assert bar(app).field.value == "/new"

    drive(app, script, SIZE)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_command_typed_while_the_board_fills_acts_on_the_lane_the_list_selects(layout):
    """An empty board is not a board the player is on: once it fills, the bar, the why line
    and a command act on the lane selected in the lane list, as on a board that was never empty."""
    deck, app = console(by_hand=False, layout=layout)

    async def script(pilot):
        assert not app.fleet.board_focused  # nothing is shown that could have the focus
        await press(pilot, "slash", *"kill")
        # the board lists Web one first (by category), the lane list L01 on Zed
        deck.release([Challenge("zed", "Zed", "pwn", 100), Challenge("web-one", "Web one", "web", 100)],
                     [QueueEntry("zed", "glm"), QueueEntry("web-one", "glm")])
        await pilot.pause()
        await pilot.pause()
        screen = app.fleet
        assert deck.lanes["L01"].challenge_id == "zed" and deck.lanes["L02"].challenge_id == "web-one"
        assert bar(app).field.has_focus and bar(app).field.value == "/kill"
        assert screen.selected_lane == "L01" and cursor_key(app) == "L01"
        assert not screen.board_focused and screen.bar_lane() is deck.lanes["L01"]
        await press(pilot, "enter")
        assert "Killed L01" in status_line(app), status_line(app)
        assert deck.lanes["L01"].state is LaneState.KILLED and deck.lanes["L02"].state is LaneState.RUNNING
        assert isinstance(app.focused, DataTable) and app.focused.id == "lanes"  # back in the lane list, not on the board

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the command menu


def menu_text(app: FlightdeckApp) -> str:
    return region_text(app, "#menu")


def menu_rows(app: FlightdeckApp) -> list[str]:
    """The command each row of the open menu shows, top row first (its frame left out)."""
    return [line.strip("│ ").split()[0] for line in menu_text(app).splitlines()[1:-1] if line.strip("│ ")]


def test_with_no_lane_the_menu_lists_new_first_and_scrolls_to_every_command():
    deck, app = console(by_hand=True)

    async def script(pilot):
        await press(pilot, "slash")
        menu = bar(app)
        assert menu.menu_open and [c.text for c in menu.completions[:4]] == ["/new ", "/help ", "/config ", "/queue "]
        assert sorted(c.text for c in menu.completions) == sorted(f"/{c.name} " for c in COMMANDS)  # all of them, each once
        rows = menu_rows(app)
        assert rows[:4] == ["/new", "/help", "/config", "/queue"] and len(rows) < len(COMMANDS)  # more commands than rows
        last = len(COMMANDS) - 1
        wanted = menu.completions[last].text
        assert wanted.strip() not in rows
        for _ in range(last):
            await pilot.press("down")
        await pilot.pause()
        assert menu.menu.highlighted == last
        assert menu_rows(app)[-1] == wanted.strip() and "/new" not in menu_rows(app)  # it scrolled to the last one
        await press(pilot, "tab")
        assert menu.field.value == wanted

    drive(app, script, SIZE)


def test_the_commands_past_the_menus_eighth_row_are_reached_with_the_arrow_keys():
    deck, app = console(by_hand=True)
    release(deck, "alpha")

    async def script(pilot):
        assert len(COMMANDS) > 9
        for index in (0, 7, 8, len(COMMANDS) - 1):  # the menu once stopped at eight entries
            await press(pilot, "slash")
            assert len(bar(app).completions) == len(COMMANDS)
            await pilot.press(*["down"] * index)
            await press(pilot, "tab")
            assert bar(app).field.value == f"/{COMMANDS[index].name} "  # a lane is selected: the usual order
            await press(pilot, "escape")
            assert bar(app).field.value == ""

    drive(app, script, SIZE)


def test_with_an_approval_waiting_the_menu_lists_approve_first():
    deck, app = console(by_hand=True)
    release(deck, "alpha")
    deck.report("L01", TurnReport(action="cat flag.txt", flag="flag{synthetic}"))

    async def script(pilot):
        assert deck.lanes["L01"].pending is not None
        await press(pilot, "slash")
        first = bar(app).completions[0]
        assert (first.text, first.suggested) == ("/approve L01", True)
        assert next(c.text for c in bar(app).completions if not c.suggested) == "/hint "  # then the commands, a lane's first
        assert menu_rows(app)[0] == "/approve"

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- wording, and the welcome screen


def test_a_board_with_challenges_and_no_lane_says_no_lanes_yet():
    deck, app = console(by_hand=False)
    deck.release([Challenge("alpha", "Alpha", "misc", 100)], [])  # on the board, and nothing queued

    async def script(pilot):
        assert app.fleet.query_one("#main").display and not deck.lanes
        assert region_text(app, "#why").strip() == "No lanes yet."

    drive(app, script, SIZE)


MEANINGS = ("the board:", "the lanes:", "the command bar:", "open a lane", "hand over a challenge", "every key, any time")


@pytest.mark.parametrize("width", [160, 70], ids=["wide", "narrow"])
def test_the_welcome_screens_meanings_stand_in_one_column_and_wrap_under_themselves(width):
    deck, app = console(by_hand=True, welcome=True)

    async def script(pilot):
        assert type(app.screen).__name__ == "WelcomeScreen"
        lines = region_text(app, "Vertical").splitlines()
        starts = {text: next(line.index(text) for line in lines if text in line) for text in MEANINGS}
        assert len(set(starts.values())) == 1, starts  # /new is a longer word than a: its meaning starts where the others do
        column = starts["the lanes:"]
        at = next(i for i, line in enumerate(lines) if "the lanes:" in line)
        if width == 160:
            assert lines[at].rstrip("│ ").endswith("the one that needs you on top")  # the dialog has room for its longest row
        else:  # a dialog too narrow for it: the rest goes under the meaning, not under the word
            rest = lines[at + 1]
            assert rest[:column].strip("│ ") == "" and rest[column] != " " and rest.rstrip("│ ").endswith("top")

    drive(app, script, (width, 46))


def shown_whole(app: FlightdeckApp, selector: str) -> bool:
    """Whether a widget of the open dialog is on screen with every row and column of it: inside
    the terminal, inside the dialog, and inside what the dialog's scrolling part shows now."""
    widget = app.screen.query_one(selector)
    region = widget.region
    if not region.area or not app.screen.region.contains_region(region):
        return False
    return all(parent.region.contains_region(region) for parent in widget.ancestors if parent is not app.screen and hasattr(parent, "region")
               and parent in app.screen.walk_children())


WELCOME_SIZES = [(80, 24), (66, 24), (64, 24), (50, 20), (80, 16), (100, 24), (160, 46)]
WELCOME_KEYS = {  # (the mock, a board the player fills): what the last row says
    (True, False): "enter open the console esc just show me the console",
    (False, True): "enter add your first challenge esc just show me the console",
    (False, False): "enter open the console esc just show me the console",
}


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("mock, by_hand", list(WELCOME_KEYS), ids=["mock", "empty by hand", "platform"])
@pytest.mark.parametrize("size", WELCOME_SIZES, ids=[f"{w}x{h}" for w, h in WELCOME_SIZES])
def test_the_welcome_screen_always_says_which_key_does_what(size, mock, by_hand, layout):
    """The last row is the one next step: it is on screen at every size, whatever the text
    over it wraps to, and Enter does what it says."""
    if mock:
        world = FakeWorld(scenarios.get("sstv"))
        app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None, welcome=True, layout=layout)
    else:
        _, app = console(by_hand=by_hand, layout=layout, welcome=True)

    async def script(pilot):
        assert type(app.screen).__name__ == "WelcomeScreen"
        said = prompt_text(app)
        assert WELCOME_KEYS[mock, by_hand] in said, said
        assert "Welcome to flightdeck" in said and shown_whole(app, ".keys")
        await press(pilot, "enter")
        assert type(app.screen).__name__ == ("NewChallengePrompt" if by_hand else "FleetScreen")

    drive(app, script, size)


def test_a_welcome_screen_too_tall_for_the_terminal_scrolls_under_its_key_line():
    _, app = console(by_hand=True, layout="deck", welcome=True)

    async def script(pilot):
        said = prompt_text(app)
        assert "enter add your first challenge" in said and "every key, any time" not in said  # the text's end is below
        await press(pilot, "down", "down", "down")  # the arrows scroll the text
        said = prompt_text(app)
        assert "Welcome to flightdeck" not in said and "enter add your first challenge" in said
        await press(pilot, "end")
        said = prompt_text(app)
        assert "every key, any time" in said and "enter add your first challenge" in said  # scrolled to, the keys still there
        await press(pilot, "enter")
        assert type(app.screen).__name__ == "NewChallengePrompt"

    drive(app, script, (50, 14))


FORM_SIZES = [(80, 24), (80, 30), (100, 24), (100, 28), (120, 30), (120, 36), (140, 40), (160, 46), (66, 24)]
FORM_KEYS = "ctrl+s add it and start a lane ctrl+o choose files ctrl+v paste an image tab next field esc cancel"
FORM_PARTS = ("#new-name", "#new-text", "#new-attached", "#new-category", "#new-points", "#new-problem", ".keys")


@pytest.mark.parametrize("size", FORM_SIZES, ids=[f"{w}x{h}" for w, h in FORM_SIZES])
def test_the_new_form_shows_every_field_and_how_to_add_the_challenge(size):
    """From 66x24 up the whole /new form is on screen: each field, the line that says what is
    attached, the line a refusal is said on, and the keys, ctrl+s first."""
    deck, app = console(by_hand=True, layout="simple", welcome=True)

    async def script(pilot):
        await press(pilot, "enter")  # the welcome screen's one next step
        form = app.screen
        assert type(form).__name__ == "NewChallengePrompt"
        said = prompt_text(app)
        assert FORM_KEYS in said, said
        assert "no file attached" in said and "category (optional)" in said and "points (optional)" in said
        assert [part for part in FORM_PARTS if not shown_whole(app, part)] == []
        assert form.query_one("#new-text").size.height >= 3  # rows to type in, inside its border
        if size[0] >= 128:  # the dialog at its widest: the keys are one row, no key apart from its label
            assert form.query_one(".keys").size.height == 1
        for field in ("new-name", "new-text", "new-category", "new-points"):  # tab goes through the fields and nothing else
            assert app.focused.id == field and shown_whole(app, f"#{field}")
            await press(pilot, "tab")
        assert app.focused.id == "new-name"
        await press(pilot, "ctrl+s")  # no name yet: refused, and the reason is on screen
        assert "give the challenge a name with some letters or digits in it" in prompt_text(app)
        assert [part for part in FORM_PARTS if not shown_whole(app, part)] == []

    drive(app, script, size)


@pytest.mark.parametrize("size", [(80, 16), (56, 20)], ids=["80x16", "56x20"])
def test_a_new_form_too_tall_for_the_terminal_keeps_its_keys_and_scrolls_to_the_field_in_use(size):
    deck, app = console(by_hand=True, layout="simple")

    async def script(pilot):
        app.new_challenge()
        await pilot.pause()
        await pilot.pause()
        form = app.screen
        assert FORM_KEYS in prompt_text(app) and shown_whole(app, ".keys") and shown_whole(app, "#new-problem")
        assert shown_whole(app, "#new-name") and not shown_whole(app, "#new-points")
        for field in ("new-text", "new-category", "new-points"):
            await press(pilot, "tab")
            await pilot.wait_for_scheduled_animations()  # the scroll to the field
            assert app.focused.id == field and shown_whole(app, f"#{field}"), field  # the field typed in is never off screen
        await press(pilot, *"250")
        assert form.query_one("#new-points").value == "250" and "250" in prompt_text(app)
        await press(pilot, "ctrl+s")
        assert "give the challenge a name" in prompt_text(app) and shown_whole(app, ".keys")

    drive(app, script, size)


def usage(command) -> str:
    return f"/{command.name} {command.args}".rstrip()


def help_rows(app: FlightdeckApp, label: str) -> list[str]:
    """The rows of the open help that a command's entry takes: from the row that starts with
    its usage (`label`, whole) to the row before the next command's."""
    lines = [re.sub(r"[▁▂▃▄▅▆▇█▔]+$", "", line.rstrip()).rstrip() for line in region_text(app, "#help-body").splitlines()]  # less the scrollbar
    at = next(i for i, line in enumerate(lines) if line.strip() == label or line.strip().startswith(label + "  "))
    end = next(i for i in range(at + 1, len(lines)) if lines[i].lstrip().startswith("/") or not lines[i].strip())
    return lines[at:end]


def test_on_an_80_column_terminal_help_puts_what_a_command_does_under_it_not_in_a_sliver_beside_it():
    """The longest usage (/config's) is 56 cells: beside it, 80 columns leave what each command
    does 14 cells a row. Too narrow for two columns, the list puts it under the command."""
    deck, app = three_lanes("simple")
    approve = BY_NAME["approve"].help

    async def script(pilot):
        await press(pilot, "question_mark")
        assert "Commands (the bar at the bottom" in prompt_text(app)  # a terminal tall enough to show the list whole
        rows = help_rows(app, "/approve [all]")
        assert rows[0].strip() == "/approve [all]"
        assert " ".join(" ".join(rows[1:]).split()) == approve and len(rows) <= 4, rows  # it took ten rows of 14 cells
        indents = {len(row) - len(row.lstrip()) for row in rows[1:]}
        assert indents == {rows[0].index("/") + 2}, rows  # under its command, set in
        said = prompt_text(app)
        for command in COMMANDS:  # every command and what it does, read whole
            assert usage(command) in said and command.help in said, command.name
        assert max(len(help_rows(app, usage(c))) for c in COMMANDS) <= 4

    drive(app, script, (80, 200))


def test_a_terminal_with_the_room_keeps_helps_commands_in_two_columns():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await press(pilot, "question_mark")
        rows = help_rows(app, "/approve [all]")
        assert rows[0].split(None, 2)[2].startswith("approve what the lane waits for")  # beside its command
        starts = {help_rows(app, usage(c))[0].index(c.help[:12]) for c in COMMANDS}
        assert len(starts) == 1  # one column

    drive(app, script, (160, 200))


@pytest.mark.parametrize("size", [(80, 24), (60, 20), (160, 46)], ids=["80x24", "60x20", "160x46"])
def test_help_always_says_how_to_close_it(size):
    deck, app = three_lanes("simple")

    async def script(pilot):
        await press(pilot, "question_mark")
        assert "esc close ↑↓ scroll" in prompt_text(app) and shown_whole(app, ".keys")
        body = app.screen.query_one("#help-body")
        assert body.max_scroll_y > 0 and app.screen.query_one("Vertical").region.contains_region(body.region)
        await press(pilot, "end")
        assert "claimed by you" in prompt_text(app) and "esc close" in prompt_text(app)  # the last row of the text, over the keys

    drive(app, script, size)


# ---------------------------------------------------------------------- the simple layout: the header

CALM = views.HeaderFacts(event="Example CTF", team=False, containerized=True, lanes=3, max_lanes=4, queue=0, need=0, held="",
                         tokens=12_000, dollars=1.5, unpriced=False, clock=3600.0)


def header(facts: views.HeaderFacts, width: int = 200, **layout) -> str:
    return views.fit_header(facts, width, **layout)[0].plain.strip()


def test_the_simple_header_says_only_what_is_not_the_usual():
    assert header(CALM, simple=True) == "flightdeck ╱ Example CTF ╱ $1.50"
    deck_header = header(CALM)
    for gone in ("all clear", "tok", "solo", "docker", "lanes", "queue", "T+"):
        assert gone in deck_header and gone not in header(CALM, simple=True), gone
    odd = replace(CALM, team=True, containerized=False, queue=12, mock="MOCK")
    assert header(odd, simple=True) == "flightdeck ╱ Example CTF ╱ MOCK ╱ team ╱ host ╱ queue 12 ╱ $1.50"


def test_who_has_the_controls_who_needs_you_and_a_held_queue_are_in_every_layouts_header():
    busy = replace(CALM, need=2, held="no key for the model", autopilot=True)
    assert header(busy, simple=True) == "flightdeck ╱ Example CTF ╱ AUTOPILOT ╱ ▲ 2 need you ╱ queue held: no key for the model ╱ $1.50"
    for layout in ({"simple": True}, {}, {"compact": True}, {"compact": True, "simple": True}):
        for width in (200, 80, 40, 20):  # however narrow: these never drop
            shown = header(busy, width, **layout)
            assert "▲ 2 need you" in shown and "queue held" in shown, (layout, width, shown)
            assert ("AP" if layout.get("compact") else "AUTOPILOT") in shown, (layout, width, shown)
    assert header(busy, compact=True, simple=True) == header(busy, compact=True)  # a narrow terminal: the compact header wins


def test_a_narrow_terminal_drops_the_simple_headers_pieces_in_order_and_never_the_dollars():
    odd = replace(CALM, team=True, containerized=False, queue=12, mock="MOCK", need=1)
    whole = views.fit_header(odd, 200, simple=True)[0].cell_len
    dropped = []
    for width in range(whole, 20, -1):
        text, left = views.fit_header(odd, width, simple=True)
        assert left[:len(dropped)] == dropped  # what went stays gone, in the order it went
        dropped = left
        assert "▲ 1 need you" in text.plain and "$1.50" in text.plain and "flightdeck" in text.plain
    assert dropped == ["event", "mock", "queue", "host", "team"]
    assert all(name in views.HEADER_WORDS for name in dropped)  # doctor has a word for each


def test_the_console_draws_the_simple_header_in_both_views_and_deck_keeps_its_own():
    deck, app = three_lanes("simple")

    async def script(pilot):
        assert region_text(app, "#header").strip() == "flightdeck ╱ ev ╱ ▲ 2 need you ╱ $0.00"
        await open_focus(pilot, app, "L01")
        assert region_text(app, "#header").strip() == "flightdeck ╱ ev ╱ ▲ 2 need you ╱ $0.00"
        app.run_command("/layout deck", "L01")
        await pilot.pause()
        assert "solo ╱ docker ╱ lanes 3/4 · queue 0 ╱ ▲ 2 need you ╱ tok 0" in region_text(app, "#header")

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the simple layout: the lane list


def title_of(app: FlightdeckApp, pane: str) -> str:
    """A pane's title as drawn on its frame."""
    return region_text(app, pane).splitlines()[0].strip("╭╮─ ")


def test_the_simple_layout_is_one_list_of_lanes_with_what_the_board_would_say_in_its_title():
    deck, app = three_lanes("simple")
    deck.release([Challenge(n, n.title(), "misc", 100) for n in ("delta", "echo", "fox")], [QueueEntry(n, "glm") for n in ("delta", "echo", "fox")])

    async def script(pilot):
        assert app.fleet.board_hidden and columns(app, "lanes") == SIMPLE_COLUMNS
        assert [key for key, *_ in views.SIMPLE_LANE_COLUMNS] == SIMPLE_COLUMNS
        assert title_of(app, "#lanes-pane") == "lanes 4/4 · 2 waiting"  # two queued behind the four lanes; nothing solved, sorted by attention: neither is said
        assert "board hidden" not in screen_text(app)  # it is not hidden: this layout has none
        await press(pilot, "s")
        assert title_of(app, "#lanes-pane") == "lanes 4/4 · 2 waiting · sort idle"
        app.fleet.set_sort(SortMode.ATTENTION)
        app.fleet.select_lane("L02")
        await press(pilot, "a")  # the flag is checked and wrong here: nothing solved yet
        deck.challenges["gamma"].status = views.ChallengeStatus.SOLVED
        app.fleet.set_filter("alpha")
        await pilot.pause()
        assert title_of(app, "#lanes-pane") == "lanes 4/4 · 2 waiting · ✓ 1 solved · filter alpha · 1 needing you hidden"

    drive(app, script, SIZE)


def test_layout_switches_the_view_and_back_and_keeps_the_cursor_the_filter_and_a_draft():
    deck, app = three_lanes("simple")

    async def script(pilot):
        app.fleet.set_filter("a")  # every lane: Alpha, Beta, Gamma
        app.fleet.set_sort(SortMode.LANE)
        app.fleet.select_lane("L03")
        bar(app).start("/hint keep this draft")
        await pilot.pause()
        before = lane_rows(app)
        for layout, shown, board in (("deck", DECK_COLUMNS, False), ("simple", SIMPLE_COLUMNS, True), ("deck", DECK_COLUMNS, False)):
            app.run_command(f"/layout {layout}", None)
            await pilot.pause()
            await pilot.pause()
            assert app.layout == layout and columns(app, "lanes") == shown and app.fleet.board_hidden is board
            assert f"layout {layout} for this run (this console has no config file)" in status_line(app)
            assert (app.fleet.selected_lane, cursor_key(app), lane_rows(app)) == ("L03", "L03", before)
            assert (app.fleet.filter_text, app.fleet.sort) == ("a", SortMode.LANE)
            assert bar(app).field.value == "/hint keep this draft" and bar(app).field.has_focus
        bar(app).clear()
        await press(pilot, "escape")
        await press(pilot, "slash")
        await type_line(pilot, "layout")  # alone: the other one
        await pilot.pause()
        assert app.layout == "simple" and columns(app, "lanes") == SIMPLE_COLUMNS
        assert "layout simple for this run" in status_line(app)

    drive(app, script, SIZE)


def test_the_lane_list_fits_its_columns_to_its_width_whenever_that_changes():
    """Not only when the fleet view asks for it: /layout gives the list its new width when the
    screen is next laid out, and on a busy machine that is after the fleet view's own fitting,
    which then fitted the old width. The board's pane is hidden here behind the fleet view's
    back, so only the table's own resize can fit the columns."""
    deck, app = three_lanes("deck")

    async def script(pilot):
        lanes = app.fleet.query_one("#lanes", DataTable)

        def fitted() -> tuple[int, int, int]:
            """The list's width, its last-action column's, and the cells its columns leave unused."""
            widths = {column.key.value: column.width for column in lanes.ordered_columns}
            return lanes.size.width, widths["last"], lanes.size.width - 1 - sum(widths.values()) - 2 * lanes.cell_padding * len(widths)

        narrow, last, spare = fitted()
        assert spare == 0 and columns(app, "lanes") == DECK_COLUMNS
        pane = app.fleet.query_one("#board-pane")
        pane.display = False
        await pilot.pause()
        wide = lanes.size.width
        assert wide > narrow and fitted() == (wide, last + wide - narrow, 0)  # the last action takes the room
        pane.display = True
        await pilot.pause()
        assert fitted() == (narrow, last, 0)
        for layout in ("simple", "deck"):
            app.run_command(f"/layout {layout}", None)
            await pilot.pause()
            assert fitted()[2] == 0 and (fitted()[0] > narrow) is (layout == "simple"), layout

    drive(app, script, SIZE)


def test_layout_refuses_any_other_word_and_says_where_to_keep_a_layout():
    deck, app = three_lanes("simple", config_path="/somewhere/config.toml")

    async def script(pilot):
        for word in ("wide", "full", "compact", "simple deck"):
            app.run_command(f"/layout {word}", None)
            await pilot.pause()
            assert_warning(app, "/layout takes simple or deck")
            assert app.layout == "simple" and columns(app, "lanes") == SIMPLE_COLUMNS
        app.run_command("/layout DECK", None)
        await pilot.pause()
        assert app.layout == "deck"
        assert 'layout deck for this run. To keep it: layout = "deck" under [console] in /somewhere/config.toml' in status_line(app)

    drive(app, script, SIZE)


PLAYERS_CONFIG = "/home/player/.config/flightdeck/config.toml"  # no such file: only its name is said
ANSWERS = (  # (the board is a platform's, typed, the status line's whole text)
    (False, "/theme nord", f'theme nord for this run. To keep it: theme = "nord" under [console] in {PLAYERS_CONFIG}'),
    (False, "/layout deck", f'layout deck for this run. To keep it: layout = "deck" under [console] in {PLAYERS_CONFIG}'),
    (False, "/layout simple", f'layout simple for this run. To keep it: layout = "simple" under [console] in {PLAYERS_CONFIG}'),
    (False, "/theme nope", "/theme names no theme: built in are flightdeck, light, nord, gruvbox, dracula; your own is NAME.toml in "
                           "/home/player/.config/flightdeck/themes"),
    (True, "/new", "/new adds a challenge to a board you fill yourself; this board comes from the platform"),
)


@pytest.mark.parametrize("size", [(80, 24), (66, 24), (120, 36)], ids=["80x24", "66x24", "120x36"])
@pytest.mark.parametrize("platform, typed, said", ANSWERS, ids=[typed for _, typed, _ in ANSWERS])
def test_an_answer_too_long_for_one_row_of_the_status_line_goes_on_in_the_next(size, platform, typed, said):
    """What a command answers is read whole on an 80-column terminal: the part that matters
    (the config file to change, where an own theme goes) is at its end."""
    from pathlib import Path

    deck, app = console(by_hand=not platform, layout="deck" if typed == "/layout simple" else "simple", config_path=PLAYERS_CONFIG,
                        themes_folder=Path(PLAYERS_CONFIG).parent / "themes")
    release(deck, "alpha", "beta")

    async def script(pilot):
        one_row = app.fleet.query_one("#status").size.width
        assert app.fleet.query_one("#status").size.height == 1 and len(lane_rows(app)) == 2
        await press(pilot, "slash")
        await type_line(pilot, typed[1:])
        await pilot.pause()
        shown = " ".join(status_line(app).split())
        assert shown == f"● {said}", shown
        rows = app.fleet.query_one("#status").size.height
        assert (rows == 1) is (len(f"● {said}") <= one_row) and rows <= 3, (rows, one_row)  # one row, unless it needs more
        assert footer_line(app).strip().endswith("q quit") and bar(app).region.bottom == app.size.height - 1  # nothing pushed off

    drive(app, script, size)


def test_a_long_answer_reads_whole_in_a_lanes_own_view_too():
    deck, app = three_lanes("simple", config_path=PLAYERS_CONFIG)

    async def script(pilot):
        screen = await open_focus(pilot, app, "L01")
        assert screen.query_one("#status").size.height == 1
        await press(pilot, "slash")
        await type_line(pilot, "layout deck")
        await pilot.pause()
        said = f'layout deck for this run. To keep it: layout = "deck" under [console] in {PLAYERS_CONFIG}'
        assert " ".join(status_line(app).split()) == f"● {said}"
        assert screen.query_one("#status").size.height == 2 and screen.query_one("#keys").region.bottom == app.size.height

    drive(app, script, (80, 24))


def test_on_a_narrow_terminal_layout_says_the_compact_layout_shows_and_it_does():
    deck, app = three_lanes("simple")

    async def script(pilot):
        compact = columns(app, "lanes")
        assert app.fleet.compact and compact == [key for key, *_ in views.COMPACT_LANE_COLUMNS]
        app.run_command("/layout deck", None)
        await pilot.pause()
        await pilot.pause()
        said = app._status[0]
        assert said == "layout deck for this run (this console has no config file); this terminal is narrow, so the compact layout shows"
        assert app.layout == "deck" and columns(app, "lanes") == compact and app.fleet.board_hidden
        assert footer_line(app).strip().startswith("a yes  d no")  # the compact key line, in both layouts
        await pilot.resize_terminal(*SIZE)
        await pilot.pause()
        await pilot.pause()
        assert columns(app, "lanes") == DECK_COLUMNS and not app.fleet.board_hidden  # the layout asked for, once there is room

    drive(app, script, (60, 30))


def test_an_app_is_built_in_the_deck_layout_unless_told_and_refuses_a_layout_it_has_not():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",)))
    assert FlightdeckApp(deck).layout == "deck" and FlightdeckApp(deck, layout="simple").layout == "simple"
    assert config.LAYOUTS == ("simple", "deck") and config.ConsoleConfig().layout == "simple"  # a run opens in simple
    with pytest.raises(ValueError, match="layout must be one of simple, deck"):
        FlightdeckApp(deck, layout="full")
    with pytest.raises(ValueError, match="layout must be one of simple, deck"):
        FlightdeckApp(deck).set_layout("wide")


# ---------------------------------------------------------------------- the simple layout: the key line and the why line

NO_LANE_BY_HAND = "/new add a challenge  ? help  q quit"
NO_LANE_PLATFORM = "? help  q quit"
HEALTHY = "enter open  / commands  ? help  q quit"
APPROVAL = "a approve  d decline  enter open  / commands  ? help  q quit"
COURSE_ALERT = "1-9 answer  x dismiss  enter open  / commands  ? help  q quit"


def test_the_simple_key_line_shows_the_keys_that_apply_to_the_selected_lane():
    deck, app = three_lanes("simple")

    async def script(pilot):
        for lane_id, line in (("L01", HEALTHY), ("L02", APPROVAL), ("L03", COURSE_ALERT)):
            app.fleet.select_lane(lane_id)
            await pilot.pause()
            assert footer_line(app).strip() == line, lane_id
        app.fleet.select_lane("L02")  # the cursor moves: the line follows it
        await press(pilot, "down")
        assert app.fleet.selected_lane != "L02" and footer_line(app).strip() in (HEALTHY, COURSE_ALERT)
        app.fleet.select_lane("L03")
        await press(pilot, "x")  # the alert is dismissed: its keys go
        assert not deck.lanes["L03"].needs_you and footer_line(app).strip() == HEALTHY
        deck.report("L03", TurnReport(turn=False, gave_up="stuck"))
        app.refresh_view()
        await pilot.pause()
        assert deck.lanes["L03"].finished and footer_line(app).strip() == HEALTHY  # a finished lane: open its transcript

    drive(app, script, SIZE)


@pytest.mark.parametrize("by_hand, line", [(True, NO_LANE_BY_HAND), (False, NO_LANE_PLATFORM)], ids=["by hand", "platform"])
def test_with_no_lane_the_simple_key_line_says_how_to_start(by_hand, line):
    deck, app = console(by_hand=by_hand, layout="simple")

    async def script(pilot):
        assert footer_line(app).strip() == line
        deck.release([Challenge("alpha", "Alpha", "misc", 100)], [])  # a challenge, and still no lane
        await pilot.pause()
        await pilot.pause()
        assert app.fleet.query_one("#main").display and footer_line(app).strip() == line
        if by_hand:  # the line's /new is a way in, like every key on it
            await pilot.click("#keys", offset=(2, 0))
            await pilot.pause()
            assert type(app.screen).__name__ == "NewChallengePrompt"

    drive(app, script, SIZE)


def test_a_key_the_simple_line_does_not_show_still_acts_and_help_lists_it():
    deck, app = three_lanes("simple")

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        assert "p pause" not in footer_line(app) and "k kill" not in footer_line(app)
        await press(pilot, "p")
        assert deck.lanes["L01"].state is LaneState.PAUSED
        await press(pilot, "p")
        assert deck.lanes["L01"].state is LaneState.RUNNING
        await press(pilot, "k")
        assert type(app.screen).__name__ == "KillPrompt"
        await press(pilot, "escape")
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen) and "Pause or resume the selected lane" in prompt_text(app)

    drive(app, script, SIZE)


def test_the_deck_layout_keeps_its_key_line_of_every_key():
    deck, app = three_lanes("deck")

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        line = footer_line(app)
        assert all(key in line for key in ("o open", "p pause", "k kill", "a approve", "d decline", "x dismiss"))

    drive(app, script, WIDE)


def test_the_simple_why_line_is_blank_for_a_lane_that_needs_nothing():
    deck, app = three_lanes("simple")

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        assert region_text(app, "#why").strip() == "" and app.fleet.query_one("#why").size.height == views.WHY_ROWS  # blank, and still there
        app.fleet.select_lane("L02")
        await pilot.pause()
        why = region_text(app, "#why")
        assert "L02 ▲ Flag found" in why and "submit flag{synthetic}" in why
        app.fleet.select_lane("L03")
        await pilot.pause()
        assert "L03 ▲ Ignores the hint: the description says SSTV" in region_text(app, "#why")
        app.run_command("/layout deck", None)
        app.fleet.select_lane("L01")
        await pilot.pause()
        assert "L01 plan: look inside" in region_text(app, "#why")  # the dashboard says what a calm lane is doing

    drive(app, script, SIZE)


SIMPLE_PAIRS = {f"{shown} {label}" for _, shown, label in fleet.SIMPLE_KEYS}


@pytest.mark.parametrize("size", [(65, 24), (80, 24), (100, 30), (120, 40), SIZE, WIDE], ids=["65x24", "80x24", "100x30", "120x40", "160x46", "190x46"])
def test_the_simple_key_line_fits_whole_at_every_size_whatever_the_lane(size):
    world = FakeWorld(scenarios.get("default"))  # team mode: claim acts, and is not on this line
    app = FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None, layout="simple")
    deck = world.deck

    async def script(pilot):
        await step_until(pilot, app, lambda: any(lane.pending for lane in deck.active_lanes())
                         and any(views.top_answerable(lane) and not lane.pending for lane in deck.active_lanes()),
                         "a lane waiting for a yes and one with an alert to answer", limit=200)
        seen = set()
        for lane in list(deck.lanes.values()):
            app.fleet.select_lane(lane.id)
            await pilot.pause()
            line = footer_line(app).strip()
            pairs = line.split("  ")
            assert cell_len(line) <= size[0] - 2 and "…" not in line, line
            assert set(pairs) <= SIMPLE_PAIRS and {"? help", "q quit", "/ commands", "enter open"} <= set(pairs), line
            if lane.pending is not None and not lane.finished:
                assert {"a approve", "d decline"} <= set(pairs), line
            seen.add(line)
        assert {APPROVAL, HEALTHY} <= seen and len(seen) >= 3  # an alert's line too

    drive(app, script, size)


# ---------------------------------------------------------------------- the simple layout: the focus view


def test_the_simple_focus_view_shows_a_part_only_when_it_has_something_in_it():
    deck, app = console(by_hand=True, layout="simple")
    release(deck, "alpha", "beta")
    deck.report("L01", TurnReport(action="file alpha.bin", plan="look inside", tokens=1200))

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        shown = lambda part: view.query_one(part).display  # noqa: E731
        assert not shown("#files-pane") and not shown("#others") and not shown("#now")
        text = screen_text(app)
        for filler in ("Nothing needs you on this lane", "No other lane needs you", "No files changed yet", "files changed"):
            assert filler not in text, filler
        title = title_of(app, "#talk-pane")
        assert "glm" in title and "turn 1" in title and "1k tok" in title and "idle" in title  # as in the dashboard
        assert footer_line(app).strip() == "esc lanes  / commands  /help all keys"
        app.run_command("/diff", "L01")
        await pilot.pause()
        assert "L01 has not changed any files yet" in status_line(app) and not shown("#files-pane")
        deck.report("L01", TurnReport(action="write solve.py", files=(FileChange("solve.py", "+++ b/solve.py\n+print(1)\n", status="added"),)))
        app.refresh_view()
        await pilot.pause()
        assert shown("#files-pane") and "solve.py" in region_text(app, "#files-pane")
        app.run_command("/diff", "L01")
        await pilot.pause()
        assert app.focused is not None and app.focused.id == "files" and "+print(1)" in region_text(app, "#files-pane")
        deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{synthetic}"))  # another lane needs the player
        app.refresh_view()
        await pilot.pause()
        assert shown("#others") and "L02 flag" in region_text(app, "#others") and not shown("#now")
        deck.report("L01", TurnReport(action="strings alpha.bin", alerts=(COURSE,)))  # and now this one
        app.refresh_view()
        await pilot.pause()
        assert shown("#now") and "needs you now" in region_text(app, "#now")
        assert footer_line(app).strip() == "1-9 answer  esc lanes  / commands  /help all keys"
        bar(app).field.focus()
        await press(pilot, "1")  # the answer the line promises, from the empty chat box
        assert deck.lanes["L01"].plan == "decode it as SSTV"
        assert footer_line(app).strip() == "esc lanes  / commands  /help all keys"

    drive(app, script, SIZE)


def test_a_lane_with_no_files_takes_the_focus_off_a_files_pane_that_goes():
    deck, app = console(by_hand=True, layout="simple")
    release(deck, "alpha", "beta")
    deck.report("L01", TurnReport(action="write solve.py", files=(FileChange("solve.py", "+++ b/solve.py\n+print(1)\n"),)))
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{synthetic}"))

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        app.run_command("/diff", "L01")
        await pilot.pause()
        assert app.focused.id == "files"
        await press(pilot, "ctrl+n")  # to L02, which changed no file
        assert view.lane_id == "L02" and not view.query_one("#files-pane").display
        assert app.focused is bar(app).field
        await press(pilot, "h", "i")
        assert bar(app).field.value == "hi"

    drive(app, script, SIZE)


def test_the_deck_focus_view_keeps_every_part_and_layout_switches_an_open_lane():
    deck, app = console(by_hand=True, layout="deck")
    release(deck, "alpha")

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        text = screen_text(app)
        assert view.query_one("#files-pane").display and view.query_one("#others").display
        assert "No files changed yet." in text and "No other lane needs you." in text and "Nothing needs you on this lane." in text
        assert footer_line(app).strip().startswith("esc fleet  enter send  / commands")
        app.run_command("/layout simple", "L01")
        await pilot.pause()
        assert isinstance(app.screen, FocusScreen) and not view.query_one("#files-pane").display and not view.query_one("#others").display
        assert footer_line(app).strip() == "esc lanes  / commands  /help all keys"
        app.run_command("/layout deck", "L01")
        await pilot.pause()
        assert view.query_one("#files-pane").display and footer_line(app).strip().startswith("esc fleet  enter send")

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the first lane a /new starts


def by_hand_console(layout: str = "simple", *, later: bool = False) -> tuple[Deck, FlightdeckApp, list]:
    """A console on an empty board whose /new releases the challenge as a run's does: at once,
    or with `later` only when the test calls what it puts in the list (a run that reads the
    challenge's images first says yes and releases it seconds later)."""
    held: list = []
    deck_box: list[Deck] = []

    async def adder(new) -> tuple[bool, str]:
        def go() -> None:
            release(deck_box[0], slug(new.name))

        if later:
            held.append(go)
        else:
            go()
        return True, f"added {new.name}"

    deck, app = console(by_hand=True, layout=layout, adder=adder)
    deck_box.append(deck)
    return deck, app, held


async def hand_over(pilot, app: FlightdeckApp, name: str) -> None:
    """/new NAME, then the form's own key to add it."""
    await press(pilot, "slash")
    await type_line(pilot, f"new {name}")
    assert type(app.screen).__name__ == "NewChallengePrompt"
    await press(pilot, "ctrl+s")
    for _ in range(20):  # the adder runs in a worker
        if type(app.screen).__name__ != "NewChallengePrompt":
            break
        await pilot.pause(0.01)
    await pilot.pause()
    await pilot.pause()


def test_the_first_lane_a_new_starts_opens_in_the_focus_view_and_the_second_does_not_move_the_player():
    deck, app, _ = by_hand_console("simple")

    async def script(pilot):
        await hand_over(pilot, app, "Alpha")
        assert list(deck.lanes) == ["L01"]
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == "L01"  # one lane: a list of one is no help
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)
        await hand_over(pilot, app, "Beta")
        assert list(deck.lanes) == ["L01", "L02"] and isinstance(app.screen, FleetScreen)  # the second: the player stays
        assert lane_rows(app) == ["L01", "L02"]

    drive(app, script, SIZE)


def test_the_first_lane_opens_when_it_starts_only_after_the_form_has_closed():
    deck, app, held = by_hand_console("simple", later=True)

    async def script(pilot):
        await hand_over(pilot, app, "Alpha")
        assert isinstance(app.screen, FleetScreen) and not deck.lanes  # the challenge is still being read
        held.pop()()  # now it is released, and its lane starts
        await pilot.pause()
        await pilot.pause()
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == "L01"

    drive(app, script, SIZE)


def test_a_player_who_turned_to_something_else_meanwhile_is_not_moved_to_the_first_lane():
    deck, app, held = by_hand_console("simple", later=True)

    async def script(pilot):
        await hand_over(pilot, app, "Alpha")
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen)
        held.pop()()
        await pilot.pause()
        await pilot.pause()
        assert list(deck.lanes) == ["L01"] and isinstance(app.screen, HelpScreen)
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)  # and not afterwards either: the moment has passed
        release(deck, "beta")
        await pilot.pause()
        await pilot.pause()
        assert isinstance(app.screen, FleetScreen)

    drive(app, script, SIZE)


def test_a_player_typing_in_the_command_bar_is_not_moved_to_the_first_lane():
    """What is being typed must not land in the lane's chat box, where plain text is a message
    to the lane."""
    deck, app, held = by_hand_console("simple", later=True)

    async def script(pilot):
        await hand_over(pilot, app, "Alpha")
        await press(pilot, "slash", *"sor")
        held.pop()()
        await pilot.pause()
        await pilot.pause()
        assert list(deck.lanes) == ["L01"] and isinstance(app.screen, FleetScreen)
        assert bar(app).field.has_focus and bar(app).field.value == "/sor"
        await press(pilot, "t", "enter", "enter")  # the menu fills in /sort, then it runs: here, on the lane list
        assert app.fleet.sort is SortMode.IDLE and not deck.lanes["L01"].hints

    drive(app, script, SIZE)


def test_the_deck_layout_and_a_platforms_board_never_open_a_lane_by_themselves():
    deck, app, _ = by_hand_console("deck")

    async def script(pilot):
        await hand_over(pilot, app, "Alpha")
        assert list(deck.lanes) == ["L01"] and isinstance(app.screen, FleetScreen)

    drive(app, script, SIZE)
    deck, app = console(by_hand=False, layout="simple")

    async def platform(pilot):
        await press(pilot, "slash")
        await type_line(pilot, "new Alpha")
        assert isinstance(app.screen, FleetScreen)  # no form: /new is not for this board
        assert_warning(app, "/new adds a challenge to a board you fill yourself")
        release(deck, "alpha")  # the platform's first challenge: its lane starts, and the player stays in the list
        await pilot.pause()
        await pilot.pause()
        assert list(deck.lanes) == ["L01"] and isinstance(app.screen, FleetScreen)

    drive(app, platform, SIZE)


# ---------------------------------------------------------------------- what doctor measures in the simple layout


@pytest.mark.parametrize("width", [40, 64, 65, 80, 99, 100, 200])
def test_the_simple_layout_never_has_the_board_left_out(width):
    fit = room.room(width, 30, max_lanes=4, containerized=True, layout="simple")
    assert fit.board is False and not any("the board" in part for part in fit.left_out())
    assert room.room(width, 30, max_lanes=4, containerized=True).board is (width < 100)  # the deck layout: under 100 columns


@pytest.mark.parametrize("size", [(50, 24), (64, 30), (65, 30), (72, 17), (80, 24), (85, 18), (86, 17), (86, 18), (120, 40)])
def test_what_doctor_says_the_simple_layout_leaves_out_is_what_the_console_leaves_out(size, monkeypatch):
    """room.room(layout="simple") against the console in that layout, on the busy run doctor
    measures with: the header's pieces in both views, the lane rows, and the key lines at their
    longest (a lane with an alert to answer and to dismiss)."""
    from test_console import four_lanes_and_one_finished, nothing

    columns_, lines = size
    fit = room.room(columns_, lines, max_lanes=4, containerized=True, layout="simple")
    assert fit.layout == "simple" and fit.compact is (columns_ <= 64)
    busy = room.busy_header(max_lanes=4, containerized=True)
    monkeypatch.setattr(views, "header_facts", lambda deck, mock="": busy)
    pieces = {name: text for name, rank, (text, *_) in views.header_pieces(busy, simple=True) if rank}  # what can drop
    if fit.compact:  # the compact header: no event's name, the queue in short; of what simple shows, its name can drop too
        assert set(pieces) == {"event", "queue"}
        pieces = {"event": pieces["event"], "flightdeck": "flightdeck"}
    deck = four_lanes_and_one_finished()
    deck.report("L02", TurnReport(action="strings c1", alerts=(COURSE,)))
    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=nothing, layout="simple")

    async def script(pilot):
        app.fleet.select_lane("L02")
        await pilot.pause()
        for view in ("fleet", "focus"):
            header = region_text(app, "#header")
            assert {name for name, text in pieces.items() if text not in header} == set(fit.header), (view, header)
            keys = region_text(app, "#keys").strip().split("  ")
            if view == "fleet":
                assert app.fleet.board_hidden and app.fleet.compact is fit.compact
                rows = [line for line in region_text(app, "#lanes").splitlines()[1:] if line.strip()]
                assert len(rows) == min(fit.rows, fit.needed)
                if fit.compact:  # the compact line, which has its own short labels: the keys it has not got
                    has = {pair.split(" ")[0] for pair in keys}
                    assert [f"{shown} {label}" for _, shown, label in fleet.SIMPLE_KEYS if shown not in has] == list(fit.fleet_keys), keys
                    assert list(fit.fleet_keys) == ["x dismiss", "enter open"]
                else:
                    whole = [f"{shown} {label}" for _, shown, label in fleet.SIMPLE_LONGEST]
                    assert [key for key in whole if key not in keys] == list(fit.fleet_keys), keys
                await open_focus(pilot, app, "L02")
            elif fit.compact:
                assert keys == [f"{key} {label}" for key, label in focus.COMPACT_KEY_LABELS]  # whole at this width
                assert list(fit.focus_keys) == ["/help all keys"]  # the one key of the simple line it has not got
            else:
                whole = [f"{key} {label}" for key, label in (focus.SIMPLE_ANSWER_LABEL, *focus.SIMPLE_KEY_LABELS)]
                assert [key for key in whole if key not in keys] == list(fit.focus_keys), keys
        assert (fit.left_out() == []) is (columns_ >= fit.columns and lines >= fit.lines)

    drive(app, script, size=size)
    assert (fit.columns, fit.lines) == (86, 18)  # an event name of 20 characters, four lanes


def test_doctor_measures_the_terminal_in_the_layout_the_config_opens(tmp_path, monkeypatch):
    from ctf_flightdeck.setup import Answers, write_config

    monkeypatch.setenv("PATH", str(tmp_path))  # no docker here: doctor runs nothing

    def line(layout: str | None, size: tuple[int, int]) -> list[str]:
        path = tmp_path / f"{layout}.toml"
        if not path.exists():
            write_config(Answers("http://127.0.0.1:9/v1", "", ("local/model",), "docker"), path)
            if layout is not None:
                path.write_text(path.read_text() + f'\n[console]\nlayout = "{layout}"\n')
        monkeypatch.setattr(os, "get_terminal_size", lambda *args: os.terminal_size(size))
        lines = CliRunner().invoke(cli.app, ["doctor", "--config", str(path)]).stdout.splitlines()
        at = next(i for i, text in enumerate(lines) if text[5:].startswith("terminal: "))
        return lines[at:at + 2] if lines[at].startswith("warn") else lines[at:at + 1]

    assert line(None, (100, 30)) == line("simple", (100, 30)) == [
        "ok   terminal: 100x30: on a busy run the console shows the whole header, its key line and a row for each of your 4 lanes"
    ]
    assert line(None, (80, 24)) == [
        "warn terminal: 80x24: on a busy run the console leaves out the event's name in the header",
        "     fix: from 86x18 it leaves none of this out, with an event name of up to 20 characters (a column more for "
        "each character more); the console still works smaller",
    ]
    assert line("deck", (100, 30))[0].startswith("warn terminal: 100x30: on a busy run the console leaves out dollars, tokens,")
    narrow = line(None, (56, 40))[0]
    assert narrow == (
        "warn terminal: 56x40: the compact layout, for 64 columns or fewer (what needs you and why, the one-key answers, "
        "each lane's state and cost); on a busy run the console leaves out the event's name and the flightdeck name in the "
        "header; each lane's last action in the lane list (the lane's own view has it) and the files pane of that view (the "
        "simple layout starts at 65 columns); x dismiss and enter open on the fleet view's key line (? lists every key); "
        "/help all keys on the focus view's key line"
    )


# ---------------------------------------------------------------------- the command, and what a run opens in


def test_layout_is_a_command_that_acts_on_no_lane_listed_beside_the_runs_other_settings():
    parsed = parse("/layout deck")
    assert (parsed.command.name, parsed.lane, parsed.arg) == ("layout", None, "deck")
    assert parse("/layout").arg == "" and not needs_lane(parse("/layout")) and not needs_lane(parsed)
    assert [c.text for c in complete("/la")] == ["/layout "]
    names = [c.name for c in COMMANDS]
    assert names.index("layout") == names.index("theme") + 1 == names.index("config") + 2
    assert BY_NAME["layout"].args == "[simple|deck]"
    assert BY_NAME["layout"].help == "simple: the lanes and what needs you; deck: the board and every column; alone: the other one"


def test_help_and_the_command_menu_list_layout():
    deck, app = three_lanes("simple")
    listed = "/layout [simple|deck] simple: the lanes and what needs you; deck: the board and every column; alone: the other one"

    async def script(pilot):
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen) and listed in prompt_text(app)
        await press(pilot, "escape")
        await press(pilot, "slash", *"la")
        assert bar(app).menu_open and listed in " ".join(region_text(app, "#bar").split())
        await press(pilot, "tab")
        assert bar(app).field.value == "/layout "

    drive(app, script, size=(160, 120))


def test_the_mock_opens_in_the_layout_the_config_names_and_in_simple_without_one(tmp_path, monkeypatch):
    built = {}
    monkeypatch.setattr(FlightdeckApp, "run", lambda self, **kw: built.update(layout=self.layout))
    monkeypatch.setenv("HOME", str(tmp_path))  # no config of the player's
    monkeypatch.delenv("FLIGHTDECK_CONFIG", raising=False)
    assert CliRunner().invoke(cli.app, ["mock"]).exit_code == 0 and built == {"layout": "simple"}
    for layout in ("deck", "simple"):
        path = tmp_path / f"{layout}.toml"
        path.write_text(f'[console]\nlayout = "{layout}"\n')
        monkeypatch.setenv("FLIGHTDECK_CONFIG", str(path))
        assert CliRunner().invoke(cli.app, ["mock"]).exit_code == 0 and built == {"layout": layout}
    path.write_text('[console]\nlayout = "full"\n')
    result = CliRunner().invoke(cli.app, ["mock"])
    assert result.exit_code == 2 and 'console.layout must be "simple" or "deck"' in result.output


def test_a_run_opens_its_console_in_the_configs_layout(tmp_path):
    import asyncio

    from ctf_flightdeck.run import prepare_run
    from fake_model import FakeModelServer
    from test_addchallenge import options

    async def main() -> None:
        with FakeModelServer([]) as server:
            for layout in (None, "deck"):
                folder = tmp_path / str(layout)
                folder.mkdir()
                opts = options(folder, server)
                if layout is not None:
                    path = opts.config
                    path.write_text(path.read_text() + f'\n[console]\nlayout = "{layout}"\n')
                run = prepare_run(opts)
                try:
                    assert run.app(refresh_seconds=None).layout == (layout or "simple")
                finally:
                    await run.shutdown()
                    run.close()

    asyncio.run(main())
