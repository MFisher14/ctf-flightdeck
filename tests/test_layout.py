"""The calm console: what both layouts say on an empty board and in the command menu, and the
`simple` layout (the default: one list of lanes, a short header, only the keys that apply now)
beside `deck` (the dashboard as it was).

Read from the screen as a player sees it (test_console's helpers rebuild the terminal from the
SVG export). Decks here are synthetic: a driver that does no work, and lanes whose turns the
test reports itself. Nothing needs a model or a network.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from textual.widgets import DataTable

from ctf_flightdeck.console import fleet, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.commands import COMMANDS
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig, LaneState
from test_console import bar, drive, lane_rows, press, quiet_deck, region_text, screen_text, status_line

SIZE = (160, 46)
LAYOUTS = ("deck",)


async def added(new) -> tuple[bool, str]:
    """A stand-in for a run's adder (/new): the board is one the player fills."""
    return True, "added"


def console(*, by_hand: bool, layout: str = "deck", **kw) -> tuple[Deck, FlightdeckApp]:
    """A console on an empty board: one the player fills (`by_hand`), or one a platform fills."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=4))
    return deck, FlightdeckApp(deck, refresh_seconds=3600.0, adder=added if by_hand else None, **kw)  # the timer is on; it never fires here


def release(deck: Deck, *ids: str) -> None:
    deck.release([Challenge(cid, cid.title(), "misc", 100) for cid in ids], [QueueEntry(cid, "glm") for cid in ids])


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
