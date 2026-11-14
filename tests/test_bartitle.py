"""The command bar names the lane it talks to (P64): the title on its border, in the lane list
and in a lane's view.

`to L04 · Ticket Desk` for the lane the keys point at or the lane a command names, `no lane`
when there is none, `the run` while a command that takes no lane is typed. The title is read
off the screen as a player sees it (test_console's helpers rebuild the terminal from the SVG
export), and each test also sends what was typed, to see that it went where the title said.

Decks are synthetic (test_layout's: a driver that does no work); nothing needs a model or a
network.
"""

from __future__ import annotations

import pytest
from rich.cells import cell_len

from ctf_flightdeck import themes
from ctf_flightdeck.console import fleet, theme, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.commands import COMMANDS, Aim, goes_to
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.widgets import BAR
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import QueueEntry
from ctf_flightdeck.core.model import Challenge, ChallengeStatus, DeckConfig, LaneState
from test_console import (
    OSC,
    assert_warning,
    bar,
    color_of,
    cursor_key,
    drive,
    open_focus,
    osc,
    press,
    quiet_deck,
    region_text,
    shown,
    terminal_frame,
    type_line,
)
from test_layout import LAYOUTS, SIZE, console, release, three_lanes

PHONE = (60, 40)  # the compact layout


def title_row(app) -> str:
    """The top row of the bar's box, as drawn: its border with the title on it."""
    return region_text(app, "#bar-input").splitlines()[0]


def title(app) -> str:
    """The title on the bar's border, as drawn: the frame around it left out."""
    row = title_row(app)
    assert row.startswith("╭─ ") and row.endswith("╮"), row
    return row.strip("╭╮─ ")


def hints(deck, lane_id: str) -> list[str]:
    return list(deck.lanes[lane_id].hints)


# ---------------------------------------------------------------------- what is typed, and where it goes


@pytest.mark.parametrize("typed, aim", [
    ("", Aim()),  # an empty bar: enter opens the lane the keys point at
    ("try sstv", Aim()),  # a message
    ("/", Aim()),
    ("/hi", Aim()),  # not a command yet
    ("/hint", Aim()),
    ("/hint look at the header", Aim()),
    ("/kill L07", Aim(lane="L07")),
    ("/kill l7 park", Aim(lane="L07")),
    ("/hint L2 look again", Aim(lane="L02")),
    ("/open L3", Aim(lane="L03")),
    ("/note", Aim(run=True)),
    ("/note the flag format is flag{...}", Aim(run=True)),
    ("/config", Aim(run=True)),
    ("/settings", Aim(run=True)),  # an alias, whole
    ("/queue", Aim(run=True)),
    ("/queue L02", Aim(run=True)),  # a word that looks like a lane names none to a command that takes none
    ("/q", Aim(run=True)),
    ("/approve", Aim()),
    ("/approve L02", Aim(lane="L02")),
    ("/approve all", Aim(run=True)),  # over every lane, so no one lane's
    ("/approve 2", Aim()),  # refused: it goes nowhere, and is never read as L02
    ("/approve all L02", Aim()),
    ("/over", Aim()),  # the menu lists /takeover; enter would refuse it
    ("/nope L02", Aim()),
])
def test_goes_to_reads_what_is_typed_as_enter_would(typed, aim):
    assert goes_to(typed) == aim


def test_every_command_that_takes_no_lane_is_the_runs_and_every_lane_command_is_not():
    no_lane = {command.name for command in COMMANDS if goes_to(f"/{command.name}").run}
    assert {"note", "config", "queue", "new", "theme", "layout", "help", "quit"} <= no_lane
    assert not no_lane & {"hint", "redirect", "fork", "kill", "approve", "decline", "dismiss", "escalate", "pause", "takeover", "diff", "copy", "open"}
    assert all(goes_to(f"/{command.name}") == Aim() for command in COMMANDS if command.name not in no_lane)


def test_the_title_names_the_lane_no_lane_or_the_run():
    deck, app = three_lanes()
    lane = deck.lanes["L01"]
    assert views.bar_title(deck, "", lane).plain == "to L01 · Alpha"
    assert views.bar_title(deck, "a message", lane).plain == "to L01 · Alpha"
    assert views.bar_title(deck, "/hint", lane).plain == "to L01 · Alpha"
    assert views.bar_title(deck, "/pause l3", lane).plain == "to L03 · Gamma"  # the lane the command names, not the one selected
    assert views.bar_title(deck, "/pause L09", lane).plain == "no lane L09"
    assert views.bar_title(deck, "/note x", lane).plain == "the run" == views.BAR_RUN
    assert views.bar_title(deck, "", None).plain == "no lane" == views.BAR_NO_LANE
    assert views.bar_title(deck, "/pause", None).plain == "no lane"
    assert views.bar_title(deck, "/pause L02", None).plain == "to L02 · Beta"  # a command that names its lane needs none selected
    assert views.bar_title(deck, "/config", None).plain == "the run"


def test_the_lane_is_what_the_title_shows_strongest_and_a_theme_colours_it():
    deck, app = three_lanes()
    try:
        for name in ("flightdeck", "light"):
            theme.use(themes.load(name, None))
            named = views.bar_title(deck, "", deck.lanes["L01"])
            styles = {named.plain[span.start:span.end]: str(span.style) for span in named.spans}
            assert str(named.style) == theme.MUTED  # "to", and whatever no span colours
            assert styles == {"L01": f"bold {theme.TEXT}", " · ": theme.MUTED, "Alpha": theme.TEXT}
            assert str(views.bar_title(deck, "/note", None).style) == theme.MUTED
            assert str(views.bar_title(deck, "", None).style) == theme.MUTED
    finally:
        theme.use(themes.DEFAULT)


# ---------------------------------------------------------------------- the lane list


@pytest.mark.parametrize("layout", LAYOUTS)
def test_the_bars_title_follows_the_cursor_and_a_message_goes_to_the_lane_it_names(layout):
    deck, app = three_lanes(layout)

    async def script(pilot):
        assert cursor_key(app) == "L02" and title(app) == "to L02 · Beta"
        assert bar(app).field.placeholder == BAR == "a message, or / for commands"
        assert BAR in region_text(app, "#bar-input")
        await press(pilot, "down")
        assert cursor_key(app) == "L03" and title(app) == "to L03 · Gamma"
        await press(pilot, "down")
        assert cursor_key(app) == "L01" and title(app) == "to L01 · Alpha"
        await press(pilot, "tab")  # into the bar: the title stays on the lane, and the placeholder is gone at the first key
        await press(pilot, *"look inside the archive")
        assert BAR not in region_text(app, "#bar-input") and title(app) == "to L01 · Alpha"
        await press(pilot, "enter")
        assert hints(deck, "L01") == ["look inside the archive"] and not hints(deck, "L02") and not hints(deck, "L03")
        await press(pilot, "up")
        assert title(app) == "to L03 · Gamma"

    drive(app, script, SIZE)


def test_the_title_reads_the_run_while_a_command_that_takes_no_lane_is_typed():
    deck, app = three_lanes()

    async def script(pilot):
        await press(pilot, "slash")
        assert title(app) == "to L02 · Beta"  # nothing named yet
        await press(pilot, *"no")
        assert title(app) == "to L02 · Beta"  # /no is not a command: the menu lists /note, enter would only fill it in
        await press(pilot, *"te")
        assert title(app) == "the run"
        await press(pilot, *" read the handout first")
        assert title(app) == "the run"
        await press(pilot, "enter")
        assert title(app) == "to L02 · Beta" and bar(app).field.value == ""
        assert deck.standing == ["read the handout first"]  # a note for every lane, not a message to the selected one
        for typed in ("/config", "/queue", "/settings", "/approve all"):
            await press(pilot, *typed)
            assert title(app) == "the run", typed
            await press(pilot, "escape", "escape")  # the first closes a menu that is open, the next empties the bar
            assert title(app) == "to L02 · Beta" and bar(app).field.value == ""

    drive(app, script, SIZE)


def test_a_command_that_names_a_lane_shows_that_lane_and_acts_on_it():
    deck, app = three_lanes()

    async def script(pilot):
        assert cursor_key(app) == "L02"
        await press(pilot, *"/pause")
        assert title(app) == "to L02 · Beta"
        await press(pilot, *" l")
        assert title(app) == "to L02 · Beta"  # `l` names no lane yet
        await press(pilot, "1")
        assert title(app) == "to L01 · Alpha"
        await press(pilot, "enter")
        assert deck.lanes["L01"].state is LaneState.PAUSED and deck.lanes["L02"].state is not LaneState.PAUSED
        assert title(app) == "to L02 · Beta" and cursor_key(app) == "L02"  # the selection did not move
        await press(pilot, *"/pause L9")
        assert title(app) == "no lane L09"
        await press(pilot, "enter")
        assert_warning(app, "No lane L09")

    drive(app, script, SIZE)


def test_on_the_board_the_title_names_a_challenges_only_lane_and_says_no_lane_for_none_or_several():
    deck, app = three_lanes("deck")
    release(deck, "delta")  # four lanes at most: delta gets one
    assert deck.apply(iv.Kill("L04", requeue=False)).ok and deck.challenges["delta"].status is ChallengeStatus.PARKED

    async def script(pilot):
        await pilot.pause()
        app.fleet.select_challenge("alpha")
        await pilot.pause()
        assert app.fleet.board_focused and title(app) == "to L01 · Alpha"
        app.fleet.select_challenge("delta")  # parked: no lane works it
        await pilot.pause()
        assert title(app) == "no lane"
        await press(pilot, "shift+tab")  # from the board into the bar: the player is still on the board's challenge
        assert app.focused is bar(app).field and title(app) == "no lane"
        await press(pilot, *"anyone there", "enter")
        assert_warning(app, "No lane is working Delta")
        assert not any(hints(deck, lane_id) for lane_id in deck.lanes)
        assert deck.apply(iv.Fork("L01")).ok and len(deck.lanes_on("alpha")) == 2
        app.fleet.select_challenge("alpha")
        await pilot.pause()
        assert title(app) == "no lane"  # two lanes work it: the bar cannot say which
        await press(pilot, "tab")  # on to the lane list
        assert not app.fleet.board_focused and title(app) == f"to {app.fleet.selected_lane} · " + deck.challenges[deck.lanes[app.fleet.selected_lane].challenge_id].name

    drive(app, script, SIZE)


def test_a_filter_that_hides_the_selected_lane_leaves_the_bar_with_no_lane():
    deck, app = three_lanes()

    async def script(pilot):
        assert title(app) == "to L02 · Beta"
        await press(pilot, *"/filter gamma", "enter")
        assert title(app) == "no lane"  # L02 is still the selection, and the filter hides it
        await press(pilot, "tab", *"hello", "enter")
        assert_warning(app, "L02 is hidden by the filter")
        assert not hints(deck, "L02")
        await press(pilot, "escape")
        assert app.fleet.filter_text == "" and title(app) == "to L02 · Beta"

    drive(app, script, SIZE)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_an_empty_board_has_no_lane_and_its_own_placeholder_until_a_lane_starts(layout):
    deck, app = console(by_hand=True, layout=layout)

    async def script(pilot):
        assert title(app) == "no lane" and bar(app).field.placeholder == fleet.BAR_EMPTY_BY_HAND
        await press(pilot, *"/new")
        assert title(app) == "the run"
        await press(pilot, "escape", "escape")
        release(deck, "alpha")
        await pilot.pause()
        await pilot.pause()
        assert title(app) == "to L01 · Alpha" and bar(app).field.placeholder == BAR

    drive(app, script, SIZE)


def test_the_title_keeps_to_the_bars_width_and_a_long_name_is_cut():
    deck, app = console(by_hand=True, layout="simple")
    name = "A challenge whose name goes on and on " * 4
    deck.release([Challenge("long", name, "misc", 100)], [QueueEntry("long", "glm")])

    async def script(pilot):
        await pilot.pause()
        row = title_row(app)
        assert cell_len(row) == app.screen.query_one("#bar-input").region.width  # the box is as wide as before
        assert row.startswith("╭─ to L01 · A challenge whose name goes on") and row.endswith("╮") and "…" in row
        assert isinstance(app.screen, FleetScreen)

    drive(app, script, PHONE)


def test_a_challenges_name_in_the_title_is_made_safe_and_is_never_markup():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",)))
    deck.release(
        [Challenge("evil", "Evil " + osc("nm") + " two\nrows", "misc", 100), Challenge("mark", "[@click=app.quit]x[/] [b]bold[/b]", "misc", 100)],
        [QueueEntry("evil", "glm"), QueueEntry("mark", "glm")],
    )
    app = FlightdeckApp(deck, refresh_seconds=None, layout="simple")

    async def script(pilot):
        for view in ("the lane list", "the lane's view"):
            assert OSC not in terminal_frame(app), view
            assert title(app) == f"to L01 · Evil {shown('nm')}^[\\ two ⏎ rows", view  # one row: the newline is folded
            if view == "the lane list":
                await press(pilot, "down")
            else:
                await type_line(pilot, "/open L02")
            assert title(app) == "to L02 · [@click=app.quit]x[/] [b]bold[/b]", view  # shown as it is: no link, no bold
            if view == "the lane list":
                await press(pilot, "up")
                await open_focus(pilot, app, "L01")
        assert isinstance(app.screen, FocusScreen)

    drive(app, script, SIZE)


def test_the_title_takes_the_themes_colours_when_the_theme_changes():
    deck, app = three_lanes()

    async def script(pilot):
        row = app.screen.query_one("#bar-input").region.y
        for name in ("light", "nord"):  # set as /theme sets it, with nothing typed: the same words in other colours
            was = (theme.MUTED, theme.TEXT)
            assert color_of(app, "to", row) == was[0].lower() and color_of(app, "L02", row) == was[1].lower()
            app.set_palette(themes.load(name, None))
            await pilot.pause()
            assert theme.MUTED != was[0] and theme.TEXT != was[1]
            assert color_of(app, "to", row) == theme.MUTED.lower() and color_of(app, "L02", row) == theme.TEXT.lower()
        app.fleet.set_filter("gamma")  # hides the selected lane
        await pilot.pause()
        assert title(app) == "no lane" and color_of(app, "no lane", row) == theme.MUTED.lower()
        was = theme.MUTED
        app.set_palette(themes.DEFAULT)
        await pilot.pause()
        assert theme.MUTED != was and color_of(app, "no lane", row) == theme.MUTED.lower()

    try:
        drive(app, script, SIZE)
    finally:
        theme.use(themes.DEFAULT)


# ---------------------------------------------------------------------- a lane's view


@pytest.mark.parametrize("layout, size", [("simple", SIZE), ("deck", SIZE), ("simple", PHONE)], ids=["simple", "deck", "compact"])
def test_in_a_lanes_view_the_chat_box_names_that_lane_and_follows_the_view(layout, size):
    deck, app = three_lanes(layout)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert title(app) == "to L01 · Alpha" and bar(app).field.placeholder == BAR
        await press(pilot, *"try the second header", "enter")
        assert hints(deck, "L01") == ["try the second header"]
        await press(pilot, "ctrl+n")  # the next lane that needs the player
        assert app.screen.lane_id == "L02" and title(app) == "to L02 · Beta"
        await type_line(pilot, "/open L03")
        assert app.screen.lane_id == "L03" and title(app) == "to L03 · Gamma"
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen) and title(app) == "to L03 · Gamma"  # the list comes back on that lane

    drive(app, script, size)


def test_in_a_lanes_view_a_command_names_the_run_or_another_lane_while_it_is_typed():
    deck, app = three_lanes()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, *"/details")
        assert title(app) == "the run"
        await press(pilot, "escape")  # closes the menu; the text stays, and so does the title
        assert bar(app).field.value == "/details" and title(app) == "the run"
        await press(pilot, *(["backspace"] * len("/details")))
        assert title(app) == "to L01 · Alpha"
        await press(pilot, *"/pause L03")
        assert title(app) == "to L03 · Gamma" and app.screen.lane_id == "L01"
        await press(pilot, "enter")
        assert deck.lanes["L03"].state is LaneState.PAUSED and deck.lanes["L01"].state is not LaneState.PAUSED
        assert title(app) == "to L01 · Alpha" and app.screen.lane_id == "L01"

    drive(app, script, SIZE)


def test_an_unsent_message_and_the_title_each_stay_with_their_lane():
    deck, app = three_lanes()

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, *"/note for every")
        assert title(app) == "the run"
        app.screen.show_lane("L02")  # the draft stays behind with L01
        await pilot.pause()
        assert bar(app).field.value == "" and title(app) == "to L02 · Beta"
        app.screen.show_lane("L01")
        await pilot.pause()
        assert bar(app).field.value == "/note for every" and title(app) == "the run"

    drive(app, script, SIZE)
