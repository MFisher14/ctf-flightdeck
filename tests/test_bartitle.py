"""The command bar names the lane it talks to (P64): the title on its border, in the lane list
and in a lane's view.

`to L04 · Ticket Desk` for the lane the keys point at or the lane a command names, `no lane`
when there is none, `the run` while a command that takes no lane is typed, and `L04 has
finished` or `L04 takes no more turns` for a lane that would refuse what is typed. The title
is read off the screen as a player sees it (test_console's helpers rebuild the terminal from
the SVG export), and each test also sends what was typed, to see that it went where the title
said.

Decks are synthetic (test_layout's: a driver that does no work); nothing needs a model or a
network.
"""

from __future__ import annotations

import pytest
from rich.cells import cell_len
from textual import events

from ctf_flightdeck import themes
from ctf_flightdeck.console import fleet, theme, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.commands import COMMANDS, Aim, Ask, goes_to
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.widgets import BAR
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, ChallengeStatus, DeckConfig, LaneState
from ctf_flightdeck.mock.world import ManualClock
from test_console import (
    OSC,
    QuietDriver,
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
    send,
    shown,
    status_line,
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
    ("/kill L07", Aim(lane="L07", ask=Ask.ACT)),
    ("/kill l7 park", Aim(lane="L07", ask=Ask.ACT)),
    ("/hint L2 look again", Aim(lane="L02")),  # read on a turn, as a message is
    ("/escalate", Aim()),
    ("/open L3", Aim(lane="L03", ask=Ask.READ)),
    ("/copy all", Aim(ask=Ask.READ)),
    ("/fork", Aim(ask=Ask.ACT)),  # its prompt
    ("/fork L2 try the other port", Aim(lane="L02", ask=Ask.FORK)),
    ("/note", Aim(run=True)),
    ("/note the flag format is flag{...}", Aim(run=True)),
    ("/config", Aim(run=True)),
    ("/settings", Aim(run=True)),  # an alias, whole
    ("/queue", Aim(run=True)),
    ("/queue L02", Aim(run=True)),  # a word that looks like a lane names none to a command that takes none
    ("/q", Aim(run=True)),
    ("/approve", Aim(ask=Ask.ACT)),
    ("/approve L02", Aim(lane="L02", ask=Ask.ACT)),
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
    to_a_lane = {command.name: goes_to(f"/{command.name}") for command in COMMANDS if command.name not in no_lane}
    assert all(not aim.run and aim.lane is None for aim in to_a_lane.values())
    assert {name: aim.ask for name, aim in to_a_lane.items()} == {  # what each asks of its lane, with nothing after its name
        "hint": Ask.TURN, "redirect": Ask.TURN, "escalate": Ask.TURN,
        "fork": Ask.ACT, "kill": Ask.ACT, "approve": Ask.ACT, "decline": Ask.ACT, "dismiss": Ask.ACT, "pause": Ask.ACT, "takeover": Ask.ACT,
        "diff": Ask.READ, "copy": Ask.READ, "open": Ask.READ,
    }


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
        await press(pilot, *"/filter zzz", "enter")
        assert title(app) == "no lane"  # L02 is still the selection, and the filter hides it with every lane (P96)
        await press(pilot, "tab", *"hello", "enter")
        assert_warning(app, "L02 is hidden by the filter")
        assert not hints(deck, "L02")
        await press(pilot, "escape")
        assert app.fleet.filter_text == "" and title(app) == "to L02 · Beta"

    drive(app, script, SIZE)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_filter_that_hides_the_selected_lane_takes_its_answers_off_the_why_line(layout):
    """The why line offered the hidden lane's answers (`1 submit flag{synthetic}`) under a bar
    that says no lane, and its keys refused them: it says the lane is hidden instead."""
    from test_console import region_text

    deck, app = three_lanes(layout)

    async def script(pilot):
        assert "submit flag{synthetic}" in region_text(app, "#why")  # L02's flag waits for a yes
        app.fleet.set_filter("zzz")  # no lane shown: with one, its row takes the selection (P96)
        await pilot.pause()
        why = " ".join(region_text(app, "#why").split())
        assert "flag{synthetic}" not in why and "L02 is hidden by the filter: esc clears it" in why
        app.fleet.set_filter("")
        await pilot.pause()
        assert "submit flag{synthetic}" in region_text(app, "#why")

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
        app.fleet.set_filter("zzz")  # hides the selected lane, and every other
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


# ---------------------------------------------------------------------- a lane that would refuse what is typed

FINISHED = "L01 has finished"
NO_TURNS = "L02 takes no more turns"
ARGS = {"hint": "look again", "redirect": "a new plan", "fork": "another way", "kill": "park", "diff": "alpha.bin", "copy": "command", "open": "L01"}


def lane_commands() -> list[str]:
    """Every lane command as it can be typed: alone, and with an argument where it takes one
    (/approve's only word is `all`, which is the run's)."""
    takes_words = {command.name for command in COMMANDS if command.lane and command.args}
    assert takes_words - {"approve"} == set(ARGS)  # a new command with an argument gets a line in ARGS
    typed = []
    for command in COMMANDS:
        if command.lane:
            typed.append(f"/{command.name}")
            if command.name in ARGS:
                typed.append(f"/{command.name} {ARGS[command.name]}")
    return typed


def ended_lanes(**kw) -> tuple[Deck, FlightdeckApp]:
    """A console whose platform takes every flag, with L01 solved, L02 killed and L03 at work."""
    deck = Deck(DeckConfig(event="ev", models=("glm",), max_lanes=4), QuietDriver(), ManualClock(1000.0), lambda challenge_id, flag: True)
    app = FlightdeckApp(deck, refresh_seconds=None, layout="simple", copier=lambda text: "", **kw)  # no clipboard but the test's
    release(deck, "alpha", "beta", "gamma")
    deck.report("L01", TurnReport(action="cat flag.txt", flag="flag{synthetic}"))
    assert deck.apply(iv.Approve("L01")).ok and deck.lanes["L01"].state is LaneState.SOLVED
    deck.report("L02", TurnReport(action="file beta.bin", output="data"))
    assert deck.apply(iv.Kill("L02", requeue=False)).ok and deck.lanes["L02"].state is LaneState.KILLED
    return deck, app


def test_the_title_names_a_lane_that_has_ended_only_for_what_it_still_takes():
    deck, app = ended_lanes()
    solved, killed, at_work = (deck.lanes[lane_id] for lane_id in ("L01", "L02", "L03"))
    for typed in ("", "a message", "/hint", "/hint look again", "/redirect a new plan", "/kill", "/kill park", "/pause", "/escalate",
                  "/approve", "/decline", "/dismiss", "/takeover", "/fork", "/ope", "/approve 2"):
        assert views.bar_title(deck, typed, solved).plain == "L01 has finished", typed
        assert views.bar_title(deck, typed, killed).plain == "L02 has finished", typed
    for typed in ("/open", "/diff", "/diff beta.bin", "/copy", "/copy all"):  # they read the lane, and ask nothing of it
        assert views.bar_title(deck, typed, solved).plain == "to L01 · Alpha", typed
        assert views.bar_title(deck, typed, killed).plain == "to L02 · Beta", typed
    assert views.bar_title(deck, "/fork another way", killed).plain == "to L02 · Beta"  # a sibling on the challenge it left
    assert views.bar_title(deck, "/fork another way", solved).plain == "L01 has finished"  # its challenge is solved
    assert views.bar_title(deck, "/hint l2 look again", at_work).plain == "L02 has finished"  # the lane a command names
    assert views.bar_title(deck, "/open L02", at_work).plain == "to L02 · Beta"
    assert views.bar_title(deck, "/pause L01", None).plain == "L01 has finished"
    assert views.bar_title(deck, "/note x", killed).plain == "the run"  # a note is for the lanes to come as well
    assert views.bar_title(deck, "a message", at_work).plain == "to L03 · Gamma"
    refused = views.bar_title(deck, "a message", killed)
    assert str(refused.style) == theme.MUTED and not refused.spans  # as `no lane`: it names nobody


def test_the_title_names_a_lane_that_takes_no_more_turns_only_for_what_asks_no_turn_of_it():
    deck, app = three_lanes()
    deck.report("L02", TurnReport(turn=False, gave_up="the model gave up"))  # its flag still waits for the player
    lane = deck.lanes["L02"]
    assert lane.gave_up_later and not lane.finished and lane.pending is not None
    for typed in ("", "a message", "/hint", "/hint look again", "/redirect", "/redirect a new plan", "/escalate", "/nope"):
        assert views.bar_title(deck, typed, lane).plain == NO_TURNS, typed
    for typed in ("/approve", "/decline", "/kill", "/kill park", "/fork", "/fork another way", "/pause", "/dismiss", "/takeover", "/open", "/copy", "/diff"):
        assert views.bar_title(deck, typed, lane).plain == "to L02 · Beta", typed
    assert views.bar_title(deck, "/escalate L02", deck.lanes["L01"]).plain == NO_TURNS
    assert str(views.bar_title(deck, "", lane).style) == theme.MUTED
    assert deck.apply(iv.Decline("L02")).ok and lane.state is LaneState.GAVE_UP
    assert views.bar_title(deck, "", lane).plain == "L02 has finished"


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_lane_that_has_ended_is_not_named_as_where_a_message_goes_in_its_view_or_in_the_list(layout):
    deck, app = three_lanes(layout)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert title(app) == "to L01 · Alpha"
        await send(pilot, app, "/kill park")
        assert deck.lanes["L01"].state is LaneState.KILLED and app.screen.lane_id == "L01"  # parked: the view stays
        assert title(app) == FINISHED  # the title follows the lane's end, with nothing typed
        row = app.screen.query_one("#bar-input").region.y
        assert color_of(app, FINISHED, row) == theme.MUTED.lower()
        await press(pilot, *"hi")
        assert title(app) == FINISHED
        await press(pilot, "enter")
        assert_warning(app, "L01 has finished (killed)")  # what the title said beforehand
        assert not hints(deck, "L01")
        await press(pilot, *"/open")
        assert title(app) == "to L01 · Alpha"  # a command the lane still takes
        await press(pilot, *(["backspace"] * len("/open")))
        assert title(app) == FINISHED
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen) and app.fleet.selected_lane == "L01"
        assert title(app) == FINISHED  # in the list: the selection is still the lane that ended
        app.fleet.select_lane("L01")  # opens the finished group, the cursor on L01's row
        await pilot.pause()
        assert cursor_key(app) == "L01" and title(app) == FINISHED
        await press(pilot, "tab", *"anyone", "enter")
        assert_warning(app, "L01 has finished (killed)")
        assert not hints(deck, "L01")
        app.fleet.select_lane("L03")
        await pilot.pause()
        assert title(app) == "to L03 · Gamma"
        await press(pilot, *"/hint L01 look")
        assert title(app) == FINISHED  # the lane the command names, whichever is selected
        await press(pilot, "enter")
        assert_warning(app, "L01 has finished (killed)")
        assert not any(hints(deck, lane_id) for lane_id in deck.lanes)

    drive(app, script, (120, 36))


@pytest.mark.parametrize("lane_id, name, forks", [
    ("L01", "Alpha", False),  # solved: nothing is left to fork for
    ("L02", "Beta", True),  # killed: a sibling can take up its challenge
], ids=["solved", "killed"])
def test_on_a_lane_that_has_ended_the_title_names_it_exactly_when_enter_does_not_refuse_it(lane_id, name, forks):
    """Every lane command, alone and with its argument, and a plain message: typed in the
    ended lane's view, the title names the lane for the ones enter carries out, and says the
    lane has finished for the ones enter refuses with those words."""
    deck, app = ended_lanes()
    finished, named = f"{lane_id} has finished", f"to {lane_id} · {name}"
    takes = ["/diff", "/diff alpha.bin", "/copy", "/copy command", "/open", "/open L01"] + (["/fork another way"] if forks else [])
    expected = {typed: named for typed in takes}

    async def script(pilot):
        await open_focus(pilot, app, lane_id)
        for typed in ["a message", *lane_commands()]:
            typed = typed.replace("L01", lane_id)
            app.say("nothing yet")  # what the status line says when enter says nothing
            app.post_message(events.Paste(typed))
            await pilot.pause()
            was = title(app)
            assert was == expected.get(typed.replace(lane_id, "L01"), finished), typed
            await press(pilot, "enter")
            assert app.screen.lane_id == lane_id and bar(app).field.value == "", typed
            assert (finished in status_line(app)) == (was == finished), (typed, status_line(app))

    drive(app, script, SIZE)
    assert [lane.id for lane in deck.lanes.values() if not lane.finished] == (["L03", "L04"] if forks else ["L03"])  # the fork was made


def test_a_lane_open_only_for_its_flags_answer_is_not_named_for_a_message_and_is_for_the_answer():
    deck, app = three_lanes()
    deck.report("L02", TurnReport(turn=False, gave_up="the model gave up"))
    assert deck.lanes["L02"].gave_up_later and not deck.lanes["L02"].finished

    async def script(pilot):
        assert cursor_key(app) == "L02" and title(app) == NO_TURNS  # in the list, with nothing typed
        await open_focus(pilot, app, "L02")
        assert title(app) == NO_TURNS
        for typed in ("try the other port", "/redirect a new plan", "/escalate"):
            app.post_message(events.Paste(typed))
            await pilot.pause()
            assert title(app) == NO_TURNS, typed
            await press(pilot, "enter")
            assert_warning(app, "L02 gave up and takes no more turns")
        assert not hints(deck, "L02") and deck.lanes["L02"].model == "glm"
        app.post_message(events.Paste("/decline"))
        await pilot.pause()
        assert title(app) == "to L02 · Beta"  # its flag's answer is what it is open for
        await press(pilot, "enter")
        assert deck.lanes["L02"].state is LaneState.GAVE_UP and title(app) == "L02 has finished"

    drive(app, script, SIZE)
