"""The peek: `space` in the lane list shows the selected lane's last steps in a panel between
the list and the why line, so a hint or a redirect can be chosen without leaving the list
(P68). In the mock, where `space` used to freeze the clock, `,` does.

Read from the screen as a player sees it (test_console's helpers rebuild the terminal from the
SVG export). Decks here are synthetic: a driver that does no work, and lanes whose turns the
test reports itself. Nothing needs a model or a network.
"""

from __future__ import annotations

import pytest
from textual.widgets import DataTable

from ctf_flightdeck.console import fleet, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import HelpScreen
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Call, Challenge, DeckConfig
from test_console import (
    OSC,
    assert_warning,
    bar,
    drive,
    make,
    osc,
    press,
    prompt_text,
    quiet_deck,
    region_text,
    screen_text,
    shown,
    status_line,
    terminal_frame,
    type_line,
)
from test_layout import console, release, three_lanes

SIZE = (120, 40)
# The three layouts the lane list is drawn in, each at a size that has room for the whole peek.
LAYOUTS = [("simple", (120, 40)), ("deck", (160, 40)), ("simple", (56, 40))]
LAYOUT_IDS = ["simple", "deck", "compact"]
STEPS = [f"⏺ step-{n} alpha.bin → out-{n}" for n in range(1, 9)]  # L01's rows in the peek, oldest first


def busy(layout: str = "simple", **kw) -> tuple[Deck, FlightdeckApp]:
    """test_layout's three lanes (L01 at work, L02 with a flag to approve, L03 with an alert
    about its course), L01 with eight more steps: more than the peek has rows for."""
    deck, app = three_lanes(layout, **kw)
    for n in range(1, 9):
        deck.report("L01", TurnReport(action=f"step-{n} alpha.bin", output=f"out-{n}"))
    return deck, app


def many(lanes: int, layout: str = "simple") -> tuple[Deck, FlightdeckApp]:
    """`lanes` lanes at work, each with one step that names it."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=lanes))
    ids = [f"c{n:02}" for n in range(1, lanes + 1)]
    deck.release([Challenge(cid, cid.upper(), "misc", 100) for cid in ids], [QueueEntry(cid, "glm") for cid in ids])
    for lane in deck.lanes.values():
        deck.report(lane.id, TurnReport(action=f"work on {lane.challenge_id}"))
    return deck, FlightdeckApp(deck, refresh_seconds=None, layout=layout)


async def select(pilot, app: FlightdeckApp, lane_id: str) -> None:
    app.fleet.select_lane(lane_id)
    await pilot.pause()


def peek_open(app: FlightdeckApp) -> bool:
    """The peek is on the screen."""
    return bool(app.fleet.query_one("#peek").display)


def peek_text(app: FlightdeckApp) -> list[str]:
    """What the peek shows, a string for each row: its rule first, then the lane's rows."""
    assert peek_open(app)
    return [line.strip() for line in region_text(app, "#peek").splitlines()]


def peek_rows(app: FlightdeckApp) -> list[str]:
    """The rows under the peek's rule that say something."""
    return [line for line in peek_text(app)[1:] if line]


def border_hint(app: FlightdeckApp) -> str:
    """The bottom border of the lanes panel, where the peek's hint is."""
    region = app.fleet.query_one("#lanes-pane").region
    return screen_text(app).splitlines()[region.bottom - 1][region.x : region.right]


# ---------------------------------------------------------------------- opening, following, closing


@pytest.mark.parametrize("layout, size", LAYOUTS, ids=LAYOUT_IDS)
def test_space_opens_a_peek_at_the_selected_lane_between_the_list_and_the_why_line_and_space_closes_it(layout, size):
    deck, app = busy(layout)

    async def script(pilot):
        await select(pilot, app, "L01")
        lanes = app.fleet.query_one("#lanes", DataTable)
        tall = lanes.region.height
        assert not peek_open(app) and "step-5" not in screen_text(app) and "space peek" in border_hint(app)
        await press(pilot, "space")
        rule, *rows = peek_text(app)
        assert rule.startswith("L01 · Alpha ─") and rule.endswith("─")  # the lane a message would go to
        assert [row for row in rows if row] == STEPS[-views.PEEK_ROWS:]  # the last six, the oldest first
        peek, why = app.fleet.query_one("#peek").region, app.fleet.query_one("#why").region
        assert lanes.region.bottom <= peek.y and peek.bottom <= why.y  # under the list, over the why line
        assert lanes.region.height == tall - peek.height == tall - views.PEEK_ROWS - 1  # its rows come from the list
        assert "space closes the peek" in border_hint(app) and "space peek" not in border_hint(app)
        assert app.focused is lanes  # the keys still act on the list
        await press(pilot, "space")
        assert not peek_open(app) and "step-5" not in screen_text(app) and lanes.region.height == tall
        assert "space peek" in border_hint(app)

    drive(app, script, size)


@pytest.mark.parametrize("layout, size", LAYOUTS, ids=LAYOUT_IDS)
def test_the_peek_follows_the_cursor_and_the_why_line_stays_under_it(layout, size):
    deck, app = busy(layout)

    async def script(pilot):
        await select(pilot, app, "L03")
        await press(pilot, "space")
        assert peek_text(app)[0].startswith("L03 · Gamma ─")
        assert peek_rows(app) == ["⏺ strings gamma.wav", "▲ Ignores the hint alert · turn 1"]
        why = region_text(app, "#why")
        assert "L03 ▲ Ignores the hint: the description says SSTV" in " ".join(why.split())  # as with the peek closed
        cursor = app.fleet.query_one("#lanes", DataTable).cursor_row
        rows = [row.key.value for row in app.fleet.query_one("#lanes", DataTable).ordered_rows]
        await press(pilot, "down" if cursor + 1 < len(rows) else "up")
        moved = app.fleet.selected_lane
        assert moved != "L03" and peek_text(app)[0].startswith(f"{moved} · ")
        assert "strings gamma.wav" not in " ".join(peek_rows(app))
        await select(pilot, app, "L02")  # a lane that waits for an approval: its log ends on the question
        assert peek_rows(app) == [
            "⏺ cat flag.txt", "· candidate flag flag{synthetic}", "▲ Flag found alert · turn 1",
            "◆ asked you · turn 1: submit flag{synthetic}",
        ]

    drive(app, script, size)


def test_the_peek_is_the_same_height_for_every_lane_so_the_list_does_not_move_with_the_cursor():
    deck, app = busy()

    async def script(pilot):
        await select(pilot, app, "L01")  # nine rows of log
        await press(pilot, "space")
        peek, lanes = app.fleet.query_one("#peek"), app.fleet.query_one("#lanes")
        full = (peek.region, lanes.region)
        assert len(peek_rows(app)) == views.PEEK_ROWS
        await select(pilot, app, "L03")  # two
        assert len(peek_rows(app)) == 2 and (peek.region, lanes.region) == full

    drive(app, script, SIZE)


def test_a_lane_that_has_taken_no_step_says_so_in_the_peek():
    deck, app = console(by_hand=True, layout="simple")
    release(deck, "alpha")
    assert deck.lanes["L01"].actions == []

    async def script(pilot):
        await press(pilot, "space")
        assert peek_text(app)[0].startswith("L01 · Alpha ─")
        assert peek_rows(app) == ["nothing yet: the lane has taken no step"]
        deck.report("L01", TurnReport(action="file alpha.bin", output="data"))  # the lane works on: the peek follows it
        app.refresh_view()
        await pilot.pause()
        assert peek_rows(app) == ["⏺ file alpha.bin → data"]

    drive(app, script, SIZE)


def test_esc_closes_the_peek_after_the_bar_and_before_the_filter():
    deck, app = busy()

    async def script(pilot):
        await select(pilot, app, "L01")
        await press(pilot, "space", "slash", *"filter alpha", "enter")
        assert app.fleet.filter_text == "alpha" and peek_open(app)
        await press(pilot, "tab", *"dra")  # something typed in the bar: esc takes that first
        assert bar(app).field.value == "dra"
        await press(pilot, "escape")
        assert bar(app).field.value == "" and peek_open(app) and app.fleet.filter_text == "alpha"
        await press(pilot, "escape")  # then the peek, and the filter the player typed stays
        assert not peek_open(app) and app.fleet.filter_text == "alpha"
        await press(pilot, "escape")
        assert app.fleet.filter_text == ""

    drive(app, script, SIZE)


def test_the_peek_stays_open_for_the_run_through_a_lanes_view_and_a_change_of_layout():
    deck, app = busy()

    async def script(pilot):
        await select(pilot, app, "L01")
        await press(pilot, "space", "enter")
        assert isinstance(app.screen, FocusScreen)
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen) and peek_rows(app) == STEPS[-views.PEEK_ROWS:]
        await press(pilot, "slash", *"layout deck", "enter")
        assert app.layout == "deck" and peek_rows(app) == STEPS[-views.PEEK_ROWS:]

    drive(app, script, (160, 40))


# ---------------------------------------------------------------------- acting on the lane the peek shows


def test_a_message_typed_in_the_bar_goes_to_the_lane_the_peek_shows_and_the_peek_shows_it():
    deck, app = busy()

    async def script(pilot):
        await select(pilot, app, "L01")
        await press(pilot, "space", "tab")
        await type_line(pilot, "try the header")
        assert deck.lanes["L01"].hints == ["try the header"] and not deck.lanes["L02"].hints and not deck.lanes["L03"].hints
        assert isinstance(app.screen, FleetScreen) and peek_text(app)[0].startswith("L01 · Alpha ─")
        assert peek_rows(app)[-1] == "› you  try the header" and peek_rows(app)[:-1] == STEPS[-views.PEEK_ROWS + 1:]

    drive(app, script, SIZE)


def test_a_number_answers_the_lane_the_peek_shows():
    deck, app = busy()

    async def script(pilot):
        await select(pilot, app, "L03")
        await press(pilot, "space")
        assert "1 redirect 2 hint" in " ".join(region_text(app, "#why").split())
        await press(pilot, "1")
        assert deck.lanes["L03"].plan == "decode it as SSTV" and deck.lanes["L01"].plan == "look inside"
        assert any("decode it as SSTV" in row and row.startswith("› you") for row in peek_rows(app))

    drive(app, script, SIZE)


def test_on_the_board_the_peek_shows_the_challenges_only_lane_and_says_so_when_there_is_none():
    deck, app = console(by_hand=True, layout="deck")
    release(deck, "alpha", "beta", "gamma", "delta", "omega")  # four lanes at most: omega waits
    deck.report("L02", TurnReport(action="cat beta.txt", output="nothing"))
    assert not deck.lanes_on("omega")

    async def script(pilot):
        await select(pilot, app, "L01")
        await press(pilot, "space")
        app.fleet.select_challenge("beta")
        await pilot.pause()
        assert peek_text(app)[0].startswith("L02 · Beta ─") and peek_rows(app) == ["⏺ cat beta.txt → nothing"]
        app.fleet.select_challenge("omega")
        await pilot.pause()
        assert peek_text(app)[0].startswith("no lane ─") and peek_rows(app) == ["no lane selected: pick one in the lane list"]

    drive(app, script, (160, 40))


def test_space_on_an_empty_board_opens_nothing_and_says_why():
    deck, app = console(by_hand=True, layout="simple")

    async def script(pilot):
        await press(pilot, "space")
        assert_warning(app, "No lane to peek at yet")
        assert app.fleet.peek is False
        release(deck, "alpha")
        app.refresh_view()
        await pilot.pause()
        assert not peek_open(app)  # it did not open behind the empty page

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- a short terminal


@pytest.mark.parametrize("lines, compact, rows", [
    (40, False, 6), (23, False, 6), (22, False, 5), (18, False, 1), (17, False, 0), (10, False, 0),
    (40, True, 6), (25, True, 6), (24, True, 5), (20, True, 1), (19, True, 0),
])
def test_the_peek_has_six_rows_where_there_is_room_and_fewer_where_the_list_would_have_under_three(lines, compact, rows):
    assert fleet.peek_rows(lines, compact=compact) == rows
    assert fleet.lane_rows(lines, compact=compact) - (rows + 1 if rows else 0) >= (fleet.PEEK_LANE_ROWS if rows else 0)
    assert (rows > 0) is (lines >= fleet.peek_lines_needed(compact=compact))


@pytest.mark.parametrize("size", [(120, 23), (120, 20), (120, 18), (56, 25), (56, 21)], ids=lambda size: f"{size[0]}x{size[1]}")
def test_on_a_short_terminal_the_peek_takes_the_rows_there_are_and_the_list_keeps_the_selected_lane_in_view(size):
    deck, app = many(9)
    compact = size[0] <= views.COMPACT_MAX_WIDTH
    rows = fleet.peek_rows(size[1], compact=compact)
    for n in range(1, 9):
        deck.report("L09", TurnReport(action=f"step-{n}"))

    async def script(pilot):
        lanes = app.fleet.query_one("#lanes", DataTable)
        await select(pilot, app, "L09")  # the last row of a list that scrolls
        await press(pilot, "space")
        assert 0 < rows == len(peek_rows(app)) and peek_rows(app) == [f"⏺ step-{n}" for n in range(9 - rows, 9)]
        assert lanes.region.height - 1 >= fleet.PEEK_LANE_ROWS  # under its column labels
        assert "L09" in region_text(app, "#lanes")  # the lane the peek shows is still a row on the screen
        await press(pilot, "up", "up", "up", "up", "up", "up")
        assert app.fleet.selected_lane == "L03" and "L03" in region_text(app, "#lanes") and peek_text(app)[0].startswith("L03 · ")

    drive(app, script, size)


@pytest.mark.parametrize("size, needed", [((120, 17), 18), ((56, 19), 20)], ids=["full", "compact"])
def test_space_on_a_terminal_with_no_room_for_the_peek_opens_nothing_and_says_how_tall_it_must_be(size, needed):
    deck, app = many(3)

    async def script(pilot):
        await press(pilot, "space")
        said = " ".join(status_line(app).split())
        assert f"No room for the peek: the terminal is {size[1]} lines tall and it needs {needed}" in said
        assert app.fleet.peek is False and not peek_open(app) and "space peek" in border_hint(app)
        await pilot.resize_terminal(size[0], needed)
        await pilot.pause()
        await press(pilot, "space")
        assert peek_rows(app) == ["⏺ work on c01"]  # one row, on the first terminal tall enough

    drive(app, script, size)


def test_a_terminal_made_shorter_hides_an_open_peek_and_says_so_and_a_taller_one_shows_it_again():
    deck, app = busy()

    async def script(pilot):
        await select(pilot, app, "L01")
        await press(pilot, "space")
        assert len(peek_rows(app)) == 6
        await pilot.resize_terminal(120, 20)
        await pilot.pause()
        assert peek_rows(app) == STEPS[-3:]
        await pilot.resize_terminal(120, 16)
        await pilot.pause()
        assert not peek_open(app) and app.fleet.peek is True
        assert "no room for the peek" in border_hint(app) and "space" not in border_hint(app)
        await pilot.resize_terminal(120, 40)
        await pilot.pause()
        assert peek_rows(app) == STEPS[-6:] and "space closes the peek" in border_hint(app)

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the rows of the peek


def test_the_peek_gives_every_tool_call_its_own_row_and_one_row_to_anything_else():
    """The lane's own view counts a run of tool calls and shows the last; the peek is read for
    the last few steps, so each call is a row: the first line of the call and of its output,
    with how many lines more. The model's words, a note and the player's message are a row each."""
    deck, app = console(by_hand=True, layout="simple")
    release(deck, "alpha")
    lane = deck.lanes["L01"]
    deck.report("L01", TurnReport(action="says: the archive has two layers"))
    deck.report("L01", TurnReport(action="unzip a.zip", output="2 files", calls=(
        Call("unzip a.zip", "inflating: one\ninflating: two"),
        Call("cat <<'EOF' > solve.py\nprint(1)\nEOF", "ok"),
    )))
    deck.report("L01", TurnReport(action="python3 solve.py", output="1"))
    deck.note("L01", "the handout has 2 files\nand a readme")
    assert [line.plain for line in views.peek_lines(deck, lane, 6)] == [
        "⏺ the archive has two layers",
        "⏺ unzip a.zip → inflating: one …+1 line",
        "⏺ cat <<'EOF' > solve.py …+2 lines → ok",
        "⏺ python3 solve.py → 1",
        "· the handout has 2 files …+1 line",
    ]
    assert [line.plain for line in views.peek_lines(deck, lane, 2)] == ["⏺ python3 solve.py → 1", "· the handout has 2 files …+1 line"]
    assert [line.plain for line in views.peek_lines(deck, lane, 3)][0] == "⏺ cat <<'EOF' > solve.py …+2 lines → ok"  # a turn's last call, not its first
    assert all("\n" not in line.plain for line in views.peek_lines(deck, lane, 6))  # each is one row

    async def script(pilot):
        await press(pilot, "space")
        assert peek_rows(app) == [line.plain for line in views.peek_lines(deck, lane, 6)]

    drive(app, script, SIZE)


def test_a_row_longer_than_the_peek_is_cut_at_its_edge_and_never_wraps():
    deck, app = console(by_hand=True, layout="simple")
    release(deck, "alpha")
    deck.report("L01", TurnReport(action="says: " + "word " * 80))
    deck.report("L01", TurnReport(action="echo " + "x" * 300, output="done"))

    async def script(pilot):
        await press(pilot, "space")
        rows = peek_rows(app)
        assert len(rows) == 2 and all(row.endswith("…") for row in rows)
        assert rows[0].startswith("⏺ word word") and rows[1].startswith("⏺ echo xxx")

    drive(app, script, SIZE)


def test_lane_and_challenge_text_in_the_peek_never_reaches_the_terminal_raw_and_is_never_markup():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",)))
    deck.release([Challenge("evil", "Evil " + osc("nm") + " [@click=app.quit]x[/]", "web", 100)], [QueueEntry("evil", "glm")])
    deck.report("L01", TurnReport(action="run " + osc("ac") + " [b]bold[/b]", output="out " + osc("ou")))
    deck.report("L01", TurnReport(action="says: " + osc("sy")))
    app = FlightdeckApp(deck, refresh_seconds=None, layout="simple")

    async def script(pilot):
        await press(pilot, "space")
        assert OSC not in terminal_frame(app)
        text = " ".join(peek_text(app))
        assert all(shown(tag) in text for tag in ("nm", "ac", "ou", "sy"))  # made visible, not dropped
        assert "[@click=app.quit]x[/]" in text and "[b]bold[/b]" in text  # as typed

    drive(app, script, (160, 40))


# ---------------------------------------------------------------------- help, and the mock's clock


def test_help_lists_space_as_the_peek():
    deck, app = busy()

    async def script(pilot):
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen)
        said = prompt_text(app)
        assert "space Peek: the selected lane's last steps under the lane list" in said and "space or esc closes it" in said
        assert "mock clock" not in said  # a run has no clock to freeze

    drive(app, script, SIZE)


def test_in_the_mock_space_peeks_and_comma_freezes_the_clock():
    world, app = make("sstv")

    async def script(pilot):
        assert "▶ live: , freezes" in region_text(app, "#header") and app.frozen is False
        await press(pilot, "space")
        assert app.frozen is False and peek_open(app)  # space no longer touches the clock
        await press(pilot, "comma")
        assert app.frozen is True and "⏸ frozen: , resumes · . steps" in region_text(app, "#header")
        before = world.deck.now
        app._on_tick()  # the mock's timer, frozen: the world stands still
        assert world.deck.now == before
        await press(pilot, "full_stop")  # one step by hand
        assert world.deck.now > before
        await press(pilot, "comma")
        assert app.frozen is False and "▶ live: , freezes" in region_text(app, "#header")
        await press(pilot, "question_mark")
        said = prompt_text(app)
        assert ", Freeze or restart the mock clock" in said and "space Freeze" not in said and "space Peek" in said

    drive(app, script, (160, 46))  # wide enough for the deck layout's header to keep the clock's note


def test_outside_the_mock_comma_is_no_key():
    deck, app = busy()

    async def script(pilot):
        before = screen_text(app)
        await press(pilot, "comma")
        assert app.frozen is False and screen_text(app) == before and bar(app).field.value == ""

    drive(app, script, SIZE)
