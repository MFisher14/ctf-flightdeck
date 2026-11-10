"""Pilot tests for the route C console: the fleet screen, the focus screen, and the console
requirements from the M0 kickoff.

Apps are built with no timers (no tick timer, refresh_seconds=None): each test ticks the
fake world itself with app.step(), so every run is the same. The one exception is the
M1-seam test, which is about the console redrawing on its own timer. pytest 9 has no async
tests, so each test drives the app inside asyncio.run().

Screen checks read what is drawn: screen_lines() rebuilds the terminal, one string per row,
from the SVG export (each text run is placed at its column; the run's clip-path names its
row).
"""

from __future__ import annotations

import asyncio
import html
import re

import pytest
from rich.cells import cell_len
from textual import events
from textual.containers import ScrollableContainer
from textual.widgets import DataTable, Select, Static

from ctf_flightdeck import fmt
from ctf_flightdeck.console import theme
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import ChallengeCard, ForkPrompt, HelpScreen, KillPrompt, TakeOverScreen
from ctf_flightdeck.console.views import FINISHED_ROW
from ctf_flightdeck.console.widgets import CommandBar
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.attention import SortMode
from ctf_flightdeck.core.model import ME, ActionKind, AlertKind, ChallengeStatus, EventKind, LaneState, PendingKind
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.scenarios import DEEP_ARCHIVE, ReleaseAt, Scenario, Spec
from ctf_flightdeck.mock.world import FakeWorld

SIZE = (160, 46)
NARROW = (120, 36)


# ---------------------------------------------------------------------- driving the app


def make(scenario: str | Scenario = "sstv", **kw) -> tuple[FakeWorld, FlightdeckApp]:
    spec = scenarios.get(scenario) if isinstance(scenario, str) else scenario
    world = FakeWorld(spec, **kw)
    return world, FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test", refresh_seconds=None)


def drive(app: FlightdeckApp, script, size: tuple[int, int] = SIZE) -> None:
    async def main() -> None:
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await script(pilot)

    asyncio.run(main())


async def step(pilot, app: FlightdeckApp, ticks: int = 1) -> None:
    app.step(ticks)
    await pilot.pause()


async def step_until(pilot, app: FlightdeckApp, cond, what: str, limit: int = 80) -> None:
    """Tick the mock world one step at a time until `cond()` holds, at most `limit` ticks.

    Every step redraws the views; the screen is let settle once at the end, which keeps
    long waits cheap (tests that check every tick's screen pause after each step)."""
    for _ in range(limit):
        if cond():
            break
        app.step()
    await pilot.pause()
    assert cond(), f"{what}: not reached within {limit} ticks"


async def press(pilot, *keys: str) -> None:
    await pilot.press(*keys)
    await pilot.pause()


async def type_line(pilot, text: str) -> None:
    """Type `text` into the focused field, key by key, and press enter."""
    await pilot.press(*text, "enter")
    await pilot.pause()


async def send(pilot, app: FlightdeckApp, text: str) -> None:
    """Put `text` in the focused field the way a terminal paste arrives, then press enter.

    For commands whose effect is under test; typing key by key costs ~50 ms a key, and the
    tests about typing itself use type_line()."""
    app.post_message(events.Paste(text))
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()


async def open_focus(pilot, app: FlightdeckApp, lane_id: str) -> FocusScreen:
    """Open a lane in the focus view, then redraw once as the console's refresh timer would.

    The redraw stands in for the timer these apps do not run; that a lane is drawn at once
    without it is test_opening_a_lane_draws_it_without_waiting_for_a_redraw.
    """
    app.open_lane(lane_id)
    await pilot.pause()
    app.refresh_view()
    await pilot.pause()
    screen = app.screen
    assert isinstance(screen, FocusScreen) and screen.lane_id == lane_id
    return screen


# ---------------------------------------------------------------------- reading the tables


def table(app: FlightdeckApp, table_id: str) -> DataTable:
    return app.fleet.query_one(f"#{table_id}", DataTable)


def cell(app: FlightdeckApp, table_id: str, row_key: str, column_key: str) -> str:
    return str(table(app, table_id).get_cell(row_key, column_key))


def row_keys(app: FlightdeckApp) -> list[str]:
    return [row.key.value for row in table(app, "lanes").ordered_rows]


def lane_rows(app: FlightdeckApp) -> list[str]:
    """Lane ids in the order the fleet shows them (the collapsed finished row left out)."""
    return [key for key in row_keys(app) if key != FINISHED_ROW]


def cursor_key(app: FlightdeckApp) -> str | None:
    keys = row_keys(app)
    return keys[table(app, "lanes").cursor_coordinate.row] if keys else None


def columns(app: FlightdeckApp, table_id: str) -> list[str]:
    return [column.key.value for column in table(app, table_id).ordered_columns]


def bar(app: FlightdeckApp) -> CommandBar:
    return app.screen.query_one("#bar" if isinstance(app.screen, FleetScreen) else "#chat", CommandBar)


# ---------------------------------------------------------------------- reading the screen

SPAN = re.compile(
    r'<text class="([^"]*-r\d+)" x="([\d.]+)" y="[\d.]+" textLength="([\d.]+)"'
    r' clip-path="url\(#[^)]*-line-(\d+)\)">(.*?)</text>'
)
FILL = re.compile(r"\.([\w-]+-r\d+) \{ fill: (#[0-9a-fA-F]{6})")


def _runs(app: FlightdeckApp) -> tuple[list[tuple[str, float, int, float, str]], dict[str, str]]:
    """Every text run of the SVG export as (style class, x, row, width, text), and each class's color."""
    svg = app.export_screenshot()
    runs = [
        (cls, float(x), int(row), float(width), html.unescape(body).replace("\xa0", " "))
        for cls, x, width, row, body in SPAN.findall(svg)
    ]
    return runs, dict(FILL.findall(svg))


def screen_lines(app: FlightdeckApp) -> list[str]:
    """The screen as plain text, one string per terminal row."""
    runs, _ = _runs(app)
    char_width = next(width / len(text) for _, _, _, width, text in runs if text)
    rows: list[list[str]] = [[] for _ in range(app.size.height)]
    for _, x, row, _, text in runs:
        col = round(x / char_width)
        cells = []
        for ch in text:
            cells.append(ch)
            if cell_len(ch) == 2:
                cells.append("")  # a wide character covers two columns
        line = rows[row]
        line.extend(" " * max(0, col + len(cells) - len(line)))
        line[col : col + len(cells)] = cells
    return ["".join(line) for line in rows]


def screen_text(app: FlightdeckApp) -> str:
    return "\n".join(line.rstrip() for line in screen_lines(app))


def footer_line(app: FlightdeckApp) -> str:
    return [line for line in screen_text(app).splitlines() if line.strip()][-1]


def region_text(app: FlightdeckApp, selector: str) -> str:
    """What is drawn inside a widget of the current screen."""
    region = app.screen.query_one(selector).region
    lines = screen_lines(app)
    return "\n".join(lines[y][region.x : region.right].rstrip() for y in range(region.y, region.bottom))


def status_line(app: FlightdeckApp) -> str:
    return region_text(app, "#status")


def color_of(app: FlightdeckApp, needle: str, row: int) -> str:
    """The text color of the run on screen row `row` that shows `needle`."""
    runs, fills = _runs(app)
    found = [fills.get(cls, "") for cls, _, at, _, text in runs if at == row and needle in text]
    assert found, f"{needle!r} is not on row {row}"
    return found[0].lower()


def assert_warning(app: FlightdeckApp, text: str) -> None:
    """`text` is in the status line, drawn in the warning color."""
    line = status_line(app)
    assert text in line, line
    row = app.screen.query_one("#status").region.y
    assert color_of(app, text, row) == theme.YELLOW.lower(), f"{text!r} is not shown as a warning"


def snapshot(app: FlightdeckApp) -> dict[str, tuple]:
    """What an intervention could change on each lane."""
    return {
        lane.id: (lane.state, lane.plan, lane.model, tuple(lane.hints), lane.pending, lane.token_cap)
        for lane in app.deck.lanes.values()
    }


def interventions(app: FlightdeckApp) -> list[str]:
    return [e.data["intervention"] for e in app.deck.events if e.kind is EventKind.INTERVENTION]


# ---------------------------------------------------------------------- fleet keys


def test_p_pauses_and_resumes_the_selected_lane_and_a_paused_lane_takes_no_turns():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        lane = deck.lanes[lane_rows(app)[0]]
        assert app.fleet.selected_lane == lane.id
        await press(pilot, "p")
        assert lane.state is LaneState.PAUSED
        assert cell(app, "lanes", lane.id, "state") == "paused"
        assert f"Paused {lane.id}" in status_line(app)
        turns = lane.turns
        others = sum(other.turns for other in deck.lanes.values() if other is not lane)
        await step(pilot, app, 6)
        assert sum(other.turns for other in deck.lanes.values() if other is not lane) > others  # time passed
        assert lane.turns == turns
        await press(pilot, "p")
        assert lane.state is LaneState.RUNNING
        assert cell(app, "lanes", lane.id, "state") == "run"
        await step_until(pilot, app, lambda: lane.turns > turns, "the resumed lane takes a turn", limit=6)

    drive(app, script)


def test_arrow_down_moves_the_selection_and_the_next_key_acts_on_the_new_lane():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        first, second = lane_rows(app)[:2]
        assert app.fleet.selected_lane == first
        await press(pilot, "down")
        assert app.fleet.selected_lane == second
        assert cell(app, "lanes", second, "bar") == "▌" and cell(app, "lanes", first, "bar") == " "
        await press(pilot, "p")
        assert deck.lanes[second].state is LaneState.PAUSED
        assert deck.lanes[first].state is LaneState.RUNNING

    drive(app, script)


def _off_hint(world: FakeWorld):
    return world.deck.lanes_on("static-hiss")[0]


def test_h_prefills_a_hint_with_the_suggestion_and_enter_queues_it():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.HINT) is not None, "off-hint alert")
        hint = next(s.text for s in lane.alert(AlertKind.HINT).suggestions if s.key == "h")
        app.fleet.select_lane(lane.id)
        await press(pilot, "h")
        field = bar(app).field
        assert app.focused is field
        assert field.value == f"/hint {lane.id} {hint} "
        await press(pilot, "enter")
        assert lane.hints == [hint]
        assert lane.alert(AlertKind.HINT) is None  # a hint answers the alert
        assert field.value == "" and app.focused is table(app, "lanes")
        await press(pilot, "enter")  # opens the lane under the cursor: still this one
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == lane.id
        app.refresh_view()  # the redraw timer
        await pilot.pause()
        assert f"› you  {hint}" in region_text(app, "#transcript")

    drive(app, script)


def test_h_then_typing_adds_to_the_prefilled_hint():
    """The prefill is the start of the command: what the player types goes after it."""
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.HINT) is not None, "off-hint alert")
        hint = next(s.text for s in lane.alert(AlertKind.HINT).suggestions if s.key == "h")
        app.fleet.select_lane(lane.id)
        await press(pilot, "h")
        await press(pilot, *"and read it")
        assert bar(app).field.value == f"/hint {lane.id} {hint} and read it"
        await press(pilot, "enter")
        assert lane.hints == [f"{hint} and read it"]

    drive(app, script)


def test_r_prefills_the_suggested_redirect_and_enter_replaces_the_plan():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.HINT) is not None, "off-hint alert")
        plan = next(s.text for s in lane.alert(AlertKind.HINT).suggestions if s.key == "r")
        assert lane.plan != plan
        app.fleet.select_lane(lane.id)
        assert "offhint" in cell(app, "lanes", lane.id, "!")
        await press(pilot, "r")
        assert bar(app).field.value == f"/redirect {lane.id} {plan}"
        await press(pilot, "enter")
        assert lane.plan == plan
        assert lane.alert(AlertKind.HINT) is None
        assert "offhint" not in cell(app, "lanes", lane.id, "!")
        assert f"{lane.id} has a new plan" in status_line(app)

    drive(app, script)


def test_f_forks_on_the_model_picked_in_the_prompt_with_the_approach_as_plan():
    world, app = make("web")
    deck = world.deck
    lane = deck.lanes_on("paper-trail")[0]

    async def script(pilot):
        assert lane.model == "glm"
        app.fleet.select_lane(lane.id)
        await press(pilot, "f")
        prompt = app.screen
        assert isinstance(prompt, ForkPrompt)
        select = prompt.query_one(Select)
        assert select.value == "sonnet"  # the default: the next stronger model
        await press(pilot, *"source first")
        await press(pilot, "tab")
        assert app.focused is select
        await press(pilot, "enter")  # open the list
        await press(pilot, "down")
        await press(pilot, "enter")  # pick the next one down
        assert select.value == "opus"
        await press(pilot, "shift+tab")
        await press(pilot, "enter")
        assert isinstance(app.screen, FleetScreen)
        forks = [other for other in deck.lanes_on("paper-trail") if other is not lane]
        assert len(forks) == 1
        fork = forks[0]
        assert (fork.parent, fork.model, fork.plan) == (lane.id, "opus", "source first")
        assert fork.id in lane_rows(app)
        assert cell(app, "lanes", fork.id, "model") == "opus"

    drive(app, script)


def test_k_opens_the_kill_prompt_on_cancel_so_enter_cancels():
    world, app = make("sstv")
    lane = world.deck.lanes["L01"]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await press(pilot, "k")
        assert isinstance(app.screen, KillPrompt)
        assert app.focused is not None and app.focused.id == "cancel"
        await press(pilot, "enter")
        assert isinstance(app.screen, FleetScreen)
        await press(pilot, "k", "escape")  # escape cancels too
        assert isinstance(app.screen, FleetScreen)
        assert lane.state is LaneState.RUNNING
        assert "kill" not in interventions(app)
        assert lane.id in lane_rows(app)

    drive(app, script)


def test_k_then_r_kills_the_lane_and_starts_a_fresh_one():
    world, app = make("sstv")
    deck = world.deck
    lane = _off_hint(world)

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await press(pilot, "k", "r")
        assert isinstance(app.screen, FleetScreen)
        assert lane.state is LaneState.KILLED
        (fresh,) = deck.lanes_on("static-hiss")
        assert fresh is not lane and fresh.attempt == 2
        assert fresh.id in lane_rows(app) and lane.id not in lane_rows(app)
        assert cell(app, "board", "static-hiss", "mark") == "▶"
        assert cell(app, "board", "static-hiss", "own") == fresh.id

    drive(app, script)


def test_k_then_p_kills_the_lane_and_parks_its_challenge():
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes_on("muddy-footprints")[0]

    async def script(pilot):
        assert cell(app, "board", "muddy-footprints", "mark") == "▶"
        app.fleet.select_lane(lane.id)
        await press(pilot, "k", "p")
        assert lane.state is LaneState.KILLED
        assert deck.challenges["muddy-footprints"].status is ChallengeStatus.PARKED
        assert deck.lanes_on("muddy-footprints") == [] and not deck.queued("muddy-footprints")
        assert cell(app, "board", "muddy-footprints", "mark") == "‖"
        assert cell(app, "board", "muddy-footprints", "own") == ""

    drive(app, script)


def test_e_escalates_the_selected_lane_and_its_model_cell_changes():
    world, app = make("sstv")
    lane = world.deck.lanes["L02"]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        assert cell(app, "lanes", lane.id, "model") == "glm"
        await press(pilot, "e")
        assert lane.model == "sonnet"
        assert cell(app, "lanes", lane.id, "model") == "sonnet"
        assert world.deck.lanes["L01"].model == "glm"

    drive(app, script)


def test_t_takes_over_the_lane_until_enter_hands_it_back():
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes["L02"]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await press(pilot, "t")
        assert isinstance(app.screen, TakeOverScreen)
        text = screen_text(app)
        assert "placeholder: this is the M0 mock" in text and "In M1 this drops you into a shell" in text
        assert lane.state is LaneState.TAKEOVER
        turns = lane.turns
        others = sum(other.turns for other in deck.lanes.values() if other is not lane)
        await step(pilot, app, 6)
        assert sum(other.turns for other in deck.lanes.values() if other is not lane) > others
        assert lane.turns == turns
        await press(pilot, "enter")
        assert isinstance(app.screen, FleetScreen)
        assert lane.state is LaneState.RUNNING
        await step_until(pilot, app, lambda: lane.turns > turns, "the handed-back lane takes a turn", limit=6)

    drive(app, script)


def test_a_approves_a_submit_and_the_board_shows_the_challenge_solved_by_the_lane():
    world, app = make("flag")
    deck = world.deck
    lane = deck.lanes_on("ticket-desk")[0]

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.pending is not None, "a candidate flag")
        assert lane.pending.kind is PendingKind.SUBMIT
        app.fleet.select_lane(lane.id)
        assert cell(app, "board", "ticket-desk", "mark") == "▶"
        await press(pilot, "a")
        assert lane.state is LaneState.SOLVED
        assert deck.challenges["ticket-desk"].status is ChallengeStatus.SOLVED
        assert cell(app, "board", "ticket-desk", "mark") == "✓"
        assert cell(app, "board", "ticket-desk", "own") == lane.id

    drive(app, script)


def test_a_approves_a_live_box_request_and_the_lane_runs_again():
    world, app = make("team")
    lane = world.deck.lanes_on("harbor-master")[0]

    def wants_box() -> bool:
        return lane.pending is not None and lane.pending.kind is PendingKind.LIVE_BOX

    async def script(pilot):
        await step_until(pilot, app, wants_box, "a live-box request")
        assert lane.state is LaneState.WAITING
        assert "box" in cell(app, "lanes", lane.id, "!")
        turns = lane.turns
        await step(pilot, app, 4)
        assert lane.turns == turns  # it waits for the player
        app.fleet.select_lane(lane.id)
        await press(pilot, "a")
        assert lane.pending is None and lane.state is LaneState.RUNNING
        assert cell(app, "lanes", lane.id, "state") == "run"
        await step_until(pilot, app, lambda: lane.turns > turns, "the approved lane takes a turn", limit=8)

    drive(app, script)


def test_a_at_the_budget_warning_raises_the_cap():
    archive = Scenario(
        name="archive", summary="", specs=(DEEP_ARCHIVE,), timeline=((0, ReleaseAt(("deep-archive",), "Board")),)
    )
    world, app = make(archive)
    lane = world.deck.lanes_on("deep-archive")[0]

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.BUDGET) is not None, "the budget warning", limit=40)
        assert lane.pending is None  # the 80% warning: the lane still runs
        cap = lane.token_cap
        assert lane.tokens >= 0.8 * cap
        assert "budget" in cell(app, "lanes", lane.id, "!")
        app.fleet.select_lane(lane.id)
        await press(pilot, "a")
        assert lane.token_cap == int(cap * 1.5)
        assert lane.alert(AlertKind.BUDGET) is None
        assert "budget" not in cell(app, "lanes", lane.id, "!")
        assert "600k tokens" in status_line(app)

    drive(app, script)


def test_c_claims_and_releases_in_team_mode():
    world, app = make("team")
    deck = world.deck

    async def script(pilot):
        assert "c claim" in footer_line(app)
        lucky = deck.challenges["lucky-sevens"]
        assert deck.lanes_on(lucky.id) == []
        app.fleet.select_challenge(lucky.id)
        await press(pilot, "c")
        assert lucky.claimed_by == ME
        assert cell(app, "board", lucky.id, "own") == ME
        await press(pilot, "c")
        assert lucky.claimed_by is None
        assert cell(app, "board", lucky.id, "own") == ""
        lane = deck.lanes_on("origami")[0]  # from the lane list: the lane's challenge
        app.fleet.select_lane(lane.id)
        await press(pilot, "c")
        assert deck.challenges["origami"].claimed_by == ME
        assert cell(app, "board", "origami", "own") == f"{lane.id}*"

    drive(app, script)


def test_c_does_nothing_in_solo_mode_and_is_not_offered():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        assert "claim" not in footer_line(app)
        app.fleet.select_challenge("bent-coin")
        events = len(deck.events)
        await press(pilot, "c")
        assert deck.challenges["bent-coin"].claimed_by is None
        assert len(deck.events) == events  # not even attempted
        assert status_line(app) == ""

    drive(app, script)


def test_s_sorts_the_lanes_by_idle_time():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        before = lane_rows(app)
        await press(pilot, "s")
        assert app.fleet.sort is SortMode.IDLE
        assert "sort idle" in region_text(app, "#lanes-pane")
        after = lane_rows(app)
        now = deck.now
        idle = [deck.lanes[key].idle(now) for key in after]
        assert len(set(idle)) > 1
        assert after == sorted(after, key=lambda key: (-deck.lanes[key].idle(now), deck.lanes[key].number))
        assert sorted(after) == sorted(before) and after != before

    drive(app, script)


def test_slash_opens_the_bar_with_a_menu_and_typing_carries_on_after_the_slash():
    world, app = make("sstv")

    async def script(pilot):
        await press(pilot, "slash")
        command_bar = bar(app)
        assert app.focused is command_bar.field
        assert command_bar.field.value == "/"
        assert command_bar.menu_open
        assert "/hint <text>" in region_text(app, "#menu")
        await press(pilot, *"fil")
        assert command_bar.field.value == "/fil"
        assert [c.text for c in command_bar.completions] == ["/filter "]
        await press(pilot, "tab")
        assert command_bar.field.value == "/filter "

    drive(app, script)


def test_filter_from_the_bar_keeps_matching_lanes_and_escape_clears_it():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        everyone = lane_rows(app)
        sonnet = [key for key in everyone if deck.lanes[key].model == "sonnet"]
        assert 0 < len(sonnet) < len(everyone)
        await press(pilot, "tab")
        command_bar = bar(app)
        assert app.focused is command_bar.field
        await press(pilot, *"/fil")
        assert command_bar.menu_open
        await press(pilot, "tab")
        assert command_bar.field.value == "/filter "
        await type_line(pilot, "sonnet")
        assert lane_rows(app) == sonnet
        assert "filter sonnet" in region_text(app, "#lanes-pane")
        await press(pilot, "escape")
        assert app.fleet.filter_text == ""
        assert lane_rows(app) == everyone

    drive(app, script)


def test_question_mark_opens_help_that_scrolls_and_escape_closes_it():
    world, app = make("sstv")

    async def script(pilot):
        await press(pilot, "question_mark")
        help_screen = app.screen
        assert isinstance(help_screen, HelpScreen)
        assert "Keys (fleet)" in screen_text(app)
        body = help_screen.query_one("#help-body")
        assert isinstance(body, ScrollableContainer)
        assert body.max_scroll_y > 0  # longer than the box: it must scroll
        await press(pilot, "down")
        assert body.scroll_y > 0
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)

    drive(app, script)


def test_tab_moves_focus_from_the_lanes_to_the_bar_to_the_board_and_back():
    world, app = make("sstv")

    async def script(pilot):
        lanes, board = table(app, "lanes"), table(app, "board")
        assert app.focused is lanes
        await press(pilot, "tab")
        assert app.focused is bar(app).field
        await press(pilot, "tab")
        assert app.focused is board and app.fleet.board_focused
        assert "enter for more" in region_text(app, "#why")  # the why line describes the challenge
        await press(pilot, "tab")
        assert app.focused is lanes and not app.fleet.board_focused
        assert "enter open" in region_text(app, "#why")

    drive(app, script)


def test_lane_keys_on_the_board_act_on_the_challenges_only_lane():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        selected = deck.lanes[app.fleet.selected_lane]
        target = deck.lanes_on("bent-coin")[0]
        assert target is not selected
        app.fleet.select_challenge("bent-coin")
        await press(pilot, "p")
        assert target.state is LaneState.PAUSED
        assert selected.state is LaneState.RUNNING

    drive(app, script)


def test_lane_keys_on_the_board_warn_when_two_lanes_work_the_challenge():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        deck.apply(iv.Fork(deck.lanes_on("bent-coin")[0].id))
        assert len(deck.lanes_on("bent-coin")) == 2
        app.fleet.select_challenge("bent-coin")
        await pilot.pause()
        before = snapshot(app)
        await press(pilot, "p")
        assert_warning(app, "2 lanes work Bent Coin")
        assert snapshot(app) == before

    drive(app, script)


def test_enter_opens_the_lane_and_escape_returns_with_that_lane_still_selected():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        top = lane_rows(app)[0]
        await press(pilot, "down", "down")
        lane = lane_rows(app)[2]
        assert app.fleet.selected_lane == lane
        await press(pilot, "enter")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == lane
        # from the open lane, pause the top lane: it drops to the bottom and this lane moves up
        await send(pilot, app, f"/pause {top}")
        assert deck.lanes[top].state is LaneState.PAUSED
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)
        assert app.fleet.selected_lane == lane and cursor_key(app) == lane
        assert lane_rows(app).index(lane) == 1  # the row moved and the cursor went with it
        assert cell(app, "lanes", lane, "bar") == "▌"
        assert deck.lanes[lane].state is LaneState.RUNNING

    drive(app, script)


def test_enter_on_a_parked_challenge_opens_its_card_and_q_queues_a_fresh_lane():
    world, app = make("sstv")
    deck = world.deck
    old = deck.lanes_on("muddy-footprints")[0]

    async def script(pilot):
        app.fleet.select_lane(old.id)
        await press(pilot, "k", "p")
        assert cell(app, "board", "muddy-footprints", "mark") == "‖"
        app.fleet.select_challenge("muddy-footprints")
        await press(pilot, "enter")
        assert isinstance(app.screen, ChallengeCard)
        assert "queue a fresh lane" in screen_text(app)
        await press(pilot, "q")
        assert isinstance(app.screen, FleetScreen)
        (fresh,) = deck.lanes_on("muddy-footprints")
        assert fresh is not old and fresh.attempt == 2 and fresh.state is LaneState.RUNNING
        assert fresh.id in lane_rows(app)
        assert cell(app, "board", "muddy-footprints", "mark") == "▶"
        assert cell(app, "board", "muddy-footprints", "own") == fresh.id

    drive(app, script)


def test_enter_on_the_finished_row_expands_and_collapses_it_and_the_cursor_stays():
    world, app = make("team")
    deck = world.deck
    stopped = deck.lanes_on("night-shift")[0]

    async def script(pilot):
        other = next(lane for lane in deck.active_lanes() if lane is not stopped)
        app.fleet.select_lane(other.id)
        await step_until(pilot, app, lambda: stopped.finished, "a lane finishes")
        assert stopped.id not in row_keys(app) and FINISHED_ROW in row_keys(app)
        for _ in range(len(row_keys(app))):
            if cursor_key(app) == FINISHED_ROW:
                break
            await press(pilot, "down")
        assert cursor_key(app) == FINISHED_ROW
        await press(pilot, "enter")
        assert isinstance(app.screen, FleetScreen)
        keys = row_keys(app)
        assert stopped.id in keys and keys.index(stopped.id) > keys.index(FINISHED_ROW)
        assert cursor_key(app) == FINISHED_ROW
        assert cell(app, "lanes", FINISHED_ROW, "!") == "▾"
        await press(pilot, "enter")
        assert stopped.id not in row_keys(app)
        assert cursor_key(app) == FINISHED_ROW
        assert cell(app, "lanes", FINISHED_ROW, "!") == "▸"

    drive(app, script)


def test_a_selected_lane_that_finishes_stays_selected_and_keys_report_it():
    world, app = make("team")
    deck = world.deck
    lane = deck.lanes_on("night-shift")[0]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await step_until(pilot, app, lambda: lane.finished, "the teammate's solve stops the lane")
        assert app.fleet.selected_lane == lane.id
        assert cursor_key(app) == FINISHED_ROW  # where the lane went, not another lane
        assert all(cell(app, "lanes", key, "bar") == " " for key in lane_rows(app))
        assert f"{lane.id} stopped" in region_text(app, "#why")
        before = snapshot(app)
        await press(pilot, "p")
        assert_warning(app, f"{lane.id} has finished")
        assert snapshot(app) == before

    drive(app, script)


def test_lane_keys_warn_when_the_filter_hides_the_selected_lane():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        selected = deck.lanes[app.fleet.selected_lane]
        assert selected.challenge_id != "bent-coin"
        await press(pilot, "tab")
        await send(pilot, app, "/filter bent")
        assert lane_rows(app) == [deck.lanes_on("bent-coin")[0].id]
        assert app.fleet.selected_lane == selected.id
        before = snapshot(app)
        await press(pilot, "p")
        assert_warning(app, f"{selected.id} is hidden by the filter")
        assert snapshot(app) == before

    drive(app, script)


# ---------------------------------------------------------------------- focus view


def test_opening_a_lane_draws_it_without_waiting_for_a_redraw():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step(pilot, app, 3)
        assert lane.actions
        app.open_lane(lane.id)
        await pilot.pause()
        await pilot.pause()
        assert isinstance(app.screen, FocusScreen)
        assert f"{lane.id} · Static Hiss" in screen_text(app)
        assert "⏺ file static_hiss.wav" in region_text(app, "#transcript")

    drive(app, script)


def _transcript(app: FlightdeckApp) -> list[str]:
    """The lane's steps and the player's messages as the focus view lists them."""
    lines = [line.strip() for line in region_text(app, "#transcript").splitlines()]
    return [line for line in lines if line.startswith(("⏺ ", "› you  "))]


def _log(lane) -> list[str]:
    """The same entries, from the lane's log."""
    shown = {ActionKind.STEP: "⏺ ", ActionKind.MESSAGE: "› you  "}
    return [shown[a.kind] + a.text for a in lane.actions if a.kind in shown]


def test_plain_text_in_the_chat_is_a_hint_and_the_transcript_shows_it():
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes_on("muddy-footprints")[0]

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.turns >= 3, "a few steps")
        selected = app.fleet.selected_lane
        assert lane.id != selected
        focus = await open_focus(pilot, app, lane.id)
        assert app.focused is focus.query_one("#chat", CommandBar).field
        assert _transcript(app) == _log(lane) and len(_log(lane)) == 3  # the whole log, in order, once
        await type_line(pilot, "try the PNG")
        assert lane.hints == ["try the PNG"]
        assert deck.lanes[selected].hints == []
        assert _transcript(app)[-1] == "› you  try the PNG"
        assert "sent, not read yet: try the PNG" in region_text(app, "#now")
        await step_until(pilot, app, lambda: not lane.hints, "the lane reads the message", limit=6)
        assert _transcript(app) == _log(lane)  # new entries appended, none repeated
        assert _transcript(app)[3] == "› you  try the PNG" and len(_log(lane)) > 4

    drive(app, script)


FOCUS_COMMANDS = [
    ("/redirect read src", lambda lane, deck: lane.plan == "read src"),
    ("/escalate", lambda lane, deck: lane.model == "sonnet"),
    ("/pause", lambda lane, deck: lane.state is LaneState.PAUSED),
    (
        "/kill park",
        lambda lane, deck: lane.state is LaneState.KILLED
        and deck.challenges[lane.challenge_id].status is ChallengeStatus.PARKED,
    ),
]


@pytest.mark.parametrize(("command", "done"), FOCUS_COMMANDS, ids=["redirect", "escalate", "pause", "kill-park"])
def test_focus_commands_act_on_the_open_lane(command, done):
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        selected = app.fleet.selected_lane
        lane = deck.lanes["L02"]
        assert lane.id != selected
        await open_focus(pilot, app, lane.id)
        before = {key: value for key, value in snapshot(app).items() if key != lane.id}
        assert not done(lane, deck)
        await send(pilot, app, command)
        assert done(lane, deck)
        assert {key: value for key, value in snapshot(app).items() if key != lane.id} == before

    drive(app, script)


def test_focus_approve_acts_on_the_open_lane():
    world, app = make("flag")
    deck = world.deck
    lane = deck.lanes_on("ticket-desk")[0]

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.pending is not None, "a candidate flag")
        other = next(x for x in deck.active_lanes() if x is not lane)
        app.fleet.select_lane(other.id)
        await open_focus(pilot, app, lane.id)
        assert "/approve" in region_text(app, "#now")
        await send(pilot, app, "/approve")
        assert lane.state is LaneState.SOLVED
        assert deck.challenges["ticket-desk"].status is ChallengeStatus.SOLVED
        assert other.state is LaneState.RUNNING
        assert "solved:" in region_text(app, "#now")

    drive(app, script)


def test_diff_shows_the_files_diff_and_moves_focus_to_the_files_list():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: "split_channels.py" in lane.files, "the lane writes a file")
        assert list(lane.files) == ["split_channels.py"]
        focus = await open_focus(pilot, app, lane.id)
        await send(pilot, app, "/diff")
        assert app.focused is focus.query_one("#files")
        diff = region_text(app, "#diff-scroll")
        assert "+++ b/split_channels.py" in diff and "@@ -0,0 +1," in diff

    drive(app, script)


def test_diff_of_a_file_the_lane_did_not_change_warns():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.files, "the lane writes a file")
        focus = await open_focus(pilot, app, lane.id)
        chat = focus.query_one("#chat", CommandBar).field
        await send(pilot, app, "/diff nope")
        assert_warning(app, f"{lane.id} has not changed nope")
        assert app.focused is chat  # still typing, not moved to the files

    drive(app, script)


def test_needs_you_card_shows_the_alert_and_its_redirect_until_it_is_answered():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.HINT) is not None, "off-hint alert")
        await open_focus(pilot, app, lane.id)
        card = region_text(app, "#now")
        assert "needs you now" in card
        assert "Ignores the hint" in card and "The description hints at slow-scan TV" in card
        assert "/redirect Decode static_hiss.wav as SSTV" in card
        await send(pilot, app, "/redirect use SSTV")
        card = region_text(app, "#now")
        assert "Ignores the hint" not in card and "/redirect" not in card
        assert "Nothing needs you on this lane" in card

    drive(app, script)


def test_the_others_strip_lists_lanes_needing_you_and_ctrl_n_opens_the_first():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        lane = _off_hint(world)
        assert lane.needs_you
        app.fleet.select_lane(deck.lanes_on("second-guess")[0].id)  # the fleet looks elsewhere
        await open_focus(pilot, app, lane.id)
        strip = region_text(app, "#others")
        listed = re.findall(r"▐(L\d+) ", strip)
        assert set(listed) == {x.id for x in deck.active_lanes() if x.needs_you and x is not lane}
        assert len(listed) == 2 and lane.id not in listed
        first = deck.lanes[listed[0]]
        assert first.pending is not None and first.pending.kind is PendingKind.SUBMIT  # a flag first
        await press(pilot, "ctrl+n")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == first.id
        assert f"{first.id} · Ticket Desk" in screen_text(app)
        assert lane.id in re.findall(r"▐(L\d+) ", region_text(app, "#others"))
        await press(pilot, "escape")  # back in the fleet, the lane last open is the selected one
        assert isinstance(app.screen, FleetScreen)
        assert app.fleet.selected_lane == first.id and cursor_key(app) == first.id

    drive(app, script)


def test_slash_menu_offers_the_lanes_suggestions_first_and_tab_fills_the_highlighted_one():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.HINT) is not None, "off-hint alert")
        suggestions = {s.key: s.text for s in lane.alert(AlertKind.HINT).suggestions}
        focus = await open_focus(pilot, app, lane.id)
        chat = focus.query_one("#chat", CommandBar)
        await press(pilot, "slash")
        assert chat.menu_open
        menu = region_text(app, "#menu").splitlines()
        entries = [line for line in menu if line.strip("│╭╮╰╯─ ")]
        assert f"/redirect {suggestions['r'][:30]}" in entries[0] and "suggested" in entries[0]
        assert f"/hint {suggestions['h']}" in entries[1] and "suggested" in entries[1]
        assert "suggested" not in entries[2]
        await press(pilot, "down")
        await press(pilot, "tab")
        assert chat.field.value == f"/hint {suggestions['h']}"

    drive(app, script)


def test_an_unknown_command_warns_in_the_status_line():
    world, app = make("sstv")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        before = len(world.deck.events)
        await send(pilot, app, "/nope")
        assert_warning(app, "Unknown command /nope")
        assert len(world.deck.events) == before

    drive(app, script)


# ---------------------------------------------------------------------- kickoff requirements


def test_attention_sort_keeps_lanes_that_need_you_on_top_after_every_tick():
    world, app = make("default")
    deck = world.deck
    selected = deck.lanes_on("second-guess")[0]  # runs quietly, then raises an alert and jumps up

    async def script(pilot):
        app.fleet.select_lane(selected.id)
        positions, needing = set(), set()
        for _ in range(30):
            await step(pilot, app)
            rows = [deck.lanes[key] for key in lane_rows(app)]
            assert all(not lane.finished for lane in rows)
            flags = [lane.needs_you for lane in rows]
            assert flags == sorted(flags, reverse=True), (world.ticks, [(x.id, x.needs_you) for x in rows])
            assert 0 < sum(flags) < len(flags)
            assert app.fleet.selected_lane == selected.id and cursor_key(app) == selected.id
            assert cell(app, "lanes", selected.id, "bar") == "▌"
            positions.add(lane_rows(app).index(selected.id))
            needing.add(sum(flags))
        assert len(positions) > 1  # the selected row moved, and the cursor followed it
        assert len(needing) > 1  # lanes started needing you during the run

    drive(app, script)


def test_wave_drop_shows_16_lane_rows_and_queues_the_rest():
    world, app = make("wave")

    async def script(pilot):
        assert lane_rows(app) == []
        await step_until(pilot, app, lambda: world.deck.challenges, "the wave drops", limit=5)
        rows = lane_rows(app)
        assert len(rows) == 16
        pane = region_text(app, "#lanes")
        assert all(lane_id in pane for lane_id in rows)  # every row is on screen
        assert "lanes 16/16 · queue 27" in region_text(app, "#header")
        assert "board 43" in region_text(app, "#board-pane")

    drive(app, script)


def test_max_lanes_holds_and_the_queue_drains_as_the_player_acts():
    world, app = make("sstv", max_lanes=2)
    deck = world.deck

    async def script(pilot):
        assert "lanes 2/2 · queue 2" in region_text(app, "#header")
        approved = killed = 0
        for _ in range(120):
            if not deck.queue:
                break
            app.step()
            assert len(deck.active_lanes()) <= 2 and len(lane_rows(app)) <= 2
            for lane in list(deck.active_lanes()):
                if lane.pending is not None:
                    app.fleet.select_lane(lane.id)
                    await press(pilot, "a")
                    approved += 1
                elif lane.needs_you:  # looping off the hint
                    app.fleet.select_lane(lane.id)
                    await press(pilot, "k", "p")
                    killed += 1
                assert len(deck.active_lanes()) <= 2
        await pilot.pause()
        assert deck.queue == []
        assert approved >= 1 and killed >= 1
        assert len(deck.lanes) == 4  # every challenge got its lane, two at a time
        assert "queue 0" in region_text(app, "#header")

    drive(app, script)


def test_team_mode_stops_a_lane_when_a_teammate_solves_its_challenge():
    world, app = make("team")
    deck = world.deck
    lane = deck.lanes_on("night-shift")[0]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await step_until(pilot, app, lambda: lane.finished, "the teammate's solve", limit=20)
        assert lane.state is LaneState.STOPPED
        assert cell(app, "board", "night-shift", "mark") == "✓"
        assert cell(app, "board", "night-shift", "own") == "wren"
        assert f"{lane.id} stopped: wren solved Night Shift" in region_text(app, "#why")

    drive(app, script)


def test_solo_mode_does_not_stop_the_lane():
    world, app = make("team", team=False)
    deck = world.deck
    lane = deck.lanes_on("night-shift")[0]

    async def script(pilot):
        await step_until(pilot, app, lambda: "wren solves night-shift" in world.skipped, "the teammate's solve", limit=20)
        assert lane.state is LaneState.RUNNING
        assert cell(app, "board", "night-shift", "mark") == "▶"
        assert cell(app, "board", "night-shift", "own") == lane.id
        assert " solo " in region_text(app, "#header")

    drive(app, script)


# ---------------------------------------------------------------------- rendering


def test_lane_rows_tick_live():
    world, app = make("sstv")
    lane = world.deck.lanes_on("bent-coin")[0]

    async def script(pilot):
        before = {c: cell(app, "lanes", lane.id, c) for c in ("turns", "cost", "last")}
        turns = lane.turns
        await step_until(pilot, app, lambda: lane.turns >= turns + 2, "two turns", limit=10)
        after = {c: cell(app, "lanes", lane.id, c) for c in ("turns", "cost", "last")}
        assert after["turns"] == str(lane.turns)
        assert after["last"] == lane.last_action
        assert all(after[c] != before[c] for c in after), (before, after)

    drive(app, script)


def test_finished_lanes_show_no_idle_time():
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes_on("muddy-footprints")[0]

    async def script(pilot):
        await step(pilot, app, 4)
        app.fleet.select_lane(lane.id)
        await press(pilot, "k", "p")
        await step(pilot, app, 4)
        app.fleet.select_lane(lane.id)  # expands the finished lanes
        await pilot.pause()
        assert lane.id in row_keys(app)
        assert cell(app, "lanes", lane.id, "idle") == "-"
        assert all(cell(app, "lanes", x.id, "idle") not in ("", "-") for x in deck.active_lanes())

    drive(app, script)


def test_cost_shows_a_dash_when_the_price_is_unknown():
    world, app = make("sstv")
    lane = world.deck.lanes_on("bent-coin")[0]

    async def script(pilot):
        await step(pilot, app, 2)
        assert cell(app, "lanes", lane.id, "cost").startswith("$")
        lane.dollars = None
        await step(pilot, app)
        assert cell(app, "lanes", lane.id, "cost") == "-"
        assert re.search(r"\$\d+\.\d\d\+", region_text(app, "#header"))  # the total says it is partial

    drive(app, script)


def test_challenge_text_is_shown_literally_and_cannot_steer_the_console():
    evil = Spec("evil", "web", "[b]X[/b]", 100, "Click [@click=app.quit]x[/] now \x1b[2J done", ("evil.zip",))
    scenario = Scenario(name="evil", summary="", specs=(evil,), timeline=((0, ReleaseAt(("evil",), "Board")),))
    world, app = make(scenario)

    async def script(pilot):
        (lane,) = world.deck.lanes_on("evil")
        assert cell(app, "board", "evil", "name") == "[b]X[/b]"
        assert cell(app, "lanes", lane.id, "chall") == "[b]X[/b]"
        app.fleet.select_challenge("evil")
        await pilot.pause()
        description = region_text(app, "#why").splitlines()[1]
        assert "Click [@click=app.quit]x[/] now ^[[2J done" in description
        assert "\x1b" not in screen_text(app)
        # Where markup would have put a clickable "x" (right after "Click "), a click does nothing.
        await pilot.click("#why", offset=(description.index("Click ") + len("Click "), 1))
        await pilot.pause()
        assert app.is_running
        await step(pilot, app, 3)
        assert app.is_running and isinstance(app.screen, FleetScreen)

    drive(app, script)


def test_narrow_terminal_keeps_idle_and_last_action_and_drops_the_model():
    world, app = make("default")

    async def script(pilot):
        lanes = columns(app, "lanes")
        assert {"idle", "last"} <= set(lanes) and "model" not in lanes
        await pilot.resize_terminal(*SIZE)
        await pilot.pause()
        assert "model" in columns(app, "lanes")
        await pilot.resize_terminal(*NARROW)
        await pilot.pause()
        lanes = columns(app, "lanes")
        assert {"idle", "last"} <= set(lanes) and "model" not in lanes
        assert "idle" in region_text(app, "#lanes").splitlines()[0]  # the header row is drawn

    drive(app, script, size=NARROW)


def test_header_counts_the_lanes_that_need_you():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        need = [lane for lane in deck.active_lanes() if lane.needs_you]
        assert len(need) == 3
        assert "▲ 3 need you" in region_text(app, "#header")
        flag = next(lane for lane in need if lane.pending is not None)
        app.fleet.select_lane(flag.id)
        await press(pilot, "a")
        assert "▲ 2 need you" in region_text(app, "#header")

    drive(app, script)


def test_header_says_all_clear_when_no_lane_needs_you():
    world, app = make("sstv")

    async def script(pilot):
        assert not any(lane.needs_you for lane in world.deck.lanes.values())
        header = region_text(app, "#header")
        assert "all clear" in header and "need you" not in header

    drive(app, script)


@pytest.mark.parametrize("name", list(scenarios.SCENARIOS))
def test_every_scenario_opens_and_runs_30_ticks_in_the_console(name):
    world, app = make(name)
    deck = world.deck

    async def script(pilot):
        for tick in range(1, 31):
            app.step()  # the views are rebuilt on every tick...
            if tick % 5 == 0:
                await pilot.pause()  # ...and drawn every fifth (the attention test draws every one)
        assert app.is_running and isinstance(app.screen, FleetScreen)
        active = deck.active_lanes()
        assert sorted(lane_rows(app)) == sorted(lane.id for lane in active)
        assert (FINISHED_ROW in row_keys(app)) == any(lane.finished for lane in deck.lanes.values())
        header = region_text(app, "#header")
        assert f"lanes {len(active)}/{deck.config.max_lanes} · queue {len(deck.queue)}" in header

    drive(app, script)


def test_the_console_redraws_on_its_own_timer_when_lanes_report_without_it():
    """The M1 seam: no mock clock in the app; the world moves on its own and the console catches up."""
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, refresh_seconds=0.05)
    lane = world.deck.lanes_on("bent-coin")[0]

    async def redrawn(pilot, cond) -> None:
        """Real time is the point here: wait, at most ~0.3 s, for the console's own timer."""
        for _ in range(30):
            if cond():
                return
            await pilot.pause(0.01)
        assert cond(), "the console did not redraw on its own timer"

    async def script(pilot):
        assert cell(app, "lanes", lane.id, "turns") == "0"
        world.tick(3)
        assert lane.turns > 0
        await redrawn(pilot, lambda: cell(app, "lanes", lane.id, "turns") == str(lane.turns))
        row = next(line for line in region_text(app, "#lanes").splitlines() if f"{lane.id} " in line)
        assert re.search(rf"\brun\s+{lane.turns}\s", row), row
        # Leave right after a redraw, away from the next one: a redraw that lands while Textual
        # tears the app down raises NoMatches (refresh_view has no shutdown guard).
        world.tick()
        header = app.fleet.query_one("#header", Static)
        await redrawn(pilot, lambda: fmt.clock(world.deck.now) in str(header.content))

    drive(app, script)
