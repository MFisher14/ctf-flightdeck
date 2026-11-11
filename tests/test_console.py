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
import os
import re
import signal

import pytest
from rich.cells import cell_len
from textual import events
from textual.containers import ScrollableContainer
from textual.widgets import DataTable, RichLog, Select, Static

from ctf_flightdeck import fmt
from ctf_flightdeck.console import room, theme, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.fleet import key_room as fleet_key_room
from ctf_flightdeck.console.focus import KEY_LABELS as FOCUS_KEYS
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import ChallengeCard, ForkPrompt, HelpScreen, KillPrompt, QuitPrompt, TakeOverScreen
from ctf_flightdeck.console.views import FINISHED_ROW
from ctf_flightdeck.console.widgets import CommandBar
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.attention import SortMode
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import (
    ME,
    ActionKind,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    DeckConfig,
    EventKind,
    FileChange,
    LaneState,
    Pending,
    PendingKind,
    Suggestion,
)
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.scenarios import DEEP_ARCHIVE, ReleaseAt, Scenario, Spec
from ctf_flightdeck.mock.world import FakeWorld, ManualClock
from deadline import within

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


def prompt_text(app: FlightdeckApp) -> str:
    """What the open modal says, as one line: its border, buttons' edges, a scrollbar's thumb
    (which can sit at the end of any row of text) and line breaks left out."""
    return " ".join(re.sub(r"[│╭╮╰╯─▔▁▂▃▄▅▆▇█]", " ", region_text(app, "Vertical")).split())


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


def test_in_a_run_help_and_the_command_menu_say_what_take_over_and_decline_do_and_they_do_it():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), flag_format=r"t\{[a-z]+\}"))
    deck.release([Challenge("alpha", "Alpha", "misc", 50), Challenge("bravo", "Bravo", "misc", 50)],
                 [QueueEntry("alpha", "glm"), QueueEntry("bravo", "glm")])
    flagged, costly = deck.lanes_on("alpha")[0], deck.lanes_on("bravo")[0]
    deck.report(flagged.id, TurnReport(flag="t{alpha}"))
    deck.report(costly.id, TurnReport(pending=Pending(PendingKind.BUDGET, "raise the cap by 50%")))

    async def on_exit():
        pass

    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=on_exit)  # a run's console: no mock clock

    async def script(pilot):
        await press(pilot, "question_mark")
        text = prompt_text(app)
        assert "placeholder" not in text
        assert ("Take over: a shell in the lane's workspace (its container in Docker); exit it to hand back, "
                "and the lane hears what you changed") in text
        assert ("Decline it: the flag is not submitted, or the live box stays off limits, and the lane carries on; "
                "refusing more budget stops the lane") in text
        assert "Quit. While lanes are open it asks first: y stops every lane for good (a run cannot be resumed)" in text
        await press(pilot, "escape")
        for typed, shown in (("/take", "/takeover a shell in the lane's workspace; exit it to hand the lane back"),
                             ("/decl", "/decline say no: not submitted, or off the box (the lane carries on); no more budget (it stops)")):
            bar(app).start(typed)
            await pilot.pause()
            assert shown in " ".join(region_text(app, "#bar").split())
            await press(pilot, "escape")
        assert deck.apply(iv.Decline(flagged.id)).ok and flagged.state is LaneState.RUNNING  # carries on
        assert deck.apply(iv.Decline(costly.id)).ok and costly.state is LaneState.STOPPED  # stops

    drive(app, script)


def test_in_the_mock_help_says_take_over_is_a_placeholder_there_and_quitting_does_not_ask():
    world, app = make("sstv")

    async def script(pilot):
        await press(pilot, "question_mark")
        text = prompt_text(app)
        assert "Take over: in the mock, a placeholder screen (a real run opens a shell in the lane's workspace)" in text
        assert "Quit (the mock has nothing to stop, so it never asks)" in text and "asks first" not in text

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


def assert_whole_transcript(focus: FocusScreen, lane) -> None:
    """The transcript holds every step and message of `lane`, once and in order, scrolled
    out of view or not (a long entry wraps: its first line starts it)."""
    lines = [strip.text.strip() for strip in focus.query_one("#transcript", RichLog).lines]
    got = [line for line in lines if line.startswith(("⏺ ", "› you  "))]
    want = _log(lane)
    assert len(got) == len(want), (len(got), len(want))
    assert all(w.startswith(g) for g, w in zip(got, want)), list(zip(got, want))


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


def _strip_lanes(app: FlightdeckApp) -> list[str]:
    """The lanes named by the chips in the focus view's others strip, left to right."""
    return re.findall(r"\b(L\d\d) [a-z]+\b", region_text(app, "#others"))


def test_the_others_strip_lists_lanes_needing_you_and_ctrl_n_visits_each_in_turn():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        lane = _off_hint(world)
        assert lane.needs_you
        app.fleet.select_lane(deck.lanes_on("second-guess")[0].id)  # the fleet looks elsewhere
        await open_focus(pilot, app, lane.id)
        need = [x.id for x in deck.needing()]
        assert len(need) == 3 and need.index(lane.id) == 1  # one lane more urgent, one less
        assert _strip_lanes(app) == [x for x in need if x != lane.id]  # attention order, this lane left out
        flag = deck.lanes[need[0]]
        assert flag.pending is not None and flag.pending.kind is PendingKind.SUBMIT  # a flag first
        # ctrl+n goes on from the open lane in attention order and wraps round to the first,
        # so it reaches every lane, not just the two most urgent
        visited = []
        for _ in need:
            await press(pilot, "ctrl+n")
            assert isinstance(app.screen, FocusScreen)
            visited.append(app.screen.lane_id)
            if app.screen.lane_id == flag.id:
                assert f"{flag.id} · Ticket Desk" in screen_text(app)
                assert lane.id in _strip_lanes(app)
        assert visited == [need[2], need[0], need[1]]
        await press(pilot, "escape")  # back in the fleet, the lane last open is the selected one
        assert isinstance(app.screen, FleetScreen)
        assert app.fleet.selected_lane == lane.id and cursor_key(app) == lane.id

    drive(app, script)


def test_ctrl_n_on_the_most_urgent_lane_moves_on_and_says_so_when_no_other_lane_needs_you():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        need = [x.id for x in deck.needing()]
        await open_focus(pilot, app, need[0])
        await press(pilot, "ctrl+n")
        assert app.screen.lane_id == need[1]  # never the lane already open
        for other in need[1:]:  # answer the others (both are course alerts): only the flag lane is left
            assert deck.lanes[other].pending is None
            assert app.apply(iv.Redirect(other, "read the handout again")).ok
        assert [x.id for x in deck.needing()] == need[:1]
        await open_focus(pilot, app, need[0])
        await press(pilot, "ctrl+n")
        assert app.screen.lane_id == need[0]
        assert "No other lane needs you right now" in status_line(app)

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
        lane.known_dollars = 0.0
        app.refresh_view()  # redraw without moving the mock clock (its lane would report more spend)
        await pilot.pause()
        assert cell(app, "lanes", lane.id, "cost") == "-"  # nothing known
        lane.known_dollars = 0.5
        app.refresh_view()
        await pilot.pause()
        assert cell(app, "lanes", lane.id, "cost") == "$.50+"  # the known part, and more unpriced
        assert re.search(r"\$\d+\.\d\d\+", region_text(app, "#header"))  # the total says it is partial

    drive(app, script)


def test_cost_is_not_a_settled_number_while_a_cli_turn_is_under_way():
    """A coding-agent CLI reports what a turn cost only when the turn ends: until then the lane's
    cost cell and its focus view say more is to come, rather than show a settled $0.00."""
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes_on("bent-coin")[0]

    async def script(pilot):
        known = lane.dollars
        deck.report(lane.id, TurnReport(action="claude: $ ls", tokens=300, dollars_later=True))
        app.refresh_view()
        await pilot.pause()
        assert cell(app, "lanes", lane.id, "cost") == f"${fmt.dollars(known, short=True)}…"
        screen = await open_focus(pilot, app, lane.id)
        assert f"${fmt.dollars(known)}… (this turn's cost comes when it ends)" in str(screen.query_one("#talk-pane").border_title)
        app.show_fleet()
        await pilot.pause()
        deck.report(lane.id, TurnReport(turn=False, tokens=50, dollars=0.25, turn_end=True))  # the CLI's report at the turn's end
        app.refresh_view()
        await pilot.pause()
        assert cell(app, "lanes", lane.id, "cost") == f"${fmt.dollars(known + 0.25, short=True)}"
        lane.dollars, lane.known_dollars = None, 0.5  # some spend had no price, and another turn is under way
        deck.report(lane.id, TurnReport(action="claude: $ cat", dollars_later=True))
        app.refresh_view()
        await pilot.pause()
        assert cell(app, "lanes", lane.id, "cost") == "$.50+…"

    drive(app, script)


def test_the_cost_column_draws_its_markers_whole_so_a_cost_over_ten_dollars_never_reads_as_settled():
    """What is drawn, not only the cell's value: "+" (some spend had no price) and "…" (a
    coding-agent CLI's turn is under way, its cost to come) are never cut off by the column."""
    world, app = make("sstv")
    lane = world.deck.lanes_on("bent-coin")[0]

    async def script(pilot):
        for dollars, known, later, drawn in (
            (12.34, 12.34, True, "$12.34…"),
            (None, 12.30, False, "$12.30+"),
            (None, 12.30, True, "$12.30+…"),
            (None, 1.23, True, "$1.23+…"),
            (99.99, 99.99, True, "$99.99…"),
            (None, 0.001, True, "$<.01+…"),
            (None, 1234.0, True, "$1234+…"),
        ):
            lane.dollars, lane.known_dollars, lane.dollars_later = dollars, known, later
            app.refresh_view()  # redraw without moving the mock clock (its lanes would report more spend)
            await pilot.pause()
            assert cell(app, "lanes", lane.id, "cost") == drawn
            (row,) = [line for line in region_text(app, "#lanes").splitlines() if f" {lane.id} " in line]
            assert f" {drawn} " in row, row

    drive(app, script)


def test_spend_a_cli_reports_after_its_lane_ended_shows_in_the_lanes_row_and_the_headers_total():
    """A coding-agent CLI reports a turn's cost when the turn ends, often after its lane has
    (killed, or solved mid-turn): the finished lane's row and the run's total count it."""
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes_on("bent-coin")[0]

    async def script(pilot):
        deck.report(lane.id, TurnReport(action="claude: $ ls", tokens=300, dollars_later=True))  # a CLI turn under way
        assert deck.apply(iv.Kill(lane.id, requeue=False)).ok and lane.finished
        app.refresh_view()  # redraw without moving the mock clock (its lanes would report more spend)
        await pilot.pause()
        app.fleet.select_lane(lane.id)  # expands the finished lanes
        await pilot.pause()
        known, total = lane.dollars, deck.totals()[1]
        assert cell(app, "lanes", lane.id, "cost") == f"${fmt.dollars(known, short=True)}…"  # its cost is still to come
        assert f"${fmt.dollars(total)}" in region_text(app, "#header")
        deck.report(lane.id, TurnReport(turn=False, tokens=50, dollars=1.25, turn_end=True, model=lane.model, why="cut"))
        app.refresh_view()
        await pilot.pause()
        assert cell(app, "lanes", lane.id, "cost") == f"${fmt.dollars(known + 1.25, short=True)}"
        assert f"${fmt.dollars(total + 1.25)}" in region_text(app, "#header")

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


SHOWN_KEYS = {f"{b.key_display or b.key} {b.description}" for b in FleetScreen.BINDINGS if b.show}


def check_key_line(app: FlightdeckApp, width: int) -> list[str]:
    """The fleet's key line fits, shows only whole keys, and keeps the ones a player must find."""
    line = footer_line(app).strip()
    pairs = line.split("  ")
    assert cell_len(line) <= width - 2 and "…" not in line, line
    assert set(pairs) <= SHOWN_KEYS, line  # nothing cut in half
    for needed in ("? help", "a approve", "d decline", "/ commands", "q quit"):
        assert needed in pairs, (needed, line)
    return pairs


@pytest.mark.parametrize("scenario", ["sstv", "team"])
@pytest.mark.parametrize("size", [(80, 24), (100, 30), (120, 40), SIZE], ids=["80x24", "100x30", "120x40", "160x46"])
def test_the_key_line_always_shows_help_quit_and_the_answers_and_only_whole_keys(scenario, size):
    world, app = make(scenario)

    async def script(pilot):
        pairs = check_key_line(app, size[0])
        if size == SIZE:
            assert len(pairs) == len(SHOWN_KEYS) - (0 if world.deck.config.team else 1)  # all of them (claim: team only)

    drive(app, script, size)


def test_the_key_line_fits_again_when_the_terminal_is_resized():
    world, app = make("sstv")

    async def script(pilot):
        everything = check_key_line(app, SIZE[0])
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        assert len(check_key_line(app, 80)) < len(everything)
        await pilot.resize_terminal(*SIZE)
        await pilot.pause()
        assert check_key_line(app, SIZE[0]) == everything

    drive(app, script)


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


# ---------------------------------------------------------------------- untrusted text, end to end


def terminal_frame(app: FlightdeckApp) -> str:
    """Everything the driver would write to a real terminal to draw the current screen,
    escape sequences included (a full update, rendered the way Textual's driver gets it)."""
    update = app.screen._compositor.render_update(full=True, screen_stack=app._background_screens)
    return update.render_segments(app.console)


OSC = "\x1b]0;"  # the start of an operating system command: set title, write the clipboard


def osc(tag: str) -> str:
    """A payload a real terminal would act on; untrusted() shows it as ^[]0;<tag>^[\\."""
    return f"{OSC}{tag}\x1b\\"


def shown(tag: str) -> str:
    return f"^[]0;{tag}"


def wrong_flag(challenge_id: str, flag: str) -> bool:
    """A platform that rejects every flag."""
    return False


def quiet_deck(config: DeckConfig) -> Deck:
    return Deck(config, QuietDriver(), ManualClock(1000.0), wrong_flag)


class QuietDriver:
    """A lane driver that does no work: the test reports the lanes' turns itself."""

    def attach(self, deck): ...
    def start(self, lane, challenge): ...
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def rejected(self, lane, flag): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...


def test_lane_and_challenge_text_never_reaches_the_terminal_raw_anywhere_it_is_drawn():
    """Every field a platform, a lane or a model can fill carries its own escape-sequence
    payload. At each stop (fleet, menu, prefilled bar and prompts, card, focus view, diff)
    the frame sent to the terminal has none of them raw, and the stop shows them, made
    visible."""
    deck = quiet_deck(DeckConfig(event="ev", team=True, models=("glm", "big")))
    evil = Challenge(
        "evil", "Evil " + osc("nm"), "web" + osc("ct"), 100, solves=5,
        description="desc " + osc("ds"), files=("f" + osc("fl"),), note="note " + osc("nt"),
    )
    calm = Challenge("calm", "Calm", "misc", 50)
    loud = Challenge("loud", "Loud", "misc", 50)
    deck.release([evil, calm, loud], [QueueEntry("evil", "glm"), QueueEntry("calm", "glm"), QueueEntry("loud", "glm")])
    lane, other, third = deck.lanes_on("evil")[0], deck.lanes_on("calm")[0], deck.lanes_on("loud")[0]
    deck.report(lane.id, TurnReport(
        action="run " + osc("ac"), output="out " + osc("ou"), plan="plan " + osc("pl"),
        files=(FileChange("solve" + osc("pa") + ".py", "+++ b/solve.py\n+x " + osc("df") + "\n", status="odd" + osc("st")),),
        alerts=(Alert(AlertKind.HINT, "why " + osc("rs"), (
            Suggestion("r", "Redirect " + osc("rl"), "decode it " + osc("rt") + "\nnext row"),
            Suggestion("h", "Hint " + osc("hl"), "think " + osc("ht")),
            Suggestion("f", "Fork " + osc("fk"), "fork it " + osc("ft")),
            Suggestion("", "Or wait " + osc("wl")),
        )),),
        flag="flag{" + osc("fg") + "}",
    ))
    deck.report(other.id, TurnReport(pending=Pending(PendingKind.LIVE_BOX, "connect " + osc("bx"))))
    deck.report(third.id, TurnReport(alerts=(Alert(AlertKind.LOOP, "again " + osc("r2"), (
        Suggestion("h", "Hint " + osc("l2"), "stop"),
        Suggestion("", "Or wait " + osc("w2")),
    )),)))
    assert lane.pending.kind is PendingKind.SUBMIT  # the candidate fits the default flag format
    app = FlightdeckApp(deck, refresh_seconds=None)
    deck.teammate_claim("calm", "mate" + osc("tm"))  # its event goes to the status line

    async def check(pilot, stop: str, *tags: str) -> None:
        await pilot.pause()
        raw = terminal_frame(app)
        assert OSC not in raw, f"{stop}: a payload reached the terminal raw"
        text = screen_text(app)
        missing = [tag for tag in tags if shown(tag) not in text]
        assert not missing, f"{stop}: {missing} not shown"

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await check(pilot, "fleet", "fg", "tm")  # the flag in the why line; the claim in the status line
        await press(pilot, "slash")
        await check(pilot, "fleet menu", "rt", "fg", "ht", "ft")
        menu = [line.strip(" │") for line in region_text(app, "#menu").splitlines()]
        assert not [line for line in menu if line.startswith("next row")]  # a newline makes no row of its own
        for key, tag in (("r", "rt"), ("h", "ht")):
            await press(pilot, "escape", "escape", key)
            assert shown(tag) in bar(app).field.value and "\x1b" not in bar(app).field.value
            await check(pilot, f"fleet {key}", tag)
        await press(pilot, "escape", "escape", "f")
        assert isinstance(app.screen, ForkPrompt)
        await check(pilot, "fork prompt", "ft")
        await press(pilot, "escape")
        app.fleet.select_lane(other.id)
        await check(pilot, "fleet, live-box lane", "bx")
        app.fleet.select_lane(third.id)  # no approval: the why line lists the alert's answers
        await check(pilot, "fleet, alert lane", "r2", "l2", "w2")
        assert app.apply(iv.Fork(lane.id, approach="a second look")).ok  # two lanes: enter shows the card
        app.fleet.select_challenge("evil")
        await press(pilot, "enter")
        assert isinstance(app.screen, ChallengeCard)
        await check(pilot, "card", "nm", "ct", "ds", "fl", "nt")
        await press(pilot, "escape")
        await open_focus(pilot, app, lane.id)
        await check(pilot, "focus", "nm", "ct", "ac", "ou", "pl", "rs", "rl", "wl", "pa", "st")
        await press(pilot, "slash")
        await check(pilot, "focus menu", "rt", "fg")
        await press(pilot, "escape", "escape")
        await send(pilot, app, "/diff")
        await check(pilot, "diff", "df", "pa")

    drive(app, script)


def test_model_names_in_the_fork_prompt_are_text_not_markup():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm", "[b]bold[/b]", "[@click=app.quit]x[/]")))
    deck.release([Challenge("c", "C", "misc", 50)], [QueueEntry("c", "glm")])
    app = FlightdeckApp(deck, refresh_seconds=None)

    async def script(pilot):
        await press(pilot, "f")
        prompt = app.screen
        assert isinstance(prompt, ForkPrompt)
        assert "[b]bold[/b]" in screen_text(app)  # the default fork model, shown as typed
        select = prompt.query_one(Select)
        await press(pilot, "tab", "enter")  # open the model list
        assert select.expanded
        text = screen_text(app)
        assert "[@click=app.quit]x[/]" in text and "[b]bold[/b]" in text

    drive(app, script)


# Made-up keys, built from pieces so no line here is shaped like a real one (.githooks/secret_scan.py).
OPENROUTER = "sk-" + "or-v1-" + "5f" * 32
GITHUB = "ghp" + "_" + "a1B2" * 9
ANTHROPIC = "sk-" + "ant-api03-" + "Qx7-" * 20
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.bm90LWEtcmVhbC1zaWduYXR1cmU"
VALUES = ("5f" * 32, "a1B2" * 9, "Qx7-" * 20, JWT)  # the part of each that would show if it were drawn


def test_what_a_lane_did_is_shown_without_its_credentials_and_the_deck_keeps_it_as_it_was():
    """A host lane that read the player's keys: its step and its output, its plan, the alert
    quoting an output and the diff of a file it wrote show each credential's name and not its
    value, in the fleet (the last-action cell, the why line) and in the focus view (the
    transcript, the plan, the needs-you card, the diff), as its transcript file keeps them. A
    flag shaped like a credential stays whole once the run knows it. The deck keeps what the
    lane did as it was, for the lane's model, which has read it already."""
    flag = "t{TOKEN=c0ffee}"
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), flag_format=r"t\{[^{}\s]+\}"))
    deck.release([Challenge("c", "C", "misc", 50)], [QueueEntry("c", "glm")])
    (lane,) = deck.lanes_on("c")
    deck.report(lane.id, TurnReport(action=f"submit {flag}", flag=flag))
    assert deck.apply(iv.Decline(lane.id)).ok  # the run knows the flag now, and the lane carries on
    curl = f"curl -H 'Authorization: Bearer {JWT}' 127.0.0.1"
    diff = f"+++ b/env.txt\n+ANTHROPIC_API_KEY={ANTHROPIC}\n"
    deck.report(lane.id, TurnReport(action=curl, output=f"OPENROUTER_API_KEY={OPENROUTER}", plan=f"log in with GITHUB_TOKEN={GITHUB}",
                                    files=(FileChange("env.txt", diff, "added"),)))
    app = FlightdeckApp(deck, refresh_seconds=None)
    reason = f"The same output came back twice: OPENROUTER_API_KEY={OPENROUTER}"

    def nothing_raw(stop: str) -> None:
        frame = terminal_frame(app)
        assert not [value for value in VALUES if value in frame], f"{stop}: a credential's value is drawn"

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await pilot.pause()
        nothing_raw("fleet")
        assert cell(app, "lanes", lane.id, "last") == "curl -H 'Authorization: Bearer [redacted]' 127.0.0.1"
        assert views.lane_why(deck, lane).plain == (
            f"▌{lane.id} plan: log in with GITHUB_TOKEN=[redacted]\n"
            "  last: curl -H 'Authorization: Bearer [redacted]' 127.0.0.1 → OPENROUTER_API_KEY=[redacted]   enter open"
        )
        assert "plan: log in with GITHUB_TOKEN=[redacted]" in region_text(app, "#why")
        deck.report(lane.id, TurnReport(action="cat keys.env", output=f"OPENROUTER_API_KEY={OPENROUTER}",
                                        alerts=(Alert(AlertKind.LOOP, reason),)))
        app.refresh_view()
        await pilot.pause()
        nothing_raw("fleet, the alert")
        assert "▲ Loop: The same output came back twice: OPENROUTER_API_KEY=[redacted]" in region_text(app, "#why")
        focus = await open_focus(pilot, app, lane.id)
        nothing_raw("focus")
        lines = [strip.text.strip() for strip in focus.query_one("#transcript", RichLog).lines]
        assert [line for line in lines if line.startswith(("⏺", "⎿", "The same"))] == [
            f"⏺ submit {flag}",
            "⏺ curl -H 'Authorization: Bearer [redacted]' 127.0.0.1",
            "⎿  OPENROUTER_API_KEY=[redacted]",
            "⏺ cat keys.env",
            "⎿  OPENROUTER_API_KEY=[redacted]",
            "The same output came back twice: OPENROUTER_API_KEY=[redacted]",
        ]
        assert "plan log in with GITHUB_TOKEN=[redacted]" in screen_text(app)  # under the transcript, on its border
        assert "Loop  The same output came back twice: OPENROUTER_API_KEY=[redacted]" in region_text(app, "#now")
        await send(pilot, app, "/diff")
        nothing_raw("diff")
        assert "+ANTHROPIC_API_KEY=[redacted]" in region_text(app, "#diff-scroll")

    drive(app, script)
    assert [(a.text, a.output) for a in lane.actions if a.kind is ActionKind.STEP][1:] == [
        (curl, f"OPENROUTER_API_KEY={OPENROUTER}"), ("cat keys.env", f"OPENROUTER_API_KEY={OPENROUTER}"),
    ]
    assert lane.plan == f"log in with GITHUB_TOKEN={GITHUB}" and lane.files["env.txt"].diff == diff
    assert lane.alerts[0].reason == reason


def test_a_megabyte_of_keys_is_taken_out_once_not_on_every_refresh():
    """Taking credentials out costs time in proportion to the text: a megabyte that is all keys
    takes a few tenths of a second. The fleet draws each lane's last action and the selected
    lane's why line again on every refresh, twice a second, and the focus view its open diff:
    what was taken out is kept, so fifty refreshes of a lane whose last step printed a
    megabyte of keys into its output and a file stay well inside the deadline, the first
    included, and none of them shows a key."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",)))
    deck.release([Challenge("c", "C", "misc", 50)], [QueueEntry("c", "glm")])
    (lane,) = deck.lanes_on("c")
    row = f"OPENROUTER_API_KEY={OPENROUTER}\n"
    keys = row * (1_000_000 // len(row))
    deck.report(lane.id, TurnReport(action="env; env > env.txt", output=keys,
                                    files=(FileChange("env.txt", "+++ b/env.txt\n" + keys, "added"),)))
    with within(10, "fifty refreshes of the fleet and the open diff"):
        for _ in range(50):
            cells, why = views.lane_cells(deck, lane), views.lane_why(deck, lane)
            diff = views.diff_view(deck, lane, lane.files["env.txt"])
    assert why.plain.startswith(f"▌{lane.id} plan: -\n  last: env; env > env.txt → OPENROUTER_API_KEY=[redacted] ⏎ OPENROUTER")
    assert "5f" * 32 not in why.plain + cells["last"].plain + diff.code
    assert diff.code.count("OPENROUTER_API_KEY=[redacted]\n") == keys.count("\n")


# ---------------------------------------------------------------------- review fixes: the fleet


def _board_cursor(app: FlightdeckApp) -> str | None:
    board = table(app, "board")
    return board.coordinate_to_cell_key(board.cursor_coordinate).row_key.value if board.row_count else None


def _queue_keys(app: FlightdeckApp, *keys: str) -> None:
    """Queue key presses the way one terminal read delivers them: all before the first is handled."""
    for key in keys:
        app._driver.send_message(events.Key(key, "\r" if key == "enter" else key))


@pytest.mark.parametrize("where", ["lanes", "board"])
def test_two_enters_that_arrive_together_open_the_lane_once_and_do_not_crash(where):
    world, app = make("default")
    deck = world.deck
    lane = deck.lanes_on("paper-trail")[0]  # its challenge has one lane, so enter on the board opens it

    async def script(pilot):
        if where == "lanes":
            app.fleet.select_lane(lane.id)
        else:
            app.fleet.select_challenge("paper-trail")
        await pilot.pause()
        _queue_keys(app, "enter", "enter")
        await pilot.pause()
        await pilot.pause()
        assert app.is_running
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == lane.id
        assert sum(isinstance(s, FocusScreen) for s in app.screen_stack) == 1
        assert_whole_transcript(app.screen, lane)  # drawn in full, once

    drive(app, script)


def test_arrow_keys_on_the_lanes_move_the_board_to_that_lanes_challenge():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        first = cursor_key(app)
        assert _board_cursor(app) == deck.lanes[first].challenge_id
        await press(pilot, "down")
        lane = deck.lanes[cursor_key(app)]
        assert lane.id != first and lane.challenge_id != deck.lanes[first].challenge_id
        assert app.fleet.selected_challenge == lane.challenge_id == _board_cursor(app)
        await press(pilot, "tab", "tab")  # bar, board: the why line is about that challenge
        assert app.fleet.board_focused
        assert deck.challenges[lane.challenge_id].name in region_text(app, "#why")

    drive(app, script)


def test_the_lane_list_keeps_its_scroll_position_when_its_rows_are_rebuilt():
    world, app = make("wave")

    async def script(pilot):
        await step_until(pilot, app, lambda: world.deck.challenges, "the wave drops", limit=5)
        lanes = table(app, "lanes")
        assert lanes.max_scroll_y > 0  # 16 rows do not fit 24 lines
        await press(pilot, *["down"] * 16)  # to the end of the list...
        await press(pilot, *["up"] * 9)  # ...then back up: the cursor sits high in a scrolled list
        y = lanes.scroll_y
        assert y > 0 and lanes.cursor_coordinate.row < 16 - 9 + 1
        app.fleet.set_filter("")  # rebuilds every row
        await pilot.pause()
        assert lanes.scroll_y == y

    drive(app, script, size=(160, 24))


def test_going_back_to_the_fleet_from_a_lane_the_filter_hides_clears_the_filter_and_selects_it():
    world, app = make("default")
    lane = world.deck.lanes_on("static-hiss")[0]

    async def script(pilot):
        app.fleet.set_filter("zzz")
        await pilot.pause()
        assert lane.id not in lane_rows(app)
        await open_focus(pilot, app, lane.id)
        await press(pilot, "escape")
        assert app.is_running and isinstance(app.screen, FleetScreen)
        assert app.fleet.filter_text == ""
        assert app.fleet.selected_lane == lane.id and cursor_key(app) == lane.id

    drive(app, script)


def test_the_lanes_title_counts_lanes_needing_you_that_the_filter_hides():
    world, app = make("default")

    async def script(pilot):
        assert "hidden" not in region_text(app, "#lanes-pane").splitlines()[0]
        app.fleet.set_filter("zzz")
        await pilot.pause()
        assert "3 needing you hidden" in region_text(app, "#lanes-pane").splitlines()[0]
        app.fleet.set_filter("flag")  # the lane with a candidate flag shows; two that need you do not
        await pilot.pause()
        assert "2 needing you hidden" in region_text(app, "#lanes-pane").splitlines()[0]

    drive(app, script)


def test_the_fleet_bar_acts_on_the_lane_the_keys_point_at():
    world, app = make("default")
    deck = world.deck
    on_board = deck.lanes_on("paper-trail")[0]
    selected = deck.lanes_on("ticket-desk")[0]

    async def script(pilot):
        app.fleet.select_lane(selected.id)
        app.fleet.select_challenge("paper-trail")  # the board points at a challenge with one lane
        await pilot.pause()
        expected = [c for c, _ in app.command_suggestions(on_board.id, with_lane=True)]
        assert [c for c, _ in bar(app).suggestions] == expected  # its suggestions, not the selected lane's
        bar(app).start("/pause")
        await press(pilot, "enter")
        assert on_board.state is LaneState.PAUSED and selected.state is not LaneState.PAUSED
        assert app.focused is table(app, "board")  # back where the bar was opened from

    drive(app, script)


def test_the_fleet_bar_refuses_a_lane_the_filter_hides_like_the_keys_do():
    world, app = make("default")
    lane = world.deck.lanes_on("ticket-desk")[0]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        app.fleet.set_filter("zzz")
        await pilot.pause()
        state, hints = lane.state, list(lane.hints)
        bar(app).start("try harder")
        await press(pilot, "enter")
        assert_warning(app, f"{lane.id} is hidden by the filter; esc clears it")
        bar(app).start("/pause")
        await press(pilot, "enter")
        assert (lane.state, lane.hints) == (state, hints)

    drive(app, script)


def test_the_fleet_bar_suggests_for_the_lane_selected_now():
    world, app = make("default")
    deck = world.deck
    first, second = [x.id for x in deck.needing()][:2]

    async def script(pilot):
        app.fleet.select_lane(first)
        await press(pilot, "slash", "escape", "escape")
        app.fleet.select_lane(second)
        await pilot.pause()
        await press(pilot, "tab")  # to the bar, without '/'
        assert app.focused is bar(app).field
        await press(pilot, "slash")
        suggested = [c.text for c in bar(app).completions if c.suggested]
        assert suggested and all(second in text for text in suggested)

    drive(app, script)


def test_enter_on_an_empty_fleet_bar_opens_the_selected_lane():
    world, app = make("default")
    lane = world.deck.lanes_on("ticket-desk")[0]

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        bar(app).start("")
        await press(pilot, "enter")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == lane.id

    drive(app, script)


def test_enter_on_a_partial_command_completes_it_instead_of_running_it():
    world, app = make("sstv")

    async def script(pilot):
        await press(pilot, "slash", *"fil", "enter")
        assert bar(app).field.value == "/filter " and app.fleet.filter_text == ""
        assert "Unknown command" not in status_line(app)
        await type_line(pilot, "bent")
        assert app.fleet.filter_text == "bent"

    drive(app, script)


@pytest.mark.parametrize(
    "text, warning",
    [
        ("/approve 2", "/approve takes no argument; name a lane like /approve L02"),
        ("/pause please", "/pause takes no argument; name a lane like /pause L02"),
        ("/open foo", "/open takes a lane, like /open L02"),
        ("/kill parkk", "/kill takes nothing (re-queue fresh) or 'park'"),
    ],
)
def test_a_command_with_a_stray_argument_warns_and_changes_nothing(text, warning):
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        flag = next(x for x in deck.active_lanes() if x.pending is not None and x.pending.kind is PendingKind.SUBMIT)
        app.fleet.select_lane(flag.id)
        before, n_events = snapshot(app), len(interventions(app))
        bar(app).start(text)
        await press(pilot, "enter")
        assert_warning(app, warning)
        assert isinstance(app.screen, FleetScreen)
        assert snapshot(app) == before and len(interventions(app)) == n_events

    drive(app, script)


def test_sort_takes_its_mode_in_any_case():
    world, app = make("default")

    async def script(pilot):
        bar(app).start("/sort Cost")
        await press(pilot, "enter")
        assert app.fleet.sort is SortMode.COST

    drive(app, script)


def test_at_80_columns_the_board_hides_and_the_lane_list_keeps_state_and_idle():
    world, app = make("default")

    async def script(pilot):
        assert app.fleet.board_hidden
        assert "board hidden" in region_text(app, "#lanes-pane").splitlines()[0]
        head = region_text(app, "#lanes").splitlines()[0]
        assert "state" in head and "idle" in head
        await pilot.resize_terminal(*NARROW)
        await pilot.pause()
        assert not app.fleet.board_hidden and "board " in region_text(app, "#board-pane").splitlines()[0]

    drive(app, script, size=(80, 24))


def test_every_burst_of_deck_events_redraws_the_console_without_a_timer():
    """With no refresh timer and no mock clock, lane reports alone redraw the console."""
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, refresh_seconds=None)
    lane = world.deck.lanes_on("bent-coin")[0]

    async def script(pilot):
        for _ in range(3):
            turns = lane.turns
            world.tick(2)
            assert lane.turns > turns
            await pilot.pause()
            assert cell(app, "lanes", lane.id, "turns") == str(lane.turns)

    drive(app, script)


def test_a_status_message_clears_after_12_seconds_in_the_live_console():
    world = FakeWorld(scenarios.get("sstv"))
    app = FlightdeckApp(world.deck, refresh_seconds=3600.0)  # the timer is on; it never fires in this test
    now = [500.0]
    app.status_clock = lambda: now[0]

    async def script(pilot):
        app.say("Paused L01")
        app.refresh_view()
        await pilot.pause()
        assert "Paused L01" in status_line(app)
        now[0] += 11.5
        app.refresh_view()
        await pilot.pause()
        assert "Paused L01" in status_line(app)
        now[0] += 1.0
        app.refresh_view()
        await pilot.pause()
        assert status_line(app).strip() == ""

    drive(app, script)


def test_the_header_drops_cost_and_tokens_first_and_keeps_the_essentials():
    world = FakeWorld(scenarios.get("default"))
    deck = world.deck
    full = views.header(deck, mock="MOCK · default", width=500).plain
    assert "$" in full and "tok " in full and "Mock Range" in full
    cut = views.header(deck, mock="MOCK · default", width=len(full) - 2)
    assert "$" not in cut.plain and "tok " in cut.plain  # the last of the lowest-priority pieces goes first
    tight = views.header(deck, mock="MOCK · default", width=70)
    assert tight.cell_len <= 70
    for piece in ("flightdeck", "team", "lanes ", "▲ 3 need you"):
        assert piece in tight.plain, (piece, tight.plain)
    for piece in ("$", "tok ", "Mock Range", "T+"):
        assert piece not in tight.plain, (piece, tight.plain)


# ---------------------------------------------------------------------- review fixes: the focus view


def test_an_unsent_message_stays_with_its_lane_when_the_focus_view_switches():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        need = [x.id for x in deck.needing()]
        focus = await open_focus(pilot, app, need[1])
        chat = focus.query_one("#chat", CommandBar)
        app.post_message(events.Paste("try sstv on the left channel"))
        await pilot.pause()
        assert chat.field.value == "try sstv on the left channel"
        await press(pilot, "ctrl+n")
        assert focus.lane_id == need[2] and chat.field.value == ""
        hints = {x.id: list(x.hints) for x in deck.lanes.values()}
        await press(pilot, "enter")  # an empty chat sends nothing
        assert {x.id: list(x.hints) for x in deck.lanes.values()} == hints
        app.open_lane(need[1])
        await pilot.pause()
        assert focus.lane_id == need[1] and chat.field.value == "try sstv on the left channel"

    drive(app, script)


def test_the_slash_menu_follows_the_open_lane_and_its_answers():
    world, app = make("default")
    deck = world.deck
    lane = _off_hint(world)

    async def script(pilot):
        focus = await open_focus(pilot, app, lane.id)
        chat = focus.query_one("#chat", CommandBar)
        await press(pilot, "slash")
        assert any(c.suggested and c.text.startswith("/redirect ") for c in chat.completions)
        assert app.apply(iv.Redirect(lane.id, "use SSTV")).ok  # answered while the menu is open
        await pilot.pause()
        assert chat.menu_open and not any(c.suggested for c in chat.completions)
        await press(pilot, "ctrl+n")
        other = deck.lanes[focus.lane_id]
        assert other.id != lane.id and not chat.menu_open and chat.field.value == ""
        await press(pilot, "slash")
        suggested = [c.text for c in chat.completions if c.suggested]
        assert suggested == [c for c, _ in app.command_suggestions(other.id, with_lane=False)]

    drive(app, script)


def test_reopening_or_switching_lanes_draws_the_whole_transcript():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        lane = next(x for x in deck.active_lanes() if x.files and len(_log(x)) >= 3)
        focus = await open_focus(pilot, app, lane.id)
        assert_whole_transcript(focus, lane)
        await send(pilot, app, "/diff")  # reopens the same lane
        assert_whole_transcript(focus, lane)
        other = next(x for x in deck.needing() if x.id != lane.id)
        app.open_lane(other.id)  # switches the open view to another lane
        await pilot.pause()
        assert_whole_transcript(focus, other)

    drive(app, script)


def test_a_lane_with_no_files_does_not_keep_the_last_lanes_file_list():
    world, app = make("sstv")
    deck = world.deck

    async def script(pilot):
        lanes = deck.active_lanes()
        await step_until(pilot, app, lambda: any(x.files for x in lanes) and not all(x.files for x in lanes), "one lane writes a file")
        with_files = next(x for x in deck.active_lanes() if x.files)
        without = next(x for x in deck.active_lanes() if not x.files)
        focus = await open_focus(pilot, app, with_files.id)
        assert focus.query_one("#files").option_count == len(with_files.files)
        app.open_lane(without.id)
        await pilot.pause()
        assert focus.query_one("#files").option_count == 0
        assert "No files changed yet." in region_text(app, "#diff-scroll")

    drive(app, script)


def test_after_diff_typing_goes_back_to_the_chat_box():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.files, "the lane writes a file")
        focus = await open_focus(pilot, app, lane.id)
        chat = focus.query_one("#chat", CommandBar)
        await send(pilot, app, "/diff")
        assert app.focused is focus.query_one("#files")
        await press(pilot, "slash")
        assert app.focused is chat.field and chat.field.value == "/" and chat.menu_open
        await type_line(pilot, "pause")
        assert lane.state is LaneState.PAUSED

    drive(app, script)


def test_diff_on_a_lane_with_no_files_warns_and_leaves_the_chat_box_focused():
    world, app = make("sstv")

    async def script(pilot):
        lane = next(x for x in world.deck.active_lanes() if not x.files)
        focus = await open_focus(pilot, app, lane.id)
        await send(pilot, app, "/diff")
        assert_warning(app, f"{lane.id} has not changed any files yet")
        assert app.focused is focus.query_one("#chat", CommandBar).field

    drive(app, script)


def test_reading_back_in_the_transcript_is_not_undone_by_new_steps():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        lane = max((x for x in deck.active_lanes() if x.state is LaneState.RUNNING), key=lambda x: len(x.actions))
        focus = await open_focus(pilot, app, lane.id)
        log = focus.query_one("#transcript", RichLog)
        await step_until(pilot, app, lambda: log.max_scroll_y > 0, "more transcript than fits")
        assert log.scroll_y == log.max_scroll_y  # it follows the lane at first
        await press(pilot, "pageup")
        y = log.scroll_y
        assert y < log.max_scroll_y
        n = len(lane.actions)
        await step_until(pilot, app, lambda: len(lane.actions) > n, "a new step")
        assert log.scroll_y == y  # still where the player was reading
        await press(pilot, *["pagedown"] * 5)
        assert log.scroll_y == log.max_scroll_y
        n = len(lane.actions)
        await step_until(pilot, app, lambda: len(lane.actions) > n, "another step")
        await pilot.pause()
        assert log.scroll_y == log.max_scroll_y  # back at the end, it follows again

    drive(app, script)


def test_escape_with_the_menu_open_closes_only_the_menu_in_the_focus_view():
    world, app = make("sstv")

    async def script(pilot):
        focus = await open_focus(pilot, app, "L01")
        chat = focus.query_one("#chat", CommandBar)
        await press(pilot, "slash")
        assert chat.menu_open
        await press(pilot, "escape")
        assert isinstance(app.screen, FocusScreen) and not chat.menu_open and chat.field.value == "/"
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)

    drive(app, script)


def test_claim_with_no_argument_in_the_focus_view_claims_the_open_lanes_challenge():
    world, app = make("default")  # team mode
    deck = world.deck
    lane = deck.lanes_on("ticket-desk")[0]

    async def script(pilot):
        app.fleet.select_challenge("paper-trail")  # the board had the focus last in the fleet
        await pilot.pause()
        assert deck.challenges["paper-trail"].claimed_by is None
        await open_focus(pilot, app, lane.id)
        await send(pilot, app, "/claim")
        assert deck.challenges["ticket-desk"].claimed_by == ME
        assert deck.challenges["paper-trail"].claimed_by is None

    drive(app, script)


def test_the_focus_view_has_no_clock_keys_in_its_header_and_tab_goes_to_the_files():
    world, app = make("sstv")

    async def script(pilot):
        assert "space freezes" in region_text(app, "#header")  # in the fleet, space does
        focus = await open_focus(pilot, app, "L01")
        header = region_text(app, "#header")
        assert "▶ live" in header and "space" not in header
        await press(pilot, "tab")
        assert app.focused is focus.query_one("#files")

    drive(app, script)


def test_at_80x24_the_focus_view_keeps_rows_for_the_transcript():
    world, app = make("default")
    lane = _off_hint(world)

    async def script(pilot):
        focus = await open_focus(pilot, app, lane.id)
        talk = focus.query_one("#talk-pane").content_region.height
        assert focus.query_one("#transcript").region.height >= 3
        assert focus.query_one("#now").region.height <= (talk + 1) // 2
        assert _transcript(app)  # some of it is drawn

    drive(app, script, size=(80, 24))


def test_a_board_card_opens_any_of_its_lanes_by_number():
    world, app = make("sstv")
    deck = world.deck
    lane = deck.lanes_on("static-hiss")[0]

    async def script(pilot):
        assert app.apply(iv.Fork(lane.id, approach="a second look")).ok
        first, second = (x.id for x in deck.lanes_on("static-hiss"))
        app.fleet.select_challenge("static-hiss")
        await press(pilot, "enter")
        assert isinstance(app.screen, ChallengeCard)
        card = screen_text(app)
        assert f" 1  {first}" in card and f" 2  {second}" in card
        await press(pilot, "3")  # no third lane: nothing happens
        assert isinstance(app.screen, ChallengeCard)
        await press(pilot, "2")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == second

    drive(app, script)


# ---------------------------------------------------------------------- M1: decline and quick answers


def _flag_lane(world: FakeWorld):
    return next(x for x in world.deck.active_lanes() if x.pending is not None and x.pending.kind is PendingKind.SUBMIT)


def test_the_why_line_numbers_the_answers_and_1_approves_a_flag():
    world, app = make("default")
    deck = world.deck

    async def script(pilot):
        lane = _flag_lane(world)
        app.fleet.select_lane(lane.id)
        await pilot.pause()
        answers = region_text(app, "#why").splitlines()[1]
        assert f" 1  submit {lane.pending.flag}" in answers and " 0  do not submit" in answers
        await press(pilot, "1")
        assert lane.state is LaneState.SOLVED
        assert deck.challenges[lane.challenge_id].status is ChallengeStatus.SOLVED

    drive(app, script)


@pytest.mark.parametrize("how", ["0", "d", "/decline"])
def test_0_d_or_slash_decline_leave_a_flag_unsubmitted_and_the_lane_running(how):
    world, app = make("default")

    async def script(pilot):
        lane = _flag_lane(world)
        flag = lane.pending.flag
        app.fleet.select_lane(lane.id)
        await pilot.pause()
        n_submits = len([e for e in world.deck.events if e.kind is EventKind.SUBMIT])
        if how.startswith("/"):
            bar(app).start(how)
        await press(pilot, "enter" if how.startswith("/") else how)
        assert lane.state is LaneState.RUNNING and lane.pending is None
        assert len([e for e in world.deck.events if e.kind is EventKind.SUBMIT]) == n_submits
        assert f"Not submitted: {flag}" in status_line(app)

    drive(app, script)


def test_a_number_takes_the_suggested_answer_of_a_course_alert_at_once():
    world, app = make("sstv")
    lane = _off_hint(world)

    async def script(pilot):
        await step_until(pilot, app, lambda: lane.alert(AlertKind.HINT) is not None, "off-hint alert")
        suggestions = [s for s in lane.alert(AlertKind.HINT).suggestions if s.key]
        assert [s.key for s in suggestions][:2] == ["r", "h"]
        app.fleet.select_lane(lane.id)
        await pilot.pause()
        answers = region_text(app, "#why").splitlines()[1]
        assert " 1  redirect" in answers and " 2  hint" in answers
        await press(pilot, "1")
        assert lane.plan == suggestions[0].text  # redirected with the suggested plan, no prompt
        assert isinstance(app.screen, FleetScreen) and lane.alert(AlertKind.HINT) is None

    drive(app, script)


def test_a_number_with_no_answer_warns():
    world, app = make("sstv")

    async def script(pilot):
        lane = world.deck.lanes[app.fleet.selected_lane]
        assert not lane.needs_you
        before = snapshot(app)
        await press(pilot, "5")
        assert_warning(app, f"{lane.id} has no answer 5")
        assert snapshot(app) == before

    drive(app, script)


def test_the_kill_answer_opens_the_kill_prompt_rather_than_killing():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm", "big")))
    deck.release([Challenge("a", "A", "misc", 50)], [QueueEntry("a", "glm")])
    (lane,) = deck.lanes_on("a")
    deck.report(lane.id, TurnReport(alerts=(Alert(AlertKind.LOOP, "again", (Suggestion("h", "Hint", "stop"), Suggestion("k", "Kill"))),)))
    app = FlightdeckApp(deck, refresh_seconds=None)

    async def script(pilot):
        app.fleet.select_lane(lane.id)
        await pilot.pause()
        assert [(a.number, a.key) for a in views.quick_answers(lane)] == [("1", "h"), ("2", "k")]
        await press(pilot, "2")
        assert isinstance(app.screen, KillPrompt) and not lane.finished
        await press(pilot, "escape")
        assert not lane.finished

    drive(app, script)


def test_in_the_focus_view_a_digit_answers_only_while_the_chat_box_is_empty():
    world, app = make("default")

    async def script(pilot):
        lane = _flag_lane(world)
        focus = await open_focus(pilot, app, lane.id)
        chat = focus.query_one("#chat", CommandBar)
        card = region_text(app, "#now")
        assert " 1  /approve   submit it" in card and " 0  /decline   do not submit" in card
        await press(pilot, "t", "r", "y", "space", "0")  # a message that has a digit in it
        assert chat.field.value == "try 0" and lane.pending is not None
        chat.clear()
        await press(pilot, "7")  # no answer 7: it is just typed
        assert chat.field.value == "7" and lane.pending is not None
        chat.clear()
        await press(pilot, "0")
        assert lane.pending is None and lane.state is LaneState.RUNNING and chat.field.value == ""

    drive(app, script)


def test_a_suggested_hint_that_starts_like_a_lane_id_goes_to_the_lane_it_was_suggested_for():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm", "big")))
    deck.release([Challenge("a", "A", "misc", 50), Challenge("b", "B", "misc", 50)], [QueueEntry("a", "glm"), QueueEntry("b", "glm")])
    first, second = deck.lanes_on("a")[0], deck.lanes_on("b")[0]
    deck.report(first.id, TurnReport(alerts=(Alert(AlertKind.LOOP, "again", (Suggestion("h", "Hint", f"{second.id} is a decoy"),)),)))
    app = FlightdeckApp(deck, refresh_seconds=None)

    async def script(pilot):
        focus = await open_focus(pilot, app, first.id)
        chat = focus.query_one("#chat", CommandBar)
        await press(pilot, "slash")
        suggested = [c.text for c in chat.completions if c.suggested]
        assert suggested == [f"/hint {first.id} {second.id} is a decoy"]  # the lane named: no misreading
        await press(pilot, "escape", "escape")
        await open_focus(pilot, app, first.id)
        await press(pilot, "1")
        assert first.hints == [f"{second.id} is a decoy"] and second.hints == []

    drive(app, script)


# ---------------------------------------------------------------------- M1: hooks for a real run


def test_on_start_runs_once_on_the_consoles_running_event_loop():
    world = FakeWorld(scenarios.get("sstv"))
    seen = []

    def on_start():
        seen.append(asyncio.get_running_loop())  # raises if no loop is running

    app = FlightdeckApp(world.deck, refresh_seconds=None, on_start=on_start)

    async def script(pilot):
        await pilot.pause()
        assert len(seen) == 1 and seen[0] is asyncio.get_running_loop()

    drive(app, script)


@pytest.mark.parametrize("how", ["q", "/quit", "ctrl+q"])
def test_quitting_awaits_the_runs_shutdown_before_the_console_exits(how):
    world = FakeWorld(scenarios.get("sstv"))
    calls = []

    async def on_exit():
        calls.append("started")
        await asyncio.sleep(0.01)  # a shutdown that takes a moment
        calls.append("done")

    app = FlightdeckApp(world.deck, refresh_seconds=None, on_exit=on_exit)

    async def script(pilot):
        if how == "/quit":
            bar(app).start(how)
            await press(pilot, "enter")
        else:
            await press(pilot, how)
        assert isinstance(app.screen, QuitPrompt) and calls == []  # its lanes are at work: it asks first
        await pilot.press("y")
        for _ in range(50):
            if not app.is_running:
                break
            await pilot.pause(0.01)
        assert calls == ["started", "done"]
        assert not app.is_running

    drive(app, script)


def open_run(*, queued: int = 0) -> tuple[Deck, list]:
    """A run's deck with three lanes at work: L01 waits for the player with a flag, L02 is
    paused, L03 runs; `queued` more challenges wait in the queue."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=3, flag_format=r"t\{[a-z]+\}"))
    names = ["alpha", "bravo", "charlie"] + [f"extra{n}" for n in range(queued)]
    deck.release([Challenge(n, n.title(), "misc", 50) for n in names], [QueueEntry(n, "glm") for n in names])
    first, second, _ = (deck.lanes_on(n)[0] for n in names[:3])
    deck.report(first.id, TurnReport(flag="t{alpha}"))
    assert deck.apply(iv.Pause(second.id)).ok
    calls: list[str] = []
    return deck, calls


@pytest.mark.parametrize("size", [SIZE, (80, 24)], ids=["160x46", "80x24"])
def test_quitting_while_lanes_are_open_asks_first_says_what_quitting_does_and_esc_or_n_stays(size):
    deck, calls = open_run(queued=2)

    async def on_exit():
        calls.append("stopped")

    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=on_exit, run_dir="/runs/20261111-093000")

    async def script(pilot):
        for answer in ("escape", "n"):
            await press(pilot, "q")
            assert isinstance(app.screen, QuitPrompt)
            text = prompt_text(app)
            assert "3 lanes still open: 1 waiting for you, 1 paused, 1 running" in text
            assert "L01 Alpha submit t{alpha}" in text  # what waits for the player, named
            assert "2 challenges queued, not started" in text
            assert "Quitting stops every lane and closes its workspace, and a run cannot be resumed" in text
            assert "Nothing that waits for you is submitted or approved" in text
            assert "The run's log and transcripts stay in /runs/20261111-093000" in text
            assert "Stay (esc) Quit (y)" in text
            await press(pilot, answer)
            assert isinstance(app.screen, FleetScreen) and app.is_running
        assert calls == [] and not any(lane.finished for lane in deck.lanes.values())
        assert deck.lanes["L01"].pending is not None

    drive(app, script, size)


def test_a_second_q_or_one_meant_for_help_or_a_card_does_not_quit_a_run():
    """q also closes help and queues from a challenge card: a double tap must not end the run."""
    deck, calls = open_run()
    deck.release([Challenge("delta", "Delta", "misc", 50)], [])  # on the board, with no lane

    async def on_exit():
        calls.append("stopped")

    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=on_exit)

    async def script(pilot):
        await press(pilot, "q", "q")
        assert isinstance(app.screen, QuitPrompt)  # the second q is not an answer
        await press(pilot, "escape", "question_mark")
        assert isinstance(app.screen, HelpScreen)
        await press(pilot, "q", "q")  # closes help, then asks
        assert isinstance(app.screen, QuitPrompt)
        await press(pilot, "escape")
        app.fleet.select_challenge("delta")
        await press(pilot, "enter")
        assert isinstance(app.screen, ChallengeCard)
        await press(pilot, "q", "q")  # queues delta, then asks
        assert isinstance(app.screen, QuitPrompt)
        await press(pilot, "ctrl+q")  # ctrl+q on the prompt is not an answer either, nor a second prompt
        assert [type(s) for s in app.screen_stack].count(QuitPrompt) == 1
        await press(pilot, "escape")
        assert app.is_running and calls == []

    drive(app, script)


def test_quitting_does_not_ask_once_every_lane_has_finished_nor_in_the_mock():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",)))
    deck.release([Challenge("alpha", "Alpha", "misc", 50)], [QueueEntry("alpha", "glm")])
    (lane,) = deck.lanes.values()
    assert deck.apply(iv.Kill(lane.id, requeue=False)).ok and lane.finished
    calls = []

    async def on_exit():
        calls.append("stopped")

    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=on_exit)

    async def finished(pilot):
        await press(pilot, "q")
        for _ in range(50):
            if not app.is_running:
                break
            await pilot.pause(0.01)
        assert calls == ["stopped"] and not app.is_running

    drive(app, finished)

    world, mock = make("sstv")  # fake lanes at work, nothing to stop: no question
    assert any(not lane.finished for lane in world.deck.lanes.values())

    async def in_the_mock(pilot):
        await press(pilot, "q")
        for _ in range(50):
            if not mock.is_running:
                break
            await pilot.pause(0.01)
        assert not mock.is_running

    drive(mock, in_the_mock)


@pytest.fixture
def stop_signals_default():
    """SIGHUP and SIGTERM as a terminal starts flightdeck (their default action); put back after."""
    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGHUP, signal.SIGTERM)}
    for sig in saved:
        signal.signal(sig, signal.SIG_DFL)
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP], ids=["SIGTERM", "SIGHUP"])
def test_a_sigterm_or_a_hang_up_stops_the_run_as_quitting_does_without_asking(stop_signals_default, sig):
    world = FakeWorld(scenarios.get("sstv"))
    calls = []

    async def on_exit():
        calls.append("started")
        await asyncio.sleep(0.01)
        calls.append("done")

    app = FlightdeckApp(world.deck, refresh_seconds=None, on_exit=on_exit)

    async def script(pilot):
        # the console catches it; if it did not, the signal would end this test run
        assert signal.getsignal(sig) not in (signal.SIG_DFL, signal.SIG_IGN, None)
        os.kill(os.getpid(), sig)
        for _ in range(100):
            if not app.is_running:
                break
            await pilot.pause(0.01)
        assert calls == ["started", "done"] and not app.is_running  # nobody had to say yes
        assert app.stopped_by == sig

    drive(app, script)
    assert signal.getsignal(sig) is signal.SIG_DFL  # given back when the console exits


def test_a_stop_signal_ignored_when_flightdeck_started_stays_ignored(stop_signals_default):
    """Under nohup, a hang-up is meant to leave the run going."""
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    world = FakeWorld(scenarios.get("sstv"))

    async def on_exit():
        pass

    app = FlightdeckApp(world.deck, refresh_seconds=None, on_exit=on_exit)

    async def script(pilot):
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
        assert signal.getsignal(signal.SIGTERM) not in (signal.SIG_DFL, signal.SIG_IGN, None)

    drive(app, script)
    assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN


def test_take_over_with_a_shell_hands_the_lane_back_when_the_console_cannot_let_go_of_the_terminal():
    """Headless (as here, or a web console), Textual cannot suspend: the lane is not left taken over."""
    finished = []

    class Session:
        shell = type("Spec", (), {"argv": ["true"], "cwd": None, "env": None})()

        async def begin(self):
            return self.shell

        def finish(self) -> str:
            finished.append(True)
            return "no files changed"

    class ShellDriver(QuietDriver):
        def takeover(self, lane):
            return Session()

    deck = Deck(DeckConfig(event="ev", models=("glm",)), ShellDriver(), ManualClock(), wrong_flag)
    deck.release([Challenge("a", "A", "misc", 50)], [QueueEntry("a", "glm")])
    (lane,) = deck.lanes_on("a")
    app = FlightdeckApp(deck, refresh_seconds=None)

    async def script(pilot):
        await press(pilot, "t")
        for _ in range(50):
            if lane.state is not LaneState.TAKEOVER:
                break
            await pilot.pause(0.01)
        assert lane.state is LaneState.RUNNING
        assert not isinstance(app.screen, TakeOverScreen)  # no placeholder: this driver has a shell
        assert finished == []  # nothing ran, so nothing to report as changed
        assert_warning(app, "L01: this console cannot hand over the terminal")
        assert "no shell: this console cannot hand over the terminal" in lane.actions[-1].text

    drive(app, script)


def test_pressing_t_while_a_lanes_workspace_is_being_prepared_warns_and_the_console_carries_on(tmp_path):
    """A docker lane takes a second or two to prepare; t in that window is refused, never a crash."""
    from ctf_flightdeck.agent.client import ModelClient
    from ctf_flightdeck.agent.driver import AgentDriver
    from ctf_flightdeck.agent.workspace import HostWorkspace
    from fake_model import FakeModelServer, text_reply

    class SlowWorkspace(HostWorkspace):
        async def prepare(self):
            await asyncio.Event().wait()  # still preparing when the player presses t

    (tmp_path / "board").mkdir()
    with FakeModelServer(responder=lambda record: text_reply("thinking")) as server:
        client = ModelClient(server.base_url, "sk-test-not-a-real-key", max_retries=0, backoff=0.0)
        driver = AgentDriver(client, lambda lane, ch: SlowWorkspace(tmp_path / lane.id, tmp_path / "board"), run_id="r")
        deck = Deck(DeckConfig(event="ev", models=("glm",)), driver, ManualClock(), wrong_flag)
        app = FlightdeckApp(deck, refresh_seconds=None)

        async def script(pilot):
            deck.release([Challenge("a", "A", "misc", 50)], [QueueEntry("a", "glm")])
            (lane,) = deck.lanes_on("a")
            app.refresh_view()
            app.fleet.select_lane(lane.id)
            await pilot.pause()
            await press(pilot, "t")
            assert app.is_running and lane.state is LaneState.RUNNING
            assert_warning(app, "L01's workspace is not ready yet; try again in a moment")
            await driver.shutdown()
            await client.aclose()

        drive(app, script)


def test_a_take_over_whose_workspace_cannot_be_checked_still_hands_the_lane_back(monkeypatch):
    from ctf_flightdeck.agent.workspace import WorkspaceError
    from ctf_flightdeck.console import takeover

    async def the_shell_ran(app, argv, cwd, env):
        return None

    monkeypatch.setattr(takeover, "run_in_terminal", the_shell_ran)

    class Session:
        async def begin(self):
            return type("Spec", (), {"argv": ["true"], "cwd": None, "env": None})()

        def finish(self) -> str:
            raise WorkspaceError("cannot snapshot workspace /gone: No such file or directory")

    class ShellDriver(QuietDriver):
        def takeover(self, lane):
            return Session()

    deck = Deck(DeckConfig(event="ev", models=("glm",)), ShellDriver(), ManualClock(), wrong_flag)
    deck.release([Challenge("a", "A", "misc", 50)], [QueueEntry("a", "glm")])
    (lane,) = deck.lanes_on("a")
    app = FlightdeckApp(deck, refresh_seconds=None)

    async def script(pilot):
        await press(pilot, "t")
        for _ in range(50):
            if lane.state is not LaneState.TAKEOVER:
                break
            await pilot.pause(0.01)
        assert lane.state is LaneState.RUNNING
        assert_warning(app, "its workspace could not be checked: cannot snapshot workspace /gone")
        assert "the workspace could not be checked" in lane.actions[-1].text

    drive(app, script)


# ---------------------------------------------------------------------- a held queue

HELD_WHY = "L01's call to glm failed in a way every lane would (check the API key): model API error: HTTP 401: no credentials"


def held_run(*, max_lanes: int = 1, flag_on: str | None = None) -> Deck:
    """A run's deck whose first lane failed in a way every lane would: the queue is held with
    challenges still in it. `flag_on`: a lane on that challenge waits for the player with a flag."""
    names = ["alpha", "bravo", "charlie", "delta"]
    deck = quiet_deck(DeckConfig(event="Harbour Lights", models=("glm",), max_lanes=max_lanes, flag_format=r"t\{[a-z]+\}"))
    deck.release([Challenge(n, n.title(), "misc", 50) for n in names], [QueueEntry(n, "glm") for n in names])
    if flag_on is not None:
        deck.report(deck.lanes_on(flag_on)[0].id, TurnReport(flag=f"t{{{flag_on}}}"))
    deck.hold_queue(HELD_WHY)
    deck.report("L01", TurnReport(turn=False, gave_up="model API error: HTTP 401"))
    return deck


async def nothing() -> None:
    pass


def test_a_held_queue_is_in_the_header_with_why_never_all_clear_and_unhold_from_the_bar_starts_the_queue():
    deck = held_run()
    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=nothing)

    async def script(pilot):
        header = region_text(app, "#header")
        assert "lanes 0/1 · queue 3" in header and "all clear" not in header and "need you" not in header
        # why, as far as the room goes: tokens, dollars, the clock and the event's name gave way to it
        assert "queue held: L01's call to glm failed in a way every lane would (check the API key): model" in header
        assert "tok " not in header and "$" not in header and "T+" not in header and "Harbour" not in header
        await press(pilot, "slash")
        entries = [line for line in region_text(app, "#menu").splitlines() if line.strip("│╭╮╰╯─ ")]
        assert "/unhold" in entries[0] and "suggested" in entries[0] and "the queue is held: L01's call" in entries[0]
        await press(pilot, *"unhold", "enter")
        assert deck.held == "" and [lane.challenge_id for lane in deck.active_lanes()] == ["bravo"]
        assert "Lifted the hold on the queue: 1 lane started, 2 queued" in status_line(app)
        header = region_text(app, "#header")
        assert "queue held" not in header and "all clear" in header and "lanes 1/1 · queue 2" in header
        assert "tok " in header and "T+" in header and "Harbour Lights" in header  # back once there is no reason to show
        await press(pilot, "slash")
        assert "/unhold" not in region_text(app, "#menu").splitlines()[1]  # suggested no more
        await press(pilot, *"unhold", "enter")
        assert_warning(app, "The queue is not held: queued lanes start as slots free up")

    drive(app, script)


def test_a_hold_while_the_console_runs_says_why_and_how_to_lift_it_and_the_focus_view_shows_it_too():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=1))
    deck.release([Challenge(n, n.title(), "misc", 50) for n in ("alpha", "bravo")], [QueueEntry(n, "glm") for n in ("alpha", "bravo")])
    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=nothing)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert "all clear" in region_text(app, "#header")
        deck.hold_queue(HELD_WHY)
        await pilot.pause()
        assert_warning(app, f"queue held until you /unhold it: {HELD_WHY}")
        header = region_text(app, "#header")
        assert "queue held: L01's call to glm" in header and "all clear" not in header
        await send(pilot, app, "/unhold")  # a command, not a lane message: it works from a lane's chat box too
        assert deck.held == "" and "Lifted the hold on the queue: 0 lanes started, 1 queued" in status_line(app)
        assert deck.lanes["L01"].hints == []

    drive(app, script)


def test_help_and_the_command_menu_list_unhold_and_what_it_does():
    deck = held_run()
    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=nothing)
    said = "lift the hold on the queue once its cause is fixed (a key or model id changed in your config needs a new run)"

    async def script(pilot):
        await press(pilot, "question_mark")
        assert f"/unhold {said}" in prompt_text(app)
        await press(pilot, "escape")
        bar(app).start("/unh")
        await pilot.pause()
        assert f"/unhold {said[:40]}" in " ".join(region_text(app, "#bar").split())

    drive(app, script, size=(160, 100))  # tall enough for help to show every command without scrolling


def test_the_header_keeps_need_you_and_queue_held_and_gives_the_reason_only_room_tokens_and_the_clock_leave():
    deck = held_run(max_lanes=2, flag_on="bravo")
    wide = views.header(deck, width=400).plain
    assert "▲ 1 need you" in wide and f"queue held: {HELD_WHY} ╱ tok 0 ╱ $0.00 ╱ T+" in wide  # room for everything
    mid = views.header(deck, width=150)
    assert mid.cell_len == 150 and "▲ 1 need you" in mid.plain and "Harbour Lights" not in mid.plain
    assert "queue held: L01's call to glm failed" in mid.plain and mid.plain.rstrip().endswith("…")
    for gone in ("tok ", "$", "T+"):
        assert gone not in mid.plain
    tight = views.header(deck, width=80)
    assert tight.plain.rstrip().endswith("▲ 1 need you ╱ queue held") and tight.cell_len <= 80  # no room for why
    lifted = views.header(quiet_deck(DeckConfig(event="ev", models=("glm",))), width=200).plain
    assert "all clear" in lifted and "queue held" not in lifted


# ---------------------------------------------------------------------- who solved it: the reports' rule


def solving_deck() -> Deck:
    """A run's deck where three challenges are solved: alpha with the flag L1 engine "reader"
    found, bravo by its lane alone, charlie by its lane with a flag L1 engine "strings" had
    printed before (a candidate the lane then submitted itself)."""
    names = ["alpha", "bravo", "charlie"]
    deck = Deck(DeckConfig(event="ev", models=("glm",), max_lanes=3, flag_format=r"t\{[a-z]+\}"), QuietDriver(),
                ManualClock(1000.0), lambda cid, flag: flag == f"t{{{cid}}}")
    deck.release([Challenge(n, n.title(), "misc", 50) for n in names], [QueueEntry(n, "glm") for n in names])
    alpha, bravo, charlie = (deck.lanes_on(n)[0] for n in names)
    deck.record_l1("alpha", "reader", "solved", flags=["t{alpha}"], lane_id=alpha.id)
    deck.report(alpha.id, TurnReport(turn=False, flag="t{alpha}"))
    deck.record_l1("charlie", "strings", "candidate", flags=["t{charlie}"], lane_id=charlie.id)
    deck.report(charlie.id, TurnReport(turn=False, flag="t{charlie}", claimed=False))
    deck.report(charlie.id, TurnReport(action="submit_flag t{charlie}", flag="t{charlie}"))
    deck.report(bravo.id, TurnReport(action="submit_flag t{bravo}", flag="t{bravo}"))
    for lane in (alpha, bravo, charlie):
        assert deck.apply(iv.Approve(lane.id)).ok and lane.state is LaneState.SOLVED
    return deck


def test_the_board_credits_a_solve_as_every_report_does_the_flag_an_l1_engine_found_to_that_engine(tmp_path):
    from ctf_flightdeck.eventlog import EventLog
    from ctf_flightdeck.runrecord import load_run, solves

    deck = solving_deck()
    app = FlightdeckApp(deck, refresh_seconds=None, on_exit=nothing)

    async def script(pilot):
        assert [cell(app, "board", n, "own") for n in ("alpha", "bravo", "charlie")] == ["L1·reader", "L02", "L1·strings"]
        app.fleet.select_challenge("alpha")
        await pilot.pause()
        assert "✓ solved by L1·reader" in region_text(app, "#why")  # in full: the board's column is narrow
        await press(pilot, "enter")
        assert isinstance(app.screen, ChallengeCard) and "owner L1·reader" in prompt_text(app)
        await press(pilot, "escape", "question_mark")
        assert "L1·name solved with the flag your L1 engine of that name found" in prompt_text(app)

    drive(app, script, size=(160, 100))
    log = EventLog(tmp_path / "events.jsonl")  # the run log the reports read: they credit the same solvers
    log.attach(deck)
    log.close()
    found = solves(load_run(tmp_path).events)
    assert {cid: (s.by, s.who) for cid, s in found.items()} == {
        "alpha": ("l1", "reader"), "bravo": ("lane", "L02"), "charlie": ("l1", "strings"),
    }


def test_the_board_reads_each_event_once_as_the_deck_grows(monkeypatch):
    """The board asks owner() of every row on every redraw: the deck's events are read once
    each, in order, however often it asks, and events added later are read when it next asks."""
    from ctf_flightdeck.runrecord import Credit

    seen: list[int] = []

    class Counted(Credit):
        def see(self, index, event):
            seen.append(index)
            super().see(index, event)

    monkeypatch.setattr(views, "Credit", Counted)
    deck = solving_deck()
    for _ in range(3):
        assert views.owner(deck, deck.challenges["alpha"]) == ("L1·reader", "l1")
        assert views.owner(deck, deck.challenges["charlie"]) == ("L1·strings", "l1")
    assert seen == list(range(len(deck.events)))
    deck.release([Challenge("delta", "Delta", "misc", 50)], [QueueEntry("delta", "glm")])
    (delta,) = deck.lanes_on("delta")
    deck.record_l1("delta", "rot", "solved", flags=["t{delta}"], lane_id=delta.id)  # after the first read
    deck.report(delta.id, TurnReport(turn=False, flag="t{delta}"))
    assert deck.apply(iv.Approve(delta.id)).ok
    assert views.owner(deck, deck.challenges["delta"]) == ("L1·rot", "l1")
    assert views.owner(deck, deck.challenges["bravo"]) == ("L02", "lane")
    assert seen == list(range(len(deck.events)))


# ---------------------------------------------------------------------- what doctor says a terminal leaves out


def four_lanes_and_one_finished(*, team: bool = False) -> Deck:
    """Four lanes at work and one that finished, so the lane list has five rows; more queued."""
    names = [f"c{n}" for n in range(7)]
    deck = quiet_deck(DeckConfig(event="E" * room.SAMPLE_EVENT, team=team, models=("glm",), max_lanes=4))
    deck.release([Challenge(n, n.upper(), "misc", 50) for n in names], [QueueEntry(n, "glm") for n in names])
    deck.report("L01", TurnReport(turn=False, gave_up="stuck"))
    assert len(deck.active_lanes()) == 4 and len(deck.lanes) == 5
    return deck


@pytest.mark.parametrize("size", [(60, 12), (99, 17), (100, 30), (108, 18), (125, 18), (146, 18), (147, 17), (147, 18)])
def test_what_doctor_says_a_terminal_leaves_out_is_what_the_console_leaves_out(size, monkeypatch):
    """doctor measures a terminal with room.room(); at that size, on the busy run it measures
    with (the header of room.busy_header), the console leaves out exactly that: the header's
    pieces in both views, the board, lane rows, the fleet view's keys and the focus view's."""
    columns, lines = size
    fit = room.room(columns, lines, max_lanes=4, containerized=True)
    busy = room.busy_header(max_lanes=4, containerized=True)
    monkeypatch.setattr(views, "header_facts", lambda deck, mock="": busy)
    pieces = {name: text for name, rank, (text, *_) in views.header_pieces(busy) if rank}  # the pieces that can drop
    app = FlightdeckApp(four_lanes_and_one_finished(), refresh_seconds=None, on_exit=nothing)

    async def script(pilot):
        for view in ("fleet", "focus"):
            header = region_text(app, "#header")
            assert {name for name, text in pieces.items() if text not in header} == set(fit.header), (view, header)
            keys = region_text(app, "#keys").strip()
            if view == "fleet":
                assert app.fleet.board_hidden is fit.board
                rows = [line for line in region_text(app, "#lanes").splitlines()[1:] if line.strip()]  # under the labels
                assert len(rows) == min(fit.rows, fit.needed) and (fit.rows < fit.needed) is (len(rows) < 5)
                every = [f"{b.key_display or b.key} {b.description}" for b in FleetScreen.BINDINGS if b.show and b.action != "claim"]
                assert [key for key in every if key not in keys.split("  ")] == sorted(fit.fleet_keys, key=every.index), keys
                await open_focus(pilot, app, "L02")
            else:
                labels = [f"{key} {label}" for key, label in FOCUS_KEYS]
                assert [label for label in labels if label not in keys] == list(fit.focus_keys), keys  # cut, or not there
        assert (fit.left_out() == []) is (size == (fit.columns, fit.lines))  # the smallest size that leaves nothing out

    drive(app, script, size=size)


@pytest.mark.parametrize("columns", [150, 155, 156])
def test_doctor_measures_team_modes_key_line_with_claim_as_the_console_draws_it(columns):
    _, solo = fleet_key_room(columns, team=False)
    left, team = fleet_key_room(columns, team=True)
    app = FlightdeckApp(four_lanes_and_one_finished(team=True), refresh_seconds=None, on_exit=nothing)

    async def script(pilot):
        keys = region_text(app, "#keys").strip().split("  ")
        every = [f"{b.key_display or b.key} {b.description}" for b in FleetScreen.BINDINGS if b.show]
        assert "c claim" in every and [key for key in every if key not in keys] == sorted(left, key=every.index)
        assert (left == []) is (columns >= team) and team == solo + len("  c claim")

    drive(app, script, size=(columns, 30))
