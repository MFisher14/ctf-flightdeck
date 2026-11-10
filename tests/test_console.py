"""Textual pilot tests: the console's keys, attention sort, max_lanes and team mode.

The app gets no clock timer here; tests tick the fake world themselves, so every run
is the same. pytest 9 has no native async tests, so each test drives the app inside
asyncio.run().
"""

from __future__ import annotations

import asyncio
import html
import re

import pytest
from textual.widgets import DataTable

from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.screens import ForkPrompt, HelpScreen, KillPrompt, TakeOverScreen, TextPrompt
from ctf_flightdeck.core.model import ME, AlertKind, ChallengeStatus, LaneState, PendingKind
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.scenarios import ReleaseAt, Scenario, Spec
from ctf_flightdeck.mock.world import FakeWorld

SIZE = (160, 48)


def make(scenario: str | Scenario = "default", **kw) -> tuple[FakeWorld, FlightdeckApp]:
    spec = scenarios.get(scenario) if isinstance(scenario, str) else scenario
    world = FakeWorld(spec, **kw)
    return world, FlightdeckApp(world.deck, ticker=world.tick, mock="MOCK · test")


def drive(app: FlightdeckApp, script) -> None:
    async def main():
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            await script(pilot)

    asyncio.run(main())


def table(app: FlightdeckApp, name: str) -> DataTable:
    return app.query_one(f"#{name}", DataTable)


def row_keys(app: FlightdeckApp) -> list[str]:
    return [row.key.value for row in table(app, "lanes").ordered_rows]


def cell(app: FlightdeckApp, name: str, row: str, column: str) -> str:
    return str(table(app, name).get_cell(row, column))


SPAN = re.compile(r'<text class="[^"]*-r\d+" x="([\d.]+)" y="([\d.]+)" textLength="([\d.]+)"[^>]*>(.*?)</text>')


def screen_text(app: FlightdeckApp) -> str:
    """The screen as plain text lines, rebuilt from the SVG export (one span per style run)."""
    lines: dict[float, list[str]] = {}
    for x, y, width, body in SPAN.findall(app.export_screenshot()):
        text = html.unescape(body).replace("\xa0", " ")
        col = round(float(x) / (float(width) / len(text)))
        line = lines.setdefault(float(y), [])
        line.extend(" " * max(0, col + len(text) - len(line)))
        line[col : col + len(text)] = text
    return "\n".join("".join(line) for _, line in sorted(lines.items()))


def on(world: FakeWorld, cid: str):
    (lane,) = world.deck.lanes_on(cid)
    return lane


async def step(pilot, app: FlightdeckApp, ticks: int = 1) -> None:
    app.step(ticks)
    await pilot.pause()


async def type_text(pilot, text: str) -> None:
    await pilot.press(*text)


# ---------------------------------------------------------------------- keys change lane state


def test_p_pauses_and_resumes_the_selected_lane():
    world, app = make("sstv")
    lane = on(world, "static-hiss")

    async def script(pilot):
        app.select_lane(lane.id)
        await pilot.press("p")
        assert lane.state is LaneState.PAUSED
        assert cell(app, "lanes", lane.id, "state") == "paused"
        turns = lane.turns
        await step(pilot, app, 5)
        assert lane.turns == turns  # a paused lane does nothing
        await pilot.press("p")
        assert lane.state is LaneState.RUNNING
        await step(pilot, app, 4)
        assert lane.turns > turns

    drive(app, script)


def test_arrow_keys_choose_the_lane_the_keys_act_on():
    world, app = make("sstv")

    async def script(pilot):
        app.select_lane(row_keys(app)[0])
        await pilot.press("down")
        second = row_keys(app)[1]
        assert app.selected_lane == second
        await pilot.press("p")
        assert world.deck.lanes[second].state is LaneState.PAUSED
        assert world.deck.lanes[row_keys(app)[0]].state is not LaneState.PAUSED

    drive(app, script)


def test_h_sends_free_text_into_the_next_turn():
    world, app = make("sstv")
    lane = on(world, "muddy-footprints")

    async def script(pilot):
        app.select_lane(lane.id)
        await pilot.press("h")
        assert isinstance(app.screen, TextPrompt)
        await type_text(pilot, "check the PNG chunks")
        await pilot.press("enter")
        assert not isinstance(app.screen, TextPrompt)
        assert lane.hints == ["check the PNG chunks"]
        assert "queued for the next turn: check the PNG chunks" in screen_text(app)
        await step(pilot, app, 4)
        assert lane.hints == []
        assert any("reads the hint: check the PNG chunks" in a.text for a in lane.actions)

    drive(app, script)


def test_escape_cancels_a_prompt_without_touching_the_lane():
    world, app = make("sstv")
    lane = on(world, "static-hiss")

    async def script(pilot):
        app.select_lane(lane.id)
        plan = lane.plan
        await pilot.press("r")
        await type_text(pilot, "something else")
        await pilot.press("escape")
        assert not isinstance(app.screen, TextPrompt)
        assert lane.plan == plan

    drive(app, script)


def test_r_redirect_prefills_the_suggestion_and_replaces_the_plan():
    world, app = make("sstv")
    lane = on(world, "static-hiss")

    async def script(pilot):
        while lane.alert(AlertKind.HINT) is None:
            await step(pilot, app)
        suggestion = lane.alert(AlertKind.HINT).suggestions[0].text
        app.select_lane(lane.id)
        await pilot.press("r")
        prompt = app.screen
        assert isinstance(prompt, TextPrompt)
        assert prompt.query_one("Input").value == suggestion
        await pilot.press("enter")
        assert lane.plan == suggestion
        assert lane.alert(AlertKind.HINT) is None
        await step(pilot, app, 4)
        assert "decoded.png" in lane.artifacts

    drive(app, script)


def test_f_forks_a_sibling_lane_on_another_model():
    world, app = make("web")
    lane = on(world, "paper-trail")

    async def script(pilot):
        app.select_lane(lane.id)
        await pilot.press("f")
        assert isinstance(app.screen, ForkPrompt)
        await type_text(pilot, "read the source first")
        await pilot.press("enter")
        siblings = world.deck.lanes_on("paper-trail")
        assert len(siblings) == 2
        fork = next(x for x in siblings if x is not lane)
        assert (fork.parent, fork.plan) == (lane.id, "read the source first")
        assert fork.model != lane.model
        assert fork.id in row_keys(app)

    drive(app, script)


def test_k_kill_requeue_starts_a_fresh_lane_and_park_parks():
    world, app = make("overthinking")
    lane = on(world, "second-guess")
    other = on(world, "tin-soldier")

    async def script(pilot):
        app.select_lane(lane.id)
        await pilot.press("k")
        assert isinstance(app.screen, KillPrompt)
        await pilot.press("r")
        assert lane.state is LaneState.KILLED
        fresh = on(world, "second-guess")
        assert fresh.attempt == 2 and fresh.id in row_keys(app)
        app.select_lane(other.id)
        await pilot.press("k")
        await pilot.press("p")
        assert other.state is LaneState.KILLED
        assert world.deck.challenges["tin-soldier"].status is ChallengeStatus.PARKED
        assert cell(app, "board", "tin-soldier", "mark") == "‖"

    drive(app, script)


def test_e_escalates_to_the_next_stronger_model():
    world, app = make("sstv")
    lane = on(world, "static-hiss")

    async def script(pilot):
        app.select_lane(lane.id)
        await pilot.press("e")
        assert lane.model == "sonnet"
        assert cell(app, "lanes", lane.id, "model") == "sonnet"
        assert lane.actions[-1].output.startswith("Challenge: Static Hiss")  # the summary

    drive(app, script)


def test_t_take_over_shows_the_placeholder_and_hands_back():
    world, app = make("sstv")
    lane = on(world, "static-hiss")

    async def script(pilot):
        app.select_lane(lane.id)
        await pilot.press("t")
        assert isinstance(app.screen, TakeOverScreen)
        assert lane.state is LaneState.TAKEOVER
        text = screen_text(app)
        assert "placeholder" in text and "In M1 this drops you into a shell" in text
        await pilot.press("enter")
        assert not isinstance(app.screen, TakeOverScreen)
        assert lane.state is LaneState.RUNNING

    drive(app, script)


def test_a_approves_the_submit_and_the_board_updates():
    world, app = make("flag")
    lane = on(world, "ticket-desk")

    async def script(pilot):
        while lane.pending is None:
            await step(pilot, app)
        app.select_lane(lane.id)
        assert cell(app, "lanes", lane.id, "!") == "▲ flag"
        assert cell(app, "board", "ticket-desk", "mark") == "▶"
        await pilot.press("a")
        assert world.deck.challenges["ticket-desk"].status is ChallengeStatus.SOLVED
        assert cell(app, "board", "ticket-desk", "mark") == "✓"
        assert cell(app, "board", "ticket-desk", "own") == lane.id
        assert lane.state is LaneState.SOLVED

    drive(app, script)


def test_a_on_a_live_box_request_lets_the_lane_continue():
    world, app = make("team")
    lane = on(world, "harbor-master")

    async def script(pilot):
        while lane.pending is None or lane.pending.kind is not PendingKind.LIVE_BOX:
            await step(pilot, app)
        app.select_lane(lane.id)
        assert cell(app, "lanes", lane.id, "!") == "◆ box"
        await pilot.press("a")
        assert lane.state is LaneState.RUNNING and lane.pending is None

    drive(app, script)


def test_c_claims_and_releases_in_team_mode_only():
    world, app = make("team")

    async def script(pilot):
        app.select_challenge("lucky-sevens")
        await pilot.press("c")
        assert world.deck.challenges["lucky-sevens"].claimed_by == ME
        assert cell(app, "board", "lucky-sevens", "own") == ME
        await pilot.press("c")
        assert world.deck.challenges["lucky-sevens"].claimed_by is None

    drive(app, script)

    solo_world, solo = make("sstv")

    async def solo_script(pilot):
        solo.select_challenge("bent-coin")
        await pilot.press("c")
        assert solo_world.deck.challenges["bent-coin"].claimed_by is None
        assert "claim" not in screen_text(solo).split("help")[0].split("sort")[0][-80:]

    drive(solo, solo_script)


def test_s_cycles_the_sort_and_slash_filters_lanes():
    world, app = make("default")

    async def script(pilot):
        await pilot.press("s")
        assert app.sort.value == "idle"
        assert "sort idle" in screen_text(app)
        await pilot.press("slash")
        await type_text(pilot, "sonnet")
        await pilot.press("enter")
        keys = [k for k in row_keys(app) if k in world.deck.lanes]
        assert keys and all(world.deck.lanes[k].model == "sonnet" for k in keys)
        assert len(keys) < len(world.deck.active_lanes())
        await pilot.press("escape")
        assert len([k for k in row_keys(app) if k in world.deck.lanes]) == len(world.deck.active_lanes())

    drive(app, script)


def test_question_mark_opens_help_and_tab_moves_focus():
    world, app = make("sstv")

    async def script(pilot):
        assert app.focused is table(app, "lanes")
        await pilot.press("tab")
        assert app.focused.id == "detail-pane"
        await pilot.press("tab")
        assert app.focused is table(app, "board")
        assert app.detail_mode == "challenge"
        await pilot.press("question_mark")
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        assert not isinstance(app.screen, HelpScreen)

    drive(app, script)


def test_lane_keys_from_the_board_act_on_that_challenges_lane():
    world, app = make("sstv")
    lane = on(world, "bent-coin")

    async def script(pilot):
        app.select_challenge("bent-coin")
        await pilot.press("p")
        assert lane.state is LaneState.PAUSED

    drive(app, script)


# ---------------------------------------------------------------------- attention sort


def test_attention_sort_puts_lanes_with_alerts_first():
    world, app = make("default")

    async def script(pilot):
        await step(pilot, app, 20)  # wave 2 has dropped; loop, effort, budget fired
        deck = world.deck
        rows = [deck.lanes[k] for k in row_keys(app) if k in deck.lanes and not deck.lanes[k].finished]
        flags = [bool(lane.alerts) for lane in rows]
        assert sum(flags) >= 4
        assert flags == sorted(flags, reverse=True), "a lane without alerts is listed above one with alerts"
        # the order really differs from lane order, so this test can tell
        assert [lane.number for lane in rows] != sorted(lane.number for lane in rows)
        assert cell(app, "lanes", rows[0].id, "!").startswith("▲")
        # approvals without alerts come right after the alerts
        waiting = [i for i, lane in enumerate(rows) if lane.pending and not lane.alerts]
        running = [i for i, lane in enumerate(rows) if not lane.pending and not lane.alerts]
        assert not waiting or not running or max(waiting) < min(running)

    drive(app, script)


def test_a_new_alert_moves_its_lane_up_and_the_selection_follows():
    world, app = make("overthinking")
    lane = on(world, "second-guess")
    deck = world.deck

    def alerted_rows():
        return [bool(deck.lanes[k].alerts) for k in row_keys(app) if k in deck.lanes]

    async def script(pilot):
        app.select_lane(lane.id)
        while lane.alert(AlertKind.EFFORT) is None:
            await step(pilot, app)
            before = row_keys(app).index(lane.id) if lane.alert(AlertKind.EFFORT) is None else None
            if before is not None:
                assert all(alerted_rows()[:before]) or not lane.alerts
        index = row_keys(app).index(lane.id)
        flags = alerted_rows()
        assert all(flags[:index]) and flags == sorted(flags, reverse=True)
        assert app.selected_lane == lane.id
        assert table(app, "lanes").cursor_coordinate.row == index  # the cursor moved with it
        await pilot.press("p")
        assert lane.state is LaneState.PAUSED  # and the keys still act on it

    drive(app, script)


# ---------------------------------------------------------------------- max_lanes and the queue


def test_wave_drop_fills_16_lanes_and_queues_27():
    world, app = make("wave")

    async def script(pilot):
        await step(pilot, app, 2)
        assert len(world.deck.challenges) == 43
        assert len([k for k in row_keys(app) if k in world.deck.lanes]) == 16
        assert "lanes 16/16 (queue 27)" in screen_text(app)

    drive(app, script)


def test_max_lanes_is_respected_and_the_queue_drains_as_the_player_acts():
    world, app = make("sstv", max_lanes=2)
    deck = world.deck

    async def script(pilot):
        assert len(deck.active_lanes()) == 2 and len(deck.queue) == 2
        assert "lanes 2/2 (queue 2)" in screen_text(app)
        for _ in range(200):
            if not deck.queue:
                break
            await step(pilot, app)
            assert len(deck.active_lanes()) <= 2
            for lane in list(deck.active_lanes()):
                if lane.pending is not None:
                    app.select_lane(lane.id)
                    await pilot.press("a")
                elif lane.alert(AlertKind.HINT):
                    app.select_lane(lane.id)
                    await pilot.press("k", "p")
        assert deck.queue == []
        assert "(queue 0)" in screen_text(app)
        assert len(deck.lanes) == 4  # every challenge got a lane, never more than 2 at once

    drive(app, script)


# ---------------------------------------------------------------------- team mode


def test_team_mode_stops_the_lane_when_a_teammate_solves_its_challenge():
    world, app = make("team")
    lane = on(world, "night-shift")

    async def script(pilot):
        app.select_lane(lane.id)
        while world.ticks < 12:
            await step(pilot, app)
        assert lane.state is LaneState.STOPPED
        assert cell(app, "board", "night-shift", "mark") == "✓"
        assert cell(app, "board", "night-shift", "own") == "bravo"
        assert lane.id not in [x.id for x in world.deck.active_lanes()]
        app.select_lane(lane.id)  # finished lanes are collapsed; selecting expands them
        assert cell(app, "lanes", lane.id, "state") == "stopped"
        assert "bravo solved Night Shift, so flightdeck stopped this lane" in screen_text(app)

    drive(app, script)


def test_solo_mode_does_not_stop_the_lane():
    world, app = make("team", team=False)
    lane = on(world, "night-shift")

    async def script(pilot):
        while world.ticks < 12:
            await step(pilot, app)
        assert lane.state is LaneState.RUNNING
        assert world.deck.challenges["night-shift"].status is ChallengeStatus.RUNNING
        assert "solo" in screen_text(app)

    drive(app, script)


def test_enter_on_the_finished_row_expands_and_collapses():
    world, app = make("team")
    lane = on(world, "night-shift")

    async def script(pilot):
        while not lane.finished:
            await step(pilot, app)
        assert lane.id not in row_keys(app)
        index = row_keys(app).index("__finished__")
        table(app, "lanes").move_cursor(row=index)
        table(app, "lanes").focus()
        await pilot.press("enter")
        assert lane.id in row_keys(app)
        await pilot.press("enter")
        assert lane.id not in row_keys(app)

    drive(app, script)


# ---------------------------------------------------------------------- untrusted text


def test_challenge_text_is_shown_literally_never_as_markup():
    evil = Spec(
        "evil", "web", "[b]X[/b]", 100,
        "[@click=app.quit]click me[/] and flag{[/]} and [red]red[/red]",
    )
    scenario = Scenario(name="evil", summary="", specs=(evil,), timeline=((0, ReleaseAt(("evil",), "Board")),))
    world, app = make(scenario)

    async def script(pilot):
        app.select_challenge("evil")
        await pilot.pause()
        text = screen_text(app)
        assert "[b]X[/b]" in text
        assert "[@click=app.quit]click me[/] and flag{[/]} and [red]red[/red]" in text
        await step(pilot, app, 3)
        assert app.is_running

    drive(app, script)


@pytest.mark.parametrize("name", list(scenarios.SCENARIOS))
def test_every_scenario_opens_and_runs_in_the_console(name):
    world, app = make(name)

    async def script(pilot):
        await step(pilot, app, 30)
        assert "flightdeck" in screen_text(app)

    drive(app, script)
