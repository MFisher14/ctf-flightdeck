"""A lane that is ended to start afresh takes the focus view with it (FlightdeckApp.follow,
follow_restart): /attach and a kill that re-queues, typed in that lane's view. Also what the
view says about the lane it is on: the simple layout's chat box and its finished line.

The decks are quiet ones (the test reports the lanes' turns), with no timers. /attach's copy
is a stand-in for Run.attach_files that waits to be let go and then restarts the challenge's
lanes as a run does; the run's own answer is tested in tests/test_addchallenge.py.
"""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.console import views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import CHAT_PLACEHOLDER, FocusScreen
from ctf_flightdeck.console.screens import HelpScreen, KillPrompt
from ctf_flightdeck.console.widgets import CommandBar
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, Challenge, DeckConfig, EventKind, LaneState, Suggestion
from test_console import drive, open_focus, press, quiet_deck, region_text, send, status_line, type_line

LAYOUTS = ("deck", "simple")
WHY = "to restart with extra.txt"


class Copy:
    """/attach's attacher: waits until the test lets the copy end, then restarts the
    challenge's lanes with the reason a run gives."""

    def __init__(self, deck: Deck) -> None:
        self.deck = deck
        self.started = asyncio.Event()
        self.end = asyncio.Event()

    async def __call__(self, challenge_id: str, files: list) -> tuple[bool, str]:
        self.started.set()
        await self.end.wait()
        for lane in self.deck.lanes_on(challenge_id):
            assert self.deck.apply(iv.Kill(lane.id, requeue=True, why=WHY)).ok
        return True, f"attached {files[0].name} to {challenge_id}"


def console(*ids: str, layout: str = "deck", max_lanes: int = 4, attach: bool = False) -> tuple[Deck, FlightdeckApp, Copy | None]:
    """A console with one lane on each challenge of `ids`, L01 on the first."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm", "big"), max_lanes=max_lanes))
    deck.release([Challenge(cid, cid.upper(), "misc", 50) for cid in ids], [QueueEntry(cid, "glm") for cid in ids])
    copy = Copy(deck) if attach else None
    return deck, FlightdeckApp(deck, refresh_seconds=None, layout=layout, attacher=copy), copy


def chat(app: FlightdeckApp):
    return app.screen.query_one("#chat", CommandBar).field


def shown(app: FlightdeckApp) -> str:
    """The lane the focus view is on, read off its title as drawn."""
    assert isinstance(app.screen, FocusScreen)
    title = region_text(app, "#talk-pane").splitlines()[0]
    assert f" {app.screen.lane_id} " in title, title
    return app.screen.lane_id


async def settle(pilot, done) -> None:
    for _ in range(200):
        if done():
            return
        await pilot.pause(0.01)
    raise AssertionError("waited too long")


# ---------------------------------------------------------------------- /attach


@pytest.mark.parametrize("layout", LAYOUTS)
def test_attach_typed_in_a_lanes_view_takes_the_view_and_the_unsent_message_to_the_fresh_lane(tmp_path, layout):
    extra = tmp_path / "extra.txt"
    extra.write_text("x")
    deck, app, copy = console("c", layout=layout, attach=True)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await send(pilot, app, f"/attach {extra}")
        await settle(pilot, copy.started.is_set)
        await pilot.press(*"try the zip")  # typed while the files are copied
        await pilot.pause()
        assert shown(app) == "L01" and chat(app).value == "try the zip"
        copy.end.set()
        await settle(pilot, lambda: len(deck.lanes) == 2 and app.screen.lane_id == "L02")
        await pilot.pause()
        assert shown(app) == "L02" and deck.lanes["L01"].finished and not deck.lanes["L02"].finished
        assert chat(app).value == "try the zip" and chat(app).has_focus  # the message goes on to the fresh lane
        assert "attached extra.txt to c" in status_line(app)
        await press(pilot, "enter")
        assert deck.lanes["L02"].hints == ["try the zip"] and chat(app).value == ""
        await press(pilot, "escape")
        await open_focus(pilot, app, "L01")
        assert chat(app).value == ""  # nothing was left behind as L01's draft

    drive(app, script)


def test_a_player_who_left_the_view_before_the_copy_ended_is_not_moved(tmp_path):
    extra = tmp_path / "extra.txt"
    extra.write_text("x")

    async def to_the_lanes(pilot, app):
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)

    async def to_another_lane(pilot, app):
        await type_line(pilot, "/open L02")
        assert shown(app) == "L02"

    for leave, stays in ((to_the_lanes, None), (to_another_lane, "L02")):
        deck, app, copy = console("c", "d", attach=True)

        async def script(pilot, leave=leave, stays=stays, deck=deck, app=app, copy=copy):
            await open_focus(pilot, app, "L01")
            await send(pilot, app, f"/attach {extra}")
            await settle(pilot, copy.started.is_set)
            await leave(pilot, app)
            copy.end.set()
            await settle(pilot, lambda: len(deck.lanes) == 3 and "attached" in app._status[0])
            await pilot.pause()
            assert deck.lanes["L03"].challenge_id == "c"  # the fresh lane is there
            if stays is None:
                assert isinstance(app.screen, FleetScreen)
            else:
                assert shown(app) == stays
            deck.report("L03", TurnReport(action="ls"))  # the deck says something: still nobody is moved
            await pilot.pause()
            assert isinstance(app.screen, FleetScreen) if stays is None else shown(app) == stays

        drive(app, script)


def test_attach_typed_on_another_challenge_or_in_the_lane_list_moves_nobody(tmp_path):
    extra = tmp_path / "extra.txt"
    extra.write_text("x")
    deck, app, copy = console("c", "d", attach=True)

    async def script(pilot):
        copy.end.set()
        await open_focus(pilot, app, "L01")
        await send(pilot, app, f"/attach d {extra}")  # d's lane restarts; the view is on c's
        await settle(pilot, lambda: len(deck.lanes) == 3)
        await pilot.pause()
        assert deck.lanes["L03"].challenge_id == "d" and shown(app) == "L01" and not deck.lanes["L01"].finished
        deck.report("L01", TurnReport(action="ls", gave_up="nothing to go on"))  # and when the lane in view has ended
        await send(pilot, app, f"/attach d {extra}")
        await settle(pilot, lambda: len(deck.lanes) == 4)
        await pilot.pause()
        assert deck.lanes["L04"].challenge_id == "d" and deck.lanes["L01"].finished and shown(app) == "L01"
        assert deck.apply(iv.Queue("c")).ok and len(deck.lanes) == 5  # c gets a lane again, for the next step
        await press(pilot, "escape")
        app.fleet.select_lane("L05")
        app.fleet.start_command(f"/attach {extra}")  # in the lane list, on the selected lane's challenge
        await press(pilot, "enter")
        await settle(pilot, lambda: len(deck.lanes) == 6)
        await pilot.pause()
        assert deck.lanes["L06"].challenge_id == "c" and isinstance(app.screen, FleetScreen)

    drive(app, script)


def test_while_the_queue_is_held_the_view_waits_and_moves_when_the_fresh_lane_starts(tmp_path):
    extra = tmp_path / "extra.txt"
    extra.write_text("x")
    deck, app, copy = console("c", attach=True)

    async def script(pilot):
        deck.hold_queue("the model API refuses the key")
        copy.end.set()
        await open_focus(pilot, app, "L01")
        await send(pilot, app, f"/attach {extra}")
        await settle(pilot, lambda: deck.lanes["L01"].finished and "attached" in app._status[0])
        await pilot.pause()
        assert list(deck.lanes) == ["L01"] and deck.queued("c") and shown(app) == "L01"  # no fresh lane yet: the view stays
        await type_line(pilot, "/fork try the other archive")  # a fork goes first in the held queue, ahead of the restart
        assert list(deck.lanes) == ["L01"] and shown(app) == "L01"
        await type_line(pilot, "/unhold")
        await pilot.pause()
        fork, fresh = deck.lanes["L02"], deck.lanes["L03"]
        assert (fork.parent, fresh.parent, fresh.attempt) == ("L01", None, 2)
        assert shown(app) == "L03"  # the lane that restarted L01, not the fork that started before it

    drive(app, script)


def test_a_view_on_a_lane_that_had_already_ended_goes_to_the_lane_attach_starts(tmp_path):
    """A lane that gave up for want of a file is the one a player attaches the file from."""
    extra = tmp_path / "extra.txt"
    extra.write_text("x")
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=4))
    deck.release([Challenge("c", "C", "misc", 50)], [QueueEntry("c", "glm")])
    deck.report("L01", TurnReport(action="ls", gave_up="the handout is missing"))

    async def attacher(challenge_id: str, files: list) -> tuple[bool, str]:
        assert deck.apply(iv.Queue(challenge_id)).ok  # as Run.attach_files does for a challenge with no lane
        return True, f"attached extra.txt to {challenge_id}; a lane starts on it when one is free"

    app = FlightdeckApp(deck, refresh_seconds=None, attacher=attacher)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert deck.lanes["L01"].finished
        await send(pilot, app, f"/attach {extra}")
        await settle(pilot, lambda: len(deck.lanes) == 2)
        await pilot.pause()
        assert shown(app) == "L02"

    drive(app, script)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_lane_that_started_during_the_copy_and_was_ended_with_the_files_is_not_the_one_the_view_goes_to(tmp_path, layout):
    """The view is on a lane that gave up. While /attach copies, the player queues the challenge
    and a lane starts on it: the files end that lane too, and the view goes to the lane that
    runs with them, not to the one just ended."""
    extra = tmp_path / "extra.txt"
    extra.write_text("x")
    deck, app, copy = console("c", layout=layout, attach=True)
    deck.report("L01", TurnReport(action="ls", gave_up="the handout is missing"))

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert deck.lanes["L01"].finished and not deck.lanes_on("c")
        await send(pilot, app, f"/attach {extra}")
        await settle(pilot, copy.started.is_set)
        await type_line(pilot, "/queue c")  # a lane starts on it while the files are copied
        assert list(deck.lanes) == ["L01", "L02"] and not deck.lanes["L02"].finished and shown(app) == "L01"
        copy.end.set()
        await settle(pilot, lambda: len(deck.lanes) == 3 and "attached" in app._status[0])
        await pilot.pause()
        ended, runs = deck.lanes["L02"], deck.lanes["L03"]
        assert (ended.state, ended.result) == (LaneState.KILLED, "to restart with extra.txt; re-queued fresh")
        assert (runs.challenge_id, runs.parent, runs.finished) == ("c", None, False)
        assert shown(app) == "L03" and app._follow is None
        if layout == "simple":
            assert chat(app).placeholder == "message L03 · / commands"

    drive(app, script)


# ---------------------------------------------------------------------- a kill that re-queues


@pytest.mark.parametrize("layout", LAYOUTS)
def test_kill_typed_in_a_lanes_view_takes_the_view_to_the_fresh_lane_and_kill_park_does_not(layout):
    deck, app, _ = console("c", "d", layout=layout)

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await type_line(pilot, "/kill L02")  # another lane's restart is not this view's
        assert deck.lanes["L02"].finished and deck.lanes["L03"].challenge_id == "d" and shown(app) == "L01"
        await type_line(pilot, "/kill")
        assert deck.lanes["L01"].state is LaneState.KILLED and deck.lanes["L04"].challenge_id == "c"
        assert shown(app) == "L04" and "Killed L01; fresh lane L04 started on C" in status_line(app)
        assert deck.lanes["L01"].result == "by the player; re-queued fresh"
        await type_line(pilot, "/kill park")
        assert deck.lanes["L04"].state is LaneState.KILLED and shown(app) == "L04"  # parked: there is no fresh lane to go to
        assert len(deck.lanes) == 4 and app._follow is None

    drive(app, script)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_the_numbered_kill_answer_and_its_prompts_re_queue_take_the_view_to_the_fresh_lane(layout):
    deck, app, _ = console("c", layout=layout)
    deck.report("L01", TurnReport(alerts=(Alert(AlertKind.LOOP, "again", (Suggestion("h", "Hint", "stop"), Suggestion("k", "Kill and re-queue fresh"))),)))

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert [(a.number, a.key) for a in views.quick_answers(deck.lanes["L01"])] == [("1", "h"), ("2", "k")]
        await press(pilot, "2")
        assert isinstance(app.screen, KillPrompt)
        await press(pilot, "r")
        await pilot.pause()
        assert deck.lanes["L01"].state is LaneState.KILLED and shown(app) == "L02"
        await press(pilot, "x")
        assert chat(app).value == "x"  # the chat box has the keys, on the fresh lane

    drive(app, script)


def test_a_player_who_turned_to_another_lane_while_the_fresh_one_waited_is_not_moved():
    deck, app, _ = console("c", "d")

    async def script(pilot):
        deck.hold_queue("the model API refuses the key")
        await open_focus(pilot, app, "L01")
        await type_line(pilot, "/kill")
        assert deck.lanes["L01"].finished and deck.queued("c") and shown(app) == "L01"
        await type_line(pilot, "/open L02")
        await type_line(pilot, "/unhold")
        await pilot.pause()
        assert deck.lanes["L03"].challenge_id == "c" and shown(app) == "L02"
        await type_line(pilot, "/open L01")  # back on the ended lane: it stays there, the restart was not followed
        deck.report("L03", TurnReport(action="ls"))
        await pilot.pause()
        assert shown(app) == "L01"

    drive(app, script)


def test_a_fresh_lane_that_starts_while_a_prompt_is_over_the_view_is_shown_when_the_prompt_closes():
    deck, app, _ = console("c")

    async def script(pilot):
        deck.hold_queue("the model API refuses the key")
        await open_focus(pilot, app, "L01")
        await type_line(pilot, "/kill")
        await type_line(pilot, "/help")
        assert isinstance(app.screen, HelpScreen)
        assert deck.release_hold().ok and deck.lanes["L02"].challenge_id == "c"
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen) and app.focus_screen.lane_id == "L01"  # nothing moves under a prompt
        await press(pilot, "escape")
        assert shown(app) == "L02"

    drive(app, script)


def test_a_fresh_lane_that_was_ended_again_under_a_prompt_is_passed_over_for_the_lane_that_runs():
    """The fresh lane starts and is ended to start afresh once more while a prompt is over the
    view: the view goes to the lane that runs, at once or when it starts, never to the one
    that ended in between."""
    for held_again in (False, True):
        deck, app, _ = console("c")

        async def script(pilot, held_again=held_again, deck=deck, app=app):
            deck.hold_queue("the model API refuses the key")
            await open_focus(pilot, app, "L01")
            await type_line(pilot, "/kill")
            await type_line(pilot, "/help")
            assert deck.release_hold().ok and not deck.lanes["L02"].finished
            if held_again:
                deck.hold_queue("the model API refuses the key")
            assert deck.apply(iv.Kill("L02", requeue=True)).ok  # as autopilot ends a lane that loops
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen) and deck.lanes["L02"].finished
            await press(pilot, "escape")
            if held_again:
                assert list(deck.lanes) == ["L01", "L02"] and deck.queued("c")
                assert shown(app) == "L01" and app._follow is not None  # the lane that will run has not started
                await type_line(pilot, "/unhold")
                await pilot.pause()
            later = deck.lanes["L03"]
            assert (later.challenge_id, later.parent, later.finished) == ("c", None, False)
            assert shown(app) == "L03" and app._follow is None

        drive(app, script)


def test_a_fresh_lane_that_ended_under_a_prompt_with_none_on_its_way_ends_the_follow():
    """The fresh lane gave up while a prompt was over the view, and its challenge is parked:
    the view is not taken to a lane that has ended, and a lane started on the challenge later
    moves nobody."""
    deck, app, _ = console("c")

    async def script(pilot):
        deck.hold_queue("the model API refuses the key")
        await open_focus(pilot, app, "L01")
        await type_line(pilot, "/kill")
        await type_line(pilot, "/help")
        assert deck.release_hold().ok and not deck.lanes["L02"].finished
        deck.report("L02", TurnReport(action="ls", gave_up="nothing to go on"))
        await pilot.pause()
        assert deck.lanes["L02"].finished and not deck.queued("c")
        await press(pilot, "escape")
        assert shown(app) == "L01" and app._follow is None
        assert deck.apply(iv.Queue("c")).ok and not deck.lanes["L03"].finished
        await pilot.pause()
        assert shown(app) == "L01"

    drive(app, script)


def test_a_follow_is_dropped_once_the_challenge_is_parked_and_a_later_lane_on_it_moves_nobody():
    deck, app, _ = console("c")
    assert deck.apply(iv.Fork("L01", approach="the other way")).ok  # L02, a second lane on c

    async def script(pilot):
        deck.hold_queue("the model API refuses the key")
        await open_focus(pilot, app, "L01")
        await type_line(pilot, "/kill")
        assert deck.lanes["L01"].finished and deck.queued("c") and shown(app) == "L01"  # held: the fresh lane waits
        assert deck.apply(iv.Kill("L02", requeue=False)).ok and not deck.queued("c")  # parked: the queued restart is gone
        await pilot.pause()
        assert deck.release_hold().ok and deck.apply(iv.Queue("c")).ok
        await pilot.pause()
        later = deck.lanes["L03"]
        assert (later.challenge_id, later.parent, later.finished) == ("c", None, False)
        assert shown(app) == "L01"

    drive(app, script)


def test_a_follow_is_dropped_once_the_challenge_is_solved():
    deck, app, _ = console("c")

    async def script(pilot):
        deck.hold_queue("the model API refuses the key")
        await open_focus(pilot, app, "L01")
        await type_line(pilot, "/kill")
        assert deck.queued("c") and app._follow is not None and shown(app) == "L01"
        deck.platform_solved("c", "you")
        await pilot.pause()
        assert not deck.queued("c") and app._follow is None and shown(app) == "L01"

    drive(app, script)


# ---------------------------------------------------------------------- the ended lane's result


def test_a_kill_with_a_reason_says_it_in_the_ended_lanes_result_and_a_plain_kill_says_who():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=4))
    deck.release([Challenge("c", "C", "misc", 50), Challenge("d", "D", "misc", 50)], [QueueEntry("c", "glm"), QueueEntry("d", "glm")])
    assert deck.apply(iv.Kill("L01", requeue=True, why=WHY)).ok and deck.apply(iv.Kill("L02", requeue=True)).ok
    with_why, plain = deck.lanes["L01"], deck.lanes["L02"]
    assert (with_why.state, with_why.result) == (LaneState.KILLED, "to restart with extra.txt; re-queued fresh")
    assert plain.result == "by the player; re-queued fresh"
    assert views.now_card(deck, with_why).plain.startswith("killed: to restart with extra.txt; re-queued fresh")
    kills = [dict(e.data) for e in deck.events if e.kind is EventKind.INTERVENTION]
    assert kills == [{"intervention": "kill", "lane": "L01", "requeue": True, "why": WHY},
                     {"intervention": "kill", "lane": "L02", "requeue": True}]  # a plain kill is logged as it always was
    assert deck.apply(iv.Kill("L03", requeue=False, why=WHY)).ok
    assert deck.lanes["L03"].result == "by the player; parked"  # a reason is why a lane restarts, not why one is parked


# ---------------------------------------------------------------------- what the view says about its lane


def test_the_simple_layouts_chat_box_names_the_lane_and_its_finished_line_says_lanes():
    deck, app, _ = console("c", "d", layout="simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        assert chat(app).placeholder == "message L01 · / commands"
        assert "message L01 · / commands" in region_text(app, "#chat")
        await type_line(pilot, "/open L02")
        assert chat(app).placeholder == "message L02 · / commands"
        await type_line(pilot, "/kill")  # the view goes to the fresh lane, and the chat box names it
        assert shown(app) == "L03" and chat(app).placeholder == "message L03 · / commands"
        await type_line(pilot, "/kill park")
        assert region_text(app, "#now").strip() == "killed: by the player; parked   this lane has ended; esc goes back to the lanes"
        await type_line(pilot, "/layout deck")
        assert chat(app).placeholder == CHAT_PLACEHOLDER
        assert region_text(app, "#now").strip() == "killed: by the player; parked   this lane has ended; esc goes back to the fleet"
        await type_line(pilot, "/layout simple")
        assert chat(app).placeholder == "message L03 · / commands"

    drive(app, script)


def test_the_deck_and_compact_layouts_chat_box_and_finished_line_are_as_they_were():
    assert CHAT_PLACEHOLDER == "message this lane (it reads it on its next turn) · / for commands"
    for size, layout in (((160, 46), "deck"), ((60, 40), "deck"), ((60, 40), "simple")):  # 60 columns: the compact layout, whatever the config says
        deck, app, _ = console("c", "d", layout=layout)

        async def script(pilot, deck=deck, app=app):
            await open_focus(pilot, app, "L01")
            assert chat(app).placeholder == CHAT_PLACEHOLDER
            await type_line(pilot, "/open L02")
            assert chat(app).placeholder == CHAT_PLACEHOLDER
            assert deck.apply(iv.Kill("L02", requeue=False)).ok
            await pilot.pause()
            assert "this lane has ended; esc goes back to the fleet" in " ".join(region_text(app, "#now").split())

        drive(app, script, size=size)
