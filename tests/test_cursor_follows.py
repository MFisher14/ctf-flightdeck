"""The lane list's selection follows what the player sees (P96).

Two cases moved it nowhere before: a filter that hides the selected lane left every key acting
on a lane that is not shown (they refused it) while the cursor was drawn on another row; and a
lane the player answered from the list, folding into `N finished`, left the selection on the
folded lane, so the next `a` warned that it had finished. Now the first selects the row the
cursor is drawn on, and the second goes on to the next lane that needs the player."""

from __future__ import annotations

from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.views import FINISHED_ROW
from ctf_flightdeck.core.attention import SortMode
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.interventions import Approve
from ctf_flightdeck.core.model import Challenge, DeckConfig, PendingKind
from ctf_flightdeck.mock.world import ManualClock
from test_console import QuietDriver, assert_warning, cursor_key, drive, lane_rows, press, row_keys, table
from test_layout import COURSE, SIZE

RIGHT = "flag{right}"


def accept(challenge_id: str, flag: str) -> bool:
    """A platform that takes one flag, the right one."""
    return flag == RIGHT


def lanes(*categories: str, submitter=None, verify=accept) -> tuple[Deck, FlightdeckApp]:
    """A console with one lane on each of the challenges L01, L02, ..., in the categories
    given, sorted by lane number, so the rows keep their order whatever the lanes need.
    `submitter`: a platform over the network, whose answer comes later (platform_verdict);
    `verify`: the board's verifier (one that answers None: the player submits by hand)."""
    deck = Deck(DeckConfig(event="ev", models=("glm",), max_lanes=len(categories)), QuietDriver(), ManualClock(1000.0), verify,
                submitter=submitter)
    names = ["alpha", "beta", "gamma", "delta", "omega"][: len(categories)]
    deck.release([Challenge(n, n.title(), c, 100) for n, c in zip(names, categories)], [QueueEntry(n, "glm") for n in names])
    app = FlightdeckApp(deck, refresh_seconds=3600.0, layout="deck")
    app.fleet.sort = SortMode.LANE
    return deck, app


def selected(app) -> str | None:
    return app.fleet.selected_lane


# ---------------------------------------------------------------------- the filter


def test_a_filter_that_hides_the_selected_lane_selects_the_row_the_cursor_is_on_and_the_keys_act_on_it():
    deck, app = lanes("web", "crypto", "crypto")
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{wrong}"))

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        app.fleet.set_filter("crypto")  # hides L01
        await pilot.pause()
        assert lane_rows(app) == ["L02", "L03"]
        assert selected(app) == cursor_key(app) == "L02"  # the row drawn highlighted is the one the keys act on
        assert app.fleet.bar_lane() is deck.lanes["L02"]
        assert "hidden by the filter" not in " ".join(app.fleet.query_one("#why").render().plain.split())
        await press(pilot, "a")
        assert deck.lanes["L02"].pending is None  # approved (and rejected: the platform takes another flag)
        await press(pilot, "escape")  # the filter goes; the selection stays where it went
        assert app.fleet.filter_text == "" and selected(app) == cursor_key(app) == "L02"

    drive(app, script, SIZE)


def test_a_filter_selects_the_lane_row_nearest_the_cursor_when_the_cursor_was_on_the_finished_row():
    deck, app = lanes("web", "crypto", "crypto")
    deck.report("L03", TurnReport(action="gave up", gave_up="nothing left to try"))
    assert deck.lanes["L03"].finished

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        assert row_keys(app) == ["L01", "L02", FINISHED_ROW]
        table(app, "lanes").move_cursor(row=2)  # straight onto the finished row, past no lane
        await pilot.pause()
        assert cursor_key(app) == FINISHED_ROW and selected(app) == "L01"  # the finished row is no lane: L01 stays
        app.fleet.set_filter("crypto")  # hides L01; L02 and the finished L03 match
        await pilot.pause()
        assert row_keys(app) == ["L02", FINISHED_ROW]
        assert selected(app) == cursor_key(app) == "L02"

    drive(app, script, SIZE)


def test_a_filter_that_shows_no_lane_leaves_the_selection_and_the_keys_still_refuse_it():
    deck, app = lanes("web", "crypto")
    deck.report("L01", TurnReport(action="cat flag.txt", flag="flag{wrong}"))

    async def script(pilot):
        app.fleet.select_lane("L01")
        app.fleet.set_filter("zzz")
        await pilot.pause()
        assert row_keys(app) == [] and selected(app) == "L01"
        await press(pilot, "a")
        assert_warning(app, "L01 is hidden by the filter; esc clears it")
        assert deck.lanes["L01"].pending is not None

    drive(app, script, SIZE)


def test_a_lane_whose_own_turn_takes_it_out_of_the_filter_keeps_the_selection_and_the_keys_refuse_it():
    """Only the player's filter moves the selection: a lane's own report that makes it stop
    matching never hands the keys to another lane, whose flag `a` would then submit."""
    deck, app = lanes("misc", "misc", "misc")
    deck.report("L01", TurnReport(action="cat flag.txt"))
    deck.report("L02", TurnReport(action="cat flag.txt"))
    deck.report("L03", TurnReport(action="cat flag.txt", flag="flag{other}"))

    async def script(pilot):
        app.fleet.select_lane("L02")
        app.fleet.set_filter("flag")
        await pilot.pause()
        assert lane_rows(app) == ["L01", "L02", "L03"] and selected(app) == "L02"
        deck.report("L02", TurnReport(action="ls -la"))  # no longer matches 'flag'
        app.refresh_view()
        await pilot.pause()
        assert lane_rows(app) == ["L01", "L03"]
        assert selected(app) == "L02"
        await press(pilot, "a")
        assert_warning(app, "L02 is hidden by the filter; esc clears it")
        assert deck.lanes["L03"].pending is not None  # nobody submitted L03's flag
        app.fleet.set_filter("flag")  # the player sets the filter again: now it moves
        await pilot.pause()
        assert selected(app) == cursor_key(app) in ("L01", "L03")

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- a lane the player answered


def test_a_lane_the_player_answers_that_folds_hands_the_selection_to_the_next_lane_that_needs_them():
    deck, app = lanes("misc", "misc", "misc", "misc")
    deck.report("L02", TurnReport(action="cat flag.txt", flag=RIGHT))
    deck.report("L04", TurnReport(action="strings delta.wav", alerts=(COURSE,)))
    assert not deck.lanes["L03"].needs_you and deck.lanes["L04"].needs_you

    async def script(pilot):
        app.fleet.select_lane("L02")
        await pilot.pause()
        await press(pilot, "a")
        assert deck.lanes["L02"].finished and "L02" not in row_keys(app)
        assert selected(app) == cursor_key(app) == "L04"  # the lane that needs the player, not L03 under it
        assert app.fleet.bar_lane() is deck.lanes["L04"]

    drive(app, script, SIZE)


def test_with_no_lane_that_needs_the_player_the_selection_goes_to_the_row_under_the_lane():
    deck, app = lanes("misc", "misc", "misc")
    deck.report("L02", TurnReport(action="cat flag.txt", flag=RIGHT))

    async def script(pilot):
        app.fleet.select_lane("L02")
        await pilot.pause()
        await press(pilot, "a")
        assert deck.lanes["L02"].finished
        assert row_keys(app) == ["L01", "L03", FINISHED_ROW] and selected(app) == cursor_key(app) == "L03"

    drive(app, script, SIZE)


def test_the_last_lane_folding_hands_the_selection_to_the_row_above():
    deck, app = lanes("misc", "misc", "misc")
    deck.report("L03", TurnReport(action="cat flag.txt", flag=RIGHT))

    async def script(pilot):
        app.fleet.select_lane("L03")
        await pilot.pause()
        await press(pilot, "1")  # the why line's first answer: submit the flag
        assert deck.lanes["L03"].finished
        assert selected(app) == cursor_key(app) == "L02"

    drive(app, script, SIZE)


def test_a_kill_from_the_list_moves_the_selection_on_as_well():
    deck, app = lanes("misc", "misc")

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        await press(pilot, "k")
        assert type(app.screen).__name__ == "KillPrompt"
        await press(pilot, "p")  # park: the lane ends and nothing starts afresh
        assert deck.lanes["L01"].finished
        assert selected(app) == cursor_key(app) == "L02"

    drive(app, script, SIZE)


def test_a_lane_that_ends_on_its_own_keeps_the_selection_even_after_an_earlier_answer_once_the_player_moved():
    """The answer counts while the selection stays on the lane: once the player went to
    another lane and back, a later end is no answer of theirs and the selection stays."""
    deck, app = lanes("misc", "misc", "misc")
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{wrong}"))

    async def script(pilot):
        app.fleet.select_lane("L02")
        await pilot.pause()
        await press(pilot, "a")  # rejected: the lane carries on
        assert not deck.lanes["L02"].finished and selected(app) == "L02"
        await press(pilot, "down", "up")
        assert selected(app) == "L02"
        deck.report("L02", TurnReport(action="gave up", gave_up="nothing left to try"))
        app.refresh_view()
        await pilot.pause()
        assert deck.lanes["L02"].finished
        assert selected(app) == "L02" and cursor_key(app) == FINISHED_ROW  # where the lane went, as before

    drive(app, script, SIZE)


def test_an_answer_that_leaves_the_lane_going_stops_counting_so_its_later_end_keeps_the_selection():
    """A rejected flag: the lane carries on, and when it gives up later on its own, with the
    selection never moved, it is no answer of the player's and the selection stays on it."""
    deck, app = lanes("misc", "misc", "misc")
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{wrong}"))

    async def script(pilot):
        app.fleet.select_lane("L02")
        await pilot.pause()
        await press(pilot, "a")  # rejected: the lane carries on
        assert not deck.lanes["L02"].finished and selected(app) == "L02"
        deck.report("L02", TurnReport(action="gave up", gave_up="nothing left to try"))
        app.refresh_view()
        await pilot.pause()
        assert deck.lanes["L02"].finished
        assert selected(app) == "L02" and cursor_key(app) == FINISHED_ROW

    drive(app, script, SIZE)


def test_a_decline_that_leaves_the_lane_going_stops_counting_as_well():
    deck, app = lanes("misc", "misc", "misc")
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{maybe}"))

    async def script(pilot):
        app.fleet.select_lane("L02")
        await pilot.pause()
        await press(pilot, "d")  # declined: the lane carries on
        assert not deck.lanes["L02"].finished and deck.lanes["L02"].pending is None
        deck.report("L02", TurnReport(action="gave up", gave_up="nothing left to try"))
        app.refresh_view()
        await pilot.pause()
        assert deck.lanes["L02"].finished
        assert selected(app) == "L02" and cursor_key(app) == FINISHED_ROW

    drive(app, script, SIZE)


def test_a_flag_on_its_way_to_the_platform_still_counts_until_its_answer_comes_back():
    """With a platform over the network the answer comes later: the approval counts while the
    flag is on its way, so a correct answer then moves the selection on; a wrong one settles
    it, and a later end of the lane keeps the selection."""
    sent: list[tuple[str, str, str]] = []
    deck, app = lanes("misc", "misc", "misc", submitter=lambda *item: sent.append(item))
    deck.report("L01", TurnReport(action="cat flag.txt", flag=RIGHT))
    deck.report("L02", TurnReport(action="cat flag.txt", flag="flag{wrong}"))

    async def script(pilot):
        app.fleet.select_lane("L01")
        await pilot.pause()
        await press(pilot, "a")
        assert sent and deck.sending("L01") and not deck.lanes["L01"].finished
        app.refresh_view()
        await pilot.pause()
        assert selected(app) == "L01"
        deck.platform_verdict("L01", RIGHT, True)
        app.refresh_view()
        await pilot.pause()
        assert deck.lanes["L01"].finished
        assert selected(app) == cursor_key(app) == "L02"  # the lane that needs the player
        await press(pilot, "a")
        assert deck.sending("L02")
        deck.platform_verdict("L02", "flag{wrong}", False)
        app.refresh_view()
        await pilot.pause()
        assert not deck.lanes["L02"].finished and selected(app) == "L02"
        deck.report("L02", TurnReport(action="gave up", gave_up="nothing left to try"))
        app.refresh_view()
        await pilot.pause()
        assert deck.lanes["L02"].finished
        assert selected(app) == "L02" and cursor_key(app) == FINISHED_ROW

    drive(app, script, SIZE)


def test_a_lane_answered_under_a_filter_it_then_leaves_goes_on_to_the_next_lane_that_needs_the_player():
    """'/filter confirm' (flags submitted by hand, waiting for the player to say how it went),
    then a: the lane is solved, folds and no longer matches the filter. The selection goes to
    the first lane shown that needs the player, in attention order, not to whatever row sits
    at the old cursor's place."""
    deck, app = lanes("misc", "misc", "misc", "misc", verify=lambda challenge_id, flag: None)
    for lane_id in ("L04", "L02", "L03"):  # L04 waits longest: the most urgent
        deck.report(lane_id, TurnReport(action="cat flag.txt", flag=f"flag{{{lane_id}}}"))
        assert deck.apply(Approve(lane_id)).ok and deck.lanes[lane_id].pending.kind is PendingKind.CONFIRM
        deck.clock.advance(60.0)

    async def script(pilot):
        app.fleet.select_lane("L02")
        app.fleet.set_filter("confirm")
        await pilot.pause()
        assert lane_rows(app) == ["L02", "L03", "L04"] and selected(app) == cursor_key(app) == "L02"
        await press(pilot, "a")  # accepted, as the player says
        assert deck.lanes["L02"].finished
        assert row_keys(app) == ["L03", "L04"]  # the solved lane no longer matches the filter
        assert [lane.id for lane in deck.needing()][0] == "L04"
        assert selected(app) == cursor_key(app) == "L04"  # not L03, the row at the old cursor's place

    drive(app, script, SIZE)
