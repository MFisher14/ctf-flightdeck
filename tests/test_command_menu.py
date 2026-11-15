"""The command bar's menu in the console: a `/` that forgives (P62).

What the menu lists is loose (a word inside a name, an alias, the words a command takes) and
what enter runs is not: these tests type into the bar of a console and read the screen, the
bar and the deck. The matching itself is in test_commands.py.

Decks are synthetic (test_layout's: a driver that does no work), every theme file is the
test's own under tmp_path, and nothing needs a model or a network.
"""

from __future__ import annotations

from ctf_flightdeck.console import theme
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.commands import COMMANDS
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, ChallengeStatus, LaneState
from test_console import assert_warning, bar, color_of, open_focus, press, prompt_text, status_line
from test_layout import SIZE, console, drive, menu_text, release, three_lanes


def rows(app: FlightdeckApp) -> list[str]:
    """The open menu's rows as the screen shows them, each with its runs of spaces as one."""
    return [" ".join(line.strip("│ ").split()) for line in menu_text(app).splitlines()[1:-1] if line.strip("│ ")]


def listed(app: FlightdeckApp) -> list[str]:
    return [completion.text for completion in bar(app).completions]


# ---------------------------------------------------------------------- aliases


def test_the_menu_shows_a_commands_aliases_beside_its_name_and_help_lists_them():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await press(pilot, "slash", "q")
        assert rows(app) == ["/quit (/q, /exit) quit flightdeck (asks first while lanes are open)", "/queue <challenge> queue a parked or new challenge"]
        assert bar(app).menu.highlighted == 0
        await press(pilot, "backspace", *"set")
        assert listed(app) == ["/settings "] and rows(app)[0].startswith("/settings your setup and its health")
        await press(pilot, "escape", "escape", "question_mark")
        said = prompt_text(app)
        assert "quit flightdeck (asks first while lanes are open) (also /q, /exit)" in said
        assert "back to the fleet (also /lanes)" in said and "/settings" in said
        assert said.count("(also /") == 2  # the two commands that have one

    drive(app, script, (160, 200))


def test_an_alias_typed_whole_runs_its_command():
    stopped = []

    async def on_exit():
        stopped.append(1)

    deck, app = three_lanes("simple", on_exit=on_exit)  # a run's console: quitting asks first while lanes are open

    async def script(pilot):
        await press(pilot, "slash", "q", "enter")  # /q is a command, whole: enter runs it, though /queue is listed too
        assert type(app.screen).__name__ == "QuitPrompt" and stopped == []  # it asks, as /quit does
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen) and bar(app).field.value == ""
        await open_focus(pilot, app, "L01")
        await press(pilot, "slash", *"lanes", "enter")
        assert isinstance(app.screen, FleetScreen)

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the loose list, the strict enter


def test_enter_on_a_name_found_loosely_fills_the_bar_and_runs_nothing():
    deck, app = three_lanes("simple")

    async def script(pilot):
        said = status_line(app)
        await press(pilot, "slash", *"over")
        assert listed(app) == ["/takeover "] and rows(app)[0].startswith("/takeover a shell in the lane's workspace")
        await press(pilot, "enter")
        assert bar(app).field.value == "/takeover " and bar(app).field.has_focus  # filled, for the player to read and send
        assert isinstance(app.screen, FleetScreen) and all(lane.state is not LaneState.TAKEOVER for lane in deck.lanes.values())
        assert status_line(app) == said  # nothing ran, so nothing was said

    drive(app, script, SIZE)


def test_what_names_no_command_is_said_in_one_muted_row_and_enter_reports_it():
    deck, app = three_lanes("simple")
    before = {lane.id: (lane.state, lane.pending) for lane in deck.lanes.values()}

    async def script(pilot):
        await press(pilot, "slash", *"zz")
        menu = bar(app)
        assert menu.menu_open and menu.completions == [] and rows(app) == ['No commands match "/zz"']
        assert menu.menu.highlighted is None
        row = menu.menu.region.y + 1
        assert color_of(app, "No commands match", row) == theme.MUTED.lower()
        await press(pilot, "down")
        assert menu.menu.highlighted is None  # it is not a row to take
        await press(pilot, "backspace", "backspace")
        assert len([c for c in menu.completions if not c.suggested]) == len(COMMANDS) and menu.menu.highlighted == 0  # the list is back
        await press(pilot, *"zz", "space", "x")
        assert rows(app) == ['No commands match "/zz"']  # still the name it does not know
        await press(pilot, "enter")
        assert_warning(app, "Unknown command /zz: type / to see the list")
        assert menu.field.value == "" and not menu.menu_open
        assert {lane.id: (lane.state, lane.pending) for lane in deck.lanes.values()} == before

    drive(app, script, SIZE)


def test_a_stray_word_after_approve_is_still_refused_and_the_menu_offers_no_lane_for_it():
    deck, app = three_lanes("simple")

    async def script(pilot):
        assert app.fleet.selected_lane == "L02" and deck.lanes["L02"].pending is not None  # the lane a loose reading would approve
        await press(pilot, "slash", *"approve", "space")
        typed = bar(app)
        assert [c.text for c in typed.completions if not c.suggested] == []  # no lane, no word: approve is typed whole
        await press(pilot, "2")
        assert typed.completions == [] and not typed.menu_open
        await press(pilot, "enter")
        assert_warning(app, "/approve takes no argument; name a lane like /approve L02 (or /approve all)")
        assert deck.lanes["L02"].pending is not None and deck.lanes["L02"].state is LaneState.WAITING

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the words after a name


def test_open_lists_the_lanes_and_enter_takes_a_row_only_once_the_arrow_keys_chose_it():
    deck, app = three_lanes("simple")

    async def script(pilot):
        selected = app.fleet.selected_lane
        assert selected == "L02"  # not the first row of the menu below
        await press(pilot, "slash", *"open", "space")
        menu = bar(app)
        assert rows(app) == ["/open L01 Alpha · run", "/open L02 Beta · wait", "/open L03 Gamma · run"]
        assert menu.menu.highlighted is None  # nothing looks chosen: enter sends what is typed
        await press(pilot, "enter")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == selected  # /open alone, as it always was
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen)

        await press(pilot, "slash", *"open", "space", "down", "down", "down")
        assert menu.menu.highlighted == 2
        await press(pilot, "enter")
        assert menu.field.value == "/open L03" and isinstance(app.screen, FleetScreen)  # the row, into the bar
        assert not menu.menu_open  # a word typed whole: nothing left to offer
        await press(pilot, "enter")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == "L03"

    drive(app, script, SIZE)


def test_tab_takes_the_first_word_when_none_is_chosen_and_a_lane_is_found_by_its_challenge():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await press(pilot, "slash", *"open", "space", "tab")
        assert bar(app).field.value == "/open L01" and bar(app).field.has_focus
        await press(pilot, "escape", "escape")
        await press(pilot, "slash", *"open", "space", *"gam")
        assert rows(app) == ["/open L03 Gamma · run"]
        await press(pilot, "tab")
        assert bar(app).field.value == "/open L03"
        await press(pilot, "escape", "escape")
        await press(pilot, "slash", *"lay", "enter")  # the name, then its words
        assert bar(app).field.value == "/layout " and rows(app) == [
            "/layout simple the lanes and what needs you (in use)", "/layout deck the board and every column"]
        await press(pilot, "d", "tab", "enter")
        assert app.layout == "deck" and "layout deck for this run" in status_line(app)

    drive(app, script, SIZE)


def test_theme_lists_the_built_in_themes_and_the_players_own(tmp_path):
    folder = tmp_path / "themes"
    folder.mkdir()
    (folder / "night.toml").write_text('base = "nord"\n[colors]\naccent = "#ff5fd7"\n')
    (folder / "notes.txt").write_text("not a theme\n")
    deck, app = console(by_hand=True, layout="simple", themes_folder=folder, config_path=str(tmp_path / "config.toml"))

    async def script(pilot):
        await press(pilot, "slash", *"theme", "space")
        assert rows(app) == ["/theme flightdeck built in, in use", "/theme light built in", "/theme nord built in", "/theme gruvbox built in",
                             "/theme dracula built in", "/theme night yours"]
        await press(pilot, *"ni")
        assert listed(app) == ["/theme night"]
        await press(pilot, "tab", "enter")
        assert theme.active().name == "night" and "theme night for this run" in status_line(app)
        await press(pilot, "slash", *"theme", "space", "n")
        assert rows(app) == ["/theme nord built in", "/theme night yours, in use"]

    drive(app, script, SIZE)


def test_queue_lists_parked_and_new_challenges_and_an_open_menu_follows_the_deck():
    deck, app = console(by_hand=True)
    release(deck, "alpha", "beta")
    deck.release([Challenge("gamma", "Gamma ray", "web", 100)], [])  # on the board, not queued: new

    async def script(pilot):
        assert deck.challenges["gamma"].status is ChallengeStatus.NEW and deck.challenges["alpha"].status is ChallengeStatus.RUNNING
        await press(pilot, "slash", *"queue", "space")
        menu = bar(app)
        assert rows(app) == ["/queue gamma Gamma ray · new"]  # not the two a lane is on
        await press(pilot, "down")
        assert menu.menu.highlighted == 0
        assert deck.apply(iv.Kill("L01", requeue=False)).ok and deck.challenges["alpha"].status is ChallengeStatus.PARKED
        app.refresh_view()  # the console draws, as it does on every deck event: no key was pressed
        await pilot.pause()
        assert rows(app) == ["/queue alpha Alpha · parked", "/queue gamma Gamma ray · new"]
        assert menu.completions[menu.menu.highlighted].text == "/queue gamma"  # the row the arrow keys chose is still the one
        await press(pilot, "enter")
        assert menu.field.value == "/queue gamma" and deck.challenges["gamma"].status is ChallengeStatus.NEW  # filled, not run
        await press(pilot, "enter")
        assert deck.challenges["gamma"].status in (ChallengeStatus.QUEUED, ChallengeStatus.RUNNING)
        assert deck.challenges["alpha"].status is ChallengeStatus.PARKED

    drive(app, script, SIZE)


def test_the_focus_views_chat_box_lists_a_commands_words_too():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, "slash", *"open", "space", "b")
        assert listed(app) == ["/open L02"] and rows(app) == ["/open L02 Beta · wait"]
        await press(pilot, "tab", "enter")
        assert isinstance(app.screen, FocusScreen) and app.screen.lane_id == "L02"
        await press(pilot, "slash", *"sort", "space", "c")
        assert rows(app) == ["/sort cost most spent first"]

    drive(app, script, SIZE)


def test_a_challenges_name_is_drawn_as_untrusted_text_in_the_menu():
    deck, app = console(by_hand=True)
    deck.release([Challenge("odd", "two\nlines \x1b[31mred", "misc", 100)], [])

    async def script(pilot):
        await press(pilot, "slash", *"queue", "space")
        shown = menu_text(app)
        assert "\x1b" not in shown and len(rows(app)) == 1 and rows(app)[0].startswith("/queue odd two")
        assert "red · new" in rows(app)[0]  # one row, the escape left out

    drive(app, script, SIZE)


HOSTILE_ID = "od\x1b]0;T\x07d"  # ESC ] 0 ; ... BEL: the sequence that sets a terminal's title
SAFE_ID = "od^[]0;T^Gd"  # the same id as text.untrusted() shows it


def test_a_challenges_id_is_drawn_as_untrusted_text_in_the_menus_row():
    deck, app = console(by_hand=True)
    deck.release([Challenge(HOSTILE_ID, "Odd one", "misc", 100)], [])  # the id is the platform's text, like the name

    async def script(pilot):
        await press(pilot, "slash", *"queue", "space")
        assert listed(app) == [f"/queue {HOSTILE_ID}"]  # the row is this challenge's
        assert rows(app) == [f"/queue {SAFE_ID} Odd one · new"]  # each control character as a marker, none dropped
        assert "\x1b" not in menu_text(app) and "\x07" not in menu_text(app)

    drive(app, script, SIZE)


def test_a_row_put_into_the_bar_is_untrusted_text_too():
    deck, app = console(by_hand=True)
    deck.release([Challenge(HOSTILE_ID, "Odd one", "misc", 100)], [])

    async def script(pilot):
        await press(pilot, "slash", *"queue", "space", "tab")
        assert bar(app).field.value == f"/queue {SAFE_ID}"  # tab: the bar draws what it holds
        await press(pilot, "escape", "slash", *"queue", "space", "down", "enter")
        assert bar(app).field.value == f"/queue {SAFE_ID}"  # enter on a chosen row: the same way in
        assert deck.challenges[HOSTILE_ID].status is ChallengeStatus.NEW  # filled, not run

    drive(app, script, SIZE)


def test_a_suggestion_that_arrives_while_the_menu_is_open_leads_it_unless_the_arrow_keys_chose_a_row():
    deck, app = console(by_hand=True)
    release(deck, "alpha")

    async def script(pilot):
        await press(pilot, "slash")
        menu = bar(app)
        assert menu.menu.highlighted == 0 and listed(app)[0] == "/hint "
        deck.report("L01", TurnReport(action="cat flag.txt", flag="flag{synthetic}"))
        app.refresh_view()
        await pilot.pause()
        assert listed(app)[0] == "/approve L01" and menu.menu.highlighted == 0  # the new first row, as before
        await press(pilot, "down", "down")
        chosen = listed(app)[2]
        assert deck.apply(iv.Decline("L01")).ok
        app.refresh_view()
        await pilot.pause()
        assert "/approve L01" not in listed(app)
        assert listed(app)[menu.menu.highlighted] == chosen  # the list moved up a row; the chosen row is still the one

    drive(app, script, SIZE)
