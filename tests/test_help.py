"""`?` opens help for where the player is (P65).

In a lane's view `?` on the empty chat box opens help, and with text in the box it is a question
mark. Help opens on "now": the keys the simple layout's key line has for the lane the keys act
on, each with its sentence; then the keys of the view it was opened from, then the other view's.
These tests press the keys in a console and read the dialog off the screen (test_console's
helpers rebuild the terminal from the SVG export), and check that nothing was sent to a lane by
a `?` that opened help.

Decks are synthetic (test_layout's: a driver that does no work); nothing needs a model or a
network.
"""

from __future__ import annotations

import re

import pytest
from textual import events

from ctf_flightdeck.console import fleet, focus, screens
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import (
    BATCH_KEY_HELP,
    BOTH_KEY_HELP,
    HELP_KEY_WIDTH,
    KEY_HELP,
    LANE_KEY_HELP,
    NOW_HELP,
    HelpScreen,
)
from ctf_flightdeck.core.deck import QueueEntry
from ctf_flightdeck.core.driver import FileChange, TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig
from test_console import (
    OSC,
    bar,
    drive,
    footer_line,
    open_focus,
    osc,
    press,
    prompt_text,
    quiet_deck,
    region_text,
    shown,
    terminal_frame,
    type_line,
)
from test_layout import LAYOUTS, SIZE, console, release, three_lanes

PHONE = (60, 40)  # the compact layout
TALL = (160, 190)  # every row of help on screen at once: nothing to scroll to
LANE_NOW = {"L01": ["esc", "/", "?", "ctrl+o"], "L02": ["1-9", "esc", "/", "?", "ctrl+o"], "L03": ["1-9", "esc", "/", "?", "ctrl+o"]}
LIST_NOW = {"L01": ["enter", "/", "?", "q"], "L02": ["a", "d", "enter", "/", "?", "q"], "L03": ["1-9", "x", "enter", "/", "?", "q"]}
NAMES = {"L01": "Alpha", "L02": "Beta", "L03": "Gamma"}


def body(app: FlightdeckApp) -> list[str]:
    """The rows of the open help's text as drawn, less its scrollbar."""
    assert isinstance(app.screen, HelpScreen)
    return [re.sub(r"[▁▂▃▄▅▆▇█▔]+$", "", line.rstrip()).rstrip() for line in region_text(app, "#help-body").splitlines()]


def now(app: FlightdeckApp) -> tuple[str, list[str]]:
    """Help's first block as drawn: its heading, and the key of each row under it down to the
    first blank row (a row with nothing in the key column is the row above, wrapped)."""
    rows = body(app)
    at = next(i for i, row in enumerate(rows) if row.strip())
    heading = rows[at]
    indent = len(heading) - len(heading.lstrip())
    keys = []
    for row in rows[at + 1:]:
        if not row.strip():
            break
        key = row[indent:indent + HELP_KEY_WIDTH].strip()
        if key:
            keys.append(key)
    return heading.strip(), keys


def line_keys(app: FlightdeckApp) -> list[str]:
    """The keys on the key line as drawn: the first word of each `key label` pair."""
    return [pair.split(" ")[0] for pair in footer_line(app).strip().split("  ")]


def hints(deck, lane_id: str) -> list[str]:
    return list(deck.lanes[lane_id].hints)


# ---------------------------------------------------------------------- in a lane: the key


def test_in_a_lane_a_question_mark_on_the_empty_chat_box_opens_help_on_that_lane_and_sends_nothing():
    deck, app = three_lanes("simple")
    plan = deck.lanes["L03"].plan

    async def script(pilot):
        view = await open_focus(pilot, app, "L03")
        assert app.focused is bar(app).field and bar(app).field.value == ""
        on_line = line_keys(app)
        assert footer_line(app).strip() == "1-9 answer  esc lanes  / commands  ? help  ctrl+o details"
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen) and app.screen.view == "lane"
        heading, keys = now(app)
        assert heading == "This lane, now: L03 · Gamma"
        assert keys == on_line == LANE_NOW["L03"]  # the keys the key line shows, in its order
        said = prompt_text(app)
        for key in keys:  # each with its sentence
            assert f"{key} {NOW_HELP['lane'][key]}" in said, key
        assert "Back to the lane list" in said and "Keys in a lane" in said
        await press(pilot, "escape")
        assert app.screen is view and app.focused is bar(app).field and bar(app).field.value == ""  # back where the player was
        assert hints(deck, "L03") == [] and deck.lanes["L03"].plan == plan  # the lane heard nothing

    drive(app, script, SIZE)


def test_with_text_in_the_chat_box_a_question_mark_is_a_question_mark_and_is_sent_with_the_message():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L01")
        await press(pilot, *"why", "question_mark")
        assert isinstance(app.screen, FocusScreen) and bar(app).field.value == "why?"
        await press(pilot, "enter")
        assert hints(deck, "L01") == ["why?"]
        await press(pilot, "space", "question_mark")  # a space first: the box is not empty, so this one is text too
        assert isinstance(app.screen, FocusScreen) and bar(app).field.value == " ?"
        await press(pilot, "enter")
        assert hints(deck, "L01") == ["why?", "?"]
        app.post_message(events.Paste("?really"))  # pasted into the empty box: text, whatever it starts with
        await pilot.pause()
        assert isinstance(app.screen, FocusScreen) and bar(app).field.value == "?really"

    drive(app, script, SIZE)


def test_from_the_files_pane_a_question_mark_opens_help_only_while_the_chat_box_is_empty():
    deck, app = three_lanes("simple")
    deck.report("L01", TurnReport(action="write solve.py", files=(FileChange("solve.py", "+++ b/solve.py\n+print(1)\n", status="added"),)))

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        app.run_command("/diff", "L01")
        await pilot.pause()
        assert app.focused.id == "files"
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen) and now(app)[0] == "This lane, now: L01 · Alpha"
        await press(pilot, "escape")
        assert app.screen is view and bar(app).field.value == ""
        bar(app).field.value = "is it base64"  # a draft in the box, and the focus on the files again
        view.query_one("#files").focus()
        await pilot.pause()
        assert app.focused.id == "files"
        await press(pilot, "question_mark")
        assert app.screen is view and bar(app).field.value == "is it base64?" and app.focused is bar(app).field

    drive(app, script, SIZE)


@pytest.mark.parametrize(("layout", "size"), [("simple", SIZE), ("deck", SIZE), ("deck", PHONE), ("simple", PHONE)],
                         ids=["simple", "deck", "compact", "compact-of-simple"])
def test_in_every_layout_a_lanes_help_opens_on_the_keys_that_apply_to_that_lane_now(layout, size):
    deck, app = three_lanes(layout)

    async def script(pilot):
        for lane_id in ("L01", "L02"):
            view = await open_focus(pilot, app, lane_id)
            await press(pilot, "question_mark")
            assert isinstance(app.screen, HelpScreen), lane_id
            assert now(app) == (f"This lane, now: {lane_id} · {NAMES[lane_id]}", LANE_NOW[lane_id])  # the answers only for a lane that has any
            await press(pilot, "question_mark")  # the same key closes it
            assert app.screen is view
        assert hints(deck, "L01") == [] and deck.lanes["L02"].pending is not None  # no `?` reached a lane, and none answered one

    drive(app, script, size)


def test_typing_help_in_a_lane_opens_the_same_help_as_the_key():
    deck, app = three_lanes("simple")

    async def script(pilot):
        await open_focus(pilot, app, "L02")
        await type_line(pilot, "/help")
        assert isinstance(app.screen, HelpScreen) and app.screen.view == "lane"
        assert now(app) == ("This lane, now: L02 · Beta", LANE_NOW["L02"])

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- in the lane list


@pytest.mark.parametrize("layout", LAYOUTS)
def test_in_the_lane_list_help_opens_on_the_selected_lanes_keys(layout):
    deck, app = three_lanes(layout)

    async def script(pilot):
        for lane_id in ("L01", "L02", "L03"):
            app.fleet.select_lane(lane_id)
            await pilot.pause()
            on_line = line_keys(app)
            await press(pilot, "question_mark")
            assert isinstance(app.screen, HelpScreen) and app.screen.view == "list"
            heading, keys = now(app)
            assert heading == f"The selected lane, now: {lane_id} · {NAMES[lane_id]}" and keys == LIST_NOW[lane_id]
            if layout == "simple":
                assert keys == on_line  # what the key line under the list shows
            said = prompt_text(app)
            for key in keys:
                assert f"{key} {NOW_HELP['list'][key]}" in said, key
            await press(pilot, "escape")
            assert isinstance(app.screen, FleetScreen)
        assert deck.lanes["L02"].pending is not None and hints(deck, "L01") == []

    drive(app, script, SIZE)


@pytest.mark.parametrize(("by_hand", "keys"), [(True, ["/new", "?", "q"]), (False, ["?", "q"])], ids=["by-hand", "platform"])
def test_with_no_lane_help_says_so_and_opens_on_what_can_be_done(by_hand, keys):
    deck, app = console(by_hand=by_hand, layout="simple")

    async def script(pilot):
        on_line = line_keys(app)
        await press(pilot, "question_mark")
        assert now(app) == ("Now, with no lane selected", keys) and keys == on_line
        if by_hand:
            assert "/new Hand a challenge to a lane: a form for its name, its text, its files or a screenshot" in prompt_text(app)

    drive(app, script, SIZE)


def test_on_the_board_help_is_about_the_challenges_only_lane_and_about_none_when_it_has_no_lane():
    deck, app = three_lanes("deck")
    deck.release([Challenge("delta", "Delta", "misc", 100)], [])  # on the board, with no lane

    async def script(pilot):
        app.fleet.select_challenge("beta")
        await pilot.pause()
        await press(pilot, "question_mark")
        assert now(app) == ("The selected lane, now: L02 · Beta", LIST_NOW["L02"])
        await press(pilot, "escape")
        app.fleet.select_challenge("delta")
        await pilot.pause()
        await press(pilot, "question_mark")
        assert now(app) == ("Now, with no lane selected", ["/new", "?", "q"])  # no key acts on a lane from here

    drive(app, script, SIZE)


@pytest.mark.parametrize("layout", LAYOUTS)
def test_a_filter_that_hides_the_selected_lane_gives_help_no_lane_as_the_keys_have_none(layout):
    deck, app = three_lanes(layout)

    async def script(pilot):
        app.fleet.select_lane("L02")
        app.fleet.set_filter("gamma")  # hides the selected lane: every key refuses it
        await pilot.pause()
        assert app.fleet.selected_lane == "L02" and app.fleet.bar_lane() is None
        await press(pilot, "question_mark")
        assert now(app) == ("Now, with no lane selected", ["/new", "?", "q"])
        assert "Beta" not in prompt_text(app).split("Keys in the lane list")[0]  # "now" names no lane
        await press(pilot, "escape")
        app.fleet.set_filter("")  # the selection is shown again, and help is about it again
        await pilot.pause()
        await press(pilot, "question_mark")
        assert now(app) == ("The selected lane, now: L02 · Beta", LIST_NOW["L02"])

    drive(app, script, SIZE)


def test_in_the_command_bar_a_question_mark_opens_help_only_while_the_bar_is_empty():
    deck, app = three_lanes("simple")

    async def script(pilot):
        app.fleet.select_lane("L01")
        await press(pilot, "slash", "backspace")  # in the bar, with nothing in it
        assert app.focused is bar(app).field and bar(app).field.value == ""
        await press(pilot, "question_mark")
        assert isinstance(app.screen, HelpScreen) and now(app)[0] == "The selected lane, now: L01 · Alpha"
        await press(pilot, "escape")
        assert isinstance(app.screen, FleetScreen) and app.focused is bar(app).field  # still typing
        await press(pilot, *"ok", "question_mark")
        assert isinstance(app.screen, FleetScreen) and bar(app).field.value == "ok?"
        await press(pilot, "enter")
        assert hints(deck, "L01") == ["ok?"]

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the dialog


@pytest.mark.parametrize("view", ["list", "lane"])
def test_help_has_every_row_from_either_view_and_starts_with_the_view_it_was_opened_from(view):
    deck, app = three_lanes("simple")

    async def script(pilot):
        if view == "lane":
            await open_focus(pilot, app, "L01")
        await press(pilot, "question_mark")
        assert app.screen.query_one("#help-body").max_scroll_y == 0  # all of it is on screen
        rows = [row.strip() for row in body(app)]
        at = [rows.index(heading) for heading in ("Keys in a lane", "Keys in the lane list", "Keys in both", "Board")]
        assert at[2] < at[3] and max(at[0], at[1]) < at[2]
        assert (at[0] < at[1]) is (view == "lane")  # its own view's keys first
        assert rows.index(now(app)[0]) < min(at)  # and "now" before them all
        said = prompt_text(app)
        for key, text in KEY_HELP + BATCH_KEY_HELP + LANE_KEY_HELP + BOTH_KEY_HELP:
            assert f"{key} {text}" in said, key
        assert "Commands (the bar at the bottom" in said and "Alerts (lanes that need you come first" in said

    drive(app, script, TALL)


def test_each_view_lists_its_own_keys_and_no_row_says_in_a_lane_of_a_list_key():
    listed, lane = dict(KEY_HELP + BATCH_KEY_HELP), dict(LANE_KEY_HELP)
    assert {"ctrl+n", "ctrl+o", "pgup pgdn", "typing"} <= set(lane) and not {"ctrl+n", "ctrl+o"} & set(listed)
    assert {"p", "h", "r", "f", "k", "e", "t", "a", "d", "A", "x", "s", "q", "space"} <= set(listed) and not {"p", "k", "q", "A", "space"} & set(lane)
    assert lane["?"] == "This help, while the chat box is empty; with text in the box it is a question mark"
    assert listed["?"] == "This help, for where you are; in the command bar, only while it is empty"
    assert lane["esc"] == "Back to the lane list" and listed["esc"] == "Leave the command bar, close the peek, or clear the filter"
    assert {"mouse drag", "ctrl+c", "ctrl+q"} == set(dict(BOTH_KEY_HELP))
    assert HELP_KEY_WIDTH == len("enter on board")  # the widest key: one column of keys down the dialog


def test_every_key_a_simple_key_line_can_show_has_a_sentence_and_help_refuses_a_view_it_does_not_know():
    in_list = {shown_ for _, shown_, _ in (fleet.NEW_KEY, *fleet.SIMPLE_KEYS)}
    in_lane = {key for key, _ in (focus.SIMPLE_ANSWER_LABEL, *focus.SIMPLE_KEY_LABELS)}
    assert set(NOW_HELP) == set(screens.HELP_VIEWS) == {"list", "lane"}
    assert set(NOW_HELP["list"]) == in_list and set(NOW_HELP["lane"]) == in_lane  # none missing, none left over
    assert all(text and text[0].isupper() for sentences in NOW_HELP.values() for text in sentences.values())
    with pytest.raises(ValueError, match="help is opened from one of"):
        HelpScreen(mock=False, view="home")


def test_a_challenges_name_in_helps_heading_is_made_safe_and_is_never_markup():
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",)))
    deck.release(
        [Challenge("evil", "Evil " + osc("nm") + " two\nrows", "misc", 100), Challenge("mark", "[@click=app.quit]x[/] [b]bold[/b]", "misc", 100)],
        [QueueEntry("evil", "glm"), QueueEntry("mark", "glm")],
    )
    app = FlightdeckApp(deck, refresh_seconds=None, layout="simple")

    async def script(pilot):
        await press(pilot, "question_mark")
        assert OSC not in terminal_frame(app)
        assert now(app)[0] == f"The selected lane, now: L01 · Evil {shown('nm')}^[\\ two ⏎ rows"  # one row: the newline is folded
        await press(pilot, "escape")
        await open_focus(pilot, app, "L02")
        await press(pilot, "question_mark")
        assert OSC not in terminal_frame(app)
        assert now(app)[0] == "This lane, now: L02 · [@click=app.quit]x[/] [b]bold[/b]"  # shown as it is: no link, no bold
        await pilot.click("#help-body", offset=(30, 1))  # on the name: nothing to click
        await pilot.pause()
        assert isinstance(app.screen, HelpScreen) and app.is_running

    drive(app, script, SIZE)


def test_in_the_mock_the_first_rows_say_what_quit_does_there():
    from test_console import make

    world, app = make("sstv")

    async def script(pilot):
        await press(pilot, "question_mark")
        heading, keys = now(app)
        assert heading.startswith("The selected lane, now: L") and keys[-1] == "q"
        first = " ".join(" ".join(body(app)).split()).split("Keys in the lane list")[0]
        assert "q Quit (the mock has nothing to stop, so it never asks)" in first and "asks first" not in first

    drive(app, script, SIZE)


# ---------------------------------------------------------------------- the docs


def test_the_spec_the_guide_and_the_changelog_say_of_help_what_the_console_draws():
    """The spec's Help section names each of help's headings in the words the dialog draws them;
    the spec, the changelog and the roadmap give a lane's simple key line as focus draws it; and
    no page still sends a player in a lane to `/help all keys`."""
    from test_docs_commands import ROOT, flat, read, section

    spec, guide = read(ROOT / "docs" / "CONSOLE-SPEC.md"), read(ROOT / "docs" / "GUIDE.md")
    changelog, roadmap = read(ROOT / "CHANGELOG.md"), read(ROOT / "docs" / "ROADMAP.md")
    help_ = flat(section(spec, "### Help"))
    for heading in (*screens.NOW_HEADING.values(), screens.NOW_NO_LANE, *screens.KEYS_HEADING.values(), screens.BOTH_HEADING):
        assert heading in help_, heading
    assert "`?`, `esc` or `q` closes it" in help_ and {"escape", "question_mark", "q"} <= {b.key for b in HelpScreen.BINDINGS}
    line = focus._key_line(focus.SIMPLE_KEY_LABELS).plain
    assert line == "esc lanes  / commands  ? help  ctrl+o details"
    for page in (spec, changelog, roadmap):
        assert f"`{flat(line)}`" in flat(page), "a page gives another key line"  # wrapped as it may be
    answered = focus._key_line((focus.SIMPLE_ANSWER_LABEL, *focus.SIMPLE_KEY_LABELS)).plain
    assert f"{len(answered) + focus.KEY_MARGIN} columns with the answers" in flat(spec)
    for page in (spec, guide, changelog):
        assert "/help all keys" not in flat(page)
    assert "`?` on the empty chat box opens help for that lane" in flat(guide)
