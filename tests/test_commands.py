"""The command bar's parser and completion (no Textual needed)."""

from __future__ import annotations

import pytest

from ctf_flightdeck.config import LAYOUTS
from ctf_flightdeck.console.commands import (
    BY_ALIAS,
    BY_NAME,
    COMMANDS,
    SECOND_WORD,
    Command,
    CommandError,
    State,
    Word,
    by_alias,
    complete,
    find,
    lane_id,
    needs_lane,
    no_match,
    parse,
)
from ctf_flightdeck.core.attention import SortMode


def test_plain_text_is_a_message():
    parsed = parse("  try the PNG chunks  ")
    assert (parsed.command, parsed.lane, parsed.arg) == (None, None, "try the PNG chunks")


def test_command_with_text():
    parsed = parse("/redirect read the source first")
    assert parsed.command.name == "redirect"
    assert (parsed.lane, parsed.arg) == (None, "read the source first")


def test_a_lane_named_first_targets_that_lane():
    parsed = parse("/kill l7 park")
    assert (parsed.command.name, parsed.lane, parsed.arg) == ("kill", "L07", "park")


def test_a_lane_like_word_is_text_for_commands_that_take_no_lane():
    parsed = parse("/filter L07 web")
    assert (parsed.lane, parsed.arg) == (None, "L07 web")


def test_command_names_are_case_insensitive():
    assert parse("/APPROVE").command.name == "approve"


def test_unknown_command_fails_loudly():
    with pytest.raises(CommandError, match="/nope"):
        parse("/nope now")


def test_lane_ids_are_normalised():
    assert [lane_id(t) for t in ("L1", "l07", "L123", "x7", "L", "7")] == ["L01", "L07", "L123", None, None, None]


def test_completion_lists_every_command_for_a_bare_slash():
    names = [c.text.strip() for c in complete("/")]
    assert names == [f"/{c.name}" for c in COMMANDS]


def test_with_no_lane_the_commands_that_need_none_come_first_and_the_rest_keep_their_order():
    names = [c.text.strip() for c in complete("/", lane=False)]
    assert names[:4] == ["/new", "/help", "/config", "/queue"]
    assert names[4:] == [f"/{c.name}" for c in COMMANDS if c.name not in ("new", "help", "config", "queue")]
    assert sorted(names) == sorted(f"/{c.name}" for c in COMMANDS)  # every command, once
    # narrowed: still what needs no lane first, and a name that starts with it before one that has it inside
    assert [c.text for c in complete("/h", lane=False)] == ["/help ", "/hint ", "/unhold "]
    suggested = (("/unhold", "the queue is held: no key"),)
    assert [c.text for c in complete("/", suggested, lane=False)][:2] == ["/unhold", "/new "]  # a suggestion still leads


def test_completion_narrows_by_prefix():
    assert [c.text for c in complete("/re")] == ["/redirect "]
    assert [c.text for c in complete("/e")] == ["/escalate ", "/quit "]  # /quit: its alias /exit starts with it
    assert [c.text for c in complete("/es")] == ["/escalate "]
    assert complete("/zzz") == []


def test_suggestions_come_first_while_they_match():
    suggested = (("/redirect Decode it as SSTV", "ignores the hint"), ("/hint Think slow-scan", "ignores the hint"))
    first = complete("/", suggested)
    assert [c.text for c in first[:2]] == ["/redirect Decode it as SSTV", "/hint Think slow-scan"]
    assert all(c.suggested for c in first[:2]) and not first[2].suggested
    narrowed = complete("/red", suggested)
    assert [c.text for c in narrowed] == ["/redirect Decode it as SSTV", "/redirect "]


def test_no_completion_once_arguments_are_typed():
    assert complete("/redirect some plan") == []
    assert complete("hello") == []


def test_a_lane_id_must_be_the_whole_word():
    # 'l3x' is not lane L03: without the end anchor '/hint l3x try' would hint L03
    assert [lane_id(t) for t in ("l3x", "L07,", "L7a", "L 7")] == [None, None, None, None]
    parsed = parse("/hint l3x try this")
    assert (parsed.lane, parsed.arg) == (None, "l3x try this")
    parsed = parse("/hint l33t speak")
    assert (parsed.lane, parsed.arg) == (None, "l33t speak")  # not 'No lane L33'
    parsed = parse("/hint l33 speak")
    assert (parsed.lane, parsed.arg) == ("L33", "speak")  # a whole word that is a lane id is one


@pytest.mark.parametrize("command", ["approve", "dismiss", "escalate", "pause", "takeover"])
def test_a_lane_command_that_takes_no_argument_refuses_a_stray_word(command):
    # '/approve 2' meant for L02 must not approve the selected lane
    with pytest.raises(CommandError, match=rf"/{command} takes no argument; name a lane like /{command} L02"):
        parse(f"/{command} 2")
    with pytest.raises(CommandError, match="takes no argument"):
        parse(f"/{command} L02 now")
    parsed = parse(f"/{command} l2")
    assert (parsed.command.name, parsed.lane, parsed.arg) == (command, "L02", "")


@pytest.mark.parametrize("command", ["back", "help", "quit"])
def test_other_commands_that_take_no_argument_refuse_one_too(command):
    with pytest.raises(CommandError, match=rf"^/{command} takes no argument$"):
        parse(f"/{command} please")
    assert parse(f"/{command}").arg == ""


def test_open_takes_only_a_lane():
    with pytest.raises(CommandError, match="/open takes a lane"):
        parse("/open foo")
    with pytest.raises(CommandError, match="/open takes a lane"):
        parse("/open 3")
    with pytest.raises(CommandError, match="/open takes a lane"):
        parse("/open L03 now")
    assert (parse("/open l3").lane, parse("/open").lane) == ("L03", None)


def test_commands_with_arguments_keep_them():
    assert parse("/kill L02 park").arg == "park"
    assert parse("/diff solve.py").arg == "solve.py"
    assert parse("/sort Cost").arg == "Cost"
    assert parse("/fork L02 read the source").arg == "read the source"


def test_approve_all_names_no_lane_and_any_other_word_is_still_refused():
    parsed = parse("/approve ALL")
    assert (parsed.command.name, parsed.lane, parsed.arg) == ("approve", None, "all")
    assert not needs_lane(parsed)  # it goes over every lane: no lane is selected for it
    assert needs_lane(parse("/approve")) and needs_lane(parse("/approve L02")) and needs_lane(parse("a message"))
    assert not needs_lane(parse("/help"))
    with pytest.raises(CommandError, match="/approve all names no lane"):
        parse("/approve L02 all")
    with pytest.raises(CommandError, match=r"/approve takes no argument; name a lane like /approve L02 \(or /approve all\)"):
        parse("/approve everything")
    with pytest.raises(CommandError, match="takes no argument"):
        parse("/approve all now")


def test_the_menu_offers_approve_all_and_dismiss():
    labels = {c.label: c.help for c in complete("/")}
    assert "/approve [all]" in labels and "after a prompt" in labels["/approve [all]"]
    assert "/dismiss" in labels and "stays quiet" in labels["/dismiss"]


def test_theme_takes_a_name_or_nothing_and_acts_on_no_lane():
    parsed = parse("/theme nord")
    assert (parsed.command.name, parsed.lane, parsed.arg) == ("theme", None, "nord")
    assert parse("/theme").arg == "" and not needs_lane(parse("/theme")) and not needs_lane(parsed)
    assert (parse("/theme l7").lane, parse("/theme l7").arg) == (None, "l7")  # a theme file may be named like a lane
    assert [c.text for c in complete("/th")] == ["/theme "]
    labels = {c.label: c.help for c in complete("/")}
    assert labels["/theme [name]"] == "the console's colours; alone: try the themes you have, and save one"
    names = [c.name for c in COMMANDS]
    assert names.index("theme") == names.index("config") + 1  # beside the run's other settings


# ---------------------------------------------------------------------- a / that forgives (P62)


def texts(typed: str, **kw) -> list[str]:
    return [c.text for c in complete(typed, **kw)]


LANES = (Word("L01", "Alpha · run", "Alpha"), Word("L02", "Web one · wait", "Web one"), Word("L10", "Zed · paused", "Zed"),
         Word("L11", "One more · run", "One more"))
STATE = State(
    lanes=LANES,
    queueable=(Word("web-two", "Web two · parked", "Web two"), Word("17", "Late Entry · new", "Late Entry")),
    themes=(Word("flightdeck", "built in, in use"), Word("nord", "built in"), Word("night", "yours")),
    layout="deck",
)


def state() -> State:
    return STATE


def test_the_aliases_are_the_ones_decided_and_approve_has_none():
    assert {alias: command.name for alias, command in BY_ALIAS.items()} == {"q": "quit", "exit": "quit", "lanes": "back"}
    assert BY_NAME["approve"].aliases == ()  # the one command that spends a try is typed whole
    with pytest.raises(CommandError, match="Unknown command /a: type / to see the list"):
        parse("/a")


@pytest.mark.parametrize(("typed", "name"), [("/q", "quit"), ("/exit", "quit"), ("/EXIT", "quit"), ("/lanes", "back")])
def test_an_alias_typed_whole_is_its_command(typed, name):
    parsed = parse(typed)
    assert (parsed.command.name, parsed.lane, parsed.arg) == (name, None, "")
    assert parsed.command is BY_NAME[name] is find(typed[1:])


def test_settings_is_a_command_of_its_own_since_p90_and_config_keeps_its_arguments():
    parsed = parse("/settings")
    assert (parsed.command.name, parsed.lane, parsed.arg) == ("settings", None, "") and not needs_lane(parsed)
    assert BY_NAME["settings"].aliases == () and BY_NAME["config"].aliases == ()
    assert parse("/config lanes 8").arg == "lanes 8"
    # what /settings took as /config's alias is refused with where it went, never run as something else
    for typed, said in (("/settings lanes 8", "/config lanes 8"), ("/SETTINGS Submit auto", "/config Submit auto"),
                        ("/settings file", "/config file")):
        with pytest.raises(CommandError, match=rf"^/settings takes no argument: {said} changes this run's$"):
            parse(typed)
    with pytest.raises(CommandError, match=r"^/settings takes no argument$"):
        parse("/settings nord")
    names = [c.name for c in COMMANDS]
    assert names.index("settings") + 1 == names.index("config")  # beside the run's other settings


def test_an_alias_takes_what_its_command_takes_and_is_refused_as_its_command_is():
    with pytest.raises(CommandError, match=r"^/quit takes no argument$"):
        parse("/q now")
    with pytest.raises(CommandError, match=r"^/back takes no argument$"):
        parse("/lanes L02")


def test_an_alias_cannot_take_a_commands_name_or_another_commands_alias():
    quit_, back = Command("quit", "", "quit", lane=False, aliases=("q",)), Command("back", "", "back", lane=False)
    assert by_alias((quit_, back)) == {"q": quit_}
    with pytest.raises(ValueError, match="/back cannot be an alias of /quit"):
        by_alias((Command("quit", "", "quit", aliases=("back",)), back))
    with pytest.raises(ValueError, match="/q cannot be an alias of /queue"):
        by_alias((quit_, Command("queue", "", "queue", aliases=("q",))))


def test_the_menu_finds_a_command_from_the_second_word_of_its_name():
    assert texts("/over") == ["/takeover "] and texts("/hold") == ["/unhold "]
    assert texts("/pilot") == ["/autopilot "] and texts("/direct") == ["/redirect "]
    assert texts("/o") == ["/open ", "/takeover "]  # the name that starts with it first
    assert texts("/ver") == [] and texts("/ake") == []  # the start of a word, not anywhere in the name
    for name, second in SECOND_WORD.items():
        assert name in BY_NAME and name.endswith(second) and name != second


def test_the_menu_finds_a_command_from_an_alias_and_shows_the_aliases_beside_the_name():
    assert texts("/set") == ["/settings "] and texts("/ex") == ["/quit "] and texts("/lan") == ["/back "]
    assert texts("/la") == ["/layout ", "/back "]  # a name before an alias
    assert texts("/q") == ["/quit ", "/queue "]  # /q is /quit, whole: it leads the name that only starts with q
    assert texts("/lanes") == ["/back "] and texts("/EXIT") == ["/quit "]
    shown = {c.text.strip(): c.also for c in complete("/")}
    assert shown["/quit"] == "/q, /exit" and shown["/config"] == "" and shown["/back"] == "/lanes"
    assert [name for name, aliases in shown.items() if aliases] == ["/back", "/quit"]  # no other command has one
    assert texts("/", lane=False)[:4] == ["/new ", "/help ", "/config ", "/queue "]  # nothing typed: the order as it was


def test_what_the_menu_finds_loosely_is_not_what_runs():
    for typed in ("/over", "/hold", "/set", "/ex", "/qu"):
        assert complete(typed), typed
        with pytest.raises(CommandError, match=f"Unknown command {typed}: type / to see the list"):
            parse(typed)
    assert texts("/approve ") == [] and texts("/approve 2") == []  # no lane is offered after /approve
    with pytest.raises(CommandError, match=r"/approve takes no argument; name a lane like /approve L02"):
        parse("/approve 2")  # and a stray word is still not read as L02


def test_after_its_name_a_command_lists_the_words_it_takes():
    assert texts("/layout ") == [f"/layout {name}" for name in LAYOUTS] == ["/layout simple", "/layout deck"]
    assert texts("/sort ") == [f"/sort {mode.value}" for mode in SortMode]
    assert texts("/autopilot ") == ["/autopilot on", "/autopilot off"]
    assert texts("/layout d") == ["/layout deck"] and texts("/sort T") == ["/sort turns"] and texts("/autopilot o") == ["/autopilot on", "/autopilot off"]
    assert texts("/autopilot of") == ["/autopilot off"]
    assert texts("/layout x") == [] and texts("/sort cost now") == []
    by_text = {c.text: c for c in complete("/layout ", state=state)}
    assert by_text["/layout deck"].help == "the board and every column (in use)"
    assert by_text["/layout simple"].help == "the lanes and what needs you" and by_text["/layout simple"].label == "/layout simple"
    assert not any(c.suggested or c.also for c in by_text.values())


def test_copy_lists_what_it_copies_each_with_what_it_is():
    listed = complete("/copy ")
    assert [c.text for c in listed] == ["/copy output", "/copy command", "/copy flag", "/copy all"]
    assert all(c.help and not (c.suggested or c.also) for c in listed)
    assert listed[0].help == "the last output (also /copy alone)"
    assert texts("/copy f") == ["/copy flag"] and texts("/copy C") == ["/copy command"]
    assert texts("/copy flag") == [] and texts("/copy x") == []
    assert texts("/co") == ["/copy ", "/config "]  # the name first: the words only after the space


def test_a_word_typed_whole_is_not_listed_since_tab_would_change_nothing():
    assert texts("/layout deck") == [] and texts("/layout DECK ") == [] and texts("/sort lane") == []
    assert texts("/autopilot on") == []
    assert texts("/open l02", state=state) == [] and texts("/theme nord", state=state) == []


def test_open_lists_the_lanes_with_their_challenge_and_state():
    listed = complete("/open ", state=state)
    assert [(c.text, c.help) for c in listed] == [("/open L01", "Alpha · run"), ("/open L02", "Web one · wait"), ("/open L10", "Zed · paused"),
                                                 ("/open L11", "One more · run")]
    assert texts("/open l1", state=state) == ["/open L01", "/open L10", "/open L11"]  # l1 is L01, as parse reads it, and starts two more
    assert texts("/open L2", state=state) == ["/open L02"] and texts("/open 2", state=state) == []
    assert texts("/open web", state=state) == ["/open L02"]  # by its challenge's name
    assert texts("/open one", state=state) == ["/open L02", "/open L11"]  # from the start of any word of the name
    assert texts("/open ne", state=state) == [] and texts("/open web one", state=state) == ["/open L02"]
    assert texts("/op", state=state) == ["/open "]  # the name first: lanes only after the space


def test_queue_lists_the_challenges_it_is_for_and_theme_the_themes():
    assert [(c.text, c.help) for c in complete("/queue ", state=state)] == [("/queue web-two", "Web two · parked"), ("/queue 17", "Late Entry · new")]
    assert texts("/queue late", state=state) == ["/queue 17"] and texts("/queue entry", state=state) == ["/queue 17"]
    assert texts("/queue w", state=state) == ["/queue web-two"] and texts("/queue 1", state=state) == ["/queue 17"]
    assert [(c.text, c.help) for c in complete("/theme ", state=state)] == [
        ("/theme flightdeck", "built in, in use"), ("/theme nord", "built in"), ("/theme night", "yours")]
    assert texts("/theme n", state=state) == ["/theme nord", "/theme night"]


def test_the_console_is_asked_for_its_state_only_by_a_command_whose_words_follow():
    asked = []

    def counted() -> State:
        asked.append(1)
        return STATE

    for typed in ("/", "/op", "/open", "/hint ", "/hint L02 try the header", "/nope x", "plain text"):
        complete(typed, state=counted)
    assert asked == []
    assert texts("/open ", state=counted) == [f"/open {lane.text}" for lane in LANES] and asked == [1]
    assert texts("/open ") == [] and texts("/queue ") == [] and texts("/theme ") == []  # nobody to ask: nothing to offer


def test_a_command_without_words_of_its_own_lists_nothing_after_its_name():
    for typed in ("/hint ", "/kill ", "/kill p", "/approve ", "/config ", "/settings ", "/new ", "/attach ", "/note ", "/filter ", "/diff "):
        assert complete(typed, state=state) == [], typed
    assert [name for name, command in BY_NAME.items() if command.words] == ["copy", "open", "theme", "layout", "queue", "autopilot", "sort"]


def test_suggestions_still_lead_the_words_after_a_name():
    suggested = (("/open L10", "it found a flag"), ("/hint Think slow-scan", "ignores the hint"))
    listed = complete("/open ", suggested, state=state)
    assert [(c.text, c.suggested) for c in listed][:2] == [("/open L10", True), ("/open L01", False)]


def test_no_match_is_said_only_when_what_is_typed_names_no_command():
    assert no_match("/zz") == 'No commands match "/zz"' and complete("/zz") == []
    assert no_match("/zz and more") == 'No commands match "/zz"'  # the name it does not know, not the words after it
    assert no_match("/ x") == 'No commands match "/"'
    assert no_match("/layout x") == "" and no_match("/q") == "" and no_match("/Settings") == "" and no_match("/hint anything") == ""
    assert no_match("zz") == "" and no_match("") == ""  # a message to the lane is no command
    assert no_match("/ov") == 'No commands match "/ov"' and complete("/ov")  # asked only when the menu has nothing to list
