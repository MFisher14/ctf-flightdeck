"""The command bar's parser and completion (no Textual needed)."""

from __future__ import annotations

import pytest

from ctf_flightdeck.console.commands import COMMANDS, CommandError, complete, lane_id, parse


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


def test_completion_narrows_by_prefix():
    assert [c.text for c in complete("/re")] == ["/redirect "]
    assert [c.text for c in complete("/e")] == ["/escalate "]
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


@pytest.mark.parametrize("command", ["approve", "escalate", "pause", "takeover"])
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
