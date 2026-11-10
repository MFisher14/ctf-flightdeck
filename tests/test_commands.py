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
