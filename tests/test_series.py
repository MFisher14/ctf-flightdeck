"""core/series.py: which challenges of a board are one series, read from their names alone.
Every name and description here is invented."""

from __future__ import annotations

import pytest

from ctf_flightdeck.core import series
from ctf_flightdeck.core.model import Challenge

FIRST = "Read the certificate of the service and give its common name."
FOLLOW_UP = "<p><em>Continuation of the same lab. See the first task.</em></p><p>Give the certificate's fingerprint.</p>"


@pytest.mark.parametrize("name,key,rest", [
    ("Tin Relay 1: Read the Certificate", "tin relay 1", "Read the Certificate"),
    ("Tin Relay 2: Hash the Icon Again", "tin relay 2", "Hash the Icon Again"),
    ("Harbor Lab - Part 2", "harbor lab", "Part 2"),
    ("Harbor Lab — The Gate", "harbor lab", "The Gate"),
    ("Harbor Lab–The Gate", "harbor lab", "The Gate"),
    ("Ghost Ship | Logbook", "ghost ship", "Logbook"),
    ("Harbor Lab Part 3", "harbor lab", "Part 3"),
    ("Harbor Lab (2/3)", "harbor lab", "(2/3)"),
    ("Harbor Lab [Task 2]", "harbor lab", "[Task 2]"),
    ("  HARBOR_lab:   the   gate ", "harbor lab", "the   gate"),
])
def test_the_series_key_is_the_shared_start_of_the_name(name, key, rest):
    assert series.split_name(name) == (key, rest)
    assert series.series_key(name) == key


@pytest.mark.parametrize("name", [
    "Web: SQL Login", "Warmup: Hello", "OSINT: Where", "Sanity Check - Hello",  # a category or a label
    "Task 2 - Read it", "Part 1: The start",  # only a part number
    "Plain Name",  # no separator, no part number
    "AB: tiny",  # too short to be a series' name
    "re-enter the vault",  # a hyphen inside a word is no separator
    "http://x.example/a",  # a colon with no space after it is none either
    ": nothing before", "nothing after: ", "",
])
def test_a_category_a_label_a_bare_part_number_or_no_separator_links_nothing(name):
    assert series.series_key(name) is None
    assert series.split_name(name) == (None, name.strip())


def test_a_name_is_read_only_as_far_as_its_cap_and_must_be_text():
    long = "Harbor Lab" + " x" * series.MAX_NAME + ": the end"  # the separator lies past the cap
    assert series.series_key(long) is None
    with pytest.raises(TypeError, match="a challenge's name is text, got NoneType"):
        series.series_key(None)


def test_the_continuation_wording_is_read_through_markup():
    assert series.continuation_marker(FOLLOW_UP) == "continuation of the same lab"
    assert series.continuation_marker("<i>See the <b>first</b> task</i> for details") == "see the first task"
    assert series.continuation_marker("This **follow-up to the previous** one is harder") == "follow-up to the previous"
    assert series.continuation_marker(FIRST) is None
    assert series.continuation_marker("a continuation of the story is not a lab") is None
    assert series.continuation_marker("") is None


def test_the_continuation_wording_past_the_cap_is_not_read():
    assert series.continuation_marker("x" * series.MAX_DESCRIPTION + " see the first task") is None


def challenge(cid: str, name: str) -> Challenge:
    return Challenge(cid, name, "misc", 100)


def test_siblings_are_the_other_challenges_with_the_same_key_in_board_order():
    board = [
        challenge("1", "Harbor Lab: Read"), challenge("2", "Web: Login"), challenge("3", "Harbor Lab - Fingerprint"),
        challenge("4", "Harbor  LAB (3/3)"), challenge("5", "Ghost Ship | Logbook"), challenge("6", "Web: Other"),
    ]
    assert [c.id for c in series.siblings(board, board[0])] == ["3", "4"]
    assert [c.id for c in series.siblings(board, board[3])] == ["1", "3"]
    assert series.siblings(board, board[4]) == []  # a key no other challenge has
    assert series.siblings(board, board[1]) == []  # "web" is a category: board[5] is no sibling
