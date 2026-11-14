"""Flag variants (flagvariants.py): the ranked other spellings of one value. Every flag here is invented."""

from __future__ import annotations

import re

import pytest

from ctf_flightdeck.flagformat import FlagFormatError
from ctf_flightdeck.flagvariants import (
    MAX_VALUE,
    MAX_VARIANTS,
    FlagVariantsError,
    Variant,
    describe,
    prefixes_of,
    variants,
)

DEFAULT = r"\w{1,64}\{[^{}\s]{1,256}\}"  # DeckConfig's own
LOOSE = r"(?i)(?:flag|CTF)\{[^{}]+\}"  # any case, two prefixes, spaces allowed in the body


def values(value: str, flag_format: str, **more) -> list[str]:
    return [v.value for v in variants(value, flag_format, **more)]


def changes(value: str, flag_format: str, **more) -> dict[str, tuple[str, ...]]:
    return {v.value: v.changes for v in variants(value, flag_format, **more)}


def test_a_body_in_capitals_gets_its_case_back_first():
    # what a one-case cipher gives: lower case is the likeliest, then a capital per word, then the weaker guesses
    got = variants("flag{ENIGMA_IS_FUN}", DEFAULT)
    assert [v.value for v in got] == [
        "flag{enigma_is_fun}", "flag{Enigma_Is_Fun}", "flag{3N1GM4_15_FUN}", "flag{3n1gm4_15_fun}", "flag{3n1gm4_15_Fun}",
    ]
    assert [v.changes for v in got[:3]] == [("case:lower",), ("case:title",), ("leet:leet",)]
    assert (got[0].score, got[1].score, got[3].score) == (0.5, 0.4, 0.125) and got[3].changes == ("case:lower", "leet:leet")
    assert got[0].what == "lower case" and got[3].what == "lower case, letters to leet"


def test_the_case_axis_is_only_offered_when_the_case_is_in_doubt():
    assert values("flag{Mixed_Case_Kept}", r"flag\{[A-Za-z_]+\}") == []  # its case is evidence: nothing to try
    assert values("flag{ABC}", r"flag\{[A-Za-z_]+\}") == []  # three capitals are not a lost case
    assert values("flag{ABCD}", r"flag\{[A-Za-z_]+\}") == ["flag{abcd}", "flag{Abcd}"]
    # the caller knows the case was lost: every other case is offered, UPPER last
    assert values("flag{Mixed_case}", r"flag\{[A-Za-z_]+\}", case_lost=True) == ["flag{mixed_case}", "flag{Mixed_Case}", "flag{MIXED_CASE}"]


def test_a_doubled_wrapper_is_fixed_first_and_every_later_variant_is_built_on_the_fix():
    got = variants("flag{FLAG{inner}}", r"(?i)flag\{.+\}")
    assert [(v.value, v.changes) for v in got] == [
        ("flag{inner}", ("fix:double-wrap",)),
        ("flag{1nn3r}", ("fix:double-wrap", "leet:leet")),
    ]
    assert got[0].score == 1.0 and got[0].what == "wrapped once, not twice"


def test_the_prefix_is_written_as_the_format_names_it():
    assert prefixes_of(LOOSE) == ("flag", "CTF")
    got = changes("FLAG{right}", LOOSE)
    assert list(got)[0] == "flag{right}" and got["flag{right}"] == ("fix:prefix:flag",)
    assert list(changes("ctf{right}", LOOSE).items())[0] == ("CTF{right}", ("fix:prefix:CTF",))
    # another word altogether: the format's first prefix
    assert list(changes("picoCTF{right}", LOOSE).items())[0] == ("flag{right}", ("fix:prefix:flag",))
    # no wrapper at all (the value need not match the format): wrapped in the first prefix
    assert list(changes("right", LOOSE).items())[0] == ("flag{right}", ("fix:wrap:flag",))
    # the format's other prefix is a weak guess, after the body's own
    assert got["CTF{right}"] == ("fix:prefix:flag", "wrap:prefix:CTF")
    assert list(got).index("CTF{right}") > list(got).index("flag{r1gh7}")
    assert variants("FLAG{right}", LOOSE)[0].what == "prefix written flag"


def test_a_format_that_names_no_literal_prefix_fixes_no_prefix():
    assert prefixes_of(DEFAULT) == () and prefixes_of(r"[A-Z]{3}\{\w+\}") == () and prefixes_of(r"\w+") == ()
    assert prefixes_of(r"^practice\{[a-z]+\}$") == ("practice",) and prefixes_of(r"\b(flag|ctf)\{.+\}") == ("flag", "ctf")
    assert prefixes_of(r"(?:flag|\w+)\{.+\}") == ()  # one alternative is not plain text: none is taken
    assert all(not c.startswith("fix:") for v in variants("FLAG{ABCDE}", DEFAULT) for c in v.changes)


def test_whitespace_is_stripped_and_spaces_become_underscores():
    got = variants(" flag{ two words } ", LOOSE)
    assert (got[0].value, got[0].changes) == ("flag{two words}", ("fix:strip", "fix:inner-space"))
    assert (got[1].value, got[1].changes, got[1].score) == ("flag{two_words}", ("fix:strip", "fix:inner-space", "spaces:underscores"), 0.6)
    assert got[1].what == "whitespace around it removed, whitespace inside the braces removed, spaces to underscores"
    # under a format with no spaces in the body, only the spellings without them are left
    assert values("flag{two words}", r"flag\{\w+\}") == ["flag{two_words}", "flag{7w0_w0rd5}"]
    # with no spaces in it, underscores to spaces is a weaker guess, and only where the format has spaces
    assert changes("flag{two_words}", r"flag\{[\w ]+\}")["flag{two words}"] == ("spaces:spaces",)
    assert "flag{two words}" not in values("flag{two_words}", DEFAULT)


def test_leet_goes_back_to_letters_and_letters_to_leet():
    assert [(v.value, v.changes, v.score) for v in variants("flag{h3ll0_w0rld}", DEFAULT)] == [("flag{hello_world}", ("leet:literal",), 0.3)]
    assert [(v.value, v.changes, v.score) for v in variants("flag{hello}", DEFAULT)] == [("flag{h3ll0}", ("leet:leet",), 0.25)]
    assert values("flag{H3LL0}", r"flag\{[A-Z0-9]+\}") == ["flag{HELLO}"]  # a token in capitals gets capitals back
    assert values("flag{key_2026}", r"flag\{[a-z_0-9]+\}") == ["flag{k3y_2026}"]  # a token of digits only is left alone


def test_accents_are_folded_to_ascii():
    got = variants("flag{café_olé_straße}", r"flag\{\w+\}")
    assert (got[0].value, got[0].changes, got[0].what) == ("flag{cafe_ole_strasse}", ("diacritics:ascii",), "accents removed")
    assert values("flag{café}", r"flag\{[a-z0-9]+\}") == ["flag{cafe}", "flag{c4f3}"]  # the accented spellings are outside this format


def test_nothing_applicable_gives_no_variants():
    assert variants("flag{12345}", DEFAULT) == ()
    assert variants("flag{}", DEFAULT) == () and variants("   ", DEFAULT) == () and variants("", DEFAULT) == ()
    assert variants("flag{ab\x00cd}", r"flag\{.+\}") == ()  # decoder noise
    assert variants("flag{" + "a" * MAX_VALUE + "}", r"flag\{.+\}") == ()  # longer than MAX_VALUE
    assert variants("flag{hello}", r"flag\{[a-z]+\}") == ()  # its one variant (leet) is outside the format


@pytest.mark.parametrize(
    ("value", "flag_format"),
    [
        (" FLAG{ENIGMA IS FUN} ", LOOSE),
        ("flag{flag{Señor_H3llo}}", r"(?:flag|ctf|htb|pico)\{.+\}"),
        ("CTF{ABCD_EFGH}", DEFAULT),
        ("plain words here", r"(?:flag|CTF)\{[\w ]+\}"),
        ("t{ABCD}", r"t\{\w+\}"),
    ],
)
def test_every_variant_matches_the_format_differs_from_the_value_and_is_listed_once(value, flag_format):
    got = variants(value, flag_format)
    assert got, "the case needs variants to say anything"
    assert all(re.fullmatch(flag_format, v.value) for v in got)
    assert value not in [v.value for v in got] and len({v.value for v in got}) == len(got) <= MAX_VARIANTS
    assert all(v.changes and v.what for v in got)
    scores = [v.score for v in got if not all(c.startswith("fix:") for c in v.changes)]
    assert scores == sorted(scores, reverse=True)  # ranked, after the safe fixes


def test_the_order_is_stable_and_a_shorter_list_is_its_start():
    value = " FLAG{ENIGMA IS FUN} "
    full = variants(value, LOOSE)
    assert len(full) == MAX_VARIANTS and full == variants(value, LOOSE)
    assert variants(value, LOOSE, max_variants=3) == full[:3] and variants(value, LOOSE, max_variants=0) == ()
    # equal scores: fewer changes first, then the order of the axes (case, diacritics, spaces, leet, wrap), then the value
    ties = variants("FLAG{ENIGMA_IS_FUN}", r"(?i)flag\{[\w ]+\}")
    assert [(v.value, v.score) for v in ties[3:7]] == [
        ("flag{ENIGMA IS FUN}", 0.25), ("flag{3N1GM4_15_FUN}", 0.25), ("flag{enigma is fun}", 0.125), ("flag{3n1gm4_15_fun}", 0.125),
    ]


def test_a_variant_combines_at_most_three_axes():
    got = variants("flag{ÉNIGMA IS FUN}", r"(?:flag|CTF)\{[^{}]+\}", case_lost=True)
    assert got and max(len(v.changes) for v in got) <= 3
    assert all(len({c.split(":")[0] for c in v.changes}) == len(v.changes) for v in got)  # one alternative per axis


def test_bad_arguments_fail_by_name():
    with pytest.raises(FlagVariantsError, match="must be a string, not bytes"):
        variants(b"flag{x}", DEFAULT)  # type: ignore[arg-type]
    for bad in (-1, MAX_VARIANTS + 1, True, 2.0):
        with pytest.raises(FlagVariantsError, match=f"max_variants must be a whole number from 0 to {MAX_VARIANTS}"):
            variants("flag{x}", DEFAULT, max_variants=bad)  # type: ignore[arg-type]
    with pytest.raises(FlagVariantsError, match="case_lost must be true or false"):
        variants("flag{x}", DEFAULT, case_lost="yes")  # type: ignore[arg-type]
    with pytest.raises(FlagFormatError, match="the flag format for flag variants does not compile"):
        variants("flag{x}", "flag\\{(")
    with pytest.raises(FlagVariantsError, match="is not a change a flag variant can have"):
        describe("case:sideways")
    with pytest.raises(FlagVariantsError, match="is not a change"):
        describe("fix:prefix:not a prefix")


def test_every_change_a_variant_can_have_reads_in_words():
    assert Variant("CTF{x}", ("fix:wrap:flag", "wrap:prefix:CTF", "wrap:plain"), 0.1).what == "wrapped as flag{...}, prefix CTF, wrapper removed"
    assert describe("case:upper") == "UPPER case" and describe("case:title") == "Title_Case per word"
    assert describe("spaces:spaces") == "underscores to spaces" and describe("leet:literal") == "leet to letters"
    assert describe("fix:strip") == "whitespace around it removed"


def test_the_wrapper_can_come_off_where_the_format_takes_a_bare_body():
    got = changes("flag{bare_words}", r"(?:flag\{)?[a-z_]+\}?")
    assert got["bare_words"] == ("wrap:plain",)
