"""Untrusted text made safe to draw, and the compact number and time formats."""

from __future__ import annotations

import pytest

from ctf_flightdeck import fmt
from ctf_flightdeck.text import MARK, untrusted

# Bidi controls, zero-width and other invisible characters that untrusted() turns into MARK:
# Unicode's Default_Ignorable_Code_Point set (DerivedCoreProperties.txt), the line and
# paragraph separators, and the interlinear annotation characters.
INVISIBLE = [
    0x00AD,  # soft hyphen
    0x034F,  # combining grapheme joiner
    0x115F, 0x1160, 0x3164, 0xFFA0,  # Hangul fillers: blank-looking letters
    0x17B4, 0x17B5,  # Khmer inherent vowels
    *range(0x180B, 0x1810),  # Mongolian free variation selectors, vowel separator
    *range(0x200B, 0x2010),  # zero-width space, ZWNJ, ZWJ, LRM, RLM
    0x2028,  # line separator
    0x2029,  # paragraph separator
    *range(0x202A, 0x202F),  # LRE, RLE, PDF, LRO, RLO
    *range(0x2060, 0x2065),  # word joiner, invisible operators
    0x2065,  # unassigned, default-ignorable
    *range(0x2066, 0x206A),  # LRI, RLI, FSI, PDI
    *range(0x206A, 0x2070),  # deprecated format characters
    *range(0xFE00, 0xFE10),  # variation selectors 1-16
    0xFEFF,  # byte order mark / zero-width no-break space
    *range(0xFFF0, 0xFFF9),  # unassigned specials, default-ignorable
    *range(0xFFF9, 0xFFFC),  # interlinear annotation anchor, separator, terminator
    *range(0x1BCA0, 0x1BCA4),  # shorthand format controls
    *range(0x1D173, 0x1D17B),  # musical symbol format controls
    0xE0001, *range(0xE0020, 0xE0080),  # language tag and tag characters
    0xE0000, 0xE0002, 0xE0080, 0xE00FF,  # unassigned in the tag block, default-ignorable
    *range(0xE0100, 0xE01F0),  # variation selectors 17-256
    0xE01F0, 0xE0FFF,  # unassigned, default-ignorable, to the end of that block
]
# Printable neighbours of those ranges, which must come through unchanged.
NEIGHBOURS = [
    0x00A0, 0x00AC, 0x00AE, 0x034E, 0x0350, 0x115E, 0x1161, 0x17B3, 0x17B6, 0x180A, 0x1810,
    0x200A, 0x2010, 0x2027, 0x202F, 0x205F, 0x2070, 0x2800, 0x3163, 0x3165, 0xFDFC, 0xFE10,
    0xFEFC, 0xFF01, 0xFF9F, 0xFFA1, 0xFFFC, 0x1BC9F, 0x1D172, 0x1D17B,
]


def test_escape_shows_as_caret_bracket():
    assert untrusted("\x1b[31mred\x1b[0m") == "^[[31mred^[[0m"


def test_c0_controls_use_caret_notation_except_tab_and_newline():
    for code in range(0x20):
        ch = chr(code)
        expected = ch if ch in "\t\n" else "^" + chr(code + 0x40)
        assert untrusted(f"a{ch}b") == f"a{expected}b", hex(code)
    assert untrusted("\x00\x07\r") == "^@^G^M"


def test_del_shows_as_caret_question_mark():
    assert untrusted("a\x7fb") == "a^?b"


def test_c1_controls_become_the_replacement_mark():
    assert MARK == "�"
    for code in range(0x80, 0xA0):
        assert untrusted(f"a{chr(code)}b") == f"a{MARK}b", hex(code)


def test_bidi_zero_width_and_bom_characters_become_the_replacement_mark():
    for code in INVISIBLE:
        assert untrusted(f"a{chr(code)}b") == f"a{MARK}b", f"U+{code:04X}"


def test_printable_neighbours_of_the_marked_ranges_are_kept():
    for code in NEIGHBOURS:
        assert untrusted(chr(code)) == chr(code), f"U+{code:04X}"


def test_the_arabic_letter_mark_is_marked_like_the_other_bidi_controls():
    # U+061C is one of Unicode's Bidi_Control characters (PropList.txt), with LRM and RLM
    assert untrusted("a\u061cb") == f"a{MARK}b"


def test_tab_and_newline_are_kept_unless_one_line():
    assert untrusted("a\tb\nc") == "a\tb\nc"
    assert untrusted("a\tb\nc", one_line=True) == "a b ⏎ c"


def test_one_line_folds_each_line_break_into_one_marker():
    assert untrusted("one\r\ntwo\nthree", one_line=True) == "one ⏎ two ⏎ three"
    assert untrusted("a\rb", one_line=True) == "a^Mb"  # a lone CR is a control, not a line break
    assert untrusted("\x1b\n", one_line=True) == "^[ ⏎ "


def test_ordinary_text_is_unchanged():
    text = "Évian 日本語 — t{ok} 🙂 ~!@#$%^&*()"
    assert untrusted(text) == text
    assert untrusted(text, one_line=True) == text


@pytest.mark.parametrize(
    "n, text",
    [
        (0, "0"),
        (999, "999"),
        (1000, "1k"),
        (210_600, "211k"),
        (999_499, "999k"),
        (999_500, "1.0M"),  # rounds before choosing the unit: never "1000k"
        (1_234_567, "1.2M"),
        (2_449_999, "2.4M"),
        (2_450_001, "2.5M"),
    ],
)
def test_tokens(n, text):
    assert fmt.tokens(n) == text


@pytest.mark.parametrize(
    "x, short, text",
    [
        (None, False, "-"),
        (None, True, "-"),
        (0.21, True, ".21"),
        (0.21, False, "0.21"),
        (3.18, True, "3.18"),
        (3.18, False, "3.18"),
        (99.994, False, "99.99"),
        (99.996, False, "100"),  # rounds to 100.00, so it is shown as a whole number
        (100, False, "100"),
        (250.4, True, "250"),
    ],
)
def test_dollars(x, short, text):
    assert fmt.dollars(x, short=short) == text


@pytest.mark.parametrize(
    "seconds, text",
    [(0, "0s"), (59.9, "59s"), (60, "1m"), (3599, "59m"), (3600, "1h00"), (3660, "1h01"), (7500, "2h05")],
)
def test_duration(seconds, text):
    assert fmt.duration(seconds) == text


@pytest.mark.parametrize(
    "seconds, text",
    [
        (0, "T+00:00:00"),
        (59.9, "T+00:00:59"),
        (60, "T+00:01:00"),
        (3599, "T+00:59:59"),
        (3600, "T+01:00:00"),
        (6130, "T+01:42:10"),
        (36_000, "T+10:00:00"),
    ],
)
def test_clock(seconds, text):
    assert fmt.clock(seconds) == text


def test_a_lone_surrogate_shows_as_an_escape_and_never_reaches_the_terminal_raw():
    from ctf_flightdeck.text import untrusted

    not_utf8 = b"report\x9b2J.txt".decode("utf-8", "surrogateescape")  # a Linux file name that is not UTF-8
    shown = untrusted(not_utf8)
    assert shown == "report\\x9b2J.txt"
    assert untrusted("a\ud800b") == "a\\ud800b"
    shown.encode("utf-8")  # strict UTF-8: no lone surrogate is left
