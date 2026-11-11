"""The flag format: the regular expression an event's flags match, checked the same way
wherever flightdeck loads one.

A flag format comes from a board's board.json, an event profile's event.flag_format, the
command line (`flightdeck ctfd pull --flag-format`, `flightdeck l1 run --flag-format`) or
flightdeck's own default. A board or a profile may be one somebody else wrote (a shared
board, a teammate's profile), so the format is untrusted text: the console, pre-flight and
the run notes show it, and every lane reads it in its brief (inside the fence, as data,
never in a system prompt). So wherever it is loaded, and again in core.model.DeckConfig as
the backstop, it must be:

- one line: no line break of any kind (a newline, a carriage return, U+2028...), so it can
  never start a line of its own wherever it is shown;
- free of control, invisible and bidirectional characters: an escape sequence reaches a
  terminal, and a zero-width or bidi character makes a format read as another;
- at most MAX_LENGTH characters (200). A real flag format is a prefix and a bounded body,
  under 100 characters even with a few prefixes to choose from; 200 leaves room for that,
  keeps the whole format readable on one line wherever it is shown (a lane's brief cuts it
  at 500), and leaves little room for words riding along in it (a comment group, (?#...),
  holds any text);
- a Python regular expression that compiles.

An error (FlagFormatError, a ValueError) names where the format came from and the rule it
breaks, and shows the format only escaped (control and invisible characters made visible)
and cut short (SHOWN characters).
"""

from __future__ import annotations

import re
import unicodedata

from .text import untrusted

MAX_LENGTH = 200  # characters
SHOWN = 60  # characters of a bad format shown in an error
LINE_BREAKS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}")  # every character str.splitlines() splits at
_HIDDEN = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})  # controls, format characters (bidi, zero-width), surrogates, separators


class FlagFormatError(ValueError):
    """A flag format breaks a rule. The message names where it came from and the rule, and
    shows the format only escaped and cut short."""


def problem(value: object) -> str | None:
    """The rule `value` breaks, followed by the format as shown(); None when it is a flag
    format flightdeck can use. Callers put where it came from in front."""
    if not isinstance(value, str):
        return "must be a string (a regular expression)"
    if not value.strip():
        return "is empty; it must be a regular expression that the event's flags match"
    for position, char in enumerate(value):
        if char in LINE_BREAKS:
            return f"must be one line, but it has a line break ({_code(char)}) at position {position}: {shown(value)}"
    for position, char in enumerate(value):
        if _hidden(char):
            return (
                "must have no control, invisible or bidirectional character, but it has "
                f"{_code(char)} at position {position}: {shown(value)}"
            )
    if len(value) > MAX_LENGTH:
        return f"is {len(value):,} characters long; it must be at most {MAX_LENGTH}: {shown(value)}"
    try:
        re.compile(value)
    except re.error as exc:  # its message may quote part of the format
        where = f" at position {exc.pos}" if exc.pos is not None else ""
        return f"does not compile as a regular expression ({untrusted(exc.msg, one_line=True)}{where}): {shown(value)}"
    except (OverflowError, RecursionError, ValueError) as exc:  # a repeat count too large, say
        return f"does not compile as a regular expression ({untrusted(str(exc), one_line=True)}): {shown(value)}"
    return None


def check(value: object, source: str) -> str:
    """`value` when it is a flag format flightdeck can use; else FlagFormatError, its message
    `source` (where the format came from) followed by problem()."""
    broken = problem(value)
    if broken is not None:
        raise FlagFormatError(f"{source} {broken}")
    assert isinstance(value, str)
    return value


def shown(value: str) -> str:
    """`value` safe to print in an error: cut to SHOWN characters first (an escape is never cut
    in half), every control character in caret notation (a newline is ^J, a tab ^I), every
    invisible or bidirectional one as U+FFFD, in double quotes."""
    cut = value[:SHOWN]
    safe = untrusted(cut.replace("\t", "^I").replace("\n", "^J"))
    return f'"{safe}"' + ("..." if len(value) > SHOWN else "")


def _hidden(char: str) -> bool:
    """A control, invisible or bidirectional character: Unicode's controls, format characters
    (the bidi controls and zero-width characters among them) and surrogates, and whatever
    text.untrusted() would not draw as it is (the rest of Default_Ignorable_Code_Point)."""
    return unicodedata.category(char) in _HIDDEN or untrusted(char) != char


def _code(char: str) -> str:
    return f"U+{ord(char):04X}"
