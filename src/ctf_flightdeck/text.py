"""Untrusted text: anything that comes from a challenge, a lane, a tool or a model.

The console shows it as rich Text (never markup) and passes it through `untrusted()`
first. Control characters would otherwise reach the terminal as escape sequences
(and a terminal's answer to one comes back as key presses), and bidi, zero-width or
other invisible characters can make text read as something it is not (a flag that looks
like another). They become visible markers. The invisible set is Unicode's
Default_Ignorable_Code_Point property plus the line and paragraph separators and the
interlinear annotation characters.

This file is pure ASCII on purpose: every character class below is written as an
escape, never as the character itself.
"""

from __future__ import annotations

import re

_UNSAFE = re.compile(
    "["
    "\x00-\x08\x0b-\x1f"  # C0 controls, except tab (09) and newline (0a)
    "\x7f-\x9f"  # DEL and the C1 controls
    "\u00ad"  # soft hyphen
    "\u034f"  # combining grapheme joiner
    "\u061c"  # Arabic letter mark (bidi)
    "\u115f\u1160"  # Hangul choseong and jungseong fillers
    "\u17b4\u17b5"  # Khmer inherent vowels
    "\u180b-\u180f"  # Mongolian variation selectors and vowel separator
    "\u200b-\u200f"  # zero-width space and joiners, LRM, RLM
    "\u2028\u2029"  # line and paragraph separators
    "\u202a-\u202e"  # bidi embeddings and overrides
    "\u2060-\u206f"  # word joiner, invisible operators, bidi isolates, deprecated format
    "\u3164"  # Hangul filler
    "\ufe00-\ufe0f"  # variation selectors 1-16
    "\ufeff"  # zero-width no-break space (BOM)
    "\uffa0"  # halfwidth Hangul filler
    "\ufff0-\ufffb"  # unassigned specials, interlinear annotation
    "\U0001bca0-\U0001bca3"  # shorthand format controls
    "\U0001d173-\U0001d17a"  # musical symbol format controls
    "\U000e0000-\U000e0fff"  # tags, variation selectors 17-256, the rest of that block
    "]"
)
MARK = "\ufffd"  # the replacement character
NEWLINE = " \u23ce "  # how a folded newline shows
_SURROGATE = re.compile("[\ud800-\udfff]")


def _escaped(match: re.Match[str]) -> str:
    """A lone surrogate: a byte that was not UTF-8 (a Linux file name, PEP 383) shows as \\xNN,
    any other as \\uNNNN. Printed as it is, one would crash a strict UTF-8 terminal or reach a
    lenient one as a raw byte (0x9b starts a control sequence)."""
    code = ord(match.group())
    if 0xDC80 <= code <= 0xDCFF:
        return f"\\x{code - 0xDC00:02x}"
    return f"\\u{code:04x}"


def _visible(match: re.Match[str]) -> str:
    code = ord(match.group())
    if code < 0x20:
        return "^" + chr(code + 0x40)  # caret notation: ESC shows as ^[
    if code == 0x7F:
        return "^?"
    return MARK


def untrusted(text: str, *, one_line: bool = False) -> str:
    """`text` made safe to draw. one_line=True also folds newlines and tabs."""
    if one_line:
        text = text.replace("\r\n", "\n").replace("\n", NEWLINE).replace("\t", " ")
    return _UNSAFE.sub(_visible, _SURROGATE.sub(_escaped, text))
