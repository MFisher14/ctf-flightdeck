"""Untrusted text: anything that comes from a challenge, a lane, a tool or a model.

The console shows it as rich Text (never markup) and passes it through `untrusted()`
first. Control characters would otherwise reach the terminal as escape sequences
(and a terminal's answer to one comes back as key presses), and bidi, zero-width or
other invisible characters can make text read as something it is not. They become
visible markers.

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
    "\u061c"  # Arabic letter mark (bidi)
    "\u180e"  # Mongolian vowel separator
    "\u200b-\u200f"  # zero-width space and joiners, LRM, RLM
    "\u2028\u2029"  # line and paragraph separators
    "\u202a-\u202e"  # bidi embeddings and overrides
    "\u2060-\u2064"  # word joiner and invisible operators
    "\u2066-\u206f"  # bidi isolates and deprecated format characters
    "\ufeff"  # zero-width no-break space (BOM)
    "\ufff9-\ufffb"  # interlinear annotation
    "\U000e0000-\U000e007f"  # tag characters
    "]"
)
MARK = "\ufffd"  # the replacement character
NEWLINE = " \u23ce "  # how a folded newline shows


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
    return _UNSAFE.sub(_visible, text)
