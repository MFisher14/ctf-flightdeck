"""Which challenges of a board are one series: a lab the board split into several tasks.

Boards often split one lab into several challenges that share a target: "Harbor Lab 1: Read the
Certificate", then "Harbor Lab 1: Fingerprint the Certificate", whose text says only
"continuation of the same lab, see the first task". Nothing on the board links them but the
name. This module reads the link from the names, and nothing else: no file is opened here and
nothing is run (agent/sharing.py hands a lane what a sibling's lane left).

The series key (series_key, split_name). Two challenges are siblings when their names have the
same key. The key is the start of the name, lower-cased, every run of other characters than
letters and digits folded to one space:

- the part before the first separator: a colon followed by a space ("Lab 1: Read it"), a
  hyphen or a bar with a space on both sides ("Lab - Part 2", "Lab | Logbook"), or an en or em
  dash, spaced or not ("Lab — The Gate");
- else, with no separator, the part before a trailing part number: "Lab Part 3", "Lab Task 2",
  "Lab (Stage 2)", "Lab pt. 2", or a fraction in brackets, "Lab (2/3)".

A key links nothing, and is None, when it is not a series' name: fewer than MIN_KEY letters and
digits ("AB: tiny"), only a category or a generic word (GENERIC_KEYS: "Web: SQL Login",
"Warmup: Hello"), or only a part number itself ("Task 2 - Read it", "Part 1: The start"). A
name with neither a separator nor a part number has no key.

The continuation wording (continuation_marker). Text such as "continuation of the same lab" or
"see the first task", read with the description's HTML tags and markdown marks removed and in
lower case, marks a challenge that needs a sibling. When it is there and no sibling is on the
board, whoever tells a lane about its series says so by name, never silently.

Names and descriptions come from the board: untrusted. They are only matched here, each cut
first (MAX_NAME, MAX_DESCRIPTION), so a long one cannot make a match slow; what a match gives
back is still the board's text, and whoever shows it treats it as data.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .model import Challenge

MAX_NAME = 300  # characters of a name read for its key
MAX_DESCRIPTION = 20_000  # characters of a description read for the continuation wording
MIN_KEY = 3  # letters and digits a key has at least

_SEPARATOR = re.compile(r"\s*:\s+|\s+[-|]\s+|\s*[–—]\s*")
_PART_WORDS = "part|pt\\.?|task|stage|step|chapter|level|episode"
_TRAILING_PART = re.compile(
    rf"^(.*?\S)[\s\-_]*[(\[]?\s*(?:{_PART_WORDS})\s*#?\s*\d+\s*(?:/\s*\d+)?\s*[)\]]?\s*$", re.IGNORECASE
)
_TRAILING_FRACTION = re.compile(r"^(.*?\S)\s*[(\[]\s*\d+\s*/\s*\d+\s*[)\]]\s*$")
_ONLY_A_PART = re.compile(r"^(?:part|pt|task|stage|step|chapter|level|episode|day|round) ?\d+$")
_TAG = re.compile(r"<[^>]{0,400}>")
_MARKS = re.compile(r"[*_`#>]+")

GENERIC_KEYS = frozenset({
    "web", "crypto", "cryptography", "pwn", "binary", "rev", "reverse", "reversing", "forensics", "forensic", "misc",
    "miscellaneous", "osint", "stego", "steganography", "hardware", "network", "networking", "mobile", "blockchain",
    "ai", "ml", "warmup", "warmups", "warm up", "beginner", "intro", "introduction", "easy", "medium", "hard",
    "insane", "bonus", "sanity", "sanity check", "challenge", "task", "part", "lab", "the", "a",
})
"""A key that is only one of these is a category or a label, not a series."""

CONTINUATION = (
    r"continuation of (?:the )?(?:same |previous |earlier |first )?(?:lab|series|scenario|challenge|task|case)",
    r"continu(?:es|ing) (?:from |on from )?(?:the )?(?:same |previous |earlier |first )(?:lab|task|challenge|part)",
    r"see the (?:first|previous|earlier|original) (?:task|challenge|part)",
    r"\bsame lab\b",
    r"follow[- ]up (?:to|of|on) (?:the )?(?:first|previous|earlier)",
    r"(?:builds|carries) on (?:from )?(?:the )?(?:first|previous|earlier) (?:task|challenge|part)",
)
"""Wording that marks a challenge as the continuation of an earlier one: matched on the
description as plain_text() gives it."""
_CONTINUATION = re.compile("|".join(f"(?:{pattern})" for pattern in CONTINUATION))


def split_name(name: str) -> tuple[str | None, str]:
    """(the series key, the rest of the name) of a challenge's name; (None, the name) when it
    has no key (see the module doc)."""
    if not isinstance(name, str):
        raise TypeError(f"a challenge's name is text, got {type(name).__name__}")
    whole = name.strip()[:MAX_NAME]
    head: str | None = None
    rest = whole
    parts = _SEPARATOR.split(whole, maxsplit=1)
    if len(parts) == 2 and parts[0].strip() and parts[1].strip():
        head, rest = parts
    else:
        match = _TRAILING_PART.match(whole) or _TRAILING_FRACTION.match(whole)
        if match is not None:
            head, rest = match.group(1), whole[len(match.group(1)):]
    if head is None:
        return None, whole
    key = re.sub(r"[^a-z0-9]+", " ", head.lower()).strip()
    if len(key.replace(" ", "")) < MIN_KEY or key in GENERIC_KEYS or _ONLY_A_PART.match(key):
        return None, whole
    return key, rest.strip()


def series_key(name: str) -> str | None:
    """The series key of a challenge's name, or None when the name links it to no other."""
    return split_name(name)[0]


def plain_text(text: str) -> str:
    """A description (its first MAX_DESCRIPTION characters) without HTML tags and markdown
    marks, its whitespace folded, in lower case."""
    bare = _MARKS.sub(" ", _TAG.sub(" ", text[:MAX_DESCRIPTION]))
    return re.sub(r"\s+", " ", bare).strip().lower()


def continuation_marker(description: str) -> str | None:
    """The continuation wording in a description, as it reads in plain_text() ("see the first
    task"), or None when there is none."""
    match = _CONTINUATION.search(plain_text(description))
    return match.group(0) if match is not None else None


def siblings(challenges: Iterable[Challenge], challenge: Challenge) -> list[Challenge]:
    """The other challenges among `challenges` in `challenge`'s series (the same key), in the
    order given; none when its name has no key."""
    key = series_key(challenge.name)
    if key is None:
        return []
    return [other for other in challenges if other.id != challenge.id and series_key(other.name) == key]
