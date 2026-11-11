"""Credential-shaped text, with its value taken out: the second layer of redaction.

flightdeck keeps secrets out of what it records at the source: a lane's commands get an
environment built from an allowlist, and a coding-agent lane's output has every secret
flightdeck holds replaced by [NAME] (agent/external.py). What a lane records can still hold
a credential that layer did not know: a host lane that read the player's keys file or
another process's environment, or a run folder written before those fixes. So what
flightdeck keeps of a run and what it shows also has the value of anything shaped like a
credential taken out: the run log (eventlog.py), lane transcripts (transcript.py), the steps
a post-flight report quotes (postflight.py), writeup drafts (writeup.py, with or without
writeup --redact) and what the console shows of a lane (console/views.py):

- NAME=value and NAME: value, where NAME is an upper-case variable name (letters, digits and
  _) that holds KEY, TOKEN, SECRET, PASSWORD, PASSWD, COOKIE or AUTH, as the environment, a
  keys file or a config writes one (ANTHROPIC_API_KEY=..., CTFD_TOKEN: ...), and a
  Makefile's :=, ::=, ?= and += too. Lower-case names are left alone on purpose: key,
  password and token are everyday CTF content (an XOR key, a password the lane found, a JWT
  it forged);
- the value of an Authorization, Proxy-Authorization or Cookie header, in any case (HTTP
  header names are), to the end of the line or the closing quote. An Authorization scheme
  (Bearer, Basic, Token...) stays in front of it. A token a lane forged and sent in one of
  these headers goes too, since nothing tells it from the player's own; where the lane made
  or printed it, it stays. A response's Set-Cookie is what the challenge's server sent, and
  stays;
- a key with a well-known prefix, wherever it is: sk-ant-, sk-or-, sk-proj-, ghp_,
  github_pat_, xoxb- and xoxp- (with 8 or more letters, digits, _ or - after it), ctfd_ and 16
  or more hex digits (a CTFd token), and AKIA and 16 upper-case letters or digits (an AWS
  access key id).

The name stays and the value becomes [redacted]; a prefixed key keeps its prefix
(sk-ant-[redacted]). A value taken out already ([redacted], or the first layer's [NAME])
stays as it is. Flags are not credentials: a match whose value lies inside one of the
strings given as `keep` (the flags the run knows: named_flags) is left as it is, and hiding
flags stays writeup --redact's job. Ordinary CTF content passes: a JWT, a hex dump or base64
has no such name in front of it and no such prefix. Every pattern runs in time linear in the
text.

This cleans only what flightdeck keeps and shows. The deck keeps a lane's text as it was, for
the lane's model, which has read it already; and a key a host lane read went to its model's
API with the rest of the lane's context, which nothing done afterwards can take back.
"""

from __future__ import annotations

import bisect
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence

from .text import NEWLINE

REDACTED = "[redacted]"
WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "COOKIE", "AUTH")
PREFIXES = ("sk-ant-", "sk-or-", "sk-proj-", "ghp_", "github_pat_", "xoxb-", "xoxp-")
SCHEMES = ("Basic", "Bearer", "Digest", "DPoP", "Negotiate", "NTLM", "Token")  # Authorization schemes, kept in front

_FOLD = re.escape(NEWLINE.strip())  # where a one-line action folded a newline (agent/tools.py, text.untrusted)
# A run of spaces or tabs is taken whole (possessive: *+ and ++) and never given back. Given
# back one blank at a time, each blank started the value again, which scanned the rest of the
# line once more: time quadratic in a run of blanks with no value after it ("Cookie:" and
# 60,000 spaces took half a minute). What matches is the same: a value needs something other
# than a blank before the line (or the quote) ends, and blanks given back add nothing of that.
_HEADER = re.compile(
    r"(?<![\w-])(?P<name>proxy-authorization|authorization|cookie)(?P<sep>[\"']?[ \t]*+:[ \t]*+[\"']?)"
    rf"(?P<scheme>(?:{'|'.join(SCHEMES)})[ \t]++)?"
    rf"(?P<value>[^\r\n\"'{_FOLD}]*[^\s\"'{_FOLD}])",
    re.IGNORECASE,
)
_ASSIGNED = re.compile(
    rf"(?<![A-Za-z0-9_])(?P<name>[A-Z0-9_]{{0,64}}(?:{'|'.join(WORDS)})[A-Z0-9_]{{0,64}})"
    # =, or a Makefile's :=, ::=, ?= or +=, but never == or !=; or a colon, but never :: or :=
    r"(?P<sep>[\"']?[ \t]*+(?:(?:::?|[?+])?=(?!=)|:(?![:=]))[ \t]*+)"
    # a quoted value cut short has no closing quote; an unquoted one never ends with the
    # punctuation of the sentence around it ("...was TOKEN=abc.", "submitted t{TOKEN=x}: correct")
    r"(?P<value>\"[^\"\r\n]*\"?|\$?'[^'\r\n]*'?|[^\s\"'`;&|<>(),]*[^\s\"'`;&|<>(),:.!?])"
)
_PREFIXED = re.compile(
    rf"(?<![A-Za-z0-9])(?P<name>{'|'.join(map(re.escape, PREFIXES))})(?P<value>[A-Za-z0-9_-]{{8,}})"
)
_CTFD = re.compile(r"(?<![A-Za-z0-9])(?P<name>ctfd_)(?P<value>[0-9a-fA-F]{16,})(?![A-Za-z0-9])")
_AWS = re.compile(r"(?<![A-Za-z0-9])(?P<name>AKIA)(?P<value>[A-Z0-9]{16})(?![A-Za-z0-9])")
_LABEL = re.compile(r"\[(?:redacted|[A-Z_][A-Z0-9_]{0,127})\]")  # a value taken out already


def redact(text: str, *, keep: Iterable[str] = ()) -> str:
    """`text` with the value of everything in it shaped like a credential replaced by
    [redacted] (see the module docstring), but where that value lies inside one of the
    strings in `keep` (the flags the run knows)."""
    return _redact(text, _kept(keep))


def redact_data(value: object, *, keep: Iterable[str] = ()) -> object:
    """Plain JSON data, as eventlog.json_safe makes it (strings, numbers, booleans, None,
    lists and dicts with string keys), with every string in it redacted as redact() does;
    the keys stay as they are."""
    return _data(value, _kept(keep))


NAMES = frozenset({"board", "challenges", "challenge", "solved"})
"""The fields of a deck event's data that name challenges rather than tell what happened: a
release's challenge ids and its board (each one's id, name, category and points), the
challenge a claim or a queue names, and the challenges an older log's warning says the
platform lists as solved. They come from the board, never from what a lane did; the report
and practice scoring match on them; and an id or a name can look like a credential
(xoxb-slack-bot, "Fortune Cookie: Part 2"). So redact_event_data leaves them as they are."""


def redact_event_data(data: object, *, keep: Iterable[str] = ()) -> object:
    """A deck event's data (plain JSON, as eventlog.json_safe makes it), redacted as
    redact_data() does, but the fields in NAMES stay as they are."""
    kept = _kept(keep)
    if not isinstance(data, Mapping):
        return _data(data, kept)
    return {key: item if key in NAMES else _data(item, kept) for key, item in data.items()}


def named_flags(data: Mapping[str, object]) -> list[str]:
    """The flags a deck event's data names: its "flag" (a lane's candidate, waiting for the
    player or submitted) and its "flags" (what an L1 engine reported). These are the flags
    the run knows, what `keep` holds for the text of a run."""
    found: list[str] = []
    if not isinstance(data, Mapping):
        return found
    flag, flags = data.get("flag"), data.get("flags")
    if isinstance(flag, str) and flag:
        found.append(flag)
    if isinstance(flags, (list, tuple)):
        found += [item for item in flags if isinstance(item, str) and item]
    return found


def _kept(keep: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item for item in keep if item))


def _data(value: object, kept: tuple[str, ...]) -> object:
    if isinstance(value, str):
        return _redact(value, kept)
    if isinstance(value, dict):
        return {key: _data(item, kept) for key, item in value.items()}
    if isinstance(value, list):
        return [_data(item, kept) for item in value]
    return value


def _redact(text: str, kept: tuple[str, ...]) -> str:
    for pattern, replace in _RULES:
        if not pattern.search(text):  # most text holds no credential at all
            continue
        spans = _spans(text, kept)
        text = pattern.sub(lambda match: match.group(0) if _covered(_inner(match), spans) else replace(match), text)
    return text


def _header(match: re.Match[str]) -> str:
    value = match.group("value")
    if _LABEL.fullmatch(value):
        return match.group(0)
    scheme = match.group("scheme") or ""
    if match.group("name").lower() == "cookie":
        scheme = ""  # a cookie has no scheme: a word that looked like one is part of its value
    return match.group("name") + match.group("sep") + scheme + REDACTED


def _assigned(match: re.Match[str]) -> str:
    value = match.group("value").removeprefix("$")
    inner = value.strip("\"'")
    if not inner or _LABEL.fullmatch(inner):  # nothing there, or taken out already
        return match.group(0)
    quote = value[0] if value[0] in "\"'" else ""
    return match.group("name") + match.group("sep") + quote + REDACTED + quote


def _prefixed(match: re.Match[str]) -> str:
    return match.group("name") + REDACTED


_RULES: tuple[tuple[re.Pattern[str], Callable[[re.Match[str]], str]], ...] = (
    (_HEADER, _header),
    (_ASSIGNED, _assigned),
    (_PREFIXED, _prefixed),
    (_CTFD, _prefixed),
    (_AWS, _prefixed),
)


def _spans(text: str, kept: Sequence[str]) -> list[tuple[int, int]]:
    """Where `text` holds a string of `kept`, as (start, end), in order, overlaps merged."""
    found: list[tuple[int, int]] = []
    for item in kept:
        at = text.find(item)
        while at >= 0:
            found.append((at, at + len(item)))
            at = text.find(item, at + 1)
    merged: list[tuple[int, int]] = []
    for start, end in sorted(found):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _inner(match: re.Match[str]) -> tuple[int, int]:
    """Where a match's value is, without the quotes (or $'...') around it."""
    start, end = match.span("value")
    value = match.group("value")
    lead = len(value) - len(value.lstrip("$\"'"))
    trail = len(value) - len(value.rstrip("\"'"))
    return start + lead, max(start + lead, end - trail)


def _covered(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    """Whether `span` lies inside one of `spans` (merged, in order)."""
    start, end = span
    at = bisect.bisect_right(spans, (start, math.inf)) - 1
    return at >= 0 and spans[at][1] >= end
