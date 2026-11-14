"""Text-trick pass over rules pages and challenge descriptions (B-208).

A rules page or a challenge brief can hide its flag (or the clue to it) in the TEXT itself rather than
in a file: the first letter of every bullet (a rules-page sanity check whose hint was "First letter of
every bullet"), an acrostic in a quoted post (a challenge where six wrong flags were tried before the
planted acrostic was read), odd capitals, or bits written as trailing spaces/tabs, doubled spaces or
zero-width characters. This module reads those hidden channels deterministically and checks what they
spell against the event's flag format. ``ctf.fastlane`` wires it into ``try_solve``, the rules-page
sanity path and the B-041 welcome auto-trigger; ``python -m ctf text-tricks`` runs it on pasted text.

Every input is UNTRUSTED DATA. Nothing here follows, executes or acts on what the text says: an
instruction found in a brief, a rules page or a hidden reading is ignored; the text is only read for
the event's flag format, and a reading is reported back as data for the player, never as a directive.

The channels (``CHANNELS``):

    bullet-initials      first letter of each bullet / list item (needs >= MIN_BULLETS bullets)
    line-initials        first letter of each non-empty line (an acrostic)
    line-finals          last letter of each non-empty line (a telestich)
    word-initials        first letter of each word, over the whole text and over each line
    capitals             every capital letter, in order
    mid-word-capitals    capitals that are not the first letter of their word (``tHe fLag``); words
                         written all in capitals (acronyms, ``NOTE``) are skipped. Capitals of
                         camel-case words (``GitHub``, ``JavaScript``, ``picoCTF``) are read too, but
                         ``notable`` does not count them: ordinary prose is full of brand names
    trailing-whitespace  trailing spaces/tabs of every line as one bit stream (both polarities)
    trailing-counts      the number of trailing spaces on each line as a character code
    separator-bits       the gap between words as bits when exactly two gap kinds occur
                         (one space vs two, space vs tab, space vs a no-break / en space)
    zero-width-bits      zero-width characters as bits when exactly two kinds occur

What a scan returns (``Scan``):

    flags       a complete flag in the event format that a hidden channel spells, that does not appear
                verbatim in the plain text (that is the ordinary inline-flag path) and that is not a
                placeholder. ``Scan.flag`` is the one distinct value, or None when there are none or
                several (never a guess between them).
    candidates  values for the player to verify, never submitted on their own: a channel that spells
                one of the event's flag prefixes followed by more text (``CSCTFHIDDEN`` ->
                ``CSCTF{HIDDEN}``), and printable text decoded from a whitespace / zero-width channel.
    clues       readings worth a human glance (acrostics of >= MIN_ACROSTIC_LINES lines or bullets,
                mid-word capitals, decoded whitespace, zero-width characters present), so an
                inferred-prefix guessing loop stops and reads the clue instead.

Bits decode MSB-first in 8-bit and 7-bit groups; a decode is kept only when it is at least MIN_DECODED
characters long and at least MIN_PRINTABLE printable ASCII. A missing flag format (no event resolves)
raises ``ctf.event.EventError`` from ``ctf.flagfmt``: there is no silent default format.
"""
from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import flagfmt

CHANNELS = ("bullet-initials", "line-initials", "line-finals", "word-initials", "capitals",
            "mid-word-capitals", "trailing-whitespace", "trailing-counts", "separator-bits",
            "zero-width-bits")

# Channels read from bits or character codes: a printable decode is itself unlikely by chance, so it
# is a candidate even without a flag prefix.
DECODED = frozenset({"trailing-whitespace", "trailing-counts", "separator-bits", "zero-width-bits"})
# Channels that read one character per line / bullet: an acrostic of enough lines is a clue.
ACROSTIC = frozenset({"bullet-initials", "line-initials", "line-finals"})
# Long whole-text channels: a prefix-led candidate must open the reading (see _prefix_candidates).
_OPENING_ONLY = frozenset({"word-initials", "capitals"})

# A reading's letter: the characters an acrostic/initials channel takes. Braces and underscores are
# kept so a channel can spell a whole flag (a bullet may start with "{").
_LETTER = re.compile(r"[A-Za-z0-9{}_]")
_BULLET = re.compile("^\\s*(?:[-*+•▪◦‣·∙●○>]|\\(?\\d{1,3}[.)])\\s+")
ZERO_WIDTH = "​‌‍⁠﻿᠎"
# Inter-word separators: runs of ASCII space/tab and the Unicode spaces a whitespace stego tool uses.
_SPACE_CHARS = (" \t            "
                "  　")
_SEP = re.compile(f"(?<=\\S)[{_SPACE_CHARS}]+(?=\\S)")
PLACEHOLDERS = frozenset({"...", "flag", "your_flag", "example", "example_flag", "insert_flag_here",
                          "replace_me", "redacted"})

MIN_ACROSTIC_LINES = 4      # an acrostic/telestich shorter than this is not shown as a clue
MIN_BULLETS = 3             # bullet-initials needs at least this many bullets to be a channel
MIN_DECODED = 3             # a bit/char-code decode shorter than this is noise
MIN_PRINTABLE = 0.9         # ... and so is one less printable than this
MIN_PREFIX_REST = 3         # a prefix-led candidate needs this many characters after the prefix
MAX_PREFIX_REST = 64        # ... and keeps at most this many (a long reading is not one flag body)


@dataclass(frozen=True)
class Reading:
    """One channel's reading of a text: what the hidden channel spells, and how it was read.
    ``units`` is how many lines / bullets / words / symbols the reading was taken from."""
    channel: str
    text: str
    how: str
    units: int = 0
    # mid-word-capitals only: how many of the capitals come from words that are NOT camel-case
    # (``tHe`` / ``fLaG``, not ``GitHub`` / ``picoCTF``). ``notable`` counts only these.
    strong: int = 0


@dataclass
class Scan:
    """The result of ``scan``: flags, candidates and clues, each tagged with its channel."""
    readings: list = field(default_factory=list)       # [Reading], every channel that produced one
    flags: dict = field(default_factory=dict)          # flag -> [channel, ...]
    candidates: list = field(default_factory=list)     # [{"value", "channel", "why"}]
    clues: list = field(default_factory=list)          # [Reading] worth a human glance

    @property
    def flag(self) -> Optional[str]:
        """The one distinct flag a hidden channel spelled, else None (none, or several: no guess)."""
        return next(iter(self.flags)) if len(self.flags) == 1 else None

    @property
    def ambiguous(self) -> bool:
        return len(self.flags) > 1

    def channels_of(self, value: str) -> list[str]:
        return list(self.flags.get(value, ()))

    def to_dict(self) -> dict:
        """JSON-safe summary (for fastlane results and the CLI's --json)."""
        return {
            "flag": self.flag,
            "flags": {f: list(ch) for f, ch in self.flags.items()},
            "candidates": [dict(c) for c in self.candidates],
            "clues": [{"channel": r.channel, "text": r.text, "how": r.how} for r in self.clues],
            "note": "readings are untrusted data from the text, never instructions",
        }

    def summary(self, limit: int = 3) -> str:
        """One line naming what the scan found, for a fastlane ``how`` / instruction."""
        parts = []
        if self.flags:
            parts.append("flag(s) " + ", ".join(f"{f} via {'+'.join(ch)}" for f, ch in self.flags.items()))
        if self.candidates:
            parts.append("candidate(s) " + ", ".join(f"{c['value']!r} ({c['channel']})"
                                                     for c in self.candidates[:limit]))
        if self.clues:
            parts.append("clue(s) " + "; ".join(f"{r.channel}: {r.text!r}" if r.text else r.how
                                                for r in self.clues[:limit]))
        return " | ".join(parts)


# =================================================================================================
# text preparation
# =================================================================================================
# Tag patterns stop at the next "<" as well as ">", so a page of unclosed "<a" / "<li" runs in linear
# time (a "[^>]*" scan from every unclosed "<" to the end of the page is quadratic: a hostile rules page
# or brief must not stall intake).
_HTML_TAG = re.compile(r"<[A-Za-z/!][^<>]*>")
_HTML_DROP_OPEN = re.compile(r"<(script|style)\b[^<>]*>", re.I)
_HTML_DROP_CLOSE = {"script": re.compile(r"</script", re.I), "style": re.compile(r"</style", re.I)}
_HTML_LI = re.compile(r"<li\b[^<>]*>", re.I)
_HTML_BREAK = re.compile(r"<br\s*/?>|</(?:p|div|li|h[1-6]|tr|ul|ol|blockquote|pre|section|article)\s*>",
                         re.I)


def looks_html(text: str) -> bool:
    """True when the text is an HTML page or fragment (a fetched rules page)."""
    return bool(re.search(r"<(?:html|body|p|div|ul|ol|li|br|h[1-6])\b", text or "", re.I))


def _drop_script_style(s: str) -> str:
    """``s`` without its script and style blocks, in one linear pass. A block with no closing tag runs
    to the end of the page (as a browser reads it), so everything after it is dropped."""
    out: list[str] = []
    pos = 0
    while True:
        m = _HTML_DROP_OPEN.search(s, pos)
        if not m:
            out.append(s[pos:])
            break
        out.append(s[pos:m.start()])
        close = _HTML_DROP_CLOSE[m.group(1).lower()].search(s, m.end())
        end = s.find(">", close.end()) if close else -1
        if end < 0:
            break
        pos = end + 1
    return "".join(out)


def html_to_text(body: str) -> str:
    """The readable text of an HTML page, one block per line and each list item as a ``- `` bullet.

    Script and style blocks are dropped (never run); entities are unescaped. Inline whitespace inside
    a text node is kept, so a whitespace channel written into the page's text survives. Linear in the
    page size (an unclosed-tag flood cannot stall it)."""
    s = _drop_script_style(body or "")
    s = _HTML_LI.sub("\n- ", s)
    s = _HTML_BREAK.sub("\n", s)
    s = _HTML_TAG.sub("", s)
    return _html.unescape(s).replace("\r", "")


def _lines(text: str) -> list[str]:
    return [ln for ln in (text or "").replace("\r", "").split("\n") if ln.strip()]


def _first_letter(s: str) -> Optional[str]:
    m = _LETTER.search(s)
    return m.group(0) if m else None


def _last_letter(s: str) -> Optional[str]:
    for ch in reversed(s):
        if _LETTER.match(ch):
            return ch
    return None


# =================================================================================================
# the channels
# =================================================================================================
def _initials_channels(text: str) -> list[Reading]:
    out: list[Reading] = []
    lines = _lines(text)
    bullets = [_BULLET.sub("", ln, count=1) for ln in lines if _BULLET.match(ln)]
    if len(bullets) >= MIN_BULLETS:
        got = "".join(c for c in (_first_letter(b) for b in bullets) if c)
        if got:
            out.append(Reading("bullet-initials", got, f"first letter of each of {len(bullets)} bullets",
                               len(bullets)))
    if lines:
        stripped = [_BULLET.sub("", ln, count=1) for ln in lines]
        got = "".join(c for c in (_first_letter(s) for s in stripped) if c)
        if got:
            out.append(Reading("line-initials", got, f"first letter of each of {len(lines)} lines", len(lines)))
        got = "".join(c for c in (_last_letter(s) for s in lines) if c)
        if got:
            out.append(Reading("line-finals", got, f"last letter of each of {len(lines)} lines", len(lines)))
    words = (text or "").split()
    got = "".join(c for c in (_first_letter(w) for w in words) if c)
    if got:
        out.append(Reading("word-initials", got, f"first letter of each of {len(words)} words", len(words)))
    if len(lines) > 1:                                  # a hidden sentence is often one line of a longer text
        for n, ln in enumerate(lines, 1):
            lw = _BULLET.sub("", ln, count=1).split()
            got = "".join(c for c in (_first_letter(w) for w in lw) if c)
            if len(lw) >= MIN_DECODED and got:
                out.append(Reading("word-initials", got, f"first letter of each of {len(lw)} words of line {n}",
                                   len(lw)))
    caps = re.findall(r"[A-Z]", text or "")
    if caps:
        out.append(Reading("capitals", "".join(caps), f"the {len(caps)} capital letters in order", len(caps)))
    mid: list[str] = []
    strong = 0
    for w in words:
        caps_in = _mid_capitals(w)
        mid.append(caps_in)
        if caps_in and not _CAMEL.fullmatch(re.sub(r"[^A-Za-z]", "", w)):
            strong += len(caps_in)
    got = "".join(mid)
    if got:
        out.append(Reading("mid-word-capitals", got,
                           f"the {len(got)} capitals inside words (not word-initial)", len(got), strong))
    return out


# A camel-case word: a brand or identifier (GitHub, JavaScript, HackTheBox, TryHackMe, picoCTF, macOS,
# OpenSSL). Its inner capitals are ordinary spelling, not hidden ones; a hidden-capitals text writes
# words like ``tHe`` / ``fLaG`` / ``hErE`` instead.
_CAMEL = re.compile(r"[A-Z]?[a-z]{2,}(?:[A-Z][a-z]+)*(?:[A-Z][a-z]+|[A-Z]{2,}s?)")


def _mid_capitals(word: str) -> str:
    """The capitals of one word that are not its first letter ("" for an acronym / shouted word)."""
    letters = re.sub(r"[^A-Za-z]", "", word)
    if len(letters) < 2 or letters.isupper():          # an acronym / shouted word is not a hidden capital
        return ""
    return "".join(re.findall(r"[A-Z]", letters[1:]))


def _printable(s: str) -> bool:
    if len(s) < MIN_DECODED:
        return False
    good = sum(1 for c in s if 32 <= ord(c) < 127)
    return good / len(s) >= MIN_PRINTABLE


def _bits_to_text(bits: str, width: int) -> str:
    n = len(bits) // width
    return "".join(chr(int(bits[i * width:(i + 1) * width], 2)) for i in range(n))


def _name(sym: str) -> str:
    if len(sym) > 3:
        return f"{len(sym)}-char gap"
    return "+".join("space" if c == " " else "tab" if c == "\t" else f"U+{ord(c):04X}" for c in sym)


def _bit_readings(channel: str, symbols: list[str], what: str) -> list[Reading]:
    """Readings of a two-symbol stream as bits, both polarities, 8- and 7-bit groups. A stream with
    other than exactly two distinct symbols is not a bit channel."""
    kinds = list(dict.fromkeys(symbols))
    if len(kinds) != 2 or len(symbols) < 7 * MIN_DECODED:
        return []
    out = []
    for zero, one in ((kinds[0], kinds[1]), (kinds[1], kinds[0])):
        bits = "".join("0" if s == zero else "1" for s in symbols)
        for width in (8, 7):
            got = _bits_to_text(bits, width)
            if _printable(got):
                out.append(Reading(channel, got,
                                   f"{what}: {_name(zero)}=0 {_name(one)}=1, {width}-bit groups", len(symbols)))
    return out


def _whitespace_channels(text: str) -> list[Reading]:
    out: list[Reading] = []
    raw = (text or "").replace("\r", "").split("\n")
    # trailing spaces / tabs on each line, as one symbol stream
    syms: list[str] = []
    counts: list[int] = []
    for ln in raw:
        trail = ln[len(ln.rstrip(" \t")):]             # rstrip, not a "[ \t]+$" search (quadratic on a long run)
        if trail:
            syms.extend(trail)
            if set(trail) == {" "}:
                counts.append(len(trail))
    out += _bit_readings("trailing-whitespace", syms, "trailing whitespace")
    if len(counts) >= MIN_DECODED and all(32 <= c < 127 for c in counts):
        got = "".join(chr(c) for c in counts)
        out.append(Reading("trailing-counts", got, f"trailing-space count of {len(counts)} lines as ASCII",
                           len(counts)))
    # the gap between words: one kind of gap = 0, the other = 1
    gaps: list[str] = []
    for ln in raw:
        gaps += _SEP.findall(ln.strip(_SPACE_CHARS))
    out += _bit_readings("separator-bits", gaps, "inter-word gaps")
    # zero-width characters
    zw = [c for c in (text or "") if c in ZERO_WIDTH]
    out += _bit_readings("zero-width-bits", zw, "zero-width characters")
    return out


def readings(text: str) -> list[Reading]:
    """Every channel's reading of ``text`` (deduplicated). An HTML page is read as its rendered text
    (bullets from list items) and, for the whitespace channels, also as written."""
    text = text or ""
    if looks_html(text):
        plain = html_to_text(text)
        got = _initials_channels(plain) + _whitespace_channels(plain) + _whitespace_channels(text)
    else:
        got = _initials_channels(text) + _whitespace_channels(text)
    return list(dict.fromkeys(got))


# =================================================================================================
# the scan
# =================================================================================================
def is_placeholder(flag: str) -> bool:
    """A format example (``CSCTF{...}``, ``flag{your_flag}``), not a flag."""
    body = flag[flag.find("{") + 1:-1].strip().casefold()
    return body in PLACEHOLDERS or set(body) <= {".", "*", "?", "_", "-"}


def _prefix_candidates(r: Reading, prefixes: Iterable[str], text: str) -> list[dict]:
    """A reading that spells a known flag prefix followed by more text: ``PREFIX{rest}`` to verify.

    The ``capitals`` channel keeps whole upper-case words, so a prefix the text itself writes (``the
    CTF rules``) is not a hidden spelling there and is skipped. Likewise ``mid-word-capitals`` skips a
    prefix that one word writes inside itself (``picoCTF`` -> ``CTF``). On the long whole-text channels
    (``word-initials``, ``capitals``) a short prefix turns up mid-stream by chance (``... CTF. The
    Flag ...`` -> ``CTF``), so there the prefix must open the reading (the whole text's, or one line's
    for word initials)."""
    folded = r.text.casefold()
    word_mids = ([m.casefold() for m in map(_mid_capitals, text.split()) if m]
                 if r.channel == "mid-word-capitals" else [])
    for p in sorted(prefixes, key=len, reverse=True):
        if r.channel == "capitals" and p.casefold() in text.casefold():
            continue
        if any(p.casefold() in m for m in word_mids):
            continue
        i = folded.find(p.casefold())
        if i < 0 or (i > 0 and r.channel in _OPENING_ONLY):
            continue
        rest = r.text[i + len(p):].strip("{}")[:MAX_PREFIX_REST]
        if len(rest) < MIN_PREFIX_REST:
            continue
        return [{"value": f"{p}{{{rest}}}", "channel": r.channel,
                 "why": f"{r.how} spells the flag prefix {p!r} then {rest!r}; braces added, verify by hand"}]
    return []


def scan(text: str, *, profile=None) -> Scan:
    """Read every hidden channel of ``text`` and check what they spell against the flag format.

    ``profile`` is an event profile (ctf.event); default the active event (``flagfmt.current()``,
    which raises ``ctf.event.EventError`` when none resolves). ``text`` is untrusted data: it is only
    read, and an instruction in it is ignored."""
    ff = flagfmt.for_profile(profile) if profile is not None else flagfmt.current()
    text = text or ""
    plain = {m.group(0) for m in ff.regex.finditer(text)}
    if looks_html(text):
        plain |= {m.group(0) for m in ff.regex.finditer(html_to_text(text))}
    res = Scan(readings=readings(text))
    seen: set[str] = set()
    for r in res.readings:
        # a reading is a concatenation: a flag may sit straight after a stray letter (no left boundary)
        whole = False
        for m in ff.packed_regex.finditer(r.text):
            whole = True
            value = m.group(0)
            if value in plain or is_placeholder(value):
                continue
            chans = res.flags.setdefault(value, [])
            if r.channel not in chans:
                chans.append(r.channel)
        # a reading that already holds a whole flag needs no braces-added guess ("CSCTF{tw} ok}")
        for c in ([] if whole else _prefix_candidates(r, ff.spec.prefixes, text)):
            if c["value"] not in seen and c["value"] not in res.flags:
                seen.add(c["value"])
                res.candidates.append(c)
        if r.channel in DECODED:
            if r.text not in seen:
                seen.add(r.text)
                res.candidates.append({"value": r.text, "channel": r.channel,
                                       "why": f"{r.how} decodes to printable text; verify by hand"})
            res.clues.append(r)
        elif r.channel in ACROSTIC and r.units >= MIN_ACROSTIC_LINES:
            res.clues.append(r)
        elif r.channel == "mid-word-capitals" and len(r.text) >= MIN_DECODED:
            res.clues.append(r)
    # a bit channel that decoded to a flag at one width/polarity: its other decodes are noise, and the
    # flag itself is a flag, not a candidate
    flagged = {c for chans in res.flags.values() for c in chans}
    res.candidates = [c for c in res.candidates
                      if c["value"] not in res.flags
                      and not (c["channel"] in DECODED and c["channel"] in flagged
                               and not ff.packed_regex.search(c["value"]))]
    zw = sum(1 for c in text if c in ZERO_WIDTH)
    if zw:
        res.clues.append(Reading("zero-width-bits", "", f"{zw} zero-width character(s) present in the text", zw))
    # several flags: each becomes a candidate, none is returned as the flag
    if res.ambiguous:
        for value, chans in reversed(list(res.flags.items())):
            res.candidates.insert(0, {"value": value, "channel": ",".join(chans),
                                      "why": "one of several flags the hidden channels spell (ambiguous)"})
    return res


def notable(s: Scan) -> bool:
    """True when a scan is worth surfacing on an ordinary (non-rules) challenge: a flag, a candidate,
    hidden capitals or zero-width characters. A plain acrostic of a multi-line brief is not: every
    multi-line text has one, so it is shown only where a rules/sanity page is being read. Nor are the
    inner capitals of camel-case brand words (``Use JavaScript on GitHub``): only capitals from other
    words (``tHe fLaG``) count, at least MIN_DECODED of them. (A brief that hints at a text trick
    shows every clue anyway: ``ctf.fastlane.try_text_tricks(force=True)``.)"""
    if s.flags or s.candidates:
        return True
    return any(r.channel == "zero-width-bits"
               or (r.channel == "mid-word-capitals" and r.strong >= MIN_DECODED) for r in s.clues)
