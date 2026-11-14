"""Reading a question's `answer_format` into a Contract (B-232).

A judged platform states, per question, the form its answer takes:

    {"kind": "ordered_tokens", "syntax": "exact tokens joined by > with no surrounding spaces"}
    {"kind": "json", "syntax": "a compact JSON array of strings in ascending order"}
    {"kind": "exact_text", "syntax": "comma-separated member names, no spaces"}
    {"kind": "enum", "accepted_values": ["low", "high"]}

`read(answer_format, question_text=None)` turns that into a `Contract`: the kind, the join separator
the text states (and whether it says no spaces surround it), the container (a JSON array or object),
the element order it states, the accepted values, and whether the literal `none` is allowed. Only
what the text states in so many words is read; anything else stays None, which the renderer turns
into a candidate axis instead of a guess. A missing contract (a CTFd event has none) is a Contract
with `present` False, never an error. A contract that is not a mapping raises AnswerFormatError.

The order is read from the syntax and from the question text, with the same phrases. Two different
orders stated (`ascending` in the syntax, `in file order` in the question) are a conflict: `order` is
None and `conflicts` names both, so a list answer keeps its order axis. A keyed order (`sorted by
size`, `digest order`) is the exception: a direction stated with it (`largest first`, `ascending`) is
the key's direction, not a second order, and `order` stays `keyed` even beside another stated order
(that one is still named in `conflicts`), so the renderer withholds the list instead of offering an
order the key does not give.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .. import idresolve as _idresolve

__all__ = ["AnswerFormatError", "Contract", "read", "ORDERS", "CONTAINERS"]

ORDERS = ("ascending", "descending", "file", "any", "keyed")
CONTAINERS = ("json_array", "json_object", "json")


class AnswerFormatError(ValueError):
    """An answer_format (or a value handed to the renderer) that cannot be read; the message names why."""


# ------------------------------------------------------------------------------------------- separator

# `joined by >`, `separated with ->`, `delimited by |` (the words Huntress used; generic.py's reading,
# lane-blind). The separator is one to three characters that are no word and no quote, followed by a
# blank, the end, or a closing punctuation mark (`joined by >.` states `>`, not `>.`).
_JOIN_VERB = r"(?:joined|separated|delimited|concatenated)\s+(?:by|with)\s+"
_JOINED_BY = re.compile(_JOIN_VERB + r"([^\w\s\"'`]{1,3}?)(?=\s|$|[.;:)](?:\s|$))")
# `joined by " > "`: a quoted separator keeps the blanks it holds.
_JOINED_QUOTED = re.compile(_JOIN_VERB + r"([\"'`])([^\w\"'`\r\n]{1,7})\1")
# Separators named by a word: `comma-separated`, `separated by commas`, `one per line`.
_NAMED = {"comma": ",", "semicolon": ";", "pipe": "|", "space": " ", "newline": "\n", "tab": "\t",
          "colon": ":", "slash": "/"}
_NAMED_ADJ = re.compile(r"\b(comma|semicolon|pipe|space|newline|tab|colon|slash)[- ](?:separated|delimited)\b")
_NAMED_VERB = re.compile(_JOIN_VERB + r"(?:an?\s+|single\s+|the\s+)?(comma|semicolon|pipe|space|newline|tab|colon|slash)(?:e?s)?\b")
_ONE_PER_LINE = re.compile(r"\bone per line\b|\beach on its own line\b")
# `comma followed by a space`, `comma and a space`, `comma-space`: the separator holds its blank.
_COMMA_SPACE = re.compile(r"\bcomma(?:[- ]space|\s+(?:followed\s+by|and)\s+(?:a\s+|one\s+|single\s+)?space)\b")
_TIGHT = re.compile(r"\bno\s+(?:surrounding\s+|extra\s+)?(?:spaces|whitespace|blanks)\b"
                    r"|\bwithout\s+(?:any\s+)?(?:surrounding\s+|extra\s+)?(?:spaces|whitespace|blanks)\b")

# ------------------------------------------------------------------------------------------- order

# Order phrases. Bare `sorted` is not read (`sorted by size` names another key); `in sorted order`,
# `sorted ascending` and `sorted alphabetically` are.
_NOT_SORTED = re.compile(r"\b(?:not\s+sorted|unsorted|do\s+not\s+sort|don't\s+sort|without\s+sorting|no\s+sorting)\b")
_ANY = re.compile(r"\bin\s+any\s+order\b|\border\s+(?:does\s+not|doesn't)\s+matter\b|\border\s+is\s+not\s+significant\b")
_FILE = re.compile(
    r"\b(?:in\s+)?(?:the\s+)?(?:file|document|stored|storage|archive|directory|table|record|original|source|"
    r"on-disk|disk|listing|central[- ]directory)\s+order\b"
    r"|\bin\s+the\s+order\s+(?:they|it|each|these|the\s+\w+)\s+(?:appears?|occurs?|(?:are|is)\s+(?:stored|listed|written|found))\b"
    r"|\bas\s+(?:they|it)\s+(?:appears?|occurs?)\b|\border\s+of\s+(?:first\s+)?(?:appearance|occurrence)\b"
    r"|\bas\s+(?:stored|listed)\b")
_ASC = re.compile(
    r"\bascending\b|\bincreasing\s+order\b|\bin\s+sorted\s+order\b|\bsorted\s+(?:ascending|alphabetically|"
    r"lexicographically|in\s+ascending)\b|\balphabetically\b|\balphabetical\s+order\b|\blexicographically\b"
    r"|\blexicographic(?:al)?\s+order\b"
    r"|\b(?:sorted|ordered)\s+by\s+(?:file\s?)?names?\b|\bsmallest\s+first\b|\blowest\s+first\b")
# Not read as an order: `alphabetical characters`, a character class `[a-z]` (an element's form, not the list's).
_DESC = re.compile(r"\bdescending\b|\bdecreasing\s+order\b|\breverse\s+(?:alphabetical|sorted|lexicographic)\b"
                   r"|\blargest\s+first\b|\bhighest\s+first\b")
# `sorted by size`, `ordered by timestamp`, `in reverse order`, `in ascending order of modification time`,
# `in chronological order`, `oldest first`: an order this module cannot apply to the list itself (a
# handler must order it and render with ordered=True). `order of <noun>` is keyed only after `in` or a
# direction (`the order of the tokens matters` states no order), and not for a noun that names the
# list's own order (`order of appearance` is file order; `order of the input`, `order of name` are not keys).
_ORDER_OF_NOT_KEY = (r"(?:first\s+)?(?:appearance|occurrence)\b|(?:file\s?)?names?\b"
                     r"|(?:file|archive|document|listing|input|source|original|table|directory|list)\b"
                     r"(?![\s-]+(?:sizes?|times?|timestamps?|dates?|offsets?|lengths?|modification|creation|access)\b)")
_TIME_END = r"(?:oldest|newest|earliest|latest|most\s+recent|least\s+recent)"
_KEYED = re.compile(r"\b(?:sorted|ordered|order(?:ed)?)\s+by\s+(?!(?:file\s?)?names?\b)(\w[\w-]*)"
                    r"|\b(?:\w[\w-]*\s+)?(?:digest|hash|size|time|timestamp|offset|date)\s+order\b|\bin\s+reverse\s+order\b"
                    r"|(?:\b(?:ascending|descending|increasing|decreasing|reverse)\s+|\bin\s+(?:the\s+)?)order\s+of\s+"
                    r"(?!(?:the\s+|their\s+|its\s+)?(?:" + _ORDER_OF_NOT_KEY + r"))(?:the\s+|their\s+|its\s+)?\w[\w-]*"
                    r"|\b(?:reverse[- ])?chronological(?:ly)?\b"
                    r"|\b" + _TIME_END + r"\s+(?:one\s+|entry\s+|file\s+)?first\b"
                    r"|\bfrom\s+(?:the\s+)?" + _TIME_END + r"\s+to\s+(?:the\s+)?" + _TIME_END + r"\b")


def _orders_in(text: str) -> list[str]:
    """The order classes `text` states, in the order of ORDERS, each once."""
    low = text.lower()
    found = []
    if _NOT_SORTED.search(low):
        found.append("file")
        low = _NOT_SORTED.sub(" ", low)
    if _ANY.search(low):
        found.append("any")
    if _KEYED.search(low):
        found.append("keyed")
        # a keyed phrase may hold an ascending/descending word that belongs to the key (`ascending digest order`)
        low = _KEYED.sub(" ", re.sub(r"\b(?:ascending|descending)\s+(?=(?:\w[\w-]*\s+)?(?:digest|hash|size|time|timestamp|offset|date)\s+order\b)", " ", low))
    if _FILE.search(low):
        found.append("file")
    if _ASC.search(low):
        found.append("ascending")
    if _DESC.search(low):
        found.append("descending")
    return [o for o in ORDERS if o in found]


# ------------------------------------------------------------------------------------------- contract

@dataclass(frozen=True)
class Contract:
    """What an answer_format states. None (or empty) for anything it does not state."""

    present: bool                          # an answer_format mapping was given at all
    kind: str = ""                         # lowercased `kind`; "" when absent
    syntax: str = ""                       # the `syntax` text as given
    accepted: tuple[str, ...] = ()         # `accepted_values` as strings
    accepted_partial: bool = False         # the syntax says the list is only examples (`such as`, `e.g.`)
    case_insensitive: bool = False         # `normalization` says case is ignored
    separator: str | None = None           # the stated join separator, as written
    tight: bool = False                    # the syntax says no spaces surround it
    container: str | None = None           # one of CONTAINERS, or None
    order: str | None = None               # one of ORDERS, or None (not stated, or a conflict)
    conflicts: tuple[str, ...] = ()        # what was stated twice, differently (`order: ascending/file`)
    none_ok: bool = False                  # the literal `none` is allowed (ctf.idresolve.permits_literal_none)
    notes: tuple[str, ...] = field(default=())

    @property
    def spaced_separator(self) -> bool:
        """The separator carries its own blanks (`", "`) or is itself a blank: no tight/spaced axis."""
        return self.separator is not None and (self.separator != self.separator.strip() or not self.separator.strip())

    def describe(self) -> dict:
        return {"present": self.present, "kind": self.kind, "separator": self.separator, "tight": self.tight,
                "container": self.container, "order": self.order, "accepted": list(self.accepted),
                "accepted_partial": self.accepted_partial, "case_insensitive": self.case_insensitive,
                "none_ok": self.none_ok, "conflicts": list(self.conflicts), "notes": list(self.notes)}


_PARTIAL = re.compile(r"\bsuch as\b|\bfor example\b|\be\.g\.|\bincluding\b|\bexamples?\b|\bor (?:an)?other\b|\betc\b")


def _separator(syntax: str) -> tuple[str | None, list[str]]:
    """(the stated separator or None, conflict notes)."""
    low = syntax.lower()
    found: list[str] = []
    for m in _JOINED_QUOTED.finditer(syntax):
        found.append(m.group(2))
    quoted_spans = [m.span() for m in _JOINED_QUOTED.finditer(syntax)]
    for m in _JOINED_BY.finditer(syntax):
        if not any(a <= m.start() < b for a, b in quoted_spans):
            found.append(m.group(1))
    if _COMMA_SPACE.search(low):
        found.append(", ")
    else:
        for rx in (_NAMED_ADJ, _NAMED_VERB):
            for m in rx.finditer(low):
                found.append(_NAMED[m.group(1)])
    if _ONE_PER_LINE.search(low):
        found.append("\n")
    distinct = list(dict.fromkeys(found))
    if len(distinct) > 1:
        return None, [f"separator: {' / '.join(repr(s) for s in distinct)}"]
    return (distinct[0] if distinct else None), []


def _container(kind: str, syntax: str) -> str | None:
    low = syntax.lower()
    arr = bool(re.search(r"\bjson\s+(?:array|list)\b|\barray\b", low))
    obj = bool(re.search(r"\bjson\s+object\b|\bobject\b", low))
    if kind == "json":
        if arr and obj:
            return "json"
        if obj:
            return "json_object"
        return "json_array" if arr else "json"
    if re.search(r"\bjson\s+(?:array|list)\b", low):
        return "json_array"
    if re.search(r"\bjson\s+object\b", low):
        return "json_object"
    return None


def read(answer_format, question_text: str | None = None) -> Contract:
    """The Contract an answer_format states. None reads as no contract (`present` False); anything that
    is not a mapping raises AnswerFormatError."""
    if answer_format is None:
        order, conflicts = _order_only(question_text)
        return Contract(present=False, order=order, conflicts=tuple(conflicts))
    if not isinstance(answer_format, dict):
        raise AnswerFormatError(f"answer_format is a {type(answer_format).__name__}, not a mapping")
    kind = answer_format.get("kind")
    kind = kind.strip().lower() if isinstance(kind, str) else ""
    syntax = answer_format.get("syntax")
    syntax = syntax if isinstance(syntax, str) else ""
    acc = answer_format.get("accepted_values")
    accepted = tuple(str(a) for a in acc if isinstance(a, (str, int, float)) and not isinstance(a, bool)) \
        if isinstance(acc, list) else ()
    norm = answer_format.get("normalization")
    case_insensitive = isinstance(norm, str) and "insensitive" in norm.lower()
    sep, conflicts = _separator(syntax)
    orders = sorted(set(_orders_in(syntax)) | set(_orders_in(question_text or "")), key=ORDERS.index)
    order, more = _settle_order(orders)
    conflicts.extend(more)
    return Contract(
        present=True, kind=kind, syntax=syntax, accepted=accepted,
        accepted_partial=bool(_PARTIAL.search(syntax.lower())), case_insensitive=case_insensitive,
        separator=sep, tight=bool(_TIGHT.search(syntax.lower())), container=_container(kind, syntax),
        order=order, conflicts=tuple(conflicts),
        none_ok=_idresolve.permits_literal_none({"answer_format": answer_format}))


def _settle_order(orders: list[str]) -> tuple[str | None, list[str]]:
    """(the order, conflict notes) for the order classes stated. A keyed order takes ascending and
    descending as its own direction and wins over any other stated order (named as a conflict)."""
    if "keyed" in orders:
        rest = [o for o in orders if o not in ("keyed", "ascending", "descending")]
        return "keyed", ([f"order: {' / '.join(['keyed'] + rest)}"] if rest else [])
    if len(orders) == 1:
        return orders[0], []
    return None, ([f"order: {' / '.join(orders)}"] if orders else [])


def _order_only(question_text):
    return _settle_order(_orders_in(question_text or ""))
