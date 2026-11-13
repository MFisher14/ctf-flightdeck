"""Flag variants: the other spellings of one value that could be the flag, in one ranked list.

    from ctf_flightdeck import flagvariants
    for v in flagvariants.variants("FLAG{ENIGMA_IS_FUN}", r"(?i)flag\\{\\w+\\}"):
        v.value     # "flag{ENIGMA_IS_FUN}", then "flag{enigma_is_fun}", ...
        v.changes   # ("fix:prefix:flag",), then ("fix:prefix:flag", "case:lower"), ...
        v.what      # "prefix written flag", then "prefix written flag, lower case": for the player

Why. A right solve can lose its spelling on the way to the platform: a cipher with one letter
case gives the flag in capitals, a decoder wraps a wrapped flag again, a lane writes spaces
where the platform has underscores. Without a list, a lane guesses those spellings one by one
and spends submissions on it. variants() names them once, best first; who consumes the list
takes it in order and stops at a budget (the deck: DeckConfig.variant_tries).

It is pure: no I/O, no clock, and the same arguments always give the same list in the same
order. It judges nothing: a variant is a guess, and only the platform says which one is the flag.

What it returns: at most `max_variants` (MAX_VARIANTS, 12) variants of `value`. Every one
fullmatches `flag_format` (the event's regular expression, checked as flagformat.check has it),
differs from `value`, and is listed once. `value` itself need not match the format. No
variants at all (an empty tuple) for a value that is empty once stripped, has empty braces,
holds a control or unassigned character (decoder noise), or is longer than MAX_VALUE characters.

The safe fixes come first. They are applied together, in this order, and the fixed value is
the first variant when it differs from `value` and matches the format; every later variant is
built on it, and lists the fixes among its changes:

  fix:strip        whitespace around the value removed
  fix:inner-space  whitespace just inside the braces removed
  fix:double-wrap  PREFIX{PREFIX{body}} (the prefix compared without case) wrapped once
  fix:wrap:P       no PREFIX{...} wrapper, and the format names literal prefixes: wrapped in the first
  fix:prefix:P     the prefix is not written as the format names it (another case, or another
                   word): written as the format has it (its own spelling, else the first prefix)

The last two need the format's literal prefixes (prefixes_of): `flag\\{...\\}` names flag,
`(?:flag|CTF)\\{...\\}` names flag and CTF, `\\w+\\{...\\}` names none.

Then the axes, each offered only when it applies to the value's body:

  case        lower, Title_Per_Word, UPPER: only when the case is in doubt, which is when the
              caller says so (case_lost) or the body has at least CASE_MIN_LETTERS letters and
              every one is a capital (what a one-case cipher gives)
  diacritics  accented letters folded to ASCII (café -> cafe)
  spaces      whitespace -> underscores; with none, underscores -> spaces
  leet        leet -> letters (h3ll0 -> hello; a token of digits only is left alone); with no
              leet in it, letters -> leet (a4 e3 i1 o0 s5 t7)
  wrap        the body without its wrapper, and the format's other literal prefixes (at most
              MAX_OTHER_PREFIXES)

Each alternative has a prior weight (WEIGHTS). A variant combines at most MAX_AXES of them, one
per axis, applied in the order of AXES; its score is the product of their weights. The list is
ranked by score (highest first), then by fewer changes, then by the order of AXES, then by the
value: so the order is total and stable. A value reached two ways keeps its better score.

From the solver pack's flag check (packs/solvers/ctf/flagcheck.py: `variants`), with these
differences: the format is a regular expression, not a list of prefixes, so a variant outside
it is dropped rather than listed; the pack's case axis goes by the name of the value's source
(an Enigma, a Morse decoder), which flightdeck does not have, so it goes by the value; and the
pack's case restored from a reference text is left out.
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from .flagformat import check as check_flag_format

MAX_VALUE = 1024  # characters of a value that gets variants
MAX_VARIANTS = 12  # variants listed for one value
MAX_AXES = 3  # alternatives one variant combines
MAX_OTHER_PREFIXES = 3  # of the format's other literal prefixes offered
CASE_MIN_LETTERS = 4  # letters, all capitals, that put the case in doubt

AXES = ("case", "diacritics", "spaces", "leet", "wrap")  # the order transforms apply in, and tie order
WEIGHTS = {
    "case:lower": 0.5, "case:title": 0.4, "case:upper": 0.3,
    "diacritics:ascii": 0.5,
    "spaces:underscores": 0.6, "spaces:spaces": 0.25,
    "leet:literal": 0.3, "leet:leet": 0.25,
    "wrap:plain": 0.35, "wrap:prefix": 0.15,
}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
DELEET = {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"}
_FOLD_EXTRA = {"ß": "ss", "æ": "ae", "Æ": "AE", "œ": "oe", "Œ": "OE", "ø": "o", "Ø": "O", "đ": "d",
               "Đ": "D", "ł": "l", "Ł": "L", "ı": "i", "þ": "th", "Þ": "TH"}
_NOISE = frozenset({"Cc", "Cf", "Co", "Cn", "Zl", "Zp"})  # control, format, private, unassigned, line and paragraph separators

_WRAPPER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")  # a wrapper's word before its brace
_LITERAL = re.compile(r"[A-Za-z0-9_]{1,32}")  # a prefix a format names as plain text
_TOKEN = re.compile(r"[A-Za-z0-9@$]+")
_WORD_SEP = re.compile(r"([_\-\s]+)")
_WHAT = {
    "fix:strip": "whitespace around it removed",
    "fix:inner-space": "whitespace inside the braces removed",
    "fix:double-wrap": "wrapped once, not twice",
    "case:lower": "lower case",
    "case:title": "Title_Case per word",
    "case:upper": "UPPER case",
    "diacritics:ascii": "accents removed",
    "spaces:underscores": "spaces to underscores",
    "spaces:spaces": "underscores to spaces",
    "leet:literal": "leet to letters",
    "leet:leet": "letters to leet",
    "wrap:plain": "wrapper removed",
}
_WHAT_PREFIX = {"fix:wrap:": "wrapped as {}{{...}}", "fix:prefix:": "prefix written {}", "wrap:prefix:": "prefix {}"}


class FlagVariantsError(ValueError):
    """A bad argument to variants(): a value that is not a string, a count out of range."""


@dataclass(frozen=True)
class Variant:
    value: str
    changes: tuple[str, ...]  # what differs from the original, in the order applied: ("fix:strip", "case:lower")
    score: float  # 1.0 for the safe fixes alone; else the product of its alternatives' weights

    @property
    def what(self) -> str:
        """The changes in words, for the player."""
        return ", ".join(describe(change) for change in self.changes)


def describe(change: str) -> str:
    """One change label in words. FlagVariantsError for a label variants() never gives."""
    if change in _WHAT:
        return _WHAT[change]
    for head, text in _WHAT_PREFIX.items():
        if change.startswith(head) and _LITERAL.fullmatch(change[len(head):]):
            return text.format(change[len(head):])
    raise FlagVariantsError(f"{change!r} is not a change a flag variant can have")


def prefixes_of(flag_format: str) -> tuple[str, ...]:
    """The literal prefixes a flag format names before its opening brace, as it spells them:
    'practice\\{[a-z]+\\}' -> ('practice',); '(?i)(?:flag|CTF)\\{.+\\}' -> ('flag', 'CTF');
    '\\w+\\{...\\}' -> (). Only what is certainly literal is taken: one alternative that is
    not plain text, and the format names none."""
    head, brace, _ = flag_format.partition(r"\{")
    if not brace:
        return ()
    head = re.sub(r"^\(\?[aiLmsux]+\)", "", head)  # global flags: (?i)
    head = head.lstrip("^")
    head = re.sub(r"^\(\?<![^)]*\)", "", head)  # a leading lookbehind (a word boundary)
    head = re.sub(r"^\\b", "", head)
    group = re.fullmatch(r"\((?:\?:)?([^()]*)\)", head)
    parts = group.group(1).split("|") if group else [head]
    return tuple(dict.fromkeys(parts)) if all(_LITERAL.fullmatch(part) for part in parts) else ()


def split(value: str) -> tuple[str | None, str]:
    """(prefix, body) of `PREFIX{body}`, else (None, value)."""
    brace = value.find("{")
    if brace > 0 and value.endswith("}") and _WRAPPER.fullmatch(value[:brace]):
        return value[:brace], value[brace + 1:-1]
    return None, value


def has_leet(body: str) -> bool:
    """A token (letters, digits, @ and $) that holds at least one letter and one leet character."""
    return any(any(c.isalpha() for c in token) and any(c in DELEET for c in token) for token in _TOKEN.findall(body))


def deleet(body: str) -> str:
    """Leet characters back to letters, inside tokens that hold a letter (`2026` is left alone).
    A token whose letters are all capitals gets capitals back."""
    def token(match: re.Match[str]) -> str:
        text = match.group(0)
        letters = [c for c in text if c.isalpha()]
        if not letters:
            return text
        upper = all(c.isupper() for c in letters)
        return "".join((DELEET[c].upper() if upper else DELEET[c]) if c in DELEET else c for c in text)
    return _TOKEN.sub(token, body)


def leetify(body: str) -> str:
    return "".join(LEET.get(c.lower(), c) for c in body)


def ascii_fold(text: str) -> str:
    """Accented letters as their ASCII letters; what has no ASCII form is left as it is."""
    out = []
    for char in text:
        if char in _FOLD_EXTRA:
            out.append(_FOLD_EXTRA[char])
        else:
            out.append("".join(c for c in unicodedata.normalize("NFKD", char) if not unicodedata.combining(c)))
    return "".join(out)


def title_words(body: str) -> str:
    """Each word between separators (_ - whitespace) with a capital first and the rest lower."""
    return "".join(part if _WORD_SEP.fullmatch(part) else part[:1].upper() + part[1:].lower()
                   for part in _WORD_SEP.split(body) if part)


def case_in_doubt(body: str) -> bool:
    """The body reads as what a one-case cipher gives: CASE_MIN_LETTERS letters or more, all capitals."""
    letters = [c for c in body if c.isalpha()]
    return len(letters) >= CASE_MIN_LETTERS and all(c.isupper() for c in letters)


def variants(
    value: str, flag_format: str, *, case_lost: bool = False, max_variants: int = MAX_VARIANTS
) -> tuple[Variant, ...]:
    """The ranked variants of `value` under `flag_format`: see the module's text. `case_lost`:
    the value came through a step that keeps no letter case, so the case axis is offered
    whatever the body looks like. FlagVariantsError for a bad argument, FlagFormatError for a
    flag format flightdeck cannot use."""
    if not isinstance(value, str):
        raise FlagVariantsError(f"a flag variant's value must be a string, not {type(value).__name__}")
    if not isinstance(case_lost, bool):
        raise FlagVariantsError(f"case_lost must be true or false, got {case_lost!r}")
    if isinstance(max_variants, bool) or not isinstance(max_variants, int) or not 0 <= max_variants <= MAX_VARIANTS:
        raise FlagVariantsError(f"max_variants must be a whole number from 0 to {MAX_VARIANTS}, got {max_variants!r}")
    pattern = re.compile(check_flag_format(flag_format, "the flag format for flag variants"))
    if len(value) > MAX_VALUE:
        return ()
    fixed = _fixed(value, prefixes_of(flag_format))
    if fixed is None:
        return ()
    prefix, body, fixes = fixed
    primary = _join(prefix, body)
    best: dict[str, tuple[float, tuple[str, ...]]] = {}
    alternatives = _alternatives(prefix, body, prefixes_of(flag_format), case_lost or case_in_doubt(body))
    axes = [axis for axis in AXES if alternatives[axis]]
    for count in range(1, min(MAX_AXES, len(axes)) + 1):
        for combo in itertools.combinations(axes, count):  # in the order of AXES, so transforms apply in that order
            for picks in itertools.product(*(alternatives[axis] for axis in combo)):
                new_prefix, new_body, score = prefix, body, 1.0
                for label, change in picks:
                    new_prefix, new_body = change(new_prefix, new_body)
                    score *= _weight(label)
                made = _join(new_prefix, new_body)
                if not new_body or made in (value, primary) or not pattern.fullmatch(made):
                    continue
                labels = tuple(label for label, _ in picks)
                old = best.get(made)
                if old is None or (score, -len(labels)) > (old[0], -len(old[1])):
                    best[made] = (score, labels)
    order = {axis: at for at, axis in enumerate(AXES)}
    ranked = sorted(best.items(), key=lambda kv: (-kv[1][0], len(kv[1][1]), [order[c.split(":")[0]] for c in kv[1][1]], kv[0]))
    out = [Variant(primary, fixes, 1.0)] if fixes and primary != value and pattern.fullmatch(primary) else []
    out += [Variant(made, fixes + labels, score) for made, (score, labels) in ranked]
    return tuple(out[:max_variants])


def _join(prefix: str | None, body: str) -> str:
    return f"{prefix}{{{body}}}" if prefix is not None else body


def _fixed(value: str, prefixes: tuple[str, ...]) -> tuple[str | None, str, tuple[str, ...]] | None:
    """`value` with the safe fixes applied, as (prefix, body, the fixes made); None when it can
    have no variants (empty, empty braces, a control character)."""
    fixes: list[str] = []
    text = value.strip()
    if text != value:
        fixes.append("fix:strip")
    if not text or any(unicodedata.category(c) in _NOISE for c in text):
        return None
    prefix, body = split(text)
    if prefix is not None and body != body.strip():
        fixes.append("fix:inner-space")
        body = body.strip()
    if prefix is not None:
        inner, inner_body = split(body)
        if inner is not None and inner.lower() == prefix.lower():
            fixes.append("fix:double-wrap")
            body = inner_body
    if prefixes:
        if prefix is None:
            prefix = prefixes[0]
            fixes.append(f"fix:wrap:{prefix}")
        elif prefix not in prefixes:
            prefix = next((p for p in prefixes if p.lower() == prefix.lower()), prefixes[0])
            fixes.append(f"fix:prefix:{prefix}")
    if not body:
        return None
    return prefix, body, tuple(fixes)


_Change = Callable[[str | None, str], tuple[str | None, str]]


def _alternatives(prefix: str | None, body: str, prefixes: tuple[str, ...], case: bool) -> dict[str, list[tuple[str, _Change]]]:
    """axis -> [(label, change(prefix, body) -> (prefix, body))] for the alternatives that apply."""
    out: dict[str, list[tuple[str, _Change]]] = {axis: [] for axis in AXES}
    if case:
        for label, fn in (("case:lower", str.lower), ("case:title", title_words), ("case:upper", str.upper)):
            if fn(body) != body:
                out["case"].append((label, lambda p, b, fn=fn: (p, fn(b))))
    if ascii_fold(body) != body:
        out["diacritics"].append(("diacritics:ascii", lambda p, b: (p, ascii_fold(b))))
    if re.search(r"\s", body):
        out["spaces"].append(("spaces:underscores", lambda p, b: (p, re.sub(r"\s+", "_", b))))
    elif "_" in body:
        out["spaces"].append(("spaces:spaces", lambda p, b: (p, b.replace("_", " "))))
    if has_leet(body):
        out["leet"].append(("leet:literal", lambda p, b: (p, deleet(b))))
    elif leetify(body) != body:
        out["leet"].append(("leet:leet", lambda p, b: (p, leetify(b))))
    if prefix is not None:
        out["wrap"].append(("wrap:plain", lambda p, b: (None, b)))
        for other in [p for p in prefixes if p.lower() != prefix.lower()][:MAX_OTHER_PREFIXES]:
            out["wrap"].append((f"wrap:prefix:{other}", lambda p, b, other=other: (other, b)))
    return out


def _weight(label: str) -> float:
    return WEIGHTS["wrap:prefix"] if label.startswith("wrap:prefix:") else WEIGHTS[label]
