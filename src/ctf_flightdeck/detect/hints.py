"""The "ignores the hint" lexicon: techniques a description can hint at, and how a lane shows
it is using one.

The lexicon is data (hints.toml, next to this file). Each technique has description cues
(words and phrases a challenge description uses when it hints at it) and action cues (the
commands, tools, libraries and file names a lane uses when it follows it).

Matching. Words are compared after the same normalisation: accents dropped, lower case,
every run of other characters made one space. A cue matches as whole words, and its last
word may take a plural "s" or "es": "Slow-Scan" matches the cue "slow scan", "text chunks"
matches "text chunk", and "xor" matches in "xor_key.py" but not in "xorshift". An action
cue whose meaning is in its symbols ("' or ", "<script", "{{7*7}}", "__class__", "unzip -P")
is matched as written instead, in the raw text (case-insensitive unless the cue has capital
letters, so "tEXt" is the PNG chunk type, never the word "text").

The loader refuses a cue that would match far too much: one with fewer than two letters or
digits, a one-word cue that is a common word ("stack", "format", "script", "or"), and a cue
made only of words like "the" and "with".

A challenge description is untrusted. It is only matched against the lexicon, never
followed: a sentence in it such as "ignore the hint" is just more words. Before matching,
web addresses are blanked (a host or a path names a place, not a technique), the text is cut
into clauses at sentence and clause punctuation (a cue never spans two), the lexicon's
boilerplate phrases ("flag format") are blanked, and a cue just after a negation in its
clause ("Nothing is hidden in the pixels") names nothing. All of it runs in time linear in
the description's length. The cues quoted back in a reason are the lexicon's own words,
never the description's.
"""

from __future__ import annotations

import re
import tomllib
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from pathlib import Path

LEXICON_FILE = "hints.toml"
ENTRY_KEYS = ("id", "name", "advice", "description", "actions")
TOP_KEYS = ("boilerplate", "technique")

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_OTHER = re.compile(r"[^a-z0-9]+")
_TOKEN = re.compile(r"\S+")
_CLAUSE = re.compile(r"[.!?;:,](?=\s|$)|\n")  # one character per boundary: linear, never backtracks
_WORDS = re.compile(r"[a-z0-9]+(?:[ _.-][a-z0-9]+)*")  # an action cue made of words, matched as words
_URL_OPENERS = "([{<\"'"

BOUNDARY = "|"  # stands for a clause boundary or a blanked phrase in normalised description text
NEGATION_WINDOW = 4  # words before a cue, in its clause, that can negate it
NEGATIONS = frozenset({
    "no", "not", "nothing", "never", "none", "neither", "nor", "without", "cannot",
    "isn", "aren", "wasn", "weren", "don", "doesn", "didn", "couldn", "shouldn", "wouldn",
    "hasn", "haven", "hadn", "mustn", "needn",
    "isnt", "arent", "wasnt", "werent", "dont", "doesnt", "didnt", "cant", "wont",
})
_CONTRACTED = frozenset({"can", "won", "ain"})  # "can't", "won't": the negation is the "t" after them
_NOT_NEGATING = frozenset({"just", "only", "simply", "merely"})  # "not just base64" still names base64

FUNCTION_WORDS = frozenset("""
a an the and or but nor if then else so as at by for from in into of off on onto out over to up
with within without via per than that this these those it its is are was were be been being am
do does did done has have had can could will would shall should may might must you your yours we
our ours i me my he him his she her they them their there here what which who whom whose when
where why how all any some each every one two no not nothing never none just only also very more
most less too again still yet back now
""".split())
"""Words that carry no technique: a cue made only of these matches everywhere."""

COMMON_WORDS = FUNCTION_WORDS | frozenset("""
flag flags file files data key keys text string strings format input output code script class
bytes byte batch reduce include export import download upload stack buffer overflow hash hashes
png jpg image images picture photo chunk chunks zip archive template eval escape sandbox usb
keyboard mouse mac signature nonce alg hid sql padding oracle cbc checker check password secret
server web login admin user token cookie session page site url link request message signal audio
sound video number numbers letter letters word words cipher hidden hide hid embedded appended
nested layers layer spectrum frequencies waterfall carrier partition system memory process
network traffic capture packet stream binary program service shell remote local host port run
runs read write open find get gets set print info value field note notes help
""".split())
"""Words too common to be a one-word cue: they appear in descriptions and outputs that hint at
nothing ("Flag format", "Download the attachment", "I hid the flag")."""


class LexiconError(ValueError):
    """The lexicon file is missing, is not TOML, or has an entry that is not right."""


def normalize(text: str) -> str:
    """Text as matched: no accents, lower case, words split by single spaces, a space at
    each end (so a cue matches only as whole words)."""
    plain = unicodedata.normalize("NFKD", text)
    plain = "".join(c for c in plain if not unicodedata.combining(c)).lower()
    words = _OTHER.sub(" ", plain).strip()
    return f" {words} " if words else " "


def without_urls(text: str) -> str:
    """`text` with every web address blanked: each whitespace-separated token that holds
    '://' or starts with 'www.'. One pass, linear in the length of the text."""

    def blank(match: re.Match[str]) -> str:
        token = match.group()
        if "://" in token or token.lstrip(_URL_OPENERS).lower().startswith("www."):
            return " "
        return token

    return _TOKEN.sub(blank, text)


def description_text(description: str, boilerplate: Iterable[str] = ()) -> str:
    """A description as description cues are matched against it: URLs blanked, one
    normalised clause after another with BOUNDARY between them, and the `boilerplate`
    phrases (already normalised, without the spaces at the ends) blanked to BOUNDARY."""
    clauses = _CLAUSE.split(without_urls(description))
    text = BOUNDARY.join(normalize(clause) for clause in clauses)
    for phrase in boilerplate:
        text = re.sub(rf"(?<= ){re.escape(phrase)}(?:e?s)?(?= )", BOUNDARY, text)
    return text


def _find_words(text: str, core: str, start: int = 0) -> int:
    """Where the words `core` (" a b", normalised, no trailing space) start in normalised
    `text`, as whole words with an optional plural "s"/"es" on the last one; -1 if absent."""
    while True:
        at = text.find(core, start)
        if at < 0:
            return -1
        end = at + len(core)
        if text.startswith(" ", end) or text.startswith("s ", end) or text.startswith("es ", end):
            return at
        start = at + 1


def _negated(text: str, at: int) -> bool:
    """Whether a negation stands in the few words before position `at`, in the same clause."""
    clause = text[max(0, at - 200):at].rsplit(BOUNDARY, 1)[-1].split()
    window = clause[-NEGATION_WINDOW - 1:]  # one more word, for the stem of a "can't"
    for i in range(max(0, len(window) - NEGATION_WINDOW), len(window)):
        word = window[i]
        nxt = window[i + 1] if i + 1 < len(window) else ""
        if word == "t" and i > 0 and (window[i - 1] in _CONTRACTED or window[i - 1] in NEGATIONS):
            return True  # "can't", "don't": the stem may sit just outside the window
        if word in NEGATIONS and nxt not in _NOT_NEGATING:
            return True
    return False


@dataclass(frozen=True)
class Technique:
    id: str
    name: str  # for the player: "SSTV (slow-scan TV)"
    advice: str  # what to do, for the redirect suggestion
    description: tuple[str, ...]  # cues, as written in the lexicon
    actions: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_description", tuple((cue, normalize(cue).rstrip()) for cue in self.description))
        object.__setattr__(self, "_actions", tuple((cue, *_action_needle(cue)) for cue in self.actions))

    def description_cues(self, text: str) -> list[tuple[int, str]]:
        """(position, cue) for every description cue in `text`, as description_text() makes
        it: whole words, not just after a negation in its clause."""
        found = []
        for cue, core in self._description:  # type: ignore[attr-defined]
            at = _find_words(text, core)
            while at >= 0 and _negated(text, at):
                at = _find_words(text, core, at + 1)
            if at >= 0:
                found.append((at, cue))
        return sorted(found)

    def action_cue(self, texts: Iterable[str]) -> str | None:
        """The first action cue found in any of `texts` (commands, outputs, a plan), or None."""
        for text in texts:
            if not text:
                continue
            normalized = lowered = None
            for cue, kind, needle in self._actions:  # type: ignore[attr-defined]
                if kind == "words":
                    normalized = normalized if normalized is not None else normalize(text)
                    if _find_words(normalized, needle) >= 0:
                        return cue
                elif kind == "literal":
                    lowered = lowered if lowered is not None else text.lower()
                    if needle in lowered:
                        return cue
                elif needle in text:  # "exact": a cue with capitals, matched as written
                    return cue
        return None


def _action_needle(cue: str) -> tuple[str, str]:
    """How an action cue is matched: ("words", normalised) for words joined by spaces, dots,
    dashes or underscores; else as written in the raw text, ("literal", lower case) or, for
    a cue with capitals, ("exact", the cue)."""
    if _WORDS.fullmatch(cue):
        return "words", normalize(cue).rstrip()
    if cue != cue.lower():
        return "exact", cue
    return "literal", cue


@dataclass(frozen=True)
class Hinted:
    """A technique a description hints at, and the lexicon cues that matched."""

    technique: Technique
    cues: tuple[str, ...]  # the lexicon's words, in the order they appear in the description
    first: int  # where the first one appears (for ordering)


@dataclass(frozen=True)
class Lexicon:
    techniques: tuple[Technique, ...]
    boilerplate: tuple[str, ...] = ()  # phrases blanked before matching ("flag format")

    def named_in(self, description: str) -> list[Hinted]:
        """The techniques `description` hints at, best first: more distinct cues, then the
        earliest mention, then lexicon order."""
        text = description_text(description, (normalize(p).strip() for p in self.boilerplate))
        found = []
        for order, technique in enumerate(self.techniques):
            cues = technique.description_cues(text)
            if cues:
                found.append((-len(cues), cues[0][0], order, Hinted(technique, tuple(c for _, c in cues), cues[0][0])))
        return [hinted for *_, hinted in sorted(found, key=lambda item: item[:3])]

    def classify(self, description: str) -> str | None:
        """The id of the technique `description` hints at most strongly, or None."""
        named = self.named_in(description)
        return named[0].technique.id if named else None

    def get(self, technique_id: str) -> Technique:
        for technique in self.techniques:
            if technique.id == technique_id:
                return technique
        raise KeyError(f"no technique {technique_id!r} in the lexicon")

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(t.id for t in self.techniques)


def load_lexicon(path: Path | None = None) -> Lexicon:
    """The lexicon in `path`, or the one shipped with flightdeck. LexiconError says what is wrong."""
    where = str(path) if path is not None else f"ctf_flightdeck/detect/{LEXICON_FILE}"
    try:
        raw = Path(path).read_text(encoding="utf-8") if path is not None else (
            files(__package__).joinpath(LEXICON_FILE).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise LexiconError(f"cannot read the hint lexicon {where}: {exc}") from None
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise LexiconError(f"the hint lexicon {where} is not valid TOML: {exc}") from None
    extra = sorted(set(data) - set(TOP_KEYS))
    if extra:
        raise LexiconError(f"the hint lexicon {where} has unknown top-level keys: {', '.join(extra)}")
    entries = data.get("technique")
    if not isinstance(entries, list) or not entries:
        raise LexiconError(f"the hint lexicon {where} has no [[technique]] entries")
    boilerplate = data.get("boilerplate", [])
    if not isinstance(boilerplate, list) or any(not isinstance(p, str) or len(_alnum(p)) < 2 for p in boilerplate):
        raise LexiconError(f"the hint lexicon {where}: boilerplate must be a list of phrases with letters or digits")
    techniques: list[Technique] = []
    for index, entry in enumerate(entries):
        techniques.append(_technique(entry, f"{where}: technique {index + 1}"))
    seen: set[str] = set()
    for technique in techniques:
        if technique.id in seen:
            raise LexiconError(f"the hint lexicon {where} lists technique {technique.id!r} twice")
        seen.add(technique.id)
    return Lexicon(tuple(techniques), tuple(boilerplate))


def _alnum(text: str) -> str:
    return normalize(text).replace(" ", "")


def _cue_problem(cue: object, key: str) -> str | None:
    """Why `cue` cannot be a cue of kind `key` ("description" or "actions"), or None."""
    if not isinstance(cue, str) or len(_alnum(cue)) < 2:
        return "must carry at least two letters or digits to match on (a single symbol or letter would match far too much)"
    if key == "actions" and _action_needle(cue)[0] != "words":
        return None  # matched as written, symbols and all
    words = normalize(cue).split()
    if len(words) == 1 and words[0] in COMMON_WORDS:
        return f"is the common word {words[0]!r}, which would match text that hints at nothing; use a phrase"
    if all(word in FUNCTION_WORDS for word in words):
        return "is made only of words like 'the' and 'with', which would match almost any text"
    return None


def _technique(entry: object, where: str) -> Technique:
    if not isinstance(entry, dict):
        raise LexiconError(f"{where} is not a table")
    extra = sorted(set(entry) - set(ENTRY_KEYS))
    if extra:
        raise LexiconError(f"{where} has unknown keys: {', '.join(extra)}")
    missing = [key for key in ENTRY_KEYS if key not in entry]
    if missing:
        raise LexiconError(f"{where} is missing {', '.join(missing)}")
    technique_id = entry["id"]
    if not isinstance(technique_id, str) or not _ID.fullmatch(technique_id):
        raise LexiconError(f"{where}: id must be lower-case words joined by '-', got {technique_id!r}")
    where = f"{where} ({technique_id})"
    for key in ("name", "advice"):
        if not isinstance(entry[key], str) or not entry[key].strip():
            raise LexiconError(f"{where}: {key} must be non-empty text")
    cues = {}
    for key in ("description", "actions"):
        value = entry[key]
        if not isinstance(value, list) or not value:
            raise LexiconError(f"{where}: {key} must be a non-empty list of cues")
        for cue in value:
            problem = _cue_problem(cue, key)
            if problem is not None:
                raise LexiconError(f"{where}: {key} cue {cue!r} {problem}")
        cues[key] = tuple(value)
    return Technique(technique_id, entry["name"].strip(), entry["advice"].strip(), cues["description"], cues["actions"])


@cache
def lexicon() -> Lexicon:
    """The lexicon shipped with flightdeck (loaded once)."""
    return load_lexicon()


def named_techniques(description: str, lex: Lexicon | None = None) -> list[Hinted]:
    """The techniques a description hints at, best first (the shipped lexicon by default)."""
    return (lex or lexicon()).named_in(description)


def top_technique(description: str, lex: Lexicon | None = None) -> Technique | None:
    """The technique a description hints at most strongly, or None."""
    named = named_techniques(description, lex)
    return named[0].technique if named else None


def classify(description: str, lex: Lexicon | None = None) -> str | None:
    """The id of the technique a description hints at most strongly, or None when it hints
    at none: the entry point the local-model evaluation's rules baseline uses."""
    return (lex or lexicon()).classify(description)
