"""The "ignores the hint" lexicon: techniques a description can hint at, and how a lane shows
it is using one.

The lexicon is data (hints.toml, next to this file). Each technique has description cues
(words and phrases a challenge description uses when it hints at it) and action cues (the
commands, tools, libraries and file names a lane uses when it follows it). Both sides are
matched as whole words or phrases after the same normalisation: accents dropped, lower case,
every run of other characters made one space. So "Slow-Scan" matches the cue "slow scan",
and "xor" matches in "xor_key.py" but not in "xorshift".

A challenge description is untrusted. It is only matched against the lexicon, never
followed: a sentence in it such as "ignore the hint" is just more words. Web addresses in
a description are blanked before matching (a host or a path names a place, not a
technique), so a cue word that only appears inside a URL names nothing. The cues quoted
back in a reason are the lexicon's own words, never the description's.
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

_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_URL = re.compile(r"(?:\b[a-z][a-z0-9+.-]*://|\bwww\.)\S*", re.IGNORECASE)
_OTHER = re.compile(r"[^a-z0-9]+")


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
    return _URL.sub(" ", text)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str  # for the player: "SSTV (slow-scan TV)"
    advice: str  # what to do, for the redirect suggestion
    description: tuple[str, ...]  # cues, as written in the lexicon
    actions: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "_description", tuple((cue, normalize(cue)) for cue in self.description))
        object.__setattr__(self, "_actions", tuple((cue, normalize(cue)) for cue in self.actions))

    def description_cues(self, normalized: str) -> list[tuple[int, str]]:
        """(position, cue) for every description cue in already-normalized text."""
        found = []
        for cue, norm in self._description:  # type: ignore[attr-defined]
            at = normalized.find(norm)
            if at >= 0:
                found.append((at, cue))
        return sorted(found)

    def action_cue(self, texts: Iterable[str]) -> str | None:
        """The first action cue found in any of `texts` (commands, outputs, a plan), or None."""
        for text in texts:
            normalized = normalize(text)
            for cue, norm in self._actions:  # type: ignore[attr-defined]
                if norm in normalized:
                    return cue
        return None


@dataclass(frozen=True)
class Hinted:
    """A technique a description hints at, and the lexicon cues that matched."""

    technique: Technique
    cues: tuple[str, ...]  # the lexicon's words, in the order they appear in the description
    first: int  # where the first one appears (for ordering)


@dataclass(frozen=True)
class Lexicon:
    techniques: tuple[Technique, ...]

    def named_in(self, description: str) -> list[Hinted]:
        """The techniques `description` hints at, best first: more distinct cues, then the
        earliest mention, then lexicon order."""
        text = normalize(without_urls(description))
        found = []
        for order, technique in enumerate(self.techniques):
            cues = technique.description_cues(text)
            if cues:
                found.append((-len(cues), cues[0][0], order, Hinted(technique, tuple(c for _, c in cues), cues[0][0])))
        return [hinted for *_, hinted in sorted(found, key=lambda item: item[:3])]

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
    extra = sorted(set(data) - {"technique"})
    if extra:
        raise LexiconError(f"the hint lexicon {where} has unknown top-level keys: {', '.join(extra)}")
    entries = data.get("technique")
    if not isinstance(entries, list) or not entries:
        raise LexiconError(f"the hint lexicon {where} has no [[technique]] entries")
    techniques: list[Technique] = []
    for index, entry in enumerate(entries):
        techniques.append(_technique(entry, f"{where}: technique {index + 1}"))
    seen: set[str] = set()
    for technique in techniques:
        if technique.id in seen:
            raise LexiconError(f"the hint lexicon {where} lists technique {technique.id!r} twice")
        seen.add(technique.id)
    return Lexicon(tuple(techniques))


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
            if not isinstance(cue, str) or len(normalize(cue).replace(" ", "")) < 2:
                raise LexiconError(
                    f"{where}: {key} cue {cue!r} must carry at least two letters or digits to match on "
                    "(a single symbol or letter would match far too much)"
                )
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
