"""Flag plausibility check and one ranked flag-variant set (B-154).

    from ctf import flagcheck
    rep = flagcheck.check(value, profile, source="strings")      # flagcheck.Check
    rep.verdict            # "ok" | "warn" | "block"
    rep.primary            # the value with the safe fixes applied (stripped, wrapped, prefix spelling)
    rep.findings           # (Finding(code, level, message), ...)
    vs = flagcheck.variants(value, profile, source="enigma")     # flagcheck.VariantSet
    vs.ranked              # (Variant(rank, value, score, changes, in_format), ...); rank 0 is the primary
    vs.plan(guesses_left)  # (to send, held): the primary plus at most `guesses_left` variants
    rep = flagcheck.try_variants(gate, cid, value, note="...")   # flagcheck.TryReport

Why. At CSCTF a value that passed PKCS7, HMAC and JSON checks was a decoy, and an Enigma solve lost
its CaMeL case; at Spooky the agents burned submissions re-guessing the wrap, leet, diacritics and
spaces of a flag. The check names those risks before a send; the variant set replaces re-guessing
with one ordered list, consumed in order and capped by the event's guess budget.

The check (findings; the verdict is the worst level):

  block  empty, empty_body, control_chars (decoder noise), not_in_format (after the safe fixes and
         any case restoration; info `nonstandard` instead under allow_nonstandard: a brief-defined
         answer)
  warn   whitespace_edge, edge_space, double_wrap, unwrapped, foreign_prefix (each is fixed in
         .primary and said so), placeholder, short_body, decoy_marker (fake, decoy, not_the_flag,
         try_harder... after undoing leet), static_source (the value came from a static shortcut:
         strings, grep, metadata, a comment, an intake scan... authors plant decoys there, and a
         local check passing does not rule one out), other_flags (other flag-format values in the
         same material), case_lost (the source does not keep letter case), spaces
  info   prefix_case (fixed), format_unknown, nonstandard, all_upper, case_ref, diacritics, leet

Plausibility is a heuristic. A decoy that passes every local check can only be told apart by the
judge: a warn verdict never means "wrong", and an ok verdict never means "solved". Only the
platform's accepted answer marks a challenge solved.

Variant axes (each is offered only when it applies to the value):

  case        restored from a reference text, lower, Title_Per_Word, UPPER (only when the case was
              lost, case_lossy / a case-losing source, or a reference text is given)
  diacritics  ASCII folding of accented letters (café -> cafe)
  spaces      spaces -> underscores, or underscores -> spaces
  leet        leet -> literal (h3ll0 -> hello; tokens that are only digits are left alone), or
              literal -> leet (a4 e3 i1 o0 s5 t7)
  wrap        wrapped -> plain body, or the event's other prefixes

Each alternative has a prior weight (WEIGHTS); a variant's score is the product of the weights of
the alternatives it combines (at most MAX_AXES of them), and the set is ranked by score, then by
fewer changes, then by axis order. The primary is rank 0 (score 1). A variant outside the event's
flag format is listed but marked in_format=False; try_variants sends it only under
allow_nonstandard.

Budget. try_variants sends the primary as the reasoned value (guess=False), then variants as
guesses (guess=True) in rank order, at most rules.guess_budget minus the guesses the challenge has
already used. It stops at the first accepted value, at any gate refusal other than `duplicate` (a
value already judged is skipped, not sent), and at an unjudged answer. Variants it may not send are
returned as `held`: the player can authorize a sweep (`ctf policy authorize-sweep`) and run them
with `ctf policy sweep --candidates FILE` (`ctf flag variants --out FILE` writes that file).
"""
from __future__ import annotations

import itertools
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import event as _event
from . import flagfmt as _flagfmt
from .sweep import _placeholder as _sweep_placeholder

LEVELS = ("info", "warn", "block")

# Sources that are static shortcuts: the value was read off the handout, not produced by solving it.
# Authors plant decoys exactly there (B-154: secustoring's decoy passed PKCS7, HMAC and JSON checks).
STATIC_SOURCES = {
    "strings": "strings over a file",
    "grep": "a text search of the files",
    "plaintext": "a value sitting in a handout file as-is",
    "metadata": "file metadata (EXIF, PDF info, archive comments)",
    "comment": "a comment in source, HTML or a config",
    "constant": "a constant embedded in a binary or script",
    "git-history": "a repository's history",
    "intake": "the no-model intake scan",
    "sweep": "the static sweep of the handout",
    "fastlane": "a fastlane decoder chain over a handout blob",
}
# Sources that lose letter case: their output's case is not evidence (B-154: Enigma lost CaMeL case).
CASE_LOSSY_SOURCES = {
    "enigma": "Enigma machines have one letter case",
    "morse": "Morse code has no letter case",
    "baconian": "the Baconian cipher has no letter case",
    "tap-code": "tap code has no letter case",
    "polybius": "a Polybius square has no letter case",
    "a1z26": "A1Z26 numbers carry no letter case",
    "t9": "phone-keypad (T9, multi-tap) digits carry no letter case",
    "braille": "Braille output usually drops letter case",
    "dna": "DNA codon ciphers carry no letter case",
    "semaphore": "semaphore has no letter case",
    "nato": "NATO spelling carries no letter case",
    "pigpen": "pigpen glyphs have no letter case",
    "playfair": "Playfair works on one letter case",
    "adfgvx": "ADFGVX works on one letter case",
    "bifid": "bifid works on one letter case",
}
# Sources that produced the value by solving: no source warning.
DERIVED_SOURCES = {
    "solver": "a solver script's output",
    "exploit": "an exploit's output against the target",
    "decrypt": "a decryption with a recovered key",
    "derived": "a derivation from the challenge data",
    "live": "the challenge service's answer",
    "player": "the player",
}
SOURCES = {**STATIC_SOURCES, **CASE_LOSSY_SOURCES, **DERIVED_SOURCES}

DECOY_WORDS = ("fake", "decoy", "nope", "troll", "rickroll", "bait", "gotcha", "lol")
DECOY_PHRASES = ("not_the_flag", "not_a_flag", "not_flag", "not_real", "try_again", "try_harder",
                 "red_herring", "nice_try", "wrong_flag", "never_gonna", "keep_looking", "too_easy")

LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
DELEET = {"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "@": "a", "$": "s"}
_FOLD_EXTRA = {"ß": "ss", "æ": "ae", "Æ": "AE", "œ": "oe", "Œ": "OE", "ø": "o", "Ø": "O", "đ": "d",
               "Đ": "D", "ł": "l", "Ł": "L", "ı": "i", "þ": "th", "Þ": "TH"}

AXES = ("case", "diacritics", "spaces", "leet", "wrap")   # the order transforms apply in, and tie order
WEIGHTS = {
    "case:restored": 0.9, "case:lower": 0.5, "case:title": 0.4, "case:upper": 0.3,
    "diacritics:ascii": 0.5,
    "spaces:underscores": 0.6, "spaces:spaces": 0.25,
    "leet:literal": 0.3, "leet:leet": 0.25,
    "wrap:plain": 0.35, "wrap:prefix": 0.15,
}
MAX_AXES = 3                 # a variant combines at most this many alternatives
DEFAULT_MAX_VARIANTS = 12    # variants after the primary
MAX_OTHER_PREFIXES = 3       # wrap:prefix alternatives (the event's other prefixes)
REF_LIMIT = 1 << 20          # bytes of a case reference text that are read

_PREFIX = re.compile(_flagfmt.UNKNOWN_PREFIX)      # a wrapper's word prefix: flagfmt's any-prefix form
_TOKEN = re.compile(r"[A-Za-z0-9@$]+")
_WORD_SEP = re.compile(r"([_\-\s]+)")


class FlagCheckError(ValueError):
    """A bad argument to the check: an unknown source name, a value that is not a string."""


@dataclass(frozen=True)
class Finding:
    code: str
    level: str          # info | warn | block
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "level": self.level, "message": self.message}


@dataclass(frozen=True)
class Check:
    value: str                          # as given
    primary: str                        # the value with the safe fixes applied
    verdict: str                        # ok | warn | block
    findings: tuple[Finding, ...]
    in_format: bool                     # primary is in the event's flag format
    source: str | None = None

    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    def level_of(self, code: str) -> str | None:
        return next((f.level for f in self.findings if f.code == code), None)

    @property
    def refuses(self) -> bool:
        """True when a finding means the value can never be a flag (nothing should be sent)."""
        return bool(self.codes() & REFUSE_CODES)

    def to_dict(self) -> dict:
        return {"value": self.value, "primary": self.primary, "verdict": self.verdict,
                "in_format": self.in_format, "source": self.source,
                "findings": [f.to_dict() for f in self.findings]}


# Findings that make a send pointless whatever the flag format says: the CLI submit path refuses them.
REFUSE_CODES = frozenset({"empty", "empty_body", "control_chars"})


@dataclass(frozen=True)
class Variant:
    rank: int
    value: str
    score: float
    changes: tuple[str, ...]            # ("spaces:underscores", "leet:literal"); () for the primary
    in_format: bool

    def to_dict(self) -> dict:
        return {"rank": self.rank, "value": self.value, "score": round(self.score, 4),
                "changes": list(self.changes), "in_format": self.in_format}


@dataclass(frozen=True)
class VariantSet:
    check: Check
    ranked: tuple[Variant, ...]         # rank 0 is the primary

    @property
    def primary(self) -> str:
        return self.check.primary

    def sendable(self, allow_nonstandard: bool = False) -> list[Variant]:
        """The ranked variants (after the primary) a gate would take: in format, unless nonstandard."""
        return [v for v in self.ranked[1:] if allow_nonstandard or v.in_format]

    def plan(self, guesses_left: int, allow_nonstandard: bool = False) -> tuple[list[Variant], list[Variant]]:
        """(to send, held): the primary and at most `guesses_left` sendable variants, in rank order;
        held is every other sendable variant, in rank order."""
        if isinstance(guesses_left, bool) or not isinstance(guesses_left, int) or guesses_left < 0:
            raise FlagCheckError(f"guesses_left must be an integer >= 0, got {guesses_left!r}")
        rest = self.sendable(allow_nonstandard)
        return [self.ranked[0], *rest[:guesses_left]], rest[guesses_left:]

    def to_dict(self) -> dict:
        return {"check": self.check.to_dict(), "ranked": [v.to_dict() for v in self.ranked]}


# ------------------------------------------------------------------------------------- helpers

def split(value: str) -> tuple[str | None, str]:
    """(prefix, body) of `PREFIX{body}`, else (None, value)."""
    i = value.find("{")
    if i > 0 and value.endswith("}") and _PREFIX.fullmatch(value[:i]):
        return value[:i], value[i + 1:-1]
    return None, value


def _letters(s: str) -> list[str]:
    return [c for c in s if c.isalpha()]


def has_leet(body: str) -> bool:
    """A token (letters, digits, @ and $) that holds at least one letter and one leet character."""
    for tok in _TOKEN.findall(body):
        if any(c.isalpha() for c in tok) and any(c in DELEET for c in tok):
            return True
    return False


def deleet(body: str) -> str:
    """Leet characters back to letters, inside tokens that hold a letter (`2026` is left alone).
    A token whose letters are all upper case gets upper-case letters back."""
    def tok(m: re.Match) -> str:
        t = m.group(0)
        if not any(c.isalpha() for c in t):
            return t
        up = all(c.isupper() for c in _letters(t))
        return "".join((DELEET[c].upper() if up else DELEET[c]) if c in DELEET else c for c in t)
    return _TOKEN.sub(tok, body)


def leetify(body: str) -> str:
    return "".join(LEET.get(c.lower(), c) for c in body)


def ascii_fold(s: str) -> str:
    out = []
    for ch in s:
        if ch in _FOLD_EXTRA:
            out.append(_FOLD_EXTRA[ch])
            continue
        out.append("".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)))
    return "".join(out)


def _title_words(body: str) -> str:
    return "".join(p if _WORD_SEP.fullmatch(p) else p[:1].upper() + p[1:].lower()
                   for p in _WORD_SEP.split(body) if p)


def _lower1(c: str) -> str:
    """`c` lower-cased, or `c` itself when lower-casing is not one character (İ -> i̇ is two)."""
    low = c.lower()
    return low if len(low) == 1 else c


def _key(s: str) -> str:
    """Case- and leet-blind comparison form; exactly one character per character, so offsets in
    the key are offsets in `s` (str.lower() alone is not length-preserving)."""
    return "".join(_lower1(DELEET.get(c, c)) for c in s)


def _case_like(b: str, r: str) -> str:
    """Letter `b` in the case of letter `r`; `b` itself when that case of `b` is not one character."""
    out = b.upper() if r.isupper() else b.lower()
    return out if len(out) == 1 else b


def _copy_case(body: str, ref: str) -> str:
    """`body` with the letter case of `ref`, position by position. Raises ValueError when the two
    differ in length: a slip in the match offsets must never truncate or shift the value."""
    if len(body) != len(ref):
        raise ValueError(f"case reference {ref!r} does not line up with {body!r}")
    return "".join(_case_like(b, r) if b.isalpha() and r.isalpha() else b for b, r in zip(body, ref))


def _casings(needle: str, ref: str) -> list[str]:
    """Distinct spellings in `ref` of `needle` (compared case- and leet-blind, as a whole word)."""
    kn, kr = _key(needle), _key(ref)
    if not kn:
        return []
    rx = re.compile(r"(?<![^\W_])" + re.escape(kn) + r"(?![^\W_])")
    return list(dict.fromkeys(ref[m.start():m.end()] for m in rx.finditer(kr)))


def restore_case(body: str, ref: str) -> str | None:
    """`body` with the letter case of its spelling in `ref` (a case-keeping copy: the challenge
    text, a known phrase). The whole body is looked up first, then each word between separators.
    A spelling found in two different casings is ambiguous and left alone. None when nothing in
    `ref` gives the body a different case. Words run together (ENIGMAISFUN) are matched only as a
    whole: they cannot be split mechanically."""
    if not ref or not _letters(body):
        return None
    whole = _casings(body, ref)
    if len(whole) == 1:
        out = _copy_case(body, whole[0])
        return out if out != body else None
    if len(whole) > 1:
        return None
    parts = _WORD_SEP.split(body)
    changed = False
    for i, p in enumerate(parts):
        if not p or _WORD_SEP.fullmatch(p) or not _letters(p):
            continue
        found = _casings(p, ref)
        if len(found) == 1:
            new = _copy_case(p, found[0])
            changed |= new != p
            parts[i] = new
    out = "".join(parts)
    return out if changed and out != body else None


def _decoy_hit(body: str) -> str | None:
    norm = re.sub(r"[^a-z0-9]+", "_", deleet(ascii_fold(body)).lower()).strip("_")
    for w in DECOY_WORDS:
        if re.search(rf"(?:^|_){w}(?:_|$)", norm):
            return w
    for p in DECOY_PHRASES:
        # whole words, and the phrase's own words may run together (nicetry, n0tth3fl4g); a phrase
        # inside a longer word is not one (i_cannot_realize_it is not "not_real")
        if re.search(r"(?:^|_)" + "_?".join(p.split("_")) + r"(?:_|$)", norm):
            return p
    return None


def _control_chars(s: str) -> list[int]:
    return [i for i, c in enumerate(s) if unicodedata.category(c) in ("Cc", "Cf", "Co", "Cn", "Zl", "Zp")]


def _source(source: str | None) -> str | None:
    if source is None:
        return None
    if not isinstance(source, str) or not source.strip():
        raise FlagCheckError("source must be a non-empty name, or None when it is not known")
    s = source.strip().lower()
    if s not in SOURCES:
        raise FlagCheckError(f"unknown source {source!r}: one of {', '.join(sorted(SOURCES))}")
    return s


def _profile(profile: _event.EventProfile | None) -> _event.EventProfile:
    return _event.current() if profile is None else profile


# ------------------------------------------------------------------------------------- the check

def check(value: str, profile: _event.EventProfile | None = None, *, source: str | None = None,
          others: Iterable[str] = (), local_checks: Iterable[str] = (), case_lossy: bool = False,
          case_ref: str | None = None, allow_nonstandard: bool = False) -> Check:
    """The plausibility findings for one candidate `value` under the event's flag format.

    source        how the value was found (a SOURCES name), or None when not known
    others        other values found in the same material (a second flag-format value: decoys)
    local_checks  local checks the value passed (padding, MAC, JSON...): named in a decoy warning
    case_lossy    the value went through a case-losing step (also implied by a CASE_LOSSY source)
    case_ref      a case-keeping text to restore the case from (the challenge text, a source file)
    """
    if not isinstance(value, str):
        raise FlagCheckError(f"value must be a string, not {type(value).__name__}")
    profile = _profile(profile)
    src = _source(source)
    ff = _flagfmt.for_profile(profile)
    spec = profile.flag
    out: list[Finding] = []

    def add(code: str, level: str, message: str) -> None:
        out.append(Finding(code, level, message))

    v = value
    if v != v.strip():
        add("whitespace_edge", "warn", "leading or trailing whitespace; the primary is stripped")
        v = v.strip()
    if not v:
        add("empty", "block", "the value is empty")
        return _done(value, v, out, False, src)
    bad = _control_chars(v)
    if bad:
        add("control_chars", "block", f"{len(bad)} control or non-printable character(s) (first at "
            f"offset {bad[0]}): decoder noise, never a flag")
    prefix, body = split(v)
    if prefix is not None and body != body.strip():
        add("edge_space", "warn", "whitespace just inside the braces; the primary has it removed")
        body = body.strip()
    inner = split(body)[0] if prefix is not None else None
    if inner is not None and inner.lower() == prefix.lower():
        add("double_wrap", "warn", f"wrapped twice ({prefix}{{{prefix}{{...}}}}); the primary is wrapped once")
        body = split(body)[1]
    if prefix is None:
        if spec.known:
            add("unwrapped", "warn", f"no {spec.prefixes[0]}{{...}} wrapper; the primary is wrapped as "
                f"{spec.prefixes[0]}{{...}} and the plain value is a variant")
            prefix = spec.prefixes[0]
        else:
            add("format_unknown", "info", "the event's flag format is not known yet: the value cannot "
                "be checked against it")
    elif spec.known and prefix.lower() not in {p.lower() for p in spec.prefixes}:
        add("foreign_prefix", "warn", f"prefix {prefix!r} is not this event's ({', '.join(spec.prefixes)}); "
            f"the primary is rewrapped as {spec.prefixes[0]}{{...}}")
        prefix = spec.prefixes[0]
    elif spec.known and spec.case == "exact" and prefix not in spec.prefixes:
        right = next(p for p in spec.prefixes if p.lower() == prefix.lower())
        add("prefix_case", "info", f"prefix {prefix!r} is spelled {right!r} in this event's format; "
            "the primary uses that spelling")
        prefix = right
    elif not spec.known:
        add("format_unknown", "info", "the event's flag format is not known yet: the prefix is not checked")
    if prefix is not None and not body:
        add("empty_body", "block", "the braces are empty")
    primary = f"{prefix}{{{body}}}" if prefix is not None else body
    in_format = ff.is_flag(primary)
    # Case restoration first: under a case-losing source the reference's spelling becomes the
    # primary, and the format finding below must judge that primary, not the one it replaced.
    lossy = case_lossy or src in CASE_LOSSY_SOURCES
    restored = restore_case(body, case_ref) if case_ref else None
    case_msg = None
    if lossy:
        why = CASE_LOSSY_SOURCES.get(src, "the value went through a case-losing step")
        case_msg = (f"{why}: the body's letter case is not evidence. Restore it from a case-keeping "
                    "copy (the challenge text, a known phrase, the source) with --case-ref; words run "
                    "together cannot be split mechanically")
        if restored is not None:
            new = f"{prefix}{{{restored}}}" if prefix is not None else restored
            if ff.is_flag(new) or not in_format:
                case_msg += f". The primary takes the reference's case: {new}"
                body, primary, in_format = restored, new, ff.is_flag(new)
            else:
                case_msg += f". The reference spells it {new}, which is outside the flag format: not used"
    if not in_format:
        if allow_nonstandard:
            add("nonstandard", "info", "not in the event's flag format; sent only as a brief-defined answer")
        else:
            add("not_in_format", "block", f"not in the event's flag format (pattern {ff.pattern}) even "
                "after the fixes: the submit gate refuses it")
    if prefix is not None and body and _sweep_placeholder(primary):
        add("placeholder", "warn", "the body is a placeholder or template value (example, flag, xxx...)")
    elif body and len(body) < 3:
        add("short_body", "warn", f"the body is only {len(body)} character(s)")
    hit = _decoy_hit(body)
    if hit:
        add("decoy_marker", "warn", f"the body reads as a decoy ({hit!r}, after undoing leet): authors "
            "plant these; solve the intended path before sending it")
    passed = [c.strip() for c in local_checks if str(c).strip()]
    if src in STATIC_SOURCES:
        msg = (f"found by {STATIC_SOURCES[src]}, a static shortcut: authors plant decoys there. Do not "
               "record it as solved until the platform accepts it; if it is rejected, solve the "
               "intended path instead of varying it")
        if passed:
            msg += (f". Passing local checks ({', '.join(passed)}) does not rule out a decoy: only the "
                    "judge tells them apart")
        add("static_source", "warn", msg)
    distinct = []
    seen = {_cmp(value, ff), _cmp(primary, ff)}
    for o in others:
        o = str(o).strip()
        if o and _cmp(o, ff) not in seen and ff.is_flag(o):
            seen.add(_cmp(o, ff))
            distinct.append(o)
    if distinct:
        add("other_flags", "warn", f"{len(distinct)} other flag-format value(s) in the same material: "
            "decoys are likely; prefer the one the intended solve produces")
    letters = _letters(body)
    if case_msg is not None:
        add("case_lost", "warn", case_msg)
    else:
        if restored is not None:
            add("case_ref", "info", f"the reference spells it {restored!r}; offered as a variant")
        if len(letters) >= 6 and all(c.isupper() for c in letters):
            add("all_upper", "info", "the body is all upper case: if it came through a case-losing "
                "channel, pass its source or --case-lossy to get case variants")
    if " " in body:
        add("spaces", "warn", "spaces in the body; platforms usually want underscores (offered as a variant)")
    if any(ord(c) > 127 and c.isalpha() for c in body):
        add("diacritics", "info", "accented or non-ASCII letters; the ASCII spelling is offered as a variant")
    if has_leet(body):
        add("leet", "info", "leet spelling; the literal spelling is offered as a variant")
    return _done(value, primary, out, in_format, src)


def _cmp(s: str, ff: _flagfmt.FlagFormat) -> str:
    s = s.strip()
    try:
        return ff.normalize(s)
    except ValueError:
        return s


def _done(value: str, primary: str, out: list[Finding], in_format: bool, src: str | None) -> Check:
    levels = {f.level for f in out}
    verdict = "block" if "block" in levels else "warn" if "warn" in levels else "ok"
    return Check(value=value, primary=primary, verdict=verdict, findings=tuple(out),
                 in_format=in_format, source=src)


# ------------------------------------------------------------------------------------- variants

def _alternatives(prefix: str | None, body: str, profile: _event.EventProfile,
                  lossy: bool, restored: str | None) -> dict[str, list[tuple[str, Callable]]]:
    """axis -> [(label, transform(prefix, body) -> (prefix, body))] for the alternatives that apply."""
    alts: dict[str, list[tuple[str, Callable]]] = {a: [] for a in AXES}
    if lossy or restored is not None:
        if restored is not None and restored != body:
            alts["case"].append(("case:restored", lambda p, b, r=restored: (p, r)))
        for label, fn in (("case:lower", str.lower), ("case:title", _title_words), ("case:upper", str.upper)):
            if fn(body) != body:
                alts["case"].append((label, lambda p, b, fn=fn: (p, fn(b))))
    if ascii_fold(body) != body:
        alts["diacritics"].append(("diacritics:ascii", lambda p, b: (p, ascii_fold(b))))
    if re.search(r"\s", body):
        alts["spaces"].append(("spaces:underscores", lambda p, b: (p, re.sub(r"\s+", "_", b))))
    elif "_" in body:
        alts["spaces"].append(("spaces:spaces", lambda p, b: (p, b.replace("_", " "))))
    if has_leet(body):
        alts["leet"].append(("leet:literal", lambda p, b: (p, deleet(b))))
    elif leetify(body) != body:
        alts["leet"].append(("leet:leet", lambda p, b: (p, leetify(b))))
    if prefix is not None:
        alts["wrap"].append(("wrap:plain", lambda p, b: (None, b)))
        others = [x for x in profile.flag.prefixes if x.lower() != prefix.lower()][:MAX_OTHER_PREFIXES]
        for x in others:
            alts["wrap"].append((f"wrap:{x}", lambda p, b, x=x: (x, b)))
    return alts


def _weight(label: str) -> float:
    return WEIGHTS.get(label, WEIGHTS["wrap:prefix"] if label.startswith("wrap:") else 0.0)


def variants(value: str, profile: _event.EventProfile | None = None, *, source: str | None = None,
             others: Iterable[str] = (), local_checks: Iterable[str] = (), case_lossy: bool = False,
             case_ref: str | None = None, allow_nonstandard: bool = False,
             max_variants: int = DEFAULT_MAX_VARIANTS) -> VariantSet:
    """The one ranked variant set of `value`: the checked primary first, then variants by score
    until `max_variants` sendable ones (in the flag format, or any under allow_nonstandard) are
    listed; an out-of-format variant ranked above the last of them is listed too, marked so.
    Raises FlagCheckError when the check blocks the value for a reason a variant cannot fix
    (empty, control characters)."""
    if isinstance(max_variants, bool) or not isinstance(max_variants, int) or max_variants < 0:
        raise FlagCheckError(f"max_variants must be an integer >= 0, got {max_variants!r}")
    profile = _profile(profile)
    chk = check(value, profile, source=source, others=others, local_checks=local_checks,
                case_lossy=case_lossy, case_ref=case_ref, allow_nonstandard=allow_nonstandard)
    if chk.refuses:
        why = "; ".join(f.message for f in chk.findings if f.code in REFUSE_CODES)
        raise FlagCheckError(f"no variants: {why}")
    ff = _flagfmt.for_profile(profile)
    prefix, body = split(chk.primary)
    lossy = case_lossy or chk.source in CASE_LOSSY_SOURCES
    # The case restored from a reference is a variant unless check() already made it the primary.
    restored = restore_case(body, case_ref) if case_ref else None
    alts = _alternatives(prefix, body, profile, lossy, restored)
    best: dict[str, tuple[float, tuple[str, ...]]] = {}
    axes = [a for a in AXES if alts[a]]
    for n in range(1, min(MAX_AXES, len(axes)) + 1):
        for combo in itertools.combinations(axes, n):
            for picks in itertools.product(*(alts[a] for a in combo)):
                p, b = prefix, body
                score = 1.0
                for label, fn in picks:      # combo follows AXES, so transforms apply in AXES order
                    p, b = fn(p, b)
                    score *= _weight(label)
                v = f"{p}{{{b}}}" if p is not None else b
                if v == chk.primary or not b:
                    continue
                labels = tuple(label for label, _ in picks)
                old = best.get(v)
                if old is None or (score, -len(labels)) > (old[0], -len(old[1])):
                    best[v] = (score, labels)
    order = {a: i for i, a in enumerate(AXES)}
    ranked = sorted(best.items(), key=lambda kv: (-kv[1][0], len(kv[1][1]),
                                                   [order[c.split(":")[0]] for c in kv[1][1]], kv[0]))
    out = [Variant(0, chk.primary, 1.0, (), chk.in_format)]
    sendable = 0
    for v, (score, labels) in ranked:
        if sendable >= max_variants:
            break
        var = Variant(len(out), v, score, labels, ff.is_flag(v))
        out.append(var)
        sendable += allow_nonstandard or var.in_format
    return VariantSet(check=chk, ranked=tuple(out))


# ------------------------------------------------------------------------------------- consuming

@dataclass
class TryReport:
    challenge_id: str
    outcome: str = "exhausted"          # accepted | exhausted | capped | stopped | refused
    reason: str = ""
    sent: int = 0
    guesses: int = 0                    # judged guess sends made by this run
    results: list[tuple[int, str, str]] = field(default_factory=list)   # (rank, value, status)
    skipped: list[tuple[int, str, str]] = field(default_factory=list)   # (rank, value, why), never sent
    held: list[str] = field(default_factory=list)   # sendable variants past the budget, rank order
    accepted: str | None = None
    check: Check | None = None

    def to_dict(self) -> dict:
        return {"challenge_id": self.challenge_id, "outcome": self.outcome, "reason": self.reason,
                "sent": self.sent, "guesses": self.guesses,
                "results": [list(r) for r in self.results], "skipped": [list(s) for s in self.skipped],
                "held": list(self.held), "accepted": self.accepted,
                "check": self.check.to_dict() if self.check else None}


def guesses_left(profile: _event.EventProfile, challenge_id: str, workdir: Path | None = None) -> int:
    """rules.guess_budget less the judged guesses the challenge has used (never below 0)."""
    from .platform.rules import EventRules       # local: ctf.platform imports would cycle at import time
    used = EventRules(profile, workdir).guesses_used(str(challenge_id))
    return max(0, profile.rules.guess_budget - used)


def try_variants(gate: Any, challenge_id: str, value: str, *, note: str, source: str | None = None,
                 others: Iterable[str] = (), local_checks: Iterable[str] = (), case_lossy: bool = False,
                 case_ref: str | None = None, confirmed: bool = False, allow_nonstandard: bool = False,
                 max_variants: int = DEFAULT_MAX_VARIANTS, workdir: Path | None = None) -> TryReport:
    """Send the ranked set of `value` through `gate` (a SubmitGate: its checks and queue apply to
    every send) in rank order: the primary as the reasoned value, then variants as guesses within
    the challenge's remaining guess budget. See the module docstring for where it stops."""
    from .platform.base import SubmitStatus
    if not note or not str(note).strip():
        raise FlagCheckError("a variant run needs a note: how the value was derived (it is the "
                             "provenance of every send)")
    profile = gate.profile
    cid = str(challenge_id)
    rep = TryReport(challenge_id=cid)
    try:
        vs = variants(value, profile, source=source, others=others, local_checks=local_checks,
                      case_lossy=case_lossy, case_ref=case_ref, allow_nonstandard=allow_nonstandard,
                      max_variants=max_variants)
    except FlagCheckError as e:
        rep.check = check(value, profile, source=source, allow_nonstandard=allow_nonstandard)
        rep.outcome, rep.reason = "refused", str(e)
        return rep
    rep.check = vs.check
    if vs.check.level_of("not_in_format") == "block":
        rep.outcome, rep.reason = "refused", next(f.message for f in vs.check.findings
                                                 if f.code == "not_in_format")
        return rep
    left = guesses_left(profile, cid, workdir)
    rest = vs.sendable(allow_nonstandard)
    for v in vs.ranked[1:]:
        if not (allow_nonstandard or v.in_format):
            rep.skipped.append((v.rank, v.value, "not in the event's flag format"))
    queue = [vs.ranked[0], *rest]
    for i, v in enumerate(queue):
        is_guess = v.rank > 0
        if is_guess and rep.guesses >= left:
            rep.held = [x.value for x in queue[i:]]
            rep.outcome = "capped"
            rep.reason = (f"guess budget reached ({profile.rules.guess_budget} per challenge, "
                          f"{left} left at the start of this run); {len(rep.held)} variant(s) held for the "
                          "player: a sweep authorization (`ctf policy authorize-sweep`) can run them")
            return rep
        what = ", ".join(v.changes) if v.changes else "as derived"
        res = gate.submit(cid, v.value, provenance=f"{str(note).strip()} [variant {v.rank}: {what}]",
                          confirmed=confirmed, allow_nonstandard=allow_nonstandard, guess=is_guess)
        if res.sent:
            rep.sent += 1
        rep.results.append((v.rank, v.value, res.status.value))
        if res.accepted:
            rep.outcome, rep.accepted, rep.reason = "accepted", v.value, res.message
            return rep
        if res.status is SubmitStatus.NOT_ALLOWED and not res.sent:
            if res.message.startswith("duplicate"):
                rep.skipped.append((v.rank, v.value, "already judged"))
                continue
            rep.held = [x.value for x in queue[i:] if x.rank > 0]      # the refused one was not sent
            rep.outcome, rep.reason = "stopped", res.message
            return rep
        if not res.status.judged:
            rep.held = [x.value for x in queue[i + 1:] if x.rank > 0]
            rep.outcome, rep.reason = "stopped", f"unjudged ({res.status.value}): {res.message}"
            return rep
        if is_guess:
            rep.guesses += 1
    rep.reason = "every sendable variant was tried"
    return rep
