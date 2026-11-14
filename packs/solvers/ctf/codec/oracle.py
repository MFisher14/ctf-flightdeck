"""Goal oracles of the codec graph (B-163): what a decoded state must prove before it is an answer.

An oracle validates the FINAL object, never "looks like English": `check(data) -> list[str]` returns the
answers the state proves (empty when it proves none). The graph stops descending at a state an oracle
accepts and reports every such state, so a convenient first hit is never taken as proof of selection.

    FlagOracle(profile=None)      the event flag format (ctf.flagfmt), printable body only
    CribOracle(crib)              a literal known plaintext; the answer is the crib's text
    SlugOracle(crib=None, ...)    a slug answer (word-word-word-NN) on its own after the crib (or alone
                                  on the final line); the warmups answer shape
    Recognizer(fn, name)          a caller predicate over the whole state (a CRC-valid config, a magic
                                  plus a clean parse); the answer is what fn returns
    AnyOf(*oracles)               the union

`strong` says whether the oracle is a full validation on its own (a crib, a recognizer): a chain of
loose steps alone that reaches a strong oracle is confirmed; one that reaches only a flag shape is not.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

SLUG = r"[a-z]+(?:-[a-z]+){2}-[0-9]{2}"     # the warmups answer: three words and two digits
_PRINTABLE = frozenset(chr(c) for c in range(0x20, 0x7F))


def _text(data: bytes) -> str:
    return data.decode("latin-1")


class Oracle:
    name = "oracle"
    strong = False

    def check(self, data: bytes) -> list[str]:          # pragma: no cover - interface
        raise NotImplementedError


class FlagOracle(Oracle):
    """The event's flag format (ctf.flagfmt): distinct flags in the state whose body is printable ASCII.

    profile=None follows the active event (flagfmt.current()); without one, using it raises flagfmt's
    EventError (no silent default format)."""
    name = "flag"
    strong = False

    def __init__(self, profile=None):
        from .. import flagfmt
        self._ff = flagfmt.for_profile(profile) if profile is not None else None
        self._flagfmt = flagfmt

    def _fmt(self):
        return self._ff if self._ff is not None else self._flagfmt.current()

    def check(self, data: bytes) -> list[str]:
        out = []
        for f in self._fmt().find_flags(_text(data)):
            body = f[f.find("{") + 1:-1]
            if all(ch in _PRINTABLE for ch in body) and f not in out:
                out.append(f)
        return out


class CribOracle(Oracle):
    """A literal known plaintext. The state proves it when the crib occurs in it whole."""
    name = "crib"
    strong = True

    def __init__(self, crib):
        self.crib = crib.encode() if isinstance(crib, str) else bytes(crib)
        if not self.crib:
            raise ValueError("an empty crib proves nothing")

    def check(self, data: bytes) -> list[str]:
        return [_text(self.crib)] if self.crib in data else []


class SlugOracle(Oracle):
    """A slug answer. With a crib: the slug that follows the crib directly (white space between allowed).
    Without one: a slug alone on the state's last non-empty line. One distinct slug only: two make the state
    prove nothing (ambiguous). `pattern` overrides the slug shape (a challenge-stated answer shape)."""
    name = "slug"
    strong = True

    def __init__(self, crib=None, pattern: str = SLUG):
        self.crib = (crib.encode() if isinstance(crib, str) else bytes(crib)) if crib else None
        self.pattern = pattern
        self._slug = re.compile(pattern.encode())
        self._after = re.compile(re.escape(self.crib) + rb"\s*(" + pattern.encode() + rb")(?![A-Za-z0-9-])") \
            if self.crib else None
        self._line = re.compile(rb"\s*(" + pattern.encode() + rb")\s*")

    def check(self, data: bytes) -> list[str]:
        if self._after is not None:
            found = {m.group(1) for m in self._after.finditer(data)}
        else:
            lines = [ln for ln in data.splitlines() if ln.strip()]
            m = self._line.fullmatch(lines[-1]) if lines else None
            found = {m.group(1)} if m else set()
        return [_text(next(iter(found)))] if len(found) == 1 else []


class Recognizer(Oracle):
    """A caller predicate over the whole state: fn(data) returns the answer (str), True (the answer is the
    state, latin-1), or a falsy value. An exception from fn is the caller's bug and is raised, not hidden."""
    strong = True

    def __init__(self, fn: Callable[[bytes], object], name: str = "recognizer"):
        self.fn, self.name = fn, name

    def check(self, data: bytes) -> list[str]:
        got = self.fn(data)
        if not got:
            return []
        if got is True:
            return [_text(data)]
        if isinstance(got, (list, tuple)):
            return [str(g) for g in got]
        return [str(got)]


class AnyOf(Oracle):
    def __init__(self, *oracles: Oracle):
        if not oracles:
            raise ValueError("AnyOf needs at least one oracle")
        self.oracles = oracles
        self.name = "|".join(o.name for o in oracles)
        self.strong = all(o.strong for o in oracles)

    def check(self, data: bytes) -> list[str]:
        out: list[str] = []
        for o in self.oracles:
            for a in o.check(data):
                if a not in out:
                    out.append(a)
        return out

    def strong_for(self, data: bytes) -> bool:
        return any(o.strong and o.check(data) for o in self.oracles)


def is_strong(oracle: Oracle, data: Optional[bytes] = None) -> bool:
    if isinstance(oracle, AnyOf) and data is not None:
        return oracle.strong_for(data)
    return bool(getattr(oracle, "strong", False))
