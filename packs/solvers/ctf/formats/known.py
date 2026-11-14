"""The known-format fingerprint DB (B-087): composite fingerprints that name a format and its public reference.

    from ctf.formats import known
    table = known.load()                         # tuple[Known] from ctf/formats/known.toml (KnownError if bad)
    leads = known.lookup(fp, data, table)        # [fingerprint.Candidate(source="known", ...)] best first
    known.match(entry, fp, data)                 # the reasons an entry matches, or None

`ctf.formats.fingerprint` (B-207) measures a member no reader names: magic strings, header fields, the
record stride, the entropy profile, a string table. Its local magic table then names a format from one
fixed signature. This module is the next lookup, built on the same `Fingerprint`: an entry combines
several signals -- signatures at fixed offsets (counted from the end when negative), an ascii token in
the header window, the base name the format is stored under, a record geometry (size == header +
N x record + trailer) and an entropy floor -- and names the format and the public reference that
documents its layout. `fingerprint.analyze` calls `lookup` after the magic table, so the B-013 sweep
and `ctf formats fingerprint` report the lead with no further wiring.

Never-wrong rules, enforced by the loader:

  * a base name or an entropy floor never carries an entry alone (an extension is a hint, and every
    ciphertext is high-entropy): an entry requires a content signal (magic, ascii or geometry);
  * a geometry alone is a 1-in-`record` coincidence, so an entry whose only required content signal is
    a geometry must also demand a supporting signal (min_support >= 1);
  * every declared signal is used: `require` and `support` list each one exactly once.

A lead is UNSURE evidence, a pointer for a human or an agent. The table holds no keys, no key
derivation and no decryption steps: it says what the bytes most likely are and where the layout is
documented, and working from that reference stays a per-challenge step.
"""
from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .fingerprint import MIN_STRING_LEN, Candidate, Fingerprint

__all__ = ["KnownError", "Known", "Sig", "Geometry", "KNOWN_TABLE", "SIGNALS", "CONTENT_SIGNALS",
           "load", "match", "lookup"]

KNOWN_TABLE = Path(__file__).with_name("known.toml")

SIGNALS = ("magic", "ascii", "names", "geometry", "entropy")
CONTENT_SIGNALS = ("magic", "ascii", "geometry")     # what the bytes themselves say
BASE_SCORE = 70                                      # above any single magic-table hit of the same member
SIGNAL_SCORE = 6                                     # each signal that held
MAX_SCORE = 96

_KEYS = {"id", "label", "family", "reference", "basis", "note", "names", "ascii", "entropy_min", "magic",
         "geometry", "require", "support", "min_support"}
_REQUIRED = ("id", "label", "reference", "basis")
_MAGIC_KEYS = {"at", "hex"}
_GEOMETRY_KEYS = {"header", "record", "trailer", "min_records"}
_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class KnownError(ValueError):
    """The known-format table cannot be used: the message names the file, the entry and the key."""


@dataclass(frozen=True)
class Sig:
    at: int            # byte offset; negative counts from the end of the member
    sig: bytes


@dataclass(frozen=True)
class Geometry:
    header: int
    record: int
    trailer: int
    min_records: int = 1


@dataclass(frozen=True)
class Known:
    id: str
    label: str
    reference: str
    basis: str
    require: tuple[str, ...]
    support: tuple[str, ...] = ()
    min_support: int = 0
    family: str = ""
    note: str = ""
    magic: tuple[Sig, ...] = ()
    ascii: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    geometry: Geometry | None = None
    entropy_min: float | None = None

    @property
    def signals(self) -> tuple[str, ...]:
        """The signals this entry declares, in SIGNALS order."""
        have = {"magic": bool(self.magic), "ascii": bool(self.ascii), "names": bool(self.names),
                "geometry": self.geometry is not None, "entropy": self.entropy_min is not None}
        return tuple(s for s in SIGNALS if have[s])


# ------------------------------------------------------------------ the loader

def _int(where: str, key: str, value, low: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise KnownError(f"{where}: {key} must be an integer")
    if low is not None and value < low:
        raise KnownError(f"{where}: {key} must be >= {low}")
    return value


def _strings(where: str, key: str, value, minlen: int = 1) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise KnownError(f"{where}: {key} must be a non-empty list of strings")
    out = tuple(v.strip() for v in value)
    if any(len(v) < minlen for v in out):
        raise KnownError(f"{where}: every {key} entry needs at least {minlen} character(s)")
    if len(set(out)) != len(out):
        raise KnownError(f"{where}: {key} lists an entry twice")
    return out


def _magic(where: str, value) -> tuple[Sig, ...]:
    if not isinstance(value, list) or not value:
        raise KnownError(f"{where}: magic must be a non-empty list of {{ at, hex }} tables")
    out = []
    for i, m in enumerate(value):
        w = f"{where}: magic[{i}]"
        if not isinstance(m, dict):
            raise KnownError(f"{w}: not a table")
        if set(m) - _MAGIC_KEYS:
            raise KnownError(f"{w}: unknown keys {sorted(set(m) - _MAGIC_KEYS)}")
        if "hex" not in m:
            raise KnownError(f"{w}: missing 'hex'")
        h = m["hex"]
        if not isinstance(h, str) or not h or len(h) % 2 or any(c not in "0123456789abcdefABCDEF" for c in h):
            raise KnownError(f"{w}: hex {h!r} is not an even-length hex string")
        raw = bytes.fromhex(h)
        if not 1 <= len(raw) <= 16:
            raise KnownError(f"{w}: hex is {len(raw)} bytes; must be 1..16")
        at = _int(w, "at", m.get("at", 0))
        if at < 0 and -at < len(raw):
            raise KnownError(f"{w}: at {at} leaves no room for {len(raw)} bytes before the end")
        out.append(Sig(at, raw))
    return tuple(out)


def _geometry(where: str, value) -> Geometry:
    w = f"{where}: geometry"
    if not isinstance(value, dict):
        raise KnownError(f"{w}: must be a table {{ header, record, trailer }}")
    if set(value) - _GEOMETRY_KEYS:
        raise KnownError(f"{w}: unknown keys {sorted(set(value) - _GEOMETRY_KEYS)}")
    if "record" not in value:
        raise KnownError(f"{w}: missing 'record'")
    record = _int(w, "record", value["record"], 2)      # a 1-byte record matches every size
    return Geometry(_int(w, "header", value.get("header", 0), 0), record,
                    _int(w, "trailer", value.get("trailer", 0), 0),
                    _int(w, "min_records", value.get("min_records", 1), 1))


def _signal_list(where: str, key: str, value, declared: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise KnownError(f"{where}: {key} must be a list of signal names")
    if len(set(value)) != len(value):
        raise KnownError(f"{where}: {key} lists a signal twice")
    for v in value:
        if v not in SIGNALS:
            raise KnownError(f"{where}: {key} names {v!r}; signals are {', '.join(SIGNALS)}")
        if v not in declared:
            raise KnownError(f"{where}: {key} names {v!r} but the entry declares no such signal")
    return tuple(value)


def _entry(where: str, m: dict) -> Known:
    if set(m) - _KEYS:
        raise KnownError(f"{where}: unknown keys {sorted(set(m) - _KEYS)}")
    for k in _REQUIRED:
        if k not in m:
            raise KnownError(f"{where}: missing {k!r}")
        if not isinstance(m[k], str) or not m[k].strip():
            raise KnownError(f"{where}: {k} must be a non-empty string")
    if not _ID.match(m["id"]):
        raise KnownError(f"{where}: id must be a lower-case slug ([a-z0-9][a-z0-9_.-]*)")
    for k in ("family", "note"):
        if k in m and not isinstance(m[k], str):
            raise KnownError(f"{where}: {k} must be a string")

    magic = _magic(where, m["magic"]) if "magic" in m else ()
    ascii_ = _strings(where, "ascii", m["ascii"], MIN_STRING_LEN) if "ascii" in m else ()
    if any(not all(32 <= ord(c) < 127 for c in t) for t in ascii_):
        raise KnownError(f"{where}: ascii tokens must be printable ascii")
    names = _strings(where, "names", m["names"]) if "names" in m else ()
    geometry = _geometry(where, m["geometry"]) if "geometry" in m else None
    entropy_min = None
    if "entropy_min" in m:
        e = m["entropy_min"]
        if isinstance(e, bool) or not isinstance(e, (int, float)) or not 0 < e <= 8:
            raise KnownError(f"{where}: entropy_min must be a number in (0, 8] bits per byte")
        entropy_min = float(e)

    probe = Known(id=m["id"], label="", reference="", basis="", require=(), magic=magic, ascii=ascii_,
                  names=names, geometry=geometry, entropy_min=entropy_min)
    declared = probe.signals
    if not declared:
        raise KnownError(f"{where}: declares no signal ({', '.join(SIGNALS)})")
    if "require" not in m and "support" not in m:
        require, support = declared, ()
    else:
        require = _signal_list(where, "require", m.get("require", []), declared)
        support = _signal_list(where, "support", m.get("support", []), declared)
        both = set(require) & set(support)
        if both:
            raise KnownError(f"{where}: {sorted(both)} listed in both require and support")
        unused = [s for s in declared if s not in require and s not in support]
        if unused:
            raise KnownError(f"{where}: declared signal(s) {unused} are in neither require nor support")
    min_support = _int(where, "min_support", m.get("min_support", 0), 0)
    if min_support > len(support):
        raise KnownError(f"{where}: min_support {min_support} exceeds the {len(support)} support signal(s)")

    content = [s for s in require if s in CONTENT_SIGNALS]
    if not content:
        raise KnownError(f"{where}: require must hold a content signal ({', '.join(CONTENT_SIGNALS)}); "
                         "a name or an entropy floor never names a format alone")
    if content == ["geometry"] and min_support < 1:
        raise KnownError(f"{where}: a geometry is a 1-in-{geometry.record} coincidence; with no other "
                         "required content signal the entry needs min_support >= 1")
    return Known(id=m["id"], label=m["label"].strip(), reference=m["reference"].strip(),
                 basis=m["basis"].strip(), require=tuple(s for s in SIGNALS if s in require),
                 support=tuple(s for s in SIGNALS if s in support), min_support=min_support,
                 family=m.get("family", "").strip(), note=m.get("note", "").strip(), magic=magic,
                 ascii=ascii_, names=names, geometry=geometry, entropy_min=entropy_min)


def load(path: Path | str | None = None) -> tuple[Known, ...]:
    """The known-format table in file order. Every key is checked; a bad entry is a KnownError naming it,
    never an entry quietly dropped. A missing file is a KnownError too (no silent empty table)."""
    path = Path(path) if path is not None else KNOWN_TABLE
    if not path.is_file():
        raise KnownError(f"{path}: the known-format table is not there")
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise KnownError(f"{path}: not TOML ({e})") from None
    if set(doc) != {"format"} or not isinstance(doc["format"], list) or not doc["format"]:
        raise KnownError(f"{path}: the table is a non-empty list of [[format]] entries and nothing else")
    out, ids = [], set()
    for i, m in enumerate(doc["format"]):
        if not isinstance(m, dict):
            raise KnownError(f"{path}: format {i + 1}: not a table")
        entry = _entry(f"{path}: format {m.get('id', i + 1)!r}", m)
        if entry.id in ids:
            raise KnownError(f"{path}: format {entry.id!r}: id listed twice")
        ids.add(entry.id)
        out.append(entry)
    return tuple(out)


# ------------------------------------------------------------------ matching

def _basename(name: str) -> str:
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _check_magic(entry: Known, fp: Fingerprint, data) -> str | None:
    parts = []
    for s in entry.magic:
        off = s.at if s.at >= 0 else fp.size + s.at
        end = off + len(s.sig)
        if off < 0 or end > len(data) or bytes(data[off:end]) != s.sig:
            return None
        parts.append(f"{s.sig.hex()} at {s.at}")
    return "magic " + ", ".join(parts)


def _check_ascii(entry: Known, fp: Fingerprint, data) -> str | None:
    for token in entry.ascii:
        if any(token in run for run in fp.magic_ascii):
            return f"header ascii {token!r}"
    return None


def _check_names(entry: Known, fp: Fingerprint, data) -> str | None:
    base = _basename(fp.name).lower()
    for glob in entry.names:
        if fnmatch.fnmatchcase(base, glob.lower()):
            return f"name matches {glob!r}"
    return None


def _check_geometry(entry: Known, fp: Fingerprint, data) -> str | None:
    g = entry.geometry
    body = fp.size - g.header - g.trailer
    if body < g.record * g.min_records or body % g.record:
        return None
    return f"size {fp.size} = {g.header} + {body // g.record} x {g.record} + {g.trailer}"


def _check_entropy(entry: Known, fp: Fingerprint, data) -> str | None:
    if fp.entropy < entry.entropy_min:
        return None
    return f"entropy {fp.entropy:.2f} >= {entry.entropy_min:g} b/byte"


_CHECKS = {"magic": _check_magic, "ascii": _check_ascii, "names": _check_names,
           "geometry": _check_geometry, "entropy": _check_entropy}


def match(entry: Known, fp: Fingerprint, data) -> tuple[str, ...] | None:
    """The reasons `entry` matches the member, one per signal that held, or None when it does not match:
    every `require` signal must hold and at least `min_support` of the `support` ones. `fp` is the
    member's B-207 Fingerprint and `data` its bytes (any buffer; read only at the entry's magic offsets)."""
    reasons = []
    for s in entry.require:
        why = _CHECKS[s](entry, fp, data)
        if why is None:
            return None
        reasons.append(why)
    held = [why for s in entry.support if (why := _CHECKS[s](entry, fp, data)) is not None]
    if len(held) < entry.min_support:
        return None
    return tuple(reasons + held)


def lookup(fp: Fingerprint, data, table) -> list[Candidate]:
    """Every entry of `table` that matches, as fingerprint Candidates (source "known"), best first: the
    score grows with the number of signals that held. `tool` is the public reference, `ref` the entry id."""
    out = []
    for entry in table:
        reasons = match(entry, fp, data)
        if reasons is None:
            continue
        why = "; ".join(reasons)
        if entry.note:
            why += f". Next: {entry.note}"
        score = min(MAX_SCORE, BASE_SCORE + SIGNAL_SCORE * len(reasons))
        out.append(Candidate("known", entry.label, why, score, tool=entry.reference, ref=entry.id))
    out.sort(key=lambda c: (-c.score, c.ref or ""))
    return out
