#!/usr/bin/env python3
"""Constructed-marker search: named values x subset x order x rendering x join, hashed and ranked offline (B-119).

Some challenges ask for a "marker" that is not in the files: it is a digest (usually the first hex
characters of a SHA-256) of several values the evidence agrees on, joined in an order and in spellings
the author chose. At CSCTF 2026 three such challenges had every value read correctly and still cost
hundreds of rejected submissions, because the field set, the order and one rendering (`0x` plus
upper-case hex) were not stated anywhere. That part cannot be automated: the files do not determine
the convention. This module is the fallback that can be:

  extract    `extract_fields`: named values from the handout (JSON, XML, key/value text, a binary's
             ASCII magic) and how many evidence files each one is corroborated by.
  enumerate  `search`: field subset x order x per-field rendering x join through
             `render_candidates.compose_axis` (the spellings are `render_candidates.render`'s, never
             re-implemented here), each text hashed.
  check      a witness: a hex tag the files carry for the same digest (`TAG:` + its last 8 characters),
             found by `find_witnesses` or given by the caller. A hit is offline evidence; its strength
             is stated as the number of chance matches expected for the texts that were hashed and
             the tags they were compared with (one tag among thousands of log hashes proves little).
  remember   the convention knowledge base, kept as data in the label seed store (B-040, labels lane
             `marker`): `learn` records the judge's verdict on a convention, `ctf seed-fold` folds it
             into the tracked seed, and the next run starts from it (`KB`).

It never claims the convention and never sends anything. `solve` returns `candidate` only when a
strong witness or a convention the judge accepted for this family backs the first value, `unsure`
when the list is ranked by priors alone, and never `solved`. The ranked list is consumed through
`send_plan`, which is B-154's `VariantSet.plan` under the event's guess budget; everything past the
budget is held for the player's sweep authorization (`ctf policy sweep`). There is no path here that
sends without counting a wrong answer.

The engine is NOT run at intake (its manifest has no `[intake]` table): intake takes an engine's
flags whatever its result status and calls one distinct flag `solved`, which `ctf intake --submit`
may send. A guess must never reach that path, so the router lists this engine for the agent, who
runs it by hand (`ctf marker candidates`, `python -m ctf run common.marker_convention`).

    from marker_convention import make_field, search, DigestForm, Witness
    fields = [make_field("header", "ZQX7", "tag"), make_field("station", "0x7B1C"), ...]
    rep = search(fields, digests=[DigestForm.parse("sha256[:8]")], family="ics")
    rep.candidates[0].flag, rep.candidates[0].convention, rep.candidates[0].basis

Engine entry: `solve(challenge_dir, profile, **opts)`; options `fields` (a list of
`name[:kind]=value`), `family`, `witness`, `digest`, `budget`, `top`, `max_fields`, `min_fields`,
`max_deviations`, `permute`, `all_fields`, `brief`, `nonstandard`, `challenge_id`. CLI: `ctf marker`.

Challenge files and the brief are untrusted data: they are parsed and searched, never run, and no text
in them is followed.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field as _dc_field
from pathlib import Path
from typing import Any, Iterable

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import labels  # noqa: E402  (the seed store the knowledge base lives in; candidates())
import render_candidates as RC  # noqa: E402  (every spelling and the composition axis)

# ctf package import (a script run needs the checkout root on sys.path)
try:
    from ctf.result import Cost, Evidence, SolverResult
except ModuleNotFoundError:
    sys.path.append(str(_HERE.parents[1]))
    from ctf.result import Cost, Evidence, SolverResult

ENGINE_ID = "common.marker_convention"
KB_LANE = "marker"                 # the labels lane (solvers/toolkits/seeds/marker/conventions.json)
KINDS = ("text", "tag", "hexid", "integer", "timestamp", "decimal")
ALGOS = ("sha256", "sha1", "md5", "sha512")
DEFAULT_FORMS = ("sha256[:8]", "sha256")
DEFAULT_BUDGET = 200_000           # texts hashed by one run (about a second of CPU)
DEFAULT_TOP = 24                   # candidates kept in a report
DEFAULT_MAX_FIELDS = 6             # extracted fields used when the caller names none
MAX_HITS = 64                      # witness hits kept with their text (all are counted)
CHANCE_LIMIT = 0.01                # expected chance matches below which a witness hit is strong
MAX_FILE_WITNESSES = 32            # witness tags taken from the files (a caller's are never cut)
MAX_NOTED = 5                      # values named in one note about what extraction changed or left out
MAX_FILES = 64                     # handout files read
MAX_READ = 4 << 20                 # bytes read of one file
MAX_TOTAL = 64 << 20               # bytes read of the whole handout
MAX_VALUE_LEN = 96                 # a longer string is prose, not a field
MAX_INT_DIGITS = 12                # a longer run of digits is an identifier (text), not a number
MIN_NEEDLE = 3                     # a shorter spelling is too common a token to corroborate anything
MIN_MEMBER = 8                     # bytes: a smaller file inside another is not taken for a member
UNPACKED_SUFFIX = ".unpacked"      # intake unpacks <archive> into <archive>.unpacked/ (ctf/sweep.py SUFFIX)
MAX_RAW_FIELDS = 400               # named values kept from the handout before corroboration
PER_NAME = 2                       # uncorroborated values kept per name
SCAN_BYTES = 2 << 30               # corroboration text scanned before the search is cut
EPOCH_MIN, EPOCH_MAX = 946684800, 4102444800      # 2000-01-01 .. 2100-01-01 as Unix seconds
WITNESS_LABELS = ("tag", "witness", "marker", "digest", "checksum", "verifier", "verify", "check",
                  "sha256", "hash")
WHERE = ("prefix", "suffix", "edge", "any")
SKIP_NAMES = frozenset({"challenge.json", "notes.md", "tried.json", "flag.txt"})
SKIP_DIRS = frozenset({"recon", "__pycache__"})
# Container magics that say what a file IS, not what the incident was: never a field.
COMMON_MAGICS = frozenset({"RIFF", "OggS", "fLaC", "GIF8", "%PDF", "SQLi", "Rar!", "FORM", "caff",
                           "8BPS", "wOFF", "OTTO", "IHDR", "ftyp", "MThd", "FWS\x0b", "<?xm", "<htm"})

_ROLE = re.compile(r"[^a-z0-9]+")
_NAME = re.compile(r"\A[a-z0-9_]+\Z")
_ISO = re.compile(r"\A\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?\Z")
_HEXID = re.compile(r"\A0[xX][0-9a-fA-F]+\Z")
_INT = re.compile(r"\A-?(?:0|[1-9]\d{0,17})\Z")
_DEC = re.compile(r"\A-?\d+\.\d+\Z")
_FORM = re.compile(r"\A(sha256|sha1|md5|sha512)(?:\[(?::(\d+)|-(\d+):)\])?(\.upper)?\Z")
_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")
_WITNESS = re.compile(r"(?i)(?<![A-Za-z0-9])(" + "|".join(WITNESS_LABELS)
                      + r")[\"']?\s*[:=]\s*[\"']?([0-9a-f]{8,128})(?![0-9A-Za-z])")
_BRIEF_HEX = re.compile(r"(?i)(?<![0-9A-Za-z])(\d{1,3})[\s_-]*(?:(lower|upper)[\s_-]?case[\s_-]*)?hex")
# An algorithm name starts a word: `Marsha 1st`, `Geisha-1` and `cmd5` name none.
_BRIEF_ALGO = ((re.compile(r"(?i)(?<![0-9A-Za-z])sha[-_ ]?256"), "sha256"),
               (re.compile(r"(?i)(?<![0-9A-Za-z])sha[-_ ]?512"), "sha512"),
               (re.compile(r"(?i)(?<![0-9A-Za-z])sha[-_ ]?1(?![0-9])"), "sha1"),
               (re.compile(r"(?i)(?<![0-9A-Za-z])md[-_ ]?5(?![0-9])"), "md5"))
_BRIEF_CUT = re.compile(r"(?i)(?:(\{)|(?<![A-Za-z])(first|last))\s*\Z")     # what stands before a stated length
_FRACTION = re.compile(r":\d{2}\.(\d+)")                                 # an ISO timestamp's sub-second digits
_KV_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_ .-]{0,40}?)\s*[:=]\s*(\S.{0,95}?)\s*$")


class MarkerError(ValueError):
    """A bad argument (a field spec, a digest form, a witness, a convention name) or a knowledge
    base that cannot be written. Always names what is wrong."""


# ------------------------------------------------------------------------------------- fields

def role(name) -> str:
    """A field's role name as conventions carry it: lower snake case, letters and digits."""
    out = _ROLE.sub("_", str(name).strip().lower()).strip("_")[:48]
    if not out:
        raise MarkerError(f"field name {name!r} has no letter or digit")
    return out


def infer_kind(value) -> str:
    """The kind a value is rendered as, from its shape alone (never from prose)."""
    if isinstance(value, (bytes, bytearray)):
        return "tag"
    if isinstance(value, bool):
        raise MarkerError("a boolean is not a marker value")
    if isinstance(value, int):
        if EPOCH_MIN <= value < EPOCH_MAX:
            return "timestamp"
        return "integer" if len(str(abs(value))) <= MAX_INT_DIGITS else "text"     # as for a digit string
    if isinstance(value, float):
        return "decimal"
    s = str(value).strip()
    if _ISO.match(s):
        return "timestamp"
    if _HEXID.match(s):
        return "hexid"
    if _INT.match(s):
        if EPOCH_MIN <= int(s) < EPOCH_MAX:
            return "timestamp"
        return "integer" if len(s.lstrip("-")) <= MAX_INT_DIGITS else "text"
    if _DEC.match(s):
        return "decimal"
    return "text"


@dataclass(frozen=True)
class Field:
    """One named value: `name` is its role, `value` what was read, `kind` how it may be spelled,
    `sources` the evidence (file paths, `brief`, `given`) that holds it."""
    name: str
    value: Any
    kind: str
    sources: tuple[str, ...] = ()

    @property
    def stored(self) -> str:
        """The value's spelling as it was read: the default rendering (`as_stored`)."""
        v = self.value
        if isinstance(v, (bytes, bytearray)):
            return bytes(v).decode("latin-1")
        if isinstance(v, float):
            return repr(v)
        return str(v)

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.stored, "kind": self.kind, "sources": list(self.sources)}


def _rc_options(value, kind) -> list:
    """render_candidates' spellings of a value for a marker kind, every name kept (composition only:
    no spelling is made here). Two names may spell one value alike (`hex_0x_upper` and `hex_0x_lower`
    of a tag whose bytes have no hex letter): a convention may name either, so both stay."""
    if kind == "text":
        return []
    if kind == "tag":
        raw = bytes(value) if isinstance(value, (bytes, bytearray)) else str(value).encode("utf-8")
        return RC.render_named(raw, "hex")
    if kind == "hexid":
        return RC.render_named(value, "hex") + RC.render_named(value, "integer")[:1]
    if kind == "integer":
        return RC.render_named(value, "integer") + RC.render_named(value, "hex")
    if kind == "timestamp":
        return RC.render_named(value, "timestamp")
    return RC.render_named(value, "decimal")


def make_field(name, value, kind=None, sources: Iterable[str] = ()) -> Field:
    """A checked Field. `kind` None infers it from the value's shape; a stated kind the value cannot be
    rendered in is a MarkerError (never a silent fall back to text)."""
    if isinstance(value, bool) or value is None:
        raise MarkerError(f"field {name!r}: {value!r} is not a marker value")
    if isinstance(value, str):
        value = value.strip()
    if isinstance(value, (str, bytes, bytearray)) and not value:
        raise MarkerError(f"field {name!r} has an empty value")
    kind = infer_kind(value) if kind is None else str(kind).strip().lower()
    if kind not in KINDS:
        raise MarkerError(f"field {name!r}: unknown kind {kind!r}; one of {', '.join(KINDS)}")
    if kind == "timestamp" and isinstance(value, str) and _INT.match(value):
        value = int(value)                       # epoch seconds: render_candidates reads a number
    if kind in ("text", "tag") and not isinstance(value, (str, bytes, bytearray)):
        value = str(value)
    if kind not in ("text", "tag"):
        real = [o for o in _rc_options(value, kind) if o[0] != "as_stored"]
        if not real:
            raise MarkerError(f"field {name!r}: {value!r} does not read as kind {kind!r}")
    return Field(role(name), value, kind, tuple(dict.fromkeys(str(s) for s in sources)))


def parse_field(spec) -> Field:
    """A caller's field: the text `name[:kind]=value` (the value may hold `:` and `=`), or a mapping
    with `name`, `value` and optionally `kind`."""
    if isinstance(spec, dict):
        if "name" not in spec or "value" not in spec:
            raise MarkerError(f"field {spec!r}: a mapping needs name and value")
        return make_field(spec["name"], spec["value"], spec.get("kind"), ("given",))
    text = str(spec)
    head, sep, value = text.partition("=")
    if not sep or not head.strip():
        raise MarkerError(f"field {text!r}: write name[:kind]=value")
    name, _, kind = head.partition(":")
    return make_field(name, value, kind.strip() or None, ("given",))


def render_table(field: Field) -> dict[str, str]:
    """Every rendering name of the field and its text: `as_stored` and render_candidates' names,
    including the ones that spell the stored text again (a convention may name either)."""
    table = {"as_stored": field.stored}
    for name, text in _rc_options(field.value, field.kind):
        table.setdefault(name, text)
    return table


def renderings(field: Field, prior: Iterable[str] = ()) -> list[tuple[str, str]]:
    """The field's distinct spellings, best first: the stored spelling (`as_stored`: the values of
    these markers are usually hashed verbatim), then render_candidates' other spellings in its order.
    `prior` names renderings the judge has accepted for this kind (the knowledge base): they lead."""
    table = render_table(field)
    lead = [name for name in dict.fromkeys(prior) if name in table]
    out, seen = [], set()
    for name in lead + [name for name in table if name not in lead]:
        if table[name] not in seen:              # one text once, under the first name that spells it
            seen.add(table[name])
            out.append((name, table[name]))
    return out


# ------------------------------------------------------------------------------------- digests

@dataclass(frozen=True)
class DigestForm:
    """How a marker is cut from a digest: `sha256[:8]` (the first 8 hex characters), `sha256[-8:]`
    (the last 8), `sha256` (all of it), with `.upper` for upper-case hex."""
    algo: str = "sha256"
    head: int | None = None
    tail: int | None = None
    upper: bool = False

    @property
    def name(self) -> str:
        cut = f"[:{self.head}]" if self.head else f"[-{self.tail}:]" if self.tail else ""
        return f"{self.algo}{cut}{'.upper' if self.upper else ''}"

    def apply(self, hexdigest: str) -> str:
        out = hexdigest[:self.head] if self.head else hexdigest[-self.tail:] if self.tail else hexdigest
        return out.upper() if self.upper else out

    @classmethod
    def parse(cls, text) -> "DigestForm":
        m = _FORM.match(str(text).strip().lower())
        if not m:
            raise MarkerError(f"digest form {text!r}: write sha256[:8], sha256[-8:] or sha256 "
                              f"(algorithms: {', '.join(ALGOS)}; add .upper for upper-case hex)")
        algo, head, tail, upper = m.group(1), m.group(2), m.group(3), bool(m.group(4))
        size = hashlib.new(algo).digest_size * 2
        for n in (head, tail):
            if n is not None and not 1 <= int(n) <= size:
                raise MarkerError(f"digest form {text!r}: {algo} has {size} hex characters")
        return cls(algo, int(head) if head else None, int(tail) if tail else None, upper)


def brief_algos(text) -> list[str]:
    """The digest algorithms a marker's brief may mean, most likely first. SHA-256 alone when the
    brief names it: any other name is then about something else (a download's MD5). When it names
    only other algorithms they lead, in the order they are named, and SHA-256 still follows: a name
    read from prose may be about a checksum of the archive, and nearly every constructed marker is
    a SHA-256, so it is never dropped from the space."""
    text = str(text or "")
    named = [name for _, name in sorted((m.start(), name) for rx, name in _BRIEF_ALGO
                                        for m in [rx.search(text)] if m)]
    return ["sha256"] if "sha256" in named else named + ["sha256"]


def forms_from_brief(text) -> list[DigestForm]:
    """The digest forms a brief states, read by shape only; [] when it states no usable length. The
    brief is untrusted data.

    A length is `N hex` (`8_lowercase_hex`, "16 lowercase hex characters"). Where it stands decides
    how much it says: inside the braces of a flag format (`CSCTF{8_lowercase_hex}`) or after `first`
    or `last` ("the first 16 hex characters"; `last` cuts the digest's tail) it is about the answer.
    Anywhere else it may be about something else ("addresses are 4 hex digits wide"), so such a
    length is used only when the brief states none of the first sort. Every distinct length left is
    kept, in the order stated (`run` notes it when there are several), with one form per algorithm
    of `brief_algos` that has that many hex characters."""
    text = str(text or "")
    algos = brief_algos(text)
    stated: list[tuple[bool, list[DigestForm]]] = []
    for m in _BRIEF_HEX.finditer(text):
        n = int(m.group(1))
        if n % 2 or n < 4:
            continue
        before = _BRIEF_CUT.search(text[:m.start()])
        tail = bool(before) and (before.group(2) or "").lower() == "last"
        upper = (m.group(2) or "").lower() == "upper"
        forms = []
        for algo in algos:
            size = hashlib.new(algo).digest_size * 2
            if n <= size:
                cut = None if n == size else n
                forms.append(DigestForm(algo, None if tail else cut, cut if tail else None, upper))
        if forms:
            stated.append((before is not None, forms))
    about_the_answer = [forms for sure, forms in stated if sure]
    out: list[DigestForm] = []
    for forms in about_the_answer or [forms for _, forms in stated]:
        out += [f for f in forms if f not in out]
    return out


# ------------------------------------------------------------------------------------- witnesses

@dataclass(frozen=True)
class Witness:
    """A hex tag the evidence carries for the marker's digest. `where` says which part of the digest
    it must equal: `prefix`, `suffix`, `edge` (either end) or `any` (anywhere inside)."""
    token: str
    where: str = "edge"
    source: str = "given"

    def match(self, hexdigest: str) -> str | None:
        """Where the token sits in the digest (`prefix`, `suffix`, `inside`), or None."""
        t = self.token
        if self.where in ("prefix", "edge", "any") and hexdigest.startswith(t):
            return "prefix"
        if self.where in ("suffix", "edge", "any") and hexdigest.endswith(t):
            return "suffix"
        if self.where == "any" and t in hexdigest:
            return "inside"
        return None

    def places(self, size: int) -> int:
        """How many positions of a `size`-character digest the token is compared at."""
        if self.where in ("prefix", "suffix"):
            return 1
        return 2 if self.where == "edge" else max(1, size - len(self.token) + 1)

    def to_dict(self) -> dict:
        return {"token": self.token, "where": self.where, "source": self.source}


def parse_witness(spec) -> Witness:
    """`HEX` or `HEX@where` (prefix, suffix, edge, any): at least 8 hex characters."""
    if isinstance(spec, Witness):
        return spec
    token, _, where = str(spec).strip().partition("@")
    token, where = token.strip().lower(), (where.strip().lower() or "edge")
    if not _HEX.match(token) or len(token) < 8:
        raise MarkerError(f"witness {spec!r}: at least 8 hex characters, optionally @prefix, @suffix, "
                          "@edge or @any")
    if where not in WHERE:
        raise MarkerError(f"witness {spec!r}: where is one of {', '.join(WHERE)}")
    return Witness(token, where, "given")


# ------------------------------------------------------------------------------------- the handout

def handout_files(challenge_dir) -> tuple[list[Path], list[str]]:
    """The evidence files of a challenge folder, sorted, and notes on what was left out. A pulled
    challenge keeps them in `files/` (and `unpacked/`); a bare folder is read whole, without the
    workspace's own files (challenge.json, notes.md... at its top level; recon/). A directory or file
    whose name starts with a dot is never entered or read (`.ctf/` holds credentials), and symlinks
    are never followed."""
    base = Path(challenge_dir)
    roots = [base / n for n in ("files", "unpacked") if (base / n).is_dir()] or [base]
    found, notes = [], []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if fn.startswith(".") or p.is_symlink() or not p.is_file():
                    continue
                if Path(dirpath) == base and fn in SKIP_NAMES:      # the workspace's own files, top level only
                    continue
                found.append(p)
    if len(found) > MAX_FILES:
        notes.append(f"{len(found) - MAX_FILES} file(s) past the first {MAX_FILES} were not read")
        found = found[:MAX_FILES]
    return found, notes


def load_handout(challenge_dir) -> tuple[list[tuple[str, bytes]], list[str]]:
    """[(path relative to the folder, its bytes)] for the evidence files, and notes on every cut: a file
    over MAX_READ is read to that length, reading stops at MAX_TOTAL, and a file whose bytes equal an
    earlier file's is listed once (an unpacked copy of a handout file must not corroborate itself)."""
    base = Path(challenge_dir)
    files, notes = handout_files(base)
    docs, seen, total, same = [], set(), 0, 0
    for i, path in enumerate(files):
        rel = path.relative_to(base).as_posix()
        if total >= MAX_TOTAL:
            notes.append(f"{len(files) - i} file(s) from {rel} on were not read: {MAX_TOTAL} bytes already read")
            break
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_READ + 1)
        except OSError as e:
            notes.append(f"{rel}: not read ({e.strerror or e})")
            continue
        if len(data) > MAX_READ:
            data = data[:MAX_READ]
            notes.append(f"{rel}: only the first {MAX_READ} bytes were read")
        digest = hashlib.sha256(data).digest()
        if digest in seen:
            same += 1
            continue
        seen.add(digest)
        total += len(data)
        docs.append((rel, data))
    if same:
        notes.append(f"{same} file(s) with the same bytes as an earlier file were counted once")
    return docs, notes


def _docs(source) -> tuple[list[tuple[str, bytes]], list[str]]:
    """`source` as loaded evidence: a challenge folder is loaded, a loaded list is used as it is."""
    if isinstance(source, (str, os.PathLike)):
        return load_handout(source)
    return list(source), []


def _is_text(data: bytes) -> bool:
    head = data[:4096]
    if not head or b"\x00" in head:
        return False
    odd = sum(1 for b in head if b < 9 or 13 < b < 32)
    return odd * 20 < len(head)


def _json_leaves(obj, name, out, depth=0) -> None:
    if depth > 12 or len(out) >= MAX_RAW_FIELDS * 4:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _json_leaves(v, str(k), out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:500]:
            _json_leaves(v, name, out, depth + 1)
    elif name and obj is not None and not isinstance(obj, bool):
        out.append((name, obj))


def _xml_leaves(text: str, out: list) -> str | None:
    """Attribute and leaf-element values of an XML document. A document that declares a DTD or an
    entity is not parsed (entity expansion is an attack surface): the reason is returned."""
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return "declares a DTD or an entity; not parsed"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return f"does not parse as XML ({e})"
    for el in root.iter():
        tag = str(el.tag).rsplit("}", 1)[-1]
        for k, v in el.attrib.items():
            out.append((str(k).rsplit("}", 1)[-1], v))
        if len(el) == 0 and (el.text or "").strip():
            out.append((tag, el.text.strip()))
    return None


def _json_number(literal: str):
    """A JSON real number as the file spells it (`12.5000` stays `12.5000`: the stored spelling is the
    first rendering); an exponent form has no fixed-point spelling to keep and is read as a float."""
    return literal if _DEC.match(literal) else float(literal)


def _named_values(rel: str, data: bytes, notes: list) -> list[tuple[str, Any]]:
    """(name, value) pairs one file states, by its content: JSON leaves, XML attributes and leaf
    elements, `key: value` lines; for a binary, its 4-character ASCII magic."""
    out: list = []
    if not _is_text(data):
        magic = data[:4].decode("latin-1")
        if len(magic) == 4 and magic.isascii() and magic.isalnum() and magic not in COMMON_MAGICS:
            out.append((f"{Path(rel).stem}_magic", data[:4]))
        return out
    text = data.decode("utf-8", errors="replace")
    lead = text.lstrip()[:1]
    if lead in "{[":
        try:
            _json_leaves(json.loads(text, parse_float=_json_number), "", out)
            return out
        except RecursionError:                    # a file of 100,000 `[`: hostile or broken, never fatal
            notes.append(f"{rel}: JSON nested too deeply to parse; read as key: value lines instead")
        except ValueError:
            pass
    if lead == "<":
        why = _xml_leaves(text, out)
        if why is None:
            return out
        notes.append(f"{rel}: {why}")
        out.clear()
    for line in text.splitlines()[:5000]:
        m = _KV_LINE.match(line)
        if m:
            out.append((m.group(1), m.group(2).strip().strip("\"'")))
    return out


def _canon(value, kind):
    """What two spellings of one value share: used to see the same value in two files."""
    if kind in ("hexid", "integer"):
        s = str(value).strip()
        try:
            return ("n", int(s, 16) if s[:2].lower() == "0x" else int(s))
        except ValueError:
            return ("s", s)
    if kind == "timestamp":
        epoch = dict(RC.render(value, "timestamp")).get("epoch_seconds")
        if not epoch:
            return ("s", str(value))
        part = _FRACTION.search(value) if isinstance(value, str) else None      # 04:05:06.100 is not 04:05:06.900
        return ("t", epoch, part.group(1).rstrip("0") if part else "")
    if kind == "decimal":
        return ("f", float(value))
    return ("s", bytes(value).decode("latin-1") if isinstance(value, (bytes, bytearray)) else str(value))


def _usable(name: str, value) -> bool:
    if isinstance(value, (int, float)):
        return value == value and abs(value) != float("inf")
    if isinstance(value, (bytes, bytearray)):
        return True
    s = str(value).strip()
    if not s or len(s) > MAX_VALUE_LEN or not s.isprintable():
        return False
    if name.lower() in WITNESS_LABELS and _HEX.match(s) and len(s) >= 8:
        return False                              # a tag FOR the digest is a witness, not an input
    return True


def _wordy(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _mentions(text_lower: str, needle: str) -> bool:
    """`needle` stands in the text as a whole token (not inside a longer word, name or number)."""
    n = needle.lower()
    start = text_lower.find(n)
    while start >= 0:
        before = text_lower[start - 1] if start else " "
        after = text_lower[start + len(n)] if start + len(n) < len(text_lower) else " "
        if not (_wordy(before) or _wordy(after)):
            return True
        start = text_lower.find(n, start + 1)
    return False


def _archive_stem(rel: str) -> str:
    for head in ("files/", "unpacked/"):
        if rel.startswith(head):
            return rel[len(head):]
    return rel


def containers(docs) -> tuple[dict[str, str], bool]:
    """({container: a member it holds}, whole): evidence files that hold another evidence file and so
    are not a second source for anything in it. Two signs, either is enough:

      by path   intake unpacked it: another file sits under `<archive>.unpacked/` (ctf/sweep.py).
      by bytes  a binary file holds another file's bytes whole: a tar, a zip written with the stored
                method, a disk image a file was carved from. Files are compared as far as they
                were read (MAX_READ): a member that large is caught by its path only. A text file
                is never taken for a container (two configurations that share lines are two
                sources), nor is a file under MIN_MEMBER bytes taken for a member.

    `whole` is False when the byte comparison stopped at SCAN_BYTES: the caller says so."""
    docs = list(docs)
    out: dict[str, str] = {}
    rels = [rel for rel, _ in docs]
    for rel in rels:
        heads = (f"{rel}{UNPACKED_SUFFIX}/", f"unpacked/{_archive_stem(rel)}{UNPACKED_SUFFIX}/")
        inside = next((o for o in rels if o != rel and o.startswith(heads)), None)
        if inside is not None:
            out[rel] = inside
    scanned, whole = 0, True
    for rel, data in docs:
        if rel in out or _is_text(data):
            continue
        for other, inner in docs:
            if other == rel or not MIN_MEMBER <= len(inner) < len(data):
                continue
            if scanned > SCAN_BYTES:
                whole = False
                break
            scanned += len(data)
            if inner in data:
                out[rel] = other
                break
    return out, whole


def extract_fields(source, brief: str = "") -> tuple[list[Field], list[str]]:
    """Named values the handout states, each with the evidence that holds it, most corroborated
    first. `source` is a challenge folder or `load_handout`'s list. A value counts as corroborated
    when two sources hold it: the same value named in another file, its spelling standing as a token
    in another file, or in the brief. A file that holds another evidence file (`containers`: an
    archive beside its unpacked members) is no source at all: it would corroborate every value of
    its own member. What a capture or a binary encodes is not decoded here (the protocol engines do
    that): pass those values as fields.

    A value shaped like a kind it cannot be rendered in (`2031-02-30T04:05:06Z`: no such day) is
    kept as text, and a value that cannot be a field at all (a name with no letter or digit) is
    left out; both are named in a note. Two timestamps are one value only when they agree to the
    last sub-second digit.

    Returns (fields, notes). Notes name everything that was left out: nothing is dropped silently."""
    docs, notes = _docs(source)
    texts: dict[str, str] = {}
    merged: dict[tuple, dict] = {}
    raw_count = 0
    as_text: list[str] = []
    not_kept: list[str] = []
    held, whole = containers(docs)
    if not whole:
        notes.append("the check for archives that hold other evidence files stopped at its scan limit: "
                     "an archive may be counted as a second source for its own member")
    for rel, data in docs:
        if rel in held:
            notes.append(f"{rel}: holds {held[rel]} (an archive or image beside what was unpacked from "
                         "it): not a second source, left out of the fields and the corroboration")
            continue
        texts[rel] = data.decode("latin-1").lower()
        for name, value in _named_values(rel, data, notes):
            if not _usable(name, value):
                continue
            raw_count += 1
            if raw_count > MAX_RAW_FIELDS:
                continue
            try:
                f = make_field(name, value, None, (rel,))
            except MarkerError:
                try:                              # shaped like a kind it does not render in: still a value
                    f = make_field(name, value, "text", (rel,))
                except MarkerError as e:
                    not_kept.append(f"{rel}: {e}")
                    continue
                as_text.append(f"{rel}: {f.name}={f.stored} (shaped like a {infer_kind(value)})")
            slot = merged.setdefault(_canon(f.value, f.kind), {"field": f, "sources": []})
            if rel not in slot["sources"]:
                slot["sources"].append(rel)
    if raw_count > MAX_RAW_FIELDS:
        notes.append(f"{raw_count - MAX_RAW_FIELDS} named value(s) past the first {MAX_RAW_FIELDS} were not kept")
    for what, rows in (("kept as text: no rendering of the kind it is shaped like exists for it", as_text),
                       ("not kept", not_kept)):
        if rows:
            more = f"; and {len(rows) - MAX_NOTED} more" if len(rows) > MAX_NOTED else ""
            notes.append(f"{len(rows)} named value(s) {what}: " + "; ".join(rows[:MAX_NOTED]) + more)
    if brief:
        texts["brief"] = str(brief).lower()
    scanned, uncut = 0, True
    for slot in merged.values():
        f = slot["field"]
        needles = [t for t in dict.fromkeys(t for _, t in renderings(f)) if len(t) >= MIN_NEEDLE]
        for rel, text in texts.items():
            if rel in slot["sources"] or not needles:
                continue
            if scanned > SCAN_BYTES:
                uncut = False
                break
            scanned += len(text) * len(needles)
            if any(_mentions(text, n) for n in needles):
                slot["sources"].append(rel)
    if not uncut:
        notes.append("corroboration search stopped at its scan limit: some values may be held by more "
                     "files than listed")
    out, per_name, dropped = [], {}, 0
    for slot in merged.values():
        f = slot["field"]
        n = per_name.get(f.name, 0)
        if len(slot["sources"]) < 2 and n >= PER_NAME:
            dropped += 1
            continue
        per_name[f.name] = n + 1
        name = f.name if n == 0 else f"{f.name}_{n + 1}"
        out.append(Field(name, f.value, f.kind, tuple(slot["sources"])))
    if dropped:
        notes.append(f"{dropped} uncorroborated value(s) of repeated names were not listed "
                     f"(the first {PER_NAME} of each name are)")
    order = {id(f): i for i, f in enumerate(out)}
    out.sort(key=lambda f: (-len(f.sources), order[id(f)]))
    return out, notes


def find_witnesses(source) -> tuple[list[Witness], list[str]]:
    """(witnesses, notes): hex tags the handout labels as a check on a digest (`TAG:9f3c21aa`,
    `"checksum": "..."`), each as an `edge` witness: the files rarely say which end of the digest the
    tag is. `source` is a challenge folder or `load_handout`'s list.

    At most MAX_FILE_WITNESSES distinct tags are taken, in reading order. Every tag compared is one
    more chance of a match (`search` counts them), and a log of thousands of hashes would make any
    hit worthless, so the rest are not compared: a note says how many were cut and where the cut
    fell."""
    out, seen, notes = [], set(), []
    for rel, data in _docs(source)[0]:
        for m in _WITNESS.finditer(data.decode("latin-1")):
            token = m.group(2).lower()
            if token not in seen:
                seen.add(token)
                if len(out) < MAX_FILE_WITNESSES:
                    out.append(Witness(token, "edge", f"{rel}:{m.group(1).lower()}"))
    if len(seen) > len(out):
        notes.append(f"the files label {len(seen)} hex tags; only the first {len(out)} are compared "
                     f"(the last one compared is {out[-1].token}, {out[-1].source}) and "
                     f"{len(seen) - len(out)} are not: give the tag that checks the marker as a witness "
                     "(witness=HEX, --witness HEX)")
    return out, notes


# ------------------------------------------------------------------------------------- conventions

@dataclass(frozen=True)
class Convention:
    """One way a marker is built: the digest form, the join, and each role with its rendering, in
    order. Its `name` is what the knowledge base stores:
    `sha256[:8];colon;header=hex_0x_upper,station=as_stored` (`-` for the join of a single field)."""
    digest: str
    join: str | None
    parts: tuple[tuple[str, str], ...]

    @property
    def name(self) -> str:
        return f"{self.digest};{self.join or '-'};" + ",".join(f"{r}={x}" for r, x in self.parts)

    @property
    def roles(self) -> tuple[str, ...]:
        return tuple(r for r, _ in self.parts)

    @classmethod
    def parse(cls, name) -> "Convention":
        bits = str(name).strip().split(";")
        if len(bits) != 3:
            raise MarkerError(f"convention {name!r}: write <digest>;<join>;<role>=<rendering>,...")
        digest = DigestForm.parse(bits[0]).name
        join = None if bits[1] == "-" else bits[1]
        if join is not None and join not in dict(RC.JOINS):
            raise MarkerError(f"convention {name!r}: unknown join {join!r}; one of "
                              f"{', '.join(n for n, _ in RC.JOINS)} (or - for one field)")
        parts = []
        for item in bits[2].split(","):
            r, sep, x = item.partition("=")
            if not sep or not _NAME.match(r) or not _NAME.match(x):
                raise MarkerError(f"convention {name!r}: {item!r} is not <role>=<rendering>")
            parts.append((r, x))
        if len({r for r, _ in parts}) != len(parts):
            raise MarkerError(f"convention {name!r}: a role is used twice")
        if (join is None) != (len(parts) == 1):
            raise MarkerError(f"convention {name!r}: one field takes the join -, several take a named join")
        return cls(digest, join, tuple(parts))

    def preimage(self, fields: Iterable[Field]) -> str | None:
        """The text this convention builds from `fields`, or None when a role is not among them or a
        rendering does not exist for its value."""
        by_name = {f.name: f for f in fields}
        texts = []
        for r, x in self.parts:
            f = by_name.get(r)
            text = render_table(f).get(x) if f is not None else None
            if text is None:
                return None
            texts.append(text)
        return dict(RC.JOINS)[self.join].join(texts) if self.join else texts[0]


# ------------------------------------------------------------------------------------- knowledge base

def family_name(family) -> str:
    """A family as the knowledge base keys it: lower snake case (`ics`, `networking`); `any` for none."""
    return _ROLE.sub("_", str(family or "").strip().lower()).strip("_") or "any"


def convention_key(family) -> str:
    """The labels candidate key that holds a family's accepted and rejected conventions."""
    return labels.candidate_key(f"{KB_LANE}.convention/{family_name(family)}")


class KB:
    """A read view of the convention knowledge base: the labels lane `marker` (tracked seed plus the
    event's runtime ledger, B-040). `available` is False, with `reason`, when it cannot be read (no
    judge ledger for the event, no resolvable event workdir): every list is then empty, and the
    caller's report says so."""

    def __init__(self) -> None:
        self.available, self.reason = True, ""
        try:
            if not labels.judge_ledger():
                self.available = False
                self.reason = (f"this event has no judge ledger (${labels.JUDGE_LEDGER_ENV}=off): "
                               "the convention knowledge base is not read")
            else:
                labels.keys(f"{KB_LANE}.")
        except Exception as e:  # noqa: BLE001 - EventError (no workdir), ValueError (a bad switch)
            self.available, self.reason = False, f"the convention knowledge base cannot be read: {e}"

    def _names(self, prefix: str) -> list[str]:
        return labels.family(prefix) if self.available else []

    def accepted(self, family) -> list[str]:
        """Conventions the judge accepted for the family, first accepted first."""
        return list(labels.state(convention_key(family))["accepted_names"]) if self.available else []

    def rejected(self, family) -> set[str]:
        return set(labels.state(convention_key(family))["rejected"]) if self.available else set()

    def joins(self) -> list[str]:
        """Joins accepted for any family, in the order they were learned."""
        return self._names(f"{KB_LANE}.join/")

    def digests(self) -> list[str]:
        return self._names(f"{KB_LANE}.digest/")

    def renders(self, kind: str) -> list[str]:
        """Renderings other than the stored spelling that were accepted for values of `kind`."""
        return self._names(f"{KB_LANE}.render/{kind}.")

    def families(self) -> list[str]:
        if not self.available:
            return []
        head = f"{KB_LANE}.convention/"
        return [k[len(head):-len(labels.CANDIDATE_MARK)] for k in labels.keys(head)]


def learn(family, convention, verdict: str, kinds: dict[str, str] | None = None,
          challenge_id: str | None = None) -> list[tuple[str, str]]:
    """Record the judge's verdict on a convention in the runtime label ledger (B-040 folds it into the
    tracked seed: `ctf seed-fold marker`). Returns the (key, name) rows written.

    accepted  the convention for its family, and what it teaches every family: its join, its digest
              form, and each rendering that differs from the stored spelling, under the value's kind
              (`kinds`: role -> kind; a role without a kind teaches no rendering). A rendering equal
              to the stored spelling is not recorded: verbatim is already the default, and the judge's
              yes could not tell the two apart.
    rejected  the convention for its family only: it is no longer offered for that family.

    MarkerError when the event has no judge ledger or a row cannot be written (never a silent miss)."""
    if verdict not in ("accepted", "rejected"):
        raise MarkerError(f"verdict must be accepted or rejected, not {verdict!r}")
    conv = convention if isinstance(convention, Convention) else Convention.parse(convention)
    if not labels.judge_ledger():
        raise MarkerError(f"this event has no judge ledger (${labels.JUDGE_LEDGER_ENV}=off): the "
                          "convention knowledge base cannot record a verdict")
    fam = family_name(family)
    rows = [(convention_key(fam), conv.name)]
    if verdict == "accepted":
        if conv.join:
            rows.append((f"{KB_LANE}.join/{fam}", conv.join))
        rows.append((f"{KB_LANE}.digest/{fam}", conv.digest))
        for r, x in conv.parts:
            kind = (kinds or {}).get(r)
            if x == "as_stored" or kind is None:
                continue
            if kind not in KINDS:
                raise MarkerError(f"role {r!r}: unknown kind {kind!r}; one of {', '.join(KINDS)}")
            row = (f"{KB_LANE}.render/{kind}.{fam}", x)
            if row not in rows:
                rows.append(row)
    for key, name in rows:
        if not labels.learn(key, name, verdict, scope="key", attempt_id=challenge_id):
            raise MarkerError(f"the label ledger did not take {verdict} {name!r} for {key}")
    return rows


# ------------------------------------------------------------------------------------- the search

@dataclass(frozen=True)
class Candidate:
    rank: int
    flag: str                 # the marker as it would be submitted (wrapped in the event's format)
    marker: str               # the bare digest cut
    convention: str           # Convention.name
    preimage: str             # the exact text that was hashed
    basis: str                # witness | witness-weak | kb | kb-recut | prior
    detail: str = ""          # which witness and how strong, or what the knowledge base holds

    def to_dict(self) -> dict:
        return {"rank": self.rank, "flag": self.flag, "marker": self.marker, "convention": self.convention,
                "preimage": self.preimage, "basis": self.basis, "detail": self.detail}


@dataclass
class Report:
    family: str
    fields: list[Field]
    digests: list[str]
    witnesses: list[Witness]
    candidates: list[Candidate]
    space: int                # compositions in the whole space
    enumerated: int           # compositions hashed (the budget may cut the space)
    witness_hits: int
    kb_available: bool
    notes: list[str] = _dc_field(default_factory=list)

    @property
    def exhausted(self) -> bool:
        return self.enumerated >= self.space

    @property
    def supported(self) -> bool:
        """The first candidate is backed by a strong witness or by a convention the judge accepted."""
        return bool(self.candidates) and self.candidates[0].basis in ("witness", "kb")

    def kinds(self) -> dict[str, str]:
        return {f.name: f.kind for f in self.fields}

    def to_dict(self) -> dict:
        return {"family": self.family, "fields": [f.to_dict() for f in self.fields],
                "digests": list(self.digests), "witnesses": [w.to_dict() for w in self.witnesses],
                "candidates": [c.to_dict() for c in self.candidates], "space": self.space,
                "enumerated": self.enumerated, "exhausted": self.exhausted,
                "witness_hits": self.witness_hits, "kb_available": self.kb_available,
                "supported": self.supported, "notes": list(self.notes)}


def _lead(items: list, prior: Iterable[str], name=lambda x: x) -> list:
    """`items` with the ones the knowledge base names moved to the front, in its order."""
    front = [it for p in dict.fromkeys(prior) for it in items if name(it) == p]
    return front + [it for it in items if it not in front]


def search(fields: Iterable[Field], digests: Iterable[DigestForm] | None = None, *,
           witnesses: Iterable[Witness] = (), family="any", kb: KB | None = None,
           budget: int = DEFAULT_BUDGET, top: int = DEFAULT_TOP, min_fields: int | None = None,
           max_deviations: int | None = None, permute: bool = True, wrap=None) -> Report:
    """Enumerate, hash, check and rank. Returns a Report whose `candidates` are ordered:

      1. witness hits, strong before weak, in enumeration order. A hit is strong when fewer than
         CHANCE_LIMIT chance matches are expected: texts hashed x algorithms x, summed over every
         witness compared whose tag is at least as long as the one that hit, positions / 16^length
         (a hit among many tags of its length is weak; a longer tag is not weakened by shorter ones);
      2. the conventions the judge accepted for this family, where every role is among the fields.
         When `digests` is given (the brief or the caller states the cut) and an accepted
         convention was cut another way, its fields, order and renderings are listed under the
         stated forms instead, as `kb-recut`: a guess that leads the prior, not a backed value;
      3. the prior: the compositions that deviate least from "every field, in the given order, as
         stored, joined by the first join" (one point per re-rendered field, one for another order,
         two per field left out, up to three for a later join), for each digest form in turn; forms
         of different algorithms alternate (when the algorithm is open too, neither hides the other).

    A convention the judge rejected for the family is left out, unless a strong witness in this
    challenge confirms it (the rejection was for other values), and one flag is listed once. The
    knowledge base only reorders: the joins, digest forms and per-kind renderings it holds are tried
    first. `budget` caps the texts hashed; the report says how much of the space that covered.
    `wrap(marker)` gives the flag (default: the bare marker)."""
    fields = list(fields)
    if not fields:
        raise MarkerError("no fields: name the values the marker is built from")
    if budget < 1 or top < 1:
        raise MarkerError("budget and top must be at least 1")
    kb = KB() if kb is None else kb
    fam = family_name(family)
    stated = bool(digests)                        # the cut is the brief's or the caller's, not a default
    forms = _lead(list(digests) if digests else [DigestForm.parse(f) for f in DEFAULT_FORMS],
                  kb.digests(), lambda f: f.name)
    if not forms:
        raise MarkerError("no digest form")
    witnesses = list(witnesses)
    joins = _lead(list(RC.JOINS), kb.joins(), lambda j: j[0])
    options = [(f.name, renderings(f, kb.renders(f.kind))) for f in fields]
    lo = min(2, len(fields)) if min_fields is None else int(min_fields)
    axis = dict(joins=joins, min_fields=lo, max_deviations=max_deviations, permute=permute)
    try:
        space = RC.compose_size(options, **axis)
    except ValueError as e:
        raise MarkerError(str(e)) from None
    algos = list(dict.fromkeys(f.algo for f in forms))
    hashers = {a: getattr(hashlib, a) for a in algos}
    position = {f.name: i for i, f in enumerate(fields)}
    default = {name: opts[0][0] for name, opts in options}
    join_rank = {name: min(i, 3) for i, (name, _) in enumerate(joins)}
    n = len(fields)

    rejected = kb.rejected(fam)
    keep = 2 * top + len(rejected)                # spare for flags listed twice and rejected conventions
    heap: list = []                               # the `keep` cheapest compositions, as (-cost, -index, comp)
    hits: list = []
    nhits = enumerated = 0
    for idx, comp in enumerate(RC.compose_axis(options, limit=budget, **axis)):
        enumerated = idx + 1
        if witnesses:
            data = comp.text.encode("utf-8")
            for algo in algos:
                hexdigest = hashers[algo](data).hexdigest()
                for w in witnesses:
                    at = w.match(hexdigest)
                    if at:
                        nhits += 1
                        if len(hits) < MAX_HITS:
                            hits.append((idx, comp, algo, w, at))
        seq = [position[name] for name in comp.fields]
        cost = (sum(1 for name, r in zip(comp.fields, comp.renders) if r != default[name])
                + (0 if seq == sorted(seq) else 1) + 2 * (n - len(seq))
                + (join_rank[comp.join] if comp.join else 0))
        item = (-cost, -idx, comp)
        if len(heap) < keep:
            heapq.heappush(heap, item)
        elif item > heap[0]:
            heapq.heapreplace(heap, item)
    prior = [comp for _, _, comp in sorted(heap, reverse=True)]

    wrap = wrap or (lambda marker: marker)
    notes: list[str] = []
    out: list[Candidate] = []
    seen: set[str] = set()
    left_out: set[str] = set()                    # flags, so one value is counted once
    kept = 0

    def add(conv: Convention, text: str, form: DigestForm, basis: str, detail: str) -> None:
        nonlocal kept
        # A rejection is the judge's answer for ANOTHER challenge's values (the base is keyed by
        # family). A strong witness is this challenge's own offline check and outranks it.
        was_rejected = conv.name in rejected
        marker = form.apply(hashers[form.algo](text.encode("utf-8")).hexdigest())
        flag = wrap(marker)
        if flag in seen or len(out) >= top:           # listed already (a witness kept it), or the list is full
            return
        if was_rejected and basis != "witness":
            left_out.add(flag)
            return
        if was_rejected:
            kept += 1
            detail += f"; the judge rejected this convention for family {fam} on other values"
        seen.add(flag)
        out.append(Candidate(len(out) + 1, flag, marker, conv.name, text, basis, detail))

    def conv_of(comp, form: DigestForm) -> Convention:
        return Convention(form.name, comp.join, tuple(zip(comp.fields, comp.renders)))

    scored = []
    for idx, comp, algo, w, at in hits:
        size = hashers[algo]().digest_size * 2
        # Every witness compared is one more chance of a match as good as this one or better.
        rivals = [x for x in witnesses if len(x.token) >= len(w.token)]
        chance = enumerated * len(algos) * sum(x.places(size) / 16 ** len(x.token) for x in rivals)
        scored.append((chance >= CHANCE_LIMIT, idx, comp, algo, w, at, chance, len(rivals)))
    for weak, idx, comp, algo, w, at, chance, among in sorted(scored, key=lambda s: (s[0], s[1])):
        detail = (f"{algo} digest {at} equals {w.token} ({w.source}); {chance:.2g} chance match(es) "
                  f"expected over {enumerated} texts" + (f" and {among} tags" if among > 1 else ""))
        for form in forms:
            if form.algo == algo:
                add(conv_of(comp, form), comp.text, form, "witness-weak" if weak else "witness", detail)
    for name in kb.accepted(fam):
        try:
            conv = Convention.parse(name)
            form = DigestForm.parse(conv.digest)
        except MarkerError as e:
            notes.append(f"knowledge base entry skipped: {e}")
            continue
        text = conv.preimage(fields)
        if text is None:
            missing = [r for r in conv.roles if r not in position]
            notes.append(f"the judge accepted {name} for family {fam}; not built here: "
                         + (f"no field named {', '.join(missing)}" if missing
                            else "a rendering it names does not exist for a value"))
            continue
        if stated and form not in forms:
            # The judge's yes was for another cut of the digest. The cut stated here wins; what
            # carries over is the fields, their order and renderings, and that is a guess.
            here = ", ".join(f.name for f in forms)
            notes.append(f"the judge accepted {name} for family {fam}, but the digest stated here is "
                         f"{here}: its fields, order and renderings are listed under {here} as a guess "
                         f"(kb-recut), not under {conv.digest}")
            for cut in forms:
                add(Convention(cut.name, conv.join, conv.parts), text, cut, "kb-recut",
                    f"the judge accepted these fields, order and renderings for family {fam} under "
                    f"{conv.digest}; the digest stated here is {cut.name}")
            continue
        if form.algo not in hashers:
            hashers[form.algo] = getattr(hashlib, form.algo)
        add(conv, text, form, "kb", f"the judge accepted this convention for family {fam}")
    tiers: list[list[DigestForm]] = []            # the n-th form of each algorithm, together
    nth: dict[str, int] = {}
    for form in forms:
        i = nth.get(form.algo, 0)
        nth[form.algo] = i + 1
        if i == len(tiers):
            tiers.append([])
        tiers[i].append(form)
    for tier in tiers:
        for comp in prior:
            for form in tier:
                add(conv_of(comp, form), comp.text, form, "prior", "")
    if left_out:
        notes.append(f"{len(left_out)} candidate(s) left out: the judge rejected their convention for family {fam}")
    if kept:
        notes.append(f"{kept} candidate(s) kept although the judge rejected their convention for family "
                     f"{fam}: a strong witness in this challenge's own files confirms them")
    if nhits > len(hits):
        notes.append(f"{nhits} witness hits; only the first {MAX_HITS} are listed")
    if witnesses and not nhits:
        notes.append("no witness hit in the part of the space that was hashed: raise the budget or narrow "
                     "the space (a known order, fewer deviations)" if enumerated < space else
                     "no witness hit: no composition of these fields, renderings and joins gives that digest")
    if not kb.available:
        notes.append(kb.reason)
    if enumerated < space:
        notes.append(f"hashed {enumerated} of {space} compositions (budget {budget}): the rest of the "
                     "space was not checked")
    return Report(family=fam, fields=fields, digests=[f.name for f in forms], witnesses=witnesses,
                  candidates=out, space=space, enumerated=enumerated, witness_hits=nhits,
                  kb_available=kb.available, notes=notes)


def pick(report: Report) -> tuple[list[str], str | None]:
    """What a solver hands on: (flags, unsure string). The flags are the report's first candidates,
    at most `labels.MAX_OPTIONS`, through `labels.candidates` on the family's convention key, so a
    convention the judge accepted for the family answers alone and the rest stay an unsure pick
    (never a plain answer before the judge has accepted a name). A strong witness is this
    challenge's own evidence and outranks the family's memory: its list is returned as ranked."""
    cands = report.candidates[:labels.MAX_OPTIONS]
    if not cands:
        return [], None
    if cands[0].basis == "witness" or not report.kb_available:
        return [c.flag for c in cands], None
    got = labels.candidates(f"{KB_LANE}.convention/{report.family}", [(c.convention, c.flag) for c in cands])
    if got is None:
        return [], None
    if labels.is_unsure(got):
        return [str(v) for _, v in labels.parse(got).options], got
    return [str(got)], None


@dataclass(frozen=True)
class Plan:
    send: tuple[str, ...]      # flags that may go out now, in order
    held: tuple[str, ...]      # flags past the guess budget: the player's sweep decides
    reasoned: bool             # the first flag is backed by a strong witness or the knowledge base
    guesses_left: int

    def to_dict(self) -> dict:
        return {"send": list(self.send), "held": list(self.held), "reasoned": self.reasoned,
                "guesses_left": self.guesses_left}


def send_plan(report: Report, profile, guesses_left: int, allow_nonstandard: bool = False) -> Plan:
    """Which of the report's candidates may be sent under the event's guess budget, through B-154's
    `flagcheck.VariantSet.plan` (the one place a ranked list is cut to the budget). A first candidate
    backed by a strong witness or an accepted convention is the reasoned value and the rest are
    guesses; with neither, the first candidate is itself a guess and takes one of `guesses_left`.
    Values outside the event's flag format are never planned (unless `allow_nonstandard`: a
    brief-defined bare marker). This plans; it sends nothing."""
    from ctf import flagcheck, flagfmt
    cands = report.candidates
    if isinstance(guesses_left, bool) or not isinstance(guesses_left, int) or guesses_left < 0:
        raise MarkerError(f"guesses_left must be an integer >= 0, got {guesses_left!r}")
    if not cands:
        return Plan((), (), False, guesses_left)
    ff = flagfmt.for_profile(profile)
    ranked = tuple(flagcheck.Variant(i, c.flag, 1.0 / (i + 1), (c.basis, c.convention), ff.is_flag(c.flag))
                   for i, c in enumerate(cands))
    chk = flagcheck.check(cands[0].flag, profile, source="derived", allow_nonstandard=allow_nonstandard)
    vs = flagcheck.VariantSet(check=chk, ranked=ranked)

    def ok(v) -> bool:
        return allow_nonstandard or v.in_format

    reasoned = report.supported
    if reasoned:
        send, held = vs.plan(guesses_left, allow_nonstandard)
    elif guesses_left > 0:
        send, held = vs.plan(guesses_left - 1, allow_nonstandard)
    else:
        send, held = [], [v for v in ranked if ok(v)]
    return Plan(tuple(v.value for v in send if ok(v)), tuple(v.value for v in held), reasoned, guesses_left)


# ------------------------------------------------------------------------------------- the engine

def read_brief(challenge_dir) -> tuple[str, str, list[str]]:
    """(description, category, notes) from the folder's challenge.json (untrusted data); empty
    strings when there is none."""
    path = Path(challenge_dir) / "challenge.json"
    if not path.is_file():
        return "", "", []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError, RecursionError) as e:
        return "", "", [f"challenge.json was not read ({type(e).__name__})"]
    if not isinstance(doc, dict):
        return "", "", ["challenge.json is not a JSON object"]
    return str(doc.get("description") or ""), str(doc.get("category") or ""), []


def _listed(value) -> list:
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _truthy(value) -> bool:
    return value is True or str(value).strip().lower() in ("1", "true", "yes", "on")


def _opt_int(opts: dict, key: str, default):
    """An integer option; `default` when it is absent. Anything that is not a whole number is a
    MarkerError naming the option."""
    value = opts.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"-?\d+", str(value).strip()):
        raise MarkerError(f"option {key} must be a whole number, got {value!r}")
    return int(str(value).strip())


def wrapper(profile, nonstandard: bool = False):
    """marker -> flag for the event: `PREFIX{marker}` with the profile's first prefix; the bare marker
    when the format is not known yet or the brief asks for it bare (`nonstandard`)."""
    spec = getattr(profile, "flag", None)
    if nonstandard or spec is None or not spec.known:
        return lambda marker: marker
    prefix = spec.prefixes[0]
    return lambda marker: f"{prefix}{{{marker}}}"


def run(challenge_dir, profile=None, **opts) -> tuple[Report | None, list[Field], list[str]]:
    """The whole offline pass over one challenge folder: (report, fields seen but not used, notes).
    `report` is None when there is no field to build from. MarkerError for a bad option."""
    base = Path(challenge_dir)
    if not base.is_dir():
        raise MarkerError(f"challenge folder not found: {base}")
    desc, category, notes = read_brief(base)
    brief = str(opts.get("brief") or desc)
    family = opts.get("family")
    if not family and category:
        from ctf import triage
        family = triage.canonical_category(category)
    docs, more = load_handout(base)
    notes += more
    explicit = [parse_field(s) for s in _listed(opts.get("fields"))]
    unused: list[Field] = []
    if explicit:
        fields = explicit
    else:
        found, more = extract_fields(docs, brief)
        notes += more
        cap = _opt_int(opts, "max_fields", DEFAULT_MAX_FIELDS)
        if not 1 <= cap <= RC.COMPOSE_MAX_FIELDS:
            raise MarkerError(f"max_fields must be 1..{RC.COMPOSE_MAX_FIELDS}, got {cap}")
        usable = found if _truthy(opts.get("all_fields")) else [f for f in found if len(f.sources) >= 2]
        fields, unused = usable[:cap], [f for f in found if f not in usable[:cap]]
    witnesses = [parse_witness(w) for w in _listed(opts.get("witness"))]
    found, more = find_witnesses(docs)
    notes += more
    witnesses += [w for w in found if w.token not in {x.token for x in witnesses}]
    digests = [DigestForm.parse(d) for d in _listed(opts.get("digest"))]
    if not digests:
        digests = forms_from_brief(brief)
        if len({d.algo for d in digests}) > 1:
            notes.append("the brief names " + ", ".join(d.algo for d in digests if d.algo != "sha256")
                         + ", which may be about something else (a download's checksum): "
                         + ", ".join(d.name for d in digests)
                         + " are all hashed and their candidates alternate (digest=FORM states one)")
        if len({(d.head, d.tail, d.upper) for d in digests}) > 1:
            notes.append("the brief states more than one hex length: " + ", ".join(d.name for d in digests)
                         + " are all hashed, the first stated first (digest=FORM states one)")
    if not fields:
        return None, unused, notes
    if len({f.name for f in fields}) != len(fields):
        raise MarkerError("two fields share a name: give each its own role")
    report = search(fields, digests or None, witnesses=witnesses, family=family or "any",
                    budget=_opt_int(opts, "budget", DEFAULT_BUDGET), top=_opt_int(opts, "top", DEFAULT_TOP),
                    min_fields=_opt_int(opts, "min_fields", None),
                    max_deviations=_opt_int(opts, "max_deviations", None),
                    permute=_truthy(opts.get("permute", True)),
                    wrap=wrapper(profile, _truthy(opts.get("nonstandard"))))
    report.notes[:0] = notes
    return report, unused, notes


def solve(challenge_dir, profile=None, **opts) -> SolverResult:
    """Engine entry. `candidate` when the first value is backed by a strong witness or by a convention
    the judge accepted for the family; `unsure` when the list is ranked by priors alone (the files do
    not determine the convention); `none` with no field or no candidate; `blocked` for a bad option
    or a missing folder. Never `solved`: only the platform's answer settles a constructed marker."""
    t0 = time.process_time()
    cid = opts.get("challenge_id")

    def result(status, flags=(), evidence=(), notes="") -> SolverResult:
        return SolverResult(status, flags=flags, evidence=evidence, engine=ENGINE_ID,
                            challenge_id=str(cid) if cid is not None else None, notes=notes,
                            cost=Cost(seconds=round(time.process_time() - t0, 3)))

    try:
        report, unused, notes = run(challenge_dir, profile, **opts)
    except (MarkerError, ValueError) as e:
        return result("blocked", notes=f"constructed-marker search did not run: {e}")
    if report is None:
        seen = ", ".join(f"{f.name}={f.stored}" for f in unused[:8])
        return result("none", notes="; ".join(
            notes + ["no named value is held by two evidence sources"
                     + (f" (seen once: {seen})" if seen else "")
                     + "; name the values with fields=[name[:kind]=value, ...] (ctf marker candidates --field)"]))
    flags, _unsure = pick(report)
    by_flag = {c.flag: c for c in report.candidates}
    evidence = [Evidence("witness" if by_flag[f].basis.startswith("witness") else "convention",
                         f"{f}: {by_flag[f].basis}: {by_flag[f].convention} over {by_flag[f].preimage[:160]!r}"
                         + (f" [{by_flag[f].detail}]" if by_flag[f].detail else ""))
                for f in flags if f in by_flag]
    summary = (f"family {report.family}; fields {', '.join(f.name for f in report.fields)}; "
               f"{report.enumerated} of {report.space} compositions hashed; "
               f"{len(report.witnesses)} witness(es), {report.witness_hits} hit(s); "
               "candidates only: send within the event guess budget (ctf marker candidates --id ID), "
               "never as a sweep without the player's authorization")
    if not flags:
        return result("none", notes="; ".join(report.notes + [summary, "no candidate is left"]))
    status = "candidate" if report.supported else "unsure"
    return result(status, flags=flags, evidence=evidence, notes="; ".join(report.notes + [summary]))
