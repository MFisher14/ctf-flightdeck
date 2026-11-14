"""The look-ahead matrix on disk (B-174), and the two rules that decide what a specimen proves.

    m = load(matrix_dir)                  # Matrix: lanes, specimens per lane, generator skips, waivers
    determinism(question, judged=())      # "deterministic" unless declared judged
    decode_chain(("base64", "zlib"), data)  # the payload, or EncodingMismatch naming the layer

Layout (unknown keys anywhere are a LookaheadError, so a typo never silently drops a rule):

    <matrix>/matrix.toml
        [lane.<lane>]
        reader = "solvers/binary/evidence.py"   # required: a module with solve_set(questions, files, ctx);
                                                # relative to the checkout root, or absolute
        judged = ["*_family_label"]             # id globs whose questions need judgment, not a procedure
        base = "base-questions.json"            # the newest base's questions (relative to the matrix):
                                                # every id it asks must be asked by a specimen that ran
        previous = "prev-questions.json"        # the base before it: `plan` diffs the two for a new shape
        timeout = 30                            # per-specimen cap, seconds (default DEFAULT_TIMEOUT)
        real_encodings = [["base64"], ["hex", "reverse"]]   # chains seen in real deliveries: each must
                                                # be exercised by a specimen that ran
        allow_unsure = false                    # true: an unsure (`??`) answer to a deterministic id is
                                                # reported, not a gap (default: a gap, it is never sent)
        [[lane.<lane>.threshold]]               # a size threshold the lane's code paths change at
        name = "siblings"; bytes = 1048576; measure = "total"   # total | member (the largest member)
        [[skipped]]                             # what the forecast generator left out, and why: a gap
        lane = "script"; name = "d28-terraform"; reason = "plan adapter differs"; ids = 44
        [[waived_threshold]]                    # a scanned size constant that does not change a path
        bytes = 262144; reason = "regex bound, not a delivery threshold"; where = "solvers/binary/*"

    <matrix>/<lane>/<specimen>/specimen.toml
        encoding = ["base64", "zlib"]           # required unless skip: every member's delivery encoding,
                                                # outermost first ("raw" alone: delivered as is)
        [encodings]                             # optional per-member override: "<member path>" = [...]
        skip = "reason"                         # the generator could not build or run it: a gap
        note = "..."
        [ctx]                                   # extra ctx the reader gets (JSON-able values)
    <matrix>/<lane>/<specimen>/questions.json   # the question list, or {"questions": [...]}
    <matrix>/<lane>/<specimen>/key.json         # optional {id: answer}; ids must be asked
    <matrix>/<lane>/<specimen>/files/...        # the delivered members (challenge-shaped, synthetic)

Determinism. A question is deterministic (unanswered = a release-blocking gap) unless the question
says `"determinism": "judged"` or its id (a leading `setN.` dropped) matches one of the lane's `judged`
globs. There is no kind-based guess: Day 28 showed that "safe None" on a stated computation is a gap,
so only an explicit declaration takes a question out of the gate.

Encodings. A specimen proves a delivery shape only if its bytes really carry the encoding it claims
(Huntress Day 16: a substituted encoding in a test hid a real bug). Every member's chain is decoded
layer by layer, strictly; a layer that does not hold is a `bad_encoding` gap. Codecs: CODECS.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import fnmatch
import json
import lzma
import re
import tomllib
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from . import LookaheadError

DETERMINISTIC = "deterministic"
JUDGED = "judged"
DEFAULT_TIMEOUT = 30.0
MEASURES = ("total", "member")
CODECS = ("raw", "base64", "base64url", "base32", "hex", "zlib", "gzip", "bz2", "xz", "utf-16le", "reverse")
MAX_DECODED = 256 * 1024 * 1024          # a decoded layer larger than this is refused (a bomb, not a specimen)

MATRIX_FILE = "matrix.toml"
SPECIMEN_FILE = "specimen.toml"
QUESTIONS_FILE = "questions.json"
KEY_FILE = "key.json"
FILES_DIR = "files"

_LANE_KEYS = {"reader", "judged", "base", "previous", "timeout", "real_encodings", "threshold", "allow_unsure"}
_THRESHOLD_KEYS = {"name", "bytes", "measure"}
_SKIPPED_KEYS = {"lane", "name", "reason", "ids"}
_WAIVED_KEYS = {"bytes", "reason", "where"}
_MATRIX_KEYS = {"lane", "skipped", "waived_threshold"}
_SPECIMEN_KEYS = {"encoding", "encodings", "skip", "note", "ctx"}
_SET_PREFIX = re.compile(r"^set\d+\.")
_LANE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class EncodingMismatch(LookaheadError):
    """A member's bytes do not carry the encoding chain its specimen claims."""


@dataclass(frozen=True)
class Threshold:
    name: str
    bytes: int
    measure: str = "total"          # total | member


@dataclass(frozen=True)
class LaneConfig:
    lane: str
    reader: str
    judged: tuple[str, ...] = ()
    base: Path | None = None
    previous: Path | None = None
    timeout: float = DEFAULT_TIMEOUT
    real_encodings: tuple[tuple[str, ...], ...] = ()
    thresholds: tuple[Threshold, ...] = ()
    allow_unsure: bool = False

    def reader_path(self, root: Path) -> Path:
        p = Path(self.reader)
        return p if p.is_absolute() else Path(root) / p


@dataclass(frozen=True)
class GeneratorSkip:
    lane: str
    name: str
    reason: str
    ids: int | None = None


@dataclass(frozen=True)
class Waiver:
    bytes: int
    reason: str
    where: str = "*"


@dataclass(frozen=True)
class Specimen:
    lane: str
    name: str
    path: Path
    questions: tuple[dict, ...]
    key: dict | None
    encodings: dict = field(default_factory=dict)     # member path -> chain (tuple)
    skip: str = ""
    note: str = ""
    ctx: dict = field(default_factory=dict)
    sizes: dict = field(default_factory=dict)         # member path -> bytes

    @property
    def files_dir(self) -> Path:
        return self.path / FILES_DIR

    @property
    def total_bytes(self) -> int:
        return sum(self.sizes.values())

    @property
    def member_bytes(self) -> int:
        return max(self.sizes.values(), default=0)

    def measure(self, how: str) -> int:
        return self.total_bytes if how == "total" else self.member_bytes

    def read_files(self) -> dict[str, bytes]:
        return {m: (self.files_dir / m).read_bytes() for m in sorted(self.sizes)}


@dataclass(frozen=True)
class Matrix:
    path: Path
    lanes: dict              # lane -> LaneConfig
    specimens: dict          # lane -> tuple[Specimen, ...]
    skipped: tuple[GeneratorSkip, ...] = ()
    waivers: tuple[Waiver, ...] = ()


# ------------------------------------------------------------------------------------------ ids


def qid_of(q: dict) -> str:
    return str(q.get("qid") or q.get("id") or "")


def bare_id(qid: str) -> str:
    """The id with a leading `setN.` dropped: the field a reader is proven on."""
    return _SET_PREFIX.sub("", qid)


def determinism(question: dict, judged=()) -> str:
    """DETERMINISTIC unless the question or the lane's `judged` globs say JUDGED."""
    v = question.get("determinism")
    if v is not None:
        if v not in (DETERMINISTIC, JUDGED):
            raise LookaheadError(f"question {qid_of(question)!r}: determinism {v!r}: use "
                                 f"{DETERMINISTIC!r} or {JUDGED!r}")
        return v
    bare = bare_id(qid_of(question))
    return JUDGED if any(fnmatch.fnmatchcase(bare, g) for g in judged) else DETERMINISTIC


def questions_in(body, where: str) -> tuple[dict, ...]:
    qs = body.get("questions") if isinstance(body, dict) else body
    if not isinstance(qs, list):
        raise LookaheadError(f"{where}: no question list (a list, or an object with 'questions')")
    seen, out = set(), []
    for i, q in enumerate(qs):
        if not isinstance(q, dict) or not qid_of(q):
            raise LookaheadError(f"{where}: question #{i + 1} has no id")
        qid = qid_of(q)
        if qid in seen:
            raise LookaheadError(f"{where}: id {qid!r} is asked twice")
        seen.add(qid)
        out.append(q)
    return tuple(out)


def read_questions(path: Path) -> tuple[dict, ...]:
    try:
        body = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LookaheadError(f"{path}: questions file not there") from None
    except (OSError, ValueError) as e:
        raise LookaheadError(f"{path}: not readable JSON ({type(e).__name__}: {e})") from None
    return questions_in(body, str(path))


# ------------------------------------------------------------------------------------ encodings


def _strip_ws(data: bytes) -> bytes:
    """Line breaks and the blanks around the text go; a blank inside a line does not (plain text whose
    words happen to be base64 letters must not decode)."""
    return data.strip().replace(b"\r", b"").replace(b"\n", b"")


def _stream(dec, data: bytes, what: str) -> bytes:
    out = dec.decompress(data, MAX_DECODED + 1)
    if len(out) > MAX_DECODED:
        raise EncodingMismatch(f"{what}: decodes past {MAX_DECODED} bytes")
    if not dec.eof:
        raise EncodingMismatch(f"{what}: truncated stream")
    if dec.unused_data:
        raise EncodingMismatch(f"{what}: {len(dec.unused_data)} byte(s) after the stream")
    return out


def _layer(codec: str, data: bytes) -> bytes:
    try:
        if codec == "base64":
            s = _strip_ws(data)
            if not s:
                raise EncodingMismatch("base64: empty")
            return base64.b64decode(s, validate=True)
        if codec == "base64url":
            s = _strip_ws(data)
            if not s or not re.fullmatch(rb"[A-Za-z0-9_-]+={0,2}", s):
                raise EncodingMismatch("base64url: not url-safe base64 text")
            return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
        if codec == "base32":
            s = _strip_ws(data)
            if not s:
                raise EncodingMismatch("base32: empty")
            return base64.b32decode(s)
        if codec == "hex":
            s = _strip_ws(data)
            if not s or not re.fullmatch(rb"[0-9A-Fa-f]+", s) or len(s) % 2:
                raise EncodingMismatch("hex: not an even run of hex digits")
            return bytes.fromhex(s.decode("ascii"))
        if codec == "zlib":
            return _stream(zlib.decompressobj(), data, "zlib")
        if codec == "gzip":
            return _stream(zlib.decompressobj(wbits=31), data, "gzip")
        if codec == "bz2":
            return _stream(bz2.BZ2Decompressor(), data, "bz2")
        if codec == "xz":
            return _stream(lzma.LZMADecompressor(), data, "xz")
        if codec == "utf-16le":
            if len(data) % 2:
                raise EncodingMismatch("utf-16le: odd length")
            return data.decode("utf-16-le", errors="strict").encode("utf-8")
        if codec == "reverse":
            return data[::-1]
    except EncodingMismatch:
        raise
    except (binascii.Error, ValueError, zlib.error, OSError, lzma.LZMAError, EOFError, UnicodeError) as e:
        raise EncodingMismatch(f"{codec}: {type(e).__name__}: {str(e)[:120]}") from None
    raise LookaheadError(f"codec {codec!r} is not known to the look-ahead (known: {', '.join(CODECS)})")


def check_chain(chain, where: str) -> tuple[str, ...]:
    if not isinstance(chain, (list, tuple)) or not chain or not all(isinstance(c, str) for c in chain):
        raise LookaheadError(f"{where}: an encoding is a non-empty list of codec names")
    for c in chain:
        if c not in CODECS:
            raise LookaheadError(f"{where}: codec {c!r} is not known to the look-ahead "
                                 f"(known: {', '.join(CODECS)}); add a decoder before using it")
    if "raw" in chain and len(chain) != 1:
        raise LookaheadError(f"{where}: 'raw' stands alone (a member delivered as is)")
    return tuple(chain)


def decode_chain(chain, data: bytes) -> bytes:
    """Decode `data` through `chain`, outermost first; EncodingMismatch names the first layer that does
    not hold."""
    chain = check_chain(chain, "encoding")
    if chain == ("raw",):
        return data
    for i, codec in enumerate(chain):
        try:
            data = _layer(codec, data)
        except EncodingMismatch as e:
            raise EncodingMismatch(f"layer {i + 1} of {'+'.join(chain)}: {e}") from None
    return data


def bad_encodings(spec: Specimen) -> list[tuple[str, str]]:
    """[(member, why)] for each member whose bytes do not carry its claimed chain."""
    out = []
    for m in sorted(spec.sizes):
        try:
            decode_chain(spec.encodings[m], (spec.files_dir / m).read_bytes())
        except EncodingMismatch as e:
            out.append((m, str(e)))
    return out


# ------------------------------------------------------------------------------------------ load


def _toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LookaheadError(f"{path}: not there") from None
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise LookaheadError(f"{path}: not readable TOML ({e})") from None


def _unknown(raw: dict, allowed: set, where: str) -> None:
    extra = sorted(set(raw) - allowed)
    if extra:
        raise LookaheadError(f"{where}: unknown key(s) {', '.join(extra)} (allowed: {', '.join(sorted(allowed))})")


def _strs(v, where: str) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise LookaheadError(f"{where}: expected a list of non-empty strings")
    return tuple(v)


def _int(v, where: str, minimum: int = 1) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        raise LookaheadError(f"{where}: expected an integer >= {minimum}")
    return v


def _lane(name: str, raw, mdir: Path) -> LaneConfig:
    where = f"{mdir / MATRIX_FILE} [lane.{name}]"
    if not _LANE_NAME.match(name):
        raise LookaheadError(f"{where}: lane names are lower-case words")
    if not isinstance(raw, dict):
        raise LookaheadError(f"{where}: expected a table")
    _unknown(raw, _LANE_KEYS, where)
    reader = raw.get("reader")
    if not isinstance(reader, str) or not reader:
        raise LookaheadError(f"{where}: reader (the module with solve_set) is required")
    judged = _strs(raw.get("judged", []), f"{where} judged")
    timeout = raw.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise LookaheadError(f"{where}: timeout must be a positive number of seconds")
    encs = raw.get("real_encodings", [])
    if not isinstance(encs, list):
        raise LookaheadError(f"{where} real_encodings: expected a list of codec lists")
    real = tuple(check_chain(c, f"{where} real_encodings #{i + 1}") for i, c in enumerate(encs))
    allow_unsure = raw.get("allow_unsure", False)
    if not isinstance(allow_unsure, bool):
        raise LookaheadError(f"{where}: allow_unsure must be true or false")
    ths = []
    for i, t in enumerate(raw.get("threshold", [])):
        tw = f"{where} threshold #{i + 1}"
        if not isinstance(t, dict):
            raise LookaheadError(f"{tw}: expected a table")
        _unknown(t, _THRESHOLD_KEYS, tw)
        if not isinstance(t.get("name"), str) or not t["name"]:
            raise LookaheadError(f"{tw}: name is required")
        measure = t.get("measure", "total")
        if measure not in MEASURES:
            raise LookaheadError(f"{tw}: measure {measure!r}: use one of {', '.join(MEASURES)}")
        ths.append(Threshold(t["name"], _int(t.get("bytes"), f"{tw} bytes"), measure))

    def rel(key):
        v = raw.get(key)
        if v is None:
            return None
        if not isinstance(v, str) or not v:
            raise LookaheadError(f"{where}: {key} is a path")
        p = mdir / v
        if not p.is_file():
            raise LookaheadError(f"{where}: {key} {v!r} is not a file under the matrix")
        return p

    return LaneConfig(name, reader, judged, rel("base"), rel("previous"), float(timeout), real, tuple(ths),
                      allow_unsure)


def load_specimen(lane: str, sdir: Path) -> Specimen:
    where = str(sdir / SPECIMEN_FILE)
    raw = _toml(sdir / SPECIMEN_FILE)
    _unknown(raw, _SPECIMEN_KEYS, where)
    skip = raw.get("skip", "")
    if not isinstance(skip, str):
        raise LookaheadError(f"{where}: skip is a reason (a string)")
    note = raw.get("note", "")
    if not isinstance(note, str):
        raise LookaheadError(f"{where}: note is a string")
    ctx = raw.get("ctx", {})
    if not isinstance(ctx, dict):
        raise LookaheadError(f"{where}: [ctx] is a table")
    questions = read_questions(sdir / QUESTIONS_FILE)
    key = None
    if (sdir / KEY_FILE).exists():
        try:
            key = json.loads((sdir / KEY_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise LookaheadError(f"{sdir / KEY_FILE}: not readable JSON ({e})") from None
        if not isinstance(key, dict):
            raise LookaheadError(f"{sdir / KEY_FILE}: expected an object {{id: answer}}")
        asked = {qid_of(q) for q in questions}
        extra = sorted(set(key) - asked)
        if extra:
            raise LookaheadError(f"{sdir / KEY_FILE}: answers id(s) no question asks: {', '.join(extra[:5])}")
    fdir = sdir / FILES_DIR
    sizes = {}
    if fdir.is_dir():
        for p in sorted(fdir.rglob("*")):
            if p.is_symlink():
                raise LookaheadError(f"{where}: member {p.relative_to(fdir)} is a symlink")
            if p.is_file():
                sizes[p.relative_to(fdir).as_posix()] = p.stat().st_size
    encodings = {}
    if not skip:
        if not sizes:
            raise LookaheadError(f"{where}: no member under files/ (a specimen delivers something)")
        if "encoding" not in raw:
            raise LookaheadError(f"{where}: encoding is required (the delivery's codec chain; [\"raw\"] "
                                 "when delivered as is)")
        default = check_chain(raw["encoding"], f"{where} encoding")
        per = raw.get("encodings", {})
        if not isinstance(per, dict):
            raise LookaheadError(f"{where}: [encodings] is a table of member path -> chain")
        stray = sorted(set(per) - set(sizes))
        if stray:
            raise LookaheadError(f"{where}: [encodings] names member(s) not under files/: {', '.join(stray)}")
        for m in sizes:
            encodings[m] = check_chain(per[m], f"{where} encodings.{m}") if m in per else default
    return Specimen(lane, sdir.name, sdir, questions, key, encodings, skip, note, ctx, sizes)


def load(matrix_dir) -> Matrix:
    mdir = Path(matrix_dir)
    if not mdir.is_dir():
        raise LookaheadError(f"{mdir}: no matrix folder")
    raw = _toml(mdir / MATRIX_FILE)
    _unknown(raw, _MATRIX_KEYS, str(mdir / MATRIX_FILE))
    lanes_raw = raw.get("lane", {})
    if not isinstance(lanes_raw, dict) or not lanes_raw:
        raise LookaheadError(f"{mdir / MATRIX_FILE}: no [lane.<name>] table")
    lanes = {name: _lane(name, v, mdir) for name, v in lanes_raw.items()}
    for d in sorted(p for p in mdir.iterdir() if p.is_dir() and not p.name.startswith(".")):
        if (d / SPECIMEN_FILE).exists():
            raise LookaheadError(f"{d}: a specimen directly under the matrix; put it under <lane>/")
        if any(c.is_dir() and (c / SPECIMEN_FILE).exists() for c in d.iterdir()) and d.name not in lanes:
            raise LookaheadError(f"{d}: specimens for lane {d.name!r}, which matrix.toml does not declare")
    specimens = {}
    for name in lanes:
        ld = mdir / name
        found = []
        if ld.is_dir():
            for sd in sorted(p for p in ld.iterdir() if p.is_dir()):
                if not (sd / SPECIMEN_FILE).exists():
                    raise LookaheadError(f"{sd}: no {SPECIMEN_FILE}")
                found.append(load_specimen(name, sd))
        specimens[name] = tuple(found)
    skipped = []
    for i, s in enumerate(raw.get("skipped", [])):
        where = f"{mdir / MATRIX_FILE} [[skipped]] #{i + 1}"
        if not isinstance(s, dict):
            raise LookaheadError(f"{where}: expected a table")
        _unknown(s, _SKIPPED_KEYS, where)
        for k in ("lane", "name", "reason"):
            if not isinstance(s.get(k), str) or not s[k]:
                raise LookaheadError(f"{where}: {k} is required")
        if s["lane"] not in lanes:
            raise LookaheadError(f"{where}: lane {s['lane']!r} is not declared")
        ids = _int(s["ids"], f"{where} ids", 0) if "ids" in s else None
        skipped.append(GeneratorSkip(s["lane"], s["name"], s["reason"], ids))
    waivers = []
    for i, w in enumerate(raw.get("waived_threshold", [])):
        where = f"{mdir / MATRIX_FILE} [[waived_threshold]] #{i + 1}"
        if not isinstance(w, dict):
            raise LookaheadError(f"{where}: expected a table")
        _unknown(w, _WAIVED_KEYS, where)
        if not isinstance(w.get("reason"), str) or not w["reason"]:
            raise LookaheadError(f"{where}: a waiver needs its reason")
        whr = w.get("where", "*")
        if not isinstance(whr, str) or not whr:
            raise LookaheadError(f"{where}: where is a path glob")
        waivers.append(Waiver(_int(w.get("bytes"), f"{where} bytes"), w["reason"], whr))
    return Matrix(mdir, lanes, specimens, tuple(skipped), tuple(waivers))
