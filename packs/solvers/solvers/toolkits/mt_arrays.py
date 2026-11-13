#!/usr/bin/env python3
"""Toolkit mt_arrays: find MT19937 word arrays in a challenge's decoded files, then clone and rewind (B-063).

A key journal, a log or a dump that holds 624 or more consecutive 32-bit words of one Mersenne
Twister gives away the whole generator: every later output, and every earlier one too. This engine
reads each handout file as a structure, tests every list of numbers in it, and for each stretch
that is MT19937 reports the recovered state, the outputs that follow and the outputs that came
before (the inverse twist), plus the seed when the stream's start is in reach.

What is read (the sweep's scratch copy `unpacked/` when there is one, else `files/`, else the folder)
  JSON, JSON lines, CBOR, MessagePack   every list in the value tree: a list of integers; integers
                                        wider than 32 bits split into words (both word orders);
                                        signed int32; numeric strings; a list of rows, joined; one
                                        field of a list of records; byte strings and long hex or
                                        base64 strings as little- and big-endian uint32
  text                                  the integers in it, in order (decimal or 0x hex), the last
                                        integer of each line (`out[3] = 123`), or 8-digit hex words
  anything else                         the whole file as little- and big-endian uint32, from offset 0

Each list is tested two ways: as outputs (tempered, what `getrandbits(32)` returns) and as raw state
words (a dumped table). The proof is in solvers/common/modern_crypto.py (`mt_runs`): the words follow
the generator's recurrence. `verified` counts the words beyond the first 624 that were reproduced.
A finding with 0 verified rests on a 31-bit self-check alone and is marked UNVERIFIED: do not answer
from it without another check.

It stops at the recovered state. How outputs become keys (how many words per record, which hash, which
counter) is the challenge's own schedule, read from its fields or its brief: that step is the solver's.

Engine contract: `solve(challenge_dir, profile, **opts)`; opts `rewind` and `forward` (outputs to
report before and after each stretch, default 624 each, at most 65536), `seed_search` (outputs before
the stretch to walk back over looking for the seeding, default 4096), `seconds` (CPU budget, default
20), `out` (folder for mt_arrays.json, default <challenge>/recon/mt_arrays). Status `unsure` when a
stretch was found (the state is recovered, the flag is not), `none` when every file was read and
nothing was found. Never `solved`: it names no flag.

CLI: `python -m ctf run toolkits.mt_arrays <challenge_dir>` (the contract), or on files directly:
  tools/ctfpy solvers/toolkits/mt_arrays.py FILE... [--rewind N] [--forward N] [--seed-search N]
                                             [--seconds S] [--out DIR] [--json]
Offline: no network, no child process, nothing executed.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)
for _p in (str(HERE), str(COMMON)):
    if _p not in sys.path:
        sys.path.append(_p)
import wire_decode                              # noqa: E402
from _shadowed import common_module             # noqa: E402

mc = common_module("modern_crypto")             # solvers/common/modern_crypto.py, never the toolkit face

ENGINE = "toolkits.mt_arrays"
SCHEMA = 1
REPORT_NAME = "mt_arrays.json"
MAX_FILE = 8 << 20                    # a larger file is not read (and is named)
MAX_FILES = 500                       # files of one challenge that are read
MAX_SPLIT = 624                       # widest integer split into words: getrandbits(19968)
DEFAULT_COUNT = 624                   # outputs reported before and after a stretch: one generation
DEFAULT_SECONDS = 20.0                # CPU seconds
WORDS = 624
SKIP_DIRS = {"recon", ".git", ".ctf"}
SKIP_FILES = {".sweep.json", ".sweep-owner", ".lock", "challenge.json", "notes.md", "triage.md"}
# Read first, and kept when MAX_FILES cuts: the structured and text files intake selects the engine on
# (the manifest's [intake] match). A web handout's package.json brings the engine in; its images and
# bundles come after the files that can hold a word list, and only while budget is left.
FIRST_SUFFIXES = {".cbor", ".msgpack", ".json", ".jsonl", ".txt"}
MASK = 0xFFFFFFFF


class OptionError(ValueError):
    """An option outside its bounds: the engine does not run (status blocked)."""


# ---- reading a file as a value ---------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_BUDGET_ERRORS = ("too many items", "too deep")


def read_document(data: bytes):
    """(format, value, note) for a file's bytes. format: `json` / `jsonl` / `cbor` / `msgpack` (value
    is the decoded tree), `text` (value is the str) or `raw` (value is the bytes). `note` is set when
    a structured decode was cut by the decoder's own size bounds, so the file is read as `raw` and the
    reader says why."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and not _CONTROL.search(text):
        body = text.strip()
        if body[:1] in ("[", "{"):
            try:
                return "json", json.loads(body), None
            except (ValueError, RecursionError):
                pass
            rows = []
            for line in body.splitlines():
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except (ValueError, RecursionError):
                    rows = None
                    break
            if rows and len(rows) > 1:
                return "jsonl", rows, None
        return "text", text, None
    note = None
    for name, decode in (("cbor", wire_decode.decode_cbor), ("msgpack", wire_decode.decode_msgpack)):
        try:
            value = decode(data)
        except (ValueError, struct.error, IndexError, RecursionError) as exc:
            if note is None and any(reason in str(exc) for reason in _BUDGET_ERRORS):
                note = f"{name} decode stopped at the decoder's bound ({exc}); read as raw words instead"
            continue
        if isinstance(value, (list, dict)):
            return name, value, None
    return "raw", data, note


# ---- every reading of a value as lists of 32-bit words ---------------------------------------------

@dataclass(frozen=True)
class View:
    path: str                         # where in the value: $.journal.registers, $[3], $.records[*].word
    reading: str                      # how the numbers were read as words
    words: list


_DEC = re.compile(r"-?\d{1,4300}\Z")          # int() refuses longer decimal strings
_HEX = re.compile(r"(?:0[xX])?[0-9a-fA-F]{1,5000}\Z")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]+={0,2}\Z")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_INT_TOKEN = re.compile(r"(?<![\w.])-?(?:0[xX][0-9a-fA-F]+|\d{1,4300})(?![\w.])")
_HEX_WORD = re.compile(r"[0-9a-fA-F]{8}\Z")


def numbers(items):
    """`items` as a list of ints when every item is an int (never a bool) or every item is a numeric
    string of one kind (decimal, or hex with or without 0x), else None."""
    if not items:
        return None
    if all(type(v) is int for v in items):
        return items
    if all(isinstance(v, str) for v in items):
        if all(_DEC.match(v) for v in items):
            return [int(v) for v in items]
        if all(_HEX.match(v) for v in items):
            return [int(v, 16) for v in items]
    return None


def word_readings(ints):
    """[(how, words)]: the ways a list of integers reads as >= 624 32-bit words. Unsigned 32-bit
    values as they are; signed 32-bit ones as two's complement; wider non-negative ones split into
    equal runs of words, in both orders (CPython's getrandbits(k) puts the first word lowest; C code
    that packs two draws usually puts it highest)."""
    if not ints:
        return []
    low, high = min(ints), max(ints)
    if low >= 0 and high <= MASK:
        return [("", ints)] if len(ints) >= WORDS else []
    if low >= -(1 << 31) and high < 1 << 31:
        return [("as two's-complement int32", [v & MASK for v in ints])] if len(ints) >= WORDS else []
    if low < 0:
        return []
    width = (high.bit_length() + 31) // 32
    if width > MAX_SPLIT or len(ints) * width < WORDS:
        return []
    return [(f"each split into {width} 32-bit words, low word first",
             [v >> 32 * i & MASK for v in ints for i in range(width)]),
            (f"each split into {width} 32-bit words, high word first",
             [v >> 32 * i & MASK for v in ints for i in reversed(range(width))])]


def byte_readings(data: bytes):
    """[(how, words)]: a byte string of >= 2496 bytes as little- and big-endian uint32 from its
    start (a tail of 1-3 bytes is left off)."""
    count = len(data) // 4
    if count < WORDS:
        return []
    return [("as little-endian uint32", list(struct.unpack_from(f"<{count}I", data))),
            ("as big-endian uint32", list(struct.unpack_from(f">{count}I", data)))]


def _string_bytes(text: str):
    """(encoding, bytes) for a long hex or base64 string, else None."""
    if len(text) >= WORDS * 8 and _HEX_RUN.match(text):
        return "hex", bytes.fromhex(text)
    if len(text) >= WORDS * 4 * 4 // 3 and _B64_RUN.match(text):
        try:
            raw = base64.b64decode(text.replace("-", "+").replace("_", "/") + "=" * (-len(text) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None
        return "base64", raw
    return None


def _child(path: str, key) -> str:
    if isinstance(key, str) and _IDENT.match(key):
        return f"{path}.{key}"
    return f"{path}[{json.dumps(key) if isinstance(key, str) else repr(key)}]"


def _flat(rows):
    """The rows of a list of lists joined, as ints, or None when a row is not a list of numbers."""
    out = []
    for row in rows:
        got = numbers(row) if isinstance(row, list) else None
        if got is None:
            return None
        out.extend(got)
    return out


def _list_views(items, path, label):
    """Views of one list (or one column of a list of records)."""
    got = numbers(items)
    if got is not None:
        for how, words in word_readings(got):
            yield View(path, " ".join(x for x in (label, how) if x), words)
        return
    if all(isinstance(v, list) for v in items):
        flat = _flat(items)
        if flat is not None:
            for how, words in word_readings(flat):
                yield View(path, " ".join(x for x in (f"{label}, rows joined", how) if x), words)
    elif all(isinstance(v, (bytes, bytearray)) for v in items):
        for how, words in byte_readings(b"".join(items)):
            yield View(path, f"{label}, byte strings joined, {how}", words)


def views(value, path: str = "$"):
    """Every reading of a decoded value as a list of >= 624 32-bit words, with where it is, in
    document order. No recursion and no depth cut: the tree is as deep as its decoder allowed."""
    stack = [(value, path)]
    while stack:
        value, path = stack.pop()
        if isinstance(value, (bytes, bytearray)):
            for how, words in byte_readings(bytes(value)):
                yield View(path, f"byte string {how}", words)
        elif isinstance(value, str):
            got = _string_bytes(value)
            if got is not None:
                for how, words in byte_readings(got[1]):
                    yield View(path, f"{got[0]} string {how}", words)
        elif isinstance(value, dict):
            stack.extend(reversed([(child, _child(path, key)) for key, child in value.items()]))
        elif isinstance(value, list) and value:
            yield from _list_views(value, path, "integers")
            if all(isinstance(v, dict) for v in value):
                for key in value[0]:
                    if all(key in v for v in value):
                        yield from _list_views([v[key] for v in value], _child(f"{path}[*]", key),
                                               "one field of each record")
            stack.extend(reversed([(child, f"{path}[{i}]") for i, child in enumerate(value)
                                   if isinstance(child, (list, dict, bytes, bytearray, str))]))


def text_views(text: str):
    """The integers written in a text, in order, or its 8-digit hex words."""
    tokens = text.replace(",", " ").split()
    if len(tokens) >= WORDS and all(_HEX_WORD.match(t) for t in tokens):
        yield View("$", "8-digit hex words", [int(t, 16) for t in tokens])
        return
    lines = [_INT_TOKEN.findall(line) for line in text.splitlines()]
    every = [t for found in lines for t in found]
    last = [found[-1] for found in lines if found]
    # `out[3] = 123` and `3: 123` carry an index on every line: the last integer of each line is the value
    readings = [("integers in the text, in order", every)]
    if len(last) != len(every):
        readings.append(("the last integer on each line", last))
    for label, tokens in readings:
        ints = [int(t, 16) if "x" in t.lower() else int(t) for t in tokens]
        for how, words in word_readings(ints):
            yield View("$", " ".join(x for x in (label, how) if x), words)


def document_views(fmt: str, value):
    if fmt == "text":
        return text_views(value)
    if fmt == "raw":
        return (View("$", f"whole file {how}", words) for how, words in byte_readings(value))
    return views(value)


# ---- findings --------------------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    format: str
    path: str
    reading: str
    mode: str                         # outputs | state
    start: int                        # index of the stretch's first word in the list as read
    length: int
    verified: int                     # words beyond the first 624 reproduced by the recurrence
    state: list                       # the stretch's last 624 state words: setstate((3, (*state, 624), None)) continues it
    next: list                        # what follows the stretch, in the list's own form
    previous: list                    # what came before it, oldest first
    seed: dict | None = None          # mt_seed_search: where the stream began, when in reach
    also_at: list = field(default_factory=list)

    @property
    def proven(self) -> bool:
        return self.verified > 0

    def to_dict(self) -> dict:
        return {
            "file": self.file, "format": self.format, "path": self.path, "reading": self.reading,
            "mode": self.mode, "start": self.start, "length": self.length, "verified": self.verified,
            "proven": self.proven,
            "state": {"words": self.state, "index": WORDS,
                      "note": "raw state words after the stretch's last word; index 624 = twist next"},
            "next": {"first_index": self.start + self.length, "values": self.next},
            "previous": {"first_index": self.start - len(self.previous), "values": self.previous},
            "seed": self.seed, "also_at": self.also_at,
        }

    def line(self) -> str:
        what = "outputs" if self.mode == "outputs" else "raw state words"
        if not self.proven:
            proof = "UNVERIFIED: 31-bit self-check only, 0 further words; do not answer from it alone"
        elif self.verified >= WORDS:
            proof = f"{self.verified} verified by the recurrence (every given word checked)"
        else:
            proof = (f"{self.verified} verified by the recurrence (under 624: not every given word is "
                     "read by a check)")
        text = (f"MT19937 {what}: {self.length} consecutive 32-bit words at {self.path} "
                f"({self.reading}), index {self.start}..{self.start + self.length - 1}; {proof}")
        if self.seed:
            text += f"; {seed_line(self.seed)}"
        return text


def seed_line(seed: dict) -> str:
    k = seed["outputs_before"]
    if seed["kind"] == "init_genrand":
        how = f"init_genrand({seed['seed']})"
    elif "python_seed_bytes" in seed:
        how = f"random.seed(bytes.fromhex('{seed['python_seed_bytes']}')) (the text or bytes seed)"
    elif seed["python_seed"].bit_length() <= 256:
        how = f"random.seed({seed['python_seed']})"
    else:
        how = f"init_by_array, a {len(seed['key'])}-word key"
    return f"stream seeded by {how}, {k} output{'s' if k != 1 else ''} before this stretch"


@dataclass
class Report:
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)       # everything not read or not finished, with why
    files: int = 0
    lists: int = 0                                  # word lists tested
    complete: bool = True                           # False: the budget ran out before every list was tested
    partial: bool = False                           # True: a list over MAX_MT_SCAN_WORDS was tested in part

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "engine": ENGINE, "files": self.files, "lists": self.lists,
                "complete": self.complete, "partial": self.partial,
                "findings": [f.to_dict() for f in self.findings], "notes": self.notes}


def _count(name: str, value, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise OptionError(f"option {name}={value!r} must be an integer from {low} to {high}")
    return value


def findings_in(view: View, *, rewind: int, forward: int, seed_search: int) -> list:
    """The MT19937 stretches of one word list, each with its state, what follows and what came before."""
    out = []
    for run in mc.mt_runs(view.words):
        tempered = run["mode"] == "outputs"
        given = view.words[run["start"]:run["start"] + run["length"]]
        x = [mc.mt_untemper(v) for v in given] if tempered else given
        before, _ = mc.mt_extend(x[:WORDS], before=rewind)
        _, after = mc.mt_extend(x[-WORDS:], after=forward)
        seed = mc.mt_seed_search(x[:WORDS], max_outputs=seed_search) if seed_search else None
        if seed is not None and seed["outputs_before"] < len(before):
            before = before[len(before) - seed["outputs_before"]:]      # nothing was drawn before the seeding
        if tempered:
            before, after = [mc.mt_temper(v) for v in before], [mc.mt_temper(v) for v in after]
        out.append(Finding(file="", format="", path=view.path, reading=view.reading,
                           mode=run["mode"], start=run["start"], length=run["length"],
                           verified=run["verified"], state=x[-WORDS:], next=after, previous=before, seed=seed))
    return out


def read_file(path: Path) -> bytes:
    """A file's bytes, at most MAX_FILE of them: a file that grew past the bound since it was listed
    raises OSError (named in the report, like any file that cannot be read)."""
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise OSError(f"over {MAX_FILE >> 20} MiB")
    return data


def examine(files: dict, *, rewind: int = DEFAULT_COUNT, forward: int = DEFAULT_COUNT,
            seed_search: int | None = None, seconds: float = DEFAULT_SECONDS, clock=time.process_time) -> Report:
    """Test every word list of `files` ({name: bytes, or a Path read when its turn comes}). `clock`
    measures the budget (CPU seconds by default); a file is only read, and a list only started, while
    budget is left, and what was not read or tested is named. One file is held in memory at a time."""
    rewind = _count("rewind", rewind, 0, mc.MAX_MT_REWIND)
    forward = _count("forward", forward, 0, mc.MAX_MT_REWIND)
    seed_search = _count("seed_search", mc.MT_SEED_SEARCH if seed_search is None else seed_search,
                         0, mc.MAX_MT_REWIND - WORDS)
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not seconds > 0:
        raise OptionError(f"option seconds={seconds!r} must be a positive number")
    rep, seen, t0 = Report(), {}, clock()
    for name, data in files.items():
        if rep.complete and clock() - t0 >= seconds:
            rep.complete = False
        if not rep.complete:
            rep.notes.append(f"{name}: not read, the budget of {seconds:g} s was spent")
            continue
        if isinstance(data, Path):
            try:
                data = read_file(data)
            except OSError as exc:
                rep.notes.append(f"{name}: not read ({exc.strerror or exc})")
                continue
        rep.files += 1
        fmt, value, note = read_document(data)
        if note:
            rep.notes.append(f"{name}: {note}")
        for view in document_views(fmt, value):
            if clock() - t0 >= seconds:
                rep.complete = False
                rep.notes.append(f"{name}: stopped at {view.path} ({view.reading}): "
                                 f"the budget of {seconds:g} s was spent")
                break
            rep.lists += 1
            if len(view.words) > mc.MAX_MT_SCAN_WORDS:
                rep.partial = True
                rep.notes.append(f"{name}: {view.path} ({view.reading}): only the first {mc.MAX_MT_SCAN_WORDS} "
                                 f"of {len(view.words)} words were tested")
                view = View(view.path, view.reading, view.words[:mc.MAX_MT_SCAN_WORDS])
            for f in findings_in(view, rewind=rewind, forward=forward, seed_search=seed_search):
                f.file, f.format = name, fmt
                key = (f.mode, f.length, tuple(f.state))
                if key in seen:                 # the same words reached by another reading (a row and its join)
                    seen[key].also_at.append(f"{name} {f.path} ({f.reading})")
                    continue
                seen[key] = f
                rep.findings.append(f)
    rep.findings.sort(key=lambda f: not f.proven)       # proven stretches first, file order kept
    return rep


# ---- the engine contract ---------------------------------------------------------------------------

def challenge_files(challenge_dir: Path, notes: list | None = None) -> dict:
    """{relative name: Path} of a challenge's files, none of them read yet (examine reads one at a
    time): the sweep's scratch copy (`unpacked/`, originals and archive members) when there is one,
    else `files/`, else the folder itself. The structured and text files (FIRST_SUFFIXES) come first,
    each group in path order. Recon output, links and the sweep's own files are left out; a file over
    MAX_FILE or past MAX_FILES is named in `notes`."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    notes = notes if notes is not None else []
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if n in SKIP_FILES or p.is_symlink() or not p.is_file():
                continue
            found.append(p)
    found.sort(key=lambda p: p.suffix.lower() not in FIRST_SUFFIXES)      # stable: path order kept in each group
    out = {}
    for p in found:
        rel = str(p.relative_to(challenge_dir))
        if p.stat().st_size > MAX_FILE:
            notes.append(f"{rel}: not read, over {MAX_FILE >> 20} MiB")
        elif len(out) >= MAX_FILES:
            notes.append(f"{rel}: not read, past the first {MAX_FILES} files")
        else:
            out[rel] = p
    return out


def result_of(rep: Report, *, seconds: float = 0.0, report_path: str | None = None, challenge_id=None):
    from ctf.result import Cost, Evidence, SolverResult
    where = f" State, following and earlier outputs: {report_path}." if report_path else ""
    evidence = tuple(Evidence("match" if f.proven else "unverified", f.line(), path=f.file) for f in rep.findings)
    notes = list(rep.notes)
    if rep.findings:
        proven = sum(f.proven for f in rep.findings)
        head = (f"{len(rep.findings)} MT19937 stretch{'es' if len(rep.findings) != 1 else ''} "
                f"({proven} proven, {len(rep.findings) - proven} unverified) in {rep.lists} word lists "
                f"of {rep.files} files.{where} The generator is recovered, the flag is not: map the "
                "outputs to keys with the challenge's own schedule.")
        status = "unsure"
    else:
        head = f"no MT19937 stretch in {rep.lists} word lists of {rep.files} files"
        status = "none" if rep.complete and not rep.partial else "unsure"
        if not rep.complete:
            head += " (not every list was tested)"
        elif rep.partial:
            head += " (not every list was tested in full)"
    return SolverResult(status=status, evidence=evidence, cost=Cost(seconds=round(seconds, 3)), engine=ENGINE,
                        challenge_id=challenge_id, notes="; ".join([head] + notes))


def write_report(rep: Report, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / REPORT_NAME
    path.write_text(json.dumps(rep.to_dict(), indent=1) + "\n", encoding="utf-8")
    return path


OPTIONS = ("rewind", "forward", "seed_search", "seconds", "out")


def _options(opts: dict) -> dict:
    unknown = sorted(set(opts) - set(OPTIONS))
    if unknown:
        raise OptionError(f"unknown option {', '.join(unknown)}; known: {', '.join(OPTIONS)}")
    return {k: opts[k] for k in OPTIONS[:4] if opts.get(k) is not None}


def solve(challenge_dir, profile, **opts):
    """Engine contract (the module docstring lists the options). The profile is not read: the engine
    names no flag."""
    from ctf.result import SolverResult
    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    notes: list = []
    try:
        options = _options(opts)
        rep = examine(challenge_files(challenge_dir, notes), **options)
    except (FileNotFoundError, OptionError) as exc:
        return SolverResult(status="blocked", engine=ENGINE, notes=str(exc))
    rep.notes[:0] = notes
    report_path = None
    if rep.findings:
        out_dir = Path(opts["out"]) if opts.get("out") else challenge_dir / "recon" / "mt_arrays"
        written = write_report(rep, out_dir)
        try:
            report_path = str(written.relative_to(challenge_dir))
        except ValueError:
            report_path = str(written)
    return result_of(rep, seconds=time.monotonic() - t0, report_path=report_path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mt_arrays.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--rewind", type=int, default=DEFAULT_COUNT, help="outputs to report before each stretch")
    ap.add_argument("--forward", type=int, default=DEFAULT_COUNT, help="outputs to report after each stretch")
    ap.add_argument("--seed-search", type=int, default=None,
                    help="outputs before the stretch to walk back over looking for the seeding")
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS, help="CPU budget")
    ap.add_argument("--out", type=Path, help=f"folder for {REPORT_NAME} (default: not written)")
    ap.add_argument("--json", action="store_true", help="print the whole report as JSON before the result")
    a = ap.parse_args(argv)
    missing = [str(p) for p in a.files if not p.is_file()]
    if missing:
        print(f"mt_arrays.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    too_big = [str(p) for p in a.files if p.stat().st_size > MAX_FILE]
    if too_big:
        print(f"mt_arrays.py: over {MAX_FILE >> 20} MiB, not read: {', '.join(too_big)}", file=sys.stderr)
        return 2
    t0 = time.monotonic()
    try:
        rep = examine({str(p): p.read_bytes() for p in a.files}, rewind=a.rewind, forward=a.forward,
                      seed_search=a.seed_search, seconds=a.seconds)
    except OptionError as exc:
        print(f"mt_arrays.py: {exc}", file=sys.stderr)
        return 2
    report_path = str(write_report(rep, a.out)) if a.out and rep.findings else None
    if a.json:
        print(json.dumps(rep.to_dict(), indent=1))
    for f in rep.findings:
        print(f"{f.file}: {f.line()}")
        if not a.json:
            print(f"  previous {len(f.previous)} (oldest first): {f.previous[:4]} ... {f.previous[-4:]}"
                  if len(f.previous) > 8 else f"  previous: {f.previous}")
            print(f"  next {len(f.next)}: {f.next[:4]} ... {f.next[-4:]}" if len(f.next) > 8 else f"  next: {f.next}")
    for n in rep.notes:
        print(f"note: {n}")
    print(result_of(rep, seconds=time.monotonic() - t0, report_path=report_path).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
