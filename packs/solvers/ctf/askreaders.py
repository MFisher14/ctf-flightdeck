"""Ask every reader before STOP on a MISSING id (B-139).

A cumulative base stops for a human or an agent when one question id has no rule after the lane's
bank-only pass, even when some reader of the repo already reads that fact (Huntress Day 9: Metadata's
`pe.coff_machine_u16_hex` while the `pe.machine` reader existed; Day 10: the same class on two lanes).
This module is the pass that runs between the bank and the STOP:

    report = ask_missing(questions, answers, files, lane)   # answers: the bank-only pass, {qid: answer|None}
    report.answers          # the bank's answers, with an unsure offer for each MISSING id one fact answers
    report.stops()          # the ids that still stop the lane, each with its named reason
    solver = AskingSolver(lane_solve_set, "metadata")        # the same, as a lane solver wrapper
    probes = probe(report, gate_submit(gate, cid, "ask-readers"))   # one option per request, at the lane's turn

**MISSING.** An id whose bank-only answer is None, or that the answers do not hold. An unsure answer
(`??` + JSON, solvers/common/labels.py) is not MISSING: it is already an open key the runner probes.

**Readers.** `openers/readers.toml` registers every reader and field catalog (schema in that file;
unknown keys and a module that is not there are errors). A lane asks the readers that list it, then
those that list `"*"`, in file order, then the one-field files an agent wrote under
`<workdir>/ask-readers/<lane>/*.py` (kind `live`, call `solve_set`, loaded fresh on every ask). Each
reader is asked the one question alone, in process, with its stdout and stderr captured (kept, cut,
for triage). A reader that raises is `error`; one whose `needs_tools` are missing, or whose file does
not load, is `unavailable`; both are named in the report, never skipped in silence. With `budget`
seconds, a reader not started when the budget is spent is `skipped`, named. The capture swaps the
process-wide sys.stdout/stderr, so readers run one at a time under one lock (two threads asking at once
are serialised, never mixed); a thread that is not asking but prints while a reader runs has that output
captured with the reader's. A running reader is not killed: the budget stops only readers not yet started.

**One fact.** Each answer is a set of values: the options of an unsure answer (spellings of one fact,
by the labels contract), or the one plain value. A labels candidates answer (`#candidates` key)
carries different facts, so each of its options is its own. Answers whose value sets meet are one
fact (transitively). Then, per MISSING id:

  offer      exactly one fact: an unsure answer under the first answering reader's key (else
             `<lane>.ask/<field>`, the field being the id without `setN.` and in canonical form),
             options in reader order (plain values named after their reader), one per value, at most
             MAX_OPTIONS, names already rejected for that key in the labels ledger dropped. It is never
             plain, even when a reader's answer was: the probe settles it in one request.
  no_reader  no reader answered (a field no reader knows, the Day 10 row 196 class): the lane stops,
             and the reason lists every reader asked and what each said.
  conflict   two or more facts: the lane stops; nothing is guessed between readers.
  rejected   one fact, but every option of it was already rejected for the key.

A reader's literal `none` counts only when the question's own format allows it
(`idresolve.permits_literal_none`). Nothing here sends anything: an offer is a `??` string, which every
runner and the Game Master adapter refuse to submit.

**Probing.** `probe(report, submit)` sends each offer's options one per request, in order, through
`submit(answer_id, value) -> SubmitResult` (`gate_submit` wraps the SubmitGate: `<cid>#<answer id>`,
`allow_nonstandard`, the provenance). Accepted (correct or already solved) closes the id; incorrect
tries the next option; an unjudged answer (rate limited, paused, not allowed) holds every probe left,
uncounted. `on_verdict(key, name, "accepted"|"rejected")` is called for each judged option (the CLI
passes `labels.learn`). `stop()` (B-221: ctf.probetier.stop_for) is read before each send; once true,
every option left is not probed, so a held probe yields the lane to a waiting fixup.

**The agent case.** `write_template(lane, qid, asked)` writes a one-field reader for the id from
`templates/ask-readers/one_field.py`, with every reader's answer for it as comments (each one physical
line: line breaks, other control characters and lone surrogates escaped, since the values come from
challenge files and the next ask runs the file), into
`<workdir>/ask-readers/<lane>/`, where the next ask finds it. CLI: `python -m ctf ask-readers`
(`list`, `triage`, `template`, `probe`).
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import sys
import threading
import time
import unicodedata
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import idresolve, packs, paths

__all__ = ["AskError", "Reader", "ReaderAnswer", "Fact", "Asked", "AskReport", "Probe", "AskingSolver",
           "load_registry", "live_readers", "readers_for", "missing_ids", "ask_one", "ask_missing",
           "probe", "gate_submit", "template_text", "write_template", "field_of", "labels_module",
           "OFFER", "NO_READER", "CONFLICT", "REJECTED", "CALLS", "KINDS", "MAX_OPTIONS",
           "REGISTRY", "LIVE_DIR", "TEMPLATE"]

OFFER, NO_READER, CONFLICT, REJECTED = "offer", "no_reader", "conflict", "rejected"
ANSWERED, NONE, ERROR, UNAVAILABLE, SKIPPED = "answered", "none", "error", "unavailable", "skipped"
CALLS = {"solve_set": "solve_set", "fields": "fields", "apk": "solve_questions"}   # call -> default function
KINDS = ("reader", "catalog", "live")
MAX_OPTIONS = 12                     # labels.MAX_OPTIONS: options one unsure answer carries
REGISTRY = ("openers", "readers.toml")
LIVE_DIR = "ask-readers"             # <workdir>/ask-readers/<lane>/*.py
TEMPLATE = ("templates", "ask-readers", "one_field.py")
APK_MAX_BYTES = 256 << 20            # uncompressed members of one package handed to an apk reader
SAID_MAX = 6000                      # characters of a reader's own output kept for triage
TEMPLATE_SAID_LINES = 80             # lines of it a one-field template quotes per reader
_READER_KEYS = {"name", "lanes", "module", "call", "function", "kind", "needs_tools", "note"}
_SET = re.compile(r"set\d+\.(.+)\Z", re.S)
_CAPTURE = threading.RLock()         # sys.stdout/stderr are process-wide: one reader is captured at a time


class AskError(ValueError):
    """A registry, a lane or an input this pass cannot use; the message names it."""


# ------------------------------------------------------------------------------------------ registry

@dataclass(frozen=True)
class Reader:
    name: str
    lanes: tuple
    module: str
    call: str
    function: str
    kind: str = "reader"
    needs_tools: tuple = ()
    note: str = ""
    path: Path | None = None         # the module file, resolved

    def asks(self, lane: str) -> bool:
        return lane in self.lanes or "*" in self.lanes


def _root(root) -> Path:
    return Path(root) if root is not None else paths.repo_root()


def load_registry(path=None, root=None) -> list[Reader]:
    """The readers of `openers/readers.toml` (or `path`), validated: AskError names the entry for an
    unknown key, a missing field, a duplicate name, an unknown call or kind, or a module file that is
    not there."""
    root = _root(root)
    p = Path(path) if path is not None else root.joinpath(*REGISTRY)
    if not p.is_file():
        raise AskError(f"no reader registry at {p} ({'/'.join(REGISTRY)})")
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise AskError(f"{p}: not TOML ({e})") from None
    extra = set(data) - {"reader"}
    if extra:
        raise AskError(f"{p}: unknown top-level key(s) {', '.join(sorted(extra))}")
    out, seen = [], set()
    for i, row in enumerate(data.get("reader") or []):
        where = f"{p.name} reader {i + 1}"
        if not isinstance(row, dict):
            raise AskError(f"{where}: not a table")
        bad = set(row) - _READER_KEYS
        if bad:
            raise AskError(f"{where} ({row.get('name')}): unknown key(s) {', '.join(sorted(bad))}")
        name = row.get("name")
        if not isinstance(name, str) or not name.strip():
            raise AskError(f"{where}: no name")
        where = f"{p.name} reader {name!r}"
        if name in seen:
            raise AskError(f"{where}: duplicate name")
        seen.add(name)
        lanes = row.get("lanes")
        if not isinstance(lanes, list) or not lanes or not all(isinstance(x, str) and x for x in lanes):
            raise AskError(f"{where}: lanes must be a non-empty list of lane names (or \"*\")")
        call = row.get("call")
        if call not in CALLS:
            raise AskError(f"{where}: call {call!r} is not one of {', '.join(CALLS)}")
        kind = row.get("kind", "reader")
        if kind not in ("reader", "catalog"):
            raise AskError(f"{where}: kind {kind!r} is not reader or catalog")
        module = row.get("module")
        if not isinstance(module, str) or not module:
            raise AskError(f"{where}: no module")
        mpath = (root / module).resolve()
        if not mpath.is_file():
            raise AskError(f"{where}: module {module} is not there ({mpath})")
        tools = row.get("needs_tools", [])
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            raise AskError(f"{where}: needs_tools must be a list of strings")
        fn = row.get("function", CALLS[call])
        if not isinstance(fn, str) or not fn.isidentifier():
            raise AskError(f"{where}: function {fn!r} is not a name")
        out.append(Reader(name, tuple(lanes), module, call, fn, kind, tuple(tools), str(row.get("note", "")),
                          mpath))
    if not out:
        raise AskError(f"{p}: no [[reader]] entries")
    return out


def _lane_dir(lane: str) -> str:
    if not isinstance(lane, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", lane):
        raise AskError(f"lane {lane!r}: want a labels lane name (binary, metadata, mobile, script, warmups, "
                       "or a toolkit prefix)")
    return lane


def live_readers(lane: str, workdir=None) -> list[Reader]:
    """The one-field files under <workdir>/ask-readers/<lane>/ (sorted by name), as live readers."""
    _lane_dir(lane)
    base = Path(workdir) if workdir is not None else paths.workdir()
    folder = base / LIVE_DIR / lane
    if not folder.is_dir():
        return []
    return [Reader(f"live:{lane}/{f.stem}", (lane,), str(f), "solve_set", "solve_set", "live", (), "", f.resolve())
            for f in sorted(folder.glob("*.py")) if f.is_file() and not f.name.startswith("_")]


def readers_for(lane: str, readers: Iterable[Reader] | None = None, root=None, workdir=None,
                live: bool = True) -> list[Reader]:
    """The readers a lane asks, in order: those naming the lane, then the "*" ones, then live files."""
    _lane_dir(lane)
    regs = list(readers) if readers is not None else load_registry(root=root)
    own = [r for r in regs if lane in r.lanes]
    every = [r for r in regs if "*" in r.lanes and lane not in r.lanes]
    return own + every + (live_readers(lane, workdir) if live else [])


# ------------------------------------------------------------------------------------------ labels

def labels_module():
    """solvers/common/labels.py of this checkout (the unsure-answer contract), as the lanes import it."""
    return packs.load_module("labels", paths.repo_root() / "solvers" / "common" / "labels.py", pack="labels")


def _load_reader(r: Reader):
    """The reader's module. A live file is loaded fresh on every ask (the agent edits it). A registered
    reader is shared with the lane's own import when that is the same file (under its stem), else kept
    under a name made from its path, so two files with one stem never stand in for each other."""
    tag = hashlib.sha1(str(r.path).encode()).hexdigest()[:12]
    if r.kind == "live":
        return packs.load_module(f"ctf_askreaders_live_{tag}", r.path, pack=r.name, cache=False)
    for name in (r.path.stem, f"ctf_askreaders_{re.sub(r'[^A-Za-z0-9_]', '_', r.name)}_{tag}"):
        have = sys.modules.get(name)
        if have is None:
            return packs.load_module(name, r.path, pack=r.name)
        f = getattr(have, "__file__", None)
        if f and Path(f).resolve() == r.path:
            return have
    raise AskError(f"{r.name}: module name for {r.path} is taken by another file")   # a sha1 collision


# ------------------------------------------------------------------------------------------ answers

@dataclass
class ReaderAnswer:
    reader: str
    status: str                          # answered | none | error | unavailable | skipped
    member: str | None = None            # the delivered member asked (fields / apk calls)
    key: str | None = None               # the unsure answer's key; None for a plain answer
    options: list = field(default_factory=list)   # [(name, value)]
    candidates: bool = False             # a labels candidates answer: each option is its own fact
    why: str = ""
    said: str = ""                       # the reader's own output, cut
    seconds: float = 0.0

    def values(self) -> set:
        return {v for _, v in self.options}

    def line(self) -> str:
        where = f" [{self.member}]" if self.member else ""
        if self.status != ANSWERED:
            return f"{self.reader}{where}: {self.status}" + (f" ({self.why})" if self.why else "")
        shown = ", ".join(f"{n}={v}" for n, v in self.options[:6]) + (" ..." if len(self.options) > 6 else "")
        return f"{self.reader}{where}: {'unsure ' + self.key if self.key else 'plain'}: {shown}"

    def to_dict(self) -> dict:
        return {"reader": self.reader, "status": self.status, "member": self.member, "key": self.key,
                "options": [list(o) for o in self.options], "candidates": self.candidates, "why": self.why,
                "seconds": round(self.seconds, 4)}


@dataclass
class Fact:
    values: set
    answers: list

    def to_dict(self) -> dict:
        return {"values": sorted(self.values), "readers": [a.reader for a in self.answers]}


@dataclass
class Asked:
    qid: str
    answer_id: str
    field: str
    outcome: str                         # offer | no_reader | conflict | rejected
    answers: list
    facts: list
    offer: str | None = None
    key: str | None = None
    reason: str = ""

    def line(self) -> str:
        if self.outcome == OFFER:
            return f"OFFER {self.qid}: {self.reason}"
        return f"STOP {self.qid}: {self.reason}"

    def to_dict(self) -> dict:
        return {"qid": self.qid, "answer_id": self.answer_id, "field": self.field, "outcome": self.outcome,
                "key": self.key, "offer": self.offer, "reason": self.reason,
                "facts": [f.to_dict() for f in self.facts], "answers": [a.to_dict() for a in self.answers]}


@dataclass
class AskReport:
    lane: str
    asked: list
    answers: dict
    readers: list

    def offers(self) -> list:
        return [a for a in self.asked if a.outcome == OFFER]

    def stops(self) -> list:
        return [a for a in self.asked if a.outcome != OFFER]

    @property
    def ok(self) -> bool:
        return not self.stops()

    def lines(self) -> list:
        return [a.line() for a in self.asked]

    def to_json(self) -> dict:
        return {"lane": self.lane, "readers": [r.name for r in self.readers],
                "counts": {o: sum(1 for a in self.asked if a.outcome == o) for o in (OFFER, NO_READER, CONFLICT, REJECTED)},
                "asked": [a.to_dict() for a in self.asked]}


def _qid(q) -> str:
    qid = q.get("qid") or q.get("id") or q.get("answer_id") if isinstance(q, dict) else None
    if not isinstance(qid, str) or not qid:
        raise AskError(f"question without a qid/id: {str(q)[:120]}")
    return qid


def missing_ids(questions, answers) -> list[str]:
    """The ids the bank-only pass left MISSING: None, or not in `answers` at all (question order)."""
    answers = answers or {}
    return [_qid(q) for q in questions or [] if answers.get(_qid(q)) is None]


def field_of(qid: str) -> str:
    """The field an id asks: without a leading setN., in canonical form (idresolve.canon)."""
    m = _SET.match(qid)
    return idresolve.canon(m.group(1) if m else qid)


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value).strip()
    try:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return str(value).strip()


def _normal(reader: Reader, member, value, question, labels, said, seconds) -> ReaderAnswer:
    """One reader's answer for one question as a ReaderAnswer."""
    a = ReaderAnswer(reader.name, NONE, member=member, said=said, seconds=seconds)
    if value is None:
        return a
    if isinstance(value, str) and labels.is_unsure(value):
        u = labels.parse(value)
        if not u.key or not u.options:
            a.status, a.why = ERROR, "an unsure answer that does not parse (nothing to probe)"
            return a
        opts = [(str(n), _text(v)) for n, v in u.options if _text(v)]
        if not idresolve.permits_literal_none(question):
            opts = [(n, v) for n, v in opts if v.lower() != "none"]
        if not opts:
            a.why = "only the literal none, which the question's format does not allow"
            return a
        a.status, a.key, a.options = ANSWERED, u.key, opts
        a.candidates = bool(labels.is_candidate(value))
        return a
    text = _text(value)
    if not text:
        return a
    if text.lower() == "none" and not idresolve.permits_literal_none(question):
        a.why = "the literal none, which the question's format does not allow"
        return a
    a.status, a.options = ANSWERED, [(reader.name, text)]
    return a


def _cut(text: str) -> str:
    """A reader's own output, kept for triage: its head (a facts page starts there) and its tail (a
    traceback ends there), SAID_MAX characters in all."""
    if len(text) <= SAID_MAX:
        return text
    head = SAID_MAX * 3 // 4
    return text[:head] + "\n[... cut ...]\n" + text[-(SAID_MAX - head):]


def _bytes_members(files: dict) -> list:
    return [(n, d) for n, d in (files or {}).items() if isinstance(d, (bytes, bytearray))]


def _apk_members(blob: bytes):
    """{name: bytes} of a package that holds classes.dex or AndroidManifest.xml, else None."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except (zipfile.BadZipFile, ValueError, OSError):
        return None
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        names = {i.filename for i in infos}
        if "classes.dex" not in names and "AndroidManifest.xml" not in names:
            return None
        if sum(i.file_size for i in infos) > APK_MAX_BYTES:
            raise AskError(f"package members total more than {APK_MAX_BYTES} bytes uncompressed")
        return {i.filename: zf.read(i) for i in infos}


def _missing_tools(r: Reader) -> list:
    from .intake.engines import tool_missing
    return tool_missing(r.needs_tools)


def _calls(r: Reader, fn, q: dict, files: dict, ctx: dict):
    """(member, thunk) for each way this reader is asked the question."""
    one = [q]
    if r.call == "solve_set":
        yield None, lambda: fn(one, dict(files or {}), ctx)
    elif r.call == "fields":
        for name, data in _bytes_members(files):
            yield name, (lambda n=name, d=data: fn(n, bytes(d), one))
    else:   # apk
        for name, data in _bytes_members(files):
            members = _apk_members(bytes(data))
            if members is not None:
                yield name, (lambda m=members, d=data: fn(one, m, bytes(d)))


def _ask_reader(r: Reader, q: dict, files: dict, ctx, labels) -> list[ReaderAnswer]:
    missing = _missing_tools(r)
    if missing:
        return [ReaderAnswer(r.name, UNAVAILABLE, why=f"needs {', '.join(missing)}, not installed")]
    try:
        mod = _load_reader(r)
    except packs.PackError as e:
        return [ReaderAnswer(r.name, UNAVAILABLE, why=f"does not load: {e.reason}")]
    fn = getattr(mod, r.function, None)
    if not callable(fn):
        return [ReaderAnswer(r.name, UNAVAILABLE, why=f"{r.module} has no function {r.function}()")]
    qid = _qid(q)
    out = []
    try:
        calls = list(_calls(r, fn, q, files, ctx))
    except AskError as e:
        return [ReaderAnswer(r.name, ERROR, why=str(e))]
    if not calls:
        return [ReaderAnswer(r.name, NONE, why=f"no delivered member it reads ({r.call})")]
    for member, thunk in calls:
        buf = io.StringIO()
        t0 = time.perf_counter()
        try:
            with _CAPTURE, contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                got = thunk()
        except Exception as e:   # one reader's failure is named and costs only its own answer
            out.append(ReaderAnswer(r.name, ERROR, member=member, why=f"raised {type(e).__name__}: {str(e)[:200]}",
                                    said=_cut(buf.getvalue()), seconds=time.perf_counter() - t0))
            continue
        seconds = time.perf_counter() - t0
        if got is not None and not isinstance(got, dict):
            out.append(ReaderAnswer(r.name, ERROR, member=member, why=f"returned {type(got).__name__}, not a dict",
                                    said=_cut(buf.getvalue()), seconds=seconds))
            continue
        out.append(_normal(r, member, (got or {}).get(qid), q, labels, _cut(buf.getvalue()), seconds))
    return out


def _facts(answers: list) -> list[Fact]:
    """Answers grouped into facts: answers whose value sets meet are one fact (transitively); each
    option of a candidates answer is its own."""
    units = []
    for a in answers:
        if a.status != ANSWERED:
            continue
        if a.candidates:
            units.extend(({v}, a) for _, v in a.options)
        else:
            units.append((a.values(), a))
    order = {id(a): i for i, a in enumerate(answers)}
    facts: list[Fact] = []
    for vals, a in units:
        hit = [f for f in facts if f.values & vals]
        merged = Fact(set(vals), [a])
        for f in hit:
            merged.values |= f.values
            merged.answers = f.answers + merged.answers
            facts.remove(f)
        facts.append(merged)
    for f in facts:   # each answer once, in reader order
        f.answers = sorted({id(x): x for x in f.answers}.values(), key=lambda x: order[id(x)])
    facts.sort(key=lambda f: order[id(f.answers[0])])
    return facts


def _offer(lane: str, qid: str, fact: Fact, labels):
    """(key, options) for one fact: the first keyed answer's key, else <lane>.ask/<field>."""
    key = next((a.key for a in fact.answers if a.key and not a.candidates), None)
    if key is None:
        key = next((a.key for a in fact.answers if a.key), None)
        if key is not None:   # a candidates key whose one option is this fact: probe under a plain key
            key = key.split(labels.CANDIDATE_MARK, 1)[0]
    if key is None:
        key = f"{lane}.ask/{field_of(qid)}"
    opts, names, values = [], set(), set()
    for a in fact.answers:
        for n, v in a.options:
            if v not in fact.values or v in values:
                continue
            name = n if n not in names else f"{n}~{a.reader}"
            if name in names:
                continue
            names.add(name)
            values.add(v)
            opts.append((name, v))
    return key, opts[:MAX_OPTIONS]


def ask_one(question: dict, files: dict, readers: Iterable[Reader], lane: str, ctx=None,
            budget: float | None = None) -> Asked:
    """Ask every reader for one question's field and decide offer / no_reader / conflict / rejected."""
    _lane_dir(lane)
    labels = labels_module()
    qid = _qid(question)
    answer_id = str(question.get("answer_id") or qid)
    sub_ctx = dict(ctx) if isinstance(ctx, dict) else {}
    sub_ctx.pop("partial", None)
    answers: list[ReaderAnswer] = []
    t_end = None if budget is None else time.perf_counter() + float(budget)
    readers = list(readers)
    for r in readers:
        if t_end is not None and time.perf_counter() >= t_end:
            answers.append(ReaderAnswer(r.name, SKIPPED, why=f"the {budget:g} s budget was spent before it started"))
            continue
        answers.extend(_ask_reader(r, question, files, sub_ctx, labels))
    facts = _facts(answers)
    fld = field_of(qid)
    asked = Asked(qid, answer_id, fld, NO_READER, answers, facts)
    said = "; ".join(a.line() for a in answers) or "no reader is registered for this lane"
    if not facts:
        asked.reason = f"no registered reader knows {fld} (asked: {said})"
        return asked
    if len(facts) > 1:
        asked.outcome = CONFLICT
        asked.reason = (f"{len(facts)} different facts for {fld}: "
                        + " | ".join(f"{'/'.join(sorted(f.values))[:80]} from {', '.join(a.reader for a in f.answers)}"
                                     for f in facts) + "; nothing is guessed between readers")
        return asked
    key, opts = _offer(lane, qid, facts[0], labels)
    try:
        rejected = set(labels.state(key).get("rejected") or ())
    except ValueError as e:
        raise AskError(f"{qid}: key {key!r} is not a labels key: {e}") from None
    left = [(n, v) for n, v in opts if n not in rejected]
    asked.key = key
    if not left:
        asked.outcome = REJECTED
        asked.reason = f"the one fact for {fld} ({', '.join(v for _, v in opts)}) was rejected under {key} already"
        return asked
    asked.outcome, asked.offer = OFFER, labels.unsure(key, left)
    asked.reason = (f"one fact from {', '.join(dict.fromkeys(a.reader for a in facts[0].answers))}: "
                    f"unsure under {key}, {len(left)} option(s) to probe")
    return asked


def ask_missing(questions, answers: dict, files: dict, lane: str, readers: Iterable[Reader] | None = None,
                ctx=None, root=None, workdir=None, budget: float | None = None) -> AskReport:
    """The pass after the bank: ask every reader of the lane for each MISSING id. `answers` is not
    changed; the report's `answers` is a copy with each offer in place."""
    questions = [q for q in questions or [] if isinstance(q, dict)]
    regs = readers_for(lane, readers, root=root, workdir=workdir)
    out = dict(answers or {})
    want = set(missing_ids(questions, answers))
    asked = []
    t_end = None if budget is None else time.perf_counter() + float(budget)
    for q in questions:
        qid = _qid(q)
        if qid not in want:
            continue
        left = None if t_end is None else max(0.0, t_end - time.perf_counter())
        a = ask_one(q, files, regs, lane, ctx=ctx, budget=left)
        asked.append(a)
        out[qid] = a.offer
    return AskReport(lane, asked, out, regs)


class AskingSolver:
    """A lane solver (solve_set) that runs the lane's own bank-only pass, then asks every reader for the
    ids it left MISSING. ctx["ask_readers"] gets the report; ctx["partial"] gets the offers."""

    def __init__(self, solve: Callable, lane: str, *, readers: Iterable[Reader] | None = None, root=None,
                 workdir=None, budget: float | None = None):
        if not callable(solve):
            raise AskError("AskingSolver needs the lane's solve_set (a callable)")
        _lane_dir(lane)
        self._solve, self.lane, self.root, self.workdir, self.budget = solve, lane, root, workdir, budget
        self.readers = list(readers) if readers is not None else None
        self.last_report: AskReport | None = None

    def solve_set(self, questions, files, ctx):
        bank = self._solve(questions, files, ctx) or {}
        rep = ask_missing(questions, bank, files, self.lane, self.readers, ctx=ctx, root=self.root,
                          workdir=self.workdir, budget=self.budget)
        self.last_report = rep
        if isinstance(ctx, dict):
            ctx["ask_readers"] = rep.to_json()
            partial = ctx.get("partial")
            if isinstance(partial, dict):
                partial.update({a.qid: a.offer for a in rep.offers()})
        return rep.answers


# ------------------------------------------------------------------------------------------ probing

@dataclass
class Probe:
    qid: str
    answer_id: str
    key: str
    name: str
    value: str
    status: str            # accepted | rejected | held | not_probed
    message: str = ""

    def line(self) -> str:
        return f"PROBE {self.qid} {self.key} {self.name}={self.value}: {self.status}" + (
            f" ({self.message})" if self.message else "")

    def to_dict(self) -> dict:
        return {"qid": self.qid, "answer_id": self.answer_id, "key": self.key, "name": self.name,
                "value": self.value, "status": self.status, "message": self.message}


def probe(report: AskReport, submit: Callable, *, max_per_id: int = MAX_OPTIONS,
          on_verdict: Callable | None = None, stop: Callable[[], bool] | None = None) -> list[Probe]:
    """Probe each offer of `report`, one option per request, in order (see the module docstring).
    `stop` (B-221, probetier.stop_for) is read before each send: once true, every option left is not
    probed ("yielded the lane"), so a held probe hands the lane to a waiting fixup."""
    if max_per_id < 1:
        raise AskError("max_per_id must be at least 1")
    labels = labels_module()
    out: list[Probe] = []
    held = yielded = False
    for a in report.offers():
        u = labels.parse(a.offer)
        for i, (name, value) in enumerate(u.options):
            if not (held or yielded or i >= max_per_id) and stop is not None and stop():
                yielded = True
            if held or yielded or i >= max_per_id:
                out.append(Probe(a.qid, a.answer_id, u.key, name, str(value), "not_probed",
                                 "held" if held else "yielded the lane" if yielded
                                 else f"over max_per_id {max_per_id}"))
                continue
            res = submit(a.answer_id, str(value))
            if res.accepted:
                out.append(Probe(a.qid, a.answer_id, u.key, name, str(value), "accepted", res.message))
                if on_verdict:
                    on_verdict(u.key, name, "accepted")
                break
            if res.status.judged:
                out.append(Probe(a.qid, a.answer_id, u.key, name, str(value), "rejected", res.message))
                if on_verdict:
                    on_verdict(u.key, name, "rejected")
                continue
            held = True
            out.append(Probe(a.qid, a.answer_id, u.key, name, str(value), "held",
                             f"{res.status.value}: {res.message}"))
    return out


def gate_submit(gate, challenge_id: str, provenance: str) -> Callable:
    """submit(answer_id, value) through the SubmitGate: one answer of `challenge_id`, brief-defined."""
    if not provenance:
        raise AskError("gate_submit needs a provenance")

    def submit(answer_id: str, value: str):
        return gate.submit(f"{challenge_id}#{answer_id}", value, provenance=provenance, allow_nonstandard=True)
    return submit


# ------------------------------------------------------------------------------------------ template

def _slug(qid: str) -> str:
    return (re.sub(r"[^a-z0-9]+", "_", qid.lower()).strip("_") or "field")[:80]


def _comment_safe(text: str) -> str:
    """`text` as one physical line of a Python comment: every line break Python or str.splitlines knows
    (\\r, \\n, \\x0b, \\x0c, \\x1c-\\x1e, \\x85, \\u2028, \\u2029), every other control character
    (a NUL makes the file not compile), and every lone surrogate (not encodable) is written as its escape.
    Reader values and messages come from challenge files: the generated reader is run on the next ask."""
    out = []
    for ch in str(text):
        if ch == "\t":
            out.append(ch)
        elif unicodedata.category(ch) in ("Cc", "Cs", "Zl", "Zp"):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def template_text(lane: str, qid: str, asked: Asked | None = None, root=None) -> str:
    """The one-field reader for `qid`, from templates/ask-readers/one_field.py, with every reader's
    answer for it as comments."""
    _lane_dir(lane)
    src = _root(root).joinpath(*TEMPLATE)
    if not src.is_file():
        raise AskError(f"the one-field template is not there: {src}")
    text = src.read_text(encoding="utf-8")
    for token in ('"__FIELD_ID__"', '"__LANE__"', "# __CANDIDATES__"):
        if token not in text:
            raise AskError(f"{src}: placeholder {token} is missing")
    seen = []
    if asked is not None:
        seen.append("# " + _comment_safe(asked.line()))
        for a in asked.answers:
            seen.append("#   " + _comment_safe(a.line()[:300]))
            for said in [s for s in a.said.splitlines() if s.strip()][:TEMPLATE_SAID_LINES]:
                seen.append("#       | " + _comment_safe(said[:200]))
    else:
        seen.append("# (no ask was run: `python -m ctf ask-readers triage` shows what every reader says)")
    return (text.replace('"__FIELD_ID__"', json.dumps(qid)).replace('"__LANE__"', json.dumps(lane))
            .replace("# __CANDIDATES__", "\n".join(seen)))


def write_template(lane: str, qid: str, asked: Asked | None = None, workdir=None, out=None, root=None,
                   force: bool = False) -> Path:
    """Write the one-field reader (default <workdir>/ask-readers/<lane>/field_<id>.py, where the next ask
    finds it). An existing file is AskError unless `force`."""
    text = template_text(lane, qid, asked, root=root)
    if out is None:
        base = Path(workdir) if workdir is not None else paths.workdir()
        out = base / LIVE_DIR / lane / f"field_{_slug(qid)}.py"
    out = Path(out)
    if out.exists() and not force:
        raise AskError(f"{out} exists (edit it, or pass force)")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out
