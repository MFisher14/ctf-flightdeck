"""Property coverage matrix by file type (B-162): what the metadata lane's readers answer on the corpus.

For every catalog format, in rank order:

  detection    each sample is identified as its own format (ctf.formats.identify), and the lane's facts
               page knows a type for it (properties_strict's detect / _other_type / MORE_TYPES)
  namespaces   every distinct reader registered in the format's namespaces, asked on every sample of the
               format the way the facts page asks (no subprocess): value / absent / unknown / error. An
               `error` is a reader that raised something other than its own Unknown on a well-formed file
  checks       every Check of every sample asked as a question through properties_strict.answer_question:
               plain / unsure / none, and whether the value the builder wrote is the plain answer or one
               of the unsure options (`matched`), and whether it is the first option (`first`)
  nearest      every catalog spelling that no reader registers, asked the same way: it must be answered
               UNSURE (never plain) and by the reader the catalog names (the option names carry it)
  gaps         plausible spellings nothing reads yet: reported, never asserted

The matrix runs with the judge ledger off ($CTF_JUDGE_LEDGER=off, restored afterwards), so it says what
the readers do with no judged evidence: every answer that is not a judge-confirmed form (size, digests,
magic prefix) is unsure, and the result is the same on every machine and event workdir.

    compute(catalog=None, lane=None)  -> Matrix
    Matrix.problems()                 the rows that break the contract (check unmatched, nearest plain or
                                      unread, sample misidentified, reader error, namespace with no reader)
    render_markdown(matrix)           docs/coverage/FORMATS.md
    lane_module()                     properties_strict, loaded by path (PackMissing / PackLoadError if not)
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import io
import json
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass, field

from .. import paths as _paths
from .. import packs as _packs
from . import corpus as _corpus
from . import identify as _identify
from . import load as _load

LANE_DIR = ("solvers", "metadata-forensics")
LANE_FILE = "properties_strict.py"
LANE_MODULE = "properties_strict"     # the name the lane's tests import it under: one module, one registry
DOC = ("docs", "coverage", "FORMATS.md")
READER_IN_OPTION = re.compile(r"~([a-z0-9_]+\.[a-z0-9_.]+)$")
SENTINEL = "??"


def lane_module():
    """properties_strict, the metadata lane's registry, loaded once by path. Its own imports (labels,
    file_properties, the reader packs) are resolved by the lane itself; a missing or broken pack raises."""
    if LANE_MODULE in sys.modules:
        return sys.modules[LANE_MODULE]
    lane_dir = _paths.repo_root().joinpath(*LANE_DIR)
    for d in (lane_dir.parent / "common", lane_dir):
        if str(d) not in sys.path:
            sys.path.insert(0, str(d))
    return _packs.load_module(LANE_MODULE, lane_dir / LANE_FILE, pack="metadata lane properties_strict")


@contextlib.contextmanager
def _no_judge():
    old = os.environ.get("CTF_JUDGE_LEDGER")
    os.environ["CTF_JUDGE_LEDGER"] = "off"
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("CTF_JUDGE_LEDGER", None)
        else:
            os.environ["CTF_JUDGE_LEDGER"] = old


def tool_available(spec: str) -> bool:
    """A tool spec is one name or alternatives joined by '|' (any one of them on PATH is enough)."""
    return any(shutil.which(t) for t in spec.split("|"))


def renderings(expected) -> set:
    """The texts an answer may carry for a value the builder wrote: the value as text; a list joined by a
    comma, a comma and a space, a space, or as compact JSON; a time as ISO 8601 (with Z, with +00:00, bare,
    with a space) or as its Windows FILETIME or Unix seconds; true/false for a bool."""
    if isinstance(expected, bool):
        return {str(expected).lower()}
    if isinstance(expected, _dt.datetime):
        t = expected.astimezone(_dt.timezone.utc).replace(tzinfo=None)
        iso = t.strftime("%Y-%m-%dT%H:%M:%S")
        return {iso + "Z", iso, iso + "+00:00", iso.replace("T", " "), iso.replace("T", " ") + " UTC",
                str(_corpus.filetime(expected)), str(int(expected.timestamp()))}
    if isinstance(expected, (list, tuple)):
        items = [str(x) for x in expected]
        return {",".join(items), ", ".join(items), " ".join(items), json.dumps(list(expected), separators=(",", ":")),
                json.dumps(list(expected))}
    return {str(expected)}


def classify(answer, labels):
    """(status, values, option names): plain / prior / unsure / none, with every value the answer offers."""
    if answer is None:
        return "none", [], []
    parsed = labels.parse(answer)
    if parsed is not None:
        return "unsure", [v for _, v in parsed.options], [n for n, _ in parsed.options]
    if labels.prior_of(answer) is not None:
        return "prior", [str(answer)], []
    return "plain", [str(answer)], []


ABSENT_OPTION = "absent"   # the lane's name for the literal `none` (the field is not in the file)


def matches(answer, expected, labels):
    """(status, matched, first): whether the value the builder wrote is the plain answer or one of the
    unsure options, and whether it is the first. The `absent` option (the literal none of a field the
    reader did not find) never satisfies a check, even one whose value is the text 'none'."""
    status, values, names = classify(answer, labels)
    want = renderings(expected)
    kept = [v for v, n in zip(values, names or [""] * len(values)) if n != ABSENT_OPTION]
    return status, any(v in want for v in kept), bool(kept) and bool(values) and values[0] == kept[0] and kept[0] in want


def ask(lane, prop: str, sample, artifact=None):
    """properties_strict's answer to 'Determine <prop> for <file>.' about one sample, with its stderr."""
    target = artifact.split("->")[-1].strip() if artifact else sample.name
    q = {"answer_id": f"corpus-{sample.id}", "question": f"Determine {prop} for {target}."}
    if artifact:
        q["artifact"] = artifact
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        answer = lane.answer_question(q, {sample.name: sample.data}, {})
    return answer, err.getvalue()


@dataclass
class CheckRow:
    sample: str
    prop: str
    artifact: str | None
    expected: str
    status: str            # plain / prior / unsure / none / not-run
    matched: bool
    first: bool
    shown: str
    reason: str = ""


@dataclass
class NearestRow:
    sample: str
    asked: str
    reader: str
    status: str
    reader_seen: str
    registered: bool       # the asked name became a registered reader since the catalog was written
    shown: str


@dataclass
class GapRow:
    sample: str
    asked: str
    note: str
    status: str
    shown: str


@dataclass
class NamespaceRow:
    namespace: str
    readers: int
    value: int
    absent: int
    unknown: int
    error: int
    errors: list = field(default_factory=list)


@dataclass
class FormatRow:
    id: str
    rank: int
    label: str
    samples: list
    identified: dict        # sample -> the first identify() match (or None)
    facts_kind: dict        # sample -> the lane's facts-page type (or None)
    namespaces: list
    checks: list
    nearest: list
    gaps: list


@dataclass
class Matrix:
    formats: list

    def problems(self) -> list:
        out = []
        for f in self.formats:
            for s, got in f.identified.items():
                if got != f.id:
                    out.append(f"{f.id}: sample {s} is identified as {got!r}")
            for s, kind in f.facts_kind.items():
                if kind is None:
                    out.append(f"{f.id}: the lane's facts page has no type for sample {s}")
            for n in f.namespaces:
                if n.readers == 0:
                    out.append(f"{f.id}: namespace {n.namespace} has no reader")
                if n.error:
                    out.append(f"{f.id}: {n.error} reader(s) of {n.namespace} raised on the corpus: {', '.join(n.errors[:5])}")
            for c in f.checks:
                if c.status != "not-run" and not c.matched:
                    out.append(f"{f.id}: {c.sample} {c.prop}{' (' + c.artifact + ')' if c.artifact else ''}: "
                               f"expected {c.expected!r}, got {c.status} {c.shown!r}")
            for n in f.nearest:
                if n.status != "unsure":
                    out.append(f"{f.id}: nearest {n.asked} is {n.status} {n.shown!r}: it must be unsure")
                elif not n.registered and n.reader_seen != n.reader:
                    out.append(f"{f.id}: nearest {n.asked} is read by {n.reader_seen or 'no named reader'}, "
                               f"the catalog says {n.reader}")
        return out

    def not_run(self) -> list:
        return [f"{f.id}: {c.sample} {c.prop}: {c.reason}" for f in self.formats for c in f.checks if c.status == "not-run"]

    def to_json(self) -> str:
        return json.dumps({"formats": [asdict(f) for f in self.formats], "problems": self.problems(),
                           "not_run": self.not_run()}, indent=1, default=str)


def lane_kind(lane, data: bytes):
    """The type the lane's facts page gives the bytes: properties_strict.detect, else _other_type, then
    a finer pack type of that container (an .msi is a compound file, an .msix a zip)."""
    kind = lane.detect(data) or lane._other_type(data)
    for finer, test in lane.MORE_TYPES:
        if finer != kind and kind in lane.RELATED.get(finer, ()) and lane._safe(test, data):
            return finer
    return kind


def _readers(lane, namespace: str) -> list:
    seen, out = set(), []
    for p in lane.REG.values():
        if p.name.split(".")[0] == namespace and p.fn not in seen:
            seen.add(p.fn)
            out.append(p)
    return out


def _namespace_row(lane, namespace: str, samples: list) -> NamespaceRow:
    row = NamespaceRow(namespace, 0, 0, 0, 0, 0)
    readers = _readers(lane, namespace)
    row.readers = len(readers)
    lane.FACTS_PAGE[0] += 1           # as the facts page asks: no reader starts a subprocess
    try:
        for p in readers:
            best = "absent"
            for s in samples:
                try:
                    options, absent = lane.options_for(p, s.name, s.data)
                except (lane.Unknown, lane.Ambiguous):
                    best = "unknown" if best == "absent" else best
                    continue
                except Exception as e:      # a reader bug on a well-formed file
                    best = "error"
                    row.errors.append(f"{p.name} ({type(e).__name__})")
                    break
                if not absent and options:
                    best = "value"
                    break
            setattr(row, best, getattr(row, best) + 1)
    finally:
        lane.FACTS_PAGE[0] -= 1
    return row


def _short(v, n=80) -> str:
    s = v if isinstance(v, str) else json.dumps(v, default=str) if isinstance(v, (list, tuple)) else str(v)
    s = s.replace("\x05", "\\x05").replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= n else s[:n - 1] + "…"


def compute(catalog=None, lane=None) -> Matrix:
    catalog = _load() if catalog is None else catalog
    lane = lane_module() if lane is None else lane
    labels = sys.modules.get("labels") or __import__("labels")
    rows = []
    with _no_judge():
        for f in catalog:
            samples = [_corpus.build(s) for s in f.samples]
            by_id = {s.id: s for s in samples}
            identified = {s.id: (lambda m: m[0].format if m else None)(_identify(s.name, s.data, catalog)) for s in samples}
            kinds = {s.id: lane_kind(lane, s.data) for s in samples}
            namespaces = [_namespace_row(lane, ns, samples) for ns in f.namespaces]
            checks = []
            for s in samples:
                for c in s.checks:
                    missing = [t for t in c.needs_tools if not tool_available(t)]
                    if missing:
                        checks.append(CheckRow(s.id, c.prop, c.artifact, _short(c.expected), "not-run", False, False, "",
                                               f"needs_tool: {', '.join(missing)} not available"))
                        continue
                    answer, _ = ask(lane, c.prop, s, c.artifact)
                    status, matched, first = matches(answer, c.expected, labels)
                    values = classify(answer, labels)[1]
                    checks.append(CheckRow(s.id, c.prop, c.artifact, _short(c.expected), status, matched, first,
                                           _short(values[0] if values else "", 60)))
            nearest = []
            for n in f.nearest:
                answer, _ = ask(lane, n.asked, by_id[n.sample])
                status, values, names = classify(answer, labels)
                seen = next((m.group(1) for m in map(READER_IN_OPTION.search, names) if m), "")
                nearest.append(NearestRow(n.sample, n.asked, n.reader, status, seen,
                                          lane.lookup(lane.canon(n.asked)) is not None, _short(values[0] if values else "", 60)))
            gaps = []
            for g in f.gaps:
                answer, _ = ask(lane, g.asked, by_id[g.sample])
                status, values, _names = classify(answer, labels)
                gaps.append(GapRow(g.sample, g.asked, g.note, status, _short(values[0] if values else "", 60)))
            rows.append(FormatRow(f.id, f.rank, f.label, list(f.samples), identified, kinds, namespaces, checks, nearest, gaps))
    return Matrix(rows)


def render_markdown(m: Matrix) -> str:
    out = ["# Format coverage matrix",
           "",
           "Generated by `python -m ctf formats matrix --write` (B-162) from `ctf/formats/catalog.toml`, the",
           "synthetic corpus in `ctf/formats/corpus.py` and the metadata lane's readers",
           "(`solvers/metadata-forensics/properties_strict.py` and its packs). Do not edit by hand: regenerate.",
           "It is computed with the judge ledger off, so every answer that is not a judge-confirmed form is",
           "unsure. A nearest-reader answer must always be unsure. `python -m ctf formats matrix` exits 1 on",
           "any problem listed at the end.",
           "",
           "## Ranked formats",
           "",
           "| rank | format | samples | identified | facts type | readers (value / absent / unknown / error) | checks matched | nearest unsure |",
           "|---:|---|---|---|---|---|---|---|"]
    for f in m.formats:
        readers = [sum(getattr(n, k) for n in f.namespaces) for k in ("readers", "value", "absent", "unknown", "error")]
        ran = [c for c in f.checks if c.status != "not-run"]
        idok = sum(1 for s, g in f.identified.items() if g == f.id)
        kinds = ", ".join(sorted({str(k) for k in f.facts_kind.values()}))
        out.append(f"| {f.rank} | {f.id} | {len(f.samples)} | {idok}/{len(f.samples)} | {kinds} | "
                   f"{readers[0]} ({readers[1]} / {readers[2]} / {readers[3]} / {readers[4]}) | "
                   f"{sum(c.matched for c in ran)}/{len(ran)}{' (+' + str(len(f.checks) - len(ran)) + ' not run)' if len(ran) < len(f.checks) else ''} | "
                   f"{sum(n.status == 'unsure' for n in f.nearest)}/{len(f.nearest)} |")
    for f in m.formats:
        out += ["", f"## {f.rank}. {f.id}: {f.label}", "",
                "| namespace | readers | value | absent | unknown | error |", "|---|---:|---:|---:|---:|---:|"]
        out += [f"| {n.namespace} | {n.readers} | {n.value} | {n.absent} | {n.unknown} | {n.error} |" for n in f.namespaces]
        out += ["", "| sample | property | expected | answer | matched | first |", "|---|---|---|---|---|---|"]
        for c in f.checks:
            prop = c.prop + (f" ({c.artifact})" if c.artifact else "")
            shown = c.reason if c.status == "not-run" else f"{c.status}: {c.shown}"
            out.append(f"| {c.sample} | {_short(prop, 70)} | {c.expected} | {_short(shown, 70)} | "
                       f"{'yes' if c.matched else 'no'} | {'yes' if c.first else 'no'} |")
        if f.nearest:
            out += ["", "Nearest reader (unregistered spellings):", "",
                    "| asked | catalog reader | answer | reader in options |", "|---|---|---|---|"]
            out += [f"| {n.asked} | {n.reader} | {n.status}{' (now registered)' if n.registered else ''}: {n.shown} | "
                    f"{n.reader_seen or '-'} |" for n in f.nearest]
        if f.gaps:
            out += ["", "Open gaps (nothing reads these spellings yet):", "", "| asked | answer | note |", "|---|---|---|"]
            out += [f"| {g.asked} | {g.status}{(': ' + g.shown) if g.shown else ''} | {g.note} |" for g in f.gaps]
    problems, not_run = m.problems(), m.not_run()
    out += ["", "## Problems", ""] + ([f"- {p}" for p in problems] or ["None."])
    out += ["", "## Not run", ""] + ([f"- {p}" for p in not_run] or ["None."])
    return "\n".join(out) + "\n"


def doc_path():
    return _paths.repo_root().joinpath(*DOC)
