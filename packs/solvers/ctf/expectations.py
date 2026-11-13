"""Expectations generated from fixture outputs, and the pins a test file takes from them (B-258).

One generator, shared by the repro scaffold (`ctf scaffold repro`, `--save`), the test-pin codemod
(`ctf testpin`) and B-196's "generated expectations from the saved corpus": run a callable over a set
of cases, normalise every output to JSON, and write one deterministic file.

    from ctf import expectations as X
    target = X.load_target("solvers/binary/d31.py:answers")     # a file path or a dotted module
    cases = [X.case("base", questions, files, None), ...]
    doc = X.generate(target, cases, target_spec="solvers/binary/d31.py:answers")
    X.write(path, doc)                       # sorted keys, one trailing newline: diffs are stable
    X.compare(X.load(path), doc)             # [Diff(case, path, expected, actual)], empty when equal
    X.pins(doc, case="base")                 # {key: value} for the codemod

The file (schema 1):

    {"schema": 1, "target": "<spec>", "cases": {"<case id>": {"output": <json>} | {"error": "Type: msg"}}}

Normalising: a mapping becomes an object with string keys (a non-string key raises), a tuple, list
or set a list (a set sorted by its JSON text), bytes `{"$bytes": "<hex>"}`, a str subclass (an
unsure answer, a prior answer) its plain text, an int subclass its int (bool stays bool). Anything
else raises ExpectationError naming the type and where it sat: a value that cannot be written is
never written as its repr.
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA = 1
BYTES_TAG = "$bytes"
MISSING = type("Missing", (), {"__repr__": lambda self: "MISSING", "__bool__": lambda self: False})()


class ExpectationError(ValueError):
    """A case, target, output or expectations file that cannot be used, with the reason."""


@dataclass
class Case:
    id: str
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    expect: Any = MISSING

    def call(self, target: Callable):
        return target(*self.args, **self.kwargs)


def case(id: str, *args, expect=MISSING, **kwargs) -> Case:
    """A case: `target(*args, **kwargs)`, optionally with the output it must give."""
    if not isinstance(id, str) or not id or "/" in id:
        raise ExpectationError(f"a case id is a non-empty string without '/': {id!r}")
    return Case(id, tuple(args), dict(kwargs), expect)


# --------------------------------------------------------------------------------------------- targets

def load_target(spec: str, root: Path | None = None) -> Callable:
    """The callable named by `file.py:function` (a path, relative to `root` or the current folder) or
    `package.module:function`. The file is loaded under a name of its own, so another folder's module
    of the same basename never shadows it; its folder goes on sys.path first (lane modules import their
    neighbours by bare name)."""
    if not isinstance(spec, str) or spec.count(":") != 1:
        raise ExpectationError(f"target {spec!r}: expected FILE.py:FUNCTION or package.module:FUNCTION")
    where, name = spec.split(":")
    if not name.isidentifier():
        raise ExpectationError(f"target {spec!r}: {name!r} is not a function name")
    if where.endswith(".py"):
        path = Path(where)
        if not path.is_absolute():
            path = (Path(root) if root is not None else Path.cwd()) / path
        if not path.is_file():
            raise ExpectationError(f"target {spec!r}: no file {path}")
        folder = str(path.resolve().parent)
        if folder not in sys.path:
            sys.path.insert(0, folder)
        modname = "expect_target_" + "".join(c if c.isalnum() else "_" for c in str(path.resolve()))
        spec_obj = importlib.util.spec_from_file_location(modname, path)
        mod = importlib.util.module_from_spec(spec_obj)
        sys.modules[modname] = mod
        try:
            spec_obj.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(modname, None)
            raise
    else:
        mod = importlib.import_module(where)
    fn = getattr(mod, name, None)
    if not callable(fn):
        raise ExpectationError(f"target {spec!r}: {where} defines no callable {name!r}")
    return fn


# ----------------------------------------------------------------------------------------- normalising

def normalize(value, where: str = "output"):
    """`value` as plain JSON (see the module docstring); ExpectationError for a type JSON cannot hold."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ExpectationError(f"{where}: {value!r} has no JSON form")
        return float(value)
    if isinstance(value, str):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {BYTES_TAG: bytes(value).hex()}
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise ExpectationError(f"{where}: key {k!r} is a {type(k).__name__}, not a string")
            out[str(k)] = normalize(v, f"{where}[{k!r}]")
        return out
    if isinstance(value, (list, tuple)):
        return [normalize(v, f"{where}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, (set, frozenset)):
        items = [normalize(v, f"{where}{{}}") for v in value]
        return sorted(items, key=lambda v: json.dumps(v, sort_keys=True))
    raise ExpectationError(f"{where}: a {type(value).__name__} has no JSON form; return plain data")


def denormalize(value):
    """The Python value a normalised JSON value stands for ({"$bytes": hex} -> bytes)."""
    if isinstance(value, dict):
        if set(value) == {BYTES_TAG} and isinstance(value[BYTES_TAG], str):
            return bytes.fromhex(value[BYTES_TAG])
        return {k: denormalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [denormalize(v) for v in value]
    return value


# ------------------------------------------------------------------------------------------ generating

def run_case(target: Callable, c: Case) -> dict:
    """{"output": <json>} or {"error": "Type: message"} for one case. Only an Exception is caught: a
    KeyboardInterrupt or SystemExit from the target stops the run."""
    try:
        out = c.call(target)
    except Exception as e:  # noqa: BLE001 - recorded, never hidden
        return {"error": f"{type(e).__name__}: {e}"}
    return {"output": normalize(out, f"case {c.id!r}")}


def generate(target: Callable, cases: Iterable[Case], target_spec: str = "") -> dict:
    """The expectations document for `cases` (ids must be unique)."""
    out: dict = {}
    for c in cases:
        if not isinstance(c, Case):
            raise ExpectationError(f"not a Case: {c!r} (build cases with expectations.case)")
        if c.id in out:
            raise ExpectationError(f"case id {c.id!r} appears twice")
        out[c.id] = run_case(target, c)
    return {"schema": SCHEMA, "target": target_spec, "cases": out}


def dumps(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def write(path: str | Path, doc: dict) -> Path:
    """Write `doc` (validated) atomically; returns the path."""
    validate(doc)
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(dumps(doc), encoding="utf-8")
    tmp.replace(path)
    return path


def validate(doc) -> dict:
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("cases"), dict):
        raise ExpectationError(f"not an expectations document (schema {SCHEMA} with a 'cases' object)")
    for cid, rec in doc["cases"].items():
        if not isinstance(rec, dict) or len(set(rec) & {"output", "error"}) != 1:
            raise ExpectationError(f"case {cid!r}: needs exactly one of 'output' or 'error'")
    return doc


def load(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ExpectationError(f"no expectations file {p}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ExpectationError(f"{p}: not JSON ({e})") from None
    return validate(doc)


# ------------------------------------------------------------------------------------------- comparing

@dataclass(frozen=True)
class Diff:
    case: str
    path: str
    expected: Any
    actual: Any

    def __str__(self):
        where = f"{self.case}{self.path}" if self.path else self.case
        return f"{where}: expected {_short(self.expected)}, got {_short(self.actual)}"


def _short(v, cap: int = 120) -> str:
    if v is MISSING:
        return "(absent)"
    text = json.dumps(v, sort_keys=True, ensure_ascii=False) if not isinstance(v, bytes) else repr(v)
    return text if len(text) <= cap else text[: cap - 3] + "..."


def _same(a, b) -> bool:
    """Equal as JSON values, with bool never equal to an int (True is not 1 in an answer)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def diff_values(expected, actual, path: str = "", case: str = "") -> list[Diff]:
    """Every place two normalised values differ: a key only on one side, a different leaf, a list of a
    different length (reported once, then the common prefix compared)."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for k in sorted(set(expected) | set(actual)):
            sub = f"{path}[{k!r}]"
            if k not in actual:
                out.append(Diff(case, sub, expected[k], MISSING))
            elif k not in expected:
                out.append(Diff(case, sub, MISSING, actual[k]))
            else:
                out += diff_values(expected[k], actual[k], sub, case)
        return out
    if isinstance(expected, list) and isinstance(actual, list):
        out = []
        if len(expected) != len(actual):
            out.append(Diff(case, f"{path}.len", len(expected), len(actual)))
        for i, (x, y) in enumerate(zip(expected, actual)):
            out += diff_values(x, y, f"{path}[{i}]", case)
        return out
    return [] if _same(expected, actual) else [Diff(case, path, expected, actual)]


def compare(expected: dict, actual: dict) -> list[Diff]:
    """Diffs between two expectations documents, case by case; a case on one side only is one Diff."""
    validate(expected)
    validate(actual)
    out = []
    ec, ac = expected["cases"], actual["cases"]
    for cid in sorted(set(ec) | set(ac)):
        if cid not in ac:
            out.append(Diff(cid, "", ec[cid], MISSING))
        elif cid not in ec:
            out.append(Diff(cid, "", MISSING, ac[cid]))
        elif "error" in ec[cid] or "error" in ac[cid]:
            if not _same(ec[cid], ac[cid]):
                out.append(Diff(cid, "", ec[cid], ac[cid]))
        else:
            out += diff_values(ec[cid]["output"], ac[cid]["output"], "", cid)
    return out


# ------------------------------------------------------------------------------------------------ pins

def outputs_of(doc) -> dict:
    """{case id: output} of an expectations document, or {"": doc} for a plain JSON object (a solver's
    {qid: answer} saved as it is). Cases that errored have no output and are left out."""
    if isinstance(doc, dict) and doc.get("schema") == SCHEMA and isinstance(doc.get("cases"), dict):
        validate(doc)
        return {cid: rec["output"] for cid, rec in doc["cases"].items() if "output" in rec}
    if isinstance(doc, dict):
        return {"": doc}
    raise ExpectationError("fixture outputs must be a JSON object or an expectations document")


class Pins(dict):
    """{key: value} for the codemod, plus what it needs to keep cases apart:

    `cases`: every case id of the document (errored ones too), so a bare key never rewrites an entry
    nested under another case's id; `ambiguous`: bare keys left out because cases disagree on them."""

    def __init__(self, values=(), cases=(), ambiguous=()):
        super().__init__(values)
        self.cases = frozenset(cases)
        self.ambiguous = frozenset(ambiguous)


def pins(doc, case: str | None = None) -> Pins:
    """{key: value} a test file's pins are rewritten from (values denormalised), as a Pins.

    Each case's output that is an object gives its keys (`qid`) and the same keys under the case
    (`case/qid`); an output that is not an object gives the case id itself. With `case`, only that
    case. Without it, a key two cases give different values is left out in its bare form (its
    `case/qid` forms stay) and named in `.ambiguous`: which case a bare key means is the caller's
    choice (--case), never a silent pick."""
    outs = outputs_of(doc)
    all_cases = set(doc["cases"]) if "" not in outs else set()
    if case is not None:
        if case not in outs:
            raise ExpectationError(f"no case {case!r} with an output (cases: {', '.join(sorted(outs)) or 'none'})")
        outs = {case: outs[case]}
    flat: dict = {}
    clash: set = set()
    for cid, out in sorted(outs.items()):
        if isinstance(out, dict) and not (set(out) == {BYTES_TAG}):
            for k, v in out.items():
                if k in flat and not _same(flat[k], v):
                    clash.add(k)
                flat.setdefault(k, v)
                if cid:
                    flat[f"{cid}/{k}"] = v
        elif cid:
            flat[cid] = out
        else:
            raise ExpectationError("a bare fixture output must be a JSON object of key -> value")
    for k in clash:
        del flat[k]
    return Pins({k: denormalize(v) for k, v in flat.items()}, all_cases, clash)
