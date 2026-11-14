"""Size thresholds and the scale specimens that cross them (B-174).

Huntress Day 28: the runner handed Warmups its sibling map only while all deliveries totalled at most
256 KiB. The Mastery expanded to 138 blobs, 289,516 bytes; the map was withheld and every set took
the expensive fallback (+18:46). The decoder was fine. Nothing had ever run a delivery past that size.

    found = scan(paths, root=None)            # [Found]: size constants and len() comparisons in code
    left = undeclared(found, matrix)          # [Found] no lane threshold declares and no waiver covers
    replicate(specimen_dir, out_dir, min_total_bytes)   # a multi-set specimen past min_total_bytes

What `scan` reports (every .py file under the paths, hidden and __pycache__ folders skipped):
    constant      a module-level UPPER_CASE name whose words include MAX, LIMIT, CAP, THRESHOLD,
                  CUTOFF, BYTES or SIZE, assigned an integer expression (literals with + - * << //)
                  of at least MIN_BYTES
    len-compare   a comparison between len(...) and an integer literal of at least MIN_BYTES
A file that does not parse is a LookaheadError: a scan that skips code is not a scan.

`undeclared` matches by byte value: a found threshold is declared when some lane of the matrix has a
`[[lane.<lane>.threshold]]` with the same `bytes`, and waived when a `[[waived_threshold]]` has the same
`bytes` and its `where` glob matches the file (relative to `root`). The gate then requires a specimen on
each side of every declared threshold.

`replicate` copies one specimen N times as sets: members under `files/set<n>/`, ids `set<n>.<id>`
(the multi-set delivery shape, ctf.idresolve's `setN.` prefix), the key and encodings with them,
with N the smallest count whose total is past `min_total_bytes`. A specimen whose ids already carry a
set prefix, or that is declared skip, is refused.
"""
from __future__ import annotations

import ast
import fnmatch
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import LookaheadError
from . import matrix as _matrix

MIN_BYTES = 1024
_SIZE_WORD = re.compile(r"(?:^|_)(?:MAX|LIMIT|CAP|THRESHOLD|CUTOFF|BYTES|SIZE)(?:_|$)")
_CONST_NAME = re.compile(r"^_?[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class Found:
    path: str              # relative to root when under it, else absolute
    line: int
    name: str
    bytes: int
    how: str               # constant | len-compare

    def line_text(self) -> str:
        return f"{self.path}:{self.line}  {self.name} = {self.bytes} ({self.how})"


def _int_expr(node) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp):
        a, b = _int_expr(node.left), _int_expr(node.right)
        if a is None or b is None:
            return None
        ops = {ast.Mult: lambda: a * b, ast.Add: lambda: a + b, ast.Sub: lambda: a - b,
               ast.LShift: lambda: a << b if 0 <= b <= 64 else None,
               ast.FloorDiv: lambda: a // b if b else None}
        fn = ops.get(type(node.op))
        return fn() if fn else None
    return None


def _is_len(node) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len"


def _files(paths) -> list[Path]:
    out = []
    for p in paths:
        p = Path(p)
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += [f for f in sorted(p.rglob("*.py"))
                    if not any(part.startswith(".") or part == "__pycache__" for part in f.relative_to(p).parts)]
        else:
            raise LookaheadError(f"{p}: no such file or folder to scan")
    return out


def _rel(f: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return f.resolve().relative_to(Path(root).resolve()).as_posix()
        except ValueError:
            pass
    return str(f)


def scan(paths, root: Path | None = None) -> list[Found]:
    found = []
    for f in _files(paths):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        except (SyntaxError, UnicodeDecodeError, ValueError) as e:
            raise LookaheadError(f"{f}: does not parse ({type(e).__name__}: {e}); the scan cannot read it") from None
        rel = _rel(f, root)
        for node in tree.body:
            targets, value = [], None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            for t in targets:
                if isinstance(t, ast.Name) and _CONST_NAME.match(t.id) and _SIZE_WORD.search(t.id.lstrip("_")):
                    v = _int_expr(value)
                    if v is not None and v >= MIN_BYTES:
                        found.append(Found(rel, node.lineno, t.id, v, "constant"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            sides = [node.left, *node.comparators]
            if not any(_is_len(s) for s in sides):
                continue
            for s in sides:
                v = _int_expr(s) if isinstance(s, (ast.Constant, ast.BinOp)) else None
                if v is not None and v >= MIN_BYTES:
                    found.append(Found(rel, node.lineno, "len()", v, "len-compare"))
    return found


def undeclared(found, m: _matrix.Matrix) -> list[Found]:
    declared = {t.bytes for cfg in m.lanes.values() for t in cfg.thresholds}
    out = []
    for f in found:
        if f.bytes in declared:
            continue
        if any(w.bytes == f.bytes and fnmatch.fnmatchcase(f.path, w.where) for w in m.waivers):
            continue
        out.append(f)
    return out


def _flat(v) -> bool:
    """A value json.dumps writes as valid TOML: a string, number, bool, or a list of those."""
    if isinstance(v, list):
        return all(_flat(x) and not isinstance(x, list) for x in v)
    return isinstance(v, (str, int, float, bool))


def replicate(specimen_dir, out_dir, min_total_bytes: int) -> Path:
    """A new specimen folder at `out_dir` whose members total more than `min_total_bytes`."""
    src = Path(specimen_dir)
    spec = _matrix.load_specimen(src.parent.name, src)
    if spec.skip:
        raise LookaheadError(f"{src}: a skipped specimen has nothing to replicate")
    if isinstance(min_total_bytes, bool) or not isinstance(min_total_bytes, int) or min_total_bytes < 1:
        raise LookaheadError("replicate: min_total_bytes must be a positive integer")
    for k, v in spec.ctx.items():
        if not _flat(v):
            raise LookaheadError(f"{src}: ctx.{k} is a table or a date; replicate copies flat values only")
    if any(re.match(r"^set\d+\.", _matrix.qid_of(q)) for q in spec.questions):
        raise LookaheadError(f"{src}: its ids already carry a set prefix; replicate a single-set specimen")
    out = Path(out_dir)
    if out.exists():
        raise LookaheadError(f"{out}: already exists")
    total = spec.total_bytes
    if total <= 0:
        raise LookaheadError(f"{src}: its members are empty; no number of copies crosses a size")
    copies = max(2, min_total_bytes // total + 1)
    (out / _matrix.FILES_DIR).mkdir(parents=True)
    questions, key, encodings = [], {}, {}
    for n in range(1, copies + 1):
        for member in sorted(spec.sizes):
            dst = out / _matrix.FILES_DIR / f"set{n}" / member
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(spec.files_dir / member, dst)
            encodings[f"set{n}/{member}"] = list(spec.encodings[member])
        for q in spec.questions:
            nq = dict(q)
            nq.pop("qid", None)
            nq["id"] = f"set{n}.{_matrix.qid_of(q)}"
            questions.append(nq)
        if spec.key:
            key.update({f"set{n}.{k}": v for k, v in spec.key.items()})
    (out / _matrix.QUESTIONS_FILE).write_text(json.dumps(questions, indent=1), encoding="utf-8")
    if spec.key:
        (out / _matrix.KEY_FILE).write_text(json.dumps(key, indent=1), encoding="utf-8")
    lines = [f'note = {json.dumps(f"{copies} sets of {src.name}, {copies * total} bytes: past {min_total_bytes}")}',
             'encoding = ["raw"]', "", "[encodings]"]
    lines += [f"{json.dumps(k)} = {json.dumps(v)}" for k, v in sorted(encodings.items())]
    if spec.ctx:
        lines += ["", "[ctx]"] + [f"{json.dumps(k)} = {json.dumps(v)}" for k, v in spec.ctx.items()]
    (out / _matrix.SPECIMEN_FILE).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
