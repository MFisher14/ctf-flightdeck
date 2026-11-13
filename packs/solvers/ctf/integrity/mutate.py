"""Mutation check (B-196): does any test notice when this code is wrong?

    python -m ctf integrity mutate FILE [--function NAME ...] [--lines A-B] [--op OP ...] [--max N]
                                        [--tests T ...] [--min-score S] [--json]

A green suite only means the tested code did what the tests checked. This check makes small, deliberate
bugs (mutants) in one source file and runs the tests the regression gate selects for that file
(`ctf.gate` impact selection, `ctf.gate.runner.run_file`, one pytest child per test file). A mutant some
test fails on is KILLED; one every selected test still passes on SURVIVED: a behaviour no test pins.
Huntress rewrote its hand mutation harness per review; this is the shipped one.

**Never in place.** The checkout is copied (its tracked and untracked-not-ignored files, as the gate lists
them) into a temporary folder, which gets a fresh `git init` (no history: its files are untracked, so a
test that lists the tree with git still sees them); each mutant is written into the copy, its stale
bytecode removed, its tests run there, and the original restored before the next mutant. The checkout
itself is only read.

**Operators** (inside function bodies only; module-level tables and constants are left alone):

    cmp       a comparison negated: == !=, < >=, > <=, in / not in, is / is not
    boundary  < <=, > >= (the off-by-one)
    bool      and <-> or
    not       `not x` -> `x`
    if        an if / while / ternary condition -> `not (cond)`
    const     True <-> False, an int n -> n + 1
    return    `return x` -> `return None`
    arith     + -, * //
    raise     a `raise` statement -> `pass`
    call      a bare call statement -> `None` (its side effect dropped)

A line carrying `# pragma: no mutate` is skipped. A mutant that does not compile, or whose text equals
another's, is dropped (counted as invalid / duplicate). Order is by line; `--max N` keeps N spread evenly.

**Before any mutant**, the selected tests run once on the unmutated copy: a red baseline is an
IntegrityError naming the file (a mutation score on red tests means nothing). Test files run fastest
first and a mutant stops at the first file that kills it. Each file's wall is a multiple of its baseline
time, never below MIN_WALL seconds, scaled by host load like the gate's wall: a mutant that hangs (an
infinite loop) is KILLED by timeout, which is a real wall-clock bound by design.

Result: one line per mutant, then `MUTATE file=... mutants=N killed=K survived=S ... score=K/N`. Exit 0
when the score reaches --min-score (default 1.0: every mutant killed), 1 below it, 2 on a usage error,
an unmapped file, a red baseline or a file no test selects (that is reported, not scored).
"""
from __future__ import annotations

import ast
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from . import IntegrityError

OPS = ("cmp", "boundary", "bool", "not", "if", "const", "return", "arith", "raise", "call")
PRAGMA = "pragma: no mutate"
MIN_WALL = 60.0          # seconds: a test file's mutant wall is never below this (before load scaling)
WALL_FACTOR = 5.0        # ... and otherwise this multiple of the file's baseline time

_NEGATE = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.GtE, ast.GtE: ast.Lt, ast.Gt: ast.LtE,
           ast.LtE: ast.Gt, ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
_BOUNDARY = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt}
_ARITH = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Mult: ast.FloorDiv, ast.FloorDiv: ast.Mult}


@dataclass(frozen=True)
class Mutant:
    rel: str             # repo-relative file
    line: int
    col: int
    op: str
    function: str        # qualified name of the function it is in
    before: str          # the source text replaced
    after: str           # what replaces it
    start: int           # character offsets of the replaced span in the file's text
    end: int

    @property
    def id(self) -> str:
        return f"{self.rel}:{self.line}:{self.col}:{self.op}"

    def apply(self, text: str) -> str:
        return text[:self.start] + self.after + text[self.end:]

    def describe(self) -> str:
        b = " ".join(self.before.split())
        a = " ".join(self.after.split())
        return f"{self.rel}:{self.line}:{self.col} {self.op} {_clip(b)!r} -> {_clip(a)!r} in {self.function}"


def _clip(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[:n - 3] + "..."


# ------------------------------------------------------------------------------------------ generation

class _Offsets:
    def __init__(self, text: str):
        self.starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.starts.append(i + 1)
        self.lines = text.split("\n")

    def at(self, line: int, col_bytes: int) -> int:
        """Character offset of (1-based line, utf-8 byte column) as ast reports positions."""
        src = self.lines[line - 1]
        return self.starts[line - 1] + len(src.encode("utf-8")[:col_bytes].decode("utf-8", errors="replace"))


def _paren(expr: ast.AST) -> str:
    return "(" + ast.unparse(expr) + ")"


def _variants(node: ast.AST, ops: set) -> list[tuple[str, str]]:
    """[(op, replacement text)] for one node; the replacement covers the node's whole span."""
    out = []
    if isinstance(node, ast.Compare):
        for i, o in enumerate(node.ops):
            for name, table in (("cmp", _NEGATE), ("boundary", _BOUNDARY)):
                new = table.get(type(o))
                if name in ops and new is not None:
                    m = ast.Compare(left=node.left, ops=list(node.ops), comparators=node.comparators)
                    m.ops[i] = new()
                    out.append((name, _paren(m)))
    elif isinstance(node, ast.BoolOp) and "bool" in ops:
        other = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        out.append(("bool", _paren(ast.BoolOp(op=other, values=node.values))))
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) and "not" in ops:
        out.append(("not", _paren(node.operand)))
    elif isinstance(node, ast.Constant) and "const" in ops:
        if node.value is True or node.value is False:
            out.append(("const", "(" + str(not node.value) + ")"))
        elif type(node.value) is int:
            out.append(("const", f"({node.value + 1})"))
    elif isinstance(node, ast.BinOp) and "arith" in ops:
        new = _ARITH.get(type(node.op))
        if new is not None:
            out.append(("arith", _paren(ast.BinOp(left=node.left, op=new(), right=node.right))))
    return out


def _functions(tree: ast.Module):
    out = []

    def walk(body, prefix):
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{n.name}"
                out.append((q, n))
                walk(n.body, q + ".")
            elif isinstance(n, ast.ClassDef):
                walk(n.body, f"{prefix}{n.name}.")
    walk(tree.body, "")
    return out


def _skip_ids(fn) -> set:
    """Nodes never mutated: annotations, docstrings, decorators, default values, f-string internals and
    the body of nested functions (they are visited as their own function)."""
    skip = set()

    def mark(n):
        for x in ast.walk(n):
            skip.add(id(x))
    for d in fn.decorator_list:
        mark(d)
    a = fn.args
    for arg in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg]:
        if arg is not None and arg.annotation is not None:
            mark(arg.annotation)
    for d in a.defaults + [x for x in a.kw_defaults if x is not None]:
        mark(d)
    if fn.returns is not None:
        mark(fn.returns)
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        mark(body[0])
    for n in ast.walk(fn):
        if n is fn:
            continue
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            mark(n)
        elif isinstance(n, (ast.JoinedStr, ast.AnnAssign)):
            mark(n.annotation if isinstance(n, ast.AnnAssign) else n)
        elif isinstance(n, ast.match_case):
            mark(n.pattern)
    return skip


def generate(root: Path, rel: str, *, ops=OPS, functions=(), lines: tuple[int, int] | None = None) -> tuple[list[Mutant], dict]:
    """(mutants, counts) for one file. counts: invalid (did not compile), duplicate, pragma (skipped)."""
    unknown = set(ops) - set(OPS)
    if unknown:
        raise IntegrityError(f"unknown mutation operator(s) {sorted(unknown)}; known: {', '.join(OPS)}")
    path = Path(root) / rel
    if not rel.endswith(".py") or not path.is_file():
        raise IntegrityError(f"{rel}: not a Python file in {root}")
    text = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as e:
        raise IntegrityError(f"{rel}: does not parse: {e.msg} (line {e.lineno})") from e
    off = _Offsets(text)
    ops = set(ops)
    counts = {"invalid": 0, "duplicate": 0, "pragma": 0}
    fns = _functions(tree)
    if functions:
        wanted = set(functions)
        fns = [(q, f) for q, f in fns if q in wanted or q.rsplit(".", 1)[-1] in wanted]
        if not fns:
            raise IntegrityError(f"{rel}: no function named {', '.join(sorted(wanted))}")
    raw: list[Mutant] = []
    for qual, fn in fns:
        skip = _skip_ids(fn)
        for n in ast.walk(fn):
            if n is fn or id(n) in skip or not hasattr(n, "lineno") or getattr(n, "end_lineno", None) is None:
                continue
            if lines and not (lines[0] <= n.lineno <= lines[1]):
                continue
            if PRAGMA in off.lines[n.lineno - 1]:
                counts["pragma"] += 1
                continue
            start, end = off.at(n.lineno, n.col_offset), off.at(n.end_lineno, n.end_col_offset)
            before = text[start:end]
            variants = []
            if isinstance(n, ast.expr):
                variants = _variants(n, ops)
            elif isinstance(n, (ast.If, ast.While)) and "if" in ops:
                t = n.test
                ts, te = off.at(t.lineno, t.col_offset), off.at(t.end_lineno, t.end_col_offset)
                raw.append(Mutant(rel, t.lineno, t.col_offset, "if", qual, text[ts:te],
                                  "not (" + text[ts:te] + ")", ts, te))
            elif isinstance(n, ast.Return) and "return" in ops and n.value is not None and not (
                    isinstance(n.value, ast.Constant) and n.value.value is None):
                v = n.value
                vs, ve = off.at(v.lineno, v.col_offset), off.at(v.end_lineno, v.end_col_offset)
                raw.append(Mutant(rel, v.lineno, v.col_offset, "return", qual, text[vs:ve], "None", vs, ve))
            elif isinstance(n, ast.Raise) and "raise" in ops:
                variants = [("raise", "pass")]
            elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and "call" in ops:
                variants = [("call", "None")]
            if isinstance(n, ast.IfExp) and "if" in ops:
                t = n.test
                ts, te = off.at(t.lineno, t.col_offset), off.at(t.end_lineno, t.end_col_offset)
                raw.append(Mutant(rel, t.lineno, t.col_offset, "if", qual, text[ts:te],
                                  "not (" + text[ts:te] + ")", ts, te))
            for op, after in variants:
                raw.append(Mutant(rel, n.lineno, n.col_offset, op, qual, before, after, start, end))
    out, seen = [], {text}
    for m in sorted(raw, key=lambda m: (m.start, m.end, OPS.index(m.op), m.after)):
        new = m.apply(text)
        if new in seen:
            counts["duplicate"] += 1
            continue
        try:
            compile(new, rel, "exec", dont_inherit=True)
        except (SyntaxError, ValueError):
            counts["invalid"] += 1
            continue
        seen.add(new)
        out.append(m)
    return out, counts


def spread(mutants: list, n: int | None) -> list:
    """At most n mutants, evenly spread over the list (all when n is None or >= len)."""
    if n is None or n >= len(mutants):
        return list(mutants)
    if n <= 0:
        return []
    step = len(mutants) / n
    return [mutants[int(i * step)] for i in range(n)]


# ---------------------------------------------------------------------------------------------- running

@dataclass
class Outcome:
    mutant: Mutant
    status: str                       # KILLED SURVIVED
    by: str = ""                      # the test file that killed it
    how: str = ""                     # FAIL ERROR TIMEOUT EMPTY
    seconds: float = 0.0

    def text(self) -> str:
        s = f"{self.status:<8} {self.mutant.describe()}"
        if self.by:
            s += f"  <- {self.by} ({self.how})"
        return s


@dataclass
class MutationReport:
    rel: str
    tests: list
    mutants: list = field(default_factory=list)       # Outcome
    counts: dict = field(default_factory=dict)        # invalid / duplicate / pragma / generated
    baseline_seconds: dict = field(default_factory=dict)
    seconds: float = 0.0

    @property
    def killed(self) -> int:
        return sum(1 for o in self.mutants if o.status == "KILLED")

    @property
    def survived(self) -> list:
        return [o for o in self.mutants if o.status == "SURVIVED"]

    @property
    def score(self) -> float:
        return self.killed / len(self.mutants) if self.mutants else 1.0

    def summary(self) -> str:
        timeouts = sum(1 for o in self.mutants if o.how == "TIMEOUT")
        return (f"MUTATE file={self.rel} tests={len(self.tests)} mutants={len(self.mutants)} killed={self.killed} "
                f"survived={len(self.survived)} timeout={timeouts} invalid={self.counts.get('invalid', 0)} "
                f"duplicate={self.counts.get('duplicate', 0)} pragma={self.counts.get('pragma', 0)} "
                f"score={self.killed}/{len(self.mutants)} seconds={self.seconds:.1f}")

    def to_json(self) -> dict:
        return {"file": self.rel, "tests": self.tests, "counts": self.counts, "seconds": round(self.seconds, 3),
                "killed": self.killed, "survived": len(self.survived), "score": round(self.score, 4),
                "mutants": [{**asdict(o.mutant), "id": o.mutant.id, "status": o.status, "by": o.by, "how": o.how,
                             "seconds": round(o.seconds, 3)} for o in self.mutants]}


def select_tests(root: Path, rel: str, *, state: Path, config: Path | None = None) -> list[str]:
    """The test files the regression gate selects for a change to `rel` (impact mode only)."""
    from ..gate import GateError
    from ..gate import config as gconfig
    from ..gate.impact import Graph
    from ..gate.warm import checkout_state
    try:
        cfg = gconfig.load(root, config)
        graph = Graph(root, cfg, checkout_state(state, root))
        sel = graph.select([rel])
    except GateError as e:
        raise IntegrityError(f"gate: {e}") from e
    if sel.mode != "impact":
        raise IntegrityError(f"the gate cannot narrow a change to {rel} ({'; '.join(sel.reasons)}): name the "
                             f"tests with --tests")
    return list(sel.tests)


def copy_checkout(root: Path, dest: Path) -> Path:
    """Copy the files the gate lists (tracked + untracked-not-ignored) into dest; returns dest."""
    from ..gate import GateError
    from ..gate.impact import list_files
    try:
        files = list_files(root)
    except GateError as e:
        raise IntegrityError(str(e)) from e
    for rel in files:
        src = Path(root) / rel
        if src.is_symlink():
            continue
        dst = dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    # A fresh, empty repository, so a test that lists the tree with git (the gate's own tests do) sees
    # the copy's files as untracked ones. It has no commits: a test that needs history fails the
    # baseline, which says so by name.
    import subprocess
    try:
        r = subprocess.run(["git", "init", "-q"], cwd=str(dest), capture_output=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise IntegrityError(f"git init in the mutation copy failed: {e}") from e
    if r.returncode != 0:
        raise IntegrityError(f"git init in the mutation copy failed: {r.stderr.decode(errors='replace').strip()}")
    return dest


def _drop_bytecode(path: Path) -> None:
    cache = path.parent / "__pycache__"
    if cache.is_dir():
        for p in cache.glob(path.stem + ".*.pyc"):
            try:
                p.unlink()
            except OSError:
                pass


def _write(path: Path, text: str, tick: int) -> None:
    """Write `text` and give it a fresh mtime, so no import can mistake stale bytecode for it."""
    st = path.stat()
    path.write_text(text, encoding="utf-8")
    t = st.st_mtime + 2 * tick + 2
    os.utime(path, (t, t))
    _drop_bytecode(path)


def run(root: Path, rel: str, *, tests: list | None = None, ops=OPS, functions=(), lines=None,
        max_mutants: int | None = None, state: Path | None = None, config: Path | None = None,
        work: Path | None = None, emit: Callable[[str], None] = print, python: str | None = None,
        load_fn: Callable[[], float] | None = None, cpus: int | None = None,
        run_file: Callable | None = None, min_wall: float = MIN_WALL,
        wall_factor: float = WALL_FACTOR) -> MutationReport:
    """Mutate `rel` in a copy of `root` and run its tests on each mutant. See the module docstring."""
    from ..gate import runner as grunner
    root = Path(root).resolve()
    rel = Path(rel).as_posix()
    if Path(rel).is_absolute():
        try:
            rel = Path(rel).resolve().relative_to(root).as_posix()
        except ValueError as e:
            raise IntegrityError(f"{rel} is outside the checkout {root}") from e
    mutants, counts = generate(root, rel, ops=ops, functions=functions, lines=lines)
    counts["generated"] = len(mutants)
    mutants = spread(mutants, max_mutants)
    if tests:
        tests = [Path(t).as_posix() for t in tests]
        missing = [t for t in tests if not (root / t).is_file()]
        if missing:
            raise IntegrityError(f"--tests: no such file: {', '.join(missing)}")
    else:
        if state is None:
            from .. import paths
            try:
                state = paths.gate_state(root)
            except FileNotFoundError as e:
                raise IntegrityError(str(e)) from e
        tests = select_tests(root, rel, state=state, config=config)
    rep = MutationReport(rel, list(tests), counts=counts)
    if not tests:
        raise IntegrityError(f"no test file selects {rel}: every mutant would survive (write a test first)")
    if not mutants:
        emit(f"mutate: {rel}: no mutant to run (generated {counts['generated']})")
        return rep
    run_file = run_file or grunner.run_file
    load_fn = load_fn or grunner.host_load
    cpus = cpus or os.cpu_count() or 1
    t0 = time.monotonic()
    tmp = Path(tempfile.mkdtemp(prefix="ctf-mutate-", dir=str(work) if work else None))
    try:
        copy = copy_checkout(root, tmp / "tree")
        out_dir = tmp / "out"
        target = copy / rel
        original = target.read_text(encoding="utf-8")
        emit(f"mutate: {rel}: {len(mutants)} mutant(s) of {counts['generated']}, tests: {', '.join(tests)}")
        base = {}
        for t in tests:
            wall, _ = grunner.scaled_wall(max(min_wall, 600.0), 4.0, load_fn(), cpus)
            row = run_file(copy, t, out_dir=out_dir / "baseline", wall=wall, python=python)
            if row.status != "PASS":
                raise IntegrityError(f"baseline is not green in the copy: {t} is {row.status} ({row.detail}); "
                                     f"fix it before a mutation check")
            base[t] = row.seconds
        rep.baseline_seconds = base
        order = sorted(tests, key=lambda t: base[t])
        for i, m in enumerate(mutants):
            _write(target, m.apply(original), i)
            m0 = time.monotonic()
            outcome = Outcome(m, "SURVIVED")
            try:
                for t in order:
                    wall, _ = grunner.scaled_wall(max(min_wall, wall_factor * base[t]), 4.0, load_fn(), cpus)
                    row = run_file(copy, t, out_dir=out_dir / f"m{i}", wall=wall, python=python,
                                   pytest_args=("-x",))
                    if row.status != "PASS":
                        outcome = Outcome(m, "KILLED", by=t, how=row.status)
                        break
            finally:
                _write(target, original, i + len(mutants) + 1)
            outcome.seconds = time.monotonic() - m0
            rep.mutants.append(outcome)
            emit(outcome.text())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rep.seconds = time.monotonic() - t0
    return rep
