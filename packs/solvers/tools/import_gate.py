#!/usr/bin/env python3
"""The dangling-import gate (B-001b): every module of the tree imports, and no import names a module
that is not there.

The forks dropped modules and kept importing them behind `try: import x / except: pass`, so a feature
went quiet instead of failing (bundle routing ran for weeks without its registry). This gate is the
loud check:

  .venv/bin/python tools/import_gate.py                 static pass + import pass over this tree
  .venv/bin/python tools/import_gate.py --static        the static pass only (a few seconds)
  .venv/bin/python tools/import_gate.py --root DIR      another checkout, or a temp copy of this one
  .venv/bin/python tools/import_gate.py --tests         also scan test files (test_*.py, conftest.py)
  .venv/bin/python tools/import_gate.py --json          the report as JSON on stdout

Exit 0 when nothing fails, 1 when something does, 2 on a usage error.

Static pass (every .py under ctf/ solvers/ tools/ speedrun/ templates/, test files only with --tests).
Each `import` and `from ... import`, wherever it stands (inside a function, under `try`, under `if`:
a guarded import of a dropped module is exactly what this is for), is resolved:

  stdlib | a module or package of this tree | an installed distribution     -> fine
  ARCHIVED (below), imported from a file the entry allows                     -> listed, fine
  OPTIONAL_EXTERNAL (below), not installed                                    -> listed, fine here
  anything else                                                               -> DANGLING (fails)

A relative import must name a file beside it. A file named by path is checked too: a string `x.py`
used as the right side of `/` or passed to a module loader (spec_from_file_location, _load_beside,
load_module, run_path), and a repo path `solvers/.../x.py` written in code, must exist, unless it is
ARCHIVED for that file or a RUNTIME_FILES name (a file absent by design until play writes it).

Import pass. Every module (not templates/: they are fill-me exploit scaffolds that run exploit code at
import) is imported in worker processes, the way it runs: a module of a package chain (ctf/...) by its
dotted name, any other file by path with its own folder first on sys.path and the lane folders the
suite uses (conftest.py) behind it. Never as __main__, so no main() runs. Stdout is discarded,
CTF_WORKDIR is a temp folder, no bytecode is written. A module that fails to import fails the gate,
unless the missing module is an ARCHIVED one this file may use (listed) or an OPTIONAL_EXTERNAL
package that is not installed (listed as BLOCKED, like a needs_tool test that did not run: the
module cannot import here until the package is installed, and the gate says which).

Adding a dependency on a PyPI package that is not installed: add its import name to OPTIONAL_EXTERNAL
(and its pin to requirements.in when the tree needs it). An unknown name stays DANGLING: a dropped
module and a missing package look the same to a parser, and this gate never guesses which.
"""
from __future__ import annotations

import argparse
import ast
import functools
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("ctf", "solvers", "tools", "speedrun", "templates")
NO_EXEC_DIRS = ("templates",)
# The lane folders the suite puts on sys.path (conftest.py): bare `import labels` resolves through them.
IMPORT_ROOTS = ("solvers/common", "solvers/toolkits", "solvers/binary", "solvers/metadata-forensics",
                "solvers/mobile-android", "solvers/script-analysis", "solvers/warmups", "solvers/web", "tools")
SKIP_PARTS = {"__pycache__", ".git", ".venv", "node_modules"}
LOADER_FUNCS = {"spec_from_file_location", "_load_beside", "load_module", "run_path"}
WORKER_TAG = "IMPORT_GATE\t"
WORKER_TIMEOUT = 300.0

_TL = "solvers/script-analysis/timed_ladder.py"
_HUNTRESS = ("archived by the master merge plan (infra-tools-ctf-claude.merge.json, 'huntress-specific'); "
             "the Huntress Game Master runner that imports it waits for the Huntress adapter (B-005)")
# module -> (why it is not in the tree, the files that may still import it). Each of these files
# refuses by name when the module is missing (tools/run.py RUNNER_MISSING, timed_ladder.py's ImportError,
# tools/unpack.py's Stop). Any other file importing one of these is DANGLING.
ARCHIVED = {
    "gm": ("tools/gm.py, the Game Master client: " + _HUNTRESS, {"tools/run.py", "tools/unpack.py", _TL}),
    "lanes": ("tools/lanes.py, the Huntress lane registry: " + _HUNTRESS, {"tools/run.py", _TL}),
    "judge": ("tools/judge.py, the wire governor and clock locks: " + _HUNTRESS, {_TL}),
    "grade": ("tools/grade.py, bank-and-probe: " + _HUNTRESS, {"tools/run.py", _TL}),
    "preflight": ("tools/preflight.py, the clock gate and replay: " + _HUNTRESS, {"tools/run.py"}),
    "proposer_gate": ("tools/proposer_gate.py: " + _HUNTRESS, {"tools/run.py", _TL}),
    "proposer_wire": ("tools/proposer_wire.py: " + _HUNTRESS, {"tools/run.py", _TL}),
    "prefix_pool": ("tools/prefix_pool.py, the Binary lane pool: " + _HUNTRESS, {_TL}),
    "verify": ("tools/verify.py, Huntress bank-and-probe of an untimed base: " + _HUNTRESS
               + "; web_patch.verify_command only spells the command", {"solvers/web/web_patch.py"}),
}
# Files that are absent by design and loaded only when present: a lane's live-fix hook is written on the
# day from day_patch_template.py. Named here so their absence is a decision, not a miss.
RUNTIME_FILES = {
    "day_patch.py": "a lane's live-fix hook, written during play from day_patch_template.py; absent by design",
    "day_patch_live.py": "the promoted live-fix hook of the metadata lane; absent by design",
}
# Import names of PyPI packages the tree uses that may be absent from .venv (optional engines and their
# tests). Absent ones are listed, never failed; a module that cannot import without one is BLOCKED.
OPTIONAL_EXTERNAL = frozenset("""
    antlr4 asterix base2048 base65536 bincopy bip32 bitcoin bson canopen cantools cbor2 crccheck dns docx
    ecoji eth_abi eth_account eth_hash eth_keyfile eth_keys eth_utils evtx faster_whisper fdt fontTools fpylll
    ggwave graphql gurux_dlms hl7apy hyperframe intelhex ishneholterlib j2735_202409 jawa jwcrypto liblzfse
    mnemonic msal msgpack pdf417gen pg8000 piexif pillow_heif psd_tools psec pyais pycipher pycrate_asn1dir
    pycrate_asn1rt pycrate_core pycrate_mobile pydicom pydifact pyevmasm pymodbus pymysql pyModeS pynmea2
    pypff pyrad redis reedsolo rlp sarpy scipy simplefix solders solidity_parser sqlglot texture2ddecoder
    torch transformers ubireader wasmtime xlrd xlwt
""".split())

_PY_FILE = re.compile(r"[A-Za-z0-9_.\-/]+\.py")
_REPO_PATH = re.compile(r"(?:ctf|solvers|tools|speedrun|templates)/[A-Za-z0-9_.\-/]+\.py")


@dataclass
class Finding:
    kind: str          # fails: dangling | dangling-path | syntax | import-error
                       # listed: blocked | archived | runtime-file | external-missing
    file: str          # repo-relative
    line: int
    name: str
    detail: str = ""

    @property
    def fails(self) -> bool:
        return self.kind in ("dangling", "dangling-path", "syntax", "import-error")

    def text(self) -> str:
        where = f"{self.file}:{self.line}" if self.line else self.file
        return f"{self.kind.upper():16} {where}  {self.name}" + (f"  ({self.detail})" if self.detail else "")


@dataclass
class Report:
    root: str
    files: int = 0
    imported: int = 0
    seconds: float = 0.0
    findings: list = field(default_factory=list)

    @property
    def failures(self) -> list:
        return [f for f in self.findings if f.fails]


# ---------------------------------------------------------------------------------------------- the tree

def _skipped(p: Path) -> bool:
    return any(part in SKIP_PARTS for part in p.parts)


def is_test_file(p: Path) -> bool:
    return p.name.startswith("test_") or p.name == "conftest.py"


def collect(root: Path, tests: bool = False) -> list:
    """The .py files the gate scans, sorted (repo-relative order)."""
    out = []
    for d in SOURCE_DIRS:
        base = root / d
        if base.is_dir():
            out += [p for p in base.rglob("*.py") if not _skipped(p.relative_to(root)) and (tests or not is_test_file(p))]
    if tests and (root / "tests").is_dir():
        out += [p for p in (root / "tests").rglob("*.py") if not _skipped(p.relative_to(root))]
    if tests and (root / "conftest.py").is_file():
        out.append(root / "conftest.py")
    return sorted(set(out))


class Tree:
    """What exists in the tree: every .py by stem and basename, every folder that holds Python code."""

    def __init__(self, root: Path):
        self.root = root
        self.stems, self.basenames, self.dirs = set(), set(), set()
        for d in SOURCE_DIRS + ("tests",):
            for p in (root / d).rglob("*.py") if (root / d).is_dir() else ():
                rel = p.relative_to(root)
                if _skipped(rel):
                    continue
                self.stems.add(p.stem)
                self.basenames.add(p.name)
                for parent in rel.parents:
                    if str(parent) != ".":
                        self.dirs.add(parent.name)
        self.stems |= {p.stem for p in root.glob("*.py")}
        self.basenames |= {p.name for p in root.glob("*.py")}
        self.search = [root] + [root / r for r in IMPORT_ROOTS]

    def local_top(self, name: str) -> bool:
        return name in self.stems or name in self.dirs

    def dotted_exists(self, dotted: str, extra: Path) -> bool | None:
        """True/False when `dotted` (a.b.c) starts at a package or namespace folder of the tree; None when
        it starts at a module file or is not resolvable that way (left to the import pass). Every search
        folder is tried: namespace packages merge their portions across sys.path."""
        parts = dotted.split(".")
        if len(parts) == 1:
            return None
        seen_head = False
        for base in [extra] + self.search:
            if (base / parts[0]).is_dir():
                seen_head = True
                tail = base.joinpath(*parts)
                if tail.with_suffix(".py").is_file() or (tail / "__init__.py").is_file() or tail.is_dir():
                    return True
        return False if seen_head else None


@functools.lru_cache(maxsize=None)
def _installed(name: str) -> bool:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return False
    if spec is None:
        return False
    origin = Path(spec.origin) if spec.origin and spec.origin not in ("built-in", "frozen") else None
    if origin is not None and REPO in origin.parents \
            and not SKIP_PARTS.intersection(origin.relative_to(REPO).parts):
        return False                    # found in this repo through sys.path: that is the tree, not a package
    return True                         # (a .venv inside the checkout is installed packages, not the tree)


_STDLIB = set(sys.stdlib_module_names) | {"__future__"}


def classify_name(name: str, rel: str, tree: Tree) -> tuple[str, str] | None:
    """None when `name` (a top-level module name) resolves; else (kind, detail)."""
    if name in _STDLIB or tree.local_top(name):
        return None
    if name in ARCHIVED:
        why, allowed = ARCHIVED[name]
        if rel in allowed:
            return "archived", why
        return "dangling", f"{why}; this file is not one that may import it"
    if _installed(name):
        return None
    if name in OPTIONAL_EXTERNAL:
        return "external-missing", "optional PyPI package, not installed in this venv"
    return "dangling", "not in the tree, not installed, not a declared optional package (OPTIONAL_EXTERNAL)"


def _skip_ids(nodes: list) -> set:
    """ids of the string constants that name rather than load: docstrings and dict keys."""
    ids = set()
    for node in nodes:
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
        elif isinstance(node, ast.Dict):
            ids.update(id(k) for k in node.keys if k is not None)
    return ids


def _local_only(top: str, tree: Tree) -> bool:
    """A name that resolves to this tree and to nothing else (not stdlib, not an installed package)."""
    return top not in _STDLIB and tree.local_top(top) and not _installed(top)


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")


def static_scan(path: Path, tree: Tree) -> list:
    rel = str(path.relative_to(tree.root))
    try:
        mod = ast.parse(path.read_bytes(), filename=rel)
    except (SyntaxError, ValueError) as e:
        return [Finding("syntax", rel, getattr(e, "lineno", 0) or 0, "does not parse", str(e)[:200])]
    out = []
    here = path.parent

    def name_finding(top: str, line: int, shown: str):
        got = classify_name(top, rel, tree)
        if got:
            out.append(Finding(got[0], rel, line, shown, got[1]))

    nodes = list(ast.walk(mod))
    skip = _skip_ids(nodes)     # a docstring or a dict key names a file, it does not load one
    for node in nodes:
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                before = len(out)
                name_finding(top, node.lineno, a.name)
                if len(out) == before and _local_only(top, tree) and tree.dotted_exists(a.name, here) is False:
                    out.append(Finding("dangling", rel, node.lineno, a.name, "no such module in the tree"))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                top = node.module.split(".")[0]
                before = len(out)
                name_finding(top, node.lineno, node.module)
                if len(out) == before and _local_only(top, tree) and tree.dotted_exists(node.module, here) is False:
                    out.append(Finding("dangling", rel, node.lineno, node.module, "no such module in the tree"))
            elif node.level > 0:
                base = path.parent
                for _ in range(node.level - 1):
                    base = base.parent
                if node.module:
                    tail = base.joinpath(*node.module.split("."))
                    if not (tail.with_suffix(".py").is_file() or (tail / "__init__.py").is_file() or tail.is_dir()):
                        out.append(Finding("dangling", rel, node.lineno, "." * node.level + node.module,
                                           f"relative import: nothing at {tail.relative_to(tree.root)}"))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and _anchored(node):
            r = node.right
            if isinstance(r, ast.Constant) and isinstance(r.value, str) and _PY_FILE.fullmatch(r.value):
                _path_ref(r.value, node.lineno, rel, tree, out)
        elif isinstance(node, ast.Call) and _call_name(node) in LOADER_FUNCS:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and _PY_FILE.fullmatch(arg.value):
                    _path_ref(arg.value, node.lineno, rel, tree, out)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip
              and _REPO_PATH.fullmatch(node.value)):
            if not (tree.root / node.value).is_file():
                _path_ref(node.value, node.lineno, rel, tree, out, exact=True)
    return out


def _anchored(node: ast.BinOp) -> bool:
    """A path built from the module's own place: the leftmost operand of the `/` chain is a constant-style
    name (HERE, ROOT, _TOOLS, REPO) or derives from __file__. A path under a temp or caller folder is not
    a reference to the tree (it is usually a file being written)."""
    left = node
    while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Div):
        left = left.left
    if any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(left)):
        return True
    while isinstance(left, (ast.Attribute, ast.Call, ast.Subscript)):    # HERE.parent.parent -> HERE
        left = left.func if isinstance(left, ast.Call) else left.value
    return isinstance(left, ast.Name) and bool(re.fullmatch(r"_?[A-Z][A-Z0-9_]*", left.id))


def _path_ref(value: str, line: int, rel: str, tree: Tree, out: list, exact: bool = False) -> None:
    """A .py file named by path. `exact`: a repo-relative path that must exist as written; otherwise the
    basename must exist somewhere in the tree."""
    base = Path(value).name
    if "/" in value and (tree.root / value).is_file():
        return
    if not exact and base in tree.basenames:
        return
    if base in RUNTIME_FILES:
        out.append(Finding("runtime-file", rel, line, value, RUNTIME_FILES[base]))
        return
    arch = ARCHIVED.get(Path(base).stem)
    if arch and rel in arch[1]:
        out.append(Finding("archived", rel, line, value, arch[0]))
    else:
        what = "repo path not in the tree" if exact else "a .py file loaded by path that is not in the tree"
        out.append(Finding("dangling-path", rel, line, value, what))


# ---------------------------------------------------------------------------------------------- import pass

def _package_name(path: Path, root: Path) -> str | None:
    """The dotted name when every folder from the root down to the file is a package (ctf/...), else None."""
    rel = path.relative_to(root)
    if len(rel.parts) < 2:
        return None
    for i in range(1, len(rel.parts)):
        if not (root.joinpath(*rel.parts[:i]) / "__init__.py").is_file():
            return None
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _nested_package(path: Path, root: Path) -> tuple[Path, str] | None:
    """For a file in a package whose ancestors are not all packages (tools/ledger/live.py: tools/ has no
    __init__.py), the folder to put on sys.path and the dotted name from the topmost package down, so its
    relative imports resolve. None when the file's folder is not a package or a name is not importable."""
    top = path.parent
    if top == root or not (top / "__init__.py").is_file():
        return None
    while top.parent != root and (top.parent / "__init__.py").is_file():
        top = top.parent
    parts = list(path.relative_to(top.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if not all(p.isidentifier() for p in parts):
        return None
    return top.parent, ".".join(parts)


def _worker(root: Path, files_list: Path, out_path: Path) -> int:
    """Import each file named in `files_list` (one repo-relative path per line); one tagged JSON line per
    file to `out_path`, a "start" line before each import so a worker that dies names the file."""
    files = [ln.strip() for ln in files_list.read_text().splitlines() if ln.strip()]
    out = open(out_path, "a", buffering=1)
    sys.stdout = open(os.devnull, "w")         # a module's own prints go nowhere (the parent discards fd 1 and 2)
    sys.dont_write_bytecode = True
    for d in reversed(IMPORT_ROOTS):
        p = str(root / d)
        if p not in sys.path:
            sys.path.insert(0, p)
    if str(root) not in sys.path:
        sys.path.append(str(root))
    import importlib
    for i, rel in enumerate(files):
        path = root / rel
        out.write(WORKER_TAG + json.dumps({"start": rel}) + "\n")
        rec = {"file": rel, "ok": True}
        t0 = time.monotonic()
        saved_path = list(sys.path)
        try:
            dotted = _package_name(path, root)
            nested = None if dotted else _nested_package(path, root)
            if dotted:
                importlib.import_module(dotted)
            elif nested:
                sys.path.insert(0, str(nested[0]))
                importlib.import_module(nested[1])
            else:
                sys.path.insert(0, str(path.parent))
                name = f"import_gate_{i}_{path.stem}"
                spec = importlib.util.spec_from_file_location(name, path)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[name] = mod
                spec.loader.exec_module(mod)
        except BaseException as e:      # noqa: BLE001 - every way an import can fail is a result here
            rec.update(ok=False, exc=type(e).__name__, missing=getattr(e, "name", None) if isinstance(e, ImportError) else None,
                       msg=str(e)[:300])
            if isinstance(e, KeyboardInterrupt):
                raise
        finally:
            sys.path[:] = saved_path
        rec["s"] = round(time.monotonic() - t0, 3)
        out.write(WORKER_TAG + json.dumps(rec) + "\n")
    return 0


def _run_workers(root: Path, rels: list, jobs: int, timeout: float) -> tuple[dict, list]:
    """({rel: record}, [rel with no result]). A worker that dies or hangs (past `timeout` s) is restarted
    after the file it was importing, which is recorded as the failure."""
    results, lost = {}, []
    pending = list(rels)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CTF_TESTING="1")
    with tempfile.TemporaryDirectory(prefix="import-gate-") as work:
        env["CTF_WORKDIR"] = str(Path(work) / "workdir")
        rnd = 0
        while pending:
            rnd += 1
            procs = []
            for i in range(jobs):
                chunk = pending[i::jobs]
                if not chunk:
                    continue
                lst, out = Path(work) / f"files-{rnd}-{i}.txt", Path(work) / f"out-{rnd}-{i}.jsonl"
                lst.write_text("\n".join(chunk) + "\n")
                p = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", "--root", str(root),
                                      "--files", str(lst), "--out", str(out)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     env=env, cwd=work)
                procs.append((p, chunk, out))
            deadline = time.monotonic() + timeout
            next_pending = []
            for p, chunk, out in procs:
                try:
                    p.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                started = None
                for ln in (out.read_text().splitlines() if out.is_file() else []):
                    if not ln.startswith(WORKER_TAG):
                        continue
                    rec = json.loads(ln[len(WORKER_TAG):])
                    if "start" in rec:
                        started = rec["start"]
                    else:
                        results[rec["file"]] = rec
                        started = None
                undone = [r for r in chunk if r not in results]
                if undone:
                    culprit = started if started in undone else undone[0]
                    lost.append(culprit)
                    results[culprit] = {"file": culprit, "ok": False, "exc": "WorkerDied",
                                        "msg": f"the worker exited ({p.returncode}) or hung while importing it"}
                    next_pending += [r for r in undone if r != culprit]
            pending = next_pending
    return results, lost


def classify_import(rec: dict) -> Finding | None:
    if rec.get("ok"):
        return None
    rel, exc, missing, msg = rec["file"], rec.get("exc", ""), rec.get("missing"), rec.get("msg", "")
    if exc in ("ModuleNotFoundError", "ImportError") and missing:
        top = missing.split(".")[0]
        if top in ARCHIVED and rel in ARCHIVED[top][1]:
            return Finding("archived", rel, 0, missing, "does not import without it: " + msg)
        if top in OPTIONAL_EXTERNAL and not _installed(top):
            return Finding("blocked", rel, 0, missing, "cannot import until this optional package is installed")
        return Finding("import-error", rel, 0, missing, f"{exc}: {msg}")
    return Finding("import-error", rel, 0, exc or "error", msg)


# ---------------------------------------------------------------------------------------------- the gate

def run_gate(root: Path = REPO, *, static_only: bool = False, tests: bool = False, jobs: int = 4,
             timeout: float = WORKER_TIMEOUT) -> Report:
    root = Path(root).resolve()
    t0 = time.monotonic()
    files = collect(root, tests=tests)
    rep = Report(root=str(root), files=len(files))
    tree = Tree(root)
    for p in files:
        rep.findings += static_scan(p, tree)
    if not static_only:
        rels = [str(p.relative_to(root)) for p in files
                if not is_test_file(p) and p.relative_to(root).parts[0] not in NO_EXEC_DIRS
                and p.relative_to(root).parts[0] != "tests"]
        results, _ = _run_workers(root, rels, max(1, jobs), timeout)
        rep.imported = sum(1 for r in results.values() if r.get("ok"))
        for rel in rels:
            f = classify_import(results[rel])
            if f:
                rep.findings.append(f)
    order = {"dangling": 0, "dangling-path": 1, "syntax": 2, "import-error": 3, "blocked": 4, "archived": 5,
             "runtime-file": 6, "external-missing": 7}
    rep.findings.sort(key=lambda f: (order.get(f.kind, 9), f.file, f.line, f.name))
    rep.seconds = round(time.monotonic() - t0, 2)
    return rep


def render(rep: Report) -> str:
    lines = [f.text() for f in rep.findings]
    kinds = {}
    for f in rep.findings:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1
    lines.append(f"import gate: {rep.files} files scanned, {rep.imported} imported, {rep.seconds} s; "
                 + (", ".join(f"{k} {n}" for k, n in sorted(kinds.items())) or "no findings"))
    lines.append("FAIL: " + str(len(rep.failures)) + " failure(s)" if rep.failures else "PASS")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(REPO), help="the tree to check (default: this checkout)")
    ap.add_argument("--static", action="store_true", help="the static pass only")
    ap.add_argument("--tests", action="store_true", help="also scan test files (static pass)")
    ap.add_argument("--jobs", type=int, default=4, help="import-pass worker processes (default 4)")
    ap.add_argument("--timeout", type=float, default=WORKER_TIMEOUT, help="seconds per worker before it is killed")
    ap.add_argument("--json", action="store_true", help="the report as JSON")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--files", help=argparse.SUPPRESS)
    ap.add_argument("--out", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if not (root / "ctf").is_dir():
        print(f"import_gate: {root} is not a ctf-tools tree (no ctf/ folder)", file=sys.stderr)
        return 2
    if args.worker:
        return _worker(root, Path(args.files), Path(args.out))
    rep = run_gate(root, static_only=args.static, tests=args.tests, jobs=args.jobs, timeout=args.timeout)
    if args.json:
        d = asdict(rep)
        d["failures"] = len(rep.failures)
        print(json.dumps(d, indent=1))
    else:
        print(render(rep))
    return 1 if rep.failures else 0


if __name__ == "__main__":
    sys.exit(main())
