#!/usr/bin/env python3
"""Run the full test suite from the repo, the way docs/migration/BASELINE.md recorded it.

    python tools/suite.py [--junit PATH] [-n N] [--no-sandbox] [-- PYTEST_ARGS ...]

The recipe, in one place:

  * outbound network denied except loopback: the run is wrapped in macOS `sandbox-exec` with the
    committed profile tools/suite.sb (tests talk only to fake services they start on 127.0.0.1);
  * `--continue-on-collection-errors`: a file that cannot be imported (a missing optional package)
    is reported as an error and the rest of the suite still runs;
  * `-n 8` xdist workers (`-n N` to change, `-n 0` for one process), `--timeout 300` per test,
    `-p no:cacheprovider` (nothing written under .pytest_cache), `-q -rfE`;
  * junit XML written to PATH (default: a timestamped file in the temp folder, printed at the end).
    Compare two runs per test with tools/junit_diff.py.

Arguments after `--` go to pytest unchanged (select files, `-k`, `-m`, ...). The pytest interpreter is
resolved like tools/ctfpy and the gate's children (ctf.pyinterp, B-153): `--python PATH`, else
$CTF_PYTHON, else this checkout's .venv, else the main checkout's .venv (a linked worktree has none of
its own), else the interpreter running this script. The choice and its source are printed first.

Before pytest starts, every collected test file is checked for a sys.exit() / SystemExit at import
(outside `if __name__ == "__main__":`). Such a file aborts the whole pytest session at collection
(INTERNALERROR on every worker); the run is refused, naming the file and line, instead.

Exit status: pytest's own; 2 when the run is refused (an import-time exit, no sandbox-exec, the
profile or a pytest plugin missing) or on a usage error.
"""
from __future__ import annotations

import argparse
import ast
import datetime as _dt
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))         # ctf.pyinterp, when run as a script with any interpreter
PROFILE = REPO / "tools" / "suite.sb"
DEFAULT_WORKERS = 8
TIMEOUT = 300
# Calls that end the interpreter (or the pytest session) when a module runs them at import.
EXIT_CALLS = frozenset({"sys.exit", "exit", "quit", "os._exit", "pytest.exit"})


# --------------------------------------------------------------------------- import-time exit lint

def _is_main_guard(node: ast.AST) -> bool:
    """`if __name__ == "__main__":` (either operand order)."""
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    t = node.test
    if len(t.ops) != 1 or not isinstance(t.ops[0], ast.Eq):
        return False
    sides = [t.left, t.comparators[0]]
    names = [s for s in sides if isinstance(s, ast.Name) and s.id == "__name__"]
    consts = [s for s in sides if isinstance(s, ast.Constant) and s.value == "__main__"]
    return bool(names and consts)


def _exit_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        name = ast.unparse(node.func)
        if name in EXIT_CALLS:
            return name
        if name == "SystemExit":
            return "SystemExit"
    if isinstance(node, ast.Raise) and node.exc is not None:
        exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
        if isinstance(exc, ast.Name) and exc.id == "SystemExit":
            return "raise SystemExit"
    return None


def _scan(nodes) -> list[tuple[int, str]]:
    """Exits in code that runs at import: module and class bodies, including if/for/try/with blocks.
    Function and lambda bodies run only when called; a __main__ guard's body only as a script."""
    hits: list[tuple[int, str]] = []
    todo = list(nodes)
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            todo.extend(node.decorator_list)
            todo.extend(d for d in node.args.defaults + node.args.kw_defaults if d is not None)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if _is_main_guard(node):
            todo.extend(node.orelse)
            continue
        what = _exit_of(node)
        if what:
            hits.append((node.lineno, what))
        todo.extend(ast.iter_child_nodes(node))
    # a `raise SystemExit(...)` is reported once, not again for its inner SystemExit(...) call
    lines = {ln for ln, w in hits if w == "raise SystemExit"}
    hits = [(ln, w) for ln, w in hits if not (w == "SystemExit" and ln in lines)]
    return sorted(set(hits))


def module_level_exits(source: str, filename: str = "<source>") -> list[tuple[int, str]]:
    """(line, call) for every interpreter exit a module would run when imported."""
    return _scan(ast.parse(source, filename).body)


def _takes_over_collection(conftest: Path) -> bool:
    """A conftest.py that defines pytest_pycollect_makemodule collects its folder's files itself
    (tests/real/ runs each script in a child process), so pytest never imports them."""
    try:
        tree = ast.parse(conftest.read_text(encoding="utf-8"), str(conftest))
    except (OSError, SyntaxError):
        return False
    return any(isinstance(n, ast.FunctionDef) and n.name == "pytest_pycollect_makemodule" for n in tree.body)


def lint_tests(tests_dir: Path) -> list[str]:
    """One line per test file that exits at import: `<path>:<line>: <call> at import`."""
    tests_dir = Path(tests_dir)
    skip = {c.parent for c in tests_dir.rglob("conftest.py") if _takes_over_collection(c)}
    problems = []
    for f in sorted(tests_dir.rglob("test_*.py")):
        if "__pycache__" in f.parts or any(d == f.parent or d in f.parents for d in skip):
            continue
        try:
            hits = module_level_exits(f.read_text(encoding="utf-8"), str(f))
        except SyntaxError:
            continue          # pytest reports it as that file's collection error; it does not abort the run
        rel = f.relative_to(tests_dir.parent) if tests_dir.parent in f.parents else f
        problems += [f"{rel}:{line}: {what} at import" for line, what in hits]
    return problems


# --------------------------------------------------------------------------- the command

def default_junit() -> Path:
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(tempfile.gettempdir()) / f"ctf-suite-{stamp}.xml"


def build_command(junit: Path, workers: int = DEFAULT_WORKERS, sandbox: bool = True,
                  extra: list[str] | None = None, python: str | None = None) -> list[str]:
    cmd = [python or sys.executable, "-m", "pytest", "-q", "-n", str(workers), "--timeout", str(TIMEOUT),
           "-p", "no:cacheprovider", "--continue-on-collection-errors", "-rfE", f"--junitxml={junit}"]
    cmd += list(extra or [])
    if sandbox:
        cmd = ["sandbox-exec", "-f", str(PROFILE)] + cmd
    return cmd


def _missing_plugins(workers: int, python: str | None = None) -> list[str]:
    """The pytest plugins `python` (default: this interpreter) lacks. Another interpreter is asked in a
    child process; one that cannot even start lacks them all."""
    need = {"pytest": "pytest", "pytest_timeout": "pytest-timeout"}
    if workers > 0:
        need["xdist"] = "pytest-xdist"
    if python is None or python == sys.executable:
        return [pkg for mod, pkg in need.items() if importlib.util.find_spec(mod) is None]
    probe = ("import importlib.util, sys\n"
             f"print(' '.join(m for m in {sorted(need)!r} if importlib.util.find_spec(m) is None))")
    try:
        r = subprocess.run([python, "-c", probe], capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return list(need.values())
    if r.returncode != 0:
        return list(need.values())
    return [need[m] for m in r.stdout.split()]


def resolve_python(repo: Path, explicit: str | None = None):
    """(path, source) of the pytest interpreter (ctf.pyinterp); raises ValueError naming a bad one."""
    from ctf import pyinterp
    if explicit:
        p = Path(explicit)
        if not (p.is_file() and os.access(p, os.X_OK)):
            raise ValueError(f"--python {explicit} is not an executable interpreter")
        return explicit, "--python"
    try:
        it = pyinterp.resolve(repo)
    except pyinterp.PythonError as e:
        raise ValueError(str(e)) from e
    return it.path, it.source


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tools/suite.py", description=__doc__.split("\n\n")[0],
                                 epilog="Arguments after -- are passed to pytest.")
    ap.add_argument("--junit", type=Path, help="junit XML output (default: a timestamped file in the temp folder)")
    ap.add_argument("-n", "--workers", type=int, default=DEFAULT_WORKERS, help="xdist workers (default 8; 0 = one process)")
    ap.add_argument("--no-sandbox", action="store_true", help="run without the sandbox-exec network sandbox")
    ap.add_argument("--python", help="the pytest interpreter (default: $CTF_PYTHON, the checkout's .venv, the "
                                     "main checkout's .venv, then this one)")
    return ap


def main(argv: list[str] | None = None, repo: Path = REPO) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    extra: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    args = _parser().parse_args(argv)
    if args.workers < 0:
        print("suite: -n must be 0 or more", file=sys.stderr)
        return 2

    problems = lint_tests(Path(repo) / "tests")
    if problems:
        print("suite: refusing to run: these test files exit at import, which aborts the whole pytest "
              "session at collection (move the code under `if __name__ == \"__main__\":` or into test functions):",
              file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 2

    try:
        python, source = resolve_python(Path(repo), args.python)
    except ValueError as e:
        print(f"suite: {e}", file=sys.stderr)
        return 2
    print(f"suite: python {python} ({source})", file=sys.stderr, flush=True)
    missing = _missing_plugins(args.workers, python)
    if missing:
        print(f"suite: {python} ({source}) lacks {', '.join(missing)}: set CTF_PYTHON or --python to the "
              "repo venv's interpreter, or run ./setup.sh in the main checkout", file=sys.stderr)
        return 2

    sandbox = not args.no_sandbox
    if sandbox:
        if shutil.which("sandbox-exec") is None:
            print("suite: sandbox-exec not found (it is macOS only): pass --no-sandbox to run without the "
                  "network sandbox", file=sys.stderr)
            return 2
        if not PROFILE.is_file():
            print(f"suite: sandbox profile {PROFILE} is missing", file=sys.stderr)
            return 2

    junit = (args.junit or default_junit()).resolve()
    junit.parent.mkdir(parents=True, exist_ok=True)
    cmd = build_command(junit, args.workers, sandbox, extra, python=python)
    print("suite: " + " ".join(cmd), file=sys.stderr, flush=True)
    rc = subprocess.call(cmd, cwd=str(repo))
    print(f"suite: exit {rc}; junit {junit}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
