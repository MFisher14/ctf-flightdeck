#!/usr/bin/env python3
"""Find a broad `except` that could silently kill a release-path guard (B-137).

    python tools/guard_audit.py [PATH ...] [--json]

PATH defaults to the release-path sources (ctf/platform, ctf/budget.py, ctf/arm.py). Static (AST) only:
nothing is imported or run. Exit 0 when nothing is found, 1 when something is, 2 on a usage error or a
file that does not parse.

The guards are declared in ``ctf/gate/guards.py``. For each one, ``call_patterns`` gives the dotted
spellings that invoke it. This flags a ``try`` whose body calls a guard when a handler on that ``try``:

  * catches a broad type -- a bare ``except``, ``except Exception``, ``except BaseException``, or a
    tuple that contains one of those -- AND
  * neither re-raises (no ``raise`` in the handler) nor exits (``sys.exit``/``os._exit``/``pytest.exit``).

That is the exact shape from Oct 9: a guard call that raised (a NameError after a refactor) was swallowed
by a broad ``except`` that then carried on as if the guard had passed, so a dead guard looked armed. A
handler that re-raises, or that exits, fails closed and is not flagged; a narrow ``except`` that names a
specific error the guard is documented to raise is a contract, not a swallow, and is not flagged.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf.gate.guards import GUARDS  # noqa: E402

BROAD = {"Exception", "BaseException"}

# The release path: where a swallowed guard lets an irreversible act through. Relative to the repo root.
DEFAULT_PATHS = ("ctf/platform", "ctf/budget.py", "ctf/arm.py")


@dataclass
class Finding:
    path: str
    line: int
    guard: str
    detail: str

    def text(self) -> str:
        return f"{self.path}:{self.line}: guard {self.guard}: {self.detail}"


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _guard_for_call(call: ast.Call):
    """The guard a call invokes, by matching its dotted spelling against the registry, else None. A bare
    pattern (`base_checks`) matches the call's terminal name; a dotted pattern (`hof.check`) must match
    the spelling exactly or as its trailing `.`-segments, so a stray `.check()` is not caught."""
    spelled = _dotted(call.func)
    terminal = spelled.rsplit(".", 1)[-1]
    for g in GUARDS:
        for pat in g.call_patterns:
            if "." in pat:
                if spelled == pat or spelled.endswith("." + pat):
                    return g
            elif terminal == pat:
                return g
    return None


def _body_calls_guard(try_node: ast.Try):
    """The first guard a call in the try body (not its handlers) invokes, or None."""
    for stmt in try_node.body:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call):
                g = _guard_for_call(n)
                if g is not None:
                    return g
    return None


def _handler_caught(h: ast.ExceptHandler) -> set[str]:
    if h.type is None:
        return {"<bare>"}
    elts = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
    out = set()
    for e in elts:
        out.add(e.id if isinstance(e, ast.Name) else _dotted(e))
    return out


def _is_broad(caught: set[str]) -> bool:
    return "<bare>" in caught or bool(caught & BROAD)


def _fails_closed(h: ast.ExceptHandler) -> bool:
    """A handler that re-raises or exits: a swallowed guard cannot slip an act through it."""
    for n in ast.walk(h):
        if isinstance(n, ast.Raise):
            return True
        if isinstance(n, ast.Call) and _dotted(n.func) in ("sys.exit", "exit", "os._exit", "pytest.exit"):
            return True
    return False


def audit_tree(tree: ast.Module, rel: str) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        g = _body_calls_guard(node)
        if g is None:
            continue
        for h in node.handlers:
            caught = _handler_caught(h)
            if _is_broad(caught) and not _fails_closed(h):
                shown = ", ".join(sorted(c for c in caught if c != "<bare>")) or "a bare except"
                out.append(Finding(rel, h.lineno, g.id,
                                   f"broad `except {shown}` wraps the guard call and neither re-raises "
                                   f"nor exits: if {g.attr} raises, the guard is silently skipped"))
    return out


def _iter_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files += sorted(x for x in p.rglob("*.py") if "__pycache__" not in x.parts)
        else:
            raise FileNotFoundError(f"guard_audit: no such path: {p}")
    return sorted(set(files))


def audit(paths: list[Path], display_base: Path | None = None):
    """(findings, parse_errors) over the given source paths."""
    findings, errors = [], []
    for f in _iter_files(paths):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"), filename=str(f))
        except SyntaxError as e:
            errors.append(f"{f}: does not parse: {e.msg} (line {e.lineno})")
            continue
        rel = str(f)
        if display_base:
            try:
                rel = str(f.resolve().relative_to(display_base.resolve()))
            except ValueError:
                pass
        findings += audit_tree(tree, rel)
    findings.sort(key=lambda x: (x.path, x.line, x.guard))
    return findings, errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", type=Path, help="source files or folders (default: the release path)")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    args = ap.parse_args(argv)
    paths = args.paths or [REPO / p for p in DEFAULT_PATHS]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"guard_audit: no such path: {', '.join(map(str, missing))}", file=sys.stderr)
        return 2
    findings, errors = audit(paths, display_base=Path.cwd())
    if args.json:
        print(json.dumps({"findings": [asdict(x) for x in findings], "errors": errors}, indent=1))
    else:
        for x in findings:
            print(x.text())
        print(f"guard_audit: {len(findings)} finding(s) over {len(GUARDS)} guard(s)")
    for e in errors:
        print(f"guard_audit: {e}", file=sys.stderr)
    if errors:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
