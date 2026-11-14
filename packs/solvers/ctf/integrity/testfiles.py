"""The test files pytest collects in a checkout, and the parsed source of the tree (shared by the checks).

    collected_test_files(root)   tests/**/test_*.py that pytest collects: not in a conftest collect_ignore,
                                 not under a folder whose conftest collects its files itself (tests/real)
    parse(path)                  ast.Module or None (a file that does not parse is reported by its check)
    source_files(root, dirs)     the non-test .py files under the given folders (repo-relative, sorted)
"""
from __future__ import annotations

import ast
import fnmatch
from functools import lru_cache
from pathlib import Path

TESTS_DIR = "tests"
# Files under the source folders that are tests or self-test scripts themselves, not code under test.
_NOT_SOURCE_PREFIXES = ("test_", "selftest")
_SKIP_PARTS = {"__pycache__", ".venv", "node_modules", ".git"}


def parse(path: Path) -> ast.Module | None:
    return _parse(str(path), _stat_key(path))


def _stat_key(path: Path):
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_size, st.st_mtime_ns, st.st_ino)


@lru_cache(maxsize=8192)
def _parse(path: str, _key) -> ast.Module | None:
    try:
        return ast.parse(Path(path).read_text(encoding="utf-8", errors="replace"), filename=path)
    except (SyntaxError, ValueError, OSError):
        return None


def conftest_facts(conftest: Path) -> tuple[set, bool]:
    """(names in collect_ignore / collect_ignore_glob, collects its folder itself) of one conftest.py."""
    tree = parse(conftest)
    if tree is None:
        return set(), False
    ignored, custom = set(), False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "pytest_pycollect_makemodule":
            custom = True
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in ("collect_ignore", "collect_ignore_glob") for t in targets) \
                    and isinstance(node.value, (ast.List, ast.Tuple)):
                ignored |= {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return ignored, custom


def ignored_by(path: Path, conftest_dir: Path, entries) -> bool:
    """True when a conftest.py in `conftest_dir` with these collect_ignore / collect_ignore_glob entries
    ignores `path`. pytest resolves both lists relative to the conftest's own folder (a bare file name in
    tests/conftest.py ignores tests/<name> only, never tests/sub/<name>). conftest_facts merges both lists,
    so every entry is matched as a case-sensitive glob; a plain path is a glob that matches only itself
    (a literal collect_ignore entry holding `*`, `?` or `[` would be over-read: none does).
    """
    rel = Path(path).relative_to(conftest_dir).as_posix()
    return any(fnmatch.fnmatchcase(rel, e) for e in entries)


def _walk_py(base: Path):
    if not base.is_dir():
        return
    for p in sorted(base.rglob("*.py")):
        if not _SKIP_PARTS & set(p.relative_to(base).parts):
            yield p


def collected_test_files(root: Path) -> list[str]:
    """Repo-relative test files pytest collects as ordinary modules (python_files = test_*.py)."""
    root = Path(root)
    tdir = root / TESTS_DIR
    if not tdir.is_dir():
        from . import IntegrityError
        raise IntegrityError(f"no {TESTS_DIR}/ folder under {root}")
    facts: dict[Path, tuple[set, bool]] = {}
    out = []
    for p in _walk_py(tdir):
        if not p.name.startswith("test_"):
            continue
        skip, d = False, p.parent
        while True:
            c = d / "conftest.py"
            if c.is_file():
                if c not in facts:
                    facts[c] = conftest_facts(c)
                ignored, custom = facts[c]
                if custom or ignored_by(p, d, ignored):
                    skip = True
                    break
            if d == root:
                break
            d = d.parent
        if not skip:
            out.append(p.relative_to(root).as_posix())
    return out


def source_files(root: Path, dirs) -> list[str]:
    """Non-test Python files under `dirs` (repo-relative folders), sorted."""
    root = Path(root)
    out = []
    for d in dirs:
        for p in _walk_py(root / d):
            if p.name.startswith(_NOT_SOURCE_PREFIXES) or p.name == "conftest.py":
                continue
            out.append(p.relative_to(root).as_posix())
    return sorted(set(out))
