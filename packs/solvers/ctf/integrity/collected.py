"""Collection check (B-196): every test file is one pytest collects and the gate runs, or one a collected test runs.

At CSCTF non-standard file names left 7 of 8 lane test files uncollected: their tests never ran and the
suite was green. Static (AST and config only, nothing imported or run). Findings, one per file:

    misnamed     a file under tests/ that defines pytest-style tests (a module-level `def test_*`, or a
                 `class Test*` with `test_*` methods) but whose name does not match pytest.ini python_files
                 (default test_*.py), and that no other test file imports: pytest never collects it
    ignored      a test file named in a conftest.py collect_ignore list
    not-gated    a collected test file the regression gate's `tests` globs (tests/gate.toml) do not match:
                 `ctf gate` never selects it
    no-tests     a collected test file with no test function or class: pytest collects nothing from it
                 (a script-style file whose checks run only under `__main__`)
    stray        a test_*.py or selftest*.py file outside tests/ (pytest.ini testpaths = tests, so pytest
                 never collects it) that no file under tests/ runs or imports: its checks never run.
                 "Runs or imports" is read from the tests/ sources: one names the file's repo-relative
                 path, or names its folder (a quoted path segment) together with its file name or an
                 `import <stem>` / `from <stem> import` line (also inside a subprocess's code string);
                 a file at the checkout root is reached by such an import line alone

Folders whose conftest.py collects the files itself (pytest_pycollect_makemodule, tests/real) are skipped.

    check(root) -> list[Finding]
"""
from __future__ import annotations

import ast
import configparser
import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import IntegrityError
from .testfiles import TESTS_DIR, conftest_facts, ignored_by, parse

RULES = ("misnamed", "ignored", "not-gated", "no-tests", "stray")
# Test-shaped file names outside tests/ that the stray rule looks at.
STRAY_PREFIXES = ("test_", "selftest")
# Folders the stray rule never walks: tests/ itself, docs and event templates, and data or runtime state
# (gitignored corpora, challenge files, analysis output) that is not code under test.
STRAY_PRUNE = frozenset({"tests", "docs", "events", "corpus", "analysis", "challenges", "_realdata", "workspace",
                         "writeups", "logs", "scratchpad", "node_modules", "__pycache__"})


@dataclass(frozen=True)
class Finding:
    path: str
    rule: str
    detail: str

    def text(self) -> str:
        return f"{self.rule:<9} {self.path}: {self.detail}"


def python_files(root: Path) -> tuple[str, ...]:
    """pytest.ini [pytest] python_files patterns (pytest's default when unset)."""
    ini = Path(root) / "pytest.ini"
    if not ini.is_file():
        return ("test_*.py", "*_test.py")
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(ini, encoding="utf-8")
    except configparser.Error as e:
        raise IntegrityError(f"pytest.ini: {e}") from e
    raw = cp.get("pytest", "python_files", fallback="test_*.py *_test.py")
    return tuple(raw.split())


def _defines_tests(tree: ast.Module) -> bool:
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test"):
            return True
        if isinstance(n, ast.ClassDef) and n.name.startswith("Test") and any(
                isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and s.name.startswith("test") for s in n.body):
            return True
    return False


def _imported_names(trees) -> set:
    out = set()
    for tree in trees:
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                out.update(a.name.rsplit(".", 1)[-1] for a in n.names)
            elif isinstance(n, ast.ImportFrom):
                if n.module:
                    out.add(n.module.rsplit(".", 1)[-1])
                out.update(a.name for a in n.names)
    return out


def check(root: Path, *, gate_tests: tuple | None = None) -> list[Finding]:
    """Every finding for the checkout at `root`. `gate_tests` (globs) defaults to tests/gate.toml's."""
    from ..gate.config import matches
    root = Path(root)
    tdir = root / TESTS_DIR
    if not tdir.is_dir():
        raise IntegrityError(f"no {TESTS_DIR}/ folder under {root}")
    if gate_tests is None:
        from ..gate import GateError
        from ..gate import config as gconfig
        try:
            gate_tests = gconfig.load(root).tests
        except GateError as e:
            raise IntegrityError(f"gate config: {e}") from e
    patterns = python_files(root)
    files = sorted(p for p in tdir.rglob("*.py") if "__pycache__" not in p.parts)
    facts = {}
    custom_dirs = set()
    for c in (p for p in files if p.name == "conftest.py"):
        facts[c.parent] = conftest_facts(c)
        if facts[c.parent][1]:
            custom_dirs.add(c.parent)
    trees = {p: parse(p) for p in files}
    imported = _imported_names(t for t in trees.values() if t is not None)
    out = []
    for p in files:
        if p.name == "conftest.py" or any(d == p.parent or d in p.parents for d in custom_dirs):
            continue
        rel = p.relative_to(root).as_posix()
        tree = trees[p]
        if tree is None:
            continue                      # a syntax error is the suite's own collection error
        named = any(fnmatch.fnmatch(p.name, pat) for pat in patterns)
        ignored = any(ignored_by(p, d, facts[d][0]) for d in facts if d == p.parent or d in p.parents)
        if not named:
            if _defines_tests(tree) and p.stem not in imported:
                out.append(Finding(rel, "misnamed", f"defines tests but does not match python_files "
                                   f"{' '.join(patterns)}: pytest never collects it (rename it test_<x>.py)"))
            continue
        if ignored:
            out.append(Finding(rel, "ignored", "named in a conftest.py collect_ignore list: pytest never runs it"))
            continue
        if not matches(rel, gate_tests):
            out.append(Finding(rel, "not-gated", f"collected by pytest but not matched by the gate's tests "
                               f"globs ({', '.join(gate_tests)}): ctf gate never selects it"))
        if not _defines_tests(tree):
            out.append(Finding(rel, "no-tests", "no test function or Test class: pytest collects nothing "
                               "from it (move its checks into test functions)"))
    out.extend(stray(root, {p: p.read_text(encoding="utf-8", errors="replace") for p in files}))
    return out


def _outside_candidates(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        dirnames[:] = sorted(n for n in dirnames if not n.startswith(".") and not (d == root and n in STRAY_PRUNE)
                             and n not in ("node_modules", "__pycache__"))
        for n in sorted(filenames):
            if n.endswith(".py") and n.startswith(STRAY_PREFIXES):
                yield d / n


def reached(rel: str, texts) -> bool:
    """True when one of the tests/ source `texts` runs or imports the outside file `rel` (see `stray`)."""
    p = Path(rel)
    folder = re.compile(r"[\"'/]" + re.escape(p.parent.name) + r"[\"'/]")
    named = re.compile(r"[\"'/]" + re.escape(p.name) + r"[\"']")
    imports = re.compile(r"(?m)^\s*(?:import\s+(?:[\w.]+\s*,\s*)*" + re.escape(p.stem) + r"\b"
                         r"|from\s+" + re.escape(p.stem) + r"\s+import\b)")
    for s in texts:
        if rel in s:
            return True
        # a root-level file has no folder to name: the checkout root is on sys.path in a pytest run
        # (rootdir conftest.py), so an import line alone reaches it
        if (not p.parent.name or folder.search(s)) and (named.search(s) or imports.search(s)):
            return True
    return False


def stray(root: Path, tests_texts: dict) -> list[Finding]:
    """`stray` findings: test-shaped files outside tests/ that no tests/ source runs or imports."""
    root = Path(root)
    texts = list(tests_texts.values())
    out = []
    for p in _outside_candidates(root):
        rel = p.relative_to(root).as_posix()
        if not reached(rel, texts):
            out.append(Finding(rel, "stray", "a test or self-test file outside tests/ (testpaths = tests): pytest "
                               "never collects it and no tests/ file runs or imports it (move its checks into "
                               "tests/, or call it from a test)"))
    return out


KNOWN = "tests/collection_known.toml"


@dataclass
class CollectAudit:
    new: list            # findings not in the known list: the check fails on these
    known: list          # findings listed in tests/collection_known.toml (reported, not failed)
    stale: list          # known entries that no longer match a finding: remove them

    @property
    def ok(self) -> bool:
        return not self.new and not self.stale


def load_known(root: Path) -> dict:
    """{(rule, path): reason} from tests/collection_known.toml (`[[known]]` rule, path, reason)."""
    import tomllib
    p = Path(root) / KNOWN
    if not p.is_file():
        return {}
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise IntegrityError(f"{KNOWN}: not valid TOML: {e}") from e
    extra = set(raw) - {"known"}
    if extra:
        raise IntegrityError(f"{KNOWN}: unknown key(s) {sorted(extra)}")
    out = {}
    for i, e in enumerate(raw.get("known", [])):
        if not isinstance(e, dict) or set(e) != {"rule", "path", "reason"}:
            raise IntegrityError(f"{KNOWN}: [[known]] #{i + 1} needs exactly rule, path, reason")
        if e["rule"] not in RULES:
            raise IntegrityError(f"{KNOWN}: [[known]] #{i + 1}: unknown rule {e['rule']!r}")
        if not isinstance(e["reason"], str) or not e["reason"].strip():
            raise IntegrityError(f"{KNOWN}: [[known]] #{i + 1}: reason must say why")
        out[(e["rule"], e["path"])] = e["reason"]
    return out


def audit(root: Path, **kw) -> CollectAudit:
    """check() split against the known list: new findings, known ones, and stale known entries."""
    found = check(root, **kw)
    known = load_known(root)
    keys = {(f.rule, f.path) for f in found}
    return CollectAudit(new=[f for f in found if (f.rule, f.path) not in known],
                        known=[f for f in found if (f.rule, f.path) in known],
                        stale=sorted(f"{rule} {path}" for rule, path in known if (rule, path) not in keys))
