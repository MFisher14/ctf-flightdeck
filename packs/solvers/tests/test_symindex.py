"""B-199: the symbol index (ctf.symindex) and `ctf symbols`.

Synthetic trees built per test. Each test fails when the behaviour is wrong: a wrong line range, a
nested function listed as a symbol, a cache that re-parses unchanged files or serves stale symbols,
imports/importers off the gate graph, an ambiguous module resolved silently.
"""
from __future__ import annotations

import argparse
import subprocess
import textwrap
from pathlib import Path

import pytest

from ctf import symindex
from ctf.cli import symbols as cli_symbols
from ctf.gate import config as gate_config

GATE_TOML = """\
version = 1
tests = ["tests/test_*.py"]
roots = ["", "lib"]
global = []
inert = []
[wall]
base_seconds = 60
max_scale = 1.0
"""

MOD = textwrap.dedent('''\
    """A module."""
    import os

    LIMIT = 3
    A, B = 1, 2
    lower = 4
    __dunder__ = 5


    @decorator
    def top(a, b=1) -> int:
        """Top doc.

        More.
        """
        def inner():
            return 0
        return a + b


    async def fetch(url):
        return url


    class Box(Base, metaclass=Meta):
        """A box."""
        SIZE = 9

        def get(self):
            return 1

        class Inner:
            def deep(self):
                return 2
''')


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.delenv("CTF_EVENT", raising=False)


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    for rel, text in {"tests/gate.toml": GATE_TOML, **files}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def _index(root: Path, state: Path) -> symindex.SymbolIndex:
    files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    return symindex.SymbolIndex(root, state, cfg=gate_config.load(root), files=files)


# --------------------------------------------------------------------------- parsing

def test_parse_symbols_ranges_kinds_and_nesting():
    syms = {s.name: s for s in symindex.symbols_of(MOD)}
    assert set(syms) == {"LIMIT", "A", "B", "top", "fetch", "Box", "Box.get", "Box.Inner", "Box.Inner.deep"}
    top = syms["top"]
    assert (top.kind, top.start, top.end) == ("def", 10, 18)        # starts at the decorator
    assert top.signature == "(a, b=1) -> int" and top.doc == "Top doc."
    assert syms["fetch"].kind == "async def"
    box = syms["Box"]
    assert (box.kind, box.start, box.end, box.signature, box.doc) == ("class", 25, 34, "(Base, metaclass=Meta)", "A box.")
    assert (syms["Box.get"].start, syms["Box.get"].end) == (29, 30)
    assert (syms["Box.Inner.deep"].start, syms["Box.Inner.deep"].end) == (33, 34)
    assert syms["LIMIT"].kind == "const" and syms["LIMIT"].start == 4


def test_parse_error_is_named_not_empty():
    got = symindex.parse_symbols("def (:\n")
    assert got["symbols"] == [] and got["error"].startswith("SyntaxError")
    with pytest.raises(symindex.SymbolError, match="not parseable Python"):
        symindex.symbols_of("def (:\n")


def test_upper_case_dunders_are_not_constants():
    assert [s.name for s in symindex.symbols_of("__VERSION__ = 1\nMAX = 2\n__x__ = 3\n")] == ["MAX"]


def test_lookup_exact_then_last_part_then_dotted_suffix():
    syms = symindex.symbols_of(MOD + "\n\ndef get():\n    return 0\n")
    assert [s.name for s in symindex.lookup(syms, "Box.get")] == ["Box.get"]
    assert [s.name for s in symindex.lookup(syms, "get")] == ["get"]          # exact top-level wins
    assert [s.name for s in symindex.lookup(syms, "deep")] == ["Box.Inner.deep"]
    assert [s.name for s in symindex.lookup(syms, "Inner.deep")] == ["Box.Inner.deep"]
    assert symindex.lookup(syms, "nothing") == []
    two = symindex.symbols_of("class A:\n    def m(self): pass\nclass B:\n    def m(self): pass\n")
    assert [s.name for s in symindex.lookup(two, "m")] == ["A.m", "B.m"]


def test_format_symbol_indents_by_depth():
    s = symindex.Symbol("def", "Box.Inner.deep", 33, 34, "(self)", "Deep.")
    assert symindex.format_symbol(s) == "    L33-34  def deep(self)  # Deep."
    c = symindex.Symbol("const", "LIMIT", 4, 4, "", "")
    assert symindex.format_symbol(c) == "L4-4  LIMIT"


# --------------------------------------------------------------------------- the index

def test_index_caches_by_content_hash_and_reparses_only_changed_files(tmp_path):
    root = _tree(tmp_path, {"pkg/__init__.py": "", "pkg/a.py": MOD, "pkg/b.py": "def one():\n    pass\n"})
    state = tmp_path / "state"
    first = _index(root, state)
    assert first.stats.computed == 3 and first.stats.reused == 0
    again = _index(root, state)
    assert again.stats.computed == 0 and again.stats.reused == 3
    (root / "pkg/b.py").write_text("def two():\n    pass\n\n\ndef three():\n    pass\n")
    changed = _index(root, state)
    assert changed.stats.computed == 1 and changed.stats.reused == 2
    assert [s.name for s in changed.symbols("pkg/b.py")] == ["two", "three"]      # not the cached "one"
    assert changed.find("one") == []
    assert (state / symindex.SYMBOLS_FILE).is_file()


def test_imports_and_importers_come_from_the_gate_graph(tmp_path):
    root = _tree(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/core.py": "VALUE = 1\n",
        "pkg/user.py": "from pkg import core\n",
        "pkg/rel.py": "from . import core\n",
        "other.py": "import os\n",
        "tests/test_core.py": "from pkg.core import VALUE\n",
    })
    idx = _index(root, tmp_path / "state")
    assert idx.imports("pkg/user.py") == ["pkg/core.py"]
    assert idx.importers("pkg/core.py") == ["pkg/rel.py", "pkg/user.py", "tests/test_core.py"]
    assert idx.importers("other.py") == []
    out = idx.outline("pkg/core.py")
    assert out.splitlines()[0] == "pkg/core.py: 1 lines, 1 symbols"
    assert "imported by (3): pkg/rel.py, pkg/user.py, tests/test_core.py" in out
    assert "imported by" not in idx.outline("pkg/core.py", users=False)


def test_outline_caps_long_lists_and_names_the_rest(tmp_path):
    files = {"pkg/__init__.py": "", "pkg/core.py": "X = 1\n"}
    files.update({f"pkg/u{i:02d}.py": "from pkg import core\n" for i in range(15)})
    idx = _index(_tree(tmp_path, files), tmp_path / "state")
    assert "imported by (15): " in idx.outline("pkg/core.py", max_list=12)
    assert "(+3 more)" in idx.outline("pkg/core.py", max_list=12)


def test_resolve_paths_modules_and_ambiguity(tmp_path):
    root = _tree(tmp_path, {"pkg/__init__.py": "", "pkg/a.py": "X = 1\n", "x.py": "", "lib/x.py": "",
                            "notes.txt": "hi\n"})
    idx = _index(root, tmp_path / "state")
    assert idx.resolve("pkg.a") == "pkg/a.py"
    assert idx.resolve("pkg/a.py") == "pkg/a.py"
    assert idx.resolve(str(root / "pkg" / "a.py")) == "pkg/a.py"
    assert idx.resolve("pkg") == "pkg/__init__.py"
    with pytest.raises(symindex.SymbolError, match="ambiguous, it names x.py, lib/x.py"):
        idx.resolve("x")
    with pytest.raises(symindex.SymbolError, match="not a Python file"):
        idx.resolve("notes.txt")
    with pytest.raises(symindex.SymbolError, match="no module of that name"):
        idx.resolve("pkg.missing")


def test_find_across_the_tree(tmp_path):
    idx = _index(_tree(tmp_path, {"a.py": MOD, "b.py": "class Box:\n    pass\n"}), tmp_path / "state")
    assert [(rel, s.name) for rel, s in idx.find("Box")] == [("a.py", "Box"), ("b.py", "Box")]
    assert [(rel, s.name) for rel, s in idx.find("Box.get")] == [("a.py", "Box.get")]


# --------------------------------------------------------------------------- ctf symbols

def _git(root: Path) -> Path:
    """`ctf symbols` lists the checkout with git (untracked-not-ignored files count), as the gate does."""
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    return root


def _args(*argv):
    p = argparse.ArgumentParser()
    cli_symbols.add_arguments(p)
    return p.parse_args(list(argv))


def test_cli_outline_and_find(tmp_path, capsys):
    root = _git(_tree(tmp_path, {"pkg/__init__.py": "", "pkg/a.py": MOD}))
    st = str(tmp_path / "state")
    assert cli_symbols.run(_args("pkg.a", "--root", str(root), "--state", st)) == 0
    out = capsys.readouterr().out
    assert "L10-18  def top(a, b=1) -> int  # Top doc." in out
    assert "  L29-30  def get(self)" in out
    assert "python -m ctf read pkg/a.py --symbol NAME" in out
    assert cli_symbols.run(_args("--find", "deep", "--root", str(root), "--state", st)) == 0
    assert capsys.readouterr().out.strip() == "pkg/a.py:33-34  def Box.Inner.deep(self)"
    assert cli_symbols.run(_args("--find", "nope", "--root", str(root), "--state", st)) == 1
    assert cli_symbols.run(_args("pkg.missing", "--root", str(root), "--state", st)) == 2
    assert cli_symbols.run(_args("pkg.a", "--find", "x", "--root", str(root), "--state", st)) == 2
    assert cli_symbols.run(_args("--root", str(root), "--state", st)) == 2


def test_cli_without_a_gate_config_fails_loudly(tmp_path, capsys):
    root = tmp_path / "bare"
    (root).mkdir()
    (root / "m.py").write_text("X = 1\n")
    assert cli_symbols.run(_args("m", "--root", str(root), "--state", str(tmp_path / "s"))) == 2
    assert "gate config not found" in capsys.readouterr().err


def test_cli_outlines_a_file_outside_the_repo_and_refuses_secret_paths(tmp_path, capsys):
    root = _git(_tree(tmp_path, {"a.py": "X = 1\n"}))
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "solve.py").write_text(MOD)
    st = str(tmp_path / "state")
    assert cli_symbols.run(_args(str(chal / "solve.py"), "--root", str(root), "--state", st)) == 0
    out = capsys.readouterr().out
    assert "(outside the repo: no import graph)" in out and "L25-34  class Box(Base, metaclass=Meta)" in out
    secret = tmp_path / ".ctf"
    secret.mkdir()
    (secret / "x.py").write_text("TOKEN = 1\n")
    assert cli_symbols.run(_args(str(secret / "x.py"), "--root", str(root), "--state", st)) == 4
    assert capsys.readouterr().out == ""
    (chal / "bad.py").write_text("def (:\n")
    assert cli_symbols.run(_args(str(chal / "bad.py"), "--root", str(root), "--state", st)) == 2


def test_cli_in_repo_file_that_does_not_parse_exits_2_with_its_outline(tmp_path, capsys):
    root = _git(_tree(tmp_path, {"good.py": "X = 1\n", "bad.py": "import good\ndef (:\n"}))
    st = str(tmp_path / "state")
    assert cli_symbols.run(_args("bad", "--root", str(root), "--state", st)) == 2
    cap = capsys.readouterr()
    assert "parse error: SyntaxError" in cap.out and "bad.py does not parse" in cap.err
    assert cli_symbols.run(_args("good", "--root", str(root), "--state", st)) == 0


def test_cli_output_is_capped(tmp_path, capsys):
    big = "\n".join(f"def function_number_{i}(alpha, beta, gamma):\n    return {i}\n" for i in range(600))
    root = _git(_tree(tmp_path, {"big.py": big}))
    st = str(tmp_path / "state")
    assert cli_symbols.run(_args("big", "--root", str(root), "--state", st, "--max-tokens", "500")) == 0
    out = capsys.readouterr().out
    assert "[ctf: output capped" in out and "function_number_599" not in out
    assert cli_symbols.run(_args("big", "--root", str(root), "--state", st, "--no-cap")) == 0
    assert "function_number_599" in capsys.readouterr().out
