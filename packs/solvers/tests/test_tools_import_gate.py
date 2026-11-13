"""tools/import_gate.py, the dangling-import gate (B-001b).

The gate passes on this tree; a dangling import planted in a temp copy (never in the tree) fails it; and
each rule is pinned on a small synthetic tree: a guarded import of a dropped module, a relative import
of nothing, a pack loaded by path that is not there, an archived module outside the files allowed to
import it, a missing optional package, a module that kills its worker.
"""
import shutil
import textwrap
from pathlib import Path

import pytest

import import_gate as gate

REPO = Path(__file__).resolve().parent.parent


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))
    return p


def _kinds(rep) -> set:
    return {(f.kind, f.file, f.name) for f in rep.findings}


# ------------------------------------------------------------------------------------------ the real tree

@pytest.mark.slow
def test_gate_passes_on_this_tree_and_imports_every_module():
    rep = gate.run_gate(REPO, jobs=2)
    assert rep.failures == [], gate.render(rep)
    executable = [p for p in gate.collect(REPO) if p.relative_to(REPO).parts[0] not in gate.NO_EXEC_DIRS]
    not_imported = {f.file for f in rep.findings if f.kind in ("blocked", "archived") and not f.line}
    assert rep.imported == len(executable) - len(not_imported) and rep.imported > 700
    # The Huntress runner's archived modules are named, not hidden.
    assert ("archived", "solvers/script-analysis/timed_ladder.py", "gm") in _kinds(rep)


def _py_only_copy(tmp_path: Path) -> Path:
    """A temp copy of the tree's Python files (the static pass reads nothing else)."""
    def ignore(d, names):
        return [n for n in names if n in gate.SKIP_PARTS or (Path(d, n).is_file() and not n.endswith(".py"))]
    root = tmp_path / "tree"
    for d in gate.SOURCE_DIRS + ("tests", ".githooks"):
        shutil.copytree(REPO / d, root / d, ignore=ignore)
    return root


def test_gate_fails_on_a_dangling_import_planted_in_a_temp_copy(tmp_path):
    root = _py_only_copy(tmp_path)
    clean = gate.run_gate(root, static_only=True)
    assert clean.failures == [], gate.render(clean)
    target = root / "solvers" / "toolkits" / "network.py"
    target.write_text(target.read_text() + textwrap.dedent("""

        def _b001b_planted():
            try:                                   # guarded, as the forks hid their dropped modules
                import dropped_module_b001b        # noqa: F401
            except ImportError:
                pass
        """))
    rep = gate.run_gate(root, static_only=True)
    assert [(f.kind, f.file, f.name) for f in rep.failures] == [
        ("dangling", "solvers/toolkits/network.py", "dropped_module_b001b")]
    assert gate.main(["--root", str(root), "--static"]) == 1
    assert not (REPO / "solvers" / "toolkits" / "network.py").read_text().count("dropped_module_b001b")


# ------------------------------------------------------------------------------------------ the rules

@pytest.fixture()
def tiny(tmp_path):
    root = tmp_path / "tiny"
    _write(root, "ctf/__init__.py", "")
    _write(root, "ctf/fine.py", "from . import sibling\n")
    _write(root, "ctf/sibling.py", "X = 1\n")
    _write(root, "solvers/common/ok.py", "import json\nimport fine_helper\n")
    _write(root, "solvers/common/fine_helper.py", "Y = 2\n")
    return root


def test_a_clean_tiny_tree_passes_both_passes(tiny):
    rep = gate.run_gate(tiny, jobs=1)
    assert rep.failures == [] and rep.imported == 5, gate.render(rep)
    assert gate.main(["--root", str(tiny)]) == 0


def test_unguarded_dangling_import_fails_both_passes(tiny):
    _write(tiny, "solvers/common/bad.py", "import dropped_module_b001b\n")
    rep = gate.run_gate(tiny, jobs=1)
    got = {(f.kind, f.name) for f in rep.failures if f.file == "solvers/common/bad.py"}
    assert got == {("dangling", "dropped_module_b001b"), ("import-error", "dropped_module_b001b")}


def test_relative_import_of_nothing_and_missing_submodule_are_dangling(tiny):
    _write(tiny, "ctf/rel.py", "from .nope import thing\n")
    _write(tiny, "solvers/common/sub.py", "def f():\n    import ctf.gone\n")
    rep = gate.run_gate(tiny, static_only=True)
    assert {(f.kind, f.file, f.name) for f in rep.failures} == {
        ("dangling", "ctf/rel.py", ".nope"), ("dangling", "solvers/common/sub.py", "ctf.gone")}


def test_a_pack_loaded_by_path_must_exist_unless_it_is_a_runtime_file(tiny):
    _write(tiny, "solvers/common/loader.py", """\
        from pathlib import Path
        HERE = Path(__file__).resolve().parent
        PACK = HERE / "readers_dropped.py"
        PATCH = HERE / "day_patch.py"
        def scratch(tmp):
            return tmp / "written_here.py"          # a file being written, not a reference
        """)
    rep = gate.run_gate(tiny, static_only=True)
    assert [(f.kind, f.name) for f in rep.failures] == [("dangling-path", "readers_dropped.py")]
    assert ("runtime-file", "solvers/common/loader.py", "day_patch.py") in _kinds(rep)


def test_archived_module_is_allowed_only_in_the_files_named(tiny):
    _write(tiny, "tools/run.py", "try:\n    import gm\nexcept ImportError:\n    gm = None\n")
    _write(tiny, "tools/other.py", "def f():\n    import gm\n")
    rep = gate.run_gate(tiny, static_only=True)
    assert ("archived", "tools/run.py", "gm") in _kinds(rep)
    assert [(f.kind, f.file) for f in rep.failures] == [("dangling", "tools/other.py")]


def test_missing_optional_package_blocks_its_module_without_failing(tiny, monkeypatch):
    monkeypatch.setattr(gate, "OPTIONAL_EXTERNAL", gate.OPTIONAL_EXTERNAL | {"b001b_fake_pypi_pkg"})
    _write(tiny, "solvers/common/needs_pkg.py", "import b001b_fake_pypi_pkg\n")
    rep = gate.run_gate(tiny, jobs=1)
    assert rep.failures == [], gate.render(rep)
    assert ("external-missing", "solvers/common/needs_pkg.py", "b001b_fake_pypi_pkg") in _kinds(rep)
    assert ("blocked", "solvers/common/needs_pkg.py", "b001b_fake_pypi_pkg") in _kinds(rep)


def test_a_module_that_kills_its_worker_fails_and_the_rest_still_import(tiny):
    _write(tiny, "solvers/common/aaa_exits.py", "import os\nos._exit(7)\n")
    rep = gate.run_gate(tiny, jobs=1)
    assert [(f.kind, f.file, f.name) for f in rep.failures] == [
        ("import-error", "solvers/common/aaa_exits.py", "WorkerDied")]
    assert rep.imported == 5


def test_syntax_error_fails(tiny):
    _write(tiny, "solvers/common/broken.py", "def (:\n")
    rep = gate.run_gate(tiny, static_only=True)
    assert [(f.kind, f.file) for f in rep.failures] == [("syntax", "solvers/common/broken.py")]


def test_not_a_tree_is_a_usage_error(tmp_path):
    assert gate.main(["--root", str(tmp_path), "--static"]) == 2


def test_a_package_inside_a_namespace_folder_imports_with_its_relative_imports(tiny):
    # tools/ has no __init__.py, tools/pkg/ does (the B-033 tools/ledger shape): `from . import` must resolve.
    _write(tiny, "tools/pkg/__init__.py", "")
    _write(tiny, "tools/pkg/core.py", "Z = 3\n")
    _write(tiny, "tools/pkg/__main__.py", "from . import core\nif __name__ == '__main__':\n    raise SystemExit(1)\n")
    _write(tiny, "tools/pkg/live.py", "from . import core\nassert core.Z == 3\n")
    rep = gate.run_gate(tiny, jobs=1)
    assert rep.failures == [], gate.render(rep)
    assert rep.imported == 9


def test_a_venv_inside_the_checkout_is_installed_packages_not_the_tree(tmp_path, monkeypatch):
    # The main checkout keeps .venv under the repo root; its site-packages must not count as the tree.
    root = tmp_path / "repo"
    _write(root, ".venv/lib/site-packages/b001b_venv_pkg/__init__.py", "")
    _write(root, "solvers/b001b_tree_mod.py", "")
    monkeypatch.syspath_prepend(str(root / ".venv/lib/site-packages"))
    monkeypatch.syspath_prepend(str(root / "solvers"))
    monkeypatch.setattr(gate, "REPO", root.resolve())
    gate._installed.cache_clear()
    try:
        assert gate._installed("b001b_venv_pkg") is True
        assert gate._installed("b001b_tree_mod") is False
    finally:
        gate._installed.cache_clear()
