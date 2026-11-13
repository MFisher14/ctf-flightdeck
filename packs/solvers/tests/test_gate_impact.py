"""B-195: test-impact selection over the static dependency graph (ctf/gate/impact.py), on a synthetic
git checkout built here."""
from __future__ import annotations

import pytest

from ctf.gate import GateError, config
from ctf.gate.impact import Graph, changed_files, list_files, parse_source
from gate_repo import git, make_repo, write

SCAN = """
[[scan]]
why = "reads every data file"
tests = ["tests/test_scan.py"]
inputs = ["data/**"]

[lanes]
liblane = ["lib/**"]
pkglane = ["pkg/**"]
"""

FILES = {
    "lib/alpha.py": "import beta\n",
    "lib/beta.py": "X = 1\n",
    "lib/leafmod.py": "import beta\n",
    "pkg/__init__.py": "",
    "pkg/core.py": "from . import helpers\n",
    "pkg/helpers.py": 'DATA = "pkg/data/table.json"\n',
    "pkg/data/table.json": "{}\n",
    "ns/mod.py": "Y = 2\n",
    "tool/run_me.py": "import gamma\n",
    "tool/gamma.py": "Z = 3\n",
    "extra/deep/side.py": "S = 4\n",
    "data/notes.cfg": "k=v\n",
    "docs/guide.md": "# guide\n",
    "setup.cfg": "[x]\n",
    "tests/conftest.py": 'collect_ignore = ["test_alpha.py"]\n',
    "tests/fixtures/imgs/a.bin": b"\x00\x01",
    "tests/test_alpha.py": "import alpha\ndef test_a():\n    assert alpha\n",
    "tests/test_pkg.py": "from pkg import core\ndef test_p():\n    assert core\n",
    "tests/test_ns.py": "from ns import mod\ndef test_n():\n    assert mod.Y == 2\n",
    "tests/test_script.py": 'SCRIPT = "tool/run_me.py"\ndef test_s():\n    assert SCRIPT\n',
    "tests/test_dyn.py": 'import importlib\ndef test_d():\n    importlib.import_module("pkg.helpers")\n',
    "tests/test_side.py": ('import sys\nfrom pathlib import Path\nREPO = Path(__file__).parent.parent\n'
                           'sys.path.insert(0, str(REPO / "extra" / "deep"))\nimport side\n'),
    "tests/test_bare.py": 'CFG = "notes.cfg"\nHELPER = "leafmod.py"\n',
    "tests/test_fixture_dir.py": 'from pathlib import Path\nIMGS = Path(__file__).parent / "fixtures" / "imgs"\n',
    "tests/test_scan.py": "def test_scan():\n    pass\n",
    "pkg/uses_lib.py": "import beta\n",
    "tests/test_chain.py": "from pkg import uses_lib\n",
    "lib/alpha2.py": "import leafmod\n",
    "tests/test_both.py": 'HELPER = "leafmod.py"\nimport alpha2\n',
    "tests/test_bareword.py": 'WORD = "deep"\nimport side\n',
    "tests/test_dunder.py": 'NAMES = ("__init__.py", "__main__.py")\nimport __main__\n',
}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES, extra_config=SCAN)


def graph(root, tmp_path):
    return Graph(root, config.load(root, root / "gate.toml"), tmp_path / "state")


def sel(root, tmp_path, *changed):
    return graph(root, tmp_path).select(list(changed))


@pytest.mark.parametrize("changed,expected", [
    ("lib/beta.py", ["tests/test_alpha.py", "tests/test_both.py", "tests/test_chain.py"]),  # config root
    ("pkg/data/table.json", ["tests/test_dyn.py", "tests/test_pkg.py"]),       # a path string, two hops in
    ("pkg/__init__.py", ["tests/test_chain.py", "tests/test_dyn.py", "tests/test_pkg.py"]),  # package init
    ("pkg/helpers.py", ["tests/test_dyn.py", "tests/test_pkg.py"]),            # relative import + dotted string
    ("ns/mod.py", ["tests/test_ns.py"]),                                       # from <namespace pkg> import x
    ("tool/gamma.py", ["tests/test_script.py"]),                               # a spelled-out script is followed
    ("extra/deep/side.py", ["tests/test_side.py"]),        # REPO / "extra" / "deep" root; a bare "deep" is not
    ("data/notes.cfg", ["tests/test_bare.py", "tests/test_scan.py"]),          # bare name + scan rule
    ("lib/leafmod.py", ["tests/test_bare.py", "tests/test_both.py"]),          # bare .py name: its content
    ("tests/fixtures/imgs/a.bin", ["tests/test_fixture_dir.py"]),              # data under a named folder
    ("tests/test_ns.py", ["tests/test_ns.py"]),                                # a test is in its own closure
])
def test_changed_file_selects_exactly_its_tests(repo, tmp_path, changed, expected):
    s = sel(repo, tmp_path, changed)
    assert s.mode == "impact"
    assert s.tests == expected
    assert all(s.why[t] == [changed] for t in expected)


def test_bare_name_is_not_followed(repo, tmp_path):
    """test_bare names "leafmod.py" (content counts) but does not import it, so leafmod's own import of beta
    is not test_bare's dependency."""
    g = graph(repo, tmp_path)
    assert "lib/leafmod.py" in g.closure("tests/test_bare.py")
    assert "lib/beta.py" not in g.closure("tests/test_bare.py")


def test_a_leaf_reached_again_by_import_is_followed(repo, tmp_path):
    """test_both names leafmod.py (a leaf) and also imports alpha2, which imports leafmod: then leafmod's own
    imports are test_both's too."""
    assert "lib/beta.py" in graph(repo, tmp_path).closure("tests/test_both.py")


def test_dunder_names_are_not_references(repo, tmp_path):
    g = graph(repo, tmp_path)
    assert g.closure("tests/test_dunder.py") == {"tests/test_dunder.py", "tests/conftest.py"}


def test_conftest_collect_ignore_is_not_a_dependency(repo, tmp_path):
    g = graph(repo, tmp_path)
    assert "tests/conftest.py" in g.closure("tests/test_ns.py")       # a test's own folder conftest counts
    assert "tests/test_alpha.py" not in g.closure("tests/test_ns.py")
    assert sel(repo, tmp_path, "tests/conftest.py").tests == sorted(t for t in FILES if t.startswith("tests/test_"))


def test_global_input_forces_a_full_run(repo, tmp_path):
    s = sel(repo, tmp_path, "pytest.ini", "lib/beta.py")
    assert s.mode == "full"
    assert s.tests == sorted(t for t in FILES if t.startswith("tests/test_")) and "global input changed: pytest.ini" in s.reasons[0]


def test_unmapped_change_forces_a_full_run_and_names_it(repo, tmp_path):
    s = sel(repo, tmp_path, "setup.cfg", "lib/beta.py")
    assert s.mode == "full" and s.unmapped == ["setup.cfg"]
    assert "no test maps to setup.cfg" in s.reasons[0]


def test_inert_change_selects_nothing_and_says_so(repo, tmp_path):
    s = sel(repo, tmp_path, "docs/guide.md")
    assert (s.mode, s.tests, s.inert) == ("impact", [], ["docs/guide.md"])
    assert any("inert" in r for r in s.reasons)


def test_deleted_module_selects_its_importers(repo, tmp_path):
    (repo / "lib" / "beta.py").unlink()
    s = sel(repo, tmp_path, "lib/beta.py")
    assert s.mode == "impact" and s.tests == ["tests/test_alpha.py", "tests/test_both.py", "tests/test_chain.py"]


def test_deleted_data_file_selects_tests_naming_it(repo, tmp_path):
    (repo / "data" / "notes.cfg").unlink()
    assert sel(repo, tmp_path, "data/notes.cfg").tests == ["tests/test_bare.py", "tests/test_scan.py"]


def test_new_untracked_test_file_is_selected(repo, tmp_path):
    write(repo, {"tests/test_new.py": "import beta\n"})
    g = graph(repo, tmp_path)
    assert "tests/test_new.py" in g.tests
    assert g.select(["lib/beta.py"]).tests == ["tests/test_alpha.py", "tests/test_both.py", "tests/test_chain.py",
                                               "tests/test_new.py"]


def test_lanes_are_direct_dependencies(repo, tmp_path):
    g = graph(repo, tmp_path)
    # test_chain reaches lib/ only through pkg/uses_lib.py: it tests pkg, not lib
    assert g.lane_tests("liblane") == ["tests/test_alpha.py", "tests/test_bare.py", "tests/test_both.py"]
    assert g.lane_tests("pkglane") == ["tests/test_chain.py", "tests/test_dyn.py", "tests/test_pkg.py"]
    with pytest.raises(GateError, match="unknown lane 'nope'"):
        g.lane_tests("nope")


def test_inputs_hold_closure_globals_scan_and_named_data(repo, tmp_path):
    g = graph(repo, tmp_path)
    ins = g.inputs("tests/test_fixture_dir.py")
    assert "tests/fixtures/imgs/a.bin" in ins
    assert {"pytest.ini", "gate.toml", "tests/conftest.py"} <= set(ins)
    assert "data/notes.cfg" in g.inputs("tests/test_scan.py")
    assert "lib/beta.py" not in ins


def test_inventory_reparses_only_changed_python(repo, tmp_path):
    g1 = graph(repo, tmp_path)
    assert g1.stats.computed == g1.stats.total > 0
    g2 = graph(repo, tmp_path)
    assert g2.stats.computed == 0 and g2.stats.reused == g1.stats.total
    write(repo, {"lib/beta.py": "X = 2\nimport alpha\n"})
    g3 = graph(repo, tmp_path)
    assert g3.stats.computed == 1
    assert "lib/alpha.py" in g3.node("lib/beta.py").deps


def test_syntax_error_is_recorded_not_fatal(repo, tmp_path):
    write(repo, {"lib/broken.py": "def (:\n", "tests/test_broken.py": "import broken\n"})
    g = graph(repo, tmp_path)
    assert g.node("lib/broken.py").error.startswith("SyntaxError")
    assert g.select(["lib/broken.py"]).tests == ["tests/test_broken.py"]
    assert parse_source("x = (")["error"]


def test_changed_files_from_git(repo):
    write(repo, {"lib/beta.py": "X = 9\n", "lib/new.py": "N = 1\n"})
    (repo / "ns" / "mod.py").unlink()
    git(repo, "add", "lib/beta.py")
    write(repo, {"pkg/helpers.py": "DATA = 1\n"})          # unstaged
    assert changed_files(repo, "HEAD") == ["lib/beta.py", "lib/new.py", "ns/mod.py", "pkg/helpers.py"]
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "two")
    assert changed_files(repo, "HEAD~1") == ["lib/beta.py", "lib/new.py", "ns/mod.py", "pkg/helpers.py"]
    assert changed_files(repo, "HEAD") == []


def test_unknown_ref_and_non_checkout_fail_loudly(repo, tmp_path):
    with pytest.raises(GateError, match="rev-parse"):
        changed_files(repo, "no-such-ref")
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(GateError, match="not a git checkout"):
        list_files(plain)
