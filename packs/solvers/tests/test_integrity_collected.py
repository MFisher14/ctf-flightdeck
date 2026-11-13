"""B-196: the collection check (ctf/integrity/collected.py): a tests/ file that defines tests must be one
pytest collects and the gate selects. Synthetic trees; nothing is collected or run."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ctf.integrity import IntegrityError, collected

GATE = ("tests/test_*.py",)


def tree(tmp_path: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return tmp_path


BASE = {
    "pytest.ini": "[pytest]\ntestpaths = tests\npython_files = test_*.py\n",
    "tests/test_ok.py": "def test_a():\n    assert 1\n",
    "tests/test_cls.py": "class TestX:\n    def test_a(self):\n        assert 1\n",
    "tests/lane_a_checks.py": "def test_hidden():\n    assert 1\n",                 # misnamed
    "tests/helpers.py": "def test_like_helper():\n    return 1\n",                 # imported by a test: fine
    "tests/test_uses_helper.py": "from helpers import test_like_helper\n\ndef test_b():\n    assert test_like_helper()\n",
    "tests/test_script.py": "def main():\n    return 0\n\nif __name__ == '__main__':\n    main()\n",
    "tests/sub/test_deep.py": "def test_c():\n    assert 1\n",
    "tests/real/conftest.py": "def pytest_pycollect_makemodule(module_path, parent):\n    return None\n",
    "tests/real/fetch_x.py": "def test_not_pytest():\n    pass\n",
}


def _rules(found):
    return sorted((f.rule, f.path) for f in found)


def test_each_rule(tmp_path):
    root = tree(tmp_path, {**BASE, "tests/conftest.py": 'collect_ignore = ["test_ignored.py"]\n',
                           "tests/test_ignored.py": "def test_x():\n    assert 1\n"})
    got = _rules(collected.check(root, gate_tests=("tests/test_*.py",)))
    assert got == [("ignored", "tests/test_ignored.py"),
                   ("misnamed", "tests/lane_a_checks.py"),
                   ("no-tests", "tests/test_script.py"),
                   ("not-gated", "tests/sub/test_deep.py")]


def test_the_ini_patterns_decide_what_is_misnamed(tmp_path):
    root = tree(tmp_path, {**BASE, "pytest.ini": "[pytest]\npython_files = test_*.py *_checks.py\n"})
    got = _rules(collected.check(root, gate_tests=("tests/**/test_*.py", "tests/*_checks.py")))
    assert ("misnamed", "tests/lane_a_checks.py") not in got and ("no-tests", "tests/test_script.py") in got
    assert collected.python_files(root) == ("test_*.py", "*_checks.py")
    (root / "pytest.ini").unlink()
    assert collected.python_files(root) == ("test_*.py", "*_test.py")       # pytest's own default


def test_the_known_list_splits_new_known_and_stale(tmp_path):
    root = tree(tmp_path, {**BASE, "tests/collection_known.toml": '''\
        [[known]]
        rule = "no-tests"
        path = "tests/test_script.py"
        reason = "script-style"

        [[known]]
        rule = "misnamed"
        path = "tests/gone.py"
        reason = "was renamed"
        '''})
    res = collected.audit(root, gate_tests=("tests/**/test_*.py",))
    assert _rules(res.new) == [("misnamed", "tests/lane_a_checks.py")]
    assert _rules(res.known) == [("no-tests", "tests/test_script.py")]
    assert res.stale == ["misnamed tests/gone.py"] and not res.ok
    (root / "tests/lane_a_checks.py").unlink()
    text = (root / "tests/collection_known.toml").read_text().split("\n\n[[known]]\nrule = \"misnamed\"")[0]
    (root / "tests/collection_known.toml").write_text(text + "\n")
    assert collected.audit(root, gate_tests=("tests/**/test_*.py",)).ok


@pytest.mark.parametrize("text,match", [
    ('[[known]]\nrule = "no-tests"\npath = "x"\n', "exactly rule, path, reason"),
    ('[[known]]\nrule = "odd"\npath = "x"\nreason = "y"\n', "unknown rule"),
    ('[[known]]\nrule = "no-tests"\npath = "x"\nreason = " "\n', "reason must say why"),
    ('other = 1\n', "unknown key"),
])
def test_a_bad_known_list_is_loud(tmp_path, text, match):
    root = tree(tmp_path, {**BASE, "tests/collection_known.toml": text})
    with pytest.raises(IntegrityError, match=match):
        collected.load_known(root)


def test_no_tests_folder_is_loud(tmp_path):
    with pytest.raises(IntegrityError, match="no tests/ folder"):
        collected.check(tmp_path, gate_tests=GATE)


def test_finding_text_and_the_finer_paths(tmp_path):
    root = tree(tmp_path, {**BASE,
                           "tests/conftest.py": 'collect_ignore = ["sub/test_deep.py"]\n',
                           "tests/real/sub/fetch_y.py": "def test_hidden_too():\n    pass\n",
                           "tests/lane_helpers.py": "def test_shaped():\n    return 1\n",
                           "tests/test_rel.py": "from . import lane_helpers\n\ndef test_r():\n    assert lane_helpers\n"})
    found = collected.check(root, gate_tests=("tests/test_*.py",))
    assert _rules(found) == [("ignored", "tests/sub/test_deep.py"),      # ignored by its path below the conftest
                             ("misnamed", "tests/lane_a_checks.py"),     # not tests/real/sub (custom collection)
                             ("no-tests", "tests/test_script.py")]       # lane_helpers is imported: a helper
    f = next(x for x in found if x.rule == "ignored")
    assert f.text() == ("ignored   tests/sub/test_deep.py: named in a conftest.py collect_ignore list: "
                        "pytest never runs it")


def test_without_a_known_list_every_finding_is_new(tmp_path):
    root = tree(tmp_path, BASE)
    res = collected.audit(root, gate_tests=("tests/**/test_*.py",))
    assert _rules(res.new) == [("misnamed", "tests/lane_a_checks.py"), ("no-tests", "tests/test_script.py")]
    assert res.known == [] and res.stale == [] and not res.ok                # new findings alone fail


def test_a_broken_pytest_ini_is_loud(tmp_path):
    root = tree(tmp_path, {**BASE, "pytest.ini": "[pytest\npython_files = x\n"})
    with pytest.raises(IntegrityError, match="pytest.ini"):
        collected.python_files(root)


def test_collect_ignore_is_relative_to_its_conftest_and_globs_match(tmp_path):
    # pytest resolves collect_ignore against the conftest's own folder: a bare name in tests/conftest.py
    # ignores tests/<name> only. tests/sub/test_deep.py shares the base name and is still collected.
    root = tree(tmp_path, {**BASE,
                           "tests/conftest.py": 'collect_ignore = ["test_deep.py"]\n'
                                                'collect_ignore_glob = ["sub/test_g*.py"]\n',
                           "tests/test_deep.py": "def test_top():\n    assert 1\n",
                           "tests/sub/test_glob1.py": "def test_g():\n    assert 1\n"})
    got = _rules(collected.check(root, gate_tests=("tests/**/test_*.py",)))
    assert ("ignored", "tests/test_deep.py") in got and ("ignored", "tests/sub/test_glob1.py") in got
    assert ("ignored", "tests/sub/test_deep.py") not in got
    from ctf.integrity.testfiles import collected_test_files
    files = collected_test_files(root)
    assert "tests/sub/test_deep.py" in files
    assert "tests/test_deep.py" not in files and "tests/sub/test_glob1.py" not in files


STRAY = {
    "solvers/lane/test_lonely.py": "def test_x():\n    assert 1\n",                      # nothing reaches it: stray
    "solvers/lane/selftest.py": "print('ok')\n",                                        # run through a code string
    "solvers/lane/helper.py": "def test_shaped():\n    return 1\n",                     # not test-shaped by name
    "tools/test_named.py": "print('ok')\n",                                             # named by its path
    "solvers/other/selftest_z.py": "print('ok')\n",          # its stem is imported, but its folder is never named
    "solvers/other/test_file_only.py": "print('ok')\n",      # its file name is quoted, its folder is not
    "solvers/deep/tests/test_nested.py": "print('ok')\n",    # a tests/ folder below the root is walked
    "docs/test_doc.py": "print('ok')\n",                     # pruned folders
    "corpus/test_c.py": "print('ok')\n",
    ".hidden/test_h.py": "print('ok')\n",
    "tests/test_runs_them.py": (
        "import subprocess, sys\nLANE = ROOT / 'solvers' / 'lane'\n"
        "CODE = '''\nimport sys\nimport os, selftest\n'''\n"
        "OTHER = 'test_file_only.py'\n"
        "def test_run():\n    assert subprocess.run([sys.executable, 'tools/test_named.py']).returncode == 0\n"
        "def test_imp():\n    import selftest_z\n"),
}


def test_stray_test_files_outside_tests(tmp_path):
    root = tree(tmp_path, {**BASE, **STRAY})
    found = collected.check(root, gate_tests=("tests/**/test_*.py",))
    got = [p for r, p in _rules(found) if r == "stray"]
    assert got == ["solvers/deep/tests/test_nested.py", "solvers/lane/test_lonely.py",
                   "solvers/other/selftest_z.py", "solvers/other/test_file_only.py"]
    f = next(x for x in found if x.rule == "stray")
    assert f.text().startswith("stray     solvers/deep/tests/test_nested.py: a test or self-test file outside tests/")


@pytest.mark.parametrize("text,hit", [
    ("X = 'solvers/lane/test_t.py'", True),                         # the repo-relative path
    ("CMD = 'python solvers/lane/test_t.py --fast'", True),         # the path inside a longer command string
    ("P = R / 'lane' / 'test_t.py'", True),                         # folder segment and file name
    ("P = R / 'lane'\nimport test_t\n", True),                      # folder and an import line
    ("P = R / 'lane'\nfrom test_t import f\n", True),
    ("P = R / 'lane'\n    import a.b, test_t\n", True),            # an import list, indented (a code string)
    ("P = R / 'lane'\nimport test_tx\n", False),                    # a longer module name is not the stem
    ("P = R / 'lane'\nx = test_t\n", False),                        # a bare word is not an import
    ("import test_t\nP = 'lanes/x'", False),                       # 'lanes' is not the folder segment
    ("P = R / 'lane'\nQ = 'test_t.pyc'", False),                    # a longer file name is not the file
    ("Q = 'test_t.py'", False),                                     # the file name without its folder
], ids=[str(i) for i in range(11)])
def test_reached_reads_paths_names_and_imports(text, hit):
    assert collected.reached("solvers/lane/test_t.py", [text]) is hit


def test_a_root_level_stray_is_reached_by_its_name_or_an_import(tmp_path):
    root = tree(tmp_path, {**BASE, "test_top.py": "print(1)\n"})
    assert [p for r, p in _rules(collected.check(root, gate_tests=GATE)) if r == "stray"] == ["test_top.py"]
    (root / "tests/test_calls_top.py").write_text("def test_t():\n    assert 'test_top.py'\n")
    assert not [f for f in collected.check(root, gate_tests=GATE) if f.rule == "stray"]
    # the root is on sys.path under pytest, so an import line alone reaches a root-level file
    assert collected.reached("test_top.py", ["import test_top\n"])
    assert not collected.reached("test_top.py", ["import test_topx\n"])
    assert not collected.reached("solvers/lane/test_top.py", ["import test_top\n"])   # a nested one needs its folder
