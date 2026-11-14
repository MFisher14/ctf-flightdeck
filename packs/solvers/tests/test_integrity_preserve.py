"""B-196: capability preservation (ctf/integrity/preserve.py): every known solve path keeps a live,
non-hollow test, and `--run` runs them strictly. Synthetic trees with the real tools/test_audit.py copied
in; the run uses real pytest children; the lane gate is the regress gate's own interface, injected."""
from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from ctf import paths
from ctf.integrity import IntegrityError, preserve

SOLVE_TESTS = '''\
import pytest


def test_forge_none():
    assert "eyJhbGciOiJub25lIn0".startswith("eyJ")


@pytest.mark.parametrize("alg", ["none", "NONE"])
def test_variants(alg):
    assert alg.lower() == "none"


def test_hollow():
    pass


class TestB64:
    def test_unencoded(self):
        assert b"hello" == b"hello"


@pytest.mark.skip(reason="needs_tool: jwt-cracker not available")
def test_skipped():
    assert len("x") == 1
'''

REGISTRY = '''\
[[solve]]
id = "jwt-alg-none"
what = "alg none"
tests = ["tests/test_solves.py::test_forge_none", "tests/test_solves.py::test_variants[none]"]
engines = ["web.jwt"]

[[solve]]
id = "b64-false"
what = "rfc 7797"
tests = ["tests/test_solves.py::TestB64::test_unencoded"]
'''


def tree(tmp_path: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    (tmp_path / "tools").mkdir(exist_ok=True)
    shutil.copy(paths.repo_root() / "tools" / "test_audit.py", tmp_path / "tools" / "test_audit.py")
    return tmp_path


@pytest.fixture
def root(tmp_path):
    return tree(tmp_path, {"pytest.ini": "[pytest]\ntestpaths = tests\n", "tests/test_solves.py": SOLVE_TESTS,
                           "tests/known_solves.toml": REGISTRY})


def test_a_sound_registry_has_no_findings(root):
    import sys
    res = preserve.check(root, engine_ids={"web.jwt"})
    assert not [m for m in sys.modules if m.startswith("_ctf_integrity")]   # the audit tool is not left loaded
    assert [s.id for s in res.solves] == ["jwt-alg-none", "b64-false"]
    assert res.findings == [] and res.ok


def test_each_static_finding(root):
    tree(root, {"tests/known_solves.toml": REGISTRY + '''
[[solve]]
id = "broken"
what = "every way a registry entry rots"
tests = ["tests/test_solves.py::test_renamed", "tests/test_gone.py::test_x", "tests/test_solves.py::test_hollow",
         "tests/helper.py::test_y"]
engines = ["web.removed"]
'''})
    res = preserve.check(root, engine_ids={"web.jwt"})
    assert res.findings == [
        "broken: tests/test_solves.py::test_renamed: no such test in tests/test_solves.py",
        "broken: tests/test_gone.py::test_x: tests/test_gone.py is not a collected test file",
        "broken: tests/test_solves.py::test_hollow: hollow test (empty-body, tools/test_audit.py)",
        "broken: tests/helper.py::test_y: tests/helper.py is not a collected test file",
        "broken: engine web.removed has no manifest any more",
    ]
    assert not res.ok


@pytest.mark.parametrize("text,match", [
    ("", "no \\[\\[solve\\]\\] entry"),
    ('[[solve]]\nid = "Bad Id"\nwhat = "x"\ntests = ["t.py::a"]\n', "id must match"),
    ('[[solve]]\nid = "a"\nwhat = ""\ntests = ["t.py::a"]\n', "'what' must say"),
    ('[[solve]]\nid = "a"\nwhat = "x"\ntests = []\n', "at least one test"),
    ('[[solve]]\nid = "a"\nwhat = "x"\ntests = ["tests/t.py"]\n', "not a pytest node id"),
    ('[[solve]]\nid = "a"\nwhat = "x"\ntests = ["t.py::a"]\nowner = "me"\n', "unknown key"),
    ('[[solve]]\nid = "a"\nwhat = "x"\ntests = ["t.py::a"]\n[[solve]]\nid = "a"\nwhat = "y"\ntests = ["t.py::b"]\n',
     "duplicate id"),
    ('nope = 1\n', "unknown key"),
    ('solve = [1]\n', "must be a table"),
    ('[[solve]]\nid = "a"\nwhat = "x"\ntests = ["t.py::a"]\nengines = "web.x"\n', "engines must be a list"),
])
def test_a_bad_registry_is_loud(root, text, match):
    (root / "tests/known_solves.toml").write_text(text)
    with pytest.raises(IntegrityError, match=match):
        preserve.load(root)


def test_a_missing_registry_or_audit_tool_is_loud(root):
    (root / "tools/test_audit.py").unlink()
    with pytest.raises(IntegrityError, match="test_audit.py not found"):
        preserve.check(root, engine_ids={"web.jwt"})
    (root / "tests/known_solves.toml").unlink()
    with pytest.raises(IntegrityError, match="no registry"):
        preserve.load(root)


def test_run_passes_the_registry_tests_and_is_strict_about_skips(root, tmp_path):
    res = preserve.run(root, preserve.check(root, engine_ids={"web.jwt"}), out_dir=tmp_path / "o",
                       emit=lambda s: None)
    assert [(n, r.status, r.passed) for n, r in res.runs] == [
        (["tests/test_solves.py::test_forge_none", "tests/test_solves.py::test_variants[none]",
          "tests/test_solves.py::TestB64::test_unencoded"], "PASS", 3)]
    assert res.ok
    tree(root, {"tests/known_solves.toml": REGISTRY.replace("::test_forge_none", "::test_skipped")})
    res = preserve.run(root, preserve.check(root, engine_ids={"web.jwt"}), out_dir=tmp_path / "o2",
                       emit=lambda s: None)
    assert res.findings == []
    assert res.runs[0][1].status == "NOTRUN" and not res.ok             # a skipped solve is not preserved
    res = preserve.run(root, preserve.check(root, engine_ids={"web.jwt"}), out_dir=tmp_path / "o3",
                       emit=lambda s: None, allow_not_run=("needs_tool",))
    assert res.ok


def test_a_broken_solve_fails_the_run(root, tmp_path):
    tree(root, {"tests/test_solves.py": SOLVE_TESTS.replace('startswith("eyJ")', 'startswith("xx")')})
    res = preserve.run(root, preserve.check(root, engine_ids={"web.jwt"}), out_dir=tmp_path / "o",
                       emit=lambda s: None)
    assert res.runs[0][1].status == "FAIL" and not res.ok


class _Gate:
    def __init__(self, lane, verdict):
        self.lane, self.verdict, self.reason = lane, verdict, f"{lane} replayed"

    @property
    def ok(self):
        return self.verdict == "YES"


def test_lanes_must_answer_yes(root):
    calls = []

    def gate(lane, **kw):
        calls.append((lane, kw))
        return _Gate(lane, "YES" if lane == "web" else "NO")
    lines = []
    res = preserve.run_lanes(["web", "binary"], preserve.check(root, engine_ids={"web.jwt"}), gate=gate,
                             emit=lines.append, workdir=Path("/x"))
    assert calls == [("web", {"workdir": Path("/x")}), ("binary", {"workdir": Path("/x")})]
    assert lines == ["YES     lane web: web replayed", "NO      lane binary: binary replayed"]
    assert not res.ok
    assert preserve.run_lanes(["web"], preserve.check(root, engine_ids={"web.jwt"}), gate=gate,
                              emit=lines.append).ok
