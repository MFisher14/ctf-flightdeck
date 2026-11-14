"""B-196: `python -m ctf integrity` exit codes and output for the static checks, over synthetic trees."""
from __future__ import annotations

import argparse
import json
import shutil
import textwrap
from pathlib import Path

import pytest

from ctf import paths
from ctf.cli import integrity as integrity_cli


def tree(tmp_path: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return tmp_path


def cli(root, *argv):
    p = argparse.ArgumentParser()
    integrity_cli.add_arguments(p)
    return integrity_cli.run(p.parse_args(["--root", str(root), *argv]))


GATE = 'version = 1\ntests = ["tests/test_*.py"]\nroots = [""]\nglobal = []\ninert = []\n' \
       '[wall]\nbase_seconds = 60\nmax_scale = 2.0\n'


@pytest.fixture
def root(tmp_path):
    r = tree(tmp_path, {
        "pytest.ini": "[pytest]\ntestpaths = tests\n",
        "tests/gate.toml": GATE,
        "pkg/__init__.py": "",
        "pkg/mod.py": 'import os\n\ndef f():\n    if os.environ.get("CTF_TESTING"):\n        return 1\n    return 2\n',
        "tests/test_mod.py": "from pkg import mod\n\ndef test_f(monkeypatch):\n"
                             "    monkeypatch.delenv('CTF_TESTING', raising=False)\n    assert mod.f() == 2\n",
        "tests/known_solves.toml": '[[solve]]\nid = "f"\nwhat = "f answers"\ntests = ["tests/test_mod.py::test_f"]\n',
        "docs/a.md": "See `pkg/mod.py`.\n",
        # tools/test_audit.py (copied below) has a test-shaped name outside tests/: a test must reach it,
        # or `collected` reports it `stray`
        "tests/test_tool_present.py": "from pathlib import Path\n\ndef test_present():\n"
                                      "    assert Path(__file__).parents[1].joinpath('tools/test_audit.py').is_file()\n",
    })
    (r / "tools").mkdir()
    shutil.copy(paths.repo_root() / "tools" / "test_audit.py", r / "tools" / "test_audit.py")
    return r


def test_fakes_exit_and_json(root, capsys):
    assert cli(root, "fakes", "--source", "pkg") == 0
    out = capsys.readouterr().out
    assert "COVERED  pkg/mod.py:4 f reads CTF_TESTING" in out and "FAKES branches=1 covered=1" in out
    tree(root, {"tests/test_mod.py": "from pkg import mod\n\ndef test_f():\n    assert mod.f() == 1\n"})
    assert cli(root, "fakes", "--source", "pkg", "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["branches"][0]["status"] == "MISSING" and data["findings"][0].startswith("MISSING pkg/mod.py:4")
    assert cli(root, "fakes") == 0                       # the default folders (ctf, solvers, tools) hold none here


def test_collected_and_doclint_exit_codes(root, capsys):
    assert cli(root, "collected") == 0
    assert "COLLECTED new=0 known=0 stale=0" in capsys.readouterr().out
    tree(root, {"tests/checks_lane_a.py": "def test_x():\n    assert 1 == 1\n"})
    assert cli(root, "collected", "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["new"][0]["rule"] == "misnamed" and data["ok"] is False
    assert cli(root, "doclint") == 0
    capsys.readouterr()
    tree(root, {"docs/a.md": "See `pkg/gone.py` and python -m ctf nonsense.\n"})
    assert cli(root, "doclint") == 1
    out = capsys.readouterr().out
    assert "docs/a.md:1: path: 'pkg/gone.py'" in out and "DOCLINT new=2" in out


def test_preserve_exit_codes(root, capsys, tmp_path):
    assert cli(root, "preserve") == 0
    assert "PRESERVE solves=1 tests=1 findings=0 runs=0" in capsys.readouterr().out
    assert cli(root, "preserve", "--run", "--out", str(tmp_path / "o")) == 0
    out = capsys.readouterr().out
    assert "PASS" in out and "result=pass" in out
    tree(root, {"tests/test_mod.py": "from pkg import mod\n\ndef test_f():\n    assert mod.f() == 3\n"})
    assert cli(root, "preserve", "--run", "--out", str(tmp_path / "o2")) == 1
    assert "result=fail" in capsys.readouterr().out
    assert cli(root, "preserve", "--allow-not-run", "bogus") == 2
    assert "unknown not-run kind" in capsys.readouterr().err
    (root / "tests/known_solves.toml").unlink()
    assert cli(root, "preserve") == 2


def test_collected_reports_a_stray_test_file_outside_tests(root, capsys):
    (root / "tests/test_tool_present.py").unlink()
    assert cli(root, "collected") == 1
    out = capsys.readouterr().out
    assert "stray     tools/test_audit.py:" in out and "COLLECTED new=1 known=0 stale=0" in out


def test_all_runs_every_static_check(root, capsys):
    assert cli(root, "all", "--source", "pkg") == 0
    out = capsys.readouterr().out
    for name in ("fakes", "collected", "doclint", "preserve"):
        assert f"== integrity {name}" in out
    assert out.strip().endswith("INTEGRITY result=pass")
    tree(root, {"docs/a.md": "See `pkg/gone.py`.\n"})
    assert cli(root, "all", "--source", "pkg") == 1
    assert capsys.readouterr().out.strip().endswith("INTEGRITY result=fail")
