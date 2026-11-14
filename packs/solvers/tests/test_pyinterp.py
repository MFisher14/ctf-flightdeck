"""B-153: the test children's interpreter resolves the same way in a main checkout and in a linked
worktree (ctf.pyinterp), and tools/suite.py and the gate's pytest children use it. Every checkout here
is a synthetic git repo; the "venv" interpreters are small shell wrappers around this interpreter that
leave a marker, so a test can see which one ran."""
from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import suite
from ctf import pyinterp
from ctf.cli import gate
from gate_repo import git, make_repo


def wrapper(path: Path, marker: Path) -> Path:
    """An executable that appends one line to `marker` and then runs this interpreter with its args."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho ran >> "{marker}"\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def no_env(monkeypatch):
    monkeypatch.delenv("CTF_PYTHON", raising=False)


@pytest.fixture
def main_and_worktree(tmp_path, no_env):
    """A main checkout with a .venv wrapper, and a linked worktree of it that has none."""
    main = make_repo(tmp_path / "main", {"tests/test_ok.py": "def test_ok():\n    pass\n"})
    marker = tmp_path / "main-venv.ran"
    wrapper(main / ".venv" / "bin" / "python", marker)
    wt = tmp_path / "wt"
    git(main, "worktree", "add", "-q", "--detach", str(wt))
    return main, wt, marker


# ------------------------------------------------------------------------- resolution order (unit)

def test_ctf_python_wins_and_must_be_executable(tmp_path, no_env):
    py = wrapper(tmp_path / "py", tmp_path / "m")
    it = pyinterp.resolve(tmp_path, environ={"CTF_PYTHON": str(py)})
    assert (it.path, it.source) == (str(py), "$CTF_PYTHON")
    bad = tmp_path / "not-exec"
    bad.write_text("x")
    with pytest.raises(pyinterp.PythonError, match="CTF_PYTHON=.*not-exec is not an executable"):
        pyinterp.resolve(tmp_path, environ={"CTF_PYTHON": str(bad)})


def test_a_bad_ctf_python_never_falls_through_to_the_venv(tmp_path, no_env):
    root = make_repo(tmp_path / "r", {})
    wrapper(root / ".venv" / "bin" / "python", tmp_path / "m")
    with pytest.raises(pyinterp.PythonError):
        pyinterp.resolve(root, environ={"CTF_PYTHON": str(tmp_path / "missing")})


def test_the_checkouts_own_venv_comes_next(tmp_path, no_env):
    root = make_repo(tmp_path / "r", {})
    py = wrapper(root / ".venv" / "bin" / "python", tmp_path / "m")
    it = pyinterp.resolve(root, environ={})
    assert it.path == str(py.resolve().parent / "python") and it.source == "the checkout's .venv"


def test_a_linked_worktree_uses_the_main_checkouts_venv(main_and_worktree):
    main, wt, _ = main_and_worktree
    assert not (wt / ".venv").exists()
    assert pyinterp.main_checkout(wt).resolve() == main.resolve()
    assert pyinterp.git_common_dir(wt) == (main / ".git").resolve()
    it = pyinterp.resolve(wt, environ={})
    assert Path(it.path).resolve() == (main / ".venv" / "bin" / "python").resolve()
    assert "main checkout" in it.source and str(main.resolve()) in it.source


def test_a_worktree_with_its_own_venv_prefers_it(main_and_worktree, tmp_path):
    main, wt, _ = main_and_worktree
    own = wrapper(wt / ".venv" / "bin" / "python", tmp_path / "own")
    assert pyinterp.resolve(wt, environ={}).path == str(own.resolve().parent / "python")


def test_nothing_found_falls_back_to_the_running_interpreter_and_says_so(tmp_path, no_env):
    root = make_repo(tmp_path / "r", {})
    it = pyinterp.resolve(root, environ={}, running="/x/python")
    assert it.path == "/x/python"
    assert it.source.startswith("the running interpreter") and "no .venv in" in it.source
    with pytest.raises(pyinterp.PythonError, match="set \\$CTF_PYTHON"):
        pyinterp.resolve(root, environ={}, running="")


def test_no_git_at_all_has_no_main_checkout(tmp_path):
    assert pyinterp.git_common_dir(tmp_path) is None and pyinterp.main_checkout(tmp_path) is None


# ------------------------------------------------------------------------------- tools/suite.py

def test_suite_runs_pytest_with_the_main_checkouts_venv_from_a_worktree(main_and_worktree, monkeypatch, capsys):
    main, wt, marker = main_and_worktree
    started = []
    monkeypatch.setattr(suite.subprocess, "call", lambda cmd, **k: started.append(cmd) or 0)
    j = wt.parent / "o.xml"
    assert suite.main(["--no-sandbox", "-n", "0", "--junit", str(j)], repo=wt) == 0
    assert Path(started[0][0]).resolve() == (main / ".venv" / "bin" / "python").resolve()
    err = capsys.readouterr().err
    assert "main checkout" in err and "suite: python" in err
    # the plugin check asked the venv interpreter itself (a child process), not this one
    assert marker.read_text().count("ran") == 1


def test_suite_reports_plugins_the_resolved_interpreter_lacks(tmp_path, no_env, monkeypatch, capsys):
    repo = make_repo(tmp_path / "r", {"tests/test_ok.py": "def test_a():\n    pass\n"})
    bare = tmp_path / "bare-py"
    bare.write_text("#!/bin/sh\nexit 3\n")                    # an interpreter that cannot import anything
    bare.chmod(0o755)
    monkeypatch.setenv("CTF_PYTHON", str(bare))
    started = []
    monkeypatch.setattr(suite.subprocess, "call", lambda cmd, **k: started.append(cmd) or 0)
    assert suite.main(["--no-sandbox", "-n", "0", "--junit", str(tmp_path / "o.xml")], repo=repo) == 2
    err = capsys.readouterr().err
    assert "lacks pytest" in err and "$CTF_PYTHON" in err and started == []


def test_suite_refuses_a_bad_python_flag_and_a_bad_ctf_python(tmp_path, no_env, monkeypatch, capsys):
    repo = make_repo(tmp_path / "r", {})
    assert suite.main(["--no-sandbox", "--python", str(tmp_path / "nope")], repo=repo) == 2
    assert "--python" in capsys.readouterr().err
    monkeypatch.setenv("CTF_PYTHON", str(tmp_path / "nope"))
    assert suite.main(["--no-sandbox"], repo=repo) == 2
    assert "CTF_PYTHON" in capsys.readouterr().err


# ------------------------------------------------------------------------------- gate children

def _gate(root: Path, state: Path, *argv) -> int:
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    return gate.run(p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
                                  *argv]))


def test_gate_children_run_with_the_main_checkouts_venv_in_a_worktree(main_and_worktree, tmp_path, capsys):
    main, wt, marker = main_and_worktree
    assert _gate(wt, tmp_path / "state", "run", "--full") == 0
    out = capsys.readouterr().out
    assert "gate: python=" in out and "main checkout" in out
    assert marker.read_text().count("ran") == 1                # one pytest child: the one test file
    assert "PASS" in out and "GATE result=pass" in out


def test_gate_python_flag_overrides_and_enters_the_warm_key(tmp_path, no_env, capsys):
    repo = make_repo(tmp_path / "r", {"tests/test_ok.py": "def test_ok():\n    pass\n"})
    m1, m2 = tmp_path / "one.ran", tmp_path / "two.ran"
    p1, p2 = wrapper(tmp_path / "py1", m1), wrapper(tmp_path / "py2", m2)
    st = tmp_path / "state"
    assert _gate(repo, st, "--python", str(p1), "run", "--changed", "tests/test_ok.py") == 0
    assert m1.read_text().count("ran") == 1
    assert _gate(repo, st, "--python", str(p1), "run", "--changed", "tests/test_ok.py") == 0
    assert m1.read_text().count("ran") == 1                    # reused warm: same interpreter, same key
    assert _gate(repo, st, "--python", str(p2), "run", "--changed", "tests/test_ok.py") == 0
    assert m2.exists() and m2.read_text().count("ran") == 1    # another interpreter: another key, it ran
    capsys.readouterr()
    assert _gate(repo, st, "--python", str(tmp_path / "missing"), "run", "--full") == 2
    assert "--python" in capsys.readouterr().err


def test_gate_with_a_bad_ctf_python_is_a_named_usage_error(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path / "r", {"tests/test_ok.py": "def test_ok():\n    pass\n"})
    monkeypatch.setenv("CTF_PYTHON", str(tmp_path / "missing"))
    assert _gate(repo, tmp_path / "state", "run", "--full") == 2
    assert "CTF_PYTHON" in capsys.readouterr().err


def test_ctfpy_and_pyinterp_agree_on_the_order():
    """tools/ctfpy is the shell twin of ctf.pyinterp: both name the same three sources in this order."""
    text = (Path(__file__).resolve().parent.parent / "tools" / "ctfpy").read_text(encoding="utf-8")
    i_env, i_own, i_main = (text.index(s) for s in ('CTF_PYTHON:-', '"$repo/.venv/bin/python"', "git-common-dir"))
    assert i_env < i_own < i_main
    assert os.path.join(".venv", "bin", "python") == str(pyinterp.VENV_PYTHON)
