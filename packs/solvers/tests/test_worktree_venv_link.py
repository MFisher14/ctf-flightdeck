"""R-17: linking the shared master venv into a git worktree (ctf.worktreevenv, ctf worktree-venv).

Fixtures are synthetic: a fake venv is a directory with an executable bin/python, and the git cases
build throwaway repos + worktrees in tmp. No real venv or checkout is touched.
"""
from __future__ import annotations

import argparse
import os
import stat
import subprocess
from pathlib import Path

import pytest

from ctf import paths
from ctf import worktreevenv as wv
from ctf.cli import worktree_venv


def _fake_venv(root: Path, name: str = "venv") -> Path:
    v = root / name
    (v / "bin").mkdir(parents=True)
    py = v / "bin" / "python"
    py.write_text("#!/bin/sh\necho fake\n")
    py.chmod(py.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return v


_GIT_ENV = dict(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t",
                GIT_COMMITTER_EMAIL="t@e", GIT_CONFIG_NOSYSTEM="1")


def _git(*args, cwd, check=True):
    env = dict(os.environ, **_GIT_ENV)
    return subprocess.run(["git", *args], cwd=str(cwd), env=env, check=check, capture_output=True,
                          text=True)


def _master_with_worktree(tmp_path: Path, ignore: str | None = None) -> tuple[Path, Path]:
    """A throwaway master repo (with ``ignore`` as its committed ignore file) and a linked worktree."""
    master = tmp_path / "master"
    master.mkdir()
    _git("init", "-q", cwd=master)
    if ignore is not None:
        (master / ".gitignore").write_text(ignore)
        _git("add", ".gitignore", cwd=master)
    _git("commit", "-q", "--allow-empty", "-m", "base", cwd=master)
    wt = tmp_path / "wt"
    _git("worktree", "add", "-q", str(wt), cwd=master)
    return master, wt


def test_link_creates_symlink_and_interpreter_resolves(tmp_path):
    venv = _fake_venv(tmp_path)
    wt = tmp_path / "wt"
    wt.mkdir()
    action, target = wv.link(wt, venv)
    assert action == "linked"
    assert target == venv.resolve()
    dest = wt / ".venv"
    assert dest.is_symlink()
    assert (dest / "bin" / "python").resolve() == (venv / "bin" / "python").resolve()


def test_link_is_idempotent(tmp_path):
    venv = _fake_venv(tmp_path)
    wt = tmp_path / "wt"
    wt.mkdir()
    assert wv.link(wt, venv)[0] == "linked"
    assert wv.link(wt, venv)[0] == "exists"


def test_wrong_link_refused_then_replaced_with_force(tmp_path):
    venv = _fake_venv(tmp_path, "venv")
    other = _fake_venv(tmp_path, "other")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".venv").symlink_to(other, target_is_directory=True)
    with pytest.raises(wv.WorktreeVenvError):
        wv.link(wt, venv)
    action, target = wv.link(wt, venv, force=True)
    assert action == "relinked"
    assert (wt / ".venv").resolve() == venv.resolve()


def test_real_venv_directory_is_never_clobbered(tmp_path):
    venv = _fake_venv(tmp_path)
    wt = tmp_path / "wt"
    (wt / ".venv" / "bin").mkdir(parents=True)   # a real venv already in the worktree
    with pytest.raises(wv.WorktreeVenvError):
        wv.link(wt, venv)
    with pytest.raises(wv.WorktreeVenvError):     # even with force: we do not delete a real venv
        wv.link(wt, venv, force=True)
    assert not (wt / ".venv").is_symlink()


def test_resolve_venv_loud_when_target_has_no_interpreter(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    wt = tmp_path / "wt"
    wt.mkdir()
    with pytest.raises(wv.WorktreeVenvError) as ei:
        wv.resolve_venv(wt, empty)
    assert "bin/python" in str(ei.value)


def test_non_executable_interpreter_is_rejected(tmp_path):
    venv = _fake_venv(tmp_path)
    (venv / "bin" / "python").chmod(0o644)
    wt = tmp_path / "wt"
    wt.mkdir()
    with pytest.raises(wv.WorktreeVenvError) as ei:
        wv.resolve_venv(wt, venv)
    assert "not executable" in str(ei.value)


def test_resolve_venv_uses_ctf_venv_env(tmp_path, monkeypatch):
    venv = _fake_venv(tmp_path)
    wt = tmp_path / "wt"
    wt.mkdir()
    monkeypatch.setenv("CTF_VENV", str(venv))
    assert wv.resolve_venv(wt) == venv.resolve()


def test_explicit_venv_wins_over_ctf_venv(tmp_path, monkeypatch):
    mine = _fake_venv(tmp_path, "mine")
    from_env = _fake_venv(tmp_path, "from_env")
    wt = tmp_path / "wt"
    wt.mkdir()
    monkeypatch.setenv("CTF_VENV", str(from_env))
    assert wv.resolve_venv(wt, mine) == mine.resolve()


def test_bad_explicit_venv_is_an_error_even_with_a_good_ctf_venv(tmp_path, monkeypatch):
    """No fallthrough: a mistyped --venv must not silently link $CTF_VENV (or the master venv)."""
    good = _fake_venv(tmp_path, "good")
    wt = tmp_path / "wt"
    wt.mkdir()
    monkeypatch.setenv("CTF_VENV", str(good))
    with pytest.raises(wv.WorktreeVenvError) as ei:
        wv.link(wt, tmp_path / "typo")
    assert "--venv" in str(ei.value)
    assert not (wt / ".venv").is_symlink()


def test_resolve_venv_raises_outside_git_with_no_hint(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_VENV", raising=False)
    wt = tmp_path / "wt"
    wt.mkdir()
    # tmp_path is not a git checkout, no --venv, no $CTF_VENV -> loud failure, no guessing.
    with pytest.raises(wv.WorktreeVenvError):
        wv.resolve_venv(wt)


@pytest.mark.needs_tool("git")
def test_git_worktree_links_the_master_venv_by_discovery(tmp_path, monkeypatch):
    """With no --venv and no $CTF_VENV, link() finds the master checkout's .venv through git."""
    monkeypatch.delenv("CTF_VENV", raising=False)
    master, wt = _master_with_worktree(tmp_path)
    _fake_venv(master, ".venv")                 # the master checkout's venv

    assert not (wt / ".venv").exists()
    assert wv.master_checkout(wt).resolve() == master.resolve()
    action, target = wv.link(wt)                # discovery path: no explicit venv
    assert action == "linked"
    assert target == (master / ".venv").resolve()
    assert (wt / ".venv" / "bin" / "python").exists()


@pytest.mark.needs_tool("git")
def test_bad_ctf_venv_is_an_error_even_with_a_good_master_venv(tmp_path, monkeypatch):
    master, wt = _master_with_worktree(tmp_path)
    _fake_venv(master, ".venv")
    monkeypatch.setenv("CTF_VENV", str(tmp_path / "typo"))
    with pytest.raises(wv.WorktreeVenvError) as ei:
        wv.resolve_venv(wt)
    assert "$CTF_VENV" in str(ei.value)


@pytest.mark.needs_tool("git")
def test_bare_repo_worktree_master_is_the_bare_dir(tmp_path, monkeypatch):
    """For a worktree of a bare repository the shared git dir is not named .git: the master is the bare
    repository directory itself (not its parent), and its .venv is the one discovered."""
    monkeypatch.delenv("CTF_VENV", raising=False)
    src = tmp_path / "src"
    src.mkdir()
    _git("init", "-q", cwd=src)
    _git("commit", "-q", "--allow-empty", "-m", "base", cwd=src)
    bare = tmp_path / "bare.git"
    _git("clone", "-q", "--bare", str(src), str(bare), cwd=tmp_path)
    wt = tmp_path / "bwt"
    _git("worktree", "add", "-q", "-b", "wtb", str(wt), cwd=bare)
    assert wv.master_checkout(wt).resolve() == bare.resolve()
    _fake_venv(bare, ".venv")
    assert wv.resolve_venv(wt) == (bare / ".venv").resolve()


@pytest.mark.needs_tool("git")
def test_link_is_ignored_by_git_where_no_pattern_covers_it(tmp_path):
    """A repo whose ignore file has only the directory form `.venv/` does not ignore a .venv SYMLINK
    (git sees a file); link() adds .venv to info/exclude first, so git status stays clean and the link
    cannot be committed by an `add -A`."""
    _master, wt = _master_with_worktree(tmp_path, ignore=".venv/\n")
    venv = _fake_venv(tmp_path, "venv")
    (wt / ".venv").symlink_to(venv, target_is_directory=True)     # the precondition this guards:
    assert _git("check-ignore", "-q", ".venv", cwd=wt, check=False).returncode == 1   # not ignored
    (wt / ".venv").unlink()
    wv.link(wt, venv)
    assert (wt / ".venv").is_symlink()
    assert _git("check-ignore", "-q", ".venv", cwd=wt, check=False).returncode == 0
    assert _git("status", "--porcelain", cwd=wt).stdout.strip() == ""
    assert wv.ensure_ignored(wt) == "ignored"   # a second call finds it covered, appends nothing


@pytest.mark.needs_tool("git")
def test_force_relink_keeps_the_link_ignored_by_git(tmp_path):
    """--force replacing a link aimed elsewhere must also make git ignore .venv: in a repo whose only
    pattern is `.venv/`, the relinked symlink would otherwise show as untracked."""
    _master, wt = _master_with_worktree(tmp_path, ignore=".venv/\n")
    venv = _fake_venv(tmp_path, "venv")
    other = _fake_venv(tmp_path, "other")
    (wt / ".venv").symlink_to(other, target_is_directory=True)   # an old link, git not yet told
    assert _git("check-ignore", "-q", ".venv", cwd=wt, check=False).returncode == 1
    action, _target = wv.link(wt, venv, force=True)
    assert action == "relinked"
    assert (wt / ".venv").resolve() == venv.resolve()
    assert _git("status", "--porcelain", cwd=wt).stdout.strip() == ""


@pytest.mark.needs_tool("git")
def test_existing_same_link_is_made_ignored_by_git(tmp_path):
    """A link already aimed at the right venv (made by hand, before git was told) comes back "exists"
    and is made ignored too, so git status is clean afterwards."""
    _master, wt = _master_with_worktree(tmp_path, ignore=".venv/\n")
    venv = _fake_venv(tmp_path, "venv")
    (wt / ".venv").symlink_to(venv, target_is_directory=True)
    assert _git("status", "--porcelain", cwd=wt).stdout.strip() != ""   # precondition: shows ?? .venv
    action, _target = wv.link(wt, venv)
    assert action == "exists"
    assert _git("status", "--porcelain", cwd=wt).stdout.strip() == ""


@pytest.mark.needs_tool("git")
def test_cli_default_links_the_checkout_root_from_a_subdirectory(tmp_path, monkeypatch, capsys):
    """Run from <wt>/sub with no --worktree: the link goes at the worktree's top level, where
    `.venv/bin/python` is spelled from, not at <wt>/sub/.venv."""
    monkeypatch.delenv("CTF_VENV", raising=False)
    master, wt = _master_with_worktree(tmp_path)
    _fake_venv(master, ".venv")
    sub = wt / "sub"
    sub.mkdir()
    monkeypatch.chdir(sub)
    rc = worktree_venv.run(argparse.Namespace(worktree=None, venv=None, force=False))
    assert rc == 0, capsys.readouterr().err
    assert not (sub / ".venv").exists()
    assert (wt / ".venv").is_symlink()
    assert (wt / ".venv").resolve() == (master / ".venv").resolve()


@pytest.mark.needs_tool("git")
def test_cli_in_the_master_checkout_reports_the_master_venv(tmp_path, monkeypatch, capsys):
    """In the master checkout itself the .venv IS the master venv: exit 0 with a plain message, the real
    directory untouched (not the old 'real directory ... want a link to <itself>' refusal)."""
    monkeypatch.delenv("CTF_VENV", raising=False)
    master, _wt = _master_with_worktree(tmp_path)
    venv = _fake_venv(master, ".venv")
    monkeypatch.chdir(master)
    rc = worktree_venv.run(argparse.Namespace(worktree=None, venv=None, force=False))
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert "master venv itself" in cap.out
    assert venv.is_dir() and not venv.is_symlink()
    assert (venv / "bin" / "python").exists()
    assert wv.link(master)[0] == "is-master"


@pytest.mark.needs_tool("git")
def test_repo_root_ignore_file_covers_a_venv_symlink(tmp_path):
    """This repo's own root ignore file must match `.venv` as a symlink (a file to git), not only as a
    directory: copy it into a throwaway repo, link, and git must already ignore it (no exclude needed)."""
    ignore = (paths.repo_root() / ".gitignore").read_text(encoding="utf-8")
    _master, wt = _master_with_worktree(tmp_path, ignore=ignore)
    venv = _fake_venv(tmp_path, "venv")
    (wt / ".venv").symlink_to(venv, target_is_directory=True)
    assert wv.ensure_ignored(wt) == "ignored"
    assert _git("status", "--porcelain", cwd=wt).stdout.strip() == ""


def test_cli_links_and_reports(tmp_path, capsys):
    venv = _fake_venv(tmp_path)
    wt = tmp_path / "wt"
    wt.mkdir()
    rc = worktree_venv.run(argparse.Namespace(worktree=wt, venv=venv, force=False))
    assert rc == 0
    out = capsys.readouterr().out
    assert str(venv.resolve()) in out
    assert (wt / ".venv").is_symlink()


def test_cli_reports_failure_loudly(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CTF_VENV", raising=False)
    wt = tmp_path / "wt"
    wt.mkdir()
    rc = worktree_venv.run(argparse.Namespace(worktree=wt, venv=tmp_path / "nope", force=False))
    assert rc == 2
    assert "worktree-venv" in capsys.readouterr().err
    assert not (wt / ".venv").is_symlink()


def test_cli_rejects_a_mistyped_venv_with_ctf_venv_set(tmp_path, monkeypatch, capsys):
    good = _fake_venv(tmp_path, "good")
    wt = tmp_path / "wt"
    wt.mkdir()
    monkeypatch.setenv("CTF_VENV", str(good))
    rc = worktree_venv.run(argparse.Namespace(worktree=wt, venv=tmp_path / "typo", force=False))
    assert rc == 2
    assert "typo" in capsys.readouterr().err
    assert not (wt / ".venv").is_symlink()
