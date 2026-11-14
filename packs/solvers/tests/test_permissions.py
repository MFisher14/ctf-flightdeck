"""B-191: player-declared permission rules + sanctioned helpers (abandon, worktree-commit).

Covers ctf/permissions.py (the declaration loader/validator) and the three CLI commands
ctf/cli/permissions.py, ctf/cli/abandon.py, ctf/cli/worktree_commit.py. The git-executing paths
are marked needs_tool("git") so they report as not run when git is absent, never silently green.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import types
from pathlib import Path

import pytest

from ctf import paths, permissions
from ctf.cli import abandon as cli_abandon
from ctf.cli import permissions as cli_perms
from ctf.cli import worktree_commit as cli_wc


# ------------------------------------------------------------------ permissions.parse / load

def _decl(**over):
    base = {"slug": "x", "allow": [{"id": "worktree-commit", "action": "commit a worktree",
                                    "reason": "agents commit their own item",
                                    "helper": "worktree-commit"}]}
    base.update(over)
    return base


def test_parse_valid_exposes_rules_and_helper():
    d = permissions.parse(_decl(), src="t", expect_slug="x")
    assert d.slug == "x"
    assert [r.id for r in d.allow] == ["worktree-commit"]
    r = d.by_id("worktree-commit")
    assert r is not None and r.action == "commit a worktree" and r.helper == "worktree-commit"
    assert d.by_id("nope") is None


def test_parse_missing_required_key_names_it():
    bad = _decl(allow=[{"id": "a", "action": "do"}])  # no reason
    with pytest.raises(permissions.PermissionError, match=r"allow\[0\]\.reason"):
        permissions.parse(bad, src="t")


@pytest.mark.parametrize("field,value", [
    ("action", "   "),    # whitespace-only action
    ("reason", "   "),     # whitespace-only reason
])
def test_parse_whitespace_only_field_rejected(field, value):
    """A field present but blank (only spaces) is not a valid string: it must be non-empty."""
    entry = {"id": "a", "action": "do", "reason": "yyyyyyyy"}
    entry[field] = value
    with pytest.raises(permissions.PermissionError,
                       match=rf"allow\[0\]\.{field} must be a non-empty string"):
        permissions.parse(_decl(allow=[entry]), src="t")


def test_parse_duplicate_id_rejected():
    bad = _decl(allow=[{"id": "a", "action": "x", "reason": "yyyyyyyy"},
                       {"id": "a", "action": "x", "reason": "yyyyyyyy"}])
    with pytest.raises(permissions.PermissionError, match="duplicate allow id 'a'"):
        permissions.parse(bad, src="t")


def test_parse_bad_id_pattern_rejected():
    with pytest.raises(permissions.PermissionError, match="must match"):
        permissions.parse(_decl(allow=[{"id": "Bad Id", "action": "x", "reason": "yyyyyyyy"}]), src="t")


def test_parse_unknown_top_level_key_rejected():
    with pytest.raises(permissions.PermissionError, match="unknown key"):
        permissions.parse(_decl(bogus=1), src="t")


def test_parse_unknown_entry_key_rejected():
    bad = _decl(allow=[{"id": "a", "action": "x", "reason": "yyyyyyyy", "extra": 1}])
    with pytest.raises(permissions.PermissionError, match=r"allow\[0\] has unknown key"):
        permissions.parse(bad, src="t")


def test_parse_unknown_helper_rejected_but_known_accepted():
    bad = _decl(allow=[{"id": "a", "action": "x", "reason": "yyyyyyyy", "helper": "nosuch"}])
    with pytest.raises(permissions.PermissionError, match="not a sanctioned helper"):
        permissions.parse(bad, src="t")
    ok = _decl(allow=[{"id": "a", "action": "x", "reason": "yyyyyyyy", "helper": "abandon"}])
    assert permissions.parse(ok, src="t").allow[0].helper == "abandon"


def test_parse_slug_mismatch_rejected():
    with pytest.raises(permissions.PermissionError, match="but the file lives in"):
        permissions.parse(_decl(slug="other"), src="t", expect_slug="x")


def test_load_optional_absent_returns_none(tmp_path):
    (tmp_path / "e1").mkdir()
    assert permissions.load_optional("e1", root=tmp_path) is None
    with pytest.raises(permissions.PermissionError, match="missing"):
        permissions.load("e1", root=tmp_path)


def test_load_path_roundtrip(tmp_path):
    f = tmp_path / "permissions.toml"
    f.write_text('slug = "e"\n[[allow]]\nid="a"\naction="do a"\nreason="because reasons"\n')
    d = permissions.load_path(f, expect_slug="e")
    assert d.allow[0].id == "a" and d.path == f


def test_shipped_template_is_valid_and_marked_example():
    """The committed template stays valid, references real helpers, and is marked as an example."""
    assert permissions.EXAMPLE_PATH == paths.repo_root() / "docs" / "examples" / "permissions.example.toml"
    d = permissions.load_path(permissions.EXAMPLE_PATH)
    assert d.example is True
    ids = {r.id for r in d.allow}
    assert {"worktree-commit", "abandon-attempt"} <= ids
    for r in d.allow:
        if r.helper is not None:
            assert r.helper in permissions.SANCTIONED_HELPERS


def test_parse_example_flag():
    assert permissions.parse(_decl(), src="t").example is False
    assert permissions.parse(_decl(example=True), src="t").example is True
    with pytest.raises(permissions.PermissionError, match="example must be true or false"):
        permissions.parse(_decl(example="yes"), src="t")


def test_sanctioned_helpers_are_real_commands():
    """Every registered helper must be an importable ctf/cli/<name>.py exposing the command API."""
    import importlib
    from ctf import cli
    discovered = {name for name, mod, err in cli.discover() if mod is not None}
    for name in permissions.SANCTIONED_HELPERS:
        assert name in discovered, f"sanctioned helper {name!r} has no working ctf/cli module"


# ------------------------------------------------------------------ ctf permissions CLI

_GOOD = ('slug = "{slug}"\n[[allow]]\nid = "worktree-commit"\naction = "commit a worktree"\n'
         'reason = "agents commit their own item"\nhelper = "worktree-commit"\n')


@pytest.fixture
def events_root(tmp_path, monkeypatch):
    """A tmp events root: ctf.paths.event_dir resolves under it, so no real event file is read."""
    root = tmp_path / "events"
    root.mkdir()
    monkeypatch.setattr(paths, "events_root", lambda: root)
    return root


def _write_event(root: Path, slug: str, text: str) -> Path:
    (root / slug).mkdir(exist_ok=True)
    f = root / slug / permissions.PROFILE_NAME
    f.write_text(text)
    return f


def _perm_args(slug, check=False):
    return types.SimpleNamespace(helpers_only=False, event=slug, check=check)

def test_cli_permissions_helpers_only(capsys):
    rc = cli_perms.run(types.SimpleNamespace(helpers_only=True, event=None, check=False))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ctf worktree-commit" in out and "ctf abandon" in out


def test_cli_permissions_lists_declared_rules(events_root, capsys):
    _write_event(events_root, "e1", _GOOD.format(slug="e1"))
    rc = cli_perms.run(_perm_args("e1"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "player-declared permission rules for 'e1'" in out
    assert "worktree-commit" in out and "helper: ctf worktree-commit" in out


def test_cli_permissions_none_declared(events_root, capsys):
    (events_root / "e2").mkdir()
    rc = cli_perms.run(_perm_args("e2"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "no permission rules declared" in out


def test_cli_permissions_check_ok(events_root, capsys):
    _write_event(events_root, "e1", _GOOD.format(slug="e1"))
    rc = cli_perms.run(_perm_args("e1", check=True))
    assert rc == 0
    assert "is valid" in capsys.readouterr().out


@pytest.mark.parametrize("check", [False, True])
def test_cli_permissions_malformed_file_returns_1(events_root, capsys, check):
    _write_event(events_root, "e3", 'slug = "e3"\n[[allow]]\nid = "a"\naction = "do"\n')  # no reason
    rc = cli_perms.run(_perm_args("e3", check=check))
    cap = capsys.readouterr()
    assert rc == 1
    assert "ctf permissions:" in cap.err and "allow[0].reason is required" in cap.err
    assert "player-declared" not in cap.out


def test_cli_permissions_unconfirmed_example_is_not_shown_as_player_declaration(events_root, capsys):
    """A verbatim copy of the template is labelled an example, never the player's declaration."""
    _write_event(events_root, "e4", permissions.EXAMPLE_PATH.read_text())
    rc = cli_perms.run(_perm_args("e4"))
    cap = capsys.readouterr()
    assert rc == 0
    assert "player-declared" not in cap.out
    assert "UNCONFIRMED EXAMPLE rules for 'e4'" in cap.out
    assert "unconfirmed example" in cap.err


def test_cli_permissions_check_fails_on_unconfirmed_example(events_root, capsys):
    _write_event(events_root, "e4", permissions.EXAMPLE_PATH.read_text())
    assert cli_perms.run(_perm_args("e4", check=True)) == 1
    cap = capsys.readouterr()
    assert "is valid" not in cap.out and "unconfirmed example" in cap.err
    # the player confirms it by deleting the example line: then it validates
    text = permissions.EXAMPLE_PATH.read_text()
    assert "example = true\n" in text
    _write_event(events_root, "e4", text.replace("example = true\n", ""))
    assert cli_perms.run(_perm_args("e4", check=True)) == 0
    assert "is valid" in capsys.readouterr().out


# ------------------------------------------------------------------ ctf abandon

def test_record_abandon_writes_and_appends(tmp_path):
    rec = cli_abandon.record_abandon(tmp_path, "web-01", "dead end: no SSTI, input is escaped",
                                     slug="huntress")
    assert rec["challenge"] == "web-01" and rec["event"] == "huntress"
    cli_abandon.record_abandon(tmp_path, "web-02", "out of budget for this one today")
    lines = (tmp_path / cli_abandon.LOG_NAME).read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["reason"].startswith("dead end")


@pytest.mark.parametrize("challenge,reason", [
    ("", "a real long reason here"),      # no challenge
    ("c", ""),                            # no reason
    ("c", "no"),                          # reason too thin
    ("c", "  a b  "),                     # non-space chars below the gate
    ("c", "abc defg"),                    # exactly MIN_REASON_CHARS - 1 = 7 non-space chars
    ("c", " a b c d e f g "),             # 7 non-space chars padded with spaces
])
def test_record_abandon_gate_rejects(tmp_path, challenge, reason):
    with pytest.raises(cli_abandon.AbandonError):
        cli_abandon.record_abandon(tmp_path, challenge, reason)
    assert not (tmp_path / cli_abandon.LOG_NAME).exists()


def test_record_abandon_gate_boundary_accepts_exactly_min(tmp_path):
    assert cli_abandon.MIN_REASON_CHARS == 8
    rec = cli_abandon.record_abandon(tmp_path, "c", "abcd efgh")   # exactly 8 non-space chars
    assert rec["reason"] == "abcd efgh"
    assert len((tmp_path / cli_abandon.LOG_NAME).read_text().splitlines()) == 1


def test_cli_abandon_run_resolves_workdir_from_env(tmp_path, monkeypatch, capsys):
    """With no --workdir, abandon writes to ctf.paths.workdir(), i.e. $CTF_WORKDIR when set."""
    wd = tmp_path / "wd"
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    monkeypatch.chdir(tmp_path)
    args = types.SimpleNamespace(challenge="rev-07", reason="the packer is out of scope today",
                                 event="huntress", workdir=None)
    assert cli_abandon.run(args) == 0
    lines = (wd / cli_abandon.LOG_NAME).read_text().splitlines()
    rec = json.loads(lines[0])
    assert rec["challenge"] == "rev-07" and rec["event"] == "huntress"
    assert str(wd.resolve() / cli_abandon.LOG_NAME) in capsys.readouterr().out
    assert not (tmp_path / cli_abandon.LOG_NAME).exists()


def test_cli_abandon_run_ok(tmp_path, capsys):
    args = types.SimpleNamespace(challenge="pwn-03", reason="segfault path is a decoy, moving on",
                                 event="huntress", workdir=tmp_path)
    assert cli_abandon.run(args) == 0
    assert "recorded" in capsys.readouterr().out
    assert (tmp_path / cli_abandon.LOG_NAME).is_file()


def test_cli_abandon_run_workdir_without_event_records_null(tmp_path, monkeypatch, capsys):
    """With an explicit --workdir and no --event, if no event resolves the record is still
    written (event=null) rather than refused: --workdir already says where to write. This is the
    documented fallback; the null event shows the gap in the log."""
    def _raise():
        raise cli_abandon._event.EventError("no event selected")
    monkeypatch.setattr(cli_abandon._event, "current", _raise)
    args = types.SimpleNamespace(challenge="misc-09", reason="no leads after an hour here",
                                 event=None, workdir=tmp_path)
    assert cli_abandon.run(args) == 0
    rec = json.loads((tmp_path / cli_abandon.LOG_NAME).read_text().splitlines()[0])
    assert rec["challenge"] == "misc-09" and rec["event"] is None


def test_cli_abandon_run_no_workdir_no_event_errors(tmp_path, monkeypatch, capsys):
    """Without --workdir, an unresolved event is a hard error (exit 2): there is no workdir to
    write to, so nothing is recorded. This is the counterpart to the event=null fallback above."""
    def _raise():
        raise cli_abandon._event.EventError("no event selected")
    monkeypatch.setattr(cli_abandon._event, "current", _raise)
    monkeypatch.chdir(tmp_path)
    args = types.SimpleNamespace(challenge="misc-09", reason="no leads after an hour here",
                                 event=None, workdir=None)
    assert cli_abandon.run(args) == 2
    assert "ctf abandon:" in capsys.readouterr().err
    assert not (tmp_path / cli_abandon.LOG_NAME).exists()


def test_cli_abandon_run_thin_reason_returns_2(tmp_path, capsys):
    args = types.SimpleNamespace(challenge="pwn-03", reason="no", event="huntress", workdir=tmp_path)
    assert cli_abandon.run(args) == 2
    assert "ctf abandon:" in capsys.readouterr().err


# ------------------------------------------------------------------ worktree-commit (pure)

def test_ensure_trailers_appends_and_is_idempotent():
    msg = "B-191: do the thing"
    t = ["Co-Authored-By=Name <x@y>"]
    once = cli_wc.ensure_trailers(msg, t)
    assert once.endswith("Co-Authored-By: Name <x@y>")
    # already present -> not duplicated
    assert cli_wc.ensure_trailers(once, t) == once


def test_ensure_trailers_bad_format_raises():
    with pytest.raises(cli_wc.WorktreeCommitError, match="KEY=VALUE"):
        cli_wc.ensure_trailers("m", ["noequals"])


def test_protected_set_defaults_and_extras():
    s = cli_wc.protected_set(["release"])
    assert {"main", "master", "release"} <= s
    assert cli_wc.protected_set([]) == frozenset({"main", "master"})


def test_no_flag_removes_a_default_protected_branch():
    """There is no override: the parser has no --allow-branch, and --protect only adds."""
    import argparse
    p = argparse.ArgumentParser()
    cli_wc.add_arguments(p)
    with pytest.raises(SystemExit):
        p.parse_args(["-m", "x", "--allow-branch", "main"])
    a = p.parse_args(["-m", "x", "--protect", "release"])
    assert {"main", "master", "release"} <= cli_wc.protected_set(a.protect)


@pytest.mark.needs_tool("git")
def test_git_info_non_repo_raises(tmp_path):
    with pytest.raises(cli_wc.WorktreeRefused, match="not inside a git work tree"):
        cli_wc.git_info(tmp_path)


@pytest.mark.needs_tool("git")
def test_git_info_inside_git_dir_refuses(tmp_path):
    """Inside the .git directory, git rev-parse --is-inside-work-tree prints 'false' with rc 0.
    That is the git dir, not the work tree, so the helper must refuse (WorktreeRefused/exit 2),
    not treat the rc-0 success as being inside a work tree."""
    _init_repo(tmp_path, "work")
    gitdir = tmp_path / ".git"
    inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=str(gitdir),
                            capture_output=True, text=True)
    assert inside.returncode == 0 and inside.stdout.strip() == "false"   # the condition under test
    with pytest.raises(cli_wc.WorktreeRefused, match="not inside a git work tree"):
        cli_wc.git_info(gitdir)
    assert cli_wc.run(_wc_args(gitdir)) == 2


def _wc_args(cwd, **over):
    a = dict(message="m", all_files=False, trailer=[], protect=[], cwd=cwd)
    a.update(over)
    return types.SimpleNamespace(**a)


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_non_repo_returns_2(tmp_path, capsys):
    assert cli_wc.run(_wc_args(tmp_path)) == 2
    assert "not inside a git work tree" in capsys.readouterr().err


# ------------------------------------------------------------------ worktree-commit (git)

def _init_repo(path: Path, branch: str) -> None:
    def g(*a):
        r = subprocess.run(["git", *a], cwd=str(path), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return r
    g("init", "-q")
    g("config", "user.email", "t@example.test")
    g("config", "user.name", "Tester")
    g("checkout", "-q", "-b", branch)
    (path / "seed.txt").write_text("seed\n")
    g("add", "-A")
    g("commit", "-q", "-m", "seed")


@pytest.mark.needs_tool("git")
def test_commit_on_work_branch_commits_with_trailer(tmp_path):
    _init_repo(tmp_path, "item/B-191")
    (tmp_path / "f.txt").write_text("change\n")
    info = cli_wc.commit(tmp_path, "add f", all_files=True,
                         protected=cli_wc.protected_set([]),
                         trailers=["Co-Authored-By=Bot <b@x>"])
    assert info.branch == "item/B-191"
    log = subprocess.run(["git", "log", "-1", "--pretty=%B"], cwd=str(tmp_path),
                         capture_output=True, text=True).stdout
    assert "add f" in log and "Co-Authored-By: Bot <b@x>" in log


@pytest.mark.needs_tool("git")
def test_commit_refuses_protected_branch(tmp_path):
    _init_repo(tmp_path, "main")
    (tmp_path / "f.txt").write_text("change\n")
    with pytest.raises(cli_wc.WorktreeRefused, match="protected branch 'main'"):
        cli_wc.commit(tmp_path, "nope", all_files=True, protected=cli_wc.protected_set([]))
    # nothing committed: HEAD is still the seed
    log = subprocess.run(["git", "log", "--oneline"], cwd=str(tmp_path),
                         capture_output=True, text=True).stdout.strip().splitlines()
    assert len(log) == 1


@pytest.mark.needs_tool("git")
def test_commit_nothing_staged_reports_git_failure(tmp_path):
    _init_repo(tmp_path, "work")
    with pytest.raises(cli_wc.GitFailed, match="git commit failed"):
        cli_wc.commit(tmp_path, "empty", all_files=True, protected=cli_wc.protected_set([]))


def _git_out(path, *a):
    return subprocess.run(["git", *a], cwd=str(path), capture_output=True, text=True).stdout


@pytest.mark.needs_tool("git")
def test_commit_default_stages_tracked_only_and_all_adds_untracked(tmp_path):
    """Default (all_files=False) is git add -u: a modified tracked file is committed, an untracked
    scratch file is not. all_files=True (git add -A) then commits the untracked file."""
    _init_repo(tmp_path, "work")
    (tmp_path / "seed.txt").write_text("seed changed\n")
    (tmp_path / "scratch.txt").write_text("untracked scratch\n")
    cli_wc.commit(tmp_path, "tracked only", all_files=False, protected=cli_wc.protected_set([]))
    files = _git_out(tmp_path, "show", "--name-only", "--pretty=format:", "HEAD").split()
    assert files == ["seed.txt"]
    assert "scratch.txt" not in _git_out(tmp_path, "ls-files").split()
    assert "?? scratch.txt" in _git_out(tmp_path, "status", "--porcelain")

    cli_wc.commit(tmp_path, "everything", all_files=True, protected=cli_wc.protected_set([]))
    files = _git_out(tmp_path, "show", "--name-only", "--pretty=format:", "HEAD").split()
    assert files == ["scratch.txt"]
    assert _git_out(tmp_path, "status", "--porcelain").strip() == ""


@pytest.mark.needs_tool("git")
def test_commit_refuses_detached_head(tmp_path):
    _init_repo(tmp_path, "work")
    seed = _git_out(tmp_path, "rev-parse", "HEAD").strip()
    subprocess.run(["git", "checkout", "-q", "--detach"], cwd=str(tmp_path), check=True)
    (tmp_path / "seed.txt").write_text("changed on detached head\n")
    with pytest.raises(cli_wc.WorktreeRefused, match="HEAD is detached"):
        cli_wc.commit(tmp_path, "nope", all_files=True, protected=cli_wc.protected_set([]))
    assert _git_out(tmp_path, "rev-parse", "HEAD").strip() == seed
    assert _git_out(tmp_path, "diff", "--cached", "--name-only").strip() == ""   # nothing staged


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_detached_returns_2(tmp_path, capsys):
    _init_repo(tmp_path, "work")
    subprocess.run(["git", "checkout", "-q", "--detach"], cwd=str(tmp_path), check=True)
    (tmp_path / "seed.txt").write_text("x\n")
    assert cli_wc.run(_wc_args(tmp_path)) == 2
    assert "HEAD is detached" in capsys.readouterr().err


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_git_failure_returns_1(tmp_path, capsys):
    _init_repo(tmp_path, "work")   # clean tree: git commit fails with nothing to commit
    assert cli_wc.run(_wc_args(tmp_path)) == 1
    assert "git commit failed" in capsys.readouterr().err
    assert len(_git_out(tmp_path, "log", "--oneline").strip().splitlines()) == 1


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_bad_trailer_returns_2(tmp_path, capsys):
    _init_repo(tmp_path, "work")
    (tmp_path / "seed.txt").write_text("x\n")
    assert cli_wc.run(_wc_args(tmp_path, trailer=["noequals"])) == 2
    assert "KEY=VALUE" in capsys.readouterr().err
    assert len(_git_out(tmp_path, "log", "--oneline").strip().splitlines()) == 1


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_run_ok(tmp_path, capsys):
    _init_repo(tmp_path, "item/x")
    (tmp_path / "g.txt").write_text("g\n")
    args = types.SimpleNamespace(message="commit g", all_files=True, trailer=[], protect=[],
                                 cwd=tmp_path)
    assert cli_wc.run(args) == 0
    assert "committed on item/x" in capsys.readouterr().out


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_protected_returns_2(tmp_path, capsys):
    _init_repo(tmp_path, "master")
    (tmp_path / "g.txt").write_text("g\n")
    args = types.SimpleNamespace(message="x", all_files=True, trailer=[], protect=[],
                                 cwd=tmp_path)
    assert cli_wc.run(args) == 2
    assert "protected branch" in capsys.readouterr().err
    assert len(_git_out(tmp_path, "log", "--oneline").strip().splitlines()) == 1


@pytest.mark.needs_tool("git")
def test_cli_worktree_commit_extra_protect_refuses(tmp_path, capsys):
    _init_repo(tmp_path, "release")
    (tmp_path / "seed.txt").write_text("x\n")
    assert cli_wc.run(_wc_args(tmp_path, protect=["release"])) == 2
    assert "protected branch 'release'" in capsys.readouterr().err
