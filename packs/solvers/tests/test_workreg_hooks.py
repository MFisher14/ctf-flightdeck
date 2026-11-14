"""B-213: the work registry hooked into the B-147 tools. `ctf worktree create --harness` registers the agent
and its claims before the worktree is made (all or nothing), and `ctf integrate run` makes the agents of
every merged branch leave the registry.

Everything runs in a synthetic git repo under tmp_path; the registry is that repo's own
(paths.workreg_state: <git common dir>/ctf-workreg), so nothing touches the real one."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from ctf import paths
from ctf import workreg as W
from ctf import worktree as wt
from ctf.cli import integrate as cli_integrate
from ctf.cli import worktree as cli_worktree

pytestmark = pytest.mark.needs_tool("git")

GIT = ["git", "-c", "user.email=t@test.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false",
       "-c", "core.hooksPath=/dev/null"]
INTEG = "integration/test"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("CTF_WORKREG_STATE", raising=False)      # the synthetic repo's own registry
    for name in (wt.ALLOW_ENV, wt.PYTHON_ENV, wt.INTEGRATION_BRANCH_ENV):
        for spelling in (name, *wt.env.legacy_names(name)):
            monkeypatch.delenv(spelling, raising=False)
    monkeypatch.setenv(wt.INTEGRATION_BRANCH_ENV, INTEG)


def _git(root: Path, *args: str) -> str:
    # hang guard only (a stuck git), not a bound under test
    r = subprocess.run([*GIT, "-C", str(root), *args], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr or r.stdout}")
    return r.stdout


def make_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", INTEG)
    (root / "base.txt").write_text("base\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


def branches(root: Path) -> set[str]:
    return set(_git(root, "for-each-ref", "--format=%(refname:short)", "refs/heads/").split())


def parser(module) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    module.add_arguments(p)
    return p


def create(repo: Path, *argv: str) -> int:
    return cli_worktree.run(parser(cli_worktree).parse_args(["create", "--repo", str(repo), *argv]))


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo")


def registry(repo: Path) -> W.Registry:
    return W.Registry(paths.workreg_state(repo))


# ------------------------------------------------------------------------------------ worktree create

def test_create_with_harness_registers_the_branch_with_worktree_and_claims(repo, tmp_path, capsys):
    dest = tmp_path / "wt-a"
    assert create(repo, "B-1", str(dest), "--harness", "codex", "--file", "ctf/x.py", "--file", "docs/") == 0
    assert (dest / "base.txt").is_file() and "item/B-1" in branches(repo)
    [v] = registry(repo).agents()
    assert v.name == "item/B-1" and v.live
    assert v.record["harness"] == "codex" and v.record["branch"] == "item/B-1"
    assert v.record["worktree"] == str(dest.resolve())
    assert v.record["claims"]["file"] == ["ctf/x.py", "docs/**"]
    assert "registered item/B-1 (codex)" in capsys.readouterr().out


def test_create_refuses_a_clashing_claim_and_creates_nothing(repo, tmp_path, capsys):
    assert create(repo, "B-1", str(tmp_path / "wt-a"), "--harness", "claude", "--file", "ctf/**") == 0
    capsys.readouterr()
    dest = tmp_path / "wt-b"
    assert create(repo, "B-2", str(dest), "--harness", "codex", "--file", "ctf/gate/runner.py") == 1
    err = capsys.readouterr().err
    assert "file 'ctf/gate/runner.py' is held by item/B-1 (claude, branch item/B-1) as 'ctf/**'" in err
    assert not dest.exists(), "the folder made for the record is removed again"
    assert "item/B-2" not in branches(repo)
    assert [v.name for v in registry(repo).agents()] == ["item/B-1"]


def test_create_validates_claims_before_anything_is_made(repo, tmp_path, capsys):
    dest = tmp_path / "wt-a"
    assert create(repo, "B-1", str(dest), "--harness", "claude", "--row", "NO-SUCH-ROW") == 2
    assert "NO-SUCH-ROW" in capsys.readouterr().err
    assert not dest.exists() and "item/B-1" not in branches(repo)
    assert registry(repo).agents() == []


def test_a_failed_worktree_add_unregisters_the_agent(repo, tmp_path, capsys):
    _git(repo, "branch", "item/B-1")                      # git refuses the branch; the registry did not
    dest = tmp_path / "wt-a"
    assert create(repo, "B-1", str(dest), "--harness", "claude", "--file", "ctf/x.py") == 2
    assert "already exists" in capsys.readouterr().err
    reg = registry(repo)
    assert reg.agents() == []
    assert [h["event"] for h in reg.history()] == ["begin", "leave"]
    assert not dest.exists()


def test_create_into_an_existing_empty_folder_keeps_it_on_failure(repo, tmp_path):
    _git(repo, "branch", "item/B-1")
    dest = tmp_path / "wt-a"
    dest.mkdir()
    assert create(repo, "B-1", str(dest), "--harness", "claude") == 2
    assert dest.is_dir(), "a folder the caller made is not removed"


def test_claims_without_harness_are_refused(repo, tmp_path, capsys):
    dest = tmp_path / "wt-a"
    assert create(repo, "B-1", str(dest), "--file", "ctf/x.py") == 2
    assert "need --harness" in capsys.readouterr().err
    assert not dest.exists() and "item/B-1" not in branches(repo)


def test_create_without_harness_registers_nothing(repo, tmp_path):
    assert create(repo, "B-1", str(tmp_path / "wt-a")) == 0
    assert not (paths.workreg_state(repo) / W.REGISTRY).exists()


def test_the_record_goes_stale_when_the_worktree_is_removed(repo, tmp_path):
    dest = tmp_path / "wt-a"
    assert create(repo, "B-1", str(dest), "--harness", "claude", "--file", "ctf/x.py") == 0
    _git(repo, "worktree", "remove", "--force", str(dest))
    [v] = registry(repo).agents()
    assert not v.live and "is gone" in v.reason


# ------------------------------------------------------------------------------------ integrate run

def items_file(tmp_path: Path, ids) -> Path:
    f = tmp_path / "to_build.json"
    f.write_text(json.dumps([{"id": i, "category": "harness", "effort": "S", "dependencies": []} for i in ids]))
    return f


def commit_on(worktree: Path, rel: str, text: str) -> None:
    (worktree / rel).write_text(text)
    _git(worktree, "add", "-A")
    _git(worktree, "commit", "-q", "-m", f"work {rel}")


def integrate(repo: Path, items: Path, *flags: str) -> int:
    args = parser(cli_integrate).parse_args(["run", "--repo", str(repo), "--items", str(items),
                                             "--no-regen", "--no-gate", *flags])
    return cli_integrate.run(args)


def test_integrate_run_makes_merged_branches_leave_the_registry(repo, tmp_path, capsys):
    a, b = tmp_path / "wt-a", tmp_path / "wt-b"
    assert create(repo, "B-1", str(a), "--harness", "claude", "--file", "a.txt") == 0
    assert create(repo, "B-2", str(b), "--harness", "codex", "--file", "b.txt") == 0
    reg = registry(repo)
    reg.begin("helper", harness="human", branch="item/B-9", files=["z.txt"])   # not queued: stays
    commit_on(a, "a.txt", "1")
    commit_on(b, "base.txt", "conflict\n")
    commit_on(repo, "base.txt", "moved on\n")             # B-2 now conflicts and does not merge
    capsys.readouterr()
    assert integrate(repo, items_file(tmp_path, ["B-1", "B-2"]), "--branches", "B-1=item/B-1",
                     "B-2=item/B-2", "--keep-going") == 1
    out = capsys.readouterr().out
    assert "left            item/B-1" in out and "left            item/B-2" not in out
    assert [v.name for v in reg.agents()] == ["helper", "item/B-2"]
    leaves = [h for h in reg.history() if h["event"] == "leave"]
    assert [(h["agent"], h["branch"]) for h in leaves] == [("item/B-1", "item/B-1")]
    assert leaves[0]["reason"] == "merged by ctf integrate run"
    # the merged branch's claim no longer blocks anyone
    assert reg.check(files=["a.txt"]) == []


def test_integrate_run_leaves_an_already_merged_branch_too(repo, tmp_path, capsys):
    a = tmp_path / "wt-a"
    assert create(repo, "B-1", str(a), "--harness", "claude") == 0
    items = items_file(tmp_path, ["B-1"])
    commit_on(a, "a.txt", "1")
    reg = registry(repo)
    assert integrate(repo, items, "--branches", "B-1=item/B-1") == 0
    reg.begin("item/B-1-again", harness="claude", branch="item/B-1")        # registered after its merge
    assert integrate(repo, items, "--branches", "B-1=item/B-1") == 0
    assert "already-merged" in capsys.readouterr().out
    assert reg.agents() == []


def test_integrate_run_with_no_registry_creates_none(repo, tmp_path):
    _git(repo, "branch", "item/B-1")
    commit_on(repo, "x.txt", "x")
    assert integrate(repo, items_file(tmp_path, ["B-1"]), "--branches", "B-1=item/B-1") == 0
    assert not paths.workreg_state(repo).exists()


def test_integrate_run_names_an_unreadable_registry_and_exits_2(repo, tmp_path, capsys):
    _git(repo, "branch", "item/B-1")
    state = paths.workreg_state(repo)
    state.mkdir()
    (state / W.REGISTRY).write_text("{not json")
    assert integrate(repo, items_file(tmp_path, ["B-1"]), "--branches", "B-1=item/B-1") == 2
    err = capsys.readouterr().err
    assert "unreadable work registry" in err and "the merges above stand" in err
