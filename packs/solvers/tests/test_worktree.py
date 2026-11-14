"""B-147: per-agent worktrees and the integrator merge queue (ctf.worktree, ctf.cli.worktree/integrate).

Everything runs on throwaway git repos built under tmp_path; no real challenge file, no network, no
remote. git is the one external dependency and is always present, so these are ordinary unit tests.

The repo helpers below (`_git`) switch hooks off for set-up commits. The code under test
(`wt.git`) leaves hooks on, and the hook tests install real hooks in the throwaway repo, so the
guard and the integrator are exercised the way git runs them."""
from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from ctf import paths
from ctf import worktree as wt
from ctf.cli import integrate as cli_integrate
from ctf.cli import worktree as cli_worktree

GIT_BASE = ["git", "-c", "user.email=t@test.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
GIT = [*GIT_BASE, "-c", "core.hooksPath=/dev/null"]
INTEG = "integration/test"


@pytest.fixture(autouse=True)
def _integration_env(monkeypatch):
    """The integration branch is configuration: name it for every test, and start from an environment
    with no allow flag and no interpreter override (a test that needs one sets it)."""
    for name in (wt.ALLOW_ENV, wt.PYTHON_ENV, wt.INTEGRATION_BRANCH_ENV):
        for spelling in (name, *wt.env.legacy_names(name)):
            monkeypatch.delenv(spelling, raising=False)
    monkeypatch.delenv("CTF_WORKREG_STATE", raising=False)   # integrate run touches the repo's own (B-213)
    monkeypatch.setenv(wt.INTEGRATION_BRANCH_ENV, INTEG)


def _git(root: Path, *args: str) -> str:
    # The timeouts in these helpers are hang guards for a stuck git, not bounds under test: they are
    # far above what a local git command (or a hook starting python) takes on a loaded machine.
    r = subprocess.run([*GIT, "-C", str(root), *args], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr or r.stdout}")
    return r.stdout


def _head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD").strip()


def _parents(root: Path, rev: str = "HEAD") -> list[str]:
    return _git(root, "rev-list", "--parents", "-n", "1", rev).split()[1:]


def _tip(root: Path, branch: str) -> str:
    return _git(root, "rev-parse", branch).strip()


def _first_parent_chain(root: Path) -> list[str]:
    """The integration branch's own commits, newest first."""
    return _git(root, "rev-list", "--first-parent", "HEAD").split()


def make_repo(root: Path, *, integration: str = INTEG) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", integration)
    (root / "base.txt").write_text("base\n")
    (root / "SHARED.txt").write_text("base\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


def add_item_branch(root: Path, iid: str, files: dict[str, str], *, base: str = INTEG,
                    prefix: str = "item") -> str:
    """Create branch <prefix>/<iid> from `base`, add `files`, commit, return to the integration branch."""
    branch = f"{prefix}/{iid}"
    _git(root, "checkout", "-q", "-b", branch, base)
    for rel, text in files.items():
        (root / rel).write_text(text)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", f"{iid}: work")
    _git(root, "checkout", "-q", base)
    return branch


def install_hook(root: Path, name: str, body: str) -> None:
    """Install a real git hook in the throwaway repo and point the repo at it (a repo-local
    core.hooksPath, so a global one on the machine cannot shadow it)."""
    hooks = root / ".git" / "test-hooks"
    hooks.mkdir(exist_ok=True)
    script = hooks / name
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    _git(root, "config", "core.hooksPath", str(hooks))


GUARD_HOOK = f'PYTHONPATH="{paths.repo_root()}" exec "{sys.executable}" -m ctf integrate guard'


def install_guard_hook(root: Path) -> None:
    """pre-commit = `python -m ctf integrate guard`, the way a checkout would wire it."""
    install_hook(root, "pre-commit", GUARD_HOOK)


def install_guard_hooks(root: Path) -> None:
    """The full wiring: the guard as pre-commit AND pre-merge-commit (git runs the second, not the
    first, when `git merge` makes a merge commit on its own)."""
    install_hook(root, "pre-commit", GUARD_HOOK)
    install_hook(root, "pre-merge-commit", GUARD_HOOK)


def hand_git(root: Path, *args: str) -> subprocess.CompletedProcess:
    """A git command run by hand: hooks on, no allow flag, result returned (not checked)."""
    return subprocess.run([*GIT_BASE, "-C", str(root), *args], capture_output=True, text=True,
                          timeout=300)


def journal(root: Path) -> Path:
    return root / ".git" / wt.STEP_JOURNAL


def commit_with_hooks(root: Path, rel: str = "poke.txt") -> subprocess.CompletedProcess:
    """A hand commit made the ordinary way: hooks on."""
    (root / rel).write_text("poke\n")
    subprocess.run([*GIT_BASE, "-C", str(root), "add", "-A"], capture_output=True, text=True, check=True)
    return subprocess.run([*GIT_BASE, "-C", str(root), "commit", "-m", "hand commit"],
                          capture_output=True, text=True, timeout=300)


@dataclass(frozen=True)
class FakeItem:
    id: str
    dependencies: tuple[str, ...] = ()


def flat(*ids: str) -> list[FakeItem]:
    return [FakeItem(i) for i in ids]


def queue(*ids: str) -> dict[str, str]:
    return {i: f"item/{i}" for i in ids}


# ------------------------------------------------------------------------------- agent_branch

def test_agent_branch_prefixes_bare_id():
    assert wt.agent_branch("B-147") == "item/B-147"
    assert wt.agent_branch("B-147", prefix="agent") == "agent/B-147"
    assert wt.agent_branch("x/y") == "item/x/y"


@pytest.mark.parametrize("bad", ["", "  ", "a b", "a~b", "a..b", "a:b", "-x", "--force", "a@{b",
                                 "a.lock", "a/", ".a", "a.", "a?b", "a\\b"])
def test_agent_branch_rejects_illegal(bad):
    with pytest.raises(wt.WorktreeError):
        wt.agent_branch(bad)


# ------------------------------------------------------------------------------- create / list

def test_create_makes_worktree_on_new_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    dest = tmp_path / "wt-A"
    w = wt.create(repo, wt.agent_branch("B-1"), dest)
    assert w.branch == "item/B-1"
    assert w.path.resolve() == dest.resolve()
    assert (dest / "base.txt").exists()
    branches = _git(repo, "branch", "--list", "item/B-1")
    assert "item/B-1" in branches


def test_create_refuses_existing_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    wt.create(repo, "item/B-1", tmp_path / "wt-A")
    with pytest.raises(wt.WorktreeError, match="already exists"):
        wt.create(repo, "item/B-1", tmp_path / "wt-B")


def test_create_refuses_nonempty_path(tmp_path):
    repo = make_repo(tmp_path / "repo")
    dest = tmp_path / "taken"
    dest.mkdir()
    (dest / "junk").write_text("x")
    with pytest.raises(wt.WorktreeError, match="already exists and is not empty"):
        wt.create(repo, "item/B-1", dest)


def test_list_worktrees_includes_created(tmp_path):
    repo = make_repo(tmp_path / "repo")
    wt.create(repo, "item/B-1", tmp_path / "wt-A")
    wt.create(repo, "item/B-2", tmp_path / "wt-B")
    got = wt.list_worktrees(repo)
    branches = {w.branch for w in got}
    assert {"item/B-1", "item/B-2"} <= branches
    assert any(w.path.resolve() == repo.resolve() for w in got)


def test_item_branches_discovers_prefixed(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"a.txt": "1"})
    add_item_branch(repo, "B-2", {"b.txt": "2"})
    _git(repo, "checkout", "-q", "-b", "scratch/other", INTEG)
    _git(repo, "checkout", "-q", INTEG)
    found = wt.item_branches(repo)
    assert found == {"B-1": "item/B-1", "B-2": "item/B-2"}


# ------------------------------------------------------------------------------- dependency_order

def test_dependency_order_dependency_before_dependent():
    branches = {"B-2": "item/B-2", "B-1": "item/B-1"}
    items = [FakeItem("B-1"), FakeItem("B-2", ("B-1",))]
    assert wt.dependency_order(branches, items) == ["B-1", "B-2"]


def test_dependency_order_beats_id_order():
    # The dependent has the LOWER id, so sorting by id alone gets this wrong.
    branches = queue("B-1", "B-2", "B-3")
    items = [FakeItem("B-1", ("B-2",)), FakeItem("B-2"), FakeItem("B-3")]
    assert wt.dependency_order(branches, items) == ["B-2", "B-3", "B-1"]


def test_dependency_order_chain_against_id_order():
    # B-1 needs B-2 needs B-3: the only valid order is the reverse of the id order.
    branches = queue("B-1", "B-2", "B-3")
    items = [FakeItem("B-1", ("B-2",)), FakeItem("B-2", ("B-3",)), FakeItem("B-3")]
    assert wt.dependency_order(branches, items) == ["B-3", "B-2", "B-1"]


def test_dependency_order_ignores_dep_outside_queue():
    # B-2 depends on B-1, but only B-2 is queued (B-1 already in base) -> B-2 alone, no error.
    branches = {"B-2": "item/B-2"}
    items = [FakeItem("B-1"), FakeItem("B-2", ("B-1",))]
    assert wt.dependency_order(branches, items) == ["B-2"]


def test_dependency_order_ignores_a_self_dependency():
    # An item that lists itself is not a cycle: it has no other item to wait for.
    assert wt.dependency_order(queue("B-1"), [FakeItem("B-1", ("B-1",))]) == ["B-1"]
    items = [FakeItem("B-1", ("B-1", "B-2")), FakeItem("B-2", ("B-2",))]
    assert wt.dependency_order(queue("B-1", "B-2"), items) == ["B-2", "B-1"]
    assert wt.queue_dependencies(queue("B-1", "B-2"), items) == {"B-1": {"B-2"}, "B-2": set()}


def test_dependency_order_stable_by_id():
    branches = {"B-3": "x", "B-1": "y", "B-2": "z"}
    items = [FakeItem("B-1"), FakeItem("B-2"), FakeItem("B-3")]
    assert wt.dependency_order(branches, items) == ["B-1", "B-2", "B-3"]


def test_dependency_order_cycle_raises():
    branches = {"B-1": "a", "B-2": "b"}
    items = [FakeItem("B-1", ("B-2",)), FakeItem("B-2", ("B-1",))]
    with pytest.raises(wt.WorktreeError, match="cycle"):
        wt.dependency_order(branches, items)


def test_dependency_order_unknown_item_raises():
    branches = {"B-9": "a"}
    items = [FakeItem("B-1")]
    with pytest.raises(wt.WorktreeError, match="no BUILD-PLAN item record"):
        wt.dependency_order(branches, items)


# ------------------------------------------------------------------------------- integrate: order

def test_integrate_merges_in_dependency_order_not_id_order(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})
    items = [FakeItem("B-1", ("B-2",)), FakeItem("B-2")]      # the dependent has the lower id
    res = wt.integrate(repo, queue("B-1", "B-2"), items=items)
    assert res.ok and not res.halted
    assert res.order == ("B-2", "B-1")
    assert [s.item for s in res.merged()] == ["B-2", "B-1"]
    assert (repo / "one.txt").exists() and (repo / "two.txt").exists()
    # History, not the report: first-parent chain is merge(B-1) <- merge(B-2) <- base, and each merge
    # commit's second parent is that item's branch tip.
    chain = _first_parent_chain(repo)
    assert len(chain) == 3 and chain[2] == base
    assert _parents(repo, chain[0]) == [chain[1], _tip(repo, "item/B-1")]
    assert _parents(repo, chain[1]) == [base, _tip(repo, "item/B-2")]
    assert [s.commit for s in res.steps] == [chain[1], chain[0]]


def test_integrate_makes_a_merge_commit_even_when_fast_forward_is_possible(tmp_path):
    # The branch is cut from the integration tip, so git could fast-forward. The queue must not: the
    # merge commit is what records the integrator as the writer, and the only commit it may amend.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"))
    assert res.ok
    assert _parents(repo) == [base, _tip(repo, "item/B-1")]
    assert _head(repo) != _tip(repo, "item/B-1")
    assert res.steps[0].status == "merged" and res.steps[0].commit == _head(repo)


# ------------------------------------------------------------------- integrate: regenerate and gate

def test_integrate_regenerate_folded_into_the_merge_commit(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})

    def regen(top: Path) -> None:
        (top / "GENERATED.txt").write_text("regen\n")
        (top / "base.txt").write_text("regenerated\n")       # a tracked generated file changes too

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=regen)
    assert res.ok
    assert wt.is_clean(repo)
    assert _git(repo, "show", "HEAD:GENERATED.txt").strip() == "regen"
    assert _git(repo, "show", "HEAD:base.txt").strip() == "regenerated"
    # One commit was added, it is the merge commit, and the base commit under it is untouched.
    assert _parents(repo) == [base, _tip(repo, "item/B-1")]
    assert _first_parent_chain(repo) == [_head(repo), base]


def test_integrate_already_merged_branch_is_reported_and_nothing_is_amended(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    assert wt.integrate(repo, queue("B-1"), items=flat("B-1")).ok
    # A later, unrelated commit lands on the integration branch (here by a test helper).
    (repo / "later.txt").write_text("later\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "later: unrelated")
    later = _head(repo)
    calls = {"regen": 0, "gate": 0}

    def regen(top: Path) -> None:
        calls["regen"] += 1
        (top / "GENERATED.txt").write_text("regen\n")        # would dirty the tree and invite an amend

    def gate(top: Path, base: str):
        calls["gate"] += 1
        return True, "green"

    # The default discovery path re-queues every local item/* branch, merged ones included.
    res = wt.integrate(repo, wt.item_branches(repo), items=flat("B-1"), regenerate=regen, gate=gate)
    assert [s.status for s in res.steps] == ["already-merged"]
    assert res.ok and res.merged() == []
    assert res.steps[0].commit == later
    assert _head(repo) == later                                # HEAD was not replaced
    assert _git(repo, "log", "-1", "--pretty=%s").strip() == "later: unrelated"
    assert calls == {"regen": 0, "gate": 0}
    assert wt.is_clean(repo) and not (repo / "GENERATED.txt").exists()


def test_integrate_already_merged_dependency_does_not_hold_its_dependent(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-2", {"two.txt": "2"})
    assert wt.integrate(repo, queue("B-2"), items=flat("B-2")).ok
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    res = wt.integrate(repo, queue("B-1", "B-2"), items=[FakeItem("B-1", ("B-2",)), FakeItem("B-2")],
                       stop_on_fail=False)
    assert {s.item: s.status for s in res.steps} == {"B-2": "already-merged", "B-1": "merged"}
    assert res.ok


def test_integrate_gate_receives_pre_merge_base(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base_before = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    seen = {}

    def gate(top: Path, base: str):
        seen["base"] = base
        seen["top"] = top
        seen["merged_file_present"] = (top / "one.txt").exists()
        return True, "green"

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=gate)
    assert res.ok
    assert seen["base"] == base_before
    assert seen["top"].resolve() == repo.resolve()
    assert seen["merged_file_present"]                         # the gate runs on the merged tree


def test_integrate_red_gate_rolls_the_merge_back_and_halts(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})

    def gate(top: Path, base: str):
        return False, "red: test failed"

    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"), gate=gate)
    assert not res.ok and res.halted
    assert [(s.item, s.status) for s in res.steps] == [("B-1", "gate-failed"), ("B-2", "skipped")]
    assert res.steps[0].detail == "red: test failed"
    assert "B-1 gate-failed" in res.steps[1].detail
    # The red merge is not on the integration branch...
    assert _head(repo) == base and wt.is_clean(repo)
    assert not (repo / "one.txt").exists()
    # ...but the step names the rolled-back merge commit for a post-mortem.
    assert _parents(repo, res.steps[0].commit) == [base, _tip(repo, "item/B-1")]
    assert res.failure().item == "B-1"


def test_integrate_keep_going_next_item_merges_on_the_base_not_on_the_red_merge(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})

    def gate(top: Path, base: str):
        red = (top / "one.txt").exists()                      # red exactly when B-1's work is present
        return (not red), ("red: B-1" if red else "green")

    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"), gate=gate,
                       stop_on_fail=False)
    assert [(s.item, s.status) for s in res.steps] == [("B-1", "gate-failed"), ("B-2", "merged")]
    assert not res.ok and not res.halted
    assert _parents(repo) == [base, _tip(repo, "item/B-2")]   # merged straight onto the base
    assert not (repo / "one.txt").exists() and (repo / "two.txt").exists()


def test_integrate_gate_that_raises_is_a_failed_gate_with_rollback(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})

    def gate(top: Path, base: str):
        raise FileNotFoundError("no such interpreter")

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=gate)
    assert res.steps[0].status == "gate-failed"
    assert "gate could not run" in res.steps[0].detail and "no such interpreter" in res.steps[0].detail
    assert _head(repo) == base and wt.is_clean(repo)


def test_integrate_gate_that_leaves_a_file_fails_and_the_file_is_never_committed(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})

    def gate(top: Path, base: str):
        (top / "junit-out.xml").write_text("<testsuite/>\n")
        return True, "green"

    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"), gate=gate,
                       stop_on_fail=False)
    assert [(s.item, s.status) for s in res.steps] == [("B-1", "gate-failed"), ("B-2", "skipped")]
    assert "junit-out.xml" in res.steps[0].detail
    assert res.halted and "junit-out.xml" in res.steps[1].detail   # halts even with keep-going
    assert _head(repo) == base
    # Left for a human, never deleted, and in no commit.
    assert (repo / "junit-out.xml").exists()
    assert _git(repo, "ls-files", "junit-out.xml").strip() == ""
    assert _git(repo, "log", "--all", "--pretty=%H", "--", "junit-out.xml").strip() == ""


def test_integrate_gate_that_commits_fails_and_is_rolled_back(tmp_path):
    # A green gate that made a commit of its own left the tree clean, but HEAD is no longer the
    # merge the queue made: the step fails and neither commit stays on the branch.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})

    def gate(top: Path, base: str):
        (top / "gate-report.txt").write_text("report\n")
        _git(top, "add", "-A")
        _git(top, "commit", "-q", "-m", "gate: committed its report")
        return True, "green"

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=gate)
    assert [s.status for s in res.steps] == ["gate-failed"]
    assert "changed the checkout" in res.steps[0].detail and "HEAD moved" in res.steps[0].detail
    assert _head(repo) == base and wt.is_clean(repo)
    assert _git(repo, "log", "--pretty=%s").strip() == "base"  # neither the merge nor the gate's commit
    assert not res.ok


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_integrate_interrupted_gate_rolls_the_merge_back_and_reraises(tmp_path, interrupt):
    # Ctrl-C during the gate: the merge is on the branch and has not passed. It must not stay
    # there, or the next run would report the branch `already-merged` without ever gating it.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    seen = {}

    def gate(top: Path, base: str):
        seen["head_in_gate"] = _head(top)
        raise interrupt()

    with pytest.raises(interrupt):
        wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=gate)
    assert seen["head_in_gate"] != base                        # the merge was there when it hit
    assert _head(repo) == base and wt.is_clean(repo)
    assert not (repo / "one.txt").exists()
    assert not journal(repo).exists()
    # The next run gates the item for real instead of accepting it.
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=lambda top, b: (False, "red"))
    assert [s.status for s in res.steps] == ["gate-failed"]
    assert _head(repo) == base


def test_integrate_interrupted_regenerate_rolls_the_merge_back_and_reraises(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})

    def regen(top: Path) -> None:
        (top / "base.txt").write_text("half regenerated\n")   # a tracked file, mid-write
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=regen)
    assert _head(repo) == base and wt.is_clean(repo)
    assert (repo / "base.txt").read_text() == "base\n"
    assert not journal(repo).exists()


KILLED_IN_GATE = """\
import os, sys
from pathlib import Path
from types import SimpleNamespace
from ctf import worktree as wt

def gate(top, base):
    os._exit(9)          # the process dies inside the gate: no exception, no cleanup

wt.integrate(Path(sys.argv[1]), {"B-1": "item/B-1"},
             items=[SimpleNamespace(id="B-1", dependencies=())], gate=gate)
"""


def test_integrate_refuses_to_run_on_the_merge_a_killed_run_left_ungated(tmp_path):
    # A kill cannot be caught, so the integrator that dies in the gate leaves its merge on the
    # branch. The next run must refuse it by name, not report the item `already-merged`.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})
    died = subprocess.run([sys.executable, "-c", KILLED_IN_GATE, str(repo)],
                          env={**os.environ, "PYTHONPATH": str(paths.repo_root())},
                          capture_output=True, text=True, timeout=600)
    assert died.returncode == 9, died.stderr
    ungated = _head(repo)
    assert _parents(repo) == [base, _tip(repo, "item/B-1")]    # the scenario: the merge is there
    assert journal(repo).exists()

    green = lambda top, b: (True, "green")                    # noqa: E731
    for q in (queue("B-1"), queue("B-2"), queue("B-1", "B-2")):
        with pytest.raises(wt.WorktreeError, match="interrupted while merging 'item/B-1'") as e:
            wt.integrate(repo, q, items=flat("B-1", "B-2"), gate=green)
        assert f"git reset --hard {base}" in str(e.value)      # says how to get out
    assert _head(repo) == ungated                              # refused, and nothing reset for us

    # After the reset the message asks for, the stale journal is dropped and the item is gated.
    _git(repo, "reset", "-q", "--hard", base)
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=lambda top, b: (False, "red"))
    assert [s.status for s in res.steps] == ["gate-failed"]
    assert _head(repo) == base and not journal(repo).exists()


def test_integrate_refuses_an_unreadable_step_journal(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    journal(repo).write_text("{not json")
    with pytest.raises(wt.WorktreeError, match="unreadable integrator step journal"):
        wt.integrate(repo, queue("B-1"), items=flat("B-1"))
    assert _head(repo) == base and journal(repo).exists()


def test_integrate_step_journal_is_gone_after_every_kind_of_step(tmp_path):
    # merged, failed and already-merged steps all leave no journal, so a later run is not refused.
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"SHARED.txt": "one\n"})
    add_item_branch(repo, "B-2", {"SHARED.txt": "two\n"})     # conflicts once B-1 is in
    seen = []

    def gate(top: Path, base: str):
        seen.append(journal(top).exists())                     # present while the step is open
        return True, "green"

    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"), gate=gate)
    assert [s.status for s in res.steps] == ["merged", "conflict"]
    assert seen == [True] and not journal(repo).exists()
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=gate)
    assert [s.status for s in res.steps] == ["already-merged"] and not journal(repo).exists()


def test_integrate_regen_failure_resets_and_stops(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})

    def regen(top: Path) -> None:
        (top / "base.txt").write_text("half written\n")       # a tracked file, half regenerated
        raise RuntimeError("generator blew up")

    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"), regenerate=regen)
    assert not res.ok and res.halted
    assert [(s.item, s.status) for s in res.steps] == [("B-1", "regen-failed"), ("B-2", "skipped")]
    assert "generator blew up" in res.steps[0].detail
    # The merge and the half-written tracked file were rolled back to the pre-merge base.
    assert _head(repo) == base and wt.is_clean(repo)
    assert (repo / "base.txt").read_text() == "base\n"


def test_integrate_regen_failure_leaving_an_untracked_file_halts_the_queue(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})

    def regen(top: Path) -> None:
        (top / "HALF.txt").write_text("half\n")
        raise RuntimeError("generator blew up")

    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"), regenerate=regen,
                       stop_on_fail=False)
    assert [(s.item, s.status) for s in res.steps] == [("B-1", "regen-failed"), ("B-2", "skipped")]
    assert res.halted and "HALF.txt" in res.steps[1].detail
    assert _head(repo) == base
    assert (repo / "HALF.txt").exists()                        # named and left, not deleted
    assert _git(repo, "ls-files", "HALF.txt").strip() == ""
    # The next run refuses the dirty tree by name instead of sweeping the file into a merge.
    with pytest.raises(wt.WorktreeError, match="HALF.txt"):
        wt.integrate(repo, queue("B-2"), items=flat("B-2"))


def test_integrate_regenerate_that_commits_is_refused_and_never_amended(tmp_path):
    # A regenerate step that makes its own commit moves HEAD off the merge commit. Folding into
    # "whatever HEAD is" would then amend a commit the queue did not make, so the step fails.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})

    def regen(top: Path) -> None:
        (top / "GENERATED.txt").write_text("regen\n")
        _git(top, "add", "-A")
        _git(top, "commit", "-q", "-m", "regen: committed by the generator")
        (top / "MORE.txt").write_text("more\n")               # and leaves the tree dirty on top

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=regen)
    assert res.steps[0].status == "regen-failed"
    assert "moved HEAD" in res.steps[0].detail
    assert _head(repo) == base
    assert _git(repo, "log", "--pretty=%s").strip() == "base"  # neither the merge nor the stray commit


def test_integrate_stops_when_the_merge_does_not_leave_the_expected_merge_commit(tmp_path):
    # A post-merge hook that commits: git merge exits 0 but HEAD is not merge(base, tip). The queue
    # must not regenerate into, gate or report that commit as its merge.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_hook(repo, "post-merge",
                 "git -c user.email=h@test.invalid -c user.name=h -c commit.gpgsign=false "
                 "commit -q --allow-empty -m 'hook: stray commit'")
    ran = []
    with pytest.raises(wt.WorktreeError, match="did not leave a merge commit"):
        wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=ran.append,
                     gate=lambda top, b: (ran.append(top), (True, "green"))[1])
    assert ran == []                                           # neither step ran
    assert _head(repo) == base and wt.is_clean(repo)


# ------------------------------------------------------------------- integrate: merge failures

def test_integrate_conflict_stops_and_aborts(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"SHARED.txt": "one\n"})
    add_item_branch(repo, "B-2", {"SHARED.txt": "two\n"})
    res = wt.integrate(repo, queue("B-1", "B-2"), items=flat("B-1", "B-2"))
    assert not res.ok
    statuses = {s.item: s.status for s in res.steps}
    assert statuses == {"B-1": "merged", "B-2": "conflict"}
    # The failed merge was aborted: the tree is clean at B-1's merge, not left mid-conflict.
    assert wt.is_clean(repo)
    assert not (repo / ".git" / "MERGE_HEAD").exists()
    assert _head(repo) == res.steps[0].commit
    assert (repo / "SHARED.txt").read_text() == "one\n"
    assert res.failure() is not None and res.failure().item == "B-2"


def test_integrate_missing_branch_is_not_called_a_conflict(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    res = wt.integrate(repo, {"B-1": "item/does-not-exist"}, items=flat("B-1"))
    assert res.steps[0].status == "missing-branch"
    assert "item/does-not-exist" in res.steps[0].detail
    assert not res.ok and _head(repo) == base and wt.is_clean(repo)


def test_integrate_merge_refused_by_a_hook_is_merge_failed_and_rolled_back(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_hook(repo, "pre-merge-commit", "echo 'hook says no' >&2; exit 1")
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"))
    assert res.steps[0].status == "merge-failed"               # no conflicted path: not a conflict
    assert _head(repo) == base and wt.is_clean(repo)
    assert not (repo / ".git" / "MERGE_HEAD").exists()
    assert not (repo / "one.txt").exists()


def test_integrate_refuses_a_branch_name_that_is_an_option(tmp_path):
    repo = make_repo(tmp_path / "repo")
    with pytest.raises(wt.WorktreeError, match="not a branch name"):
        wt.integrate(repo, {"B-1": "--strategy=ours"}, items=flat("B-1"))


# ------------------------------------------------------------------- integrate: preconditions

def test_integrate_refuses_wrong_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    _git(repo, "checkout", "-q", "-b", "somewhere-else")
    with pytest.raises(wt.WorktreeError, match="integration branch"):
        wt.integrate(repo, {}, items=[])


def test_integrate_refuses_dirty_tree(tmp_path):
    repo = make_repo(tmp_path / "repo")
    (repo / "base.txt").write_text("dirtied\n")
    with pytest.raises(wt.WorktreeError, match="uncommitted changes"):
        wt.integrate(repo, {}, items=[])


def test_integrate_sees_untracked_files_whatever_the_git_config_says(tmp_path):
    # With status.showUntrackedFiles=no a plain `git status --porcelain` hides untracked files.
    repo = make_repo(tmp_path / "repo")
    _git(repo, "config", "status.showUntrackedFiles", "no")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})

    # A stray untracked file fails the clean-tree precondition, by name.
    (repo / "stray.txt").write_text("stray\n")
    assert not wt.is_clean(repo)
    with pytest.raises(wt.WorktreeError, match="uncommitted changes.*stray.txt"):
        wt.integrate(repo, queue("B-1"), items=flat("B-1"))
    (repo / "stray.txt").unlink()
    assert wt.is_clean(repo)

    # A brand-new file written by regenerate is folded into the merge commit.
    def regen(top: Path) -> None:
        (top / "GENERATED.txt").write_text("regen\n")

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=regen)
    assert [s.status for s in res.steps] == ["merged"]
    assert _git(repo, "show", "HEAD:GENERATED.txt").strip() == "regen"
    assert _parents(repo) == [base, _tip(repo, "item/B-1")]

    # And a gate that leaves an untracked file behind is still caught.
    after_one = _head(repo)

    def gate(top: Path, base: str):
        (top / "junit-out.xml").write_text("<testsuite/>\n")
        return True, "green"

    res = wt.integrate(repo, queue("B-2"), items=flat("B-2"), gate=gate)
    assert [s.status for s in res.steps] == ["gate-failed"] and "junit-out.xml" in res.steps[0].detail
    assert _head(repo) == after_one


def test_integrate_without_a_configured_integration_branch_refuses(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    monkeypatch.delenv(wt.INTEGRATION_BRANCH_ENV)
    with pytest.raises(wt.WorktreeError, match="no integration branch configured"):
        wt.integrate(repo, {}, items=[])
    # The argument is enough on its own.
    assert wt.integrate(repo, {}, items=[], integration_branch=INTEG).ok


def test_integration_branch_name_sources_in_order(tmp_path):
    repo = make_repo(tmp_path / "repo")
    _git(repo, "config", wt.INTEGRATION_BRANCH_GIT_CONFIG, "from-git-config")
    env_set = {wt.INTEGRATION_BRANCH_ENV: "from-env"}
    assert wt.integration_branch_name("from-arg", repo=repo, environ=env_set) == "from-arg"
    assert wt.integration_branch_name(None, repo=repo, environ=env_set) == "from-env"
    assert wt.integration_branch_name(None, repo=repo, environ={}) == "from-git-config"
    with pytest.raises(wt.WorktreeError, match="no integration branch configured"):
        wt.integration_branch_name(None, environ={})          # no repo to ask, nothing set


# ------------------------------------------------------------------- integrate: keep-going

def test_integrate_keep_going_continues_past_failure(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"SHARED.txt": "one\n"})
    add_item_branch(repo, "B-2", {"SHARED.txt": "two\n"})
    add_item_branch(repo, "B-3", {"three.txt": "3"})
    res = wt.integrate(repo, queue("B-1", "B-2", "B-3"), items=flat("B-1", "B-2", "B-3"),
                       stop_on_fail=False)
    statuses = {s.item: s.status for s in res.steps}
    assert statuses == {"B-1": "merged", "B-2": "conflict", "B-3": "merged"}
    assert (repo / "three.txt").exists()
    assert not res.ok and not res.halted  # the conflict is still a failure overall


def test_integrate_keep_going_skips_everything_that_depends_on_a_failure(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"SHARED.txt": "one\n"})
    add_item_branch(repo, "B-2", {"SHARED.txt": "two\n"})     # conflicts once B-1 is in
    add_item_branch(repo, "B-3", {"three.txt": "3"})          # needs B-2
    add_item_branch(repo, "B-4", {"four.txt": "4"})           # needs B-3, so B-2 transitively
    add_item_branch(repo, "B-5", {"five.txt": "5"})           # independent
    items = [FakeItem("B-1"), FakeItem("B-2"), FakeItem("B-3", ("B-2",)), FakeItem("B-4", ("B-3",)),
             FakeItem("B-5")]
    res = wt.integrate(repo, queue("B-1", "B-2", "B-3", "B-4", "B-5"), items=items, stop_on_fail=False)
    by = {s.item: s for s in res.steps}
    assert {i: s.status for i, s in by.items()} == {
        "B-1": "merged", "B-2": "conflict", "B-3": "skipped", "B-4": "skipped", "B-5": "merged"}
    assert "B-2 (conflict)" in by["B-3"].detail               # names the failed dependency
    assert "B-3 (skipped)" in by["B-4"].detail                # and the transitive one
    assert not (repo / "three.txt").exists() and not (repo / "four.txt").exists()
    assert (repo / "five.txt").exists()
    assert not res.ok and [s.item for s in res.failures()] == ["B-2"]


# ------------------------------------------------- integrate: a dependency outside the queue

def test_integrate_holds_an_item_whose_unqueued_dependency_branch_is_not_merged(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    add_item_branch(repo, "B-2", {"two.txt": "2"})            # needs B-1
    add_item_branch(repo, "B-3", {"three.txt": "3"})          # needs B-2
    add_item_branch(repo, "B-4", {"four.txt": "4"})           # independent
    items = [FakeItem("B-1"), FakeItem("B-2", ("B-1",)), FakeItem("B-3", ("B-2",)), FakeItem("B-4")]

    # Only B-2..B-4 are queued; item/B-1 exists and is not in the integration branch.
    res = wt.integrate(repo, queue("B-2", "B-3", "B-4"), items=items, stop_on_fail=False)
    by = {s.item: s for s in res.steps}
    assert {i: s.status for i, s in by.items()} == {"B-2": "skipped", "B-3": "skipped", "B-4": "merged"}
    assert "B-1 (item/B-1)" in by["B-2"].detail and "not queued" in by["B-2"].detail
    assert "B-2 (skipped)" in by["B-3"].detail                # the hold carries to its dependents
    assert not res.ok and not res.halted                      # a held item is not a success
    assert not (repo / "two.txt").exists() and not (repo / "three.txt").exists()
    assert _parents(repo) == [base, _tip(repo, "item/B-4")]

    # Once B-1 is merged, the same queue goes through.
    assert wt.integrate(repo, queue("B-1"), items=items).ok
    res = wt.integrate(repo, queue("B-2", "B-3"), items=items)
    assert [(s.item, s.status) for s in res.steps] == [("B-2", "merged"), ("B-3", "merged")]


def test_integrate_dependency_with_no_local_branch_does_not_hold_its_dependent(tmp_path):
    # B-0 has no branch here (merged long ago and deleted, or never built): nothing to wait for.
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-2", {"two.txt": "2"})
    res = wt.integrate(repo, queue("B-2"), items=[FakeItem("B-0"), FakeItem("B-2", ("B-0",))])
    assert [s.status for s in res.steps] == ["merged"] and res.ok


def test_integrate_unqueued_dependency_is_looked_up_under_the_given_prefix(tmp_path):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"one.txt": "1"}, prefix="lane")
    add_item_branch(repo, "B-2", {"two.txt": "2"}, prefix="lane")
    items = [FakeItem("B-1"), FakeItem("B-2", ("B-1",))]
    held = wt.integrate(repo, {"B-2": "lane/B-2"}, items=items, prefix="lane")
    assert [s.status for s in held.steps] == ["skipped"] and "B-1 (lane/B-1)" in held.steps[0].detail
    assert wt.unmerged_dependency_branches(repo, {"B-1", "B-9"}, prefix="lane") == [("B-1", "lane/B-1")]
    # Under the default prefix there is no item/B-1 branch, so nothing holds B-2.
    assert wt.unmerged_dependency_branches(repo, {"B-1"}) == []
    assert wt.integrate(repo, {"B-2": "lane/B-2"}, items=items).ok


# ------------------------------------------------------------------- refuse_direct_commit (unit)

def test_guard_refuses_direct_commit_on_integration_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    with pytest.raises(wt.DirectCommitRefused):
        wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: INTEG})


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_guard_allows_when_allow_env_true(tmp_path, value):
    repo = make_repo(tmp_path / "repo")
    wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: INTEG, wt.ALLOW_ENV: value})


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "definitely"])
def test_guard_refuses_when_allow_env_is_not_true(tmp_path, value):
    # "0"/"false" must not admit just because the variable is set; a non-boolean fails closed.
    repo = make_repo(tmp_path / "repo")
    with pytest.raises(wt.DirectCommitRefused):
        wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: INTEG, wt.ALLOW_ENV: value})


def test_guard_allows_on_non_integration_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    _git(repo, "checkout", "-q", "-b", "item/B-1")
    wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: INTEG})  # no raise


def test_guard_reads_the_branch_name_from_the_environ_it_is_given(tmp_path):
    # os.environ names INTEG (the fixture); the environ passed in names another branch and wins.
    repo = make_repo(tmp_path / "repo")
    wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: "some/other-branch"})
    with pytest.raises(wt.DirectCommitRefused, match="integration/test"):
        wt.refuse_direct_commit(repo)                          # os.environ: refused


def test_guard_uses_git_config_when_the_environment_names_no_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    with pytest.raises(wt.WorktreeError, match="no integration branch configured"):
        wt.refuse_direct_commit(repo, environ={})
    _git(repo, "config", wt.INTEGRATION_BRANCH_GIT_CONFIG, INTEG)
    with pytest.raises(wt.DirectCommitRefused):
        wt.refuse_direct_commit(repo, environ={})


def test_guard_refuses_a_hand_merge_in_progress(tmp_path):
    # MERGE_HEAD is no exemption: concluding a merge by hand is a direct commit like any other.
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    _git(repo, "merge", "--no-commit", "--no-ff", "item/B-1")
    assert (repo / ".git" / "MERGE_HEAD").exists()
    with pytest.raises(wt.DirectCommitRefused, match="hand merge"):
        wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: INTEG})
    # The integrator's flag is what admits, merge or not.
    wt.refuse_direct_commit(repo, environ={wt.INTEGRATION_BRANCH_ENV: INTEG, wt.ALLOW_ENV: "1"})


def test_guard_allows_unborn_branch(tmp_path):
    root = tmp_path / "fresh"
    root.mkdir()
    _git(root, "init", "-q", "-b", INTEG)
    wt.refuse_direct_commit(root, environ={wt.INTEGRATION_BRANCH_ENV: INTEG})  # the first commit


# ------------------------------------------------------------------- the guard as a real git hook

def test_hook_refuses_a_hand_commit_on_the_integration_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    install_guard_hook(repo)
    cp = commit_with_hooks(repo)
    assert cp.returncode != 0
    assert "refusing a direct commit on the integration branch" in cp.stderr
    assert _head(repo) == base                                 # nothing landed


def test_hook_allows_a_hand_commit_on_an_item_branch(tmp_path):
    repo = make_repo(tmp_path / "repo")
    install_guard_hook(repo)
    _git(repo, "checkout", "-q", "-b", "item/B-1")
    before = _head(repo)
    cp = commit_with_hooks(repo)
    assert cp.returncode == 0, cp.stderr
    assert _parents(repo) == [before]


def test_hook_refuses_concluding_a_hand_merge_with_an_edit_staged_alongside(tmp_path):
    # `git merge --no-commit`, edit an unrelated tracked file, `git commit`: a direct edit riding
    # in on a merge commit. pre-commit runs for that commit and the guard refuses it.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_guard_hook(repo)
    assert hand_git(repo, "merge", "--no-commit", "--no-ff", "item/B-1").returncode == 0
    (repo / "base.txt").write_text("edited by hand during the merge\n")
    assert hand_git(repo, "add", "-A").returncode == 0
    cp = hand_git(repo, "commit", "-m", "hand merge plus an edit")
    assert cp.returncode != 0
    assert "refusing a direct commit on the integration branch" in cp.stderr
    assert _head(repo) == base                                 # nothing landed


def test_pre_merge_commit_hook_refuses_a_clean_hand_merge(tmp_path):
    # A clean `git merge --no-ff` never runs pre-commit; pre-merge-commit is the hook git runs.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_guard_hooks(repo)
    cp = hand_git(repo, "merge", "--no-ff", "--no-edit", "item/B-1")
    assert cp.returncode != 0
    assert "refusing a direct commit on the integration branch" in cp.stderr
    assert _head(repo) == base
    # git leaves the merge open; concluding it by hand is refused as well (pre-commit).
    assert hand_git(repo, "commit", "--no-edit").returncode != 0
    assert _head(repo) == base


def test_hook_admits_the_integrators_own_commits(tmp_path, monkeypatch):
    # The integration branch comes from git config here (what a hook in every worktree would read).
    # The guard is wired as pre-commit and pre-merge-commit: the integrator's merge goes through
    # the second, and the regenerate step forces its amend through the first.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    monkeypatch.delenv(wt.INTEGRATION_BRANCH_ENV)
    _git(repo, "config", wt.INTEGRATION_BRANCH_GIT_CONFIG, INTEG)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_guard_hooks(repo)

    def regen(top: Path) -> None:
        (top / "GENERATED.txt").write_text("regen\n")

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=regen)
    assert [s.status for s in res.steps] == ["merged"], res.steps
    assert _git(repo, "show", "HEAD:GENERATED.txt").strip() == "regen"
    assert _parents(repo) == [base, _tip(repo, "item/B-1")]
    # The same hooks still refuse a hand commit afterwards: the allow flag did not leak.
    after = _head(repo)
    assert commit_with_hooks(repo).returncode != 0
    assert _head(repo) == after


def test_integrators_merge_passes_the_guard_without_a_regenerate_step(tmp_path):
    # No regenerate, so no amend: the only commit is the merge itself, through pre-merge-commit.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_guard_hooks(repo)
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"))
    assert [s.status for s in res.steps] == ["merged"], res.steps
    assert _parents(repo) == [base, _tip(repo, "item/B-1")]


def test_integrate_reports_a_fold_commit_the_hook_refuses(tmp_path):
    # A pre-commit hook that refuses everything (a secret scan that fires, say): the regenerated
    # files cannot be committed, so the step fails and the merge is rolled back.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    install_hook(repo, "pre-commit", "echo 'scan: blocked' >&2; exit 1")

    def regen(top: Path) -> None:
        (top / "base.txt").write_text("regenerated\n")

    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), regenerate=regen)
    assert res.steps[0].status == "regen-failed"
    assert "scan: blocked" in res.steps[0].detail
    assert _head(repo) == base and wt.is_clean(repo)


# ------------------------------------------------------------------- production step wiring

def stub_python(tmp_path: Path, *, fail_on: str = "", exit_code: int = 3, say: str = "") -> tuple[Path, Path]:
    """A stand-in interpreter: appends "<cwd>|<argv>" to a log, prints `say`, and exits `exit_code`
    when its arguments contain `fail_on` (else 0). Returns (stub, log)."""
    log = tmp_path / "stub.log"
    stub = tmp_path / "stub-python"
    lines = ["#!/bin/sh", f'printf \'%s|%s\\n\' "$PWD" "$*" >> "{log}"']
    if say:
        lines.append(f"echo '{say}'")
    if fail_on:
        lines.append(f'case "$*" in *"{fail_on}"*) echo "stub: boom" >&2; exit {exit_code};; esac')
    lines.append("exit 0")
    stub.write_text("\n".join(lines) + "\n")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub, log


def logged(log: Path) -> list[tuple[str, str]]:
    out = []
    for line in log.read_text().splitlines():
        cwd, _, argv = line.partition("|")
        out.append((os.path.realpath(cwd), argv))
    return out


def make_event(repo: Path, slug: str, *, profile: bool = True) -> None:
    d = repo / "events" / slug
    d.mkdir(parents=True)
    if profile:
        (d / "event.toml").write_text(f'slug = "{slug}"\n')


def test_default_regenerate_runs_every_generator_in_the_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    make_event(repo, "alpha")
    make_event(repo, "beta")
    make_event(repo, "not-an-event", profile=False)            # no event.toml: nothing to regenerate
    stub, log = stub_python(tmp_path)
    wt.default_regenerate(repo, python=stub)
    here = os.path.realpath(repo)
    assert logged(log) == [
        (here, "tools/requirements_gen.py"),
        (here, "-m ctf engines generate"),
        (here, "-m ctf engines coverage --write"),
        (here, "-m ctf new-event alpha --regen"),
        (here, "-m ctf new-event beta --regen"),
    ]


def test_default_regenerate_failure_names_the_command_and_stops(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    stub, log = stub_python(tmp_path, fail_on="engines generate")
    with pytest.raises(wt.WorktreeError, match=r"-m ctf engines generate.*exit 3.*stub: boom"):
        wt.default_regenerate(repo, python=stub)
    assert [argv for _, argv in logged(log)] == ["tools/requirements_gen.py", "-m ctf engines generate"]


def test_default_gate_runs_the_gate_since_base_and_reports_its_last_line(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    stub, log = stub_python(tmp_path, say="GATE green files=3")
    assert wt.default_gate(repo, "abc123", python=stub) == (True, "GATE green files=3")
    assert logged(log) == [(os.path.realpath(repo), "-m ctf gate run --base abc123")]


def test_default_gate_red_exit_is_not_ok(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    stub, _ = stub_python(tmp_path, fail_on="gate run", exit_code=1, say="GATE red files=3")
    assert wt.default_gate(repo, "abc123", python=stub) == (False, "exit 1: GATE red files=3")


def test_resolve_python_uses_only_the_first_source_given(tmp_path, monkeypatch):
    stub, _ = stub_python(tmp_path)
    assert wt.resolve_python() == sys.executable               # nothing given: this interpreter
    monkeypatch.setenv(wt.PYTHON_ENV, str(stub))
    assert wt.resolve_python() == str(stub)
    assert wt.resolve_python(sys.executable) == sys.executable  # the argument beats the variable
    # An unusable source is an error naming it, never a reason to try the next one.
    monkeypatch.setenv(wt.PYTHON_ENV, str(tmp_path / "missing-python"))
    with pytest.raises(wt.WorktreeError, match=r"\$CTF_PYTHON.*missing-python"):
        wt.resolve_python()
    with pytest.raises(wt.WorktreeError, match="the python argument"):
        wt.resolve_python(tmp_path / "also-missing")
    not_executable = tmp_path / "plain-file"
    not_executable.write_text("#!/bin/sh\n")
    with pytest.raises(wt.WorktreeError, match="not an executable file"):
        wt.resolve_python(not_executable)


def test_integrate_with_default_gate_and_no_interpreter_fails_the_step_not_the_run(tmp_path, monkeypatch):
    # What a fresh worktree used to hit: the gate's interpreter is missing. That is a failed gate
    # with the merge rolled back, not a traceback with the merge left on the branch.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    monkeypatch.setenv(wt.PYTHON_ENV, str(tmp_path / "missing-python"))
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"), gate=wt.default_gate)
    assert res.steps[0].status == "gate-failed"
    assert "no usable interpreter" in res.steps[0].detail and "missing-python" in res.steps[0].detail
    assert _head(repo) == base and wt.is_clean(repo)


def test_integrate_with_default_steps_against_a_stub_interpreter(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"})
    stub, log = stub_python(tmp_path, say="GATE green")
    monkeypatch.setenv(wt.PYTHON_ENV, str(stub))
    res = wt.integrate(repo, queue("B-1"), items=flat("B-1"),
                       regenerate=wt.default_regenerate, gate=wt.default_gate)
    assert [s.status for s in res.steps] == ["merged"], res.steps
    assert [argv for _, argv in logged(log)] == [
        "tools/requirements_gen.py", "-m ctf engines generate", "-m ctf engines coverage --write",
        f"-m ctf gate run --base {base}"]


# ------------------------------------------------------------------------------- CLI

def _parser(module) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    module.add_arguments(p)
    return p


def test_cli_repo_flag_is_accepted_before_and_after_the_sub_command(tmp_path):
    for module, tail in ((cli_worktree, ["list"]), (cli_worktree, ["create", "B-9", "wt9"]),
                         (cli_integrate, ["guard"]), (cli_integrate, ["plan"]), (cli_integrate, ["run"])):
        p = _parser(module)
        assert p.parse_args([*tail, "--repo", str(tmp_path)]).repo == tmp_path
        assert p.parse_args(["--repo", str(tmp_path), *tail]).repo == tmp_path
        assert p.parse_args(tail).repo is None                 # absent: run() falls back to the cwd


def test_cli_worktree_create_and_list(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    args = _parser(cli_worktree).parse_args(["create", "B-9", str(tmp_path / "wt9"), "--repo", str(repo)])
    assert cli_worktree.run(args) == 0
    assert (tmp_path / "wt9" / "base.txt").exists()
    out = capsys.readouterr().out
    assert "item/B-9" in out

    args = _parser(cli_worktree).parse_args(["list", "--json", "--repo", str(repo)])
    assert cli_worktree.run(args) == 0
    assert "item/B-9" in capsys.readouterr().out


def test_cli_worktree_create_refuses_and_exits_2(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    _git(repo, "branch", "item/B-9")
    args = argparse.Namespace(repo=repo, action="create", branch="B-9",
                              path=tmp_path / "wt9", base="HEAD")
    assert cli_worktree.run(args) == 2
    assert "already exists" in capsys.readouterr().err


def items_file(tmp_path: Path, spec: dict[str, list[str]]) -> Path:
    import json
    f = tmp_path / "to_build.json"
    f.write_text(json.dumps([{"id": i, "category": "harness", "effort": "S", "dependencies": deps}
                             for i, deps in spec.items()]))
    return f


def run_args(repo: Path, items: Path, *flags: str) -> argparse.Namespace:
    return _parser(cli_integrate).parse_args(["run", "--repo", str(repo), "--items", str(items), *flags])


def test_cli_integrate_plan(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"a.txt": "1"})
    add_item_branch(repo, "B-2", {"b.txt": "2"})
    f = items_file(tmp_path, {"B-1": ["B-2"], "B-2": []})     # the dependent has the lower id
    args = _parser(cli_integrate).parse_args(["plan", "--repo", str(repo), "--items", str(f)])
    assert cli_integrate.run(args) == 0
    out = capsys.readouterr().out.splitlines()
    assert [line.split("\t") for line in out] == [["B-2", "item/B-2"], ["B-1", "item/B-1"]]


@pytest.mark.parametrize("action", ["plan", "run"])
def test_cli_integrate_empty_queue_exits_2(tmp_path, capsys, action):
    # No item/<id> branches and no --branches: nothing to do is a usage error, not a green run.
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    f = items_file(tmp_path, {"B-1": []})
    args = _parser(cli_integrate).parse_args([action, "--repo", str(repo), "--items", str(f)])
    assert cli_integrate.run(args) == 2
    cap = capsys.readouterr()
    assert "no item branches to merge" in cap.err and cap.out == ""
    assert _head(repo) == base


def test_cli_integrate_run_passes_the_prefix_to_the_dependency_hold(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"one.txt": "1"}, prefix="lane")
    add_item_branch(repo, "B-2", {"two.txt": "2"}, prefix="lane")
    f = items_file(tmp_path, {"B-1": [], "B-2": ["B-1"]})
    args = run_args(repo, f, "--no-regen", "--no-gate", "--prefix", "lane", "--branches", "B-2=lane/B-2")
    assert cli_integrate.run(args) == 1
    out = capsys.readouterr().out
    assert out.startswith("skipped") and "B-1 (lane/B-1)" in out and "ok=False" in out
    assert _head(repo) == base


def test_contracts_lists_the_env_names_the_integrator_reads():
    # They are read through constants, so the CONTRACTS doc test (which looks for literals) cannot
    # see them: check the section 3 list here.
    doc = (paths.repo_root() / "docs" / "CONTRACTS.md").read_text()
    section3 = doc[doc.index("\n## 3. Environment"):doc.index("\n## 4. ")]
    for name in (wt.INTEGRATION_BRANCH_ENV, wt.ALLOW_ENV, wt.PYTHON_ENV):
        assert f"`{name}`" in section3, name
    listed, _, outside = section3.partition("Read outside `ctf.env`")
    assert f"`{wt.PYTHON_ENV}`" in listed                      # read through ctf.env too, not only outside


def test_cli_integrate_guard_exit_codes(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    args = _parser(cli_integrate).parse_args(["guard", "--repo", str(repo)])
    assert cli_integrate.run(args) == 2                        # on the integration branch: refused
    assert "refusing a direct commit" in capsys.readouterr().err
    monkeypatch.setenv(wt.ALLOW_ENV, "1")
    assert cli_integrate.run(args) == 0                        # the integrator's flag admits
    monkeypatch.delenv(wt.ALLOW_ENV)
    _git(repo, "checkout", "-q", "-b", "item/B-1")
    assert cli_integrate.run(args) == 0                        # an item branch: allowed
    monkeypatch.delenv(wt.INTEGRATION_BRANCH_ENV)
    assert cli_integrate.run(args) == 2                        # nothing names the branch: loud
    assert "no integration branch configured" in capsys.readouterr().err
    named = _parser(cli_integrate).parse_args(["guard", "--repo", str(repo), "--integration-branch", INTEG])
    assert cli_integrate.run(named) == 0


def test_cli_integrate_run_end_to_end(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo")
    add_item_branch(repo, "B-1", {"a.txt": "1"})
    add_item_branch(repo, "B-2", {"b.txt": "2"})
    f = items_file(tmp_path, {"B-1": [], "B-2": ["B-1"]})
    assert cli_integrate.run(run_args(repo, f, "--no-regen", "--no-gate")) == 0
    assert (repo / "a.txt").exists() and (repo / "b.txt").exists()
    out = capsys.readouterr().out
    assert out.count("merged") >= 2 and "merged=2 failed=0 halted=False ok=True" in out


def test_cli_integrate_run_wires_the_default_regenerate_and_gate(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    f = items_file(tmp_path, {"B-1": [], "B-2": [], "B-3": []})
    calls: list[tuple] = []
    monkeypatch.setattr(wt, "default_regenerate", lambda top: calls.append(("regen", Path(top).resolve())))

    def fake_gate(top, gate_base):
        calls.append(("gate", Path(top).resolve(), gate_base))
        return True, "green"

    monkeypatch.setattr(wt, "default_gate", fake_gate)
    here = repo.resolve()

    add_item_branch(repo, "B-1", {"a.txt": "1"})
    assert cli_integrate.run(run_args(repo, f, "--branches", "B-1=item/B-1")) == 0
    assert calls == [("regen", here), ("gate", here, base)]    # both steps, regenerate first

    calls.clear()
    add_item_branch(repo, "B-2", {"b.txt": "2"})
    assert cli_integrate.run(run_args(repo, f, "--branches", "B-2=item/B-2", "--no-gate")) == 0
    assert calls == [("regen", here)]

    calls.clear()
    after_two = _head(repo)
    add_item_branch(repo, "B-3", {"c.txt": "3"})
    assert cli_integrate.run(run_args(repo, f, "--branches", "B-3=item/B-3", "--no-regen")) == 0
    assert calls == [("gate", here, after_two)]


def test_cli_integrate_run_red_default_gate_exits_1_and_rolls_back(tmp_path, capsys, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    base = _head(repo)
    add_item_branch(repo, "B-1", {"a.txt": "1"})
    f = items_file(tmp_path, {"B-1": []})
    monkeypatch.setattr(wt, "default_gate", lambda top, gate_base: (False, "GATE red"))
    assert cli_integrate.run(run_args(repo, f, "--no-regen")) == 1
    out = capsys.readouterr().out
    assert "gate-failed" in out and "GATE red" in out and "ok=False" in out
    assert _head(repo) == base


def test_cli_integrate_keep_going_flag(tmp_path, capsys):
    def build(root: Path) -> tuple[Path, Path]:
        repo = make_repo(root / "repo")
        add_item_branch(repo, "B-1", {"SHARED.txt": "one\n"})
        add_item_branch(repo, "B-2", {"SHARED.txt": "two\n"})  # conflicts once B-1 is in
        add_item_branch(repo, "B-3", {"three.txt": "3"})       # independent
        add_item_branch(repo, "B-4", {"four.txt": "4"})        # needs B-2
        root.mkdir(exist_ok=True)
        return repo, items_file(root, {"B-1": [], "B-2": [], "B-3": [], "B-4": ["B-2"]})

    def statuses(out: str) -> dict[str, str]:
        rows = [line.split() for line in out.splitlines() if not line.startswith("INTEGRATE")]
        return {r[1]: r[0] for r in rows}

    # Without the flag the first failure halts the queue: B-3 is not tried.
    repo, f = build(tmp_path / "stop")
    assert cli_integrate.run(run_args(repo, f, "--no-regen", "--no-gate")) == 1
    assert statuses(capsys.readouterr().out) == {
        "B-1": "merged", "B-2": "conflict", "B-3": "skipped", "B-4": "skipped"}
    assert not (repo / "three.txt").exists()

    # With it the independent item still merges and the dependent one is skipped.
    repo, f = build(tmp_path / "go")
    assert cli_integrate.run(run_args(repo, f, "--no-regen", "--no-gate", "--keep-going")) == 1
    assert statuses(capsys.readouterr().out) == {
        "B-1": "merged", "B-2": "conflict", "B-3": "merged", "B-4": "skipped"}
    assert (repo / "three.txt").exists() and not (repo / "four.txt").exists()
