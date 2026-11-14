"""B-038: post-event promotion loop and the fold-audit gate, against a synthetic master and event fork
built in a temp dir (git only; nothing from a real event)."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import buildplan as bp
from ctf import event, foldaudit, ledger, paths
from ctf import promote as pr
from ctf.promote import PromoteError

pytestmark = pytest.mark.needs_tool("git")

UTC = dt.timezone.utc
SLUG = "demo"


@pytest.fixture(autouse=True)
def _git_env(tmp_path, monkeypatch):
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[init]\n\tdefaultBranch = main\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for k in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{k}_NAME", "Test")
        monkeypatch.setenv(f"GIT_{k}_EMAIL", "test@example.invalid")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))


def g(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def commit(repo: Path, msg: str = "c") -> str:
    g(repo, "add", "-A")
    g(repo, "commit", "-q", "-m", msg)
    return g(repo, "rev-parse", "HEAD")


MANIFEST = """id = "{lane}.{name}"
lane = "{lane}"
entry = "solvers.{lane}.{name}:solve"
capabilities = ["executes"]
cost_class = "cheap"
status = "experimental"

[[routes]]
category = ["crypto"]
keywords = ["rsa"]
priority = 40
"""


@pytest.fixture
def world(tmp_path):
    """A master with a start tag, and an event fork cloned from it."""
    master = tmp_path / "master"
    master.mkdir()
    g(master, "init", "-q")
    write(master, "tools/unpack.py", "def unpack():\n    return 1\n")
    write(master, "tools/old.py", "OLD = 1\n")
    write(master, "solvers/common/rsa.py", "def solve():\n    pass\n")
    write(master, ".gitignore", "*.log\n")
    write(master, f"events/{SLUG}/README", "profile goes here\n")
    base = commit(master, "base")
    g(master, "tag", "-a", pr.start_tag(SLUG), "-m", "start")
    fork = tmp_path / "fork"
    subprocess.run(["git", "clone", "-q", str(master), str(fork)], check=True, capture_output=True)
    return master, fork, base


def make_event_changes(fork: Path) -> None:
    write(fork, "tools/unpack.py", "def unpack():\n    return 2  # committed live fix\n")
    commit(fork, "live fix")
    write(fork, "solvers/common/rsa.py", "def solve():\n    return 'fixed'\n")      # uncommitted
    write(fork, "solve_ww.py", "print('event script')\n")                          # untracked
    write(fork, "challenges/7-baby/out.bin", "data")                               # untracked data
    (fork / "tools/old.py").unlink()                                               # deleted
    write(fork, "run.log", "ignored by .gitignore\n")
    write(fork, ".ctf/session.json", "never read\n")


def inv(master, fork=None, ws=None, **kw):
    return pr.inventory(SLUG, master=master, fork=fork, workspace=ws, log=False, **kw)


# ------------------------------------------------------------------------------------- inventory

def test_inventory_lists_every_live_change_with_its_state(world):
    master, fork, base = world
    make_event_changes(fork)
    rec = inv(master, fork)
    by = {e.path: e for e in rec.entries}
    assert set(by) == {"tools/unpack.py", "solvers/common/rsa.py", "solve_ww.py",
                       "challenges/7-baby/out.bin", "tools/old.py"}
    assert (by["tools/unpack.py"].change, by["tools/unpack.py"].state) == ("modified", "committed")
    assert (by["solvers/common/rsa.py"].change, by["solvers/common/rsa.py"].state) == ("modified", "uncommitted")
    assert (by["solve_ww.py"].change, by["solve_ww.py"].state) == ("added", "untracked")
    assert by["tools/old.py"].change == "deleted" and by["tools/old.py"].blob is None
    assert by["tools/unpack.py"].blob == g(fork, "hash-object", "tools/unpack.py")
    assert by["solve_ww.py"].blob == g(fork, "hash-object", "solve_ww.py")
    assert rec.base == base and rec.base_ref == "event/demo/start"
    assert rec.fork_head == g(fork, "rev-parse", "HEAD")
    assert len(rec.pending()) == 5


def test_committed_then_edited_again_is_uncommitted(world):
    master, fork, _ = world
    write(fork, "tools/unpack.py", "def unpack():\n    return 2\n")
    commit(fork, "live fix")
    write(fork, "tools/unpack.py", "def unpack():\n    return 3  # edited again, not committed\n")
    write(fork, "tools/kept.py", "K = 1\n")
    g(fork, "add", "tools/kept.py")
    g(fork, "commit", "-q", "-m", "kept")                              # committed and left alone
    write(fork, "tools/staged.py", "S = 1\n")
    g(fork, "add", "tools/staged.py")                                  # staged, never committed
    by = {e.path: e for e in inv(master, fork).entries}
    assert (by["tools/unpack.py"].change, by["tools/unpack.py"].state) == ("modified", "uncommitted")
    assert by["tools/unpack.py"].blob == g(fork, "hash-object", "tools/unpack.py")
    assert (by["tools/staged.py"].change, by["tools/staged.py"].state) == ("added", "uncommitted")
    assert (by["tools/kept.py"].change, by["tools/kept.py"].state) == ("added", "committed")


def test_inventory_proposes_engine_fold_and_drop(world, tmp_path):
    master, fork, _ = world
    make_event_changes(fork)
    write(fork, "tools/same.py", "X = 1\n")
    write(master, "tools/same.py", "X = 1\n")       # the master already has it
    commit(master, "same")
    write(fork, "solvers/web/sqli_probe.py", "def solve():\n    pass\n")
    ws = tmp_path / "ws"
    write(ws, "12-baby-rsa/solve.py", "print(1)\n")
    write(ws, "12-baby-rsa/files/chall.py", "attachment, not ours\n")
    write(ws, "12-baby-rsa/notes.md", "notes are not scripts\n")
    rec = inv(master, fork, ws)
    p = {e.key: e.proposal for e in rec.entries}
    assert p["fork:tools/unpack.py"]["action"] == "fold" and p["fork:tools/unpack.py"]["dest"] == ["tools/unpack.py"]
    assert p["fork:tools/same.py"]["action"] == "fold" and "already in the master" in p["fork:tools/same.py"]["why"]
    assert p["fork:challenges/7-baby/out.bin"]["action"] == "drop"
    assert p["fork:solve_ww.py"] == {
        "action": "engine", "module": "solvers/common/solve_ww.py",
        "manifest": "solvers/common/solve_ww.manifest.toml", "test": "tests/test_common_solve_ww.py",
        "why": p["fork:solve_ww.py"]["why"]}
    assert p["fork:solvers/web/sqli_probe.py"]["module"] == "solvers/web/sqli_probe.py"
    assert p["fork:solvers/web/sqli_probe.py"]["test"] == "tests/test_web_sqli_probe.py"
    assert p["workspace:12-baby-rsa/solve.py"]["module"] == "solvers/common/baby_rsa_solve.py"
    assert "workspace:12-baby-rsa/files/chall.py" not in p
    assert "workspace:12-baby-rsa/notes.md" not in p


def test_engine_name_qualifies_generic_stems():
    assert pr.engine_name("12-baby-rsa/solve.py") == "baby_rsa_solve"
    assert pr.engine_name("x/sa.py") == "x_sa"
    assert pr.engine_name("work/padding_oracle.py") == "padding_oracle"
    assert pr.engine_name("9lives.py") == "e_9lives"
    assert pr.engine_paths("metadata-forensics", "exif_walk")["test"] == "tests/test_metadata_forensics_exif_walk.py"
    with pytest.raises(PromoteError, match="bad lane"):
        pr.engine_paths("Bad Lane", "x")


def test_missing_start_tag_fails_naming_the_fix(tmp_path):
    master = tmp_path / "m"
    master.mkdir()
    g(master, "init", "-q")
    write(master, "a.py", "a\n")
    sha = commit(master)
    with pytest.raises(PromoteError, match=r"no tag event/demo/start.*--base"):
        inv(master, master)
    rec = inv(master, master, base=sha)
    assert rec.base == sha and rec.base_ref == sha and rec.entries == []
    with pytest.raises(PromoteError, match="not a commit"):
        inv(master, master, base="feedfacefeedface")


def test_fork_without_the_start_commit_is_refused(world, tmp_path):
    master, _, _ = world
    other = tmp_path / "other"
    other.mkdir()
    g(other, "init", "-q")
    write(other, "z.py", "z\n")
    commit(other)
    with pytest.raises(PromoteError, match="does not contain the start commit"):
        inv(master, other)


def test_nothing_to_inventory_and_not_a_repo(world, tmp_path):
    master, _, _ = world
    with pytest.raises(PromoteError, match="nothing to inventory"):
        inv(master)
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(PromoteError, match="not a git checkout"):
        inv(master, plain)


# ------------------------------------------------------------------------------------- decisions

def test_decision_validation(world, tmp_path):
    master, fork, _ = world
    make_event_changes(fork)
    ws = tmp_path / "ws"
    write(ws, "c/solve.py", "1\n")
    rec = inv(master, fork, ws)
    with pytest.raises(PromoteError, match="needs a reason"):
        pr.decide(rec, "solve_ww.py", {"action": "drop", "reason": "  "}, log=False)
    with pytest.raises(PromoteError, match="sidecar"):
        pr.decide(rec, "solve_ww.py", {"action": "engine", "module": "solvers/common/a.py",
                                       "manifest": "solvers/common/b.manifest.toml",
                                       "test": "tests/test_a.py"}, log=False)
    with pytest.raises(PromoteError, match="not under"):
        pr.decide(rec, "solve_ww.py", {"action": "engine", "module": "lib/a.py",
                                       "manifest": "lib/a.manifest.toml", "test": "tests/test_a.py"}, log=False)
    with pytest.raises(PromoteError, match="tests/"):
        pr.decide(rec, "solve_ww.py", {"action": "engine", "module": "solvers/common/a.py",
                                       "manifest": "solvers/common/a.manifest.toml", "test": "a_test.py"}, log=False)
    with pytest.raises(PromoteError, match="needs dest"):
        pr.decide(rec, "workspace:c/solve.py", {"action": "fold"}, log=False)
    with pytest.raises(PromoteError, match="relative"):
        pr.decide(rec, "tools/unpack.py", {"action": "fold", "dest": ["../x.py"]}, log=False)
    with pytest.raises(PromoteError, match="unknown key"):
        pr.decide(rec, "tools/unpack.py", {"action": "fold", "colour": "red"}, log=False)
    with pytest.raises(PromoteError, match="not one of"):
        pr.decide(rec, "tools/unpack.py", {"action": "keep"}, log=False)
    with pytest.raises(PromoteError, match="not in the master"):
        pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": "abcdef1"}, master=master, log=False)
    with pytest.raises(PromoteError, match="no inventoried entry"):
        pr.decide(rec, "nope.py", {"action": "drop", "reason": "x"}, log=False)
    assert rec.pending() == rec.entries        # nothing was recorded by a refused decision
    e = pr.decide(rec, "tools/unpack.py", {"action": "fold"}, log=False)
    assert e.decision["dest"] == ["tools/unpack.py"] and "decided" in e.decision
    # the start commit itself (master HEAD before any fold) cannot have folded an event's change
    with pytest.raises(PromoteError, match="at or before the event's start commit"):
        pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": g(master, "rev-parse", "HEAD")},
                  master=master, log=False)
    write(master, "tools/other.py", "O = 1\n")
    other = commit(master, "unrelated")
    with pytest.raises(PromoteError, match="does not change tools/unpack.py"):
        pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": other}, master=master, log=False)
    assert rec.get("tools/unpack.py").decision.get("commit") is None   # refusals recorded nothing
    write(master, "tools/unpack.py", "def unpack():\n    return 2  # adapted\n")
    commit(master, "fold")
    short = g(master, "rev-parse", "--short", "HEAD")
    e = pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": short}, master=master, log=False)
    assert e.decision["commit"] == g(master, "rev-parse", "HEAD")


def test_record_round_trip_and_strict_load(world):
    master, fork, _ = world
    make_event_changes(fork)
    rec = inv(master, fork)
    pr.decide(rec, "solve_ww.py", {"action": "drop", "reason": "one-off"}, log=False)
    p = pr.save_record(rec, master)
    assert p == master / "events" / SLUG / "promotion.json"
    back = pr.load_record(SLUG, master)
    assert back.to_json() == rec.to_json()
    data = json.loads(p.read_text())
    data["entries"][0]["extra"] = 1
    p.write_text(json.dumps(data))
    with pytest.raises(PromoteError, match="unknown key"):
        pr.load_record(SLUG, master)
    data["entries"][0].pop("extra")
    data["schema"] = 2
    p.write_text(json.dumps(data))
    with pytest.raises(PromoteError, match="schema"):
        pr.load_record(SLUG, master)
    data["schema"] = 1
    data["entries"][0]["decision"] = {"action": "drop"}
    p.write_text(json.dumps(data))
    with pytest.raises(PromoteError, match="needs a reason"):
        pr.load_record(SLUG, master)
    with pytest.raises(PromoteError, match="no promotion record"):
        pr.load_record("other", master)
    data["entries"][0]["decision"] = None
    p.write_text(json.dumps(data))
    with pytest.raises(PromoteError, match="not 'other'"):
        pr.load_record("other", master, p)


def test_reinventory_keeps_decisions_for_unchanged_content_only(world):
    master, fork, _ = world
    make_event_changes(fork)
    rec = inv(master, fork)
    pr.decide(rec, "solve_ww.py", {"action": "drop", "reason": "one-off"}, log=False)
    pr.decide(rec, "solvers/common/rsa.py", {"action": "fold"}, log=False)
    pr.decide(rec, "challenges/7-baby/out.bin", {"action": "drop", "reason": "data"}, log=False)
    write(fork, "solvers/common/rsa.py", "def solve():\n    return 'fixed again'\n")
    (fork / "challenges/7-baby/out.bin").unlink()
    rec2 = inv(master, fork, previous=rec)
    assert rec2.get("solve_ww.py").decision["action"] == "drop"
    assert rec2.get("solvers/common/rsa.py").decision is None          # content changed: decide again
    gone = rec2.get("challenges/7-baby/out.bin")
    assert gone.stale and gone.decision["reason"] == "data"
    with pytest.raises(PromoteError, match="not 'demo'"):
        pr.inventory(SLUG, master=master, fork=fork, log=False,
                     previous=pr.Record("other", "x", "x", None, "t"))


def test_accept_takes_proposals(world):
    master, fork, _ = world
    make_event_changes(fork)
    rec = inv(master, fork)
    done = pr.accept(rec, ["solve_ww.py"], log=False)
    assert done[0].decision["module"] == "solvers/common/solve_ww.py" and "why" not in done[0].decision
    pr.accept(rec, None, log=False)
    assert rec.pending() == []


# ------------------------------------------------------------------------------------------ audit

def decided_world(world):
    master, fork, _ = world
    make_event_changes(fork)
    rec = inv(master, fork)
    pr.decide(rec, "tools/unpack.py", {"action": "fold"}, log=False)
    pr.decide(rec, "solvers/common/rsa.py", {"action": "fold"}, log=False)
    pr.decide(rec, "tools/old.py", {"action": "fold"}, log=False)
    pr.decide(rec, "challenges/7-baby/out.bin", {"action": "drop", "reason": "challenge data"}, log=False)
    pr.accept(rec, ["solve_ww.py"], log=False)
    pr.save_record(rec, master)
    commit(master, "record")
    return master, fork, rec


def verdicts(res):
    return {f.key: f.verdict for f in res.findings}


def fold_everything(master: Path, fork: Path) -> str:
    for rel in ("tools/unpack.py", "solvers/common/rsa.py"):
        write(master, rel, (fork / rel).read_text())
    (master / "tools/old.py").unlink()
    write(master, "solvers/common/solve_ww.py", "def solve(challenge_dir, profile, **opts):\n    pass\n")
    write(master, "solvers/common/solve_ww.manifest.toml", MANIFEST.format(lane="common", name="solve_ww"))
    write(master, "tests/test_common_solve_ww.py",
          "from solvers.common import solve_ww\n\ndef test_it():\n    assert solve_ww.solve\n")
    return commit(master, "fold the event")


def test_undecided_fails_and_drop_passes(world):
    master, fork, _ = world
    make_event_changes(fork)
    rec = inv(master, fork)
    pr.decide(rec, "challenges/7-baby/out.bin", {"action": "drop", "reason": "data"}, log=False)
    pr.save_record(rec, master)
    res = foldaudit.audit(SLUG, master=master, log=False)
    v = verdicts(res)
    assert v["fork:challenges/7-baby/out.bin"] == "pass"
    assert v["fork:tools/unpack.py"] == "fail" and not res.passed
    assert "undecided" in {f.key: f.reason for f in res.findings}["fork:tools/unpack.py"]


def test_audit_fails_until_every_fix_reaches_the_target_then_passes(world):
    master, fork, _ = decided_world(world)
    before = foldaudit.audit(SLUG, master=master, log=False)
    v = verdicts(before)
    assert v == {"fork:tools/unpack.py": "fail", "fork:solvers/common/rsa.py": "fail",
                 "fork:tools/old.py": "fail", "fork:challenges/7-baby/out.bin": "pass",
                 "fork:solve_ww.py": "fail"}
    reasons = {f.key: f.reason for f in before.findings}
    assert "still in the target" in reasons["fork:tools/old.py"]
    assert "engine not in the target" in reasons["fork:solve_ww.py"]
    folded = fold_everything(master, fork)
    after = foldaudit.audit(SLUG, master=master, log=False)
    assert after.passed, foldaudit.render(after)
    assert after.target_commit == folded
    # the gate is about the commit the next event starts from: an older target still fails
    old = foldaudit.audit(SLUG, master=master, target="event/demo/start", log=False)
    assert not old.passed


def test_partial_fold_fails_naming_the_missing_fix(world):
    master, fork, _ = decided_world(world)
    fold_everything(master, fork)
    write(master, "solvers/common/rsa.py", "def solve():\n    pass  # reverted\n")
    commit(master, "revert")
    res = foldaudit.audit(SLUG, master=master, log=False)
    assert [f.key for f in res.failures()] == ["fork:solvers/common/rsa.py"]
    assert "differs" in res.failures()[0].reason


def test_fold_by_commit_must_be_in_target_history(world):
    master, fork, rec = decided_world(world)
    record_commit = g(master, "rev-parse", "HEAD")
    # adapted, not copied: the master's content differs from the fork's
    write(master, "tools/unpack.py", "def unpack():\n    return 2  # folded with a test\n")
    adapted = commit(master, "adapted fold")
    rec = pr.load_record(SLUG, master)
    assert verdicts(foldaudit.audit(SLUG, master=master, log=False))["fork:tools/unpack.py"] == "fail"
    pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": adapted}, master=master, log=False)
    pr.save_record(rec, master)
    commit(master, "record")
    res = foldaudit.audit(SLUG, master=master, log=False)
    assert verdicts(res)["fork:tools/unpack.py"] == "pass"
    # the same decision against a target that does not contain the folding commit fails
    g(master, "branch", "side", record_commit)
    res = foldaudit.audit(SLUG, master=master, target="side", log=False)
    reasons = {f.key: f.reason for f in res.failures()}
    assert "not in the history of the target" in reasons["fork:tools/unpack.py"]


def test_fold_by_commit_still_needs_the_dest(world):
    master, fork, rec = decided_world(world)
    fold_everything(master, fork)
    write(master, "tools/unpack.py", "def unpack():\n    return 2  # adapted\n")
    sha = commit(master, "adapted")
    rec = pr.load_record(SLUG, master)
    pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": sha,
                                       "dest": ["tools/unpack.py", "tools/unpack2.py"]},
              master=master, log=False)
    pr.save_record(rec, master)
    commit(master, "record")
    res = foldaudit.audit(SLUG, master=master, log=False)
    assert {f.key: f.reason for f in res.failures()}["fork:tools/unpack.py"].endswith("tools/unpack2.py")


def _force_decision(master: Path, key: str, decision: dict) -> None:
    """Write a decision straight into the committed record, the way a hand edit or a stale
    `--commit HEAD` would, past decide()'s own checks: the gate must not trust the record."""
    rec = pr.load_record(SLUG, master)
    rec.get(key).decision = decision
    pr.save_record(rec, master)
    commit(master, "record edited")


def test_fold_commit_must_come_after_the_start_and_change_the_dest(world):
    master, fork, rec = decided_world(world)
    base, record_commit = rec.base, g(master, "rev-parse", "HEAD")    # record_commit changes only the record
    for c, why in ((base, "at or before the event's start commit"),
                   (record_commit, "does not change tools/unpack.py")):
        _force_decision(master, "tools/unpack.py", {"action": "fold", "dest": ["tools/unpack.py"], "commit": c})
        res = foldaudit.audit(SLUG, master=master, log=False)
        reason = {f.key: f.reason for f in res.findings}["fork:tools/unpack.py"]
        assert verdicts(res)["fork:tools/unpack.py"] == "fail" and why in reason, reason
    # the same holds for an engine decision naming the start commit
    _force_decision(master, "solve_ww.py", {"action": "engine", "module": "solvers/common/solve_ww.py",
                                            "manifest": "solvers/common/solve_ww.manifest.toml",
                                            "test": "tests/test_common_solve_ww.py", "commit": base})
    folded = fold_everything(master, fork)
    reasons = {f.key: f.reason for f in foldaudit.audit(SLUG, master=master, log=False).failures()}
    assert "at or before the event's start commit" in reasons["fork:solve_ww.py"]
    engine = {"action": "engine", "module": "solvers/common/solve_ww.py",
              "manifest": "solvers/common/solve_ww.manifest.toml", "test": "tests/test_common_solve_ww.py"}
    _force_decision(master, "solve_ww.py", {**engine, "commit": record_commit})
    reasons = {f.key: f.reason for f in foldaudit.audit(SLUG, master=master, log=False).failures()}
    assert "does not change solvers/common/solve_ww.py" in reasons["fork:solve_ww.py"]
    # the commit that wrote the engine is accepted
    _force_decision(master, "solve_ww.py", {**engine, "commit": folded})
    assert verdicts(foldaudit.audit(SLUG, master=master, log=False))["fork:solve_ww.py"] == "pass"


def test_fold_by_merge_commit_counts_what_it_brought_in(world):
    master, fork, _ = decided_world(world)
    g(master, "checkout", "-q", "-b", "fold")
    write(master, "tools/unpack.py", "def unpack():\n    return 2  # adapted on a branch\n")
    commit(master, "adapted")
    g(master, "checkout", "-q", "main")
    g(master, "merge", "-q", "--no-ff", "-m", "merge the fold", "fold")
    merge = g(master, "rev-parse", "HEAD")
    rec = pr.load_record(SLUG, master)
    pr.decide(rec, "tools/unpack.py", {"action": "fold", "commit": merge}, master=master, log=False)
    pr.save_record(rec, master)
    commit(master, "record")
    assert verdicts(foldaudit.audit(SLUG, master=master, log=False))["fork:tools/unpack.py"] == "pass"


def test_engine_decision_on_an_engine_that_predates_the_event_fails(world):
    master, fork, _ = world
    write(master, "solvers/common/rsa.manifest.toml", MANIFEST.format(lane="common", name="rsa"))
    write(master, "tests/test_common_rsa.py", "from solvers.common import rsa\n\ndef test_it():\n    assert rsa\n")
    start = commit(master, "rsa engine, before the event")
    g(fork, "pull", "-q", "--ff-only", "origin", "main")
    make_event_changes(fork)
    rec = inv(master, fork, base=start)
    pr.decide(rec, "solve_ww.py", {"action": "engine", "module": "solvers/common/rsa.py",
                                   "manifest": "solvers/common/rsa.manifest.toml",
                                   "test": "tests/test_common_rsa.py"}, log=False)
    pr.save_record(rec, master)
    commit(master, "record")
    reason = {f.key: f.reason for f in foldaudit.audit(SLUG, master=master, log=False).findings}["fork:solve_ww.py"]
    assert "unchanged since the event's start commit" in reason
    write(master, "solvers/common/rsa.py", "def solve(challenge_dir, profile, **opts):\n    return 'event'\n")
    commit(master, "the event's script reaches the engine")
    assert verdicts(foldaudit.audit(SLUG, master=master, log=False))["fork:solve_ww.py"] == "pass"


def test_a_start_commit_missing_from_the_master_fails_commit_and_engine_checks(world):
    master, fork, _ = world
    make_event_changes(fork)
    fork_only = g(fork, "rev-parse", "HEAD")              # the fork's live-fix commit: never in the master
    rec = inv(master, fork, base=fork_only)
    assert rec.base == fork_only
    pr.accept(rec, ["solve_ww.py"], log=False)
    fold_everything(master, fork)
    write(master, "solvers/common/rsa.py", "def solve():\n    return 'adapted'\n")
    adapted = commit(master, "adapted")
    rec.get("solvers/common/rsa.py").decision = {"action": "fold", "dest": ["solvers/common/rsa.py"],
                                                 "commit": adapted}
    pr.save_record(rec, master)
    commit(master, "record")
    reasons = {f.key: f.reason for f in foldaudit.audit(SLUG, master=master, log=False).failures()}
    for key in ("fork:solvers/common/rsa.py", "fork:solve_ww.py"):
        assert f"start commit {fork_only[:12]} is not in the master" in reasons[key], reasons


def test_audit_fails_until_the_record_is_committed_at_the_target(world, tmp_path):
    master, fork, _ = decided_world(world)
    fold_everything(master, fork)
    assert foldaudit.audit(SLUG, master=master, log=False).passed
    rec = pr.load_record(SLUG, master)
    pr.decide(rec, "solve_ww.py", {"action": "drop", "reason": "edited locally"}, log=False)
    pr.save_record(rec, master)                                        # not committed
    res = foldaudit.audit(SLUG, master=master, log=False)
    assert [f.key for f in res.failures()] == [f"record:events/{SLUG}/promotion.json"]
    assert "differs" in res.failures()[0].reason
    d = bp.check_build("B-1", _profile(), workdir=tmp_path, now=dt.datetime(2027, 3, 10, tzinfo=UTC),
                       master=master, log=False)
    assert not d.allowed and "record:" in d.reason
    commit(master, "record")
    assert foldaudit.audit(SLUG, master=master, log=False).passed
    g(master, "rm", "-q", "--cached", f"events/{SLUG}/promotion.json")
    g(master, "commit", "-q", "-m", "untrack the record")
    res = foldaudit.audit(SLUG, master=master, log=False)
    assert [f.key for f in res.failures()] == [f"record:events/{SLUG}/promotion.json"]
    assert "not committed at the target" in res.failures()[0].reason


@pytest.mark.parametrize("breakage, expect", [
    (("solvers/common/solve_ww.manifest.toml", 'id = "common.solve_ww"\nlane = "common"\n'), "invalid"),
    (("solvers/common/solve_ww.manifest.toml", MANIFEST.format(lane="common", name="other")), "entry runs"),
    (("tests/test_common_solve_ww.py", "def test_it():\n    assert True\n"), "never names"),
])
def test_engine_promotion_is_checked(world, breakage, expect):
    master, fork, _ = decided_world(world)
    fold_everything(master, fork)
    write(master, *breakage)
    commit(master, "break")
    res = foldaudit.audit(SLUG, master=master, log=False)
    reasons = {f.key: f.reason for f in res.failures()}
    assert list(reasons) == ["fork:solve_ww.py"] and expect in reasons["fork:solve_ww.py"]


def test_audit_with_fork_fails_on_unrecorded_or_changed_fixes(world):
    master, fork, _ = decided_world(world)
    fold_everything(master, fork)
    assert foldaudit.audit(SLUG, master=master, fork=fork, log=False).passed
    write(fork, "tools/late_fix.py", "LATE = 1\n")
    write(fork, "tools/unpack.py", "def unpack():\n    return 3  # changed after the record\n")
    res = foldaudit.audit(SLUG, master=master, fork=fork, log=False)
    reasons = {f.key: f.reason for f in res.failures()}
    assert "not in the record" in reasons["fork:tools/late_fix.py"]
    assert "changed after it was recorded" in reasons["fork:tools/unpack.py"]


def test_audit_with_fork_fails_when_the_record_misstates_the_change(world):
    master, fork, _ = decided_world(world)
    fold_everything(master, fork)
    p = pr.record_path(SLUG, master)
    data = json.loads(p.read_text())
    for e in data["entries"]:
        if e["path"] == "tools/unpack.py":
            e["change"] = "added"            # same content, wrong kind: the master had this file
    p.write_text(json.dumps(data))
    commit(master, "record edited")
    assert foldaudit.audit(SLUG, master=master, log=False).passed      # the entry itself is folded
    res = foldaudit.audit(SLUG, master=master, fork=fork, log=False)
    assert [f.key for f in res.failures()] == ["fork:tools/unpack.py"]
    assert "changed after it was recorded" in res.failures()[0].reason


def test_audit_with_workspace_finds_new_scripts(world, tmp_path):
    master, fork, _ = world
    ws = tmp_path / "ws"
    write(ws, "3-x/solve.py", "1\n")
    rec = inv(master, None, ws)
    pr.decide(rec, "3-x/solve.py", {"action": "drop", "reason": "one-off"}, log=False)
    pr.save_record(rec, master)
    commit(master, "record")
    assert foldaudit.audit(SLUG, master=master, workspace=ws, log=False).passed
    write(ws, "3-x/solve2.py", "2\n")
    res = foldaudit.audit(SLUG, master=master, workspace=ws, log=False)
    assert [f.key for f in res.failures()] == ["workspace:3-x/solve2.py"]


def test_audit_errors_are_loud(world):
    master, _, _ = world
    with pytest.raises(PromoteError, match="no promotion record"):
        foldaudit.audit(SLUG, master=master, log=False)
    pr.save_record(pr.Record(SLUG, "x", "x", None, "t"), master)
    with pytest.raises(PromoteError, match="not a commit"):
        foldaudit.audit(SLUG, master=master, target="no-such-ref", log=False)


def test_audit_logs_to_the_ledger(world):
    master, fork, _ = decided_world(world)
    res = foldaudit.audit(SLUG, master=master)
    recs = [r for r in ledger.read(paths.workdir(SLUG)) if r["event"] == "fold_audit.check"]
    assert len(recs) == 1 and recs[0]["passed"] is False and recs[0]["failures"] == len(res.failures())


# ---------------------------------------------------------------------- next event start + build gate

PROFILE = """slug = "{slug}"
name = "X"
dates = {{ start = {start}, end = {end} }}
[platform]
kind = "manual"
[flag]
prefixes = []
[rules]
submit_mode = "manual"
flag_sharing = "forbidden"
ai_on_platform = "allowed"
"""


def test_start_tag_for_the_next_event_is_refused_while_a_fix_is_unfolded(world):
    master, fork, _ = decided_world(world)
    with pytest.raises(foldaudit.FoldAuditFailed, match="demo"):
        pr.tag_start("next", master=master, log=False)
    assert pr.commit_of(master, "refs/tags/event/next/start") is None
    sha = fold_everything(master, fork)
    got, results = pr.tag_start("next", master=master, log=False)
    assert got == sha and [r.event for r in results] == ["demo"] and results[0].passed
    assert g(master, "rev-parse", "event/next/start^{commit}") == sha
    with pytest.raises(PromoteError, match="already exists"):
        pr.tag_start("next", master=master, log=False)


def test_audit_all_requires_a_record_for_every_started_event_that_ended(world):
    master, _, _ = world
    g(master, "tag", "-a", "event/live/start", "-m", "s")
    g(master, "tag", "-a", "event/past/start", "-m", "s")
    now = dt.datetime(2027, 6, 1, tzinfo=UTC)
    write(master, "events/live/event.toml", PROFILE.format(slug="live", start="2027-05-30", end="2027-06-02"))
    write(master, "events/past/event.toml", PROFILE.format(slug="past", start="2027-05-01", end="2027-05-02"))
    commit(master, "profiles")
    res = {r.event: r for r in foldaudit.audit_all(master=master, now=now, exclude={"demo"}, log=False)}
    assert res["live"].passed and "still running" in res["live"].note
    assert not res["past"].passed and "no promotion record" in res["past"].findings[0].reason
    # demo has a start tag too and no record: it fails when not excluded
    res = {r.event: r for r in foldaudit.audit_all(master=master, now=now, log=False)}
    assert not res["demo"].passed


def _profile(slug=SLUG):
    return event.parse({
        "slug": slug, "name": "Demo",
        "dates": {"start": dt.date(2027, 3, 1), "end": dt.date(2027, 3, 2)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
    })


def test_build_gate_post_event_follows_the_fold_audit(world, tmp_path):
    master, fork, _ = decided_world(world)
    after = dt.datetime(2027, 3, 10, tzinfo=UTC)
    d = bp.check_build("B-1", _profile(), workdir=tmp_path, now=after, master=master)
    assert not d.allowed and d.phase == "post-event" and "fold-audit fails" in d.reason
    fold_everything(master, fork)
    d = bp.check_build("B-1", _profile(), workdir=tmp_path, now=after, master=master)
    assert d.allowed and "fold-audit passed" in d.reason
    recs = [r for r in ledger.read(tmp_path) if r["event"] == "build_plan.check"]
    assert [r["allowed"] for r in recs] == [False, True]


# --------------------------------------------------------------------------------------------- CLI

def cli(*args):
    return subprocess.run([sys.executable, "-m", "ctf", *args], capture_output=True, text=True,
                          cwd=str(paths.repo_root()), env=os.environ.copy(), timeout=120)


def test_cli_loop_end_to_end(world, tmp_path):
    master, fork, _ = world
    make_event_changes(fork)
    ws = tmp_path / "ws"
    write(ws, "5-crib/solve.py", "print(1)\n")
    m = ["--master", str(master)]
    r = cli("fold-audit", SLUG, *m)
    assert r.returncode == 2 and "no promotion record" in r.stderr
    r = cli("promote", "inventory", SLUG, "--fork", str(fork), "--workspace", str(ws), *m)
    assert r.returncode == 0, r.stderr
    assert "fork:tools/unpack.py" in r.stdout and "6 entries, 6 undecided" in r.stdout
    r = cli("fold-audit", SLUG, *m)
    assert r.returncode == 1 and "FOLD_AUDIT result=fail" in r.stdout and "undecided" in r.stdout
    r = cli("promote", "decide", SLUG, "workspace:5-crib/solve.py", "--drop", *m)
    assert r.returncode == 2 and "needs a reason" in r.stderr
    assert cli("promote", "decide", SLUG, "workspace:5-crib/solve.py", "--drop", "--reason", "one-off", *m).returncode == 0
    r = cli("promote", "decide", SLUG, "solve_ww.py", "--engine", "--lane", "common", "--name", "solve_ww", *m)
    assert r.returncode == 0, r.stderr
    assert cli("promote", "decide", SLUG, "challenges/7-baby/out.bin", "--drop", "--reason", "data", *m).returncode == 0
    r = cli("promote", "accept", SLUG, "--all", *m)
    assert r.returncode == 0 and "0 undecided" in r.stdout
    r = cli("promote", "show", SLUG, "--json", *m)
    data = json.loads(r.stdout)
    assert {e["path"]: e["decision"]["action"] for e in data["entries"]}["solve_ww.py"] == "engine"
    commit(master, "record")
    r = cli("promote", "start", "next", *m)
    assert r.returncode == 1 and "refused" in r.stderr
    fold_everything(master, fork)
    r = cli("fold-audit", SLUG, "--fork", str(fork), "--workspace", str(ws), "--json", *m)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)[0]["passed"] is True
    r = cli("fold-audit", "--all", *m)
    assert r.returncode == 0 and "FOLD_AUDIT result=pass events=1" in r.stdout
    r = cli("promote", "start", "next", *m)
    assert r.returncode == 0 and "tagged event/next/start" in r.stdout
    assert cli("fold-audit", *m).returncode == 2


# ------------------------------------------------------------------------------------ edge cases

def test_symlink_blob_matches_git_and_is_not_followed(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    g(repo, "init", "-q")
    write(repo, "target.txt", "the target's content\n")
    os.symlink("target.txt", repo / "link")
    g(repo, "add", "-A")
    staged = {line.split()[3]: line.split()[1] for line in g(repo, "ls-files", "-s").splitlines()}
    assert pr.blob_id(repo / "link") == staged["link"]
    assert pr.blob_id(repo / "target.txt") == staged["target.txt"]
    assert pr.blob_id(repo / "link") != pr.blob_id(repo / "target.txt")


def test_more_proposals(world):
    master, fork, _ = world
    make_event_changes(fork)
    write(fork, "tools/notes.cfg", "changed config\n")                 # new non-script master file
    write(master, "solvers/common/solve_ww.py", "taken\n")             # the proposed engine name exists
    commit(master, "taken")
    rec = inv(master, fork)
    p = {e.path: e.proposal for e in rec.entries}
    assert p["tools/old.py"]["action"] == "fold" and "deleted" in p["tools/old.py"]["why"]
    assert p["tools/notes.cfg"]["action"] == "fold"
    assert "already exists in the master" in p["solve_ww.py"]["why"]


def test_ambiguous_entry_needs_the_full_key(world, tmp_path):
    master, fork, _ = world
    write(fork, "solve_ww.py", "fork\n")
    ws = tmp_path / "ws"
    write(ws, "solve_ww.py", "ws\n")
    rec = inv(master, fork, ws)
    with pytest.raises(PromoteError, match="fork:solve_ww.py or workspace:solve_ww.py"):
        pr.find_entry(rec, "solve_ww.py")
    assert pr.find_entry(rec, "workspace:solve_ww.py").source == "workspace"
