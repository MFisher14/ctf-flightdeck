"""B-213: the build-time work registry, file claims, fold owners and the idle-machine lock (ctf/workreg.py,
ctf/cli/work.py, the idle-lock wiring in ctf/gate/runner.py, ctf/adapt/regress.py and their CLIs).

Everything runs on a registry folder under tmp_path with a synthetic backlog and a synthetic promotion
record. Liveness is driven through an injected pid_alive and a step clock; the idle lock's waits through
an injected clock and sleep, so nothing here asserts a wall-clock upper bound. The only processes started
are this interpreter (racing registrations, a crashed lock holder) and pytest children of the gate."""
from __future__ import annotations

import argparse
import fcntl
import io
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctf import backlog, paths, promote
from ctf import workreg as W
from ctf.cli import _idle
from ctf.cli import work as work_cli

REPO = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------------------------------- fixtures

class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


def write_backlog(path: Path, rows: dict[str, str]) -> Path:
    backlog.save(path, [backlog.parse_row({"id": i, "title": f"row {i}", "status": s}) for i, s in rows.items()])
    return path


ROWS = {"B-1": "open", "B-2": "open", "B-3": "in-progress", "B-4": "blocked", "B-9": "built"}


@pytest.fixture
def bl(tmp_path):
    return write_backlog(tmp_path / "backlog.jsonl", ROWS)


@pytest.fixture
def alive():
    return {os.getpid()}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def reg(tmp_path, bl, alive, clock):
    return W.Registry(tmp_path / "state", backlog=bl, master=tmp_path / "master",
                      clock=clock, pid_alive=lambda p: p in alive)


def make_promotion(master: Path, slug: str = "evt") -> Path:
    """A promotion record with: a fork fold (dest tools/unpack.py), a fork fold already decided to two
    paths, a dropped entry, and a workspace engine proposal."""
    def entry(source, path, **kw):
        return promote.Entry(source=source, path=path, change="modified" if source == "fork" else "added",
                             state="committed" if source == "fork" else "workspace", blob="0" * 40, **kw)
    rec = promote.Record(event=slug, base="a" * 40, base_ref=f"event/{slug}/start", fork_head=None,
                         inventoried="2026-11-01T00:00:00+00:00", entries=[
                             entry("fork", "tools/unpack.py", proposal={"action": "fold", "dest": ["tools/unpack.py"]}),
                             entry("fork", "ctf/x.py", proposal={"action": "fold", "dest": ["ctf/x.py"]},
                                   decision={"action": "fold", "dest": ["ctf/x.py", "ctf/y.py"],
                                             "decided": "2026-11-02T00:00:00+00:00"}),
                             entry("fork", "junk.py", proposal={"action": "fold", "dest": ["junk.py"]},
                                   decision={"action": "drop", "reason": "duplicate of the master",
                                             "decided": "2026-11-02T00:00:00+00:00"}),
                             entry("workspace", "13-y/y_fix.py", proposal={"action": "fold", "dest": ["ctf/y.py"]}),
                             entry("workspace", "12-rsa/solve.py",
                                   proposal={"action": "engine", "module": "solvers/crypto/rsa_solve.py",
                                             "manifest": "solvers/crypto/rsa_solve.manifest.toml",
                                             "test": "tests/test_rsa_solve.py"}),
                         ])
    return promote.save_record(rec, master=master)


# ------------------------------------------------------------------------------------------- patterns

@pytest.mark.parametrize("raw, want", [
    ("ctf/workreg.py", "ctf/workreg.py"),
    ("./ctf/workreg.py", "ctf/workreg.py"),
    ("ctf/gate/", "ctf/gate/**"),
    ("  tests/test_*.py ", "tests/test_*.py"),
])
def test_normalize_pattern(raw, want):
    assert W.normalize_pattern(raw) == want


@pytest.mark.parametrize("bad, match", [
    ("", "empty"), ("   ", "empty"), ("/etc/passwd", "relative"), ("ctf/../x.py", r"'\.\.'"),
    ("ctf//x.py", "segment"), ("ctf/[ab].py", "not supported"), ("ctf/{a,b}.py", "not supported"),
    ("ctf\\x.py", "not supported"),
])
def test_normalize_pattern_refuses(bad, match):
    with pytest.raises(W.WorkRegError, match=match):
        W.normalize_pattern(bad)


@pytest.mark.parametrize("a, b, overlap", [
    ("ctf/*.py", "ctf/*.md", False),          # same literal prefix, disjoint suffixes: a prefix test says yes
    ("ctf/**", "ctf/gate/runner.py", True),
    ("ctf/*.py", "ctf/gate/runner.py", False),  # * stays in one segment
    ("ctf/gate/", "ctf/gate/runner.py", True),
    ("ctf/gate/", "ctf/gatekeeper.py", False),
    ("a/**/b", "a/b", True),                    # **/ matches zero directories
    ("a/**/b", "a/x/y/b", True),
    ("a/**/b", "a/xb", False),
    ("*.py", "x/y.py", False),
    ("**/*.py", "x/y.py", True),
    ("t/test_?.py", "t/test_ab.py", False),
    ("t/test_*.py", "t/*_x.py", True),          # glob against glob: t/test_x.py matches both
    ("x/*", "x/*/y", False),
    ("x/**", "x", False),
    ("solvers/dex/dex_float.py", "solvers/dex/dex_float.py", True),
    ("solvers/dex/dex_float.py", "solvers/dex/dex_float.pyc", False),
])
def test_patterns_overlap(a, b, overlap):
    assert W.patterns_overlap(a, b) is overlap
    assert W.patterns_overlap(b, a) is overlap


def test_pattern_matches_takes_a_path_not_a_pattern():
    assert W.pattern_matches("ctf/**", "ctf/a/b.py")
    assert not W.pattern_matches("ctf/*.py", "ctf/a/b.py")
    with pytest.raises(W.WorkRegError, match="pattern, not a path"):
        W.pattern_matches("ctf/**", "ctf/*.py")


# ------------------------------------------------------------------------------------------- registry

def test_begin_records_harness_branch_rows_and_claims(reg, tmp_path):
    wt = tmp_path / "wt-213"
    wt.mkdir()
    rec = reg.begin("item/B-213", harness="claude", branch="item/B-213", worktree=wt, pid=os.getpid(),
                    rows=["B-1"], files=["ctf/workreg.py", "tests/"], note="registry")
    assert rec["reaped"] == []
    [v] = reg.agents()
    assert v.name == "item/B-213" and v.live and v.reason == ""
    r = v.record
    assert (r["harness"], r["branch"], r["worktree"], r["pid"]) == ("claude", "item/B-213", str(wt.resolve()), os.getpid())
    assert r["claims"] == {"row": ["B-1"], "file": ["ctf/workreg.py", "tests/**"], "fold": []}
    # the state is a real file other processes read, not memory
    on_disk = json.loads((tmp_path / "state" / W.REGISTRY).read_text())
    assert on_disk["agents"]["item/B-213"]["claims"]["row"] == ["B-1"]
    assert [h["event"] for h in reg.history()] == ["begin"]


def test_a_second_agent_on_a_claimed_row_is_refused_by_name(reg):
    reg.begin("item/B-1", harness="codex", branch="item/B-1", rows=["B-1"])
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("item/B-1b", harness="claude", branch="item/B-1b", rows=["B-1"])
    [c] = e.value.conflicts
    assert (c.kind, c.wanted, c.owner, c.harness, c.branch) == ("row", "B-1", "item/B-1", "codex", "item/B-1")
    assert "held by item/B-1 (codex, branch item/B-1)" in str(e.value)
    assert [v.name for v in reg.agents()] == ["item/B-1"]


def test_begin_is_all_or_nothing(reg):
    reg.begin("a", harness="claude", files=["solvers/dex/dex_float.py"])
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("b", harness="codex", rows=["B-2"], files=["solvers/dex/*.py", "docs/x.md"])
    assert [(c.kind, c.wanted, c.held) for c in e.value.conflicts] == [
        ("file", "solvers/dex/*.py", "solvers/dex/dex_float.py")]
    assert [v.name for v in reg.agents()] == ["a"]
    # B-2 was not taken by the refused registration
    reg.begin("c", harness="human", rows=["B-2"])


def test_every_clash_is_named_not_just_the_first(reg):
    reg.begin("a", harness="claude", rows=["B-1"], files=["ctf/x.py"])
    reg.begin("b", harness="codex", rows=["B-2"], files=["tests/"])
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("c", harness="claude", rows=["B-1", "B-2"], files=["ctf/x.py", "tests/test_x.py"])
    got = sorted((c.owner, c.kind, c.wanted) for c in e.value.conflicts)
    assert got == [("a", "file", "ctf/x.py"), ("a", "row", "B-1"),
                   ("b", "file", "tests/test_x.py"), ("b", "row", "B-2")]


def test_disjoint_file_claims_coexist(reg):
    reg.begin("a", harness="claude", files=["ctf/*.py"])
    reg.begin("b", harness="codex", files=["ctf/*.md", "ctf/gate/runner.py"])
    assert {v.name for v in reg.agents()} == {"a", "b"}


def test_one_live_agent_per_branch_and_per_worktree(reg, tmp_path):
    wt = tmp_path / "wt"
    wt.mkdir()
    reg.begin("a", harness="claude", branch="item/B-1", worktree=wt)
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("b", harness="codex", branch="item/B-1")
    assert [(c.kind, c.wanted) for c in e.value.conflicts] == [("branch", "item/B-1")]
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("c", harness="codex", branch="item/B-2", worktree=wt / ".")
    assert [c.kind for c in e.value.conflicts] == ["worktree"]
    assert [c.kind for c in reg.check(branch="item/B-1", worktree=wt)] == ["branch", "worktree"]
    assert reg.check("a", branch="item/B-1", worktree=wt) == []


def test_an_agent_registers_once(reg):
    reg.begin("a", harness="claude")
    with pytest.raises(W.WorkRegError, match="already registered"):
        reg.begin("a", harness="claude")


@pytest.mark.parametrize("kw, match", [
    (dict(harness="gpt"), "harness"),
    (dict(harness="claude", rows=["B-404"]), "not in the backlog"),
    (dict(harness="claude", rows=["B-9"]), "built"),
    (dict(harness="claude", pid=-3), "positive int"),
    (dict(harness="claude", pid=4242), "not a live process"),
    (dict(harness="claude", ttl=0), "ttl"),
    (dict(harness="claude", ttl="soon"), "ttl"),
])
def test_begin_validates_before_writing(reg, tmp_path, kw, match):
    with pytest.raises(W.WorkRegError, match=match):
        reg.begin("a", **kw)
    assert not (tmp_path / "state" / W.REGISTRY).exists()


def test_open_hard_tail_rows_can_be_claimed(reg):
    reg.begin("a", harness="claude", rows=["B-3", "B-4"])     # in-progress and blocked are open rows


def test_missing_backlog_is_a_named_error(tmp_path):
    r = W.Registry(tmp_path / "s", backlog=tmp_path / "nope.jsonl")
    with pytest.raises(W.WorkRegError, match="backlog file not found"):
        r.begin("a", harness="claude", rows=["B-1"])


def test_dead_pid_record_does_not_block_and_is_reaped(reg, alive):
    alive.add(4242)
    reg.begin("crashed", harness="codex", pid=4242, rows=["B-1"], files=["ctf/x.py"])
    alive.discard(4242)
    [v] = reg.agents()                                   # listing observes, never reaps
    assert not v.live and v.reason == "pid 4242 is gone"
    assert reg.check(rows=["B-1"], files=["ctf/x.py"]) == []
    rec = reg.begin("fresh", harness="claude", rows=["B-1"], files=["ctf/x.py"])
    assert rec["reaped"] == ["crashed (pid 4242 is gone)"]
    assert [v.name for v in reg.agents()] == ["fresh"]
    assert [(h["event"], h["agent"]) for h in reg.history()] == [("begin", "crashed"), ("reap", "crashed"),
                                                                   ("begin", "fresh")]


def test_a_refused_registration_still_persists_the_reap(reg, alive):
    alive.add(4242)
    reg.begin("crashed", harness="codex", pid=4242, rows=["B-2"])
    reg.begin("live", harness="claude", rows=["B-1"])
    alive.discard(4242)
    with pytest.raises(W.ClaimConflict):
        reg.begin("new", harness="claude", rows=["B-1"])
    assert [v.name for v in reg.agents()] == ["live"]


def test_claim_for_an_agent_gone_stale_is_refused_and_its_reap_saved(reg, alive, tmp_path):
    """A dead agent's claim() must not quietly add claims that block no one: it is reaped and refused."""
    alive.add(4242)
    reg.begin("a", harness="codex", pid=4242, files=["ctf/x.py"])
    alive.discard(4242)
    for _ in range(2):
        with pytest.raises(W.WorkRegError, match="agent a is not registered"):
            reg.claim("a", files=["ctf/y.py"])
    saved = json.loads((tmp_path / "state" / W.REGISTRY).read_text())
    assert saved["agents"] == {}
    assert [(h["event"], h["agent"]) for h in reg.history()] == [("begin", "a"), ("reap", "a")]
    assert reg.check(files=["ctf/y.py", "ctf/x.py"]) == []


def test_an_already_registered_refusal_still_saves_the_reap(reg, alive, tmp_path):
    alive.add(4242)
    reg.begin("crashed", harness="codex", pid=4242, rows=["B-2"])
    reg.begin("a", harness="claude", rows=["B-1"])
    alive.discard(4242)
    with pytest.raises(W.WorkRegError, match="agent a is already registered"):
        reg.begin("a", harness="claude")
    saved = json.loads((tmp_path / "state" / W.REGISTRY).read_text())
    assert sorted(saved["agents"]) == ["a"]
    assert [(h["event"], h["agent"]) for h in reg.history()].count(("reap", "crashed")) == 1


def test_a_logged_reap_is_always_on_disk(reg, alive, tmp_path):
    """Every 'reap' history line matches a record that is gone from the saved registry."""
    alive.add(4242)
    reg.begin("crashed", harness="codex", pid=4242, rows=["B-1"])
    reg.begin("live", harness="claude", rows=["B-2"])
    alive.discard(4242)
    with pytest.raises(W.ClaimConflict):
        reg.begin("x", harness="claude", rows=["B-2"])
    saved = json.loads((tmp_path / "state" / W.REGISTRY).read_text())
    reaped = [h["agent"] for h in reg.history() if h["event"] == "reap"]
    assert reaped == ["crashed"] and not set(reaped) & set(saved["agents"])


def test_leave_branch_removes_every_agent_on_that_branch_only(reg, alive):
    alive.add(4242)
    reg.begin("a", harness="claude", branch="item/B-1", files=["ctf/a.py"])
    reg.begin("b", harness="codex", branch="item/B-2", files=["ctf/b.py"])
    reg.begin("c", harness="codex", branch="item/B-3", pid=4242, files=["ctf/c.py"])
    alive.discard(4242)                                     # stale records on the branch go too
    assert reg.leave_branch("item/B-1", why="merged") == ["a"]
    assert reg.leave_branch("item/B-3") == ["c"]
    assert reg.leave_branch("item/B-1") == []             # none left: not an error
    assert [v.name for v in reg.agents()] == ["b"]
    assert [(h["event"], h["agent"], h.get("reason")) for h in reg.history() if h["event"] == "leave"] == [
        ("leave", "a", "merged"), ("leave", "c", "")]
    assert reg.check(files=["ctf/a.py", "ctf/c.py"]) == []


def test_leave_branch_with_no_registry_creates_nothing(tmp_path):
    state = tmp_path / "state"
    assert W.Registry(state).leave_branch("item/B-1") == []
    assert not state.exists()
    with pytest.raises(W.WorkRegError, match="bad branch"):
        W.Registry(state).leave_branch(" x")


def test_ttl_record_goes_stale_without_heartbeat(reg, clock):
    reg.begin("a", harness="claude", ttl=60, rows=["B-1"])
    clock.t += 59
    reg.heartbeat("a")
    clock.t += 59
    assert reg.agents()[0].live
    with pytest.raises(W.ClaimConflict):
        reg.begin("b", harness="codex", rows=["B-1"])
    clock.t += 1
    v = reg.agents()[0]
    assert not v.live and "no heartbeat for 60s" in v.reason
    with pytest.raises(W.WorkRegError, match="stale"):
        reg.heartbeat("a")
    reg.begin("b", harness="codex", rows=["B-1"])


def test_a_removed_worktree_makes_the_record_stale(reg, tmp_path):
    wt = tmp_path / "wt"
    wt.mkdir()
    reg.begin("a", harness="claude", worktree=wt, files=["ctf/"])
    wt.rmdir()
    assert reg.agents()[0].reason == f"worktree {wt.resolve()} is gone"
    assert reg.reap() == [f"a (worktree {wt.resolve()} is gone)"]
    assert reg.agents() == []


def test_a_record_with_no_liveness_is_held_until_leave(reg, clock):
    reg.begin("a", harness="human", rows=["B-1"])
    clock.t += 10 ** 7
    assert reg.agents()[0].live and reg.reap() == []
    released = reg.leave("a")
    assert released["claims"]["row"] == ["B-1"]
    reg.begin("b", harness="claude", rows=["B-1"])
    with pytest.raises(W.WorkRegError, match="not registered"):
        reg.leave("a")


def test_claim_adds_all_or_nothing_and_needs_a_registered_agent(reg):
    reg.begin("a", harness="claude", rows=["B-1"])
    reg.begin("b", harness="codex", files=["docs/"])
    reg.claim("a", rows=["B-2"], files=["ctf/x.py"])
    assert reg.agents()[0].record["claims"] == {"row": ["B-1", "B-2"], "file": ["ctf/x.py"], "fold": []}
    with pytest.raises(W.ClaimConflict) as e:
        reg.claim("a", rows=["B-3"], files=["docs/README.md"])
    assert [(c.owner, c.kind) for c in e.value.conflicts] == [("b", "file")]
    assert "B-3" not in reg.agents()[0].record["claims"]["row"]
    with pytest.raises(W.WorkRegError, match="not registered"):
        reg.claim("ghost", rows=["B-3"])
    reg.claim("a", rows=["B-1"])                                  # re-claiming its own row is not a clash
    assert reg.agents()[0].record["claims"]["row"] == ["B-1", "B-2"]


def test_release_drops_only_what_is_held(reg):
    reg.begin("a", harness="claude", rows=["B-1", "B-2"], files=["ctf/x.py", "tests/"])
    with pytest.raises(W.WorkRegError, match="does not hold: row B-3, file docs/"):
        reg.release("a", rows=["B-1", "B-3"], files=["docs/"])
    assert reg.agents()[0].record["claims"]["row"] == ["B-1", "B-2"]
    reg.release("a", rows=["B-1"], files=["./tests/"])
    assert reg.agents()[0].record["claims"] == {"row": ["B-2"], "file": ["ctf/x.py"], "fold": []}
    reg.begin("b", harness="codex", rows=["B-1"], files=["tests/test_q.py"])
    reg.claim("b", rows=["B-3"])
    reg.leave("b")
    hist = [(h["event"], h["agent"]) for h in reg.history()]
    assert hist == [("begin", "a"), ("release", "a"), ("begin", "b"), ("claim", "b"), ("leave", "b")]
    assert reg.history()[1]["claims"] == {"row": ["B-1"], "file": ["tests/**"], "fold": []}


def test_check_is_read_only_and_ignores_the_agents_own_claims(reg, tmp_path):
    reg.begin("a", harness="claude", rows=["B-1"], files=["ctf/x.py"])
    before = (tmp_path / "state" / W.REGISTRY).read_bytes()
    assert [c.kind for c in reg.check(rows=["B-1"], files=["ctf/*.py"])] == ["row", "file"]
    assert reg.check("a", rows=["B-1"], files=["ctf/*.py"]) == []
    assert reg.check(rows=["B-2"], files=["ctf/gate/x.py"]) == []
    assert (tmp_path / "state" / W.REGISTRY).read_bytes() == before


def test_check_on_an_empty_registry_creates_nothing(reg, tmp_path):
    assert reg.check(rows=["B-1"]) == []
    assert not (tmp_path / "state").exists()


def test_an_unreadable_registry_is_never_reset(reg, tmp_path):
    p = tmp_path / "state" / W.REGISTRY
    p.parent.mkdir(parents=True)
    p.write_text("{not json")
    with pytest.raises(W.WorkRegError, match="unreadable work registry"):
        reg.begin("a", harness="claude")
    with pytest.raises(W.WorkRegError, match="unreadable"):
        reg.agents()
    p.write_text(json.dumps({"schema": 99, "agents": {}}))
    with pytest.raises(W.WorkRegError, match="schema-1"):
        reg.check()
    assert json.loads(p.read_text())["schema"] == 99


# ------------------------------------------------------------------------------------------- folds

def test_one_owner_per_fold(reg, tmp_path):
    make_promotion(tmp_path / "master")
    rec = reg.begin("a", harness="claude", folds=["evt:fork:tools/unpack.py"])
    assert rec["claims"]["fold"] == [{"key": "evt:fork:tools/unpack.py", "paths": ["tools/unpack.py"]}]
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("b", harness="codex", folds=["evt:tools/unpack.py"])   # the path names the same entry
    assert [(c.kind, c.wanted, c.owner) for c in e.value.conflicts] == [("fold", "evt:fork:tools/unpack.py", "a")]


def test_a_fold_holds_its_master_paths_against_file_claims(reg, tmp_path):
    make_promotion(tmp_path / "master")
    reg.begin("a", harness="claude", folds=["evt:fork:ctf/x.py"])        # decided: ctf/x.py and ctf/y.py
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("b", harness="codex", files=["ctf/y.py"])
    [c] = e.value.conflicts
    assert c.kind == "file" and c.held == "ctf/y.py (fold evt:fork:ctf/x.py)"
    reg.begin("c", harness="codex", files=["solvers/crypto/"])
    with pytest.raises(W.ClaimConflict) as e:                            # and a fold meets file claims
        reg.claim("a", folds=["evt:workspace:12-rsa/solve.py"])          # lands under solvers/crypto/
    assert {(c.kind, c.owner, c.held) for c in e.value.conflicts} == {("fold", "c", "solvers/crypto/**")}


def test_two_folds_that_land_on_one_master_path_clash(reg, tmp_path):
    make_promotion(tmp_path / "master")
    reg.begin("a", harness="claude", folds=["evt:fork:ctf/x.py"])        # lands at ctf/x.py and ctf/y.py
    with pytest.raises(W.ClaimConflict) as e:
        reg.begin("b", harness="codex", folds=["evt:workspace:13-y/y_fix.py"])   # lands at ctf/y.py
    [c] = e.value.conflicts
    assert (c.kind, c.wanted, c.held) == ("fold", "evt:workspace:13-y/y_fix.py -> ctf/y.py",
                                          "ctf/y.py (fold evt:fork:ctf/x.py)")


def test_fold_claims_dedupe_and_release(reg, tmp_path):
    make_promotion(tmp_path / "master")
    reg.begin("a", harness="claude", folds=["evt:fork:tools/unpack.py", "evt:tools/unpack.py"])
    reg.claim("a", folds=["evt:fork:tools/unpack.py"])
    assert [f["key"] for f in reg.agents()[0].record["claims"]["fold"]] == ["evt:fork:tools/unpack.py"]
    reg.release("a", folds=["evt:fork:tools/unpack.py"])
    assert reg.agents()[0].record["claims"]["fold"] == []
    reg.begin("b", harness="codex", folds=["evt:fork:tools/unpack.py"])


@pytest.mark.parametrize("fold, match", [
    ("evt:fork:junk.py", "decided 'drop'"),
    ("evt:fork:nope.py", "no inventoried entry"),
    ("other:fork:tools/unpack.py", "no promotion record"),
    ("evt", "bad fold claim"),
    ("Bad Slug:x", "bad event slug"),
])
def test_fold_claims_are_checked_against_the_promotion_record(reg, tmp_path, fold, match):
    make_promotion(tmp_path / "master")
    with pytest.raises(W.WorkRegError, match=match):
        reg.begin("a", harness="claude", folds=[fold])


# ------------------------------------------------------------------------------------------- concurrency

RACE = """
import sys
from pathlib import Path
from ctf import workreg as W
state, bl, name, go = sys.argv[1:5]
while not Path(go).exists():
    pass
try:
    W.Registry(Path(state), backlog=bl).begin(name, harness="codex", rows=["B-1"])
    print("WON")
except W.ClaimConflict:
    print("LOST")
"""


def test_racing_registrations_have_exactly_one_winner(tmp_path, bl):
    state, go = tmp_path / "state", tmp_path / "go"
    env = dict(os.environ, PYTHONPATH=str(REPO))
    procs = [subprocess.Popen([sys.executable, "-c", RACE, str(state), str(bl), f"agent-{i}", str(go)],
                              cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, text=True) for i in range(4)]
    go.write_text("go")
    outs = [p.communicate(timeout=300)[0].strip() for p in procs]
    assert sorted(outs) == ["LOST", "LOST", "LOST", "WON"]
    assert len(W.Registry(state, backlog=bl).agents()) == 1


# ------------------------------------------------------------------------------------------- idle lock

def lock(tmp_path, label, mode=W.EXCLUSIVE, **kw):
    kw.setdefault("timeout", 0)
    return W.IdleLock(tmp_path / "state", label, mode=mode, **kw)


def test_exclusive_excludes_exclusive_and_names_the_holder(tmp_path):
    with lock(tmp_path, "gate run", agent="item/B-1"):
        with pytest.raises(W.IdleLockTimeout, match=r"held by gate run \(exclusive, pid \d+ agent item/B-1\)"):
            lock(tmp_path, "adapt gate").acquire()
    with lock(tmp_path, "adapt gate") as second:      # released: free again
        assert second.record["label"] == "adapt gate"


def test_shared_holders_coexist_and_keep_out_an_exclusive_one(tmp_path):
    with lock(tmp_path, "heavy 1", W.SHARED), lock(tmp_path, "heavy 2", W.SHARED):
        assert W.idle_status(tmp_path / "state")["state"] == "shared"
        with pytest.raises(W.IdleLockTimeout, match="heavy 1 .*heavy 2|heavy 2 .*heavy 1"):
            lock(tmp_path, "timing").acquire()
    with lock(tmp_path, "timing"):
        assert W.idle_status(tmp_path / "state")["state"] == "exclusive"
        with pytest.raises(W.IdleLockTimeout, match="held by timing"):
            lock(tmp_path, "heavy 3", W.SHARED).acquire()
    assert W.idle_status(tmp_path / "state")["state"] == "free"


def _wanted(tmp_path, pid):
    d = tmp_path / "state" / W.IDLE_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / f"wanted-{pid}-0-0.json").write_text(json.dumps({"pid": pid, "label": "timing suite", "mode": W.EXCLUSIVE}))


def test_a_waiting_timing_suite_holds_off_new_shared_takers(tmp_path):
    _wanted(tmp_path, os.getpid())
    with pytest.raises(W.IdleLockTimeout, match="a timing suite is waiting for it: timing suite"):
        lock(tmp_path, "heavy", W.SHARED).acquire()


def test_a_dead_waiter_does_not_hold_off_shared_takers(tmp_path):
    _wanted(tmp_path, 4242)
    with lock(tmp_path, "heavy", W.SHARED, pid_alive=lambda p: p == os.getpid()):
        pass


def test_an_exclusive_waiter_leaves_a_wanted_record_while_it_waits_and_removes_it(tmp_path):
    c = Clock(0.0)
    seen = []
    with lock(tmp_path, "heavy", W.SHARED):
        def on_wait(why):
            seen.append((why, W.idle_status(tmp_path / "state")["waiting"]))
        with pytest.raises(W.IdleLockTimeout):
            lock(tmp_path, "timing", timeout=10, poll=5, clock=c, sleep=c.sleep, on_wait=on_wait).acquire()
    assert len(seen) == 2                                  # t=0 and t=5 waited; t=10 gave up
    assert all(w and w[0]["label"] == "timing" for _why, w in seen)
    assert W.idle_status(tmp_path / "state")["waiting"] == []


def test_the_wait_ends_when_the_holder_releases(tmp_path):
    c = Clock(0.0)
    holder = lock(tmp_path, "heavy", W.SHARED)
    holder.acquire()
    polls = []

    def sleep(s):
        polls.append(s)
        c.sleep(s)
        if len(polls) == 3:
            holder.release()
    got = lock(tmp_path, "timing", timeout=None, poll=2, clock=c, sleep=sleep)
    with got:
        assert got.waited == 6 and polls == [2, 2, 2]
        st = W.idle_status(tmp_path / "state")
        assert st["waiting"] == [] and [h["label"] for h in st["holders"]] == ["timing"]


def test_max_load_waits_for_a_quiet_host(tmp_path):
    c = Clock(0.0)
    loads = iter([40.0, 30.0, 3.0])
    why = []
    lk = lock(tmp_path, "timing", timeout=100, poll=1, clock=c, sleep=c.sleep, max_load=0.5,
              load_fn=lambda: next(loads), cpus=10, on_wait=why.append)
    with lk:
        assert lk.record["load_per_cpu"] == 0.3 and lk.waited == 2
    assert why == ["host load 4.00 per CPU is over 0.5", "host load 3.00 per CPU is over 0.5"]
    with pytest.raises(W.IdleLockTimeout, match="host load 9.00 per CPU is over 0.5"):
        lock(tmp_path, "timing", max_load=0.5, load_fn=lambda: 90.0, cpus=10).acquire()


def test_holder_records_are_removed_on_release(tmp_path):
    with lock(tmp_path, "gate run") as lk:
        st = W.idle_status(tmp_path / "state")
        assert [h["label"] for h in st["holders"]] == ["gate run"] and st["stale"] == []
        assert lk.record["pid"] == os.getpid()
    st = W.idle_status(tmp_path / "state")
    assert st == {"state": "free", "holders": [], "waiting": [], "stale": []}


@pytest.mark.parametrize("kw, match", [
    (dict(mode="both"), "mode"), (dict(poll=0), "poll"), (dict(timeout=-1), "timeout"),
    (dict(max_load=0), "max_load"),
])
def test_idle_lock_rejects_bad_settings(tmp_path, kw, match):
    with pytest.raises(W.WorkRegError, match=match):
        W.IdleLock(tmp_path, "x", **kw)


HOLD = """
import sys, time
from pathlib import Path
from ctf import workreg as W
lk = W.IdleLock(Path(sys.argv[1]), "crashing suite")
lk.acquire()
Path(sys.argv[2]).write_text("held")
time.sleep(600)
"""


def test_a_crashed_holder_never_wedges_the_lock(tmp_path):
    state, ready = tmp_path / "state", tmp_path / "ready"
    p = subprocess.Popen([sys.executable, "-c", HOLD, str(state), str(ready)], cwd=str(tmp_path),
                         env=dict(os.environ, PYTHONPATH=str(REPO)))
    try:
        for _ in range(6000):                     # a hang guard for the child's start, not a bound under test
            if ready.exists() or p.poll() is not None:
                break
            time.sleep(0.05)
        assert ready.exists(), "the holder child never took the lock"
        assert W.idle_status(state)["state"] == "exclusive"
        with pytest.raises(W.IdleLockTimeout, match=f"crashing suite .*pid {p.pid}"):
            lock(tmp_path, "next suite").acquire()
    finally:
        p.send_signal(signal.SIGKILL)               # our own child, standing in for a crashed suite
        p.wait(timeout=120)
    st = W.idle_status(state)
    assert st["state"] == "free" and [r["pid"] for r in st["stale"]] == [p.pid]
    with lock(tmp_path, "next suite"):
        pass


# ------------------------------------------------------------------------------------------- paths

def test_workreg_state_is_the_git_common_dir_shared_by_worktrees(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_WORKREG_STATE", raising=False)
    main = tmp_path / "main"
    (main / ".git" / "worktrees" / "wt1").mkdir(parents=True)
    (main / ".git" / "worktrees" / "wt1" / "commondir").write_text("../..\n")
    wt = tmp_path / "wt1"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {main / '.git' / 'worktrees' / 'wt1'}\n")
    assert paths.workreg_state(main) == (main / ".git" / "ctf-workreg").resolve()
    assert paths.workreg_state(wt) == paths.workreg_state(main)
    monkeypatch.setenv("CTF_WORKREG_STATE", str(tmp_path / "elsewhere"))
    assert paths.workreg_state(wt) == (tmp_path / "elsewhere").resolve()
    monkeypatch.delenv("CTF_WORKREG_STATE")
    with pytest.raises(FileNotFoundError, match="CTF_WORKREG_STATE"):
        paths.workreg_state(tmp_path / "nogit")


# ------------------------------------------------------------------------------------------- ctf work CLI

def work(*argv):
    p = argparse.ArgumentParser()
    work_cli.add_arguments(p)
    return work_cli.run(p.parse_args(list(argv)))


@pytest.fixture
def cli_env(tmp_path, bl):
    return ["--state", str(tmp_path / "state"), "--backlog", str(bl), "--master", str(tmp_path / "master")]


def test_cli_start_names_conflicts_and_exits_1(cli_env, capsys):
    assert work("start", "item/B-1", "--harness", "codex", "--row", "B-1", "--file", "tests/", *cli_env) == 0
    assert "registered item/B-1 (codex, branch item/B-1): rows B-1; files tests/**" in capsys.readouterr().out
    assert work("start", "item/B-2", "--harness", "claude", "--row", "B-1", "--file", "tests/test_a.py",
                *cli_env) == 1
    err = capsys.readouterr().err.splitlines()
    assert err == ["ctf work: conflict: row 'B-1' is held by item/B-1 (codex, branch item/B-1)",
                   "ctf work: conflict: file 'tests/test_a.py' is held by item/B-1 (codex, branch item/B-1) as "
                   "'tests/**'"]
    assert work("check", "--row", "B-1", "--json", *cli_env) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["conflicts"][0]["owner"] == "item/B-1"
    assert work("check", "--row", "B-2", *cli_env) == 0
    assert "no conflict" in capsys.readouterr().out


def test_cli_errors_exit_2(cli_env, capsys):
    assert work("start", "a", "--harness", "claude", "--row", "B-404", *cli_env) == 2
    assert "not in the backlog" in capsys.readouterr().err
    assert work("leave", "ghost", *cli_env) == 2
    assert work("claim", "a", "--file", "/abs", *cli_env) == 2


def test_cli_lifecycle_list_claim_release_leave(cli_env, capsys, tmp_path):
    assert work("start", "a", "--harness", "human", "--branch", "feature/x", *cli_env) == 0
    assert work("claim", "a", "--row", "B-2", "--file", "ctf/x.py", *cli_env) == 0
    assert work("release", "a", "--file", "ctf/x.py", *cli_env) == 0
    assert work("heartbeat", "a", *cli_env) == 0
    capsys.readouterr()
    assert work("list", "--json", *cli_env) == 0
    [rec] = json.loads(capsys.readouterr().out)
    assert (rec["agent"], rec["branch"], rec["live"], rec["claims"]["row"], rec["claims"]["file"]) == \
        ("a", "feature/x", True, ["B-2"], [])
    assert work("leave", "a", *cli_env) == 0
    assert "a left (released: rows B-2)" in capsys.readouterr().out
    assert work("list", *cli_env) == 0
    assert "no agent registered" in capsys.readouterr().out


def test_cli_idle_run_returns_the_commands_code_and_3_on_timeout(cli_env, tmp_path, capsys):
    assert work("idle-run", *cli_env, "--", sys.executable, "-c", "raise SystemExit(7)") == 7
    probe = ("import fcntl, os, sys\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
             "try:\n    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)\nexcept BlockingIOError:\n    sys.exit(0)\n"
             "sys.exit(5)\n")
    # the command runs while the lock is held exclusive: a shared probe from it is refused
    assert work("idle-run", *cli_env, "--", sys.executable, "-c", probe, str(tmp_path / "state" / W.IDLE_LOCK)) == 0
    # --shared lets another shared taker in
    assert work("idle-run", "--shared", *cli_env, "--", sys.executable, "-c", probe,
                str(tmp_path / "state" / W.IDLE_LOCK)) == 5
    with W.IdleLock(tmp_path / "state", "someone else's suite"):
        assert work("idle-run", "--timeout", "0", *cli_env, "--", sys.executable, "-c", "pass") == 3
    assert "someone else's suite" in capsys.readouterr().err
    assert work("idle-run", *cli_env) == 2


def test_cli_idle_status(cli_env, tmp_path, capsys):
    with W.IdleLock(tmp_path / "state", "gate run", agent="item/B-7"):
        assert work("idle-status", *cli_env) == 0
    out = capsys.readouterr().out
    assert "idle lock: exclusive" in out and "held by gate run (exclusive" in out and "agent item/B-7" in out


# ------------------------------------------------------------------------------------------- flags

def _args(**kw):
    return argparse.Namespace(**{"idle_lock": None, "idle_timeout": None, **kw})


def test_idle_flags_win_over_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKREG_STATE", str(tmp_path / "st"))
    monkeypatch.delenv(_idle.ENV_IDLE_LOCK, raising=False)
    assert _idle.idle_lock_factory(_args(), None, "x") is None
    monkeypatch.setenv(_idle.ENV_IDLE_LOCK, "1")
    f = _idle.idle_lock_factory(_args(idle_timeout=3.0), None, "gate run")
    lk = f()
    assert isinstance(lk, W.IdleLock) and lk.mode == W.EXCLUSIVE and lk.timeout == 3.0
    assert lk.dir == (tmp_path / "st").resolve()
    assert _idle.idle_lock_factory(_args(idle_lock=False), None, "x") is None
    monkeypatch.setenv(_idle.ENV_IDLE_LOCK, "0")
    assert _idle.idle_lock_factory(_args(idle_lock=True), None, "x") is not None
    monkeypatch.setenv(_idle.ENV_IDLE_LOCK, "maybe")
    with pytest.raises(W.WorkRegError, match="CTF_IDLE_LOCK"):
        _idle.idle_lock_factory(_args(), None, "x")


def test_idle_wait_reasons_are_printed_once_each(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKREG_STATE", str(tmp_path / "st"))
    buf = io.StringIO()
    f = _idle.idle_lock_factory(_args(idle_lock=True, idle_timeout=0.0), None, "gate run", stream=buf)
    with W.IdleLock(tmp_path / "st", "other"):
        lk = f()
        lk.on_wait("held by other")
        lk.on_wait("held by other")
        lk.on_wait("held by someone")
    assert buf.getvalue().splitlines() == ["gate run: waiting for the idle-machine lock: held by other",
                                           "gate run: waiting for the idle-machine lock: held by someone"]
