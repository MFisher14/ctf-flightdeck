"""B-197: arm and release-morning safety, against a synthetic git master built in a temp dir, and a
real-process regression for the owned-process-group fence. Nothing from a real event is read."""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctf import arm, ledger, paths
from ctf.arm import ArmError

GIT = pytest.mark.needs_tool("git")

SLUG = "demo"
D1 = dt.datetime(2026, 10, 9, 2, 0, 0)
D2 = dt.datetime(2026, 10, 10, 2, 0, 0)


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


def commit(repo: Path, rel: str, text: str, msg: str = "c") -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    g(repo, "add", "-A")
    g(repo, "commit", "-q", "-m", msg)
    return g(repo, "rev-parse", "HEAD")


@pytest.fixture
def master(tmp_path):
    repo = tmp_path / "master"
    repo.mkdir()
    g(repo, "init", "-q")
    commit(repo, "a.txt", "one\n", "base")
    return repo


# ---------------------------------------------------------------------------------- dated tags

@GIT
def test_arm_writes_dated_tag_on_head(master):
    head = g(master, "rev-parse", "HEAD")
    t = arm.arm(SLUG, master=master, now=D1, log=False)
    assert t.name == "event/demo/armed/2026-10-09"
    assert t.commit == head
    assert g(master, "rev-parse", "event/demo/armed/2026-10-09^{commit}") == head
    # annotated, not lightweight
    assert g(master, "cat-file", "-t", "event/demo/armed/2026-10-09") == "tag"


@GIT
def test_arm_same_commit_same_day_is_noop(master):
    t1 = arm.arm(SLUG, master=master, now=D1, log=False)
    t2 = arm.arm(SLUG, master=master, now=D1, log=False)
    assert t2.name == t1.name
    tags = g(master, "tag", "-l", "event/demo/armed/*").split()
    assert tags == ["event/demo/armed/2026-10-09"]


@GIT
def test_rearm_same_day_new_commit_gets_numbered_suffix_no_force(master):
    """The fault: `git tag -f` was blocked, so a human re-armed nightly. A re-arm writes a *new*
    dated tag, never force-moving the old one."""
    arm.arm(SLUG, master=master, now=D1, log=False)
    commit(master, "b.txt", "live fix\n", "fix")
    head2 = g(master, "rev-parse", "HEAD")
    t2 = arm.arm(SLUG, master=master, now=D1, log=False)
    assert t2.name == "event/demo/armed/2026-10-09.2"
    assert t2.commit == head2
    # the original tag is untouched (still the base commit), so nothing was force-moved
    assert g(master, "rev-parse", "event/demo/armed/2026-10-09^{commit}") != head2
    t3 = arm.arm(SLUG, master=master, now=D1, log=False)  # same commit now -> noop
    assert t3.name == t2.name


@GIT
def test_rearm_an_earlier_commit_same_day_writes_a_new_latest_tag(master):
    """After a rollback the operator re-arms commit A the same day it was first armed, after B. The
    call must not be a no-op on the old armed/D tag: A must become the latest armed tag."""
    a = g(master, "rev-parse", "HEAD")
    t1 = arm.arm(SLUG, master=master, now=D1, log=False)              # armed/D   -> A
    commit(master, "b.txt", "b\n", "B")
    arm.arm(SLUG, master=master, now=D1, log=False)                   # armed/D.2 -> B
    t3 = arm.arm(SLUG, master=master, ref=a, now=D1, log=False)       # re-arm A
    assert t3.name == "event/demo/armed/2026-10-09.3"
    assert t3.commit == a and t3.name != t1.name
    assert arm.latest_armed(SLUG, master=master).commit == a
    assert arm.lag(SLUG, master=master, head=a).state == "armed"


@GIT
def test_armed_suffix_sorts_numerically(master):
    """`.10` must sort after `.9` (a string sort would put it after `.1`)."""
    for i in range(10):
        commit(master, f"f{i}.txt", f"{i}\n")
        arm.arm(SLUG, master=master, now=D1, log=False, fence_check=False)
    last = arm.latest_armed(SLUG, master=master)
    assert last.name == "event/demo/armed/2026-10-09.10"
    assert last.commit == g(master, "rev-parse", "HEAD")


@GIT
def test_latest_armed_orders_by_date_then_suffix(master):
    arm.arm(SLUG, master=master, now=D1, log=False)                 # day1
    commit(master, "b.txt", "x\n")
    arm.arm(SLUG, master=master, now=D1, log=False)                 # day1 .2
    commit(master, "c.txt", "y\n")
    latest = arm.arm(SLUG, master=master, now=D2, log=False)        # day2
    assert arm.latest_armed(SLUG, master=master).name == latest.name
    assert latest.name == "event/demo/armed/2026-10-10"


@GIT
def test_arm_logs_to_ledger(master, tmp_path):
    arm.arm(SLUG, master=master, now=D1, log=True)
    events = [e["event"] for e in ledger.read(workdir=paths.workdir(SLUG))]
    assert "arm.write" in events


# ---------------------------------------------------------------------------------- lag / release

@GIT
def test_lag_not_lagging_when_armed_is_head(master):
    arm.arm(SLUG, master=master, now=D1, log=False)
    lg = arm.lag(SLUG, master=master)
    assert lg.state == "armed"
    assert lg.is_lagging is False
    assert lg.behind == 0


@GIT
def test_lag_flags_live_fix_outside_the_armed_tag(master):
    arm.arm(SLUG, master=master, now=D1, log=False)
    commit(master, "b.txt", "live\n", "live fix")
    commit(master, "c.txt", "more\n", "live fix 2")
    lg = arm.lag(SLUG, master=master)
    assert lg.state == "lagging"
    assert lg.is_lagging is True
    assert lg.behind == 2
    assert lg.files == ("b.txt", "c.txt")


@GIT
def test_lag_not_armed(master):
    lg = arm.lag(SLUG, master=master)
    assert lg.state == "not-armed"
    assert lg.is_lagging is True


@GIT
def test_lag_ahead_when_release_ref_is_behind_armed(master):
    commit(master, "b.txt", "x\n")
    arm.arm(SLUG, master=master, now=D1, log=False)  # armed at the newer commit
    lg = arm.lag(SLUG, master=master, head="HEAD~1")
    assert lg.state == "ahead"
    assert lg.is_lagging is True


@GIT
def test_lag_diverged(master):
    base = g(master, "rev-parse", "HEAD")
    commit(master, "main.txt", "m\n", "on main")
    arm.arm(SLUG, master=master, now=D1, log=False)  # armed on main tip
    g(master, "checkout", "-q", "-b", "other", base)
    commit(master, "other.txt", "o\n", "on other")
    lg = arm.lag(SLUG, master=master, head="other")
    assert lg.state == "diverged"
    assert lg.is_lagging is True


# ------------------------------------------------------------------------------- freeze / green

@GIT
def test_freeze_blocks_arming_a_later_commit(master):
    fz = arm.freeze(SLUG, master=master, now=D1, log=False)
    assert arm.active_freeze(SLUG, master=master).name == fz.name
    commit(master, "b.txt", "past freeze\n", "past freeze")
    with pytest.raises(ArmError) as e:
        arm.arm(SLUG, master=master, now=D1, log=False)
    assert "frozen" in str(e.value)
    # arming the frozen commit itself is allowed
    t = arm.arm(SLUG, master=master, ref=fz.commit, now=D1, log=False)
    assert t.commit == fz.commit


@GIT
def test_allow_past_freeze_overrides(master):
    arm.freeze(SLUG, master=master, now=D1, log=False)
    commit(master, "b.txt", "past\n")
    t = arm.arm(SLUG, master=master, now=D1, allow_past_freeze=True, log=False)
    assert t.name == "event/demo/armed/2026-10-09"


@GIT
def test_thaw_lifts_freeze_then_arm_works(master):
    arm.freeze(SLUG, master=master, now=D1, log=False)
    commit(master, "b.txt", "past\n")
    arm.thaw(SLUG, master=master, now=D2, log=False)
    assert arm.active_freeze(SLUG, master=master) is None
    t = arm.arm(SLUG, master=master, now=D2, log=False)
    assert t.commit == g(master, "rev-parse", "HEAD")


@GIT
def test_refreeze_after_thaw_is_active_and_blocks_arming(master):
    """freeze -> thaw -> freeze: the second freeze is in force (a thaw only lifts freezes before it)."""
    arm.freeze(SLUG, master=master, now=D1, log=False)
    arm.thaw(SLUG, master=master, now=D1 + dt.timedelta(hours=1), log=False)
    commit(master, "b.txt", "b\n")
    fz2 = arm.freeze(SLUG, master=master, now=D1 + dt.timedelta(hours=2), log=False)
    assert arm.active_freeze(SLUG, master=master).name == fz2.name
    commit(master, "c.txt", "past the second freeze\n")
    with pytest.raises(ArmError, match="frozen"):
        arm.arm(SLUG, master=master, now=D2, log=False)


@GIT
def test_freeze_thaw_freeze_in_one_second_keeps_order(master):
    """Stamps in the same second get .n suffixes from one shared freeze/thaw sequence, so a freeze
    made right after a thaw is still in force and nothing collides."""
    f1 = arm.freeze(SLUG, master=master, now=D1, log=False)
    th = arm.thaw(SLUG, master=master, now=D1, log=False)
    f2 = arm.freeze(SLUG, master=master, now=D1, log=False)
    assert (f1.leaf, th.leaf, f2.leaf) == ("2026-10-09T02-00-00", "2026-10-09T02-00-00.2",
                                           "2026-10-09T02-00-00.3")
    assert arm.active_freeze(SLUG, master=master).name == f2.name
    arm.thaw(SLUG, master=master, now=D1, log=False)
    assert arm.active_freeze(SLUG, master=master) is None


@GIT
def test_thaw_without_freeze_refuses(master):
    with pytest.raises(ArmError):
        arm.thaw(SLUG, master=master, log=False)


@GIT
def test_mark_green_twice_in_one_second(master):
    """B-195's gate marks green after each green run: a second run in the same second must not
    crash. Same commit -> no-op returning the tag; another commit -> a .2 suffix."""
    g1 = arm.mark_green(SLUG, master=master, now=D1, log=False)
    assert arm.mark_green(SLUG, master=master, now=D1, log=False).name == g1.name
    assert g(master, "tag", "-l", "event/demo/green/*").split() == [g1.name]
    commit(master, "b.txt", "b\n")
    g2 = arm.mark_green(SLUG, master=master, now=D1, log=False)
    assert g2.name == g1.name + ".2"
    assert arm.rollback_target(SLUG, master=master).commit == g(master, "rev-parse", "HEAD")


@GIT
def test_mark_green_require_clean_refuses_a_dirty_tree(master):
    (master / "a.txt").write_text("edited, not committed\n")
    with pytest.raises(ArmError, match="a.txt"):
        arm.mark_green(SLUG, master=master, now=D1, log=False, require_clean=True)
    assert arm.last_green(SLUG, master=master) is None
    g(master, "checkout", "--", "a.txt")
    (master / "new.txt").write_text("untracked\n")
    with pytest.raises(ArmError, match="new.txt"):
        arm.mark_green(SLUG, master=master, now=D1, log=False, require_clean=True)
    (master / "new.txt").unlink()
    t = arm.mark_green(SLUG, master=master, now=D1, log=False, require_clean=True)
    assert t.commit == g(master, "rev-parse", "HEAD")


@GIT
def test_bad_ref_is_an_input_error_not_a_refusal(master):
    for call in (lambda: arm.arm(SLUG, master=master, ref="no-such-ref", log=False),
                 lambda: arm.lag(SLUG, master=master, head="no-such-ref"),
                 lambda: arm.mark_green(SLUG, master=master, ref="no-such-ref", log=False),
                 lambda: arm.freeze(SLUG, master=master, ref="no-such-ref", log=False)):
        with pytest.raises(arm.ArmInputError) as e:
            call()
        assert not isinstance(e.value, ArmError)
        assert "no-such-ref" in str(e.value)


@GIT
def test_rollback_target_is_last_green(master):
    with pytest.raises(ArmError):
        arm.rollback_target(SLUG, master=master)   # no green yet -> loud, no silent fallback
    g1 = arm.mark_green(SLUG, master=master, now=D1, log=False)
    commit(master, "b.txt", "x\n")
    g2 = arm.mark_green(SLUG, master=master, now=D2, log=False)
    rb = arm.rollback_target(SLUG, master=master)
    assert rb.name == g2.name
    assert rb.commit != g1.commit


# -------------------------------------------------------------- process-identity fence
#
# Every fence test uses real processes this test starts (sleep and sh, never a challenge binary).
# "Orphan" helpers are made the way a detaching helper is: a shell starts `sleep &` and exits, so the
# sleep is reparented away from us (no longer our descendant) but stays in our session.

FENCE = pytest.mark.needs_tool("py:psutil", "sh", "sleep")
QUIET = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _sleeper(**kw) -> subprocess.Popen:
    return subprocess.Popen(["sleep", "30"], **QUIET, **kw)


def _kill(proc) -> None:
    try:
        proc.kill()
    except Exception:
        pass


def _orphan(*, own_group: bool):
    """A `sleep 30` whose launching shell has exited: in our session, not our descendant. With
    own_group=True the shell ran in a new process group (the orphan keeps that group); otherwise it
    stays in ours. Returns (psutil.Process of the orphan, the launcher's pid = the orphan's pgid
    when own_group)."""
    import psutil
    kw = {"process_group": 0} if own_group else {}
    sh = subprocess.Popen(["sh", "-c", "sleep 30 </dev/null >/dev/null 2>&1 & echo $!"],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, **kw)
    out, _ = sh.communicate(timeout=10)
    orphan = psutil.Process(int(out.strip()))
    assert all(a.pid != os.getpid() for a in orphan.parents()), "setup: the orphan is not detached"
    assert os.getsid(orphan.pid) == os.getsid(0), "setup: the orphan must share our session"
    return orphan, sh.pid


@FENCE
def test_detached_helper_is_ours_and_never_waited_on():
    """Day-29 regression: tools/process_group.spawn makes every owned helper a new session leader.
    The old fence (same group or session) called such a helper foreign, so the opener waited on its
    own helper. A detached child must be ours and must not be in safe_to_wait()."""
    from tools.process_group import spawn
    helper = spawn(["sleep", "30"], **QUIET)
    plain = _sleeper(start_new_session=True)
    try:
        assert os.getsid(helper.pid) != os.getsid(0), "setup: the helper is detached"
        v = arm.classify([helper.pid, plain.pid])
        assert v.ours == (helper.pid, plain.pid)
        assert v.why[helper.pid] == "descendant"
        assert v.safe_to_wait() == ()
    finally:
        helper.stop()
        helper.wait_after_stop()
        _kill(plain)
        plain.wait()


@FENCE
def test_grandchild_through_a_detached_child_is_a_descendant():
    """Lineage is walked to any depth: sh (new session) -> sleep is ours via sh."""
    sh = subprocess.Popen(["sh", "-c", "sleep 30 & echo $!; wait"], start_new_session=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
    try:
        grandchild = int(sh.stdout.readline())
        assert os.getpgid(grandchild) != os.getpgrp()
        v = arm.classify([grandchild])
        assert v.ours == (grandchild,)
        assert v.why[grandchild] == "descendant"
    finally:
        os.killpg(sh.pid, 9)
        sh.wait()


@FENCE
def test_same_session_other_group_orphan_is_foreign():
    """Shared session is not ownership: an unregistered orphan in another process group is foreign
    (a terminal session holds unrelated jobs), so a wait for foreign work does include it."""
    orphan, _ = _orphan(own_group=True)
    try:
        assert os.getpgid(orphan.pid) != os.getpgrp()
        v = arm.classify([orphan.pid])
        assert v.foreign == (orphan.pid,)
        assert v.safe_to_wait() == (orphan.pid,)
        assert v.why[orphan.pid] == "foreign"
    finally:
        _kill(orphan)


@FENCE
def test_orphan_in_our_own_group_is_ours():
    orphan, _ = _orphan(own_group=False)
    try:
        assert os.getpgid(orphan.pid) == os.getpgrp()
        v = arm.classify([orphan.pid])
        assert v.ours == (orphan.pid,)
        assert v.why[orphan.pid] == "own-group"
    finally:
        _kill(orphan)


@FENCE
def test_registered_orphan_is_ours_and_a_stale_record_is_not(tmp_path):
    """The Day-29 rerun case: the spawner exited, its helper lives on. Registered, it is ours. A
    record whose pid now names another process (create time differs) gives no ownership."""
    orphan, _ = _orphan(own_group=True)
    reg = arm.OwnedRegistry(tmp_path / "owned")
    try:
        rec = reg.register(orphan.pid, label="propose-helper")
        assert rec.pgid == os.getpgid(orphan.pid)
        v = arm.classify([orphan.pid], registry=reg)
        assert v.ours == (orphan.pid,) and v.why[orphan.pid] == "registered"
        assert v.safe_to_wait() == ()
        # a stale record: same pid, another create time (the pid was reused)
        stale = {"pid": orphan.pid, "pgid": os.getpgrp() + 999_999,
                 "create_time": rec.create_time - 100.0, "label": "old"}
        (tmp_path / "owned" / f"{orphan.pid}.json").write_text(json.dumps(stale))
        v2 = arm.classify([orphan.pid], registry=reg)
        assert v2.foreign == (orphan.pid,)
        assert reg.forget(orphan.pid) is True and reg.records() == []
    finally:
        _kill(orphan)


@FENCE
def test_registered_group_owns_members_after_the_leader_exits(tmp_path):
    """A registered helper leader (pgid = its pid) exits; a member of its group lives on and is
    still ours, by group. Without the registry the member is foreign."""
    import psutil
    sh = subprocess.Popen(["sh", "-c", "sleep 30 </dev/null >/dev/null 2>&1 & echo $!; read x"],
                          process_group=0, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    member = psutil.Process(int(sh.stdout.readline()))
    reg = arm.OwnedRegistry(tmp_path / "owned")
    try:
        reg.register(sh, label="leader")
        sh.stdin.close()
        sh.wait(timeout=10)
        assert os.getpgid(member.pid) == sh.pid
        v = arm.classify([member.pid], registry=reg)
        assert v.ours == (member.pid,) and v.why[member.pid] == "registered-group"
        assert arm.classify([member.pid]).foreign == (member.pid,)
    finally:
        _kill(member)


@FENCE
def test_a_registered_group_with_no_member_left_is_expired(tmp_path):
    """Leader and every member gone: the pgid is free for reuse by unrelated work, so the record
    must not keep owning it. classify expires (deletes) it; a live group keeps its record."""
    import psutil
    gone = subprocess.Popen(["sleep", "30"], process_group=0)
    reg = arm.OwnedRegistry(tmp_path / "owned")
    reg.register(gone, label="gone")
    gone_pgid = gone.pid
    assert arm.group_alive(gone_pgid) is True
    gone.kill()
    gone.wait(timeout=10)
    assert arm.group_alive(gone_pgid) is False

    # a second registered group whose leader exits but a member lives on: kept
    sh = subprocess.Popen(["sh", "-c", "sleep 30 </dev/null >/dev/null 2>&1 & echo $!; read x"],
                          process_group=0, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    member = psutil.Process(int(sh.stdout.readline()))
    try:
        reg.register(sh, label="leader")
        sh.stdin.close()
        sh.wait(timeout=10)
        assert {r.pid for r in reg.records()} == {gone.pid, sh.pid}
        v = arm.classify([member.pid], registry=reg)
        assert v.why[member.pid] == "registered-group"
        assert {r.pid for r in reg.records()} == {sh.pid}       # the empty group's record is gone
    finally:
        _kill(member)
    member.wait(timeout=10)
    assert not arm.group_alive(sh.pid)
    arm.classify([], registry=reg)
    assert reg.records() == []


def test_registry_expire_drops_only_the_exact_record(tmp_path):
    reg = arm.OwnedRegistry(tmp_path / "owned")
    (tmp_path / "owned").mkdir()
    rec = arm.OwnedRecord(pid=999_991, pgid=999_991, create_time=100.0, label="x")
    (tmp_path / "owned" / "999991.json").write_text(json.dumps(
        {"pid": 999_991, "pgid": 999_991, "create_time": 200.0, "label": "newer"}))
    assert reg.expire(rec) is False                      # rewritten since (create time): kept
    assert [r.label for r in reg.records()] == ["newer"]
    (tmp_path / "owned" / "999991.json").write_text(json.dumps(
        {"pid": 999_991, "pgid": 4242, "create_time": 100.0, "label": "regrouped"}))
    assert reg.expire(rec) is False                      # rewritten since (group): kept
    assert [r.label for r in reg.records()] == ["regrouped"]
    (tmp_path / "owned" / "999991.json").write_text(json.dumps(rec.__dict__))
    assert reg.expire(rec) is True and reg.records() == []
    assert reg.expire(rec) is False                      # already gone


@FENCE
def test_descendant_of_a_registered_helper_is_registered(tmp_path):
    """Registered helper M (orphaned, still running) has a child S: S is ours through M."""
    import psutil
    launcher = subprocess.Popen(
        ["sh", "-c", "sh -c 'sleep 30 & echo $!; wait' </dev/null & echo $!"],
        process_group=0, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
    lines = [launcher.stdout.readline(), launcher.stdout.readline()]
    launcher.wait(timeout=10)
    pids = sorted(int(x) for x in lines)
    procs = [psutil.Process(p) for p in pids]
    try:
        # ppid is set at fork (the name may still be the shell's until exec), so pick by parentage
        a, b = procs
        middle, child = (a, b) if b.ppid() == a.pid else (b, a)
        assert child.ppid() == middle.pid, "setup: the middle shell is the sleeper's parent"
        reg = arm.OwnedRegistry(tmp_path / "owned")
        reg.register(middle.pid)
        (tmp_path / "owned" / f"{middle.pid}.json").write_text(json.dumps(
            {"pid": middle.pid, "pgid": -1, "create_time": middle.create_time(), "label": "m"}))
        v = arm.classify([child.pid], registry=reg)
        assert v.ours == (child.pid,) and v.why[child.pid] == "registered"
    finally:
        for p in procs:
            _kill(p)


@FENCE
def test_ancestor_is_ours():
    """Waiting on our own parent would deadlock: an ancestor is ours."""
    v = arm.classify([os.getppid()])
    assert v.ours == (os.getppid(),)
    assert v.why[os.getppid()] == "ancestor"


@FENCE
def test_self_dedupe_zombie_and_gone():
    import psutil
    dead = subprocess.Popen(["sh", "-c", "exit 0"])
    dead.wait()                                  # reaped: gone
    zombie = subprocess.Popen(["sh", "-c", "exit 0"])
    try:
        deadline = time.monotonic() + 10
        while psutil.Process(zombie.pid).status() != psutil.STATUS_ZOMBIE:
            assert time.monotonic() < deadline, "setup: the child never became a zombie"
            time.sleep(0.02)
        v = arm.classify([os.getpid(), os.getpid(), dead.pid, zombie.pid, 2_000_000_000])
        assert v.ours == (os.getpid(),)          # de-duped, self
        assert v.missing == (dead.pid, zombie.pid, 2_000_000_000)
        assert v.why[zombie.pid] == "zombie" and v.why[dead.pid] == "gone"
        assert v.foreign == ()
    finally:
        zombie.wait()


@FENCE
def test_registry_refuses_dead_pid_and_corrupt_record(tmp_path):
    dead = subprocess.Popen(["sh", "-c", "exit 0"])
    dead.wait()
    reg = arm.OwnedRegistry(tmp_path / "owned")
    with pytest.raises(ArmError, match="not running"):
        reg.register(dead.pid)
    with pytest.raises(arm.ArmInputError):
        reg.register(object())
    (tmp_path / "owned").mkdir()
    (tmp_path / "owned" / "123.json").write_text("{not json")
    with pytest.raises(ArmError, match="123.json"):
        arm.classify([os.getpid()], registry=reg)


@FENCE
def test_fence_selftest_passes_with_the_real_classify():
    assert arm.fence_selftest() == []


def _session_fence(pids, *, registry=None):
    """The pre-fix fence (same process group OR same session), used to prove the self-test and
    arm() catch it."""
    me, pg, sd = os.getpid(), os.getpgrp(), os.getsid(0)
    ours, foreign = [], []
    for p in pids:
        (ours if p == me or os.getpgid(p) == pg or os.getsid(p) == sd else foreign).append(p)
    return arm.FenceVerdict(me, pg, tuple(ours), tuple(foreign), ())


def _everything_ours(pids, *, registry=None):
    pids = tuple(pids)
    return arm.FenceVerdict(os.getpid(), os.getpgrp(), pids, (), (), {p: "x" for p in pids})


@FENCE
def test_fence_selftest_catches_a_wrong_fence(monkeypatch):
    monkeypatch.setattr(arm, "classify", _session_fence)
    problems = arm.fence_selftest()
    assert any("detached" in p for p in problems), problems
    monkeypatch.setattr(arm, "classify", _everything_ours)
    problems = arm.fence_selftest()
    assert any("not foreign" in p for p in problems), problems


@GIT
@FENCE
def test_arm_runs_the_fence_regression_and_refuses_on_failure(master, monkeypatch):
    monkeypatch.setattr(arm, "classify", _session_fence)
    with pytest.raises(ArmError, match="fence"):
        arm.arm(SLUG, master=master, now=D1, log=False)
    assert g(master, "tag", "-l", "event/demo/armed/*") == ""
    # the explicit bypass still arms
    assert arm.arm(SLUG, master=master, now=D1, log=False, fence_check=False).leaf == "2026-10-09"


# -------------------------------------------------------------------- unwired (arm report)

def _pkg_tree(root: Path):
    files = {
        "pkg/__init__.py": "",
        "pkg/cli/__init__.py": "",
        "pkg/cli/cmd.py": "HELP = 'x'\n",                       # cli command -> entrypoint
        "pkg/_private.py": "X = 1\n",                           # underscore -> entrypoint
        "pkg/used.py": "VALUE = 1\n",
        "pkg/used_rel.py": "VALUE = 2\n",
        "pkg/from_pkg.py": "VALUE = 3\n",
        "pkg/up_two.py": "VALUE = 4\n",
        "pkg/helpers.py": "def thing():\n    return 5\n",
        "pkg/other/__init__.py": "",
        "pkg/other/mod2.py": "VALUE = 6\n",
        "pkg/dyn.py": "VALUE = 7\n",
        "pkg/doc_only.py": "VALUE = 8\n",
        "pkg/hidden_only.py": "VALUE = 9\n",
        "pkg/legacy_target.py": "VALUE = 10\n",
        "pkg/orphan.py": "def never_called():\n    return 0\n",
        "pkg/sub/__init__.py": "",
        # deep resolves `..` relative to its package pkg.sub: pkg.up_two, pkg.helpers, pkg.other.mod2
        "pkg/sub/deep.py": ("from .. import up_two\nfrom ..helpers import thing\n"
                            "from ..other import mod2\nfrom ..... import beyond_top\n"),
        "pkg/sibling.py": "from . import used_rel\n",
        "consumer.py": ("import importlib\nimport pkg.used\nfrom pkg import from_pkg\n"
                        "import pkg.sub.deep\nimportlib.import_module('pkg.dyn')\n"),
        "notes.py": ('"""pkg.doc_only is mentioned in this docstring only."""\n'
                     "# import pkg.doc_only  (a comment is not an import)\n"),
        ".venv/lib/site.py": "import pkg.hidden_only\n",         # hidden folder: not the tree
        "broken.py": "import pkg.legacy_target\ndef (:\n",       # does not parse -> textual
    }
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_unwired_resolves_every_import_form(tmp_path):
    _pkg_tree(tmp_path)
    rows = arm.unwired(root=tmp_path, package="pkg")
    mods = {r.module for r in rows}
    for wired in ("pkg.used",            # import pkg.used
                  "pkg.from_pkg",        # from pkg import from_pkg
                  "pkg.used_rel",        # from . import used_rel
                  "pkg.up_two",          # from .. import up_two
                  "pkg.helpers",         # from ..helpers import thing
                  "pkg.other.mod2",      # from ..other import mod2
                  "pkg.sub.deep",        # import pkg.sub.deep
                  "pkg.dyn",             # importlib.import_module('pkg.dyn')
                  "pkg.legacy_target"):  # a file that does not parse, searched textually
        assert wired not in mods, wired
    for entry in ("pkg", "pkg.cli", "pkg.cli.cmd", "pkg._private", "pkg.sub", "pkg.other"):
        assert entry not in mods, entry
    assert mods == {"pkg.orphan", "pkg.sibling", "pkg.doc_only", "pkg.hidden_only"}
    assert {r.path for r in rows} >= {"pkg/orphan.py", "pkg/doc_only.py"}


def test_imported_names_resolves_relative_levels():
    names, _ = arm.imported_names("from .. import x\nfrom ..a.b import y\nfrom . import z\n",
                                  "top.mid.leaf", False)
    assert {"top.x", "top.a.b", "top.a.b.y", "top.mid.z"} <= names
    # an __init__ is its own package: `from . import z` in top/mid/__init__.py is top.mid.z
    names2, _ = arm.imported_names("from . import z\nfrom .. import w\n", "top.mid", True)
    assert {"top.mid.z", "top.w"} <= names2
    assert arm.imported_names("def (:\n", "m", False) is None


def _write(root: Path, files: dict) -> None:
    for rel, text in files.items():
        q = root / rel
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_text(text)


def test_unwired_tests_are_not_callers_by_default(tmp_path):
    """A module that only a test imports is the 'built but unwired' fault: reported. With
    include_tests it is not. A conftest's pytest_plugins registration is wiring (pytest loads it)."""
    _write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/only_tested.py": "VALUE = 1\n",
        "pkg/only_conftest.py": "VALUE = 2\n",
        "pkg/only_root_test.py": "VALUE = 3\n",
        "pkg/only_suffix_test.py": "VALUE = 4\n",
        "pkg/plugin.py": "VALUE = 5\n",
        "pkg/plugin_list.py": "VALUE = 6\n",
        "pkg/used.py": "VALUE = 7\n",
        "pkg/test_inside.py": "def test_x():\n    pass\n",        # a test file: never reported
        "tests/test_mod.py": "from pkg import only_tested\n",
        "tests/conftest.py": ("import pkg.only_conftest\n"
                              "pytest_plugins = ['pkg.plugin_list']\n"),
        "conftest.py": 'pytest_plugins = ("pkg.plugin",)\n',
        "test_root.py": "import pkg.only_root_test\n",
        "lib/thing_test.py": "import pkg.only_suffix_test\n",
        "app.py": "import pkg.used\n",
    })
    default = {r.module for r in arm.unwired(root=tmp_path, package="pkg")}
    assert default == {"pkg.only_tested", "pkg.only_conftest", "pkg.only_root_test",
                       "pkg.only_suffix_test"}
    rows = arm.unwired(root=tmp_path, package="pkg")
    assert all("non-test" in r.reason for r in rows)
    assert {r.module for r in arm.unwired(root=tmp_path, package="pkg", include_tests=True)} == set()


def test_unwired_a_module_naming_itself_is_not_its_own_caller(tmp_path):
    """`logging.getLogger("pkg.selfname")` or an error message naming the module is a string with
    its own dotted name: that must not make it wired."""
    _write(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/selfname.py": ('import logging\nLOG = logging.getLogger("pkg.selfname")\n'
                            'ERR = "pkg.selfname failed"\n'),
        "pkg/selfimport.py": "import pkg.selfimport\n",
        "pkg/broken_self.py": "import pkg.broken_self\ndef (:\n",   # unparseable: textual search
    })
    mods = {r.module for r in arm.unwired(root=tmp_path, package="pkg")}
    assert mods == {"pkg.selfname", "pkg.selfimport", "pkg.broken_self"}


def test_pytest_plugins_parses_every_form():
    assert arm.pytest_plugins('pytest_plugins = "a.b"\n') == {"a.b"}
    assert arm.pytest_plugins('pytest_plugins = ("a", "b.c")\n') == {"a", "b.c"}
    assert arm.pytest_plugins('pytest_plugins = ["x"]\nother = ["y"]\n') == {"x"}
    assert arm.pytest_plugins("def f():\n    pytest_plugins = ['z']\n") == set()   # not module level
    assert arm.pytest_plugins("def (:\n") == set()


def test_unwired_cli_include_tests(tmp_path, capsys):
    _write(tmp_path, {"pkg/__init__.py": "", "pkg/only_tested.py": "V = 1\n",
                      "tests/test_mod.py": "import pkg.only_tested\n"})
    assert ctf_main("unwired", "--master", str(tmp_path), "--package", "pkg", "--json") == 0
    assert [r["module"] for r in json.loads(capsys.readouterr().out)] == ["pkg.only_tested"]
    assert ctf_main("unwired", "--master", str(tmp_path), "--package", "pkg", "--json",
                    "--include-tests") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_unwired_missing_package_is_loud(tmp_path):
    with pytest.raises(arm.ArmInputError):
        arm.unwired(root=tmp_path, package="nope")


# ----------------------------------------------------------------------------- CLI end to end

def ctf_main(*argv) -> int:
    from ctf.cli import main
    return main(["release", *argv])


@GIT
@FENCE
def test_cli_headline_form_arms_the_slug(master, capsys):
    """`python -m ctf release SLUG` (the documented form) writes the armed tag, through the real parser."""
    assert ctf_main(SLUG, "--master", str(master)) == 0
    assert g(master, "tag", "-l", "event/demo/armed/*").startswith("event/demo/armed/")
    assert "armed demo at" in capsys.readouterr().out
    assert ctf_main("arm", SLUG, "--master", str(master)) == 0      # explicit form, same day: no-op
    assert len(g(master, "tag", "-l", "event/demo/armed/*").split()) == 1


@GIT
@FENCE
def test_cli_release_check_exit_codes(master, capsys):
    m = ("--master", str(master))
    assert ctf_main(SLUG, *m) == 0
    assert ctf_main("check", SLUG, *m) == 0            # armed == HEAD
    commit(master, "b.txt", "live\n")
    assert ctf_main("check", SLUG, *m) == 1            # a live fix now lags the armed tag
    assert ctf_main("status", SLUG, *m) == 0                   # status never fails on lag
    capsys.readouterr()
    # an unresolvable ref is an error (2), not "lagging" (1)
    assert ctf_main("check", SLUG, *m, "--head", "no-such-ref") == 2
    assert "no-such-ref" in capsys.readouterr().err
    assert ctf_main(SLUG, *m, "--ref", "no-such-ref") == 2


@GIT
def test_cli_errors_and_refusals(master, capsys):
    m = ("--master", str(master))
    assert ctf_main("bogus", SLUG, *m) == 2                    # unknown action
    assert "unknown action" in capsys.readouterr().err
    assert ctf_main("green", *m) == 2                          # no slug
    assert ctf_main("thaw", SLUG, *m) == 1                     # refusal: nothing frozen
    assert ctf_main("rollback", SLUG, *m) == 1                 # refusal: no green tag
    assert ctf_main("unwired", "--master", str(master), "--package", "nope") == 2


# ------------------------------------------------------------- gate run --mark-green (B-195 wiring)

GATE_FILES = {
    ".gitignore": "__pycache__/\n",
    "lib/val.txt": "7\n",
    "docs/notes.md": "# notes\n",
    "tests/test_ok.py": 'VAL = "lib/val.txt"\ndef test_one():\n    pass\n',
    "tests/test_red.py": 'RED = "red.flag"\ndef test_red():\n    assert 0\n',
    "red.flag": "1\n",
}


def _gate(repo: Path, tmp_path: Path, *argv) -> int:
    import argparse
    from ctf.cli import gate
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    common = ["--root", str(repo), "--config", str(repo / "gate.toml"), "--state", str(tmp_path / "state")]
    return gate.run(p.parse_args(common + list(argv)))


@GIT
def test_gate_only_a_full_green_run_marks_green(tmp_path, capsys):
    """Only a green full run on a clean tree marks the rollback target. An impact or lane run (or a
    pytest selection option) proves only part of the suite, so it is refused before running."""
    from gate_repo import make_repo
    repo = make_repo(tmp_path / "repo", GATE_FILES, extra_config='\n[lanes]\nvals = ["lib/val.txt"]\n')
    tags = lambda: g(repo, "tag", "-l", "event/demo/green/*").split()

    assert _gate(repo, tmp_path, "run", "--full", "--mark-green", SLUG) == 1
    assert tags() == []                                          # red: never marked
    capsys.readouterr()

    (repo / "tests" / "test_red.py").write_text('RED = "red.flag"\ndef test_red():\n    pass\n')
    g(repo, "add", "-A")
    g(repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "fix red")
    head = g(repo, "rev-parse", "HEAD")

    # an impact run that is green and gates a file: refused before it runs, exit 2
    assert _gate(repo, tmp_path, "run", "--changed", "lib/val.txt", "--mark-green", SLUG) == 2
    cap = capsys.readouterr()
    assert "not a full green" in cap.err and "gate: output=" not in cap.out
    assert tags() == []
    # a lane run, and a full run filtered by a lane
    assert _gate(repo, tmp_path, "run", "--lane", "vals", "--mark-green", SLUG) == 2
    assert _gate(repo, tmp_path, "run", "--full", "--lane", "vals", "--mark-green", SLUG) == 2
    assert "a --lane filter" in capsys.readouterr().err
    # a full run narrowed by a pytest selection option
    assert _gate(repo, tmp_path, "run", "--full", "--pytest-arg=-k", "--pytest-arg=one",
                 "--mark-green", SLUG) == 2
    assert _gate(repo, tmp_path, "run", "--full", "--pytest-arg=--deselect=tests/test_ok.py::test_one",
                 "--mark-green", SLUG) == 2
    assert "narrows" in capsys.readouterr().err
    assert tags() == []
    # a pytest option that does not select is fine
    assert _gate(repo, tmp_path, "run", "--full", "--pytest-arg=-q", "--mark-green", SLUG) == 0
    assert "marked green demo" in capsys.readouterr().out
    assert len(tags()) == 1
    t = arm.rollback_target(SLUG, master=repo)
    assert t.commit == head
    assert "gate full run, 2 file(s)" in g(repo, "tag", "-l", "--format=%(contents)", t.name)

    (repo / "lib" / "val.txt").write_text("8\n")                 # uncommitted edit, still green
    assert _gate(repo, tmp_path, "run", "--full", "--mark-green", SLUG) == 2
    assert "uncommitted" in capsys.readouterr().err
    assert len(tags()) == 1
    assert _gate(repo, tmp_path, "run", "--changed", "lib/val.txt") == 0   # no flag: plain green


@GIT
def test_gate_full_run_of_no_test_file_is_not_green(tmp_path, capsys):
    from gate_repo import make_repo
    repo = make_repo(tmp_path / "repo", {".gitignore": "__pycache__/\n", "lib/val.txt": "7\n"})
    rc = _gate(repo, tmp_path, "run", "--full", "--mark-green", SLUG)
    assert rc == 2
    assert "gated no test file" in capsys.readouterr().err
    assert g(repo, "tag", "-l", "event/demo/green/*") == ""


@GIT
def test_gate_env_file_refuses_mark_green(tmp_path, capsys):
    """B-137 release-gate integrity: an ENV file does not turn the gate red (its code was not what
    broke), so a full run with one green test and one ENV file exits 0 -- but --mark-green must still be
    refused, because that ENV file never actually proved its code green and a rollback target that
    counted it would lie. Without the env guard in _mark_green the run tags HEAD and exits 0, so this
    fires exactly on the regression."""
    from gate_repo import make_repo
    files = {
        ".gitignore": "__pycache__/\n",
        "tests/test_ok.py": "def test_ok():\n    assert True\n",
        # fails with an explicit GATE-ENV marker -> classified ENV, not FAIL (envfail.py)
        "tests/test_blocked.py": 'def test_blocked():\n    raise AssertionError("GATE-ENV: fake tool not on PATH")\n',
    }
    repo = make_repo(tmp_path / "repo", files)
    tags = lambda: g(repo, "tag", "-l", "event/demo/green/*").split()

    rc = _gate(repo, tmp_path, "run", "--full", "--mark-green", SLUG)
    out = capsys.readouterr()
    assert "env=1" in out.out                              # the run saw exactly one ENV file
    assert rc == 2                                         # ENV present -> mark-green refused
    assert "blocked by the environment" in out.err
    assert tags() == []                                   # and HEAD was NOT tagged green

    # control: with the ENV file removed, the same full run marks green and exits 0 -- proving it is the
    # ENV file, not some other refusal, that blocked the mark above.
    (repo / "tests" / "test_blocked.py").unlink()
    g(repo, "add", "-A")
    g(repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "drop blocked test")
    assert _gate(repo, tmp_path, "run", "--full", "--mark-green", SLUG) == 0
    assert "marked green demo" in capsys.readouterr().out
    assert len(tags()) == 1


def test_green_refusal_rules():
    """The rule itself, on hand-built selections (the gate test above runs it end to end)."""
    from types import SimpleNamespace as NS
    from ctf.cli.gate import green_refusal
    graph = NS(tests=["tests/test_a.py", "tests/test_b.py"])
    full = NS(mode="full", tests=["tests/test_b.py", "tests/test_a.py"])
    assert green_refusal(graph, full) == ""
    assert "impact" in green_refusal(graph, NS(mode="impact", tests=list(graph.tests)))
    assert "lane" in green_refusal(graph, NS(mode="full", tests=["tests/test_a.py"]))
    for narrowing in (("-k", "x"), ("-kx",), ("-m", "slow"), ("--deselect=a",), ("--lf",),
                      ("--last-failed",), ("--ignore=tests/test_a.py",), ("--sw",)):
        assert "narrows" in green_refusal(graph, full, narrowing), narrowing
    assert green_refusal(graph, full, ("-q", "-x", "-p", "no:cacheprovider")) == ""
