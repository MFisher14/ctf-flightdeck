"""B-175: the end-of-event reaper (ctf/reaper.py, `ctf reap`).

Dry run first; only the exact ids the player confirms are acted on, each re-checked right before.
Git state is a throwaway repo built by the test; processes are synthetic sleepers.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctf import jobs, procid, reaper, sessions
from ctf.cli import main as cli_main

PY = sys.executable
SLEEP = [PY, "-c", "import time; time.sleep(60)"]
GIT_ID = ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"]

needs_git = pytest.mark.needs_tool("git")


def git(repo, *argv, check=True):
    cp = subprocess.run(["git", *GIT_ID, "-C", str(repo), *argv], capture_output=True, text=True)
    if check and cp.returncode != 0:
        raise AssertionError(f"git {argv}: {cp.stderr}")
    return cp.stdout.strip()


def commit(repo, name, text="x"):
    (Path(repo) / name).write_text(text)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def R(tmp_path, monkeypatch):
    """main + merged/unmerged branches + three linked worktrees (clean merged, dirty, unmerged)."""
    monkeypatch.delenv("CTF_INTEGRATION_BRANCH", raising=False)
    repo = (tmp_path / "repo").resolve()
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, "a")
    git(repo, "branch", "item/merged")
    git(repo, "branch", "keepme")
    git(repo, "checkout", "-q", "-b", "item/unmerged")
    commit(repo, "u")
    git(repo, "checkout", "-q", "main")
    git(repo, "branch", "item/wt-done")
    git(repo, "branch", "item/wt-dirty")
    git(repo, "branch", "item/wt-open")
    wts = tmp_path / "wts"
    git(repo, "worktree", "add", "-q", str(wts / "done"), "item/wt-done")
    git(repo, "worktree", "add", "-q", str(wts / "dirty"), "item/wt-dirty")
    git(repo, "worktree", "add", "-q", str(wts / "open"), "item/wt-open")
    (wts / "dirty" / "scratch.txt").write_text("untracked work")
    commit(wts / "open", "o")
    here = tmp_path / "elsewhere"
    here.mkdir()

    class X:
        pass
    x = X()
    x.repo, x.wts, x.here, x.tmp = repo, wts.resolve(), here, tmp_path
    x.plan = lambda **kw: reaper.plan(repo=repo, here=here, **kw)
    return x


def ids(p):
    return [c.id for c in p.candidates]


@needs_git
def test_plan_lists_only_clean_merged_worktrees_and_merged_unprotected_branches(R):
    p = R.plan(protect=["keepme"])
    done = f"worktree:{R.wts / 'done'}"
    assert ids(p) == [done, "branch:item/merged", "branch:item/wt-done"]
    by = p.by_id()
    assert by["branch:item/wt-done"].after == done
    assert by["branch:item/merged"].facts["sha"] == git(R.repo, "rev-parse", "item/merged")
    kept = {k.what: k.reason for k in p.kept}
    assert "untracked" in kept[f"worktree:{R.wts / 'dirty'}"]
    assert "not merged" in kept[f"worktree:{R.wts / 'open'}"]
    assert "checked out at" in kept["branch:item/wt-dirty"]
    assert kept["branch:keepme"] == "protected"
    assert not any(c.id in ("branch:main", "branch:item/unmerged") for c in p.candidates)
    assert any("not merged into HEAD" in n for n in p.notes)
    assert any("not checked" in n for n in p.notes)      # no jobs / sessions folder given


@needs_git
def test_execute_acts_on_exactly_the_confirmed_ids_and_logs_them(R):
    p = R.plan(protect=["keepme"])
    log = R.tmp / "reaper.jsonl"
    res = reaper.execute(p, ["branch:item/merged"], log=log)
    assert [(r.id, r.outcome) for r in res] == [("branch:item/merged", "done")]
    assert git(R.repo, "branch", "--list", "item/merged") == ""
    assert git(R.repo, "branch", "--list", "item/wt-done") != ""        # not confirmed: kept
    assert (R.wts / "done").is_dir()
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert [(r["id"], r["outcome"]) for r in rows] == [("branch:item/merged", "done")]


@needs_git
def test_an_unknown_id_stops_the_run_before_anything_is_done(R):
    p = R.plan()
    with pytest.raises(reaper.ReapError, match="not in the current plan.*branch:main"):
        reaper.execute(p, ["branch:item/merged", "branch:main"], log=None)
    assert git(R.repo, "branch", "--list", "item/merged") != ""
    with pytest.raises(reaper.ReapError, match="no id confirmed"):
        reaper.execute(p, [], log=None)


@needs_git
def test_a_worktree_branch_needs_its_worktree_confirmed_first(R):
    p = R.plan()
    wt = f"worktree:{R.wts / 'done'}"
    res = reaper.execute(p, ["branch:item/wt-done"], log=None)
    assert [(r.outcome, r.detail) for r in res] == [("skipped", f"needs {wt} first (confirm it too)")]
    assert git(R.repo, "branch", "--list", "item/wt-done") != ""
    res = reaper.execute(p, ["branch:item/wt-done", wt], log=None)        # order given is irrelevant
    assert [(r.id, r.outcome) for r in res] == [(wt, "done"), ("branch:item/wt-done", "done")]
    assert not (R.wts / "done").exists()
    assert git(R.repo, "branch", "--list", "item/wt-done") == ""


@needs_git
def test_state_that_changed_after_the_plan_is_refused(R):
    p = R.plan()
    # the branch moved on (a new commit): update-ref with the planned sha must refuse
    git(R.repo, "checkout", "-q", "item/merged")
    commit(R.repo, "late")
    git(R.repo, "checkout", "-q", "main")
    # the clean worktree got new untracked work
    (R.wts / "done" / "new.txt").write_text("work")
    res = {r.id: r for r in reaper.execute(p, ["branch:item/merged", f"worktree:{R.wts / 'done'}"],
                                          log=None)}
    assert res["branch:item/merged"].outcome == "failed"
    assert "not merged" in res["branch:item/merged"].detail or "moved" in res["branch:item/merged"].detail
    assert git(R.repo, "branch", "--list", "item/merged") != ""
    assert res[f"worktree:{R.wts / 'done'}"].outcome == "failed"
    assert "untracked" in res[f"worktree:{R.wts / 'done'}"].detail
    assert (R.wts / "done" / "new.txt").exists()


@needs_git
def test_branch_delete_is_compare_and_delete_on_the_planned_sha(R):
    commit(R.repo, "b")                                      # main: a -> b; item/merged stays at a
    p = R.plan()
    planned = p.by_id()["branch:item/merged"].facts["sha"]
    assert planned == git(R.repo, "rev-parse", "main~1")
    # the branch moves to another merged commit after the plan: still merged, but not what was checked
    git(R.repo, "branch", "-f", "item/merged", "main")
    res = reaper.execute(p, ["branch:item/merged"], log=None)
    assert res[0].outcome == "failed" and "was not deleted" in res[0].detail
    assert git(R.repo, "rev-parse", "item/merged") == git(R.repo, "rev-parse", "main")


@needs_git
def test_protected_branches_include_the_base_current_and_integration_branch(R):
    git(R.repo, "config", "ctftools.integrationBranch", "item/merged")
    p = R.plan(base="item/wt-done")
    names = {c.id for c in p.candidates}
    assert "branch:item/merged" not in names                 # the configured integration branch
    assert "branch:item/wt-done" not in names                # the base itself
    assert "branch:main" not in names                        # main, and the current branch
    prot = reaper.protected_branches(R.repo, "item/wt-done", ["extra"])
    assert {"main", "master", "item/wt-done", "item/merged", "extra"} <= prot


@needs_git
def test_a_branch_that_becomes_protected_after_the_plan_is_refused_at_execute(R):
    p = R.plan()
    assert "branch:item/merged" in ids(p)
    git(R.repo, "config", "ctftools.integrationBranch", "item/merged")   # protected only now
    res = reaper.execute(p, ["branch:item/merged"], log=None)
    assert [(r.outcome, r.detail) for r in res] == [("failed", "branch item/merged is protected")]
    assert git(R.repo, "branch", "--list", "item/merged") != ""


@needs_git
def test_execute_re_applies_the_plans_protect_extras(R):
    assert R.plan(protect=["keepme"]).protect == ("keepme",)
    p = R.plan()
    assert "branch:keepme" in ids(p)
    p.protect = ("keepme",)            # the extras the plan carries are checked again at delete time
    res = reaper.execute(p, ["branch:keepme"], log=None)
    assert [(r.outcome, r.detail) for r in res] == [("failed", "branch keepme is protected")]
    assert git(R.repo, "branch", "--list", "keepme") != ""


@needs_git
def test_the_worktree_holding_the_current_directory_is_kept(R):
    p = reaper.plan(repo=R.repo, here=R.wts / "done")
    assert f"worktree:{R.wts / 'done'}" not in ids(p)
    assert any(k.reason == "the current directory is inside it" for k in p.kept)


@needs_git
def test_bad_base_is_a_named_error(R):
    with pytest.raises(reaper.ReapError, match="base 'nope' is not a commit"):
        R.plan(base="nope")


# ------------------------------------------------------------------ processes

def _cleanup(*ps):
    for p in ps:
        if p.poll() is None:
            p.kill()
        p.wait()


@pytest.fixture
def P(tmp_path, monkeypatch):
    for v in (jobs.OWNER_ENV, jobs.OWNER_PID_ENV):
        monkeypatch.delenv(v, raising=False)
    jr, sr = tmp_path / "jobs", tmp_path / "sessions"
    yield jr, sr
    for st in jobs.list_jobs(jr):
        if st.state == "running":
            try:
                jobs.kill(st.dir)
            except jobs.JobError:
                pass


def test_plan_and_confirm_jobs_and_sessions(P, tmp_path):
    jr, sr = P
    running = jobs.start(SLEEP, root=jr, name="brute", owner="agent-1")
    keep = jobs.start(SLEEP, root=jr, name="keep")
    launcher = subprocess.Popen(SLEEP)
    try:
        c = sessions.claim(sr, "playday", harness="claude", pid=launcher.pid)
        (sr / "old.json").write_text(json.dumps({"name": "old", "launcher_pid": 999999,
                                                 "launcher_start": 1.0}))
        play = f"session:playday@{launcher.pid}-{int(round(c.record['launcher_start'] * 1000))}"
        old = "session:old@999999-1000"
        p = reaper.plan(jobs_root=jr, sessions_root=sr)
        assert set(ids(p)) == {f"job:{running.id}", f"job:{keep.id}", play, old}
        assert ids(p)[:2] == [old, play]                               # sessions act first
        assert "owner agent-1" in p.by_id()[f"job:{running.id}"].detail
        res = reaper.execute(p, [f"job:{running.id}", old, play],
                             log=tmp_path / "log.jsonl", agent_grace=0.5, launcher_grace=0.2)
        assert {r.id: r.outcome for r in res} == {f"job:{running.id}": "done", old: "done",
                                                  play: "done"}
        assert jobs.state(running.dir).state == "exited"
        assert jobs.state(keep.dir).state == "running"                 # not confirmed: untouched
        assert launcher.wait(timeout=20) is not None
        assert not (sr / "old.json").exists() and not (sr / "playday.json").exists()
    finally:
        _cleanup(launcher)


def _alive_after_a_moment(proc):
    time.sleep(0.3)
    return proc.poll() is None


def test_a_stale_session_re_claimed_after_the_dry_run_is_never_stopped(P, tmp_path, capsys):
    jr, sr = P
    sr.mkdir(parents=True)
    (sr / "playday.json").write_text(json.dumps({"name": "playday", "launcher_pid": 999999,
                                                 "launcher_start": 1.0}))
    dry = reaper.plan(jobs_root=jr, sessions_root=sr)
    stale_id = "session:playday@999999-1000"
    assert ids(dry) == [stale_id]
    assert dry.by_id()[stale_id].action.startswith("remove the stale session record")
    launcher = subprocess.Popen(SLEEP)
    try:
        c = sessions.claim(sr, "playday", harness="claude", pid=launcher.pid)
        assert c.replaced is not None                       # the stale record was replaced
        # the confirm run plans afresh: the id the player read is not the new claim's id
        fresh = reaper.plan(jobs_root=jr, sessions_root=sr)
        assert stale_id not in ids(fresh)
        with pytest.raises(reaper.ReapError, match="not in the current plan"):
            reaper.execute(fresh, [stale_id], log=None)
        # the same through the CLI: exit 2, nothing done
        log = tmp_path / "r.jsonl"
        assert cli_main(["reap", "--jobs-dir", str(jr), "--sessions-dir", str(sr), "--log", str(log),
                         "--confirm", stale_id]) == 2
        assert "not in the current plan" in capsys.readouterr().err
        # and the re-claim lands between plan and execute of one run: refused, record kept
        res = reaper.execute(dry, [stale_id], log=None, agent_grace=0.1, launcher_grace=0.1)
        assert res[0].outcome == "failed" and "re-claimed" in res[0].detail
        assert _alive_after_a_moment(launcher), "the new launcher was stopped"
        assert json.loads((sr / "playday.json").read_text())["launcher_pid"] == launcher.pid
    finally:
        _cleanup(launcher)


def test_a_live_session_re_claimed_between_plan_and_execute_is_not_stopped(P):
    jr, sr = P
    first, second = subprocess.Popen(SLEEP), subprocess.Popen(SLEEP)
    try:
        sessions.claim(sr, "playday", harness="claude", pid=first.pid)
        p = reaper.plan(jobs_root=jr, sessions_root=sr)
        [planned] = [c for c in p.candidates if c.kind == "session"]
        assert planned.facts["status"] == "live"
        _cleanup(first)                                    # its launcher ends; a new one claims the name
        sessions.claim(sr, "playday", harness="claude", pid=second.pid)
        res = reaper.execute(p, [planned.id], log=None, agent_grace=0.1, launcher_grace=0.1)
        assert res[0].outcome == "failed" and "now held by another launcher" in res[0].detail
        assert _alive_after_a_moment(second), "the new holder was stopped"
    finally:
        _cleanup(first, second)


def test_sessions_stop_refuses_an_unexpected_holder(tmp_path):
    a, b = subprocess.Popen(SLEEP), subprocess.Popen(SLEEP)
    try:
        ca = sessions.claim(tmp_path, "s", harness="claude", pid=a.pid)
        _cleanup(a)
        sessions.claim(tmp_path, "s", harness="claude", pid=b.pid)
        with pytest.raises(sessions.SessionError, match="now held by another launcher"):
            sessions.stop(tmp_path, "s", agent_grace=0.1, launcher_grace=0.1, expect=ca.record)
        assert _alive_after_a_moment(b)
        held = sessions.peek(tmp_path, "s").record
        assert sessions.reap_id("s", ca.record) != sessions.reap_id("s", held)
        # the refusal a launcher prints names the exact id the player confirms
        with pytest.raises(sessions.SessionLive) as ei:
            sessions.claim(tmp_path, "s", harness="claude")
        assert f"--confirm {sessions.reap_id('s', held)})" in str(ei.value)
    finally:
        _cleanup(a, b)


def test_a_re_claim_by_the_same_pid_with_another_start_is_refused(P):
    """pid + start time, not pid alone: the planned claim names the live launcher's pid but an
    older start (the pid was reused). Neither the reaper's stale-record removal nor
    sessions.stop(expect=) may treat the new claim as the planned one."""
    jr, sr = P
    sr.mkdir(parents=True)
    launcher = subprocess.Popen(SLEEP)
    try:
        real = procid.start_time(launcher.pid)
        old = {"name": "playday", "launcher_pid": launcher.pid, "launcher_start": real - 50.0}
        (sr / "playday.json").write_text(json.dumps(old))
        dry = reaper.plan(jobs_root=jr, sessions_root=sr)
        [planned] = [c for c in dry.candidates if c.kind == "session"]
        assert planned.facts["status"] == "stale" and planned.facts["launcher_pid"] == launcher.pid
        c = sessions.claim(sr, "playday", harness="claude", pid=launcher.pid)   # same pid, new start
        assert c.replaced == old
        res = reaper.execute(dry, [planned.id], log=None, agent_grace=0.1, launcher_grace=0.1)
        assert res[0].outcome == "failed" and "re-claimed" in res[0].detail, res[0].detail
        assert json.loads((sr / "playday.json").read_text())["launcher_start"] == c.record["launcher_start"]
        assert _alive_after_a_moment(launcher), "the same-pid re-claim was stopped"
    finally:
        _cleanup(launcher)


def test_sessions_stop_refuses_an_expected_claim_with_the_same_pid_but_another_start(tmp_path):
    launcher = subprocess.Popen(SLEEP)
    try:
        c = sessions.claim(tmp_path, "s", harness="claude", pid=launcher.pid)
        stale = {"launcher_pid": launcher.pid, "launcher_start": c.record["launcher_start"] - 50.0}
        with pytest.raises(sessions.SessionError, match="now held by another launcher"):
            sessions.stop(tmp_path, "s", agent_grace=0.1, launcher_grace=0.1, expect=stale)
        assert _alive_after_a_moment(launcher), "a claim that only shares the pid was stopped"
        assert (tmp_path / "s.json").exists()
    finally:
        _cleanup(launcher)


def test_a_stale_record_without_a_launcher_start_is_removed_by_its_id(P, tmp_path):
    jr, sr = P
    sr.mkdir(parents=True)
    (sr / "nostart.json").write_text(json.dumps({"name": "nostart", "launcher_pid": 999998}))
    p = reaper.plan(jobs_root=jr, sessions_root=sr)
    assert ids(p) == ["session:nostart@999998-nostart"]
    res = reaper.execute(p, ["session:nostart@999998-nostart"], log=tmp_path / "l.jsonl")
    assert (res[0].outcome, res[0].detail) == ("done", "stale record removed")
    assert not (sr / "nostart.json").exists()


def test_a_no_start_record_re_claimed_by_its_own_pid_is_not_removed(P):
    """A no-start record naming a live pid is stale (a bare pid proves nothing). When that pid then
    really claims the name, the new record has a start and must not match the planned one."""
    jr, sr = P
    sr.mkdir(parents=True)
    launcher = subprocess.Popen(SLEEP)
    try:
        (sr / "s.json").write_text(json.dumps({"name": "s", "launcher_pid": launcher.pid}))
        dry = reaper.plan(jobs_root=jr, sessions_root=sr)
        sid = f"session:s@{launcher.pid}-nostart"
        assert ids(dry) == [sid] and dry.by_id()[sid].facts["status"] == "stale"
        sessions.claim(sr, "s", harness="claude", pid=launcher.pid)
        res = reaper.execute(dry, [sid], log=None, agent_grace=0.1, launcher_grace=0.1)
        assert res[0].outcome == "failed" and "re-claimed" in res[0].detail, res[0].detail
        assert json.loads((sr / "s.json").read_text())["launcher_pid"] == launcher.pid
        assert _alive_after_a_moment(launcher)
    finally:
        _cleanup(launcher)


def test_a_stale_record_rewritten_without_a_start_after_the_plan_is_not_removed(P):
    """The planned stale claim had a start; the record now on disk names the same pid with no start.
    That is not the planned record, so it stays."""
    jr, sr = P
    sr.mkdir(parents=True)
    (sr / "s.json").write_text(json.dumps({"name": "s", "launcher_pid": 999997, "launcher_start": 1.0}))
    dry = reaper.plan(jobs_root=jr, sessions_root=sr)
    assert ids(dry) == ["session:s@999997-1000"]
    (sr / "s.json").write_text(json.dumps({"name": "s", "launcher_pid": 999997}))
    res = reaper.execute(dry, ["session:s@999997-1000"], log=None)
    assert res[0].outcome == "failed" and "re-claimed" in res[0].detail, res[0].detail
    assert (sr / "s.json").exists()


def test_a_lost_job_without_identity_is_kept_and_one_with_identity_is_offered(P):
    jr, _ = P
    bystander = subprocess.Popen(SLEEP, start_new_session=True)
    try:
        for jid, extra in (("noid", {"pid": bystander.pid}),
                           ("withid", {"pid": bystander.pid, "pgid": bystander.pid,
                                       "pid_start": procid.start_time(bystander.pid)})):
            d = jr / jid
            d.mkdir(parents=True)
            (d / jobs.JOB_FILE).write_text(json.dumps({"id": jid, "name": jid, "argv": ["x"], "cwd": "/",
                                                       "created_at": time.time() - 3600, **extra}))
            (d / jobs.LOCK_FILE).touch()
        p = reaper.plan(jobs_root=jr)
        assert ids(p) == ["job:withid"]
        assert "lost (supervisor gone), command pid" in p.by_id()["job:withid"].detail
        assert [k.what for k in p.kept] == ["job:noid"]
        res = reaper.execute(p, ["job:withid"], log=None)
        assert res[0].outcome == "done"
        assert bystander.wait(timeout=20) is not None
    finally:
        _cleanup(bystander)


# ------------------------------------------------------------------ CLI

@needs_git
def test_cli_dry_run_then_confirm(R, capsys, monkeypatch):
    base = ["reap", "--no-processes", "--repo", str(R.repo)]
    assert cli_main(base) == 0
    out = capsys.readouterr().out
    assert "branch:item/merged" in out and "dry run: nothing was changed" in out
    assert git(R.repo, "branch", "--list", "item/merged") != ""
    assert cli_main([*base, "--json"]) == 0
    assert "branch:item/merged" in [c["id"] for c in json.loads(capsys.readouterr().out)["candidates"]]
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    log = R.tmp / "r.jsonl"
    assert cli_main([*base, "--confirm", "branch:item/nope", "--log", str(log)]) == 2
    assert "not in the current plan" in capsys.readouterr().err
    assert cli_main([*base, "--confirm", "branch:item/merged", "--log", str(log)]) == 0
    assert "done     branch:item/merged" in capsys.readouterr().out
    assert git(R.repo, "branch", "--list", "item/merged") == ""
    assert json.loads(log.read_text().splitlines()[0])["id"] == "branch:item/merged"
    # a skipped (needs its worktree) id makes the run exit 1
    assert cli_main([*base, "--confirm", "branch:item/wt-done", "--log", str(log)]) == 1


def test_cli_confirm_without_any_log_location_is_refused(tmp_path, monkeypatch, capsys):
    for v in ("CTF_WORKDIR", "CTF_EVENT", "CTF_JOBS_DIR", "CTF_SESSIONS_DIR"):
        monkeypatch.delenv(v, raising=False)
    jr = tmp_path / "jobs"
    assert cli_main(["reap", "--jobs-dir", str(jr), "--sessions-dir", str(tmp_path / "s"),
                     "--confirm", "job:x"]) == 2
    assert "no log location" in capsys.readouterr().err


def test_cli_without_a_workdir_names_the_missing_folder(monkeypatch, capsys):
    for v in ("CTF_WORKDIR", "CTF_EVENT", "CTF_JOBS_DIR", "CTF_SESSIONS_DIR"):
        monkeypatch.delenv(v, raising=False)
    assert cli_main(["reap"]) == 2
    assert "no jobs folder" in capsys.readouterr().err


@needs_git
def test_locked_and_missing_worktrees_are_kept(R):
    git(R.repo, "worktree", "lock", str(R.wts / "done"))
    p = R.plan()
    kept = {k.what: k.reason for k in p.kept}
    assert kept[f"worktree:{R.wts / 'done'}"].startswith("locked")
    assert "branch:item/wt-done" in kept                       # its branch stays checked out
    git(R.repo, "worktree", "unlock", str(R.wts / "done"))
    import shutil
    shutil.rmtree(R.wts / "done")
    p = R.plan()
    kept = {k.what: k.reason for k in p.kept}
    assert kept[f"worktree:{R.wts / 'done'}"].startswith("missing on disk")
    assert f"worktree:{R.wts / 'done'}" not in ids(p)
