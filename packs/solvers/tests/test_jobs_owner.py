"""B-175: named jobs with owners, exact identities and pidfiles (ctf/jobs.py additions, ctf job list/stop/reap).

The B-144 behaviour (start/wait/kill/prune) is covered by tests/test_jobs.py; this file covers what
B-175 adds. Every command is a synthetic python sleeper.
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time

import pytest

from ctf import jobs, procid
from ctf.cli import main as cli_main

PY = sys.executable
SLEEP = [PY, "-c", "import time; time.sleep(60)"]


@pytest.fixture
def root(tmp_path, monkeypatch):
    for v in (jobs.OWNER_ENV, jobs.OWNER_PID_ENV):
        monkeypatch.delenv(v, raising=False)
    r = tmp_path / "jobs"
    yield r
    for st in jobs.list_jobs(r):          # never leave a test's job running
        if st.state == "running" and isinstance(st.job.get("supervisor_pid"), int):
            try:
                jobs.kill(st.dir)
            except jobs.JobError:
                pass


def _sleeper(*, new_session=False):
    return subprocess.Popen(SLEEP, start_new_session=new_session)


def _cleanup(*ps):
    for p in ps:
        if p.poll() is None:
            p.kill()
        p.wait()


def _fake(root, job_id, *, name="fake", extra=None, created_at=None):
    d = root / job_id
    d.mkdir(parents=True)
    rec = {"id": job_id, "name": name, "argv": ["fake"], "cwd": str(root),
           "created_at": time.time() - 3600 if created_at is None else created_at}
    rec.update(extra or {})
    (d / jobs.JOB_FILE).write_text(json.dumps(rec))
    (d / jobs.LOCK_FILE).touch()
    (d / jobs.LOG_FILE).touch()
    return d


# ------------------------------------------------------------------ the record

def test_start_records_owner_identity_pgid_start_times_and_a_pidfile(root):
    me = os.getpid()
    job = jobs.start(SLEEP, root=root, name="brute", owner="agent-1", owner_pid=me)
    rec = json.loads((job.dir / jobs.JOB_FILE).read_text())
    assert rec["owner"] == "agent-1" and rec["owner_pid"] == me
    assert procid.same_start(rec["owner_start"], procid.start_time(me))
    assert rec["pid"] == job.pid and rec["pgid"] == job.pid          # the command leads its group
    assert procid.matches(job.pid, rec["pid_start"])
    assert procid.matches(rec["supervisor_pid"], rec["supervisor_start"])
    assert (job.dir / jobs.PID_FILE).read_text() == f"{job.pid}\n"
    st = jobs.state(job.dir)
    assert jobs.command_status(st) == "alive" and jobs.owner_status(st) == "alive"


def test_owner_defaults_come_from_the_launcher_environment(root, monkeypatch):
    holder = _sleeper()
    try:
        monkeypatch.setenv(jobs.OWNER_ENV, "codex-7-123-abc")
        monkeypatch.setenv(jobs.OWNER_PID_ENV, str(holder.pid))
        job = jobs.start(SLEEP, root=root, name="x")
        rec = json.loads((job.dir / jobs.JOB_FILE).read_text())
        assert (rec["owner"], rec["owner_pid"]) == ("codex-7-123-abc", holder.pid)
        _cleanup(holder)
        assert jobs.owner_status(jobs.state(job.dir)) == "gone"      # an orphan now
    finally:
        _cleanup(holder)


def test_no_owner_records_none(root):
    job = jobs.start(SLEEP, root=root, name="x")
    rec = json.loads((job.dir / jobs.JOB_FILE).read_text())
    assert "owner" not in rec and jobs.owner_status(jobs.state(job.dir)) == "none"


def test_owner_errors_are_named_and_start_nothing(root):
    dead = subprocess.Popen([PY, "-c", "pass"])
    dead.wait()
    with pytest.raises(jobs.JobError, match=f"owner pid {dead.pid} .*not a live process"):
        jobs.start(SLEEP, root=root, owner="a", owner_pid=dead.pid)
    with pytest.raises(jobs.JobError, match="needs an owner name"):
        jobs.start(SLEEP, root=root, owner_pid=os.getpid())
    with pytest.raises(jobs.JobError, match="bad owner"):
        jobs.start(SLEEP, root=root, owner="a b")
    with pytest.raises(jobs.JobError, match="bad owner pid"):
        jobs.start(SLEEP, root=root, owner="a", owner_pid="x1")
    assert jobs.list_jobs(root) == []


# ------------------------------------------------------------------ names

def test_exclusive_refuses_a_second_live_job_of_the_same_name(root):
    first = jobs.start(SLEEP, root=root, name="crack", exclusive=True)
    with pytest.raises(jobs.JobError, match=rf"a live job named 'crack' already exists \({first.id}\)"):
        jobs.start(SLEEP, root=root, name="crack", exclusive=True)
    assert len(jobs.list_jobs(root)) == 1
    other = jobs.start(SLEEP, root=root, name="crack")       # not exclusive: allowed
    jobs.kill(first.dir)
    jobs.kill(other.dir)
    again = jobs.start(SLEEP, root=root, name="crack", exclusive=True)   # nothing live now
    assert again.id != first.id


def test_a_name_resolves_to_its_one_live_job(root):
    a = jobs.start(SLEEP, root=root, name="alpha")
    assert jobs.job_dir(root, "alpha") == a.dir
    assert jobs.job_dir(root, a.id) == a.dir
    b = jobs.start(SLEEP, root=root, name="alpha")
    with pytest.raises(jobs.JobError, match="ambiguous: 2 live jobs"):
        jobs.job_dir(root, "alpha")
    jobs.kill(a.dir)
    jobs.kill(b.dir)
    with pytest.raises(jobs.JobError, match="neither an id nor the name of a live job"):
        jobs.job_dir(root, "alpha")


# ------------------------------------------------------------------ exact identity before a signal

def test_kill_refuses_a_session_leader_whose_start_time_differs(root):
    leader = _sleeper(new_session=True)      # passes the B-144 getsid check, but is not our supervisor
    try:
        d = _fake(root, "reused-2", extra={"supervisor_pid": leader.pid, "pid": leader.pid,
                                           "supervisor_start": procid.start_time(leader.pid) - 30.0})
        with open(d / jobs.LOCK_FILE, "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            assert jobs.state(d).state == "running"
            with pytest.raises(jobs.JobError, match="pid was reused"):
                jobs.kill(d, timeout=1.0)
        time.sleep(0.2)
        assert leader.poll() is None, "a reused supervisor pid was signalled"
    finally:
        _cleanup(leader)


def test_kill_lost_stops_the_group_by_exact_identity_and_closes_the_record(root):
    code = ("import subprocess, sys, time\n"
            "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print(c.pid, flush=True)\n"
            "time.sleep(60)\n")
    cmd = subprocess.Popen([PY, "-c", code], start_new_session=True, stdout=subprocess.PIPE, text=True)
    try:
        child = int(cmd.stdout.readline())
        cstart = procid.start_time(child)
        d = _fake(root, "lost-1", extra={"pid": cmd.pid, "pgid": cmd.pid,
                                         "pid_start": procid.start_time(cmd.pid),
                                         "supervisor_pid": 999999, "started_at": time.time() - 10})
        assert jobs.state(d).state == "lost"
        st = jobs.kill_lost(d, grace=0.5, timeout=20)
        assert st.state == "exited" and st.exit["lost"] and st.exit["killed"]
        assert st.exit["killed_by"] == "reap"
        assert cmd.wait(timeout=20) is not None
        end = time.monotonic() + 20
        while procid.status(child, cstart) == "alive" and time.monotonic() < end:
            time.sleep(0.05)
        assert procid.status(child, cstart) != "alive", "the lost job's group was not stopped"
        assert "lost, then stopped by reap" in jobs.describe(st)
    finally:
        _cleanup(cmd)


def test_kill_lost_never_signals_a_reused_pid_and_refuses_without_identity(root):
    bystander = _sleeper(new_session=True)
    try:
        d = _fake(root, "lost-2", extra={"pid": bystander.pid, "pgid": bystander.pid,
                                         "pid_start": procid.start_time(bystander.pid) - 40.0})
        st = jobs.kill_lost(d)
        assert st.state == "exited" and st.exit["killed"] is False and "reused" in st.exit["note"]
        d3 = _fake(root, "lost-3", extra={"pid": bystander.pid, "pgid": bystander.pid})  # no pid_start
        with pytest.raises(jobs.JobError, match="no exact identity recorded"):
            jobs.kill_lost(d3)
        d4 = _fake(root, "lost-4", extra={"pid": bystander.pid,
                                          "pid_start": procid.start_time(bystander.pid)})   # no pgid
        with pytest.raises(jobs.JobError, match="no process group recorded"):
            jobs.kill_lost(d4)
        time.sleep(0.2)
        assert bystander.poll() is None
    finally:
        _cleanup(bystander)


def test_kill_lost_refuses_a_job_that_is_not_lost(root):
    job = jobs.start(SLEEP, root=root, name="x")
    with pytest.raises(jobs.JobError, match="is not lost"):
        jobs.kill_lost(job.dir)


# ------------------------------------------------------------------ reap by owner

def test_reap_stops_only_the_owners_live_jobs(root):
    a1 = jobs.start(SLEEP, root=root, name="a1", owner="agent-A")
    a2 = jobs.start(SLEEP, root=root, name="a2", owner="agent-A")
    b1 = jobs.start(SLEEP, root=root, name="b1", owner="agent-B")
    n1 = jobs.start(SLEEP, root=root, name="n1")
    dry = jobs.reap(root, owner="agent-A", dry_run=True)
    assert sorted(r.id for r in dry) == sorted([a1.id, a2.id])
    assert {r.outcome for r in dry} == {"would_stop"}
    assert jobs.state(a1.dir).state == "running"
    got = jobs.reap(root, owner="agent-A")
    assert sorted((r.id, r.outcome) for r in got) == sorted([(a1.id, "stopped"), (a2.id, "stopped")])
    assert jobs.state(a1.dir).state == "exited" and jobs.state(a2.dir).state == "exited"
    assert jobs.state(b1.dir).state == "running" and jobs.state(n1.dir).state == "running"
    assert jobs.reap(root, owner="agent-A") == []
    with pytest.raises(jobs.JobError, match="bad owner"):
        jobs.reap(root, owner="")


def test_reap_closes_a_lost_job_whose_command_is_gone(root):
    gone = subprocess.Popen([PY, "-c", "pass"], start_new_session=True)
    start = procid.start_time(gone.pid) or time.time()
    gone.wait()
    d = _fake(root, "lost-own", extra={"owner": "agent-C", "pid": gone.pid, "pgid": gone.pid,
                                       "pid_start": start})
    got = jobs.reap(root, owner="agent-C")
    assert [(r.id, r.outcome) for r in got] == [("lost-own", "closed")]
    assert jobs.state(d).state == "exited"


# ------------------------------------------------------------------ CLI

def test_cli_list_stop_and_reap(root, capsys):
    j = jobs.start(SLEEP, root=root, name="brute", owner="agent-Z")
    k = jobs.start(SLEEP, root=root, name="other", owner="agent-Y")
    assert cli_main(["job", "list", "--jobs-dir", str(root), "--owner", "agent-Z", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["id"] for r in rows] == [j.id]
    r = rows[0]
    assert (r["name"], r["owner"], r["pid"], r["pgid"], r["state"]) == ("brute", "agent-Z", j.pid, j.pid,
                                                                        "running")
    assert r["pidfile"] == str(j.dir / jobs.PID_FILE)
    assert cli_main(["job", "list", "--jobs-dir", str(root), "--live"]) == 0
    out = capsys.readouterr().out
    assert "owner=agent-Z" in out and "owner=agent-Y" in out
    assert cli_main(["job", "stop", "brute", "--jobs-dir", str(root)]) == 0
    assert jobs.state(j.dir).state == "exited"
    capsys.readouterr()
    assert cli_main(["job", "reap", "--owner", "agent-Y", "--jobs-dir", str(root)]) == 0
    out = capsys.readouterr().out
    assert f"stopped     {k.id}" in out
    assert jobs.state(k.dir).state == "exited"
    assert cli_main(["job", "start", "--jobs-dir", str(root), "--name", "q", "--owner", "bad owner",
                     "--", *SLEEP]) == 2
    assert "bad owner" in capsys.readouterr().err


def test_cli_start_exclusive(root, capsys):
    assert cli_main(["job", "start", "--jobs-dir", str(root), "--name", "solo", "--exclusive",
                     "--", *SLEEP]) == 0
    capsys.readouterr()
    assert cli_main(["job", "start", "--jobs-dir", str(root), "--name", "solo", "--exclusive",
                     "--", *SLEEP]) == 2
    assert "already exists" in capsys.readouterr().err


def test_cli_stop_closes_a_lost_job_whose_command_is_gone(root, capsys):
    gone = subprocess.Popen([PY, "-c", "pass"], start_new_session=True)
    start = procid.start_time(gone.pid) or time.time()
    gone.wait()
    d = _fake(root, "lost-cli", extra={"pid": gone.pid, "pgid": gone.pid, "pid_start": start})
    assert cli_main(["job", "stop", "lost-cli", "--jobs-dir", str(root)]) == 0
    st = jobs.state(d)
    assert st.state == "exited" and st.exit["lost"] and st.exit["killed"] is False
    assert "closed: command already gone" in capsys.readouterr().out


# ------------------------------------------------------------------ verification round 1

def _gone_identity():
    gone = subprocess.Popen([PY, "-c", "pass"], start_new_session=True)
    start = procid.start_time(gone.pid) or time.time()
    gone.wait()
    return {"pid": gone.pid, "pgid": gone.pid, "pid_start": start}


def test_kill_lost_records_the_signal_that_actually_ended_the_command(root):
    import signal as _signal
    # dies on TERM: exit.json says SIGTERM (generous grace so a loaded machine never escalates;
    # the wait ends as soon as the command is gone)
    soft = _sleeper(new_session=True)
    try:
        d = _fake(root, "lost-soft", extra={"pid": soft.pid, "pgid": soft.pid,
                                            "pid_start": procid.start_time(soft.pid)})
        st = jobs.kill_lost(d, grace=60, timeout=20)
        assert st.exit["killed"] is True and st.exit["signal"] == "SIGTERM"
        assert soft.wait(timeout=20) == -_signal.SIGTERM
    finally:
        _cleanup(soft)
    # ignores TERM: the KILL ended it, and exit.json must say SIGKILL, not SIGTERM
    code = ("import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n")
    hard = subprocess.Popen([PY, "-c", code], start_new_session=True, stdout=subprocess.PIPE, text=True)
    try:
        assert hard.stdout.readline().strip() == "ready"
        d = _fake(root, "lost-hard", extra={"pid": hard.pid, "pgid": hard.pid,
                                            "pid_start": procid.start_time(hard.pid)})
        st = jobs.kill_lost(d, grace=0.3, timeout=20)
        assert st.exit["killed"] is True and st.exit["signal"] == "SIGKILL"
        assert hard.wait(timeout=20) == -_signal.SIGKILL
    finally:
        _cleanup(hard)


def test_a_lost_job_whose_command_is_gone_does_not_hold_its_name(root):
    dead = _fake(root, "solo-dead", name="solo", extra=_gone_identity())
    assert jobs.state(dead).state == "lost"
    assert jobs.holds_name(jobs.state(dead)) is False
    # alone under its name it is still found by name (so `ctf job stop solo` can close it) ...
    assert jobs.job_dir(root, "solo") == dead
    # ... but it neither blocks an exclusive start of the name ...
    live = jobs.start(SLEEP, root=root, name="solo", exclusive=True)
    # ... nor makes the name ambiguous: the name now means the job that holds it
    assert jobs.job_dir(root, "solo") == live.dir
    assert jobs.state(dead).state == "lost"                    # untouched, still there to close


def test_a_lost_job_whose_command_still_runs_or_is_unprovable_holds_its_name(root):
    cmd = _sleeper(new_session=True)
    try:
        _fake(root, "held-alive", name="held", extra={"pid": cmd.pid, "pgid": cmd.pid,
                                                      "pid_start": procid.start_time(cmd.pid)})
        with pytest.raises(jobs.JobError, match="a live job named 'held' already exists"):
            jobs.start(SLEEP, root=root, name="held", exclusive=True)
        _fake(root, "unk-1", name="unk", extra={"pid": cmd.pid})                  # no start time
        with pytest.raises(jobs.JobError, match="a live job named 'unk' already exists"):
            jobs.start(SLEEP, root=root, name="unk", exclusive=True)
        _fake(root, "reu-1", name="reu", extra={"pid": cmd.pid, "pgid": cmd.pid,
                                                "pid_start": procid.start_time(cmd.pid) - 50.0})
        with pytest.raises(jobs.JobError, match="a live job named 'reu' already exists"):
            jobs.start(SLEEP, root=root, name="reu", exclusive=True)
        _fake(root, "unk-2", name="unk", extra=_gone_identity())
        assert jobs.job_dir(root, "unk") == root / "unk-1"   # the gone one does not compete
    finally:
        _cleanup(cmd)
