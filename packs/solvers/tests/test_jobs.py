"""B-144: no-model job wait (ctf/jobs.py, `python -m ctf job`).

Every job here is a small Python program written in the test; nothing external runs. A gated job
waits for a file the test creates, so timing never decides an outcome.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctf import jobs
from ctf.cli import main as cli_main

PY = sys.executable
REPO = Path(__file__).resolve().parent.parent

# Waits (at most 30 s) for the gate file argv[1], prints a marker, exits with argv[2].
GATED = (
    "import os, sys, time\n"
    "g = sys.argv[1]\n"
    "end = time.time() + 30\n"
    "while not os.path.exists(g) and time.time() < end:\n"
    "    time.sleep(0.02)\n"
    "print('done-marker', flush=True)\n"
    "sys.exit(int(sys.argv[2]))\n"
)


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "jobs"
    yield r
    for st in jobs.list_jobs(r):          # never leave a test's job running
        if st.state == "running" and isinstance(st.job.get("supervisor_pid"), int):
            try:
                jobs.kill(st.dir)
            except jobs.JobError:
                pass
        pid = st.job.get("pid")
        if isinstance(pid, int) and st.state in ("running", "lost"):   # an exited pid may be reused
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass


def gated(tmp_path, rc=0, name="g"):
    gate = tmp_path / f"gate-{name}"
    return gate, [PY, "-c", GATED, str(gate), str(rc)]


def until(pred, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.02)
    return pred()


# ------------------------------------------------------------------ start / wait

def test_start_returns_while_the_command_runs_and_wait_wakes_once_at_exit(root, tmp_path):
    gate, argv = gated(tmp_path)
    t0 = time.monotonic()
    job = jobs.start(argv, root=root, name="bench")
    assert time.monotonic() - t0 < 10
    assert job.id.startswith("bench-")
    st = jobs.state(job.dir)
    assert st.state == "running" and st.job["pid"] == job.pid
    code, states = jobs.wait([job.id], root=root, timeout=0.3)
    assert code == jobs.EXIT_TIMEOUT and states[0].state == "running"
    gate.touch()
    code, states = jobs.wait([job.id], root=root, timeout=20)
    assert code == jobs.EXIT_OK
    st = states[0]
    assert st.state == "exited" and st.exit["rc"] == 0 and st.exit["killed"] is False
    msg = jobs.summary(st)
    assert msg.startswith(f"job {job.id}: exited rc=0")
    assert str(job.log) in msg and "done-marker" in msg
    assert (job.dir / jobs.SUMMARY_FILE).read_text() == jobs.summary(st)


def test_nonzero_exit_is_wait_code_1_and_names_the_rc(root, tmp_path):
    gate, argv = gated(tmp_path, rc=3)
    gate.touch()
    job = jobs.start(argv, root=root)
    code, (st,) = jobs.wait([job.id], root=root, timeout=20)
    assert code == jobs.EXIT_FAILED
    assert st.exit["rc"] == 3 and "exited rc=3" in jobs.summary(st)


def test_command_gets_job_id_and_runs_in_cwd(root, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    job = jobs.start([PY, "-c", "import os; print(os.environ['CTF_JOB_ID']); print(os.getcwd())"],
                     root=root, cwd=work)
    code, (st,) = jobs.wait([job.id], root=root, timeout=20)
    assert code == 0
    out = job.log.read_text().split("\n")
    assert out[0] == job.id
    assert Path(out[1]).resolve() == work.resolve()


def test_wait_all_and_any(root, tmp_path):
    gate_a, a = gated(tmp_path, name="a")
    gate_b, b = gated(tmp_path, name="b")
    ja = jobs.start(a, root=root, name="a")
    jb = jobs.start(b, root=root, name="b")
    gate_a.touch()
    code, states = jobs.wait([ja.id, jb.id], root=root, any_=True, timeout=20)
    assert code == jobs.EXIT_OK
    assert {s.id: s.state for s in states}[ja.id] == "exited"
    assert {s.id: s.state for s in states}[jb.id] == "running"
    code, _ = jobs.wait([ja.id, jb.id], root=root, timeout=0.3)
    assert code == jobs.EXIT_TIMEOUT
    gate_b.touch()
    code, states = jobs.wait([ja.id, jb.id], root=root, timeout=20)
    assert code == jobs.EXIT_OK and all(s.state == "exited" for s in states)


def test_combined_code_precedence():
    def s(state, rc=None):
        return jobs.JobState("x", Path("."), state, {}, None if rc is None else {"rc": rc})
    assert jobs.combined_code([s("exited", 0), s("exited", 2)]) == jobs.EXIT_FAILED
    assert jobs.combined_code([s("exited", 1), s("running")]) == jobs.EXIT_TIMEOUT
    assert jobs.combined_code([s("running"), s("lost")]) == jobs.EXIT_ERROR
    assert jobs.combined_code([s("exited", 0), s("running")], any_=True) == jobs.EXIT_OK
    assert jobs.combined_code([s("running")], any_=True) == jobs.EXIT_TIMEOUT


# ------------------------------------------------------------------ detachment, kill, lost

def test_job_survives_the_callers_process_group_being_killed(root, tmp_path):
    """A harness that kills the tool call's process group must not take the job with it."""
    gate, argv = gated(tmp_path)
    inner = " ".join(subprocess.list2cmdline([a]) for a in
                     [PY, "-m", "ctf", "job", "start", "--jobs-dir", str(root), "--name", "surv", "--", *argv])
    caller = subprocess.Popen(["/bin/sh", "-c", f"{inner}; exec sleep 60"], cwd=REPO,
                              start_new_session=True, stdout=subprocess.PIPE, text=True)
    try:
        first = caller.stdout.readline()
        assert first.startswith("job surv-"), first
        job_id = first.split()[1]
    finally:
        os.killpg(caller.pid, signal.SIGKILL)
        caller.wait()
    d = jobs.job_dir(root, job_id)
    st = jobs.state(d)
    assert st.state == "running"
    sup, pid = st.job["supervisor_pid"], st.job["pid"]
    assert os.getsid(sup) == sup != caller.pid       # its own session, not the caller's
    assert os.getsid(pid) == pid                     # the command leads its own group
    gate.touch()
    code, (st,) = jobs.wait([job_id], root=root, timeout=20)
    assert code == jobs.EXIT_OK and "done-marker" in jobs.summary(st)


def test_kill_stops_the_command_and_its_children(root, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    prog = (
        "import subprocess, sys, time\n"
        "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(g.pid))\n"
        "time.sleep(60)\n"
    )
    job = jobs.start([PY, "-c", prog], root=root, name="tree")
    gpid = int(until(lambda: pidfile.is_file() and pidfile.read_text().strip()))
    st = jobs.kill(job.dir)
    assert st.state == "exited" and st.exit["killed"] is True
    assert st.exit["signal"] == "SIGTERM" and st.exit["rc"] == -signal.SIGTERM

    def gone():
        try:
            os.kill(gpid, 0)
        except ProcessLookupError:
            return True
        return False
    assert until(gone, 5), "the job's child survived ctf job kill"
    code, _ = jobs.wait([job.id], root=root, timeout=5)
    assert code == jobs.EXIT_FAILED
    with pytest.raises(jobs.JobError, match="not running"):
        jobs.kill(job.dir)


def test_a_dead_supervisor_is_reported_lost_not_running(root, tmp_path):
    gate, argv = gated(tmp_path)
    job = jobs.start(argv, root=root)
    os.kill(job.supervisor_pid, signal.SIGKILL)
    try:
        os.waitpid(job.supervisor_pid, 0)
    except ChildProcessError:
        pass
    st = until(lambda: (s := jobs.state(job.dir)).state == "lost" and s)
    assert st and st.state == "lost"
    assert "LOST" in jobs.describe(st) and str(job.pid) in jobs.describe(st)
    code, _ = jobs.wait([job.id], root=root, timeout=5)
    assert code == jobs.EXIT_ERROR
    os.killpg(job.pid, signal.SIGKILL)


# ------------------------------------------------------------------ loud failures

def test_missing_command_fails_at_start_and_creates_no_job(root):
    with pytest.raises(jobs.JobError, match="command not found on PATH: no-such-tool-b144"):
        jobs.start(["no-such-tool-b144", "--x"], root=root)
    with pytest.raises(jobs.JobError, match="no command"):
        jobs.start([], root=root)
    with pytest.raises(jobs.JobError, match="no-such-hook-b144"):
        jobs.start([PY, "-c", "pass"], root=root, on_exit=["no-such-hook-b144"])
    assert jobs.list_jobs(root) == []


def test_command_that_cannot_exec_is_failed_to_start(root, tmp_path):
    bad = tmp_path / "bad-interp"
    bad.write_text("#!/nonexistent/interpreter-b144\n")
    bad.chmod(0o755)
    with pytest.raises(jobs.JobError, match="did not start"):
        jobs.start([str(bad)], root=root)
    (st,) = jobs.list_jobs(root)
    assert st.state == "failed_to_start"
    code, _ = jobs.wait([st.id], root=root, timeout=1)
    assert code == jobs.EXIT_ERROR


def test_job_ids_are_checked(root, tmp_path):
    with pytest.raises(jobs.JobError, match="no jobs"):
        jobs.job_dir(root, "last")
    with pytest.raises(jobs.JobError, match="bad job id"):
        jobs.job_dir(root, "../etc")
    with pytest.raises(jobs.JobError, match="no job 'nope'"):
        jobs.wait(["nope"], root=root, timeout=0)
    j1 = jobs.start([PY, "-c", "pass"], root=root, name="one")
    time.sleep(0.01)
    j2 = jobs.start([PY, "-c", "pass"], root=root, name="two")
    assert jobs.job_dir(root, "last") == j2.dir
    assert [s.id for s in jobs.list_jobs(root)] == [j2.id, j1.id]


def test_jobs_root_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_JOBS_DIR", str(tmp_path / "env-jobs"))
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    assert jobs.jobs_root(tmp_path / "flag") == (tmp_path / "flag").resolve()
    assert jobs.jobs_root() == (tmp_path / "env-jobs").resolve()
    monkeypatch.delenv("CTF_JOBS_DIR")
    assert jobs.jobs_root() == (tmp_path / "wd").resolve() / "jobs"
    monkeypatch.delenv("CTF_WORKDIR")
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b144")
    with pytest.raises(jobs.JobError, match="CTF_JOBS_DIR"):
        jobs.jobs_root()


# ------------------------------------------------------------------ the wake message

def test_wake_message_tail_is_short_and_stripped(root, tmp_path):
    prog = ("import sys\n"
            "for i in range(500): print(f'row-{i:03d}')\n"
            "print('\\x1b[31mRED\\x1b[0m\\x07bell')\n")
    job = jobs.start([PY, "-c", prog], root=root)
    code, (st,) = jobs.wait([job.id], root=root, timeout=20)
    assert code == 0
    msg = jobs.summary(st, lines=5)
    assert "row-499" in msg and "row-496" in msg and "row-495" not in msg
    assert "REDbell" in msg and "\x1b" not in msg and "\x07" not in msg
    assert "last 5 line(s)" in msg


def test_wake_message_is_byte_capped(tmp_path):
    log = tmp_path / "out.log"
    log.write_text("".join("x" * 250 + f"{i}\n" for i in range(100)))
    text = jobs.tail_text(log, 50, 2000)
    assert len(text) <= 2000 + len("[...] ")
    assert text.startswith("[...] ") and text.endswith("99")
    long = tmp_path / "long.log"
    long.write_text("y" * 5000 + "\n")
    assert jobs.tail_text(long, 1, 10_000) == "y" * jobs.TAIL_LINE_CHARS + " [...]"
    big = tmp_path / "big.log"
    big.write_bytes(b"z" * 100_000 + b"\nlast\n")
    assert jobs.tail_text(big, 5, 2000) == "last"      # the partial first chunk line is dropped


def test_on_exit_hook_wakes_once_with_status_on_stdin(root, tmp_path):
    rec = tmp_path / "hook.jsonl"
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json, os, sys\n"
        f"with open({str(rec)!r}, 'a') as f:\n"
        "    f.write(json.dumps({'stdin': sys.stdin.read(),\n"
        "        'env': {k: v for k, v in os.environ.items() if k.startswith('CTF_JOB_')}}) + '\\n')\n")
    gate, argv = gated(tmp_path, rc=5)
    gate.touch()
    job = jobs.start(argv, root=root, on_exit=[PY, str(hook)])
    code, _ = jobs.wait([job.id], root=root, timeout=20)
    assert code == jobs.EXIT_FAILED
    assert until(lambda: (job.dir / jobs.HOOK_FILE).is_file())
    lines = rec.read_text().splitlines()
    assert len(lines) == 1
    got = json.loads(lines[0])
    assert got["env"]["CTF_JOB_ID"] == job.id and got["env"]["CTF_JOB_RC"] == "5"
    assert got["env"]["CTF_JOB_LOG"] == str(job.log)
    assert f"job {job.id}: exited rc=5" in got["stdin"] and "done-marker" in got["stdin"]
    assert json.loads((job.dir / jobs.HOOK_FILE).read_text())["rc"] == 0


# ------------------------------------------------------------------ CLI

def test_cli_run_prints_the_wake_message_and_exit_code(root, capsys):
    rc = cli_main(["job", "run", "--jobs-dir", str(root), "--name", "cli", "--",
                   PY, "-c", "print('hello-b144'); raise SystemExit(4)"])
    out = capsys.readouterr().out
    assert rc == jobs.EXIT_FAILED
    assert "exited rc=4" in out and "hello-b144" in out


def test_cli_start_wait_status_tail_kill(root, tmp_path, capsys):
    gate, argv = gated(tmp_path)
    assert cli_main(["job", "start", "--jobs-dir", str(root), "--name", "c", "--", *argv]) == 0
    out = capsys.readouterr().out
    job_id = out.split()[1]
    assert f"python -m ctf job wait {job_id}" in out
    assert cli_main(["job", "wait", "--jobs-dir", str(root), "--timeout", "0.2", "last"]) == 124
    assert "keeps running" in capsys.readouterr().out
    assert cli_main(["job", "status", "--jobs-dir", str(root)]) == 0
    assert f"{job_id}  running" in capsys.readouterr().out
    gate.touch()
    assert cli_main(["job", "wait", "--jobs-dir", str(root), "--tail", "0", job_id]) == 0
    out = capsys.readouterr().out
    assert "exited rc=0" in out and "done-marker" not in out
    assert cli_main(["job", "tail", "--jobs-dir", str(root), job_id, "-n", "1"]) == 0
    assert capsys.readouterr().out.strip() == "done-marker"
    assert cli_main(["job", "kill", "--jobs-dir", str(root), job_id]) == jobs.EXIT_ERROR
    assert "is not running" in capsys.readouterr().err


def test_cli_errors_are_named_and_exit_2(root, capsys):
    assert cli_main(["job", "start", "--jobs-dir", str(root)]) == 2
    assert "no command" in capsys.readouterr().err
    assert cli_main(["job", "wait", "--jobs-dir", str(root), "nope"]) == 2
    assert "ctf job: no job 'nope'" in capsys.readouterr().err
    assert cli_main(["job", "start", "--jobs-dir", str(root), "--on-exit", "a 'b", "--", PY]) == 2
    assert "--on-exit" in capsys.readouterr().err


def test_cli_run_timeout_leaves_the_job_running(root, tmp_path, capsys):
    gate, argv = gated(tmp_path)
    rc = cli_main(["job", "run", "--jobs-dir", str(root), "--timeout", "0.2", "--", *argv])
    assert rc == jobs.EXIT_TIMEOUT
    (st,) = jobs.list_jobs(root)
    assert st.state == "running"
    gate.touch()
    assert jobs.wait([st.id], root=root, timeout=20)[0] == 0


# ------------------------------------------------------------------ the agent rules teach it

def test_agent_rules_teach_the_job_wait_and_ban_poll_loops():
    from ctf import event, eventrules
    body = eventrules.split_header(eventrules.render(event.load("huntress"))["AGENTS.md"])[1]
    section = body.split("## Long-running commands", 1)[1].split("\n## ", 1)[0]
    for needle in ("python -m ctf job start", "python -m ctf job wait", "python -m ctf job run",
                   "`sleep`", "`ps`", "write_stdin", "124"):
        assert needle in section, needle


# ------------------------------------------------------------------ verification round 1

def test_job_gets_default_int_and_hup_dispositions(root):
    """The supervisor shields itself from HUP/INT; the command must not inherit that shield."""
    prog = ("import os, signal, time\n"
            "print('int-default', signal.getsignal(signal.SIGINT) is signal.default_int_handler)\n"
            "print('hup-default', signal.getsignal(signal.SIGHUP) == signal.SIG_DFL, flush=True)\n"
            "os.kill(os.getpid(), signal.SIGHUP)\n"
            "time.sleep(5)\n"
            "print('survived-hup')\n")
    job = jobs.start([PY, "-c", prog], root=root, name="sig")
    code, (st,) = jobs.wait([job.id], root=root, timeout=20)
    out = job.log.read_text()
    assert "int-default True" in out and "hup-default True" in out, out
    assert "survived-hup" not in out
    assert code == jobs.EXIT_FAILED and st.exit["rc"] == -signal.SIGHUP
    assert st.exit["killed"] is False


def test_supervisor_survives_a_stray_hup_and_int(root, tmp_path):
    gate, argv = gated(tmp_path)
    job = jobs.start(argv, root=root)
    os.kill(job.supervisor_pid, signal.SIGHUP)
    os.kill(job.supervisor_pid, signal.SIGINT)
    time.sleep(0.3)
    assert jobs.state(job.dir).state == "running"
    gate.touch()
    code, (st,) = jobs.wait([job.id], root=root, timeout=20)
    assert code == jobs.EXIT_OK and st.exit["rc"] == 0


def _fake_job(root, job_id, *, exit=None, created_at=None, on_exit=None, extra=None):
    d = root / job_id
    d.mkdir(parents=True)
    rec = {"id": job_id, "name": "fake", "argv": ["fake"], "cwd": str(root),
           "created_at": time.time() if created_at is None else created_at, "on_exit": on_exit}
    rec.update(extra or {})
    (d / jobs.JOB_FILE).write_text(json.dumps(rec))
    (d / jobs.LOCK_FILE).touch()
    (d / jobs.LOG_FILE).touch()
    if exit is not None:
        (d / jobs.EXIT_FILE).write_text(json.dumps(exit))
    return d


def test_kill_refuses_a_supervisor_pid_that_is_not_a_session_leader(root):
    """pid reuse: the recorded supervisor pid now names some other process, which must not be signalled."""
    import fcntl
    bystander = subprocess.Popen([PY, "-c", "import time; time.sleep(30)"])   # not a session leader
    try:
        assert os.getsid(bystander.pid) != bystander.pid
        d = _fake_job(root, "reused-1", extra={"supervisor_pid": bystander.pid})
        with open(d / jobs.LOCK_FILE, "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)           # a live supervisor's lock: the job reads running
            assert jobs.state(d).state == "running"
            with pytest.raises(jobs.JobError, match="refused to signal"):
                jobs.kill(d, timeout=1.0)
        time.sleep(0.1)
        assert bystander.poll() is None, "kill signalled a process that is not the job's supervisor"
    finally:
        bystander.kill()
        bystander.wait()
        import shutil
        shutil.rmtree(root / "reused-1", ignore_errors=True)   # the fixture must not act on a dead pid


def test_relative_command_resolves_against_cwd_not_the_callers(root, tmp_path, monkeypatch):
    tooldir, elsewhere = tmp_path / "tooldir", tmp_path / "elsewhere"
    tooldir.mkdir()
    elsewhere.mkdir()
    tool = tooldir / "tool.sh"
    tool.write_text("#!/bin/sh\necho rel-ok\n")
    tool.chmod(0o755)
    monkeypatch.chdir(elsewhere)
    job = jobs.start(["./tool.sh"], root=root, cwd=tooldir)
    code, _ = jobs.wait([job.id], root=root, timeout=20)
    assert code == jobs.EXIT_OK and "rel-ok" in job.log.read_text()
    # and the other way round: ./tool.sh in the caller's folder but not in --cwd fails at start
    monkeypatch.chdir(tooldir)
    with pytest.raises(jobs.JobError, match=r"not executable: \./tool\.sh"):
        jobs.start(["./tool.sh"], root=root, cwd=elsewhere)


def test_a_term_that_arrives_before_the_command_spawns_is_replayed(root, tmp_path):
    """Deterministic early TERM: output.log is a FIFO, so the supervisor blocks opening it after
    arming its TERM handler and before spawning the command. TERM lands in that window; the
    command must then be stopped as soon as it exists, not left to run."""
    gate, argv = gated(tmp_path)                      # the gate is never opened: runs ~30 s
    d = root / "early-1"
    d.mkdir(parents=True)
    (d / jobs.JOB_FILE).write_text(json.dumps({"id": "early-1", "name": "early", "argv": argv,
                                               "cwd": str(tmp_path), "created_at": time.time(),
                                               "on_exit": None}))
    (d / jobs.LOCK_FILE).touch()
    os.mkfifo(d / jobs.LOG_FILE)
    r, w = os.pipe()
    try:
        sup = jobs._spawn_supervisor(d, w)
    finally:
        os.close(w)
    reader = None
    try:
        assert until(lambda: "TERM handler armed" in (d / jobs.SUPERVISOR_LOG).read_text()), \
            (d / jobs.SUPERVISOR_LOG).read_text()
        assert jobs.state(d).state == "running" and "pid" not in jobs.state(d).job   # not spawned
        os.kill(sup.pid, signal.SIGTERM)
        time.sleep(0.2)
        reader = os.open(d / jobs.LOG_FILE, os.O_RDONLY | os.O_NONBLOCK)   # unblocks the supervisor
        reply = jobs._read_ready(r, 10)
        assert reply.startswith("OK "), reply
        code, (st,) = jobs.wait(["early-1"], root=root, timeout=10)
        assert st.state == "exited", "the early TERM was dropped: the command kept running"
        assert st.exit["killed"] is True and st.exit["killed_by"] == "SIGTERM"
        assert st.exit["rc"] == -signal.SIGTERM and code == jobs.EXIT_FAILED
    finally:
        os.close(r)
        if reader is not None:
            os.close(reader)
        sup.wait(timeout=15)


def test_prune_removes_only_jobs_that_ended_long_enough_ago(root, tmp_path):
    import fcntl
    now = time.time()
    old = _fake_job(root, "old-1", exit={"rc": 0, "ended_at": now - 3600, "duration_s": 1.0})
    bad = _fake_job(root, "bad-1", exit={"rc": None, "start_error": "x", "ended_at": now - 3600})
    edge = _fake_job(root, "edge-1", exit={"rc": 0, "ended_at": now - 600, "duration_s": 1.0})
    new = _fake_job(root, "new-1", exit={"rc": 1, "ended_at": now - 5, "duration_s": 1.0})
    lost = _fake_job(root, "lost-1", created_at=now - 7200)     # no pid recorded: nothing to signal
    hook = _fake_job(root, "hook-1", exit={"rc": 0, "ended_at": now - 3600}, on_exit=["h"])
    hookdone = _fake_job(root, "hookdone-1", exit={"rc": 0, "ended_at": now - 3600}, on_exit=["h"])
    (hookdone / jobs.HOOK_FILE).write_text("{}")
    # a failed start never runs its hook, so a missing on_exit.json must not keep it forever
    badhook = _fake_job(root, "badhook-1", exit={"rc": None, "start_error": "x", "ended_at": now - 3600},
                        on_exit=["h"])
    noend = _fake_job(root, "noend-1", exit={"rc": 0})
    run = _fake_job(root, "run-1", created_at=now - 7200)
    outside = tmp_path / "outside"
    target = _fake_job(outside, "linked-1", exit={"rc": 0, "ended_at": now - 3600})
    (root / "linked-1").symlink_to(target)
    with open(run / jobs.LOCK_FILE, "a+") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        assert jobs.state(lost).state == "lost" and jobs.state(run).state == "running"
        want = {"old-1", "bad-1", "edge-1", "hookdone-1", "badhook-1"}
        dry = jobs.prune(root, older_than=600, dry_run=True, now=now)
        assert {s.id for s in dry} == want
        assert old.is_dir() and edge.is_dir()            # a dry run removes nothing
        assert {s.id for s in jobs.prune(root, older_than=600.5, dry_run=True, now=now)} == \
            want - {"edge-1"}
        gone = jobs.prune(root, older_than=600, now=now)
    assert {s.id for s in gone} == want
    for p in (old, bad, edge, hookdone, badhook):
        assert not p.exists()
    for p in (new, lost, hook, noend, run, target):
        assert (p / jobs.JOB_FILE).is_file(), p
    with pytest.raises(jobs.JobError, match="older-than"):
        jobs.prune(root, older_than=-1)


def test_parse_duration():
    assert jobs.parse_duration("90") == 90
    assert jobs.parse_duration("90s") == 90
    assert jobs.parse_duration("30m") == 1800
    assert jobs.parse_duration("1.5h") == 5400
    assert jobs.parse_duration("7d") == 7 * 86400
    for bad in ("", "7w", "-5", "d", "5 days"):
        with pytest.raises(jobs.JobError, match="bad duration"):
            jobs.parse_duration(bad)


def test_cli_prune(root, capsys):
    now = time.time()
    _fake_job(root, "old-2", exit={"rc": 0, "ended_at": now - 3 * 86400, "duration_s": 2.0})
    _fake_job(root, "new-2", exit={"rc": 0, "ended_at": now - 60, "duration_s": 2.0})
    assert cli_main(["job", "prune", "--jobs-dir", str(root), "--older-than", "1d", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would remove old-2" in out and "new-2" not in out and "would remove 1 job(s)" in out
    assert (root / "old-2").is_dir()
    assert cli_main(["job", "prune", "--jobs-dir", str(root), "--older-than", "1d"]) == 0
    assert "removed 1 job(s)" in capsys.readouterr().out
    assert not (root / "old-2").exists() and (root / "new-2").is_dir()
    assert cli_main(["job", "prune", "--jobs-dir", str(root), "--older-than", "soon"]) == 2
    assert "bad duration" in capsys.readouterr().err
