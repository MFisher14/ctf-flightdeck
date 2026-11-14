"""B-175 in the agent launchers (tools/launch_gate.py, tools/claude_launch, tools/codex_launch).

* a supervised agent's jobs are recorded against a fresh owner and stopped when the agent exits;
* --session NAME refuses to start over a live session (pid AND start time), replaces a stale one,
  records the agent's identity and is released when the launcher returns;
* an exec'd (ungated) agent gets the owner variables with its own pid.

Every harness is a stub executable written by the test; no real Codex or Claude session starts.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf import jobs, ledger, procid, sessions
from ctf import paths
from tools import launch_gate

REPO = paths.repo_root()
PY = sys.executable
SLEEP = [PY, "-c", "import time; time.sleep(60)"]

STUB = '''#!{py}
import json, os, subprocess, sys, time
if sys.argv[1:] == ["--help"]:      # claude_launch reads the CLI's help for --effort; no session
    print("Options:\\n  --effort <level>  Effort level for the current session")
    sys.exit(0)
spec = json.load(open(os.environ["STUB_SPEC"]))
seen = {{k: os.environ.get(k) for k in ("CTF_JOB_OWNER", "CTF_JOB_OWNER_PID", "CTF_JOBS_DIR")}}
seen["pid"] = os.getpid()
if spec.get("session_file"):
    seen["session"] = json.load(open(spec["session_file"]))
if spec.get("job"):
    out = subprocess.run([sys.executable, "-m", "ctf", "job", "start", "--name", "bg", "--",
                          sys.executable, "-c", "import time; time.sleep(60)"],
                         cwd=spec["repo"], capture_output=True, text=True)
    seen["job_rc"] = out.returncode
    seen["job_out"] = out.stdout + out.stderr
with open(spec["mark"], "a") as fh:
    fh.write(json.dumps(seen) + "\\n")
sys.exit(spec.get("rc", 0))
'''


class Env:
    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.ws = tmp_path / "ws"
        self.mark = tmp_path / "mark.jsonl"
        self.spec = tmp_path / "spec.json"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        for name in ("codex", "claude"):
            p = self.bin / name
            p.write_text(STUB.format(py=PY))
            p.chmod(0o755)
        self.stub()

    def stub(self, **kw):
        self.spec.write_text(json.dumps({"mark": str(self.mark), "repo": str(REPO), **kw}))

    def env(self, **extra):
        e = dict(os.environ, CTF_WORKDIR=str(self.work), CTF_EVENT="csctf", STUB_SPEC=str(self.spec))
        for k in ("CTF_CHALLENGE", "CTF_SESSION", "CTF_SESSIONS_DIR", "CTF_JOBS_DIR",
                  jobs.OWNER_ENV, jobs.OWNER_PID_ENV):
            e.pop(k, None)
        e.update(extra)
        return e

    def run(self, tool, *args, **extra):
        binopt = ["--codex-bin" if tool == "codex_launch" else "--claude-bin",
                  str(self.bin / tool.split("_")[0])]
        argv = [PY, str(REPO / "tools" / tool), "--workspace", str(self.ws), *binopt, *args]
        return subprocess.run(argv, capture_output=True, text=True, env=self.env(**extra),
                              stdin=subprocess.DEVNULL, timeout=120)

    def seen(self) -> list[dict]:
        if not self.mark.exists():
            return []
        return [json.loads(x) for x in self.mark.read_text().splitlines() if x.strip()]

    def events(self, kind):
        return [r for r in ledger.read(self.work) if r["event"] == kind]


@pytest.fixture
def E(tmp_path):
    e = Env(tmp_path)
    yield e
    for st in jobs.list_jobs(e.work / "jobs"):          # never leave a test's job running
        if st.state == "running":
            try:
                jobs.kill(st.dir)
            except jobs.JobError:
                pass


def _cleanup(*ps):
    for p in ps:
        if p.poll() is None:
            p.kill()
        p.wait()


# ------------------------------------------------------------------ auto-reap on agent exit

def test_a_supervised_agents_jobs_are_reaped_when_it_exits_and_no_one_elses(E):
    other = jobs.start(SLEEP, root=E.work / "jobs", name="other", owner="someone-else")
    E.stub(job=True)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0, r.stderr
    seen = E.seen()[0]
    assert seen["job_rc"] == 0, seen["job_out"]
    owner = seen["CTF_JOB_OWNER"]
    assert owner and owner.startswith("codex-7-")
    assert Path(seen["CTF_JOBS_DIR"]) == (E.work / "jobs")
    assert int(seen["CTF_JOB_OWNER_PID"]) != seen["pid"]          # the launcher, not the agent
    mine = [st for st in jobs.list_jobs(E.work / "jobs") if st.job.get("owner") == owner]
    assert len(mine) == 1
    st = mine[0]
    assert st.job["owner_pid"] == int(seen["CTF_JOB_OWNER_PID"])
    assert st.state == "exited" and st.exit["killed"], "the agent's job outlived the agent"
    assert jobs.state(other.dir).state == "running", "another owner's job was reaped"
    reaped = E.events("jobs_reaped")
    assert len(reaped) == 1 and reaped[0]["owner"] == owner and reaped[0]["stopped"] == [st.id]
    assert reaped[0]["failed"] == []
    assert E.events("agent_launch")[0]["job_owner"] == owner
    # the record order: agent_exit, then the reap
    kinds = [x["event"] for x in ledger.read(E.work) if x["event"] in ("agent_exit", "jobs_reaped")]
    assert kinds == ["agent_exit", "jobs_reaped"]


def test_an_agent_that_starts_no_job_records_no_reap(E):
    E.stub()
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0, r.stderr
    assert E.events("jobs_reaped") == []


def test_reap_owned_jobs_records_and_names_a_failure(tmp_path, capsys):
    """A job that cannot be stopped is named on stderr and in jobs_reaped.failed, never dropped."""
    root = tmp_path / "jobs"
    d = root / "stuck"
    d.mkdir(parents=True)
    (d / jobs.JOB_FILE).write_text(json.dumps({"id": "stuck", "name": "stuck", "argv": ["x"], "cwd": "/",
                                               "created_at": time.time() - 3600, "owner": "own-1",
                                               "pid": 999999}))          # lost, no identity
    (d / jobs.LOCK_FILE).touch()
    recorded = []
    gate = SimpleNamespace(harness="codex", record=lambda ev, **f: recorded.append((ev, f)))
    res = launch_gate.reap_owned_jobs(gate, "own-1", root)
    assert [(r.id, r.outcome) for r in res] == [("stuck", "failed")]
    assert recorded == [("jobs_reaped", {"owner": "own-1", "stopped": [], "failed": ["stuck"]})]
    assert "job stuck: failed (job stuck: no exact identity recorded" in capsys.readouterr().err
    assert launch_gate.reap_owned_jobs(gate, "own-1", tmp_path / "absent") == []


# ------------------------------------------------------------------ sessions

def test_a_launcher_refuses_to_start_over_a_live_session(E):
    holder = subprocess.Popen(SLEEP)
    try:
        sessions.claim(E.work / "sessions", "playday", harness="claude", pid=holder.pid)
        for extra in ((), ("--dry-run",)):
            r = E.run("claude_launch", "--session", "playday", *extra)
            assert r.returncode == launch_gate.EXIT_REFUSED, r.stderr
            assert "session 'playday' is live" in r.stderr and f"pid {holder.pid}" in r.stderr
        r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go", CTF_SESSION="playday")
        assert r.returncode == launch_gate.EXIT_REFUSED and "is live" in r.stderr
        assert E.seen() == [], "an agent started over a live session"
        assert E.events("agent_launch") == []
        assert json.loads((E.work / "sessions" / "playday.json").read_text())["launcher_pid"] == holder.pid
    finally:
        _cleanup(holder)


def test_a_free_session_records_the_agent_and_is_released_after(E):
    sess = E.work / "sessions" / "day.json"
    E.stub(session_file=str(sess))
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--session", "day", "go")
    assert r.returncode == 0, r.stderr
    seen = E.seen()[0]
    rec = seen["session"]
    assert rec["agent_pid"] == seen["pid"] and rec["agent_pgid"] == seen["pid"]   # headless: own group
    assert rec["owner"] == seen["CTF_JOB_OWNER"] and rec["harness"] == "codex" and rec["challenge"] == "7"
    assert rec["launcher_pid"] != seen["pid"]
    assert not sess.exists(), "the launcher did not release its session"


def test_a_stale_session_is_replaced_and_said_so(E):
    dead = subprocess.Popen([PY, "-c", "pass"])
    start = procid.start_time(dead.pid) or 1.0
    dead.wait()
    (E.work / "sessions").mkdir()
    (E.work / "sessions" / "day.json").write_text(json.dumps({"name": "day", "launcher_pid": dead.pid,
                                                              "launcher_start": start}))
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--session", "day", "go")
    assert r.returncode == 0, r.stderr
    assert "replaced a stale record" in r.stderr
    assert len(E.seen()) == 1


def test_a_refused_gate_releases_the_session(E):
    ledger.append("spend", workdir=E.work, challenge_id="7", usd=30.0, tok=10)     # over the $25 cap
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--session", "s", "go")
    assert r.returncode == launch_gate.EXIT_REFUSED
    assert not (E.work / "sessions" / "s.json").exists()


def test_claim_session_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_SESSIONS_DIR", str(tmp_path))
    monkeypatch.delenv("CTF_SESSION", raising=False)
    args = SimpleNamespace(session=None, challenge=None)
    assert launch_gate.claim_session(args, "claude", dry_run=False) == (None, None)
    args.session = "bad name"
    with pytest.raises(launch_gate.GateError, match="bad session name"):
        launch_gate.claim_session(args, "claude", dry_run=False)
    args.session = "ok"
    assert launch_gate.claim_session(args, "claude", dry_run=True) == (None, None)
    assert not (tmp_path / "ok.json").exists()                      # a dry run claims nothing
    c, refused = launch_gate.claim_session(args, "claude", dry_run=False)
    assert refused is None and (tmp_path / "ok.json").exists()
    assert launch_gate.release_session(c) and not (tmp_path / "ok.json").exists()
    monkeypatch.setenv("CTF_SESSION", "fromenv")
    assert launch_gate.session_from(None) == "fromenv"
    assert launch_gate.session_from("given") == "given"


# ------------------------------------------------------------------ exec path

def test_an_execd_agent_gets_the_owner_variables_with_its_own_pid(E):
    E.stub()
    r = E.run("claude_launch", "--no-notes")
    assert r.returncode == 0, r.stderr
    seen = E.seen()[0]
    assert seen["CTF_JOB_OWNER"].startswith("claude-nochallenge-")
    assert int(seen["CTF_JOB_OWNER_PID"]) == seen["pid"]          # exec keeps the pid
    assert seen["CTF_JOBS_DIR"] is None


def test_new_owner_is_unique_and_valid():
    a, b = launch_gate.new_owner("codex", "web/1 x"), launch_gate.new_owner("codex", "web/1 x")
    assert a != b
    assert jobs._OWNER_RE.match(a) and "/" not in a and " " not in a
