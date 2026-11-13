"""B-178: supervised agents that outlive their session, are detected as lost after a crash, and are
relaunched with their checkpoint. The "agent" is a stub launcher script written by the test; no real
Claude or Codex session is ever started."""
from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

from ctf import campaign, paths, scratch
from ctf.campaign import Campaign, CampaignError
from ctf.cli import main as ctf_main

STUB = """#!{python}
import json, os, sys, tempfile, time
from pathlib import Path
out = Path(os.environ["STUB_OUT"])
n = len(list(out.glob("run-*.json"))) + 1
data = {{"stdin": sys.stdin.read(), "argv": sys.argv[1:], "cwd": os.getcwd(),
        "env": {{k: os.environ.get(k) for k in ("CTF_CAMPAIGN_AGENT", "CTF_CAMPAIGN_GOAL",
               "CTF_CAMPAIGN_RESUME", "CTF_SCRATCH_DIR", "TMPDIR", "CTF_WORKDIR",
               "CTF_CHALLENGE", "CTF_EVENT")}}}}
with tempfile.NamedTemporaryFile("w", delete=False, suffix=".tmp") as fh:   # lands in TMPDIR
    fh.write("scratch")
data["tempfile"] = fh.name
(out / f"run-{{n}}.json").write_text(json.dumps(data))
mode = (out / "mode").read_text().strip() if (out / "mode").exists() else "exit0"
if mode == "hang":
    while not (out / "release").exists():
        time.sleep(0.05)
sys.exit(3 if mode == "exit3" else 0)
"""


# Rule 16: these tests poll a REAL detached subprocess, which no injected clock can drive, so this timeout
# is genuinely wall-clock. It is a ceiling for the failure case only: what is asserted is that the
# condition is eventually reached, never how long it took. 180 s holds at load 50-170 on this machine and
# still bounds a stuck test. The fixture gives the supervisor's own start the same allowance.
WALL_CLOCK_CEILING = 180.0
ENDED = ("done", "failed", "lost")


def _wait(pred, timeout=WALL_CLOCK_CEILING, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def _wait_status(camp, aid, want, what):
    """Wait until agent `aid` is recorded `want`. An agent that ended any other way fails at once with
    what was recorded, instead of after the whole ceiling."""
    def reached():
        rec = camp.load()["agents"][aid]
        if rec["status"] != want and rec["status"] in ENDED:
            raise AssertionError(f"{what}: agent {aid} is {rec['status']} (rc {rec.get('rc')}, note "
                                 f"{rec.get('note')!r}), not {want}")
        return rec["status"] == want
    _wait(reached, what=what)


@pytest.fixture
def env(tmp_path, monkeypatch):
    wd = tmp_path / "work"
    (wd / "12-web-login").mkdir(parents=True)
    out = tmp_path / "out"
    out.mkdir()
    tools = tmp_path / "launchers"
    tools.mkdir()
    stub = tools / "fake_agent"
    stub.write_text(STUB.format(python=sys.executable))
    stub.chmod(0o755)
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    monkeypatch.setenv("STUB_OUT", str(out))
    monkeypatch.setenv(campaign.LAUNCHERS_ENV, str(stub))
    monkeypatch.setattr(campaign, "SUPERVISOR_START_WAIT", WALL_CLOCK_CEILING)    # see WALL_CLOCK_CEILING
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Solve challenge 12. Original instructions.")
    camp = Campaign(wd, event="csctf")
    camp.add_goal("web12", "SSTI on 12", challenge="12", lane="web", next_step="probe jinja")
    yield {"wd": wd, "out": out, "stub": stub, "camp": camp, "prompt": prompt}
    # never leave a stub running: release any hang and kill leftover supervisors
    (out / "release").write_text("1")
    for rec in Campaign(wd).load()["agents"].values():
        pid = rec.get("supervisor_pid")
        if pid and rec["status"] == "running":
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def _runs(out: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(out.glob("run-*.json"))]


def _status(camp, aid):
    return camp.load()["agents"][aid]["status"]


def test_launcher_allow_list(env, monkeypatch, tmp_path):
    with pytest.raises(CampaignError, match="not allowed"):
        campaign.resolve_launcher("/bin/echo")
    with pytest.raises(CampaignError, match="not on PATH"):
        campaign.resolve_launcher("no-such-launcher-xyz")
    with pytest.raises(CampaignError, match="does not exist"):
        campaign.resolve_launcher(str(tmp_path / "missing"))
    # the repo's fenced launchers are allowed without any configuration (resolved, never run here)
    monkeypatch.delenv(campaign.LAUNCHERS_ENV)
    monkeypatch.chdir(paths.repo_root())
    assert campaign.resolve_launcher("tools/codex_launch") == (paths.repo_root() / "tools" / "codex_launch").resolve()
    with pytest.raises(CampaignError, match="not allowed"):
        campaign.resolve_launcher(str(env["stub"]))
    with pytest.raises(CampaignError, match="not allowed"):
        env["camp"].launch("x", [str(env["stub"])], harness="codex")
    assert "x" not in env["camp"].load()["agents"]


def test_launch_runs_detached_with_prompt_env_and_scratch_then_records_done(env):
    camp, out = env["camp"], env["out"]
    rec = camp.launch("web-a", [str(env["stub"]), "--flag", "v"], harness="codex", challenge="12",
                      goal="web12", prompt_file=env["prompt"], cwd=env["wd"])
    assert rec["launches"] == 1 and rec["supervised"] and rec["supervisor_pid"]
    # the supervisor is a session leader: the caller's session ending cannot take it down
    try:
        assert os.getsid(rec["supervisor_pid"]) == rec["supervisor_pid"]
    except ProcessLookupError:
        pass        # it already finished, which the next wait checks
    _wait_status(camp, "web-a", "done", "agent done")
    final = camp.load()["agents"]["web-a"]
    assert final["rc"] == 0 and final["pid"]
    (run,) = _runs(out)
    assert run["argv"] == ["--flag", "v"] and run["cwd"] == str(env["wd"].resolve())
    assert run["stdin"] == "Solve challenge 12. Original instructions."
    e = run["env"]
    assert e["CTF_CAMPAIGN_AGENT"] == "web-a" and e["CTF_CAMPAIGN_GOAL"] == "web12"
    assert e["CTF_CAMPAIGN_RESUME"] == str(camp.resume_path) and e["CTF_WORKDIR"] == str(env["wd"])
    assert e["CTF_CHALLENGE"] == "12" and e["CTF_EVENT"] == "csctf", \
        "an R-09 launcher gates and meters the launch on the campaign's challenge"
    pass_dir = Path(final["scratch"])
    assert pass_dir.parent == (env["wd"] / "12-web-login" / ".scratch").resolve()
    assert e["TMPDIR"] == e["CTF_SCRATCH_DIR"] == str(pass_dir)
    assert Path(run["tempfile"]).parent == pass_dir, "temp files land in the pass, not /tmp"
    m = scratch.read_manifest(pass_dir)
    assert m["status"] == "closed" and m["agent"] == "web-a"
    assert [f["path"] for f in m["files"]] == [Path(run["tempfile"]).name]
    assert "=== exit 0" in Path(final["log"]).read_text()
    assert camp.relaunch_list() == []
    # "done" is on disk before the supervisor has rewritten RESUME.md; check() reads the pair under the
    # state lock, so it sees the finished write (the next test pins that).
    assert camp.check() == [], "every write by the supervisor keeps RESUME.md current"


def _resume_rev(camp):
    return int(re.search(r"<!-- ctf-campaign-resume rev=(\d+) -->", camp.resume_path.read_text()).group(1))


def test_check_waits_out_a_writer_that_is_between_its_state_and_resume_writes(env, monkeypatch):
    """Every writer replaces state.json and then RESUME.md under the state lock. A check() that read the
    two without that lock, landing between the two replaces, called a resume stale that was current a
    moment later (the launch test above failed that way under load: "RESUME.md is missing or older than
    state rev 5"). No clock decides this test: the writer is held between its two writes until the
    checker has either asked for the state lock (it then waits for the writer) or returned."""
    camp, wd = env["camp"], env["wd"]
    camp.register("a", "codex", goal="web12")
    assert camp.check() == []
    rev = camp.load()["rev"]
    writer, checker = Campaign(wd, event="csctf"), Campaign(wd, event="csctf")
    in_gap, checker_moved = threading.Event(), threading.Event()
    seen: dict = {}
    real_write_resume, real_lock = writer.write_resume, checker._lock

    def held_write_resume(st):
        seen["gap"] = (Campaign(wd).load()["rev"], _resume_rev(camp))
        in_gap.set()
        seen["released"] = checker_moved.wait(WALL_CLOCK_CEILING)   # failure-case ceiling only
        return real_write_resume(st)

    @contextlib.contextmanager
    def announced_lock():
        checker_moved.set()
        with real_lock():
            yield

    def check():
        try:
            seen["problems"] = checker.check()
        finally:
            checker_moved.set()

    monkeypatch.setattr(writer, "write_resume", held_write_resume)
    monkeypatch.setattr(checker, "_lock", announced_lock)
    w = threading.Thread(target=lambda: seen.update(finished=writer.finish("a", "done", rc=0)), daemon=True)
    c = threading.Thread(target=check, daemon=True)
    w.start()
    assert in_gap.wait(WALL_CLOCK_CEILING), "the writer never reached its RESUME.md write"
    c.start()
    w.join(WALL_CLOCK_CEILING)
    c.join(WALL_CLOCK_CEILING)
    assert not w.is_alive() and not c.is_alive()
    assert seen["gap"] == (rev + 1, rev), "the check ran while state.json was a rev ahead of RESUME.md"
    assert seen["released"] and seen["finished"] is True
    assert seen["problems"] == [], "check() must not report the resume a writer is about to bring current"
    assert _resume_rev(camp) == rev + 1


def _race_a_whole_writer(monkeypatch, wd, held_at, reader):
    """Run `reader()` in this thread and stop it inside its first `Campaign.<held_at>(st)` call: it has
    read state.json by then and has not yet touched RESUME.md. A second Campaign then finishes agent "a"
    from another thread, a whole writer cycle (state.json, then RESUME.md). The reader goes on once that
    writer has either completed (the reader was not holding the state lock, so nothing kept the writer
    out) or has asked for the state lock while the reader holds it (the writer then waits for the reader
    to let go). No clock decides which; WALL_CLOCK_CEILING bounds the failure case only.
    Returns (what reader() returned, {"read_rev", "writer_got_in", "finished"})."""
    me = threading.current_thread()
    asked, done = threading.Event(), threading.Event()
    holding: list = []          # non-empty while this thread holds the state lock
    seen: dict = {}
    real_lock, real_held_at = Campaign._lock, getattr(Campaign, held_at)

    @contextlib.contextmanager
    def lock(self):
        mine = threading.current_thread() is me
        if not mine:
            asked.set()
        with real_lock(self):
            if mine:
                holding.append(1)
            try:
                yield
            finally:
                if mine:
                    holding.pop()

    def write():
        try:
            seen["finished"] = Campaign(wd, event="csctf").finish("a", "done", rc=0)
        finally:
            done.set()

    writer = threading.Thread(target=write, daemon=True)

    def held(self, st):
        if threading.current_thread() is me and "read_rev" not in seen:
            seen["read_rev"] = st["rev"]
            writer.start()
            assert asked.wait(WALL_CLOCK_CEILING), "the writer never asked for the state lock"
            if not holding:
                assert done.wait(WALL_CLOCK_CEILING), "nothing held the state lock, yet the writer never finished"
            seen["writer_got_in"] = done.is_set()
        return real_held_at(self, st)

    monkeypatch.setattr(Campaign, "_lock", lock)
    monkeypatch.setattr(Campaign, held_at, held)
    result = reader()
    assert "read_rev" in seen, f"the reader never called {held_at}"
    writer.join(WALL_CLOCK_CEILING)
    assert not writer.is_alive(), "the writer never got the state lock back from the reader"
    return result, seen


def test_check_keeps_a_whole_writer_out_between_its_state_and_resume_reads(env, monkeypatch):
    """check() reads state.json and then RESUME.md. Were the state lock let go between the two, a writer
    completing in that window would leave check() comparing the old state rev with the new resume, and it
    would report "older than state rev N" for a pair that is current."""
    camp, wd = env["camp"], env["wd"]
    camp.register("a", "codex", goal="web12")
    rev = camp.load()["rev"]
    assert camp.check() == [] and _resume_rev(camp) == rev
    problems, seen = _race_a_whole_writer(monkeypatch, wd, "resume_current", Campaign(wd, event="csctf").check)
    assert seen["read_rev"] == rev
    assert problems == [], "check() compared a state rev and a RESUME.md from either side of a write"
    assert seen["writer_got_in"] is False, "a writer ran between check()'s two reads"
    assert seen["finished"] is True and camp.load()["rev"] == rev + 1, "the writer ran once check() was done"
    assert _resume_rev(camp) == rev + 1 and camp.check() == []


def test_cli_resume_rebuilds_the_resume_file_under_the_state_lock(env, monkeypatch, capsys):
    """`ctf campaign resume` reads the state and rewrites RESUME.md. Without the state lock around the
    pair, a supervisor finishing in between has its newer RESUME.md overwritten by the older one, which
    then stays a rev behind state.json until the next change (check() reports it, correctly)."""
    camp, wd = env["camp"], env["wd"]
    camp.register("a", "codex", goal="web12")
    rev = camp.load()["rev"]
    assert camp.check() == []       # current, so the reconcile that `resume` starts with rewrites nothing
    rc, seen = _race_a_whole_writer(monkeypatch, wd, "write_resume",
                                    lambda: ctf_main(["campaign", "resume", "--quiet"]))
    assert rc == 0 and capsys.readouterr().out == ""
    assert seen["read_rev"] == rev
    assert seen["finished"] is True and camp.load()["rev"] == rev + 1
    assert _resume_rev(camp) == rev + 1, "the resume command put an older RESUME.md over the writer's"
    assert seen["writer_got_in"] is False, "a writer ran between the resume command's read and its write"
    assert camp.check() == []


def test_a_supervisor_that_does_not_detach_in_time_is_recorded_failed(env, monkeypatch):
    """campaign.SUPERVISOR_START_WAIT bounds the supervisor's start. A new interpreter cannot import
    ctf.campaign and detach within a millisecond, so this launch always runs into it."""
    camp, out = env["camp"], env["out"]
    monkeypatch.setattr(campaign, "SUPERVISOR_START_WAIT", 0.001)
    with pytest.raises(CampaignError, match=r"agent 'a': supervisor did not start: .*timed out after 0\.001 s"):
        camp.launch("a", [str(env["stub"])], harness="codex", challenge="12", goal="web12")
    rec = camp.load()["agents"]["a"]
    assert rec["status"] == "failed" and rec["launches"] == 1 and rec["supervisor_pid"] is None
    assert rec["note"].startswith("supervisor did not start")
    assert scratch.read_manifest(Path(rec["scratch"]))["status"] == "failed"
    assert not campaign.lock_held(camp.agent_lock("a")), "the stopped supervisor holds no agent lock"
    assert _runs(out) == [], "the agent was never started"
    assert camp.check() == []


def test_nonzero_exit_is_failed_and_relaunch_needs_include_failed(env):
    camp, out = env["camp"], env["out"]
    (out / "mode").write_text("exit3")
    camp.launch("a", [str(env["stub"])], harness="claude", challenge="12", goal="web12")
    _wait_status(camp, "a", "failed", "agent failed")
    rec = camp.load()["agents"]["a"]
    assert rec["rc"] == 3
    assert scratch.read_manifest(Path(rec["scratch"]))["status"] == "failed"
    with pytest.raises(CampaignError, match="only lost agents"):
        camp.relaunch("a")
    (out / "mode").write_text("exit0")
    camp.relaunch("a", include_failed=True)
    _wait_status(camp, "a", "done", "relaunch done")


def test_crash_is_detected_as_lost_and_relaunch_resumes_from_the_checkpoint(env):
    camp, out = env["camp"], env["out"]
    (out / "mode").write_text("hang")
    rec = camp.launch("web-a", [str(env["stub"])], harness="codex", challenge="12", goal="web12",
                      prompt_file=env["prompt"])
    _wait(lambda: len(_runs(out)) == 1, what="first run started")
    assert camp.reconcile() == [], "a live supervised agent is not lost"
    camp.checkpoint("web12", "ruled out ERB and Twig", next_step="read app config via jinja", agent="web-a")
    # simulate the Mac crashing: the whole agent process group dies without recording anything
    os.killpg(rec["supervisor_pid"], signal.SIGKILL)
    _wait(lambda: not campaign.lock_held(camp.agent_lock("web-a")), what="lock released")
    assert _status(camp, "web-a") == "running", "nothing recorded the death"
    assert camp.reconcile() == ["web-a"]
    lost = camp.load()["agents"]["web-a"]
    assert lost["status"] == "lost" and "supervisor is gone" in lost["lost_reason"]
    resume = camp.resume_path.read_text()
    assert "python -m ctf campaign relaunch web-a" in resume.split("## Relaunch list")[1].split("## ")[0]
    old_pass = Path(lost["scratch"])
    (out / "mode").write_text("exit0")
    new = camp.relaunch("web-a")
    assert new["launches"] == 2
    _wait_status(camp, "web-a", "done", "relaunch done")
    runs = _runs(out)
    assert len(runs) == 2
    stdin = runs[1]["stdin"]
    assert stdin.startswith("RELAUNCH: agent `web-a` was interrupted")
    assert "read app config via jinja" in stdin and "ruled out ERB and Twig" in stdin
    assert stdin.rstrip().endswith("Solve challenge 12. Original instructions.")
    assert str(old_pass) in stdin
    assert scratch.read_manifest(old_pass)["status"] == "interrupted"
    final = camp.load()["agents"]["web-a"]
    assert Path(final["scratch"]) != old_pass
    assert [h["status"] for h in final["history"]] == ["lost"]
    from ctf import ledger
    assert any(r["event"] == "campaign.relaunch" and r["agent"] == "web-a" for r in ledger.read(env["wd"]))


def test_running_agent_cannot_be_launched_twice(env):
    camp, out = env["camp"], env["out"]
    (out / "mode").write_text("hang")
    camp.launch("a", [str(env["stub"])], harness="codex")
    with pytest.raises(CampaignError, match="already running"):
        camp.launch("a", [str(env["stub"])], harness="codex")
    (out / "release").write_text("1")
    _wait_status(camp, "a", "done", "agent done")


def test_relaunch_never_doubles_a_live_process(env, monkeypatch):
    camp, out = env["camp"], env["out"]
    monkeypatch.setattr(campaign, "LOCK_RELEASE_WAIT", 0.3)
    (out / "mode").write_text("hang")
    camp.launch("a", [str(env["stub"])], harness="codex")
    _wait(lambda: len(_runs(out)) == 1, what="first run")
    with camp.transaction() as st:          # a wrong "lost" mark (e.g. a hand edit) while it still runs
        st["agents"]["a"]["status"] = "lost"
    with pytest.raises(CampaignError, match="still holds its lock"):
        camp.relaunch("a")
    assert len(_runs(out)) == 1
    (out / "release").write_text("1")


def test_launch_rechecks_running_inside_the_start_transaction(env, monkeypatch):
    """launch() checks for a running agent without the lock; _start must check again in its
    transaction, or an agent registered in between is silently overwritten."""
    camp, out = env["camp"], env["out"]
    real_start = camp._start

    def racing_start(aid, spec, *, preamble):
        camp.register(aid, "claude", note="won the race")
        return real_start(aid, spec, preamble=preamble)

    monkeypatch.setattr(camp, "_start", racing_start)
    with pytest.raises(CampaignError, match="already running"):
        camp.launch("a", [str(env["stub"])], harness="codex")
    rec = camp.load()["agents"]["a"]
    assert rec["supervised"] is False and rec["note"] == "won the race", "the registered agent survives"
    assert not campaign.lock_held(camp.agent_lock("a")), "the refused start released its lock"
    time.sleep(0.5)
    assert _runs(out) == [], "no supervisor was started"


def test_launch_refuses_a_challenge_at_its_cap_or_stopped(env):
    from ctf import budget, event
    camp, out = env["camp"], env["out"]
    meter = budget.LedgerMeter(event.load("csctf"), workdir=env["wd"], on_cap=lambda st, path: None)
    with pytest.raises(budget.BudgetExceeded):     # recorded, then refused: the cap is reached
        meter.add_spend("12", meter.cap("12"), 100)
    with pytest.raises(CampaignError, match="not launched: challenge 12 is at its budget cap"):
        camp.launch("a", [str(env["stub"])], harness="codex", challenge="12", goal="web12")
    meter.extend("12", 5.0, by="max", reason="test")
    budget.on_team_solve("12", workdir=env["wd"])
    with pytest.raises(CampaignError, match="not launched: challenge 12 is stopped \\(team_solve\\)"):
        camp.launch("a", [str(env["stub"])], harness="codex", challenge="12", goal="web12")
    assert camp.load()["agents"] == {}
    assert not (env["wd"] / "12-web-login" / ".scratch").exists(), "a refused launch opens no scratch pass"
    time.sleep(0.3)
    assert _runs(out) == []


def test_gated_launcher_challenge_must_match_the_campaign(env, monkeypatch, tmp_path):
    gated = tmp_path / "gated" / "codex_launch"
    gated.parent.mkdir()
    gated.write_text(env["stub"].read_text())
    gated.chmod(0o755)
    monkeypatch.setenv(campaign.LAUNCHERS_ENV, os.pathsep.join([str(env["stub"]), str(gated)]))
    camp = env["camp"]
    for args in (["--challenge", "13"], ["--challenge=13"]):
        with pytest.raises(CampaignError, match="--challenge 13 does not match"):
            camp.launch("a", [str(gated), *args], harness="codex", challenge="12")
        with pytest.raises(CampaignError, match="does not match"):
            camp.launch("a", [str(gated), *args], harness="codex")
    assert camp.load()["agents"] == {}
    # after a bare --, the arguments are the harness's, not the launcher's
    rec = camp.launch("b", [str(gated), "--challenge", "12", "--", "--challenge", "x"], harness="codex",
                      challenge="12")
    _wait_status(camp, "b", "done", "matching launch done")
    assert rec["launches"] == 1
    # only the R-09 launchers' own flag is checked; another launcher's --challenge is its business
    rec = camp.launch("c", [str(env["stub"]), "--challenge", "13"], harness="codex", challenge="12")
    _wait_status(camp, "c", "done", "ungated launch done")


def test_launch_validation(env):
    camp = env["camp"]
    with pytest.raises(CampaignError, match="needs a command"):
        camp.launch("a", [], harness="codex")
    with pytest.raises(CampaignError, match="harness"):
        camp.launch("a", [str(env["stub"])], harness="gpt")
    with pytest.raises(CampaignError, match="no goal"):
        camp.launch("a", [str(env["stub"])], harness="codex", goal="nope")
    with pytest.raises(scratch.ScratchError, match="no challenge folder"):
        camp.launch("a", [str(env["stub"])], harness="codex", challenge="99")
    with pytest.raises(CampaignError, match="prompt file"):
        camp.launch("a", [str(env["stub"])], harness="codex", prompt_file=env["wd"] / "nope.md")
    assert camp.load()["agents"] == {}


def test_cli_launch_resume_relaunch_end_to_end(env, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "csctf")     # the budget cap of challenge 12 is the event's
    camp, out = env["camp"], env["out"]
    (out / "mode").write_text("hang")
    assert ctf_main(["campaign", "launch", "web-a", "--harness", "codex", "--challenge", "12",
                     "--goal", "web12", "--", str(env["stub"]), "--x"]) == 0
    assert "launch 1 started" in capsys.readouterr().out
    _wait(lambda: len(_runs(out)) == 1, what="first run")
    assert _runs(out)[0]["argv"] == ["--x"]
    pid = camp.load()["agents"]["web-a"]["supervisor_pid"]
    os.killpg(pid, signal.SIGKILL)
    _wait(lambda: not campaign.lock_held(camp.agent_lock("web-a")), what="lock released")
    (out / "mode").write_text("exit0")
    assert ctf_main(["campaign", "resume", "--relaunch"]) == 0
    cap = capsys.readouterr()
    assert "LOST: agent web-a" in cap.err and "relaunched web-a (launch 2)" in cap.err
    assert cap.out.startswith("<!-- ctf-campaign-resume rev=")
    _wait_status(camp, "web-a", "done", "relaunch done")
    assert ctf_main(["campaign", "status", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["agents"]["web-a"]["launches"] == 2 and data["relaunch"] == []
