"""B-198: the no-model live status surface (ctf.live, ctf.progress, `python -m ctf live`) and the gate's
progress file. Every source is synthetic: temp git checkouts, temp workdirs, fake HTTP services on
127.0.0.1. No model, no platform."""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import event, ledger, live, paths, progress
from ctf.cli import gate as gate_cli
from ctf.cli import live as live_cli
from gate_repo import GIT, make_repo

NOW = 1_800_000_000.0
DEAD = 2**22 + 12345            # never a live pid in these tests (alive() is injected where it matters)


@pytest.fixture(autouse=True)
def _no_host_workdir(monkeypatch, tmp_path):
    """Every event workdir these tests resolve (the CLI's, the scope check's pointed-service ledger) is a
    temp folder: nothing reads this host's ~/ctf-work."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "ctf-work"))


def sh(root: Path, *args: str, ts: float | None = None) -> str:
    e = dict(os.environ)
    if ts is not None:
        e["GIT_AUTHOR_DATE"] = e["GIT_COMMITTER_DATE"] = f"@{int(ts)} +0000"
    r = subprocess.run([*GIT, "-C", str(root), *args], capture_output=True, text=True, timeout=60, env=e)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


PLAN = """# plan
- `B-001` [S/A] one
- `B-002` [M/A dep:B-001] two
- `B-003` [L/~] three
- `B-004` [XL/N] four
- `B-002` [S/A] duplicate line: the first occurrence wins
"""


def commit(root: Path, files: dict, msg: str, ts: float) -> str:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    sh(root, "add", "-A")
    sh(root, "commit", "-q", "-m", msg, ts=ts)
    return sh(root, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    sh(root, "init", "-q")
    commit(root, {"BUILD-PLAN.md": PLAN}, "plan", NOW - 30 * 3600)
    return root


def sources(root: Path, **kw) -> live.Sources:
    kw.setdefault("ps", lambda: "")
    kw.setdefault("now", NOW)
    return live.Sources(repo=root, git=live.make_git(root), **kw)


# ---------------------------------------------------------------------------------------------- plan

def test_plan_percent_rate_and_eta_from_logs_and_their_git_add_times(repo):
    commit(repo, {"docs/build-log/B-001a.md": "Status: **built**.\n"}, "a", NOW - 5 * 3600)
    commit(repo, {"docs/build-log/B-001b.md": "Status: built\n"}, "b", NOW - 4 * 3600)
    commit(repo, {"docs/build-log/B-002.md": "x\nStatus: **partial** (gaps)\n"}, "c", NOW - 1 * 3600)
    commit(repo, {"docs/build-log/R-01.md": "Status: built\n"}, "not a plan item", NOW - 1800)
    p = live.plan_section(sources(repo))
    # 4 items, effort S1 M2 L4 XL8 = 15; B-001 (both parts logged) and B-002 are done = 3 units
    assert (p["items"], p["done"], p["pct"], p["effort_pct"]) == (4, 2, 50.0, 20.0)
    assert p["by_status"] == {"built": 1, "partial": 1}
    # both done items landed in the last 6 h: 3 units / 6 h = 0.5 units/h; 12 units left -> 24 h
    assert p["rate_units_per_h"] == 0.5 and p["basis"] == "last 6 h"
    assert p["eta_s"] == 24 * 3600
    assert p["undated"] == 0


def test_plan_split_unit_counts_once_any_part_is_logged(repo):
    commit(repo, {"docs/build-log/B-001a.md": "Status: built\n"}, "a", NOW - 3600)
    p = live.plan_section(sources(repo))
    assert p["done"] == 1 and p["by_status"] == {"built": 1}
    commit(repo, {"docs/build-log/B-002x.md": "Status: built\n", "docs/build-log/B-0031.md": "Status: built\n"},
           "not parts: B-002x is a part of B-002, B-0031 is not a part of B-003", NOW - 1800)
    assert live.plan_section(sources(repo))["done"] == 2


def test_plan_split_unit_parts_that_disagree_and_old_logs_use_the_all_time_rate(repo):
    commit(repo, {"docs/build-log/B-001a.md": "Status: built\n", "docs/build-log/B-001b.md": "Status: blocked\n"},
           "a", NOW - 20 * 3600)
    commit(repo, {"docs/build-log/B-003.md": "Status: built\n"}, "b", NOW - 10 * 3600)
    (repo / "docs/build-log/B-004.md").write_text("no status line\n")       # written, never committed
    p = live.plan_section(sources(repo))
    assert p["by_status"] == {"partial": 1, "built": 1, "logged": 1}        # parts disagree -> partial
    assert p["done"] == 3 and p["undated"] == 1
    # no 2 logs in the last 6 h: all time, 5 dated units over the 20 h since the first log
    assert p["basis"] == "since the first log" and p["rate_units_per_h"] == 0.25
    assert p["eta_s"] == round(2 / 0.25 * 3600)        # B-002 (2 units) left


def test_plan_one_recent_log_is_not_a_window_rate(repo):
    commit(repo, {"docs/build-log/B-003.md": "Status: built\n"}, "old", NOW - 8 * 3600)
    commit(repo, {"docs/build-log/B-002.md": "Status: built\n"}, "new", NOW - 3600)
    p = live.plan_section(sources(repo))
    # one log in the window is no rate: 6 units over the 8 h since the first log
    assert p["basis"] == "since the first log" and p["rate_units_per_h"] == 0.75


def test_plan_without_a_plan_or_logs_says_why(repo, tmp_path):
    assert live.plan_section(sources(repo))["basis"] == "no dated build logs yet"
    assert live.plan_section(sources(repo))["eta_s"] is None
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "no BUILD-PLAN.md" in live.plan_section(sources(empty))["error"]


def test_build_section_reports_branch_head_age_and_dirty(repo, tmp_path):
    head = sh(repo, "rev-parse", "HEAD")
    (repo / "BUILD-PLAN.md").write_text(PLAN + "edit\n")
    b = live.build_section(sources(repo))
    assert b["head"] == head and b["dirty"] == 1 and b["head_age_s"] == 30 * 3600
    assert b["branch"] in ("main", "master")
    assert "not a git checkout" in live.build_section(sources(tmp_path))["error"]


# ------------------------------------------------------------------------------------------ progress

def test_progress_eta_observed_then_usual_then_unknown(tmp_path):
    folder = tmp_path / "progress"
    first = progress.Progress(folder, "gate", total=10, jobs=2, label="impact", run_id="a")
    rec = progress.read(folder)[0]
    assert rec["state"] == progress.RUNNING and rec["eta"]["eta_s"] is None
    assert rec["eta"]["basis"].startswith("unknown")
    first.step(warm=True)
    first.step(seconds=4.0)
    first.step(seconds=6.0, bad="tests/test_x.py")
    rec = progress.read(folder)[0]
    assert (rec["done"], rec["ran"], rec["warm"], rec["bad"], rec["bad_items"]) == (3, 2, 1, 1, ["tests/test_x.py"])
    # 7 left x mean 5 s of the files that ran / 2 at a time
    assert rec["eta"] == {"eta_s": 17.5, "basis": "observed"}
    first.finish("fail")
    hist = progress.history(folder)
    assert hist[-1]["ran"] == 2 and hist[-1]["ran_seconds"] == 10.0 and hist[-1]["result"] == "fail"
    # a new run of the same kind and label has the usual per-file time before its first file
    progress.Progress(folder, "gate", total=4, jobs=1, label="impact", run_id="b")
    progress.Progress(folder, "gate", total=4, jobs=1, label="full", run_id="c")
    by = {r["run_id"]: r for r in progress.read(folder)}
    assert by["b"]["eta"] == {"eta_s": 20.0, "basis": "usual"}
    assert by["c"]["eta"]["eta_s"] is None                  # another label has no history
    assert by["a"]["state"] == progress.FINISHED and by["a"]["eta"]["eta_s"] == 0.0


def test_a_run_whose_owner_is_gone_reads_as_died_never_running(tmp_path):
    folder = tmp_path / "p"
    p = progress.Progress(folder, "job", total=None, label="build")
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    p.set(child_pid=proc.pid)
    assert progress.read(folder)[0]["state"] == progress.RUNNING          # this process owns it
    rec = progress.read(folder, alive=lambda pid: pid == proc.pid and progress.pid_alive(pid))[0]
    assert rec["state"] == progress.DIED and rec["eta"]["basis"] == "died"
    assert progress.pid_alive(os.getpid()) and not progress.pid_alive(proc.pid)
    assert not progress.pid_alive(True) and not progress.pid_alive(None) and not progress.pid_alive(0)


def test_a_live_child_keeps_a_run_running_after_its_owner_died(tmp_path):
    """The wrapper (owner pid) was killed while CMD (child pid) still runs: the job is running."""
    folder = tmp_path / "p"
    p = progress.Progress(folder, "job", total=None, label="suite", child_pid=os.getpid())
    p.rec["pid"] = DEAD
    progress._write_atomic(p.path, p.rec)
    assert progress.read(folder)[0]["state"] == progress.RUNNING
    p.rec["child_pid"] = DEAD + 1
    progress._write_atomic(p.path, p.rec)
    assert progress.read(folder)[0]["state"] == progress.DIED


def test_history_is_trimmed_to_its_newest_lines(tmp_path, monkeypatch):
    folder = tmp_path / "p"
    monkeypatch.setattr(progress, "HISTORY_MAX", 5)
    for i in range(8):
        progress.Progress(folder, "gate", total=1, label=f"r{i}", run_id=f"r{i}", clock=lambda i=i: NOW + i).finish("pass")
    hist = progress.history(folder)
    assert [h["label"] for h in hist] == ["r3", "r4", "r5", "r6", "r7"]
    assert progress.trim_history(folder, keep=2) == 3
    assert [h["label"] for h in progress.history(folder)] == ["r6", "r7"]
    assert progress.trim_history(folder, keep=2) == 0


def test_unreadable_progress_file_is_reported_and_finished_runs_are_pruned(tmp_path):
    folder = tmp_path / "p"
    folder.mkdir()
    (folder / "gate-bad.json").write_text("{not json")
    for i in range(progress.KEEP_FINISHED + 3):
        progress.Progress(folder, "gate", total=1, run_id=f"r{i:02d}", clock=lambda i=i: NOW + i).finish("pass")
    running = progress.Progress(folder, "gate", total=1, run_id="live")
    recs = progress.read(folder)
    assert [r for r in recs if r["state"] == progress.UNREADABLE][0]["file"] == "gate-bad.json"
    names = {r["file"] for r in recs}
    assert "gate-r00.json" not in names and f"gate-r{progress.KEEP_FINISHED + 2:02d}.json" in names
    assert sum(1 for r in recs if r["state"] == progress.FINISHED) == progress.KEEP_FINISHED
    assert running.path.name in names
    with pytest.raises(ValueError):
        running.set(done=5)
    with pytest.raises(ValueError):
        progress.Progress(folder, "../x", total=1)


# ------------------------------------------------------------------------- the gate writes progress

def test_gate_run_writes_a_progress_file_and_live_reports_the_red_gate(tmp_path, capsys):
    files = {"tests/test_ok.py": "def test_one():\n    pass\n",
             "tests/test_red.py": "def test_red():\n    assert 0\n"}
    root = make_repo(tmp_path / "g", files)
    p = argparse.ArgumentParser()
    gate_cli.add_arguments(p)
    state = tmp_path / "state"
    args = p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
                         "run", "--full", "--jobs", "1"])
    assert gate_cli.run(args) == 1
    capsys.readouterr()
    recs = progress.read(state / progress.PROGRESS_DIR)
    assert len(recs) == 1
    r = recs[0]
    assert (r["kind"], r["label"], r["total"], r["done"], r["ran"], r["bad"]) == ("gate", "full", 2, 2, 2, 1)
    assert r["bad_items"] == ["tests/test_red.py"] and r["result"] == "fail" and r["state"] == progress.FINISHED
    assert r["head"] == sh(root, "rev-parse", "HEAD")
    assert progress.history(state / progress.PROGRESS_DIR)[-1]["total"] == 2
    snap = live.collect(sources(root, gate_progress=state / progress.PROGRESS_DIR))
    assert "last gate full fail: 1 red file(s)" in snap["alerts"]
    assert any(k == "gates" and v.startswith("gate full fail 2/2, 1 red") for k, v in live.text_lines(snap))


def test_gate_progress_is_finished_as_interrupted_when_the_run_raises(tmp_path, monkeypatch, capsys):
    root = make_repo(tmp_path / "g", {"tests/test_ok.py": "def test_one():\n    pass\n"})
    from ctf.gate import runner

    def boom(*a, **kw):
        kw["on_row"](runner.Row(test="tests/test_ok.py", status="PASS", seconds=1.0))
        raise KeyboardInterrupt
    monkeypatch.setattr(runner, "run_gate", boom)
    p = argparse.ArgumentParser()
    gate_cli.add_arguments(p)
    state = tmp_path / "state"
    args = p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
                         "run", "--full"])
    assert gate_cli.run(args) == 130
    r = progress.read(state / progress.PROGRESS_DIR)[0]
    assert r["result"] == "interrupted" and r["done"] == 1

    def crash(*a, **kw):
        raise RuntimeError("runner bug")
    monkeypatch.setattr(runner, "run_gate", crash)
    with pytest.raises(RuntimeError, match="runner bug"):         # a crash still propagates
        gate_cli.run(args)
    r = progress.read(state / progress.PROGRESS_DIR)[0]
    assert r["result"] == "error" and r["state"] == progress.FINISHED


def test_gate_warm_rows_count_as_done_not_ran(tmp_path, capsys):
    """A stored green result reused warm is done but did not run: it adds no time to the observed ETA."""
    files = {"lib/val.txt": "7\n", "lib/other.txt": "x\n",
             "tests/test_ok.py": 'VAL = "lib/val.txt"\ndef test_one():\n    pass\n',
             "tests/test_other.py": 'OTHER = "lib/other.txt"\ndef test_two():\n    pass\n'}
    root = make_repo(tmp_path / "g", files)
    p = argparse.ArgumentParser()
    gate_cli.add_arguments(p)
    state = tmp_path / "state"
    argv = ["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
            "run", "--changed", "lib/val.txt", "lib/other.txt", "--jobs", "1"]
    assert gate_cli.run(p.parse_args(argv)) == 0              # both run green and are stored
    (root / "lib/other.txt").write_text("changed\n")
    assert gate_cli.run(p.parse_args(argv)) == 0              # test_ok reused warm, test_other runs
    assert "warm" in [ln for ln in capsys.readouterr().out.splitlines() if "tests/test_ok.py" in ln][-1]
    r = progress.read(state / progress.PROGRESS_DIR)[0]
    assert (r["label"], r["total"], r["done"], r["ran"], r["warm"]) == ("impact", 2, 2, 1, 1)
    assert progress.history(state / progress.PROGRESS_DIR)[-1]["ran"] == 1


# --------------------------------------------------------------------------------------------- event

def _stream(wd: Path, events: list[dict]) -> None:
    p = wd / "watch" / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(json.dumps({"seq": i + 1, "ts": NOW - 100 + i, **e}) + "\n" for i, e in enumerate(events)))


@pytest.fixture
def workdir(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    _stream(wd, [{"event": "board_open", "count": 3},
                 {"event": "challenge_new", "challenge_id": "c1", "points": 100},
                 {"event": "challenge_new", "challenge_id": "c2", "points": 200},
                 {"event": "challenge_new", "challenge_id": "c3", "points": 300},
                 {"event": "points_changed", "challenge_id": "c3", "old": 300, "new": 250},
                 {"event": "team_solved", "challenge_id": "c3"},
                 {"event": "poll_error", "status": 502, "error": "bad gateway", "consecutive": 1}])
    ledger.append("platform.submit", workdir=wd, challenge_id="c1", status="correct", provenance="agent",
                  flag="CSCTF{never_on_the_page}")
    ledger.append("platform.submit", workdir=wd, challenge_id="c2", status="incorrect")
    ledger.append("agent_launch", workdir=wd, challenge_id="c1", harness="claude", pid=os.getpid())
    ledger.append("agent_launch", workdir=wd, challenge_id="c2", harness="codex", pid=DEAD)
    ledger.append("agent_launch", workdir=wd, challenge_id="c3", harness="claude", pid=DEAD)
    ledger.append("agent_exit", workdir=wd, challenge_id="c3", harness="claude", rc=0)
    ledger.append("spend", workdir=wd, challenge_id="c1", usd=1.5, tok=10)
    ledger.append("spend", workdir=wd, challenge_id="c2", usd=2.25, tok=10)
    claims = wd / "dispatch" / "claims"
    claims.mkdir(parents=True)
    (claims / "c1.json").write_text(json.dumps({"intake": "done", "dispatcher_pid": DEAD}))
    (claims / "c2.json").write_text(json.dumps({"intake": "failed", "dispatcher_pid": DEAD}))
    (claims / "c3.json").write_text("{torn")
    return wd


def test_event_board_solves_agents_claims_and_spend(repo, workdir):
    prof = event.load("csctf")
    snap = live.collect(sources(repo, profile=prof, workdir=workdir))
    ev = snap["event"]
    assert ev["board"] == 3 and ev["solved"] == 2 and ev["solved_by_us"] == 1 and ev["solved_team_only"] == 1
    assert ev["points"] == 350.0                       # c1 100 + c3 at its changed 250
    assert (ev["agents_running"], ev["agents_died"]) == (1, 1)
    assert ev["spend_usd"] == 3.75
    assert (ev["claims"], ev["intake"], ev["claims_unreadable"]) == (3, {"done": 1, "failed": 1}, 1)
    assert ev["dispatcher_running"] is False and ev["watcher_pid"] is None
    assert ev["poll_erroring"]["status"] == 502
    assert "1 agent(s) died without an exit record" in snap["alerts"]
    assert "board polls failing (status 502)" in snap["alerts"]
    assert "1 unreadable claim file(s)" in snap["alerts"]
    # nothing secret or path-like reaches the snapshot, the text or the page
    blob = json.dumps(snap, default=str) + live.render_text(snap) + live.render_html(snap, title="t")
    assert "never_on_the_page" not in blob and str(workdir) not in blob and str(repo) not in blob


def test_poll_ok_clears_the_error_and_a_live_event_without_a_watcher_alerts(repo, workdir):
    with open(workdir / "watch" / "events.jsonl", "a") as fh:
        fh.write(json.dumps({"seq": 99, "ts": NOW, "event": "poll_ok", "after_errors": 1, "down_s": 5}) + "\n")
    prof = event.load("csctf")
    live_prof = dataclasses.replace(prof, start=dt.datetime.fromtimestamp(NOW - 3600, dt.timezone.utc),
                                    end=dt.datetime.fromtimestamp(NOW + 3600, dt.timezone.utc))
    snap = live.collect(sources(repo, profile=live_prof, workdir=workdir))
    assert snap["event"]["poll_erroring"] is None and snap["event"]["phase"] == "in-event"
    assert "event is live and no watcher is running (ctf watch run)" in snap["alerts"]
    assert not any(a.startswith("board polls failing") for a in snap["alerts"])
    post = dataclasses.replace(prof, start=dt.date(2020, 1, 1), end=dt.date(2020, 1, 2))
    assert "event is live and no watcher is running (ctf watch run)" not in \
        live.collect(sources(repo, profile=post, workdir=workdir))["alerts"]


def test_corrupt_stream_and_missing_workdir_are_named(repo, tmp_path, workdir):
    prof = event.load("csctf")
    snap = live.collect(sources(repo, profile=prof, workdir=tmp_path / "nope"))
    assert snap["event"]["errors"] == ["the event workdir does not exist yet (nothing has run for this event)"]
    assert snap["alerts"] == []
    with open(workdir / "watch" / "events.jsonl", "a") as fh:
        fh.write("{torn\n")
    snap = live.collect(sources(repo, profile=prof, workdir=workdir))
    assert any(a.startswith("watch stream:") for a in snap["alerts"])
    assert snap["event"]["board"] is None


# --------------------------------------------------------------------------------------------- armed

def test_armed_against_head_at_behind_diverged_unknown(repo, tmp_path):
    wd = tmp_path / "w"
    git = live.make_git(repo)
    a = live.arm(wd, git, note="day 1", now=NOW - 7200)
    s = live.armed_section(sources(repo, workdir=wd), sh(repo, "rev-parse", "HEAD"))
    assert s["state"] == "at HEAD" and s["age_s"] == 7200 and s["note"] == "day 1"
    commit(repo, {"x.txt": "1"}, "one", NOW - 60)
    commit(repo, {"x.txt": "2"}, "two", NOW - 30)
    snap = live.collect(sources(repo, workdir=wd))
    assert snap["armed"]["state"] == "behind HEAD" and snap["armed"]["ahead"] == 2
    assert f"armed {a['commit'][:7]} is behind HEAD (2 commit(s) since); re-arm or restart" in snap["alerts"]
    sh(repo, "checkout", "-q", "-b", "side", a["commit"])
    commit(repo, {"y.txt": "1"}, "side", NOW - 10)
    live.arm(wd, git)
    sh(repo, "checkout", "-q", "-")
    snap = live.collect(sources(repo, workdir=wd))
    assert snap["armed"]["state"] == "diverged"
    live.armed_path(wd).write_text(json.dumps({"commit": "f" * 40, "ts": NOW}))
    assert live.collect(sources(repo, workdir=wd))["armed"]["state"] == "unknown commit"
    live.armed_path(wd).write_text("{")
    snap = live.collect(sources(repo, workdir=wd))
    assert snap["armed"]["state"] == "unreadable" and "armed: unreadable" in snap["alerts"]
    with pytest.raises(live.LiveError, match="not a git checkout"):
        live.arm(wd, live.make_git(tmp_path / "nogit"))


# ---------------------------------------------------------------------------------- jobs and workers

def test_job_records_running_then_its_result(repo, tmp_path):
    folder = tmp_path / "jobs"
    gate_file = tmp_path / "release"
    seen = {}

    def watch_it():
        for _ in range(400):
            recs = progress.read(folder)
            if recs and recs[0].get("child_pid"):
                seen["rec"] = recs[0]
                break
            time.sleep(0.02)
        gate_file.write_text("go")
    t = threading.Thread(target=watch_it)
    t.start()
    code = ("import pathlib,time,sys\np=pathlib.Path(sys.argv[1])\n"
            "while not p.exists(): time.sleep(0.02)\nsys.exit(3)")
    rc = live.run_job("suite", [sys.executable, "-c", code, str(gate_file)], folder=folder, repo=repo)
    t.join()
    assert rc == 3
    assert seen["rec"]["state"] == progress.RUNNING and seen["rec"]["label"] == "suite"
    r = progress.read(folder)[0]
    assert r["result"] == "rc=3" and r["head"] == sh(repo, "rev-parse", "HEAD")
    snap = live.collect(sources(repo, job_progress=folder, now=time.time()))
    assert "job suite finished rc=3" in snap["alerts"]
    assert [v for k, v in live.text_lines(snap) if k == "jobs"][0].startswith("job suite rc=3, ")
    running = dict(seen["rec"], started=snap["generated"] - 60)
    assert live._run_line(running, snap["generated"]) == "job suite running, 60s in"
    assert live.run_job("suite", [sys.executable, "-c", "pass"], folder=folder, repo=repo) == 0
    assert "job suite finished rc=3" not in live.collect(sources(repo, job_progress=folder))["alerts"]
    with pytest.raises(live.LiveError, match="bad job name"):
        live.run_job("../x", ["true"], folder=folder, repo=repo)
    with pytest.raises(live.LiveError, match="cannot start"):
        live.run_job("nope", [str(tmp_path / "no-such-binary")], folder=folder, repo=repo)
    assert progress.read(folder)[0]["result"] == "not started"


def test_a_running_job_on_an_old_head_and_a_died_job_alert_and_forget_clears_died(repo, tmp_path):
    folder = tmp_path / "jobs"
    progress.Progress(folder, "job", total=None, label="old", head="0" * 40, run_id="old")
    dead = progress.Progress(folder, "job", total=5, label="gone", run_id="gone")
    dead.rec["pid"] = DEAD
    progress._write_atomic(dead.path, dead.rec)
    lost = progress.Progress(folder, "job", total=None, label="lost", run_id="lost", clock=lambda: NOW - 300)
    lost.rec.update(pid=DEAD, updated=NOW - 60)
    progress._write_atomic(lost.path, lost.rec)
    snap = live.collect(sources(repo, job_progress=folder))
    head = sh(repo, "rev-parse", "HEAD")
    assert f"job old runs 0000000, HEAD is now {head[:7]}" in snap["alerts"]
    assert "job gone died at 0/5" in snap["alerts"]
    assert "job lost died before it finished" in snap["alerts"]
    lines = [v for k, v in live.text_lines(snap) if k == "jobs"]
    assert any(v.startswith(f"job gone DIED at 0/5 (pid {DEAD} gone") for v in lines)
    assert f"job lost DIED after 4m (pid {DEAD} gone, last update 60s ago)" in lines
    assert sorted(live.forget_died([folder])) == ["job-gone.json", "job-lost.json"]
    assert [r["label"] for r in progress.read(folder)] == ["old"]


def test_workers_worktrees_unmerged_item_branches_and_process_counts(repo, tmp_path):
    base = sh(repo, "rev-parse", "HEAD")
    sh(repo, "branch", "item/B-008")                         # merged (same commit)
    sh(repo, "worktree", "add", "-q", "-b", "item/B-009", str(tmp_path / "wt-nine"))
    commit(tmp_path / "wt-nine", {"n.txt": "9"}, "nine", NOW - 120)
    ps = "/usr/local/bin/claude\nclaude\n/opt/codex\nzsh\nclaude-helper\n"
    w = live.workers_section(sources(repo, ps=lambda: ps))
    assert w["procs"] == {"claude": 2, "codex": 1}
    assert w["waiting_merge"] == ["item/B-009"]
    by = {t["name"]: t for t in w["worktrees"]}
    assert by["wt-nine"]["branch"] == "item/B-009" and by["wt-nine"]["head_age_s"] == 120
    assert by["repo"]["head"] == base
    w = live.workers_section(sources(repo, ps=lambda: None))
    assert w["procs"] is None and w["procs_error"] == "ps could not run"


# ------------------------------------------------------------------------------------ text and page

def test_page_escapes_untrusted_text_and_carries_the_digest_and_time(repo):
    prof = dataclasses.replace(event.load("csctf"), name="<script>alert(1)</script>")
    snap = live.collect(sources(repo, profile=prof, workdir=None))
    title = live.page_title(snap)
    page = live.render_html(snap, title=title, refresh=15)
    assert "<script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    meta = live.page_meta(page)
    assert meta[live.META_DIGEST] == snap["digest"] and meta[live.META_GENERATED] == f"{NOW:.0f}"
    assert '<meta http-equiv="refresh" content="15">' in page
    team = dataclasses.replace(prof, name="CSCTF", platform=dataclasses.replace(prof.platform, team="Our Team"))
    assert live.page_title(live.collect(sources(repo, profile=team))) == "CSCTF - Our Team"
    assert live.page_title(snap, "Override") == "Override"


def test_scrub_keeps_relative_text_and_cuts_absolute_paths():
    roots = [("/srv/work/ev", "<workdir>"), ("/srv/home", "<repo>")]
    assert live.scrub("ledger: /srv/work/ev/ledger.jsonl:3: corrupt", roots) == "ledger: <workdir>/ledger.jsonl:3: corrupt"
    assert live.scrub("no git directory at /opt/x/.git: set V", roots) == "no git directory at <path>/.git: set V"
    assert live.scrub("PermissionError: [Errno 13] denied: '/a/b/c.json'", roots) == \
        "PermissionError: [Errno 13] denied: '<path>/c.json'"
    assert live.scrub("/srv/homework/x", roots) == "<path>/x"            # /srv/home is not a prefix of it
    assert live.scrub("/srv/home/a.py", roots) == "<repo>/a.py"
    for kept in ("item/B-198 2/5 done", "https://h.example/x", "~/ctf-work", "tests/test_x.py", "effort/h",
                 "<script>alert(1)</script>", "<repo>/x", "<path>/x", "<workdir>/ledger.jsonl:3: corrupt"):
        assert live.scrub(kept, roots) == kept
    # a path right after ":" or "-" or ">" is still a path; only a URL scheme's "//" is not
    assert live.scrub("error:/opt/u/secret/x.toml", roots) == "error:<path>/x.toml"
    assert live.scrub("ledger.jsonl:/abs/x", roots) == "ledger.jsonl:<path>/x"
    assert live.scrub("x->/abs/y", roots) == "x-><path>/y"
    assert live.scrub("x-/abs/y", roots) == "x-<path>/y"
    assert live.scrub("file:///abs/q", roots) == "file:<path>/q"
    assert live.scrub("at:/srv/home/a.py", roots) == "at:<repo>/a.py"


def test_scrub_tree_scrubs_keys_values_and_nested_lists():
    roots = [("/srv/home", "<repo>")]
    tree = {"/srv/home/k.json": {"/opt/x/key": ["/srv/home/a", ("/opt/b/c",)], "n": 3}, 7: "/opt/q"}
    assert live._scrub_tree(tree, roots) == \
        {"<repo>/k.json": {"<path>/key": ["<repo>/a", ["<path>/c"]], "n": 3}, 7: "<path>/q"}


def _no_abs_path(blob: str, *paths_: Path) -> None:
    for p in paths_:
        for form in {str(p), str(Path(p).resolve())}:
            assert form not in blob, f"{form} leaked"


def test_no_absolute_path_reaches_the_snapshot_page_or_push(repo, tmp_path, fake):
    """Error notes name files (an unknown slug's profile, a corrupt ledger line, a checkout with no .git):
    the snapshot, page and push carry the file name, never its absolute path."""
    unknown = live.default_sources(event_slug="nosuch").notes["event"]
    with pytest.raises(FileNotFoundError) as nogit:
        paths.gate_state(tmp_path / "nogit")
    assert "event.toml" in unknown and str(tmp_path / "nogit") in str(nogit.value)    # the raw notes hold paths
    wd = tmp_path / "work"
    ledger.append("spend", workdir=wd, challenge_id="c1", usd=1.0)
    with open(ledger.path(wd), "a") as fh:
        fh.write("{torn\n")
    a = live.collect(sources(repo, notes={"event": unknown, "gates": str(nogit.value)}))
    b = live.collect(sources(repo, profile=event.load("csctf"), workdir=wd))
    assert any(al.startswith("ledger: <workdir>/ledger.jsonl:2: corrupt ledger line") for al in b["alerts"])
    assert ("event", a["notes"]["event"]) in live.text_lines(a) and "<path>/event.toml" in a["notes"]["event"]
    assert ("gates", a["notes"]["gates"]) in live.text_lines(a) and "<path>/.git" in a["notes"]["gates"]
    blob = ""
    for snap in (a, b):
        live.push(snap, fake.url + "/t", state_dir=tmp_path / "st", title="x", force=True, now=NOW)
        blob += json.dumps(snap, default=str) + live.render_text(snap) + live.render_html(snap, title="t")
    blob += "".join(p["body"] + json.dumps(p["headers"]) for p in fake.posts)
    assert len(fake.posts) == 2 and "corrupt ledger line" in fake.posts[1]["body"]
    _no_abs_path(blob, tmp_path, repo, paths.repo_root(), Path.home())


def test_digest_tracks_state_not_time(repo, tmp_path):
    folder = tmp_path / "jobs"
    a = live.collect(sources(repo, job_progress=folder))
    b = live.collect(sources(repo, job_progress=folder, now=NOW + 500))
    assert a["digest"] == b["digest"]
    p = progress.Progress(folder, "gate", total=3, label="impact")
    c = live.collect(sources(repo, job_progress=folder))
    p.step(seconds=1)
    d = live.collect(sources(repo, job_progress=folder))
    assert len({a["digest"], c["digest"], d["digest"]}) == 3
    # the push key ignores progress counts (no push per test file), not a new red file
    assert live.push_key(c) == live.push_key(d)
    p.step(seconds=1, bad="t")
    assert live.push_key(live.collect(sources(repo, job_progress=folder))) != live.push_key(d)


# ------------------------------------------------------------------------------- fake push/page host

class Fake:
    def __init__(self):
        self.posts: list[dict] = []
        self.status = 200
        self.page = b""
        self.ctype = "text/html; charset=utf-8"
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                fake.posts.append({"path": self.path, "body": self.rfile.read(n).decode(),
                                   "headers": dict(self.headers)})
                self.send_response(fake.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                self.send_response(fake.status)
                self.send_header("Content-Type", fake.ctype)
                self.send_header("Content-Length", str(len(fake.page)))
                self.end_headers()
                self.wfile.write(fake.page)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        if not getattr(self, "closed", False):
            self.closed = True
            self.srv.shutdown()
            self.srv.server_close()


@pytest.fixture
def fake():
    f = Fake()
    yield f
    f.close()


def test_push_sends_on_change_only_and_alerts_jump_the_interval(repo, tmp_path, fake):
    st = tmp_path / "st"
    folder = tmp_path / "jobs"
    url = fake.url + "/topic-secret"
    snap = live.collect(sources(repo, job_progress=folder))
    assert live.push(snap, url, state_dir=st, title="CSCTF", now=NOW) == "sent"
    post = fake.posts[-1]
    assert post["path"] == "/topic-secret" and post["headers"]["Priority"] == "3"
    assert post["headers"]["Title"] == "CSCTF: ok" and "plan:" in post["body"]
    assert live.push(snap, url, state_dir=st, title="CSCTF", now=NOW + 1) == "unchanged"
    p = progress.Progress(folder, "gate", total=4, label="impact")
    s2 = live.collect(sources(repo, job_progress=folder))
    assert live.push(s2, url, state_dir=st, title="CSCTF", min_interval=60, now=NOW + 2) == "too soon"
    assert live.push(s2, url, state_dir=st, title="CSCTF", min_interval=60, now=NOW + 120) == "sent"
    p.rec["pid"] = DEAD
    progress._write_atomic(p.path, p.rec)
    s3 = live.collect(sources(repo, job_progress=folder))
    assert live.push(s3, url, state_dir=st, title="CSCTF", min_interval=600, now=NOW + 121) == "sent"
    assert fake.posts[-1]["headers"]["Priority"] == "4" and "ALERT: gate impact died" in fake.posts[-1]["body"]
    assert len(fake.posts) == 3
    assert live.push(s3, url, state_dir=st, title="CSCTF", force=True, now=NOW + 122) == "sent"


def test_a_failed_push_is_an_error_and_is_retried(repo, tmp_path, fake):
    st = tmp_path / "st"
    snap = live.collect(sources(repo))
    fake.status = 500
    with pytest.raises(live.PushError, match="HTTP 500"):
        live.push(snap, fake.url + "/t", state_dir=st, title="x", now=NOW)
    assert not (st / live.PUSH_STATE).exists()
    fake.status = 200
    assert live.push(snap, fake.url + "/t", state_dir=st, title="x", now=NOW) == "sent"


def test_endpoints_are_never_the_platform_or_a_challenge_target(repo, tmp_path, monkeypatch):
    prof = event.load("csctf")

    def never(*a, **kw):
        raise AssertionError("a refused endpoint must not be contacted")
    snap = live.collect(sources(repo))
    host = prof.platform.base_url
    for url, why in ((host + "/x", "event platform"), ("https://web.ctf-platform.example/x", "live challenge target"),
                     ("ftp://127.0.0.1/x", r"an http\(s\) URL")):
        with pytest.raises(live.LiveError, match=why):
            live.push(snap, url, state_dir=tmp_path, title="x", profile=prof, opener=never)
        with pytest.raises(live.LiveError, match=why):
            live.smoke(url, profile=prof, opener=never)
    monkeypatch.setenv("CTF_PLATFORM_URL", "https://board.other.example")
    with pytest.raises(live.LiveError, match="event platform"):
        live.check_endpoint("https://board.other.example/p", None)
    assert live.check_endpoint("http://127.0.0.1:9/p", prof) == "127.0.0.1"


def test_with_no_event_the_endpoint_is_checked_against_every_profile(repo, tmp_path, monkeypatch):
    """--no-event (or no resolvable event) is not a way past the scope: every profile's platform and
    live_service_scope are refused."""
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)
    monkeypatch.delenv("CTF_EVENT", raising=False)
    slugs = event.available()
    assert {"csctf", "huntress"} <= set(slugs)

    def never(*a, **kw):
        raise AssertionError("a refused endpoint must not be contacted")
    snap = live.collect(sources(repo))
    hunt = event.load("huntress").platform.base_url
    for url, why in ((hunt + "/x", "event platform"),
                     ("https://web.ctf-platform.example/x", "live challenge target of event 'csctf'")):
        with pytest.raises(live.LiveError, match=why):
            live.check_endpoint(url, None)
        with pytest.raises(live.LiveError, match=why):
            live.push(snap, url, state_dir=tmp_path, title="x", opener=never)
        with pytest.raises(live.LiveError, match=why):
            live.smoke(url, opener=never)
    assert live.check_endpoint("http://127.0.0.1:9/p", None) == "127.0.0.1"
    # every profile, not only the first: a later profile's challenge host is refused too
    for url, slug in (("https://x.huntress.example/", "huntress"), ("https://x.pink.ctf.example/", "pink")):
        with pytest.raises(live.LiveError, match=f"live challenge target of event '{slug}'"):
            live.check_endpoint(url, None)
    real_load = event.load

    def broken(slug, root=None):
        if slug == "huntress":
            raise event.EventError("events/huntress/event.toml: not valid TOML")
        return real_load(slug, root)
    monkeypatch.setattr(event, "load", broken)
    with pytest.raises(live.LiveError, match="against event 'huntress': its profile does not load"):
        live.check_endpoint("http://127.0.0.1:9/p", None)
    assert live.check_endpoint("http://127.0.0.1:9/p", real_load("csctf")) == "127.0.0.1"


def test_cli_push_and_smoke_with_no_event_refuse_a_challenge_host(status_env, stable, capsys):
    assert run_cli("push", "--no-event", "--url", "https://web.ctf-platform.example/t") == 2
    assert "live challenge target of event 'csctf'" in capsys.readouterr().err
    assert run_cli("smoke", "--no-event", "https://web.ctf-platform.example/") == 2
    assert "live challenge target of event 'csctf'" in capsys.readouterr().err


def test_smoke_passes_on_our_fresh_page_and_names_each_failure(repo, tmp_path, fake):
    snap = live.collect(sources(repo))
    fake.page = live.render_html(snap, title="t").encode()
    ok = live.smoke(fake.url + "/", expect_digest=snap["digest"], now=NOW + 10)
    assert [c.name for c in ok] == ["http", "html", "marker", "fresh", "digest"] and all(c.ok for c in ok)
    stale = {c.name: c for c in live.smoke(fake.url + "/", max_age=600, now=NOW + 601)}
    assert not stale["fresh"].ok and stale["http"].ok
    other = {c.name: c for c in live.smoke(fake.url + "/", expect_digest="0" * 64, now=NOW)}
    assert not other["digest"].ok
    fake.ctype = "text/plain"
    assert not {c.name: c for c in live.smoke(fake.url + "/", now=NOW)}["html"].ok
    fake.ctype, fake.page = "text/html", b"<html>an old deploy</html>"
    res = {c.name: c for c in live.smoke(fake.url + "/", now=NOW)}
    assert not res["marker"].ok and "fresh" not in res
    fake.status = 404
    res = live.smoke(fake.url + "/", now=NOW)
    assert len(res) == 1 and not res[0].ok and "HTTP 404" in res[0].detail
    fake.close()
    down = live.smoke(fake.url + "/", now=NOW)
    assert not down[0].ok and "no answer" in down[0].detail


# ----------------------------------------------------------------------------------------------- CLI

def run_cli(*argv) -> int:
    from ctf.cli import main
    return main(["live", *argv])


@pytest.fixture
def status_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_STATUS_STATE", str(tmp_path / "status-state"))
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))      # never this host's ~/ctf-work/<slug>
    monkeypatch.delenv(live.PUSH_ENV, raising=False)
    return tmp_path / "status-state"


@pytest.fixture
def stable(monkeypatch, repo, tmp_path):
    """The CLI's sources pointed at a temp checkout: the shared real checkout changes under a test (other
    builders add worktrees and branches), which would make 'unchanged' pushes flaky."""
    real = live.default_sources

    def fixed(**kw):
        s = real(**kw)
        s.repo, s.git, s.ps = repo, live.make_git(repo), (lambda: "")
        s.gate_progress = tmp_path / "gate-progress"
        return s
    monkeypatch.setattr(live, "default_sources", fixed)
    return repo


def test_cli_show_json_page_and_event_flags_after_the_action(status_env, tmp_path, capsys):
    assert run_cli("--no-event", "--json") == 0
    snap = json.loads(capsys.readouterr().out)
    assert snap["event"] is None and snap["notes"]["event"] == "not read (--no-event)"
    assert {"build", "plan", "gates", "jobs", "workers", "armed", "etas", "alerts", "digest"} <= set(snap)
    out = tmp_path / "site" / "index.html"
    assert run_cli("page", "--event", "csctf", "--out", str(out), "--title", "Team") == 0
    page = out.read_text()
    assert "<title>Team</title>" in page and "csctf (" in page
    assert run_cli("page", "--no-event", "--out", str(out)) == 0
    assert "no event" not in out.read_text() and "not read (--no-event)" in out.read_text()
    capsys.readouterr()
    assert run_cli("show", "--no-event") == 0
    text = capsys.readouterr().out
    assert text.splitlines()[1].startswith("build ") and "plan " in text


def test_cli_push_needs_a_url_and_never_prints_it(status_env, stable, fake, capsys, monkeypatch):
    assert run_cli("--no-event", "push") == 2
    assert live.PUSH_ENV in capsys.readouterr().err
    monkeypatch.setenv(live.PUSH_ENV, fake.url + "/s3cr3t-topic")
    assert run_cli("push", "--no-event") == 0
    assert run_cli("push", "--no-event") == 0
    out, err = capsys.readouterr()
    assert out.splitlines() == ["live: push sent", "live: push unchanged"]
    assert "s3cr3t" not in out + err
    fake.status = 503
    assert run_cli("push", "--no-event", "--force") == 1
    out, err = capsys.readouterr()
    assert "HTTP 503" in err and "s3cr3t" not in out + err


def test_cli_loop_writes_the_page_and_pushes_once_per_change(status_env, stable, fake, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv(live.PUSH_ENV, fake.url + "/t")
    page = tmp_path / "p.html"
    assert run_cli("loop", "--no-event", "--every", "0", "--count", "3", "--page", str(page), "--push") == 0
    assert page.exists() and len(fake.posts) == 1
    assert run_cli("loop", "--no-event", "--every", "0", "--count", "1") == 2
    assert "loop needs --page" in capsys.readouterr().err


def test_cli_smoke_against_the_local_page(status_env, stable, fake, tmp_path, capsys):
    page = tmp_path / "index.html"
    assert run_cli("page", "--no-event", "--out", str(page)) == 0
    fake.page = page.read_bytes()
    assert run_cli("smoke", "--no-event", fake.url + "/", "--local", str(page)) == 0
    assert "SMOKE result=pass" in capsys.readouterr().out
    fake.page = fake.page.replace(b'name="ctf-live-digest" content="', b'name="ctf-live-digest" content="00')
    assert run_cli("smoke", "--no-event", fake.url + "/", "--local", str(page)) == 1
    out = capsys.readouterr().out
    assert "FAIL digest" in out and "SMOKE result=fail" in out
    (tmp_path / "plain.html").write_text("<html></html>")
    assert run_cli("smoke", fake.url + "/", "--local", str(tmp_path / "plain.html")) == 2


def test_cli_job_and_forget(status_env, capsys):
    assert run_cli("job", "--name", "unit", "--", sys.executable, "-c", "import sys; sys.exit(4)") == 4
    recs = progress.read(status_env / progress.PROGRESS_DIR)
    assert recs[0]["label"] == "unit" and recs[0]["result"] == "rc=4"
    assert run_cli("job", "--name", "unit") == 2
    assert "no command given" in capsys.readouterr().err
    assert run_cli("forget", "--died") == 0
    assert "removed 0 died" in capsys.readouterr().out


def test_cli_arm_needs_an_event(status_env, tmp_path, capsys, monkeypatch):
    assert run_cli("arm", "--no-event") == 2
    assert "cannot arm" in capsys.readouterr().err
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    assert run_cli("arm", "--event", "csctf", "--note", "release") == 0
    rec = json.loads((tmp_path / "wd" / live.STATUS_DIR / live.ARMED).read_text())
    assert rec["commit"] == live.make_git(paths.repo_root())("rev-parse", "HEAD") and rec["note"] == "release"


# --------------------------------------------------------------------------------------------- paths

def test_status_state_override_checkout_and_worktree(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_STATUS_STATE", str(tmp_path / "st"))
    assert paths.status_state() == (tmp_path / "st").resolve()
    monkeypatch.delenv("CTF_STATUS_STATE")
    main = tmp_path / "main"
    main.mkdir()
    sh(main, "init", "-q")
    commit(main, {"a": "1"}, "a", NOW)
    assert paths.status_state(main) == (main / ".git" / "ctf-status").resolve()
    sh(main, "worktree", "add", "-q", str(tmp_path / "wt"))
    assert paths.status_state(tmp_path / "wt") == (main / ".git" / "ctf-status").resolve()
    with pytest.raises(FileNotFoundError, match="CTF_STATUS_STATE"):
        paths.status_state(tmp_path)
    with pytest.raises(FileNotFoundError, match="CTF_GATE_STATE"):
        paths.gate_state(tmp_path)
