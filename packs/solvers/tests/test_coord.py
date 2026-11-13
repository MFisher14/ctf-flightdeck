"""B-239: completion-driven agent coordination (ctf/coord.py, ctf/cli/coord.py).

Parents block on a child's completion instead of timed polls; a per-lane relay passes only new findings
and decisions under a cap; one command shows lane state. Every child here is synthetic: a callback on a
fake clock that writes the files a real child would (completion file, campaign state, job exit record,
standby presence, dispatch claim, lane message), plus one real child process that runs the CLI. No
agent session, no model, no network.
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import campaign, coord, dispatch, ledger, paths, spawn, standby
from ctf.cli import main as ctf_main


@pytest.fixture
def wd(tmp_path, monkeypatch):
    w = tmp_path / "work"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    monkeypatch.delenv("CTF_JOBS_DIR", raising=False)
    return w


class Clock:
    """A monotonic clock that moves only when the waiter sleeps; `at(t, fn)` runs fn (a child acting)
    once the clock passes t."""

    def __init__(self):
        self.t = 0.0
        self.todo: list[tuple[float, object]] = []
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    def at(self, t: float, fn) -> None:
        self.todo.append((t, fn))
        self.todo.sort(key=lambda x: x[0])

    def sleep(self, d: float) -> None:
        assert d > 0, "the waiter slept for nothing (a busy loop)"
        self.sleeps.append(d)
        assert len(self.sleeps) < 100_000, "the wait never returned"
        self.t += d
        while self.todo and self.todo[0][0] <= self.t:
            self.todo.pop(0)[1]()


def run_wait(wd, targets, c: Clock, **kw):
    kw.setdefault("timeout", 600.0)
    return coord.wait(targets, workdir=wd, clock=c, sleep=c.sleep, wall=lambda: 1000.0 + c.t, **kw)


def dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def put_claim(wd: Path, cid: str, **fields) -> None:
    p = dispatch.claim_path(wd, cid)
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {"schema": 1, "challenge_id": cid, "name": f"chal {cid}", "category": "web", "lane": "web",
           "points": 100, "seq": 1, "status": "dispatched", "intake": "pending", "handout": str(wd / "h.md"),
           **fields}
    p.write_text(json.dumps(rec))


# ------------------------------------------------------------------------------- completion files

def test_completion_file_is_written_once_and_holds_a_one_line_summary(wd):
    rec = coord.complete("c1", "done", "found\nthe key\x1b[31m", paths=["a.txt", "b.txt"],
                         challenge_id="12", lane="web", by="codex:1", workdir=wd, clock=lambda: 5.0)
    on_disk = json.loads(coord.done_path(wd, "c1").read_text())
    assert on_disk == rec
    assert rec["summary"] == "found the key [31m" and "\n" not in rec["summary"]
    assert rec["paths"] == ["a.txt", "b.txt"] and rec["ts"] == 5.0
    with pytest.raises(coord.CoordError, match="already completed"):
        coord.complete("c1", "failed", "second result", workdir=wd)
    assert json.loads(coord.done_path(wd, "c1").read_text())["status"] == "done"
    coord.complete("c1", "failed", "second result", replace=True, workdir=wd)
    assert json.loads(coord.done_path(wd, "c1").read_text())["status"] == "failed"
    assert not [p for p in coord.done_path(wd, "c1").parent.iterdir() if p.name.endswith(".tmp")]


@pytest.mark.parametrize("kw, msg", [
    ({"status": "ok"}, "completion status"),
    ({"summary": "  \n "}, "needs a summary"),
    ({"child": "../x"}, "bad child id"),
    ({"child": "a..b"}, "bad child id"),
    ({"paths": [f"p{i}" for i in range(coord.MAX_PATHS + 1)]}, "at most"),
    ({"lane": "a/b"}, "bad lane"),
])
def test_a_bad_completion_is_refused_by_name(wd, kw, msg):
    args = {"child": "c1", "status": "done", "summary": "s", **kw}
    with pytest.raises(coord.CoordError, match=msg):
        coord.complete(args.pop("child"), args.pop("status"), args.pop("summary"), workdir=wd, **args)
    assert not (coord.coord_dir(wd) / coord.DONE_DIR / "c1.json").exists()


# ------------------------------------------------------------------------------- waiting (fake clock)

def test_wait_returns_once_when_the_child_completes_with_one_check_per_interval(wd):
    c = Clock()
    c.at(30.0, lambda: coord.complete("c1", "done", "flag candidate in out.txt", paths=["out.txt"],
                                      workdir=wd))
    res = run_wait(wd, ["c1"], c, interval=0.5)
    assert res.code == coord.EXIT_OK and not res.timed_out
    assert c.t == 30.0                            # woke at the completion, not at the timeout
    assert res.checks == 61                       # 0, 0.5, ... 30: one file check per interval
    assert all(d == 0.5 for d in c.sleeps)
    out = res.render()
    assert "child:c1 done: flag candidate in out.txt -> out.txt" in out
    assert out.startswith("ctf coord wait: 1 of 1 completed after 30s")


def test_wait_for_all_holds_until_the_last_child_and_reports_a_failure(wd):
    c = Clock()
    c.at(10.0, lambda: coord.complete("a", "done", "ok", workdir=wd))
    c.at(90.0, lambda: coord.complete("b", "failed", "crashed on input", workdir=wd))
    res = run_wait(wd, ["child:a", "b"], c)
    assert c.t == 90.0
    assert res.code == coord.EXIT_FAILED
    assert [p.state for p in res.probes] == ["done", "failed"]


def test_wait_any_returns_at_the_first_completion(wd):
    c = Clock()
    c.at(10.0, lambda: coord.complete("b", "blocked", "needs the player's ruling", workdir=wd))
    c.at(90.0, lambda: coord.complete("a", "done", "ok", workdir=wd))
    res = run_wait(wd, ["a", "b"], c, any_=True)
    assert c.t == 10.0
    assert res.code == coord.EXIT_FAILED            # the one that ended is blocked, not done
    assert "child:a pending" in res.render() and "child:b blocked: needs the player's ruling" in res.render()
    c2 = Clock()
    c2.at(5.0, lambda: coord.complete("d", "done", "ok", workdir=wd))
    assert run_wait(wd, ["d", "never"], c2, any_=True).code == coord.EXIT_OK


def test_timeout_returns_124_once_and_is_logged(wd):
    c = Clock()
    res = run_wait(wd, ["c9"], c, timeout=60.0, interval=7.0)
    assert res.timed_out and res.code == coord.EXIT_TIMEOUT
    assert c.t == 60.0                              # the last sleep is cut to the timeout, not past it
    assert c.sleeps[-1] == pytest.approx(60.0 - 56.0)
    assert "wait again, do not poll" in res.render()
    c2 = Clock()
    c2.at(3.0, lambda: coord.complete("c8", "done", "ok", workdir=wd))
    run_wait(wd, ["c8"], c2)
    recs = [json.loads(x) for x in (coord.coord_dir(wd) / coord.WAITS_LOG).read_text().splitlines()]
    assert [r["outcome"] for r in recs] == ["timeout", "completed"]
    assert recs[0]["targets"] == ["child:c9"] and recs[0]["code"] == 124 and recs[0]["waited_s"] == 60.0
    s = coord.stats(wd)
    assert (s["waits"], s["completed"], s["timed_out"]) == (2, 1, 1)


def test_a_short_timed_poll_is_refused_unless_allowed(wd):
    with pytest.raises(coord.CoordError, match="timed poll"):
        run_wait(wd, ["c1"], Clock(), timeout=coord.MIN_TIMEOUT - 1)
    res = run_wait(wd, ["c1"], Clock(), timeout=coord.MIN_TIMEOUT)
    assert res.code == coord.EXIT_TIMEOUT
    res = run_wait(wd, ["c1"], Clock(), timeout=1.0, allow_short=True)
    assert res.code == coord.EXIT_TIMEOUT and res.waited_s == 1.0
    with pytest.raises(coord.CoordError, match="twice"):
        run_wait(wd, ["c1", "child:c1"], Clock())
    with pytest.raises(coord.CoordError, match="at least one target"):
        run_wait(wd, [], Clock())


def test_no_timeout_waits_as_long_as_it_takes(wd):
    c = Clock()
    c.at(5000.0, lambda: coord.complete("long", "done", "ok", workdir=wd))
    res = run_wait(wd, ["long"], c, timeout=None, interval=10.0)
    assert res.code == 0 and c.t == 5000.0


@pytest.mark.parametrize("text, msg", [
    ("nope:x", "unknown target kind"),
    ("child:x=waiting", "only a standby target"),
    ("standby:w=sleeping", "standby states"),
    ("job:../x", "bad job id"),
])
def test_bad_targets_are_named(text, msg):
    with pytest.raises(coord.CoordError, match=msg):
        coord.parse_target(text)


def test_parse_target_defaults_and_states():
    assert coord.parse_target("c1") == coord.Target("child", "c1")
    t = coord.parse_target("standby:w-1=assigned,left")
    assert t.kind == "standby" and t.ident == "w-1" and t.want == {"assigned", "left"}
    assert str(t) == "standby:w-1=assigned,left"


# ------------------------------------------------------------------------------- other targets

def test_campaign_agent_done_failed_and_lost(wd):
    camp = campaign.Campaign(wd)
    camp.register("a1", "codex", challenge="12")
    camp.register("a2", "claude")
    c = Clock()
    c.at(20.0, lambda: camp.finish("a1", "done", note="solved", rc=0))
    res = run_wait(wd, ["campaign:a1"], c)
    assert c.t == 20.0 and res.code == 0
    assert "campaign:a1 done rc=0 challenge=12: solved" in res.render()
    c = Clock()
    c.at(4.0, lambda: camp.finish("a2", "failed", note="tool crashed", rc=3))
    assert run_wait(wd, ["campaign:a2"], c).code == coord.EXIT_FAILED

    # registered with a heartbeat older than the campaign's stale limit: lost, nothing written
    old = campaign.Campaign(wd, now=lambda: 1_000.0)
    old.register("a3", "codex")
    rev = camp.load()["rev"]
    res = run_wait(wd, ["campaign:a3"], Clock())
    assert res.code == coord.EXIT_FAILED and res.probes[0].state == "lost"
    assert "no heartbeat" in res.probes[0].line
    assert camp.load()["rev"] == rev and camp.load()["agents"]["a3"]["status"] == "running"

    # a supervised agent whose lock nobody holds: its supervisor is gone
    with camp.transaction() as st:
        st["agents"]["a4"] = {**st["agents"]["a1"], "id": "a4", "status": "running", "supervised": True}
    assert run_wait(wd, ["campaign:a4"], Clock()).probes[0].state == "lost"
    # the same agent while its supervisor holds the lock is running
    camp.agents_dir.mkdir(parents=True, exist_ok=True)
    with open(camp.agent_lock("a4"), "w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        res = run_wait(wd, ["campaign:a4"], Clock(), timeout=1.0, allow_short=True)
        assert res.code == coord.EXIT_TIMEOUT and res.probes[0].line == "campaign:a4 pending: running"

    with pytest.raises(coord.CoordError, match="no agent 'ghost'"):
        run_wait(wd, ["campaign:ghost"], Clock())


def _fake_job(root: Path, jid: str) -> Path:
    d = root / jid
    d.mkdir(parents=True)
    (d / "job.json").write_text(json.dumps({"id": jid, "argv": ["solve"], "pid": 1, "created_at": 0}))
    (d / "lock").write_text("")
    return d


def test_job_target_reads_the_b144_exit_record(wd, tmp_path):
    root = wd / "jobs"
    d = _fake_job(root, "j1")
    c = Clock()
    with open(d / "lock", "a+") as lf:          # the supervisor holds the lock while the command runs
        fcntl.flock(lf, fcntl.LOCK_EX)
        c.at(12.0, lambda: (d / "exit.json").write_text(json.dumps({"rc": 0, "duration_s": 12.0})))
        res = run_wait(wd, ["job:j1"], c)
    assert c.t == 12.0 and res.code == 0 and "job:j1 exited rc=0" in res.probes[0].line
    d2 = _fake_job(root, "j2")
    (d2 / "exit.json").write_text(json.dumps({"rc": 7}))
    assert run_wait(wd, ["job:j2"], Clock()).code == coord.EXIT_FAILED
    _fake_job(root, "j3")                        # no lock holder, no exit record: the supervisor died
    res = run_wait(wd, ["job:j3"], Clock())
    assert res.probes[0].state == "lost" and res.code == coord.EXIT_FAILED
    with pytest.raises(coord.CoordError, match="no job 'j9'"):
        run_wait(wd, ["job:j9"], Clock())
    other = tmp_path / "elsewhere"
    _fake_job(other, "j4")
    (other / "j4" / "exit.json").write_text(json.dumps({"rc": 0}))
    assert run_wait(wd, ["job:j4"], Clock(), jobs_root=other).code == 0


def test_standby_presence_states(wd):
    c = Clock()
    c.at(8.0, lambda: standby.register(wd, "w1", status=standby.WAITING, pid=None))
    res = run_wait(wd, ["standby:w1"], c)
    assert c.t == 8.0 and res.code == 0 and res.probes[0].state == "waiting"
    c = Clock()
    c.at(15.0, lambda: standby.register(wd, "w1", status=standby.ASSIGNED, challenge_id="12", pid=None))
    res = run_wait(wd, ["standby:w1=assigned"], c)
    assert c.t == 15.0 and res.code == 0 and "standby:w1=assigned assigned on 12" in res.probes[0].line
    standby.register(wd, "w2", status=standby.LEFT, pid=None)
    assert run_wait(wd, ["standby:w2=assigned"], Clock()).code == coord.EXIT_FAILED
    assert run_wait(wd, ["standby:w2"], Clock()).code == 0
    standby.register(wd, "w3", status=standby.WAITING, pid=dead_pid())
    res = run_wait(wd, ["standby:w3"], Clock())
    assert res.probes[0].state == "lost" and res.code == coord.EXIT_FAILED
    standby.register(wd, "w4", status=standby.WAITING, pid=os.getpid())
    res = run_wait(wd, ["standby:w4=assigned"], Clock(), timeout=2.0, allow_short=True)
    assert res.code == coord.EXIT_TIMEOUT and res.probes[0].line == "standby:w4=assigned pending: waiting"


def test_claim_target_waits_for_intake(wd):
    put_claim(wd, "12", intake="started")
    c = Clock()
    c.at(40.0, lambda: dispatch.update_claim(wd, "12", intake="done"))
    res = run_wait(wd, ["claim:12"], c)
    assert c.t == 40.0 and res.code == 0 and "lane=web intake=done" in res.probes[0].line
    put_claim(wd, "13", intake="failed", intake_attempts=3, intake_error="download 404")
    res = run_wait(wd, ["claim:13"], Clock())
    assert res.code == coord.EXIT_FAILED and "download 404" in res.probes[0].line
    put_claim(wd, "14", intake="off")
    assert run_wait(wd, ["claim:14"], Clock()).code == 0
    c = Clock()
    c.at(9.0, lambda: put_claim(wd, "15", intake="done"))
    assert run_wait(wd, ["claim:15"], c).code == 0 and c.t == 9.0
    dispatch.claim_path(wd, "16").write_text("{not json")
    with pytest.raises(coord.CoordError, match="unreadable claim"):
        run_wait(wd, ["claim:16"], Clock())


def test_msg_target_wakes_on_a_new_finding_and_moves_the_waiters_cursor(wd):
    coord.send("web", "finding", "old finding", sender="h1", workdir=wd)
    c = Clock()                                   # unseen by the parent's cursor: wakes at once
    res = run_wait(wd, ["msg:web"], c, as_agent="parent")
    assert c.t == 0.0 and res.code == 0 and "old finding" in res.render()
    c = Clock()
    c.at(5.0, lambda: coord.send("web", "finding", "my own note", sender="parent", workdir=wd))
    c.at(25.0, lambda: coord.send("web", "status", "still working", sender="h1", workdir=wd))
    c.at(50.0, lambda: coord.send("web", "finding", "JWT alg none accepted", sender="h2", workdir=wd))
    res = run_wait(wd, ["msg:web"], c, as_agent="parent")
    assert c.t == 50.0 and res.code == 0          # own message and a dropped status did not wake it
    out = res.render()
    assert "JWT alg none accepted" in out and "old finding" not in out and "my own note" not in out
    assert "still working" not in out
    assert coord.inbox("web", "parent", workdir=wd) == []      # the wait delivered them
    # without --as the baseline is the lane at the start
    c = Clock()
    c.at(7.0, lambda: coord.send("web", "decision", "stop the SSTI lane", sender="parent", workdir=wd))
    res = run_wait(wd, ["msg:web"], c)
    assert c.t == 7.0 and "stop the SSTI lane" in res.render() and "old finding" not in res.render()


# ------------------------------------------------------------------------------- a real child process

def test_a_real_child_process_completes_and_the_parent_cli_wait_wakes(wd, capsys):
    script = ("import subprocess, sys, time; time.sleep(0.3); "
              "sys.exit(subprocess.call([sys.executable, '-m', 'ctf', 'coord', '--workdir', sys.argv[1], 'done', "
              "'k1', '--status', 'done', '--summary', 'rsa factored', '--challenge', '7']))")
    env = {**os.environ, "PYTHONPATH": str(paths.repo_root())}
    child = subprocess.Popen([sys.executable, "-c", script, str(wd)], cwd=str(paths.repo_root()), env=env)
    try:
        rc = ctf_main(["coord", "--workdir", str(wd), "wait", "child:k1", "--timeout", "600"])
    finally:
        child.wait(timeout=600)
    assert child.returncode == 0
    assert rc == 0
    out = capsys.readouterr().out
    assert "child:k1 done (7): rsa factored" in out


# ------------------------------------------------------------------------------- the relay

def test_relay_passes_only_new_findings_and_decisions(wd):
    v = coord.send("web", "finding", "SSTI in the name param", sender="h1", workdir=wd, clock=lambda: 1.0)
    assert v.delivered and v.seq == 1
    v = coord.send("web", "Finding", "ssti  IN the name-param!", sender="h2", workdir=wd)
    assert not v.delivered and v.reason == "repeat"
    v = coord.send("web", "decision", "SSTI in the name param", sender="parent", workdir=wd)
    assert v.delivered and v.seq == 2               # same text, other kind: a decision is new
    for kind, home in [("status", "orch report"), ("question", "--status blocked"), ("ack", "not sent"),
                       ("chatter", "status line")]:
        v = coord.send("web", kind, f"{kind} text", sender="h1", workdir=wd)
        assert not v.delivered and v.reason == "kind" and home in v.detail
    assert [m["seq"] for m in coord.messages(wd, "web")] == [1, 2]
    dr = coord.dropped(wd, "web")
    assert [d["reason"] for d in dr] == ["repeat", "kind", "kind", "kind", "kind"]
    assert dr[0]["from"] == "h2"
    with pytest.raises(coord.CoordError, match="empty"):
        coord.send("web", "finding", " \n", sender="h1", workdir=wd)
    with pytest.raises(coord.CoordError, match="bad lane"):
        coord.send("../web", "finding", "x", sender="h1", workdir=wd)


def test_the_lane_cap_holds_messages_until_the_player_raises_it(wd, capsys):
    coord.set_cap(wd, "pwn", 2, by="player", reason="test cap")
    assert coord.send("pwn", "finding", "one", sender="a", workdir=wd).delivered
    assert coord.send("pwn", "finding", "two", sender="a", workdir=wd).delivered
    v = coord.send("pwn", "decision", "three", sender="parent", workdir=wd)
    assert not v.delivered and v.reason == "cap" and "coord cap pwn" in v.detail
    assert ctf_main(["coord", "--workdir", str(wd), "send", "pwn", "finding", "four", "--from", "a"]) == 3
    assert "not sent (cap)" in capsys.readouterr().err
    assert ctf_main(["coord", "--workdir", str(wd), "cap", "pwn", "3", "--reason", "late wave"]) == 0
    assert coord.lane_cap(wd, "pwn") == 3
    assert coord.send("pwn", "decision", "three", sender="parent", workdir=wd).delivered
    assert not coord.send("pwn", "finding", "five", sender="a", workdir=wd).delivered
    assert coord.lane_cap(wd, "web") == coord.LANE_MSG_CAP
    with pytest.raises(coord.CoordError, match="needs a reason"):
        coord.set_cap(wd, "pwn", 9, by="p", reason=" ")
    (coord.lane_dir(wd, "pwn") / coord.CAP_NAME).write_text(json.dumps({"cap": "lots"}))
    with pytest.raises(coord.CoordError, match="non-negative integer"):
        coord.send("pwn", "finding", "six", sender="a", workdir=wd)


def test_the_default_cap_is_enforced(wd):
    for i in range(coord.LANE_MSG_CAP):
        assert coord.send("re", "finding", f"finding number {i}", sender="a", workdir=wd).delivered
    v = coord.send("re", "finding", "one more", sender="a", workdir=wd)
    assert not v.delivered and v.reason == "cap"


def test_inbox_shows_unseen_messages_once_and_never_the_readers_own(wd):
    coord.send("web", "finding", "f1", sender="h1", workdir=wd)
    coord.send("web", "decision", "d1", sender="parent", workdir=wd)
    assert [m["text"] for m in coord.inbox("web", "parent", workdir=wd, peek=True)] == ["f1"]
    assert [m["text"] for m in coord.inbox("web", "h1", workdir=wd)] == ["d1"]
    assert coord.inbox("web", "h1", workdir=wd) == []
    assert [m["text"] for m in coord.inbox("web", "parent", workdir=wd)] == ["f1"]
    assert coord.inbox("web", "parent", workdir=wd) == []
    coord.send("web", "finding", "f2", sender="h2", workdir=wd)
    assert [m["text"] for m in coord.inbox("web", "h1", workdir=wd)] == ["f2"]


def test_relay_forwards_lane_results_from_the_ledger_once(wd, capsys):
    spawn.record_result("12", "web", "found", "admin cookie forgeable", paths=["12/notes.md"], workdir=wd)
    spawn.record_result("12", "web", "partial", "half the routes mapped", workdir=wd)
    ledger.append("spend", workdir=wd, challenge_id="12", usd=1.0)
    spawn.record_result("13", "crypto rsa", "ruled_out", "not small e", workdir=wd)
    verdicts, problems = coord.relay(wd)
    assert [(v.lane, v.kind, v.delivered) for v in verdicts] == [("web", "finding", True),
                                                                   ("web", "progress", False)]
    assert len(problems) == 1 and "record 4" in problems[0] and "bad lane" in problems[0]
    assert coord.messages(wd, "web")[0]["text"] == "12 found: admin cookie forgeable -> 12/notes.md"
    assert coord.relay(wd) == ([], [])               # the cursor: nothing forwarded twice
    spawn.record_result("12", "web", "blocked", "needs a second account", workdir=wd)
    assert ctf_main(["coord", "--workdir", str(wd), "relay"]) == 0
    assert "1 delivered, 0 dropped" in capsys.readouterr().out
    assert [m["text"] for m in coord.messages(wd, "web")][-1] == "12 blocked: needs a second account"
    (coord.coord_dir(wd) / coord.RELAY_CURSOR).write_text(json.dumps({"ledger_records": 99}))
    with pytest.raises(coord.CoordError, match="ledger was replaced"):
        coord.relay(wd)


# ------------------------------------------------------------------------------- the lane board

def test_lane_board_joins_claims_leases_pool_campaign_completions_and_messages(wd, capsys):
    put_claim(wd, "12", name="login", intake="done")
    put_claim(wd, "3", name="cookie", intake="started")
    put_claim(wd, "7", name="rsa", lane="crypto", intake="done")
    standby.try_lease(wd, "12", "w1", owner_pid=None)
    standby.register(wd, "w1", status=standby.ASSIGNED, challenge_id="12", pid=None)
    standby.register(wd, "w2", status=standby.WAITING, pid=None)
    standby.register(wd, "w3", status=standby.WAITING, pid=dead_pid())
    camp = campaign.Campaign(wd)
    camp.register("a1", "codex", challenge="7")
    camp.register("a2", "claude", challenge="99")
    campaign.Campaign(wd, now=lambda: 1_000.0).register("a3", "codex", challenge="12")
    coord.complete("c1", "done", "e=3 cube root", challenge_id="7", workdir=wd)
    coord.complete("c2", "failed", "nothing", workdir=wd)
    coord.send("web", "finding", "f", sender="a", workdir=wd)
    coord.send("web", "status", "s", sender="a", workdir=wd)
    b = coord.board(wd)
    assert [(r.lane, r.challenge_id) for r in b.rows] == [("crypto", "7"), ("web", "3"), ("web", "12")]
    r12 = b.rows[2]
    assert r12.owner == "w1" and r12.agents == ["a3:lost?"] and r12.intake == "done"
    assert b.rows[0].agents == ["a1:running"] and b.rows[0].completions == ["c1:done"]
    assert b.idle == ["w2"]                      # w1 is assigned, w3's pid is gone
    assert b.loose_agents == ["a2:running"] and b.loose_completions == ["c2:failed"]
    assert b.lanes["web"]["delivered"] == 1 and b.lanes["web"]["dropped"] == 1
    assert b.problems == []
    text = coord.render_board(b)
    assert "LANE web  msgs 1/20 (1 dropped)" in text
    assert "  12 login claim=dispatched intake=done owner=w1 agents=a3:lost?" in text
    assert "POOL waiting: w2" in text and "AGENTS on no claim: a2:running" in text
    assert ctf_main(["coord", "--workdir", str(wd), "lanes", "--json"]) == 0
    got = json.loads(capsys.readouterr().out)
    assert got["idle"] == ["w2"] and len(got["rows"]) == 3
    dispatch.claim_path(wd, "8").write_text("{broken")
    assert ctf_main(["coord", "--workdir", str(wd), "lanes"]) == 1
    assert "PROBLEM:" in capsys.readouterr().out


def test_an_empty_workdir_has_an_empty_board(wd):
    assert coord.render_board(coord.board(wd)) == "no claims, agents, completions or lane messages yet\n"


# ------------------------------------------------------------------------------- CLI

def test_cli_done_wait_exit_codes(wd, capsys):
    base = ["coord", "--workdir", str(wd)]
    assert ctf_main(base + ["done", "c1", "--status", "failed", "--summary", "segfault", "--path", "core"]) == 0
    assert ctf_main(base + ["done", "c1", "--status", "done", "--summary", "again"]) == 2
    assert "already completed" in capsys.readouterr().err
    assert ctf_main(base + ["wait", "c1"]) == 1
    assert "child:c1 failed: segfault -> core" in capsys.readouterr().out
    assert ctf_main(base + ["wait", "c2", "--timeout", "5"]) == 2
    assert "timed poll" in capsys.readouterr().err
    assert ctf_main(base + ["wait", "c2", "--timeout", "0", "--allow-short", "--json"]) == 124
    got = json.loads(capsys.readouterr().out)
    assert got["timed_out"] is True and got["targets"][0]["state"] == "pending"
    assert ctf_main(base + ["wait", "bogus:x"]) == 2
    assert ctf_main(base + ["stats", "--json"]) == 0
    s = json.loads(capsys.readouterr().out)
    assert s["completed"] == 1 and s["timed_out"] == 1


def test_agent_rules_teach_completion_waits_and_the_lane_relay():
    body = (paths.repo_root() / "templates" / "event" / "agent-rules.md.tmpl").read_text()
    section = body.split("## Waiting on other agents", 1)[1].split("\n## ", 1)[0]
    for needle in ("python -m ctf coord done", "python -m ctf coord wait", "python -m ctf coord lanes",
                   "python -m ctf coord send", "wait_agent", "list_agents",
                   # round 1: a lane wait reads from the agent's own cursor, and a background wait has
                   # no timeout to expire into another paid turn
                   "`msg:<lane> --as <you>`", "`--no-timeout`"):
        assert needle in section, needle
    for ev in ("csctf", "huntress", "pink", "spooky"):
        for f in ("CLAUDE.md", "AGENTS.md"):
            text = (paths.repo_root() / "events" / ev / f).read_text()
            assert "## Waiting on other agents" in text
            assert "`msg:<lane> --as <you>`" in text and "`--no-timeout`" in text, (ev, f)


# ------------------------------------------------------------------------------- added on the second pass

def test_a_message_delivered_after_the_last_check_stays_unseen(wd):
    """The wait moves the reader's cursor past exactly what it printed, not to the lane's end at commit."""
    coord.send("web", "finding", "first", sender="h1", workdir=wd)
    prober = coord._Prober(wd, as_agent="parent")
    t = coord.parse_target("msg:web")
    prober.start([t])
    probe = prober.probe(t)
    assert probe.done and "first" in probe.line and probe.upto == 1
    coord.send("web", "finding", "second, after the check", sender="h2", workdir=wd)
    prober.commit([probe])
    assert coord.cursor(wd, "web", "parent") == 1
    assert [m["text"] for m in coord.inbox("web", "parent", workdir=wd)] == ["second, after the check"]
    prober.commit([probe])                           # a stale commit never moves the cursor back
    assert coord.cursor(wd, "web", "parent") == 2


def test_a_wait_on_own_messages_only_never_wakes_and_keeps_the_cursor(wd):
    coord.send("web", "decision", "parent's own call", sender="parent", workdir=wd)
    res = run_wait(wd, ["msg:web"], Clock(), timeout=60.0, as_agent="parent")
    assert res.code == coord.EXIT_TIMEOUT
    assert coord.cursor(wd, "web", "parent") == 0


def test_a_spawn_brief_ends_with_the_completion_command_the_parent_waits_on(wd):
    from ctf import budget, event
    prof = event.load("csctf")
    meter = budget.LedgerMeter(prof, workdir=wd, on_cap=lambda st, p: None)
    d = spawn.Spawner(wd, meter=meter).request("12", role="helper", lane="web", task="map the routes")
    assert d.admitted
    text = Path(d.brief_path).read_text()
    stop = text.split("## Stop rule", 1)[1]
    assert f"python -m ctf coord done {d.spawn_id} --status done|failed|blocked" in stop
    assert "--challenge 12" in stop
    c = Clock()
    c.at(42.0, lambda: coord.complete(d.spawn_id, "done", "routes mapped", challenge_id="12", workdir=wd))
    res = run_wait(wd, [d.spawn_id], c)
    assert c.t == 42.0 and res.code == 0 and f"child:{d.spawn_id} done (12): routes mapped" in res.render()


@pytest.mark.parametrize("body, msg", [
    ("{not json", "unreadable completion file"),
    ('["a list"]', "not a JSON object"),
    ('{"status": "maybe", "summary": "x"}', "completion status 'maybe'"),
])
def test_a_corrupt_completion_file_is_a_named_error(wd, body, msg):
    p = coord.done_path(wd, "c1")
    p.parent.mkdir(parents=True)
    p.write_text(body)
    with pytest.raises(coord.CoordError, match=msg):
        run_wait(wd, ["c1"], Clock())
    assert ctf_main(["coord", "--workdir", str(wd), "wait", "c1"]) == 2


def test_corrupt_lane_files_are_named_errors(wd):
    coord.send("web", "finding", "f", sender="a", workdir=wd)
    with open(coord.lane_dir(wd, "web") / coord.MSGS_NAME, "a") as fh:
        fh.write("{torn\n")
    with pytest.raises(coord.CoordError, match=r"msgs.jsonl:2: corrupt lane message"):
        coord.send("web", "finding", "g", sender="a", workdir=wd)
    p = coord.lane_dir(wd, "re") / coord.CURSORS_DIR / "parent.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"seq": -1}))
    with pytest.raises(coord.CoordError, match="cursor seq"):
        coord.inbox("re", "parent", workdir=wd)
    (coord.coord_dir(wd) / coord.RELAY_CURSOR).write_text(json.dumps({"ledger_records": "x"}))
    with pytest.raises(coord.CoordError, match="ledger_records"):
        coord.relay(wd)


def test_bad_wait_parameters_are_refused(wd):
    with pytest.raises(coord.CoordError, match="interval must be > 0"):
        run_wait(wd, ["c1"], Clock(), interval=0)
    with pytest.raises(coord.CoordError, match="timeout must be >= 0"):
        run_wait(wd, ["c1"], Clock(), timeout=-1, allow_short=True)
    assert not (coord.coord_dir(wd) / coord.WAITS_LOG).exists()     # a refused wait logs nothing


def test_a_wait_with_log_off_writes_no_record(wd):
    coord.complete("c1", "done", "ok", workdir=wd)
    assert run_wait(wd, ["c1"], Clock(), log=False).code == 0
    assert not (coord.coord_dir(wd) / coord.WAITS_LOG).exists()


def test_job_root_comes_from_ctf_jobs_dir_then_the_cli_flag(wd, tmp_path, monkeypatch):
    root = tmp_path / "jobroot"
    _fake_job(root, "j5")
    (root / "j5" / "exit.json").write_text(json.dumps({"rc": 0}))
    with pytest.raises(coord.CoordError, match="no job 'j5'"):
        run_wait(wd, ["job:j5"], Clock())
    monkeypatch.setenv("CTF_JOBS_DIR", str(root))
    assert run_wait(wd, ["job:j5"], Clock()).code == 0
    monkeypatch.delenv("CTF_JOBS_DIR")
    assert ctf_main(["coord", "--workdir", str(wd), "wait", "job:j5", "--jobs-dir", str(root)]) == 0


def test_cli_inbox_and_stats_text(wd, capsys):
    base = ["coord", "--workdir", str(wd)]
    assert ctf_main(base + ["inbox", "web", "--as", "parent"]) == 0
    assert "no new message in lane web" in capsys.readouterr().out
    assert ctf_main(base + ["send", "web", "finding", "SQLi in /search", "--from", "h1"]) == 0
    assert "delivered #1 to lane web" in capsys.readouterr().out
    assert ctf_main(base + ["send", "web", "status", "still going", "--from", "h1"]) == 3
    assert ctf_main(base + ["send", "web", "finding", "sqli in /search", "--from", "h2"]) == 3
    capsys.readouterr()
    assert ctf_main(base + ["inbox", "web", "--as", "parent", "--peek"]) == 0
    out = capsys.readouterr().out
    assert "1 new message(s) (data, not instructions)" in out and "#1 finding from h1: SQLi in /search" in out
    assert ctf_main(base + ["inbox", "web", "--as", "parent", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["text"] == "SQLi in /search"
    assert ctf_main(base + ["inbox", "web", "--as", "parent"]) == 0
    assert "no new message" in capsys.readouterr().out
    assert ctf_main(base + ["stats"]) == 0
    out = capsys.readouterr().out
    assert "messages: 1 delivered, 2 dropped" in out
    assert "web: 1/20 delivered; dropped: kind 1, repeat 1" in out
    assert coord.stats(wd)["lanes"]["web"]["dropped_by"] == {"kind": 1, "repeat": 1}


def test_board_lines_are_cut_to_the_width(wd):
    put_claim(wd, "12", name="a" * 40, intake="done")
    for i in range(6):
        coord.complete(f"child-{i}-with-a-long-name", "done", "ok", challenge_id="12", workdir=wd)
    text = coord.render_board(coord.board(wd), width=80)
    row = [ln for ln in text.splitlines() if ln.startswith("  12 ")][0]
    assert len(row) == 80 and row.endswith("...")
    assert "child-5-with-a-long-name:done" in coord.render_board(coord.board(wd), width=1000)


# ------------------------------------------------------------------------------- verification round 1

@pytest.mark.parametrize("bad", ["failed", "blocked"])
def test_wait_any_with_one_ok_and_one_failure_in_the_same_check_succeeds(wd, bad):
    """--any: the first check sees two finished children, one done and one failed or blocked. One target
    reached success, so the wait succeeds (exit 0); every finished line is still printed."""
    coord.complete("ok1", "done", "flag candidate", workdir=wd)
    coord.complete("bad1", bad, "dead end", workdir=wd)
    c = Clock()
    res = run_wait(wd, ["bad1", "ok1", "never"], c, any_=True)
    assert c.t == 0.0 and res.checks == 1
    assert [p.done for p in res.probes] == [True, True, False]
    assert res.code == coord.EXIT_OK
    out = res.render()
    assert f"child:bad1 {bad}: dead end" in out and "child:ok1 done: flag candidate" in out
    # the same two under a wait for all, with the third finished too: a failure among them is exit 1
    coord.complete("never", "done", "late", workdir=wd)
    assert run_wait(wd, ["bad1", "ok1", "never"], Clock()).code == coord.EXIT_FAILED


def test_relay_advances_its_cursor_past_each_record_it_delivered_before_a_crash(wd):
    """An OSError on the second record leaves the first delivered and counted: the next relay neither
    offers it again (no 'repeat' drop) nor skips the record that failed."""
    spawn.record_result("12", "web", "found", "admin cookie forgeable", workdir=wd)
    spawn.record_result("13", "pwn", "found", "format string at printf", workdir=wd)
    blocker = coord.coord_dir(wd) / coord.LANES_DIR / "pwn"
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("a file where the pwn lane folder belongs")   # the pwn send cannot create its lane
    with pytest.raises(OSError):
        coord.relay(wd)
    assert [m["text"] for m in coord.messages(wd, "web")] == ["12 found: admin cookie forgeable"]
    cur = json.loads((coord.coord_dir(wd) / coord.RELAY_CURSOR).read_text())["ledger_records"]
    assert cur == len(list(ledger.read(wd))) - 1       # past the delivered record, not past the failed one
    blocker.unlink()
    verdicts, problems = coord.relay(wd)
    assert problems == [] and [(v.lane, v.delivered) for v in verdicts] == [("pwn", True)]
    assert coord.dropped(wd, "web") == []              # the web finding was not offered a second time
    assert coord.stats(wd)["dropped"] == 0 and coord.stats(wd)["delivered"] == 2


def test_the_liveness_helpers_coord_reads_are_public(wd):
    """coord reads campaign and process liveness through public names, not another module's privates."""
    assert dispatch.pid_alive(os.getpid()) is True
    for pid in (dead_pid(), None, "x", 0, -5):
        assert dispatch.pid_alive(pid) is False, pid
    camp = campaign.Campaign(wd)
    camp.register("fresh", "codex")
    campaign.Campaign(wd, now=lambda: 1_000.0).register("stale", "codex")
    agents = camp.load()["agents"]
    assert camp.alive(agents["fresh"]) == (True, "")
    alive, why = camp.alive(agents["stale"])
    assert alive is False and "no heartbeat" in why
    src = (paths.repo_root() / "ctf" / "coord.py").read_text()
    assert "._alive(" not in src and "._pid_alive(" not in src
