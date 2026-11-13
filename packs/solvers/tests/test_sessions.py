"""B-175: named launcher sessions (ctf/sessions.py) and the `ctf session` command.

A launcher refuses to start over a live session, where live means pid AND start time match. Every
"launcher" and "agent" here is a synthetic sleeper started by the test.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from ctf import procid, sessions
from ctf.cli import main as cli_main

PY = sys.executable


def _sleeper(*, new_session=False, code="import time; time.sleep(60)"):
    return subprocess.Popen([PY, "-c", code], start_new_session=new_session)


def _cleanup(*ps):
    for p in ps:
        if p.poll() is None:
            p.kill()
        p.wait()


def test_claim_writes_the_exact_identity_and_release_removes_it(tmp_path):
    c = sessions.claim(tmp_path, "playday", harness="claude", challenge="7")
    rec = json.loads((tmp_path / "playday.json").read_text())
    assert rec["launcher_pid"] == os.getpid()
    assert procid.same_start(rec["launcher_start"], procid.start_time(os.getpid()))
    assert rec["harness"] == "claude" and rec["challenge"] == "7"
    assert c.replaced is None
    assert sessions.release(c) is True
    assert not (tmp_path / "playday.json").exists()
    assert sessions.release(c) is False          # nothing left that is ours


def test_a_second_claim_over_a_live_launcher_is_refused(tmp_path):
    launcher = _sleeper()
    try:
        sessions.claim(tmp_path, "playday", harness="claude", pid=launcher.pid)
        with pytest.raises(sessions.SessionLive, match=r"session 'playday' is live.*launcher pid "
                                                       rf"{launcher.pid}.*--confirm session:playday"):
            sessions.claim(tmp_path, "playday", harness="claude")
        # the record still names the live holder
        assert json.loads((tmp_path / "playday.json").read_text())["launcher_pid"] == launcher.pid
    finally:
        _cleanup(launcher)


def test_a_live_agent_keeps_the_session_even_when_its_launcher_is_gone(tmp_path):
    launcher, agent = _sleeper(), _sleeper(new_session=True)
    try:
        c = sessions.claim(tmp_path, "s1", harness="codex", pid=launcher.pid)
        sessions.set_agent(c, agent.pid, own_group=True, owner="own-1")
        _cleanup(launcher)
        st = sessions.session_state(tmp_path, "s1")
        assert (st.status, st.launcher, st.agent) == ("live", "gone", "alive")
        assert st.record["owner"] == "own-1" and st.record["agent_pgid"] == agent.pid
        with pytest.raises(sessions.SessionLive, match="its agent pid"):
            sessions.claim(tmp_path, "s1", harness="codex")
    finally:
        _cleanup(launcher, agent)


def test_a_dead_or_reused_pid_does_not_hold_the_session(tmp_path):
    other = _sleeper()
    try:
        # stale: the recorded pid is alive but started at another time (reused) -> not live
        (tmp_path / "s2.json").write_text(json.dumps({
            "name": "s2", "launcher_pid": other.pid,
            "launcher_start": procid.start_time(other.pid) - 100.0}))
        assert sessions.session_state(tmp_path, "s2").status == "stale"
        c = sessions.claim(tmp_path, "s2", harness="claude")
        assert c.replaced["launcher_pid"] == other.pid
        assert json.loads((tmp_path / "s2.json").read_text())["launcher_pid"] == os.getpid()
        sessions.release(c)
        time.sleep(0.1)
        assert other.poll() is None
    finally:
        _cleanup(other)


def test_release_leaves_a_record_that_is_no_longer_ours(tmp_path):
    c = sessions.claim(tmp_path, "s3", harness="claude")
    holder = _sleeper()
    try:
        (tmp_path / "s3.json").write_text(json.dumps({
            "name": "s3", "launcher_pid": holder.pid, "launcher_start": procid.start_time(holder.pid)}))
        assert sessions.release(c) is False
        assert (tmp_path / "s3.json").exists()
        with pytest.raises(sessions.SessionError, match="no longer held"):
            sessions.set_agent(c, holder.pid, own_group=False)
    finally:
        _cleanup(holder)


@pytest.mark.parametrize("bad", ["", "../x", "a b", "-x", "x" * 65])
def test_bad_session_names(tmp_path, bad):
    with pytest.raises(sessions.SessionError, match="bad session name"):
        sessions.claim(tmp_path, bad, harness="claude")


def test_sessions_root_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_SESSIONS_DIR", str(tmp_path / "s"))
    assert sessions.sessions_root() == (tmp_path / "s").resolve()
    monkeypatch.delenv("CTF_SESSIONS_DIR")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "w"))
    assert sessions.sessions_root() == (tmp_path / "w" / "sessions").resolve()
    assert sessions.sessions_root(tmp_path / "o") == (tmp_path / "o").resolve()


def test_stop_ends_the_agent_group_then_the_launcher_and_removes_the_record(tmp_path):
    launcher = _sleeper()
    code = ("import subprocess, sys, time\n"
            "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print(c.pid, flush=True)\n"
            "time.sleep(60)\n")
    agent = subprocess.Popen([PY, "-c", code], start_new_session=True, stdout=subprocess.PIPE, text=True)
    try:
        grandchild = int(agent.stdout.readline())
        gstart = procid.start_time(grandchild)
        c = sessions.claim(tmp_path, "day", harness="claude", pid=launcher.pid)
        sessions.set_agent(c, agent.pid, own_group=True)
        s = sessions.stop(tmp_path, "day", agent_grace=0.5, launcher_grace=0.2, timeout=20)
        assert (s.agent, s.launcher, s.removed) == ("stopped", "stopped", True)
        assert agent.wait(timeout=20) is not None and launcher.wait(timeout=20) is not None
        end = time.monotonic() + 20
        while procid.status(grandchild, gstart) == "alive" and time.monotonic() < end:
            time.sleep(0.05)
        assert procid.status(grandchild, gstart) != "alive", "the agent's group was not stopped"
        assert not (tmp_path / "day.json").exists()
    finally:
        _cleanup(launcher, agent)


def test_stop_never_signals_a_reused_launcher_pid(tmp_path):
    bystander = _sleeper()
    try:
        (tmp_path / "old.json").write_text(json.dumps({
            "name": "old", "launcher_pid": bystander.pid,
            "launcher_start": procid.start_time(bystander.pid) + 50.0}))
        s = sessions.stop(tmp_path, "old", agent_grace=0.1, launcher_grace=0.1, timeout=2)
        assert (s.agent, s.launcher, s.removed) == ("none", "not_running", True)
        time.sleep(0.2)
        assert bystander.poll() is None
    finally:
        _cleanup(bystander)


def test_cli_session_list(tmp_path, capsys):
    launcher = _sleeper()
    try:
        sessions.claim(tmp_path, "live1", harness="claude", challenge="9", pid=launcher.pid)
        (tmp_path / "gone1.json").write_text(json.dumps({"name": "gone1", "launcher_pid": 999999,
                                                         "launcher_start": 1.0}))
        assert cli_main(["session", "list", "--sessions-dir", str(tmp_path)]) == 0
        out = capsys.readouterr().out
        assert "live1" in out and "live " in out.split("live1", 1)[1].splitlines()[0]
        assert "gone1" in out and "stale" in out.split("gone1", 1)[1].splitlines()[0]
        assert cli_main(["session", "list", "--sessions-dir", str(tmp_path), "--json"]) == 0
        rows = {r["name"]: r["status"] for r in json.loads(capsys.readouterr().out)}
        assert rows == {"live1": "live", "gone1": "stale"}
    finally:
        _cleanup(launcher)


def test_cli_session_list_without_a_root_is_a_named_error(monkeypatch, capsys):
    for v in ("CTF_SESSIONS_DIR", "CTF_WORKDIR", "CTF_EVENT"):
        monkeypatch.delenv(v, raising=False)
    import ctf.event as ev
    monkeypatch.setattr(ev, "current", lambda *a, **k: (_ for _ in ()).throw(ev.EventError("none")))
    assert cli_main(["session", "list"]) == 2
    assert "no sessions folder" in capsys.readouterr().err
