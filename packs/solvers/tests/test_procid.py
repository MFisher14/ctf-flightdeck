"""B-175: exact process identity (pid + start time) and identity-checked termination (ctf/procid.py).

Every process here is a synthetic python/sleep child started by the test and reaped by it.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from ctf import procid

PY = sys.executable


def _sleeper(*, new_session=False, code="import time; time.sleep(60)"):
    return subprocess.Popen([PY, "-c", code], start_new_session=new_session)


def _until(pred, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def _cleanup(p):
    if p.poll() is None:
        p.kill()
    p.wait()


def test_identity_of_a_live_process_and_status_by_start_time():
    p = _sleeper()
    try:
        ident = procid.identity(p.pid)
        assert ident["pid"] == p.pid and isinstance(ident["start"], float)
        assert procid.status(p.pid, ident["start"]) == "alive"
        assert procid.matches(p.pid, ident["start"])
        # the same pid with another start time is a reused pid, never "alive"
        assert procid.status(p.pid, ident["start"] - 5.0) == "reused"
        assert not procid.matches(p.pid, ident["start"] - 5.0)
        # a bare pid (no start recorded) proves nothing
        assert procid.status(p.pid, None) == "reused"
    finally:
        _cleanup(p)
    assert procid.status(p.pid, ident["start"]) == "gone"
    assert procid.start_time(p.pid) is None
    with pytest.raises(procid.ProcIdError, match="not a live process"):
        procid.identity(p.pid)


def test_a_zombie_is_not_alive():
    p = subprocess.Popen([PY, "-c", "pass"])
    start = procid.start_time(p.pid)
    try:
        assert _until(lambda: procid.status(p.pid, start) == "zombie")
        assert procid.start_time(p.pid) is None
        assert not procid.matches(p.pid, start)
    finally:
        p.wait()


@pytest.mark.parametrize("bad", [0, -1, True, "12", None, 1.5])
def test_bad_pids(bad):
    assert procid.status(bad, 1.0) == "gone"
    with pytest.raises(procid.ProcIdError, match="bad pid"):
        procid.start_time(bad)


def test_same_start_tolerance():
    assert procid.same_start(100.0, 100.005)
    assert not procid.same_start(100.0, 100.5)
    assert not procid.same_start(None, 100.0)


def test_terminate_stops_a_whole_group_when_its_leader_is_proved():
    # the leader starts a grandchild in the same group; terminate(pgid=...) must take both
    code = ("import subprocess, sys, time\n"
            "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "print(c.pid, flush=True)\n"
            "time.sleep(60)\n")
    p = subprocess.Popen([PY, "-c", code], start_new_session=True, stdout=subprocess.PIPE, text=True)
    try:
        child = int(p.stdout.readline())
        cstart = procid.start_time(child)
        start = procid.start_time(p.pid)
        assert procid.terminate(p.pid, start, pgid=p.pid, grace=0.5, timeout=20) == "stopped"
        p.wait(timeout=20)
        assert _until(lambda: procid.status(child, cstart) != "alive")
    finally:
        _cleanup(p)


def test_terminate_refuses_a_reused_pid_and_sends_nothing():
    p = _sleeper()
    try:
        start = procid.start_time(p.pid)
        assert procid.terminate(p.pid, start - 10.0, grace=0.1, timeout=1) == "not_running"
        time.sleep(0.2)
        assert p.poll() is None, "a process whose start time differs from the record was signalled"
    finally:
        _cleanup(p)


def test_terminate_refuses_a_group_the_pid_does_not_lead():
    p = _sleeper()              # same group as the test runner: must never be group-signalled
    try:
        start = procid.start_time(p.pid)
        with pytest.raises(procid.ProcIdError, match="refused"):
            procid.terminate(p.pid, start, pgid=os.getpgid(0), grace=0.1, timeout=1)
        with pytest.raises(procid.ProcIdError, match="refused"):
            procid.terminate(p.pid, start, pgid=p.pid, grace=0.1, timeout=1)   # not a leader
        time.sleep(0.2)
        assert p.poll() is None
    finally:
        _cleanup(p)


def test_terminate_escalates_to_kill_for_a_process_that_ignores_term():
    code = ("import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n")
    p = subprocess.Popen([PY, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "ready"
        start = procid.start_time(p.pid)
        assert procid.terminate(p.pid, start, grace=0.3, timeout=20) == "stopped"
        assert p.wait(timeout=20) == -signal.SIGKILL
    finally:
        _cleanup(p)


def test_terminate_report_names_the_signal_that_ended_the_process():
    # TERM is enough: a plain sleeper dies on it. The grace is generous only so a loaded machine
    # never escalates; the loop returns as soon as the process is gone.
    p = _sleeper()
    try:
        start = procid.start_time(p.pid)
        assert procid.terminate_report(p.pid, start, grace=60, timeout=20) == ("stopped", "SIGTERM")
        assert p.wait(timeout=20) == -signal.SIGTERM
    finally:
        _cleanup(p)
    # TERM ignored: the KILL ended it, and the report says so
    code = ("import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n")
    q = subprocess.Popen([PY, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert q.stdout.readline().strip() == "ready"
        start = procid.start_time(q.pid)
        assert procid.terminate_report(q.pid, start, grace=0.3, timeout=20) == ("stopped", "SIGKILL")
        assert q.wait(timeout=20) == -signal.SIGKILL
    finally:
        _cleanup(q)
    # nothing to signal: not_running, no signal
    assert procid.terminate_report(q.pid, start, grace=0.1, timeout=1) == ("not_running", None)
