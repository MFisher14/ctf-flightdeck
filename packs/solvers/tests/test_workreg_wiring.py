"""B-213: the idle-machine lock as the regression gate (ctf/gate/runner.py, `ctf gate run`) and the adapt lane
gate (ctf/adapt/regress.py, `ctf adapt gate`) take it.

The gate tests run real pytest children in a synthetic checkout (tests/gate_repo.py); one child test file
probes the lock itself with a non-blocking shared flock, so it passes only while the gate holds the lock
exclusive. The adapt tests run the probe engine of tests/adapt_repo.py; a marker file the engine writes on
its first run shows the lock was taken before any case ran and released after."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import pytest

from ctf import workreg as W
from ctf.cli import adapt as adapt_cli
from ctf.cli import gate as gate_cli
from ctf.gate import config
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import run_gate
from gate_repo import make_repo

import adapt_repo as AR

pytestmark = pytest.mark.needs_tool("git")

PROBE_TEST = '''\
import fcntl, os
def test_the_idle_lock_is_held_exclusive_while_this_runs():
    fd = os.open(os.environ["WORKREG_PROBE_LOCK"], os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return
    finally:
        os.close(fd)
    raise AssertionError("the idle lock was free while the gate ran this file")
'''

FILES = {"tests/test_probe.py": PROBE_TEST}


@pytest.fixture
def gate_env(tmp_path, monkeypatch):
    root = make_repo(tmp_path / "repo", FILES)
    state = tmp_path / "workreg"
    state.mkdir()
    (state / W.IDLE_LOCK).touch()
    monkeypatch.setenv("WORKREG_PROBE_LOCK", str(state / W.IDLE_LOCK))
    monkeypatch.setenv("CTF_WORKREG_STATE", str(state))
    monkeypatch.delenv("CTF_IDLE_LOCK", raising=False)
    return root, state, tmp_path / "gate-state"


def _run(root, gstate, **kw):
    graph = Graph(root, config.load(root, root / "gate.toml"), gstate / "co")
    sel = Selection("impact", ["tests/test_probe.py"], [], {})
    return run_gate(graph, sel, state=gstate, out_dir=gstate / "out", emit=lambda s: None,
                    load_fn=lambda: 0.0, cpus=4, **kw)


def test_run_gate_holds_the_idle_lock_while_files_run(gate_env):
    root, state, gstate = gate_env
    rep = _run(root, gstate, warm=False, idle=lambda: W.IdleLock(state, "gate run", timeout=0))
    assert [r.status for r in rep.rows] == ["PASS"], rep.rows[0].detail
    assert W.idle_status(state)["state"] == "free"        # released after the run


def test_without_the_lock_the_probe_file_is_red(gate_env):
    """The probe is a real test of the lock: with no idle factory it fails."""
    root, state, gstate = gate_env
    rep = _run(root, gstate, warm=False)
    assert [r.status for r in rep.rows] == ["FAIL"]


def test_run_gate_waits_for_the_holder_and_names_it_on_timeout(gate_env):
    root, state, gstate = gate_env
    with W.IdleLock(state, "another gate", agent="item/B-9"):
        with pytest.raises(W.IdleLockTimeout, match="another gate .*agent item/B-9"):
            _run(root, gstate, warm=False, idle=lambda: W.IdleLock(state, "gate run", timeout=0))
    assert not (gstate / "out").exists() or not any((gstate / "out").glob("*.xml")), "no file ran"


def test_an_all_warm_run_does_not_take_the_lock(gate_env):
    root, state, gstate = gate_env
    _run(root, gstate, warm=True, idle=lambda: W.IdleLock(state, "gate run", timeout=0))   # stores warm

    def must_not_be_taken():
        raise AssertionError("the idle lock was taken for a run with nothing to execute")
    rep = _run(root, gstate, warm=True, idle=must_not_be_taken)
    assert rep.rows[0].warm


def gate(root, gstate, *argv):
    p = argparse.ArgumentParser()
    gate_cli.add_arguments(p)
    args = p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(gstate),
                         *argv])
    return gate_cli.run(args)


def test_gate_cli_idle_lock_flag(gate_env, capsys):
    root, state, gstate = gate_env
    assert gate(root, gstate, "run", "--changed", "tests/test_probe.py", "--no-warm", "--idle-lock") == 0
    assert gate(root, gstate, "run", "--changed", "tests/test_probe.py", "--no-warm") == 1   # off by default
    capsys.readouterr()
    with W.IdleLock(state, "someone's timing suite"):
        assert gate(root, gstate, "run", "--changed", "tests/test_probe.py", "--no-warm", "--idle-lock",
                    "--idle-timeout", "0") == 2
    assert "someone's timing suite" in capsys.readouterr().err


def test_gate_cli_env_turns_it_on_and_the_flag_off(gate_env, monkeypatch):
    root, state, gstate = gate_env
    monkeypatch.setenv("CTF_IDLE_LOCK", "1")
    assert gate(root, gstate, "run", "--changed", "tests/test_probe.py", "--no-warm") == 0
    assert gate(root, gstate, "run", "--changed", "tests/test_probe.py", "--no-warm", "--no-idle-lock") == 1


# ------------------------------------------------------------------------------------------- adapt

IDLE = dict(load=0.0, cpus=1, guard="hook")


@pytest.fixture
def adapt_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path)
    wd = tmp_path / "work"
    wd.mkdir()
    return root, wd, tmp_path / "workreg"


class Recording(W.IdleLock):
    """A real IdleLock that notes whether the probe engine had run when it was taken and released."""

    def __init__(self, state, marker: Path, seen: list):
        super().__init__(state, "adapt gate", timeout=0)
        self.marker, self.seen = marker, seen

    def acquire(self):
        self.seen.append(("acquire", self.marker.exists()))
        return super().acquire()

    def release(self):
        self.seen.append(("release", self.marker.exists(), W.idle_status(self.dir)["state"]))
        super().release()



def test_adapt_gate_holds_the_lock_around_the_replays(adapt_env, monkeypatch, tmp_path):
    from ctf.adapt import regress as R
    root, wd, state = adapt_env
    marker = tmp_path / "engine-ran"
    monkeypatch.setenv("ADAPT_PROBE_ONCE", str(marker))     # the first engine run writes the marker
    seen: list = []
    g = R.gate("probe", root=root, workdir=wd, record=False, idle=lambda: Recording(state, marker, seen), **IDLE)
    assert marker.exists() and g.cases
    assert seen == [("acquire", False), ("release", True, "exclusive")]
    assert W.idle_status(state)["state"] == "free"


def test_an_all_warm_adapt_gate_does_not_take_the_lock(adapt_env):
    """As run_gate: nothing replays, so the idle lock is not taken (a held lock would not stall it)."""
    from ctf.adapt import regress as R
    root, wd, state = adapt_env
    first = R.gate("probe", root=root, workdir=wd, record=False,
                   idle=lambda: W.IdleLock(state, "adapt gate", timeout=0), **IDLE)
    assert any(o.status == R.PASS for o in first.cases)

    def must_not_be_taken():
        raise AssertionError("the idle lock was taken for a gate with nothing to replay")
    again = R.gate("probe", root=root, workdir=wd, record=False, idle=must_not_be_taken, **IDLE)
    assert [o.status for o in again.cases if o.status != R.NOT_RUN] and \
        all(o.status in (R.WARM, R.NOT_RUN) for o in again.cases)


def test_adapt_gate_takes_the_lock_once_for_several_replays(adapt_env):
    from ctf.adapt import regress as R
    root, wd, state = adapt_env
    made: list = []

    def factory():
        made.append(1)
        return W.IdleLock(state, "adapt gate", timeout=0)
    g = R.gate("probe", root=root, workdir=wd, record=False, warm=False, idle=factory, **IDLE)
    assert sum(o.runs for o in g.cases) >= 2, "the probe set replays more than once"
    assert made == [1]


def test_adapt_gate_refuses_to_replay_while_another_suite_holds_the_lock(adapt_env, tmp_path, monkeypatch):
    from ctf.adapt import regress as R
    root, wd, state = adapt_env
    marker = tmp_path / "engine-ran"
    monkeypatch.setenv("ADAPT_PROBE_ONCE", str(marker))
    with W.IdleLock(state, "gate run"):
        with pytest.raises(W.IdleLockTimeout, match="held by gate run"):
            R.gate("probe", root=root, workdir=wd, record=False,
                   idle=lambda: W.IdleLock(state, "adapt gate", timeout=0), **IDLE)
    assert not marker.exists(), "no case ran without the lock"


def test_adapt_cli_flag_takes_the_lock(adapt_env, monkeypatch, capsys):
    root, wd, state = adapt_env
    monkeypatch.setenv("CTF_WORKREG_STATE", str(state))
    monkeypatch.delenv("CTF_IDLE_LOCK", raising=False)
    p = argparse.ArgumentParser()
    adapt_cli.add_arguments(p)
    argv = ["gate", "probe", "--root", str(root), "--workdir", str(wd), "--guard", "hook"]
    with W.IdleLock(state, "gate run"):
        assert adapt_cli.run(p.parse_args([*argv, "--idle-lock", "--idle-timeout", "0"])) == 2
        assert "held by gate run" in capsys.readouterr().err
        # off by default: the same gate runs while the lock is held
        assert adapt_cli.run(p.parse_args(argv)) == 0
