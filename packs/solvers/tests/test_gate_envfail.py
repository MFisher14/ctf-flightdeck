"""B-137: an environment problem (Docker daemon down, a sandbox-denied bind, a declared-missing tool)
is classified ENV, not FAIL -- reported apart, never turning the gate red, and judged from the test
outcomes alone. Every repo is synthetic and every child runs plain pytest (no network, no binary)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf.gate import config, envfail
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import run_gate
from ctf.gate.warm import WarmStore, file_key
from gate_repo import make_repo


# ------------------------------------------------------------------ the classifier (unit)

def test_docker_daemon_down_is_env():
    v = envfail.classify(["RuntimeError: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"])
    assert v and v.signature == "docker-daemon"


def test_sandbox_denied_bind_is_env():
    v = envfail.classify(["PermissionError: [Errno 1] Operation not permitted (bind on 127.0.0.1:0)"])
    assert v and v.signature == "sandbox-deny"


def test_explicit_marker_carries_its_reason():
    v = envfail.classify(["Failed: GATE-ENV: ghidra headless not on PATH"])
    assert v and v.signature == "gate-env-marker" and v.reason == "ghidra headless not on PATH"


def test_a_real_assertion_is_not_env():
    assert not envfail.classify(["AssertionError: assert 1 == 2"])


def test_a_real_failure_beside_an_env_one_keeps_it_red():
    # the strict rule: EVERY failing message must be environment, or the file stays a code failure.
    assert not envfail.classify(["Cannot connect to the Docker daemon", "assert 1 == 2"])


def test_no_messages_is_not_env():
    assert not envfail.classify([])
    assert not envfail.classify(["", "   "])


def test_junit_bad_messages_reads_failures_and_errors_not_skips(tmp_path):
    x = tmp_path / "j.xml"
    x.write_text('<testsuite><testcase name="a"><failure message="boom">trace</failure></testcase>'
                 '<testcase name="b"><error message="setup died"/></testcase>'
                 '<testcase name="c"><skipped type="pytest.skip" message="no tool"/></testcase>'
                 '<testcase name="d"/></testsuite>')
    msgs = envfail.junit_bad_messages(x)
    assert any("boom" in m and "trace" in m for m in msgs)
    assert any("setup died" in m for m in msgs)
    assert not any("no tool" in m for m in msgs)       # a skip is not a failure
    assert len(msgs) == 2


# ------------------------------------------------------------------ the runner (integration)

ENVREPO = {
    "tests/test_docker.py": (
        "def test_needs_docker():\n"
        "    raise RuntimeError('Cannot connect to the Docker daemon at unix:///var/run/docker.sock')\n"),
    "tests/test_real.py": "def test_broken():\n    assert 1 == 2, 'a genuine code defect'\n",
    "tests/test_mixed.py": (
        "def test_env():\n"
        "    raise RuntimeError('Cannot connect to the Docker daemon')\n"
        "def test_also_broken():\n    assert 0\n"),
    "tests/test_ok.py": "def test_ok():\n    assert True\n",
}


def _graph(root, state):
    return Graph(root, config.load(root, root / "gate.toml"), state / "co")


def _run(root, state, tests, **kw):
    kw.setdefault("load_fn", lambda: 0.0)
    kw.setdefault("cpus", 4)
    sel = Selection("impact", sorted(tests), [], {})
    rep = run_gate(_graph(root, state), sel, state=state, out_dir=state / "out", emit=lambda s: None, **kw)
    return rep, {r.test: r for r in rep.rows}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", ENVREPO)


def test_a_docker_down_file_is_env_and_does_not_fail_the_gate(repo, tmp_path):
    rep, rows = _run(repo, tmp_path / "s", ["tests/test_docker.py", "tests/test_ok.py"])
    assert rows["tests/test_docker.py"].status == "ENV"
    assert "docker" in rows["tests/test_docker.py"].detail.lower()
    assert rep.ok                                   # ENV is not a failure: the gate stays green
    assert rep.count("ENV") == 1


def test_a_real_failure_is_still_fail_not_env(repo, tmp_path):
    rep, rows = _run(repo, tmp_path / "s", ["tests/test_real.py"])
    assert rows["tests/test_real.py"].status == "FAIL"
    assert not rep.ok


def test_a_file_mixing_env_and_real_failure_stays_red(repo, tmp_path):
    rep, rows = _run(repo, tmp_path / "s", ["tests/test_mixed.py"])
    assert rows["tests/test_mixed.py"].status == "FAIL"    # the real defect wins; it is not hidden as ENV
    assert not rep.ok


def test_an_env_result_is_not_stored_warm(repo, tmp_path):
    state = tmp_path / "s"
    _run(repo, state, ["tests/test_docker.py"])
    g = _graph(repo, state)
    key = file_key(g, "tests/test_docker.py")
    assert WarmStore(state).get(key, "tests/test_docker.py") is None
    assert not list(state.glob("warm/*/*.json"))


def test_env_detection_never_probes_docker(repo, tmp_path, monkeypatch):
    # The gate must not shell out to `docker`; the verdict comes from the junit the child wrote. Guard
    # that by making any subprocess of a real docker binary explode -- the run must still succeed.
    import subprocess
    real = subprocess.run

    def no_docker(cmd, *a, **k):
        argv = cmd if isinstance(cmd, (list, tuple)) else [cmd]
        if argv and "docker" in str(argv[0]):
            raise AssertionError("the gate probed docker; it must classify from test outcomes only")
        return real(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", no_docker)
    rep, rows = _run(repo, tmp_path / "s", ["tests/test_docker.py"])
    assert rows["tests/test_docker.py"].status == "ENV"
