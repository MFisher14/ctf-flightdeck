"""B-036: `python -m ctf adapt` end to end, in subprocesses, on a synthetic checkout (tests/adapt_repo.py)."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from ctf import ledger

import adapt_repo as AR

pytestmark = pytest.mark.needs_tool("git")


@pytest.fixture
def env(tmp_path):
    root = AR.make_repo(tmp_path)
    wd = tmp_path / "work"
    wd.mkdir()
    e = {k: v for k, v in os.environ.items() if not k.startswith("ADAPT_PROBE_")}
    e.update(CTF_GATE_STATE=str(tmp_path / "gs"), CTF_WORKDIR=str(wd))
    e.pop("CTF_EVENT", None)
    return root, wd, e


def ctf(env, *args, extra=None):
    root, wd, e = env
    if extra:
        e = dict(e, **extra)
    return subprocess.run([sys.executable, "-m", "ctf", "adapt", *args], cwd=str(AR.REPO), env=e,
                          capture_output=True, text=True, timeout=300)


def gate_args(env, *lanes, more=()):
    root, wd, _ = env
    return ["gate", *lanes, "--root", str(root), "--workdir", str(wd), "--guard", "hook", *more]


def test_gate_exit_codes(env, tmp_path):
    r = ctf(env, *gate_args(env, "probe"))
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("LANE probe: YES  3 case(s), ran 3, warm 0")
    r = ctf(env, *gate_args(env, "probe", more=["--json"]))
    assert r.returncode == 0 and [c["status"] for c in json.loads(r.stdout)[0]["cases"]] == ["warm"] * 3
    r = ctf(env, *gate_args(env, "probe", more=["--no-warm", "--no-regate"]), extra={"ADAPT_PROBE_EXIT": "5"})
    assert r.returncode == 1 and "FAIL" in r.stdout and "engine exited 5" in r.stdout
    r = ctf(env, *gate_args(env, "probe", more=["--recut", "1.2"]))
    assert r.returncode == 2 and "no less than 2x" in r.stderr
    r = ctf(env, *gate_args(env, "nolane"))
    assert r.returncode == 2 and "no regression set" in r.stderr


def test_gate_not_run_exits_3(tmp_path):
    ans = AR.fixture_answer(AR.BASE_FIXTURE, tmp_path)
    root = AR.make_repo(tmp_path, opener=(
        f'[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "{AR.ENGINE}"\nlabel = "p"\n'
        f'fixture = "{AR.BASE_FIXTURE}"\nexpect = ["{ans}"]\ncontrols = ["{AR.CONTROL_FIXTURE}"]\n'
        'needs_os_sandbox = true\n'))
    e = dict(os.environ, CTF_GATE_STATE=str(tmp_path / "gs"))
    r = subprocess.run([sys.executable, "-m", "ctf", "adapt", "gate", "probe", "--root", str(root), "--workdir",
                        str(tmp_path / "w"), "--guard", "hook"], cwd=str(AR.REPO), env=e, capture_output=True,
                       text=True, timeout=300)
    assert r.returncode == 3 and "NOT-RUN" in r.stdout


def test_record_prewarm_and_the_chain(env, tmp_path):
    root, wd, _ = env
    inp = AR.write(tmp_path, "accepted.bin", "the day 2 delivery\n")
    common = ["--root", str(root), "--workdir", str(wd)]
    r = ctf(env, "record", "probe", "d02", "--engine", AR.ENGINE, "--input", str(inp), "--expect",
            AR.answer_for(inp.read_bytes()), "--mode", "time_trial", *common)
    assert r.returncode == 0 and "recorded probe/event:d02" in r.stdout, r.stderr
    r = ctf(env, "record", "probe", "d02", "--engine", AR.ENGINE, "--input", str(inp), "--expect", "x", *common)
    assert r.returncode == 2 and "exists" in r.stderr
    r = ctf(env, "prewarm", *common, "--guard", "hook")
    assert r.returncode == 0 and "LANE probe: YES  4 case(s), ran 4" in r.stdout, r.stdout + r.stderr

    base = "script-analysis-day-06-bash-behavior-graphs"
    chain = ["chain", base, "--lane", "probe", *common, "--guard", "hook"]
    r = ctf(env, *chain)
    assert r.returncode == 3 and r.stdout.startswith(f"WAIT {base}:")
    r = ctf(env, "mark", base, "--by", "teammate", "--note", "banked by a teammate", *common)
    assert r.returncode == 0
    r = ctf(env, *chain, "--json")
    step = json.loads(r.stdout)
    assert r.returncode == 0 and step["action"] == "start" and step["challenge_id"] == f"{base}/time_trial"
    assert step["closed"] == {"base": "teammate"} and step["gate"]["cases"][0]["status"] == "warm"
    r = ctf(env, "attempt", f"{base}/time_trial", "--outcome", "incorrect", "--lane-key", step["lane_key"], *common)
    assert r.returncode == 0
    r = ctf(env, *chain)
    assert r.returncode == 1 and r.stdout.startswith("STOP") and "lane is unchanged" in r.stdout
    assert {r["event"] for r in ledger.read(wd)} >= {"adapt.gate", "adapt.chain", "adapt.closed", "adapt.attempt"}


def test_chain_on_a_malformed_ledger_ts_exits_2_with_a_named_error(env):
    root, wd, _ = env
    ledger.path(wd).write_text(json.dumps({"ts": "garbage", "event": "adapt.closed", "challenge_id": "x",
                                           "by": "hand"}) + "\n")
    r = ctf(env, "chain", "script-analysis-day-06-bash-behavior-graphs", "--lane", "probe", "--root", str(root),
            "--workdir", str(wd), "--guard", "hook")
    assert r.returncode == 2 and "malformed ts 'garbage'" in r.stderr and "Traceback" not in r.stderr, r.stderr


def test_qdiff_exit_codes(env, tmp_path):
    a = tmp_path / "base.json"
    b = tmp_path / "timed.json"
    a.write_text(json.dumps({"questions": [{"id": "x", "answer_format": {"kind": "integer"}}]}))
    b.write_text(json.dumps({"questions": [{"id": "x", "answer_format": {"kind": "exact_text"}}]}))
    r = ctf(env, "qdiff", str(a), str(a))
    assert r.returncode == 0 and "same questions" in r.stdout
    r = ctf(env, "qdiff", str(a), str(b), "--json")
    assert r.returncode == 1 and json.loads(r.stdout) == [
        {"what": "kind", "id": "x", "before": "integer", "after": "exact_text", "attention": True}]
    (tmp_path / "bad.json").write_text("{")
    r = ctf(env, "qdiff", str(a), str(tmp_path / "bad.json"))
    assert r.returncode == 2 and "unreadable JSON" in r.stderr


def test_prewarm_watch_runs_for_its_duration_and_duration_needs_watch(env):
    root, wd, _ = env
    common = ["--root", str(root), "--workdir", str(wd), "--guard", "hook"]
    r = ctf(env, "prewarm", "probe", "--watch", "0.2", "--duration", "0.5", *common)
    assert r.returncode == 0 and r.stdout.count("LANE probe: YES") == 1, r.stdout + r.stderr
    r = ctf(env, "prewarm", "probe", "--duration", "1", *common)
    assert r.returncode == 2 and "--duration needs --watch" in r.stderr
