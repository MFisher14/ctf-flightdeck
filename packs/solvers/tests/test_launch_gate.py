"""R-09: the budget gate in tools/codex_launch and tools/claude_launch (tools/launch_gate.py).

Every ledger is synthetic and every harness is a stub executable written by the test: no real
Codex or Claude session is started and nothing leaves 127.0.0.1. The event is the csctf profile
(per_point 0.5, floor $25, ceiling $250), so an unregistered challenge has a $25 cap.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctf import budget, ledger, paths
from ctf.event import Budget
from tools import launch_gate
from tools.ledger import pricing

REPO = paths.repo_root()
PY = sys.executable
PRICES = pricing.load_prices()

STUB = '''#!{py}
import json, os, sys, time
if sys.argv[1:] == ["--help"]:      # B-095: claude_launch reads the CLI's help for --effort; no session
    print("Options:\\n  --effort <level>  Effort level for the current session")
    sys.exit(0)
spec = json.load(open(os.environ["STUB_SPEC"]))
mark = spec["mark"]
with open(mark, "a") as fh:
    fh.write("started " + json.dumps(sys.argv[1:]) + "\\n")
for line in spec.get("lines", []):
    print(line, flush=True)
time.sleep(spec.get("sleep", 0))
with open(mark, "a") as fh:
    fh.write("finished\\n")
sys.exit(spec.get("rc", 0))
'''


class Env:
    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.ws = tmp_path / "ws"
        self.mark = tmp_path / "mark.txt"
        self.spec = tmp_path / "spec.json"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        for name in ("codex", "claude"):
            p = self.bin / name
            p.write_text(STUB.format(py=PY))
            p.chmod(0o755)
        self.stub(lines=[])

    def stub(self, *, lines=(), sleep=0.0, rc=0):
        self.spec.write_text(json.dumps({"mark": str(self.mark), "lines": list(lines), "sleep": sleep,
                                         "rc": rc}))

    def env(self, **extra):
        e = dict(os.environ, CTF_WORKDIR=str(self.work), CTF_EVENT="csctf", STUB_SPEC=str(self.spec))
        e.pop("CTF_CHALLENGE", None)
        e.update(extra)
        return e

    def argv(self, tool, *args):
        binopt = ["--codex-bin" if tool == "codex_launch" else "--claude-bin", str(self.bin / tool.split("_")[0])]
        return [PY, str(REPO / "tools" / tool), "--workspace", str(self.ws), *binopt, *args]

    def run(self, tool, *args, timeout=60, **extra):
        return subprocess.run(self.argv(tool, *args), capture_output=True, text=True, env=self.env(**extra),
                              stdin=subprocess.DEVNULL, timeout=timeout)

    def popen(self, tool, *args, **extra):
        return subprocess.Popen(self.argv(tool, *args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=self.env(**extra), stdin=subprocess.DEVNULL)

    def started(self) -> bool:
        return self.mark.exists() and "started" in self.mark.read_text()

    def finished(self) -> bool:
        return self.mark.exists() and "finished" in self.mark.read_text()

    def stub_argv(self) -> list:
        line = next(x for x in self.mark.read_text().splitlines() if x.startswith("started "))
        return json.loads(line[len("started "):])

    def events(self, kind=None):
        return [r for r in ledger.read(self.work) if kind is None or r["event"] == kind]

    def meter(self):
        return budget.LedgerMeter(Budget(per_point=0.5, floor=25.0, ceiling=250.0), workdir=self.work)


@pytest.fixture
def E(tmp_path):
    return Env(tmp_path)


def codex_turn(inp, cached, out):
    return json.dumps({"type": "turn.completed",
                       "usage": {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out}})


def claude_msg(mid, model, inp, out, cache_read=0):
    return json.dumps({"type": "assistant", "message": {
        "id": mid, "model": model, "role": "assistant", "content": [{"type": "text", "text": "x"}],
        "usage": {"input_tokens": inp, "output_tokens": out, "cache_read_input_tokens": cache_read}}})


def claude_usd(model, inp, out, cache_read=0):
    return pricing.cost({"harness": "claude", "model": model, "speed": "standard", "input": inp,
                         "output": out, "cache_read": cache_read}, PRICES)


def wait_for(cond, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


# ------------------------------------------------------------------ the three acceptance cases

def test_refused_at_the_cap_and_names_the_extend_command(E):
    ledger.append("spend", workdir=E.work, challenge_id="7", usd=30.0, tok=10)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "solve it")
    assert r.returncode == launch_gate.EXIT_REFUSED == 3, r.stderr
    assert "at its budget cap" in r.stderr and "spent $30.00 of $25.00" in r.stderr
    assert "python -m ctf budget extend 7 --usd <amount> --reason <why>" in r.stderr
    assert not E.mark.exists(), "the harness must not start at the cap"
    assert [x["reason"] for x in E.events("agent_refused")] == ["at_cap"]
    assert len(E.events("budget_checkpoint")) == 1 and E.events("agent_launch") == []


def test_refused_after_a_team_solve_even_with_an_extension(E):
    E.meter().extend("7", 100.0, by="max", reason="close")
    assert budget.on_team_solve("7", solver="teammate", workdir=E.work)
    for tool, args in (("claude_launch", ["--challenge", "7"]),
                       ("codex_launch", ["--challenge", "7", "--model", "gpt-6.1-terra", "go"])):
        r = E.run(tool, *args)
        assert r.returncode == 3, (tool, r.stderr)
        assert "was solved by teammate" in r.stderr and "final" in r.stderr, r.stderr
        assert "budget extend" not in r.stderr and "budget resume" not in r.stderr
    assert not E.mark.exists()
    assert [x["reason"] for x in E.events("agent_refused")] == ["team_solve", "team_solve"]


def test_allowed_after_an_extend_and_spend_is_charged_from_codex_json(E):
    ledger.append("spend", workdir=E.work, challenge_id="7", usd=30.0, tok=10)
    assert E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go").returncode == 3
    E.meter().extend("7", 50.0, by="max", reason="one stage left")          # cap now $75
    E.stub(lines=["{\"type\":\"thread.started\"}", "not json at all",
                  codex_turn(1_000_000, 200_000, 100_000)], rc=0)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0, r.stderr
    assert E.finished()
    argv = E.stub_argv()
    assert argv[:2] == ["exec", "--skip-git-repo-check"] and "--json" in argv and argv[-1] == "go"
    assert "turn.completed" in r.stdout and "not json at all" in r.stdout      # output passed through
    sp = [x for x in E.events("spend") if x.get("source") == "launcher:codex"]
    # gpt-6.1-terra: 800k non-cached * $1 + 200k cached * $0.05 + 100k out * $5 (per million)
    assert len(sp) == 1 and sp[0]["usd"] == pytest.approx(0.8 + 0.01 + 0.5) and sp[0]["tok"] == 1_100_000
    assert E.meter().spent("7").usd == pytest.approx(31.31)
    assert [x["mode"] for x in E.events("agent_launch")] == ["headless"]
    assert [x["rc"] for x in E.events("agent_exit")] == [0]


# ------------------------------------------------------------------ B-096: the agent's work role

def test_role_is_recorded_on_agent_launch(E):
    E.meter().extend("7", 50.0, by="max", reason="verify stage")
    E.stub(lines=[codex_turn(1000, 0, 100)], rc=0)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--role", "verify", "go")
    assert r.returncode == 0, r.stderr
    launch = E.events("agent_launch")
    assert len(launch) == 1 and launch[0]["role"] == "verify"
    assert "--role" not in E.stub_argv()                 # the role is the launcher's, not passed on


def test_role_from_the_environment(E):
    E.meter().extend("7", 50.0, by="max", reason="verify stage")
    E.stub(lines=[codex_turn(1000, 0, 100)], rc=0)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go", CTF_ROLE="solve")
    assert r.returncode == 0, r.stderr
    assert E.events("agent_launch")[0]["role"] == "solve"


def test_no_role_leaves_the_field_off_the_record(E):
    E.stub(lines=[codex_turn(1000, 0, 100)], rc=0)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0, r.stderr
    assert "role" not in E.events("agent_launch")[0]


def test_an_unknown_role_is_refused_before_the_agent_starts(E):
    r = E.run("claude_launch", "--challenge", "7", "--role", "reviewer")
    assert r.returncode == 2 and "unknown role" in r.stderr
    assert not E.mark.exists() and E.events("agent_launch") == []


def test_an_unknown_role_is_refused_even_when_the_gate_is_off(E):
    # role_from runs before challenge_from in gate_for, so an invalid --role is refused loudly (exit 2)
    # even with no --challenge, when the budget gate would otherwise be off. The agent never starts.
    r = E.run("claude_launch", "--role", "reviewer")
    assert r.returncode == 2 and "unknown role" in r.stderr
    assert not E.mark.exists() and E.events("agent_launch") == []


# ------------------------------------------------------------------ other refusals

def test_manual_stop_is_refused_with_the_resume_command_and_resume_lifts_it(E):
    E.meter().stop("7", "manual", by="max")
    r = E.run("claude_launch", "--challenge", "7")
    assert r.returncode == 3 and "stopped by hand" in r.stderr
    assert "python -m ctf budget resume 7" in r.stderr and not E.mark.exists()
    E.meter().resume("7", by="max")
    r = E.run("claude_launch", "--challenge", "7")
    assert r.returncode == 0, r.stderr
    assert E.finished()


def test_no_progress_timer_refuses_a_stale_high_value_tail(E):
    old = time.time() - 30 * 60
    with open(ledger.path(E.work), "a") as fh:
        fh.write(json.dumps({"ts": old, "event": "budget_challenge", "challenge_id": "9", "tail": True}) + "\n")
    r = E.run("claude_launch", "--challenge", "9")
    assert r.returncode == 3 and "no progress" in r.stderr and "budget resume 9" in r.stderr
    assert [x["reason"] for x in E.events("stop")] == ["no_progress"] and not E.mark.exists()


def test_challenge_from_the_environment(E):
    ledger.append("spend", workdir=E.work, challenge_id="12", usd=99.0, tok=1)
    r = E.run("claude_launch", CTF_CHALLENGE="12")
    assert r.returncode == 3 and "challenge 12 is at its budget cap" in r.stderr
    r = E.run("claude_launch", CTF_CHALLENGE="  ")
    assert r.returncode == 2 and "empty" in r.stderr


def test_dry_run_decides_the_same_and_writes_nothing(E):
    ledger.append("spend", workdir=E.work, challenge_id="7", usd=30.0, tok=10)
    before = ledger.path(E.work).read_bytes()
    r = E.run("codex_launch", "--dry-run", "--challenge", "7", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 3 and "budget extend 7" in r.stderr and r.stdout == ""
    r = E.run("claude_launch", "--dry-run", "--challenge", "7")
    assert r.returncode == 3 and "budget extend 7" in r.stderr
    assert ledger.path(E.work).read_bytes() == before
    assert not (E.work / "budget" / "checkpoints").exists()
    r = E.run("codex_launch", "--dry-run", "--challenge", "8", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0 and " --json " in r.stdout and "spent $0.00 of $25.00 cap (ok)" in r.stderr

def test_dry_run_refuses_a_challenge_stopped_by_a_team_solve_or_by_hand(E):
    # well under the cap: only the stop can refuse these dry runs
    assert budget.on_team_solve("7", solver="teammate", workdir=E.work)
    E.meter().stop("8", "manual", by="max")
    before = ledger.path(E.work).read_bytes()
    for tool, extra in (("claude_launch", []), ("codex_launch", ["--model", "gpt-6.1-terra", "go"])):
        r = E.run(tool, "--dry-run", "--challenge", "7", *extra)
        assert r.returncode == 3, (tool, r.stderr)
        assert "was solved by teammate" in r.stderr and "budget extend" not in r.stderr, r.stderr
        assert r.stdout == ""
        r = E.run(tool, "--dry-run", "--challenge", "8", *extra)
        assert r.returncode == 3, (tool, r.stderr)
        assert "stopped by hand" in r.stderr and "python -m ctf budget resume 8" in r.stderr, r.stderr
    assert ledger.path(E.work).read_bytes() == before, "a dry run must write nothing"
    assert not E.mark.exists()
    # the same unstopped challenge is admitted, so the refusals above came from the stops
    r = E.run("claude_launch", "--dry-run", "--challenge", "9")
    assert r.returncode == 0, r.stderr


def test_dry_run_refuses_at_exactly_the_cap(E):
    ledger.append("spend", workdir=E.work, challenge_id="7", usd=25.0, tok=1)    # spent == $25 cap
    ledger.append("spend", workdir=E.work, challenge_id="8", usd=24.99, tok=1)
    r = E.run("claude_launch", "--dry-run", "--challenge", "7")
    assert r.returncode == 3 and "spent $25.00 of $25.00" in r.stderr and "budget extend 7" in r.stderr
    r = E.run("claude_launch", "--dry-run", "--challenge", "8")
    assert r.returncode == 0 and "spent $24.99 of $25.00 cap (ok)" in r.stderr, r.stderr
    # the real launch decides the same at the boundary
    r = E.run("claude_launch", "--challenge", "7")
    assert r.returncode == 3 and not E.mark.exists()


def test_benign_codex_passthrough_is_still_admitted(E):
    r = E.run("codex_launch", "--dry-run", "--challenge", "8", "--model", "gpt-6.1-terra", "go", "--",
              "-c", "model_reasoning_summary=none", "--config=hide_agent_reasoning=true",
              "-cmodel_verbosity=low", "-c=tools.web_search=false")
    assert r.returncode == 0, r.stderr
    assert "model_reasoning_summary=none" in r.stdout and "--json" in r.stdout
    # the attached forms are admitted by the fence too, and passed through unchanged
    assert " -cmodel_verbosity=low " in r.stdout and " -c=tools.web_search=false" in r.stdout


def test_no_challenge_says_the_gate_is_off(E):
    r = E.run("claude_launch", "--dry-run")
    assert r.returncode == 0 and "budget gate: off" in r.stderr and "stream-json" not in r.stdout
    assert not ledger.path(E.work).exists()


def test_gated_runs_refuse_unpriceable_setups(E):
    r = E.run("codex_launch", "--challenge", "7", "go")
    assert r.returncode == 2 and "needs --model" in r.stderr
    r = E.run("codex_launch", "--challenge", "7", "--model", "no-such-model", "go")
    assert r.returncode == 2 and "no price for codex model 'no-such-model'" in r.stderr
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go", "--", "-m", "gpt-6-astra")
    assert r.returncode == 2 and "refused codex argument -m" in r.stderr
    for attached in ("-mgpt-6-astra", "-m=gpt-6-astra"):                  # clap's attached short forms
        r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go", "--", attached)
        assert r.returncode == 2 and "refused codex argument -m" in r.stderr, (attached, r.stderr)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go", "--", "--model=x")
    assert r.returncode == 2 and "refused codex argument --model" in r.stderr
    for over in (["-c", "model=x"], ["-cmodel=x"], ["-c=model=x"], ["--config=model_provider=y"],
                 ["-cmodel_provider = y"]):
        r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "go", "--", *over)
        assert r.returncode == 2 and "refused codex override 'model'" in r.stderr, (over, r.stderr)
    r = E.run("claude_launch", "--challenge", "7", "--", "-p", "--output-format", "text", "hi")
    assert r.returncode == 2 and "refused --output-format text" in r.stderr
    r = E.run("claude_launch", "--challenge", "7", "--gate-poll", "0")
    assert r.returncode == 2 and "--gate-poll must be > 0" in r.stderr
    assert not E.mark.exists()


# ------------------------------------------------------------------ mid-run enforcement

def test_codex_crossing_the_cap_mid_run_is_stopped(E):
    E.stub(lines=[codex_turn(30_000_000, 0, 0)], sleep=60)                  # $30 on a $25 cap
    t0 = time.monotonic()
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--gate-poll", "30", "go")
    assert r.returncode == 3, r.stderr
    assert time.monotonic() - t0 < 30, "stopped on the charge, not at the next poll or the agent's end"
    assert "stopped the agent" in r.stderr and "budget extend 7" in r.stderr
    assert E.started() and not E.finished()
    assert E.meter().spent("7").usd == pytest.approx(30.0)
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(3, "at_cap")]


def test_team_solve_mid_run_stops_an_interactive_session(E):
    E.stub(sleep=60)
    p = E.popen("claude_launch", "--challenge", "7", "--gate-poll", "0.2")
    try:
        assert wait_for(E.started), "stub never started"
        assert budget.on_team_solve("7", workdir=E.work)
        out, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    assert p.returncode == 3, err
    assert "not metered by the launcher" in err and "was solved" in err
    assert not E.finished()
    assert [x["mode"] for x in E.events("agent_launch")] == ["interactive"]
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(3, "team_solve")]


def test_team_solve_mid_run_stops_a_metered_headless_codex_run(E):
    E.stub(lines=[codex_turn(1_000, 0, 100)], sleep=60)                     # a few cents, then works on
    p = E.popen("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--gate-poll", "0.2", "go")
    try:
        assert wait_for(E.started), "stub never started"
        assert wait_for(lambda: any(x.get("source") == "launcher:codex" for x in E.events("spend")))
        assert budget.on_team_solve("7", solver="teammate", workdir=E.work)
        out, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    assert p.returncode == 3, err
    assert "stopped the agent" in err and "was solved by teammate" in err
    assert E.started() and not E.finished()
    assert [(x["mode"], x["metered"]) for x in E.events("agent_launch")] == [("headless", True)]
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(3, "team_solve")]


def test_manual_stop_mid_run_stops_a_metered_claude_print_run(E):
    E.stub(lines=[claude_msg("m1", "claude-sonnet-4-6", 100, 10)], sleep=60)
    p = E.popen("claude_launch", "--challenge", "7", "--gate-poll", "0.2", "--", "-p", "hi")
    try:
        assert wait_for(E.started), "stub never started"
        E.meter().stop("7", "manual", by="max")
        out, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    assert p.returncode == 3, err
    assert "stopped by hand" in err and "budget resume 7" in err and not E.finished()
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(3, "manual")]


def test_spend_reported_after_the_cap_crossing_line_is_still_charged(E):
    # $30 crosses the $25 cap and stops the agent; the $2 line already printed must not be lost
    E.stub(lines=[codex_turn(30_000_000, 0, 0), codex_turn(2_000_000, 0, 0)], sleep=60)
    r = E.run("codex_launch", "--challenge", "7", "--model", "gpt-6.1-terra", "--gate-poll", "30", "go")
    assert r.returncode == 3, r.stderr
    assert not E.finished()
    sp = [x["usd"] for x in E.events("spend") if x.get("source") == "launcher:codex"]
    assert sp == [pytest.approx(30.0), pytest.approx(2.0)]
    assert E.meter().spent("7").usd == pytest.approx(32.0)
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(3, "at_cap")]


def test_spend_reported_after_an_unpriceable_line_is_still_charged(E):
    m = "claude-sonnet-4-6"
    E.stub(lines=[claude_msg("m1", "claude-unknown-9", 10, 10), claude_msg("m2", m, 1000, 100)], sleep=60)
    r = E.run("claude_launch", "--challenge", "7", "--", "-p", "hi")
    assert r.returncode == 2 and "could not be priced" in r.stderr
    assert not E.finished()
    sp = [x["usd"] for x in E.events("spend") if x.get("source") == "launcher:claude"]
    assert sp == [pytest.approx(claude_usd(m, 1000, 100))]
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(2, "unpriced")]


def test_spend_queued_at_ctrl_c_is_still_charged(E):
    """supervise() in process: the injected clock raises KeyboardInterrupt (Ctrl-C) once the stub's
    usage line has been passed through, before the supervisor's drain has charged it."""
    import io
    import threading
    E.stub(lines=[codex_turn(3_000_000, 0, 0)], sleep=60)                     # $3
    gate = launch_gate.Gate(E.meter(), "7", harness="codex")
    out = io.StringIO()
    usage = launch_gate.CodexJsonUsage("gpt-6.1-terra", PRICES)
    calls = {"n": 0}
    lock = threading.Lock()

    def clock():
        with lock:
            calls["n"] += 1
            n = calls["n"]
        if n == 2:                                   # the first drain of the supervise loop
            assert wait_for(lambda: usage.usd > 0), "stub usage line never read"
            time.sleep(0.3)                          # feed() has returned; let the reader queue it
            raise KeyboardInterrupt
        return time.monotonic()

    rc = launch_gate.supervise([str(E.bin / "codex")], gate, cwd=E.tmp,
                               usage=usage,
                               poll_seconds=30, stdout=out, stderr=io.StringIO(),
                               popen_kwargs={"env": E.env()}, clock=clock)
    assert rc == 130
    assert E.started() and not E.finished()
    assert E.meter().spent("7").usd == pytest.approx(3.0)
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(130, "interrupted")]


def test_ctrl_c_waits_for_a_usage_line_still_being_priced(E):
    """The reader is still inside feed() when Ctrl-C lands; feed() returns only after the agent has
    been stopped and reaped. The increment must still be charged, so supervise() has to wait for
    the reader before its final drain (without the join, the drain runs first and finds nothing)."""
    import io
    import threading

    class SlowUsage:
        def __init__(self):
            self.entered, self.release = threading.Event(), threading.Event()

        def feed(self, line):
            if "turn.completed" not in line:
                return []
            self.entered.set()
            assert self.release.wait(20)
            pid = E.events("agent_launch")[0]["pid"]

            def reaped():
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return True
                return False
            assert wait_for(reaped, timeout=20), "agent was never stopped"
            time.sleep(0.3)                          # well after stop_agent() has returned
            return [launch_gate.Increment(3.0, 7)]

    E.stub(lines=[codex_turn(1, 0, 0)], sleep=60)
    gate = launch_gate.Gate(E.meter(), "7", harness="codex")
    usage = SlowUsage()
    calls = {"n": 0}

    def clock():
        calls["n"] += 1
        if calls["n"] == 2:                          # the first drain of the supervise loop
            assert usage.entered.wait(20), "stub usage line never read"
            usage.release.set()
            raise KeyboardInterrupt
        return time.monotonic()

    rc = launch_gate.supervise([str(E.bin / "codex")], gate, cwd=E.tmp, usage=usage,
                               poll_seconds=30, stdout=io.StringIO(), stderr=io.StringIO(),
                               popen_kwargs={"env": E.env()}, clock=clock)
    assert rc == 130
    assert E.started() and not E.finished()
    assert E.meter().spent("7").usd == pytest.approx(3.0)
    assert [(x["rc"], x["reason"]) for x in E.events("agent_exit")] == [(130, "interrupted")]


def test_claude_print_mode_is_metered_from_stream_json(E):
    m = "claude-sonnet-4-6"
    u1 = claude_usd(m, 1000, 100)
    u2 = claude_usd(m, 1000, 900)                     # same message, more output: charged the difference
    u3 = claude_usd(m, 2000, 50, cache_read=10_000)
    total = u2 + u3 + 0.25                             # the harness's own total is higher: topped up
    E.stub(lines=[claude_msg("m1", m, 1000, 100), claude_msg("m1", m, 1000, 900),
                  claude_msg("m1", m, 1000, 900), claude_msg("m2", m, 2000, 50, 10_000),
                  json.dumps({"type": "result", "subtype": "success", "total_cost_usd": total})], rc=4)
    r = E.run("claude_launch", "--challenge", "7", "--", "-p", "hi")
    assert r.returncode == 4, r.stderr                                       # the agent's own code
    argv = E.stub_argv()
    assert argv[argv.index("--output-format") + 1] == "stream-json" and "--verbose" in argv
    assert argv[-2:] == ["-p", "hi"]
    sp = [x for x in E.events("spend") if x.get("source") == "launcher:claude"]
    assert sum(x["usd"] for x in sp) == pytest.approx(total)
    assert sum(x["tok"] for x in sp) == 1000 + 900 + 2000 + 50 + 10_000
    assert u1 < u2


def test_unpriced_claude_model_stops_the_agent_loudly(E):
    E.stub(lines=[claude_msg("m1", "claude-unknown-9", 10, 10)], sleep=60)
    r = E.run("claude_launch", "--challenge", "7", "--", "-p", "hi")
    assert r.returncode == 2 and "could not be priced" in r.stderr and "claude-unknown-9" in r.stderr
    assert E.started() and not E.finished()


# ------------------------------------------------------------------ the usage readers

def test_claude_stream_usage_never_lowers_and_ignores_other_lines():
    u = launch_gate.ClaudeStreamUsage(PRICES)
    m = "claude-sonnet-4-6"
    a = u.feed(claude_msg("m1", m, 100, 500))
    assert len(a) == 1 and a[0].usd == pytest.approx(claude_usd(m, 100, 500))
    assert u.feed(claude_msg("m1", m, 100, 400)) == []           # fewer output tokens: nothing more
    assert u.feed('{"type":"user","message":{"usage":{}}}') == []
    assert u.feed('{"type":"result","total_cost_usd":0.000001}') == []    # lower than charged
    assert u.feed('{"type":"result","total_cost_usd":"lots"}') == []
    assert u.feed("garbage \"result\"") == []
    top = u.feed('{"type":"result","total_cost_usd":1.0}')
    assert len(top) == 1 and top[0].usd == pytest.approx(1.0 - claude_usd(m, 100, 500)) and top[0].tokens == 0


def test_codex_json_usage_prices_turns_only():
    u = launch_gate.CodexJsonUsage("gpt-6-astra", PRICES)
    assert u.feed('{"type":"item.completed","item":{"text":"turn.completed"}}') == []
    assert u.feed('{"type":"turn.failed","usage":{"input_tokens":5}}') == []
    got = u.feed(codex_turn(2_000_000, 1_000_000, 10_000))
    assert len(got) == 1 and got[0].usd == pytest.approx(10 + 1 + 0.5) and got[0].tokens == 2_010_000
    with pytest.raises(launch_gate.GateError, match="needs --model"):
        launch_gate.CodexJsonUsage(None, PRICES)


def test_refusal_text_names_the_lifting_command():
    def st(reason=None, by=None):
        return budget.ChallengeStatus("5", 30.0, 1, 25.0, 25.0, 0.0, None, False, False, None,
                                      "stopped" if reason else "at_cap", reason, by)
    assert "budget extend 5 --usd" in launch_gate.refusal_text(st(), "at_cap")
    assert "budget resume 5" in launch_gate.refusal_text(st("manual"), "manual")
    assert "budget resume 5" in launch_gate.refusal_text(st("no_progress"), "no_progress")
    t = launch_gate.refusal_text(st("team_solve", "alice"), "team_solve")
    assert "solved by alice" in t and "extend" not in t.replace("nothing to extend", "")
