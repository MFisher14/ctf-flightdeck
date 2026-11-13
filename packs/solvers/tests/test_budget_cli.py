"""B-033: python -m ctf budget status | extend | stop | resume | set."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

import pytest

from ctf import budget, ledger, paths
from ctf.cli import budget as cli_budget


def run_ctf(tmp_path, *args):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="csctf")
    return subprocess.run([sys.executable, "-m", "ctf", "budget", *args], cwd=paths.repo_root(), env=e,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)


def call(monkeypatch, tmp_path, *argv, tty=False, typed=None):
    """Run the command in-process (so a terminal can be simulated)."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty, raising=False)
    prompts = []

    def fake_input(prompt):
        prompts.append(prompt)
        if typed is None:
            raise AssertionError("unexpected prompt")
        return typed

    monkeypatch.setattr("builtins.input", fake_input)
    p = argparse.ArgumentParser()
    cli_budget.add_arguments(p)
    return cli_budget.run(p.parse_args(list(argv))), prompts


def evs(tmp_path, kind):
    return [r for r in ledger.read(tmp_path) if r["event"] == kind]


def test_status_set_and_json_end_to_end(tmp_path):
    r = run_ctf(tmp_path, "status")
    assert r.returncode == 0 and "no challenges in the ledger yet" in r.stdout
    r = run_ctf(tmp_path, "set", "9158", "--points", "560", "--name", "Phantom Drift")
    assert r.returncode == 0, r.stderr
    assert "of $250.00" in r.stdout and "no-progress-timer=on" in r.stdout
    ledger.append("spend", workdir=tmp_path, challenge_id="9158", usd=12.5, tok=4000)
    r = run_ctf(tmp_path, "status", "--json")
    rows = [json.loads(x) for x in r.stdout.splitlines()]
    assert rows == [dict(rows[0], challenge_id="9158", spent_usd=12.5, tokens=4000, cap_usd=250.0,
                         points=560.0, state="ok", timer_applies=True)]
    r = run_ctf(tmp_path, "set", "9158")
    assert r.returncode == 2 and "needs at least one of" in r.stderr


def test_extend_refuses_without_a_terminal(tmp_path):
    ledger.append("spend", workdir=tmp_path, challenge_id="7", usd=30.0, tok=1)
    r = run_ctf(tmp_path, "extend", "7", "--usd", "50", "--reason", "close")
    assert r.returncode == 1
    assert "human decision" in r.stderr and "interactive terminal" in r.stderr
    assert evs(tmp_path, "budget_extend") == []


def test_extend_with_a_person_at_the_terminal(monkeypatch, tmp_path):
    ledger.append("spend", workdir=tmp_path, challenge_id="7", usd=30.0, tok=1)
    code, prompts = call(monkeypatch, tmp_path, "extend", "7", "--usd", "50", "--reason", "one stage left",
                         tty=True, typed="7")
    assert code == 0 and "Type the challenge id (7)" in prompts[0]
    ext = evs(tmp_path, "budget_extend")
    assert len(ext) == 1 and ext[0]["usd"] == 50.0 and ext[0]["reason"] == "one stage left" and ext[0]["by"]
    m = budget.LedgerMeter(budget.Budget(), workdir=tmp_path)
    assert m.cap("7") == 75.0


def test_extend_wrong_confirmation_changes_nothing(monkeypatch, tmp_path):
    code, _ = call(monkeypatch, tmp_path, "extend", "7", "--usd", "50", "--reason", "x", tty=True, typed="8")
    assert code == 1 and evs(tmp_path, "budget_extend") == []


def test_extend_rejects_non_positive_amount_before_asking(monkeypatch, tmp_path):
    code, prompts = call(monkeypatch, tmp_path, "extend", "7", "--usd", "0", "--reason", "x", tty=True)
    assert code == 2 and prompts == [] and evs(tmp_path, "budget_extend") == []


def test_stop_solved_fires_the_team_solve_hook(tmp_path):
    r = run_ctf(tmp_path, "stop", "9156", "--solved", "--by", "dev")
    assert r.returncode == 0 and "stopped (team solve)" in r.stdout
    r = run_ctf(tmp_path, "stop", "9156", "--solved")
    assert r.returncode == 0 and "already stopped" in r.stdout
    stops = evs(tmp_path, "stop")
    assert [(s["challenge_id"], s["reason"], s.get("by")) for s in stops] == [("9156", "team_solve", "dev")]
    r = run_ctf(tmp_path, "status", "9156")
    assert "STOPPED (team_solve, by dev)" in r.stdout


def test_manual_stop_then_resume_needs_a_terminal(monkeypatch, tmp_path):
    r = run_ctf(tmp_path, "stop", "5", "--note", "pivot to web")
    assert r.returncode == 0 and evs(tmp_path, "stop")[0]["reason"] == "manual"
    r = run_ctf(tmp_path, "resume", "5")
    assert r.returncode == 1 and "human decision" in r.stderr
    code, _ = call(monkeypatch, tmp_path, "resume", "5", tty=True, typed="5")
    assert code == 0 and len(evs(tmp_path, "budget_resume")) == 1
    assert budget.is_stopped("5", workdir=tmp_path) is None


def test_resume_refuses_a_team_solve_without_prompting(monkeypatch, tmp_path):
    budget.on_team_solve("5", workdir=tmp_path)
    code, prompts = call(monkeypatch, tmp_path, "resume", "5", tty=True, typed="5")
    assert code == 2 and prompts == [] and evs(tmp_path, "budget_resume") == []


def test_unknown_event_fails_loudly(tmp_path):
    r = run_ctf(tmp_path, "--event", "nope", "status")
    assert r.returncode == 2 and "nope" in r.stderr


def test_budget_command_is_listed():
    r = subprocess.run([sys.executable, "-m", "ctf", "--help"], cwd=paths.repo_root(),
                       capture_output=True, text=True, timeout=60)
    assert "per-challenge budget caps and stop signals" in r.stdout
    assert not [ln for ln in r.stdout.splitlines() if "budget" in ln and "BROKEN" in ln]
