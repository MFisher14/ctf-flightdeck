"""B-178: `python -m ctf campaign` end to end (goals, end-of-build resume, hooks, briefs, recover),
and a launched agent outliving the process that launched it."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time

import pytest

from ctf import campaign, paths
from ctf.campaign import Campaign
from ctf.cli import main as ctf_main


@pytest.fixture
def wd(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_EVENT", "csctf")
    (tmp_path / "12-login").mkdir()
    return tmp_path


def test_goal_commands_and_mandatory_end(wd, capsys):
    assert ctf_main(["campaign", "goal", "add", "web12", "--title", "SSTI", "--challenge", "12",
                     "--lane", "web"]) == 0
    assert ctf_main(["campaign", "goal", "checkpoint", "web12", "--note", "ruled out ERB"]) == 0
    capsys.readouterr()
    # the end of a build is refused while a live goal does not say where to pick up
    assert ctf_main(["campaign", "end", "--summary", "night 1"]) == 2
    assert "no next step" in capsys.readouterr().err
    assert ctf_main(["campaign", "check"]) == 1
    assert "without a next step: web12" in capsys.readouterr().err
    assert ctf_main(["campaign", "goal", "checkpoint", "web12", "--note", "jinja confirmed",
                     "--next", "read config"]) == 0
    capsys.readouterr()
    assert ctf_main(["campaign", "end", "--summary", "night 1", "--by", "max"]) == 0
    out = capsys.readouterr().out.split()
    assert {os.path.basename(p) for p in out} == {"RESUME.md", "next-session.md", "web-gap.md"}
    assert ctf_main(["campaign", "check"]) == 0
    gap = (wd / "briefs" / "web-gap.md").read_text()
    assert "ruled out ERB" in gap and "jinja confirmed" in gap
    assert ctf_main(["campaign", "goal", "set", "web12", "--status", "done"]) == 0
    capsys.readouterr()
    assert ctf_main(["campaign", "goal", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["web12"]["status"] == "done"


def test_check_hook_lets_a_fresh_workdir_stop(wd, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"stop_hook_active": false}'))
    assert ctf_main(["campaign", "check", "--hook"]) == 0, "no campaign yet: the Stop hook never blocks"
    assert "no campaign" in capsys.readouterr().err
    assert ctf_main(["campaign", "check"]) == 0
    assert not (wd / "campaign").exists() and not (wd / "RESUME.md").exists(), \
        "check writes nothing: the Stop hook runs in every workdir and leaves an unused one as it was"


def test_check_hook_blocks_stop_once(wd, capsys, monkeypatch):
    assert ctf_main(["campaign", "goal", "add", "g", "--title", "goal"]) == 0
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"stop_hook_active": false}'))
    assert ctf_main(["campaign", "check", "--hook"]) == 2
    assert "campaign end" in capsys.readouterr().err
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"stop_hook_active": true}'))
    assert ctf_main(["campaign", "check", "--hook"]) == 0, "a hook never traps the session in a loop"


def test_brief_and_resume_commands(wd, capsys):
    assert ctf_main(["campaign", "goal", "add", "web12", "--title", "SSTI", "--lane", "web",
                     "--next", "probe"]) == 0
    capsys.readouterr()
    assert ctf_main(["campaign", "brief", "gap", "--lane", "web", "--stdout"]) == 0
    text = capsys.readouterr().out
    assert text.startswith("# web gap brief: csctf") and "SSTI" in text and "Live hosts in scope" in text
    assert ctf_main(["campaign", "brief", "next-session"]) == 0
    assert capsys.readouterr().out.strip().endswith("next-session.md")
    (wd / "RESUME.md").unlink()
    assert ctf_main(["campaign", "resume"]) == 0
    assert "## Goals in progress" in capsys.readouterr().out
    assert (wd / "RESUME.md").exists(), "resume rebuilds a missing resume file"


def test_resume_relaunch_reports_agents_it_cannot_restart(wd, capsys):
    camp = Campaign(wd, now=lambda: 1000.0)
    camp.register("codex-web", "codex")
    camp2 = Campaign(wd, now=lambda: 1000.0 + campaign.STALE_HEARTBEAT_SECONDS + 5)
    assert camp2.reconcile() == ["codex-web"]
    assert ctf_main(["campaign", "resume", "--relaunch", "--quiet"]) == 1
    assert "not relaunched: codex-web: registered by hand" in capsys.readouterr().err


def test_recover_command(wd, capsys):
    assert ctf_main(["campaign", "goal", "add", "a", "--title", "a"]) == 0
    assert ctf_main(["campaign", "goal", "add", "b", "--title", "b"]) == 0
    (wd / "campaign" / "state.json").write_text("garbage")
    capsys.readouterr()
    assert ctf_main(["campaign", "status"]) == 2
    assert "recover" in capsys.readouterr().err
    assert ctf_main(["campaign", "recover"]) == 0
    assert "restored rev 1" in capsys.readouterr().out
    assert set(Campaign(wd).load()["goals"]) == {"a"}


def test_launched_agent_outlives_the_launching_process(wd, tmp_path):
    out = tmp_path / "agent-out"
    out.mkdir()
    stub = tmp_path / "bin" / "slow_agent"
    stub.parent.mkdir()
    stub.write_text(f"#!{sys.executable}\n"
                    "import os, time, pathlib\n"
                    "o = pathlib.Path(os.environ['STUB_OUT'])\n"
                    "(o / 'started').write_text(str(os.getppid()))\n"
                    "while not (o / 'release').exists():\n"
                    "    time.sleep(0.05)\n"
                    "(o / 'finished').write_text('1')\n")
    stub.chmod(0o755)
    env = {**os.environ, "CTF_WORKDIR": str(wd), "CTF_EVENT": "csctf", "STUB_OUT": str(out),
           campaign.LAUNCHERS_ENV: str(stub), "PYTHONPATH": str(paths.repo_root())}
    # the launching "session": a separate process that exits right after the launch
    r = subprocess.run([sys.executable, "-m", "ctf", "campaign", "launch", "bg", "--harness", "codex",
                        "--no-scratch", "--", str(stub)], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    camp = Campaign(wd)
    end = time.time() + 30
    while not (out / "started").exists() and time.time() < end:
        time.sleep(0.05)
    assert (out / "started").exists()
    assert camp.reconcile() == [] and camp.load()["agents"]["bg"]["status"] == "running"
    (out / "release").write_text("1")
    end = time.time() + 30
    while camp.load()["agents"]["bg"]["status"] == "running" and time.time() < end:
        time.sleep(0.05)
    assert (out / "finished").exists()
    assert camp.load()["agents"]["bg"]["status"] == "done"
