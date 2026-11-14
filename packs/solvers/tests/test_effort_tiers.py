"""B-095: effort tiers -- launch-pinned medium with a time ramp.

Offline. No agent is started and no model is called. The profile parsing and the effort ladder are
pure; the escalation ramp is driven by ledger records written with chosen timestamps and a controlled
clock (the method of tests/test_escalation.py); the Claude CLI flag detection is driven by injected
`--help` text and by a stub CLI the test writes, with one marked test that reads the real installed
CLI's help (no session). The launchers are run as subprocesses against that stub.
"""
from __future__ import annotations

import dataclasses
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ctf import escalation, event, fence_launch, ledger, paths, spawn

# --------------------------------------------------------------------------- profile [models].effort

_BASE_TOML = """
slug = "demo"
name = "Demo"
[dates]
start = 2026-01-01T00:00:00Z
end = 2026-01-02T00:00:00Z
[platform]
kind = "ctfd"
base_url = "https://example.test"
[flag]
prefixes = ["CSCTF"]
[rules]
submit_mode = "auto"
flag_sharing = "allowed"
ai_on_platform = "allowed"
"""


def _profile(extra: str = "") -> event.EventProfile:
    return event.parse(tomllib.loads(_BASE_TOML + extra), src="<demo>")


def test_models_effort_defaults_to_medium():
    assert event.Models().effort == "medium"
    assert _profile().models.effort == "medium"      # no [models] section -> the default


def test_models_effort_is_read_from_the_profile():
    p = _profile('[models]\neffort = "high"\n')
    assert p.models.effort == "high"


def test_an_unknown_effort_tier_is_refused_by_name():
    with pytest.raises(event.EventError) as ei:
        _profile('[models]\neffort = "turbo"\n')
    msg = str(ei.value)
    assert "effort" in msg and "turbo" in msg and "medium" in msg   # names the key, value and choices


# ----------------------------------------------------------------------------------- step_effort

def test_step_effort_ramps_one_tier_per_step():
    assert escalation.step_effort("medium", 0) == "medium"
    assert escalation.step_effort("medium", 1) == "high"
    assert escalation.step_effort("medium", 2) == "max"
    assert escalation.step_effort("low", 1) == "medium"


def test_step_effort_clamps_at_the_top_tier():
    assert escalation.step_effort("high", 5) == "max"
    assert escalation.step_effort("max", 1) == "max"


def test_step_effort_treats_negative_steps_as_zero():
    assert escalation.step_effort("medium", -3) == "medium"


def test_step_effort_rejects_an_unknown_base_tier():
    with pytest.raises(escalation.EscalationError):
        escalation.step_effort("ludicrous", 1)


# -------------------------------------------------------- the escalation ramp (ledger + clock)

@pytest.fixture
def prof():
    return event.load("csctf")       # [models].effort defaults to medium


ROSTER = ["glm-5.3", "gpt-6-sol"]    # extend the csctf default [opus-5-5, opus-4-8]


def write_ledger(workdir, event_type, *, ts, **fields):
    rec = {"ts": float(ts), "event": event_type, **fields}
    p = ledger.path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def esc(prof, workdir, *, now, roster=ROSTER, **kw):
    return escalation.Escalator(prof, workdir=workdir, roster=roster, clock=lambda: now, **kw)


def test_second_agent_launches_one_tier_above_the_base(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()
    second = [d for d in made if d.action == "second"]
    assert len(second) == 1
    assert second[0].effort == "high"           # base medium -> high: a fresh agent, not a mid-session bump
    assert second[0].to_fields()["effort"] == "high"


def test_third_agent_launches_two_tiers_above_the_base(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    made = esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once()
    by_action = {d.action: d for d in made}
    assert by_action["second"].effort == "high"
    assert by_action["third"].effort == "max"   # medium -> high -> max across the ramp


def test_a_reroute_relaunches_at_the_base_tier_not_a_ramp_step(tmp_path, prof):
    # A reroute replaces a dead handoff (refusal / provider error); it is not a ramp step, so it
    # relaunches at the launch-pinned base rather than bumping effort.
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude",
                 reason="refusal")
    made = esc(prof, tmp_path, now=1013.0).once()
    reroutes = [d for d in made if d.action == "reroute"]
    assert len(reroutes) == 1 and reroutes[0].effort == "medium"


def test_the_base_tier_follows_the_profile_default(tmp_path):
    # A profile pinned at "low" ramps low -> medium -> high, not medium -> high -> max.
    p = _profile('[models]\neffort = "low"\n')
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    made = esc(p, tmp_path, now=1000.0 + escalation.THIRD_S).once()
    by_action = {d.action: d for d in made}
    assert by_action["second"].effort == "medium" and by_action["third"].effort == "high"


def test_an_effort_override_sets_the_base(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S, effort="high").once()
    second = [d for d in made if d.action == "second"][0]
    assert second.effort == "max"       # override base high -> second at max


def test_an_unknown_base_effort_is_refused_at_construction(tmp_path, prof):
    with pytest.raises(escalation.EscalationError):
        escalation.Escalator(prof, workdir=tmp_path, effort="turbo")


def test_the_escalation_record_carries_the_effort(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()
    recs = [r for r in ledger.read(tmp_path) if r["event"] == escalation.LEDGER_EVENT]
    assert recs and recs[0].get("effort") == "high"     # the written record, not just the Decision


def test_show_reports_the_owner_effort(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    view = esc(prof, tmp_path, now=1050.0).show("9")
    assert view["owner_effort"] == "medium"


# ----------------------------------------------------------- Claude CLI effort flag detection

_HELP_WITH_EFFORT = """Usage: claude [options] [command] [prompt]

Options:
  --agent <agent>        Agent for the current session.
  --effort <level>       Effort level for the current session
  --max-budget-usd <n>   Maximum dollar amount to spend on API
"""

_HELP_WITHOUT_EFFORT = """Usage: claude [options] [command] [prompt]

Options:
  --agent <agent>        Agent for the current session.
  --max-budget-usd <n>   Maximum dollar amount to spend on API
"""


def test_claude_effort_flag_found_in_help():
    assert fence_launch.claude_effort_flag(help_text=_HELP_WITH_EFFORT) == "--effort"


def test_claude_effort_flag_absent_fails_loudly_by_name():
    with pytest.raises(fence_launch.LaunchError) as ei:
        fence_launch.claude_effort_flag("claude-x", help_text=_HELP_WITHOUT_EFFORT)
    msg = str(ei.value)
    assert "claude-x" in msg and "--effort" in msg      # names the binary and the missing flag


def test_claude_effort_flag_is_not_fooled_by_a_substring():
    # "--effortless" or the word in prose must not count as the flag.
    txt = "Options:\n  --effortless           do less\nNotes: set effort by other means\n"
    with pytest.raises(fence_launch.LaunchError):
        fence_launch.claude_effort_flag(help_text=txt)


def test_claude_argv_puts_the_effort_before_the_passthrough_and_runs_no_cli(tmp_path):
    # claude_argv is pure: the binary does not exist, so any attempt to run it would raise
    absent = str(tmp_path / "no-such-claude")
    argv = fence_launch.claude_argv(Path("/w/s.json"), claude_bin=absent, extra=("--print",), effort="high")
    assert argv == [absent, "--settings", "/w/s.json", "--effort", "high", "--print"]


def test_claude_argv_omits_effort_when_unset():
    argv = fence_launch.claude_argv(Path("/w/s.json"))
    assert "--effort" not in argv


def test_codex_argv_passes_effort_as_a_reasoning_config(tmp_path):
    from ctf import fence as _fence
    home, ws, repo = (tmp_path / "home" / "p", tmp_path / "work" / "e", tmp_path / "src" / "r")
    for d in (home, ws, repo):
        d.mkdir(parents=True)
    f = _fence.build(home=home.resolve(), workspace=ws.resolve(), repo=repo.resolve(), user_dir=None)
    argv = fence_launch.codex_argv(f, effort="high", prompt="go")
    assert 'model_reasoning_effort="high"' in " ".join(argv)


@pytest.mark.needs_tool("claude")
def test_installed_claude_cli_documents_an_effort_flag():
    # The real check B-095 relies on: this build of Claude Code must document the effort flag.
    assert fence_launch.claude_effort_flag("claude") == "--effort"


# ------------------------------------------------- the `--help` call itself, against a stub CLI
#
# The stub stands in for the claude (and codex) binary. It appends one JSON line per call to the mark
# file (its argv and what it read from stdin), so a test sees every time the launcher ran it. A
# `--help` call prints the spec's help text; `help_sleep` makes that call hang.

_CLI_STUB = '''#!{py}
import json, os, sys, time
spec = json.load(open(os.environ["STUB_SPEC"]))
with open(spec["mark"], "a") as fh:
    fh.write(json.dumps({{"argv": sys.argv[1:], "stdin": sys.stdin.read()}}) + "\\n")
if sys.argv[1:] == ["--help"]:
    time.sleep(spec.get("help_sleep", 0))
    print(spec["help"])
sys.exit(0)
'''


class Cli:
    def __init__(self, tmp_path: Path):
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.ws = tmp_path / "ws"
        self.mark = tmp_path / "calls.jsonl"
        self.spec = tmp_path / "spec.json"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        for name in ("claude", "codex"):
            p = self.bin / name
            p.write_text(_CLI_STUB.format(py=sys.executable))
            p.chmod(0o755)
        self.help(_HELP_WITH_EFFORT)

    def help(self, text: str, sleep: float = 0):
        self.spec.write_text(json.dumps({"mark": str(self.mark), "help": text, "help_sleep": sleep}))

    def run(self, tool, *args, stdin_text="", event_slug="csctf"):
        env = dict(os.environ, CTF_WORKDIR=str(self.work), STUB_SPEC=str(self.spec))
        for k in ("CTF_CHALLENGE", "CTF_SPAWN_ID", "CTF_EVENT", "CLAUDE_BIN", "CODEX_BIN"):
            env.pop(k, None)
        if event_slug:
            env["CTF_EVENT"] = event_slug
        harness = tool.split("_")[0]
        cmd = [sys.executable, str(paths.repo_root() / "tools" / tool), "--workspace", str(self.ws)]
        if f"--{harness}-bin" not in args:
            cmd += [f"--{harness}-bin", str(self.bin / harness)]
        return subprocess.run([*cmd, *args], capture_output=True, text=True, env=env, input=stdin_text,
                              timeout=300)

    def calls(self) -> list[dict]:
        if not self.mark.exists():
            return []
        return [json.loads(x) for x in self.mark.read_text().splitlines()]


@pytest.fixture
def cli(tmp_path, monkeypatch):
    c = Cli(tmp_path)
    monkeypatch.setenv("STUB_SPEC", str(c.spec))      # for the tests that run the stub in-process
    return c


def _after(argv: list, flag: str):
    return argv[argv.index(flag) + 1]


def test_the_help_call_has_no_stdin_and_reads_the_flag(cli):
    assert fence_launch.claude_effort_flag(str(cli.bin / "claude")) == "--effort"
    assert cli.calls() == [{"argv": ["--help"], "stdin": ""}]     # one call, stdin at EOF


def test_a_cli_whose_help_has_no_effort_flag_is_refused_by_name(cli):
    cli.help(_HELP_WITHOUT_EFFORT)
    with pytest.raises(fence_launch.LaunchError) as ei:
        fence_launch.claude_effort_flag(str(cli.bin / "claude"))
    assert "--effort" in str(ei.value) and str(cli.bin / "claude") in str(ei.value)


def test_a_help_call_that_never_returns_is_a_named_error(cli):
    # The stub's help call sleeps far longer than the budget given here, so the call always times
    # out; nothing is asserted about how fast (rule: no wall-clock upper bound).
    cli.help(_HELP_WITH_EFFORT, sleep=3600)
    with pytest.raises(fence_launch.LaunchError) as ei:
        fence_launch.claude_effort_flag(str(cli.bin / "claude"), timeout=1.0)
    assert "did not return within 1 s" in str(ei.value) and "--effort" in str(ei.value)


def test_a_cli_that_cannot_be_started_is_a_named_error(tmp_path):
    bad = tmp_path / "broken"
    bad.write_text(f"#!{tmp_path / 'no-such-interpreter'}\n")
    bad.chmod(0o755)
    for binary in (str(bad), str(tmp_path / "absent")):
        with pytest.raises(fence_launch.LaunchError) as ei:
            fence_launch.claude_effort_flag(binary)
        assert "could not start" in str(ei.value) and binary in str(ei.value)


# ------------------------------------------------------- the launchers: default, probe, dry run

def _tool(name: str):
    """tools/<name> loaded as a module (the launchers have no .py suffix)."""
    path = paths.repo_root() / "tools" / name
    loader = importlib.machinery.SourceFileLoader(f"b095_{name}", str(path))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("name", ["claude_launch", "codex_launch"])
def test_the_launch_default_is_the_profiles_effort(name, monkeypatch):
    mod = _tool(name)
    real = event.load
    seen = []

    def load(slug, root=None):
        seen.append(slug)
        p = real(slug, root)
        return dataclasses.replace(p, models=dataclasses.replace(p.models, effort="low"))

    monkeypatch.setattr(event, "load", load)
    monkeypatch.delenv("CTF_EVENT", raising=False)
    assert mod._profile_effort("csctf") == "low" and seen == ["csctf"]      # --event
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert mod._profile_effort(None) == "low" and seen == ["csctf", "pink"]  # $CTF_EVENT
    monkeypatch.delenv("CTF_EVENT")
    assert mod._profile_effort(None) is None and len(seen) == 2             # no event: no effort


def test_a_real_claude_launch_pins_the_profile_effort_after_one_help_call(cli):
    want = event.load("csctf").models.effort
    r = cli.run("claude_launch", "--", "-p", "hi", stdin_text="THE PROMPT")
    assert r.returncode == 0, r.stderr
    helped, session = cli.calls()                  # exactly two runs of the CLI: the help, the session
    assert helped == {"argv": ["--help"], "stdin": ""}      # the help call did not eat the piped prompt
    assert session["stdin"] == "THE PROMPT"
    argv = session["argv"]
    assert _after(argv, "--effort") == want and argv.count("--effort") == 1
    assert argv.index("--effort") < argv.index("-p") and argv[-2:] == ["-p", "hi"]


def test_an_explicit_effort_overrides_the_profile(cli):
    other = "high" if event.load("csctf").models.effort != "high" else "low"
    r = cli.run("claude_launch", "--effort", other, "--", "-p", "hi")
    assert r.returncode == 0, r.stderr
    assert _after(cli.calls()[-1]["argv"], "--effort") == other
    r = cli.run("codex_launch", "--dry-run", "--effort", other, "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0 and f'model_reasoning_effort="{other}"' in r.stdout, r.stderr


def test_codex_launch_defaults_to_the_profile_effort(cli):
    want = event.load("csctf").models.effort
    r = cli.run("codex_launch", "--dry-run", "--model", "gpt-6.1-terra", "go")
    assert r.returncode == 0 and f'model_reasoning_effort="{want}"' in r.stdout, r.stderr


def test_a_launch_with_no_event_passes_no_effort_and_asks_no_help(cli):
    r = cli.run("claude_launch", "--no-notes", "--", "-p", "hi", event_slug=None)
    assert r.returncode == 0, r.stderr
    (session,) = cli.calls()                       # the session only: no help call
    assert "--effort" not in session["argv"] and session["argv"][-2:] == ["-p", "hi"]


def test_a_claude_cli_without_the_flag_stops_the_launch_and_gives_the_seat_back(cli):
    cli.help(_HELP_WITHOUT_EFFORT)
    r = cli.run("claude_launch", "--challenge", "7", "--", "-p", "hi")
    assert r.returncode == 2 and "Traceback" not in r.stderr
    assert "documents no --effort flag" in r.stderr and str(cli.bin / "claude") in r.stderr
    assert [c["argv"] for c in cli.calls()] == [["--help"]]         # no session was started
    recs = list(ledger.read(cli.work))
    assert [x for x in recs if x["event"] == "agent_launch"] == []
    spawns = [x["spawn_id"] for x in recs if x["event"] == "spawn"]
    assert spawns and [x["spawn_id"] for x in recs if x["event"] == "spawn_void"] == spawns
    assert spawn.Spawner(cli.work).view("7").agents == 0
    # the same launch with a CLI that documents the flag starts the session
    cli.help(_HELP_WITH_EFFORT)
    r = cli.run("claude_launch", "--challenge", "7", "--", "-p", "hi")
    assert r.returncode == 0, r.stderr
    assert "--effort" in cli.calls()[-1]["argv"]


def test_a_launch_the_gate_refuses_does_not_run_the_cli(cli):
    ledger.append("spend", workdir=cli.work, challenge_id="7", usd=10_000.0, tok=10)   # over any cap
    r = cli.run("claude_launch", "--challenge", "7", "--", "-p", "hi")
    assert r.returncode == 3, r.stderr
    assert cli.calls() == []                       # neither the help call nor a session


def test_a_claude_dry_run_runs_no_cli_and_needs_no_binary(cli):
    want = event.load("csctf").models.effort
    cli.help(_HELP_WITHOUT_EFFORT)                 # a real launch against this CLI is refused (above)
    for extra in ([], ["--claude-bin", str(cli.bin / "absent")]):
        r = cli.run("claude_launch", "--dry-run", *extra, "--", "-p", "hi")
        assert r.returncode == 0, r.stderr
        assert f" --effort {want} -p hi" in r.stdout
        assert f"effort: {want} (dry run: the CLI was not asked" in r.stderr
    assert cli.calls() == []                       # the CLI was never run
