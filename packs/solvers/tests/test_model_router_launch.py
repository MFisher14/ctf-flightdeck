"""B-201: the model router in the agent launchers (tools/route_launch.py, tools/codex_launch,
tools/claude_launch), the speed-tier argv (ctf/fence_launch.py codex_argv) and the route budget in the
launch gate (tools/launch_gate.py).

The launchers run in-process (loaded from tools/) against the shipped csctf profile with a synthetic
[routing] table patched in; every harness is a stub executable written here, so no real Codex or Claude
session starts and nothing leaves 127.0.0.1. Every ledger is synthetic.
"""
from __future__ import annotations

import argparse
import copy
import importlib.machinery
import importlib.util
import json
import os
import sys
import tomllib
from pathlib import Path

import pytest

from ctf import budget, event, fence, fence_launch, ledger, paths
from ctf.event import Budget
from tools import launch_gate, route_launch
from tools.ledger import pricing

PRICES = pricing.load_prices()
BASE = tomllib.loads((paths.event_dir("csctf") / "event.toml").read_text(encoding="utf-8"))

ROUTING = {"route": [
    {"role": "solve", "model": "claude-sonnet-5-5", "effort": "low"},
    {"role": "solve", "harness": "codex", "model": "gpt-6.1-terra", "effort": "minimal"},
    {"role": "solve", "difficulty": "hard", "effort": "high"},
    {"role": "build", "harness": "codex", "model": "gpt-6-astra", "tier": "ultrafast", "budget_usd": 0.05},
    {"role": "doc", "model": "claude-opus-5-5", "tier": "fast", "budget_usd": 5},
]}

STUB = '''#!{py}
import json, os, sys, time
if sys.argv[1:] == ["--help"]:
    print("Options:\\n  --effort <level>  Effort level for the current session")
    sys.exit(0)
spec = json.load(open(os.environ["STUB_SPEC"]))
with open(spec["mark"], "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
for line in spec.get("lines", []):
    print(line, flush=True)
time.sleep(spec.get("sleep", 0))
sys.exit(0)
'''


def _tool(name: str):
    path = paths.repo_root() / "tools" / name
    loader = importlib.machinery.SourceFileLoader(f"b201_{name}", str(path))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


class Env:
    def __init__(self, tmp_path: Path, monkeypatch):
        self.tmp, self.mp = tmp_path, monkeypatch
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.ws = tmp_path / "ws"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.mark = tmp_path / "mark.txt"
        self.spec = tmp_path / "spec.json"
        for n in ("codex", "claude"):
            p = self.bin / n
            p.write_text(STUB.format(py=sys.executable))
            p.chmod(0o755)
        self.stub()
        monkeypatch.setenv("CTF_WORKDIR", str(self.work))
        monkeypatch.setenv("CTF_EVENT", "csctf")
        monkeypatch.setenv("STUB_SPEC", str(self.spec))
        for k in ("CTF_CHALLENGE", "CTF_ROLE", "CTF_DIFFICULTY", "CTF_CATEGORY", "CTF_SPAWN_ID"):
            monkeypatch.delenv(k, raising=False)
        self.routing(ROUTING)

    def routing(self, routing):
        data = copy.deepcopy(BASE)
        if routing is not None:
            data["routing"] = routing
        prof = event.parse(data, src="test.toml")
        real = event.load
        self.mp.setattr(event, "load", lambda slug, root=None: prof if slug == "csctf" else real(slug, root))
        return prof

    def stub(self, *, lines=(), sleep=0.0):
        self.spec.write_text(json.dumps({"mark": str(self.mark), "lines": list(lines), "sleep": sleep}))

    def run(self, tool, *args):
        harness = tool.split("_")[0]
        mod = _tool(tool)
        saved = dict(os.environ)
        try:
            return mod.main(["--workspace", str(self.ws), f"--{harness}-bin", str(self.bin / harness),
                             *args])
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def argvs(self) -> list[list[str]]:
        if not self.mark.exists():
            return []
        return [json.loads(x) for x in self.mark.read_text().splitlines()]

    def events(self, kind):
        return [r for r in ledger.read(self.work) if r["event"] == kind]


@pytest.fixture
def E(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def codex_turn(inp, cached, out):
    return json.dumps({"type": "turn.completed",
                       "usage": {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out}})


def _after(argv, flag):
    return argv[argv.index(flag) + 1]


# ----------------------------------------------------------------------------- codex_launch

def test_codex_launch_routes_model_and_effort_by_role(E, capsys):
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "go") == 0
    cap = capsys.readouterr()
    assert "-m gpt-6.1-terra" in cap.out and 'model_reasoning_effort="minimal"' in cap.out
    assert "model route: solve/medium (rule:1) -> model gpt-6.1-terra, effort minimal" in cap.err
    # hard: the */hard effort rule is less specific than the codex rule naming an effort
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "--difficulty", "hard", "go") == 0
    assert 'model_reasoning_effort="minimal"' in capsys.readouterr().out


def test_explicit_model_and_effort_win_over_the_route(E, capsys):
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "--model", "gpt-6-luna", "--effort",
                 "high", "go") == 0
    cap = capsys.readouterr()
    assert "-m gpt-6-luna" in cap.out and 'model_reasoning_effort="high"' in cap.out
    assert "the route's gpt-6.1-terra is not used" in cap.err and "the route's minimal is not used" in cap.err


def test_no_role_or_no_routing_table_leaves_the_launch_unrouted(E, capsys):
    assert E.run("codex_launch", "--dry-run", "--model", "gpt-6-luna", "go") == 0
    cap = capsys.readouterr()
    assert "model route: off" in cap.err and "-m gpt-6-luna" in cap.out
    E.routing(None)
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "--model", "gpt-6-luna", "go") == 0
    cap = capsys.readouterr()
    assert "model route" not in cap.err
    assert f'model_reasoning_effort="{event.load("csctf").models.effort}"' in cap.out   # B-095 default


@pytest.mark.parametrize("args, routing, msg", [
    (["--role", "solve", "--difficulty", "hard"], None, "has no [routing] table"),
    (["--difficulty", "hard"], ROUTING, "need a role"),
    (["--role", "solve", "--no-route", "--category", "pwn"], ROUTING, "--no-route contradicts --category"),
])
def test_routing_options_that_cannot_be_honoured_are_refused(E, capsys, args, routing, msg):
    E.routing(routing)
    assert E.run("codex_launch", "--dry-run", "--model", "gpt-6-luna", *args, "go") == 2
    assert msg in capsys.readouterr().err


def test_difficulty_from_the_environment(E, capsys, monkeypatch):
    monkeypatch.setenv("CTF_DIFFICULTY", "insane")
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "go") == 2
    assert "unknown difficulty 'insane'" in capsys.readouterr().err
    monkeypatch.setenv("CTF_DIFFICULTY", "hard")
    monkeypatch.setenv("CTF_ROLE", "doc")
    E.routing({"route": [{"role": "doc", "difficulty": "hard", "effort": "max"}]})
    assert E.run("codex_launch", "--dry-run", "--model", "gpt-6-luna", "go") == 0
    assert 'model_reasoning_effort="max"' in capsys.readouterr().out


def test_an_unpriced_routing_table_stops_the_launch(E, capsys):
    E.routing({"route": [{"role": "solve", "model": "claude-unpriced-9"}]})
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "go") == 2
    assert "claude-unpriced-9" in capsys.readouterr().err


def test_a_routed_gated_launch_records_the_route(E):
    E.stub(lines=[codex_turn(1000, 0, 100)])
    assert E.run("codex_launch", "--challenge", "7", "--role", "solve", "--difficulty", "easy",
                 "--category", "Crypto", "go") == 0
    (launch,) = E.events("agent_launch")
    assert launch["role"] == "solve" and launch["model"] == "gpt-6.1-terra"
    assert (launch["difficulty"], launch["tier"], launch["route"], launch["category"]) == \
        ("easy", "default", "rule:1", "Crypto")
    assert launch["effort"] == "minimal"           # the codex rule's effort, the one launched
    assert "tier_budget_usd" not in launch
    (argv,) = E.argvs()
    assert "--disable" in argv and "ultrafast_mode" in argv and not any(a.startswith("service_tier") for a in argv)


def test_a_routed_launch_records_the_effort_it_ran_at(E, capsys):
    E.stub(lines=[codex_turn(1000, 0, 100)])
    assert E.run("codex_launch", "--challenge", "7", "--role", "solve", "--effort", "high", "go") == 0
    (launch,) = E.events("agent_launch")
    assert launch["effort"] == "high"              # the explicit --effort, not the route's "minimal"
    (argv,) = E.argvs()
    assert 'model_reasoning_effort="high"' in argv


def test_a_corrupt_ledger_stops_a_routed_launch_by_name(E, capsys):
    lp = ledger.path(E.work)
    lp.write_text("{not json\n", encoding="utf-8")
    assert E.run("codex_launch", "--dry-run", "--role", "solve", "go") == 2
    err = capsys.readouterr().err
    assert "cannot be read for the B-096 A/B gate" in err and str(lp) in err
    assert "Traceback" not in err and E.argvs() == []


# ----------------------------------------------------------------------------- speed tiers

def test_a_speed_tier_route_needs_a_budget_gated_launch(E, capsys):
    assert E.run("codex_launch", "--dry-run", "--role", "build", "go") == 2
    assert "needs a budget-gated launch" in capsys.readouterr().err
    assert E.run("codex_launch", "--challenge", "7", "--role", "build", "--interactive") == 2
    assert "needs a metered run" in capsys.readouterr().err
    assert E.argvs() == [] and E.events("agent_launch") == []


def test_a_speed_tier_run_uses_the_tier_prices_it_and_stops_at_its_budget(E, capsys):
    # one turn: base (1000*10 + 100*50)/1e6 = $0.015; ultrafast is 6x = $0.09 >= the $0.05 budget.
    # The stub then sleeps: the gate must stop it (no upper bound on how long that takes).
    E.stub(lines=[codex_turn(1000, 0, 100)], sleep=120)
    rc = E.run("codex_launch", "--challenge", "7", "--role", "build", "--gate-poll", "0.2", "go")
    err = capsys.readouterr().err
    assert rc == launch_gate.EXIT_REFUSED, err
    assert "speed-tier route allows" in err
    (argv,) = E.argvs()
    assert 'service_tier="ultrafast"' in argv and "-m" in argv and _after(argv, "-m") == "gpt-6-astra"
    disabled = [argv[i + 1] for i, a in enumerate(argv) if a == "--disable"]
    assert "ultrafast_mode" not in disabled and {"fast_mode", "shell_snapshot"} <= set(disabled)
    (launch,) = E.events("agent_launch")
    assert launch["tier"] == "ultrafast" and launch["tier_budget_usd"] == 0.05
    spend = sum(r["usd"] for r in E.events("spend"))
    assert spend == pytest.approx(0.09)
    assert E.events("agent_exit")[-1]["reason"] == launch_gate.ROUTE_BUDGET
    assert E.events("agent_refused")[-1]["reason"] == launch_gate.ROUTE_BUDGET


def test_an_explicit_model_drops_the_routes_speed_tier(E, capsys):
    E.stub(lines=[codex_turn(1000, 0, 100)])
    assert E.run("codex_launch", "--challenge", "7", "--role", "build", "--model", "gpt-6-luna", "go") == 0
    (argv,) = E.argvs()
    assert not any(a.startswith("service_tier") for a in argv)
    (launch,) = E.events("agent_launch")
    assert launch["tier"] == "default" and "tier_budget_usd" not in launch


# ----------------------------------------------------------------------------- claude_launch

def test_claude_launch_passes_the_routed_model(E, capsys):
    assert E.run("claude_launch", "--dry-run", "--no-notes", "--role", "solve", "--", "-p", "hi") == 0
    out = capsys.readouterr().out
    assert "--model claude-sonnet-5-5" in out and "--effort low" in out


def test_a_passthrough_model_wins_on_claude(E, capsys):
    assert E.run("claude_launch", "--dry-run", "--no-notes", "--role", "solve", "--", "--model",
                 "claude-opus-5-5", "-p", "hi") == 0
    out = capsys.readouterr().out
    assert out.count("--model") == 1 and "--model claude-opus-5-5" in out


def test_claude_launch_refuses_a_speed_tier_route(E, capsys):
    assert E.run("claude_launch", "--dry-run", "--no-notes", "--role", "doc", "--", "-p", "hi") == 2
    assert "claude_launch cannot pin a Claude speed tier" in capsys.readouterr().err


def test_a_gated_claude_launch_records_the_route(E):
    assert E.run("claude_launch", "--no-notes", "--challenge", "7", "--role", "solve", "--difficulty",
                 "hard", "--", "-p", "hi") == 0
    (launch,) = E.events("agent_launch")
    assert launch["model"] == "claude-sonnet-5-5" and launch["difficulty"] == "hard"
    assert launch["route"] == "rule:0" and launch["tier"] == "default" and launch["effort"] == "high"
    session = E.argvs()[-1]
    assert _after(session, "--model") == "claude-sonnet-5-5" and _after(session, "--effort") == "high"


def test_a_gated_claude_launch_records_an_explicit_effort_over_the_routes(E):
    # solve/hard routes effort "high"; the explicit --effort "medium" is what runs, so it is what the
    # escalator's ramp must read back from agent_launch.
    assert E.run("claude_launch", "--no-notes", "--challenge", "7", "--role", "solve", "--difficulty",
                 "hard", "--effort", "medium", "--", "-p", "hi") == 0
    (launch,) = E.events("agent_launch")
    assert launch["effort"] == "medium" and launch["route"] == "rule:0"
    session = E.argvs()[-1]
    assert _after(session, "--effort") == "medium"


# ----------------------------------------------------------------------------- units

def test_codex_argv_service_tier(tmp_path):
    dirs = [tmp_path / "home" / "player", tmp_path / "work" / "csctf", tmp_path / "src" / "ctf-tools"]
    for d in dirs:
        d.mkdir(parents=True)
    home, ws, repo = (d.resolve() for d in dirs)
    f = fence.build(home=home, workspace=ws, repo=repo, user_dir=None)
    std = fence_launch.codex_argv(f, prompt="p")
    assert not any(a.startswith("service_tier") for a in std)
    assert fence_launch.codex_argv(f, prompt="p", service_tier="default") == std
    ultra = fence_launch.codex_argv(f, prompt="p", service_tier="ultrafast")
    assert 'service_tier="ultrafast"' in ultra
    dis = [ultra[i + 1] for i, a in enumerate(ultra) if a == "--disable"]
    assert dis == ["fast_mode", "shell_snapshot"]
    pri = fence_launch.codex_argv(f, prompt="p", service_tier="priority")
    assert [pri[i + 1] for i, a in enumerate(pri) if a == "--disable"] == list(fence_launch.CODEX_DISABLED_FEATURES)
    with pytest.raises(fence_launch.LaunchError):
        fence_launch.codex_argv(f, prompt="p", service_tier="warp")
    with pytest.raises(fence_launch.LaunchError):           # a passthrough tier is still refused
        fence_launch.codex_argv(f, prompt="p", service_tier="ultrafast", extra=["-c", "service_tier=fast"])


def test_codex_usage_prices_the_tier():
    line = codex_turn(1000, 0, 100)
    assert launch_gate.CodexJsonUsage("gpt-6-astra", PRICES).feed(line)[0].usd == pytest.approx(0.015)
    assert launch_gate.CodexJsonUsage("gpt-6-astra", PRICES, speed="ultrafast").feed(line)[0].usd == \
        pytest.approx(0.09)
    with pytest.raises(launch_gate.GateError):
        launch_gate.CodexJsonUsage("gpt-6.1-sol", PRICES, speed="ultrafast")


def test_the_gate_stops_an_agent_at_its_route_budget(tmp_path):
    meter = budget.LedgerMeter(Budget(per_point=0.5, floor=25.0, ceiling=250.0), workdir=tmp_path)
    g = launch_gate.Gate(meter, "7", harness="codex")
    g.charge(10.0, 10)                                  # no route cap: only the $25 challenge cap
    g.agent_cap_usd = 12.0
    g.charge(1.0, 10)
    with pytest.raises(launch_gate.GateRefused) as ei:
        g.charge(1.0, 10)                               # 12.0 >= 12.0
    assert ei.value.reason == launch_gate.ROUTE_BUDGET and "$12.00" in str(ei.value)
    assert meter.spent("7").usd == pytest.approx(12.0)  # the spend is still on the ledger


def test_check_speed_tier_and_record_route_units():
    class G:
        agent_cap_usd = None
        launch_fields: dict = {}
    from ctf import router
    r = router.Route(role="build", difficulty="easy", model="gpt-6-astra", harness="codex", effort="low",
                     tier="ultrafast", budget_usd=3.0, model_rule=0)
    route_launch.check_speed_tier(None, "default", gate=None, metered=False)     # default: nothing
    g = G()
    route_launch.check_speed_tier(r, "ultrafast", gate=g, metered=True)
    assert g.agent_cap_usd == 3.0
    with pytest.raises(route_launch.RouteLaunchError):
        route_launch.check_speed_tier(None, "ultrafast", gate=g, metered=True)
    route_launch.record_route(g, r, "default")
    assert g.launch_fields["tier"] == "default" and "tier_budget_usd" not in g.launch_fields
    assert g.launch_fields["effort"] == "low"                     # no launched effort: the route's
    route_launch.record_route(g, r, "ultrafast", effort="max")
    assert g.launch_fields["tier_budget_usd"] == 3.0 and g.launch_fields["effort"] == "max"
    assert route_launch.passthrough_model(["-p", "x", "--model=claude-opus-5-5"]) == "claude-opus-5-5"
    assert route_launch.passthrough_model(["-p", "x"]) is None
    with pytest.raises(route_launch.RouteLaunchError):
        route_launch.passthrough_model(["--model"])


def test_add_route_options_defaults():
    p = argparse.ArgumentParser()
    route_launch.add_route_options(p)
    a = p.parse_args([])
    assert (a.difficulty, a.category, a.no_route) == (None, None, False)
