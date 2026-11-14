"""B-194: ctf.workflows (the pre-launch registry, schema check, agent-cap dry-run) and `ctf workflow`.

Pure-Python, no node: the manifests gate a launch before the JS even starts. A consistency check ties
each manifest's cap and required args to what the JS enforces (so the two representations cannot drift).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import workflows as wf

ROOT = Path(__file__).resolve().parents[1]

LANE_ARGS = {"event": "E", "repo": "/r", "out": "/w", "task": "t", "redactFlags": True,
             "lanes": [{"key": "web", "id": "web-1"}, {"key": "crypto", "id": "crypto-1"}]}


# ------------------------------------------------------------------------------------ registry loading

def test_load_all_lists_the_shipped_workflows():
    got = {w.name for w in wf.load_all()}
    assert {"lane-fanout", "verify-fanout"} <= got
    for w in wf.load_all():
        assert w.script_path.is_file()


def test_get_unknown_workflow_fails_loudly():
    with pytest.raises(wf.WorkflowError) as e:
        wf.get("no-such-workflow")
    assert "no-such-workflow" in str(e.value)


def test_manifest_with_unknown_key_is_rejected(tmp_path, monkeypatch):
    d = tmp_path / "workflows"
    d.mkdir()
    (d / "x.js").write_text("export const meta = {}\n")
    (d / "x.wf.toml").write_text(
        'name="x"\nscript="x.js"\ndescription="d"\nrequired=["lanes"]\nlane_arg="lanes"\n'
        'stages_per_lane=1\nextra_agents=0\nmax_agents=4\nbogus=1\n')
    monkeypatch.setattr(wf.paths, "repo_root", lambda: tmp_path)
    with pytest.raises(wf.WorkflowError) as e:
        wf.load_all()
    assert "bogus" in str(e.value)


def test_manifest_missing_script_file_is_rejected(tmp_path, monkeypatch):
    d = tmp_path / "workflows"
    d.mkdir()
    (d / "x.wf.toml").write_text(
        'name="x"\nscript="x.js"\ndescription="d"\nrequired=["lanes"]\nlane_arg="lanes"\n'
        'stages_per_lane=1\nextra_agents=0\nmax_agents=4\n')
    monkeypatch.setattr(wf.paths, "repo_root", lambda: tmp_path)
    with pytest.raises(wf.WorkflowError) as e:
        wf.load_all()
    assert "not found" in str(e.value)


# -------------------------------------------------------------------- schema check + cap dry-run (python)

def test_validate_names_the_first_missing_required_arg():
    w = wf.get("lane-fanout")
    for key in ("event", "repo", "out", "task", "redactFlags", "lanes"):
        args = {k: v for k, v in LANE_ARGS.items() if k != key}
        with pytest.raises(wf.WorkflowError) as e:
            wf.validate(w, args)
        assert f'"{key}"' in str(e.value)


def test_validate_requires_a_nonempty_lane_list():
    w = wf.get("lane-fanout")
    with pytest.raises(wf.WorkflowError) as e:
        wf.validate(w, {**LANE_ARGS, "lanes": []})
    assert "non-empty list" in str(e.value)


def test_plan_agents_and_check_cap():
    w = wf.get("lane-fanout")  # stages_per_lane=2, extra=1, max=24
    assert wf.plan_agents(w, LANE_ARGS) == 2 * 2 + 1
    big = {**LANE_ARGS, "lanes": [{"key": f"l{i}", "id": f"l{i}-1"} for i in range(12)]}
    with pytest.raises(wf.WorkflowError) as e:
        wf.check_cap(w, big)  # 25 > 24
    assert "agent cap exceeded" in str(e.value) and "25" in str(e.value)
    ok = {**LANE_ARGS, "lanes": [{"key": f"l{i}", "id": f"l{i}-1"} for i in range(11)]}
    assert wf.check_cap(w, ok) == 23


VERIFY_ARGS = {"event": "E", "targets": [{"id": "f1", "claim": "c"}]}


def _verify_args(n):
    return {"event": "E", "targets": [{"id": f"t{i}", "claim": "c"} for i in range(n)]}


def test_check_cap_allows_planned_equal_to_cap():
    # Boundary: planned == cap must PASS. check_cap uses `>` (not `>=`), so a count that exactly meets
    # the cap is allowed. verify-fanout plans one verifier per target (stages_per_lane=1, extra=0) under
    # a hard cap of 16, so 16 targets plan exactly 16 agents and run; 17 exceed it. lane-fanout cannot
    # test this edge: its plan 2L+1 is always odd and can never equal its even cap 24.
    w = wf.get("verify-fanout")
    at_cap = _verify_args(16)
    assert wf.plan_agents(w, at_cap) == 16
    assert wf.check_cap(w, at_cap) == 16          # planned == cap -> allowed (kills `>` -> `>=`)
    assert wf.preflight(w, at_cap) == 16          # the full gate also admits the boundary
    over = _verify_args(17)
    with pytest.raises(wf.WorkflowError) as e:
        wf.check_cap(w, over)                      # 17 > 16 -> refused
    assert "agent cap exceeded" in str(e.value) and "17" in str(e.value)


def test_agentCap_only_lowers_the_cap():
    w = wf.get("lane-fanout")
    assert wf.effective_cap(w, LANE_ARGS) == 24
    assert wf.effective_cap(w, {**LANE_ARGS, "agentCap": 4}) == 4
    assert wf.effective_cap(w, {**LANE_ARGS, "agentCap": 100}) == 24  # cannot exceed the hard cap
    with pytest.raises(wf.WorkflowError):
        wf.check_cap(w, {**LANE_ARGS, "agentCap": 4})  # 5 planned > 4


def test_preflight_runs_schema_then_cap():
    w = wf.get("lane-fanout")
    assert wf.preflight(w, LANE_ARGS) == 5
    with pytest.raises(wf.WorkflowError):
        wf.preflight(w, {k: v for k, v in LANE_ARGS.items() if k != "event"})


# ------------------------------------------------------------- the manifest agrees with the JS (no drift)

def _js_hard_cap(name):
    src = (wf.workflows_dir() / f"{name}.js").read_text()
    m = re.search(r"HARD_AGENT_CAP\s*=\s*(\d+)", src)
    assert m, f"{name}.js declares no HARD_AGENT_CAP"
    return int(m.group(1))


@pytest.mark.parametrize("name", ["lane-fanout", "verify-fanout"])
def test_manifest_cap_matches_the_js_hard_cap(name):
    assert wf.get(name).max_agents == _js_hard_cap(name)


# The per-workflow stage constants the JS uses to compute its own planned count, by workflow name.
_JS_STAGE_CONSTS = {
    "lane-fanout": ("STAGES_PER_LANE", "INDEX_AGENTS"),
    "verify-fanout": ("STAGES_PER_TARGET", "EXTRA_AGENTS"),
}


@pytest.mark.parametrize("name", ["lane-fanout", "verify-fanout"])
def test_manifest_stage_counts_match_the_js(name):
    # The JS and the manifest each carry the per-lane stage count and the extra-agent count. The Python
    # pre-launch dry-run (plan_agents) reads the manifest; the JS computes its own planned count from
    # these constants. If they drifted, `ctf workflow check` would report a count the JS does not spawn.
    src = (wf.workflows_dir() / f"{name}.js").read_text()
    stage_const, extra_const = _JS_STAGE_CONSTS[name]
    ms = re.search(rf"\b{stage_const}\s*=\s*(\d+)", src)
    me = re.search(rf"\b{extra_const}\s*=\s*(\d+)", src)
    assert ms, f"{name}.js declares no {stage_const}"
    assert me, f"{name}.js declares no {extra_const}"
    w = wf.get(name)
    assert int(ms.group(1)) == w.stages_per_lane, f"{name}: {stage_const} != manifest stages_per_lane"
    assert int(me.group(1)) == w.extra_agents, f"{name}: {extra_const} != manifest extra_agents"


@pytest.mark.parametrize("name", ["lane-fanout", "verify-fanout"])
def test_every_required_arg_is_read_by_the_js(name):
    # Each manifest-required argument is actually consumed by the script (args.<name> or args['<name>']).
    src = (wf.workflows_dir() / f"{name}.js").read_text()
    for key in wf.get(name).required:
        assert re.search(rf"'{re.escape(key)}'|\"{re.escape(key)}\"", src), f"{name}.js never reads {key!r}"


# --------------------------------------------------------------------------------- lanes from the board

def test_lanes_from_board_collects_distinct_lanes(tmp_path):
    claims = tmp_path / "dispatch" / "claims"
    claims.mkdir(parents=True)
    (claims / "1.json").write_text(json.dumps({"challenge_id": "1", "lane": "web"}))
    (claims / "2.json").write_text(json.dumps({"challenge_id": "2", "lane": "crypto"}))
    (claims / "3.json").write_text(json.dumps({"challenge_id": "3", "lane": "web"}))
    assert wf.lanes_from_board(tmp_path) == ["crypto", "web"]


def test_lanes_from_board_falls_back_to_canonical_category(tmp_path):
    claims = tmp_path / "dispatch" / "claims"
    claims.mkdir(parents=True)
    (claims / "1.json").write_text(json.dumps({"challenge_id": "1", "category": "Reverse Engineering"}))
    from ctf import triage
    assert wf.lanes_from_board(tmp_path) == [triage.canonical_category("Reverse Engineering")]


def test_lanes_from_board_raises_on_unreadable_claim(tmp_path):
    claims = tmp_path / "dispatch" / "claims"
    claims.mkdir(parents=True)
    (claims / "bad.json").write_text("{ not json")
    with pytest.raises(wf.WorkflowError) as e:
        wf.lanes_from_board(tmp_path)
    assert "unreadable" in str(e.value)


def test_lanes_from_board_empty_when_no_claims(tmp_path):
    assert wf.lanes_from_board(tmp_path) == []


def test_lanes_from_profile_canonicalises_categories():
    from ctf import event, triage
    prof = event.load("csctf")
    lanes = wf.lanes_from_profile(prof)
    assert lanes == sorted(lanes)
    assert all(lane == triage.canonical_category(lane) for lane in lanes)
    assert lanes  # csctf declares categories


# --------------------------------------------------------------------------------------------- the CLI

def _cli(*args, input_files=None):
    return subprocess.run([sys.executable, "-m", "ctf", "workflow", *args],
                          capture_output=True, text=True, cwd=ROOT)


def test_cli_list_json_shows_caps_and_required():
    r = _cli("list", "--json")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    by = {d["name"]: d for d in data}
    assert by["lane-fanout"]["max_agents"] == 24
    assert "lanes" in by["lane-fanout"]["required"]


def test_cli_check_refuses_over_cap(tmp_path):
    args = {**LANE_ARGS, "lanes": [{"key": f"l{i}", "id": f"l{i}-1"} for i in range(12)]}
    f = tmp_path / "args.json"
    f.write_text(json.dumps(args))
    r = _cli("check", "lane-fanout", "--args-file", str(f))
    assert r.returncode == 1
    assert "agent cap exceeded" in (r.stderr + r.stdout)


def test_cli_check_passes_valid_args(tmp_path):
    f = tmp_path / "args.json"
    f.write_text(json.dumps(LANE_ARGS))
    r = _cli("check", "lane-fanout", "--args-file", str(f), "--json")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["ok"] and out["planned_agents"] == 5


def test_cli_check_names_missing_arg(tmp_path):
    f = tmp_path / "args.json"
    f.write_text(json.dumps({k: v for k, v in LANE_ARGS.items() if k != "out"}))
    r = _cli("check", "lane-fanout", "--args-file", str(f))
    assert r.returncode == 1
    assert '"out"' in (r.stderr + r.stdout)
