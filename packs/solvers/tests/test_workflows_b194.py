"""B-194: the shipped workflow scripts enforce their four guards BEFORE any agent is spawned.

These run the real workflows/*.js files under the shared node harness (wf_harness) and assert the
behaviour by the recorded agent() calls: a failed guard records zero calls, so a bad schema or an
over-cap fan-out costs no agents. Marked needs_tool("node") so they report NOT RUN when node is absent.
"""
from pathlib import Path

import pytest

from wf_harness import run_wf

ROOT = Path(__file__).resolve().parents[1]
WF_DIR = ROOT / "workflows"
LANE_FANOUT = WF_DIR / "lane-fanout.js"
VERIFY_FANOUT = WF_DIR / "verify-fanout.js"

needs_node = pytest.mark.needs_tool("node")

LANES3 = [
    {"key": "web", "id": "web-1", "folder": "/r/ch/web-1"},
    {"key": "crypto", "id": "crypto-1"},
    {"key": "pwn", "id": "pwn-1", "solver": "solvers/binary/"},
]
LANE_ARGS = {"event": "Example CTF 2027", "repo": "/r", "out": "/w/out",
             "task": "Document how the lane was solved.", "redactFlags": True, "lanes": LANES3}


def labels(r):
    return [c["label"] for c in r["calls"]]


# --------------------------------------------------------------------- the files ship, outside .claude/

def test_shipped_workflows_live_outside_dot_claude():
    files = sorted(p.name for p in WF_DIR.glob("*.js"))
    assert files == ["day-lookahead.js", "lane-fanout.js", "verify-fanout.js"]
    # No shipped workflow lives under a .claude/ directory anywhere in the repo tree.
    assert not list(ROOT.glob(".claude/**/workflows/*.js"))


# ------------------------------------------------------------------ guard 1: schema check before launch

@needs_node
@pytest.mark.parametrize("missing", ["event", "repo", "out", "task", "redactFlags", "lanes"])
def test_lane_fanout_missing_required_arg_fails_by_name_zero_agents(tmp_path, missing):
    args = {k: v for k, v in LANE_ARGS.items() if k != missing}
    r = run_wf(LANE_FANOUT, args, tmp_path)
    assert not r["ok"]
    assert f'"{missing}"' in r["error"]
    assert r["calls"] == []  # the schema check runs before any agent


@needs_node
def test_lane_fanout_redact_flags_must_be_boolean(tmp_path):
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "redactFlags": "yes"}, tmp_path)
    assert not r["ok"] and "redactFlags" in r["error"]
    assert r["calls"] == []


@needs_node
def test_every_agent_call_carries_a_schema(tmp_path):
    # A StructuredOutput schema on every agent is what stops a parse/StructuredOutput mismatch aborting
    # the run (the 2026 retro). The harness records opts.schema; none may be null.
    r = run_wf(LANE_FANOUT, LANE_ARGS, tmp_path)
    assert r["ok"], r
    assert r["calls"]
    assert all(c["schema"] is not None for c in r["calls"])


# ---------------------------------------------------------------- guard 2: lanes from the board, not code

@needs_node
def test_lane_fanout_has_no_builtin_lane_list_empty_fails(tmp_path):
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "lanes": []}, tmp_path)
    assert not r["ok"] and "non-empty array" in r["error"]
    assert r["calls"] == []


@needs_node
def test_lane_fanout_fans_out_over_exactly_the_board_lanes(tmp_path):
    # The web lane must not be dropped: whatever the board gives is what runs (the retro: hard-coded
    # lanes skipped web).
    r = run_wf(LANE_FANOUT, LANE_ARGS, tmp_path)
    assert r["ok"], r
    ls = labels(r)
    for lane in ("web", "crypto", "pwn"):
        assert f"write:{lane}" in ls and f"check:{lane}" in ls
    assert "write:index" in ls


@needs_node
def test_lane_fanout_rejects_malformed_lane_before_launch(tmp_path):
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "lanes": [{"key": "web"}]}, tmp_path)  # no id
    assert not r["ok"] and 'is missing "id"' in r["error"]
    assert r["calls"] == []


# ----------------------------------------------------------------- guard 3: briefs carry only the task

@needs_node
def test_each_lane_brief_carries_only_its_own_lane(tmp_path):
    r = run_wf(LANE_FANOUT, LANE_ARGS, tmp_path)
    assert r["ok"], r
    web_write = next(c["prompt"] for c in r["calls"] if c["label"] == "write:web")
    assert "/r/ch/web-1" in web_write and "web" in web_write
    # The web writer's brief must not name another lane's challenge folder/id.
    assert "crypto-1" not in web_write and "pwn-1" not in web_write


@needs_node
def test_no_brief_carries_a_human_question_or_free_form_arg(tmp_path):
    # A field the brief builder does not use (e.g. a note/question meant for the player) must never
    # reach a running agent (the retro: a human question reached the agents).
    sentinel = "ASK-THE-PLAYER-SHOULD-WE-CONTINUE"
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "note": sentinel, "question": sentinel}, tmp_path)
    assert r["ok"], r
    assert all(sentinel not in c["prompt"] for c in r["calls"])


# ---------------------------------------------- guard 4: hard agent cap with a dry-run count before launch

@needs_node
def test_lane_fanout_over_cap_fails_before_any_agent(tmp_path):
    # 12 lanes -> 12*2 + 1 = 25 agents > hard cap 24: must throw with zero recorded agent calls.
    lanes = [{"key": f"l{i}", "id": f"l{i}-1"} for i in range(12)]
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "lanes": lanes}, tmp_path)
    assert not r["ok"]
    assert "agent cap exceeded" in r["error"] and "25" in r["error"]
    assert r["calls"] == []


@needs_node
def test_lane_fanout_at_cap_runs(tmp_path):
    # 11 lanes -> 11*2 + 1 = 23 <= 24: runs, spawning exactly the planned count.
    lanes = [{"key": f"l{i}", "id": f"l{i}-1"} for i in range(11)]
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "lanes": lanes}, tmp_path)
    assert r["ok"], r
    assert len(r["calls"]) == 23  # matches the dry-run plan
    assert r["result"]["planned"] == 23


@needs_node
def test_agentCap_can_only_lower_the_cap_not_raise_it(tmp_path):
    # A small agentCap tightens the bound and fails a fan-out the hard cap would allow.
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "agentCap": 4}, tmp_path)  # 3 lanes -> 7 agents > 4
    assert not r["ok"] and "agent cap exceeded" in r["error"]
    assert r["calls"] == []
    # And it cannot raise the cap above the hard ceiling: 12 lanes (25) with agentCap 100 still fails.
    lanes = [{"key": f"l{i}", "id": f"l{i}-1"} for i in range(12)]
    r = run_wf(LANE_FANOUT, {**LANE_ARGS, "lanes": lanes, "agentCap": 100}, tmp_path)
    assert not r["ok"] and "agent cap exceeded" in r["error"]
    assert r["calls"] == []


# ------------------------------------------------------------------------------- verify-fanout workflow

VERIFY_ARGS = {"event": "Example CTF 2027", "targets": [
    {"id": "t1", "claim": "flag is X", "evidence": "/e/1"},
    {"id": "t2", "claim": "flag is Y"},
]}


@needs_node
@pytest.mark.parametrize("missing", ["event", "targets"])
def test_verify_fanout_missing_required_arg_zero_agents(tmp_path, missing):
    args = {k: v for k, v in VERIFY_ARGS.items() if k != missing}
    r = run_wf(VERIFY_FANOUT, args, tmp_path)
    assert not r["ok"] and f'"{missing}"' in r["error"]
    assert r["calls"] == []


@needs_node
def test_verify_fanout_one_schema_verifier_per_target(tmp_path):
    r = run_wf(VERIFY_FANOUT, VERIFY_ARGS, tmp_path)
    assert r["ok"], r
    assert sorted(labels(r)) == ["verify:t1", "verify:t2"]
    assert all(c["schema"] is not None for c in r["calls"])  # no StructuredOutput mismatch aborts
    t1 = next(c["prompt"] for c in r["calls"] if c["label"] == "verify:t1")
    assert "flag is X" in t1 and "t2" not in t1  # only its own target


@needs_node
def test_verify_fanout_over_cap_fails_before_any_agent(tmp_path):
    targets = [{"id": f"t{i}", "claim": "c"} for i in range(17)]  # hard cap 16
    r = run_wf(VERIFY_FANOUT, {**VERIFY_ARGS, "targets": targets}, tmp_path)
    assert not r["ok"] and "agent cap exceeded" in r["error"]
    assert r["calls"] == []
