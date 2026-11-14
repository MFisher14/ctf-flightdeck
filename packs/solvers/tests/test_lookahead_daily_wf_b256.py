"""B-256: workflows/day-lookahead.js under a node stub harness.

The shipped workflow is run with agent()/pipeline()/phase()/log() stubbed (the tests/wf_harness.py pattern,
B-194), with one addition: each test scripts how each agent call behaves (`ok`, `throw`, `null`, `wrong`
lane), so the retry-on-null and the missing-lane check (Huntress backlog row 335, the day-retro analyzeLane
port) are proven by the recorded calls and the return value. Prediction text is agent work: the stub
returns a schema-shaped reply. Node-backed tests are marked needs_tool("node"); the manifest-vs-JS
consistency tests are pure Python.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from ctf import event
from ctf import workflows as wf
from ctf.lookahead import daily, forecast

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "workflows" / "day-lookahead.js"
MANIFEST = ROOT / "workflows" / "day-lookahead.wf.toml"
needs_node = pytest.mark.needs_tool("node")

# The B-194 harness, with scripted agent behaviour: BEHAVE maps a call label to a list of outcomes taken
# in order across calls with that label's lane (first attempt, then the retry); default "ok".
HARNESS = r"""
const fs = require('fs')
const [file, argsJson, behaveJson] = process.argv.slice(2)
const BEHAVE = JSON.parse(behaveJson)
let src = fs.readFileSync(file, 'utf8').replace(/^export const meta/m, 'const meta')
const calls = []
const agent = async (prompt, opts = {}) => {
  calls.push({ label: opts.label, prompt, schema: opts.schema || null, phase: opts.phase || null })
  const lane = String(opts.label).split(':')[1]
  const n = calls.filter(c => String(c.label).split(':')[1] === lane).length
  const plan = BEHAVE[lane] || []
  const how = plan[n - 1] || 'ok'
  if (how === 'throw') throw new Error('classifier refused')
  if (how === 'null') return null
  if (how === 'wrong') return { lane: 'someone-else', file: 'x', new: [], gaps: [], note: '', specimens: [] }
  return { lane, file: `/out/predictions-${lane}.md`, new: [`${lane}_new_*`], gaps: [], note: `n${n}`, specimens: ['s'] }
}
const pipeline = async (items, ...stages) => Promise.all(items.map(async (it) => {
  let v = it
  for (let i = 0; i < stages.length; i++) v = await stages[i](i === 0 ? it : v, it)
  return v
}))
const parallel = async (thunks) => Promise.all(thunks.map(async (t) => { try { return await t() } catch (e) { return null } }))
const phase = () => {}
const logs = []
const log = (m) => logs.push(m)
const fn = new Function('args', 'agent', 'pipeline', 'parallel', 'phase', 'log', `return (async () => { ${src}\n })()`)
fn(JSON.parse(argsJson), agent, pipeline, parallel, phase, log)
  .then(r => console.log(JSON.stringify({ ok: true, result: r, calls, logs })))
  .catch(e => console.log(JSON.stringify({ ok: false, error: String(e && e.message || e), calls, logs })))
"""


def run(args, tmp_path, behave=None):
    node = shutil.which("node")
    assert node, "mark the test needs_tool('node')"
    h = tmp_path / "harness.cjs"
    h.write_text(HARNESS)
    p = subprocess.run([node, str(h), str(JS), json.dumps(args), json.dumps(behave or {})],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


LANES = [
    {"key": "web", "reasons": ["no gate report: coverage unknown"], "staged": []},
    {"key": "script-analysis", "reasons": ["1 open gap(s) (unanswered)"],
     "staged": ["tagged-python-marker-joined", "computed-raw"]},
    {"key": "warmups", "reasons": ["new shape: 2 changed id(s), e.g. size_a"], "staged": []},
]
ARGS = {"event": "Example CTF 2027", "repo": "/r", "out": "/w/la/d29", "day": "d29", "matrix": "/w/matrix",
        "lanes": LANES}


def labels(r):
    return [c["label"] for c in r["calls"]]


# ------------------------------------------------------------------------- retry and missing-lane check


@needs_node
def test_every_planned_lane_gets_one_predictor_when_all_answer(tmp_path):
    r = run(ARGS, tmp_path)
    assert r["ok"], r
    assert sorted(labels(r)) == ["predict:script-analysis", "predict:warmups", "predict:web"]
    assert [s["lane"] for s in r["result"]["staged"]] == ["web", "script-analysis", "warmups"]
    assert r["result"]["notStaged"] == [] and r["result"]["planned"] == 6


@needs_node
@pytest.mark.parametrize("how", ["throw", "null", "wrong"])
def test_a_lane_that_returns_nothing_is_rerun_once_with_a_reworded_brief(tmp_path, how):
    r = run(ARGS, tmp_path, {"warmups": [how]})
    assert r["ok"], r
    warm = [c for c in r["calls"] if c["label"].startswith("predict:warmups")]
    assert [c["label"] for c in warm] == ["predict:warmups", "predict:warmups:retry"]
    assert "This is a re-run" not in warm[0]["prompt"] and "This is a re-run" in warm[1]["prompt"]
    assert 'set lane to exactly "warmups"' in warm[1]["prompt"]
    staged = {s["lane"]: s for s in r["result"]["staged"]}
    assert set(staged) == {"web", "script-analysis", "warmups"} and staged["warmups"]["note"] == "n2"
    assert r["result"]["notStaged"] == []
    assert any("predict:warmups returned nothing; re-running once" in m for m in r["logs"])
    assert len(r["calls"]) == 4                     # no other lane re-ran


@needs_node
def test_a_lane_that_fails_twice_is_named_not_staged_and_the_rest_are_kept(tmp_path):
    r = run(ARGS, tmp_path, {"warmups": ["throw", "null"], "web": ["wrong", "wrong"]})
    assert r["ok"], r
    assert r["result"]["notStaged"] == ["web", "warmups"]
    assert [s["lane"] for s in r["result"]["staged"]] == ["script-analysis"]
    assert "warmups: NOT staged (its predictor returned nothing twice)" in r["logs"]
    assert "web: NOT staged (its predictor returned nothing twice)" in r["logs"]
    assert any("1 of 3 planned lane(s) staged; NOT staged: web, warmups" in m for m in r["logs"])
    assert len(r["calls"]) == 5                     # never a third attempt


@needs_node
def test_workflow_result_feeds_finish_which_names_the_missing_lane(tmp_path):
    """End to end over the no-model halves: args from the plan, the workflow, then finish's README."""
    doc = {"event": "b256", "day": "d29", "matrix": "/w/matrix",
           "lanes": [{"key": ln["key"], "agent": True, "reasons": ln["reasons"], "staged": ln["staged"]}
                     for ln in LANES] + [{"key": "binary", "agent": False, "reasons": ["gate green"], "staged": []}]}
    prof = event.parse({"slug": "b256", "name": "Example CTF 2027", "categories": ["Web"],
                        "dates": {"start": dt.date(2027, 1, 1), "end": dt.date(2027, 1, 9)},
                        "platform": {"kind": "manual"}, "flag": {"prefixes": ["ZZ"]},
                        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"}},
                       src="<test>")
    args = daily.workflow_args(prof, doc, repo="/r", out="/w/la/d29")
    assert wf.preflight(wf.get("day-lookahead"), args) == 6
    r = run(args, tmp_path, {"script-analysis": ["throw", "throw"]})
    assert r["ok"], r
    rep = daily.finish(doc, r["result"], tmp_path / "d29")
    assert rep.not_staged == ["script-analysis"] and rep.no_agent == ["binary"]
    text = rep.readme.read_text()
    assert "- script-analysis: NOT staged" in text and "2 of 3 agent lane(s) staged" in text
    assert set(forecast.load(rep.forecast).lanes) == {"web", "warmups"}


# ------------------------------------------------------------------------------- the B-194 guards


@needs_node
@pytest.mark.parametrize("missing", ["event", "repo", "out", "day", "matrix", "lanes"])
def test_a_missing_required_arg_fails_by_name_with_zero_agents(tmp_path, missing):
    r = run({k: v for k, v in ARGS.items() if k != missing}, tmp_path)
    assert not r["ok"] and f'"{missing}"' in r["error"] and r["calls"] == []


@needs_node
@pytest.mark.parametrize("lanes,msg", [
    ([], "non-empty array"),
    ([{"key": "web", "reasons": []}], "carries no plan reasons"),
    ([{"key": "Web", "reasons": ["r"]}], "no lane key of lower-case words"),
    ([{"key": "../x", "reasons": ["r"]}], "no lane key of lower-case words"),
    ([{"key": "web", "reasons": ["r"]}, {"key": "web", "reasons": ["r"]}], "duplicate lane key"),
])
def test_bad_lane_lists_fail_before_any_agent(tmp_path, lanes, msg):
    r = run({**ARGS, "lanes": lanes}, tmp_path)
    assert not r["ok"] and msg in r["error"] and r["calls"] == []


@needs_node
def test_the_cap_counts_the_retry_and_is_checked_before_any_agent(tmp_path):
    many = [{"key": f"l{i}", "reasons": ["r"]} for i in range(9)]
    r = run({**ARGS, "lanes": many}, tmp_path)
    assert not r["ok"] and "dry-run plans 18 agents" in r["error"] and r["calls"] == []
    r = run({**ARGS, "lanes": many[:8]}, tmp_path)
    assert r["ok"] and len(r["calls"]) == 8 and r["result"]["planned"] == 16
    r = run({**ARGS, "agentCap": 5}, tmp_path)
    assert not r["ok"] and "> cap 5" in r["error"] and r["calls"] == []
    r = run({**ARGS, "lanes": many, "agentCap": 100}, tmp_path)
    assert not r["ok"] and "> cap 16" in r["error"]


@needs_node
def test_each_brief_carries_only_its_own_lane_and_no_free_form_arg(tmp_path):
    r = run({**ARGS, "note": "QUESTION FOR THE PLAYER: is web down?"}, tmp_path)
    assert r["ok"]
    by = {c["label"]: c["prompt"] for c in r["calls"]}
    for ln in LANES:
        p = by[f"predict:{ln['key']}"]
        assert f"Your lane: {ln['key']}." in p
        assert all(reason in p for reason in ln["reasons"])
        for other in LANES:
            if other is ln:
                continue
            assert f"Your lane: {other['key']}" not in p
            assert not any(reason in p for reason in other["reasons"])
            assert not any(s in p for s in other["staged"])
        assert "QUESTION FOR THE PLAYER" not in p
    sa = by["predict:script-analysis"]
    assert "tagged-python-marker-joined, computed-raw" in sa and "Do not rewrite them" in sa
    assert "already staged" not in by["predict:web"]
    assert "/w/la/d29/predictions-web.md" in by["predict:web"]


@needs_node
def test_every_agent_call_is_schema_forced(tmp_path):
    r = run(ARGS, tmp_path, {"web": ["throw"]})
    assert r["calls"] and all(c["schema"] for c in r["calls"])
    for c in r["calls"]:
        assert set(c["schema"]["required"]) == {"lane", "file", "new", "gaps", "note", "specimens"}


# --------------------------------------------------------------- manifest and JS agree (pure Python)


def _const(src, name):
    m = re.search(rf"\b{name}\s*=\s*(\d+)", src)
    assert m, f"{name} not found in day-lookahead.js"
    return int(m.group(1))


def test_the_manifest_matches_the_js():
    src = JS.read_text()
    man = tomllib.loads(MANIFEST.read_text())
    w = wf.get("day-lookahead")
    assert w.max_agents == man["max_agents"] == _const(src, "HARD_AGENT_CAP")
    assert w.stages_per_lane == _const(src, "STAGES_PER_LANE")
    assert w.extra_agents == _const(src, "EXTRA_AGENTS")
    for key in w.required:
        assert re.search(rf"need\(args, '{re.escape(key)}'", src), key
    assert w.lane_arg == "lanes"


def test_the_workflow_ships_outside_dot_claude_and_is_listed():
    assert "day-lookahead" in wf.names()
    assert ".claude" not in JS.relative_to(ROOT).parts
