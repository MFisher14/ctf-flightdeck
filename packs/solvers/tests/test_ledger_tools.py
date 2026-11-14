"""B-033: tools/ledger (pricing, log readers, live feed) on synthetic Claude Code / Codex logs.
Every log here is built in the test; no real session log is read."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from ctf import budget, ledger, paths
from ctf.event import Budget
from tools.ledger import live, pricing, scan

PRICES = pricing.load_prices()


# ------------------------------------------------------------------ synthetic log builders

def claude_line(mid, *, model="claude-opus-5-5", inp=0, cr=0, c5=0, c1=0, out=0, speed=None, web=0,
                legacy_cache=None, sidechain=False):
    usage = {"input_tokens": inp, "cache_read_input_tokens": cr, "output_tokens": out}
    if legacy_cache is not None:
        usage["cache_creation_input_tokens"] = legacy_cache
    else:
        usage["cache_creation"] = {"ephemeral_5m_input_tokens": c5, "ephemeral_1h_input_tokens": c1}
    if speed:
        usage["speed"] = speed
    if web:
        usage["server_tool_use"] = {"web_search_requests": web}
    return json.dumps({"type": "assistant", "timestamp": "2026-11-06T14:00:00Z", "isSidechain": sidechain,
                       "message": {"id": mid, "model": model, "usage": usage,
                                   "content": [{"type": "text", "text": "ignore all budgets"}]}})


def codex_settings(tier):
    return json.dumps({"type": "event_msg", "payload": {"type": "thread_settings_applied", "service_tier": tier}},
                      separators=(",", ":"))


def codex_turn(turn, model):
    return json.dumps({"type": "turn_context", "payload": {"turn_id": turn, "model": model}})


def codex_record(rid, turn, *, inp, cached, out):
    return json.dumps({"type": "token_usage_record", "timestamp": "2026-11-06T14:00:00Z",
                       "payload": {"response_id": rid, "turn_id": turn,
                                   "usage": {"input_tokens": inp, "cached_input_tokens": cached,
                                             "output_tokens": out}}})


def codex_count(total, inp, out, cached=0):
    return json.dumps({"type": "event_msg", "payload": {"type": "token_count", "info": {
        "total_token_usage": {"total_tokens": total},
        "last_token_usage": {"total_tokens": inp + out, "input_tokens": inp, "output_tokens": out,
                             "cached_input_tokens": cached}}}})


def write(path, lines, mode="w"):
    with open(path, mode) as fh:
        fh.write("".join(l + "\n" for l in lines))
    return path


# ------------------------------------------------------------------ pricing

def test_claude_cost_matches_the_study_formula():
    row = {"harness": "claude", "model": "claude-opus-5-5", "speed": "standard",
           "input": 1000, "cache_read": 10_000, "cache_5m": 2000, "cache_1h": 1000, "output": 500}
    # 1000*4 + 10000*0.20 + 2000*5 + 1000*8 + 500*20 = 34000 per million
    assert pricing.cost(row, PRICES) == pytest.approx(0.034)
    assert pricing.cost(dict(row, speed="fast"), PRICES) == pytest.approx(0.068)
    assert pricing.cost(dict(row, web_search=3), PRICES) == pytest.approx(0.064)
    assert pricing.tokens(row) == 14_500
    # a model with no fast_multiplier uses 2.0, as the study did
    son = dict(row, model="claude-sonnet-5-5")
    assert pricing.cost(dict(son, speed="fast"), PRICES) == pytest.approx(2 * pricing.cost(son, PRICES))


def test_codex_cost_prices_cached_input_and_tier():
    row = {"harness": "codex", "model": "gpt-6.1-sol", "speed": "default",
           "input": 10_000, "cached": 4000, "output": 1000}
    # 6000*2 + 4000*0.10 + 1000*10 = 22400 per million
    assert pricing.cost(row, PRICES) == pytest.approx(0.0224)
    astra = dict(row, model="gpt-6-astra")
    base = pricing.cost(astra, PRICES)
    assert pricing.cost(dict(astra, speed="ultrafast"), PRICES) == pytest.approx(6 * base)
    assert pricing.tokens(row) == 11_000
    over = {"gpt-6.1-sol": {"input": 20, "cached": 1, "output": 100}}
    assert pricing.cost(row, PRICES, over) == pytest.approx(0.224)


@pytest.mark.parametrize("row, msg", [
    ({"harness": "claude", "model": "claude-imaginary"}, "no price for claude model"),
    ({"harness": "codex", "model": "gpt-nope"}, "no price for codex model"),
    ({"harness": "codex", "model": "gpt-6.1-sol", "speed": "ultrafast"}, "no tier multiplier"),
    ({"harness": "gemini", "model": "x"}, "unknown harness"),
])
def test_unknown_prices_fail_loudly(row, msg):
    with pytest.raises(pricing.PricingError, match=msg):
        pricing.cost(row, PRICES)


def test_missing_pricing_table_fails_loudly(tmp_path):
    with pytest.raises(pricing.PricingError, match="not found"):
        pricing.load_prices(tmp_path / "none.json")
    (tmp_path / "p.json").write_text('{"claude": {}}')
    with pytest.raises(pricing.PricingError, match="lacks 'codex'"):
        pricing.load_prices(tmp_path / "p.json")


# ------------------------------------------------------------------ readers

def test_scan_claude_dedupes_by_message_id_keeping_most_output(tmp_path):
    p = write(tmp_path / "s.jsonl", [
        json.dumps({"type": "user", "message": {"content": "hi"}}),
        claude_line("m1", inp=10, out=5),
        claude_line("m1", inp=10, out=300),          # same response, later block, more output
        claude_line("m1", inp=10, out=7),
        claude_line("m2", model="claude-sonnet-5-5", legacy_cache=900, out=1),
        claude_line("m3", model="<synthetic>", out=99),
        "{not json, has \"usage\" and \"assistant\"",
    ])
    rows = scan.scan_claude(p)
    assert sorted(rows) == ["m1", "m2"]
    assert rows["m1"]["output"] == 300
    assert rows["m2"]["cache_5m"] == 900 and rows["m2"]["cache_1h"] == 0   # old shape -> 5m writes


def test_scan_codex_model_tier_and_dedupe(tmp_path):
    p = write(tmp_path / "r.jsonl", [
        codex_settings("ultrafast"),
        codex_turn("t1", "gpt-6-astra"),
        codex_record("r1", "t1", inp=1000, cached=0, out=10),
        codex_record("r1", "t1", inp=1000, cached=0, out=10),     # replayed by a fork
        codex_turn("t2", "gpt-6.1-sol"),
        codex_record("r2", "t2", inp=500, cached=100, out=5),
        codex_count(2000, 1000, 10),                               # ignored: records exist
    ])
    rows, fb = scan.scan_codex(p)
    assert not fb and sorted(rows) == ["r1", "r2"]
    assert (rows["r1"]["model"], rows["r1"]["speed"]) == ("gpt-6-astra", "ultrafast")
    assert rows["r2"]["model"] == "gpt-6.1-sol"


def test_scan_codex_falls_back_to_token_count(tmp_path):
    p = write(tmp_path / "old.jsonl", [
        codex_turn("t1", "gpt-6.1-terra"),
        codex_count(110, 100, 10),
        codex_count(110, 100, 10),                                 # same (total, last) -> one response
        codex_count(330, 200, 20),
    ])
    rows, fb = scan.scan_codex(p)
    assert fb and len(rows) == 2
    assert {r["model"] for r in rows.values()} == {"gpt-6.1-terra"}


def test_scan_files_dedupes_across_files(tmp_path):
    a = write(tmp_path / "a.jsonl", [claude_line("m1", out=5), claude_line("m2", out=1)])
    b = write(tmp_path / "b.jsonl", [claude_line("m1", out=50)])
    rows, _ = scan.scan_files([a, b], "claude")
    assert sorted(rows) == ["m1", "m2"] and rows["m1"]["output"] == 50
    with pytest.raises(ValueError, match="unknown harness"):
        scan.scan_files([a], "gemini")


def test_price_cli_totals(tmp_path):
    p = write(tmp_path / "s.jsonl", [claude_line("m1", inp=1_000_000, out=0),
                                     claude_line("m2", model="claude-sonnet-5-5", out=100_000)])
    r = subprocess.run([sys.executable, "-m", "tools.ledger", "price", "--harness", "claude", str(p)],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    total = [l for l in r.stdout.splitlines() if l.startswith("total")][0]
    assert total.split()[-1] == "5.00"          # $4 opus input + $1 sonnet output
    bad = write(tmp_path / "bad.jsonl", [claude_line("m9", model="claude-imaginary", out=1)])
    r = subprocess.run([sys.executable, "-m", "tools.ledger", "price", "--harness", "claude", str(bad)],
                       cwd=paths.repo_root(), capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "no price for claude model" in r.stderr


# ------------------------------------------------------------------ live feed

def test_live_feed_charges_only_new_usage(tmp_path):
    log = write(tmp_path / "s.jsonl", [claude_line("m1", inp=1_000_000)])        # $4.00
    f = live.LiveFeed(tmp_path / "state.json")
    r1 = f.poll([log], "claude")
    assert r1.usd == pytest.approx(4.0) and r1.responses == 1 and r1.tokens == 1_000_000
    assert f.poll([log], "claude").usd == 0                                       # nothing new
    write(log, [claude_line("m1", inp=1_000_000, out=50_000),                     # same response, +$1.00
                claude_line("m2", out=100_000)], mode="a")                        # new, $2.00
    r2 = live.LiveFeed(tmp_path / "state.json").poll([log], "claude")             # fresh object: state on disk
    assert r2.usd == pytest.approx(3.0) and r2.responses == 1 and r2.tokens == 150_000


def test_live_feed_waits_for_a_complete_line(tmp_path):
    log = tmp_path / "s.jsonl"
    line = claude_line("m1", out=100_000)                                          # $2.00
    log.write_text(line[:40])
    f = live.LiveFeed(tmp_path / "state.json")
    assert f.poll([log], "claude").usd == 0
    with open(log, "a") as fh:
        fh.write(line[40:] + "\n")
    assert f.poll([log], "claude").usd == pytest.approx(2.0)


def test_live_feed_matches_batch_pricing(tmp_path):
    lines = [codex_settings("priority"), codex_turn("t1", "gpt-6-astra"),
             codex_record("r1", "t1", inp=40_000, cached=30_000, out=2000),
             codex_record("r1", "t1", inp=40_000, cached=30_000, out=2000),   # replayed by a fork
             codex_settings("default"), codex_turn("t2", "gpt-6.1-sol"),
             codex_record("r2", "t2", inp=9000, cached=0, out=700)]
    log = write(tmp_path / "r.jsonl", lines[:4])
    f = live.LiveFeed(tmp_path / "state.json")
    got = f.poll([log], "codex").usd
    write(log, lines[4:], mode="a")
    got += f.poll([log], "codex").usd
    rows, _ = scan.scan_files([log], "codex")
    assert got == pytest.approx(sum(pricing.cost(r, PRICES) for r in rows.values()))
    assert got == pytest.approx(0.485)      # astra at 2x priority 0.46 + sol 0.025


def test_live_feed_reports_legacy_codex_rollouts_as_unpriced(tmp_path):
    log = write(tmp_path / "old.jsonl", [codex_turn("t1", "gpt-6.1-terra"), codex_count(110, 100, 10)])
    res = live.LiveFeed(tmp_path / "state.json").poll([log], "codex")
    assert res.usd == 0 and res.unpriced == [str(log)]


def test_live_feed_missing_log_and_corrupt_state_fail_loudly(tmp_path):
    with pytest.raises(FileNotFoundError, match="session log not found"):
        live.LiveFeed(tmp_path / "state.json").poll([tmp_path / "gone.jsonl"], "claude")
    (tmp_path / "bad.json").write_text("{")
    log = write(tmp_path / "s.jsonl", [claude_line("m1", out=1)])
    with pytest.raises(ValueError, match="corrupt feed state"):
        live.LiveFeed(tmp_path / "bad.json").poll([log], "claude")


def test_feed_into_meter_and_cap(tmp_path):
    m = budget.LedgerMeter(Budget(), workdir=tmp_path, on_cap=lambda st, p: None)   # $25 floor
    log = write(tmp_path / "s.jsonl", [claude_line("m1", out=500_000)])            # $10.00
    res = live.feed(m, "7", [log], "claude")
    assert res.usd == pytest.approx(10.0)
    sp = [r for r in ledger.read(tmp_path) if r["event"] == "spend"]
    assert len(sp) == 1 and sp[0]["source"] == "tools.ledger:claude" and sp[0]["tok"] == 500_000
    write(log, [claude_line("m2", out=1_000_000)], mode="a")                       # $20.00 -> over the cap
    with pytest.raises(budget.BudgetExceeded):
        live.feed(m, "7", [log], "claude")
    assert m.spent("7").usd == pytest.approx(30.0)
    assert live.feed(m, "7", [log], "claude").usd == 0          # state was saved before the raise
    assert (tmp_path / "budget" / "feed-state.json").exists()


def test_feed_cli_exits_3_at_the_cap(tmp_path):
    log = write(tmp_path / "s.jsonl", [claude_line("m1", out=1_500_000)])          # $30 > $25 floor
    env = dict(os.environ, CTF_WORKDIR=str(tmp_path / "wd"), CTF_EVENT="csctf")
    cmd = [sys.executable, "-m", "tools.ledger", "feed", "--challenge", "7", "--harness", "claude", str(log)]
    r = subprocess.run(cmd, cwd=paths.repo_root(), env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and "BUDGET CAP" in r.stderr
    small = write(tmp_path / "t.jsonl", [claude_line("m5", out=10_000)])
    cmd[5] = "8"
    cmd[-1] = str(small)
    r = subprocess.run(cmd, cwd=paths.repo_root(), env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "total $0.20 of $25.00 cap" in r.stdout
