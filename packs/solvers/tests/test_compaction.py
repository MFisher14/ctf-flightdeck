"""B-032: compaction thresholds (ctf/compaction.py, `ctf compaction`, the launch wiring, the doctor check).

Every session log here is synthetic JSONL written by the test; every harness binary is a stub file
(searched for a marker, never run) or a tiny shell script that records its argv and environment.
Nothing starts a real Claude or Codex session.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import compaction as C
from ctf import doctor, fence, fence_launch, paths

PY = sys.executable
REPO = paths.repo_root()
# Variables a test environment must not inherit from the operator's shell.
_SCRUB = ("CTF_COMPACT_", "CLAUDE_CODE_AUTO_COMPACT_WINDOW", "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE",
          "DISABLE_AUTO_COMPACT", "DISABLE_COMPACT", "CODEX_", "CLAUDE_BIN", "CTF_EVENT", "CTF_OPENER")


def clean_env(**kw) -> dict[str, str]:
    e = {k: v for k, v in os.environ.items() if not k.startswith(_SCRUB)}
    e.update(kw)
    return e


# ------------------------------------------------------------------------------------ thresholds

def test_defaults_are_claude_200k_and_codex_150k():
    assert C.threshold("claude", {}) == 200_000
    assert C.threshold("codex", {}) == 150_000


@pytest.mark.parametrize("raw,want", [("250000", 250_000), ("250k", 250_000), ("250K", 250_000),
                                      ("1m", 1_000_000), (" 120k ", 120_000), ("1.5m", None)])
def test_override_parses_token_counts(raw, want):
    if want is None:      # 1.5m is out of Claude's bounds
        with pytest.raises(C.CompactionError, match="outside"):
            C.threshold("claude", {"CTF_COMPACT_CLAUDE": raw})
        return
    assert C.threshold("claude", {"CTF_COMPACT_CLAUDE": raw}) == want


def test_off_means_no_threshold_per_harness():
    e = {"CTF_COMPACT_CODEX": "off"}
    assert C.threshold("codex", e) is None and C.threshold("claude", e) == 200_000
    assert C.threshold("claude", {"CTF_COMPACT_CLAUDE": "OFF"}) is None


@pytest.mark.parametrize("raw", ["lots", "200kb", "-5", "2e5", "0.5k1", "true", "100.5", "100000.5",
                                 "150000.25", "0.0005m"])
def test_unusable_values_fail_loudly(raw):
    with pytest.raises(C.CompactionError, match="CTF_COMPACT_CODEX"):
        C.threshold("codex", {"CTF_COMPACT_CODEX": raw})


@pytest.mark.parametrize("raw", ["200000.5", "150000.25", "100000.5"])
def test_fractional_token_counts_are_refused_not_truncated(raw):
    # In bounds once truncated, so only the whole-number check stands between them and a threshold.
    with pytest.raises(C.CompactionError, match="whole number"):
        C.parse_tokens(raw, name="X")
    with pytest.raises(C.CompactionError, match="whole number"):
        C.threshold("claude", {"CTF_COMPACT_CLAUDE": raw})
    assert C.parse_tokens("200.5k", name="X") == 200_500     # a fraction that lands whole is fine


@pytest.mark.parametrize("harness,raw", [("claude", "99999"), ("claude", "1000001"), ("codex", "49999"),
                                         ("codex", "2m")])
def test_bounds_are_enforced(harness, raw):
    with pytest.raises(C.CompactionError, match="outside"):
        C.threshold(harness, {C.ENV_VARS[harness]: raw})


@pytest.mark.parametrize("harness,raw", [("claude", "100000"), ("claude", "1000000"), ("codex", "50000")])
def test_bounds_are_inclusive(harness, raw):
    assert C.threshold(harness, {C.ENV_VARS[harness]: raw}) == int(raw)


def test_unknown_harness_is_refused():
    with pytest.raises(C.CompactionError, match="unknown harness"):
        C.threshold("gemini", {})


# --------------------------------------------------------------------------- launch settings

def test_claude_env_settings_and_codex_args_carry_the_thresholds():
    assert C.claude_env({}) == {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"}
    assert C.claude_settings({}) == {"autoCompactWindow": 200_000}
    assert C.codex_config_args({}) == ["-c", "model_auto_compact_token_limit=150000"]
    e = {"CTF_COMPACT_CLAUDE": "300k", "CTF_COMPACT_CODEX": "120k"}
    assert C.claude_env(e) == {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "300000"}
    assert C.codex_config_args(e) == ["-c", "model_auto_compact_token_limit=120000"]


def test_off_passes_nothing():
    e = {"CTF_COMPACT_CLAUDE": "off", "CTF_COMPACT_CODEX": "off", "DISABLE_AUTO_COMPACT": "1"}
    assert C.claude_env(e) == {} and C.claude_settings(e) == {} and C.codex_config_args(e) == []


@pytest.mark.parametrize("var,val,why", [
    ("DISABLE_AUTO_COMPACT", "1", "DISABLE_AUTO_COMPACT is set"),
    ("DISABLE_COMPACT", "true", "DISABLE_COMPACT is set"),
    ("CLAUDE_AUTOCOMPACT_PCT_OVERRIDE", "50", "lowers the threshold"),
    ("CLAUDE_CODE_AUTO_COMPACT_WINDOW", "500000", "differs from the threshold 200000"),
    ("CLAUDE_CODE_AUTO_COMPACT_WINDOW", "garbage", "differs from the threshold"),
])
def test_claude_env_refuses_a_conflicting_setting(var, val, why):
    with pytest.raises(C.CompactionError, match=why):
        C.claude_env({var: val})


@pytest.mark.parametrize("extra", [{"DISABLE_AUTO_COMPACT": "0"}, {"DISABLE_COMPACT": "false"},
                                   {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200k"},
                                   {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"}])
def test_claude_env_accepts_harmless_settings(extra):
    assert C.claude_env(extra) == {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"}


def _fence(tmp_path):
    home, ws, repo = (tmp_path / "home" / "p", tmp_path / "work" / "e", tmp_path / "src" / "r")
    for d in (home, ws, repo):
        d.mkdir(parents=True)
    return fence.build(home=home.resolve(), workspace=ws.resolve(), repo=repo.resolve(), user_dir=None)


def _cval(argv: list[str], key: str) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-c" and argv[i + 1].startswith(key + "=")]


def test_codex_argv_sets_the_threshold(tmp_path, monkeypatch):
    for v in [k for k in os.environ if k.startswith("CTF_COMPACT_")]:
        monkeypatch.delenv(v)
    a = fence_launch.codex_argv(_fence(tmp_path), model="m", prompt="go")
    assert _cval(a, "model_auto_compact_token_limit") == ["model_auto_compact_token_limit=150000"]
    assert a[-1] == "go"
    monkeypatch.setenv("CTF_COMPACT_CODEX", "100k")
    a = fence_launch.codex_argv(_fence(tmp_path / "2"), prompt="go")
    assert _cval(a, "model_auto_compact_token_limit") == ["model_auto_compact_token_limit=100000"]
    monkeypatch.setenv("CTF_COMPACT_CODEX", "off")
    assert _cval(fence_launch.codex_argv(_fence(tmp_path / "3"), prompt="go"),
                 "model_auto_compact_token_limit") == []
    monkeypatch.setenv("CTF_COMPACT_CODEX", "nope")
    with pytest.raises(fence_launch.LaunchError, match="CTF_COMPACT_CODEX"):
        fence_launch.codex_argv(_fence(tmp_path / "4"), prompt="go")


@pytest.mark.parametrize("extra", [["-c", "model_auto_compact_token_limit=900000"],
                                   ["--config=model_auto_compact_token_limit=900000"],
                                   ["-cmodel_auto_compact_token_limit=1"]])
def test_codex_passthrough_cannot_move_the_threshold(tmp_path, extra):
    with pytest.raises(fence_launch.LaunchError, match="compaction"):
        fence_launch.codex_argv(_fence(tmp_path), extra=extra, prompt="x")


# ------------------------------------------------------------------------------- the launchers

def _exe(path: Path, body: str) -> Path:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _claude_launch(tmp_path, *args, **env):
    e = clean_env(CTF_WORKDIR=str(tmp_path / "ws"), **env)
    return subprocess.run([PY, str(REPO / "tools" / "claude_launch"), *args], capture_output=True,
                          text=True, env=e, timeout=60)


def test_claude_launch_dry_run_shows_the_window(tmp_path):
    r = _claude_launch(tmp_path, "--dry-run")
    assert r.returncode == 0, r.stderr
    w = (tmp_path / "ws").resolve()
    # B-118's prompt-cache TTL variables follow the window (tests/test_cache_ttl.py covers them).
    assert r.stdout.startswith(f"cd {w} && CLAUDE_CODE_AUTO_COMPACT_WINDOW=200000 CLAUDE_CODE_PROMPT_CACHE_TTL=")
    r = _claude_launch(tmp_path, "--dry-run", CTF_COMPACT_CLAUDE="off")
    assert r.returncode == 0 and r.stdout.startswith(f"cd {w} && CLAUDE_CODE_PROMPT_CACHE_TTL="), r.stdout
    assert "AUTO_COMPACT_WINDOW" not in r.stdout


def test_claude_launch_starts_the_agent_with_the_window(tmp_path):
    rec = tmp_path / "env.txt"
    stub = _exe(tmp_path / "claude", f'echo "W=${{CLAUDE_CODE_AUTO_COMPACT_WINDOW:-unset}}" > "{rec}"\n')
    r = _claude_launch(tmp_path, "--claude-bin", str(stub), CTF_COMPACT_CLAUDE="350k")
    assert r.returncode == 0, r.stderr
    assert rec.read_text().strip() == "W=350000"


def test_claude_launch_refuses_a_conflicting_setting(tmp_path):
    rec = tmp_path / "ran.txt"
    stub = _exe(tmp_path / "claude", f'touch "{rec}"\n')
    r = _claude_launch(tmp_path, "--claude-bin", str(stub), DISABLE_AUTO_COMPACT="1")
    assert r.returncode == 2 and "DISABLE_AUTO_COMPACT" in r.stderr
    assert not rec.exists()


def _fake_codex(tmp_path: Path) -> Path:
    body = f'''
{{ printf '%s\\n' "$@"; echo @@END@@; }} >> "{tmp_path}/codex_calls.txt"
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then echo "PREFLIGHT_OK done" > "$2"; shift 2; else shift; fi
done
'''
    return _exe(tmp_path / "codex", body)


def _codex_calls(tmp_path: Path) -> list[list[str]]:
    p = tmp_path / "codex_calls.txt"
    return [c.splitlines() for c in p.read_text().split("@@END@@\n") if c.strip()] if p.exists() else []


def _preflight(tmp_path, **env):
    e = clean_env(CODEX_BIN=str(tmp_path / "codex"), CODEX_PREFLIGHT_DIR=str(tmp_path / "pf"),
                  TMPDIR=str(tmp_path), **env)
    return subprocess.run(["bash", str(REPO / "tools" / "codex_handoff.sh"), "--preflight"],
                          capture_output=True, text=True, env=e, timeout=60)


@pytest.mark.needs_tool("bash", "perl", "shasum")
@pytest.mark.parametrize("env,want", [({}, ["model_auto_compact_token_limit=150000"]),
                                      ({"CTF_COMPACT_CODEX": "200k"}, ["model_auto_compact_token_limit=200000"]),
                                      ({"CTF_COMPACT_CODEX": "off"}, [])])
def test_codex_handoff_passes_the_threshold(tmp_path, env, want):
    _fake_codex(tmp_path)
    r = _preflight(tmp_path, **env)
    assert r.returncode == 0, r.stderr
    (call,) = _codex_calls(tmp_path)
    assert _cval(call, "model_auto_compact_token_limit") == want


@pytest.mark.needs_tool("bash")
def test_codex_handoff_dies_on_a_bad_threshold_before_any_call(tmp_path):
    _fake_codex(tmp_path)
    r = _preflight(tmp_path, CTF_COMPACT_CODEX="huge")
    assert r.returncode == 2
    assert "CTF_COMPACT_CODEX='huge'" in r.stderr and "no compaction threshold" in r.stderr
    assert _codex_calls(tmp_path) == []


def _opener(tmp_path, **env):
    rec = tmp_path / "claude_rec.txt"
    _exe(tmp_path / "claude", f'{{ echo "W=${{CLAUDE_CODE_AUTO_COMPACT_WINDOW:-unset}}"; printf "%s\\n" "$@"; }} '
                              f'> "{rec}"\necho "session backgrounded: id abc"\n')
    _exe(tmp_path / "docker", "exit 0\n")
    prompt = tmp_path / "prompt.md"
    prompt.write_text("run the wave")
    conf = tmp_path / "opener.conf"
    conf.write_text(f"EVENT_NAME=Test Event\nWINDOW_START=20261106\nWINDOW_END=20261109\n"
                    f"PROMPT_FILE={prompt}\nREPO={tmp_path}\nLOG_DIR={tmp_path / 'logs'}\nDOCKER_WAIT=0\n")
    e = clean_env(CLAUDE_BIN=str(tmp_path / "claude"), DOCKER_BIN=str(tmp_path / "docker"),
                  CTF_OPENER_TODAY="20261107", CTF_OPENER_NOTIFY="0", CTF_OPENER_START_DOCKER="0", **env)
    r = subprocess.run(["bash", str(REPO / "tools" / "pink_launch.sh"), str(conf)], capture_output=True,
                       text=True, env=e, timeout=60)
    log = (tmp_path / "logs" / "opener.log")
    return r, (rec.read_text().splitlines() if rec.exists() else None), (log.read_text() if log.exists() else "")


@pytest.mark.needs_tool("bash")
def test_opener_starts_the_wave_session_with_the_window(tmp_path):
    r, rec, log = _opener(tmp_path)
    assert r.returncode == 0, log
    assert rec[0] == "W=200000"
    args = rec[1:]
    assert args[:2] == ["--bg", "--remote-control"] and args[-1] == "run the wave"
    assert json.loads(args[args.index("--settings") + 1]) == {"autoCompactWindow": 200000}


@pytest.mark.needs_tool("bash")
def test_opener_off_passes_neither(tmp_path):
    r, rec, log = _opener(tmp_path, CTF_COMPACT_CLAUDE="off")
    assert r.returncode == 0, log
    assert rec[0] == "W=unset" and "--settings" not in rec


@pytest.mark.needs_tool("bash")
def test_opener_fails_on_a_conflicting_setting_without_starting_claude(tmp_path):
    r, rec, log = _opener(tmp_path, CLAUDE_AUTOCOMPACT_PCT_OVERRIDE="40")
    assert r.returncode != 0 and rec is None
    assert "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE" in log and "compaction threshold" in log


# ------------------------------------------------------------------------------- session logs

def _claude_line(mid, ctx, *, out=10, sidechain=False, model="claude-opus-5-5", split=(0.0, 0.1)):
    """An assistant line whose context (input + cache writes + cache reads) is exactly `ctx`."""
    inp, cw = int(ctx * split[0]) or 3, int(ctx * split[1])
    usage = {"input_tokens": inp, "cache_creation_input_tokens": cw,
             "cache_read_input_tokens": ctx - inp - cw, "output_tokens": out}
    return json.dumps({"type": "assistant", "isSidechain": sidechain, "sessionId": "s",
                       "timestamp": "2026-11-07T10:00:00Z",
                       "message": {"id": mid, "model": model, "role": "assistant", "usage": usage}})


def _boundary(pre=None, trigger="auto"):
    meta = {"trigger": trigger}
    if pre is not None:
        meta["preTokens"] = pre
    return json.dumps({"type": "system", "subtype": "compact_boundary", "sessionId": "s",
                       "timestamp": "2026-11-07T11:00:00Z", "compactMetadata": meta})


def _write(tmp_path, name, lines):
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n")
    return p


def test_claude_audit_measures_context_dedupes_and_skips_sidechains(tmp_path):
    lines = [
        json.dumps({"type": "user", "sessionId": "s", "message": {"role": "user", "content": "go"}}),
        _claude_line("m1", 50_000),
        _claude_line("m1", 50_000, out=400),               # same response, another content block
        _claude_line("m2", 150_000),
        _claude_line("sc", 900_000, sidechain=True),      # a subagent's line: not the main thread
        _claude_line("syn", 900_000, model="<synthetic>"),
        _claude_line("m3", 215_000),                      # over 200K but within the 10% tolerance
        _claude_line("m4", 260_000),                      # over the tolerance
        _boundary(255_000),
        _claude_line("m5", 40_000),
        "not json",
    ]
    a = C.audit(_write(tmp_path, "t.jsonl", lines), environ={})
    assert (a.harness, a.threshold, a.responses, a.peak) == ("claude", 200_000, 5, 260_000)
    assert a.mean == pytest.approx((50_000 + 150_000 + 215_000 + 260_000 + 40_000) / 5)
    assert a.over == 1 and not a.held
    assert a.excess_tokens == 15_000 + 60_000
    assert [(c.index, c.trigger, c.pre_tokens) for c in a.compactions] == [(4, "auto", 255_000)]
    assert a.fired_at == [255_000]
    assert "EXCEEDED (1 responses over)" in a.line() and "auto-compacted at 255,000" in a.line()


def test_claude_context_counts_nested_cache_writes(tmp_path):
    usage = {"input_tokens": 5, "cache_read_input_tokens": 100_000, "output_tokens": 1,
             "cache_creation": {"ephemeral_5m_input_tokens": 7, "ephemeral_1h_input_tokens": 11}}
    line = json.dumps({"type": "assistant", "sessionId": "s",
                       "message": {"id": "x", "model": "claude-opus-5-5", "usage": usage}})
    a = C.audit(_write(tmp_path, "t.jsonl", [line]), environ={})
    assert a.peak == 100_023


def test_claude_audit_held_and_tolerance_and_limit(tmp_path):
    p = _write(tmp_path, "t.jsonl", [_claude_line("a", 120_000), _claude_line("b", 215_000),
                                     _boundary(215_000), _claude_line("c", 30_000)])
    a = C.audit(p, environ={})
    assert a.held and a.over == 0 and a.excess_tokens == 15_000
    assert not C.audit(p, environ={}, tolerance=0.0).held
    tight = C.audit(p, environ={}, limit=100_000)
    assert tight.threshold == 100_000 and tight.over == 2
    off = C.audit(p, environ={"CTF_COMPACT_CLAUDE": "off"})
    assert off.threshold is None and not off.held and off.over == 0 and "THRESHOLD OFF" in off.line()
    with pytest.raises(C.CompactionError, match="tolerance"):
        C.audit(p, environ={}, tolerance=-0.1)


def test_manual_compactions_are_not_calibration(tmp_path):
    p = _write(tmp_path, "t.jsonl", [_claude_line("a", 90_000), _boundary(90_000, trigger="manual"),
                                     _claude_line("b", 195_000), _boundary(196_000),
                                     _claude_line("c", 10_000)])
    a = C.audit(p, environ={})
    assert [(c.trigger, c.pre_tokens) for c in a.compactions] == [("manual", 90_000), ("auto", 196_000)]
    assert a.fired_at == [196_000]
    assert a.to_dict()["fired_at"] == [196_000]
    assert "auto-compacted at 196,000..196,000" in a.line()


def test_claude_boundary_without_pre_tokens_uses_the_last_response(tmp_path):
    p = _write(tmp_path, "t.jsonl", [_claude_line("a", 190_000), _boundary(None), _claude_line("b", 20_000)])
    (c,) = C.audit(p, environ={}).compactions
    assert c.pre_tokens == 190_000 and c.index == 1


def _codex_record(rid, inp, cached=0):
    return json.dumps({"timestamp": "t", "type": "event_msg", "payload": {
        "type": "token_usage_record", "response_id": rid, "turn_id": "u",
        "usage": {"input_tokens": inp, "cached_input_tokens": cached, "output_tokens": 50}}})


def _codex_count(inp, total):
    return json.dumps({"timestamp": "t", "type": "event_msg", "payload": {"type": "token_count", "info": {
        "last_token_usage": {"input_tokens": inp, "cached_input_tokens": 0, "output_tokens": 9,
                             "total_tokens": inp + 9},
        "total_token_usage": {"total_tokens": total}}}})


_META = json.dumps({"timestamp": "t", "type": "session_meta", "payload": {"id": "x"}})
_COMPACTED = json.dumps({"timestamp": "t", "type": "compacted", "payload": {"message": ""}})
_COMPACTED_EVT = json.dumps({"timestamp": "t", "type": "event_msg", "payload": {"type": "context_compacted"}})


def test_codex_audit_reads_records_dedupes_and_counts_one_compaction(tmp_path):
    lines = [_META, _codex_count(1, 1), _codex_record("r1", 80_000, 70_000), _codex_record("r1", 80_000),
             _codex_count(2, 2), _codex_record("r2", 170_000), _COMPACTED, _COMPACTED_EVT,
             _codex_record("r3", 30_000)]
    a = C.audit(_write(tmp_path, "rollout.jsonl", lines), environ={})
    assert (a.harness, a.threshold, a.responses, a.peak, a.over) == ("codex", 150_000, 3, 170_000, 1)
    assert a.excess_tokens == 20_000
    assert [(c.index, c.pre_tokens) for c in a.compactions] == [(2, 170_000)]


def test_codex_audit_falls_back_to_token_count_and_compaction_events(tmp_path):
    lines = [_META, _codex_count(100_000, 100_009), _codex_count(100_000, 100_009),   # replayed line
             _codex_count(140_000, 240_018), _COMPACTED_EVT, _codex_count(20_000, 260_027)]
    a = C.audit(_write(tmp_path, "rollout.jsonl", lines), environ={})
    assert a.responses == 3 and a.peak == 140_000 and a.held
    assert [(c.index, c.pre_tokens) for c in a.compactions] == [(2, 140_000)]


def test_codex_compaction_before_any_response_has_no_pre_tokens(tmp_path):
    lines = [_META, _COMPACTED, _codex_record("r1", 40_000), _codex_record("r2", 60_000)]
    a = C.audit(_write(tmp_path, "rollout.jsonl", lines), environ={})
    assert [(c.index, c.pre_tokens) for c in a.compactions] == [(0, None)]
    assert a.fired_at == []
    lines = [_META, _COMPACTED_EVT, _codex_count(30_000, 30_009)]           # the fallback series
    b = C.audit(_write(tmp_path, "rollout2.jsonl", lines), environ={})
    assert [(c.index, c.pre_tokens) for c in b.compactions] == [(0, None)]


def test_detect_harness_looks_past_unrecognised_leading_lines(tmp_path):
    junk = [json.dumps({"type": "file-history-snapshot", "n": i}) for i in range(49)]
    assert C.detect_harness(_write(tmp_path, "a.jsonl", junk + [_claude_line("m", 5)])) == "claude"
    assert C.detect_harness(_write(tmp_path, "b.jsonl", ["{}", "not json", _META])) == "codex"
    # the default reads 50 lines, no more: a log that only identifies itself on line 51 needs --harness
    with pytest.raises(C.CompactionError, match="neither"):
        C.detect_harness(_write(tmp_path, "c.jsonl", junk + ["{}", _claude_line("m", 5)]))
    assert C.detect_harness(_write(tmp_path, "d.jsonl", ["{}", _META]), lines=2) == "codex"


def test_detect_harness_and_unreadable_logs(tmp_path):
    assert C.detect_harness(_write(tmp_path, "a.jsonl", [_META])) == "codex"
    assert C.detect_harness(_write(tmp_path, "b.jsonl", [_claude_line("m", 5)])) == "claude"
    with pytest.raises(C.CompactionError, match="neither"):
        C.detect_harness(_write(tmp_path, "c.jsonl", ['{"hello": 1}', "[]"]))
    with pytest.raises(C.CompactionError, match="cannot read"):
        C.audit(tmp_path / "missing.jsonl", "claude")
    with pytest.raises(C.CompactionError, match="no claude usage records"):
        C.audit(_write(tmp_path, "d.jsonl", [_boundary(5)]), "claude")
    # --harness overrides detection: a Claude transcript read as Codex has no Codex usage
    with pytest.raises(C.CompactionError, match="no codex usage records"):
        C.audit(_write(tmp_path, "e.jsonl", [_claude_line("m", 5)]), "codex")


def test_check_reads_the_latest_context(tmp_path):
    p = _write(tmp_path, "t.jsonl", [_claude_line("a", 250_000), _boundary(250_000), _claude_line("b", 60_000)])
    r = C.check(p, environ={})
    assert (r.context, r.threshold, r.over) == (60_000, 200_000, False)
    assert C.check(p, environ={}, limit=60_000).over          # at the threshold counts as reached
    assert not C.check(p, environ={}, limit=60_001).over
    with pytest.raises(C.CompactionError, match="threshold is off"):
        C.check(p, environ={"CTF_COMPACT_CLAUDE": "off"})
    q = _write(tmp_path, "u.jsonl", [_claude_line("a", 250_000), _boundary(250_000)])
    with pytest.raises(C.CompactionError, match="compacted after its last response"):
        C.check(q, environ={})


# ------------------------------------------------------------------------------------ the CLI

def ctf(*args, **env):
    return subprocess.run([PY, "-m", "ctf", "compaction", *args], cwd=REPO, env=clean_env(**env),
                          capture_output=True, text=True, timeout=60)


def test_cli_check_exit_codes(tmp_path):
    p = _write(tmp_path, "t.jsonl", [_claude_line("a", 120_000), _claude_line("b", 205_000)])
    r = ctf("check", str(p))
    assert r.returncode == 3 and "205,000 of 200,000" in r.stdout and "AT THRESHOLD" in r.stdout
    r = ctf("check", str(p), "--limit", "300k")
    assert r.returncode == 0 and "under" in r.stdout
    r = ctf("check", str(p), CTF_COMPACT_CLAUDE="250k")
    assert r.returncode == 0
    r = ctf("check", str(tmp_path / "nope.jsonl"), "--harness", "claude")
    assert r.returncode == 2 and "cannot read" in r.stderr
    r = ctf("check", str(p), "--limit", "off")
    assert r.returncode == 2 and "--limit" in r.stderr


def test_cli_audit_exit_codes_and_json(tmp_path):
    good = _write(tmp_path, "good.jsonl", [_claude_line("a", 120_000), _boundary(198_000), _claude_line("b", 9_000)])
    bad = _write(tmp_path, "bad.jsonl", [_META, _codex_record("r", 400_000)])
    r = ctf("audit", str(good))
    assert r.returncode == 0 and r.stdout.startswith("HELD") and "1 compactions" in r.stdout
    r = ctf("audit", str(good), str(bad), "--json")
    assert r.returncode == 1
    docs = [json.loads(x) for x in r.stdout.splitlines()]
    assert [(d["harness"], d["held"], d["peak"]) for d in docs] == [("claude", True, 120_000),
                                                                      ("codex", False, 400_000)]
    assert docs[0]["fired_at"] == [198_000] and docs[1]["excess_tokens"] == 250_000
    r = ctf("audit", str(good), CTF_COMPACT_CLAUDE="off")
    assert r.returncode == 1 and "THRESHOLD OFF" in r.stdout
    r = ctf("audit", str(good), CTF_COMPACT_CLAUDE="tiny")
    assert r.returncode == 2 and "CTF_COMPACT_CLAUDE" in r.stderr


def test_cli_show(tmp_path):
    r = ctf("show", "--json", CTF_COMPACT_CODEX="off")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc == {"thresholds": {"claude": 200_000, "codex": None},
                   "claude_env": {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"},
                   "claude_settings": {"autoCompactWindow": 200_000}, "codex_args": []}
    r = ctf("show", CTF_COMPACT_CLAUDE="300k")
    assert r.returncode == 0 and "300,000 tokens  (CTF_COMPACT_CLAUDE)" in r.stdout
    r = ctf("show", DISABLE_COMPACT="1")
    assert r.returncode == 2 and "DISABLE_COMPACT" in r.stderr


def test_shell_interface_exit_codes():
    def mod(arg, **env):
        return subprocess.run([PY, "-m", "ctf.compaction", arg], cwd=REPO, env=clean_env(**env),
                              capture_output=True, text=True, timeout=60)
    assert mod("codex-config").stdout.strip() == "model_auto_compact_token_limit=150000"
    assert mod("claude-env").stdout.strip() == "CLAUDE_CODE_AUTO_COMPACT_WINDOW=200000"
    assert mod("claude-settings").stdout.strip() == '{"autoCompactWindow":200000}'
    off = mod("claude-env", CTF_COMPACT_CLAUDE="off")
    assert off.returncode == 0 and off.stdout == ""
    bad = mod("claude-env", DISABLE_AUTO_COMPACT="yes")
    assert bad.returncode == 2 and bad.stdout == "" and "DISABLE_AUTO_COMPACT" in bad.stderr
    assert mod("bogus").returncode == 2


# ----------------------------------------------------------------------------- doctor check

def _bin(tmp_path, name, marker: bytes | None, *, script=False, pad=0):
    p = tmp_path / "bin" / name
    p.parent.mkdir(exist_ok=True)
    head = b"#!/bin/sh\n" if script else b"\xcf\xfa\xed\xfe"      # a shim, or a Mach-O-looking build
    p.write_bytes(head + b"\0" * pad + (marker or b"nothing here") + b"\0" * 64)
    return p


def _doc_env(tmp_path, *, claude=b"CLAUDE_CODE_AUTO_COMPACT_WINDOW", codex=b"model_auto_compact_token_limit",
             config: str | None = "model_auto_compact_token_limit = 150000\n", **kw):
    home = tmp_path / "codex-home"
    home.mkdir(exist_ok=True)
    if config is not None:
        (home / "config.toml").write_text(config)
    e = {"PATH": "/nonexistent", "CODEX_HOME": str(home),
         "CLAUDE_BIN": str(_bin(tmp_path, "claude", claude)), "CODEX_BIN": str(_bin(tmp_path, "codex", codex)),
         "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "200000"}
    e.update(kw)
    return {k: v for k, v in e.items() if v is not None}


def test_preflight_ok_when_everything_is_in_place(tmp_path):
    st, detail, fix = C.preflight(_doc_env(tmp_path))
    assert st == "ok", detail
    assert "claude at 200,000" in detail and "codex at 150,000" in detail and "= 150,000" in detail


def test_preflight_fails_on_a_build_without_the_knob(tmp_path):
    st, detail, fix = C.preflight(_doc_env(tmp_path, claude=None))
    assert st == "fail" and "has no CLAUDE_CODE_AUTO_COMPACT_WINDOW" in detail and "restart" in fix
    st, detail, _ = C.preflight(_doc_env(tmp_path, codex=None))
    assert st == "fail" and "has no model_auto_compact_token_limit" in detail


def test_preflight_fails_on_a_conflicting_environment_and_a_bad_value(tmp_path):
    st, detail, _ = C.preflight(_doc_env(tmp_path, DISABLE_AUTO_COMPACT="1"))
    assert st == "fail" and "DISABLE_AUTO_COMPACT" in detail
    st, detail, fix = C.preflight(_doc_env(tmp_path, CTF_COMPACT_CODEX="small"))
    assert st == "fail" and "CTF_COMPACT_CODEX" in detail and "token count" in fix


@pytest.mark.parametrize("kw,needle", [
    ({"CLAUDE_CODE_AUTO_COMPACT_WINDOW": None}, "hand-started claude sessions use the default window"),
    ({"config": None}, "sets no model_auto_compact_token_limit"),
    ({"config": "model_auto_compact_token_limit = 400000\n"}, "is above 150,000"),
    ({"config": 'model_auto_compact_token_limit = "150000"\n'}, "is not an integer"),
    ({"CLAUDE_BIN": "/nonexistent/claude"}, "claude CLI not found"),
    ({"CTF_COMPACT_CODEX": "off"}, "codex threshold off"),
])
def test_preflight_warns(tmp_path, kw, needle):
    st, detail, fix = C.preflight(_doc_env(tmp_path, **kw))
    assert st == "warn" and needle in detail, detail


def test_preflight_warn_fix_names_the_human_step(tmp_path):
    _, _, fix = C.preflight(_doc_env(tmp_path, CLAUDE_CODE_AUTO_COMPACT_WINDOW=None, config=None))
    assert "export CLAUDE_CODE_AUTO_COMPACT_WINDOW=200000" in fix
    assert "model_auto_compact_token_limit = 150000" in fix


def test_preflight_codex_config_is_read_only_with_codex_checks(tmp_path):
    e = _doc_env(tmp_path, config="this is [not toml\n")
    st, detail, _ = C.preflight(e)
    assert st == "fail" and "not readable TOML" in detail
    st, detail, _ = C.preflight(e, codex=False)
    assert st == "ok" and "config.toml" not in detail


def test_preflight_launcher_shim_is_a_warning(tmp_path):
    e = _doc_env(tmp_path)
    e["CLAUDE_BIN"] = str(_bin(tmp_path, "claude-shim", None, script=True))
    st, detail, _ = C.preflight(e)
    assert st == "warn" and "launcher script" in detail
    e["CLAUDE_BIN"] = str(_bin(tmp_path, "claude-shim2", b"CLAUDE_CODE_AUTO_COMPACT_WINDOW", script=True))
    assert C.preflight(e)[0] == "ok"


def test_a_large_script_without_the_knob_is_a_build_without_it(tmp_path):
    # A #! file over SCRIPT_PROBE_LIMIT (an npm cli.js, say) is the build itself, not a shim.
    marker = b"CLAUDE_CODE_AUTO_COMPACT_WINDOW"
    big = _bin(tmp_path, "cli.js", None, script=True, pad=C.SCRIPT_PROBE_LIMIT)
    assert big.stat().st_size >= C.SCRIPT_PROBE_LIMIT
    assert C.knob_in_build(big, marker) is False
    assert C.knob_in_build(_bin(tmp_path, "cli2.js", marker, script=True, pad=C.SCRIPT_PROBE_LIMIT),
                           marker) is True
    small = _bin(tmp_path, "shim", None, script=True)
    assert C.knob_in_build(small, marker) is None
    e = _doc_env(tmp_path)
    e["CLAUDE_BIN"] = str(big)
    st, detail, _ = C.preflight(e)
    assert st == "fail" and "has no CLAUDE_CODE_AUTO_COMPACT_WINDOW" in detail


def test_knob_found_across_a_chunk_boundary(tmp_path):
    marker = b"model_auto_compact_token_limit"
    for pad in range(0, 40):
        p = _bin(tmp_path, f"c{pad}", marker, pad=pad)
        assert C.knob_in_build(p, marker, chunk=32) is True, pad
    assert C.knob_in_build(_bin(tmp_path, "none", None, pad=100), marker, chunk=32) is False


def test_doctor_runs_the_compaction_check(tmp_path, monkeypatch):
    from ctf import event
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))     # the allowance check reads the workdir
    cs = doctor.run_checks(event.load("pink"), codex=False, environ=_doc_env(tmp_path, claude=None))
    names = [c.name for c in cs]
    assert names.index("compaction") == names.index("router") + 1
    c = cs[names.index("compaction")]
    assert c.status == "fail" and "CLAUDE_CODE_AUTO_COMPACT_WINDOW" in c.detail and c.blocking


def test_doctor_no_codex_does_not_read_the_codex_config(tmp_path, monkeypatch):
    from ctf import event
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))     # the allowance check reads the workdir
    e = _doc_env(tmp_path, config="this is [not toml\n")
    cs = doctor.run_checks(event.load("pink"), codex=False, environ=e)
    c = next(c for c in cs if c.name == "compaction")
    assert c.status == "ok" and "config.toml" not in c.detail, c.detail


def test_preflight_finds_the_cli_on_path_and_needs_it_executable(tmp_path):
    e = _doc_env(tmp_path)
    e.pop("CLAUDE_BIN")
    bindir = tmp_path / "pathbin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_bytes(b"\xcf\xfa\xed\xfe" + b"CLAUDE_CODE_AUTO_COMPACT_WINDOW")
    e["PATH"] = f"/nonexistent{os.pathsep}{bindir}"
    st, detail, _ = C.preflight(e)
    assert st == "warn" and "claude CLI not found ('claude')" in detail    # not executable yet
    exe.chmod(0o755)
    st, detail, _ = C.preflight(e)
    assert st == "ok" and "claude at 200,000" in detail, detail


def test_over_is_strictly_above_the_tolerance_band(tmp_path):
    p = _write(tmp_path, "t.jsonl", [_claude_line("a", 220_000)])
    assert C.audit(p, environ={}).held                       # exactly threshold * 1.1: still held
    q = _write(tmp_path, "u.jsonl", [_claude_line("a", 220_001)])
    assert C.audit(q, environ={}).over == 1
    r = _write(tmp_path, "v.jsonl", [_claude_line("a", 200_000)])
    assert C.audit(r, environ={}, tolerance=0.0).held and C.audit(r, environ={}).excess_tokens == 0
