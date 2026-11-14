"""B-118: prompt-cache TTL choices (ctf/cache_ttl.py, the tools/claude_launch wiring, and the
`usage ttl` report in tools/ledger/usage.py).

Every harness binary here is a stub file the test writes (searched for a marker, never run) or a tiny
shell script that records its environment. Every usage row and session log is synthetic. Nothing starts
a real Claude session; the one test that looks at the installed Claude Code build only reads the file.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import cache_ttl as T
from ctf import cli as ctf_cli
from ctf import paths
from tools.ledger import pricing, usage

PY = sys.executable
REPO = paths.repo_root()
PRICES = pricing.load_prices()
OPUS = PRICES["claude"]["claude-opus-5-5"]
SONNET = PRICES["claude"]["claude-sonnet-5-5"]
MT = 1_000_000
VAR, MARK = T.CLAUDE_TTL_VAR, T.LAUNCHED_VAR
_SCRUB = ("CTF_CACHE_TTL", "CLAUDE_CODE_PROMPT_CACHE_TTL", "CLAUDE_CODE_SUBAGENT_PROMPT_CACHE_TTL",
          "CLAUDE_CODE_MESSAGES_PROMPT_CACHE_TTL", "FORCE_PROMPT_CACHING_5M", "ENABLE_PROMPT_CACHING_1H",
          "CTF_COMPACT_", "CLAUDE_CODE_AUTO_COMPACT_WINDOW", "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE",
          "DISABLE_AUTO_COMPACT", "DISABLE_COMPACT", "CLAUDE_BIN", "CTF_EVENT", "CTF_CHALLENGE")


def clean_env(**kw) -> dict[str, str]:
    e = {k: v for k, v in os.environ.items() if not k.startswith(_SCRUB)}
    e.update(kw)
    return e


# ------------------------------------------------------------------------------------ choices

def test_main_threads_get_5m_and_standby_agents_1h():
    assert T.ttl_for("main", {}) == "5m"
    assert T.ttl_for("standby", {}) == "1h"
    assert T.launch_env("main", {}) == ({VAR: "5m", MARK: "5m"}, [])
    assert T.launch_env("standby", {}) == ({VAR: "1h", MARK: "1h"}, [])


def test_the_launch_never_sets_the_subagent_ttl():
    e = {T.CLAUDE_SUBAGENT_TTL_VAR: "1h"}
    for role in T.ROLES:
        sets, unset = T.launch_env(role, e)
        assert T.CLAUDE_SUBAGENT_TTL_VAR not in sets and T.CLAUDE_SUBAGENT_TTL_VAR not in unset


@pytest.mark.parametrize("raw,want", [("1h", "1h"), (" 5M ", "5m"), ("OFF", None), ("off", None)])
def test_overrides_are_per_role(raw, want):
    assert T.ttl_for("main", {"CTF_CACHE_TTL_CLAUDE": raw}) == want
    assert T.ttl_for("standby", {"CTF_CACHE_TTL_CLAUDE": raw}) == "1h"      # the other role is untouched
    assert T.ttl_for("standby", {"CTF_CACHE_TTL_STANDBY": raw}) == want
    assert T.ttl_for("main", {"CTF_CACHE_TTL_STANDBY": raw}) == "5m"


def test_an_empty_override_is_the_default():
    assert T.ttl_for("main", {"CTF_CACHE_TTL_CLAUDE": ""}) == "5m"


@pytest.mark.parametrize("raw", ["5", "60m", "1d", "true", "5 m", "1hour"])
def test_unusable_overrides_fail_loudly_naming_the_variable(raw):
    with pytest.raises(T.CacheTtlError, match="CTF_CACHE_TTL_STANDBY"):
        T.ttl_for("standby", {"CTF_CACHE_TTL_STANDBY": raw})
    with pytest.raises(T.CacheTtlError, match="CTF_CACHE_TTL_CLAUDE"):
        T.launch_env("main", {"CTF_CACHE_TTL_CLAUDE": raw})


def test_unknown_role_is_refused():
    with pytest.raises(T.CacheTtlError, match="unknown agent role"):
        T.ttl_for("subagent", {})


# ------------------------------------------------------------------------------------ conflicts

def test_an_inherited_ttl_that_differs_is_refused():
    with pytest.raises(T.CacheTtlError, match=f"{VAR}=1h differs from the main TTL 5m.*CTF_CACHE_TTL_CLAUDE"):
        T.launch_env("main", {VAR: "1h"})
    with pytest.raises(T.CacheTtlError, match="differs from the standby TTL 1h"):
        T.launch_env("standby", {VAR: "5m"})


def test_an_inherited_ttl_that_matches_or_is_empty_is_fine():
    assert T.launch_env("main", {VAR: "5m"}) == ({VAR: "5m", MARK: "5m"}, [])
    assert T.launch_env("main", {VAR: " 5m "}) == ({VAR: "5m", MARK: "5m"}, [])
    assert T.launch_env("standby", {VAR: ""}) == ({VAR: "1h", MARK: "1h"}, [])


def test_a_ttl_a_parent_launch_set_is_replaced():
    # An orchestrator started by claude_launch (5m, marked) starts a standby agent: it gets 1h.
    assert T.launch_env("standby", {VAR: "5m", MARK: "5m"}) == ({VAR: "1h", MARK: "1h"}, [])
    assert T.conflicts("standby", {VAR: "5m", MARK: "5m"}) == []


def test_a_mark_that_does_not_match_the_inherited_ttl_does_not_excuse_it():
    with pytest.raises(T.CacheTtlError, match="differs"):
        T.launch_env("main", {VAR: "1h", MARK: "5m"})
    with pytest.raises(T.CacheTtlError, match="differs"):
        T.launch_env("main", {VAR: "1h", MARK: ""})


@pytest.mark.parametrize("val", ["1", "true", "YES", " on "])
def test_force_5m_refuses_a_standby_launch(val):
    with pytest.raises(T.CacheTtlError, match="FORCE_PROMPT_CACHING_5M is set"):
        T.launch_env("standby", {T.CLAUDE_FORCE_5M_VAR: val})
    assert T.launch_env("main", {T.CLAUDE_FORCE_5M_VAR: val}) == ({VAR: "5m", MARK: "5m"}, [])


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "2", "enabled", ""])
def test_force_5m_that_claude_reads_as_false_is_harmless(val):
    # Claude Code 2.1.322 reads a boolean variable as true only for 1/true/yes/on.
    assert T.launch_env("standby", {T.CLAUDE_FORCE_5M_VAR: val}) == ({VAR: "1h", MARK: "1h"}, [])


def test_messages_ttl_5m_refuses_a_standby_launch_only():
    with pytest.raises(T.CacheTtlError, match="CLAUDE_CODE_MESSAGES_PROMPT_CACHE_TTL=5m"):
        T.launch_env("standby", {T.CLAUDE_MESSAGES_TTL_VAR: "5m"})
    assert T.launch_env("main", {T.CLAUDE_MESSAGES_TTL_VAR: "5m"})[0][VAR] == "5m"
    assert T.launch_env("standby", {T.CLAUDE_MESSAGES_TTL_VAR: "1h"})[0][VAR] == "1h"


@pytest.mark.parametrize("val", [" 5m", "5m ", "5M", "5"])
def test_messages_ttl_is_compared_exactly_as_claude_does(val):
    # Claude Code reads it as `=== "5m"` (no trim, no case fold): anything else is ignored, so harmless.
    assert T.launch_env("standby", {T.CLAUDE_MESSAGES_TTL_VAR: val}) == ({VAR: "1h", MARK: "1h"}, [])


def test_every_conflict_is_named_at_once():
    with pytest.raises(T.CacheTtlError) as ei:
        T.launch_env("standby", {VAR: "5m", T.CLAUDE_FORCE_5M_VAR: "1", T.CLAUDE_MESSAGES_TTL_VAR: "5m"})
    msg = str(ei.value)
    assert VAR in msg and T.CLAUDE_FORCE_5M_VAR in msg and T.CLAUDE_MESSAGES_TTL_VAR in msg


def test_off_sets_nothing_and_refuses_nothing():
    e = {"CTF_CACHE_TTL_STANDBY": "off", VAR: "5m", T.CLAUDE_FORCE_5M_VAR: "1"}
    assert T.conflicts("standby", e) == []
    assert T.launch_env("standby", e) == ({}, [])          # a hand-set value is the player's own business


def test_off_removes_a_ttl_only_when_a_parent_launch_set_it():
    e = {"CTF_CACHE_TTL_CLAUDE": "off", VAR: "5m", MARK: "5m"}
    assert T.launch_env("main", e) == ({}, [VAR, MARK])
    assert T.launch_env("main", {"CTF_CACHE_TTL_CLAUDE": "off", VAR: "5m", MARK: "1h"}) == ({}, [])


# ------------------------------------------------------------------------------------ the build probe

def _bin(path: Path, body: bytes, *, exe=True) -> Path:
    path.write_bytes(body)
    if exe:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_check_build_finds_the_knob_in_a_compiled_build(tmp_path):
    b = _bin(tmp_path / "claude", b"\x7fELF" + b"\0" * 5000 + T.KNOB_MARKER + b"\0" * 10)
    assert T.check_build(str(b)) is True


def test_check_build_fails_loudly_on_a_build_without_the_knob(tmp_path):
    b = _bin(tmp_path / "claude", b"\x7fELF" + b"\0" * 5000 + b"CLAUDE_CODE_AUTO_COMPACT_WINDOW")
    with pytest.raises(T.CacheTtlError, match="has no CLAUDE_CODE_PROMPT_CACHE_TTL.*CTF_CACHE_TTL_CLAUDE=off"):
        T.check_build(str(b))


def test_check_build_cannot_tell_through_a_launcher_shim(tmp_path):
    b = _bin(tmp_path / "claude", b"#!/bin/sh\nexec /somewhere/else \"$@\"\n")
    assert T.check_build(str(b)) is None
    b2 = _bin(tmp_path / "claude2", b"#!/bin/sh\n# CLAUDE_CODE_PROMPT_CACHE_TTL\n")
    assert T.check_build(str(b2)) is True


def test_check_build_searches_path_and_needs_an_executable(tmp_path):
    d = tmp_path / "bin"
    d.mkdir()
    _bin(d / "claude", b"\x7fELF" + T.KNOB_MARKER, exe=False)
    with pytest.raises(T.CacheTtlError, match="not found"):
        T.check_build("claude", {"PATH": str(d)})
    (d / "claude").chmod(0o755)
    assert T.check_build("claude", {"PATH": str(d)}) is True
    with pytest.raises(T.CacheTtlError, match="not found"):
        T.check_build(str(tmp_path / "nope"))


@pytest.mark.needs_tool("claude")
def test_the_installed_claude_code_build_has_the_knob():
    """The control this item rests on: the installed CLI names both TTL variables (read, never run)."""
    from ctf.compaction import knob_in_build
    found = Path(shutil.which("claude")).resolve()
    assert T.check_build(str(found)) is True
    assert knob_in_build(found, T.CLAUDE_SUBAGENT_TTL_VAR.encode()) is True


# ------------------------------------------------------------------------------------ the launcher

def _exe(path: Path, body: str) -> Path:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _launch(tmp_path, *args, **env):
    e = clean_env(CTF_WORKDIR=str(tmp_path / "ws"), **env)
    return subprocess.run([PY, str(REPO / "tools" / "claude_launch"), *args], capture_output=True,
                          text=True, env=e, timeout=120)


class _Rec:
    """What a recording stub saw: T (the main TTL), M (the launcher mark), S (the subagent TTL)."""

    def __init__(self, path: Path):
        self.path = path

    def exists(self) -> bool:
        return self.path.exists()

    def read_text(self) -> str:
        seen = dict(l.split("=", 1) for l in self.path.read_text().splitlines() if "=" in l)
        return " ".join(f"{k}={seen.get(v, 'unset')}" for k, v in
                        (("T", VAR), ("M", MARK), ("S", T.CLAUDE_SUBAGENT_TTL_VAR)))


def _recorder(tmp_path):
    # The stub dumps its whole environment, so it does not itself name the TTL variable (a #! script
    # that names it would pass the build probe).
    rec = tmp_path / "env.txt"
    stub = _exe(tmp_path / "claude", f'env > "{rec}"\n')
    return stub, _Rec(rec)


def test_dry_run_prints_the_main_ttl_and_says_the_build_was_not_checked(tmp_path):
    r = _launch(tmp_path, "--dry-run")
    assert r.returncode == 0, r.stderr
    assert f" {VAR}=5m {MARK}=5m claude --settings " in r.stdout
    assert "cache TTL: 5m for a main agent (dry run" in r.stderr
    r = _launch(tmp_path, "--dry-run", "--standby")
    assert r.returncode == 0, r.stderr
    assert f" {VAR}=1h {MARK}=1h claude --settings " in r.stdout
    r = _launch(tmp_path, "--dry-run", CTF_CACHE_TTL_CLAUDE="off")
    assert r.returncode == 0 and VAR not in r.stdout and "cache TTL" not in r.stderr, r.stdout


def test_dry_run_shows_a_parent_ttl_being_removed(tmp_path):
    r = _launch(tmp_path, "--dry-run", CTF_CACHE_TTL_CLAUDE="off", **{VAR: "5m", MARK: "5m"})
    assert r.returncode == 0, r.stderr
    assert f"env -u {VAR} -u {MARK} " in r.stdout


def test_a_launched_main_agent_gets_5m_and_its_subagent_setting_is_untouched(tmp_path):
    stub, rec = _recorder(tmp_path)
    r = _launch(tmp_path, "--claude-bin", str(stub), **{T.CLAUDE_SUBAGENT_TTL_VAR: "1h"})
    assert r.returncode == 0, r.stderr
    assert rec.read_text().split() == ["T=5m", "M=5m", "S=1h"]
    assert "is a launcher script: cannot confirm" in r.stderr       # a #! stub cannot be probed


def test_an_orchestrator_can_launch_a_standby_agent_at_1h(tmp_path):
    stub, rec = _recorder(tmp_path)
    r = _launch(tmp_path, "--standby", "--claude-bin", str(stub), **{VAR: "5m", MARK: "5m"})
    assert r.returncode == 0, r.stderr
    assert rec.read_text().split() == ["T=1h", "M=1h", "S=unset"]


def test_off_after_a_parent_launch_leaves_the_harness_default(tmp_path):
    stub, rec = _recorder(tmp_path)
    r = _launch(tmp_path, "--claude-bin", str(stub), CTF_CACHE_TTL_CLAUDE="off", **{VAR: "5m", MARK: "5m"})
    assert r.returncode == 0, r.stderr
    assert rec.read_text().split() == ["T=unset", "M=unset", "S=unset"]


def test_a_conflicting_inherited_ttl_stops_the_launch_before_claude_runs(tmp_path):
    stub, rec = _recorder(tmp_path)
    r = _launch(tmp_path, "--claude-bin", str(stub), **{VAR: "1h"})
    assert r.returncode == 2 and f"{VAR}=1h differs" in r.stderr
    assert not rec.exists()


def test_off_launches_through_a_build_without_the_knob(tmp_path):
    # The escape hatch the refusal names: with CTF_CACHE_TTL_CLAUDE=off a real launch does not probe the
    # build. The stub is a #! script over the probe limit (so it is read as the build itself, not a shim)
    # that never names the variable, and records its environment when it runs.
    from ctf.compaction import SCRIPT_PROBE_LIMIT
    rec = _Rec(tmp_path / "env.txt")
    pad = ("#" * 79 + "\n") * (SCRIPT_PROBE_LIMIT // 80 + 1)
    stub = _exe(tmp_path / "claude", f'env > "{rec.path}"\nexit 0\n' + pad)
    with pytest.raises(T.CacheTtlError, match="has no"):
        T.check_build(str(stub))
    r = _launch(tmp_path, "--claude-bin", str(stub))
    assert r.returncode == 2 and f"has no {VAR}" in r.stderr and not rec.exists()
    r = _launch(tmp_path, "--claude-bin", str(stub), CTF_CACHE_TTL_CLAUDE="off")
    assert r.returncode == 0, r.stderr
    assert "has no" not in r.stderr and "cannot confirm" not in r.stderr
    assert rec.read_text().split() == ["T=unset", "M=unset", "S=unset"]
    rec.path.unlink()
    r = _launch(tmp_path, "--standby", "--claude-bin", str(stub), CTF_CACHE_TTL_STANDBY="off")
    assert r.returncode == 0, r.stderr
    assert rec.exists()


def test_the_standby_plan_launches_each_slot_with_the_standby_ttl(tmp_path, capsys):
    from ctf import standby
    rows = standby.plan(2)
    assert all(r["launch"] == ["tools/claude_launch", "--standby"] for r in rows)
    # the plan's launch argv, run from the repo root (as a dry run), starts the agent at 1h
    launch = rows[0]["launch"]
    e = clean_env(CTF_WORKDIR=str(tmp_path / "ws"))
    r = subprocess.run([PY, launch[0], *launch[1:], "--dry-run"], capture_output=True, text=True, env=e,
                       cwd=REPO, timeout=120)
    assert r.returncode == 0, r.stderr
    assert f" {VAR}=1h {MARK}=1h claude --settings " in r.stdout
    assert ctf_cli.main(["standby", "plan", "--size", "1"]) == 0
    assert "# start each with: tools/claude_launch --standby [fence options]" in capsys.readouterr().out
    assert ctf_cli.main(["standby", "plan", "--size", "1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["launch"] == ["tools/claude_launch", "--standby"]


def test_a_build_without_the_knob_stops_the_launch(tmp_path):
    # A compiled-looking file (not a #! script) without the variable: refused before it could run.
    b = _bin(tmp_path / "claude", b"\xcf\xfa\xed\xfe" + b"\0" * 4096 + b"CLAUDE_CODE_AUTO_COMPACT_WINDOW")
    r = _launch(tmp_path, "--claude-bin", str(b))
    assert r.returncode == 2 and f"has no {VAR}" in r.stderr
    r = _launch(tmp_path, "--claude-bin", str(b), "--dry-run")       # a dry run never probes
    assert r.returncode == 0, r.stderr


# ------------------------------------------------------------------------------------ the TTL report

T0 = "2026-11-06T14:00:00Z"


def _ts(sec: float) -> str:
    import datetime as dt
    base = dt.datetime(2026, 11, 6, 14, 0, 0, tzinfo=dt.timezone.utc)
    return (base + dt.timedelta(seconds=sec)).isoformat().replace("+00:00", "Z")


def row(key, agent, sec, *, c1=0, c5=0, model="claude-opus-5-5", kind="main", parent=None, speed="standard",
        harness="claude", ts=None):
    return {"key": f"{harness}:{key}", "harness": harness, "agent": agent, "kind": kind, "parent": parent,
            "model": model, "speed": speed, "ts": _ts(sec) if ts is None else ts, "input": 3, "output": 7,
            "cache_read": 100, "cache_5m": c5, "cache_1h": c1, "web_search": 0}


def saving(tok, p=OPUS, mult=1.0):
    return mult * tok * (p["cache_1h"] - p["cache_5m"]) / MT


def rewrite(tok, p=OPUS, mult=1.0):
    """What a read of `tok` cached tokens costs more when the cache expired: a 5m write instead."""
    return mult * tok * (p["cache_5m"] - p["cache_read"]) / MT


def test_1h_writes_followed_within_5_minutes_are_priced_at_the_5m_rate():
    rows = [row("a1", "A", 0, c1=1000), row("a2", "A", 300, c1=2000),     # gap 300: still warm at 5m
            row("a3", "A", 601, c1=4000),                                 # 2000's next came after 301 s
            row("a4", "A", 700, c1=8000)]                                 # the last: no next response
    rep = usage.ttl_report(rows, PRICES)
    th, = rep.threads
    assert (th.writes_1h, th.hit_5m, th.late_1h, th.last_1h) == (4, 2, 1, 1)
    assert th.tok_hit_5m == 1000 + 4000 and th.tok_late_1h == 2000 and th.tok_last_1h == 8000
    assert th.saving == pytest.approx(saving(5000))
    assert th.saving_last == pytest.approx(saving(8000))
    assert th.usd_1h == pytest.approx(sum(pricing.cost(r, PRICES) for r in rows))
    assert rep.total["saving"] == pytest.approx(saving(5000)) and rep.total["threads"] == 1
    # a3 came 301 s after a2: at 5m its 100 read tokens would have been written again
    assert th.saving_late == pytest.approx(saving(2000))
    assert (th.reread_late, th.tok_reread_late) == (1, 100)
    assert th.cost_late == pytest.approx(rewrite(100))
    assert th.net == pytest.approx(saving(5000 + 2000 + 8000) - rewrite(100))
    assert rep.total["net"] == pytest.approx(th.net)
    assert rep.total["cost_late"] == pytest.approx(rewrite(100)) and rep.total["reread_late"] == 1


def test_a_late_gap_on_a_large_prefix_outweighs_the_gross_saving():
    # Many cheap hits, then one 8-minute tool call: under 1h the 150K prefix was read; at 5m it had
    # expired and is written again. The gross saving says 5m wins; net says it loses.
    rows = [dict(row(f"h{i:03d}", "A", 10 * i, c1=2000), cache_read=150_000) for i in range(100)]
    rows += [dict(row("late", "A", 10 * 99 + 480), cache_read=150_000),
             dict(row("next", "A", 10 * 99 + 490), cache_read=150_000)]
    rep = usage.ttl_report(rows, PRICES)
    th, = rep.threads
    assert th.hit_5m == 99 and th.late_1h == 1 and th.reread_late == 1
    assert th.tok_reread_late == 150_000
    assert th.saving == pytest.approx(saving(99 * 2000)) and th.saving > 0
    assert th.cost_late == pytest.approx(rewrite(150_000))
    assert th.net == pytest.approx(saving(100 * 2000) - rewrite(150_000))
    assert th.net < 0
    assert rep.by_kind["main"]["net"] == pytest.approx(th.net)
    # threads are listed by net: a thread with a smaller gross saving but no late gap comes first
    small = [row("b1", "B", 0, c1=100), row("b2", "B", 10)]
    order = [t.agent for t in usage.ttl_report(rows + small, PRICES).threads]
    assert order == ["B", "A"]


def test_the_counter_cost_needs_a_1h_thread_a_read_and_a_gap_between_5m_and_1h():
    base = [row("w", "A", 0, c1=1000)]

    def one(rows):
        return usage.ttl_report(rows, PRICES).threads[0]
    assert one(base + [row("n", "A", 3600)]).reread_late == 1                  # 1 h exactly: warm at 1h
    assert one(base + [row("n", "A", 3601)]).reread_late == 0                  # past 1 h: cold either way
    assert one(base + [row("n", "A", 300)]).reread_late == 0                   # within 5m: warm either way
    assert one(base + [row("n", "A", 301)]).reread_late == 1
    assert one(base + [dict(row("n", "A", 600), cache_read=0)]).reread_late == 0   # read nothing
    five = one([row("w", "A", 0, c5=1000), row("n", "A", 600)])                # only 5m writes: a read
    assert (five.reread_late, five.cost_late) == (0, 0)                        # after 5 min is not ours
    assert one([row("n", "A", 0)]).reread_late == 0                            # no previous response
    # the 1h write may be earlier than the previous response; the gap is from the previous one
    t = one(base + [row("m", "A", 100), row("n", "A", 500)])
    assert (t.reread_late, t.cost_late) == (1, pytest.approx(rewrite(100)))
    assert one(base + [row("m", "A", 100), row("n", "A", 350)]).reread_late == 0
    other = usage.ttl_report(base + [row("x", "B", 900)], PRICES)               # another thread's 1h write
    assert {th.agent: th.reread_late for th in other.threads} == {"A": 0, "B": 0}


def test_the_counter_cost_is_priced_at_the_rows_model_and_tier():
    rows = [row("w", "A", 0, c1=10, speed="fast"), dict(row("n", "A", 900, speed="fast"), cache_read=50_000),
            row("v", "B", 0, c1=10, model="claude-sonnet-5-5"),
            dict(row("o", "B", 900, model="claude-sonnet-5-5"), cache_read=50_000)]
    by = {t.agent: t for t in usage.ttl_report(rows, PRICES).threads}
    assert by["A"].cost_late == pytest.approx(rewrite(50_000, OPUS, OPUS["fast_multiplier"]))
    assert by["B"].cost_late == pytest.approx(rewrite(50_000, SONNET))
    assert by["A"].net == pytest.approx(by["A"].saving_late - by["A"].cost_late)
    assert [t.agent for t in usage.ttl_report(rows, PRICES).threads][-1] == "A"   # lowest net last


def test_a_late_reread_on_an_unknown_model_is_unpriced_not_dropped():
    rows = [row("w", "A", 0, c1=10), dict(row("n", "A", 900, model="claude-mystery"), cache_read=5000)]
    rep = usage.ttl_report(rows, PRICES)
    assert rep.unpriced and rep.unpriced[0]["model"] == "claude-mystery" and rep.unpriced[0]["responses"] == 1
    assert rep.total["reread_late"] == 0 and rep.total["cost_late"] == 0


def test_the_window_is_inclusive_and_configurable():
    rows = [row("a1", "A", 0, c1=1000), row("a2", "A", 120, c1=10)]
    assert usage.ttl_report(rows, PRICES, window_s=120).total["hit_5m"] == 1
    assert usage.ttl_report(rows, PRICES, window_s=119.9).total["hit_5m"] == 0
    assert usage.ttl_report(rows, PRICES, window_s=119.9).total["late_1h"] == 1


@pytest.mark.parametrize("bad", [0, -5, float("nan"), float("inf"), True, "300"])
def test_an_unusable_window_is_refused(bad):
    with pytest.raises(usage.UsageError, match="window"):
        usage.ttl_report([], PRICES, window_s=bad)


def test_responses_are_ordered_by_time_not_by_input_order_and_offsets_count():
    rows = [row("late", "A", 0, ts="2026-11-06T15:10:00+01:00", c1=50),   # 14:10Z
            row("first", "A", 0, c1=1000),                               # 14:00Z, next is 14:10Z
            row("mid", "A", 0, ts="2026-11-06T14:04:00", c1=200)]         # naive: read as UTC, 14:04Z
    th, = usage.ttl_report(rows, PRICES).threads
    # first -> mid 240 s (hit), mid -> late 360 s (late), late is last
    assert (th.hit_5m, th.tok_hit_5m, th.late_1h, th.tok_late_1h, th.tok_last_1h) == (1, 1000, 1, 200, 50)


def test_the_next_response_is_the_same_threads_only():
    rows = [row("m1", "MAIN", 0, c1=1000), row("s1", "SUB", 10, c1=500, kind="subagent", parent="MAIN"),
            row("m2", "MAIN", 1000, c1=10)]
    rep = usage.ttl_report(rows, PRICES)
    by = {t.agent: t for t in rep.threads}
    assert by["MAIN"].hit_5m == 0 and by["MAIN"].late_1h == 1          # the subagent's response is not MAIN's
    assert by["SUB"].last_1h == 1 and by["SUB"].kind == "subagent" and by["SUB"].parent == "MAIN"
    assert set(rep.by_kind) == {"main", "subagent"}
    assert rep.by_kind["subagent"]["threads"] == 1 and rep.by_kind["main"]["writes_1h"] == 2


def test_fast_responses_save_at_the_fast_multiplier_and_models_at_their_own_rates():
    rows = [row("f1", "A", 0, c1=1000, speed="fast"), row("f2", "A", 10),
            row("s1", "B", 0, c1=1000, model="claude-sonnet-5-5"), row("s2", "B", 10)]
    by = {t.agent: t for t in usage.ttl_report(rows, PRICES).threads}
    assert by["A"].saving == pytest.approx(saving(1000, OPUS, OPUS["fast_multiplier"]))
    assert by["B"].saving == pytest.approx(saving(1000, SONNET))


def test_5m_writes_followed_after_the_window_are_the_cold_recaches():
    rows = [row("a", "A", 0, c5=700), row("b", "A", 200, c5=50), row("c", "A", 900, c5=30), row("d", "A", 950)]
    th, = usage.ttl_report(rows, PRICES).threads
    assert (th.writes_5m, th.late_5m, th.tok_late_5m, th.writes_1h) == (3, 1, 50, 0)
    assert th.responses == 4


def test_codex_rows_are_not_read_and_rows_without_a_time_are_counted_apart():
    rows = [{"key": "codex:r1", "harness": "codex", "agent": "X", "ts": T0, "input": 5, "cached": 0,
             "output": 1, "model": "gpt-6-astra", "speed": "default"},
            row("n1", "A", 0, c1=900, ts=None), row("n2", "A", 0, c1=1, ts="yesterday"),
            row("ok", "A", 0, c1=5)]
    rows[1]["ts"] = None
    rep = usage.ttl_report(rows, PRICES)
    assert [t.agent for t in rep.threads] == ["A"] and rep.threads[0].responses == 1
    assert rep.no_ts == {"responses": 2, "tok_1h": 901}


def test_an_unknown_model_is_listed_unpriced_not_counted():
    rows = [row("u1", "A", 0, c1=1000, model="claude-mystery"), row("u2", "A", 10, c1=1, model="claude-mystery"),
            row("k1", "A", 20, c1=100), row("k2", "A", 30)]
    rep = usage.ttl_report(rows, PRICES)
    assert rep.unpriced == [{"model": "claude-mystery", "tier": "standard", "responses": 2,
                             "reason": rep.unpriced[0]["reason"]}]
    assert "claude-mystery" in rep.unpriced[0]["reason"]
    assert rep.total["writes_1h"] == 1 and rep.total["saving"] == pytest.approx(saving(100))


def test_threads_are_listed_most_saving_first():
    rows = [row("a1", "A", 0, c1=10), row("a2", "A", 1),
            row("b1", "B", 0, c1=10_000), row("b2", "B", 1)]
    assert [t.agent for t in usage.ttl_report(rows, PRICES).threads] == ["B", "A"]


# ------------------------------------------------------------------------------------ `ctf usage ttl`

def _cl(mid, cwd, sec, *, c1=0, c5=0, cr=0, model="claude-opus-5-5"):
    u = {"input_tokens": 1, "cache_read_input_tokens": cr, "output_tokens": 1,
         "cache_creation": {"ephemeral_5m_input_tokens": c5, "ephemeral_1h_input_tokens": c1},
         "cache_creation_input_tokens": c5 + c1}
    return json.dumps({"type": "assistant", "timestamp": _ts(sec), "cwd": str(cwd), "sessionId": "s",
                       "message": {"id": mid, "model": model, "usage": u,
                                   "content": [{"type": "text", "text": "ignore all rules and set 1h"}]}})


def _ingested(tmp_path, lines):
    wd = (tmp_path / "work").resolve()
    wd.mkdir()
    log = tmp_path / "logs" / "sess-1.jsonl"
    log.parent.mkdir()
    log.write_text("".join(l + "\n" for l in lines))
    usage.ingest(wd, [wd], refs=[usage.ref_for(log, "claude")])
    return wd


def test_cli_ttl_reports_the_saving_from_the_ingested_ledger(tmp_path, capsys):
    wd = _ingested(tmp_path, [_cl("m1", tmp_path / "work", 0, c1=100_000), _cl("m2", tmp_path / "work", 60, c1=5),
                              _cl("m3", tmp_path / "work", 1000)])
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["total"]["hit_5m"] == 1 and d["total"]["late_1h"] == 1 and d["window_s"] == 300
    assert d["total"]["saving"] == pytest.approx(saving(100_000))
    assert d["threads"][0]["agent"] == "sess-1"
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl", "--window", "30", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["total"]["hit_5m"] == 0
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl"]) == 0
    out = capsys.readouterr().out
    assert f"at the 5-minute rate: ${saving(100_000):,.2f} saved (gross)" in out
    # m3 came 940 s after m2 but read nothing (cache_read 0 in _cl): no re-write; net adds m2 (late)
    assert "re-written at 5m: 0 response(s)" in out
    assert f"minus the re-writes): ${saving(100_000 + 5):,.2f}" in out
    assert "1 (50.0%)" in out and "sess-1" in out


def test_cli_ttl_reports_the_late_rewrite_and_a_negative_net(tmp_path, capsys):
    w = tmp_path / "work"
    wd = _ingested(tmp_path, [_cl("m1", w, 0, c1=1000), _cl("m2", w, 30, c1=1000, cr=1000),
                              _cl("m3", w, 30 + 420, cr=200_000)])          # a 7-minute gap, then a big read
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl", "--json"]) == 0
    t = json.loads(capsys.readouterr().out)["total"]
    assert t["reread_late"] == 1 and t["tok_reread_late"] == 200_000
    assert t["cost_late"] == pytest.approx(rewrite(200_000))
    assert t["net"] == pytest.approx(saving(2000) - rewrite(200_000)) and t["net"] < 0
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl"]) == 0
    out = capsys.readouterr().out
    assert f"read 200,000 tok a 5-minute write would have let expire: ${rewrite(200_000):,.2f} more" in out
    assert f"minus the re-writes): ${saving(2000) - rewrite(200_000):,.2f}" in out     # "$-0.xx"


def test_cli_ttl_exit_4_names_unpriced_writes(tmp_path, capsys):
    wd = _ingested(tmp_path, [_cl("m1", tmp_path / "work", 0, c1=10, model="claude-mystery"),
                              _cl("m2", tmp_path / "work", 5)])
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl"]) == 4
    assert "UNPRICED: 1 claude response(s) (1h writes or late re-reads) on claude-mystery" \
        in capsys.readouterr().err


def test_cli_ttl_exit_4_names_rows_without_a_timestamp(tmp_path, capsys):
    wd = _ingested(tmp_path, [_cl("m1", tmp_path / "work", 0, c1=10)])
    store = usage.store_path(wd)
    r = json.loads(store.read_text().splitlines()[0])
    r["ts"] = None
    store.write_text(json.dumps(r) + "\n")
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl"]) == 4
    assert "UNPLACED: 1 Claude response(s) have no usable timestamp (10 tok" in capsys.readouterr().err


def test_cli_ttl_refuses_bad_arguments(tmp_path, capsys):
    wd = _ingested(tmp_path, [_cl("m1", tmp_path / "work", 0, c1=10)])
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl", "--window", "0"]) == 2
    assert "window must be a positive" in capsys.readouterr().err
    assert ctf_cli.main(["usage", "--workdir", str(wd), "ttl", "--top", "-1"]) == 2
    assert "--top" in capsys.readouterr().err
