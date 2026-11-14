"""B-170: harness failover for release mornings (ctf/failover.py, `ctf failover`, the doctor's failover
check, docs/runbooks/harness-failover.md).

Every quota reading, task and harness binary here is synthetic. The rehearsal tests start the real fenced
launchers (tools/codex_launch, tools/claude_launch) with a stub harness binary that carries the stub
marker; no real Claude or Codex session is ever started, and nothing touches the network.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import cli, doctor, event, failover, flagfmt, ledger, paths, quota

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 11, 6, 9, 0, tzinfo=UTC).timestamp()        # 3 h before the noon release
H = 3600.0
REPO = paths.repo_root()
RUNBOOK = REPO / failover.RUNBOOK


def prof(categories=("Web", "Cryptography", "Rev"), **allowance):
    data = {"slug": "fdemo", "name": "Failover Demo", "categories": list(categories),
            "dates": {"start": dt.datetime(2026, 11, 1, tzinfo=UTC), "end": dt.datetime(2026, 11, 30, tzinfo=UTC)},
            "platform": {"kind": "ctfd", "base_url": "https://demo.example/"}, "flag": {"prefixes": ["DEMO"]},
            "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
            "allowance": {"daily_release": "12:00", **allowance}}
    return event.parse(data)


def R(harness, window, used=None, *, ts=T0, resets=None, exhausted=False):
    return quota.Reading(harness, window, ts, "test", used_pct=used, resets_at=resets, exhausted=exhausted)


def snap(readings=(), p=None, now=T0, last_ok=None):
    latest = {}
    quota.merge(latest, readings)
    return quota.build_snapshot(p or prof(), latest, last_ok or {}, now)


def live_rec(harness, held=True, lanes=(("web", "pass", 10.0),), ts=None, live=True, deadline=300.0):
    return {"ts": ts if ts is not None else T0, "event": failover.REHEARSAL_EVENT, "harness": harness,
            "live": live, "held": held, "deadline_s": deadline, "wall_s": 12.0, "parallel": len(lanes),
            "by": "t", "lanes": [{"lane": a, "status": b, "seconds": c, "exit_code": 0, "detail": ""}
                                 for a, b, c in lanes]}


# ------------------------------------------------------------------ readiness

def test_readiness_counts_every_lane_against_the_window():
    s = snap([R("claude", "weekly", 70), R("codex", "weekly", 10)])     # claude at 80% with the margin
    one = failover.readiness(s, "claude", lanes=1)
    assert one.now and one.at_release and one.ready and one.why == ""
    six = failover.readiness(s, "claude", lanes=6)                       # 6 x 5% = 30%: past 100
    assert not six.now and six.at_release and not six.ready
    assert "lane(s) held" in six.why and "past the 100% release limit" in six.why
    # the per-lane estimate is used
    assert failover.readiness(s, "claude", lanes=2, est_pct=15).now is False
    assert failover.readiness(s, "claude", lanes=2, est_pct=10).now is True


def test_readiness_of_an_exhausted_harness_and_the_release_it_is_funded_at():
    after = T0 + 5 * H                                                   # resets after the noon release
    before = T0 + 1 * H                                                  # resets before it
    r = failover.readiness(snap([R("claude", "weekly", exhausted=True, resets=after)]), "claude")
    assert (r.now, r.at_release, r.status) == (False, False, "exhausted")
    assert "not funded at the release" in r.why
    r = failover.readiness(snap([R("claude", "weekly", exhausted=True, resets=before)]), "claude")
    assert (r.now, r.at_release) == (False, True)


def test_a_probe_harness_is_not_ready_for_a_release():
    # a limit hit 40 min ago (recheck 30 min) whose named reset is still ahead: probe state
    s = snap([R("codex", "weekly", exhausted=True, ts=T0 - 40 * 60, resets=T0 + 2 * H)])
    r = failover.readiness(s, "codex", lanes=1)
    assert r.status == "probe" and not r.now and "probe job" in r.why


def test_an_unmetered_harness_counts_as_ready_and_says_so():
    r = failover.readiness(snap([]), "codex", lanes=6)
    assert r.ready and r.status == "unmetered" and "unmetered" in r.why


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "2"])
def test_readiness_refuses_a_bad_lane_count(bad):
    with pytest.raises(failover.FailoverError, match="lanes must be"):
        failover.readiness(snap([]), "claude", lanes=bad)


def test_other_and_unknown_harness():
    assert failover.other("claude") == "codex" and failover.other("codex") == "claude"
    with pytest.raises(failover.FailoverError, match="unknown harness"):
        failover.other("gemini")


# ------------------------------------------------------------------ the decision

def test_both_ready_stays_on_the_primary():
    d = failover.decide(snap([R("claude", "weekly", 20), R("codex", "weekly", 20)]), lanes=3)
    assert (d.action, d.target, d.active, d.switch) == ("stay", "claude", "claude", False)
    assert "ready now and at the release" in d.trigger


def test_claude_exhausted_before_the_release_fails_over_to_codex():
    s = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H), R("codex", "weekly", 30)])
    d = failover.decide(s, lanes=3)
    assert (d.action, d.target, d.switch) == ("failover", "codex", True)
    assert "claude (primary) cannot hold the release" in d.trigger and "limit hit" in d.trigger
    assert d.ready["claude"].now is False and d.ready["codex"].now is True
    assert d.next_release == dt.datetime(2026, 11, 6, 12, 0, tzinfo=UTC).timestamp()


def test_failover_warns_to_plan_the_failback_when_the_primary_is_funded_by_the_release():
    s = snap([R("claude", "session", exhausted=True, resets=T0 + 1 * H), R("codex", "weekly", 30)])
    d = failover.decide(s, lanes=2)
    assert d.action == "failover"
    assert any("funded again by the release" in w and "fail back" in w for w in d.warnings)
    s = snap([R("claude", "session", exhausted=True, resets=T0 + 5 * H), R("codex", "weekly", 30)])
    assert not any("fail back" in w for w in failover.decide(s, lanes=2).warnings)


def test_codex_primary_turns_the_direction_round():
    s = snap([R("codex", "weekly", exhausted=True, resets=T0 + 5 * H), R("claude", "weekly", 30)])
    d = failover.decide(s, primary="codex", lanes=2)
    assert (d.action, d.target, d.primary) == ("failover", "claude", "codex")


def test_failback_when_the_primary_is_ready_again_and_stay_while_it_is_not():
    ready = snap([R("claude", "weekly", 20), R("codex", "weekly", 20)])
    d = failover.decide(ready, active="codex", lanes=2)
    assert (d.action, d.target, d.active) == ("failback", "claude", "codex") and d.switch
    out = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H), R("codex", "weekly", 20)])
    d = failover.decide(out, active="codex", lanes=2)
    assert (d.action, d.target) == ("stay", "codex") and not d.switch


def test_both_out_is_stranded_and_names_who_is_funded_by_the_release():
    s = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H),
              R("codex", "weekly", exhausted=True, resets=T0 + 1 * H)])
    d = failover.decide(s, lanes=1)
    assert (d.action, d.target, d.switch) == ("stranded", None, False)
    assert d.trigger.startswith("no harness can take release work now") and "claude:" in d.trigger
    assert any(w.endswith(": codex") for w in d.warnings)
    s = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H),
              R("codex", "weekly", exhausted=True, resets=T0 + 6 * H)])
    assert failover.decide(s).warnings == ()


def test_a_lane_count_the_primary_cannot_fund_fails_over_though_one_lane_fits():
    s = snap([R("claude", "weekly", 70), R("codex", "weekly", 10)])
    assert failover.decide(s, lanes=1).action == "stay"
    assert failover.decide(s, lanes=6).action == "failover"


def test_the_decision_carries_what_the_target_rehearsal_found():
    s = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H), R("codex", "weekly", 10)])
    d = failover.decide(s, records=[])
    assert any("codex was never rehearsed live" in w for w in d.warnings)
    d = failover.decide(s, records=[live_rec("codex", held=True)])
    assert not any("rehears" in w for w in d.warnings)
    d = failover.decide(s, records=[live_rec("codex", held=False, lanes=(("web", "pass", 5.0), ("pwn", "timeout", 600.0)))])
    assert any("did not hold" in w and "pwn timeout" in w and "web" not in w.split("hold:")[1] for w in d.warnings)
    # staying on the primary says nothing about the other harness's rehearsal
    ok = snap([R("claude", "weekly", 10), R("codex", "weekly", 10)])
    assert failover.decide(ok, records=[]).warnings == ()


def test_decide_refuses_an_unknown_active_harness():
    with pytest.raises(failover.FailoverError, match="unknown active harness"):
        failover.decide(snap([]), active="gemini")


# ------------------------------------------------------------------ the switch record

def test_switch_records_and_moves_the_active_harness(tmp_path):
    assert failover.active(tmp_path) == "claude"
    rec = failover.switch(tmp_path, "codex", by="max", reason="claude weekly out")
    assert (rec["event"], rec["harness"], rec["from_harness"], rec["action"], rec["primary"]) == \
        ("failover.switch", "codex", "claude", "failover", "claude")
    assert failover.active(tmp_path) == "codex"
    with pytest.raises(failover.FailoverError, match="codex already holds the lanes"):
        failover.switch(tmp_path, "codex", by="max", reason="again")
    back = failover.switch(tmp_path, "claude", by="max", reason="claude reset")
    assert (back["action"], back["from_harness"]) == ("failback", "codex")
    assert failover.active(tmp_path) == "claude"
    assert [r["harness"] for r in ledger.read(tmp_path) if r["event"] == "failover.switch"] == ["codex", "claude"]


def test_active_takes_the_newest_switch_whatever_the_file_order():
    recs = [{"ts": 20.0, "event": "failover.switch", "harness": "claude"},
            {"ts": 10.0, "event": "failover.switch", "harness": "codex"},
            {"ts": 30.0, "event": "other", "harness": "codex"}]
    assert failover.active(None, records=recs) == "claude"
    assert failover.active(None, "codex", records=[]) == "codex"


@pytest.mark.parametrize("kw, msg", [({"by": "", "reason": "x"}, "who made it"),
                                     ({"by": "max", "reason": " "}, "needs a reason")])
def test_switch_refuses_without_who_or_why(tmp_path, kw, msg):
    with pytest.raises(failover.FailoverError, match=msg):
        failover.switch(tmp_path, "codex", **kw)
    assert not ledger.path(tmp_path).exists()


# ------------------------------------------------------------------ the steps and the runbook

def _ctf_commands(text: str) -> list[list[str]]:
    """Every `python -m ctf ...` command in text, split into argv after `python -m ctf`."""
    out = []
    for m in re.finditer(r"\$\((python -m ctf [^)]*)\)", text):
        out.append(m.group(1))
    text = re.sub(r"\$\([^)]*\)", "X", text)
    for line in text.splitlines():
        for seg in re.split(r"`|\|", line):
            seg = seg.strip().rstrip(".")
            if seg.startswith("python -m ctf "):
                out.append(seg)
    return [shlex.split(c)[3:] for c in out]


def _launcher_commands(text: str) -> list[list[str]]:
    out = []
    for line in text.splitlines():
        for seg in re.split(r"`|\|", line):
            seg = re.sub(r"\$\([^)]*\)", "X", seg).strip().rstrip(".")
            if seg.startswith(("tools/codex_launch ", "tools/claude_launch ")):
                out.append(shlex.split(seg))
    return out


BUILTINS = {"me", "list", "pull", "triage", "submit", "status", "check", "doctor", "wait"}


def _parses(argv: list[str]) -> None:
    name = argv[0]
    if name in BUILTINS:
        return
    mods = {n: m for n, m, err in cli.discover() if err is None}
    assert name in mods, f"`python -m ctf {name}` is not a command"
    p = argparse.ArgumentParser(prog=f"ctf {name}", exit_on_error=False)
    mods[name].add_arguments(p)
    try:
        p.parse_args(argv[1:])
    except (argparse.ArgumentError, SystemExit) as e:
        raise AssertionError(f"`python -m ctf {' '.join(argv)}` does not parse: {e}") from None


def _launcher_flags(tool: str) -> set[str]:
    out = subprocess.run([sys.executable, str(REPO / tool), "--help"], capture_output=True, text=True,
                         timeout=60, cwd=str(REPO))
    assert out.returncode == 0, out.stderr
    return set(re.findall(r"(--[a-z][a-z0-9-]*)", out.stdout))


def _check_launchers(cmds):
    flags = {}
    for argv in cmds:
        tool = argv[0]
        assert (REPO / tool).is_file(), tool
        if tool not in flags:
            flags[tool] = _launcher_flags(tool)
        own = argv[1:argv.index("--")] if "--" in argv else argv[1:]
        unknown = [a for a in own if a.startswith("--") and a not in flags[tool]]
        assert not unknown, f"{tool} has no flag(s) {unknown}"


def _decisions():
    p = prof()
    out = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H), R("codex", "weekly", 10)])
    ok = snap([R("claude", "weekly", 10), R("codex", "weekly", 10)])
    both = snap([R("claude", "weekly", exhausted=True, resets=T0 + 5 * H),
                 R("codex", "weekly", exhausted=True, resets=T0 + 5 * H)])
    return p, {"failover": failover.decide(out, records=[]), "failback": failover.decide(ok, active="codex"),
               "stay": failover.decide(ok), "stranded": failover.decide(both)}


def test_steps_name_the_right_launcher_and_switch_per_action(tmp_path):
    p, ds = _decisions()
    assert {a: d.action for a, d in ds.items()} == {a: a for a in ds}
    fo = failover.steps(ds["failover"], p, workdir=tmp_path)
    text = "\n".join(fo)
    assert "switch --to codex" in text and "tools/codex_launch" in text and "tools/claude_launch" not in text
    assert "AGENTS.md" in text and f"--workdir {tmp_path}" in text
    assert "Warning: codex was never rehearsed live" in text
    fb = "\n".join(failover.steps(ds["failback"], p))
    assert "switch --to claude" in fb and "tools/claude_launch" in fb and "tools/codex_launch" not in fb
    assert "CLAUDE.md" in fb and "--model claude-opus-5-5" in fb and "--workdir <workdir>" in fb
    st = failover.steps(ds["stay"], p)
    assert len(st) == 1 and st[0].startswith("No switch: claude keeps the lanes")
    sd = "\n".join(failover.steps(ds["stranded"], p))
    assert "dispatch --event fdemo run" in sd and "switch" not in sd and "gate --kind release" in sd
    # the reason quoted into the switch command stays one shell word
    sw = next(c for c in _ctf_commands(text) if c[:1] == ["failover"] and "switch" in c)
    assert sw[sw.index("--reason") + 1].startswith("claude (primary) cannot hold the release")


def test_every_command_in_the_steps_parses(tmp_path):
    p, ds = _decisions()
    text = "\n".join(s for d in ds.values() for s in failover.steps(d, p, workdir=tmp_path))
    cmds = _ctf_commands(text)
    assert len(cmds) >= 10
    for argv in cmds:
        _parses(argv)
    _check_launchers(_launcher_commands(text))


def test_the_advisory_trigger_follow_up_is_a_build_plan_item_and_every_pointer_names_it():
    # Nothing reads failover.active() yet; that gap must stay on the plan, not only in a build log.
    plan = (REPO / "BUILD-PLAN.md").read_text(encoding="utf-8")
    items = [ln for ln in plan.splitlines() if ln.startswith("- `B-170-F1` ")]
    assert len(items) == 1, "BUILD-PLAN.md must list follow-up B-170-F1 exactly once"
    deps = re.search(r"\[[A-Z]+/[A-Z?~]+ dep:([^\]]+)\]", items[0])
    assert deps and {"B-004", "B-016"} <= set(deps.group(1).split(","))
    assert "failover.active()" in items[0]
    _, _, tail = plan.partition("# Follow-ups found during the build")
    assert tail and "- `B-170-F1` " in tail.split("\n# ")[0], "B-170-F1 sits outside the follow-up section"
    contracts = (REPO / "docs" / "CONTRACTS.md").read_text(encoding="utf-8")
    sec49 = contracts.split("## 49. Harness failover")[1].split("\n## ")[0]
    for where, text in (("runbook", RUNBOOK.read_text(encoding="utf-8")), ("CONTRACTS 49", sec49),
                        ("ctf.failover docstring", failover.__doc__)):
        assert "`B-170-F1`" in text, f"the {where} does not name the follow-up item"


def test_every_command_in_the_runbook_parses_and_its_launcher_flags_exist():
    text = RUNBOOK.read_text(encoding="utf-8")
    cmds = _ctf_commands(text)
    assert len(cmds) >= 15
    for argv in cmds:
        _parses(argv)
    launchers = _launcher_commands(text)
    assert {c[0] for c in launchers} == {"tools/codex_launch", "tools/claude_launch"}
    _check_launchers(launchers)
    for a in failover.ACTIONS:
        assert f"`{a.upper()}`" in text, f"the runbook's trigger table lacks {a}"
    assert failover.STUB_MARKER in text


def test_the_parse_check_catches_a_bad_command():
    with pytest.raises(AssertionError, match="does not parse"):
        _parses(["failover", "check", "--to", "codex"])
    with pytest.raises(AssertionError, match="is not a command"):
        _parses(["nosuchcommand"])


# ------------------------------------------------------------------ the doctor's check

def test_check_warns_until_both_directions_held_live(tmp_path):
    p = prof()
    c = failover.check(p, workdir=tmp_path)
    assert c.status == "warn" and "claude was never rehearsed live" in c.detail \
        and "codex was never rehearsed live" in c.detail
    assert "rehearse --to claude --live" in c.fix and "rehearse --to codex --live" in c.fix
    ledger.append(failover.REHEARSAL_EVENT, workdir=tmp_path, **{k: v for k, v in live_rec("codex").items()
                                                                  if k not in ("ts", "event")})
    c = failover.check(p, workdir=tmp_path)
    assert c.status == "warn" and "onto codex: live rehearsal held" in c.detail
    assert "rehearse --to codex" not in c.fix and "rehearse --to claude" in c.fix
    ledger.append(failover.REHEARSAL_EVENT, workdir=tmp_path, **{k: v for k, v in live_rec("claude").items()
                                                                  if k not in ("ts", "event")})
    c = failover.check(p, workdir=tmp_path)
    assert c.status == "ok" and "onto claude" in c.detail and "onto codex" in c.detail


def test_check_names_the_lanes_of_a_rehearsal_that_did_not_hold_and_ignores_stub_runs():
    recs = [live_rec("claude"), live_rec("codex", ts=T0),
            live_rec("codex", held=False, ts=T0 + 10, lanes=(("web", "pass", 1.0), ("rev", "wrong", 4.0),
                                                            ("pwn", "pass", 400.0)))]
    w = failover.rehearsal_warnings(recs, "codex")
    assert len(w) == 1 and "rev wrong" in w[0] and "pwn slow (400s > 300s)" in w[0] and "web" not in w[0]
    assert failover.rehearsal_warnings(recs, "claude") == []
    # a newer stub run that held does not count as live
    stub = live_rec("claude", live=False, ts=T0 + 50)
    w = failover.rehearsal_warnings([stub], "claude")
    assert len(w) == 1 and "never rehearsed live" in w[0] and "stub rehearsal of the mechanics held" in w[0]
    assert failover.rehearsal_warnings(recs + [stub], "claude") == []


def test_check_fails_on_an_unreadable_ledger_and_runs_in_the_doctor(tmp_path, monkeypatch):
    ledger.path(tmp_path).write_text("{not json\n")
    c = failover.check(prof(), workdir=tmp_path)
    assert c.status == "fail" and "cannot read the ledger" in c.detail
    good = tmp_path / "good"
    monkeypatch.setenv("CTF_WORKDIR", str(good))
    cs = doctor.run_checks(prof(), codex=False)
    fo = [c for c in cs if c.name == "failover"]
    assert len(fo) == 1 and fo[0].status == "warn" and "never rehearsed live" in fo[0].detail


def test_the_doctor_reads_failover_from_the_usage_workdir_it_was_handed(tmp_path, monkeypatch):
    # batch-33 integration (B-170 x B-190): run_checks hands its usage_workdir to the failover check too,
    # so a doctor run pointed at one workdir never reads another event's ledger.
    bad = tmp_path / "handed"
    bad.mkdir()
    ledger.path(bad).write_text("{not json\n")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "default"))
    cs = doctor.run_checks(prof(), codex=False, usage_workdir=bad, usage=False, power=False, toolbox=False)
    fo = [c for c in cs if c.name == "failover"]
    assert len(fo) == 1 and fo[0].status == "fail" and "cannot read the ledger" in fo[0].detail
    names = [c.name for c in cs]
    assert names.index("allowance") + 1 == names.index("failover") < names.index("token")


# ------------------------------------------------------------------ tasks, lanes, encodings

def _decode(val: str, enc: str) -> str:
    if enc == "base64":
        return base64.b64decode(val).decode()
    if enc == "hex":
        return bytes.fromhex(val).decode()
    if enc == "rot13":
        return codecs.decode(val, "rot13")
    if enc == "reversed":
        return val[::-1]
    if enc == "base32":
        return base64.b32decode(val).decode()
    if enc == "xor-0x2a-hex":
        return bytes(b ^ 0x2A for b in bytes.fromhex(val)).decode()
    raise AssertionError(enc)


@pytest.mark.parametrize("enc", failover.ENCODINGS)
def test_every_encoding_round_trips_and_hides_the_flag(enc):
    flag = "DEMO{rehearsal_0a1b2c3d}"
    txt = failover.task_text("web", flag, enc)
    assert flag not in txt and f"encoded with: {enc}" in txt
    assert _decode(txt.splitlines()[2], enc) == flag


def test_unknown_encoding_is_refused():
    with pytest.raises(failover.FailoverError, match="unknown encoding"):
        failover.encode("x", "rot47")


def test_lanes_come_from_the_announced_categories():
    assert failover.profile_lanes(prof(("Web", "Cryptography", "Rev", "web", "Cloud / Container",
                                        "Metadata Forensics"))) == \
        ("web", "crypto", "reverse", "opsec", "metadata-forensics")
    assert failover.profile_lanes(prof(())) == failover.DEFAULT_LANES


# ------------------------------------------------------------------ the rehearsal, end to end

STUB = r'''#!{py}
# ctf-harness-stub
import base64, codecs, json, os, sys, time
argv = sys.argv[1:]
prompt = argv[argv.index("-p") + 1] if "-p" in argv else argv[-1]
lane = prompt.split(", lane ", 1)[1].split(":", 1)[0]
mode = json.loads(os.environ.get("STUB_PLAN", "{}")).get(lane, "ok")
start = time.time()
open("stub-argv.json", "w").write(json.dumps({"argv": argv, "cwd": os.getcwd()}))
open("stub.pid", "w").write(str(os.getpid()))
lines = open("task.txt").read().splitlines()
enc, val = lines[1].rsplit(": ", 1)[1], lines[2]
dec = {"base64": lambda v: base64.b64decode(v).decode(), "hex": lambda v: bytes.fromhex(v).decode(),
       "rot13": lambda v: codecs.decode(v, "rot13"), "reversed": lambda v: v[::-1],
       "base32": lambda v: base64.b32decode(v).decode(),
       "xor-0x2a-hex": lambda v: bytes(b ^ 0x2A for b in bytes.fromhex(v)).decode()}[enc]
flag = dec(val)
if mode.startswith("sleep:"):
    time.sleep(float(mode[6:]))
if mode == "hang":
    time.sleep(120)
if mode == "fail":
    sys.stderr.write("stub: provider error, usage limit reached\n")
    sys.exit(1)
if mode == "silent":
    sys.exit(0)
open("result.txt", "w").write((flag[:-2] + "x}" if mode == "wrong" else flag) + "\n")
open("stub-times.json", "w").write(json.dumps([start, time.time()]))
'''


@pytest.fixture
def stub(tmp_path):
    p = tmp_path / "bin" / "harness-stub"
    p.parent.mkdir()
    p.write_text(STUB.replace("{py}", sys.executable))
    p.chmod(0o755)
    return p


def _env(plan=None, **extra):
    env = dict(os.environ)
    env["STUB_PLAN"] = json.dumps(plan or {})
    env.update(extra)
    return env


def _lane_dirs(rep):
    return {ln.lane: Path(rep.root) / ln.lane for ln in rep.lanes}


@pytest.mark.parametrize("harness", ["codex", "claude"])
def test_a_stub_rehearsal_runs_every_lane_through_the_fenced_launcher(tmp_path, stub, harness):
    p = prof()
    rep = failover.rehearse(p, harness, by="tester", workdir=tmp_path / "wd", bin=str(stub), environ=_env(),
                            deadline_s=60)
    assert rep.held and rep.failed == [] and not rep.live
    assert [ln.lane for ln in rep.lanes] == ["web", "crypto", "reverse"]
    assert all(ln.status == "pass" and ln.exit_code == 0 for ln in rep.lanes)
    ff = flagfmt.for_profile(p)
    flags = set()
    for lane, d in _lane_dirs(rep).items():
        got = (d / "result.txt").read_text().strip()
        assert ff.is_flag(got)
        flags.add(got)
        seen = json.loads((d / "stub-argv.json").read_text())
        assert Path(seen["cwd"]).resolve() == d.resolve()             # the launcher ran it in the lane dir
        if harness == "codex":
            assert seen["argv"][:2] == ["exec", "--skip-git-repo-check"]
            assert any(a.startswith("permissions.ctf_fence=") for a in seen["argv"])   # the fence profile
            assert f"lane {lane}:" in seen["argv"][-1]
        else:
            assert seen["argv"][0] == "--settings" and seen["argv"][1].endswith("claude-settings.json")
            i = seen["argv"].index("-p")
            assert f"lane {lane}:" in seen["argv"][i + 1]
            assert seen["argv"][seen["argv"].index("--permission-mode") + 1] == "acceptEdits"
    assert len(flags) == 3                                             # one fresh flag per lane
    recs = [r for r in ledger.read(tmp_path / "wd") if r["event"] == failover.REHEARSAL_EVENT]
    assert len(recs) == 1
    r = recs[0]
    assert (r["harness"], r["live"], r["held"], r["by"], r["parallel"], r["deadline_s"]) == \
        (harness, False, True, "tester", 3, 60.0)
    assert [ln["lane"] for ln in r["lanes"]] == ["web", "crypto", "reverse"]
    assert not any(f in json.dumps(r) for f in flags)                 # the ledger carries no flag


def test_a_rehearsal_names_each_failing_lane(tmp_path, stub):
    plan = {"web": "wrong", "crypto": "fail", "reverse": "silent", "pwn": "ok"}
    rep = failover.rehearse(prof(), "codex", by="t", workdir=tmp_path, bin=str(stub), environ=_env(plan),
                            lanes=["web", "crypto", "reverse", "pwn"], deadline_s=60)
    st = {ln.lane: ln for ln in rep.lanes}
    assert st["web"].status == "wrong"
    assert st["crypto"].status == "launch-error" and st["crypto"].exit_code == 1 \
        and "usage limit reached" in st["crypto"].detail
    assert st["reverse"].status == "no-result" and st["reverse"].exit_code == 0
    assert st["pwn"].status == "pass"
    assert not rep.held and rep.failed == ["web wrong", "crypto launch-error", "reverse no-result"]
    r = [r for r in ledger.read(tmp_path) if r["event"] == failover.REHEARSAL_EVENT][-1]
    assert r["held"] is False
    assert failover.rehearsal_warnings([dict(r, live=True)], "codex")[0].endswith(
        "web wrong, crypto launch-error, reverse no-result")


def test_a_lane_past_its_timeout_is_killed_and_reported(tmp_path, stub):
    rep = failover.rehearse(prof(), "codex", by="t", workdir=tmp_path, bin=str(stub),
                            environ=_env({"web": "hang"}), lanes=["web", "crypto"], deadline_s=30, timeout_s=4)
    st = {ln.lane: ln for ln in rep.lanes}
    assert st["web"].status == "timeout" and st["web"].exit_code is None and st["crypto"].status == "pass"
    assert 4 <= st["web"].seconds < 30
    pid = int((Path(rep.root) / "web" / "stub.pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert rep.failed == ["web timeout"]


def test_lanes_run_at_once_by_default_and_one_by_one_with_parallel_1(tmp_path, stub):
    plan = {"a": "sleep:2", "b": "sleep:2", "c": "sleep:2"}
    rep = failover.rehearse(prof(), "codex", by="t", workdir=tmp_path / "1", bin=str(stub), environ=_env(plan),
                            lanes=["a", "b", "c"], deadline_s=60)
    times = [json.loads((d / "stub-times.json").read_text()) for d in _lane_dirs(rep).values()]
    assert max(s for s, _e in times) < min(e for _s, e in times)       # all three overlapped
    assert rep.parallel == 3
    plan = {"a": "sleep:0.3", "b": "sleep:0.3", "c": "sleep:0.3"}
    rep = failover.rehearse(prof(), "codex", by="t", workdir=tmp_path / "2", bin=str(stub), environ=_env(plan),
                            lanes=["a", "b", "c"], parallel=1, deadline_s=60)
    times = [json.loads((d / "stub-times.json").read_text()) for d in _lane_dirs(rep).values()]
    assert all(times[i + 1][0] >= times[i][1] for i in range(2))      # strictly one after the other
    assert rep.wall_s >= sum(ln.seconds for ln in rep.lanes) - 0.5


def test_a_slow_lane_does_not_hold_even_when_right():
    rep = failover.RehearsalReport("codex", True, "/x", [failover.LaneResult("web", "pass", 10.0, 0),
                                                          failover.LaneResult("pwn", "pass", 31.0, 0)],
                                   31.0, 30.0, 2)
    assert rep.failed == ["pwn slow (31s > 30s)"] and not rep.held
    rep.deadline_s = 31.0
    assert rep.held
    assert not failover.RehearsalReport("codex", True, "/x", [], 0.0, 30.0, 0).held   # no lanes: no answer


def test_the_budget_gate_stays_off_for_rehearsal_lanes(tmp_path, stub):
    rep = failover.rehearse(prof(), "codex", by="t", workdir=tmp_path, bin=str(stub),
                            environ=_env(CTF_CHALLENGE="12"), lanes=["web"], deadline_s=60)
    assert rep.held
    log = (Path(rep.root) / "web" / failover.LOG_NAME).read_text()
    assert "budget gate: off" in log


# ------------------------------------------------------------------ the guards

def test_the_real_cli_needs_live(tmp_path):
    real = tmp_path / "codex"
    real.write_text("#!/bin/sh\necho real\n")
    real.chmod(0o755)
    with pytest.raises(failover.FailoverError, match="pass --live"):
        failover.rehearse(prof(), "codex", by="t", workdir=tmp_path / "wd", bin=str(real), environ=_env())
    assert not (tmp_path / "wd").exists()                              # nothing written, nothing recorded


def test_a_stub_that_is_the_cli_on_path_is_refused(tmp_path, stub):
    d = tmp_path / "pathbin"
    d.mkdir()
    (d / "codex").symlink_to(stub)
    with pytest.raises(failover.FailoverError, match="the one on PATH"):
        failover.guard_bin("codex", str(d / "codex"), live=False, env={"PATH": str(d)})


def test_live_is_refused_under_testing_and_with_a_stub(tmp_path, stub):
    with pytest.raises(failover.FailoverError, match="refused under CTF_TESTING"):
        failover.guard_bin("codex", str(stub), live=True, env={"CTF_TESTING": "1", "PATH": ""})
    with pytest.raises(failover.FailoverError, match="names a stub"):
        failover.guard_bin("codex", str(stub), live=True, env={"PATH": ""})
    real = tmp_path / "claude"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    assert failover.guard_bin("claude", str(real), live=True, env={"PATH": ""}) == str(real.resolve())


def test_a_marker_past_the_window_does_not_count(tmp_path):
    p = tmp_path / "late"
    p.write_text("#!/bin/sh\n" + "#" * failover.STUB_MARKER_WINDOW + "\n# ctf-harness-stub\n")
    p.chmod(0o755)
    with pytest.raises(failover.FailoverError, match="pass --live"):
        failover.guard_bin("codex", str(p), live=False, env={"PATH": ""})


def test_a_missing_binary_fails_loudly(tmp_path):
    with pytest.raises(failover.FailoverError, match="not found .set CODEX_BIN"):
        failover.guard_bin("codex", str(tmp_path / "nope"), live=False, env={"PATH": ""})
    with pytest.raises(failover.FailoverError, match="not found .set CLAUDE_BIN"):
        failover.guard_bin("claude", "claude-not-installed", live=False, env={"PATH": str(tmp_path)})


def test_the_binary_comes_from_the_harness_env_variable(tmp_path, stub):
    rep = failover.rehearse(prof(), "claude", by="t", workdir=tmp_path, environ=_env(CLAUDE_BIN=str(stub)),
                            lanes=["web"], deadline_s=60)
    assert rep.held and rep.bin == str(stub.resolve())
    with pytest.raises(failover.FailoverError, match="not found .set CODEX_BIN"):
        failover.rehearse(prof(), "codex", by="t", workdir=tmp_path,
                          environ=_env(CLAUDE_BIN=str(stub), CODEX_BIN=str(tmp_path / "none")), lanes=["web"])


@pytest.mark.parametrize("kw, msg", [
    ({"by": ""}, "who ran it"),
    ({"lanes": []}, "no lanes"),
    ({"lanes": ["web", "web"]}, "distinct plain names"),
    ({"lanes": ["../x"]}, "distinct plain names"),
    ({"lanes": [".hidden"]}, "distinct plain names"),
    ({"deadline_s": 0}, "deadline_s must be > 0"),
    ({"timeout_s": -1}, "timeout_s must be > 0"),
    ({"parallel": 0}, "parallel must be >= 1"),
])
def test_rehearse_refuses_bad_arguments(tmp_path, stub, kw, msg):
    args = {"by": "t", "workdir": tmp_path / "wd", "bin": str(stub), "environ": _env(), **kw}
    with pytest.raises(failover.FailoverError, match=msg):
        failover.rehearse(prof(), "codex", **args)
    assert not ledger.path(tmp_path / "wd").exists()


# ------------------------------------------------------------------ the CLI

def _ctf(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_cli_check_follows_the_meter_through_failover_failback_and_stranded(tmp_path, capsys):
    wd = str(tmp_path)
    base = ["failover", "--event", "huntress", "--workdir", wd]
    quota.record(tmp_path, "claude", "weekly", used_pct=10, by="t")
    quota.record(tmp_path, "codex", "weekly", used_pct=10, by="t")
    rc, out, _ = _ctf(base + ["check"], capsys)
    assert rc == 0 and out.startswith("STAY: active claude, should hold the lanes: claude (6 lane(s);")
    quota.record(tmp_path, "claude", "weekly", exhausted=True, by="t")
    rc, out, _ = _ctf(base + ["check"], capsys)
    assert rc == 3 and out.startswith("FAILOVER: active claude, should hold the lanes: codex")
    assert "switch --to codex" in out and "codex was never rehearsed live" in out
    rc, out, _ = _ctf(base + ["switch", "--to", "codex", "--by", "t", "--reason", "claude out"], capsys)
    assert rc == 0 and "recorded failover: claude -> codex" in out
    rc, out, _ = _ctf(base + ["check"], capsys)
    assert rc == 0 and out.startswith("STAY: active codex")
    rc, _o, err = _ctf(base + ["switch", "--to", "codex", "--by", "t", "--reason", "again"], capsys)
    assert rc == 2 and "already holds the lanes" in err
    quota.record(tmp_path, "claude", "weekly", used_pct=5, by="t")
    rc, out, _ = _ctf(base + ["check", "--json"], capsys)
    d = json.loads(out)
    assert rc == 3 and (d["action"], d["target"], d["active"]) == ("failback", "claude", "codex")
    assert any("switch --to claude" in s for s in d["steps"])
    quota.record(tmp_path, "claude", "weekly", exhausted=True, by="t")
    quota.record(tmp_path, "codex", "weekly", exhausted=True, by="t")
    rc, out, _ = _ctf(base + ["check"], capsys)
    assert rc == 1 and out.startswith("STRANDED")


def test_cli_lanes_flag_changes_what_must_be_funded(tmp_path, capsys):
    base = ["failover", "--event", "huntress", "--workdir", str(tmp_path)]
    quota.record(tmp_path, "claude", "weekly", used_pct=70, by="t")
    quota.record(tmp_path, "codex", "weekly", used_pct=10, by="t")
    assert _ctf(base + ["check", "--lanes", "1"], capsys)[0] == 0
    assert _ctf(base + ["check"], capsys)[0] == 3                       # huntress: 6 lanes


def test_cli_rehearse_and_status(tmp_path, stub, capsys, monkeypatch):
    monkeypatch.setenv("STUB_PLAN", json.dumps({"crypto": "wrong"}))
    base = ["failover", "--event", "huntress", "--workdir", str(tmp_path)]
    rc, out, _ = _ctf(base + ["rehearse", "--to", "codex", "--by", "t", "--bin", str(stub), "--lanes", "web,crypto",
                              "--deadline", "60", "--json"], capsys)
    rep = json.loads(out)
    assert rc == 1 and rep["held"] is False and rep["failed"] == ["crypto wrong"] and rep["deadline_s"] == 60.0
    monkeypatch.setenv("STUB_PLAN", "{}")
    rc, out, _ = _ctf(base + ["rehearse", "--to", "codex", "--by", "t", "--bin", str(stub), "--lanes", "web"], capsys)
    assert rc == 0 and "rehearsal onto codex, stub (mechanics only): HELD" in out
    rc, out, _ = _ctf(base + ["status"], capsys)
    assert rc == 0 and "active: claude" in out and "onto codex: stub rehearsal HELD" in out \
        and "onto claude: never rehearsed" in out and "WARN  failover:" in out
    rc, out, _ = _ctf(base + ["status", "--json"], capsys)
    st = json.loads(out)
    assert st["last_rehearsal"]["codex"]["held"] is True and st["check"]["status"] == "warn"


def test_cli_rehearse_with_the_real_cli_is_a_named_error(tmp_path, capsys):
    real = tmp_path / "codex"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    rc, _o, err = _ctf(["failover", "--event", "huntress", "--workdir", str(tmp_path / "wd"), "rehearse", "--to",
                        "codex", "--by", "t", "--bin", str(real)], capsys)
    assert rc == 2 and err.startswith("ctf failover:") and "pass --live" in err
    rc, _o, err = _ctf(["failover", "--event", "huntress", "--workdir", str(tmp_path / "wd"), "rehearse", "--to",
                        "codex", "--by", "t", "--bin", str(real), "--live"], capsys)
    assert rc == 2 and "refused under CTF_TESTING" in err


def test_cli_unknown_event_is_a_named_error(tmp_path, capsys):
    rc, _o, err = _ctf(["failover", "--event", "no-such-event", "--workdir", str(tmp_path), "check"], capsys)
    assert rc == 2 and err.startswith("ctf failover:")


# ------------------------------------------------------------------ quota.funded_at is the public trigger helper

def test_quota_funded_at_is_public_and_believes_a_named_reset():
    rel = T0 + 3 * H                                                     # the noon release
    st = lambda rs: snap(rs).harnesses["claude"]                         # noqa: E731
    assert quota.funded_at(st([]), rel) is True                          # no reading: unmetered, funded
    hit = st([R("claude", "weekly", exhausted=True, resets=T0 + 2 * H)])
    assert quota.funded_at(hit, rel) is True and quota.funded_at(hit, T0 + 1 * H) is False
    assert quota.funded_at(hit, T0 + 2 * H) is True                      # the reset itself counts
    full = st([R("claude", "weekly", 95, resets=T0 + 4 * H)])            # 95% + 10% margin: over 100
    assert quota.funded_at(full, rel) is False and quota.funded_at(full, T0 + 4 * H) is True
    assert quota.funded_at(st([R("claude", "weekly", 50)]), rel) is True
    assert not hasattr(quota, "_funded_at")                              # one name, not a private twin


# ------------------------------------------------------------------ pruning rehearsal lane folders

def _run_dir(wd, stamp, harness, hexs="abc123"):
    d = wd / failover.REHEARSAL_DIR / f"{stamp}-{harness}-{hexs}"
    (d / "web").mkdir(parents=True)
    (d / "web" / "task.txt").write_text("x")
    return d


def test_prune_keeps_the_newest_runs_per_harness_and_touches_nothing_else(tmp_path):
    wd = tmp_path / "wd"
    c1 = _run_dir(wd, "20261101T090000", "codex")
    c2 = _run_dir(wd, "20261102T090000", "codex")
    c3 = _run_dir(wd, "20261103T090000", "codex", "0f0f0f")
    k1 = _run_dir(wd, "20261101T100000", "claude")
    k2 = _run_dir(wd, "20261105T100000", "claude")
    base = wd / failover.REHEARSAL_DIR
    (base / "notes").mkdir()                                             # not a run folder: left alone
    (base / "20261101T090000-gemini-abc123").mkdir()                     # unknown harness: left alone
    (base / "README.txt").write_text("keep me")
    outside = tmp_path / "outside-20261101T080000"
    outside.mkdir()
    (outside / "precious").write_text("x")
    (base / "20261101T080000-codex-dead00").symlink_to(outside)          # a symlink is never followed
    assert failover.rehearsal_runs(wd) == [c1, k1, c2, c3, k2]
    by_name = lambda ps: sorted(ps, key=lambda p: p.name)                # noqa: E731
    assert failover.prune_rehearsals(wd, keep=4) == []                   # 3 codex runs, keep 4: none go
    assert failover.rehearsal_runs(wd) == [c1, k1, c2, c3, k2]
    assert failover.prune_rehearsals(wd, keep=1, dry_run=True) == by_name([c1, c2, k1])
    assert c1.exists() and c2.exists() and k1.exists()                   # a dry run removes nothing
    assert failover.prune_rehearsals(wd, keep=1) == by_name([c1, c2, k1])
    assert not c1.exists() and not c2.exists() and not k1.exists()
    assert c3.exists() and k2.exists()
    assert (base / "notes").is_dir() and (base / "README.txt").read_text() == "keep me"
    assert (base / "20261101T090000-gemini-abc123").is_dir() and (outside / "precious").exists()
    assert (base / "20261101T080000-codex-dead00").is_symlink()
    assert failover.prune_rehearsals(wd, keep=5) == []                   # keep past the count removes nothing
    assert c3.exists() and k2.exists()
    assert failover.prune_rehearsals(wd, keep=0) == by_name([c3, k2])
    assert failover.rehearsal_runs(wd) == [] and (outside / "precious").exists()


def test_prune_keeps_the_ledger_records(tmp_path, stub):
    p = prof()
    for _ in range(2):
        failover.rehearse(p, "codex", by="t", workdir=tmp_path, bin=str(stub), environ=_env(), lanes=["web"],
                          deadline_s=60)
    runs = failover.rehearsal_runs(tmp_path)
    assert len(runs) == 2 and all(Path(r.parent.parent) == tmp_path for r in runs)
    before = list(ledger.read(tmp_path))
    assert failover.prune_rehearsals(tmp_path, keep=1) == [runs[0]]
    assert failover.rehearsal_runs(tmp_path) == [runs[1]]
    assert list(ledger.read(tmp_path)) == before


@pytest.mark.parametrize("bad", [-1, 1.5, True, "1"])
def test_prune_refuses_a_bad_keep(tmp_path, bad):
    _run_dir(tmp_path, "20261101T090000", "codex")
    with pytest.raises(failover.FailoverError, match="keep must be"):
        failover.prune_rehearsals(tmp_path, keep=bad)
    assert len(failover.rehearsal_runs(tmp_path)) == 1


def test_prune_refuses_a_symlinked_rehearsal_folder_and_is_empty_without_one(tmp_path):
    assert failover.prune_rehearsals(tmp_path / "none", keep=0) == []
    elsewhere = tmp_path / "elsewhere"
    _run_dir(elsewhere, "20261101T090000", "codex")
    wd = tmp_path / "wd"
    wd.mkdir()
    (wd / failover.REHEARSAL_DIR).symlink_to(elsewhere / failover.REHEARSAL_DIR)
    with pytest.raises(failover.FailoverError, match="is a symlink"):
        failover.prune_rehearsals(wd, keep=0)
    assert len(failover.rehearsal_runs(elsewhere)) == 1


def test_cli_prune(tmp_path, capsys):
    a = _run_dir(tmp_path, "20261101T090000", "codex")
    b = _run_dir(tmp_path, "20261102T090000", "codex")
    base = ["failover", "--event", "huntress", "--workdir", str(tmp_path), "prune"]
    rc, out, _ = _ctf(base + ["--dry-run", "--json"], capsys)
    assert rc == 0 and json.loads(out) == {"dry_run": True, "keep": 1, "removed": [str(a)]} and a.exists()
    rc, out, _ = _ctf(base, capsys)
    assert rc == 0 and out.startswith("removed 1 rehearsal run folder(s)") and str(a) in out
    assert not a.exists() and b.exists()
    rc, _o, err = _ctf(base + ["--keep", "-1"], capsys)
    assert rc == 2 and "keep must be" in err and b.exists()
