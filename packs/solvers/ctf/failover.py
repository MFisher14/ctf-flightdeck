"""Harness failover for release mornings (B-170): the budget meter's trigger, the switch record, the
runbook steps, and a rehearsal that turns "can the other harness hold every lane?" into a yes or a no.

    from ctf import failover
    d = failover.decide(quota.snapshot(profile, workdir=wd), primary="claude",
                        active=failover.active(wd, "claude"), lanes=6, records=ledger.read(wd))
    d.action                      # stay | failover | failback | stranded
    failover.steps(d, profile)    # the runbook steps for that action, as commands to run
    failover.switch(wd, "codex", by="max", reason=d.trigger)      # a failover.switch ledger record
    rep = failover.rehearse(profile, "codex", workdir=wd, by="max", live=True)   # one session per lane
    failover.check(profile, workdir=wd)                           # the doctor's "failover" check
    failover.prune_rehearsals(wd, keep=1)                         # lane folders: newest run per harness

Why. At Huntress, Claude's usage limit forced work onto Codex mid-event on at least two days ("Claude
limit doesn't reset til 1:50p", "Claude is out of tokens for the day"), and no failover had ever been
tried for a release morning ("I want to test having codex run everything"). The runbook is
docs/runbooks/harness-failover.md; this module is the part of it a machine can do.

The trigger is the B-171 quota meter (ctf.quota). `readiness()` asks two questions of one harness:
  now         can it take `lanes` release jobs at once right now? (quota.schedule of that many
              "release" jobs pinned to it; a harness in probe state is not ready: one probe job may go
              there, not a release)
  at_release  is it funded at the next release (quota's own test: a named reset is believed)?
A harness with no reading at all counts as ready (unmetered) and the decision says so.

`decide()` keeps the primary harness while it is ready now and at the release; else moves to the other
harness when that one is ready now (warning when the primary is funded again by the release, so the
failback is planned); else `stranded` (naming any harness funded again by the release). A harness that
can take the lanes now is also funded at the release as far as the meter knows, so `at_release` adds
information only when `now` is no: a limit that resets before the release.
The action compares that target with the active harness (the last `failover.switch` record, else the
primary): `stay` (no change), `failover` (off the primary), `failback` (back to the primary: the reverse
path), `stranded` (no harness can take release work now: the no-model paths keep running).

Whether the other harness can actually hold every lane is the unknown the hard-tail entry names.
`rehearse()` answers it: it writes one synthetic smoke task per lane (a flag in the event format,
encoded a different simple way per lane), starts one agent per lane at once through the fenced
launcher of the target harness (tools/codex_launch, tools/claude_launch: the same path a real lane
uses), and checks each lane's result file against its flag within `deadline_s`. The task is a smoke
test of the path (launch, fence, workspace, prompt, result, wall time at release fan-out), not of solving
skill. With `live=False` the harness binary must be a stub carrying STUB_MARKER (the mechanics only);
`live=True` runs the real CLI, one model session per lane, and is refused under CTF_TESTING. Every
rehearsal is recorded as a `failover.rehearsal` ledger record; `check()` (the doctor) warns until both
directions have a live rehearsal that held, and names the lanes of one that did not. The lane folders
are kept for inspection until `prune_rehearsals()` (`ctf failover prune`) removes all but the newest
run per harness; the ledger records are never pruned.

Nothing here switches by itself: `active()` is read by `ctf failover check/status` only. The dispatcher
(B-004), the escalation roster (B-016) and the launchers do not consult it yet (follow-up `B-170-F1` in
BUILD-PLAN.md: it needs a model-to-harness map, see docs/build-log/B-170.md).
"""
from __future__ import annotations

import base64
import codecs
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from . import ledger as _ledger
from . import paths as _paths
from . import quota as _quota
from .event import EventProfile

HARNESSES = _quota.HARNESSES
ACTIONS = ("stay", "failover", "failback", "stranded")
SWITCH_EVENT = "failover.switch"
REHEARSAL_EVENT = "failover.rehearsal"
STUB_MARKER = "ctf-harness-stub"      # a rehearsal without --live needs a harness binary carrying this
STUB_MARKER_WINDOW = 4096
LAUNCHERS = {"claude": "tools/claude_launch", "codex": "tools/codex_launch"}
BIN_ENV = {"claude": "CLAUDE_BIN", "codex": "CODEX_BIN"}
DEFAULT_LANES = ("web", "crypto", "forensics", "reverse", "pwn", "misc")
DEFAULT_DEADLINE_S = 300.0            # a lane must answer within this to count as held at release speed
REHEARSAL_DIR = "failover-rehearsal"
TASK_NAME = "task.txt"
RESULT_NAME = "result.txt"
LOG_NAME = "launch.log"
LANE_STATUSES = ("pass", "wrong", "no-result", "timeout", "launch-error")
ENCODINGS = ("base64", "hex", "rot13", "reversed", "base32", "xor-0x2a-hex")
POLL_S = 0.05


class FailoverError(ValueError):
    """A failover request or rehearsal cannot run as given; the message names what and why."""


def other(harness: str) -> str:
    if harness not in HARNESSES:
        raise FailoverError(f"unknown harness {harness!r} (one of {', '.join(HARNESSES)})")
    return next(h for h in HARNESSES if h != harness)


# ------------------------------------------------------------------ readiness and the decision

@dataclass(frozen=True)
class Readiness:
    harness: str
    now: bool                        # can take `lanes` release jobs at once right now
    at_release: bool                 # funded at the next release (or now, with no release ahead)
    status: str                      # the meter's harness status: ok | unmetered | exhausted | probe
    why: str                         # why not, or a note ("" when ready and metered)

    @property
    def ready(self) -> bool:
        return self.now and self.at_release

    def to_dict(self) -> dict:
        return asdict(self)


def readiness(snap: _quota.Snapshot, harness: str, *, lanes: int = 1, est_pct: float | None = None) -> Readiness:
    """Whether `harness` alone can take `lanes` release jobs now, and is funded at the next release."""
    if harness not in snap.harnesses:
        raise FailoverError(f"unknown harness {harness!r} (one of {', '.join(HARNESSES)})")
    if not isinstance(lanes, int) or isinstance(lanes, bool) or lanes < 1:
        raise FailoverError(f"lanes must be a whole number >= 1, got {lanes!r}")
    jobs = [_quota.Job(f"lane-{i + 1}", "release", (harness,), None, est_pct) for i in range(lanes)]
    plan = _quota.schedule(snap, jobs)
    s = snap.harnesses[harness]
    reasons = []
    probes = [a for a in plan.assigned if a.mode == "probe"]
    now_ok = not plan.held and not probes
    if probes:
        reasons.append(f"{harness} is past a limit hit's recheck time: send one probe job, not the release")
    if plan.held:
        hd = plan.held[0]
        reasons.append(f"{len(plan.held)}/{lanes} lane(s) held: {hd.reasons.get(harness, '')}"
                       + (f" (opens {_quota.fmt_time(hd.release_at)})" if hd.release_at else ""))
    at = snap.next_release if snap.next_release is not None else snap.now
    rel_ok = _quota.funded_at(s, at)
    if not rel_ok:
        reasons.append(f"{harness} is not funded at {'the release ' if snap.next_release is not None else ''}"
                       f"{_quota.fmt_time(at)}")
    if s.status == "unmetered":
        reasons.append(f"{harness} has no usable quota reading (unmetered: counted as ready)")
    return Readiness(harness, now_ok, rel_ok, s.status, "; ".join(r for r in reasons if r))


@dataclass(frozen=True)
class Decision:
    action: str                      # stay | failover | failback | stranded
    primary: str
    active: str                      # the harness holding the lanes now (last switch, else the primary)
    target: str | None               # the harness that should hold them (None: stranded)
    trigger: str                     # what in the meter decided it
    now: float
    next_release: float | None
    ready: dict                      # {harness: Readiness}
    warnings: tuple = ()

    @property
    def switch(self) -> bool:
        return self.action in ("failover", "failback")

    def to_dict(self) -> dict:
        return {"action": self.action, "primary": self.primary, "active": self.active, "target": self.target,
                "trigger": self.trigger, "now": self.now, "next_release": self.next_release,
                "ready": {h: r.to_dict() for h, r in self.ready.items()}, "warnings": list(self.warnings)}


def decide(snap: _quota.Snapshot, *, primary: str = "claude", active: str | None = None, lanes: int = 1,
           est_pct: float | None = None, records: Iterable[dict] | None = None) -> Decision:
    """Which harness should hold the lanes, and what to do about it (see the module doc). `records`
    (the event ledger) adds what the last rehearsal of the target harness found."""
    o = other(primary)
    active = primary if active is None else active
    if active not in HARNESSES:
        raise FailoverError(f"unknown active harness {active!r}")
    rp = readiness(snap, primary, lanes=lanes, est_pct=est_pct)
    ro = readiness(snap, o, lanes=lanes, est_pct=est_pct)
    warns = []
    if rp.ready:
        target, trigger = primary, f"{primary} (primary) is ready now and at the release"
        if rp.why:
            trigger += f" ({rp.why})"
    elif ro.now:
        target, trigger = o, f"{primary} (primary) cannot hold the release: {rp.why}"
        if rp.at_release and snap.next_release is not None:
            warns.append(f"{primary} is funded again by the release at {_quota.fmt_time(snap.next_release)}: "
                         "fail back before it when the check says so")
    else:
        target, trigger = None, f"no harness can take release work now: {primary}: {rp.why}; {o}: {ro.why}"
        later = [h for h, r in ((primary, rp), (o, ro)) if r.at_release and snap.next_release is not None]
        if later:
            warns.append(f"funded again by the release at {_quota.fmt_time(snap.next_release)}: "
                         + ", ".join(later))
    if target is None:
        action = "stranded"
    elif target == active:
        action = "stay"
    else:
        action = "failback" if target == primary else "failover"
    if target is not None and target != primary and records is not None:
        warns.extend(rehearsal_warnings(records, target))
    return Decision(action, primary, active, target, trigger, snap.now, snap.next_release,
                    {primary: rp, o: ro}, tuple(warns))


# ------------------------------------------------------------------ the switch record

def active(workdir: Path | None, primary: str = "claude", records: Iterable[dict] | None = None) -> str:
    """The harness holding the lanes: the newest `failover.switch` record's harness, else the primary."""
    other(primary)                                   # validates
    last = last_switch(workdir, records)
    return last["harness"] if last is not None else primary


def last_switch(workdir: Path | None, records: Iterable[dict] | None = None) -> dict | None:
    recs = _ledger.read(workdir) if records is None else records
    best = None
    for r in recs:
        if r.get("event") == SWITCH_EVENT and r.get("harness") in HARNESSES:
            if best is None or float(r.get("ts") or 0) >= float(best.get("ts") or 0):
                best = r
    return best


def switch(workdir: Path | None, to: str, *, by: str, reason: str, primary: str = "claude",
           records: Iterable[dict] | None = None) -> dict:
    """Record that `to` now holds the lanes (a `failover.switch` ledger record). Refuses a switch to the
    harness already active, so a repeated command cannot hide which switch happened when."""
    if not isinstance(by, str) or not by.strip():
        raise FailoverError("a switch must name who made it (by=...)")
    if not isinstance(reason, str) or not reason.strip():
        raise FailoverError("a switch needs a reason (the trigger from `ctf failover check`)")
    other(to)
    cur = active(workdir, primary, records)
    if cur == to:
        raise FailoverError(f"{to} already holds the lanes (active since the last switch or as primary)")
    action = "failback" if to == primary else "failover"
    return _ledger.append(SWITCH_EVENT, workdir=workdir, harness=to, from_harness=cur, action=action,
                          primary=primary, by=by, reason=reason)


# ------------------------------------------------------------------ the runbook steps

RUNBOOK = "docs/runbooks/harness-failover.md"


def steps(d: Decision, profile: EventProfile, *, workdir: Path | None = None) -> list[str]:
    """The runbook steps for this decision, with the event filled in (docs/runbooks/harness-failover.md
    is the full text). Each step is one line; commands are in backticks."""
    slug = profile.slug
    wd = str(workdir) if workdir is not None else "<workdir>"
    if d.action == "stay":
        return [f"No switch: {d.active} keeps the lanes. Re-run `python -m ctf failover --event {slug} check` "
                "after every `python -m ctf quota scan`, and before each release."]
    if d.action == "stranded":
        return [f"No harness can take release work: `python -m ctf quota --event {slug} status` shows each "
                "window and when it resets or is re-probed.",
                f"Keep the no-model paths running: `python -m ctf dispatch --event {slug} run` (claims, "
                "intake, Layer-1 openers, auto-submit) needs no model.",
                "Hold solve and build work; writeups wait too. Send one probe job to a harness when "
                f"`python -m ctf quota --event {slug} gate --kind release` says it may go.",
                f"When a harness opens, run `python -m ctf failover --event {slug} check` again."]
    to = d.target
    out = [f"Record the switch: `python -m ctf failover --event {slug} switch --to {to} --by <you> "
           f"--reason \"{_one_line(d.trigger)}\"`.",
           f"Install the agent rules where {to} loads them ({'AGENTS.md' if to == 'codex' else 'CLAUDE.md'}): "
           f"`python -m ctf new-event {slug} --regen --workdir {wd}`."]
    if to == "codex":
        out += ["Move the orchestrator to a Codex session in the workdir: "
                f"`tools/codex_launch --event {slug} --workspace {wd} --interactive`.",
                "Start each claimed lane on Codex with its handout as the prompt: "
                f"`python -m ctf dispatch --event {slug} show <id> | tools/codex_launch --event {slug} "
                "--challenge <id> --model <codex-model> -`.",
                "Give escalation models that can run: "
                f"`python -m ctf escalate --event {slug} run --model <codex-model> --model <second-codex-model>`."]
    else:
        out += ["Move the orchestrator to a Claude Code session in the workdir: "
                f"`tools/claude_launch --event {slug} --workspace {wd}`.",
                "Start each claimed lane on Claude with its handout as the prompt: "
                f"`tools/claude_launch --event {slug} --challenge <id> -- -p \"$(python -m ctf dispatch --event {slug} "
                f"show <id>)\"`. Stop Codex handoffs (tools/codex_handoff.sh) until Codex is back.",
                "Give escalation models that can run: "
                f"`python -m ctf escalate --event {slug} run --model {profile.models.primary}`."]
    out += ["Submitting does not change: every agent submits on sight through `python -m ctf submit` (the "
            "gate and queue are the same for both harnesses).",
            f"Watch for the way back: re-run `python -m ctf failover --event {slug} check` after each "
            "`python -m ctf quota scan`; it answers `failback` when the primary is ready again."]
    for w in d.warnings:
        out.append(f"Warning: {w}")
    return out


def _one_line(s: str, limit: int = 160) -> str:
    s = " ".join(str(s).split()).replace('"', "'")
    return s if len(s) <= limit else s[:limit - 3] + "..."


# ------------------------------------------------------------------ rehearsal records

def rehearsals(records: Iterable[dict], harness: str | None = None, *, live: bool | None = None) -> list[dict]:
    """`failover.rehearsal` records, oldest first, optionally for one target harness and live or not."""
    out = [r for r in records if r.get("event") == REHEARSAL_EVENT
           and (harness is None or r.get("harness") == harness)
           and (live is None or bool(r.get("live")) == live)]
    return sorted(out, key=lambda r: float(r.get("ts") or 0))


def _failed_lanes(rec: Mapping) -> list[str]:
    dl = float(rec.get("deadline_s") or 0)
    bad = []
    for ln in rec.get("lanes") or []:
        st = ln.get("status")
        if st != "pass":
            bad.append(f"{ln.get('lane')} {st}")
        elif dl and float(ln.get("seconds") or 0) > dl:
            bad.append(f"{ln.get('lane')} slow ({float(ln.get('seconds')):.0f}s > {dl:g}s)")
    return bad


def rehearsal_warnings(records: Iterable[dict], harness: str) -> list[str]:
    """What the rehearsals of `harness` say about it holding every lane ([] when a live one held)."""
    recs = list(records)
    live = rehearsals(recs, harness, live=True)
    if not live:
        mech = rehearsals(recs, harness, live=False)
        tail = (f" (a stub rehearsal of the mechanics {'held' if mech[-1].get('held') else 'did not hold'} at "
                f"{_quota.fmt_time(float(mech[-1].get('ts') or 0))})" if mech else "")
        return [f"{harness} was never rehearsed live: whether it holds every lane at release speed is "
                f"unknown{tail}"]
    last = live[-1]
    if last.get("held"):
        return []
    return [f"{harness}'s last live rehearsal ({_quota.fmt_time(float(last.get('ts') or 0))}) did not hold: "
            + ", ".join(_failed_lanes(last) or ["no lane result"])]


def check(profile: EventProfile, *, workdir: Path | None = None):
    """The doctor's "failover" check: has each direction (onto Claude, onto Codex) a live rehearsal that
    held? ok when both have; warn naming what is missing or which lanes did not hold; fail when the
    ledger cannot be read."""
    from .doctor import Check
    wd = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
    try:
        recs = list(_ledger.read(wd))
    except (ValueError, OSError) as e:
        return Check("failover", "fail", f"cannot read the ledger: {e}", "move the corrupt ledger aside")
    warns, oks = [], []
    for h in HARNESSES:
        w = rehearsal_warnings(recs, h)
        if w:
            warns.extend(w)
        else:
            last = rehearsals(recs, h, live=True)[-1]
            oks.append(f"onto {h}: live rehearsal held ({len(last.get('lanes') or [])} lanes, "
                       f"{float(last.get('wall_s') or 0):.0f}s, {_quota.fmt_time(float(last.get('ts') or 0))})")
    if warns:
        fix = "; ".join(f"`python -m ctf failover --event {profile.slug} rehearse --to {h} --live --by <you>`"
                        for h in HARNESSES if rehearsal_warnings(recs, h))
        return Check("failover", "warn", "; ".join(oks + warns),
                     fix + f" (one model session per lane; runbook {RUNBOOK})")
    return Check("failover", "ok", "; ".join(oks))


# ------------------------------------------------------------------ the rehearsal

def profile_lanes(profile: EventProfile) -> tuple[str, ...]:
    """The event's lanes: its announced categories, canonicalised as the router does, else DEFAULT_LANES."""
    from .triage import canonical_category
    out: list[str] = []
    for c in profile.categories:
        lane = re.sub(r"[^a-z0-9_]+", "-", canonical_category(c)).strip("-") or "misc"
        if lane not in out:
            out.append(lane)
    return tuple(out) or DEFAULT_LANES


def encode(flag: str, encoding: str) -> str:
    if encoding == "base64":
        return base64.b64encode(flag.encode()).decode()
    if encoding == "hex":
        return flag.encode().hex()
    if encoding == "rot13":
        return codecs.encode(flag, "rot13")
    if encoding == "reversed":
        return flag[::-1]
    if encoding == "base32":
        return base64.b32encode(flag.encode()).decode()
    if encoding == "xor-0x2a-hex":
        return bytes(b ^ 0x2A for b in flag.encode()).hex()
    raise FailoverError(f"unknown encoding {encoding!r} (one of {', '.join(ENCODINGS)})")


def task_text(lane: str, flag: str, encoding: str) -> str:
    return (f"Failover rehearsal task (lane: {lane}). This is a synthetic smoke task, not a challenge.\n"
            f"The value on the next line is the flag, encoded with: {encoding}\n"
            f"{encode(flag, encoding)}\n")


def prompt_text(profile: EventProfile, lane: str) -> str:
    prefix = profile.flag.prefixes[0] if profile.flag.prefixes else "FLAG"
    return (f"Failover rehearsal for event {profile.slug}, lane {lane}: a synthetic smoke task, not a real "
            f"challenge. Read {TASK_NAME} in the current folder. It holds one value, encoded the way it says; "
            f"decoded, it is a flag in the event format ({prefix}{{...}}). Write exactly that flag, alone on "
            f"the first line, to ./{RESULT_NAME}. Do not submit anything, do not use the network, and do not "
            "read outside the current folder.")


@dataclass(frozen=True)
class LaneResult:
    lane: str
    status: str                      # pass | wrong | no-result | timeout | launch-error
    seconds: float
    exit_code: int | None
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RehearsalReport:
    harness: str
    live: bool
    bin: str
    lanes: list = field(default_factory=list)   # [LaneResult]
    wall_s: float = 0.0
    deadline_s: float = DEFAULT_DEADLINE_S
    parallel: int = 0
    root: str = ""

    @property
    def failed(self) -> list[str]:
        return _failed_lanes({"deadline_s": self.deadline_s, "lanes": [ln.to_dict() for ln in self.lanes]})

    @property
    def held(self) -> bool:
        return bool(self.lanes) and not self.failed

    def to_dict(self) -> dict:
        return {"harness": self.harness, "live": self.live, "bin": self.bin, "held": self.held,
                "failed": self.failed, "lanes": [ln.to_dict() for ln in self.lanes], "wall_s": self.wall_s,
                "deadline_s": self.deadline_s, "parallel": self.parallel, "root": self.root}


def _resolve_bin(raw: str, env: Mapping[str, str]) -> str | None:
    if os.sep in raw:
        p = Path(raw).expanduser()
        return str(p.resolve()) if p.is_file() else None
    return shutil.which(raw, path=env.get("PATH", os.defpath))


def _has_marker(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return STUB_MARKER.encode() in fh.read(STUB_MARKER_WINDOW)
    except OSError:
        return False


def guard_bin(harness: str, raw: str, *, live: bool, env: Mapping[str, str]) -> str:
    """The resolved harness binary, or FailoverError: a missing binary; a stub under --live; the real
    CLI (no STUB_MARKER, or the harness CLI on PATH) without --live; any live run under CTF_TESTING."""
    path = _resolve_bin(raw, env)
    if path is None:
        raise FailoverError(f"{harness} binary {raw!r} not found (set {BIN_ENV[harness]} or --bin)")
    stub = _has_marker(path)
    cli = shutil.which(harness, path=env.get("PATH", os.defpath))
    is_cli = cli is not None and os.path.realpath(cli) == os.path.realpath(path)
    if live:
        if env.get("CTF_TESTING"):
            raise FailoverError("a live rehearsal starts real model sessions: refused under CTF_TESTING")
        if stub:
            raise FailoverError(f"--live names a stub ({path} carries {STUB_MARKER!r}): a stub run rehearses "
                                "the mechanics only; drop --live")
        return path
    if is_cli or not stub:
        raise FailoverError(f"{path} is the real {harness} CLI (no {STUB_MARKER!r} marker in its first "
                            f"{STUB_MARKER_WINDOW} bytes{', and it is the one on PATH' if is_cli else ''}): a "
                            "rehearsal with it starts one model session per lane; pass --live to mean that")
    return path


def lane_command(profile: EventProfile, harness: str, lane_dir: Path, prompt: str, *, bin: str,
                 model: str | None = None, python: str = sys.executable, repo: Path | None = None) -> list[str]:
    """The fenced launch of one lane: the same launcher a real lane uses."""
    repo = _paths.repo_root() if repo is None else Path(repo)
    launcher = str(repo / LAUNCHERS[harness])
    base = [python, launcher, "--event", profile.slug, "--workspace", str(lane_dir)]
    if harness == "codex":
        return base + ["--codex-bin", bin] + (["--model", model] if model else []) + [prompt]
    return (base + ["--claude-bin", bin, "--", "-p", prompt, "--permission-mode", "acceptEdits"]
            + (["--model", model] if model else []))


def rehearse(profile: EventProfile, harness: str, *, by: str, workdir: Path | None = None,
             lanes: Iterable[str] | None = None, live: bool = False, bin: str | None = None,
             model: str | None = None, parallel: int | None = None, deadline_s: float = DEFAULT_DEADLINE_S,
             timeout_s: float | None = None, environ: Mapping[str, str] | None = None,
             record: bool = True, python: str = sys.executable, repo: Path | None = None) -> RehearsalReport:
    """Run one synthetic lane per lane on `harness`, all at once by default (release fan-out), through the
    fenced launcher; check each result against its flag. Records a `failover.rehearsal` ledger record."""
    if not isinstance(by, str) or not by.strip():
        raise FailoverError("a rehearsal must name who ran it (by=...)")
    other(harness)
    env = dict(os.environ if environ is None else environ)
    env.pop("CTF_CHALLENGE", None)          # a rehearsal lane is not a challenge: the budget gate stays off
    raw = bin or env.get(BIN_ENV[harness]) or harness
    path = guard_bin(harness, raw, live=live, env=env)
    lane_names = tuple(lanes) if lanes is not None else profile_lanes(profile)
    if not lane_names:
        raise FailoverError("no lanes to rehearse")
    if len(set(lane_names)) != len(lane_names) or any(not ln or "/" in ln or ln.startswith(".") for ln in lane_names):
        raise FailoverError(f"lanes must be distinct plain names, got {list(lane_names)}")
    if not deadline_s or deadline_s <= 0:
        raise FailoverError(f"deadline_s must be > 0, got {deadline_s!r}")
    timeout = float(timeout_s) if timeout_s is not None else 2.0 * deadline_s
    if timeout <= 0:
        raise FailoverError(f"timeout_s must be > 0, got {timeout_s!r}")
    par = len(lane_names) if parallel is None else int(parallel)
    if par < 1:
        raise FailoverError(f"parallel must be >= 1, got {parallel!r}")
    from .doctor import synth_flag
    wd = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
    root = wd / REHEARSAL_DIR / f"{time.strftime('%Y%m%dT%H%M%S')}-{harness}-{secrets.token_hex(3)}"
    lanes_todo = []
    for i, lane in enumerate(lane_names):
        d = root / lane
        d.mkdir(parents=True)
        flag = synth_flag(profile, token=secrets.token_hex(4))
        enc = ENCODINGS[i % len(ENCODINGS)]
        (d / TASK_NAME).write_text(task_text(lane, flag, enc), encoding="utf-8")
        cmd = lane_command(profile, harness, d, prompt_text(profile, lane), bin=path, model=model,
                           python=python, repo=repo)
        lanes_todo.append((lane, d, flag, cmd))
    results, wall = _run_lanes(lanes_todo, env, par, timeout)
    rep = RehearsalReport(harness, live, path, [results[ln] for ln, *_ in lanes_todo], round(wall, 3),
                          float(deadline_s), par, str(root))
    if record:
        _ledger.append(REHEARSAL_EVENT, workdir=wd, harness=harness, live=bool(live), held=rep.held,
                       lanes=[ln.to_dict() for ln in rep.lanes], wall_s=rep.wall_s, deadline_s=rep.deadline_s,
                       parallel=par, by=by)
    return rep


RUN_DIR_RE = re.compile(r"^(\d{8}T\d{6})-(" + "|".join(HARNESSES) + r")-[0-9a-f]{6}$")


def rehearsal_runs(workdir: Path) -> list[Path]:
    """The rehearsal run folders under <workdir>/failover-rehearsal/, oldest first. Only real folders
    named as `rehearse` names them (<stamp>-<harness>-<hex>) count; anything else there is left alone."""
    base = Path(workdir) / REHEARSAL_DIR
    if base.is_symlink():
        raise FailoverError(f"{base} is a symlink: refusing to list or prune through it")
    if not base.is_dir():
        return []
    runs = [p for p in base.iterdir() if RUN_DIR_RE.match(p.name) and p.is_dir() and not p.is_symlink()]
    return sorted(runs, key=lambda p: (RUN_DIR_RE.match(p.name).group(1), p.stat().st_mtime, p.name))


def prune_rehearsals(workdir: Path, *, keep: int = 1, dry_run: bool = False) -> list[Path]:
    """Remove all but the newest `keep` rehearsal run folders per harness (0 removes them all); the
    ledger records stay, so the doctor's check is unchanged. Returns the folders removed (or, with
    `dry_run`, the ones that would be). Symlinks and folders not named by `rehearse` are never touched."""
    if not isinstance(keep, int) or isinstance(keep, bool) or keep < 0:
        raise FailoverError(f"keep must be a whole number >= 0, got {keep!r}")
    by_h: dict[str, list[Path]] = {}
    for p in rehearsal_runs(workdir):
        by_h.setdefault(RUN_DIR_RE.match(p.name).group(2), []).append(p)
    gone = []
    for runs in by_h.values():
        gone.extend(runs[:max(0, len(runs) - keep)])
    gone.sort(key=lambda p: p.name)
    if not dry_run:
        for p in gone:
            shutil.rmtree(p)
    return gone


def _tail(p: Path, n: int = 300) -> str:
    try:
        t = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return " ".join(t[-n:].split())


def _judge(lane: str, d: Path, flag: str, rc: int | None, secs: float, timed_out: bool) -> LaneResult:
    if timed_out:
        return LaneResult(lane, "timeout", secs, rc, f"no exit within the timeout; log: {_tail(d / LOG_NAME)}")
    res = d / RESULT_NAME
    if not res.is_file():
        if rc:
            return LaneResult(lane, "launch-error", secs, rc, f"exit {rc}, no {RESULT_NAME}: {_tail(d / LOG_NAME)}")
        return LaneResult(lane, "no-result", secs, rc, f"exit {rc}, no {RESULT_NAME}")
    lines = res.read_text(encoding="utf-8", errors="replace").splitlines()
    got = lines[0].strip() if lines else ""
    if got != flag:
        return LaneResult(lane, "wrong", secs, rc, f"{RESULT_NAME} first line is not the lane's flag")
    return LaneResult(lane, "pass", secs, rc, f"exit {rc}" if rc else "")


def _run_lanes(todo, env, parallel: int, timeout: float) -> tuple[dict, float]:
    """Start up to `parallel` lanes at once; each gets `timeout` seconds from its own start. Returns
    ({lane: LaneResult}, wall seconds from the first start to the last exit)."""
    pending = list(todo)
    running: dict = {}
    out: dict = {}
    t0 = time.monotonic()
    while pending or running:
        while pending and len(running) < parallel:
            lane, d, flag, cmd = pending.pop(0)
            log = open(d / LOG_NAME, "wb")
            try:
                proc = subprocess.Popen(cmd, cwd=str(d), env=env, stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, start_new_session=True)
            except OSError as e:
                log.close()
                out[lane] = LaneResult(lane, "launch-error", 0.0, None, f"cannot start the launcher: {e}")
                continue
            running[lane] = (proc, log, d, flag, time.monotonic())
        for lane in list(running):
            proc, log, d, flag, start = running[lane]
            rc = proc.poll()
            secs = time.monotonic() - start
            if rc is None and secs <= timeout:
                continue
            timed_out = rc is None
            if timed_out:
                _kill(proc)
            log.close()
            del running[lane]
            out[lane] = _judge(lane, d, flag, proc.returncode if not timed_out else None, round(secs, 3), timed_out)
        if running:
            time.sleep(POLL_S)
    return out, time.monotonic() - t0


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()
