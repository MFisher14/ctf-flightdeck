"""Harness quota meter, allowance reserve and quota-aware scheduling (B-171).

Plan, spend and weekly limits of Claude Code and Codex cut work mid-flight at three events: a build
paused 71.5 min on a spend limit, a weekly limit hit 7 minutes before a release, Codex usage
exhaustion was the most frequent Codex error, and a Codex "out until <date>" turned out wrong 11
minutes later. This module turns quota readings into a state per harness and window, holds a reserve
for releases, and schedules jobs onto the harness that can take them.

    from ctf import quota
    snap = quota.snapshot(profile, workdir=wd)        # Snapshot: each harness, each window, now
    plan = quota.schedule(snap, [quota.Job("w1", "writeup"), quota.Job("b7", "build")])
    plan.assigned / plan.held / plan.batches          # held jobs grouped by the time they open
    quota.check(profile, workdir=wd)                  # the doctor's "allowance" check
    quota.record(wd, "claude", "weekly", used_pct=62, by="max")   # a reading the player took by hand
    quota.daily(rows, ledger.read(wd), price=..., tz=..., allowance_usd=...)   # the per-day ledger

Readings (Reading) come from three places, newest per (harness, window) wins:
  * the session-log scanner (tools/ledger/quota.py, `python -m ctf quota scan`), which keeps them in
    <workdir>/usage/quota-state.json: Codex `rate_limits` snapshots (used percent, window, reset), the
    limit-hit messages both harnesses log, and the last time each harness served a response;
  * `quota.reading` ledger events, written by record() (`python -m ctf quota set`), for what the player
    reads off the harness's own usage screen;
  * nothing: a harness with no reading is "unmetered" and every plan and the doctor say so.

Window state (WindowState.status):
  ok         a used percentage is known; effective_pct = used + allowance.margin_pct (a reading is not
             trusted to the percent). A window whose reset time has passed counts as reset (margin only).
  unmetered  nothing constrains it that is known: no reading, or a limit hit that a response served
             more than DISPROOF_GRACE_S after it disproved (the PINK+ case: Codex said out for days and
             ran 11 minutes later). A response logged within the grace may have been in flight when
             the limit hit (a dozen agents share an account), so it disproves nothing.
  exhausted  a limit hit (or used >= 100) and neither its reset nor its recheck time has come: no work.
  probe      a limit hit whose recheck time (allowance.recheck_minutes after the hit) has passed though
             the named reset has not: one probe job may go there (PROBE_JOBS) to find out.

The allowance (profile [allowance], ctf.event.Allowance). Limits per job kind, in percent of a window:
writeup, retro and release work may use the whole window (100); solve work stops at 100 - reserve_pct
and build work at min(build_ceiling_pct, that) while the window outlives the next release (its reset
is after the release, or unknown). Next release: the earliest of dates.start, allowance.releases and
allowance.daily_release (every day of the event, in allowance.tz) still ahead.

schedule() takes jobs in kind order (writeups and retros first, then release work, solves, builds;
input order within a kind) and gives each to the harness that fits it: its preferred harness when that
fits, else the one with the most headroom left, then an unmetered harness, then a probe. A job that fits
nowhere is held with the reason per harness and the time it opens (the earliest reset or recheck among
its harnesses); held jobs are grouped into batches by that time, so a waiting orchestrator releases each
batch when its limit resets (`python -m ctf quota wait`).
"""
from __future__ import annotations

import collections
import datetime as _dt
import json
import math
import os
import time
import zoneinfo
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

from . import ledger as _ledger
from . import paths as _paths
from .event import Allowance, EventProfile

HARNESSES = ("claude", "codex")
KINDS = ("writeup", "retro", "release", "solve", "build")
KIND_RANK = {"writeup": 0, "retro": 0, "release": 1, "solve": 2, "build": 3}
DEFAULT_EST_PCT = {"writeup": 1.0, "retro": 1.0, "release": 5.0, "solve": 5.0, "build": 5.0}
RESERVED_KINDS = frozenset({"solve", "build"})   # kinds the pre-release reserve is held back from
STATUSES = ("ok", "unmetered", "exhausted", "probe")
PROBE_JOBS = 1                       # jobs a plan sends to a harness in probe state
STALE_HOURS = 6.0                    # a reading older than this is reported as a lower bound
DISPROOF_GRACE_S = 300.0             # a served response disproves a limit hit only this long after it:
                                     # one logged sooner may have been in flight when the limit hit
READING_EVENT = "quota.reading"
STATE_DIR = "usage"
STATE_NAME = "quota-state.json"
WINDOW_NAMES = {300: "session", 10080: "weekly"}


class QuotaError(ValueError):
    """A reading, job or quota state is not usable as given; the message names what and why."""


# ------------------------------------------------------------------ readings

@dataclass(frozen=True)
class Reading:
    """One observation of a harness quota window. `ts` is when it was observed (epoch seconds)."""
    harness: str
    window: str                      # session | weekly | spend | limit (unnamed) | <n>min | ...
    ts: float
    source: str                      # codex-rate-limits | codex-limit | claude-limit | manual
    used_pct: float | None = None
    resets_at: float | None = None
    exhausted: bool = False          # a limit-hit message: no more work until reset (or a recheck)
    window_minutes: int | None = None
    note: str = ""

    def __post_init__(self):
        if self.harness not in HARNESSES:
            raise QuotaError(f"unknown harness {self.harness!r} (one of {', '.join(HARNESSES)})")
        if not isinstance(self.window, str) or not self.window.strip():
            raise QuotaError("a reading needs a window name")
        if self.used_pct is not None and (not _finite(self.used_pct) or self.used_pct < 0):
            raise QuotaError(f"used_pct must be a number >= 0, got {self.used_pct!r}")
        if self.used_pct is None and not self.exhausted:
            raise QuotaError(f"{self.harness} {self.window}: a reading needs a used percentage or exhausted")
        if self.resets_at is not None and not _finite(self.resets_at):
            raise QuotaError(f"resets_at must be epoch seconds, got {self.resets_at!r}")

    @property
    def full(self) -> bool:
        return self.exhausted or (self.used_pct is not None and self.used_pct >= 100)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping) -> "Reading":
        try:
            return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})
        except TypeError as e:
            raise QuotaError(f"not a quota reading: {e}") from None


def _finite(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _order(r: Reading) -> tuple:
    return (r.ts, r.full, r.used_pct or 0.0)


def merge(into: dict[tuple[str, str], Reading], readings: Iterable[Reading]) -> int:
    """Keep the newest reading per (harness, window) in `into`. Returns how many replaced or added."""
    n = 0
    for r in readings:
        k = (r.harness, r.window)
        cur = into.get(k)
        if cur is None or _order(r) > _order(cur):
            into[k] = r
            n += 1
    return n


def window_name(minutes) -> str | None:
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes <= 0:
        return None
    return WINDOW_NAMES.get(minutes, f"{minutes}min")


# ------------------------------------------------------------------ the stored state

def state_path(workdir: Path) -> Path:
    return Path(workdir) / STATE_DIR / STATE_NAME


def load_state(workdir: Path) -> dict:
    """The scanner's state: {"files": {log: offset info}, "readings": [Reading dicts], "last_ok": {harness:
    epoch}}. A missing file is an empty state; a corrupt one raises QuotaError naming the file."""
    p = state_path(workdir)
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"files": {}, "readings": [], "last_ok": {}}
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise QuotaError(f"{p}: corrupt quota state ({e}); move it aside and run `python -m ctf quota scan`") from None
    if not isinstance(st, dict):
        raise QuotaError(f"{p}: corrupt quota state (not an object)")
    st.setdefault("files", {})
    st.setdefault("readings", [])
    st.setdefault("last_ok", {})
    return st


def save_state(workdir: Path, st: dict) -> Path:
    p = state_path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return p


def record(workdir: Path | None, harness: str, window: str, *, used_pct: float | None = None,
           resets_at: float | None = None, exhausted: bool = False, by: str, note: str | None = None) -> dict:
    """A reading the player took off the harness's own usage screen, as a `quota.reading` ledger event."""
    if not isinstance(by, str) or not by.strip():
        raise QuotaError("a reading must name who took it (by=...)")
    Reading(harness, window, time.time(), "manual", used_pct=used_pct, resets_at=resets_at,
            exhausted=exhausted)                                   # validates
    fields: dict = {"harness": harness, "window": window, "exhausted": bool(exhausted), "by": by}
    if used_pct is not None:
        fields["used_pct"] = float(used_pct)
    if resets_at is not None:
        fields["resets_at"] = float(resets_at)
    if note:
        fields["note"] = note
    return _ledger.append(READING_EVENT, workdir=workdir, **fields)


def readings(workdir: Path, records: Iterable[dict] | None = None) -> tuple[dict[tuple[str, str], Reading], dict[str, float]]:
    """Newest reading per (harness, window) from the scanner state and the ledger, and the last time each
    harness served a response ({harness: epoch})."""
    st = load_state(workdir)
    out: dict[tuple[str, str], Reading] = {}
    merge(out, (Reading.from_dict(d) for d in st["readings"]))
    recs = records if records is not None else _ledger.read(workdir)
    manual = []
    for r in recs:
        if r.get("event") != READING_EVENT:
            continue
        manual.append(Reading(r.get("harness"), r.get("window"), float(r.get("ts") or 0.0), "manual",
                              used_pct=r.get("used_pct"), resets_at=r.get("resets_at"),
                              exhausted=bool(r.get("exhausted")), note=str(r.get("note") or "")))
    merge(out, manual)
    last_ok = {h: float(v) for h, v in (st.get("last_ok") or {}).items() if h in HARNESSES and _finite(v)}
    return out, last_ok


# ------------------------------------------------------------------ releases

def _tz(allowance: Allowance) -> zoneinfo.ZoneInfo:
    return zoneinfo.ZoneInfo(allowance.tz)


def _as_epoch(d: _dt.date | _dt.datetime, tz) -> float:
    if not isinstance(d, _dt.datetime):
        d = _dt.datetime(d.year, d.month, d.day, tzinfo=tz)
    elif d.tzinfo is None:
        d = d.replace(tzinfo=tz)
    return d.timestamp()


def event_span(profile: EventProfile) -> tuple[float, float]:
    """The event's (start, end) as epoch seconds, end exclusive. A naive datetime and a bare date are in
    the [allowance] zone, and a date-only end is the whole last day. The one reading of dates.start and
    dates.end shared by next_release, the no-release warning and the clock line (ctf.clockline)."""
    tz = _tz(profile.allowance)
    start, end = _as_epoch(profile.start, tz), _as_epoch(profile.end, tz)
    if not isinstance(profile.end, _dt.datetime):
        end += 86400.0                       # a date-only end is the whole last day
    return start, end


def next_release(profile: EventProfile, now: float) -> float | None:
    """The earliest release still ahead of `now` (epoch), or None: the event start, each listed release,
    and the daily release on every day from the start to the end of the event."""
    a = profile.allowance
    tz = _tz(a)
    start, end = event_span(profile)
    cands = [start] + [r.timestamp() for r in a.releases]
    if a.daily_release:
        hh, mm = (int(x) for x in a.daily_release.split(":"))
        day = _dt.datetime.fromtimestamp(max(now, start), tz).date()
        for i in range(2):
            d = day + _dt.timedelta(days=i)
            t = _dt.datetime(d.year, d.month, d.day, hh, mm, tzinfo=tz).timestamp()
            if start <= t <= end:
                cands.append(t)
    ahead = [t for t in cands if t > now]
    return min(ahead) if ahead else None


def limit_pct(kind: str, reserved: bool, allowance: Allowance) -> float:
    """How much of a window a job of `kind` may bring it to. `reserved`: the window outlives the next
    release, so the reserve is held back from solve and build work."""
    if kind not in KIND_RANK:
        raise QuotaError(f"unknown job kind {kind!r} (one of {', '.join(KINDS)})")
    lim = 100.0
    if reserved and kind in RESERVED_KINDS:
        lim -= allowance.reserve_pct
    if kind == "build":
        lim = min(lim, allowance.build_ceiling_pct)
    return lim


# ------------------------------------------------------------------ state per window and harness

@dataclass(frozen=True)
class WindowState:
    harness: str
    window: str
    status: str                      # ok | unmetered | exhausted | probe
    used_pct: float | None           # as read (None: not known)
    effective_pct: float | None      # used + margin, at most 100 (None: not known)
    resets_at: float | None
    open_at: float | None            # exhausted: when it may be tried again (reset or recheck)
    reserved: bool                   # the window outlives the next release: the reserve applies
    reading_ts: float | None
    source: str
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def window_state(r: Reading, last_ok: float | None, allowance: Allowance, now: float,
                 release: float | None) -> WindowState:
    margin = allowance.margin_pct
    resets = r.resets_at
    if resets is not None and now >= resets:
        nxt = None
        if r.window_minutes:
            step = r.window_minutes * 60.0
            nxt = resets + step * (math.floor((now - resets) / step) + 1)
        return WindowState(r.harness, r.window, "ok", 0.0, min(100.0, margin), nxt, None,
                           _reserved(nxt, release), r.ts, r.source,
                           f"reset at {fmt_time(resets)}; no reading since (counted as {margin:g}% used)")
    if r.full:
        if last_ok is not None and last_ok > r.ts + DISPROOF_GRACE_S:
            return WindowState(r.harness, r.window, "unmetered", None, None, resets, None, False, r.ts,
                               r.source, f"limit hit at {fmt_time(r.ts)}, but a response was served at "
                               f"{fmt_time(last_ok)}: that limit reading was wrong or lifted")
        recheck = r.ts + allowance.recheck_minutes * 60.0
        open_at = min(recheck, resets) if resets is not None else recheck
        named = f"named reset {fmt_time(resets)}" if resets is not None else "no reset time named"
        if now < open_at:
            return WindowState(r.harness, r.window, "exhausted", r.used_pct, 100.0, resets, open_at, False,
                               r.ts, r.source, f"limit hit at {fmt_time(r.ts)} ({named}); "
                               f"try again at {fmt_time(open_at)}")
        return WindowState(r.harness, r.window, "probe", r.used_pct, None, resets, None, False, r.ts, r.source,
                           f"limit hit at {fmt_time(r.ts)} ({named}); the recheck time "
                           f"{fmt_time(recheck)} has passed: {PROBE_JOBS} probe job may find out")
    eff = min(100.0, float(r.used_pct) + margin)
    note = f"{r.used_pct:g}% used + {margin:g}% margin"
    age = now - r.ts
    if age > STALE_HOURS * 3600:
        note += f"; the reading is {age / 3600:.1f} h old (a lower bound)"
    return WindowState(r.harness, r.window, "ok", float(r.used_pct), eff, resets, None,
                       _reserved(resets, release), r.ts, r.source, note)


def _reserved(resets: float | None, release: float | None) -> bool:
    return release is not None and (resets is None or resets > release)


@dataclass(frozen=True)
class HarnessState:
    harness: str
    status: str                      # the worst window: exhausted > probe > ok > unmetered
    windows: tuple[WindowState, ...]
    last_ok: float | None

    @property
    def metered(self) -> tuple[WindowState, ...]:
        return tuple(w for w in self.windows if w.status == "ok")

    def to_dict(self) -> dict:
        return {"harness": self.harness, "status": self.status, "last_ok": self.last_ok,
                "windows": [w.to_dict() for w in self.windows]}


_WORST = ("exhausted", "probe", "ok", "unmetered")


@dataclass(frozen=True)
class Snapshot:
    now: float
    next_release: float | None
    allowance: Allowance
    harnesses: dict                  # {harness: HarnessState}, every harness in HARNESSES

    def to_dict(self) -> dict:
        return {"now": self.now, "next_release": self.next_release,
                "harnesses": {h: s.to_dict() for h, s in self.harnesses.items()}}

    @property
    def read(self) -> bool:
        """Whether any harness has a reading at all."""
        return any(s.windows for s in self.harnesses.values())


def build_snapshot(profile: EventProfile, latest: Mapping[tuple[str, str], Reading],
                   last_ok: Mapping[str, float], now: float) -> Snapshot:
    rel = next_release(profile, now)
    hs = {}
    for h in HARNESSES:
        ws = tuple(window_state(r, last_ok.get(h), profile.allowance, now, rel)
                   for (hh, _w), r in sorted(latest.items()) if hh == h)
        status = next((s for s in _WORST if any(w.status == s for w in ws)), "unmetered")
        hs[h] = HarnessState(h, status, ws, last_ok.get(h))
    return Snapshot(now, rel, profile.allowance, hs)


def snapshot(profile: EventProfile, *, workdir: Path | None = None, now: float | None = None) -> Snapshot:
    wd = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
    latest, last_ok = readings(wd)
    return build_snapshot(profile, latest, last_ok, time.time() if now is None else now)


# ------------------------------------------------------------------ scheduling

@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    harnesses: tuple[str, ...] = HARNESSES
    prefer: str | None = None
    est_pct: float | None = None     # share of a window the job is expected to use; default by kind

    def __post_init__(self):
        if not isinstance(self.id, str) or not self.id.strip():
            raise QuotaError(f"a job needs a non-empty id, got {self.id!r}")
        if self.kind not in KIND_RANK:
            raise QuotaError(f"job {self.id}: unknown kind {self.kind!r} (one of {', '.join(KINDS)})")
        hs = tuple(self.harnesses)
        if not hs or any(h not in HARNESSES for h in hs):
            raise QuotaError(f"job {self.id}: harnesses must be a non-empty subset of {', '.join(HARNESSES)}, "
                             f"got {list(hs)}")
        object.__setattr__(self, "harnesses", hs)
        if self.prefer is not None and self.prefer not in hs:
            raise QuotaError(f"job {self.id}: prefer {self.prefer!r} is not one of its harnesses {list(hs)}")
        if self.est_pct is not None and (not _finite(self.est_pct) or self.est_pct <= 0 or self.est_pct > 100):
            raise QuotaError(f"job {self.id}: est_pct must be a number in (0, 100], got {self.est_pct!r}")

    @property
    def est(self) -> float:
        return float(self.est_pct) if self.est_pct is not None else DEFAULT_EST_PCT[self.kind]

    @classmethod
    def from_dict(cls, d: Mapping) -> "Job":
        if not isinstance(d, Mapping):
            raise QuotaError(f"a job must be an object, got {d!r}")
        extra = set(d) - {"id", "kind", "harnesses", "prefer", "est_pct"}
        if extra:
            raise QuotaError(f"job {d.get('id')!r}: unknown key(s) {', '.join(sorted(extra))}")
        if "id" not in d or "kind" not in d:
            raise QuotaError(f"a job needs id and kind, got {dict(d)!r}")
        hs = d.get("harnesses", HARNESSES)
        if isinstance(hs, str) or not isinstance(hs, (list, tuple)):
            raise QuotaError(f"job {d.get('id')!r}: harnesses must be a list")
        return cls(str(d["id"]), d["kind"], tuple(hs), d.get("prefer"), d.get("est_pct"))


def load_jobs(data) -> list[Job]:
    """Jobs from decoded JSON: a list of job objects, or {"jobs": [...]}. Duplicate ids are an error."""
    if isinstance(data, Mapping):
        data = data.get("jobs")
    if not isinstance(data, list):
        raise QuotaError('jobs must be a JSON list of {"id", "kind", ...} objects (or {"jobs": [...]})')
    jobs = [Job.from_dict(d) for d in data]
    dup = [k for k, n in collections.Counter(j.id for j in jobs).items() if n > 1]
    if dup:
        raise QuotaError(f"duplicate job id(s): {', '.join(sorted(dup))}")
    return jobs


@dataclass(frozen=True)
class Assignment:
    job: str
    kind: str
    harness: str
    mode: str                        # fit | unmetered | probe
    est_pct: float
    headroom_pct: float | None       # least headroom left in the harness's windows after this job

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Held:
    job: str
    kind: str
    release_at: float | None         # when the first of its harnesses opens; None: no time is known
    reasons: dict                    # {harness: why it cannot take the job}

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Plan:
    now: float
    next_release: float | None
    assigned: list = field(default_factory=list)       # [Assignment], in scheduling order
    held: list = field(default_factory=list)           # [Held]
    batches: list = field(default_factory=list)        # [(release_at | None, (job ids))], soonest first
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"now": self.now, "next_release": self.next_release,
                "assigned": [a.to_dict() for a in self.assigned], "held": [h.to_dict() for h in self.held],
                "batches": [{"release_at": t, "jobs": list(ids)} for t, ids in self.batches],
                "warnings": list(self.warnings)}


def _fit(hs: HarnessState, job: Job, projected: dict, probes: dict, allowance: Allowance, release):
    """(mode | None, headroom after, open time | None, reason)."""
    ex = [w for w in hs.windows if w.status == "exhausted"]
    if ex:
        until = max(w.open_at for w in ex)
        return None, None, until, "; ".join(f"{w.window} {w.note}" for w in ex)
    if any(w.status == "probe" for w in hs.windows):
        if probes[hs.harness] > 0:
            return "probe", None, None, ""
        return None, None, None, f"a probe job is already out on {hs.harness}; wait for it or for a reading"
    if not hs.metered:
        return "unmetered", None, None, ""
    blocked, rooms = [], []
    for w in hs.metered:
        lim = limit_pct(job.kind, w.reserved, allowance)
        cur = projected[(hs.harness, w.window)]
        if cur + job.est > lim + 1e-9:
            why = (f"{w.window} at {cur:g}% ({w.note}) + {job.est:g}% is past the {lim:g}% {job.kind} limit")
            if w.reserved and job.kind in RESERVED_KINDS and allowance.reserve_pct:
                why += f" (reserve held for the release at {fmt_time(release)})"
            blocked.append((w, why + (f"; resets {fmt_time(w.resets_at)}" if w.resets_at else "; no reset time known")))
        else:
            rooms.append(lim - cur - job.est)
    if blocked:
        times = [w.resets_at for w, _ in blocked]
        until = max(times) if all(t is not None for t in times) else None
        return None, None, until, "; ".join(why for _, why in blocked)
    return "fit", min(rooms), None, ""


_MODE_RANK = {"fit": 0, "unmetered": 1, "probe": 2}


def schedule(snap: Snapshot, jobs: Iterable[Job]) -> Plan:
    """Give each job a harness or hold it with its reasons and the time it opens (see the module doc)."""
    jobs = list(jobs)
    ids = collections.Counter(j.id for j in jobs)
    dup = sorted(k for k, n in ids.items() if n > 1)
    if dup:
        raise QuotaError(f"duplicate job id(s): {', '.join(dup)}")
    plan = Plan(snap.now, snap.next_release)
    projected = {(h, w.window): w.effective_pct for h, s in snap.harnesses.items() for w in s.metered}
    probes = {h: PROBE_JOBS for h in snap.harnesses}
    order = sorted(range(len(jobs)), key=lambda i: (KIND_RANK[jobs[i].kind], i))
    for i in order:
        job = jobs[i]
        options, reasons, opens = [], {}, []
        for h in job.harnesses:
            mode, room, until, why = _fit(snap.harnesses[h], job, projected, probes, snap.allowance,
                                          snap.next_release)
            if mode is None:
                reasons[h] = why
                if until is not None:
                    opens.append(until)
                continue
            options.append((_MODE_RANK[mode], h != job.prefer, -(room if room is not None else 0.0),
                            job.harnesses.index(h), h, mode, room))
        if not options:
            plan.held.append(Held(job.id, job.kind, min(opens) if opens else None, reasons))
            continue
        *_, h, mode, room = min(options)
        if mode == "probe":
            probes[h] -= 1
        for w in snap.harnesses[h].metered:
            projected[(h, w.window)] += job.est
        plan.assigned.append(Assignment(job.id, job.kind, h, mode, job.est, room))
    groups: dict = collections.defaultdict(list)
    for hd in plan.held:
        groups[hd.release_at].append(hd.job)
    plan.batches = sorted(((t, tuple(v)) for t, v in groups.items()),
                          key=lambda kv: (kv[0] is None, kv[0] or 0.0))
    for h, s in snap.harnesses.items():
        if s.status == "unmetered" and any(a.harness == h for a in plan.assigned):
            plan.warnings.append(f"{h}: no usable quota reading; jobs routed there are unmetered "
                                 f"(python -m ctf quota scan, or quota set {h} ...)")
        if s.status == "probe":
            plan.warnings.append(f"{h}: a limit hit is past its recheck time; {PROBE_JOBS} probe job may "
                                 "go there before more")
    return plan


def next_wait(plan: Plan) -> float | None:
    """When the first held batch with a known time opens (epoch), or None."""
    for t, _ids in plan.batches:
        if t is not None:
            return t
    return None


# ------------------------------------------------------------------ the doctor's check

def check(profile: EventProfile, *, workdir: Path | None = None, now: float | None = None):
    """The doctor's "allowance" check (ctf.doctor.run_checks): is the next release funded?

    fail  every harness is known to be blocked through the next release (exhausted past it, or a
          window at its limit that does not reset before it);
    warn  no reading at all, a harness exhausted / in probe / unmetered, a window that outlives the
          release already past 100 - reserve_pct, a stale reading, or a running event whose profile
          names no release (the reserve would never apply);
    ok    otherwise."""
    from .doctor import Check
    try:
        snap = snapshot(profile, workdir=workdir, now=now)
    except (QuotaError, ValueError, OSError) as e:
        return Check("allowance", "fail", f"cannot read the quota state: {e}",
                     "move the corrupt file aside, then `python -m ctf quota scan`")
    a = snap.allowance
    rel = snap.next_release
    rel_s = f"next release {fmt_time(rel)}" if rel is not None else "no release ahead"
    fix = "`python -m ctf quota scan` (session logs) or `python -m ctf quota set <harness> ...` (the usage screen)"
    unset = _no_release_configured(profile, snap.now)
    if unset:
        fix += f"; set [allowance] releases or daily_release in events/{profile.slug}/event.toml"
    if not snap.read:
        return Check("allowance", "warn", f"no quota reading for {', '.join(HARNESSES)}: the meter cannot "
                     f"tell whether work is funded ({rel_s})" + (f"; {unset}" if unset else ""), fix)
    warns, lines, funded = ([unset] if unset else []), [], []
    for h, s in snap.harnesses.items():
        parts = [f"{w.window} {w.status}" + (f" {w.effective_pct:g}%" if w.effective_pct is not None else "")
                 for w in s.windows] or ["no reading"]
        lines.append(f"{h}: " + ", ".join(parts))
        if s.status != "ok":
            warns.append(f"{h} is {s.status}" + (": " + "; ".join(w.note for w in s.windows if w.status == s.status)
                                                 if s.windows else ""))
        for w in s.metered:
            if w.reserved and w.effective_pct is not None and w.effective_pct > 100 - a.reserve_pct:
                warns.append(f"{h} {w.window} at {w.effective_pct:g}% (with margin) has eaten into the "
                             f"{a.reserve_pct:g}% release reserve; it resets {fmt_time(w.resets_at)}")
            if "lower bound" in w.note:
                warns.append(f"{h} {w.window}: {w.note}")
        funded.append(funded_at(s, rel if rel is not None else snap.now))
    detail = "; ".join(lines) + f"; {rel_s}"
    if not any(funded):                      # a harness with no reading counts as funded (funded_at)
        when = "at the next release" if rel is not None else "now"
        return Check("allowance", "fail", f"no harness can take release work {when}: {detail}"
                     + ("; " + "; ".join(warns) if warns else ""),
                     "plan expensive work after a reset, or raise the plan's limit; then " + fix)
    if warns:
        return Check("allowance", "warn", detail + ". " + "; ".join(warns), fix)
    return Check("allowance", "ok", detail)


def _no_release_configured(profile: EventProfile, now: float) -> str | None:
    """A warning when the event is running and the profile names no release (allowance.releases and
    allowance.daily_release both empty): the event start was the only release, so from then on the
    pre-release reserve never applies. None before the start, after the end, or with a release set."""
    a = profile.allowance
    if a.releases or a.daily_release:
        return None
    start, end = event_span(profile)
    if not start <= now < end:
        return None
    return ("the event is running and [allowance] names no release (releases, daily_release): the "
            "pre-release reserve is off until one is set")


def funded_at(s: HarnessState, at: float) -> bool:
    """Whether the harness can take release work at `at`, as far as the readings say (public: the doctor's
    allowance check and ctf.failover.readiness both use it, section 10). No window at all is funded
    (unmetered); an exhausted window is funded once its named reset (else its recheck time) is at or
    before `at`; an ok window at or over 100% (with the margin) is funded once its reset is."""
    if not s.windows:
        return True
    for w in s.windows:
        # a named reset is believed for this (a recheck may find it wrong, but cannot be counted on)
        if w.status == "exhausted" and ((w.resets_at if w.resets_at is not None else w.open_at) or math.inf) > at:
            return False
        if w.status == "ok" and w.effective_pct is not None and w.effective_pct >= 100 \
                and (w.resets_at is None or w.resets_at > at):
            return False
    return True


# ------------------------------------------------------------------ the per-day ledger

@dataclass(frozen=True)
class Day:
    date: str                        # YYYY-MM-DD in the allowance time zone
    usage_usd: dict                  # {harness: usd} from the usage ledger (B-193), priced
    usage_total: float
    spend_usd: dict                  # {category: usd} from the event ledger's spend events
    spend_total: float
    total: float                     # max(usage_total, spend_total): the two overlap (reconcile)
    allowance_usd: float
    over: bool
    unpriced: int

    def to_dict(self) -> dict:
        return asdict(self)


def _day(ts, tz) -> str | None:
    if _finite(ts):
        return _dt.datetime.fromtimestamp(float(ts), tz).date().isoformat()
    if isinstance(ts, str) and ts:
        try:
            d = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=_dt.timezone.utc)
        return d.astimezone(tz).date().isoformat()
    return None


def daily(rows: Iterable[dict], records: Iterable[dict], *, price: Callable[[dict], float], tz: str = "UTC",
          allowance_usd: float = 0.0) -> tuple[list[Day], int]:
    """Spend per day: usage-ledger rows priced with `price` (a row it cannot price raises ValueError and is
    counted unpriced) by harness, and the event ledger's `spend` events by category (challenge spend
    without one is "solve", other spend without one "uncategorized"). Returns (days, undated rows)."""
    zone = zoneinfo.ZoneInfo(tz)
    use: dict = collections.defaultdict(lambda: collections.defaultdict(float))
    spend: dict = collections.defaultdict(lambda: collections.defaultdict(float))
    unpriced: dict = collections.Counter()
    undated = 0
    for r in rows:
        d = _day(r.get("ts"), zone)
        if d is None:
            undated += 1
            continue
        try:
            usd = price(r)
        except ValueError:
            unpriced[d] += 1
            use[d]                                   # the day exists even if nothing on it priced
            continue
        use[d][r.get("harness") or "?"] += usd
    for rec in records:
        if rec.get("event") != "spend":
            continue
        d = _day(rec.get("ts"), zone)
        if d is None:
            continue
        cat = rec.get("category") or ("solve" if rec.get("challenge_id") else "uncategorized")
        spend[d][cat] += float(rec.get("usd") or 0.0)
    out = []
    for d in sorted(set(use) | set(spend)):
        u, s = dict(use.get(d, {})), dict(spend.get(d, {}))
        ut, stt = sum(u.values()), sum(s.values())
        tot = max(ut, stt)
        out.append(Day(d, u, ut, s, stt, tot, allowance_usd, bool(allowance_usd) and tot > allowance_usd,
                       unpriced[d]))
    return out, undated


# ------------------------------------------------------------------ helpers

def fmt_time(t: float | None) -> str:
    if t is None:
        return "unknown"
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
