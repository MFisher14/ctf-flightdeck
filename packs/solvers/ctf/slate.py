"""Multi-event priority scheduler (B-214): several CTFs at once, shared by the player's priority.

At PINK+ the player capped the event at 3 agents in chat ("just keep the challenges limited to 3 for
now") and lifted it 31 minutes later ("spin up more and get us to first"), and setting up Spooky
interrupted the PINK+ wave. Which event matters more at a given moment is the player's call (the spec's
blocker); this module records that call and applies it, so parallel events stop competing through chat.

    from ctf import slate
    store = slate.Store()                                   # paths.slate_state(): one slate per host
    store.set("pink", by="max", reason="podium race", priority=2, max_agents=3)
    store.set("spooky", by="max", reason="setup only", priority=1, weight=1, min_agents=1)
    sl = store.load()                                       # Slate: the events in play
    slate.workspaces(sl)                                    # {slug: workdir}; SlateError when two overlap
    slate.child_env(sl, "pink")                             # env for an agent: CTF_EVENT + CTF_WORKDIR
    slate.fence_for(sl, "pink")                             # its fence, every other event's workdir denied
    slate.allocate(sl, cap=6, demand={"pink": 5, "spooky": 4})   # Allocation: agents per event, why
    slate.plan(sl, {"pink": [quota.Job(...)], ...}, allocation=a)  # SlatePlan: jobs on harnesses, held
    sched = slate.Scheduler(store, governor.Governor(paths.governor_state()))
    lease = sched.acquire("pink", "solve 12")               # an agent slot from pink's share of the host

The slate (``<state>/slate.json``) holds one Entry per event in play:

    priority       int, default 0. Strict tiers: a higher priority is served in full before a lower one.
    weight         > 0, default 1. Share within one priority tier (agents and quota in proportion).
    max_agents     None or >= 0: the most agents this event may hold (the PINK+ "limit it to 3").
    min_agents     >= 0, default 0: a floor served before any share, in priority order (so a low
                   priority event is not starved to zero).
    quota_cap_pct  None or (0, 100]: the most of any harness quota window one plan may give this event.
    paused         True: no new agents and no jobs (running agents are never stopped).
    workdir        None (paths.workdir(slug)) or an explicit folder for this event's runtime state.

Every change names who made it and why (``by``, ``reason``) and is appended to ``history.jsonl``: the
priority is the player's, never an agent's guess. An event must have a loadable profile (ctf.event).

Isolation. ``workspaces`` resolves every event's workdir and refuses two that are the same folder or nest
(a set CTF_WORKDIR pins every event to one folder: the error says so), and one inside the repo.
``child_env`` pins an agent to its event; ``fence_for`` builds the B-219 fence for one event with every
other event's workdir denied, so a solver of one event cannot read another's challenges or notes.

Agent capacity. ``allocate(slate, cap, demand)`` splits ``cap`` agents: floors first (``min_agents``, in
priority order), then each priority tier in turn, inside a tier one agent at a time to the event with the
fewest agents per unit of weight (ties: higher weight, then slug), never past ``max_agents`` or the
event's demand. An event's free agents are its share less its running agents, and never more than the
seats the cap has open after every running agent (an event over its share still holds its seats); those
open seats go tier by tier, highest priority first, and inside a tier one at a time to the event with the
fewest agents (running plus opened) per unit of weight (ties: higher weight, then slug). ``Scheduler`` applies it across processes: the cap is the
host governor's (B-176) minus heavy agents that are not on the slate (or belong to an event since
removed); a waiter is admitted when its place among its event's waiters is inside the event's free share
and the governor seats it. A waiter inside its share holds a governor ticket between tries, so it keeps
its place in the host queue; a waiter outside its share gives that place up. Leases carry the label
``slate:<slug>: ...`` so the running count per event is read back from the governor. Raising another event's priority never
stops a running agent: the over-share event's new agents wait.

Budget. Harness quota windows (B-171) belong to the account, not the event: ``account_readings`` merges
the quota readings of every event workdir (newest per harness and window). ``plan`` places jobs with
``quota.schedule`` one at a time, events taken in priority order and by weight within a tier, every
event's jobs in its own kind order (writeups first). Each event applies its own margin and limits to
the shared usage; the release reserve holds for the earliest next release of any active event (one
event's solve work must not eat another's release); ``quota_cap_pct`` caps one event's share; one
probe job per harness across all events; an event's agents past its free share are held.

No model, no network, nothing stopped or signalled. The only state written is under ``<state>``.
"""
from __future__ import annotations

import collections
import dataclasses
import datetime as _dt
import fcntl
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

from . import event as _event
from . import paths as _paths
from . import quota as _quota

STATE_NAME = "slate.json"
HISTORY_NAME = "history.jsonl"
QUEUE_DIR = "queue"
LOCK_NAME = "lock"
LABEL_PREFIX = "slate:"            # governor lease label: "slate:<slug>: <label>"
SETTABLE = ("priority", "weight", "max_agents", "min_agents", "quota_cap_pct", "paused", "workdir")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_LABEL_RE = re.compile(r"^slate:([a-z0-9][a-z0-9-]{0,63}): ")


class SlateError(ValueError):
    """The slate, an entry, a workspace layout or a job file cannot be used; the message says why."""


def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


# ------------------------------------------------------------------------------------------ entries

@dataclass(frozen=True)
class Entry:
    """One event in play and the player's settings for it (see the module doc)."""
    slug: str
    priority: int = 0
    weight: float = 1.0
    max_agents: int | None = None
    min_agents: int = 0
    quota_cap_pct: float | None = None
    paused: bool = False
    workdir: str | None = None
    set_by: str = ""
    reason: str = ""
    set_at: float = 0.0

    def __post_init__(self):
        if not isinstance(self.slug, str) or not _SLUG_RE.match(self.slug):
            raise SlateError(f"bad event slug {self.slug!r}")
        if not _int(self.priority):
            raise SlateError(f"{self.slug}: priority must be an integer, got {self.priority!r}")
        if not _num(self.weight) or self.weight <= 0:
            raise SlateError(f"{self.slug}: weight must be a number > 0, got {self.weight!r}")
        if self.max_agents is not None and (not _int(self.max_agents) or self.max_agents < 0):
            raise SlateError(f"{self.slug}: max_agents must be an integer >= 0 or none, got {self.max_agents!r}")
        if not _int(self.min_agents) or self.min_agents < 0:
            raise SlateError(f"{self.slug}: min_agents must be an integer >= 0, got {self.min_agents!r}")
        if self.max_agents is not None and self.min_agents > self.max_agents:
            raise SlateError(f"{self.slug}: min_agents {self.min_agents} is above max_agents {self.max_agents}")
        if self.quota_cap_pct is not None and (not _num(self.quota_cap_pct)
                                               or not 0 < self.quota_cap_pct <= 100):
            raise SlateError(f"{self.slug}: quota_cap_pct must be in (0, 100] or none, got {self.quota_cap_pct!r}")
        if not isinstance(self.paused, bool):
            raise SlateError(f"{self.slug}: paused must be true or false, got {self.paused!r}")
        if self.workdir is not None and (not isinstance(self.workdir, str) or not self.workdir.strip()
                                         or not Path(self.workdir).expanduser().is_absolute()):
            raise SlateError(f"{self.slug}: workdir must be an absolute folder path (or ~/...) or none, "
                             f"got {self.workdir!r}")

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping) -> "Entry":
        if not isinstance(d, Mapping):
            raise SlateError(f"a slate entry must be an object, got {d!r}")
        extra = set(d) - {f.name for f in dataclasses.fields(cls)}
        if extra:
            raise SlateError(f"slate entry {d.get('slug')!r}: unknown key(s) {', '.join(sorted(extra))}")
        if "slug" not in d:
            raise SlateError(f"a slate entry needs a slug, got {dict(d)!r}")
        return cls(**d)


def order_key(e: Entry) -> tuple:
    """Serving order: higher priority first, then higher weight, then slug."""
    return (-e.priority, -e.weight, e.slug)


@dataclass(frozen=True)
class Slate:
    entries: Mapping[str, Entry] = field(default_factory=dict)

    def get(self, slug: str) -> Entry:
        try:
            return self.entries[slug]
        except KeyError:
            have = ", ".join(sorted(self.entries)) or "none"
            raise SlateError(f"event {slug!r} is not on the slate (on it: {have}); "
                             f"add it with `python -m ctf slate set {slug} --by WHO --reason WHY`") from None

    def ordered(self) -> list[Entry]:
        return sorted(self.entries.values(), key=order_key)

    def active(self) -> list[Entry]:
        return [e for e in self.ordered() if not e.paused]

    def to_dict(self) -> dict:
        return {"events": {s: e.to_dict() for s, e in sorted(self.entries.items())}}


# ------------------------------------------------------------------------------------- the store

class Store:
    """The slate on disk under ``state_dir`` (default ``paths.slate_state()``): ``slate.json``, written
    atomically under an flock on ``lock``, and ``history.jsonl``, one line per change. ``events_root``
    replaces ``events/`` when checking that a slug has a profile."""

    def __init__(self, state_dir: Path | str | None = None, *, events_root: Path | str | None = None,
                 clock: Callable[[], float] = time.time):
        self.dir = Path(state_dir) if state_dir is not None else _paths.slate_state()
        self.events_root = Path(events_root) if events_root is not None else None
        self.clock = clock

    @property
    def path(self) -> Path:
        return self.dir / STATE_NAME

    @property
    def history_path(self) -> Path:
        return self.dir / HISTORY_NAME

    def lock(self):
        """An exclusive flock on ``<state>/lock``; close the returned file to release it."""
        self.dir.mkdir(parents=True, exist_ok=True)
        fh = open(self.dir / LOCK_NAME, "a+")
        fcntl.flock(fh, fcntl.LOCK_EX)
        return fh

    def load(self) -> Slate:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return Slate({})
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise SlateError(f"{self.path}: corrupt slate ({e}); move it aside and set the events again") from None
        if not isinstance(raw, dict) or not isinstance(raw.get("events"), dict):
            raise SlateError(f"{self.path}: corrupt slate (no events object)")
        out = {}
        for slug, d in raw["events"].items():
            e = Entry.from_dict(d)
            if e.slug != slug:
                raise SlateError(f"{self.path}: entry under {slug!r} names slug {e.slug!r}")
            out[slug] = e
        return Slate(out)

    def _save(self, sl: Slate) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / f".{STATE_NAME}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(sl.to_dict(), fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            tmp.unlink(missing_ok=True)

    def _history(self, rec: dict) -> None:
        with open(self.history_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    @staticmethod
    def _who(by: str, reason: str) -> tuple[str, str]:
        if not isinstance(by, str) or not by.strip():
            raise SlateError("a slate change must name who made it (by=...): the priority is the player's call")
        if not isinstance(reason, str) or not reason.strip():
            raise SlateError("a slate change must say why (reason=...)")
        return by.strip(), reason.strip()

    def _change(self, action: str, slug: str, by: str, reason: str,
                fn: Callable[[Entry | None, Slate], Entry | None]) -> Entry | None:
        by, reason = self._who(by, reason)
        fh = self.lock()
        try:
            sl = self.load()
            before = sl.entries.get(slug)
            if action != "add" and before is None:
                sl.get(slug)                        # SlateError: not on the slate
            if action == "add" and before is not None:
                action = "set"
            after = fn(before, sl)
            entries = dict(sl.entries)
            if after is None:
                entries.pop(slug, None)
            else:
                after = dataclasses.replace(after, set_by=by, reason=reason, set_at=self.clock())
                entries[slug] = after
            self._save(Slate(entries))
            self._history({"ts": self.clock(), "action": action, "slug": slug, "by": by, "reason": reason,
                           "before": before.to_dict() if before else None,
                           "after": after.to_dict() if after else None})
            return after
        finally:
            fh.close()

    def set(self, slug: str, *, by: str, reason: str, **changes) -> Entry:
        """Add ``slug`` to the slate or change its settings (keys in SETTABLE). The event must have a
        profile that loads; the result must still isolate every workspace."""
        bad = sorted(set(changes) - set(SETTABLE))
        if bad:
            raise SlateError(f"unknown slate setting(s) {', '.join(bad)} (settable: {', '.join(SETTABLE)})")
        _event.load(slug, self.events_root)          # EventError names the missing or broken profile

        def fn(cur: Entry | None, sl: Slate) -> Entry:
            new = dataclasses.replace(cur if cur is not None else Entry(slug), **changes)
            workspaces(Slate({**sl.entries, slug: new}))      # refuses a layout that does not isolate
            return new

        return self._change("add", slug, by, reason, fn)

    def pause(self, slug: str, *, by: str, reason: str) -> Entry:
        return self._change("pause", slug, by, reason, lambda e, _sl: dataclasses.replace(e, paused=True))

    def resume(self, slug: str, *, by: str, reason: str) -> Entry:
        return self._change("resume", slug, by, reason, lambda e, _sl: dataclasses.replace(e, paused=False))

    def remove(self, slug: str, *, by: str, reason: str) -> None:
        self._change("remove", slug, by, reason, lambda e, _sl: None)

    def history(self) -> list[dict]:
        try:
            text = self.history_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        out = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise SlateError(f"{self.history_path}:{n}: corrupt history line ({e})") from None
        return out


# -------------------------------------------------------------------------------------- isolation

def _under(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def workdir_of(e: Entry) -> Path:
    """This event's workdir: the entry's own folder, else ``paths.workdir(slug)``."""
    if e.workdir is not None:
        return Path(e.workdir).expanduser().resolve()
    return _paths.workdir(e.slug)


def workspaces(sl: Slate) -> dict[str, Path]:
    """{slug: workdir} for every event on the slate (paused ones too). SlateError when two events share
    a folder or one sits inside another's, or a workdir lies inside the repo."""
    ws = {s: workdir_of(e) for s, e in sorted(sl.entries.items())}
    repo = _paths.repo_root().resolve()
    for s, w in ws.items():
        if _under(w, repo):
            raise SlateError(f"{s}: workdir {w} is inside the repo {repo}; runtime state never goes in the repo")
    slugs = sorted(ws)
    for i, a in enumerate(slugs):
        for b in slugs[i + 1:]:
            wa, wb = ws[a], ws[b]
            if wa == wb:
                why = (" (CTF_WORKDIR is set and pins every event to one folder: unset it, or give each "
                       "event its own `--workdir`)" if sl.entries[a].workdir is None
                       and sl.entries[b].workdir is None else "")
                raise SlateError(f"events {a} and {b} share the workdir {wa}{why}")
            if _under(wa, wb) or _under(wb, wa):
                inner, outer = (a, b) if _under(wa, wb) else (b, a)
                raise SlateError(f"event {inner}'s workdir {ws[inner]} is inside event {outer}'s {ws[outer]}; "
                                 "each event needs its own folder")
    return ws


def child_env(sl: Slate, slug: str, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for an agent of ``slug``: ``base`` (default this process's) with ``CTF_EVENT`` and
    ``CTF_WORKDIR`` pinned to that event, whatever they were."""
    sl.get(slug)
    ws = workspaces(sl)
    env = dict(os.environ if base is None else base)
    env["CTF_EVENT"] = slug
    env["CTF_WORKDIR"] = str(ws[slug])
    return env


def fence_for(sl: Slate, slug: str, *, events_root: Path | str | None = None, **build_kw):
    """The B-219 fence for an agent of ``slug``: its event's fence config, its workdir as the workspace,
    and every other slate event's workdir added to the denied roots. ``build_kw`` goes to
    ``fence.from_config`` (repo, home, user_dir, ... for tests)."""
    from . import fence as _fence
    sl.get(slug)
    ws = workspaces(sl)
    cfg = _fence.load_config(slug, root=events_root)
    others = [w for s, w in ws.items() if s != slug]
    return _fence.from_config(cfg, workspace=ws[slug], extra_deny=others, slug=slug, **build_kw)


# ------------------------------------------------------------------------------- agent allocation

@dataclass(frozen=True)
class Share:
    slug: str
    agents: int              # this event's share of the cap
    running: int             # agents it holds now
    demand: int              # agents it wants (running + waiting, or jobs)
    reason: str
    room: int | None = None  # host seats opened to it (see allocate); None: not limited by the host

    @property
    def free(self) -> int:
        """Agents it may start now: within its share, and within the room the cap has left after every
        running agent (another event over its share still holds its seats)."""
        own = max(0, self.agents - self.running)
        return own if self.room is None else max(0, min(own, self.room))

    def to_dict(self) -> dict:
        return {**dataclasses.asdict(self), "free": self.free}


@dataclass(frozen=True)
class Allocation:
    cap: int
    shares: Mapping[str, Share]

    def to_dict(self) -> dict:
        return {"cap": self.cap, "shares": {s: v.to_dict() for s, v in self.shares.items()}}


def allocate(sl: Slate, cap: int, demand: Mapping[str, int],
             running: Mapping[str, int] | None = None) -> Allocation:
    """Split ``cap`` agents across the slate by the player's priority (see the module doc). ``demand``:
    agents each event wants (running included); ``running``: agents it holds now (default 0)."""
    if not _int(cap) or cap < 0:
        raise SlateError(f"cap must be an integer >= 0, got {cap!r}")
    running = dict(running or {})
    for name, m in (("demand", demand), ("running", running)):
        for s, n in m.items():
            if not _int(n) or n < 0:
                raise SlateError(f"{name} for {s} must be an integer >= 0, got {n!r}")
            sl.get(s)
    want = {e.slug: max(int(demand.get(e.slug, 0)), running.get(e.slug, 0)) for e in sl.entries.values()}
    limit = {}
    for e in sl.active():
        lim = want[e.slug]
        if e.max_agents is not None:
            lim = min(lim, e.max_agents)
        limit[e.slug] = lim
    give = {s: 0 for s in sl.entries}
    left = cap
    for e in sl.active():                                    # floors, in priority order
        n = min(e.min_agents, limit[e.slug], left)
        give[e.slug] += n
        left -= n
    tiers = sorted({e.priority for e in sl.active()}, reverse=True)
    for p in tiers:
        tier = [e for e in sl.active() if e.priority == p]
        while left > 0:
            cands = [e for e in tier if give[e.slug] < limit[e.slug]]
            if not cands:
                break
            e = min(cands, key=lambda e: (give[e.slug] / e.weight, -e.weight, e.slug))
            give[e.slug] += 1
            left -= 1
    own = {s: max(0, give[s] - running.get(s, 0)) for s in sl.entries}
    room = max(0, cap - sum(running.values()))               # seats no running agent holds
    opened = {s: 0 for s in sl.entries}
    for p in sorted({e.priority for e in sl.entries.values()}, reverse=True):
        tier = [e for e in sl.ordered() if e.priority == p]  # tier by tier, by weight inside one
        while room > 0:
            cands = [e for e in tier if opened[e.slug] < own[e.slug]]
            if not cands:
                break
            e = min(cands, key=lambda e: ((running.get(e.slug, 0) + opened[e.slug]) / e.weight,
                                          -e.weight, e.slug))
            opened[e.slug] += 1
            room -= 1
    shares = {}
    for e in sl.ordered():
        s, n, run = e.slug, give[e.slug], running.get(e.slug, 0)
        if e.paused:
            why = f"paused by {e.set_by or '?'} ({e.reason or 'no reason'}): no new agents"
        elif want[s] == 0:
            why = "no demand"
        else:
            why = f"priority {e.priority}, weight {e.weight:g}: {n} of cap {cap}"
            if e.min_agents:
                why += f"; floor {e.min_agents}"
            if e.max_agents is not None and e.max_agents < want[s]:
                why += f"; max_agents {e.max_agents} set by {e.set_by or '?'}"
            if n < limit[s]:
                why += f"; {limit[s] - n} more wanted: the cap went to higher priority or larger weight"
        if run > n:
            why += f"; {run - n} over its share (running agents are never stopped; new ones wait)"
        if own[s] > opened[s]:
            why += (f"; only {opened[s]} of its {own[s]} free seats are open: other events run over their "
                    "share and still hold seats under the cap")
        shares[s] = Share(s, n, run, want[s], why, opened[s])
    return Allocation(cap, shares)


# ------------------------------------------------------------------------- admission (processes)

def lease_label(slug: str, label: str) -> str:
    return f"{LABEL_PREFIX}{slug}: {label}"


def label_event(label: str) -> str | None:
    """The slug a governor lease label belongs to, or None for a heavy agent not on the slate."""
    m = _LABEL_RE.match(label or "")
    return m.group(1) if m else None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class Scheduler:
    """Admission of agents across processes: each waiter files a ticket under ``<state>/queue`` and is
    admitted when it is inside its event's free share (``allocate`` over the governor's cap minus heavy
    agents not on the slate) and the governor seats it. Everything is decided under the store's lock;
    the governor keeps its own lock for the host-wide cap."""

    def __init__(self, store: Store, governor, *, pid_alive: Callable[[int], bool] = _pid_alive,
                 clock: Callable[[], float] = time.time):
        self.store = store
        self.governor = governor
        self.pid_alive = pid_alive
        self.clock = clock
        self.reaped: list[str] = []
        self.last: Allocation | None = None
        self.last_reason = ""
        self.host_reason = ""

    def _qdir(self) -> Path:
        d = self.store.dir / QUEUE_DIR
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _tickets(self) -> list[dict]:
        out = []
        for p in sorted(self._qdir().glob("*.json")):
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
                pid, slug = int(rec["pid"]), str(rec["slug"])
            except (OSError, ValueError, KeyError, TypeError):
                self.reaped.append(f"{p.name} (unreadable)")
                p.unlink(missing_ok=True)
                continue
            if not self.pid_alive(pid):
                self.reaped.append(f"{p.name} (pid {pid} gone)")
                if rec.get("gov"):
                    self.governor.dequeue(str(rec["gov"]))
                p.unlink(missing_ok=True)
                continue
            out.append({**rec, "id": p.stem, "slug": slug, "pid": pid})
        return out

    def _write_ticket(self, tid: str, rec: Mapping) -> None:
        p = self._qdir() / f"{tid}.json"
        tmp = p.with_name(f".{p.name}.tmp")
        tmp.write_text(json.dumps({k: v for k, v in rec.items() if k != "id"}), encoding="utf-8")
        os.replace(tmp, p)

    def _withdraw_host_place(self, t: dict) -> None:
        """Give up the governor ticket ``t`` holds (its place in the host queue), if any."""
        if t.get("gov"):
            self.governor.dequeue(str(t["gov"]))
            self._write_ticket(t["id"], {k: v for k, v in t.items() if k != "gov"})

    def census(self) -> tuple[dict, dict, int]:
        """({slug: running}, {slug: [ticket ids, oldest first]}, heavy agents not on the slate)."""
        running: dict[str, int] = collections.Counter()
        other = 0
        for lease in self.governor.leases():
            s = label_event(lease.label)
            if s is None:
                other += 1
            else:
                running[s] += 1
        waiting: dict[str, list] = collections.defaultdict(list)
        for t in self._tickets():
            waiting[t["slug"]].append(t["id"])
        return dict(running), dict(waiting), other

    def _allocation_locked(self, sl: Slate) -> Allocation:
        running, waiting, other = self.census()
        d = self.governor.decision()
        other += sum(n for s, n in running.items() if s not in sl.entries)   # a removed event's agents
        cap = max(0, d.cap - other)
        on = {s: n for s, n in running.items() if s in sl.entries}
        demand = {s: on.get(s, 0) + len(waiting.get(s, [])) for s in sl.entries}
        self.last = allocate(sl, cap, demand, on)
        self.host_reason = d.reason
        return self.last

    def allocation(self) -> Allocation:
        fh = self.store.lock()
        try:
            return self._allocation_locked(self.store.load())
        finally:
            fh.close()

    def enqueue(self, slug: str, label: str, pid: int | None = None) -> str:
        pid = os.getpid() if pid is None else pid
        fh = self.store.lock()
        try:
            self.store.load().get(slug)
            tid = f"{time.time_ns():020d}-{pid}"
            self._write_ticket(tid, {"pid": pid, "slug": slug, "label": label, "queued": self.clock()})
            return tid
        finally:
            fh.close()

    def dequeue(self, ticket: str) -> None:
        """Withdraw ``ticket`` and the place in the host queue it holds."""
        fh = self.store.lock()
        try:
            p = self.store.dir / QUEUE_DIR / f"{ticket}.json"
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                rec = {}
            if isinstance(rec, dict) and rec.get("gov"):
                self.governor.dequeue(str(rec["gov"]))
            p.unlink(missing_ok=True)
        finally:
            fh.close()

    def try_admit(self, ticket: str):
        """A governor Lease when ``ticket`` is admitted now, else None (``last_reason`` says why).

        A ticket inside its event's free share holds a governor ticket, so it keeps its place in the host
        queue between tries (a non-slate waiter queued after it does not pass it). Every ticket outside its
        share gives that place up, whichever waiter's try notices it."""
        fh = self.store.lock()
        try:
            tickets = {t["id"]: t for t in self._tickets()}
            if ticket not in tickets:
                raise SlateError(f"ticket {ticket} is not queued (its process is gone or it was removed)")
            t = tickets[ticket]
            sl = self.store.load()
            entry = sl.get(t["slug"])
            alloc = self._allocation_locked(sl)
            by_event: dict[str, list] = collections.defaultdict(list)
            for i in sorted(tickets):
                by_event[tickets[i]["slug"]].append(i)
            for s, ids in by_event.items():
                sh = alloc.shares.get(s)
                for i in ids[sh.free if sh is not None else 0:]:
                    self._withdraw_host_place(tickets[i])
            share = alloc.shares[entry.slug]
            pos = by_event[entry.slug].index(ticket)
            if pos >= share.free:
                self.last_reason = (f"{entry.slug}: {share.running} running, share {share.agents}, "
                                    f"place {pos + 1} in its queue ({share.reason})")
                return None
            held = {r["id"] for r in self.governor.queue()}
            gt = t.get("gov")
            if not gt or gt not in held:
                gt = self.governor.enqueue(lease_label(entry.slug, str(t.get("label", ""))), pid=t["pid"])
                self._write_ticket(ticket, {**t, "gov": gt})
            lease = self.governor.try_acquire(gt)
            if lease is None:
                gd = self.governor.last
                self.last_reason = (f"{entry.slug}: inside its share, but the host has no free slot "
                                    f"({gd.running} running, cap {gd.cap}: {gd.reason}); it keeps its "
                                    "place in the host queue" if gd else
                                    f"{entry.slug}: inside its share, but the host has no free slot")
                return None
            (self.store.dir / QUEUE_DIR / f"{ticket}.json").unlink(missing_ok=True)
            self.last_reason = ""
            return lease
        finally:
            fh.close()

    def acquire(self, slug: str, label: str, *, timeout: float | None = None, poll: float = 5.0,
                sleep: Callable[[float], None] = time.sleep,
                on_wait: Callable[[str], None] | None = None):
        """Queue for an agent slot of ``slug`` and wait until admitted. Past ``timeout`` raises
        ``governor.GovernorTimeout`` with the last reason."""
        from .governor import GovernorTimeout
        if poll <= 0:
            raise SlateError(f"poll must be > 0, got {poll}")
        ticket = self.enqueue(slug, label)
        start = self.clock()
        try:
            while True:
                lease = self.try_admit(ticket)
                if lease is not None:
                    ticket = ""
                    return lease
                if timeout is not None and self.clock() - start >= timeout:
                    raise GovernorTimeout(f"not admitted within {timeout:g} s: {self.last_reason}")
                if on_wait is not None:
                    on_wait(self.last_reason)
                sleep(poll)
        finally:
            if ticket:
                self.dequeue(ticket)

    def release(self, lease) -> None:
        self.governor.release(lease)


# ------------------------------------------------------------------------- budget: quota planning

def account_readings(workdirs: Iterable[Path]):
    """Account-wide quota readings: the newest reading per (harness, window) across every event workdir,
    and the latest served response per harness. A corrupt quota state raises QuotaError naming it."""
    latest: dict = {}
    last_ok: dict[str, float] = {}
    for wd in workdirs:
        lt, ok = _quota.readings(Path(wd))
        _quota.merge(latest, lt.values())
        for h, t in ok.items():
            last_ok[h] = max(t, last_ok.get(h, t))
    return latest, last_ok


@dataclass(frozen=True)
class Placed:
    slug: str
    assignment: object        # quota.Assignment

    def to_dict(self) -> dict:
        return {"event": self.slug, **self.assignment.to_dict()}


@dataclass(frozen=True)
class HeldJob:
    slug: str
    job: str
    kind: str
    release_at: float | None
    reasons: Mapping[str, str]     # {harness or "agents" or "event": why}

    def to_dict(self) -> dict:
        return {"event": self.slug, "job": self.job, "kind": self.kind, "release_at": self.release_at,
                "reasons": dict(self.reasons)}


@dataclass
class SlatePlan:
    now: float
    next_release: float | None                 # the earliest next release of any active event
    allocation: Allocation | None
    assigned: list = field(default_factory=list)    # [Placed], in placing order
    held: list = field(default_factory=list)        # [HeldJob]
    batches: list = field(default_factory=list)     # [(release_at | None, ((slug, job), ...))]
    warnings: list = field(default_factory=list)

    def for_event(self, slug: str) -> tuple[list, list]:
        return ([p for p in self.assigned if p.slug == slug], [h for h in self.held if h.slug == slug])

    def to_dict(self) -> dict:
        return {"now": self.now, "next_release": self.next_release,
                "allocation": self.allocation.to_dict() if self.allocation else None,
                "assigned": [p.to_dict() for p in self.assigned], "held": [h.to_dict() for h in self.held],
                "batches": [{"release_at": t, "jobs": [{"event": s, "job": j} for s, j in ids]}
                            for t, ids in self.batches],
                "warnings": list(self.warnings)}


def _reserved(resets: float | None, release: float | None) -> bool:
    return release is not None and (resets is None or resets > release)


def _adjusted(snap, added: Mapping, release: float | None):
    """``snap`` with the shared usage placed so far added to each metered window, and the reserve
    recomputed against the slate-wide next release."""
    hs = {}
    for h, s in snap.harnesses.items():
        ws = []
        for w in s.windows:
            if w.status == "ok":
                w = dataclasses.replace(w, effective_pct=min(100.0, w.effective_pct + added.get((h, w.window), 0.0)),
                                        reserved=_reserved(w.resets_at, release))
            ws.append(w)
        hs[h] = dataclasses.replace(s, windows=tuple(ws))
    return dataclasses.replace(snap, next_release=release, harnesses=hs)


def _as_epoch(d, tz) -> float:
    if not isinstance(d, _dt.datetime):
        d = _dt.datetime(d.year, d.month, d.day, tzinfo=tz)
    elif d.tzinfo is None:
        d = d.replace(tzinfo=tz)
    return d.timestamp()


def _dates_note(prof, now: float) -> str | None:
    import zoneinfo
    tz = zoneinfo.ZoneInfo(prof.allowance.tz)
    start, end = _as_epoch(prof.start, tz), _as_epoch(prof.end, tz)
    if not isinstance(prof.end, _dt.datetime):
        end += 86400.0
    if now < start:
        return f"{prof.slug}: the event has not started (starts {_quota.fmt_time(start)})"
    if now >= end:
        return f"{prof.slug}: the event has ended ({_quota.fmt_time(end)}); only writeup and retro work fits it"
    return None


def load_jobs(data) -> dict[str, list]:
    """Jobs per event from decoded JSON: {"<slug>": [job objects as quota.load_jobs takes], ...}."""
    if not isinstance(data, Mapping) or not data:
        raise SlateError('a slate job file is an object {"<event slug>": [{"id", "kind", ...}], ...}')
    out = {}
    for slug, jobs in data.items():
        try:
            out[str(slug)] = _quota.load_jobs(jobs)
        except _quota.QuotaError as e:
            raise SlateError(f"{slug}: {e}") from None
    return out


def plan(sl: Slate, jobs: Mapping[str, Iterable], *, now: float | None = None,
         allocation: Allocation | None = None, events_root: Path | str | None = None) -> SlatePlan:
    """Place every event's jobs on a harness by the player's priority (see the module doc). With an
    ``allocation``, an event's jobs past its free agents are held ("agents")."""
    now = time.time() if now is None else float(now)
    jobs = {s: list(js) for s, js in jobs.items()}
    for s, js in jobs.items():
        sl.get(s)
        dup = sorted(k for k, n in collections.Counter(j.id for j in js).items() if n > 1)
        if dup:
            raise SlateError(f"{s}: duplicate job id(s) {', '.join(dup)}")
    ws = workspaces(sl)
    latest, last_ok = account_readings(ws.values())
    root = Path(events_root) if events_root is not None else None
    out = SlatePlan(now, None, allocation)
    live = [e for e in sl.active() if jobs.get(e.slug)]
    for e in sl.ordered():
        if e.paused:
            for j in jobs.get(e.slug, []):
                out.held.append(HeldJob(e.slug, j.id, j.kind, None,
                                        {"event": f"paused by {e.set_by or '?'} ({e.reason or 'no reason'})"}))
    profiles = {e.slug: _event.load(e.slug, root) for e in sl.active()}
    snaps = {s: _quota.build_snapshot(p, latest, last_ok, now) for s, p in profiles.items()}
    rels = [sn.next_release for sn in snaps.values() if sn.next_release is not None]
    out.next_release = min(rels) if rels else None
    for s, p in profiles.items():
        note = _dates_note(p, now) if jobs.get(s) else None
        if note:
            out.warnings.append(note)

    queues = {e.slug: collections.deque(sorted(jobs[e.slug], key=lambda j: _quota.KIND_RANK[j.kind]))
              for e in live}
    free = {s: (allocation.shares[s].free if allocation is not None and s in allocation.shares else 0)
            for s in queues} if allocation is not None else None
    given: dict[str, int] = collections.Counter()
    added: dict = collections.defaultdict(float)          # (harness, window) -> pct placed this plan
    mine: dict = collections.defaultdict(float)           # (slug, harness, window) -> pct placed for slug
    probed: dict[str, str] = {}                            # harness -> the event its one probe job went to
    used_harness: set[str] = set()
    for p in sorted({e.priority for e in live}, reverse=True):
        tier = {e.slug: e for e in live if e.priority == p}
        while True:
            cands = [tier[s] for s in tier if queues[s]]
            if not cands:
                break
            e = min(cands, key=lambda e: (given[e.slug] / e.weight, -e.weight, e.slug))
            job = queues[e.slug].popleft()
            snap = snaps[e.slug]
            if free is not None and given[e.slug] >= free[e.slug]:
                sh = allocation.shares.get(e.slug)
                out.held.append(HeldJob(e.slug, job.id, job.kind, None, {
                    "agents": f"no free agent in {e.slug}'s share ({sh.reason if sh else 'not allocated'})"}))
                continue
            reasons, allowed = {}, []
            for h in job.harnesses:
                hs = snap.harnesses[h]
                if h in probed and any(w.status == "probe" for w in hs.windows):
                    reasons[h] = f"the one probe job on {h} went to {probed[h]}; wait for it or for a reading"
                    continue
                if e.quota_cap_pct is not None:
                    over = [w.window for w in hs.metered
                            if mine[(e.slug, h, w.window)] + job.est > e.quota_cap_pct + 1e-9]
                    if over:
                        reasons[h] = (f"{', '.join(over)}: {e.slug} has {max(mine[(e.slug, h, w)] for w in over):g}% "
                                      f"of its quota_cap_pct {e.quota_cap_pct:g}% this plan "
                                      f"(set by {e.set_by or '?'})")
                        continue
                allowed.append(h)
            if not allowed:
                out.held.append(HeldJob(e.slug, job.id, job.kind, None, reasons))
                continue
            one = _quota.Job(job.id, job.kind, tuple(allowed), job.prefer if job.prefer in allowed else None,
                             job.est_pct)
            qp = _quota.schedule(_adjusted(snap, added, out.next_release), [one])
            if not qp.assigned:
                hd = qp.held[0]
                out.held.append(HeldJob(e.slug, job.id, job.kind, hd.release_at, {**reasons, **hd.reasons}))
                continue
            a = qp.assigned[0]
            out.assigned.append(Placed(e.slug, a))
            given[e.slug] += 1
            used_harness.add(a.harness)
            if a.mode == "probe":
                probed[a.harness] = e.slug
            for w in snap.harnesses[a.harness].metered:
                added[(a.harness, w.window)] += a.est_pct
                mine[(e.slug, a.harness, w.window)] += a.est_pct
    groups: dict = collections.defaultdict(list)
    for hd in out.held:
        groups[hd.release_at].append((hd.slug, hd.job))
    out.batches = sorted(((t, tuple(v)) for t, v in groups.items()), key=lambda kv: (kv[0] is None, kv[0] or 0.0))
    if snaps:
        any_snap = next(iter(snaps.values()))
        for h in sorted(used_harness):
            if any_snap.harnesses[h].status == "unmetered":
                out.warnings.append(f"{h}: no usable quota reading in any event workdir; jobs routed there are "
                                    f"unmetered (python -m ctf quota scan, or quota set {h} ...)")
    return out


# ------------------------------------------------------------------------------------- the check

def check(sl: Slate, *, events_root: Path | str | None = None) -> list[str]:
    """Problems that stop the slate working, one line each ([] = fine): a profile that does not load, a
    workspace layout that does not isolate, an empty or all-paused slate."""
    probs = []
    if not sl.entries:
        return ["the slate is empty: add an event with `python -m ctf slate set SLUG --by WHO --reason WHY`"]
    root = Path(events_root) if events_root is not None else None
    for s in sorted(sl.entries):
        try:
            _event.load(s, root)
        except _event.EventError as e:
            probs.append(f"{s}: {e}")
    try:
        workspaces(sl)
    except (SlateError, _event.EventError) as e:
        probs.append(str(e))
    if not sl.active():
        probs.append("every event on the slate is paused: no agent will start")
    return probs
