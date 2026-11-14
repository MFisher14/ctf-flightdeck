"""Host resource governor (B-176): cap heavy agents by load, RAM, battery, thermal state and disk.

Host limits were hit in every 2026 event: PINK+ ran the laptop to load 140 with 931k pageouts and all 8
Codex runs died empty; CSCTF agent RSS climbed to 39 GB then 59 GB before the Mac crashed; on Huntress a
Mac on a 128 W charger fell from 100% to 12% under build load; Spooky ran with about 806 MB free. The
PINK+ session concluded the host runs 4-6 heavy agents at once. This module is that governor:

  * ``probe_host()`` reads the host: load average, total/available RAM, the macOS memory-pressure level
    (sysctl), battery percent / plugged / charging state (psutil + ``pmset -g batt``), the thermal and
    performance warning level and CPU speed limit (``pmset -g therm``), and free disk at a path. A reading
    it cannot take is recorded in ``HostState.unknown`` with the reason -- never guessed.
  * ``GovernorPolicy`` holds the knobs (heavy-agent cap, RAM per heavy agent, load thresholds per CPU,
    battery floor, disk floor, RSS alert), from ``CTF_GOVERNOR_*`` through ``ctf.env``. The RAM held back
    for the OS and Docker production is B-018's ``CTF_CAPACITY_RESERVE_MB``.
  * ``decide(state, policy, running)`` turns a reading into a ceiling on concurrent heavy agents and the
    slots free now; every limit that binds carries a named reason. Unknown readings are listed; with
    ``strict`` each one blocks.
  * ``Governor`` keeps host-wide slot leases and a FIFO queue on disk (``paths.governor_state()``), so
    every harness and lane on the machine shares one cap: ``acquire`` waits in the queue until the
    governor admits it, ``release`` frees the slot, a lease whose process died is reaped.
  * ``snapshot_processes`` / ``agent_trees`` / ``rss_alerts`` are the RSS watchdog (alert only: it never
    kills anything), and ``measure`` turns two snapshots into a measured per-agent RAM and CPU budget --
    the numbers B-018's ``CTF_CAPACITY_AGENT_RAM_MB`` and ``CTF_CAPACITY_AGENTS_PER_CPU`` want.
  * ``host_checks`` reports all of it as doctor checks (``ctf.doctor.Check``).

Disk preflight, the symlink-rejecting copier, Spotlight exclusion and post-acceptance eviction are in
``ctf.diskguard``. No model, no network. The only processes started are read-only queries (``pmset``,
``sysctl``); nothing here stops, signals or modifies another process.
"""
from __future__ import annotations

import fcntl
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import capacity as _capacity
from . import env as _env

MiB = 1024 * 1024
GiB = 1024 * MiB

# Defaults. HEAVY_CAP is the PINK+ conclusion (4-6 heavy agents on the event laptop). A heavy agent is
# a model-driven solver lane plus what it spawns (QEMU, brute forcers, decompilers).
DEFAULT_HEAVY_CAP = 6
DEFAULT_HEAVY_RAM_MB = 2048
DEFAULT_LOAD_SOFT = 1.5          # 1-minute load per logical CPU at which new heavy agents are halved
DEFAULT_LOAD_HARD = 3.0          # ... at which no new heavy agent starts
DEFAULT_BATTERY_LOW = 25         # percent
DEFAULT_DISK_MIN_GB = 10.0
DEFAULT_RSS_ALERT_MB = 8192      # one agent's process tree
DEFAULT_AGENT_NAMES = ("claude", "codex")
MAX_AGENTS_PER_CPU = 8.0         # a measured agents-per-CPU is clamped here: a near-idle sample is not a budget

PRESSURE_LEVELS = {1: "normal", 2: "warn", 4: "critical"}   # kern.memorystatus_vm_pressure_level


class GovernorError(RuntimeError):
    """The governor cannot act; the message names the missing reading, tool or bad setting."""


class GovernorTimeout(GovernorError):
    """``acquire`` waited past its timeout without being admitted."""


# ------------------------------------------------------------------------------------------- readings

@dataclass(frozen=True)
class Battery:
    """``present`` False means the host has no battery (a desktop): no battery limit applies.
    ``state`` is what pmset reports: charging | discharging | charged | not-charging | finishing, or ""
    when it was not read."""

    present: bool
    percent: float | None = None
    plugged: bool | None = None
    state: str = ""

    @property
    def charger_deficit(self) -> bool:
        """On the charger and still discharging: the load draws more than the charger supplies."""
        return bool(self.present and self.plugged and self.state == "discharging")


@dataclass(frozen=True)
class Thermal:
    """``speed_limit`` is the CPU speed limit in percent (100 = not throttled); ``warning_level`` and
    ``performance_level`` are pmset's warning levels (0 = none recorded)."""

    speed_limit: int | None = None
    warning_level: int = 0
    performance_level: int = 0


@dataclass(frozen=True)
class HostState:
    cpu_count: int
    load1: float
    load5: float
    load15: float
    total_ram_bytes: int
    available_ram_bytes: int
    disk_path: str
    disk_free_bytes: int
    disk_total_bytes: int
    pressure: str | None = None         # normal | warn | critical | None (unknown)
    battery: Battery | None = None      # None = not read (see unknown)
    thermal: Thermal | None = None      # None = not read (see unknown)
    unknown: tuple[tuple[str, str], ...] = ()
    source: str = "measured"

    def __post_init__(self) -> None:
        if self.cpu_count < 1:
            raise GovernorError(f"host cpu_count must be >= 1, got {self.cpu_count}")
        for name in ("load1", "load5", "load15"):
            v = getattr(self, name)
            if not math.isfinite(v) or v < 0:
                raise GovernorError(f"host {name} must be a finite number >= 0, got {v}")
        if self.available_ram_bytes < 0 or self.total_ram_bytes < self.available_ram_bytes:
            raise GovernorError(f"host RAM reading is inconsistent (available {self.available_ram_bytes},"
                                f" total {self.total_ram_bytes})")
        if self.disk_free_bytes < 0:
            raise GovernorError(f"disk free bytes is negative ({self.disk_free_bytes})")

    @property
    def load_per_cpu(self) -> float:
        return self.load1 / self.cpu_count

    def resources(self) -> _capacity.HostResources:
        """This reading as B-018's ``HostResources`` (for ``ctf.capacity`` sizing)."""
        return _capacity.HostResources(total_ram_bytes=self.total_ram_bytes,
                                       available_ram_bytes=self.available_ram_bytes,
                                       cpu_count=self.cpu_count, source=self.source)

    def to_dict(self) -> dict:
        return {
            "cpu_count": self.cpu_count, "load": [self.load1, self.load5, self.load15],
            "load_per_cpu": round(self.load_per_cpu, 2),
            "total_ram_gib": round(self.total_ram_bytes / GiB, 2),
            "available_ram_gib": round(self.available_ram_bytes / GiB, 2),
            "pressure": self.pressure,
            "battery": None if self.battery is None else {
                "present": self.battery.present, "percent": self.battery.percent,
                "plugged": self.battery.plugged, "state": self.battery.state},
            "thermal": None if self.thermal is None else {
                "speed_limit": self.thermal.speed_limit, "warning_level": self.thermal.warning_level,
                "performance_level": self.thermal.performance_level},
            "disk_path": self.disk_path, "disk_free_gib": round(self.disk_free_bytes / GiB, 2),
            "unknown": {k: v for k, v in self.unknown}, "source": self.source,
        }


_BATT_LINE = re.compile(r"(\d+(?:\.\d+)?)%;\s*([a-z][a-z ]*?)\s*(?:;|$)", re.M)


def parse_pmset_batt(text: str) -> Battery:
    """Parse ``pmset -g batt``. No ``InternalBattery`` line means no battery; a battery line that does
    not parse raises ``GovernorError`` (never read as "no battery")."""
    plugged = None
    m = re.search(r"Now drawing from '([^']+)'", text)
    if m:
        plugged = m.group(1).strip().lower() == "ac power"
    if "InternalBattery" not in text:
        return Battery(present=False, plugged=plugged)
    bm = _BATT_LINE.search(text.lower())
    if not bm:
        raise GovernorError(f"pmset -g batt: battery line not understood: {text.strip()[:200]!r}")
    state = bm.group(2).strip()
    state = {"ac attached": "not-charging", "not charging": "not-charging",
             "finishing charge": "finishing"}.get(state, state)
    return Battery(present=True, percent=float(bm.group(1)), plugged=plugged, state=state)


def parse_pmset_therm(text: str) -> Thermal | None:
    """Parse ``pmset -g therm``. None when the output carries none of the lines it knows (unknown)."""
    seen = False
    speed = None
    m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", text)
    if m:
        speed, seen = int(m.group(1)), True
    levels = {"thermal": 0, "performance": 0}
    for kind in levels:
        if re.search(rf"No {kind} warning level has been recorded", text, re.I):
            seen = True
        lm = re.search(rf"{kind} warning level[^0-9\n]*(\d+)", text, re.I)
        if lm and not re.search(rf"No {kind} warning level", text, re.I):
            levels[kind], seen = int(lm.group(1)), True
    if not seen:
        return None
    return Thermal(speed_limit=speed, warning_level=levels["thermal"],
                   performance_level=levels["performance"])


def parse_pressure_level(text: str) -> str | None:
    try:
        return PRESSURE_LEVELS.get(int(text.strip()))
    except ValueError:
        return None


def _run_cmd(argv: Sequence[str]) -> tuple[int, str]:
    """Run one read-only host query. FileNotFoundError and timeouts propagate to the caller, which
    records the reading as unknown with the reason."""
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=10)
    return p.returncode, p.stdout


def _existing(path: Path) -> Path:
    p = Path(path).expanduser()
    while not p.exists():
        if p.parent == p:
            break
        p = p.parent
    return p


def probe_host(disk_path: str | Path, *, run: Callable[[Sequence[str]], tuple[int, str]] = _run_cmd,
               psutil_mod: Any = None, loadavg: Callable[[], tuple[float, float, float]] | None = None,
               platform: str | None = None) -> HostState:
    """Read this host. Load and RAM are required (``GovernorError`` if they cannot be read); battery,
    thermal state and memory pressure that cannot be read are recorded in ``unknown`` with the reason.
    ``disk_path`` (or its nearest existing ancestor) is where free disk is measured."""
    platform = platform or sys.platform
    if psutil_mod is None:
        try:
            import psutil as psutil_mod
        except Exception as e:  # pragma: no cover - psutil is a pinned dependency
            raise GovernorError("psutil is required to read the host (pinned in requirements.in)") from e
    try:
        l1, l5, l15 = (loadavg or os.getloadavg)()
    except OSError as e:
        raise GovernorError(f"could not read the load average: {e}") from e
    try:
        vm = psutil_mod.virtual_memory()
        cpus = psutil_mod.cpu_count(logical=True)
    except Exception as e:
        raise GovernorError(f"could not read RAM / CPU count: {e}") from e
    if not cpus:
        raise GovernorError("could not read the host CPU count")
    unknown: list[tuple[str, str]] = []

    def query(name: str, argv: Sequence[str]) -> str | None:
        try:
            rc, out = run(argv)
        except FileNotFoundError:
            unknown.append((name, f"{argv[0]} not found"))
            return None
        except (OSError, subprocess.SubprocessError) as e:
            unknown.append((name, f"{' '.join(argv)} failed: {e}"))
            return None
        if rc != 0:
            unknown.append((name, f"{' '.join(argv)} exited {rc}"))
            return None
        return out

    # battery: psutil says whether there is one; pmset adds charging state on macOS
    battery: Battery | None
    try:
        sb = psutil_mod.sensors_battery()
    except Exception as e:
        sb, battery = None, None
        unknown.append(("battery", f"psutil.sensors_battery failed: {e}"))
    else:
        battery = Battery(present=False) if sb is None else Battery(
            present=True, percent=float(sb.percent), plugged=bool(sb.power_plugged))
    if platform == "darwin" and battery is not None and battery.present:
        out = query("battery-state", ["pmset", "-g", "batt"])
        if out is not None:
            try:
                pb = parse_pmset_batt(out)
            except GovernorError as e:
                unknown.append(("battery-state", str(e)))
            else:
                battery = replace(battery, state=pb.state,
                                  plugged=pb.plugged if pb.plugged is not None else battery.plugged)

    thermal: Thermal | None = None
    pressure: str | None = None
    if platform == "darwin":
        out = query("thermal", ["pmset", "-g", "therm"])
        if out is not None:
            thermal = parse_pmset_therm(out)
            if thermal is None:
                unknown.append(("thermal", f"pmset -g therm output not understood: {out.strip()[:120]!r}"))
        out = query("pressure", ["sysctl", "-n", "kern.memorystatus_vm_pressure_level"])
        if out is not None:
            pressure = parse_pressure_level(out)
            if pressure is None:
                unknown.append(("pressure", f"kern.memorystatus_vm_pressure_level = {out.strip()!r}"))
    else:
        unknown.append(("thermal", f"thermal state is read on macOS only (pmset); host is {platform}"))
        unknown.append(("pressure", f"memory pressure is read on macOS only (sysctl); host is {platform}"))

    dp = _existing(Path(disk_path))
    try:
        du = shutil.disk_usage(dp)
    except OSError as e:
        raise GovernorError(f"could not read free disk at {dp}: {e}") from e
    return HostState(cpu_count=int(cpus), load1=float(l1), load5=float(l5), load15=float(l15),
                     total_ram_bytes=int(vm.total), available_ram_bytes=int(vm.available),
                     disk_path=str(dp), disk_free_bytes=int(du.free), disk_total_bytes=int(du.total),
                     pressure=pressure, battery=battery, thermal=thermal, unknown=tuple(unknown))


# ------------------------------------------------------------------------------------------- policy

def _env_float(name: str, environ: Mapping[str, str] | None) -> float | None:
    raw = _env.get(name, environ=environ)
    if raw is None:
        return None
    try:
        v = float(raw)
    except ValueError:
        raise GovernorError(f"{name} is not a number: {raw!r}") from None
    if not math.isfinite(v):
        raise GovernorError(f"{name} must be a finite number, got {raw!r}")
    return v


@dataclass(frozen=True)
class GovernorPolicy:
    """``heavy_cap``    most heavy agents at once on this host, whatever the readings (PINK+: 4-6).
    ``heavy_ram_mb``    RAM one more heavy agent needs before it is admitted.
    ``reserve_ram_mb``  RAM held back for the OS and Docker production (B-018's reserve).
    ``load_soft`` / ``load_hard``  1-minute load per CPU at which the cap halves / no new agent starts.
    ``battery_low``     percent below which no new heavy agent starts on battery or on a losing charger.
    ``disk_min_gb``     free disk below which no new heavy agent starts.
    ``rss_alert_mb``    one agent tree's RSS at which the watchdog alerts.
    ``strict``          an unknown reading blocks instead of being reported."""

    heavy_cap: int = DEFAULT_HEAVY_CAP
    heavy_ram_mb: int = DEFAULT_HEAVY_RAM_MB
    reserve_ram_mb: int = _capacity.DEFAULT_RESERVE_RAM_MB
    load_soft: float = DEFAULT_LOAD_SOFT
    load_hard: float = DEFAULT_LOAD_HARD
    battery_low: int = DEFAULT_BATTERY_LOW
    disk_min_gb: float = DEFAULT_DISK_MIN_GB
    rss_alert_mb: int = DEFAULT_RSS_ALERT_MB
    agent_names: tuple[str, ...] = DEFAULT_AGENT_NAMES
    strict: bool = False

    def __post_init__(self) -> None:
        if self.heavy_cap < 1:
            raise GovernorError(f"heavy_cap must be >= 1, got {self.heavy_cap}")
        if self.heavy_ram_mb < 1:
            raise GovernorError(f"heavy_ram_mb must be >= 1, got {self.heavy_ram_mb}")
        if self.reserve_ram_mb < 0:
            raise GovernorError(f"reserve_ram_mb must be >= 0, got {self.reserve_ram_mb}")
        for name in ("load_soft", "load_hard", "disk_min_gb"):
            v = getattr(self, name)
            if not math.isfinite(v) or v < 0:
                raise GovernorError(f"{name} must be a finite number >= 0, got {v}")
        if self.load_soft <= 0 or self.load_hard < self.load_soft:
            raise GovernorError(f"need 0 < load_soft <= load_hard, got {self.load_soft} / {self.load_hard}")
        if not 0 <= self.battery_low <= 100:
            raise GovernorError(f"battery_low must be a percent 0-100, got {self.battery_low}")
        if self.rss_alert_mb < 1:
            raise GovernorError(f"rss_alert_mb must be >= 1, got {self.rss_alert_mb}")
        if not self.agent_names or any(not n.strip() for n in self.agent_names):
            raise GovernorError(f"agent_names must name at least one process, got {self.agent_names!r}")

    @classmethod
    def from_env(cls, *, environ: Mapping[str, str] | None = None) -> "GovernorPolicy":
        """Defaults with ``CTF_GOVERNOR_*`` overrides (and B-018's ``CTF_CAPACITY_RESERVE_MB``); a bad
        value raises ``GovernorError`` naming the variable."""
        kw: dict[str, Any] = {}
        try:
            ints = {
                "heavy_cap": _env.get_int("CTF_GOVERNOR_HEAVY_CAP", environ=environ),
                "heavy_ram_mb": _env.get_int("CTF_GOVERNOR_HEAVY_RAM_MB", environ=environ),
                "battery_low": _env.get_int("CTF_GOVERNOR_BATTERY_LOW", environ=environ),
                "rss_alert_mb": _env.get_int("CTF_GOVERNOR_RSS_ALERT_MB", environ=environ),
                "reserve_ram_mb": _env.get_int("CTF_CAPACITY_RESERVE_MB", environ=environ),
            }
            strict = _env.get_bool("CTF_GOVERNOR_STRICT", environ=environ)
        except _env.EnvError as e:
            raise GovernorError(str(e)) from e
        kw.update({k: v for k, v in ints.items() if v is not None})
        for key, var in (("load_soft", "CTF_GOVERNOR_LOAD_SOFT"), ("load_hard", "CTF_GOVERNOR_LOAD_HARD"),
                         ("disk_min_gb", "CTF_GOVERNOR_DISK_MIN_GB")):
            v = _env_float(var, environ)
            if v is not None:
                kw[key] = v
        names = _env.get("CTF_GOVERNOR_AGENT_NAMES", environ=environ)
        if names is not None:
            kw["agent_names"] = tuple(n.strip() for n in names.split(",") if n.strip())
            if not kw["agent_names"]:
                raise GovernorError(f"CTF_GOVERNOR_AGENT_NAMES names no process: {names!r}")
        kw["strict"] = strict
        return cls(**kw)


# ------------------------------------------------------------------------------------------- decision

@dataclass(frozen=True)
class Limit:
    """One resource's ceiling on concurrent heavy agents, with why."""

    resource: str
    ceiling: int
    reason: str


@dataclass(frozen=True)
class Decision:
    """``cap`` concurrent heavy agents the host takes now; ``running`` already hold a slot; ``slots`` may
    start. ``limits`` is every ceiling considered; ``binding`` those at the cap below the policy cap."""

    cap: int
    running: int
    heavy_cap: int
    limits: tuple[Limit, ...]
    unknown: tuple[tuple[str, str], ...] = ()

    @property
    def slots(self) -> int:
        return max(0, self.cap - self.running)

    @property
    def binding(self) -> tuple[Limit, ...]:
        if self.cap >= self.heavy_cap:
            return ()
        return tuple(l for l in self.limits if l.ceiling == self.cap)

    @property
    def reason(self) -> str:
        b = self.binding
        if not b:
            return f"policy cap {self.heavy_cap} heavy agents"
        return "; ".join(f"{l.resource}: {l.reason}" for l in b)

    def admit(self, ids: Sequence) -> "Admission":
        """Seat the first ``slots`` of ``ids`` now and queue the rest with the binding reason."""
        ids = list(ids)
        n = min(len(ids), self.slots)
        queued = tuple(ids[n:])
        why = ""
        if queued:
            why = (f"{len(queued)} queued: {self.running} running, cap {self.cap} "
                   f"({self.reason})")
        return Admission(granted=tuple(ids[:n]), queued=queued, reason=why)

    def to_dict(self) -> dict:
        return {"cap": self.cap, "running": self.running, "slots": self.slots,
                "heavy_cap": self.heavy_cap, "reason": self.reason,
                "limits": [{"resource": l.resource, "ceiling": l.ceiling, "reason": l.reason}
                           for l in self.limits],
                "unknown": {k: v for k, v in self.unknown}}


@dataclass(frozen=True)
class Admission:
    granted: tuple
    queued: tuple
    reason: str


def _half(cap: int) -> int:
    return max(1, cap // 2)


def decide(state: HostState, policy: GovernorPolicy | None = None, running: int = 0) -> Decision:
    """The ceiling on concurrent heavy agents for ``state`` under ``policy`` with ``running`` already
    holding slots. Ceilings are totals: RAM headroom adds to what is running (their RAM is already out
    of ``available``); load, pressure, battery, thermal and disk set an absolute ceiling."""
    policy = policy or GovernorPolicy()
    if running < 0:
        raise GovernorError(f"running must be >= 0, got {running}")
    cap = policy.heavy_cap
    limits = [Limit("policy", cap, f"heavy-agent cap {cap} (CTF_GOVERNOR_HEAVY_CAP)")]

    per = state.load_per_cpu
    load_txt = f"load {state.load1:.1f} on {state.cpu_count} CPUs ({per:.2f}/CPU)"
    if per >= policy.load_hard:
        limits.append(Limit("load", 0, f"{load_txt} >= hard {policy.load_hard}/CPU: no new heavy agent"))
    elif per >= policy.load_soft:
        limits.append(Limit("load", _half(cap), f"{load_txt} >= soft {policy.load_soft}/CPU: cap halved"))
    else:
        limits.append(Limit("load", cap, f"{load_txt} under soft {policy.load_soft}/CPU"))

    usable = max(0, state.available_ram_bytes - policy.reserve_ram_mb * MiB)
    headroom = usable // (policy.heavy_ram_mb * MiB)
    limits.append(Limit("ram", running + int(headroom),
                        f"{state.available_ram_bytes / GiB:.1f} GiB available - {policy.reserve_ram_mb} MiB "
                        f"reserve = room for {headroom} more at {policy.heavy_ram_mb} MiB each"))

    if state.pressure == "critical":
        limits.append(Limit("pressure", 0, "memory pressure critical: no new heavy agent"))
    elif state.pressure == "warn":
        limits.append(Limit("pressure", _half(cap), "memory pressure warn: cap halved"))

    b = state.battery
    if b is not None and b.present:
        pct = f"{b.percent:.0f}%" if b.percent is not None else "?%"
        low = b.percent is not None and b.percent < policy.battery_low
        if not b.plugged:
            if low:
                limits.append(Limit("battery", 0, f"on battery at {pct} < {policy.battery_low}%"))
            else:
                limits.append(Limit("battery", _half(cap), f"on battery ({pct}): cap halved"))
        elif b.charger_deficit:
            if low:
                limits.append(Limit("battery", 0, f"charger cannot keep up (discharging at {pct} < "
                                                   f"{policy.battery_low}% while plugged in)"))
            else:
                limits.append(Limit("battery", _half(cap),
                                    f"charger cannot keep up (discharging at {pct} while plugged in): "
                                    f"cap halved"))

    t = state.thermal
    if t is not None:
        lvl = max(t.warning_level, t.performance_level)
        sl = t.speed_limit if t.speed_limit is not None else 100
        if lvl >= 2 or sl < 60:
            limits.append(Limit("thermal", 0, f"thermal warning level {lvl}, CPU speed limit {sl}%"))
        elif lvl >= 1 or sl < 100:
            limits.append(Limit("thermal", _half(cap),
                                f"thermal warning level {lvl}, CPU speed limit {sl}%: cap halved"))

    floor = int(policy.disk_min_gb * GiB)
    if state.disk_free_bytes < floor:
        limits.append(Limit("disk", 0, f"{state.disk_free_bytes / GiB:.1f} GiB free at {state.disk_path} "
                                       f"< {policy.disk_min_gb:g} GiB (CTF_GOVERNOR_DISK_MIN_GB)"))

    if policy.strict:
        for name, why in state.unknown:
            limits.append(Limit(name, 0, f"not read ({why}) and CTF_GOVERNOR_STRICT is set"))

    return Decision(cap=max(0, min(l.ceiling for l in limits)), running=running, heavy_cap=cap,
                    limits=tuple(limits), unknown=state.unknown)


# ------------------------------------------------------------------------------------- slot leases

def _write_json(path: Path, rec: dict) -> None:
    """Write ``rec`` to ``path`` atomically: a temp file beside it (not ``*.json``, so no reader lists
    it), flushed and fsynced, then renamed over ``path``. A reader sees no file or the whole file, never
    a truncated one; a write that fails leaves nothing behind."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(rec))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@dataclass(frozen=True)
class Lease:
    id: str
    pid: int
    label: str
    started: float
    path: Path


class Governor:
    """Host-wide heavy-agent slots shared through files under ``state_dir``: ``leases/<id>.json`` per
    running heavy agent and ``queue/<id>.json`` per waiter, guarded by an flock on ``lock``. Every listing
    of those folders holds the lock, and files are written atomically (temp file, then rename). A lease
    or ticket whose process is gone, or that cannot be parsed, is reaped (and reported by ``reaped``)."""

    def __init__(self, state_dir: Path, policy: GovernorPolicy | None = None,
                 probe: Callable[[], HostState] | None = None, *,
                 pid_alive: Callable[[int], bool] = _pid_alive, clock: Callable[[], float] = time.time):
        self.dir = Path(state_dir)
        self.policy = policy or GovernorPolicy.from_env()
        self.probe = probe or (lambda: probe_host(self.dir))
        self.pid_alive = pid_alive
        self.clock = clock
        self.reaped: list[str] = []
        self.last: Decision | None = None
        self.last_state: HostState | None = None

    # files ------------------------------------------------------------------------------------
    def _sub(self, name: str) -> Path:
        p = self.dir / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _locked(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        fh = open(self.dir / "lock", "a+")
        fcntl.flock(fh, fcntl.LOCK_EX)
        return fh

    def _live(self, sub: str) -> list[tuple[Path, dict]]:
        out = []
        d = self.dir / sub
        if not d.is_dir():
            return out
        for p in sorted(d.glob("*.json")):
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
                pid = int(rec["pid"])
            except (OSError, ValueError, KeyError, TypeError):
                # an unreadable lease would hold a slot forever or hide one: name it and drop it
                self.reaped.append(f"{sub}/{p.name} (unreadable)")
                p.unlink(missing_ok=True)
                continue
            if not self.pid_alive(pid):
                self.reaped.append(f"{sub}/{p.name} (pid {pid} gone)")
                p.unlink(missing_ok=True)
                continue
            out.append((p, rec))
        return out

    def leases(self) -> list[Lease]:
        fh = self._locked()   # _live reaps files it cannot parse: only ever under the writers' lock
        try:
            live = self._live("leases")
        finally:
            fh.close()
        return [Lease(id=r.get("id", p.stem), pid=int(r["pid"]), label=str(r.get("label", "")),
                      started=float(r.get("started", 0)), path=p) for p, r in live]

    def queue(self) -> list[dict]:
        fh = self._locked()
        try:
            return [r for _, r in self._live("queue")]
        finally:
            fh.close()

    def decision(self) -> Decision:
        fh = self._locked()
        try:
            return self._decide_locked()
        finally:
            fh.close()

    def _decide_locked(self) -> Decision:
        running = len(self._live("leases"))
        self.last_state = self.probe()
        self.last = decide(self.last_state, self.policy, running)
        return self.last

    # tickets ----------------------------------------------------------------------------------
    def enqueue(self, label: str, pid: int | None = None) -> str:
        pid = os.getpid() if pid is None else pid
        tid = f"{time.time_ns():020d}-{pid}"
        fh = self._locked()
        try:
            _write_json(self._sub("queue") / f"{tid}.json",
                        {"id": tid, "pid": pid, "label": label, "queued": self.clock()})
        finally:
            fh.close()
        return tid

    def dequeue(self, ticket: str) -> None:
        (self.dir / "queue" / f"{ticket}.json").unlink(missing_ok=True)

    def try_acquire(self, ticket: str) -> Lease | None:
        """Admit ``ticket`` when it is within the free slots counting from the head of the queue."""
        fh = self._locked()
        try:
            queue = self._live("queue")
            ids = [p.stem for p, _ in queue]
            if ticket not in ids:
                raise GovernorError(f"ticket {ticket} is not queued (its process is gone or it was removed)")
            d = self._decide_locked()
            if ids.index(ticket) >= d.slots:
                return None
            path, rec = queue[ids.index(ticket)]
            lease = Lease(id=ticket, pid=int(rec["pid"]), label=str(rec.get("label", "")),
                          started=self.clock(), path=self._sub("leases") / f"{ticket}.json")
            _write_json(lease.path, {"id": lease.id, "pid": lease.pid, "label": lease.label,
                                     "started": lease.started})
            path.unlink(missing_ok=True)
            return lease
        finally:
            fh.close()

    def acquire(self, label: str, *, timeout: float | None = None, poll: float = 5.0,
                sleep: Callable[[float], None] = time.sleep,
                on_wait: Callable[[Decision, int], None] | None = None) -> Lease:
        """Queue, then wait until admitted. ``timeout`` None waits forever; past it ``GovernorTimeout``
        names the binding limit. ``on_wait(decision, position)`` is called each poll while waiting."""
        if poll <= 0:
            raise GovernorError(f"poll must be > 0, got {poll}")
        ticket = self.enqueue(label)
        start = self.clock()
        try:
            while True:
                lease = self.try_acquire(ticket)
                if lease is not None:
                    ticket = ""
                    return lease
                d = self.last
                if timeout is not None and self.clock() - start >= timeout:
                    raise GovernorTimeout(
                        f"not admitted within {timeout:g} s: {d.running} running, cap {d.cap} ({d.reason})")
                if on_wait is not None:
                    ids = [r["id"] for r in self.queue()]
                    on_wait(d, ids.index(ticket) if ticket in ids else -1)
                sleep(poll)
        finally:
            if ticket:
                self.dequeue(ticket)

    def release(self, lease: Lease) -> None:
        lease.path.unlink(missing_ok=True)


# ------------------------------------------------------------------------------------ RSS watchdog

@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    name: str
    rss_bytes: int
    cpu_seconds: float = 0.0
    exe: str = ""


@dataclass(frozen=True)
class AgentTree:
    """One agent process (``name`` matched ``agent_names``) and every descendant."""

    root: int
    name: str
    pids: tuple[int, ...]
    rss_bytes: int
    cpu_seconds: float


def snapshot_processes(psutil_mod: Any = None) -> tuple[list[Proc], int]:
    """Every process this user can read: ``(procs, unreadable)``. Processes psutil may not read
    (another user's, or gone mid-scan) are counted in ``unreadable``, never silently dropped."""
    if psutil_mod is None:
        import psutil as psutil_mod
    procs: list[Proc] = []
    unreadable = 0
    for p in psutil_mod.process_iter(["pid", "ppid", "name", "exe", "memory_info", "cpu_times"]):
        info = p.info
        mi, ct = info.get("memory_info"), info.get("cpu_times")
        if mi is None or info.get("name") is None:
            unreadable += 1
            continue
        cpu = float(ct.user + ct.system) if ct is not None else 0.0
        procs.append(Proc(pid=int(info["pid"]), ppid=int(info.get("ppid") or 0), name=str(info["name"]),
                          rss_bytes=int(mi.rss), cpu_seconds=cpu, exe=str(info.get("exe") or "")))
    return procs, unreadable


def is_agent(p: Proc, names: Iterable[str]) -> bool:
    """A process is an agent when its name is one of ``names`` exactly (case-sensitive, so the
    ``Claude`` desktop app is not the ``claude`` CLI), or its executable is a versioned install of one
    (Claude Code runs as ``.../claude/versions/<version>`` and shows the version as its name)."""
    names = set(names)
    if p.name in names or Path(p.exe).name in names:
        return True
    parts = Path(p.exe).parts
    return len(parts) >= 3 and parts[-2] == "versions" and parts[-3] in names


def agent_trees(procs: Sequence[Proc], names: Iterable[str] = DEFAULT_AGENT_NAMES) -> list[AgentTree]:
    """Group processes into agent trees: a root is a process whose name is in ``names`` with no
    matching ancestor; its tree is it plus all descendants (counted once)."""
    names = tuple(names)
    by_pid = {p.pid: p for p in procs}
    kids: dict[int, list[int]] = {}
    for p in procs:
        if p.ppid != p.pid:
            kids.setdefault(p.ppid, []).append(p.pid)

    def has_matching_ancestor(p: Proc) -> bool:
        seen = {p.pid}
        q = by_pid.get(p.ppid)
        while q is not None and q.pid not in seen:
            if is_agent(q, names):
                return True
            seen.add(q.pid)
            q = by_pid.get(q.ppid)
        return False

    out = []
    for p in procs:
        if not is_agent(p, names) or has_matching_ancestor(p):
            continue
        tree, stack = [], [p.pid]
        while stack:
            pid = stack.pop()
            if pid in tree:
                continue
            tree.append(pid)
            stack.extend(kids.get(pid, ()))
        out.append(AgentTree(root=p.pid, name=p.name, pids=tuple(sorted(tree)),
                             rss_bytes=sum(by_pid[x].rss_bytes for x in tree),
                             cpu_seconds=sum(by_pid[x].cpu_seconds for x in tree)))
    return sorted(out, key=lambda t: -t.rss_bytes)


def rss_alerts(trees: Sequence[AgentTree], policy: GovernorPolicy, total_ram_bytes: int) -> list[str]:
    """Alert lines: each agent tree at or over ``rss_alert_mb``, and all agent trees together at or over
    half of physical RAM. The watchdog alerts only; it never stops a process."""
    out = []
    limit = policy.rss_alert_mb * MiB
    for t in trees:
        if t.rss_bytes >= limit:
            out.append(f"agent {t.name} pid {t.root} tree RSS {t.rss_bytes / GiB:.1f} GiB "
                       f"({len(t.pids)} processes) >= {policy.rss_alert_mb} MiB (CTF_GOVERNOR_RSS_ALERT_MB)")
    total = sum(t.rss_bytes for t in trees)
    if trees and total_ram_bytes and total >= total_ram_bytes // 2:
        out.append(f"{len(trees)} agent trees hold {total / GiB:.1f} GiB RSS >= half of "
                   f"{total_ram_bytes / GiB:.0f} GiB RAM")
    return out


def record_alerts(state_dir: Path, alerts: Sequence[str], clock: Callable[[], float] = time.time) -> None:
    if not alerts:
        return
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(state_dir) / "alerts.jsonl", "a", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps({"ts": clock(), "alert": a}) + "\n")


# ------------------------------------------------------------------------------------- measurement

@dataclass(frozen=True)
class Measurement:
    """Per-agent RSS and CPU over an interval, and the B-018 knobs they imply."""

    agents: int
    interval: float
    rss_mib: tuple[float, ...]
    cpu_percent: tuple[float, ...]
    per_agent_ram_mb: int        # recommended CTF_CAPACITY_AGENT_RAM_MB
    agents_per_cpu: float | None  # recommended CTF_CAPACITY_AGENTS_PER_CPU (None: no CPU used)

    def to_dict(self) -> dict:
        return {"agents": self.agents, "interval": self.interval, "rss_mib": list(self.rss_mib),
                "cpu_percent": list(self.cpu_percent), "per_agent_ram_mb": self.per_agent_ram_mb,
                "agents_per_cpu": self.agents_per_cpu}


def _p90(xs: Sequence[float]) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, math.ceil(0.9 * len(s)) - 1)]


def measure(before: Sequence[Proc], after: Sequence[Proc], interval: float,
            names: Iterable[str] = DEFAULT_AGENT_NAMES) -> Measurement:
    """Measured per-agent budget from two snapshots ``interval`` seconds apart. RAM: the 90th-percentile
    tree RSS plus 25% headroom. CPU: 100 / mean tree CPU percent agents per logical CPU. Raises
    ``GovernorError`` when no agent process is running (nothing to measure is not a measurement)."""
    if interval <= 0:
        raise GovernorError(f"interval must be > 0, got {interval}")
    names = tuple(names)
    trees = agent_trees(after, names)
    if not trees:
        raise GovernorError(f"no agent processes named {', '.join(names)} are running to measure "
                            f"(start a lane, or set CTF_GOVERNOR_AGENT_NAMES)")
    cpu_before = {p.pid: p.cpu_seconds for p in before}
    by_pid = {p.pid: p for p in after}
    rss, cpu = [], []
    for t in trees:
        used = sum(max(0.0, by_pid[x].cpu_seconds - cpu_before.get(x, by_pid[x].cpu_seconds))
                   for x in t.pids)
        rss.append(round(t.rss_bytes / MiB, 1))
        cpu.append(round(100.0 * used / interval, 1))
    per_agent = int(math.ceil(_p90(rss) * 1.25))
    mean_cpu = sum(cpu) / len(cpu)
    apc = round(min(MAX_AGENTS_PER_CPU, 100.0 / mean_cpu), 2) if mean_cpu > 0 else None
    return Measurement(agents=len(trees), interval=interval, rss_mib=tuple(rss), cpu_percent=tuple(cpu),
                       per_agent_ram_mb=max(1, per_agent), agents_per_cpu=apc)


# ---------------------------------------------------------------------------------------- doctor

def host_checks(state: HostState, decision: Decision, policy: GovernorPolicy,
                trees: Sequence[AgentTree] | None = None,
                measurement: Measurement | None = None, measure_error: str = "") -> list:
    """The governor's readings as ``ctf.doctor.Check`` rows: host-load, host-ram, host-battery,
    host-thermal, host-disk, governor, agent-rss, agent-budget. A reading not taken is a ``skip`` naming
    why (never ok); with ``policy.strict`` it is a ``fail``."""
    from .doctor import Check

    unknown = dict(state.unknown)
    skip = "fail" if policy.strict else "skip"
    lim = {l.resource: l for l in decision.limits}
    out = []

    def from_limit(name: str, resource: str, ok_detail: str) -> None:
        l = lim.get(resource)
        if l is None or l.ceiling >= decision.heavy_cap:
            out.append(Check(name, "ok", ok_detail if l is None else l.reason))
        elif l.ceiling == 0:
            out.append(Check(name, "fail", l.reason, "wait for the host to recover, or free the resource"))
        else:
            out.append(Check(name, "warn", l.reason))

    from_limit("host-load", "load", "")
    ram = lim["ram"]
    pres = lim.get("pressure")
    if pres is not None and pres.ceiling == 0:
        out.append(Check("host-ram", "fail", pres.reason, "stop a heavy agent or a memory-hungry tool"))
    elif ram.ceiling - decision.running <= 0:
        out.append(Check("host-ram", "fail", ram.reason, "free RAM before starting another heavy agent"))
    elif pres is not None:
        out.append(Check("host-ram", "warn", f"{ram.reason}; {pres.reason}"))
    elif "pressure" in unknown:
        out.append(Check("host-ram", "warn", f"{ram.reason}; memory pressure not read ({unknown['pressure']})"))
    else:
        out.append(Check("host-ram", "ok", f"{ram.reason}; pressure {state.pressure}"))

    b = state.battery
    if b is None:
        out.append(Check("host-battery", skip, f"not read: {unknown.get('battery', 'no reading')}"))
    elif not b.present:
        out.append(Check("host-battery", "ok", "no battery (desktop): no battery limit"))
    else:
        detail = f"{b.percent:.0f}%, {'plugged in' if b.plugged else 'on battery'}, {b.state or 'state unread'}"
        if "battery" in lim:
            l = lim["battery"]
            out.append(Check("host-battery", "fail" if l.ceiling == 0 else "warn", l.reason,
                             "plug in a charger that can carry the load, or run fewer heavy agents"))
        elif "battery-state" in unknown:
            out.append(Check("host-battery", "warn",
                             f"{detail}; charging state not read ({unknown['battery-state']})"))
        else:
            out.append(Check("host-battery", "ok", detail))

    if state.thermal is None:
        out.append(Check("host-thermal", skip, f"not read: {unknown.get('thermal', 'no reading')}"))
    else:
        from_limit("host-thermal", "thermal",
                   f"no thermal or performance warning, CPU speed limit "
                   f"{state.thermal.speed_limit if state.thermal.speed_limit is not None else 100}%")

    from_limit("host-disk", "disk", f"{state.disk_free_bytes / GiB:.1f} GiB free at {state.disk_path} "
                                    f"(floor {policy.disk_min_gb:g} GiB)")

    gstat = "ok" if decision.slots > 0 else "warn"
    out.append(Check("governor", gstat, f"{decision.running} heavy agent(s) running, cap {decision.cap}, "
                                        f"{decision.slots} slot(s) free ({decision.reason})"))

    if trees is None:
        out.append(Check("agent-rss", skip, "process table not read"))
    else:
        alerts = rss_alerts(trees, policy, state.total_ram_bytes)
        if alerts:
            out.append(Check("agent-rss", "fail", "; ".join(alerts),
                             "find the runaway agent (ctf governor watch --once) and restart it"))
        else:
            biggest = f", largest {trees[0].rss_bytes / GiB:.1f} GiB" if trees else ""
            out.append(Check("agent-rss", "ok", f"{len(trees)} agent tree(s){biggest}, alert at "
                                                f"{policy.rss_alert_mb} MiB"))

    if measurement is not None:
        out.append(Check("agent-budget", "ok",
                         f"measured {measurement.agents} agent(s) over {measurement.interval:g} s: "
                         f"set CTF_CAPACITY_AGENT_RAM_MB={measurement.per_agent_ram_mb}"
                         + (f", CTF_CAPACITY_AGENTS_PER_CPU={measurement.agents_per_cpu}"
                            if measurement.agents_per_cpu is not None else "")))
    else:
        out.append(Check("agent-budget", skip,
                         f"not measured: {measure_error or 'run with --measure SECONDS'}"))
    return out
