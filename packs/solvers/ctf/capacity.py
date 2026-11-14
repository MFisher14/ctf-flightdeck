"""Agent capacity past the harness subagent cap (B-018).

A single harness process caps the number of concurrent subagents. Measured at a CTFd wave open, that
ceiling denied 16 of 36 Wave-1 dispatches with a median 375 s wait, while the wave skill still claimed
"no concurrency cap ... 30-40 agents run fine" (dev/SPEED-STUDY.md rank 4 / adopt item 5). The fix is to
stop trusting one process: size concurrent agent capacity to the *host* (RAM and CPU) and spread the
board across as many worker lanes -- separate harness processes or headless workers -- as the host can
run, so every challenge on a wave-sized board is seated at T0.

This module runs no model, makes no network call and launches nothing. It is pure sizing arithmetic:

  * ``measure_host()`` reads host facts (total/available RAM, logical CPUs) through psutil, failing
    loudly if it cannot -- never a silent guess.
  * ``CapacityPolicy`` holds the knobs (RAM per agent, host RAM held back for the OS and Max's Docker
    production services, agents per CPU, the per-process subagent cap, an optional worker ceiling), with
    ``from_env`` overrides read through ``ctf.env`` so nothing is hardcoded.
  * ``concurrency_budget(host, policy)`` turns host + policy into the concurrent-agent ceiling.
  * ``plan_board(demand, host, policy)`` lays a board of ``demand`` challenges onto worker lanes: it
    seats what the host can run at T0 and queues the rest **with a named reason** (``plan.reason``);
    nothing is dropped silently.

B-176 (host resource governor: load, battery, thermal, disk) is meant to build on ``HostResources`` and
``CapacityPolicy`` -- keep this the one place host sizing is computed.

Nothing here is authoritative about how many subagents a given harness build allows; ``per_worker_cap``
is that known limit and is a policy input, not something this module probes.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import Mapping, Sequence

from . import env as _env

_MB = 1024 * 1024


class CapacityError(RuntimeError):
    """Host sizing could not be computed; the message names what is missing or invalid."""


@dataclass(frozen=True)
class HostResources:
    """What the host can offer, in bytes and whole logical CPUs. ``source`` is ``measured`` from a live
    host or ``synthetic`` when built by hand (tests, what-if sizing)."""

    total_ram_bytes: int
    available_ram_bytes: int
    cpu_count: int
    source: str = "measured"

    def __post_init__(self) -> None:
        for name in ("total_ram_bytes", "available_ram_bytes", "cpu_count"):
            if getattr(self, name) < 0:
                raise CapacityError(f"host {name} is negative ({getattr(self, name)})")
        if self.cpu_count == 0:
            raise CapacityError("host cpu_count is 0; cannot size capacity")
        if self.available_ram_bytes > self.total_ram_bytes:
            raise CapacityError(
                f"host available_ram_bytes ({self.available_ram_bytes}) exceeds total "
                f"({self.total_ram_bytes})")


def measure_host() -> HostResources:
    """Read this host's RAM and CPU through psutil. Raises ``CapacityError`` (never a quiet default) if
    psutil is missing or a reading is unusable."""
    try:
        import psutil
    except Exception as e:  # pragma: no cover - psutil is a pinned dependency
        raise CapacityError(
            "psutil is required to size host capacity (add it to requirements.in and install)") from e
    try:
        vm = psutil.virtual_memory()
        cpu = psutil.cpu_count(logical=True) or psutil.cpu_count(logical=False)
    except Exception as e:  # pragma: no cover - defensive
        raise CapacityError(f"could not read host resources: {e}") from e
    if not cpu:
        raise CapacityError("could not read the host CPU count")
    return HostResources(total_ram_bytes=int(vm.total), available_ram_bytes=int(vm.available),
                         cpu_count=int(cpu), source="measured")


# Defaults. Agents are harness processes that spend most of their time waiting on a model API, so a host
# can run several per logical CPU; the RAM reservation is the real backstop. The reserve holds memory
# back for the OS and for Max's Docker production services on this machine.
DEFAULT_PER_AGENT_RAM_MB = 512
DEFAULT_RESERVE_RAM_MB = 4096
DEFAULT_AGENTS_PER_CPU = 4.0
DEFAULT_PER_WORKER_CAP = 20


@dataclass(frozen=True)
class CapacityPolicy:
    """Knobs that turn host facts into a concurrent-agent ceiling and a worker count.

    ``per_agent_ram_mb``   RAM reserved per concurrent agent lane.
    ``reserve_ram_mb``     host RAM held back (OS + Docker production) before dividing by the per-agent
                           reservation.
    ``agents_per_cpu``     concurrent agents per logical CPU (these are I/O-bound harness processes).
    ``per_worker_cap``     the harness subagent cap of ONE worker process -- the ceiling this item routes
                           around by running several workers.
    ``max_workers``        optional hard ceiling on worker processes (``None`` = host-bounded).
    ``use_available_ram``  size from available RAM (default, respects what is already running) or from
                           total RAM (``False``).
    """

    per_agent_ram_mb: int = DEFAULT_PER_AGENT_RAM_MB
    reserve_ram_mb: int = DEFAULT_RESERVE_RAM_MB
    agents_per_cpu: float = DEFAULT_AGENTS_PER_CPU
    per_worker_cap: int = DEFAULT_PER_WORKER_CAP
    max_workers: int | None = None
    use_available_ram: bool = True

    def __post_init__(self) -> None:
        if self.per_agent_ram_mb <= 0:
            raise CapacityError(f"per_agent_ram_mb must be > 0, got {self.per_agent_ram_mb}")
        if self.reserve_ram_mb < 0:
            raise CapacityError(f"reserve_ram_mb must be >= 0, got {self.reserve_ram_mb}")
        if not math.isfinite(self.agents_per_cpu):
            raise CapacityError(f"agents_per_cpu must be a finite number, got {self.agents_per_cpu}")
        if self.agents_per_cpu <= 0:
            raise CapacityError(f"agents_per_cpu must be > 0, got {self.agents_per_cpu}")
        if self.per_worker_cap < 1:
            raise CapacityError(f"per_worker_cap must be >= 1, got {self.per_worker_cap}")
        if self.max_workers is not None and self.max_workers < 1:
            raise CapacityError(f"max_workers must be >= 1 when set, got {self.max_workers}")

    @classmethod
    def from_env(cls, *, environ: Mapping[str, str] | None = None) -> "CapacityPolicy":
        """Policy with ``CTF_CAPACITY_*`` overrides applied, each failing loudly on a bad value.

        CTF_CAPACITY_AGENT_RAM_MB, CTF_CAPACITY_RESERVE_MB, CTF_CAPACITY_SUBAGENT_CAP,
        CTF_CAPACITY_MAX_WORKERS (int); CTF_CAPACITY_AGENTS_PER_CPU (float);
        CTF_CAPACITY_RAM_BASIS = available | total.
        """
        try:
            ints = {
                "per_agent_ram_mb": _env.get_int("CTF_CAPACITY_AGENT_RAM_MB", environ=environ),
                "reserve_ram_mb": _env.get_int("CTF_CAPACITY_RESERVE_MB", environ=environ),
                "per_worker_cap": _env.get_int("CTF_CAPACITY_SUBAGENT_CAP", environ=environ),
                "max_workers": _env.get_int("CTF_CAPACITY_MAX_WORKERS", environ=environ),
            }
        except _env.EnvError as e:
            raise CapacityError(str(e)) from e
        kw: dict = {k: v for k, v in ints.items() if v is not None}
        raw = _env.get("CTF_CAPACITY_AGENTS_PER_CPU", environ=environ)
        if raw:
            try:
                kw["agents_per_cpu"] = float(raw)
            except ValueError as e:
                raise CapacityError(f"CTF_CAPACITY_AGENTS_PER_CPU is not a number: {raw!r}") from e
            if not math.isfinite(kw["agents_per_cpu"]):
                raise CapacityError(f"CTF_CAPACITY_AGENTS_PER_CPU must be a finite number, got {raw!r}")
        basis = _env.get("CTF_CAPACITY_RAM_BASIS", environ=environ)
        if basis:
            if basis not in ("available", "total"):
                raise CapacityError(
                    f"CTF_CAPACITY_RAM_BASIS must be 'available' or 'total', got {basis!r}")
            kw["use_available_ram"] = basis == "available"
        return replace(cls(), **kw)


@dataclass(frozen=True)
class Budget:
    """The concurrent-agent ceiling and which resource bounds it."""

    capacity: int          # concurrent agents the host can run
    by_ram: int            # ceiling from RAM alone
    by_cpu: int            # ceiling from CPU alone
    binding: str           # "ram" | "cpu" | "tie"
    usable_ram_bytes: int  # RAM left after the reserve


def concurrency_budget(host: HostResources, policy: CapacityPolicy | None = None) -> Budget:
    """The number of agents this host can run at once under ``policy`` (default policy if ``None``)."""
    policy = policy or CapacityPolicy()
    ram = host.available_ram_bytes if policy.use_available_ram else host.total_ram_bytes
    usable = max(0, ram - policy.reserve_ram_mb * _MB)
    by_ram = usable // (policy.per_agent_ram_mb * _MB)
    by_cpu = math.floor(host.cpu_count * policy.agents_per_cpu)
    capacity = max(0, min(by_ram, by_cpu))
    if by_ram < by_cpu:
        binding = "ram"
    elif by_cpu < by_ram:
        binding = "cpu"
    else:
        binding = "tie"
    return Budget(capacity=int(capacity), by_ram=int(by_ram), by_cpu=int(by_cpu),
                  binding=binding, usable_ram_bytes=int(usable))


@dataclass(frozen=True)
class Seating:
    """What a policy lets the host seat at once: the host ``budget``, the worker processes that seating
    needs (``workers``, after any ``max_workers`` ceiling) and the agents they can hold (``seatable``)."""

    budget: Budget
    workers: int
    seatable: int


def seating(host: HostResources, policy: CapacityPolicy | None = None) -> Seating:
    """The host budget turned into worker processes and a seatable ceiling under ``policy``. Both
    ``ctf capacity show`` and ``plan_board`` use this, so they never disagree."""
    policy = policy or CapacityPolicy()
    budget = concurrency_budget(host, policy)
    cap = budget.capacity
    workers = math.ceil(cap / policy.per_worker_cap) if cap else 0
    if policy.max_workers is not None:
        workers = min(workers, policy.max_workers)
    return Seating(budget=budget, workers=workers, seatable=min(cap, workers * policy.per_worker_cap))


@dataclass(frozen=True)
class CapacityPlan:
    """A board laid onto worker lanes.

    ``demand``    challenges to seat.
    ``capacity``  host concurrent-agent ceiling (the budget).
    ``granted``   challenges seated at T0.
    ``workers``   worker processes (harness/headless) to run for ``granted``.
    ``lanes``     per-worker lists of challenge ids/indices (len == ``workers``).
    ``queued``    ids/indices not seated at T0 (never dropped).
    ``reason``    why any were queued, naming the binding limit; empty when all seated.
    """

    demand: int
    capacity: int
    granted: int
    workers: int
    per_worker_cap: int
    lanes: tuple[tuple, ...]
    queued: tuple
    reason: str
    budget: Budget

    @property
    def denied(self) -> int:
        return len(self.queued)

    @property
    def satisfied(self) -> bool:
        return self.denied == 0

    @property
    def multi_process(self) -> bool:
        """True when the plan needs more than one worker -- i.e. it is past a single harness's cap."""
        return self.workers > 1


def plan_board(demand: int,
               host: HostResources | None = None,
               policy: CapacityPolicy | None = None,
               *,
               ids: Sequence | None = None) -> CapacityPlan:
    """Lay ``demand`` challenges (or the explicit ``ids``) onto worker lanes for this host.

    Seats ``min(demand, capacity, max_workers*cap)`` at T0, block-filling lanes to ``per_worker_cap``, and
    queues the rest with a named reason. ``host`` defaults to ``measure_host()``, ``policy`` to
    ``CapacityPolicy.from_env()``.
    """
    policy = policy or CapacityPolicy.from_env()
    host = host or measure_host()
    if ids is not None:
        items = list(ids)
        if demand is None:
            demand = len(items)
        if len(items) != demand:
            raise CapacityError(f"ids has {len(items)} entries but demand is {demand}")
    else:
        if demand is None:
            raise CapacityError("plan_board needs a demand or explicit ids")
        if demand < 0:
            raise CapacityError(f"demand must be >= 0, got {demand}")
        items = list(range(demand))

    seat = seating(host, policy)
    budget, cap, seatable = seat.budget, seat.budget.capacity, seat.seatable

    granted = min(demand, seatable)
    workers_used = math.ceil(granted / policy.per_worker_cap) if granted else 0

    lanes: list[tuple] = []
    for w in range(workers_used):
        start = w * policy.per_worker_cap
        end = min(start + policy.per_worker_cap, granted)
        lanes.append(tuple(items[start:end]))
    queued = tuple(items[granted:])

    reason = ""
    if queued:
        reason = _queue_reason(demand, granted, budget, policy, seatable)

    return CapacityPlan(demand=demand, capacity=cap, granted=granted, workers=workers_used,
                        per_worker_cap=policy.per_worker_cap, lanes=tuple(lanes), queued=queued,
                        reason=reason, budget=budget)


def _queue_reason(demand: int, granted: int, budget: Budget, policy: CapacityPolicy,
                  seatable: int) -> str:
    short = demand - granted
    # A max_workers ceiling that bites below the host budget is the binding reason.
    if policy.max_workers is not None and seatable < budget.capacity:
        return (f"{short} of {demand} queued: CTF_CAPACITY_MAX_WORKERS={policy.max_workers} seats "
                f"{seatable} (host budget would allow {budget.capacity})")
    gb = budget.usable_ram_bytes / float(1024 ** 3)
    ram = f"{gb:.1f} GiB usable / {policy.per_agent_ram_mb} MiB per agent"
    if budget.binding == "tie":
        return (f"{short} of {demand} queued: host seats {budget.capacity} agents, RAM- and CPU-bound "
                f"alike ({ram}; {budget.by_cpu} = {policy.agents_per_cpu}/CPU)")
    if budget.binding == "ram":
        return (f"{short} of {demand} queued: host seats {budget.capacity} agents, RAM-bound ({ram})")
    return (f"{short} of {demand} queued: host seats {budget.capacity} agents, CPU-bound "
            f"({budget.by_cpu} = {policy.agents_per_cpu}/CPU)")
