"""The host governor: no new lane starts while this machine is over a limit.

A run that starts lanes faster than the machine can carry them loses all of them: at a load of
140, with the RAM gone or the disk nearly full, every agent dies. The governor reads three things
and holds new starts while one is past its limit (the `[governor]` table of the config):

- the load: the 1-minute load average divided by the number of CPUs, over `max_load_per_cpu`;
- the RAM available without swapping, under `min_free_ram_mb`. Linux: MemAvailable in
  /proc/meminfo. macOS: vm_stat's free, inactive and speculative pages times its page size
  (what the kernel can hand out without paging: the same sum Activity Monitor leaves out of
  "memory used");
- the free disk where the run folder is (the folder itself, or its nearest folder that
  exists), under `min_free_disk_mb`.

A limit of 0 is off. `enabled = false` turns the governor off whole.

probe() takes the readings. One that cannot be taken (another OS, a program missing, output
flightdeck does not understand) is unknown, with the reason (hardware.Fact), never a guess, and
decide() never holds a start for an unknown reading: the run says once, before it starts, which
reading it has not got. probe() sees the machine through a hardware.Host (programs from PATH's
absolute folders only, a short timeout) and three readers a test replaces: the load average, the
CPU count and a folder's disk usage. Nothing is written, signalled or contacted.

decide() is pure: a Reading, the policy and the number of lanes at work give a Decision. Each
limit that binds is one clause naming the limit and the reading ("load 4.2 per CPU (33.6 on 8
CPUs) is over max_load_per_cpu 3"). With no lane at work a lane may always start, whatever
binds: a run is never left with a queue and nothing running.

The governor only ever holds back a NEW lane. It stops, pauses and signals nothing: the lanes
at work carry on, and so does the queue's order. It is not a hold on the queue (Deck.hold_queue,
which waits for the player's /unhold and disengages autopilot): starts resume by themselves when
the reading recovers. Governor is what a run keeps (run.py): the last reading, taken again on
the run's tick off the event loop, and limit(), the gate the deck consults before it starts a
queued lane (Deck.start_gate).

From the solver pack's host governor (`packs/solvers/ctf/governor.py`), which caps its heavy
agents by load, RAM, battery, thermal state and disk with leases shared between harnesses. Here
there is one harness and one lane cap (`[lanes] max_lanes`), so the three readings that ran
machines into the ground are kept, and each either holds starts or does not.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import GovernorConfig
from .hardware import COMMAND_TIMEOUT, GIB, MIB, Fact, Host, ProbeError, RealHost, _output

TICK_SECONDS = 15.0  # how often a run reads the machine again (the load is a 1-minute average)
MAX_LOAD = 1_000_000.0  # a load average above this is not one
MAX_CPUS = 65_536
MAX_BYTES = 2**60  # 1 EiB: more RAM or disk than this is not a reading

_MEMAVAILABLE = re.compile(r"^MemAvailable:[ \t]+([0-9]+)[ \t]+kB[ \t]*$", re.M)
_PAGE_SIZE = re.compile(r"page size of ([0-9]+) bytes")
_PAGES = re.compile(r"^Pages (free|inactive|speculative):[ \t]+([0-9]+)\.[ \t]*$", re.M)
_AVAILABLE_PAGES = ("free", "inactive", "speculative")


@dataclass(frozen=True)
class Reading:
    """This machine now. Each fact is a value, or None and why it is unknown."""

    load: Fact[float]  # the 1-minute load average
    cpus: Fact[int]  # logical CPUs
    free_ram: Fact[int]  # bytes of RAM available without swapping
    free_disk: Fact[int]  # bytes free on the disk at `disk_path`
    disk_path: str  # the folder the disk was read at: the run folder, or its nearest folder that exists

    @property
    def load_per_cpu(self) -> Fact[float]:
        if self.load.value is None:
            return Fact(None, self.load.unknown)
        if self.cpus.value is None:
            return Fact(None, self.cpus.unknown)
        return Fact(self.load.value / self.cpus.value)

    def unknown(self) -> list[str]:
        """Each reading that could not be taken, with the reason."""
        named = (("the load per CPU", self.load_per_cpu), ("the available RAM", self.free_ram), ("the free disk", self.free_disk))
        return [f"{name} ({fact.unknown})" for name, fact in named if fact.value is None]


@dataclass(frozen=True)
class Decision:
    """decide()'s answer: may a new lane start, and each limit that binds now."""

    start: bool
    binding: tuple[str, ...] = ()  # one clause per limit that binds, naming the limit and the reading

    @property
    def limits(self) -> str:
        """The limits that bind, in one line; "" when none does."""
        return "; ".join(self.binding)

    @property
    def reason(self) -> str:
        """Why no new lane starts, in one line; "" when one may."""
        return "" if self.start else self.limits


def probe(
    path: Path,
    host: Host | None = None,
    *,
    loadavg: Callable[[], tuple[float, float, float]] | None = None,
    cpu_count: Callable[[], int | None] = os.cpu_count,
    disk_usage: Callable[[Path], tuple[int, int, int]] = shutil.disk_usage,
) -> Reading:
    """Read this machine (`host`, by default RealHost()); the disk is read at `path` (a run
    folder), or at its nearest folder that exists. Never raises for a reading it cannot take."""
    host = host if host is not None else RealHost()
    where = _existing(path)
    return Reading(
        load=_load(host, loadavg),
        cpus=_cpus(cpu_count),
        free_ram=_free_ram(host),
        free_disk=_free_disk(where, disk_usage),
        disk_path=str(where),
    )


def decide(reading: Reading, policy: GovernorConfig, running_lanes: int) -> Decision:
    """Whether a new lane may start with `running_lanes` at work. Pure: no clock, no I/O.

    A limit binds when its reading is known and past it; an unknown reading and a limit of 0
    bind nothing. With `enabled` false nothing binds. With no lane at work a lane may start
    whatever binds (Decision.binding still names what does)."""
    if isinstance(running_lanes, bool) or not isinstance(running_lanes, int) or running_lanes < 0:
        raise ValueError(f"running_lanes must be a whole number, 0 or more, not {running_lanes!r}")
    if not policy.enabled:
        return Decision(True)
    binding: list[str] = []
    per_cpu = reading.load_per_cpu.value
    if policy.max_load_per_cpu and per_cpu is not None and per_cpu > policy.max_load_per_cpu:
        cpus = reading.cpus.value
        binding.append(
            f"load {per_cpu:.1f} per CPU ({reading.load.value:.1f} on {cpus} CPU{'' if cpus == 1 else 's'}) "
            f"is over max_load_per_cpu {policy.max_load_per_cpu:g}"
        )
    ram = reading.free_ram.value
    if policy.min_free_ram_mb and ram is not None and ram < policy.min_free_ram_mb * MIB:
        binding.append(f"{_size(ram)} of RAM available is under min_free_ram_mb {policy.min_free_ram_mb}")
    disk = reading.free_disk.value
    if policy.min_free_disk_mb and disk is not None and disk < policy.min_free_disk_mb * MIB:
        binding.append(f"{_size(disk)} free on the disk at {reading.disk_path} is under min_free_disk_mb {policy.min_free_disk_mb}")
    return Decision(not binding or running_lanes == 0, tuple(binding))


def summary(reading: Reading) -> str:
    """The readings in one line, an unknown one with its reason."""
    per_cpu, ram, disk = reading.load_per_cpu, reading.free_ram, reading.free_disk
    cpus = reading.cpus.value
    parts = [
        f"load {per_cpu.value:.1f} per CPU ({cpus} CPU{'' if cpus == 1 else 's'})" if per_cpu.value is not None
        else f"load not read ({per_cpu.unknown})",
        f"{_size(ram.value)} of RAM available" if ram.value is not None else f"available RAM not read ({ram.unknown})",
        f"{_size(disk.value)} free on the disk at {reading.disk_path}" if disk.value is not None
        else f"free disk at {reading.disk_path} not read ({disk.unknown})",
    ]
    return ", ".join(parts)


class Governor:
    """A run's governor: the policy, where the disk is read, and the last reading."""

    def __init__(self, policy: GovernorConfig, path: Path, *, read: Callable[[Path], Reading] | None = None) -> None:
        self.policy = policy
        self.path = path
        self._read = read if read is not None else probe
        self.reading: Reading | None = None  # None until the first use()

    def take(self) -> Reading:
        """Read the machine (it may run a program: call it off the event loop). Changes nothing
        here: give the reading to use()."""
        return self._read(self.path)

    def use(self, reading: Reading | None) -> None:
        """The reading limit() goes by from now on; None: there is none, and nothing binds."""
        self.reading = reading

    def refresh(self) -> Reading:
        """take() and use() in one: the first reading, before the run's loop is up."""
        self.use(self.take())
        assert self.reading is not None
        return self.reading

    def limit(self) -> str:
        """The limits that bind at the last reading, in one line; "" when none does, the
        governor is off or nothing was read yet. The deck's start gate (Deck.start_gate): the
        deck itself lets a lane start when none is at work."""
        if self.reading is None:
            return ""
        return decide(self.reading, self.policy, 0).limits


def _size(n: int) -> str:
    return f"{n / GIB:.1f} GiB" if n >= GIB else f"{n // MIB} MiB"


def _existing(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def _load(host: Host, loadavg: Callable[[], tuple[float, float, float]] | None) -> Fact[float]:
    if loadavg is None:
        loadavg = getattr(os, "getloadavg", None)
        if loadavg is None:
            return Fact(None, f"this Python has no load average to read on {host.system or 'this OS'}")
    try:
        one = loadavg()[0]
    except OSError as exc:
        return Fact(None, f"the load average cannot be read ({exc.strerror or type(exc).__name__})")
    if isinstance(one, bool) or not isinstance(one, (int, float)) or not 0 <= one < MAX_LOAD:  # a NaN fails both
        return Fact(None, "the load average read is not a load")
    return Fact(float(one))


def _cpus(cpu_count: Callable[[], int | None]) -> Fact[int]:
    count = cpu_count()
    if isinstance(count, bool) or not isinstance(count, int) or not 0 < count <= MAX_CPUS:
        return Fact(None, "the number of CPUs cannot be read")
    return Fact(count)


def _free_ram(host: Host) -> Fact[int]:
    if host.system == "Linux":
        try:
            text = host.read("/proc/meminfo")
        except OSError as exc:
            return Fact(None, f"/proc/meminfo cannot be read ({exc.strerror or type(exc).__name__})")
        found = _MEMAVAILABLE.findall(text)
        if len(found) != 1 or not int(found[0]) * 1024 < MAX_BYTES:
            return Fact(None, "/proc/meminfo has no MemAvailable line in kB that flightdeck can read")
        return Fact(int(found[0]) * 1024)
    if host.system == "Darwin":
        try:
            text = _output(host, "vm_stat", [], COMMAND_TIMEOUT)
        except ProbeError as exc:
            return Fact(None, str(exc))
        size = _PAGE_SIZE.findall(text)
        pages = _PAGES.findall(text)
        if len(size) != 1 or not 0 < int(size[0]) <= GIB or sorted(name for name, _ in pages) != sorted(_AVAILABLE_PAGES):
            return Fact(None, "vm_stat printed something flightdeck cannot read the page size and the free, "
                              "inactive and speculative pages from")
        available = int(size[0]) * sum(int(count) for _, count in pages)
        if not available < MAX_BYTES:
            return Fact(None, "vm_stat printed more available memory than a machine has")
        return Fact(available)
    return Fact(None, f"available RAM is read on macOS and Linux (WSL counts as Linux), not on {host.system or 'this OS'}")


def _free_disk(where: Path, disk_usage: Callable[[Path], tuple[int, int, int]]) -> Fact[int]:
    try:
        free = disk_usage(where)[2]
    except OSError as exc:
        return Fact(None, f"the disk at {where} cannot be read ({exc.strerror or type(exc).__name__})")
    if isinstance(free, bool) or not isinstance(free, int) or not 0 <= free < MAX_BYTES:
        return Fact(None, f"the free space read for the disk at {where} is not a number of bytes")
    return Fact(free)
