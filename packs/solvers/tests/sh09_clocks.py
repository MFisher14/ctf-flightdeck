"""SH-09: load-independent clocks and a work meter for the suite's cost bounds (not a test module).

The suite runs at a load average of 50 to 170 on 14 cores. That breaks a bound in two ways:

  waiting   a process that waits for a core accrues wall time but no CPU time. Fixed by counting CPU time
            (thread_seconds) or by running an engine's own wall-clock budgets on the CPU clock (cpu_clock),
            as SH-08 did.
  a slower  under sustained all-core load this machine (a laptop) runs its cores far below their top clock:
  core      measured 2.0 to 2.2 GHz on the performance cores against a top clock of 4.51 GHz, and 2.6 GHz on
            the efficiency cores. The same work then takes about twice the CPU seconds, so a CPU-time bound
            set on an idle machine fails under load (SH-08's gap). work_seconds counts the work in core
            cycles, which a lower clock does not change, and gives it in seconds at the top clock: what the
            work costs on an idle machine, the machine the bounds were set on. Work that runs on an
            efficiency core takes more cycles (about 1.5x), so the reading errs on the strict side.

    with cpu_clock(): ...                      time.monotonic and time.perf_counter read process CPU time
                                               (code that waits must not run inside: time.sleep raises)
    out, s = thread_seconds(fn, *a, **kw)      CPU seconds of this thread
    out, s = work_seconds(fn, *a, **kw)        seconds at the top clock (cycles / TOP_CLOCK_HZ)
    out, s, why = work_seconds_unless_missing(fn, *a, **kw)
                                               the same; without a meter fn still runs, s is None and why
                                               names what is absent

work_seconds needs the per-process cycle counter (macOS proc_pid_rusage, RUSAGE_INFO_V4) and the chip's top
clock (TOP_CLOCK_HZ). Without either it raises WorkMeterMissing with the reason. A test whose answer checks do
not need the meter still runs them (work_seconds_unless_missing) and then reports only its cost bound not run
(cost_not_run), never as passed.
"""
from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import os
import sys
import time

# The performance cores' top clock, by the chip's brand string (sysctl machdep.cpu.brand_string), from the
# maker's specification. A chip that is not listed has no work meter: its cost checks are reported not run.
TOP_CLOCK_HZ = {
    "Apple M4 Max": 4.51e9,
}


class WorkMeterMissing(RuntimeError):
    """The cycle counter or the chip's top clock is not available here."""


class CpuClockWait(RuntimeError):
    """Code inside cpu_clock() tried to wait (time.sleep)."""


def _no_wait(seconds):
    raise CpuClockWait(
        f"time.sleep({seconds!r}) inside sh09_clocks.cpu_clock(): code that waits must not run on the CPU clock "
        f"(process time does not advance while it waits, so a wait until a time.monotonic deadline would never end)")


@contextlib.contextmanager
def cpu_clock():
    """For the block, time.monotonic and time.perf_counter read time.process_time.

    An engine whose budgets and deadlines are read from those clocks then counts them in seconds of this
    process's work: the same budgets, but a process that waits for a core spends none of them. Work over a
    budget still runs it out. Code that bound a clock function at import (threading, subprocess) keeps the
    real one. The clocks come back on any exit.

    Code that WAITS must not run inside it. Process time does not advance while the process sleeps or waits
    on another process, so a loop that sleeps until time.monotonic() passes a deadline would never end. So
    that such code fails loudly instead of hanging, time.sleep raises CpuClockWait inside the block. A module
    that bound sleep at import (`from time import sleep`) keeps the real one: do not wrap such code."""
    saved = time.monotonic, time.perf_counter, time.sleep
    time.monotonic = time.perf_counter = time.process_time
    time.sleep = _no_wait
    try:
        yield
    finally:
        time.monotonic, time.perf_counter, time.sleep = saved


def thread_seconds(fn, *args, **kwargs):
    """(fn(*args, **kwargs), the CPU seconds this thread spent in it)."""
    t0 = time.thread_time()
    out = fn(*args, **kwargs)
    return out, time.thread_time() - t0


class _RUsageInfoV4(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in (
        "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups", "ri_pageins",
        "ri_wired_size", "ri_resident_size", "ri_phys_footprint", "ri_proc_start_abstime", "ri_proc_exit_abstime",
        "ri_child_user_time", "ri_child_system_time", "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
        "ri_child_pageins", "ri_child_elapsed_abstime", "ri_diskio_bytesread", "ri_diskio_byteswritten",
        "ri_cpu_time_qos_default", "ri_cpu_time_qos_maintenance", "ri_cpu_time_qos_background",
        "ri_cpu_time_qos_utility", "ri_cpu_time_qos_legacy", "ri_cpu_time_qos_user_initiated",
        "ri_cpu_time_qos_user_interactive", "ri_billed_system_time", "ri_serviced_system_time",
        "ri_logical_writes", "ri_lifetime_max_phys_footprint", "ri_instructions", "ri_cycles",
        "ri_billed_energy", "ri_serviced_energy", "ri_interval_max_phys_footprint", "ri_runnable_time")]


_RUSAGE_INFO_V4 = 4
_METER = {}


def _sysctl_string(name: str, libc) -> str:
    size = ctypes.c_size_t(0)
    if libc.sysctlbyname(name.encode(), None, ctypes.byref(size), None, 0) != 0 or not size.value:
        raise WorkMeterMissing(f"sysctl {name} is not readable here")
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctlbyname(name.encode(), buf, ctypes.byref(size), None, 0) != 0:
        raise WorkMeterMissing(f"sysctl {name} is not readable here")
    return buf.value.decode("utf-8", "replace").strip()


def meter():
    """(read_cycles, top_clock_hz): the process cycle counter and the chip's top clock. WorkMeterMissing
    names what is absent. Looked up once per process."""
    if "got" in _METER:
        return _METER["got"]
    if sys.platform != "darwin":
        raise WorkMeterMissing(f"no per-process cycle counter on {sys.platform} (macOS proc_pid_rusage only)")
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                  ctypes.c_void_p, ctypes.c_size_t]
    brand = _sysctl_string("machdep.cpu.brand_string", libc)
    hz = TOP_CLOCK_HZ.get(brand)
    if hz is None:
        raise WorkMeterMissing(f"no top clock is known for the chip {brand!r} (tests/sh09_clocks.py TOP_CLOCK_HZ)")
    path = ctypes.util.find_library("proc")
    if not path:
        raise WorkMeterMissing("libproc is not found")
    proc = ctypes.CDLL(path, use_errno=True)
    proc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(_RUsageInfoV4)]
    pid = os.getpid()

    def read_cycles() -> int:
        ri = _RUsageInfoV4()
        if proc.proc_pid_rusage(pid, _RUSAGE_INFO_V4, ctypes.byref(ri)) != 0:
            raise WorkMeterMissing(f"proc_pid_rusage failed (errno {ctypes.get_errno()})")
        return ri.ri_cycles

    if read_cycles() <= 0:
        raise WorkMeterMissing("proc_pid_rusage gives no cycle count here")
    _METER["got"] = (read_cycles, hz)
    return _METER["got"]


def work_seconds(fn, *args, **kwargs):
    """(fn(*args, **kwargs), its work in seconds at the chip's top clock: the core cycles this process spent
    in it over TOP_CLOCK_HZ). Raises WorkMeterMissing before fn runs when the meter is not available."""
    read_cycles, hz = meter()
    c0 = read_cycles()
    out = fn(*args, **kwargs)
    return out, (read_cycles() - c0) / hz


def work_seconds_unless_missing(fn, *args, **kwargs):
    """(fn(*args, **kwargs), its work in seconds at the top clock, None) with the meter, and
    (fn(*args, **kwargs), None, the reason) without it. Without the meter fn still runs, so the checks of what
    it returned still run; the caller must then report its cost bound not run with the reason (cost_not_run),
    never pass it."""
    try:
        meter()
    except WorkMeterMissing as e:
        return fn(*args, **kwargs), None, str(e)
    out, work = work_seconds(fn, *args, **kwargs)
    return out, work, None


def cost_not_run(reason):
    """In a pytest test, after its answer checks ran: report the test not run for its cost bound, with the
    reason the work meter is missing."""
    import pytest
    pytest.skip(f"not run: the cost bound has no work meter ({reason}); the answer checks before it ran and passed")


def not_run_without_meter():
    """In a pytest test: report the test not run (with the reason) when work_seconds cannot measure here."""
    import pytest
    try:
        meter()
    except WorkMeterMissing as e:
        pytest.skip(f"not run: no work meter ({e})")
