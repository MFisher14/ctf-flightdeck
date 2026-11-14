#!/usr/bin/env python3
"""Focused tests for the Darwin/arm64 Unicorn cache-line capability guard.

The dangerous path is never invoked here: fake ``sysctlbyname`` functions exercise success,
denial, malformed output and exceptions.  On a sandboxed Apple-silicon host, the final check also
proves the public emulator declines before Unicorn's first ``mem_map`` instead of taking SIGILL.

Run:  .venv/bin/python -I -B tests/test_unicorn_capability_guard.py
"""
import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "common"))

import native_emulate as ne  # noqa: E402

PASS = 0
FAIL = 0


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name)


def fake_sysctl(result=0, value=128, size=8, raises=False):
    def call(name, old_value, old_size, new_value, new_size):
        if raises:
            raise OSError("synthetic sysctl failure")
        if old_value:
            ctypes.cast(old_value, ctypes.POINTER(ctypes.c_uint64))[0] = value
        if old_size:
            ctypes.cast(old_size, ctypes.POINTER(ctypes.c_size_t))[0] = size
        return result

    return call


def declines_without_mapping():
    try:
        ne.emulate_x86_sysv(b"\xc3", [])
    except ne.EmulationError as exc:
        return "not available" in str(exc)
    except Exception:
        return False
    return False


def main():
    called = []

    def should_not_run(*args):
        called.append(args)
        return -1

    check("non-Darwin bypasses the Darwin probe",
          ne._darwin_arm64_cacheline_usable("linux", "arm64", should_not_run) and not called)
    check("Darwin x86_64 bypasses the arm64 probe",
          ne._darwin_arm64_cacheline_usable("darwin", "x86_64", should_not_run) and not called)
    check("Darwin arm64 accepts a readable nonzero cache line",
          ne._darwin_arm64_cacheline_usable("darwin", "arm64", fake_sysctl()))
    check("Darwin arm64 denies a failed cache-line sysctl",
          not ne._darwin_arm64_cacheline_usable("darwin", "arm64", fake_sysctl(result=-1)))
    check("Darwin arm64 denies a zero cache-line value",
          not ne._darwin_arm64_cacheline_usable("darwin", "arm64", fake_sysctl(value=0)))
    check("Darwin arm64 denies a malformed cache-line size",
          not ne._darwin_arm64_cacheline_usable("darwin", "arm64", fake_sysctl(size=16)))
    check("Darwin arm64 denies a cache-line probe exception",
          not ne._darwin_arm64_cacheline_usable("darwin", "arm64", fake_sysctl(raises=True)))

    host_capable = ne._darwin_arm64_cacheline_usable()
    check("host capability controls Unicorn availability",
          host_capable or (not ne.UNICORN_AVAILABLE and declines_without_mapping()))

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
