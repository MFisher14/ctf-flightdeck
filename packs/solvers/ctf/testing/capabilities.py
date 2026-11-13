"""Capabilities a sandbox can take away from the test process (B-192), for the test markers
`needs_loopback` and `needs_jit` (ctf/testing/pytest_plugin.py, docs/CONTRACTS.md section 9).

    from ctf.testing import capabilities
    capabilities.loopback()   # Capability(ok, reason): can this process bind and connect on 127.0.0.1?
    capabilities.jit()        # Capability(ok, reason): can a child process run JIT code (and Unicorn)?

Why: Codex's workspace-write sandbox denied loopback bind (most of one lane's 27 failures were fake
services that could not listen) and killed Unicorn with SIGILL. The SIGILL is not a JIT denial:
plain MAP_JIT code runs under Codex's seatbelt. Its policy (codex-cli 0.167) allows the sysctl
"hw.cachelinesize_compat" but not "hw.cachelinesize"; Unicorn's QEMU then falls back to reading the
cache type register, which traps (verified: `sandbox-exec` with only that one sysctl denied kills
Unicorn the same way). No Codex setting adds a sysctl, so a test that needs Unicorn's JIT is
reported as not run there, with the probe's own error as the reason, instead of failing.

Each probe runs once per process and is cached. The JIT probe runs in a child Python, because a
failing JIT engine kills the process that tries it (SIGILL), and that must not be the test runner.
"""
from __future__ import annotations

import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Sequence

from .. import sandboxinfo


@dataclass(frozen=True)
class Capability:
    ok: bool
    reason: str = ""           # why not, when not ok


# The child: map one page with MAP_JIT, write `mov w0, #42; ret` (arm64) or `mov eax, 42; ret`
# (x86-64) into it and call it; then, when Unicorn is installed, emulate two x86 instructions with
# it (the engine that died under Codex). Prints JIT-OK 42 on success; a sandbox that denies it
# refuses the mapping (exit 3, JIT-DENIED) or kills the child (SIGILL / SIGKILL / SIGBUS).
JIT_PROBE_SRC = r"""
import ctypes, errno, os, platform, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                      ctypes.c_long]
darwin = sys.platform == "darwin"
MAP_PRIVATE = 0x2
MAP_ANON = 0x1000 if darwin else 0x20
MAP_JIT = 0x800 if darwin else 0
size = 16384
p = libc.mmap(None, size, 7, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0)
if p is None or p == ctypes.c_void_p(-1).value:
    e = ctypes.get_errno()
    print("JIT-DENIED mmap:", errno.errorcode.get(e, e), os.strerror(e))
    sys.exit(3)
arch = platform.machine().lower()
if arch in ("arm64", "aarch64"):
    code = bytes.fromhex("40058052c0035fd6")          # mov w0, #42 ; ret
elif arch in ("x86_64", "amd64"):
    code = bytes.fromhex("b82a000000c3")              # mov eax, 42 ; ret
else:
    print("JIT-UNKNOWN-ARCH", arch)
    sys.exit(4)
if darwin and arch == "arm64":
    wp = libc.pthread_jit_write_protect_np
    wp.argtypes = [ctypes.c_int]
    wp(0)
ctypes.memmove(p, code, len(code))
if darwin and arch == "arm64":
    wp(1)
    inv = libc.sys_icache_invalidate
    inv.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    inv(p, len(code))
fn = ctypes.CFUNCTYPE(ctypes.c_int)(p)
got = fn()
try:
    import unicorn
except ImportError:
    unicorn = None
if unicorn is not None:
    from unicorn import x86_const
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, b"\x41\x41")                # inc ecx ; inc ecx
    uc.reg_write(x86_const.UC_X86_REG_ECX, 40)
    uc.emu_start(0x1000, 0x1002)
    got = uc.reg_read(x86_const.UC_X86_REG_ECX)
print("JIT-OK", got, "unicorn" if unicorn is not None else "no-unicorn")
"""

# Not a bound on the probe's work: it only keeps a hung child from hanging the test session, so it
# sits far above a Python start-up on a heavily loaded machine (wall-clock by nature).
JIT_PROBE_TIMEOUT_S = 120.0

_CACHE: dict[str, Capability] = {}


def classify_jit(returncode: int, stdout: str, stderr: str) -> Capability:
    """Read the JIT child's result. Only "JIT-OK 42" with exit 0 counts as working."""
    out = (stdout or "").strip()
    if returncode == 0 and "JIT-OK 42" in out:
        return Capability(True)
    # A signal death: negative from subprocess, or 128+N when a wrapper (a shell, `codex sandbox`)
    # passes the child's death on as an exit status.
    signum = -returncode if returncode < 0 else returncode - 128 if 128 < returncode < 160 else 0
    if signum:
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = f"signal {signum}"
        return Capability(False, f"a JIT child was killed by {name} (exit {returncode}): the sandbox "
                                 "does not let JIT code (Unicorn) run")
    tail = (out or (stderr or "").strip()).splitlines()
    detail = tail[-1][:160] if tail else "no output"
    return Capability(False, f"a JIT child failed (exit {returncode}: {detail})")


def probe_jit(argv: Sequence[str] | None = None, *, timeout: float = JIT_PROBE_TIMEOUT_S) -> Capability:
    """Run the JIT child (argv replaces it, for tests) and classify its result. Uncached."""
    cmd = list(argv) if argv is not None else [sys.executable, "-I", "-c", JIT_PROBE_SRC]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return Capability(False, f"the JIT child did not finish within {timeout:g} s")
    except OSError as e:
        return Capability(False, f"could not start the JIT child: {e}")
    return classify_jit(r.returncode, r.stdout, r.stderr)


def probe_loopback() -> Capability:
    """Uncached: bind a listener on 127.0.0.1:0 and connect to it (ctf.sandboxinfo's probe)."""
    try:
        sandboxinfo.probe_loopback()
    except OSError as e:
        return Capability(False, f"cannot bind and connect on 127.0.0.1 ({type(e).__name__}: {e}); "
                                 "a sandbox denies loopback")
    return Capability(True)


def loopback() -> Capability:
    if "loopback" not in _CACHE:
        _CACHE["loopback"] = probe_loopback()
    return _CACHE["loopback"]


def jit() -> Capability:
    if "jit" not in _CACHE:
        _CACHE["jit"] = probe_jit()
    return _CACHE["jit"]


def reset() -> None:
    """Forget cached results (a test that changes what the probes see)."""
    _CACHE.clear()


def is_socket_denial(exc: BaseException | None) -> bool:
    """True when `exc` (or an exception it explicitly wraps: `raise ... from` (__cause__), a
    `reason` attribute (URLError, urllib3's MaxRetryError) or an exception among its args (requests'
    ConnectionError)) is an EPERM/EACCES OSError with no file name: what a sandbox's denied bind or
    connect raises. A denied file operation carries the file name and does not count.

    __context__ is NOT followed: it only says an exception was being handled when this one was
    raised, so an assert that fails inside `except PermissionError:` (or after an EPERM from
    os.kill) is a real failure, never a socket denial."""
    import errno as _errno
    seen: set[int] = set()
    stack = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen or not isinstance(e, BaseException):
            continue
        seen.add(id(e))
        if (isinstance(e, OSError) and e.errno in (_errno.EPERM, _errno.EACCES)
                and e.filename is None and e.filename2 is None):
            return True
        stack += [e.__cause__, getattr(e, "reason", None)]
        if not isinstance(e, AssertionError):       # `assert ok, err` puts err in args: a failure
            stack += [a for a in getattr(e, "args", ()) if isinstance(a, BaseException)]
    return False

