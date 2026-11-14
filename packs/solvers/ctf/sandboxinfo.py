"""Is this process running inside a sandbox, and which capabilities did a self-test confirm (B-190)?

    from ctf import sandboxinfo
    info = sandboxinfo.detect()        # SandboxInfo(sandboxed, evidence, verified, failed)
    info.unverified(("network",))      # capabilities a result needed that this process could not confirm

Why: Codex ran readiness checks inside its own sandbox and reported what the sandbox denied (no
network, no Docker socket) as host blockers. A result seen only inside a sandbox is not a host fact.
The doctor (ctf/doctor.py) uses this to label such results "sandbox-only" instead of failing on them.

Evidence that the process is sandboxed (any one is enough):
  - the Codex sandbox's own markers: $CODEX_SANDBOX (e.g. "seatbelt"), $CODEX_SANDBOX_NETWORK_DISABLED
  - macOS: libsystem's sandbox_check(getpid(), NULL, 0) answers non-zero (a seatbelt profile applies;
    sandbox-exec, the Codex and Claude Code sandboxes all use one)
  - a capability probe that works on any normal host failed

Capability probes (no outside network, nothing left behind):
  loopback   bind a listener on 127.0.0.1:0 and connect to it
  tmp-write  create and delete a file in the temp folder

"network" (outbound to the internet or the platform) is never probed here: that would contact a
host. Inside a sandbox it is therefore always unverified, and so is "docker".
"""
from __future__ import annotations

import ctypes
import os
import platform
import socket
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Mapping

CAPABILITIES = ("loopback", "tmp-write", "network", "docker")
PROBED = ("loopback", "tmp-write")


@dataclass(frozen=True)
class SandboxInfo:
    sandboxed: bool
    evidence: tuple[str, ...] = ()
    verified: frozenset[str] = frozenset()          # probed and working
    failed: Mapping[str, str] = field(default_factory=dict)   # probed and broken: capability -> error

    def unverified(self, needs) -> tuple[str, ...]:
        """Of `needs`, the capabilities a result in this process cannot vouch for: all of them that
        were not verified, when sandboxed; none, on the host."""
        if not self.sandboxed:
            return ()
        return tuple(n for n in needs if n not in self.verified)

    def summary(self) -> str:
        if not self.sandboxed:
            return "not sandboxed"
        return "sandboxed: " + "; ".join(self.evidence)


def probe_loopback(timeout: float = 2.0) -> None:
    """Raise OSError unless a TCP listener on 127.0.0.1 accepts a connection from this process."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            pass
    finally:
        srv.close()


def probe_tmp_write() -> None:
    """Raise OSError unless a file can be created (and is removed) in the temp folder."""
    fd, name = tempfile.mkstemp(prefix="ctf-capcheck-")
    try:
        os.write(fd, b"ok")
    finally:
        os.close(fd)
        os.unlink(name)


DEFAULT_PROBES: dict[str, Callable[[], None]] = {"loopback": probe_loopback, "tmp-write": probe_tmp_write}


def macos_sandboxed() -> bool | None:
    """True/False from libsystem's sandbox_check for this process; None off macOS or when the call
    is not available (then it is simply not evidence either way)."""
    if platform.system() != "Darwin":
        return None
    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        fn = lib.sandbox_check
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    return fn(os.getpid(), None, 0) != 0


def detect(environ: Mapping[str, str] | None = None, *,
           probes: Mapping[str, Callable[[], None]] | None = None,
           os_check: Callable[[], bool | None] | None = macos_sandboxed) -> SandboxInfo:
    e = os.environ if environ is None else environ
    evidence: list[str] = []
    v = e.get("CODEX_SANDBOX")
    if v:
        evidence.append(f"CODEX_SANDBOX={v}")
    if (e.get("CODEX_SANDBOX_NETWORK_DISABLED") or "").strip() not in ("", "0"):
        evidence.append("CODEX_SANDBOX_NETWORK_DISABLED is set (network off in the Codex sandbox)")
    if os_check is not None and os_check():
        evidence.append("macOS sandbox_check: a sandbox profile applies to this process")
    verified, failed = set(), {}
    for name, fn in (DEFAULT_PROBES if probes is None else probes).items():
        try:
            fn()
        except Exception as err:  # the probe's point is to say what broke
            failed[name] = f"{type(err).__name__}: {err}"[:200]
        else:
            verified.add(name)
    for name, err in failed.items():
        evidence.append(f"{name} probe failed ({err})")
    return SandboxInfo(bool(evidence), tuple(evidence), frozenset(verified), dict(failed))
