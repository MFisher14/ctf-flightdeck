"""How intake denies engines the network (B-002).

    g = guard.resolve("auto")             # Guard(mode, prefix, reason); GuardError when it cannot hold
    argv = guard.wrap(g, runner.command(...), root)

Two layers:
  os    an OS network sandbox around the engine process and every child it starts: sandbox-exec with
        a deny-network profile on macOS, `unshare --net --map-root-user` on Linux. Probed once per
        process by running `true` under it (it fails, for example, inside another sandbox).
  hook  ctf/intake/_guardboot.py's audit hook in the engine interpreter: no socket but AF_UNIX, no
        name lookup, and no child process (a child would not carry the hook).
Both modes install the hook; mode os adds the OS sandbox and allows children. `auto` is os when the
probe passes, else hook, and the reason is written into every report: engines that start other
programs (`spawns = true`, or an external-command entry) are then not run, with that reason. Asking
for `os` where it is unavailable raises GuardError naming the probe's answer; nothing runs unguarded.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MODES = ("auto", "os", "hook")
DARWIN_PROFILE = "(version 1)(allow default)(deny network*)"
PROBE_TIMEOUT = 10

_PROBE: dict[str, tuple] = {}


class GuardError(RuntimeError):
    """The network guard asked for cannot be applied."""


@dataclass(frozen=True)
class Guard:
    mode: str                         # os | hook
    prefix: tuple[str, ...] = ()      # argv prefix of the OS sandbox (mode os)
    reason: str = ""

    @property
    def allows_spawn(self) -> bool:
        return self.mode == "os"


def _candidate() -> tuple[tuple[str, ...] | None, str]:
    if sys.platform == "darwin":
        exe = shutil.which("sandbox-exec")
        if not exe:
            return None, "sandbox-exec is not on PATH"
        return (exe, "-p", DARWIN_PROFILE), "sandbox-exec deny-network profile"
    if sys.platform.startswith("linux"):
        exe = shutil.which("unshare")
        if not exe:
            return None, "unshare is not on PATH"
        return (exe, "--net", "--map-root-user", "--"), "unshare --net (new empty network namespace)"
    return None, f"no OS network sandbox is known for {sys.platform}"


def os_sandbox(refresh: bool = False) -> tuple[tuple[str, ...] | None, str]:
    """(argv prefix, description) when the OS sandbox works here, else (None, why not). Cached."""
    if refresh or "os" not in _PROBE:
        prefix, what = _candidate()
        if prefix is not None:
            true = shutil.which("true") or "/usr/bin/true"
            try:
                cp = subprocess.run([*prefix, true], capture_output=True, timeout=PROBE_TIMEOUT)
            except (OSError, subprocess.TimeoutExpired) as e:
                prefix, what = None, f"{what} probe failed ({type(e).__name__}: {e})"
            else:
                if cp.returncode != 0:
                    err = cp.stderr.decode("utf-8", "replace").strip().splitlines()
                    prefix, what = None, (f"{what} probe exited {cp.returncode}"
                                          + (f": {err[-1]}" if err else ""))
        _PROBE["os"] = (prefix, what)
    return _PROBE["os"]


def resolve(mode: str = "auto") -> Guard:
    if mode not in MODES:
        raise GuardError(f"network guard {mode!r}: use one of {', '.join(MODES)}")
    if mode == "hook":
        return Guard("hook", (), "hook chosen: Python audit hook only; engines that start programs are not run")
    prefix, what = os_sandbox()
    if prefix is not None:
        return Guard("os", tuple(prefix), f"OS sandbox: {what}, plus the Python audit hook")
    if mode == "os":
        raise GuardError(f"network guard os asked for, but the OS sandbox is unavailable: {what}")
    return Guard("hook", (), f"OS sandbox unavailable ({what}): Python audit hook only; engines that "
                             "start other programs are not run")


def boot_path(root: Path) -> Path:
    return Path(root) / "ctf" / "intake" / "_guardboot.py"


def wrap(guard: Guard, cmd: list[str], root: Path) -> list[str]:
    """A runner.command(...) argv ([python, -I, <ctf/engines/_boot.py>, ...]) run under the guard."""
    if len(cmd) < 3 or cmd[1] != "-I" or Path(cmd[2]).name != "_boot.py":
        raise GuardError(f"unexpected engine command shape {cmd[:3]!r}: ctf.engines.runner.command changed")
    return [*guard.prefix, cmd[0], "-I", str(boot_path(root)), "--mode", guard.mode, "--", *cmd[2:]]
