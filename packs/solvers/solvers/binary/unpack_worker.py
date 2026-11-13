#!/usr/bin/env python3
"""An isolated unpack worker: recover a packed PE's code by bounded emulation, in a sandboxed child (B-241).

UPX has a real recovery road (``upx -d`` in the Docker sandbox, B-167).  Every other protector family was
recognition only: the stub that rebuilds the program is code, and reading it by hand is the +30 minute
class.  This engine runs the stub where it can do no harm and stops where the rebuilt program begins:

  * the image is mapped by ``pe_emu.map_pe`` and run inside ``pe_emu.SafeUnicorn`` (PE32 and PE32+) with
    the modelled Windows environment, every byte of the image the run writes recorded;
  * the run stops at the first instruction fetched from bytes it wrote (the stub handing over to what it
    unpacked: the original entry point), the image is dumped as a PE a static tool loads
    (``pe_emu.dump_pe``) and the import slots the stub rebuilt are named (``pe_emu.rebuilt_imports``);
  * the hand-over is followed for up to ``layers`` layers; the deepest dump reached is returned;
  * everything the harness does not model still ends the run by name (an unmodelled API, an unhandled
    exception, a budget), and that is a ``declined`` result, never a guess.

The emulation never happens in the caller's process.  ``unpack()`` starts THIS FILE as a child
(``--worker``) under the operating system's sandbox and talks to it over pipes:

  * macOS: ``sandbox-exec`` with a profile that denies the network, every file write and fork;
  * Linux: ``unshare --net --map-root-user`` (an empty network namespace);
  * inside the child, on every platform: CPU-time, file-size, core and descriptor limits, and a Python
    audit hook that refuses sockets, child processes and opening anything for writing.

Where the OS sandbox cannot be applied (inside another sandbox, an unknown platform) ``unpack()`` raises
:class:`SandboxUnavailable` naming the probe's answer.  It never runs the worker unsandboxed on its own;
a caller that has its own containment passes ``sandbox=`` explicitly.  It is a subprocess, not a Docker
image: nothing is built, pulled or started.

    from solvers.binary import unpack_worker
    outcome = unpack_worker.unpack(data)          # data = the PE bytes (never a path, never executed)
    outcome.status                                # "unpacked" | "not-packed" | "declined"
    outcome.dump, outcome.oep_rva, outcome.report

CLI:  python solvers/binary/unpack_worker.py FILE [--out DUMP] [--layers N] [--timeout S]
      exit 0 unpacked, 1 not packed or declined, 2 the sandbox is unavailable or a usage error.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_INSTRUCTIONS = 2_000_000      # per layer
DEFAULT_MEMORY = 8_000_000            # memory accesses per layer
DEFAULT_WALL = 60.0                   # the harness's own ceiling per layer (seconds)
DEFAULT_LAYERS = 4
DEFAULT_CPU = 300                     # CPU seconds the child may use before the kernel stops it
DEFAULT_TIMEOUT = 600.0               # wall seconds the parent waits before it kills the child
MAX_LAYERS = 16
MAX_HEADER = 4096
MAX_STDERR = 2000
PROBE_TIMEOUT = 10

DARWIN_PROFILE = ('(version 1)(allow default)(deny network*)(deny file-write*)'
                  '(allow file-write-data (literal "/dev/null"))(deny process-fork)')

_PROBE: dict[str, tuple] = {}


class SandboxUnavailable(RuntimeError):
    """The OS sandbox the worker must run under cannot be applied here; the message says why."""


@dataclass(frozen=True)
class UnpackOutcome:
    status: str                       # unpacked | not-packed | declined
    reason: str                       # why not unpacked ("" when unpacked)
    oep_rva: int | None = None        # the recovered entry point of the deepest layer
    dump: bytes = b""                 # the dumped PE of the deepest layer
    report: dict = field(default_factory=dict)


# ============================================================================ the OS sandbox
def _candidate() -> tuple[tuple[str, ...] | None, str]:
    if sys.platform == "darwin":
        exe = shutil.which("sandbox-exec")
        if not exe:
            return None, "sandbox-exec is not on PATH"
        return (exe, "-p", DARWIN_PROFILE), "sandbox-exec (no network, no file write, no fork)"
    if sys.platform.startswith("linux"):
        exe = shutil.which("unshare")
        if not exe:
            return None, "unshare is not on PATH"
        return (exe, "--net", "--map-root-user", "--"), "unshare --net (an empty network namespace)"
    return None, f"no OS sandbox is known for {sys.platform}"


def os_sandbox(refresh: bool = False) -> tuple[tuple[str, ...] | None, str]:
    """(argv prefix, description) when the OS sandbox works here, else (None, why not).  Probed once
    per process by running ``true`` under it (it fails, for example, inside another sandbox)."""
    if refresh or "os" not in _PROBE:
        prefix, what = _candidate()
        if prefix is not None:
            true = shutil.which("true") or "/usr/bin/true"
            try:
                done = subprocess.run([*prefix, true], capture_output=True, timeout=PROBE_TIMEOUT)
            except (OSError, subprocess.TimeoutExpired) as exc:
                prefix, what = None, f"{what} probe failed ({type(exc).__name__}: {exc})"
            else:
                if done.returncode != 0:
                    err = done.stderr.decode("utf-8", "replace").strip().splitlines()
                    prefix, what = None, (f"{what} probe exited {done.returncode}"
                                          + (f": {err[-1]}" if err else ""))
        _PROBE["os"] = (prefix, what)
    return _PROBE["os"]


# ============================================================================ the parent side
def _declined(reason: str, report: dict | None = None) -> UnpackOutcome:
    return UnpackOutcome("declined", reason, None, b"", dict(report or {}, status="declined", reason=reason))


def unpack(data: bytes, *, layers: int = DEFAULT_LAYERS, instruction_cap: int = DEFAULT_INSTRUCTIONS,
           memory_cap: int = DEFAULT_MEMORY, wall_seconds: float = DEFAULT_WALL,
           cpu_seconds: int = DEFAULT_CPU, timeout: float = DEFAULT_TIMEOUT,
           sandbox: tuple[str, ...] | None = None, python: str | None = None) -> UnpackOutcome:
    """Unpack PE ``data`` in a sandboxed child and return what it recovered.

    ``sandbox`` is the argv prefix the child is started under; the default is the OS sandbox, and
    :class:`SandboxUnavailable` is raised when that cannot be applied (no unsandboxed run happens).
    ``timeout`` is the wall time the parent waits; the child bounds its own work by instructions,
    memory accesses and CPU seconds, so a slow machine does not change the outcome, only the wait.
    """
    raw = bytes(data)
    if not isinstance(layers, int) or not 1 <= layers <= MAX_LAYERS:
        raise ValueError(f"layers must be 1..{MAX_LAYERS}")
    if sandbox is None:
        sandbox, why = os_sandbox()
        if sandbox is None:
            raise SandboxUnavailable(f"the unpack worker runs only under the OS sandbox, which is "
                                     f"unavailable here: {why}")
    header = {"size": len(raw), "layers": layers, "instruction_cap": int(instruction_cap),
              "memory_cap": int(memory_cap), "wall_seconds": float(wall_seconds),
              "cpu_seconds": int(cpu_seconds)}
    command = [*sandbox, python or sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--worker"]
    with tempfile.TemporaryDirectory(prefix="ctf-unpack-") as empty:
        try:
            done = subprocess.run(command, input=json.dumps(header).encode() + b"\n" + raw,
                                  capture_output=True, timeout=timeout, cwd=empty,
                                  env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"})
        except subprocess.TimeoutExpired:
            return _declined(f"the worker did not finish within {timeout:g} s and was killed")
        except OSError as exc:
            raise SandboxUnavailable(f"the unpack worker could not be started: {exc}") from exc
    if done.returncode != 0:
        tail = done.stderr.decode("utf-8", "replace").strip()[-MAX_STDERR:].splitlines()
        if done.returncode < 0:
            try:
                name = signal.Signals(-done.returncode).name
            except ValueError:
                name = f"signal {-done.returncode}"
            what = f"the worker was stopped by {name}"
            if name == "SIGXCPU":
                what += f" (its CPU limit of {int(cpu_seconds)} s)"
        else:
            what = f"the worker exited {done.returncode}"
        return _declined(what + (f": {tail[-1]}" if tail else ""))
    line, _, rest = done.stdout.partition(b"\n")
    try:
        report = json.loads(line)
        size = int(report["dump_size"])
        status = str(report["status"])
    except (ValueError, KeyError, TypeError):
        return _declined("the worker's answer is not the report it was asked for")
    if status not in ("unpacked", "not-packed", "declined") or size != len(rest) \
            or (status == "unpacked") != bool(size):
        return _declined("the worker's answer is inconsistent (status, dump size)")
    if status == "unpacked" and hashlib.sha256(rest).hexdigest() != report.get("dump_sha256"):
        return _declined("the worker's dump does not match the hash it reported")
    return UnpackOutcome(status, str(report.get("reason", "")), report.get("oep_rva"), bytes(rest), report)


# ============================================================================ the child side
def unpack_image(data: bytes, *, layers: int, instruction_cap: int, memory_cap: int,
                 wall_seconds: float, backend=None) -> tuple[dict, bytes]:
    """Run the image to where it executes bytes it wrote, up to ``layers`` times.  ``(report, dump)``.

    This is the worker's whole job, as a function of the bytes.  It runs in the child; a test may call
    it in-process with the guarded real backend on a synthetic image.
    """
    from solvers.toolkits import pe_emu as PE

    report = {"status": "declined", "reason": "", "oep_rva": None, "layers": [], "notes": [],
              "dump_size": 0, "dump_sha256": None, "rebuilt_imports": [], "resolved": [],
              "anti_debug": [], "image": None}
    try:
        pe = PE.map_pe(data)
    except PE.PEError as exc:
        report["reason"] = f"not a PE image the mapper takes: {exc}"
        return report, b""
    report["image"] = {"machine": pe.machine, "is_64": pe.is_64, "entry_rva": pe.entry_rva,
                       "load_base": pe.load_base, "file_sha256": pe.file_sha256,
                       "sections": [s.name for s in pe.sections],
                       "imports": [s.display for s in pe.imports]}
    environment = PE.WindowsEnvironment()
    try:
        box = PE.SafeUnicorn(pe, environment=environment, track_image_writes=True,
                             instruction_cap=instruction_cap, memory_cap=memory_cap,
                             wall_seconds=wall_seconds, backend=backend)
        box.run_tls_callbacks()                  # a protector may do its work before the entry point
    except PE.EmulationDenied as exc:
        report["reason"] = str(exc)
        return report, b""
    dump, memory, start = b"", None, None
    for depth in range(layers):
        try:
            result = box.run(start, stop_on_written_exec=True)
        except PE.EmulationDenied as exc:
            if not report["layers"]:
                report["reason"] = str(exc)
            else:
                report["notes"].append(f"after layer {depth}: {exc}")
            break
        if result.reason != "written-exec":
            ending = f"the image ran to its {result.reason} without executing bytes it wrote"
            if not report["layers"]:
                report.update(status="not-packed", reason=ending)
            else:
                report["notes"].append(f"after layer {depth}: {ending}")
            break
        memory = box.image_memory()
        oep = result.address - pe.load_base
        dump = PE.dump_pe(pe, memory, entry_rva=oep)
        report["layers"].append({"oep_rva": oep, "written_bytes": sum(box.image_written),
                                 "instructions": result.instructions,
                                 "dump_sha256": hashlib.sha256(dump).hexdigest()})
        report.update(status="unpacked", reason="", oep_rva=oep)
        box.image_written[:] = bytes(len(box.image_written))      # a later layer is what is written next
        start = result.address
    if memory is not None:
        report["rebuilt_imports"] = [list(row) for row in PE.rebuilt_imports(pe, memory, environment)]
        report["dump_size"] = len(dump)
        report["dump_sha256"] = hashlib.sha256(dump).hexdigest()
    report["resolved"] = [list(row) for row in environment.resolved]
    report["anti_debug"] = [[e.api, e.query, e.answered] for e in environment.anti_debug]
    return report, dump


def apply_limits(cpu_seconds: int) -> dict:
    """Kernel limits on the child: CPU time, no regular-file writes, no core file, few descriptors.
    Returns what was set; a limit the platform refuses is named, not skipped silently.  (Memory is
    bounded by the harness itself: the file, image, stack, heap and snapshot caps of pe_emu.)"""
    import resource

    wanted = (("cpu_seconds", resource.RLIMIT_CPU, int(cpu_seconds)), ("file_size", resource.RLIMIT_FSIZE, 0),
              ("core", resource.RLIMIT_CORE, 0), ("open_files", resource.RLIMIT_NOFILE, 64))
    applied = {}
    for name, which, value in wanted:
        try:
            resource.setrlimit(which, (value, value))
            applied[name] = value
        except (ValueError, OSError) as exc:
            applied[name] = f"not enforced: {exc}"
    return applied


_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
_DENIED_EVENTS = ("socket.", "subprocess.", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
                  "os.forkpty", "pty.spawn", "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.truncate",
                  "os.symlink", "os.link", "os.chmod", "os.chown", "shutil.", "webbrowser.", "urllib.",
                  "http.client.", "ftplib.", "smtplib.")


def install_guard() -> None:
    """The in-process layer: an audit hook that refuses sockets, child processes and file writes.  It
    cannot be removed once installed, and it holds on every platform, whatever the OS layer does."""
    def hook(event: str, args: tuple) -> None:
        if event == "open":
            mode, flags = (args + (None, None, None))[1:3]
            if (isinstance(flags, int) and flags & _WRITE_FLAGS) or \
                    (isinstance(mode, str) and set(mode) & set("wax+")):
                raise PermissionError("unpack worker: opening a file for writing is denied")
        elif event.startswith(_DENIED_EVENTS):
            raise PermissionError(f"unpack worker: {event} is denied")
    sys.addaudithook(hook)


def guard_state() -> dict:
    """What the audit hook answers, asked without doing anything: the audit events a file write, a
    connection and a child process raise, sent with ``sys.audit`` alone (no file is opened, no socket made,
    no process started).  Each value is "denied" or "allowed"."""
    seen = {}
    for name, event, args in (("write", "open", (os.devnull, "w", os.O_WRONLY)),
                              ("connect", "socket.connect", (None, ("127.0.0.1", 9))),
                              ("spawn", "subprocess.Popen", (sys.executable, [sys.executable], None, None))):
        try:
            sys.audit(event, *args)
            seen[name] = "allowed"
        except PermissionError:
            seen[name] = "denied"
    return seen


def _read_exact(stream, size: int) -> bytes:
    chunks, left = [], size
    while left:
        piece = stream.read(left)
        if not piece:
            raise ValueError("the input ended before the announced size")
        chunks.append(piece)
        left -= len(piece)
    return b"".join(chunks)


def _worker() -> int:
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    spec = json.loads(stdin.readline(MAX_HEADER))
    sys.path.insert(0, str(ROOT))
    from solvers.toolkits import pe_emu as PE          # before the limits: importing reads files only
    size = int(spec["size"])
    if not 0 <= size <= PE.MAX_FILE:
        raise ValueError("the announced size is outside the file cap")
    data = _read_exact(stdin, size)
    limits = apply_limits(int(spec["cpu_seconds"]))
    install_guard()
    guard = guard_state()
    if set(guard.values()) != {"denied"}:
        raise RuntimeError(f"the audit hook is not refusing what it must ({guard}): the image is not run")
    report, dump = unpack_image(data, layers=int(spec["layers"]), instruction_cap=int(spec["instruction_cap"]),
                                memory_cap=int(spec["memory_cap"]), wall_seconds=float(spec["wall_seconds"]))
    report["limits"] = limits
    report["guard"] = guard
    stdout.write(json.dumps(report).encode() + b"\n" + dump)
    stdout.flush()
    return 0


def _probe(argv: list[str]) -> int:
    """What the containment refuses, tried from inside it: a file write, a connection to
    127.0.0.1:PORT and a child process.  ``--no-hook`` leaves the audit hook out, to see the OS
    layer alone.  Prints one JSON object."""
    import socket

    port = int(argv[0])
    if "--no-hook" not in argv:
        install_guard()
    seen = {}

    def attempt(name, action):
        try:
            action()
            seen[name] = "allowed"
        except BaseException as exc:                      # a denial of any kind is the answer
            seen[name] = f"denied: {type(exc).__name__}"

    def write():
        with open("probe.txt", "w") as handle:
            handle.write("x")

    def connect():
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass

    def spawn():
        subprocess.run([sys.executable, "-I", "-c", "pass"], check=True, timeout=30)

    attempt("write", write)
    attempt("connect", connect)
    attempt("spawn", spawn)
    print(json.dumps(seen, sort_keys=True))
    return 0


# ============================================================================ CLI
def main(argv: list[str] | None = None) -> int:
    import argparse

    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--worker"]:
        return _worker()
    if argv[:1] == ["--probe"]:
        return _probe(argv[1:])
    parser = argparse.ArgumentParser(prog="unpack_worker.py",
                                     description="unpack a PE by bounded emulation in a sandboxed child")
    parser.add_argument("file", help="the packed PE (read as data; never executed on the host)")
    parser.add_argument("--out", help="write the dumped PE here when one is recovered")
    parser.add_argument("--layers", type=int, default=DEFAULT_LAYERS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    sys.path.insert(0, str(ROOT))
    from solvers.toolkits import pe_emu as PE

    try:
        with open(args.file, "rb") as handle:
            data = handle.read(PE.MAX_FILE + 1)
        if len(data) > PE.MAX_FILE:
            raise ValueError("the file is over the PE file cap")
        outcome = unpack(data, layers=args.layers, timeout=args.timeout)
    except (OSError, ValueError, SandboxUnavailable) as exc:
        print(f"unpack_worker: {exc}", file=sys.stderr)
        return 2
    if outcome.status == "unpacked" and args.out:
        Path(args.out).write_bytes(outcome.dump)
    print(json.dumps(outcome.report, indent=2, sort_keys=True))
    return 0 if outcome.status == "unpacked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
