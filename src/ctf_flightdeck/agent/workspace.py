"""Lane workspaces: where a lane's commands run, on this machine or in a container.

A lane works in its own copy of the challenge handout, never in the handout itself. The
host runtime runs each command with bash in that directory; the docker runtime bind-mounts
the same directory at /work in one container per lane (D9). Either way the files live on
this machine, so flightdeck can snapshot them between turns and show the player what a
lane changed.

Everything in a workspace is untrusted: the handout comes from the challenge and the
lane's commands are steered by it. So flightdeck's own reads and writes there never follow
a symlink (a container can plant /work/x -> /etc/passwd, which on this machine points at
the host's file), never block on a FIFO, and never land outside the root. Commands get an
environment built fresh from an allowlist, so no API key or token is handed to them. In
the host runtime that is not a wall: a command runs as the player and can read whatever
the player's account can, flightdeck's own environment and so the API key included (see
HostWorkspace). A docker lane sees none of that.

One deliberate difference from the M1 contract: the host take-over shell gets the player's
own TERM, not the allowlist's TERM=dumb, so editors and pagers work in it. The lane's own
commands still get TERM=dumb.
"""

from __future__ import annotations

import asyncio
import codecs
import difflib
import errno
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..core.model import FileChange
from ..text import untrusted

PRIVATE = ".flightdeck"
"""flightdeck's own directory in a workspace (home, tmp, logs, tool output). Never copied
from a handout and never snapshotted; the host runtime puts it back before each command if
the lane removed or replaced it (restore_private)."""

CONTAINER_ROOT = "/work"
OUTPUT_CAP = 10 * 1024 * 1024  # bytes of a command's output kept; the rest is dropped with a note
NOT_RUN = 126  # the exit status of a command the host runtime could not start (bash's "cannot execute")
DOCKER_BACKSTOP = 15.0  # seconds past a command's own timeout before the docker exec client is killed
DOCKER_CALL_TIMEOUT = 60.0  # seconds for docker's own housekeeping calls (run, inspect, rm)

SNAPSHOT_FILES = 5000
SNAPSHOT_DEPTH = 64
HASH_LIMIT = 1024 * 1024  # files up to this size get a sha1
TEXT_LIMIT = 64 * 1024  # text files up to this size are kept for diffs
SNIFF = 8192

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK  # NONBLOCK: opening a FIFO must not hang


@dataclass(frozen=True)
class RunResult:
    """What a command did. output holds stdout and stderr together, in the order written."""

    exit_code: int | None  # None when it timed out or was killed
    output: bytes
    timed_out: bool = False


@dataclass(frozen=True)
class ShellSpec:
    """How to open the player's take-over shell for a lane."""

    argv: list[str]
    cwd: Path | None
    env: dict[str, str] | None  # None: inherit the player's environment


class WorkspaceError(Exception):
    """A workspace cannot do what was asked. The message names the reason: docker missing,
    an image not present, a container name in use, a handout that is not there..."""


class Workspace(Protocol):
    root: Path  # the lane's working directory on this machine

    async def prepare(self) -> None: ...

    async def run(self, command: str, *, timeout: float, stdin: bytes | None = None) -> RunResult: ...

    async def close(self) -> None: ...

    def interactive_shell(self) -> ShellSpec: ...


# ---------------------------------------------------------------- files, never through a symlink


def open_dir(root: Path, parts: Sequence[str], *, create: bool = False) -> int:
    """A descriptor for root/parts where every part is a real directory, never a symlink.
    create=True makes the missing ones. The caller closes it."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in parts:
            if create:
                try:
                    os.mkdir(name, dir_fd=fd)
                except FileExistsError:
                    pass  # opened below, which refuses it if it is not a directory
            inner = os.open(name, _DIR, dir_fd=fd)
            os.close(fd)
            fd = inner
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_inside(root: Path, parts: Sequence[str]) -> int:
    """A read descriptor for the regular file root/parts, following no symlink on the way.
    OSError when it is missing, a directory, a symlink or not a regular file."""
    if not parts:
        raise IsADirectoryError(errno.EISDIR, "is a directory")
    *dirs, name = parts
    dir_fd = open_dir(root, dirs)
    try:
        fd = os.open(name, _FILE, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        os.close(fd)
        if stat.S_ISDIR(mode):
            raise IsADirectoryError(errno.EISDIR, "is a directory")
        raise OSError(errno.EINVAL, "not a regular file")
    os.set_blocking(fd, True)
    return fd


def write_inside(root: Path, relative: str, data: bytes) -> None:
    """Write root/relative (a path of flightdeck's own, like .flightdeck/out/x.txt) as a new
    file, making missing directories and following no symlink. An existing file of that name
    is replaced, never written through: the lane may have planted a hard link or a FIFO."""
    parts = relative.split("/")
    if relative.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"not a plain relative path: {relative!r}")
    *dirs, name = parts
    dir_fd = open_dir(root, dirs, create=True)
    try:
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    with open(fd, "wb") as out:
        out.write(data)


def restore_private(root: Path) -> None:
    """Make root/.flightdeck and its home/ and tmp/ real directories again, for a lane that
    deleted them or put something else there (by extracting an archive, say). .flightdeck is
    flightdeck's own name, so a file, a symlink or a FIFO there is unlinked, never followed,
    and the directory made anew. OSError when that cannot be done. WorkspaceError when root
    itself cannot be opened (it is gone, say): that is a broken workspace, not a broken
    .flightdeck."""
    try:
        top = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise WorkspaceError(f"workspace {root} cannot be opened: {exc.strerror or exc}") from None
    try:
        _own_dir(top, PRIVATE)
        private = os.open(PRIVATE, _DIR, dir_fd=top)
    finally:
        os.close(top)
    try:
        for sub in ("home", "tmp"):
            _own_dir(private, sub)
    finally:
        os.close(private)


def _own_dir(dir_fd: int, name: str) -> None:
    """dir_fd/name as a directory: made if missing, and anything else there unlinked first."""
    try:
        info = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        info = None
    if info is not None and stat.S_ISDIR(info.st_mode):
        return
    if info is not None:
        os.unlink(name, dir_fd=dir_fd)  # a symlink itself goes, never what it points at
    os.mkdir(name, dir_fd=dir_fd)


def _quoted(text: str) -> str:
    """A name from a handout or a lane, escaped so it cannot fake a line of a log."""
    return json.dumps(text)


# ---------------------------------------------------------------- the handout copy


def copy_handout(handout: Path, root: Path) -> None:
    """Copy the handout's files and directories (challenge.json too) into root, which must be
    new or empty, and make root/.flightdeck with home/ and tmp/.

    Symlinks are skipped (they could point anywhere on this machine), so is anything that is
    not a regular file or a directory, so are __pycache__ folders (pip byte-compiles a packaged
    handout's .py files at install), and so is a handout's own .flightdeck (a planted
    .flightdeck/home/.bashrc would run in the player's take-over shell). Each skip is written
    to root/.flightdeck/prepare.log. Nothing is ever written to the handout.
    """
    source = Path(handout).resolve()
    if not source.is_dir():
        raise WorkspaceError(f"handout {handout} is not a directory")
    target = Path(root).resolve()
    if target.is_relative_to(source) or source.is_relative_to(target):
        raise WorkspaceError(f"workspace {root} and handout {handout} overlap; a lane must work in a copy")
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise WorkspaceError(f"workspace {root} already exists and is not an empty directory")
    try:
        root.mkdir(parents=True, exist_ok=True)
        notes: list[tuple[str, str]] = []
        files, size = _copy_tree(source, root, notes)
        for sub in ("home", "tmp"):
            (root / PRIVATE / sub).mkdir(parents=True, exist_ok=True)
        lines = [f"copied {files} files ({size} bytes) from the handout"]
        lines += [note for _, note in sorted(notes)]
        (root / PRIVATE / "prepare.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        raise WorkspaceError(f"could not copy handout {handout} into {root}: {exc}") from None


def add_to_log(root: Path, line: str) -> None:
    """Add a line to root/.flightdeck/prepare.log, never through a symlink. For prepare()
    only: no command of the lane's has run yet, so nothing else is writing there."""
    log = f"{PRIVATE}/prepare.log"
    fd = open_inside(root, log.split("/"))
    with open(fd, "rb") as f:
        old = f.read()
    write_inside(root, log, old + line.encode("utf-8") + b"\n")


def _copy_tree(source: Path, target: Path, notes: list[tuple[str, str]]) -> tuple[int, int]:
    """(files, bytes) copied. Iterative, so a deeply nested handout cannot hit the recursion limit."""
    files = size = 0
    pending = [(source, target, "")]
    while pending:
        src_dir, dst_dir, prefix = pending.pop()
        with os.scandir(src_dir) as listing:
            entries = sorted(listing, key=lambda e: e.name)
        for entry in entries:
            rel = prefix + entry.name
            if entry.is_symlink():
                try:
                    to = _quoted(os.readlink(entry.path))
                except OSError:
                    to = "an unreadable target"
                notes.append((rel, f"skipped {_quoted(rel)}: a symlink (to {to}); symlinks are never copied"))
            elif not prefix and entry.name == PRIVATE:
                notes.append((rel, f"skipped {_quoted(rel)}: the name is reserved for flightdeck's own files"))
            elif entry.name == "__pycache__" and entry.is_dir(follow_symlinks=False):
                # bytecode Python wrote for the handout's .py files (pip does at install), not challenge content
                notes.append((rel, f"skipped {_quoted(rel)}: Python's bytecode cache, not part of the handout"))
            elif entry.is_dir(follow_symlinks=False):
                (dst_dir / entry.name).mkdir()
                pending.append((Path(entry.path), dst_dir / entry.name, rel + "/"))
            elif entry.is_file(follow_symlinks=False):
                size += _copy_file(Path(entry.path), dst_dir / entry.name)
                files += 1
            else:
                notes.append((rel, f"skipped {_quoted(rel)}: not a regular file or a directory"))
    return files, size


def _copy_file(source: Path, target: Path) -> int:
    """Copy one file: content, permission bits (owner-writable, never setuid) and times.
    Times are kept because they can be part of a forensics challenge."""
    fd = os.open(source, _FILE)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, f"{source} is not a regular file")
        with open(fd, "rb", closefd=False) as src, open(target, "xb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
    finally:
        os.close(fd)
    os.chmod(target, (info.st_mode & 0o777) | stat.S_IWUSR)
    os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))
    return info.st_size


# ---------------------------------------------------------------- running a command


class _Capture(asyncio.Protocol):
    """Collects what a pipe delivers, up to a cap, and counts what it drops."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.data = bytearray()
        self.dropped = 0
        self.closed: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    def data_received(self, data: bytes) -> None:
        room = max(0, self.cap - len(self.data))
        self.data += data[:room]
        self.dropped += max(0, len(data) - room)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.closed.done():
            self.closed.set_result(None)

    def output(self) -> bytes:
        if not self.dropped:
            return bytes(self.data)
        note = f"\n[output over {self.cap // (1024 * 1024)} MB: {self.dropped} more bytes dropped]\n"
        return bytes(self.data) + note.encode()


async def _execute(
    argv: Sequence[str],
    *,
    cwd: Path | None,
    env: dict[str, str] | None,
    stdin: bytes | None,
    timeout: float,
    started: Callable[[asyncio.subprocess.Process], None],
) -> tuple[int | None, bytes, bool]:
    """Run argv in a new session with stdout and stderr on one pipe, for at most `timeout`
    seconds: (return code, output, timed out).

    It waits for the end of the output, not just the process, the way `docker exec` does: a
    background child still writing to the pipe keeps the command going until the timeout,
    while one whose output is redirected keeps running after it. On timeout, or if the
    caller is cancelled, the whole process group is killed.
    """
    loop = asyncio.get_running_loop()
    capture = _Capture(OUTPUT_CAP)
    read_fd, write_fd = os.pipe()
    pipe = open(read_fd, "rb", buffering=0)
    proc: asyncio.subprocess.Process | None = None
    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                env=env,
                stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                stdout=write_fd,
                stderr=write_fd,
                start_new_session=True,
            )
        finally:
            os.close(write_fd)
        transport, _ = await loop.connect_read_pipe(lambda: capture, pipe)
    except BaseException:
        pipe.close()
        if proc is not None:
            _kill_group(proc.pid)
        raise
    started(proc)
    feeder = asyncio.ensure_future(_feed(proc.stdin, stdin)) if proc.stdin is not None and stdin is not None else None
    timed_out = False
    try:
        try:
            await asyncio.wait_for(_finished(capture, proc), timeout)
        except TimeoutError:
            timed_out = True
            _kill_group(proc.pid)
            await proc.wait()
            # Collect what is still in the pipe; a process outside the group may hold it open.
            await asyncio.wait([capture.closed], timeout=1.0)
    finally:
        if proc.returncode is None:  # cancelled: never leave the command running
            _kill_group(proc.pid)
        transport.close()
        if feeder is not None:
            feeder.cancel()
    return proc.returncode, capture.output(), timed_out


async def _finished(capture: _Capture, proc: asyncio.subprocess.Process) -> None:
    await asyncio.shield(capture.closed)  # a timeout cancels this task, never the capture
    await proc.wait()


async def _feed(writer: asyncio.StreamWriter, data: bytes) -> None:
    try:
        writer.write(data)
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass  # the command exited without reading all of its input, which is its business
    finally:
        writer.close()


def _kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass  # already gone (or the number now belongs to someone else's group)


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def _exit_status(code: int) -> int:
    """A shell-style status: a process killed by signal n is 128 + n (a segfault is 139)."""
    return code if code >= 0 else 128 - code


def _check_call(command: str, timeout: float) -> None:
    if "\0" in command:
        raise ValueError("a command cannot contain a NUL character")
    if not (isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout > 0):
        raise ValueError(f"timeout must be a positive number of seconds, got {timeout!r}")


# ---------------------------------------------------------------- host runtime

_ALLOWED_ENV = ("PATH", "LANG", "LC_ALL")


class HostWorkspace:
    """Runs a lane's commands with bash on this machine, in root (containerized = false, D9).

    Meant for players on a disposable VM. A command runs as the player's own account and can
    do whatever that account can: read and change the player's files, and read the
    environment of the player's other processes (`ps eww`, /proc/<pid>/environ), flightdeck's
    own among them, so the API key flightdeck was started with too. The allowlist in _env
    only keeps keys and tokens out of the command's own environment; it is not a boundary,
    and nothing here can make it one. The docker runtime is what keeps a lane from all this:
    a container sees neither this machine's processes nor its files outside the workspace.

    Each command runs in its own process group. A timeout kills the group; close() kills
    every group the lane left running, such as a server it started in the background.
    """

    def __init__(self, root: Path, handout: Path, *, shell: str = "bash") -> None:
        self.root = Path(root).absolute()
        self.handout = Path(handout)
        self.shell = shell
        self.workdir = str(self.root)  # root as the lane's commands see it
        self._bash: str | None = None
        self._groups: set[int] = set()  # process groups started here that may still be running
        self._closed = False

    async def prepare(self) -> None:
        if self._closed:
            raise WorkspaceError("workspace is closed")
        bash = shutil.which("bash")
        if bash is None:
            raise WorkspaceError("bash not found on PATH; the host runtime runs every command with bash")
        await asyncio.to_thread(copy_handout, self.handout, self.root)
        self._bash = bash

    async def run(self, command: str, *, timeout: float, stdin: bytes | None = None) -> RunResult:
        """Run one command. Whatever the lane did to its .flightdeck, this never raises for
        it: the directories are put back, and if even that fails the command is not run and
        the result says why (exit status NOT_RUN)."""
        bash = self._ready()
        _check_call(command, timeout)
        try:
            restore_private(self.root)
        except OSError as exc:
            note = (
                f"flightdeck: cannot set up {PRIVATE}/home and {PRIVATE}/tmp: {exc}; the command was not run. "
                f"{PRIVATE} is flightdeck's own directory: the player can take over the lane to repair it.\n"
            )
            return RunResult(NOT_RUN, note.encode())
        env = self._env()
        self._prune()
        try:
            code, output, timed_out = await _execute(
                [bash, "-c", command], cwd=self.root, env=env, stdin=stdin, timeout=timeout, started=self._started
            )
        except OSError as exc:
            raise WorkspaceError(f"cannot run a command in {self.root}: {exc}") from None
        self._prune()
        if timed_out:
            return RunResult(None, output, timed_out=True)
        if code is None or (code < 0 and self._closed):
            return RunResult(None, output)
        return RunResult(_exit_status(code), output)

    async def close(self) -> None:
        self._closed = True
        self._prune()
        for pgid in sorted(self._groups):
            _kill_group(pgid)
        self._groups.clear()

    def interactive_shell(self) -> ShellSpec:
        self._ready()
        try:
            restore_private(self.root)
        except OSError:
            pass  # it opens anyway: taking over is how the player repairs what the lane broke
        env = self._env()
        env["TERM"] = os.environ.get("TERM", "dumb")  # the player's own terminal, so editors and pagers work
        env["HISTFILE"] = str(self.root / PRIVATE / "takeover_history")
        return ShellSpec([self.shell, "-i"], self.root, env)

    def _ready(self) -> str:
        if self._closed:
            raise WorkspaceError("workspace is closed")
        if self._bash is None:
            raise WorkspaceError("workspace not prepared: call prepare() first")
        return self._bash

    def _env(self) -> dict[str, str]:
        """The allowlist, built fresh for each command: nothing else of this machine's
        environment (no API keys, no tokens). HOME and TMPDIR are the lane's own, which
        restore_private() makes sure are there."""
        env = {name: os.environ[name] for name in _ALLOWED_ENV if name in os.environ}
        env["TERM"] = "dumb"
        env["HOME"] = str(self.root / PRIVATE / "home")
        env["TMPDIR"] = str(self.root / PRIVATE / "tmp")
        return env

    def _started(self, proc: asyncio.subprocess.Process) -> None:
        self._groups.add(proc.pid)  # start_new_session: the process group id is its pid

    def _prune(self) -> None:
        """Forget groups with no process left, so close() never signals a number the system
        has since given to someone else's group."""
        self._groups = {pgid for pgid in self._groups if _group_alive(pgid)}


# ---------------------------------------------------------------- docker runtime

_DOCKER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]+")
_NETWORK = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*")
_MEMORY = re.compile(r"\d+(\.\d+)?[bkmgBKMG]?")
_CPUS = re.compile(r"\d+(\.\d+)?")
_SIGKILL_STATUS = 128 + signal.SIGKILL


def docker_unavailable() -> str | None:
    """Why docker cannot run lanes here ("docker not found on PATH", "docker daemon not
    running ..."), or None when it can."""
    if shutil.which("docker") is None:
        return "docker not found on PATH"
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return "docker daemon not answering (docker version took over 20 s)"
    except OSError as exc:
        return f"docker cannot be run: {exc.strerror or exc}"
    if proc.returncode != 0 or not proc.stdout.strip():
        detail = _first_line(proc.stderr.decode("utf-8", "replace"))
        return f"docker daemon not running ({detail})" if detail else "docker daemon not running"
    return None


def _first_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return untrusted(lines[0], one_line=True)[:300] if lines else ""


async def _docker(*args: str, timeout: float = DOCKER_CALL_TIMEOUT) -> tuple[int, str]:
    """Run one docker housekeeping command: (exit code, stdout and stderr together)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        raise WorkspaceError("docker not found on PATH") from None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise WorkspaceError(f"docker {args[0]} did not finish within {timeout:.0f} s") from None
    return proc.returncode if proc.returncode is not None else -1, out.decode("utf-8", "replace")


def _seconds(timeout: float) -> str:
    """A duration for GNU timeout, rounded up to the millisecond (never "0", which means no limit)."""
    ms = max(1, math.ceil(timeout * 1000))
    return f"{ms // 1000}.{ms % 1000:03d}s"


class DockerWorkspace:
    """Runs a lane's commands in a container of its own (containerized = true, D9), with root
    bind-mounted at /work.

    The container comes from a local image only (--pull never: flightdeck never pulls), with
    memory, CPU and process limits, and an init process (--init) that reaps orphans, so
    commands killed on timeout do not pile up as zombies against the pids limit. Each command
    is `docker exec ... timeout --signal=KILL <t>s bash -c COMMAND`, with a host-side
    backstop that kills the docker client if docker itself hangs. close() removes the
    container. The docker client inherits flightdeck's environment, but docker passes none
    of it into the container.

    prepare() refuses an image without bash or timeout, which every command needs. An image
    without python3 (debian:bookworm-slim, say) is fine for the shell, so it only sets
    python_missing, for the python tool to answer, and says so in prepare.log.
    """

    def __init__(
        self,
        root: Path,
        handout: Path,
        *,
        image: str,
        name: str,
        network: str = "bridge",
        memory: str = "2g",
        cpus: str = "2",
        pids_limit: int = 512,
    ) -> None:
        _require(bool(_DOCKER_NAME.fullmatch(name)), f"container name {name!r} is not valid (letters, digits, _ . -; at least 2 characters)")
        _require(bool(image) and not image.startswith("-") and not any(c.isspace() for c in image), f"image {image!r} is not a valid image name")
        _require(bool(_NETWORK.fullmatch(network)), f"network {network!r} is not a valid network name")
        _require(bool(_MEMORY.fullmatch(memory)), f"memory {memory!r} is not a size like 2g or 512m")
        _require(bool(_CPUS.fullmatch(cpus)), f"cpus {cpus!r} is not a number like 2 or 1.5")
        _require(isinstance(pids_limit, int) and not isinstance(pids_limit, bool) and pids_limit > 0, f"pids_limit must be a positive integer, got {pids_limit!r}")
        self.root = Path(root).absolute()
        _require(":" not in str(self.root.resolve()), f"workspace path {self.root} contains ':', which docker -v cannot mount")
        self.handout = Path(handout)
        self.image = image
        self.name = name
        self.network = network
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.workdir = CONTAINER_ROOT  # root as the lane's commands see it
        self.python_missing: str | None = None  # set by prepare() when the image has no python3: why the python tool cannot run
        self._started = False  # our container exists, or may: close() must remove it
        self._starting: asyncio.Future[tuple[int, str]] | None = None  # `docker run`, which a cancel must not cut off
        self._ready = False
        self._closed = False
        self._clients: set[asyncio.subprocess.Process] = set()  # docker exec clients still running

    async def prepare(self) -> None:
        if self._closed:
            raise WorkspaceError("workspace is closed")
        reason = await asyncio.to_thread(docker_unavailable)
        if reason:
            raise WorkspaceError(reason)
        code, _ = await _docker("image", "inspect", "--format", "{{.Id}}", self.image)
        if code != 0:
            raise WorkspaceError(self._image_missing())
        code, _ = await _docker("container", "inspect", "--format", "{{.Id}}", self.name)
        if code == 0:
            raise WorkspaceError(self._name_in_use())
        await asyncio.to_thread(copy_handout, self.handout, self.root)
        # From here the container may exist (the name was free a moment ago, so whatever has
        # it is ours). `docker run` carries on in the docker CLI even if this lane is
        # cancelled, so it runs as a task of its own, which close() waits for before it
        # removes the container.
        self._started = True
        self._starting = asyncio.ensure_future(_docker(*self.run_args()))
        code, out = await asyncio.shield(self._starting)
        if code != 0:
            if "already in use" in out:
                self._started = False  # someone else's container: never remove it
                raise WorkspaceError(self._name_in_use())
            await self.close()
            if "No such image" in out:
                raise WorkspaceError(self._image_missing())
            raise WorkspaceError(f"docker run failed for image {self.image}: {_first_line(out)}")
        code, _ = await _docker("exec", self.name, "bash", "-c", "command -v timeout")
        if code != 0:
            await self.close()
            raise WorkspaceError(f"image {self.image} has no bash or no timeout (coreutils); lane commands need both")
        code, _ = await _docker("exec", self.name, "bash", "-c", "command -v python3")
        if code != 0:  # remembered: the python tool answers this instead of failing with exit 127
            self.python_missing = (
                f"python3 is not installed in this lane's container (image {self.image}), so the python tool "
                "cannot run here; use shell instead. The lane image has python3: the player can build it "
                "with `flightdeck image build`."
            )
            add_to_log(self.root, f"python3 is not in image {self.image}: the python tool will not work in this lane "
                                  "(`flightdeck image build` builds the lane image, which has it)")
        self._ready = True

    async def run(self, command: str, *, timeout: float, stdin: bytes | None = None) -> RunResult:
        if self._closed:
            raise WorkspaceError("workspace is closed")
        if not self._ready:
            raise WorkspaceError("workspace not prepared: call prepare() first")
        _check_call(command, timeout)
        argv = ["docker", "exec", "-i", "-w", CONTAINER_ROOT, self.name, "timeout", "--signal=KILL", _seconds(timeout), "bash", "-c", command]
        begun = time.monotonic()
        try:
            code, output, stuck = await _execute(
                argv, cwd=None, env=None, stdin=stdin, timeout=timeout + DOCKER_BACKSTOP, started=self._clients.add
            )
        except FileNotFoundError:
            raise WorkspaceError("docker not found on PATH") from None
        finally:
            self._clients = {c for c in self._clients if c.returncode is None}
        elapsed = time.monotonic() - begun
        if stuck:
            return RunResult(None, output, timed_out=True)
        if code is None or self._closed:
            return RunResult(None, output)
        if code == _SIGKILL_STATUS and elapsed >= timeout:
            return RunResult(None, output, timed_out=True)  # timeout --signal=KILL takes itself down too
        if code != 0 and output.startswith((b"Error response from daemon", b"OCI runtime")) and not await self._running():
            raise WorkspaceError(f"container {self.name} is not running any more (stopped or removed outside flightdeck)")
        return RunResult(_exit_status(code), output)

    async def close(self) -> None:
        self._closed = True
        for client in list(self._clients):
            if client.returncode is None:
                _kill_group(client.pid)
        if self._starting is not None:
            try:
                code, out = await asyncio.shield(self._starting)  # a `docker run` still going: let it end first
            except Exception:  # it failed or timed out: whatever it left is removed below
                code, out = -1, ""
            if code != 0 and "already in use" in out:
                self._started = False  # someone else's container: never remove it
        if not self._started:
            return
        code, out = await _docker("rm", "-f", self.name)
        if code != 0 and "No such container" not in out:
            raise WorkspaceError(f"docker rm -f {self.name} failed: {_first_line(out)}")
        self._started = False

    def interactive_shell(self) -> ShellSpec:
        if self._closed or not self._ready:
            raise WorkspaceError("workspace is closed" if self._closed else "workspace not prepared: call prepare() first")
        history = f"HISTFILE={CONTAINER_ROOT}/{PRIVATE}/takeover_history"  # what the player ran, for the lane to hear
        return ShellSpec(["docker", "exec", "-it", "-e", history, "-w", CONTAINER_ROOT, self.name, "bash", "-i"], None, None)

    def run_args(self) -> list[str]:
        """The `docker run` arguments that start this lane's container."""
        return [
            "run", "-d", "--rm", "--init", "--pull", "never",
            "--name", self.name,
            "--network", self.network,
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            "-v", f"{self.root.resolve()}:{CONTAINER_ROOT}",
            "-w", CONTAINER_ROOT,
            "--entrypoint", "sleep",
            self.image, "infinity",
        ]

    async def _running(self) -> bool:
        code, out = await _docker("container", "inspect", "--format", "{{.State.Running}}", self.name)
        return code == 0 and out.strip() == "true"

    def _image_missing(self) -> str:
        return f"image {self.image} is not present locally; flightdeck never pulls images (pull it yourself if you want it)"

    def _name_in_use(self) -> str:
        return f"container name {self.name} is already in use (docker rm -f {self.name} if it is a leftover)"


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


# ---------------------------------------------------------------- snapshots and diffs


@dataclass(frozen=True)
class Snapshot:
    """What a workspace held at one moment: enough to tell what changed, and to diff small text files."""

    files: dict[str, tuple[int, int, str]]  # relative posix path -> (size, mtime_ns, sha1 hex; "" if over 1 MB)
    texts: dict[str, str]  # relative path -> content, for text files up to 64 KB
    truncated: bool = False  # stopped after 5000 files


def take_snapshot(root: Path) -> Snapshot:
    """Snapshot root, skipping root/.flightdeck and every symlink.

    The walk goes through directory descriptors opened with O_NOFOLLOW, so a lane that swaps
    a directory for a symlink mid-walk cannot make flightdeck read outside root, and files
    are opened non-blocking, so a FIFO cannot hang it. An unreadable file is still listed
    (size and time, no hash); an unreadable directory lists as empty; directories nested more
    than 64 deep are not walked.
    """
    try:
        top = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise WorkspaceError(f"cannot snapshot workspace {root}: {exc.strerror or exc}") from None
    scan = _Scan()
    try:
        scan.walk(top, "", 0)
    finally:
        os.close(top)
    return Snapshot(scan.files, scan.texts, scan.truncated)


class _Scan:
    def __init__(self) -> None:
        self.files: dict[str, tuple[int, int, str]] = {}
        self.texts: dict[str, str] = {}
        self.truncated = False

    def walk(self, dir_fd: int, prefix: str, depth: int) -> None:
        """Depth first, names sorted: the order of the (component, ...) tuples of the paths."""
        try:
            with os.scandir(dir_fd) as listing:
                entries = sorted(listing, key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if self.truncated:
                return
            if not prefix and entry.name == PRIVATE:
                continue
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 >= SNAPSHOT_DEPTH:
                        continue  # absurdly deep: left out of every snapshot alike
                    sub = os.open(entry.name, _DIR, dir_fd=dir_fd)
                    try:
                        self.walk(sub, prefix + entry.name + "/", depth + 1)
                    finally:
                        os.close(sub)
                elif entry.is_file(follow_symlinks=False):
                    if len(self.files) >= SNAPSHOT_FILES:
                        self.truncated = True
                        return
                    self._file(dir_fd, entry, prefix + entry.name)
            except OSError:
                continue  # it vanished or changed type while we looked

    def _file(self, dir_fd: int, entry: os.DirEntry[str], rel: str) -> None:
        try:
            fd = os.open(entry.name, _FILE, dir_fd=dir_fd)
        except OSError:
            info = entry.stat(follow_symlinks=False)
            self.files[rel] = (info.st_size, info.st_mtime_ns, "")
            return
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return
            data = _read_upto(fd, HASH_LIMIT + 1) if info.st_size <= HASH_LIMIT else None
        finally:
            os.close(fd)
        if data is None or len(data) > HASH_LIMIT:
            self.files[rel] = (info.st_size, info.st_mtime_ns, "")
            return
        self.files[rel] = (len(data), info.st_mtime_ns, hashlib.sha1(data, usedforsecurity=False).hexdigest())
        if len(data) <= TEXT_LIMIT and (text := _text(data)) is not None:
            self.texts[rel] = text


def _read_upto(fd: int, limit: int) -> bytes:
    chunks, size = [], 0
    while size < limit:
        chunk = os.read(fd, min(1024 * 1024, limit - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def _text(data: bytes) -> str | None:
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def changed_files(before: Snapshot, after: Snapshot, root: Path) -> list[FileChange]:
    """Every file added, modified or deleted between two snapshots of root, sorted by path.

    A text file (both sides at most 64 KB of UTF-8) gets a unified diff; anything else gets
    one line such as "binary file, 1234 bytes". root is where `after` was taken: a file too
    big to keep in a snapshot is looked at there, to tell text from binary. A path missing
    from a truncated snapshot but past its last file is not reported, since that snapshot
    stopped before reaching it.
    """
    before_end = _last_key(before) if before.truncated else None
    after_end = _last_key(after) if after.truncated else None
    changes = []
    for path in sorted(before.files.keys() | after.files.keys()):
        old, new = before.files.get(path), after.files.get(path)
        if old is None:
            if before_end is not None and _key(path) > before_end:
                continue
            status = "added"
        elif new is None:
            if after_end is not None and _key(path) > after_end:
                continue
            status = "deleted"
        elif _same(old, new):
            continue
        else:
            status = "modified"
        changes.append(FileChange(path, _describe(path, status, before, after, root), status))
    return changes


def _key(path: str) -> tuple[str, ...]:
    return tuple(path.split("/"))


def _last_key(snapshot: Snapshot) -> tuple[str, ...]:
    return max((_key(p) for p in snapshot.files), default=())


def _same(old: tuple[int, int, str], new: tuple[int, int, str]) -> bool:
    if old[0] != new[0]:
        return False
    if old[2] and new[2]:
        return old[2] == new[2]
    return old[1] == new[1]  # no hash on one side (over 1 MB): trust the time


def _describe(path: str, status: str, before: Snapshot, after: Snapshot, root: Path) -> str:
    old_text = "" if status == "added" else before.texts.get(path)
    new_text = "" if status == "deleted" else after.texts.get(path)
    if old_text is not None and new_text is not None:
        return _unified(path, status, old_text, new_text)
    old, new = before.files.get(path), after.files.get(path)
    if old is None or new is None or old[0] == new[0]:
        sizes = f"{(new or old or (0,))[0]} bytes"
    else:
        sizes = f"{old[0]} -> {new[0]} bytes"
    return f"{_kind(path, old, new, before, after, root)}, {sizes}"


def _kind(path: str, old: tuple[int, int, str] | None, new: tuple[int, int, str] | None, before: Snapshot, after: Snapshot, root: Path) -> str:
    """Why there is no diff: a small file that is not UTF-8 text is binary; a big one is looked at."""
    for side, snapshot in ((old, before), (new, after)):
        if side is not None and side[0] <= TEXT_LIMIT and path not in snapshot.texts:
            return "binary file"
    if new is not None and new[0] > TEXT_LIMIT:
        return _peek(root, path) or "file over 64 KB"
    return "file over 64 KB"


def _peek(root: Path, path: str) -> str | None:
    try:
        fd = open_inside(root, path.split("/"))
    except OSError:
        return None
    try:
        data = os.read(fd, SNIFF)
    finally:
        os.close(fd)
    if b"\0" in data:
        return "binary file"
    try:
        codecs.getincrementaldecoder("utf-8")().decode(data)  # a character cut at the end is fine
    except UnicodeDecodeError:
        return "binary file"
    return "text file over 64 KB"


_NO_NEWLINE = "\\ No newline at end of file\n"
_NEEDS_QUOTES = re.compile(r'[\x00-\x1f\x7f"\\]')


def _unified(path: str, status: str, old: str, new: str) -> str:
    a = "/dev/null" if status == "added" else _label("a/" + path)
    b = "/dev/null" if status == "deleted" else _label("b/" + path)
    lines = list(difflib.unified_diff(_diff_lines(old), _diff_lines(new), a, b))
    return "".join(lines or [f"--- {a}\n", f"+++ {b}\n"]).rstrip("\n")


def _label(name: str) -> str:
    """A diff header name, quoted like git does when it holds a newline or a quote, so a file
    name cannot fake a header or a hunk line."""
    return json.dumps(name, ensure_ascii=False) if _NEEDS_QUOTES.search(name) else name


def _diff_lines(text: str) -> list[str]:
    """Lines split on newlines only, with git's marker after a last line that has none."""
    lines = text.split("\n")
    out = [line + "\n" for line in lines[:-1]]
    if lines[-1]:
        out.append(lines[-1] + "\n" + _NO_NEWLINE)
    return out
