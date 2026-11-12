"""L1 engines in Docker (D17): when lanes run in Docker, the player's L1 solvers do too.

Each engine run gets a container of its own, from the lane image:

- the engine's copy of the handout (agent.workspace.copy_handout, as on the host) is
  bind-mounted at /work, its working directory;
- the pack, and what a python engine loads of flightdeck (the package's __init__.py and its
  l1 folder: the boot script and SolverResult), are mounted read-only at the paths they have
  on this machine, so the engine's command names the same files in the container;
- its network is "none", unless the caller says the engine may be online: the event lets
  lanes reach the challenge's live instance at once (instance policy auto) and the
  challenge has one. Then it is the fenced network the lane's engines share
  (agent/l1stage.py makes it: agent/egress.py), which reaches that instance and nothing
  else, as the lane's own container's does: never Docker's bridge network;
- the programs the command needs (python3 for a python entry, a cli entry's program, the
  manifest's needs_tools, and bash, which starts the engine) are looked up on the image's
  PATH (programs()), never on this machine's.

What the engine prints is still kept within bounds by flightdeck's capture (l1/_capture.py),
which runs here, with flightdeck's own python, and starts `docker exec` (run_argv): the docker
client hands back the engine's stdout and stderr apart, and its exit status. So a hostile
handout that takes over an engine's parser is in a container with no network, not on this
machine; and an image needs no python3 unless the engine is a python engine.

The container is removed when the run ends, however it ends. Before that, unless the copy
is kept, the copy's contents are removed from inside the container, as the container's
root (wipe()): where docker runs containers as this machine's root, what an engine made in
/work is root's here, and the player could not remove it.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path

# flightdeck's own docker helpers (the lane workspace's): one way of calling docker
from ..agent.workspace import (
    CONTAINER_ROOT,
    DockerWorkspace,
    RunResult,
    ShellSpec,
    WorkspaceError,
    _docker,
    _execute,
    _exit_status,
    _first_line,
    absolute_path,
)

PACKAGE = Path(__file__).resolve().parent.parent  # flightdeck's package folder: _boot.py loads it for an engine
MAX_NAME = 128  # characters of a container name; a longer one is cut and a hash keeps it apart
_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]")

# Run in the container as `bash -c _LOOKUP flightdeck-l1 NAME...`: prints, each ended by a NUL,
# the image's PATH with only its absolute directories (a relative one would find programs in
# /work, the challenge's copy), then where each NAME is on that PATH ("" when it is not).
# `type -P` finds only programs, never a shell builtin, which `exec` could not run.
_LOOKUP = r"""exec 2>/dev/null
set -f
IFS=:
p=
for d in $PATH; do case $d in /*) p=${p:+$p:}$d;; esac; done
unset IFS
PATH=$p
printf '%s\0' "$PATH"
for t; do printf '%s\0' "$(type -P -- "$t")"; done
"""

# Run in the container as `bash -c _WIPE flightdeck-l1 /work`: every folder under it gets its
# owner's read, write and search back (chmod -R never follows a symlink), then everything
# under it goes, depth first (find never follows a symlink either).
_WIPE = r"""chmod -R u+rwx -- "$1" 2>/dev/null
find "$1" -mindepth 1 -delete
"""


def engine_mounts(pack: Path) -> list[tuple[Path, str]]:
    """An engine container's read-only mounts, each at the path it has on this machine: the
    pack (the path its manifests were read from), and what a python engine loads of
    flightdeck (the package's __init__.py and its l1 folder)."""
    folder = Path(pack).expanduser().absolute()
    return [
        (folder, str(folder)),
        (PACKAGE / "__init__.py", str(PACKAGE / "__init__.py")),
        (PACKAGE / "l1", str(PACKAGE / "l1")),
    ]


def container_name(run: str, lane: str, engine_id: str) -> str:
    """flightdeck-<run>-<lane>-l1-<engine id>, in the characters docker allows in a name, at
    most MAX_NAME long (a longer one is cut, and a hash of it keeps it apart)."""
    raw = f"flightdeck-{run}-{lane}-l1-{engine_id}"
    name = _NAME_CHARS.sub("-", raw)
    if len(name) > MAX_NAME:
        digest = hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
        name = f"{name[:MAX_NAME - 11]}-{digest}"
    return name


def fence_name(run: str, lane: str) -> str:
    """What the fenced network a lane's online engines share is named after
    (agent.egress.Egress: <this>-net, and its proxies <this>-egress-1, ...): no engine's
    container has such a name (container_name: theirs have -l1- in them). Cut like one, with
    room for those endings."""
    raw = f"flightdeck-{run}-{lane}-l1net"
    name = _NAME_CHARS.sub("-", raw)
    room = MAX_NAME - len("-egress-99")
    if len(name) > room:
        digest = hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()[:10]
        name = f"{name[:room - 11]}-{digest}"
    return name


class EngineContainer:
    """One L1 engine run's workspace in Docker (see the module docstring).

    prepare() copies the handout and starts the container (agent.workspace.DockerWorkspace,
    with the read-only mounts); programs() looks programs up in it; exec_argv() is the
    `docker exec` that runs a command there, and run_argv() runs a command on this machine
    (flightdeck's capture, which starts that docker exec); wipe() empties /work from inside;
    close() removes the container. run() and interactive_shell() are the lane workspace's:
    in the container. `labels` go on the container (a run's: leftovers.labels())."""

    def __init__(self, root: Path, handout: Path, *, image: str, name: str, network: str, pack: Path,
                 labels: Mapping[str, str] | None = None) -> None:
        self.box = DockerWorkspace(root, handout, image=image, name=name, network=network, mounts=engine_mounts(pack),
                                   labels=labels)
        self.root = self.box.root
        self.workdir = CONTAINER_ROOT  # root as the engine sees it
        self.image = image
        self.name = name
        self.network = network
        self._ready = False
        self._closed = False

    async def prepare(self) -> None:
        await self.box.prepare()
        self._ready = True

    async def programs(self, names: Sequence[str]) -> tuple[dict[str, str | None], str]:
        """({name: its absolute path in the container, or None when the image has no such
        program}, the PATH they were looked up on: the image's, absolute directories only).
        WorkspaceError when the container does not answer."""
        self._check()
        names = list(dict.fromkeys(names))
        code, out = await _docker("exec", self.name, "bash", "-c", _LOOKUP, "flightdeck-l1", *names)
        parts = out.split("\0")
        if code != 0 or len(parts) != len(names) + 2 or parts[-1]:
            said = _first_line(out.replace("\0", " ")) or f"docker exec exited {code}"
            raise WorkspaceError(f"could not look up the engine's programs in container {self.name}: {said}")
        found = {name: (at if at.startswith("/") else None) for name, at in zip(names, parts[1:-1])}
        return found, absolute_path(parts[0])

    def exec_argv(self, argv: Sequence[str], env: Mapping[str, str]) -> list[str]:
        """The `docker exec` that runs argv in this container, from /work, with env and nothing
        else of this machine's environment (docker passes none of it in). Its stdin is not
        attached. WorkspaceError when there is no docker on PATH."""
        docker = shutil.which("docker", path=absolute_path(os.environ.get("PATH", "")))
        if docker is None:
            raise WorkspaceError("docker not found on PATH")
        settings = [arg for key, value in env.items() for arg in ("-e", f"{key}={value}")]
        return [docker, "exec", "-w", CONTAINER_ROOT, *settings, self.name, *argv]

    async def run_argv(self, argv: Sequence[str], *, timeout: float) -> RunResult:
        """Run argv on THIS machine, from the copy's folder, in a process group of its own that
        a timeout or a cancel kills, with flightdeck's environment: the docker client needs it
        (its context, its socket) and docker passes none of it into the container. The engine
        a killed `docker exec` leaves running in the container ends when close() removes it."""
        self._check()
        if not (isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and math.isfinite(timeout) and timeout > 0):
            raise ValueError(f"timeout must be a positive number of seconds, got {timeout!r}")
        try:
            code, output, timed_out = await _execute(
                list(argv), cwd=self.root, env=None, stdin=None, timeout=timeout, started=lambda proc: None
            )
        except OSError as exc:
            raise WorkspaceError(f"cannot start the engine for container {self.name}: {exc.strerror or exc}") from None
        if timed_out:
            return RunResult(None, output, timed_out=True)
        if code is None or (code < 0 and self._closed):
            return RunResult(None, output)
        return RunResult(_exit_status(code), output)

    async def wipe(self) -> str:
        """Remove what is in /work, from inside the container, as its root user, after giving
        the owner back every folder an engine made unreadable (a shared folder of Docker
        Desktop holds root to the file modes). Symlinks are removed, never followed. "" when
        it is done, or when there is no container to do it in (close() has run, or prepare()
        failed), else why it could not be: the copy is then removed from this machine alone."""
        if self._closed or not self._ready:
            return ""
        try:
            code, out = await _docker("exec", "-u", "0", self.name, "bash", "-c", _WIPE, "flightdeck-l1", CONTAINER_ROOT)
        except WorkspaceError as exc:
            return str(exc)
        return "" if code == 0 else (_first_line(out) or f"emptying {CONTAINER_ROOT} exited {code}")

    async def close(self) -> None:
        self._closed = True
        await self.box.close()

    async def run(self, command: str, *, timeout: float, stdin: bytes | None = None) -> RunResult:
        """A shell command in the container, as a lane's (DockerWorkspace.run)."""
        return await self.box.run(command, timeout=timeout, stdin=stdin)

    def interactive_shell(self) -> ShellSpec:
        return self.box.interactive_shell()

    def _check(self) -> None:
        if self._closed:
            raise WorkspaceError("workspace is closed")
        if not self._ready:
            raise WorkspaceError("workspace not prepared: call prepare() first")
