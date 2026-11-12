"""Synthetic L1 packs and challenges for the tests: engines written into tmp_path, never a
real solver, and folder-board challenges with invented files."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import textwrap
from pathlib import Path

from ctf_flightdeck.core.model import Challenge

FLAG = r"t\{[a-z0-9_]+\}"


def run(coro):
    return asyncio.run(coro)


def write_manifest(pack: Path, name: str, text: str) -> Path:
    path = pack / f"{name}.manifest.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip())
    return path


def python_engine(pack: Path, name: str, body: str, *, engine_id: str | None = None, extra: str = "",
                  route: str = 'keywords = ["demo"]') -> Path:
    """pack/<name>.py with `body` (dedented) and its manifest, entry <name>.py:solve."""
    pack.mkdir(parents=True, exist_ok=True)
    (pack / f"{name}.py").write_text(textwrap.dedent(body).lstrip())
    return write_manifest(pack, name, f"""
        id = "{engine_id or name}"
        entry = "{name}.py:solve"
        {extra}
        [[routes]]
        {route}
        """)


def cli_engine(pack: Path, name: str, script: str, *, engine_id: str | None = None, output: str = "text",
               extra: str = "", route: str = 'keywords = ["demo"]') -> Path:
    """An executable bash script pack/<name>.sh and its manifest, entry cli:./<name>.sh."""
    pack.mkdir(parents=True, exist_ok=True)
    path = pack / f"{name}.sh"
    path.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(script).lstrip())
    path.chmod(0o755)
    return write_manifest(pack, name, f"""
        id = "{engine_id or name}"
        entry = "cli:./{name}.sh"
        output = "{output}"
        {extra}
        [[routes]]
        {route}
        """)


def challenge_dir(board: Path, name: str, files: dict[str, str | bytes] | None = None, *,
                  category: str = "misc", description: str = "a demo challenge", **spec) -> Path:
    """board/<name>/ with a challenge.json and the given files (paths may have subfolders)."""
    folder = board / name
    folder.mkdir(parents=True)
    data = {"name": spec.pop("title", name.replace("-", " ").title()), "category": category, "points": 100,
            "description": description, **spec}
    (folder / "challenge.json").write_text(json.dumps(data))
    for rel, content in (files or {}).items():
        target = folder / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
    return folder


def challenge(name: str = "Demo", category: str = "misc", description: str = "") -> Challenge:
    return Challenge(id=name.lower().replace(" ", "-"), name=name, category=category, points=100, description=description)


def tree(root: Path) -> dict[str, tuple[str, int, int]]:
    """Every entry under root (symlinks not followed): relative path -> (kind, mode, mtime_ns)
    plus a hash for files, to show nothing changed."""
    out = {}
    for directory, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(directory) / name
            info = path.lstat()
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                out[rel] = ("link:" + os.readlink(path), info.st_mode, info.st_mtime_ns)
            elif path.is_file():
                out[rel] = ("file:" + hashlib.sha256(path.read_bytes()).hexdigest(), info.st_mode, info.st_mtime_ns)
            else:
                out[rel] = ("dir", info.st_mode, info.st_mtime_ns)
    return out


# ---------------------------------------------------------------- L1 engines in Docker

DOCKER_IMAGE = "debian:bookworm-slim"  # the only image tests use, and only when it is already here (never pulled)

FAKE_DOCKER = r"""#!/bin/bash
# A stand-in for the docker CLI: it records each `docker run`, answers what an engine's
# container asks while it prepares (from this machine's bash), and runs no engine. Each
# `docker ps` is written to ps.log and lists what ps.txt next to it holds (nothing when there
# is none), or fails saying what ps.fail holds; each `docker rm` is written to rm.log.
# A fenced lane's network (agent/egress.py): each `docker network ...` is written to
# network.log; `network ls` lists what networks.txt holds, or fails saying what networks.fail
# holds; `network inspect` prints what gateway.txt holds (a network with no gateway without it); `network
# create` fails saying what create.fail holds. The `docker run` of an egress proxy
# (--entrypoint python3) is written to proxies.log, not runs.log: its arguments up to the
# script, then its configuration; `docker logs` says the proxy is ready, or what logs.txt holds.
here="$(dirname "$0")"
case "$1" in
  version) echo 99.0.0-fake ;;
  image) echo sha256:fake ;;
  container) echo "Error: No such container" >&2; exit 1 ;;
  network)
    printf '%s\n' "$*" >> "$here/network.log"
    case "$2" in
      ls) if [ -f "$here/networks.fail" ]; then cat "$here/networks.fail" >&2; exit 1; fi
          cat "$here/networks.txt" 2>/dev/null; exit 0 ;;
      inspect) cat "$here/gateway.txt" 2>/dev/null || echo '[{"Subnet":"172.30.0.0/16"}]'; exit 0 ;;
      create) if [ -f "$here/create.fail" ]; then cat "$here/create.fail" >&2; exit 1; fi; echo fake-network-id ;;
    esac
    exit 0 ;;
  logs) if [ -f "$here/logs.txt" ]; then cat "$here/logs.txt"; else echo "flightdeck-egress ready"; fi ;;
  run)
    all="$*"
    case " $all " in
      *" --entrypoint python3 "*) printf '%s %s\n' "${all%% -I -c *}" "${@: -1}" >> "$here/proxies.log" ;;
      *) printf '%s\n' "$all" >> "$here/runs.log" ;;
    esac
    echo fake-container-id ;;
  ps)
    printf '%s\n' "$*" >> "$(dirname "$0")/ps.log"
    if [ -f "$(dirname "$0")/ps.fail" ]; then cat "$(dirname "$0")/ps.fail" >&2; exit 1; fi
    cat "$(dirname "$0")/ps.txt" 2>/dev/null; exit 0 ;;
  rm) printf '%s\n' "$*" >> "$(dirname "$0")/rm.log"; exit 0 ;;
  exec)
    shift
    while [ "${1#-}" != "$1" ]; do case "$1" in -w|-e|-u) shift 2 ;; *) shift ;; esac; done
    shift
    if [ "$1 $2" = "bash -c" ] && [ "${3#command -v }" != "$3" ]; then echo "/usr/bin/${3#command -v }"; exit 0; fi
    if [ "$1" = bash ]; then shift; exec bash "$@"; fi  # the program lookup, answered from this machine
    exit 0 ;;
  *) echo "fake docker: unexpected call: $*" >&2; exit 2 ;;
esac
"""
FAKE_IMAGE = "flightdeck-test-fake-image:1"  # a made-up name: only the fake docker ever sees it


def install_fake_docker(tmp_path: Path, monkeypatch) -> Path:
    """FAKE_DOCKER first on PATH, so no container is started; returns the file each `docker
    run` is written to (one line of its arguments)."""
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (fake_bin / "docker").write_text(FAKE_DOCKER)
    (fake_bin / "docker").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    return fake_bin / "runs.log"


def docker_skip_reason() -> str | None:
    """Why the tests with a real container cannot run here, or None when they can."""
    from ctf_flightdeck.agent.workspace import docker_unavailable

    reason = docker_unavailable()
    if reason:
        return reason
    probe = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", DOCKER_IMAGE], capture_output=True, timeout=60)
    if probe.returncode != 0:
        return f"image {DOCKER_IMAGE} is not present locally (these tests never pull it)"
    return None


def containers(word: str) -> list[str]:
    """The names of the containers (running or not) whose name holds `word`."""
    out = subprocess.run(["docker", "ps", "-a", "--filter", f"name={word}", "--format", "{{.Names}}"],
                         capture_output=True, text=True, timeout=60)
    return [line for line in out.stdout.splitlines() if word in line]


def remove_containers(word: str) -> None:
    for left in containers(word):
        subprocess.run(["docker", "rm", "-f", left], capture_output=True, timeout=60)
