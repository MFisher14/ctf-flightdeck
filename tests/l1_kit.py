"""Synthetic L1 packs and challenges for the tests: engines written into tmp_path, never a
real solver, and folder-board challenges with invented files."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
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
