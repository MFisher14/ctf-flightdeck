"""Per-challenge scratch with a per-pass manifest (B-178).

All scratch for a challenge lives in its workspace folder, never under /tmp:

    <workdir>/<challenge folder>/.scratch/
        001-<purpose>/            one pass: an agent run, a relaunch, a by-hand attempt
            MANIFEST.json         who, why, when, status, and (once closed) every file with size + sha256
            ...                   the pass's files
        002-<purpose>/

A pass is opened, worked in (TMPDIR points at it: env_for()), and closed. Closing records the file
list in the manifest, so a later pass (or a relaunched agent) can see what an interrupted one left
without re-deriving it. A machine restart that clears /tmp does not touch it.

    from ctf import scratch
    chal = scratch.challenge_dir("12")                       # <workdir>/12-<slug>, exactly one match
    p = scratch.open_pass(chal, "angr-sweep", agent="rev-1")
    subprocess.run(cmd, env={**os.environ, **scratch.env_for(p)})
    scratch.close_pass(p, "closed", note="ruled out the xor path")
    scratch.passes(chal)                                     # manifests, oldest first
    scratch.prune(chal, keep=3)                              # remove old closed passes only

Statuses: open (in use), closed (finished normally), interrupted (its agent was lost and relaunched),
failed (its agent exited non-zero). Nothing here deletes a file outside `.scratch/`, an open pass, or a
folder that has no manifest.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

from . import paths as _paths

SCRATCH_DIR = ".scratch"
MANIFEST = "MANIFEST.json"
LOCK = ".lock"
SCHEMA = 1
STATUSES = ("open", "closed", "interrupted", "failed")
CLOSED_STATUSES = frozenset(STATUSES) - {"open"}
HASH_LIMIT = 64 * 1024 * 1024          # files above this are listed with size only
_PASS_RE = re.compile(r"^(\d{3,})-[a-z0-9][a-z0-9-]*$")


class ScratchError(RuntimeError):
    """A scratch operation cannot proceed; the message names why."""


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-")[:40].strip("-")
    if not s:
        raise ScratchError(f"a scratch pass needs a purpose made of letters or digits, got {text!r}")
    return s


def challenge_dir(ref: str | Path, workdir: Path | None = None) -> Path:
    """The challenge folder for `ref`: an existing directory path, or a challenge id / folder name
    under the workdir (`<id>` or `<id>-<slug>`). Exactly one match, else ScratchError."""
    p = Path(ref)
    if p.is_absolute() or os.sep in str(ref):
        if not p.is_dir():
            raise ScratchError(f"challenge folder {p} does not exist")
        return p.resolve()
    ref = str(ref).strip()
    if not ref or ref.startswith("."):
        raise ScratchError(f"bad challenge reference {ref!r}")
    wd = Path(workdir) if workdir is not None else _paths.workdir()
    if not wd.is_dir():
        raise ScratchError(f"workdir {wd} does not exist (python -m ctf workdir --create)")
    exact = wd / ref
    if exact.is_dir() and not exact.is_symlink():
        return exact.resolve()
    hits = sorted(d for d in wd.iterdir()
                  if d.is_dir() and not d.is_symlink() and d.name.startswith(ref + "-"))
    if not hits:
        raise ScratchError(f"no challenge folder for {ref!r} under {wd} (expected {ref} or {ref}-<name>)")
    if len(hits) > 1:
        raise ScratchError(f"challenge reference {ref!r} is ambiguous under {wd}: "
                           + ", ".join(h.name for h in hits))
    return hits[0].resolve()


def scratch_root(chal: Path) -> Path:
    root = Path(chal) / SCRATCH_DIR
    if root.is_symlink():
        raise ScratchError(f"{root} is a symlink; scratch must live inside the challenge folder")
    return root


def _write_manifest(pass_dir: Path, data: dict) -> None:
    tmp = pass_dir / f".{MANIFEST}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, pass_dir / MANIFEST)


def read_manifest(pass_dir: Path) -> dict:
    mp = Path(pass_dir) / MANIFEST
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScratchError(f"{pass_dir} has no {MANIFEST}; it is not a scratch pass") from None
    except json.JSONDecodeError as e:
        raise ScratchError(f"{mp}: corrupt manifest: {e}") from None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or data.get("status") not in STATUSES:
        raise ScratchError(f"{mp}: not a schema-{SCHEMA} scratch manifest")
    return data


def open_pass(chal: Path, purpose: str, *, agent: str | None = None, goal: str | None = None,
              now: float | None = None) -> Path:
    """Create the next numbered pass folder under <chal>/.scratch and write its open manifest."""
    chal = Path(chal)
    if not chal.is_dir():
        raise ScratchError(f"challenge folder {chal} does not exist")
    root = scratch_root(chal)
    root.mkdir(exist_ok=True)
    name = _slug(purpose)
    fd = os.open(root / LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)     # one number per pass, even with agents racing
        nums = [int(m.group(1)) for d in root.iterdir() if (m := _PASS_RE.match(d.name))]
        pass_dir = root / f"{max(nums, default=0) + 1:03d}-{name}"
        pass_dir.mkdir()
        _write_manifest(pass_dir, {
            "schema": SCHEMA, "pass": pass_dir.name, "purpose": purpose, "agent": agent, "goal": goal,
            "challenge_dir": str(chal.resolve()), "started": time.time() if now is None else now,
            "ended": None, "status": "open", "note": None, "files": None,
        })
    finally:
        os.close(fd)
    return pass_dir


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(pass_dir: Path) -> list[dict]:
    """Every entry under the pass except its manifest: files with size and sha256 (size only above
    HASH_LIMIT), symlinks with their target (never followed)."""
    pass_dir = Path(pass_dir)
    out = []
    for dirpath, dirnames, filenames in os.walk(pass_dir, followlinks=False):
        d = Path(dirpath)
        for name in sorted(dirnames):
            if (d / name).is_symlink():
                out.append({"path": str((d / name).relative_to(pass_dir)), "symlink": os.readlink(d / name)})
        dirnames[:] = sorted(n for n in dirnames if not (d / n).is_symlink())
        for name in sorted(filenames):
            f = d / name
            rel = str(f.relative_to(pass_dir))
            if d == pass_dir and (name == MANIFEST or name.startswith(f".{MANIFEST}.")):
                continue
            if f.is_symlink():
                out.append({"path": rel, "symlink": os.readlink(f)})
                continue
            size = f.stat().st_size
            out.append({"path": rel, "bytes": size, "sha256": _sha256(f) if size <= HASH_LIMIT else None})
    return out


def close_pass(pass_dir: Path, status: str = "closed", *, note: str | None = None,
               now: float | None = None) -> dict:
    """Record the pass's files and final status. Closing a closed pass is an error."""
    if status not in CLOSED_STATUSES:
        raise ScratchError(f"close status must be one of {sorted(CLOSED_STATUSES)}, got {status!r}")
    pass_dir = Path(pass_dir)
    data = read_manifest(pass_dir)
    if data["status"] != "open":
        raise ScratchError(f"pass {pass_dir.name} is already {data['status']}")
    data.update(status=status, note=note, ended=time.time() if now is None else now,
                files=inventory(pass_dir))
    _write_manifest(pass_dir, data)
    return data


def passes(chal: Path) -> list[dict]:
    """Manifests of every pass under <chal>/.scratch, oldest first, each with "dir" added. A folder
    there without a valid manifest is an error (it would be invisible to prune and resume)."""
    root = scratch_root(Path(chal))
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir(), key=lambda x: (_num(x.name), x.name)):
        if d.name.startswith(".") and d.is_file():
            continue
        if not d.is_dir() or d.is_symlink() or not _PASS_RE.match(d.name):
            raise ScratchError(f"{d}: unexpected entry in {root}; only numbered pass folders belong there")
        m = read_manifest(d)
        m["dir"] = str(d)
        out.append(m)
    return out


def _num(name: str) -> int:
    m = _PASS_RE.match(name)
    return int(m.group(1)) if m else -1


def latest(chal: Path) -> dict | None:
    ps = passes(chal)
    return ps[-1] if ps else None


def prune(chal: Path, keep: int) -> list[str]:
    """Delete closed passes beyond the newest `keep` closed ones. Open passes are never touched."""
    if keep < 0:
        raise ScratchError("keep must be >= 0")
    closed = [p for p in passes(chal) if p["status"] != "open"]
    doomed = closed[:max(0, len(closed) - keep)]
    root = scratch_root(Path(chal)).resolve()
    removed = []
    for p in doomed:
        d = Path(p["dir"])
        if d.resolve().parent != root:
            raise ScratchError(f"refusing to delete {d}: not directly under {root}")
        shutil.rmtree(d)
        removed.append(d.name)
    return removed


def env_for(pass_dir: Path) -> dict[str, str]:
    """Environment entries that send a process's temporary files into the pass."""
    p = str(Path(pass_dir).resolve())
    return {"TMPDIR": p, "TMP": p, "TEMP": p, "CTF_SCRATCH_DIR": p}
