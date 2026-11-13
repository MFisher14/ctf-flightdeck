"""Disk side of the host resource governor (B-176): disk-budget preflight, a copier that rejects
symlinks, post-acceptance eviction of large artifacts, and Spotlight exclusion for worktrees.

Evidence: a self-referential ``challenges/challenges`` symlink made a Huntress test copier recurse until
the disk filled (3 ENOSPC hits, 108 false failures, a failed 3,026 s run); Spooky ran with about 806 MB
free while 1 GB and 850 MB captures sat in solved challenges' folders; Spotlight indexed agent worktrees
under build load.

    from ctf import diskguard
    diskguard.disk_preflight(dest, need_bytes, min_free_bytes)   # -> DiskVerdict (.ok, .reason)
    diskguard.safe_copytree(src, dst, min_free_bytes=...)         # SymlinkRejected / DiskBudgetError first
    diskguard.eviction_plan(workdir, min_bytes=...)               # large files in ACCEPTED challenges only
    diskguard.apply_eviction(plan, workdir)                       # deletes them, records evicted.json
    diskguard.spotlight_status(path) / exclude_from_spotlight(path)

Nothing here follows a symlink. ``apply_eviction`` is the only function that deletes, and it deletes only
files ``eviction_plan`` listed, re-checked (same inode, size and mtime, still a regular file inside the
challenge folder) at the moment of deletion.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

GiB = 1024 ** 3
MiB = 1024 ** 2

DEFAULT_EVICT_MIN_MB = 50

# What eviction keeps whatever its size: the writeup, the solve scripts and the challenge's own records.
KEEP_NAMES = frozenset({"flag.txt", "notes.md", "tried.json", "triage.md", "evicted.json"})
KEEP_SUFFIXES = frozenset({".md", ".txt", ".py", ".sh", ".sage", ".c", ".h", ".cc", ".cpp", ".rs", ".go",
                           ".js", ".ts", ".rb", ".pl", ".php", ".toml", ".yaml", ".yml", ".json",
                           ".ipynb", ".gp", ".m"})
KEEP_PREFIXES = ("solve", "writeup", "exploit", "README")
KEEP_DIRS = frozenset({"writeup", "writeups", "scripts", "solve", "recon"})

_CHALLENGE_DIR = re.compile(r"^([A-Za-z0-9_]+)-")

NEVER_INDEX = ".metadata_never_index"


class DiskGuardError(RuntimeError):
    """A disk guard refused; the message names the path and the limit."""


class SymlinkRejected(DiskGuardError):
    """The source tree holds a symlink (or a non-regular file): the copier never follows one."""


class DiskBudgetError(DiskGuardError):
    """The copy or job would leave less free disk than the floor."""


# ------------------------------------------------------------------------------------------ preflight

@dataclass(frozen=True)
class DiskVerdict:
    ok: bool
    path: str
    free_bytes: int
    need_bytes: int
    min_free_bytes: int
    reason: str


def _existing(path: Path) -> Path:
    p = Path(path).expanduser().absolute()
    while not p.exists() and p.parent != p:
        p = p.parent
    return p


def disk_preflight(path: str | Path, need_bytes: int, min_free_bytes: int = 0, *,
                   usage=shutil.disk_usage) -> DiskVerdict:
    """Would writing ``need_bytes`` under ``path`` leave at least ``min_free_bytes`` free? Measured on
    the volume of ``path`` (or its nearest existing ancestor)."""
    if need_bytes < 0 or min_free_bytes < 0:
        raise DiskGuardError(f"need ({need_bytes}) and floor ({min_free_bytes}) must be >= 0")
    where = _existing(Path(path))
    free = int(usage(where).free)
    left = free - need_bytes
    ok = left >= min_free_bytes
    reason = (f"{need_bytes / GiB:.2f} GiB needed at {where}: {free / GiB:.2f} GiB free, "
              f"{left / GiB:.2f} GiB would remain (floor {min_free_bytes / GiB:.2f} GiB)")
    return DiskVerdict(ok=ok, path=str(where), free_bytes=free, need_bytes=need_bytes,
                       min_free_bytes=min_free_bytes, reason=reason)


def parse_size(text: str) -> int:
    """``123``, ``500M``, ``2G``, ``1.5GiB`` -> bytes (binary units). Raises ``DiskGuardError``."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)(?:i?[bB])?\s*", text or "")
    if not m:
        raise DiskGuardError(f"not a size: {text!r} (use e.g. 500M, 2G)")
    mult = {"": 1, "k": 1024, "m": MiB, "g": GiB, "t": 1024 * GiB}[m.group(2).lower()]
    return int(float(m.group(1)) * mult)


# --------------------------------------------------------------------------------------------- copier

def scan_tree(src: str | Path) -> tuple[int, int]:
    """``(files, bytes)`` of the regular files under ``src``. Raises ``SymlinkRejected`` naming the first
    symlink, socket, FIFO or device found; never follows a link."""
    src = Path(src)
    st = os.lstat(src)
    if stat.S_ISLNK(st.st_mode):
        raise SymlinkRejected(f"refusing to copy: {src} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise DiskGuardError(f"{src} is not a directory")
    files = total = 0
    stack = [src]
    while stack:
        d = stack.pop()
        with os.scandir(d) as it:
            for e in it:
                m = e.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(m):
                    raise SymlinkRejected(f"refusing to copy: {e.path} is a symlink "
                                          f"(-> {os.readlink(e.path)}); copiers never follow links")
                if stat.S_ISDIR(m):
                    stack.append(Path(e.path))
                elif stat.S_ISREG(m):
                    files += 1
                    total += e.stat(follow_symlinks=False).st_size
                else:
                    raise SymlinkRejected(f"refusing to copy: {e.path} is not a regular file or folder")
    return files, total


def safe_copytree(src: str | Path, dst: str | Path, *, min_free_bytes: int = 0,
                  usage=shutil.disk_usage) -> int:
    """Copy the folder ``src`` to the new folder ``dst`` with no symlink followed or copied, after a
    disk-budget preflight. Everything is checked before the first byte is written: a symlink raises
    ``SymlinkRejected``, a copy that would leave less than ``min_free_bytes`` free raises
    ``DiskBudgetError``, an existing ``dst`` raises ``DiskGuardError``. Returns bytes copied."""
    src, dst = Path(src), Path(dst)
    if os.path.lexists(dst):
        raise DiskGuardError(f"destination {dst} already exists")
    if _existing(dst).resolve().is_relative_to(src.resolve()):
        raise DiskGuardError(f"destination {dst} is inside the source {src}: the copy would recurse")
    _, total = scan_tree(src)
    verdict = disk_preflight(dst.parent, total, min_free_bytes, usage=usage)
    if not verdict.ok:
        raise DiskBudgetError(f"copy of {src} refused: {verdict.reason}")
    copied = 0
    for root, dirs, files in os.walk(src, followlinks=False):
        rel = Path(root).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=False)
        for f in files:
            s = Path(root) / f
            if os.path.islink(s):  # appeared after the scan
                raise SymlinkRejected(f"refusing to copy: {s} became a symlink during the copy")
            shutil.copy2(s, dst / rel / f, follow_symlinks=False)
            copied += os.lstat(s).st_size
        for d in dirs:
            if os.path.islink(Path(root) / d):
                raise SymlinkRejected(f"refusing to copy: {Path(root) / d} became a symlink during the copy")
    return copied


# ------------------------------------------------------------------------------------------- eviction

@dataclass(frozen=True)
class Evictable:
    challenge: str        # the challenge folder name
    path: Path            # absolute file path
    size: int
    inode: int
    mtime_ns: int
    why_accepted: str     # "flag.txt" (our accepted flag) or "team solve" (ledger stop)


@dataclass(frozen=True)
class EvictionPlan:
    files: tuple[Evictable, ...]
    kept: int                     # large files kept as writeup / scripts / records
    challenges: tuple[str, ...]   # accepted challenge folders scanned

    @property
    def bytes(self) -> int:
        return sum(f.size for f in self.files)


def _keep(rel: Path) -> bool:
    name = rel.name
    if name in KEEP_NAMES or rel.suffix.lower() in KEEP_SUFFIXES:
        return True
    if any(name.lower().startswith(p.lower()) for p in KEEP_PREFIXES):
        return True
    return any(part in KEEP_DIRS for part in rel.parts[:-1])


def eviction_plan(workdir: str | Path, *, min_bytes: int = DEFAULT_EVICT_MIN_MB * MiB,
                  solved: Iterable[str] | None = None) -> EvictionPlan:
    """Large files in challenge folders (``<id>-<slug>``) whose flag was accepted: the folder holds
    ``flag.txt`` (written on an accepted submit) or its id is in ``solved`` (default: the team-solve
    view, ``ctf.solved.solved_ids``). Writeups, scripts and the challenge records are kept whatever their
    size. Symlinks are never followed or listed. Unsolved folders are never touched."""
    if min_bytes < 1:
        raise DiskGuardError(f"min_bytes must be >= 1, got {min_bytes}")
    wd = Path(workdir)
    if not wd.is_dir():
        raise DiskGuardError(f"workdir {wd} is not a folder")
    if solved is None:
        from . import solved as _solved
        solved = _solved.solved_ids(wd)
    solved = {str(s) for s in solved}
    files: list[Evictable] = []
    kept = 0
    scanned = []
    for d in sorted(wd.iterdir()):
        m = _CHALLENGE_DIR.match(d.name)
        if not m or d.is_symlink() or not d.is_dir():
            continue
        flag = d / "flag.txt"
        if flag.is_file() and not flag.is_symlink():
            why = "flag.txt"
        elif m.group(1) in solved:
            why = "team solve"
        else:
            continue
        scanned.append(d.name)
        for root, dirs, names in os.walk(d, followlinks=False):
            for n in names:
                p = Path(root) / n
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode) or st.st_size < min_bytes:
                    continue
                if _keep(p.relative_to(d)):
                    kept += 1
                    continue
                files.append(Evictable(challenge=d.name, path=p.absolute(), size=st.st_size,
                                       inode=st.st_ino, mtime_ns=st.st_mtime_ns, why_accepted=why))
    return EvictionPlan(files=tuple(files), kept=kept, challenges=tuple(scanned))


def apply_eviction(plan: EvictionPlan, workdir: str | Path, *, ledger: bool = True) -> list[dict]:
    """Delete the planned files. Each is re-checked first (still a regular file, same inode, size and
    mtime, inside its challenge folder); a changed one is skipped and reported, never deleted. Each
    challenge folder gets an ``evicted.json`` record; with ``ledger`` one ``governor.evict`` ledger
    record per file. Returns one record per planned file with ``action`` evicted | skipped."""
    wd = Path(workdir).resolve()
    out: list[dict] = []
    per_dir: dict[str, list[dict]] = {}
    for f in plan.files:
        cdir = (wd / f.challenge).resolve()
        real = Path(f.path).parent.resolve() / Path(f.path).name   # the file itself is never followed
        rec = {"challenge": f.challenge, "path": os.path.relpath(real, cdir),
               "size": f.size, "accepted": f.why_accepted, "t": time.time()}
        try:
            st = os.lstat(f.path)
            inside = real.is_relative_to(cdir)
        except OSError as e:
            rec.update(action="skipped", reason=f"gone: {e.strerror}")
            out.append(rec)
            continue
        if not inside:
            rec.update(action="skipped", reason="no longer inside its challenge folder")
        elif not stat.S_ISREG(st.st_mode):
            rec.update(action="skipped", reason="no longer a regular file")
        elif (st.st_ino, st.st_size, st.st_mtime_ns) != (f.inode, f.size, f.mtime_ns):
            rec.update(action="skipped", reason="changed since the plan (inode, size or mtime)")
        else:
            os.unlink(f.path)
            rec.update(action="evicted")
            per_dir.setdefault(f.challenge, []).append(rec)
        out.append(rec)
    for chal, recs in per_dir.items():
        p = wd / chal / "evicted.json"
        try:
            prior = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else []
        except ValueError:
            prior = []
        p.write_text(json.dumps(prior + recs, indent=1), encoding="utf-8")
    if ledger:
        from . import ledger as _ledger
        for r in out:
            _ledger.append("governor.evict", workdir=wd, challenge=r["challenge"], path=r["path"],
                           size=r["size"], action=r["action"], reason=r.get("reason", ""))
    return out


# ------------------------------------------------------------------------------------------ spotlight

@dataclass(frozen=True)
class SpotlightStatus:
    excluded: bool
    how: str          # "noindex-folder" | "marker" | "none"
    detail: str


def spotlight_status(path: str | Path) -> SpotlightStatus:
    """Is ``path`` kept out of Spotlight? macOS skips any folder whose name ends in ``.noindex`` (and
    everything under it); a ``.metadata_never_index`` marker file asks it to skip the folder holding it.
    The marker is honoured at volume roots; for plain folders recent macOS releases may ignore it, so the
    marker alone is reported with that caveat and the Spotlight Privacy list is the sure route."""
    p = Path(path).expanduser().absolute()
    for a in (p, *p.parents):
        if a.name.endswith(".noindex"):
            return SpotlightStatus(True, "noindex-folder", f"{a} ends in .noindex")
    for a in (p, *p.parents):
        if (a / NEVER_INDEX).is_file():
            return SpotlightStatus(True, "marker", f"{a / NEVER_INDEX} present (honoured at volume roots; "
                                                    f"add the folder to Spotlight Privacy to be sure)")
    return SpotlightStatus(False, "none", f"nothing keeps {p} out of Spotlight")


def exclude_from_spotlight(path: str | Path) -> SpotlightStatus:
    """Write the ``.metadata_never_index`` marker into the folder ``path`` (it must exist) and return the
    resulting status."""
    p = Path(path).expanduser()
    if not p.is_dir() or p.is_symlink():
        raise DiskGuardError(f"{p} is not a folder")
    (p / NEVER_INDEX).touch(exist_ok=True)
    return spotlight_status(p)
