"""Routing: which engines a challenge reaches, best first, and why.

A route matches when every condition it states holds:
- category: the challenge's category code is one of them;
- keywords: one of them is a substring of the challenge's name + " " + description,
  lower-cased;
- files: one of the patterns matches a handout file: `ext:.x` (a case-insensitive suffix of
  the file name, so `ext:.tar.gz` works), `magic:<text>` (the file's first 4096 bytes start
  with the text as latin-1; `magic:0x<hex>` is bytes) or `name:<glob>` (fnmatch on the file
  name, case-sensitive).
An engine's score is its best matching route's priority; hits sort by priority (high
first), then id.

The handout is untrusted: the walk never follows a symlink and only opens regular files
(through no symlink, and non-blocking, so a FIFO cannot hang it). It searches
subdirectories, stops after 2000 files, and leaves out the board's own challenge.json at
the top. File names from the handout appear in a hit's reason made safe to print.

Routing looks only at what an engine will see: the files agent.workspace.copy_handout
puts in the engine's copy. So it leaves out what that copy leaves out: symlinks, anything
that is not a regular file or a directory, a .flightdeck/ at the top (flightdeck's own
name) and every __pycache__/ folder (Python's bytecode cache). An engine is never routed
by a file it will not have.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..agent.workspace import PRIVATE, open_inside
from ..core.model import Challenge
from ..platform.manual import CHALLENGE_FILE, category_code
from ..text import untrusted
from .manifest import MAGIC_BYTES, Manifest, Route, file_pattern

MAX_FILES = 2000
MAX_DIRS = 20000  # a handout of nothing but empty directories still ends
NOT_COPIED_DIRS = ("__pycache__",)  # folders copy_handout leaves out at any depth (and .flightdeck at the top)


@dataclass(frozen=True)
class Hit:
    manifest: Manifest
    priority: int
    reason: str  # e.g. "category cry, keyword 'base64'"


def route(manifests: Sequence[Manifest], challenge: Challenge, handout: Path) -> list[Hit]:
    """The engines `challenge` reaches, best first. `handout` is its challenge directory."""
    handout = Path(handout)
    if not handout.is_dir():
        raise ValueError(f"handout {untrusted(str(handout), one_line=True)} is not a directory")
    files = HandoutFiles(handout)
    text = f"{challenge.name} {challenge.description}".lower()
    category = category_code(challenge.category)
    hits: list[Hit] = []
    for manifest in manifests:
        best: tuple[int, list[str]] | None = None
        for candidate in manifest.routes:
            reasons = _match(candidate, category, text, files)
            if reasons is not None and (best is None or candidate.priority > best[0]):
                best = (candidate.priority, reasons)
        if best is not None:
            hits.append(Hit(manifest, best[0], ", ".join(best[1])))
    hits.sort(key=lambda hit: (-hit.priority, hit.manifest.id))
    return hits


@dataclass(frozen=True)
class Miss:
    """An engine a challenge does not reach, and why: its nearest route (the fewest
    conditions that failed, then the most that held, then the highest priority)."""

    manifest: Manifest
    route: Route
    failed: tuple[str, ...]  # e.g. "no keyword 'caesar' | 'bruteforce' in its name or description"
    held: tuple[str, ...]  # e.g. "category cry"


def misses(manifests: Sequence[Manifest], challenge: Challenge, handout: Path) -> list[Miss]:
    """The engines `challenge` does not reach, by id, each with its nearest route and the
    conditions of it that failed (and those that held). `route` says which it does reach."""
    handout = Path(handout)
    if not handout.is_dir():
        raise ValueError(f"handout {untrusted(str(handout), one_line=True)} is not a directory")
    files = HandoutFiles(handout)
    text = f"{challenge.name} {challenge.description}".lower()
    category = category_code(challenge.category)
    reached = {hit.manifest.id for hit in route(manifests, challenge, handout)}
    out: list[Miss] = []
    for manifest in sorted(manifests, key=lambda m: m.id):
        if manifest.id in reached:
            continue
        checked = [(rule, *_check(rule, category, text, files)) for rule in manifest.routes]
        rule, held, failed = min(checked, key=lambda c: (len(c[2]), -len(c[1]), -c[0].priority))
        out.append(Miss(manifest, rule, tuple(failed), tuple(held)))
    return out


def _check(rule: Route, category: str, text: str, files: HandoutFiles) -> tuple[list[str], list[str]]:
    """(the conditions of `rule` that held, those that failed), each as a phrase; unlike
    _match it looks at every condition."""
    held: list[str] = []
    failed: list[str] = []
    if rule.any:
        return ["any challenge"], []
    if rule.category:
        if category in rule.category:
            held.append(f"category {category}")
        else:
            failed.append(f"its category {_quote(category or 'none')} is not {' | '.join(rule.category)}")
    if rule.keywords:
        keyword = next((k for k in rule.keywords if k in text), None)
        if keyword is not None:
            held.append(f"keyword {_quote(keyword)}")
        else:
            failed.append(f"no keyword {' | '.join(_quote(k) for k in rule.keywords)} in its name or description")
    if rule.files:
        found = files.match(rule.files)
        if found is not None:
            pattern, rel = found
            held.append(f"file {_quote(rel)} ({pattern})")
        else:
            failed.append(f"no file of the handout matches {' | '.join(rule.files)}")
    return held, failed


def _match(rule: Route, category: str, text: str, files: HandoutFiles) -> list[str] | None:
    """Why `rule` matches (one phrase per condition), or None if a condition fails."""
    reasons: list[str] = []
    if rule.any:
        return ["any challenge"]
    if rule.category:
        if category not in rule.category:
            return None
        reasons.append(f"category {category}")
    if rule.keywords:
        keyword = next((k for k in rule.keywords if k in text), None)
        if keyword is None:
            return None
        reasons.append(f"keyword {_quote(keyword)}")
    if rule.files:
        found = files.match(rule.files)
        if found is None:
            return None
        pattern, rel = found
        reasons.append(f"file {_quote(rel)} ({pattern})")
    return reasons


class HandoutFiles:
    """The regular files of a handout, walked once and only when a route asks; the first
    bytes of each read once, when a magic pattern asks."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._files: list[tuple[str, str]] | None = None  # (relative posix path, file name)
        self._heads: dict[str, bytes] = {}

    def files(self) -> list[tuple[str, str]]:
        if self._files is None:
            self._files = _walk(self.root)
        return self._files

    def match(self, patterns: Sequence[str]) -> tuple[str, str] | None:
        """(pattern, relative path) for the first pattern that matches a file, or None."""
        for pattern in patterns:
            kind, arg = file_pattern(pattern)
            for rel, name in self.files():
                if kind == "ext" and name.lower().endswith(arg):
                    return pattern, rel
                if kind == "name" and fnmatch.fnmatchcase(name, arg):
                    return pattern, rel
                if kind == "magic" and self.head(rel).startswith(arg):
                    return pattern, rel
        return None

    def head(self, rel: str) -> bytes:
        if rel not in self._heads:
            self._heads[rel] = _head(self.root, rel)
        return self._heads[rel]


def _walk(root: Path) -> list[tuple[str, str]]:
    """Regular files under root, in a fixed order (a directory's files by name, then its
    subdirectories by name, depth first), at most MAX_FILES."""
    files: list[tuple[str, str]] = []
    pending: list[tuple[Path, str]] = [(root, "")]
    dirs = 0
    while pending and len(files) < MAX_FILES and dirs < MAX_DIRS:
        directory, prefix = pending.pop()
        dirs += 1
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda e: e.name)
        except OSError:
            continue  # unreadable: nothing in it can match
        subdirs: list[tuple[Path, str]] = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if not (prefix == "" and entry.name == PRIVATE) and entry.name not in NOT_COPIED_DIRS:
                        subdirs.append((Path(entry.path), f"{prefix}{entry.name}/"))
                elif entry.is_file(follow_symlinks=False):
                    if prefix == "" and entry.name == CHALLENGE_FILE:
                        continue  # the board's metadata, not a handout file
                    files.append((prefix + entry.name, entry.name))
                    if len(files) >= MAX_FILES:
                        break
            except OSError:
                continue  # it vanished or changed while we looked
        pending.extend(reversed(subdirs))
    return files


def _head(root: Path, rel: str) -> bytes:
    """The first MAGIC_BYTES of root/rel, or b"" if it cannot be read as a regular file."""
    try:
        fd = open_inside(root, rel.split("/"))
    except OSError:
        return b""
    try:
        chunks: list[bytes] = []
        size = 0
        while size < MAGIC_BYTES:
            chunk = os.read(fd, MAGIC_BYTES - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    except OSError:
        return b""
    finally:
        os.close(fd)


def _quote(text: str) -> str:
    """Untrusted text in a reason: made safe to print, on one line, cut short."""
    safe = untrusted(text.encode("utf-8", "backslashreplace").decode("utf-8"), one_line=True)
    return "'" + (safe if len(safe) <= 60 else safe[:57] + "...") + "'"
