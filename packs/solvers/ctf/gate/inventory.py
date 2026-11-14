"""Content-hash incremental inventory: recompute only what changed.

Two layers, each persisted as one JSON file and written atomically (temp file + rename, so a reader
never sees half a file and two writers only lose cache entries, never corrupt them):

    ContentHashes(path)               sha256 of a file, re-read only when its stat signature
                                      (size, mtime_ns, ctime_ns, inode) changed since it was hashed
        .sha(abs_path) -> str | None  None for a missing file
    Inventory(path, version)          key -> value computed from that key's content hash
        .refresh(items, compute)      items: {key: content hash}; compute(key) runs only for a key that is
                                      new or whose hash changed; keys no longer listed are dropped
        .get(key)                     the stored value
        .stats                        Stats(total, computed, reused, removed, rebuilt)

Neither layer is authoritative: an unreadable or wrong-version file is rebuilt from scratch and
`stats.rebuilt` names why (the caller prints it), never silently reused. The inventory is keyed by
content hash, not by path or time, so it is shared safely across worktrees and reruns: the same bytes
always map to the same value. The gate keys its parse results by file content (impact.py); the same
class serves any corpus that is re-derived per item (a speed-run mode list, a case index).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

_CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(_CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _load_json(path: Path, version: str) -> tuple[dict, str]:
    """(entries, why-rebuilt). A missing file is a plain first build (why = '')."""
    if not path.exists():
        return {}, ""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        return {}, f"{path.name} unreadable ({type(e).__name__}); rebuilt"
    if not isinstance(d, dict) or d.get("version") != version or not isinstance(d.get("entries"), dict):
        return {}, f"{path.name} has another format version; rebuilt"
    return d["entries"], ""


def _write_json(path: Path, version: str, entries: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": version, "entries": entries}, f, separators=(",", ":"), sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass
class Stats:
    total: int = 0
    computed: int = 0
    reused: int = 0
    removed: int = 0
    rebuilt: str = ""


class ContentHashes:
    """sha256 per absolute path, re-hashed only when the stat signature moved."""

    VERSION = "hashes-1"

    def __init__(self, path: Path):
        self.path = Path(path)
        self._entries, self.rebuilt = _load_json(self.path, self.VERSION)
        self.hashed = 0         # files actually read this session
        self.reused = 0
        self._dirty = False
        self._session: dict[str, str | None] = {}

    @staticmethod
    def _sig(st: os.stat_result) -> list:
        return [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]

    def sha(self, path: Path) -> str | None:
        """The file's sha256 (None when missing). Stat'ed once per session: a run sees one snapshot."""
        key = str(Path(path).absolute())
        if key in self._session:
            return self._session[key]
        got = self._sha(key)
        self._session[key] = got
        return got

    def _sha(self, key: str) -> str | None:
        try:
            st = os.stat(key)
        except FileNotFoundError:
            return None
        if not os.path.isfile(key):
            return None
        sig = self._sig(st)
        hit = self._entries.get(key)
        if hit and hit[0] == sig:
            self.reused += 1
            return hit[1]
        digest = sha256_file(Path(key))
        self.hashed += 1
        self._entries[key] = [sig, digest]
        self._dirty = True
        return digest

    def save(self) -> None:
        if self._dirty:
            _write_json(self.path, self.VERSION, self._entries)
            self._dirty = False


class Inventory:
    """key -> value, recomputed only for keys whose content hash changed."""

    def __init__(self, path: Path, version: str):
        self.path = Path(path)
        self.version = version
        self._entries, rebuilt = _load_json(self.path, version)
        self.stats = Stats(rebuilt=rebuilt)
        self._dirty = False

    def refresh(self, items: Mapping[str, str], compute: Callable[[str], Any]) -> Stats:
        """Bring the inventory in line with `items` ({key: content hash}). Returns this pass's stats."""
        s = Stats(rebuilt=self.stats.rebuilt)
        for key, digest in items.items():
            if digest is None:
                raise ValueError(f"inventory item {key!r} has no content hash (missing file?)")
            old = self._entries.get(key)
            if old is not None and old[0] == digest:
                s.reused += 1
                continue
            self._entries[key] = [digest, compute(key)]
            s.computed += 1
            self._dirty = True
        for key in [k for k in self._entries if k not in items]:
            del self._entries[key]
            s.removed += 1
            self._dirty = True
        s.total = len(self._entries)
        self.stats = s
        return s

    def get(self, key: str) -> Any:
        return self._entries[key][1]

    def discard(self, key: str) -> bool:
        """Forget one key, so the next refresh computes it whatever its hash (a value that must not be
        reused, such as a red replay). True when it was there."""
        if key not in self._entries:
            return False
        del self._entries[key]
        self._dirty = True
        return True

    def __contains__(self, key: str) -> bool:
        return key in self._entries

    def save(self) -> None:
        if self._dirty:
            _write_json(self.path, self.version, self._entries)
            self._dirty = False
