"""The shared read map (B-034): one record of what each agent has read of a challenge's files, so a
second agent does not pay to read a file the first agent already read (EFFICIENCY-PLAN section 3.6:
cross-agent duplicate reads cost $1,369.52). Intake's sweep already hashes every file, so the map is
seeded from that sweep manifest and then every `ctf read` appends its own read.

Paths are relative to the challenge dir. A pulled challenge's originals are keyed by where they live
(`files/<name>`, the path `ctf read` records), its unpacked members by their scratch path
(`unpacked/<archive>.unpacked/<member>`). Every entry and every read carries the content's sha256, so a
read of one copy is found from another copy of the same bytes (`prior_reads(..., sha256=)`), and a read
of content that has since changed is not counted as already paid for.

Stored at `<challenge_dir>/recon/readmap.json` (schema 1), beside intake's other recon output. The map
is shared by every agent on the challenge: `save` takes an exclusive lock on `recon/readmap.json.lock`
(fcntl.flock), re-reads the current file, merges, and replaces it atomically (temp file + os.replace),
so one agent's record never drops another's, even when agents save at the same moment. A sweep manifest
that is present but unreadable fails loudly (ReadMapError); it is never silently treated as "nothing
read".

    from ctf import readmap
    m = readmap.ReadMap.open(challenge_dir)             # loads recon/readmap.json, seeding from the sweep
    prior = m.prior_reads("logs/a.txt", "lines:1-40", sha256=digest)   # overlapping reads, oldest first
    m.record("logs/a.txt", digest, size, "text", "lines:1-40", tokens=120, agent=readmap.agent_id())
    m.save()
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import env

__all__ = ["SCHEMA", "MAP_PATH", "SWEEP_PATH", "LOCK_SUFFIX", "ReadMapError", "FileRead", "FileEntry",
           "ReadMap", "agent_id", "overlaps"]

SCHEMA = 1
MAP_PATH = "recon/readmap.json"          # under the challenge dir, beside intake's recon output
SWEEP_PATH = "unpacked/.sweep.json"      # the sweep's scratch manifest for a pulled challenge
LOCK_SUFFIX = ".lock"                    # recon/readmap.json.lock: held (flock) while a save merges


class ReadMapError(RuntimeError):
    """The map or the sweep manifest it seeds from is present but cannot be read or has a wrong schema."""


def agent_id(*, environ=None) -> str:
    """Who is reading, for the map. `$CTF_AGENT` when set, else "agent". Never a home path or a pid, so
    the value is stable across a worker's reads and comparable between agents."""
    return env.get("CTF_AGENT", "agent", environ=environ) or "agent"


@dataclass
class FileRead:
    """One agent's one read of a file: which agent, when, what selector, the estimated token cost, and
    the sha256 of the content it read ("" when unknown)."""
    agent: str
    at: float
    selector: str                         # "full" | "lines:A-B" | "grep:PATTERN" | "bytes:N"
    tokens: int
    sha256: str = ""

    def to_dict(self) -> dict:
        return {"agent": self.agent, "at": round(self.at, 3), "selector": self.selector, "tokens": self.tokens,
                "sha256": self.sha256}

    @classmethod
    def from_dict(cls, d: dict) -> "FileRead":
        return cls(agent=str(d["agent"]), at=float(d["at"]), selector=str(d["selector"]),
                   tokens=int(d.get("tokens", 0)), sha256=str(d.get("sha256", "")))


@dataclass
class FileEntry:
    """A file known to the map: its path (challenge-dir relative), content hash, size, kind, its reads."""
    path: str
    sha256: str = ""
    size: int = 0
    kind: str = ""
    reads: list[FileRead] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"path": self.path, "sha256": self.sha256, "size": self.size, "kind": self.kind,
                "reads": [r.to_dict() for r in self.reads]}

    @classmethod
    def from_dict(cls, d: dict) -> "FileEntry":
        return cls(path=str(d["path"]), sha256=str(d.get("sha256", "")), size=int(d.get("size", 0)),
                   kind=str(d.get("kind", "")), reads=[FileRead.from_dict(r) for r in d.get("reads", [])])


def _read_key(r: FileRead) -> tuple:
    return (r.agent, round(r.at, 3), r.selector, r.sha256)


_LINES = re.compile(r"lines:(\d+)-(\d+)")


def overlaps(earlier: str, now: str) -> bool:
    """Whether a read with selector `earlier` already showed some of what `now` asks for: the same
    selector; a "full" read against any line range (or the reverse); two line ranges that share a line;
    or two byte previews (both start at offset 0). A grep is only the same read as the same grep."""
    if earlier == now:
        return True
    a, b = _LINES.fullmatch(earlier), _LINES.fullmatch(now)
    if a and b:
        return int(a.group(1)) <= int(b.group(2)) and int(b.group(1)) <= int(a.group(2))
    if (earlier == "full" and b) or (now == "full" and a):
        return True
    return earlier.startswith("bytes:") and now.startswith("bytes:")


@dataclass
class ReadMap:
    """The challenge's shared read map, in memory. `open` loads and seeds it; `save` merges it back."""
    file: Path
    entries: dict[str, FileEntry] = field(default_factory=dict)

    # -------------------------------------------------------------- loading and seeding

    @classmethod
    def load(cls, challenge_dir) -> "ReadMap":
        """Load `<challenge_dir>/recon/readmap.json` if it exists, else an empty map. A present file with
        a wrong schema or malformed JSON is a ReadMapError, never silently discarded."""
        d = Path(challenge_dir)
        f = d / MAP_PATH
        m = cls(file=f)
        if f.exists():
            m.entries = _parse_map(f)
        return m

    @classmethod
    def open(cls, challenge_dir, *, seed: bool = True) -> "ReadMap":
        """Load the map and, when `seed`, add every file of the sweep manifest it does not hold yet, so a
        file intake already hashed is known before anyone reads it (also when a read came first)."""
        m = cls.load(challenge_dir)
        if seed:
            m.seed_from_sweep(challenge_dir)
        return m

    def seed_from_sweep(self, challenge_dir) -> int:
        """Add an entry for every file in `<challenge_dir>/unpacked/.sweep.json` that is not already in
        the map: an original under its own path (`<sources>/<name>`, e.g. `files/a.txt`), a member under
        its scratch path. Returns how many were added. No sweep file: nothing added (not an error). A
        present but unreadable sweep: ReadMapError."""
        f = Path(challenge_dir) / SWEEP_PATH
        if not f.exists():
            return 0
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ReadMapError(f"{f}: unreadable sweep manifest: {e}") from e
        if not isinstance(data, dict) or "manifest" not in data:
            raise ReadMapError(f"{f}: not a sweep manifest (no 'manifest')")
        sources = str(data.get("sources") or ".").strip("/")
        added = 0
        for ent in data.get("manifest", []):
            if not isinstance(ent, dict):
                raise ReadMapError(f"{f}: a manifest entry is not an object")
            if ent.get("original"):
                name = str(ent.get("chain") or "")
                path = name if sources in ("", ".") or not name else f"{sources}/{name}"
            else:
                path = ent.get("path")
            if not path or path in self.entries:
                continue
            self.entries[path] = FileEntry(path=path, sha256=str(ent.get("sha256", "")),
                                           size=int(ent.get("size", 0)), kind=str(ent.get("kind", "")))
            added += 1
        return added

    # -------------------------------------------------------------- queries

    def lookup(self, path: str) -> FileEntry | None:
        return self.entries.get(path)

    def prior_reads(self, path: str, selector: str, *, exclude_agent: str | None = None,
                    sha256: str | None = None) -> list[FileRead]:
        """Every recorded read that already showed some of what `selector` asks for (`overlaps`), oldest
        first, optionally excluding one agent's own reads. Without `sha256`, only reads of `path`. With
        `sha256` (the content about to be read), reads of `path` and of any other entry holding the same
        bytes (a scratch copy, an unpacked member) count, and a read whose recorded content hash differs
        (the file changed since) does not. A non-empty result means this read was already paid for."""
        if sha256:
            ents = [e for p, e in self.entries.items() if p == path or e.sha256 == sha256]
        else:
            ent = self.entries.get(path)
            ents = [ent] if ent is not None else []
        out = []
        for e in ents:
            for r in e.reads:
                if r.agent == exclude_agent or not overlaps(r.selector, selector):
                    continue
                read_sha = r.sha256 or e.sha256
                if sha256 and read_sha and read_sha != sha256:
                    continue
                out.append(r)
        return sorted(out, key=lambda r: r.at)

    # -------------------------------------------------------------- recording

    def record(self, path: str, sha256: str, size: int, kind: str, selector: str, *, tokens: int,
               agent: str, at: float | None = None) -> FileRead:
        """Note that `agent` read `path` (content `sha256`) with `selector`. Creates the file entry if
        new; the entry's hash and size become this read's (the file as last seen), and a blank kind is
        filled in. Returns the FileRead it appended."""
        ent = self.entries.get(path)
        if ent is None:
            ent = FileEntry(path=path)
            self.entries[path] = ent
        if sha256:
            ent.sha256, ent.size = sha256, size
        ent.kind = ent.kind or kind
        r = FileRead(agent=agent, at=time.time() if at is None else at, selector=selector, tokens=tokens,
                     sha256=sha256)
        ent.reads.append(r)
        return r

    # -------------------------------------------------------------- saving

    def to_dict(self) -> dict:
        return {"schema": SCHEMA, "entries": [e.to_dict() for e in self.entries.values()]}

    def save(self) -> None:
        """Merge this map into whatever is on disk and write it atomically. Holds an exclusive flock on
        `<map>.lock` across the re-read, the merge and the replace, so two agents saving at once are
        serialised and neither's records are lost; the merge unions entries and reads."""
        self.file.parent.mkdir(parents=True, exist_ok=True)
        lock = self.file.with_name(self.file.name + LOCK_SUFFIX)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            current = _parse_map(self.file) if self.file.exists() else {}
            merged = _merge(current, self.entries)
            tmp = self.file.with_name(f"{self.file.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            payload = {"schema": SCHEMA, "entries": [e.to_dict() for e in merged.values()]}
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.file)
        finally:
            os.close(fd)                     # closing the descriptor releases the lock
        self.entries = merged


def _parse_map(f: Path) -> dict[str, FileEntry]:
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ReadMapError(f"{f}: unreadable read map: {e}") from e
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ReadMapError(f"{f}: read map schema is not {SCHEMA}")
    out: dict[str, FileEntry] = {}
    for ent in data.get("entries", []):
        e = FileEntry.from_dict(ent)
        out[e.path] = e
    return out


def _newest(e: FileEntry) -> float:
    return max((r.at for r in e.reads), default=0.0)


def _merge(base: dict[str, FileEntry], extra: dict[str, FileEntry]) -> dict[str, FileEntry]:
    """Union `extra` (this process's map) into `base` (the map on disk). Reads are unioned; an entry's
    hash and size are the most recently read version's (a blank on disk is filled from `extra`)."""
    out = {p: FileEntry(e.path, e.sha256, e.size, e.kind, list(e.reads)) for p, e in base.items()}
    for path, e in extra.items():
        cur = out.get(path)
        if cur is None:
            out[path] = FileEntry(e.path, e.sha256, e.size, e.kind, list(e.reads))
            continue
        if e.sha256 and (not cur.sha256 or _newest(e) > _newest(cur)):
            cur.sha256, cur.size = e.sha256, e.size     # the file as most recently seen
        cur.size = cur.size or e.size
        cur.kind = cur.kind or e.kind
        seen = {_read_key(r) for r in cur.reads}
        for r in e.reads:
            if _read_key(r) not in seen:
                cur.reads.append(r)
                seen.add(_read_key(r))
    return out
