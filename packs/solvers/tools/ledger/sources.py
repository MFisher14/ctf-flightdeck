"""Find the session logs the usage ledger (B-193) reads: Claude Code projects and Codex rollouts whose
working folder is inside one of the given roots (the event workdir, plus any --root).

    logs = claude_logs(roots)            # [LogRef] under paths.claude_home()/projects
    logs, notes = codex_logs(roots)      # [LogRef] from the Codex thread DB and ~/.codex/sessions
    threads = thread_db(home)            # {thread id: Thread} from <codex home>/state_<n>.sqlite

Both homes are read-only: the thread DB is opened with sqlite `immutable=1` (no lock, no -shm/-wal
write), session logs are opened for reading only. The trade-off: a live Codex DB in WAL mode is read
without its uncheckpointed -wal pages, so a thread written only to the WAL so far has no DB row here (no
spawn edge, no DB model). Its rollout is still found by the sessions-folder scan (by session_meta cwd),
but a nested subagent among them falls back to cwd attribution. codex_logs() adds a note whenever a
non-empty -wal file sits beside the DB; re-run ingest once Codex has checkpointed (or exited). Nothing here reads message content: Claude project
folders are matched by name, a Codex rollout only by its first (session_meta) line's id, cwd and fork
parent, and thread DB rows only by the columns listed in THREAD_COLUMNS (never titles or first messages).

A log outside every root is never opened past that first line, so work in other folders on this machine
(customer work included) never enters the ledger. The per-response cwd check in tools/ledger/usage.py
is the second fence: a response whose cwd is outside every root is dropped even in a matched log.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from ctf import paths as _paths

THREAD_DB_RE = re.compile(r"^state_(\d+)\.sqlite$")
REQUIRED_COLUMNS = ("id", "rollout_path", "cwd")
OPTIONAL_COLUMNS = ("model", "source", "thread_source", "agent_role", "agent_nickname", "created_at",
                    "attached_thread_parent_id")
THREAD_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS
CODEX_LOG_DIRS = ("sessions", "archived_sessions")
_UUID_TAIL = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")


class SourceError(RuntimeError):
    """A session-log source cannot be read as asked (missing folder, unreadable or changed DB schema)."""


@dataclass(frozen=True)
class Thread:
    id: str
    rollout_path: str
    cwd: str
    model: str | None = None
    source: str | None = None
    thread_source: str | None = None
    agent_role: str | None = None
    agent_nickname: str | None = None
    created_at: int | None = None
    parent: str | None = None          # attached_thread_parent_id, else the thread_spawn_edges parent


@dataclass(frozen=True)
class LogRef:
    """One session log and who wrote it. `agent` is the Claude session / subagent id or the Codex
    thread id; `parent` the main session (Claude subagent) or the parent thread (Codex spawn/fork)."""
    path: Path
    harness: str
    agent: str
    parent: str | None = None
    kind: str = "main"                 # main | subagent | fork
    cwd: str | None = None             # the log's starting folder, when known before reading it
    model: str | None = None           # Codex: the thread DB's model, used when no turn_context names one


# ------------------------------------------------------------------ roots

def _forms(p: str | Path) -> set[str]:
    """The spellings a folder can appear under in a log: as written, and resolved (macOS /tmp ->
    /private/tmp, symlinked homes)."""
    raw = os.path.normpath(os.path.expanduser(str(p)))
    out = {raw}
    try:
        out.add(os.path.realpath(raw))
    except OSError:
        pass
    return out


def normalize_roots(roots) -> tuple[str, ...]:
    out: set[str] = set()
    for r in roots:
        if r is None or not str(r).strip():
            raise SourceError("an empty root was given")
        out |= _forms(r)
    if not out:
        raise SourceError("no roots: name the event workdir (and any --root) whose sessions to read")
    return tuple(sorted(out))


def inside(cwd: str | None, roots: tuple[str, ...]) -> bool:
    """Whether `cwd` is one of `roots` or below one (either spelling)."""
    if not cwd:
        return False
    for c in _forms(cwd):
        for r in roots:
            if c == r or c.startswith(r.rstrip(os.sep) + os.sep):
                return True
    return False


# ------------------------------------------------------------------ Claude Code

def claude_slug(folder: str) -> str:
    """Claude Code names a project folder after its cwd with every character outside [A-Za-z0-9]
    made '-'."""
    return re.sub(r"[^A-Za-z0-9]", "-", folder)


def claude_logs(roots, home: Path | None = None) -> list[LogRef]:
    """Session JSONLs of every Claude Code project whose folder is a root or below one. The project
    name match is a pre-filter (the name encoding is lossy); usage.py checks each response's cwd."""
    roots = normalize_roots(roots)
    home = Path(home) if home is not None else _paths.claude_home()
    projects = home / "projects"
    if not projects.is_dir():
        raise SourceError(f"no Claude Code projects folder at {projects} (set CLAUDE_CONFIG_DIR, or pass "
                          "--harness codex to read Codex only)")
    slugs = {claude_slug(r) for r in roots}
    out: list[LogRef] = []
    for d in sorted(projects.iterdir()):
        if not d.is_dir() or not any(d.name == s or d.name.startswith(s + "-") for s in slugs):
            continue
        # main sessions first, so a response a subagent log repeats stays with the main session
        for f in sorted(d.rglob("*.jsonl"), key=lambda f: (len(f.relative_to(d).parts), str(f))):
            out.append(claude_ref(f, d))
    return out


def claude_ref(path: Path, project_dir: Path | None = None) -> LogRef:
    """Who wrote a Claude log, from its place in the project folder: <proj>/<session>.jsonl is a main
    session; <proj>/<session>/subagents/<agent>.jsonl (or any deeper file) is a subagent of <session>."""
    path = Path(path)
    if project_dir is None:
        return LogRef(path, "claude", path.stem)
    rel = path.relative_to(project_dir).parts
    if len(rel) == 1:
        return LogRef(path, "claude", path.stem)
    return LogRef(path, "claude", path.stem, parent=rel[0], kind="subagent")


# ------------------------------------------------------------------ Codex

def thread_db_path(home: Path) -> Path | None:
    """The newest state_<n>.sqlite in the Codex home, or None."""
    best = None
    try:
        names = os.listdir(home)
    except FileNotFoundError:
        return None
    for name in names:
        m = THREAD_DB_RE.match(name)
        if m and (best is None or int(m.group(1)) > best[0]):
            best = (int(m.group(1)), home / name)
    return best[1] if best else None


def thread_db(home: Path | None = None) -> tuple[dict[str, Thread], Path | None]:
    """({thread id: Thread}, db path) from the Codex thread DB; ({}, None) when there is none.
    A DB that cannot be read, or lacks a required column, raises SourceError naming it."""
    home = Path(home) if home is not None else _paths.codex_home()
    db = thread_db_path(home)
    if db is None:
        return {}, None
    try:
        con = sqlite3.connect(f"{db.resolve().as_uri()}?immutable=1", uri=True)
    except sqlite3.Error as e:
        raise SourceError(f"cannot open the Codex thread DB {db}: {e}") from None
    try:
        have = {r[1] for r in con.execute("PRAGMA table_info(threads)")}
        if not have:
            raise SourceError(f"{db} has no threads table (Codex changed its state DB; update "
                              "tools/ledger/sources.py)")
        lacking = [c for c in REQUIRED_COLUMNS if c not in have]
        if lacking:
            raise SourceError(f"{db}: threads table lacks {', '.join(lacking)} (Codex changed its "
                              "state DB; update tools/ledger/sources.py)")
        cols = [c for c in THREAD_COLUMNS if c in have]
        edges: dict[str, str] = {}
        tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
        if "thread_spawn_edges" in tables:
            for parent, child in con.execute("select parent_thread_id, child_thread_id from thread_spawn_edges"):
                edges[child] = parent
        out: dict[str, Thread] = {}
        for row in con.execute(f"select {', '.join(cols)} from threads"):
            d = dict(zip(cols, row))
            parent = d.pop("attached_thread_parent_id", None) or edges.get(d["id"])
            out[d["id"]] = Thread(parent=parent, **d)
        return out, db
    except sqlite3.Error as e:
        raise SourceError(f"cannot read the Codex thread DB {db}: {e}") from None
    finally:
        con.close()


def rollout_meta(path: Path) -> dict:
    """The id, cwd and fork parent of a rollout from its first line (session_meta), or {}."""
    try:
        with open(path, "rb") as fh:
            first = fh.readline()
    except OSError:
        return {}
    try:
        d = json.loads(first)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(d, dict) or d.get("type") != "session_meta" or not isinstance(d.get("payload"), dict):
        return {}
    p = d["payload"]
    return {k: p.get(k) for k in ("id", "cwd", "forked_from_id", "thread_source", "source")
            if isinstance(p.get(k), str)}


def _thread_kind(t: Thread | None, meta: dict) -> str:
    src = (t.thread_source if t else None) or meta.get("thread_source") or ""
    if "subagent" in src or (t is not None and t.parent and not meta.get("forked_from_id")):
        return "subagent"
    if meta.get("forked_from_id"):
        return "fork"
    return "main"


def codex_logs(roots, home: Path | None = None) -> tuple[list[LogRef], list[str]]:
    """([LogRef], notes) for every Codex rollout whose thread ran in a root: threads from the thread
    DB by their cwd, then rollouts under sessions/ and archived_sessions/ the DB does not list, by
    their session_meta cwd. Notes name what could not be used (no DB, a DB row whose rollout is gone,
    a non-empty -wal beside the DB whose pages the immutable read does not see)."""
    roots = normalize_roots(roots)
    home = Path(home) if home is not None else _paths.codex_home()
    dirs = [home / d for d in CODEX_LOG_DIRS if (home / d).is_dir()]
    threads, db = thread_db(home)
    if not dirs and db is None:
        raise SourceError(f"no Codex sessions folder or thread DB under {home} (set CODEX_HOME, or pass "
                          "--harness claude to read Claude only)")
    notes: list[str] = []
    if db is None:
        notes.append(f"no Codex thread DB (state_<n>.sqlite) in {home}: threads found from rollouts "
                     "only; spawn parents unknown")
    else:
        wal = db.with_name(db.name + "-wal")
        if wal.is_file() and wal.stat().st_size > 0:
            notes.append(f"{wal} is not empty: the thread DB is read immutable, without its uncheckpointed "
                         "WAL, so threads only in the WAL lack DB spawn parents and models (their rollouts "
                         "are still found by cwd); re-run ingest after Codex checkpoints or exits")
    out: list[LogRef] = []
    listed: set[str] = set()
    for t in sorted(threads.values(), key=lambda t: (t.created_at or 0, t.id)):
        rp = Path(t.rollout_path)
        listed.add(os.path.realpath(rp))
        if not inside(t.cwd, roots):
            continue
        if not rp.is_file():
            notes.append(f"Codex thread {t.id} ran in a root but its rollout {rp} is gone: its usage "
                         "is not in the ledger")
            continue
        meta = rollout_meta(rp)
        out.append(LogRef(rp, "codex", t.id, parent=t.parent or meta.get("forked_from_id"),
                          kind=_thread_kind(t, meta), cwd=t.cwd, model=t.model))
    for d in dirs:
        for f in sorted(d.rglob("rollout-*.jsonl")):
            if os.path.realpath(f) in listed:
                continue
            meta = rollout_meta(f)
            if not inside(meta.get("cwd"), roots):
                continue
            m = _UUID_TAIL.search(f.stem)
            tid = meta.get("id") or (m.group(1) if m else f.stem)
            out.append(LogRef(f, "codex", tid, parent=meta.get("forked_from_id"),
                              kind=_thread_kind(None, meta), cwd=meta.get("cwd")))
    return out, notes
