"""B-213: the build-time work registry, file claims, one owner per fold, and the idle-machine lock.

On Huntress build nights Claude armed a build without knowing Codex was working (an hour to fold and
re-gate), one solver file was reworked in five worktrees, two agents built the same solver, and parallel
builders collided on one box and one branch. This module is the shared record that stops it:

    reg = Registry(paths.workreg_state())
    reg.begin("item/B-213", harness="claude", branch="item/B-213", worktree=wt, rows=["B-213"],
              files=["ctf/workreg.py", "tests/test_workreg*.py"], folds=["csctf:fork:tools/unpack.py"])
        # before spawn: all or nothing. ClaimConflict names every clash (who holds it, which harness,
        # which branch, as which claim); nothing is written when there is one.
    reg.check(rows=[...], files=[...], folds=[...])   # the same test, read-only, for any planner
    reg.agents()                                       # who is working: harness, pid, branch, rows, claims
    reg.claim(agent, files=[...]) / reg.release(agent, files=[...]) / reg.heartbeat(agent) / reg.leave(agent)
    reg.leave_branch("item/B-213")                     # after a merge: every agent on that branch leaves

    with IdleLock(paths.workreg_state(), "gate run", mode=EXCLUSIVE, timeout=1800):
        ...   # a timing suite: no other timing suite, and no shared (heavy) holder, runs meanwhile

**Agents** are keyed by name; by convention the name is the agent's B-147 branch (`item/<id>`), and the
branch and worktree are recorded too (B-147 makes them; nothing here creates a worktree). A record holds
the harness (`claude`, `codex`, `human`, `other`), an optional pid and heartbeat ttl, the claimed backlog
rows, file claims and folds. Two live agents may not share a name, a branch or a worktree.

**Liveness.** A record is *stale* when its pid is gone, its ttl lapsed without a heartbeat, or its
worktree folder no longer exists; otherwise it is live (held until `leave`). A stale record's claims do
not conflict. Every mutation reaps stale records first (only registry entries are removed; each reap
is saved at once, even when the mutation then fails, and written to the history and returned). The
registry only observes: it never signals, stops or kills a process, and never touches a worktree or
branch.

**Claims.**

- `row`: a B-138 backlog row id. It must exist in the backlog (default `docs/backlog.jsonl`) and be open;
  a done row or an unknown id is a named error. One live owner per row.
- `file`: a repo-relative path pattern. `*` and `?` stay inside one path segment, `**` crosses segments,
  `**/` matches zero or more whole directories, a trailing `/` claims a whole directory (`d/` is `d/**`).
  Character classes and braces are refused. Two file claims conflict when some path matches both; the
  test is exact (a product of the two patterns' automata), so `ctf/*.py` and `ctf/*.md` do not clash
  while `ctf/**` and `ctf/gate/x.py` do.
- `fold`: `<event slug>:<promotion entry key>` (ctf.promote; e.g. `csctf:fork:tools/unpack.py`). The entry
  must exist in that event's promotion record and must not be decided `drop`. One live owner per fold.
  The master paths the fold lands at (its decision, else its proposal: `promote.decision_paths`) are
  held too: they conflict with another agent's file claims, and the other way round.

**State**, under `paths.workreg_state()` (the git common dir, shared by every worktree):

    registry.json   {"schema": 1, "agents": {name: record}}, replaced atomically under the flock
    registry.lock   the flock every mutation holds
    history.jsonl   one line per begin, claim, release, leave and reap (who, when, what)
    idle.lock       the idle-machine lock (flock: exclusive for a timing suite, shared for heavy work)
    idle/           holder-*.json and wanted-*.json records, so a waiter can name who it waits on

An unreadable registry is a named error, never reset. No network, no model, no ledger (this is
build-time state, not an event's).

**Idle-machine lock.** A timing suite (the regression gate `ctf gate run --idle-lock`, the adapt lane
gate `ctf adapt gate --idle-lock`, or any command under `ctf work idle-run`) takes it *exclusive*; heavy
work that only wants timing suites to wait for it takes it *shared*. While an exclusive taker waits it
leaves a `wanted` record, and new shared takers hold off, so a steady stream of heavy work cannot starve
a timing suite. `max_load` (load1 per CPU) optionally makes the taker wait until the host is that quiet.
The kernel drops a flock when its holder dies, so a crashed holder never wedges the lock; its holder
record is then reported as stale. A wait past `timeout` raises IdleLockTimeout naming the holders.
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

SCHEMA = 1
HARNESSES = ("claude", "codex", "human", "other")
KINDS = ("row", "file", "fold")
REGISTRY = "registry.json"
LOCK = "registry.lock"
HISTORY = "history.jsonl"
IDLE_LOCK = "idle.lock"
IDLE_DIR = "idle"
EXCLUSIVE = "exclusive"
SHARED = "shared"
IDLE_MODES = (EXCLUSIVE, SHARED)
DEFAULT_IDLE_POLL = 5.0

_GLOB_REFUSED = set("[]{}\\")


class WorkRegError(RuntimeError):
    """The registry cannot act: a bad name, claim, harness or state file. The message names it."""


@dataclass(frozen=True)
class Conflict:
    """One clash: `wanted` (of `kind`) is blocked by `held`, a claim of the live agent `owner`."""

    kind: str          # row | file | fold | branch | worktree
    wanted: str
    held: str
    owner: str
    harness: str
    branch: str

    def describe(self) -> str:
        how = "" if self.held == self.wanted else f" as {self.held!r}"
        return (f"{self.kind} {self.wanted!r} is held by {self.owner} "
                f"({self.harness}, branch {self.branch or '-'}){how}")

    def to_dict(self) -> dict:
        return {"kind": self.kind, "wanted": self.wanted, "held": self.held, "owner": self.owner,
                "harness": self.harness, "branch": self.branch}


class ClaimConflict(WorkRegError):
    """A claim (or a registration) clashes with a live agent's. `conflicts` names every clash."""

    def __init__(self, conflicts: Sequence[Conflict]):
        self.conflicts = tuple(conflicts)
        super().__init__("claim conflict: " + "; ".join(c.describe() for c in self.conflicts))


class IdleLockTimeout(WorkRegError):
    """The idle-machine lock was not obtained within the timeout; the message names who holds it."""


def _pid_alive(pid: Any) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ------------------------------------------------------------------------------------ path patterns

def normalize_pattern(pattern: str) -> str:
    """A file claim in canonical form: repo-relative posix, no `./`, a trailing `/` turned into `/**`.
    Refuses an empty, absolute or `..` pattern, a backslash, and character classes or braces."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise WorkRegError(f"bad file claim {pattern!r}: empty")
    p = pattern.strip()
    if bad := sorted(set(p) & _GLOB_REFUSED):
        raise WorkRegError(f"bad file claim {pattern!r}: {' '.join(bad)} not supported (use * ? ** and a "
                           f"trailing / for a directory)")
    if p.startswith("/"):
        raise WorkRegError(f"bad file claim {pattern!r}: must be relative to the repo root")
    while p.startswith("./"):
        p = p[2:]
    if p.endswith("/"):
        p += "**"
    parts = p.split("/")
    if any(s in ("", ".", "..") for s in parts):
        raise WorkRegError(f"bad file claim {pattern!r}: empty, '.' or '..' path segment")
    return p


_EPS, _LIT, _SEG, _ANY = 0, 1, 2, 3     # edge kinds: epsilon, one literal char, one non-/ char, one char


def _nfa(pat: str) -> tuple[list[list[tuple[int, str, int]]], int, set[str]]:
    """(edges per state, accept state, literal chars) for a normalized pattern."""
    states: list[list[tuple[int, str, int]]] = [[]]
    lits: set[str] = set()

    def new() -> int:
        states.append([])
        return len(states) - 1

    cur, i = 0, 0
    while i < len(pat):
        if pat.startswith("**/", i):
            loop, end = new(), new()
            states[cur] += [(_EPS, "", end), (_EPS, "", loop)]
            states[loop] += [(_ANY, "", loop), (_LIT, "/", end)]
            cur, i = end, i + 3
        elif pat.startswith("**", i):
            nxt = new()
            states[cur].append((_EPS, "", nxt))
            states[nxt].append((_ANY, "", nxt))
            cur, i = nxt, i + 2
        elif pat[i] == "*":
            nxt = new()
            states[cur].append((_EPS, "", nxt))
            states[nxt].append((_SEG, "", nxt))
            cur, i = nxt, i + 1
        elif pat[i] == "?":
            nxt = new()
            states[cur].append((_SEG, "", nxt))
            cur, i = nxt, i + 1
        else:
            nxt = new()
            states[cur].append((_LIT, pat[i], nxt))
            lits.add(pat[i])
            cur, i = nxt, i + 1
    return states, cur, lits


def _closure(states, start: Iterable[int]) -> frozenset[int]:
    seen = set(start)
    todo = list(seen)
    while todo:
        s = todo.pop()
        for kind, _c, t in states[s]:
            if kind == _EPS and t not in seen:
                seen.add(t)
                todo.append(t)
    return frozenset(seen)


def _step(states, cur: frozenset[int], ch: str) -> frozenset[int]:
    out = set()
    for s in cur:
        for kind, c, t in states[s]:
            if (kind == _LIT and c == ch) or (kind == _SEG and ch != "/") or kind == _ANY:
                out.add(t)
    return _closure(states, out)


def patterns_overlap(a: str, b: str) -> bool:
    """True when some path matches both file claims (each normalized first). Exact: a breadth-first walk
    of the two patterns' automata in step, over their literal characters, `/` and one stand-in for every
    other character."""
    na, aa, la = _nfa(normalize_pattern(a))
    nb, ab, lb = _nfa(normalize_pattern(b))
    alphabet = sorted(la | lb | {"/", "\x00"})
    start = (_closure(na, [0]), _closure(nb, [0]))
    seen = {start}
    todo = [start]
    while todo:
        sa, sb = todo.pop()
        if aa in sa and ab in sb:
            return True
        for ch in alphabet:
            nxt = (_step(na, sa, ch), _step(nb, sb, ch))
            if nxt[0] and nxt[1] and nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    return False


def pattern_matches(pattern: str, path: str) -> bool:
    """True when the file claim `pattern` covers the concrete repo-relative `path`."""
    if any(ch in path for ch in "*?"):
        raise WorkRegError(f"{path!r} is a pattern, not a path")
    return patterns_overlap(pattern, path)


# ------------------------------------------------------------------------------------ validation

def _check_name(value: str, what: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(c in value for c in "\n\r\t") \
            or value != value.strip():
        raise WorkRegError(f"bad {what} {value!r}: a non-empty single-line name without surrounding spaces")
    return value


def _check_harness(harness: str) -> str:
    if harness not in HARNESSES:
        raise WorkRegError(f"harness {harness!r} is not one of {', '.join(HARNESSES)}")
    return harness


def _check_pid(pid: Any, pid_alive: Callable[[Any], bool]) -> int | None:
    if pid is None:
        return None
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise WorkRegError(f"pid must be a positive int or None, got {pid!r}")
    if not pid_alive(pid):
        raise WorkRegError(f"pid {pid} is not a live process (the record would be stale at once): pass the "
                           f"agent harness's pid, or none")
    return pid


def _check_ttl(ttl: Any) -> float | None:
    if ttl is None:
        return None
    if isinstance(ttl, bool):
        raise WorkRegError(f"ttl must be a number of seconds, got {ttl!r}")
    try:
        t = float(ttl)
    except (TypeError, ValueError):
        raise WorkRegError(f"ttl must be a number of seconds, got {ttl!r}") from None
    if not t > 0:
        raise WorkRegError(f"ttl must be > 0, got {ttl!r}")
    return t


def backlog_rows(path: str | Path | None = None) -> dict[str, Any]:
    """{row id: ctf.backlog.Row} from the B-138 backlog file (default: the master `docs/backlog.jsonl`).
    A missing or bad file is a named WorkRegError."""
    from . import backlog as _backlog
    p = Path(path) if path is not None else _backlog.default_path()
    try:
        return {r.id: r for r in _backlog.load(p)}
    except _backlog.BacklogError as e:
        raise WorkRegError(f"backlog for row claims: {e}") from None


def resolve_fold(fold: str, *, master: Path | None = None) -> tuple[str, list[str]]:
    """Validate a fold claim `<slug>:<source>:<path>` (or `<slug>:<path>` when the path names one entry)
    against the event's promotion record (ctf.promote) and return (the canonical claim
    `<slug>:<entry key>`, the master paths it lands at: its decision's, else its proposal's; may be
    empty). A fold with no record, no such entry, or a `drop` decision is a named WorkRegError."""
    from . import promote as _promote
    slug, sep, key = str(fold).partition(":")
    if not sep or not slug or not key:
        raise WorkRegError(f"bad fold claim {fold!r}: use <event slug>:<source>:<path>, e.g. "
                           f"csctf:fork:tools/unpack.py")
    try:
        rec = _promote.load_record(slug, master=master)
        entry = _promote.find_entry(rec, key)
    except (_promote.PromoteError, ValueError) as e:
        raise WorkRegError(f"fold {fold!r}: {e}") from None
    d = entry.decision or entry.proposal or {}
    if d.get("action") == "drop":
        raise WorkRegError(f"fold {fold!r}: decided 'drop' ({d.get('reason', 'no reason')}): nothing to fold")
    try:
        dest = [normalize_pattern(p) for p in _promote.decision_paths(d)] if d.get("action") else []
    except KeyError as e:
        raise WorkRegError(f"fold {fold!r}: its {d.get('action')} decision lacks {e}") from None
    return f"{slug}:{entry.key}", dest


# ------------------------------------------------------------------------------------ registry

def _dedupe(xs: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(xs))


@dataclass(frozen=True)
class AgentView:
    name: str
    record: dict
    live: bool
    reason: str          # why it is stale ("" when live)

    def to_dict(self) -> dict:
        return {"agent": self.name, "live": self.live, "stale_reason": self.reason, **self.record}


class Registry:
    """The shared registry under `state` (normally `paths.workreg_state()`). `backlog` is the B-138 file
    row claims are checked against (default: `docs/backlog.jsonl` of this checkout); `master` is the
    checkout whose `events/<slug>/promotion.json` fold claims are checked against (default: this one).
    `clock` is wall time (heartbeats are compared across processes); `pid_alive` is injectable for tests."""

    def __init__(self, state: Path, *, backlog: str | Path | None = None, master: Path | None = None,
                 clock: Callable[[], float] = time.time, pid_alive: Callable[[Any], bool] = _pid_alive):
        self.dir = Path(state)
        self.backlog = backlog
        self.master = master
        self.clock = clock
        self.pid_alive = pid_alive

    # files ---------------------------------------------------------------------------------------
    @property
    def path(self) -> Path:
        return self.dir / REGISTRY

    @contextmanager
    def _locked(self) -> Iterator[dict]:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.dir / LOCK, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield self._read()
        finally:
            os.close(fd)

    def _read(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema": SCHEMA, "agents": {}}
        except (OSError, ValueError) as e:
            raise WorkRegError(f"{self.path}: unreadable work registry ({e}); fix or move it by hand") from None
        if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("agents"), dict):
            raise WorkRegError(f"{self.path}: not a schema-{SCHEMA} work registry; fix or move it by hand")
        return data

    def _write(self, data: dict) -> None:
        tmp = self.path.with_name(f".{REGISTRY}.{os.getpid()}-{threading.get_ident()}.tmp")
        try:
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)
        finally:
            tmp.unlink(missing_ok=True)

    def _log(self, event: str, agent: str, **fields) -> None:
        rec = {"ts": round(self.clock(), 3), "event": event, "agent": agent, **fields}
        with open(self.dir / HISTORY, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    # liveness ------------------------------------------------------------------------------------
    def stale_reason(self, rec: dict) -> str:
        """Why a record is stale, or "" when it is live (module docstring)."""
        pid = rec.get("pid")
        if pid is not None and not self.pid_alive(pid):
            return f"pid {pid} is gone"
        ttl = rec.get("ttl")
        if ttl is not None:
            idle = self.clock() - float(rec.get("heartbeat") or rec.get("started") or 0)
            if idle >= float(ttl):
                return f"no heartbeat for {idle:.0f}s (ttl {float(ttl):g}s)"
        wt = rec.get("worktree")
        if wt and not Path(wt).exists():
            return f"worktree {wt} is gone"
        return ""

    def _reap(self, data: dict) -> list[str]:
        """Remove stale records from `data` and save at once (under the caller's flock), then log each:
        a reap in the history is always a reap on disk, whatever the caller does or raises next."""
        gone = []
        for name in sorted(data["agents"]):
            why = self.stale_reason(data["agents"][name])
            if why:
                del data["agents"][name]
                gone.append((name, why))
        if gone:
            self._write(data)
            for name, why in gone:
                self._log("reap", name, reason=why)
        return [f"{name} ({why})" for name, why in gone]

    # claims --------------------------------------------------------------------------------------
    def _resolve(self, rows: Iterable[str], files: Iterable[str], folds: Iterable[str]) -> dict:
        rows, files, folds = _dedupe(rows), _dedupe(files), _dedupe(folds)
        if rows:
            known = backlog_rows(self.backlog)
            for r in rows:
                row = known.get(r)
                if row is None:
                    raise WorkRegError(f"row {r!r} is not in the backlog ({self.backlog or 'docs/backlog.jsonl'})")
                if row.terminal:
                    raise WorkRegError(f"row {r} is {row.status} (done): nothing to claim")
        files = _dedupe(normalize_pattern(f) for f in files)
        fold_recs, seen = [], set()
        for f in folds:
            key, dest = resolve_fold(_check_name(f, "fold claim"), master=self.master)
            if key not in seen:
                seen.add(key)
                fold_recs.append({"key": key, "paths": dest})
        return {"row": rows, "file": files, "fold": fold_recs}

    def _conflicts(self, data: dict, agent: str | None, want: dict, *, branch: str | None = None,
                   worktree: str | None = None) -> list[Conflict]:
        out: list[Conflict] = []
        want_fold_paths = [(f["key"], p) for f in want["fold"] for p in f["paths"]]
        for name in sorted(data["agents"]):
            if name == agent:
                continue
            rec = data["agents"][name]
            if self.stale_reason(rec):
                continue
            mk = lambda kind, w, h: Conflict(kind, w, h, name, rec.get("harness", ""), rec.get("branch", ""))  # noqa: E731
            claims = rec.get("claims", {})
            if branch and rec.get("branch") == branch:
                out.append(mk("branch", branch, branch))
            if worktree and rec.get("worktree") and _same_path(rec["worktree"], worktree):
                out.append(mk("worktree", worktree, rec["worktree"]))
            for r in want["row"]:
                if r in claims.get("row", []):
                    out.append(mk("row", r, r))
            held_fold_paths = [(f["key"], p) for f in claims.get("fold", []) for p in f.get("paths", [])]
            for f in want["fold"]:
                if f["key"] in [h["key"] for h in claims.get("fold", [])]:
                    out.append(mk("fold", f["key"], f["key"]))
            for w in want["file"]:
                for h in claims.get("file", []):
                    if patterns_overlap(w, h):
                        out.append(mk("file", w, h))
                for key, p in held_fold_paths:
                    if patterns_overlap(w, p):
                        out.append(mk("file", w, f"{p} (fold {key})"))
            for key, p in want_fold_paths:
                for h in claims.get("file", []):
                    if patterns_overlap(p, h):
                        out.append(mk("fold", f"{key} -> {p}", h))
                for hkey, hp in held_fold_paths:
                    if hkey != key and patterns_overlap(p, hp):
                        out.append(mk("fold", f"{key} -> {p}", f"{hp} (fold {hkey})"))
        return out

    # public --------------------------------------------------------------------------------------
    def check(self, agent: str | None = None, *, rows: Iterable[str] = (), files: Iterable[str] = (),
              folds: Iterable[str] = (), branch: str | None = None, worktree: str | None = None) -> list[Conflict]:
        """The conflicts these claims would meet, ignoring `agent`'s own; read-only. Validates the claims."""
        want = self._resolve(rows, files, folds)
        return self._conflicts(self._read(), agent, want, branch=branch,
                               worktree=None if worktree is None else str(worktree))

    def begin(self, agent: str, *, harness: str, branch: str = "", worktree: str | Path | None = None,
              pid: int | None = None, ttl: float | None = None, rows: Iterable[str] = (),
              files: Iterable[str] = (), folds: Iterable[str] = (), note: str = "") -> dict:
        """Register `agent` with its claims before it is spawned: all or nothing. Raises ClaimConflict
        naming every clash (another live agent's row, file, fold, branch or worktree), WorkRegError when
        `agent` is already registered and live or a claim is invalid. Returns the record (with `reaped`:
        the stale records removed on the way)."""
        _check_name(agent, "agent name")
        _check_harness(harness)
        if branch:
            _check_name(branch, "branch")
        pid = _check_pid(pid, self.pid_alive)
        ttl = _check_ttl(ttl)
        wt = str(Path(worktree).resolve()) if worktree else ""
        want = self._resolve(rows, files, folds)
        with self._locked() as data:
            reaped = self._reap(data)
            cur = data["agents"].get(agent)
            if cur is not None:
                raise WorkRegError(f"agent {agent} is already registered (branch {cur.get('branch') or '-'}, "
                                   f"{cur.get('harness')}): `claim` to add to it, or `leave` first")
            conflicts = self._conflicts(data, agent, want, branch=branch or None, worktree=wt or None)
            if conflicts:
                raise ClaimConflict(conflicts)
            now = round(self.clock(), 3)
            rec = {"harness": harness, "branch": branch, "worktree": wt, "pid": pid, "ttl": ttl,
                   "started": now, "heartbeat": now, "note": note, "claims": want}
            data["agents"][agent] = rec
            self._write(data)
            self._log("begin", agent, harness=harness, branch=branch, claims=_summary(want))
        return {"agent": agent, **rec, "reaped": reaped}

    def _live_record(self, data: dict, agent: str) -> dict:
        rec = data["agents"].get(agent)
        if rec is None:
            raise WorkRegError(f"agent {agent} is not registered (never began, left, or was reaped as stale)")
        return rec

    def claim(self, agent: str, *, rows: Iterable[str] = (), files: Iterable[str] = (),
              folds: Iterable[str] = ()) -> dict:
        """Add claims to a registered, live agent: all or nothing (ClaimConflict names every clash). An
        agent that has gone stale is reaped first, so claiming for it is a 'not registered' error."""
        want = self._resolve(rows, files, folds)
        with self._locked() as data:
            reaped = self._reap(data)
            rec = self._live_record(data, agent)
            conflicts = self._conflicts(data, agent, want)
            if conflicts:
                raise ClaimConflict(conflicts)
            c = rec.setdefault("claims", {"row": [], "file": [], "fold": []})
            c["row"] = _dedupe([*c.get("row", []), *want["row"]])
            c["file"] = _dedupe([*c.get("file", []), *want["file"]])
            have = {f["key"] for f in c.get("fold", [])}
            c["fold"] = [*c.get("fold", []), *[f for f in want["fold"] if f["key"] not in have]]
            self._write(data)
            self._log("claim", agent, claims=_summary(want))
        return {"agent": agent, **rec, "reaped": reaped}

    def release(self, agent: str, *, rows: Iterable[str] = (), files: Iterable[str] = (),
                folds: Iterable[str] = ()) -> dict:
        """Drop some of an agent's claims. A claim it does not hold is a named error (nothing changes)."""
        rows, folds = _dedupe(rows), _dedupe(folds)
        files = _dedupe(normalize_pattern(f) for f in files)
        with self._locked() as data:
            rec = self._live_record(data, agent)
            c = rec.get("claims", {})
            missing = ([f"row {r}" for r in rows if r not in c.get("row", [])]
                       + [f"file {f}" for f in files if f not in c.get("file", [])]
                       + [f"fold {f}" for f in folds if f not in [x["key"] for x in c.get("fold", [])]])
            if missing:
                raise WorkRegError(f"agent {agent} does not hold: {', '.join(missing)}")
            c["row"] = [r for r in c.get("row", []) if r not in rows]
            c["file"] = [f for f in c.get("file", []) if f not in files]
            c["fold"] = [f for f in c.get("fold", []) if f["key"] not in folds]
            self._write(data)
            self._log("release", agent, claims={"row": rows, "file": files, "fold": folds})
        return {"agent": agent, **rec}

    def heartbeat(self, agent: str) -> dict:
        """Stamp a registered agent's heartbeat now (keeps a ttl record live)."""
        with self._locked() as data:
            rec = self._live_record(data, agent)
            why = self.stale_reason(rec)
            if why:
                raise WorkRegError(f"agent {agent} is stale ({why}): `begin` again")
            rec["heartbeat"] = round(self.clock(), 3)
            self._write(data)
        return {"agent": agent, **rec}

    def leave(self, agent: str) -> dict:
        """Remove a registered agent and all its claims (it finished, or the operator frees a crashed
        holder's claims). Only the registry entry is removed; no process is touched."""
        with self._locked() as data:
            rec = self._live_record(data, agent)
            del data["agents"][agent]
            self._write(data)
            self._log("leave", agent, branch=rec.get("branch", ""))
        return {"agent": agent, **rec}

    def reap(self) -> list[str]:
        """Remove every stale record now; returns what was removed and why."""
        with self._locked() as data:
            return self._reap(data)

    def leave_branch(self, branch: str, *, why: str = "") -> list[str]:
        """Remove every agent registered on `branch`, live or stale (its work merged: `ctf integrate
        run` calls this for each merged branch). Returns their names; none is not an error. With no
        registry yet, nothing is created and [] is returned. No process is touched."""
        _check_name(branch, "branch")
        if not self.path.exists():
            return []
        with self._locked() as data:
            names = [n for n in sorted(data["agents"]) if data["agents"][n].get("branch") == branch]
            for n in names:
                del data["agents"][n]
            if names:
                self._write(data)
                for n in names:
                    self._log("leave", n, branch=branch, reason=why)
        return names

    def agents(self) -> list[AgentView]:
        """Every registered agent, live or stale (read-only: nothing is reaped)."""
        data = self._read()
        return [AgentView(n, data["agents"][n], not self.stale_reason(data["agents"][n]),
                          self.stale_reason(data["agents"][n])) for n in sorted(data["agents"])]

    def history(self) -> list[dict]:
        p = self.dir / HISTORY
        if not p.is_file():
            return []
        out = []
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError as e:
                    raise WorkRegError(f"{p}:{n}: unreadable history line ({e})") from None
        return out


def _summary(want: dict) -> dict:
    return {"row": list(want["row"]), "file": list(want["file"]), "fold": [f["key"] for f in want["fold"]]}


def _same_path(a: str, b: str) -> bool:
    try:
        return Path(a).resolve() == Path(b).resolve()
    except OSError:
        return a == b


# ------------------------------------------------------------------------------------ idle lock

class IdleLock:
    """The idle-machine lock (module docstring). Use as a context manager, or `acquire()`/`release()`.

    `timeout` None waits forever; 0 tries once. `clock`/`sleep` drive the wait (inject a step clock in
    tests); `max_load` with `load_fn`/`cpus` waits for load1/cpus <= max_load. `on_wait(reason)` is called
    before each sleep with why it is still waiting."""

    def __init__(self, state: Path, label: str, *, mode: str = EXCLUSIVE, agent: str = "",
                 timeout: float | None = None, poll: float = DEFAULT_IDLE_POLL,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 wall: Callable[[], float] = time.time, pid_alive: Callable[[Any], bool] = _pid_alive,
                 max_load: float | None = None, load_fn: Callable[[], float] | None = None,
                 cpus: int | None = None, on_wait: Callable[[str], None] | None = None):
        if mode not in IDLE_MODES:
            raise WorkRegError(f"idle lock mode {mode!r} is not one of {', '.join(IDLE_MODES)}")
        if not (isinstance(poll, (int, float)) and poll > 0):
            raise WorkRegError(f"poll must be > 0, got {poll!r}")
        if timeout is not None and not (isinstance(timeout, (int, float)) and timeout >= 0):
            raise WorkRegError(f"timeout must be >= 0 or None, got {timeout!r}")
        if max_load is not None and not (isinstance(max_load, (int, float)) and max_load > 0):
            raise WorkRegError(f"max_load must be > 0, got {max_load!r}")
        self.dir = Path(state)
        self.label = _check_name(label, "idle lock label")
        self.mode, self.agent, self.timeout, self.poll = mode, agent, timeout, poll
        self.clock, self.sleep, self.wall, self.pid_alive = clock, sleep, wall, pid_alive
        self.max_load = max_load
        self.load_fn = load_fn or (lambda: os.getloadavg()[0])
        self.cpus = max(1, int(cpus or os.cpu_count() or 1))
        self.on_wait = on_wait
        self._fd: int | None = None
        self._holder: Path | None = None
        self.waited = 0.0
        self.record: dict | None = None

    def _rec_path(self, kind: str) -> Path:
        return self.dir / IDLE_DIR / f"{kind}-{os.getpid()}-{threading.get_ident()}-{time.time_ns()}.json"

    def _write_rec(self, path: Path, rec: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name("." + path.name + ".tmp")
        tmp.write_text(json.dumps(rec, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)

    def acquire(self) -> dict:
        if self._fd is not None:
            raise WorkRegError("idle lock already held by this object")
        self.dir.mkdir(parents=True, exist_ok=True)
        start = self.clock()
        wanted = None
        base = {"pid": os.getpid(), "label": self.label, "mode": self.mode, "agent": self.agent}
        if self.mode == EXCLUSIVE:
            wanted = self._rec_path("wanted")
            self._write_rec(wanted, {**base, "since": round(self.wall(), 3)})
        try:
            while True:
                why = self._try()
                if why is None:
                    self.waited = self.clock() - start
                    return self.record  # type: ignore[return-value]
                if self.timeout is not None and self.clock() - start >= self.timeout:
                    raise IdleLockTimeout(f"idle-machine lock ({self.mode}) for {self.label!r} not obtained "
                                          f"within {self.timeout:g}s: {why}")
                if self.on_wait is not None:
                    self.on_wait(why)
                self.sleep(self.poll)
        finally:
            if wanted is not None:
                wanted.unlink(missing_ok=True)

    def _try(self) -> str | None:
        """Take the lock now and return None, or return why not."""
        if self.mode == SHARED:
            waiting = _records(self.dir, "wanted", self.pid_alive)[0]
            if waiting:
                return "a timing suite is waiting for it: " + "; ".join(describe_holder(r) for r in waiting)
        fd = os.open(self.dir / IDLE_LOCK, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if self.mode == EXCLUSIVE else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            holders = _records(self.dir, "holder", self.pid_alive)[0]
            return "held by " + ("; ".join(describe_holder(r) for r in holders) if holders else "an unrecorded holder")
        load = None
        if self.max_load is not None:
            load = float(self.load_fn()) / self.cpus
            if load > self.max_load:
                os.close(fd)
                return f"host load {load:.2f} per CPU is over {self.max_load:g}"
        self._fd = fd
        self._holder = self._rec_path("holder")
        self.record = {"pid": os.getpid(), "label": self.label, "mode": self.mode, "agent": self.agent,
                       "since": round(self.wall(), 3), "load_per_cpu": load}
        self._write_rec(self._holder, self.record)
        return None

    def release(self) -> None:
        if self._holder is not None:
            self._holder.unlink(missing_ok=True)
            self._holder = None
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "IdleLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()


def describe_holder(r: dict) -> str:
    agent = f" agent {r['agent']}" if r.get("agent") else ""
    return f"{r.get('label', '?')} ({r.get('mode', '?')}, pid {r.get('pid', '?')}{agent})"


def _records(state: Path, kind: str, pid_alive: Callable[[Any], bool]) -> tuple[list[dict], list[dict]]:
    """(live, stale) idle records of `kind` (holder | wanted). Stale = the pid is gone."""
    d = Path(state) / IDLE_DIR
    live, stale = [], []
    if not d.is_dir():
        return live, stale
    for p in sorted(d.glob(f"{kind}-*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as e:
            raise WorkRegError(f"{p}: unreadable idle-lock record ({e})") from None
        (live if pid_alive(rec.get("pid")) else stale).append(rec)
    return live, stale


def idle_status(state: Path, *, pid_alive: Callable[[Any], bool] = _pid_alive) -> dict:
    """The idle lock as it stands: `state` free | shared | exclusive (probed with a non-blocking flock,
    released at once), the live holders and waiters, and stale records (a holder that died: the kernel
    already dropped its lock)."""
    d = Path(state)
    lock = d / IDLE_LOCK
    st = "free"
    if lock.exists():
        fd = os.open(lock, os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    st = "shared"
                except BlockingIOError:
                    st = "exclusive"
        finally:
            os.close(fd)
    holders, stale_h = _records(d, "holder", pid_alive)
    waiting, stale_w = _records(d, "wanted", pid_alive)
    return {"state": st, "holders": holders, "waiting": waiting, "stale": stale_h + stale_w}


def idle_lock_for(root: Path | None, label: str, *, mode: str = EXCLUSIVE, timeout: float | None = None,
                  **kw) -> Callable[[], IdleLock]:
    """A factory for the idle lock of the checkout `root` (paths.workreg_state), for callers that take it
    once per run (the regression gate, each adapt lane gate)."""
    from . import paths as _paths
    state = _paths.workreg_state(root)
    return lambda: IdleLock(state, label, mode=mode, timeout=timeout, **kw)
