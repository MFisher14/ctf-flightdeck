"""Named agent sessions: a launcher never starts over a live one (B-175).

Play-day sessions started by a scheduler (launchd, cron, a loop) used to pile up: each run started a
new agent while yesterday's never exited. A launcher given `--session NAME` (or $CTF_SESSION) now
claims the name first, and refuses while the previous holder is still alive. "Alive" is decided by
exact identity, pid AND start time (ctf/procid.py), never by a pid alone: a pid that was reused by an
unrelated process does not keep a session claimed, and is never signalled.

    root = sessions_root()                       # $CTF_SESSIONS_DIR, else <workdir>/sessions
    c = claim(root, "playday", harness="claude", challenge="7")   # SessionLive when held
    set_agent(c, pid, own_group=True)            # the supervised agent's identity, once started
    release(c)                                   # on exit: removes the record if it is still ours
    list_sessions(root)                          # [SessionState]: live | stale
    peek(root, name)                             # SessionState | None, changes nothing
    stop(root, "playday")                        # TERM/KILL the agent, then the launcher, by identity
    reap_id(name, record)                        # "session:<name>@<launcher pid>-<start ms>"

One record per name, `<root>/<name>.json`:

    name, harness, challenge, owner, claimed_at,
    launcher_pid, launcher_start          the launcher process (for an exec'd agent, the agent itself)
    agent_pid, agent_start, agent_pgid    the supervised agent, once started (agent_pgid only when it
                                          leads its own process group)

`<root>/.<name>.lock` is flocked while a record is read and changed, so two launchers started at the
same moment cannot both claim one name. Stopping a session is the reaper's job (ctf/reaper.py,
`ctf reap`): the player confirms it by exact id. That id carries the claim's launcher identity
(`reap_id`), not the name alone: a name re-claimed by a new launcher after the dry run is a different
id, so confirming the old one can never stop the new holder.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import env as _env
from . import event as _event
from . import paths as _paths
from . import procid as _procid

SESSIONS_ENV = "CTF_SESSIONS_DIR"
SESSION_ENV = "CTF_SESSION"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

AGENT_GRACE = 5.0         # seconds between TERM and KILL of the agent
LAUNCHER_GRACE = 30.0     # seconds a supervising launcher gets to record agent_exit and reap jobs


class SessionError(RuntimeError):
    """A session operation failed with a named reason."""


class SessionLive(SessionError):
    """The name is held by a live session; `record` is its record, `holder` the live identity."""

    def __init__(self, name: str, record: dict, holder: str):
        self.name, self.record, self.holder = name, record, holder
        pid = record.get(f"{holder}_pid")
        since = record.get("claimed_at")
        age = f", claimed {time.time() - float(since):.0f}s ago" if isinstance(since, (int, float)) else ""
        super().__init__(
            f"session {name!r} is live: its {holder} pid {pid} (same start time as recorded) still "
            f"runs{age}. Refusing to start a second one over it. To end it, the player runs: "
            f"python -m ctf reap (then --confirm {reap_id(name, record)})")


@dataclass
class Claim:
    name: str
    path: Path
    record: dict
    replaced: dict | None = None     # the stale record this claim replaced, if any


@dataclass
class SessionState:
    name: str
    path: Path
    record: dict
    status: str              # live | stale
    launcher: str            # procid status of the launcher
    agent: str               # procid status of the agent, or "none"


def sessions_root(override: str | os.PathLike | None = None) -> Path:
    if override:
        return Path(override).expanduser().resolve()
    v = _env.get(SESSIONS_ENV)
    if v:
        return Path(v).expanduser().resolve()
    try:
        return _paths.workdir() / "sessions"
    except _event.EventError as e:
        raise SessionError(f"no sessions folder: pass --sessions-dir, or set {SESSIONS_ENV}, CTF_WORKDIR "
                           f"or CTF_EVENT ({e})") from None


def reap_id(name: str, record: dict) -> str:
    """The reaper's id for this claim of `name`: the name plus the launcher's exact identity (pid,
    and start time in milliseconds), e.g. ``session:playday@4242-1731400000123``. Two claims of one
    name by different launchers get different ids."""
    start = record.get("launcher_start")
    if isinstance(start, (int, float)) and not isinstance(start, bool):
        stamp = str(int(round(float(start) * 1000)))
    else:
        stamp = "nostart"
    return f"session:{name}@{record.get('launcher_pid')}-{stamp}"


def same_claim(a: dict | None, b: dict | None) -> bool:
    """True when both records name the same launcher by pid AND start time."""
    return (a is not None and b is not None and a.get("launcher_pid") == b.get("launcher_pid")
            and _procid.same_start(a.get("launcher_start"), b.get("launcher_start")))


def _has_start(rec: dict) -> bool:
    v = rec.get("launcher_start")
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def same_stale_record(a: dict | None, b: dict | None) -> bool:
    """For removing a STALE record only: same_claim, or both records lack a launcher start and name
    the same pid. claim() always records a start, so a real re-claim never matches a no-start
    record; a no-start record (hand-written, corrupt or an older format) can never be live, so
    removing it never stops anything. Never use this to decide what to signal."""
    if same_claim(a, b):
        return True
    return (a is not None and b is not None and a.get("launcher_pid") == b.get("launcher_pid")
            and not _has_start(a) and not _has_start(b))


def check_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise SessionError(f"bad session name {name!r} (letters, digits and _.- only, at most 64)")
    return name


def _record_path(root: Path, name: str) -> Path:
    return Path(root) / f"{check_name(name)}.json"


@contextmanager
def _locked(root: Path, name: str):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    with open(root / f".{check_name(name)}.lock", "a+") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _read(p: Path) -> dict | None:
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise SessionError(f"unreadable session record {p}: {e}") from None
    if not isinstance(data, dict):
        raise SessionError(f"session record {p} is not a JSON object")
    return data


def _write(p: Path, data: dict) -> None:
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    os.replace(tmp, p)


def _holders(rec: dict) -> tuple[str, str]:
    launcher = _procid.status(rec.get("launcher_pid"), rec.get("launcher_start"))
    if rec.get("agent_pid") is None:
        agent = "none"
    else:
        agent = _procid.status(rec.get("agent_pid"), rec.get("agent_start"))
    return launcher, agent


def _live_holder(rec: dict) -> str | None:
    launcher, agent = _holders(rec)
    if agent == "alive":
        return "agent"
    if launcher == "alive":
        return "launcher"
    return None


def claim(root: Path, name: str, *, harness: str, challenge: str | None = None,
          owner: str | None = None, pid: int | None = None) -> Claim:
    """Claim `name` for the launcher `pid` (default: this process). SessionLive while the previous
    holder's launcher or agent is alive by exact identity; a stale record is replaced (and returned
    in Claim.replaced so the launcher can say so)."""
    pid = os.getpid() if pid is None else pid
    try:
        me = _procid.identity(pid)
    except _procid.ProcIdError as e:
        raise SessionError(f"cannot claim session {name!r}: {e}") from None
    p = _record_path(root, name)
    with _locked(root, name):
        old = _read(p)
        if old is not None:
            holder = _live_holder(old)
            if holder is not None:
                raise SessionLive(name, old, holder)
        rec = {"name": name, "harness": harness, "challenge": challenge, "owner": owner,
               "claimed_at": time.time(), "launcher_pid": me["pid"], "launcher_start": me["start"]}
        _write(p, rec)
    return Claim(name=name, path=p, record=rec, replaced=old)


def _still_ours(c: Claim, rec: dict | None) -> bool:
    return (rec is not None and rec.get("launcher_pid") == c.record["launcher_pid"]
            and _procid.same_start(rec.get("launcher_start"), c.record["launcher_start"]))


def set_agent(c: Claim, pid: int, *, own_group: bool, owner: str | None = None) -> None:
    """Record the supervised agent's exact identity on the claim (SessionError if it is not ours)."""
    try:
        ident = _procid.identity(pid)
    except _procid.ProcIdError as e:
        raise SessionError(f"session {c.name!r}: agent {e}") from None
    root = c.path.parent
    with _locked(root, c.name):
        rec = _read(c.path)
        if not _still_ours(c, rec):
            raise SessionError(f"session {c.name!r} is no longer held by this launcher")
        rec.update(agent_pid=ident["pid"], agent_start=ident["start"],
                   agent_pgid=pid if own_group else None)
        if owner is not None:
            rec["owner"] = owner
        _write(c.path, rec)
        c.record = rec


def release(c: Claim | None) -> bool:
    """Remove the record if it still names this claim's launcher. True when removed."""
    if c is None:
        return False
    with _locked(c.path.parent, c.name):
        if not _still_ours(c, _read(c.path)):
            return False
        c.path.unlink()
        return True


def peek(root: Path, name: str) -> SessionState | None:
    """The session's state, or None when no record of that name exists. Changes nothing."""
    if _read(_record_path(root, name)) is None:
        return None
    return session_state(root, name)


def session_state(root: Path, name: str) -> SessionState:
    p = _record_path(root, name)
    rec = _read(p)
    if rec is None:
        raise SessionError(f"no session {name!r} in {root}")
    launcher, agent = _holders(rec)
    live = "alive" in (launcher, agent)
    return SessionState(name, p, rec, "live" if live else "stale", launcher, agent)


def list_sessions(root: Path) -> list[SessionState]:
    root = Path(root)
    if not root.is_dir():
        return []
    out = []
    for p in sorted(root.glob("*.json")):
        if p.name.startswith("."):
            continue
        name = p.stem
        if not _NAME_RE.match(name):
            continue
        out.append(session_state(root, name))
    return out


@dataclass
class Stopped:
    name: str
    agent: str        # stopped | not_running | none
    launcher: str     # stopped | exited | not_running | same_as_agent
    removed: bool


def stop(root: Path, name: str, *, agent_grace: float = AGENT_GRACE,
         launcher_grace: float = LAUNCHER_GRACE, timeout: float = 10.0,
         expect: dict | None = None) -> Stopped:
    """End a live session by exact identity: TERM (then KILL) the agent -- its whole group when it
    leads one -- then give a supervising launcher `launcher_grace` seconds to record agent_exit and
    reap the agent's jobs before it, too, is stopped. The record is removed once nothing in it is
    alive. Raises SessionError for an unknown name or when an identity no longer matches its group.

    `expect` (a record, or {launcher_pid, launcher_start}) is the claim the caller decided to stop:
    when the record now names another launcher (the name was re-claimed), SessionError and nothing
    is signalled."""
    st = session_state(root, name)
    rec = st.record
    if expect is not None and not same_claim(rec, expect):
        raise SessionError(
            f"session {name!r} is now held by another launcher (pid {rec.get('launcher_pid')}, not "
            f"{expect.get('launcher_pid')} as planned); nothing was signalled. Run the dry run again")
    lp, ls = rec.get("launcher_pid"), rec.get("launcher_start")
    ap, as_ = rec.get("agent_pid"), rec.get("agent_start")
    try:
        if ap is None:
            agent = "none"
        else:
            agent = _procid.terminate(ap, as_, pgid=rec.get("agent_pgid"), grace=agent_grace,
                                      timeout=timeout)
        if ap is not None and ap == lp and _procid.same_start(as_, ls):
            launcher = "same_as_agent"
        else:
            end = time.monotonic() + max(0.0, launcher_grace) if agent == "stopped" else 0.0
            while time.monotonic() < end and _procid.matches(lp, ls):
                time.sleep(0.1)
            if _procid.matches(lp, ls):
                launcher = _procid.terminate(lp, ls, grace=agent_grace, timeout=timeout)
            else:
                launcher = "exited" if agent == "stopped" else "not_running"
    except _procid.ProcIdError as e:
        raise SessionError(f"session {name!r}: {e}") from None
    removed = False
    with _locked(root, name):
        now = _read(st.path)
        if now is not None and now.get("launcher_pid") == lp and _live_holder(now) is None:
            st.path.unlink()
            removed = True
        elif now is None:
            removed = True        # the launcher released it on its way out
    return Stopped(name, agent, launcher, removed)
