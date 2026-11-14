"""B-037: warm standby agent pool.

A cold agent launch costs 11.5-24.6 s to the first tool; a warm agent that is already up and blocked on
a queue command wakes in a few seconds (dev/SPEED-STUDY.md 2.2, item 6). This module is that queue.
Warm agents are launched ahead of a wave and block on `ctf standby take`; when the no-model dispatcher
(B-004, ctf.dispatch) writes claims, each waiting agent is handed exactly one claim and its
machine-written handout. No model, no platform call, no network: it only reads the dispatch claims under
the workdir and writes small lease / presence files beside them.

Everything lives under ``<workdir>/dispatch/`` (the B-004 dispatch dir):

    claims/<id>.json     the claim (B-004 writes it; standby only reads it)
    leases/<id>.json     a lease: which warm agent owns this claim (standby writes it, exclusively)
    standby/<agent>.json a warm agent's presence record (waiting | assigned | left)

A claim is *available* when it has a claim file, its claim status is ``dispatched`` (a claim a later
lifecycle marks solved/gone is never handed out) and it has no live lease. ``take`` reads the handout of
the lowest-seq available claim first, then creates its lease with an atomic exclusive ``os.link`` of a
fully written temp file, so two agents can never win the same claim and no reader ever sees a
half-written lease.

A bad handout (missing, unreadable, or no handout path) is that one claim's problem, not the pool's:
``take`` leases nothing for it, records it once per take (a ``standby.bad_handout`` ledger row), skips it
and hands out the next available claim; the Assignment names what it skipped (``skipped``) and
``pool_status`` lists it (``bad_handouts``). If the wait ends with nothing handed out and bad claims were
seen, ``take`` raises StandbyError naming them (CLI exit 2), not a quiet StandbyTimeout. A corrupt claim
file or a claim with no integer ``seq`` still stops every take: the pool cannot be ordered.

Lease liveness. The process that runs ``ctf standby take`` exits as soon as it prints the handout, so its
pid says nothing about whether the warm agent is still working. A lease therefore names its owner's
liveness explicitly, one of:

    pid    the owner's pid (in-process ``take`` uses its own; the CLI only with ``--owner-pid``, the agent
           harness pid). Stale when that pid is gone and the lease is older than ``stale_after``.
    ttl    a heartbeat lease (CLI ``--ttl S``): stale when not renewed (``ctf standby renew``) within S s
           and no live pid holds it.
    none   (the CLI default) held until released: never auto-reclaimed. ``ctf standby release --force``
           is the operator's recovery for a crashed holder.

Reclaiming a stale lease, renewing and releasing all run under an exclusive ``flock`` on the claim's
``leases/<id>.json.lock`` and replace the lease file atomically, so two reclaimers of one stale lease
serialise and exactly one wins (the second re-reads a live lease and backs off).

Pools (B-212). ``take`` reads one *pool* of claims: ``dispatch`` (the default: the B-004 challenge claims
above) or ``helpers`` (the lane-helper claims the no-model helper watcher writes on a lane STOP,
``<workdir>/helpers/claims/<id>.json``, ``ctf.helpers``). ``take(..., lane=L)`` hands out only claims of
that lane. A warm agent's presence record names the pool and lane it waits on (``pool``, ``lane``, written
only when not the defaults), so the helper watcher can tell whether a warm helper is waiting for a lane.
Leases of both pools live in ``leases/`` (helper ids are ``helper-<lane>-<n>``, never a platform id).
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import briefdiscipline as _discipline
from . import dispatch as _dispatch
from . import ledger as _ledger
from . import paths as _paths

LEASES = "leases"
STANDBY = "standby"
TAKE_EVENT = "standby.take"
BAD_HANDOUT_EVENT = "standby.bad_handout"
RELEASE_EVENT = "standby.release"

# The claim status a warm agent may be handed (ctf.dispatch.Claim.status); any other status (a lifecycle
# that marks a claim solved or gone, B-015) takes it out of the pool.
DISPATCHED = "dispatched"

# `owner_pid` default for in-process callers: the calling process owns the lease.
OWN_PROCESS = "self"

# Presence states on a warm agent.
WAITING = "waiting"      # up and blocked on take, no claim yet
ASSIGNED = "assigned"    # took a claim and is working it
LEFT = "left"            # take ended (timeout or release) without holding a claim

DEFAULT_TIMEOUT = 540.0  # under the 10-minute tool wall, like tools/day_wait.py
MAX_TIMEOUT = 580.0
DEFAULT_POLL = 0.2
DEFAULT_STALE_AFTER = 120.0

# Claim pools a warm agent can block on (module docstring, B-212).
DISPATCH_POOL = "dispatch"
HELPERS_POOL = "helpers"
POOLS = (DISPATCH_POOL, HELPERS_POOL)

# B-118: how a warm agent is started (repo-relative): the Claude launcher with the standby prompt-cache
# TTL (1h), since the agent idles up to DEFAULT_TIMEOUT on take before its first real turn.
LAUNCH_ARGV = ("tools/claude_launch", "--standby")

# A warm agent name must name a file under standby/ ; keep it a plain token.
_SAFE_AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

class StandbyError(RuntimeError):
    """The warm pool cannot proceed: a bad agent name, an unreadable claim/lease, or a missing handout."""


class StandbyTimeout(StandbyError):
    """`take` waited the whole timeout and no claim became available."""


# --------------------------------------------------------------------------------------- layout

def leases_dir(workdir: Path | None = None) -> Path:
    return _dispatch.dispatch_dir(workdir) / LEASES


def lease_path(workdir: Path | None, challenge_id: str) -> Path:
    from . import watch as _watch
    return leases_dir(workdir) / f"{_watch.safe_id(str(challenge_id))}.json"


def standby_dir(workdir: Path | None = None) -> Path:
    return _dispatch.dispatch_dir(workdir) / STANDBY


def presence_path(workdir: Path | None, agent: str) -> Path:
    return standby_dir(workdir) / f"{safe_agent(agent)}.json"


def safe_agent(agent: str) -> str:
    """The agent name, validated to a plain filename token. A name that cannot safely name a file (empty,
    a path separator, `..`, a metacharacter) is a loud error, never silently rewritten."""
    name = str(agent)
    if not _SAFE_AGENT.fullmatch(name):
        raise StandbyError(
            f"bad agent name {agent!r}: use [A-Za-z0-9][A-Za-z0-9_.-]{{0,63}} (names a presence file)")
    return name


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp{os.getpid()}-{threading.get_ident()}")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _load_json(path: Path, what: str) -> dict:
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as e:
        raise StandbyError(f"{path}: unreadable {what} ({e})") from None
    if not isinstance(rec, dict):
        raise StandbyError(f"{path}: {what} is not a JSON object")
    return rec


# --------------------------------------------------------------------------------------- presence

def _presence_pid(pid: int | None | str) -> int | None:
    return os.getpid() if pid == OWN_PROCESS else pid  # type: ignore[return-value]


def register(workdir: Path | None, agent: str, *, status: str = WAITING,
             challenge_id: str | None = None, clock: Callable[[], float] = time.time,
             pid: int | None | str = OWN_PROCESS, pool: str = DISPATCH_POOL,
             lane: str | None = None) -> dict:
    """Write (or refresh) a warm agent's presence record and return it. Pure bookkeeping for `pool_status`;
    it never leases a claim. `pid` is the agent's liveness pid (OWN_PROCESS = this process; None when the
    agent named none, e.g. a CLI take without --owner-pid). `pool` / `lane` name what the agent waits on;
    they are written only when not the defaults (B-212)."""
    name = safe_agent(agent)
    rec = {"schema": 1, "agent": name, "status": status, "challenge_id": challenge_id,
           "pid": _presence_pid(pid), "updated_at": round(clock(), 3)}
    if pool != DISPATCH_POOL:
        rec["pool"] = _check_pool(pool)
    if lane is not None:
        rec["lane"] = str(lane)
    _write_atomic(presence_path(workdir, name), json.dumps(rec, indent=1) + "\n")
    return rec


def read_presence(workdir: Path | None = None) -> dict[str, dict]:
    """{agent: presence record} for every warm agent that has registered. A record that cannot be read is
    a loud error (StandbyError), never skipped."""
    d = standby_dir(workdir)
    out: dict[str, dict] = {}
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        try:
            rec = _load_json(p, "presence record")
        except FileNotFoundError:
            continue
        out[str(rec.get("agent") or p.stem)] = rec
    return out


# --------------------------------------------------------------------------------------- leases

def read_leases(workdir: Path | None = None) -> dict[str, dict]:
    """{challenge_id: lease record} for every lease on disk. An unreadable lease is a loud error."""
    d = leases_dir(workdir)
    out: dict[str, dict] = {}
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        try:
            rec = _load_json(p, "lease")
        except FileNotFoundError:
            continue
        cid = rec.get("challenge_id")
        if cid is None:
            raise StandbyError(f"{p}: lease names no challenge_id")
        out[str(cid)] = rec
    return out


def _resolve_owner_pid(owner_pid: int | None | str) -> int | None:
    """The pid a lease ties its liveness to. OWN_PROCESS -> this process; None -> no pid (the lease is held
    until released, or until its ttl lapses); an int must be a live process, since a lease owned by a dead
    pid would be reclaimable the moment it is written."""
    if owner_pid == OWN_PROCESS:
        return os.getpid()
    if owner_pid is None:
        return None
    if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
        raise StandbyError(f"owner pid must be a positive int, None or {OWN_PROCESS!r}, got {owner_pid!r}")
    if not _dispatch._pid_alive(owner_pid):
        raise StandbyError(f"owner pid {owner_pid} is not a live process (its lease would be reclaimable "
                           "at once); pass the warm agent harness's pid")
    return owner_pid


def _check_ttl(ttl: float | None) -> float | None:
    if ttl is None:
        return None
    try:
        t = float(ttl)
    except (TypeError, ValueError):
        raise StandbyError(f"ttl must be a number of seconds, got {ttl!r}") from None
    if not t > 0:
        raise StandbyError(f"ttl must be > 0, got {ttl!r}")
    return t


def _lease_time(lease: dict, key: str) -> float:
    v = lease.get(key)
    try:
        return float(v)
    except (TypeError, ValueError):
        raise StandbyError(
            f"lease on claim {lease.get('challenge_id')!r} has no usable {key} ({v!r})") from None


def _lease_is_stale(lease: dict, *, clock: Callable[[], float], stale_after: float) -> bool:
    """Whether another warm agent may reclaim this lease (see the module docstring):

    - a live owner pid always keeps it;
    - a ttl lease is stale once it has gone `ttl` seconds without a renewal;
    - a pid lease whose pid is gone is stale once older than `stale_after` (a recent lease is honoured even
      if the pid check is momentarily wrong);
    - a lease with neither pid nor ttl is held until released (never auto-reclaimed).

    A lease with an unusable timestamp or ttl is a loud error, never guessed at."""
    pid = lease.get("pid")
    if pid is not None and _dispatch._pid_alive(pid):
        return False
    if lease.get("ttl") is None and pid is None:
        return False
    last = _lease_time(lease, "renewed_at" if lease.get("renewed_at") is not None else "leased_at")
    if lease.get("ttl") is not None:
        return clock() - last >= _lease_time(lease, "ttl")
    return clock() - last >= stale_after


def _lease_mode(lease: dict) -> str:
    if lease.get("pid") is not None:
        return "pid"
    return "ttl" if lease.get("ttl") is not None else "held"


@contextmanager
def _lease_lock(path: Path):
    """An exclusive flock on `<lease>.lock`. Every lease mutation (create, reclaim, renew, release) runs
    under it, so two reclaimers of one stale lease serialise. The kernel drops the lock when its holder
    dies, so a crashed holder never wedges a claim. The lock file is left in place (unlinking a flock'd
    file is itself racy)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path.with_name(path.name + ".lock"), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _create_exclusive(path: Path, text: str) -> bool:
    """Create `path` with `text` only if it does not exist: write a temp file, then `os.link` it into place.
    The link is atomic and fails if the path exists, so exactly one creator wins and a reader never sees a
    half-written lease."""
    tmp = path.with_name(f"{path.name}.new{os.getpid()}-{threading.get_ident()}")
    tmp.write_text(text, encoding="utf-8")
    try:
        os.link(tmp, path)
        return True
    except FileExistsError:
        return False
    finally:
        tmp.unlink(missing_ok=True)


def try_lease(workdir: Path | None, challenge_id: str, agent: str, *,
              clock: Callable[[], float] = time.time,
              stale_after: float = DEFAULT_STALE_AFTER,
              owner_pid: int | None | str = OWN_PROCESS,
              ttl: float | None = None) -> dict | None:
    """Atomically lease one claim to `agent`, or return None if another agent already holds a live lease.

    Under the claim's lease lock: an exclusive create if there is no lease; otherwise re-read the lease and
    replace it only if it is stale (see `_lease_is_stale`). A live lease is left untouched. `owner_pid`
    and `ttl` set the new lease's liveness (module docstring)."""
    name = safe_agent(agent)
    pid = _resolve_owner_pid(owner_pid)
    ttl = _check_ttl(ttl)
    path = lease_path(workdir, challenge_id)
    with _lease_lock(path):
        now = round(clock(), 3)
        rec = {"schema": 1, "challenge_id": str(challenge_id), "agent": name, "pid": pid, "ttl": ttl,
               "leased_at": now, "renewed_at": now}
        payload = json.dumps(rec, indent=1) + "\n"
        if _create_exclusive(path, payload):
            return rec
        try:
            cur = _load_json(path, "lease")
        except FileNotFoundError:
            # Removed by something that does not take the lock; the exclusive create decides it.
            return rec if _create_exclusive(path, payload) else None
        if not _lease_is_stale(cur, clock=clock, stale_after=stale_after):
            return None
        _write_atomic(path, payload)
        return rec


def renew(workdir: Path | None, agent: str, challenge_id: str, *,
          clock: Callable[[], float] = time.time) -> dict | None:
    """Heartbeat a lease `agent` holds: stamp `renewed_at` now and return the lease, or None when `agent`
    does not hold it (never leased, released, or reclaimed after its ttl lapsed: stop working it)."""
    name = safe_agent(agent)
    path = lease_path(workdir, challenge_id)
    with _lease_lock(path):
        try:
            cur = _load_json(path, "lease")
        except FileNotFoundError:
            return None
        if str(cur.get("agent")) != name:
            return None
        cur["renewed_at"] = round(clock(), 3)
        _write_atomic(path, json.dumps(cur, indent=1) + "\n")
        return cur


def _unlease(workdir: Path | None, challenge_id: str, owner: str | None) -> dict | None:
    """Remove a claim's lease under its lock and return the removed record: only when `owner` holds it,
    or whoever holds it when `owner` is None. None when nothing was removed."""
    path = lease_path(workdir, challenge_id)
    with _lease_lock(path):
        try:
            cur = _load_json(path, "lease")
        except FileNotFoundError:
            return None
        if owner is not None and str(cur.get("agent")) != owner:
            return None
        path.unlink()
        return cur


def lease_is_stale(lease: dict, *, clock: Callable[[], float] = time.time,
                   stale_after: float = DEFAULT_STALE_AFTER) -> bool:
    """Public form of `_lease_is_stale`, for a sibling watcher (ctf.helpers) that checks a lease it read
    with `read_leases` before trying to reclaim it. Advisory only: `try_lease` re-checks under the lock."""
    return _lease_is_stale(lease, clock=clock, stale_after=stale_after)


def unlease(workdir: Path | None, challenge_id: str, owner: str | None) -> dict | None:
    """Public form of `_unlease`: remove a claim's lease under its lock, without touching presence or the
    ledger (the caller records what it did). Only when `owner` holds it, or whoever does when None."""
    return _unlease(workdir, challenge_id, owner)


def release(workdir: Path | None, agent: str, challenge_id: str, *,
            clock: Callable[[], float] = time.time, record: bool = True, force: bool = False) -> bool:
    """Give a leased claim back to the pool and return whether a lease was removed. Without `force` only
    the holder (`agent`) can release it, and its presence goes back to WAITING. With `force` (the operator
    recovering a crashed holder's never-expiring lease) `agent` names the operator: the lease is removed
    whoever holds it and the former holder is marked LEFT."""
    name = safe_agent(agent)
    cur = _unlease(workdir, challenge_id, None if force else name)
    if cur is None:
        return False
    holder = str(cur.get("agent"))
    if not force:
        register(workdir, name, status=WAITING, clock=clock, pid=cur.get("pid"))
    elif holder != name and _SAFE_AGENT.fullmatch(holder):
        register(workdir, holder, status=LEFT, clock=clock, pid=cur.get("pid"))
    if record:
        _ledger.append(RELEASE_EVENT, workdir=workdir, challenge_id=str(challenge_id), agent=name,
                       holder=holder, forced=bool(force))
    return True


# --------------------------------------------------------------------------------------- the queue

@dataclass(frozen=True)
class Assignment:
    """What one warm agent woke to: the claim record, its handout text and path, the lease, and how long
    the agent waited."""
    challenge_id: str
    lane: str
    claim: dict
    handout: str
    handout_path: str
    lease: dict
    waited: float
    skipped: tuple[tuple[str, str], ...] = ()   # (challenge_id, reason): bad-handout claims passed over


def _check_pool(pool: str) -> str:
    if pool not in POOLS:
        raise StandbyError(f"unknown claim pool {pool!r}: one of {', '.join(POOLS)}")
    return pool


def read_pool_claims(workdir: Path | None, pool: str = DISPATCH_POOL
                     ) -> tuple[dict[str, dict], list[tuple[Path, str]]]:
    """({id: claim record}, [(path, reason)] unreadable) for one claim pool (module docstring)."""
    if _check_pool(pool) == HELPERS_POOL:
        from . import helpers as _helpers          # local: helpers imports this module
        return _helpers.read_claims(workdir)
    return _dispatch.read_claims(workdir)


def _claim_seq(cid: str, rec: dict) -> int:
    seq = rec.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise StandbyError(f"claim {cid!r} has no integer seq ({seq!r}): cannot order it in the warm pool")
    return seq


def _available(workdir: Path | None, leases: dict[str, dict], *,
               clock: Callable[[], float], stale_after: float, pool: str = DISPATCH_POOL,
               lane: str | None = None) -> list[tuple[int, str, dict]]:
    """Dispatched claims with no live lease, as (seq, challenge_id, claim record), lowest seq first
    (earliest detected wins, then id for a stable order). A claim whose status is not `dispatched` (a
    lifecycle marked it solved or gone) is not handed out. A corrupt claim or a claim with no integer seq
    is a loud error. `pool` picks the claim pool; `lane` keeps only that lane's claims (B-212)."""
    claims, bad = read_pool_claims(workdir, pool)
    if bad:
        raise StandbyError("; ".join(r for _, r in bad))
    out: list[tuple[int, str, dict]] = []
    for cid, rec in claims.items():
        if rec.get("status", DISPATCHED) != DISPATCHED:
            continue
        if lane is not None and str(rec.get("lane") or "") != lane:
            continue
        lease = leases.get(cid)
        if lease is not None and not _lease_is_stale(lease, clock=clock, stale_after=stale_after):
            continue
        out.append((_claim_seq(str(cid), rec), str(cid), rec))
    out.sort(key=lambda t: (t[0], t[1]))
    return out


def _handout_text(claim: dict) -> tuple[str, str]:
    hp = claim.get("handout")
    if not hp:
        raise StandbyError(f"claim {claim.get('challenge_id')!r} names no handout path")
    p = Path(hp)
    try:
        return p.read_text(encoding="utf-8"), str(p)
    except FileNotFoundError:
        raise StandbyError(f"handout for claim {claim.get('challenge_id')!r} is missing: {p}") from None
    except OSError as e:
        raise StandbyError(f"handout for claim {claim.get('challenge_id')!r} unreadable: {e}") from None


def take(workdir: Path | None, agent: str, *, timeout: float = DEFAULT_TIMEOUT,
         poll: float = DEFAULT_POLL, stale_after: float = DEFAULT_STALE_AFTER,
         clock: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time,
         sleep: Callable[[float], None] = time.sleep, record: bool = True,
         owner_pid: int | None | str = OWN_PROCESS, ttl: float | None = None,
         pool: str = DISPATCH_POOL, lane: str | None = None) -> Assignment:
    """Block until a claim is available, lease exactly one to `agent`, and return it with its handout.

    The warm agent registers as WAITING, then every `poll` seconds (never sleeping past `timeout`) looks
    for the lowest-seq available claim, reads its handout and tries to lease it (a claim lost to another
    agent is skipped). A claim with a bad handout is skipped without a lease and recorded once (module
    docstring). On a win it marks itself ASSIGNED, records a `standby.take` ledger row and returns; if
    anything fails after the lease, the lease is dropped before the error propagates. If no claim is
    handed out within `timeout` seconds it marks itself LEFT and raises StandbyTimeout, or StandbyError
    naming the bad claims when it skipped any. `owner_pid` / `ttl` set the lease's liveness (module docstring; the CLI passes
    owner_pid=None unless told the harness pid). `clock` measures the timeout (monotonic); `wall` stamps
    records; both are injectable for tests. `pool` / `lane` choose which claims this agent may be handed
    (module docstring, B-212) and are recorded on its presence."""
    name = safe_agent(agent)
    _check_pool(pool)
    if timeout < 0:
        raise StandbyError(f"timeout must be >= 0, got {timeout}")
    if poll <= 0:
        raise StandbyError(f"poll must be > 0, got {poll}")
    pid = _resolve_owner_pid(owner_pid)
    ttl = _check_ttl(ttl)
    started = clock()
    where = {"pool": pool, "lane": lane}
    register(workdir, name, status=WAITING, clock=wall, pid=pid, **where)
    bad: dict[str, str] = {}   # claims skipped this take for a bad handout: id -> reason
    while True:
        leases = read_leases(workdir)
        for _seq, cid, claim in _available(workdir, leases, clock=wall, stale_after=stale_after, **where):
            try:
                handout, hp = _handout_text(claim)
            except StandbyError as e:
                if cid not in bad:
                    bad[cid] = str(e)
                    if record:
                        _ledger.append(BAD_HANDOUT_EVENT, workdir=workdir, challenge_id=cid, agent=name,
                                       reason=str(e))
                continue  # one bad claim never stops the pool: try the next available claim
            bad.pop(cid, None)  # its handout is back
            lease = try_lease(workdir, cid, name, clock=wall, stale_after=stale_after,
                              owner_pid=pid, ttl=ttl)
            if lease is None:
                continue  # another warm agent won this one; try the next available claim
            try:
                waited = round(clock() - started, 3)
                register(workdir, name, status=ASSIGNED, challenge_id=cid, clock=wall, pid=pid, **where)
                if record:
                    extra = {} if pool == DISPATCH_POOL else {"pool": pool}
                    _ledger.append(TAKE_EVENT, workdir=workdir, challenge_id=cid,
                                   lane=str(claim.get("lane") or ""), agent=name, waited=waited, **extra)
            except BaseException:
                _unlease(workdir, cid, name)  # never strand a claim on a failed hand-off
                raise
            return Assignment(challenge_id=cid, lane=str(claim.get("lane") or ""), claim=claim,
                              handout=handout, handout_path=hp, lease=lease, waited=waited,
                              skipped=tuple(sorted(bad.items())))
        elapsed = clock() - started
        if elapsed >= timeout:
            register(workdir, name, status=LEFT, clock=wall, pid=pid, **where)
            if bad:
                raise StandbyError(
                    f"warm agent {name!r} was handed nothing within {timeout:g}s: skipped {len(bad)} "
                    "claim(s) with a bad handout: " + "; ".join(bad[c] for c in sorted(bad)))
            raise StandbyTimeout(
                f"no claim became available for warm agent {name!r} within {timeout:g}s "
                f"(is `ctf dispatch run` writing claims?)")
        sleep(min(poll, timeout - elapsed))  # never sleep past the timeout, whatever `poll` is


# --------------------------------------------------------------------------------------- the pool

def pool_status(workdir: Path | None = None, *, clock: Callable[[], float] = time.time,
                stale_after: float = DEFAULT_STALE_AFTER) -> dict:
    """A snapshot of the warm pool: the claims and how many are available vs leased, each live lease (and
    which of them are held until released, with no pid or ttl), the available claims `take` would skip
    for a bad handout (`bad_handouts`), and every registered warm agent with its state. An agent with no recorded pid has `alive` None (unknown). Read-only."""
    claims, bad = _dispatch.read_claims(workdir)
    leases = read_leases(workdir)
    presence = read_presence(workdir)
    live = {cid: l for cid, l in leases.items()
            if not _lease_is_stale(l, clock=clock, stale_after=stale_after)}
    stale = [cid for cid in leases if cid not in live]
    available = [cid for cid, rec in claims.items()
                 if cid not in live and rec.get("status", DISPATCHED) == DISPATCHED]
    bad_handouts = []
    for cid in available:
        try:
            _handout_text(claims[cid])
        except StandbyError:
            bad_handouts.append(cid)
    agents = [{"agent": a, "status": r.get("status"), "challenge_id": r.get("challenge_id"),
               "pid": r.get("pid"),
               "alive": None if r.get("pid") is None else _dispatch._pid_alive(r.get("pid"))}
              for a, r in sorted(presence.items())]
    return {"claims": len(claims), "available": sorted(available), "leased": sorted(live),
            "held_until_release": sorted(c for c, l in live.items() if _lease_mode(l) == "held"),
            "bad_handouts": sorted(bad_handouts),
            "stale_leases": sorted(stale), "waiting": sum(1 for a in agents if a["status"] == WAITING),
            "assigned": sum(1 for a in agents if a["status"] == ASSIGNED), "agents": agents,
            "unreadable_claims": [str(p) for p, _ in bad]}


def plan(size: int, *, prefix: str = "standby", argv_prefix: tuple[str, ...] | None = None,
         timeout: float = DEFAULT_TIMEOUT, ttl: float | None = None) -> list[dict]:
    """The launch plan for a warm pool of `size` agents: for each, a canonical agent name, the exact
    argv it blocks on (`ctf standby take --agent <name>`, plus `--ttl S` when a heartbeat lease is
    wanted) and `launch`, the launcher argv that starts the agent (LAUNCH_ARGV, repo-relative: the fence
    options and `-- <claude args>` follow it); `--standby` gives it 1h prompt-cache writes so its warm
    prefix survives the wait on take (B-118, ctf/cache_ttl.py). Build work cannot launch real agents (no model, no network), so this hands the orchestrator
    the plan; launching the agents ~T-7 min is a human/orchestrator step. The names are stable
    (`<prefix>-01` ...), so re-running the plan addresses the same pool slots. Each row also carries
    `brief`: the command discipline (B-043, ctf.briefdiscipline) to put in that agent's launch prompt;
    the handout it wakes to carries the same rules."""
    if size <= 0:
        raise StandbyError(f"pool size must be > 0, got {size}")
    safe_agent(f"{prefix}-01")  # validate the prefix shapes a legal agent name
    ttl = _check_ttl(ttl)
    base = list(argv_prefix) if argv_prefix is not None else ["python", "-m", "ctf"]
    width = max(2, len(str(size)))
    out = []
    for i in range(1, size + 1):
        name = f"{prefix}-{i:0{width}d}"
        argv = base + ["standby", "take", "--agent", name, "--timeout", f"{timeout:g}"]
        if ttl is not None:
            argv += ["--ttl", f"{ttl:g}"]
        out.append({"agent": name, "argv": argv, "launch": list(LAUNCH_ARGV),
                    "brief": _discipline.rules_plain()})
    return out
