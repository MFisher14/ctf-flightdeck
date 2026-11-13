"""The release latency path (B-185): pre-warmed connections, parallel list and start, phase timing
from the first request, status-only recovery of a non-idempotent start with a persisted pending
attempt and a provisioning alert, and the wire-floor table per mode.

    gate = get_adapter(profile)
    res = latency.open_release(gate, "web-day-28", anchor=release_ts, dest=folder)
    #   at anchor - lead_s: warm(gate, 2)      TCP (and TLS) connections opened, no request sent
    #   at anchor:          list || start       on those connections, in parallel
    #   then:               provisioning wait   status reads only, alert at 45 s, never a re-POST
    #   then:               download            every delivery; the "ready" mark
    #   every step a row of <workdir>/wire/phases.jsonl

Why (Huntress). The Mobile first-blood deficit of 2-3 s on Day 30 was not solver work: artifact to
ready took 89 ms, the rest was list, server, start, download and wire. Before Day 28 the phases were
not timed, so a loss could not be split into start and download. On Day 28 one web target stayed
preparing for 594.955 s while the old client sent 17 start POSTs and 121 status polls, re-POSTing
after status said "preparing". Speed-run floors were not known before ranked attempts.

What it does:

  warm         opens `connections` keep-alive connections of the adapter's session pool to the
               platform origin (urllib3 pool, the same pool requests will use), with no HTTP request:
               nothing is journaled or counted by the wire budget. Do it a few seconds before the
               release (an idle connection may be closed by the server after its keep-alive time).
  parallel     runs callables at once (threads), each a timed phase; an error is kept per call.
  StartGuard   a start POST is not idempotent: it is sent once, and every later question about the
               attempt is answered by status reads only. The pending attempt is persisted in
               <workdir>/wire/starts.json (every process of the event shares it): a second
               start() of a challenge whose start is posting, preparing or of unknown outcome sends
               no POST but one status read. A POST that raised (a timeout) leaves the outcome unknown
               and is resolved by status. A POST is re-sent only when status says no attempt exists
               and the last POST is older than post_grace_s (40 s: it may still be in flight or
               being handled), at most max_posts unanswered POSTs per attempt; past that StartRefused names the record to clear. await_ready
               polls status (1 s for the first 10 s, then 2 s, then 5 s) and raises the
               provisioning alert once per attempt, across processes, alert_after_s (default 45)
               after the first POST: one stderr line, a phases row, and the alert callback.
  open_release the whole path for one challenge (an untimed one: a Game Master Time Trial or
               Mastery start runs a clock, which only the opener starts; refused before any request).
  phases       PhaseLog writes a row per step: run, challenge, mode, phase, t0, t1, dur_s, rel_s
               (seconds since the release anchor), ok, error, pid. run_report() joins the rows of a
               run with the wire journal (requests, held_s, bytes) and names the phases it lacks
               rather than inventing them.
  floors       floor_table() gives per mode the best and median round trip of each op (wire
               journal) and of each phase (phases log), the opening floor (first request to ready),
               the submit floor and their sum: the wire floor of an attempt with zero solver time.
               A known record (first blood, Hall of Fame time) per mode is compared against it.

The sole-lane exemption from the minute hold is the wire's (ctf/platform/wire.py: sole_lane,
mark_lane_done). `python -m ctf latency ...` is the CLI (ctf/cli/latency.py).
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import fcntl
import json
import os
import re
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping

from .. import ledger as _ledger
from .. import paths
from . import wire as _wire
from .base import InstanceInfo, NotAllowed, NotSupported, PlatformError

GATE_EVENT = "adapt.gate"        # the ledger record a lane gate writes (ctf/adapt/regress.py)
GATE_GREEN = "yes"               # its green verdict (regress.YES)

PHASES_NAME = "phases.jsonl"
STARTS_NAME = "starts.json"
STARTS_LOCK = "starts.lock"
FLOORS_NAME = "floors.json"

DEFAULT_CONNECTIONS = 2          # list and start in parallel
DEFAULT_LEAD_S = 2.0             # warm this long before the anchor
DEFAULT_ALERT_AFTER_S = 45.0     # the provisioning alert (the spec's 30-60 s)
DEFAULT_MAX_POSTS = 2            # unanswered start POSTs per attempt: the first and one re-POST
DEFAULT_POST_GRACE_S = 40.0      # a POST of another process younger than this may still be in flight
DEFAULT_TIMEOUT_S = 600.0        # how long await_ready polls (Day 28: 594.955 s preparing)

STATE_OF = {"running": "ready", "starting": "preparing", "stopped": "absent", "unknown": "unknown"}
PENDING = frozenset({"posting", "preparing", "unknown"})
REQUEST_PHASES = ("list", "start", "status", "provision", "download", "detail", "submit")
TIMED_SUFFIXES = ("time_trial", "mastery")
_GM_LANE = re.compile(r"^([A-Za-z]+)-day-\d+", re.I)
_RECORD_RE = re.compile(r"^([^=\s]+)=([0-9]+(?:\.[0-9]+)?)$")


class LatencyError(PlatformError):
    """The latency path cannot do what it was asked (no pool to warm, an unusable workdir)."""


class StartRefused(LatencyError):
    """A start would be a re-POST past max_posts, or of an attempt whose state says not to."""


# ------------------------------------------------------------------------------------------ places

def workdir_of(gate: Any) -> Path:
    """The workdir the gate's wire journals into (the event's when no wire is installed)."""
    w = _wire.of(gate)
    if w is not None:
        return w.workdir
    return paths.workdir(gate.profile.slug)


def phases_path(workdir: Path) -> Path:
    return _wire.wire_dir(workdir) / PHASES_NAME


def _mkdir(workdir: Path) -> Path:
    d = _wire.wire_dir(workdir)
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise LatencyError(f"wire dir {d} is unusable ({e}); set CTF_WORKDIR to a writable folder") from e
    return d


def mode_of(kind: str | None, challenge: str | None) -> str:
    """The mode a challenge's timings are grouped by. Game Master: "<lane>/<mode>", the lane from the
    id ("mobile-day-04" -> mobile) and the mode its suffix (time_trial, mastery) or "base". Other
    kinds: the kind. No challenge (a list): "*"."""
    if not challenge:
        return "*"
    cid = str(challenge).split("#", 1)[0]
    if kind == "gamemaster":
        family, _, suffix = cid.partition("/")
        m = _GM_LANE.match(family)
        lane = m.group(1).lower() if m else family
        return f"{lane}/{suffix.strip('/').lower() or 'base'}"
    return kind or "-"


def is_timed(kind: str | None, challenge: str) -> bool:
    return kind == "gamemaster" and str(challenge).split("#", 1)[0].rstrip("/").lower().endswith(
        tuple("/" + s for s in TIMED_SUFFIXES))


# ------------------------------------------------------------------------------------------ phases

class PhaseLog:
    """Timed phases of one run (one opening of one challenge), appended to <workdir>/wire/phases.jsonl
    as they end. Times are epoch seconds (the wire journal's clock)."""

    def __init__(self, workdir: Path, *, challenge: str | None = None, run: str | None = None,
                 anchor: float | None = None, mode: str | None = None, kind: str | None = None,
                 clock: Callable[[], float] = time.time):
        self.workdir = Path(workdir)
        self.challenge = challenge
        self.run = run or uuid.uuid4().hex[:12]
        self.anchor = anchor
        self.mode = mode or mode_of(kind, challenge)
        self._clock = clock
        self.rows: list[dict] = []

    def _write(self, row: dict) -> dict:
        d = _mkdir(self.workdir)
        line = (json.dumps(row, sort_keys=True) + "\n").encode("utf-8")
        try:
            fd = os.open(d / PHASES_NAME, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
        except OSError as e:
            raise LatencyError(f"phases log {d / PHASES_NAME} cannot be written ({e})") from e
        self.rows.append(row)
        return row

    def _row(self, phase: str, t0: float, t1: float, ok: bool, error: str | None, extra: dict) -> dict:
        return {**extra, "run": self.run, "challenge": self.challenge, "mode": self.mode, "phase": phase,
                "t0": round(t0, 4), "t1": round(t1, 4), "dur_s": round(t1 - t0, 4),
                "rel_s": round(t0 - self.anchor, 4) if self.anchor is not None else None,
                "ok": ok, "error": error, "pid": os.getpid()}

    @contextlib.contextmanager
    def span(self, phase: str, **extra: Any) -> Iterator[dict]:
        """Time the block as `phase`. The yielded dict is extra fields for the row (bytes, state...).
        An exception is recorded (ok false, its class) and re-raised."""
        t0 = self._clock()
        try:
            yield extra
        except BaseException as e:
            self._write(self._row(phase, t0, self._clock(), False, type(e).__name__, extra))
            raise
        self._write(self._row(phase, t0, self._clock(), True, None, extra))

    def mark(self, phase: str, **extra: Any) -> dict:
        """A zero-length row (anchor, ready, provision_alert)."""
        t = self._clock()
        return self._write(self._row(phase, t, t, True, None, extra))


def read_phases(workdir: Path, *, since: float | None = None) -> tuple[list[dict], int]:
    """(rows, unreadable line count) of the phases log, oldest first; [] when there is none."""
    try:
        text = phases_path(workdir).read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], 0
    rows, bad = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(r, dict) or not isinstance(r.get("t0"), (int, float)) or not r.get("run"):
            bad += 1
            continue
        if since is None or r["t0"] >= since:
            rows.append(r)
    return rows, bad


# ------------------------------------------------------------------------------------------ warm

def _adapter(gate: Any) -> Any:
    return getattr(gate, "_adapter", gate)


def _session(adapter: Any) -> Any:
    s = getattr(adapter, "_s", None)
    inner = getattr(s, "_inner", s)       # a WireSession wraps the requests.Session
    import requests
    if not isinstance(inner, requests.Session):
        raise NotSupported(f"the {getattr(adapter, 'kind', '?')} adapter has no requests session to warm "
                           f"(got {type(inner).__name__})")
    return inner


def _origin(adapter: Any) -> str:
    url = getattr(adapter, "url", None) or getattr(adapter, "base_url", None)
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise NotSupported(f"the {getattr(adapter, 'kind', '?')} adapter names no http(s) platform URL")
    return url


POOL_API = ("_get_conn", "_put_conn", "pool")     # urllib3 2.x HTTPConnectionPool: what warm() uses


def _check_pool_api(pool: Any) -> None:
    """warm() takes and returns connections through urllib3's pool internals (no public call opens
    a connection without a request). A urllib3 that lacks them is named, never worked around."""
    import urllib3
    missing = [n for n in POOL_API if not hasattr(pool, n)]
    if not missing and not hasattr(pool.pool, "maxsize"):
        missing = ["pool.maxsize"]
    if missing:
        raise LatencyError(f"warm: the urllib3 {urllib3.__version__} connection pool "
                           f"({type(pool).__name__}) has no {', '.join(missing)}; warm() needs urllib3 2.x "
                           "pool internals (the urllib3 in the venv changed: re-check warm() against it)")


def warm(gate: Any, connections: int = DEFAULT_CONNECTIONS, *, phases: PhaseLog | None = None) -> int:
    """Open `connections` idle keep-alive connections to the platform in the adapter's session pool,
    without sending a request; the next requests (up to that many at once) reuse them. Returns the
    number of connections now idle in the pool. Raises NotSupported for an adapter with no requests
    session, LatencyError when the connect fails or the pool is too small to keep them."""
    if not isinstance(connections, int) or connections < 1:
        raise ValueError(f"connections must be an integer >= 1, got {connections!r}")
    adapter = _adapter(gate)
    s, url = _session(adapter), _origin(adapter)
    import requests
    import urllib3
    ad = s.get_adapter(url)
    settings = s.merge_environment_settings(url, {}, None, s.verify, s.cert)
    prep = requests.Request("GET", url).prepare()
    # the pool requests will use for this origin (no connection is made by getting it)
    pool = ad.get_connection_with_tls_context(prep, settings["verify"], proxies=settings["proxies"],
                                              cert=settings["cert"])
    _check_pool_api(pool)
    size = pool.pool.maxsize
    if isinstance(size, int) and size > 0 and connections > size:
        raise LatencyError(f"warm: {connections} connections asked, but the session pool keeps {size} "
                           "(mount an HTTPAdapter with a larger pool_maxsize)")
    ctx = phases.span("warm", connections=connections) if phases else contextlib.nullcontext({})
    with ctx:
        taken = []
        try:
            for _ in range(connections):
                conn = pool._get_conn()           # an idle connection, or a new unconnected one
                taken.append(conn)
                if getattr(conn, "sock", None) is None:
                    conn.connect()
        except (OSError, urllib3.exceptions.HTTPError) as e:
            for c in taken:
                with contextlib.suppress(Exception):
                    c.close()
                pool._put_conn(None)          # give the slot back empty
            raise LatencyError(f"warm: connect to {url} failed ({type(e).__name__}: {e})") from e
        for c in taken:
            pool._put_conn(c)
    return sum(1 for c in list(pool.pool.queue) if c is not None and getattr(c, "sock", None) is not None)


# ------------------------------------------------------------------------------------------ parallel

@dataclass
class Outcome:
    name: str
    value: Any = None
    error: BaseException | None = None
    t0: float = 0.0
    t1: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None


def parallel(calls: Mapping[str, Callable[[], Any]], *, phases: PhaseLog | None = None,
             clock: Callable[[], float] = time.time) -> dict[str, Outcome]:
    """Run every call at once (one thread each); {name: Outcome}. Each call is the phase `name`
    when `phases` is given. An exception is kept in its Outcome, never raised here."""
    if not calls:
        return {}

    def one(name: str, fn: Callable[[], Any]) -> Outcome:
        out = Outcome(name, t0=clock())
        try:
            if phases is not None:
                with phases.span(name):
                    out.value = fn()
            else:
                out.value = fn()
        except Exception as e:      # kept for the caller, never hidden
            out.error = e
        out.t1 = clock()
        return out

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(calls)) as ex:
        futs = {name: ex.submit(one, name, fn) for name, fn in calls.items()}
        return {name: f.result() for name, f in futs.items()}


# ------------------------------------------------------------------------------------------ starts

@dataclass
class StartOutcome:
    """What a start or a status read says about one attempt. state: ready | preparing | unknown |
    absent (status says no attempt). posted: this call sent a start POST."""
    challenge: str
    state: str
    info: InstanceInfo | None = None
    posted: bool = False
    posts: int = 0
    polls: int = 0
    waited_s: float = 0.0
    alerted: bool = False
    note: str = ""


def poll_interval(elapsed_s: float) -> float:
    """Seconds between two status reads while an attempt is preparing."""
    if elapsed_s < 10.0:
        return 1.0
    if elapsed_s < 30.0:
        return 2.0
    return 5.0


def _key(challenge: str) -> str:
    return str(challenge).split("#", 1)[0]


@contextlib.contextmanager
def _starts_locked(workdir: Path) -> Iterator[Path]:
    d = _mkdir(workdir)
    try:
        fd = os.open(d / STARTS_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as e:
        raise LatencyError(f"start lock {d / STARTS_LOCK} cannot be opened ({e})") from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield d / STARTS_NAME
    finally:
        os.close(fd)


def _load_starts(p: Path) -> dict:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (ValueError, OSError) as e:
        # never guess: a lost record could mean a re-POST of a preparing attempt
        raise LatencyError(f"start records {p} do not parse ({e}); fix or remove the file (every "
                           "pending start in it is then forgotten)") from e
    if not isinstance(data, dict):
        raise LatencyError(f"start records {p} are not a JSON object")
    return data


def _save_starts(p: Path, data: dict) -> None:
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True, indent=1)
        os.replace(tmp, p)
    except OSError as e:
        raise LatencyError(f"start records {p} cannot be written ({e})") from e


def pending_starts(workdir: Path) -> dict:
    """{challenge: record} of every start record in the workdir (any state)."""
    with _starts_locked(workdir) as p:
        return _load_starts(p)


def clear_start(workdir: Path, challenge: str) -> bool:
    """Forget the start record of `challenge` (the operator's: the next start() POSTs again).
    True when there was one."""
    with _starts_locked(workdir) as p:
        data = _load_starts(p)
        had = data.pop(_key(challenge), None) is not None
        if had:
            _save_starts(p, data)
    return had


class StartGuard:
    """Status-only recovery of non-idempotent starts (see the module docstring)."""

    def __init__(self, gate: Any, *, workdir: Path | None = None,
                 alert_after_s: float = DEFAULT_ALERT_AFTER_S, max_posts: int = DEFAULT_MAX_POSTS,
                 post_grace_s: float = DEFAULT_POST_GRACE_S, phases: PhaseLog | None = None,
                 alert: Callable[[StartOutcome], None] | None = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 err: Any = None):
        if alert_after_s <= 0:
            raise ValueError(f"alert_after_s must be > 0, got {alert_after_s!r}")
        if not isinstance(max_posts, int) or max_posts < 1:
            raise ValueError(f"max_posts must be an integer >= 1, got {max_posts!r}")
        self.gate = gate
        self.workdir = Path(workdir) if workdir is not None else workdir_of(gate)
        self.alert_after_s = float(alert_after_s)
        self.max_posts = max_posts
        self.post_grace_s = float(post_grace_s)
        self.phases = phases
        self._alert = alert
        self._clock, self._sleep = clock, sleep
        self._err = err

    @property
    def err(self):
        return self._err if self._err is not None else sys.stderr

    def record(self, challenge: str) -> dict | None:
        with _starts_locked(self.workdir) as p:
            return _load_starts(p).get(_key(challenge))

    def _out(self, cid: str, state: str, rec: Mapping, **kw: Any) -> StartOutcome:
        return StartOutcome(cid, state, posts=int(rec.get("posts", 0)), polls=int(rec.get("polls", 0)),
                            alerted=bool(rec.get("alerted")), **kw)

    # ------------------------------------------------------------------------------- start
    def start(self, challenge: str, *, post: Callable[[str], InstanceInfo] | None = None) -> StartOutcome:
        """One start: a POST when no start of this attempt is pending, else one status read.

        `post(cid) -> InstanceInfo` replaces gate.start_instance as the POST: the opener's timed
        clock start (B-231, ctf/platform/timedstart.py) passes it, and only with it is a timed id
        accepted. A post that raises NotAllowed (a refusal: nothing was created) leaves no record."""
        cid = _key(challenge)
        if post is None and is_timed(getattr(self.gate, "kind", None), cid):
            raise NotAllowed(f"start: {cid} is a timed id; its start runs a clock, and only the opener "
                             "starts a clock")
        send = post if post is not None else self.gate.start_instance
        with _starts_locked(self.workdir) as p:
            data = _load_starts(p)
            prev = data.get(cid)
            if prev and prev.get("state") in PENDING:
                pending = True
            else:
                pending = False
                if prev and int(prev.get("open_posts", 0)) >= self.max_posts:
                    raise StartRefused(
                        f"start: {cid} has had {prev['open_posts']} start POST(s) and status still says no "
                        f"attempt exists; max_posts {self.max_posts} reached, no POST sent. Read "
                        f"`ctf latency pending`, then `ctf latency pending --clear {cid}` to allow another")
                now = self._clock()
                open_posts = int(prev.get("open_posts", 0)) if prev else 0
                rec = {"challenge": cid, "state": "posting", "posts": int((prev or {}).get("posts", 0)) + 1,
                       "open_posts": open_posts + 1,
                       "first_post": (prev or {}).get("first_post") if open_posts else now,
                       "last_post": now, "polls": int((prev or {}).get("polls", 0)) if open_posts else 0,
                       "alerted": (prev or {}).get("alerted") if open_posts else None,
                       "pid": os.getpid(), "error": None}
                data[cid] = rec
                _save_starts(p, data)
        if pending:
            out = self.recover(cid)
            out.note = (f"a start of {cid} is pending ({prev.get('state')} since "
                        f"{prev.get('first_post') or prev.get('last_post')}); recovered by status, no POST")
            return out
        try:
            if self.phases is not None:
                with self.phases.span("start", post=rec["posts"]) as ex:
                    info = send(cid)
                    ex["state"] = info.state
            else:
                info = send(cid)
        except (NotAllowed, NotSupported):
            self._restore(cid, prev)
            raise
        except PlatformError as e:
            self._update(cid, state="unknown", error=str(e)[:200])
            print(f"ctf latency: the start POST of {cid} raised ({e}); its outcome is unknown: recovering "
                  "by status only, no re-POST", file=self.err)
            out = self.recover(cid)
            out.posted = True
            return out
        state = STATE_OF.get(info.state, "unknown")
        rec = self._update(cid, state=state, **self._ready_fields(state))
        return self._out(cid, state, rec, info=info, posted=True)

    def _ready_fields(self, state: str) -> dict:
        if state == "ready":
            return {"open_posts": 0, "ready_at": self._clock()}
        return {}

    def _restore(self, cid: str, prev: dict | None) -> None:
        with _starts_locked(self.workdir) as p:
            data = _load_starts(p)
            if prev is None:
                data.pop(cid, None)
            else:
                data[cid] = prev
            _save_starts(p, data)

    def _update(self, cid: str, **fields: Any) -> dict:
        with _starts_locked(self.workdir) as p:
            data = _load_starts(p)
            rec = dict(data.get(cid) or {"challenge": cid, "posts": 0, "open_posts": 0, "polls": 0})
            rec.update(fields)
            data[cid] = rec
            _save_starts(p, data)
        return rec

    # ------------------------------------------------------------------------------- status
    def recover(self, challenge: str) -> StartOutcome:
        """One status read; the start record follows what it says. A POST of another process still
        in flight (posting, younger than post_grace_s) keeps the record pending even when status does
        not show the attempt yet."""
        cid = _key(challenge)
        if self.phases is not None:
            with self.phases.span("status") as ex:
                info = self.gate.instance_status(cid)
                ex["state"] = info.state
        else:
            info = self.gate.instance_status(cid)
        state = STATE_OF.get(info.state, "unknown")
        now = self._clock()
        note = ""
        with _starts_locked(self.workdir) as p:
            data = _load_starts(p)
            rec = dict(data.get(cid) or {"challenge": cid, "posts": 0, "open_posts": 0, "polls": 0})
            rec["polls"] = int(rec.get("polls", 0)) + 1
            rec["last_poll"] = now
            if (state == "absent" and rec.get("state") in ("posting", "unknown")
                    and now - float(rec.get("last_post") or 0) < self.post_grace_s):
                # a POST in flight (another process's), or ours that raised and the server may still
                # be handling: status not showing the attempt yet is not proof that it does not exist
                state, note = "unknown", ("status shows no attempt yet, but a start POST was sent "
                                          f"{now - float(rec.get('last_post') or 0):.1f} s ago")
            else:
                rec["state"] = state
                rec.update(self._ready_fields(state))
            data[cid] = rec
            _save_starts(p, data)
        return self._out(cid, state, rec, info=info, note=note)

    def _maybe_alert(self, cid: str, out: StartOutcome, since: float) -> None:
        now = self._clock()
        with _starts_locked(self.workdir) as p:
            data = _load_starts(p)
            rec = data.get(cid) or {}
            first = float(rec.get("first_post") or since)
            if rec.get("alerted") or now - first < self.alert_after_s:
                return
            rec["alerted"] = now
            data[cid] = rec
            _save_starts(p, data)
        waited = now - first
        out.alerted = True
        print(f"ctf latency: PROVISIONING ALERT: {cid} is still {out.state} {waited:.0f} s after its first "
              f"start POST ({int(rec.get('posts', 0))} POST(s), {int(rec.get('polls', 0))} status read(s)); "
              "no start is re-POSTed while it prepares. Tell the player; the cause is the platform's "
              "until its logs say otherwise", file=self.err)
        if self.phases is not None:
            self.phases.mark("provision_alert", waited_s=round(waited, 3), state=out.state)
        if self._alert is not None:
            self._alert(out)

    def await_ready(self, challenge: str, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> StartOutcome:
        """Status reads until the attempt is ready or absent, or timeout_s passes (then the last
        outcome, still preparing/unknown, with a note). Never a POST."""
        cid = _key(challenge)
        t0 = self._clock()
        ctx = self.phases.span("provision") if self.phases is not None else contextlib.nullcontext({})
        with ctx as ex:
            while True:
                out = self.recover(cid)
                out.waited_s = round(self._clock() - t0, 3)
                if out.state in ("ready", "absent"):
                    break
                self._maybe_alert(cid, out, t0)
                elapsed = self._clock() - t0
                if elapsed >= timeout_s:
                    out.note = (f"still {out.state} after {elapsed:.0f} s of status reads (timeout "
                                f"{timeout_s:g} s); no start was re-POSTed")
                    break
                self._sleep(min(poll_interval(elapsed), max(timeout_s - elapsed, 0.001)))
            ex["state"] = out.state
            ex["polls"] = out.polls
        return out

    def ensure_ready(self, challenge: str, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> StartOutcome:
        """start(), then status reads until ready. A start is re-POSTed only when status says the
        attempt does not exist (StartRefused past max_posts)."""
        cid = _key(challenge)
        t0 = self._clock()
        out = self.start(cid)
        while True:
            if out.state == "ready":
                return out
            left = timeout_s - (self._clock() - t0)
            if out.state == "absent":
                if left <= 0:
                    out.note = "status says no attempt exists and the timeout has passed"
                    return out
                out = self.start(cid)          # status proved no attempt: the one case for a POST
                continue
            if left <= 0:
                return out
            out = self.await_ready(cid, timeout_s=left)
            if out.state not in ("ready", "absent"):
                return out


# ------------------------------------------------------------------------------------------ opening

@dataclass
class ReleaseOpen:
    challenge: str
    run: str
    listed: bool | None = None
    start: StartOutcome | None = None
    files: list[Path] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    phases: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and self.listed is not False and (self.start is None
                                                                 or self.start.state == "ready")


def open_release(gate: Any, challenge: str, *, anchor: float | None = None, lead_s: float = DEFAULT_LEAD_S,
                 connections: int = DEFAULT_CONNECTIONS, start: bool = True, dest: Path | None = None,
                 timeout_s: float = DEFAULT_TIMEOUT_S, alert_after_s: float = DEFAULT_ALERT_AFTER_S,
                 workdir: Path | None = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep, err: Any = None) -> ReleaseOpen:
    """The latency-first opening of one untimed challenge: warm at anchor - lead_s, then at the
    anchor list || start (list || detail with start=False), the provisioning wait by status, the
    download into `dest` (when given) and the ready mark; every step a phase row."""
    cid = _key(challenge)
    kind = getattr(gate, "kind", None)
    if start and is_timed(kind, cid):
        raise NotAllowed(f"open_release: {cid} is a timed id; its start runs a clock, and only the opener "
                         "starts a clock (pass start=False to read it)")
    wd = Path(workdir) if workdir is not None else workdir_of(gate)
    log = PhaseLog(wd, challenge=cid, anchor=anchor, kind=kind, clock=clock)
    res = ReleaseOpen(cid, log.run, phases=log.rows)
    if anchor is not None and clock() < anchor - lead_s:
        sleep(anchor - lead_s - clock())
    warm(gate, connections, phases=log)
    if anchor is not None and clock() < anchor:
        sleep(anchor - clock())
    log.mark("anchor" if anchor is not None else "go")
    guard = StartGuard(gate, workdir=wd, alert_after_s=alert_after_s, phases=None, clock=clock,
                       sleep=sleep, err=err)
    calls: dict[str, Callable[[], Any]] = {"list": gate.list_challenges}
    if start:
        calls["start"] = lambda: guard.start(cid)
    else:
        calls["detail"] = lambda: gate.get_challenge(cid)
    got = parallel(calls, phases=log, clock=clock)
    for name, o in got.items():
        if o.error is not None:
            res.errors[name] = f"{type(o.error).__name__}: {o.error}"
    if got["list"].ok:
        res.listed = any(getattr(c, "id", None) == cid for c in got["list"].value)
    if start and got["start"].ok:
        res.start = got["start"].value
        if res.start.state in ("preparing", "unknown"):
            guard.phases = log
            res.start = guard.await_ready(cid, timeout_s=timeout_s)
            guard.phases = None
        if res.start.state == "absent":
            res.errors["start"] = (f"status says no attempt of {cid} exists after the start "
                                   f"({res.start.posts} POST(s)); `ctf latency start {cid}` re-POSTs once")
    ready_to_read = not res.errors and (res.start is None or res.start.state == "ready")
    if dest is not None and ready_to_read:
        try:
            with log.span("download") as ex:
                res.files = list(gate.download_files(cid, Path(dest)))
                ex["files"] = len(res.files)
                ex["bytes"] = sum(p.stat().st_size for p in res.files)
        except PlatformError as e:
            res.errors["download"] = str(e)
    if ready_to_read and "download" not in res.errors:
        log.mark("ready")
    return res


# ------------------------------------------------------------------------- timed opener (B-252)

def latest_gate(workdir: Path, lane: str) -> dict | None:
    """The newest `adapt.gate` ledger record for `lane` (ctf/adapt/regress.record_gate), or None."""
    latest = None
    for r in _ledger.read(Path(workdir)):
        if r.get("event") == GATE_EVENT and r.get("lane") == lane:
            latest = r
    return latest


def gate_green(workdir: Path, lane: str) -> bool:
    """Whether the newest `adapt.gate` record for `lane` is green (verdict YES). The gate-green event
    the timed ladder starts off (B-252/B-036): the lane's regression gate passed its last run."""
    rec = latest_gate(workdir, lane)
    return bool(rec) and rec.get("verdict") == GATE_GREEN


@dataclass
class TimedOpen:
    """The warm opening of one timed mode (Time Trial, Mastery). `started` is set when the clock
    start was POSTed; `info` is its InstanceInfo (running with a deadline, or the state it reached).
    `action` is the chain action that opened it (start | retry) or, when nothing was started, the
    chain action that said not to (wait | stop | hold | done)."""
    challenge: str
    run: str
    mode: str
    action: str = "start"
    started: bool = False
    listed: bool | None = None
    info: InstanceInfo | None = None
    reason: str = ""
    files: list[Path] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    phases: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (self.started and not self.errors and self.info is not None
                and self.info.state == "running")


def _await_running(gate: Any, cid: str, log: PhaseLog, *, timeout_s: float,
                   clock: Callable[[], float], sleep: Callable[[float], None]) -> InstanceInfo:
    """Status reads (never a POST: the clock is already running) until the timed attempt is running
    or stopped, or timeout_s passes. A read-only provisioning wait."""
    t0 = clock()
    with log.span("provision") as ex:
        info = gate.instance_status(cid)
        while info.state not in ("running", "stopped"):
            elapsed = clock() - t0
            if elapsed >= timeout_s:
                break
            sleep(min(poll_interval(elapsed), max(timeout_s - elapsed, 0.001)))
            info = gate.instance_status(cid)
        ex["state"] = info.state
    return info


def open_timed(gate: Any, challenge: str, *, starter: Callable[[str], InstanceInfo] | None = None,
               anchor: float | None = None, lead_s: float = DEFAULT_LEAD_S,
               connections: int = DEFAULT_CONNECTIONS, dest: Path | None = None,
               timeout_s: float = DEFAULT_TIMEOUT_S, action: str = "start", list_poll: bool = True,
               workdir: Path | None = None, clock: Callable[[], float] = time.time,
               sleep: Callable[[float], None] = time.sleep, err: Any = None) -> TimedOpen:
    """The latency-first opening of one timed mode: warm at anchor - lead, then at the anchor the
    clock start (through `starter`) in parallel with a list poll (poll-to-detect the mode is live),
    a read-only provisioning wait if it is still starting, the download into `dest` (when given) and
    the ready mark; every step a PhaseLog row for the timed mode, so floor_table gets its opening.

    A timed start runs a clock and is not idempotent: it is POSTed exactly once, never recovered by a
    re-POST (unlike StartGuard's untimed starts). `starter(cid) -> InstanceInfo` is the clock-start
    call; it defaults to B-231's no-model route (ctf/platform/timedstart.py: the start goes through
    StartGuard's start record; a refused body reads op=openapi once and retries once with the body it
    lists, run_for_time:true; the pool fields are checked with halloffame). A start refused for good
    is an error of the opening (errors["start"]), never a body ladder here. No submit is sent:
    open_timed never touches a submit barrier."""
    cid = _key(challenge)
    kind = getattr(gate, "kind", None)
    if not is_timed(kind, cid):
        raise NotAllowed(f"open_timed: {cid} is not a timed id (.../time_trial, .../mastery); an "
                         "untimed start goes through open_release (it starts no clock)")
    wd = Path(workdir) if workdir is not None else workdir_of(gate)
    if starter is None:
        from . import timedstart        # local: timedstart imports this module
        starter = timedstart.router(gate, workdir=wd, err=err)
    log = PhaseLog(wd, challenge=cid, anchor=anchor, kind=kind, clock=clock)
    res = TimedOpen(cid, log.run, log.mode, action=action, phases=log.rows)
    if anchor is not None and clock() < anchor - lead_s:
        sleep(anchor - lead_s - clock())
    warm(gate, connections, phases=log)
    if anchor is not None and clock() < anchor:
        sleep(anchor - clock())
    log.mark("anchor" if anchor is not None else "go")
    calls: dict[str, Callable[[], Any]] = {"start": lambda: starter(cid)}
    if list_poll:
        calls["list"] = gate.list_challenges
    got = parallel(calls, phases=log, clock=clock)
    for name, o in got.items():
        if o.error is not None:
            res.errors[name] = f"{type(o.error).__name__}: {o.error}"
    if list_poll and got["list"].ok:
        res.listed = any(getattr(c, "id", None) == cid for c in got["list"].value)
    if got["start"].ok:
        info = got["start"].value
        if not isinstance(info, InstanceInfo):
            res.errors["start"] = f"starter returned {type(info).__name__}, not an InstanceInfo"
        else:
            res.started, res.info = True, info
            if info.state == "starting":
                res.info = _await_running(gate, cid, log, timeout_s=timeout_s, clock=clock, sleep=sleep)
            if res.info.state == "stopped":
                res.errors["start"] = (f"the timed attempt of {cid} is stopped after the start "
                                       "(expired or never created); the clock did not run")
    ready = res.started and not res.errors and res.info is not None and res.info.state == "running"
    if dest is not None and ready:
        try:
            with log.span("download") as ex:
                res.files = list(gate.download_files(cid, Path(dest)))
                ex["files"] = len(res.files)
                ex["bytes"] = sum(p.stat().st_size for p in res.files)
        except PlatformError as e:
            res.errors["download"] = str(e)
    if ready and "download" not in res.errors:
        log.mark("ready")
    return res


def _chain_plan(base: str, lane: str, *, workdir: Path, root: Path | None):
    from ..adapt import chain
    return chain.plan(base, lane, workdir=workdir, root=root)


def ladder_on_green(gate: Any, base: str, lane: str, *, starter: Callable[[str], InstanceInfo] | None = None,
                    workdir: Path | None = None, root: Path | None = None, planner: Callable | None = None,
                    require_green: bool = True, anchor: float | None = None, lead_s: float = DEFAULT_LEAD_S,
                    connections: int = DEFAULT_CONNECTIONS, dest: Path | None = None,
                    timeout_s: float = DEFAULT_TIMEOUT_S, clock: Callable[[], float] = time.time,
                    sleep: Callable[[float], None] = time.sleep, err: Any = None) -> TimedOpen:
    """Start the next timed mode off a gate-green event (B-252, the executor B-036/B-044 defer to):
    when the lane's newest `adapt.gate` record is green and `chain.plan` says `start` (or `retry`),
    open that mode with open_timed; otherwise do nothing and report the chain's reason. `planner`
    (default `chain.plan`) is the seam the chain decision comes through. No submit barrier is moved:
    this only lists and starts."""
    wd = Path(workdir) if workdir is not None else workdir_of(gate)
    kind = getattr(gate, "kind", None)
    if require_green and not gate_green(wd, lane):
        rec = latest_gate(wd, lane)
        why = ("no adapt.gate record for the lane yet" if rec is None
               else f"the lane's latest adapt.gate is {rec.get('verdict')!r}, not green")
        return TimedOpen(base, "", mode_of(kind, None), action="hold", reason=f"not laddering: {why}")
    plan = planner if planner is not None else _chain_plan
    step = plan(base, lane, workdir=wd, root=root)
    if step.action in ("start", "retry") and step.challenge_id:
        return open_timed(gate, step.challenge_id, starter=starter, action=step.action, anchor=anchor,
                          lead_s=lead_s, connections=connections, dest=dest, timeout_s=timeout_s,
                          workdir=wd, clock=clock, sleep=sleep, err=err)
    return TimedOpen(step.challenge_id or base, "", mode_of(kind, step.challenge_id),
                     action=step.action, reason=step.reason)


# ------------------------------------------------------------------------------------------ reports

def _stats(values: Iterable[float]) -> dict:
    v = sorted(float(x) for x in values)
    if not v:
        return {"n": 0, "min": None, "p50": None}
    return {"n": len(v), "min": round(v[0], 4), "p50": round(statistics.median(v), 4)}


def run_report(phase_rows: list[dict], journal_rows: list[dict], *, challenge: str | None = None) -> list[dict]:
    """One row per run (oldest first): its anchor, the first request's time after it, each phase's
    start (rel_s) and duration, the opening time (first phase start to the ready mark), and from the
    wire journal the requests of that challenge (and the lists) inside the run, their total hold and
    bytes. `missing` names the phases a complete opening has and this run lacks."""
    runs: dict[str, list[dict]] = {}
    for r in phase_rows:
        if challenge is None or r.get("challenge") == challenge:
            runs.setdefault(r["run"], []).append(r)
    out = []
    for run, rows in runs.items():
        rows.sort(key=lambda r: r["t0"])
        cid = rows[0].get("challenge")
        anchor = next((r["t0"] - r["rel_s"] for r in rows if r.get("rel_s") is not None), None)
        reqs = [r for r in rows if r["phase"] in REQUEST_PHASES]
        t_first = min((r["t0"] for r in reqs), default=None)
        t_end = max((r["t1"] for r in rows), default=None)
        ready = next((r for r in rows if r["phase"] == "ready"), None)
        phases: dict[str, dict] = {}
        for r in rows:
            if r["phase"] in phases:
                continue
            phases[r["phase"]] = {"rel_s": r.get("rel_s"), "dur_s": r.get("dur_s"), "ok": r.get("ok"),
                                  **({"error": r["error"]} if r.get("error") else {})}
        jr = [x for x in journal_rows if t_first is not None and t_end is not None
              and t_first - 0.5 <= x.get("ts", 0) <= t_end + 0.5
              and (x.get("challenge") == cid or (x.get("challenge") is None and x.get("op") == "list"))]
        want = ["warm", "list", "detail" if "detail" in phases else "start", "download", "ready"]
        out.append({"run": run, "challenge": cid, "mode": rows[0].get("mode"), "anchor": anchor,
                    "first_request_rel_s": (round(t_first - anchor, 4) if anchor is not None and t_first
                                            is not None else None),
                    "open_s": round(ready["t0"] - t_first, 4) if ready and t_first is not None else None,
                    "phases": phases, "requests": len(jr),
                    "held_s": round(sum(float(x.get("held_s") or 0) for x in jr), 4),
                    "bytes": sum(int(x["bytes"]) for x in jr if isinstance(x.get("bytes"), int)),
                    "missing": [p for p in want if p not in phases]})
    return out


def submit_rtt(journal_rows: list[dict], *, kind: str | None = None, lane: str | None = None) -> dict:
    """The per-submit round trip from the wire journal (B-252): `_stats` (n, min, p50) of the dur_s
    of every answered submit (status below 400). `lane` keeps only submits whose mode lane matches
    (the lane of a "<lane>/<mode>" key); None keeps every submit of the kind."""
    vals = []
    for x in journal_rows:
        if x.get("op") != "submit":
            continue
        st = x.get("status")
        if not isinstance(st, int) or st >= 400 or not isinstance(x.get("dur_s"), (int, float)):
            continue
        if lane is not None:
            mlane = mode_of(x.get("kind") or kind, x.get("challenge")).partition("/")[0]
            if mlane != lane:
                continue
        vals.append(x["dur_s"])
    return _stats(vals)


def bank_submit_floor(journal_rows: list[dict], *, count: int, kind: str | None = None,
                      lane: str | None = None) -> dict:
    """The cumulative bank-submit critical path (B-252): to open the timed ladder, `count` base
    answer ids are banked (the Huntress benchmark's 1300-1516). At the measured per-submit round
    trip this is a flat-seconds floor no solver speed cuts. Returns the per-submit stats and the
    bank floor at the min and p50 round trip (count x rtt); `bank_floor_min_s` is None when no submit
    has been measured for the lane yet. This is the wire round-trip floor of banking back to back; it
    does not fold in the submit queue's own spacing (a barrier B-252 must not move)."""
    if not isinstance(count, int) or count < 0:
        raise ValueError(f"bank count must be an integer >= 0, got {count!r}")
    rtt = submit_rtt(journal_rows, kind=kind, lane=lane)
    mn, p50 = rtt.get("min"), rtt.get("p50")
    return {"count": count, "submit_rtt": rtt,
            "bank_floor_min_s": round(mn * count, 4) if mn is not None else None,
            "bank_floor_p50_s": round(p50 * count, 4) if p50 is not None else None}


def parse_records(items: Iterable[str]) -> dict[str, float]:
    """{mode: seconds} from MODE=SECONDS strings (a record to compare against the floor)."""
    out = {}
    for it in items:
        m = _RECORD_RE.match(it.strip())
        if not m:
            raise ValueError(f"record {it!r} is not MODE=SECONDS (e.g. mobile/time_trial=2.351)")
        out[m.group(1)] = float(m.group(2))
    return out


TIMED_UNMEASURED = ("; a timed mode's opening is the Game Master opener's (it starts the clock), and the "
                    "opener does not write phases.jsonl yet (B-252; the carried tools/run.py waits on B-005), "
                    "so no opening floor exists for it until an opener writes PhaseLog rows")


def _timed_mode(mode: str) -> bool:
    return mode.rpartition("/")[2] in TIMED_SUFFIXES


def floor_table(phase_rows: list[dict], journal_rows: list[dict], *, kind: str | None = None,
                records: Mapping[str, float] | None = None,
                bank_counts: Mapping[str, int] | None = None) -> list[dict]:
    """The wire-floor table, one row per mode (sorted): `ops` the round trip (dur_s) of each op of
    an answered request (status below 400) from the wire journal, `phases` each ok phase's duration
    from the phases log, `open_floor_s` the fastest opening (first request to ready), `submit_floor_s`
    the fastest submit, `floor_s` their sum (the wire floor with zero solver time; None when either
    is unmeasured). With a record for the mode: `margin_s` (record - floor) and `verdict`; an
    unmeasured timed mode (time_trial, mastery) with no opening says that only an opener's PhaseLog
    rows can give it one (open_release refuses timed starts).

    `bank_counts` (B-252): {mode: cumulative base-bank size}. A mode named in it gains `bank` (the
    bank-submit floor from the lane's measured submit round trip, bank_submit_floor): the flat-seconds
    gate the timed ladder waits behind. It is reported, never added into `floor_s` (the bank is a
    base-lane barrier, not part of the mode's own opening; B-252 shrinks it, never moves it)."""
    records = dict(records or {})
    bank_counts = dict(bank_counts or {})
    modes: dict[str, dict] = {}

    def slot(mode: str) -> dict:
        return modes.setdefault(mode, {"ops": {}, "phases": {}, "opens": []})

    for x in journal_rows:
        st = x.get("status")
        if not isinstance(st, int) or st >= 400 or not isinstance(x.get("dur_s"), (int, float)):
            continue
        mode = mode_of(x.get("kind") or kind, x.get("challenge"))
        slot(mode)["ops"].setdefault(x.get("op") or "?", []).append(x["dur_s"])
    for r in phase_rows:
        if r.get("ok") and isinstance(r.get("dur_s"), (int, float)) and r["phase"] not in ("anchor", "go",
                                                                                           "ready"):
            slot(r.get("mode") or "-")["phases"].setdefault(r["phase"], []).append(r["dur_s"])
    for rep in run_report(phase_rows, journal_rows):
        if rep["open_s"] is not None:
            slot(rep["mode"] or "-")["opens"].append(rep["open_s"])
    table = []
    for mode in sorted(set(modes) | set(records) | set(bank_counts)):
        m = modes.get(mode) or {"ops": {}, "phases": {}, "opens": []}
        ops = {op: _stats(v) for op, v in sorted(m["ops"].items())}
        ph = {p: _stats(v) for p, v in sorted(m["phases"].items())}
        open_floor = min(m["opens"]) if m["opens"] else None
        submit_floor = ops.get("submit", {}).get("min")
        floor = round(open_floor + submit_floor, 4) if open_floor is not None and submit_floor is not None else None
        row = {"mode": mode, "ops": ops, "phases": ph, "runs": len(m["opens"]),
               "open_floor_s": open_floor, "submit_floor_s": submit_floor, "floor_s": floor}
        if mode in bank_counts:
            row["bank"] = bank_submit_floor(journal_rows, count=bank_counts[mode], kind=kind,
                                            lane=str(mode).partition("/")[0] or None)
        if mode in records:
            rec = records[mode]
            row["record_s"] = rec
            if floor is None:
                row["margin_s"], row["verdict"] = None, "unmeasured: no complete opening and submit on record"
                if _timed_mode(mode) and open_floor is None:
                    row["verdict"] += TIMED_UNMEASURED
            else:
                row["margin_s"] = round(rec - floor, 4)
                row["verdict"] = ("below the wire floor: solver work cannot reach it" if rec < floor
                                  else f"beatable with {rec - floor:.3f} s of solve time")
        table.append(row)
    return table


def write_floors(workdir: Path, table: list[dict], *, now: float | None = None) -> Path:
    """Write the table to <workdir>/wire/floors.json (0600); returns the path."""
    d = _mkdir(workdir)
    p = d / FLOORS_NAME
    tmp = d / f".{FLOORS_NAME}.{os.getpid()}.tmp"
    body = {"written": time.time() if now is None else now, "modes": table}
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh, indent=1, sort_keys=True)
        os.replace(tmp, p)
    except OSError as e:
        raise LatencyError(f"floors table {p} cannot be written ({e})") from e
    return p
