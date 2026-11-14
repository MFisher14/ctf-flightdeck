"""The platform wire (B-140): a per-request journal and a release-minute request budget.

    gate = get_adapter(profile)          # wire.install(gate, adapter) has already run
    gate.list_challenges()               # journaled, and held while the budget says so
    wire.of(gate).lane = "watch"         # name the lane of this process (default: $CTF_WIRE_LANE)

Why. On Huntress Days 8, 9 and 10 a 429 on `list` landed in the first minute of the release
(09:00:36, 09:00:36, 09:00:29) at 88-102 requests in the last 60 s, under the 120 a minute measured
off-hours, and paused untimed requests 26-33 s; on Day 9 it held a base that was ready. The journal
of the day kept bare timestamps, so which ops and which lanes spent the minute was never known.

Every HTTP request an adapter sends through its session passes here (every process of the event
shares one state, under <workdir>/wire/):

  journal      <workdir>/wire/journal.jsonl (0600, append-only, one line per request):
                 ts (send start), asked (when the caller asked), held_s, held_by (pause | team |
                 release | poll_gap | poll_inflight | lane | null), forced, dur_s, op, method, cls, lane, pid,
                 challenge (when the request names one), status (HTTP code, null when the send
                 raised), error (exception class), n60 (requests in the 60 s up to and including
                 this one, every process), nmin (the same in this calendar minute), rel_s (seconds
                 since the active release anchor, null outside a window), and on a 429:
                 retry_after, pause_s, limit_headers (Retry-After, X-RateLimit-*, RateLimit-*);
                 exempt ("sole_lane" when the sole-lane rule let it past a budget, else null) and
                 bytes (the response's Content-Length, null without one; B-185). dur_s is the time
                 to the response headers: a streamed body (an artifact) is read after it.
               Never a URL (CTFd file links carry signed tokens), a body, a header value other
               than the limit headers, a flag or a credential.
  op           what the request is: Game Master list | status | artifact | openapi | start |
               submit; CTFd list | challenge | submit | solves (ours, or one challenge's: B-099) |
               scoreboard | home | time | file | api:<first path segment>; else the method in lower case.
  class        priority (submit, start: they may use the reserve and no lane budget holds them),
               poll (list), read (everything else).

The budget (the profile's [wire] table, WirePace; a 0 cap is no cap, and every request is journaled
either way). Before a request is sent:

  pause        after an HTTP 429 every process holds every request until the pause ends:
               Retry-After when the platform gives one (capped at pause_max_s), else pause_s,
               doubling when the 429 comes within REPEAT_WINDOW_S of the previous one, up to
               pause_max_s. Never cut short by max_wait_s: a request sent into it is refused again.
  team         per_minute: at most that many requests in any 60 s window, every process together;
               a read or poll stops at per_minute - reserve, a priority request may use the reserve.
  release      inside a release window [anchor, anchor + release_window_s): release_budget
               requests in the whole window, again less the reserve for reads and polls.
  poll gap     inside a window, from anchor + release_poll_free_s on, list polls (every lane
               together) at least release_poll_gap_s apart: the watcher's 1 s fast poll and the
               lanes' list calls are spread so a resume after :30 does not find the minute spent.
  poll inflight (B-252) at most poll_inflight list polls run at once, every process together: a poll
               is held (held_by "poll_inflight") until a slot frees. The gap spreads polls in time;
               this bounds how many are outstanding, so the release's poll-to-detect never piles a
               third list GET on the server while two are unanswered. A slot is taken when a poll is
               admitted and freed when its request returns (or raises); a slot older than
               POLL_INFLIGHT_TTL_S is reaped (a crashed process). 0 = off (no cap). Never forceable
               and never lifted by the sole-lane rule: it caps concurrency, not a per-minute budget.
  lane         inside a window, release_lane_budget (or release_lanes[lane]) requests per named
               lane: every request of the lane counts, its reads are held past the budget, its
               polls and priority requests never are. An unnamed lane (no CTF_WIRE_LANE) has no lane
               budget.
  sole lane    (B-185) a named lane that is the only one still working in the window is exempt from
               the release, poll-gap and lane budgets (never from a pause or the team cap, so it
               spends only what per_minute has room for): there is at least one other lane, and
               every other lane (one that sent a read or priority request in the window, is named in
               release_lanes, or was marked done) has been marked done since the anchor
               (mark_lane_done; `ctf latency lane-done LANE`). The
               board watcher's lane (PASSIVE_LANES) never counts; an unnamed request that is not a
               poll does (nobody can mark it done), so it blocks the exemption. The journal row of
               an exempted request says exempt: "sole_lane". Day 14: the last lane's settling probe
               was held 40.1 s by the minute's turn with every other lane already done.
  max wait     a request the release, poll-gap or lane budget has held max_wait_s is sent anyway,
               journaled forced: true, with one line on stderr: those budgets spread the minute,
               they never refuse. max_wait_s never lifts a pause or the team cap: per_minute stands
               for the platform's own limit, so a request past it would only draw the 429 (and the
               pause of every process) it is there to avoid. A team-cap hold ends when the oldest
               counted request leaves the 60 s window; one held past max_wait_s says so on stderr.

Release anchors: the profile's dates.start (a datetime with a zone) and every anchor recorded with
mark_releases() (`ctf watch run` records its --wave/--daily anchors, `ctf wait --not-before` its
start; `ctf wire mark-release`).

State, journal and anchors are per workdir. A wire dir that cannot be created or written fails the
request loudly (WireError), naming the folder; a state file that does not parse is rebuilt from the
journal with one line on stderr. `python -m ctf wire status | journal | ratelimits | mark-release`
reads it (ctf/cli/wire.py); `ratelimits` gives, for each 429, the request mix by op and lane of the
60 s before it: the cause the Huntress journal could not show.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import json
import math
import os
import re
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Generator, Iterable, Iterator, Mapping
from urllib.parse import urlsplit

from .. import env, paths
from ..event import LANE_RE, EventProfile, WirePace
from . import _http
from .base import PlatformError

DIR_NAME = "wire"
JOURNAL_NAME = "journal.jsonl"
STATE_NAME = "state.json"
LOCK_NAME = "state.lock"

WINDOW_S = 60.0                 # the team cap's rolling window
REPEAT_WINDOW_S = 120.0         # a 429 this soon after the previous one doubles the pause
ANCHOR_KEEP_S = 86400.0         # release anchors older than this are dropped from the state
REBUILD_TAIL_BYTES = 262144     # how much of the journal a torn state is rebuilt from
MIN_SLEEP_S = 0.001

POLL_INFLIGHT = 2               # (B-252) list polls allowed outstanding at once, every process together
POLL_INFLIGHT_TTL_S = 30.0     # a poll slot held longer than this is reaped (its process crashed)
POLL_INFLIGHT_RECHECK_S = 0.05 # how often a poll held by the inflight cap re-checks for a free slot
POLL_INFLIGHT_REASON = "poll_inflight"

PRIORITY_OPS = frozenset({"submit", "start"})
POLL_OPS = frozenset({"list"})
PRIORITY, POLL, READ = "priority", "poll", "read"
HOLD_REASONS = ("pause", "team", "release", "poll_gap", POLL_INFLIGHT_REASON, "lane")
FORCEABLE = frozenset({"release", "poll_gap", "lane"})   # the holds max_wait_s lifts (never pause, team)
PASSIVE_LANES = frozenset({"watch"})   # lanes that never compete for a release minute (the board watcher)
SOLE_LANE = "sole_lane"
_LIMIT_HEADER = re.compile(r"^(retry-after|x-ratelimit-[a-z-]+|ratelimit(-[a-z-]+)?|x-rate-limit-[a-z-]+)$", re.I)
_CHALLENGE_PATH = re.compile(r"^/challenges/(\d+)$")
_CHALLENGE_SOLVES_PATH = re.compile(r"^/challenges/(\d+)/solves$")


class WireError(PlatformError):
    """The wire cannot journal or budget a request (its folder is unusable, a bad lane name)."""


# ------------------------------------------------------------------------------------------ ops

def op_of(kind: str, method: str, url: str, *, base_url: str | None = None,
          params: Mapping[str, Any] | None = None, json_body: Any = None) -> tuple[str, str | None]:
    """(op, challenge id or None) of one request. Only names and ids: never a value of the body."""
    m = method.upper()
    if kind == "gamemaster":
        p = params or {}
        cid = p.get("challenge")
        if m == "GET":
            return str(p.get("op") or "get"), (str(cid) if cid is not None else None)
        if m == "POST" and isinstance(json_body, dict):
            cid = json_body.get("challenge")
            cid = str(cid) if cid is not None else None
            return ("submit" if "answers" in json_body else "start" if cid else "post"), cid
        return m.lower(), None
    if kind == "ctfd":
        path = urlsplit(url).path
        base = urlsplit(base_url or "").path.rstrip("/")
        if base and path.startswith(base):
            path = path[len(base):]
        path = "/" + path.strip("/") if path.strip("/") else "/"
        if path == "/":
            return ("time" if m == "HEAD" else "home"), None
        if path.startswith("/files/"):
            return "file", None
        if path.startswith("/api/v1/"):
            rest = path[len("/api/v1"):]
            if rest == "/challenges":
                return "list", None
            if rest == "/challenges/attempt":
                cid = json_body.get("challenge_id") if isinstance(json_body, dict) else None
                return "submit", (str(cid) if cid is not None else None)
            mm = _CHALLENGE_PATH.match(rest)
            if mm:
                return "challenge", mm.group(1)
            if rest in ("/teams/me/solves", "/users/me/solves"):
                return "solves", None
            mm = _CHALLENGE_SOLVES_PATH.match(rest)
            if mm:                      # every team's solves of one challenge (B-099: first blood)
                return "solves", mm.group(1)
            if rest == "/scoreboard":
                return "scoreboard", None
            return "api:" + rest.strip("/").split("/", 1)[0], None
        return m.lower(), None
    return m.lower(), None


def op_class(op: str) -> str:
    if op in PRIORITY_OPS:
        return PRIORITY
    if op in POLL_OPS:
        return POLL
    return READ


# ------------------------------------------------------------------------------------------ budget

def active_anchors(anchors: Iterable[float], now: float, pace: WirePace) -> list[float]:
    return sorted(a for a in anchors if a <= now < a + pace.release_window_s)


def decide(pace: WirePace, rows: list, now: float, *, lane: str | None, cls: str,
           anchors: Iterable[float] = (), pause_until: float = 0.0,
           lift: Iterable[str] = ()) -> tuple[float, str | None]:
    """(seconds to wait, the reason) before a request of class `cls` from `lane` may be sent, given
    the requests already counted (`rows`: [ts, lane, cls] of every process). (0.0, None): send now.
    The reason is the rule that holds it longest; the caller re-asks after the wait. `lift` names
    rules of FORCEABLE to leave out (for a request held max_wait_s); a pause or the team cap is
    never lifted."""
    lifted = frozenset(lift)
    if lifted - FORCEABLE:
        raise ValueError(f"only {sorted(FORCEABLE)} can be lifted, not {sorted(lifted - FORCEABLE)}")
    if pause_until > now:
        return pause_until - now, "pause"
    waits: list[tuple[float, str]] = []
    reserve = 0 if cls == PRIORITY else pace.reserve
    if pace.per_minute:
        limit = pace.per_minute - reserve
        recent = sorted(r[0] for r in rows if now - WINDOW_S < r[0] <= now)
        if len(recent) >= limit:
            waits.append((recent[len(recent) - limit] + WINDOW_S - now, "team"))
    for a in active_anchors(anchors, now, pace):
        end = a + pace.release_window_s
        inwin = [r for r in rows if a <= r[0] < end]
        if "release" not in lifted and pace.release_budget and len(inwin) >= pace.release_budget - reserve:
            waits.append((end - now, "release"))
        if ("poll_gap" not in lifted and cls == POLL and pace.release_poll_gap_s
                and now >= a + pace.release_poll_free_s):
            polls = [r[0] for r in rows if r[2] == POLL and r[0] <= now]
            if polls and max(polls) + pace.release_poll_gap_s > now:
                waits.append((max(polls) + pace.release_poll_gap_s - now, "poll_gap"))
        budget = pace.lane_budget(lane)
        if "lane" not in lifted and cls == READ and budget and sum(1 for r in inwin if r[1] == lane) >= budget:
            waits.append((end - now, "lane"))
    if not waits:
        return 0.0, None
    return max(waits)


def sole_lane(rows: list, lane: str | None, anchors: Iterable[float], now: float, pace: WirePace,
              done: Mapping[str, float]) -> bool:
    """Whether `lane` is the only lane still working in every active release window (B-185). The
    other lanes of a window are those with a read or priority request in it (`rows`: [ts, lane,
    cls]), those named in pace.release_lanes and those marked done (`done`: {lane: when}) since its
    anchor; there must be at least one (a lane alone at the start of a window is not "the last one
    working": the others may not have asked yet), and every one must be marked done at or after the
    anchor. PASSIVE_LANES never count; an unnamed non-poll request always does and is never done.
    False outside a window and for an unnamed lane."""
    if not lane:
        return False
    act = active_anchors(anchors, now, pace)
    if not act:
        return False
    for a in act:
        others: set = {r[1] for r in rows if a <= r[0] <= now and r[2] != POLL}
        others |= {name for name, _ in pace.release_lanes}
        others |= {name for name, when in done.items() if isinstance(when, (int, float)) and when >= a}
        others -= {lane, *PASSIVE_LANES}
        if not others:
            return False
        for o in others:
            when = done.get(o)          # None (an unnamed request) is never in `done`
            if not isinstance(when, (int, float)) or when < a:
                return False
    return True


def live_inflight(entries: Any, now: float, *, ttl: float = POLL_INFLIGHT_TTL_S) -> list:
    """The poll-inflight slots still live at `now`: well-formed [pid, token, started_ts] entries
    whose start is within `ttl` (a crashed process's slot is reaped). (B-252)"""
    out = []
    for e in entries or ():
        if (isinstance(e, list) and len(e) == 3 and isinstance(e[2], (int, float))
                and e[2] > now - ttl):
            out.append(e)
    return out


def next_pause(pace: WirePace, now: float, retry_after: float | None, last_429: float,
               last_pause: float) -> float:
    """Seconds every process pauses after a 429 answered at `now`."""
    if retry_after is not None and retry_after > 0:
        return min(float(retry_after), pace.pause_max_s)
    if last_429 and now - last_429 <= REPEAT_WINDOW_S and last_pause:
        return min(last_pause * 2, pace.pause_max_s)
    return pace.pause_s


def content_length(resp: Any) -> int | None:
    """The response's Content-Length as an int, or None (absent, or not a number)."""
    try:
        v = dict(getattr(resp, "headers", None) or {})
    except (TypeError, ValueError):
        return None
    raw = next((x for k, x in v.items() if isinstance(k, str) and k.lower() == "content-length"), None)
    try:
        n = int(str(raw).strip()) if raw is not None else None
    except ValueError:
        return None
    return n if n is not None and n >= 0 else None


def limit_headers(resp: Any) -> dict[str, str]:
    """The rate-limit headers of a response (no other header is ever kept)."""
    out = {}
    for k, v in dict(getattr(resp, "headers", None) or {}).items():
        if isinstance(k, str) and _LIMIT_HEADER.match(k):
            out[k.lower()] = str(v)[:200]
    return out


# ------------------------------------------------------------------------------------------ places

def wire_dir(workdir: Path) -> Path:
    return Path(workdir) / DIR_NAME


def journal_path(workdir: Path) -> Path:
    return wire_dir(workdir) / JOURNAL_NAME


def _mkdir(workdir: Path) -> Path:
    d = wire_dir(workdir)
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise WireError(f"wire dir {d} is unusable ({e}); no platform request is sent unjournaled "
                        "(set CTF_WORKDIR to a writable folder)") from e
    return d


@contextlib.contextmanager
def _locked(workdir: Path) -> Iterator[None]:
    d = _mkdir(workdir)
    try:
        fd = os.open(d / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as e:
        raise WireError(f"wire lock {d / LOCK_NAME} cannot be opened ({e})") from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def read_journal(workdir: Path, *, since: float | None = None) -> tuple[list[dict], int]:
    """(rows, unreadable line count) of the journal, oldest first; [] when there is none."""
    p = journal_path(workdir)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], 0
    return _parse_rows(text.splitlines(), since)


def _parse_rows(lines: Iterable[str], since: float | None) -> tuple[list[dict], int]:
    rows, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if not isinstance(r, dict) or not isinstance(r.get("ts"), (int, float)):
            bad += 1
            continue
        if since is None or r["ts"] >= since:
            rows.append(r)
    return rows, bad


def _read_state(workdir: Path, now: float, err: Any) -> dict:
    p = wire_dir(workdir) / STATE_NAME
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(st, dict):
            return st
    except FileNotFoundError:
        return {}
    except (ValueError, OSError):
        pass
    # A torn state must not lose the count: rebuild the recent rows from the journal's tail.
    rows: list[dict] = []
    try:
        with open(journal_path(workdir), "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - REBUILD_TAIL_BYTES))
            rows, _ = _parse_rows(fh.read().decode("utf-8", "replace").splitlines(), now - 2 * WINDOW_S)
    except FileNotFoundError:
        pass
    print(f"ctf wire: {p} did not parse; rebuilt {len(rows)} recent request(s) from the journal",
          file=err)
    return {"recent": [[r["ts"], r.get("lane"), r.get("cls", READ)] for r in rows]}


def _write_state(workdir: Path, st: dict) -> None:
    d = wire_dir(workdir)
    tmp = d / f"state.tmp{os.getpid()}"
    try:
        tmp.write_text(json.dumps(st, sort_keys=True), encoding="utf-8")
        os.replace(tmp, d / STATE_NAME)
    except OSError as e:
        raise WireError(f"wire state {d / STATE_NAME} cannot be written ({e})") from e


def _append(workdir: Path, rec: dict) -> None:
    d = _mkdir(workdir)
    line = (json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        fd = os.open(d / JOURNAL_NAME, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    except OSError as e:
        raise WireError(f"wire journal {d / JOURNAL_NAME} cannot be written ({e})") from e


def mark_releases(workdir: Path, anchors: Iterable[float], *, now: float | None = None) -> list[float]:
    """Record release anchors (epoch seconds) for every process of the workdir; returns the kept set."""
    now = time.time() if now is None else now
    with _locked(workdir):
        st = _read_state(workdir, now, sys.stderr)
        kept = {float(a) for a in st.get("releases", ()) if float(a) >= now - ANCHOR_KEEP_S}
        kept |= {float(a) for a in anchors if float(a) >= now - ANCHOR_KEEP_S}
        st["releases"] = sorted(kept)
        _write_state(workdir, st)
    return st["releases"]


def clear_releases(workdir: Path) -> None:
    with _locked(workdir):
        st = _read_state(workdir, time.time(), sys.stderr)
        st["releases"] = []
        _write_state(workdir, st)


def mark_lane_done(workdir: Path, lane: str, *, done: bool = True, now: float | None = None) -> dict:
    """Mark `lane` done (or, done=False, working again) for every process of the workdir; returns
    {lane: when} of the lanes marked done. The sole-lane rule reads it (B-185)."""
    if not lane or not LANE_RE.fullmatch(lane):
        raise WireError(f"lane {lane!r} must match {LANE_RE.pattern}")
    now = time.time() if now is None else now
    with _locked(workdir):
        st = _read_state(workdir, now, sys.stderr)
        marks = {k: float(v) for k, v in (st.get("lanes_done") or {}).items()
                 if isinstance(v, (int, float)) and float(v) >= now - ANCHOR_KEEP_S}
        if done:
            marks[lane] = now
        else:
            marks.pop(lane, None)
        st["lanes_done"] = marks
        _write_state(workdir, st)
    return marks


def profile_anchors(profile: EventProfile) -> list[float]:
    s = profile.start
    if isinstance(s, _dt.datetime) and s.tzinfo is not None:
        return [s.timestamp()]
    return []


# ------------------------------------------------------------------------------------------ the wire

class Wire:
    """The journal and budget of one event's platform requests (one per adapter; every process of
    the workdir shares the state)."""

    def __init__(self, profile: EventProfile, *, kind: str | None = None, workdir: Path | None = None,
                 pace: WirePace | None = None, lane: str | None = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 environ: Mapping[str, str] | None = None, err: Any = None,
                 poll_inflight: int = POLL_INFLIGHT):
        self.profile = profile
        self.kind = kind or profile.platform.kind
        self.pace = pace if pace is not None else profile.wire
        self._workdir = workdir
        self._lane = lane
        self._clock, self._sleep = clock, sleep
        self._environ = environ
        self._err = err
        if not isinstance(poll_inflight, int) or poll_inflight < 0:
            raise WireError(f"poll_inflight must be an integer >= 0 (0 = off), got {poll_inflight!r}")
        self.poll_inflight = poll_inflight

    @property
    def workdir(self) -> Path:
        return Path(self._workdir) if self._workdir is not None else paths.workdir(self.profile.slug)

    @property
    def err(self):
        return self._err if self._err is not None else sys.stderr

    @property
    def lane(self) -> str | None:
        v = self._lane if self._lane is not None else env.get("CTF_WIRE_LANE", environ=self._environ)
        if v and not LANE_RE.fullmatch(v):
            raise WireError(f"lane {v!r} (CTF_WIRE_LANE) must match {LANE_RE.pattern}")
        return v or None

    @lane.setter
    def lane(self, value: str | None) -> None:
        if value and not LANE_RE.fullmatch(value):
            raise WireError(f"lane {value!r} must match {LANE_RE.pattern}")
        self._lane = value

    # ------------------------------------------------------------------------------- admission
    def _keep_s(self) -> float:
        return max(2 * WINDOW_S, self.pace.release_window_s + WINDOW_S)

    def admit(self, lane: str | None, cls: str) -> dict:
        """Wait for this request's turn, count it, and return the journal fields of the admission."""
        steps = self.admission(lane, cls)
        while True:
            try:
                wait = next(steps)
            except StopIteration as done:
                return done.value
            self._sleep(wait)

    def admission(self, lane: str | None, cls: str) -> Generator[float, None, dict]:
        """admit() as a generator: it yields each wait (seconds) instead of sleeping, and returns the
        journal fields. The caller moves the clock (a release-minute simulation interleaves many)."""
        asked = self._clock()
        held_budget = 0.0           # time held by a budget (team, release, poll gap, lane), not a pause
        held_by: str | None = None
        noted = False
        wd = self.workdir
        while True:
            with _locked(wd):
                now = self._clock()
                st = _read_state(wd, now, self.err)
                rows = [r for r in st.get("recent", ()) if isinstance(r, list) and len(r) == 3
                        and r[0] > now - self._keep_s()]
                anchors = [*st.get("releases", ()), *profile_anchors(self.profile)]
                pause_until = float(st.get("pause_until", 0.0))
                wait, why = decide(self.pace, rows, now, lane=lane, cls=cls, anchors=anchors,
                                   pause_until=pause_until)
                forced = False
                exempt = None
                if wait > 0 and why in FORCEABLE and sole_lane(rows, lane, anchors, now, self.pace,
                                                               st.get("lanes_done") or {}):
                    # the only lane still working: the spreading budgets have no one to spread it from
                    exempt = SOLE_LANE
                    wait, why = decide(self.pace, rows, now, lane=lane, cls=cls, anchors=anchors,
                                       pause_until=pause_until, lift=FORCEABLE)
                if wait > 0 and why in FORCEABLE and held_budget >= self.pace.max_wait_s:
                    # held max_wait_s: the spreading budgets let it go; a pause or the team cap still holds
                    forced = True
                    wait, why = decide(self.pace, rows, now, lane=lane, cls=cls, anchors=anchors,
                                       pause_until=pause_until, lift=FORCEABLE)
                inflight = live_inflight(st.get("poll_inflight"), now)
                if wait <= 0 and cls == POLL and self.poll_inflight and len(inflight) >= self.poll_inflight:
                    # the concurrency cap, not a spreading budget: not forceable, never lifted by sole_lane
                    wait, why = POLL_INFLIGHT_RECHECK_S, POLL_INFLIGHT_REASON
                poll_token = None
                if wait <= 0:
                    rows.append([now, lane, cls])
                    st["recent"] = rows
                    if cls == POLL and self.poll_inflight:
                        poll_token = f"{os.getpid()}:{uuid.uuid4().hex[:12]}"
                        st["poll_inflight"] = [*inflight, [os.getpid(), poll_token, now]]
                    _write_state(wd, st)
                    minute = math.floor(now / 60.0) * 60.0
                    act = active_anchors(anchors, now, self.pace)
                    out = {"asked": round(asked, 3), "ts": round(now, 3), "held_s": round(now - asked, 3),
                           "held_by": held_by, "forced": forced, "exempt": exempt,
                           "n60": sum(1 for r in rows if now - WINDOW_S < r[0] <= now),
                           "nmin": sum(1 for r in rows if minute <= r[0] <= now),
                           "rel_s": round(now - act[0], 3) if act else None}
                    if poll_token is not None:
                        out["_poll_token"] = poll_token
                    return out
            held_by = held_by or why
            # a spreading budget is re-asked at max_wait_s (when it is lifted); a pause, team cap or
            # poll-inflight hold runs until its own condition clears
            step = max(min(wait, self.pace.max_wait_s - held_budget) if why in FORCEABLE else wait,
                       MIN_SLEEP_S)
            if why not in ("pause", POLL_INFLIGHT_REASON):
                held_budget += step
            if why == "team" and held_budget > self.pace.max_wait_s and not noted:
                noted = True
                print(f"ctf wire: lane {lane or '-'} held {held_budget:g} s by the team cap (per_minute "
                      f"{self.pace.per_minute}); max_wait_s never lifts it", file=self.err)
            yield step

    def _free_poll(self, token: str) -> None:
        """Give back the poll-inflight slot `token` held (B-252): the request has returned or raised."""
        wd = self.workdir
        with _locked(wd):
            now = self._clock()
            st = _read_state(wd, now, self.err)
            st["poll_inflight"] = [e for e in live_inflight(st.get("poll_inflight"), now) if e[1] != token]
            _write_state(wd, st)

    def _after_429(self, resp: Any, rec: dict) -> None:
        wd = self.workdir
        with _locked(wd):
            now = self._clock()
            st = _read_state(wd, now, self.err)
            ra = _http.retry_after(resp)
            pause = next_pause(self.pace, now, ra, float(st.get("last_429", 0.0)),
                               float(st.get("last_pause_s", 0.0)))
            st["pause_until"] = max(float(st.get("pause_until", 0.0)), now + pause)
            st["last_429"] = now
            st["last_pause_s"] = pause
            _write_state(wd, st)
        rec.update(retry_after=ra, pause_s=round(pause, 3), limit_headers=limit_headers(resp))
        print(f"ctf wire: HTTP 429 on {rec['op']} (lane {rec['lane'] or '-'}; {rec['n60']} request(s) "
              f"in the last 60 s, {rec['nmin']} in this minute); every process pauses {pause:g} s "
              "(`ctf wire ratelimits` shows the mix)", file=self.err)

    def send(self, request: Callable[..., Any], method: str, url: str, **kw: Any) -> Any:
        """Journal and budget one request, then make it with `request(method, url, **kw)`."""
        op, cid = op_of(self.kind, method, url, base_url=self.profile.platform.base_url,
                        params=kw.get("params"), json_body=kw.get("json"))
        cls = op_class(op)
        lane = self.lane
        adm = self.admit(lane, cls)
        if adm["forced"]:
            print(f"ctf wire: {op} (lane {lane or '-'}) sent after {adm['held_s']:g} s held by the "
                  f"{adm['held_by']} budget (max_wait_s {self.pace.max_wait_s:g}); journaled forced",
                  file=self.err)
        rec = {**adm, "op": op, "method": method.upper(), "cls": cls, "lane": lane, "pid": os.getpid(),
               "challenge": cid, "status": None, "error": None, "kind": self.kind}
        poll_token = rec.pop("_poll_token", None)       # not journaled: a poll-inflight slot to free
        t0 = self._clock()
        try:
            resp = request(method, url, **kw)
        except BaseException as e:
            rec.update(dur_s=round(self._clock() - t0, 4), error=type(e).__name__)
            if poll_token is not None:
                self._free_poll(poll_token)
            _append(self.workdir, rec)
            raise
        rec["dur_s"] = round(self._clock() - t0, 4)
        status = getattr(resp, "status_code", None)
        rec["status"] = status if isinstance(status, int) else None
        rec["bytes"] = content_length(resp)
        if poll_token is not None:
            self._free_poll(poll_token)
        if status == 429:
            self._after_429(resp, rec)
        _append(self.workdir, rec)
        return resp

    def status(self) -> dict:
        """The shared state now: counts, pause, active windows and per-lane spend in them."""
        wd = self.workdir
        now = self._clock()
        with _locked(wd):
            st = _read_state(wd, now, self.err)
        rows = [r for r in st.get("recent", ()) if isinstance(r, list) and len(r) == 3]
        anchors = sorted({*st.get("releases", ()), *profile_anchors(self.profile)})
        act = active_anchors(anchors, now, self.pace)
        minute = math.floor(now / 60.0) * 60.0
        windows = []
        for a in act:
            inwin = [r for r in rows if a <= r[0] < a + self.pace.release_window_s]
            windows.append({"anchor": a, "elapsed_s": round(now - a, 3), "requests": len(inwin),
                            "by_lane": dict(Counter(r[1] or "-" for r in inwin))})
        upcoming = [a for a in anchors if a > now]
        return {"now": now, "n60": sum(1 for r in rows if now - WINDOW_S < r[0] <= now),
                "nmin": sum(1 for r in rows if minute <= r[0] <= now),
                "pause_left_s": max(0.0, round(float(st.get("pause_until", 0.0)) - now, 3)),
                "last_429": st.get("last_429"), "windows": windows,
                "next_anchor": upcoming[0] if upcoming else None, "pace": self.pace}


class WireSession:
    """A requests.Session stand-in that sends every request(...) through a Wire. Attributes (headers,
    cookies, trust_env) are the wrapped session's."""

    def __init__(self, inner: Any, wire: Wire):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "wire", wire)

    def request(self, method: str, url: str, **kw: Any) -> Any:
        return self.wire.send(self._inner.request, method, url, **kw)

    def get(self, url: str, **kw: Any) -> Any:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw: Any) -> Any:
        return self.request("HEAD", url, **kw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._inner, name, value)


def install(gate: Any, adapter: Any, **kw: Any) -> Wire | None:
    """Route the adapter's platform session through a Wire and attach it to the gate. An adapter
    with no HTTP session (`_s`: the manual drop folder, a test double) sends no request: None."""
    s = getattr(adapter, "_s", None)
    if s is None or not callable(getattr(s, "request", None)):
        return None
    if isinstance(s, WireSession):
        w = s.wire
    else:
        w = Wire(gate.profile, kind=getattr(adapter, "kind", None), **kw)
        adapter._s = WireSession(s, w)
    gate.wire = w           # read back with of(gate): a plain attribute, never the adapter's
    return w


def of(gate: Any) -> Wire | None:
    """The Wire get_adapter installed on this gate, or None (an adapter that sends no request)."""
    return getattr(gate, "__dict__", {}).get("wire")


# ------------------------------------------------------------------------------------------ analysis

def ratelimit_report(rows: list[dict]) -> list[dict]:
    """For each 429 in the journal: when, what, and the mix of the 60 s up to it (every request the
    journal holds with ts in (t - 60, t], this one included), by op, lane and class."""
    out = []
    for r in rows:
        if r.get("status") != 429:
            continue
        t = r["ts"]
        win = [x for x in rows if t - WINDOW_S < x["ts"] <= t]
        minute = math.floor(t / 60.0) * 60.0
        out.append({"ts": t, "op": r.get("op"), "lane": r.get("lane"), "n60": r.get("n60"),
                    "nmin": r.get("nmin"), "second": round(t - minute, 3), "rel_s": r.get("rel_s"),
                    "pause_s": r.get("pause_s"), "retry_after": r.get("retry_after"),
                    "limit_headers": r.get("limit_headers") or {},
                    "journal_60s": len(win),
                    "journal_minute": sum(1 for x in rows if minute <= x["ts"] <= t),
                    "by_op": dict(Counter(x.get("op") or "?" for x in win).most_common()),
                    "by_lane": dict(Counter(x.get("lane") or "-" for x in win).most_common()),
                    "by_class": dict(Counter(x.get("cls") or "?" for x in win).most_common()),
                    "forced_60s": sum(1 for x in win if x.get("forced"))})
    return out
