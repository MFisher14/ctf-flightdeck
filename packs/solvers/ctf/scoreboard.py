"""Automatic scoreboard ingestion and first-blood benchmarking (B-099).

    gate = get_adapter(profile)
    res = scoreboard.ingest(gate)                        # one low-priority read of the public board
    state = scoreboard.load(workdir)                     # what every ingest has gathered
    b = scoreboard.bench(state, list(ledger.read(workdir)), team="our team")
    print(scoreboard.render_bench(b))                    # per-lane gap vs rivals, first bloods won/lost
    recs = scoreboard.floor_records(b, kind="ctfd")      # {mode: s}: latency.floor_table's known record

    scoreboard.record_solve(workdir, "web-day-01", "rivals", at)   # hand entry (a Game Master board)

`python -m ctf scoreboard ingest | watch | record | show | bench | floors` is the CLI
(ctf/cli/scoreboard.py).

Why. At Huntress the human pasted 12-20 KB leaderboard dumps into the agent run after run and asked
it to count from them; first bloods won or lost to other teams were never measured at CSCTF. The
yardstick that did exist (Huntress tools/benchmark_vs_firstblood.py over tools/solvetimes.py) read
hand-copied board times from a JSON file and replayed Game Master days. Here the board is read through
the platform adapter, and our times come from the event ledger (ctf/replay.py's accepted stage).

Ingest (one cycle; `watch` repeats it):
  1. Kind. Only CTFd publishes other teams' solves: on any other kind the adapter's own scoreboard()
     raises first, named, with no request (Game Master NotSupported, manual NotAllowed).
  2. Low priority. Board polls never compete with solving: before the cycle, and again before each
     per-challenge read, the cycle is deferred (nothing sent, IngestResult.deferred says why) while the
     wire (ctf/platform/wire.py) is paused after a 429, while a release window is open, or while the
     last 60 s already hold half of the team's per-minute budget less its reserve. force=True skips
     this check (never the wire's own holds). Every request goes through the wire, journaled under
     lane "board" (ops scoreboard, list, solves), so `ctf wire ratelimits` sees what the board spent.
  3. Reads. GET /scoreboard (the standings), the challenge list (CTFd gives each challenge's solve
     count), then GET /challenges/<id>/solves only for challenges whose count changed since the last
     read, never-read ones first, at most max_solves a cycle (the rest are `pending` for the next).
     A count of 0 needs no read. HTTP 403 on a solves read (scores hidden) stops the cycle loudly
     after the board is saved: NotSupported naming it. Any other failure of one read is kept in
     IngestResult.errors and the cycle goes on.
     The cycle names its lane by setting the gate's wire lane (Wire.lane) for its length, so a gate
     (and its Wire) must not be shared with another lane's thread while a cycle runs: give ingest its
     own gate, as the CLI does (one process). A shared one would journal that thread's requests as
     "board" and spend the board's budget share on them.
  4. Store, under <workdir>/scoreboard/ (0600 files, one writer at a time by flock):
       state.json   {schema, updated, board_at, board: [[rank, team, score]...],
                     challenges: {id: {name, category, points, count, fetched, solves: [{account, at,
                     account_id[, hand: true]}...] earliest first}}}
                     `count` is the challenge list's solve count when it gives one (never the number
                     of rows the solves read returned: a capped or paginated read must not make the
                     challenge look changed every cycle), else the number of rows.
       events.jsonl one line per cycle ({ts, event: "board", rows: the top keep_rows standings plus
                     our row}) and per new first blood ({ts, event: "first_blood", challenge_id,
                     account, at, ours[, source: "hand"]}); `ours` is null when no team name is known.
     Team names are public board data. No URL, header, token or flag is written.

Hand entry (record_solve; `ctf scoreboard record CID TEAM WHEN`): a Game Master event publishes no
other team's solves, and a CTFd may hide them, so a first-blood time read off a stream, an
announcement or a screenshot is entered by hand into the same store (a row with hand: true; no
request). An ingest keeps the hand rows of teams its own read does not list (the board's row wins for
a team it lists), and record_solve refuses a team the board already records. Recording the same team
again replaces its hand row; delete=True removes it (a missing one is an error, named).

Bench (offline: the store plus the ledger, no request):
  ours      our first accepted time of a challenge: the board's record of our team's solve (the
            platform's clock, the same as the rivals') when it is there, else the ledger's first
            `accepted` stage (ctf/replay.py). The row says which (`ours_source`: board, hand for
            a hand-entered row, ledger).
  rival     the earliest solve by any other team: the first blood we raced.
  gap_s     ours - rival (negative: we led by that much). status: won (we were first), lost (a rival
            was), unsolved (a rival solved it, we did not), uncontested (we solved it, nobody else).
  release   the T0 of the challenge's wave in the ledger (replay.waves: the announced start, else the
            detection; replay.assign places it), else, for a challenge the ledger never staged, the
            last wave opened at or before its first board solve, else the caller's t0, else unknown.
            With it: ours_elapsed_s (from the ledger
            accepted time when present: the ledger's clock), rival_elapsed_s, and the Huntress verdict:
            target_s = rival_elapsed_s * (1 - margin) (margin 0.3: beat first blood by 30 %), PASS when
            ours_elapsed_s <= target_s, FAIL when slower or unsolved, NOTARGET without a release or rival.
  lanes     per lane (the board's category): won, lost, unsolved, uncontested, PASS/FAIL/NOTARGET,
            median, best and worst gap, and the rival teams that took the first bloods we lost.

floor_records(bench, kind) gives latency.floor_table its known record per mode: the fastest rival
first blood after release (latency.mode_of(kind, id) groups ids: CTFd is one mode, "ctfd").
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import statistics
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping

from . import paths
from . import replay as _replay
from .platform import wire as _wire
from .platform.base import NotSupported, PlatformError, challenge_solves

DIR_NAME = "scoreboard"
STATE_NAME = "state.json"
EVENTS_NAME = "events.jsonl"
LOCK_NAME = "state.lock"
SCHEMA = 1

LANE = "board"                 # the wire lane every board request is journaled under
INGEST_KINDS = frozenset({"ctfd"})
MAX_SOLVES = 20                # per-challenge solves reads in one cycle
KEEP_ROWS = 50                 # standings rows kept per cycle in events.jsonl (plus ours)
DEFAULT_INTERVAL_S = 60.0
DEFAULT_MARGIN = 0.3           # the Huntress yardstick: beat first blood by 30 %
UNKNOWN_LANE = "-"

WON, LOST, UNSOLVED, UNCONTESTED = "won", "lost", "unsolved", "uncontested"
PASS, FAIL, NOTARGET = "PASS", "FAIL", "NOTARGET"


class ScoreboardError(RuntimeError):
    """The board store cannot be read or written, or a bench input is missing (named)."""


# ------------------------------------------------------------------------------------------ store

def store_dir(workdir: Path) -> Path:
    return Path(workdir) / DIR_NAME


def empty_state() -> dict:
    return {"schema": SCHEMA, "updated": None, "board_at": None, "board": [], "challenges": {}}


def load(workdir: Path) -> dict:
    """The store's state.json, or an empty state when no ingest has run. A file that is not this
    schema's JSON raises ScoreboardError naming it (never read as an empty board)."""
    p = store_dir(workdir) / STATE_NAME
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return empty_state()
    except OSError as e:
        raise ScoreboardError(f"scoreboard state {p} cannot be read ({e.strerror or e})") from None
    try:
        st = json.loads(raw)
    except ValueError as e:
        raise ScoreboardError(f"scoreboard state {p} is not JSON ({e})") from None
    if not isinstance(st, dict) or st.get("schema") != SCHEMA or not isinstance(st.get("challenges"), dict):
        raise ScoreboardError(f"scoreboard state {p} is not schema {SCHEMA}; move it aside to start over")
    return st


def _mkdir(workdir: Path) -> Path:
    d = store_dir(workdir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    except OSError as e:
        raise ScoreboardError(f"scoreboard folder {d} cannot be created ({e.strerror or e})") from None
    return d


@contextlib.contextmanager
def _locked(workdir: Path) -> Iterator[None]:
    d = _mkdir(workdir)
    fd = os.open(d / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _save(workdir: Path, st: dict) -> None:
    d = _mkdir(workdir)
    p, tmp = d / STATE_NAME, d / f".{STATE_NAME}.{os.getpid()}.tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(st, fh, indent=1, sort_keys=True)
        os.replace(tmp, p)
    except OSError as e:
        raise ScoreboardError(f"scoreboard state {p} cannot be written ({e.strerror or e})") from None


def _append(workdir: Path, recs: Iterable[dict]) -> None:
    data = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in recs)
    if not data:
        return
    p = _mkdir(workdir) / EVENTS_NAME
    try:
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, data.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as e:
        raise ScoreboardError(f"scoreboard events {p} cannot be written ({e.strerror or e})") from None


def read_events(workdir: Path) -> list[dict]:
    p = store_dir(workdir) / EVENTS_NAME
    if not p.exists():
        return []
    out = []
    with open(p, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError as e:
                    raise ScoreboardError(f"{p}:{n}: corrupt line ({e})") from None
    return out


# ------------------------------------------------------------------------------------------ helpers

def same_team(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and a.strip().casefold() == b.strip().casefold()


def first_blood(entry: Mapping[str, Any]) -> dict | None:
    """The earliest timed solve of a challenge entry of the store (None when it has none)."""
    timed = [s for s in entry.get("solves") or () if isinstance(s.get("at"), (int, float))]
    return min(timed, key=lambda s: s["at"]) if timed else None


def _ordered(solves: list[dict]) -> list[dict]:
    """Earliest first, untimed rows last (stable for ties)."""
    return sorted(solves, key=lambda s: (not isinstance(s.get("at"), (int, float)), s.get("at") or 0.0))


def _count(raw: Mapping[str, Any]) -> int | None:
    v = raw.get("solves") if isinstance(raw, Mapping) else None
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def busy(w: Any) -> str | None:
    """Why a low-priority board read must wait now (the wire `w`'s shared state), or None."""
    st = w.status()
    if st["pause_left_s"] > 0:
        return f"the wire is paused {st['pause_left_s']:g} s after an HTTP 429"
    if st["windows"]:
        win = st["windows"][0]
        return (f"a release window is open ({win['elapsed_s']:g} s since its anchor): the board yields "
                "the release minute to the lanes")
    pace = st["pace"]
    if pace.per_minute:
        share = max(1, (pace.per_minute - pace.reserve) // 2)
        if st["n60"] >= share:
            return (f"{st['n60']} request(s) in the last 60 s: the board uses at most {share} (half the "
                    f"team's per_minute {pace.per_minute} less its reserve {pace.reserve})")
    return None


@contextlib.contextmanager
def _as_lane(w: Any, lane: str) -> Iterator[None]:
    if w is None:
        yield
        return
    prev = w.__dict__.get("_lane")
    w.lane = lane
    try:
        yield
    finally:
        w.lane = prev


# ------------------------------------------------------------------------------------------ ingest

@dataclass
class IngestResult:
    deferred: str | None = None            # why nothing was sent (low priority), else None
    board_rows: int = 0
    challenges: int = 0
    fetched: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    first_bloods: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return asdict(self)


def _refuse_kind(gate: Any) -> None:
    kind = getattr(gate, "kind", None)
    if kind in INGEST_KINDS:
        return
    gate.scoreboard()          # Game Master: NotSupported, manual: NotAllowed, both named, no request
    raise NotSupported(f"scoreboard ingestion reads CTFd boards; the {kind} adapter has no ingest path")


def ingest(gate: Any, *, workdir: Path | None = None, team: str | None = None,
           max_solves: int = MAX_SOLVES, force: bool = False, lane: str = LANE,
           keep_rows: int = KEEP_ROWS, now: Callable[[], float] = time.time) -> IngestResult:
    """One low-priority read of the public board into the store (module docstring). `gate` is what
    ctf.platform.get_adapter returns. `team` (default: the profile's platform.team) marks our solves."""
    if not isinstance(max_solves, int) or max_solves < 0:
        raise ValueError(f"max_solves must be an integer >= 0, got {max_solves!r}")
    _refuse_kind(gate)
    profile = gate.profile
    wd = Path(workdir) if workdir is not None else paths.workdir(profile.slug)
    team = team if team is not None else profile.platform.team
    w = _wire.of(gate)
    if w is not None and not force:
        why = busy(w)
        if why:
            return IngestResult(deferred=why)
    res = IngestResult()
    with _as_lane(w, lane):
        rows = gate.scoreboard()
        chs = gate.list_challenges()
        t_board = now()
        with _locked(wd):
            st = load(wd)
            st["board"] = [[r.rank, r.team, r.score] for r in rows]
            st["board_at"] = t_board
            known = st["challenges"]
            todo = []
            for ch in chs:
                e = known.setdefault(ch.id, {"solves": [], "count": None, "fetched": None})
                e.update(name=ch.name, category=ch.category, points=ch.points)
                n = _count(ch.raw)
                if n == 0:
                    # the board lists no solve: its own rows go, hand-entered ones stay (docstring);
                    # the stored rows are already in order, and a filter keeps it
                    e.update(solves=[s for s in e.get("solves") or () if s.get("hand")], count=0)
                elif n is None or e.get("fetched") is None or e.get("count") != n:
                    todo.append(ch.id)
            todo.sort(key=lambda c: (known[c].get("fetched") is not None, known[c].get("fetched") or 0.0))
            stop: NotSupported | None = None
            for i, cid in enumerate(todo):
                if i >= max_solves:
                    res.pending = todo[i:]
                    break
                why = busy(w) if (w is not None and not force and i) else None
                if why:
                    res.pending = todo[i:]
                    res.deferred = f"stopped after {i} solves read(s): {why}"
                    break
                try:
                    solves = challenge_solves(gate, cid)
                except NotSupported as e:
                    stop = e
                    res.pending = todo[i:]
                    break
                except PlatformError as e:
                    res.errors.append(str(e))
                    continue
                e = known[cid]
                before = first_blood(e)
                read = [{"account": s.account, "at": s.at, "account_id": s.account_id} for s in solves]
                hand = [s for s in e.get("solves") or () if s.get("hand")
                        and not any(same_team(s.get("account"), r["account"]) for r in read)]
                e["solves"] = _ordered(read + hand) if hand else read
                e["count"] = _count(next(c.raw for c in chs if c.id == cid)) or len(solves)
                e["fetched"] = now()
                res.fetched.append(cid)
                after = first_blood(e)
                if after and (before is None or (before["account"], before["at"]) != (after["account"], after["at"])):
                    res.first_bloods.append({"challenge_id": cid, "account": after["account"], "at": after["at"],
                                             "ours": same_team(after["account"], team) if team else None})
            st["updated"] = now()
            _save(wd, st)
            ours = [r for r in st["board"] if same_team(r[1], team)] if team else []
            top = st["board"][:keep_rows]
            snap = top + [r for r in ours if r not in top]
            _append(wd, [{"ts": t_board, "event": "board", "rows": snap},
                         *({"ts": t_board, "event": "first_blood", **fb} for fb in res.first_bloods)])
    res.board_rows, res.challenges = len(rows), len(chs)
    if stop is not None:
        raise NotSupported(f"{stop} (the standings were saved; {len(res.pending)} challenge(s) not read)")
    return res


def watch(gate: Any, *, cycles: int | None = None, interval_s: float = DEFAULT_INTERVAL_S,
          sleep: Callable[[float], None] = time.sleep, on_result: Callable[[IngestResult], None] | None = None,
          on_error: Callable[[PlatformError], None] | None = None, **kw: Any) -> list[IngestResult]:
    """ingest() every interval_s, `cycles` times (None: until interrupted). A platform failure of one
    cycle goes to on_error and the next cycle runs; NotSupported / NotAllowed stop the watch (raised)."""
    if cycles is not None and (not isinstance(cycles, int) or cycles < 1):
        raise ValueError(f"cycles must be an integer >= 1 or None, got {cycles!r}")
    if not interval_s > 0:
        raise ValueError(f"interval_s must be > 0, got {interval_s!r}")
    out: list[IngestResult] = []
    n = 0
    while cycles is None or n < cycles:
        if n:
            sleep(interval_s)
        n += 1
        try:
            r = ingest(gate, **kw)
        except NotSupported:
            raise
        except PlatformError as e:
            if on_error is not None:
                on_error(e)
            continue
        out.append(r)
        if on_result is not None:
            on_result(r)
    return out


# ------------------------------------------------------------------------------------------ hand entry

def record_solve(workdir: Path, challenge_id: str, account: str, at: float | None = None, *,
                 category: str | None = None, name: str | None = None, team: str | None = None,
                 delete: bool = False, now: Callable[[], float] = time.time) -> dict:
    """Enter (or, delete=True, remove) one team's solve of one challenge by hand (module docstring:
    Hand entry). No request is sent, on any platform kind. `team` (our board name) only sets the
    first_blood event's `ours`. Returns the challenge's entry as stored."""
    cid = str(challenge_id).strip() if challenge_id is not None else ""
    who = str(account).strip() if account is not None else ""
    if not cid:
        raise ScoreboardError("record: a challenge id is required")
    if not who:
        raise ScoreboardError("record: a team name is required")
    if not delete and (not isinstance(at, (int, float)) or isinstance(at, bool) or not math.isfinite(at)):
        raise ScoreboardError(f"record: the solve time must be epoch seconds, got {at!r}")
    wd = Path(workdir)
    with _locked(wd):
        st = load(wd)
        known = st["challenges"]
        if delete and cid not in known:
            raise ScoreboardError(f"record --delete: challenge {cid} is not in the store")
        e = known.setdefault(cid, {"solves": [], "count": None, "fetched": None})
        e.setdefault("name", None)
        e.setdefault("category", None)
        if name is not None:
            e["name"] = name
        if category is not None:
            e["category"] = category
        solves = list(e.get("solves") or ())
        if any(same_team(s.get("account"), who) and not s.get("hand") for s in solves):
            raise ScoreboardError(f"record: the board already records a solve of challenge {cid} by {who!r}; "
                                  "its own time wins over a hand entry")
        keep = [s for s in solves if not (s.get("hand") and same_team(s.get("account"), who))]
        if delete and len(keep) == len(solves):
            raise ScoreboardError(f"record --delete: no hand-entered solve of challenge {cid} by {who!r}")
        before = first_blood(e)
        if not delete:
            keep.append({"account": who, "at": float(at), "account_id": None, "hand": True})
        e["solves"] = _ordered(keep)
        after = first_blood(e)
        t = now()
        st["updated"] = t
        _save(wd, st)
        if after and (before is None or (before["account"], before["at"]) != (after["account"], after["at"])):
            _append(wd, [{"ts": t, "event": "first_blood", "challenge_id": cid, "account": after["account"],
                          "at": after["at"], "ours": same_team(after["account"], team) if team else None,
                          "source": "hand"}])
        return e


# ------------------------------------------------------------------------------------------ bench

@dataclass(frozen=True)
class BenchRow:
    challenge_id: str
    name: str
    lane: str
    status: str                            # won | lost | unsolved | uncontested
    rival: str | None                      # the first other team to solve it
    rival_at: float | None
    ours_at: float | None                  # the time gap_s uses
    ours_source: str | None                # board | hand | ledger | None
    gap_s: float | None                    # ours - rival (negative: we led)
    place: int | None                      # our place among every solve (1 = first blood)
    release_at: float | None
    ours_elapsed_s: float | None
    rival_elapsed_s: float | None
    target_s: float | None
    verdict: str                           # PASS | FAIL | NOTARGET


@dataclass(frozen=True)
class LaneBench:
    lane: str
    challenges: int
    won: int
    lost: int
    unsolved: int
    uncontested: int
    passed: int
    failed: int
    notarget: int
    median_gap_s: float | None
    best_gap_s: float | None
    worst_gap_s: float | None
    lost_to: dict


@dataclass
class Bench:
    team: str
    margin: float
    rows: list[BenchRow]
    lanes: list[LaneBench]
    notes: list[str]

    def to_dict(self) -> dict:
        return {"team": self.team, "margin": self.margin, "rows": [asdict(r) for r in self.rows],
                "lanes": [asdict(x) for x in self.lanes], "notes": self.notes}


def ledger_accepted(records: Iterable[dict]) -> dict[str, float]:
    """{challenge id: our first accepted time} from the ledger (ctf/replay.py's accepted stage)."""
    out: dict[str, float] = {}
    for s in _replay.stage_events(records):
        if s.stage == "accepted" and s.challenge_id and s.challenge_id not in out:
            out[s.challenge_id] = s.ts
    return out


def release_times(records: list[dict]) -> tuple[dict[str, float], list[tuple[float, float]]]:
    """({challenge id: the T0 of its wave}, [(wave start, wave T0)...]) from the ledger's wave_open,
    detect and stage records (replay.assign: a detect names the wave, else the last wave opened at or
    before the challenge's first stage)."""
    st = _replay.stage_events(records)
    wl = _replay.waves(records, stages=st)
    t0 = {w.label: w.t0 for w in wl}
    return ({cid: t0[label] for cid, label in _replay.assign(st, wl).items() if label in t0},
            sorted((w.start, w.t0) for w in wl))


def _release_of(cid: str, rel: Mapping[str, float], wave_starts: list[tuple[float, float]],
                first_seen: float | None, t0: float | None) -> float | None:
    """The release of one challenge: its ledger wave; else (a challenge our ledger never staged) the
    last wave opened at or before its first board solve, as replay.assign places a stage; else t0."""
    if cid in rel:
        return rel[cid]
    if first_seen is not None:
        opened = [w0 for start, w0 in wave_starts if start <= first_seen]
        if opened:
            return opened[-1]
    return t0


def _verdict(ours_el: float | None, rival_el: float | None, margin: float, solved: bool) -> tuple[float | None, str]:
    if rival_el is None:
        return None, NOTARGET
    target = round(rival_el * (1.0 - margin), 3)
    if not solved:
        return target, FAIL
    if ours_el is None:
        return target, NOTARGET
    return target, PASS if ours_el <= target else FAIL


def bench(state: Mapping[str, Any], records: list[dict], *, team: str | None,
          margin: float = DEFAULT_MARGIN, t0: float | None = None, lane: str | None = None) -> Bench:
    """Per-challenge and per-lane first-blood benchmark (module docstring). `team` is our team as the
    board names it (required: without it a rival cannot be told from us)."""
    if not team or not str(team).strip():
        raise ScoreboardError("bench needs our team's board name: set platform.team in the event profile "
                              "or pass --team")
    if not 0.0 <= margin < 1.0:
        raise ValueError(f"margin must be in [0, 1), got {margin!r}")
    challenges = state.get("challenges") or {}
    acc = ledger_accepted(records)
    rel, wave_starts = release_times(records)
    notes: list[str] = []
    if not wave_starts and t0 is None:
        notes.append("no wave_open in the ledger and no --t0: release times unknown, every verdict NOTARGET")
    if not any(same_team(s.get("account"), team) for e in challenges.values() for s in e.get("solves") or ()):
        if any(e.get("solves") for e in challenges.values()):
            notes.append(f"no solve on the board is by {team!r}: check the team name (our times come from "
                         "the ledger only)")
    rows: list[BenchRow] = []
    for cid in sorted(set(challenges) | set(acc), key=lambda c: (len(c), c)):
        e = challenges.get(cid) or {}
        cat = str(e.get("category") or "").strip() or UNKNOWN_LANE
        if lane is not None and cat.casefold() != lane.casefold():
            continue
        timed = sorted((s for s in e.get("solves") or () if isinstance(s.get("at"), (int, float))),
                       key=lambda s: s["at"])
        mine = next((s for s in timed if same_team(s.get("account"), team)), None)
        rivals = [s for s in timed if not same_team(s.get("account"), team)]
        rival = rivals[0] if rivals else None
        led = acc.get(cid)
        if mine is not None:
            ours_at, source = float(mine["at"]), ("hand" if mine.get("hand") else "board")
        elif led is not None:
            ours_at, source = led, "ledger"
        else:
            ours_at, source = None, None
        if ours_at is None and rival is None:
            continue
        rival_at = float(rival["at"]) if rival else None
        if ours_at is None:
            status = UNSOLVED
        elif rival_at is None:
            status = UNCONTESTED
        else:
            status = WON if ours_at <= rival_at else LOST
        gap = round(ours_at - rival_at, 3) if ours_at is not None and rival_at is not None else None
        place = (1 + sum(1 for s in rivals if s["at"] < ours_at)) if ours_at is not None else None
        release = _release_of(cid, rel, wave_starts, float(timed[0]["at"]) if timed else None, t0)
        ours_el = rival_el = None
        if release is not None:
            ref = led if led is not None else ours_at
            ours_el = round(ref - release, 3) if ref is not None else None
            rival_el = round(rival_at - release, 3) if rival_at is not None else None
        target, verdict = _verdict(ours_el, rival_el, margin, ours_at is not None)
        rows.append(BenchRow(cid, str(e.get("name") or cid), cat, status, rival["account"] if rival else None,
                             rival_at, ours_at, source, gap, place, release, ours_el, rival_el, target, verdict))
    return Bench(str(team), margin, rows, _lanes(rows), notes)


def _lanes(rows: list[BenchRow]) -> list[LaneBench]:
    out = []
    for name in sorted({r.lane for r in rows}):
        rs = [r for r in rows if r.lane == name]
        gaps = [r.gap_s for r in rs if r.gap_s is not None]
        n = Counter(r.status for r in rs)
        v = Counter(r.verdict for r in rs)
        lost_to = Counter(r.rival for r in rs if r.status in (LOST, UNSOLVED) and r.rival)
        out.append(LaneBench(name, len(rs), n[WON], n[LOST], n[UNSOLVED], n[UNCONTESTED], v[PASS], v[FAIL],
                             v[NOTARGET], round(statistics.median(gaps), 3) if gaps else None,
                             min(gaps) if gaps else None, max(gaps) if gaps else None,
                             dict(lost_to.most_common())))
    return out


def floor_records(b: Bench, *, kind: str) -> dict[str, float]:
    """{mode: the fastest rival first blood after release} for latency.floor_table(records=...)."""
    from .platform import latency
    out: dict[str, float] = {}
    for r in b.rows:
        if r.rival_elapsed_s is None or r.rival_elapsed_s < 0:
            continue
        mode = latency.mode_of(kind, r.challenge_id)
        out[mode] = min(out.get(mode, r.rival_elapsed_s), r.rival_elapsed_s)
    return out


# ------------------------------------------------------------------------------------------ render

def _s(x: float | None) -> str:
    return "-" if x is None else f"{x:+.1f}" if x else "0.0"


def _e(x: float | None) -> str:
    return "-" if x is None else f"{x:.1f}"


def render_bench(b: Bench) -> str:
    lines = [f"First-blood benchmark for {b.team} (target: beat the rival first blood by {b.margin:.0%})", ""]
    if not b.rows:
        lines.append("nothing to compare: no board solve and no accepted challenge in the ledger")
    else:
        lines.append(f"{'lane':<22} {'n':>3} {'won':>4} {'lost':>4} {'unsol':>5} {'alone':>5} "
                     f"{'pass':>4} {'fail':>4} {'gap med':>8} {'worst':>8}  first bloods lost to")
        for x in b.lanes:
            to = ", ".join(f"{t} x{k}" for t, k in list(x.lost_to.items())[:3]) or "-"
            lines.append(f"{x.lane[:22]:<22} {x.challenges:>3} {x.won:>4} {x.lost:>4} {x.unsolved:>5} "
                         f"{x.uncontested:>5} {x.passed:>4} {x.failed:>4} {_s(x.median_gap_s):>8} "
                         f"{_s(x.worst_gap_s):>8}  {to}")
        lines += ["", f"{'id':<8} {'lane':<16} {'status':<11} {'place':>5} {'gap s':>8} {'ours s':>8} "
                      f"{'rival s':>8} {'target':>8} verdict  rival"]
        for r in b.rows:
            lines.append(f"{r.challenge_id[:8]:<8} {r.lane[:16]:<16} {r.status:<11} "
                         f"{r.place if r.place is not None else '-':>5} {_s(r.gap_s):>8} "
                         f"{_e(r.ours_elapsed_s):>8} {_e(r.rival_elapsed_s):>8} {_e(r.target_s):>8} "
                         f"{r.verdict:<8} {r.rival or '-'}")
    for n in b.notes:
        lines.append(f"NOTE {n}")
    return "\n".join(lines)
