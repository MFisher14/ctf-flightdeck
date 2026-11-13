"""Completion-driven agent coordination: no wait polling from model turns (B-239).

At CSCTF 2,169 subagent responses did nothing but coordinate (`send_message`, `wait_agent`,
`list_agents`, `followup_task`, `wait`): $166.70, 18% of the event's subagent spend. 280 of 409
`wait_agent` calls timed out (68%, mean timeout 24 s) and each timeout bought another paid turn; one
agent sent 95 messages. This module replaces the three habits with files and one blocking command:

1. **Block on a completion, not a timed poll.** A parent runs ONE `ctf coord wait TARGET...`; the
   process (no model) checks the targets' files and returns once, when they have completed (or the
   first has, with `--any`). A target is:

       child:ID      (or a bare ID) the child's completion file <workdir>/coord/done/<ID>.json, written by
                     the child's last command: `ctf coord done ID --status done|failed|blocked --summary`
       campaign:AID  a supervised or registered campaign agent (B-178, ctf/campaign.py) reaching done,
                     failed or lost (a dead supervisor or a stale heartbeat reads as lost; nothing written)
       job:ID        a `ctf job` run (B-144, ctf/jobs.py) exiting: exit.json, or lost
       standby:AGENT[=STATE,...]  a warm agent's presence (B-037, ctf/standby.py): by default present
                     (waiting, assigned or left); `=assigned` waits for it to take a claim. `left` or a
                     dead pid end the wait as a failure when not wanted
       claim:CID     the dispatcher's claim (B-004) with intake finished (done/off; failed is a failure)
       msg:LANE      a new relayed finding or decision in the lane (see 2); with `--as AGENT` the agent's
                     inbox cursor, else the lane as it was when the wait began

   The wait refuses a timeout under MIN_TIMEOUT (60 s) unless `--allow-short`: a short timed poll is
   the waste this replaces. A timeout returns 124 with one line per pending target (wait again; no
   digest). Every wait appends one record to <workdir>/coord/waits.jsonl, so `ctf coord stats` shows
   completed vs timed-out waits. Claude Code: run the wait in the background (one notification at
   exit). Codex: run it as one blocking command.

2. **A per-lane message cap behind a no-model relay.** `ctf coord send LANE KIND TEXT --from AGENT`
   delivers only a *new* `finding` or `decision` (RELAYED_KINDS) to <workdir>/coord/lanes/<LANE>/
   msgs.jsonl. Anything else is dropped with the reason and where it belongs instead: another kind
   (`status` -> `ctf orch report`, `question` -> `ctf coord done --status blocked`), a repeat (same
   kind and normalised text already delivered in the lane), or a lane at its cap (LANE_MSG_CAP
   delivered messages; `ctf coord cap LANE N` raises it). Dropped offers go to dropped.jsonl. Readers
   take unseen messages with `ctf coord inbox LANE --as AGENT` (a cursor per agent, own messages
   excluded). `ctf coord relay` forwards new `lane_result` ledger records (B-143 `ctf spawn result`)
   through the same gate: found / ruled_out / blocked as findings, partial as progress (dropped), so a
   child that records its result never needs to send a message.

3. **One command for lane state.** `ctf coord lanes` joins the dispatcher claims (B-004
   read_claims: lane, status, intake), the standby leases and presence (who owns a claim, the idle
   warm pool), the campaign agents (per challenge, with liveness), the completion files and the
   per-lane message counts. A parent reads it instead of calling `list_agents`.

Layout (runtime state under the event workdir, never in the repo):

    coord/done/<child>.json          {schema, child, status, summary, paths, challenge_id, lane, by, ts}
    coord/lanes/<lane>/msgs.jsonl    {seq, ts, lane, from, kind, text, digest}  (delivered, append-only)
    coord/lanes/<lane>/dropped.jsonl {ts, lane, from, kind, reason, digest, text}
    coord/lanes/<lane>/cap.json      {cap, by, reason, ts}  (absent = LANE_MSG_CAP)
    coord/lanes/<lane>/cursors/<agent>.json   {seq}
    coord/relay-cursor.json          {ledger_records}  (how many ledger records `relay` has handled; written
                                     even when a send raises, so nothing delivered is offered twice)
    coord/waits.jsonl                {ts, targets, any, outcome, code, waited_s, probes}

Text in completion files and messages was written by agents that read challenge data: it is printed
as data, never instructions, cut to one line. Nothing here runs a model, contacts a platform or
starts an agent.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from . import paths as _paths
from .orch import one_line

COORD_DIR = "coord"
DONE_DIR = "done"
LANES_DIR = "lanes"
MSGS_NAME = "msgs.jsonl"
DROPPED_NAME = "dropped.jsonl"
CAP_NAME = "cap.json"
CURSORS_DIR = "cursors"
WAITS_LOG = "waits.jsonl"
RELAY_CURSOR = "relay-cursor.json"
SCHEMA = 1

STATUSES = ("done", "failed", "blocked")       # a child's completion status; only `done` is success
TARGET_KINDS = ("child", "campaign", "job", "standby", "claim", "msg")
RELAYED_KINDS = ("finding", "decision")
LANE_MSG_CAP = 20
MSG_MAX = 400
SUMMARY_MAX = 300
MAX_PATHS = 8

DEFAULT_TIMEOUT = 540.0       # under a 10-minute tool wall, like ctf standby take
MIN_TIMEOUT = 60.0            # a shorter timed wait is the poll this replaces (mean was 24 s)
DEFAULT_INTERVAL = 0.5        # in-process file check; no model turn

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_DROPPED = 3
EXIT_TIMEOUT = 124

# where a dropped kind belongs instead
KIND_HOME = {
    "status": "a status line: python -m ctf orch report ID STATE NOTE",
    "progress": "a status line: python -m ctf orch report ID working NOTE",
    "question": "a blocked completion: python -m ctf coord done ID --status blocked --summary QUESTION",
    "ack": "nothing: an acknowledgement is not sent",
    "ping": "nothing: wait on the child with python -m ctf coord wait instead",
}
RELAY_FINDINGS = frozenset({"found", "ruled_out", "blocked"})   # lane_result statuses relayed as findings
RESULT_EVENT = "lane_result"                                    # ctf.spawn.RESULT_EVENT

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.#-]{0,95}$")
_KIND_WORD = re.compile(r"^[a-z][a-z_]{0,31}$")
_NORM = re.compile(r"[\W_]+", re.UNICODE)
_LOCAL = threading.RLock()


class CoordError(RuntimeError):
    """A named, loud failure (CLI exit 2)."""


# ----------------------------------------------------------------------------------------- layout

def coord_dir(workdir: Path | None = None) -> Path:
    return (_paths.workdir() if workdir is None else Path(workdir)) / COORD_DIR


def _safe_id(what: str, value: Any) -> str:
    v = str(value or "").strip()
    if not _ID.match(v) or v in (".", "..") or ".." in v:
        raise CoordError(f"bad {what} {value!r}: letters, digits and _.#- only, at most 96 characters")
    return v


def done_path(workdir: Path | None, child: str) -> Path:
    return coord_dir(workdir) / DONE_DIR / f"{_safe_id('child id', child)}.json"


def lane_dir(workdir: Path | None, lane: str) -> Path:
    return coord_dir(workdir) / LANES_DIR / _safe_id("lane", lane)


def _write_atomic(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}-{threading.get_ident()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p)


def _append(p: Path, rec: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(rec, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def _read_json(p: Path, what: str) -> dict:
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise CoordError(f"{p}: unreadable {what} ({e})") from None
    if not isinstance(rec, dict):
        raise CoordError(f"{p}: {what} is not a JSON object")
    return rec


def _read_jsonl(p: Path, what: str) -> list[dict]:
    if not p.is_file():
        return []
    out = []
    with open(p, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError as e:
                raise CoordError(f"{p}:{n}: corrupt {what} line ({e}); repair or remove it") from None
            if not isinstance(rec, dict):
                raise CoordError(f"{p}:{n}: {what} line is not a JSON object")
            out.append(rec)
    return out


@contextlib.contextmanager
def _flock(p: Path) -> Iterator[None]:
    p.parent.mkdir(parents=True, exist_ok=True)
    with _LOCAL:                                  # flock is per open file: threads need their own guard
        fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


# ------------------------------------------------------------------------------- completion files

def complete(child: str, status: str, summary: str, *, paths: Iterable[str] = (), challenge_id: str | None = None,
             lane: str | None = None, by: str | None = None, replace: bool = False,
             workdir: Path | None = None, clock: Callable[[], float] = time.time) -> dict:
    """A child's last act: write its completion file atomically. One completion per child id; a second
    one refuses (CoordError) unless `replace`, so a parent never sees a result change under it."""
    if status not in STATUSES:
        raise CoordError(f"completion status must be one of {', '.join(STATUSES)}, got {status!r}")
    text = one_line(summary, SUMMARY_MAX)
    if not text:
        raise CoordError("a completion needs a summary: what was found, what failed, or the question")
    ps = [one_line(p, 300) for p in paths if str(p).strip()]
    if len(ps) > MAX_PATHS:
        raise CoordError(f"at most {MAX_PATHS} paths in a completion (got {len(ps)}): point at a folder")
    rec = {"schema": SCHEMA, "child": _safe_id("child id", child), "status": status, "summary": text,
           "paths": ps, "challenge_id": one_line(challenge_id, 64) or None,
           "lane": _safe_id("lane", lane) if lane else None, "by": one_line(by, 64) or None,
           "ts": round(clock(), 3)}
    p = done_path(workdir, child)
    body = json.dumps(rec, indent=1, sort_keys=True) + "\n"
    if replace:
        _write_atomic(p, body)
        return rec
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}-{threading.get_ident()}.tmp")
    tmp.write_text(body, encoding="utf-8")
    try:
        os.link(tmp, p)                           # exclusive: never a half-written or second result
    except FileExistsError:
        raise CoordError(f"child {child!r} already completed ({p}); pass --replace to overwrite") from None
    finally:
        tmp.unlink()
    return rec


def read_completions(workdir: Path | None = None) -> dict[str, dict]:
    """{child: completion record}. An unreadable file is a loud error."""
    d = coord_dir(workdir) / DONE_DIR
    if not d.is_dir():
        return {}
    return {p.stem: _read_json(p, "completion file") for p in sorted(d.glob("*.json"))}


# ----------------------------------------------------------------------------------------- targets

@dataclass(frozen=True)
class Target:
    kind: str
    ident: str
    want: frozenset[str] = frozenset()

    def __str__(self) -> str:
        return f"{self.kind}:{self.ident}" + (f"={','.join(sorted(self.want))}" if self.want else "")


def parse_target(text: str) -> Target:
    from . import standby as _standby
    raw = str(text or "").strip()
    kind, sep, rest = raw.partition(":")
    if not sep:
        kind, rest = "child", raw
    if kind not in TARGET_KINDS:
        raise CoordError(f"unknown target kind {kind!r} in {raw!r}; one of: {', '.join(TARGET_KINDS)}")
    ident, eq, want_s = rest.partition("=")
    want: frozenset[str] = frozenset()
    if eq:
        if kind != "standby":
            raise CoordError(f"{raw!r}: only a standby target takes =STATE")
        want = frozenset(w.strip() for w in want_s.split(",") if w.strip())
        allowed = {_standby.WAITING, _standby.ASSIGNED, _standby.LEFT}
        if not want or not want <= allowed:
            raise CoordError(f"{raw!r}: standby states are {', '.join(sorted(allowed))}")
    return Target(kind, _safe_id(f"{kind} id", ident), want)


@dataclass
class Probe:
    target: Target
    state: str           # "pending" or what the target reached
    done: bool
    ok: bool
    line: str            # one line for the wake message (data, not instructions)
    upto: int = 0        # a msg target: the last lane seq this probe read (the reader's cursor moves here)


def _pending(t: Target, why: str) -> Probe:
    return Probe(t, "pending", False, False, f"{t} pending: {why}")


class _Prober:
    """Reads a target's files. `start()` fixes the baselines (a msg target's start seq)."""

    def __init__(self, workdir: Path, *, as_agent: str | None = None, jobs_root: Path | None = None):
        self.wd = Path(workdir)
        self.as_agent = _safe_id("agent", as_agent) if as_agent else None
        self.jobs_root = jobs_root
        self.base: dict[Target, int] = {}

    def start(self, targets: Iterable[Target]) -> None:
        for t in targets:
            if t.kind == "msg":
                self.base[t] = (cursor(self.wd, t.ident, self.as_agent) if self.as_agent
                                else last_seq(self.wd, t.ident))

    def probe(self, t: Target) -> Probe:
        return getattr(self, f"_{t.kind}")(t)

    def _child(self, t: Target) -> Probe:
        p = done_path(self.wd, t.ident)
        if not p.is_file():
            return _pending(t, "no completion file yet")
        rec = _read_json(p, "completion file")
        status = rec.get("status")
        if status not in STATUSES:
            raise CoordError(f"{p}: completion status {status!r} is not one of {', '.join(STATUSES)}")
        where = ", ".join(x for x in (rec.get("challenge_id"), rec.get("lane")) if x)
        line = f"{t} {status}" + (f" ({where})" if where else "") + f": {one_line(rec.get('summary'))}"
        if rec.get("paths"):
            line += " -> " + " ".join(one_line(x, 200) for x in rec["paths"][:MAX_PATHS])
        return Probe(t, status, True, status == "done", line)

    def _campaign(self, t: Target) -> Probe:
        from . import campaign as _campaign
        camp = _campaign.Campaign(self.wd)
        try:
            st = camp.load()
        except _campaign.CampaignError as e:
            raise CoordError(str(e)) from None
        rec = st["agents"].get(t.ident)
        if rec is None:
            raise CoordError(f"the campaign has no agent {t.ident!r} (python -m ctf campaign status)")
        status = rec.get("status")
        why = ""
        if status == "running":
            alive, why = camp.alive(rec)      # the campaign's own liveness rule; read-only, nothing written
            if alive:
                return _pending(t, "running")
            status = "lost"
        elif status == "lost":
            why = rec.get("lost_reason") or ""
        bits = [f"{t} {status}"]
        if rec.get("rc") is not None:
            bits.append(f"rc={rec['rc']}")
        if rec.get("challenge"):
            bits.append(f"challenge={rec['challenge']}")
        text = one_line(why or rec.get("note") or "")
        if rec.get("log"):
            bits.append(f"log={rec['log']}")
        return Probe(t, status, True, status == "done", " ".join(bits) + (f": {text}" if text else ""))

    def _job(self, t: Target) -> Probe:
        from . import env as _env
        from . import jobs as _jobs
        root = self.jobs_root
        if root is None:
            v = _env.get("CTF_JOBS_DIR")
            root = Path(v).expanduser().resolve() if v else self.wd / "jobs"
        try:
            st = _jobs.state(_jobs.job_dir(root, t.ident))
        except _jobs.JobError as e:
            raise CoordError(str(e)) from None
        if not st.done:
            return _pending(t, _jobs.describe(st))
        return Probe(t, st.state, True, st.wait_code() == _jobs.EXIT_OK,
                     f"{t} {_jobs.describe(st)} -> {st.log}")

    def _standby(self, t: Target) -> Probe:
        from . import dispatch as _dispatch
        from . import standby as _standby
        try:
            rec = _standby.read_presence(self.wd).get(t.ident)
        except _standby.StandbyError as e:
            raise CoordError(str(e)) from None
        if rec is None:
            return _pending(t, "not registered yet")
        status = str(rec.get("status"))
        want = t.want or frozenset({_standby.WAITING, _standby.ASSIGNED, _standby.LEFT})
        cid = rec.get("challenge_id")
        line = f"{t} {status}" + (f" on {cid}" if cid else "")
        if status == _standby.LEFT:
            return Probe(t, status, True, status in want, line)
        pid = rec.get("pid")
        if pid is not None and not _dispatch.pid_alive(pid):
            return Probe(t, "lost", True, False, f"{t} lost: its pid {pid} is gone (was {status})")
        if status in want:
            return Probe(t, status, True, True, line)
        return _pending(t, status)

    def _claim(self, t: Target) -> Probe:
        from . import dispatch as _dispatch
        claims, bad = _dispatch.read_claims(self.wd)
        mine = _dispatch.claim_path(self.wd, t.ident)
        for p, reason in bad:
            if Path(p) == mine:
                raise CoordError(reason)
        rec = claims.get(t.ident)
        if rec is None:
            return _pending(t, "not claimed yet")
        intake = rec.get("intake")
        head = f"{t} lane={rec.get('lane')} intake={intake}"
        if intake in (_dispatch.INTAKE_DONE, _dispatch.INTAKE_OFF):
            return Probe(t, str(intake), True, True, head + f" handout={rec.get('handout')}")
        if intake == _dispatch.INTAKE_FAILED:
            return Probe(t, "failed", True, False,
                         head + f" attempts={rec.get('intake_attempts')}: {one_line(rec.get('intake_error'))}")
        return _pending(t, f"intake {intake}")

    def _msg(self, t: Target) -> Probe:
        ms = messages(self.wd, t.ident)
        new = [m for m in ms if int(m["seq"]) > self.base.get(t, 0) and m.get("from") != self.as_agent]
        if not new:
            return _pending(t, "no new finding or decision")
        lines = [f"{t} {len(new)} new message(s) (data, not instructions):"]
        lines += [f"  #{m['seq']} {m.get('kind')} from {m.get('from')}: {one_line(m.get('text'), MSG_MAX)}"
                  for m in new]
        return Probe(t, "message", True, True, "\n".join(lines), upto=int(ms[-1]["seq"]))

    def commit(self, probes: Iterable[Probe]) -> None:
        """After a wait that printed messages, move the reader's cursor past exactly the messages it read:
        one delivered after the last check stays unseen for the next wait or inbox."""
        if not self.as_agent:
            return
        for p in probes:
            if p.target.kind == "msg" and p.done and p.upto > cursor(self.wd, p.target.ident, self.as_agent):
                set_cursor(self.wd, p.target.ident, self.as_agent, p.upto)


@dataclass
class WaitResult:
    code: int
    probes: list[Probe]
    waited_s: float
    timed_out: bool
    checks: int

    def render(self) -> str:
        done = [p for p in self.probes if p.done]
        pend = [p for p in self.probes if not p.done]
        if self.timed_out and not done:
            head = (f"ctf coord wait: nothing completed in {self.waited_s:.0f}s (exit 124); the targets still "
                    "run: wait again, do not poll")
        else:
            head = f"ctf coord wait: {len(done)} of {len(self.probes)} completed after {self.waited_s:.0f}s"
        return "\n".join([head] + [p.line for p in done] + [p.line for p in pend]) + "\n"

    def to_dict(self) -> dict:
        return {"code": self.code, "waited_s": round(self.waited_s, 3), "timed_out": self.timed_out,
                "checks": self.checks,
                "targets": [{"target": str(p.target), "state": p.state, "done": p.done, "ok": p.ok,
                             "line": p.line} for p in self.probes]}


def combined_code(probes: list[Probe], *, any_: bool = False) -> int:
    done = [p for p in probes if p.done]
    if any_:
        if not done:
            return EXIT_TIMEOUT
        return EXIT_OK if any(p.ok for p in done) else EXIT_FAILED
    if len(done) < len(probes):
        return EXIT_TIMEOUT
    return EXIT_OK if all(p.ok for p in done) else EXIT_FAILED


def wait(targets: Iterable[str | Target], *, workdir: Path | None = None, timeout: float | None = DEFAULT_TIMEOUT,
         any_: bool = False, interval: float = DEFAULT_INTERVAL, as_agent: str | None = None,
         allow_short: bool = False, jobs_root: Path | None = None,
         clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
         wall: Callable[[], float] = time.time, log: bool = True) -> WaitResult:
    """Block, with no model turn, until every target (with `any_`, the first) has completed, or
    `timeout` seconds pass (None = no limit). One file check per `interval` seconds of `clock`."""
    wd = _paths.workdir() if workdir is None else Path(workdir)
    ts = [t if isinstance(t, Target) else parse_target(t) for t in targets]
    if not ts:
        raise CoordError("wait needs at least one target (child:ID, campaign:ID, job:ID, standby:AGENT, "
                         "claim:ID or msg:LANE)")
    if len(set(ts)) != len(ts):
        raise CoordError("a target is named twice")
    if timeout is not None:
        if timeout < 0:
            raise CoordError(f"timeout must be >= 0, got {timeout}")
        if timeout < MIN_TIMEOUT and not allow_short:
            raise CoordError(f"a {timeout:g}s timeout is a timed poll (the waste this replaces): use at least "
                             f"{MIN_TIMEOUT:g}s, no timeout, or --allow-short")
    if interval <= 0:
        raise CoordError(f"interval must be > 0, got {interval}")
    prober = _Prober(wd, as_agent=as_agent, jobs_root=jobs_root)
    prober.start(ts)
    t0 = clock()
    checks = 0
    while True:
        probes = [prober.probe(t) for t in ts]
        checks += 1
        n_done = sum(p.done for p in probes)
        if (any_ and n_done) or n_done == len(probes):
            timed_out = False
            break
        elapsed = clock() - t0
        if timeout is not None and elapsed >= timeout:
            timed_out = True
            break
        sleep(interval if timeout is None else min(interval, timeout - elapsed))
    waited = clock() - t0
    res = WaitResult(combined_code(probes, any_=any_), probes, waited, timed_out, checks)
    prober.commit(probes)
    if log:
        _append(coord_dir(wd) / WAITS_LOG,
                {"ts": round(wall(), 3), "targets": [str(t) for t in ts], "any": any_,
                 "outcome": "timeout" if timed_out else "completed", "code": res.code,
                 "waited_s": round(waited, 3), "checks": checks, "as": as_agent})
    return res


# ------------------------------------------------------------------------------------ the relay

@dataclass
class Verdict:
    lane: str
    kind: str
    delivered: bool
    reason: str            # delivered | kind | repeat | cap
    seq: int | None = None
    detail: str = ""

    def line(self) -> str:
        if self.delivered:
            return f"delivered #{self.seq} to lane {self.lane}"
        return f"not sent ({self.reason}): {self.detail}"


def digest(kind: str, text: str) -> str:
    norm = _NORM.sub(" ", str(text).casefold()).strip()
    return hashlib.sha256(f"{kind}\0{norm}".encode("utf-8")).hexdigest()[:16]


def messages(workdir: Path | None, lane: str) -> list[dict]:
    """The lane's delivered messages, oldest first."""
    return _read_jsonl(lane_dir(workdir, lane) / MSGS_NAME, "lane message")


def dropped(workdir: Path | None, lane: str) -> list[dict]:
    return _read_jsonl(lane_dir(workdir, lane) / DROPPED_NAME, "dropped message")


def last_seq(workdir: Path | None, lane: str) -> int:
    ms = messages(workdir, lane)
    return int(ms[-1]["seq"]) if ms else 0


def lane_cap(workdir: Path | None, lane: str) -> int:
    p = lane_dir(workdir, lane) / CAP_NAME
    if not p.is_file():
        return LANE_MSG_CAP
    cap = _read_json(p, "lane cap").get("cap")
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 0:
        raise CoordError(f"{p}: cap must be a non-negative integer, got {cap!r}")
    return cap


def set_cap(workdir: Path | None, lane: str, cap: int, *, by: str, reason: str,
            clock: Callable[[], float] = time.time) -> dict:
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 0:
        raise CoordError(f"cap must be a non-negative integer, got {cap!r}")
    why = one_line(reason, 200)
    if not why:
        raise CoordError("raising or lowering a lane cap needs a reason")
    rec = {"cap": cap, "by": one_line(by, 64) or "player", "reason": why, "ts": round(clock(), 3)}
    _write_atomic(lane_dir(workdir, lane) / CAP_NAME, json.dumps(rec, indent=1) + "\n")
    return rec


def send(lane: str, kind: str, text: str, *, sender: str, workdir: Path | None = None,
         clock: Callable[[], float] = time.time) -> Verdict:
    """Offer one message to the lane. Delivered only when it is a finding or a decision, not a repeat,
    and the lane is under its cap; otherwise recorded in dropped.jsonl with the reason."""
    lane = _safe_id("lane", lane)
    kind = str(kind or "").strip().lower()
    if not _KIND_WORD.match(kind):
        raise CoordError(f"bad message kind {kind!r}; a finding or a decision is relayed")
    sender = _safe_id("sender", sender)
    body = one_line(text, MSG_MAX)
    if not body:
        raise CoordError("an empty message is not sent")
    d = lane_dir(workdir, lane)
    dg = digest(kind, body)
    with _flock(d / ".lock"):
        ms = messages(workdir, lane)
        reason, detail = "delivered", ""
        if kind not in RELAYED_KINDS:
            reason = "kind"
            detail = (f"only a new {' or '.join(RELAYED_KINDS)} is relayed; a {kind} belongs in "
                      + KIND_HOME.get(kind, "a status line (ctf orch report) or the completion file"))
        elif any(m.get("digest") == dg for m in ms):
            reason, detail = "repeat", f"lane {lane} already has this {kind}"
        else:
            cap = lane_cap(workdir, lane)
            if len(ms) >= cap:
                reason = "cap"
                detail = (f"lane {lane} is at its cap of {cap} messages: put it in the completion file or a "
                          f"lane result; the player raises the cap with python -m ctf coord cap {lane} N")
        now = round(clock(), 3)
        if reason != "delivered":
            _append(d / DROPPED_NAME, {"ts": now, "lane": lane, "from": sender, "kind": kind,
                                       "reason": reason, "digest": dg, "text": body})
            return Verdict(lane, kind, False, reason, None, detail)
        seq = (int(ms[-1]["seq"]) if ms else 0) + 1
        _append(d / MSGS_NAME, {"seq": seq, "ts": now, "lane": lane, "from": sender, "kind": kind,
                                "text": body, "digest": dg})
        return Verdict(lane, kind, True, "delivered", seq)


def cursor(workdir: Path | None, lane: str, agent: str) -> int:
    p = lane_dir(workdir, lane) / CURSORS_DIR / f"{_safe_id('agent', agent)}.json"
    if not p.is_file():
        return 0
    seq = _read_json(p, "inbox cursor").get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise CoordError(f"{p}: cursor seq must be a non-negative integer, got {seq!r}")
    return seq


def set_cursor(workdir: Path | None, lane: str, agent: str, seq: int) -> None:
    p = lane_dir(workdir, lane) / CURSORS_DIR / f"{_safe_id('agent', agent)}.json"
    _write_atomic(p, json.dumps({"seq": int(seq)}) + "\n")


def inbox(lane: str, agent: str, *, workdir: Path | None = None, peek: bool = False) -> list[dict]:
    """The lane's messages this agent has not seen (its own excluded). Advances its cursor unless peek."""
    lane = _safe_id("lane", lane)
    agent = _safe_id("agent", agent)
    ms = messages(workdir, lane)
    seen = cursor(workdir, lane, agent)
    new = [m for m in ms if int(m["seq"]) > seen and m.get("from") != agent]
    if not peek and ms and int(ms[-1]["seq"]) > seen:
        set_cursor(workdir, lane, agent, int(ms[-1]["seq"]))
    return new


def relay(workdir: Path | None = None, *, clock: Callable[[], float] = time.time) -> tuple[list[Verdict], list[str]]:
    """Forward the ledger's new `lane_result` records through the gate. Returns (verdicts, problems):
    a record whose lane is not a usable lane id is a named problem, not skipped quietly."""
    from . import ledger as _ledger
    wd = _paths.workdir() if workdir is None else Path(workdir)
    cpath = coord_dir(wd) / RELAY_CURSOR
    with _flock(coord_dir(wd) / ".relay.lock"):
        done = 0
        if cpath.is_file():
            done = _read_json(cpath, "relay cursor").get("ledger_records")
            if not isinstance(done, int) or isinstance(done, bool) or done < 0:
                raise CoordError(f"{cpath}: ledger_records must be a non-negative integer, got {done!r}")
        try:
            recs = list(_ledger.read(wd))
        except ValueError as e:
            raise CoordError(str(e)) from None
        if len(recs) < done:
            raise CoordError(f"the ledger has {len(recs)} records but {cpath} says {done} were relayed: the "
                             "ledger was replaced; remove the cursor to relay it from the start")
        verdicts: list[Verdict] = []
        problems: list[str] = []
        upto = done                  # records fully handled; the cursor moves to here even when a send
        try:                         # raises (OSError), so a delivered record is never offered twice
            for i, r in enumerate(recs[done:], done + 1):
                if r.get("event") == RESULT_EVENT:
                    status = r.get("status")
                    kind = "finding" if status in RELAY_FINDINGS else "progress"
                    text = f"{r.get('challenge_id')} {status}: {r.get('summary')}"
                    if r.get("paths"):
                        text += " -> " + " ".join(str(x) for x in r["paths"])
                    try:
                        verdicts.append(send(str(r.get("lane") or ""), kind, text,
                                             sender=str(r.get("spawn_id") or "ledger"), workdir=wd, clock=clock))
                    except CoordError as e:
                        problems.append(f"ledger record {i} ({RESULT_EVENT}): {e}")
                upto = i
        finally:
            _write_atomic(cpath, json.dumps({"ledger_records": upto}) + "\n")
    return verdicts, problems


def lane_names(workdir: Path | None = None) -> list[str]:
    d = coord_dir(workdir) / LANES_DIR
    return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []


def lane_counts(workdir: Path | None = None) -> dict[str, dict]:
    out = {}
    for lane in lane_names(workdir):
        dr = dropped(workdir, lane)
        out[lane] = {"delivered": len(messages(workdir, lane)), "dropped": len(dr),
                     "dropped_by": {k: sum(1 for x in dr if x.get("reason") == k) for k in ("kind", "repeat", "cap")
                                    if any(x.get("reason") == k for x in dr)},
                     "cap": lane_cap(workdir, lane)}
    return out


# ------------------------------------------------------------------------------- the lane board

@dataclass
class LaneRow:
    challenge_id: str
    lane: str
    name: str = ""
    claim: str = ""          # claim status (dispatched, ...)
    intake: str = ""
    owner: str | None = None  # the standby agent holding its lease
    agents: list[str] = field(default_factory=list)       # campaign agents "id:status"
    completions: list[str] = field(default_factory=list)  # "child:status"


@dataclass
class Board:
    rows: list[LaneRow]
    lanes: dict[str, dict]            # message counts per message lane
    idle: list[str]                   # warm agents waiting with no claim
    loose_agents: list[str]           # campaign agents on no claimed challenge
    loose_completions: list[str]
    problems: list[str]

    def to_dict(self) -> dict:
        return {"rows": [r.__dict__ for r in self.rows], "lanes": self.lanes, "idle": self.idle,
                "loose_agents": self.loose_agents, "loose_completions": self.loose_completions,
                "problems": self.problems}


def _id_key(cid: str) -> tuple:
    return tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"(\d+)", cid) if x)


def board(workdir: Path | None = None) -> Board:
    """Every lane's state from files, no agent asked: claims, leases, warm pool, campaign agents,
    completions and message counts. Unreadable claims are listed as problems."""
    from . import campaign as _campaign
    from . import dispatch as _dispatch
    from . import standby as _standby
    wd = _paths.workdir() if workdir is None else Path(workdir)
    claims, bad = _dispatch.read_claims(wd)
    problems = [r for _, r in bad]
    try:
        leases = _standby.read_leases(wd)
        presence = _standby.read_presence(wd)
    except _standby.StandbyError as e:
        raise CoordError(str(e)) from None
    camp = _campaign.Campaign(wd)
    try:
        cst = camp.load()
    except _campaign.CampaignError as e:
        raise CoordError(str(e)) from None
    rows = {cid: LaneRow(cid, str(c.get("lane") or "-"), one_line(c.get("name"), 40), str(c.get("status") or ""),
                         str(c.get("intake") or ""), (leases.get(cid) or {}).get("agent"))
            for cid, c in claims.items()}
    loose_agents = []
    for aid, rec in sorted(cst["agents"].items()):
        status = rec.get("status")
        if status == "running" and not camp.alive(rec)[0]:
            status = "lost?"           # not yet reconciled: the supervisor or heartbeat is gone
        tag = f"{aid}:{status}"
        ch = rec.get("challenge")
        (rows[ch].agents if ch in rows else loose_agents).append(tag)
    loose_done = []
    for child, rec in read_completions(wd).items():
        tag = f"{child}:{rec.get('status')}"
        ch = rec.get("challenge_id")
        (rows[ch].completions if ch in rows else loose_done).append(tag)
    idle = [a for a, r in sorted(presence.items())
            if r.get("status") == _standby.WAITING
            and (r.get("pid") is None or _dispatch.pid_alive(r.get("pid")))]
    ordered = sorted(rows.values(), key=lambda r: (r.lane, _id_key(r.challenge_id)))
    return Board(ordered, lane_counts(wd), idle, loose_agents, loose_done, problems)


def render_board(b: Board, *, width: int = 120) -> str:
    out: list[str] = []
    lanes = sorted({r.lane for r in b.rows} | set(b.lanes))
    for lane in lanes:
        c = b.lanes.get(lane)
        msg = f"  msgs {c['delivered']}/{c['cap']}" + (f" ({c['dropped']} dropped)" if c["dropped"] else "") if c else ""
        out.append(f"LANE {lane}{msg}")
        for r in (x for x in b.rows if x.lane == lane):
            bits = [f"  {r.challenge_id}", r.name or "-", f"claim={r.claim}", f"intake={r.intake}"]
            if r.owner:
                bits.append(f"owner={r.owner}")
            if r.agents:
                bits.append("agents=" + ",".join(r.agents))
            if r.completions:
                bits.append("done=" + ",".join(r.completions))
            line = " ".join(bits)
            out.append(line if len(line) <= width else line[: width - 3] + "...")
    if b.idle:
        out.append("POOL waiting: " + ", ".join(b.idle))
    if b.loose_agents:
        out.append("AGENTS on no claim: " + ", ".join(b.loose_agents))
    if b.loose_completions:
        out.append("DONE on no claim: " + ", ".join(b.loose_completions))
    for p in b.problems:
        out.append(f"PROBLEM: {p}")
    if not out:
        out.append("no claims, agents, completions or lane messages yet")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------------------- stats

def stats(workdir: Path | None = None) -> dict:
    """How the coordination went: waits completed vs timed out, messages delivered vs dropped."""
    waits = _read_jsonl(coord_dir(workdir) / WAITS_LOG, "wait record")
    lanes = lane_counts(workdir)
    return {"waits": len(waits),
            "completed": sum(1 for w in waits if w.get("outcome") == "completed"),
            "timed_out": sum(1 for w in waits if w.get("outcome") == "timeout"),
            "delivered": sum(c["delivered"] for c in lanes.values()),
            "dropped": sum(c["dropped"] for c in lanes.values()),
            "lanes": lanes}
