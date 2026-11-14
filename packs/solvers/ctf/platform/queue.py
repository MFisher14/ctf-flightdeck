"""The cross-process submit queue (B-006): one queue for every solver process of an event.

    gate = get_adapter(profile)        # queue.install(gate) has already run
    gate.submit(cid, flag, provenance="...")   # submit on sight: returns the verdict

Why. The CSCTF client paced submissions per process, so about 20 parallel solvers did not pace each
other; wave 1 sat behind "You're submitting flags too fast" for about 15 minutes and 13 flags waited
a median 387 s, under hand-built retry loops and an "orchestrator submits" rule. This queue lets
every solver submit the moment it has a flag, and keeps the team inside the platform's limits:

  team budget        at most submit.per_minute sends in any 60 s window, from every process
  spacing            at least submit.interval_s between any two sends, and
                     submit.per_challenge_interval_s between two sends on one challenge
  shared pause       a rate_limited answer pauses every process (Retry-After when the platform
                     gives one, else 20 s doubling to 120 s); a paused answer waits 30 s
  automatic retry    a rate_limited or paused answer (not judged) is re-sent by the same call
                     until it is judged or submit.max_hold_s has passed; then it stays queued
  send errors        a send that raises (network error, timeout) is recorded as an unjudged
                     "error" attempt and its spool is kept, so `submit-queue drain` resends it
                     through the gate (dedupe and all); the call re-raises. It is not resent
                     in-call: a timed-out POST may have been judged, and a blind resend could add a
                     second wrong answer on the platform that the ledger never saw.
  dedupe             a value already judged on a challenge is never re-sent, and nothing is sent
                     on a challenge (or answer id) the team already got accepted
  atomic rules       the gate's checks (wrong_answer_stop, guess_budget, dedupe), the send and the
                     ledger record run under one per-challenge lock, so two processes cannot both
                     take the last allowed wrong answer. The lock is not held while a call waits
                     for its turn: it is dropped for the sleep and the checks run again before the
                     send, and a caller waits for the lock only until its own max_hold_s deadline
  attempt ledger     every answered send is a "platform.submit" record (ctf/platform/rules.py);
                     each finished call adds a "submit.done" record (attempts, held_s, status)
  timed fast path    a batch for a timed attempt (B-044: req.attempt with a deadline, a ranked
                     retry, or any AttemptRef on a /time_trial or /mastery id, deadline or not)
                     skips the per-challenge spacing (the team budget, spacing and shared pause
                     still hold) and is never spooled: it is dead when its attempt ends. With a
                     deadline it is also refused unsent once deadline - DEADLINE_MARGIN_S has
                     passed and held at most until then; without one (Day 8 replies carried a
                     null deadline) it is held at most max_hold_s, then dropped, not queued.
                     The cutoff compares this machine's clock with the server's deadline as
                     given: no skew allowance beyond the margin (keep the clock NTP-synced).
                     A ranked Hall of Fame retry (attempt.ranked_retry) is deduped against its
                     own attempt's records only; a partly banked batch (accepted, answers
                     remaining) does not make the challenge "solved"
  spool              a request is written to <workdir>/submitq/pending/ before its first send and
                     removed when it is judged or refused. A spool file is flock-held while its
                     call runs, so one left unlocked is orphaned (its process died, it outran
                     max_hold_s, or its send raised): `python -m ctf submit-queue drain` sends it
                     again through the gate. A rotating flag (ctf.dynamic) is never spooled: it is
                     dead within minutes. A spooled sweep send (B-173) is resent only while its
                     authorization is valid and claimed by a run (EventRules.check), and drain
                     paces it: at least sweep.interval_s after the last send on that challenge,
                     the same spacing the sweep runner keeps.

State lives under the event workdir (<workdir>/submitq/), next to the ledger it protects, so every
checkout and worktree playing one event shares it. The platform's own limit is not known exactly
(CTFd answers "ratelimited" past a per-minute count); the per-minute default (10) is a guess to tune
per event in the profile's [submit] table.

A queue never touches the disk for a request the stateless checks refuse (manual mode, provenance,
format, confirm mode): those return before any lock or spool exists.
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator

from .. import ledger, paths
from ..event import EventProfile, SubmitPace
from .base import SubmitResult, SubmitStatus
from .gamemaster import is_timed
from .policy import AttemptRef, SubmitGate, SubmitRequest, _refuse, base_checks
from .rules import EVENT as SUBMIT_EVENT
from .rules import challenge_key

DIR_NAME = "submitq"
WINDOW_S = 60.0                 # the team budget's window
RATELIMIT_PAUSE_S = 20.0        # first shared pause after a rate_limited answer with no Retry-After
RATELIMIT_PAUSE_MAX_S = 120.0   # the pause doubles on repeated rate limits, up to this
PAUSED_WAIT_S = 30.0            # wait after a "paused" answer (the event is paused) before re-sending
RETRY_STATUSES = (SubmitStatus.RATE_LIMITED, SubmitStatus.PAUSED)
DONE_EVENT = "submit.done"
ERROR_STATUS = "error"          # the ledger status of a send that raised (unjudged)
LOCK_POLL_S = 0.05              # how often a caller re-tries a busy challenge lock

DUPLICATE = "duplicate"         # refusal reasons start with one of these words
SOLVED = "solved"
EXPIRED = "expired"             # a timed batch whose attempt deadline (less the margin) has passed
DEADLINE_MARGIN_S = 0.3         # a timed batch is not sent this close to its attempt's deadline (the
                                # Huntress tools record no rejection with under 0.3 s on the clock)


class QueueError(RuntimeError):
    """The queue's state cannot be used (unwritable workdir, a corrupt spool file)."""


def _sha(flag: str) -> str:
    return hashlib.sha256(flag.encode("utf-8")).hexdigest()


def _record_sha(rec: dict) -> str | None:
    if "flag_sha256" in rec:
        return rec["flag_sha256"]
    if "flag" in rec:
        return _sha(str(rec["flag"]))
    return None


def _attempt_ref(d: dict) -> AttemptRef:
    pool = tuple((str(k), bool(v)) for k, v in d.get("pool") or ())
    return AttemptRef(attempt_id=d.get("attempt_id"), deadline=d.get("deadline"),
                      ranked_retry=bool(d.get("ranked_retry")), eligible=d.get("eligible"),
                      origin=str(d.get("origin") or "unknown"), pool=pool)


class SubmitQueue:
    def __init__(self, profile: EventProfile, *, workdir: Path | None = None,
                 pace: SubmitPace | None = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep, window_s: float = WINDOW_S):
        self.profile = profile
        self.pace = pace if pace is not None else profile.submit
        self._workdir = workdir
        self._clock = clock
        self._sleep = sleep
        self.window_s = float(window_s)

    # ------------------------------------------------------------------------------- places
    @property
    def workdir(self) -> Path:
        return Path(self._workdir) if self._workdir is not None else paths.workdir(self.profile.slug)

    @property
    def dir(self) -> Path:
        return self.workdir / DIR_NAME

    @property
    def state_path(self) -> Path:
        return self.dir / "pace.json"

    @property
    def pending_dir(self) -> Path:
        return self.dir / "pending"

    def _mkdirs(self) -> None:
        try:
            (self.dir / "locks").mkdir(parents=True, exist_ok=True)
            self.pending_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise QueueError(f"submit queue state dir {self.dir} is unusable ({e}); refusing to submit "
                             "unqueued (set CTF_WORKDIR to a writable folder)") from e

    @contextlib.contextmanager
    def _flock(self, path: Path) -> Iterator[None]:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)        # closing the descriptor drops the lock

    def _lock_path(self, challenge_id: str) -> Path:
        name = hashlib.sha256(challenge_key(challenge_id).encode("utf-8")).hexdigest()[:24]
        return self.dir / "locks" / f"{name}.lock"

    @contextlib.contextmanager
    def challenge_lock_until(self, challenge_id: str, deadline: float) -> Iterator[bool]:
        """The cross-process lock for one challenge (a multi-answer id locks its whole challenge),
        waited for only until `deadline`: yields True when held, False when the deadline passed
        first (nothing is held then)."""
        fd = os.open(self._lock_path(challenge_id), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held = True
                    break
                except BlockingIOError:
                    if self._clock() >= deadline:
                        held = False
                        break
                    self._sleep(LOCK_POLL_S)
            yield held
        finally:
            os.close(fd)        # closing the descriptor drops the lock

    # ------------------------------------------------------------------------------- pace state
    def _read(self) -> dict:
        try:
            st = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except ValueError:
            # A torn state file must not wedge the queue (the lock still serialises us and the next
            # write repairs it); pace conservatively: a send "just now", the budget spent.
            now = self._clock()
            return {"last_send": now, "sends": [now] * self.pace.per_minute}
        return st if isinstance(st, dict) else {}

    def _write(self, st: dict) -> None:
        tmp = self.state_path.with_name(f"pace.tmp{os.getpid()}")
        tmp.write_text(json.dumps(st, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def wait_s(self, st: dict, now: float, challenge_id: str, *, timed: bool = False) -> float:
        """Seconds until a send on `challenge_id` may go, given the shared state. A timed batch
        (timed=True) is not held by the per-challenge spacing."""
        p = self.pace
        waits = [0.0,
                 float(st.get("last_send", 0.0)) + p.interval_s - now,
                 float(st.get("blocked_until", 0.0)) - now]
        last_here = (st.get("by_challenge") or {}).get(challenge_key(challenge_id))
        if last_here is not None and not timed:
            waits.append(float(last_here) + p.per_challenge_interval_s - now)
        recent = sorted(t for t in st.get("sends", ()) if t > now - self.window_s)
        if len(recent) >= p.per_minute:
            waits.append(recent[len(recent) - p.per_minute] + self.window_s - now)
        return max(waits)

    def try_turn(self, challenge_id: str, *, timed: bool = False) -> float | None:
        """Take this send's turn now if it is free and stamp it (None), else return the seconds
        until it comes (nothing stamped). Never sleeps."""
        with self._flock(self.dir / "pace.lock"):
            st = self._read()
            now = self._clock()
            w = self.wait_s(st, now, challenge_id, timed=timed)
            if w > 0:
                return w
            st["sends"] = [t for t in st.get("sends", ()) if t > now - self.window_s] + [now]
            st["last_send"] = now
            by = {k: v for k, v in (st.get("by_challenge") or {}).items()
                  if v > now - max(self.pace.per_challenge_interval_s, self.window_s,
                                   self.profile.sweep.interval_s)}
            by[challenge_key(challenge_id)] = now
            st["by_challenge"] = by
            self._write(st)
            return None

    def fold(self, result: SubmitResult) -> None:
        """Fold one answer into the shared state: a rate limit or a pause holds every process."""
        with self._flock(self.dir / "pace.lock"):
            st = self._read()
            now = self._clock()
            if result.status is SubmitStatus.RATE_LIMITED:
                prev = float(st.get("pause_s", 0.0))
                backoff = min(RATELIMIT_PAUSE_MAX_S, prev * 2 if prev else RATELIMIT_PAUSE_S)
                st["pause_s"] = backoff
                pause = result.retry_after if result.retry_after and result.retry_after > 0 else backoff
                st["blocked_until"] = max(float(st.get("blocked_until", 0.0)), now + pause)
                st["last_block"] = "rate_limited"
            elif result.status is SubmitStatus.PAUSED:
                st["blocked_until"] = max(float(st.get("blocked_until", 0.0)), now + PAUSED_WAIT_S)
                st["last_block"] = "paused"
            elif result.status.judged:
                st["pause_s"] = 0.0
            self._write(st)

    # ------------------------------------------------------------------------------- dedupe check
    def check(self, profile: EventProfile, req: SubmitRequest) -> str | None:
        """A gate check (registered by install): no re-send of a judged value, nothing on a challenge
        the team already got accepted. Runs under the challenge lock when the queue sends."""
        sha = _sha(req.flag)
        att = req.attempt
        ranked = att is not None and att.ranked_retry
        if ranked and not att.attempt_id:
            return (f"{DUPLICATE}: a ranked retry of {req.challenge_id} names no attempt id, so its "
                    "records cannot be told from the first solve's; nothing sent")
        for r in ledger.read(self.workdir):
            if (r.get("event") != SUBMIT_EVENT or r.get("event_slug") != profile.slug
                    or str(r.get("challenge_id")) != req.challenge_id or not r.get("judged")):
                continue
            if ranked and r.get("attempt_id") != att.attempt_id:
                continue                # a ranked retry is a fresh variant: earlier attempts say nothing
            if (r.get("status") in (SubmitStatus.CORRECT.value, SubmitStatus.ALREADY_SOLVED.value)
                    and not r.get("partial")):
                return (f"{SOLVED}: challenge {req.challenge_id} was already accepted "
                        f"({r.get('status')}); nothing to send")
            if _record_sha(r) == sha:
                return (f"{DUPLICATE}: this value was already judged {r.get('status')} on challenge "
                        f"{req.challenge_id}; re-derive it instead of re-sending")
        return None

    # ------------------------------------------------------------------------------- spool
    def _record_error(self, req: SubmitRequest, err: BaseException) -> None:
        """An unjudged "error" attempt in the ledger for a send that raised: it counts toward no
        limit, and dedupe does not block a resend of the value."""
        fields = {"event_slug": self.profile.slug, "challenge_id": req.challenge_id,
                  "status": ERROR_STATUS, "judged": False, "guess": req.guess,
                  "confirmed": req.confirmed, "provenance": req.provenance, "post_stop": False,
                  "error": f"{type(err).__name__}: {str(err)[:300]}"}
        if req.rotating:
            fields["rotating"] = True
        if req.sweep is not None:
            fields["sweep"] = req.sweep
        if self.profile.rules.flag_sharing == "allowed":
            fields["flag"] = req.flag
        else:
            fields["flag_sha256"] = _sha(req.flag)
        ledger.append(SUBMIT_EVENT, workdir=self.workdir, **fields)

    def _spool_record(self, req: SubmitRequest) -> dict:
        rec = {"id": uuid.uuid4().hex, "event_slug": self.profile.slug, "created": self._clock(),
               "pid": os.getpid(), "challenge_id": req.challenge_id, "flag": req.flag,
               "provenance": req.provenance, "confirmed": req.confirmed,
               "allow_nonstandard": req.allow_nonstandard, "guess": req.guess, "sweep": req.sweep}
        if req.answers:     # an untimed batch (a timed one is never spooled): drain resends it whole
            rec["answers"] = [list(p) for p in req.answers]
        if req.attempt is not None:
            rec["attempt"] = dataclasses.asdict(req.attempt)
        return rec

    def _open_spool(self, rec: dict) -> tuple[Path, int]:
        # Written and locked under a temporary name, then renamed: the lock follows the file, so no
        # reader ever sees a spool entry that is unlocked or half written.
        path = self.pending_dir / f"{rec['id']}.json"
        tmp = self.pending_dir / f".{rec['id']}.tmp"
        fd = os.open(tmp, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, json.dumps(rec, sort_keys=True).encode("utf-8"))
        os.fsync(fd)
        os.replace(tmp, path)
        return path, fd

    @staticmethod
    def _close_spool(path: Path, fd: int, *, remove: bool) -> None:
        try:
            if remove:
                path.unlink(missing_ok=True)
        finally:
            os.close(fd)

    def pending(self) -> list[dict]:
        """Every spooled request, with state "in_flight" (a running call holds it) or "orphaned"."""
        out = []
        if not self.pending_dir.is_dir():
            return out
        for path in sorted(self.pending_dir.glob("*.json")):
            try:
                fd = os.open(path, os.O_RDONLY)
            except FileNotFoundError:
                continue                       # finished meanwhile
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    state = "orphaned"
                except BlockingIOError:
                    state = "in_flight"
                rec = self._load_spool(path)
            finally:
                os.close(fd)
            out.append(dict(rec, state=state, path=str(path)))
        return out

    @staticmethod
    def _load_spool(path: Path) -> dict:
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise QueueError(f"spooled submit {path} is unreadable ({e}); inspect and remove it by hand")
        if not isinstance(rec, dict) or not {"challenge_id", "flag", "provenance"} <= set(rec):
            raise QueueError(f"spooled submit {path} lacks challenge_id/flag/provenance")
        return rec

    # ------------------------------------------------------------------------------- submit
    def submit(self, gate: SubmitGate, req: SubmitRequest, *, _spool: tuple[Path, int] | None = None
               ) -> SubmitResult:
        reason = base_checks(gate.profile, req)       # stateless: refuse before any disk state
        if reason:
            if _spool is not None:
                self._close_spool(*_spool, remove=True)
            return _refuse(reason)
        started = self._clock()
        deadline = started + self.pace.max_hold_s
        att = req.attempt
        # A timed attempt is dead when it ends, deadline known or not (Day 8 replies said null).
        timed = att is not None and (att.deadline is not None or att.ranked_retry
                                     or is_timed(challenge_key(req.challenge_id)))
        if timed and att.deadline is not None:
            # This machine's clock against the server's deadline: no skew allowance beyond the margin.
            cutoff = float(req.attempt.deadline) - DEADLINE_MARGIN_S
            if started >= cutoff:
                if _spool is not None:
                    self._close_spool(*_spool, remove=True)
                left = float(req.attempt.deadline) - started
                return _refuse(f"{EXPIRED}: the attempt's deadline is {left:+.1f}s away (under the "
                               f"{DEADLINE_MARGIN_S}s margin); nothing sent on {req.challenge_id}")
            deadline = min(deadline, cutoff)
        dead_at_deadline = req.rotating or timed      # never spooled: dead within minutes / at the deadline
        self._mkdirs()
        spool = _spool
        attempts = 0
        result: SubmitResult | None = None
        keep = False
        try:
            while True:
                # One pass: under the challenge lock, check, then send if the turn is free. The lock
                # is dropped before any sleep, so a waiting call never holds up the challenge.
                with self.challenge_lock_until(req.challenge_id, deadline) as held:
                    if not held:
                        later = LOCK_POLL_S
                        busy = "the challenge lock is held by another call"
                    else:
                        reason = gate.refusal(req)
                        if reason:
                            result = _refuse(reason)
                            break
                        if spool is None and not dead_at_deadline:
                            spool = self._open_spool(self._spool_record(req))
                        later = self.try_turn(req.challenge_id, timed=timed)
                        busy = "team budget, spacing or a shared pause"
                        if later is None:
                            attempts += 1
                            try:
                                result = gate.send(req)
                            except Exception as e:
                                answered = getattr(e, "result", None)
                                if isinstance(answered, SubmitResult):
                                    self.fold(answered)  # RecordError: the platform answered; pace on it
                                else:
                                    keep = not timed     # unjudged: leave it for drain (a timed batch dies)
                                    self._record_error(req, e)
                                    self._done(req, ERROR_STATUS, attempts, started, keep)
                                    if spool is not None:
                                        e.add_note("the send stays queued: fix the cause, then "
                                                   "`python -m ctf submit-queue drain` resends it")
                                raise
                            self.fold(result)
                            if result.status not in RETRY_STATUSES:
                                break
                            continue                     # retry: the next pass reads the new pause
                if self._clock() + later > deadline:
                    keep = not timed            # a timed batch is dropped at its deadline, never queued
                    held_s = self._clock() - started
                    msg = (f"{'not sent' if timed else 'queued: not sent'} after {held_s:.0f}s ({busy}); "
                           f"the next turn is "
                           f"{later:.0f}s away")
                    if result is not None:
                        msg = (f"{result.status.value} {attempts} time(s) and still unjudged after "
                               f"{held_s:.0f}s; the next turn is {later:.0f}s away")
                    if timed:
                        msg += ("; the attempt's deadline comes first, so it is dropped, not queued"
                                if att.deadline is not None else
                                "; a timed attempt ends before a drain could resend it, so it is "
                                "dropped, not queued")
                    if spool is None and not dead_at_deadline:
                        # never got the lock: spool it unchecked; drain runs every check first
                        spool = self._open_spool(self._spool_record(req))
                    if spool is not None:
                        msg += "; left queued for `python -m ctf submit-queue drain`"
                    result = SubmitResult(SubmitStatus.RATE_LIMITED, msg, retry_after=later,
                                          sent=result is not None)
                    break
                self._sleep(later)
        finally:
            if spool is not None:
                self._close_spool(*spool, remove=not keep)
        if attempts or keep:
            self._done(req, result.status.value, attempts, started, keep)
        return result

    def _done(self, req: SubmitRequest, status: str, attempts: int, started: float, keep: bool) -> None:
        ledger.append(DONE_EVENT, workdir=self.workdir, event_slug=self.profile.slug,
                      challenge_id=req.challenge_id, status=status, attempts=attempts,
                      held_s=round(self._clock() - started, 3), queued=keep)

    def drain(self, gate: SubmitGate) -> list[tuple[dict, SubmitResult]]:
        """Send every orphaned spooled request again through the gate (checks, dedupe and all)."""
        done = []
        if not self.pending_dir.is_dir():
            return done
        for path in sorted(self.pending_dir.glob("*.json")):
            try:
                fd = os.open(path, os.O_RDWR)
            except FileNotFoundError:
                continue                       # finished by its owner meanwhile
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)                   # in flight: its own call is still working on it
                continue
            if not path.exists():
                os.close(fd)
                continue
            try:
                rec = self._load_spool(path)
            except QueueError:
                os.close(fd)
                raise
            if rec.get("event_slug") != self.profile.slug:
                os.close(fd)
                raise QueueError(f"spooled submit {path} belongs to event {rec.get('event_slug')!r}, "
                                 f"not {self.profile.slug!r}")
            att = rec.get("attempt")
            req = SubmitRequest(str(rec["challenge_id"]), str(rec["flag"]), str(rec["provenance"]),
                                bool(rec.get("confirmed")), bool(rec.get("allow_nonstandard")),
                                bool(rec.get("guess")),
                                sweep=str(rec["sweep"]) if rec.get("sweep") is not None else None,
                                answers=tuple((str(k), str(v)) for k, v in rec.get("answers") or ()),
                                attempt=_attempt_ref(att) if isinstance(att, dict) else None)
            if req.sweep is not None:
                self._sweep_pace(req.challenge_id)
            done.append((rec, self.submit(gate, req, _spool=(path, fd))))
        return done

    def _sweep_pace(self, challenge_id: str) -> None:
        """Hold a resent sweep send until sweep.interval_s after the last send on its challenge (the
        sweep runner's pacer, which a drain has no run to keep)."""
        with self._flock(self.dir / "pace.lock"):
            last = (self._read().get("by_challenge") or {}).get(challenge_key(challenge_id))
        if last is not None:
            wait = float(last) + self.profile.sweep.interval_s - self._clock()
            if wait > 0:
                self._sleep(wait)

    # ------------------------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        st = self._read() if self.state_path.exists() else {}
        now = self._clock()
        recent = [t for t in st.get("sends", ()) if t > now - self.window_s]
        pend = self.pending()
        return {
            "event": self.profile.slug,
            "per_minute": self.pace.per_minute,
            "sent_last_window": len(recent),
            "interval_s": self.pace.interval_s,
            "per_challenge_interval_s": self.pace.per_challenge_interval_s,
            "max_hold_s": self.pace.max_hold_s,
            "paused_for_s": max(0.0, float(st.get("blocked_until", 0.0)) - now),
            "last_block": st.get("last_block"),
            "pending_in_flight": sum(1 for p in pend if p["state"] == "in_flight"),
            "pending_orphaned": sum(1 for p in pend if p["state"] == "orphaned"),
        }


def install(gate: SubmitGate, workdir: Path | None = None, **kw: Any) -> SubmitQueue:
    """Attach a submit queue to the gate: dedupe as a check, and every submit through the queue."""
    q = SubmitQueue(gate.profile, workdir=workdir, **kw)
    gate.add_check(q.check)
    gate.set_queue(q)
    return q
