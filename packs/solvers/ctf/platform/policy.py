"""The submit policy gate: every platform submission passes through here.

    gate = SubmitGate(adapter, profile)          # what ctf.platform.get_adapter() returns
    gate.submit(cid, flag, provenance="xor of body", confirmed=False)

The gate exposes the adapter's read calls unchanged and replaces submit() with a checked one.
Checks run in order; the first refusal returns SubmitResult(NOT_ALLOWED, sent=False) and the raw
adapter is never called:

  1. manual mode     submit_mode "manual" (or platform kind manual): never sent; the player submits.
  2. provenance      a non-empty note on where the value came from (it goes into the write-up).
  3. format          the value is a flag in the event format, unless allow_nonstandard=True (an
                     answer the brief defines, e.g. OSINT coordinates).
  4. confirm mode    submit_mode "confirm" needs confirmed=True (the player said yes).
  5. extra checks    callables registered with add_check(); B-173 and B-044 plug in here instead
                     of editing the adapters. A check returns None to pass or a reason string to
                     refuse. get_adapter() registers the event rules (ctf/platform/rules.py:
                     wrong_answer_stop, guess_budget, flag_sharing) and then the submit queue's
                     dedupe (ctf/platform/queue.py, B-006).

The submit queue (B-006). get_adapter() also attaches a SubmitQueue with set_queue(). With a queue,
submit() hands the request to it: the queue takes the challenge's cross-process lock, runs the
checks above under it (so a count-then-send is atomic across processes), waits for the team's turn
(per-minute budget, spacing, a shared rate-limit pause), sends, and retries a rate-limited or paused
answer automatically. Without a queue (a bare SubmitGate) the checks run and the adapter is called
once, as before.

rotating=True marks a rotating (dynamic) flag: an incorrect answer is a timing miss and does not
count toward wrong_answer_stop, up to submit.rotating_miss_budget misses per challenge (rules.py);
past that each miss counts. Only ctf.dynamic may pass it; any other caller gets ValueError.

sweep="<authorization id>" marks one send of a player-authorized sweep run (B-173): the player's
authorization (`ctf policy authorize-sweep`, a platform.sweep_auth ledger record) stands in for the
wrong-answer stop and the guess budget for its count of sends (rules.py). Only ctf.eventpolicy's
paced sweep runner may pass it; any other caller gets ValueError.

After the adapter answers, every observer registered with add_observer(fn(profile, req, result))
sees the result (rules.py records it in the ledger, which is how the wrong-answer count and the
guess budget are kept). An observer that fails raises RecordError carrying the result: the value
was sent, so the caller must learn the verdict, and the failed record must not pass silently.

The fast submit path (B-044). gate.submit_answers(cid, {aid: value, ...}, provenance=...,
attempt=AttemptRef(...)) sends every answer of one attempt in ONE request (the Game Master grades
a batch as one) through the same checks, queue, records and observers. Its SubmitRequest carries
the pairs in `answers` and their canonical text (batch_flag) as `flag`; the format check applies to
every value. With an AttemptRef that has a deadline, the queue skips the per-challenge spacing and
never holds or spools the batch past the deadline (queue.py); ctf.platform.halloffame registers the
Hall of Fame check and records every timed result's eligibility.

The `ctf submit` command, `python -m ctf.submit` and ctf.dynamic go through this gate (B-006). The
legacy library function ctf.submit.guarded_submit keeps its own guards and has no caller in the
repo; manual mode is enforced there by ctf/platform/legacy.py (R-02).
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .. import flagfmt
from ..event import EventProfile
from .base import NotSupported, PlatformAdapter, PlatformError, SubmitResult, SubmitStatus


@dataclass(frozen=True)
class AttemptRef:
    """The timed attempt a batch belongs to (B-044, built by ctf.platform.halloffame.TimedAttempt).

    deadline (epoch seconds) makes it a timed fast-path send: no per-challenge spacing, never held
    or spooled past deadline - DEADLINE_MARGIN_S (queue.py). ranked_retry marks a Hall of Fame retry
    of an already-solved timed id: dedupe looks only at this attempt's records, and the Hall of Fame
    check refuses it when the server said the attempt is not eligible. origin is the start reply's
    classification (fresh, own, foreign, unknown); a foreign (teammate's) attempt needs confirmed.
    pool holds the start reply's pool fields, for the result's eligibility check."""
    attempt_id: str | None = None
    deadline: float | None = None
    ranked_retry: bool = False
    eligible: bool | None = None
    origin: str = "unknown"
    pool: tuple[tuple[str, bool], ...] = ()


@dataclass(frozen=True)
class SubmitRequest:
    challenge_id: str
    flag: str
    provenance: str
    confirmed: bool = False
    allow_nonstandard: bool = False
    guess: bool = False               # an unreasoned variant of an earlier value (rules.guess_budget)
    rotating: bool = False            # a rotating flag (ctf.dynamic): a miss is not a wrong answer
    sweep: str | None = None          # a player-authorized sweep send: the authorization id (B-173)
    # B-044: a batch of (answer id, value) sent in one request (gate.submit_answers); flag is then
    # batch_flag(answers), the batch's canonical text, so dedupe and the records work unchanged.
    answers: tuple[tuple[str, str], ...] = ()
    attempt: AttemptRef | None = None


def batch_flag(answers: Mapping[str, str] | tuple) -> str:
    """The canonical text of a batch: sorted JSON of {answer id: value}."""
    return json.dumps(dict(answers), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# Modules allowed to pass rotating=True (the rotating-flag carve-out; solver scripts once used the
# carried equivalent on static challenges to walk past the wrong-answer guard).
ROTATING_CALLERS = frozenset({"ctf.dynamic"})
# Modules allowed to pass sweep=<authorization id>: the paced, once-per-run sweep runner (B-173).
SWEEP_CALLERS = frozenset({"ctf.eventpolicy"})

Check = Callable[[EventProfile, SubmitRequest], "str | None"]
Observer = Callable[[EventProfile, SubmitRequest, SubmitResult], None]


class RecordError(PlatformError):
    """The submission was sent and answered, but an observer failed to record it. `.result` is the
    platform's answer."""

    def __init__(self, message: str, result: SubmitResult):
        super().__init__(message)
        self.result = result


def _refuse(reason: str) -> SubmitResult:
    return SubmitResult(SubmitStatus.NOT_ALLOWED, reason, sent=False)


def base_checks(profile: EventProfile, req: SubmitRequest) -> str | None:
    if profile.manual:
        return f"event {profile.slug!r} is manual: the player submits by hand"
    if not req.provenance.strip():
        return "a submission needs a provenance note"
    if not req.allow_nonstandard:
        fmt = flagfmt.for_profile(profile)
        values = [v for _, v in req.answers] if req.answers else [req.flag]
        if not all(fmt.is_flag(v) for v in values):
            return "value is not in the event flag format (pass allow_nonstandard only for brief-defined answers)"
    if profile.rules.submit_mode == "confirm" and not req.confirmed:
        return "submit_mode is 'confirm': the player must confirm this submission"
    return None


class SubmitGate:
    def __init__(self, adapter: PlatformAdapter, profile: EventProfile):
        self._adapter = adapter
        self.profile = profile
        self.kind = adapter.kind
        self._checks: list[Check] = []
        self._observers: list[Observer] = []
        self._queue: Any = None

    def set_queue(self, queue: Any) -> None:
        """Route every submit through `queue` (ctf.platform.queue.SubmitQueue): queue.submit(gate, req)."""
        self._queue = queue

    @property
    def queue(self) -> Any:
        return self._queue

    def add_check(self, check: Check) -> None:
        self._checks.append(check)

    def add_observer(self, observer: Observer) -> None:
        self._observers.append(observer)

    def __getattr__(self, name):
        # Read calls (list_challenges, get_challenge, ...) and optional capabilities pass through.
        if name == "submit":
            raise AttributeError(name)
        return getattr(self._adapter, name)

    def submit(self, challenge_id: str, flag: str, *, provenance: str, confirmed: bool = False,
               allow_nonstandard: bool = False, guess: bool = False,
               rotating: bool = False, sweep: str | None = None) -> SubmitResult:
        caller = sys._getframe(1).f_globals.get("__name__", "?")
        if rotating and caller not in ROTATING_CALLERS:
            raise ValueError(f"rotating=True is reserved for the rotating-flag path (ctf.dynamic); "
                             f"called from {caller!r}. A static challenge's wrong answer always counts.")
        if sweep is not None and caller not in SWEEP_CALLERS:
            raise ValueError(f"sweep= is reserved for the paced sweep runner (ctf.eventpolicy.run_sweep, "
                             f"`python -m ctf policy sweep`); called from {caller!r}")
        req = SubmitRequest(str(challenge_id), flag.strip(), provenance or "", confirmed,
                            allow_nonstandard, guess, rotating, sweep)
        if self._queue is not None:
            return self._queue.submit(self, req)
        reason = self.refusal(req)
        if reason:
            return _refuse(reason)
        return self.send(req)

    def submit_answers(self, challenge_id: str, answers: Mapping[str, str], *, provenance: str,
                       attempt: AttemptRef | None = None, confirmed: bool = False,
                       allow_nonstandard: bool = False) -> SubmitResult:
        """B-044's fast path: every answer of one attempt in ONE request (Game Master), through the
        same checks, queue and records as submit(). A manual event is refused (NOT_ALLOWED, sent
        False) before anything else; an adapter with no batch call raises NotSupported."""
        if not isinstance(answers, Mapping) or not answers:
            raise ValueError("submit_answers needs a non-empty {answer id: value} mapping")
        pairs = tuple(sorted((str(k), str(v).strip()) for k, v in answers.items()))
        req = SubmitRequest(str(challenge_id), batch_flag(pairs), provenance or "", confirmed,
                            allow_nonstandard, answers=pairs, attempt=attempt)
        reason = base_checks(self.profile, req)
        if reason:
            return _refuse(reason)
        if self.kind == "manual":           # ai_on_platform forbidden: get_adapter chose manual mode
            return _refuse(f"event {self.profile.slug!r} is in manual mode (no automation on its "
                           "platform): the player submits by hand")
        if not callable(getattr(self._adapter, "submit_answers", None)):
            raise NotSupported(f"the {self.kind} adapter sends one answer per request; it has no "
                               "batch submit (submit_answers)")
        if self._queue is not None:
            return self._queue.submit(self, req)
        reason = self.refusal(req)
        if reason:
            return _refuse(reason)
        return self.send(req)

    def refusal(self, req: SubmitRequest) -> str | None:
        """The first check's reason to refuse `req`, or None. The queue calls this under its lock."""
        for check in (base_checks, *self._checks):
            reason = check(self.profile, req)
            if reason:
                return reason
        return None

    def send(self, req: SubmitRequest) -> SubmitResult:
        """One raw send of an already-checked request, then every observer. The queue calls this."""
        if req.answers:
            result = self._adapter.submit_answers(req.challenge_id, dict(req.answers))
        else:
            result = self._adapter.submit(req.challenge_id, req.flag)
        for observe in self._observers:
            try:
                observe(self.profile, req, result)
            except Exception as e:
                raise RecordError(f"submit of challenge {req.challenge_id} was answered "
                                  f"{result.status.value}, but recording it failed: {e}", result) from e
        return result
