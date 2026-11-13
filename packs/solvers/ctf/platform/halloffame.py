"""Hall of Fame eligibility and the timed fast submit path (B-044).

The Game Master's Time Trial and Mastery ids (".../time_trial", ".../mastery") feed a fastest-times
board, the Hall of Fame. Two things went wrong at Huntress 2026:

  * Day 8: a dual-pool route answered a timed id with a REGULAR attempt (`run_for_time` false,
    `hall_of_fame_eligible` false, deadline null). The 1.56 s and 2.26 s solves scored but posted
    nothing to the board, and nothing noticed. So every timed result is checked here, and a regular
    attempt on a timed id is said out loud (a NOTE on stderr, a `hof.result` ledger record, a WARN
    in `ctf hof report`).
  * Day 1: our own live starts read as a teammate's attempt (77 s lost on the web Time Trial). An
    attempt is "already running" when the start reply's `started_at` trails the server's `Date`
    header; a slow reply (3-11 s web starts) trails it by its own round trip. classify_start()
    subtracts the request's elapsed time and adds a skew tolerance before it calls an attempt a
    teammate's, and an attempt id we recorded as our own start is never a teammate's.

    from ctf.platform import get_adapter, halloffame
    gate = get_adapter(profile)                        # halloffame.install(gate) has already run
    att = halloffame.TimedAttempt.from_reply(gate, cid, start_body, date=resp.headers["Date"],
                                             elapsed_s=resp.elapsed.total_seconds())
    if att.origin.teammate: ...                        # a teammate's attempt: ask the player
    res = att.submit({aid: value, ...}, provenance="...")    # ONE request for every answer
    res.result.status, res.eligibility.eligible, res.note    # the verdict and the board check

Who starts a clock is not decided here: the adapter's start_instance refuses timed ids, and only
the opener starts a clock. This module takes the start (or retry) reply the opener got: its body,
its Date header and how long the request took.

The fast path is gate.submit_answers (policy.py): every answer in one POST (the judge grades a
batch as one), no per-challenge spacing, never held or spooled past the attempt's deadline
(queue.py). It goes only through the SubmitGate, so a manual event is refused before anything is
sent. install(gate) (called by get_adapter) adds the check and the observer:

  check     a batch for a teammate's attempt (origin "foreign") needs confirmed=True (the player);
            a ranked retry (a Hall of Fame retry of an already-solved timed id) is refused, with
            nothing sent, when the server said the attempt is not eligible (an explicit false of
            hall_of_fame_eligible, run_for_time or variant_fresh). A reply without the fields says
            nothing (a legacy route), as in the Huntress speed runner. A ranked retry is also
            refused when an earlier attempt's records say ranked_attempts_remaining 0 and this
            attempt's own reply does not say hall_of_fame_eligible true (the later body wins). A
            retry runner should still skip an id whose known_ranked_left() is 0 before it asks for
            a retry at all; this check is the backstop.
  observer  every timed result (a timed id, or a batch whose attempt has a deadline) gets a
            `hof.result` ledger record with its eligibility; a regular attempt prints one NOTE line.

Records (ledger, section 10): `hof.start` (record_start: a classified start or retry reply) and
`hof.result`. Neither holds a flag or an answer value.
"""
from __future__ import annotations

import datetime as _dt
import math
import sys
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .. import ledger, paths
from ..event import EventProfile
from .gamemaster import is_timed
from .policy import AttemptRef, SubmitGate, SubmitRequest
from .base import SubmitResult
from .rules import challenge_key

POOL_FIELDS = ("run_for_time", "hall_of_fame_eligible", "variant_fresh")
COUNT_FIELDS = ("ranked_attempts_remaining", "unique_attempts_remaining", "regular_variants_remaining")
REGULAR_NOTE = "regular attempt on a timed id"
START_EVENT = "hof.start"
RESULT_EVENT = "hof.result"

# A start reply whose started_at trails the server Date by this much more than the request's own
# round trip is an attempt that was already running (the Huntress tools/run.py RESUMED_AFTER).
RESUMED_AFTER_S = 1.0
# Extra allowance for the clock that stamps started_at and the one that writes Date disagreeing.
# (The Date header's 1 s resolution needs none: it truncates, which can only make a start look
# fresher than it is, never staler.)
SKEW_TOLERANCE_S = 1.0

ORIGINS = ("fresh", "own", "foreign", "unknown")
OWN_ORIGINS = ("fresh", "own")

NOT_ELIGIBLE = "not_eligible"          # refusal reasons start with one of these words
NO_RANKED_LEFT = "no_ranked_attempt"
TEAMMATE = "teammate_attempt"


# ------------------------------------------------------------------------------- eligibility

def pool_of(body: Any) -> dict[str, bool]:
    """The pool fields a start, retry or result body carries, as they came (absent ones left out)."""
    if not isinstance(body, Mapping):
        return {}
    return {k: body[k] for k in POOL_FIELDS if isinstance(body.get(k), bool)}


def counts_of(body: Any) -> dict[str, int]:
    """The attempt counts a body carries (ranked/unique attempts, regular variants remaining)."""
    if not isinstance(body, Mapping):
        return {}
    return {k: body[k] for k in COUNT_FIELDS
            if isinstance(body.get(k), int) and not isinstance(body.get(k), bool)}


@dataclass(frozen=True)
class Eligibility:
    """What the server said about one timed attempt's Hall of Fame standing. Later bodies win.

    eligible: False when any pool field is an explicit false; True when hall_of_fame_eligible is
    true and nothing says false; None when nothing was said (a legacy route, or not a timed id).
    regular: a timed id answered with a regular attempt (run_for_time or hall_of_fame_eligible
    false): it scores, but posts nothing to the fastest-times board."""
    challenge_id: str
    timed: bool
    eligible: bool | None
    regular: bool
    pool: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    unranked_by: tuple[str, ...] = ()

    @property
    def ranked_left(self) -> int | None:
        return self.counts.get("ranked_attempts_remaining")

    @property
    def note(self) -> str | None:
        """The NOTE line for a regular attempt on a timed id, else None."""
        if not self.regular:
            return None
        said = ", ".join(f"{k}=false" for k in ("run_for_time", "hall_of_fame_eligible")
                         if self.pool.get(k) is False)
        return (f"{REGULAR_NOTE}: {self.challenge_id} ({said}); it scores, but posts nothing to the "
                "fastest-times board (the start body lacked run_for_time:true, or the route ignores it)")

    def verdict(self) -> str:
        if not self.timed:
            return f"{self.challenge_id} is not a timed id: no Hall of Fame"
        if self.eligible is False:
            return f"NOT ranked: the server said {', '.join(self.unranked_by)}"
        if self.eligible is True:
            return "eligible: the server said hall_of_fame_eligible true"
        return "the server said nothing about eligibility (no pool field in any body)"


def eligibility(challenge_id: str, *bodies: Any, timed: bool | None = None) -> Eligibility:
    """The Hall of Fame standing of one attempt from its bodies (start, then result; later wins).
    timed defaults to whether the id is a Time Trial / Mastery id."""
    cid = challenge_key(str(challenge_id))
    is_t = is_timed(cid) if timed is None else bool(timed)
    pool: dict = {}
    counts: dict = {}
    for b in bodies:
        pool.update(pool_of(b))
        counts.update(counts_of(b))
    if not is_t:
        return Eligibility(cid, False, None, False, pool, counts)
    unranked = tuple(f"{k}=false" for k in POOL_FIELDS if pool.get(k) is False)
    if unranked:
        eligible = False
    elif pool.get("hall_of_fame_eligible") is True:
        eligible = True
    else:
        eligible = None
    regular = pool.get("run_for_time") is False or pool.get("hall_of_fame_eligible") is False
    return Eligibility(cid, True, eligible, regular, pool, counts, unranked)


# ------------------------------------------------------------------------------- start origin

@dataclass(frozen=True)
class StartOrigin:
    """Whose attempt a start (or retry) reply returned.

    fresh    started by this request (started_at within the round trip + RESUMED_AFTER_S + skew)
    own      an attempt id we recorded as our own earlier start (a rejoin, never a teammate's)
    foreign  already running before this request, and not ours: a teammate's
    unknown  the reply does not say (no started_at, no Date): never read as a teammate's"""
    kind: str
    attempt_id: str | None = None
    late_s: float | None = None        # Date - started_at
    elapsed_s: float = 0.0             # the request's own round trip
    reason: str = ""

    @property
    def teammate(self) -> bool:
        return self.kind == "foreign"


def _epoch(value: Any, what: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{what} is not a time")
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError(f"{what} is not finite")
        return float(value)
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            raise ValueError(f"{what} has no time zone")
        return value.timestamp()
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            d = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                d = parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError):
                raise ValueError(f"{what} {text[:40]!r} is not a time") from None
        if d is None or d.tzinfo is None:
            raise ValueError(f"{what} {text[:40]!r} has no time zone")
        return d.timestamp()
    raise ValueError(f"{what} is missing")


def classify_start(body: Any, *, date: Any, elapsed_s: float = 0.0,
                   own_attempt_ids: Iterable[str] = (), resumed_after_s: float = RESUMED_AFTER_S,
                   skew_tolerance_s: float = SKEW_TOLERANCE_S) -> StartOrigin:
    """Classify a start/retry reply: `body` (its JSON), `date` (its Date header: an HTTP-date, an
    ISO time, an aware datetime or epoch seconds) and `elapsed_s` (how long the request took).

    The server stamps a fresh attempt's started_at between receiving the POST and sending the
    reply, so a fresh attempt trails Date by at most the round trip. The attempt is a teammate's
    only when it trails by more than elapsed_s + resumed_after_s + skew_tolerance_s and its id is
    not one of ours."""
    if not isinstance(elapsed_s, (int, float)) or isinstance(elapsed_s, bool) or elapsed_s < 0 \
            or not math.isfinite(elapsed_s):
        raise ValueError(f"elapsed_s must be a finite number >= 0, got {elapsed_s!r}")
    for name, v in (("resumed_after_s", resumed_after_s), ("skew_tolerance_s", skew_tolerance_s)):
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0 or not math.isfinite(v):
            raise ValueError(f"{name} must be a finite number >= 0, got {v!r}")
    aid = body.get("attempt_id") if isinstance(body, Mapping) else None
    aid = aid if isinstance(aid, str) and aid else None
    elapsed = float(elapsed_s)
    if aid is not None and aid in set(own_attempt_ids):
        return StartOrigin("own", aid, None, elapsed, f"attempt {aid} is one of our own recorded starts")
    try:
        started = _epoch(body.get("started_at") if isinstance(body, Mapping) else None, "started_at")
    except ValueError as e:
        return StartOrigin("unknown", aid, None, elapsed, f"the reply has no readable started_at ({e})")
    try:
        now = _epoch(date, "the Date header")
    except ValueError as e:
        return StartOrigin("unknown", aid, None, elapsed, f"the reply has no readable Date header ({e})")
    late = now - started
    allowed = elapsed + resumed_after_s + skew_tolerance_s
    if late > allowed:
        return StartOrigin("foreign", aid, round(late, 3), elapsed,
                           f"started_at trails the server Date by {late:.2f}s, more than the round trip "
                           f"{elapsed:.2f}s + {resumed_after_s:g}s + skew {skew_tolerance_s:g}s: the "
                           "attempt was already running, and its id is not one of our starts")
    return StartOrigin("fresh", aid, round(late, 3), elapsed,
                       f"started_at trails the server Date by {late:.2f}s, within the round trip "
                       f"{elapsed:.2f}s + {resumed_after_s:g}s + skew {skew_tolerance_s:g}s")


def classify_response(resp: Any, **kw: Any) -> tuple[dict, StartOrigin]:
    """classify_start for a requests.Response (its .json(), headers["Date"], .elapsed)."""
    try:
        body = resp.json()
    except Exception as e:
        raise ValueError(f"the start reply is not JSON ({type(e).__name__})") from None
    if not isinstance(body, dict):
        raise ValueError("the start reply is not a JSON object")
    elapsed = getattr(resp, "elapsed", None)
    elapsed_s = max(0.0, elapsed.total_seconds()) if elapsed is not None else 0.0
    date = (getattr(resp, "headers", None) or {}).get("Date")
    return body, classify_start(body, date=date, elapsed_s=elapsed_s, **kw)


# ------------------------------------------------------------------------------- ledger

def _workdir(profile: EventProfile, workdir: Path | None) -> Path:
    return Path(workdir) if workdir is not None else paths.workdir(profile.slug)


def _deadline(body: Any) -> float | None:
    v = body.get("deadline") if isinstance(body, Mapping) else None
    if v is None:
        return None
    try:
        return _epoch(v, "deadline")
    except ValueError:
        return None


def record_start(profile: EventProfile, challenge_id: str, body: Any, origin: StartOrigin, *,
                 workdir: Path | None = None) -> dict:
    """A `hof.start` ledger record: the classified start/retry reply (no answer, no flag)."""
    el = eligibility(challenge_id, body)
    if origin.kind not in ORIGINS:
        raise ValueError(f"unknown start origin {origin.kind!r}")
    return ledger.append(START_EVENT, workdir=_workdir(profile, workdir), event_slug=profile.slug,
                         challenge_id=el.challenge_id, attempt_id=origin.attempt_id, origin=origin.kind,
                         late_s=origin.late_s, elapsed_s=round(origin.elapsed_s, 3),
                         deadline=_deadline(body), eligible=el.eligible, regular=el.regular,
                         pool=el.pool, counts=el.counts, reason=origin.reason)


def own_attempt_ids(profile: EventProfile, challenge_id: str, *, workdir: Path | None = None) -> set[str]:
    """Attempt ids of our own starts of this challenge (hof.start records, origin fresh or own)."""
    key = challenge_key(str(challenge_id))
    return {r["attempt_id"] for r in ledger.read(_workdir(profile, workdir))
            if r.get("event") == START_EVENT and r.get("event_slug") == profile.slug
            and r.get("challenge_id") == key and r.get("origin") in OWN_ORIGINS
            and isinstance(r.get("attempt_id"), str)}


def known_ranked_left(profile: EventProfile, challenge_id: str, *, workdir: Path | None = None,
                      exclude_attempt: str | None = None) -> int | None:
    """ranked_attempts_remaining as the server last said it for this challenge (hof records), or
    None when it never did. A ranked retry runner skips an id at 0 before any request.
    exclude_attempt leaves out one attempt's own records (what was known before that attempt)."""
    key = challenge_key(str(challenge_id))
    left = None
    for r in ledger.read(_workdir(profile, workdir)):
        if (r.get("event") in (START_EVENT, RESULT_EVENT) and r.get("event_slug") == profile.slug
                and r.get("challenge_id") == key
                and (exclude_attempt is None or r.get("attempt_id") != exclude_attempt)):
            v = (r.get("counts") or {}).get("ranked_attempts_remaining")
            if isinstance(v, int) and not isinstance(v, bool):
                left = v
    return left


def record_result(profile: EventProfile, req: SubmitRequest, result: SubmitResult,
                  el: Eligibility, *, workdir: Path | None = None) -> dict:
    """A `hof.result` ledger record: one timed result and its eligibility (no answer, no flag)."""
    return ledger.append(RESULT_EVENT, workdir=_workdir(profile, workdir), event_slug=profile.slug,
                         challenge_id=el.challenge_id,
                         attempt_id=req.attempt.attempt_id if req.attempt is not None else None,
                         status=result.status.value, eligible=el.eligible, regular=el.regular,
                         pool=el.pool, counts=el.counts, note=el.note)


def report(profile: EventProfile, *, workdir: Path | None = None) -> list[dict]:
    """Every hof.start / hof.result record of the event, oldest first, each with a `warn` line
    (None when there is nothing to act on): a regular attempt on a timed id, an attempt the server
    called not eligible, or a start read as a teammate's."""
    out = []
    for r in ledger.read(_workdir(profile, workdir)):
        if r.get("event") not in (START_EVENT, RESULT_EVENT) or r.get("event_slug") != profile.slug:
            continue
        warn = None
        if r.get("regular"):
            warn = r.get("note") or f"{REGULAR_NOTE}: {r.get('challenge_id')}"
        elif r.get("eligible") is False:
            warn = f"not eligible for the Hall of Fame: {r.get('challenge_id')} ({r.get('pool')})"
        elif r.get("origin") == "foreign":
            warn = f"start read as a teammate's attempt: {r.get('challenge_id')} ({r.get('reason')})"
        out.append(dict(r, warn=warn))
    return out


# ------------------------------------------------------------------------------- gate hooks

def _is_timed_req(req: SubmitRequest) -> bool:
    return (req.attempt is not None and req.attempt.deadline is not None) or is_timed(challenge_key(req.challenge_id))


def check(profile: EventProfile, req: SubmitRequest, *, workdir: Path | None = None) -> str | None:
    """The gate check (install): teammate attempts need the player; a ranked retry the server
    called not eligible, or one with no ranked attempt left, gets no submit."""
    att = req.attempt
    if att is None:
        return None
    if att.origin == "foreign" and not req.confirmed:
        return (f"{TEAMMATE}: attempt {att.attempt_id or '?'} of {challenge_key(req.challenge_id)} was "
                "already running before our start (a teammate's); nothing is posted at it unless the "
                "player says so (confirmed=True)")
    if att.ranked_retry:
        el = eligibility(req.challenge_id, dict(att.pool), timed=True)
        if att.eligible is False or el.eligible is False:
            why = ", ".join(el.unranked_by) or "eligible=false"
            return (f"{NOT_ELIGIBLE}: the server said {why} for this ranked retry of "
                    f"{challenge_key(req.challenge_id)}; it would set no Hall of Fame time, so nothing "
                    "is submitted")
        if dict(att.pool).get("hall_of_fame_eligible") is not True:
            left = known_ranked_left(profile, req.challenge_id, workdir=workdir,
                                     exclude_attempt=att.attempt_id)
            if left == 0:
                return (f"{NO_RANKED_LEFT}: an earlier attempt's reply said ranked_attempts_remaining 0 "
                        f"for {challenge_key(req.challenge_id)}, and this retry's reply does not say "
                        "hall_of_fame_eligible true; it would set no Hall of Fame time, so nothing is "
                        "submitted")
    return None


def observe(profile: EventProfile, req: SubmitRequest, result: SubmitResult, *,
            workdir: Path | None = None) -> Eligibility | None:
    """The gate observer (install): every timed result gets a hof.result record; a regular attempt
    on a timed id prints one NOTE line on stderr. Returns the eligibility (None: not timed)."""
    if not _is_timed_req(req):
        return None
    start_pool = dict(req.attempt.pool) if req.attempt is not None else {}
    el = eligibility(req.challenge_id, start_pool, result.reply or {}, timed=True)
    record_result(profile, req, result, el, workdir=workdir)
    if el.note:
        print(f"NOTE {el.note}", file=sys.stderr, flush=True)
    return el


def install(gate: SubmitGate, workdir: Path | None = None) -> None:
    """Register the Hall of Fame check and observer on a gate (get_adapter does this)."""
    gate.add_check(lambda profile, req: check(profile, req, workdir=workdir))
    gate.add_observer(lambda profile, req, result: observe(profile, req, result, workdir=workdir))


# ------------------------------------------------------------------------------- timed attempt

@dataclass(frozen=True)
class TimedResult:
    result: SubmitResult
    eligibility: Eligibility

    @property
    def note(self) -> str | None:
        return self.eligibility.note


@dataclass(frozen=True)
class TimedAttempt:
    """One timed attempt, from the start (or retry) reply the opener got."""
    gate: Any
    challenge_id: str
    body: dict
    origin: StartOrigin
    eligibility: Eligibility
    ranked_retry: bool = False

    @classmethod
    def from_reply(cls, gate: Any, challenge_id: str, body: Mapping, *, date: Any, elapsed_s: float = 0.0,
                   ranked_retry: bool = False, record: bool = True, workdir: Path | None = None,
                   resumed_after_s: float = RESUMED_AFTER_S,
                   skew_tolerance_s: float = SKEW_TOLERANCE_S) -> "TimedAttempt":
        """Classify the reply against our own recorded starts, check its eligibility, and (record)
        write the hof.start record, so a later rejoin of this attempt reads as ours."""
        if not isinstance(body, Mapping):
            raise ValueError("a timed attempt needs the start reply's JSON object")
        cid = challenge_key(str(challenge_id))
        profile = gate.profile
        own = own_attempt_ids(profile, cid, workdir=workdir)
        origin = classify_start(body, date=date, elapsed_s=elapsed_s, own_attempt_ids=own,
                                resumed_after_s=resumed_after_s, skew_tolerance_s=skew_tolerance_s)
        el = eligibility(cid, body)
        if record:
            record_start(profile, cid, body, origin, workdir=workdir)
        return cls(gate, cid, dict(body), origin, el, ranked_retry)

    @property
    def attempt_id(self) -> str | None:
        return self.origin.attempt_id

    @property
    def deadline(self) -> float | None:
        return _deadline(self.body)

    @property
    def answer_ids(self) -> list[str]:
        ids = self.body.get("answer_ids")
        if not isinstance(ids, list) or not ids:
            ids = [q.get("id") for q in self.body.get("questions") or () if isinstance(q, Mapping)]
        return [i for i in ids if isinstance(i, str) and i]

    def ref(self) -> AttemptRef:
        return AttemptRef(attempt_id=self.attempt_id, deadline=self.deadline, ranked_retry=self.ranked_retry,
                          eligible=self.eligibility.eligible, origin=self.origin.kind,
                          pool=tuple(sorted(self.eligibility.pool.items())))

    def submit(self, answers: Mapping[str, str], *, provenance: str, confirmed: bool = False,
               allow_nonstandard: bool = True) -> TimedResult:
        """Every answer in ONE request through the gate (gate.submit_answers). Answer ids the
        attempt does not list are refused before anything is sent. allow_nonstandard defaults to
        True: Game Master answers are the brief's own answers, not flags."""
        known = set(self.answer_ids)
        if known:
            stray = sorted(set(answers) - known)
            if stray:
                raise ValueError(f"answer id(s) {', '.join(stray)} are not in attempt "
                                 f"{self.attempt_id}'s answer_ids ({', '.join(sorted(known))})")
        res = self.gate.submit_answers(self.challenge_id, answers, provenance=provenance, attempt=self.ref(),
                                       confirmed=confirmed, allow_nonstandard=allow_nonstandard)
        return TimedResult(res, eligibility(self.challenge_id, self.body, res.reply or {}, timed=True))
