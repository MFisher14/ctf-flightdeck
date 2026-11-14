"""The event's submit rules, enforced on every platform submission (registered by get_adapter).

    gate = get_adapter(profile)        # rules.install(gate) has already run
    gate.submit(cid, flag, provenance="...", guess=False)

What the gate itself checks is in policy.py (manual mode, provenance, flag format, confirm mode).
This module adds the rules that need a memory of earlier submissions:

  wrong_answer_stop   after N judged-incorrect answers on one challenge, refuse until the player
                      decides. confirmed=True alone does NOT pass it (B-006; PINK+ OS ran 8 wrong
                      sends on a bare "yes" flag): the player records a counted approval for the
                      challenge (grant(), `ctf submit-queue approve <id> --reason ...`), and a send
                      past the stop needs confirmed=True AND an unused approval. A judged send past
                      the stop spends one; an unjudged one (rate_limited, paused) does not.
                      rules.approved_extras = false (B-173) makes the stop final: grant() refuses
                      and no send past the stop goes out, an authorized sweep's included.
  guess_budget        a submission marked guess=True (an unreasoned variant of an earlier value)
                      is refused once the challenge has used `guess_budget` judged guesses. The
                      default budget is 0: no guessing.
  authorized sweeps   (B-173) the player authorizes one sweep run on one challenge with
                      authorize_sweep() (`ctf policy authorize-sweep <id> --count N --reason ...`):
                      a "platform.sweep_auth" record with an id, a count (at most sweep.max_count)
                      and an expiry (sweep.ttl_s). A send carrying sweep=<id> (only the paced runner,
                      ctf.eventpolicy.run_sweep, may pass it) skips the wrong-answer stop and the
                      guess budget while the authorization is unexpired and has judged sends left;
                      otherwise it is refused, naming why. Its misses do not count toward the stop
                      or the budget afterwards (the authorization covered them), so the guard is
                      back on, unchanged, the moment the run ends. sweep.mode = "forbidden" refuses
                      every authorization and every sweep send. A sweep send also needs the run's
                      claim file (<workdir>/sweeps/<id>.run, written by run_sweep before its first
                      send), and its value must be one the run listed there (by SHA-256) before
                      offering it: a spooled sweep record that `submit-queue drain` resends is
                      refused unless it is one of the run's own sends, so a hand-written spool
                      record cannot stand in for the one run, before or after it.
  flag_sharing        "forbidden" means a flag may not leave the team; the record written here
                      then keeps only the flag's SHA-256, never the value, so no log, sync or
                      handoff built on the ledger can carry it out. ("allowed" keeps the value.)

The memory is the event ledger (ctf.ledger, <workdir>/ledger.jsonl): one "platform.submit" record
per answered submission (post_stop marks a send past the stop, rotating a rotating-flag send), and
one "platform.approval" record per player approval. Unjudged answers (rate_limited, paused,
not_allowed, and "error" for a send that raised) are recorded but count toward no limit. A
multi-answer id "<cid>#<answer>" counts against <cid>.

  batches (B-044)     a batch (gate.submit_answers) is ONE record on its challenge: `answers` (the
                      count), `partial` when it was banked with answers still open, `attempt_id`
                      (and `ranked_retry`) when it names its timed attempt. A wrong batch counts
                      as one wrong answer toward wrong_answer_stop.

  remaining (B-016)   a correct send whose reply says how many answers are still open records it:
                      `remaining` = the Game Master `accepted` reply's count, or 0 for its `CORRECT`
                      reply (the challenge is complete). Other platforms' replies say neither: no
                      field. The escalator (ctf/escalation.py) resolves a multi-answer parent on 0.

  rotating misses     an incorrect answer to a rotating flag (rotating=True, only ctf.dynamic) is a
                      timing miss, not a wrong answer, for the first submit.rotating_miss_budget
                      misses on a challenge (default 6). Every miss past that budget counts toward
                      wrong_answer_stop like a static wrong answer, so neither a long attempts sweep
                      nor a dynamic call on a static challenge can walk past the stop: at most
                      budget + stop wrong values go out before the player must approve more.

Count-then-send is atomic across processes when the gate has a submit queue (get_adapter attaches
one): the queue runs these checks, the send and the record under one per-challenge lock
(ctf/platform/queue.py). A bare SubmitGate without a queue has no such lock.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Callable

from .. import ledger, paths
from ..event import EventProfile
from .base import SubmitResult, SubmitStatus
from .policy import SubmitGate, SubmitRequest

EVENT = "platform.submit"
APPROVAL = "platform.approval"
SWEEP_AUTH = "platform.sweep_auth"
SWEEP_DIR = "sweeps"            # <workdir>/sweeps/<auth id>.run: the claim of the one run


def sweep_claim_path(workdir: Path, auth_id: str) -> Path:
    """Where the one run of sweep authorization `auth_id` records its claim."""
    return Path(workdir) / SWEEP_DIR / f"{auth_id}.run"


def challenge_key(challenge_id: str) -> str:
    return str(challenge_id).split("#", 1)[0]


def _remaining_after(result: SubmitResult) -> int | None:
    """How many answers the platform says are still open after a correct send: a Game Master
    `accepted` reply's `remaining`, 0 for its `CORRECT` reply (the challenge is complete). None when
    the send was not correct or its reply says neither (every other platform)."""
    if result.status is not SubmitStatus.CORRECT or not isinstance(result.reply, dict):
        return None
    word = result.reply.get("result")
    if word == "CORRECT":
        return 0
    rem = result.reply.get("remaining")
    if word == "accepted" and isinstance(rem, int) and not isinstance(rem, bool) and rem >= 0:
        return rem
    return None


class EventRules:
    def __init__(self, profile: EventProfile, workdir: Path | None = None,
                 clock: Callable[[], float] = time.time):
        self.profile = profile
        self._workdir = workdir
        self._clock = clock

    @property
    def workdir(self) -> Path:
        return self._workdir if self._workdir is not None else paths.workdir(self.profile.slug)

    # ------------------------------------------------------------------------------- memory
    def history(self, challenge_id: str) -> list[dict]:
        key = challenge_key(challenge_id)
        return [r for r in ledger.read(self.workdir)
                if r.get("event") == EVENT and r.get("event_slug") == self.profile.slug
                and challenge_key(r.get("challenge_id", "")) == key]

    def rotating_misses(self, challenge_id: str) -> int:
        return sum(1 for r in self.history(challenge_id)
                   if r.get("status") == "incorrect" and r.get("rotating"))

    def wrong_count(self, challenge_id: str) -> int:
        """Wrong answers toward wrong_answer_stop: every static miss outside an authorized sweep,
        plus the rotating misses past submit.rotating_miss_budget."""
        static = sum(1 for r in self.history(challenge_id)
                     if r.get("status") == "incorrect" and not r.get("rotating") and not r.get("sweep"))
        over = self.rotating_misses(challenge_id) - self.profile.submit.rotating_miss_budget
        return static + max(0, over)

    def approvals_granted(self, challenge_id: str) -> int:
        key = challenge_key(challenge_id)
        return sum(int(r.get("count", 0)) for r in ledger.read(self.workdir)
                   if r.get("event") == APPROVAL and r.get("event_slug") == self.profile.slug
                   and challenge_key(r.get("challenge_id", "")) == key)

    def approvals_left(self, challenge_id: str) -> int:
        spent = sum(1 for r in self.history(challenge_id) if r.get("post_stop") and r.get("judged"))
        return self.approvals_granted(challenge_id) - spent

    def grant(self, challenge_id: str, reason: str, count: int = 1) -> dict:
        """Record the player's approval for `count` more sends past wrong_answer_stop on this challenge."""
        if not self.profile.rules.approved_extras:
            raise ValueError(f"event {self.profile.slug!r} has rules.approved_extras = false: the "
                             "wrong-answer stop is final, no approval reopens a challenge")
        if not reason or not reason.strip():
            raise ValueError("an approval needs a reason (who approved and why; it goes into the write-up)")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"approval count must be an integer >= 1, got {count!r}")
        return ledger.append(APPROVAL, workdir=self.workdir, event_slug=self.profile.slug,
                             challenge_id=challenge_key(challenge_id), count=count, reason=reason.strip())

    def guesses_used(self, challenge_id: str) -> int:
        """Judged guess=True sends toward guess_budget (an authorized sweep's sends do not count)."""
        return sum(1 for r in self.history(challenge_id)
                   if r.get("guess") and r.get("judged") and not r.get("sweep"))

    # ------------------------------------------------------------------------------- sweeps (B-173)
    def authorize_sweep(self, challenge_id: str, count: int, reason: str,
                        ttl_s: float | None = None) -> dict:
        """Record the player's authorization for ONE sweep run of up to `count` sends on this
        challenge; returns the record (its auth_id is what the run passes). Raises ValueError when
        the profile forbids sweeps or a value is out of range."""
        sw = self.profile.sweep
        if not sw.authorized:
            raise ValueError(f"event {self.profile.slug!r} has sweep.mode = {sw.mode!r}: no sweep may be "
                             "authorized (set [sweep] mode = 'player-authorized' in its event.toml)")
        if not reason or not reason.strip():
            raise ValueError("a sweep authorization needs a reason (who authorized it and why)")
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= sw.max_count:
            raise ValueError(f"sweep count must be an integer from 1 to sweep.max_count "
                             f"({sw.max_count}), got {count!r}")
        ttl = sw.ttl_s if ttl_s is None else ttl_s
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not 0 < ttl <= sw.ttl_s:
            raise ValueError(f"sweep ttl must be > 0 and at most sweep.ttl_s ({sw.ttl_s:g} s), got {ttl!r}")
        return ledger.append(SWEEP_AUTH, workdir=self.workdir, event_slug=self.profile.slug,
                             challenge_id=challenge_key(challenge_id), auth_id=secrets.token_hex(8),
                             count=count, reason=reason.strip(),
                             expires_at=round(self._clock() + float(ttl), 3))

    def sweep_auth(self, auth_id: str) -> dict | None:
        """The platform.sweep_auth record with this id for this event, or None."""
        for r in ledger.read(self.workdir):
            if (r.get("event") == SWEEP_AUTH and r.get("event_slug") == self.profile.slug
                    and r.get("auth_id") == auth_id):
                return r
        return None

    def sweep_used(self, auth_id: str) -> int:
        """Judged sends made under this authorization (unjudged ones spend nothing)."""
        return sum(1 for r in ledger.read(self.workdir)
                   if r.get("event") == EVENT and r.get("event_slug") == self.profile.slug
                   and r.get("sweep") == auth_id and r.get("judged"))

    def sweep_refusal(self, challenge_id: str, auth_id: str) -> str | None:
        """Why a sweep send under `auth_id` on `challenge_id` may not go now, or None."""
        sw = self.profile.sweep
        if not sw.authorized:
            return (f"sweep: event {self.profile.slug!r} has sweep.mode = {sw.mode!r}; no sweep send "
                    "goes out, whatever authorization is recorded")
        auth = self.sweep_auth(auth_id)
        key = challenge_key(challenge_id)
        if auth is None:
            return (f"sweep: no authorization {auth_id!r} is recorded for event {self.profile.slug!r}; "
                    f"the player runs `python -m ctf policy authorize-sweep {key} --count N --reason ...`")
        if auth.get("challenge_id") != key:
            return f"sweep: authorization {auth_id} is for challenge {auth.get('challenge_id')}, not {key}"
        if self._clock() >= float(auth.get("expires_at", 0)):
            return f"sweep: authorization {auth_id} expired; ask the player for a new one"
        used = self.sweep_used(auth_id)
        if used >= int(auth.get("count", 0)):
            return (f"sweep: authorization {auth_id} is used up ({used} of {auth.get('count')} sends); "
                    "the guard is back on: ask the player before anything more")
        return None

    def sweep_unclaimed(self, auth_id: str, flag: str) -> str | None:
        """Why a sweep send of `flag` under `auth_id` is not part of the authorization's one run, or
        None. The run claims the authorization (its claim file) and lists, by SHA-256, every value
        it offers before offering it; a value the run never offered is not one of its sends."""
        path = sweep_claim_path(self.workdir, auth_id)
        if not auth_id.isalnum() or not path.is_file():
            return (f"sweep: authorization {auth_id} was not claimed by a run; a sweep send goes only "
                    "from `python -m ctf policy sweep` (ctf.eventpolicy.run_sweep), which claims it "
                    "once before its first send")
        try:
            claim = json.loads(path.read_text(encoding="utf-8"))
            offered = claim["offered"]
            if not isinstance(offered, list):
                raise TypeError("offered is not a list")
        except (OSError, ValueError, KeyError, TypeError) as e:
            return (f"sweep: the claim file of authorization {auth_id} ({path}) is unreadable "
                    f"({type(e).__name__}: {e}); inspect it by hand")
        if hashlib.sha256(flag.encode("utf-8")).hexdigest() not in offered:
            return (f"sweep: this value was never offered by the run of authorization {auth_id}; a "
                    "sweep send goes only from that run (a spooled one is resent by drain), never "
                    "from a hand-written spool record")
        return None

    # ------------------------------------------------------------------------------- check
    def check(self, profile: EventProfile, req: SubmitRequest) -> str | None:
        rules = profile.rules
        wrong = self.wrong_count(req.challenge_id)
        if wrong >= rules.wrong_answer_stop and not rules.approved_extras:
            return (f"wrong_answer_stop: {wrong} wrong answer(s) on challenge "
                    f"{challenge_key(req.challenge_id)} (limit {rules.wrong_answer_stop}); "
                    "rules.approved_extras is false on this event, so the stop is final: no approval "
                    "or sweep reopens it")
        if req.sweep is not None:
            # The player's sweep authorization stands in for the stop and the guess budget.
            return self.sweep_refusal(req.challenge_id, req.sweep) or self.sweep_unclaimed(req.sweep, req.flag)
        if wrong >= rules.wrong_answer_stop:
            key = challenge_key(req.challenge_id)
            head = (f"wrong_answer_stop: {wrong} wrong answer(s) on challenge {key} "
                    f"(limit {rules.wrong_answer_stop}")
            missed = self.rotating_misses(req.challenge_id)
            if missed > self.profile.submit.rotating_miss_budget:
                head += (f"; {missed} rotating miss(es), past submit.rotating_miss_budget "
                         f"{self.profile.submit.rotating_miss_budget}")
            head += ")"
            if not req.confirmed:
                return (f"{head}; stop and ask the player. Do not approve it yourself: only the player "
                        f"records an approval (`python -m ctf submit-queue approve {key} --reason ...`), "
                        "then the send is resent with --confirm (confirmed=True)")
            if self.approvals_left(req.challenge_id) < 1:
                return (f"{head}; confirmed=True is not enough: no unused player approval is recorded "
                        f"(the player runs `python -m ctf submit-queue approve {key} --reason ...`)")
        if req.guess:
            used = self.guesses_used(req.challenge_id)
            if used >= rules.guess_budget:
                return (f"guess_budget: {used} guess(es) used on challenge "
                        f"{challenge_key(req.challenge_id)} (budget {rules.guess_budget}); "
                        "re-derive the value from the artifact instead of varying it")
        return None

    # ------------------------------------------------------------------------------- record
    def record(self, profile: EventProfile, req: SubmitRequest, result: SubmitResult) -> None:
        fields = {
            "event_slug": profile.slug,
            "challenge_id": req.challenge_id,
            "status": result.status.value,
            "judged": result.status.judged,
            "guess": req.guess,
            "confirmed": req.confirmed,
            "provenance": req.provenance,
            # a sweep send went out under the sweep authorization, not a stop approval: it spends none
            "post_stop": (req.sweep is None
                          and self.wrong_count(req.challenge_id) >= profile.rules.wrong_answer_stop),
        }
        if req.rotating:
            fields["rotating"] = True
        if req.sweep is not None:
            fields["sweep"] = req.sweep
        if req.answers:                       # a batch (B-044): one record, the canonical text as flag
            fields["answers"] = len(req.answers)
            reply = result.reply or {}
            remaining = reply.get("remaining")
            if (reply.get("result") == "accepted" and isinstance(remaining, int)
                    and not isinstance(remaining, bool) and remaining > 0):
                fields["partial"] = True      # banked, answers still open: the challenge is not solved
        remaining = _remaining_after(result)
        if remaining is not None:
            fields["remaining"] = remaining
        if req.attempt is not None:
            fields["attempt_id"] = req.attempt.attempt_id
            if req.attempt.ranked_retry:
                fields["ranked_retry"] = True
        if profile.rules.flag_sharing == "allowed":
            fields["flag"] = req.flag
        else:
            fields["flag_sha256"] = hashlib.sha256(req.flag.encode("utf-8")).hexdigest()
        ledger.append(EVENT, workdir=self.workdir, **fields)


def install(gate: SubmitGate, workdir: Path | None = None) -> EventRules:
    """Register the event rules on a gate: the check (before any send) and the recorder (after)."""
    rules = EventRules(gate.profile, workdir)
    gate.add_check(rules.check)
    gate.add_observer(rules.record)
    return rules
