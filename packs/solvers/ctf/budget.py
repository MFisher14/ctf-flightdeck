"""Hard-tail budget gates and stop signals (B-033). Spend is fed by tools/ledger (live session logs),
by B-101/B-193 later, or by hand.

    class Meter(Protocol):
        add_spend(challenge_id, usd, tokens) -> None   record spend against one challenge
        spent(challenge_id) -> Spend                    cumulative usd + tokens
        cap(challenge_id) -> float                      the USD cap for that challenge right now

cap_usd() is the agreed cap rule from the event profile's [budget] table, so every Meter applies
the same numbers: per_point * points, clamped to [floor, ceiling]; when per_challenge_day is set
(the Huntress flat rate) the cap is per_challenge_day * days_open instead, still clamped by ceiling.
When the profile sets the overthink fields (B-130) and the solve count is known, a low-point,
high-solve challenge is clamped down to overthink_usd (an easy, well-solved row is not worth a deep
spend). At the cap a Meter raises BudgetExceeded; extending is a human decision (B-033 blocker),
recorded in the ledger.

LedgerMeter is the implementation. All of its state lives in the event ledger (<workdir>/ledger.jsonl),
so every agent process and the CLI see the same numbers:

    spend              {challenge_id, usd, tok, source?}     one priced slice of model spend
    budget_challenge   {challenge_id, points?, solves?, opened_at?, tail?, name?}  what the cap is computed from
    budget_extend      {challenge_id, usd, by, reason, cap_usd}            a human raised the cap
    budget_checkpoint  {challenge_id, spent_usd, cap_usd, path}           the cap was reached
    stop               {challenge_id, reason, by?, note?}  reason: team_solve | no_progress | manual
    budget_resume      {challenge_id, by}                  a human lifted a manual/no-progress stop
    progress           {challenge_id, note?}               the work moved forward (resets the timer)

(The token count is the field "tok": ctf.ledger refuses any key containing "token" as a secret.)

Gates, checked by LedgerMeter.check() and by add_spend():
  * cap: spent >= cap -> one checkpoint per cap level (a JSON file under <workdir>/budget/checkpoints
    plus a budget_checkpoint event), the on_cap callback (default: a line on stderr telling the player
    how to extend), then BudgetExceeded. Nothing in this module extends a cap by itself: extend() is
    only called by `python -m ctf budget extend`, which needs a person at a terminal.
  * team solve: on_team_solve(challenge_id) records a stop; the B-015 solved watcher calls it, and
    `python -m ctf budget stop ID --solved` fires it by hand. A team-solve stop is final.
  * no progress: for high-value tails (points at or above ceiling/per_point, i.e. where the value cap
    no longer bites, or a challenge registered with tail=True) 20 minutes with no progress-type ledger
    event stops the challenge. Progress-type events: PROGRESS_EVENTS below.
  * OSINT box (B-115, opt-in): a meter built with `token_cap` and/or `time_box_seconds` also gates live
    OSINT -- `check()` raises OsintBoxExceeded once the challenge has used its token cap or run past its
    wall-clock time box, so an open-ended OSINT loop stops and hands off to a human. A meter that sets
    neither is unchanged. The handoff rig that catches the signal and writes the handoff file is
    ctf.osint_playbook; it never drives a browser or starts a model.
"""
from __future__ import annotations

import datetime as _dt
import json
import math
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Protocol, runtime_checkable

from . import ledger as _ledger
from . import paths as _paths
from .event import Budget, EventProfile

NO_PROGRESS_SECONDS = 20 * 60
STOP_REASONS = ("team_solve", "no_progress", "manual")
RESUMABLE = frozenset({"no_progress", "manual"})
PROGRESS_EVENTS = frozenset({"progress", "claim", "first_tool", "candidate", "budget_challenge",
                             "budget_extend", "budget_resume"})
CHECKPOINT_DIR = ("budget", "checkpoints")


class BudgetExceeded(RuntimeError):
    def __init__(self, challenge_id: str, spent_usd: float, cap_usd: float):
        super().__init__(f"challenge {challenge_id}: spent ${spent_usd:.2f} of ${cap_usd:.2f} cap; "
                         "checkpoint and ask the player to extend")
        self.challenge_id, self.spent_usd, self.cap_usd = challenge_id, spent_usd, cap_usd


class ChallengeStopped(RuntimeError):
    """Work on this challenge must stop (a teammate solved it, no progress, or a manual stop)."""

    def __init__(self, challenge_id: str, reason: str, detail: str = ""):
        msg = f"challenge {challenge_id}: stopped ({reason})"
        super().__init__(msg + (f": {detail}" if detail else ""))
        self.challenge_id, self.reason = challenge_id, reason


# OSINT time-box / token-cap reasons (B-115). An OSINT-profile meter (token_cap and/or
# time_box_seconds set) raises this from check() when a live-OSINT run hits its token cap or its wall
# time box. It is a *signal*, not a stop: the B-115 handoff rig (ctf.osint_playbook) catches it, writes
# the handoff file for the human and records the stop. A bare meter with neither set never raises it.
OSINT_TOKEN_CAP = "token_cap"
OSINT_TIME_BOX = "time_box"
OSINT_REASONS = (OSINT_TOKEN_CAP, OSINT_TIME_BOX)


class OsintBoxExceeded(RuntimeError):
    """A live-OSINT run reached its token cap or its time box; hand off to the human."""

    def __init__(self, challenge_id: str, reason: str, *, tokens: int, token_cap: int | None,
                 elapsed_s: float | None, time_box_seconds: float | None):
        if reason == OSINT_TOKEN_CAP:
            detail = f"used {tokens} of {token_cap} tokens"
        else:
            detail = f"ran {elapsed_s:.0f}s of a {time_box_seconds:.0f}s time box" if elapsed_s is not None \
                else "time box reached"
        super().__init__(f"challenge {challenge_id}: live-OSINT {reason} reached ({detail}); hand off to "
                         "the human (nothing more is run automatically)")
        self.challenge_id, self.reason = challenge_id, reason
        self.tokens, self.token_cap = tokens, token_cap
        self.elapsed_s, self.time_box_seconds = elapsed_s, time_box_seconds


@dataclass(frozen=True)
class Spend:
    usd: float = 0.0
    tokens: int = 0


@runtime_checkable
class Meter(Protocol):
    def add_spend(self, challenge_id: str, usd: float, tokens: int) -> None: ...
    def spent(self, challenge_id: str) -> Spend: ...
    def cap(self, challenge_id: str) -> float: ...


def cap_usd(budget: Budget, points: int | float | None, days_open: int | None = None,
            solves: int | None = None) -> float:
    """USD cap for one challenge under `budget`. `points` None (unknown value) gives the floor.

    B-130 overthink cap: when `solves` is known and the budget's overthink fields are set, a
    low-point, high-solve challenge (points <= overthink_max_points and solves >= overthink_min_solves)
    is clamped down to overthink_usd. A low-point row that many teams already solved is an easy one;
    it is not worth a deep token spend (Pink 29 burned ~1.96B tokens on a 50-point / 71-solve row).
    The clamp only ever LOWERS the cap, and never fires when the solve count is unknown."""
    base = _base_cap_usd(budget, points, days_open)
    over = overthink_cap(budget, points, solves)
    return min(base, over) if over is not None else base


def _base_cap_usd(budget: Budget, points: int | float | None, days_open: int | None) -> float:
    if budget.per_challenge_day is not None:
        if days_open is None or days_open < 1:
            raise ValueError("a per_challenge_day budget needs days_open >= 1")
        return min(budget.ceiling, budget.per_challenge_day * days_open)
    if points is None:
        return budget.floor
    if points < 0:
        raise ValueError("points must be >= 0")
    return max(budget.floor, min(budget.ceiling, budget.per_point * points))


def overthink_cap(budget: Budget, points: int | float | None, solves: int | None) -> float | None:
    """The hard overthink cap for a low-point, high-solve challenge, or None when it does not apply
    (the overthink fields are unset, the solve count or points are unknown, or the challenge is not
    both low-point and high-solve). B-130."""
    if (budget.overthink_usd is None or budget.overthink_max_points is None
            or budget.overthink_min_solves is None):
        return None
    if points is None or solves is None:
        return None
    if solves < 0:
        raise ValueError("solves must be >= 0")
    if points <= budget.overthink_max_points and solves >= budget.overthink_min_solves:
        return budget.overthink_usd
    return None


def high_value_points(budget: Budget) -> float | None:
    """Points at which the per-point cap reaches the ceiling (the value cap stops biting). None for a
    per_challenge_day budget (points are not comparable there) or a zero per_point."""
    if budget.per_challenge_day is not None or budget.per_point <= 0:
        return None
    return budget.ceiling / budget.per_point


# ------------------------------------------------------------------ state

@dataclass
class _State:
    challenge_id: str
    spend_usd: float = 0.0
    tokens: int = 0
    points: float | None = None
    solves: int | None = None
    opened_ts: float | None = None
    tail: bool = False
    name: str | None = None
    first_ts: float | None = None
    last_progress_ts: float | None = None
    extended_usd: float = 0.0
    stop_reason: str | None = None
    stop_by: str | None = None
    checkpointed_caps: set = field(default_factory=set)


@dataclass(frozen=True)
class ChallengeStatus:
    challenge_id: str
    spent_usd: float
    tokens: int
    cap_usd: float
    base_cap_usd: float
    extended_usd: float
    points: float | None
    tail: bool
    timer_applies: bool
    idle_seconds: float | None
    state: str                     # ok | at_cap | stopped
    stop_reason: str | None
    stop_by: str | None
    # OSINT time-box / token-cap profile (B-115); None on a meter that sets neither.
    token_cap: int | None = None
    tokens_left: int | None = None
    box_seconds_left: float | None = None
    box_state: str = "ok"          # ok | over_tokens | over_time

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_when(value) -> float:
    """epoch seconds (int/float/numeric str) or ISO-8601 (a naive value is UTC)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, _dt.datetime):
        d = value
    elif isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
        try:
            d = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"not a time: {value!r} (epoch seconds or ISO-8601)") from None
    else:
        raise ValueError(f"not a time: {value!r}")
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.timestamp()


def _check_id(challenge_id) -> str:
    if not isinstance(challenge_id, str) or not challenge_id.strip():
        raise ValueError(f"challenge_id must be a non-empty string, got {challenge_id!r}")
    return challenge_id


def _safe_name(challenge_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", challenge_id)[:80] or "_"


class LedgerMeter:
    """The Meter, backed by the event ledger. Reads the ledger incrementally (byte offset), so a
    long-running agent pays only for new lines."""

    def __init__(self, profile: EventProfile | Budget, *, workdir: Path | None = None,
                 points: Mapping[str, float] | Callable[[str], float | None] | None = None,
                 solves: Mapping[str, int] | Callable[[str], int | None] | None = None,
                 no_progress_seconds: float = NO_PROGRESS_SECONDS,
                 high_value_points: float | None = None,
                 token_cap: int | None = None,
                 time_box_seconds: float | None = None,
                 on_cap: Callable[[ChallengeStatus, Path], None] | None = None,
                 clock: Callable[[], float] = time.time):
        self.budget = profile.budget if isinstance(profile, EventProfile) else profile
        if not isinstance(self.budget, Budget):
            raise TypeError("LedgerMeter needs an EventProfile or an event.Budget")
        slug = profile.slug if isinstance(profile, EventProfile) else None
        self.workdir = Path(workdir) if workdir is not None else _paths.workdir(slug)
        self._points = points
        self._solves = solves          # a scoreboard adapter: cid -> solve count (B-130 overthink cap)
        self.no_progress_seconds = float(no_progress_seconds)
        hv = high_value_points if high_value_points is not None else globals()["high_value_points"](self.budget)
        self.high_value_points = hv
        # OSINT time-box / token-cap profile (B-115). Both default None: a meter that sets neither
        # behaves exactly as before and never raises OsintBoxExceeded.
        if token_cap is not None and (isinstance(token_cap, bool) or not isinstance(token_cap, int)
                                      or token_cap < 1):
            raise ValueError(f"token_cap must be an int >= 1, got {token_cap!r}")
        if time_box_seconds is not None and (isinstance(time_box_seconds, bool)
                                             or not isinstance(time_box_seconds, (int, float))
                                             or not math.isfinite(time_box_seconds) or time_box_seconds <= 0):
            raise ValueError(f"time_box_seconds must be a finite number > 0, got {time_box_seconds!r}")
        self.token_cap = token_cap
        self.time_box_seconds = float(time_box_seconds) if time_box_seconds is not None else None
        self.on_cap = on_cap if on_cap is not None else _default_on_cap
        self.clock = clock
        self._states: dict[str, _State] = {}
        self._offset = 0
        self._ino = None

    # ---------------------------------------------------------------- ledger tail
    def _refresh(self) -> None:
        p = _ledger.path(self.workdir)
        try:
            st = p.stat()
        except FileNotFoundError:
            return
        if self._ino is not None and (st.st_ino != self._ino or st.st_size < self._offset):
            self._states.clear()           # ledger replaced or truncated: rebuild from the start
            self._offset = 0
        self._ino = st.st_ino
        if st.st_size == self._offset:
            return
        with open(p, "rb") as fh:
            fh.seek(self._offset)
            chunk = fh.read()
        end = chunk.rfind(b"\n")
        if end < 0:
            return                         # a writer is mid-line; take it next time
        for n, raw in enumerate(chunk[:end + 1].splitlines()):
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError as e:
                raise ValueError(f"{p}: corrupt ledger line at byte {self._offset}: {e}") from None
            self._apply(rec)
        self._offset += end + 1

    def _state(self, cid: str) -> _State:
        s = self._states.get(cid)
        if s is None:
            s = self._states[cid] = _State(cid)
        return s

    def _apply(self, rec: dict) -> None:
        cid = rec.get("challenge_id")
        if not isinstance(cid, str) or not cid:
            return
        ev, ts = rec.get("event"), float(rec.get("ts") or 0.0)
        s = self._state(cid)
        if s.first_ts is None or ts < s.first_ts:
            s.first_ts = ts
        if ev in PROGRESS_EVENTS:
            s.last_progress_ts = max(s.last_progress_ts or 0.0, ts)
        if ev == "spend":
            s.spend_usd += float(rec.get("usd") or 0.0)
            s.tokens += int(rec.get("tok") or 0)
        elif ev == "budget_challenge":
            if rec.get("points") is not None:
                s.points = float(rec["points"])
            if rec.get("solves") is not None:
                s.solves = int(rec["solves"])
            if rec.get("opened_at") is not None:
                s.opened_ts = float(rec["opened_at"])
            if rec.get("tail") is not None:
                s.tail = bool(rec["tail"])
            if rec.get("name"):
                s.name = str(rec["name"])
        elif ev == "budget_extend":
            s.extended_usd += float(rec.get("usd") or 0.0)
        elif ev == "budget_checkpoint":
            s.checkpointed_caps.add(round(float(rec.get("cap_usd") or 0.0), 6))
        elif ev == "stop":
            if s.stop_reason != "team_solve":      # a team solve is final
                s.stop_reason, s.stop_by = rec.get("reason"), rec.get("by")
        elif ev == "budget_resume":
            if s.stop_reason in RESUMABLE:
                s.stop_reason = s.stop_by = None

    # ---------------------------------------------------------------- Meter protocol
    def add_spend(self, challenge_id: str, usd: float, tokens: int, *, source: str | None = None) -> None:
        cid = _check_id(challenge_id)
        if isinstance(usd, bool) or not isinstance(usd, (int, float)) or not math.isfinite(usd) or usd < 0:
            raise ValueError(f"usd must be a finite number >= 0, got {usd!r}")
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ValueError(f"tokens must be an int >= 0, got {tokens!r}")
        fields = {"challenge_id": cid, "usd": float(usd), "tok": tokens}
        if source:
            fields["source"] = source
        _ledger.append("spend", workdir=self.workdir, **fields)
        self._gate_cap(cid)

    def spent(self, challenge_id: str) -> Spend:
        self._refresh()
        s = self._states.get(_check_id(challenge_id))
        return Spend(round(s.spend_usd, 10), s.tokens) if s else Spend()

    def cap(self, challenge_id: str) -> float:
        self._refresh()
        cid = _check_id(challenge_id)
        return self._base_cap(cid) + self._state(cid).extended_usd

    # ---------------------------------------------------------------- the rest of the API
    def points(self, challenge_id: str) -> float | None:
        self._refresh()
        s = self._state(challenge_id)
        if s.points is not None:
            return s.points
        if callable(self._points):
            return self._points(challenge_id)
        if self._points is not None:
            v = self._points.get(challenge_id)
            return None if v is None else float(v)
        return None

    def solves(self, challenge_id: str) -> int | None:
        """The challenge's solve count (how many teams have it), for the B-130 overthink cap. From a
        ledger budget_challenge record first, then the scoreboard adapter passed as `solves=`. None
        when it is unknown (the overthink cap then never fires)."""
        self._refresh()
        s = self._state(challenge_id)
        if s.solves is not None:
            return s.solves
        if callable(self._solves):
            v = self._solves(challenge_id)
            return None if v is None else int(v)
        if self._solves is not None:
            v = self._solves.get(challenge_id)
            return None if v is None else int(v)
        return None

    def days_open(self, challenge_id: str) -> int:
        s = self._state(challenge_id)
        start = s.opened_ts if s.opened_ts is not None else s.first_ts
        if start is None:
            return 1
        return max(1, math.ceil((self.clock() - start) / 86400.0))

    def _base_cap(self, cid: str) -> float:
        days = self.days_open(cid) if self.budget.per_challenge_day is not None else None
        return cap_usd(self.budget, self.points(cid), days, self.solves(cid))

    def register(self, challenge_id: str, *, points: float | None = None, solves: int | None = None,
                 opened_at=None, tail: bool | None = None, name: str | None = None) -> dict:
        """Record what the cap is computed from (and start the no-progress clock). `solves` is the
        challenge's solve count for the B-130 overthink cap; omit it to leave the cap on points only."""
        cid = _check_id(challenge_id)
        fields: dict = {"challenge_id": cid}
        if points is not None:
            if isinstance(points, bool) or not isinstance(points, (int, float)) or points < 0:
                raise ValueError(f"points must be a number >= 0, got {points!r}")
            fields["points"] = points
        if solves is not None:
            if isinstance(solves, bool) or not isinstance(solves, int) or solves < 0:
                raise ValueError(f"solves must be an int >= 0, got {solves!r}")
            fields["solves"] = solves
        if opened_at is not None:
            fields["opened_at"] = _parse_when(opened_at)
        if tail is not None:
            fields["tail"] = bool(tail)
        if name:
            fields["name"] = name
        return _ledger.append("budget_challenge", workdir=self.workdir, **fields)

    def extend(self, challenge_id: str, usd: float, *, by: str, reason: str) -> float:
        """Raise the cap by `usd`. A human decision: only `python -m ctf budget extend` (which needs a
        terminal and a typed confirmation) calls this. Returns the new cap."""
        cid = _check_id(challenge_id)
        if isinstance(usd, bool) or not isinstance(usd, (int, float)) or not math.isfinite(usd) or usd <= 0:
            raise ValueError(f"an extension must be a positive amount, got {usd!r}")
        if not by or not str(by).strip():
            raise ValueError("an extension must name who decided it (by=...)")
        if not reason or not str(reason).strip():
            raise ValueError("an extension must give a reason")
        new_cap = self.cap(cid) + float(usd)
        _ledger.append("budget_extend", workdir=self.workdir, challenge_id=cid, usd=float(usd),
                       by=str(by), reason=str(reason), cap_usd=new_cap)
        return new_cap

    def stop(self, challenge_id: str, reason: str, *, by: str | None = None, note: str | None = None) -> bool:
        """Record a stop. Returns False when the challenge already carries a stop with that reason."""
        cid = _check_id(challenge_id)
        if reason not in STOP_REASONS:
            raise ValueError(f"stop reason must be one of {', '.join(STOP_REASONS)}, got {reason!r}")
        self._refresh()
        s = self._state(cid)
        if s.stop_reason == reason or s.stop_reason == "team_solve":
            return False
        fields = {"challenge_id": cid, "reason": reason}
        if by:
            fields["by"] = by
        if note:
            fields["note"] = note
        _ledger.append("stop", workdir=self.workdir, **fields)
        return True

    def resume(self, challenge_id: str, *, by: str) -> None:
        """Lift a manual or no-progress stop (a human decision). A team-solve stop is final."""
        cid = _check_id(challenge_id)
        if not by or not str(by).strip():
            raise ValueError("a resume must name who decided it (by=...)")
        self._refresh()
        s = self._state(cid)
        if s.stop_reason is None:
            raise ValueError(f"challenge {cid} is not stopped")
        if s.stop_reason not in RESUMABLE:
            raise ValueError(f"challenge {cid} was stopped by {s.stop_reason}; that stop is final")
        _ledger.append("budget_resume", workdir=self.workdir, challenge_id=cid, by=str(by))

    def mark_progress(self, challenge_id: str, note: str | None = None) -> None:
        fields = {"challenge_id": _check_id(challenge_id)}
        if note:
            fields["note"] = note
        _ledger.append("progress", workdir=self.workdir, **fields)

    def challenges(self) -> list[str]:
        self._refresh()
        return sorted(self._states)

    def timer_applies(self, challenge_id: str) -> bool:
        s = self._state(challenge_id)
        if s.tail:
            return True
        pts = self.points(challenge_id)
        return self.high_value_points is not None and pts is not None and pts >= self.high_value_points

    def idle_seconds(self, challenge_id: str) -> float | None:
        """Seconds since the last progress-type event (or since the challenge first appeared)."""
        s = self._state(challenge_id)
        since = s.last_progress_ts if s.last_progress_ts is not None else s.first_ts
        return None if since is None else max(0.0, self.clock() - since)

    # ------------------------------------------------------------------ OSINT time-box / token-cap
    def tokens_left(self, challenge_id: str) -> int | None:
        """Tokens remaining under the OSINT token cap, or None when no cap is set."""
        if self.token_cap is None:
            return None
        return max(0, self.token_cap - self.spent(challenge_id).tokens)

    def box_elapsed(self, challenge_id: str) -> float | None:
        """Seconds since the OSINT run opened (the registered `opened_at`, else the first ledger event
        for the challenge). None when no time box is set or the challenge has no event yet. Wall-clock
        on purpose: the time box bounds a human/agent's live-OSINT session, which is real elapsed
        time; drive it in tests with an injected `clock` (see docs/build-log/B-115.md)."""
        if self.time_box_seconds is None:
            return None
        self._refresh()
        s = self._state(challenge_id)
        start = s.opened_ts if s.opened_ts is not None else s.first_ts
        return None if start is None else max(0.0, self.clock() - start)

    def box_seconds_left(self, challenge_id: str) -> float | None:
        """Seconds left in the OSINT time box (the full box before the run opens), or None when unset."""
        if self.time_box_seconds is None:
            return None
        elapsed = self.box_elapsed(challenge_id)
        return self.time_box_seconds if elapsed is None else max(0.0, self.time_box_seconds - elapsed)

    def osint_reason(self, challenge_id: str) -> str | None:
        """The OSINT box reason tripped for this challenge right now, or None. The token cap is checked
        first (a hard resource), then the time box, so the reason is deterministic when both are over."""
        if self.token_cap is not None and self.spent(challenge_id).tokens >= self.token_cap:
            return OSINT_TOKEN_CAP
        if self.time_box_seconds is not None:
            elapsed = self.box_elapsed(challenge_id)
            if elapsed is not None and elapsed >= self.time_box_seconds:
                return OSINT_TIME_BOX
        return None

    def status(self, challenge_id: str) -> ChallengeStatus:
        self._refresh()
        cid = _check_id(challenge_id)
        s = self._state(cid)
        base = self._base_cap(cid)
        cap = base + s.extended_usd
        state = "stopped" if s.stop_reason else ("at_cap" if s.spend_usd >= cap else "ok")
        reason = self.osint_reason(cid)
        box_state = "over_tokens" if reason == OSINT_TOKEN_CAP else ("over_time" if reason == OSINT_TIME_BOX
                                                                     else "ok")
        return ChallengeStatus(cid, round(s.spend_usd, 10), s.tokens, cap, base, s.extended_usd,
                               self.points(cid), s.tail, self.timer_applies(cid), self.idle_seconds(cid),
                               state, s.stop_reason, s.stop_by,
                               token_cap=self.token_cap, tokens_left=self.tokens_left(cid),
                               box_seconds_left=self.box_seconds_left(cid), box_state=box_state)

    def check(self, challenge_id: str) -> ChallengeStatus:
        """Gate before more work. Raises ChallengeStopped (team solve, manual stop, or the no-progress
        timer, which it records), OsintBoxExceeded (an OSINT-profile meter's token cap or time box has
        been reached -- a signal the B-115 handoff rig catches; never raised by a meter that sets
        neither), or BudgetExceeded (after the checkpoint); else returns the status."""
        cid = _check_id(challenge_id)
        st = self.status(cid)
        if st.stop_reason:
            raise ChallengeStopped(cid, st.stop_reason)
        reason = self.osint_reason(cid)
        if reason is not None:
            raise OsintBoxExceeded(cid, reason, tokens=st.tokens, token_cap=self.token_cap,
                                   elapsed_s=self.box_elapsed(cid), time_box_seconds=self.time_box_seconds)
        if st.timer_applies and st.idle_seconds is not None and st.idle_seconds >= self.no_progress_seconds:
            mins = st.idle_seconds / 60
            self.stop(cid, "no_progress", note=f"{mins:.0f} min without progress")
            raise ChallengeStopped(cid, "no_progress", f"{mins:.0f} min without progress on a high-value tail")
        self._gate_cap(cid)
        return st

    def _gate_cap(self, cid: str) -> None:
        st = self.status(cid)
        if st.spent_usd < st.cap_usd:
            return
        s = self._state(cid)
        key = round(st.cap_usd, 6)
        if key not in s.checkpointed_caps:
            path = self._write_checkpoint(st)
            _ledger.append("budget_checkpoint", workdir=self.workdir, challenge_id=cid,
                           spent_usd=st.spent_usd, cap_usd=st.cap_usd, path=str(path))
            s.checkpointed_caps.add(key)
            self.on_cap(st, path)
        raise BudgetExceeded(cid, st.spent_usd, st.cap_usd)

    def _write_checkpoint(self, st: ChallengeStatus) -> Path:
        d = self.workdir.joinpath(*CHECKPOINT_DIR)
        d.mkdir(parents=True, exist_ok=True)
        recent = [r for r in _ledger.read(self.workdir) if r.get("challenge_id") == st.challenge_id][-50:]
        n = len(list(d.glob(f"{_safe_name(st.challenge_id)}-*.json"))) + 1
        path = d / f"{_safe_name(st.challenge_id)}-{n}.json"
        doc = {"challenge_id": st.challenge_id, "at": self.clock(), "status": st.to_dict(),
               "ask": extend_hint(st), "recent_events": recent}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, default=str)
        return path


def extend_hint(st: ChallengeStatus) -> str:
    return (f"budget cap reached on challenge {st.challenge_id}: spent ${st.spent_usd:.2f} of "
            f"${st.cap_usd:.2f}. Work is paused. To continue, the player runs: "
            f"python -m ctf budget extend {st.challenge_id} --usd <amount> --reason <why>")


def _default_on_cap(st: ChallengeStatus, path: Path) -> None:
    print(f"BUDGET: {extend_hint(st)} (checkpoint: {path})", file=sys.stderr)


# ------------------------------------------------------------------ the solved-watcher hook

def on_team_solve(challenge_id: str, *, solver: str | None = None, workdir: Path | None = None) -> bool:
    """Stop all work on `challenge_id` because a teammate (or we) solved it. The B-015 solved watcher
    calls this once per solve it sees; repeated calls are no-ops. Returns True when it recorded a new
    stop. Needs no event profile: it only writes the ledger."""
    cid = _check_id(challenge_id)
    for rec in _ledger.read(workdir):
        if rec.get("event") == "stop" and rec.get("challenge_id") == cid and rec.get("reason") == "team_solve":
            return False
    fields = {"challenge_id": cid, "reason": "team_solve"}
    if solver:
        fields["by"] = solver
    _ledger.append("stop", workdir=workdir, **fields)
    return True


def is_stopped(challenge_id: str, *, workdir: Path | None = None) -> str | None:
    """The active stop reason for a challenge, or None. Cheap enough for an agent loop guard."""
    cid = _check_id(challenge_id)
    reason = None
    for rec in _ledger.read(workdir):
        if rec.get("challenge_id") != cid:
            continue
        if rec.get("event") == "stop" and reason != "team_solve":
            reason = rec.get("reason")
        elif rec.get("event") == "budget_resume" and reason in RESUMABLE:
            reason = None
    return reason
