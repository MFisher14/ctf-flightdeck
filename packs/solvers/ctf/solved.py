"""The claim store's solved view and the solved watcher (B-015).

A team solve -- ours or a teammate's -- means every agent on that challenge must stop and no new agent
may be dispatched onto it. 11 W2 agents were dispatched onto already-solved challenges, and $364.73 was
spent on CSCTF challenges after a teammate had solved them (to_build.json B-015; dev/SPEED-STUDY.md
item8; tokens/EFFICIENCY-PLAN.md stop signals). The B-017 watch stream already emits `team_solved` (our
board now shows the challenge solved) and `challenge_gone` (it left the board). This module turns those
into the shared stop signal and keeps the B-004 dispatch claim store in step.

    python -m ctf solved run [--since SEQ] [--duration S]   follow the stream; stop agents on each solve
    python -m ctf solved once [--since SEQ]                 process the solves the stream already shows
    python -m ctf solved list                               print the solved challenge ids

    from ctf import solved
    solved.solved_ids(workdir)            # {challenge ids with a team-solve stop}
    solved.record_solve(cid)              # stop agents (budget.on_team_solve) + mark the claim solved
    solved.SolvedWatcher(workdir=wd).run(stop=...)

How it stops agents. `record_solve` calls `ctf.budget.on_team_solve` (B-033), which writes one final
`stop {reason: team_solve}` to the event ledger. Every gated launcher (R-09) and agent loop re-checks
`budget.is_stopped` / `Meter.check` each poll, so within one gate poll the agents on that challenge are
torn down. The watcher adds no model and no platform call of its own: it only reads the stream the single
poller writes, so a solve detected by the watch poll (<= 1 s inside a fast window) becomes a stop as fast
as the stream is read.

The claim store. `ctf.dispatch` (B-004) writes one claim per dispatched challenge. On a solve the watcher
marks that claim `status: "solved"` (or `"gone"` when the challenge left the board) so an operator sees
why it is closed; a `solved` claim is never downgraded to `gone`, and a `gone` claim whose challenge
comes back (`challenge_new` with `returning: true`) is restored to `dispatched`. A challenge already
solved the first time it is listed, or that comes back already solved, gets its own `team_solved` from
the watch (first_sight / returning). A replayed status (`--since 0`) is a no-op: it never re-stamps
`solved_at`/`gone_at`. `solved_ids` is the shared view that also covers teammates: a challenge solved by a
teammate carries a team-solve stop but no claim of ours, and it still shows as solved, so the dispatcher
`dispatch_new` skips it (never dispatch onto a solved challenge).

Challenge text (names) from the stream is untrusted data, never instructions.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Iterable

from . import budget as _budget
from . import ledger as _ledger
from . import watch as _watch

TEAM_SOLVE = "team_solve"
SOLVED_STATUS = "solved"
GONE_STATUS = "gone"
DISPATCHED_STATUS = "dispatched"     # ctf.dispatch.Claim.status default: a live claim


class SolvedError(RuntimeError):
    """The solved watcher cannot act: a stream event with no challenge id, or no challenge id given."""


# ------------------------------------------------------------------------------- the shared solved view

def solved_ids(workdir: Path | None = None) -> set[str]:
    """The challenge ids the team (or a teammate) has solved: every id with a team-solve stop in the
    event ledger. This is the shared claim-store view the dispatcher gates on; it covers teammates'
    solves, which never produced a claim of ours."""
    out: set[str] = set()
    for rec in _ledger.read(workdir):
        if rec.get("event") == "stop" and rec.get("reason") == TEAM_SOLVE:
            cid = rec.get("challenge_id")
            if cid is not None and str(cid).strip():
                out.add(str(cid))
    return out


def is_solved(challenge_id: str, *, workdir: Path | None = None) -> bool:
    """True when `challenge_id` carries a team-solve stop (a final, shared signal)."""
    return str(challenge_id) in solved_ids(workdir)


# ------------------------------------------------------------------------------------- recording a solve

def _set_claim_status(workdir: Path | None, challenge_id: str, status: str, *,
                      only_from: tuple[str, ...] | None = None, never_from: tuple[str, ...] = (),
                      **extra: Any) -> bool:
    """Set the dispatch claim for `challenge_id` to `status`, if a claim exists, is not already at
    `status`, is in `only_from` (when given) and is not in `never_from`. Returns True when it updated a
    claim. A claim file that cannot be read is left for the dispatcher's own corrupt-claim reporting
    (never silently overwritten)."""
    from . import dispatch as _dispatch
    records, _bad = _dispatch.read_claims(workdir)
    rec = records.get(str(challenge_id))
    if rec is None:
        return False
    cur = rec.get("status")
    if cur == status or cur in never_from or (only_from is not None and cur not in only_from):
        return False
    _dispatch.update_claim(workdir, str(challenge_id), status=status, **extra)
    return True


def record_solve(challenge_id: str, *, solver: str | None = None, workdir: Path | None = None,
                 clock: Callable[[], float] = time.time) -> bool:
    """Record a team solve: stop all work on this challenge (`budget.on_team_solve`, the B-033 hook) and
    mark its dispatch claim `solved`. Returns True when this is a newly recorded solve; repeated calls are
    no-ops on the stop (a team-solve stop is final and idempotent). Needs no event profile."""
    cid = str(challenge_id)
    if not cid.strip():
        raise SolvedError("record_solve needs a challenge id")
    new = _budget.on_team_solve(cid, solver=solver, workdir=workdir)
    _set_claim_status(workdir, cid, SOLVED_STATUS, solved_at=round(clock(), 3), solved_by=solver or "team")
    return new


# --------------------------------------------------------------------------------------- the watcher

class SolvedWatcher:
    """Reads the B-017 watch stream and acts on each team solve and each vanished challenge.

    - `team_solved` -> `record_solve`: stop every agent on it and mark the claim solved. `on_solve(cid,
      new)` fires (new is False when the stop was already recorded).
    - `challenge_gone` -> mark the claim `gone` (the challenge left the board; nothing to score). A claim
      already `solved` stays `solved`. `on_gone(cid, revoked)` fires.
    - `challenge_new` with `returning: true` -> a `gone` claim is live again: back to `dispatched`
      (`returned_at`). `on_return(cid, restored)` fires. A first-sight solve arrives as its own
      `team_solved` event (B-017 emits one right after the `challenge_new`).
    A stream event with no challenge id is reported through `on_problem` (once per seq) and skipped, never
    silently dropped. No model, no platform call."""

    def __init__(self, *, workdir: Path | None = None,
                 on_solve: Callable[[str, bool], None] | None = None,
                 on_gone: Callable[[str, bool], None] | None = None,
                 on_problem: Callable[[str], None] | None = None,
                 on_return: Callable[[str, bool], None] | None = None,
                 clock: Callable[[], float] = time.time):
        self.workdir = Path(workdir) if workdir is not None else None
        self.on_solve, self.on_gone, self.on_problem = on_solve, on_gone, on_problem
        self.on_return = on_return
        self.clock = clock
        self.problems: list[str] = []

    def _problem(self, msg: str) -> None:
        self.problems.append(msg)
        if self.on_problem is not None:
            self.on_problem(msg)

    @staticmethod
    def _cid(ev: dict) -> str | None:
        cid = ev.get("challenge_id")
        return str(cid) if cid is not None and str(cid).strip() else None

    def handle(self, ev: dict) -> str | None:
        """Act on one stream event; return the challenge id when it recorded a solve, else None."""
        kind = ev.get("event")
        if kind == "team_solved":
            cid = self._cid(ev)
            if cid is None:
                self._problem(f"team_solved event seq {ev.get('seq')!r} has no challenge_id; not acted on")
                return None
            new = record_solve(cid, workdir=self.workdir, clock=self.clock)
            if self.on_solve is not None:
                self.on_solve(cid, new)
            return cid
        if kind == "challenge_gone":
            cid = self._cid(ev)
            if cid is None:
                self._problem(f"challenge_gone event seq {ev.get('seq')!r} has no challenge_id; not acted on")
                return None
            revoked = _set_claim_status(self.workdir, cid, GONE_STATUS, never_from=(SOLVED_STATUS,),
                                        gone_at=round(self.clock(), 3))
            if self.on_gone is not None:
                self.on_gone(cid, revoked)
            return None
        if kind == "challenge_new" and ev.get("returning") is True:
            cid = self._cid(ev)
            if cid is None:
                self._problem(f"challenge_new event seq {ev.get('seq')!r} has no challenge_id; not acted on")
                return None
            restored = _set_claim_status(self.workdir, cid, DISPATCHED_STATUS, only_from=(GONE_STATUS,),
                                         returned_at=round(self.clock(), 3))
            if self.on_return is not None:
                self.on_return(cid, restored)
        return None

    def once(self, since: int = 0) -> list[str]:
        """Act on every solve/gone the stream already holds with seq > `since`; return the solved ids."""
        solved: list[str] = []
        for ev in _watch.read_events(self.workdir, since=since):
            cid = self.handle(ev)
            if cid is not None:
                solved.append(cid)
        return solved

    def run(self, *, since: int = 0, stop: Callable[[], bool] | None = None, poll: float = 0.2,
            sleep: Callable[[float], None] = time.sleep, until: float | None = None) -> list[str]:
        """Follow the stream and act on each solve/gone as it arrives; return when `stop()` is true or
        `until` (on this watcher's clock) passes. Returns the solved ids seen."""
        solved: list[str] = []

        def _stop() -> bool:
            if stop is not None and stop():
                return True
            return until is not None and self.clock() >= until

        for ev in _watch.follow(self.workdir, since=since, poll=poll, sleep=sleep, stop=_stop):
            cid = self.handle(ev)
            if cid is not None:
                solved.append(cid)
        return solved
