"""Timed-mode chaining (B-036): base -> time_trial -> mastery, opened by any close, behind the lane gate.

A Game Master challenge has three modes, `<id>`, `<id>/time_trial` and `<id>/mastery`. At Huntress
2026 the timed modes waited for an agent whenever the base was not closed by our own opener: a base a
teammate banked (Day 6 Script and Binary), a Time Trial banked by hand (Day 23 Metadata), or a base our
opener closed but whose Time Trial start was left to an agent-launched script (Day 4 Binary). A Mastery
that failed was not retried after its fix was folded (Day 7), and a killed run left no record that it
never submitted (Day 23 Binary). This module decides, from the event's own records and with no model:

    step = plan("binary-day-04", "binary", workdir=wd)     # ChainStep
    step.action          # wait | start | retry | stop | hold | done
    step.challenge_id    # the mode the action is about ("binary-day-04/time_trial")
    step.gate            # the LaneGate behind a start, retry or stop

    mark_closed("script-day-06", by="teammate", workdir=wd)   # a close no record of ours shows
    with AttemptGuard("x/mastery", lane_key=step.lane_key, workdir=wd) as att:
        ...                                                 # the clock runner's solve and submit
        att.done("correct")                                 # anything else, or a kill: not_submitted

**Closed** (`closures`, earliest record wins): our accepted send (`platform.submit` with status
correct or already_solved and not `partial`, the answer suffix `#<aid>` stripped), an `adapt.attempt`
with outcome correct, an `adapt.closed` mark (by `teammate` or `hand`), a team-solve `stop` in the
ledger (B-015's shared solved view, `ctf.solved`; read as a teammate's unless our own send came first),
or a `team_solved` line of the board watch stream (B-017; a teammate). Who closed it does not matter to
the chain; it is reported.

**The rule.** The first mode not closed decides. The base not closed: `wait` (the opener's job). A
timed mode whose predecessor is closed: the lane gate (`regress.gate`, warm reuse) says `start` on YES,
`stop` on NO (after its own recut and re-gate), `hold` on NOT_RUN (a person decides; never started
blind). A timed mode with failed attempts (`incorrect`, `not_submitted`, `expired`): at most
`max_retries` (default 1) automatic retries, each behind the gate (`retry`). A wrong answer is retried
only when the lane key has changed since that attempt recorded it: the same code would give the same
answers, so the retry is refused (`stop`) without running the gate, and a wrong answer recorded without
a lane key is refused too (fail closed). Everything closed: `done`. Each plan writes an `adapt.chain`
ledger record (`record=False` skips it).

**The same-artifact retry (B-253).** A retry that would replay the very artifact the failed attempt
solved (`plan(..., artifact_sha256=<its sha256>)`) is refused (`stop`) without running the gate when that
attempt (`not_submitted` or `expired`; a wrong answer is decided by the lane key alone, above) recorded the same artifact sha256, the same lane key as now, ids its solver left unanswered
(`missing` > 0) and no learned key (`learned` empty): the replay can only reach the same answers, so the
gate's NO is already known (Huntress Day 30 Script Mastery spent 21.04 s replaying to it). An attempt
that learned a key the solver reads is retried behind the gate as before (the Day 30 TT's gate passed
because its ladder learned one). An attempt that recorded no artifact sha256, no lane key or no
`missing` count (a kill before the send) cannot be shown to repeat, so it goes to the gate as before.

**The clock.** `AttemptGuard` holds a running clock (`ctf.adapt.clocks`) for the life of the attempt,
with its `deadline` (epoch seconds; None for a regular attempt), so the deadline-aware quiet check
throttles offline replays only while an attempt with a deadline runs.

Nothing here starts a clock: the opener does (B-252/B-003), on `start` or `retry`.
"""
from __future__ import annotations

import re
import signal
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .. import ledger as _ledger
from .. import paths as _paths
from .. import solved as _solved
from .. import watch as _watch
from . import AdaptError
from . import clocks as _clocks
from . import regress as _regress

MODES = ("base", "time_trial", "mastery")
TIMED = MODES[1:]
OUTCOMES = ("correct", "incorrect", "not_submitted", "expired")
FAILED = ("incorrect", "not_submitted", "expired")
BY = ("teammate", "hand")
ACCEPTED = frozenset({"correct", "already_solved"})
ACTIONS = ("wait", "start", "retry", "stop", "hold", "done")
DEFAULT_RETRIES = 1


def split(challenge_id: str) -> tuple[str, str]:
    """(base id, mode) of a Game Master id; an answer suffix `#<aid>` is dropped."""
    cid = str(challenge_id).split("#", 1)[0]
    for mode in TIMED:
        if cid.endswith("/" + mode):
            return cid[: -len(mode) - 1], mode
    return cid, "base"


def mode_id(base: str, mode: str) -> str:
    if mode not in MODES:
        raise AdaptError(f"mode {mode!r}: one of {', '.join(MODES)}")
    return base if mode == "base" else f"{base}/{mode}"


def _workdir(workdir: Path | None) -> Path:
    if workdir is not None:
        return Path(workdir)
    try:
        return _paths.workdir()
    except Exception as e:  # noqa: BLE001 - no event and no CTF_WORKDIR: say which
        raise AdaptError(f"no workdir: set CTF_WORKDIR or CTF_EVENT ({e})") from None


# --------------------------------------------------------------------------- records

@dataclass(frozen=True)
class Closure:
    challenge_id: str
    by: str                     # us | teammate | hand
    source: str                 # submit | attempt | mark | solved | watch
    ts: float
    note: str = ""


def _ts(rec: dict, where: str) -> float:
    """A closing record's timestamp. A malformed one is an AdaptError naming the record by its event and
    challenge id (never the raw row, which can hold anything), never a traceback."""
    raw = rec.get("ts")
    if raw is None:
        return 0.0
    try:
        if isinstance(raw, bool):
            raise TypeError("a boolean")
        return float(raw)
    except (TypeError, ValueError) as e:
        name = f"{str(rec.get('event'))[:40]!r} record for {str(rec.get('challenge_id'))[:80]!r}"
        raise AdaptError(f"{where}: the {name} has a malformed ts {repr(raw)[:40]} "
                         f"({type(e).__name__})") from None


def closures(workdir: Path | None = None) -> dict[str, Closure]:
    """Every closed challenge id (a mode id) with its earliest close."""
    wd = _workdir(workdir)
    found: list[Closure] = []
    for r in _ledger.read(wd):
        ev, cid = r.get("event"), r.get("challenge_id")
        if not cid:
            continue
        # only a record that becomes a close has its ts read: a malformed ts on any other row is not ours to judge
        if ev == "platform.submit" and r.get("status") in ACCEPTED and not r.get("partial"):
            found.append(Closure(str(cid).split("#", 1)[0], "us", "submit", _ts(r, "the ledger")))
        elif ev == "adapt.attempt" and r.get("outcome") == "correct":
            found.append(Closure(str(cid), "us", "attempt", _ts(r, "the ledger")))
        elif ev == "adapt.closed":
            found.append(Closure(str(cid), str(r.get("by")), "mark", _ts(r, "the ledger"), str(r.get("note") or "")))
        elif ev == "stop" and r.get("reason") == _solved.TEAM_SOLVE:
            found.append(Closure(str(cid), "teammate", "solved", _ts(r, "the ledger"), str(r.get("by") or "")))
    try:
        stream = _watch.read_events(wd)
    except _watch.WatchError as e:
        raise AdaptError(f"the board watch stream is unreadable: {e}") from None
    for ev in stream:
        if ev.get("event") == "team_solved" and ev.get("challenge_id"):
            found.append(Closure(str(ev["challenge_id"]), "teammate", "watch", _ts(ev, "the board watch stream")))
    out: dict[str, Closure] = {}
    for c in sorted(found, key=lambda c: c.ts):
        out.setdefault(c.challenge_id, c)
    return out


def mark_closed(challenge_id: str, *, by: str, note: str = "", workdir: Path | None = None) -> dict:
    """Record a close no record of ours shows: a teammate's, or one banked by hand. It opens the next mode."""
    if by not in BY:
        raise AdaptError(f"closed by {by!r}: one of {', '.join(BY)} (our own closes are read from the ledger)")
    split(challenge_id)
    return _ledger.append("adapt.closed", workdir=_workdir(workdir), challenge_id=str(challenge_id), by=by, note=note)


def _fold_seeds(workdir: Path) -> None:
    """B-040: after an accepted solve, fold the event's label verdicts into the tracked master seeds, so a
    convention the judge accepted this run is promoted at once instead of waiting for a manual
    `ctf seed-fold`. The fold under `workdir` honours the order-degenerate guard and promotes only what the
    label ledger recorded (first-seen labels still need probing on the untimed base -- the item's blocker).

    Best effort: a fold that cannot run -- a judge-free event (no ledger to fold), an unreadable seed, or
    seedfold itself unavailable -- prints one stderr line and is dropped. It must never cost the attempt
    record that just succeeded, so no exception from the fold propagates out of `record_attempt`."""
    try:
        from .. import seedfold
        seedfold.fold_all(workdir=workdir, warn=lambda _m: None)
    except Exception as e:  # noqa: BLE001 - a fold failure is never the record's undoing
        print(f"[adapt] seed fold after a correct attempt skipped: {type(e).__name__}: {e}", file=sys.stderr)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _check_sha(value, what: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256.match(value):
        raise AdaptError(f"{what} {str(value)[:80]!r}: a lower-case hex sha256")
    return value


def record_attempt(challenge_id: str, outcome: str, *, lane_key: str | None = None, note: str | None = None,
                   workdir: Path | None = None, artifact_sha256: str | None = None, missing: int | None = None,
                   learned=()) -> dict:
    """One finished timed attempt: correct, incorrect, not_submitted (killed or out of time before the
    send) or expired. `lane_key` is the gate's lane key the attempt ran with: a wrong answer can only be
    retried automatically once that key has changed. `artifact_sha256` (the delivery the solver ran on),
    `missing` (ids it left unanswered) and `learned` (keys the attempt learned that the solver reads) let
    `plan` refuse a same-artifact retry that can only repeat (B-253).

    A `correct` outcome also folds the event's learned label verdicts into the tracked master seeds
    (`_fold_seeds`, B-040): the "automatic fold after each accepted solve". Best effort -- the record is
    written first and a fold failure never propagates."""
    if outcome not in OUTCOMES:
        raise AdaptError(f"outcome {outcome!r}: one of {', '.join(OUTCOMES)}")
    if missing is not None and (isinstance(missing, bool) or not isinstance(missing, int) or missing < 0):
        raise AdaptError(f"missing {missing!r}: a non-negative count of unanswered ids")
    if isinstance(learned, str) or not all(isinstance(k, str) and k.strip() for k in learned):
        raise AdaptError("learned: a list of non-blank key names")
    sha = _check_sha(artifact_sha256, "artifact_sha256")
    fields = {"challenge_id": str(challenge_id), "outcome": outcome}
    if lane_key:
        fields["lane_key"] = lane_key
    if note:
        fields["note"] = note
    if sha:
        fields["artifact_sha256"] = sha
    if missing is not None:
        fields["missing"] = missing
    if learned:
        fields["learned"] = sorted(set(learned))
    wd = _workdir(workdir)
    rec = _ledger.append("adapt.attempt", workdir=wd, **fields)
    if outcome == "correct":
        _fold_seeds(wd)
    return rec


def attempts(challenge_id: str, workdir: Path | None = None) -> list[dict]:
    return [r for r in _ledger.read(_workdir(workdir))
            if r.get("event") == "adapt.attempt" and r.get("challenge_id") == str(challenge_id)]


class AttemptGuard:
    """Around one timed attempt: whatever ends it without `done(outcome)` (an exception, sys.exit, a
    SIGTERM from whoever kills the runner, Ctrl-C) records `not_submitted`, so the chain sees a failed
    attempt instead of nothing. SIGTERM is turned into SystemExit(143) while the guard is active (main
    thread only); the previous handler is restored on exit.

    It also holds a running clock (`ctf.adapt.clocks`) from enter to exit, with `deadline` (epoch seconds
    at which the attempt's window ends; None for an attempt without one), so the deadline-aware quiet
    check sees it. `artifact_sha256` is recorded with the outcome (the same-artifact retry rule)."""

    def __init__(self, challenge_id: str, *, lane_key: str | None = None, workdir: Path | None = None,
                 deadline: float | None = None, artifact_sha256: str | None = None):
        self.challenge_id = str(challenge_id)
        self.lane_key = lane_key
        self.workdir = _workdir(workdir)
        self.deadline = _clocks.check_deadline(deadline)
        self.artifact_sha256 = _check_sha(artifact_sha256, "artifact_sha256")
        self.outcome: str | None = None
        self._prev = None
        self._installed = False
        self._clock: Path | None = None

    def _term(self, signum, frame):
        raise SystemExit(128 + signum)

    def __enter__(self) -> "AttemptGuard":
        self._clock = _clocks.start(self.challenge_id, deadline=self.deadline, workdir=self.workdir)
        if threading.current_thread() is threading.main_thread():
            self._prev = signal.signal(signal.SIGTERM, self._term)
            self._installed = True
        return self

    def done(self, outcome: str, note: str | None = None, *, missing: int | None = None, learned=()) -> None:
        if self.outcome is not None:
            raise AdaptError(f"attempt {self.challenge_id} already recorded as {self.outcome}")
        record_attempt(self.challenge_id, outcome, lane_key=self.lane_key, note=note, workdir=self.workdir,
                       artifact_sha256=self.artifact_sha256, missing=missing, learned=learned)
        self.outcome = outcome

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            if self.outcome is None:
                if exc_type is None:
                    why = "the attempt ended without an outcome"
                elif issubclass(exc_type, SystemExit) and getattr(exc, "code", None) == 128 + signal.SIGTERM:
                    why = "killed (SIGTERM) before the send"
                else:
                    why = f"stopped by {exc_type.__name__} before the send"
                record_attempt(self.challenge_id, "not_submitted", lane_key=self.lane_key, note=why,
                               workdir=self.workdir, artifact_sha256=self.artifact_sha256)
                self.outcome = "not_submitted"
        finally:
            if self._clock is not None:
                _clocks.stop(self._clock)
                self._clock = None
            if self._installed:
                signal.signal(signal.SIGTERM, self._prev if self._prev is not None else signal.SIG_DFL)
        return False


# --------------------------------------------------------------------------- the plan

@dataclass(frozen=True)
class ChainStep:
    base: str
    challenge_id: str | None            # the mode id the action is about (None when done)
    mode: str | None
    action: str                         # ACTIONS
    reason: str
    closed: dict = field(default_factory=dict)      # mode -> "us" | "teammate" | "hand"
    gate: _regress.LaneGate | None = None
    lane_key: str | None = None         # the gate's (pass it to AttemptGuard on start/retry)


def plan(base_id: str, lane: str, *, workdir: Path | None = None, root: Path | None = None,
         max_retries: int = DEFAULT_RETRIES, gate_kw: dict | None = None, keyer=None,
         record: bool = True, artifact_sha256: str | None = None) -> ChainStep:
    """The next step of `base_id`'s chain (rules in the module docstring). `gate_kw` goes to
    `regress.gate` (cap, guard, profile, load, ...). `artifact_sha256`: the artifact a retry would replay
    (a same-artifact retry); None when a retry gets a new one."""
    artifact_sha256 = _check_sha(artifact_sha256, "artifact_sha256")
    base, mode = split(base_id)
    if mode != "base" or str(base_id) != base:
        raise AdaptError(f"{base_id!r}: plan takes the base id (without /time_trial, /mastery or #answer)")
    if not isinstance(max_retries, int) or max_retries < 0:
        raise AdaptError(f"max_retries {max_retries!r} must be a non-negative integer")
    wd = _workdir(workdir)
    closed = closures(wd)
    done = {m: closed[mode_id(base, m)].by for m in MODES if mode_id(base, m) in closed}
    kw = dict(gate_kw or {})

    def finish(step: ChainStep) -> ChainStep:
        if record:
            _ledger.append("adapt.chain", workdir=wd, challenge_id=step.challenge_id or base, lane=lane,
                           action=step.action, reason=step.reason)
        return step

    def gated(mid: str, m: str, ok_action: str, why_ok: str) -> ChainStep:
        g = _regress.gate(lane, root=root, workdir=wd, keyer=keyer, **kw)
        if g.verdict == _regress.YES:
            return finish(ChainStep(base, mid, m, ok_action, why_ok, done, g, g.lane_key))
        if g.verdict == _regress.NO:
            return finish(ChainStep(base, mid, m, "stop", f"lane gate NO: {g.reason}", done, g, g.lane_key))
        return finish(ChainStep(base, mid, m, "hold", f"lane gate not run: {g.reason}", done, g, g.lane_key))

    if "base" not in done:
        return finish(ChainStep(base, base, "base", "wait", "base not closed (by us, a teammate or by hand)", done))
    for i, m in enumerate(TIMED):
        if m in done:
            continue
        mid = mode_id(base, m)
        prev = MODES[i]
        opened = f"{prev} closed by {done[prev]}"
        fails = [a for a in attempts(mid, wd) if a.get("outcome") in FAILED]
        if not fails:
            return gated(mid, m, "start", opened)
        if len(fails) > max_retries:
            return finish(ChainStep(base, mid, m, "stop",
                                    f"{len(fails)} failed attempt(s); automatic retries allowed: {max_retries}", done))
        last = fails[-1]
        if last.get("outcome") == "incorrect":
            was = last.get("lane_key")
            if not was:
                return finish(ChainStep(base, mid, m, "stop",
                                        "answered wrong with no lane key recorded: cannot tell whether the lane "
                                        "changed since, so no automatic retry", done))
            now = _regress.current_lane_key(lane, root=root, workdir=wd, keyer=keyer)
            if now == was:
                return finish(ChainStep(base, mid, m, "stop",
                                        "answered wrong, and the lane is unchanged since (same lane key): a retry "
                                        "would repeat the answers; fold a fix first", done, lane_key=now))
        elif _repeats(last, artifact_sha256):          # incorrect: decided above on the lane key alone
            now = _regress.current_lane_key(lane, root=root, workdir=wd, keyer=keyer)
            if now == last.get("lane_key"):
                return finish(ChainStep(base, mid, m, "stop",
                                        f"same artifact, same lane key, {last['missing']} id(s) left unanswered and "
                                        "no key learned: a same-artifact retry gate would replay to the same NO; "
                                        "fold a fix first", done, lane_key=now))
        return gated(mid, m, "retry", f"{opened}; retry {len(fails)} of {max_retries} after "
                                      f"{last.get('outcome')}")
    return finish(ChainStep(base, None, None, "done", "every mode closed", done))


def _repeats(last: dict, artifact_sha256: str | None) -> bool:
    """Whether a retry on `artifact_sha256` would repeat the failed attempt `last` (its lane key is
    compared by the caller): the same artifact, ids left unanswered, and nothing learned."""
    missing = last.get("missing")
    return (artifact_sha256 is not None and last.get("artifact_sha256") == artifact_sha256
            and bool(last.get("lane_key")) and isinstance(missing, int) and not isinstance(missing, bool)
            and missing > 0 and not last.get("learned"))
