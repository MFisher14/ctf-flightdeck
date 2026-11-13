"""B-221: the probe tier: a ready probe that closes a clean base goes first (Huntress Day 28).

    job = probetier.ProbeJob("cid", answer_ids=("q7",), open_ids=("q7",), options={"q7": [("json", "[34]")]})
    probetier.classify(job)                    # ("fixup", why)
    for job in probetier.order(jobs): ...      # fixup, then normal, then low; stable within a tier
    with probetier.turn(job, workdir=wd, lane="metadata"):
        ...                                    # send the job's options, one per request, under the lane lock
    stop = probetier.stop_for(job, workdir=wd, lane="metadata")   # the `stop` for ctf.bisect / a held loop

Why. On Huntress Day 28 the Metadata base stopped on one id (disk.partition_start_lba_sequence) and the
proposer had the correct candidate, [34], in hand 12 s after the release. Its probe was the 47th request of
the release minute at the "normal" tier; the hold guard refused the predicted 48 s wait and the probe was
dropped. A standby agent then wrote the reader and closed the base at +70 s. The fix there gave a ready,
clean, base-closing probe the "fixup" tier (tools/verify.py, row 313). Here:

  the wire       every answer submission is already the wire's `priority` class (ctf/platform/wire.py: op
                 submit -> PRIORITY: it may use the reserve, and no release-lane budget holds it), so the
                 Day 28 hold, a probe at a reads' place in the minute, cannot happen at the master's wire.
                 tests/test_probetier.py pins that.
  the lane       what was left is the order of a lane's own probe work, and a ready probe waiting behind a
                 held split. This module classifies a probe job, orders jobs, and gives a fixup job its turn
                 through B-141's lane lock: it raises the promote-wanted flag while it waits, so a held
                 no-deadline split (ctf.bisect with lanelock.yield_stop) ends at its next sub-batch and hands
                 the lane over. A normal or low job waits for the lock without raising the flag.

Tiers (TIERS, best first):

  fixup   options for every id of the job are built (ready), every id the base still lacks is one of
          them (it closes the base), the base has no rejected or held answer, it is not a split, and the
          attempt has no deadline
  normal  any other clean probe: not ready yet, other ids still open, or a deadline attempt (its clock
          orders it, and a candidate is probed only without one, row 346)
  low     the base has a rejected (BAD) or held answer, or the job is a split of a rejected batch
          (ctf.bisect): Huntress gave a split the low tier and never fixup

Nothing is sent here: the tier changes only the order and the lane-lock turn. Every option stays unsure and
is sent alone by whoever runs the job (ctf.askreaders.probe, a proposer runner), through the SubmitGate.

Caller: `python -m ctf ask-readers probe` builds its job with job_from_report (the offers are the job's
ids and options, every MISSING id the ask saw is open), takes its turn, and passes stop_for as
askreaders.probe's `stop`.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from . import lanelock

__all__ = ["FIXUP", "NORMAL", "LOW", "TIERS", "ProbeJob", "ProbeTierError", "classify", "order", "turn",
           "stop_for", "job_from_report"]

FIXUP, NORMAL, LOW = "fixup", "normal", "low"
TIERS = (FIXUP, NORMAL, LOW)
_RANK = {t: i for i, t in enumerate(TIERS)}


class ProbeTierError(ValueError):
    """A probe job that cannot be classified (no answer ids, an option map naming ids it does not settle)."""


@dataclass(frozen=True)
class ProbeJob:
    """One probe job of one challenge: the ids it settles and the options built for them so far.

    open_ids    every id the base still lacks (its MISSING and unsure ids)
    options     {answer id: [(form name, value), ...]}: the candidates in hand; an id with none is not ready
    deadline    the attempt's deadline (epoch seconds), None for a no-deadline attempt
    bad         the base has a rejected (BAD) or held answer
    split       a split of a rejected batch (ctf.bisect)
    source      who built it (proposer, ask-readers, ...): for the log only
    """
    challenge_id: str
    answer_ids: tuple
    open_ids: tuple = ()
    options: Mapping[str, Sequence] = field(default_factory=dict)
    deadline: float | None = None
    bad: bool = False
    split: bool = False
    source: str = ""

    def __post_init__(self):
        if not self.challenge_id:
            raise ProbeTierError("a probe job names its challenge")
        ids = tuple(str(a) for a in self.answer_ids)
        if not ids:
            raise ProbeTierError(f"{self.challenge_id}: a probe job settles at least one answer id")
        extra = sorted(set(self.options) - set(ids))
        if extra:
            raise ProbeTierError(f"{self.challenge_id}: options for ids the job does not settle: {extra}")
        object.__setattr__(self, "answer_ids", ids)
        object.__setattr__(self, "open_ids", tuple(str(a) for a in self.open_ids))

    @property
    def ready(self) -> bool:
        return all(self.options.get(a) for a in self.answer_ids)

    @property
    def closes_base(self) -> bool:
        return bool(self.open_ids) and set(self.open_ids) <= set(self.answer_ids)


def classify(job: ProbeJob) -> tuple[str, str]:
    """(tier, why) of one job (see the module docstring)."""
    if job.split:
        return LOW, "a split of a rejected batch is never fixup (it yields the lane instead)"
    if job.bad:
        return LOW, "the base has a rejected or held answer"
    if job.deadline is not None:
        return NORMAL, "a deadline attempt: its clock orders it"
    if not job.ready:
        missing = [a for a in job.answer_ids if not job.options.get(a)]
        return NORMAL, f"no candidate built yet for {', '.join(missing)}"
    if not job.closes_base:
        left = sorted(set(job.open_ids) - set(job.answer_ids))
        return NORMAL, ("the base's open ids are not given" if not job.open_ids
                        else f"other ids stay open after it: {', '.join(left)}")
    return FIXUP, "ready, clean, no deadline, and it closes the base"


def order(jobs: Iterable[ProbeJob]) -> list[ProbeJob]:
    """The jobs best tier first (fixup, normal, low), in their given order within a tier."""
    jobs = list(jobs)
    return [j for _, _, j in sorted((_RANK[classify(j)[0]], i, j) for i, j in enumerate(jobs))]


@contextmanager
def _lock(workdir: Path | None, lane: str, blocking: bool, on_wait: Callable[[], None] | None):
    """The lane lock for the `with` block. It is tried without waiting first: when the lane is free it is
    held at once and on_wait is never called; when it is held, BlockingIOError if `blocking` is False, else
    on_wait() (the caller's notice that it is about to wait) and then the blocking wait."""
    with ExitStack() as stack:
        try:
            stack.enter_context(lanelock.lane_lock(workdir, lane, blocking=False))
        except BlockingIOError:
            if not blocking:
                raise
            if on_wait is not None:
                on_wait()
            stack.enter_context(lanelock.lane_lock(workdir, lane, blocking=True))
        yield


@contextmanager
def turn(job: ProbeJob, *, lane: str, workdir: Path | None = None, blocking: bool = True,
         on_wait: Callable[[], None] | None = None):
    """The job's turn on the lane: the lane lock held for the `with` block, the tier yielded. A fixup job
    raises the promote-wanted flag before it tries the lock and keeps it up while it waits (as
    lanelock.promote_waiting does), so a held no-deadline split yields to it; the flag is cleared once the
    lock is held, and on the way out whether or not it ever was. Any other job waits on the lock alone.
    BlockingIOError when `blocking` is False and the lane is held. on_wait() is called once, just before
    the turn starts to wait on a held lane (never when the lane is free, never with `blocking` False)."""
    tier, _why = classify(job)
    if tier == FIXUP:
        lanelock.set_promote_wanted(workdir, lane, f"fixup-probe:{job.challenge_id}")
        try:
            with _lock(workdir, lane, blocking, on_wait):
                lanelock.clear_promote_wanted(workdir, lane)
                yield tier
        finally:
            lanelock.clear_promote_wanted(workdir, lane)
    else:
        with _lock(workdir, lane, blocking, on_wait):
            yield tier


def stop_for(job: ProbeJob, *, lane: str, workdir: Path | None = None) -> Callable[[], bool] | None:
    """The `stop` of the job's own send loop. A held (no-deadline) normal or low job ends once a waiting
    job has raised the flag; a fixup job never yields (it is what the others yield to), and a deadline
    job never reads the flag (lanelock.yield_stop: yielding a timed attempt could lose it)."""
    if classify(job)[0] == FIXUP:
        return None
    return lanelock.yield_stop(workdir, lane, deadline=job.deadline is not None)


def job_from_report(report, challenge_id: str, *, deadline: float | None = None, bad: bool = False,
                    source: str = "ask-readers") -> ProbeJob:
    """The probe job of an ask-readers report (ctf.askreaders.AskReport): its offers are the ids it settles,
    each with its offer's options, and every id the ask found MISSING is open, so a report whose every
    MISSING id has an offer closes the base. ProbeTierError when the report offers nothing."""
    from . import askreaders
    labels = askreaders.labels_module()
    options = {a.qid: list(labels.parse(a.offer).options) for a in report.offers()}
    return ProbeJob(challenge_id, answer_ids=tuple(options), open_ids=tuple(a.qid for a in report.asked),
                    options=options, deadline=deadline, bad=bad, source=source)
