"""B-141: split a rejected confident batch over the batch submit path, suspects first.

A confident batch is every answer of one attempt sent in one request (ctf.platform.policy
SubmitGate.submit_answers; the Game Master grades the batch as one). When the Game Master rejects
it, at least one answer is wrong but the reply does not say which. This module finds the wrong one(s)
and banks the right ones, inside the attempt, by sending proper subsets and reading each verdict.

It is the master re-homing of ``grade.bank`` from the Huntress event's grading tool (read-only
source), ported onto SubmitGate.submit_answers instead of the Huntress Game Master client. Two
properties of the original are kept and tested here:

* **Never-wrong.** It banks only the values the solver already computed (never a new guess); every id
  in ``banked`` was in an accepted sub-batch, and every id in ``bad`` was rejected *alone*, so a bad
  verdict always rests on a request of its own. The whole batch is never sent again (its rejection is
  already known), and no identical set of (id, value) pairs goes on the wire twice.

* **Suspects first (B-141).** ``suspects`` are the ids a live ``day_patch`` answered -- the ones most
  likely to be wrong. When a rejected batch holds suspects and non-suspects, the non-suspects go out
  as one batch first: accepted, they are banked in one request and the split is confined to the
  suspects; rejected, the cut told nothing and the split falls back to the classic order over
  everything (one extra request). On Huntress Day 30 Metadata's Time Trial a 35-id batch held one
  agent-answered id; the classic split isolated it only after 6 sub-batch requests, where
  suspects-first needs two (the 34 non-suspects, then the one suspect alone).

Yielding to a waiting promote (B-141). ``stop`` is an optional predicate checked *before every*
sub-batch send. On a *no-deadline* attempt the caller passes
``ctf.lanelock.yield_stop(workdir, lane, deadline=False)``, which is true once a standby's finished
fix has raised the promote-wanted flag; the held split then ends and hands the lane back instead of
running out the whole bisect while the fix waits. A *deadline* attempt passes ``stop=None``
(``yield_stop(..., deadline=True)`` returns None): its clock, not the fix, decides when it stops, so
it never reads the flag. When ``stop`` ends a run, the ids not yet banked or named bad are reported
in ``unchecked``.

    from ctf import bisect, lanelock
    res = bisect.bisect(gate, cid, answers, provenance="day_patch + solver",
                        suspects=day_patch_answered,
                        stop=lanelock.yield_stop(workdir, lane, deadline=has_deadline))
    # res.banked: ids the judge accepted; res.bad: ids rejected alone; res.unchecked: not reached.

``split(answer_id) -> family_key`` optionally groups ids into families so a rejected batch is cut on
a family boundary before it is halved (the Huntress lane rule); without it a rejected batch is only
halved. It never changes a conclusion, only the request count.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

from .platform.base import SubmitResult, SubmitStatus


class BisectYield(Exception):
    """The ``stop`` predicate asked the held split to yield the lane (a promote is waiting)."""


class _NonVerdict(Exception):
    """A send came back as something other than a judged verdict (rate limited, paused, refused): the
    split cannot continue, the rest stays unchecked."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class BankResult:
    """What a bisect concluded. ``banked`` and ``bad`` are disjoint; ``unchecked`` are the ids a stop
    (yield or non-verdict) left unreached. ``requests`` counts the sub-batch sends (not the original
    rejected batch, whose verdict was the premise). ``solved`` is true when every id was banked and
    none was bad. ``stopped`` names why a run ended early, else None."""

    banked: frozenset[str] = frozenset()
    bad: frozenset[str] = frozenset()
    unchecked: frozenset[str] = frozenset()
    requests: int = 0
    solved: bool = False
    stopped: str | None = None
    last: SubmitResult | None = None


# Gate protocol: anything with submit_answers(cid, mapping, *, provenance, allow_nonstandard,
# confirmed) -> SubmitResult. ctf.platform.policy.SubmitGate is the real one.
Gate = object


def bisect(gate: Gate, challenge_id: str, answers: Mapping[str, str], *, provenance: str,
           split: Callable[[str], object] | None = None,
           suspects: Sequence[str] | frozenset[str] = (),
           stop: Callable[[], bool] | None = None,
           allow_nonstandard: bool = False, confirmed: bool = False) -> BankResult:
    """Bisect a rejected confident batch. See the module docstring. ``answers`` is the full
    {answer id: value} of the attempt whose one-request batch the judge rejected."""
    run = _Run(gate, str(challenge_id), dict(answers), provenance=provenance, split=split,
               suspects=frozenset(suspects), stop=stop, allow_nonstandard=allow_nonstandard,
               confirmed=confirmed)
    return run.go()


class _Run:
    def __init__(self, gate, cid, answers, *, provenance, split, suspects, stop,
                 allow_nonstandard, confirmed):
        self.gate = gate
        self.cid = cid
        self.answers = answers
        self.provenance = provenance
        self.split = split
        self.suspects = suspects
        self.stop = stop
        self.allow_nonstandard = allow_nonstandard
        self.confirmed = confirmed
        self.ids = [aid for aid in answers]          # question order
        self.banked: set[str] = set()
        self.bad: set[str] = set()
        self.aside: list[str] = []                   # set-aside (unsent) second halves, for settle
        self._verdict: dict[frozenset, bool] = {}
        self.requests = 0
        self.last: SubmitResult | None = None
        # The whole batch's rejection is the premise: record it so no cut ever resends it whole.
        if self.ids:
            self._verdict[frozenset(self.ids)] = False

    # ------------------------------------------------------------------ wire
    def _ask(self, ids: Sequence[str]) -> bool:
        """Send ``ids`` as one sub-batch and return True (accepted) or False (rejected). A cached
        verdict is reused without a send. Checks ``stop`` before every real send."""
        key = frozenset(ids)
        if key in self._verdict:
            return self._verdict[key]
        if self.stop is not None and self.stop():
            raise BisectYield("promote-wanted")
        values = {aid: self.answers[aid] for aid in ids}
        result = self.gate.submit_answers(self.cid, values, provenance=self.provenance,
                                           allow_nonstandard=self.allow_nonstandard,
                                           confirmed=self.confirmed)
        self.requests += 1
        self.last = result
        if result.accepted:                          # CORRECT or ALREADY_SOLVED: all of ids are right
            verdict = True
        elif result.status is SubmitStatus.INCORRECT:
            verdict = False
        else:                                        # rate limited, paused, refused: not a verdict
            raise _NonVerdict(f"{result.status.value}: {result.message}")
        self._verdict[key] = verdict
        return verdict

    def _bank(self, ids: Sequence[str]) -> None:
        self.banked.update(ids)

    # ------------------------------------------------------------------ split
    def _halves(self, ids: Sequence[str]) -> tuple[list[str], list[str]]:
        """Cut ``ids`` in two. With a ``split`` family function, the whole batch is first cut so no
        family straddles the boundary (families told apart before their ids are); within one family
        it halves. Without ``split`` it halves. Deterministic for a given input order."""
        ids = list(ids)
        if self.split is not None:
            fams: list[object] = []
            groups: dict[object, list[str]] = {}
            for aid in ids:
                fam = self.split(aid)
                if fam not in groups:
                    groups[fam] = []
                    fams.append(fam)
                groups[fam].append(aid)
            if len(fams) > 1:
                mid = (len(fams) + 1) // 2
                left = [aid for fam in fams[:mid] for aid in groups[fam]]
                right = [aid for fam in fams[mid:] for aid in groups[fam]]
                return left, right
        mid = (len(ids) + 1) // 2
        return ids[:mid], ids[mid:]

    def _split_group(self, ids: Sequence[str]) -> None:
        """Isolate the wrong answer(s) in ``ids``, which is known to hold at least one (its containing
        batch was rejected). Follow pass: at each cut only the first half is sent; an accepted first
        half is banked and the wrong answer is in the second half (cut next, unsent); a rejected first
        half is cut next and the second half is set aside. A single id is always sent alone, so a bad
        verdict rests on a request of its own."""
        ids = list(ids)
        if len(ids) == 1:
            aid = ids[0]
            if self._ask(ids):                       # surprise accept: never name an accepted id bad
                self._bank(ids)
            else:
                self.bad.add(aid)
            return
        a, b = self._halves(ids)
        if self._ask(a):
            self._bank(a)
            self._split_group(b)                     # wrong answer is in b (a was accepted)
        else:
            self._set_aside(b)                       # second half unsent, settled later
            self._split_group(a)                     # wrong answer is in a

    def _set_aside(self, ids: Sequence[str]) -> None:
        self.aside.extend(ids)

    def _settle(self) -> None:
        """Everything set aside goes out as one batch. Accepted: banked, done. Rejected: another
        answer is wrong, so split what was set aside and settle again. Each pass resolves at least one
        more bad id and shrinks the open set, so it terminates."""
        while self.aside:
            rest = list(dict.fromkeys(self.aside))   # de-dup, keep order
            rest = [aid for aid in rest if aid not in self.banked and aid not in self.bad]
            self.aside = []
            if not rest:
                return
            if self._ask(rest):
                self._bank(rest)
                return
            self._split_group(rest)

    # ------------------------------------------------------------------ driver
    def go(self) -> BankResult:
        stopped: str | None = None
        try:
            susp = [aid for aid in self.ids if aid in self.suspects]
            non = [aid for aid in self.ids if aid not in self.suspects]
            if susp and non:
                if self._ask(non):                   # suspects-first: isolate the suspects
                    self._bank(non)
                    self._split_group(susp)          # the wrong answer is confined to the suspects
                else:
                    # A wrong answer is outside the suspects; the cut told nothing about them. Fall
                    # back to the classic split over everything (one extra request).
                    self._split_group(self.ids)
            elif self.ids:
                self._split_group(self.ids)
            self._settle()
        except BisectYield as e:
            stopped = str(e)
        except _NonVerdict as e:
            stopped = e.reason
        resolved = self.banked | self.bad
        unchecked = frozenset(aid for aid in self.ids if aid not in resolved)
        solved = bool(self.ids) and not self.bad and not unchecked
        return BankResult(banked=frozenset(self.banked), bad=frozenset(self.bad),
                          unchecked=unchecked, requests=self.requests, solved=solved,
                          stopped=stopped, last=self.last)
