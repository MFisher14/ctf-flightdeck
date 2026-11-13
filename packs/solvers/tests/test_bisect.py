"""B-141: the suspects-first confident-batch bisect over SubmitGate.submit_answers.

The fake Game Master grades a batch as one (a real-shaped SubmitResult): a batch is accepted iff
every id in it holds a right value, full CORRECT iff it also covers every still-open id. It records
every batch it is sent, so the tests can assert *what* went on the wire, not only the conclusion.
"""
from __future__ import annotations

import itertools

import pytest

from ctf import bisect, event, lanelock
from ctf.platform import SubmitGate
from ctf.platform.base import SubmitResult, SubmitStatus


class FakeGame:
    """A Game Master adapter whose grading is decided by which ids hold the right value. ``right`` is
    the set of (id, value) pairs the judge accepts; any other value for an id is wrong. A batch is
    accepted when all its pairs are right; it is full CORRECT when it is accepted and covers every id
    of the challenge not yet solved."""

    kind = "gamemaster"

    def __init__(self, right: dict[str, str], all_ids):
        self.right = dict(right)
        self.all_ids = set(all_ids)
        self.solved: set[str] = set()
        self.batches: list[frozenset[str]] = []

    def submit_answers(self, cid, answers):
        self.batches.append(frozenset(answers))
        ok = all(self.right.get(aid) == val for aid, val in answers.items())
        if not ok:
            return SubmitResult(SubmitStatus.INCORRECT, "incorrect", reply={"result": "incorrect"})
        self.solved.update(answers)
        if self.solved >= self.all_ids:
            return SubmitResult(SubmitStatus.CORRECT, "CORRECT", reply={"result": "CORRECT"})
        remaining = len(self.all_ids - self.solved)
        return SubmitResult(SubmitStatus.CORRECT, f"accepted; {remaining} remaining",
                            reply={"result": "accepted", "remaining": remaining})

    # read side (unused by the bisect, present for the adapter shape)
    def submit(self, cid, flag):  # pragma: no cover - a batch never goes out one by one here
        raise AssertionError("the bisect uses submit_answers, never submit")

    def list_challenges(self):
        return []

    def get_challenge(self, cid):
        raise NotImplementedError

    def download_files(self, cid, dest):
        return []

    def team_solves(self):
        return []

    def scoreboard(self):
        return []


def gate_for(right, all_ids):
    adapter = FakeGame(right, all_ids)
    gate = SubmitGate(adapter, event.load("csctf"))
    return gate, adapter


def answers_with_wrong(n, wrong_ids):
    """n ids id00..; each right value is "right-<id>"; a wrong id gets "wrong-<id>"."""
    ids = [f"id{i:02d}" for i in range(n)]
    right = {aid: f"right-{aid}" for aid in ids}
    answers = {aid: (f"wrong-{aid}" if aid in wrong_ids else right[aid]) for aid in ids}
    return ids, right, answers


def run_bisect(right, answers, **kw):
    gate, adapter = gate_for(right, answers)
    res = bisect.bisect(gate, "c", answers, provenance="solver", allow_nonstandard=True, **kw)
    return res, adapter


# --------------------------------------------------------------------------- correctness

def test_single_wrong_is_isolated_and_rest_banked():
    ids, right, answers = answers_with_wrong(8, {"id05"})
    res, adapter = run_bisect(right, answers)
    assert res.bad == {"id05"}
    assert res.banked == set(ids) - {"id05"}
    assert not res.unchecked


def test_bad_id_was_rejected_alone():
    # Every id named bad must have been sent as a one-id batch (a verdict of its own).
    ids, right, answers = answers_with_wrong(16, {"id09"})
    res, adapter = run_bisect(right, answers)
    assert res.bad == {"id09"}
    assert frozenset({"id09"}) in adapter.batches


def test_banked_ids_were_in_an_accepted_batch():
    ids, right, answers = answers_with_wrong(16, {"id03"})
    res, adapter = run_bisect(right, answers)
    accepted_union = set()
    for batch in adapter.batches:
        if all(right.get(a) == answers[a] for a in batch):
            accepted_union |= batch
    assert res.banked <= accepted_union
    assert res.banked == set(ids) - {"id03"}


def test_whole_batch_is_never_resent():
    ids, right, answers = answers_with_wrong(10, {"id07"})
    res, adapter = run_bisect(right, answers)
    assert frozenset(ids) not in adapter.batches


def test_no_set_is_sent_twice():
    ids, right, answers = answers_with_wrong(12, {"id02"})
    res, adapter = run_bisect(right, answers)
    assert len(adapter.batches) == len(set(adapter.batches))


def test_two_wrong_ids_both_isolated():
    ids, right, answers = answers_with_wrong(16, {"id04", "id11"})
    res, adapter = run_bisect(right, answers)
    assert res.bad == {"id04", "id11"}
    assert res.banked == set(ids) - {"id04", "id11"}
    assert not res.unchecked
    for b in ("id04", "id11"):
        assert frozenset({b}) in adapter.batches


def test_all_right_but_premise_rejected_banks_everything():
    # A degenerate case: no id is actually wrong (the whole-batch premise is only recorded, never
    # resent). The splitter banks everything and names nothing bad.
    ids, right, answers = answers_with_wrong(4, set())
    res, adapter = run_bisect(right, answers)
    assert res.bad == set()
    assert res.banked == set(ids)
    assert res.solved is True


def test_classic_cut_sends_the_ceiling_half_first():
    # Pins the halving pivot `mid = (len(ids) + 1) // 2`. The classic cut sends the CEILING half first,
    # never the floor half: with 15 ids the first sub-batch is the first 8 ids, not the first 7. This
    # fails if the pivot is changed to `len(ids) // 2`. The wrong id is the last id, so the first half
    # is all-right and is sent intact as the opening sub-batch.
    ids, right, answers = answers_with_wrong(15, {"id14"})
    res, adapter = run_bisect(right, answers)
    assert len(adapter.batches[0]) == 8
    assert adapter.batches[0] == frozenset(ids[:8])
    assert res.bad == {"id14"}
    assert res.banked == set(ids) - {"id14"}


def test_split_family_cuts_on_family_boundary():
    # Exercises the `split=` family branch of `_halves`. With a family function a rejected batch is
    # regrouped by family and the family *list* is halved (ceiling), so no family straddles the cut and
    # the first sub-batch is the first ceil(nfam/2) families' ids -- NOT a plain id-order prefix. Three
    # interleaved families of two ids: the cut is families A,B = {id00,id01,id03,id04}; a plain halving
    # (ids[:3] = {id00,id01,id02}) is never sent, and the ceiling over 3 families (2 families left, not
    # 1) is pinned, so a floor pivot in either the family or the fallback split is caught.
    ids, right, answers = answers_with_wrong(6, {"id05"})
    fam = {"id00": "A", "id03": "A", "id01": "B", "id04": "B", "id02": "C", "id05": "C"}
    res, adapter = run_bisect(right, answers, split=lambda aid: fam[aid])
    assert adapter.batches[0] == frozenset({"id00", "id01", "id03", "id04"})
    assert frozenset({"id00", "id01", "id02"}) not in adapter.batches
    assert res.bad == {"id05"}
    assert res.banked == set(ids) - {"id05"}
    assert not res.unchecked


# --------------------------------------------------------------------------- suspects first (B-141)

def test_suspect_wrong_isolated_in_two_requests():
    # The Day-30 shape: one wrong id, and it IS a suspect. Non-suspects go out first (one request),
    # then the lone suspect alone (one request): two sub-batch requests total.
    ids, right, answers = answers_with_wrong(35, {"id20"})
    res, adapter = run_bisect(right, answers, suspects={"id20"})
    assert res.bad == {"id20"}
    assert res.banked == set(ids) - {"id20"}
    assert res.requests == 2
    # The very first sub-batch is exactly the non-suspects (the suspect is isolated first).
    assert adapter.batches[0] == frozenset(set(ids) - {"id20"})


def test_suspects_first_beats_classic_on_requests():
    ids, right, answers = answers_with_wrong(35, {"id20"})
    classic, _ = run_bisect(right, answers)
    suspect, _ = run_bisect(right, answers, suspects={"id20"})
    assert suspect.requests < classic.requests
    assert classic.bad == suspect.bad == {"id20"}


def test_all_suspects_sends_no_empty_batch():
    # Every id is a suspect, so the non-suspect set is empty. The `if susp and non` guard must be
    # FALSE here: with nothing to isolate the suspects against, the run falls through to the classic
    # cut over all ids. It must never open by sending the empty non-suspect set. Under `if susp or
    # non` the empty set is asked first (SubmitGate rejects an empty mapping with ValueError), so this
    # pins the `and`: the all-suspects case is the only input where the two guards differ.
    ids, right, answers = answers_with_wrong(8, {"id05"})
    res, adapter = run_bisect(right, answers, suspects=set(ids))
    assert res.bad == {"id05"}
    assert res.banked == set(ids) - {"id05"}
    assert not res.unchecked
    assert frozenset() not in adapter.batches          # no empty sub-batch ever went on the wire
    assert all(len(b) >= 1 for b in adapter.batches)


def test_wrong_outside_suspects_falls_back_but_is_correct():
    # The wrong id is NOT a suspect: the non-suspect batch is rejected, the cut tells nothing about
    # the suspects, and the split falls back to the classic order over everything. Still correct.
    ids, right, answers = answers_with_wrong(16, {"id06"})
    res, adapter = run_bisect(right, answers, suspects={"id01", "id02"})
    assert res.bad == {"id06"}
    assert res.banked == set(ids) - {"id06"}
    # The non-suspects were tried first as one batch.
    assert adapter.batches[0] == frozenset(set(ids) - {"id01", "id02"})


# --------------------------------------------------------------------------- yield to a promote

def test_stop_predicate_ends_run_and_marks_unchecked():
    # A stop that fires before the 2nd send: only the first sub-batch goes out, the rest is unchecked.
    ids, right, answers = answers_with_wrong(16, {"id08"})
    gate, adapter = gate_for(right, answers)
    calls = itertools.count()

    def stop():
        return next(calls) >= 1   # false for the first check, true thereafter

    res = bisect.bisect(gate, "c", answers, provenance="p", allow_nonstandard=True, stop=stop)
    assert res.stopped == "promote-wanted"
    assert len(adapter.batches) == 1
    resolved = res.banked | res.bad
    assert res.unchecked == set(ids) - resolved
    assert res.unchecked


def test_non_verdict_stops_and_leaves_unchecked():
    # A rate-limited reply is not a verdict: the split stops and the rest stays unchecked.
    class RateLimited(FakeGame):
        def submit_answers(self, cid, answers):
            self.batches.append(frozenset(answers))
            return SubmitResult(SubmitStatus.RATE_LIMITED, "rate_limited", retry_after=1.0)

    ids, right, answers = answers_with_wrong(8, {"id03"})
    adapter = RateLimited(right, answers)
    gate = SubmitGate(adapter, event.load("csctf"))
    res = bisect.bisect(gate, "c", answers, provenance="p", allow_nonstandard=True)
    assert res.stopped is not None and "rate_limited" in res.stopped
    assert res.unchecked == set(ids)


# --------------------------------------------------------------------------- deadline vs held (B-141)

def test_deadline_attempt_ignores_the_flag(tmp_path):
    # yield_stop(deadline=True) is None: even with the flag up, the timed attempt runs to completion.
    ids, right, answers = answers_with_wrong(16, {"id10"})
    lanelock.set_promote_wanted(tmp_path, "metadata", "fix")
    gate, adapter = gate_for(right, answers)
    stop = lanelock.yield_stop(tmp_path, "metadata", deadline=True)
    assert stop is None
    res = bisect.bisect(gate, "c", answers, provenance="p", allow_nonstandard=True, stop=stop)
    assert res.stopped is None
    assert res.bad == {"id10"}
    assert not res.unchecked


def test_held_attempt_yields_on_the_flag(tmp_path):
    # yield_stop(deadline=False) with the flag up ends the held split before any send.
    ids, right, answers = answers_with_wrong(16, {"id10"})
    lanelock.set_promote_wanted(tmp_path, "metadata", "fix")
    gate, adapter = gate_for(right, answers)
    stop = lanelock.yield_stop(tmp_path, "metadata", deadline=False)
    res = bisect.bisect(gate, "c", answers, provenance="p", allow_nonstandard=True, stop=stop)
    assert res.stopped == "promote-wanted"
    assert adapter.batches == []            # it yielded before sending anything
    assert res.unchecked == set(ids)


def test_held_attempt_runs_when_no_flag(tmp_path):
    # Same held wiring, but no promote waiting: the split runs normally.
    ids, right, answers = answers_with_wrong(16, {"id10"})
    gate, adapter = gate_for(right, answers)
    stop = lanelock.yield_stop(tmp_path, "metadata", deadline=False)
    res = bisect.bisect(gate, "c", answers, provenance="p", allow_nonstandard=True, stop=stop)
    assert res.stopped is None
    assert res.bad == {"id10"}
