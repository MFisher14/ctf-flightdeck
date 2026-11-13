"""B-040 (fixer round 1): the automatic fold after each accepted solve.

`ctf.adapt.chain.record_attempt` is the recorder a timed attempt (and `AttemptGuard`) ends through. On a
`correct` outcome it now folds the event's learned label verdicts into the tracked master seeds
(`seedfold.fold_all`, under the attempt's own workdir), so a convention the judge accepted this run is
promoted at once -- the "automatic fold after each accepted solve" the item centers on, which before
B-040's fix fired only from the manual `ctf seed-fold` CLI. The fold is best effort: it never costs the
attempt record.

These tests drive the real recorder and the real fold (nothing about the fold is mocked); only the
tracked seed path is redirected to a temp dir so the suite never writes `solvers/<lane>/conventions.json`.
"""
import json

import pytest

import labels
from ctf import ledger as _ledger
from ctf.adapt import chain as C

CID = "binary-reverse-engineering-day-04/time_trial"
KEY, NAME = "binary.format/elf", "elf"


@pytest.fixture
def wd(tmp_path, monkeypatch):
    """A clean event workdir with the tracked seed redirected to a temp dir. $CTF_WORKDIR is the same
    workdir the attempt records in, as in production (the opener sets it for the whole run)."""
    for name in ("CTF_JUDGE_LEDGER", "CTF_TESTING", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR"):
        monkeypatch.delenv(name, raising=False)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    monkeypatch.setattr(labels, "seed_path", lambda lane: seeds / f"{lane}.json")
    labels._cache.clear()
    labels._gate_said.clear()
    yield work, seeds
    labels._cache.clear()


def _recorded_outcome(work, challenge_id):
    return [r.get("outcome") for r in _ledger.read(work)
            if r.get("event") == "adapt.attempt" and r.get("challenge_id") == challenge_id]


def test_correct_attempt_folds_the_learned_verdict_into_the_tracked_seed(wd):
    work, seeds = wd
    # the judge accepted the name during the run: it reached the runtime label ledger
    assert labels.learn(KEY, NAME, "accepted", left=30.0) is True
    seed = seeds / "binary.json"
    assert not seed.exists()                       # nothing folded yet

    rec = C.record_attempt(CID, "correct", lane_key="k1", workdir=work)

    assert rec["outcome"] == "correct"             # the attempt is still recorded
    assert _recorded_outcome(work, CID) == ["correct"]
    # the correct outcome triggered the fold: the accepted name is now in the tracked seed
    assert seed.exists(), "a correct attempt must fold the learned verdict into the seed"
    assert json.loads(seed.read_text())[KEY]["accepted"] == NAME


def test_a_failed_attempt_does_not_fold(wd):
    work, seeds = wd
    assert labels.learn(KEY, NAME, "accepted", left=30.0) is True
    seed = seeds / "binary.json"

    C.record_attempt(CID, "incorrect", lane_key="k1", workdir=work)

    assert _recorded_outcome(work, CID) == ["incorrect"]
    assert not seed.exists(), "only an accepted solve folds; a wrong attempt must not touch the seed"


def test_the_fold_is_best_effort_and_never_costs_the_record(wd, monkeypatch, capsys):
    """A judge-free event has no ledger to fold: `fold_all` raises SeedFoldError, which the recorder
    swallows after one stderr line. The attempt record must still be written and no exception propagate."""
    work, _seeds = wd
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    labels._cache.clear()

    rec = C.record_attempt(CID, "correct", lane_key="k1", workdir=work)   # must not raise

    assert rec["outcome"] == "correct"
    assert _recorded_outcome(work, CID) == ["correct"]
    assert "seed fold after a correct attempt skipped" in capsys.readouterr().err


def test_the_fold_uses_the_attempts_workdir_not_the_ambient_one(wd, monkeypatch):
    """record_attempt may be given a --workdir other than $CTF_WORKDIR; the fold must read the ledger of
    THAT workdir. The verdict is learned in the attempt's workdir while $CTF_WORKDIR points elsewhere."""
    work, seeds = wd
    other = work.parent / "other"
    other.mkdir()
    # the learned verdict lives in the attempt's workdir; the ambient $CTF_WORKDIR is a different, empty dir
    assert labels.learn(KEY, NAME, "accepted", left=30.0) is True
    monkeypatch.setenv("CTF_WORKDIR", str(other))
    labels._cache.clear()

    C.record_attempt(CID, "correct", lane_key="k1", workdir=work)

    seed = seeds / "binary.json"
    assert seed.exists() and json.loads(seed.read_text())[KEY]["accepted"] == NAME
