"""B-040: ctf.seedfold -- the automatic fold of event-learned label verdicts into the tracked seeds.

fold_all folds every lane that has a runtime ledger (or the lanes named) into its tracked seed, the same
promotion `labels.py promote` runs by hand, so it can run after each accepted solve. It promotes only
what the judge ledger recorded, honours the order-degenerate guard, skips a ledger file that is not a
lane, and refuses without a judge ledger. The CLI (`python -m ctf seed-fold`) is exercised through run().
"""
import argparse
import json
import sys
from pathlib import Path

import pytest

import labels
from ctf import seedfold


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("CTF_JUDGE_LEDGER", "CTF_TESTING", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR", "CTF_WORKDIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    monkeypatch.setattr(labels, "seed_path", lambda lane: seeds / f"{lane}.json")
    labels._cache.clear()
    labels._gate_said.clear()
    yield seeds
    labels._cache.clear()


def _learn(key, name, verdict="accepted", **kw):
    assert labels.learn(key, name, verdict, **kw) is True


def test_fold_all_discovers_every_lane_with_a_ledger_and_promotes(_isolated):
    _learn("binary.format/elf", "elf")
    _learn("script.control/bat.for", "for_once")
    result = seedfold.fold_all(labels_mod=labels)
    assert set(result) == {"binary", "script"}
    bseed = json.loads((_isolated / "binary.json").read_text())
    sseed = json.loads((_isolated / "script.json").read_text())
    assert bseed["binary.format/elf"]["accepted"] == "elf"
    assert sseed["script.control/bat.for"]["accepted"] == "for_once"


def test_fold_all_honours_the_order_degenerate_guard(_isolated):
    _learn("binary.config_order/elf", "sorted", degenerate=True)
    result = seedfold.fold_all(["binary"], labels_mod=labels)
    assert "binary" in result
    seed = json.loads((_isolated / "binary.json").read_text())
    assert seed["binary.config_order/elf"]["accepted"] is None   # a degenerate accept is not promoted


def test_fold_all_skips_a_ledger_file_that_is_not_a_lane(_isolated, tmp_path):
    _learn("binary.format/elf", "elf")
    # a hand-dropped file whose stem is not a labels lane must be left alone, with a warning, never guessed
    stray = tmp_path / "work" / "_ledger" / "notalane.jsonl"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_text(json.dumps({"key": "x.y/z", "name": "n", "verdict": "accepted"}) + "\n")
    warned = []
    result = seedfold.fold_all(labels_mod=labels, warn=warned.append)
    assert set(result) == {"binary"}
    assert any("notalane" in w for w in warned)


def test_fold_all_is_idempotent(_isolated):
    _learn("binary.format/elf", "elf")
    first = seedfold.fold_all(labels_mod=labels)
    assert first["binary"]                       # the first fold changes the key
    second = seedfold.fold_all(labels_mod=labels)
    assert second["binary"] == []                # nothing left to change


def test_fold_all_refuses_without_a_judge_ledger(_isolated, monkeypatch):
    _learn("binary.format/elf", "elf")
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    labels._cache.clear()
    with pytest.raises(seedfold.SeedFoldError, match="no judge ledger"):
        seedfold.fold_all(labels_mod=labels)


def test_fold_all_raises_on_an_unknown_explicit_lane(_isolated):
    with pytest.raises(seedfold.SeedFoldError, match="unknown lane"):
        seedfold.fold_all(["bogus"], labels_mod=labels)


def test_ledger_lanes_maps_a_solver_folder_alias(_isolated, tmp_path):
    # a ledger named by the solver-folder alias resolves to the lane
    f = tmp_path / "work" / "_ledger" / "binary-reverse-engineering.jsonl"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"key": "binary.format/elf", "name": "elf", "verdict": "accepted"}) + "\n")
    assert seedfold.ledger_lanes(labels) == ["binary"]


def test_cli_dry_run_reports_without_writing(tmp_path, monkeypatch, capsys):
    """The CLI, end to end through run(), against the real labels module (dry-run writes nothing)."""
    from ctf.cli import seed_fold
    wd = tmp_path / "work"
    (wd / "_ledger").mkdir(parents=True)
    (wd / "_ledger" / "warmups.jsonl").write_text(
        json.dumps({"key": "warmups.selftest/shape", "name": "alpha", "verdict": "accepted"}) + "\n")
    monkeypatch.setenv("CTF_WORKDIR", str(wd))
    monkeypatch.delenv("CTF_JUDGE_LEDGER", raising=False)
    # the real tracked warmups seed must not be touched by a dry run
    real_seed = seedfold.seed_path(seedfold.labels_module(), "warmups")
    before = real_seed.read_text() if real_seed.exists() else None
    args = argparse.Namespace(lanes=[], dry_run=True, workdir=None, json=False)
    rc = seed_fold.run(args)
    out = capsys.readouterr().out
    assert rc == 0
    assert "warmups.selftest/shape" in out
    assert "dry-run" in out
    after = real_seed.read_text() if real_seed.exists() else None
    assert after == before      # dry run wrote nothing to the tracked seed


def test_cli_workdir_flag_folds_that_workdir_without_touching_the_environment(_isolated, tmp_path, monkeypatch):
    """`--workdir DIR` must fold DIR's ledger (not the ambient workdir's) and thread the path straight
    into the fold, never mutating the process environment: the workdir env is read only by ctf.paths, so
    a CLI run leaves the whole environment exactly as it found it (round-2 removed the env mutation).

    The environment is checked as a whole (snapshot and compare), never by reading the workdir var by
    name -- the single-source scan forbids any module but ctf.paths from reading that variable."""
    import os
    from ctf.cli import seed_fold
    seeds = _isolated
    ambient = tmp_path / "work"                    # the fixture's workdir (left empty here)
    other = tmp_path / "other"
    # the verdict is recorded under `other`, while the ambient workdir stays empty
    monkeypatch.setenv("CTF_WORKDIR", str(other))
    labels._cache.clear()
    _learn("binary.format/elf", "elf")
    monkeypatch.setenv("CTF_WORKDIR", str(ambient))
    labels._cache.clear()
    env_before = dict(os.environ)                  # snapshot the whole environment

    args = argparse.Namespace(lanes=["binary"], dry_run=False, workdir=other, json=False)
    rc = seed_fold.run(args)

    assert rc == 0
    # folded from `other`, not the empty ambient workdir
    seed = json.loads((seeds / "binary.json").read_text())
    assert seed["binary.format/elf"]["accepted"] == "elf"
    # the CLI leaked nothing into the environment (the whole mapping is unchanged)
    assert dict(os.environ) == env_before
