"""labels.py after the B-001 hand merge (Huntress base + CSCTF show(), gated on the judge-ledger capability).

Covers: the CTF_JUDGE_LEDGER gate (on by default; off = no seed/ledger read, learn records nothing,
promote refuses, lane_of accepts any prefix without touching LANE_DIRS; a bad value fails loudly),
the CTF_* env names (CTF_WORKDIR, CTF_TESTING + CTF_LEDGER_MASK, CTF_FAMILY_PRIOR) and show().
"""
import json

import pytest

import labels
from ctf import event, paths

KEY = "warmups.gate_selftest/shape"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("CTF_JUDGE_LEDGER", "CTF_TESTING", "CTF_LEDGER_MASK", "CTF_FAMILY_PRIOR", "CTF_WORKDIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    seed = tmp_path / "seed.json"
    seed.write_text("{}")
    monkeypatch.setattr(labels, "seed_path", lambda lane: seed)
    labels._cache.clear()
    labels._gate_said.clear()
    yield seed
    labels._cache.clear()


def _ledger_file(tmp_path):
    return tmp_path / "work" / "_ledger" / "warmups.jsonl"


def test_ledger_lives_under_the_event_workdir(tmp_path):
    assert labels.challenges_root() == paths.workdir() == (tmp_path / "work").resolve()
    assert labels.learn(KEY, "alpha", "accepted") is True
    assert _ledger_file(tmp_path).is_file()


def test_no_workdir_and_no_event_fails_loudly_instead_of_using_the_checkout(monkeypatch):
    # B-001a: the old fallbacks (<repo>/challenges, a worktree's main checkout) are gone.
    monkeypatch.delenv("CTF_WORKDIR")
    monkeypatch.delenv("CTF_EVENT", raising=False)
    with pytest.raises(event.EventError, match="CTF_EVENT"):
        labels.challenges_root()
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert labels.challenges_root() == paths.workdir("pink")
    assert paths.repo_root() not in labels.challenges_root().parents


def test_gate_on_by_default_learn_then_plain(tmp_path):
    assert labels.judge_ledger() is True
    first = labels.pick(KEY, ["alpha", "beta"])
    assert labels.is_unsure(first)
    assert labels.learn(KEY, "alpha", "accepted") is True
    assert labels.pick(KEY, ["alpha", "beta"]) == "alpha"


def test_gate_on_unknown_lane_raises():
    with pytest.raises(ValueError, match="lane must be one of"):
        labels.lane_of("ctfd.thing/shape")


def test_gate_off_reads_nothing_records_nothing(tmp_path, monkeypatch, capsys, _isolated):
    _isolated.write_text(json.dumps({KEY: {"accepted": "alpha", "rejected": ["beta"], "split": False}}))
    labels.learn(KEY, "gamma", "rejected")              # a ledger row written while the gate is on
    rows_before = _ledger_file(tmp_path).read_text()
    assert labels.pick(KEY, ["alpha", "beta"]) == "alpha"
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "off")
    labels._cache.clear()
    got = labels.pick(KEY, ["alpha", "beta", "gamma"])
    assert labels.is_unsure(got)
    assert labels.parse(got).names == ["alpha", "beta", "gamma"]   # neither the seed's rejection nor the ledger's
    assert labels.state(KEY)["accepted"] is None
    assert labels.learn(KEY, "alpha", "accepted") is False
    assert labels.learn(KEY, "beta", "accepted") is False
    assert _ledger_file(tmp_path).read_text() == rows_before
    assert capsys.readouterr().err.count("no judge ledger") == 1     # said once, not per call
    with pytest.raises(ValueError, match="CTF_JUDGE_LEDGER"):
        labels.promote("warmups")
    assert labels.main(["promote", "warmups"]) == 2


def test_gate_off_lane_of_is_lenient_and_leaves_lane_dirs(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "0")
    before = dict(labels.LANE_DIRS)
    assert labels.lane_of("ctfd.thing/shape") == "ctfd"
    assert labels.lane_of("/shape") == "misc"
    got = labels.pick("ctfd.thing/shape", ["a", "b"])
    assert labels.parse(got).key == "ctfd.thing/shape"
    assert labels.LANE_DIRS == before


def test_gate_bad_value_fails_loudly(monkeypatch):
    monkeypatch.setenv("CTF_JUDGE_LEDGER", "maybe")
    with pytest.raises(ValueError, match="CTF_JUDGE_LEDGER"):
        labels.judge_ledger()
    with pytest.raises(ValueError, match="CTF_JUDGE_LEDGER"):
        labels.pick(KEY, ["alpha"])


def test_mask_uses_ctf_names(monkeypatch, _isolated):
    _isolated.write_text(json.dumps({KEY: {"accepted": "alpha", "rejected": [], "split": False}}))
    assert labels.pick(KEY, ["alpha", "beta"]) == "alpha"
    monkeypatch.setenv("CTF_LEDGER_MASK", "warmups.gate_selftest/*")
    labels._cache.clear()
    assert labels.pick(KEY, ["alpha", "beta"]) == "alpha"           # inert without CTF_TESTING=1
    monkeypatch.setenv("CTF_TESTING", "1")
    labels._cache.clear()
    assert labels.is_unsure(labels.pick(KEY, ["alpha", "beta"]))


def test_family_prior_switch_uses_ctf_name(monkeypatch, _isolated):
    seed = {f"warmups.role/m{i}.shape": {"accepted": "same", "rejected": [], "split": False} for i in range(6)}
    _isolated.write_text(json.dumps(seed))
    new = "warmups.role/fresh.shape"
    assert labels.pick(new, ["same", "other"]) == "same"
    monkeypatch.setenv("CTF_FAMILY_PRIOR", "off")
    labels._cache.clear()
    assert labels.is_unsure(labels.pick(new, ["same", "other"]))


def test_show():
    assert labels.show("plain") == "plain"
    assert labels.show(None) == ""
    assert labels.show(labels.unsure(KEY, [("raw", "1"), ("hex", "0x1")])) == "candidates: 1, 0x1"
    assert labels.show(labels.unsure(KEY, [])) == "(no candidates)"
