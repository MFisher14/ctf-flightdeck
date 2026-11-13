"""B-040: the order-degenerate guard in solvers/common/labels.py.

The judge banks a batch when every answer is right. An acceptance on an input the convention cannot
distinguish -- already-sorted bytes, where `sorted` and `as_is` produce the same output; an identity XOR
key, where every spelling of the transform coincides -- is CORRECT but proves nothing, so promoting the
name to a plain answer would be wrong on the next variant. `labels.degenerate_accept` detects the
collision from the options; `labels.learn(..., degenerate=...)` marks the row; `_fold` keeps its evidence
but never promotes the name. A later, distinguishing acceptance of the same name still promotes it.
"""
import json

import pytest

import labels

KEY = "binary.config_order/elf"
# The two offered spellings of one fact. On already-sorted input they coincide (degenerate); on a later
# unsorted variant they differ, and the judge's yes then tells them apart.
DEGENERATE = [("sorted", "AB"), ("as_is", "AB")]
DISTINCT = [("sorted", "AB"), ("as_is", "BA")]


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


def test_degenerate_accept_detects_a_value_collision():
    assert labels.degenerate_accept(DEGENERATE, "sorted") is True
    assert labels.degenerate_accept(DEGENERATE, "as_is") is True
    assert labels.degenerate_accept(DISTINCT, "sorted") is False
    # a name not offered cannot be degenerate, and bare labels are their own values, so two never collide
    assert labels.degenerate_accept(DISTINCT, "missing") is False
    assert labels.degenerate_accept(["alpha", "beta"], "alpha") is False


def test_a_degenerate_acceptance_is_not_promoted_to_plain(_isolated):
    flag = labels.degenerate_accept(DEGENERATE, "sorted")
    assert flag is True
    assert labels.learn(KEY, "sorted", "accepted", degenerate=flag) is True
    # the next variant, where the spellings differ, must stay unsure -- the judge never distinguished them.
    got = labels.pick(KEY, DISTINCT)
    assert labels.is_unsure(got)
    assert labels.parse(got).names == ["sorted", "as_is"]
    st = labels.state(KEY)
    assert st["accepted"] is None and st["accepted_names"] == []
    # the observation is still recorded, marked so a human sees why it was not banked.
    assert any("degenerate" in e for e in st["evidence"])


def test_a_later_distinguishing_acceptance_promotes_the_name(_isolated):
    labels.learn(KEY, "sorted", "accepted", degenerate=True)
    assert labels.is_unsure(labels.pick(KEY, DISTINCT))
    # a run on an input where sorted != as_is accepts `sorted`: now it is a real, plain answer.
    labels.learn(KEY, "sorted", "accepted", degenerate=False)
    assert labels.pick(KEY, DISTINCT) == "AB"
    assert labels.state(KEY)["accepted"] == "sorted"


def test_a_degenerate_acceptance_does_not_clear_a_rejection_or_split(_isolated):
    _isolated.write_text(json.dumps({KEY: {"accepted": None, "rejected": ["sorted"], "split": False}}))
    labels._cache.clear()
    labels.learn(KEY, "sorted", "accepted", degenerate=True)
    st = labels.state(KEY)
    assert st["accepted"] is None
    assert "sorted" in st["rejected"]      # a non-distinguishing yes must not un-reject a known-bad name
    assert st["split"] is False            # nor split the key


def test_promote_folds_degenerate_evidence_but_not_the_name(_isolated):
    labels.learn(KEY, "sorted", "accepted", degenerate=True)
    changed = labels.promote("binary")
    assert any(KEY in line for line in changed)
    data = json.loads(_isolated.read_text())
    assert data[KEY]["accepted"] is None
    assert "accepted_names" not in data[KEY] or data[KEY]["accepted_names"] == []
    assert any("degenerate" in e for e in data[KEY]["evidence"])


def test_the_row_carries_the_degenerate_flag_only_for_an_accept(_isolated):
    labels.learn(KEY, "sorted", "accepted", degenerate=True)
    labels.learn(KEY, "as_is", "rejected", degenerate=True)   # degenerate is meaningless for a rejection
    rows = labels._read_rows("binary")
    by_name = {r["name"]: r for r in rows}
    assert by_name["sorted"].get("degenerate") is True
    assert "degenerate" not in by_name["as_is"]
