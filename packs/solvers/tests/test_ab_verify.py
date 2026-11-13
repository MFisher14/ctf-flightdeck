"""B-096: the verify-role A/B harness (tools/ledger/ab_verify.py).

No model is called: every reviewer here is a stub the test writes. The harness feeds a fixed set of
seeded-bug diffs to two reviewer configs and counts bugs found per config; the ledger is synthetic.
"""
from __future__ import annotations

import json

import pytest

from ctf import ledger
from tools.ledger import ab_verify as ab

# A tiny fixed corpus: two diffs, three seeded bugs in all.
CORPUS = [
    {"id": "d1", "diff": "--- a\n+++ b\n+ strcpy(dst, src);\n+ int n = len - 1;",
     "bugs": [{"id": "overflow", "marker": "buffer overflow"},
              {"id": "offbyone", "marker": r"off.by.one", "regex": True}]},
    {"id": "d2", "diff": "--- a\n+++ b\n+ query = 'SELECT * WHERE id=' + uid",
     "bugs": [{"id": "sqli", "marker": "SQL injection"}]},
]


def corpus():
    return ab.load_corpus([dict(d) for d in CORPUS])


def reviewer(found_markers, *, usd=0.0, tokens=0):
    """A stub reviewer whose prose happens to contain the given marker strings."""
    text = "I reviewed the diff and found: " + "; ".join(found_markers)

    def review(_diff):
        return ab.Review(text, usd=usd, tokens=tokens)

    return review


# ------------------------------------------------------------------ corpus loading

def test_load_corpus_parses_bugs_and_regex_flag():
    diffs = corpus()
    assert [d.id for d in diffs] == ["d1", "d2"]
    assert [b.id for b in diffs[0].bugs] == ["overflow", "offbyone"]
    assert diffs[0].bugs[1].regex is True


@pytest.mark.parametrize("bad", [
    [{"diff": "x"}],                                   # no id
    [{"id": "d", "diff": "x", "bugs": [{"id": "b"}]}],  # bug without a marker
    [{"id": "d", "diff": "x"}, {"id": "d", "diff": "y"}],  # duplicate diff id
    [],                                                # empty corpus
])
def test_load_corpus_rejects_bad_shapes(bad):
    with pytest.raises(ab.ABError):
        ab.load_corpus(bad)


def test_seeded_bug_marker_matching_is_case_insensitive_and_regex_aware():
    overflow = ab.SeededBug("o", "buffer overflow")
    offbyone = ab.SeededBug("x", r"off.by.one", regex=True)
    assert overflow.detect("A classic BUFFER OVERFLOW here")
    assert not overflow.detect("no issue")
    assert offbyone.detect("this is an off-by-one bug")   # regex . matches the hyphen
    assert not offbyone.detect("offbyone")                # needs a separator between words


# ------------------------------------------------------------------ the A/B run

def test_counts_bugs_found_per_config():
    diffs = corpus()
    # opus finds all three; sonnet misses the off-by-one.
    configs = [
        ab.ReviewerConfig("opus", "claude-opus-5-5",
                          reviewer(["buffer overflow", "off-by-one", "SQL injection"])),
        ab.ReviewerConfig("sonnet", "claude-sonnet-5-5",
                          reviewer(["buffer overflow", "SQL injection"])),
    ]
    res = ab.run_ab(diffs, configs)
    assert res.bugs_total == 3
    opus, sonnet = res.config("opus"), res.config("sonnet")
    assert (opus.found, opus.missed) == (3, 0)
    assert opus.recall == 1.0
    assert (sonnet.found, sonnet.missed) == (2, 1)
    assert sonnet.recall == pytest.approx(2 / 3)
    # the miss is attributed to the right diff and bug.
    miss = [s for s in res.scores if s.config == "sonnet" and s.missed]
    assert len(miss) == 1 and miss[0].diff_id == "d1" and miss[0].missed == ("offbyone",)


def test_config_order_preserved_and_cost_aggregated():
    diffs = corpus()
    configs = [
        ab.ReviewerConfig("sonnet", "claude-sonnet-5-5", reviewer(["SQL injection"], usd=0.01, tokens=100)),
        ab.ReviewerConfig("opus", "claude-opus-5-5", reviewer(["buffer overflow"], usd=0.05, tokens=200)),
    ]
    res = ab.run_ab(diffs, configs)
    assert [c.name for c in res.configs] == ["sonnet", "opus"]
    # two diffs reviewed per config, so the per-review cost is doubled.
    assert res.config("sonnet").usd == pytest.approx(0.02)
    assert res.config("opus").tokens == 400


def test_a_plain_string_reviewer_return_is_accepted():
    diffs = corpus()
    res = ab.run_ab(diffs, [ab.ReviewerConfig(
        "s", "m", lambda _d: "found a SQL injection and a buffer overflow and an off-by-one slip")])
    assert res.config("s").found == 3


def test_a_bad_reviewer_return_is_rejected_not_scored_as_zero():
    diffs = corpus()
    with pytest.raises(ab.ABError):
        ab.run_ab(diffs, [ab.ReviewerConfig("s", "m", lambda _d: 123)])


def test_a_crashing_reviewer_is_not_swallowed():
    diffs = corpus()

    def boom(_d):
        raise RuntimeError("model unreachable")

    with pytest.raises(RuntimeError, match="model unreachable"):
        ab.run_ab(diffs, [ab.ReviewerConfig("s", "m", boom)])


def test_run_ab_rejects_empty_inputs_and_duplicate_names():
    with pytest.raises(ab.ABError):
        ab.run_ab([], [ab.ReviewerConfig("s", "m", reviewer([]))])
    with pytest.raises(ab.ABError):
        ab.run_ab(corpus(), [])
    with pytest.raises(ab.ABError):
        ab.run_ab(corpus(), [ab.ReviewerConfig("s", "m", reviewer([])),
                             ab.ReviewerConfig("s", "n", reviewer([]))])


# ------------------------------------------------------------------ the ledger record and the gate

def test_verify_stays_on_primary_until_an_approving_record_exists(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    primary, candidate = "claude-opus-5-5", "claude-sonnet-5-5"
    # no record yet -> primary.
    assert ab.chosen_verify_model(ledger.read(wd), primary=primary, candidate=candidate) == primary
    res = ab.run_ab(corpus(), [ab.ReviewerConfig("sonnet", candidate,
                                                 reviewer(["buffer overflow", "SQL injection"]))])
    # an unapproved result does not flip verify to the candidate.
    ab.record_result(wd, res, by="max", approved=False)
    assert ab.chosen_verify_model(ledger.read(wd), primary=primary, candidate=candidate) == primary
    # an approved record naming the candidate does.
    ab.record_result(wd, res, by="max", approved=True, approved_model=candidate)
    assert ab.chosen_verify_model(ledger.read(wd), primary=primary, candidate=candidate) == candidate


def test_an_unapproved_record_that_names_the_model_still_keeps_verify_on_primary(tmp_path):
    # record_result stores approved_model even on an unapproved record (the human noted which model the
    # trial ran), so a record can carry approved=False AND approved_model=candidate. The gate must read
    # the `approved` flag, not just the named model: an unapproved-but-named record must not flip verify
    # to the candidate. This is the exact safety invariant the item exists to enforce.
    wd = tmp_path / "work"
    wd.mkdir()
    primary, candidate = "claude-opus-5-5", "claude-sonnet-5-5"
    res = ab.run_ab(corpus(), [ab.ReviewerConfig("sonnet", candidate,
                                                 reviewer(["buffer overflow", "SQL injection"]))])
    rec = ab.record_result(wd, res, by="max", approved=False, approved_model=candidate)
    assert rec["approved"] is False and rec["approved_model"] == candidate  # the named-but-unapproved shape
    assert ab.chosen_verify_model(ledger.read(wd), primary=primary, candidate=candidate) == primary


def test_record_result_writes_the_per_config_counts(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    res = ab.run_ab(corpus(), [
        ab.ReviewerConfig("opus", "claude-opus-5-5",
                          reviewer(["buffer overflow", "off-by-one", "SQL injection"])),
        ab.ReviewerConfig("sonnet", "claude-sonnet-5-5", reviewer(["buffer overflow"])),
    ])
    rec = ab.record_result(wd, res, by="max", approved=False, note="first pass")
    assert rec["event"] == ab.AB_EVENT and rec["bugs_total"] == 3 and rec["note"] == "first pass"
    byname = {c["name"]: c for c in rec["configs"]}
    assert byname["opus"]["recall"] == 1.0
    assert byname["sonnet"]["found"] == 1 and byname["sonnet"]["missed"] == 2
    # it is on the ledger.
    assert any(r["event"] == ab.AB_EVENT for r in ledger.read(wd))


def test_approved_record_must_name_the_model(tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    res = ab.run_ab(corpus(), [ab.ReviewerConfig("s", "m", reviewer([]))])
    with pytest.raises(ab.ABError):
        ab.record_result(wd, res, by="max", approved=True)
    with pytest.raises(ab.ABError):
        ab.record_result(wd, res, by="", approved=False)


# ------------------------------------------------------------------ the CLI corpus check

def test_main_validates_a_corpus_file(tmp_path, capsys):
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps({"diffs": CORPUS}), encoding="utf-8")
    assert ab.main(["--corpus", str(p), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["diffs"] == 2 and out["bugs"] == 3


def test_main_reports_a_bad_corpus(tmp_path, capsys):
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps([{"id": "d"}]), encoding="utf-8")   # no diff text
    assert ab.main(["--corpus", str(p)]) == 2
    assert "ab_verify" in capsys.readouterr().err


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
