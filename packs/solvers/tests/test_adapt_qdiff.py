"""B-036: the question-contract diff of a timed start (ctf/adapt/qdiff.py). Synthetic bodies shaped like a
Game Master status body; the Day 17 shape is an integer answer that became exact_text with a sentence
allowing the literal none."""
from __future__ import annotations

import pytest

from ctf.adapt import qdiff as Q


def q(qid, kind="integer", syntax="a decimal integer", text=None, accepted=None):
    fmt = {"kind": kind, "syntax": syntax}
    if accepted is not None:
        fmt["accepted_values"] = accepted
    return {"id": qid, "question": text or f"What is {qid}?", "answer_format": fmt}


BASE = {"questions": [q("d01_analysis_recover_code"), q("d01_analysis_entry_point", "pattern", "0x hex")]}


def whats(d):
    return [(c.what, c.qid) for c in d.changes]


def test_the_day_17_shape_needs_attention():
    timed = {"questions": [
        q("d01_analysis_recover_code", "exact_text", "the code as printed; use the literal none when it is absent"),
        q("d01_analysis_entry_point", "pattern", "0x hex")]}
    d = Q.qdiff(BASE, timed)
    assert whats(d) == [("kind", "d01_analysis_recover_code"), ("none", "d01_analysis_recover_code"),
                        ("syntax", "d01_analysis_recover_code")]
    kind = d.changes[0]
    assert (kind.before, kind.after) == ("integer", "exact_text") and kind.attention
    none = d.changes[1]
    assert (none.before, none.after) == ("not allowed", "allowed")
    assert len(d.attention) == 3
    assert d.lines()[0].startswith("ATTN kind")


def test_same_questions_say_so():
    d = Q.qdiff(BASE, BASE["questions"])
    assert d.changes == () and d.attention == () and d.lines() == ["same questions: no change from the base"]


def test_a_wording_change_alone_is_information():
    timed = [q("d01_analysis_recover_code", text="Recover the code."), q("d01_analysis_entry_point", "pattern", "0x hex")]
    d = Q.qdiff(BASE, timed)
    assert whats(d) == [("text", "d01_analysis_recover_code")] and d.attention == ()
    assert d.lines()[0].startswith("info text")


def test_added_removed_and_accepted_values():
    before = [q("a", "enum", "one of", accepted=["x", "y"]), q("gone")]
    after = [q("a", "enum", "one of", accepted=["y", "x", "z"]), q("new")]
    d = Q.qdiff(before, after)
    assert whats(d) == [("accepted", "a"), ("added", "new"), ("removed", "gone")]
    assert d.changes[0].before == "x, y" and d.changes[0].after == "x, y, z"
    assert all(c.attention for c in d.changes)


def test_literal_none_withdrawn_is_a_change_too():
    before = [q("a", "exact_text", "text", accepted=["none", "x"])]
    after = [q("a", "exact_text", "text", accepted=["x"])]
    d = Q.qdiff(before, after)
    assert ("none", "a") in whats(d)
    assert [c for c in d.changes if c.what == "none"][0].after == "not allowed"


def test_qid_is_accepted_as_the_id():
    d = Q.qdiff([{"qid": "a", "answer_format": {"kind": "integer"}}], [{"qid": "a", "answer_format": {"kind": "json"}}])
    assert whats(d) == [("kind", "a")]


@pytest.mark.parametrize("body", [{"no": "questions"}, "text", [{"question": "no id"}], [42]])
def test_unreadable_bodies_are_refused(body):
    with pytest.raises(Q.QDiffError):
        Q.qdiff(body, BASE)
