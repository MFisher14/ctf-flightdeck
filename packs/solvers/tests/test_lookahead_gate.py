"""B-174: the look-ahead completeness gate (ctf.lookahead.matrix and ctf.lookahead.gate).

Every specimen, question and member here is synthetic, written into tmp_path by tests/lookahead_build.py.
evaluate() is tested on hand-made SpecimenRun results (its input), and run_lane()/gate() for real: the
probe reader runs in the guarded child process.
"""
from __future__ import annotations

import base64
import bz2
import gzip
import json
import lzma
import re
import socket
import threading
import zlib

import pytest

from ctf import ledger, paths
from ctf.lookahead import LookaheadError
from ctf.lookahead import gate as G
from ctf.lookahead import matrix as M

import lookahead_build as LB

ROOT = paths.repo_root()


def _ran(name, answers):
    return G.SpecimenRun(name, G.RAN, "", answers, 0.01)


def _lane(tmp_path, **cfg):
    return LB.matrix(tmp_path, {"probe": {"reader": "unused.py", **cfg}})


def _kinds(rep):
    return sorted(g.kind for g in rep.gaps)


# ------------------------------------------------------------------- the Day 28 shape: falsely green


def test_a_run_with_no_wrong_answer_is_red_when_a_deterministic_id_is_unanswered(tmp_path):
    m = _lane(tmp_path)
    qs = [LB.q(f"d28_field_{i}") for i in range(30)] + [LB.q("d28_set_count", "integer")]
    LB.specimen(m, "probe", "base", qs, key={f"d28_field_{i}": f"v{i}" for i in range(30)})
    answers = {f"d28_field_{i}": f"v{i}" for i in range(30)}          # every keyed answer right
    answers["d28_set_count"] = None                                   # the "safe None"
    rep = G.evaluate(M.load(m), "probe", {"base": _ran("base", answers)})
    assert not rep.ok and rep.verdict == G.RED
    assert [(g.kind, g.qid) for g in rep.gaps] == [("unanswered", "d28_set_count")]
    c = rep.counts()
    assert (c["correct"], c["wrong"], c["unanswered"], c["gaps"]) == (30, 0, 1, 1)
    assert rep.headline().startswith("LOOKAHEAD probe: RED  1 gap(s);")
    assert "1 unanswered deterministic" in rep.headline()


def test_the_same_run_with_the_id_answered_is_green(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "base", [LB.q("a"), LB.q("b", "integer")], key={"a": "x"})
    rep = G.evaluate(M.load(m), "probe", {"base": _ran("base", {"a": "x", "b": 7})})
    assert rep.ok and rep.gaps == () and rep.counts()["answered"] == 2


def test_a_missing_answer_and_a_blank_answer_are_unanswered(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("a"), LB.q("b")])
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {"b": "  "})})
    assert [(g.kind, g.qid) for g in rep.gaps] == [("unanswered", "a"), ("unanswered", "b")]


# ---------------------------------------------------------------------------------- determinism


def test_judged_ids_unanswered_are_reported_not_gaps(tmp_path):
    m = _lane(tmp_path, judged=["*_family_label"])
    LB.specimen(m, "probe", "s", [LB.q("set2.d28_family_label"), LB.q("why", determinism="judged"), LB.q("hash")])
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {})})
    assert [(g.kind, g.qid) for g in rep.gaps] == [("unanswered", "hash")]
    assert rep.counts()["unanswered_judged"] == 2 and rep.counts()["unanswered"] == 1


def test_determinism_defaults_to_deterministic_for_every_kind():
    for kind in ("exact_text", "pattern", "integer", "json", "enum", "boolean", "something_new"):
        assert M.determinism(LB.q("x", kind)) == M.DETERMINISTIC
    assert M.determinism(LB.q("x"), judged=["y*"]) == M.DETERMINISTIC
    assert M.determinism(LB.q("set3.y_label"), judged=["y*"]) == M.JUDGED
    assert M.determinism(LB.q("x", determinism="deterministic"), judged=["x"]) == M.DETERMINISTIC
    with pytest.raises(LookaheadError, match="determinism 'maybe'"):
        M.determinism(LB.q("x", determinism="maybe"))


# ------------------------------------------------------------------------------- classification


def test_wrong_answers_against_the_key_are_gaps_and_lists_compare_as_json(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("a"), LB.q("b", "integer"), LB.q("c", "json"), LB.q("d", "json")],
                key={"a": "right", "b": 64, "c": ["x", "y"], "d": {"k": 1}})
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {"a": "wrong", "b": "64", "c": ["x", "y"],
                                                         "d": {"k": 2}})})
    assert [(g.kind, g.qid) for g in rep.gaps] == [("wrong", "a"), ("wrong", "d")]
    assert "'wrong', the key is 'right'" in rep.gaps[0].detail
    assert {r.qid: r.status for r in rep.rows} == {"a": "wrong", "b": "correct", "c": "correct", "d": "wrong"}


def test_the_literal_none_is_wrong_unless_the_format_allows_it(tmp_path):
    m = _lane(tmp_path)
    allowed = LB.q("p", "enum")
    allowed["answer_format"]["accepted_values"] = ["alpha", "none"]
    LB.specimen(m, "probe", "s", [LB.q("n"), allowed, LB.q("k")], key={"k": "none"})
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {"n": "none", "p": "none", "k": "none"})})
    assert [(g.kind, g.qid) for g in rep.gaps] == [("wrong", "n")]
    assert "literal none" in rep.gaps[0].detail
    assert {r.qid: r.status for r in rep.rows}["p"] == "answered"
    assert {r.qid: r.status for r in rep.rows}["k"] == "correct"


def test_unsure_answers(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q(x) for x in ("pairs", "plain", "miss", "bad", "nokey")],
                key={"pairs": "0x10", "plain": "beta", "miss": "gamma", "bad": "x"})
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {
        "pairs": '??{"key": "k", "options": [["raw", "16"], ["hex", "0x10"]]}',
        "plain": '??["alpha", "beta"]',
        "miss": '??["alpha", "beta"]',
        "bad": "??not json",
        "nokey": '??["a", "b"]'})})
    st = {r.qid: r.status for r in rep.rows}
    assert st == {"pairs": "unsure", "plain": "unsure", "miss": "wrong", "bad": "wrong", "nokey": "unsure"}
    assert [(g.kind, g.qid) for g in rep.gaps] == [("unsure", "pairs"), ("unsure", "plain"), ("wrong", "miss"),
                                                   ("wrong", "bad"), ("unsure", "nokey")]
    assert "never sent" in rep.gaps[0].detail
    assert rep.counts()["unsure"] == 3


def test_an_unsure_deterministic_answer_is_a_gap_unless_judged_or_the_lane_allows_it(tmp_path):
    qs = [LB.q("hash"), LB.q("set2.why_label"), LB.q("story", determinism="judged")]
    answers = {"hash": '??["a", "b"]', "set2.why_label": '??["x", "y"]', "story": '??["p", "q"]'}
    m = _lane(tmp_path, judged=["why_label"])
    LB.specimen(m, "probe", "s", qs, key={"hash": "a"})
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", answers)})
    assert not rep.ok and [(g.kind, g.qid) for g in rep.gaps] == [("unsure", "hash")]
    assert rep.counts()["unsure"] == 3
    m2 = LB.matrix(tmp_path, {"probe": {"reader": "unused.py", "judged": ["why_label"], "allow_unsure": True}},
                   name="m2")
    LB.specimen(m2, "probe", "s", qs, key={"hash": "a"})
    rep = G.evaluate(M.load(m2), "probe", {"s": _ran("s", answers)})
    assert rep.ok and rep.counts()["unsure"] == 3
    m3 = LB.matrix(tmp_path, {"probe": {"reader": "unused.py", "allow_unsure": "yes"}}, name="m3")
    with pytest.raises(LookaheadError, match="allow_unsure must be true or false"):
        M.load(m3)


# ------------------------------------------------------------------- skips, crashes and cut runs


def test_declared_and_generator_skips_are_gaps_and_their_ids_count_as_skipped(tmp_path):
    m = LB.matrix(tmp_path, {"probe": {"reader": "unused.py"}},
                  skipped=[{"lane": "probe", "name": "d28-terraform", "reason": "plan adapter differs", "ids": 44}])
    LB.specimen(m, "probe", "ok", [LB.q("a")])
    LB.specimen(m, "probe", "left", [LB.q("t1"), LB.q("t2")], skip="no Terraform writer")
    mx = M.load(m)
    runs = {"ok": _ran("ok", {"a": "1"}), "left": G.SpecimenRun("left", G.SKIPPED, "declared skip: no Terraform writer")}
    rep = G.evaluate(mx, "probe", runs)
    assert [(g.kind, g.specimen) for g in rep.gaps] == [("skipped", "left"), ("skipped", "d28-terraform")]
    assert "2 id(s) not exercised" in rep.gaps[0].detail
    assert "44 id(s) not exercised" in rep.gaps[1].detail and "plan adapter differs" in rep.gaps[1].detail
    assert rep.counts()["skipped"] == 2


def test_crashed_and_cut_specimens_are_gaps(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "a", [LB.q("x")])
    LB.specimen(m, "probe", "b", [LB.q("y")])
    LB.specimen(m, "probe", "c", [LB.q("z")])
    rep = G.evaluate(M.load(m), "probe", {"a": G.SpecimenRun("a", G.CRASHED, "ValueError: boom"),
                                          "b": G.SpecimenRun("b", G.CUT, "cut at the 2s cap"),
                                          "c": _ran("c", {"z": "1"})})
    assert [(g.kind, g.specimen) for g in rep.gaps] == [("crashed", "a"), ("cut", "b")]
    assert {r.qid: r.status for r in rep.rows} == {"x": "skipped", "y": "skipped", "z": "answered"}


def test_a_lane_with_nothing_run_is_empty_and_red(tmp_path):
    m = _lane(tmp_path)
    rep = G.evaluate(M.load(m), "probe", {})
    assert _kinds(rep) == ["empty"]
    LB.specimen(m, "probe", "only", [LB.q("x")], skip="not built")
    rep = G.evaluate(M.load(m), "probe", {"only": G.SpecimenRun("only", G.SKIPPED, "declared skip")})
    assert _kinds(rep) == ["empty", "skipped"]


def test_a_specimen_with_no_run_result_is_an_error(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("x")])
    with pytest.raises(LookaheadError, match="no run result for specimen s"):
        G.evaluate(M.load(m), "probe", {})


# --------------------------------------------------------------------------- the newest base


def test_every_id_of_the_newest_base_must_be_asked_by_a_specimen_that_ran(tmp_path):
    m = tmp_path / "matrix"
    m.mkdir()
    (m / "base.json").write_text(json.dumps({"questions": [LB.q("set1.alpha"), LB.q("set2.alpha"),
                                                              LB.q("set1.beta"), LB.q("set2.beta"),
                                                              LB.q("set3.beta"), LB.q("gamma")]}))
    LB.matrix(tmp_path, {"probe": {"reader": "unused.py", "base": "base.json"}})
    LB.specimen(m, "probe", "ran", [LB.q("set1.alpha")])
    LB.specimen(m, "probe", "notrun", [LB.q("gamma")], skip="later")
    runs = {"ran": _ran("ran", {"set1.alpha": "x"}), "notrun": G.SpecimenRun("notrun", G.SKIPPED, "declared skip")}
    rep = G.evaluate(M.load(m), "probe", runs)
    unc = [(g.kind, g.qid) for g in rep.gaps if g.kind == "uncovered"]
    assert unc == [("uncovered", "beta"), ("uncovered", "gamma")]     # alpha once covered, by bare id;
    #                                                                   beta, asked by three sets, one gap


def test_a_base_path_that_is_not_a_file_is_an_error(tmp_path):
    m = _lane(tmp_path, base="nope.json")
    with pytest.raises(LookaheadError, match="base 'nope.json' is not a file"):
        M.load(m)


# ------------------------------------------------------------------------------- thresholds


def test_a_declared_threshold_needs_a_specimen_on_each_side(tmp_path):
    th = [{"name": "siblings", "bytes": 100, "measure": "total"}, {"name": "member", "bytes": 60, "measure": "member"}]
    m = _lane(tmp_path, threshold=th)
    LB.specimen(m, "probe", "small", [LB.q("a")], {"x": b"a" * 50})
    rep = G.evaluate(M.load(m), "probe", {"small": _ran("small", {"a": "1"})})
    details = [g.detail for g in rep.gaps if g.kind == "threshold"]
    assert len(details) == 2 and all("no specimen that ran is above it" in d for d in details)
    LB.specimen(m, "probe", "big", [LB.q("b")], {"x": b"a" * 50, "y": b"b" * 51})    # total 101, member 51
    rep = G.evaluate(M.load(m), "probe", {"small": _ran("small", {"a": "1"}), "big": _ran("big", {"b": "1"})})
    assert [g.detail for g in rep.gaps] == [
        "member (60 bytes, member): no specimen that ran is above it; build one with "
        "`python -m ctf lookahead scale`"]


def test_a_threshold_reached_only_from_above_still_needs_one_below(tmp_path):
    m = _lane(tmp_path, threshold=[{"name": "t", "bytes": 10}])
    LB.specimen(m, "probe", "big", [LB.q("a")], {"x": b"a" * 11})
    rep = G.evaluate(M.load(m), "probe", {"big": _ran("big", {"a": "1"})})
    assert [g.detail.split(":")[1].strip() for g in rep.gaps] == ["no specimen that ran is at or below it; build one with `python -m ctf lookahead scale`"]
    LB.specimen(m, "probe", "edge", [LB.q("b")], {"x": b"a" * 10})                 # exactly at: below side
    rep = G.evaluate(M.load(m), "probe", {"big": _ran("big", {"a": "1"}), "edge": _ran("edge", {"b": "1"})})
    assert rep.ok


def test_a_skipped_specimen_does_not_cross_a_threshold(tmp_path):
    m = _lane(tmp_path, threshold=[{"name": "t", "bytes": 10}])
    LB.specimen(m, "probe", "small", [LB.q("a")], {"x": b"a"})
    LB.specimen(m, "probe", "big", [LB.q("b")], {"x": b"a" * 20}, skip="too slow")
    rep = G.evaluate(M.load(m), "probe", {"small": _ran("small", {"a": "1"}),
                                          "big": G.SpecimenRun("big", G.SKIPPED, "declared skip")})
    assert _kinds(rep) == ["skipped", "threshold"]


# -------------------------------------------------------------------------------- encodings

PAYLOAD = b"the stated payload of a synthetic delivery\n"


@pytest.mark.parametrize("chain, encoded", [
    (("raw",), PAYLOAD),
    (("base64",), base64.b64encode(PAYLOAD)),
    (("base64url",), base64.urlsafe_b64encode(b"\xfb\xff" + PAYLOAD).rstrip(b"=")),
    (("base32",), base64.b32encode(PAYLOAD)),
    (("hex",), PAYLOAD.hex().encode() + b"\n"),
    (("zlib",), zlib.compress(PAYLOAD)),
    (("gzip",), gzip.compress(PAYLOAD, mtime=0)),  # mtime=0: a default header stamps the wall clock into the parametrize id (SH-07 / R-01)
    (("bz2",), bz2.compress(PAYLOAD)),
    (("xz",), lzma.compress(PAYLOAD)),
    (("utf-16le",), PAYLOAD.decode().encode("utf-16-le")),
    (("reverse",), PAYLOAD[::-1]),
    (("base64", "zlib"), LB.b64_zlib(PAYLOAD)),
    (("hex", "reverse", "base64"), base64.b64encode(PAYLOAD)[::-1].hex().encode()),
])
def test_each_codec_decodes_a_real_encoding(chain, encoded):
    want = b"\xfb\xff" + PAYLOAD if chain == ("base64url",) else PAYLOAD
    assert M.decode_chain(chain, encoded) == want


@pytest.mark.parametrize("chain, data, where", [
    (("base64",), PAYLOAD, "layer 1 of base64"),
    (("hex",), b"abc", "layer 1 of hex"),
    (("zlib",), PAYLOAD, "layer 1 of zlib"),
    (("zlib",), zlib.compress(PAYLOAD) + b"trailer", "after the stream"),
    (("zlib",), zlib.compress(PAYLOAD)[:-3], "truncated"),
    (("gzip",), zlib.compress(PAYLOAD), "layer 1 of gzip"),
    (("bz2",), PAYLOAD, "layer 1 of bz2"),
    (("xz",), PAYLOAD, "layer 1 of xz"),
    (("utf-16le",), b"abc", "odd length"),
    (("base64", "zlib"), base64.b64encode(PAYLOAD), "layer 2 of base64+zlib"),
    (("base64url",), b"ab+/", "layer 1 of base64url"),
])
def test_a_chain_that_does_not_hold_names_its_layer(chain, data, where):
    with pytest.raises(M.EncodingMismatch, match=where.replace("+", r"\+")):
        M.decode_chain(chain, data)


def test_unknown_codecs_and_raw_in_a_chain_are_errors():
    with pytest.raises(LookaheadError, match="codec 'rot47' is not known"):
        M.decode_chain(("rot47",), b"x")
    with pytest.raises(LookaheadError, match="'raw' stands alone"):
        M.decode_chain(("raw", "base64"), b"x")


def test_a_substituted_encoding_is_a_gap(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "honest", [LB.q("a")], {"d.bin": LB.b64_zlib(PAYLOAD)}, encoding=("base64", "zlib"))
    LB.specimen(m, "probe", "fake", [LB.q("b")], {"d.bin": base64.b64encode(PAYLOAD)}, encoding=("base64", "zlib"))
    LB.specimen(m, "probe", "mixed", [LB.q("c")], {"d.bin": base64.b64encode(PAYLOAD), "e.txt": b"plain"},
                encoding=("base64",), encodings={"e.txt": ["raw"]})
    rep = G.evaluate(M.load(m), "probe", {n: _ran(n, {k: "1"}) for n, k in (("honest", "a"), ("fake", "b"),
                                                                             ("mixed", "c"))})
    assert [(g.kind, g.specimen) for g in rep.gaps] == [("bad_encoding", "fake")]
    assert "member d.bin: layer 2 of base64+zlib" in rep.gaps[0].detail


def test_every_real_encoding_must_be_exercised(tmp_path):
    m = _lane(tmp_path, real_encodings=[["base64"], ["hex", "reverse"]])
    LB.specimen(m, "probe", "b64", [LB.q("a")], {"d": base64.b64encode(PAYLOAD)}, encoding=("base64",))
    rep = G.evaluate(M.load(m), "probe", {"b64": _ran("b64", {"a": "1"})})
    assert [(g.kind, g.detail) for g in rep.gaps] == [
        ("unexercised_encoding", "real deliveries use hex+reverse; no specimen that ran does")]
    LB.specimen(m, "probe", "hexrev", [LB.q("b")], {"d": PAYLOAD[::-1].hex().encode()}, encoding=("hex", "reverse"))
    rep = G.evaluate(M.load(m), "probe", {"b64": _ran("b64", {"a": "1"}), "hexrev": _ran("hexrev", {"b": "1"})})
    assert rep.ok


@pytest.mark.parametrize("status", [G.CRASHED, G.CUT])
def test_a_specimen_that_did_not_finish_does_not_exercise_its_encoding(tmp_path, status):
    m = _lane(tmp_path, real_encodings=[["base64"]])
    LB.specimen(m, "probe", "plain", [LB.q("a")], {"d": PAYLOAD})
    LB.specimen(m, "probe", "b64", [LB.q("b")], {"d": base64.b64encode(PAYLOAD)}, encoding=("base64",))
    rep = G.evaluate(M.load(m), "probe", {"plain": _ran("plain", {"a": "1"}),
                                          "b64": G.SpecimenRun("b64", status, "stopped")})
    assert [(g.kind, g.detail) for g in rep.gaps if g.kind != status] == [
        ("unexercised_encoding", "real deliveries use base64; no specimen that ran does")]


# ---------------------------------------------------------------------- the computed tier hint


def test_an_id_only_the_computed_tier_answers_is_still_a_gap_with_its_value_shown(tmp_path):
    m = _lane(tmp_path)
    text = "How many members are in the delivered evidence set?"
    LB.specimen(m, "probe", "s", [LB.q("d28_member_count", "integer", text), LB.q("other")],
                {"a": b"1", "b": b"2", "c": b"3"}, key={"d28_member_count": 3})
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {"other": "x"})})
    assert [(g.kind, g.qid) for g in rep.gaps] == [("unanswered", "d28_member_count")]
    assert "the computed tier has '3'" in rep.gaps[0].detail and "disagrees" not in rep.gaps[0].detail
    assert {r.qid: r.computed for r in rep.rows} == {"d28_member_count": 3, "other": None}
    assert rep.counts()["computed_ready"] == 1


def test_a_computed_value_that_disagrees_with_the_key_is_named(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("n", "integer", "How many files are in the delivery")],
                {"a": b"1"}, key={"n": 2})
    rep = G.evaluate(M.load(m), "probe", {"s": _ran("s", {})})
    assert "it disagrees with the key '2'" in rep.gaps[0].detail


# ------------------------------------------------------------------------------ loading errors


@pytest.mark.parametrize("toml, msg", [
    ('[lane.probe]\nreader = "r.py"\ncolour = "red"\n', "unknown key"),
    ('[lane.probe]\njudged = ["x"]\n', "reader"),
    ('[lane.probe]\nreader = "r.py"\ntimeout = 0\n', "timeout must be a positive"),
    ('[lane.probe]\nreader = "r.py"\n[[lane.probe.threshold]]\nname = "t"\nbytes = 10\nmeasure = "avg"\n', "measure 'avg'"),
    ('[lane.probe]\nreader = "r.py"\n[[lane.probe.threshold]]\nname = "t"\nbytes = 0\n', "integer >= 1"),
    ('[lane.probe]\nreader = "r.py"\nreal_encodings = [["base64", "rot47"]]\n', "codec 'rot47'"),
    ('[lane.probe]\nreader = "r.py"\n[[skipped]]\nlane = "other"\nname = "n"\nreason = "r"\n', "lane 'other' is not declared"),
    ('[lane.probe]\nreader = "r.py"\n[[skipped]]\nlane = "probe"\nname = "n"\n', "reason is required"),
    ('[lane.probe]\nreader = "r.py"\n[[waived_threshold]]\nbytes = 10\n', "needs its reason"),
    ('[lane.Probe]\nreader = "r.py"\n', "lower-case"),
    ('', "no [lane.<name>] table"),
])
def test_matrix_toml_errors_are_loud(tmp_path, toml, msg):
    m = tmp_path / "matrix"
    m.mkdir()
    (m / "matrix.toml").write_text(toml)
    with pytest.raises(LookaheadError, match=re.escape(msg)):
        M.load(m)


@pytest.mark.parametrize("make, msg", [
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a")], raw_toml="note = 'x'\n"), "encoding is required"),
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a")], raw_toml='encoding = ["raw"]\nmode = 1\n'), "unknown key"),
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a")], key={"zzz": 1}), "answers id(s) no question asks: zzz"),
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a"), LB.q("a")]), "id 'a' is asked twice"),
    (lambda m: LB.specimen(m, "probe", "s", [{"question": "no id"}]), "question #1 has no id"),
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a")], {}), "no member under files/"),
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a")], encodings={"ghost": ["raw"]}), "not under files/: ghost"),
    (lambda m: LB.specimen(m, "probe", "s", [LB.q("a")], encoding=("raw", "hex")), "'raw' stands alone"),
    (lambda m: LB.specimen(m, "other", "s", [LB.q("a")]), "lane 'other', which matrix.toml does not declare"),
])
def test_specimen_errors_are_loud(tmp_path, make, msg):
    m = _lane(tmp_path)
    make(m)
    with pytest.raises(LookaheadError, match=re.escape(msg)):
        M.load(m)


def test_a_folder_without_specimen_toml_under_a_lane_is_an_error(tmp_path):
    m = _lane(tmp_path)
    (m / "probe" / "stray").mkdir(parents=True)
    with pytest.raises(LookaheadError, match="no specimen.toml"):
        M.load(m)


def test_a_symlinked_member_is_refused(tmp_path):
    m = _lane(tmp_path)
    d = LB.specimen(m, "probe", "s", [LB.q("a")])
    (d / "files" / "link").symlink_to(d / "files" / "a.txt")
    with pytest.raises(LookaheadError, match="is a symlink"):
        M.load(m)


# ------------------------------------------------------------------- the reader, for real


def _probe_matrix(tmp_path, **lane):
    reader = LB.write_reader(tmp_path)
    return LB.matrix(tmp_path, {"probe": {"reader": reader, "timeout": 2, **lane}})


def test_run_lane_runs_the_reader_on_the_real_files(tmp_path):
    m = _probe_matrix(tmp_path)
    LB.specimen(m, "probe", "s1", [LB.q("x_total_size", "integer"), LB.q("name"), LB.q("open")],
                {"a.txt": b"hello", "sub/b.txt": b"abc"}, key={"x_total_size": 8, "name": "n"},
                ctx={"answers": {"name": "n"}})
    runs = G.run_lane(M.load(m), "probe", root=ROOT, guard="hook", workdir=tmp_path / "wd")
    assert runs["s1"].status == G.RAN and runs["s1"].answers == {"x_total_size": 8, "name": "n", "open": None}
    rep = G.evaluate(M.load(m), "probe", runs)
    assert {r.qid: r.status for r in rep.rows} == {"x_total_size": "correct", "name": "correct", "open": "unanswered"}
    assert [(g.kind, g.qid) for g in rep.gaps] == [("unanswered", "open")]
    assert list((tmp_path / "wd").iterdir()) == []                     # run folders removed


def test_a_raising_hanging_or_non_dict_reader_is_named_and_the_rest_still_run(tmp_path):
    m = _probe_matrix(tmp_path, timeout=1)
    LB.specimen(m, "probe", "a_raise", [LB.q("x")], ctx={"mode": "raise"})
    LB.specimen(m, "probe", "b_hang", [LB.q("y")], ctx={"mode": "hang"})
    LB.specimen(m, "probe", "c_nondict", [LB.q("z")], ctx={"mode": "nondict"})
    LB.specimen(m, "probe", "d_fine", [LB.q("w_total_size", "integer")])
    runs = G.run_lane(M.load(m), "probe", root=ROOT, guard="hook")
    assert {n: r.status for n, r in runs.items()} == {"a_raise": "crashed", "b_hang": "cut",
                                                       "c_nondict": "crashed", "d_fine": "ran"}
    assert runs["a_raise"].reason.startswith("RuntimeError: reader broke at probe_reader.py:")
    assert runs["b_hang"].reason == "cut at the 1s cap" and runs["b_hang"].answers == {"partial_id": "p"}
    assert "returned list, not a dict" in runs["c_nondict"].reason
    assert runs["d_fine"].answers == {"w_total_size": 5}


def test_a_reader_that_kills_its_process_leaves_later_specimens_not_reached(tmp_path):
    m = _probe_matrix(tmp_path)
    LB.specimen(m, "probe", "a_ok", [LB.q("a_total_size")])
    LB.specimen(m, "probe", "b_exit", [LB.q("b")], ctx={"mode": "exit"})
    LB.specimen(m, "probe", "c_after", [LB.q("c")])
    runs = G.run_lane(M.load(m), "probe", root=ROOT, guard="hook")
    assert runs["a_ok"].status == G.RAN
    assert runs["b_exit"].status == G.CRASHED and "reader process exited 7" in runs["b_exit"].reason
    assert runs["c_after"].status == G.SKIPPED and runs["c_after"].reason.startswith("not reached")
    rep = G.evaluate(M.load(m), "probe", runs)
    assert [(g.kind, g.specimen) for g in rep.gaps] == [("crashed", "b_exit"), ("skipped", "c_after")]


def test_a_reader_that_does_not_load_is_an_error(tmp_path):
    reader = LB.write_reader(tmp_path, "broken.py", "def other():\n    pass\n")
    m = LB.matrix(tmp_path, {"probe": {"reader": reader}})
    LB.specimen(m, "probe", "s", [LB.q("a")])
    with pytest.raises(LookaheadError, match="does not load: AttributeError"):
        G.run_lane(M.load(m), "probe", root=ROOT, guard="hook")
    missing = LB.matrix(tmp_path, {"probe": {"reader": "solvers/no/such_reader.py"}}, name="m2")
    LB.specimen(missing, "probe", "s", [LB.q("a")])
    with pytest.raises(LookaheadError, match="is not a file under"):
        G.run_lane(M.load(missing), "probe", root=ROOT, guard="hook")


def test_declared_skips_are_not_sent_to_the_reader(tmp_path):
    m = _probe_matrix(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("a")], skip="not built", ctx={"mode": "exit"})
    runs = G.run_lane(M.load(m), "probe", root=ROOT, guard="hook")
    assert runs == {"s": G.SpecimenRun("s", G.SKIPPED, "declared skip: not built")}


def test_the_reader_cannot_reach_the_network(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(0.5)
    hits = []

    def accept():
        try:
            c, _ = srv.accept()
            hits.append(c.recv(10))
        except OSError:
            pass
    t = threading.Thread(target=accept)
    t.start()
    try:
        m = _probe_matrix(tmp_path)
        LB.specimen(m, "probe", "s", [LB.q("a")], ctx={"mode": "net", "port": srv.getsockname()[1]})
        runs = G.run_lane(M.load(m), "probe", root=ROOT, guard="hook")
    finally:
        t.join()
        srv.close()
    assert runs["s"].status == G.CRASHED and "intake network guard" in runs["s"].reason
    assert hits == []


def test_the_reader_sees_no_secret_and_no_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_TOKEN", "do-not-pass")
    m = _probe_matrix(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("secret_seen"), LB.q("ledger_env")], ctx={"mode": "env"})
    runs = G.run_lane(M.load(m), "probe", root=ROOT, guard="hook")
    assert runs["s"].answers == {"secret_seen": None, "ledger_env": "0"}


def test_gate_records_one_ledger_row_per_lane_and_refuses_unknown_lanes(tmp_path):
    reader = LB.write_reader(tmp_path)
    m = LB.matrix(tmp_path, {"one": {"reader": reader}, "two": {"reader": reader}})
    LB.specimen(m, "one", "s", [LB.q("a_total_size")])
    LB.specimen(m, "two", "s", [LB.q("b")])
    wd = tmp_path / "wd"
    reps = G.gate(m, root=ROOT, workdir=wd, guard="hook")
    assert [(r.lane, r.verdict) for r in reps] == [("one", "green"), ("two", "red")]
    recs = [r for r in ledger.read(wd) if r["event"] == "lookahead.gate"]
    assert [(r["lane"], r["verdict"], r["unanswered"], r["gaps"], r["ran"]) for r in recs] == [
        ("one", "green", 0, 0, 1), ("two", "red", 1, 1, 1)]
    only = G.gate(m, ["two"], root=ROOT, workdir=wd, guard="hook", record_to_ledger=False)
    assert [r.lane for r in only] == ["two"]
    assert len([r for r in ledger.read(wd) if r["event"] == "lookahead.gate"]) == 2
    with pytest.raises(LookaheadError, match="lane\\(s\\) three not in"):
        G.gate(m, ["three"], root=ROOT, workdir=wd, guard="hook")


def test_report_json_carries_rows_gaps_and_counts(tmp_path):
    m = _lane(tmp_path)
    LB.specimen(m, "probe", "s", [LB.q("a"), LB.q("b")], key={"a": "1"})
    body = G.evaluate(M.load(m), "probe", {"s": _ran("s", {"a": "1"})}).to_json()
    assert body["verdict"] == "red" and body["counts"]["correct"] == 1
    assert body["gaps"] == [{"kind": "unanswered", "lane": "probe", "specimen": "s", "qid": "b",
                             "detail": "deterministic and unanswered"}]
    assert [r["status"] for r in body["rows"]] == ["correct", "unanswered"]
