"""B-174: the computed-field tier, size thresholds and scale specimens, forecast scoring and the agent plan
(ctf.lookahead.computed, ctf.lookahead.scale, ctf.lookahead.forecast). All inputs are synthetic."""
from __future__ import annotations

import hashlib
import json
import re

import pytest

from ctf import ledger
from ctf.lookahead import LookaheadError
from ctf.lookahead import computed as C
from ctf.lookahead import forecast as F
from ctf.lookahead import gate as G
from ctf.lookahead import matrix as M
from ctf.lookahead import scale as S

import lookahead_build as LB

FILES = {"evidence/zeta.bin": b"\x00\x01zeta", "evidence/alpha.txt": b"alpha text", "beta.cfg": b"k=v\n"}


# ----------------------------------------------------------------------------- the computed tier


def test_member_count_and_size():
    assert C.answer(LB.q("n", "integer", "How many members are in the delivered evidence set?"), FILES) == 3
    assert C.answer(LB.q("n", "integer", "how many FILES were delivered in the delivery"), FILES) == 3
    assert C.answer(LB.q("s", "integer", "What is the size in bytes of member `alpha.txt`?"), FILES) == 10
    assert C.answer(LB.q("s", "integer", "What is the size in bytes of the file 'beta.cfg'"), FILES) == 4


@pytest.mark.parametrize("algo, fn", [("md5", hashlib.md5), ("SHA-1", hashlib.sha1), ("sha256", hashlib.sha256)])
def test_member_digest(algo, fn):
    q = LB.q("d", "pattern", f'What is the {algo} of member "zeta.bin"?')
    assert C.answer(q, FILES) == fn(b"\x00\x01zeta").hexdigest()


def test_digest_of_digests_in_name_order_with_and_without_newlines():
    order = [b"alpha text", b"k=v\n", b"\x00\x01zeta"]              # alpha.txt, beta.cfg, zeta.bin
    parts = [hashlib.md5(x).hexdigest() for x in order]
    q = LB.q("dd", "exact_text", "What is the SHA-256 of the concatenation of the members' MD5 hex digests "
                                 "in name order?")
    assert C.answer(q, FILES) == hashlib.sha256("".join(parts).encode()).hexdigest()
    qn = LB.q("dd", "exact_text", "What is the sha256 of the concatenation of the members' md5 hex digests "
                                  "in name order, separated by newlines")
    assert C.answer(qn, FILES) == hashlib.sha256("\n".join(parts).encode()).hexdigest()


@pytest.mark.parametrize("question", [
    LB.q("n", "exact_text", "How many members are in the delivered evidence set?"),        # not an integer kind
    LB.q("s", "integer", "What is the size in bytes of member `missing.bin`?"),             # no such member
    LB.q("d", "pattern", "What is the sha512 of member `zeta.bin`?"),                       # algo not known
    LB.q("d", "integer", "What is the md5 of member `zeta.bin`?"),                          # digest as integer
    LB.q("n", "integer", "How many members are in the delivered evidence set, excluding decoys?"),  # near miss
    {"id": "d", "question": "What is the md5 of member `zeta.bin`?",
     "answer_format": {"kind": "pattern", "syntax": "UPPERCASE hexadecimal"}},           # a spelling it won't guess
    {"id": "d", "question": "What is the md5 of member `zeta.bin`?",
     "answer_format": {"kind": "pattern", "syntax": "hexadecimal with a 0x prefix"}},
    LB.q("x", "exact_text", "What is the campaign?"),
])
def test_the_tier_does_not_answer_what_it_cannot_compute_exactly(question):
    assert C.answer(question, FILES) is None


def test_ambiguous_member_names_are_not_answered():
    dup = {"set1/a.bin": b"1", "set2/a.bin": b"22"}
    assert C.answer(LB.q("s", "integer", "What is the size in bytes of member `a.bin`"), dup) is None
    q = LB.q("dd", "exact_text", "What is the md5 of the concatenation of the files' md5 hex digests in name order")
    assert C.answer(q, dup) is None
    assert C.answer(LB.q("n", "integer", "How many members are in the delivery"), {}) is None


def test_fill_never_overrides_and_wrap_puts_the_tier_behind_the_lane():
    qs = [LB.q("n", "integer", "How many members are in the delivery"),
          LB.q("s", "integer", "What is the size in bytes of member `beta.cfg`"),
          LB.q("other")]
    out, filled = C.fill(qs, FILES, {"n": 99, "s": None})
    assert out == {"n": 99, "s": 4}
    assert filled == ["s"]
    # a blank-text answer is unanswered to the gate (gate.classify), so the tier fills it too
    for blank in ("", "  \n"):
        out, filled = C.fill(qs, FILES, {"n": blank, "s": "0"})
        assert out == {"n": 3, "s": "0"} and filled == ["n"]
    assert C.fill(qs, FILES, {"n": 0, "s": False})[0] == {"n": 0, "s": False}   # falsy, not empty

    calls = []

    def lane(questions, files, ctx):
        calls.append(ctx)
        return {"n": 7, "s": None, "other": None}
    wrapped = C.wrap(lane)
    assert wrapped(qs, FILES, {"k": 1}) == {"n": 7, "s": 4, "other": None}
    assert calls == [{"k": 1}] and wrapped.__wrapped__ is lane


def test_a_lane_that_wraps_the_tier_closes_the_gap(tmp_path):
    reader = LB.write_reader(tmp_path, "wrapped.py", LB.READER.replace("def solve_set", "def _inner") + (
        "\nfrom ctf.lookahead import computed as _c\nsolve_set = _c.wrap(_inner)\n"))
    m = LB.matrix(tmp_path, {"probe": {"reader": reader}})
    LB.specimen(m, "probe", "s", [LB.q("count", "integer", "How many members are in the delivery")],
                {"a": b"1", "b": b"2"}, key={"count": 2})
    LB.specimen(m, "probe", "blank", [LB.q("count", "integer", "How many members are in the delivery")],
                {"a": b"1", "b": b"2", "c": b"3"}, key={"count": 3}, ctx={"answers": {"count": " "}})
    rep = G.gate(m, workdir=tmp_path / "wd", guard="hook", record_to_ledger=False)[0]
    assert rep.ok and [(r.specimen, r.status) for r in rep.rows] == [("blank", "correct"), ("s", "correct")]


# ------------------------------------------------------------------------------ thresholds


CODE = '''
SIBLINGS_MAX = 1024 * 1024
MAX_LITERAL = 256 * 1024
_CHUNK_BYTES: int = 1 << 16
SMALL_CAP = 512
RETRIES = 5000
lower_limit = 9999
NOT_A_SIZE = "x"

def f(data):
    if len(data) > 262144:
        return 1
    if 4096 <= len(data):
        return 2
    if len(data) < 10:
        return 3
'''


def test_scan_finds_size_constants_and_len_comparisons(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "runner.py").write_text(CODE)
    (tmp_path / "pkg" / ".hidden").mkdir()
    (tmp_path / "pkg" / ".hidden" / "x.py").write_text("HIDDEN_MAX = 99999\n")
    found = S.scan([tmp_path / "pkg"], root=tmp_path)
    got = sorted((f.name, f.bytes, f.how, f.path) for f in found)
    assert got == [("MAX_LITERAL", 262144, "constant", "pkg/runner.py"),
                   ("SIBLINGS_MAX", 1048576, "constant", "pkg/runner.py"),
                   ("_CHUNK_BYTES", 65536, "constant", "pkg/runner.py"),
                   ("len()", 4096, "len-compare", "pkg/runner.py"),
                   ("len()", 262144, "len-compare", "pkg/runner.py")]
    assert found[0].line_text().startswith("pkg/runner.py:")


def test_scan_refuses_what_it_cannot_read(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    with pytest.raises(LookaheadError, match="does not parse"):
        S.scan([tmp_path])
    with pytest.raises(LookaheadError, match="no such file or folder"):
        S.scan([tmp_path / "nope"])


def test_undeclared_thresholds_by_value_and_waiver_glob(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("SIBLINGS_MAX = 1048576\nMAX_LITERAL = 262144\nREGEX_CAP = 65536\n")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "b.py").write_text("OTHER_CAP = 65536\n")
    m = LB.matrix(tmp_path, {"warmups": {"reader": "r.py", "threshold": [{"name": "siblings", "bytes": 1048576}]}},
                  waived=[{"bytes": 65536, "reason": "a regex bound", "where": "src/*"}])
    found = S.scan([tmp_path / "src", tmp_path / "lib"], root=tmp_path)
    left = S.undeclared(found, M.load(m))
    assert sorted((f.name, f.path) for f in left) == [("MAX_LITERAL", "src/a.py"), ("OTHER_CAP", "lib/b.py")]


def test_replicate_builds_a_multi_set_specimen_past_the_size(tmp_path):
    m = LB.matrix(tmp_path, {"warmups": {"reader": "r.py"}})
    src = LB.specimen(m, "warmups", "one", [LB.q("slug"), LB.q("x_total_size", "integer")],
                      {"blob.txt": LB.b64_zlib(b"slug-one\n" * 4)}, encoding=("base64", "zlib"),
                      key={"slug": "slug-one"}, ctx={"mode": "answer", "level": 3})
    one = M.load_specimen("warmups", src)
    out = S.replicate(src, m / "warmups" / "scaled", 3 * one.total_bytes + 1)
    big = M.load_specimen("warmups", out)
    assert big.total_bytes > 3 * one.total_bytes + 1 and len(big.sizes) == 4
    assert sorted(big.sizes) == [f"set{n}/blob.txt" for n in range(1, 5)]
    assert [M.qid_of(q) for q in big.questions][:2] == ["set1.slug", "set1.x_total_size"]
    assert big.key == {f"set{n}.slug": "slug-one" for n in range(1, 5)}
    assert set(big.encodings.values()) == {("base64", "zlib")} and M.bad_encodings(big) == []
    assert big.ctx == {"mode": "answer", "level": 3}
    assert "4 sets of one" in big.note


def test_replicate_makes_at_least_two_sets_and_crosses_a_threshold_the_gate_checks(tmp_path):
    reader = LB.write_reader(tmp_path)
    m = LB.matrix(tmp_path, {"probe": {"reader": reader, "threshold": [{"name": "siblings", "bytes": 1000}]}})
    src = LB.specimen(m, "probe", "small", [LB.q("x_total_size", "integer")], {"a.txt": b"a" * 300})
    rep = G.gate(m, workdir=tmp_path / "wd", guard="hook", record_to_ledger=False)[0]
    assert [g.kind for g in rep.gaps] == ["threshold"]
    S.replicate(src, m / "probe" / "scaled", 1000)
    rep = G.gate(m, workdir=tmp_path / "wd", guard="hook", record_to_ledger=False)[0]
    assert rep.ok, rep.lines()
    assert M.load_specimen("probe", m / "probe" / "scaled").total_bytes == 1200
    tiny = S.replicate(src, tmp_path / "tiny", 1)
    assert len(M.load_specimen("probe", tiny).sizes) == 2


def test_replicate_refusals(tmp_path):
    m = LB.matrix(tmp_path, {"probe": {"reader": "r.py"}})
    pre = LB.specimen(m, "probe", "pre", [LB.q("set1.a")])
    with pytest.raises(LookaheadError, match="already carry a set prefix"):
        S.replicate(pre, tmp_path / "o1", 100)
    sk = LB.specimen(m, "probe", "sk", [LB.q("a")], skip="later")
    with pytest.raises(LookaheadError, match="nothing to replicate"):
        S.replicate(sk, tmp_path / "o2", 100)
    ok = LB.specimen(m, "probe", "ok", [LB.q("a")])
    (tmp_path / "taken").mkdir()
    with pytest.raises(LookaheadError, match="already exists"):
        S.replicate(ok, tmp_path / "taken", 100)
    with pytest.raises(LookaheadError, match="positive integer"):
        S.replicate(ok, tmp_path / "o3", 0)
    nested = LB.specimen(m, "probe", "nested", [LB.q("a")], ctx={"t": {"k": 1}})
    with pytest.raises(LookaheadError, match="ctx.t is a table"):
        S.replicate(nested, tmp_path / "o4", 100)
    assert not (tmp_path / "o4").exists()


# --------------------------------------------------------------------------------- forecasts


PREV = {"questions": [LB.q("d27_a"), LB.q("d27_b", "integer"), LB.q("old_gone")]}
DAY = {"questions": [LB.q("d27_a"), LB.q("d27_b", "exact_text"), LB.q("set1.d28_count", "integer"),
                     LB.q("set2.d28_count", "integer"), LB.q("d28_gpt_lba"), {**LB.q("d27_a"), "id": "d27_c",
                                                                             "question": "reworded only"}]}


def _forecast(tmp_path, text):
    p = tmp_path / "forecast.toml"
    p.write_text(text)
    return F.load(p)


def test_score_names_hits_misses_and_unused_globs(tmp_path):
    fc = _forecast(tmp_path, 'day = "d28"\n[lane.binary]\nnew = ["d28_*count", "d28_symbol_*"]\n')
    s = F.score(fc, "binary", PREV, DAY, workdir=tmp_path)
    assert s.new == ("d27_b", "d27_c", "d28_count", "d28_gpt_lba")       # kind change and adds; removed not counted
    assert s.hit == ("d28_count",) and s.missed == ("d27_b", "d27_c", "d28_gpt_lba")
    assert s.unused == ("d28_symbol_*",) and s.recall == 0.25
    (rec,) = [r for r in ledger.read(tmp_path) if r["event"] == "lookahead.score"]
    assert {k: rec[k] for k in ("lane", "day", "new", "hit", "missed", "unused", "recall")} == {
        "lane": "binary", "day": "d28", "new": 4, "hit": 1, "missed": 3, "unused": 1, "recall": 0.25}
    assert "gap_ids" not in rec
    assert s.lines()[0] == "FORECAST binary d28: 1/4 new id(s) named, recall 25%; 1 glob(s) matched nothing"


def test_score_against_the_day_report_names_release_gaps_the_forecast_missed(tmp_path):
    fc = _forecast(tmp_path, '[lane.binary]\nnew = ["d28_*"]\ngaps = ["d28_count"]\n')
    report = {"lane": "binary", "gaps": [
        {"kind": "unanswered", "qid": "set1.d28_count"}, {"kind": "unanswered", "qid": "set2.d28_count"},
        {"kind": "wrong", "qid": "d28_gpt_lba"}, {"kind": "uncovered", "qid": "d28_new_field"},
        {"kind": "unsure", "qid": "set3.d28_mbr_sig"},
        {"kind": "skipped", "qid": "", "specimen": "s"}]}
    s = F.score(fc, "binary", PREV, DAY, report=report, workdir=tmp_path)
    assert s.gap_ids == ("d28_count", "d28_gpt_lba", "d28_mbr_sig", "d28_new_field")
    assert s.gap_missed == ("d28_gpt_lba", "d28_mbr_sig", "d28_new_field")
    (rec,) = [r for r in ledger.read(tmp_path) if r["event"] == "lookahead.score"]
    assert (rec["gap_ids"], rec["gap_missed"]) == (4, 3)
    with pytest.raises(LookaheadError, match="report is for lane 'web'"):
        F.score(fc, "binary", PREV, DAY, report={"lane": "web", "gaps": []}, record=False)


def test_nothing_new_has_no_recall_and_record_false_writes_nothing(tmp_path):
    fc = _forecast(tmp_path, '[lane.binary]\nnew = ["x"]\n')
    s = F.score(fc, "binary", PREV, PREV, workdir=tmp_path, record=False)
    assert s.new == () and s.recall is None and "n/a" in s.lines()[0]
    assert not ledger.path(tmp_path).exists()


@pytest.mark.parametrize("text, msg", [
    ('[lane.binary]\nnew = "d28_*"\n', "new is a list of id globs"),
    ('[lane.binary]\nwhen = 1\n', "unknown key(s) when"),
    ('nope = 1\n[lane.binary]\n', "unknown key(s) nope"),
    ('day = "d28"\n', "no [lane.<name>] table"),
    ('[lane', "not readable TOML"),
])
def test_forecast_file_errors(tmp_path, text, msg):
    p = tmp_path / "f.toml"
    p.write_text(text)
    with pytest.raises(LookaheadError, match=re.escape(msg)):
        F.load(p)


def test_score_refuses_a_lane_the_forecast_does_not_name(tmp_path):
    fc = _forecast(tmp_path, '[lane.binary]\nnew = ["x"]\n')
    with pytest.raises(LookaheadError, match="no \\[lane.web\\]"):
        F.score(fc, "web", PREV, DAY, record=False)


def test_plan_runs_an_agent_only_for_a_new_shape_or_an_open_gap():
    green = {"lane": "script", "gaps": []}
    red = {"lane": "binary", "gaps": [{"kind": "unanswered", "qid": "x"}, {"kind": "skipped", "qid": ""}]}
    plans = {p.lane: p for p in F.plan([green, red, {"lane": "mobile", "gaps": []}, {"lane": "metadata", "gaps": []}],
                                       {"script": (PREV, PREV), "binary": (PREV, PREV), "mobile": (PREV, DAY),
                                        "warmups": (PREV, PREV), "metadata": None})}
    assert {k: p.agent for k, p in plans.items()} == {"script": False, "binary": True, "mobile": True,
                                                      "warmups": True, "metadata": True}
    assert plans["script"].reasons == ("gate green", "shape unchanged")
    assert plans["binary"].reasons[0] == "2 open gap(s) (skipped, unanswered)"
    assert plans["mobile"].reasons[1].startswith("new shape: 4 changed id(s)")
    assert plans["warmups"].reasons[0] == "no gate report: coverage unknown"
    assert plans["metadata"].reasons == ("gate green", "shape unknown: no previous base to compare")
    assert plans["script"].line() == "none  script: gate green; shape unchanged"


def test_plan_accepts_lane_reports_as_objects(tmp_path):
    m = LB.matrix(tmp_path, {"probe": {"reader": "r.py"}})
    LB.specimen(m, "probe", "s", [LB.q("a")])
    rep = G.evaluate(M.load(m), "probe", {"s": G.SpecimenRun("s", G.RAN, "", {"a": "1"})})
    (p,) = F.plan([rep], {"probe": (PREV, PREV)})
    assert p.agent is False
    assert json.loads(json.dumps(rep.to_json()))["lane"] == "probe"
