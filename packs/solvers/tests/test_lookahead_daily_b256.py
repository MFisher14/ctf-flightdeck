"""B-256: the daily look-ahead's deterministic plumbing.

ctf.lookahead.tagged (tagged-copy containers per language, staged as matrix specimens), ctf.lookahead.fixtures
(computed-field specimens through real encodings), ctf.lookahead.daily (lanes from the profile and
forecast.plan, the workflow args, the missing-lane README and the scorable forecast) and
`python -m ctf lookahead-daily`. Every file, profile and matrix is synthetic and built in tmp_path.

The tagged-copy runtime tests run our own generated source (never a challenge file) under each language's
interpreter, so each container is proven to really carry the tagged copy; each is marked needs_tool for its
interpreter so it reports NOT RUN when that interpreter is absent.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import lookahead_build as LB
from ctf import cli, event
from ctf import workflows as wf
from ctf.lookahead import LookaheadError
from ctf.lookahead import computed, daily, fixtures, forecast, tagged
from ctf.lookahead import gate as G
from ctf.lookahead import matrix as M

TAG = "ZZ_ANALYSIS_V1"

RUNNERS = {
    "python": ([sys.executable, "-I"], None),
    "javascript": (["node"], "node"),
    "apps-script": (["node"], "node"),
    "powershell": (["pwsh", "-NoProfile", "-NonInteractive", "-File"], "pwsh"),
    "bash": (["bash"], "bash"),
    "php": (["php"], "php"),
    "ruby": (["ruby"], "ruby"),
    "perl": (["perl"], "perl"),
    "lua": (["lua"], "lua"),
}
RUN_EXT = {"apps-script": ".js"}      # node runs Apps Script source as .js


def _pairs(containers=tagged.CONTAINERS):
    out = []
    for fam, f in tagged.FAMILIES.items():
        for c in containers:
            if c in f.skip:
                continue
            tool = RUNNERS[fam][1]
            marks = [pytest.mark.needs_tool(tool)] if tool else []
            out.append(pytest.param(fam, c, marks=marks, id=f"{fam}-{c}"))
    return out


def profile(categories=("Web", "Binary", "Script Analysis", "Warmups"), daily_release="09:00", releases=()):
    allowance = {"releases": list(releases)}
    if daily_release:
        allowance["daily_release"] = daily_release
    return event.parse({
        "slug": "b256-test", "name": "B256 Test CTF",
        "categories": list(categories),
        "dates": {"start": dt.date(2027, 1, 1), "end": dt.date(2027, 1, 20)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": ["ZZ"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
        "allowance": allowance,
    }, src="<test>")


def profile_toml(tmp: Path, *, rolling=True) -> Path:
    p = tmp / "event.toml"
    p.write_text(
        'slug = "b256-test"\nname = "B256 Test CTF"\n'
        'categories = ["Web", "Binary", "Script Analysis", "Warmups"]\n'
        "dates = { start = 2027-01-01, end = 2027-01-20 }\n"
        '[platform]\nkind = "manual"\n[flag]\nprefixes = ["ZZ"]\n'
        '[rules]\nsubmit_mode = "manual"\nflag_sharing = "forbidden"\nai_on_platform = "allowed"\n'
        + ('[allowance]\ndaily_release = "09:00"\n' if rolling else ""), encoding="utf-8")
    return p


# ======================================================================================= tagged copies


@pytest.mark.parametrize("fam,container", _pairs([c for c in tagged.CONTAINERS if c != "comment"]))
def test_the_tagged_copy_is_really_carried_by_each_container(tmp_path, fam, container):
    """Run the generated source (ours, synthetic) and print the probe: it must evaluate to <TAG>-<payload>,
    and the untagged second copy to the payload."""
    rs = tagged.render(fam, container, TAG, seed=7)
    f = tagged.FAMILIES[fam]
    src = tmp_path / f"probe{RUN_EXT.get(fam, rs.ext)}"
    src.write_text(rs.text + f.print_stmt(rs.probe) + "\n" + f.print_stmt(rs.second) + "\n", encoding="utf-8")
    cmd = RUNNERS[fam][0]
    p = subprocess.run(cmd + [str(src)], capture_output=True, text=True, timeout=120, cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    assert p.stdout.split() == [rs.tagged, rs.payload]
    assert rs.tagged == f"{TAG}-{rs.payload}"


@pytest.mark.parametrize("fam", list(tagged.FAMILIES))
def test_where_the_tagged_copy_lives_differs_by_container(fam):
    f = tagged.FAMILIES[fam]
    for c in tagged.CONTAINERS:
        if c in f.skip:
            with pytest.raises(LookaheadError, match="not staged"):
                tagged.render(fam, c, TAG)
            continue
        rs = tagged.render(fam, c, TAG, seed=11)
        lines = rs.text.splitlines()
        body = lines[len(f.header):]
        comments = [ln for ln in body if ln.startswith(f.comment)]
        if c == "comment":           # the 2026 look-ahead shape: the tagged copy in a comment
            assert comments == [f"{f.comment} {rs.tagged}"] and rs.probe is None
        elif c == "no-comment":      # no comment at all
            assert comments == [] and rs.tagged in rs.text
        elif c == "marker-joined":   # a bare marker, never the payload, in the comment
            assert comments == [f"{f.comment} {TAG}:SPLIT"]
        else:
            assert comments == [f"{f.comment} {TAG}"], (c, comments)
        if c in ("marker-joined", "concat", "charcodes", "split-constants"):
            assert rs.tagged not in rs.text, c       # a reader must assemble it, not grep it
        else:
            assert rs.tagged in rs.text, c
        assert rs.payload in rs.text or c == "marker-joined"
        if c == "marker-joined":
            assert rs.payload not in rs.text         # the second copy is joined from other cuts


def test_render_is_deterministic_per_seed_and_tag():
    a = tagged.render("python", "concat", TAG, seed="d29")
    assert a == tagged.render("python", "concat", TAG, seed="d29")
    b = tagged.render("python", "concat", TAG, seed="d30")
    assert a.payload != b.payload
    c = tagged.render("python", "concat", "OTHER_TAG", seed="d29")
    assert c.tagged.startswith("OTHER_TAG-") and c.payload == a.payload


@pytest.mark.parametrize("bad", ["", None, "1TAG", "TAG-X", "T" * 65, "tag with space"])
def test_a_missing_or_malformed_tag_fails_loudly(bad):
    with pytest.raises(LookaheadError, match="no default tag"):
        tagged.render("python", "concat", bad)


def test_unknown_family_or_container_fails_loudly():
    with pytest.raises(LookaheadError, match="family 'cobol'"):
        tagged.render("cobol", "concat", TAG)
    with pytest.raises(LookaheadError, match="container 'zip'"):
        tagged.render("python", "zip", TAG)


def _matrix(tmp: Path, lanes=("script-analysis",), **lane_cfg):
    reader = LB.write_reader(tmp)
    return LB.matrix(tmp, {ln: {"reader": reader, **lane_cfg.get(ln.replace("-", "_"), {})} for ln in lanes})


def test_stage_writes_one_loadable_specimen_per_family_and_container(tmp_path):
    m = _matrix(tmp_path)
    names = tagged.stage(m, "script-analysis", TAG, seed="d29")
    expected = sum(len([c for c in tagged.CONTAINERS if c not in f.skip]) for f in tagged.FAMILIES.values())
    assert len(names) == expected == len(tagged.FAMILIES) * len(tagged.CONTAINERS) - len(tagged.NOT_APPLICABLE)
    assert ("bash", "property") in tagged.NOT_APPLICABLE and "tagged-bash-property" not in names
    loaded = {s.name: s for s in M.load(m).specimens["script-analysis"]}
    assert set(loaded) == set(names)
    s = loaded["tagged-perl-heredoc"]
    rs = tagged.render("perl", "heredoc", TAG, seed="d29")
    assert s.key == {"tagged_copy": rs.tagged}
    assert s.encodings == {"member.pl": ("raw",)}
    assert s.read_files() == {"member.pl": rs.text.encode()}
    assert [q["id"] for q in s.questions] == ["tagged_copy"]
    assert M.determinism(s.questions[0]) == M.DETERMINISTIC


def test_restaging_rewrites_its_own_specimens_but_refuses_a_foreign_folder(tmp_path):
    m = _matrix(tmp_path)
    tagged.stage(m, "script-analysis", TAG, seed="d29", families=["python"])
    first = (m / "script-analysis" / "tagged-python-concat" / "files" / "member.py").read_text()
    tagged.stage(m, "script-analysis", TAG, seed="d30", families=["python"])      # same day re-run: ours
    second = (m / "script-analysis" / "tagged-python-concat" / "files" / "member.py").read_text()
    assert first != second
    LB.specimen(m, "script-analysis", "tagged-ruby-concat", [LB.q("x")], {"a.rb": b"hand made"})
    with pytest.raises(LookaheadError, match="not staged by the tagged-copy step"):
        tagged.stage(m, "script-analysis", TAG, families=["ruby"], containers=["concat"])
    assert (m / "script-analysis" / "tagged-ruby-concat" / "files" / "a.rb").read_bytes() == b"hand made"


def test_stage_needs_a_declared_lane_and_known_names(tmp_path):
    m = _matrix(tmp_path)
    with pytest.raises(LookaheadError, match="lane 'web' is not declared"):
        tagged.stage(m, "web", TAG)
    with pytest.raises(LookaheadError, match="family 'cobol'"):
        tagged.stage(m, "script-analysis", TAG, families=["cobol"])
    with pytest.raises(LookaheadError, match="nothing to stage"):
        tagged.stage(m, "script-analysis", TAG, families=["bash"], containers=["property"])
    with pytest.raises(LookaheadError, match="no default tag"):
        tagged.stage(m, "script-analysis", "")


COMMENT_ONLY_READER = r'''
import re
def solve_set(questions, files, ctx):
    text = "".join(v.decode() for v in files.values())
    m = re.search(r"^(?:#|//|--) ([A-Za-z][A-Za-z0-9_]*-[A-Za-z0-9]+)$", text, re.M)
    return {q["id"]: (m.group(1) if m else None) for q in questions}
'''


def test_the_gate_names_every_container_a_comment_only_reader_misses(tmp_path):
    """The Day 18 shape: a reader that only knows the tagged comment is green on the 2026 staging and red
    on every other container, each named."""
    reader = LB.write_reader(tmp_path, "comment_only.py", COMMENT_ONLY_READER)
    m = LB.matrix(tmp_path, {"script-analysis": {"reader": reader}})
    fams = ["python", "javascript", "bash"]
    names = tagged.stage(m, "script-analysis", TAG, seed="d18", families=fams)
    rep = G.gate(m, workdir=tmp_path / "wd", guard="hook", record_to_ledger=False)[0]
    assert not rep.ok
    comment_shape = {f"tagged-{f}-comment" for f in fams}
    missed = {g.specimen for g in rep.gaps if g.kind == "unanswered"}
    assert missed == set(names) - comment_shape and len(missed) == len(names) - 3
    correct = {r.specimen for r in rep.rows if r.status == "correct"}
    assert correct == comment_shape
    assert not [g for g in rep.gaps if g.kind == "wrong"]


# ================================================================================ computed fixtures


@pytest.mark.parametrize("codec", [c for c in M.CODECS if c != "raw"])
def test_every_codec_encoder_is_undone_by_the_matrix_decoder(codec):
    plain = b"stated computations 0123456789 abc"
    enc = fixtures.encode_chain([codec], plain)
    assert enc != plain or codec == "reverse" and plain == plain[::-1]
    assert M.decode_chain([codec], enc) == plain


def test_multi_layer_chains_apply_the_innermost_layer_first():
    plain = b"hello computed"
    enc = fixtures.encode_chain(["base64", "zlib"], plain)       # outermost first, as a specimen says
    assert enc == base64.b64encode(__import__("zlib").compress(plain))
    assert M.decode_chain(["base64", "zlib"], enc) == plain
    for chain in (["hex", "reverse"], ["base32", "gzip"], ["base64url", "utf-16le"], ["base64", "bz2", "xz"]):
        assert M.decode_chain(chain, fixtures.encode_chain(chain, plain)) == plain
    assert fixtures.encode_chain(["raw"], plain) == plain
    with pytest.raises(LookaheadError, match="not known"):
        fixtures.encode_chain(["rot13"], plain)


def test_stage_computed_uses_the_lanes_real_encodings_and_its_key_is_right(tmp_path):
    m = _matrix(tmp_path, ("binary",), binary={"real_encodings": [["base64"], ["hex", "reverse"]]})
    names = fixtures.stage_computed(m, "binary", seed="d29")
    assert names == ["computed-base64", "computed-hex_reverse"]
    specs = {s.name: s for s in M.load(m).specimens["binary"]}
    for name, chain in (("computed-base64", ("base64",)), ("computed-hex_reverse", ("hex", "reverse"))):
        s = specs[name]
        assert set(s.encodings.values()) == {chain}
        assert M.bad_encodings(s) == []
        files = s.read_files()
        assert 2 <= len(files) <= 4
        assert s.key["computed_count"] == len(files)
        for q in s.questions:
            # the template tier and the fixture's own hashlib key are independent; they must agree
            assert computed.answer(q, files) == s.key[q["id"]], q["id"]
        n0 = sorted(files)[0]
        assert s.key["computed_md5_0"] == hashlib.md5(files[n0]).hexdigest()
        assert s.key["computed_size_0"] == len(files[n0])


def test_stage_computed_defaults_to_raw_and_refuses_foreign_folders(tmp_path):
    m = _matrix(tmp_path, ("binary",))
    assert fixtures.stage_computed(m, "binary") == ["computed-raw"]
    assert fixtures.stage_computed(m, "binary") == ["computed-raw"]       # its own: rewritten
    LB.specimen(m, "binary", "computed-base64", [LB.q("x")], {"a": b"QUJD"}, encoding=("base64",))
    with pytest.raises(LookaheadError, match="not staged by the computed-fixture step"):
        fixtures.stage_computed(m, "binary", chains=[["base64"]])
    with pytest.raises(LookaheadError, match="lane 'web' is not declared"):
        fixtures.stage_computed(m, "web")


NONE_READER = "def solve_set(questions, files, ctx):\n    return {q['id']: None for q in questions}\n"
WRAPPED_READER = NONE_READER.replace("def solve_set", "def _inner") + (
    "\nfrom ctf.lookahead import computed as _c\nsolve_set = _c.wrap(_inner)\n")


def test_the_gate_is_red_until_the_lane_adopts_the_computed_tier(tmp_path):
    none = LB.write_reader(tmp_path, "none.py", NONE_READER)
    wrapped = LB.write_reader(tmp_path, "wrapped.py", WRAPPED_READER)
    m = LB.matrix(tmp_path, {"binary": {"reader": none, "real_encodings": [["base64"]]},
                             "mobile": {"reader": wrapped, "real_encodings": [["base64"]]}})
    fixtures.stage_computed(m, "binary", seed=1)
    fixtures.stage_computed(m, "mobile", seed=1)
    reps = {r.lane: r for r in G.gate(m, workdir=tmp_path / "wd", guard="hook", record_to_ledger=False)}
    asked = {q["id"] for s in M.load(m).specimens["binary"] for q in s.questions}
    assert not reps["binary"].ok
    assert {g.qid for g in reps["binary"].gaps if g.kind == "unanswered"} == asked
    assert reps["mobile"].ok, [g.line() for g in reps["mobile"].gaps]
    assert all(r.status == "correct" for r in reps["mobile"].rows)


# ========================================================================================== daily


def test_profile_lanes_are_slugs_of_the_events_own_categories():
    p = profile(categories=("Warmups", "Binary", "Script Analysis", "Mobile / Android", "binary"))
    assert daily.profile_lanes(p) == ("warmups", "binary", "script-analysis", "mobile-android")
    with pytest.raises(LookaheadError, match="declares no categories"):
        daily.profile_lanes(profile(categories=()))


def test_only_a_rolling_release_event_gets_a_daily_look_ahead():
    daily.require_rolling(profile(daily_release="09:00"))
    t1, t2 = dt.datetime(2027, 1, 2, 9, tzinfo=dt.timezone.utc), dt.datetime(2027, 1, 3, 9, tzinfo=dt.timezone.utc)
    daily.require_rolling(profile(daily_release="", releases=(t1, t2)))
    for p in (profile(daily_release=""), profile(daily_release="", releases=(t1,))):
        with pytest.raises(LookaheadError, match="not a rolling-release event"):
            daily.require_rolling(p)


def _shape(tmp: Path, name: str, ids) -> str:
    (tmp / name).write_text(json.dumps([{"id": i, "question": f"What is {i}?",
                                         "answer_format": {"kind": "exact_text"}} for i in ids]))
    return name


def _plan_matrix(tmp: Path) -> Path:
    reader = LB.write_reader(tmp)
    m = tmp / "matrix"
    m.mkdir()
    _shape(m, "bin-prev.json", ["a", "b"])
    _shape(m, "bin-base.json", ["a", "b"])
    _shape(m, "sa-prev.json", ["x"])
    _shape(m, "sa-base.json", ["x"])
    return LB.matrix(tmp, {"binary": {"reader": reader, "previous": "bin-prev.json", "base": "bin-base.json"},
                           "script-analysis": {"reader": reader, "previous": "sa-prev.json",
                                               "base": "sa-base.json"}})


REPORTS = [{"lane": "binary", "gaps": []},
           {"lane": "script-analysis", "gaps": [{"kind": "unanswered", "qid": "x", "lane": "script-analysis"}]}]


def test_plan_day_covers_exactly_the_profile_lanes_through_forecast_plan(tmp_path):
    m = _plan_matrix(tmp_path)
    plans = daily.plan_day(profile(), m, REPORTS)
    assert [p.lane for p in plans] == ["web", "binary", "script-analysis", "warmups"]
    got = {p.lane: p for p in plans}
    assert not got["binary"].agent                      # gate green, shape unchanged: the gate is its look-ahead
    assert got["script-analysis"].agent and "open gap" in got["script-analysis"].reasons[0]
    for lane in ("web", "warmups"):                     # in the profile, never in the matrix: never dropped
        assert got[lane].agent and "no gate report" in got[lane].reasons[0]
        assert "shape unknown" in got[lane].reasons[1]
    first_night = daily.plan_day(profile(), m, None)
    assert all(p.agent for p in first_night)


def test_plan_day_refuses_lanes_the_profile_does_not_have(tmp_path):
    m = _plan_matrix(tmp_path)
    with pytest.raises(LookaheadError, match=r"matrix lane\(s\) binary .*not lanes of event"):
        daily.plan_day(profile(categories=("Web", "Script Analysis")), m, [])
    with pytest.raises(LookaheadError, match=r"gate report lane\(s\) script"):
        daily.plan_day(profile(), m, [{"lane": "script", "gaps": []}])


def test_workflow_args_carry_only_agent_lanes_and_pass_the_prelaunch_gate(tmp_path):
    m = _plan_matrix(tmp_path)
    p = profile()
    doc = daily.plan_doc(p, daily.plan_day(p, m, REPORTS), day="d29", matrix_dir=m,
                         staged={"script-analysis": ["tagged-python-concat"]})
    args = daily.workflow_args(p, doc, repo=tmp_path / "repo", out=tmp_path / "out" / "d29")
    assert [ln["key"] for ln in args["lanes"]] == ["web", "script-analysis", "warmups"]
    sa = args["lanes"][1]
    assert sa["staged"] == ["tagged-python-concat"] and "open gap" in sa["reasons"][0]
    assert args["event"] == "B256 Test CTF" and args["day"] == "d29"
    w = wf.get("day-lookahead")
    assert wf.preflight(w, args) == 6                   # 3 lanes x (predictor + its re-run)
    with pytest.raises(wf.WorkflowError, match="cap exceeded"):
        wf.preflight(w, {**args, "agentCap": 5})
    with pytest.raises(LookaheadError, match="not planned lanes"):
        daily.plan_doc(p, daily.plan_day(p, m, REPORTS), day="d29", matrix_dir=m, staged={"crypto": ["x"]})
    green = [dict(r, gaps=[]) for r in REPORTS]
    quiet = daily.plan_doc(profile(categories=("Binary", "Script Analysis")),
                           daily.plan_day(profile(categories=("Binary", "Script Analysis")), m, green),
                           day="d29", matrix_dir=m)
    with pytest.raises(LookaheadError, match="no lane needs an agent"):
        daily.workflow_args(p, quiet, repo=tmp_path, out=tmp_path)


def test_nine_agent_lanes_are_over_the_hard_cap():
    w = wf.get("day-lookahead")
    lanes = [{"key": f"l{i}", "reasons": ["r"], "staged": []} for i in range(9)]
    base = {"event": "E", "repo": "/r", "out": "/o", "day": "d1", "matrix": "/m"}
    assert wf.preflight(w, {**base, "lanes": lanes[:8]}) == 16
    with pytest.raises(wf.WorkflowError, match="18 agents > cap 16"):
        wf.preflight(w, {**base, "lanes": lanes})


def _doc(lanes):
    return {"event": "b256-test", "day": "d29", "matrix": "/m",
            "lanes": [{"key": k, "agent": a, "reasons": [r], "staged": s} for k, a, r, s in lanes]}


DOC = _doc([("web", True, "no gate report: coverage unknown", []),
            ("binary", False, "gate green", []),
            ("script-analysis", True, "1 open gap(s) (unanswered)", ["tagged-python-concat", "tagged-js-concat"]),
            ("warmups", True, "new shape", [])])


def _staged(lane, new=("d30_*",), gaps=(), note="n", file=None):
    return {"lane": lane, "file": file or f"/o/predictions-{lane}.md", "new": list(new), "gaps": list(gaps),
            "note": note, "specimens": ["s1"]}


def test_finish_names_a_lane_that_was_not_staged_with_its_last_forecast(tmp_path):
    prev = tmp_path / "prev.toml"
    prev.write_text('day = "d28"\n[lane.warmups]\nnew = ["mastery_*"]\ngaps = ["size_*"]\nnote = "256 KiB"\n')
    result = {"staged": [_staged("web"), _staged("script-analysis", gaps=["structural_*"])],
              "notStaged": []}                         # the workflow's own list may even omit the lane
    rep = daily.finish(DOC, result, tmp_path / "d29", previous_forecast=prev)
    assert not rep.ok and rep.not_staged == ["warmups"] and rep.no_agent == ["binary"]
    assert rep.staged == ["web", "script-analysis"]
    text = rep.readme.read_text()
    assert "2 of 3 agent lane(s) staged; 1 NOT staged (warmups)" in text
    assert "- warmups: NOT staged" in text
    assert "last forecast (d28): new mastery_*; gaps size_*" in text and "note: 256 KiB" in text
    assert "- binary: no agent (gate green)" in text
    assert "2 specimen(s) staged by the no-model step" in text
    assert "all" not in text.lower().split()


def test_finish_writes_a_forecast_that_forecast_score_scores(tmp_path):
    result = {"staged": [_staged("web", new=["d30_*", "login_*"], gaps=["d30_token"]),
                         _staged("script-analysis"), _staged("warmups")], "notStaged": []}
    rep = daily.finish(DOC, result, tmp_path / "d29")
    assert rep.ok and rep.forecast is not None
    fc = forecast.load(rep.forecast)
    assert fc.day == "d29" and set(fc.lanes) == {"web", "script-analysis", "warmups"}
    prev = [{"id": "a", "question": "What is a?", "answer_format": {"kind": "exact_text"}}]
    actual = prev + [{"id": "d30_token", "question": "What is the token?", "answer_format": {"kind": "exact_text"}},
                     {"id": "other_new", "question": "What is other?", "answer_format": {"kind": "exact_text"}}]
    report = {"lane": "web", "gaps": [{"kind": "unanswered", "qid": "d30_token"},
                                      {"kind": "wrong", "qid": "other_new"}]}
    s = forecast.score(fc, "web", prev, actual, report, record=False)
    assert s.hit == ("d30_token",) and s.missed == ("other_new",) and s.unused == ("login_*",)
    assert s.recall == 0.5 and s.gap_missed == ("other_new",)


def test_finish_rejects_results_that_do_not_match_the_plan(tmp_path):
    with pytest.raises(LookaheadError, match="'binary' was not given an agent"):
        daily.finish(DOC, {"staged": [_staged("binary")]}, tmp_path)
    with pytest.raises(LookaheadError, match="'crypto' was not given an agent"):
        daily.finish(DOC, {"staged": [_staged("crypto")]}, tmp_path)
    with pytest.raises(LookaheadError, match="staged twice"):
        daily.finish(DOC, {"staged": [_staged("web"), _staged("web")]}, tmp_path)
    with pytest.raises(LookaheadError, match="no workflow result was given"):
        daily.finish(DOC, None, tmp_path)
    with pytest.raises(LookaheadError, match="expected the day-lookahead return value"):
        daily.finish(DOC, {"lanes": []}, tmp_path)


def test_finish_with_no_agent_lanes_writes_the_readme_and_removes_a_stale_forecast(tmp_path):
    quiet = _doc([("binary", False, "gate green", []), ("web", False, "gate green", [])])
    out = tmp_path / "d29"
    out.mkdir()
    (out / daily.FORECAST_FILE).write_text('[lane.web]\nnew = ["old_*"]\n')
    rep = daily.finish(quiet, None, out)
    assert rep.ok and rep.forecast is None and not (out / daily.FORECAST_FILE).exists()
    assert "0 of 0 agent lane(s) staged; 0 NOT staged; 2 lane(s) needed no agent" in rep.readme.read_text()


def test_finish_drops_blank_globs_and_says_so(tmp_path):
    result = {"staged": [_staged("web", new=["d30_*", "  "]), _staged("script-analysis"), _staged("warmups")]}
    rep = daily.finish(DOC, result, tmp_path)
    assert rep.dropped_globs == [("web", "new", "  ")]
    assert forecast.load(rep.forecast).lanes["web"].new == ("d30_*",)
    assert "Blank forecast globs dropped (not scorable): web.new" in rep.readme.read_text()


def test_finish_says_none_on_record_when_the_last_forecast_lacks_the_lane(tmp_path):
    prev = tmp_path / "prev.toml"
    prev.write_text('day = "d28"\n[lane.web]\nnew = ["x_*"]\n')
    rep = daily.finish(DOC, {"staged": [_staged("web"), _staged("script-analysis")]}, tmp_path / "o",
                       previous_forecast=prev)
    assert re.search(r"- warmups: NOT staged.*\n  last forecast: none on record", rep.readme.read_text())


@pytest.mark.parametrize("bad", ["", "d 29", "../d29", "x" * 40, None])
def test_a_bad_day_label_is_refused(bad):
    with pytest.raises(LookaheadError, match="day"):
        daily.check_day(bad)


# ============================================================================================ CLI


def _cli(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_cli_prepare_stages_plans_and_writes_checked_args_then_finish(tmp_path, capsys):
    m = _plan_matrix(tmp_path)
    rep = tmp_path / "report.json"
    rep.write_text(json.dumps(REPORTS))
    prof = profile_toml(tmp_path)
    out = tmp_path / "lookahead"
    rc, so, se = _cli(["lookahead-daily", "prepare", "--profile", str(prof), "--matrix", str(m), "--out", str(out),
                       "--day", "d29", "--report", str(rep), "--tagged", "script-analysis", "--tag", TAG,
                       "--families", "python,lua", "--computed", "binary", "--repo", str(tmp_path)], capsys)
    assert rc == 0, se
    doc = json.loads((out / "d29" / "plan.json").read_text())
    by = {ln["key"]: ln for ln in doc["lanes"]}
    assert list(by) == ["web", "binary", "script-analysis", "warmups"]
    assert len(by["script-analysis"]["staged"]) == 16 and by["binary"]["staged"] == ["computed-raw"]
    args = json.loads((out / "d29" / "workflow-args.json").read_text())
    assert [ln["key"] for ln in args["lanes"]] == ["web", "script-analysis", "warmups"]
    assert args["out"] == str((out / "d29").resolve())
    assert (m / "script-analysis" / "tagged-lua-heredoc" / "key.json").is_file()
    rc, so, se = _cli(["workflow", "check", "day-lookahead", "--args-file", str(out / "d29" / "workflow-args.json")],
                      capsys)
    assert rc == 0, se
    res = tmp_path / "result.json"
    res.write_text(json.dumps({"staged": [_staged("web"), _staged("script-analysis")], "notStaged": ["warmups"]}))
    rc, so, se = _cli(["lookahead-daily", "finish", "--plan", str(out / "d29" / "plan.json"),
                       "--result", str(res)], capsys)
    assert rc == 1 and "- warmups: NOT staged" in so
    res.write_text(json.dumps({"staged": [_staged(k) for k in ("web", "script-analysis", "warmups")]}))
    rc, so, se = _cli(["lookahead-daily", "finish", "--plan", str(out / "d29" / "plan.json"),
                       "--result", str(res), "--json"], capsys)
    assert rc == 0 and json.loads(so)["not_staged"] == []
    assert forecast.load(out / "d29" / "forecast.toml").day == "d29"


def test_cli_prepare_refuses_a_non_rolling_event_before_staging(tmp_path, capsys):
    m = _plan_matrix(tmp_path)
    rc, so, se = _cli(["lookahead-daily", "prepare", "--profile", str(profile_toml(tmp_path, rolling=False)),
                       "--matrix", str(m), "--out", str(tmp_path / "o"), "--day", "d29",
                       "--computed", "binary"], capsys)
    assert rc == 2 and "not a rolling-release event" in se
    assert not (m / "binary" / "computed-raw").exists()


def test_cli_prepare_with_no_agent_lane_exits_1_and_removes_stale_args(tmp_path, capsys):
    m = _plan_matrix(tmp_path)
    prof = tmp_path / "event.toml"
    prof.write_text(profile_toml(tmp_path).read_text().replace(
        '"Web", "Binary", "Script Analysis", "Warmups"', '"Binary", "Script Analysis"'))
    rep = tmp_path / "green.json"
    rep.write_text(json.dumps([{"lane": "binary", "gaps": []}, {"lane": "script-analysis", "gaps": []}]))
    day = tmp_path / "o" / "d29"
    day.mkdir(parents=True)
    (day / "workflow-args.json").write_text("{}")
    rc, so, se = _cli(["lookahead-daily", "prepare", "--profile", str(prof), "--matrix", str(m),
                       "--out", str(tmp_path / "o"), "--day", "d29", "--report", str(rep)], capsys)
    assert rc == 1 and "no lane needs an agent" in so
    assert not (day / "workflow-args.json").exists()
    rc, so, se = _cli(["lookahead-daily", "finish", "--plan", str(day / "plan.json")], capsys)
    assert rc == 0 and "2 lane(s) needed no agent" in so


@pytest.mark.parametrize("extra,msg", [
    (["--tagged", "script-analysis"], "--tagged needs --tag"),
    (["--computed", "crypto"], "staging lane 'crypto' is not a lane of event"),
    (["--day", "../x"], "day '../x'"),
])
def test_cli_prepare_input_errors_exit_2_with_a_named_reason(tmp_path, capsys, extra, msg):
    m = _plan_matrix(tmp_path)
    argv = ["lookahead-daily", "prepare", "--profile", str(profile_toml(tmp_path)), "--matrix", str(m),
            "--out", str(tmp_path / "o"), "--day", "d29"] + extra
    rc, so, se = _cli(argv, capsys)
    assert rc == 2 and msg in se
