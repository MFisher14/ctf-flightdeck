"""B-154: the flag plausibility check and the ranked flag-variant set (ctf/flagcheck.py, ctf flag).

Profiles are synthetic TOML files; the submit gate, the event rules, the queue and the ledger are
real, and the platform is a scripted adapter (test_submit_queue.ScriptedAdapter). No value here comes
from a real challenge.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

import ctf.cli as cli
from ctf import event, flagcheck as fc, ledger
from ctf.platform import SubmitGate, SubmitStatus, queue, rules

from test_submit_queue import Clock, ScriptedAdapter

TOML = """
slug = "{slug}"
name = "flagcheck test"
dates = {{ start = 2026-01-01, end = 2026-12-31 }}

[platform]
kind = "{kind}"
base_url = "https://board.flagcheck.test"

[flag]
prefixes = [{prefixes}]
body = '{body}'
case = "{case}"

[rules]
submit_mode = "{mode}"
flag_sharing = "allowed"
ai_on_platform = "allowed"
wrong_answer_stop = {stop}
guess_budget = {budget}

[submit]
per_minute = 1000
interval_s = 0.0
per_challenge_interval_s = 0.0
max_hold_s = 5.0
"""


def make(tmp_path: Path, *, slug="fc-test", prefixes=("PINK",), body=r"[^{}\n]{1,256}", case="exact",
         mode="auto", stop=3, budget=0, kind="ctfd") -> event.EventProfile:
    d = tmp_path / "profiles" / slug
    d.mkdir(parents=True, exist_ok=True)
    text = TOML.format(slug=slug, kind=kind, prefixes=", ".join(f'"{p}"' for p in prefixes), body=body,
                       case=case, mode=mode, stop=stop, budget=budget)
    (d / "event.toml").write_text(text, encoding="utf-8")
    return event.load_path(d / "event.toml", expect_slug=slug)


@pytest.fixture
def prof(tmp_path):
    return make(tmp_path)


def codes(chk):
    return {f.code: f.level for f in chk.findings}


# ------------------------------------------------------------------------------------- the check
def test_a_static_shortcut_draws_a_decoy_warning_naming_the_local_checks(prof):
    chk = fc.check("PINK{s3cure_st0re}", prof, source="strings", local_checks=["pkcs7", "hmac", "json"])
    assert codes(chk)["static_source"] == "warn" and chk.verdict == "warn"
    msg = next(f.message for f in chk.findings if f.code == "static_source")
    assert "decoy" in msg and "pkcs7, hmac, json" in msg and "only the judge" in msg
    for src in fc.STATIC_SOURCES:
        assert "static_source" in fc.check("PINK{abc_def}", prof, source=src).codes(), src


def test_a_derived_source_draws_no_decoy_warning(prof):
    for src in fc.DERIVED_SOURCES:
        chk = fc.check("PINK{abc_def}", prof, source=src)
        assert "static_source" not in chk.codes() and chk.verdict == "ok", src
    assert "pkcs7" not in str(fc.check("PINK{abc_def}", prof, source="strings").to_dict())


def test_an_unknown_source_fails_loudly(prof):
    with pytest.raises(fc.FlagCheckError, match="unknown source 'stringz'"):
        fc.check("PINK{abc}", prof, source="stringz")
    with pytest.raises(fc.FlagCheckError):
        fc.check("PINK{abc}", prof, source="  ")
    with pytest.raises(fc.FlagCheckError, match="must be a string"):
        fc.check(b"PINK{abc}", prof)


def test_a_case_losing_source_warns_and_a_reference_restores_the_case(tmp_path):
    cs = make(tmp_path, prefixes=("CSCTF",), case="prefix-insensitive")
    lost = fc.check("CSCTF{ENIGMAISFUN}", cs, source="enigma")
    assert codes(lost)["case_lost"] == "warn" and lost.primary == "CSCTF{ENIGMAISFUN}"
    assert "Enigma" in next(f.message for f in lost.findings if f.code == "case_lost")
    fixed = fc.check("CSCTF{ENIGMAISFUN}", cs, source="enigma", case_ref="The key phrase: EnigmaIsFun.")
    assert fixed.primary == "CSCTF{EnigmaIsFun}" and fixed.in_format
    assert "reference's case" in next(f.message for f in fixed.findings if f.code == "case_lost")
    flagged = fc.check("CSCTF{ENIGMAISFUN}", cs, case_lossy=True, case_ref="EnigmaIsFun")
    assert flagged.primary == "CSCTF{EnigmaIsFun}" and "case_lost" in flagged.codes()


def test_without_a_lossy_source_case_is_only_advice(prof):
    chk = fc.check("PINK{SHOUTING_BODY}", prof)
    assert codes(chk) == {"all_upper": "info"} and chk.primary == "PINK{SHOUTING_BODY}"
    assert "all_upper" not in fc.check("PINK{SHORT}", prof).codes(), "fewer than 6 letters"
    assert "all_upper" not in fc.check("PINK{Mixed_Case_Body}", prof).codes()
    ref = fc.check("PINK{SHOUTING_BODY}", prof, case_ref="a Shouting body")
    assert ref.primary == "PINK{SHOUTING_BODY}", "without a lossy source the reference only advises"
    assert codes(ref)["case_ref"] == "info" and "Shouting_body" in str(ref.to_dict())


def test_a_case_reference_outside_the_format_is_not_used(tmp_path):
    hexy = make(tmp_path, prefixes=("flag",), body="[0-9a-f]{8}")
    chk = fc.check("flag{deadbeef}", hexy, case_lossy=True, case_ref="DEADBEEF")
    assert chk.primary == "flag{deadbeef}" and chk.in_format
    assert "outside the flag format" in next(f.message for f in chk.findings if f.code == "case_lost")


def test_restore_case_whole_words_and_ambiguity():
    assert fc.restore_case("ENIGMAISFUN", "x EnigmaIsFun y") == "EnigmaIsFun"
    assert fc.restore_case("ENIGMA_IS_FUN", "the Enigma is fun") == "Enigma_is_fun"
    assert fc.restore_case("3N1GMA", "Enigma") == "3n1gma", "leet-blind match, digits kept"
    assert fc.restore_case("ENIGMA", "Enigmatic machines") is None, "whole words only"
    assert fc.restore_case("ENIGMAISFUN", "EnigmaIsFun and ENIGMAisFUN") is None, "two casings: ambiguous"
    assert fc.restore_case("FUN_RUN", "Fun fun Run") == "FUN_Run", "an ambiguous word is left alone"
    assert fc.restore_case("enigma", "enigma") is None, "no change is None"
    assert fc.restore_case("1234", "1234") is None and fc.restore_case("abc", "") is None


def test_restore_case_survives_a_character_whose_lower_case_is_longer(tmp_path):
    # 'İ'.lower() is two characters: a lowered copy of the reference would shift every later offset
    assert len("İ".lower()) == 2
    ref = "İstanbul notes: the Enigma machine"
    assert fc.restore_case("ENIGMA", ref) == "Enigma"
    assert fc.restore_case("ENIGMA_MACHINE", ref) == "Enigma_machine"
    assert fc.restore_case("ISTANBUL", "İstanbul") is None, "İ is not i: no match, nothing invented"
    cs = make(tmp_path, prefixes=("CSCTF",), case="prefix-insensitive")
    chk = fc.check("CSCTF{ENIGMA_MACHINE}", cs, source="enigma", case_ref=ref)
    assert chk.primary == "CSCTF{Enigma_machine}"
    with pytest.raises(ValueError, match="does not line up"):
        fc._copy_case("ENIGMA", "Enigm")
    assert fc.restore_case("straße", "STRAẞE") == "STRAßE", "ß has no one-letter upper case: kept"
    assert fc.restore_case("ENIGMA", "ÉEnigma") is None, "a non-ASCII letter is part of the word"


def test_an_ambiguous_whole_body_is_not_restored_word_by_word():
    # the whole body has two spellings: the word "RUN" alone has one, but the body stays as it is
    assert fc.restore_case("FUN_RUN", "Fun_Run fun_Run") is None
    assert fc.restore_case("FUN_RUN", "Fun_Run") == "Fun_Run"


def test_a_case_reference_applies_to_an_out_of_format_primary(tmp_path):
    hexy = make(tmp_path, prefixes=("flag",), body="[0-9a-f]{8}")
    chk = fc.check("flag{ZZZZ_YYYY}", hexy, source="morse", case_ref="Zzzz_Yyyy")
    assert chk.primary == "flag{Zzzz_Yyyy}" and not chk.in_format
    assert codes(chk)["not_in_format"] == "block"
    assert "reference's case" in next(f.message for f in chk.findings if f.code == "case_lost")


def test_the_format_finding_judges_the_case_restored_primary(tmp_path):
    camel = make(tmp_path, prefixes=("flag",), body="[A-Z][a-z]+")
    chk = fc.check("flag{ENIGMA}", camel, source="enigma", case_ref="the Enigma")
    assert chk.primary == "flag{Enigma}" and chk.in_format
    assert "not_in_format" not in chk.codes() and chk.verdict == "warn"
    assert codes(fc.check("flag{ENIGMA}", camel, source="enigma"))["not_in_format"] == "block"


def test_safe_fixes_are_applied_to_the_primary_and_named(prof):
    chk = fc.check("  PINK{ PINK{inner_value} }\n", prof)
    assert chk.primary == "PINK{inner_value}" and chk.in_format
    assert {"whitespace_edge", "edge_space", "double_wrap"} <= chk.codes()
    plain = fc.check("just_the_body", prof)
    assert plain.primary == "PINK{just_the_body}" and codes(plain)["unwrapped"] == "warn"
    foreign = fc.check("flag{x_y_z}", prof)
    assert foreign.primary == "PINK{x_y_z}" and codes(foreign)["foreign_prefix"] == "warn"
    cased = fc.check("pink{x_y_z}", prof)
    assert cased.primary == "PINK{x_y_z}" and codes(cased) == {"prefix_case": "info"}
    assert cased.verdict == "ok"
    mixed = fc.check("pink{PINK{xyz}}", prof)
    assert "double_wrap" in mixed.codes() and mixed.primary == "PINK{xyz}", "a double wrap in two cases"


def test_prefix_case_is_no_finding_when_the_event_ignores_it(tmp_path):
    sp = make(tmp_path, prefixes=("spooky",), case="prefix-insensitive")
    chk = fc.check("SPOOKY{x_y_z}", sp)
    assert chk.codes() == set() and chk.primary == "SPOOKY{x_y_z}" and chk.verdict == "ok"


def test_an_unknown_format_cannot_be_fixed(tmp_path):
    unk = make(tmp_path, prefixes=(), mode="confirm")
    plain = fc.check("some_body", unk)
    assert plain.primary == "some_body" and "format_unknown" in plain.codes()
    wrapped = fc.check("ANY{some_body}", unk)
    assert wrapped.primary == "ANY{some_body}" and codes(wrapped)["format_unknown"] == "info"
    assert wrapped.in_format


def test_values_that_are_never_flags_block(prof):
    noise = fc.check("PINK{ab\x01cd}", prof)
    assert codes(noise)["control_chars"] == "block" and noise.refuses and noise.verdict == "block"
    assert fc.check("PINK{ab​cd}", prof).refuses, "a zero-width format character is noise too"
    assert fc.check("   ", prof).codes() == {"whitespace_edge", "empty"} and fc.check("", prof).refuses
    assert codes(fc.check("PINK{}", prof))["empty_body"] == "block"
    assert not fc.check("PINK{café}", prof).refuses, "an accented letter is not noise"


def test_outside_the_format_blocks_unless_nonstandard(tmp_path):
    hexy = make(tmp_path, prefixes=("flag",), body="[0-9a-f]{32}")
    bad = fc.check("flag{not-hex}", hexy)
    assert codes(bad)["not_in_format"] == "block" and not bad.in_format and not bad.refuses
    ok = fc.check("flag{not-hex}", hexy, allow_nonstandard=True)
    assert codes(ok)["nonstandard"] == "info" and ok.verdict != "block"


def test_placeholders_short_bodies_and_decoy_markers_warn(prof):
    assert codes(fc.check("PINK{example}", prof))["placeholder"] == "warn"
    assert "short_body" not in fc.check("PINK{xx}", prof).codes(), "a placeholder is not also short"
    assert codes(fc.check("PINK{q7}", prof))["short_body"] == "warn"
    assert "short_body" not in fc.check("PINK{q7z}", prof).codes()
    for body in ("n0t_th3_fl4g", "try_h4rd3r", "FAKE_flag_here", "this-is-a-decoy", "nicetry"):
        assert codes(fc.check(f"PINK{{{body}}}", prof)).get("decoy_marker") == "warn", body
    for body in ("controller_logic", "lollipop_tree", "fakeroot_build"):
        assert "decoy_marker" not in fc.check(f"PINK{{{body}}}", prof).codes(), body


def test_decoy_phrases_match_whole_words_only(prof):
    for body in ("n0tth3fl4g", "this_is_not_the_flag", "not_flag", "notflag", "NOT-REAL", "keep looking"):
        assert codes(fc.check(f"PINK{{{body}}}", prof)).get("decoy_marker") == "warn", body
    for body in ("i_cannot_realize_it", "cannotflag_this", "entry_again_soon", "knot_really"):
        assert "decoy_marker" not in fc.check(f"PINK{{{body}}}", prof).codes(), body


def test_other_flag_values_in_the_same_material_warn(tmp_path):
    sp = make(tmp_path, prefixes=("spooky",), case="prefix-insensitive")
    same = fc.check("spooky{one_value}", sp, others=["SPOOKY{one_value}", "  spooky{one_value} ", "noise"])
    assert "other_flags" not in same.codes(), "the same flag in another prefix case is not another"
    upper = fc.check("SPOOKY{one_value}", sp, others=["spooky{one_value}"])
    assert "other_flags" not in upper.codes(), "compared in the event's normal form"
    bare = fc.check("one_value", sp, others=["spooky{one_value}"])
    assert "other_flags" not in bare.codes(), "the wrapped primary is the same value"
    two = fc.check("spooky{one_value}", sp, others=["spooky{other_value}", "spooky{other_value}", "x{y}"])
    msg = next(f.message for f in two.findings if f.code == "other_flags")
    assert msg.startswith("1 other flag-format value")


def test_axis_findings_name_the_variant_axes(prof):
    chk = fc.check("PINK{h3ll0 wörld}", prof)
    assert codes(chk) == {"spaces": "warn", "diacritics": "info", "leet": "info"}
    assert fc.check("PINK{year_2026}", prof).codes() == set(), "digits alone are not leet"


# ------------------------------------------------------------------------------------- helpers
def test_leet_and_folding_helpers():
    assert fc.deleet("h3ll0_w0rld_2026") == "hello_world_2026"
    assert fc.deleet("N0T_TH3") == "NOT_THE", "an upper-case token gets upper-case letters"
    assert fc.deleet("p@$$") == "pass"
    assert fc.leetify("test site") == "7357 5173"
    assert fc.has_leet("w0rd") and not fc.has_leet("2026_year") and not fc.has_leet("word")
    assert fc.ascii_fold("café straße øl") == "cafe strasse ol"
    assert fc.split("A{b{c}}") == ("A", "b{c}") and fc.split("plain") == (None, "plain")


# ------------------------------------------------------------------------------------- variants
def test_the_ranked_set_puts_the_primary_first_then_by_score(prof):
    vs = fc.variants("PINK{h3ll0 wörld}", prof, max_variants=50)
    vals = [v.value for v in vs.ranked]
    assert vals[0] == "PINK{h3ll0 wörld}" and vs.ranked[0].changes == () and vs.ranked[0].score == 1.0
    assert len(vals) == len(set(vals)), "one set: no value twice"
    assert vals[1:4] == ["PINK{h3ll0_wörld}", "PINK{h3ll0 world}", "h3ll0 wörld"]
    assert [v.changes for v in vs.ranked[1:4]] == [("spaces:underscores",), ("diacritics:ascii",),
                                                   ("wrap:plain",)]
    scores = [v.score for v in vs.ranked]
    assert scores == sorted(scores, reverse=True)
    assert [v.rank for v in vs.ranked] == list(range(len(vals)))
    assert "PINK{hello_world}" in vals, "the three axes combine"
    full = next(v for v in vs.ranked if v.value == "PINK{hello_world}")
    assert full.changes == ("diacritics:ascii", "spaces:underscores", "leet:literal")
    assert full.score == pytest.approx(0.5 * 0.6 * 0.3)


def test_ties_break_on_fewer_changes_then_axis_order(prof):
    vs = fc.variants("PINK{n0_spaces}", prof, max_variants=50)
    assert vs.ranked[1].value == "n0_spaces"                      # wrap:plain 0.35
    literal = next(v for v in vs.ranked if v.changes == ("leet:literal",))
    both = next(v for v in vs.ranked if v.changes == ("spaces:spaces", "leet:literal"))
    assert literal.rank < both.rank
    spaced = next(v for v in vs.ranked if v.changes == ("spaces:spaces",))
    assert spaced.value == "PINK{n0 spaces}" and literal.value == "PINK{no_spaces}"


def test_out_of_format_variants_are_marked_and_not_counted_against_the_cap(prof):
    two = fc.variants("PINK{h3ll0 wörld}", prof, max_variants=2)
    assert [v.in_format for v in two.ranked] == [True, True, True], "plain ranks below this cut"
    vs = fc.variants("PINK{h3ll0 wörld}", prof, max_variants=3)
    assert [v.in_format for v in vs.ranked] == [True, True, True, False, True]
    assert vs.ranked[3].value == "h3ll0 wörld" and vs.ranked[4].changes == ("leet:literal",)
    assert [v.rank for v in vs.sendable()] == [1, 2, 4]
    assert len(vs.sendable(allow_nonstandard=True)) == 4
    assert len(fc.variants("PINK{h3ll0 wörld}", prof, max_variants=0).ranked) == 1
    with pytest.raises(fc.FlagCheckError):
        fc.variants("PINK{abc}", prof, max_variants=-1)


def test_the_cap_counts_every_variant_under_nonstandard(prof):
    vs = fc.variants("PINK{h3ll0 wörld}", prof, max_variants=3, allow_nonstandard=True)
    assert len(vs.ranked) == 4 and vs.ranked[3].value == "h3ll0 wörld"


def test_case_variants_only_when_case_was_lost(tmp_path, prof):
    plain = fc.variants("PINK{Some_Value}", prof, max_variants=50)
    assert not any(c.startswith("case:") for v in plain.ranked for c in v.changes)
    cs = make(tmp_path, prefixes=("CSCTF",), case="prefix-insensitive", slug="fc-cs")
    lost = fc.variants("CSCTF{ENIGMA_IS_FUN}", cs, source="morse", max_variants=50)
    by = {v.changes: v.value for v in lost.ranked}
    assert by[("case:lower",)] == "CSCTF{enigma_is_fun}"
    assert by[("case:title",)] == "CSCTF{Enigma_Is_Fun}"
    assert lost.ranked[1].changes == ("case:lower",)
    ref = fc.variants("CSCTF{ENIGMA_IS_FUN}", cs, case_ref="Enigma Is Fun", max_variants=50)
    assert ref.primary == "CSCTF{ENIGMA_IS_FUN}", "not lossy: the reference spelling is a variant"
    assert ref.ranked[1].changes == ("case:restored",) and ref.ranked[1].value == "CSCTF{Enigma_Is_Fun}"


def test_wrap_variants_offer_the_events_other_prefixes(tmp_path):
    cs = make(tmp_path, prefixes=("CSCTF", "chronos", "CTF", "flag", "extra"), case="prefix-insensitive")
    vs = fc.variants("CSCTF{abc_def}", cs, max_variants=50)
    wraps = {v.changes[0] for v in vs.ranked[1:] if len(v.changes) == 1 and v.changes[0].startswith("wrap:")}
    assert wraps == {"wrap:plain", "wrap:chronos", "wrap:CTF", "wrap:flag"}, "at most three other prefixes"


def test_a_value_reached_two_ways_keeps_its_best_score(prof):
    # PINK{5455} is case:upper + leet:leet (0.3 * 0.25, found first) and diacritics:ascii + leet:leet
    # (0.5 * 0.25, found later): the set keeps the better path
    vs = fc.variants("PINK{saß}", prof, source="morse", max_variants=50)
    v = next(v for v in vs.ranked if v.value == "PINK{5455}")
    assert v.score == pytest.approx(0.125) and v.changes == ("diacritics:ascii", "leet:leet")


def test_a_blocked_value_has_no_variants(prof):
    with pytest.raises(fc.FlagCheckError, match="no variants"):
        fc.variants("PINK{a\x00b}", prof)


def test_plan_spends_the_guess_budget_in_rank_order(prof):
    vs = fc.variants("PINK{h3ll0 wörld}", prof, max_variants=5)
    send, held = vs.plan(0)
    assert [v.rank for v in send] == [0] and [v.value for v in held] == [v.value for v in vs.sendable()]
    send, held = vs.plan(2)
    assert [v.value for v in send[1:]] == [v.value for v in vs.sendable()[:2]]
    assert [v.value for v in held] == [v.value for v in vs.sendable()[2:]]
    for bad in (-1, True, 1.5):
        with pytest.raises(fc.FlagCheckError):
            vs.plan(bad)


# ------------------------------------------------------------------------------------- try_variants
def gate_for(prof, adapter, work):
    clock = Clock()
    g = SubmitGate(adapter, prof)
    rules.install(g, work)
    queue.install(g, work, clock=clock, sleep=clock.sleep)
    return g


def submits(work):
    return [r for r in ledger.read(work) if r["event"] == "platform.submit"]


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    return w


def test_try_sends_the_value_then_guesses_until_accepted(tmp_path, work):
    p = make(tmp_path, budget=2, stop=5)
    a = ScriptedAdapter(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT, SubmitStatus.CORRECT)
    vs = fc.variants("PINK{h3ll0 wörld}", p)
    rep = fc.try_variants(gate_for(p, a, work), "7", "PINK{h3ll0 wörld}", note="xor key from header",
                          workdir=work)
    want = [v.value for v in vs.ranked[:1] + tuple(vs.sendable()[:2])]
    assert [v for _, v in a.sent] == want and rep.outcome == "accepted" and rep.accepted == want[2]
    assert rep.sent == 3 and rep.guesses == 1
    recs = submits(work)
    assert [r["guess"] for r in recs] == [False, True, True]
    assert recs[0]["provenance"] == "xor key from header [variant 0: as derived]"
    assert recs[1]["provenance"].startswith("xor key from header [variant 1: spaces:underscores]")


def test_try_is_capped_by_the_guess_budget_and_holds_the_rest(tmp_path, work):
    p = make(tmp_path, budget=1, stop=9)
    a = ScriptedAdapter()                                   # every answer incorrect
    rep = fc.try_variants(gate_for(p, a, work), "7", "PINK{h3ll0 wörld}", note="n", workdir=work)
    vs = fc.variants("PINK{h3ll0 wörld}", p)
    assert rep.outcome == "capped" and len(a.sent) == 2 and rep.guesses == 1
    assert rep.held == [v.value for v in vs.sendable()[1:]] and rep.held
    assert "guess budget reached" in rep.reason
    assert all(v.in_format for v in vs.ranked if v.value in [s for _, s in a.sent])


def test_try_with_budget_zero_sends_only_the_value(tmp_path, work):
    p = make(tmp_path, budget=0)
    a = ScriptedAdapter()
    rep = fc.try_variants(gate_for(p, a, work), "7", "PINK{w0rd one}", note="n", workdir=work)
    assert a.sent == [("7", "PINK{w0rd one}")] and rep.outcome == "capped"
    assert rep.held == [v.value for v in fc.variants("PINK{w0rd one}", p).sendable()]


def test_try_counts_guesses_used_before_the_run(tmp_path, work):
    p = make(tmp_path, budget=2, stop=9)
    a = ScriptedAdapter()
    g = gate_for(p, a, work)
    assert g.submit("7", "PINK{earlier_guess}", provenance="old guess", guess=True).sent
    assert fc.guesses_left(p, "7", work) == 1
    rep = fc.try_variants(g, "7", "PINK{w0rd one}", note="n", workdir=work)
    assert rep.guesses == 1 and len(a.sent) == 3 and rep.outcome == "capped"
    assert fc.guesses_left(p, "7", work) == 0 and fc.guesses_left(p, "8", work) == 2


def test_guesses_left_never_goes_below_zero(tmp_path, work):
    # three guesses spent under a budget of 3, then the profile's budget is lowered to 1
    wide = make(tmp_path, budget=3, stop=9)
    g = gate_for(wide, ScriptedAdapter(), work)
    for i in range(3):
        assert g.submit("7", f"PINK{{guess_{i}}}", provenance="old guess", guess=True).sent
    narrow = make(tmp_path, budget=1, stop=9)
    assert fc.guesses_left(narrow, "7", work) == 0
    vs = fc.variants("PINK{w0rd one}", narrow)
    assert vs.plan(fc.guesses_left(narrow, "7", work))[0] == [vs.ranked[0]]


def test_try_skips_an_already_judged_value_and_goes_on(tmp_path, work):
    p = make(tmp_path, budget=1, stop=9)
    a = ScriptedAdapter()
    g = gate_for(p, a, work)
    g.submit("7", "PINK{w0rd one}", provenance="first try")
    a.answers = [SubmitStatus.CORRECT]
    rep = fc.try_variants(g, "7", "PINK{w0rd one}", note="n", workdir=work)
    assert (0, "PINK{w0rd one}", "already judged") in rep.skipped
    assert rep.outcome == "accepted" and a.sent[-1] == ("7", "PINK{w0rd_one}") and len(a.sent) == 2


def test_try_stops_at_the_wrong_answer_stop(tmp_path, work):
    p = make(tmp_path, budget=6, stop=2)
    a = ScriptedAdapter()
    rep = fc.try_variants(gate_for(p, a, work), "7", "PINK{h3ll0 wörld}", note="n", workdir=work)
    assert len(a.sent) == 2 and rep.outcome == "stopped" and rep.reason.startswith("wrong_answer_stop")
    sendable = [v.value for v in fc.variants("PINK{h3ll0 wörld}", p).sendable()]
    assert rep.results[-1] == (2, sendable[1], "not_allowed"), "the refused variant was not sent"
    assert rep.held == sendable[1:], "the refused variant and every later one are held"


def test_try_stops_on_an_unjudged_answer(tmp_path, work):
    p = make(tmp_path, budget=3, stop=9)
    a = ScriptedAdapter(SubmitStatus.INCORRECT, SubmitStatus.NOT_ALLOWED)
    rep = fc.try_variants(gate_for(p, a, work), "7", "PINK{w0rd one}", note="n", workdir=work)
    assert rep.outcome == "stopped" and rep.reason.startswith("unjudged (not_allowed)")
    assert len(a.sent) == 2 and rep.guesses == 0
    assert rep.held == [v.value for v in fc.variants("PINK{w0rd one}", p).sendable()[1:]]


def test_try_never_sends_an_out_of_format_variant_unless_nonstandard(tmp_path, work):
    p = make(tmp_path, budget=12, stop=99)
    a = ScriptedAdapter()
    rep = fc.try_variants(gate_for(p, a, work), "7", "PINK{w0rd one}", note="n", workdir=work)
    assert a.sent and all(v.startswith("PINK{") for _, v in a.sent)
    assert any(why == "not in the event's flag format" for _, _, why in rep.skipped)
    assert rep.outcome == "exhausted"


def test_try_refuses_a_blocked_value_and_needs_a_note(tmp_path, work):
    p = make(tmp_path, budget=3)
    a = ScriptedAdapter()
    g = gate_for(p, a, work)
    rep = fc.try_variants(g, "7", "PINK{a\x07b}", note="n", workdir=work)
    assert rep.outcome == "refused" and "control" in rep.reason and a.sent == []
    hexy = make(tmp_path, prefixes=("flag",), body="[0-9a-f]{4}", slug="fc-hex", budget=3)
    rep = fc.try_variants(gate_for(hexy, a, work), "7", "flag{zzzz}", note="n", workdir=work)
    assert rep.outcome == "refused" and "flag format" in rep.reason and a.sent == []
    with pytest.raises(fc.FlagCheckError, match="note"):
        fc.try_variants(g, "7", "PINK{abc}", note=" ", workdir=work)


# ------------------------------------------------------------------------------------- CLI
@pytest.fixture
def board(tmp_path, monkeypatch):
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))
    state = {"profile": make(tmp_path, budget=1, stop=9), "adapter": ScriptedAdapter(), "work": work}
    monkeypatch.setattr(event, "current", lambda root=None: state["profile"])
    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = lambda profile: state["adapter"]
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    return state


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_check_exit_codes_and_json(board, capsys):
    assert run(capsys, "flag", "check", "PINK{clean_value}", "--source", "solver")[0] == 0
    code, out, _ = run(capsys, "flag", "check", "PINK{clean_value}", "--source", "grep", "--passed", "hmac")
    assert code == 1 and "static_source" in out and "hmac" in out
    assert run(capsys, "flag", "check", "PINK{a\x01}")[0] == 4
    code, out, _ = run(capsys, "flag", "check", "pink{x_y_z}", "--json")
    doc = json.loads(out)
    assert code == 0 and doc["primary"] == "PINK{x_y_z}" and doc["findings"][0]["code"] == "prefix_case"
    code, _, err = run(capsys, "flag", "check", "PINK{abc}", "--event", "no-such-event")
    assert code == 2 and "error" in err


def test_cli_check_reads_the_case_reference(board, tmp_path, capsys):
    ref = tmp_path / "desc.txt"
    ref.write_text("Decode the EnigmaIsFun message.", encoding="utf-8")
    code, out, _ = run(capsys, "flag", "check", "PINK{ENIGMAISFUN}", "--source", "enigma",
                       "--case-ref", str(ref))
    assert code == 1 and "primary: PINK{EnigmaIsFun}" in out
    code, _, err = run(capsys, "flag", "check", "PINK{X}", "--case-ref", str(tmp_path / "missing.txt"))
    assert code == 2 and "cannot read the case reference" in err


def test_cli_variants_writes_the_held_list_for_a_sweep(board, tmp_path, capsys):
    out_file = tmp_path / "held.txt"
    code, out, _ = run(capsys, "flag", "variants", "PINK{w0rd one}", "--out", str(out_file))
    vs = fc.variants("PINK{w0rd one}", board["profile"])
    assert code == 0 and "1 left on a challenge" in out
    assert out_file.read_text().splitlines() == [v.value for v in vs.sendable()[1:]]
    assert " 1. PINK{w0rd_one}" in out and "[not in the flag format]" in out
    gate_for(board["profile"], ScriptedAdapter(), board["work"]).submit(
        "9", "PINK{used}", provenance="p", guess=True)
    code, out, _ = run(capsys, "flag", "variants", "PINK{w0rd one}", "--id", "9", "--json")
    doc = json.loads(out)
    assert doc["guesses_left"] == 0 and doc["held"] == [v.value for v in vs.sendable()]
    assert run(capsys, "flag", "variants", "PINK{\x02}")[0] == 4


def test_cli_try_sends_in_order_and_reports_held(board, capsys):
    code, out, _ = run(capsys, "flag", "try", "5", "PINK{w0rd one}", "--note", "from the key")
    assert code == 1 and "capped" in out and "held for the player" in out
    assert [v for _, v in board["adapter"].sent] == ["PINK{w0rd one}", "PINK{w0rd_one}"]
    board["adapter"].answers = [SubmitStatus.CORRECT]
    code, out, _ = run(capsys, "flag", "try", "6", "PINK{abc_def}", "--note", "n")
    assert code == 0 and "accepted" in out


def test_cli_try_refuses_a_manual_event_before_any_send(board, tmp_path, capsys):
    board["profile"] = make(tmp_path, mode="manual", slug="fc-manual")
    code, _, err = run(capsys, "flag", "try", "5", "PINK{abc}", "--note", "n")
    assert code == 4 and "ctf flag variants" in err and board["adapter"].sent == []
    assert run(capsys, "flag", "variants", "PINK{abc def}")[0] == 0, "variants work offline on manual"


def test_ctf_submit_prints_plausibility_warnings_and_refuses_noise(board, capsys):
    code, _, err = run(capsys, "submit", "5", "PINK{two words}", "--note", "n")
    assert "plausibility warn (spaces)" in err and board["adapter"].sent == [("5", "PINK{two words}")]
    code, _, err = run(capsys, "submit", "6", "PINK{a\x03b}", "--note", "n")
    assert code == 4 and "plausibility check blocks" in err and len(board["adapter"].sent) == 1
    code, _, err = run(capsys, "submit", "7", "PINK{fine_value}", "--note", "n")
    assert "plausibility" not in err


def test_ctf_submit_takes_the_source_and_the_local_checks(board, capsys):
    code, _, err = run(capsys, "submit", "5", "PINK{s3cure_st0re}", "--note", "n", "--source", "strings",
                       "--passed", "pkcs7", "--passed", "hmac")
    assert "plausibility warn (static_source)" in err and "pkcs7, hmac" in err
    assert board["adapter"].sent == [("5", "PINK{s3cure_st0re}")], "a warning does not stop the send"
    code, _, err = run(capsys, "submit", "6", "PINK{ENIGMA_TEXT}", "--note", "n", "--source", "enigma")
    assert "plausibility warn (case_lost)" in err
    with pytest.raises(SystemExit):
        cli.main(["submit", "7", "PINK{abc}", "--source", "stringz"])
    assert len(board["adapter"].sent) == 2


def test_ctf_submit_leaves_the_format_refusal_to_the_gate(board, capsys):
    code, _, err = run(capsys, "submit", "5", "PINK{a{b}", "--note", "n")
    assert code == 4 and "not_in_format" not in err and "plausibility" not in err
    assert board["adapter"].sent == []


# ------------------------------------------------------------------------------------- intake lane
def test_intake_auto_submit_stands_down_on_a_decoy_body(tmp_path, work):
    from ctf.intake import autosubmit
    p = make(tmp_path, stop=9)
    a = ScriptedAdapter()
    g = gate_for(p, a, work)
    out = autosubmit.auto_submit("3", "solved", ["PINK{n0t_th3_fl4g}"], g, profile=p, provenance="x",
                                 workdir=work)
    assert not out.submitted and a.sent == [] and "decoy_marker" in out.reason
    assert out.flag == "PINK{n0t_th3_fl4g}" and "not sent" in out.line()
    ok = autosubmit.auto_submit("4", "solved", ["PINK{plain_find}"], g, profile=p, provenance="x",
                                workdir=work)
    assert ok.submitted and a.sent == [("4", "PINK{plain_find}")]
