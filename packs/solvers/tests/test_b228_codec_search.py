"""B-228: the Mobile codec_search reversible-transform engine, consolidated and armed.

The Mobile lane repeatedly extended solvers/mobile-android/codec_search.py; B-228 consolidates the six
reversible-transform shapes and arms each as an openers/layer1.toml case. Every APK here is built by
ctf.openers.mobile_fixtures from code, and every expected code is the fixture's own Python oracle, never the
reader under test. The shapes are the coverage rows B-228 closes:

  Day 4  "Pending Intent Relay"   a reversible xor over the document's extra `key` field, read plain (`xor`)
  Day 15 "Native Library Secrets" codec `native`, no data: the code is a string of a bundled .so (`native:so-secret`)
  Day 19 "Reflection Maze"        a lone-data reading under the folded-in `reflection` codec (`reflection:plain`)
  Day 20 "Loaded Later"           the document's `data` names a dex by path, read BEFORE the budgeted brute
                                  (pointer-step-first, `apk-string:dex`); it survives a Mastery budget where the
                                  field search alone starves
  Day 26 "Split Decision"         codec `split` with empty parts the feature split fills (`split:by-order+feature`)
  Day 29 "White-box Key Recovery" 40 hex digits + an integer `key`: the shape-triggered linear-offset reader
                                  recovers the code, offered unsure (`linear-offset:sub-key-step`)

The gap-specific behaviours (pointer-step-first order, the no-deadline/shape-triggered reads, fail-closed) are
asserted at a level that does not depend on the machine's wall clock: named_member_hit and linear_offset_shape
are called directly with a generous budget, and the fail-closed controls return None by construction.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

from ctf import paths
from ctf.openers import fixtures
from ctf.openers import mobile_fixtures as F

REPO = paths.repo_root()
for _d in ("solvers/common", "solvers/mobile-android"):
    if str(REPO / _d) not in sys.path:
        sys.path.insert(0, str(REPO / _d))

import codec_search as C  # noqa: E402
import labels  # noqa: E402


@pytest.fixture(autouse=True)
def _private_workdir(tmp_path, monkeypatch):
    """A fresh judge-ledger workdir (the seed's judged names only), the judge ledger on, no mask, no live fix."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    for k in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK", "CTF_TESTING"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(C, "_patch", None)
    labels._cache.clear()


def _members(blob: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def _cli_env(tmp_path) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("CTF_EVENT", "CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK")}
    env["CTF_WORKDIR"] = str(tmp_path / "cli-work")
    return env


def _engine_cli(tmp_path, blob: bytes, name: str = "sample.apk") -> str:
    """Run the engine command line the opener and `ctf run` use, on one delivery; return its stdout."""
    p = tmp_path / name
    p.write_bytes(blob)
    r = subprocess.run([sys.executable, "-I", str(REPO / "solvers/mobile-android/codec_search.py"), str(p)],
                       capture_output=True, text=True, timeout=120, env=_cli_env(tmp_path), cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr[-2000:]
    return r.stdout


# --------------------------------------------------------------------------- the frozen keys are the oracles

def test_the_frozen_opener_keys_are_the_oracles_codes():
    """openers/layer1.toml freezes each B-228 case's line; the fixtures' oracles compute the code independently."""
    raw = tomllib.loads((REPO / "openers" / "layer1.toml").read_text())
    mobile = next(o for o in raw["opener"] if o["lane"] == "mobile-android")
    keys = {c["fixture"]: c["expect"] for c in mobile["case"]}
    assert keys["apk_reversible_xor"] == [f": {F.reversible_value()}  [high] xor"]
    assert keys["apk_reversible_xor_variant"] == [f": {F.reversible_value(F.REVERSIBLE_VARIANT_CODE)}  [high] xor"]
    assert keys["apk_native_so"] == [f": {F.native_value()}  [medium] native:so-secret"]
    assert keys["apk_lone_reflection"] == [f": {F.reflection_value()}  [high] reflection:plain"]
    assert keys["apk_named_member"] == [f": {F.named_member_value()}  [medium] apk-string:dex"]
    assert keys["apk_split_feature"] == [f": {F.split_feature_value()}  [high] split:by-order+feature"]
    assert keys["apk_whitebox_offset"] == [f": unsure {F.whitebox_value()}", "linear-offset:sub-key-step"]
    # the six codes are distinct, so no case passes on another's key
    codes = {F.reversible_value(), F.reversible_value(F.REVERSIBLE_VARIANT_CODE), F.native_value(),
             F.reflection_value(), F.named_member_value(), F.split_feature_value(), F.whitebox_value()}
    assert len(codes) == 7
    assert "apk_split_feature_no_parts" in mobile["controls"]


def test_the_new_fixtures_are_registered_and_deterministic(tmp_path):
    for name in ("apk_reversible_xor", "apk_reversible_xor_variant", "apk_native_so", "apk_lone_reflection",
                 "apk_named_member", "apk_split_feature", "apk_split_feature_no_parts", "apk_whitebox_offset"):
        assert fixtures.BUILDERS[name] is F.BUILDERS[name]
        a = fixtures.build(name, tmp_path / "a" / name).read_bytes()
        b = fixtures.build(name, tmp_path / "b" / name).read_bytes()
        assert a == b, name


# --------------------------------------------------------------------------- each shape, through the engine CLI

@pytest.mark.parametrize("builder, name, expect", [
    (F.reversible_apk, "sample.apk", f": {F.reversible_value()}  [high] xor"),
    (F.native_apk, "sample.apk", f": {F.native_value()}  [medium] native:so-secret"),
    (F.reflection_apk, "sample.apk", f": {F.reflection_value()}  [high] reflection:plain"),
    (F.named_member_apk, "sample.apk", f": {F.named_member_value()}  [medium] apk-string:dex"),
    (F.whitebox_apk, "sample.apk", f": unsure {F.whitebox_value()} "),
])
def test_the_engine_cli_reads_each_single_apk_shape(tmp_path, builder, name, expect):
    out = _engine_cli(tmp_path, builder(), name)
    assert expect in out, out


def test_the_engine_cli_reads_the_split_feature_bundle(tmp_path):
    out = _engine_cli(tmp_path, F.split_feature_bundle(), "sample.apks")
    assert f": {F.split_feature_value()}  [high] split:by-order+feature" in out, out
    # the feature split without its part documents: the empty parts cannot be filled, no code, no [high]
    out = _engine_cli(tmp_path, F.split_feature_bundle(with_parts=False), "no_parts.apks")
    assert F.split_feature_value() not in out and "[high]" not in out, out


# --------------------------------------------------------------------------- the gap-specific behaviours

def test_pointer_step_first_reads_the_named_member(tmp_path):
    """Day 20 "Loaded Later": the document's `data` names a dex by path; named_member_hit reads that member's
    string table (route `apk-string:dex`). Called with a generous budget so the assertion never flakes under load;
    solve_members invokes it BEFORE the field search (the no-deadline, pointer-step-first order)."""
    members = _members(F.named_member_apk())
    saw: list = []
    hit = C.named_member_hit(members, lambda: [], C.Clock(60), saw)
    assert hit is not None and hit.value == F.named_member_value() and hit.route == "apk-string:dex"


def test_solve_members_consults_the_named_member_read_before_the_field_search(monkeypatch):
    """The pointer-step-first order, proved without the wall clock: solve_members calls named_member_hit before the
    loop over the document's own fields, and returns its Hit at once. A sentinel the field search could never
    produce stands in for the named read; solve_members returns it, so the named read precedes — and pre-empts —
    the budgeted brute. (On the Day 20 Time Trial the field search spent the whole 0.40 s first and answered None.)"""
    members = _members(F.named_member_apk())
    sentinel = C.Hit("ANS-5E27121E5E27121E", "medium", "apk-string:dex", "", ())
    monkeypatch.setattr(C, "named_member_hit", lambda *a, **k: sentinel)
    hit = C.solve_members(members, clock=C.Clock(60))
    assert hit is not None and hit.value == sentinel.value and hit.route == "apk-string:dex"


def test_the_white_box_reader_fires_by_shape_and_fails_closed():
    """Day 29: the shape-triggered linear-offset reader (codec_more.linear_offset_shape) recovers the code from
    40 hex digits and an integer key, checks no deadline, and declines (None) when the key is not a JSON integer
    or the recovered bytes are not an answer shape — never a guess."""
    shape = C.codec_more.linear_offset_shape
    data = F._whitebox_data(F.whitebox_value(), F.WHITEBOX_KEY, F.WHITEBOX_STEP)
    assert shape({"data": data, "key": F.WHITEBOX_KEY}) == F.whitebox_value()
    # fail closed: a string key is outside this structural contract; a boolean is not an integer
    assert shape({"data": data, "key": "29"}) is None
    # The bool guard (codec_more.py:895) is load-bearing, not coincidental: this payload is built so that
    # under the plain integer 1 it reconstructs a real answer. A boolean key must still be refused outright
    # (True == 1 in Python), so the reader never silently reads it as the integer 1.
    decodes_under_one = F._whitebox_data("ANS-0123456789ABCDEF", 1, 5)
    assert shape({"data": decodes_under_one, "key": 1}) == "ANS-0123456789ABCDEF"
    assert shape({"data": decodes_under_one, "key": True}) is None
    # fail closed: data that is not exactly 40 hex digits is not this shape
    assert shape({"data": data[:-2], "key": F.WHITEBOX_KEY}) is None
    # never a guess: the step is pinned by the `ANS-` crib, but when the same step reconstructs a body that is
    # not 16 upper-case hex digits the reader declines rather than offer the non-answer bytes.
    non_answer = F._whitebox_data("ANS-Z000000000000000", F.WHITEBOX_KEY, F.WHITEBOX_STEP)
    assert shape({"data": non_answer, "key": F.WHITEBOX_KEY}) is None


def test_the_white_box_answer_is_unsure_under_a_fingerprinted_candidate_key(tmp_path):
    """The recovered code is never plain: decide() offers it unsure under a document-fingerprint candidate key,
    so it reaches the judge only as a probe (it may not borrow the judged `table` name)."""
    out = C.solve_apk(F.whitebox_apk())
    assert labels.is_unsure(out)
    parsed = labels.parse(out)
    assert parsed.key.startswith("mobile.codec/linear-offset@doc-") and parsed.key.endswith("#candidates")
    assert [v for _n, v in parsed.options] == [F.whitebox_value()]


def test_the_bare_codec_pick_offers_one_probe_and_fails_closed():
    """Day 19 "Reflection Maze", the named lone-data one-probe fall-through (codec_search._bare_codec_pick, the
    row-367 LOW step-4 candidate): an answer-shaped `data` under a codec NO reader of the module applies by name,
    with nothing else to confirm it, becomes a one-probe unsure pick `<codec>:plain` rather than None. It is
    exercised directly here because the folded-in `reflection` reader now closes the armed Day-19 fixture before
    this fall-through is reached. Fail-closed on every ambiguity, so it never probes a guess."""
    code = "ANS-AAAAAAAAAAAAAAAA"  # invariant under every rotation/reversal/weave/rot move, so unambiguous
    assert C._alphabet_variants(code) == set()

    def held(codec, c=code):
        return C.Hit(c, "low", codec + " " + C.NOT_APPLIED, codec, ())

    def doc(codec, c=code):
        return {"schema": "huntress.mobile.puzzle.v1", "codec": codec, "data": c}

    members = {"assets/other.json": b"{}"}
    # fires: a genuinely novel control name, the code in clear, nothing else -> a one-probe `<codec>:plain` pick
    hit = C._bare_codec_pick(held("zephyr-control"), doc("zephyr-control"), members)
    assert hit is not None and hit.value == code and hit.route == "zephyr-control:plain"
    # fail closed: a codec a reader DOES apply by name (xor) is handled by that reader, never this fall-through
    assert C._bare_codec_pick(held("xor"), doc("xor"), members) is None
    # fail closed: a different ANS- code standing in clear elsewhere makes `data` a possible decoy -> None
    decoy = {"assets/other.json": b'{"x":"ANS-BBBBBBBBBBBBBBBB"}'}
    assert C._bare_codec_pick(held("zephyr-control"), doc("zephyr-control"), decoy) is None
    # fail closed: a code an alphabet move reads as a different valid code is ambiguous -> None
    amb = "ANS-ABABABABABABABAB"
    assert C._alphabet_variants(amb)
    assert C._bare_codec_pick(held("zephyr-control", amb), doc("zephyr-control", amb), members) is None


def test_the_split_feature_reassembly_fills_empty_parts_and_fails_closed():
    """Day 26: split_bundle.readings fills each empty part once from a non-base split's part document and reads the
    by-order join (`split:by-order+feature`); with the feature parts removed an empty part is left and nothing is
    read (fail closed)."""
    b = C.split_bundle.bundle(F.split_feature_bundle())
    options, _extra, why = C.split_bundle.readings(b)
    assert options and options[0] == ("split:by-order+feature", F.split_feature_value()) and why == ""
    # with the feature split's part documents removed there is nothing to fill the empty parts: no split+feature
    # reading (the engine then falls through to the ordinary split handling, which cannot join an empty part: None,
    # proved end-to-end by test_the_engine_cli_reads_the_split_feature_bundle).
    b0 = C.split_bundle.bundle(F.split_feature_bundle(with_parts=False))
    options0, _e0, _why0 = C.split_bundle.readings(b0)
    assert options0 == []


def test_the_reversible_transform_uses_the_documents_extra_key_field():
    """Day 4: the code is `data` under one byte of xor whose byte is the document's extra `key` field; the reader
    reverses it to the code (never the raw data). A wrong key would not reverse to an answer code."""
    blob = F.reversible_apk()
    assert C.solve_apk(blob) == F.reversible_value()
    # the data on its own is not the code; the key field is load-bearing
    doc = _members(blob)[C.PUZZLE]
    import json
    assert F.reversible_value() not in doc.decode()
    assert json.loads(doc)["key"] == F.REVERSIBLE_KEY
