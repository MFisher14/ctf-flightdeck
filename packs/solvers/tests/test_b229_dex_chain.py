"""B-229: the Dalvik dex-chain VM armed for the mobile `analysis` codec, its trace, and the pre-release replay.

Every APK here is built by ctf.openers.dexasm / ctf.openers.mobile_fixtures from code, and every expected code is
computed by the fixtures' Python oracles, never by the reader under test. The shapes are the coverage rows:
Day 5 (split with an order field), Day 23 TT and Mastery (a dex chain with decoys and a long[] table), Day 26 (a
split bundle whose chain reads a feature-split asset), Day 31 Mastery set 10 (asset read + InMemoryDexClassLoader
+ reflection), and the fail-closed rule (an unmodelled call, a missing payload, two chains, a placeholder code).
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from ctf import dexvm as D
from ctf import openers, paths
from ctf.adapt import regress
from ctf.openers import dexasm, fixtures
from ctf.openers import mobile_fixtures as F

REPO = paths.repo_root()
for _d in ("solvers/common", "solvers/mobile-android"):
    if str(REPO / _d) not in sys.path:
        sys.path.insert(0, str(REPO / _d))

import codec_search as C  # noqa: E402
import dex_chain_codec as dcc  # noqa: E402
import dex_chain_replay as R  # noqa: E402  (the trace; the replay is ctf.dexvm)
import labels  # noqa: E402

TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

CHAIN = F.chain_value(*F.CHAIN_BASE)
VARIANT = F.chain_value(*F.CHAIN_VARIANT)
LOADER = F.loader_value(*F.LOADER_BASE)
BUNDLE = F.split_asset_value()


@pytest.fixture(autouse=True)
def _private_workdir(tmp_path, monkeypatch):
    """A fresh judge-ledger workdir (the seed's judged names only), the judge ledger on, no mask, no live fix."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    for k in ("CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(C, "_patch", None)


def _members(blob: bytes) -> dict:
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {n: zf.read(n) for n in zf.namelist()}


def _cli_env(tmp_path) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in ("CTF_EVENT", "CTF_JUDGE_LEDGER", "CTF_LEDGER_MASK")}
    env["CTF_WORKDIR"] = str(tmp_path / "cli-work")
    return env


def _engine_cli(tmp_path, blob: bytes, name: str = "sample.apk") -> str:
    p = tmp_path / name
    p.write_bytes(blob)
    r = subprocess.run([sys.executable, "-I", str(REPO / "solvers/mobile-android/codec_search.py"), str(p)],
                       capture_output=True, text=True, timeout=120, env=_cli_env(tmp_path), cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr[-2000:]
    return r.stdout


def _dexvm(tmp_path, *args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "ctf", "dexvm", *map(str, args)], capture_output=True, text=True,
                          timeout=180, env=env or _cli_env(tmp_path), cwd=str(REPO))


# --------------------------------------------------------------------------- the assembler and the oracles

def test_dexasm_writes_a_dex_whose_header_tables_and_code_the_reader_parses():
    d = dexasm.DexFile()
    m = d.method("Lcom/x/A;", "f", "JJ")
    c = dexasm.Code(regs=4, ins=2, outs=0)
    c.const_wide(0, 0x1122334455667788)
    c.return_wide(0)
    d.define("Lcom/x/A;", [(m, c)])
    blob = d.build()
    assert blob[:8] == b"dex\n035\x00"
    assert struct.unpack_from("<II", blob, 0x20) == (len(blob), 0x70)
    assert struct.unpack_from("<I", blob, 0x28)[0] == 0x12345678
    dex = dcc.Dex(blob)
    assert dex.mname[m] == ("Lcom/x/A;", "f")
    regs, ins, units = dex.code[m]
    assert (regs, ins) == (4, 2)
    assert units[:5] == [0x0018, 0x7788, 0x5566, 0x3344, 0x1122] and units[5] == 0x0010
    assert dex.meth_shorty(m) == "JJ"
    # the class definition names its own type (class_idx), not type 0
    assert dex.type_str(struct.unpack_from("<I", blob, dex.cls_off)[0]) == "Lcom/x/A;"


def test_dexasm_fails_loudly_on_what_it_cannot_encode():
    c = dexasm.Code(regs=4)
    with pytest.raises(dexasm.DexAsmError, match="v16"):
        c.invoke(0x71, 0, [16])
    with pytest.raises(dexasm.DexAsmError, match="out of range"):
        c.const4(0, 9)
    c.goto16("nowhere")
    with pytest.raises(dexasm.DexAsmError, match="nowhere"):
        c.units()


def test_fill_array_data_payload_is_aligned_and_holds_the_values():
    c = dexasm.Code(regs=4)
    c.const4(0, 1)                  # one unit, so the payload needs a pad unit
    c.fill_array_data(1, 8, [0x0102030405060708])
    c.return_void()
    u = c.units()
    at = u.index(0x0300)
    assert at % 2 == 0
    assert u[at + 1] == 8 and u[at + 2] == 1
    assert u[at + 4:at + 8] == [0x0708, 0x0506, 0x0304, 0x0102]
    assert u[2] == at - 1           # the 31t offset counts from the fill-array-data instruction (unit 1)


def test_the_frozen_opener_keys_are_the_oracles_codes():
    """openers/layer1.toml freezes each new mobile case's code; the fixtures' oracles compute it independently."""
    raw = tomllib.loads((REPO / "openers" / "layer1.toml").read_text())
    mobile = next(o for o in raw["opener"] if o["lane"] == "mobile-android")
    keys = {c["fixture"]: c["expect"] for c in mobile["case"]}
    assert keys["apk_analysis_chain"] == [f": {CHAIN}  [high] analysis dex chain"]
    assert keys["apk_analysis_chain_variant"] == [f": {VARIANT}  [high] analysis dex chain"]
    assert keys["apk_analysis_loader"] == [f": {LOADER}  [high] analysis dex chain"]
    assert keys["apk_split_by_order"] == [f": {F.SPLIT_CODE}  [high] split:by-order"]
    assert keys["apk_split_asset_bundle"] == [f": {BUNDLE}  [high] analysis:dex-chain+split-asset"]
    assert {"apk_analysis_unmodelled", "apk_analysis_no_payload", "apk_split_asset_no_asset"} <= set(mobile["controls"])
    assert len({CHAIN, VARIANT, LOADER, F.SPLIT_CODE, BUNDLE}) == 5


def test_the_split_document_places_each_part_at_its_order_position():
    doc = F.split_doc()
    rebuilt = [""] * len(doc["parts"])
    for part, pos in zip(doc["parts"], doc["order"]):
        rebuilt[pos] = part
    assert "".join(rebuilt) == F.SPLIT_CODE
    assert "".join(doc["parts"]) != F.SPLIT_CODE                       # listed out of order
    assert "".join(doc["parts"][i] for i in doc["order"]) != F.SPLIT_CODE   # the other reading is not the code


def test_the_new_fixtures_are_registered_and_deterministic(tmp_path):
    for name in F.BUILDERS:
        assert fixtures.BUILDERS[name] is F.BUILDERS[name]
        a = fixtures.build(name, tmp_path / "a" / name).read_bytes()
        b = fixtures.build(name, tmp_path / "b" / name).read_bytes()
        assert a == b, name


# --------------------------------------------------------------------------- the VM on each shape

@pytest.mark.parametrize("spec", [F.CHAIN_BASE, F.CHAIN_VARIANT,
                                  (7, 0x9E3779B97F4A7C15, 0, (1, 2, 3, 0x7FFFFFFFFFFFFFFF), 3)])
def test_the_chain_runs_the_reachable_method_through_its_table(spec):
    files = _members(F.chain_apk(spec))
    trace = []
    codes, declines = dcc.analysis_codes_ex(files, _trace=trace)
    assert (codes, declines) == ([F.chain_value(*spec)], 0)
    assert dcc.recover(files) == F.chain_value(*spec)
    # one entry ran: Release.code; the decoy transforms were never entries and never fed the code
    assert [(e["entry"], e["outcome"]) for e in trace] == [("Lcom/huntress/d23/Release;->code", "code")]
    seed, k_mul, k_xor, table, pick = spec
    assert F.chain_value(seed, k_mul ^ 0xFF, k_xor ^ 0xFF, table, pick) != codes[0]
    assert F.chain_value(seed, k_mul, k_xor, table, (pick + 1) % len(table)) != codes[0]


def test_the_loader_reads_the_asset_loads_it_in_memory_and_invokes_by_reflection():
    files = _members(F.loader_apk())
    trace = []
    assert dcc.analysis_codes_ex(files, _trace=trace) == ([LOADER], 0)
    assert dcc.recover(files) == LOADER
    assert len(trace) == 1 and trace[0]["loaded_inmemory"] is True and trace[0]["code"] == LOADER


@pytest.mark.parametrize("files, why", [
    (lambda: _members(F.loader_apk(with_payload=False)), "asset not in this package"),
    (lambda: dict(_members(F.loader_apk()), **{"classes.dex": F.loader_dex(F.LOADER_BASE[0], method="deriveV2")}),
     "payload method not unique"),
    (lambda: _members(F.chain_apk(unmodelled=True)), "Lcom/vendor/attest/Sdk;->verdict"),
])
def test_an_unmodelled_step_declines_with_its_reason_and_no_code(files, why):
    files = files()
    trace = []
    codes, declines = dcc.analysis_codes_ex(files, _trace=trace)
    assert codes == [] and declines == 1
    assert dcc.recover(files) is None
    assert dcc.answer(C.CODE_QUESTION, files) is None
    assert [e["outcome"] for e in trace] == ["decline"] and why in trace[0]["reason"]


def test_two_chains_are_candidates_never_plain():
    files = _members(F.chain_apk(twin_seed=0x1234))
    codes, declines = dcc.analysis_codes_ex(files)
    assert sorted(codes) == sorted([CHAIN, F.chain_value(0x1234, *F.CHAIN_BASE[1:])]) and declines == 0
    assert dcc.recover(files) is None
    got = dcc.answer(C.CODE_QUESTION, files)
    assert labels.is_unsure(got)
    assert sorted(v for _n, v in labels.parse(got).options) == sorted(codes)


def test_a_lone_code_beside_a_decline_is_unsure():
    """The chain's code from one entry, while a second entry declines: never plain (the decline may be the real one)."""
    files = _members(F.chain_apk())
    files["classes2.dex"] = _members(F.chain_apk(unmodelled=True, pkg="com/huntress/d23b"))["classes.dex"]
    codes, declines = dcc.analysis_codes_ex(files)
    assert codes == [CHAIN] and declines == 1
    assert dcc.recover(files) is None
    got = dcc.answer(C.CODE_QUESTION, files)
    assert labels.is_unsure(got) and labels.parse(got).key.endswith("#partial")


def test_the_trace_never_changes_what_the_chain_returns(monkeypatch):
    for blob in (F.chain_apk(), F.chain_apk(unmodelled=True), F.loader_apk(), F.chain_apk(twin_seed=5)):
        files = _members(blob)
        assert dcc.analysis_codes_ex(files) == dcc.analysis_codes_ex(files, _trace=[])


def test_entries_past_the_bound_or_the_budget_are_traced_as_skipped(monkeypatch):
    files = _members(F.chain_apk())
    monkeypatch.setattr(dcc, "MAX_ENTRIES", 0)
    trace = []
    assert dcc.analysis_codes_ex(files, _trace=trace) == ([], 1)
    assert [e["outcome"] for e in trace] == ["skipped"] and "MAX_ENTRIES" in trace[0]["reason"]
    monkeypatch.setattr(dcc, "MAX_ENTRIES", 64)
    monkeypatch.setattr(dcc, "TOTAL_STEPS", 0)
    trace = []
    assert dcc.analysis_codes_ex(files, _trace=trace) == ([], 1)
    assert [e["outcome"] for e in trace] == ["skipped"] and "step budget" in trace[0]["reason"]


# --------------------------------------------------------------------------- the armed reader (the engine CLI)

@pytest.mark.parametrize("blob, code", [(lambda: F.chain_apk(), CHAIN), (lambda: F.chain_apk(F.CHAIN_VARIANT), VARIANT),
                                        (lambda: F.loader_apk(), LOADER)])
def test_the_engine_cli_answers_an_analysis_delivery_plain(tmp_path, blob, code):
    """Day 23 TT/Mastery and Day 31 set 10: the command line the opener and `ctf run` use reads the dex chain (before
    B-229 it printed None: solve_apk never ran the chain)."""
    out = _engine_cli(tmp_path, blob())
    assert f": {code}  [high] analysis dex chain (dex_chain_codec.py)" in out
    assert C.solve_apk(blob()) is None          # the pre-B-229 path: the reason the CLI had to change


def test_the_engine_cli_reads_a_day26_split_bundle_through_the_split_asset_hook(tmp_path):
    """The opener's Day 26 bundle (ctf.openers.mobile_splits_synth's d26_tt, its code from the chain spec's oracle)."""
    out = _engine_cli(tmp_path, F.split_asset_bundle(), "split_decision.apks")
    assert f": {BUNDLE}  [high] analysis:dex-chain+split-asset" in out
    # a feature split without the asset the chain reads: no code at all
    out = _engine_cli(tmp_path, F.split_asset_bundle(with_asset=False), "no_asset.apks")
    assert BUNDLE not in out and "[high]" not in out


def test_the_moved_synth_module_is_the_same_module_under_its_test_name():
    """tests/day27_mobile_splits_synth.py is an alias of ctf.openers.mobile_splits_synth (moved in fix round 1)."""
    import day27_mobile_splits_synth as old
    from ctf.openers import mobile_splits_synth as new
    assert old is new
    assert F.split_asset_bundle()[:2] == b"PK"
    members = _members(F.split_asset_bundle())
    assert list(members) == ["base.apk", "feature.apk"]
    assert "assets/huntress_feature.bin" in _members(members["feature.apk"])
    assert "assets/huntress_feature.bin" not in _members(_members(F.split_asset_bundle(with_asset=False))["feature.apk"])


def test_the_engine_cli_reads_day5_split_by_order(tmp_path):
    out = _engine_cli(tmp_path, F.split_apk())
    assert f": {F.SPLIT_CODE}  [high] split:by-order" in out


@pytest.mark.parametrize("blob, gone", [
    (lambda: F.chain_apk(unmodelled=True), CHAIN),
    (lambda: F.chain_apk(unmodelled=True, sample=True), CHAIN),
    (lambda: F.loader_apk(with_payload=False), LOADER),
])
def test_the_engine_cli_fails_closed_on_a_declined_chain(tmp_path, blob, gone):
    """No code, no candidate: None, and the line tells the operator where to look (fix round 1: the placeholder
    beside a declined chain was still offered unsure under apk-string:dex:beside-analysis)."""
    out = _engine_cli(tmp_path, blob())
    assert gone not in out and F.SAMPLE_CODE not in out
    assert "[high]" not in out and "unsure" not in out                   # nothing plain, nothing offered
    line = out.strip().splitlines()[-1]
    assert ": None  [none] analysis dex chain" in line, line
    assert "fail closed" in line and "ctf dexvm show" in line, line


def test_a_placeholder_code_in_the_dex_is_never_the_plain_answer(tmp_path):
    """Day 23 Mastery: the first live patch offered ANS-0123456789ABCDEF for sets it could not read."""
    out = _engine_cli(tmp_path, F.chain_apk(unmodelled=True, sample=True))
    assert F.SAMPLE_CODE not in out                                    # not plain, not a candidate
    assert C.solve_delivery(F.chain_apk(unmodelled=True, sample=True)) is None
    assert "candidate" not in C.LAST and "key" not in C.LAST
    # beside a chain that reads, the placeholder is not even offered: the chain's code is the answer
    assert C.solve_delivery(F.chain_apk(sample=True)) == CHAIN


class _Partial(dict):
    """The runner's partial answers (ctf.adapt.setpool takes them when a set is cut), recording every value written."""

    def __init__(self):
        super().__init__()
        self.seen = []

    def update(self, *a, **k):
        d = dict(*a, **k)
        self.seen += list(d.values())
        super().update(d)

    def __setitem__(self, k, v):
        self.seen.append(v)
        super().__setitem__(k, v)


SET_BUDGET = 30.0   # seconds: far past any load this machine sees, so the generic search always runs to the end (rule 16)


@pytest.fixture
def steady_budget(monkeypatch):
    """Fix round 3: an explicit set budget in place of the production 0.40 s (codec_search.BUDGET, which set_budget
    reads for a set of three deliveries or fewer). Under load the production budget ran out before the generic search
    reached the placeholder, the answer was None with nothing withdrawn, and the fail-closed tests flaked."""
    monkeypatch.setattr(C, "BUDGET", SET_BUDGET)
    assert C.set_budget({"set": 1}) == SET_BUDGET


def _solve_set(blob: bytes, partial=None, questions=None) -> dict:
    """codec_search.solve_set as ctf.adapt.setpool calls it for one set of one delivery."""
    ctx = {"set": 1, "delivery": blob, "delivery_name": "d.apk", "partial": {} if partial is None else partial}
    return C.solve_set([dict(C.CODE_QUESTION)] if questions is None else questions, {}, ctx)


def _assert_search_reached_the_placeholder():
    """The generic search ran to the end and read the placeholder (demoted unsure beside the declined chain): so a
    None answer below is the withdrawal's doing, never a budget that ran out first."""
    assert C.LAST_SET.get("analysis_unread") == "codes=0 declines=1", C.LAST_SET
    assert not any("time budget" in str(s) for s in C.LAST_SET.get("saw", ())), C.LAST_SET.get("saw")


def test_the_set_path_the_timed_runner_drives_fails_closed_too(steady_budget):
    """Fix round 2: the withdrawal is solve_set's own, so ctf.adapt.setpool (the timed runner's set pool) never gets
    the placeholder beside a declined chain: not as the answer, not as an unsure candidate, not in the partial answers
    a cut set falls back to. Day 23 Mastery's first patch offered sets 1/2/4/5 ANS-0123456789ABCDEF on this path."""
    p = _Partial()
    assert _solve_set(F.chain_apk(unmodelled=True, sample=True), p) == {"answer": None}
    _assert_search_reached_the_placeholder()
    assert not any(F.SAMPLE_CODE in str(v) for v in p.seen), p.seen
    assert C.LAST_SET["withdrawn"] == ["answer"] and C.LAST_SET["route"] == C.FAIL_CLOSED_ROUTE
    assert C.LAST_SET["answer"] is None and "key" not in C.LAST_SET and "candidate" not in C.LAST_SET
    # a chain that reads: its own code, plain, nothing withdrawn, and the placeholder never looked at
    p = _Partial()
    assert _solve_set(F.chain_apk(sample=True), p) == {"answer": CHAIN}
    assert "withdrawn" not in C.LAST_SET and F.SAMPLE_CODE not in str(p.seen)


def test_the_set_path_fails_closed_for_a_code_question_under_another_id(steady_budget):
    """Fix round 3: the rule covers every question the module gives the code (`mine`), not only the id `answer`. A
    set's one ANS-format question under another id (the Day 14 look-ahead gives it the code) beside a declined chain
    is None and withdrawn, never the placeholder unsure under :beside-analysis."""
    p = _Partial()
    q = {"id": "code", "answer_format": "ANS-XXXXXXXXXXXXXXXX"}
    assert _solve_set(F.chain_apk(unmodelled=True, sample=True), p, [q]) == {"code": None}
    _assert_search_reached_the_placeholder()
    assert C.LAST_SET["withdrawn"] == ["code"] and C.LAST_SET["route"] == C.FAIL_CLOSED_ROUTE
    assert not any(F.SAMPLE_CODE in str(v) for v in p.seen), p.seen
    assert "key" not in C.LAST_SET and "candidate" not in C.LAST_SET


def test_the_set_path_fails_closed_when_the_chain_run_raises(steady_budget, monkeypatch):
    """Fix round 3: a chain run that raises computed no code. The document is still `analysis`, so the generic
    search's placeholder is withdrawn exactly as beside a decline, never offered because the run blew up."""
    def boom(*_a, **_k):
        raise RuntimeError("synthetic chain failure")

    monkeypatch.setattr(dcc, "AnalysisRun", boom)
    assert C.dex_chain_codec is dcc
    p = _Partial()
    assert _solve_set(F.chain_apk(unmodelled=True, sample=True), p) == {"answer": None}
    _assert_search_reached_the_placeholder()
    assert C.LAST_SET["chain_codes"] == [] and C.LAST_SET["withdrawn"] == ["answer"]
    assert C.LAST_SET["route"] == C.FAIL_CLOSED_ROUTE
    assert not any(F.SAMPLE_CODE in str(v) for v in p.seen), p.seen


def test_the_set_path_keeps_an_unsure_answer_the_chain_computed(steady_budget):
    """The rule withdraws only a value no chain method computed: one code beside a decline stays an unsure #partial."""
    files = _members(F.chain_apk())
    files["classes2.dex"] = _members(F.chain_apk(unmodelled=True, pkg="com/huntress/d23b"))["classes.dex"]
    got = _solve_set(dexasm.apk(files))["answer"]
    parsed = labels.parse(got)
    assert labels.is_unsure(got) and parsed.key.endswith("#partial") and [v for _n, v in parsed.options] == [CHAIN]
    assert "withdrawn" not in C.LAST_SET


def test_chain_stray_names_only_values_the_chain_did_not_compute():
    two = labels.unsure("mobile.codec/apk-string:dex:beside-analysis", [("a", CHAIN), ("b", F.SAMPLE_CODE)])
    assert C._chain_stray(two, [CHAIN]) == [F.SAMPLE_CODE]
    assert C._chain_stray(two, [CHAIN, F.SAMPLE_CODE]) == []
    assert C._chain_stray(two, []) == [CHAIN, F.SAMPLE_CODE]
    assert C._chain_stray(F.SAMPLE_CODE, []) == []                 # plain: only the chain answers an analysis plain
    assert C._chain_stray(None, []) == [] and C._chain_stray("??not json", []) == []   # nothing offered


def test_solve_delivery_leaves_other_deliveries_to_solve_apk(monkeypatch):
    calls = []
    real = C.solve_set
    monkeypatch.setattr(C, "solve_set", lambda *a, **k: calls.append(a) or real(*a, **k))
    assert C.solve_delivery(F.split_apk()) == F.SPLIT_CODE and calls == []
    assert C.solve_delivery(F.chain_apk()) == CHAIN and len(calls) == 1
    assert C.LAST["computed"] == "analysis"


# --------------------------------------------------------------------------- the opener (ctf arm, adapt prewarm)

def test_the_mobile_opener_holds_every_shape_and_its_controls():
    o = openers.for_lane("mobile-android")
    cases = {c.fixture: c for c in o.all_cases}
    assert cases["apk_analysis_chain"].mode == "time_trial"
    assert cases["apk_analysis_chain_variant"].mode == "mastery"
    assert cases["apk_analysis_loader"].mode == "mastery"
    assert cases["apk_split_by_order"].mode == "base"
    # Day 26 TT (fix round 1): the split-asset bundle is an opener case, so `ctf arm` / `adapt prewarm` gate it
    assert cases["apk_split_asset_bundle"].mode == "time_trial" and cases["apk_split_asset_bundle"].within == 30
    assert {"apk_analysis_unmodelled", "apk_analysis_no_payload", "apk_split_asset_no_asset"} <= set(o.controls)


def test_the_day26_control_would_fail_arming_if_its_asset_came_back(tmp_path, monkeypatch):
    """The no-asset control is a real control: built WITH the asset, the bundle case's key holds on it."""
    o = openers.for_lane("mobile-android")
    monkeypatch.setitem(fixtures.BUILDERS, "apk_split_asset_no_asset", F.BUILDERS["apk_split_asset_bundle"])
    r = openers.arm(o, workdir=tmp_path)
    assert r.status == openers.FAILED
    bad = [c for c in r.cases if c.fixture == "apk_split_asset_no_asset"]
    assert bad and bad[0].status == openers.FAILED


def test_a_control_whose_chain_reads_would_fail_the_opener(tmp_path, monkeypatch):
    """If the VM stopped declining the unmodelled call (it read it as a no-op), the control would print the chain
    case's key and arming must fail."""
    o = openers.for_lane("mobile-android")
    monkeypatch.setitem(fixtures.BUILDERS, "apk_analysis_unmodelled", F.BUILDERS["apk_analysis_chain"])
    r = openers.arm(o, workdir=tmp_path)
    assert r.status == openers.FAILED
    bad = [c for c in r.cases if c.fixture == "apk_analysis_unmodelled"]
    assert bad and bad[0].status == openers.FAILED


# --------------------------------------------------------------------------- trace and replay (ctf dexvm)

def test_trace_delivery_reports_the_verdict_and_the_armed_answer():
    t = R.trace_delivery(F.chain_apk())
    assert (t["verdict"], t["answer"], t["codes"]) == ("one-code", CHAIN, [CHAIN])
    t = R.trace_delivery(F.chain_apk(unmodelled=True, sample=True))
    assert t["verdict"] == "declined" and t["answer"] is None and t["codes"] == []
    assert any("Lcom/vendor/attest/Sdk;->verdict" in r for r in t["reasons"])
    assert t["unsure"] is None                                           # the placeholder is not even offered
    t = R.trace_delivery(F.chain_apk(twin_seed=9))
    assert t["verdict"] == "candidates" and t["answer"] is None
    t = R.trace_delivery(F.split_apk())
    assert t["verdict"] == "not-analysis" and t["entries"] == [] and t["answer"] == F.SPLIT_CODE
    t = R.trace_delivery(b"not a zip")
    assert t["verdict"] == "unreadable" and t["answer"] is None


def test_trace_delivery_reports_partial_with_each_records_dex_index():
    """One code beside a decline in a second dex: verdict `partial`, never plain, and each trace record names the dex
    member it came from (classes.dex is 0, classes2.dex is 1)."""
    files = _members(F.chain_apk())
    files["classes2.dex"] = _members(F.chain_apk(unmodelled=True, pkg="com/huntress/d23b"))["classes.dex"]
    t = R.trace_delivery(dexasm.apk(files))
    assert t["verdict"] == "partial" and t["codes"] == [CHAIN] and t["declines"] == 1
    assert t["answer"] is None and t["unsure"]["key"].endswith("#partial")
    assert [o[1] for o in t["unsure"]["options"]] == [CHAIN]
    assert [(e["dex"], e["entry"], e["outcome"]) for e in t["entries"]] == [
        (0, "Lcom/huntress/d23/Release;->code", "code"), (1, "Lcom/huntress/d23b/Release;->code", "decline")]


def _no_code_apk() -> bytes:
    """An `analysis` APK whose one entry references the "ANS-" literal and returns it: a string, but not a code."""
    d = dexasm.DexFile()
    cls = "Lcom/huntress/nc/Release;"
    c = dexasm.Code(regs=2, ins=0, outs=0)
    c.const_string(0, d.string("ANS-"))
    c.return_object(0)
    d.define(cls, [(d.method(cls, "code", "L"), c)])
    doc = {"schema": "huntress.mobile.puzzle.v2", "day": 23, "codec": "analysis"}
    return dexasm.apk({"classes.dex": d.build(), F.PUZZLE: json.dumps(doc).encode()})


def test_a_mobile_apk_routes_to_the_reader_before_its_trace(tmp_path):
    """Fix round 2: codec_search (the lane's reader, whose CLI reads a delivery) has a mobile .apk route at 25, so
    triage lists it first and the tracer (20) after it. Before, the tracer was the only mobile-APK route."""
    from ctf.engines import router
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "app.apk").write_bytes(F.chain_apk())
    ids = [h.manifest.id for h in router.route("mobile", "an android app", tmp_path / "files")]
    assert D.READER in ids and D.TRACER in ids
    assert ids.index(D.READER) < ids.index(D.TRACER)
    hit = {h.manifest.id: h for h in router.route("mobile", "", tmp_path / "files")}
    assert (hit[D.READER].priority, hit[D.TRACER].priority) == (25, 20)


def _no_entry_apk() -> bytes:
    """An `analysis` APK whose dex holds a method but no "ANS-" literal anywhere: no entry for the chain to run."""
    d = dexasm.DexFile()
    cls = "Lcom/huntress/ne/Release;"
    c = dexasm.Code(regs=2, ins=0, outs=0)
    c.const_string(0, d.string("hello"))
    c.return_object(0)
    d.define(cls, [(d.method(cls, "code", "L"), c)])
    doc = {"schema": "huntress.mobile.puzzle.v2", "day": 23, "codec": "analysis"}
    return dexasm.apk({"classes.dex": d.build(), F.PUZZLE: json.dumps(doc).encode()})


def test_an_analysis_dex_with_no_ans_entry_is_traced_as_no_entry():
    """Fix round 2: no method references an ANS literal, so nothing ran and nothing declined: `no-entry`, not
    `declined` (which says a method ran and the VM stopped somewhere dexvm show can name)."""
    t = R.trace_delivery(_no_entry_apk())
    assert (t["codec"], t["verdict"]) == ("analysis", "no-entry")
    assert (t["codes"], t["declines"], t["entries"], t["reasons"]) == ([], 0, [], [])
    assert t["answer"] is None and t["unsure"] is None


def test_an_entry_that_runs_to_no_code_is_traced_as_no_code():
    files = _members(_no_code_apk())
    trace = []
    assert dcc.analysis_codes_ex(files, _trace=trace) == ([], 1)
    assert [(e["entry"], e["outcome"]) for e in trace] == [("Lcom/huntress/nc/Release;->code", "no-code")]
    assert "returned str" in trace[0]["reason"]
    t = R.trace_delivery(_no_code_apk())
    assert t["verdict"] == "declined" and t["answer"] is None and t["unsure"] is None
    assert any("returned str" in r for r in t["reasons"])


# --------------------------------------------------------------------------- the live fix (day_patch.py)

def test_a_live_fix_reaches_every_delivery_shape(tmp_path, monkeypatch):
    """solve_delivery hears day_patch.py on a delivery solve_apk reads too, not only on the set path (fix round 1),
    and a live fix's answer for a declined chain is not withdrawn by the fail-closed rule."""
    fix = "ANS-00000000DA7FA7C4"
    seen = []
    patch = type("Patch", (), {"answer": staticmethod(lambda q, files, ctx: seen.append(ctx["delivery_name"]) or fix)})
    plain_apk = fixtures.build("apk_without_puzzle", tmp_path / "np").read_bytes()
    assert C.solve_delivery(plain_apk, "np.apk") is None                       # no fix: nothing
    monkeypatch.setattr(C, "_patch", patch)
    assert C.solve_delivery(plain_apk, "np.apk") == fix
    assert (C.LAST["confidence"], C.LAST["route"]) == ("day_patch", "day_patch.py live fix")
    assert C.solve_delivery(F.chain_apk(unmodelled=True, sample=True), "d23.apk") == fix
    assert C.LAST["route"] == "day_patch.py live fix"
    assert seen == ["np.apk", "d23.apk"]
    # a plain answer is not offered to answer(): the reader's own code stands
    assert C.solve_delivery(F.chain_apk(), "ok.apk") == CHAIN and seen == ["np.apk", "d23.apk"]


def test_a_live_fix_override_withdraws_a_plain_answer_on_the_apk_path(monkeypatch):
    calls = []

    def override(q, value, files, ctx):
        calls.append(value)
        return C.PATCH_WITHDRAW

    monkeypatch.setattr(C, "_patch", type("Patch", (), {"override": staticmethod(override)}))
    assert C.solve_delivery(F.split_apk(), "d05.apk") is None
    assert calls == [F.SPLIT_CODE] and C.LAST["route"] == "day_patch.py live fix"


def test_the_engine_cli_applies_a_day_patch_file(tmp_path):
    """The command line `ctf run` / `ctf arm` / `adapt prewarm` run, with a day_patch.py beside the solver (a copy of
    the solver folders, so the checkout's own folder never holds one)."""
    import shutil
    solvers = tmp_path / "copy" / "solvers"
    for d in ("mobile-android", "common"):
        shutil.copytree(REPO / "solvers" / d, solvers / d, ignore=shutil.ignore_patterns("__pycache__", "day_patch.py"))
    (solvers.parent / "ctf").symlink_to(REPO / "ctf")                # labels imports ctf from beside its solvers/
    (solvers / "mobile-android" / "day_patch.py").write_text(
        "def answer(q, files, ctx):\n    return 'ANS-00000000DA7FA7C4'\n")
    apk_path = fixtures.build("apk_without_puzzle", tmp_path / "in")
    r = subprocess.run([sys.executable, "-I", str(solvers / "mobile-android" / "codec_search.py"), str(apk_path)],
                       capture_output=True, text=True, timeout=120, env=_cli_env(tmp_path), cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr[-2000:]
    assert ": ANS-00000000DA7FA7C4  [day_patch] day_patch.py live fix" in r.stdout
    (solvers / "mobile-android" / "day_patch.py").unlink()
    r = subprocess.run([sys.executable, "-I", str(solvers / "mobile-android" / "codec_search.py"), str(apk_path)],
                       capture_output=True, text=True, timeout=120, env=_cli_env(tmp_path), cwd=str(tmp_path))
    assert "ANS-00000000DA7FA7C4" not in r.stdout and ": None  [none]" in r.stdout


# --------------------------------------------------------------------------- show and replay (ctf.dexvm, ctf dexvm)

def _builds(root: Path) -> Path:
    (root / "day-23").mkdir(parents=True)
    (root / "day-20").mkdir()
    (root / "day-23" / "release.apk").write_bytes(F.chain_apk())
    (root / "day-20" / "loaded_later.apk").write_bytes(F.loader_apk())
    (root / "day-20" / "notes.txt").write_text("not a build")
    return root


def test_read_line_reads_the_readers_answer_line():
    p = Path("/x/a.apk")
    out = "noise\n/x/a.apk: ANS-0011223344556677  [high] analysis dex chain (dex_chain_codec.py)\n"
    got = D.read_line(out, p)
    assert (got["answer"], got["confidence"], got["plain"]) == ("ANS-0011223344556677", "high", True)
    got = D.read_line("/x/a.apk: unsure ANS-0011223344556677 (key k)  [medium] apk-string\n", p)
    assert got["answer"] is None and got["plain"] is False and got["shown"].startswith("unsure")
    assert D.read_line("/x/b.apk: ANS-0011223344556677  [high] r\n", p)["plain"] is False   # another file's line


def test_find_builds_does_not_follow_a_symlink(tmp_path):
    root = _builds(tmp_path / "saved")
    outside = tmp_path / "elsewhere.apk"
    outside.write_bytes(F.chain_apk(F.CHAIN_VARIANT))
    (root / "day-23" / "linked.apk").symlink_to(outside)
    assert [p.relative_to(root).as_posix() for p in D.find_builds(root)] == [
        "day-20/loaded_later.apk", "day-23/release.apk"]


def test_a_build_past_the_size_cap_is_reported_not_read(tmp_path, monkeypatch):
    root = _builds(tmp_path / "saved")
    monkeypatch.setattr(D, "MAX_BUILD_BYTES", 16)
    ran = []
    monkeypatch.setattr(D._Runs, "run", lambda self, *a, **k: ran.append(a))
    rep = D.replay(root, workdir=tmp_path / "wd")
    assert ran == [] and not rep["ok"]
    assert [b["verdict"] for b in rep["builds"]] == ["unreadable", "unreadable"]
    assert "past the 16" in rep["failures"][0]["reasons"][0]


def test_replay_needs_every_unrecorded_build_plain(tmp_path):
    root = _builds(tmp_path / "saved")
    rep = D.replay(root, workdir=tmp_path / "wd")
    assert rep["ok"] and [b["path"] for b in rep["builds"]] == ["day-20/loaded_later.apk", "day-23/release.apk"]
    assert {b["answer"] for b in rep["builds"]} == {CHAIN, LOADER}
    (root / "day-20" / "broken.apk").write_bytes(F.loader_apk(with_payload=False))
    rep = D.replay(root, workdir=tmp_path / "wd")
    assert not rep["ok"] and [f["path"] for f in rep["failures"]] == ["day-20/broken.apk"]
    assert "asset not in this package" in " ".join(rep["failures"][0]["reasons"])   # the tracer's reason


def test_replay_fails_a_plain_line_from_a_reader_that_exited_non_zero(tmp_path, monkeypatch):
    """Fix round 2: an unrecorded build passes only when the reader printed a plain code AND exited 0. A reader that
    printed its line and then crashed (exit 1) did not answer: the build fails, is traced, and is never recorded."""
    root = tmp_path / "saved"
    root.mkdir()
    (root / "crash.apk").write_bytes(F.chain_apk())
    runs = []

    def run(self, engine, input_path, via):
        runs.append(engine)
        if engine == D.READER:
            return openers.EngineRun(1, f"{input_path}: {CHAIN}  [high] analysis dex chain (dex_chain_codec.py)\n",
                                     "Traceback (most recent call last): boom\n", 0.1)
        return openers.EngineRun(0, json.dumps({"verdict": "one-code", "reasons": []}) + "\n", "", 0.1)

    monkeypatch.setattr(D._Runs, "run", run)
    wd = tmp_path / "wd"
    rep = D.replay(root, workdir=wd, record=True)
    (b,) = rep["builds"]
    assert (b["plain"], b["answer"], b["exit"]) == (True, CHAIN, 1)          # the line read plain ...
    assert not rep["ok"] and [f["path"] for f in rep["failures"]] == ["crash.apk"]   # ... and still a failure
    assert rep["failures"][0]["why"].startswith("not answered plain")
    assert runs == [D.READER, D.TRACER] and rep["recorded"] == []
    assert regress.event_cases("mobile-android", wd) == []
    # control: the same line with exit 0 passes and is recorded
    monkeypatch.setattr(D._Runs, "run", lambda self, engine, input_path, via: openers.EngineRun(
        0, f"{input_path}: {CHAIN}  [high] analysis dex chain (dex_chain_codec.py)\n", "", 0.1))
    rep = D.replay(root, workdir=wd, record=True)
    assert rep["ok"] and len(rep["recorded"]) == 1


def test_replay_records_only_plain_builds_as_adapt_event_cases_and_holds_them(tmp_path):
    """--record writes B-036 event cases (so `adapt gate` replays them); a build not answered plain is never
    recorded; a recorded build is held to its accepted answer."""
    root = _builds(tmp_path / "saved")
    (root / "day-23" / "declined.apk").write_bytes(F.chain_apk(unmodelled=True, sample=True))
    wd = tmp_path / "wd"
    rep = D.replay(root, workdir=wd, record=True)
    assert [f["path"] for f in rep["failures"]] == ["day-23/declined.apk"]
    cases = regress.event_cases("mobile-android", wd)
    assert sorted(c.input.name for c in cases) == ["loaded_later.apk", "release.apk"]
    assert {c.expect for c in cases} == {(f": {CHAIN}  [high]",), (f": {LOADER}  [high]",)}
    assert all(c.engine == D.READER for c in cases)
    names = {c.name for c in regress.regression_set("mobile-android", workdir=wd)}
    assert {c.name for c in cases} <= names                                 # the lane gate's set holds them
    # a second record does not record again; recorded builds are now held to their case
    rep = D.replay(root, workdir=wd, record=True)
    assert rep["recorded"] == [] and rep["held"] == 2
    assert {b["path"]: b["held"] for b in rep["builds"]}["day-23/release.apk"].startswith("event:dexvm-")
    # the reader now prints something else for a held build: a regression, named
    case = next(c for c in cases if c.input.name == "release.apk")
    toml = case.input.parent.parent / "case.toml"
    toml.write_text(toml.read_text().replace(CHAIN, VARIANT))
    rep = D.replay(root, workdir=wd)
    why = {f["path"]: f["why"] for f in rep["failures"]}
    assert why["day-23/release.apk"].startswith("regressed") and VARIANT in why["day-23/release.apk"]
    assert CHAIN in why["day-23/release.apk"]


def test_show_runs_each_delivery_through_the_guarded_tracer_engine(tmp_path):
    good, bad = tmp_path / "good.apk", tmp_path / "bad.apk"
    good.write_bytes(F.loader_apk())
    bad.write_bytes(F.chain_apk(unmodelled=True))
    got = D.show([good, bad], workdir=tmp_path / "wd")
    assert [(t["verdict"], t["answer"]) for t in got] == [("one-code", LOADER), ("declined", None)]
    assert got[0]["entries"][0]["loaded_inmemory"] is True
    assert list((tmp_path / "wd").iterdir()) == []                      # the run folders are gone
    from ctf.intake import guard as G
    if G.os_sandbox()[0] is None:                                       # no OS sandbox here: `os` must refuse
        with pytest.raises(G.GuardError, match="OS sandbox is unavailable"):
            D.show([good], workdir=tmp_path / "wd", guard="os")
    with pytest.raises(D.DexvmError, match="missing.apk"):
        D.show([tmp_path / "missing.apk"], workdir=tmp_path / "wd")


def test_replay_errors_are_named(tmp_path):
    with pytest.raises(D.DexvmError, match="not found"):
        D.replay(tmp_path / "nope", workdir=tmp_path / "wd")
    (tmp_path / "empty").mkdir()
    with pytest.raises(D.DexvmError, match="no build"):
        D.replay(tmp_path / "empty", workdir=tmp_path / "wd")
    root = _builds(tmp_path / "saved")
    with pytest.raises(D.DexvmError, match="timeout"):
        D.replay(root, workdir=tmp_path / "wd", timeout=0)


def test_dexvm_show_cli(tmp_path):
    good, bad = tmp_path / "good.apk", tmp_path / "bad.apk"
    good.write_bytes(F.loader_apk())
    bad.write_bytes(F.chain_apk(unmodelled=True))
    r = _dexvm(tmp_path, "show", good)
    assert r.returncode == 0, r.stderr
    assert f"answer: {LOADER}  [plain]" in r.stdout and "in-memory dex loaded" in r.stdout
    r = _dexvm(tmp_path, "show", good, bad, "--json")
    assert r.returncode == 1, r.stderr
    got = json.loads(r.stdout)
    assert [t["verdict"] for t in got] == ["one-code", "declined"]
    assert got[1]["entries"][0]["outcome"] == "decline"
    r = _dexvm(tmp_path, "show", tmp_path / "missing.apk")
    assert r.returncode == 2 and "missing.apk" in r.stderr


def test_dexvm_replay_cli(tmp_path):
    root = _builds(tmp_path / "saved")
    r = _dexvm(tmp_path, "replay", root, "--record")
    assert r.returncode == 0, r.stderr
    assert "2 build(s), 0 failure(s)" in r.stdout and "recorded 2 event case(s)" in r.stdout
    assert len(regress.event_cases("mobile-android", tmp_path / "cli-work")) == 2
    (root / "day-20" / "loaded_later.apk").write_bytes(F.loader_apk(with_payload=False))
    r = _dexvm(tmp_path, "replay", root)
    assert r.returncode == 1 and "FAILED day-20/loaded_later.apk: not answered plain" in r.stdout
    r = _dexvm(tmp_path, "replay", tmp_path / "empty-nope")
    assert r.returncode == 2 and "not found" in r.stderr


def test_dexvm_replay_without_a_folder_names_the_variable(tmp_path):
    env = _cli_env(tmp_path)
    env.pop("CTF_REAL_CHALLENGES", None)
    r = _dexvm(tmp_path, "replay", env=env)
    assert r.returncode == 2 and "CTF_REAL_CHALLENGES" in r.stderr


def test_dexvm_replay_reads_the_saved_folder_from_the_variable(tmp_path):
    """No DIR: replay reads $CTF_REAL_CHALLENGES through ctf.paths; set to a missing folder it fails, naming it."""
    env = _cli_env(tmp_path)
    env["CTF_REAL_CHALLENGES"] = str(_builds(tmp_path / "saved"))
    r = _dexvm(tmp_path, "replay", env=env)
    assert r.returncode == 0, r.stderr
    assert "2 build(s), 0 failure(s)" in r.stdout
    env["CTF_REAL_CHALLENGES"] = str(tmp_path / "no-such-saved-tree")
    r = _dexvm(tmp_path, "replay", env=env)
    assert r.returncode == 2 and "not found" in r.stderr and "CTF_REAL_CHALLENGES" in r.stderr


def test_dexvm_without_an_event_fails_loudly(tmp_path):
    env = {k: v for k, v in _cli_env(tmp_path).items() if k not in ("CTF_WORKDIR", "CTF_EVENT")}
    r = _dexvm(tmp_path, "show", tmp_path / "x.apk", env=env)
    assert r.returncode == 2 and "event's workdir" in r.stderr and "CTF_EVENT" in r.stderr
