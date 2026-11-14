"""B-028: side-channel CPA over NPZ/NPY trace corpora (aligned, masked, 2nd-order).

Engine under test: solvers/common/cpa_npz.py (common.cpa_npz).

Every fixture is synthesised inside the test: a random key, random plaintexts, and
traces whose leak samples carry the modelled leakage plus Gaussian noise.  No real
challenge file is read.  numpy-dependent tests are marked ``needs_tool("py:numpy")`` and
the end-to-end decrypt test also needs ``py:Crypto`` so they report NOT RUN, never pass,
when the tool is absent.
"""
from __future__ import annotations

import os
import sys

import pytest

from ctf import event
from ctf.result import SolverResult

from solvers.common import cpa_npz

CSCTF = event.load("csctf")

# An obviously synthetic AES-128 key (a byte ramp), never a value from a real challenge.
SYNTH_KEY = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")

pytestmark = pytest.mark.needs_tool("py:numpy")


def _np():
    import numpy as np
    return np


# --------------------------------------------------------------- synthetic corpora


def _first_order_traces(np, key, sbox, n=400, noise=0.8, seed=1):
    """One leak sample per key byte: trace[:, b] = HW(sbox[p[:,b] ^ key[b]]) + noise."""
    rng = np.random.default_rng(seed)
    b = len(key)
    plains = rng.integers(0, 256, size=(n, b), dtype=np.uint8)
    hw = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)
    sbox_arr = np.array(sbox, dtype=np.int64)
    traces = rng.normal(0.0, noise, size=(n, b + 2))
    for byte in range(b):
        leak = hw[sbox_arr[(plains[:, byte].astype(np.int64)) ^ key[byte]]]
        traces[:, byte + 1] += leak            # column byte+1 leaks byte `byte`
    return traces, plains


def _masked_traces(np, key, sbox, n=3000, noise=0.25, seed=7, mask_gain=1.0, decoy=0.0):
    """Mask sample L0 = HW(m); byte sample Lj = HW(sbox[p^k] ^ m), with a fresh byte mask m.

    ``mask_gain`` scales the mask sample; ``decoy`` > 0 replaces the last column with pure
    noise of that standard deviation (top variance, no leakage).
    """
    rng = np.random.default_rng(seed)
    b = len(key)
    plains = rng.integers(0, 256, size=(n, b), dtype=np.uint8)
    masks = rng.integers(0, 256, size=n, dtype=np.int64)
    hw = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)
    sbox_arr = np.array(sbox, dtype=np.int64)
    s = b + 2
    traces = rng.normal(0.0, noise, size=(n, s))
    traces[:, 0] += mask_gain * hw[masks]                       # mask sample
    for byte in range(b):
        inter = sbox_arr[(plains[:, byte].astype(np.int64)) ^ key[byte]]
        traces[:, byte + 1] += hw[(inter ^ masks) & 0xFF]       # masked leak
    if decoy > 0:
        traces[:, s - 1] = rng.normal(0.0, decoy, size=n)      # high-variance, leak-free decoy
    return traces, plains


def _desync(np, traces, pad=10, spike=40.0, seed=13):
    """Random-delay each trace by 0..pad-1 samples behind a trigger spike."""
    rng = np.random.default_rng(seed)
    n, s = traces.shape
    out = np.zeros((n, s + pad))
    for i in range(n):
        shift = int(rng.integers(0, pad))
        out[i, shift] = spike
        out[i, shift + 1 : shift + 1 + s] = traces[i]
    return out


# ------------------------------------------------------------------- first order


def test_first_order_recovers_full_key():
    np = _np()
    key = bytes([0x2B, 0x7E, 0x15, 0x16])
    traces, plains = _first_order_traces(np, key, cpa_npz._AES_SBOX)
    recovered, detail = cpa_npz.cpa_first_order(traces, plains)
    assert recovered == key
    assert all(d["clean"] for d in detail)
    assert all(d["margin"] > 0.03 for d in detail)


def test_first_order_wrong_key_not_returned_on_noise_only():
    np = _np()
    rng = np.random.default_rng(3)
    plains = rng.integers(0, 256, size=(300, 2), dtype=np.uint8)
    traces = rng.normal(0.0, 1.0, size=(300, 4))     # pure noise: no leakage
    recovered, detail = cpa_npz.cpa_first_order(traces, plains)
    assert recovered is None                          # unique-best/margin rule declines
    assert not all(d["clean"] for d in detail)


def test_first_order_margin_rule_declines_ghost_key():
    """Two guesses both clear min_correlation but tie: the margin rule must decline.

    Under the identity S-box HW(p^k) and HW(p^~k) = 8 - HW(p^k) are perfectly
    anti-correlated, so k and k^0xff reach the same |corr|: a strong score with no margin.
    """
    np = _np()
    identity = tuple(range(256))
    key = bytes([0x3C])
    traces, plains = _first_order_traces(np, key, identity, n=600, noise=0.5, seed=4)
    recovered, detail = cpa_npz.cpa_first_order(traces, plains, sbox=identity)
    d = detail[0]
    assert d["score"] >= 0.2                          # passes min_correlation on its own
    assert d["margin"] < 0.03                         # but the ghost runner-up ties it
    assert d["key"] in (0x3C, 0x3C ^ 0xFF)
    assert recovered is None
    assert d["clean"] is False


def test_supplied_sbox_is_used():
    """A non-AES S-box in the file must drive the leakage model; the AES default fails."""
    np = _np()
    rng = np.random.default_rng(11)
    perm = np.array(rng.permutation(256), dtype=np.int64)       # a custom bijective S-box
    custom = tuple(int(v) for v in perm)
    key = bytes([0x41, 0x99])
    traces, plains = _first_order_traces(np, key, custom)
    with_custom, _ = cpa_npz.cpa_first_order(traces, plains, sbox=custom)
    with_default, _ = cpa_npz.cpa_first_order(traces, plains)   # AES S-box: wrong model
    assert with_custom == key
    assert with_default != key                                  # proves the file S-box mattered


# -------------------------------------------------------------- alignment & 2nd order


def test_align_traces_restores_first_order():
    """A random-delay trace is unrecoverable until aligned on the trigger argmax."""
    np = _np()
    key = bytes([0x10, 0x20])
    base, plains = _first_order_traces(np, key, cpa_npz._AES_SBOX, n=500, noise=0.5, seed=5)
    rng = np.random.default_rng(5)
    n, s = base.shape
    pad = 12
    des = np.zeros((n, s + pad))
    for i in range(n):
        shift = int(rng.integers(0, pad))
        des[i, shift] = 25.0                           # trigger spike inside the window
        des[i, shift + 1 : shift + 1 + s] = base[i]
    misaligned, _ = cpa_npz.cpa_first_order(des, plains)
    aligned = cpa_npz.align_traces(des, window=pad + 1)
    fixed, _ = cpa_npz.cpa_first_order(aligned, plains)
    assert misaligned != key                           # desync defeats raw CPA
    assert fixed == key                                # alignment recovers it


def test_leak_points_ranks_variable_samples():
    np = _np()
    rng = np.random.default_rng(2)
    traces = rng.normal(0.0, 0.01, size=(200, 10))
    traces[:, 4] += rng.integers(0, 100, size=200)     # high-variance sample
    traces[:, 7] += rng.integers(0, 50, size=200)
    pts = cpa_npz.leak_points(traces, limit=3)
    assert pts[0] == 4 and 7 in pts


def test_second_order_recovers_masked_key():
    np = _np()
    key = bytes([0x7A, 0xC5])
    traces, plains = _masked_traces(np, key, cpa_npz._AES_SBOX)
    # first order alone cannot see through the fresh mask
    first, _ = cpa_npz.cpa_first_order(traces, plains)
    assert first != key
    recovered, detail = cpa_npz.cpa_second_order(traces, plains)
    assert recovered == key
    assert all(d["mask_sample"] == 0 for d in detail)  # the mask sample is column 0


def test_second_order_joint_search_skips_high_variance_decoy():
    """The mask sample is not the top-variance column: the joint mask-sample search must
    still find it (a search on the decoy alone recovers nothing)."""
    np = _np()
    key = bytes([0x7A, 0xC5])
    traces, plains = _masked_traces(np, key, cpa_npz._AES_SBOX, mask_gain=1.5, decoy=20.0)
    pts = cpa_npz.leak_points(traces)
    assert pts[0] == traces.shape[1] - 1 and pts[1] == 0   # decoy first, mask second
    recovered, detail = cpa_npz.cpa_second_order(traces, plains)
    assert recovered == key
    assert all(d["mask_sample"] == 0 for d in detail)
    only_decoy, _ = cpa_npz.cpa_second_order(traces, plains, points=[pts[0]])
    assert only_decoy != key


def test_second_order_narrowed_partners_still_recover():
    """On a trace wider than MAX_SECOND_ORDER_TARGETS only the top-variance partners are
    combined with the mask sample; the key and mask sample survive the narrowing."""
    np = _np()
    key = bytes([0x11, 0xE7])
    narrow, plains = _masked_traces(np, key, cpa_npz._AES_SBOX, n=2500, seed=17)
    rng = np.random.default_rng(17)
    width = cpa_npz.MAX_SECOND_ORDER_TARGETS + 40
    wide = rng.normal(0.0, 0.05, size=(narrow.shape[0], width))   # idle, low-variance samples
    # the masked block sits past column MAX_SECOND_ORDER_TARGETS: taking the first 256
    # columns as partners (not the top-variance ones) would drop every leak sample
    start = width - 10
    assert start >= cpa_npz.MAX_SECOND_ORDER_TARGETS
    wide[:, start : start + narrow.shape[1]] = narrow
    recovered, detail = cpa_npz.cpa_second_order(wide, plains, points=cpa_npz.leak_points(wide, limit=8))
    assert recovered == key
    # mask x leak and leak x mask are the same product, so either end may be reported
    assert all(start <= d["mask_sample"] < start + narrow.shape[1] for d in detail)
    assert all(d["partners"] == cpa_npz.MAX_SECOND_ORDER_TARGETS for d in detail)
    _, full = cpa_npz.cpa_second_order(narrow, plains)
    assert all(d["partners"] == narrow.shape[1] for d in full)   # narrow traces: every sample


# ------------------------------------------------------------------------ loading


def test_load_corpus_detects_named_arrays(tmp_path):
    np = _np()
    traces = np.zeros((5, 8), dtype=np.float32)
    plains = np.zeros((5, 16), dtype=np.uint8)
    sbox = np.array(cpa_npz._AES_SBOX, dtype=np.uint8)
    p = tmp_path / "traces.npz"
    np.savez(p, traces=traces, plaintexts=plains, sbox=sbox)
    t, pl, sb = cpa_npz.load_corpus(p)
    assert t.shape == (5, 8) and pl.shape == (5, 16)
    assert sb == cpa_npz._AES_SBOX


def test_load_corpus_detects_by_shape_without_names(tmp_path):
    np = _np()
    p = tmp_path / "unnamed.npz"
    np.savez(p, arr_0=np.zeros((6, 20), dtype=np.float64), arr_1=np.zeros((6, 4), dtype=np.uint8))
    t, pl, sb = cpa_npz.load_corpus(p)
    assert t.shape == (6, 20) and pl.shape == (6, 4) and sb is None


def test_load_corpus_rejects_count_mismatch(tmp_path):
    np = _np()
    p = tmp_path / "bad.npz"
    np.savez(p, traces=np.zeros((5, 8)), plaintexts=np.zeros((4, 2), dtype=np.uint8))
    with pytest.raises(cpa_npz.CorpusError):
        cpa_npz.load_corpus(p)


def test_load_corpus_rejects_non_finite(tmp_path):
    np = _np()
    t = np.zeros((4, 8)); t[0, 0] = np.inf
    p = tmp_path / "inf.npz"
    np.savez(p, traces=t, plaintexts=np.zeros((4, 2), dtype=np.uint8))
    with pytest.raises(cpa_npz.CorpusError):
        cpa_npz.load_corpus(p)


def test_load_corpus_missing_plaintexts(tmp_path):
    np = _np()
    p = tmp_path / "only.npz"
    np.savez(p, traces=np.zeros((4, 8)))
    with pytest.raises(cpa_npz.CorpusError):
        cpa_npz.load_corpus(p)


def test_load_corpus_ignores_non_bijective_sbox(tmp_path):
    """A 256-entry array named sbox that is not a permutation is not an S-box."""
    np = _np()
    bogus = (np.arange(256, dtype=np.int64) // 2).astype(np.uint8)   # in range, values repeat
    p = tmp_path / "traces.npz"
    np.savez(p, traces=np.zeros((5, 8)), plaintexts=np.zeros((5, 2), dtype=np.uint8), sbox=bogus)
    _, _, sb = cpa_npz.load_corpus(p)
    assert sb is None


def test_find_corpus_npy_pair_picks_traces_not_plaintexts(tmp_path):
    """plaintexts.npy sorts first and contains the letter 't'; traces.npy must still win."""
    np = _np()
    np.save(tmp_path / "plaintexts.npy", np.zeros((4, 2), dtype=np.uint8))
    np.save(tmp_path / "traces.npy", np.zeros((4, 8)))
    assert cpa_npz._find_corpus(tmp_path).name == "traces.npy"


def test_find_corpus_lone_plaintexts_npy_is_not_traces(tmp_path):
    np = _np()
    np.save(tmp_path / "plaintexts.npy", np.zeros((4, 2), dtype=np.uint8))
    assert cpa_npz._find_corpus(tmp_path) is None


def test_solve_float_data_npy_is_traces_with_pt_sibling(tmp_path):
    """``data`` is also a plaintext name, but a float data.npy is the traces; its plaintexts
    sit in pt.npy (a short name the sibling lookup must know)."""
    np = _np()
    key = bytes([0x2B, 0x7E, 0x15, 0x16])
    traces, plains = _first_order_traces(np, key, cpa_npz._AES_SBOX, n=500, noise=0.6, seed=9)
    ch = tmp_path / "datanpy"
    ch.mkdir()
    np.save(ch / "data.npy", traces)
    np.save(ch / "pt.npy", plains)
    assert cpa_npz._find_corpus(ch).name == "data.npy"
    res = cpa_npz.solve(ch, CSCTF, challenge_id="datanpy")
    assert res.status == "candidate", res.notes
    assert res.flags == (key.hex(),)


def test_find_corpus_prefers_widest_float_npy(tmp_path):
    """With no trace-named file, the widest float 2-D array is the traces, whatever its name."""
    np = _np()
    np.save(tmp_path / "aaa_meta.npy", np.zeros((4, 3), dtype=np.float64))
    np.save(tmp_path / "capture.npy", np.zeros((4, 50), dtype=np.float32))
    np.save(tmp_path / "inputs.npy", np.zeros((4, 16), dtype=np.uint8))
    assert cpa_npz._find_corpus(tmp_path).name == "capture.npy"


def test_load_corpus_float_data_key_is_not_plaintexts(tmp_path):
    """An NPZ whose float traces are stored under ``data`` keeps them as traces; the integer
    array is the plaintexts."""
    np = _np()
    p = tmp_path / "capture.npz"
    np.savez(p, data=np.zeros((6, 20), dtype=np.float32), arr_1=np.ones((6, 4), dtype=np.uint8))
    t, pl, _ = cpa_npz.load_corpus(p)
    assert t.shape == (6, 20) and pl.shape == (6, 4)
    assert int(pl[0, 0]) == 1


# ------------------------------------------------------------ script entry & routing


def test_main_prints_solver_result_for_a_corpus_file(tmp_path, capsys):
    """Triage prints `python cpa_npz.py <file>`: the script must take the corpus file, use
    its folder, and print a SolverResult JSON line."""
    np = _np()
    key = bytes([0x01, 0x02, 0x03, 0x04])
    ch = tmp_path / "cli"
    ch.mkdir()
    _write_corpus(np, str(ch), key, cpa_npz._AES_SBOX, include_sbox=False)
    code = cpa_npz.main([str(ch / "traces.npz"), "--event", "csctf", "--opt", "order=first"])
    out = capsys.readouterr().out.strip().splitlines()[-1]
    res = SolverResult.from_json(out)
    assert code == 0
    assert res.status == "candidate" and res.flags == (key.hex(),)
    assert cpa_npz.main([str(tmp_path / "missing.npz"), "--event", "csctf"]) == 2
    assert cpa_npz.main(["--opt", "order"]) == 2


def test_script_run_bootstraps_ctf_import(tmp_path):
    """Run as a plain script (no checkout root on sys.path), the module must still import
    the ctf package and answer."""
    import subprocess
    from ctf import paths

    np = _np()
    key = bytes([0x01, 0x02, 0x03, 0x04])
    ch = tmp_path / "script"
    ch.mkdir()
    _write_corpus(np, str(ch), key, cpa_npz._AES_SBOX, include_sbox=False)
    script = paths.repo_root() / "solvers" / "common" / "cpa_npz.py"
    proc = subprocess.run([sys.executable, "-I", str(script), str(ch), "--event", "csctf"],
                          cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    res = SolverResult.from_json(proc.stdout.strip().splitlines()[-1])
    assert res.flags == (key.hex(),)


def test_cpa_keywords_route_to_runnable_engine():
    """A CPA keyword with no corpus downloaded yet must suggest this runnable engine, not the
    import-only sidechannel_offline library."""
    from ctf import triage

    s = triage.suggest("crypto", "We captured a power trace of the AES unit; recover the key with cpa")
    by_id = {r["id"]: r for r in s["routes"]}
    assert "common.cpa_npz" in by_id
    assert by_id["common.cpa_npz"]["class"] == "executes"
    assert "common.sidechannel_offline" not in by_id


# -------------------------------------------------------------- end-to-end engine


def _write_corpus(np, folder, key, sbox, include_sbox):
    traces, plains = _first_order_traces(np, key, sbox, n=500, noise=0.6, seed=9)
    arrays = {"traces": traces.astype(np.float32), "plaintexts": plains}
    if include_sbox:
        arrays["sbox"] = np.array(sbox, dtype=np.uint8)
    np.savez(os.path.join(folder, "traces.npz"), **arrays)
    return traces, plains


@pytest.mark.needs_tool("py:numpy", "py:Crypto")
def test_solve_opens_sealed_blob(tmp_path):
    """Full path: recover the key, decrypt the sealed AES-CTR blob, return the flag."""
    np = _np()
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    key = SYNTH_KEY
    ch = tmp_path / "synthetic-ctr"
    ch.mkdir()
    _write_corpus(np, str(ch), key, cpa_npz._AES_SBOX, include_sbox=False)
    flag = b"CSCTF{synthetic_first_order_fixture}"
    ctr = Counter.new(128, initial_value=0)
    blob = AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(flag)
    (ch / "sealed.hex").write_text(blob.hex())

    res = cpa_npz.solve(ch, CSCTF, challenge_id="synthetic")
    assert isinstance(res, SolverResult)
    assert res.status == "solved"
    assert res.flags == (flag.decode(),)
    assert any(e.kind == "decrypt" for e in res.evidence)


def test_solve_npy_pair_recovers_key(tmp_path):
    """A two-file .npy corpus (traces.npy + plaintexts.npy) solves end to end."""
    np = _np()
    key = bytes([0x2B, 0x7E, 0x15, 0x16])
    traces, plains = _first_order_traces(np, key, cpa_npz._AES_SBOX, n=500, noise=0.6, seed=9)
    ch = tmp_path / "npy"
    ch.mkdir()
    np.save(ch / "traces.npy", traces)
    np.save(ch / "plaintexts.npy", plains)
    res = cpa_npz.solve(ch, CSCTF, challenge_id="npy")
    assert res.status == "candidate", res.notes
    assert res.flags == (key.hex(),)
    assert "corpus traces.npy" in res.notes


@pytest.mark.needs_tool("py:numpy", "py:Crypto")
def test_solve_masked_desynced_falls_back_to_second_order(tmp_path):
    """Random delay + fresh Boolean mask, AES-128-CTR sealed blob (the masked-relay shape).

    First order fails, so solve() must see the trigger spike, align, run second order on
    its own, then open the blob to the flag.
    """
    np = _np()
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    key = SYNTH_KEY
    masked, plains = _masked_traces(np, key, cpa_npz._AES_SBOX, n=3000, seed=29)
    traces = _desync(np, masked)
    first, _ = cpa_npz.cpa_first_order(traces, plains)
    assert first is None                               # the fallback is really exercised
    ch = tmp_path / "synthetic-masked"
    ch.mkdir()
    np.savez(ch / "traces.npz", traces=traces.astype(np.float32), plaintexts=plains)
    flag = b"CSCTF{synthetic_masked_fixture}"
    blob = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=0)).encrypt(flag)
    (ch / "sealed.hex").write_text(blob.hex())

    res = cpa_npz.solve(ch, CSCTF, challenge_id="synthetic")
    assert res.status == "solved", res.notes
    assert res.flags == (flag.decode(),)
    assert "second-order (aligned, masked)" in res.notes
    assert "spike found: aligned first" in res.notes
    assert any(e.kind == "decrypt" for e in res.evidence)


def _aligned_masked_no_trigger(np, key, n=3000, width=40, mask_col=20, seed=31):
    """An already-aligned masked corpus: idle noise up front (no trigger spike), the mask
    sample at ``mask_col`` and byte b's masked leak at ``mask_col + 2 + b``."""
    rng = np.random.default_rng(seed)
    masked, plains = _masked_traces(np, key, cpa_npz._AES_SBOX, n=n, seed=seed)
    traces = rng.normal(0.0, 0.25, size=(n, width))
    traces[:, mask_col] = masked[:, 0]
    for b in range(len(key)):
        traces[:, mask_col + 2 + b] = masked[:, b + 1]
    return traces, plains


def test_has_trigger_sees_spike_not_noise():
    np = _np()
    key = bytes([0x7A, 0xC5])
    masked, _ = _masked_traces(np, key, cpa_npz._AES_SBOX, n=500, seed=3)
    assert cpa_npz.has_trigger(_desync(np, masked)) is True
    plain, _ = _aligned_masked_no_trigger(np, key, n=500)
    assert cpa_npz.has_trigger(plain) is False


def test_solve_aligned_masked_without_trigger_keeps_alignment(tmp_path):
    """An aligned masked corpus has no trigger: aligning on the argmax of its noisy leading
    window would shift rows at random and lose the key, so solve() must run raw first."""
    np = _np()
    key = bytes([0x3D, 0x91, 0x5E, 0xA8])
    traces, plains = _aligned_masked_no_trigger(np, key)
    assert cpa_npz.cpa_first_order(traces, plains)[0] is None          # needs second order
    shuffled, _ = cpa_npz.cpa_second_order(cpa_npz.align_traces(traces), plains)
    assert shuffled != key                             # blind alignment really destroys it
    ch = tmp_path / "aligned-masked"
    ch.mkdir()
    np.savez(ch / "traces.npz", traces=traces, plaintexts=plains)
    res = cpa_npz.solve(ch, CSCTF, challenge_id="synthetic")
    assert res.status == "candidate", res.notes
    assert res.flags == (key.hex(),)
    assert "second-order (raw, masked)" in res.notes
    assert "spike absent: raw first" in res.notes


def test_solve_falls_back_to_raw_when_a_glitch_fakes_a_trigger(tmp_path):
    """A random-position glitch in the leading window looks like a trigger, so aligned runs
    first and fails (the data was already aligned); solve() must then try the raw traces."""
    np = _np()
    key = bytes([0x3D, 0x91, 0x5E, 0xA8])
    traces, plains = _aligned_masked_no_trigger(np, key)
    rng = np.random.default_rng(37)
    traces[np.arange(traces.shape[0]), rng.integers(0, 10, size=traces.shape[0])] += 40.0
    assert cpa_npz.has_trigger(traces) is True
    ch = tmp_path / "glitch"
    ch.mkdir()
    np.savez(ch / "traces.npz", traces=traces, plaintexts=plains)
    res = cpa_npz.solve(ch, CSCTF, challenge_id="synthetic")
    assert "spike found: aligned first" in res.notes
    assert res.status == "candidate", res.notes
    assert res.flags == (key.hex(),)
    assert "second-order (raw, masked)" in res.notes


def test_solve_align_option_forces_one_variant(tmp_path):
    """align=false (a string, as `ctf run --opt` passes it) must not align, so a desynced
    masked corpus is not recovered; align=true must align; a bad value is named."""
    np = _np()
    key = bytes([0x7A, 0xC5])
    masked, plains = _masked_traces(np, key, cpa_npz._AES_SBOX, n=3000, seed=29)
    ch = tmp_path / "desync"
    ch.mkdir()
    np.savez(ch / "traces.npz", traces=_desync(np, masked), plaintexts=plains)
    raw_only = cpa_npz.solve(ch, CSCTF, align="false")
    assert raw_only.status == "none", raw_only.notes
    forced = cpa_npz.solve(ch, CSCTF, align="true")
    assert forced.status == "candidate" and forced.flags == (key.hex(),), forced.notes
    bad = cpa_npz.solve(ch, CSCTF, align="maybe")
    assert bad.status == "blocked" and "align option" in bad.notes


def test_solve_names_missing_crypto_when_blob_present(tmp_path, monkeypatch):
    """Without pycryptodome a sealed blob cannot be tried: say so by name, keep the key."""
    np = _np()
    key = bytes([0x01, 0x02, 0x03, 0x04])
    ch = tmp_path / "nocrypto"
    ch.mkdir()
    _write_corpus(np, str(ch), key, cpa_npz._AES_SBOX, include_sbox=False)
    (ch / "sealed.hex").write_text("00" * 32)
    for mod in ("Crypto", "Crypto.Cipher", "Crypto.Util"):
        monkeypatch.setitem(sys.modules, mod, None)
    res = cpa_npz.solve(ch, CSCTF, challenge_id="x")
    assert res.status == "candidate"
    assert res.flags == (key.hex(),)
    assert "py:Crypto" in res.notes
    assert "needs the decrypt mode" not in res.notes
    with pytest.raises(cpa_npz.MissingTool):
        cpa_npz.open_with_key(ch, key, CSCTF)


def test_solve_candidate_when_no_blob(tmp_path):
    """Key recovered but nothing to open: a candidate (the key), never a false 'solved'."""
    np = _np()
    key = bytes([0x01, 0x02, 0x03, 0x04])
    ch = tmp_path / "ch"
    ch.mkdir()
    _write_corpus(np, str(ch), key, cpa_npz._AES_SBOX, include_sbox=False)
    res = cpa_npz.solve(ch, CSCTF, challenge_id="x")
    assert res.status == "candidate"
    assert res.flags == (key.hex(),)


def test_solve_none_without_corpus(tmp_path):
    ch = tmp_path / "empty"
    ch.mkdir()
    (ch / "readme.txt").write_text("no traces here")
    res = cpa_npz.solve(ch, CSCTF)
    assert res.status == "none"
    assert "no .npz" in res.notes


def test_solve_uses_file_sbox_for_9153_shape(tmp_path):
    """9153 ships the S-box in the NPZ; solve must take it and recover the code bytes."""
    np = _np()
    rng = np.random.default_rng(21)
    custom = tuple(int(v) for v in rng.permutation(256))
    key = bytes([0x66, 0x33, 0x77])               # printable-ish 'code bytes'
    ch = tmp_path / "9153"
    ch.mkdir()
    _write_corpus(np, str(ch), key, custom, include_sbox=True)
    res = cpa_npz.solve(ch, CSCTF, challenge_id="9153")
    assert res.status in ("candidate", "solved")
    assert key.hex() in res.flags or key.decode("latin-1") in res.flags


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
