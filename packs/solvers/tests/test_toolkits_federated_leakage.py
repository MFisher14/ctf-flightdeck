"""B-092: gradient-inversion / federated-leakage solver (solvers/toolkits/federated_leakage.py).

Every fixture is synthesised here: a small dense net with random weights, one training sample, and
the update that sample produces, computed by this file's own backward pass (never by the engine's).
No real challenge file is read and nothing is executed. Texts and flags are obviously synthetic.
"""
from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import event
from ctf.result import SolverResult
from solvers.toolkits import federated_leakage as fl

REPO = Path(__file__).resolve().parents[1]
CSCTF = event.load("csctf")
FF = fl.flagfmt.for_profile(CSCTF)
FLAG = b"CSCTF{synthetic_update_leak_0a1b2c}"

pytestmark = pytest.mark.needs_tool("py:numpy")


def _np():
    import numpy as np
    return np


# ---- a synthetic net and its single-sample update (independent of the engine) ---------------------------

ACT = {"relu": (lambda np, z: np.maximum(z, 0.0), lambda np, z: (z > 0).astype(float)),
       "tanh": (lambda np, z: np.tanh(z), lambda np, z: 1.0 - np.tanh(z) ** 2),
       "sigmoid": (lambda np, z: 1.0 / (1.0 + np.exp(-z)), None),
       "linear": (lambda np, z: z, None)}


def _net(np, dims, seed, bias=True):
    rng = np.random.default_rng(seed)
    Ws = [rng.normal(0.0, 0.4, size=(dims[i + 1], dims[i])) for i in range(len(dims) - 1)]
    bs = [rng.normal(0.0, 0.2, size=dims[i + 1]) if bias else np.zeros(dims[i + 1]) for i in range(len(dims) - 1)]
    return Ws, bs


def _loss(np, Ws, bs, x, label, act="relu"):
    a = x
    for k, (W, b) in enumerate(zip(Ws, bs)):
        z = W @ a + b
        a = ACT[act][0](np, z) if k < len(Ws) - 1 else z
    return float(np.log(np.exp(a - a.max()).sum()) + a.max() - a[label])


def _update(np, Ws, bs, x, label, act="relu"):
    """(dW per layer, db per layer) of softmax cross-entropy for the one sample (x, label)."""
    f, df = ACT[act]
    acts, zs, a = [x], [], x
    for k, (W, b) in enumerate(zip(Ws, bs)):
        z = W @ a + b
        zs.append(z)
        a = f(np, z) if k < len(Ws) - 1 else z
        acts.append(a)
    p = np.exp(zs[-1] - zs[-1].max())
    p /= p.sum()
    delta = p.copy()
    delta[label] -= 1.0
    gW, gb = [None] * len(Ws), [None] * len(Ws)
    for k in range(len(Ws) - 1, -1, -1):
        gW[k], gb[k] = np.outer(delta, acts[k]), delta.copy()
        if k:
            delta = (Ws[k].T @ delta) * df(np, zs[k - 1])
    return gW, gb


def _text_input(np, text: bytes, width: int, scale: float = 255.0):
    x = np.zeros(width)
    x[:len(text)] = np.frombuffer(text, dtype=np.uint8) / scale
    return x


def _case(np, dims=(40, 24, 6), seed=1, text=FLAG, label=2, bias=True, act="relu"):
    Ws, bs = _net(np, dims, seed, bias=bias)
    x = _text_input(np, text, dims[0])
    gW, gb = _update(np, Ws, bs, x, label, act)
    return Ws, bs, x, gW, gb


def _save(folder: Path, name: str = "update.npz", **arrays) -> Path:
    np = _np()
    folder.mkdir(parents=True, exist_ok=True)
    np.savez(folder / name, **arrays)
    return folder / name


def _f32(np, a):
    return a.astype(np.float32)


# ---- the closed form: W[i] / b[i], agreement across units -----------------------------------------------

def test_ratio_recovers_the_input_and_skips_dead_units():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    dead = int((gb[0] == 0).sum())
    assert 0 < dead < len(gb[0])                              # the fixture has dead ReLU units: b == 0 there
    fit = fl.ratio_recover(gW[0], gb[0])
    assert np.allclose(fit.x, x, atol=1e-12)
    assert fit.live == len(gb[0]) - dead and fit.agree == fit.live
    assert fit.spread < 1e-9


def test_ratio_declines_a_batch_of_two_samples():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    gW2, gb2 = _update(np, Ws, bs, _text_input(np, b"another training sample entirely", 40), 4)
    with pytest.raises(fl.NoLeak, match="ratios disagree") as e:
        fl.ratio_recover(gW[0] + gW2[0], gb[0] + gb2[0])
    assert 0.0 <= e.value.share < fl.MIN_SHARE


def test_ratio_declines_model_weights_zero_bias_and_zero_rows():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    with pytest.raises(fl.NoLeak, match="ratios disagree"):
        fl.ratio_recover(Ws[0], bs[0])                        # weights are not an update
    with pytest.raises(fl.NoLeak, match="bias update is all zero"):
        fl.ratio_recover(gW[0], np.zeros(24))
    with pytest.raises(fl.NoLeak, match="ratio is zero"):
        fl.ratio_recover(np.zeros((24, 40)), gb[0])
    with pytest.raises(fl.NoLeak, match="not a"):
        fl.ratio_recover(gW[0], gb[1])                        # 24 units against a 6-long bias


def test_ratio_drops_an_outlier_unit_but_not_a_third_of_them():
    np = _np()
    rng = np.random.default_rng(5)
    x = rng.uniform(0.1, 0.9, size=12)
    delta = rng.uniform(0.5, 1.5, size=10)
    W = np.outer(delta, x)
    one_bad = W.copy()
    one_bad[3] += rng.normal(0, 0.3, size=12)
    fit = fl.ratio_recover(one_bad, delta)
    assert (fit.live, fit.agree) == (10, 9)
    assert np.allclose(fit.x, x, atol=1e-12)                  # the outlier is not averaged in
    three_bad = one_bad.copy()
    three_bad[5] += rng.normal(0, 0.3, size=12)
    three_bad[8] += rng.normal(0, 0.3, size=12)
    with pytest.raises(fl.NoLeak, match="7 of 10"):
        fl.ratio_recover(three_bad, delta)
    assert fl.ratio_recover(three_bad, delta, min_share=0.6).agree == 7


def test_ratio_weighs_units_by_their_bias_so_weak_units_do_not_add_their_noise():
    """One strong unit and twenty weak ones under the same absolute rounding noise (what a difference
    of float32 weights looks like): every weak ratio is 50 times noisier. The answer is the least
    squares fit, which the strong unit carries; a plain median of the ratios is ten times worse."""
    np = _np()
    rng = np.random.default_rng(8)
    x = rng.uniform(0.2, 0.9, size=12)
    delta = np.array([1.0] + [0.02] * 20)
    W = np.outer(delta, x) + rng.uniform(-1e-4, 1e-4, size=(21, 12))
    fit = fl.ratio_recover(W, delta)
    assert fit.agree == 21
    assert float(np.abs(fit.x - x).max()) < 2e-4
    assert float(np.abs(np.median(W / delta[:, None], axis=0) - x).max()) > 5e-4


def test_ratio_ignores_a_unit_whose_bias_is_numerically_dead():
    np = _np()
    rng = np.random.default_rng(6)
    x = rng.uniform(0.1, 0.9, size=8)
    delta = np.array([1.0, 0.7, -0.4, 1e-9])                  # the last is far under LIVE_REL of the largest
    W = np.outer(delta, x)
    W[3] = rng.normal(0, 1e-9, size=8)                        # rounding noise, as large as its signal
    fit = fl.ratio_recover(W, delta)
    assert fit.live == 3 and np.allclose(fit.x, x, atol=1e-12)


def test_ratio_with_one_live_unit_reports_one():
    np = _np()
    x = np.linspace(0.1, 0.8, 6)
    delta = np.array([0.0, 0.5, 0.0])
    fit = fl.ratio_recover(np.outer(delta, x), delta)
    assert (fit.live, fit.agree) == (1, 1) and np.allclose(fit.x, x)


def test_ratio_tolerance_is_the_callers():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    W32, b32 = _f32(np, gW[0]), _f32(np, gb[0])
    assert np.allclose(fl.ratio_recover(W32, b32).x, x, atol=1e-6)        # float32 rounding sits inside the default
    with pytest.raises(fl.NoLeak, match="ratios disagree"):
        fl.ratio_recover(W32, b32, tol=1e-12)


def test_ratio_two_live_units_that_disagree_are_declined():
    """Two live units are the fewest the agreement check runs on: two that disagree (a two-sample
    batch where only two hidden units fired) must not pass for one input."""
    np = _np()
    x1 = np.linspace(0.1, 0.8, 6)
    x2 = x1[::-1].copy()
    delta = np.array([0.0, 0.6, -0.9, 0.0])
    W = np.zeros((4, 6))
    W[1], W[2] = 0.6 * x1, -0.9 * x2                          # unit 1 saw sample one, unit 2 sample two
    with pytest.raises(fl.NoLeak, match="ratios disagree \\(0 of 2 live units") as e:
        fl.ratio_recover(W, delta)
    assert e.value.share == 0.0
    W[2] = -0.9 * x1                                          # the same two units, one sample: accepted
    fit = fl.ratio_recover(W, delta)
    assert (fit.live, fit.agree) == (2, 2) and np.allclose(fit.x, x1, atol=1e-12)


def test_ratio_default_tolerance_rejects_a_near_miss():
    """A unit off by 3 % of max|x| is a different sample, not rounding: the default (1 %) leaves it out."""
    np = _np()
    rng = np.random.default_rng(9)
    x = rng.uniform(0.1, 0.9, size=12)
    delta = rng.uniform(0.5, 1.5, size=10)
    W = np.outer(delta, x)
    off = np.zeros(12)
    off[4] = 0.03 * float(np.abs(x).max())
    W[6] = delta[6] * (x + off)
    fit = fl.ratio_recover(W, delta)
    assert (fit.live, fit.agree) == (10, 9)
    assert np.allclose(fit.x, x, atol=1e-12) and fit.spread < 1e-12
    loose = fl.ratio_recover(W, delta, tol=0.05)              # it is a near miss: a looser tol takes it in
    assert loose.agree == 10 and loose.spread == pytest.approx(0.03, rel=1e-9)


# ---- pairs by shape, never by name; first layer first ---------------------------------------------------

def test_recover_finds_the_pair_whatever_the_names_and_order():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    arrays = {"arr_0": gb[1], "arr_1": Ws[1], "arr_2": gW[1], "arr_3": bs[0], "arr_4": gb[0], "arr_5": Ws[0],
              "arr_6": gW[0], "arr_7": bs[1]}
    recs, notes = fl.recover(arrays)
    first = recs[0]
    assert (first.w.name, first.b.name, first.layout) == ("arr_6", "arr_4", "rows")
    assert first.head and first.confirmed and first.scale_known and first.sign_known
    assert np.allclose(first.x, x, atol=1e-12)
    assert [(r.w.name, r.b.name) for r in recs] == [("arr_6", "arr_4"), ("arr_2", "arr_0")]   # nothing else agrees
    assert not recs[1].head and recs[1].in_dim == 24          # the second layer leaks hidden activations


def test_recover_reads_an_inputs_by_units_matrix():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    recs, _ = fl.recover({"kernel_grad": gW[0].T.copy(), "bias_grad": gb[0]})
    assert recs[0].layout == "columns" and recs[0].out_dim == 24
    assert np.allclose(recs[0].x, x, atol=1e-12)


def test_first_layer_wins_even_when_the_hidden_layer_is_wider_and_stored_first():
    np = _np()
    Ws, bs, x, gW, gb = _case(np, dims=(36, 64, 6), seed=3)
    recs, _ = fl.recover({"g_w2": gW[1], "g_b2": gb[1], "g_w1": gW[0], "g_b1": gb[0]})
    assert [r.in_dim for r in recs] == [36, 64]               # not the widest input, not archive order
    assert [r.head for r in recs] == [True, False]
    fl.decode(recs[0], FF)
    assert recs[0].decodes[0][2] == (FLAG.decode(),)


def test_model_weights_alone_recover_nothing_and_name_the_near_miss():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    recs, notes = fl.recover({"W1": Ws[0], "b1": bs[0], "W2": Ws[1], "b2": bs[1]})
    assert recs == []
    assert any("no (W, b) pair agreed; nearest:" in n and "ratios disagree" in n for n in notes)
    recs, notes = fl.recover({"v": bs[0], "w": bs[1]})
    assert recs == [] and notes == ["no 2-D numeric array: not a model update"]


@pytest.mark.parametrize("order", ["old-first", "new-first", "mixed"])
def test_old_and_new_weights_are_differenced(order):
    """A client that sends back new weights: the update is new - old, float32 as shipped."""
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    lr = 0.05
    old_w, old_b = _f32(np, Ws[0]), _f32(np, bs[0])
    new_w, new_b = _f32(np, Ws[0] - lr * gW[0]), _f32(np, bs[0] - lr * gb[0])
    arrays = {"old-first": {"w_a": old_w, "w_b": new_w, "c_a": old_b, "c_b": new_b},
              "new-first": {"w_a": new_w, "w_b": old_w, "c_a": new_b, "c_b": old_b},
              "mixed": {"w_a": old_w, "w_b": new_w, "c_a": new_b, "c_b": old_b}}[order]
    recs, _ = fl.recover(arrays)
    first = recs[0]
    assert (first.w.name, first.b.name) == ("w_b - w_a", "c_b - c_a")
    assert not first.sign_known
    sign = -1.0 if order == "mixed" else 1.0                  # only a mixed storage order flips the ratio
    assert np.allclose(first.x * sign, x, atol=2e-3)
    fl.decode(first, FF)
    label, text, flags = first.decodes[0]
    assert flags == (FLAG.decode(),)
    assert label == ("x*255 of -x" if order == "mixed" else "x*255")


def test_a_weight_difference_is_never_paired_with_a_plain_bias_array():
    """new - old weights against a raw bias gradient would agree at the wrong scale (1 / -lr)."""
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    recs, _ = fl.recover({"w_old": Ws[0], "w_new": Ws[0] - 0.05 * gW[0], "bias_grad": gb[0]}, match=False)
    assert recs and all(r.b is None for r in recs)


# ---- byte-scale decodes ---------------------------------------------------------------------------------

@pytest.mark.parametrize("label,scale,offset", fl.SCALES, ids=[s[0] for s in fl.SCALES])
def test_each_named_byte_scale_decodes(label, scale, offset):
    np = _np()
    text = b"flag{scale_test_01}"
    x = np.zeros(24)
    x[:len(text)] = (np.frombuffer(text, dtype=np.uint8) - offset) / scale
    x[len(text):] = (0 - offset) / scale                      # padding is byte 0 in every scale
    hits = fl.decode_bytes(x)
    assert hits[0] == (label, text.decode())
    assert all(t == text.decode() for _, t in hits) and len(hits) == 1


def test_decode_bytes_rounds_drops_padding_and_rejects_non_text():
    np = _np()
    text = b"plain words here"
    x = _text_input(np, text, 32)
    noisy = x + np.random.default_rng(2).uniform(-0.2, 0.2, size=32) / 255.0
    assert fl.decode_bytes(noisy) == [("x*255", text.decode())]           # rounded, NUL padding dropped
    assert fl.decode_bytes(x + 0.4 / 255.0) == []                         # not on integers under any scale
    assert fl.decode_bytes(np.random.default_rng(3).uniform(0, 1, size=32)) == []
    high = x.copy()
    high[0] = 300 / 255.0
    assert fl.decode_bytes(high) == []                                    # out of byte range: not clamped into text
    ctrl = x.copy()
    ctrl[3] = 7 / 255.0
    assert fl.decode_bytes(ctrl) == []                                    # a control byte inside the text
    assert fl.decode_bytes(_text_input(np, b"abc", 16)) == []             # under MIN_TEXT
    assert fl.decode_bytes(np.zeros(0)) == [] and fl.fit_decode(np.zeros(0)) == []


def test_fit_decode_finds_an_unnamed_scale():
    np = _np()
    text = b"CSCTF{unnamed_scale_7f}"
    x = _text_input(np, text, 30, scale=1000.0)
    assert fl.decode_bytes(x) == []
    hits = fl.fit_decode(x)
    assert [t for _, t in hits] == [text.decode()]
    assert hits[0][0].startswith("fitted scale x*1000")
    assert fl.fit_decode(-x) == []                                        # nothing positive to map


def test_fit_decode_reports_every_reading_of_an_ambiguous_vector():
    np = _np()
    text = b"2026110620261107"                                            # digits also read at twice the scale
    hits = fl.fit_decode(_text_input(np, text, 16, scale=400.0))
    assert hits[0][1] == text.decode() and len(hits) >= 2
    assert bytes(2 * c for c in text).decode() in [t for _, t in hits]


def test_fit_decode_refuses_vectors_any_scale_would_fit():
    np = _np()
    assert fl.fit_decode(_text_input(np, b"aaaaaaaaaa", 10, scale=77.0)) == []     # one byte value
    assert fl.fit_decode(_text_input(np, b"abcde", 5, scale=77.0)) == []           # under MIN_FIT_TEXT
    assert fl.fit_decode(np.random.default_rng(4).uniform(0.1, 1, size=20)) == []


# ---- the archive: static detect, object arrays refused, allow_pickle never on ---------------------------

class _Boom:
    """Unpickling this creates a folder: proof that an object array was loaded."""

    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (os.mkdir, (self.marker,))


def _object_npz(tmp_path, marker, **extra):
    np = _np()
    payload = np.empty(1, dtype=object)
    payload[0] = _Boom(str(marker))
    folder = tmp_path / "ch"
    folder.mkdir(exist_ok=True)
    np.savez(folder / "update.npz", meta=payload, **extra)
    assert not marker.exists()
    return folder


def test_inspect_archive_lists_arrays_statically(tmp_path):
    np = _np()
    p = _save(tmp_path, w=np.zeros((3, 2), dtype=np.float32), b=np.zeros(3, dtype=np.int16), tag=np.array(["a", "b"]))
    listed = fl.inspect_archive(p.read_bytes())
    assert [(a["name"], a["shape"], a["numeric"], a["object"]) for a in listed] == [
        ("w", [3, 2], True, False), ("b", [3], True, False), ("tag", [2], False, False)]
    with pytest.raises(fl.Refused, match="not a NumPy .npz"):
        fl.inspect_archive(b"definitely not a zip")


def test_an_archive_of_object_arrays_is_refused_and_never_loaded(tmp_path):
    marker = tmp_path / "unpickled"
    folder = _object_npz(tmp_path, marker)
    res = fl.solve(folder, CSCTF)
    assert res.status == "blocked"
    assert res.notes == "update.npz: refused: nothing loadable: meta (object array: it would need allow_pickle)"
    assert not marker.exists()


def test_an_object_array_beside_a_real_update_is_refused_alone(tmp_path):
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    marker = tmp_path / "unpickled"
    folder = _object_npz(tmp_path, marker, gw=_f32(np, gW[0]), gb=_f32(np, gb[0]))
    res = fl.solve(folder, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG.decode(),)
    assert "update.npz: refused, never loaded: meta (object array: it would need allow_pickle)" in res.notes
    assert not marker.exists()


def test_numpy_itself_refuses_an_object_array_the_static_reader_missed(tmp_path, monkeypatch):
    """Second layer: with the static check blinded, numpy.load(allow_pickle=False) still refuses."""
    marker = tmp_path / "unpickled"
    folder = _object_npz(tmp_path, marker)
    monkeypatch.setattr(fl, "inspect_archive", lambda data: [
        {"name": "meta", "shape": [1], "dtype": "<f8", "numeric": True, "object": False}])
    arrays, notes, refused = fl.load_arrays(folder / "update.npz")
    assert arrays == {}
    assert len(refused) == 1 and refused[0].startswith("meta (numpy refused it: ValueError: Object arrays cannot be loaded")
    assert notes == ["refused, never loaded: " + refused[0]]
    assert not marker.exists()
    assert fl.solve(folder, CSCTF).status == "blocked"        # nothing else to read: said, not passed over
    assert not marker.exists()


def test_a_file_that_is_not_an_npz_is_refused_by_name(tmp_path):
    folder = tmp_path / "ch"
    folder.mkdir()
    with zipfile.ZipFile(folder / "notes.npz", "w") as z:
        z.writestr("readme.txt", "CSCTF{not_from_an_array_1234}")
    (folder / "junk.npz").write_bytes(b"\x00\x01 not a zip at all")
    res = fl.solve(folder, CSCTF)
    assert res.status == "blocked" and not res.flags
    assert "junk.npz: refused: not a NumPy .npz archive" in res.notes
    assert "notes.npz: refused: not a NumPy .npz archive" in res.notes


def test_load_arrays_shapes_and_named_omissions(tmp_path, monkeypatch):
    np = _np()
    p = _save(tmp_path, col=np.ones((5, 1)), row=np.ones((1, 5)), flat=np.arange(5), mat=np.ones((1, 4, 3)),
              scalar=np.float64(3.0), conv=np.ones((2, 3, 3, 3)), words=np.array(["x", "y"]),
              bad=np.array([1.0, float("nan")]), big=np.ones((30, 30)))
    monkeypatch.setattr(fl, "MAX_ELEMENTS", 500)
    arrays, notes, refused = fl.load_arrays(p)
    assert refused == []
    assert {n: a.shape for n, a in arrays.items()} == {"col": (5,), "row": (5,), "flat": (5,), "mat": (4, 3)}
    assert all(a.dtype == np.float64 for a in arrays.values())
    text = "\n".join(notes)
    assert "big: 900 elements is over the 500 limit, not read" in text
    assert "bad: holds a non-finite value, left out" in text
    assert "not numeric, left out: words" in text
    assert "conv: shape (2, 3, 3, 3) is neither" in text and "scalar: shape ()" in text


def test_a_column_shaped_bias_still_pairs(tmp_path):
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    folder = tmp_path / "ch"
    _save(folder, dW=gW[0], db=gb[0].reshape(-1, 1))
    assert fl.solve(folder, CSCTF).flags == (FLAG.decode(),)


# ---- no bias: rank one, then the one scale by gradient matching -----------------------------------------

def test_rank_one_factors_an_update_and_rejects_weights():
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    u, r, live = fl.rank_one(gW[0])
    assert np.allclose(np.outer(u, r), gW[0], atol=1e-12)
    assert live == int((gb[0] != 0).sum())
    assert fl.rank_one(Ws[0]) is None                         # full rank
    assert fl.rank_one(np.zeros((4, 4))) is None
    one_row = np.zeros((5, 7))
    one_row[2] = np.arange(1, 8)
    assert fl.rank_one(one_row) is None                       # a single row proves nothing
    assert fl.rank_one(gW[0] + 1e-2 * np.abs(gW[0]).max() * np.eye(24, 40)) is None


@pytest.mark.parametrize("act,bias", [("relu", True), ("relu", False), ("tanh", True), ("sigmoid", True), ("linear", False)])
def test_model_gradients_match_finite_differences(act, bias):
    np = _np()
    Ws, bs = _net(np, (7, 9, 5, 4), seed=11, bias=bias)
    x = np.random.default_rng(12).uniform(0.1, 0.9, size=7)
    layers = [(W, b if bias else None) for W, b in zip(Ws, bs)]
    got = fl.model_gradients(x, layers, 1, act)
    eps = 1e-6
    for k, (i, j) in ((0, (2, 3)), (1, (4, 1)), (2, (0, 2)), (0, (8, 6)), (2, (3, 4))):
        bumped = [W.copy() for W in Ws]
        bumped[k][i, j] += eps
        down = [W.copy() for W in Ws]
        down[k][i, j] -= eps
        numeric = (_loss(np, bumped, bs, x, 1, act) - _loss(np, down, bs, x, 1, act)) / (2 * eps)
        assert got[k][i, j] == pytest.approx(numeric, abs=1e-7)


@pytest.mark.parametrize("seed", [21, 22, 23])
def test_match_scale_pins_the_scale_label_and_step(seed):
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), seed, bias=False)
    x = np.random.default_rng(seed + 100).uniform(0.05, 0.9, size=30)
    label = seed % 6
    gW, _ = _update(np, Ws, bs, x, label)
    lr = 0.03
    direction = x / x.max()
    layers = [(W, None) for W in Ws]
    m = fl.match_scale(direction, layers, [_f32(np, -lr * g) for g in gW])
    assert m.scale == pytest.approx(float(x.max()), rel=1e-4)
    assert m.label == label and m.sharp
    assert m.factor == pytest.approx(-lr, rel=1e-3)
    assert m.residual < 1e-5
    only_first = fl.match_scale(direction, layers, [gW[0], None])         # the later layer's update withheld
    assert only_first.scale == pytest.approx(float(x.max()), rel=1e-6) and only_first.factor == pytest.approx(1.0)


def test_match_scale_keeps_the_grid_point_when_refinement_lands_worse(monkeypatch):
    """The residual has ReLU kinks, so golden section may settle somewhere worse than the best grid
    scale. The grid scale is then kept, not the worse refinement."""
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 21, bias=False)
    grid = np.logspace(-4.0, 4.0, fl.MATCH_GRID)
    c = float(grid[90])                                       # the true scale is a grid point exactly
    direction = np.random.default_rng(121).uniform(0.05, 0.9, size=30)
    direction /= direction.max()
    gW, _ = _update(np, Ws, bs, c * direction, 3)
    layers = [(W, None) for W in Ws]
    monkeypatch.setattr(fl, "_golden", lambda f, lo, hi, steps=80: hi)    # a refinement that lands a grid step off
    m = fl.match_scale(direction, layers, gW)
    assert m.scale == c and m.label == 3 and m.residual < 1e-9
    monkeypatch.undo()
    assert fl.match_scale(direction, layers, gW).scale == pytest.approx(c, rel=1e-6)


def test_golden_section_finds_the_minimum_of_a_unimodal_function():
    assert fl._golden(lambda t: (t - 0.3) ** 2, -1.0, 2.0) == pytest.approx(0.3, abs=1e-6)
    assert fl._golden(lambda t: abs(t + 0.7), -1.0, 2.0) == pytest.approx(-0.7, abs=1e-6)


def test_match_scale_finds_a_negative_scale_for_a_signed_input():
    """The direction has its largest entry at +1; when that entry of x is negative, so is the scale."""
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 24, bias=False)
    x = np.random.default_rng(25).uniform(-0.6, 0.6, size=30)
    x[7] = -0.95
    gW, _ = _update(np, Ws, bs, x, 4)
    m = fl.match_scale(x / x[7], [(W, None) for W in Ws], gW)
    assert m.scale == pytest.approx(-0.95, rel=1e-6) and m.label == 4 and m.sharp
    recs, _ = fl.recover({"A": Ws[0], "B": Ws[1], "gA": gW[0], "gB": gW[1]})
    assert recs[0].scale_known and np.allclose(recs[0].x, x, atol=1e-7)


def test_match_scale_says_when_a_saturated_model_does_not_pin_the_scale():
    """Huge last-layer weights: the softmax is one-hot for a whole range of scales, so every one of
    them reproduces the update. The match is reported flat and x stays a direction."""
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 26, bias=False)
    Ws[1] = Ws[1] * 500.0
    x = np.random.default_rng(27).uniform(0.05, 0.9, size=30)
    logits = Ws[1] @ np.maximum(Ws[0] @ x, 0.0)
    label = int((np.argmax(logits) + 1) % 6)                              # not the predicted class
    gW, _ = _update(np, Ws, bs, x, label)
    m = fl.match_scale(x / x.max(), [(W, None) for W in Ws], gW)
    assert m.residual < fl.MATCH_TOL and m.label == label and not m.sharp
    recs, _ = fl.recover({"A": Ws[0], "B": Ws[1], "gA": gW[0], "gB": gW[1]})
    assert not recs[0].scale_known and recs[0].method == "no bias: rank-one direction"
    assert float(np.abs(recs[0].x).max()) == pytest.approx(1.0)
    assert any("the scale is NOT pinned and x stays a direction" in n for n in recs[0].notes)


def test_match_scale_bounds_its_own_work(monkeypatch):
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 28, bias=False)
    x = np.random.default_rng(29).uniform(0.05, 0.9, size=30)
    gW, _ = _update(np, Ws, bs, x, 0)
    layers = [(W, None) for W in Ws]
    work = (2 * fl.MATCH_GRID + 100) * 7 * (20 * 30 + 6 * 20)             # scales x (1 + labels) x weight elements
    monkeypatch.setattr(fl, "MAX_MATCH_WORK", work)
    assert fl.match_scale(x / x.max(), layers, gW).label == 0             # exactly at the limit: allowed
    monkeypatch.setattr(fl, "MAX_MATCH_WORK", work - 1)
    with pytest.raises(fl.NoLeak, match=f"too large to search \\({work} weight elements to touch, limit {work - 1}\\)"):
        fl.match_scale(x / x.max(), layers, gW)
    monkeypatch.setattr(fl, "MAX_MATCH_WORK", work)
    monkeypatch.setattr(fl, "MAX_LABELS", 3)
    with pytest.raises(fl.NoLeak, match="6 classes is over the 3 enumerated"):
        fl.match_scale(x / x.max(), layers, gW)


def test_no_bias_old_and_new_weights_match_against_the_old_model():
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 43, bias=False)
    x = np.random.default_rng(44).uniform(0.05, 0.9, size=30)
    gW, _ = _update(np, Ws, bs, x, 3)
    lr = 0.5                                                  # large: the new weights are a different model
    recs, _ = fl.recover({"w1_old": Ws[0], "w1_new": Ws[0] - lr * gW[0], "w2_old": Ws[1], "w2_new": Ws[1] - lr * gW[1]})
    first = recs[0]
    assert first.w.name == "w1_new - w1_old" and first.scale_known
    assert np.allclose(first.x, x, rtol=1e-6)
    assert any("on model w1_old -> w2_old (no bias)" in n and "update = -0.5 x gradient" in n for n in first.notes)


def test_gradient_matching_declines_by_name_when_shapes_do_not_decide():
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 45, bias=False)
    rng = np.random.default_rng(46)
    x = rng.uniform(0.05, 0.9, size=30)
    gW, _ = _update(np, Ws, bs, x, 2)

    def why(arrays):
        recs, _ = fl.recover(arrays)
        assert recs[0].w.name == "gA" and recs[0].layout == "rows" and not recs[0].scale_known
        return recs[0].notes[0]

    two_models = why({"A1": Ws[0], "A2": rng.normal(size=(20, 30)), "B": Ws[1], "gA": gW[0]})
    assert two_models.startswith("scale not fixed by gradient matching: 2 weight arrays of shape (20, 30) (A1, A2)")
    fork = why({"A": Ws[0], "B": Ws[1], "C": rng.normal(size=(9, 20)), "gA": gW[0]})
    assert "the model chain is ambiguous after A" in fork and "(6, 20)" in fork and "(9, 20)" in fork
    twice = why({"A": Ws[0], "B": Ws[1], "gA": gW[0], "sA": -0.1 * gW[0]})
    assert "2 candidate updates of shape (20, 30): gA, sA" in twice


def test_match_scale_declines_a_model_that_did_not_make_the_update():
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 31, bias=False)
    x = np.random.default_rng(32).uniform(0.05, 0.9, size=30)
    gW, _ = _update(np, Ws, bs, x, 2)
    other, _ = _net(np, (30, 20, 6), 33, bias=False)
    with pytest.raises(fl.NoLeak, match="never lines up"):
        fl.match_scale(x / x.max(), [(W, None) for W in other], gW)
    with pytest.raises(fl.NoLeak, match="unknown activation 'gelu'"):
        fl.match_scale(x / x.max(), [(W, None) for W in Ws], gW, activation="gelu")
    with pytest.raises(fl.NoLeak, match="no update to match"):
        fl.match_scale(x / x.max(), [(W, None) for W in Ws], [None, None])


def test_no_bias_update_with_its_model_recovers_the_exact_input():
    """Not text: only gradient matching can put a scale on the rank-one direction."""
    np = _np()
    Ws, bs = _net(np, (30, 20, 6), 41, bias=False)
    x = np.random.default_rng(42).uniform(0.05, 0.9, size=30)
    gW, _ = _update(np, Ws, bs, x, 5)
    recs, _ = fl.recover({"layer_a": Ws[0], "layer_b": Ws[1], "step_a": -0.1 * gW[0], "step_b": -0.1 * gW[1]})
    first = recs[0]
    assert first.b is None and first.w.name == "step_a" and first.layout == "rows" and first.head
    assert first.method == "no bias: rank-one direction + gradient matching"
    assert first.scale_known and first.sign_known and first.confirmed
    assert np.allclose(first.x, x, rtol=1e-6)
    assert any("gradient matching on model layer_a -> layer_b (no bias)" in n and "label 5" in n for n in first.notes)
    off, _ = fl.recover({"layer_a": Ws[0], "layer_b": Ws[1], "step_a": -0.1 * gW[0], "step_b": -0.1 * gW[1]}, match=False)
    assert not off[0].scale_known and float(np.abs(off[0].x).max()) == pytest.approx(1.0)
    assert np.allclose(off[0].x * x.max(), x, rtol=1e-9)      # the direction alone, largest entry +1


def test_no_bias_matching_needs_the_right_activation(tmp_path):
    np = _np()
    Ws, bs = _net(np, (40, 24, 6), 51, bias=False)
    x = np.random.default_rng(52).uniform(0.05, 0.9, size=40)
    gW, _ = _update(np, Ws, bs, x, 1, act="tanh")
    arrays = {"A": Ws[0], "B": Ws[1], "dA": gW[0], "dB": gW[1]}
    relu, _ = fl.recover(arrays)
    assert not relu[0].scale_known
    assert any("scale not fixed by gradient matching" in n and "assumed relu" in n for n in relu[0].notes)
    tanh, _ = fl.recover(arrays, activation="tanh")
    assert tanh[0].scale_known and np.allclose(tanh[0].x, x, rtol=1e-6)
    res = fl.solve(_save(tmp_path / "ch", **arrays).parent, CSCTF, activation="tanh", out=str(tmp_path / "o"))
    assert res.status == "unsure" and "gradient matching on model A -> B" in res.notes


def test_bias_sent_only_for_the_last_layer_still_finds_the_first(tmp_path):
    """Layer 1 has no bias update, layer 2 has one: the head is layer 1 (rank one), scaled by matching
    against the model with its bias vectors."""
    np = _np()
    Ws, bs, x, gW, gb = _case(np, seed=61)
    recs, _ = fl.recover({"W1": Ws[0], "b1": bs[0], "W2": Ws[1], "b2": bs[1], "uW1": gW[0], "uW2": gW[1], "ub2": gb[1]})
    assert [(r.w.name, r.b.name if r.b else None, r.head) for r in recs] == [("uW1", None, True), ("uW2", "ub2", False)]
    assert recs[0].scale_known and np.allclose(recs[0].x, x, atol=1e-6)
    assert any("with bias b1, b2" in n for n in recs[0].notes)
    fl.decode(recs[0], FF)
    assert recs[0].decodes[0] == ("x*255", FLAG.decode(), (FLAG.decode(),))


def test_no_bias_and_no_model_reads_text_by_the_fitted_scale(tmp_path):
    np = _np()
    Ws, bs, x, gW, gb = _case(np, bias=False, seed=71)
    folder = tmp_path / "ch"
    _save(folder, only=_f32(np, -0.02 * gW[0]))
    res = fl.solve(folder, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG.decode(),)
    assert res.evidence[0].kind == "rank-one" and "fitted scale" in res.evidence[0].detail
    assert "scale not fixed by gradient matching: no model weights of shape (24, 40)" in res.notes


# ---- the engine contract -------------------------------------------------------------------------------

def _dawn(np, folder: Path, text=FLAG, name="dispatch-authenticator.npz", seed=1):
    """The 9096 shape: a shared model, the unit's read-out (logits and a scalar label), then its
    single-sample update, stored as float32."""
    Ws, bs, x, gW, gb = _case(np, dims=(50, 64, 8), seed=seed, text=text)
    _save(folder, name, W1=_f32(np, Ws[0]), b1=_f32(np, bs[0]), W2=_f32(np, Ws[1]), b2=_f32(np, bs[1]),
          logits=_f32(np, Ws[1] @ np.maximum(Ws[0] @ x + bs[0], 0) + bs[1]), label=np.int64(2),
          update_W1=_f32(np, gW[0]), update_b1=_f32(np, gb[0]), update_W2=_f32(np, gW[1]),
          update_b2=_f32(np, gb[1]))
    return x


def test_solve_reads_the_flag_from_a_shared_model_handout(tmp_path):
    np = _np()
    x = _dawn(np, tmp_path / "files")
    res = fl.solve(tmp_path, CSCTF, challenge_id="9096")
    assert isinstance(res, SolverResult)
    assert res.status == "solved" and res.flags == (FLAG.decode(),)
    assert res.engine == "toolkits.federated_leakage" and res.challenge_id == "9096"
    ev = res.evidence[0]
    assert ev.kind == "ratio" and ev.path == "files/dispatch-authenticator.npz"
    assert "update_W1 / update_b1 (rows, 50 inputs, 64 units)" in ev.detail and "x*255" in ev.detail
    saved = np.load(tmp_path / "recon" / "federated_leakage" / "files_dispatch-authenticator.npz.input.npy")
    assert np.allclose(saved, x, atol=1e-6)
    assert "wrote recon/federated_leakage/files_dispatch-authenticator.npz.input.npy" in res.notes
    assert "label: shape () is neither a dense-layer matrix nor a vector, left out" in res.notes
    assert len(res.evidence) == 1                             # the second layer agrees too, but is not text


def test_solve_text_outside_the_flag_format_is_a_candidate(tmp_path):
    np = _np()
    _dawn(np, tmp_path, text=b"  meet at the old mill at dawn  ")
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == ("meet at the old mill at dawn",)
    assert "not in the event flag format" in res.notes


def test_solve_the_same_value_from_two_archives_is_reported_once(tmp_path):
    np = _np()
    _dawn(np, tmp_path / "f", name="a.npz")
    _dawn(np, tmp_path / "f", name="b.npz", seed=2)
    res = fl.solve(tmp_path / "f", CSCTF)
    assert res.status == "solved" and res.flags == (FLAG.decode(),) and len(res.evidence) == 2
    _dawn(np, tmp_path / "t", name="a.npz", text=b"the same plain words")
    _dawn(np, tmp_path / "t", name="b.npz", text=b"the same plain words", seed=2)
    res = fl.solve(tmp_path / "t", CSCTF)
    assert res.status == "candidate" and res.flags == ("the same plain words",)


def test_solve_two_archives_with_different_flags_is_a_candidate(tmp_path):
    np = _np()
    other = b"CSCTF{a_second_synthetic_one_ffee00}"
    _dawn(np, tmp_path, name="a.npz")
    _dawn(np, tmp_path, name="b.npz", text=other, seed=2)
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == (FLAG.decode(), other.decode())
    assert "several flags decoded" in res.notes


def test_solve_an_image_input_is_unsure_and_saved_with_a_picture(tmp_path):
    np = _np()
    Ws, bs = _net(np, (64, 20, 4), 81)
    img = np.random.default_rng(82).uniform(0.0, 1.0, size=64)
    gW, gb = _update(np, Ws, bs, img, 0)
    _save(tmp_path / "files", "g.npz", gw=gW[0], gb=gb[0])
    out = tmp_path / "elsewhere"
    res = fl.solve(tmp_path, CSCTF, out=str(out))
    assert res.status == "unsure" and not res.flags
    assert "no byte-scale text" in res.notes and "read the saved array" in res.notes
    assert np.allclose(np.load(out / "files_g.npz.input.npy"), img, atol=1e-12)
    pgm = (out / "files_g.npz.input.pgm").read_bytes()
    head = b"P5\n8 8\n255\n"
    assert pgm.startswith(head) and len(pgm) == len(head) + 64
    scaled = np.rint((img - img.min()) / (img.max() - img.min()) * 255)
    assert list(pgm[len(head):]) == [int(v) for v in scaled]
    assert not (tmp_path / "recon").exists()                  # `out` replaces the default folder


def test_solve_none_for_an_unrelated_archive_and_for_no_archive(tmp_path):
    np = _np()
    rng = np.random.default_rng(91)
    a = tmp_path / "a"
    _save(a, "traces.npz", traces=rng.normal(size=(40, 12)), plaintexts=rng.integers(0, 256, size=(40, 4)),
          sbox=np.arange(12))
    res = fl.solve(a, CSCTF)
    assert res.status == "none" and not res.flags
    assert "traces.npz: no (W, b) pair agreed; nearest:" in res.notes
    b = tmp_path / "b"
    b.mkdir()
    (b / "readme.txt").write_text("nothing numeric")
    res = fl.solve(b, CSCTF)
    assert res.status == "none" and res.notes == "no .npz archive in the challenge files"
    with pytest.raises(FileNotFoundError):
        fl.solve(tmp_path / "missing", CSCTF)


def test_solve_tolerance_option_reaches_the_ratio(tmp_path):
    """Float32 rounding is over a 1e-12 tolerance, so no (W, b) pair agrees; the update is still rank
    one, so the text is read the no-bias way instead (direction, fitted scale)."""
    np = _np()
    _dawn(np, tmp_path)
    loose = fl.solve(tmp_path, CSCTF, tol="1e-2")
    assert loose.status == "solved" and {e.kind for e in loose.evidence} == {"ratio"}
    tight = fl.solve(tmp_path, CSCTF, tol="1e-12", match="false")
    assert tight.flags == (FLAG.decode(),) and {e.kind for e in tight.evidence} == {"rank-one"}
    assert "fitted scale" in tight.evidence[0].detail


def test_find_archives_prefers_the_sweep_copy_and_skips_recon_and_links(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "a.npz").write_bytes(b"x")
    assert [p.relative_to(tmp_path).as_posix() for p in fl.find_archives(tmp_path)] == ["files/a.npz"]
    (tmp_path / "unpacked" / "inner.zip.unpacked").mkdir(parents=True)
    (tmp_path / "unpacked" / "B.NPZ").write_bytes(b"x")
    (tmp_path / "unpacked" / "inner.zip.unpacked" / "c.npz").write_bytes(b"x")
    (tmp_path / "unpacked" / "d.npy").write_bytes(b"x")
    (tmp_path / "unpacked" / "recon").mkdir()
    (tmp_path / "unpacked" / "recon" / "old.npz").write_bytes(b"x")
    (tmp_path / "unpacked" / "link.npz").symlink_to(tmp_path / "files" / "a.npz")
    assert [p.relative_to(tmp_path).as_posix() for p in fl.find_archives(tmp_path)] == [
        "unpacked/B.NPZ", "unpacked/inner.zip.unpacked/c.npz"]


def test_solve_names_the_archives_it_did_not_read(tmp_path, monkeypatch):
    np = _np()
    _dawn(np, tmp_path, name="a.npz")
    _dawn(np, tmp_path, name="b.npz", text=b"CSCTF{never_read_past_the_cap_99}", seed=2)
    monkeypatch.setattr(fl, "MAX_FILES", 1)
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "solved" and res.flags == (FLAG.decode(),)       # b.npz would have made two flags
    assert "only the first 1 of 2 .npz files were read" in res.notes


def test_solve_reports_at_most_three_candidate_texts(tmp_path):
    np = _np()
    texts = [b"first plain dispatch", b"second plain dispatch", b"third plain dispatch", b"fourth plain dispatch"]
    for i, t in enumerate(texts):
        _dawn(np, tmp_path, name=f"{i}.npz", text=t, seed=i + 1)
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "candidate" and res.flags == tuple(t.decode() for t in texts[:3])


def test_solve_an_rgb_image_input_gets_an_interleaved_picture(tmp_path):
    np = _np()
    Ws, bs = _net(np, (192, 12, 4), 83)
    img = np.random.default_rng(84).uniform(0.0, 1.0, size=192)           # channel-first 3 x 8 x 8
    gW, gb = _update(np, Ws, bs, img, 1)
    _save(tmp_path, "g.npz", gw=gW[0], gb=gb[0])
    assert fl.solve(tmp_path, CSCTF, out=str(tmp_path / "o")).status == "unsure"
    ppm = (tmp_path / "o" / "g.npz.input.ppm").read_bytes()
    head = b"P6\n8 8\n255\n"
    assert ppm.startswith(head) and len(ppm) == len(head) + 192
    scaled = np.rint((img - img.min()) / (img.max() - img.min()) * 255).astype(int).reshape(3, 8, 8)
    body = ppm[len(head):]
    assert list(body[:3]) == [scaled[0, 0, 0], scaled[1, 0, 0], scaled[2, 0, 0]]
    assert list(body[3 * 9:3 * 9 + 3]) == [scaled[0, 1, 1], scaled[1, 1, 1], scaled[2, 1, 1]]
    assert not (tmp_path / "o" / "g.npz.input.pgm").exists()


def test_one_live_unit_is_reported_unconfirmed(tmp_path):
    np = _np()
    x = np.linspace(0.1, 0.8, 6)
    delta = np.array([0.0, 0.5, 0.0])
    recs, _ = fl.recover({"g": np.outer(delta, x), "d": delta})
    assert len(recs) == 1 and not recs[0].confirmed and np.allclose(recs[0].x, x)
    assert recs[0].notes == ["one live unit only: nothing to agree with, unconfirmed"]
    _save(tmp_path, g=np.outer(delta, x), d=delta)
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "unsure" and "one live unit only" in res.notes and "1/1 live units agree" in res.notes


def test_caps_are_named_not_silent(tmp_path, monkeypatch):
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    vecs = {f"v{i}": np.random.default_rng(i).normal(size=6) for i in range(5)}
    _, notes = fl.recover({"gw": gW[0], "gb": gb[0], **vecs})
    assert "5 arrays of shape (6,): over 4, their differences were not tried" in notes
    monkeypatch.setattr(fl, "MAX_PAIRS", 1)
    recs, notes = fl.recover({"w": Ws[0], "b": bs[0], "gw": gW[0], "gb": gb[0]})
    assert "stopped after 1 (W, b) candidates" in notes and all(r.b is None for r in recs)
    p = _save(tmp_path, gw=gW[0], gb=gb[0], w=Ws[0], b=bs[0])
    monkeypatch.setattr(fl, "MAX_ARRAYS", 2)
    arrays, notes, _ = fl.load_arrays(p)
    assert list(arrays) == ["gw", "gb"] and "only the first 2 of 4 arrays were read" in notes
    monkeypatch.setattr(fl, "MAX_FILE", 10)
    with pytest.raises(fl.Refused, match="over the 10 byte limit"):
        fl.load_arrays(p)
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "blocked" and "update.npz: refused:" in res.notes and "over the 10 byte limit" in res.notes
    with pytest.raises(fl.Refused, match="unreadable"):
        fl.load_arrays(tmp_path / "gone.npz")


def test_total_element_budget_bounds_loading_and_differences(tmp_path, monkeypatch):
    """MAX_FILE bounds compressed bytes only; the element total bounds what is decompressed and
    differenced, so a hostile archive of compressible arrays cannot exhaust memory."""
    np = _np()
    Ws, bs, x, gW, gb = _case(np)
    p = _save(tmp_path, gw=gW[0], gb=gb[0], w=Ws[0], b=bs[0])     # 960 + 24 + 960 + 24 elements
    monkeypatch.setattr(fl, "MAX_TOTAL_ELEMENTS", 984)
    arrays, notes, _ = fl.load_arrays(p)
    assert list(arrays) == ["gw", "gb"]                       # exactly at the total: still read
    assert "w: not read, it would bring the archive to 1944 elements, over the 984 total limit" in notes
    assert any(n.startswith("b: not read, it would bring the archive to 1008 elements") for n in notes)
    monkeypatch.setattr(fl, "MAX_TOTAL_ELEMENTS", 983)
    arrays, notes, _ = fl.load_arrays(p)
    assert list(arrays) == ["gw"]                             # one element short: gb no longer fits beside gw
    assert "gb: not read, it would bring the archive to 984 elements, over the 983 total limit" in notes

    old = {"w1_old": Ws[0], "w1_new": Ws[0] - 0.1 * gW[0], "b1_old": bs[0], "b1_new": bs[0] - 0.1 * gb[0]}
    monkeypatch.setattr(fl, "MAX_TOTAL_ELEMENTS", 1968 + 960 + 24)              # room for both differences, exactly
    recs, notes = fl.recover(old)
    assert recs and recs[0].w.name == "w1_new - w1_old" and np.allclose(recs[0].x, x, atol=1e-9)
    assert not any("element total" in n for n in notes)
    monkeypatch.setattr(fl, "MAX_TOTAL_ELEMENTS", 1968 + 960 + 23)              # the weight difference spends the room
    recs, notes = fl.recover(old)
    assert "1 of 1 differences of shape (24,) not tried: over the 2951 element total" in notes
    assert all(r.b is None for r in recs)                     # no bias difference: no ratio pair
    monkeypatch.setattr(fl, "MAX_TOTAL_ELEMENTS", 1968 + 959)                   # one short for the weight difference
    recs, notes = fl.recover(old)
    assert "1 of 1 differences of shape (24, 40) not tried: over the 2927 element total" in notes
    assert all(r.w.name != "w1_new - w1_old" for r in recs)


def test_solve_is_blocked_by_name_without_numpy(tmp_path, monkeypatch):
    def gone():
        raise fl.Refused("numpy is required (needs_tools py:numpy)")
    monkeypatch.setattr(fl, "_np", gone)
    res = fl.solve(tmp_path, CSCTF)
    assert res.status == "blocked" and "numpy is required" in res.notes


# ---- wiring: manifest, routes, intake, the script --------------------------------------------------------

def test_manifest_arms_the_engine_at_intake_on_any_npz():
    from ctf.engines import manifest
    m = next(x for x in manifest.discover() if x.id == "toolkits.federated_leakage")
    assert m.cost_class == "cheap" and m.status == "active" and "py:numpy" in m.needs_tools
    assert (m.intake.select, m.intake.run, tuple(m.intake.match)) == ("files", "challenge", ("ext:.npz",))
    assert not m.intake.spawns


def test_routes_by_file_and_by_brief(tmp_path):
    from ctf import triage
    from ctf.engines import router
    np = _np()
    _dawn(np, tmp_path / "with")
    ids = [h.manifest.id for h in router.route("misc", "Operation Dawn: annex entry 17", tmp_path / "with")]
    assert "toolkits.federated_leakage" in ids
    assert ids.index("toolkits.federated_leakage") < ids.index("common.cpa_npz")
    assert "toolkits.federated_leakage" in [h.manifest.id for h in router.route("ml", "a model", tmp_path / "with")]
    (tmp_path / "without").mkdir()
    (tmp_path / "without" / "notes.txt").write_text("plain words")
    assert "toolkits.federated_leakage" not in [h.manifest.id for h in router.route("misc", "Operation Dawn", tmp_path / "without")]
    brief = "every unit sends its learning update back to command; we also lifted the shared model"
    assert triage.suggest("misc", brief)["routes"][0]["id"] == "toolkits.federated_leakage"
    login = "the portal trusts a federated identity provider for single sign-on"
    assert "toolkits.federated_leakage" not in [r["id"] for r in triage.suggest("web", login)["routes"]]
    firmware = "the router pulls a signed model update and a weight update table from the shared model server"
    assert "toolkits.federated_leakage" not in [r["id"] for r in triage.suggest("hardware", firmware)["routes"]]


def test_intake_runs_the_engine_on_a_misc_handout_with_no_model(tmp_path):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    np = _np()
    cd = tmp_path / "9096-the-shared-model"
    _dawn(np, cd / "unpacked")
    guard = G.Guard("hook", (), "test")
    plan = E.plan(manifest.discover(), "misc", "Operation Dawn, annex entry 17", cd / "unpacked", guard=guard)
    job = next(j for j in plan.jobs if j.engine == "toolkits.federated_leakage")
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines", profile=CSCTF,
                    guard=guard, root=REPO, python=sys.executable, challenge_id="9096", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.flags == (FLAG.decode(),)
    assert (cd / "recon" / "federated_leakage" / "unpacked_dispatch-authenticator.npz.input.npy").is_file()


def test_main_prints_a_summary_and_the_result_json_last(tmp_path, capsys):
    np = _np()
    _dawn(np, tmp_path / "ch")
    f = tmp_path / "ch" / "dispatch-authenticator.npz"
    assert fl.main([str(f), "--event", "csctf"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    res = SolverResult.from_json(lines[-1])
    assert res.status == "solved" and res.flags == (FLAG.decode(),)
    assert lines[0].startswith("[ratio] dispatch-authenticator.npz: update_W1 / update_b1")
    assert not (tmp_path / "ch" / "recon").exists()           # a file argument writes nothing unasked
    assert fl.main([str(f), "--event", "csctf", "--out", str(tmp_path / "o")]) == 0
    assert (tmp_path / "o" / "dispatch-authenticator.npz.input.npy").is_file()
    capsys.readouterr()
    assert fl.main([str(f), "--event", "csctf", "--opt", "tol=1e-12", "--opt", "match=false"]) == 0
    res = SolverResult.from_json(capsys.readouterr().out.strip().splitlines()[-1])
    assert {e.kind for e in res.evidence} == {"rank-one"}     # the options reached the file read too
    assert fl.main([str(tmp_path / "ch"), "--event", "csctf", "--opt", "tol=1e-12", "--opt", "match=false"]) == 0
    res = SolverResult.from_json(capsys.readouterr().out.strip().splitlines()[-1])
    assert {e.kind for e in res.evidence} == {"rank-one"}     # the options reached solve()
    assert (tmp_path / "ch" / "recon" / "federated_leakage").is_dir()     # a folder argument is solve()


def test_main_usage_errors_exit_two(tmp_path, capsys):
    assert fl.main([]) == 2
    assert fl.main([str(tmp_path / "missing.npz"), "--event", "csctf"]) == 2
    assert fl.main([str(tmp_path), "--opt", "tol"]) == 2
    assert fl.main([str(tmp_path), "--event"]) == 2
    assert fl.main([str(tmp_path), "--bogus"]) == 2
    assert fl.main([str(tmp_path), "--event", "no-such-event-slug"]) == 2
    err = capsys.readouterr().err
    assert "usage: federated_leakage.py" in err and "does not exist" in err and "not key=value" in err


def test_script_run_bootstraps_its_own_imports(tmp_path):
    """Run as a plain script from another folder (no checkout root on sys.path), it still answers."""
    np = _np()
    _dawn(np, tmp_path / "ch")
    script = REPO / "solvers" / "toolkits" / "federated_leakage.py"
    proc = subprocess.run([sys.executable, "-I", str(script), str(tmp_path / "ch"), "--event", "csctf"],
                          cwd=tmp_path, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    assert SolverResult.from_json(proc.stdout.strip().splitlines()[-1]).flags == (FLAG.decode(),)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
