"""B-116: the backdoored small-net trigger extractor (solvers/toolkits/model_trigger.py, toolkits.model_trigger).

Every net is built inside the test (tests/b116_models.py): authenticators whose hidden units detect
chunks of a made-up flag, benign random nets with one or two implanted units, and per-character and
one-hot variants, written as npz, safetensors, a hand-assembled PyTorch zip, loose .npy files and JSON.
No real challenge file. Engine budgets are given explicitly and are CPU time, so machine load does
not decide a result.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import b116_models as fx  # noqa: E402

from ctf import event, flagfmt  # noqa: E402
from ctf.result import SolverResult  # noqa: E402
from solvers.toolkits import _model_tensors as tensors  # noqa: E402
from solvers.toolkits import model_trigger as mt  # noqa: E402

pytestmark = pytest.mark.needs_tool("py:numpy")

REPO = Path(__file__).resolve().parents[1]
CSCTF = event.load("csctf")
FF = flagfmt.for_profile(CSCTF)
FLAG = "CSCTF{synthetic_ash_0421}"            # made up for these tests
BUDGET = 300.0                                # CPU seconds: far above what any case here needs
PRINTABLE95 = "".join(map(chr, range(0x20, 0x7F)))


def _profile(prefixes):
    import datetime
    return event.parse({
        "slug": "b116-test", "name": "B-116 test", "dates": {"start": datetime.date(2026, 1, 1),
                                                             "end": datetime.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b116.test"},
        "flag": {"prefixes": list(prefixes), "body": "[^}\\n]{1,256}", "case": "prefix-insensitive"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["localhost"]},
    }, src="<test>")


def _challenge(tmp_path, files: dict) -> Path:
    ch = tmp_path / "9154-synthetic"
    for rel, raw in files.items():
        p = ch / "files" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    return ch


def _solve(tmp_path, files, profile=CSCTF, **opts) -> SolverResult:
    opts.setdefault("budget_s", BUDGET)
    return mt.solve(_challenge(tmp_path, files), profile, **opts)


def _relu_forward(layers, x):
    a = x
    for i, (w, b) in enumerate(layers):
        a = a @ w.T + b
        if i < len(layers) - 1:
            a = np.maximum(a, 0)
    return a


# ---------------------------------------------------------------- rebuilding the network

def _random_layers(seed=0, sizes=(8, 5, 2)):
    rng = np.random.default_rng(seed)
    return [(rng.normal(size=(o, i)), rng.normal(size=o)) for i, o in zip(sizes, sizes[1:])]


def test_torch_layout_is_rebuilt_and_its_forward_pass_matches():
    (w1, b1), (w2, b2) = _random_layers()
    net = mt.build_mlp({"fc1.weight": w1, "fc1.bias": b1, "fc2.weight": w2, "fc2.bias": b2})
    assert net.shape == "8-5-2" and [l.bias_name for l in net.layers] == ["fc1.bias", "fc2.bias"]
    x = np.random.default_rng(1).normal(size=(4, 8))
    assert np.allclose(net.forward(x), _relu_forward([(w1, b1), (w2, b2)], x))


def test_in_out_storage_is_turned_round_and_said_so():
    (w1, b1), (w2, b2) = _random_layers()
    net = mt.build_mlp({"W1": w1.T.copy(), "b1": b1, "W2": w2.T.copy(), "b2": b2})
    x = np.random.default_rng(2).normal(size=(3, 8))
    assert net.shape == "8-5-2" and np.allclose(net.forward(x), _relu_forward([(w1, b1), (w2, b2)], x))
    assert "W1 is stored (in, out)" in net.notes and "W2 is stored (in, out)" in net.notes


def test_positional_npz_names_pair_weights_with_the_biases_that_fit():
    (w1, b1), (w2, b2) = _random_layers()
    net = mt.build_mlp({"arr_0": w1, "arr_1": b1, "arr_2": w2, "arr_3": b2})
    x = np.random.default_rng(3).normal(size=(3, 8))
    assert [l.bias_name for l in net.layers] == ["arr_1", "arr_3"]
    assert np.allclose(net.forward(x), _relu_forward([(w1, b1), (w2, b2)], x))


def test_output_weight_vector_and_scalar_bias_make_a_one_output_layer():
    (w1, b1), _ = _random_layers()
    v, c = np.arange(5.0) - 2, np.float64(0.25)
    net = mt.build_mlp({"W1": w1, "b1": b1, "W2": v, "b2": c})
    x = np.random.default_rng(4).normal(size=(3, 8))
    assert net.shape == "8-5-1"
    assert np.allclose(net.forward(x)[:, 0], np.maximum(x @ w1.T + b1, 0) @ v + 0.25)
    assert any("read as a 1 x 5 output layer" in n for n in net.notes)


def test_layer_order_comes_from_the_shapes_when_the_names_do_not_sort():
    (w1, b1), (w2, b2) = _random_layers()
    net = mt.build_mlp({"a_out.weight": w2, "a_out.bias": b2, "b_in.weight": w1, "b_in.bias": b1})
    assert [l.name for l in net.layers] == ["b_in.weight", "a_out.weight"]
    assert any("layer order taken from the shapes" in n for n in net.notes)


def test_missing_bias_is_zero_and_noted():
    (w1, _b1), (w2, b2) = _random_layers()
    net = mt.build_mlp({"fc1.weight": w1, "fc2.weight": w2, "fc2.bias": b2})
    assert not net.layers[0].b.any() and any("fc1.weight: no bias vector of length 5" in n for n in net.notes)


@pytest.mark.parametrize("tensors_, message", [
    ({"conv1.weight": np.zeros((4, 3, 3, 3)), "fc.weight": np.zeros((2, 4)), "fc.bias": np.zeros(2)}, "convolution"),
    ({"traces": np.zeros((50, 20)), "plaintexts": np.zeros((20, 16))}, "no tensor is named like a weight"),
    ({"enc.weight": np.ones((4, 6)), "dec.weight": np.ones((4, 6))}, "more than one layer reading"),
    ({"a.weight": np.ones((4, 6)), "b.weight": np.ones((3, 5))}, "do not chain"),
    ({"b1": np.zeros(4)}, "no 2-D weight matrix"),
])
def test_what_is_not_a_dense_chain_is_refused_with_the_reason(tensors_, message):
    with pytest.raises(mt.NetError, match=message):
        mt.build_mlp(tensors_)


@pytest.mark.parametrize("kind, fn", [
    ("tanh", np.tanh), ("sigmoid", lambda z: 1 / (1 + np.exp(-z))), ("identity", lambda z: z),
    ("leaky_relu", lambda z: np.where(z > 0, z, 0.01 * z)),
])
def test_named_activations_are_applied_between_layers(kind, fn):
    (w1, b1), (w2, b2) = _random_layers()
    net = mt.build_mlp({"W1": w1, "b1": b1, "W2": w2, "b2": b2}, kind)
    x = np.random.default_rng(5).normal(size=(3, 8))
    assert np.allclose(net.forward(x), fn(x @ w1.T + b1) @ w2.T + b2)
    with pytest.raises(mt.OptionError, match="swish"):
        mt.build_mlp({"W1": w1, "b1": b1}, "swish")


# ---------------------------------------------------------------- anomalous units

def test_the_implanted_unit_is_the_outlier_and_the_integrity_report_agrees():
    net = mt.build_mlp(fx.tampered_mlp(FLAG))
    report = mt.unit_anomalies(net)
    assert {(u["layer"], u["unit"]) for u in report["units"]} == {(0, 7)}
    assert {"weight_norm", "outgoing_norm"} <= {u["stat"] for u in report["units"]}
    assert all(abs(u["robust_z"]) >= mt.ANOMALY_Z for u in report["units"])
    rows = {r["name"]: r for r in report["integrity"]["tensors"]}
    assert rows["W1.weight_norm"]["robust_outliers"] == 1 and rows["W1.weight_norm"]["count"] == 48
    assert {"kind": "weight-concentration-candidate", "tensor": "W1.weight_norm"}.items() <= \
        report["integrity"]["findings"][0].items()


def test_a_benign_random_net_has_no_outlier_unit():
    rng = np.random.default_rng(11)
    net = mt.build_mlp({"W1": rng.normal(0, 0.2, (48, 64)), "b1": rng.normal(0, 0.1, 48),
                        "W2": rng.normal(0, 0.3, (3, 48)), "b2": np.zeros(3)})
    report = mt.unit_anomalies(net)
    assert report["units"] == [] and report["integrity"]["findings"] == []


def _one_layer_with_an_outlier(units):
    """A one-layer net of `units` units: unit 0's weights are 40 times the others' (which grow
    slowly, so the spread is not zero), biases spread evenly."""
    w = np.vstack([np.full(16, 40.0)] + [np.full(16, 1.0 + 0.1 * i) for i in range(1, units)])
    return mt.build_mlp({"W1": w, "b1": np.linspace(-1, 1, units)})


def test_a_layer_of_eight_units_is_judged_and_one_of_seven_is_not():
    eight = mt.unit_anomalies(_one_layer_with_an_outlier(8))
    assert {(u["unit"], u["stat"]) for u in eight["units"]} == {(0, "weight_norm"), (0, "peak_weight")}
    seven = mt.unit_anomalies(_one_layer_with_an_outlier(7))
    assert seven["units"] == []                                                # too few units to call one odd
    assert {r["name"] for r in seven["integrity"]["tensors"]} >= {"W1.weight_norm"}   # the numbers still go in


def test_the_integrity_report_finding_is_in_the_result_evidence(tmp_path):
    result = _solve(tmp_path, {"model.npz": fx.npz_bytes(fx.tampered_mlp(FLAG))})
    lines = [e.detail for e in result.evidence if "weight_outlier_report" in e.detail]
    assert len(lines) == 1 and lines[0].startswith("files/model.npz: model_integrity_forensics.weight_outlier_report")
    assert "W1.weight_norm (top 1% of units carry" in lines[0]
    rng = np.random.default_rng(11)                                            # a benign net: no such line
    benign = {"W1": rng.normal(0, 0.2, (48, 64)), "b1": rng.normal(0, 0.1, 48),
              "W2": rng.normal(0, 0.3, (3, 48)), "b2": np.zeros(3)}
    quiet = _solve(tmp_path / "b", {"model.npz": fx.npz_bytes(benign)})
    assert not any("weight_outlier_report" in e.detail for e in quiet.evidence)


# ---------------------------------------------------------------- input encodings

def test_encodings_offered_for_an_input_width():
    rng = np.random.default_rng(0)
    net = mt.build_mlp({"W1": rng.normal(size=(4, 760)), "b1": np.zeros(4)})          # 760 = 8 x 95
    encs, skipped = mt.encodings_for(net)
    assert [e.name for e in encs] == ["bits 0/1", "bits -1/+1", "one-hot x95", "characters (code/255)",
                                      "characters (code/256)", "characters (code/127)", "characters (code/128)",
                                      "characters (code)"]
    assert [(e.groups, e.choices) for e in encs[:4]] == [(760, 2), (760, 2), (8, 95), (760, 96)]
    odd, why = mt.encodings_for(mt.build_mlp({"W1": rng.normal(size=(4, 25)), "b1": np.zeros(4)}))
    assert [e.kind for e in odd] == ["chars"] * 5 and "bits: 25 inputs is not a multiple of 8 or 7" in why


def test_the_search_bookkeeping_equals_the_real_forward_pass_for_every_encoding():
    """The search works on first-layer pre-activations; the input vector it stands for must give the
    same logits through the real forward pass, or what is found is not what is verified."""
    rng = np.random.default_rng(6)
    net = mt.build_mlp({"W1": rng.normal(size=(6, 760)), "b1": rng.normal(size=6),
                        "W2": rng.normal(size=(3, 6)), "b2": rng.normal(size=3)})
    for enc in mt.encodings_for(net)[0]:
        choice = rng.integers(0, enc.choices, size=enc.groups)
        vec = enc.vector(choice)
        assert vec.shape == (760,)
        assert np.allclose(net.forward(vec), net.tail(enc.z1(net, choice)[None, :])), enc.name
    signed = mt.encodings_for(net)[0][1]
    assert set(np.unique(signed.vector(rng.integers(0, 2, 760)))) == {-1.0, 1.0}


def test_bit_decoders_read_both_orders_and_both_widths():
    net8 = mt.build_mlp({"W1": np.ones((2, 16)), "b1": np.zeros(2)})
    enc = mt.encodings_for(net8)[0][0]
    readings = dict(enc.decodes(fx.bits_of("Hi").astype(int)))
    assert readings["8-bit MSB first"] == "Hi" and readings["8-bit LSB first"] == "\x12\x96"
    net7 = mt.build_mlp({"W1": np.ones((2, 14)), "b1": np.zeros(2)})
    enc7 = mt.encodings_for(net7)[0][0]
    assert dict(enc7.decodes(fx.bits_of("Hi", msb=False, width=7).astype(int))) == {
        "7-bit MSB first": "\x09\x4b", "7-bit LSB first": "Hi"}


# ---------------------------------------------------------------- the search

def test_search_finds_the_one_input_a_detector_net_accepts():
    net = mt.build_mlp(fx.detector_mlp(FLAG))
    enc = mt.encodings_for(net)[0][0]
    found = mt.search(net, enc, ("high", 0))
    assert found["score"] > 0 and np.array_equal(found["choice"], fx.bits_of(FLAG).astype(int))
    assert mt.random_rate(net, enc, ("high", 0)) == 0.0 and mt.random_rate(net, enc, ("low", 0)) == 1.0


def test_a_tie_is_not_on_the_targets_side():
    """A random input that leaves the output exactly at the decision line is not accepted: with the
    output weights all zero every input scores exactly 0, so neither side is reached."""
    net = mt.build_mlp({"W1": np.ones((4, 16)), "b1": np.zeros(4), "W2": np.zeros((1, 4)), "b2": np.zeros(1)})
    enc = mt.encodings_for(net)[0][0]
    assert mt.random_rate(net, enc, ("high", 0), samples=64) == 0.0
    assert mt.random_rate(net, enc, ("low", 0), samples=64) == 0.0


def test_without_the_leaky_stage_the_dead_relu_net_gives_the_search_nothing():
    """Why the search anneals: under the real ReLU every detector unit is dead away from the trigger,
    so coordinate ascent on the real objective alone never moves toward it."""
    net = mt.build_mlp(fx.detector_mlp(FLAG))
    enc = mt.encodings_for(net)[0][0]
    found = mt.search(net, enc, ("high", 0), schedule=(0.0,))
    assert found["score"] < 0 and not np.array_equal(found["choice"], fx.bits_of(FLAG).astype(int))
    barely = mt.search(net, enc, ("high", 0), schedule=(0.01, 0.0))            # any leak at all is enough here
    assert barely["score"] > 0 and np.array_equal(barely["choice"], fx.bits_of(FLAG).astype(int))


def test_extract_reports_the_trigger_with_the_real_forward_pass_numbers():
    net = mt.build_mlp(fx.detector_mlp(FLAG))
    report = mt.extract(net, FF)
    top = report["triggers"][0]
    assert mt.proven(top) and top["flags"] == [FLAG] and top["text"] == FLAG and top["clean"]
    assert (top["encoding"], top["decoder"], top["target"]) == ("bits 0/1", "8-bit MSB first", "high 0")
    assert top["score"] == pytest.approx(float(net.forward(fx.bits_of(FLAG))[0, 0])) == pytest.approx(0.5)
    assert top["random_rate"] == 0.0 and top["alternatives"] == []
    assert any("not searched after an accepted flag was found" in s for s in report["skipped"])


def test_a_flag_inside_other_characters_is_not_proof():
    assert mt._clean(FLAG + "\x00\x00", FLAG) and mt._clean("  " + FLAG, FLAG)
    assert not mt._clean("#[" + FLAG, FLAG) and not mt._clean(FLAG + "x", FLAG)
    entry = {"flags": [FLAG], "clean": False, "accepted": True}
    assert not mt.proven(entry) and mt.proven({**entry, "clean": True})
    assert not mt.proven({**entry, "clean": True, "accepted": False})


# ---------------------------------------------------------------- end to end: formats and encodings

def _torch_names(net):
    return {"fc1.weight": net["W1"], "fc1.bias": net["b1"], "fc2.weight": net["W2"], "fc2.bias": net["b2"]}


def _f32(net):
    return {k: v.astype(np.float32) for k, v in net.items()}


CASES = {
    "npz": (lambda: {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG))},
            "200-25-1", "bits 0/1", "8-bit MSB first"),
    "lsb-first": (lambda: {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG, msb=False))},
                  "200-25-1", "bits 0/1", "8-bit LSB first"),
    "signed-inputs": (lambda: {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG, signed=True))},
                      "200-25-1", "bits -1/+1", "8-bit MSB first"),
    "seven-bit": (lambda: {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG, chunk=7, width=7))},
                  "175-25-1", "bits 0/1", "7-bit MSB first"),
    "in-out-storage": (lambda: {"authenticator.npz": fx.npz_bytes(
        {k: (v.T.copy() if v.ndim == 2 else v) for k, v in fx.detector_mlp(FLAG).items()})},
        "200-25-1", "bits 0/1", "8-bit MSB first"),
    "safetensors": (lambda: {"model.safetensors": fx.safetensors_bytes(_f32(_torch_names(fx.detector_mlp(FLAG))))},
                    "200-25-1", "bits 0/1", "8-bit MSB first"),
    "torch-zip": (lambda: {"model.pt": fx.torch_zip_bytes(_torch_names(fx.detector_mlp(FLAG)))},
                  "200-25-1", "bits 0/1", "8-bit MSB first"),
    "json": (lambda: {"weights.json": json.dumps({k: v.tolist() for k, v in fx.detector_mlp(FLAG).items()}).encode()},
             "200-25-1", "bits 0/1", "8-bit MSB first"),
    "loose-npy": (lambda: {f"{k}.npy": _npy(v) for k, v in fx.detector_mlp(FLAG).items()},
                  "200-25-1", "bits 0/1", "8-bit MSB first"),
    "characters-over-255": (lambda: {"check.npz": fx.npz_bytes(fx.char_mlp(FLAG, 1 / 255))},
                            "25-50-1", "characters (code/255)", "one value per character"),
    "characters-raw-code": (lambda: {"check.npz": fx.npz_bytes(fx.char_mlp(FLAG, 1.0))},
                            "25-50-1", "characters (code)", "one value per character"),
    "one-hot": (lambda: {"check.npz": fx.npz_bytes(fx.onehot_mlp(FLAG, PRINTABLE95))},
                "2375-25-1", "one-hot x95", "one-hot over 95 characters"),
}


def _npy(arr) -> bytes:
    import io
    buf = io.BytesIO()
    np.save(buf, arr)
    return buf.getvalue()


@pytest.mark.parametrize("case", sorted(CASES))
def test_solve_recovers_the_flag_from_each_format_and_encoding(tmp_path, case):
    build, shape, encoding, decoder = CASES[case]
    result = _solve(tmp_path, build())
    assert result.status == "solved" and result.flags == (FLAG,), result.notes
    assert result.engine == "toolkits.model_trigger"
    proof = [e for e in result.evidence if e.kind == "forward-pass"]
    assert proof and f"rebuilt as a {shape} relu MLP" in proof[0].detail
    assert f"input read as {encoding}, {decoder}" in proof[0].detail
    assert "(0.0% of random inputs are there)" in proof[0].detail
    assert SolverResult.from_json(result.to_json()) == result


def test_custom_one_hot_alphabet_is_an_option(tmp_path):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789{}_!"           # 40 characters, the author's own order
    flag = "flag{custom_alphabet_42}"
    files = {"check.npz": fx.npz_bytes(fx.onehot_mlp(flag, alphabet))}
    assert _solve(tmp_path, files).status in ("none", "unsure")       # the standard alphabets do not read it
    result = _solve(tmp_path, files, alphabet=alphabet)
    assert result.status == "solved" and result.flags == (flag,)
    assert "one-hot over 40 characters" in next(e.detail for e in result.evidence if e.kind == "forward-pass")


# ---------------------------------------------------------------- tampered classifiers

@pytest.mark.parametrize("classes", [1, 3])
@pytest.mark.parametrize("strict", [True, False])
def test_a_benign_net_with_an_implanted_unit_is_solved_and_the_unit_is_named(tmp_path, classes, strict):
    result = _solve(tmp_path, {"model.npz": fx.npz_bytes(fx.tampered_mlp(FLAG, classes=classes, strict=strict))})
    assert result.status == "solved" and result.flags == (FLAG,), result.notes
    anomaly = next(e for e in result.evidence if e.kind == "anomaly")
    assert "1 outlier unit(s)" in anomaly.detail and "W1[7] " in anomaly.detail
    spelled = [e for e in result.evidence if "an outlier unit, W1[7], spells it" in e.detail]
    assert spelled and spelled[0].kind == "forward-pass"
    assert f"on the {'high 0' if classes == 1 else 'class 2'} side" in spelled[0].detail
    # a tolerant unit accepts neighbours of the flag: they are reported as weaker readings, never returned
    assert ("weaker reading(s) not returned" in result.notes) == (not strict)


def test_unit_readoff_spells_the_flag_from_the_implanted_unit_alone():
    net = mt.build_mlp(fx.tampered_mlp(FLAG, strict=False))
    enc = mt.encodings_for(net)[0][0]
    hits = mt.unit_readoffs(net, enc, FF, lambda target: mt.random_rate(net, enc, target), frozenset({7}))
    assert [(h["unit"], h["polarity"], h["flags"]) for h in hits] == [(7, "highest", [FLAG])]
    assert hits[0]["accepted"] and hits[0]["anomalous"] and hits[0]["clean"] and hits[0]["target"] == "high 0"
    assert hits[0]["score"] == pytest.approx(float(net.forward(fx.bits_of(FLAG))[0, 0]))


def test_a_unit_that_spells_the_flag_but_does_not_flip_the_net_is_only_a_candidate(tmp_path):
    """The unit's weights are the complement pattern (it is most active on the inverted text), so the
    text is read off its lowest-weighted values and the forward pass does not accept it."""
    net = fx.tampered_mlp(FLAG)
    net["W1"][7] *= -1.0
    built = mt.build_mlp(net)
    enc = mt.encodings_for(built)[0][0]
    hits = mt.unit_readoffs(built, enc, FF, lambda target: mt.random_rate(built, enc, target))
    assert [(h["unit"], h["polarity"], h["accepted"]) for h in hits if h["flags"] == [FLAG]] == [(7, "lowest", False)]
    result = _solve(tmp_path, {"model.npz": fx.npz_bytes(net)})
    assert result.status == "candidate" and result.flags[0] == FLAG
    assert "does not accept the decoded input as a rare one" in result.notes
    assert all(e.kind != "forward-pass" for e in result.evidence)


def test_when_no_unit_spells_it_and_neighbours_are_accepted_the_result_is_a_candidate(tmp_path):
    result = _solve(tmp_path, {"model.npz": fx.npz_bytes(fx.split_tampered_mlp(FLAG))})
    assert result.status == "candidate" and result.flags[0] == FLAG and len(result.flags) > 1, result.notes
    assert "several different flags were recovered" in result.notes
    assert all(f != FLAG and len(f) == len(FLAG) for f in result.flags[1:])
    proof = next(e for e in result.evidence if e.kind == "forward-pass")
    assert "the search's best input for high 0" in proof.detail and "other accepted flag(s) one position away" in proof.detail


# ---------------------------------------------------------------- nothing there, not a flag, unknown format

def test_a_net_with_no_backdoor_is_none(tmp_path):
    rng = np.random.default_rng(5)
    benign = {"W1": rng.normal(0, 0.2, (16, 64)), "b1": rng.normal(0, 0.1, 16),
              "W2": rng.normal(0, 0.3, (1, 16)), "b2": np.array([0.1])}
    result = _solve(tmp_path, {"model.npz": fx.npz_bytes(benign)})
    assert result.status == "none" and result.flags == ()
    assert "no input that the rebuilt net accepts decodes to a flag" in result.notes


def test_an_accepted_input_that_is_text_but_not_a_flag_is_unsure(tmp_path):
    result = _solve(tmp_path, {"auth.npz": fx.npz_bytes(fx.detector_mlp("open sesame 4242!"))})
    assert result.status == "unsure" and result.flags == ()
    assert "'open sesame 4242!'" in result.notes and "outside the flag format" in result.notes


def test_per_character_text_counts_only_when_the_net_pins_it_down(tmp_path):
    """Any input of a one-value-per-character net is printable, so an accepted soft optimum is not
    reported as text; an exact-match net's text is."""
    exact = _solve(tmp_path, {"auth.npz": fx.npz_bytes(fx.char_mlp("open sesame 4242!"))})
    assert exact.status == "unsure" and "'open sesame 4242!'" in exact.notes
    rng = np.random.default_rng(3)
    soft = {"W1": rng.normal(0, 0.2, (12, 20)), "b1": np.zeros(12), "W2": np.abs(rng.normal(0, 0.3, (1, 12))),
            "b2": np.array([-3.0])}
    net = mt.build_mlp(soft)
    report = mt.extract(net, FF)
    reached = [t for t in report["triggers"] if t["accepted"]]
    assert reached and all(t["text"] is None for t in reached)       # it is reached, on a rare side, and says nothing
    other = tmp_path / "soft"
    result = _solve(other, {"model.npz": fx.npz_bytes(soft)})
    assert result.status == "none" and result.evidence == ()


def test_unknown_flag_format_caps_the_result_at_candidate(tmp_path):
    result = _solve(tmp_path, {"auth.npz": fx.npz_bytes(fx.detector_mlp("zzz{made_up_value}"))}, profile=_profile([]))
    assert result.status == "candidate" and result.flags == ("zzz{made_up_value}",)
    assert "flag format is not known yet" in result.notes


def test_no_model_file_is_none_and_a_pickle_is_never_loaded(tmp_path):
    import pickle
    result = _solve(tmp_path, {"readme.txt": b"hello", "model.pt": pickle.dumps({"W1": [[1.0]]}, protocol=4)})
    assert result.status == "none" and "no small model file" in result.notes
    assert "is a pickle; it is never loaded" in result.notes


# ---------------------------------------------------------------- activation

def test_activation_named_in_the_file_is_used_without_trying_others(tmp_path):
    net = _f32(_torch_names(fx.detector_mlp(FLAG)))
    ts = tensors.load_bytes(fx.safetensors_bytes(net, metadata={"activation": "tanh"}), "m.safetensors")
    assert mt.activation_hint(ts) == "tanh"
    rep = mt.analyze_set(ts, FF)
    assert rep["activation"] == "tanh" and not any("activation not named" in n for n in rep["notes"])
    plain = tensors.load_bytes(fx.safetensors_bytes(net), "m.safetensors")
    assert mt.activation_hint(plain) is None
    assert any(n.startswith("activation not named by the file: tried relu;") for n in mt.analyze_set(plain, FF)["notes"])


def test_when_relu_finds_no_flag_the_other_activations_are_tried(tmp_path):
    files = {"check.npz": fx.npz_bytes(fx.tanh_bump_mlp("CSCTF{tanh_bump}"))}
    result = _solve(tmp_path, files)
    assert result.status == "solved" and result.flags == ("CSCTF{tanh_bump}",), result.notes
    assert "activation not named by the file: tried relu, tanh; the result is under tanh" in result.notes
    proof = next(e for e in result.evidence if e.kind == "forward-pass")
    assert "16-32-1 tanh MLP" in proof.detail and "characters (code)" in proof.detail
    forced = _solve(tmp_path, files, activation="relu")                # the option is honoured: ReLU alone finds none
    assert forced.status == "none" and forced.flags == ()
    assert "activation not named" not in forced.notes


# ---------------------------------------------------------------- options, budget, files

@pytest.mark.parametrize("opts, message", [
    ({"activation": "swish"}, "option activation='swish' is not one of relu"),
    ({"budget_s": 0}, "option budget_s=0 must be positive"),
    ({"budget_s": "soon"}, "option budget_s='soon' is not a number"),
    ({"seed": -1}, "option seed=-1 is not a non-negative integer"),
    ({"alphabet": "aab"}, "option alphabet must be a string of two or more distinct characters"),
    ({"max_inputs": True}, "option max_inputs=True is not a number"),
])
def test_a_wrong_option_blocks_with_its_name(tmp_path, opts, message):
    result = mt.solve(_challenge(tmp_path, {"auth.npz": fx.npz_bytes(fx.detector_mlp(FLAG))}), CSCTF, **opts)
    assert result.status == "blocked" and message in result.notes


def test_a_spent_budget_stops_the_search_and_says_so(tmp_path):
    ticks = iter(range(10_000))
    result = _solve(tmp_path, {"auth.npz": fx.npz_bytes(fx.detector_mlp(FLAG))},
                    budget_s=2, clock=lambda: float(next(ticks)))             # a step clock: one second per look
    assert result.status == "none" and result.flags == ()
    assert "search cut by the CPU budget" in result.notes and "CPU budget spent before it was searched" in result.notes


def test_input_cap_is_named(tmp_path):
    result = _solve(tmp_path, {"auth.npz": fx.npz_bytes(fx.detector_mlp(FLAG))}, max_inputs=100)
    assert result.status == "none" and "200 inputs is over the 100 input search cap" in result.notes


def test_model_files_are_found_once_and_recon_is_left_alone(tmp_path, monkeypatch):
    raw = fx.npz_bytes(fx.detector_mlp(FLAG))
    ch = _challenge(tmp_path, {"authenticator.npz": raw})
    for rel in ("unpacked/authenticator.npz", "recon/engines/x/copy.npz"):
        (ch / rel).parent.mkdir(parents=True, exist_ok=True)
        (ch / rel).write_bytes(raw if rel.startswith("unpacked") else fx.npz_bytes(fx.detector_mlp("CSCTF{in_recon_dir}")))
    (ch / "challenge.json").write_text(json.dumps({"id": "9154", "name": "x"}))
    sets, notes = mt.find_model_sets(ch)
    assert [s.source for s in sets] == ["files/authenticator.npz"] and notes == []
    monkeypatch.setattr(tensors, "MAX_FILE", 100)
    sets, notes = mt.find_model_sets(ch)
    assert sets == [] and any("too large to be a small net" in n for n in notes)


# ---------------------------------------------------------------- wiring: manifest, router, runner, intake

def test_manifest_is_a_cheap_contract_engine_with_an_intake_adapter():
    from ctf.engines import manifest
    m = {x.id: x for x in manifest.discover(REPO)}["toolkits.model_trigger"]
    assert m.entry_raw == "solvers.toolkits.model_trigger:solve" and m.cost_class == "cheap"
    assert m.intake.run == "challenge" and m.intake.select == "route" and "py:numpy" in m.needs_tools


def test_router_sends_small_net_challenges_here(tmp_path):
    from ctf.engines import router
    ch = _challenge(tmp_path, {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG))})
    ids = [h.manifest.id for h in router.route("ML", "The sentry trusts this model. Forge the order.", ch / "files")]
    assert ids[0] == "toolkits.model_trigger"
    misc = [h.manifest.id for h in router.route("misc", "the authenticator was backdoored; find what it accepts",
                                                 ch / "files")]
    assert "toolkits.model_trigger" in misc
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "toolkits.model_trigger" not in [h.manifest.id for h in router.route("ML", "a backdoored model", empty)]


def test_a_symlinked_model_file_is_not_followed(tmp_path):
    """A link in the challenge folder could point at a file outside it: discovery names it and does
    not read it."""
    outside = tmp_path / "elsewhere" / "net.npz"
    outside.parent.mkdir()
    outside.write_bytes(fx.npz_bytes(fx.detector_mlp(FLAG)))
    ch = _challenge(tmp_path, {})
    (ch / "files").mkdir(parents=True, exist_ok=True)
    (ch / "files" / "net.npz").symlink_to(outside)
    sets, notes = mt.find_model_sets(ch)
    assert sets == [] and "files/net.npz: a symlink, not followed" in notes
    result = mt.solve(ch, CSCTF, budget_s=BUDGET)
    assert result.status == "none" and not result.flags
    (ch / "files" / "linked").symlink_to(outside.parent, target_is_directory=True)
    assert mt.find_model_sets(ch)[0] == []                                     # nor through a linked folder


def test_the_challenge_wide_model_budget_drops_what_does_not_fit(tmp_path, monkeypatch):
    first, second = fx.npz_bytes(fx.detector_mlp(FLAG)), fx.npz_bytes(fx.tampered_mlp(FLAG))
    ch = _challenge(tmp_path, {"a.npz": first, "b.npz": second})
    sets, _ = mt.find_model_sets(ch)
    cost_a = len(first) + sum(a.nbytes for a in sets[0].tensors.values())
    monkeypatch.setattr(mt, "MAX_CHALLENGE_BYTES", cost_a + len(second))      # b's file fits, its tensors do not
    sets, notes = mt.find_model_sets(ch)
    assert [s.source for s in sets] == ["files/a.npz"]
    assert any(n.startswith("b.npz: not kept") and "model-file budget" in n for n in notes)
    monkeypatch.setattr(mt, "MAX_CHALLENGE_BYTES", cost_a)                     # room for exactly the first
    sets, notes = mt.find_model_sets(ch)
    assert [s.source for s in sets] == ["files/a.npz"] and any(n.startswith("b.npz: not read") for n in notes)
    monkeypatch.setattr(mt, "MAX_CHALLENGE_BYTES", len(first) - 1)              # not even the first file is read
    sets, notes = mt.find_model_sets(ch)
    assert sets == [] and "a.npz: not read" in notes[0]


def test_router_puts_a_plain_torch_checkpoint_after_the_model_file_readers(tmp_path):
    """A .pt with no backdoor word is as likely a pickle-exploit file: the static readers rank first
    there. An npz or safetensors file, or a brief that names a backdoor, still ranks this engine first."""
    from ctf.engines import router
    ch = _challenge(tmp_path, {"model.pt": fx.torch_zip_bytes(fx.detector_mlp(FLAG))})
    ids = [h.manifest.id for h in router.route("ML", "Load our model and tell us what it does.", ch / "files")]
    assert "toolkits.model_trigger" in ids
    assert ids.index("toolkits.ai_model_files") < ids.index("toolkits.model_trigger")
    told = [h.manifest.id for h in router.route("ML", "this model was backdoored", ch / "files")]
    assert told.index("toolkits.model_trigger") < told.index("toolkits.ai_model_files")


def test_ctf_run_prints_the_solver_result(tmp_path):
    from ctf.engines import runner
    ch = _challenge(tmp_path, {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG))})
    cmd = runner.command("toolkits.model_trigger", [str(ch), "--event", "csctf", "--opt", "budget_s=300"], record=False)
    cp = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO,
                        env={**os.environ, "CTF_WORKDIR": str(tmp_path)})
    assert cp.returncode == 0, cp.stderr
    result = SolverResult.from_json(cp.stdout.strip().splitlines()[-1])
    assert result.status == "solved" and result.flags == (FLAG,) and result.engine == "toolkits.model_trigger"


class _Adapter:
    kind = "fake"

    def __init__(self, ch, files):
        self.ch, self.files = ch, files

    def get_challenge(self, cid):
        return self.ch

    def list_challenges(self):
        return [self.ch]

    def download_files(self, cid, dest):
        out = []
        for rel, data in self.files.items():
            p = Path(dest) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            out.append(p)
        return out

    def submit(self, cid, flag):
        raise AssertionError("intake never submits")

    def team_solves(self):
        return []


def test_intake_runs_it_on_an_ml_challenge_with_no_model_in_the_loop(tmp_path):
    from ctf import intake as I
    from ctf.platform.base import Challenge, FileRef
    ch = Challenge(id="9154", name="The Sentry's Model (synthetic)", category="ML", points=870,
                   description="The sentry only opens for one order. Recover it.",
                   files=(FileRef("authenticator.npz"),))
    rep = I.intake_one("9154", CSCTF, adapter=_Adapter(ch, {"authenticator.npz": fx.npz_bytes(fx.detector_mlp(FLAG))}),
                       workdir=tmp_path / "wd", options=I.Options(net_guard="hook", record=False))
    runs = [r for r in rep.runs if r.engine == "toolkits.model_trigger"]
    assert runs and runs[0].status == "ok" and runs[0].result_status == "solved", (rep.plan, rep.notes)
    assert runs[0].flags == (FLAG,)
    assert rep.status == "solved" and FLAG in rep.flags


def test_search_caps_are_named_not_silent(monkeypatch):
    net = mt.build_mlp(fx.tampered_mlp(FLAG, classes=3))
    monkeypatch.setattr(mt, "MAX_TARGETS", 2)
    report = mt.extract(net, FF)
    assert "3 classes: only the first 2 were searched" in report["skipped"]
    assert {t["target"] for t in report["triggers"] if t["source"] == "search"} == {"class 0", "class 1"}
    monkeypatch.setattr(mt, "MAX_CONTRIB", 200 * 2 * 48)                       # room for the bit tables only
    encs, skipped = mt.encodings_for(net)
    assert [e.name for e in encs] == ["bits 0/1", "bits -1/+1"]
    assert "characters (code/255): 200 x 96 x 48 values is over the search table cap" in skipped


def test_activation_hint_reads_metadata_and_tensor_names():
    hinted = tensors.TensorSet("npz", "m.npz", tensors={"sigmoid_out.weight": np.zeros((1, 2))})
    assert mt.activation_hint(hinted) == "sigmoid"
    leaky = tensors.TensorSet("safetensors", "m", tensors={"w": np.zeros((1, 2))}, metadata={"act": "LeakyReLU(0.01)"})
    assert mt.activation_hint(leaky) == "leaky_relu"


def test_when_the_shapes_allow_two_orientations_the_narrowing_then_the_torch_one_is_taken():
    w = np.arange(8.0).reshape(1, 8)
    for stored in (w, w.T.copy()):                                             # a single layer, no bias to decide
        net = mt.build_mlp({"weight": stored})
        assert net.shape == "8-1" and np.allclose(net.forward(np.ones(8)), [[28.0]])
        assert any("the shapes allow another orientation" in n for n in net.notes)
    auto = mt.build_mlp({"dec.weight": np.ones((6, 4)), "enc.weight": np.ones((4, 6))})
    assert auto.shape == "4-6-4" and not any("stored (in, out)" in n for n in auto.notes)


def test_accepted_means_beating_the_best_other_class():
    logits = np.array([[1.0, 5.0, 3.0]])
    assert mt._score(logits, ("class", 2), True)[0] == -2.0                    # the real decision: 3 against 5
    assert mt._score(logits, ("class", 2), False)[0] == 0.0                    # the search stand-in: 3 against the mean
    assert mt._score(np.array([[2.5]]), ("high", 0), True)[0] == 2.5 == -mt._score(np.array([[2.5]]), ("low", 0), True)[0]
    net = mt.build_mlp({"W": np.array([[1.0, 0.0], [0.0, 1.0], [1.0, 1.0]]), "b": np.array([0.0, 2.0, 0.5])})
    assert mt._landing(net, np.array([1.0, 0.0])) == (("class", 1), 0.5)       # logits 1, 2, 1.5


def test_only_printable_flags_count_and_padding_is_dropped():
    assert mt._flags_in(FLAG + "\x00\x00\x00", FF) == [FLAG]
    assert mt._flags_in("CSCTF{a\x01b}", FF) == [] and mt._flags_in("CSCTF{caf\xe9}", FF) == []
    assert mt._flags_in("no flag here", FF) == []


def test_a_flag_the_net_scores_highest_but_accepts_everything_around_is_only_a_candidate(tmp_path):
    """The same detector with its output bias raised so every input is accepted: the best-scoring
    input is still the flag, but the forward pass flips nothing, so it is not proof."""
    net = fx.detector_mlp(FLAG)
    net["b2"] = net["b2"] + 100.0
    result = _solve(tmp_path, {"auth.npz": fx.npz_bytes(net)})
    assert result.status == "candidate" and result.flags == (FLAG,)
    assert "does not accept the decoded input as a rare one" in result.notes
    assert result.evidence and {e.kind for e in result.evidence} == {"decode"}
    assert "(100.0% of random inputs are there)" in result.evidence[0].detail


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
