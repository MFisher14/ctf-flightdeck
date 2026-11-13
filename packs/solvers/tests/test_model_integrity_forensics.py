"""Deterministic tests for saved-evidence model integrity helpers."""
from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "solvers" / "toolkits" / "model_integrity_forensics.py"
SPEC = importlib.util.spec_from_file_location("r5g_model_integrity_forensics_tested", MODULE)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)


def test_saved_backdoor_pairs_find_target_uplift_without_claiming_causality():
    rows = []
    for index in range(12):
        rows.append({"true_label": str(index % 3), "clean_prediction": str(index % 3),
                     "triggered_prediction": "target" if index < 11 else str(index % 3),
                     "clean_confidence": 0.8, "triggered_confidence": 0.95})
    report = M.backdoor_behavior_report(rows)
    assert report["target_candidate"] == "target"
    assert report["target_count"] == 11 and report["target_fraction"] == 11 / 12
    assert report["clean_accuracy"] == 1
    assert report["findings"][0]["kind"] == "target-concentration-candidate"
    assert report["backdoor_verified"] is False
    with pytest.raises(ValueError):
        M.backdoor_behavior_report([{"clean_prediction": "a", "triggered_prediction": "b",
                                     "clean_confidence": 2, "triggered_confidence": 0.5}])


def test_activation_spectral_report_is_deterministic_bounded_and_group_aware():
    clean = [[-0.2, 0.0], [-0.1, 0.1], [0.0, -0.1], [0.1, 0.0], [0.2, 0.1]]
    marked = [[8.0, 8.1], [8.2, 7.9], [7.8, 8.0]]
    report = M.activation_spectral_report(clean + marked, trigger_flags=[False] * 5 + [True] * 3)
    assert report["samples"] == 8 and report["dimensions"] == 2
    assert report["top_eigenvalue"] > 0
    assert report["group_comparison"]["standardized_separation"] > 2
    assert any(row["kind"] == "trigger-group-separation-candidate" for row in report["findings"])
    assert report["backdoor_verified"] is False
    with pytest.raises(ValueError):
        M.activation_spectral_report([[1, 2], [3]])
    with pytest.raises(ValueError):
        M.activation_spectral_report([[1, math.nan], [2, 3]])


def test_neural_cleanse_uses_saved_norms_only_and_handles_zero_mad():
    result = M.neural_cleanse_summary({"a": 10, "b": 10.5, "c": 9.5, "target": 0.1})
    assert result["minimum_class"] == "target"
    assert result["anomaly_index"] > 2
    assert result["findings"][0]["kind"] == "small-mask-outlier-candidate"
    assert result["optimization_performed"] is False
    flat = M.neural_cleanse_summary({"a": 1, "b": 1, "c": 1})
    assert flat["anomaly_index"] is None and flat["findings"] == []


def test_weight_outliers_and_energy_concentration_are_descriptive():
    concentrated = [100.0] + [0.01] * 99
    result = M.weight_outlier_report([
        {"name": "dense/kernel", "values": concentrated},
        {"name": "balanced", "values": [-1, 1] * 20},
    ])
    first = result["tensors"][0]
    assert first["top_one_percent_energy_fraction"] > 0.99
    assert any(row["tensor"] == "dense/kernel" for row in result["findings"])
    assert result["backdoor_verified"] is False


def test_watermark_binomial_controls_and_weight_signature():
    trials = [{"expected": 1, "observed": 1} for _ in range(24)]
    trials += [{"match": index % 2 == 0, "control": True} for index in range(10)]
    result = M.watermark_response_report(trials)
    assert result["trials"] == result["matches"] == 24
    assert result["control_match_rate"] == 0.5
    assert result["one_sided_p_value"] == pytest.approx(2 ** -24)
    assert result["findings"][0]["kind"] == "watermark-response-candidate"
    assert result["watermark_verified"] is False and result["model_loaded"] is False

    signature = M.weight_signature_report([2, -3, 0.01, -0.01], [1, 0, 1, 0], margin=0.1)
    assert signature["observed_bits"] == [1, 0, None, None]
    assert signature["decided_bits"] == signature["matches"] == 2
    assert signature["hamming_distance"] == 0


def test_module_has_no_runtime_loader_transport_or_execution_surface():
    source = MODULE.read_text(encoding="utf-8")
    forbidden = ("pickle.load", "torch.load", "load_model(", "onnxruntime", "tensorflow",
                 "requests.", "urllib.request", "socket.", "subprocess.", "eval(", "exec(")
    assert not any(token in source for token in forbidden)
    with pytest.raises(ValueError):
        M.neural_cleanse_summary({str(index): 1 for index in range(M.MAX_ROWS + 1)})
    with pytest.raises(ValueError):
        M.weight_outlier_report([{"name": "bad", "values": [math.inf]}])
    with pytest.raises(ValueError):
        M.weight_signature_report([10 ** 10000], [1])

