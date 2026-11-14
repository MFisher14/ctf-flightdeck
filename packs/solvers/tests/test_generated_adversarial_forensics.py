"""Deterministic tests for transparent generated-content/adversarial evidence."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "solvers" / "toolkits" / "generated_adversarial_forensics.py"
SPEC = importlib.util.spec_from_file_location("r5g_generated_adversarial_forensics_tested", MODULE)
assert SPEC and SPEC.loader
G = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = G
SPEC.loader.exec_module(G)


def test_text_features_are_transparent_and_reference_calibration_is_caller_supplied():
    result = G.generated_text_features(
        "One short sentence. One short sentence. One short sentence!",
        references={"varied": ["A tiny line. Then a substantially longer and different line appears!",
                               "Words vary wildly; rhythm changes."],
                    "repetitive": ["one short sentence one short sentence", "repeat repeat repeat repeat"]},
    )
    features = result["features"]
    assert features["tokens"] == 9
    assert features["bigram_repetition"] > 0
    assert features["compression_ratio"] > 0
    assert {row["label"] for row in result["reference_calibration"]} == {"varied", "repetitive"}
    assert result["ai_generated_verified"] is False
    assert "not an authorship verdict" in result["note"]


def test_greenlist_uses_supplied_memberships_and_never_infers_a_key():
    result = G.greenlist_watermark_test([True] * 24, expected_rate=0.5)
    assert result["matches"] == 24
    assert result["one_sided_p_value"] == pytest.approx(2 ** -24)
    assert result["membership_source"] == "caller-supplied"
    assert result["key_inferred"] is False and result["watermark_verified"] is False


def test_provenance_reports_exact_generator_and_redacts_prompt_value():
    metadata = {"Software": "ComfyUI", "workflow": {"positive_prompt": "private fixture prompt",
                                                       "sampler": "euler"},
                "c2pa_present": True}
    result = G.provenance_evidence(metadata)
    kinds = {row["kind"] for row in result["findings"]}
    assert {"generator-metadata", "generation-workflow-field"} <= kinds
    assert result["c2pa_fields"] == [{"key": "c2pa_present", "value": True}]
    assert "private fixture prompt" not in G.stable_json(result)
    assert result["provenance_validated"] is False


def test_adversarial_structure_delegates_base_metrics_and_adds_components_effect():
    original = [0.0] * 16
    modified = [1.0, 1.0, 0.0, 0.0] + [0.0] * 12
    result = G.adversarial_structure_report(
        original, modified, shape=[4, 4], value_range=[0, 1],
        outputs={"original_label": "cat", "modified_label": "dog",
                 "original_scores": [0.8, 0.2], "modified_scores": [0.1, 0.9]},
    )
    assert result["base_metrics"]["l0"] == 2
    assert result["structure"]["component_count"] == 1
    assert result["structure"]["component_sizes"] == [2]
    assert result["structure"]["total_variation"] == 3
    assert result["saved_output_effect"]["label_changed"] is True
    assert {row["kind"] for row in result["findings"]} >= {"compact-perturbation-candidate", "saved-label-flip"}
    assert result["adversarial_effect_verified"] is False and result["model_loaded"] is False


def test_rgb_channel_snr_and_universal_delta_alignment():
    original = [1.0, 1.0, 1.0] * 4
    modified = [1.0, 1.5, 1.0] * 4
    report = G.adversarial_structure_report(original, modified, shape=[2, 2, 3], value_range=[0, 2])
    assert report["structure"]["channels"] == 3
    assert report["structure"]["channel_snr"][1]["noise_rms"] == 0.5
    pairs = [{"original": [index, 0, 0], "modified": [index + 1, 0, 0]} for index in range(4)]
    universal = G.universal_perturbation_report(pairs)
    assert universal["mean_pairwise_cosine"] == pytest.approx(1)
    assert universal["centroid_to_mean_norm_ratio"] == pytest.approx(1)
    assert universal["comparisons_capped"] is False and universal["similarity_scope"] == "complete"
    assert universal["findings"][0]["kind"] == "shared-delta-candidate"

    capped = G.universal_perturbation_report(
        [{"original": [index], "modified": [index + 1]} for index in range(202)])
    assert capped["full_pair_comparisons"] == 202 * 201 // 2
    assert capped["comparisons"] == G.MAX_COMPARISONS
    assert capped["comparisons_capped"] is True and capped["similarity_scope"] == "partial-prefix"
    assert capped["findings"] == []


def test_fail_closed_bounds_and_no_runtime_or_transport_surface():
    with pytest.raises(ValueError):
        G.generated_text_features("x", references={"bad": "not-a-list"})
    with pytest.raises(ValueError):
        G.greenlist_watermark_test([True, 1])
    with pytest.raises(ValueError):
        G.greenlist_watermark_test([True] * (G._integrity().MAX_ROWS + 1))
    with pytest.raises(ValueError):
        G.adversarial_structure_report([0], [1], shape=[1])
    with pytest.raises(ValueError):
        G.provenance_evidence({str(index): "x" for index in range(G.MAX_METADATA_ITEMS + 1)})
    with pytest.raises(ValueError):
        G.universal_perturbation_report([{"original": [], "modified": []}] * 2)
    with pytest.raises(ValueError):
        G.universal_perturbation_report([{"original": [10 ** 10000], "modified": [0]}] * 2)
    extreme = G.adversarial_structure_report(
        [1e100, -1e100, 1e100, -1e100],
        [0.9e100, -0.9e100, 1.1e100, -1.1e100], shape=[2, 2])
    assert G.stable_json(extreme)
    source = MODULE.read_text(encoding="utf-8")
    forbidden = ("pickle.load", "torch.load", "load_model(", "onnxruntime", "tensorflow",
                 "requests.", "urllib.request", "socket.", "subprocess.")
    assert not any(token in source for token in forbidden)

