from __future__ import annotations

import itertools
import json
import math
import sys
from pathlib import Path

import pytest


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_geo_ml as G  # noqa: E402


def assert_offline_human(report):
    assert report["model_called"] is False
    assert report["embedding_generated"] is False
    assert report["automatic_answer"] is None
    assert report["requires_human_pin"] is True
    json.dumps(report, allow_nan=False)


def test_saved_embedding_rank_consensus_margin_and_outlier_detection():
    report = G.rank_embedding_candidates(
        [
            {"crop_id": "full", "model": "saved-a", "embedding": [1.0, 0.0]},
            {"crop_id": "sign", "model": "saved-a", "embedding": [0.9, 0.1]},
            {"crop_id": "sky", "model": "saved-b", "embedding": [0.0, 1.0]},
        ],
        [
            {"id": "bucharest", "label": "Bucharest", "embedding": [1.0, 0.0],
             "coordinate": [44.4268, 26.1025], "source": "saved gallery"},
            {"id": "paris", "label": "Paris", "embedding": [0.0, 1.0],
             "coordinate": [48.8566, 2.3522], "source": "saved gallery"},
        ],
    )
    assert report["dimension"] == 2
    assert report["candidates"][0]["id"] == "bucharest"
    assert report["candidates"][0]["top_votes"] == 2
    assert report["outlier_queries"] == ["sky"]
    assert report["consensus_unanimous"] is False
    assert report["model_top_votes"] == {
        "saved-a": {"bucharest": 2}, "saved-b": {"paris": 1}}
    assert all(math.isfinite(row["mean_cosine"]) for row in report["candidates"])
    assert_offline_human(report)


def test_scaled_cosine_handles_large_finite_vectors_and_rejects_bad_shapes():
    report = G.rank_embedding_candidates(
        [{"id": "q", "embedding": [1e308, 1e308]}],
        [{"id": "same", "embedding": [1e308, 1e308]},
         {"id": "opposite", "embedding": [-1e308, -1e308]}],
    )
    assert report["candidates"][0]["mean_cosine"] == pytest.approx(1.0)
    assert_offline_human(report)
    with pytest.raises(G.GeoMLError, match="zero-norm"):
        G.rank_embedding_candidates(
            [{"id": "q", "embedding": [0, 0]}],
            [{"id": "a", "embedding": [1, 0]}, {"id": "b", "embedding": [0, 1]}])
    with pytest.raises(G.GeoMLError, match="dimension"):
        G.rank_embedding_candidates(
            [{"id": "q", "embedding": [1, 0]}],
            [{"id": "a", "embedding": [1]}, {"id": "b", "embedding": [0]}])
    with pytest.raises(G.GeoMLError, match="non-finite"):
        G.rank_embedding_candidates(
            [{"id": "q", "embedding": [math.nan]}],
            [{"id": "a", "embedding": [1]}, {"id": "b", "embedding": [2]}])
    with pytest.raises(G.GeoMLError, match="controls"):
        G.rank_embedding_candidates(
            [{"id": "q", "embedding": [1]}],
            [{"id": "a", "embedding": [1], "source": "bad\nsource"},
             {"id": "b", "embedding": [2]}])


def test_classifier_uncertainty_votes_and_geographic_dispersion():
    report = G.analyze_classifier_outputs([
        {"crop_id": "one", "model": "saved-a", "predictions": [
            {"label": "Bucharest", "probability": 8, "coordinate": [44.4268, 26.1025]},
            {"label": "Paris", "probability": 2, "coordinate": [48.8566, 2.3522]},
        ]},
        {"crop_id": "two", "model": "saved-b", "predictions": [
            {"label": "Paris", "probability": 0.6, "coordinate": [48.8566, 2.3522]},
            {"label": "Bucharest", "probability": 0.4, "coordinate": [44.4268, 26.1025]},
        ]},
    ])
    assert report["outputs"] == 2
    assert report["candidates"][0]["label"] == "Bucharest"
    assert report["outlier_outputs"] == ["two"]
    assert report["top_coordinate_max_separation_m"] > 1_000_000
    assert report["geographically_dispersed"] is True
    assert report["per_output"][0]["renormalized"] is True
    assert 0 <= report["per_output"][0]["normalized_entropy"] <= 1
    assert_offline_human(report)


def test_classifier_probability_overflow_is_scale_safe_and_strict_json():
    report = G.analyze_classifier_outputs([{"id": "huge", "predictions": [
        {"label": "A", "probability": 1e308, "coordinate": [0, 0]},
        {"label": "B", "probability": 1e308, "coordinate": [1, 1]},
    ]}])
    assert report["per_output"][0]["top"]["probability"] == pytest.approx(0.5)
    assert report["per_output"][0]["margin"] == pytest.approx(0.0)
    assert report["per_output"][0]["renormalized"] is True
    assert_offline_human(report)
    for bad in (float("inf"), float("nan"), -1, True):
        with pytest.raises(G.GeoMLError):
            G.analyze_classifier_outputs([{"predictions": [
                {"label": "A", "probability": bad},
                {"label": "B", "probability": 1},
            ]}])


def test_fusion_combines_only_supplied_exif_ocr_and_landmark_evidence():
    ml = G.rank_embedding_candidates(
        [{"id": "q1", "embedding": [1, 0]}, {"id": "q2", "embedding": [1, 0.1]}],
        [{"id": "bucharest", "label": "Bucharest Clock Tower", "embedding": [1, 0],
          "coordinate": [44.4268, 26.1025]},
         {"id": "paris", "label": "Paris", "embedding": [0, 1],
          "coordinate": [48.8566, 2.3522]}],
    )
    report = G.fuse_geolocation_evidence(ml, {
        "exif_coordinate": {"lat": 44.4269, "lon": 26.1025},
        "ocr_place_names": ["Bucharest"],
        "landmark_candidates": [
            {"name": "Bucharest Clock Tower", "coordinate": [44.4268, 26.1025]},
        ],
    })
    assert report["candidates"][0]["label"] == "Bucharest Clock Tower"
    assert report["candidates"][0]["matched_ocr"] == ["bucharest"]
    assert report["candidates"][0]["landmark_match"] is True
    assert report["candidates"][0]["exif_distance_m"] < 20
    assert report["sources"] == ["exif", "ocr", "landmark"]
    assert report["evidence_conflict"] is False
    assert_offline_human(report)


@pytest.mark.parametrize("votes", [True, -1, 129, 1.5, "2"])
def test_fusion_rejects_untrusted_top_vote_types_and_ranges(votes):
    report = {"model_called": False, "embedding_generated": False,
              "automatic_answer": None, "requires_human_pin": True, "candidates": [
        {"id": "x", "label": "X", "coordinate": [0, 0], "top_votes": votes},
    ]}
    with pytest.raises(G.GeoMLError, match="top_votes"):
        G.fuse_geolocation_evidence(report, {})


def test_generator_and_fusion_collection_caps_do_not_hang(monkeypatch):
    monkeypatch.setattr(G, "MAX_QUERIES", 2)
    produced = []

    def forever():
        for index in itertools.count():
            produced.append(index)
            yield {"id": str(index), "embedding": [1, 0]}

    with pytest.raises(G.GeoMLError, match="exceeds the 2 item cap"):
        G.rank_embedding_candidates(
            forever(), [{"id": "a", "embedding": [1, 0]}, {"id": "b", "embedding": [0, 1]}])
    assert produced == [0, 1, 2]
    with pytest.raises(G.GeoMLError, match="record iterable"):
        G.analyze_classifier_outputs(42)

    monkeypatch.setattr(G, "MAX_CANDIDATES", 2)
    with pytest.raises(G.GeoMLError, match="ML candidates exceed"):
        G.fuse_geolocation_evidence(
            {"model_called": False, "embedding_generated": False,
             "automatic_answer": None, "requires_human_pin": True,
             "candidates": [{}, {}, {}]}, {})
    with pytest.raises(G.GeoMLError, match="OCR place names"):
        G.fuse_geolocation_evidence(
            {"model_called": False, "embedding_generated": False,
             "automatic_answer": None, "requires_human_pin": True, "candidates": []},
            {"ocr_place_names": ["x"] * 129})


def test_duplicate_saved_ids_labels_and_forged_online_reports_are_rejected():
    with pytest.raises(G.GeoMLError, match="query ids"):
        G.rank_embedding_candidates(
            [{"id": "same", "embedding": [1, 0]}, {"id": "same", "embedding": [0, 1]}],
            [{"id": "a", "embedding": [1, 0]}, {"id": "b", "embedding": [0, 1]}])
    with pytest.raises(G.GeoMLError, match="prediction labels"):
        G.analyze_classifier_outputs([{"id": "one", "predictions": [
            {"label": "A", "probability": 1}, {"label": "A", "probability": 2}]}])
    with pytest.raises(G.GeoMLError, match="offline saved-ML"):
        G.fuse_geolocation_evidence(
            {"model_called": False, "embedding_generated": True,
             "automatic_answer": None, "requires_human_pin": True, "candidates": []}, {})
    with pytest.raises(G.GeoMLError, match="offline saved-ML"):
        G.fuse_geolocation_evidence(
            {"model_called": False, "embedding_generated": False,
             "automatic_answer": "forged pin", "requires_human_pin": False,
             "candidates": []}, {})
    with pytest.raises(G.GeoMLError, match="controls"):
        G.rank_embedding_candidates(
            [{"id": "query\n", "embedding": [1]}],
            [{"id": "a", "embedding": [1]}, {"id": "b", "embedding": [2]}])


def test_fusion_distance_tie_break_preserves_exact_zero_distance():
    ml = {"model_called": False, "embedding_generated": False,
          "automatic_answer": None, "requires_human_pin": True,
          "candidates": [
              {"label": "A-near", "coordinate": [0, 0.001], "top_votes": 1},
              {"label": "Z-exact", "coordinate": [0, 0], "top_votes": 1},
          ]}
    report = G.fuse_geolocation_evidence(ml, {"exif_coordinate": [0, 0]})
    assert report["candidates"][0]["label"] == "Z-exact"
    assert report["candidates"][0]["exif_distance_m"] == pytest.approx(0)
