#!/usr/bin/env python3
"""Offline analysis of saved geolocation embeddings and classifier outputs.

This module never creates an embedding, imports a model framework, opens an image, or calls a
model/API. It validates caller-supplied numeric features and prediction records, measures consensus
and uncertainty, and fuses them with supplied EXIF/OCR/landmark evidence for human review.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

MAX_VECTOR = 16_384
MAX_QUERIES = 128
MAX_CANDIDATES = 2_000
MAX_PREDICTIONS = 256
MAX_TEXT = 512
EARTH_RADIUS_M = 6_371_008.8


class GeoMLError(ValueError):
    pass


def _take(values: Iterable[Any], cap: int, field: str, *, minimum: int = 0) -> list[Any]:
    if isinstance(values, (str, bytes, bytearray, Mapping)):
        raise GeoMLError(f"{field} must be a record iterable")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise GeoMLError(f"{field} must be a record iterable") from exc
    rows = []
    for _ in range(cap + 1):
        try:
            rows.append(next(iterator))
        except StopIteration:
            break
    if len(rows) > cap:
        raise GeoMLError(f"{field} exceeds the {cap} item cap")
    if len(rows) < minimum:
        raise GeoMLError(f"{field} needs at least {minimum} item(s)")
    return rows


def _text(value: Any, field: str) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise GeoMLError(f"{field} must be text")
    raw = str(value)
    result = raw.strip()
    if (not result or len(result) > MAX_TEXT or any(ord(ch) < 0x20 for ch in raw)
            or any(0xD800 <= ord(ch) <= 0xDFFF for ch in raw)):
        raise GeoMLError(f"{field} is empty, overlong, or contains controls")
    return result


def _vector(values: Any, field: str) -> list[float]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise GeoMLError(f"{field} must be a numeric vector")
    if not 1 <= len(values) <= MAX_VECTOR:
        raise GeoMLError(f"{field} dimension is outside 1..{MAX_VECTOR}")
    result = []
    for value in values:
        if isinstance(value, bool):
            raise GeoMLError(f"{field} contains a boolean")
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise GeoMLError(f"{field} contains a non-number") from exc
        if not math.isfinite(number):
            raise GeoMLError(f"{field} contains a non-finite number")
        result.append(number)
    return result


def _coordinate(value: Any) -> tuple[float, float] | None:
    if value in (None, ""):
        return None
    if isinstance(value, Mapping):
        pair = (value.get("latitude", value.get("lat")), value.get("longitude", value.get("lon")))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) == 2:
        pair = (value[0], value[1])
    else:
        raise GeoMLError("coordinate must be [lat,lon] or a mapping")
    if any(isinstance(item, bool) for item in pair):
        raise GeoMLError("coordinate contains a boolean")
    try:
        lat, lon = map(float, pair)
    except (TypeError, ValueError, OverflowError) as exc:
        raise GeoMLError("coordinate is not numeric") from exc
    if not all(map(math.isfinite, (lat, lon))) or not -90 <= lat <= 90 or not -180 <= lon <= 180:
        raise GeoMLError("coordinate is outside Earth bounds")
    return lat, lon


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise GeoMLError("embedding dimensions differ")
    scale_left = max(abs(value) for value in left)
    scale_right = max(abs(value) for value in right)
    if scale_left == 0 or scale_right == 0:
        raise GeoMLError("zero-norm embedding cannot be ranked")
    a = [value / scale_left for value in left]
    b = [value / scale_right for value in right]
    dot = math.fsum(x * y for x, y in zip(a, b))
    norm = math.sqrt(math.fsum(x * x for x in a) * math.fsum(y * y for y in b))
    result = max(-1.0, min(1.0, dot / norm))
    if not math.isfinite(result):
        raise GeoMLError("cosine result is non-finite")
    return result


def _distance(left: tuple[float, float], right: tuple[float, float]) -> float:
    p1, p2 = math.radians(left[0]), math.radians(right[0])
    dp, dl = p2 - p1, math.radians(right[1] - left[1])
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))


def _report(kind: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, **fields, "model_called": False, "embedding_generated": False,
            "automatic_answer": None, "requires_human_pin": True,
            "note": "saved-model evidence only; independently verify the scene and let the player pin"}


def rank_embedding_candidates(query_embeddings: Iterable[Mapping[str, Any]],
                              candidates: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Rank supplied candidate embeddings across crops/models with no model execution."""
    query_rows = _take(query_embeddings, MAX_QUERIES, "query embeddings", minimum=1)
    candidate_rows = _take(candidates, MAX_CANDIDATES, "embedding candidates", minimum=2)
    queries = []
    dimension = None
    seen_query_ids = set()
    for index, raw in enumerate(query_rows):
        if not isinstance(raw, Mapping):
            raise GeoMLError("query embeddings must be mappings")
        vector = _vector(raw.get("embedding"), f"query embedding {index}")
        dimension = dimension or len(vector)
        if len(vector) != dimension:
            raise GeoMLError("query embedding dimensions differ")
        query_id = _text(raw.get("crop_id", raw.get("id", f"query-{index}")), "query id")
        if query_id in seen_query_ids:
            raise GeoMLError("query ids must be unique")
        seen_query_ids.add(query_id)
        queries.append({"id": query_id,
                        "model": _text(raw.get("model", "saved-model"), "model name"),
                        "embedding": vector})
    normalized_candidates = []
    seen_ids = set()
    for index, raw in enumerate(candidate_rows):
        if not isinstance(raw, Mapping):
            raise GeoMLError("embedding candidates must be mappings")
        candidate_id = _text(raw.get("id", raw.get("label", f"candidate-{index}")), "candidate id")
        if candidate_id in seen_ids:
            raise GeoMLError("candidate ids must be unique")
        seen_ids.add(candidate_id)
        vector = _vector(raw.get("embedding"), f"candidate embedding {candidate_id}")
        if len(vector) != dimension:
            raise GeoMLError("candidate embedding dimension differs from query")
        normalized_candidates.append({"id": candidate_id,
                                      "label": _text(raw.get("label", candidate_id), "candidate label"),
                                      "embedding": vector,
                                      "coordinate": _coordinate(raw.get("coordinate")),
                                      "source": _text(raw.get("source", "saved-candidate"),
                                                      "candidate source")})
    per_query, scores, votes = [], defaultdict(list), Counter()
    for query in queries:
        ranked = []
        for candidate in normalized_candidates:
            similarity = _cosine(query["embedding"], candidate["embedding"])
            scores[candidate["id"]].append(similarity)
            ranked.append({"id": candidate["id"], "similarity": similarity})
        ranked.sort(key=lambda row: (-row["similarity"], row["id"]))
        votes[ranked[0]["id"]] += 1
        margin = ranked[0]["similarity"] - ranked[1]["similarity"]
        per_query.append({"query_id": query["id"], "model": query["model"],
                          "top": ranked[:10], "top_margin": margin,
                          "ambiguous": margin < 0.02})
    lookup = {row["id"]: row for row in normalized_candidates}
    combined = []
    for candidate_id, values in scores.items():
        source = lookup[candidate_id]
        combined.append({"id": candidate_id, "label": source["label"],
                         "mean_cosine": statistics.fmean(values),
                         "median_cosine": statistics.median(values),
                         "minimum_cosine": min(values), "top_votes": votes[candidate_id],
                         "query_support": len(values), "coordinate": source["coordinate"],
                         "source": source["source"], "candidate_only": True})
    combined.sort(key=lambda row: (-row["top_votes"], -row["mean_cosine"], row["id"]))
    winner = combined[0]["id"]
    outliers = [row["query_id"] for row in per_query if row["top"][0]["id"] != winner]
    model_votes: dict[str, Counter] = defaultdict(Counter)
    for row in per_query:
        model_votes[row["model"]][row["top"][0]["id"]] += 1
    return _report("saved_embedding_geolocation", dimension=dimension, query_count=len(queries),
                   candidates=combined, per_query=per_query, outlier_queries=outliers,
                   model_top_votes={key: dict(value) for key, value in sorted(model_votes.items())},
                   consensus_unanimous=not outliers,
                   caveat="cosine similarity depends on the supplied model/index and is not location proof")


def _entropy(probabilities: Sequence[float]) -> float:
    if len(probabilities) <= 1:
        return 0.0
    return -math.fsum(value * math.log(value) for value in probabilities if value > 0) / math.log(len(probabilities))


def analyze_classifier_outputs(outputs: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Audit saved top-k classifier/geocoder outputs for confidence and geographic consensus."""
    rows = _take(outputs, MAX_QUERIES, "classifier outputs", minimum=1)
    reports, label_scores, votes = [], defaultdict(list), Counter()
    top_coordinates = []
    seen_output_ids = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise GeoMLError("classifier outputs must be mappings")
        predictions = raw.get("predictions")
        if not isinstance(predictions, list) or not 2 <= len(predictions) <= MAX_PREDICTIONS:
            raise GeoMLError("each classifier output needs 2..256 predictions")
        output_id = _text(raw.get("crop_id", raw.get("id", f"output-{index}")), "output id")
        if output_id in seen_output_ids:
            raise GeoMLError("classifier output ids must be unique")
        seen_output_ids.add(output_id)
        parsed, seen_labels = [], set()
        for item in predictions:
            if not isinstance(item, Mapping) or isinstance(item.get("probability"), bool):
                raise GeoMLError("predictions need label/probability mappings")
            label = _text(item.get("label"), "prediction label")
            if label in seen_labels:
                raise GeoMLError("prediction labels must be unique within an output")
            seen_labels.add(label)
            try:
                probability = float(item.get("probability"))
            except (TypeError, ValueError, OverflowError) as exc:
                raise GeoMLError("prediction probability is not numeric") from exc
            if not math.isfinite(probability) or probability < 0:
                raise GeoMLError("prediction probability is negative or non-finite")
            parsed.append({"label": label, "probability": probability,
                           "coordinate": _coordinate(item.get("coordinate"))})
        # Normalize through the largest finite weight.  Summing two legal values such as
        # 1e308 directly overflows to infinity and used to turn every result into zero.
        scale = max(item["probability"] for item in parsed)
        if scale <= 0:
            raise GeoMLError("prediction probabilities sum to zero")
        scaled_total = math.fsum(item["probability"] / scale for item in parsed)
        if not math.isfinite(scaled_total) or scaled_total <= 0:
            raise GeoMLError("prediction probabilities cannot be normalized safely")
        raw_total = (scale * scaled_total
                     if scale <= sys.float_info.max / scaled_total else math.inf)
        for item in parsed:
            item["probability"] = (item["probability"] / scale) / scaled_total
            label_scores[item["label"]].append(item["probability"])
        parsed.sort(key=lambda item: (-item["probability"], item["label"]))
        top = parsed[0]
        votes[top["label"]] += 1
        if top["coordinate"] is not None:
            top_coordinates.append((top["label"], top["coordinate"]))
        reports.append({"id": output_id,
                        "model": _text(raw.get("model", "saved-model"), "model name"),
                        "top": top, "margin": top["probability"] - parsed[1]["probability"],
                        "normalized_entropy": _entropy([item["probability"] for item in parsed]),
                        "renormalized": not math.isfinite(raw_total) or abs(raw_total - 1.0) > 1e-9,
                        "ambiguous": top["probability"] - parsed[1]["probability"] < 0.05})
    labels = [{"label": label, "top_votes": votes[label],
               "mean_probability_where_present": statistics.fmean(values),
               "observations": len(values), "candidate_only": True}
              for label, values in label_scores.items()]
    labels.sort(key=lambda item: (-item["top_votes"], -item["mean_probability_where_present"], item["label"]))
    maximum_distance = 0.0
    for i, (_, left) in enumerate(top_coordinates):
        for _, right in top_coordinates[i + 1:]:
            maximum_distance = max(maximum_distance, _distance(left, right))
    winner = labels[0]["label"]
    return _report("saved_classifier_geolocation", outputs=len(rows), candidates=labels,
                   per_output=reports, outlier_outputs=[row["id"] for row in reports if row["top"]["label"] != winner],
                   top_coordinate_max_separation_m=maximum_distance,
                   geographically_dispersed=maximum_distance > 100_000,
                   consensus_unanimous=all(row["top"]["label"] == winner for row in reports),
                   caveat="saved probabilities may be uncalibrated or indexed against the wrong gallery")


def _norm(value: Any) -> str:
    return " ".join(str(value).casefold().split())


def fuse_geolocation_evidence(ml_report: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Correlate saved-ML candidates with supplied EXIF, OCR, and landmark observations."""
    if not isinstance(ml_report, Mapping) or not isinstance(ml_report.get("candidates"), list):
        raise GeoMLError("ML report must contain a candidates list")
    if (ml_report.get("model_called") is not False
            or ml_report.get("embedding_generated") is not False
            or ml_report.get("automatic_answer") is not None
            or ml_report.get("requires_human_pin") is not True
            or not isinstance(evidence, Mapping)):
        raise GeoMLError("only an offline saved-ML report and evidence mapping are accepted")
    ml_candidates = ml_report["candidates"]
    if len(ml_candidates) > MAX_CANDIDATES:
        raise GeoMLError("ML candidates exceed the bound")
    exif = _coordinate(evidence.get("exif_coordinate"))
    raw_ocr = evidence.get("ocr_place_names", [])
    if not isinstance(raw_ocr, list) or len(raw_ocr) > 128:
        raise GeoMLError("OCR place names must be a list of at most 128 values")
    ocr = {_norm(_text(item, "OCR place name")) for item in raw_ocr}
    landmarks = evidence.get("landmark_candidates", [])
    if not isinstance(landmarks, list) or len(landmarks) > MAX_CANDIDATES:
        raise GeoMLError("landmark candidates exceed the bound")
    landmark_index = {}
    for row in landmarks:
        if not isinstance(row, Mapping):
            raise GeoMLError("landmark candidates must be mappings")
        name = _text(row.get("name"), "landmark candidate name")
        key = _norm(name)
        if key in landmark_index:
            raise GeoMLError("landmark candidate names must be unique")
        landmark_index[key] = _coordinate(row.get("coordinate"))
    fused, seen_labels = [], set()
    for index, raw in enumerate(ml_candidates):
        if not isinstance(raw, Mapping):
            raise GeoMLError("ML candidates must be mappings")
        label = _text(raw.get("label", raw.get("id", f"candidate-{index}")), "ML candidate label")
        normalized_label = _norm(label)
        if normalized_label in seen_labels:
            raise GeoMLError("ML candidate labels must be unique")
        seen_labels.add(normalized_label)
        coordinate = _coordinate(raw.get("coordinate"))
        if coordinate is None:
            coordinate = landmark_index.get(_norm(label))
        exif_distance = _distance(coordinate, exif) if coordinate is not None and exif is not None else None
        matched_ocr = sorted(value for value in ocr if value and (value in _norm(label) or _norm(label) in value))
        landmark_match = _norm(label) in landmark_index
        top_votes = raw.get("top_votes", 0)
        if isinstance(top_votes, bool) or not isinstance(top_votes, int):
            raise GeoMLError("ML candidate top_votes must be an integer")
        if not 0 <= top_votes <= MAX_QUERIES:
            raise GeoMLError(f"ML candidate top_votes must be in 0..{MAX_QUERIES}")
        score = top_votes * 10 + len(matched_ocr) * 15 + (15 if landmark_match else 0)
        if exif_distance is not None:
            score += 30 if exif_distance <= 1_000 else 10 if exif_distance <= 25_000 else -20
        fused.append({"label": label, "coordinate": coordinate, "exif_distance_m": exif_distance,
                      "matched_ocr": matched_ocr, "landmark_match": landmark_match,
                      "evidence_score": score, "candidate_only": True})
    fused.sort(key=lambda row: (-row["evidence_score"], row["exif_distance_m"] is None,
                               (math.inf if row["exif_distance_m"] is None
                                else row["exif_distance_m"]), row["label"]))
    return _report("fused_saved_ml_geolocation", candidates=fused,
                   evidence_conflict=bool(fused and fused[0]["exif_distance_m"] is not None
                                          and fused[0]["exif_distance_m"] > 100_000),
                   sources=[name for name, present in (("exif", exif is not None), ("ocr", bool(ocr)),
                                                       ("landmark", bool(landmark_index))) if present])


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GeoMLError(message)


def _json_file(path: str) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > 32 << 20:
        raise GeoMLError("input exceeds 32 MiB")
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline saved-embedding/classifier geolocation analysis")
    parser.add_argument("operation", choices=("embeddings", "classifier", "fuse"))
    parser.add_argument("input")
    parser.add_argument("--candidates")
    parser.add_argument("--evidence")
    try:
        args = parser.parse_args(argv)
        value = _json_file(args.input)
        if args.operation == "embeddings":
            if not args.candidates:
                raise GeoMLError("embeddings needs --candidates")
            result = rank_embedding_candidates(value, _json_file(args.candidates))
        elif args.operation == "classifier":
            result = analyze_classifier_outputs(value)
        else:
            if not args.evidence:
                raise GeoMLError("fuse needs --evidence")
            result = fuse_geolocation_evidence(value, _json_file(args.evidence))
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError, OverflowError) as exc:
        print(f"osint_geo_ml: {exc}", file=__import__("sys").stderr)
        return 2


__all__ = ["GeoMLError", "analyze_classifier_outputs", "fuse_geolocation_evidence",
           "rank_embedding_candidates"]

if __name__ == "__main__":
    raise SystemExit(main())
