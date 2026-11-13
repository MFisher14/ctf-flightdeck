#!/usr/bin/env python3
"""Offline evidence helpers for model backdoors and watermarks.

The functions in this module consume *saved numeric evidence*: predictions, activation
matrices, already-produced trigger-mask norms, or weight samples.  They never import or load a
model, synthesize a trigger, query an endpoint, or claim that a statistical outlier proves intent.
All conclusions are deliberately named candidates and retain their sample counts.
"""
from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any


MAX_ROWS = 10_000
MAX_DIMENSIONS = 2_048
MAX_VALUES = 500_000
MAX_ITERATIONS = 128
MAX_ABS = 1e150


def _number(value: Any, field: str = "value") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be numeric")
    try:
        result = float(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError(f"{field} must be finite and bounded") from exc
    if not math.isfinite(result) or abs(result) > MAX_ABS:
        raise ValueError(f"{field} must be finite and bounded")
    return result


def _vector(value: Any, *, field: str = "vector") -> list[float]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{field} must be a numeric list")
    if len(value) > MAX_DIMENSIONS:
        raise ValueError(f"{field} exceeds dimension cap")
    return [_number(item, field) for item in value]


def _norm(values: Sequence[float]) -> float:
    scale = max((abs(value) for value in values), default=0.0)
    if scale == 0:
        return 0.0
    result = scale * math.sqrt(math.fsum((value / scale) ** 2 for value in values))
    if not math.isfinite(result):
        raise ValueError("numeric norm overflow")
    return result


def _median_mad(values: Sequence[float]) -> tuple[float, float]:
    median = float(statistics.median(values)) if values else 0.0
    mad = float(statistics.median(abs(value - median) for value in values)) if values else 0.0
    return median, mad


def _binomial_tail(n: int, k: int, probability: float) -> float:
    """P[X >= k], evaluated by log-sum-exp to avoid combinatorial overflow."""
    if n < 0 or not 0 <= k <= n or not 0 <= probability <= 1:
        raise ValueError("invalid binomial parameters")
    if k == 0:
        return 1.0
    if probability == 0:
        return 0.0
    if probability == 1:
        return 1.0
    logs = [math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(probability) + (n - i) * math.log1p(-probability)
            for i in range(k, n + 1)]
    peak = max(logs)
    return min(1.0, math.exp(peak) * math.fsum(math.exp(value - peak) for value in logs))


def backdoor_behavior_report(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize paired clean/triggered predictions saved by a separate experiment.

    Required fields are ``clean_prediction`` and ``triggered_prediction``. Optional
    ``true_label``, ``clean_confidence`` and ``triggered_confidence`` fields add transparent
    accuracy/confidence facts. No inference is run here.
    """
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise ValueError("records must be a list")
    if not 1 <= len(records) <= MAX_ROWS:
        raise ValueError("records must be non-empty and bounded")
    clean, triggered, truths = [], [], []
    clean_conf, trigger_conf = [], []
    for row in records:
        if not isinstance(row, Mapping) or "clean_prediction" not in row or "triggered_prediction" not in row:
            raise ValueError("each record needs clean_prediction and triggered_prediction")
        clean.append(str(row["clean_prediction"])[:256])
        triggered.append(str(row["triggered_prediction"])[:256])
        truths.append(str(row["true_label"])[:256] if "true_label" in row else None)
        if "clean_confidence" in row or "triggered_confidence" in row:
            if "clean_confidence" not in row or "triggered_confidence" not in row:
                raise ValueError("confidence fields must be paired")
            clean_value = _number(row["clean_confidence"], "clean_confidence")
            trigger_value = _number(row["triggered_confidence"], "triggered_confidence")
            if not 0 <= clean_value <= 1 or not 0 <= trigger_value <= 1:
                raise ValueError("confidence values must lie in [0,1]")
            clean_conf.append(clean_value); trigger_conf.append(trigger_value)
    counts = Counter(triggered)
    target, target_count = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0]
    clean_target = sum(label == target for label in clean)
    flips = sum(left != right for left, right in zip(clean, triggered))
    truth_rows = [(left, right, truth) for left, right, truth in zip(clean, triggered, truths) if truth is not None]
    findings = []
    concentration = target_count / len(records)
    uplift = concentration - clean_target / len(records)
    if len(records) >= 8 and concentration >= 0.75 and uplift >= 0.5:
        findings.append({"kind": "target-concentration-candidate", "score": 82,
                         "target": target, "triggered_fraction": concentration,
                         "clean_baseline_fraction": clean_target / len(records),
                         "reason": "saved triggered outputs concentrate on one label beyond the paired clean baseline"})
    return {
        "records": len(records), "target_candidate": target,
        "target_count": target_count, "target_fraction": concentration,
        "clean_target_fraction": clean_target / len(records), "target_uplift": uplift,
        "label_flip_count": flips, "label_flip_fraction": flips / len(records),
        "clean_accuracy": (sum(left == truth for left, _right, truth in truth_rows) / len(truth_rows)) if truth_rows else None,
        "triggered_accuracy": (sum(right == truth for _left, right, truth in truth_rows) / len(truth_rows)) if truth_rows else None,
        "mean_confidence_shift": (math.fsum(b - a for a, b in zip(clean_conf, trigger_conf)) / len(clean_conf)) if clean_conf else None,
        "findings": findings, "backdoor_verified": False, "requires_human_review": True,
        "note": "paired saved outputs are evidence only; trigger provenance and experiment controls are external",
    }


def activation_spectral_report(samples: Sequence[Sequence[float]], *, labels: Sequence[Any] | None = None,
                               trigger_flags: Sequence[bool] | None = None,
                               iterations: int = 48) -> dict[str, Any]:
    """Top centered-covariance direction and robust projection outliers for saved activations."""
    if not isinstance(samples, Sequence) or isinstance(samples, (str, bytes, bytearray)):
        raise ValueError("samples must be a matrix")
    if not 2 <= len(samples) <= min(MAX_ROWS, 2_000):
        raise ValueError("activation matrix row count is out of bounds")
    matrix = [_vector(row, field="activation") for row in samples]
    dimension = len(matrix[0])
    if not 1 <= dimension <= MAX_DIMENSIONS or any(len(row) != dimension for row in matrix):
        raise ValueError("activation rows need one bounded common dimension")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError("iterations out of bounds")
    if labels is not None and (not isinstance(labels, Sequence) or isinstance(labels, (str, bytes, bytearray))
                               or len(labels) != len(matrix)):
        raise ValueError("labels must be a sequence matching the activation rows")
    if trigger_flags is not None and (not isinstance(trigger_flags, Sequence)
                                      or isinstance(trigger_flags, (str, bytes, bytearray))
                                      or len(trigger_flags) != len(matrix) or
                                      any(not isinstance(flag, bool) for flag in trigger_flags)):
        raise ValueError("trigger_flags length/type mismatch")
    means = [math.fsum(row[j] for row in matrix) / len(matrix) for j in range(dimension)]
    centered = [[value - means[j] for j, value in enumerate(row)] for row in matrix]
    # A uniform start can be exactly orthogonal to the dominant eigenvector (its covariance null
    # space), which collapses the power iteration to zero; fall back to standard basis seeds, at
    # least one of which has a component along a non-degenerate direction.
    seeds = [[1.0 / math.sqrt(dimension)] * dimension]
    seeds += [[1.0 if j == i else 0.0 for j in range(dimension)] for i in range(dimension)]
    vector = [0.0] * dimension
    for seed in seeds:
        candidate, collapsed = seed, False
        for _ in range(iterations):
            projections = [math.fsum(value * direction for value, direction in zip(row, candidate)) for row in centered]
            update = [math.fsum(row[j] * projection for row, projection in zip(centered, projections)) / len(centered)
                      for j in range(dimension)]
            length = _norm(update)
            if length == 0:
                collapsed = True
                break
            candidate = [value / length for value in update]
        if not collapsed:
            vector = candidate
            break
    projections = [math.fsum(value * direction for value, direction in zip(row, vector)) for row in centered]
    eigenvalue = math.fsum(value * value for value in projections) / len(projections)
    median, mad = _median_mad(projections)
    scale = 1.4826 * mad
    robust = [abs(value - median) / scale if scale else 0.0 for value in projections]
    outliers = [index for index, score in enumerate(robust) if score >= 3.5]
    group = None
    if trigger_flags is not None and any(trigger_flags) and not all(trigger_flags):
        marked = [value for value, flag in zip(projections, trigger_flags) if flag]
        clean = [value for value, flag in zip(projections, trigger_flags) if not flag]
        pooled = math.sqrt((math.fsum((x - statistics.mean(marked)) ** 2 for x in marked)
                            + math.fsum((x - statistics.mean(clean)) ** 2 for x in clean))
                           / max(1, len(projections) - 2))
        group = {"triggered_mean_projection": statistics.mean(marked),
                 "clean_mean_projection": statistics.mean(clean),
                 "standardized_separation": abs(statistics.mean(marked) - statistics.mean(clean)) / pooled if pooled else None,
                 "triggered_count": len(marked), "clean_count": len(clean)}
    findings = []
    if outliers:
        findings.append({"kind": "spectral-outlier-candidate", "score": 68,
                         "sample_indices": outliers[:256], "reason": "robust outliers occur on the top saved-activation covariance direction"})
    if group and group["standardized_separation"] is not None and group["standardized_separation"] >= 2:
        findings.append({"kind": "trigger-group-separation-candidate", "score": 78,
                         "standardized_separation": group["standardized_separation"],
                         "reason": "caller-labelled trigger and clean groups separate on the top spectral direction"})
    return {"samples": len(matrix), "dimensions": dimension, "iterations": iterations,
            "top_eigenvalue": eigenvalue, "direction": vector[:256],
            "projection_median": median, "projection_mad": mad,
            "outlier_indices": outliers[:1_000], "group_comparison": group,
            "label_count": len(set(map(str, labels))) if labels is not None else None,
            "findings": findings, "backdoor_verified": False, "requires_human_review": True}


def neural_cleanse_summary(class_mask_norms: Mapping[Any, Any] | Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Median/MAD anomaly summary over *already generated* per-class trigger mask norms."""
    if isinstance(class_mask_norms, Mapping):
        if not 3 <= len(class_mask_norms) <= MAX_ROWS:
            raise ValueError("need three or more bounded mask norms")
        rows = [(str(key)[:256], _number(value, "mask norm")) for key, value in class_mask_norms.items()]
    elif isinstance(class_mask_norms, Sequence) and not isinstance(class_mask_norms, (str, bytes, bytearray)):
        if not 3 <= len(class_mask_norms) <= MAX_ROWS:
            raise ValueError("need three or more bounded mask norms")
        rows = []
        for row in class_mask_norms:
            if not isinstance(row, Mapping) or "class" not in row or "norm" not in row:
                raise ValueError("mask rows need class and norm")
            rows.append((str(row["class"])[:256], _number(row["norm"], "mask norm")))
    else:
        raise ValueError("class_mask_norms must be a mapping or list")
    if any(value < 0 for _label, value in rows):
        raise ValueError("need three or more bounded non-negative mask norms")
    if len({label for label, _value in rows}) != len(rows):
        raise ValueError("class labels must be unique")
    values = [value for _label, value in rows]
    median, mad = _median_mad(values)
    label, minimum = min(rows, key=lambda item: (item[1], item[0]))
    anomaly = (median - minimum) / (1.4826 * mad) if mad else None
    finding = []
    if anomaly is not None and anomaly >= 2:
        finding.append({"kind": "small-mask-outlier-candidate", "score": 74, "class": label,
                        "anomaly_index": anomaly,
                        "reason": "one saved class mask norm is low relative to the cross-class median/MAD"})
    return {"classes": len(rows), "median_norm": median, "mad_norm": mad,
            "minimum_class": label, "minimum_norm": minimum, "anomaly_index": anomaly,
            "findings": finding, "optimization_performed": False,
            "backdoor_verified": False, "requires_human_review": True}


def weight_outlier_report(tensors: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Robust distribution/concentration facts over caller-supplied weight samples."""
    if not isinstance(tensors, Sequence) or isinstance(tensors, (str, bytes, bytearray)):
        raise ValueError("tensors must be a list")
    if not 1 <= len(tensors) <= 10_000:
        raise ValueError("tensor list is empty or too large")
    rows, total = [], 0
    for index, tensor in enumerate(tensors):
        if not isinstance(tensor, Mapping):
            raise ValueError("tensor entry must be an object")
        values = _vector(tensor.get("values"), field="weights")
        total += len(values)
        if total > MAX_VALUES:
            raise ValueError("weight sample cap exceeded")
        if not values:
            continue
        median, mad = _median_mad(values)
        scale = 1.4826 * mad
        outliers = sum(abs(value - median) / scale >= 6 for value in values) if scale else 0
        energy = sorted((value * value for value in values), reverse=True)
        top_count = max(1, math.ceil(len(energy) * 0.01))
        total_energy = math.fsum(energy)
        concentration = math.fsum(energy[:top_count]) / total_energy if total_energy else 0.0
        rows.append({"name": str(tensor.get("name", index))[:256], "count": len(values),
                     "median": median, "mad": mad, "max_abs": max(map(abs, values)),
                     "robust_outliers": outliers, "top_one_percent_energy_fraction": concentration})
    findings = [{"kind": "weight-concentration-candidate", "score": 58, "tensor": row["name"],
                 "fraction": row["top_one_percent_energy_fraction"],
                 "reason": "a small supplied weight subset carries most sampled squared magnitude"}
                for row in rows if row["count"] >= 20 and row["top_one_percent_energy_fraction"] >= 0.8]
    return {"tensor_count": len(rows), "sampled_values": total, "tensors": rows,
            "findings": findings, "backdoor_verified": False, "requires_human_review": True}


def watermark_response_report(trials: Sequence[Any], *, expected_rate: float = 0.5) -> dict[str, Any]:
    """Exact one-sided match test over saved challenge/response watermark trials."""
    expected_rate = _number(expected_rate, "expected_rate")
    if not 0 <= expected_rate <= 1:
        raise ValueError("expected_rate must lie in [0,1]")
    if not isinstance(trials, Sequence) or isinstance(trials, (str, bytes, bytearray)):
        raise ValueError("trials must be a list")
    if not 1 <= len(trials) <= MAX_ROWS:
        raise ValueError("trial count is out of bounds")
    matches, controls = [], []
    for row in trials:
        control = False
        if isinstance(row, bool):
            match = row
        elif isinstance(row, Mapping):
            control = row.get("control") is True
            if "match" in row:
                if not isinstance(row["match"], bool):
                    raise ValueError("match must be boolean")
                match = row["match"]
            elif "expected" in row and "observed" in row:
                match = row["expected"] == row["observed"]
            else:
                raise ValueError("trial needs match or expected/observed")
        else:
            raise ValueError("invalid watermark trial")
        (controls if control else matches).append(match)
    if not matches:
        raise ValueError("at least one non-control trial is required")
    successes = sum(matches)
    p_value = _binomial_tail(len(matches), successes, expected_rate)
    variance = len(matches) * expected_rate * (1 - expected_rate)
    z_score = (successes - len(matches) * expected_rate) / math.sqrt(variance) if variance else None
    findings = []
    if len(matches) >= 20 and p_value <= 0.01:
        findings.append({"kind": "watermark-response-candidate", "score": 76,
                         "p_value": p_value, "reason": "saved response matches exceed the caller-supplied null rate"})
    return {"trials": len(matches), "matches": successes, "match_rate": successes / len(matches),
            "expected_rate": expected_rate, "z_score": z_score, "one_sided_p_value": p_value,
            "control_trials": len(controls),
            "control_match_rate": sum(controls) / len(controls) if controls else None,
            "findings": findings, "watermark_verified": False, "requires_human_review": True,
            "network_used": False, "model_loaded": False}


def weight_signature_report(bit_scores: Sequence[Any], expected_bits: Sequence[Any], *, margin: float = 0.0) -> dict[str, Any]:
    """Compare supplied projection scores with an expected bit signature; no projection is created."""
    margin = _number(margin, "margin")
    if margin < 0:
        raise ValueError("margin must be non-negative")
    if not isinstance(bit_scores, Sequence) or not isinstance(expected_bits, Sequence) \
            or isinstance(bit_scores, (str, bytes, bytearray)) or isinstance(expected_bits, (str, bytes, bytearray)):
        raise ValueError("scores and bits must be lists")
    if not 1 <= len(bit_scores) == len(expected_bits) <= MAX_ROWS:
        raise ValueError("scores and bits need equal bounded length")
    scores = [_number(value, "bit score") for value in bit_scores]
    if any(bit not in (0, 1, False, True) for bit in expected_bits):
        raise ValueError("expected bits must be 0/1")
    observed = [1 if value > margin else (0 if value < -margin else None) for value in scores]
    decided = [(got, int(want)) for got, want in zip(observed, expected_bits) if got is not None]
    matches = sum(got == want for got, want in decided)
    p_value = _binomial_tail(len(decided), matches, 0.5) if decided else None
    return {"bits": len(scores), "decided_bits": len(decided), "undecided_bits": len(scores) - len(decided),
            "matches": matches, "hamming_distance": len(decided) - matches,
            "match_rate": matches / len(decided) if decided else None,
            "one_sided_p_value": p_value, "observed_bits": observed,
            "watermark_verified": False, "requires_human_review": True,
            "note": "scores and expected signature were supplied by the caller; no model or secret key was accessed"}


def json_report(value: Any) -> str:
    """Stable JSON convenience for saved reports."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)

