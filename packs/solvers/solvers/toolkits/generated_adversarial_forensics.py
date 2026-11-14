#!/usr/bin/env python3
"""Transparent generated-content and adversarial-artifact evidence, entirely offline.

This module deliberately avoids an "AI detector" verdict. Text stylometry, provenance strings,
watermark membership bits, pixel deltas, and saved output changes are reported as reproducible
features or candidates. Base perturbation norms delegate to ``llm_security_depth``; no model,
embedding service, decoder, endpoint, or untrusted artifact is executed.
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import math
import re
import statistics
import sys
import unicodedata
import zlib
from collections import Counter, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
MAX_TEXT_BYTES = 4 << 20
MAX_REFERENCE_TEXTS = 2_000
MAX_REFERENCE_BYTES = 16 << 20
MAX_PAIRS = 1_000
MAX_COMPARISONS = 20_000
MAX_METADATA_ITEMS = 10_000
MAX_DEPTH = 24


def _load(name: str, filename: str):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"static helper unavailable: {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _base():
    return _load("csctf_r5g_llm_depth_for_generated", "llm_security_depth.py")


def _integrity():
    return _load("csctf_r5g_integrity_for_generated", "model_integrity_forensics.py")


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("text input must be a string")
    if len(value.encode("utf-8", "surrogatepass")) > MAX_TEXT_BYTES:
        raise ValueError("text exceeds 4 MiB cap")
    return unicodedata.normalize("NFKC", value)


def _entropy(counts: Counter[Any]) -> float:
    total = sum(counts.values())
    return -math.fsum((count / total) * math.log2(count / total) for count in counts.values()) if total else 0.0


FEATURE_KEYS = ("type_token_ratio", "token_entropy", "bigram_repetition", "trigram_repetition",
                "sentence_length_cv", "punctuation_fraction", "character_entropy",
                "compression_ratio", "zipf_rmse")


def _raw_text_features(value: str) -> dict[str, float | int]:
    text = _text(value)
    tokens = re.findall(r"[^\W_]+(?:['’-][^\W_]+)?", text.casefold(), re.UNICODE)
    if len(tokens) > 200_000:
        raise ValueError("token count exceeds cap")
    sentences = [part for part in re.split(r"(?<=[.!?])(?:[\s\r\n]+|$)", text) if part.strip()]
    sentence_lengths = [len(re.findall(r"[^\W_]+", sentence, re.UNICODE)) for sentence in sentences]
    token_counts = Counter(tokens)
    bigrams = Counter(zip(tokens, tokens[1:]))
    trigrams = Counter(zip(tokens, tokens[1:], tokens[2:]))
    repeated_bigrams = sum(count - 1 for count in bigrams.values() if count > 1)
    repeated_trigrams = sum(count - 1 for count in trigrams.values() if count > 1)
    mean_sentence = statistics.mean(sentence_lengths) if sentence_lengths else 0.0
    sentence_cv = statistics.pstdev(sentence_lengths) / mean_sentence if mean_sentence and len(sentence_lengths) > 1 else 0.0
    punctuation = sum(unicodedata.category(char).startswith("P") for char in text)
    raw = text.encode("utf-8", "surrogatepass")
    ranked = sorted(token_counts.values(), reverse=True)
    zipf_rmse = 0.0
    if len(ranked) >= 2:
        # Fit log(frequency) = intercept + slope*log(rank), then expose residual only.
        xs = [math.log(index + 1) for index in range(len(ranked))]
        ys = [math.log(count) for count in ranked]
        mx, my = statistics.mean(xs), statistics.mean(ys)
        denom = math.fsum((x - mx) ** 2 for x in xs)
        slope = math.fsum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom if denom else 0.0
        intercept = my - slope * mx
        zipf_rmse = math.sqrt(math.fsum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys)) / len(xs))
    return {
        "characters": len(text), "bytes": len(raw), "tokens": len(tokens), "unique_tokens": len(token_counts),
        "sentences": len(sentences), "type_token_ratio": len(token_counts) / len(tokens) if tokens else 0.0,
        "token_entropy": _entropy(token_counts),
        "bigram_repetition": repeated_bigrams / max(1, len(tokens) - 1),
        "trigram_repetition": repeated_trigrams / max(1, len(tokens) - 2),
        "mean_sentence_tokens": mean_sentence, "sentence_length_cv": sentence_cv,
        "punctuation_fraction": punctuation / len(text) if text else 0.0,
        "character_entropy": _entropy(Counter(text)),
        "compression_ratio": len(zlib.compress(raw, 9)) / len(raw) if raw else 0.0,
        "zipf_rmse": zipf_rmse,
    }


def generated_text_features(text: str, *, references: Mapping[str, Sequence[str]] | None = None) -> dict[str, Any]:
    """Return stylometric facts and optional distances to caller-supplied reference groups."""
    features = _raw_text_features(text)
    calibration = []
    if references is not None:
        if not isinstance(references, Mapping) or len(references) > 32:
            raise ValueError("references must be a bounded label-to-text-list mapping")
        count = byte_count = 0
        for label, examples in references.items():
            if not isinstance(examples, Sequence) or isinstance(examples, (str, bytes, bytearray)):
                raise ValueError("each reference group must be a text list")
            count += len(examples)
            if count > MAX_REFERENCE_TEXTS:
                raise ValueError("reference text count exceeds cap")
            rows = []
            for example in examples:
                if not isinstance(example, str):
                    raise ValueError("reference examples must be strings")
                byte_count += len(example.encode("utf-8", "surrogatepass"))
                if byte_count > MAX_REFERENCE_BYTES:
                    raise ValueError("reference bytes exceed cap")
                rows.append(_raw_text_features(example))
            if not rows:
                continue
            means = {key: math.fsum(float(row[key]) for row in rows) / len(rows) for key in FEATURE_KEYS}
            scales = {key: statistics.pstdev(float(row[key]) for row in rows) if len(rows) > 1 else 0.0 for key in FEATURE_KEYS}
            distance_terms = [((float(features[key]) - means[key]) / scales[key]) ** 2
                              for key in FEATURE_KEYS if scales[key] > 1e-12]
            calibration.append({"label": str(label)[:128], "examples": len(rows),
                                "standardized_distance": math.sqrt(math.fsum(distance_terms)) if distance_terms else None,
                                "means": means})
        calibration.sort(key=lambda row: (row["standardized_distance"] is None,
                                          row["standardized_distance"] or 0, row["label"]))
    return {"features": features, "reference_calibration": calibration,
            "ai_generated_verified": False, "requires_human_review": True,
            "note": "stylometry is descriptive and dataset-dependent; it is not an authorship verdict"}


def greenlist_watermark_test(memberships: Sequence[bool], *, expected_rate: float = 0.5) -> dict[str, Any]:
    """Test caller-supplied green/red token memberships; no key or tokenizer is inferred."""
    if not isinstance(memberships, Sequence) or isinstance(memberships, (str, bytes, bytearray)):
        raise ValueError("memberships must be a boolean list")
    if not 1 <= len(memberships) <= _integrity().MAX_ROWS:
        raise ValueError("membership count is out of bounds")
    if any(not isinstance(item, bool) for item in memberships):
        raise ValueError("memberships must be a boolean list")
    report = _integrity().watermark_response_report(list(memberships), expected_rate=expected_rate)
    report["membership_source"] = "caller-supplied"
    report["key_inferred"] = False
    return report


GENERATOR_RX = re.compile(r"(?i)\b(?:stable[ -]?diffusion|automatic1111|comfyui|invokeai|midjourney|"
                          r"dall[ -]?e|firefly|flux(?:\.[0-9]+)?|generative ai|text[- ]to[- ]image)\b")
PROMPT_KEY_RX = re.compile(r"(?i)(?:^|[._ -])(?:negative[._ -]?)?prompt(?:$|[._ -])|workflow|sampler|cfg[._ -]?scale|seed")


def _metadata_strings(value: Any, path: str = "$", depth: int = 0, state: dict[str, int] | None = None):
    state = state if state is not None else {"items": 0}
    if depth > MAX_DEPTH or state["items"] >= MAX_METADATA_ITEMS:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            state["items"] += 1
            if state["items"] > MAX_METADATA_ITEMS:
                return
            next_path = f"{path}.{str(key)[:128]}"
            if isinstance(item, str):
                yield next_path, item[:16_384]
            elif isinstance(item, (Mapping, list, tuple)):
                yield from _metadata_strings(item, next_path, depth + 1, state)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value[:MAX_METADATA_ITEMS]):
            if isinstance(item, str):
                yield f"{path}[{index}]", item[:16_384]
            elif isinstance(item, (Mapping, list, tuple)):
                yield from _metadata_strings(item, f"{path}[{index}]", depth + 1, state)


def provenance_evidence(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Inventory exact generator/workflow/C2PA strings from already-extracted metadata."""
    if not isinstance(metadata, Mapping):
        raise ValueError("metadata must be an object")
    if len(metadata) > MAX_METADATA_ITEMS:
        raise ValueError("metadata item count exceeds cap")
    rows, findings = list(_metadata_strings(metadata)), []
    for path, value in rows:
        match = GENERATOR_RX.search(path + " " + value)
        if match:
            findings.append({"kind": "generator-metadata", "score": 88, "path": path,
                             "generator_text": match.group(0), "verified_metadata": True,
                             "reason": "an extracted metadata field names a generative tool or family"})
        if PROMPT_KEY_RX.search(path):
            findings.append({"kind": "generation-workflow-field", "score": 72, "path": path,
                             "value_digest": __import__("hashlib").sha256(value.encode("utf-8", "surrogatepass")).hexdigest(),
                             "value_length": len(value), "verified_metadata": True,
                             "reason": "metadata key is generation-workflow-shaped; value is retained only as a digest"})
    c2pa = []
    for key, value in itertools.islice(metadata.items(), MAX_METADATA_ITEMS):
        if re.search(r"(?i)c2pa|content.?credential|manifest", str(key)):
            c2pa.append({"key": str(key)[:128], "value": value if isinstance(value, (bool, int, float, type(None))) else str(value)[:256]})
    findings.sort(key=lambda row: (-row["score"], row["path"]))
    return {"metadata_strings": len(rows), "findings": findings[:2_000], "c2pa_fields": c2pa[:256],
            "ai_generated_verified": False, "provenance_validated": False,
            "requires_human_review": True,
            "note": "metadata can be absent, copied, or forged; cryptographic C2PA validation is outside this helper"}


def _flatten(value: Any, out: list[float] | None = None, depth: int = 0) -> list[float]:
    out = [] if out is None else out
    if depth > MAX_DEPTH:
        raise ValueError("numeric nesting exceeds cap")
    if isinstance(value, bool):
        raise ValueError("booleans are not numeric samples")
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("numeric samples must be finite and bounded") from exc
        if not math.isfinite(number) or abs(number) > 1e150:
            raise ValueError("numeric samples must be finite and bounded")
        out.append(number)
        if len(out) > _base().MAX_VECTOR:
            raise ValueError("numeric sample cap exceeded")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _flatten(item, out, depth + 1)
    else:
        raise ValueError("numeric inputs must contain only lists and numbers")
    return out


def _pixel_magnitudes(delta: Sequence[float], shape: Sequence[int], tolerance: float) -> tuple[list[float], int, int, int]:
    if len(shape) == 2:
        height, width = shape
        channels = 1
    elif len(shape) == 3:
        height, width, channels = shape
        if channels > 64:
            raise ValueError("channel count exceeds cap")
    else:
        raise ValueError("structural analysis requires HxW or HxWxC shape")
    magnitudes = []
    for pixel in range(height * width):
        values = delta[pixel * channels:(pixel + 1) * channels]
        magnitudes.append(math.sqrt(math.fsum(value * value for value in values)))
    return magnitudes, height, width, channels


def _components(mask: Sequence[bool], height: int, width: int) -> list[int]:
    seen, sizes = set(), []
    for start, active in enumerate(mask):
        if not active or start in seen:
            continue
        queue, size = deque([start]), 0
        seen.add(start)
        while queue:
            point = queue.popleft(); size += 1
            y, x = divmod(point, width)
            for ny, nx in ((y - 1, x), (y + 1, x), (y, x - 1), (y, x + 1)):
                nxt = ny * width + nx
                if 0 <= ny < height and 0 <= nx < width and mask[nxt] and nxt not in seen:
                    seen.add(nxt); queue.append(nxt)
        sizes.append(size)
    return sorted(sizes, reverse=True)


def _correlation(left: Sequence[float], right: Sequence[float]) -> float | None:
    if not left:
        return None
    ml, mr = math.fsum(left) / len(left), math.fsum(right) / len(right)
    dl, dr = [value - ml for value in left], [value - mr for value in right]
    nl = math.sqrt(math.fsum(value * value for value in dl))
    nr = math.sqrt(math.fsum(value * value for value in dr))
    if not nl or not nr:
        return 1.0 if left == right else None
    return max(-1.0, min(1.0, math.fsum(a * b for a, b in zip(dl, dr)) / (nl * nr)))


def _stable_norm(values: Sequence[float]) -> float:
    scale = max((abs(value) for value in values), default=0.0)
    if scale == 0:
        return 0.0
    result = scale * math.sqrt(math.fsum((value / scale) ** 2 for value in values))
    if not math.isfinite(result):
        raise ValueError("numeric norm overflow")
    return result


def _saved_output_effect(outputs: Any) -> dict[str, Any] | None:
    if outputs is None:
        return None
    if not isinstance(outputs, Mapping):
        raise ValueError("outputs must be an object")
    result = {"label_changed": None, "score_l2": None, "margin_shift": None}
    if "original_label" in outputs and "modified_label" in outputs:
        result["label_changed"] = outputs["original_label"] != outputs["modified_label"]
    if "original_scores" in outputs or "modified_scores" in outputs:
        left = _flatten(outputs.get("original_scores")); right = _flatten(outputs.get("modified_scores"))
        if len(left) != len(right) or not left:
            raise ValueError("saved output score vectors need equal nonzero length")
        result["score_l2"] = _stable_norm([b - a for a, b in zip(left, right)])
        if len(left) >= 2:
            lm = sorted(left, reverse=True); rm = sorted(right, reverse=True)
            result["margin_shift"] = (rm[0] - rm[1]) - (lm[0] - lm[1])
    result["effect_source"] = "caller-supplied saved outputs"
    return result


def adversarial_structure_report(original: Any, modified: Any, *, shape: Sequence[int],
                                 value_range: Sequence[float] | None = None,
                                 tolerance: float = 0.0, outputs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Add spatial/roughness/structure facts to the existing exact perturbation report."""
    base = _base().adversarial_static_report(original, modified, shape=shape,
                                             value_range=value_range, tolerance=tolerance)
    left, right = _flatten(original), _flatten(modified)
    delta = [b - a for a, b in zip(left, right)]
    magnitudes, height, width, channels = _pixel_magnitudes(delta, shape, tolerance)
    mask = [value > tolerance for value in magnitudes]
    component_sizes = _components(mask, height, width)
    horizontal = math.fsum(abs(magnitudes[y * width + x + 1] - magnitudes[y * width + x])
                           for y in range(height) for x in range(width - 1))
    vertical = math.fsum(abs(magnitudes[(y + 1) * width + x] - magnitudes[y * width + x])
                         for y in range(height - 1) for x in range(width))
    total_variation = horizontal + vertical
    checkerboard = abs(math.fsum(value * (-1 if (index // width + index % width) % 2 else 1)
                                 for index, value in enumerate(magnitudes))) / max(1e-300, math.fsum(magnitudes))
    channel_snr = []
    for channel in range(channels):
        signal = [left[index] for index in range(channel, len(left), channels)]
        noise = [delta[index] for index in range(channel, len(delta), channels)]
        signal_power = math.fsum(value * value for value in signal) / max(1, len(signal))
        noise_power = math.fsum(value * value for value in noise) / max(1, len(noise))
        channel_snr.append({"channel": channel,
                            "snr_db": 10 * math.log10(signal_power / noise_power) if signal_power > 0 and noise_power > 0 else None,
                            "noise_rms": math.sqrt(noise_power)})
    dynamic = float(value_range[1]) - float(value_range[0]) if value_range is not None else 1.0
    mu_x, mu_y = (math.fsum(left) / len(left), math.fsum(right) / len(right)) if left else (0.0, 0.0)
    vx = math.fsum((value - mu_x) ** 2 for value in left) / max(1, len(left) - 1)
    vy = math.fsum((value - mu_y) ** 2 for value in right) / max(1, len(right) - 1)
    cov = math.fsum((a - mu_x) * (b - mu_y) for a, b in zip(left, right)) / max(1, len(left) - 1)
    c1, c2 = (0.01 * dynamic) ** 2, (0.03 * dynamic) ** 2
    if left:
        luminance = (2 * mu_x * mu_y + c1) / (mu_x * mu_x + mu_y * mu_y + c1)
        contrast_structure = (2 * cov + c2) / (vx + vy + c2)
        ssim = luminance * contrast_structure
    else:
        ssim = 1.0
    structure = {"height": height, "width": width, "channels": channels,
                 "component_count": len(component_sizes), "component_sizes": component_sizes[:1_000],
                 "largest_component_fraction": component_sizes[0] / max(1, sum(mask)) if component_sizes else 0.0,
                 "total_variation": total_variation, "checkerboard_projection_fraction": checkerboard,
                 "global_correlation": _correlation(left, right), "global_ssim": ssim,
                 "channel_snr": channel_snr}
    effect = _saved_output_effect(outputs)
    findings = []
    if len(component_sizes) == 1 and component_sizes and component_sizes[0] <= max(1, height * width // 4):
        findings.append({"kind": "compact-perturbation-candidate", "score": 58,
                         "pixels": component_sizes[0], "reason": "all changed pixels form one small connected component"})
    if checkerboard >= 0.8 and sum(mask) >= 4:
        findings.append({"kind": "checkerboard-perturbation-candidate", "score": 52,
                         "fraction": checkerboard, "reason": "delta magnitude strongly projects onto the checkerboard basis"})
    if effect and effect.get("label_changed") is True:
        findings.append({"kind": "saved-label-flip", "score": 75,
                         "reason": "caller-supplied saved labels differ; this helper did not run the model"})
    return {"base_metrics": base, "structure": structure, "saved_output_effect": effect,
            "findings": findings, "adversarial_effect_verified": False,
            "model_loaded": False, "network_used": False, "requires_human_review": True}


def universal_perturbation_report(pairs: Sequence[Mapping[str, Any]], *, tolerance: float = 0.0) -> dict[str, Any]:
    """Compare deltas across a bounded batch of caller-supplied original/modified pairs."""
    if not isinstance(pairs, Sequence) or isinstance(pairs, (str, bytes, bytearray)) \
            or not 2 <= len(pairs) <= MAX_PAIRS:
        raise ValueError("pairs must contain between two and 1000 entries")
    deltas = []
    dimension = None
    for row in pairs:
        if not isinstance(row, Mapping) or "original" not in row or "modified" not in row:
            raise ValueError("each pair needs original and modified")
        left, right = _flatten(row["original"]), _flatten(row["modified"])
        if len(left) != len(right) or not left:
            raise ValueError("each pair needs equal non-empty input sizes")
        dimension = len(left) if dimension is None else dimension
        if len(left) != dimension:
            raise ValueError("all pair dimensions must match")
        deltas.append([b - a if abs(b - a) > tolerance else 0.0 for a, b in zip(left, right)])
    comparisons, similarities = 0, []
    norms = [_stable_norm(delta) for delta in deltas]
    for index, right in enumerate(deltas):
        for prior in range(index):
            if comparisons >= MAX_COMPARISONS:
                break
            comparisons += 1
            denom = norms[index] * norms[prior]
            similarities.append(math.fsum(a * b for a, b in zip(deltas[prior], right)) / denom if denom else 0.0)
        if comparisons >= MAX_COMPARISONS:
            break
    centroid = [math.fsum(delta[j] for delta in deltas) / len(deltas) for j in range(dimension or 0)]
    centroid_norm = _stable_norm(centroid)
    mean_norm = math.fsum(norms) / len(norms)
    mean_similarity = math.fsum(similarities) / len(similarities) if similarities else None
    full_comparisons = len(deltas) * (len(deltas) - 1) // 2
    comparisons_capped = comparisons < full_comparisons
    findings = []
    if not comparisons_capped and len(deltas) >= 3 and mean_similarity is not None \
            and mean_similarity >= 0.9 and centroid_norm >= 0.8 * mean_norm:
        findings.append({"kind": "shared-delta-candidate", "score": 70,
                         "mean_pairwise_cosine": mean_similarity,
                         "reason": "saved perturbation deltas are strongly aligned across inputs"})
    return {"pairs": len(deltas), "dimension": dimension, "comparisons": comparisons,
            "full_pair_comparisons": full_comparisons, "comparisons_capped": comparisons_capped,
            "similarity_scope": "partial-prefix" if comparisons_capped else "complete",
            "mean_pairwise_cosine": mean_similarity,
            "centroid_to_mean_norm_ratio": centroid_norm / mean_norm if mean_norm else None,
            "findings": findings, "universal_effect_verified": False,
            "model_loaded": False, "requires_human_review": True}


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)

