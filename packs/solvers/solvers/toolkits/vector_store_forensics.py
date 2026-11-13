#!/usr/bin/env python3
"""Static vector-store poisoning, ranking, and exposure evidence.

Document parsing and cosine primitives delegate to ``common/agent_trace.py``. This overlay operates
only on vectors already present in an artifact or explicitly supplied by the caller. It never creates
an embedding, calls a vector database, queries a model, or treats a nearest codebook label as recovered
plaintext unless the supplied numeric vector is an exact finite match.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
import statistics
import struct
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
MAX_DOCUMENTS = 5_000
MAX_STORE_BYTES = 64 << 20
MAX_TEXT_BYTES = 32 << 20
MAX_VECTOR_DOCUMENTS = 1_000
MAX_DIMENSIONS = 8_192
MAX_CODEBOOK = 10_000
MAX_TARGETS = 1_000
MAX_COMPARISONS = 250_000
MAX_FINDINGS = 5_000
MAX_DEPTH = 24
MAX_ABS = 1e150


def _load_reader():
    name = "csctf_r5g_common_agent_trace_vector"
    if name in sys.modules:
        return sys.modules[name]
    path = HERE.parent / "common" / "agent_trace.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("existing agent trace/vector reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


at = _load_reader()


def _vector(value: Any) -> tuple[list[float] | None, str | None]:
    if value is None:
        return None, "missing-vector"
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return None, "vector-not-a-list"
    if not 1 <= len(value) <= MAX_DIMENSIONS:
        return None, "vector-dimension-out-of-bounds"
    out = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            return None, "vector-has-nonnumeric-value"
        try:
            number = float(item)
        except (ValueError, TypeError, OverflowError):
            return None, "vector-magnitude-out-of-bounds"
        if not math.isfinite(number):
            return None, "vector-has-nonfinite-value"
        if abs(number) > MAX_ABS:
            return None, "vector-magnitude-out-of-bounds"
        out.append(number)
    return out, None


def _norm(vector: Sequence[float]) -> float:
    scale = max((abs(value) for value in vector), default=0.0)
    if scale == 0:
        return 0.0
    result = scale * math.sqrt(math.fsum((value / scale) ** 2 for value in vector))
    if not math.isfinite(result):
        raise ValueError("vector norm overflow")
    return result


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    # Delegate the operation after bounded finite validation and stable rescaling.
    if len(left) != len(right) or not left:
        return 0.0
    scale_left = max(map(abs, left)); scale_right = max(map(abs, right))
    if not scale_left or not scale_right:
        return 0.0
    result = at.cosine([value / scale_left for value in left], [value / scale_right for value in right])
    if not math.isfinite(result):
        raise ValueError("cosine produced a non-finite value")
    return max(-1.0, min(1.0, result))


def _vector_digest(vector: Sequence[float]) -> str:
    raw = b"".join(struct.pack(">d", 0.0 if value == 0 else value) for value in vector)
    return hashlib.sha256(raw).hexdigest()


def _text_digest(text: str) -> str:
    normalized = " ".join(text.casefold().split())
    return hashlib.sha256(normalized.encode("utf-8", "surrogatepass")).hexdigest()


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[^\W_]{2,}", text.casefold(), re.UNICODE)[:20_000])


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _documents(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, (bytes, bytearray)):
        if len(value) > MAX_STORE_BYTES:
            raise ValueError("saved vector store exceeds byte cap")
        docs = at.read_docs(bytes(value), "saved-vector-store")
    elif isinstance(value, Mapping):
        if len(value) > MAX_DOCUMENTS:
            raise ValueError("document mapping exceeds cap")
        for key in ("documents", "docs", "chunks", "records", "items", "data"):
            if isinstance(value.get(key), Sequence) and not isinstance(value.get(key), (str, bytes, bytearray)) \
                    and len(value[key]) > MAX_DOCUMENTS:
                raise ValueError("wrapped document sequence exceeds cap")
        try:
            docs = at.docs_from(value, "saved-vector-store")
        except (TypeError, ValueError, RecursionError, AttributeError):
            docs = []
        if not docs and isinstance(value.get("documents"), list):
            value = value["documents"]
            docs = [dict(row) for row in value if isinstance(row, Mapping)]
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > MAX_DOCUMENTS:
            raise ValueError("document count exceeds cap")
        docs = [dict(row) for row in value if isinstance(row, Mapping)]
    else:
        raise ValueError("documents must be structured saved data")
    if len(docs) > MAX_DOCUMENTS:
        raise ValueError("document count exceeds cap")
    out, text_bytes = [], 0
    for index, row in enumerate(docs):
        text = row.get("text", row.get("content", row.get("document", "")))
        text = text if isinstance(text, str) else ""
        if len(text.encode("utf-8", "surrogatepass")) > (4 << 20):
            text = text[:4 << 20]
        text_bytes += len(text.encode("utf-8", "surrogatepass"))
        if text_bytes > MAX_TEXT_BYTES:
            raise ValueError("saved document text exceeds aggregate cap")
        meta = row.get("meta", row.get("metadata", {}))
        meta = meta if isinstance(meta, Mapping) else {}
        vector = row.get("embedding", row.get("vector", row.get("values")))
        out.append({"id": str(row.get("id", row.get("doc_id", index)))[:512],
                    "text": text, "vector_raw": vector,
                    "source": str(row.get("source", meta.get("source", "")))[:1_024]})
    return out


def _validated(documents: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    docs = _documents(documents)
    findings, records, dimensions = [], [], Counter()
    ids = defaultdict(list)
    for index, doc in enumerate(docs):
        ids[doc["id"]].append(index)
        vector, error = _vector(doc["vector_raw"])
        if error:
            findings.append({"kind": error, "score": 72, "document": doc["id"],
                             "index": index, "verified": True})
            continue
        assert vector is not None
        norm = _norm(vector)
        dimensions[len(vector)] += 1
        if norm == 0:
            findings.append({"kind": "zero-norm-vector", "score": 64, "document": doc["id"],
                             "index": index, "verified": True})
        records.append({"index": index, "id": doc["id"], "vector": vector, "norm": norm,
                        "vector_sha256": _vector_digest(vector), "text_sha256": _text_digest(doc["text"]),
                        "tokens": _tokens(doc["text"]), "source": doc["source"]})
    for ident, indexes in ids.items():
        if len(indexes) > 1:
            findings.append({"kind": "duplicate-document-id", "score": 82, "document": ident,
                             "indices": indexes[:256], "count": len(indexes), "verified": True})
    if len(dimensions) > 1:
        findings.append({"kind": "mixed-vector-dimensions", "score": 88,
                         "dimensions": dict(sorted(dimensions.items())), "verified": True})
    public_records = [{key: value for key, value in row.items() if key not in {"vector", "tokens", "meta"}}
                      for row in records]
    findings.sort(key=lambda row: (-row["score"], row["kind"], row.get("index", 0)))
    public = {"document_count": len(docs), "valid_vector_count": len(records),
              "dimension_counts": dict(sorted(dimensions.items())), "records": public_records,
              "findings": findings[:MAX_FINDINGS], "valid": not findings, "network_used": False}
    return public, records


def validate_vector_store(documents: Any) -> dict[str, Any]:
    """Validate dimensions/finiteness/IDs without exposing document text or vector values."""
    public, _records_internal = _validated(documents)
    return public


def _pairs(records: Sequence[Mapping[str, Any]], state: dict[str, int | bool]):
    for right in range(len(records)):
        for left in range(right):
            if int(state["attempted"]) >= MAX_COMPARISONS:
                state["capped"] = True
                return
            state["attempted"] = int(state["attempted"]) + 1
            if len(records[left]["vector"]) == len(records[right]["vector"]):
                state["compatible"] = int(state["compatible"]) + 1
                yield left, right, _cosine(records[left]["vector"], records[right]["vector"])


def vector_poison_report(documents: Any, *, trusted_ids: Sequence[str] = (), k: int = 5,
                         near_similarity: float = 0.995, lexical_ceiling: float = 0.2) -> dict[str, Any]:
    """Cross-check saved vector geometry against text/provenance; intent remains unverified."""
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= 64:
        raise ValueError("k must be an integer in [1,64]")
    for _value in (lexical_ceiling, near_similarity):
        if not isinstance(_value, (int, float)) or isinstance(_value, bool):
            raise ValueError("similarity thresholds must be numbers")
    if not 0 <= lexical_ceiling <= 1 or not -1 <= near_similarity <= 1:
        raise ValueError("similarity thresholds are out of bounds")
    checked, records = _validated(documents)
    if len(records) > MAX_VECTOR_DOCUMENTS:
        raise ValueError("valid vector document count exceeds geometry cap")
    geometry = [row for row in records if row["norm"] > 0]
    findings = list(checked["findings"])
    neighbours: list[list[tuple[float, int]]] = [[] for _ in geometry]
    exact: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(records):
        exact[row["vector_sha256"]].append(index)
    for indexes in exact.values():
        if len(indexes) > 1:
            text_hashes = {records[index]["text_sha256"] for index in indexes}
            if len(text_hashes) > 1:
                findings.append({"kind": "exact-vector-divergent-text", "score": 94,
                                 "documents": [records[index]["id"] for index in indexes[:128]],
                                 "vector_sha256": records[indexes[0]]["vector_sha256"], "verified": True})
    pair_state: dict[str, int | bool] = {"attempted": 0, "compatible": 0, "capped": False}
    for left, right, similarity in _pairs(geometry, pair_state):
        neighbours[left].append((similarity, right)); neighbours[right].append((similarity, left))
        if similarity >= near_similarity:
            lexical = _jaccard(geometry[left]["tokens"], geometry[right]["tokens"])
            if lexical <= lexical_ceiling and geometry[left]["text_sha256"] != geometry[right]["text_sha256"]:
                findings.append({"kind": "vector-text-collision-candidate", "score": 86,
                                 "documents": [geometry[left]["id"], geometry[right]["id"]],
                                 "cosine": similarity, "token_jaccard": lexical,
                                 "reason": "near-identical supplied vectors accompany lexically disjoint saved text"})
    full_pair_count = len(geometry) * (len(geometry) - 1) // 2
    comparison_capped = bool(pair_state["capped"]) or int(pair_state["attempted"]) < full_pair_count
    hub_counts = Counter()
    if not comparison_capped:
        for rows in neighbours:
            rows.sort(key=lambda item: (-item[0], geometry[item[1]]["id"], item[1]))
            for _score, index in rows[:min(k, len(rows))]:
                hub_counts[index] += 1
        counts = list(hub_counts.values()) + [0] * (len(geometry) - len(hub_counts))
        mean = statistics.mean(counts) if counts else 0.0
        spread = statistics.pstdev(counts) if len(counts) > 1 else 0.0
        threshold = max(k + 1, math.ceil(mean + 3 * spread))
        for index, count in hub_counts.items():
            if count >= threshold:
                findings.append({"kind": "knn-hub-candidate", "score": 60,
                                 "document": geometry[index]["id"], "neighbour_occurrences": count,
                                 "threshold": threshold, "verified_geometry": True})
    if not isinstance(trusted_ids, Sequence) or isinstance(trusted_ids, (str, bytes, bytearray)) \
            or len(trusted_ids) > MAX_DOCUMENTS:
        raise ValueError("trusted_ids must be a bounded list")
    trusted = {str(value) for value in trusted_ids}
    trusted_rows = [row for row in geometry if row["id"] in trusted]
    centroid = None
    if trusted_rows:
        dimensions = {len(row["vector"]) for row in trusted_rows}
        if len(dimensions) != 1:
            raise ValueError("trusted vectors have mixed dimensions")
        dimension = dimensions.pop()
        centroid = [math.fsum(row["vector"][axis] for row in trusted_rows) / len(trusted_rows)
                    for axis in range(dimension)]
        if _norm(centroid) == 0:
            findings.append({"kind": "trusted-centroid-zero-norm", "score": 52,
                             "trusted_count": len(trusted_rows), "verified": True,
                             "reason": "caller-designated trusted vectors cancel to a zero centroid; cosine comparison is undefined"})
            centroid = None
        else:
            for row in geometry:
                if row["id"] not in trusted and len(row["vector"]) == dimension:
                    similarity = _cosine(row["vector"], centroid)
                    if similarity < 0:
                        findings.append({"kind": "trusted-centroid-outlier-candidate", "score": 48,
                                         "document": row["id"], "centroid_cosine": similarity,
                                         "reason": "vector lies opposite the caller-designated trusted centroid"})
    # Same normalized text represented inconsistently is a version/provenance lead.
    by_text = defaultdict(list)
    for row in records:
        by_text[row["text_sha256"]].append(row)
    for group in by_text.values():
        if len(group) > 1 and len({row["vector_sha256"] for row in group}) > 1:
            findings.append({"kind": "same-text-inconsistent-vector", "score": 68,
                             "documents": [row["id"] for row in group[:128]],
                             "reason": "identical normalized saved text has multiple supplied vectors or embedding versions"})
    findings.sort(key=lambda row: (-int(row.get("score", 0)), row["kind"], str(row.get("document", ""))))
    return {**checked, "findings": findings[:MAX_FINDINGS],
            "geometry_vector_count": len(geometry),
            "pair_comparisons": int(pair_state["attempted"]),
            "compatible_pair_comparisons": int(pair_state["compatible"]),
            "full_pair_comparisons": full_pair_count,
            "pair_comparisons_capped": comparison_capped, "k": k,
            "hub_occurrences": {geometry[index]["id"]: count for index, count in sorted(hub_counts.items())},
            "trusted_count": len(trusted_rows), "trusted_centroid_computed": centroid is not None,
            "poisoning_verified": False, "requires_human_review": True,
            "note": "geometry/text disagreement is evidence only; embedding model and corpus provenance are external"}


def audit_saved_ranking(query: Sequence[Any], returned: Sequence[Any], corpus: Any,
                        *, score_tolerance: float = 1e-6) -> dict[str, Any]:
    """Recompute cosine order for a saved single-query result; no database is contacted."""
    q, error = _vector(query)
    if error or q is None or _norm(q) == 0:
        raise ValueError("query must be a bounded nonzero finite vector")
    if not isinstance(returned, Sequence) or isinstance(returned, (str, bytes, bytearray)) \
            or len(returned) > MAX_DOCUMENTS:
        raise ValueError("returned results must be a bounded list")
    if not isinstance(score_tolerance, (int, float)) or isinstance(score_tolerance, bool) \
            or score_tolerance < 0:
        raise ValueError("score_tolerance must be finite and non-negative")
    try:
        _finite_tolerance = math.isfinite(float(score_tolerance))
    except OverflowError:
        _finite_tolerance = False
    if not _finite_tolerance:
        raise ValueError("score_tolerance must be finite and non-negative")
    _checked, records = _validated(corpus)
    compatible = [row for row in records if len(row["vector"]) == len(q)]
    scored = sorted(((_cosine(q, row["vector"]), row["id"]) for row in compatible),
                    key=lambda item: (-item[0], item[1]))
    returned_rows = []
    for item in returned:
        if isinstance(item, Mapping):
            ident, claimed = str(item.get("id", item.get("doc_id", "")))[:512], item.get("score", item.get("similarity"))
        else:
            ident, claimed = str(item)[:512], None
        if not ident:
            raise ValueError("returned item lacks id")
        if claimed is not None:
            try:
                converted = float(claimed)
            except (ValueError, TypeError, OverflowError):
                converted = math.nan
            if isinstance(claimed, bool) or not isinstance(claimed, (int, float)) or not math.isfinite(converted):
                raise ValueError("claimed score must be finite numeric")
            claimed = converted
        returned_rows.append((ident, claimed))
    actual = dict((ident, score) for score, ident in scored)
    findings = []
    counts = Counter(ident for ident, _score in returned_rows)
    for ident, count in counts.items():
        if count > 1:
            findings.append({"kind": "duplicate-returned-id", "score": 80, "document": ident,
                             "count": count, "verified": True})
    known = [(ident, claimed) for ident, claimed in returned_rows if ident in actual]
    for ident, claimed in known:
        if claimed is not None and abs(claimed - actual[ident]) > score_tolerance:
            findings.append({"kind": "reported-score-mismatch", "score": 88, "document": ident,
                             "reported": claimed, "recomputed": actual[ident], "verified": True})
    expected_order = [ident for _score, ident in scored if ident in counts]
    observed_order = [ident for ident, _score in returned_rows if ident in actual]
    if observed_order != expected_order[:len(observed_order)]:
        findings.append({"kind": "returned-order-mismatch", "score": 84,
                         "observed": observed_order[:256], "recomputed": expected_order[:256], "verified": True})
    if known:
        floor = min(actual[ident] for ident, _claimed in known)
        omitted = [ident for score, ident in scored if ident not in counts and score > floor + score_tolerance]
        if omitted:
            findings.append({"kind": "nearer-corpus-items-omitted", "score": 76,
                             "documents": omitted[:256], "returned_floor": floor, "verified": True})
    for ident, _claimed in returned_rows:
        if ident not in actual:
            findings.append({"kind": "returned-id-not-in-compatible-corpus", "score": 72,
                             "document": ident, "verified": True})
    findings.sort(key=lambda row: (-row["score"], row["kind"], str(row.get("document", ""))))
    return {"corpus_vectors": len(compatible), "returned": len(returned_rows),
            "recomputed_order": [ident for _score, ident in scored[:len(returned_rows) + 256]],
            "findings": findings[:MAX_FINDINGS], "ranking_verified_from_saved_vectors": True,
            "retrieval_contacted": False, "requires_human_review": True}


def _codebook(value: Any) -> list[tuple[str, list[float]]]:
    if isinstance(value, Mapping):
        if not 1 <= len(value) <= MAX_CODEBOOK:
            raise ValueError("codebook size is out of bounds")
        items = list(value.items())
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if not 1 <= len(value) <= MAX_CODEBOOK:
            raise ValueError("codebook size is out of bounds")
        items = []
        for row in value:
            if not isinstance(row, Mapping) or "label" not in row or "vector" not in row:
                raise ValueError("codebook rows need label and vector")
            items.append((row["label"], row["vector"]))
    else:
        raise ValueError("codebook must be a mapping or row list")
    if not 1 <= len(items) <= MAX_CODEBOOK:
        raise ValueError("codebook size is out of bounds")
    out, seen = [], set()
    for label, raw in items:
        label = str(label)[:1_024]
        if label in seen:
            raise ValueError("codebook labels must be unique")
        seen.add(label)
        vector, error = _vector(raw)
        if error or vector is None or _norm(vector) == 0:
            raise ValueError(f"invalid codebook vector for {label!r}")
        out.append((label, vector))
    return out


def embedding_exposure_report(targets: Any, codebook: Any, *, additive: bool = False,
                              max_terms: int = 3) -> dict[str, Any]:
    """Nearest/exact candidates against a caller-supplied codebook only."""
    entries = _codebook(codebook)
    if not isinstance(max_terms, int) or isinstance(max_terms, bool) or not 1 <= max_terms <= 4:
        raise ValueError("max_terms must be an integer in [1,4]")
    if isinstance(targets, Mapping):
        if not 1 <= len(targets) <= MAX_TARGETS:
            raise ValueError("target count is out of bounds")
        target_items = list(targets.items())
    elif isinstance(targets, Sequence) and not isinstance(targets, (str, bytes, bytearray)):
        if not 1 <= len(targets) <= MAX_TARGETS:
            raise ValueError("target count is out of bounds")
        target_items = []
        for index, row in enumerate(targets):
            if isinstance(row, Mapping):
                target_items.append((row.get("id", index), row.get("vector", row.get("embedding"))))
            else:
                target_items.append((index, row))
    else:
        raise ValueError("targets must be a mapping or list")
    if not 1 <= len(target_items) <= MAX_TARGETS:
        raise ValueError("target count is out of bounds")
    required = len(target_items) * len(entries) * (1 + max_terms if additive else 1)
    if required > MAX_COMPARISONS:
        raise ValueError("target/codebook comparison cap exceeded")
    results, comparisons = [], 0
    for ident, raw in target_items:
        target, error = _vector(raw)
        if error or target is None or _norm(target) == 0:
            raise ValueError(f"invalid target vector {ident!r}")
        compatible = [(label, vector) for label, vector in entries if len(vector) == len(target)]
        if not compatible:
            raise ValueError("no codebook vector matches target dimension")
        scored = []
        for label, vector in compatible:
            comparisons += 1
            if comparisons > MAX_COMPARISONS:
                raise ValueError("target/codebook comparison cap exceeded")
            residual = math.sqrt(math.fsum((a - b) ** 2 for a, b in zip(target, vector)))
            scored.append((_cosine(target, vector), residual, label, vector))
        scored.sort(key=lambda row: (-row[0], row[1], row[2]))
        best = scored[0]
        exact = all(a == b for a, b in zip(target, best[3]))
        row = {"id": str(ident)[:512], "nearest_label": best[2], "cosine": best[0],
               "residual_l2": best[1], "margin": best[0] - scored[1][0] if len(scored) > 1 else None,
               "exact_match": exact, "plaintext_recovered": exact,
               "candidate_only": not exact}
        if additive:
            residual_vector = list(target); labels = []
            for _ in range(max_terms):
                choices = []
                for label, vector in compatible:
                    comparisons += 1
                    if comparisons > MAX_COMPARISONS:
                        raise ValueError("target/codebook comparison cap exceeded")
                    choices.append((_cosine(residual_vector, vector), label, vector))
                choices.sort(key=lambda item: (-item[0], item[1]))
                _score, label, vector = choices[0]
                labels.append(label)
                residual_vector = [left - right for left, right in zip(residual_vector, vector)]
                if _norm(residual_vector) <= 1e-12:
                    break
            row["additive_candidate"] = labels
            row["additive_residual_l2"] = _norm(residual_vector)
            row["additive_semantics_assumed"] = True
        results.append(row)
    return {"targets": len(results), "codebook_entries": len(entries), "comparisons": comparisons,
            "results": results, "codebook_source": "caller-supplied",
            "embedding_service_contacted": False, "inversion_verified": False,
            "requires_human_review": True,
            "note": "nearest labels are candidates; only exact supplied-vector matches set plaintext_recovered"}


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      default=lambda item: "<non-json>")

