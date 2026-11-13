#!/usr/bin/env python3
"""Offline orchestration across the Round-5a archetype dispatchers.

The public API is :func:`autosolve`.  It accepts a description and paths/named bytes, performs only
bounded local parsing, fans selected archetypes to the existing-engine dispatchers, and returns ranked
flag-shaped candidates with derivations for human review.  It has no submit or network capability.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for directory in (ROOT, HERE, ROOT / "solvers" / "common", ROOT / "solvers" / "warmups",
                  ROOT / "solvers" / "web"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import dispatch_core as core  # noqa: E402


DISPATCH_MODULES = {
    "crypto": "dispatch_crypto",
    "forensics": "dispatch_forensics",
    "exploit": "dispatch_exploit",
}

_CATEGORY_DISPATCHER = {
    "crypto": "crypto", "cryptography": "crypto", "sanity": "crypto",
    "web": "exploit", "pwn": "exploit", "binary": "exploit", "reverse": "exploit",
    "reversing": "exploit", "blockchain": "exploit", "programming": "exploit",
    "forensics": "forensics", "forensic": "forensics", "stego": "forensics",
    "steganography": "forensics", "network": "forensics", "networking": "forensics",
    "ics": "forensics", "mobile": "forensics", "windows": "forensics",
    "linux": "forensics", "opsec": "forensics", "osint": "forensics", "ml": "forensics",
}


def _triage_advice(category: str, description: str) -> dict[str, Any]:
    """Read existing routing as advice only; never mutate or invoke an engine CLI."""
    try:
        from ctf import triage
        result = triage.suggest(category or "misc", description)
        return {
            "category": result.get("category"),
            "playbook": result.get("playbook"),
            "engines": list(result.get("engines") or [])[:64],
        }
    except (Exception, SystemExit) as exc:
        return {"category": category or "unknown", "playbook": None, "engines": [],
                "error": f"{type(exc).__name__}: {str(exc).splitlines()[0][:500]}"}


def _string_items(value: Any, *, maximum: int) -> list[str]:
    if type(value) not in (list, tuple):
        return []
    return [str(item)[:1000] for item in value[:maximum] if isinstance(item, (str, int, float, bool))]


def _bounded_json(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> Any:
    """Copy dispatcher evidence into a bounded JSON-only tree; reject executable/custom objects."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > 4096 or depth > 10:
        raise ValueError("dispatcher evidence exceeds JSON bounds")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > 4096:
            raise ValueError("dispatcher evidence integer exceeds bound")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("dispatcher evidence contains a non-finite number")
        return value
    if type(value) is str:
        return value[:4000]
    if type(value) in (bytes, bytearray, memoryview):
        raw = bytes(value)
        return {"byte_length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if type(value) is dict:
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:128]:
            if not isinstance(key, (str, int, bool)):
                raise ValueError("dispatcher evidence has a non-scalar key")
            out[str(key)[:200]] = _bounded_json(item, depth=depth + 1, nodes=nodes)
        return out
    if type(value) in (list, tuple):
        return [_bounded_json(item, depth=depth + 1, nodes=nodes) for item in value[:256]]
    raise ValueError(f"non-JSON dispatcher evidence: {type(value).__name__}")


def _safe_rows(value: Any, *, maximum: int) -> tuple[list[dict[str, Any]], int]:
    if type(value) not in (list, tuple):
        return [], 0 if value is None else 1
    rows, rejected = [], 0
    for item in value[:maximum]:
        if type(item) is not dict:
            rejected += 1
            continue
        try:
            clean = _bounded_json(item)
        except (TypeError, ValueError, OverflowError, RecursionError):
            rejected += 1
            continue
        if isinstance(clean, dict):
            rows.append(clean)
        else:
            rejected += 1
    rejected += max(0, len(value) - maximum)
    return rows, rejected


def _sanitize_candidate(candidate: Any, *, dispatcher: str) -> dict[str, Any] | None:
    if type(candidate) is not dict:
        return None
    try:
        confidence = str(candidate.get("confidence") or "low")
        if confidence not in {"low", "medium", "high"}:
            confidence = "low"
        return core.make_candidate(
            candidate.get("value"),
            archetype=str(candidate.get("archetype") or "unknown"),
            engine=str(candidate.get("engine") or dispatcher),
            source=str(candidate.get("source") or dispatcher),
            derivation=_string_items(candidate.get("derivation"), maximum=32),
            verified=candidate.get("verified") is True,
            confidence=confidence,
            evidence=_string_items(candidate.get("evidence"), maximum=32),
            warnings=_string_items(candidate.get("warnings"), maximum=32),
        )
    except (Exception, SystemExit):
        return None


def _run_dispatcher(group: str, description: str, artifacts: Sequence[core.Artifact],
                    category: str) -> dict[str, Any]:
    module_name = DISPATCH_MODULES[group]
    started_attempt = core.make_attempt(module_name, status="selected")
    try:
        module = importlib.import_module(module_name)
        function = getattr(module, "dispatch")
    except (Exception, SystemExit) as exc:
        return {
            "group": group,
            "module": module_name,
            "attempts": [started_attempt, core.make_attempt(
                module_name, status="unavailable", error=f"{type(exc).__name__}: {exc}")],
            "candidates": [], "observations": [], "warnings": ["dispatcher unavailable"],
        }
    value, attempt = core.safe_engine_call(module_name, function, description, artifacts,
                                           category=category)
    if type(value) is not dict:
        return {"group": group, "module": module_name,
                "attempts": [started_attempt, attempt], "candidates": [], "observations": [],
                "warnings": ["dispatcher declined or returned a non-report"]}
    contract_ok = (
        value.get("offline") is True
        and type(value.get("network_requests")) is int
        and value.get("network_requests") == 0
        and value.get("submitted") is False
        and value.get("executed_artifacts") is not True
    )
    if not contract_ok:
        return {"group": group, "module": module_name,
                "attempts": [started_attempt, core.make_attempt(
                    module_name, status="error", error="dispatcher violated offline/no-submit contract")],
                "candidates": [], "observations": [],
                "warnings": ["rejected dispatcher result that violated safety contract"]}
    candidates = []
    rejected = 0
    supplied_candidates = value.get("candidates")
    if type(supplied_candidates) in (list, tuple):
        raw_candidates = supplied_candidates
    elif supplied_candidates is None:
        raw_candidates = []
    else:
        raw_candidates, rejected = [], 1
    for candidate in raw_candidates[:256]:
        clean = _sanitize_candidate(candidate, dispatcher=module_name)
        if clean is None:
            rejected += 1
        else:
            candidates.append(clean)
    rejected += max(0, len(raw_candidates) - 256)
    warnings = _string_items(value.get("warnings"), maximum=64)
    if rejected:
        warnings.append(f"rejected {rejected} malformed/non-flag candidate(s)")
    attempts, rejected_attempts = _safe_rows(value.get("attempts"), maximum=256)
    observations, rejected_observations = _safe_rows(value.get("observations"), maximum=256)
    if rejected_attempts:
        warnings.append(f"rejected {rejected_attempts} malformed/non-JSON attempt row(s)")
    if rejected_observations:
        warnings.append(f"rejected {rejected_observations} malformed/non-JSON observation row(s)")
    return {
        "group": group,
        "module": module_name,
        "attempts": [started_attempt, attempt] + attempts,
        "candidates": candidates,
        "observations": observations,
        "warnings": warnings,
    }


def _apply_category_hint(selections: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    group = _CATEGORY_DISPATCHER.get(str(category or "").strip().casefold())
    if group is None:
        return selections
    rows = [dict(row) for row in selections]
    existing = next((row for row in rows if row.get("dispatcher") == group), None)
    if existing is None:
        rows.append({"dispatcher": group, "score": 3,
                     "evidence": [f"category-hint:{category}"]})
    else:
        existing["score"] = int(existing.get("score") or 0) + 3
        existing["evidence"] = list(existing.get("evidence") or []) + [f"category-hint:{category}"]
    return sorted(rows, key=lambda row: (-int(row["score"]), str(row["dispatcher"])))


def autosolve(description: str, files: Any, *, category: str = "") -> dict[str, Any]:
    """Triage and run bounded offline dispatchers, returning candidates for human review.

    ``files`` accepts the forms documented by :func:`dispatch_core.normalize_artifacts`.  The
    function never connects, executes artifacts, writes challenge data, or submits a value.
    """
    description = core.normalize_description(description)
    category = core.normalize_category(category)
    artifacts = core.normalize_artifacts(files)
    archetypes = core.classify_archetypes(description, artifacts)
    selections = _apply_category_hint(core.dispatcher_scores(archetypes), category)
    direct = core.direct_artifact_report(description, artifacts)

    result: dict[str, Any] = {
        "schema": "csctf-r5a-autosolve-v1",
        "dispatcher": "autosolve",
        "offline": True,
        "network_requests": 0,
        "submitted": False,
        "category_hint": category,
        "description": {
            "length": len(description),
            "sha256": hashlib.sha256(description.encode("utf-8")).hexdigest(),
        },
        "artifacts": [artifact.public() for artifact in artifacts],
        "archetypes": archetypes,
        "dispatcher_selection": selections,
        "existing_triage_advice": _triage_advice(category, description),
        "dispatcher_reports": [],
        "attempts": list(direct.get("attempts") or []),
        "candidates": list(direct.get("candidates") or []),
        "observations": [],
        "warnings": list(direct.get("warnings") or []),
    }

    for selection in selections:
        group = str(selection["dispatcher"])
        report = _run_dispatcher(group, description, artifacts, category)
        result["dispatcher_reports"].append({
            "group": group,
            "module": report["module"],
            "candidate_count": len(report["candidates"]),
            "observation_count": len(report["observations"]),
            "warnings": report["warnings"],
        })
        result["attempts"].extend(report["attempts"])
        result["candidates"].extend(report["candidates"])
        result["observations"].extend(report["observations"])
        result["warnings"].extend(report["warnings"])

    result["routing_summary"] = (
        f"selected {len(selections)} dispatcher(s) from {len(archetypes)} archetype signal(s); "
        f"all output requires human review"
    )
    return core.finalize_report(result)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline archetype autosolver; emits ranked candidates and derivations, never submits")
    parser.add_argument("files", nargs="*", help="artifact paths (read as bounded data only)")
    parser.add_argument("--description", default="", help="challenge description text")
    parser.add_argument("--description-file", help="read description text from this local file")
    parser.add_argument("--category", default="", help="optional category hint")
    parser.add_argument("--json", action="store_true", help="emit the complete JSON report")
    return parser


def _human(report: Mapping[str, Any]) -> str:
    lines = [report.get("routing_summary", "offline autosolve"),
             "archetypes: " + ", ".join(
                 f"{row['archetype']}({row['score']})" for row in report.get("archetypes") or [])]
    candidates = report.get("candidates") or []
    if not candidates:
        lines.append("no flag-shaped candidate recovered; inspect observations/attempts with --json")
    for row in candidates:
        lines.append(f"#{row['rank']} {row['value']}  confidence={row['confidence']} "
                     f"verified-local={row['verified']}  HUMAN REVIEW REQUIRED")
        lines.extend(f"    -> {step}" for step in row.get("derivation") or [])
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        description = args.description
        if args.description_file:
            path = Path(args.description_file)
            with path.open("rb") as handle:
                raw_description = handle.read(core.MAX_DESCRIPTION * 4 + 1)
            if len(raw_description) > core.MAX_DESCRIPTION * 4:
                raise core.R5AInputError("description file exceeds bounded read limit")
            description = raw_description.decode("utf-8", "replace")
        report = autosolve(description, [Path(value) for value in args.files], category=args.category)
    except (core.R5AInputError, OSError, ValueError) as exc:
        parser.exit(2, f"autosolve: {str(exc).splitlines()[0]}\n")
    sys.stdout.write(core.public_json(report) if args.json else _human(report))
    return 0 if report["candidates"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

