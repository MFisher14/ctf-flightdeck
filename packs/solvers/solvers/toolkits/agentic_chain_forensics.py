#!/usr/bin/env python3
"""Bounded multi-hop forensics for saved agent/tool traces.

``solvers/common/agent_trace.py`` remains the transcript/config parser and prompt-injection reader.
This overlay consumes its normalized rows (or delegates normalization to it), verifies call/result
integrity, and builds evidence-only value/capability chains. It never invokes a tool, follows a URL,
opens a model API, or treats transcript text as an instruction. Potential secrets are represented by
length and digest, never copied into the report.
"""
from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import math
import re
import sys
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
MAX_ROWS = 20_000
MAX_TRACE_BYTES = 32 << 20
MAX_AGGREGATE_BYTES = 32 << 20
MAX_DEPTH = 16
MAX_LEAVES = 10_000
MAX_FLOW_VALUES = 100_000
MAX_VALUE = 4_096
MAX_EDGES = 100_000
MAX_FINDINGS = 5_000
MAX_CHAINS = 1_000
MAX_SNAPSHOTS = 1_000

SECRET_KEY = re.compile(r"(?i)(?:secret|password|passwd|token|authorization|api[_-]?key|credential|cookie|session|private[_-]?key)")
SECRET_VALUE = re.compile(r"(?i)(?:bearer\s+[a-z0-9._~+/-]{8,}|(?:sk|ghp|xox[baprs])[-_][a-z0-9_-]{8,}|"
                          r"-----BEGIN [A-Z ]*PRIVATE KEY-----)")
SINKS = {
    "network": ("http", "url", "fetch", "request", "browser", "webhook", "curl", "post"),
    "message": ("send", "mail", "email", "message", "notify", "slack", "teams"),
    "filesystem-write": ("write", "save", "append", "upload", "replace", "edit", "patch"),
    "memory": ("memory", "remember", "profile", "preference", "persist"),
    "execution": ("shell", "terminal", "exec", "command", "python", "process"),
    "delegation": ("delegate", "handoff", "spawn", "subagent", "agent"),
}
SENSITIVE_READ = ("secret", "credential", "token", "password", "keychain", "environment", "env", "read_file", "get_file")


def _load_reader():
    name = "csctf_r5g_common_agent_trace"
    if name in sys.modules:
        return sys.modules[name]
    path = HERE.parent / "common" / "agent_trace.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("existing agent-trace reader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


at = _load_reader()


def _digest(value: Any) -> str:
    value = _redact(value)
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8", "surrogatepass")
    except (ValueError, TypeError, RecursionError):
        raw = repr(type(value).__name__).encode()
    return hashlib.sha256(raw).hexdigest()


def _bounded_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "<non-finite>"
    if isinstance(value, str):
        return value[:MAX_VALUE]
    return str(value)[:MAX_VALUE]


def _redact(value: Any, path: str = "$", depth: int = 0, state: dict[str, int] | None = None) -> Any:
    state = state if state is not None else {"items": 0}
    if depth > MAX_DEPTH:
        return "<depth-capped>"
    if state["items"] >= MAX_LEAVES:
        return "<item-capped>"
    if isinstance(value, Mapping):
        out = {}
        for key, item in itertools.islice(value.items(), MAX_LEAVES):
            state["items"] += 1
            name = str(key)[:128]
            if SECRET_KEY.search(name):
                text = str(item)
                out[name] = {"redacted": True, "length": len(text),
                             "sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()}
            else:
                out[name] = _redact(item, f"{path}.{name}", depth + 1, state)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact(item, f"{path}[{index}]", depth + 1, state)
                for index, item in enumerate(value[:MAX_LEAVES])]
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if isinstance(value, str) and SECRET_VALUE.search(value):
        return {"redacted": True, "length": len(value),
                "sha256": hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()}
    return _bounded_scalar(value)


def _leaves(value: Any, path: str = "$", depth: int = 0, state: dict[str, int] | None = None):
    state = state if state is not None else {"items": 0}
    if depth > MAX_DEPTH or state["items"] >= MAX_LEAVES:
        return
    if isinstance(value, Mapping):
        for key, item in itertools.islice(value.items(), MAX_LEAVES):
            state["items"] += 1
            yield from _leaves(item, f"{path}.{str(key)[:128]}", depth + 1, state)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value[:MAX_LEAVES]):
            yield from _leaves(item, f"{path}[{index}]", depth + 1, state)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value)
        if 4 <= len(text) <= MAX_VALUE:
            yield path, text


def _parse_result(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if len(value) > (4 << 20):
        return value[:4 << 20]
    try:
        return json.loads(value)
    except (ValueError, TypeError, RecursionError):
        return value


def _payload_size(value: Any, *, budget: int, depth: int = 0,
                  seen: set[int] | None = None) -> int:
    """Conservative bounded size estimate without serializing attacker-controlled structures."""
    if budget < 0:
        return MAX_AGGREGATE_BYTES + 1
    if depth > MAX_DEPTH:
        return MAX_AGGREGATE_BYTES + 1
    if value is None or isinstance(value, (bool, int, float)):
        return 16
    if isinstance(value, str):
        # UTF-8 uses at most four bytes per code point; avoid allocating an encoded copy.
        return min(MAX_AGGREGATE_BYTES + 1, len(value) * 4)
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    seen = set() if seen is None else seen
    identity = id(value)
    if identity in seen:
        return 0
    if isinstance(value, Mapping):
        if len(value) > MAX_LEAVES:
            return MAX_AGGREGATE_BYTES + 1
        seen.add(identity); total = 0
        for key, item in itertools.islice(value.items(), MAX_LEAVES):
            total += _payload_size(str(key), budget=budget - total, depth=depth + 1, seen=seen)
            total += _payload_size(item, budget=budget - total, depth=depth + 1, seen=seen)
            if total > budget:
                break
        seen.remove(identity)
        return total
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > MAX_LEAVES:
            return MAX_AGGREGATE_BYTES + 1
        seen.add(identity); total = 0
        for item in value:
            total += _payload_size(item, budget=budget - total, depth=depth + 1, seen=seen)
            if total > budget:
                break
        seen.remove(identity)
        return total
    return min(MAX_AGGREGATE_BYTES + 1, len(type(value).__name__) * 4)


def _normalized(value: Any) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]]]:
    approvals = []
    candidate = value
    if isinstance(value, Mapping):
        if len(value) > MAX_ROWS:
            raise ValueError("trace wrapper mapping exceeds cap")
        for key in ("rows", "messages", "turns", "conversation", "transcript", "approvals"):
            if isinstance(value.get(key), Sequence) and not isinstance(value.get(key), (str, bytes, bytearray)) \
                    and len(value[key]) > MAX_ROWS:
                raise ValueError(f"{key} sequence exceeds cap")
        if isinstance(value.get("approvals"), list):
            if len(value["approvals"]) > MAX_ROWS:
                raise ValueError("approval list exceeds cap")
            approvals = [row for row in value["approvals"] if isinstance(row, Mapping)]
        if isinstance(value.get("rows"), list):
            candidate = value["rows"]
    if isinstance(candidate, (bytes, bytearray)):
        if len(candidate) > MAX_TRACE_BYTES:
            raise ValueError("trace bytes exceed cap")
        rows = at.load_trace(bytes(candidate))
    elif isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes, bytearray)):
        if len(candidate) > MAX_ROWS:
            raise ValueError("trace row count exceeds cap")
        if all(isinstance(row, Mapping) and row.get("kind") in {"message", "call", "result", "approval", "handoff"}
               for row in candidate):
            rows = [dict(row) for row in candidate]
        else:
            try:
                rows = at.trace_rows(candidate)
            except (TypeError, ValueError, RecursionError, AttributeError):
                rows = []
    else:
        try:
            rows = at.trace_rows(candidate)
        except (TypeError, ValueError, RecursionError, AttributeError):
            rows = []
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("trace must normalize to at most 20000 rows")
    normalized = [dict(row) for row in rows if isinstance(row, Mapping)]
    aggregate = 0
    for row in normalized:
        for key in ("text", "content", "arguments", "args", "result", "output"):
            if key not in row:
                continue
            aggregate += _payload_size(row[key], budget=MAX_AGGREGATE_BYTES - aggregate)
            if aggregate > MAX_AGGREGATE_BYTES:
                raise ValueError("trace text/argument payload exceeds aggregate cap")
    return normalized, approvals


def _classify_tool(name: str, arguments: Any) -> tuple[list[str], bool]:
    parts, size = [name], len(name)
    for index, (_path, value) in enumerate(_leaves(arguments) or ()):
        if index >= 1_024 or size >= 64_000:
            break
        clipped = value[:min(MAX_VALUE, 64_000 - size)]
        parts.append(clipped); size += len(clipped) + 1
    text = " ".join(parts).casefold()[:64_000]
    sinks = [kind for kind, hints in SINKS.items() if any(hint in text for hint in hints)]
    sensitive = any(hint in text for hint in SENSITIVE_READ)
    return sinks, sensitive


def _attack_evidence(text: str) -> bool:
    try:
        return bool(at.addresses_solver(at.strip_invisible(text)) or
                    any(item.get("strong") for item in at.hidden_text(text)))
    except (TypeError, ValueError, RecursionError):
        return False


def build_event_graph(value: Any) -> dict[str, Any]:
    """Normalize a saved trace and return redacted nodes plus structural/value-flow edges."""
    rows, embedded_approvals = _normalized(value)
    nodes, edges, findings = [], [], []
    calls_by_id: dict[str, list[int]] = defaultdict(list)
    results_by_id: dict[str, list[int]] = defaultdict(list)
    raw_args, raw_results = {}, {}
    for index, row in enumerate(rows):
        kind = str(row.get("kind", "message")).lower()
        tool = str(row.get("tool") or row.get("name") or "")[:256]
        call_id = row.get("call_id")
        call_id = str(call_id)[:512] if call_id is not None else None
        arguments = row.get("arguments", row.get("args"))
        result = row.get("result", row.get("output", row.get("text", "")))
        sinks, sensitive = _classify_tool(tool, arguments) if kind == "call" else ([], False)
        text = str(row.get("text", ""))[:4 << 20]
        node = {"index": index, "kind": kind, "role": str(row.get("role", "unknown"))[:64],
                "tool": tool or None, "call_id": call_id,
                "agent_id": str(row.get("agent_id", row.get("agent", "")))[:256] or None,
                "parent_agent_id": str(row.get("parent_agent_id", row.get("parent_agent", "")))[:256] or None,
                "text_length": len(text), "text_sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
                "attack_evidence": _attack_evidence(text) if kind in {"result", "message"} else False,
                "sinks": sinks, "sensitive_read_candidate": sensitive}
        if kind == "call":
            raw_args[index] = arguments
            node["arguments_digest"] = _digest(arguments)
            node["arguments"] = _redact(arguments)
            if call_id is not None:
                calls_by_id[call_id].append(index)
        elif kind == "result":
            raw_results[index] = _parse_result(result)
            node["result_digest"] = _digest(result)
            if call_id is not None:
                results_by_id[call_id].append(index)
        nodes.append(node)

    # Call/result pairing and integrity anomalies.
    paired_result: dict[int, int] = {}
    used_calls = set()
    for call_id, indexes in calls_by_id.items():
        if len(indexes) > 1:
            findings.append({"kind": "duplicate-call-id", "score": 90, "call_id_sha256": _digest(call_id),
                             "call_indices": indexes, "verified": True})
    for call_id, indexes in results_by_id.items():
        if len(indexes) > 1:
            digests = [nodes[index].get("result_digest") for index in indexes]
            findings.append({"kind": "replayed-or-duplicate-result", "score": 78,
                             "call_id_sha256": _digest(call_id), "result_indices": indexes,
                             "identical": len(set(digests)) == 1, "verified": True})
    for result_index in [index for index, node in enumerate(nodes) if node["kind"] == "result"]:
        call_id = nodes[result_index]["call_id"]
        candidates = calls_by_id.get(call_id, []) if call_id is not None else []
        prior = [index for index in candidates if index < result_index and index not in used_calls]
        if prior:
            call_index = prior[-1]
        elif candidates:
            call_index = candidates[0]
            findings.append({"kind": "result-before-call", "score": 94, "result_index": result_index,
                             "call_index": call_index, "verified": True})
        else:
            fallback = [index for index in range(result_index - 1, -1, -1)
                        if nodes[index]["kind"] == "call" and index not in used_calls]
            call_index = fallback[0] if call_id is None and fallback else None
        if call_index is None:
            findings.append({"kind": "orphan-tool-result", "score": 88, "result_index": result_index,
                             "call_id_present": call_id is not None, "verified": True})
            continue
        used_calls.add(call_index); paired_result[call_index] = result_index
        edges.append({"kind": "call-result", "source": call_index, "target": result_index,
                      "verified": call_id is not None, "inferred_nearest": call_id is None})
        if nodes[result_index]["tool"] and nodes[call_index]["tool"] and nodes[result_index]["tool"] != nodes[call_index]["tool"]:
            findings.append({"kind": "call-result-tool-mismatch", "score": 92,
                             "call_index": call_index, "result_index": result_index,
                             "call_tool": nodes[call_index]["tool"], "result_tool": nodes[result_index]["tool"],
                             "verified": True})

    # Exact leaf propagation from prior results to later call arguments. Values never leave as text.
    result_values: dict[str, list[tuple[int, str]]] = defaultdict(list)
    flow_values = 0
    flow_capped = False
    for index, value in raw_results.items():
        for path, text in _leaves(value) or ():
            if flow_values >= MAX_FLOW_VALUES:
                flow_capped = True
                break
            flow_values += 1
            result_values[hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()].append((index, path))
        if flow_capped:
            break
    for call_index, arguments in raw_args.items():
        for arg_path, text in _leaves(arguments) or ():
            if flow_values >= MAX_FLOW_VALUES:
                flow_capped = True
                break
            flow_values += 1
            digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
            source = next(((index, path) for index, path in reversed(result_values.get(digest, [])) if index < call_index), None)
            if source is None:
                continue
            edges.append({"kind": "value-flow", "source": source[0], "target": call_index,
                          "value_sha256": digest, "value_length": len(text),
                          "source_path": source[1][:256], "target_path": arg_path[:256], "verified": True})
            if len(edges) >= MAX_EDGES:
                break
        if flow_capped or len(edges) >= MAX_EDGES:
            break

    # A result inherits the structural provenance of its call; used later for multi-hop paths.
    for call_index, result_index in paired_result.items():
        edges.append({"kind": "provenance", "source": call_index, "target": result_index,
                      "verified": True})

    if len(edges) > MAX_EDGES:
        edges = edges[:MAX_EDGES]
        findings.append({"kind": "edge-cap-reached", "score": 50, "cap": MAX_EDGES, "verified": True})
    if flow_capped:
        findings.append({"kind": "value-flow-cap-reached", "score": 50,
                         "cap": MAX_FLOW_VALUES, "verified": True})
    safe_approvals = []
    for approval in embedded_approvals:
        safe_approvals.append({"call_id": str(approval.get("call_id"))[:512] if approval.get("call_id") is not None else None,
                               "tool": str(approval.get("tool", ""))[:256] or None,
                               "approved": approval.get("approved", True) is True,
                               "arguments_digest": _digest(approval.get("arguments")) if "arguments" in approval else None})
    return {"nodes": nodes, "edges": edges, "findings": findings[:MAX_FINDINGS],
            "approvals": safe_approvals, "paired_results": paired_result}


def audit_approvals(graph: Mapping[str, Any], *, approvals: Sequence[Mapping[str, Any]] = (),
                    require_approval: bool = False) -> list[dict[str, Any]]:
    """Compare saved approval argument digests with calls; never grants authority itself."""
    embedded = list(graph.get("approvals", ()))
    if not isinstance(approvals, Sequence) or isinstance(approvals, (str, bytes, bytearray)):
        raise ValueError("approvals must be a list")
    if len(embedded) + len(approvals) > MAX_ROWS:
        raise ValueError("approval list exceeds cap")
    approvals = embedded + list(approvals)
    by_id: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for approval in approvals:
        if not isinstance(approval, Mapping):
            raise ValueError("approval must be an object")
        if approval.get("approved", True) is not True:
            continue
        if approval.get("call_id") is not None:
            by_id[str(approval["call_id"])].append(approval)
    findings = []
    for node in graph.get("nodes", []):
        if node.get("kind") != "call":
            continue
        matched = by_id.get(str(node.get("call_id")), []) if node.get("call_id") is not None else []
        if not matched and require_approval:
            findings.append({"kind": "call-without-saved-approval", "score": 82,
                             "call_index": node["index"], "tool": node.get("tool"), "verified": True})
            continue
        for approval in matched:
            approved_tool = str(approval.get("tool", node.get("tool")))
            if approved_tool != node.get("tool"):
                findings.append({"kind": "approval-tool-drift", "score": 94,
                                 "call_index": node["index"], "approved_tool": approved_tool[:256],
                                 "executed_tool": node.get("tool"), "verified": True})
            approved_digest = approval.get("arguments_digest")
            if approved_digest is None and "arguments" in approval:
                approved_digest = _digest(approval["arguments"])
            if approved_digest is not None and approved_digest != node.get("arguments_digest"):
                findings.append({"kind": "approval-argument-drift", "score": 96,
                                 "call_index": node["index"],
                                 "approved_digest": approved_digest,
                                 "executed_digest": node.get("arguments_digest"), "verified": True})
    return findings[:MAX_FINDINGS]


def audit_tool_snapshots(tool_snapshots: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Detect description/schema/server changes across caller-ordered saved tool snapshots."""
    if not isinstance(tool_snapshots, Sequence) or isinstance(tool_snapshots, (str, bytes, bytearray)) \
            or len(tool_snapshots) > MAX_SNAPSHOTS:
        raise ValueError("tool snapshots must be a bounded list")
    previous: dict[str, dict[str, Any]] = {}
    findings = []
    for snapshot_index, snapshot in enumerate(tool_snapshots):
        if not isinstance(snapshot, Mapping):
            raise ValueError("snapshot must be an object")
        tools = snapshot.get("tools", [snapshot])
        if not isinstance(tools, list) or len(tools) > MAX_ROWS:
            raise ValueError("snapshot tools must be a bounded list")
        for tool in tools:
            if not isinstance(tool, Mapping) or not isinstance(tool.get("name"), str):
                continue
            name = tool["name"][:256]
            state = {field: _digest(tool.get(field)) for field in ("description", "schema", "server", "capabilities")}
            if name in previous:
                changed = [field for field in state if state[field] != previous[name][field]]
                if changed:
                    findings.append({"kind": "tool-schema-drift", "score": 86,
                                     "tool": name, "snapshot_index": snapshot_index,
                                     "changed_fields": changed, "before": {field: previous[name][field] for field in changed},
                                     "after": {field: state[field] for field in changed}, "verified": True})
            previous[name] = state
    return findings[:MAX_FINDINGS]


def _delegation_findings(nodes: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    parent, edges, findings = {}, [], []
    for node in nodes:
        agent, ancestor = node.get("agent_id"), node.get("parent_agent_id")
        if agent and ancestor:
            edges.append({"kind": "delegation", "source_agent": ancestor, "target_agent": agent,
                          "event_index": node["index"], "verified": True})
            if agent in parent and parent[agent] != ancestor:
                findings.append({"kind": "agent-parent-drift", "score": 78, "agent_id": agent,
                                 "parents": sorted({parent[agent], ancestor}), "verified": True})
            parent[agent] = ancestor
    for agent in list(parent):
        path, current = [], agent
        while current in parent and current not in path and len(path) <= MAX_DEPTH:
            path.append(current); current = parent[current]
        if current in path:
            cycle = path[path.index(current):] + [current]
            findings.append({"kind": "delegation-cycle", "score": 90, "agents": cycle, "verified": True})
    return edges, findings


def _chains(graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    nodes = graph["nodes"]
    adjacency: dict[int, list[int]] = defaultdict(list)
    for edge in graph["edges"]:
        if edge.get("kind") in {"value-flow", "call-result", "provenance"}:
            adjacency[int(edge["source"])].append(int(edge["target"]))
    sources = [node["index"] for node in nodes if node.get("attack_evidence")]
    # Sensitive-read calls are separate origins for read->egress evidence.
    sensitive = [node["index"] for node in nodes if node.get("kind") == "call" and node.get("sensitive_read_candidate")]
    rows, seen = [], set()
    for origin, family in [(index, "untrusted-source-chain") for index in sources] + \
                          [(index, "sensitive-read-chain") for index in sensitive]:
        queue = deque([(origin, [origin])])
        while queue and len(rows) < MAX_CHAINS:
            current, path = queue.popleft()
            if len(path) > MAX_DEPTH:
                continue
            node = nodes[current]
            actionable = node.get("kind") == "call" and node.get("sinks") and current != origin
            if actionable:
                key = (origin, current, tuple(path))
                if key not in seen:
                    seen.add(key)
                    rows.append({"kind": family, "score": 92 if family == "sensitive-read-chain" else 86,
                                 "source_index": origin, "sink_index": current,
                                 "path": path, "sink_tool": node.get("tool"), "sinks": node.get("sinks"),
                                 "hops": len(path) - 1,
                                 "rationale": "saved structural/value-flow edges connect source and action; causality is not proven"})
            for nxt in adjacency.get(current, []):
                if nxt not in path and nxt >= current:
                    queue.append((nxt, path + [nxt]))
    return rows


def analyze_agentic_chains(value: Any, *, policy: Mapping[str, Any] | None = None,
                           approvals: Sequence[Mapping[str, Any]] = (),
                           tool_snapshots: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Complete saved-trace graph, integrity, authorization, delegation and chain report."""
    policy = {} if policy is None else policy
    if not isinstance(policy, Mapping):
        raise ValueError("policy must be an object")
    graph = build_event_graph(value)
    findings = list(graph["findings"])
    findings += audit_approvals(graph, approvals=approvals,
                                require_approval=policy.get("require_approval") is True)
    findings += audit_tool_snapshots(tool_snapshots)
    enforce_allowed = "allowed_tools" in policy
    allowed_rows = policy.get("allowed_tools", [])
    if not isinstance(allowed_rows, list) or len(allowed_rows) > MAX_ROWS:
        raise ValueError("allowed_tools must be a bounded list")
    allowed = {str(item) for item in allowed_rows}
    for node in graph["nodes"]:
        if enforce_allowed and node.get("kind") == "call" and node.get("tool") not in allowed:
            findings.append({"kind": "tool-outside-saved-policy", "score": 80,
                             "call_index": node["index"], "tool": node.get("tool"), "verified": True})
    delegation_edges, delegation_findings = _delegation_findings(graph["nodes"])
    findings += delegation_findings
    signatures: dict[tuple[str, str], list[int]] = defaultdict(list)
    for node in graph["nodes"]:
        if node.get("kind") == "call":
            signatures[(node.get("tool") or "", node.get("arguments_digest") or "")].append(node["index"])
    for (tool, _digest_value), indexes in signatures.items():
        if len(indexes) >= 3:
            findings.append({"kind": "repeated-call-loop-candidate", "score": 66,
                             "tool": tool, "call_indices": indexes[:256], "count": len(indexes),
                             "verified": True})
    chains = _chains(graph)
    findings.sort(key=lambda row: (-int(row.get("score", 0)), row.get("kind", ""),
                                   int(row.get("call_index", row.get("source_index", 0)))))
    return {"node_count": len(graph["nodes"]), "edge_count": len(graph["edges"]),
            "nodes": graph["nodes"], "edges": graph["edges"],
            "delegation_edges": delegation_edges, "findings": findings[:MAX_FINDINGS],
            "chains": chains, "causality_verified": False, "compromise_verified": False,
            "requires_human_review": True, "artifact_executed": False,
            "network_used": False,
            "note": "trace text is inert data; chains establish saved provenance, not malicious intent"}

