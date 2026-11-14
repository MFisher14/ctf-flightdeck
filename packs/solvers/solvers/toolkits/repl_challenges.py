#!/usr/bin/env python3
"""Offline, replay-checked helpers for saved REPL and quiz transcripts.

No function opens a socket or writes an answer.  Every returned answer is a
candidate carrying an explicit replay check and ``sent=False``.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import heapq
import ipaddress
import json
import math
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence


MAX_TASKS = 1_000
MAX_RPN_TOKENS = 10_000
MAX_RPN_SOURCE_CHARS = 1_000_000
MAX_RPN_TOKEN_CHARS = 3_000
MAX_STACK_ITEMS = 4_096
MAX_MATRIX_DIMENSION = 32
MAX_INTEGER_BITS = 8_192
MAX_RATIONAL_BITS = 16_384
MAX_RATIONAL_TEXT_CHARS = 10_000
MAX_GRAPH_NODES = 10_000
MAX_GRAPH_EDGES = 50_000
MAX_FRAME_BYTES = 4_000_000
MAX_EVENTS = 20_000


class Refuse(ValueError):
    """Malformed input or an explicit offline-analysis bound was reached."""


def _integer(value: Any, *, label: str = "integer") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise Refuse(f"{label} must be an integer")
    if value.bit_length() > MAX_INTEGER_BITS:
        raise Refuse(f"{label} exceeds {MAX_INTEGER_BITS}-bit bound")
    return value


def _bounded_result(value: int) -> int:
    return _integer(value, label="intermediate integer")


def _fraction(value: Any, *, label: str = "rational") -> Fraction:
    if isinstance(value, bool):
        raise Refuse(f"{label} must be an integer or rational")
    if isinstance(value, Fraction):
        result = value
    elif isinstance(value, int):
        result = Fraction(_integer(value, label=label), 1)
    elif isinstance(value, str):
        if len(value) > MAX_RATIONAL_TEXT_CHARS:
            raise Refuse(f"{label} text exceeds bound")
        try:
            result = Fraction(value)
        except (ValueError, ZeroDivisionError) as exc:
            raise Refuse(f"invalid {label}") from exc
    else:
        raise Refuse(f"{label} must be an integer or 'p/q' string")
    if result.numerator.bit_length() > MAX_RATIONAL_BITS or result.denominator.bit_length() > MAX_RATIONAL_BITS:
        raise Refuse(f"{label} exceeds rational bit bound")
    return result


def _candidate(kind: str, answer: Any, *, verified: bool, details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "answer_kind": kind,
        "candidate_answer": answer,
        "candidate_only": True,
        "requires_human_confirmation": True,
        "replay_verified": bool(verified),
        "sent": False,
        "network_used": False,
    }
    if details:
        result.update(details)
    return result


_RPN_BINARY = {"+", "-", "*", "//", "%", "gcd", "lcm", "pow", "min", "max"}
_RPN_UNARY = {"neg", "abs"}


def _rpn_value(tokens: Sequence[str], *, with_trace: bool) -> tuple[int, list[dict[str, Any]]]:
    if not tokens or len(tokens) > MAX_RPN_TOKENS:
        raise Refuse(f"RPN token count must be in 1..{MAX_RPN_TOKENS}")
    stack: list[int] = []
    trace: list[dict[str, Any]] = []
    for offset, token in enumerate(tokens):
        if not isinstance(token, str) or len(token) > MAX_RPN_TOKEN_CHARS:
            raise Refuse("RPN token is not bounded text")
        try:
            value = int(token, 10)
        except ValueError:
            value = None
        if value is not None:
            stack.append(_integer(value, label="RPN literal"))
        elif token in _RPN_UNARY:
            if not stack:
                raise Refuse(f"RPN stack underflow at token {offset}")
            operand = stack.pop()
            stack.append(_bounded_result(-operand if token == "neg" else abs(operand)))
        elif token in _RPN_BINARY:
            if len(stack) < 2:
                raise Refuse(f"RPN stack underflow at token {offset}")
            right = stack.pop()
            left = stack.pop()
            if token == "+":
                result = left + right
            elif token == "-":
                result = left - right
            elif token == "*":
                result = left * right
            elif token == "//":
                if right == 0:
                    raise Refuse("RPN division by zero")
                result = left // right
            elif token == "%":
                if right == 0:
                    raise Refuse("RPN modulo by zero")
                result = left % right
            elif token == "gcd":
                result = math.gcd(left, right)
            elif token == "lcm":
                result = math.lcm(left, right)
            elif token == "pow":
                if right < 0 or right > MAX_INTEGER_BITS:
                    raise Refuse("RPN exponent outside bounded nonnegative range")
                result = pow(left, right)
            elif token == "min":
                result = min(left, right)
            else:
                result = max(left, right)
            stack.append(_bounded_result(result))
        else:
            raise Refuse(f"unsupported RPN token {token!r}")
        if len(stack) > MAX_STACK_ITEMS:
            raise Refuse("RPN stack exceeds bound")
        if with_trace and len(trace) < 2_048:
            trace.append({
                "offset": offset,
                "token": token,
                "stack_depth": len(stack),
                "stack_top_preview": list(stack[-16:]),
            })
    if len(stack) != 1:
        raise Refuse(f"RPN expression leaves {len(stack)} stack values")
    return stack[0], trace


def solve_rpn(expression: str | Sequence[str]) -> dict[str, Any]:
    if isinstance(expression, str):
        if len(expression) > MAX_RPN_SOURCE_CHARS:
            raise Refuse("RPN source exceeds text bound")
        tokens = expression.split()
    elif isinstance(expression, Sequence) and not isinstance(expression, (bytes, bytearray)):
        if len(expression) > MAX_RPN_TOKENS:
            raise Refuse("RPN token count exceeds bound")
        if not all(isinstance(token, str) for token in expression):
            raise Refuse("RPN sequence tokens must be strings")
        tokens = list(expression)
    else:
        raise Refuse("RPN expression must be text or a token sequence")
    answer, trace = _rpn_value(tokens, with_trace=True)
    replay, _ = _rpn_value(tokens, with_trace=False)
    return _candidate("rpn_integer", answer, verified=replay == answer, details={"tokens": tokens, "trace": trace})


def _integer_matrix(matrix: Sequence[Sequence[Any]], *, square: bool = True) -> list[list[int]]:
    if not isinstance(matrix, Sequence) or isinstance(matrix, (str, bytes, bytearray)):
        raise Refuse("matrix must be a sequence of rows")
    if not matrix or len(matrix) > MAX_MATRIX_DIMENSION:
        raise Refuse(f"matrix row count must be in 1..{MAX_MATRIX_DIMENSION}")
    rows: list[list[Any]] = []
    for row in matrix:
        if not isinstance(row, Sequence) or isinstance(row, (str, bytes, bytearray)):
            raise Refuse("matrix rows must be bounded sequences")
        if not 1 <= len(row) <= MAX_MATRIX_DIMENSION:
            raise Refuse("matrix row width exceeds bound")
        rows.append(list(row))
    width = len(rows[0])
    if width < 1 or width > MAX_MATRIX_DIMENSION or any(len(row) != width for row in rows):
        raise Refuse("matrix must be nonempty and rectangular within bounds")
    if square and width != len(rows):
        raise Refuse("matrix must be square")
    return [[_integer(value, label="matrix entry") for value in row] for row in rows]


def _det_mod(matrix: Sequence[Sequence[int]], prime: int) -> int:
    work = [[value % prime for value in row] for row in matrix]
    determinant = 1
    for column in range(len(work)):
        pivot = next((row for row in range(column, len(work)) if work[row][column]), None)
        if pivot is None:
            return 0
        if pivot != column:
            work[pivot], work[column] = work[column], work[pivot]
            determinant = -determinant
        pivot_value = work[column][column]
        determinant = determinant * pivot_value % prime
        inverse = pow(pivot_value, prime - 2, prime)
        for row in range(column + 1, len(work)):
            factor = work[row][column] * inverse % prime
            for index in range(column, len(work)):
                work[row][index] = (work[row][index] - factor * work[column][index]) % prime
    return determinant % prime


def bareiss_determinant(matrix: Sequence[Sequence[Any]]) -> dict[str, Any]:
    original = _integer_matrix(matrix)
    work = [row[:] for row in original]
    size = len(work)
    sign = 1
    previous = 1
    if size == 1:
        answer = work[0][0]
    else:
        for column in range(size - 1):
            pivot_row = next((row for row in range(column, size) if work[row][column] != 0), None)
            if pivot_row is None:
                answer = 0
                break
            if pivot_row != column:
                work[pivot_row], work[column] = work[column], work[pivot_row]
                sign *= -1
            pivot = work[column][column]
            for row in range(column + 1, size):
                for index in range(column + 1, size):
                    numerator = work[row][index] * pivot - work[row][column] * work[column][index]
                    if column and numerator % previous:
                        raise Refuse("non-exact Bareiss division; malformed integer state")
                    work[row][index] = _bounded_result(numerator // previous)
                work[row][column] = 0
            previous = pivot
        else:
            answer = sign * work[-1][-1]
        answer = _bounded_result(answer)
    primes = (1_000_000_007, 1_000_000_009)
    residues = {str(prime): _det_mod(original, prime) for prime in primes}
    verified = all(answer % prime == residues[str(prime)] for prime in primes)
    return _candidate(
        "determinant", answer, verified=verified,
        details={"dimension": size, "verification_residues": residues, "algorithm": "fraction-free Bareiss"},
    )


def solve_rational_system(matrix: Sequence[Sequence[Any]], vector: Sequence[Any]) -> dict[str, Any]:
    if not isinstance(matrix, Sequence) or isinstance(matrix, (str, bytes, bytearray)):
        raise Refuse("coefficient matrix must be a sequence")
    if not matrix or len(matrix) > MAX_MATRIX_DIMENSION:
        raise Refuse("rational system must have a bounded square coefficient matrix")
    rows: list[list[Any]] = []
    for row in matrix:
        if not isinstance(row, Sequence) or isinstance(row, (str, bytes, bytearray)):
            raise Refuse("coefficient rows must be bounded sequences")
        if len(row) != len(matrix):
            raise Refuse("rational system must have a bounded square coefficient matrix")
        rows.append(list(row))
    if not isinstance(vector, Sequence) or isinstance(vector, (str, bytes, bytearray)) or len(vector) != len(rows):
        raise Refuse("right-hand vector length must match the matrix")
    coefficients = [[_fraction(value, label="coefficient") for value in row] for row in rows]
    right = [_fraction(value, label="right-hand value") for value in vector]
    augmented = [row[:] + [right[index]] for index, row in enumerate(coefficients)]
    size = len(augmented)

    def check(value: Fraction) -> Fraction:
        return _fraction(value, label="rational elimination intermediate")

    for column in range(size):
        pivot_row = next((row for row in range(column, size) if augmented[row][column]), None)
        if pivot_row is None:
            inconsistent = any(
                all(value == 0 for value in augmented[row][:-1]) and augmented[row][-1] != 0
                for row in range(size)
            )
            raise Refuse("inconsistent rational system" if inconsistent else "rational system is not uniquely solvable")
        if pivot_row != column:
            augmented[pivot_row], augmented[column] = augmented[column], augmented[pivot_row]
        pivot = augmented[column][column]
        augmented[column] = [check(value / pivot) for value in augmented[column]]
        for row in range(size):
            if row == column or augmented[row][column] == 0:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                check(value - factor * pivot_value)
                for value, pivot_value in zip(augmented[row], augmented[column])
            ]
    solution = [augmented[index][-1] for index in range(size)]
    verified = all(
        sum((coefficient * value for coefficient, value in zip(row, solution)), Fraction(0)) == expected
        for row, expected in zip(coefficients, right)
    )
    return _candidate(
        "rational_vector",
        [str(value) for value in solution],
        verified=verified,
        details={"dimension": size, "exact": True},
    )


def _node(value: Any) -> str | int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Refuse("graph nodes must be strings or integers")
    if isinstance(value, str) and len(value) > 1_024:
        raise Refuse("graph node label exceeds bound")
    if isinstance(value, int):
        _integer(value, label="graph node")
    return value


def _node_key(value: str | int) -> tuple[str, str]:
    return type(value).__name__, repr(value)


def _weighted_graph(graph: Mapping[Any, Mapping[Any, Any]]) -> dict[str | int, dict[str | int, int]]:
    if not isinstance(graph, Mapping):
        raise Refuse("graph must map nodes to neighbor-weight mappings")
    result: dict[str | int, dict[str | int, int]] = {}
    edge_count = 0
    for raw_node, raw_neighbors in graph.items():
        node = _node(raw_node)
        if not isinstance(raw_neighbors, Mapping):
            raise Refuse("each graph adjacency value must be a mapping")
        result.setdefault(node, {})
        for raw_neighbor, raw_weight in raw_neighbors.items():
            neighbor = _node(raw_neighbor)
            weight = _integer(raw_weight, label="edge weight")
            if weight < 0:
                raise Refuse("shortest-path graph cannot contain negative weights")
            result[node][neighbor] = weight
            result.setdefault(neighbor, {})
            edge_count += 1
            if edge_count > MAX_GRAPH_EDGES:
                raise Refuse("graph edge bound exceeded")
        if len(result) > MAX_GRAPH_NODES:
            raise Refuse("graph node bound exceeded")
    return result


def shortest_path(graph: Mapping[Any, Mapping[Any, Any]], start: Any, end: Any) -> dict[str, Any]:
    adjacency = _weighted_graph(graph)
    source, target = _node(start), _node(end)
    if source not in adjacency or target not in adjacency:
        raise Refuse("shortest-path endpoint is absent from graph")
    distances: dict[str | int, int] = {source: 0}
    previous: dict[str | int, str | int] = {}
    heap: list[tuple[int, tuple[str, str], str | int]] = [(0, _node_key(source), source)]
    settled: set[str | int] = set()
    while heap:
        distance, _, node = heapq.heappop(heap)
        if node in settled or distance != distances.get(node):
            continue
        settled.add(node)
        if node == target:
            break
        for neighbor, weight in sorted(adjacency[node].items(), key=lambda item: _node_key(item[0])):
            candidate = _bounded_result(distance + weight)
            if candidate < distances.get(neighbor, candidate + 1):
                distances[neighbor] = candidate
                previous[neighbor] = node
                heapq.heappush(heap, (candidate, _node_key(neighbor), neighbor))
    if target not in distances:
        raise Refuse("target is unreachable")
    path: list[str | int] = [target]
    while path[-1] != source:
        path.append(previous[path[-1]])
    path.reverse()
    replay_distance = sum(adjacency[left][right] for left, right in zip(path, path[1:]))
    return _candidate(
        "shortest_path",
        {"distance": distances[target], "path": path},
        verified=replay_distance == distances[target] and path[0] == source and path[-1] == target,
        details={"settled_nodes": len(settled)},
    )


def topological_order(edges: Sequence[Sequence[Any]], *, nodes: Sequence[Any] = ()) -> dict[str, Any]:
    if not isinstance(edges, Sequence) or isinstance(edges, (str, bytes, bytearray)):
        raise Refuse("edges must be a sequence of pairs")
    if len(edges) > MAX_GRAPH_EDGES:
        raise Refuse("graph edge bound exceeded")
    if not isinstance(nodes, Sequence) or isinstance(nodes, (str, bytes, bytearray)):
        raise Refuse("nodes must be a bounded sequence")
    if len(nodes) > MAX_GRAPH_NODES:
        raise Refuse("graph node bound exceeded")
    all_nodes = {_node(value) for value in nodes}
    adjacency: dict[str | int, set[str | int]] = {}
    indegree: dict[str | int, int] = {}
    normalized_edges: set[tuple[str | int, str | int]] = set()
    for raw_edge in edges:
        if not isinstance(raw_edge, Sequence) or isinstance(raw_edge, (str, bytes, bytearray)) or len(raw_edge) != 2:
            raise Refuse("each topological edge must contain exactly two nodes")
        left, right = _node(raw_edge[0]), _node(raw_edge[1])
        all_nodes.update((left, right))
        normalized_edges.add((left, right))
    if len(all_nodes) > MAX_GRAPH_NODES:
        raise Refuse("graph node bound exceeded")
    for node in all_nodes:
        adjacency[node] = set()
        indegree[node] = 0
    for left, right in normalized_edges:
        if right not in adjacency[left]:
            adjacency[left].add(right)
            indegree[right] += 1
    ready = [(_node_key(node), node) for node in all_nodes if indegree[node] == 0]
    heapq.heapify(ready)
    order: list[str | int] = []
    unique = True
    while ready:
        if len(ready) != 1:
            unique = False
        _, node = heapq.heappop(ready)
        order.append(node)
        for neighbor in sorted(adjacency[node], key=_node_key):
            indegree[neighbor] -= 1
            if indegree[neighbor] == 0:
                heapq.heappush(ready, (_node_key(neighbor), neighbor))
    if len(order) != len(all_nodes):
        remaining = sorted((node for node in all_nodes if indegree[node] > 0), key=_node_key)
        return _candidate(
            "topological_order", None, verified=False,
            details={"cycle_detected": True, "remaining_nodes": remaining, "unique": False},
        )
    positions = {node: index for index, node in enumerate(order)}
    verified = all(positions[left] < positions[right] for left, right in normalized_edges)
    return _candidate(
        "topological_order", order, verified=verified,
        details={"cycle_detected": False, "unique": unique},
    )


def subnet_report(cidr: str, *, address: str | None = None) -> dict[str, Any]:
    if not isinstance(cidr, str) or len(cidr) > 256:
        raise Refuse("CIDR must be bounded text")
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise Refuse("invalid CIDR") from exc
    checked_address = None
    contains = None
    if address is not None:
        if not isinstance(address, str) or len(address) > 128:
            raise Refuse("address must be bounded text")
        try:
            checked_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise Refuse("invalid address") from exc
        contains = checked_address.version == network.version and checked_address in network

    total = network.num_addresses
    if network.version == 4 and network.prefixlen <= 30:
        first_host = network.network_address + 1
        last_host = network.broadcast_address - 1
        usable = total - 2
        convention = "exclude IPv4 network and broadcast addresses"
    else:
        first_host = network.network_address
        last_host = network.broadcast_address
        usable = total
        convention = "all addresses (IPv4 /31-/32 or IPv6; policy may differ)"
    answer = {
        "network": str(network.network_address),
        "broadcast_or_last": str(network.broadcast_address),
        "prefix_length": network.prefixlen,
        "netmask": str(network.netmask),
        "hostmask": str(network.hostmask),
        "total_addresses": total,
        "first_host": str(first_host),
        "last_host": str(last_host),
        "usable_addresses": usable,
        "address": str(checked_address) if checked_address is not None else None,
        "address_in_network": contains,
    }
    replay = ipaddress.ip_network(f"{answer['network']}/{answer['prefix_length']}", strict=True)
    return _candidate(
        "subnet",
        answer,
        verified=replay == network,
        details={"host_range_convention": convention},
    )


def weekday(iso_date: str) -> dict[str, Any]:
    if not isinstance(iso_date, str) or len(iso_date) != 10:
        raise Refuse("date must be ISO YYYY-MM-DD")
    try:
        value = _datetime.date.fromisoformat(iso_date)
    except ValueError as exc:
        raise Refuse("invalid ISO date") from exc
    # Independent ordinal relation: 0001-01-01 was Monday.
    replay_index = (value.toordinal() - 1) % 7
    answer = {"weekday": value.strftime("%A"), "iso_weekday": value.isoweekday()}
    return _candidate(
        "weekday", answer,
        verified=replay_index + 1 == value.isoweekday(),
        details={"date": iso_date},
    )


def _bytes(value: bytes | bytearray | str, *, label: str = "payload") -> bytes:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        encoded = bytes(value)
    else:
        raise Refuse(f"{label} must be bytes or text")
    if len(encoded) > MAX_FRAME_BYTES:
        raise Refuse(f"{label} exceeds byte bound")
    return encoded


def _parse_netstrings(data: bytes) -> tuple[list[bytes], bool]:
    frames: list[bytes] = []
    cursor = 0
    while cursor < len(data):
        colon = data.find(b":", cursor, min(len(data), cursor + 12))
        if colon < 0:
            return frames, False
        raw_length = data[cursor:colon]
        if not raw_length or len(raw_length) > 10 or not raw_length.isdigit():
            return frames, False
        if len(raw_length) > 1 and raw_length.startswith(b"0"):
            return frames, False
        length = int(raw_length)
        end = colon + 1 + length
        if length > MAX_FRAME_BYTES or end >= len(data) or data[end : end + 1] != b",":
            return frames, False
        frames.append(data[colon + 1 : end])
        cursor = end + 1
    return frames, cursor == len(data)


def _parse_length_prefix(data: bytes, width: int, byteorder: str) -> tuple[list[bytes], bool]:
    frames: list[bytes] = []
    cursor = 0
    while cursor < len(data):
        if cursor + width > len(data):
            return frames, False
        length = int.from_bytes(data[cursor : cursor + width], byteorder)
        cursor += width
        if length > MAX_FRAME_BYTES or cursor + length > len(data):
            return frames, False
        frames.append(data[cursor : cursor + length])
        cursor += length
    return frames, cursor == len(data)


def analyze_framing(payload: bytes | bytearray | str) -> dict[str, Any]:
    data = _bytes(payload)
    candidates: list[dict[str, Any]] = []
    if data:
        newline_frames = data.splitlines()
        newline_complete = data.endswith((b"\n", b"\r"))
        if len(newline_frames) >= 2 or newline_complete:
            candidates.append({
                "framing": "newline",
                "complete": newline_complete,
                "frame_count": len(newline_frames),
            })
            json_ok = True
            for frame in newline_frames:
                if not frame.strip():
                    continue
                try:
                    json.loads(frame)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    json_ok = False
                    break
            if json_ok and newline_frames:
                candidates.append({
                    "framing": "json-lines",
                    "complete": newline_complete,
                    "frame_count": len(newline_frames),
                })
        netstrings, complete = _parse_netstrings(data)
        if netstrings:
            candidates.append({"framing": "netstring", "complete": complete, "frame_count": len(netstrings)})
        for width in (2, 4):
            for byteorder in ("big", "little"):
                frames, complete = _parse_length_prefix(data, width, byteorder)
                if frames and complete:
                    candidates.append({
                        "framing": f"uint{width * 8}-{byteorder}-length-prefix",
                        "complete": True,
                        "frame_count": len(frames),
                    })
    candidates.sort(key=lambda row: (not row["complete"], -row["frame_count"], row["framing"]))
    return {
        "candidates": candidates,
        "payload_bytes": len(data),
        "candidate_only": True,
        "requires_human_confirmation": True,
        "sent": False,
        "network_used": False,
    }


def analyze_saved_session(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes, bytearray)):
        raise Refuse("events must be a saved sequence")
    if len(events) > MAX_EVENTS:
        raise Refuse("saved event count exceeds bound")
    normalized: list[dict[str, Any]] = []
    total_bytes = 0
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise Refuse("each session event must be a mapping")
        direction = event.get("direction")
        if direction not in {"recv", "send"}:
            raise Refuse("event direction must be 'recv' or 'send'")
        data = _bytes(event.get("data", b""), label="event data")
        total_bytes += len(data)
        if total_bytes > MAX_FRAME_BYTES:
            raise Refuse("saved session exceeds byte bound")
        text = data.decode("utf-8", errors="replace")
        normalized.append({"index": index, "direction": direction, "data": data, "text": text})

    echoes: list[dict[str, int]] = []
    for index, event in enumerate(normalized):
        if event["direction"] != "send" or not event["data"]:
            continue
        for later in normalized[index + 1 :]:
            if later["direction"] == "send":
                break
            if event["data"].strip() and event["data"].strip() in later["data"]:
                echoes.append({"send_event": index, "recv_event": later["index"]})
                break

    recv_prompts = [event["text"].strip() for event in normalized if event["direction"] == "recv"]
    prompt_counts = {prompt: count for prompt, count in Counter(recv_prompts).items() if prompt and count > 1}
    lower = "\n".join(recv_prompts).casefold()
    retry_markers = [marker for marker in ("retry", "try again", "again", "incorrect", "wrong") if marker in lower]
    acceptance_markers = [
        marker for marker in ("accepted", "correct", "success", "congratulations", "flag{") if marker in lower
    ]
    rejection_markers = [marker for marker in ("rejected", "incorrect", "wrong", "failed") if marker in lower]
    if acceptance_markers and not rejection_markers:
        final_state = "acceptance_evidence"
    elif rejection_markers and not acceptance_markers:
        final_state = "rejection_evidence"
    elif acceptance_markers or rejection_markers:
        final_state = "mixed_markers"
    else:
        final_state = "unknown"
    raw = b"".join(event["data"] for event in normalized)
    return {
        "event_count": len(normalized),
        "total_bytes": total_bytes,
        "echo_pairs": echoes,
        "repeated_prompts": prompt_counts,
        "retry_markers": retry_markers,
        "acceptance_markers": acceptance_markers,
        "rejection_markers": rejection_markers,
        "final_state_candidate": final_state,
        "framing": analyze_framing(raw),
        "candidate_only": True,
        "requires_human_confirmation": True,
        "sent": False,
        "network_used": False,
    }


def solve_saved_task(task: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(task, Mapping):
        raise Refuse("saved task must be a mapping")
    kind = task.get("type")
    if kind == "rpn":
        result = solve_rpn(task.get("expression", ""))
    elif kind == "determinant":
        result = bareiss_determinant(task.get("matrix", ()))
    elif kind == "linear_system":
        result = solve_rational_system(task.get("matrix", ()), task.get("vector", ()))
    elif kind == "shortest_path":
        result = shortest_path(task.get("graph", {}), task.get("start"), task.get("end"))
    elif kind == "topological":
        result = topological_order(task.get("edges", ()), nodes=task.get("nodes", ()))
    elif kind == "subnet":
        result = subnet_report(task.get("cidr", ""), address=task.get("address"))
    elif kind == "weekday":
        result = weekday(task.get("date", ""))
    else:
        raise Refuse(f"unsupported saved task type {kind!r}")
    result["task_type"] = kind
    # This invariant is intentionally checked at the dispatch boundary so a
    # future helper cannot accidentally become a live quiz driver.
    if result.get("sent") is not False or result.get("network_used") is not False:
        raise Refuse("offline task invariant violated")
    return result


def build_quiz_replay(tasks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not isinstance(tasks, Sequence) or isinstance(tasks, (str, bytes, bytearray)):
        raise Refuse("tasks must be a saved sequence")
    if len(tasks) > MAX_TASKS:
        raise Refuse("saved task count exceeds bound")
    results = [solve_saved_task(task) for task in tasks]
    actions: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        if result["candidate_answer"] is None or not result["replay_verified"]:
            continue
        actions.append({
            "task_index": index,
            "would_send": json.dumps(result["candidate_answer"], sort_keys=True, ensure_ascii=False),
            "sent": False,
            "replay_verified": True,
        })
    return {
        "results": results,
        "actions": actions,
        "all_replay_verified": all(result["replay_verified"] for result in results),
        "sent": False,
        "network_used": False,
        "requires_human_confirmation": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="JSON file containing one task, task list, or event list")
    parser.add_argument("--events", action="store_true", help="interpret JSON as saved session events")
    args = parser.parse_args(argv)
    value = json.loads(Path(args.path).read_text(encoding="utf-8"))
    if args.events:
        result = analyze_saved_session(value)
    elif isinstance(value, list):
        result = build_quiz_replay(value)
    else:
        result = solve_saved_task(value)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "Refuse",
    "analyze_framing",
    "analyze_saved_session",
    "bareiss_determinant",
    "build_quiz_replay",
    "shortest_path",
    "solve_rational_system",
    "solve_rpn",
    "solve_saved_task",
    "subnet_report",
    "topological_order",
    "weekday",
]
