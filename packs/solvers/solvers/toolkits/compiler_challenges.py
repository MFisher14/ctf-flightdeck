#!/usr/bin/env python3
"""Bounded static helpers for grammar, compiler, and toy-VM challenges.

The module accepts already-supplied grammar/IR/trace data.  It contains no
bytecode parser and never executes target instructions or host code.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Mapping, Sequence


EPSILON = "ε"
END_MARKER = "$"
MAX_NONTERMINALS = 256
MAX_PRODUCTIONS = 4_096
MAX_RHS_SYMBOLS = 256
MAX_SYMBOL_CHARS = 256
MAX_IR_INSTRUCTIONS = 20_000
MAX_CFG_EDGES = 50_000
MAX_STACK_HEIGHT = 100_000
MAX_HEIGHTS_PER_NODE = 64
MAX_STACK_STATES = 200_000
MAX_TRACES = 20_000
MAX_TRACE_STACK = 2_048
MAX_INTEGER_BITS = 8_192


class Refuse(ValueError):
    """Malformed data or an explicit analysis bound was reached."""


def _symbol(value: Any, *, label: str = "symbol") -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_SYMBOL_CHARS:
        raise Refuse(f"{label} must be nonempty bounded text")
    if value == END_MARKER:
        raise Refuse(f"{END_MARKER!r} is reserved for the end marker")
    return value


def _normalize_grammar(
    grammar: Mapping[str, Sequence[Sequence[str]]], start: str
) -> tuple[dict[str, list[tuple[str, ...]]], set[str]]:
    if not isinstance(grammar, Mapping) or not grammar or len(grammar) > MAX_NONTERMINALS:
        raise Refuse("grammar must be a bounded nonempty mapping")
    start = _symbol(start, label="start symbol")
    nonterminals = {_symbol(value, label="nonterminal") for value in grammar}
    if start not in nonterminals:
        raise Refuse("start symbol is not a grammar nonterminal")
    normalized: dict[str, list[tuple[str, ...]]] = {}
    production_count = 0
    for nonterminal, raw_alternatives in grammar.items():
        if not isinstance(raw_alternatives, Sequence) or isinstance(raw_alternatives, (str, bytes, bytearray)):
            raise Refuse("each nonterminal must map to a sequence of alternatives")
        if not raw_alternatives:
            raise Refuse("each nonterminal needs at least one production")
        alternatives: list[tuple[str, ...]] = []
        for raw_rhs in raw_alternatives:
            if not isinstance(raw_rhs, Sequence) or isinstance(raw_rhs, (str, bytes, bytearray)):
                raise Refuse("each production must be a symbol sequence, not a string")
            if len(raw_rhs) > MAX_RHS_SYMBOLS:
                raise Refuse("production right-hand side exceeds bound")
            rhs = tuple(_symbol(value, label="production symbol") for value in raw_rhs)
            if EPSILON in rhs:
                if rhs != (EPSILON,):
                    raise Refuse("epsilon must be the sole symbol in a production")
                rhs = ()
            alternatives.append(rhs)
            production_count += 1
            if production_count > MAX_PRODUCTIONS:
                raise Refuse("grammar production bound exceeded")
        normalized[nonterminal] = alternatives
    terminals = {
        symbol
        for alternatives in normalized.values()
        for rhs in alternatives
        for symbol in rhs
        if symbol not in nonterminals
    }
    if EPSILON in terminals:
        raise Refuse("epsilon cannot be a terminal")
    return normalized, terminals


def _first_sequence(
    rhs: Sequence[str],
    first: Mapping[str, set[str]],
    nullable: set[str],
    nonterminals: set[str],
) -> set[str]:
    if not rhs:
        return {EPSILON}
    result: set[str] = set()
    for symbol in rhs:
        if symbol in nonterminals:
            result.update(first[symbol] - {EPSILON})
            if symbol not in nullable:
                break
        else:
            result.add(symbol)
            break
    else:
        result.add(EPSILON)
    return result


def analyze_grammar(
    grammar: Mapping[str, Sequence[Sequence[str]]], *, start: str
) -> dict[str, Any]:
    """Compute nullable, FIRST, FOLLOW, and LL(1) table conflicts."""

    productions, terminals = _normalize_grammar(grammar, start)
    nonterminals = set(productions)
    nullable: set[str] = set()
    changed = True
    while changed:
        changed = False
        for left, alternatives in productions.items():
            if left in nullable:
                continue
            if any(not rhs or all(symbol in nullable for symbol in rhs) for rhs in alternatives):
                nullable.add(left)
                changed = True

    first: dict[str, set[str]] = {nonterminal: set() for nonterminal in nonterminals}
    changed = True
    while changed:
        changed = False
        for left, alternatives in productions.items():
            before = len(first[left])
            for rhs in alternatives:
                first[left].update(_first_sequence(rhs, first, nullable, nonterminals))
            changed |= len(first[left]) != before

    follow: dict[str, set[str]] = {nonterminal: set() for nonterminal in nonterminals}
    follow[start].add(END_MARKER)
    changed = True
    while changed:
        changed = False
        for left, alternatives in productions.items():
            for rhs in alternatives:
                trailer = set(follow[left])
                for symbol in reversed(rhs):
                    if symbol in nonterminals:
                        before = len(follow[symbol])
                        follow[symbol].update(trailer)
                        changed |= len(follow[symbol]) != before
                        if symbol in nullable:
                            trailer.update(first[symbol] - {EPSILON})
                        else:
                            trailer = set(first[symbol] - {EPSILON})
                    else:
                        trailer = {symbol}

    table: defaultdict[tuple[str, str], list[int]] = defaultdict(list)
    production_rows: list[dict[str, Any]] = []
    production_id = 0
    for left, alternatives in productions.items():
        for rhs in alternatives:
            prediction = _first_sequence(rhs, first, nullable, nonterminals)
            lookaheads = prediction - {EPSILON}
            if EPSILON in prediction:
                lookaheads.update(follow[left])
            for lookahead in lookaheads:
                table[(left, lookahead)].append(production_id)
            production_rows.append({
                "id": production_id,
                "left": left,
                "right": list(rhs),
                "predict": sorted(lookaheads),
            })
            production_id += 1
    conflicts = [
        {"nonterminal": left, "lookahead": lookahead, "production_ids": ids}
        for (left, lookahead), ids in table.items()
        if len(ids) > 1
    ]
    conflicts.sort(key=lambda row: (row["nonterminal"], row["lookahead"]))
    return {
        "start": start,
        "nonterminals": sorted(nonterminals),
        "terminals": sorted(terminals),
        "nullable": sorted(nullable),
        "first": {key: sorted(value) for key, value in sorted(first.items())},
        "follow": {key: sorted(value) for key, value in sorted(follow.items())},
        "productions": production_rows,
        "ll1_conflicts": conflicts,
        "is_ll1": not conflicts,
        "candidate_only": True,
        "requires_human_confirmation": True,
    }


def _bounded_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise Refuse(f"{label} must be an integer")
    if value.bit_length() > MAX_INTEGER_BITS:
        raise Refuse(f"{label} exceeds integer bit bound")
    return value


def analyze_stack_cfg(
    ir: Sequence[Mapping[str, Any]],
    *,
    entry: int | None = None,
    initial_height: int = 0,
) -> dict[str, Any]:
    """Build a CFG and propagate stack heights over caller-supplied IR."""

    if not isinstance(ir, Sequence) or isinstance(ir, (str, bytes, bytearray)):
        raise Refuse("IR must be a supplied instruction sequence")
    if not ir or len(ir) > MAX_IR_INSTRUCTIONS:
        raise Refuse(f"IR instruction count must be in 1..{MAX_IR_INSTRUCTIONS}")
    initial_height = _bounded_integer(initial_height, label="initial stack height")
    if not 0 <= initial_height <= MAX_STACK_HEIGHT:
        raise Refuse("initial stack height outside bound")

    instructions: list[dict[str, Any]] = []
    by_offset: dict[int, dict[str, Any]] = {}
    allowed_flows = {"fallthrough", "jump", "branch", "switch", "return", "halt", "throw"}
    for index, raw in enumerate(ir):
        if not isinstance(raw, Mapping):
            raise Refuse("each IR instruction must be a mapping")
        offset = _bounded_integer(raw.get("offset"), label="instruction offset")
        if offset in by_offset:
            raise Refuse(f"duplicate IR offset {offset}")
        pop = _bounded_integer(raw.get("pop", 0), label="stack pop count")
        push = _bounded_integer(raw.get("push", 0), label="stack push count")
        if not 0 <= pop <= MAX_STACK_HEIGHT or not 0 <= push <= MAX_STACK_HEIGHT:
            raise Refuse("stack effect outside bound")
        flow = raw.get("flow", "fallthrough")
        if flow not in allowed_flows:
            raise Refuse(f"unsupported IR flow {flow!r}")
        raw_targets = raw.get("targets")
        if raw_targets is None and "target" in raw:
            raw_targets = [raw["target"]]
        if raw_targets is None:
            raw_targets = []
        if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes, bytearray)):
            raise Refuse("IR targets must be a bounded sequence")
        if len(raw_targets) > 256:
            raise Refuse("IR target list exceeds bound")
        targets = [_bounded_integer(value, label="branch target") for value in raw_targets]
        if flow == "jump" and len(targets) != 1:
            raise Refuse("jump instruction needs exactly one target")
        if flow in {"branch", "switch"} and not targets:
            raise Refuse(f"{flow} instruction needs at least one target")
        if flow in {"fallthrough", "return", "halt", "throw"} and targets:
            raise Refuse(f"{flow} instruction cannot carry targets")
        semantic = raw.get("semantic", raw.get("opcode", "unknown"))
        if not isinstance(semantic, (str, int)) or (isinstance(semantic, str) and len(semantic) > MAX_SYMBOL_CHARS):
            raise Refuse("IR semantic/opcode must be bounded text or integer")
        instruction = {
            "index": index,
            "offset": offset,
            "semantic": semantic,
            "pop": pop,
            "push": push,
            "flow": flow,
            "targets": targets,
        }
        instructions.append(instruction)
        by_offset[offset] = instruction

    if entry is None:
        entry = instructions[0]["offset"]
    entry = _bounded_integer(entry, label="entry offset")
    if entry not in by_offset:
        raise Refuse("entry offset is absent from IR")
    known_offsets = set(by_offset)
    for instruction in instructions:
        missing = set(instruction["targets"]) - known_offsets
        if missing:
            raise Refuse(f"IR branch target(s) absent: {sorted(missing)}")

    successors: dict[int, list[int]] = {}
    edge_count = 0
    for index, instruction in enumerate(instructions):
        next_offset = instructions[index + 1]["offset"] if index + 1 < len(instructions) else None
        flow = instruction["flow"]
        if flow == "fallthrough":
            outgoing = [] if next_offset is None else [next_offset]
        elif flow == "branch":
            outgoing = list(instruction["targets"])
            if next_offset is not None:
                outgoing.append(next_offset)
        elif flow in {"jump", "switch"}:
            outgoing = list(instruction["targets"])
        else:
            outgoing = []
        outgoing = list(dict.fromkeys(outgoing))
        successors[instruction["offset"]] = outgoing
        edge_count += len(outgoing)
        if edge_count > MAX_CFG_EDGES:
            raise Refuse("CFG edge bound exceeded")

    heights: dict[int, set[int]] = {offset: set() for offset in known_offsets}
    heights[entry].add(initial_height)
    queue: deque[tuple[int, int]] = deque([(entry, initial_height)])
    underflows: set[tuple[int, int, int]] = set()
    explosions: set[int] = set()
    state_count = 0
    while queue:
        offset, height = queue.popleft()
        state_count += 1
        if state_count > MAX_STACK_STATES:
            raise Refuse("CFG stack-state bound exceeded")
        instruction = by_offset[offset]
        if height < instruction["pop"]:
            underflows.add((offset, height, instruction["pop"]))
            continue
        after = height - instruction["pop"] + instruction["push"]
        if after > MAX_STACK_HEIGHT:
            explosions.add(offset)
            continue
        for successor in successors[offset]:
            if after in heights[successor]:
                continue
            if len(heights[successor]) >= MAX_HEIGHTS_PER_NODE:
                explosions.add(successor)
                continue
            heights[successor].add(after)
            queue.append((successor, after))

    reachable = {offset for offset, values in heights.items() if values}
    inconsistent = [
        {"offset": offset, "incoming_heights": sorted(values)}
        for offset, values in heights.items()
        if len(values) > 1
    ]
    inconsistent.sort(key=lambda row: row["offset"])
    underflow_rows = [
        {"offset": offset, "incoming_height": height, "required_pop": required}
        for offset, height, required in sorted(underflows)
    ]

    leaders = {entry}
    for index, instruction in enumerate(instructions):
        leaders.update(instruction["targets"])
        if instruction["flow"] != "fallthrough" and index + 1 < len(instructions):
            leaders.add(instructions[index + 1]["offset"])
    return {
        "entry": entry,
        "cfg_edges": [
            {"from": source, "to": target}
            for source in [instruction["offset"] for instruction in instructions]
            for target in successors[source]
        ],
        "basic_block_leaders": sorted(leaders),
        "incoming_stack_heights": {str(offset): sorted(heights[offset]) for offset in sorted(heights)},
        "stack_underflows": underflow_rows,
        "inconsistent_merges": inconsistent,
        "unbounded_or_state_explosion_offsets": sorted(explosions),
        "unreachable_offsets": sorted(known_offsets - reachable),
        "stack_consistent": not underflows and not inconsistent and not explosions,
        "analysis_truncated": bool(explosions),
        "states_explored": state_count,
        "supplied_ir_only": True,
        "executed": False,
        "candidate_only": True,
        "requires_human_confirmation": True,
    }


def _trace_scalar(value: Any, *, label: str) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        return _bounded_integer(value, label=label)
    if isinstance(value, str) and len(value) <= MAX_SYMBOL_CHARS:
        return value
    if value is None or isinstance(value, bool):
        return value
    raise Refuse(f"{label} must be a bounded JSON scalar")


def _trace_stack(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise Refuse(f"{label} must be a bounded sequence")
    if len(value) > MAX_TRACE_STACK:
        raise Refuse(f"{label} exceeds stack bound")
    return [_trace_scalar(item, label=f"{label} item") for item in value]


def _trace_mapping(value: Any, *, label: str) -> dict[Any, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > 1_024:
        raise Refuse(f"{label} must be a bounded mapping")
    result: dict[Any, Any] = {}
    for key, item in value.items():
        normalized_key = _trace_scalar(key, label=f"{label} key")
        result[normalized_key] = _trace_scalar(item, label=f"{label} value")
    return result


def _observation_candidates(observation: Mapping[str, Any]) -> tuple[set[str], dict[str, Any]]:
    before = _trace_stack(observation.get("before_stack", ()), label="before_stack")
    after = _trace_stack(observation.get("after_stack", ()), label="after_stack")
    immediate = observation.get("immediate")
    if immediate is not None:
        immediate = _trace_scalar(immediate, label="immediate")
    candidates: set[str] = set()
    if after == before:
        candidates.add("noop_or_nonstack_effect")
    if len(after) == len(before) + 1 and after[:-1] == before:
        candidates.add("push_unknown")
        if immediate is not None and after[-1] == immediate:
            candidates.add("push_immediate")
    if before and after == before[:-1]:
        candidates.add("pop")
    if before and after == before + [before[-1]]:
        candidates.add("dup")
    if len(before) >= 2 and after == before[:-2] + [before[-1], before[-2]]:
        candidates.add("swap")
    if before and all(isinstance(value, int) and not isinstance(value, bool) for value in (before[-1],)):
        value = before[-1]
        if after == before[:-1] + [-value]:
            candidates.add("neg")
        if after == before[:-1] + [int(value == 0)]:
            candidates.add("logical_not")
    if len(before) >= 2 and all(
        isinstance(value, int) and not isinstance(value, bool) for value in before[-2:]
    ):
        left, right = before[-2:]
        prefix = before[:-2]
        binary = {
            "add": left + right,
            "sub": left - right,
            "reverse_sub": right - left,
            "mul": left * right,
            "xor": left ^ right,
            "and": left & right,
            "or": left | right,
            "eq": int(left == right),
            "lt": int(left < right),
            "gt": int(left > right),
        }
        if right != 0:
            binary["trunc_div"] = abs(left) // abs(right) * (-1 if (left < 0) ^ (right < 0) else 1)
            binary["mod"] = left % right
        for semantic, result in binary.items():
            if result.bit_length() <= MAX_INTEGER_BITS and after == prefix + [result]:
                candidates.add(semantic)

    before_registers = _trace_mapping(observation.get("before_registers"), label="before_registers")
    after_registers = _trace_mapping(observation.get("after_registers"), label="after_registers")
    changed_registers = [
        key
        for key in set(before_registers) | set(after_registers)
        if before_registers.get(key) != after_registers.get(key)
    ]
    if before_registers or after_registers:
        if not changed_registers:
            candidates.add("registers_unchanged")
        elif len(changed_registers) == 1 and after == before:
            key = changed_registers[0]
            old, new = before_registers.get(key), after_registers.get(key)
            if isinstance(old, int) and isinstance(new, int):
                if new == old + 1:
                    candidates.add("register_increment")
                if new == old - 1:
                    candidates.add("register_decrement")
                if new == 0:
                    candidates.add("register_zero")
            if immediate is not None and new == immediate:
                candidates.add("register_load_immediate")

    before_memory = _trace_mapping(observation.get("before_memory"), label="before_memory")
    after_memory = _trace_mapping(observation.get("after_memory"), label="after_memory")
    changed_memory = [
        key
        for key in set(before_memory) | set(after_memory)
        if before_memory.get(key) != after_memory.get(key)
    ]
    if len(changed_memory) == 1 and before and after == before[:-1]:
        address = changed_memory[0]
        if after_memory.get(address) == before[-1]:
            candidates.add("store_top_to_memory")
    if immediate is not None and immediate in before_memory:
        if after == before + [before_memory[immediate]]:
            candidates.add("load_memory_at_immediate")

    halted = observation.get("halted")
    if halted is True:
        candidates.add("halt")
    before_pc = observation.get("before_pc")
    after_pc = observation.get("after_pc")
    next_pc = observation.get("next_pc")
    for label, value in (("before_pc", before_pc), ("after_pc", after_pc), ("next_pc", next_pc)):
        if value is not None:
            _bounded_integer(value, label=label)
    if (
        after_pc is not None
        and isinstance(immediate, int)
        and not isinstance(immediate, bool)
        and after_pc == immediate
    ):
        candidates.add("jump_immediate")
    if (
        before
        and len(after) == len(before) - 1
        and after_pc is not None
        and next_pc is not None
        and isinstance(immediate, int)
        and not isinstance(immediate, bool)
        and after_pc in {next_pc, immediate}
    ):
        candidates.add("conditional_jump_pop")
    summary = {
        "stack_delta": len(after) - len(before),
        "changed_registers": sorted((repr(value) for value in changed_registers)),
        "changed_memory_keys": sorted((repr(value) for value in changed_memory)),
    }
    return candidates, summary


def infer_opcode_semantics(traces: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Intersect semantic predicates across supplied before/after traces."""

    if not isinstance(traces, Sequence) or isinstance(traces, (str, bytes, bytearray)):
        raise Refuse("traces must be a supplied sequence")
    if not traces or len(traces) > MAX_TRACES:
        raise Refuse(f"trace count must be in 1..{MAX_TRACES}")
    grouped: defaultdict[tuple[str, str], list[tuple[Any, set[str], dict[str, Any]]]] = defaultdict(list)
    for index, trace in enumerate(traces):
        if not isinstance(trace, Mapping):
            raise Refuse("each trace must be a mapping")
        opcode = _trace_scalar(trace.get("opcode"), label="opcode")
        candidates, summary = _observation_candidates(trace)
        summary["trace_index"] = index
        grouped[(type(opcode).__name__, repr(opcode))].append((opcode, candidates, summary))

    rows: list[dict[str, Any]] = []
    for key in sorted(grouped):
        observations = grouped[key]
        compatible = set(observations[0][1])
        for _, candidates, _ in observations[1:]:
            compatible.intersection_update(candidates)
        union = set().union(*(candidates for _, candidates, _ in observations))
        rows.append({
            "opcode": observations[0][0],
            "observation_count": len(observations),
            "compatible_candidates": sorted(compatible),
            "seen_but_inconsistent_candidates": sorted(union - compatible),
            "unexplained": not compatible,
            "observation_summaries": [summary for _, _, summary in observations[:64]],
        })
    return {
        "opcodes": rows,
        "verdict": None,
        "candidate_only": True,
        "requires_human_confirmation": True,
        "supplied_traces_only": True,
        "executed": False,
    }


grammar_analysis = analyze_grammar
stack_cfg = analyze_stack_cfg
opcode_semantic_candidates = infer_opcode_semantics


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="JSON data file")
    parser.add_argument("--mode", choices=("grammar", "cfg", "traces"), required=True)
    parser.add_argument("--start")
    parser.add_argument("--entry", type=int)
    args = parser.parse_args(argv)
    data = json.loads(Path(args.path).read_text(encoding="utf-8"))
    if args.mode == "grammar":
        if args.start is None:
            raise Refuse("--start is required for grammar mode")
        result = analyze_grammar(data, start=args.start)
    elif args.mode == "cfg":
        result = analyze_stack_cfg(data, entry=args.entry)
    else:
        result = infer_opcode_semantics(data)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "END_MARKER",
    "EPSILON",
    "Refuse",
    "analyze_grammar",
    "analyze_stack_cfg",
    "grammar_analysis",
    "infer_opcode_semantics",
    "opcode_semantic_candidates",
    "stack_cfg",
]
