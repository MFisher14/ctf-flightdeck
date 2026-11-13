#!/usr/bin/env python3
"""Bounded Brain-Flak interpreter for the remaining common CTF esolang gap.

Brain-Flak has no output instruction: implementations conventionally display a final stack, and
challenge encoders disagree on top-to-bottom versus bottom-to-top byte rendering.  This engine never
guesses that convention.  It returns the exact final stacks plus both verified byte candidates for
human review.  Programs are parsed/executed as data with depth/step/stack/integer caps.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


MAX_SOURCE = 2 << 20
MAX_DEPTH = 256
MAX_STEPS = 1_000_000
MAX_STACK = 100_000
MAX_BITS = 4096


class Refuse(ValueError):
    pass


PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}


def parse(text: str):
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_SOURCE:
        raise Refuse("source exceeds 2 MiB")
    source = "".join(char for char in text if not char.isspace())
    if not source or any(char not in "()[]{}<>" for char in source):
        raise Refuse("Brain-Flak source must contain only brackets/whitespace")

    def sequence(index: int, closing: str | None, depth: int):
        if depth > MAX_DEPTH:
            raise Refuse("nesting depth cap")
        nodes = []
        while index < len(source):
            char = source[index]
            if char in ")]}>":
                if char != closing:
                    raise Refuse("mismatched closing bracket")
                return nodes, index + 1
            children, index = sequence(index + 1, PAIRS[char], depth + 1)
            nodes.append((char, children))
        if closing is not None:
            raise Refuse("unclosed bracket")
        return nodes, index

    try:
        nodes, end = sequence(0, None, 0)
    except RecursionError as exc:
        raise Refuse("parser recursion cap") from exc
    if end != len(source):
        raise Refuse("trailing parse data")
    return nodes


def execute(text: str, *, steps: int = MAX_STEPS) -> dict:
    tree = parse(text)
    if not isinstance(steps, int):
        raise Refuse("invalid step budget")
    state = {"stacks": [[], []], "active": 0, "steps": 0, "limit": min(max(1, steps), MAX_STEPS)}

    def bounded(value: int) -> int:
        if not isinstance(value, int) or value.bit_length() > MAX_BITS:
            raise Refuse("integer bound")
        return value

    def tick():
        state["steps"] += 1
        if state["steps"] > state["limit"]:
            raise Refuse("step cap")

    def evaluate(nodes) -> int:
        total = 0
        for opener, children in nodes:
            tick()
            active = state["stacks"][state["active"]]
            if not children:
                if opener == "(":
                    value = 1
                elif opener == "[":
                    value = len(active)
                elif opener == "{":
                    value = active.pop() if active else 0
                else:
                    state["active"] ^= 1
                    value = 0
            elif opener == "(":
                value = bounded(evaluate(children))
                active = state["stacks"][state["active"]]
                if len(active) >= MAX_STACK:
                    raise Refuse("stack cap")
                active.append(value)
            elif opener == "[":
                value = bounded(-evaluate(children))
            elif opener == "<":
                evaluate(children)
                value = 0
            else:  # {...}: execute while top is non-zero; value is the sum of all iterations.
                value = 0
                while True:
                    active = state["stacks"][state["active"]]
                    if not active or active[-1] == 0:
                        break
                    tick()
                    value = bounded(value + evaluate(children))
            total = bounded(total + value)
        return total

    try:
        accumulator = evaluate(tree)
    except RecursionError as exc:
        raise Refuse("execution recursion cap") from exc
    return {"stacks": [list(stack) for stack in state["stacks"]], "active_stack": state["active"],
            "accumulator": accumulator, "steps": state["steps"], "halted": True}


def output_candidates(report: dict) -> list[dict]:
    """Byte renderings of the final active stack, retained only when exact and replayable."""
    stacks = report.get("stacks") if isinstance(report, dict) else None
    active_index = report.get("active_stack") if isinstance(report, dict) else None
    if (not isinstance(stacks, list) or len(stacks) != 2
            or not isinstance(active_index, int) or isinstance(active_index, bool)
            or active_index not in (0, 1)):
        raise Refuse("invalid execution report")
    active = stacks[active_index]
    if not isinstance(active, list):
        raise Refuse("invalid execution report")
    if not active or not all(isinstance(value, int) and 0 <= value <= 255 for value in active):
        return []
    rows = []
    seen = set()
    for convention, values in (("bottom_to_top", active), ("top_to_bottom", reversed(active))):
        data = bytes(values)
        if data in seen:
            continue
        seen.add(data)
        rows.append({"convention": convention, "bytes_hex": data.hex(),
                     "text": data.decode("utf-8", "replace"), "verified_from_stack": True,
                     "candidate_only": True})
    return rows


def analyze(text: str) -> dict:
    report = execute(text)
    report["output_candidates"] = output_candidates(report)
    report["answer"] = None
    report["requires_human_convention"] = len(report["output_candidates"]) > 1
    return report


def encode_fixture(data: bytes) -> str:
    """Straight-line test encoder: push each byte as the sum of N ``()`` nilads."""
    if not isinstance(data, bytes) or len(data) > 4096:
        raise ValueError("fixture data bound")
    return "".join("(" + "()" * value + ")" for value in data)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Refuse(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="bounded Brain-Flak interpreter (outputs ranked stack conventions)")
    parser.add_argument("input")
    try:
        args = parser.parse_args(argv)
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_SOURCE:
            raise Refuse("source exceeds 2 MiB")
        print(json.dumps(analyze(raw.decode("utf-8", "strict")), indent=2, ensure_ascii=False))
        return 0
    except SystemExit as exc:                       # argparse --help exits 0; keep it a clean return
        return 0 if (exc.code or 0) == 0 else 2
    except (OSError, Refuse, ValueError, TypeError, UnicodeError, RecursionError,
            MemoryError, OverflowError) as exc:
        print(f"esolang_round5: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
