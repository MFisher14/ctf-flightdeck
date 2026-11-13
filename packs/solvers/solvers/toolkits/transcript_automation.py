#!/usr/bin/env python3
"""Offline programming-quiz automation over saved transcripts.

This module deliberately has no transport.  It reuses the pure prompt handlers from ``tools/netplay``
against saved prompts, validates answers by deterministic replay, and compiles literal state-machine
plans for human review.  No answer or plan is sent anywhere.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
MAX_INPUT = 8 << 20
MAX_PROMPTS = 10_000
MAX_STATES = 1_000
MAX_TEXT = 64_000
MAX_BITS = 16_384


def _load_netplay():
    name = "csctf_netplay_offline_handlers"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "netplay.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("netplay handlers unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


netplay = _load_netplay()


def _bounded(value: int) -> int:
    if not isinstance(value, int) or value.bit_length() > MAX_BITS:
        raise ValueError("integer result exceeds the bit bound")
    return value


def extended_math(prompt: str) -> str:
    """Solve explicit factorial/GCD/LCM/binomial/modular-inverse prompts with replay checks."""
    if not isinstance(prompt, str) or len(prompt) > MAX_TEXT:
        raise ValueError("prompt exceeds bound")
    low = prompt.lower()
    match = re.search(r"\b(?:factorial\s+of\s+(\d{1,6})|factorial\s*\(\s*(\d{1,6})\s*\)|(\d{1,6})\s*!)", low)
    if match and ("factorial" in low or "!" in match.group(0)):
        n = int(next(group for group in match.groups() if group is not None))
        if n > 5000:
            raise ValueError("factorial index exceeds 5000")
        value = _bounded(math.factorial(n))
        if n and value // n != math.factorial(n - 1):
            raise ValueError("factorial replay failed")
        return str(value)
    operation = re.search(r"\b(?:gcd|greatest common divisor|lcm|least common multiple)\b", low)
    if operation:
        # Parse only the explicit operand run following the operation.  Harvesting every integer in
        # the whole prompt made labels such as "Round 5" silently become a third GCD operand.
        tail = prompt[operation.end():]
        operands = re.match(
            r"\s*(?:(?:of|for)\s+|[:=]\s*)?\(?\s*"
            r"(-?\d{1,200}(?:\s*(?:,|;|\band\b|&|\s)\s*-?\d{1,200})+)\s*\)?",
            tail, re.I)
        values = [int(item) for item in re.findall(r"-?\d{1,200}", operands.group(1))] if operands else []
        if not 2 <= len(values) <= 1000:
            raise ValueError("GCD/LCM needs 2..1000 explicit integers")
        if "lcm" in low or "least common" in low:
            result = math.lcm(*values)
            if any(result % value for value in values if value):
                raise ValueError("LCM replay failed")
        else:
            result = math.gcd(*values)
            if any(value % result for value in values) if result else any(values):
                raise ValueError("GCD replay failed")
        return str(_bounded(result))
    match = re.search(r"\b(?:choose|binomial)\s*\(?\s*(\d{1,6})\s*[, ]\s*(\d{1,6})\s*\)?", low)
    if not match:
        match = re.search(r"\b(\d{1,6})\s+choose\s+(\d{1,6})\b", low)
    if match:
        n, k = map(int, match.groups())
        if n > 100_000 or k > n:
            raise ValueError("binomial arguments outside bound")
        value = _bounded(math.comb(n, k))
        if value != math.comb(n, n - k):
            raise ValueError("binomial symmetry replay failed")
        return str(value)
    match = re.search(r"\b(?:modular\s+)?inverse\s+of\s+(-?\d{1,200})\s+(?:mod|modulo)\s+(\d{1,200})", low)
    if match:
        value, modulus = map(int, match.groups())
        if modulus <= 1 or modulus.bit_length() > MAX_BITS:
            raise ValueError("invalid modulus")
        try:
            inverse = pow(value, -1, modulus)
        except ValueError as exc:
            raise ValueError("modular inverse does not exist") from exc
        if value * inverse % modulus != 1:
            raise ValueError("modular inverse replay failed")
        return str(inverse)
    match = re.search(r"\bsum\s+(?:of\s+)?(?:integers\s+)?(?:from\s+)?(-?\d+)\s+(?:to|through|\.\.)\s+(-?\d+)", low)
    if match:
        start, end = map(int, match.groups())
        if abs(end - start) > 10**9:
            raise ValueError("range exceeds bound")
        count = abs(end - start) + 1
        value = count * (start + end) // 2
        return str(_bounded(value))
    raise ValueError("unsupported extended math prompt")


def answer_prompt(prompt: str) -> dict[str, Any]:
    """Return one deterministic candidate with a repeated-computation check, or decline."""
    if not isinstance(prompt, str) or not prompt or len(prompt) > MAX_TEXT:
        raise ValueError("prompt must be bounded nonempty text")
    first = netplay.auto_handler(prompt)
    solver = "netplay.auto_handler"
    if first is None:
        first = extended_math(prompt)
        solver = "extended_math"
    second = netplay.auto_handler(prompt) if solver == "netplay.auto_handler" else extended_math(prompt)
    if first != second:
        raise ValueError("deterministic replay disagreed")
    return {"prompt": prompt, "candidate_answer": first, "solver": solver,
            "deterministic_replay_verified": True, "sent": False,
            "semantic_answer_verified": False, "candidate_only": True,
            "verification_scope": "same parser/solver replay proves determinism, not prompt interpretation",
            "requires_human_review": True}


def _transcript_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("events", value.get("transcript", value.get("messages", value)))
    if not isinstance(value, list) or len(value) > MAX_PROMPTS * 2:
        raise ValueError("transcript must be a bounded event list")
    return [row for row in value if isinstance(row, dict)]


def analyze_transcript(value: Any) -> dict[str, Any]:
    """Compute candidates for receive events and compare any following recorded sends."""
    rows = _transcript_rows(value)
    results = []
    for index, row in enumerate(rows):
        direction = str(row.get("direction", row.get("role", ""))).lower()
        if direction not in {"recv", "receive", "server", "prompt"} and "prompt" not in row:
            continue
        prompt = row.get("prompt", row.get("data", row.get("content", "")))
        if not isinstance(prompt, str):
            continue
        try:
            result = answer_prompt(prompt)
        except (ValueError, TypeError, OverflowError):
            results.append({"event": index, "prompt": prompt, "declined": True, "sent": False})
            continue
        result["event"] = index
        recorded = row.get("answer")
        if recorded is None and index + 1 < len(rows):
            nxt = rows[index + 1]
            ndir = str(nxt.get("direction", nxt.get("role", ""))).lower()
            if ndir in {"send", "sent", "client", "answer"}:
                recorded = nxt.get("data", nxt.get("content", nxt.get("answer")))
        if recorded is not None:
            result["recorded_answer"] = str(recorded).rstrip("\r\n")
            result["recorded_matches"] = result["recorded_answer"] == result["candidate_answer"]
            # A saved answer mismatch does not undo deterministic replay; it is separate evidence
            # and never promotes either value without an independently recorded acceptance event.
            result["candidate_consistent_with_recording"] = result["recorded_matches"]
        results.append(result)
        if len(results) >= MAX_PROMPTS:
            break
    return {"events": len(rows), "rounds": results, "sent": False, "flag": None}


def validate_state_machine(spec: Any) -> dict[str, dict[str, Any]]:
    if isinstance(spec, dict) and isinstance(spec.get("states"), list):
        states = spec["states"]
    elif isinstance(spec, list):
        states = spec
    else:
        raise ValueError("state machine must contain a states list")
    if not 1 <= len(states) <= MAX_STATES:
        raise ValueError("state count outside bound")
    out = {}
    for row in states:
        if not isinstance(row, dict):
            raise ValueError("state is not an object")
        name = str(row.get("name", ""))
        expect = row.get("expect_contains")
        if not name or len(name) > 128 or name in out or not isinstance(expect, str) or not expect:
            raise ValueError("state needs unique name and literal expect_contains")
        if len(expect) > 4096:
            raise ValueError("expect literal too large")
        handler = row.get("handler")
        send = row.get("send")
        if (handler is None) == (send is None):
            raise ValueError("state needs exactly one of handler or send")
        if handler is not None and handler not in {*netplay.HANDLERS, "auto", "extended_math"}:
            raise ValueError("unknown handler")
        out[name] = {"name": name, "expect_contains": expect, "handler": handler, "send": send,
                     "next": row.get("next")}
    for row in out.values():
        if row["next"] is not None and row["next"] not in out:
            raise ValueError("state references unknown next state")
    return out


def replay_state_machine(spec: Any, received: list[str], *, start: str | None = None) -> dict[str, Any]:
    """Replay literal state transitions over saved receive blocks; return an unsent plan."""
    states = validate_state_machine(spec)
    if not isinstance(received, list) or len(received) > MAX_PROMPTS or not all(isinstance(x, str) for x in received):
        raise ValueError("received blocks must be a bounded string list")
    current = start or next(iter(states))
    output = []
    for index, prompt in enumerate(received):
        state = states[current]
        if state["expect_contains"] not in prompt:
            raise ValueError(f"saved prompt {index} does not match state {current}")
        if state["handler"] == "auto":
            answer = answer_prompt(prompt)["candidate_answer"]
        elif state["handler"] == "extended_math":
            answer = extended_math(prompt)
        elif state["handler"]:
            answer = netplay.HANDLERS[state["handler"]](prompt)
            # Re-run the named handler before retaining a value.
            if answer != netplay.HANDLERS[state["handler"]](prompt):
                raise ValueError("handler replay disagreed")
        else:
            answer = str(state["send"])
        output.append({"state": current, "received_index": index, "candidate_send": answer,
                       "literal_expect_verified": True, "semantic_answer_verified": False,
                       "candidate_only": True, "sent": False})
        nxt = state["next"]
        if nxt is None:
            if index != len(received) - 1:
                raise ValueError("saved transcript continues after terminal state")
            current = None
            break
        current = nxt
    return {"steps": output, "terminal": current is None, "sent": False,
            "requires_human_review": True}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _json(path: str) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_INPUT:
        raise ValueError("input exceeds 8 MiB")
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline saved-transcript quiz and state-machine analysis")
    parser.add_argument("operation", choices=("prompt", "transcript", "state"))
    parser.add_argument("input")
    parser.add_argument("--received", help="JSON file containing saved receive strings for state replay")
    try:
        args = parser.parse_args(argv)
        if args.operation == "prompt":
            raw = Path(args.input).read_text(encoding="utf-8")
            result = answer_prompt(raw)
        elif args.operation == "transcript":
            result = analyze_transcript(_json(args.input))
        else:
            if not args.received:
                raise ValueError("state replay requires --received")
            result = replay_state_machine(_json(args.input), _json(args.received))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError, OverflowError) as exc:
        print(f"transcript_automation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
