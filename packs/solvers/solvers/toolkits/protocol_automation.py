#!/usr/bin/env python3
"""Offline programming-challenge inference over saved transcripts and sequences.

There is intentionally no transport code.  The module parses recorded receive/send
events, infers repeated round shapes, emits inert driver plans, and provides exact
finite-difference, linear-recurrence, Berlekamp--Massey, and CRT helpers.  Every
derived value is a candidate for replay/human review; nothing is transmitted.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable


MAX_INPUT = 8 << 20
MAX_EVENTS = 20_000
MAX_EVENT_TEXT = 128_000
MAX_SEQUENCE = 4096
MAX_BITS = 16_384
MAX_ORDER = 32
MAX_RECURRENCE_TERMS = 512
MAX_RECURRENCE_WORK_BITS = 1_000_000


class Refuse(ValueError):
    pass


ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
PREFIX_RE = re.compile(
    r"^\s*(S>|C>|server\s*:|client\s*:|recv\s*:|receive\s*:|send\s*:|sent\s*:|"
    r"prompt\s*:|answer\s*:|<<<|>>>)(.*)$", re.I)


def _text(value: Any) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8", "surrogatepass")) > MAX_EVENT_TEXT:
        raise Refuse("event text exceeds bound")
    return ANSI_RE.sub("", value).replace("\r\n", "\n").replace("\r", "\n")


def _direction(value: Any) -> str | None:
    value = str(value or "").strip().casefold()
    if value in {"recv", "receive", "received", "server", "prompt", "s", "assistant"}:
        return "recv"
    if value in {"send", "sent", "client", "answer", "c", "user"}:
        return "send"
    return None


def _json_events(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("events", value.get("transcript", value.get("messages", value)))
    if not isinstance(value, list) or len(value) > MAX_EVENTS:
        raise Refuse("JSON transcript must be a bounded event list")
    events = []
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            continue
        direction = _direction(row.get("direction", row.get("role", row.get("type"))))
        if direction is None and "prompt" in row:
            direction = "recv"
        if direction is None and "answer" in row:
            direction = "send"
        if direction is None:
            continue
        content = row.get("content", row.get("data", row.get("text",
                      row.get("prompt" if direction == "recv" else "answer", ""))))
        if not isinstance(content, str):
            continue
        events.append({"direction": direction, "text": _text(content), "source_index": index})
    return events


def parse_transcript(value: Any) -> list[dict[str, Any]]:
    """Normalize JSON or prefixed plain-text transcripts; never opens a connection."""
    if isinstance(value, (dict, list)):
        events = _json_events(value)
    else:
        if isinstance(value, bytes):
            if len(value) > MAX_INPUT:
                raise Refuse("transcript exceeds 8 MiB")
            value = value.decode("utf-8", "strict")
        if not isinstance(value, str) or len(value.encode("utf-8", "surrogatepass")) > MAX_INPUT:
            raise Refuse("transcript exceeds 8 MiB")
        stripped = value.lstrip()
        if stripped.startswith(("[", "{")):
            try:
                return _json_events(json.loads(value))
            except json.JSONDecodeError:
                pass
        events = []
        for line_number, line in enumerate(value.splitlines()):
            match = PREFIX_RE.match(line)
            if match:
                marker = match.group(1).casefold().replace(" ", "")
                direction = "recv" if marker in {"s>", "server:", "recv:", "receive:",
                                                    "prompt:", "<<<"} else "send"
                events.append({"direction": direction, "text": _text(match.group(2).lstrip()),
                               "source_index": line_number})
            elif events:
                combined = events[-1]["text"] + "\n" + line
                events[-1]["text"] = _text(combined)
        if len(events) > MAX_EVENTS:
            raise Refuse("event count exceeds bound")
    if not events:
        raise Refuse("no receive/send events found")
    if len(events) > MAX_EVENTS:
        raise Refuse("event count exceeds bound")
    return events


def prompt_signature(text: str) -> str:
    text = _text(text).casefold()
    text = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", text)
    text = re.sub(r"\b[0-9a-f]{24,}\b", "<hexblob>", text)
    text = re.sub(r"\b(?:[a-z0-9+/]{24,}={0,2})\b", "<blob>", text)
    text = re.sub(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])", "<num>", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:4096]


def _handler_lead(prompt: str) -> str:
    low = prompt.casefold()
    if re.search(r"\b(?:sha(?:-?\d+)?|md5|blake|crc32|digest|hash)\b", low):
        return "hashing"
    if re.search(r"\b(?:base\s*\d+|binary|octal|hexadecimal)\b", low):
        return "base_conversion"
    if re.search(r"\b(?:prime|fibonacci|collatz|sequence|next\s+(?:term|number))\b", low):
        return "sequence"
    if re.search(r"\b(?:gcd|lcm|factorial|choose|binomial|modular inverse|calculate|compute)\b", low):
        return "math"
    if re.search(r"\b(?:rot13|caesar|atbash|decode|decrypt)\b", low):
        return "classical_transform"
    if re.search(r"\b(?:sort|dedupe|reverse).{0,20}\b(?:list|array|values)\b", low):
        return "list_operation"
    return "unclassified"


def infer_protocol(value: Any) -> dict[str, Any]:
    events = parse_transcript(value)
    rounds = []
    pending = None
    for index, event in enumerate(events):
        if event["direction"] == "recv":
            if pending is not None:
                rounds.append(pending)
            pending = {"receive_event": index, "prompt": event["text"], "recorded_send": None}
        elif pending is not None and pending["recorded_send"] is None:
            pending["send_event"] = index
            pending["recorded_send"] = event["text"]
            rounds.append(pending)
            pending = None
    if pending is not None:
        rounds.append(pending)
    if not rounds:
        raise Refuse("transcript has no receive rounds")

    states, state_index, state_rows = [], {}, {}
    previous = None
    transitions: dict[tuple[str, str], int] = {}
    for number, row in enumerate(rounds):
        signature = prompt_signature(row["prompt"])
        if signature not in state_index:
            name = f"state_{len(states)}"
            state_index[signature] = name
            prefix = re.split(r"<num>|<hex>|<hexblob>|<blob>", signature, maxsplit=1)[0].strip()
            state_row = {"name": name, "signature": signature, "expect_prefix": prefix,
                         "handler_lead": _handler_lead(row["prompt"]), "observations": 0}
            states.append(state_row)
            state_rows[name] = state_row
        state = state_index[signature]
        state_rows[state]["observations"] += 1
        row.update(round=number, state=state, signature=signature,
                   handler_lead=_handler_lead(row["prompt"]), candidate_only=True)
        if row["recorded_send"] is not None:
            response = row["recorded_send"].strip()
            row["recorded_response_shape"] = (
                "integer" if re.fullmatch(r"-?\d+", response) else
                "hex" if re.fullmatch(r"[0-9a-fA-F]+", response) else
                "single_line_text" if "\n" not in response else "multiline_text"
            )
        if previous is not None:
            transitions[(previous, state)] = transitions.get((previous, state), 0) + 1
        previous = state
    transition_rows = [{"from": left, "to": right, "count": count}
                       for (left, right), count in sorted(transitions.items())]
    plan = {"version": 1, "offline_only": True, "network_enabled": False, "sent": False,
            "states": states, "transitions": transition_rows,
            "note": "handler_lead is a lexical suggestion; replay and human verification are required"}
    return {"events": events, "rounds": rounds, "states": states, "transitions": transition_rows,
            "driver_plan": plan, "sent": False, "answer": None, "requires_human_review": True}


def render_inert_scaffold(plan: dict[str, Any]) -> str:
    """Render a transport-free Python scaffold that only classifies saved text."""
    if not isinstance(plan, dict) or plan.get("network_enabled") is not False:
        raise Refuse("plan must be an offline driver plan")
    states = plan.get("states")
    if not isinstance(states, list) or len(states) > MAX_EVENTS:
        raise Refuse("invalid plan states")
    for state in states:
        if (not isinstance(state, dict)
                or not all(isinstance(state.get(key), str)
                           for key in ("name", "expect_prefix", "handler_lead"))):
            raise Refuse("invalid plan state")
    compact = json.dumps({"states": states}, ensure_ascii=False, separators=(",", ":"))
    if len(compact.encode()) > MAX_INPUT:
        raise Refuse("plan exceeds scaffold bound")
    return (
        "# Generated offline replay scaffold: it has no transport and sends nothing.\n"
        "import json\n\n"
        f"PLAN = json.loads({compact!r})\n\n"
        "def classify_saved_receive(saved_receive):\n"
        "    for state in PLAN['states']:\n"
        "        prefix = state.get('expect_prefix', '')\n"
        "        if prefix and prefix.casefold() in saved_receive.casefold():\n"
        "            return {'state': state['name'], 'handler_lead': state['handler_lead'],\n"
        "                    'candidate_answer': None, 'sent': False}\n"
        "    return {'state': None, 'candidate_answer': None, 'sent': False}\n"
    )


def _ints(values: Iterable[int]) -> list[int]:
    if not isinstance(values, (list, tuple)) or not 3 <= len(values) <= MAX_SEQUENCE:
        raise Refuse("sequence needs 3..4096 integers")
    out = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value.bit_length() > MAX_BITS:
            raise Refuse("sequence contains an invalid or oversized integer")
        out.append(value)
    return out


def _difference_model(values: list[int], max_degree: int) -> list[list[int]] | None:
    levels = [list(values)]
    if len(values) >= 2 and len(set(values)) == 1:
        return levels
    for _degree in range(1, min(max_degree, len(values) - 2) + 1):
        prev = levels[-1]
        levels.append([right - left for left, right in zip(prev, prev[1:])])
        if len(levels[-1]) >= 2 and len(set(levels[-1])) == 1:
            return levels
    return None


def _extend_differences(levels: list[list[int]], count: int) -> list[int]:
    predictions = []
    levels = [list(row) for row in levels]
    for _ in range(count):
        levels[-1].append(levels[-1][-1])
        for index in range(len(levels) - 2, -1, -1):
            levels[index].append(levels[index][-1] + levels[index + 1][-1])
        if levels[0][-1].bit_length() > MAX_BITS:
            raise Refuse("predicted integer exceeds bit bound")
        predictions.append(levels[0][-1])
    return predictions


def finite_difference_predict(values: Iterable[int], *, count: int = 1,
                              max_degree: int = 8) -> dict[str, Any]:
    values = _ints(values)
    if not 1 <= count <= 100 or not 1 <= max_degree <= 32:
        raise Refuse("prediction count/degree outside bound")
    model = _difference_model(values, max_degree)
    if model is None:
        raise Refuse("no bounded constant-difference model")
    holdout = _difference_model(values[:-1], max_degree)
    if holdout is None or _extend_differences(holdout, 1)[0] != values[-1]:
        raise Refuse("difference model failed one-term holdout replay")
    return {"kind": "finite_difference", "degree": len(model) - 1,
            "constant_difference": model[-1][0], "predictions": _extend_differences(model, count),
            "holdout_verified": True, "candidate_only": True, "requires_human_review": True}


def _solve_linear(values: list[int], order: int) -> list[Fraction] | None:
    if len(values) < 2 * order:
        return None
    matrix = []
    for n in range(order, len(values)):
        matrix.append([Fraction(values[n - i - 1]) for i in range(order)] + [Fraction(values[n])])
    row = 0
    pivots = []
    for col in range(order):
        pivot = next((at for at in range(row, len(matrix)) if matrix[at][col]), None)
        if pivot is None:
            continue
        matrix[row], matrix[pivot] = matrix[pivot], matrix[row]
        divisor = matrix[row][col]
        matrix[row] = [value / divisor for value in matrix[row]]
        for at in range(len(matrix)):
            if at != row and matrix[at][col]:
                factor = matrix[at][col]
                matrix[at] = [left - factor * right for left, right in zip(matrix[at], matrix[row])]
        pivots.append(col)
        row += 1
    if any(not any(line[:order]) and line[-1] for line in matrix) or len(pivots) != order:
        return None
    solution = [Fraction(0) for _ in range(order)]
    for at, col in enumerate(pivots):
        solution[col] = matrix[at][-1]
    return solution


def _fraction_json(value: Fraction) -> int | dict[str, int]:
    return value.numerator if value.denominator == 1 else {
        "numerator": value.numerator, "denominator": value.denominator}


def exact_recurrence_predict(values: Iterable[int], *, count: int = 1,
                             max_order: int = 8) -> dict[str, Any]:
    values = _ints(values)
    if not 1 <= count <= 100 or not 1 <= max_order <= MAX_ORDER:
        raise Refuse("prediction count/order outside bound")
    if len(values) > MAX_RECURRENCE_TERMS:
        raise Refuse("exact recurrence term count exceeds computational bound")
    if sum(max(1, value.bit_length()) for value in values) > MAX_RECURRENCE_WORK_BITS:
        raise Refuse("exact recurrence bit-work exceeds computational bound")
    found = None
    for order in range(1, min(max_order, (len(values) - 1) // 2) + 1):
        coefficients = _solve_linear(values[:-1], order)
        if coefficients is None:
            continue
        predicted = sum(coefficients[i] * values[-2 - i] for i in range(order))
        if predicted == values[-1]:
            found = (order, coefficients)
            break
    if found is None:
        raise Refuse("no unique exact recurrence passed holdout replay")
    order, coefficients = found
    if any(value.numerator.bit_length() > MAX_BITS or value.denominator.bit_length() > MAX_BITS
           for value in coefficients):
        raise Refuse("recurrence coefficient exceeds bit bound")
    sequence = [Fraction(value) for value in values]
    predictions = []
    for _ in range(count):
        value = sum(coefficients[i] * sequence[-i - 1] for i in range(order))
        if value.numerator.bit_length() > MAX_BITS or value.denominator.bit_length() > MAX_BITS:
            raise Refuse("recurrence prediction exceeds bit bound")
        sequence.append(value)
        predictions.append(_fraction_json(value))
    return {"kind": "exact_linear_recurrence", "order": order,
            "coefficients": [_fraction_json(value) for value in coefficients],
            "predictions": predictions, "holdout_verified": True,
            "candidate_only": True, "requires_human_review": True}


def _prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def _bm_coefficients(sequence: list[int], modulus: int) -> list[int]:
    c, b = [1], [1]
    length, shift, discrepancy_base = 0, 1, 1
    for n in range(len(sequence)):
        discrepancy = sequence[n]
        for i in range(1, length + 1):
            discrepancy = (discrepancy + c[i] * sequence[n - i]) % modulus
        if discrepancy == 0:
            shift += 1
            continue
        previous = c[:]
        factor = discrepancy * pow(discrepancy_base, -1, modulus) % modulus
        if len(c) < len(b) + shift:
            c.extend([0] * (len(b) + shift - len(c)))
        for index, value in enumerate(b):
            c[index + shift] = (c[index + shift] - factor * value) % modulus
        if 2 * length <= n:
            length = n + 1 - length
            b, discrepancy_base, shift = previous, discrepancy, 1
        else:
            shift += 1
    return [(-c[index]) % modulus for index in range(1, length + 1)]


def berlekamp_massey(values: Iterable[int], modulus: int, *, count: int = 1) -> dict[str, Any]:
    values = _ints(values)
    if (isinstance(modulus, bool) or not isinstance(modulus, int)
            or modulus > 2_147_483_647 or not _prime(modulus)):
        raise Refuse("modulus must be a prime no larger than 2^31-1")
    if not 1 <= count <= 100:
        raise Refuse("prediction count outside bound")
    sequence = [value % modulus for value in values]
    training = sequence[:-1]
    coefficients = _bm_coefficients(training, modulus)
    length = len(coefficients)
    if not coefficients or len(training) < 2 * length:
        raise Refuse("modular recurrence is not sufficiently determined")
    held_out = sum(coefficients[i] * training[-i - 1] for i in range(length)) % modulus
    if held_out != sequence[-1]:
        raise Refuse("modular recurrence failed one-term holdout replay")
    for n in range(length, len(sequence)):
        if sum(coefficients[i] * sequence[n - i - 1] for i in range(length)) % modulus != sequence[n]:
            raise Refuse("modular recurrence replay failed")
    predictions = []
    for _ in range(count):
        value = sum(coefficients[i] * sequence[-i - 1] for i in range(length)) % modulus
        sequence.append(value)
        predictions.append(value)
    return {"kind": "berlekamp_massey", "modulus": modulus, "order": length,
            "coefficients": coefficients, "predictions": predictions,
            "full_replay_verified": True, "holdout_verified": True,
            "candidate_only": True, "requires_human_review": True}


def crt(congruences: Iterable[Iterable[int]]) -> dict[str, Any]:
    if not isinstance(congruences, (list, tuple)) or not 1 <= len(congruences) <= 1024:
        raise Refuse("CRT needs 1..1024 congruences")
    value, modulus = 0, 1
    normalized = []
    for item in congruences:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise Refuse("each congruence must be [remainder, modulus]")
        remainder, other = item
        if (isinstance(remainder, bool) or isinstance(other, bool)
                or not isinstance(remainder, int) or not isinstance(other, int) or other <= 1
                or remainder.bit_length() > MAX_BITS or other.bit_length() > MAX_BITS):
            raise Refuse("invalid congruence")
        remainder %= other
        divisor = math.gcd(modulus, other)
        if (remainder - value) % divisor:
            raise Refuse("inconsistent congruences")
        left, right = modulus // divisor, other // divisor
        step = 0 if right == 1 else ((remainder - value) // divisor * pow(left, -1, right)) % right
        value += modulus * step
        modulus *= right
        value %= modulus
        if value.bit_length() > MAX_BITS or modulus.bit_length() > MAX_BITS:
            raise Refuse("CRT result exceeds bit bound")
        normalized.append((remainder, other))
    verified = all(value % other == remainder for remainder, other in normalized)
    return {"value": value, "modulus": modulus, "verified": verified,
            "candidate_only": True, "requires_human_review": True}


def solve_sequence(values: Iterable[int], *, modulus: int | None = None) -> dict[str, Any]:
    values = _ints(values)
    if modulus is not None and (isinstance(modulus, bool) or not isinstance(modulus, int)
                                or modulus > 2_147_483_647 or not _prime(modulus)):
        raise Refuse("modulus must be a prime no larger than 2^31-1")
    candidates = []
    for function in (finite_difference_predict, exact_recurrence_predict):
        try:
            candidates.append(function(values))
        except Refuse:
            pass
    if modulus is not None:
        try:
            candidates.append(berlekamp_massey(values, modulus))
        except Refuse:
            pass
    return {"values": values, "candidates": candidates, "answer": None,
            "requires_human_review": True}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Refuse(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline transcript/state/sequence inference")
    parser.add_argument("operation", choices=("transcript", "sequence", "crt", "scaffold"))
    parser.add_argument("input")
    parser.add_argument("--modulus", type=int)
    try:
        args = parser.parse_args(argv)
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_INPUT:
            raise Refuse("input exceeds 8 MiB")
        if args.operation in {"transcript", "scaffold"}:
            report = infer_protocol(raw)
            result = render_inert_scaffold(report["driver_plan"]) if args.operation == "scaffold" else report
            if isinstance(result, str):
                print(result, end="")
                return 0
        else:
            value = json.loads(raw)
            result = solve_sequence(value, modulus=args.modulus) if args.operation == "sequence" else crt(value)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, Refuse, ValueError, TypeError,
            OverflowError, MemoryError, ZeroDivisionError) as exc:
        print(f"protocol_automation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
