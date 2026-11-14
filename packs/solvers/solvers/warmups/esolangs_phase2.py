#!/usr/bin/env python3
"""Bounded offline Whirl and Kipple interpreters for CTF artifacts.

Whirl follows Sean Heber's public-domain reference implementation, including
the ``00`` execution latch and non-incrementing program-counter jumps.  Kipple
implements the core language plus its official interpreter's documented string
preprocessor.  Neither interpreter performs live I/O or host-code execution.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


MAX_SOURCE_CHARS = 1_000_000
MAX_STEPS = 250_000
MAX_OUTPUT_CHARS = 65_536
MAX_MEMORY_CELLS = 65_536
MAX_STACK_ITEMS = 100_000
MAX_NESTING = 128
MAX_INTEGER_BITS = 4_096


class Refuse(ValueError):
    """Invalid input or an explicit analysis bound was reached."""


OPS_COMMANDS = (
    "noop", "exit", "one", "zero", "load", "store", "padd", "dadd",
    "logic", "if", "intio", "ascio",
)
MATH_COMMANDS = (
    "noop", "load", "store", "add", "mult", "div", "zero", "lt",
    "gt", "eq", "not", "neg",
)


def _bounded_int(value: int, *, label: str = "integer") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise Refuse(f"{label} must be an integer")
    if value.bit_length() > MAX_INTEGER_BITS:
        raise Refuse(f"{label} exceeds {MAX_INTEGER_BITS}-bit analysis bound")
    return value


def _trunc_div(left: int, right: int) -> int:
    if right == 0:
        raise Refuse("Whirl division by zero")
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) ^ (right < 0) else quotient


def run_whirl(
    source: str,
    *,
    integer_input: Sequence[int] = (),
    character_input: str = "",
    max_steps: int = MAX_STEPS,
    max_output: int = MAX_OUTPUT_CHARS,
) -> dict[str, Any]:
    """Interpret Whirl from text with explicit saved input values."""

    if not isinstance(source, str):
        raise Refuse("Whirl source must be text")
    if len(source) > MAX_SOURCE_CHARS:
        raise Refuse("Whirl source exceeds size bound")
    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or not 1 <= max_steps <= MAX_STEPS:
        raise Refuse(f"max_steps must be in 1..{MAX_STEPS}")
    if not isinstance(max_output, int) or isinstance(max_output, bool) or not 1 <= max_output <= MAX_OUTPUT_CHARS:
        raise Refuse(f"max_output must be in 1..{MAX_OUTPUT_CHARS}")
    program = "".join(ch for ch in source if ch in "01")
    if not program:
        raise Refuse("Whirl source contains no instructions")

    if (
        not isinstance(integer_input, Sequence)
        or isinstance(integer_input, (str, bytes, bytearray))
        or len(integer_input) > MAX_OUTPUT_CHARS
    ):
        raise Refuse("Whirl integer input must be a bounded sequence")
    if not isinstance(character_input, str) or len(character_input) > MAX_OUTPUT_CHARS:
        raise Refuse("Whirl character input must be bounded text")
    ints = [_bounded_int(value, label="Whirl integer input") for value in integer_input]
    chars = [ord(ch) for ch in character_input]
    if any(value > 0xFF for value in chars):
        raise Refuse("Whirl character input must use byte/ASCII values")
    int_index = char_index = 0
    active = 0  # Operations=0, Math=1.
    positions = [0, 0]
    directions = [1, 1]  # +1 is clockwise.
    values = [0, 0]
    memory: dict[int, int] = {0: 0}
    memory_pointer = pc = steps = executions = 0
    execute_latch = False
    output_parts: list[str] = []
    output_length = 0
    stop_reason = "end_of_program"
    trace: list[dict[str, Any]] = []

    def append_output(piece: str) -> None:
        nonlocal output_length
        if output_length + len(piece) > max_output:
            raise Refuse("Whirl output exceeds bound")
        output_parts.append(piece)
        output_length += len(piece)

    while 0 <= pc < len(program):
        if steps >= max_steps:
            stop_reason = "step_limit"
            break
        steps += 1
        instruction_pc = pc
        instruction = program[pc]
        next_pc = pc + 1
        if instruction == "1":
            positions[active] = (positions[active] + directions[active]) % 12
            execute_latch = False
        else:
            directions[active] *= -1
            if not execute_latch:
                execute_latch = True
            else:
                execute_latch = False
                ring = active
                command = (OPS_COMMANDS, MATH_COMMANDS)[ring][positions[ring]]
                executions += 1
                memval = memory.get(memory_pointer, 0)
                event: dict[str, Any] = {
                    "pc": instruction_pc,
                    "ring": "operations" if ring == 0 else "math",
                    "command": command,
                    "memory_pointer": memory_pointer,
                    "memory_value_before": memval,
                    "ring_value_before": values[ring],
                }
                if ring == 0:
                    if command == "exit":
                        stop_reason = "exit"
                    elif command == "one":
                        values[ring] = 1
                    elif command == "zero":
                        values[ring] = 0
                    elif command == "load":
                        values[ring] = memval
                    elif command == "store":
                        memory[memory_pointer] = values[ring]
                    elif command in {"padd", "if"}:
                        if command == "padd" or memval != 0:
                            # Reference behavior: assign current_pc + value and
                            # suppress the ordinary increment for this cycle.
                            target = instruction_pc + values[ring]
                            if not 0 <= target < len(program):
                                stop_reason = "program_pointer_out_of_bounds"
                            else:
                                next_pc = target
                    elif command == "dadd":
                        target = memory_pointer + values[ring]
                        if target < 0:
                            stop_reason = "memory_pointer_out_of_bounds"
                        elif target >= MAX_MEMORY_CELLS:
                            raise Refuse("Whirl memory pointer exceeds bound")
                        else:
                            memory_pointer = target
                            memory.setdefault(target, 0)
                    elif command == "logic":
                        values[ring] = int(values[ring] != 0) if memval != 0 else 0
                    elif command == "intio":
                        if values[ring] == 0:
                            if int_index >= len(ints):
                                raise Refuse("Whirl requested unavailable integer input")
                            memory[memory_pointer] = ints[int_index]
                            int_index += 1
                        else:
                            append_output(str(memval))
                    elif command == "ascio":
                        if values[ring] == 0:
                            if char_index >= len(chars):
                                raise Refuse("Whirl requested unavailable character input")
                            memory[memory_pointer] = chars[char_index]
                            char_index += 1
                        else:
                            # The reference uses C `%c`: model it as a bounded
                            # byte, rather than silently accepting Unicode.
                            if not 0 <= memval <= 0xFF:
                                raise Refuse("Whirl character output is outside byte range")
                            append_output(chr(memval))
                else:
                    if command == "load":
                        values[ring] = memval
                    elif command == "store":
                        memory[memory_pointer] = values[ring]
                    elif command == "add":
                        values[ring] += memval
                    elif command == "mult":
                        values[ring] *= memval
                    elif command == "div":
                        values[ring] = _trunc_div(values[ring], memval)
                    elif command == "zero":
                        values[ring] = 0
                    elif command == "lt":
                        values[ring] = int(values[ring] < memval)
                    elif command == "gt":
                        values[ring] = int(values[ring] > memval)
                    elif command == "eq":
                        values[ring] = int(values[ring] == memval)
                    elif command == "not":
                        values[ring] = int(values[ring] == 0)
                    elif command == "neg":
                        values[ring] = -values[ring]

                values[ring] = _bounded_int(values[ring], label="Whirl ring value")
                memory[memory_pointer] = _bounded_int(
                    memory.get(memory_pointer, 0), label="Whirl memory value"
                )
                event.update({
                    "memory_pointer_after": memory_pointer,
                    "memory_value_after": memory.get(memory_pointer, 0),
                    "ring_value_after": values[ring],
                })
                if len(trace) < 1_024:
                    trace.append(event)
                # The reference returns from cur->execute() before switching
                # rings for Exit and invalid PAdd/DAdd destinations.
                if stop_reason == "end_of_program":
                    active = 1 - active
                else:
                    pc = instruction_pc
                    break
        pc = next_pc

    return {
        "language": "whirl",
        "output": "".join(output_parts),
        "steps": steps,
        "command_executions": executions,
        "stop_reason": stop_reason,
        "program_counter": pc,
        "active_ring": "operations" if active == 0 else "math",
        "ring_positions": {"operations": positions[0], "math": positions[1]},
        "ring_directions": {
            "operations": "clockwise" if directions[0] == 1 else "counterclockwise",
            "math": "clockwise" if directions[1] == 1 else "counterclockwise",
        },
        "ring_values": {"operations": values[0], "math": values[1]},
        "memory_pointer": memory_pointer,
        "memory": {str(key): memory[key] for key in sorted(memory)},
        "input_consumed": {"integers": int_index, "characters": char_index},
        "trace": trace,
        "candidate": True,
        "requires_human_confirmation": True,
    }


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    offset: int


@dataclass(frozen=True)
class _Operand:
    kind: str
    value: str | int


@dataclass(frozen=True)
class _Chain:
    operands: tuple[_Operand, ...]
    operators: tuple[str, ...]


@dataclass(frozen=True)
class _Loop:
    stack: str
    body: tuple["_Statement", ...]


_Statement = _Chain | _Loop


def _lex_kipple(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    cursor = 0
    while cursor < len(source):
        ch = source[cursor]
        if ch.isspace():
            cursor += 1
            continue
        if ch == "#":
            newline = source.find("\n", cursor)
            cursor = len(source) if newline < 0 else newline + 1
            continue
        if ch.isdigit():
            end = cursor + 1
            while end < len(source) and source[end].isdigit():
                end += 1
            raw = source[cursor:end]
            if len(raw) > 10 or (len(raw) == 10 and raw > "2147483647"):
                raise Refuse("Kipple literal exceeds signed 32-bit maximum")
            tokens.append(_Token("operand", raw, cursor))
            cursor = end
            continue
        if "a" <= ch <= "z" or ch == "@":
            tokens.append(_Token("operand", ch, cursor))
            cursor += 1
            continue
        if ch in "><+-?()":
            tokens.append(_Token(ch, ch, cursor))
            cursor += 1
            continue
        if ch == '"':
            end = cursor + 1
            value: list[str] = []
            while end < len(source) and source[end] != '"':
                if source[end] == "\\":
                    end += 1
                    if end >= len(source):
                        raise Refuse("unterminated Kipple string escape")
                    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}
                    if source[end] not in escapes:
                        raise Refuse("unsupported Kipple string escape")
                    value.append(escapes[source[end]])
                else:
                    value.append(source[end])
                end += 1
            if end >= len(source):
                raise Refuse("unterminated Kipple string")
            tokens.append(_Token("string", "".join(value), cursor))
            cursor = end + 1
            continue
        raise Refuse(f"invalid Kipple character at offset {cursor}")
    return tokens


def _operand(token: _Token) -> _Operand:
    if token.kind == "string":
        return _Operand("string", token.value)
    if token.kind != "operand":
        raise Refuse(f"expected Kipple operand at offset {token.offset}")
    if token.value.isdigit():
        return _Operand("integer", int(token.value))
    return _Operand("stack", token.value)


class _KippleParser:
    def __init__(self, tokens: Sequence[_Token]):
        self.tokens = tokens
        self.index = 0

    def parse(self) -> tuple[_Statement, ...]:
        result = self._program(depth=0, in_loop=False)
        if self.index != len(self.tokens):
            token = self.tokens[self.index]
            raise Refuse(f"unexpected Kipple token at offset {token.offset}")
        return tuple(result)

    def _program(
        self,
        *,
        depth: int,
        in_loop: bool,
        prefix: _Operand | None = None,
    ) -> list[_Statement]:
        if depth > MAX_NESTING:
            raise Refuse("Kipple nesting exceeds bound")
        statements: list[_Statement] = []
        if prefix is not None and self.index < len(self.tokens) and self.tokens[self.index].kind in {
            ">", "<", "+", "-", "?",
        }:
            statements.append(self._chain(prefix))
        while self.index < len(self.tokens):
            token = self.tokens[self.index]
            if token.kind == ")":
                if not in_loop:
                    raise Refuse(f"unmatched ')' at offset {token.offset}")
                return statements
            if token.kind == "(":
                self.index += 1
                if self.index >= len(self.tokens):
                    raise Refuse("Kipple loop is missing its controlling stack")
                control = _operand(self.tokens[self.index])
                if control.kind != "stack":
                    raise Refuse("Kipple loop controller must be a stack")
                self.index += 1
                # In compact official syntax `(i>o)`, the controller is also
                # the implicit left operand of the first body operation.
                body = self._program(depth=depth + 1, in_loop=True, prefix=control)
                if self.index >= len(self.tokens) or self.tokens[self.index].kind != ")":
                    raise Refuse("unterminated Kipple loop")
                self.index += 1
                statements.append(_Loop(str(control.value), tuple(body)))
                continue

            if token.kind not in {"operand", "string"}:
                raise Refuse(f"expected Kipple operand at offset {token.offset}")
            left = _operand(token)
            self.index += 1
            if self.index >= len(self.tokens) or self.tokens[self.index].kind not in {
                ">", "<", "+", "-", "?",
            }:
                # Core Kipple ignores values not adjacent to an operator.
                continue
            statements.append(self._chain(left))
        if in_loop:
            raise Refuse("unterminated Kipple loop")
        return statements

    def _chain(self, left: _Operand) -> _Chain:
        if self.index >= len(self.tokens):
            raise Refuse("bare Kipple operand has no operator")
        operator = self.tokens[self.index]
        if operator.kind == "?":
            if left.kind != "stack":
                raise Refuse("Kipple '?' requires a stack")
            self.index += 1
            return _Chain((left,), ("?",))
        if operator.kind not in {">", "<", "+", "-"}:
            raise Refuse(f"expected Kipple operator at offset {operator.offset}")
        operands = [left]
        operators: list[str] = []
        while self.index < len(self.tokens) and self.tokens[self.index].kind in {
            ">", "<", "+", "-",
        }:
            operator = self.tokens[self.index]
            self.index += 1
            if self.index >= len(self.tokens) or self.tokens[self.index].kind not in {
                "operand", "string",
            }:
                raise Refuse(f"missing Kipple right operand at offset {operator.offset}")
            operators.append(operator.kind)
            operands.append(_operand(self.tokens[self.index]))
            self.index += 1
        if self.index < len(self.tokens) and self.tokens[self.index].kind == "?":
            if operands[-1].kind != "stack":
                raise Refuse("Kipple trailing '?' requires a stack")
            operators.append("?")
            self.index += 1
        return _Chain(tuple(operands), tuple(operators))


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def run_kipple(
    source: str,
    *,
    input_text: str = "",
    max_steps: int = MAX_STEPS,
    max_stack_items: int = MAX_STACK_ITEMS,
    max_output: int = MAX_OUTPUT_CHARS,
) -> dict[str, Any]:
    """Interpret bounded Kipple core syntax and its official string extension."""

    if not isinstance(source, str) or not isinstance(input_text, str):
        raise Refuse("Kipple source and input must be text")
    if len(source) > MAX_SOURCE_CHARS or len(input_text) > MAX_OUTPUT_CHARS:
        raise Refuse("Kipple source or input exceeds size bound")
    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or not 1 <= max_steps <= MAX_STEPS:
        raise Refuse(f"max_steps must be in 1..{MAX_STEPS}")
    if not isinstance(max_stack_items, int) or isinstance(max_stack_items, bool) or not 1 <= max_stack_items <= MAX_STACK_ITEMS:
        raise Refuse(f"max_stack_items must be in 1..{MAX_STACK_ITEMS}")
    if not isinstance(max_output, int) or isinstance(max_output, bool) or not 1 <= max_output <= MAX_OUTPUT_CHARS:
        raise Refuse(f"max_output must be in 1..{MAX_OUTPUT_CHARS}")

    statements = _KippleParser(_lex_kipple(source)).parse()
    stacks: dict[str, list[int]] = {chr(code): [] for code in range(ord("a"), ord("z") + 1)}
    stacks["@"] = []
    for ch in input_text:
        stacks["i"].append(ord(ch))
    if len(stacks["i"]) > max_stack_items:
        raise Refuse("Kipple input exceeds stack-item bound")

    steps = 0
    item_count = len(stacks["i"])
    peak_items = item_count

    def account() -> None:
        nonlocal steps
        steps += 1
        if steps > max_steps:
            raise Refuse("Kipple step bound exceeded")

    def pop_stack(name: str) -> int:
        nonlocal item_count
        if not stacks[name]:
            return 0
        item_count -= 1
        return stacks[name].pop()

    def clear_stack(name: str) -> None:
        nonlocal item_count
        item_count -= len(stacks[name])
        stacks[name].clear()

    def read_operand(operand: _Operand) -> int:
        if operand.kind == "integer":
            return int(operand.value)
        if operand.kind == "stack":
            return pop_stack(str(operand.value))
        raise Refuse("Kipple string is not a scalar arithmetic operand")

    def push_raw(name: str, value: int) -> None:
        nonlocal item_count, peak_items
        stacks[name].append(_i32(value))
        item_count += 1
        if item_count > max_stack_items:
            raise Refuse("Kipple stack-item bound exceeded")
        peak_items = max(peak_items, item_count)

    def push_one(name: str, value: int) -> None:
        if name == "@":
            # Push natural digit order: the least-significant character is top.
            for char in str(_i32(value)):
                push_raw(name, ord(char))
        else:
            push_raw(name, value)

    def push_string(name: str, value: str, *, reverse: bool) -> None:
        # Official preprocessing is asymmetric: `"Hi">s` expands to reversed
        # pushes, while `s<"Hi"` expands to forward pushes.
        characters = reversed(value) if reverse else value
        for char in characters:
            push_one(name, ord(char))

    def execute_chain(chain: _Chain) -> None:
        if chain.operators == ("?",):
            account()
            name = str(chain.operands[0].value)
            if (stacks[name][-1] if stacks[name] else 0) == 0:
                clear_stack(name)
            return
        # A merged chain evaluates each syntactic operand at most once.  Thus
        # `a<b>c` pops b once and copies that same value to both a and c.
        scalar_cache: dict[int, int] = {}

        def scalar(index: int) -> int:
            if index not in scalar_cache:
                scalar_cache[index] = read_operand(chain.operands[index])
            return scalar_cache[index]

        for index, operator in enumerate(chain.operators):
            account()
            left = chain.operands[index]
            if operator == "?":
                name = str(left.value)
                if (stacks[name][-1] if stacks[name] else 0) == 0:
                    clear_stack(name)
                continue
            right = chain.operands[index + 1]
            if operator == ">":
                if right.kind != "stack":
                    raise Refuse("Kipple '>' destination must be a stack")
                destination = str(right.value)
                if left.kind == "string":
                    push_string(destination, str(left.value), reverse=True)
                else:
                    push_one(destination, scalar(index))
            elif operator == "<":
                if left.kind != "stack":
                    raise Refuse("Kipple '<' destination must be a stack")
                destination = str(left.value)
                if right.kind == "string":
                    push_string(destination, str(right.value), reverse=False)
                else:
                    push_one(destination, scalar(index + 1))
            else:
                if left.kind != "stack" or left.value == "@":
                    raise Refuse("Kipple arithmetic left operand must be a stack a-z")
                # Pop/read the right operand first.  For `a+a`, the left top is
                # consequently the item below the popped right operand.
                right_value = scalar(index + 1)
                name = str(left.value)
                left_top = stacks[name][-1] if stacks[name] else 0
                push_one(name, left_top + right_value if operator == "+" else left_top - right_value)

    def execute_program(program: Iterable[_Statement], depth: int = 0) -> None:
        if depth > MAX_NESTING:
            raise Refuse("Kipple runtime nesting exceeds bound")
        for statement in program:
            if isinstance(statement, _Chain):
                execute_chain(statement)
            else:
                while stacks[statement.stack]:
                    account()  # Loop dispatch is bounded independently of body.
                    execute_program(statement.body, depth + 1)

    execute_program(statements)
    output_values: list[int] = []
    while stacks["o"]:
        if len(output_values) >= max_output:
            raise Refuse("Kipple output exceeds bound")
        output_values.append(pop_stack("o"))
    if any(not 0 <= value <= 0xFF for value in output_values):
        raise Refuse("Kipple output contains a value outside ASCII byte range")
    output = "".join(chr(value) for value in output_values)
    nonempty = {name: list(values) for name, values in stacks.items() if values}
    return {
        "language": "kipple",
        "output": output,
        "output_values": output_values,
        "steps": steps,
        "peak_stack_items": peak_items,
        "stacks": nonempty,
        "string_preprocessor_used": '"' in source,
        "candidate": True,
        "requires_human_confirmation": True,
    }


def identify_esolangs(source: str, *, filename: str = "") -> list[dict[str, Any]]:
    """Return evidence-backed candidates, never an asserted classification."""

    if not isinstance(source, str) or len(source) > MAX_SOURCE_CHARS:
        raise Refuse("source must be bounded text")
    suffix = Path(filename).suffix.casefold()
    candidates: list[dict[str, Any]] = []

    binary = "".join(ch for ch in source if ch in "01")
    significant = "".join(ch for ch in source if not ch.isspace())
    binary_ratio = len(binary) / max(1, len(significant))
    whirl_evidence: list[str] = []
    whirl_score = 0.0
    if suffix in {".wrl", ".whirl"}:
        whirl_score += 0.42
        whirl_evidence.append("Whirl filename suffix")
    if len(binary) >= 16 and binary_ratio >= 0.98:
        whirl_score += 0.38
        whirl_evidence.append("long binary-only instruction stream")
    if binary.count("00") >= 2:
        whirl_score += 0.18
        whirl_evidence.append("multiple 00 command-execution latches")
    if whirl_score >= 0.45:
        candidates.append({
            "language": "whirl",
            "confidence": round(min(0.99, whirl_score), 3),
            "evidence": whirl_evidence,
        })

    kipple_evidence: list[str] = []
    kipple_score = 0.0
    if suffix in {".kip", ".kipple"}:
        kipple_score += 0.46
        kipple_evidence.append("Kipple filename suffix")
    transfers = re.findall(r'(?:\d+|[a-z@]|"[^"\n]*")[<>](?:[a-z@]|\d+)', source)
    arithmetic = re.findall(r"[a-z](?:[+-](?:[a-z@]|\d+)|\?)", source)
    loops = re.findall(r"\([a-z](?=[\s\da-z@\"(])", source)
    if len(transfers) + len(arithmetic) >= 2:
        kipple_score += 0.31
        kipple_evidence.append("repeated stack-transfer/arithmetic syntax")
    if loops:
        kipple_score += 0.19
        kipple_evidence.append("parenthesized stack-controlled loop")
    if "@" in source and (">@" in source or "@>" in source):
        kipple_score += 0.12
        kipple_evidence.append("Kipple digit-stack use")
    try:
        if source.strip():
            _KippleParser(_lex_kipple(source)).parse()
            if transfers or arithmetic or loops:
                kipple_score += 0.12
                kipple_evidence.append("complete bounded Kipple parse")
    except Refuse:
        pass
    if kipple_score >= 0.45:
        candidates.append({
            "language": "kipple",
            "confidence": round(min(0.99, kipple_score), 3),
            "evidence": kipple_evidence,
        })

    candidates.sort(key=lambda item: (-item["confidence"], item["language"]))
    return candidates


def analyze(source: str, *, filename: str = "") -> dict[str, Any]:
    return {
        "candidates": identify_esolangs(source, filename=filename),
        "candidate_only": True,
        "requires_human_confirmation": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="source file to inspect")
    parser.add_argument("--language", choices=("identify", "whirl", "kipple"), default="identify")
    parser.add_argument("--input", default="", help="saved character input; never live stdin")
    parser.add_argument("--integer", action="append", type=int, default=[])
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:               # argparse exits 0 on --help, 2 on a usage error
        return 0 if (exc.code or 0) == 0 else 2
    path = Path(args.path)
    source = path.read_text(encoding="utf-8", errors="replace")
    if args.language == "whirl":
        result = run_whirl(source, integer_input=args.integer, character_input=args.input)
    elif args.language == "kipple":
        result = run_kipple(source, input_text=args.input)
    else:
        result = analyze(source, filename=path.name)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["Refuse", "analyze", "identify_esolangs", "run_kipple", "run_whirl"]
