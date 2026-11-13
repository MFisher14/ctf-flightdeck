#!/usr/bin/env python3
"""Bounded, data-only interpreters for two previously uncovered CTF esolangs.

The module implements the standard Aheui core (Hangul grid, 28 storages, queue,
arithmetic, control flow and explicit input/output) and Modular SNUSP.  Source is
never evaluated as host code.  Every mutable resource has a hard cap, and the
identifiers deliberately require structural evidence instead of treating any
Korean text or Brainfuck-looking fragment as a program.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path
from typing import Iterable


MAX_SOURCE = 2 << 20
MAX_CELLS = 262_144
MAX_STEPS = 1_000_000
MAX_STORAGE = 100_000
MAX_OUTPUT = 1 << 20
MAX_CALL_DEPTH = 4096
MAX_INTEGER_BITS = 4096


class Refuse(ValueError):
    """The artifact is malformed, unsupported, or exceeded a safety bound."""


# Hangul syllable decomposition indices (Unicode AC00 algorithm).
CHOSEONG = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
JUNGSEONG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
JONGSEONG = "\0ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"

# Number of strokes for the final consonant.  ㅇ and ㅎ are I/O selectors for
# push/pop, so their numeric entries are intentionally absent.
STROKES = (0, 2, 4, 4, 2, 5, 5, 3, 5, 7, 9, 9, 7, 9, 9, 8,
           4, 4, 6, 2, 4, None, 3, 4, 3, 4, 4, None)
QUEUE_STORAGE = 21  # final ㅇ
EXTENSION_STORAGE = 27  # final ㅎ; unsupported extension protocol


def compose_aheui(initial: int, vowel: int = 0, final: int = 0) -> str:
    """Compose one Hangul instruction; useful for exact fixtures and tooling."""
    if not (0 <= initial < 19 and 0 <= vowel < 21 and 0 <= final < 28):
        raise Refuse("invalid Hangul component index")
    return chr(0xAC00 + (initial * 21 + vowel) * 28 + final)


def decompose_aheui(char: str) -> tuple[int, int, int] | None:
    if not isinstance(char, str) or len(char) != 1:
        return None
    value = ord(char) - 0xAC00
    if not 0 <= value < 19 * 21 * 28:
        return None
    return value // 588, value % 588 // 28, value % 28


def _grid(source: str) -> list[list[str]]:
    if not isinstance(source, str) or len(source.encode("utf-8", "surrogatepass")) > MAX_SOURCE:
        raise Refuse("source exceeds 2 MiB")
    lines = source.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise Refuse("empty source")
    width = max(map(len, lines), default=0)
    if not width or width * len(lines) > MAX_CELLS:
        raise Refuse("program grid exceeds cell bound")
    return [list(line.ljust(width)) for line in lines]


def _bounded_int(value: int) -> int:
    if not isinstance(value, int) or value.bit_length() > MAX_INTEGER_BITS:
        raise Refuse("integer exceeds bit bound")
    return value


def run_aheui(source: str, *, number_input: Iterable[int] = (), char_input: str = "",
              steps: int = MAX_STEPS) -> dict:
    """Run standard core Aheui and return an evidence report.

    The extension-protocol storage (final ㅎ selected by ㅅ/ㅆ) is declined because
    its behavior is implementation-defined.  EOF produces -1, matching common
    Aheui implementations.  No implicit answer/flag decision is made.
    """
    grid = _grid(source)
    height, width = len(grid), len(grid[0])
    if not isinstance(steps, int) or isinstance(steps, bool):
        raise Refuse("steps must be an integer")
    limit = min(max(1, int(steps)), MAX_STEPS)
    # Do not materialize an arbitrary/infinite iterable before enforcing the cap.
    # A challenge harness may supply a generator, so consume at most cap+1 items.
    try:
        iterator = iter(number_input)
    except TypeError as exc:
        raise Refuse("number input must be an iterable of integers") from exc
    numbers = []
    for value in iterator:
        if len(numbers) >= MAX_STORAGE:
            raise Refuse("number input exceeds bound")
        if isinstance(value, bool) or not isinstance(value, int) or value.bit_length() > MAX_INTEGER_BITS:
            raise Refuse("number input exceeds bound")
        numbers.append(value)
    if not isinstance(char_input, str) or len(char_input.encode("utf-8", "surrogatepass")) > MAX_SOURCE:
        raise Refuse("character input exceeds bound")
    number_at = char_at = 0

    stores = [deque() for _ in range(28)]
    current = 0
    total_values = 0
    output = bytearray()
    row = col = 0
    dy, dx = 1, 0

    def store_pop(index: int) -> int:
        nonlocal total_values
        storage = stores[index]
        value = storage.popleft() if index == QUEUE_STORAGE else storage.pop()
        total_values -= 1
        return value

    def store_peek(index: int) -> int:
        storage = stores[index]
        return storage[0] if index == QUEUE_STORAGE else storage[-1]

    def store_push(index: int, value: int) -> None:
        nonlocal total_values
        if index == EXTENSION_STORAGE:
            raise Refuse("Aheui extension-protocol storage is unsupported")
        if total_values >= MAX_STORAGE:
            raise Refuse("storage value cap")
        stores[index].append(_bounded_int(value))
        total_values += 1

    def reverse() -> None:
        nonlocal dy, dx
        dy, dx = -dy, -dx

    def enough(count: int) -> bool:
        return len(stores[current]) >= count

    for tick in range(1, limit + 1):
        parts = decompose_aheui(grid[row][col])
        if parts is not None:
            initial, vowel, final = parts
            if initial == 18:  # ㅎ: terminate
                exit_value = store_pop(current) if stores[current] else 0
                return {
                    "language": "aheui", "halted": True, "steps": tick,
                    "exit_value": exit_value, "output_hex": bytes(output).hex(),
                    "output_text": bytes(output).decode("utf-8", "replace"),
                    "remaining_values": total_values, "candidate_only": True,
                    "requires_human_review": True,
                }
            if initial in {2, 3, 4, 5, 16}:  # div/add/mul/mod/sub
                if not enough(2):
                    reverse()
                else:
                    first, second = store_pop(current), store_pop(current)
                    if initial in {2, 5} and first == 0:
                        raise Refuse("division or modulo by zero")
                    if initial == 2:
                        value = second // first
                    elif initial == 3:
                        value = second + first
                    elif initial == 4:
                        value = second * first
                    elif initial == 5:
                        value = second % first
                    else:
                        value = second - first
                    store_push(current, value)
            elif initial == 6:  # ㅁ: pop / output
                if not enough(1):
                    reverse()
                else:
                    value = store_pop(current)
                    if final == QUEUE_STORAGE:
                        rendered = str(value).encode("ascii")
                        if len(output) + len(rendered) > MAX_OUTPUT:
                            raise Refuse("output cap")
                        output.extend(rendered)
                    elif final == EXTENSION_STORAGE:
                        if not 0 <= value <= 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                            raise Refuse("invalid Unicode scalar output")
                        rendered = chr(value).encode("utf-8")
                        if len(output) + len(rendered) > MAX_OUTPUT:
                            raise Refuse("output cap")
                        output.extend(rendered)
            elif initial == 7:  # ㅂ: push / input
                if final == QUEUE_STORAGE:
                    value = numbers[number_at] if number_at < len(numbers) else -1
                    if number_at < len(numbers):
                        number_at += 1
                elif final == EXTENSION_STORAGE:
                    value = ord(char_input[char_at]) if char_at < len(char_input) else -1
                    if char_at < len(char_input):
                        char_at += 1
                else:
                    value = STROKES[final]
                    if value is None:
                        raise Refuse("invalid stroke constant")
                store_push(current, value)
            elif initial == 8:  # ㅃ: duplicate
                if not enough(1):
                    reverse()
                else:
                    store_push(current, store_peek(current))
            elif initial == 17:  # ㅍ: swap
                if not enough(2):
                    reverse()
                elif current == QUEUE_STORAGE:
                    first, second = stores[current].popleft(), stores[current].popleft()
                    stores[current].appendleft(first)
                    stores[current].appendleft(second)
                else:
                    stores[current][-1], stores[current][-2] = stores[current][-2], stores[current][-1]
            elif initial == 9:  # ㅅ: select storage
                if final == EXTENSION_STORAGE:
                    raise Refuse("Aheui extension-protocol storage is unsupported")
                current = final
            elif initial == 10:  # ㅆ: transfer
                if not enough(1):
                    reverse()
                elif final == EXTENSION_STORAGE:
                    raise Refuse("Aheui extension-protocol storage is unsupported")
                else:
                    store_push(final, store_pop(current))
            elif initial == 12:  # ㅈ: greater-or-equal comparison
                if not enough(2):
                    reverse()
                else:
                    first, second = store_pop(current), store_pop(current)
                    store_push(current, int(second >= first))
            elif initial == 14:  # ㅊ: conditional fork
                if not enough(1):
                    reverse()
                elif store_pop(current) == 0:
                    reverse()

            # Vowel momentum is applied after any instruction-triggered reversal.
            absolute = {0: (0, 1), 2: (0, 2), 4: (0, -1), 6: (0, -2),
                        8: (-1, 0), 12: (-2, 0), 13: (1, 0), 17: (2, 0)}
            if vowel in absolute:
                dy, dx = absolute[vowel]
            elif vowel == 18:  # ㅡ reflects vertical movement
                dy = -dy
            elif vowel == 20:  # ㅣ reflects horizontal movement
                dx = -dx
            elif vowel == 19:  # ㅢ reflects either axis
                dy, dx = -dy, -dx

        row = (row + dy) % height
        col = (col + dx) % width
    raise Refuse("Aheui step cap reached without termination")


def identify_aheui(source: str, *, filename: str = "") -> dict:
    """Conservative structural identification; never declares natural Korean alone a program."""
    if not isinstance(source, str):
        raise Refuse("source must be text")
    chars = [char for char in source if not char.isspace()]
    parts = [decompose_aheui(char) for char in chars]
    hangul = [part for part in parts if part is not None]
    operations = [part for part in hangul if part[0] in {2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 17, 18}]
    directional = [part for part in hangul if part[1] in {0, 2, 4, 6, 8, 12, 13, 17, 18, 19, 20}]
    has_halt = any(part[0] == 18 for part in hangul)
    suffix = filename.lower().endswith((".aheui", ".aheui.txt"))
    strong = bool(suffix and len(hangul) >= 4 and has_halt and len(operations) >= 3 and directional)
    return {"language": "aheui", "hangul_cells": len(hangul), "operation_cells": len(operations),
            "has_halt": has_halt, "filename_evidence": suffix, "strong_match": strong,
            "candidate_only": True, "note": "Hangul content without suffix evidence is never auto-routed"}


def run_snusp(source: str, input_data: bytes = b"", *, steps: int = MAX_STEPS,
              cell_bits: int = 8) -> dict:
    """Run Core/Modular SNUSP using a bounded one-dimensional byte-cell tape."""
    grid = _grid(source)
    if not isinstance(input_data, bytes) or len(input_data) > MAX_SOURCE:
        raise Refuse("input exceeds bound")
    if cell_bits not in (8, 16, 32):
        raise Refuse("cell_bits must be 8, 16, or 32")
    mask = (1 << cell_bits) - 1
    height, width = len(grid), len(grid[0])
    start = next(((x, y) for y, line in enumerate(grid) for x, char in enumerate(line) if char == "$"),
                 (0, 0))
    x, y = start
    dx, dy = 1, 0
    pointer = 0
    tape = [0]
    call_stack: list[tuple[int, int, int, int]] = []
    output = bytearray()
    input_at = 0
    if not isinstance(steps, int) or isinstance(steps, bool):
        raise Refuse("steps must be an integer")
    limit = min(max(1, int(steps)), MAX_STEPS)
    halted = False

    for tick in range(1, limit + 1):
        if not (0 <= x < width and 0 <= y < height):
            halted = True
            break
        op = grid[y][x]
        if op == ">":
            pointer += 1
            if pointer >= MAX_STORAGE:
                raise Refuse("SNUSP tape cap")
            if pointer == len(tape):
                tape.append(0)
        elif op == "<":
            if pointer == 0:
                raise Refuse("SNUSP negative data pointer")
            pointer -= 1
        elif op == "+":
            tape[pointer] = (tape[pointer] + 1) & mask
        elif op == "-":
            tape[pointer] = (tape[pointer] - 1) & mask
        elif op == ",":
            tape[pointer] = input_data[input_at] if input_at < len(input_data) else 0
            input_at += input_at < len(input_data)
        elif op == ".":
            if len(output) >= MAX_OUTPUT:
                raise Refuse("SNUSP output cap")
            output.append(tape[pointer] & 0xFF)
        elif op == "/":
            dx, dy = -dy, -dx
        elif op == "\\":
            dx, dy = dy, dx
        elif op == "!":
            x, y = x + dx, y + dy
        elif op == "?" and tape[pointer] == 0:
            x, y = x + dx, y + dy
        elif op == "@":
            if len(call_stack) >= MAX_CALL_DEPTH:
                raise Refuse("SNUSP call depth cap")
            call_stack.append((x + dx, y + dy, dx, dy))
        elif op == "#":
            if not call_stack:
                halted = True
                break
            x, y, dx, dy = call_stack.pop()
        x, y = x + dx, y + dy
    else:
        raise Refuse("SNUSP step cap reached without leaving the grid")

    return {"language": "snusp", "halted": halted, "steps": tick,
            "output_hex": bytes(output).hex(), "output_text": bytes(output).decode("utf-8", "replace"),
            "data_pointer": pointer, "current_cell": tape[pointer], "call_depth": len(call_stack),
            "candidate_only": True, "requires_human_review": True}


def identify_snusp(source: str, *, filename: str = "") -> dict:
    if not isinstance(source, str):
        raise Refuse("source must be text")
    instructions = [char for char in source if char in "<>+-,./\\!?@#$"]
    flow = [char for char in instructions if char in "/\\!?@#"]
    data = [char for char in instructions if char in "<>+-,."]
    suffix = filename.lower().endswith((".snusp", ".snusp.txt"))
    strong = bool(len(instructions) >= 5 and len(flow) >= 1 and len(data) >= 2 and ("$" in source or suffix))
    return {"language": "snusp", "instructions": len(instructions), "flow_instructions": len(flow),
            "data_instructions": len(data), "start_marker": "$" in source,
            "filename_evidence": suffix, "strong_match": strong, "candidate_only": True}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise Refuse(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="bounded Aheui and Modular SNUSP artifact interpreter")
    parser.add_argument("language", choices=("aheui", "snusp", "identify"))
    parser.add_argument("input")
    parser.add_argument("--stdin-text", default="", help="explicit offline input text")
    try:
        args = parser.parse_args(argv)
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_SOURCE:
            raise Refuse("source exceeds 2 MiB")
        source = raw.decode("utf-8", "strict")
        if args.language == "aheui":
            result = run_aheui(source, char_input=args.stdin_text)
        elif args.language == "snusp":
            result = run_snusp(source, args.stdin_text.encode())
        else:
            result = {"aheui": identify_aheui(source, filename=args.input),
                      "snusp": identify_snusp(source, filename=args.input), "answer": None}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except SystemExit as exc:               # argparse --help exits 0; keep it a clean return
        return 0 if (exc.code or 0) == 0 else 2
    except (OSError, UnicodeError, Refuse, ValueError, TypeError, OverflowError, MemoryError) as exc:
        print(f"esolangs_remaining: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
