#!/usr/bin/env python3
"""Chicken esolang VM (B-055). The language whose only token is the word "chicken".

Chicken (Torbjorn Soderstedt, esolangs.org) encodes a program as lines; the opcode of a line is the
number of "chicken" tokens on it. There is a single self-referential stack: slot 0 holds the program
(the opcode list), slot 1 holds the user input, and execution pushes and pops above them. This module
is a bounded, offline interpreter of that model. Nothing here runs a downloaded file: the source is
counted into opcodes and the opcodes are walked with a hard step cap and no I/O.

Opcode table (opcode = count of "chicken" on the line):

    0   axe       halt the program
    1   chicken   push the string "chicken"
    2   add       b = pop, a = pop; push a + b   (numbers add; strings concatenate)
    3   fox       b = pop, a = pop; push a - b
    4   rooster   b = pop, a = pop; push a * b
    5   compare   b = pop, a = pop; push (a == b) as 1 / 0
    6   pick      DOUBLE-WIDE: s = the next opcode (the source selector), i = pop (the index);
                  push source[i], where source is the stack when s == 0 and the input when s == 1
    7   peck      addr = pop, v = pop; stack[addr] = v       (B-250; addr 0/1 or past the top is loud)
    8   fr        offset = pop, cond = pop; when cond is not 0 jump `offset` opcodes on from the one
                  after fr (B-250; a jump before the start is loud)
    9   BBQ       v = pop; push the string "&#v;"  (B-250: the reference interpreter's HTML-escaped
                  character, so a program's output is entity text an HTML decoder reads)
    >=10          push the integer (opcode - 10)

B-055 shipped opcodes 7, 8 and 9 as undefined; the esolangs.org table defines them (peck, fr, BBQ) and
B-250 completed them, so every opcode is defined. A bad pick source, a bad peck/fr operand and the caps
stay a loud ChickenError (no silent fallback). Addresses (pick source 0, peck) index this module's stack
model: slot 0 the program, slot 1 the input, execution values from slot 2.

The input (slot 1 and pick source 1) is the list of byte values of `stdin`, so pick source 1, index i
loads the i-th input byte as a number.

Output: when the program halts (op 0, or it runs past the last opcode), the top of the stack is the
result. render() turns it into bytes -- a number is emitted as the character with that code point
(like most Chicken interpreters' Hello-World convention), the "chicken" string and any other string as
its UTF-8 bytes. The exact render of a bare number is a documented choice, not a spec guarantee; run()
can also return the raw final stack so a caller validates the value instead of its rendering.

API:

  count_opcodes(src) -> list[int]          one opcode per source line (count of "chicken")
  run(opcodes, stdin=b"", *, steps=..., with_stack=False) -> bytes | (bytes, list)
  run_source(src, stdin=b"", *, steps=...) -> bytes
"""
from __future__ import annotations

import sys

STEPS = 1_000_000           # hard cap on executed opcodes (Chicken has no jumps, but pick can loop data)
OUTPUT = 1 << 16            # bytes a program may render before it is treated as runaway

CHICKEN = "chicken"


class ChickenError(ValueError):
    """The program is malformed or hit an undefined opcode."""


def count_opcodes(src) -> list:
    """One opcode per line: the number of whitespace-separated "chicken" tokens on it. A line with no
    chickens is opcode 0 (axe), as the language defines. A stray non-"chicken" token is a loud error
    so a non-Chicken file is rejected, never half-run."""
    if isinstance(src, bytes):
        src = src.decode("utf-8", "strict")
    ops = []
    for lineno, line in enumerate(src.split("\n"), 1):
        toks = line.split()
        for t in toks:
            if t != CHICKEN:
                raise ChickenError(f"line {lineno}: token {t!r} is not 'chicken'")
        ops.append(len(toks))
    # A single trailing newline adds one empty (opcode 0) line; drop exactly one trailing 0 so a file
    # written with a final newline is not forced to halt on a phantom axe before its real end.
    if len(ops) > 1 and ops[-1] == 0 and src.endswith("\n"):
        ops.pop()
    return ops


def run(opcodes, stdin=b"", *, steps=STEPS, with_stack=False):
    """Execute Chicken opcodes. Returns the rendered output bytes, or (output, final_stack) when
    with_stack is True. Raises ChickenError on an undefined opcode or a double-wide pick that runs off
    the end. The step cap and output cap make it total on any input."""
    if not isinstance(steps, int) or isinstance(steps, bool) or steps < 0:
        raise ChickenError("steps must be a non-negative int")
    if isinstance(stdin, str):
        stdin = stdin.encode("utf-8")
    inp = list(stdin)                       # source 1: input bytes as numbers
    stack = [list(opcodes), inp]            # slot 0 = program, slot 1 = input; execution grows above
    ip = 0
    count = 0
    n = len(opcodes)
    while ip < n:
        count += 1
        if count > steps:
            raise ChickenError("step cap exceeded (non-halting program?)")
        op = opcodes[ip]
        ip += 1
        if op == 0:                         # axe
            break
        if op == 1:                         # chicken
            stack.append(CHICKEN)
        elif op == 2:                       # add / concat
            b, a = _pop(stack), _pop(stack)
            stack.append(_binop(a, b, "add"))
        elif op == 3:                       # fox / subtract
            b, a = _pop(stack), _pop(stack)
            stack.append(_binop(a, b, "sub"))
        elif op == 4:                       # rooster / multiply
            b, a = _pop(stack), _pop(stack)
            stack.append(_binop(a, b, "mul"))
        elif op == 5:                       # compare
            b, a = _pop(stack), _pop(stack)
            stack.append(1 if a == b else 0)
        elif op == 6:                       # pick (double-wide load)
            if ip >= n:
                raise ChickenError("pick at the end of the program has no source operand")
            source_sel = opcodes[ip]
            ip += 1
            idx = _pop(stack)
            if not isinstance(idx, int):
                raise ChickenError(f"pick index must be a number, got {idx!r}")
            if source_sel == 0:
                src = stack
            elif source_sel == 1:
                src = inp
            else:
                raise ChickenError(f"pick source {source_sel} is not 0 (stack) or 1 (input)")
            if not (0 <= idx < len(src)):
                raise ChickenError(f"pick index {idx} out of range for source {source_sel}")
            stack.append(src[idx])
        elif op == 7:                       # peck (B-250): addr = pop, value = pop; stack[addr] = value
            addr, value = _pop(stack), _pop(stack)
            if not isinstance(addr, int) or isinstance(addr, bool):
                raise ChickenError(f"peck address must be a number, got {addr!r}")
            if addr < 2:
                raise ChickenError(f"peck to slot {addr} would overwrite the program or the input")
            if addr > len(stack):
                raise ChickenError(f"peck address {addr} is past the top of the stack ({len(stack)} slots)")
            if addr == len(stack):
                stack.append(value)
            else:
                stack[addr] = value
        elif op == 8:                       # fr (B-250): offset = pop, condition = pop; jump if truthy
            offset, cond = _pop(stack), _pop(stack)
            if not isinstance(offset, int) or isinstance(offset, bool):
                raise ChickenError(f"fr offset must be a number, got {offset!r}")
            # 0 is the only false value a Chicken program can make: its strings are never empty ("chicken",
            # its concatenations, BBQ's "&#v;"), and the program and input slots are lists, true as in JS.
            if cond != 0:
                ip += offset                # relative to the opcode after fr
                if ip < 0:
                    raise ChickenError(f"fr jumped before the start of the program (ip {ip})")
        elif op == 9:                       # BBQ (B-250): the top as an HTML-escaped character
            v = _pop(stack)
            if not isinstance(v, int) or isinstance(v, bool):
                raise ChickenError(f"BBQ needs a number, got {v!r}")
            stack.append(f"&#{v};")
        elif op >= 10:                      # push literal (op - 10)
            stack.append(op - 10)

    out = render(stack[-1]) if len(stack) > 2 else b""
    if len(out) > OUTPUT:
        raise ChickenError("output cap exceeded")
    return (out, stack) if with_stack else out


def _pop(stack):
    # Never pop the program (slot 0) or the input (slot 1): an underflowing program yields 0, like the
    # reference's empty-slot behaviour, instead of corrupting the self-referential base.
    if len(stack) <= 2:
        return 0
    return stack.pop()


def _binop(a, b, kind):
    if isinstance(a, str) or isinstance(b, str):
        if kind == "add":
            out = _as_str(a) + _as_str(b)
            if len(out) > OUTPUT:           # B-250: fr loops can double a string per pass; stop it here
                raise ChickenError("string value exceeds the output cap")
            return out
        raise ChickenError(f"cannot {kind} the string value(s) {a!r}, {b!r}")
    if not (isinstance(a, int) and isinstance(b, int)):
        # B-250 review: a pick of slot 0 or 1 puts the program or input list on the stack; arithmetic on it is
        # a loud ChickenError, not a Python TypeError out of a reader that only expects ChickenError.
        raise ChickenError(f"cannot {kind} the values {a!r}, {b!r}")
    if kind == "add":
        return a + b
    if kind == "sub":
        return a - b
    return a * b


def _as_str(v):
    return v if isinstance(v, str) else str(v)


def render(value) -> bytes:
    """The output bytes for a final top-of-stack value. A number is the character with that code point
    (documented convention); a string is its UTF-8 bytes. An out-of-range code point renders empty."""
    if isinstance(value, bool):
        return b"1" if value else b"0"
    if isinstance(value, int):
        if 0 <= value <= 0x10FFFF and not (0xD800 <= value <= 0xDFFF):
            return chr(value).encode("utf-8")
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, list):
        return b""                          # the program/opcode list on top renders to nothing
    raise ChickenError(f"cannot render value {value!r}")


def run_source(src, stdin=b"", *, steps=STEPS) -> bytes:
    return run(count_opcodes(src), stdin, steps=steps)


def source_of(opcodes) -> str:
    """The Chicken source for an opcode list (one line per opcode): a fixture / round-trip helper."""
    return "\n".join(" ".join([CHICKEN] * op) for op in opcodes)


def _main(argv) -> int:       # pragma: no cover
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: chicken.py <program.chicken> [...]", file=sys.stderr)
        return 0 if argv else 2
    for path in argv:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        try:
            out = run_source(src)
        except ChickenError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            return 2
        print("%s: %r" % (path, out))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
