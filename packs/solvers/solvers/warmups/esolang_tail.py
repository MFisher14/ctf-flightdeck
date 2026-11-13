#!/usr/bin/env python3
"""Bounded interpreters for Unlambda/Lazy-K, Thue, FRACTRAN, Hexagony, FALSE, and Underload.

Input bytes are supplied explicitly; no reader opens stdin. Programs are data walked by Python,
never eval'd or exec'd. Every loop, term, integer, state set, stack and output is capped. The
The Hexagony reader lays source onto the canonical centered hexagon, maintains all six instruction
pointers, wraps rays across opposite edges, implements mirrors/branches and the directed-edge memory
grid, and remains bounded by the same step/integer/output limits as the other interpreters.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from collections import deque
from pathlib import Path

MAX_SOURCE = 4 << 20
MAX_STEPS = 500_000
MAX_OUTPUT = 1 << 20
MAX_STACK = 100_000
MAX_TERM_NODES = 200_000
MAX_STATES = 4096
MAX_INTEGER_BITS = 4096


class Refuse(Exception):
    pass


def _tick(state, amount=1):
    state["steps"] += amount
    if state["steps"] > state["limit"] or (state["steps"] & 0xFFF == 0 and
                                           state.get("deadline") is not None and
                                           time.monotonic() > state["deadline"]):
        raise Refuse("step/time cap")


# ---- Unlambda and Lazy-K/SKI -----------------------------------------------------------------------

def _combinator_tokens(text, unlambda):
    tokens, index = [], 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "#":
            index = text.find("\n", index)
            if index < 0:
                break
            continue
        if char in (".", "?") and unlambda:
            if index + 1 >= len(text):
                raise Refuse("truncated character primitive")
            tokens.append(("dot" if char == "." else "ask", ord(text[index + 1]) & 0xFF))
            index += 2
            continue
        allowed = "`skivdr@|ec" if unlambda else "`skiSKI"
        if char not in allowed:
            raise Refuse("unsupported combinator token")
        tokens.append(char.lower())
        index += 1
        if len(tokens) > MAX_TERM_NODES:
            raise Refuse("term cap")
    return tokens


def _parse_combinator(text, unlambda):
    tokens = _combinator_tokens(text, unlambda)
    if not tokens:
        raise Refuse("empty program")

    def parse(index, depth):
        if depth > 512 or index >= len(tokens):
            raise Refuse("malformed/deep combinator expression")
        token = tokens[index]
        if token == "`":
            left, index = parse(index + 1, depth + 1)
            right, index = parse(index, depth + 1)
            return ("app", left, right), index
        return token, index + 1

    try:
        expression, end = parse(0, 0)
    except RecursionError as exc:
        raise Refuse("combinator recursion cap") from exc
    if end != len(tokens):
        raise Refuse("trailing combinator expression")
    return expression


class _UnlambdaExit(Exception):
    pass


def unlambda(text, input_data=b"", *, steps=MAX_STEPS, deadline=None):
    """Evaluate the bounded Unlambda core; call/cc (``c``) deliberately declines."""
    if (not isinstance(text, str) or len(text) > MAX_SOURCE or not isinstance(input_data, bytes)
            or not isinstance(steps, int)):
        return None
    try:
        expression = _parse_combinator(text, True)
    except Refuse:
        return None
    state = {"steps": 0, "limit": min(max(1, steps), MAX_STEPS), "deadline": deadline,
             "input": input_data, "input_at": 0, "current": None, "out": bytearray()}

    def evaluate(term, depth=0):
        _tick(state)
        if depth > 1024:
            raise Refuse("evaluation depth")
        if isinstance(term, tuple) and term and term[0] == "app":
            function = evaluate(term[1], depth + 1)
            if function == "d":
                return ("delay", term[2])
            argument = evaluate(term[2], depth + 1)
            return apply(function, argument, depth + 1)
        return term

    def apply(function, argument, depth):
        _tick(state)
        if function == "i":
            return argument
        if function == "v":
            return "v"
        if function == "k":
            return ("k1", argument)
        if isinstance(function, tuple) and function[0] == "k1":
            return function[1]
        if function == "s":
            return ("s1", argument)
        if isinstance(function, tuple) and function[0] == "s1":
            return ("s2", function[1], argument)
        if isinstance(function, tuple) and function[0] == "s2":
            return evaluate(("app", ("app", function[1], argument),
                             ("app", function[2], argument)), depth + 1)
        if isinstance(function, tuple) and function[0] == "dot":
            state["out"].append(function[1])
            if len(state["out"]) > MAX_OUTPUT:
                raise Refuse("output cap")
            return argument
        if isinstance(function, tuple) and function[0] == "delay":
            return evaluate(("app", function[1], argument), depth + 1)
        if function == "r":
            state["out"].append(10)
            if len(state["out"]) > MAX_OUTPUT:
                raise Refuse("output cap")
            return argument
        if function == "@":
            if state["input_at"] < len(state["input"]):
                state["current"] = state["input"][state["input_at"]]
                state["input_at"] += 1
                marker = "i"
            else:
                state["current"], marker = None, "v"
            return evaluate(("app", argument, marker), depth + 1)
        if isinstance(function, tuple) and function[0] == "ask":
            return evaluate(("app", argument, "i" if state["current"] == function[1] else "v"), depth + 1)
        if function == "|":
            value = ("dot", state["current"]) if state["current"] is not None else "v"
            return evaluate(("app", argument, value), depth + 1)
        if function == "e":
            raise _UnlambdaExit
        if function == "c":
            raise Refuse("call/cc is outside the bounded core")
        raise Refuse("attempt to apply a non-function")

    try:
        evaluate(expression)
    except _UnlambdaExit:
        pass
    except (Refuse, RecursionError, IndexError, OverflowError):
        return None
    return bytes(state["out"]) if state["out"] else None


def _term_nodes(term):
    todo, count = [term], 0
    while todo:
        value = todo.pop()
        count += 1
        if count > MAX_TERM_NODES:
            return count
        if isinstance(value, tuple) and value and value[0] == "app":
            todo.extend((value[1], value[2]))
    return count


def _ski_reduce_once(term):
    if isinstance(term, tuple) and term[0] == "app":
        function, argument = term[1], term[2]
        if function == "i":
            return argument, True
        if isinstance(function, tuple) and function[0] == "app" and function[1] == "k":
            return function[2], True
        if (isinstance(function, tuple) and function[0] == "app" and
                isinstance(function[1], tuple) and function[1][0] == "app" and function[1][1] == "s"):
            x, y, z = function[1][2], function[2], argument
            return ("app", ("app", x, z), ("app", y, z)), True
        left, changed = _ski_reduce_once(function)
        if changed:
            return ("app", left, argument), True
        right, changed = _ski_reduce_once(argument)
        if changed:
            return ("app", function, right), True
    return term, False


def _render_ski(term):
    return "`" + _render_ski(term[1]) + _render_ski(term[2]) if isinstance(term, tuple) and term[0] == "app" else str(term)


def lazy_k_normal_form(text, *, steps=MAX_STEPS):
    """Normalize the SKI/backquote Lazy-K surface; Jot/Iota stream encodings are unsupported."""
    if not isinstance(steps, int):
        return None
    try:
        term = _parse_combinator(text, False)
        for count in range(min(max(1, steps), MAX_STEPS)):
            term, changed = _ski_reduce_once(term)
            if _term_nodes(term) > MAX_TERM_NODES:
                return None
            if not changed:
                return {"normal_form": _render_ski(term), "steps": count, "verified_irreducible": True}
    except (Refuse, RecursionError, OverflowError):
        return None
    return None


# ---- Thue ------------------------------------------------------------------------------------------

def _parse_thue(text):
    if not isinstance(text, str) or len(text) > MAX_SOURCE:
        raise Refuse("source cap")
    rules, initial, separator = [], [], False
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not separator:
            if line.strip() == "::=":
                separator = True
                continue
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            left, marker, right = line.partition("::=")
            if not marker or not left or len(left) > 4096 or len(right) > 4096:
                raise Refuse("invalid Thue rule")
            rules.append((left, right))
            if len(rules) > 4096:
                raise Refuse("rule cap")
        else:
            initial.append(line)
    if not separator or not rules:
        raise Refuse("missing Thue separator/rules")
    return rules, "\n".join(initial)


def thue(text, input_data=b"", *, steps=10000):
    """Enumerate bounded nondeterministic terminal candidates rather than choosing randomly."""
    if not isinstance(steps, int):
        return []
    try:
        rules, initial = _parse_thue(text)
    except Refuse:
        return []
    queue = deque([(initial, b"", 0, 0)])
    seen, terminal = {(initial, b"", 0)}, []
    limit = min(max(1, steps), MAX_STEPS)
    while queue and len(seen) <= MAX_STATES and len(terminal) < MAX_STATES:
        state, output, input_at, depth = queue.popleft()
        if depth >= limit:
            continue
        moves = []
        for left, right in rules:
            start = 0
            while True:
                at = state.find(left, start)
                if at < 0:
                    break
                replacement, emitted, next_input = right, b"", input_at
                if right.startswith("~"):
                    try:
                        emitted = right[1:].encode("utf-8")
                    except UnicodeEncodeError as exc:
                        raise Refuse("Thue emitted un-encodable text") from exc
                    replacement = ""
                elif right == ":::":
                    end = input_data.find(b"\n", input_at)
                    end = len(input_data) if end < 0 else end
                    replacement = input_data[input_at:end].decode("latin-1")
                    next_input = min(len(input_data), end + 1)
                new_state = state[:at] + replacement + state[at + len(left):]
                new_output = output + emitted
                if len(new_state) <= MAX_SOURCE and len(new_output) <= MAX_OUTPUT:
                    moves.append((new_state, new_output, next_input))
                start = at + 1
                if len(moves) >= MAX_STATES:
                    break
            if len(moves) >= MAX_STATES:
                break
        if not moves:
            terminal.append({"state": state, "output": output, "steps": depth})
        for new_state, new_output, next_input in moves:
            key = (new_state, new_output, next_input)
            if key not in seen and len(seen) < MAX_STATES:
                seen.add(key)
                queue.append((new_state, new_output, next_input, depth + 1))
    unique = {}
    for item in terminal:
        unique.setdefault((item["state"], item["output"]), item)
    return list(unique.values())[:MAX_STATES]


# ---- FRACTRAN --------------------------------------------------------------------------------------

def parse_fractran(text, initial=None):
    if not isinstance(text, str) or len(text) > MAX_SOURCE:
        raise Refuse("FRACTRAN source exceeds cap")
    found = re.search(r"(?im)^\s*(?:n|input|start)\s*=\s*(\d+)\s*$", text)
    if initial is None and found:
        initial = int(found.group(1))
    fractions = []
    body = re.sub(r"(?im)^\s*(?:n|input|start)\s*=\s*\d+\s*$", "", text)
    for numerator, denominator in re.findall(r"(\d+)\s*/\s*(\d+)", body):
        p, q = int(numerator), int(denominator)
        if p <= 0 or q <= 0 or p.bit_length() > MAX_INTEGER_BITS or q.bit_length() > MAX_INTEGER_BITS:
            raise Refuse("invalid/oversized FRACTRAN fraction")
        divisor = math.gcd(p, q)
        fractions.append((p // divisor, q // divisor))
        if len(fractions) > 10000:
            raise Refuse("FRACTRAN fraction cap exceeded")
    if not fractions or not isinstance(initial, int) or isinstance(initial, bool) or initial <= 0:
        raise Refuse("FRACTRAN needs fractions and a positive initial integer")
    if initial.bit_length() > MAX_INTEGER_BITS:
        raise Refuse("FRACTRAN initial integer exceeds bit cap")
    return fractions, initial


def fractran(text, initial=None, *, steps=10000):
    if not isinstance(steps, int):
        return None
    try:
        fractions, value = parse_fractran(text, initial)
    except Refuse:
        return None
    sequence, halted = [value], False
    for _ in range(min(max(1, steps), MAX_STEPS)):
        for numerator, denominator in fractions:
            product = value * numerator
            if product % denominator == 0:
                value = product // denominator
                if value.bit_length() > MAX_INTEGER_BITS:
                    return None
                sequence.append(value)
                break
        else:
            halted = True
            break
        if len(sequence) > 100000:
            return None
    return {"sequence": sequence, "final": value, "halted": halted,
            "steps": len(sequence) - 1, "verified": halted}


# ---- Hexagony -------------------------------------------------------------------------------------

_HEX_DIRECTIONS = ((1, 0), (0, 1), (-1, 1), (-1, 0), (0, -1), (1, -1))


def _hex_cells(source):
    compact = "".join(char for char in source if not char.isspace())
    if not compact:
        raise Refuse("empty Hexagony program")
    side = 1
    while 3 * side * (side - 1) + 1 < len(compact):
        side += 1
    if side > 128:
        raise Refuse("Hexagony side cap")
    count = 3 * side * (side - 1) + 1
    compact = compact.ljust(count, ".")
    radius, cells, index = side - 1, {}, 0
    for row in range(-radius, radius + 1):
        first = max(-radius, -row - radius)
        last = min(radius, -row + radius)
        for column in range(first, last + 1):
            cells[(column, row)] = compact[index]
            index += 1
    return cells, radius


def _hex_inside(cell, radius):
    q, r = cell
    return max(abs(q), abs(r), abs(q + r)) <= radius


def _hex_step(cell, direction, radius):
    dq, dr = _HEX_DIRECTIONS[direction]
    target = (cell[0] + dq, cell[1] + dr)
    if _hex_inside(target, radius):
        return target, False
    # The ray left the finite hexagon.  Walk backwards to its opposite intersection; this handles
    # edges and exact-corner exits without an unbounded coordinate search.
    target = cell
    while _hex_inside((target[0] - dq, target[1] - dr), radius):
        target = (target[0] - dq, target[1] - dr)
    return target, True


def _honey_neighbors(vertex):
    x, y = vertex
    vertical = (x, y + (1 if (x + y) % 2 == 0 else -1))
    return ((x - 1, y), (x + 1, y), vertical)


def _edge_key(left, right):
    return (left, right) if left <= right else (right, left)


def _memory_turn(pointer, side):
    tail, head = pointer
    choices = [point for point in _honey_neighbors(head) if point != tail]
    if len(choices) != 2:
        raise Refuse("invalid memory edge")
    incoming = (head[0] - tail[0], head[1] - tail[1])

    def cross(point):
        outgoing = (point[0] - head[0], point[1] - head[1])
        return incoming[0] * outgoing[1] - incoming[1] * outgoing[0]

    choices.sort(key=cross)
    chosen = choices[-1] if side == "left" else choices[0]
    return head, chosen


def _hex_linear_compat(program, input_data, limit):
    """Preserve the old documented one-row literal/output convenience as a strict fast path."""
    if not program or any(char not in ".`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,?;!$@"
                          for char in program):
        return None
    value, output, input_at, pc = 0, bytearray(), 0, 0
    for _ in range(limit):
        if not 0 <= pc < len(program):
            return None
        op = program[pc]
        if op == "@": return bytes(output) if output else None
        if op in ".`": pass
        elif op.isdigit(): value = value * 10 + int(op) if value >= 0 else value * 10 - int(op)
        elif op.isalpha(): value = ord(op)
        elif op == ",":
            value = input_data[input_at] if input_at < len(input_data) else -1
            input_at += input_at < len(input_data)
        elif op == "?":
            match = re.match(rb"\s*[-+]?\d+", input_data[input_at:])
            value = int(match.group(0)) if match else 0
            input_at += match.end() if match else 0
        elif op == ";": output.append(value & 0xFF)
        elif op == "!": output.extend(str(value).encode())
        elif op == "$": pc += 1
        if abs(value).bit_length() > MAX_INTEGER_BITS or len(output) > MAX_OUTPUT: return None
        pc += 1
    return None


def hexagony(text, input_data=b"", *, steps=MAX_STEPS):
    """Execute bounded Hexagony with six IPs, edge wrapping, and directed-edge memory."""
    if (not isinstance(text, str) or len(text) > MAX_SOURCE or not isinstance(input_data, bytes)
            or not isinstance(steps, int)):
        return None
    limit = min(max(1, steps), MAX_STEPS)
    compact = "".join(char for char in text if not char.isspace())
    if len(text.splitlines()) <= 1:
        compatible = _hex_linear_compat(compact, input_data, limit)
        if compatible is not None:
            return compatible
    try:
        cells, radius = _hex_cells(text)
    except Refuse:
        return None
    corners = ((0, -radius), (radius, -radius), (radius, 0), (0, radius),
               (-radius, radius), (-radius, 0))
    ips = [{"cell": corners[index], "direction": index} for index in range(6)]
    active, memory = 0, {}
    pointer = ((0, 0), (1, 0))
    output, input_at = bytearray(), 0

    def current():
        return memory.get(_edge_key(*pointer), 0)

    def store(value):
        if not isinstance(value, int) or isinstance(value, bool) or abs(value).bit_length() > MAX_INTEGER_BITS:
            raise Refuse("Hexagony integer cap")
        memory[_edge_key(*pointer)] = value
        if len(memory) > MAX_STACK:
            raise Refuse("Hexagony memory cap")

    def neighbor(side):
        edge = _memory_turn(pointer, side)
        return memory.get(_edge_key(*edge), 0)

    try:
        for _ in range(limit):
            ip = ips[active]
            op = cells[ip["cell"]]
            value = current()
            if op == "@":
                return bytes(output) if output else None
            if op in ".`":
                pass
            elif op in "0123456789":
                digit = int(op); store(value * 10 + digit if value >= 0 else value * 10 - digit)
            elif op.isalpha() and ord(op) < 128:
                store(ord(op))
            elif op == ",":
                store(input_data[input_at] if input_at < len(input_data) else -1)
                input_at += input_at < len(input_data)
            elif op == "?":
                match = re.search(rb"[-+]?\d+", input_data[input_at:])
                store(int(match.group(0)) if match else 0)
                input_at += match.end() if match else 0
            elif op == ";": output.append(value & 0xFF)
            elif op == "!": output.extend(str(value).encode("ascii"))
            elif op == "+": store(neighbor("left") + neighbor("right"))
            elif op == "-": store(neighbor("left") - neighbor("right"))
            elif op == "*": store(neighbor("left") * neighbor("right"))
            elif op in (":", "%"):
                left, right = neighbor("left"), neighbor("right")
                store(0 if right == 0 else (left // right if op == ":" else left % right))
            elif op == "~": store(-value)
            elif op == "&": store(neighbor("left"))
            elif op == "^": store(neighbor("right"))
            elif op == "(": store(value - 1)
            elif op == ")": store(value + 1)
            elif op == "{": pointer = _memory_turn(pointer, "left")
            elif op == "}": pointer = _memory_turn(pointer, "right")
            elif op == "=": pointer = (pointer[1], pointer[0])
            elif op == '"': pointer = _memory_turn((pointer[1], pointer[0]), "left")
            elif op == "'": pointer = _memory_turn((pointer[1], pointer[0]), "right")
            elif op in "_|/\\":
                direction = ip["direction"]
                ip["direction"] = ({"_": -direction, "|": 3 - direction,
                                    "/": 4 - direction, "\\": 2 - direction}[op]) % 6
            elif op == ">": ip["direction"] = 1 if value > 0 else 5
            elif op == "<": ip["direction"] = 2 if value > 0 else 4
            elif op == "[": active = (active - 1) % 6; ip = ips[active]
            elif op == "]": active = (active + 1) % 6; ip = ips[active]
            elif op == "#": active = value % 6; ip = ips[active]
            elif op == "$":
                ip["cell"], _ = _hex_step(ip["cell"], ip["direction"], radius)
            else:
                raise Refuse("unsupported Hexagony token")
            if len(output) > MAX_OUTPUT:
                raise Refuse("Hexagony output cap")
            ip["cell"], _ = _hex_step(ip["cell"], ip["direction"], radius)
    except (Refuse, IndexError, KeyError, OverflowError, ValueError):
        return None
    return None


# ---- Underload ------------------------------------------------------------------------------------

def underload(text, *, steps=MAX_STEPS):
    """Execute the common Underload core; output is explicit ``S`` only."""
    if not isinstance(text, str) or len(text) > MAX_SOURCE or not isinstance(steps, int):
        return None
    stack, output = [], bytearray()
    program, pc = text, 0
    limit = min(max(1, steps), MAX_STEPS)
    try:
        for _ in range(limit):
            if pc >= len(program):
                return bytes(output) if output else None
            op = program[pc]; pc += 1
            if op.isspace(): continue
            if op == "(":
                depth, start = 1, pc
                while pc < len(program) and depth:
                    if program[pc] == "(": depth += 1
                    elif program[pc] == ")": depth -= 1
                    pc += 1
                if depth: raise Refuse("unterminated Underload string")
                stack.append(program[start:pc - 1])
            elif op == "~":
                if len(stack) < 2: raise Refuse("Underload stack underflow")
                stack[-2], stack[-1] = stack[-1], stack[-2]
            elif op == ":":
                if not stack: raise Refuse("Underload stack underflow")
                stack.append(stack[-1])
            elif op == "!":
                if not stack: raise Refuse("Underload stack underflow")
                stack.pop()
            elif op == "*":
                if len(stack) < 2: raise Refuse("Underload stack underflow")
                right, left = stack.pop(), stack.pop(); stack.append(left + right)
            elif op == "a":
                if not stack: raise Refuse("Underload stack underflow")
                stack[-1] = "(" + stack[-1] + ")"
            elif op == "^":
                if not stack: raise Refuse("Underload stack underflow")
                injected = stack.pop()
                if len(program) + len(injected) > MAX_SOURCE: raise Refuse("Underload source cap")
                program = program[:pc] + injected + program[pc:]
            elif op == "S":
                if not stack: raise Refuse("Underload stack underflow")
                output.extend(stack.pop().encode("utf-8"))
            else:
                raise Refuse("unsupported Underload token")
            if len(stack) > MAX_STACK or sum(map(len, stack)) > MAX_SOURCE or len(output) > MAX_OUTPUT:
                raise Refuse("Underload resource cap")
    except (Refuse, IndexError, OverflowError, ValueError, UnicodeError):
        return None
    return None


# ---- FALSE -----------------------------------------------------------------------------------------

def _false_block(source, start):
    depth, index = 1, start
    while index < len(source):
        char = source[index]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return source[start:index], index + 1
        elif char == '"':
            end = source.find('"', index + 1)
            if end < 0:
                raise Refuse("unterminated string")
            index = end
        elif char == "{":
            end = source.find("}", index + 1)
            if end < 0:
                raise Refuse("unterminated comment")
            index = end
        index += 1
    raise Refuse("unterminated lambda")


def false_lang(text, input_data=b"", *, steps=MAX_STEPS, deadline=None):
    if (not isinstance(text, str) or len(text) > MAX_SOURCE or not isinstance(input_data, bytes)
            or not isinstance(steps, int)):
        return None
    stack = []
    variables = {chr(code): 0 for code in range(ord("a"), ord("z") + 1)}
    output = bytearray()
    state = {"steps": 0, "limit": min(max(1, steps), MAX_STEPS), "deadline": deadline, "input": 0}

    def pop():
        if not stack:
            raise Refuse("stack underflow")
        return stack.pop()

    def integer(value):
        if not isinstance(value, int) or isinstance(value, bool):
            raise Refuse("integer required")
        return value

    def execute(source, depth=0):
        if depth > 256:
            raise Refuse("lambda depth")
        index = 0
        while index < len(source):
            _tick(state)
            char = source[index]
            if char.isspace():
                index += 1
                continue
            if char == "{":
                end = source.find("}", index + 1)
                if end < 0:
                    raise Refuse("unterminated comment")
                index = end + 1
                continue
            if char == '"':
                end = source.find('"', index + 1)
                if end < 0:
                    raise Refuse("unterminated string")
                output.extend(source[index + 1:end].encode("latin-1", "replace"))
                if len(output) > MAX_OUTPUT:
                    raise Refuse("output cap")
                index = end + 1
                continue
            if char == "'":                 # character literal: push the next character's code point
                if index + 1 >= len(source):
                    raise Refuse("truncated character literal")
                stack.append(ord(source[index + 1]))
                index += 2
                continue
            if char in "0123456789":
                end = index + 1
                while end < len(source) and source[end] in "0123456789":
                    end += 1
                value = int(source[index:end])
                if value.bit_length() > MAX_INTEGER_BITS:
                    raise Refuse("integer cap")
                stack.append(value)
                index = end
                continue
            if char == "[":
                block, index = _false_block(source, index + 1)
                stack.append(("block", block))
                continue
            if "a" <= char <= "z":
                stack.append(("var", char))
            elif char == ":":
                variable, value = pop(), pop()
                if not (isinstance(variable, tuple) and variable[0] == "var"):
                    raise Refuse("store needs variable")
                variables[variable[1]] = value
            elif char == ";":
                variable = pop()
                if not (isinstance(variable, tuple) and variable[0] == "var"):
                    raise Refuse("fetch needs variable")
                stack.append(variables[variable[1]])
            elif char == "$":
                value = pop(); stack.extend((value, value))
            elif char == "%":
                pop()
            elif char == "\\":
                right, left = pop(), pop(); stack.extend((right, left))
            elif char == "@":
                c, b, a = pop(), pop(), pop(); stack.extend((b, c, a))
            elif char == "ø":
                offset = integer(pop())
                if offset < 0 or offset >= len(stack):
                    raise Refuse("pick outside stack")
                stack.append(stack[-1 - offset])
            elif char in "+-*/=><&|":
                right, left = integer(pop()), integer(pop())
                if char == "/" and right == 0:
                    raise Refuse("division by zero")
                if char == "+": value = left + right
                elif char == "-": value = left - right
                elif char == "*": value = left * right
                elif char == "/":
                    value = abs(left) // abs(right)           # truncate toward zero, exact ints only
                    if (left < 0) != (right < 0):
                        value = -value
                elif char == "=": value = -1 if left == right else 0
                elif char == ">": value = -1 if left > right else 0
                elif char == "<": value = -1 if left < right else 0
                elif char == "&": value = left & right
                else: value = left | right
                if abs(value).bit_length() > MAX_INTEGER_BITS:
                    raise Refuse("integer cap")
                stack.append(value)
            elif char == "~":
                stack.append(~integer(pop()))
            elif char == "_":
                stack.append(-integer(pop()))
            elif char == "!":
                block = pop()
                if not (isinstance(block, tuple) and block[0] == "block"):
                    raise Refuse("execute needs lambda")
                execute(block[1], depth + 1)
            elif char == "?":
                block, condition = pop(), integer(pop())
                if not (isinstance(block, tuple) and block[0] == "block"):
                    raise Refuse("conditional needs lambda")
                if condition:
                    execute(block[1], depth + 1)
            elif char == "#":
                body, condition = pop(), pop()
                if not all(isinstance(block, tuple) and block[0] == "block" for block in (condition, body)):
                    raise Refuse("while needs two lambdas")
                while True:
                    execute(condition[1], depth + 1)
                    if not integer(pop()):
                        break
                    execute(body[1], depth + 1)
            elif char == ".":
                output.extend(str(integer(pop())).encode("ascii"))
            elif char == ",":
                output.append(integer(pop()) & 0xFF)
            elif char == "^":
                at = state["input"]
                stack.append(input_data[at] if at < len(input_data) else -1)
                state["input"] += at < len(input_data)
            elif char == "ß":
                pass
            else:
                raise Refuse("unsupported FALSE token")
            if len(stack) > MAX_STACK or len(output) > MAX_OUTPUT:
                raise Refuse("stack/output cap")
            index += 1

    try:
        execute(text)
    except (Refuse, RecursionError, IndexError, OverflowError, ValueError):
        return None
    return bytes(output) if output else None


def run_language(language, source, input_data=b""):
    language = language.lower().replace("_", "-")
    if language == "unlambda":
        value = unlambda(source, input_data)
        return {"candidates": [value] if value is not None else []}
    if language in ("lazy-k", "lazyk", "ski"):
        return lazy_k_normal_form(source)
    if language == "thue":
        return {"candidates": thue(source, input_data)}
    if language == "fractran":
        return fractran(source)
    if language == "hexagony":
        value = hexagony(source, input_data)
        return {"candidates": [value] if value is not None else []}
    if language == "false":
        value = false_lang(source, input_data)
        return {"candidates": [value] if value is not None else []}
    if language == "underload":
        value = underload(source)
        return {"candidates": [value] if value is not None else []}
    raise ValueError("unknown esolang")


def _render(value):
    if isinstance(value, bytes):
        return {"hex": value.hex(), "text": value.decode("utf-8", "replace")}
    raise TypeError


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover
        raise ValueError(message)


def main(argv=None):
    parser = _Parser(prog="esolang_tail.py")
    parser.add_argument("language", choices=("unlambda", "lazy-k", "thue", "fractran", "hexagony",
                                              "false", "underload"))
    parser.add_argument("input")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--input-text", default=None)
    group.add_argument("--input-hex", default=None)
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        with Path(args.input).open("rb") as handle:
            raw = handle.read(MAX_SOURCE + 1)
        if len(raw) > MAX_SOURCE:
            raise ValueError("program exceeds 4 MiB cap")
        if args.input_hex is not None:
            if len(args.input_hex) > MAX_SOURCE * 2 or len(args.input_hex) % 2:
                raise ValueError("input hex exceeds cap or has odd length")
            supplied = bytes.fromhex(args.input_hex)
        else:
            supplied = (args.input_text or "").encode("utf-8")
        result = run_language(args.language, raw.decode("utf-8", "replace"), supplied)
        print(json.dumps(result, sort_keys=True, default=_render))
        return 0
    except SystemExit as exc:               # argparse --help exits 0; keep it a clean return
        return 0 if (exc.code or 0) == 0 else 2
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError) as exc:
        print(f"esolang_tail: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
