#!/usr/bin/env python3
"""Bounded interpreters for programs that print a text (Warmups, Day 9 round 2).

  .venv/bin/python solvers/warmups/esolangs.py <file> [...]     what each file prints, by every reader that takes it

Each reader refuses what is not a program of its language (returns None) and runs under a step cap
and a wall-clock deadline (time.perf_counter() value; checked every few thousand steps, never a
signal): a program that does not end in time gives None, not a part of its output. None of them reads
input: a program that asks for input is refused. Nothing here executes a downloaded file; a program
is data that these loops walk over.

  cow(text)          COW (moo, mOo, moO, mOO, Moo, MOo, MoO, MOO, OOO, MMM, OOM, oom)
  whitespace(text)   Whitespace (space, tab, line feed; everything else in the file must be absent)
  befunge(text)      Befunge-93 on its 80 x 25 grid; '?', '&' and '~' are refusals (random, input)
  malbolge(text)     Malbolge (the reference tables; the loader's own check of every character)
  jsfuck(text)       JSFuck: the six characters []()!+ evaluated over a fixed vocabulary of JavaScript
                     (see JSFUCK below). A program wrapped for eval gives its source text, never run.

Brainfuck and Ook! are in solvers/common/classical.py (backlog row 88). Piet needs an image and is out.
"""
import math
import re
import sys
import time

STEPS = 400_000          # default step cap of the loop interpreters
OUTPUT = 4096            # bytes a program may print
TICK = 4096              # steps between two looks at the clock
SCAN = 1 << 17           # instructions a COW program may pass looking for a loop's other end between two looks


class Refuse(Exception):
    """Not a program of this language, or one this reader does not run to its end."""


def _late(deadline) -> bool:
    return deadline is not None and time.perf_counter() > deadline


# ---------------------------------------------------------------------------- COW

COW_OPS = ("moo", "mOo", "moO", "mOO", "Moo", "MOo", "MoO", "MOO", "OOO", "MMM", "OOM", "oom")
_COW = {w: i for i, w in enumerate(COW_OPS)}


def cow(text: str, steps: int = STEPS, deadline=None):
    """What a COW program prints, or None. Strict: the text is nothing but the twelve instructions and
    white space (the language itself skips other text; a warmup blob that is one has none)."""
    if not isinstance(text, str):
        return None
    words = text.split()
    if len(words) < 8 or any(w not in _COW for w in words):
        packed = "".join(words)                           # written without spaces: three letters each
        if len(packed) < 24 or len(packed) % 3 or re.sub(r"[mMoO]", "", packed):
            return None
        words = [packed[i:i + 3] for i in range(0, len(packed), 3)]
        if any(w not in _COW for w in words):
            return None
    prog = [_COW[w] for w in words]
    if 4 not in prog and 10 not in prog:   # nothing printed
        return None
    n = len(prog)
    mem, ptr, pc, reg, out, count = [0] * 30000, 0, 0, None, bytearray(), 0

    # A jump is looked for once per instruction and remembered, and the looking is counted against the
    # clock: a loop that skips a long stretch on every pass must not run past the deadline between two
    # looks at it (240 000 instructions skipped per pass took 7.9 s against a 0.1 s deadline).
    jumps, scanned = {}, [0]

    def scan(at, step, up, down):
        depth, start = 1, at
        while 0 <= at < n:
            if prog[at] == up:
                depth += 1
            elif prog[at] == down:
                depth -= 1
                if depth == 0:
                    break
            at += step
        else:
            raise Refuse("a loop without its other end")
        scanned[0] += abs(at - start) + 1
        if scanned[0] >= SCAN:
            scanned[0] = 0
            if _late(deadline):
                raise Refuse("time")
        return at

    def forward(at):   # MOO on zero: skip the next instruction, then go behind the matching moo
        to = jumps.get(at)
        if to is None:
            to = jumps[at] = scan(at + 2, 1, 7, 0) + 1
        return to

    def backward(at):   # moo: skip the instruction before it, then back to the matching MOO
        to = jumps.get(~at)
        if to is None:
            to = jumps[~at] = scan(at - 2, -1, 0, 7)
        return to

    try:
        while pc < n:
            count += 1
            if count > steps or (count % TICK == 0 and _late(deadline)) or len(out) > OUTPUT:
                return None
            op = prog[pc]
            if op == 3:               # mOO: run the cell's value as an instruction
                op = mem[ptr]
                if op == 3 or not 0 <= op <= 11:
                    break
            if op == 0:
                pc = backward(pc)
                continue
            if op == 1:
                ptr -= 1
                if ptr < 0:
                    return None
            elif op == 2:
                ptr += 1
                if ptr >= len(mem):
                    return None
            elif op == 4:
                if mem[ptr] == 0:
                    return None      # it would read a character
                out.append(mem[ptr] & 255)
            elif op == 5:
                mem[ptr] -= 1
            elif op == 6:
                mem[ptr] += 1
            elif op == 7:
                if mem[ptr] == 0:
                    pc = forward(pc)
                    continue
            elif op == 8:
                mem[ptr] = 0
            elif op == 9:
                if reg is None:
                    reg = mem[ptr]
                else:
                    mem[ptr], reg = reg, None
            elif op == 10:
                out += str(mem[ptr]).encode()
            elif op == 11:
                return None          # it would read a number
            pc += 1
    except Refuse:
        return None
    if len(out) > OUTPUT:                 # a final output instruction must still respect the cap
        return None
    return bytes(out) or None


def cow_encode(data: bytes) -> str:
    """A COW program that prints `data` (for tests): each byte counted up or down from the last."""
    out, cur = [], 0
    for b in data:
        out += ["MoO" if b > cur else "MOo"] * abs(b - cur) + ["Moo"]
        cur = b
    return " ".join(out)


# ---------------------------------------------------------------------------- Whitespace

def _ws_number(code, at):
    """(value, index after the terminating line feed) of a Whitespace number at `at`."""
    end = code.find("\n", at)
    if end < 0 or end == at:
        raise Refuse("number")
    bits = code[at + 1:end]
    value = int(bits.replace(" ", "0").replace("\t", "1"), 2) if bits else 0
    return (-value if code[at] == "\t" else value), end + 1


def _ws_label(code, at):
    end = code.find("\n", at)
    if end < 0:
        raise Refuse("label")
    return code[at:end], end + 1


_WS = (("  ", "push", "n"), (" \n ", "dup", ""), (" \t ", "copy", "n"), (" \n\t", "swap", ""), (" \n\n", "drop", ""),
       (" \t\n", "slide", "n"), ("\t   ", "add", ""), ("\t  \t", "sub", ""), ("\t  \n", "mul", ""), ("\t \t ", "div", ""),
       ("\t \t\t", "mod", ""), ("\t\t ", "store", ""), ("\t\t\t", "load", ""), ("\n  ", "mark", "l"),
       ("\n \t", "call", "l"), ("\n \n", "jump", "l"), ("\n\t ", "jz", "l"), ("\n\t\t", "jneg", "l"), ("\n\t\n", "ret", ""),
       ("\n\n\n", "end", ""), ("\t\n  ", "outc", ""), ("\t\n \t", "outn", ""), ("\t\n\t ", "inc", ""), ("\t\n\t\t", "inn", ""))


def whitespace(text: str, steps: int = STEPS, deadline=None):
    """What a Whitespace program prints, or None. Strict: the text holds only spaces, tabs and line
    ends (the language skips anything else as a comment; a blob with other characters is not taken),
    it parses as instructions from its first character to its last, and it ends by its end
    instruction or by running off its last instruction."""
    if not isinstance(text, str):
        return None
    code = text.replace("\r", "")
    if len(code) < 12 or code.strip(" \t\n") or "\t" not in code or "\n" not in code:
        return None
    prog, labels, at = [], {}, 0
    try:
        while at < len(code):
            if len(prog) % TICK == TICK - 1 and _late(deadline):
                return None
            for lead, name, arg in _WS:
                if code.startswith(lead, at):
                    at += len(lead)
                    value = None
                    if arg == "n":
                        value, at = _ws_number(code, at)
                    elif arg == "l":
                        value, at = _ws_label(code, at)
                    if name == "mark":
                        if value in labels:
                            raise Refuse("label twice")
                        labels[value] = len(prog)
                    else:
                        prog.append((name, value))
                    break
            else:
                if not code[at:].strip("\n"):   # line ends after the last instruction
                    break
                raise Refuse("no instruction")
    except Refuse:
        return None
    if not any(name in ("outc", "outn") for name, _ in prog):
        return None
    stack, heap, calls, out, pc, count = [], {}, [], bytearray(), 0, 0
    try:
        while pc < len(prog):
            count += 1
            if count > steps or (count % TICK == 0 and _late(deadline)) or len(out) > OUTPUT:
                return None
            name, v = prog[pc]
            pc += 1
            if name == "push":
                stack.append(v)
            elif name == "dup":
                stack.append(stack[-1])
            elif name == "copy":
                if v < 0:
                    return None
                stack.append(stack[-1 - v])
            elif name == "swap":
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif name == "drop":
                stack.pop()
            elif name == "slide":
                top = stack.pop()
                if v < 0 or v > len(stack):
                    return None
                del stack[len(stack) - v:]
                stack.append(top)
            elif name in ("add", "sub", "mul", "div", "mod"):
                b, a = stack.pop(), stack.pop()
                if name in ("div", "mod") and b == 0:
                    return None
                stack.append(a + b if name == "add" else a - b if name == "sub" else a * b if name == "mul"
                             else a // b if name == "div" else a % b)
                if abs(stack[-1]) > 1 << 64:
                    return None
            elif name == "store":
                value, addr = stack.pop(), stack.pop()
                heap[addr] = value
            elif name == "load":
                stack.append(heap.get(stack.pop(), 0))
            elif name == "call":
                calls.append(pc)
                pc = labels[v]
            elif name == "jump":
                pc = labels[v]
            elif name == "jz":
                if stack.pop() == 0:
                    pc = labels[v]
            elif name == "jneg":
                if stack.pop() < 0:
                    pc = labels[v]
            elif name == "ret":
                pc = calls.pop()
            elif name == "end":
                break
            elif name == "outc":
                c = stack.pop()
                if not 0 <= c <= 0x10FFFF:
                    return None
                out += chr(c).encode("utf-8", "replace")
            elif name == "outn":
                out += str(stack.pop()).encode()
            else:                       # inc, inn: input
                return None
            if len(stack) > 100_000 or len(calls) > 10_000:
                return None
    except (IndexError, KeyError):
        return None
    if len(out) > OUTPUT:                 # a final output instruction must still respect the cap
        return None
    return bytes(out) or None


def whitespace_encode(data: bytes) -> str:
    """A Whitespace program that prints `data` (for tests): push, print, ..., end."""
    out = []
    for b in data:
        out.append("  " + " " + format(b, "b").replace("0", " ").replace("1", "\t") + "\n" + "\t\n  ")
    return "".join(out) + "\n\n\n"


# ---------------------------------------------------------------------------- Befunge-93

_BEFUNGE_MOVES = {">": (1, 0), "<": (-1, 0), "^": (0, -1), "v": (0, 1)}


def befunge(text: str, steps: int = 100_000, deadline=None):
    """What a Befunge-93 program prints, or None. The text must fit the 80 x 25 grid, be ASCII and
    hold an '@' and an output instruction; a program that reaches '?', '&' or '~' (random direction,
    input) is refused, as is one that does not reach '@' within the step cap."""
    if not isinstance(text, str):
        return None
    lines = text.replace("\r", "").rstrip("\n").split("\n")
    if (not text.isascii() or "@" not in text or ("," not in text and "." not in text) or len(lines) > 25
            or max(map(len, lines)) > 80 or len(text) < 6):
        return None
    grid = [list(ln.ljust(80)) for ln in lines] + [[" "] * 80 for _ in range(25 - len(lines))]
    x = y = 0
    dx, dy = 1, 0
    stack, out, string, count = [], bytearray(), False, 0
    pop = lambda: stack.pop() if stack else 0   # noqa: E731
    while True:
        count += 1
        if count > steps or (count % TICK == 0 and _late(deadline)) or len(out) > OUTPUT or len(stack) > 100_000:
            return None
        c = grid[y][x]
        if string:
            if c == '"':
                string = False
            else:
                stack.append(ord(c))
        elif c == " ":
            pass
        elif c in _BEFUNGE_MOVES:
            dx, dy = _BEFUNGE_MOVES[c]
        elif "0" <= c <= "9":
            stack.append(ord(c) - 48)
        elif c == '"':
            string = True
        elif c == ",":
            out.append(pop() & 255)
        elif c == ".":
            out += b"%d " % pop()
        elif c == "@":
            break
        elif c in "+-*/%`":
            b, a = pop(), pop()
            if c in "/%" and b == 0:
                return None             # the reference asks the user what the result should be
            stack.append(a + b if c == "+" else a - b if c == "-" else a * b if c == "*" else
                         int(a / b) if c == "/" else int(math.fmod(a, b)) if c == "%" else int(a > b))
            if abs(stack[-1]) > 1 << 62:
                return None
        elif c == "!":
            stack.append(int(pop() == 0))
        elif c == "_":
            dx, dy = (1, 0) if pop() == 0 else (-1, 0)
        elif c == "|":
            dx, dy = (0, 1) if pop() == 0 else (0, -1)
        elif c == ":":
            v = pop()
            stack += [v, v]
        elif c == "\\":
            b, a = pop(), pop()
            stack += [b, a]
        elif c == "$":
            pop()
        elif c == "#":
            x, y = (x + dx) % 80, (y + dy) % 25
        elif c == "g":
            gy, gx = pop(), pop()
            stack.append(ord(grid[gy][gx]) if 0 <= gx < 80 and 0 <= gy < 25 else 0)
        elif c == "p":
            gy, gx, v = pop(), pop(), pop()
            if not (0 <= gx < 80 and 0 <= gy < 25 and 0 <= v <= 0x10FFFF):
                return None
            grid[gy][gx] = chr(v)
        else:                           # '?', '&', '~', or a character that is no instruction
            return None
        x, y = (x + dx) % 80, (y + dy) % 25
    return bytes(out) or None


def befunge_encode(data: bytes, width: int = 64) -> str:
    """A Befunge-93 program that prints `data` (for tests): rows of string mode walked as a snake (to the
    right, down, to the left, down), then the print loop `>:#,_@`. No double quote in the text; at most
    22 rows of width - 4 characters."""
    todo = data[::-1].decode("latin-1")          # the last character is pushed first
    assert '"' not in todo and 16 <= width <= 78
    chunks = [todo[i:i + width - 4] for i in range(0, len(todo), width - 4)]
    assert len(chunks) <= 22
    lines = []
    for i, chunk in enumerate(chunks):
        body = '"' + chunk + '"'
        if i % 2 == 0:
            lines.append((">" + body).ljust(width) + "v")
        else:
            lines.append("v" + body[::-1].rjust(width - 1) + "<")
    if len(chunks) % 2:                          # the last row ended at the right: come back to column 0
        lines.append("v".ljust(width) + "<")
    lines.append(">:#,_@")
    return "\n".join(lines)


# ---------------------------------------------------------------------------- Malbolge

_XLAT1 = '+b(29e*j1VMEKLyC})8&m#~W>qxdRp0wkrUo[D7,XTcA"lI.v%{gJh4G\\-=O@5`_3i<?Z\';FNQuY]szf$!BS/|t:Pn6^Ha'
_XLAT2 = '5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1CB6v^=I_0/8|jsb9m<.TVac`uY*MK\'X~xDl}REokN:#?G"i@'
_CRAZY = ((4, 3, 3, 1, 0, 0, 1, 0, 0), (4, 3, 5, 1, 0, 2, 1, 0, 2), (5, 5, 4, 2, 2, 1, 2, 2, 1),
          (4, 3, 3, 1, 0, 0, 7, 6, 6), (4, 3, 5, 1, 0, 2, 7, 6, 8), (5, 5, 4, 2, 2, 1, 8, 8, 7),
          (7, 6, 6, 7, 6, 6, 4, 3, 3), (7, 6, 8, 7, 6, 8, 4, 3, 5), (8, 8, 7, 8, 8, 7, 5, 5, 4))
_P9 = (1, 9, 81, 729, 6561)
_MB_SIZE = 59049


def _crazy(x: int, y: int) -> int:
    t = 0
    for p in _P9:
        t += _CRAZY[(y // p) % 9][(x // p) % 9] * p
    return t


def malbolge_valid(text: str) -> bool:
    """The loader's own check: every character, at its position, is one of the eight instructions."""
    pos = 0
    for ch in text:
        if ch in "\t\r\n\v\f ":
            continue
        c = ord(ch)
        if not 33 <= c <= 126 or _XLAT1[(c - 33 + pos) % 94] not in "ji*p</vo":
            return False
        pos += 1
    return pos >= 8


def malbolge(text: str, steps: int = 2_000_000, deadline=None):
    """What a Malbolge program prints, or None. Refused unless it passes the loader's check, which a
    text that is not a program fails at its first characters; the memory behind the program is filled
    in (59049 words) only when the program reaches for it."""
    if not isinstance(text, str):
        return None
    if len(text) < 8 or not malbolge_valid(text[:16]) or not malbolge_valid(text):
        return None
    mem = [ord(ch) for ch in text if ch not in "\t\r\n\v\f "]
    if len(mem) > _MB_SIZE or len(mem) < 2:
        return None
    loaded = len(mem)

    def fill():
        while len(mem) < _MB_SIZE:
            mem.append(_crazy(mem[-1], mem[-2]))

    a = c = d = 0
    out, count = bytearray(), 0
    while True:
        count += 1
        if count > steps or (count % TICK == 0 and _late(deadline)) or len(out) > OUTPUT:
            return None
        if (c >= loaded or d >= loaded) and len(mem) < _MB_SIZE:
            if _late(deadline):
                return None
            fill()
        v = mem[c]
        if not 33 <= v <= 126:
            return None
        op = _XLAT1[(v - 33 + c) % 94]
        if op == "j":
            d = mem[d]
        elif op == "i":
            c = mem[d]
        elif op == "*":
            m = mem[d]
            a = mem[d] = m // 3 + m % 3 * 19683
        elif op == "p":
            a = mem[d] = _crazy(a, mem[d])
        elif op == "<":
            out.append(a % 256)
        elif op == "/":
            return None                 # input
        elif op == "v":
            break
        if (c >= loaded or d >= loaded) and len(mem) < _MB_SIZE:
            fill()
        if not 33 <= mem[c] <= 126:
            return None
        mem[c] = ord(_XLAT2[mem[c] - 33])
        c = (c + 1) % _MB_SIZE
        d = (d + 1) % _MB_SIZE
    return bytes(out) or None


# ---------------------------------------------------------------------------- JSFuck

JSFUCK = """The JavaScript that jsfuck() knows (anything else is a refusal, never a guess):
values       [] and nested arrays, numbers, strings, true, false, undefined
operators    ! and + before a value, + between two, ++ before a value (one more than its number), [key], (argument)
strings      [index], length, constructor, italics, fontcolor, bold, big, small, strike, sub, sup, blink, fixed,
             anchor, link, fontsize, slice, concat, at, charAt, toUpperCase, toLowerCase, toString, split, join
arrays       [index], length, constructor, concat, join, slice, at, entries, and the function text of any method
numbers      constructor, toString(radix)
functions    Number, String, Boolean, Array, Object, Function, RegExp, Date; name, constructor, call;
             String.fromCharCode, escape, unescape, atob, btoa; eval(source) gives the source, not run
Function(s)  "return <one of the names above, this, /0/, new Date(n), a quoted text>"; any other source text
             is the wrapped program itself: it is returned as text and never run"""


class _Undefined:
    def __repr__(self):
        return "undefined"


_UNDEF = _Undefined()


class _Fn:
    """A native function: its name is its text (function NAME() { [native code] })."""
    def __init__(self, name, call=None, this=None, props=None):
        self.name, self.call, self.this, self.props = name, call, this, props or {}


class _Obj:
    """An object known only by its text and its constructor."""
    def __init__(self, text, ctor=None, props=None):
        self.text, self.ctor, self.props = text, ctor, props or {}


class _Program(Exception):
    """Function(source)() for a source that is not in the vocabulary: the wrapped program."""
    def __init__(self, source):
        self.source = source


def _js_number(x) -> str:
    if x != x:
        return "NaN"
    if x in (math.inf, -math.inf):
        return "Infinity" if x > 0 else "-Infinity"
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(float(x))
    if "e" in r:
        mant, exp = r.split("e")
        if mant.endswith(".0"):
            mant = mant[:-2]
        return mant + "e" + exp[0] + exp[1:].lstrip("0")
    if 0 < abs(x) < 1e-6:   # repr writes 1e-07 for these already; kept for safety
        return r
    return r


def _js_str(v) -> str:
    if isinstance(v, str):
        return v
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is _UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return _js_number(v)
    if isinstance(v, list):
        return ",".join("" if e is _UNDEF or e is None else _js_str(e) for e in v)
    if isinstance(v, _Fn):
        return "function %s() { [native code] }" % v.name
    if isinstance(v, _Obj):
        return v.text
    raise Refuse("value")


_JS_NUMERIC = re.compile(r"[+-]?(?:Infinity|(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?))")


def _js_num(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if v is _UNDEF:
        return math.nan
    if v is None:
        return 0
    if isinstance(v, (list, str)):
        s = _js_str(v).strip()
        if s == "":
            return 0
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            return int(s, 16)
        if not _JS_NUMERIC.fullmatch(s):
            return math.nan
        try:
            x = float(s.replace("Infinity", "inf"))
        except (ValueError, OverflowError):
            return math.nan
        return int(x) if x == x and abs(x) < 1e15 and x == int(x) else x
    return math.nan


def _js_true(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v == v and v != 0
    if isinstance(v, str):
        return v != ""
    return not (v is _UNDEF or v is None)


def _js_add(a, b):
    if isinstance(a, (list, _Fn, _Obj)):
        a = _js_str(a)
    if isinstance(b, (list, _Fn, _Obj)):
        b = _js_str(b)
    if isinstance(a, str) or isinstance(b, str):
        out = _js_str(a) + _js_str(b)
        if len(out) > 1 << 20:
            raise Refuse("long")
        return out
    return _js_num(a) + _js_num(b)


def _escape(s: str) -> str:
    return "".join(c if (c.isascii() and c.isalnum()) or c in "@*_+-./" else
                   ("%%%02X" % ord(c) if ord(c) < 256 else "%%u%04X" % ord(c)) for c in s)


def _unescape(s: str) -> str:
    return re.sub(r"%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1) or m.group(2), 16)), s)


def _to_radix(n, radix) -> str:
    n, radix = _js_num(n), (10 if radix is _UNDEF else _js_num(radix))
    if n != n or n in (math.inf, -math.inf) or n != int(n) or n < 0 or not 2 <= radix <= 36:
        if radix == 10:
            return _js_number(n)
        raise Refuse("radix")
    n, radix, digits = int(n), int(radix), ""
    while True:
        n, r = divmod(n, radix)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[r] + digits
        if not n:
            return digits


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_DAYS = ("Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed")   # 1970-01-01 was a Thursday


def _date_text(ms=None) -> str:
    """Date's text in the form every engine prints (Thu Jan 01 1970 00:00:00 GMT+0000 (...)). Without a
    time it is a fixed day: JSFuck reads only the letters G, M and T out of it, which stand at the same
    places on any day."""
    days = 20000 if ms is None else int(ms // 86_400_000)
    secs = 0 if ms is None else int(ms // 1000) % 86400
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    year = yoe + era * 400 + (1 if month <= 2 else 0)
    return "%s %s %02d %04d %02d:%02d:%02d GMT+0000 (Coordinated Universal Time)" % (
        _DAYS[days % 7], _MONTHS[month - 1], day, year, secs // 3600, secs // 60 % 60, secs % 60)


_HTML_WRAP = {"italics": "i", "bold": "b", "big": "big", "small": "small", "strike": "strike", "sub": "sub",
              "sup": "sup", "blink": "blink", "fixed": "tt"}
_HTML_ATTR = {"fontcolor": ("font", "color"), "fontsize": ("font", "size"), "anchor": ("a", "name"), "link": ("a", "href")}
_ARRAY_METHODS = ("filter", "fill", "find", "flat", "at", "entries", "concat", "join", "slice", "sort", "pop", "push", "map",
                  "indexOf", "includes", "keys", "some", "every", "reduce", "reverse", "findIndex", "forEach", "flatMap",
                  "lastIndexOf", "shift", "unshift", "splice", "values", "copyWithin", "findLast", "toString")
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class _JS:
    def __init__(self, src, deadline):
        self.s, self.i, self.n, self.deadline, self.count = src, 0, len(src), deadline, 0
        fn = self.Function = _Fn("Function", self._function)
        self.ctors = {
            "Number": _Fn("Number", lambda this, a: 0 if a is _UNDEF else _js_num(a)),
            "String": _Fn("String", lambda this, a: "" if a is _UNDEF else _js_str(a),
                          props={"fromCharCode": _Fn("fromCharCode", lambda this, a: self._chr(a)),
                                 "fromCodePoint": _Fn("fromCodePoint", lambda this, a: self._chr(a))}),
            "Boolean": _Fn("Boolean", lambda this, a: _js_true(a)),
            "Array": _Fn("Array", lambda this, a: []),
            "Object": _Fn("Object", lambda this, a: self._object()),
            "RegExp": _Fn("RegExp", lambda this, a: self._regexp(
                "(?:)" if a is _UNDEF or _js_str(a) == "" else re.sub(r"(?<!\\)/", r"\\/", _js_str(a)))),
            "Date": _Fn("Date", lambda this, a: _date_text()),
            "Function": fn,
        }
        self.globals = dict(self.ctors)
        self.globals.update({
            "escape": _Fn("escape", lambda this, a: _escape(_js_str(a))),
            "unescape": _Fn("unescape", lambda this, a: _unescape(_js_str(a))),
            "atob": _Fn("atob", lambda this, a: self._atob(_js_str(a))),
            "btoa": _Fn("btoa", lambda this, a: self._btoa(_js_str(a))),
            "eval": _Fn("eval", self._eval),
        })

    # -- host pieces
    @staticmethod
    def _chr(a):
        n = _js_num(a)
        if n != n or not 0 <= n <= 0x10FFFF:
            raise Refuse("char code")
        return chr(int(n))

    @staticmethod
    def _atob(s):
        import base64
        try:
            return base64.b64decode(s + "=" * (-len(s) % 4), validate=True).decode("latin-1")
        except Exception:
            raise Refuse("atob")

    @staticmethod
    def _btoa(s):
        import base64
        try:
            return base64.b64encode(s.encode("latin-1")).decode()
        except Exception:
            raise Refuse("btoa")

    @staticmethod
    def _eval(this, a):
        if not isinstance(a, str):
            return a
        raise _Program(a)      # eval(source): the wrapped program, read and not run

    def _object(self):
        return _Obj("[object Object]", self.ctors["Object"])

    def _regexp(self, source):
        return _Obj("/%s/" % source, self.ctors["RegExp"])

    def _function(self, this, a):
        source = "" if a is _UNDEF else _js_str(a)

        def run(this2, arg):
            body = source.strip().rstrip(";").strip()
            m = re.fullmatch(r"return\s*(.*)", body, re.S)
            what = m.group(1).strip() if m else None
            if what in self.globals:
                return self.globals[what]
            if what == "this":
                return _Obj("[object Window]")
            if what is not None:
                rx = re.fullmatch(r"/((?:[^/\\\n]|\\.)+)/", what)
                if rx:
                    return self._regexp(rx.group(1))
                dt = re.fullmatch(r"new\s+Date\(\s*(\d{1,16})\s*\)", what)
                if dt:
                    return _Obj(_date_text(int(dt.group(1))), self.ctors["Date"])
                if re.fullmatch(r"new\s+Date(?:\(\s*\))?", what) or what == "Date()":
                    return _Obj(_date_text(), self.ctors["Date"])
                q = re.fullmatch(r"([\"'])((?:[^\\\n]|\\.)*)\1", what, re.S)
                if q and q.group(1) not in re.sub(r"\\.", "", q.group(2)):
                    return self._unquote(q.group(2))
            raise _Program(source)
        return _Fn("anonymous", run)

    @staticmethod
    def _unquote(body: str) -> str:
        simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}

        def one(m):
            u4, ub, x, o, c = m.groups()
            if u4 or ub or x:
                v = int(u4 or ub or x, 16)
                if v > 0x10FFFF:
                    raise Refuse("escape")
                return chr(v)
            if o:
                return chr(int(o, 8))
            return simple.get(c, c)
        return re.sub(r"\\(?:u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}|x([0-9a-fA-F]{2})|([0-7]{1,3})|(.))", one, body, flags=re.S)

    # -- property access and calls
    def member(self, obj, key):
        k = _js_str(key)
        if isinstance(obj, str):
            if k.isdigit():
                return obj[int(k)] if int(k) < len(obj) else _UNDEF
            if k == "length":
                return len(obj)
            if k == "constructor":
                return self.ctors["String"]
            if k in _HTML_WRAP:
                tag = _HTML_WRAP[k]
                return _Fn(k, lambda this, a: "<%s>%s</%s>" % (tag, this, tag), obj)
            if k in _HTML_ATTR:
                tag, attr = _HTML_ATTR[k]
                return _Fn(k, lambda this, a: '<%s %s="%s">%s</%s>' % (tag, attr, _js_str(a).replace('"', "&quot;"), this, tag), obj)
            table = {
                "slice": lambda this, a: this[self._index(a, len(this)):],
                "concat": lambda this, a: this + ("" if a is _UNDEF else _js_str(a)),
                "at": lambda this, a: self._at(this, a),
                "charAt": lambda this, a: (this[int(_js_num(a) or 0)] if 0 <= (_js_num(a) or 0) < len(this) else ""),
                "toUpperCase": lambda this, a: this.upper(),
                "toLowerCase": lambda this, a: this.lower(),
                "toString": lambda this, a: this,
                "valueOf": lambda this, a: this,
                "trim": lambda this, a: this.strip(),
                "split": lambda this, a: ([this] if a is _UNDEF else list(this) if _js_str(a) == "" else this.split(_js_str(a))),
            }
            if k in table:
                return _Fn(k, table[k], obj)
            return _UNDEF
        if isinstance(obj, list):
            if k.isdigit():
                return obj[int(k)] if int(k) < len(obj) else _UNDEF
            if k == "length":
                return len(obj)
            if k == "constructor":
                return self.ctors["Array"]
            table = {
                "concat": lambda this, a: this + (a if isinstance(a, list) else [] if a is _UNDEF else [a]),
                "join": lambda this, a: ("," if a is _UNDEF else _js_str(a)).join(
                    "" if e is _UNDEF or e is None else _js_str(e) for e in this),
                "slice": lambda this, a: this[self._index(a, len(this)):],
                "at": lambda this, a: self._at(this, a),
                "entries": lambda this, a: _Obj("[object Array Iterator]", self.ctors["Object"]),
                "keys": lambda this, a: _Obj("[object Array Iterator]", self.ctors["Object"]),
                "values": lambda this, a: _Obj("[object Array Iterator]", self.ctors["Object"]),
                "toString": lambda this, a: _js_str(this),
            }
            if k in table:
                return _Fn(k, table[k], obj)
            if k in _ARRAY_METHODS:
                return _Fn(k, None, obj)    # its text is known, calling it is not
            return _UNDEF
        if isinstance(obj, bool):
            return self.ctors["Boolean"] if k == "constructor" else _UNDEF
        if isinstance(obj, (int, float)):
            if k == "constructor":
                return self.ctors["Number"]
            if k == "toString":
                return _Fn(k, lambda this, a: _to_radix(this, a), obj)
            return _UNDEF
        if isinstance(obj, _Fn):
            if k in obj.props:
                return obj.props[k]
            if k == "constructor":
                return self.Function
            if k == "name":
                return obj.name
            if k == "call":
                target = obj
                if target.call is None:
                    raise Refuse("call")
                return _Fn("call", lambda this, a: target.call(a, _UNDEF))
            if k == "toString":
                return _Fn(k, lambda this, a: _js_str(this), obj)
            return _UNDEF
        if isinstance(obj, _Obj):
            if k in obj.props:
                return obj.props[k]
            if k == "constructor":
                return obj.ctor if obj.ctor is not None else self.ctors["Object"]
            if k == "toString":
                return _Fn("toString", lambda this, a: "[object Undefined]" if this is _UNDEF else "[object Object]"
                           if isinstance(this, _Obj) and this.text.startswith("[object") else _js_str(this), obj)
            if k == "source" and obj.text.startswith("/"):
                return obj.text[1:-1]
            return _UNDEF
        raise Refuse("property of undefined")

    @staticmethod
    def _index(a, n):
        i = 0 if a is _UNDEF else _js_num(a)
        if i != i:
            i = 0
        i = int(i)
        return max(0, n + i) if i < 0 else min(i, n)

    @staticmethod
    def _at(this, a):
        i = 0 if a is _UNDEF else _js_num(a)
        i = 0 if i != i else int(i)
        if i < 0:
            i += len(this)
        return this[i] if 0 <= i < len(this) else _UNDEF

    def _call_fn(self, fn, this, arg):
        if not isinstance(fn, _Fn) or fn.call is None:
            raise Refuse("call")
        return fn.call(fn.this if fn.this is not None else this, arg)

    # -- the parser
    def peek(self):
        return self.s[self.i] if self.i < self.n else ""

    def expr(self):
        left = self.unary()
        while self.peek() == "+":
            self.i += 1
            left = _js_add(left, self.unary())
        return left

    def unary(self):
        c = self.peek()
        if c == "!":
            self.i += 1
            return not _js_true(self.unary())
        if c == "+":
            if self.s.startswith("++", self.i):
                self.i += 2
                return _js_num(self.unary()) + 1
            self.i += 1
            return _js_num(self.unary())
        return self.postfix()

    def postfix(self):
        self.count += 1
        if self.count % 512 == 0 and _late(self.deadline):
            raise Refuse("time")
        c = self.peek()
        this = _UNDEF
        if c == "[":
            self.i += 1
            if self.peek() == "]":
                value = []
            else:
                value = [self.expr()]
            self._eat("]")
        elif c == "(":
            self.i += 1
            value = self.expr()
            self._eat(")")
        else:
            raise Refuse("syntax")
        while True:
            c = self.peek()
            if c == "[":
                self.i += 1
                key = self.expr()
                self._eat("]")
                if value is _UNDEF or value is None:
                    raise Refuse("property of undefined")
                this, value = value, self.member(value, key)
            elif c == "(":
                self.i += 1
                arg = _UNDEF if self.peek() == ")" else self.expr()
                self._eat(")")
                this, value = _UNDEF, self._call_fn(value, this, arg)
            else:
                return value

    def _eat(self, c):
        if self.peek() != c:
            raise Refuse("syntax")
        self.i += 1


_JSFUCK_CHARS = re.compile(r"[\[\]()!+\s]+")


def jsfuck(text: str, deadline=None):
    """The text a JSFuck expression stands for, or None. A program wrapped for eval
    ([]["filter"]["constructor"](SOURCE)()) gives SOURCE: it is read, not run."""
    if not isinstance(text, str):
        return None
    if len(text) < 12 or not _JSFUCK_CHARS.fullmatch(text):
        return None
    src = re.sub(r"\s+", "", text)
    if len(src) < 12:
        return None
    js = _JS(src, deadline)
    limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(max(limit, 5000))
        value = js.expr()
        if js.i != js.n:
            return None
        out = _js_str(value)
    except _Program as p:
        out = p.source
    except (Refuse, RecursionError, IndexError, ValueError, OverflowError, TypeError):
        return None
    finally:
        sys.setrecursionlimit(limit)
    return out.encode("utf-8", "replace") if out else None


# ---------------------------------------------------------------------------- Deadfish

_DEADFISH = frozenset(b"ids o\t\r\n")   # the four instructions and white space


def deadfish(text: str, steps: int = STEPS, deadline=None):
    """What a Deadfish program prints as raw bytes, or None. Deadfish is a single accumulator and four
    instructions: 'i' increment, 'd' decrement, 's' square, 'o' output. After every i/d/s the value
    resets to 0 when it is -1 or 256 (the language's own rule). It has no loops and reads no input, so
    the run is linear in the program length and a step cap and output cap bound it; the deadline is only
    a courtesy. The reader is strict: the text is nothing but the four instructions and white space, and
    it must hold at least one 'o' (nothing printed otherwise). 'o' is read as the byte output variant the
    text warmups use (the raw accumulator byte, not its decimal spelling): a number-output program does
    not reproduce the sentence and is left None by the caller."""
    if not isinstance(text, str):
        return None
    body = text.strip()
    data = body.encode("latin-1", "replace")
    if len(body) < 2 or set(data) - _DEADFISH or b"o" not in data:
        return None
    acc, out, count = 0, bytearray(), 0
    for ch in body:
        count += 1
        if count > steps or len(out) > OUTPUT:
            return None
        if ch == "o":
            if not (count & 0x3FFF) and _late(deadline):
                return None
            out.append(acc & 0xFF)
            continue
        if ch == "i":
            acc += 1
        elif ch == "d":
            acc -= 1
        elif ch == "s":
            acc *= acc
        else:            # white space
            continue
        if acc == -1 or acc == 256:
            acc = 0
    if len(out) > OUTPUT:                 # a final output instruction must still respect the cap
        return None
    return bytes(out) or None


def deadfish_encode(data: bytes) -> str:
    """A Deadfish program that prints `data` as bytes (for tests): each byte reached from the last by
    counting up or down, then 'o'. No square is used, so it never trips the reset rule."""
    out, cur = [], 0
    for b in data:
        out.append(("i" if b > cur else "d") * abs(b - cur) + "o")
        cur = b
    return "".join(out)


READERS = (("cow", cow), ("whitespace", whitespace), ("befunge", befunge), ("malbolge", malbolge),
           ("jsfuck", jsfuck), ("deadfish", deadfish))


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: esolangs.py <file> [...]", file=sys.stderr)
        return 2
    for path in argv:
        try:
            raw = open(path, "rb").read()
        except OSError as e:
            print("%s: %s" % (path, e.strerror or e), file=sys.stderr)
            continue
        text = raw.decode("utf-8", "replace")
        hits = 0
        for name, reader in READERS:
            out = reader(text, deadline=time.perf_counter() + 10)
            if out is not None:
                hits += 1
                print("%s: %s prints %r" % (path, name, out[:400]))
        if not hits:
            print("%s: no reader takes it" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
