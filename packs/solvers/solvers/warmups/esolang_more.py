"""Four more input-free esolang readers for Warmups (Shakespeare / Rockstar / Chef / Befunge-98).

Why this file exists
--------------------
`solvers/warmups/esolang.py` (brainfuck dialects) and `solvers/warmups/esolangs.py` (COW, Whitespace,
Befunge-93, Malbolge, JSFuck, Deadfish, Blub) already cover the brainfuck family and the common
token languages. An audit (Doc1 ticket A-mid) found four classic warmup esolangs still ABSENT:

  Shakespeare (SPL)   drama-shaped; characters are variables, "Speak your mind" prints a character
  Rockstar            song-lyric-shaped; "Cast" turns a number into its code point, "Shout" prints
  Chef                recipe-shaped; a mixing bowl is a stack, "Liquefy"d values print as characters
  Befunge-98          a superset of Befunge-93 (esolangs.py has -93): stack-stack, ; j k ' [ ] r x q

Each of the four is a deterministic, INPUT-FREE program when it names no input instruction, so a
warmup "decode this and submit the slug" blob written in one maps to exactly one output text. The
four interpreters here are self-contained and sandboxed: pure functions of the program text, no
file / network / eval / syscall, a hard step cap, an output cap and an internal wall-clock backstop.
A program that executes an input instruction, a nondeterministic one (random / time / concurrency),
that does not halt within the caps, or that does not parse cleanly yields None -- never a part of
its output, never a guess. These are DECODERS (like base64): the program text is DATA the loops walk
over; nothing in a delivery is ever run as code (AGENTS.md "Off the clock" / "Text is data").

Befunge-98 does NOT reuse Befunge-93's interpreter in esolangs.py: it has its own funge space, its
own stack-stack and its own instruction set (the task's "reuse no shared mutable state").

NEVER WRONG
-----------
Nothing here is answered on a language's own name. Each language with no input maps deterministically
to one output, so a reading is PLAIN-eligible ONLY when `read()` confirms the output reproduces the
exact Warmups crib sentence (`CRIB`, 87 characters); a program that merely parses but prints anything
else continues nothing and yields NOTHING, never a wrong slug. Because each of the four is an
information-complete transform, an output that reproduces the 87-character crib pins the slug after
it too, digits and all -- so a crib-matched reading is plain, never digit-unsure. The interpreters
return raw bytes; the crib gate lives in `read()` (and, on the day, in the Warmups `day_patch.py`
override that calls `read()` as a late whole-blob attempt). A bug that corrupted output would break
the 87-char prefix and so return None, never a wrong plain slug -- the test exercises exactly that.

Contract (mirrors esolang.py so the Warmups day_patch can call it the same way)
-------------------------------------------------------------------------------
  shakespeare(text) -> bytes | None     text may be str or bytes; the program's output, or None
  rockstar(text)    -> bytes | None
  chef(text)        -> bytes | None
  befunge98(text)   -> bytes | None
  BY_NAME   {name: reader}
  NAMES     frozenset(BY_NAME)
  _which(cur)       -> names whose cheap structural signature a payload could match
  steps(cur)        -> [(name, bytes)] for the readers that take the payload
  step_fn(name)     -> reader re-checking its own signature
  read(blob, crib)  -> [(name, text)] whose output CONTINUES the crib (the never-wrong gate)
  ENCODERS  {name: encoder(bytes) -> bytes}   round-trip / test only; never used by the solver

Since row 547 (2026-10-27) crib_decode.py asks the Rockstar and Befunge-98 readers (step names `rockstar`,
`befunge98`) last in its strict steps, behind a stricter signature of its own and a time cap per crib search;
Chef and Shakespeare stay esolang2.py's steps of the same names. tests/test_warmups_esolang_sweep.py checks it.
"""

import math
import re
import sys
import time

# -- bounds -------------------------------------------------------------------------------------
STEPS = 2_000_000        # hard instruction cap of every interpreter
OUTPUT = 65_536          # bytes a program may print before it is abandoned (None)
READER_TIME = 0.10       # wall-clock backstop (s) one reader call may run
TICK = 1 << 14           # instructions between two looks at the wall clock
MAX_PROG = 256 * 1024    # bytes of a program a reader runs
MIN_PROG = 16            # bytes below which nothing is attempted (noise)
FUNGE_CELLS = 1 << 20    # hard cap on the number of funge-space cells a Befunge-98 program may touch


class _Halt(Exception):
    """A program reached its end instruction (normal stop)."""


class _Refuse(Exception):
    """Not a program of this language, an input / nondeterministic instruction, or over a cap."""


# -- common helpers -----------------------------------------------------------------------------
def _text(b):
    """A payload as a str within the size bounds, or None. Accepts str or bytes; bytes must be
    UTF-8. A payload outside [MIN_PROG, MAX_PROG] bytes is refused before any work."""
    if isinstance(b, str):
        raw = b.encode("utf-8", "surrogatepass")
        t = b
    elif isinstance(b, (bytes, bytearray, memoryview)):
        raw = bytes(b)
        try:
            t = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        return None
    if not (MIN_PROG <= len(raw) <= MAX_PROG):
        return None
    return t


def _deadline():
    return time.perf_counter() + READER_TIME


class _Out:
    """A bounded output accumulator. append() raises _Refuse past OUTPUT bytes; an undecodable
    code point also refuses (a deterministic program that prints text keeps to real characters)."""

    __slots__ = ("buf",)

    def __init__(self):
        self.buf = bytearray()

    def byte(self, v):
        self.buf.append(v & 0xFF)
        if len(self.buf) > OUTPUT:
            raise _Refuse("output over the cap")

    def codepoint(self, v):
        if 0 <= v < 256:
            self.buf.append(v)
        else:
            try:
                self.buf += chr(v).encode("utf-8")
            except (ValueError, OverflowError):
                raise _Refuse("output code point out of range")
        if len(self.buf) > OUTPUT:
            raise _Refuse("output over the cap")

    def text(self, s):
        self.buf += s.encode("utf-8")
        if len(self.buf) > OUTPUT:
            raise _Refuse("output over the cap")

    def value(self):
        return bytes(self.buf) or None


# ================================================================================================
# Befunge-98  (its own funge space and stack-stack; not esolangs.py's Befunge-93)
# ================================================================================================
# Instructions that read input, are nondeterministic, touch the environment, fork, or run external
# code are refused the moment the IP executes them (a program that never reaches one still runs):
_B98_REFUSE = set("&~?=yti")          # input int/char, random, exec, sysinfo(time), concurrency, file-in
# 'o' (file out) and '(' ')' (fingerprints) are refused too; handled explicitly below.


def befunge98(text):
    """What a Befunge-98 program prints, as bytes, or None. Refuses input / random / time /
    concurrency / file / fingerprint / shell instructions (executed), a program that does not halt
    within the caps, or output over the cap. `,` prints a byte, `.` an integer and a space."""
    t = _text(text)
    if t is None:
        return None
    try:
        return _run_befunge98(t, _deadline())
    except _Halt as h:
        return h.args[0] or None
    except _Refuse:
        return None
    except (ValueError, IndexError, ZeroDivisionError, OverflowError, RecursionError):
        return None


def _run_befunge98(src, deadline):
    lines = src.split("\n")
    height = len(lines)
    width = max((len(ln) for ln in lines), default=0)
    if width == 0 or height == 0:
        raise _Refuse("empty")
    grid = {}
    touched = 0
    for y, ln in enumerate(lines):
        for x, ch in enumerate(ln):
            if ch != " ":
                grid[(x, y)] = ord(ch)
                touched += 1

    def get(x, y):
        return grid.get((x, y), 32)

    def put(x, y, v):
        nonlocal touched, width, height
        if (x, y) not in grid:
            touched += 1
            if touched > FUNGE_CELLS:
                raise _Refuse("funge space too large")
        grid[(x, y)] = v & 0x7FFFFFFF
        if 0 <= x < 1 << 20 and x >= width:
            width = x + 1
        if 0 <= y < 1 << 20 and y >= height:
            height = y + 1

    out = _Out()
    stacks = [[]]                         # stack stack; stacks[-1] is the current TOSS
    x = y = 0
    dx, dy = 1, 0
    strmode = False
    str_prev_space = False                 # a run of spaces in string mode pushes one space (98 spec)
    count = 0

    def push(v):
        stacks[-1].append(v & 0x7FFFFFFF if v >= 0 else -((-v) & 0x7FFFFFFF))

    def pop():
        return stacks[-1].pop() if stacks[-1] else 0

    def step_ip():
        nonlocal x, y
        x = (x + dx) % width if width else 0
        y = (y + dy) % height if height else 0

    while True:
        count += 1
        if count > STEPS:
            raise _Refuse("step cap")
        if not (count & (TICK - 1)) and time.perf_counter() > deadline:
            raise _Refuse("time")
        c = get(x, y)
        ch = chr(c) if 0 <= c < 0x110000 else "�"

        if strmode:
            if ch == '"':
                strmode = False
            elif ch == " ":
                if not str_prev_space:     # collapse contiguous spaces to a single space
                    push(c)
                str_prev_space = True
                step_ip()
                continue
            else:
                push(c)
            str_prev_space = False
            step_ip()
            continue

        if "0" <= ch <= "9":
            push(ord(ch) - 48)
        elif "a" <= ch <= "f":
            push(ord(ch) - 87)            # 98: a..f push 10..15
        elif ch == '"':
            strmode = True
            str_prev_space = False
        elif ch == "'":                   # fetch: push the next cell, skip over it
            step_ip()
            push(get(x, y))
        elif ch == "+":
            push(pop() + pop())
        elif ch == "*":
            push(pop() * pop())
        elif ch == "-":
            a = pop(); b = pop(); push(b - a)
        elif ch == "/":
            a = pop(); b = pop(); push(0 if a == 0 else int(b / a))
        elif ch == "%":
            a = pop(); b = pop(); push(0 if a == 0 else b - int(b / a) * a)
        elif ch == "!":
            push(0 if pop() else 1)
        elif ch == "`":
            a = pop(); b = pop(); push(1 if b > a else 0)
        elif ch == ">":
            dx, dy = 1, 0
        elif ch == "<":
            dx, dy = -1, 0
        elif ch == "^":
            dx, dy = 0, -1
        elif ch == "v":
            dx, dy = 0, 1
        elif ch == "_":
            dx, dy = (-1, 0) if pop() else (1, 0)
        elif ch == "|":
            dx, dy = (0, -1) if pop() else (0, 1)
        elif ch == "w":                   # 98 compare
            a = pop(); b = pop()
            if b < a:
                dx, dy = _turn_left(dx, dy)
            elif b > a:
                dx, dy = _turn_right(dx, dy)
        elif ch == "[":                   # 98 turn left
            dx, dy = _turn_left(dx, dy)
        elif ch == "]":                   # 98 turn right
            dx, dy = _turn_right(dx, dy)
        elif ch == "r":                   # 98 reflect
            dx, dy = -dx, -dy
        elif ch == "x":                   # 98 absolute delta
            a = pop(); b = pop(); dx, dy = b, a
        elif ch == ":":
            v = pop(); push(v); push(v)
        elif ch == "\\":
            a = pop(); b = pop(); push(a); push(b)
        elif ch == "$":
            pop()
        elif ch == "n":                   # 98 clear stack
            stacks[-1].clear()
        elif ch == ".":
            out.text(str(pop()) + " ")
        elif ch == ",":
            out.codepoint(pop())
        elif ch == "#":                   # trampoline
            step_ip()
        elif ch == "j":                   # 98 jump forward n cells
            n = pop()
            for _ in range(abs(n) % (width * height + 1)):
                if n >= 0:
                    step_ip()
                else:
                    x = (x - dx) % width
                    y = (y - dy) % height
        elif ch == "k":                   # 98 iterate: run the next instruction n times
            n = pop()
            step_ip()
            nc = get(x, y)
            nch = chr(nc) if 0 <= nc < 0x110000 else "�"
            if n > 0:
                if n > STEPS:
                    raise _Refuse("iterate count too large")
                for _ in range(n):
                    _b98_simple(nch, push, pop, out)
        elif ch == "s":                   # 98 store char: write popped value to the next cell, skip it
            v = pop()
            step_ip()
            put(x, y, v)
        elif ch == "{":                   # 98 begin block (stack-stack)
            n = pop()
            cur = stacks[-1]
            moved = []
            if n > 0:
                for _ in range(min(n, len(cur))):
                    moved.append(cur.pop())
                for _ in range(max(0, n - len(cur) - 0)):
                    pass
                moved = moved[::-1]
                while len(moved) < n:
                    moved.insert(0, 0)
            elif n < 0:
                for _ in range(-n):
                    cur.append(0)
            stacks.append(moved)
        elif ch == "}":                   # 98 end block
            if len(stacks) < 2:
                dx, dy = -dx, -dy         # reflect: no SOSS
            else:
                n = pop()
                top = stacks.pop()
                soss = stacks[-1]
                if n > 0:
                    take = top[-n:] if n <= len(top) else ([0] * (n - len(top)) + top)
                    soss.extend(take)
                elif n < 0:
                    for _ in range(-n):
                        if soss:
                            soss.pop()
        elif ch == "u":                   # 98 stack under stack
            if len(stacks) < 2:
                dx, dy = -dx, -dy
            else:
                n = pop()
                toss = stacks[-1]
                soss = stacks[-2]
                if n > 0:
                    for _ in range(n):
                        toss.append(soss.pop() if soss else 0)
                elif n < 0:
                    for _ in range(-n):
                        soss.append(toss.pop() if toss else 0)
        elif ch == "p":                   # put
            yy = pop(); xx = pop(); v = pop()
            put(xx, yy, v)
        elif ch == "g":                   # get
            yy = pop(); xx = pop(); push(get(xx, yy))
        elif ch == ";":                   # 98 jump over: skip to the next ';'
            while True:
                step_ip()
                if get(x, y) == ord(";"):
                    break
                count += 1
                if count > STEPS:
                    raise _Refuse("step cap in comment")
        elif ch == "@":
            raise _Halt(out.value())
        elif ch == "q":                   # 98 quit (ignore the exit code; the output is what we read)
            pop()
            raise _Halt(out.value())
        elif ch in _B98_REFUSE or ch == "o" or ch == "(" or ch == ")":
            raise _Refuse("input / nondeterministic / environment instruction %r" % ch)
        elif ch == " ":
            pass
        elif ch in "z":                   # 98 no-op
            pass
        else:
            # Unknown printable instruction in Befunge-98 reflects. A program that loops forever
            # this way hits the step cap and so returns None, never a wrong output.
            dx, dy = -dx, -dy
        step_ip()


def _b98_simple(nch, push, pop, out):
    """Execute one non-moving instruction for the `k` iterate command (bounded subset)."""
    if "0" <= nch <= "9":
        push(ord(nch) - 48)
    elif "a" <= nch <= "f":
        push(ord(nch) - 87)
    elif nch == "+":
        push(pop() + pop())
    elif nch == "*":
        push(pop() * pop())
    elif nch == "-":
        a = pop(); b = pop(); push(b - a)
    elif nch == ":":
        v = pop(); push(v); push(v)
    elif nch == "$":
        pop()
    elif nch == ",":
        out.codepoint(pop())
    elif nch == ".":
        out.text(str(pop()) + " ")
    elif nch == " ":
        pass
    else:
        raise _Refuse("k over an unsupported instruction %r" % nch)


def _turn_left(dx, dy):
    return dy, -dx


def _turn_right(dx, dy):
    return -dy, dx


# ================================================================================================
# Chef
# ================================================================================================
_ORDINAL = {"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6,
            "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10}
_CHEF_LEAD = {"put", "fold", "add", "remove", "combine", "divide", "liquefy", "liquify", "stir",
              "mix", "clean", "pour", "set", "serve", "serves", "take", "refrigerate"}
_LIQUID_UNITS = {"ml", "l", "dash", "dashes"}
_DRY_UNITS = {"g", "kg", "pinch", "pinches"}
_VAGUE_UNITS = {"cup", "cups", "teaspoon", "teaspoons", "tablespoon", "tablespoons",
                "level", "heaped"}


def chef(text):
    """What a Chef recipe prints, as bytes, or None. "Take ... from refrigerator" (input) and
    "Mix ... well" (randomise) are refused; an auxiliary recipe call, an unknown method statement,
    a program that does not halt within the caps, or output over the cap -> None."""
    t = _text(text)
    if t is None:
        return None
    try:
        return _run_chef(t, _deadline())
    except _Halt as h:
        return h.args[0] or None
    except _Refuse:
        return None
    except (ValueError, IndexError, KeyError, OverflowError):
        return None


def _run_chef(src, deadline):
    paras = [p for p in re.split(r"\n\s*\n", src.replace("\r\n", "\n")) if p.strip()]
    if len(paras) < 2:
        raise _Refuse("no sections")

    ingredients = {}       # name -> [value_or_None, is_liquid]
    method = None
    serves = None
    for p in paras:
        head = p.strip().split("\n", 1)
        first = head[0].strip().rstrip(".").lower()
        body = head[1] if len(head) > 1 else ""
        if first == "ingredients":
            for ln in body.split("\n"):
                _chef_ingredient(ln.strip(), ingredients)
        elif first == "method":
            method = body
        else:
            m = re.match(r"serves\s+(\d+)", p.strip(), re.I)
            if m:
                serves = int(m.group(1))
    if method is None:
        # Some recipes put "Method." inline; try the last paragraph.
        raise _Refuse("no method")

    # Build the statement list.
    flat = " ".join(ln.strip() for ln in method.split("\n"))
    stmts = [s.strip() for s in re.split(r"\.\s*", flat) if s.strip()]
    ing_names = sorted(ingredients, key=len, reverse=True)
    ing_alt = "|".join(re.escape(n) for n in ing_names) if ing_names else r"(?!x)x"

    bowls = {}             # index -> list of [value, is_liquid]
    dishes = {}            # index -> list of [value, is_liquid]

    def bowl(i):
        return bowls.setdefault(i, [])

    def dish(i):
        return dishes.setdefault(i, [])

    def nth(m):
        if not m:
            return 1
        w = m.strip().lower()
        if w in _ORDINAL:
            return _ORDINAL[w]
        if w.isdigit():
            return int(w)
        return 1

    nth_re = r"(?:the\s+)?(?:(\w+)\s+)?mixing bowl"
    pc = 0
    loop_stack = []
    count = 0
    stopped = False
    while pc < len(stmts) and not stopped:
        count += 1
        if count > STEPS:
            raise _Refuse("step cap")
        if not (count & (TICK - 1)) and time.perf_counter() > deadline:
            raise _Refuse("time")
        s = stmts[pc]
        low = s.lower()
        moved = _chef_exec(s, low, ingredients, ing_alt, nth_re, nth, bowl, dish,
                           stmts, loop_stack)
        if moved is _STOP:
            stopped = True
            break
        if isinstance(moved, int):
            pc = moved
        else:
            pc += 1

    out = _Out()
    if serves is None:
        serves = max(dishes) if dishes else 0
    for i in range(1, serves + 1):
        for val, liquid in reversed(dish(i)):     # LIFO: the top of the dish is printed first
            if val is None:
                raise _Refuse("a dish holds an ingredient with no value")
            if liquid:
                out.codepoint(val)
            else:
                out.text(str(val))
    return out.value()


_STOP = object()


def _chef_ingredient(ln, ingredients):
    if not ln:
        return
    m = re.match(r"(-?\d+)\s+(.*)$", ln)
    if m:
        val = int(m.group(1))
        rest = m.group(2).strip()
    else:
        val = None
        rest = ln
    liquid = False
    toks = rest.split()
    if toks:
        unit = toks[0].lower()
        if unit in _LIQUID_UNITS:
            liquid = True
            rest = " ".join(toks[1:])
        elif unit in _DRY_UNITS or unit in _VAGUE_UNITS:
            rest = " ".join(toks[1:])
    name = rest.strip().lower()
    if name:
        ingredients[name] = [val, liquid]


def _chef_exec(s, low, ingredients, ing_alt, nth_re, nth, bowl, dish, stmts, loop_stack):
    # --- refusals: input and nondeterminism ---
    if re.match(r"take\s+.+\s+from\s+refrigerator", low):
        raise _Refuse("Chef input (Take from refrigerator)")
    if re.match(r"mix(\s+.*)?\s+well$", low) or low == "mix well" or re.match(r"mix the .*well$", low):
        raise _Refuse("Chef randomise (Mix well)")
    if low.startswith("serve with "):
        raise _Refuse("auxiliary recipe call")
    if low.startswith("refrigerate"):
        return _STOP

    # --- put / fold ---
    m = re.match(r"put (?:the\s+)?(%s) into %s$" % (ing_alt, nth_re), low)
    if m:
        name, n = m.group(1), nth(m.group(2))
        v = ingredients[name]
        bowl(n).append([v[0], v[1]])
        return None
    m = re.match(r"fold (?:the\s+)?(%s) into %s$" % (ing_alt, nth_re), low)
    if m:
        name, n = m.group(1), nth(m.group(2))
        b = bowl(n)
        if not b:
            raise _Refuse("fold from an empty bowl")
        val, liq = b.pop()
        ingredients[name][0] = val
        return None

    # --- add dry ingredients ---
    m = re.match(r"add dry ingredients(?: to %s)?$" % nth_re, low)
    if m:
        n = nth(m.group(1))
        total = sum(v[0] for v in ingredients.values() if v[0] is not None and not v[1])
        bowl(n).append([total, False])
        return None

    # --- add / remove / combine / divide ---
    for verb, op in (("add", "+"), ("remove", "-"), ("combine", "*"), ("divide", "/")):
        m = re.match(r"%s (?:the\s+)?(%s)(?: (?:to|from|into)? ?%s)?$" % (verb, ing_alt, nth_re), low)
        if m:
            name, n = m.group(1), nth(m.group(2))
            b = bowl(n)
            if not b:
                raise _Refuse("%s with an empty bowl" % verb)
            iv = ingredients[name][0]
            if iv is None:
                raise _Refuse("%s with an ingredient with no value" % verb)
            if op == "+":
                b[-1][0] += iv
            elif op == "-":
                b[-1][0] -= iv
            elif op == "*":
                b[-1][0] *= iv
            else:
                if iv == 0:
                    raise _Refuse("divide by zero")
                b[-1][0] = int(b[-1][0] / iv)
            return None

    # --- liquefy ---
    m = re.match(r"liqu[ei]fy contents of %s$" % nth_re, low)
    if m:
        n = nth(m.group(1))
        for item in bowl(n):
            item[1] = True
        return None
    m = re.match(r"liqu[ei]fy (?:the\s+)?(%s)$" % ing_alt, low)
    if m:
        ingredients[m.group(1)][1] = True
        return None

    # --- stir ---
    m = re.match(r"stir %s for (\d+) minutes?$" % nth_re, low)
    if m:
        n = nth(m.group(1)); rolls = int(m.group(2))
        _chef_roll(bowl(n), rolls)
        return None
    m = re.match(r"stir (?:the\s+)?(%s) into %s$" % (ing_alt, nth_re), low)
    if m:
        name, n = m.group(1), nth(m.group(2))
        iv = ingredients[name][0] or 0
        _chef_roll(bowl(n), iv)
        return None

    # --- clean ---
    m = re.match(r"clean %s$" % nth_re, low)
    if m:
        bowl(nth(m.group(1))).clear()
        return None

    # --- pour ---
    m = re.match(r"pour contents of %s into (?:the\s+)?(?:(\w+)\s+)?baking dish$" % nth_re, low)
    if m:
        bn = nth(m.group(1))
        dn = _ORDINAL.get((m.group(2) or "").lower(), int(m.group(2)) if (m.group(2) or "").isdigit() else 1)
        dish(dn).extend([list(it) for it in bowl(bn)])
        return None

    # --- set aside (break out of the innermost loop) ---
    if low == "set aside":
        if not loop_stack:
            raise _Refuse("Set aside outside a loop")
        open_pc, _ing, close_pc = loop_stack[-1]
        return close_pc + 1

    # --- loop close: "<verb> [the <ing>] until <verbed>" ---
    m = re.match(r"(\w+)(?: (?:the\s+)?(%s))? until (\w+)$" % ing_alt, low)
    if m and " until " in (" " + low + " "):
        if not loop_stack:
            raise _Refuse("loop close without an open")
        open_pc, open_ing, _ = loop_stack[-1]
        dec_ing = m.group(2)
        if dec_ing is not None and ingredients[dec_ing][0] is not None:
            ingredients[dec_ing][0] -= 1
        loop_stack.pop()
        if ingredients[open_ing][0]:
            return open_pc
        return None

    # --- loop open: "<verb> the <ing>" ---
    m = re.match(r"(\w+) (?:the\s+)?(%s)$" % ing_alt, low)
    if m and m.group(1) not in _CHEF_LEAD:
        open_ing = m.group(2)
        if ingredients[open_ing][0]:
            # enter the loop: find the matching close and record it
            close_pc = _chef_match_close(stmts, _current_index(stmts, s), ing_alt)
            loop_stack.append((_current_index(stmts, s), open_ing, close_pc))
            return None
        else:
            # skip the loop body entirely
            close_pc = _chef_match_close(stmts, _current_index(stmts, s), ing_alt)
            return close_pc + 1

    raise _Refuse("unknown Chef method statement: %r" % s)


def _current_index(stmts, s):
    return stmts.index(s)


def _chef_match_close(stmts, open_pc, ing_alt):
    depth = 0
    for i in range(open_pc, len(stmts)):
        low = stmts[i].lower()
        if re.match(r"(\w+)(?: (?:the\s+)?(%s))? until (\w+)$" % ing_alt, low) and " until " in (" " + low + " "):
            if depth == 1:
                return i
            depth -= 1
        elif re.match(r"(\w+) (?:the\s+)?(%s)$" % ing_alt, low):
            verb = low.split(" ", 1)[0]
            if verb not in _CHEF_LEAD:
                depth += 1
    raise _Refuse("loop open without a matching close")


def _chef_roll(b, n):
    # Chef "Stir ... for n minutes" / roll: the top ingredient goes DOWN n places and the others rise
    # one (David Morgan-Mar's spec). After popping the top, that is index len(b) - n, clamped at 0 so a
    # roll of n >= depth sends the top to the bottom. B-055: was len(b) - n + 1, an off-by-one that left
    # a roll of 1 a no-op and disagreed with the esolang2 Chef; now matches the spec and that reader.
    if not b or n <= 0:
        return
    top = b.pop()
    b.insert(max(0, len(b) - n), top)


# ================================================================================================
# Rockstar
# ================================================================================================
_RS_KEYWORDS = {
    "a", "an", "the", "my", "your", "our", "their", "his", "her", "its",
    "is", "are", "was", "were", "be", "being", "been",
    "put", "into", "let", "in", "say", "shout", "whisper", "scream", "print", "cast", "burn",
    "listen", "to", "build", "up", "knock", "down", "turn", "round",
    "while", "until", "if", "else", "break", "continue", "take", "it",
    "plus", "with", "minus", "without", "times", "of", "over", "and", "or", "not",
    "he", "she", "him", "them", "they", "ze", "zie", "mysterious", "null", "nothing",
    "nowhere", "nobody", "empty", "gone", "true", "false", "yes", "no", "ok", "maybe",
    "higher", "greater", "bigger", "stronger", "lower", "less", "smaller", "weaker", "than",
    "as", "says", "give", "back", "return",
}
_RS_SAY = {"say", "shout", "whisper", "scream", "print"}
_RS_INC = {"up"}
_RS_DEC = {"down"}


def rockstar(text):
    """What a Rockstar program prints, as bytes, or None. "Listen to X" (input) is refused; an
    unknown line, a program that does not halt within the caps, or output over the cap -> None.
    Output is UTF-8 of each value said (a char from a Cast number, a string, or a number)."""
    t = _text(text)
    if t is None:
        return None
    try:
        return _run_rockstar(t, _deadline())
    except _Halt as h:
        return h.args[0] or None
    except _Refuse:
        return None
    except (ValueError, IndexError, KeyError, TypeError):
        return None


def _run_rockstar(src, deadline):
    raw_lines = src.replace("\r\n", "\n").split("\n")
    lines = []
    for ln in raw_lines:
        ln = _rs_strip_comments(ln)         # strip (comments), but not parens inside "strings"
        lines.append(ln.rstrip())
    out = _Out()
    env = {}
    last_var = [None]
    count = [0]
    _rs_block(lines, 0, len(lines), env, out, last_var, deadline, count, in_loop=False)
    return out.value()


def _rs_strip_comments(ln):
    """Remove Rockstar (parenthesised) comments, leaving parentheses inside "quoted strings" intact.
    An unterminated '(' is kept verbatim (it is not a comment), matching the prior regex behaviour."""
    out = []
    i, n = 0, len(ln)
    in_str = False
    while i < n:
        c = ln[i]
        if in_str:
            out.append(c)
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == '(':
            j = ln.find(")", i + 1)
            if j == -1:
                out.append(c)               # unterminated: not a comment, keep it
                i += 1
            else:
                i = j + 1                    # drop the whole (...)
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _rs_block(lines, start, end, env, out, last_var, deadline, count, in_loop):
    """Execute lines[start:end]; return ("break"|"continue"|None)."""
    i = start
    while i < end:
        count[0] += 1
        if count[0] > STEPS:
            raise _Refuse("step cap")
        if not (count[0] & (TICK - 1)) and time.perf_counter() > deadline:
            raise _Refuse("time")
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        low = line.lower()

        # --- block openers: while / until / if ---
        mw = re.match(r"(while|until|if)\s+(.*)$", low)
        if mw:
            kind = mw.group(1)
            block_end = _rs_block_end(lines, i + 1, end)
            if kind in ("while", "until"):
                guard = line[len(mw.group(1)):].strip()
                loops = 0
                while True:
                    loops += 1
                    count[0] += 1
                    if count[0] > STEPS:
                        raise _Refuse("loop step cap")
                    if not (count[0] & (TICK - 1)) and time.perf_counter() > deadline:
                        raise _Refuse("time")
                    cond = _rs_truth(_rs_cond(guard, env, last_var))
                    if kind == "until":
                        cond = not cond
                    if not cond:
                        break
                    sig = _rs_block(lines, i + 1, block_end, env, out, last_var, deadline, count, True)
                    if sig == "break":
                        break
                    # "continue" just re-tests the guard
                i = block_end
                continue
            else:  # if
                cond = _rs_truth(_rs_cond(line[2:].strip(), env, last_var))
                # optional Else on the line after the block
                else_start = else_end = None
                if block_end < end and lines[block_end].strip().lower().startswith("else"):
                    else_start = block_end + 1
                    else_end = _rs_block_end(lines, else_start, end)
                if cond:
                    sig = _rs_block(lines, i + 1, block_end, env, out, last_var, deadline, count, in_loop)
                    if sig:
                        return sig
                elif else_start is not None:
                    sig = _rs_block(lines, else_start, else_end, env, out, last_var, deadline, count, in_loop)
                    if sig:
                        return sig
                i = else_end if else_end is not None else block_end
                continue

        if low in ("break", "break it down") and in_loop:
            return "break"
        if low in ("continue", "take it to the top") and in_loop:
            return "continue"
        if low.startswith("else"):
            i += 1
            continue

        _rs_statement(line, env, out, last_var)
        i += 1
    return None


def _rs_block_end(lines, start, end):
    i = start
    while i < end:
        if not lines[i].strip():
            return i
        i += 1
    return end


def _rs_statement(line, env, out, last_var):
    low = line.lower()

    if re.match(r"listen to\b", low):
        raise _Refuse("Rockstar input (Listen to)")
    if low in ("give back", "return") or low.startswith("give back ") or low.startswith("return "):
        raise _Halt(out.value())

    # Say / Shout / Whisper / Scream / Print <expr>
    m = re.match(r"(say|shout|whisper|scream|print)\s+(.*)$", low)
    if m:
        expr = line[len(m.group(1)):].strip()
        val = _rs_eval(expr, env, last_var)
        out.text(_rs_str(val) + "\n")
        return

    # Cast / Burn <src> into <dst>   (number -> char, string -> parsed number)
    m = re.match(r"(cast|burn)\s+(.*)$", low)
    if m:
        rest = line[len(m.group(1)):].strip()
        mm = re.match(r"(.*)\s+into\s+(.*)$", rest, re.I)
        if mm:
            src_expr, dst = mm.group(1).strip(), mm.group(2).strip()
        else:
            src_expr = dst = rest
        val = _rs_eval(src_expr, env, last_var)
        env[_rs_key(dst, last_var)] = _rs_cast(val)
        last_var[0] = _rs_key(dst, last_var)
        return

    # Build X up / Knock X down
    m = re.match(r"build\s+(.*?)\s+up(\s+up)*$", low)
    if m:
        var = line[5:].strip()
        times = low.count(" up")
        k = _rs_key(var.rsplit(" up", times)[0].strip() if False else _rs_strip_tail(var, "up"), last_var)
        env[k] = (_rs_num(env.get(k, 0))) + times
        last_var[0] = k
        return
    m = re.match(r"knock\s+(.*?)\s+down(\s+down)*$", low)
    if m:
        var = line[5:].strip()
        times = low.count(" down")
        k = _rs_key(_rs_strip_tail(var, "down"), last_var)
        env[k] = (_rs_num(env.get(k, 0))) - times
        last_var[0] = k
        return

    # Put <expr> into <var>
    m = re.match(r"put\s+(.*)\s+into\s+(.*)$", line, re.I)
    if m:
        val = _rs_eval(m.group(1).strip(), env, last_var)
        k = _rs_key(m.group(2).strip(), last_var)
        env[k] = val
        last_var[0] = k
        return

    # Let <var> be <expr>
    m = re.match(r"let\s+(.*)\s+be\s+(.*)$", line, re.I)
    if m:
        k = _rs_key(m.group(1).strip(), last_var)
        val = _rs_eval(m.group(2).strip(), env, last_var)
        env[k] = val
        last_var[0] = k
        return

    # <var> says <poetic string>
    m = re.match(r"(.*?)\s+says\s+(.*)$", line, re.I)
    if m and _rs_looks_var(m.group(1)):
        k = _rs_key(m.group(1).strip(), last_var)
        env[k] = m.group(2)              # the rest of the line, verbatim
        last_var[0] = k
        return

    # <var> is/are/was/were <literal>
    m = re.match(r"(.*?)\s+(is|are|was|were)\s+(.*)$", line, re.I)
    if m and _rs_looks_var(m.group(1)):
        k = _rs_key(m.group(1).strip(), last_var)
        env[k] = _rs_literal(m.group(3).strip())
        last_var[0] = k
        return

    raise _Refuse("unknown Rockstar line: %r" % line)


def _rs_strip_tail(s, word):
    toks = s.split()
    while toks and toks[-1].lower() == word:
        toks.pop()
    return " ".join(toks)


def _rs_looks_var(s):
    s = s.strip()
    return bool(s) and bool(re.match(r"[A-Za-z][A-Za-z\s']*$", s))


def _rs_key(name, last_var):
    name = name.strip()
    low = name.lower()
    if low in ("it", "he", "she", "him", "her", "them", "they", "ze", "zie"):
        if last_var[0] is None:
            raise _Refuse("pronoun with no antecedent")
        return last_var[0]
    return re.sub(r"\s+", " ", low)


def _rs_eval(expr, env, last_var):
    expr = expr.strip()
    # binary arithmetic: plus/with, minus/without, times/of, over
    for ops, fn in ((("plus", "with"), lambda a, b: _rs_add(a, b)),
                    (("minus", "without"), lambda a, b: _rs_num(a) - _rs_num(b)),
                    (("times", "of"), lambda a, b: _rs_num(a) * _rs_num(b)),
                    (("over", "divided by"), lambda a, b: _rs_div(a, b))):
        for op in ops:
            found = list(re.finditer(r"\b%s\b" % re.escape(op), expr, re.I))
            if found:
                m = found[-1]            # rightmost split: binary operators are left-associative
                left = expr[:m.start()].strip()
                right = expr[m.end():].strip()
                if left and right:
                    return fn(_rs_eval(left, env, last_var), _rs_eval(right, env, last_var))
    return _rs_value(expr, env, last_var)


def _rs_value(tok, env, last_var):
    t = tok.strip()
    if t == "":
        return 0
    if t[0] == '"' and t[-1] == '"' and len(t) >= 2:
        return t[1:-1]
    low = t.lower()
    if low in ("true", "yes", "ok", "right"):
        return True
    if low in ("false", "no", "lies", "wrong"):
        return False
    if low in ("nothing", "nowhere", "nobody", "null", "gone", "empty", "mysterious"):
        return 0
    if re.match(r"-?\d+(\.\d+)?$", t):
        f = float(t)
        return int(f) if f.is_integer() else f
    k = _rs_key(t, last_var)
    if k in env:
        last_var[0] = k
        return env[k]
    raise _Refuse("undefined Rockstar variable: %r" % t)


def _rs_literal(rest):
    """A literal after is/are/was/were: a quoted string, a plain number, or a poetic number."""
    rest = rest.strip()
    if rest and rest[0] == '"' and rest[-1] == '"':
        return rest[1:-1]
    if re.match(r"-?\d+(\.\d+)?$", rest):
        f = float(rest)
        return int(f) if f.is_integer() else f
    low = rest.lower()
    if low in ("true", "yes", "false", "no", "nothing", "null", "nowhere", "nobody", "empty",
               "gone", "mysterious"):
        return _rs_value(rest, {}, [None])
    # poetic number literal: each word's letter-count mod 10 is a digit; '.' is the decimal point.
    digits = []
    had_dot = False
    for word in re.findall(r"[A-Za-z']+|\.", rest):
        if word == ".":
            digits.append(".")
            had_dot = True
        else:
            n = len(re.sub(r"[^A-Za-z]", "", word))
            digits.append(str(n % 10))
    if not digits or all(d == "." for d in digits):
        raise _Refuse("empty poetic literal")
    s = "".join(digits)
    f = float(s)
    return f if had_dot else int(f)


def _rs_cond(expr, env, last_var):
    expr = expr.strip().rstrip("?")
    m = re.match(r"(.*?)\s+(is|are|was|were)\s+(.*)$", expr, re.I)
    if m:
        left = _rs_eval(m.group(1), env, last_var)
        rest = m.group(3).strip()
        mc = re.match(r"(?:as\s+\w+\s+as\s+)(.*)$", rest, re.I)
        if mc:
            return _rs_eq(left, _rs_eval(mc.group(1), env, last_var))
        mc = re.match(r"(?:higher|greater|bigger|stronger)\s+than\s+(.*)$", rest, re.I)
        if mc:
            return _rs_num(left) > _rs_num(_rs_eval(mc.group(1), env, last_var))
        mc = re.match(r"(?:lower|less|smaller|weaker)\s+than\s+(.*)$", rest, re.I)
        if mc:
            return _rs_num(left) < _rs_num(_rs_eval(mc.group(1), env, last_var))
        if rest.lower().startswith("not "):
            return not _rs_eq(left, _rs_eval(rest[4:], env, last_var))
        return _rs_eq(left, _rs_eval(rest, env, last_var))
    mc = re.match(r"(.*?)\s+(?:ain't|aint|isn't|isnt)\s+(.*)$", expr, re.I)
    if mc:
        return not _rs_eq(_rs_eval(mc.group(1), env, last_var), _rs_eval(mc.group(2), env, last_var))
    return _rs_eval(expr, env, last_var)


def _rs_eq(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return _rs_truth(a) == _rs_truth(b)
    return a == b


def _rs_truth(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v != ""
    return bool(v)


def _rs_num(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        try:
            f = float(v)
            return int(f) if f.is_integer() else f
        except ValueError:
            raise _Refuse("not a number: %r" % v)
    raise _Refuse("not a number")


def _rs_add(a, b):
    if isinstance(a, str) or isinstance(b, str):
        return _rs_str(a) + _rs_str(b)
    return _rs_num(a) + _rs_num(b)


def _rs_div(a, b):
    db = _rs_num(b)
    if db == 0:
        raise _Refuse("division by zero")
    r = _rs_num(a) / db
    return int(r) if isinstance(r, float) and r.is_integer() else r


def _rs_cast(v):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        n = int(v)
        if 0 <= n <= 0x10FFFF:
            return chr(n)
        raise _Refuse("Cast of a code point out of range")
    if isinstance(v, str):
        m = re.match(r"-?\d+", v.strip())
        if m:
            return int(m.group(0))
        raise _Refuse("Cast of a non-numeric string")
    raise _Refuse("Cast of a non-castable value")


def _rs_str(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() else repr(v)
    if isinstance(v, int):
        return str(v)
    if v is None:
        return "null"
    return str(v)


# ================================================================================================
# Shakespeare (SPL)
# ================================================================================================
_SPL_CHARS = {
    "achilles", "agamemnon", "agrippa", "aufidius", "autolycus", "banquo", "beatrice", "benedick",
    "benvolio", "bianca", "brabantio", "brutus", "capulet", "cassius", "claudio", "claudius",
    "cleopatra", "cordelia", "cornwall", "demetrius", "desdemona", "dogberry", "duncan", "egeus",
    "emilia", "escalus", "falstaff", "fenton", "ferdinand", "ford", "fortinbras", "gertrude",
    "goneril", "hamlet", "hecate", "helen", "helena", "hermia", "hermione", "hippolyta", "horatio",
    "imogen", "isabella", "juliet", "lennox", "leonato", "luciana", "lucio", "lysander", "macbeth",
    "macduff", "malcolm", "mariana", "mercutio", "miranda", "montague", "mopsa", "oberon", "octavia",
    "olivia", "ophelia", "orlando", "orsino", "othello", "page", "pantino", "paris", "peter",
    "petruchio", "phebe", "pisanio", "polonius", "pompey", "portia", "priam", "prospero", "proteus",
    "publius", "puck", "regan", "robin", "roderigo", "romeo", "rosalind", "sebastian", "shallow",
    "shylock", "slender", "solinus", "stephano", "thaisa", "theseus", "thurio", "timon", "titania",
    "titus", "troilus", "tybalt", "ulysses", "valentine", "venus", "vincentio", "viola",
}
_SPL_POS_NOUN = {
    "lord", "lady", "king", "queen", "prince", "angel", "flower", "happiness", "joy", "plum",
    "summer", "hero", "rose", "kingdom", "pony", "cat", "nose", "hamster", "chihuahua", "cow",
    "horse", "animal", "aunt", "brother", "cousin", "daughter", "father", "grandfather",
    "grandmother", "mother", "nephew", "niece", "sister", "son", "uncle", "moon", "heaven", "lamp",
    "light", "roman", "child", "squirrel", "fellow", "friend", "peace", "smile", "sky", "sun",
    "star", "town", "road",
}
_SPL_NEU_NOUN = {"nothing", "zero"}
_SPL_NEG_NOUN = {
    "bastard", "beggar", "blister", "codpiece", "coward", "curse", "death", "devil", "draught",
    "famine", "goat", "hell", "hog", "leech", "lie", "pig", "plague", "starvation", "toad", "war",
    "wolf", "microbe", "rat", "oozing", "stench",
}
_SPL_ARTICLE = {"a", "an", "the"}
_SPL_OPS = {"sum", "difference", "product", "quotient", "remainder", "square", "cube", "factorial",
            "twice"}
_SPL_PRON_YOU = {"you", "thee", "thou", "thyself", "yourself"}
_SPL_PRON_ME = {"i", "me", "myself", "mine"}
_ROMAN = {"i": 1, "v": 5, "x": 10, "l": 50, "c": 100, "d": 500, "m": 1000}


def shakespeare(text):
    """What a Shakespeare Programming Language program prints, as bytes, or None. Input
    instructions ("Listen to your heart" / "Open your mind") are refused; an unparseable value,
    a program that does not halt within the caps, or output over the cap -> None."""
    t = _text(text)
    if t is None:
        return None
    try:
        return _run_spl(t, _deadline())
    except _Halt as h:
        return h.args[0] or None
    except _Refuse:
        return None
    except (ValueError, IndexError, KeyError, RecursionError):
        return None


def _roman_val(s):
    s = s.lower()
    total = 0
    prev = 0
    for ch in reversed(s):
        if ch not in _ROMAN:
            return None
        v = _ROMAN[ch]
        if v < prev:
            total -= v
        else:
            total += v
            prev = v
    return total


def _run_spl(src, deadline):
    # Drop the title (everything up to the first period).
    dot = src.find(".")
    if dot < 0:
        raise _Refuse("no title")
    body_all = src[dot + 1:]

    names_alt = "|".join(sorted((re.escape(n) for n in _SPL_CHARS), key=len, reverse=True))
    # Event tokenizer: stage directions, act/scene headers, character cues. Case-insensitive on
    # keywords; character names matched case-insensitively.
    # Act/Scene headers REQUIRE the colon, so a prose mention of "scene I" (e.g. in a goto
    # sentence "Let us return to scene I.") is not mistaken for a header.
    ev_re = re.compile(
        r"\[(?P<stage>[^\]]*)\]"
        r"|\bAct\s+(?P<act>[IVXLCDMivxlcdm]+)\s*:"
        r"|\bScene\s+(?P<scene>[IVXLCDMivxlcdm]+)\s*:"
        r"|\b(?P<cue>%s)\s*:" % names_alt,
        re.I)

    # Declare characters from the persona section (sentences "<Name>, ...") before the first Act.
    vars_ = {}
    stacks = {}
    first_act = ev_re.search(body_all)
    persona_region = body_all[:first_act.start()] if first_act else body_all
    for sent in re.split(r"[.!?]", persona_region):
        mm = re.match(r"\s*(%s)\s*," % names_alt, sent, re.I)
        if mm:
            vars_[mm.group(1).lower()] = 0
            stacks[mm.group(1).lower()] = []
    if len(vars_) < 2:
        raise _Refuse("fewer than two characters declared")

    # Build the instruction list and the act/scene label table.
    instrs = []            # ("enter", names) | ("exit", names) | ("stmt", speaker, sentence)
    acts = []              # list of (actnum, {scenenum: instr_index})
    cur_speaker = [None]

    def add_sentences(prose, speaker):
        for s in re.findall(r"[^.!?]*[.!?]", prose):
            if s.strip():
                instrs.append(("stmt", speaker, s.strip()))

    pos = first_act.start() if first_act else len(body_all)
    last = pos
    for m in ev_re.finditer(body_all, pos):
        # prose between the previous event and this one belongs to the current speaker
        add_sentences(body_all[last:m.start()], cur_speaker[0])
        last = m.end()
        if m.group("stage") is not None:
            instrs.append(_spl_stage(m.group("stage"), names_alt))
        elif m.group("act") is not None:
            acts.append((_roman_val(m.group("act")) or (len(acts) + 1), {}))
        elif m.group("scene") is not None:
            if not acts:
                acts.append((1, {}))
            acts[-1][1][_roman_val(m.group("scene")) or (len(acts[-1][1]) + 1)] = len(instrs)
        elif m.group("cue") is not None:
            cur_speaker[0] = m.group("cue").lower()
    add_sentences(body_all[last:], cur_speaker[0])

    # Execute.
    out = _Out()
    stage = []             # names currently on stage, in entry order
    flag = [False]
    cur_act = [acts[0][0] if acts else 1]
    count = 0
    pc = 0
    while pc < len(instrs):
        count += 1
        if count > STEPS:
            raise _Refuse("step cap")
        if not (count & (TICK - 1)) and time.perf_counter() > deadline:
            raise _Refuse("time")
        kind = instrs[pc][0]
        if kind == "enter":
            for n in instrs[pc][1]:
                if n not in stage:
                    stage.append(n)
        elif kind == "exit":
            names = instrs[pc][1]
            if names is None:
                stage.clear()
            else:
                for n in names:
                    if n in stage:
                        stage.remove(n)
        else:
            _speaker = instrs[pc][1]
            sentence = instrs[pc][2]
            jump = _spl_stmt(sentence, _speaker, stage, vars_, stacks, out, flag, acts, cur_act)
            if jump is not None:
                pc = jump
                continue
        pc += 1
    return out.value()


def _spl_stage(inside, names_alt):
    low = inside.strip().lower()
    names = [n.lower() for n in re.findall(r"(%s)" % names_alt, inside, re.I)]
    if low.startswith("enter"):
        return ("enter", names)
    if low.startswith("exeunt"):
        return ("exit", names if names else None)
    if low.startswith("exit"):
        return ("exit", names)
    # An unrecognised stage direction is a no-op.
    return ("exit", [])


def _spl_addressee(speaker, stage):
    others = [n for n in stage if n != speaker]
    if not others:
        return None
    return others[-1]


def _spl_stmt(sentence, speaker, stage, vars_, stacks, out, flag, acts, cur_act):
    toks = re.findall(r"[a-z]+", sentence.lower())
    if not toks:
        return None
    ad = _spl_addressee(speaker, stage)

    # input -> refuse
    if _spl_has(toks, ["listen", "to", "your", "heart"]) or _spl_has(toks, ["open", "your", "mind"]):
        raise _Refuse("Shakespeare input")

    # goto: (let us | we shall | we must) (return | proceed) to (scene|act) <roman>
    mg = re.search(r"(?:return|proceed)\s+to\s+(scene|act)\s+([ivxlcdm]+)", sentence.lower())
    if mg:
        target = _roman_val(mg.group(2))
        if mg.group(1) == "scene":
            for an, scenes in acts:
                if an == cur_act[0] and target in scenes:
                    return scenes[target]
            raise _Refuse("goto to an unknown scene")
        else:
            for an, scenes in acts:
                if an == target and scenes:
                    cur_act[0] = an
                    return min(scenes.values())
            raise _Refuse("goto to an unknown act")

    # conditional: "if so, <stmt>" / "if not, <stmt>"
    if toks[0] == "if" and len(toks) >= 2 and toks[1] in ("so", "not"):
        want = (toks[1] == "so")
        rest = sentence.split(",", 1)
        if len(rest) == 2 and flag[0] == want:
            return _spl_stmt(rest[1].strip(), speaker, stage, vars_, stacks, out, flag, acts, cur_act)
        return None

    # question -> set the flag
    if sentence.rstrip().endswith("?"):
        flag[0] = _spl_question(toks, speaker, ad, vars_)
        return None

    # output
    if _spl_has(toks, ["speak"]) and ("mind" in toks):
        if ad is None:
            raise _Refuse("no addressee for output")
        out.codepoint(vars_[ad] & 0x10FFFF if vars_[ad] >= 0 else 0)
        return None
    if _spl_has(toks, ["open"]) and ("heart" in toks):
        if ad is None:
            raise _Refuse("no addressee for output")
        out.text(str(vars_[ad]))
        return None

    # stack: remember / recall
    if toks[0] == "remember":
        if ad is None:
            raise _Refuse("no addressee for remember")
        val = _spl_value(toks[1:], speaker, ad, vars_)[0]
        stacks[ad].append(val)
        return None
    if toks[0] == "recall":
        if ad is None or not stacks[ad]:
            raise _Refuse("recall from an empty stack")
        vars_[ad] = stacks[ad].pop()
        return None

    # assignment to the addressee: "you are <expr>" / "thou art <expr>" / "you <nounphrase>"
    if toks[0] in _SPL_PRON_YOU:
        if ad is None:
            raise _Refuse("no addressee for assignment")
        vt = _spl_assign_tokens(toks)
        vars_[ad] = _spl_value(vt, speaker, ad, vars_)[0]
        return None

    # assignment to the speaker: "I am <expr>"
    if toks[0] in ("i",) and len(toks) >= 2 and toks[1] in ("am", "are"):
        vars_[speaker] = _spl_value(toks[2:], speaker, ad, vars_)[0]
        return None

    # Any other sentence is flavour text (a no-op), which keeps us tolerant of real SPL prose.
    return None


def _spl_has(toks, seq):
    n = len(seq)
    for i in range(len(toks) - n + 1):
        if toks[i:i + n] == seq:
            return True
    return False


def _spl_assign_tokens(toks):
    i = 1
    if i < len(toks) and toks[i] in ("are", "art", "am", "be", "beest", "is"):
        i += 1
    # "as <adj> as <nounphrase>" -> value is the noun phrase after the SECOND "as"
    as_idx = [j for j, t in enumerate(toks) if t == "as"]
    if len(as_idx) >= 2 and as_idx[0] >= i:
        return toks[as_idx[1] + 1:]
    return toks[i:]


def _spl_question(toks, speaker, ad, vars_):
    as_idx = [j for j, t in enumerate(toks) if t == "as"]
    if len(as_idx) >= 2:
        a, _ = _spl_value(toks[1:as_idx[0]] or toks[:as_idx[0]], speaker, ad, vars_, soft=True)
        b, _ = _spl_value(toks[as_idx[1] + 1:], speaker, ad, vars_, soft=True)
        return a == b
    if "than" in toks:
        ti = toks.index("than")
        a, _ = _spl_value(toks[1:ti], speaker, ad, vars_, soft=True)
        b, _ = _spl_value(toks[ti + 1:], speaker, ad, vars_, soft=True)
        more = any(w in toks[:ti] for w in ("more", "better", "bigger", "greater", "higher",
                                            "nicer", "fatter", "punier"))
        return a > b if more else a < b
    return False


def _spl_value(toks, speaker, ad, vars_, soft=False):
    """Parse a value expression from `toks`; return (value, index_consumed). Raises _Refuse on a
    parse failure unless soft (then returns (0, ...))."""
    try:
        val, i = _spl_parse(toks, 0, speaker, ad, vars_)
        return val, i
    except _Refuse:
        if soft:
            return 0, len(toks)
        raise


def _spl_parse(toks, i, speaker, ad, vars_):
    if i >= len(toks):
        raise _Refuse("empty value")
    t = toks[i]

    # binary / unary operators
    if t == "the" and i + 1 < len(toks) and toks[i + 1] in _SPL_OPS:
        op = toks[i + 1]
        j = i + 2
        if j < len(toks) and toks[j] in ("of", "between"):
            j += 1
        if op in ("sum", "product"):
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            j = _spl_expect_and(toks, j)
            b, j = _spl_parse(toks, j, speaker, ad, vars_)
            return (a + b if op == "sum" else a * b), j
        if op == "difference":
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            j = _spl_expect_and(toks, j)
            b, j = _spl_parse(toks, j, speaker, ad, vars_)
            return a - b, j
        if op == "quotient":
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            j = _spl_expect_and(toks, j)
            b, j = _spl_parse(toks, j, speaker, ad, vars_)
            if b == 0:
                raise _Refuse("quotient by zero")
            return int(a / b), j
        if op == "remainder":
            # "the remainder of the quotient between X and Y"
            while j < len(toks) and toks[j] in ("of", "the", "quotient", "between"):
                j += 1
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            j = _spl_expect_and(toks, j)
            b, j = _spl_parse(toks, j, speaker, ad, vars_)
            if b == 0:
                raise _Refuse("remainder by zero")
            return a - int(a / b) * b, j
        if op == "square" and j < len(toks) and toks[j] == "root":
            a, j = _spl_parse(toks, j + 1, speaker, ad, vars_)
            return math.isqrt(abs(a)), j
        if op == "square":
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            return a * a, j
        if op == "cube":
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            return a ** 3, j
        if op == "factorial":
            a, j = _spl_parse(toks, j, speaker, ad, vars_)
            if a < 0 or a > 10:
                raise _Refuse("factorial out of range")
            return math.factorial(a), j
    if t == "twice":
        a, j = _spl_parse(toks, i + 1, speaker, ad, vars_)
        return 2 * a, j

    # pronouns
    if t in _SPL_PRON_YOU:
        if ad is None:
            raise _Refuse("no addressee referenced")
        return vars_[ad], i + 1
    if t in _SPL_PRON_ME:
        return vars_[speaker], i + 1

    # a character name
    if t in vars_:
        return vars_[t], i + 1

    # a noun phrase: article? adjective* noun
    j = i
    while j < len(toks) and toks[j] in _SPL_ARTICLE:
        j += 1
    adj = 0
    while j < len(toks) and toks[j] not in _SPL_POS_NOUN and toks[j] not in _SPL_NEG_NOUN \
            and toks[j] not in _SPL_NEU_NOUN:
        # stop if we run into a structural word
        if toks[j] in ("and",) or toks[j] in _SPL_OPS or toks[j] in _SPL_PRON_YOU \
                or toks[j] in _SPL_PRON_ME or toks[j] in vars_:
            raise _Refuse("no noun in the phrase")
        adj += 1
        j += 1
        if adj > 64:
            raise _Refuse("absurd adjective run")
    if j >= len(toks):
        raise _Refuse("noun phrase without a noun")
    noun = toks[j]
    if noun in _SPL_NEU_NOUN:
        sign = 0
    elif noun in _SPL_POS_NOUN:
        sign = 1
    else:
        sign = -1
    return sign * (1 << adj), j + 1


def _spl_expect_and(toks, j):
    if j < len(toks) and toks[j] == "and":
        return j + 1
    raise _Refuse("expected 'and' in a binary operator")


# ================================================================================================
# Registry (esolang.py interface)
# ================================================================================================
BY_NAME = {"shakespeare": shakespeare, "rockstar": rockstar, "chef": chef, "befunge98": befunge98}
NAMES = frozenset(BY_NAME)


def _which(cur):
    """The step names whose cheap structural signature a payload could match. Each reader still
    checks itself exactly, so a signature match is never by itself an answer. These languages are
    English-word programs, so the gates only keep the VMs off obvious non-programs (the readers run
    as a late whole-blob attempt from the Warmups day_patch, so a miss here only costs a parse)."""
    if isinstance(cur, str):
        b = cur.encode("utf-8", "surrogatepass")
    elif isinstance(cur, (bytes, bytearray, memoryview)):
        b = bytes(cur)
    else:
        return ()
    if not (MIN_PROG <= len(b) <= MAX_PROG):
        return ()
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    low = t.lower()
    names = []
    if ("act " in low and "scene " in low and ":" in t
            and ("speak your mind" in low or "speak thy mind" in low or "open your heart" in low)):
        names.append("shakespeare")
    if (re.search(r"\b(say|shout|whisper|scream|print)\b", low)
            and re.search(r"\b(put|let|is|are|was|were|cast|burn)\b", low)):
        names.append("rockstar")
    if "ingredients" in low and "method" in low:
        names.append("chef")
    if "@" in t and _looks_befunge(t):
        names.append("befunge98")
    return tuple(names)


def _looks_befunge(t):
    # Dense symbolic program, not English prose: most non-space characters are Befunge operators,
    # and there is a directional / output instruction.
    body = re.sub(r"\s", "", t)
    if not body:
        return False
    ops = set("><^v_|?:\\$.,#@pg'\";+-*/%!`[]rxjkn{}uwsq0123456789abcdef")
    frac = sum(1 for ch in body if ch in ops) / len(body)
    return frac > 0.55 and any(ch in t for ch in ",.@")


def steps(cur):
    """[(name, bytes)]: what the readers of this module make of one payload."""
    out = []
    for name in _which(cur):
        try:
            o = BY_NAME[name](cur)
        except Exception:
            o = None
        if o:
            out.append((name, o))
    return out


def step_fn(name):
    """The reader (payload -> bytes or None) of one step by its name, re-checking its own
    signature so a chain cannot apply a reader to a payload its gate would reject."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        return fn(b) if name in _which(b) else None

    f.__name__ = "d_" + name
    return f


# -- crib-gated reader (the never-wrong gate; standalone / day_patch / test use) -----------------
CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "


def read(blob, crib=CRIB):
    """Every (name, decoded text) this module reads whose decode is the crib sentence followed by
    exactly ONE clean slug token.

    This is the never-wrong gate the Warmups day_patch applies: a reader is answered plain only when
    its bytes reproduce the exact crib sentence AND the remainder after it is a single whitespace-free
    slug. `startswith(crib)` alone is necessary but NOT sufficient: a valid program that halts can
    print `crib + <trailing junk>`, `crib + <slug> + <decoy second line>` ("submit this instead: ...")
    or `crib + <prose>`, all of which start with the crib yet are not a clean slug. Offering any of
    those would ship a wrong plain answer (the decoy/junk contaminates the slug the day_patch submits).
    So the post-crib remainder, once stripped of leading/trailing whitespace (e.g. the single trailing
    newline a Shout adds), must contain NO internal whitespace and be non-empty. Returns a list, so a
    program that merely parses but prints anything else yields NOTHING, not a wrong plain slug.
    """
    found = []
    for name, out in steps(blob):
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not text.startswith(crib):
            continue
        rest = text[len(crib):].strip()
        if rest and not re.search(r"\s", rest):
            found.append((name, text))
    return found


# -- encoders (tests / round-trip only; never used by the solver) --------------------------------
def enc_shakespeare(data):
    """A minimal SPL program that prints `data`: two characters set each byte (Romeo addresses
    Juliet) with sums of powers of two, then 'Speak your mind'. No loop, so it always halts."""
    lines = [
        "The Diligent Reader's Warmup.",
        "",
        "Romeo, a young man of remarkable patience.",
        "Juliet, a lady of considerable grace.",
        "",
        "Act I: The one and only act.",
        "",
        "Scene I: The one and only scene.",
        "",
        "[Enter Romeo and Juliet]",
        "",
    ]
    speech = []
    for byte in data:
        speech.append("You are %s." % _spl_phrase(byte))
        speech.append("Speak your mind.")
    lines.append("Romeo: " + " ".join(speech))
    lines.append("")
    lines.append("[Exeunt]")
    return ("\n".join(lines) + "\n").encode()


def _spl_phrase(n):
    if n == 0:
        return "nothing"
    bits = [k for k in range(16) if n & (1 << k)]
    terms = ["a " + ("sweet " * k) + "cat" for k in bits]
    return _spl_sum(terms)


def _spl_sum(terms):
    if len(terms) == 1:
        return terms[0]
    return "the sum of %s and %s" % (terms[0], _spl_sum(terms[1:]))


def enc_rockstar(data):
    """A Rockstar program that builds `data` char by char (numeric literal -> Cast -> concat) and
    shouts it once."""
    lines = ['Let my message be ""']
    for byte in data:
        lines.append("Put %d into my letter" % byte)
        lines.append("Cast my letter into my glyph")
        lines.append("Let my message be my message plus my glyph")
    lines.append("Shout my message")
    return ("\n".join(lines) + "\n").encode()


def enc_chef(data):
    """A Chef recipe that pushes `data` (reversed, so the LIFO dish prints forward), liquefies the
    bowl so every value prints as a character, pours into the baking dish and serves one."""
    names = [_chef_name(i) for i in range(len(data))]
    out = ["Decode Souffle.", "", "Ingredients."]
    # push order = reverse of the message, so reversed-dish printing yields the message forward
    order = list(range(len(data)))[::-1]
    for i in order:
        out.append("%d g %s" % (data[i], names[i]))
    out += ["", "Method."]
    for i in order:
        out.append("Put %s into the mixing bowl." % names[i])
    out.append("Liquefy contents of the mixing bowl.")
    out.append("Pour contents of the mixing bowl into the baking dish.")
    out += ["", "Serves 1."]
    return ("\n".join(out) + "\n").encode()


def _chef_name(i):
    # unique lowercase-letter ingredient names: a, b, ..., z, aa, ab, ...
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(97 + r) + s
    return "ingredient " + s


def enc_befunge98(data):
    """A one-line Befunge-98 program: for each byte, `'<char>,` fetches the char and outputs it,
    then `@` halts. Requires the message to be single-line printable (the crib + slug is)."""
    cells = []
    for byte in data:
        if byte in (10, 13):
            raise ValueError("befunge98 encoder: newline in message")
        cells.append("'")
        cells.append(chr(byte))
        cells.append(",")
    cells.append("@")
    return "".join(cells).encode()


ENCODERS = {"shakespeare": enc_shakespeare, "rockstar": enc_rockstar, "chef": enc_chef,
            "befunge98": enc_befunge98}


def main(argv):
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: esolang_more.py <file> [...]", file=sys.stderr)
        return 2
    for path in argv:
        try:
            raw = open(path, "rb").read()
        except OSError as e:
            print("%s: %s" % (path, e.strerror or e), file=sys.stderr)
            continue
        hit = read(raw) or steps(raw)
        if hit:
            for name, out in hit:
                shown = out if isinstance(out, str) else out[:400]
                print("%s: %s -> %r" % (path, name, shown))
        else:
            print("%s: no reader takes it" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
