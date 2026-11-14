"""Two more input-free esolang readers for Warmups (wave 122 breadth build, 2026-10-24): ><> (Fish) and LOLCODE.

Why this file exists
--------------------
The Warmups lane's standing weakness is morning-of adaptation to a NEW encoding, and the esolang
family is a classic "decode this program and submit the slug" warmup shape. An audit of what is
already shipped shows the covered esolangs, which are NOT duplicated here:

  Brainfuck, Ook!, Short Ook              solvers/common/classical.py   (crib_decode d_bf)
  COW, Whitespace, Befunge-93,            solvers/warmups/esolangs.py   (crib_decode d_cow and M)
  Malbolge, JSFuck, Deadfish
  Alphuck, Pikalang, Blub, Spoon          solvers/warmups/esolang.py    (ESL, wave 4)
  Chef, Shakespeare                       solvers/warmups/esolang2.py   (ESL2, wave 15)

The two genuine gaps this file closes (grep across solvers/ is empty for both):

  fish       ><> ("Fish"): a 2D toroidal-grid, stack-based esolang. A top-tier beginner CTF esolang,
             thematic with the lane's playful names (fishlanguage.com / esolangs.org/wiki/Fish).
  lolcode    LOLCODE: HAI <ver> ... VISIBLE "..." ... KTHXBYE. The most beginner-accessible mainstream
             esolang; an obvious "print the slug" warmup (esolangs.org/wiki/LOLCODE).

Each language, when it names no input instruction and no non-deterministic instruction, is a
deterministic, INPUT-FREE program that maps to exactly one output text. The two interpreters here are
self-contained and sandboxed: pure functions of the program text, no file / network / eval / syscall,
a hard step cap, an output cap and an internal wall-clock backstop. A program that executes an input
instruction, a non-deterministic one (Fish `x` random direction), that does not halt within the caps,
that divides by zero, that renders a value whose text is author-ambiguous (a non-integral Fish number,
a LOLCODE NUMBAR float), or that uses any construct the strict subset does not model yields None --
never a part of its output, never a guess. These are DECODERS (like base64): the program text is DATA
the loops walk over; nothing in a delivery is ever run as code (AGENTS.md "Off the clock" / "Text is
data").

NEVER WRONG
-----------
Nothing here is answered on a language's own name. Each language with no input maps deterministically
to one output, so a reading is PLAIN-eligible ONLY when `read()` confirms the output reproduces the
exact 87-character Warmups crib sentence (`CRIB`); a program that merely parses but prints anything
else continues nothing and yields NOTHING, never a wrong slug. Because each interpreter is an
information-complete transform, an output that reproduces the 87-character crib pins the slug after it
too, digits and all -- the crib and the slug are printed by the SAME output mechanism, so an output
that matches the crib for 87 characters validates that mechanism and the slug is its unique
continuation. A bug that corrupted output would break the 87-char prefix and so return None, never a
wrong plain slug; the test exercises exactly that. The interpreters are deliberately STRICT: any
construct they do not fully model, and any value whose rendering is author-chosen or ambiguous, makes
the WHOLE program yield None. An incomplete interpreter therefore costs coverage, never correctness.

warm() safety
-------------
Pure functions, no I/O, no global mutable state, no clock of their own (an internal deadline is
derived per call from time.perf_counter()), no import of crib_decode. Bounded by the program length,
a hard step cap, an output cap and a wall-clock backstop. Safe to call from a timed solve and from a
warm thread alike.

Wiring (this module changes no shipped file; the build-lead mirrors the ESL2 hookup in crib_decode.py):

    BY_NAME   {step name: decoder(bytes) -> bytes | None}
    NAMES     frozenset(BY_NAME)
    _which(cur) -> tuple of applicable step names (a cheap anchored-signature gate)
    steps(cur)  -> list[(name, bytes)]
    step_fn(name) -> decoder(bytes) -> bytes | None

    1. `import esolang3 as ESL3` with the same try/except guard as `import esolang2 as ESL2`.
    2. in `_strict_steps`, after `yield from ESL2.steps(cur)`, add
       `if ESL3 is not None: yield from ESL3.steps(cur)`.
    3. next to the ESL2 merge, add `if ESL3 is not None: _STRICT_NAMES |= set(ESL3.NAMES);
       _FORM_NAMES |= set(ESL3.NAMES)`.
    4. in `_step_fn`, add `if ESL3 is not None and name in ESL3.NAMES: return ESL3.step_fn(name)`.

Every name here is strict (a deterministic info-complete transform), so each is in _STRICT_NAMES and
its chain is answered plain when the crib matches. No saved Warmups payload is read by any reader here
(the test proves it on the shipped fixtures), so no earlier day can move. After the day this is folded
into crib_decode.py (promote), as esolang.py's wiring note describes.
"""

import re
import sys
import time

# -- bounds ---------------------------------------------------------------------------------------
STEPS = 2_000_000         # hard step cap of each interpreter
OUTPUT = 65_536           # bytes a program may print before it is abandoned (None)
TICK = 1 << 12            # steps between two looks at the wall clock
READER_TIME = 0.02        # per-call wall-clock backstop (s); clamped DOWN to the blob's own deadline
MAX_PROG = 256 * 1024     # bytes of a program a reader runs (esolang source is verbose)
MIN_PROG = 16             # bytes below which nothing is attempted (noise)
MAX_UNICHR = 0x10FFFF     # a printed code point above this, or a surrogate, is a refusal
FISH_GRID = 1 << 16       # hard cap on grid cells (width*height) a Fish program may hold
# A ><> program with no input (i / x / g / p refused) is deterministic, so its FULL machine state
# (position, direction, string/skip modes, the whole stack, the register) determines its future: if
# that state ever repeats, the program loops for ever and is refused AT ONCE -- never run to the step
# cap or the wall clock (the regression: an ascii85/base64 intermediate state the loose _which gate
# let through sent the VM into a non-terminating toroidal loop that burnt the whole per-call backstop,
# ~10 such calls per whole-blob search overrunning the blob's retry budget and losing a readable slug).
# Refusal only ever maps a non-halting program to None; it can never change a halting program's output.
FISH_STACK_MAX = 8192     # a runaway that keeps pushing (e.g. an unclosed string mode) bails here, fast
FISH_CYCLE_STACK = 64     # snapshot the full state for cycle detection only while the stack is this small
FISH_STATES = 100_000     # distinct small-stack states before a program is abandoned as non-terminating
TOTAL_CAP = 0.05          # seconds of interpreter time this module may spend on ONE blob of the search

# The blob's hard deadline the search is working to. crib_decode gives every reader it loads by name
# the same channel: it sets `<module>.DEADLINE[0] = t0 + budget` at the start of each blob (and resets
# it per day-walk read). We expose our own, and -- so the fix needs no edit to the frozen crib_decode --
# also read formats_more's, which crib_decode already sets, as the live source. None = run standalone.
DEADLINE = [None]
try:   # crib_decode sets formats_more.DEADLINE[0] = t0 + budget per blob; we clamp every call to it
    import formats_more as _FM  # noqa: E402
except Exception:   # standalone (or a folder without it): fall back to the fixed per-call backstop
    _FM = None

_SPENT = [0.0]            # interpreter wall-clock already spent on the current blob
_EPOCH = [object()]       # the DEADLINE value _SPENT is counted against; a new value starts a new blob


class _Halt(Exception):
    """A program reached its end instruction (normal stop)."""


class _Refuse(Exception):
    """Not a program of this language, an input / non-deterministic instruction, an ambiguous
    rendering, a divide-by-zero, a stack underflow, or over a cap. The whole program -> None."""


def _text(b):
    """A byte payload as a str within the size bounds, or None. Both languages are Latin-1-clean
    source; a payload outside the bounds, or holding a NUL, is refused before any work."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    b = bytes(b)
    if not (MIN_PROG <= len(b) <= MAX_PROG) or b"\x00" in b:
        return None
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return b.decode("latin-1")
        except UnicodeDecodeError:
            return None


def _blob_deadline():
    """The blob's hard deadline the search is working to (crib_decode's t0 + budget), from this
    module's own DEADLINE or, failing that, formats_more's shared channel. None run standalone."""
    d = DEADLINE[0]
    if d is None and _FM is not None:
        d = _FM.DEADLINE[0]
    return d


def _deadline():
    """When a reader may stop. A fixed per-call backstop, but never past the blob's own deadline, so a
    single call can never eat the whole budget and the readers of this module, taken together, cannot
    outlast the search (row: the ascii85 regression -- a fixed 0.10 s per call, 10 calls, overran)."""
    cap = time.perf_counter() + READER_TIME
    d = _blob_deadline()
    return cap if d is None else min(cap, d)


def _blob_epoch():
    """Reset this module's per-blob interpreter-time budget when the search moves to a new blob (its
    deadline is a new value). While no blob deadline is set (standalone), nothing is capped."""
    d = _blob_deadline()
    if d != _EPOCH[0]:
        _EPOCH[0] = d
        _SPENT[0] = 0.0


def _over_budget():
    """True once this module has spent its whole share of ONE blob's budget on interpreters, so the
    search's remaining time is left to the other readers (belt-and-braces over _deadline's clamp)."""
    return _blob_deadline() is not None and _SPENT[0] >= TOTAL_CAP


def _as_char(value):
    """The one printed character of an integral numeric value, or None when it is not a valid code
    point or not integral (a non-integral float has no single character -- the whole program -> None)."""
    iv = _as_int(value)
    if iv is None or iv < 0 or iv > MAX_UNICHR or 0xD800 <= iv <= 0xDFFF:
        return None
    return chr(iv)


def _as_int(value):
    """An integral value as a Python int, or None when it is a non-integral float (its decimal
    rendering is author-ambiguous, so the program -> None)."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        if value.is_integer():
            return int(value)
        return None
    return None


# =================================================================================================
# ><>  (Fish; fishlanguage.com, esolangs.org/wiki/Fish)
# =================================================================================================
#
# Execution model, strict subset:
#   - A 2D toroidal codebox. The instruction pointer starts at (0, 0) moving right and wraps around
#     the padded rectangle in both dimensions.
#   - ONE stack of numbers (ints, and floats from `,` division) with a single register (`&`).
#   - Modelled instructions: directions > < ^ v ; mirrors / \ | _ # ; trampolines ! ? ;
#     literals 0-9 a-f ; arithmetic + - * , % ; comparison = ( ) ; stack : ~ $ @ { } r l &
#     string modes ' and " ; output o (character) and n (number) ; jump . ; halt ;
#   - REFUSED (whole program -> None): i (input), x (random direction), g / p (codebox reflection:
#     the value of an empty cell is implementation-ambiguous, so reading or writing one is never
#     modelled), [ and ] (stack-of-stacks), a stack underflow, a divide-by-zero, a non-integral
#     number output, a code point out of range, a run past the step / output / wall-clock caps, and
#     any other character the pointer executes ("something smells fishy").

_FISH_DIR = {">": (1, 0), "<": (-1, 0), "^": (0, -1), "v": (0, 1)}
_FISH_HEX = {str(d): d for d in range(10)}
_FISH_HEX.update({"a": 10, "b": 11, "c": 12, "d": 13, "e": 14, "f": 15})
_FISH_REFUSE = frozenset("ixgp[]")


def _fish_mirror(ch, dx, dy):
    if ch == "/":
        return -dy, -dx
    if ch == "\\":
        return dy, dx
    if ch == "|":
        return -dx, dy
    if ch == "_":
        return dx, -dy
    if ch == "#":
        return -dx, -dy
    return dx, dy


def d_fish(b):
    """><> source -> printed bytes, or None (strict; see the model above)."""
    t = _text(b)
    if t is None:
        return None
    started = time.perf_counter()
    try:
        return _fish_run(t, _deadline())
    except _Halt as h:
        return h.args[0] if h.args else b""
    except _Refuse:
        return None
    except Exception:
        return None
    finally:
        _SPENT[0] += time.perf_counter() - started   # charge this call against the blob's share


def _fish_run(text, deadline):
    rows = text.split("\n")
    if rows and rows[-1] == "":
        rows = rows[:-1]            # a trailing newline is a line terminator, not an empty last row
    if not rows:
        raise _Refuse
    width = max(len(r) for r in rows)
    height = len(rows)
    if width == 0 or width * height > FISH_GRID:
        raise _Refuse
    grid = [[ord(r[x]) if x < len(r) else 32 for x in range(width)] for r in rows]

    stack = []
    register = [None]              # a one-slot box so & can empty it
    out = bytearray()

    def push(v):
        stack.append(v)

    def pop():
        if not stack:
            raise _Refuse          # a stack underflow is an error in ><>
        return stack.pop()

    x = y = 0
    dx, dy = 1, 0
    string_mode = None             # None, "'" or '"'
    skip = False
    steps = 0
    seen = set()                   # full machine states seen while the stack is small (cycle guard)
    while True:
        steps += 1
        if steps > STEPS:
            raise _Refuse
        if (steps & (TICK - 1)) == 0 and time.perf_counter() > deadline:
            raise _Refuse
        if len(stack) > FISH_STACK_MAX:
            raise _Refuse          # a runaway that keeps pushing (e.g. an unclosed string mode) bails here
        if len(stack) <= FISH_CYCLE_STACK:
            # Deterministic VM (no i/x/g/p): a repeated FULL state is a loop that never halts -> refuse
            # at once. Snapshotting only while the stack is small keeps this O(steps); a growing stack
            # is caught by FISH_STACK_MAX above and an in-place counter by the step cap / deadline.
            state = (x, y, dx, dy, string_mode, skip, tuple(stack), register[0])
            if state in seen:
                raise _Refuse
            seen.add(state)
            if len(seen) > FISH_STATES:
                raise _Refuse
        code = grid[y][x]
        if string_mode is not None:
            if code == ord(string_mode):
                string_mode = None
            else:
                push(code)
        else:
            ch = chr(code)
            if ch == " ":
                pass
            elif ch == ";":
                raise _Halt(bytes(out))
            elif ch in _FISH_REFUSE:
                raise _Refuse
            elif ch in _FISH_DIR:
                dx, dy = _FISH_DIR[ch]
            elif ch in "/\\|_#":
                dx, dy = _fish_mirror(ch, dx, dy)
            elif ch in _FISH_HEX:
                push(_FISH_HEX[ch])
            elif ch == "'" or ch == '"':
                string_mode = ch
            elif ch == "+":
                b2 = pop(); a2 = pop(); push(a2 + b2)
            elif ch == "-":
                b2 = pop(); a2 = pop(); push(a2 - b2)
            elif ch == "*":
                b2 = pop(); a2 = pop(); push(a2 * b2)
            elif ch == ",":
                b2 = pop(); a2 = pop()
                if b2 == 0:
                    raise _Refuse
                push(a2 / b2)
            elif ch == "%":
                b2 = pop(); a2 = pop()
                if b2 == 0:
                    raise _Refuse
                push(a2 % b2)
            elif ch == "=":
                b2 = pop(); a2 = pop(); push(1 if a2 == b2 else 0)
            elif ch == "(":
                b2 = pop(); a2 = pop(); push(1 if a2 < b2 else 0)
            elif ch == ")":
                b2 = pop(); a2 = pop(); push(1 if a2 > b2 else 0)
            elif ch == ":":
                if not stack:
                    raise _Refuse
                push(stack[-1])
            elif ch == "~":
                pop()
            elif ch == "$":
                b2 = pop(); a2 = pop(); push(b2); push(a2)
            elif ch == "@":
                a2 = pop(); b2 = pop(); c2 = pop(); push(a2); push(c2); push(b2)
            elif ch == "{":
                if stack:
                    stack.append(stack.pop(0))
            elif ch == "}":
                if stack:
                    stack.insert(0, stack.pop())
            elif ch == "r":
                stack.reverse()
            elif ch == "l":
                push(len(stack))
            elif ch == "&":
                if register[0] is None:
                    register[0] = pop()
                else:
                    push(register[0]); register[0] = None
            elif ch == ".":
                ny = pop(); nx = pop()
                nx = _as_int(nx); ny = _as_int(ny)
                if nx is None or ny is None or nx < 0 or ny < 0:
                    raise _Refuse
                x = nx % width
                y = ny % height
                # jump replaces the position; the move below advances from the target
            elif ch == "o":
                c = _as_char(pop())
                if c is None:
                    raise _Refuse
                out += c.encode("utf-8")
                if len(out) > OUTPUT:
                    raise _Refuse
            elif ch == "n":
                iv = _as_int(pop())
                if iv is None:
                    raise _Refuse
                out += str(iv).encode("ascii")
                if len(out) > OUTPUT:
                    raise _Refuse
            elif ch == "!":
                skip = True
            elif ch == "?":
                if pop() == 0:
                    skip = True
            else:
                raise _Refuse       # an unmodelled executed character: "something smells fishy"
        # advance the pointer (twice on a trampoline)
        x = (x + dx) % width
        y = (y + dy) % height
        if skip:
            x = (x + dx) % width
            y = (y + dy) % height
            skip = False


# =================================================================================================
# LOLCODE  (esolangs.org/wiki/LOLCODE; LOLCODE 1.2 spec)
# =================================================================================================
#
# Execution model, strict subset:
#   - Envelope: the first statement is HAI [<version>], the last reached is KTHXBYE (execution stops
#     there).  Comments: BTW ... to end of line; OBTW ... TLDR across lines.
#   - Values: YARN (string), NUMBR (integer). NUMBAR (float) is REFUSED -- its decimal rendering is
#     author-chosen.  NOOB (uninitialised) prints nothing in the spec but is REFUSED here (fail
#     closed).
#   - Statements: I HAS A <var> [ITZ <expr>] ; <var> R <expr> ; VISIBLE <expr> [!] (one operand; the
#     trailing ! suppresses the newline).
#   - Expressions: a YARN literal "..." with the spec escapes (:) :> :o :" :: :(HHHH) ), a NUMBR
#     literal, a variable, SMOOSH <expr> [AN <expr> ...] [MKAY] (concatenation), and the unambiguous
#     integer operators SUM/DIFF/PRODUKT/MOD/BIGGR/SMALLR OF <x> AN <y>.
#   - REFUSED (whole program -> None): GIMMEH (input), loops (IM IN YR / IM OUTTA YR), conditionals
#     (O RLY?), functions (HOW IZ I), QUOSHUNT (rounding is author-chosen), a NUMBAR, a comparison /
#     boolean, printing a NOOB, an unknown escape, and any other statement or token.

_LOL_STR_ESCAPE = {")": "\n", ">": "\t", "o": "\a", '"': '"', ":": ":"}
_LOL_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_LOL_NUMBR = re.compile(r"^-?[0-9]+$")
_LOL_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_LOL_BINOP = {"SUM": lambda a, b: a + b, "DIFF": lambda a, b: a - b,
              "PRODUKT": lambda a, b: a * b, "MOD": lambda a, b: a % b,
              "BIGGR": lambda a, b: max(a, b), "SMALLR": lambda a, b: min(a, b)}
_LOL_REFUSE_WORDS = frozenset({
    "GIMMEH", "IM", "O", "WTF", "HOW", "QUOSHUNT", "BOTH", "EITHER", "WON", "NOT", "ANY", "ALL",
    "DIFFRINT", "MAEK", "IS", "GTFO", "FOUND", "CAN", "FAIL", "WIN", "NOOB",
})


class _Lol:
    """A strict, single-pass LOLCODE interpreter over the pre-stripped statement list."""

    def __init__(self, deadline):
        self.vars = {}
        self.out = bytearray()
        self.deadline = deadline
        self.steps = 0

    def _tick(self):
        self.steps += 1
        if self.steps > STEPS:
            raise _Refuse
        if (self.steps & (TICK - 1)) == 0 and time.perf_counter() > self.deadline:
            raise _Refuse

    def _emit(self, s):
        self.out += s.encode("utf-8")
        if len(self.out) > OUTPUT:
            raise _Refuse

    # -- expression evaluation ------------------------------------------------------------------
    def _render(self, value):
        """A value's text when printed (VISIBLE / SMOOSH). YARN as itself, NUMBR as its decimal; a
        NOOB or any other type -> refuse."""
        if isinstance(value, str):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        raise _Refuse

    def _eval(self, toks):
        """Evaluate the whole token list as ONE expression, or refuse. Returns a YARN (str) or a
        NUMBR (int)."""
        value, rest = self._eval_one(toks)
        if rest:                         # trailing tokens the grammar does not consume
            raise _Refuse
        return value

    def _eval_one(self, toks):
        """(value, remaining tokens) for the first expression in `toks`."""
        if not toks:
            raise _Refuse
        self._tick()
        head = toks[0]
        if head.startswith('"'):
            return self._yarn(head), toks[1:]
        if _LOL_NUMBR.match(head):
            return int(head), toks[1:]
        if head in _LOL_BINOP:
            if len(toks) < 2 or toks[1] != "OF":
                raise _Refuse
            a, rest = self._eval_one(toks[2:])
            if rest and rest[0] == "AN":
                rest = rest[1:]
            b, rest = self._eval_one(rest)
            if not isinstance(a, int) or isinstance(a, bool) \
                    or not isinstance(b, int) or isinstance(b, bool):
                raise _Refuse
            return _LOL_BINOP[head](a, b), rest
        if head == "SMOOSH":
            parts = []
            rest = toks[1:]
            while rest and rest[0] not in ("MKAY",):
                val, rest = self._eval_one(rest)
                parts.append(self._render(val))
                if rest and rest[0] == "AN":
                    rest = rest[1:]
            if rest and rest[0] == "MKAY":
                rest = rest[1:]
            return "".join(parts), rest
        if head in _LOL_REFUSE_WORDS or head == "OF" or head == "AN" or head == "MKAY":
            raise _Refuse
        if _LOL_IDENT.match(head):
            if head not in self.vars:
                raise _Refuse
            v = self.vars[head]
            if v is None:                # a NOOB used in an expression
                raise _Refuse
            return v, toks[1:]
        raise _Refuse

    def _yarn(self, tok):
        """A YARN literal token (already a single '"..."' token) -> its decoded string, or refuse on
        an unterminated literal or an unknown escape."""
        if len(tok) < 2 or tok[0] != '"' or tok[-1] != '"':
            raise _Refuse
        body = tok[1:-1]
        out = []
        i, n = 0, len(body)
        while i < n:
            ch = body[i]
            if ch == '"':
                raise _Refuse            # a bare quote inside the body: not a single literal
            if ch != ":":
                out.append(ch)
                i += 1
                continue
            if i + 1 >= n:
                raise _Refuse
            nxt = body[i + 1]
            if nxt in _LOL_STR_ESCAPE:
                out.append(_LOL_STR_ESCAPE[nxt])
                i += 2
            elif nxt == "(":
                end = body.find(")", i + 2)
                if end == -1:
                    raise _Refuse
                hexs = body[i + 2:end]
                if not re.fullmatch(r"[0-9A-Fa-f]+", hexs or ""):
                    raise _Refuse
                cp = int(hexs, 16)
                c = _as_char(cp)
                if c is None:
                    raise _Refuse
                out.append(c)
                i = end + 1
            else:
                raise _Refuse            # :[name], :{var}, or any other escape is not modelled
        return "".join(out)

    # -- statements -----------------------------------------------------------------------------
    def run(self, statements):
        if not statements:
            raise _Refuse
        first = statements[0]
        if not first or first[0] != "HAI":
            raise _Refuse
        if len(first) > 1:
            if len(first) != 2 or not _LOL_VERSION.match(first[1]):
                raise _Refuse
        saw_end = False
        for toks in statements[1:]:
            self._tick()
            if not toks:
                continue
            if toks[0] == "KTHXBYE":
                if len(toks) != 1:
                    raise _Refuse
                saw_end = True
                break
            self._statement(toks)
        if not saw_end:
            raise _Refuse
        return bytes(self.out)

    def _statement(self, toks):
        head = toks[0]
        if head == "HAI":
            raise _Refuse                # HAI only as the first statement
        if head == "I":
            # I HAS A <var> [ITZ <expr>]
            if len(toks) < 4 or toks[1] != "HAS" or toks[2] != "A" or not _LOL_IDENT.match(toks[3]):
                raise _Refuse
            var = toks[3]
            if len(toks) == 4:
                self.vars[var] = None    # NOOB
                return
            if toks[4] != "ITZ":
                raise _Refuse
            self.vars[var] = self._eval(toks[5:])
            return
        if head == "VISIBLE":
            body = toks[1:]
            newline = True
            if body and body[-1] == "!":
                newline = False
                body = body[:-1]
            if not body:
                raise _Refuse
            value = self._eval(body)
            self._emit(self._render(value))
            if newline:
                self._emit("\n")
            return
        if len(toks) >= 2 and toks[1] == "R" and _LOL_IDENT.match(head) and head not in _LOL_REFUSE_WORDS:
            # <var> R <expr>
            if head not in self.vars:
                raise _Refuse            # assignment to an undeclared variable
            self.vars[head] = self._eval(toks[2:])
            return
        raise _Refuse                    # an unmodelled statement -> the whole program is None


def _lol_statements(text):
    """The LOLCODE source as a list of statement token lists, comments stripped, or None. A statement
    ends at a newline or a top-level comma; `...`/`,` at a physical line end continues the line; a
    comma or newline inside a YARN literal does not split. BTW / OBTW..TLDR comments are removed."""
    # strip OBTW ... TLDR block comments (line-oriented, as the spec requires them on their own lines)
    lines = text.split("\n")
    kept = []
    in_block = False
    for raw in lines:
        stripped = raw.strip()
        if in_block:
            if stripped == "TLDR" or stripped.startswith("TLDR "):
                in_block = False
            continue
        if stripped == "OBTW" or stripped.startswith("OBTW "):
            in_block = True
            continue
        kept.append(raw)
    if in_block:
        return None                      # an unterminated OBTW block
    joined = "\n".join(kept)

    # tokenise into statements, respecting YARN literals and BTW line comments
    statements = []
    cur = []                             # tokens of the current statement
    tok = []                             # characters of the current token
    i, n = 0, len(joined)

    def flush_tok():
        if tok:
            cur.append("".join(tok))
            tok.clear()

    def flush_stmt():
        flush_tok()
        if cur:
            statements.append(cur[:])
            cur.clear()

    while i < n:
        ch = joined[i]
        if ch == '"':
            # read a whole YARN literal as one token (the ':' escapes are decoded later)
            flush_tok()
            j = i + 1
            buf = ['"']
            while j < n:
                c = joined[j]
                if c == ":" and j + 1 < n:
                    buf.append(c)
                    buf.append(joined[j + 1])
                    j += 2
                    continue
                buf.append(c)
                j += 1
                if c == '"':
                    break
            else:
                return None              # unterminated string literal
            cur.append("".join(buf))
            i = j
            continue
        if ch == "\n":
            flush_stmt()
            i += 1
            continue
        if ch == ",":
            flush_stmt()
            i += 1
            continue
        if ch == "!":
            # the only use of ! outside a YARN literal is VISIBLE's newline suppressor; it is always
            # its own token, so it splits off a preceding operand (VISIBLE msg! -> "msg", "!")
            flush_tok()
            cur.append("!")
            i += 1
            continue
        if ch.isspace():
            flush_tok()
            i += 1
            continue
        # a BTW comment runs to the end of the physical line
        if ch == "B" and joined.startswith("BTW", i) and (i + 3 >= n or not _wordchar(joined[i + 3])) \
                and (not tok):
            # BTW must start a token boundary
            nl = joined.find("\n", i)
            i = n if nl == -1 else nl
            continue
        tok.append(ch)
        i += 1
    flush_stmt()
    return statements


def _wordchar(c):
    return c.isalnum() or c == "_"


def d_lolcode(b):
    """LOLCODE source -> printed bytes, or None (strict; see the model above)."""
    t = _text(b)
    if t is None:
        return None
    started = time.perf_counter()
    try:
        statements = _lol_statements(t)
        if statements is None:
            return None
        return _Lol(_deadline()).run(statements)
    except _Refuse:
        return None
    except Exception:
        return None
    finally:
        _SPENT[0] += time.perf_counter() - started   # charge this call against the blob's share


# =================================================================================================
# registry (esolang2.py interface)
# =================================================================================================
BY_NAME = {"fish": d_fish, "lolcode": d_lolcode}
NAMES = frozenset(BY_NAME)

# Cheap anchored signature gates. A base64/hex/decimal warmup blob matches none of them, so the
# common path pays one failed search per gate and no interpreter runs. Each decoder re-checks itself
# exactly, so a signature match is never by itself an answer.
#
# fish: a ><> program that prints a slug must HALT (`;`), OUTPUT (`o` or `n`) and SOURCE 87+ crib
# characters -- which, in the warmup shape, comes from a string literal (`'` or `"`): the straight-line
# and looping encoders and every fixture all quote their text. A direction/mirror char alone no longer
# gates (the regression: ascii85's `<~ ~>` framing is nothing but direction chars, so an ascii85/base64
# intermediate state tripped the VM with no quote); requiring the quote is a stronger, more specific
# signature that still passes every genuine program. The plain crib holds `o`/`n` and `!` but no `;`, so
# it never gates; and the fish VM refuses on the first unmodelled executed char and on non-termination,
# so a blob that gates but is not a program yields None at once -- never a wrong slug, never a hang.
# lolcode: the HAI ... KTHXBYE envelope, each at the start of a (stripped) line.
_GATE_LOL_HAI = re.compile(rb"(?im)^[ \t]*HAI\b")
_GATE_LOL_END = re.compile(rb"(?im)^[ \t]*KTHXBYE\b")


def _which(cur) -> tuple:
    """The step names whose signature a payload could match (a cheap gate). Each decoder still checks
    itself exactly, so a signature match is never by itself an answer."""
    if not isinstance(cur, (bytes, bytearray, memoryview)):
        return ()
    b = bytes(cur)
    if not (MIN_PROG <= len(b) <= MAX_PROG) or b"\x00" in b:
        return ()
    names = []
    if b";" in b and (b"o" in b or b"n" in b) and (b"'" in b or b'"' in b):
        names.append("fish")
    if _GATE_LOL_HAI.search(b) and _GATE_LOL_END.search(b):
        names.append("lolcode")
    return tuple(names)


def steps(cur) -> list:
    """[(name, bytes)]: what the readers of this module make of one payload. The interpreters are
    skipped once this module has spent its whole share of the blob's budget (_over_budget), so no
    quantity of candidate states the search throws at it can overrun the blob (the ascii85 regression)."""
    _blob_epoch()
    out = []
    for name in _which(cur):
        if _over_budget():
            break
        try:
            o = BY_NAME[name](cur)
        except Exception:
            o = None
        if o:
            out.append((name, o))
    return out


def step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one step by its name, or None. Like esolang2's
    step_fn, the returned function re-checks the signature with _which so a chain cannot apply a
    reader to a payload its gate would reject."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        return fn(b) if name in _which(b) else None

    f.__name__ = "d_" + name
    return f


# -- crib-gated reader (standalone / test use; mirrors crib_decode's search) ----------------------
CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "


def read(blob, crib: str = CRIB):
    """Every (name, decoded text) this module reads whose decode CONTINUES the crib sentence. This is
    the never-wrong gate the full solver applies: a reader is answered plain only when its bytes
    reproduce the exact sentence, so a decoy that merely parses yields NOTHING, not a wrong slug."""
    found = []
    for name, out in steps(blob):
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text.startswith(crib):
            found.append((name, text))
    return found


# -- encoders (tests and round-trip only; never used by the solver) -------------------------------
def fish_encode(data: bytes) -> bytes:
    """A straight-line ><> program that prints `data`: push the bytes reversed in string mode (so the
    first byte is on top), output each with `o`, then halt. No loop, no mirror, so it always halts
    under the caps; `"` cannot appear in the crib or a slug, so the string literal is unambiguous."""
    chars = data.decode("latin-1")
    if '"' in chars or "\x00" in chars:
        raise ValueError("fish_encode: unsupported byte for the straight-line encoder")
    rev = chars[::-1]
    return ('"' + rev + '"' + "o" * len(chars) + ";").encode("latin-1")


def fish_encode_loop(data: bytes) -> bytes:
    """A LOOPING ><> program that prints `data` (exercises string mode, `l`, `?`, `!`, `v`, `>`, grid
    wrapping). The canonical two-row print loop:

        !v"<rev(data)>"!
         >l?!;o

    Row 0: the leading `!` skips the `v` on the first pass, string mode pushes the bytes reversed (so
    the first byte is on top), the trailing `!` then skips back onto the (now live) `v`, which drops
    the pointer onto row 1. Row 1: `>` heads right; `l` pushes the stack length; `?` skips the `!`
    when the length is zero (so the pointer reaches `;` and halts) and otherwise lets `!` trampoline
    past `;` to `o`, which prints the top byte; the trailing padding wraps round to `>` for the next
    byte. Used only by the test to validate the 2D / trampoline / conditional machinery; the solver
    never emits code."""
    chars = data.decode("latin-1")
    if '"' in chars or "\x00" in chars or "\n" in chars:
        raise ValueError("fish_encode_loop: unsupported byte")
    row0 = '!v"' + chars[::-1] + '"!'
    row1 = " >l?!;o"
    return (row0 + "\n" + row1).encode("latin-1")


_LOL_ENC_ESCAPE = {":": "::", '"': ':"', "\n": ":)", "\t": ":>", "\a": ":o"}


def _lol_escape(s: str) -> str:
    return "".join(_LOL_ENC_ESCAPE.get(c, c) for c in s)


def lolcode_encode(data: bytes) -> bytes:
    """A LOLCODE program that prints `data` with no trailing newline (VISIBLE ... !), so the reader's
    output equals `data` exactly for the round-trip test."""
    s = data.decode("latin-1")
    return ('HAI 1.2\nVISIBLE "' + _lol_escape(s) + '"!\nKTHXBYE\n').encode("latin-1")


def lolcode_encode_nl(data: bytes) -> bytes:
    """A LOLCODE program that prints `data` with the default trailing newline (no `!`)."""
    s = data.decode("latin-1")
    return ('HAI 1.2\nVISIBLE "' + _lol_escape(s) + '"\nKTHXBYE\n').encode("latin-1")


ENCODERS = {"fish": fish_encode, "lolcode": lolcode_encode}


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: esolang3.py <file> [...]", file=sys.stderr)
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
