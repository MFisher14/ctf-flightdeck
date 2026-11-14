"""Boolfuck and generic brainfuck-token-dialect readers for Warmups (Day 28 look-ahead build, 2026-10-27).

Why this file exists
--------------------
The Warmups lane's standing weakness is morning-of adaptation to a NEW encoding, and the esolang family is
on a two-day streak (Day 26 Brainfuck, Day 27 Ook!). A third joke language is the highest-likelihood Day-28
shape (docs/retro/day-28/predictions-warmups.md). The shipped tree already covers Brainfuck, Ook!, Short Ook,
COW, Whitespace, Befunge, Malbolge, JSFuck, Deadfish and the brainfuck-dialects alphuck/pikalang/blub/spoon
(esolang.py). Two measured gaps remain and are built here:

  boolfuck     a BIT-level brainfuck ( + flips a bit, ; outputs a bit, no '.' and no '-' )
               esolangs.org/wiki/Boolfuck
  bfdialect    ANY new named brainfuck TOKEN-dialect (Hodor / Trollscript / FuckFuck / Nyan / ...) whose
               8 commands are whitespace-separated word tokens -- the token->command map is LEARNED from the
               fixed crib sentence and the program is then run on the sandboxed brainfuck VM.

Each maps deterministically to brainfuck (boolfuck directly, a dialect through the learned map) and runs on a
self-contained, sandboxed VM: a pure function of the input, no file/network/syscall access, a hard step cap,
an output cap, bounded cells, and an internal wall-clock backstop. A program that reads input (an executed
`,`), runs its pointer out of range, has unbalanced brackets, or does not halt within the caps yields None --
never a part of its output, never a guess. These are DECODERS (like base64): the program text is data the
loop walks over.

NEVER WRONG
-----------
  * boolfuck is a strict, information-complete transform: it is answered plain ONLY because crib_decode's
    search confirms its output continues the exact sentence (crib_decode.CRIB). A blob that merely shares the
    boolfuck alphabet but decodes to anything else yields NOTHING.
  * bfdialect LEARNS its map from the crib: it tries every injective assignment of the (<=8) distinct tokens
    to the 8 brainfuck commands, keeps only assignments whose output reproduces the exact 87-character crib,
    and returns the decoded bytes ONLY when every crib-matching assignment agrees on one output (else None).
    The 87-character crib pins the map; the slug after it (digits and all) is then pinned by the same program,
    so the reading is plain, never digit-unsure. If the search cannot be completed within its backstop, or
    two assignments give different crib-prefixed outputs, it returns None -- it never guesses.

A brainfuck/boolfuck/dialect transform is information-complete, so when the output reproduces the crib the
slug after it is pinned too -- these are plain readers, never digit-unsure.

warm() safety
-------------
Pure functions, no I/O, no global mutable state, no clock of its own (an internal deadline is derived per
call from time.perf_counter()), no import of crib_decode. Bounded by the program length (MAX_PROG), the step
cap and the output cap. Safe to call from crib_decode.warm() on a thread and from a timed solve alike.

Wiring (this module adds new readers; it rewrites no existing reader. crib_decode.py mirrors the esolang
(ESL) / esolang3 (ESL3) hookup):

    BY_NAME   {step name: decoder(bytes) -> bytes | None}
    NAMES     frozenset(BY_NAME)
    _which(cur) -> tuple of applicable step names (a cheap anchored signature gate)
    steps(cur)  -> list[(name, bytes)]
    step_fn(name) -> decoder(bytes) -> bytes | None

Every name here is strict (a deterministic info-complete transform; bfdialect's map is pinned by the crib),
so each is in _STRICT_NAMES and its chain is answered plain when the crib matches. No saved Warmups payload
is read by any reader here (the test proves it on the shipped fixtures), so no earlier day can move.
"""

import itertools
import re
import sys
import time

# -- bounds ---------------------------------------------------------------------------------------
STEPS = 5_000_000        # hard step cap of the brainfuck / boolfuck VM
OUTPUT = 65_536          # bytes a program may print before it is abandoned (None)
CELLS = 300_000          # tape cells (boolfuck is a bit tape, so it needs more than byte-BF)
TICK = 1 << 14           # steps between two looks at the wall clock
READER_TIME = 0.05       # wall-clock backstop (s) one boolfuck reader call may run (COW's COW_TIME)
DIALECT_TIME = 0.20      # wall-clock backstop (s) the bfdialect map search may run
MAX_PROG = 512 * 1024    # bytes of a program a reader runs (a dialect/boolfuck program dwarfs its BF)
MIN_PROG = 16            # bytes below which nothing is attempted (noise)

BF_CMDS = "><+-.,[]"     # the eight brainfuck commands (bfdialect maps tokens onto these)

CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
_CRIB_BYTES = CRIB.encode()


def _text(b):
    """A byte payload as an ASCII str within the size bounds, or None. The dialects are ASCII; a non-ASCII
    or out-of-range payload is refused before any work."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    b = bytes(b)
    if not (MIN_PROG <= len(b) <= MAX_PROG):
        return None
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return None


def _deadline(seconds=READER_TIME):
    return time.perf_counter() + seconds


# -- the sandboxed brainfuck VM (byte tape), with early prefix abort ------------------------------
def run_bf(ops, *, cells=CELLS, steps=STEPS, out_cap=OUTPUT, deadline=None, want=None):
    """What a brainfuck op-string prints, as bytes, or None.

    None when the brackets are unbalanced, an executed `,` would read input (there is none), the pointer
    leaves the tape, more than `out_cap` bytes are printed, or the program does not halt within `steps` or
    before `deadline`. Cells wrap mod 256. Pure: no I/O, no syscalls, no global state.

    `want` (optional bytes) is an early-abort prefix: the run is abandoned (None) the instant an output byte
    diverges from `want[:len(out)]`. This prunes a wrong learned map at its first output byte, so the
    bfdialect search is cheap even when it tries many assignments.
    """
    if not ops or "." not in ops:
        return None
    if cells < 1:                    # a zero-length tape has no cell 0 to address
        return None
    jump = {}
    stack = []
    for i, c in enumerate(ops):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None
            j = stack.pop()
            jump[i] = j
            jump[j] = i
    if stack:
        return None
    mem = bytearray(cells)
    ptr = pc = count = 0
    out = bytearray()
    n = len(ops)
    wlen = len(want) if want is not None else 0
    while pc < n:
        count += 1
        if count > steps:
            return None
        if deadline is not None and not (count & (TICK - 1)) and time.perf_counter() > deadline:
            return None
        c = ops[pc]
        if c == "+":
            mem[ptr] = (mem[ptr] + 1) & 0xFF
        elif c == "-":
            mem[ptr] = (mem[ptr] - 1) & 0xFF
        elif c == ">":
            ptr += 1
            if ptr >= cells:
                return None
        elif c == "<":
            ptr -= 1
            if ptr < 0:
                return None
        elif c == ".":
            b = mem[ptr]
            k = len(out)
            if want is not None and k < wlen and b != want[k]:
                return None          # diverged from the crib: this learned map is wrong
            out.append(b)
            if len(out) > out_cap:
                return None
        elif c == ",":
            return None              # input: there is none, so the run is not deterministic
        elif c == "[":
            if mem[ptr] == 0:
                pc = jump[pc]
        elif c == "]":
            if mem[ptr] != 0:
                pc = jump[pc]
        pc += 1
    return bytes(out) or None


# -- the sandboxed boolfuck VM (bit tape) ---------------------------------------------------------
def run_boolfuck(ops, *, cells=CELLS, steps=STEPS, out_cap=OUTPUT, deadline=None):
    """What a boolfuck op-string prints, as bytes, or None.

    Boolfuck (esolangs.org/wiki/Boolfuck): a bit tape, all 0.
      +  flip the bit under the pointer
      ;  output the bit under the pointer (bits are packed LSB-first into bytes)
      ,  read a bit of input   -> there is none, so an executed ',' is a refusal (None)
      <  >  move the pointer
      [  ]  standard brainfuck loop on the current bit
    Bits that do not fill a final byte are emitted as a final zero-padded byte (the author's
    reference behaviour, samuelhughes.com/boof). None on unbalanced brackets, an executed ',', a
    pointer off the tape, the output cap, the step cap or the deadline. Pure.
    """
    if not ops or ";" not in ops:
        return None
    if cells < 1:                    # a zero-length tape has no cell 0 to address
        return None
    jump = {}
    stack = []
    for i, c in enumerate(ops):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None
            j = stack.pop()
            jump[i] = j
            jump[j] = i
    if stack:
        return None
    tape = bytearray(cells)
    ptr = pc = count = 0
    out = bytearray()
    bits = 0
    nbits = 0
    n = len(ops)
    while pc < n:
        count += 1
        if count > steps:
            return None
        if deadline is not None and not (count & (TICK - 1)) and time.perf_counter() > deadline:
            return None
        c = ops[pc]
        if c == "+":
            tape[ptr] ^= 1
        elif c == ";":
            bits |= tape[ptr] << nbits      # LSB first
            nbits += 1
            if nbits == 8:
                out.append(bits)
                if len(out) > out_cap:
                    return None
                bits = 0
                nbits = 0
        elif c == ",":
            return None
        elif c == ">":
            ptr += 1
            if ptr >= cells:
                return None
        elif c == "<":
            ptr -= 1
            if ptr < 0:
                return None
        elif c == "[":
            if tape[ptr] == 0:
                pc = jump[pc]
        elif c == "]":
            if tape[ptr] != 0:
                pc = jump[pc]
        pc += 1
    if nbits:                        # flush a partial final byte, remaining bits zero (author spec)
        out.append(bits)
        if len(out) > out_cap:
            return None
    return bytes(out) or None


# -- boolfuck reader ------------------------------------------------------------------------------
_BOOLFUCK_SET = frozenset("+;,<>[]")
_BOOLFUCK_GATE = re.compile(rb"[+;,<>\[\] \t\r\n\v\f]+")


def d_boolfuck(b):
    """A boolfuck program run with a step/output/time cap: what it prints, or None. White space is ignored.
    A '.' or '-' (brainfuck's byte ops) makes the payload not boolfuck -> None; a program with no ';' prints
    nothing and is refused."""
    t = _text(b)
    if t is None:
        return None
    has_semi = False
    ops = []
    for ch in t:
        if ch.isspace():
            continue
        if ch not in _BOOLFUCK_SET:
            return None
        if ch == ";":
            has_semi = True
        ops.append(ch)
    if not has_semi:
        return None
    s = "".join(ops)
    cells = min(CELLS, s.count(">") + 2)
    return run_boolfuck(s, cells=cells, deadline=_deadline())


# -- generic brainfuck-token-dialect reader -------------------------------------------------------
MIN_DIALECT_TOKENS = 16      # fewer whitespace tokens than this is noise, not a program
MAX_DISTINCT = 8             # a brainfuck dialect has at most eight commands
_WORDY = re.compile(r"[A-Za-z]")
# These vocabularies already have fixed language semantics in esolang.py.  Their whitespace-token programs also
# satisfy the generic learned-dialect shape, but an alternative learned token map is not another valid reading of
# Pikalang or Blub.  Keep the generic reader for every other vocabulary; subsets matter because a valid program
# need not exercise all eight commands.
_NAMED_TOKEN_VOCABS = (
    frozenset({"pi", "ka", "pika", "chu", "pipi", "pichu", "pikachu", "pikapi"}),
    frozenset({"Blub.", "Blub?", "Blub!"}),
)


def _dialect_parts(b):
    """The whitespace-separated token list of a candidate dialect program, or None. A dialect here is a
    program of >= MIN_DIALECT_TOKENS whitespace tokens over at most MAX_DISTINCT distinct tokens, at least one
    of which is word-like (len >= 2 with a letter). That gate rejects the common encodings (base64/hex: one
    token or > 8 distinct; digit and morse lists: no word token; pure brainfuck/boolfuck: handled elsewhere)."""
    t = _text(b)
    if t is None:
        return None
    parts = t.split()
    if len(parts) < MIN_DIALECT_TOKENS:
        return None
    distinct = set(parts)
    if not (2 <= len(distinct) <= MAX_DISTINCT):
        return None
    if not any(len(tok) >= 2 and _WORDY.search(tok) for tok in distinct):
        return None
    return parts


def _generic_dialect_parts(b):
    """Token parts only when no shipped named language owns this exact vocabulary."""
    parts = _dialect_parts(b)
    if parts is None:
        return None
    tokens = frozenset(parts)
    return None if any(tokens <= vocabulary for vocabulary in _NAMED_TOKEN_VOCABS) else parts


def _learn_run(parts, deadline):
    """Learn the token->command map from the crib and return the decoded bytes, or None.

    Every injective assignment of the distinct tokens to the brainfuck commands is tried; a run is abandoned
    the instant its output diverges from the crib (run_bf's `want`), so a wrong map costs about one output
    byte. The decoded bytes of every assignment that reproduces the whole crib are collected; the reader
    answers ONLY when they all agree on one output (the crib pins the map). On an incomplete search (the
    deadline), or on two disagreeing crib-matching outputs, it returns None -- never a guess."""
    order = {}
    for tok in parts:
        if tok not in order:
            order[tok] = len(order)
    distinct = list(order)
    k = len(distinct)
    if not (2 <= k <= MAX_DISTINCT):
        return None
    idx = [order[tok] for tok in parts]          # the program as a sequence of token indices
    outputs = set()
    for perm in itertools.permutations(BF_CMDS, k):
        if time.perf_counter() > deadline:
            return None                          # search not finished: cannot prove uniqueness -> no guess
        if "." not in perm:
            continue                             # nothing is ever printed
        ops = "".join(perm[i] for i in idx)
        out = run_bf(ops, deadline=deadline, want=_CRIB_BYTES)
        if out is not None and out.startswith(_CRIB_BYTES):
            outputs.add(out)
            if len(outputs) > 1:
                return None                      # two readings disagree: ambiguous -> no guess
    if len(outputs) == 1:
        return next(iter(outputs))
    return None


def d_bfdialect(b):
    """A brainfuck TOKEN-dialect whose eight commands are whitespace-separated word tokens (Hodor,
    Trollscript, FuckFuck, Nyan, ...). The token->command map is learned from the crib; the program is then
    run on the brainfuck VM. Plain only when the learned map reproduces the exact crib and every crib-matching
    map agrees on one output; else None."""
    parts = _generic_dialect_parts(b)
    if parts is None:
        return None
    return _learn_run(parts, _deadline(DIALECT_TIME))


# -- registry (esolang.py / base_extra.py interface) ----------------------------------------------
BY_NAME = {"boolfuck": d_boolfuck, "bfdialect": d_bfdialect}
NAMES = frozenset(BY_NAME)


def _which(cur) -> tuple:
    """The step names whose signature a payload could match (a cheap gate). Each decoder still checks itself
    exactly, so a signature match is never by itself an answer."""
    if not isinstance(cur, (bytes, bytearray, memoryview)):
        return ()
    b = bytes(cur)
    if not (MIN_PROG <= len(b) <= MAX_PROG):
        return ()
    names = []
    if _BOOLFUCK_GATE.fullmatch(b) and b"." not in b and b";" in b:
        names.append("boolfuck")
    if _generic_dialect_parts(b) is not None:
        names.append("bfdialect")
    return tuple(names)


def steps(cur) -> list:
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


def step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one step by its name, or None. Like esolang's step_fn, the
    returned function re-checks the signature with _which so a chain cannot apply a reader to a payload its
    gate would reject."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        return fn(b) if name in _which(b) else None

    f.__name__ = "d_" + name
    return f


# -- crib-gated reader (standalone / test use; mirrors crib_decode's search) ----------------------
def read(blob, crib: str = CRIB):
    """Every (name, decoded text) this module reads whose decode CONTINUES the crib sentence. The never-wrong
    gate the full solver applies: a reader is answered plain only when its bytes reproduce the exact
    sentence. A decoy that merely shares an alphabet yields NOTHING."""
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
def bf_encode(data: bytes) -> str:
    """A loop-free brainfuck program that prints `data`: one cell, counted up or down from the last byte,
    then '.'. No loop, no pointer move, no input, so it always halts under the caps."""
    out, cur = [], 0
    for byte in data:
        delta = (byte - cur) & 0xFF
        out.append("+" * delta if delta <= 128 else "-" * (256 - delta))
        out.append(".")
        cur = byte
    return "".join(out)


def boolfuck_encode(data: bytes) -> str:
    """A loop-free boolfuck program that prints `data`: for each byte, flip then output each of its 8 bits
    LSB-first on one cell (toggling as needed). Round-trips through run_boolfuck."""
    out = []
    cur = 0
    for byte in data:
        for i in range(8):
            bit = (byte >> i) & 1
            if bit != cur:
                out.append("+")
                cur = bit
            out.append(";")
    return "".join(out)


def dialect_encode(data: bytes, tokens) -> bytes:
    """Encode `data` as a whitespace-separated brainfuck token-dialect. `tokens` maps each of the 8 brainfuck
    commands to its word token. Used only by tests."""
    prog = bf_encode(data)
    return " ".join(tokens[op] for op in prog).encode()


ENCODERS = {"boolfuck": boolfuck_encode}


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: esolang4.py <file> [...]", file=sys.stderr)
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
