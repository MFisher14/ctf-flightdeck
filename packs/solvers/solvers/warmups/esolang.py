"""Bounded brainfuck-family esolang readers for Warmups (wave 4 breadth build, 2026-10-23).

Why this file exists
--------------------
The Warmups lane's standing weakness is morning-of adaptation to a NEW encoding. The esolang
family is a classic warmup shape ("decode this and submit the slug"). An audit of what is already
shipped (2026-10-23) shows the headline esolangs are ALL covered and so are NOT duplicated here:

  Brainfuck, Ook!, Short Ook (. ? !)   solvers/common/classical.py  (crib_decode d_bf; Short Ook and
                                       ook/OOK in any case only since row 546: before it d_bf's `"Ook" in t`
                                       test refused both before the short form was reached)
  COW (moo/mOo/...), Whitespace,       solvers/warmups/esolangs.py  (crib_decode d_cow and M)
  Befunge-93, Malbolge, JSFuck, Deadfish

The genuine gap is the brainfuck-DIALECT family -- token substitutions of Brainfuck that CTF
warmups reach for and that no shipped reader takes:

  alphuck    the eight letters a c e i j o p s                 (esolangs.org/wiki/Alphuck)
  pikalang   pi ka pika chu pipi pichu pikachu pikapi           (esolangs.org/wiki/Pikalang)
  blub       "Blub." "Blub?" "Blub!" in pairs (Ook-structured)  (esolangs.org/wiki/Blub)
  spoon      a binary Huffman prefix code of the eight commands (esolangs.org/wiki/Spoon)

Each maps deterministically to Brainfuck and runs on ONE self-contained, sandboxed brainfuck VM
below: a pure function of the input, no file/network/syscall access, a hard step cap and an output
cap, and an internal wall-clock backstop. A program that reads input (an executed `,`), runs its
pointer out of range, has unbalanced brackets, or does not halt within the caps yields None -- never
a part of its output, never a guess. These are DECODERS (like base64), not "running a delivery": the
program text is data that the loop walks over.

NEVER WRONG
-----------
Nothing here is answered on a dialect's own name. A reading is plain ONLY because crib_decode's
search confirms the program's output continues the exact sentence (crib_decode.CRIB); the `read()`
helper applies that same crib gate for standalone / test use. A blob that merely shares a dialect's
small alphabet but decodes to anything other than the sentence yields NOTHING, never a wrong slug.
A brainfuck transform is information-complete, so when the output reproduces the 87-character crib
the slug after it is pinned too, digits and all -- these are plain readers, never digit-unsure.

warm() safety
-------------
Pure functions, no I/O, no global mutable state, no clock of its own (an internal deadline is derived
per call from time.perf_counter()), no import of crib_decode. Bounded by the program length
(MAX_PROG), the step cap and the output cap. Safe to call from crib_decode.warm() on a thread and
from a timed solve alike.

Wiring (this module changes no shipped file; the build-lead mirrors the byte_order (BO) / base_extra
(BE) hookup in crib_decode.py):

    BY_NAME   {step name: decoder(bytes) -> bytes | None}
    NAMES     frozenset(BY_NAME)
    _which(cur) -> tuple of applicable step names (a cheap anchored-regex signature gate)
    steps(cur)  -> list[(name, bytes)]
    step_fn(name) -> decoder(bytes) -> bytes | None

    1. `import esolang as ESL` with the same try/except guard as `import base_extra as BE`.
    2. in `_strict_steps`, after `yield from BE.steps(cur)`, add
       `if ESL is not None: yield from ESL.steps(cur)`.
    3. next to the BE line, add `if ESL is not None: _STRICT_NAMES |= set(ESL.NAMES);
       _FORM_NAMES |= set(ESL.NAMES)`.
    4. in `_step_fn`, add `if ESL is not None and name in ESL.NAMES: return ESL.step_fn(name)`.

Every name here is strict (a deterministic info-complete transform), so each is in _STRICT_NAMES and
its chain is answered plain when the crib matches. No saved Warmups payload is read by any reader
here (the test proves it on the shipped fixtures), so no earlier day can move.
"""

import re
import sys
import time

# -- bounds ---------------------------------------------------------------------------------------
STEPS = 2_000_000        # hard step cap of the brainfuck VM (the task's "e.g. 2M steps")
OUTPUT = 65_536          # bytes a program may print before it is abandoned (None)
CELLS = 30_000           # tape cells; a pointer that leaves [0, CELLS) is a refusal
TICK = 1 << 14           # steps between two looks at the wall clock
READER_TIME = 0.05       # wall-clock backstop (s) one reader call may run (COW's COW_TIME)
MAX_PROG = 128 * 1024    # bytes of a program a reader runs (a dialect program is larger than its BF)
MIN_PROG = 16            # bytes below which nothing is attempted (noise)
MAX_SPOON = 64 * 1024    # bytes of a Spoon bit-text a reader runs (bit-dense; smaller cap than the rest)

BF_OPS = "><+-.,[]"


# -- the sandboxed brainfuck VM -------------------------------------------------------------------
def run_bf(ops: str, *, cells: int = CELLS, steps: int = STEPS, out_cap: int = OUTPUT, deadline=None):
    """What a brainfuck op-string prints, as bytes, or None.

    None when the brackets are unbalanced, an executed `,` would read input (there is none), the
    pointer leaves the tape, more than `out_cap` bytes are printed, or the program does not halt
    within `steps` or before `deadline` (a time.perf_counter() value). Cells wrap mod 256. Pure:
    no I/O, no syscalls, no global state.
    """
    if not ops:
        return None
    if cells < 1:                      # a zero-length tape has no cell 0 to address
        return None
    # Bracket map (also the balance check): unbalanced -> None, before a single step runs.
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
    if "." not in ops:                 # nothing is ever printed: not a decoder's program
        return None
    mem = bytearray(cells)
    ptr = pc = count = 0
    out = bytearray()
    n = len(ops)
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
            out.append(mem[ptr])
            if len(out) > out_cap:
                return None
        elif c == ",":
            return None                # input: there is none, so the run is not deterministic
        elif c == "[":
            if mem[ptr] == 0:
                pc = jump[pc]
        elif c == "]":
            if mem[ptr] != 0:
                pc = jump[pc]
        pc += 1
    return bytes(out) or None


# -- helpers --------------------------------------------------------------------------------------
def _text(b):
    """A byte payload as an ASCII str within the size bounds, or None. The dialects are all ASCII;
    a non-ASCII or over-long payload is refused before any work."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    try:
        b = bytes(b)
    except ValueError:                 # e.g. a released memoryview
        return None
    if not (MIN_PROG <= len(b) <= MAX_PROG):
        return None
    try:
        return b.decode("ascii")
    except UnicodeDecodeError:
        return None


def _deadline():
    return time.perf_counter() + READER_TIME


# -- alphuck: a one-letter substitution of the eight commands -------------------------------------
_ALPHUCK = {"a": ">", "c": "<", "e": "+", "i": "-", "j": ".", "o": ",", "p": "[", "s": "]"}
_ALPHUCK_ENC = {v: k for k, v in _ALPHUCK.items()}


def d_alphuck(b):
    """Alphuck: a>, c<, e+, i-, j., o,, p[, s]. White space is a token separator only; any other
    character makes the payload not Alphuck (None)."""
    t = _text(b)
    if t is None:
        return None
    ops = []
    for ch in t:
        if ch.isspace():
            continue
        op = _ALPHUCK.get(ch)
        if op is None:
            return None
        ops.append(op)
    return run_bf("".join(ops), deadline=_deadline())


# -- pikalang: Pokemon-word tokens; white space is a token boundary, else greedy longest match ----
# esolangs.org/wiki/Pikalang
_PIKALANG = {"pipi": ">", "pichu": "<", "pi": "+", "ka": "-", "pikachu": ".", "pikapi": ",",
             "pika": "[", "chu": "]"}
_PIKALANG_ENC = {">": "pipi", "<": "pichu", "+": "pi", "-": "ka", ".": "pikachu", ",": "pikapi",
                 "[": "pika", "]": "chu"}
# Longest first, so a run with no white space resolves by longest match (pikachu before pika before pi).
_PIKA_TOKENS = sorted(_PIKALANG, key=len, reverse=True)
_PIKA_CHARS = set("".join(_PIKALANG))


def _greedy(chunk: str, tokens, table):
    """Tokenise a white-space-free run by longest match; the op string, or None if it does not
    consume cleanly."""
    ops = []
    i, n = 0, len(chunk)
    while i < n:
        for tok in tokens:
            if chunk.startswith(tok, i):
                ops.append(table[tok])
                i += len(tok)
                break
        else:
            return None
    return ops


def d_pikalang(b):
    """Pikalang. White space separates tokens; inside a white-space-free run, longest match (so
    'pikachu' is one '.' token, never 'pika'+'chu'). A run that does not tokenise cleanly is None."""
    t = _text(b)
    if t is None:
        return None
    if set(t) - _PIKA_CHARS - set(" \t\r\n\v\f"):
        return None
    ops = []
    for chunk in t.split():
        got = _greedy(chunk, _PIKA_TOKENS, _PIKALANG)
        if got is None:
            return None
        ops += got
    return run_bf("".join(ops), deadline=_deadline())


# -- blub: Ook-structured, "Blub." "Blub?" "Blub!" in pairs ---------------------------------------
# esolangs.org/wiki/Blub
_BLUB = {
    ("Blub.", "Blub?"): ">", ("Blub?", "Blub."): "<", ("Blub.", "Blub."): "+",
    ("Blub!", "Blub!"): "-", ("Blub!", "Blub."): ".", ("Blub.", "Blub!"): ",",
    ("Blub!", "Blub?"): "[", ("Blub?", "Blub!"): "]",
    # ("Blub?", "Blub?") is "fishfood": a pointer boost with no Brainfuck equivalent -> refuse.
}
_BLUB_ENC = {v: k for k, v in _BLUB.items()}
_BLUB_TOKEN = re.compile(r"Blub[.?!]")


def d_blub(b):
    """Blub: pairs of "Blub." / "Blub?" / "Blub!" map to the eight commands (Ook's structure). An
    odd number of tokens, a "Blub? Blub?" fishfood pair, or any non-token character is None."""
    t = _text(b)
    if t is None:
        return None
    toks = _BLUB_TOKEN.findall(t)
    # Every non-white-space character must belong to a token (no stray text).
    if "".join(toks) != "".join(t.split()):
        return None
    if len(toks) < 2 or len(toks) % 2:
        return None
    ops = []
    for i in range(0, len(toks), 2):
        op = _BLUB.get((toks[i], toks[i + 1]))
        if op is None:                 # fishfood or an impossible pair
            return None
        ops.append(op)
    return run_bf("".join(ops), deadline=_deadline())


# -- spoon: a binary Huffman prefix code of the eight commands ------------------------------------
# esolangs.org/wiki/Spoon
_SPOON = {"1": "+", "000": "-", "010": ">", "011": "<", "0011": "]", "00100": "[",
          "001010": ".", "0010110": ",", "00101110": "DEBUG", "00101111": "END"}
_SPOON_ENC = {"+": "1", "-": "000", ">": "010", "<": "011", "]": "0011", "[": "00100",
              ".": "001010", ",": "0010110"}
_SPOON_MAXLEN = max(len(c) for c in _SPOON)   # 8: a partial longer than this is malformed


def d_spoon(b):
    """Spoon: a prefix-free binary code (see _SPOON). White space is ignored. The DEBUG command
    (dump the whole tape) has no deterministic text and is refused; END stops the program. A
    bitstream that does not parse cleanly, or whose brainfuck program does not halt / print, is None."""
    t = _text(b)
    if t is None:
        return None
    bits = "".join(t.split())
    if not bits or len(bits) > MAX_SPOON or set(bits) - {"0", "1"}:
        return None
    ops = []
    cur = ""
    for bit in bits:
        cur += bit
        if len(cur) > _SPOON_MAXLEN:
            return None                # no codeword this long: malformed
        cmd = _SPOON.get(cur)
        if cmd is None:
            continue
        cur = ""
        if cmd == "END":
            break                      # stop execution: the rest of the stream is not run
        if cmd == "DEBUG":
            return None                # tape dump: not a deterministic text
        ops.append(cmd)
    if cur:                            # trailing bits that are not a complete codeword
        return None
    return run_bf("".join(ops), deadline=_deadline())


# -- registry (byte_order.py / base_extra.py interface) -------------------------------------------
BY_NAME = {"alphuck": d_alphuck, "pikalang": d_pikalang, "blub": d_blub, "spoon": d_spoon}
NAMES = frozenset(BY_NAME)

# Cheap anchored signature gates: a payload that is not a dialect's alphabet fails at the first
# foreign byte, so the common path (base64, hex, ...) pays one failed fullmatch per dialect and no VM
# runs. Each decoder still re-checks itself exactly.
_GATE = {
    "alphuck": re.compile(rb"[aceijops \t\r\n\v\f]+"),
    "pikalang": re.compile(rb"[pikachu \t\r\n\v\f]+"),
    "blub": re.compile(rb"(?:Blub[.?!][ \t\r\n\v\f]*)+"),
    "spoon": re.compile(rb"[01 \t\r\n\v\f]+"),
}


def _which(cur) -> tuple:
    """The step names whose signature a payload could match (a cheap gate). Each decoder still
    checks itself exactly, so a signature match is never by itself an answer."""
    if not isinstance(cur, (bytes, bytearray, memoryview)):
        return ()
    b = bytes(cur)
    if not (MIN_PROG <= len(b) <= MAX_PROG):
        return ()
    names = []
    for name, rx in _GATE.items():
        if name == "spoon" and len(b) > MAX_SPOON:
            continue
        if rx.fullmatch(b):
            names.append(name)
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
    """The decoder (bytes -> bytes or None) of one step by its name, or None. Like base_extra's
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
    """Every (name, decoded text) this module reads whose decode CONTINUES the crib sentence.

    This is the never-wrong gate the full solver applies: a reader is answered plain only when its
    bytes reproduce the exact sentence. Returns a list, so a decoy that merely shares a dialect's
    alphabet (and so decodes to garbage) yields NOTHING, not a wrong plain slug.
    """
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
    """A loop-free brainfuck program that prints `data`: one cell, counted up or down from the last
    byte, then '.'. No loop, no pointer move, no input, so it always halts under the caps."""
    out, cur = [], 0
    for byte in data:
        delta = (byte - cur) & 0xFF
        out.append("+" * delta if delta <= 128 else "-" * (256 - delta))
        out.append(".")
        cur = byte
    return "".join(out)


def enc_alphuck(data: bytes) -> bytes:
    return "".join(_ALPHUCK_ENC[op] for op in bf_encode(data)).encode()


def enc_pikalang(data: bytes) -> bytes:
    return " ".join(_PIKALANG_ENC[op] for op in bf_encode(data)).encode()


def enc_blub(data: bytes) -> bytes:
    return " ".join("%s %s" % _BLUB_ENC[op] for op in bf_encode(data)).encode()


def enc_spoon(data: bytes) -> bytes:
    return ("".join(_SPOON_ENC[op] for op in bf_encode(data)) + "00101111").encode()  # + END


ENCODERS = {"alphuck": enc_alphuck, "pikalang": enc_pikalang, "blub": enc_blub, "spoon": enc_spoon}


def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: esolang.py <file> [...]", file=sys.stderr)
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
