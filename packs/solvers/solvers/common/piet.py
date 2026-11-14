#!/usr/bin/env python3
"""Piet reader: a PNG/GIF/BMP codel grid run as a bounded, sandboxed stack VM (Warmups image path).

GAP-PIET (Doc1 ticket A-mid). solvers/warmups/esolangs.py says "Piet needs an image and is out"; this
module is that reader, kept apart because it needs a picture, not text. It is a library the Warmups
day_patch.py override (or a lane agent) calls on an image delivery; after the day it is folded into
crib_decode.py the way the cow/whitespace/malbolge readers are. It is NOT a shipped lane solver and
edits none.

  run_piet(image_bytes, steps=STEPS, deadline=None, stdin=None) -> bytes | None
      The bytes a Piet program prints, or None. None of a byte string is ever trusted on its own: a
      Piet program with no input is deterministic, so the output is a FACT only once it reproduces
      the Warmups crib (read_slug below), the same contract the keyless esolang readers follow. With
      stdin (bytes/str) an input program is driven by it; in(char)/in(number) read from stdin and
      return EOF = -1 once it is exhausted (npiet's convention).

  run_trace(image_bytes, steps=STEPS, deadline=None, stdin=None) -> Trace | None
      The full Trace(output, steps, consumed, halted, needed_input) of a run, returned for any
      decodable grid whether or not it cleanly halted, so the input oracle can read the step and
      input-consumption counts. None only when the image is not a clean Piet grid.

  recover_input(probe, length, alphabet, *, prefix=b"") -> bytes
  piet_step_probe / piet_consumed_probe(image_bytes, steps=STEPS, deadline=None, pad=0) -> probe
      The input-read oracle. A probe maps a candidate input to a comparable score; recover_input
      greedily fixes the input one position at a time, choosing at each the alphabet byte that
      maximises the probe (ties keep the first tried). It recovers the secret of a program that
      checks its input prefix-first and leaks how far it got through how many steps it ran or how
      much input it consumed (PINK Glitched Screen's PIN, recovered one char at a time). The probes
      above build such a score from run_trace; any probe callable works, so the search is testable
      without a branching Piet image.

  read_slug(image_bytes, steps=STEPS, deadline=None) -> str | None
      The slug on the last line, returned only when run_piet's output reproduces the 87-character
      sentence followed by one well-formed slug and nothing else. Never a guess: an output that does
      not continue the crib is None, never a slug read out of the middle of some other text.

Never-guess (AGENTS.md, "Uncertain answers"), so that a wrong slug is impossible:

  * No colour is guessed. Every codel's RGB must be EXACTLY one of the 20 Piet colours (6 hues x 3
    lightness + white + black). One off-palette pixel (an anti-aliased edge, a JPEG, a photo) => None.
  * The codel size is the greatest common divisor of every maximal run of one colour, across rows and
    columns. It always divides the width and the height and tiles the image into uniform codels; an
    image that does not tile cleanly at that size (an ambiguous grid) => None.
  * A program that reads input (the in(number) / in(char) commands) cannot be run with no input and
    is NOT run with none: => None (its output would depend on something we do not have). Supply
    stdin to drive such a program, or use recover_input to solve for the input it wants.
  * A program that does not halt within the step cap, or prints more than OUTPUT bytes, => None: a
    partial print is never returned.
  * An image with no transition at all (one solid block, or fewer than two colours) prints nothing
    and is => None.

Nothing here executes a downloaded file: a Piet program is data that this loop walks over, with a
hard step cap and an optional wall-clock deadline (time.perf_counter() value, checked every few
thousand steps, never a signal), no input, and no file or network access.
"""
import io
import re
import sys
import time
from collections import namedtuple
from math import gcd

try:
    from PIL import Image
except Exception:   # absence is handled loudly at the decode boundary, not by a silent None
    Image = None


class MissingPillowError(RuntimeError):
    """Raised when a Piet operation is attempted but Pillow (py:PIL) is not installed.

    Rule 6 (no silent fallback): a missing reader dependency fails loudly with a named reason, so an
    unconfigured install is visible at the engine boundary rather than masquerading as the never-guess
    None that _decode returns for an image that is genuinely not a clean Piet grid. The manifest's
    needs_tools=["py:PIL"] is the router's gate; this is the gate for a direct caller."""

STEPS = 2_000_000       # default step cap of the VM (one step = one block-to-block move)
OUTPUT = 1 << 16        # bytes a program may print before it is treated as non-halting
TICK = 8192             # steps between two looks at the deadline

# ---------------------------------------------------------------------------- the palette

# 18 colours as (hue 0..5) x (lightness 0..2), index = hue * 3 + lightness; then white and black.
# Hue order: red, yellow, green, cyan, blue, magenta. Lightness: light, normal, dark.
_HUE_RGB = (
    ((255, 192, 192), (255, 0, 0), (192, 0, 0)),        # red
    ((255, 255, 192), (255, 255, 0), (192, 192, 0)),    # yellow
    ((192, 255, 192), (0, 255, 0), (0, 192, 0)),        # green
    ((192, 255, 255), (0, 255, 255), (0, 192, 192)),    # cyan
    ((192, 192, 255), (0, 0, 255), (0, 0, 192)),        # blue
    ((255, 192, 255), (255, 0, 255), (192, 0, 192)),    # magenta
)
COLORS = [_HUE_RGB[h][l] for h in range(6) for l in range(3)]   # index 0..17 -> RGB
WHITE_RGB = (255, 255, 255)
BLACK_RGB = (0, 0, 0)
WHITE = 18
BLACK = 19

PALETTE = {rgb: i for i, rgb in enumerate(COLORS)}
PALETTE[WHITE_RGB] = WHITE
PALETTE[BLACK_RGB] = BLACK

# Command table: TABLE[dhue][dlight]. dhue is the hue change 0..5, dlight the lightness change 0..2.
TABLE = (
    (None,   "push",  "pop"),     # hue +0
    ("add",  "sub",   "mul"),     # hue +1
    ("div",  "mod",   "not"),     # hue +2
    ("gt",   "ptr",   "sw"),      # hue +3
    ("dup",  "roll",  "in_n"),    # hue +4
    ("in_c", "out_n", "out_c"),   # hue +5: in(char), out(number), out(char)
)
_INPUT_OPS = frozenset({"in_n", "in_c"})

# Direction pointer: 0 right, 1 down, 2 left, 3 up. (drow, dcol).
_DELTA = ((0, 1), (1, 0), (0, -1), (-1, 0))

# ---------------------------------------------------------------------------- the crib gate

CRIB = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
# A slug: three lowercase words and a two-digit suffix (crib_decode.SLUG_FULL, mirrored here so this
# module imports nothing from the shipped lane solver).
SLUG_FULL = re.compile(r"[a-z]+-[a-z]+-[a-z]+-[0-9]{2}")


# ---------------------------------------------------------------------------- image -> codel grid

def _codel_size(full, W, H):
    """The codel size: the gcd of every maximal one-colour run, over rows and columns. >= 1."""
    s = 0
    for y in range(H):
        row = full[y]
        run = 1
        for x in range(1, W):
            if row[x] == row[x - 1]:
                run += 1
            else:
                s = gcd(s, run)
                run = 1
        s = gcd(s, run)
    for x in range(W):
        run = 1
        prev = full[0][x]
        for y in range(1, H):
            cur = full[y][x]
            if cur == prev:
                run += 1
            else:
                s = gcd(s, run)
                run = 1
                prev = cur
        s = gcd(s, run)
    return s or 1


def _decode(image_bytes):
    """A codel grid (rows of colour indices 0..19) from the image bytes, or None. None on: an image
    Pillow cannot open, any off-palette pixel, an empty image, or a grid that does not tile cleanly
    into uniform codels at the detected codel size (an ambiguous grid)."""
    if Image is None:
        raise MissingPillowError("Piet reader needs Pillow (py:PIL); install pillow to read images")
    if not image_bytes:
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return None
    W, H = img.size
    if W == 0 or H == 0:
        return None
    px = img.load()
    full = [[0] * W for _ in range(H)]
    for y in range(H):
        row = full[y]
        for x in range(W):
            idx = PALETTE.get(px[x, y])
            if idx is None:
                return None                     # off-palette colour: never guessed
            row[x] = idx
    s = _codel_size(full, W, H)
    if s <= 0 or W % s or H % s:
        return None                             # cannot tile: ambiguous codel size
    cw, ch = W // s, H // s
    grid = [[0] * cw for _ in range(ch)]
    for by in range(0, H, s):
        c0row = full[by]
        for bx in range(0, W, s):
            c0 = c0row[bx]
            for dy in range(s):                 # every pixel of the s x s codel must agree
                frow = full[by + dy]
                for dx in range(s):
                    if frow[bx + dx] != c0:
                        return None             # not uniform: ambiguous codel size
            grid[by // s][bx // s] = c0
    return grid


# ---------------------------------------------------------------------------- the VM

def _flood(grid, r, c):
    """Every codel of the colour block that holds (r, c), as a set of (row, col). 4-connected."""
    target = grid[r][c]
    H, W = len(grid), len(grid[0])
    seen = {(r, c)}
    stack = [(r, c)]
    while stack:
        y, x = stack.pop()
        for dy, dx in _DELTA:
            ny, nx = y + dy, x + dx
            if 0 <= ny < H and 0 <= nx < W and (ny, nx) not in seen and grid[ny][nx] == target:
                seen.add((ny, nx))
                stack.append((ny, nx))
    return seen


def _exit_codel(block, dp, cc):
    """The codel a block is left from, for direction pointer dp and codel chooser cc (0 left, 1 right).
    Furthest in the dp direction, then furthest to the cc side of dp."""
    # For each dp, (primary key to maximise) then (secondary key for cc=left, reversed for cc=right).
    if dp == 0:        # right: max col; cc left -> min row, cc right -> max row
        prim = max(c for _, c in block)
        cands = [(r, c) for r, c in block if c == prim]
        return min(cands) if cc == 0 else max(cands)     # min/max (row, col) with col fixed -> by row
    if dp == 1:        # down: max row; cc left -> max col, cc right -> min col
        prim = max(r for r, _ in block)
        cands = [(r, c) for r, c in block if r == prim]
        return max(cands) if cc == 0 else min(cands)     # by col
    if dp == 2:        # left: min col; cc left -> max row, cc right -> min row
        prim = min(c for _, c in block)
        cands = [(r, c) for r, c in block if c == prim]
        return max(cands) if cc == 0 else min(cands)
    # dp == 3          # up: min row; cc left -> min col, cc right -> max col
    prim = min(r for r, _ in block)
    cands = [(r, c) for r, c in block if r == prim]
    return min(cands) if cc == 0 else max(cands)


def _stack_op(op, stack, blocksize):
    """Apply a value/arithmetic Piet command in place. Pointer, switch, input and output are handled
    by the caller (they touch dp/cc, the output buffer, or need input). An op without enough stack is
    a no-op, as the Piet spec requires."""
    if op == "push":
        stack.append(blocksize)
    elif op == "pop":
        if stack:
            stack.pop()
    elif op in ("add", "sub", "mul", "div", "mod", "gt"):
        if len(stack) < 2:
            return
        a, b = stack[-1], stack[-2]
        if op in ("div", "mod") and a == 0:
            return                                # division by zero: left untouched
        stack.pop(); stack.pop()
        if op == "add":
            stack.append(b + a)
        elif op == "sub":
            stack.append(b - a)
        elif op == "mul":
            stack.append(b * a)
        elif op == "div":
            q = abs(b) // abs(a)
            stack.append(-q if (b < 0) != (a < 0) else q)   # truncate toward zero (npiet)
        elif op == "mod":
            stack.append(b % a)                   # Python % matches Piet's (sign of the divisor)
        else:                                     # gt
            stack.append(1 if b > a else 0)
    elif op == "not":
        if stack:
            stack.append(0 if stack.pop() != 0 else 1)
    elif op == "dup":
        if stack:
            stack.append(stack[-1])
    elif op == "roll":
        if len(stack) < 2:
            return
        count, depth = stack[-1], stack[-2]
        if depth < 0 or depth > len(stack) - 2:
            return                                # ill-formed roll: no-op (values kept)
        stack.pop(); stack.pop()
        if depth > 0:
            r = count % depth
            if r:
                part = stack[-depth:]
                stack[-depth:] = part[-r:] + part[:-r]


def _white_slide(grid, r, c, dp, cc):
    """Slide from a white codel (r, c) in a straight line. Returns (r, c, dp, cc) for the colour codel
    entered (no command run), or None when the slide is trapped (a loop, or nowhere to go). When
    blocked, the Piet rule is to toggle CC and rotate DP clockwise and try again from the same codel;
    a repeated (position, dp, cc) means a cycle -> the program ends."""
    H, W = len(grid), len(grid[0])
    seen = set()
    while True:
        if (r, c, dp, cc) in seen:
            return None
        seen.add((r, c, dp, cc))
        dr, dc = _DELTA[dp]
        nr, nc = r + dr, c + dc
        if not (0 <= nr < H and 0 <= nc < W) or grid[nr][nc] == BLACK:
            cc ^= 1
            dp = (dp + 1) % 4
            continue
        if grid[nr][nc] == WHITE:
            r, c = nr, nc
            continue
        return nr, nc, dp, cc                      # a colour codel: enter it, no command


# ---------------------------------------------------------------------------- input

# What an in(number)/in(char) command returned, and why a run stopped.
Trace = namedtuple("Trace", "output steps consumed halted needed_input")
# output: bytes printed so far; steps: block-to-block commands executed; consumed: input values read;
# halted: True only on a clean stop (never a step-cap or deadline exit); needed_input: True when the
# program tried to read input that was not available (so the result is not a fact).


class _NoInput:
    """The reader used when no stdin is supplied: any in() command fails the run (the historical
    contract -- an input program run with no input is None, never a guess)."""
    consumed = 0
    exhausted = False

    def read_char(self):
        return None

    def read_number(self):
        return None


class _StdinReader:
    """Feeds a fixed input to in(char)/in(number). in(char) returns the next byte's value; in(number)
    reads an optional sign and decimal digits (skipping leading whitespace), like npiet's stdin. At
    end of input both return EOF = -1 (npiet's convention) and set .exhausted, so a program that keeps
    reading past the input is still deterministic. Never a guess: the bytes are given, nothing is
    invented."""

    def __init__(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._data = bytes(data)
        self._i = 0
        self.consumed = 0
        self.exhausted = False

    def read_char(self):
        if self._i >= len(self._data):
            self.exhausted = True
            return -1
        v = self._data[self._i]
        self._i += 1
        self.consumed += 1
        return v

    def read_number(self):
        n = len(self._data)
        while self._i < n and self._data[self._i] in b" \t\r\n\f\v":
            self._i += 1
        if self._i >= n:
            self.exhausted = True
            return -1
        start = self._i
        if self._data[self._i] in b"+-":
            self._i += 1
        digits = self._i
        while self._i < n and 0x30 <= self._data[self._i] <= 0x39:
            self._i += 1
        if self._i == digits:                      # a sign with no digits, or no digit at all: EOF
            self._i = start
            self.exhausted = True
            return -1
        self.consumed += 1
        return int(self._data[start:self._i])


def _execute(grid, steps, deadline, reader):
    """Run a decoded Piet grid and return a Trace, or None when the grid itself is unusable (fewer
    than two colours). reader.read_char()/read_number() supply input; _NoInput makes any read fail the
    run. The never-guess rules are in the module docstring."""
    H, W = len(grid), len(grid[0])
    # Need at least two colours for any transition; a solid image prints nothing.
    if len({v for row in grid for v in row} - {WHITE, BLACK}) < 2:
        return None

    out = bytearray()
    stack = []
    dp, cc = 0, 0            # direction pointer right, codel chooser left
    r = c = 0
    count = 0
    stuck = 0                # consecutive blocked attempts
    halted = False           # True only on a clean stop; a step-cap exit is never a clean halt
    needed_input = False

    while count < steps:
        count += 1
        if count % TICK == 0 and deadline is not None and time.perf_counter() > deadline:
            break
        if len(out) > OUTPUT:
            break

        color = grid[r][c]
        if color == BLACK:
            break                                  # the pointer can never stand on black (ill-formed)
        if color == WHITE:
            res = _white_slide(grid, r, c, dp, cc)
            if res is None:
                halted = True
                break
            r, c, dp, cc = res
            stuck = 0
            continue

        block = _flood(grid, r, c)
        er, ec = _exit_codel(block, dp, cc)
        dr, dc = _DELTA[dp]
        nr, nc = er + dr, ec + dc

        if not (0 <= nr < H and 0 <= nc < W) or grid[nr][nc] == BLACK:
            # Blocked: toggle CC (even attempts), rotate DP clockwise (odd attempts); 8 -> halt.
            if stuck % 2 == 0:
                cc ^= 1
            else:
                dp = (dp + 1) % 4
            stuck += 1
            if stuck >= 8:
                halted = True                      # every exit blocked: the program ends
                break
            continue

        ncolor = grid[nr][nc]
        if ncolor == WHITE:
            r, c = nr, nc                          # enter white, no command
            stuck = 0
            continue

        dhue = (ncolor // 3 - color // 3) % 6
        dlight = (ncolor % 3 - color % 3) % 3
        op = TABLE[dhue][dlight]

        if op in _INPUT_OPS:
            v = reader.read_char() if op == "in_c" else reader.read_number()
            if v is None:                          # no input available: the run is not a fact
                needed_input = True
                break
            stack.append(v)
        elif op == "ptr":
            if stack:
                dp = (dp + stack.pop()) % 4
        elif op == "sw":
            if stack:
                cc = (cc + abs(stack.pop())) % 2
        elif op == "out_n":
            if stack:
                out += str(stack.pop()).encode("ascii")
        elif op == "out_c":
            if stack:
                n = stack.pop()
                if 0 <= n <= 0x10FFFF and not (0xD800 <= n <= 0xDFFF):
                    out += chr(n).encode("utf-8")
        else:
            _stack_op(op, stack, len(block))

        r, c = nr, nc
        stuck = 0

    return Trace(bytes(out), count, reader.consumed, halted, needed_input)


def run_trace(image_bytes, steps=STEPS, deadline=None, stdin=None):
    """A Trace of running a Piet image, or None when the image is not a clean Piet grid (off-palette,
    ambiguous codel size, fewer than two colours, broken bytes). stdin (bytes/str) feeds in(char) and
    in(number); without it an input command ends the run with needed_input=True. The Trace is always
    returned for a decodable grid, halted or not, so callers (the input oracle) can read the step and
    input-consumption counts even when the program did not cleanly halt."""
    if not isinstance(steps, int) or isinstance(steps, bool):
        return None
    if deadline is not None and not isinstance(deadline, (int, float)):
        return None
    grid = _decode(image_bytes)
    if grid is None:
        return None
    reader = _StdinReader(stdin) if stdin is not None else _NoInput()
    return _execute(grid, steps, deadline, reader)


def run_piet(image_bytes, steps=STEPS, deadline=None, stdin=None):
    """The bytes a Piet program prints, or None. See the module docstring for the never-guess rules;
    None is returned for any ambiguity, any run that does not cleanly halt in time, and -- when no
    stdin is given -- any need for input. With stdin (bytes/str) an input program is run against it."""
    tr = run_trace(image_bytes, steps=steps, deadline=deadline, stdin=stdin)
    if tr is None or not tr.halted:
        return None                                # ran past the step cap / needed input: never a partial print
    return tr.output if tr.output else None


# ---------------------------------------------------------------------------- the input-read oracle

def recover_input(probe, length, alphabet, *, prefix=b""):
    """Recover a program's secret input one position at a time. `probe(candidate: bytes) -> score` is
    any callable whose score is larger the more of `candidate`'s leading bytes are correct (how many
    steps a prefix-first checker ran, how much input it read, ...). At each of `length` positions the
    byte from `alphabet` with the highest probe is fixed; ties keep the first byte tried, so the
    search is deterministic. Returns the recovered bytes (its length is len(prefix) + length).

    This is a greedy hill-climb and is exact only when the probe is non-decreasing in the length of
    the correct prefix (the usual shape of a char-by-char checker). It is the method PINK used on the
    Glitched Screen PIN; the Piet binding is piet_step_probe / piet_consumed_probe below."""
    if length < 0:
        raise ValueError("length must be >= 0")
    alpha = bytes(alphabet) if not isinstance(alphabet, (bytes, bytearray)) else bytes(alphabet)
    if not alpha:
        raise ValueError("alphabet is empty")
    known = bytes(prefix)
    for _ in range(length):
        best_byte = None
        best_score = None
        for b in alpha:
            score = probe(known + bytes([b]))
            if best_score is None or score > best_score:
                best_score = score
                best_byte = b
        known += bytes([best_byte])
    return known


def _probe(image_bytes, field, steps, deadline, pad):
    grid = _decode(image_bytes)
    if grid is None:
        raise ValueError("not a decodable Piet image")

    def probe(candidate):
        data = bytes(candidate)
        if pad:
            data = data + b"\x00" * pad
        tr = _execute(grid, steps, deadline, _StdinReader(data))
        return getattr(tr, field)

    return probe


def piet_step_probe(image_bytes, steps=STEPS, deadline=None, pad=0):
    """A probe scoring a candidate input by how many block-to-block commands the image runs on it. A
    prefix-first checker runs further the more leading bytes are right, so recover_input climbs to the
    secret. `pad` appends that many NUL bytes after the candidate (so an unfinished prefix still has
    input to read)."""
    return _probe(image_bytes, "steps", steps, deadline, pad)


def piet_consumed_probe(image_bytes, steps=STEPS, deadline=None, pad=0):
    """A probe scoring a candidate input by how many input values the image reads before it stops. A
    checker that bails on the first wrong byte reads one more byte per correct leading byte."""
    return _probe(image_bytes, "consumed", steps, deadline, pad)


# ---------------------------------------------------------------------------- the crib gate

def read_slug(image_bytes, steps=STEPS, deadline=None):
    """The slug a Piet image proves, or None. The output of run_piet is trusted only when it is the
    87-character Warmups sentence followed by exactly one well-formed slug (crib_decode's contract),
    so a wrong slug can never be returned: anything else is None."""
    out = run_piet(image_bytes, steps=steps, deadline=deadline)
    if not out:
        return None
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text.lstrip("﻿").strip()
    if not text.startswith(CRIB):
        return None
    rest = text[len(CRIB):].strip()
    if not SLUG_FULL.fullmatch(rest):
        return None                                # the remainder is not exactly one slug
    return rest


def _main(argv) -> int:       # pragma: no cover
    if argv and argv[0] in ("-h", "--help"):
        print("usage: piet.py <image> [...]")
        return 0
    if not argv:
        print("piet.py: expected at least one image", file=sys.stderr)
        return 2
    try:
        for path in argv:
            with open(path, "rb") as fh:
                raw = fh.read()
            o = run_piet(raw)
            s = read_slug(raw)
            print("%s: out=%r slug=%r" % (path, (o[:120] if o else o), s))
    except Exception as exc:
        print(f"piet.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
