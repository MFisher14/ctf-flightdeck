#!/usr/bin/env python3
"""B-055: Piet input support (stdin), run_trace, and the input-read oracle.

  .venv/bin/python -m pytest tests/test_b055_piet_input.py

Offline, no network, no token. Every image is hand-built from the 20-colour Piet palette with a tiny
input-echo encoder: a horizontal chain of 1-codel blocks whose colour transitions are, in turn,
in(char) then out(char), so the program reads a byte and prints it, N times, then falls into a
black-walled trap and halts cleanly. The encoder is only a fixture; the module under test derives
everything from the pixels.

What is checked:

  stdin        an echo-N program driven by stdin prints exactly what it read (variant-proof on the
               bytes), and reading past the input yields EOF = -1 (chr(-1) is unprintable, so it adds
               nothing), with the input-consumption count capped at what was actually read.
  refuse       the SAME input program with no stdin is None (the historical never-guess contract),
               and run_trace reports needed_input = True without inventing a byte.
  trace        run_trace returns step and consumed counts for a decodable grid even when it did not
               halt; None only for a non-Piet image.
  oracle       recover_input greedily recovers a secret from a prefix-monotone probe (the search
               itself, proven with a pure-Python checker), and the Piet-bound probes read real run
               traces (piet_consumed_probe grows with how much input the image consumed).
"""
import io
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import piet  # noqa: E402

try:
    from PIL import Image
except ImportError:          # every test needs Pillow: reported NOT RUN by the needs_tool marker
    Image = None

pytestmark = pytest.mark.needs_tool("py:PIL")

W, B = piet.WHITE, piet.BLACK


def _render(grid, scale=1):
    H, Wd = len(grid), len(grid[0])
    img = Image.new("RGB", (Wd * scale, H * scale))
    px = img.load()
    for y in range(H):
        for x in range(Wd):
            v = grid[y][x]
            rgb = piet.WHITE_RGB if v == W else piet.BLACK_RGB if v == B else piet.COLORS[v]
            for dy in range(scale):
                for dx in range(scale):
                    px[x * scale + dx, y * scale + dy] = rgb
    bio = io.BytesIO()
    img.save(bio, "PNG")
    return bio.getvalue()


def _echo_grid(n):
    """A 3-row Piet program that reads n bytes and echoes each. Row 0 is a chain of 1-codel blocks:
    the transition into an even block is in(char) (hue +5, lightness +0), into an odd block out(char)
    (hue +5, lightness +2). The chain ends on a sentinel that receives the last out(char); below it a
    pop/pop ladder into a 3-wide bar traps every exit so the VM halts cleanly after printing."""
    h = l = 0                       # start colour: red, normal -> index 1 (h=0,l=1); begin at l=1
    l = 1
    row0 = [h * 3 + l]
    for k in range(n):
        # in(char): hue +5, lightness +0
        h, l = (h + 5) % 6, (l + 0) % 3
        row0.append(h * 3 + l)
        # out(char): hue +5, lightness +2
        h, l = (h + 5) % 6, (l + 2) % 3
        row0.append(h * 3 + l)
    pf = len(row0) - 1              # sentinel index (the block the final out(char) lands on)
    d1 = h * 3 + (l + 2) % 3        # sentinel -> D1: pop (hue +0, lightness +2)
    tcol = h * 3 + (l + 1) % 3      # D1 -> T: pop
    width = pf + 3
    row0 += [B] * (width - len(row0))
    row1 = [B] * width
    row2 = [B] * width
    row1[pf] = d1
    row2[pf - 1] = row2[pf] = row2[pf + 1] = tcol
    return [row0, row1, row2]


def echo_png(n, scale=1):
    return _render(_echo_grid(n), scale)


# ---------------------------------------------------------------------------- stdin drives input
def test_stdin_echo():
    img = echo_png(3)
    assert piet.run_piet(img, stdin=b"abc") == b"abc"
    assert piet.run_piet(img, stdin="XYZ") == b"XYZ"      # str is utf-8 encoded
    # A different image length echoes a different count: the behaviour is on the pixels, not hard-coded.
    assert piet.run_piet(echo_png(5), stdin=b"hello") == b"hello"
    # Codel size 3 (scaled) reads and echoes the same.
    assert piet.run_piet(echo_png(2, scale=3), stdin=b"QZ") == b"QZ"


def test_stdin_eof_is_minus_one():
    # Only one byte for a 3-read program: the first prints, the two EOF reads push -1 (unprintable).
    tr = piet.run_trace(echo_png(3), stdin=b"a")
    assert tr is not None and tr.halted
    assert tr.output == b"a"
    assert tr.consumed == 1                       # EOF reads are not counted as consumed input


# ---------------------------------------------------------------------------- no stdin: never a guess
def test_input_program_without_stdin_is_none():
    img = echo_png(2)
    assert piet.run_piet(img) is None             # the historical contract: no input -> None
    tr = piet.run_trace(img)                      # but a trace is still produced, flagged
    assert tr is not None
    assert tr.needed_input is True
    assert tr.halted is False
    assert tr.output == b""                       # nothing invented


# ---------------------------------------------------------------------------- run_trace shape
def test_run_trace_reports_counts_and_none_only_for_non_piet():
    tr = piet.run_trace(echo_png(2), stdin=b"ok")
    assert tr.halted and tr.output == b"ok"
    assert tr.steps > 0 and tr.consumed == 2
    # A non-Piet image (solid colour, no transition) -> None, not a Trace.
    bio = io.BytesIO()
    Image.new("RGB", (8, 8), piet.COLORS[1]).save(bio, "PNG")
    assert piet.run_trace(bio.getvalue()) is None
    assert piet.run_trace(b"not an image") is None


# ---------------------------------------------------------------------------- the oracle search
def test_recover_input_greedy_search():
    secret = b"7392"
    alphabet = b"0123456789"

    def prefix_len(candidate):
        # A char-by-char checker leaks how many leading bytes are right (monotone in the prefix).
        n = 0
        for a, b in zip(candidate, secret):
            if a != b:
                break
            n += 1
        return n

    assert piet.recover_input(prefix_len, len(secret), alphabet) == secret
    # A wrong alphabet cannot recover the secret (guards against a tautology).
    assert piet.recover_input(prefix_len, len(secret), b"01") != secret


def test_recover_input_edges():
    assert piet.recover_input(lambda c: 0, 0, b"ab") == b""
    with pytest.raises(ValueError):
        piet.recover_input(lambda c: 0, 2, b"")
    with pytest.raises(ValueError):
        piet.recover_input(lambda c: 0, -1, b"ab")


def test_recover_input_tie_break_keeps_first_tried():
    # recover_input documents "ties keep the first byte tried": when two alphabet bytes probe to the
    # SAME maximal score, the one iterated first must win. A strictly-monotone probe can never expose
    # this, so only an explicit tie does. Kills the `score > best_score` -> `score >= best_score`
    # mutation, which would silently switch the tie-break to "keep the LAST tied byte".
    def tie_probe(candidate):
        # 'a' (tried first below) and 'z' (tried last) both score 1; 'b','c' score 0 -> a tie at top.
        return 1 if candidate[-1:] in (b"a", b"z") else 0

    assert piet.recover_input(tie_probe, 1, b"abcz") == b"a"
    # It is "first ITERATED", not "smallest byte": reversing the alphabet keeps the now-first-tried 'z'.
    assert piet.recover_input(tie_probe, 1, b"zcba") == b"z"


# ---------------------------------------------------------------------------- missing Pillow is loud
def test_missing_pillow_fails_loudly(monkeypatch):
    # Rule 6 (no silent fallback): without Pillow the reader must fail with a named reason, not return
    # the never-guess None that a caller cannot tell apart from "not a clean Piet grid". Simulate the
    # absent install by forcing the module's Image reference to None.
    monkeypatch.setattr(piet, "Image", None)
    with pytest.raises(piet.MissingPillowError):
        piet.run_trace(b"\x89PNG\r\n\x1a\n")
    with pytest.raises(piet.MissingPillowError):
        piet.run_piet(b"\x89PNG\r\n\x1a\n")


# ---------------------------------------------------------------------------- the Piet-bound probe
def test_piet_consumed_probe_reads_real_traces():
    probe = piet.piet_consumed_probe(echo_png(3))
    assert probe(b"") == 0
    assert probe(b"a") == 1
    assert probe(b"ab") == 2
    assert probe(b"abc") == 3
    assert probe(b"abcdef") == 3                   # a 3-read program never reads more than 3
    # The step probe also runs the image and returns a positive count.
    assert piet.piet_step_probe(echo_png(2))(b"xy") > 0
    # A non-decodable image is a loud failure, not a silent zero.
    with pytest.raises(ValueError):
        piet.piet_consumed_probe(b"not an image")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
