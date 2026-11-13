#!/usr/bin/env python3
"""Offline test of the Piet reader (solvers/common/piet.py, GAP-PIET).

  .venv/bin/python -m pytest tests/test_piet.py   (or `python tests/test_piet.py`)

No network and no token. Every image is built here from the 20-colour Piet palette with a tiny
linear-program encoder (value block of a byte's size, a push transition, an out(char) transition,
then a black-walled downward terminator so the program halts cleanly). The encoder is only a test
fixture; the module under test derives everything from the image bytes.

What is checked, with the never-guess holes exercised on purpose (not only the easy happy path):

  happy      a hand-built Piet image that prints the crib + slug -> read_slug returns that slug,
             and run_piet returns the exact bytes; the same at codel size 3 (scaled x3).
  codel      _codel_size returns 1 for a 1:1 grid and 3 for a x3 grid; a x3 image decodes the same.
  no-crib    a valid Piet program whose output does NOT begin with the crib (plain text, or even a
             slug-shaped string with no crib) -> run_piet gives the bytes but read_slug is None:
             never a slug read out of some other text.
  bad-tail   the crib followed by a malformed slug, or by the slug plus extra text -> read_slug None.
  off-pal    one off-palette pixel (an anti-aliased / photographic colour) -> None.
  non-piet   a colour gradient and a solid single-colour image -> None.
  input      a program whose only transition is in(char) (needs runtime input) -> None.
  no-halt    a program run under a step cap too small to finish -> None (never a partial print).
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

CRIB = piet.CRIB


def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)) if detail and not ok else ""))
    assert ok, name + ((" :: " + str(detail)) if detail else "")


# ---------------------------------------------------------------------------- the fixture encoder

W, B = piet.WHITE, piet.BLACK


def _render(grid, scale=1):
    """A PNG of a grid of colour indices (0..17, WHITE, BLACK), each codel scaled to scale x scale."""
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


def _program_grid(data):
    """A 3-row Piet program that prints `data`. Row 0 holds, left to right, for each byte: a value
    block whose width is the byte value, then a push transition into a one-codel operator block; the
    out(char) transition into the next value block prints the byte. A single sentinel block (F)
    receives the last out(char), then turns down into a black-walled terminator so the VM halts with
    every exit blocked (proved by run_piet in the test)."""
    h = l = 0
    row0 = []
    for b in data:
        if b < 1:
            raise ValueError("the encoder prints bytes >= 1 (printable text only)")
        row0 += [h * 3 + l] * b                   # value block, width = byte value
        nl, nh = (l + 1) % 3, h                    # push: hue +0, lightness +1
        row0 += [nh * 3 + nl]                       # operator block
        h, l = (nh + 5) % 6, (nl + 2) % 3           # out(char): hue +5, lightness +2 -> next value colour
    row0 += [h * 3 + l]                             # F: the sentinel that takes the final out(char)
    pf = len(row0) - 1
    d1 = h * 3 + (l + 2) % 3                         # F -> D1 = pop (hue +0, lightness +2)
    tcol = h * 3 + (l + 1) % 3                       # D1 -> T = pop
    width = pf + 3
    row0 += [B] * (width - len(row0))               # black to the right of F
    row1 = [B] * width
    row2 = [B] * width
    row1[pf] = d1                                   # D1, directly below F
    row2[pf - 1] = row2[pf] = row2[pf + 1] = tcol   # T: a 3-wide bar entered at its middle from above
    return [row0, row1, row2]


def piet_png(data, scale=1):
    return _render(_program_grid(data), scale)


# ---------------------------------------------------------------------------- happy path

SLUG = "brave-compass-clover-42"


@pytest.fixture(scope="module")
def crib_img():
    return piet_png((CRIB + SLUG).encode())


def test_happy_path(crib_img):
    check(piet.read_slug(crib_img) == SLUG, "happy: read_slug recovers the slug from a crib program")
    check(piet.run_piet(crib_img) == (CRIB + SLUG).encode(), "happy: run_piet returns the exact crib + slug bytes")

    crib_img3 = piet_png((CRIB + SLUG).encode(), scale=3)
    check(piet.read_slug(crib_img3) == SLUG, "happy: read_slug works at codel size 3 (image scaled x3)")

    # A second, differently-shaped slug, to show the slug is read from the bytes, not hard-coded.
    SLUG2 = "zesty-lantern-fjord-07"
    check(piet.read_slug(piet_png((CRIB + SLUG2).encode())) == SLUG2,
          "happy: a different slug is recovered (variant-proof)")


# ---------------------------------------------------------------------------- codel size inference
def test_codel_size_inference():
    check(piet._codel_size(_program_grid(b"Hi"), len(_program_grid(b"Hi")[0]), 3) == 1,
          "codel: a 1:1 grid infers codel size 1")
    scaled = _render(_program_grid(b"Hi"), scale=3)
    # Rebuild the full-res index grid from the rendered PNG and infer its codel size.
    _im = Image.open(io.BytesIO(scaled)).convert("RGB")
    _px = _im.load()
    _full = [[piet.PALETTE[_px[x, y]] for x in range(_im.size[0])] for y in range(_im.size[1])]
    check(piet._codel_size(_full, _im.size[0], _im.size[1]) == 3, "codel: an x3 grid infers codel size 3")
    check(piet.run_piet(scaled) == b"Hi", "codel: an x3 image decodes to the same output as x1")


# ---------------------------------------------------------------------------- no-crib: never a stray slug
def test_no_crib_never_a_stray_slug():
    plain_img = piet_png(b"hello world")
    check(piet.run_piet(plain_img) == b"hello world", "no-crib: run_piet returns the real bytes")
    check(piet.read_slug(plain_img) is None, "no-crib: plain text does not yield a slug")

    # A slug-shaped output with NO crib in front: read_slug must still refuse it.
    slug_only = piet_png(b"brave-compass-clover-42")
    check(piet.run_piet(slug_only) == b"brave-compass-clover-42", "no-crib: slug-shaped bytes are produced")
    check(piet.read_slug(slug_only) is None, "no-crib: a slug without the crib sentence is None (not a guess)")


# ---------------------------------------------------------------------------- bad tail after the crib
def test_bad_tail_after_the_crib():
    check(piet.read_slug(piet_png((CRIB + "hello").encode())) is None,
          "bad-tail: crib followed by a non-slug is None")
    check(piet.read_slug(piet_png((CRIB + SLUG + " and more").encode())) is None,
          "bad-tail: crib + slug + trailing text is None (the remainder must be exactly one slug)")


# ---------------------------------------------------------------------------- off-palette
def test_off_palette():
    _im = Image.open(io.BytesIO(piet_png(b"Hi"))).convert("RGB")
    _im.load()[0, 0] = (1, 2, 3)                        # an anti-aliased / photographic colour
    _bio = io.BytesIO()
    _im.save(_bio, "PNG")
    off_img = _bio.getvalue()
    check(piet.run_piet(off_img) is None, "off-pal: one off-palette pixel -> run_piet None")
    check(piet.read_slug(off_img) is None, "off-pal: one off-palette pixel -> read_slug None")


# ---------------------------------------------------------------------------- non-Piet images
def test_non_piet_images():
    grad = Image.new("RGB", (30, 10))
    _g = grad.load()
    for y in range(10):
        for x in range(30):
            _g[x, y] = (x * 8 % 256, y * 25 % 256, (x + y) * 5 % 256)
    _bio = io.BytesIO()
    grad.save(_bio, "PNG")
    check(piet.run_piet(_bio.getvalue()) is None, "non-piet: a colour gradient -> None")
    check(piet.read_slug(_bio.getvalue()) is None, "non-piet: a colour gradient -> read_slug None")

    _bio = io.BytesIO()
    Image.new("RGB", (20, 20), piet.COLORS[1]).save(_bio, "PNG")
    check(piet.run_piet(_bio.getvalue()) is None, "non-piet: a solid one-colour image (no transition) -> None")


# ---------------------------------------------------------------------------- input needed
# Two codels: colour index 0 -> index 16 is hue +5, lightness +1 == in(char).
def test_input_needed():
    in_img = _render([[0, 16]])
    check(piet.run_piet(in_img) is None, "input: an in(char) program needs runtime input -> None")


# ---------------------------------------------------------------------------- non-halting (step cap)
def test_non_halting_step_cap(crib_img):
    check(piet.run_piet(crib_img, steps=5) is None,
          "no-halt: a run that cannot finish within the step cap -> None (never a partial print)")


# ---------------------------------------------------------------------------- empty / garbage bytes
def test_empty_garbage_bytes():
    check(piet.run_piet(b"") is None, "garbage: empty bytes -> None")
    check(piet.run_piet(b"not an image at all") is None, "garbage: non-image bytes -> None")
    check(piet.read_slug(b"\x89PNG\r\n\x1a\nnope") is None, "garbage: broken PNG header -> None")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
