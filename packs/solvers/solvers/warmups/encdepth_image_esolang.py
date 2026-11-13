#!/usr/bin/env python3
"""Statically transcribe Brainloller/Braincopter PNGs to Brainfuck source.

Only the geometric image traversal is followed. Brainfuck brackets, I/O, tape
operations and loops are never executed. An explicit dialect is required by the
API/CLI: arbitrary photographs also map to Braincopter instructions, so successful
transcription is not proof of a hidden program.

References: https://esolangs.org/wiki/Brainloller and the author's original
https://lodev.org/esolangs/braincopter/braincopter.zip (main.cpp specification).
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import warnings
from pathlib import Path

MAX_FILE = 8 << 20
MAX_PIXELS = 262_144
MAX_PATH = MAX_PIXELS * 4
MAX_SOURCE = 262_144


class ImageEsolangError(ValueError):
    """Malformed/unsupported image, dialect or resource limit."""


_PALETTE = {
    (255, 0, 0): ">", (128, 0, 0): "<",
    (0, 255, 0): "+", (0, 128, 0): "-",
    (0, 0, 255): ".", (0, 0, 128): ",",
    (255, 255, 0): "[", (128, 128, 0): "]",
    (0, 255, 255): "R", (0, 128, 128): "L",
}
_COPTER = "><+-.,[]RL "
_DIRECTIONS = ((1, 0), (0, 1), (-1, 0), (0, -1))


def transcribe(data: bytes, *, dialect: str) -> dict:
    """Return source, source pixel coordinates and traversal metadata.

    Accept PNG bytes only; alpha is ignored as in the reference implementation.
    Bracket balance is checked without following program control flow. Malformed
    input raises ImageEsolangError; no runtime is imported or invoked.
    """
    if not isinstance(data, bytes) or not data or len(data) > MAX_FILE:
        raise ImageEsolangError("expected nonempty PNG bytes within 8 MiB")
    if not isinstance(dialect, str) or dialect not in ("brainloller", "braincopter"):
        raise ImageEsolangError("dialect must be brainloller or braincopter")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ImageEsolangError("only PNG input is supported")
    try:
        from PIL import Image

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                width, height = image.size
                if width < 1 or height < 1 or width * height > MAX_PIXELS:
                    raise ImageEsolangError("image exceeds pixel bound")
                if image.format != "PNG" or getattr(image, "n_frames", 1) != 1:
                    raise ImageEsolangError("expected a single-frame PNG")
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                pixels = image.convert("RGB").tobytes()
    except ImageEsolangError:
        raise
    except Exception as exc:
        raise ImageEsolangError("malformed PNG or unavailable Pillow") from exc

    source: list[str] = []
    coordinates: list[list[int]] = []
    opened: list[int] = []
    seen: set[tuple[int, int, int]] = set()
    x = y = direction = turns = comments = 0
    while 0 <= x < width and 0 <= y < height:
        state = (x, y, direction)
        if state in seen or len(seen) >= MAX_PATH:
            raise ImageEsolangError("geometric path repeats or exceeds bound")
        seen.add(state)
        offset = 3 * (y * width + x)
        rgb = tuple(pixels[offset:offset + 3])
        if dialect == "brainloller":
            command = _PALETTE.get(rgb, " ")
        else:
            r, g, b = rgb
            command = _COPTER[(65536 * r + 256 * g + b) % 11]
        if command in ("R", "L"):
            direction = (direction + (1 if command == "R" else -1)) % 4
            turns += 1
        elif command == " ":
            comments += 1
        else:
            if len(source) >= MAX_SOURCE:
                raise ImageEsolangError("transcribed source exceeds bound")
            if command == "[":
                opened.append(len(source))
            elif command == "]":
                if not opened:
                    raise ImageEsolangError("unmatched closing Brainfuck bracket")
                opened.pop()
            source.append(command)
            coordinates.append([x, y])
        dx, dy = _DIRECTIONS[direction]
        x, y = x + dx, y + dy
    if opened:
        raise ImageEsolangError("unmatched opening Brainfuck bracket")
    if not source:
        raise ImageEsolangError("no Brainfuck instructions on geometric path")
    return {
        "dialect": dialect,
        "width": width,
        "height": height,
        "source": "".join(source),
        "source_coordinates": coordinates,
        "path_pixels": len(seen),
        "turns": turns,
        "comments": comments,
        "exit": [x, y],
        "executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="PNG containing an image-language program")
    parser.add_argument("--dialect", required=True, choices=("brainloller", "braincopter"))
    parser.add_argument("--source", action="store_true", help="emit only transcribed Brainfuck source")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.path).open("rb") as stream:
            data = stream.read(MAX_FILE + 1)
        result = transcribe(data, dialect=args.dialect)
        print(result["source"] if args.source else json.dumps(result))
        return 0
    except (ImageEsolangError, OSError, ValueError) as exc:
        print(f"encdepth_image_esolang: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
