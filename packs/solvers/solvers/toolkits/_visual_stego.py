"""Shared pieces of the B-117 visual stego engines (symbol_stream, swf_parse, gif_reveal, and
solvers/web/route_crawl.py): which files of a challenge an engine reads, safe output names, the
status rule they share, and whether a camera decoder for codes is there at all. A helper, not an
engine (no manifest).

The status rule: a flag read out of bytes or out of an error-corrected code is evidence
(`proven`); a flag read by OCR is only ever a `candidate`.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.append(str(HERE))

# One list of what a challenge folder holds that is not the challenge: image_carve's (Phase 1).
from image_carve import SKIP_DIRS, SKIP_FILES      # noqa: E402

NO_CODE_READER = "codes not read: neither py:zxingcpp nor py:pyzbar is importable"


def challenge_paths(challenge_dir, max_size: int) -> tuple[list, list]:
    """([(relative name, Path)], [skipped notes]) of a challenge's files, sorted by name: the sweep's
    scratch copy (`unpacked/`) when there is one, else `files/`, else the folder itself. Recon
    output, bookkeeping files and links are left out; a file over `max_size` bytes is left out and
    named in the notes. FileNotFoundError when the folder does not exist.

    The same walk as image_carve.challenge_files, with its skip lists. It is its own function
    because these engines need what that one does not give: the paths (they read the first bytes
    before the whole file), a cap of their own, and the name of each file the cap left out."""
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        raise FileNotFoundError(f"no such challenge folder: {challenge_dir}")
    root = next((challenge_dir / d for d in ("unpacked", "files") if (challenge_dir / d).is_dir()), challenge_dir)
    out, skipped = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for name in sorted(filenames):
            path = here / name
            if name in SKIP_FILES or path.is_symlink() or not path.is_file():
                continue
            rel = str(path.relative_to(challenge_dir))
            size = path.stat().st_size
            if size > max_size:
                skipped.append(f"{rel}: {size} bytes is over the {max_size} byte cap, not read")
                continue
            out.append((rel, path))
    return out, skipped


def safe_name(name: str) -> str:
    """A file name made of a relative path, for an output folder."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or "file"


def code_reader_missing() -> str | None:
    """None when a camera decoder for QR and barcodes imports (zxing-cpp, else pyzbar: what
    carve_stego.decode_codes reads with), else the note an engine adds to its result. Without one
    decode_codes returns nothing, which would read as "no code in the picture"."""
    try:
        import zxingcpp  # noqa: F401
        return None
    except ImportError:
        pass
    try:
        from pyzbar import pyzbar  # noqa: F401
        return None
    except Exception:                                   # ImportError, or libzbar itself is absent
        return NO_CODE_READER


def status_of(proven, candidates, material: bool) -> str:
    """The SolverResult status: one proven flag and nothing else is `solved`; any other flag is a
    `candidate`; material for a human or model read with no flag is `unsure`; else `none`."""
    proven, candidates = list(dict.fromkeys(proven)), [c for c in dict.fromkeys(candidates) if c not in proven]
    if len(proven) == 1 and not candidates:
        return "solved"
    if proven or candidates:
        return "candidate"
    return "unsure" if material else "none"
