"""Where the practice set that ships with flightdeck lives (inside the installed package,
so `flightdeck practice` works without a clone)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


MEASURED = (
    "the whole practice set cost $0.02 on Haiku 5.5 through OpenRouter, and $0.02 as claude lanes on Haiku "
    "(13 and 12 of 14 solved, 2026-11-16; docs/MODELS.md, \"What the practice set costs\"); a larger model costs more"
)
"""What one full run was measured to cost, said before a practice run starts (issue #43)."""


def practice_dir() -> Path:
    """The bundled practice board. Raises FileNotFoundError, naming the path, if this
    installation has no practice set (a broken or partial install)."""
    path = Path(str(files("ctf_flightdeck").joinpath("practice")))
    if not (path / "board.json").is_file():
        raise FileNotFoundError(f"the practice set is missing from this installation (looked in {path})")
    return path
