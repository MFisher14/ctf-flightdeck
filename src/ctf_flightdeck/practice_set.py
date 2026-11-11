"""Where the practice set that ships with flightdeck lives (inside the installed package,
so `flightdeck practice` works without a clone)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def practice_dir() -> Path:
    """The bundled practice board. Raises FileNotFoundError, naming the path, if this
    installation has no practice set (a broken or partial install)."""
    path = Path(str(files("ctf_flightdeck").joinpath("practice")))
    if not (path / "board.json").is_file():
        raise FileNotFoundError(f"the practice set is missing from this installation (looked in {path})")
    return path
