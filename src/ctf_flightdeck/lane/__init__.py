"""The lane image: a Dockerfile shipped with flightdeck and the command that builds it.

flightdeck never pulls or builds an image on its own: `flightdeck image build` does,
when the player runs it.
"""

from __future__ import annotations

import shutil
from importlib.resources import as_file, files
from pathlib import Path

IMAGE = "ctf-flightdeck-lane:1"


def dockerfile() -> str:
    return files(__package__).joinpath("Dockerfile").read_text(encoding="utf-8")


def build_command(tag: str = IMAGE, *, docker: str | None = None) -> list[str]:
    """The `docker build` argv for the lane image (the context is this package's folder)."""
    return [docker or shutil.which("docker") or "docker", "build", "--tag", tag, "--file", "Dockerfile", "."]


def context_dir() -> Path:
    """A real folder holding the Dockerfile (the package's own, or a temporary copy)."""
    with as_file(files(__package__).joinpath("Dockerfile")) as path:
        return Path(path).parent
