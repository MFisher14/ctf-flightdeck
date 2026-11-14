"""The lane image: a Dockerfile shipped with flightdeck and the command that builds it.

flightdeck never pulls or builds an image on its own: `flightdeck image build` does,
when the player runs it. The build writes the Dockerfile's fingerprint on the image as a
label, so `flightdeck doctor` can tell an image that an older flightdeck built (it is there,
so nothing else would ask for a rebuild) from one built from the Dockerfile shipped now.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from importlib.resources import as_file, files
from pathlib import Path

IMAGE = "ctf-flightdeck-lane:1"
LABEL = "org.ctf-flightdeck.lane.dockerfile"  # on a built image: fingerprint() of the Dockerfile it was built from


def dockerfile() -> str:
    return files(__package__).joinpath("Dockerfile").read_text(encoding="utf-8")


def fingerprint() -> str:
    """The shipped Dockerfile's SHA-256, its first 16 hex digits: what build_command() labels
    the image with."""
    return hashlib.sha256(dockerfile().encode("utf-8")).hexdigest()[:16]


def build_command(tag: str = IMAGE, *, docker: str | None = None) -> list[str]:
    """The `docker build` argv for the lane image (the context is this package's folder)."""
    return [docker or shutil.which("docker") or "docker", "build", "--tag", tag, "--label", f"{LABEL}={fingerprint()}",
            "--file", "Dockerfile", "."]


def built_from(image: str = IMAGE, *, docker: str | None = None) -> str | None:
    """The Dockerfile fingerprint the image on this machine carries (LABEL): "" when it has
    none (a flightdeck older than the label built it, or it was built by hand). None when it
    cannot be asked: no docker, no such image here, no answer. Nothing is pulled."""
    docker = docker or shutil.which("docker")
    if docker is None:
        return None
    try:
        done = subprocess.run([docker, "image", "inspect", "--format", "{{json .Config.Labels}}", image],
                              capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
        labels = json.loads(done.stdout.decode("utf-8", "replace")) if done.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    if done.returncode != 0 or not isinstance(labels, dict | None):
        return None
    value = (labels or {}).get(LABEL, "")
    return value if isinstance(value, str) else ""


def context_dir() -> Path:
    """A real folder holding the Dockerfile (the package's own, or a temporary copy)."""
    with as_file(files(__package__).joinpath("Dockerfile")) as path:
        return Path(path).parent
