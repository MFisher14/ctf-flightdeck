"""The pre-provisioned wheelhouse (B-188): every pin, downloaded once, installable with no network.

    from ctf.toolchain import wheels
    rep = wheels.check()                        # WheelReport for paths.wheelhouse_dir() and requirements.txt
    rep.missing                                 # [(name, version)] with no wheel or sdist in the folder
    wheels.plan()                               # [argv]: fill it (network: a human step), install from it offline

Why: sandboxed lanes had no route to PyPI or GitHub (DNS failures, "no matching distribution"), so
they hand-built stand-ins for libraries that were one install away. A lane that may lack the network
installs from the wheelhouse instead: `uv pip install --offline --no-index --find-links <dir>`.

The pins are requirements.txt's (generated from requirements.in, the single source, R-14). A file
counts for a pin when its distribution name (PEP 503 normalised) and version match: a wheel
`<name>-<version>-<tags>.whl` or an sdist `<name>-<version>.tar.gz` / `.zip`. A missing folder is a
WheelsError naming it (never an empty wheelhouse that "passes").
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import paths

REQUIREMENTS_REL = Path("requirements.txt")
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s#;]+)")
_SDIST = (".tar.gz", ".zip", ".tar.bz2")


class WheelsError(ValueError):
    """The wheelhouse folder or the requirements file is missing or unreadable."""


@dataclass(frozen=True)
class WheelReport:
    directory: str
    requirements: str
    pins: int
    present: tuple[tuple[str, str], ...]
    missing: tuple[tuple[str, str], ...]
    other_version: tuple[tuple[str, str, str], ...]   # (name, pinned, versions found)

    @property
    def passed(self) -> bool:
        return not self.missing

    def to_dict(self) -> dict[str, Any]:
        return {"directory": self.directory, "requirements": self.requirements, "pins": self.pins,
                "passed": self.passed, "present": [list(x) for x in self.present],
                "missing": [list(x) for x in self.missing], "other_version": [list(x) for x in self.other_version]}


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _norm_version(v: str) -> str:
    return v.lower().lstrip("v")


def parse_pins(text: str) -> list[tuple[str, str]]:
    """(name as written, version) for every `name==version` line."""
    return [(m.group(1), m.group(2)) for line in text.splitlines() if (m := _PIN.match(line))]


def dist_of(filename: str) -> tuple[str, str] | None:
    """(normalised name, version) of a wheel or sdist file name, or None for anything else."""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) >= 5:
            return normalise(parts[0]), _norm_version(parts[1])
        return None
    for ext in _SDIST:
        if filename.endswith(ext):
            stem = filename[: -len(ext)]
            name, sep, ver = stem.rpartition("-")
            if sep and name and ver[:1].isdigit():
                return normalise(name), _norm_version(ver)
    return None


def requirements_path(root: Path | None = None) -> Path:
    return (paths.repo_root() if root is None else Path(root)) / REQUIREMENTS_REL


def check(directory: Path | None = None, requirements: Path | None = None) -> WheelReport:
    d = paths.wheelhouse_dir() if directory is None else Path(directory)
    req = requirements_path() if requirements is None else Path(requirements)
    if not d.is_dir():
        raise WheelsError(f"wheelhouse {d} is not there: fill it with `python -m ctf toolchain wheels --plan` "
                          "(a human step: it downloads), or set CTF_WHEELHOUSE")
    try:
        pins = parse_pins(req.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise WheelsError(f"{req}: requirements file not found") from None
    if not pins:
        raise WheelsError(f"{req}: no name==version pins in it")
    have: dict[str, set[str]] = {}
    for f in d.iterdir():
        dv = dist_of(f.name)
        if dv and f.is_file():
            have.setdefault(dv[0], set()).add(dv[1])
    present, missing, other = [], [], []
    for name, ver in pins:
        found = have.get(normalise(name), set())
        if _norm_version(ver) in found:
            present.append((name, ver))
        else:
            missing.append((name, ver))
            if found:
                other.append((name, ver, ", ".join(sorted(found))))
    return WheelReport(str(d), str(req), len(pins), tuple(present), tuple(missing), tuple(other))


def plan(directory: Path | None = None, requirements: Path | None = None,
         python: str | None = None) -> list[list[str]]:
    """The two commands: fill the wheelhouse (needs the network: a human step before the event), and
    install from it with no network (what a lane without PyPI runs)."""
    d = paths.wheelhouse_dir() if directory is None else Path(directory)
    req = requirements_path() if requirements is None else Path(requirements)
    py = python or sys.executable
    return [[py, "-m", "pip", "download", "--dest", str(d), "-r", str(req)],
            ["uv", "pip", "install", "--python", py, "--offline", "--no-index", "--find-links", str(d), "-r",
             str(req)]]


__all__ = ["WheelReport", "WheelsError", "check", "dist_of", "normalise", "parse_pins", "plan",
           "requirements_path"]
