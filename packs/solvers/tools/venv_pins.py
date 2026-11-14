#!/usr/bin/env python3
"""Check that the running venv has every pin in requirements.in installed at its version (SH-01).

The shared .venv fell behind requirements.in once, which caused 13 collection errors and dozens of
ModuleNotFoundError failures that looked like engine bugs. This check names the drift instead:

    .venv/bin/python tools/venv_pins.py [--requirements FILE]

It prints one line per pin that is MISSING (not installed) or MISMATCH (another version installed),
then the uv command that fixes them, and exits 1. It exits 0 when every pin is installed as written,
and 2 when the requirements file is missing or holds a line that is not an exact pin.
Packages installed but not pinned are not its business.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf import paths  # noqa: E402

_PIN = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)")


class PinFileError(ValueError):
    """The requirements file is missing or holds something other than exact pins."""


@dataclass(frozen=True)
class Drift:
    name: str
    pinned: str
    installed: str | None  # None: not installed

    @property
    def kind(self) -> str:
        return "MISSING" if self.installed is None else "MISMATCH"

    def line(self) -> str:
        if self.installed is None:
            return f"MISSING  {self.name}=={self.pinned}: not installed"
        return f"MISMATCH {self.name}=={self.pinned}: {self.installed} installed"


def normalise(name: str) -> str:
    """PEP 503 name normalisation, so dissect.ntfs and dissect-ntfs are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pins(text: str, source: str = "requirements.in") -> dict[str, str]:
    """Return {name as written: version} for every `name==version` line; comments and blanks skip.

    Any other line, or a package pinned twice, raises PinFileError naming the line.
    """
    pins: dict[str, str] = {}
    seen: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = _PIN.fullmatch(line)
        if match is None:
            raise PinFileError(f"{source}:{number}: not an exact pin (name==version): {line!r}")
        name, version = match.groups()
        key = normalise(name)
        if key in seen:
            raise PinFileError(f"{source}:{number}: {name} is pinned twice (first on line {seen[key]})")
        seen[key] = number
        pins[name] = version
    return pins


def installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def drift(pins: dict[str, str],
          version_of: Callable[[str], str | None] = installed_version) -> list[Drift]:
    """Every pin whose installed version is absent or different, in file order."""
    out = []
    for name, pinned in pins.items():
        got = version_of(name)
        if got != pinned:
            out.append(Drift(name, pinned, got))
    return out


def install_command(found: list[Drift]) -> str:
    specs = " ".join(f"{d.name}=={d.pinned}" for d in found)
    return f"uv pip install --python {sys.executable} {specs}"


def check(requirements: Path,
          version_of: Callable[[str], str | None] = installed_version) -> list[Drift]:
    if not requirements.is_file():
        raise PinFileError(f"{requirements}: requirements file not found")
    return drift(parse_pins(requirements.read_text(encoding="utf-8"), str(requirements)), version_of)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--requirements", type=Path, default=paths.repo_root() / "requirements.in",
                    help="pin file to check (default: requirements.in at the repo root)")
    args = ap.parse_args(argv)
    try:
        found = check(args.requirements)
    except PinFileError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    if not found:
        print(f"OK every pin in {args.requirements} is installed in {sys.prefix}")
        return 0
    for d in found:
        print(d.line())
    print(f"FIX  {install_command(found)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
