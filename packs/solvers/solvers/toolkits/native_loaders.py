#!/usr/bin/env python3
"""Optional full-loader emulators (Qiling, unidbg): detected, never installed, never a fallback (B-241).

The bounded emulators of this repo (``solvers/common/native_image.py`` for ELF and Mach-O images,
``solvers/toolkits/pe_emu.py`` for PE) decline whatever they do not model: a library that needs the
real dynamic linker, a JNI call into ART, a protector that depends on its environment.  That class is
what Qiling (a Unicorn-based loader with a root filesystem) and unidbg (a JVM-hosted Android loader)
exist for.  Neither ships with the repo and neither is installed by build work or by a solver: an
operator installs one by hand when an event needs it.

This module only answers "is it usable here, and if not, why not":

    from solvers.toolkits import native_loaders
    native_loaders.status("qiling")        # LoaderStatus(name, available, reason, detail)
    native_loaders.require("unidbg")       # LoaderStatus, or LoaderUnavailable naming the reason
    native_loaders.report()                # {"qiling": {...}, "unidbg": {...}}: JSON-able

Nothing here imports Qiling or starts a JVM.  Importing Qiling would import Unicorn outside the
guarded capability check in ``solvers/common/native_emulate`` (on Darwin/arm64 that import can die
with an uncatchable signal), so presence is read from the import system's metadata only.  A caller
that gets an "available" status still runs the loader in its own sandboxed process, on synthetic or
handed-out bytes it is allowed to emulate; this module never does.

Settings (read through ``ctf.env``):
  CTF_QILING_ROOTFS   the root filesystem folder Qiling loads libraries from
  CTF_UNIDBG_JAR      the unidbg jar (with dependencies) a JVM runs
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Mapping

LOADERS = ("qiling", "unidbg")
QILING_ROOTFS_ENV = "CTF_QILING_ROOTFS"
UNIDBG_JAR_ENV = "CTF_UNIDBG_JAR"
HUMAN_STEP = ("it is an operator's install, never done by build work or a solver "
              "(see docs/build-log/B-241.md, Human steps)")


class LoaderUnavailable(RuntimeError):
    """The optional loader asked for is not usable here; the message names the loader and the reason."""

    def __init__(self, name: str, reason: str):
        super().__init__(f"optional loader {name} is unavailable: {reason}")
        self.name = name
        self.reason = reason


@dataclass(frozen=True)
class LoaderStatus:
    name: str
    available: bool
    reason: str            # why it is unavailable; "" when available
    detail: str            # where it was found (a path), "" when unavailable


def _setting(name: str, environ: Mapping[str, str] | None) -> str | None:
    from ctf import env
    return env.get(name, environ=environ)


def _qiling(environ, find_spec, which) -> LoaderStatus:
    try:
        spec = find_spec("qiling")
    except (ImportError, ValueError) as exc:
        return LoaderStatus("qiling", False, f"the qiling package cannot be located ({exc}); {HUMAN_STEP}", "")
    if spec is None:
        return LoaderStatus("qiling", False, f"the qiling package is not installed in this interpreter; "
                                             f"{HUMAN_STEP}", "")
    rootfs = _setting(QILING_ROOTFS_ENV, environ)
    if not rootfs:
        return LoaderStatus("qiling", False, f"{QILING_ROOTFS_ENV} is not set (Qiling needs a root filesystem "
                                             "to load libraries from)", "")
    if not Path(rootfs).is_dir():
        return LoaderStatus("qiling", False, f"{QILING_ROOTFS_ENV} names a folder that does not exist", "")
    return LoaderStatus("qiling", True, "", str(spec.origin or "qiling"))


def _unidbg(environ, find_spec, which) -> LoaderStatus:
    jar = _setting(UNIDBG_JAR_ENV, environ)
    if not jar:
        return LoaderStatus("unidbg", False, f"{UNIDBG_JAR_ENV} is not set (unidbg is a jar a JVM runs); "
                                             f"{HUMAN_STEP}", "")
    if not Path(jar).is_file():
        return LoaderStatus("unidbg", False, f"{UNIDBG_JAR_ENV} names a file that does not exist", "")
    java = which("java")
    if not java:
        return LoaderStatus("unidbg", False, "java is not on PATH (unidbg needs a JVM)", "")
    return LoaderStatus("unidbg", True, "", jar)


_PROBES: dict[str, Callable] = {"qiling": _qiling, "unidbg": _unidbg}


def status(name: str, *, environ: Mapping[str, str] | None = None,
           find_spec: Callable = importlib.util.find_spec,
           which: Callable = shutil.which) -> LoaderStatus:
    """Whether optional loader ``name`` is usable in this process, and the named reason when not.

    ``environ``, ``find_spec`` and ``which`` are injectable for tests; production callers omit them.
    """
    probe = _PROBES.get(name)
    if probe is None:
        raise ValueError(f"unknown optional loader {name!r}: use one of {', '.join(LOADERS)}")
    return probe(environ, find_spec, which)


def require(name: str, **kwargs) -> LoaderStatus:
    """The status of an available loader, or :class:`LoaderUnavailable` naming why it is not."""
    found = status(name, **kwargs)
    if not found.available:
        raise LoaderUnavailable(name, found.reason)
    return found


def report(**kwargs) -> dict:
    """Every optional loader's status as a JSON-able dict (for a brief or a doctor report)."""
    return {name: asdict(status(name, **kwargs)) for name in LOADERS}


def main(argv: list[str] | None = None) -> int:
    """Print the report as JSON.  Exit 0 when a loader is available, 1 when none is."""
    import argparse

    parser = argparse.ArgumentParser(prog="native_loaders.py", description=__doc__.splitlines()[0])
    parser.parse_args(argv)
    found = report()
    print(json.dumps(found, indent=2, sort_keys=True))
    return 0 if any(row["available"] for row in found.values()) else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    raise SystemExit(main())
