"""ctf workdir [--create] — print the per-event working folder, ctf.paths.workdir().

The one way a shell script learns the workdir: `wd="$(python -m ctf workdir)"`. No script defaults
$CTF_WORKDIR itself (tests/test_single_sources.py refuses `${CTF_WORKDIR:-...}`).
"""
from __future__ import annotations

import argparse
import sys

from .. import event as _event
from .. import paths as _paths

HELP = "print the event working folder ($CTF_WORKDIR, else ~/ctf-work/<event>)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--create", action="store_true", help="create the folder if it does not exist")


def run(args: argparse.Namespace) -> int:
    try:
        d = _paths.ensure_workdir() if args.create else _paths.workdir()
    except _event.EventError as e:
        print(f"ctf workdir: {e}", file=sys.stderr)
        return 2
    print(d)
    return 0
