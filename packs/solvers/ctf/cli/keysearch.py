"""`ctf keysearch`: the resumable key-search harness (B-215, solvers/common/keysearch.py).

    python -m ctf keysearch new ID --spec SPEC.toml [--replace] [--allow-weak]
    python -m ctf keysearch run ID [--workers N] [--max-chunks N] [--cpu-seconds S] [--all]
    python -m ctf keysearch status ID [--json]
    python -m ctf keysearch show ID [--hit N | --index I] [--reveal]
    python -m ctf keysearch list
    (--root DIR before the action moves the searches out of <workdir>/keysearch)

A search is a job on disk (candidate banks, templates, derivations, an exact verifier) and a ledger of
the chunks already searched, so `run` after a crash, a budget stop or a handoff to another agent
continues where the last run stopped. Hits are shown masked; `show --reveal` prints one to stdout.
The spec format and the exit codes are in the engine's docstring and docs/keysearch.md.
"""
from __future__ import annotations

import argparse

from .. import packs as _packs
from .. import paths as _paths

HELP = "resumable key search: candidate banks, exact verifier, crash-safe ledger (B-215)"


def engine():
    """solvers/common/keysearch.py of this checkout, loaded once under its flat name."""
    return _packs.load_module("keysearch", _paths.repo_root() / "solvers" / "common" / "keysearch.py",
                              pack="keysearch")


def add_arguments(p: argparse.ArgumentParser) -> None:
    engine().add_arguments(p)


def run(args: argparse.Namespace) -> int:
    return engine().dispatch(args)
