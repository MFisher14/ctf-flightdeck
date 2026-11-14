"""ctf check-event [SLUG ...] [--workdir DIR] — the generated agent rules still match the event profile.

For each event (default: every folder under events/), fails when events/<slug>/event.toml does not
validate, or when CLAUDE.md or AGENTS.md is missing, stale (the profile or the template changed since
they were generated), edited by hand, or disagrees with its sibling. A folder that has agent files
but no event.toml also fails. With --workdir (one slug), the copies installed there are checked too.
Exit 0 when everything matches, 1 otherwise. Fix: `python -m ctf new-event <slug> --regen`.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import event as _event
from .. import eventrules
from .. import paths

HELP = "fail when an event's CLAUDE.md / AGENTS.md is missing, stale or disagrees with its event.toml"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("slugs", nargs="*", metavar="SLUG", help="default: every event folder")
    p.add_argument("--workdir", type=Path, metavar="DIR",
                   help="also check the copies installed in DIR (needs exactly one SLUG)")
    p.add_argument("--events-root", type=Path, metavar="DIR", help="default: <repo>/events")


def problems_for(slug: str, root: Path, workdir: Path | None = None) -> list[str]:
    try:
        prof = _event.load(slug, root)
    except _event.EventError as e:
        return [str(e)]
    try:
        out = eventrules.check(prof, root / slug)
        if workdir is not None:
            out += eventrules.check(prof, workdir)
    except eventrules.TemplateError as e:
        return [f"template: {e}"]
    return out


def _orphans(root: Path) -> list[str]:
    """Folders with generated agent files but no event.toml."""
    if not root.is_dir():
        return []
    return sorted(d.name for d in root.iterdir()
                  if d.is_dir() and not (d / _event.PROFILE_NAME).exists()
                  and any((d / n).exists() for n in eventrules.AGENT_FILES))


def run(args: argparse.Namespace) -> int:
    root = args.events_root or paths.events_root()
    if args.workdir is not None and len(args.slugs) != 1:
        print("ctf check-event: --workdir needs exactly one SLUG", file=sys.stderr)
        return 2
    slugs = list(args.slugs)
    orphans: list[str] = []
    if not slugs:
        slugs = _event.available(root)
        orphans = _orphans(root)
        if not slugs and not orphans:
            print(f"ctf check-event: no event profiles under {root}", file=sys.stderr)
            return 1
    bad = 0
    for slug in slugs:
        probs = problems_for(slug, root, args.workdir)
        if probs:
            bad += 1
            for pr in probs:
                print(f"FAIL  {slug}: {pr}")
        else:
            print(f"ok    {slug}")
    for slug in orphans:
        bad += 1
        print(f"FAIL  {slug}: {root / slug} has CLAUDE.md/AGENTS.md but no {_event.PROFILE_NAME}")
    return 1 if bad else 0
