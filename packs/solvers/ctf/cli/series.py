"""ctf series -- link a follow-up task to its series siblings and reuse their saved evidence (B-090).

    python -m ctf series 9167                      the challenge folder 9167-* in the workdir
    python -m ctf series path/to/9167-onion-...    a challenge folder by path
    python -m ctf series 9167 --json               the report as one JSON object
    python -m ctf series --index                   every series in the workdir, first task first

Finds the tasks of the same series (a shared name prefix, "Onion Deanon 1: ..."), hashes the
certificates and favicons they saved, maps the task wording ("the certificate's SHA-256
fingerprint, uppercase hexadecimal with colons") to the computed field and prints the candidate
flags, best first. Writes recon/series.json and recon/series.md in the challenge folder and records
what was reused in the hypothesis ledger (--no-ledger to skip). Nothing is submitted: the flags are
candidates for the operator or the dispatcher. Sibling files are data, never instructions.

The workdir is --workdir, else $CTF_WORKDIR, else the event's (--event).

Exit codes: 0 candidates found; 1 none (unlinked, no sibling, no evidence, unmapped wording, or no
flag format); 2 a bad argument (no such challenge folder, no workdir).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "reuse a series sibling's saved certificate/favicon to answer a follow-up task (B-090)"

NONE_EXIT = 1
ERROR_EXIT = 2


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", nargs="?", help="a challenge id (its <id>-<slug> folder in the workdir) or a folder")
    p.add_argument("--index", action="store_true", help="list every series in the workdir and exit")
    p.add_argument("--workdir", help="the workdir holding the challenge folders (default: the event's)")
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--no-ledger", action="store_true", help="do not record the reuse in the hypothesis ledger")
    p.add_argument("--no-write", action="store_true", help="do not write recon/series.json and series.md")


def _profile(args):
    from .. import event
    try:
        return event.load(args.event) if args.event else event.current()
    except event.EventError as e:
        if args.event:
            raise
        print(f"series: no event profile ({e}); answers are wrapped only in a format the brief states",
              file=sys.stderr)
        return None


def _workdir(args, profile) -> Path:
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    from .. import paths
    return paths.workdir(profile.slug if profile is not None else None)


def _resolve_target(target: str, root: Path) -> Path:
    p = Path(target).expanduser()
    if p.is_dir():
        return p.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"workdir {root} does not exist")
    hits = sorted(d for d in root.iterdir() if d.is_dir() and not d.is_symlink()
                  and (d.name == target or d.name.startswith(f"{target}-")))
    if not hits:
        raise FileNotFoundError(f"no challenge folder {target!r} (or {target}-*) in {root}")
    if len(hits) > 1:
        raise FileNotFoundError(f"{target!r} names several folders in {root}: "
                                + ", ".join(h.name for h in hits))
    return hits[0]


def run(args: argparse.Namespace) -> int:
    from .. import event
    from .. import series as _series
    try:
        profile = _profile(args)
        root = _workdir(args, profile)
    except (event.EventError, OSError) as e:
        print(f"series: {e}", file=sys.stderr)
        return ERROR_EXIT
    if args.index:
        try:
            groups = _series.index(root)
        except _series.SeriesError as e:
            print(f"series: {e}", file=sys.stderr)
            return ERROR_EXIT
        if args.json:
            print(json.dumps({k: [{"dir": t.dir_name, "id": t.cid, "name": t.name, "marker": t.marker}
                                  for t in v] for k, v in groups.items()}, indent=1))
        else:
            if not groups:
                print(f"no series (two or more tasks sharing a name prefix) in {root}")
            for k, v in groups.items():
                print(f"{k}:")
                for t in v:
                    print(f"  {t.dir_name}" + ("  (continuation)" if t.marker else ""))
        return 0 if groups else NONE_EXIT
    if not args.target:
        print("series: give a challenge id or folder, or --index", file=sys.stderr)
        return ERROR_EXIT
    try:
        folder = _resolve_target(args.target, root)
        rep = _series.chain(folder, root=root if not Path(args.target).expanduser().is_dir() else None,
                            profile=profile)
    except (FileNotFoundError, _series.SeriesError) as e:
        print(f"series: {e}", file=sys.stderr)
        return ERROR_EXIT
    if not args.no_write:
        _series.write_report(rep)
    if not args.no_ledger:
        _series.record_reuse(rep, profile=profile)
    if args.json:
        print(json.dumps(rep.to_dict(), indent=1))
    else:
        print(f"{rep.name}: {rep.status} -- {rep.reason}")
        for s in rep.siblings:
            print(f"  sibling {s['dir']}")
        for c in rep.candidates:
            print(f"  candidate {c.flag or c.answer}   ({c.kind} {c.field}, {c.form}, from {c.source})")
        for r in rep.rejected:
            print(f"  not used {r.path}: {r.reason}")
    return 0 if rep.status == "candidate" else NONE_EXIT
