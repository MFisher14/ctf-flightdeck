"""ctf sweep <path> — the pull-time corpus sweep (B-013) on a pulled challenge, a drop folder or a bare
file or folder: recursive unpack into a scratch copy, sha256 manifest, triage, and a flag sweep
(plain, UTF-16, embedded base64/base32/hex, URL-decoded, split metadata fragments). See ctf/sweep.py.

    python -m ctf sweep ~/ctf-work/csctf/9076-last-buffer           # -> <challenge>/unpacked/
    python -m ctf sweep ./dropped.png --event spooky                 # -> <workdir>/sweep/dropped.png-<hash>/
    python -m ctf sweep <path> --out DIR --brief "text of the brief" --json

Exit 0 when the sweep ran (whatever it found), 2 when it could not run (the reason is one line on
stderr). Nothing is submitted.
"""
from __future__ import annotations

import argparse
import sys

from .. import event as _event
from .. import sweep as _sweep
from ..packs import PackError

HELP = "unpack a challenge's files into a scratch copy and sweep every member for the flag (no model)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", help="a pulled challenge folder, a drop folder, or any file or folder")
    p.add_argument("--out", help="scratch folder (default: <challenge>/unpacked or <workdir>/sweep/<name>-<hash>)")
    p.add_argument("--brief", help="the challenge text; flags quoted in it are excluded as template text")
    p.add_argument("--event", help="event slug (default: $CTF_EVENT / the only profile)")
    p.add_argument("--max-depth", type=int, default=None, help="archives inside archives to follow (default 6)")
    p.add_argument("--json", action="store_true", help="print the SolverResult JSON instead of the summary")


def run(args: argparse.Namespace) -> int:
    try:
        profile = _event.load(args.event) if args.event else _event.current()
        walk = None
        if args.max_depth is not None:
            if args.max_depth < 0:
                raise _sweep.SweepError("--max-depth must be 0 or more")
            walk = _sweep.archive_expand().Walk(max_depth=args.max_depth)
        rep = _sweep.sweep(args.path, profile, out=args.out, brief=args.brief, walk=walk)
    except (_sweep.SweepError, _event.EventError, PackError, OSError) as e:
        print(f"ctf sweep: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    print(rep.result.to_json() if args.json else rep.render())
    return 0
