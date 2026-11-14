"""ctf web-traps -- flag an anti-AI honeypot, injected text or an open regex gate before acting (B-104).

    python -m ctf web-traps <challenge_dir>             challenge.json's brief + files/ + unpacked/
    python -m ctf web-traps <file|dir>... [--description-file F]
    python -m ctf web-traps ... --json                  machine-readable

Detect and flag only (BUILD-PLAN.md hard tail #2). It reads the brief and the handout as data with
solvers/toolkits/web_traps.py and prints the verdict (trap | suspect | clean), the action, the rules
and signals behind it, and every regex validation gate that leaves its input open with the marker the
code checks and a candidate input checked offline against the pattern. It sends nothing, contacts no
endpoint a brief names, reads no platform and runs no delivered code; a `trap` is a challenge to
refuse and hand to the human, never one to solve.

Exit: 0 scanned (clean or suspect), 1 a trap was flagged (do not proceed), 2 on an error (a path that
does not exist, an unreadable challenge.json, the reader missing).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from .. import paths as _paths

HELP = "flag an anti-AI honeypot / prompt injection / open regex gate in a brief and handout (B-104)"
TRAP_EXIT = 1


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="+", help="a challenge folder (with challenge.json), a folder or a file")
    p.add_argument("--description-file", dest="description_file",
                   help="a file holding the brief text (instead of challenge.json's)")
    p.add_argument("--json", action="store_true", help="machine-readable output")


def _reader():
    name = "ctf_b104_web_traps"
    if name in sys.modules:
        return sys.modules[name]
    path = _paths.repo_root() / "solvers" / "toolkits" / "web_traps.py"
    if not path.is_file():
        raise FileNotFoundError(f"the honeypot / regex-gate reader is missing: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run(args: argparse.Namespace) -> int:
    try:
        wt = _reader()
        desc = None
        if args.description_file:
            desc = Path(args.description_file).read_bytes()[:wt.MAX_FILE].decode("utf-8", "replace")
        results = [wt.scan_path(p, desc) for p in args.paths]
    except (OSError, ValueError, RuntimeError) as e:
        print(f"ctf web-traps: {e}", file=sys.stderr)
        return 2
    verdict = max((r["verdict"] for r in results), key=wt._RANK.get)
    if args.json:
        print(json.dumps({"verdict": verdict, "results": results}, indent=1, ensure_ascii=False, default=str))
    else:
        for path, r in zip(args.paths, results):
            print(f"# {path}")
            print(wt.render(r))
    return TRAP_EXIT if verdict == wt.TRAP else 0
