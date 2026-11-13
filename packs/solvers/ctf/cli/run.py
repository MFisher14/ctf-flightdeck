"""ctf run <engine> [args...]: run one engine with the repo's interpreter, sys.path and env (B-187).

The engine is a manifest id (toolkits.network), its name (network), a basename (network.py) or a
path. Everything after the engine name goes to the engine untouched. See ctf/engines/runner.py.
"""
from __future__ import annotations

import argparse
import sys

HELP = "run an engine by name with the right interpreter, sys.path and env (records engine.run)"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-ledger", action="store_true", help="do not append engine.run to the ledger")
    parser.add_argument("--challenge-id", help="recorded with the run in the ledger")
    parser.add_argument("engine", help="engine id, name, basename or path")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="passed to the engine")


def run(args: argparse.Namespace) -> int:
    from ..engines import manifest, runner
    try:
        return runner.run(args.engine, list(args.args), record=not args.no_ledger,
                          challenge_id=args.challenge_id)
    except (runner.EngineError, manifest.ManifestError) as e:
        print(f"ctf run: {e}", file=sys.stderr)
        return 2
