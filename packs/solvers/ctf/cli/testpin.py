"""ctf testpin -- rewrite the values test files pin from fixture outputs; a diff unless --write (B-258).

    python -m ctf testpin --outputs FILE [--case ID] [--set KEY=JSON]... [--names REGEX]
                          [--write] [--check] [--strict] TESTFILE...

FILE is an expectations document (`ctf scaffold repro ... --save`, ctf.expectations) or a plain JSON
object {key: value} (a solver's saved answers). --set adds or overrides one key (its value is JSON;
a bare word is taken as a string). What a pin is: ctf/testpin.py.

Without --write it prints the unified diff and changes nothing (a dry run). One summary line per file
on stderr: edits, already pinned, skipped (not a literal) with their lines. Exit 0 done; 1 with
--check when a pin would change, or with --strict when a pin was skipped; 2 an error (no such file,
outputs that are not usable, a rewrite that would not read back).

Cases that disagree on a key without --case: the bare key is left out (one note on stderr naming the
keys), its `case/key` forms are kept, and a pin on the bare key is skipped and named. An entry nested
under a case id takes only its own case's value, so --case never writes one case's value into another.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import expectations as _x
from .. import testpin as _tp

HELP = "rewrite the expected values test files pin from fixture outputs (dry-run diff by default)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("files", nargs="+", type=Path, help="test files to rewrite")
    p.add_argument("--outputs", type=Path, help="expectations document or a JSON object of key -> value")
    p.add_argument("--case", help="take the keys of this case only")
    p.add_argument("--set", dest="sets", action="append", default=[], metavar="KEY=JSON",
                   help="one key's new value (JSON; a bare word is a string)")
    p.add_argument("--names", default=_tp.DEFAULT_NAMES,
                   help="regex for the names of pinned dict literals (default: EXPECT*, *_EXPECTED, ...)")
    p.add_argument("--write", action="store_true", help="write the files (default: show the diff only)")
    p.add_argument("--check", action="store_true", help="exit 1 when a pin would change")
    p.add_argument("--strict", action="store_true", help="exit 1 when a matching pin was skipped")


def _values(args) -> _x.Pins:
    values = _x.Pins()
    if args.outputs is not None:
        try:
            doc = json.loads(args.outputs.read_text(encoding="utf-8"))
        except OSError as e:
            raise _x.ExpectationError(f"--outputs {args.outputs}: {e.strerror or e}") from None
        except ValueError as e:
            raise _x.ExpectationError(f"--outputs {args.outputs}: not JSON ({e})") from None
        values = _x.pins(doc, args.case)
    elif args.case:
        raise _x.ExpectationError("--case needs --outputs")
    for item in args.sets:
        key, eq, text = item.partition("=")
        if not eq or not key:
            raise _x.ExpectationError(f"--set {item!r}: expected KEY=JSON")
        try:
            values[key] = _x.denormalize(json.loads(text))
        except ValueError:
            values[key] = text
    if not values:
        raise _x.ExpectationError("nothing to pin: give --outputs or --set")
    # a key given by --set is the caller's choice, not an ambiguity
    return _x.Pins(values, values.cases, values.ambiguous - set(values))


def run(args: argparse.Namespace) -> int:
    try:
        values = _values(args)
    except _x.ExpectationError as e:
        print(f"ctf testpin: {e}", file=sys.stderr)
        return 2
    if values.ambiguous:
        print("ctf testpin: cases disagree on " + ", ".join(sorted(values.ambiguous))
              + ": their bare keys are left out (pick one with --case, or pin the case/key form)",
              file=sys.stderr)
    changed = skipped = 0
    for path in args.files:
        try:
            text, plan = _tp.rewrite_file(path, values, write=args.write, names=args.names,
                                             cases=values.cases, ambiguous=values.ambiguous)
        except _tp.TestPinError as e:
            print(f"ctf testpin: {e}", file=sys.stderr)
            return 2
        if text and not args.write:
            sys.stdout.write(text)
        changed += len(plan.edits)
        skipped += len(plan.skipped)
        verb = "rewrote" if args.write else "would rewrite"
        line = f"{path}: {verb} {len(plan.edits)}, already pinned {len(plan.unchanged)}, skipped {len(plan.skipped)}"
        print(line, file=sys.stderr)
        for key, ln, why in plan.skipped:
            print(f"  skipped {key} at line {ln}: {why}", file=sys.stderr)
    if args.check and changed and not args.write:
        return 1
    if args.strict and skipped:
        return 1
    return 0
