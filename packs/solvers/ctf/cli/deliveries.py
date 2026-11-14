"""ctf deliveries ATTEMPT [--json] — which delivery serves which set of a saved attempt (B-042).

    python -m ctf deliveries challenges/day-04/<id>/mastery            # the folder, or its attempt.json
    python -m ctf deliveries attempt.json --json

ATTEMPT is a saved attempt: `attempt.json` beside `artifact/<file>` (one delivery) or
`artifact/delivery-NN/<file>` (several), as the runners and the Game Master adapter save it. Prints one
line per set with the delivery `ctf.deliveries` proves is its own and the rule that proves it:

    set 1 <- delivery 1: evidence.zip [named]  15 question(s), 2,104 bytes
    set 2 <- delivery 1: bundle.zip -> blob-02.txt [member]  1 question(s), 96 bytes
    set 3 <- UNMAPPED: no member of the bundle is numbered 3, and its questions do not name delivery 1

Nothing is solved, started or sent. Exit 0 when every set has its own delivery, 1 when any set is
unmapped (it would reach a solver with no files: do not start a clock on it), 2 when the attempt or
one of its deliveries cannot be read.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import deliveries as _deliveries

HELP = "show which delivery serves which set of a saved multi-set attempt; exit 1 when a set has none"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("attempt", type=Path, help="a saved attempt folder, or the attempt.json in it")
    p.add_argument("--json", action="store_true", help="print the pairing as JSON")


def run(args: argparse.Namespace) -> int:
    try:
        saved = _deliveries.read_attempt(args.attempt)
        inputs = _deliveries.set_inputs(saved)
        if not inputs:
            raise _deliveries.DeliveryError(f"{saved.folder}: the attempt asks no question")
    except _deliveries.DeliveryError as e:
        print(f"ctf deliveries: {e}", file=sys.stderr)
        return 2
    asked: dict[int, int] = {}
    for q in saved.attempt.get("questions") or []:
        if isinstance(q, dict):
            asked[_deliveries.set_of(q)] = asked.get(_deliveries.set_of(q), 0) + 1
    unmapped = [i.choice.set for i in inputs if not i.choice.mapped]
    if args.json:
        print(json.dumps({"ok": not unmapped, "deliveries": list(saved.names),
                          "sets": [dict(i.choice.to_dict(), label=i.label, questions=asked.get(i.choice.set, 0),
                                        bytes=None if i.data is None else len(i.data)) for i in inputs]},
                         indent=1, sort_keys=True))
    else:
        for i in inputs:
            n = i.choice.set
            if i.choice.mapped:
                size = f", {len(i.data):,} bytes" if i.data is not None else ""
                print(f"set {n} <- {i.label} [{i.choice.rule}]  {asked.get(n, 0)} question(s){size}")
            else:
                print(f"set {n} <- {i.label}")
        print(f"{len(inputs) - len(unmapped)} of {len(inputs)} set(s) paired with their own delivery"
              + (f"; FAIL CLOSED: set(s) {', '.join(map(str, unmapped))} have none" if unmapped else ""))
    return 1 if unmapped else 0
