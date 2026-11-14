"""ctf resolve-ids QUESTIONS (--conventions TOML | --known-ids FILE | --attempt JSON)... — map renamed
question ids onto the ids a lane's readers are proven on, and fail closed (B-010).

    python -m ctf resolve-ids status.json --attempt base/attempt.json
    python -m ctf resolve-ids status.json --conventions solvers/binary/id_conventions.toml
    python -m ctf resolve-ids q.json --known-ids fields.txt --member roster.csv --member notes.txt --json

QUESTIONS is a saved status or attempt body (an object with `questions`), a list of question objects,
or a list of ids. The catalog is the union of every --conventions, --known-ids (a JSON list or one id
per line) and --attempt given; at most one --conventions. --member names a delivered file (stem rule);
--members-dir lists a folder's file names (names only, nothing is opened). Prints one line per id
(`exact`, `a -> b (rule)`, `UNMATCHED ...`, `AMBIGUOUS ...`) or, with --json, the report.

Exit 0 when every id resolves, 1 when any is unmatched or ambiguous (do not start a clock on it),
2 on unusable input (a missing file, no catalog, a bad convention file).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import idresolve as _ir

HELP = "map renamed question ids onto known field readers; exit 1 when any id is unmatched or ambiguous"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("questions", type=Path, help="JSON: status/attempt body, list of questions, or list of ids")
    p.add_argument("--conventions", type=Path, help="a lane's id convention TOML")
    p.add_argument("--known-ids", type=Path, action="append", default=[], metavar="FILE",
                   help="known ids: a JSON list or one id per line (repeatable)")
    p.add_argument("--attempt", type=Path, action="append", default=[], metavar="JSON",
                   help="a saved attempt whose question ids are known (repeatable)")
    p.add_argument("--member", action="append", default=[], metavar="NAME", help="a delivered member name")
    p.add_argument("--members-dir", type=Path, help="use the file names in this folder as delivered members")
    p.add_argument("--json", action="store_true", help="print the report as JSON")


def _read_ids(path: Path) -> list:
    if not path.is_file():
        raise _ir.ConventionError(f"known-ids file not found: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except ValueError:
        return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise _ir.ConventionError(f"{path}: a JSON known-ids file must be a list of strings")
    return data


def _read_attempt(path: Path) -> list:
    if not path.is_file():
        raise _ir.ConventionError(f"attempt file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        raise _ir.ConventionError(f"{path}: not JSON ({e})") from None
    return list(_ir.Catalog.from_attempt(data).known)


def build_catalog(args) -> _ir.Catalog:
    known = []
    for f in args.known_ids:
        known += _read_ids(f)
    for f in args.attempt:
        known += _read_attempt(f)
    if args.conventions is not None:
        return _ir.load_conventions(args.conventions, known=known)
    if not known:
        raise _ir.ConventionError("no catalog: give --conventions, --known-ids or --attempt")
    return _ir.Catalog(known)


def run(args: argparse.Namespace) -> int:
    try:
        questions = _ir.load_questions(args.questions)
        catalog = build_catalog(args)
        members = list(args.member)
        if args.members_dir is not None:
            if not args.members_dir.is_dir():
                raise _ir.ConventionError(f"members folder not found: {args.members_dir}")
            members += sorted(p.name for p in args.members_dir.iterdir() if p.is_file())
        report = _ir.resolve_all(questions, catalog, members)
    except _ir.ConventionError as e:
        print(f"ctf resolve-ids: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_json(), indent=1, sort_keys=True))
    else:
        for r in report.resolutions:
            print(r.line())
        n = report.to_json()["counts"]
        print(f"resolved {n['exact'] + n['mapped']} of {len(report.resolutions)} "
              f"(exact {n['exact']}, mapped {n['mapped']}, unmatched {n['unmatched']}, ambiguous {n['ambiguous']})"
              + ("" if report.ok else "; FAIL CLOSED: do not start a clock on these ids"))
    return 0 if report.ok else 1
