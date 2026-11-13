"""ctf accepted-formats harvest | check | show — the metadata lane's accepted-format catalog (B-218).

    python -m ctf accepted-formats harvest [--corpus DIR ...]        harvest judged attempts; print a summary
    python -m ctf accepted-formats harvest --out FILE                 ... and write the catalog to FILE
    python -m ctf accepted-formats harvest --write                    ... into the tracked catalog
                                                                      (solvers/metadata-forensics/accepted_formats.json)
    python -m ctf accepted-formats harvest --check                    exit 1 when the tracked catalog differs
                                                                      from a fresh harvest
    python -m ctf accepted-formats check BODY [--catalog F] [--json]  the pre-clock brief of a status body /
                                                                      attempt.json: per question its property,
                                                                      status, probe order, and the exact missing
                                                                      piece of anything the catalog cannot shape
    python -m ctf accepted-formats show [PROPERTY ...] [--catalog F]  catalog entries and their probe order

The corpus is a folder of judged attempts OUTSIDE this checkout (the saved `challenges/` of a past event):
`--corpus`, else $CTF_REAL_CHALLENGES. There is no default: judge vocabulary that was never published only
exists in judged attempts. Its files are read as JSON data, never run; nothing under a dot-folder is read.

Exit codes: 0 ok; 1 `check` found a question that needs a probe plan or an agent (status unshaped, or a
syntax phrase the judge never used before), or `harvest --check` found the tracked catalog stale;
2 unusable input (no corpus, a corpus inside the checkout, no judged attempt of the lane, a broken
catalog, an unreadable body, an unknown property).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "metadata accepted-format catalog: pre-event vocabulary harvest, pre-clock brief, probe orders"

LANE_DIR = ("solvers", "metadata-forensics")


def _af():
    from .. import packs, paths
    return packs.load_module("metadata_accepted_formats", paths.repo_root().joinpath(*LANE_DIR, "accepted_formats.py"),
                             pack="metadata accepted_formats")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    hv = sp.add_parser("harvest", help="harvest judged attempts into a catalog")
    hv.add_argument("--corpus", action="append", type=Path,
                    help="a judged-attempt folder outside the checkout (repeatable; default $CTF_REAL_CHALLENGES)")
    hv.add_argument("--lane", default="metadata-forensics", help="lane folder prefix (default metadata-forensics)")
    g = hv.add_mutually_exclusive_group()
    g.add_argument("--out", type=Path, help="write the harvested catalog to this file")
    g.add_argument("--write", action="store_true", help="write the tracked catalog")
    g.add_argument("--check", action="store_true", help="exit 1 when the tracked catalog is stale")
    g.add_argument("--json", action="store_true", help="print the harvested catalog")
    ck = sp.add_parser("check", help="pre-clock brief of a status body or attempt.json")
    ck.add_argument("body", type=Path)
    ck.add_argument("--catalog", type=Path, help="another catalog file (default: the tracked one)")
    ck.add_argument("--json", action="store_true")
    sh = sp.add_parser("show", help="catalog entries and their probe order")
    sh.add_argument("properties", nargs="*")
    sh.add_argument("--catalog", type=Path, help="another catalog file (default: the tracked one)")


def _summary(cat) -> str:
    lines = [f"{len(cat.properties)} properties, {len(cat.syntax)} syntax phrases, {len(cat.unparsed)} unparsed ids"]
    for prop in sorted(cat.properties):
        e = cat.properties[prop]
        best = e.accepted.most_common(1)
        head = f"accepted {best[0][0]} x{best[0][1]}" if best else (
            "consistent " + "/".join(sorted(e.consistent)) if e.consistent else
            f"unclassified x{e.unclassified}" if e.unclassified else "no judged answer")
        rej = f"; refused {', '.join(sorted(e.rejected))}" if e.rejected else ""
        lines.append(f"  {prop} [{e.kind}{'/' + str(e.opts['width_bits']) if e.opts.get('width_bits') else ''}]: "
                     f"{head}{rej}; asked {e.asked}")
    return "\n".join(lines)


def _harvest(AF, args) -> int:
    cat = AF.harvest(args.corpus or [None], lane=args.lane)
    if cat.unreadable:      # a partly broken corpus: said on every action, never a silently smaller catalog
        print(f"ctf accepted-formats: WARNING {len(cat.unreadable)} corpus file(s) could not be read; the "
              f"catalog leaves them out:", file=sys.stderr)
        for line in cat.unreadable:
            print(f"  {line}", file=sys.stderr)
    if args.check:
        have = AF.Catalog.load(AF.DEFAULT_PATH)
        if have.dumps() != cat.dumps():
            print(f"ctf accepted-formats: {AF.DEFAULT_PATH} is stale against the corpus: "
                  f"run harvest --write", file=sys.stderr)
            return 1
        print(f"ctf accepted-formats: {AF.DEFAULT_PATH} matches the corpus")
        return 0
    if args.json:
        sys.stdout.write(cat.dumps())
        return 0
    if args.write or args.out:
        path = cat.save(AF.DEFAULT_PATH if args.write else args.out)
        print(f"wrote {path}")
    print(_summary(cat))
    return 0


def _catalog(AF, path):
    return AF.Catalog.load(path) if path else AF.load_default()


def _check(AF, args) -> int:
    try:
        body = json.loads(args.body.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"ctf accepted-formats check: {args.body}: unreadable ({e})", file=sys.stderr)
        return 2
    questions = AF.questions_of(body)
    if not questions:
        print(f"ctf accepted-formats check: {args.body}: no questions", file=sys.stderr)
        return 2
    findings = AF.brief(questions, _catalog(AF, args.catalog))
    if args.json:
        print(json.dumps([f.to_json() for f in findings], indent=1))
    else:
        for f in findings:
            print(("!! " if f.attention else "   ") + f.line())
    bad = [f for f in findings if f.attention]
    if bad:
        print(f"ctf accepted-formats check: {len(bad)} of {len(findings)} question(s) need a probe on the untimed "
              f"base or an agent before the clock (see MISSING / NEW SYNTAX)", file=sys.stderr)
        return 1
    return 0


def _show(AF, args) -> int:
    cat = _catalog(AF, args.catalog)
    props = args.properties or sorted(cat.properties)
    unknown = [p for p in props if p not in cat.properties]
    if unknown:
        print(f"ctf accepted-formats show: not in the catalog: {', '.join(unknown)}", file=sys.stderr)
        return 2
    for p in props:
        e = cat.properties[p]
        print(json.dumps({"property": p, **e.to_json(), "probe": cat.probe_order(p, e.kind, e.opts)}, indent=1))
    return 0


def run(args: argparse.Namespace) -> int:
    AF = _af()
    try:
        if args.action == "harvest":
            return _harvest(AF, args)
        if args.action == "check":
            return _check(AF, args)
        return _show(AF, args)
    except (AF.CorpusError, AF.CatalogError) as e:
        print(f"ctf accepted-formats {args.action}: {e}", file=sys.stderr)
        return 2
