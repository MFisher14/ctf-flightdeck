"""`python -m ctf state <sub>` — read the harness's lane-state files with compact, fixed output, so
agents stop writing inline `cat … | python -c` and heredoc JSON readers for them (B-257).

Per-challenge (take a challenge id with `--root`, else `$CTF_REAL_CHALLENGES`, or the folder with
`--dir`): `attempt`, `result`, `start`, `key`, `answers`, `verdicts`, `ladder`, `proofs`.
Per-lane: `conventions`, `routes`. Comparison: `qdiff BASE TIMED`.
Wrappers over the event commands (never a second parser for the same files): `status` folds
`ctf wire status` + `ctf ledger summary` (+ `ctf hypothesis list` for `--cid`), `journal` is
`ctf wire journal`. `lint` flags briefs that still tell agents to hand-parse these files.

No network, no model, no challenge binary. A missing or unreadable file fails loudly (exit 2).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

from .. import lanestate as _ls

HELP = "read lane state (attempt/result/start/key/verdicts/answers/ladder/proofs/conventions/routes/qdiff/status/journal) with compact output"

# subcommands that locate a challenge folder from an id/root or --dir
_PER_CHALLENGE = ("attempt", "result", "start", "key", "answers", "verdicts", "ladder", "proofs")


def _add_locator(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("cid", nargs="?", help="challenge id (located under --root/$CTF_REAL_CHALLENGES)")
    sp.add_argument("--root", type=Path, help="challenges root (default: $CTF_REAL_CHALLENGES)")
    sp.add_argument("--dir", type=Path, help="the challenge folder directly (skips id lookup)")


def add_arguments(p: argparse.ArgumentParser, *, skip: tuple[str, ...] = ()):
    """The subcommands; returns the subparsers action so `ctf show` (B-210) can add its own beside them
    (one command over one library). `skip` leaves out the subcommands the caller replaces."""
    sub = p.add_subparsers(dest="sub", required=True)
    for name in _PER_CHALLENGE:
        if name in skip:
            continue
        sc = sub.add_parser(name, help=f"the challenge's {name} state")
        _add_locator(sc)
        if name == "proofs":
            sc.add_argument("--file", type=Path, help="read this proof-hunt results file directly")

    con = sub.add_parser("conventions", help="a lane's answer and id conventions")
    con.add_argument("--lane", default="binary", help="lane folder under solvers/ (default: binary)")
    con.add_argument("--root", type=Path, help="repo root (default: the checkout)")
    con.add_argument("--answers", type=Path, help="override the conventions.json path")
    con.add_argument("--ids", type=Path, help="override the id_conventions.toml path")

    rt = sub.add_parser("routes", help="the triage route table (route_table.jsonl)")
    rt.add_argument("--root", type=Path, help="repo root (default: the checkout)")
    rt.add_argument("--lane", help="only this lane (the engine id's first segment)")
    rt.add_argument("--category", help="only routes with this category")
    rt.add_argument("--id", dest="engine_id", help="only this engine id")

    qd = sub.add_parser("qdiff", help="question-contract diff of a timed start against its base")
    qd.add_argument("base", type=Path, help="base attempt/start body (JSON with questions)")
    qd.add_argument("timed", type=Path, help="timed start body (JSON with questions)")

    stt = sub.add_parser("status", help="wire status + ledger summary (+ hypotheses for --cid)")
    stt.add_argument("--cid", help="also show the attempts ledger for this challenge")
    stt.add_argument("--event", help="event slug (default: the current event)")
    stt.add_argument("--workdir", help="event workdir (default: the event's)")

    jrn = sub.add_parser("journal", help="the platform request journal (wraps ctf wire journal)")
    jrn.add_argument("--event", help="event slug (default: the current event)")
    jrn.add_argument("--workdir", help="event workdir (default: the event's)")
    jrn.add_argument("--since", help="epoch seconds, ISO-8601 with offset, or N seconds ago")
    jrn.add_argument("--lane")
    jrn.add_argument("--op")
    jrn.add_argument("--status", type=int, help="only rows with this HTTP status")
    jrn.add_argument("--json", action="store_true", help="one JSON row per line")

    ln = sub.add_parser("lint", help="flag briefs that still hand-parse lane-state files")
    ln.add_argument("paths", nargs="+", help="brief files or folders (*.md/*.txt/*.tmpl)")
    return sub


def _emit(lines) -> int:
    for ln in lines:
        print(ln)
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        if args.sub in _PER_CHALLENGE:
            d = _ls.resolve_challenge_dir(args.cid, root=args.root, direct=args.dir)
            if args.sub == "proofs":
                return _emit(_ls.read_proofs(d, direct=args.file))
            return _emit(_ls.VARIANT_READERS[args.sub](d))
        if args.sub == "conventions":
            return _emit(_ls.read_conventions(lane=args.lane, root=args.root,
                                              answers_path=args.answers, ids_path=args.ids))
        if args.sub == "routes":
            return _emit(_ls.read_routes(root=args.root, lane=args.lane,
                                         category=args.category, engine_id=args.engine_id))
        if args.sub == "qdiff":
            return _emit(_ls.read_qdiff(args.base, args.timed))
        if args.sub == "status":
            return _status(args)
        if args.sub == "journal":
            return _journal(args)
        if args.sub == "lint":
            return _lint(args)
    except _ls.LaneStateError as e:
        print(f"ctf state {args.sub}: {e}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled sub {args.sub!r}")


def _status(args) -> int:
    """Fold the event status surfaces; each is the existing command, not a second reader (R: wrap,
    don't re-parse). A collaborator that fails returns non-zero and we go on to the next."""
    from . import wire as _wire, ledger as _ledger, hypothesis as _hyp
    worst = 0
    print("== wire status ==")
    worst |= _wire.run(SimpleNamespace(action="status", event=args.event, workdir=args.workdir, json=False))
    print("== ledger summary ==")
    worst |= _ledger.run(SimpleNamespace(action="summary", event=args.event, workdir=args.workdir,
                                         wave=None, json=False))
    if args.cid:
        print(f"== hypotheses {args.cid} ==")
        worst |= _hyp.run(SimpleNamespace(action="list", event=args.event, workdir=args.workdir,
                                          cid=args.cid, json=False))
    return 0 if worst == 0 else 1


def _journal(args) -> int:
    from . import wire as _wire
    return _wire.run(SimpleNamespace(action="journal", event=args.event, workdir=args.workdir,
                                     since=args.since, lane=args.lane, op=args.op,
                                     status=args.status, json=args.json))


def _lint(args) -> int:
    findings = _ls.lint_briefs(args.paths)
    if not findings:
        print(f"ctf state lint: no hand-parsed lane-state readers in {len(args.paths)} path(s)")
        return 0
    for f, n, named, line in findings:
        print(f"{f}:{n}: hand-parses {named} — use `python -m ctf state`: {line}")
    print(f"ctf state lint: {len(findings)} finding(s); replace inline readers with `python -m ctf state <sub>`",
          file=sys.stderr)
    return 1
